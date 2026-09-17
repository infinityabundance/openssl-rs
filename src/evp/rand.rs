//! Phase 7.3f — the `EVP_RAND` method object and the context it is run through.
//!
//! `crypto/evp/evp_rand.c`, whole. The third of the provider-only classes and the one that breaks
//! the pattern the other two established, in three ways that a reader who had internalised
//! `EVP_MAC` and `EVP_KDF` would not expect:
//!
//!   * **a context has a parent, and a parent is a reference.** `EVP_RAND_CTX_new` takes an
//!     `EVP_RAND *` and an optional `EVP_RAND_CTX *`, the reference to the parent is taken *before*
//!     the provider's constructor is called, and that constructor is handed the parent's algorithm
//!     context **and the parent's dispatch table** — which is why `EvpRand` keeps a `dispatch`
//!     field that no other class in this stratum has, a raw pointer to the algorithm's own
//!     `OSSL_DISPATCH` table.
//!   * **a context is reference counted, and releasing it is recursive.** Every other context
//!     object in this stratum is owned outright and released once; this one has a `refcnt` of its
//!     own, and the last release drops the parent — which may itself be the last reference to its
//!     own parent. So the release is a chain, and a transcription that freed one level would leave
//!     a whole tree of provider contexts alive.
//!   * **every operation is wrapped in the provider's lock.** `EVP_RAND_CTX_get_params` and its
//!     eleven siblings each take a lock, call a `_locked` helper, and release — and the lock is
//!     *optional*: a method with no `lock` answers 1 for every acquisition, so the pair is free for
//!     a provider that does not need it. `EVP_RAND_enable_locking` is the one entry point that is
//!     not wrapped, because it is the call that *enables* the thing.
//!
//! ## The structural check is three counters and not a list
//!
//! `fnrandcnt == 3` counts `instantiate`, `uninstantiate` and `generate`; `fnctxcnt == 3` counts
//! `newctx`, `freectx` and — the surprise — `get_ctx_params`, so a provider that cannot report its
//! own context parameters is refused at fetch time rather than failing later at the first
//! `generate`; and the two locking counters must each be *all or nothing*: `fnenablelockcnt` is 0 or
//! 1 and `fnlockcnt` is 0 or 2, so a provider that published a lock and no unlock is refused. The
//! FIPS-only zeroization counter is not compiled in this profile and is therefore absent rather
//! than relaxed.
//!
//! `fnctxcnt` counting `get_ctx_params` is load-bearing in a way the check alone does not show:
//! `evp_rand_generate_locked` **asks** for `OSSL_RAND_PARAM_MAX_REQUEST` and refuses the whole
//! generation when the answer is missing or zero, because the loop it drives is chunked by it. So
//! the fetch-time check and the runtime requirement are the same requirement, and the class is
//! honest about it up front.
//!
//! ## What is not here
//!
//! `evp_rand_can_seed`, `evp_rand_get_seed` and `evp_rand_clear_seed` are internal, are declared in
//! `include/crypto/evp.h`, and are called only by `crypto/rand/rand_lib.c` — which is Phase 9's. The
//! `get_seed` and `clear_seed` *fields* are filled by this file's dispatch walk, because the walk is
//! this file's; their three callers arrive with the stratum that needs them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{
    evp_generic_do_all, evp_generic_fetch, GenericDoAllFn, MethodFromAlgorithmFn,
};
use crate::evp::fetch::{evp_is_a, evp_names_do_all};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_construct_uint, OsslParam,
};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_OP_RAND` — `include/openssl/core_dispatch.h`. The fifth operation the walk visits.
const OSSL_OP_RAND: c_int = 5;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c".as_ptr();
/// `evp_rand_new`'s `OPENSSL_zalloc(sizeof(*rand))` (line 81).
const LINE_ZALLOC_RAND: c_int = 81;
/// `evp_rand_free`'s `OPENSSL_free(rand->type_name)` (line 73).
const LINE_FREE_TYPE_NAME: c_int = 73;
/// `evp_rand_free`'s `OPENSSL_free(rand)` (line 76).
const LINE_FREE_RAND: c_int = 76;
/// `EVP_RAND_CTX_new`'s `OPENSSL_zalloc(sizeof(*ctx))` (line 350).
const LINE_ZALLOC_CTX: c_int = 350;
/// `EVP_RAND_CTX_new`'s `OPENSSL_free(ctx)` — three call sites in one function, at lines 355, 362
/// and 374, and all three are the same statement.
const LINE_FREE_CTX_ON_NEW: c_int = 374;
/// `EVP_RAND_CTX_free`'s `OPENSSL_free(ctx)` (line 399).
const LINE_FREE_CTX: c_int = 399;

/// `EVP_RAND_STATE_ERROR` — `include/openssl/evp.h`. The state `EVP_RAND_get_state` answers when it
/// cannot ask.
const EVP_RAND_STATE_ERROR: c_int = 2;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the nineteen function-pointer types.
//
// `OSSL_FUNC_RAND_*` from `include/openssl/core_dispatch.h`, and each type is what
// `OSSL_CORE_MAKE_FUNC` generates for the corresponding entry. The ids are part of the wire format
// a provider is compiled against, so they are copied rather than derived.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_RAND_NEWCTX`.
const OSSL_FUNC_RAND_NEWCTX: c_int = 1;
/// `OSSL_FUNC_RAND_FREECTX`.
const OSSL_FUNC_RAND_FREECTX: c_int = 2;
/// `OSSL_FUNC_RAND_INSTANTIATE`.
const OSSL_FUNC_RAND_INSTANTIATE: c_int = 3;
/// `OSSL_FUNC_RAND_UNINSTANTIATE`.
const OSSL_FUNC_RAND_UNINSTANTIATE: c_int = 4;
/// `OSSL_FUNC_RAND_GENERATE`.
const OSSL_FUNC_RAND_GENERATE: c_int = 5;
/// `OSSL_FUNC_RAND_RESEED`.
const OSSL_FUNC_RAND_RESEED: c_int = 6;
/// `OSSL_FUNC_RAND_NONCE`.
const OSSL_FUNC_RAND_NONCE: c_int = 7;
/// `OSSL_FUNC_RAND_ENABLE_LOCKING`.
const OSSL_FUNC_RAND_ENABLE_LOCKING: c_int = 8;
/// `OSSL_FUNC_RAND_LOCK`.
const OSSL_FUNC_RAND_LOCK: c_int = 9;
/// `OSSL_FUNC_RAND_UNLOCK`.
const OSSL_FUNC_RAND_UNLOCK: c_int = 10;
/// `OSSL_FUNC_RAND_GETTABLE_PARAMS`.
const OSSL_FUNC_RAND_GETTABLE_PARAMS: c_int = 11;
/// `OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS: c_int = 12;
/// `OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS: c_int = 13;
/// `OSSL_FUNC_RAND_GET_PARAMS`.
const OSSL_FUNC_RAND_GET_PARAMS: c_int = 14;
/// `OSSL_FUNC_RAND_GET_CTX_PARAMS`. One of the three counters — see the module documentation.
const OSSL_FUNC_RAND_GET_CTX_PARAMS: c_int = 15;
/// `OSSL_FUNC_RAND_SET_CTX_PARAMS`.
const OSSL_FUNC_RAND_SET_CTX_PARAMS: c_int = 16;
/// `OSSL_FUNC_RAND_VERIFY_ZEROIZATION`.
const OSSL_FUNC_RAND_VERIFY_ZEROIZATION: c_int = 17;
/// `OSSL_FUNC_RAND_GET_SEED`. Filled here, called by Phase 9's `rand_lib.c`.
const OSSL_FUNC_RAND_GET_SEED: c_int = 18;
/// `OSSL_FUNC_RAND_CLEAR_SEED`. Filled here, called by Phase 9's `rand_lib.c`.
const OSSL_FUNC_RAND_CLEAR_SEED: c_int = 19;

/// `OSSL_FUNC_rand_newctx_fn` — `void *(*)(void *provctx, void *parent,
/// const OSSL_DISPATCH *parent_calls)`.
///
/// **The only constructor in this stratum with three arguments**, and the third is the parent's
/// dispatch table rather than the parent's context: a child DRBG is handed the parent's *callbacks*
/// so that it can call through them, which is the whole mechanism by which a provider's own DRBG
/// chains onto another one's.
pub(crate) type RandNewCtxFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslDispatch) -> *mut c_void;
/// `OSSL_FUNC_rand_freectx_fn` — `void (*)(void *vctx)`.
pub(crate) type RandFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_rand_instantiate_fn` — `int (*)(void *vdrbg, unsigned int strength,
/// int prediction_resistance, const unsigned char *pstr, size_t pstr_len,
/// const OSSL_PARAM params[])`.
pub(crate) type RandInstantiateFn = unsafe extern "C" fn(
    *mut c_void,
    c_uint,
    c_int,
    *const c_uchar,
    usize,
    *const OsslParam,
) -> c_int;
/// `OSSL_FUNC_rand_uninstantiate_fn` — `int (*)(void *vdrbg)`.
pub(crate) type RandUninstantiateFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_rand_generate_fn` — `int (*)(void *vctx, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *addin,
/// size_t addin_len)`.
pub(crate) type RandGenerateFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    usize,
    c_uint,
    c_int,
    *const c_uchar,
    usize,
) -> c_int;
/// `OSSL_FUNC_rand_reseed_fn` — `int (*)(void *vctx, int prediction_resistance,
/// const unsigned char *ent, size_t ent_len, const unsigned char *addin, size_t addin_len)`.
pub(crate) type RandReseedFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
/// `OSSL_FUNC_rand_nonce_fn` — `size_t (*)(void *vctx, unsigned char *out, unsigned int strength,
/// size_t min_noncelen, size_t max_noncelen)`.
pub(crate) type RandNonceFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, c_uint, usize, usize) -> usize;
/// `OSSL_FUNC_rand_enable_locking_fn` — `int (*)(void *vctx)`.
pub(crate) type RandEnableLockingFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_rand_lock_fn` — `int (*)(void *vctx)`.
pub(crate) type RandLockFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_rand_unlock_fn` — `void (*)(void *vctx)`.
pub(crate) type RandUnlockFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_rand_gettable_params_fn` — `const OSSL_PARAM *(*)(void *provctx)`.
pub(crate) type RandGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_rand_gettable_ctx_params_fn` — `const OSSL_PARAM *(*)(void *vctx, void *provctx)`.
pub(crate) type RandGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_rand_settable_ctx_params_fn` — the same signature.
pub(crate) type RandSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_rand_get_params_fn` — `int (*)(OSSL_PARAM params[])`.
pub(crate) type RandGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `OSSL_FUNC_rand_get_ctx_params_fn` — `int (*)(void *vctx, OSSL_PARAM params[])`.
pub(crate) type RandGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_rand_set_ctx_params_fn` — `int (*)(void *vctx, const OSSL_PARAM params[])`.
pub(crate) type RandSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_rand_verify_zeroization_fn` — `int (*)(void *vctx)`.
pub(crate) type RandVerifyZeroizationFn = unsafe extern "C" fn(*mut c_void) -> c_int;
/// `OSSL_FUNC_rand_get_seed_fn` — `size_t (*)(void *vctx, unsigned char **buffer, int entropy,
/// size_t min_len, size_t max_len, int prediction_resistance, const unsigned char *adin,
/// size_t adin_len)`. Filled here, called by Phase 9's `rand_lib.c`.
pub(crate) type RandGetSeedFn = unsafe extern "C" fn(
    *mut c_void,
    *mut *mut c_uchar,
    c_int,
    usize,
    usize,
    c_int,
    *const c_uchar,
    usize,
) -> usize;
/// `OSSL_FUNC_rand_clear_seed_fn` — `void (*)(void *vctx, unsigned char *buffer, size_t b_len)`.
pub(crate) type RandClearSeedFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize);

/// `OSSL_RAND_PARAM_MAX_REQUEST` — `include/openssl/core_names.h`.
///
/// `evp_rand_generate_locked` asks for this before it generates anything and refuses the whole call
/// when the answer is absent or zero, because the loop it drives is chunked by it.
const OSSL_RAND_PARAM_MAX_REQUEST: *const c_char = c"max_request".as_ptr();
/// `OSSL_RAND_PARAM_STRENGTH` — `include/openssl/core_names.h`.
const OSSL_RAND_PARAM_STRENGTH: *const c_char = c"strength".as_ptr();
/// `OSSL_RAND_PARAM_STATE` — `include/openssl/core_names.h`.
const OSSL_RAND_PARAM_STATE: *const c_char = c"state".as_ptr();

/// `struct evp_rand_st` — `EVP_RAND`, from `crypto/evp/evp_rand.c`.
///
/// Sixteen callbacks, one bookkeeping block, and **one field no other class has**: `dispatch`, the
/// algorithm's own `OSSL_DISPATCH` table as the provider published it. It is kept rather than
/// merely walked because `EVP_RAND_CTX_new` hands it to a child context's constructor, so the
/// table itself is part of the class's state and not just of the fetch.
///
/// `pub` for the reason every internal type in an exported signature is: twenty exported functions
/// take or return one, Rust requires the type of an exported item's parameter to be at least as
/// visible, and the authority keeps `evp_rand_st` in `evp_rand.c` itself. Every field is
/// `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpRand {
    /// `OSSL_PROVIDER *prov` — the provider that published it, holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `int name_id` — the namemap identity the method was fetched under.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `const OSSL_DISPATCH *dispatch` — the algorithm's own table, handed to a child's `newctx`.
    pub(crate) dispatch: *const OsslDispatch,
    /// `OSSL_FUNC_rand_newctx_fn *newctx`.
    pub(crate) newctx: Option<RandNewCtxFn>,
    /// `OSSL_FUNC_rand_freectx_fn *freectx`.
    pub(crate) freectx: Option<RandFreeCtxFn>,
    /// `OSSL_FUNC_rand_instantiate_fn *instantiate`.
    pub(crate) instantiate: Option<RandInstantiateFn>,
    /// `OSSL_FUNC_rand_uninstantiate_fn *uninstantiate`.
    pub(crate) uninstantiate: Option<RandUninstantiateFn>,
    /// `OSSL_FUNC_rand_generate_fn *generate`.
    pub(crate) generate: Option<RandGenerateFn>,
    /// `OSSL_FUNC_rand_reseed_fn *reseed`.
    pub(crate) reseed: Option<RandReseedFn>,
    /// `OSSL_FUNC_rand_nonce_fn *nonce`.
    pub(crate) nonce: Option<RandNonceFn>,
    /// `OSSL_FUNC_rand_enable_locking_fn *enable_locking`.
    pub(crate) enable_locking: Option<RandEnableLockingFn>,
    /// `OSSL_FUNC_rand_lock_fn *lock`.
    pub(crate) lock: Option<RandLockFn>,
    /// `OSSL_FUNC_rand_unlock_fn *unlock`.
    pub(crate) unlock: Option<RandUnlockFn>,
    /// `OSSL_FUNC_rand_gettable_params_fn *gettable_params`.
    pub(crate) gettable_params: Option<RandGettableParamsFn>,
    /// `OSSL_FUNC_rand_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<RandGettableCtxParamsFn>,
    /// `OSSL_FUNC_rand_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<RandSettableCtxParamsFn>,
    /// `OSSL_FUNC_rand_get_params_fn *get_params`.
    pub(crate) get_params: Option<RandGetParamsFn>,
    /// `OSSL_FUNC_rand_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<RandGetCtxParamsFn>,
    /// `OSSL_FUNC_rand_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<RandSetCtxParamsFn>,
    /// `OSSL_FUNC_rand_verify_zeroization_fn *verify_zeroization`.
    pub(crate) verify_zeroization: Option<RandVerifyZeroizationFn>,
    /// `OSSL_FUNC_rand_get_seed_fn *get_seed` — filled here, called by Phase 9's `rand_lib.c`.
    pub(crate) get_seed: Option<RandGetSeedFn>,
    /// `OSSL_FUNC_rand_clear_seed_fn *clear_seed` — filled here, called by Phase 9's `rand_lib.c`.
    pub(crate) clear_seed: Option<RandClearSeedFn>,
}

/// `struct evp_rand_ctx_st` — `EVP_RAND_CTX`, from `crypto/evp/evp_local.h`.
///
/// **Four fields, where every other context in this stratum has two.** The algorithm context and
/// the method it belongs to are the same as `EVP_MAC_CTX`'s; the parent is this class's alone, and
/// so is a reference count on the *context* rather than only on the method — which is what makes a
/// context shareable and its release a chain.
///
/// `pub` for the same reason `EvpRand` is.
#[repr(C)]
pub struct EvpRandCtx {
    /// `EVP_RAND *meth` — the method, holding a reference of this context's own.
    pub(crate) meth: *mut EvpRand,
    /// `void *algctx` — the provider's context, from `newctx`.
    pub(crate) algctx: *mut c_void,
    /// `EVP_RAND_CTX *parent` — the parent, holding a reference of this context's own, or NULL.
    pub(crate) parent: *mut EvpRandCtx,
    /// `CRYPTO_REF_COUNT refcnt` — the **context's** count, not the method's.
    pub(crate) refcnt: AtomicI32,
}

// ---------------------------------------------------------------------------------------------
// The method object
// ---------------------------------------------------------------------------------------------

/// `static int evp_rand_up_ref(void *vrand)` — the shape `evp_generic_fetch` wants.
///
/// **Answers 1 for NULL**, which every other class's does not: the authority tests `vrand != NULL`
/// and returns 1 without touching the count. It is the one method-level reference taker in this
/// stratum with a NULL arm, and it exists because `EVP_RAND_CTX_new` releases a chain that may
/// include a NULL parent.
///
/// # Safety
/// `vrand` must be NULL or a live `EvpRand`.
unsafe extern "C" fn evp_rand_up_ref(vrand: *mut c_void) -> c_int {
    // SAFETY: `vrand` is NULL or live per the contract.
    unsafe { EVP_RAND_up_ref(vrand.cast::<EvpRand>()) }
}

/// `static void evp_rand_free(void *vrand)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vrand` must be NULL or a live `EvpRand`.
unsafe extern "C" fn evp_rand_free(vrand: *mut c_void) {
    // SAFETY: `vrand` is NULL or live per the contract.
    unsafe { EVP_RAND_free(vrand.cast::<EvpRand>()) };
}

/// `static void *evp_rand_new(void)`.
///
/// # Safety
/// No preconditions: it allocates and writes one field.
unsafe fn evp_rand_new() -> *mut EvpRand {
    let rand =
        CRYPTO_zalloc(core::mem::size_of::<EvpRand>(), FILE, LINE_ZALLOC_RAND).cast::<EvpRand>();
    if rand.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `rand` is a fresh zeroed block this call owns.
    unsafe { (*rand).refcnt = AtomicI32::new(1) };
    rand
}

/// `static void *evp_rand_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// Four counters, and the arithmetic is the strictest in the stratum:
///
///   * `fnrandcnt == 3` — `instantiate`, `uninstantiate`, `generate`;
///   * `fnctxcnt == 3` — `newctx`, `freectx`, and **`get_ctx_params`**, which no other class counts
///     toward its context functions. A provider that cannot report its own context parameters is
///     refused here rather than failing at the first generate, because `generate` needs
///     `max_request` from exactly that call;
///   * `fnenablelockcnt` is 0 or 1 and `fnlockcnt` is 0 or 2 — each an **all-or-nothing pair**, so
///     a provider that published a lock and no unlock is refused rather than deadlocking;
///   * the FIPS-module zeroization counter is not compiled in this profile, so its clause is absent
///     rather than relaxed — the two are different statements and the code says which one it is.
///
/// The failure raise is `EVP_R_INVALID_PROVIDER_FUNCTIONS`, and it comes **after** the object is
/// released, which is the authority's order and the reason the release is not conditional on an
/// error flag.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live or NULL.
unsafe extern "C" fn evp_rand_from_algorithm(
    name_id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let rand = unsafe { evp_rand_new() };
    if rand.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_129) };
        return ptr::null_mut();
    }

    // SAFETY: `rand` is live.
    unsafe { (*rand).name_id = name_id };
    // SAFETY: `algodef` is live per the contract.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `rand` is this call's own object.
        unsafe { EVP_RAND_free(rand) };
        return ptr::null_mut();
    }
    // SAFETY: `rand` is live and `type_name` is the string just allocated for it.
    unsafe { (*rand).type_name = type_name };
    // SAFETY: `algodef` is live.
    unsafe {
        (*rand).description = (*algodef).algorithm_description;
        // The table itself, kept because a child context's constructor is handed it.
        (*rand).dispatch = fns;
    }

    let mut fns = fns;
    let mut fnrandcnt = 0;
    let mut fnctxcnt = 0;
    let mut fnlockcnt = 0;
    let mut fnenablelockcnt = 0;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator. Each arm reads `function_id` before deciding, and fills its field only if the
    // field is still NULL -- so the *first* entry for an id wins, which is every class's rule.
    unsafe {
        while (*fns).function_id != OSSL_DISPATCH_END {
            let id = (*fns).function_id;
            match id {
                OSSL_FUNC_RAND_NEWCTX if (*rand).newctx.is_none() => {
                    (*rand).newctx = entry_function::<RandNewCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_RAND_FREECTX if (*rand).freectx.is_none() => {
                    (*rand).freectx = entry_function::<RandFreeCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_RAND_INSTANTIATE if (*rand).instantiate.is_none() => {
                    (*rand).instantiate = entry_function::<RandInstantiateFn>(fns);
                    fnrandcnt += 1;
                }
                OSSL_FUNC_RAND_UNINSTANTIATE if (*rand).uninstantiate.is_none() => {
                    (*rand).uninstantiate = entry_function::<RandUninstantiateFn>(fns);
                    fnrandcnt += 1;
                }
                OSSL_FUNC_RAND_GENERATE if (*rand).generate.is_none() => {
                    (*rand).generate = entry_function::<RandGenerateFn>(fns);
                    fnrandcnt += 1;
                }
                OSSL_FUNC_RAND_RESEED if (*rand).reseed.is_none() => {
                    (*rand).reseed = entry_function::<RandReseedFn>(fns);
                }
                OSSL_FUNC_RAND_NONCE if (*rand).nonce.is_none() => {
                    (*rand).nonce = entry_function::<RandNonceFn>(fns);
                }
                OSSL_FUNC_RAND_ENABLE_LOCKING if (*rand).enable_locking.is_none() => {
                    (*rand).enable_locking = entry_function::<RandEnableLockingFn>(fns);
                    fnenablelockcnt += 1;
                }
                OSSL_FUNC_RAND_LOCK if (*rand).lock.is_none() => {
                    (*rand).lock = entry_function::<RandLockFn>(fns);
                    fnlockcnt += 1;
                }
                OSSL_FUNC_RAND_UNLOCK if (*rand).unlock.is_none() => {
                    (*rand).unlock = entry_function::<RandUnlockFn>(fns);
                    fnlockcnt += 1;
                }
                OSSL_FUNC_RAND_GETTABLE_PARAMS if (*rand).gettable_params.is_none() => {
                    (*rand).gettable_params = entry_function::<RandGettableParamsFn>(fns);
                }
                OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS if (*rand).gettable_ctx_params.is_none() => {
                    (*rand).gettable_ctx_params = entry_function::<RandGettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS if (*rand).settable_ctx_params.is_none() => {
                    (*rand).settable_ctx_params = entry_function::<RandSettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_RAND_GET_PARAMS if (*rand).get_params.is_none() => {
                    (*rand).get_params = entry_function::<RandGetParamsFn>(fns);
                }
                OSSL_FUNC_RAND_GET_CTX_PARAMS if (*rand).get_ctx_params.is_none() => {
                    (*rand).get_ctx_params = entry_function::<RandGetCtxParamsFn>(fns);
                    // The surprise: this counts toward the *context* total, not the rand one.
                    fnctxcnt += 1;
                }
                OSSL_FUNC_RAND_SET_CTX_PARAMS if (*rand).set_ctx_params.is_none() => {
                    (*rand).set_ctx_params = entry_function::<RandSetCtxParamsFn>(fns);
                }
                OSSL_FUNC_RAND_VERIFY_ZEROIZATION if (*rand).verify_zeroization.is_none() => {
                    (*rand).verify_zeroization = entry_function::<RandVerifyZeroizationFn>(fns);
                }
                OSSL_FUNC_RAND_GET_SEED if (*rand).get_seed.is_none() => {
                    (*rand).get_seed = entry_function::<RandGetSeedFn>(fns);
                }
                OSSL_FUNC_RAND_CLEAR_SEED if (*rand).clear_seed.is_none() => {
                    (*rand).clear_seed = entry_function::<RandClearSeedFn>(fns);
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }

    if fnrandcnt != 3
        || fnctxcnt != 3
        || (fnenablelockcnt != 0 && fnenablelockcnt != 1)
        || (fnlockcnt != 0 && fnlockcnt != 2)
    {
        // SAFETY: `rand` is this call's own object.
        unsafe { EVP_RAND_free(rand) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_268) };
        return ptr::null_mut();
    }

    if !prov.is_null() {
        // SAFETY: `prov` is live per the contract.
        if unsafe { ossl_provider_up_ref(prov) } == 0 {
            // SAFETY: `rand` is this call's own object.
            unsafe { EVP_RAND_free(rand) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_RAND_274) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `rand` is live.
    unsafe { (*rand).prov = prov };

    rand.cast::<c_void>()
}

/// `EVP_RAND *EVP_RAND_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `libctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_fetch(
    libctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpRand {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            libctx,
            OSSL_OP_RAND,
            algorithm,
            properties,
            evp_rand_from_algorithm as MethodFromAlgorithmFn,
            evp_rand_up_ref as MethodUpRefFn,
            evp_rand_free as MethodFreeFn,
        )
    }
    .cast::<EvpRand>()
}

/// `int EVP_RAND_up_ref(EVP_RAND *rand)`.
///
/// **Answers 1 for NULL without touching anything.** No other method-level reference taker in this
/// stratum has that arm; it is here because the chain `EVP_RAND_CTX_free` walks can include a NULL
/// parent and the authority's own `evp_rand_up_ref` tests for it.
///
/// # Safety
/// `rand` must be NULL or a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_up_ref(rand: *mut EvpRand) -> c_int {
    if rand.is_null() {
        return 1;
    }
    // SAFETY: `rand` is live per the contract.
    unsafe { (*rand).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void EVP_RAND_free(EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be NULL or a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_free(rand: *mut EvpRand) {
    if rand.is_null() {
        return;
    }
    // SAFETY: `rand` is live per the contract.
    let last = unsafe { (*rand).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference and the block is this call's.
    unsafe {
        CRYPTO_free(
            (*rand).type_name.cast::<c_void>(),
            FILE,
            LINE_FREE_TYPE_NAME,
        );
        ossl_provider_free((*rand).prov);
        CRYPTO_free(rand.cast::<c_void>(), FILE, LINE_FREE_RAND);
    }
}

/// `int evp_rand_get_number(const EVP_RAND *rand)` — internal, and the namemap identity.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[allow(dead_code)] // no caller until Phase 9's rand_lib.c lands
pub(crate) unsafe fn evp_rand_get_number(rand: *const EvpRand) -> c_int {
    // SAFETY: `rand` is live per the contract.
    unsafe { (*rand).name_id }
}

/// `const char *EVP_RAND_get0_name(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get0_name(rand: *const EvpRand) -> *const c_char {
    // SAFETY: `rand` is live per the contract.
    unsafe { (*rand).type_name }
}

/// `const char *EVP_RAND_get0_description(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get0_description(rand: *const EvpRand) -> *const c_char {
    // SAFETY: `rand` is live per the contract.
    unsafe { (*rand).description }
}

/// `int EVP_RAND_is_a(const EVP_RAND *rand, const char *name)`.
///
/// # Safety
/// `rand` must be NULL or a live `EvpRand`; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_is_a(rand: *const EvpRand, name: *const c_char) -> c_int {
    if rand.is_null() {
        return 0;
    }
    // SAFETY: `rand` is live per the contract.
    let (prov, name_id) = unsafe { ((*rand).prov, (*rand).name_id) };
    // SAFETY: `prov` is the provider the method was fetched from and the visitor contract is the
    // namemap's.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `const OSSL_PROVIDER *EVP_RAND_get0_provider(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get0_provider(rand: *const EvpRand) -> *const OsslProvider {
    // SAFETY: `rand` is live per the contract.
    unsafe { (*rand).prov }
}

/// `int EVP_RAND_get_params(EVP_RAND *rand, OSSL_PARAM params[])`.
///
/// Answers **1** for a missing callback, as the other two provider-only classes do.
///
/// # Safety
/// `rand` must be a live `EvpRand`; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get_params(rand: *mut EvpRand, params: *mut OsslParam) -> c_int {
    // SAFETY: `rand` is live per the contract.
    let Some(f) = (unsafe { (*rand).get_params }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `const OSSL_PARAM *EVP_RAND_gettable_params(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_gettable_params(rand: *const EvpRand) -> *const OsslParam {
    // SAFETY: `rand` is live per the contract.
    let Some(f) = (unsafe { (*rand).gettable_params }) else {
        return ptr::null();
    };
    // SAFETY: `rand` is live, so a method with a `gettable_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*rand).prov) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `const OSSL_PARAM *EVP_RAND_gettable_ctx_params(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_gettable_ctx_params(rand: *const EvpRand) -> *const OsslParam {
    // SAFETY: `rand` is live per the contract.
    let Some(f) = (unsafe { (*rand).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `rand` is live, so a method with a `gettable_ctx_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*rand).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_RAND_settable_ctx_params(const EVP_RAND *rand)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_settable_ctx_params(rand: *const EvpRand) -> *const OsslParam {
    // SAFETY: `rand` is live per the contract.
    let Some(f) = (unsafe { (*rand).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `rand` is live, so a method with a `settable_ctx_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*rand).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_RAND_CTX_gettable_params(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_gettable_params(ctx: *mut EvpRandCtx) -> *const OsslParam {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live per the contract.
    let Some(f) = (unsafe { (*meth).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `meth` is live, so a method with a `gettable_ctx_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*meth).prov) };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx, provctx) }
}

/// `const OSSL_PARAM *EVP_RAND_CTX_settable_params(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_settable_params(ctx: *mut EvpRandCtx) -> *const OsslParam {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live per the contract.
    let Some(f) = (unsafe { (*meth).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `meth` is live, so a method with a `settable_ctx_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*meth).prov) };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx, provctx) }
}

/// `void EVP_RAND_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_RAND *rand, void *arg),
/// void *arg)`.
///
/// A **NULL visitor is refused** rather than passed to a walk that would call it; the boundary is
/// `EVP_MD_do_all_provided`'s, measured in `docs/SECURITY_DIVERGENCE_POLICY.md`
/// D-MD-DOALL-NULL-1.
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpRand, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(visitor) = fn_ else {
        return;
    };
    // SAFETY: `visitor` is a live function pointer and `GenericDoAllFn` is the same ABI with an
    // unnamed pointee -- the authority's own cast. Nothing is called through it except by the walk,
    // in this call.
    let trampoline: GenericDoAllFn = unsafe { core::mem::transmute::<_, GenericDoAllFn>(visitor) };
    // SAFETY: `libctx` is NULL or live; the three class callbacks are this module's own.
    unsafe {
        evp_generic_do_all(
            libctx,
            OSSL_OP_RAND,
            trampoline,
            arg,
            evp_rand_from_algorithm as MethodFromAlgorithmFn,
            evp_rand_up_ref as MethodUpRefFn,
            evp_rand_free as MethodFreeFn,
        )
    }
}

/// `int EVP_RAND_names_do_all(const EVP_RAND *rand, void (*fn)(const char *name, void *data),
/// void *data)`.
///
/// # Safety
/// `rand` must be a live `EvpRand`; `fn_` NULL or a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_names_do_all(
    rand: *const EvpRand,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `rand` is live per the contract.
    let (prov, name_id) = unsafe { ((*rand).prov, (*rand).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------------------------

/// `int EVP_RAND_CTX_up_ref(EVP_RAND_CTX *ctx)`.
///
/// `ctx` is dereferenced unconditionally — the authority takes `&ctx->refcnt` with no test — so a
/// NULL is a caller error on both sides and not a checked refusal.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_up_ref(ctx: *mut EvpRandCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `EVP_RAND_CTX *EVP_RAND_CTX_new(EVP_RAND *rand, EVP_RAND_CTX *parent)`.
///
/// **Two references and four failure shapes**, and the order of them is the whole function:
///
///   1. a NULL method raises `EVP_R_INVALID_NULL_ALGORITHM` before anything is allocated;
///   2. the block and the context's own count come first, so a context exists before a parent is
///      considered;
///   3. the **parent's** reference is taken next — before the provider's constructor — so that a
///      constructor which calls back into the parent's callbacks can rely on it;
///   4. the provider's `newctx` is handed the parent's algorithm context **and the parent's
///      dispatch table**, and only if it succeeds is a reference taken on the method.
///
/// Step 4's short-circuit is the one this crate has already got wrong twice in one stratum: the
/// authority's `(ctx->algctx = rand->newctx(...)) == NULL || !EVP_RAND_up_ref(rand)` does **not**
/// take the reference when the constructor refuses, and evaluating both operands up front leaks
/// one. The failure path is unusually complete here and is transcribed whole: the constructor's
/// left-over is released, the context's own count is dropped, the block is freed, **and the
/// parent's reference is given back** — so a refused context does not leak its parent either.
///
/// # Safety
/// `rand` must be NULL or a live `EvpRand`; `parent` NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_new(
    rand: *mut EvpRand,
    parent: *mut EvpRandCtx,
) -> *mut EvpRandCtx {
    if rand.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_346) };
        return ptr::null_mut();
    }

    let ctx = CRYPTO_zalloc(core::mem::size_of::<EvpRandCtx>(), FILE, LINE_ZALLOC_CTX)
        .cast::<EvpRandCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe { (*ctx).refcnt = AtomicI32::new(1) };

    let mut parent_ctx: *mut c_void = ptr::null_mut();
    let mut parent_dispatch: *const OsslDispatch = ptr::null();
    if !parent.is_null() {
        // SAFETY: `parent` is live per the contract.
        if unsafe { EVP_RAND_CTX_up_ref(parent) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_RAND_359) };
            // SAFETY: `ctx` is this call's own block and nothing else holds it yet.
            unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
            return ptr::null_mut();
        }
        // SAFETY: `parent` is live.
        unsafe {
            parent_ctx = (*parent).algctx;
            // The parent's *method* is live, and its table is what a child constructor is handed.
            parent_dispatch = (*(*parent).meth).dispatch;
        }
    }

    // SAFETY: `rand` is live per the contract.
    let (newctx, freectx) = unsafe { ((*rand).newctx, (*rand).freectx) };
    let algctx = match newctx {
        Some(f) => {
            // SAFETY: `rand` is live, so a method with a `newctx` has a provider.
            let provctx = unsafe { ossl_provider_ctx((*rand).prov) };
            // SAFETY: `f` is the provider's own constructor; the last two arguments are the
            // parent's context and table, either of which may be NULL.
            unsafe { f(provctx, parent_ctx, parent_dispatch) }
        }
        None => ptr::null_mut(),
    };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).algctx = algctx };

    // The reference is taken only when the constructor succeeded: the authority's `||`.
    let ok = if algctx.is_null() {
        false
    } else {
        // SAFETY: `rand` is live per the contract.
        (unsafe { EVP_RAND_up_ref(rand) }) != 0
    };
    if !ok {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_371) };
        if let Some(f) = freectx {
            // SAFETY: `f` is the method's own releaser and `algctx` is what its constructor left.
            unsafe { f(algctx) };
        }
        // SAFETY: `ctx` is this call's own block.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
        // The parent's reference, given back. A NULL parent is accepted and does nothing.
        // SAFETY: `parent` is NULL or live per the contract, and this is the reference taken above.
        unsafe { EVP_RAND_CTX_free(parent) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx`, `rand` and `parent` are all live.
    unsafe {
        (*ctx).meth = rand;
        (*ctx).parent = parent;
    }
    ctx
}

/// `void EVP_RAND_CTX_free(EVP_RAND_CTX *ctx)`.
///
/// **Reference counted, and recursive.** The context's own count is dropped first, and only the
/// last reference releases anything: the provider's context, the method's reference, the block —
/// and then **the parent**, which is a release of a whole other context and may cascade. A
/// transcription that released one level would leave a tree of provider contexts alive, and one
/// that did not release the parent at all would leak a whole chain per context.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_free(ctx: *mut EvpRandCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    let last = unsafe { (*ctx).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference.
    let (meth, algctx, parent) = unsafe { ((*ctx).meth, (*ctx).algctx, (*ctx).parent) };
    // SAFETY: `meth` is live, because this context holds a reference to it.
    let freectx = unsafe { (*meth).freectx };
    if let Some(f) = freectx {
        // SAFETY: `f` is the method's own releaser and `algctx` is the context its constructor
        // handed back.
        unsafe { f(algctx) };
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).algctx = ptr::null_mut() };
    // SAFETY: `meth` is live and this is the reference `EVP_RAND_CTX_new` took.
    unsafe { EVP_RAND_free(meth) };
    // SAFETY: `ctx` came from this crate's allocator and has just been released of everything.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX) };
    // The parent's reference, and the recursion: a NULL parent is accepted and does nothing.
    // SAFETY: `parent` is NULL or live, and this is the reference `EVP_RAND_CTX_new` took.
    unsafe { EVP_RAND_CTX_free(parent) };
}

/// `EVP_RAND *EVP_RAND_CTX_get0_rand(EVP_RAND_CTX *ctx)`.
///
/// The **borrowed** method: no reference is taken.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_get0_rand(ctx: *mut EvpRandCtx) -> *mut EvpRand {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).meth }
}

/// `static int evp_rand_lock(EVP_RAND_CTX *rand)`.
///
/// **Answers 1 when there is no lock**, which is what makes the wrapper free for a provider that
/// does not need one — and what makes a provider that publishes a `lock` and no `unlock`
/// impossible, because the fetch refuses it.
///
/// # Safety
/// `rand` must be a live context whose `meth` is live.
unsafe fn evp_rand_lock(rand: *mut EvpRandCtx) -> c_int {
    // SAFETY: `rand` is live per the contract.
    let meth = unsafe { (*rand).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).lock }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*rand).algctx) }
}

/// `static void evp_rand_unlock(EVP_RAND_CTX *rand)`.
///
/// # Safety
/// `rand` must be a live context whose `meth` is live.
unsafe fn evp_rand_unlock(rand: *mut EvpRandCtx) {
    // SAFETY: `rand` is live per the contract.
    let meth = unsafe { (*rand).meth };
    // SAFETY: `meth` is live.
    let unlock = unsafe { (*meth).unlock };
    if let Some(f) = unlock {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f((*rand).algctx) };
    }
}

/// `int EVP_RAND_enable_locking(EVP_RAND_CTX *rand)`.
///
/// **The one operation that is not wrapped in the lock**, because it is the call that enables the
/// lock: a provider that answered through a lock it had not yet enabled would deadlock.
///
/// A method with no `enable_locking` raises `EVP_R_LOCKING_NOT_SUPPORTED` — the only refusal in this
/// file that is raised because a capability is *absent* rather than because an argument is wrong.
///
/// # Safety
/// `rand` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_enable_locking(rand: *mut EvpRandCtx) -> c_int {
    // SAFETY: `rand` is live per the contract.
    let meth = unsafe { (*rand).meth };
    // SAFETY: `meth` is live.
    if let Some(f) = unsafe { (*meth).enable_locking } {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        return unsafe { f((*rand).algctx) };
    }
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::EVP_RAND_98) };
    0
}

/// `static int evp_rand_get_ctx_params_locked(EVP_RAND_CTX *ctx, OSSL_PARAM params[])`.
///
/// **No test on `get_ctx_params`**: the fetch's structural check counts it, so by the time a context
/// exists the callback does. That is the one place this class's check has a consequence a reader
/// would otherwise miss — the callback is not optional here, and the reason is that `generate`
/// cannot work without it.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_get_ctx_params_locked(ctx: *mut EvpRandCtx, params: *mut OsslParam) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `get_ctx_params` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).get_ctx_params }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback, `algctx` is its context and `params` is the
    // caller's array.
    unsafe { f((*ctx).algctx, params) }
}

/// `static int evp_rand_set_ctx_params_locked(EVP_RAND_CTX *ctx, const OSSL_PARAM params[])`.
///
/// Answers **1** for a missing callback, unlike the read above — the two are asymmetric because a
/// *write* that nothing reads is a no-op while a *read* that nothing answers is a failure.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_set_ctx_params_locked(ctx: *mut EvpRandCtx, params: *const OsslParam) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).set_ctx_params }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback, `algctx` is its context and `params` is the
    // caller's array.
    unsafe { f((*ctx).algctx, params) }
}

/// `int EVP_RAND_CTX_get_params(EVP_RAND_CTX *ctx, OSSL_PARAM params[])`.
///
/// The lock/call/unlock shape, and the lock's refusal is a **0** rather than a raise: a provider
/// that could not be locked has already said so through its own error queue.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_get_params(
    ctx: *mut EvpRandCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_get_ctx_params_locked(ctx, params) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `int EVP_RAND_CTX_set_params(EVP_RAND_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_CTX_set_params(
    ctx: *mut EvpRandCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_set_ctx_params_locked(ctx, params) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static int evp_rand_instantiate_locked(EVP_RAND_CTX *ctx, unsigned int strength,
/// int prediction_resistance, const unsigned char *pstr, size_t pstr_len,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_instantiate_locked(
    ctx: *mut EvpRandCtx,
    strength: c_uint,
    prediction_resistance: c_int,
    pstr: *const c_uchar,
    pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `instantiate` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).instantiate }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
    // arguments.
    unsafe {
        f(
            (*ctx).algctx,
            strength,
            prediction_resistance,
            pstr,
            pstr_len,
            params,
        )
    }
}

/// `int EVP_RAND_instantiate(EVP_RAND_CTX *ctx, unsigned int strength,
/// int prediction_resistance, const unsigned char *pstr, size_t pstr_len,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `pstr` NULL or readable for `pstr_len` bytes; `params` NULL or
/// terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_instantiate(
    ctx: *mut EvpRandCtx,
    strength: c_uint,
    prediction_resistance: c_int,
    pstr: *const c_uchar,
    pstr_len: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe {
        evp_rand_instantiate_locked(ctx, strength, prediction_resistance, pstr, pstr_len, params)
    };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static int evp_rand_uninstantiate_locked(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_uninstantiate_locked(ctx: *mut EvpRandCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `uninstantiate` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).uninstantiate }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx) }
}

/// `int EVP_RAND_uninstantiate(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_uninstantiate(ctx: *mut EvpRandCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_uninstantiate_locked(ctx) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static int evp_rand_generate_locked(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *addin,
/// size_t addin_len)`.
///
/// **A chunked loop around the provider, and the chunk size is asked for rather than assumed.**
/// `max_request` comes from the context's own parameters, and an absent or zero answer is
/// `EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE` — a refusal *before* any bytes are produced, which is
/// why the fetch's structural check counts `get_ctx_params`. A provider with a maximum smaller than
/// the caller's request is therefore used correctly rather than refused, and one that answers zero
/// fails loudly instead of looping forever.
///
/// `prediction_resistance` is cleared after the first chunk, and the authority's comment says why:
/// the remaining chunks come from a DRBG that has already been reseeded once for this call, so
/// asking again would be asking twice for the same guarantee.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live; `out` writable for `outlen` bytes; `addin`
/// NULL or readable for `addin_len` bytes.
unsafe fn evp_rand_generate_locked(
    ctx: *mut EvpRandCtx,
    out: *mut c_uchar,
    mut outlen: usize,
    strength: c_uint,
    mut prediction_resistance: c_int,
    addin: *const c_uchar,
    addin_len: usize,
) -> c_int {
    let mut max_request: usize = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry and `params` has room for two; the key is a literal
    // and the value pointer is this frame's.
    unsafe {
        params[0] = OSSL_PARAM_construct_size_t(OSSL_RAND_PARAM_MAX_REQUEST, &mut max_request)
    };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live and `params` is a terminated array of this frame's storage.
    if unsafe { evp_rand_get_ctx_params_locked(ctx, params.as_mut_ptr()) } == 0 || max_request == 0
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_562) };
        return 0;
    }

    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `generate` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).generate }) else {
        return 0;
    };

    let mut out = out;
    while outlen > 0 {
        let chunk = if outlen > max_request {
            max_request
        } else {
            outlen
        };
        // SAFETY: `f` is the provider's own callback; `out` is the caller's buffer advanced by the
        // chunks already written, which is writable for `chunk` bytes because `chunk <= outlen`.
        if unsafe {
            f(
                (*ctx).algctx,
                out,
                chunk,
                strength,
                prediction_resistance,
                addin,
                addin_len,
            )
        } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EVP_RAND_569) };
            return 0;
        }
        outlen -= chunk;
        // SAFETY: `out` is the caller's buffer and `chunk` bytes of it have just been written.
        out = unsafe { out.add(chunk) };
        prediction_resistance = 0;
    }
    1
}

/// `int EVP_RAND_generate(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen,
/// unsigned int strength, int prediction_resistance, const unsigned char *addin,
/// size_t addin_len)`.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for `outlen` bytes; `addin` NULL or readable for
/// `addin_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_generate(
    ctx: *mut EvpRandCtx,
    out: *mut c_uchar,
    outlen: usize,
    strength: c_uint,
    prediction_resistance: c_int,
    addin: *const c_uchar,
    addin_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe {
        evp_rand_generate_locked(
            ctx,
            out,
            outlen,
            strength,
            prediction_resistance,
            addin,
            addin_len,
        )
    };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static int evp_rand_reseed_locked(EVP_RAND_CTX *ctx, int prediction_resistance,
/// const unsigned char *ent, size_t ent_len, const unsigned char *addin, size_t addin_len)`.
///
/// Answers **1** for a missing `reseed`: a DRBG with nothing to reseed is a success, not a refusal.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_reseed_locked(
    ctx: *mut EvpRandCtx,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    addin: *const c_uchar,
    addin_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).reseed }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
    // arguments.
    unsafe {
        f(
            (*ctx).algctx,
            prediction_resistance,
            ent,
            ent_len,
            addin,
            addin_len,
        )
    }
}

/// `int EVP_RAND_reseed(EVP_RAND_CTX *ctx, int prediction_resistance, const unsigned char *ent,
/// size_t ent_len, const unsigned char *addin, size_t addin_len)`.
///
/// # Safety
/// `ctx` must be a live context; `ent` and `addin` NULL or readable for their lengths.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_reseed(
    ctx: *mut EvpRandCtx,
    prediction_resistance: c_int,
    ent: *const c_uchar,
    ent_len: usize,
    addin: *const c_uchar,
    addin_len: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe {
        evp_rand_reseed_locked(ctx, prediction_resistance, ent, ent_len, addin, addin_len)
    };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static unsigned int evp_rand_strength_locked(EVP_RAND_CTX *ctx)`.
///
/// **Answers 0 for a failed read**, where `EVP_RAND_get_state` answers a state constant for the same
/// failure — the two functions disagree about what an unanswerable question means, and both
/// answers are in the API.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_strength_locked(ctx: *mut EvpRandCtx) -> c_uint {
    let mut strength: c_uint = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry and `params` has room for two; the key is a literal
    // and the value pointer is this frame's.
    unsafe { params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &mut strength) };
    params[1] = OSSL_PARAM_construct_end();
    // SAFETY: `ctx` is live and `params` is a terminated array of this frame's storage.
    if unsafe { evp_rand_get_ctx_params_locked(ctx, params.as_mut_ptr()) } == 0 {
        return 0;
    }
    strength
}

/// `unsigned int EVP_RAND_get_strength(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get_strength(ctx: *mut EvpRandCtx) -> c_uint {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_strength_locked(ctx) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `static int evp_rand_nonce_locked(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen)`.
///
/// **`nonce` is optional and its absence falls back to `generate`** — with the context's own
/// strength, no prediction resistance and no additional input, which is what a nonce is: a
/// generation the caller does not control. The provider's `nonce` answers a `size_t` and the
/// authority tests it `> 0`, so a provider that produced zero bytes is a refusal.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live; `out` writable for `outlen` bytes.
unsafe fn evp_rand_nonce_locked(ctx: *mut EvpRandCtx, out: *mut c_uchar, outlen: usize) -> c_int {
    // SAFETY: `ctx` is live and the lock is held by the caller.
    let str_ = unsafe { evp_rand_strength_locked(ctx) };
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    if let Some(f) = unsafe { (*meth).nonce } {
        // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
        // arguments. The last two are the same value: the authority asks for exactly `outlen`.
        return c_int::from((unsafe { f((*ctx).algctx, out, str_, outlen, outlen) }) > 0);
    }
    // SAFETY: `ctx` is live and this call holds the lock, so the `_locked` form is the right one.
    unsafe { evp_rand_generate_locked(ctx, out, outlen, str_, 0, ptr::null(), 0) }
}

/// `int EVP_RAND_nonce(EVP_RAND_CTX *ctx, unsigned char *out, size_t outlen)`.
///
/// The one operation with a **three-way argument check** before the lock: a NULL context, a NULL
/// buffer and a zero length all reach `ERR_R_PASSED_NULL_PARAMETER`. A zero length is not a legal
/// no-op here the way it is for `EVP_DigestUpdate`, and the reason is that a nonce of no bytes is
/// not a nonce.
///
/// # Safety
/// `ctx` must be NULL or a live context; `out` NULL or writable for `outlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_nonce(
    ctx: *mut EvpRandCtx,
    out: *mut c_uchar,
    outlen: usize,
) -> c_int {
    if ctx.is_null() || out.is_null() || outlen == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_RAND_656) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_nonce_locked(ctx, out, outlen) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

/// `int EVP_RAND_get_state(EVP_RAND_CTX *ctx)`.
///
/// **The state constant is the answer for a failed read**, where `EVP_RAND_get_strength` answers 0
/// for the same failure. `state` is left uninitialised by the authority and only written by a
/// successful read, so the `EVP_RAND_STATE_ERROR` assignment is what a caller sees — which is why
/// this transcription initialises it to that constant rather than to zero and then overwriting it.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_get_state(ctx: *mut EvpRandCtx) -> c_int {
    let mut state: c_int = EVP_RAND_STATE_ERROR;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry and `params` has room for two; the key is a literal
    // and the value pointer is this frame's.
    unsafe { params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_STATE, &mut state) };
    params[1] = OSSL_PARAM_construct_end();
    // SAFETY: `ctx` is live and `params` is a terminated array of this frame's storage.
    if unsafe { EVP_RAND_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
        state = EVP_RAND_STATE_ERROR;
    }
    state
}

/// `static int evp_rand_verify_zeroization_locked(EVP_RAND_CTX *ctx)`.
///
/// Answers **0** for a missing `verify_zeroization` — not 1. A provider that cannot prove its state
/// is zeroized has not proven it, and the class treats "cannot say" as "no".
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
unsafe fn evp_rand_verify_zeroization_locked(ctx: *mut EvpRandCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).verify_zeroization }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx) }
}

/// `int EVP_RAND_verify_zeroization(EVP_RAND_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_RAND_verify_zeroization(ctx: *mut EvpRandCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    if unsafe { evp_rand_lock(ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live and the lock was taken.
    let res = unsafe { evp_rand_verify_zeroization_locked(ctx) };
    // SAFETY: `ctx` is live and the lock is held by this call.
    unsafe { evp_rand_unlock(ctx) };
    res
}

// ---------------------------------------------------------------------------------------------
// `evp_rand_can_seed`, `evp_rand_get_seed` and `evp_rand_clear_seed` are **not here**. They are
// internal, are declared in `include/crypto/evp.h`, and their only callers are in
// `crypto/rand/rand_lib.c`, which is Phase 9's. The `get_seed` and `clear_seed` *fields* are filled
// by the walk above, because the walk is this file's; their three callers arrive with the stratum
// that needs them, in the same shape the MAC and KDF classes' SKEY fields did.
// ---------------------------------------------------------------------------------------------

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// A method built by hand, so the arms of this file that are not about fetching can be read
    /// without a provider.
    fn a_hand_built_rand() -> EvpRand {
        EvpRand {
            prov: ptr::null_mut(),
            name_id: 13,
            type_name: ptr::null_mut(),
            description: c"a hand-built RAND".as_ptr(),
            refcnt: AtomicI32::new(1),
            dispatch: ptr::null(),
            newctx: None,
            freectx: None,
            instantiate: None,
            uninstantiate: None,
            generate: None,
            reseed: None,
            nonce: None,
            enable_locking: None,
            lock: None,
            unlock: None,
            gettable_params: None,
            gettable_ctx_params: None,
            settable_ctx_params: None,
            get_params: None,
            get_ctx_params: None,
            set_ctx_params: None,
            verify_zeroization: None,
            get_seed: None,
            clear_seed: None,
        }
    }

    /// The coordinate of the last error raised, against a recorded site.
    fn assert_coordinate(site: &err_sites::ErrSite) {
        use crate::runtime::err::ERR_peek_last_error_all;

        let mut file: *const c_char = ptr::null();
        let mut line: c_int = 0;
        let mut func: *const c_char = ptr::null();
        let mut data: *const c_char = ptr::null();
        let mut flags: c_int = 0;
        // SAFETY: every output pointer is this frame's own storage.
        let code = unsafe {
            ERR_peek_last_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags)
        };
        assert_ne!(code, 0, "an error was raised");
        // SAFETY: the call wrote a NUL-terminated string the error state still owns.
        assert_eq!(unsafe { CStr::from_ptr(file) }, site.file, "file");
        assert_eq!(line, site.line, "line");
        // SAFETY: as above.
        assert_eq!(unsafe { CStr::from_ptr(func) }, site.func, "function");
    }

    /// `EVP_RAND_up_ref` is the one method-level reference taker in this stratum with a **NULL
    /// arm**, and it answers 1 — a success — rather than refusing. It exists so that the recursive
    /// release below can hand a NULL parent to itself.
    #[test]
    fn the_method_reference_taker_accepts_null() {
        let mut rand = a_hand_built_rand();
        let p: *mut EvpRand = ptr::addr_of_mut!(rand);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_RAND_up_ref(ptr::null_mut()), 1, "NULL is not a refusal");
            assert_eq!(EVP_RAND_up_ref(p), 1, "and neither is a live object");
            assert_eq!(rand.refcnt.load(Ordering::Acquire), 2);
            EVP_RAND_free(p);
            assert_eq!(
                rand.refcnt.load(Ordering::Acquire),
                1,
                "not the last one yet"
            );
            EVP_RAND_free(ptr::null_mut());
        }
    }

    /// The accessors and the four parameter entry points, on a method with no provider.
    #[test]
    fn the_method_accessors_read_fields_and_guard_null() {
        let rand = a_hand_built_rand();
        let p: *const EvpRand = ptr::addr_of!(rand);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(evp_rand_get_number(p), 13);
            assert!(EVP_RAND_get0_name(p).is_null());
            assert_eq!(
                CStr::from_ptr(EVP_RAND_get0_description(p)),
                c"a hand-built RAND"
            );
            assert!(EVP_RAND_get0_provider(p).is_null());
            assert_eq!(
                EVP_RAND_is_a(p, c"whatever".as_ptr()),
                1,
                "the NULL-provider quirk"
            );
            assert_eq!(EVP_RAND_is_a(ptr::null(), c"whatever".as_ptr()), 0);
            assert_eq!(EVP_RAND_names_do_all(p, None, ptr::null_mut()), 1);
            assert!(EVP_RAND_gettable_params(p).is_null());
            assert!(EVP_RAND_gettable_ctx_params(p).is_null());
            assert!(EVP_RAND_settable_ctx_params(p).is_null());
            assert_eq!(EVP_RAND_get_params(p.cast_mut(), ptr::null_mut()), 1);
        }
    }

    /// The three-way argument check `EVP_RAND_nonce` makes, at its own coordinate, and the fact
    /// that a **zero length** is one of the three — a nonce of no bytes is not a nonce, where a
    /// zero-length digest update is a legal call.
    #[test]
    fn the_nonce_refuses_a_null_and_a_zero_length() {
        let mut rand = a_hand_built_rand();
        let mut ctx = EvpRandCtx {
            meth: ptr::addr_of_mut!(rand),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
        };
        let out = [0u8; 16];
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            assert_eq!(
                EVP_RAND_nonce(ptr::null_mut(), out.as_ptr() as *mut c_uchar, 16),
                0
            );
            assert_coordinate(&err_sites::EVP_RAND_656);
            assert_eq!(
                EVP_RAND_nonce(ptr::addr_of_mut!(ctx), ptr::null_mut(), 16),
                0
            );
            assert_coordinate(&err_sites::EVP_RAND_656);
            assert_eq!(
                EVP_RAND_nonce(ptr::addr_of_mut!(ctx), out.as_ptr() as *mut c_uchar, 0),
                0
            );
            assert_coordinate(&err_sites::EVP_RAND_656);
        }
    }

    /// A NULL method is `EVP_R_INVALID_NULL_ALGORITHM` before anything is allocated — the third
    /// class in this stratum to refuse that argument, and the third different answer: the MAC class
    /// dereferences it, the KDF class refuses silently, and this one raises.
    #[test]
    fn a_null_method_raises_before_anything_is_allocated() {
        // SAFETY: NULL is the documented refusal for this class.
        unsafe {
            assert!(EVP_RAND_CTX_new(ptr::null_mut(), ptr::null_mut()).is_null());
            assert_coordinate(&err_sites::EVP_RAND_346);
        }
    }

    /// The wrapping pair: a method with no `lock` answers 1 for every acquisition, so the eleven
    /// locked entry points are free for a provider that does not need one — and a method with a
    /// `lock` is *used*, which the counters show.
    #[test]
    fn the_locking_pair_is_optional_and_free_when_absent() {
        static LOCKS: AtomicI32 = AtomicI32::new(0);
        static UNLOCKS: AtomicI32 = AtomicI32::new(0);

        /// `static int lock(void *vctx)` — counts and accepts.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn counting_lock(_vctx: *mut c_void) -> c_int {
            LOCKS.fetch_add(1, Ordering::AcqRel);
            1
        }

        /// `static void unlock(void *vctx)` — counts.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn counting_unlock(_vctx: *mut c_void) {
            UNLOCKS.fetch_add(1, Ordering::AcqRel);
        }

        let mut rand = a_hand_built_rand();
        let mut ctx = EvpRandCtx {
            meth: ptr::addr_of_mut!(rand),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
        };
        let p: *mut EvpRandCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            /* No lock: the acquisition answers 1 and the call goes through -- and `get_params`
             * answers 1 for a missing `get_ctx_params`, so the whole thing succeeds. */
            assert_eq!(EVP_RAND_CTX_set_params(p, ptr::null()), 1);
            assert_eq!(LOCKS.load(Ordering::Acquire), 0);

            rand.lock = Some(counting_lock);
            rand.unlock = Some(counting_unlock);
            /* The writes above are read back through the pointer the context holds, so that the
             * compiler sees the method it is about to be called through is the one just built. */
            assert!(rand.lock.is_some() && rand.unlock.is_some());
            assert_eq!(EVP_RAND_CTX_set_params(p, ptr::null()), 1);
            assert_eq!(LOCKS.load(Ordering::Acquire), 1, "the lock was taken");
            assert_eq!(UNLOCKS.load(Ordering::Acquire), 1, "and released");
        }
    }

    /// `EVP_RAND_enable_locking` is the one entry point that is **not** wrapped in the lock, and a
    /// method with no `enable_locking` raises rather than answering quietly.
    #[test]
    fn enable_locking_is_not_itself_locked_and_raises_when_absent() {
        static ENABLES: AtomicI32 = AtomicI32::new(0);

        /// `static int enable_locking(void *vctx)` — counts and accepts.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn counting_enable(_vctx: *mut c_void) -> c_int {
            ENABLES.fetch_add(1, Ordering::AcqRel);
            1
        }

        let mut rand = a_hand_built_rand();
        let mut ctx = EvpRandCtx {
            meth: ptr::addr_of_mut!(rand),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
        };
        let p: *mut EvpRandCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            assert_eq!(EVP_RAND_enable_locking(p), 0);
            assert_coordinate(&err_sites::EVP_RAND_98);
            rand.enable_locking = Some(counting_enable);
            assert!(rand.enable_locking.is_some());
            assert_eq!(EVP_RAND_enable_locking(p), 1);
            assert_eq!(ENABLES.load(Ordering::Acquire), 1);
        }
    }

    /// `EVP_RAND_verify_zeroization` answers **0** for a missing verifier — not 1. A provider that
    /// cannot prove its state is zeroized has not proven it.
    #[test]
    fn an_unprovable_zeroization_is_a_no() {
        let mut rand = a_hand_built_rand();
        let mut ctx = EvpRandCtx {
            meth: ptr::addr_of_mut!(rand),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
        };
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            assert_eq!(EVP_RAND_verify_zeroization(ptr::addr_of_mut!(ctx)), 0);
        }
    }

    /// `EVP_RAND_get_state` answers `EVP_RAND_STATE_ERROR` when the read fails, where
    /// `EVP_RAND_get_strength` answers 0 for the same failure — and neither is a raise.
    #[test]
    fn an_unanswerable_state_and_strength_are_constants_rather_than_refusals() {
        let mut rand = a_hand_built_rand();
        let mut ctx = EvpRandCtx {
            meth: ptr::addr_of_mut!(rand),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
        };
        let p: *mut EvpRandCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            /* With no `get_ctx_params` at all the read answers 0, so both constants appear. */
            assert_eq!(EVP_RAND_get_state(p), EVP_RAND_STATE_ERROR);
            assert_eq!(EVP_RAND_get_strength(p), 0);
        }
    }

    /// The context reference count, and the recursion: releasing the last reference to a child
    /// releases its parent's reference too.
    ///
    /// The two contexts are stack objects with a fabricated provider context, so nothing is
    /// dereferenced by the provider — but the *chain* is real: `EVP_RAND_CTX_free(child)` with a
    /// count of 1 must drop the parent's count as well, and the test asserts the arithmetic rather
    /// than the calls.
    #[test]
    fn the_last_release_drops_the_parents_reference() {
        let mut child_meth = a_hand_built_rand();
        let mut parent_meth = a_hand_built_rand();
        let mut parent = EvpRandCtx {
            meth: ptr::addr_of_mut!(parent_meth),
            algctx: ptr::null_mut(),
            parent: ptr::null_mut(),
            refcnt: AtomicI32::new(2),
        };
        let mut child = EvpRandCtx {
            meth: ptr::addr_of_mut!(child_meth),
            algctx: ptr::null_mut(),
            parent: ptr::addr_of_mut!(parent),
            refcnt: AtomicI32::new(2),
        };
        // SAFETY: both contexts and both methods are this frame's own live objects, and neither
        // method has a `freectx`, so nothing is called through a fabricated pointer.
        unsafe {
            assert_eq!(EVP_RAND_CTX_up_ref(ptr::addr_of_mut!(child)), 1);
            assert_eq!(child.refcnt.load(Ordering::Acquire), 3);
            EVP_RAND_CTX_free(ptr::addr_of_mut!(child));
            assert_eq!(child.refcnt.load(Ordering::Acquire), 2, "not the last one");
            assert_eq!(
                parent.refcnt.load(Ordering::Acquire),
                2,
                "so the parent was not touched"
            );
            /* The two remaining references are the test's own; dropping one of the child's leaves
             * it non-zero and still does not touch the parent. The recursion itself is exercised
             * by the court, which can build a real parent. */
            EVP_RAND_CTX_free(ptr::addr_of_mut!(child));
            assert_eq!(child.refcnt.load(Ordering::Acquire), 1);
            assert_eq!(parent.refcnt.load(Ordering::Acquire), 2);
            EVP_RAND_CTX_free(ptr::null_mut());
        }
    }
}
