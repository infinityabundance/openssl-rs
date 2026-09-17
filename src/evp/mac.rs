//! Phase 7.3e — the `EVP_MAC` method object and the context it is run through.
//!
//! `crypto/evp/mac_meth.c` and `crypto/evp/mac_lib.c`, transcribed together because they are one
//! class: the first is the object a fetch produces and the second is the object a caller makes
//! *from* it. `crypto/evp/kdf_meth.c` and `kdf_lib.c` are the same pair for `EVP_KDF` and are the
//! other half of this subphase.
//!
//! ## The first class with no legacy half
//!
//! `EVP_MAC` and `EVP_KDF` were introduced *by* the provider interface, so unlike `EVP_MD` and
//! `EVP_CIPHER` they have no pre-3.0 object underneath them. `struct evp_mac_st` is nine
//! provider callbacks and four bookkeeping fields; there is no `origin`, no function-pointer table
//! a caller can fill in, and no `md_data`. Three consequences follow, and each is a place where a
//! reader who had internalised the digest class would guess wrong:
//!
//!   * **a method cannot be built by hand.** `EVP_MAC_meth_new` does not exist in any OpenSSL
//!     version. The only way to obtain one is to fetch it, so an `EVP_MAC` is *always*
//!     `EVP_ORIG_DYNAMIC` in spirit, and `EVP_MAC_free` has no origin test to make.
//!   * **a method whose callbacks are missing is refused at fetch time**, not tolerated. The
//!     digest class accepts a handler with *no* structural functions when a standalone one-shot
//!     is present, because a legacy method might be behind it. This class accepts exactly
//!     `fnmaccnt == 3 && fnctxcnt == 2` and nothing else, so by the time a caller holds an
//!     `EVP_MAC`, `newctx`, `freectx`, `update` and `final` are all non-NULL and there is no
//!     "legacy arm" to fall back to.
//!   * **the size question has no fallback to a method constant.** `EVP_MD` caches `md_size` at
//!     fetch time from the provider; `EVP_MAC_CTX_get_mac_size` *asks the context* every time,
//!     because a MAC's output size can depend on parameters set after the fetch. That is why
//!     `get_size_t_ctx_param` exists and why it can answer 0.
//!
//! ## The structural check is `3` and `2`, and the `3` counts `init_skey`
//!
//! `fnmaccnt` counts `init`, `update`, `final` and — through the `mac_init_found` flag — either
//! `init` **or** `init_skey`, so a provider that publishes only the symmetric-key form is legal.
//! `fnctxcnt` counts `newctx` and `freectx` and nothing else: `dupctx` is deliberately not counted,
//! which is why `EVP_MAC_CTX_dup` on a method with no `dupctx` is a NULL rather than something the
//! fetch refused. `EVP_KDF`'s check is the same shape with a different arithmetic, and finding the
//! two out is the point of transcribing them rather than sharing a helper.
//!
//! ## Two raise sites that look wrong and are the authority's
//!
//! `EVP_MAC_init` and `EVP_MAC_init_SKEY` raise
//! `ERR_raise(ERR_R_EVP_LIB, ERR_R_UNSUPPORTED)` — the **library** argument is a reason constant.
//! The `ERR` registry resolves the library from the raised code's `ERR_LIB_MASK`, so the error a
//! caller reads back is `EVP`/`UNSUPPORTED` and the oddity is invisible; the recorded sites in
//! `src/runtime/err_sites.rs` carry the authority's own numbers, which is why this crate can
//! reproduce it exactly rather than "fixing" it into a raise from the EVP library.
//!
//! ## What is not here
//!
//! `EVP_MAC_init_SKEY` takes an `EVP_SKEY`, whose `EVP_SKEYMGMT` is 7.3f's, and it is the one row
//! of this subphase handed forward with the dependency named. `EVP_MAC_do_all_provided`'s NULL
//! visitor is refused rather than called through, for the reason `EVP_MD_do_all_provided`'s is
//! (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MD-DOALL-NULL-1).
//!
//! One more boundary was *found* by transcribing this file rather than known in advance, and it is
//! worth naming here because it is in `EVP_MAC_CTX_dup`'s own body: the authority reaches
//! `src->meth->dupctx(src->algctx)` with no test, and `dupctx` is deliberately **not** counted by
//! the structural check — so a method with no duplicator is fetchable and usable right up to the
//! moment it is duplicated, at which point the authority faults. Measured (exit 139) and recorded
//! as `D-MAC-DUPCTX-NULL-1`; this crate answers the NULL that the authority's *next* statement
//! would have produced, so the boundary is one step wide.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
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
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_locate_const, OsslParam,
};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// `OSSL_OP_MAC` — `include/openssl/core_dispatch.h`. The third operation the walk visits, and
/// the one this class is fetched under.
const OSSL_OP_MAC: c_int = 3;

/// The authority's translation unit, so a failing allocation or free records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c".as_ptr();
/// `evp_mac_new`'s `OPENSSL_zalloc(sizeof(*mac))` (line 49), in `mac_meth.c`.
const LINE_ZALLOC_MAC: c_int = 49;
/// `evp_mac_free`'s `OPENSSL_free(mac)`, in `mac_meth.c`.
///
/// The three frees in `evp_mac_free` are one after another with no intervening call, so the line
/// numbers are the authority's own and they differ by one; each is named rather than derived so a
/// reader can check them against the file.
const LINE_FREE_MAC: c_int = 42;
/// `evp_mac_free`'s `OPENSSL_free(mac->type_name)`, in `mac_meth.c`.
const LINE_FREE_TYPE_NAME: c_int = 39;
/// `EVP_MAC_CTX_new`'s `OPENSSL_zalloc(sizeof(EVP_MAC_CTX))` (line 24).
const LINE_ZALLOC_CTX: c_int = 24;
/// `EVP_MAC_CTX_new`'s `OPENSSL_free(ctx)` (line 32).
const LINE_FREE_CTX_ON_NEW: c_int = 32;
/// `EVP_MAC_CTX_free`'s `OPENSSL_free(ctx)` (line 47).
const LINE_FREE_CTX: c_int = 47;
/// `EVP_MAC_CTX_dup`'s `OPENSSL_malloc(sizeof(*dst))` (line 57).
const LINE_MALLOC_CTX_DUP: c_int = 57;
/// `EVP_MAC_CTX_dup`'s `OPENSSL_free(dst)` (line 65).
const LINE_FREE_CTX_ON_DUP: c_int = 65;
/// `EVP_Q_mac`'s `OPENSSL_malloc(len)` (line 299).
const LINE_MALLOC_Q_MAC: c_int = 299;
/// `EVP_Q_mac`'s `OPENSSL_free(out)` (line 301).
const LINE_FREE_Q_MAC: c_int = 301;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the thirteen function-pointer types.
//
// `OSSL_FUNC_MAC_*` from `include/openssl/core_dispatch.h`, and each type is what
// `OSSL_CORE_MAKE_FUNC` generates for the corresponding entry. The ids are part of the wire format
// a provider is compiled against, so they are copied rather than derived.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_MAC_NEWCTX`.
const OSSL_FUNC_MAC_NEWCTX: c_int = 1;
/// `OSSL_FUNC_MAC_DUPCTX`.
const OSSL_FUNC_MAC_DUPCTX: c_int = 2;
/// `OSSL_FUNC_MAC_FREECTX`.
const OSSL_FUNC_MAC_FREECTX: c_int = 3;
/// `OSSL_FUNC_MAC_INIT`.
const OSSL_FUNC_MAC_INIT: c_int = 4;
/// `OSSL_FUNC_MAC_UPDATE`.
const OSSL_FUNC_MAC_UPDATE: c_int = 5;
/// `OSSL_FUNC_MAC_FINAL`.
const OSSL_FUNC_MAC_FINAL: c_int = 6;
/// `OSSL_FUNC_MAC_GET_PARAMS`.
const OSSL_FUNC_MAC_GET_PARAMS: c_int = 7;
/// `OSSL_FUNC_MAC_GET_CTX_PARAMS`.
const OSSL_FUNC_MAC_GET_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_MAC_SET_CTX_PARAMS`.
const OSSL_FUNC_MAC_SET_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_MAC_GETTABLE_PARAMS`.
const OSSL_FUNC_MAC_GETTABLE_PARAMS: c_int = 10;
/// `OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS: c_int = 11;
/// `OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS: c_int = 12;
/// `OSSL_FUNC_MAC_INIT_SKEY`. Counted toward the same total as `INIT`, which is why this class's
/// structural check accepts a provider that publishes the symmetric-key form alone.
const OSSL_FUNC_MAC_INIT_SKEY: c_int = 13;

/// `OSSL_FUNC_mac_newctx_fn` — `void *(*)(void *provctx)`.
pub(crate) type MacNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_mac_dupctx_fn` — `void *(*)(void *src)`.
pub(crate) type MacDupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_mac_freectx_fn` — `void (*)(void *mctx)`.
pub(crate) type MacFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_mac_init_fn` — `int (*)(void *mctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])`.
pub(crate) type MacInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_uchar, usize, *const OsslParam) -> c_int;
/// `OSSL_FUNC_mac_update_fn` — `int (*)(void *mctx, const unsigned char *in, size_t inl)`.
pub(crate) type MacUpdateFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
/// `OSSL_FUNC_mac_final_fn` — `int (*)(void *mctx, unsigned char *out, size_t *outl,
/// size_t outsize)`.
pub(crate) type MacFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_mac_gettable_params_fn` — `const OSSL_PARAM *(*)(void *provctx)`.
pub(crate) type MacGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_mac_gettable_ctx_params_fn` — `const OSSL_PARAM *(*)(void *mctx, void *provctx)`.
pub(crate) type MacGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_mac_settable_ctx_params_fn` — the same signature.
pub(crate) type MacSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_mac_get_params_fn` — `int (*)(OSSL_PARAM params[])`.
pub(crate) type MacGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `OSSL_FUNC_mac_get_ctx_params_fn` — `int (*)(void *mctx, OSSL_PARAM params[])`.
pub(crate) type MacGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_mac_set_ctx_params_fn` — `int (*)(void *mctx, const OSSL_PARAM params[])`.
pub(crate) type MacSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_mac_init_skey_fn` — `int (*)(void *mctx, void *key, const OSSL_PARAM params[])`.
///
/// The `void *key` is an `EVP_SKEY`'s `keydata`, not the `EVP_SKEY` — which is why the method
/// object's field is typed with an opaque pointer rather than with 7.3f's type. It is 7.3f's
/// obligation either way; see `EVP_MAC_init_SKEY` below.
pub(crate) type MacInitSkeyFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;

/// `OSSL_MAC_PARAM_SIZE` — `include/openssl/core_names.h`.
const OSSL_MAC_PARAM_SIZE: *const c_char = c"size".as_ptr();
/// `OSSL_MAC_PARAM_BLOCK_SIZE` — `include/openssl/core_names.h`.
///
/// **`"block-size"`, with a hyphen.** The digest class's key is `"blocksize"` and the cipher
/// class's is `"blocksize"` too, so a reader who pattern-matched from either would build a
/// descriptor the provider does not recognise and `EVP_MAC_CTX_get_block_size` would answer 0 for
/// every MAC in existence without a single error anywhere.
const OSSL_MAC_PARAM_BLOCK_SIZE: *const c_char = c"block-size".as_ptr();
/// `OSSL_MAC_PARAM_XOF` — `include/openssl/core_names.h`.
const OSSL_MAC_PARAM_XOF: *const c_char = c"xof".as_ptr();
/// `OSSL_MAC_PARAM_DIGEST` — `include/openssl/core_names.h`, aliased to `OSSL_ALG_PARAM_DIGEST`.
const OSSL_MAC_PARAM_DIGEST: *const c_char = c"digest".as_ptr();
/// `OSSL_MAC_PARAM_CIPHER` — `include/openssl/core_names.h`, aliased to `OSSL_ALG_PARAM_CIPHER`.
const OSSL_MAC_PARAM_CIPHER: *const c_char = c"cipher".as_ptr();

/// `struct evp_mac_st` — `EVP_MAC`, from `include/crypto/evp.h`.
///
/// Nine callbacks and four bookkeeping fields, in the authority's order. Every callback is an
/// `Option` because the authority tests each one for NULL before calling it — and because
/// `evp_mac_from_algorithm` fills each field only if it is still NULL, which is how the *first*
/// entry for an id wins.
///
/// `pub` for the reason every internal type in an exported signature is: eleven exported functions
/// take or return one, Rust requires the type of an exported item's parameter to be at least as
/// visible, and the authority keeps `evp_mac_st` in `include/crypto/evp.h`, which is not installed.
/// Every field is `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpMac {
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
    /// `OSSL_FUNC_mac_newctx_fn *newctx`.
    pub(crate) newctx: Option<MacNewCtxFn>,
    /// `OSSL_FUNC_mac_dupctx_fn *dupctx`.
    pub(crate) dupctx: Option<MacDupCtxFn>,
    /// `OSSL_FUNC_mac_freectx_fn *freectx`.
    pub(crate) freectx: Option<MacFreeCtxFn>,
    /// `OSSL_FUNC_mac_init_fn *init`.
    pub(crate) init: Option<MacInitFn>,
    /// `OSSL_FUNC_mac_update_fn *update`.
    pub(crate) update: Option<MacUpdateFn>,
    /// `OSSL_FUNC_mac_final_fn *final`.
    pub(crate) final_: Option<MacFinalFn>,
    /// `OSSL_FUNC_mac_gettable_params_fn *gettable_params`.
    pub(crate) gettable_params: Option<MacGettableParamsFn>,
    /// `OSSL_FUNC_mac_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<MacGettableCtxParamsFn>,
    /// `OSSL_FUNC_mac_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<MacSettableCtxParamsFn>,
    /// `OSSL_FUNC_mac_get_params_fn *get_params`.
    pub(crate) get_params: Option<MacGetParamsFn>,
    /// `OSSL_FUNC_mac_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<MacGetCtxParamsFn>,
    /// `OSSL_FUNC_mac_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<MacSetCtxParamsFn>,
    /// `OSSL_FUNC_mac_init_skey_fn *init_skey`.
    pub(crate) init_skey: Option<MacInitSkeyFn>,
}

/// `struct evp_mac_ctx_st` — `EVP_MAC_CTX`, from `crypto/evp/evp_local.h`.
///
/// **Two fields.** The method and the provider's opaque context, and nothing else — which is the
/// smallest context object in the EVP layer and the clearest statement of what the provider
/// interface moved: everything that used to live on the context now lives behind `algctx`.
///
/// `pub` for the same reason `EvpMac` is.
#[repr(C)]
pub struct EvpMacCtx {
    /// `EVP_MAC *meth` — the method, holding a reference of this context's own.
    pub(crate) meth: *mut EvpMac,
    /// `void *algctx` — the provider's context, from `newctx`.
    pub(crate) algctx: *mut c_void,
}

// ---------------------------------------------------------------------------------------------
// The method object
// ---------------------------------------------------------------------------------------------

/// `static int evp_mac_up_ref(void *vmac)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vmac` must be a live `EvpMac`.
unsafe extern "C" fn evp_mac_up_ref(vmac: *mut c_void) -> c_int {
    // SAFETY: `vmac` is live per the contract.
    unsafe { EVP_MAC_up_ref(vmac.cast::<EvpMac>()) }
}

/// `static void evp_mac_free(void *vmac)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vmac` must be NULL or a live `EvpMac`.
unsafe extern "C" fn evp_mac_free(vmac: *mut c_void) {
    // SAFETY: `vmac` is NULL or live per the contract.
    unsafe { EVP_MAC_free(vmac.cast::<EvpMac>()) };
}

/// `static void *evp_mac_new(void)`.
///
/// A zeroed block and a reference count of 1. **There is no `origin` field to set**, which is the
/// whole difference from `evp_md_new`: a method of this class exists only as the answer to a fetch,
/// so there is no table that could own one and no half of the object that is not the provider's.
///
/// # Safety
/// No preconditions: it allocates and writes one field.
unsafe fn evp_mac_new() -> *mut EvpMac {
    let mac = CRYPTO_zalloc(core::mem::size_of::<EvpMac>(), FILE, LINE_ZALLOC_MAC).cast::<EvpMac>();
    if mac.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `mac` is a fresh zeroed block this call owns.
    unsafe { (*mac).refcnt = AtomicI32::new(1) };
    mac
}

/// `static void *evp_mac_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// The class constructor `evp_generic_fetch` is handed. It is `evp_md_from_algorithm`'s shape with
/// a different arithmetic and no legacy NID to resolve, and the two counters are the whole of it:
///
///   * `fnmaccnt` counts `update`, `final`, and **either** `init` **or** `init_skey`. The
///     `mac_init_found` flag is what makes the last one an *or* rather than an addition, so a
///     provider that publishes the symmetric-key initialiser and not the byte-string one has a
///     count of 3 and is accepted;
///   * `fnctxcnt` counts `newctx` and `freectx` and **not** `dupctx`. That asymmetry is deliberate
///     and observable: without `dupctx` the method is still fetchable and `EVP_MAC_CTX_dup` is the
///     NULL of a method that cannot copy, rather than a fetch that failed.
///
/// The check is `!= 3 || != 2` rather than `!= 3 && != 2`, so a provider with four mac functions
/// and two context functions is refused as loudly as one with two mac functions. That is not the
/// digest class's rule, which has a legal five-function arm.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live or NULL.
unsafe extern "C" fn evp_mac_from_algorithm(
    name_id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let mac = unsafe { evp_mac_new() };
    if mac.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_METH_66) };
        return ptr::null_mut();
    }

    // SAFETY: `mac` is live.
    unsafe { (*mac).name_id = name_id };

    // SAFETY: `algodef` is live per the contract.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `mac` is this call's own object.
        unsafe { EVP_MAC_free(mac) };
        return ptr::null_mut();
    }
    // SAFETY: `mac` is live and `type_name` is the string just allocated for it.
    unsafe { (*mac).type_name = type_name };
    // SAFETY: `algodef` is live.
    unsafe { (*mac).description = (*algodef).algorithm_description };

    let mut fns = fns;
    let mut fnmaccnt = 0;
    let mut fnctxcnt = 0;
    let mut mac_init_found = false;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator. Each arm reads `function_id` before deciding, and fills its field only if the
    // field is still NULL -- so the *first* entry for an id wins, which is every class's rule.
    unsafe {
        while (*fns).function_id != OSSL_DISPATCH_END {
            let id = (*fns).function_id;
            match id {
                OSSL_FUNC_MAC_NEWCTX if (*mac).newctx.is_none() => {
                    (*mac).newctx = entry_function::<MacNewCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_MAC_DUPCTX if (*mac).dupctx.is_none() => {
                    (*mac).dupctx = entry_function::<MacDupCtxFn>(fns);
                }
                OSSL_FUNC_MAC_FREECTX if (*mac).freectx.is_none() => {
                    (*mac).freectx = entry_function::<MacFreeCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_MAC_INIT if (*mac).init.is_none() => {
                    (*mac).init = entry_function::<MacInitFn>(fns);
                    mac_init_found = true;
                }
                OSSL_FUNC_MAC_UPDATE if (*mac).update.is_none() => {
                    (*mac).update = entry_function::<MacUpdateFn>(fns);
                    fnmaccnt += 1;
                }
                OSSL_FUNC_MAC_FINAL if (*mac).final_.is_none() => {
                    (*mac).final_ = entry_function::<MacFinalFn>(fns);
                    fnmaccnt += 1;
                }
                OSSL_FUNC_MAC_GETTABLE_PARAMS if (*mac).gettable_params.is_none() => {
                    (*mac).gettable_params = entry_function::<MacGettableParamsFn>(fns);
                }
                OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS if (*mac).gettable_ctx_params.is_none() => {
                    (*mac).gettable_ctx_params = entry_function::<MacGettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS if (*mac).settable_ctx_params.is_none() => {
                    (*mac).settable_ctx_params = entry_function::<MacSettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_MAC_GET_PARAMS if (*mac).get_params.is_none() => {
                    (*mac).get_params = entry_function::<MacGetParamsFn>(fns);
                }
                OSSL_FUNC_MAC_GET_CTX_PARAMS if (*mac).get_ctx_params.is_none() => {
                    (*mac).get_ctx_params = entry_function::<MacGetCtxParamsFn>(fns);
                }
                OSSL_FUNC_MAC_SET_CTX_PARAMS if (*mac).set_ctx_params.is_none() => {
                    (*mac).set_ctx_params = entry_function::<MacSetCtxParamsFn>(fns);
                }
                OSSL_FUNC_MAC_INIT_SKEY if (*mac).init_skey.is_none() => {
                    (*mac).init_skey = entry_function::<MacInitSkeyFn>(fns);
                    mac_init_found = true;
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }

    // The `init`-or-`init_skey` fold, and then the check.
    fnmaccnt += c_int::from(mac_init_found);
    if fnmaccnt != 3 || fnctxcnt != 2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_METH_159) };
        // SAFETY: `mac` is this call's own object.
        unsafe { EVP_MAC_free(mac) };
        return ptr::null_mut();
    }

    if !prov.is_null() {
        // SAFETY: `prov` is live per the contract.
        if unsafe { ossl_provider_up_ref(prov) } == 0 {
            // SAFETY: `mac` is this call's own object.
            unsafe { EVP_MAC_free(mac) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `mac` is live.
    unsafe { (*mac).prov = prov };

    mac.cast::<c_void>()
}

/// `EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `libctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_fetch(
    libctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpMac {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            libctx,
            OSSL_OP_MAC,
            algorithm,
            properties,
            evp_mac_from_algorithm as MethodFromAlgorithmFn,
            evp_mac_up_ref as MethodUpRefFn,
            evp_mac_free as MethodFreeFn,
        )
    }
    .cast::<EvpMac>()
}

/// `int EVP_MAC_up_ref(EVP_MAC *mac)`.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_up_ref(mac: *mut EvpMac) -> c_int {
    // SAFETY: `mac` is live per the contract.
    unsafe { (*mac).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void EVP_MAC_free(EVP_MAC *mac)`.
///
/// The order is the authority's: the name, the provider reference, the block. The reference count
/// is an `AtomicI32` here rather than the authority's `CRYPTO_REF_COUNT`, and the difference is
/// only in what the count is stored in — the last-reference test is the same, and it is why the
/// count is *not* cleared: the block is released with it.
///
/// # Safety
/// `mac` must be NULL or a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_free(mac: *mut EvpMac) {
    if mac.is_null() {
        return;
    }
    // SAFETY: `mac` is live per the contract.
    let last = unsafe { (*mac).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference and the block is this call's.
    unsafe {
        CRYPTO_free((*mac).type_name.cast::<c_void>(), FILE, LINE_FREE_TYPE_NAME);
        ossl_provider_free((*mac).prov);
        CRYPTO_free(mac.cast::<c_void>(), FILE, LINE_FREE_MAC);
    }
}

/// `int evp_mac_get_number(const EVP_MAC *mac)` — internal, and the namemap identity.
///
/// `pub(crate)` because its only caller is 7.6's `HMAC`/`CMAC` façade, which needs the same number
/// `EVP_MAC_is_a` resolves against.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[allow(dead_code)] // no caller until 7.6's HMAC/CMAC façade lands
pub(crate) unsafe fn evp_mac_get_number(mac: *const EvpMac) -> c_int {
    // SAFETY: `mac` is live per the contract.
    unsafe { (*mac).name_id }
}

/// `const OSSL_PROVIDER *EVP_MAC_get0_provider(const EVP_MAC *mac)`.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_get0_provider(mac: *const EvpMac) -> *const OsslProvider {
    // SAFETY: `mac` is live per the contract.
    unsafe { (*mac).prov }
}

/// `const OSSL_PARAM *EVP_MAC_gettable_params(const EVP_MAC *mac)`.
///
/// The callback takes the **provider context**, because a method-level parameter list is a
/// constant of the provider and not of any one method.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_gettable_params(mac: *const EvpMac) -> *const OsslParam {
    // SAFETY: `mac` is live per the contract.
    let Some(f) = (unsafe { (*mac).gettable_params }) else {
        return ptr::null();
    };
    // SAFETY: `mac` is live, so a method with a `gettable_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*mac).prov) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `const OSSL_PARAM *EVP_MAC_gettable_ctx_params(const EVP_MAC *mac)`.
///
/// The **method-level** form of the context question, which is why the first argument is NULL: the
/// list is asked for with no context to describe. `EVP_MAC_CTX_gettable_params` is the same
/// question asked with one, and a provider may answer them differently — which is exactly what the
/// two of them being separate functions allows.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_gettable_ctx_params(mac: *const EvpMac) -> *const OsslParam {
    // SAFETY: `mac` is live per the contract.
    let Some(f) = (unsafe { (*mac).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `mac` is live, so a method with a `gettable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*mac).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), alg) }
}

/// `const OSSL_PARAM *EVP_MAC_settable_ctx_params(const EVP_MAC *mac)`.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_settable_ctx_params(mac: *const EvpMac) -> *const OsslParam {
    // SAFETY: `mac` is live per the contract.
    let Some(f) = (unsafe { (*mac).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `mac` is live, so a method with a `settable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*mac).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), alg) }
}

/// `const OSSL_PARAM *EVP_MAC_CTX_gettable_params(EVP_MAC_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_gettable_params(ctx: *mut EvpMacCtx) -> *const OsslParam {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live per the contract.
    let Some(f) = (unsafe { (*meth).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `meth` is live, so a method with a `gettable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*meth).prov) };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx, alg) }
}

/// `const OSSL_PARAM *EVP_MAC_CTX_settable_params(EVP_MAC_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_settable_params(ctx: *mut EvpMacCtx) -> *const OsslParam {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live per the contract.
    let Some(f) = (unsafe { (*meth).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `meth` is live, so a method with a `settable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*meth).prov) };
    // SAFETY: `f` is the provider's own callback and `algctx` is its context.
    unsafe { f((*ctx).algctx, alg) }
}

/// `int EVP_MAC_get_params(EVP_MAC *mac, OSSL_PARAM params[])`.
///
/// **Answers 1 when there is no callback**, and the authority's comment says why: a parameter list
/// nothing recognised and a parameter list with no handler are the same answer to a caller, and
/// neither is a failure. That is the opposite of the digest class's `EVP_MD_get_params`, which
/// answers 0 for a missing callback — so the two classes disagree here and only a transcription
/// that keeps them apart is right.
///
/// # Safety
/// `mac` must be a live `EvpMac`; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_get_params(mac: *mut EvpMac, params: *mut OsslParam) -> c_int {
    // SAFETY: `mac` is live per the contract.
    let Some(f) = (unsafe { (*mac).get_params }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `int EVP_MAC_CTX_get_params(EVP_MAC_CTX *ctx, OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_get_params(
    ctx: *mut EvpMacCtx,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).get_ctx_params }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback, `algctx` is its context and `params` is the
    // caller's array.
    unsafe { f((*ctx).algctx, params) }
}

/// `int EVP_MAC_CTX_set_params(EVP_MAC_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_set_params(
    ctx: *mut EvpMacCtx,
    params: *const OsslParam,
) -> c_int {
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

/// `const char *EVP_MAC_get0_name(const EVP_MAC *mac)`.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_get0_name(mac: *const EvpMac) -> *const c_char {
    // SAFETY: `mac` is live per the contract.
    unsafe { (*mac).type_name }
}

/// `const char *EVP_MAC_get0_description(const EVP_MAC *mac)`.
///
/// The provider's own string, with **no fallback**: the digest class falls back to the legacy long
/// name, and this class has no legacy names to fall back to.
///
/// # Safety
/// `mac` must be a live `EvpMac`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_get0_description(mac: *const EvpMac) -> *const c_char {
    // SAFETY: `mac` is live per the contract.
    unsafe { (*mac).description }
}

/// `int EVP_MAC_is_a(const EVP_MAC *mac, const char *name)`.
///
/// The NULL test is on the **method**, where `EVP_MD_is_a`'s is not: the two classes differ in
/// which argument they guard.
///
/// # Safety
/// `mac` must be NULL or a live `EvpMac`; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_is_a(mac: *const EvpMac, name: *const c_char) -> c_int {
    if mac.is_null() {
        return 0;
    }
    // SAFETY: `mac` is live per the contract.
    let (prov, name_id) = unsafe { ((*mac).prov, (*mac).name_id) };
    // SAFETY: `prov` is the provider the method was fetched from and the visitor contract is the
    // namemap's.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `int EVP_MAC_names_do_all(const EVP_MAC *mac, void (*fn)(const char *name, void *data),
/// void *data)`.
///
/// Answers **1 without visiting anything** for a method with no provider — which a fetched method
/// cannot have, since the fetch is what gave it one; the arm exists for the same reason its
/// siblings in this file do, and the digest class's copy of it says the same thing.
///
/// # Safety
/// `mac` must be a live `EvpMac`; `fn_` may be NULL.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_names_do_all(
    mac: *const EvpMac,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `mac` is live per the contract.
    let (prov, name_id) = unsafe { ((*mac).prov, (*mac).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `void EVP_MAC_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_MAC *mac, void *arg),
/// void *arg)`.
///
/// Every MAC every activated provider publishes. A **NULL visitor is refused** rather than passed
/// to a walk that would call it; the boundary is the same one `EVP_MD_do_all_provided` records and
/// is measured in `docs/SECURITY_DIVERGENCE_POLICY.md` D-MD-DOALL-NULL-1.
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpMac, *mut c_void)>,
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
            OSSL_OP_MAC,
            trampoline,
            arg,
            evp_mac_from_algorithm as MethodFromAlgorithmFn,
            evp_mac_up_ref as MethodUpRefFn,
            evp_mac_free as MethodFreeFn,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------------------------

/// `EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac)`.
///
/// Two allocations and a reference, and **two ways to fail that share one release**: a provider
/// whose `newctx` answers NULL and a reference count that will not move. Both call `freectx` on
/// whatever `newctx` left — which is NULL in the first case and a live context in the second — and
/// both raise the same reason.
///
/// # Safety
/// `mac` must be a live `EvpMac` this call may take a reference to.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_new(mac: *mut EvpMac) -> *mut EvpMacCtx {
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<EvpMacCtx>(), FILE, LINE_ZALLOC_CTX).cast::<EvpMacCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is a fresh zeroed block this call owns.
    unsafe { (*ctx).meth = mac };

    // `newctx` and `freectx` are both non-NULL by the structural check every fetch performs; the
    // refusal below is therefore unreachable and is written as the same release path rather than as
    // a fault, so a method that somehow arrived without its constructor is dropped cleanly.
    // SAFETY: `mac` is live per the contract.
    let (newctx, freectx) = unsafe { ((*mac).newctx, (*mac).freectx) };
    let Some(newctx) = newctx else {
        // SAFETY: `ctx` is this call's own block.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
        return ptr::null_mut();
    };
    // SAFETY: `mac` is live, so a method with a `newctx` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*mac).prov) };
    // SAFETY: `newctx` is the provider's own constructor and `provctx` is its context.
    let algctx = unsafe { newctx(provctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).algctx = algctx };

    // SAFETY: `mac` is live per the contract.
    let refd = unsafe { EVP_MAC_up_ref(mac) };
    if algctx.is_null() || refd == 0 {
        // The release is the method's own, and `algctx` is what its constructor left -- NULL or a
        // live context, both of which it is contracted to accept.
        if let Some(freectx) = freectx {
            // SAFETY: `freectx` is the method's own releaser and `algctx` is what its constructor
            // left.
            unsafe { freectx(algctx) };
        }
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_31) };
        // SAFETY: `ctx` is this call's own block.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
        return ptr::null_mut();
    }
    ctx
}

/// `void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx)`.
///
/// **The method is released through `EVP_MAC_free`**, which is where the reference this context
/// took in `EVP_MAC_CTX_new` is given back — so a context and its method are one unit of lifetime
/// and a caller that keeps a method alive past its context has to say so with `EVP_MAC_up_ref`.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_free(ctx: *mut EvpMacCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live, because this context holds a reference to it.
    let freectx = unsafe { (*meth).freectx };
    if let Some(f) = freectx {
        // SAFETY: `f` is the method's own releaser and `algctx` is the context its constructor
        // handed back.
        unsafe { f((*ctx).algctx) };
    }
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).algctx = ptr::null_mut() };
    // SAFETY: `meth` is live and this is the reference `EVP_MAC_CTX_new` took.
    unsafe { EVP_MAC_free(meth) };
    // SAFETY: `ctx` came from this crate's allocator and has just been released of everything.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX) };
}

/// `EVP_MAC_CTX *EVP_MAC_CTX_dup(const EVP_MAC_CTX *src)`.
///
/// A **NULL context is not a NULL copy**: `src` is dereferenced unconditionally, so a caller error
/// is a caller error on both sides. What *is* checked is `src->algctx`, and a NULL there answers
/// NULL — which is the state a context reaches through nothing but a failed `EVP_MAC_CTX_new`, so
/// the check is a contract rather than a guard.
///
/// The order of the two operations is what makes the failure path correct: the method is
/// referenced *before* the algorithm context is duplicated, so the `EVP_MAC_CTX_free` on the
/// failure path has a reference to give back. A transcription that duplicated first would leak the
/// method on every failed copy.
///
/// # Safety
/// `src` must be a live context, or NULL (which faults on both sides).
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_dup(src: *const EvpMacCtx) -> *mut EvpMacCtx {
    // SAFETY: `src` is live per the contract.
    if unsafe { (*src).algctx }.is_null() {
        return ptr::null_mut();
    }
    let dst = CRYPTO_malloc(core::mem::size_of::<EvpMacCtx>(), FILE, LINE_MALLOC_CTX_DUP)
        .cast::<EvpMacCtx>();
    if dst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dst` is a fresh block of exactly the source's size and `src` is a live object.
    unsafe { ptr::copy_nonoverlapping(src, dst, 1) };

    // SAFETY: `dst` is live and its `meth` is the source's, which is live.
    if unsafe { EVP_MAC_up_ref((*dst).meth) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_63) };
        // SAFETY: `dst` is this call's own block and nothing else holds it.
        unsafe { CRYPTO_free(dst.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_DUP) };
        return ptr::null_mut();
    }

    // SAFETY: `src` is live and its method has a `dupctx` -- or this is the NULL that a method
    // without one produces, which is the refusal the caller sees.
    let dupctx = unsafe { (*(*src).meth).dupctx };
    let algctx = match dupctx {
        // SAFETY: `dupctx` is the provider's own callback and `src->algctx` is its context.
        Some(f) => unsafe { f((*src).algctx) },
        None => ptr::null_mut(),
    };
    // SAFETY: `dst` is live.
    unsafe { (*dst).algctx = algctx };
    if algctx.is_null() {
        // SAFETY: `dst` is this call's own context, and the reference taken above is given back
        // here. `freectx` is called with the NULL the failed duplicate left, which is the state
        // the authority releases from too.
        unsafe { EVP_MAC_CTX_free(dst) };
        return ptr::null_mut();
    }
    dst
}

/// `EVP_MAC *EVP_MAC_CTX_get0_mac(EVP_MAC_CTX *ctx)`.
///
/// The **borrowed** method: no reference is taken, so the answer is only as good as the context's
/// own lifetime.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_get0_mac(ctx: *mut EvpMacCtx) -> *mut EvpMac {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).meth }
}

/// `static size_t get_size_t_ctx_param(EVP_MAC_CTX *ctx, const char *name)`.
///
/// Two questions and two fallbacks, and the second is the interesting one:
///
///   * **the context must exist.** A NULL `algctx` answers 0 without asking anyone, which is what
///     makes this function answer 0 for a context whose `newctx` failed;
///   * **`get_ctx_params` first, then `get_params`.** The method-level reader is tried when the
///     context-level one is absent — so a provider that publishes only the method-level
///     parameter list still answers a *context* question, through it. That is not a delegation the
///     digest class has anywhere.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live; `name` NUL-terminated.
unsafe fn get_size_t_ctx_param(ctx: *mut EvpMacCtx, name: *const c_char) -> usize {
    // SAFETY: `ctx` is live per the contract.
    // SAFETY: `ctx` is live per the contract.
    if unsafe { (*ctx).algctx }.is_null() {
        return 0;
    }
    let mut sz: usize = 0;
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry and `params` has room for two; `name` is the
    // caller's NUL-terminated key and the value pointer is this frame's.
    unsafe { params[0] = OSSL_PARAM_construct_size_t(name, &mut sz) };
    params[1] = OSSL_PARAM_construct_end();

    // SAFETY: `ctx` is live.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let (get_ctx_params, get_params) = unsafe { ((*meth).get_ctx_params, (*meth).get_params) };
    if let Some(f) = get_ctx_params {
        // SAFETY: `f` is the provider's own callback, `algctx` is its context and `params` is this
        // frame's array.
        // SAFETY: the return value is what decides whether `sz` is read.
        if unsafe { f((*ctx).algctx, params.as_mut_ptr()) } != 0 {
            return sz;
        }
    } else if let Some(f) = get_params {
        // SAFETY: `f` is the provider's own callback and `params` is this frame's array.
        if unsafe { f(params.as_mut_ptr()) } != 0 {
            return sz;
        }
    }
    0
}

/// `size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_get_mac_size(ctx: *mut EvpMacCtx) -> usize {
    // SAFETY: `ctx` is live per the contract.
    unsafe { get_size_t_ctx_param(ctx, OSSL_MAC_PARAM_SIZE) }
}

/// `size_t EVP_MAC_CTX_get_block_size(EVP_MAC_CTX *ctx)`.
///
/// The key is `"block-size"`: see [`OSSL_MAC_PARAM_BLOCK_SIZE`]'s note, which is here because this
/// is the function that would silently answer 0 for every MAC if it were wrong.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_CTX_get_block_size(ctx: *mut EvpMacCtx) -> usize {
    // SAFETY: `ctx` is live per the contract.
    unsafe { get_size_t_ctx_param(ctx, OSSL_MAC_PARAM_BLOCK_SIZE) }
}

/// `int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])`.
///
/// The missing-callback refusal raises `ERR_R_UNSUPPORTED` with `ERR_R_EVP_LIB` as the *library*
/// argument; see the module documentation. Unreachable for a fetched method, because the
/// structural check counts `init` or `init_skey` toward its three — so the arm exists for a method
/// that publishes `init_skey` **only**, whose byte-string initialiser really is absent.
///
/// # Safety
/// `ctx` must be a live context; `key` readable for `keylen` bytes; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_init(
    ctx: *mut EvpMacCtx,
    key: *const c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let Some(f) = (unsafe { (*meth).init }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_119) };
        return 0;
    };
    // SAFETY: `f` is the provider's own callback, `algctx` is its context and the rest are the
    // caller's arguments.
    unsafe { f((*ctx).algctx, key, keylen, params) }
}

/// `int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)`.
///
/// **No test on `update`**, where `EVP_MAC_init` has one — the structural check makes it
/// non-NULL, so the authority does not ask again.
///
/// # Safety
/// `ctx` must be a live context; `data` readable for `datalen` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_update(
    ctx: *mut EvpMacCtx,
    data: *const c_uchar,
    datalen: usize,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `update` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).update }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
    // arguments.
    unsafe { f((*ctx).algctx, data, datalen) }
}

/// `static int evp_mac_final(EVP_MAC_CTX *ctx, int xof, unsigned char *out, size_t *outl,
/// size_t outsize)`.
///
/// Five refusals and one convention, and the convention is what a caller has to know:
///
///   * a NULL context or a NULL method is `EVP_R_INVALID_NULL_ALGORITHM`;
///   * a missing `final` is `EVP_R_FINAL_ERROR` — unreachable for a fetched method;
///   * **a NULL `out` is a size query**: it answers 1 and writes the MAC's size through `outl`,
///     and a NULL `outl` there is `ERR_R_PASSED_NULL_PARAMETER`. That is the shape `EVP_Q_mac`
///     uses to learn how much to allocate;
///   * a buffer smaller than the MAC's size is `EVP_R_BUFFER_TOO_SMALL`, tested **before** the
///     provider is called and against the *MAC's* size rather than the requested output length;
///   * and the XOF form sets `xof` as a parameter first, where a refusal is
///     `EVP_R_SETTING_XOF_FAILED` rather than the provider's own answer.
///
/// The length the provider reports is written to the caller's `outl` **only if the caller supplied
/// one**, and it is a local in between — so a provider that reports a length without being asked
/// for one cannot corrupt the caller's stack.
///
/// # Safety
/// `ctx` NULL or a live context; `out` NULL or writable for `outsize` bytes; `outl` NULL or
/// writable; `outsize` the buffer's size.
unsafe fn evp_mac_final(
    ctx: *mut EvpMacCtx,
    xof: c_int,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_150) };
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    if meth.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_150) };
        return 0;
    }
    // SAFETY: `meth` is live.
    let Some(final_) = (unsafe { (*meth).final_ }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_154) };
        return 0;
    };

    // SAFETY: `ctx` is live per the contract.
    let macsize = unsafe { EVP_MAC_CTX_get_mac_size(ctx) };
    if out.is_null() {
        if outl.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::MAC_LIB_161) };
            return 0;
        }
        // SAFETY: `outl` was checked for NULL.
        unsafe { *outl = macsize };
        return 1;
    }
    if outsize < macsize {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::MAC_LIB_168) };
        return 0;
    }
    if xof != 0 {
        // The `xof` flag travels by address, so the provider may rewrite it -- that is the
        // authority's own aliasing and not an accident here.
        let mut xof_flag = xof;
        let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
        // SAFETY: the constructor writes one entry and `params` has room for two; the key is a
        // literal and the value pointer is this frame's.
        unsafe { params[0] = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &mut xof_flag) };
        params[1] = OSSL_PARAM_construct_end();
        // SAFETY: `ctx` is live and `params` is a terminated array of this frame's storage.
        if unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) } <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::MAC_LIB_176) };
            return 0;
        }
    }

    let mut l: usize = 0;
    // SAFETY: `final_` is the provider's own callback, `algctx` is its context, `out` is the
    // caller's buffer and `l`/`outsize` are this frame's and the caller's.
    let res = unsafe { final_((*ctx).algctx, out, &mut l, outsize) };
    if !outl.is_null() {
        // SAFETY: `outl` was checked for NULL.
        unsafe { *outl = l };
    }
    res
}

/// `int EVP_MAC_final(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)`.
///
/// # Safety
/// As `evp_mac_final`, with `xof` false.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_final(
    ctx: *mut EvpMacCtx,
    out: *mut c_uchar,
    outl: *mut usize,
    outsize: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_mac_final(ctx, 0, out, outl, outsize) }
}

/// `int EVP_MAC_finalXOF(EVP_MAC_CTX *ctx, unsigned char *out, size_t outsize)`.
///
/// The XOF form, and it passes a **NULL length**: a caller of this entry point cannot learn how
/// much was written, because the length is the length it asked for.
///
/// # Safety
/// `ctx` must be a live context; `out` writable for `outsize` bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_MAC_finalXOF(
    ctx: *mut EvpMacCtx,
    out: *mut c_uchar,
    outsize: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_mac_final(ctx, 1, out, ptr::null_mut(), outsize) }
}

/// `unsigned char *EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
/// const char *subalg, const OSSL_PARAM *params, const void *key, size_t keylen,
/// const unsigned char *data, size_t datalen, unsigned char *out, size_t outsize,
/// size_t *outlen)`.
///
/// A fetch and then five calls joined by `&&`, so the first refusal stops the rest. Four things in
/// it are not obvious:
///
///   * **`*outlen` is zeroed before anything else**, including before the fetch — so a failed
///     `EVP_Q_mac` never leaves a caller's length holding a previous value;
///   * **`subalg` is delivered as `digest` or as `cipher`, and which one is asked of the MAC.** The
///     list the method *says* it takes decides: `digest` if it is offered, `cipher` if not, and
///     `ERR_R_PASSED_INVALID_ARGUMENT` if neither — so a caller cannot attach a sub-algorithm to a
///     MAC that has no notion of one;
///   * **a NULL key with a zero length becomes the data pointer.** A "dummy key", in the
///     authority's words: the single-shot form hashes data, and a MAC that needs a key will refuse
///     a key that is the data, which is the intended outcome rather than a silent success;
///   * **`params` is applied twice**, once through `EVP_MAC_CTX_set_params` and once as the
///     initialiser's argument. The authority does both and the second is not redundant for a
///     provider that reads its parameters in `init` rather than in `set_ctx_params`.
///
/// The two-call shape of the output is the reason `EVP_MAC_final`'s NULL-`out` convention exists:
/// with no `out` the first call is a size query, the buffer is allocated, and the second call fills
/// it — and a failure of that second call frees the buffer and answers NULL rather than returning a
/// half-filled one.
///
/// # Safety
/// `name`, `propq` and `subalg` NULL or NUL-terminated; `key` readable for `keylen` bytes or the
/// dummy-key case; `data` readable for `datalen` bytes; `out` NULL or writable for `outsize` bytes;
/// `outlen` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_Q_mac(
    libctx: *mut c_void,
    name: *const c_char,
    propq: *const c_char,
    subalg: *const c_char,
    params: *const OsslParam,
    key: *const c_void,
    keylen: usize,
    data: *const c_uchar,
    datalen: usize,
    out: *mut c_uchar,
    outsize: usize,
    outlen: *mut usize,
) -> *mut c_uchar {
    // SAFETY: `name` and `propq` are NULL or NUL-terminated per the contract.
    let mac = unsafe { EVP_MAC_fetch(libctx, name, propq) };
    let mut subalg_param: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    let mut len: usize = 0;
    let mut res: *mut c_uchar = ptr::null_mut();

    // SAFETY: `outlen` was checked for NULL.
    unsafe {
        if !outlen.is_null() {
            *outlen = 0;
        }
    }
    if mac.is_null() {
        return ptr::null_mut();
    }

    if !subalg.is_null() {
        // SAFETY: `mac` is live.
        let defined_params = unsafe { EVP_MAC_settable_ctx_params(mac) };
        let mut param_name = OSSL_MAC_PARAM_DIGEST;

        // SAFETY: `defined_params` is the provider's own terminated descriptor list, or NULL --
        // which `OSSL_PARAM_locate_const` accepts and answers NULL for.
        if unsafe { OSSL_PARAM_locate_const(defined_params, param_name) }.is_null() {
            param_name = OSSL_MAC_PARAM_CIPHER;
            // SAFETY: as above.
            if unsafe { OSSL_PARAM_locate_const(defined_params, param_name) }.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::MAC_LIB_283) };
                // SAFETY: `mac` is this call's own reference and `ctx` is still NULL.
                unsafe { EVP_MAC_free(mac) };
                return ptr::null_mut();
            }
        }
        // SAFETY: the constructor writes one entry and `subalg_param` has room for two; the key is
        // one of the two literals above and the buffer is the caller's own string, which the
        // authority casts the `const` away from because `OSSL_PARAM_UTF8_STRING` writes nothing.
        unsafe {
            subalg_param[0] =
                OSSL_PARAM_construct_utf8_string(param_name, subalg.cast_mut().cast::<c_char>(), 0);
        }
    }

    // The dummy key: a single-shot MAC call with no key hashes the data.
    let mut key = key;
    if key.is_null() && keylen == 0 {
        key = data.cast::<c_void>();
    }

    // SAFETY: `mac` is live and this is the class's own context constructor.
    let ctx = unsafe { EVP_MAC_CTX_new(mac) };
    // The `&&` chain is the authority's: the first failure stops the rest, so a context that could
    // not be made never reaches the five calls and a `set_params` that refused never reaches the
    // initialise.
    // SAFETY: `ctx` is NULL or this call's own context, and the remaining arguments are the
    // caller's, forwarded under this function's contract.
    let ran = unsafe {
        !ctx.is_null()
            && EVP_MAC_CTX_set_params(ctx, subalg_param.as_ptr()) != 0
            && EVP_MAC_CTX_set_params(ctx, params) != 0
            && EVP_MAC_init(ctx, key.cast::<c_uchar>(), keylen, params) != 0
            && EVP_MAC_update(ctx, data, datalen) != 0
            && EVP_MAC_final(ctx, out, &mut len, outsize) != 0
    };
    if ran {
        let mut out = out;
        if out.is_null() {
            out = CRYPTO_malloc(len, FILE, LINE_MALLOC_Q_MAC).cast::<c_uchar>();
            // SAFETY: `out` is the block just allocated, or NULL, and `ctx` is live.
            if !out.is_null() && unsafe { EVP_MAC_final(ctx, out, ptr::null_mut(), len) } == 0 {
                // SAFETY: `out` is this call's own block and the final refused to fill it.
                unsafe { CRYPTO_free(out.cast::<c_void>(), FILE, LINE_FREE_Q_MAC) };
                out = ptr::null_mut();
            }
        }
        res = out;
        // SAFETY: `outlen` was checked for NULL.
        unsafe {
            if !res.is_null() && !outlen.is_null() {
                *outlen = len;
            }
        }
    }

    // SAFETY: `ctx` is NULL or this call's own context; `mac` is this call's own reference.
    unsafe {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }
    res
}

// ---------------------------------------------------------------------------------------------
// `int EVP_MAC_init_SKEY(EVP_MAC_CTX *ctx, EVP_SKEY *skey, const OSSL_PARAM params[])` is
// **not here**: it is handed to 7.3f with the dependency named in `forensics/phase7-obligations.json`.
//
// The body reads `skey->skeymgmt->prov` and `skey->keydata`, and `EVP_SKEY` is
// `crypto/evp/skeymgmt_lib.c`'s — 7.3f's, alongside the `EVP_SKEYMGMT` methods it is built from.
// Nothing in this crate can construct an `EVP_SKEY` today, so a transcription here would produce a
// function no court could reach and no caller could call; the hand-off row is the honest record of
// that, and the method *object* above already carries the `init_skey` field it will need, because
// the structural check counts it.
// ---------------------------------------------------------------------------------------------

// SPDX-License-Identifier: Apache-2.0
#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// A method built by hand, so the parts of this file that are not about fetching can be read
    /// without a provider. `newctx` and `freectx` are the two the structural check requires.
    fn a_hand_built_mac() -> EvpMac {
        EvpMac {
            prov: ptr::null_mut(),
            name_id: 7,
            type_name: ptr::null_mut(),
            description: c"a hand-built MAC".as_ptr(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            dupctx: None,
            freectx: None,
            init: None,
            update: None,
            final_: None,
            gettable_params: None,
            gettable_ctx_params: None,
            settable_ctx_params: None,
            get_params: None,
            get_ctx_params: None,
            set_ctx_params: None,
            init_skey: None,
        }
    }

    /// The three accessors that are pure field reads, and the one that answers 0 for a NULL where
    /// its digest sibling answers -1: this class has no error path in `is_a` at all.
    #[test]
    fn the_method_accessors_read_fields_and_guard_null() {
        let mac = a_hand_built_mac();
        let p: *const EvpMac = ptr::addr_of!(mac);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(evp_mac_get_number(p), 7);
            assert!(EVP_MAC_get0_name(p).is_null());
            assert_eq!(
                CStr::from_ptr(EVP_MAC_get0_description(p)),
                c"a hand-built MAC"
            );
            assert!(EVP_MAC_get0_provider(p).is_null());
            /* **1, not 0**, and the reason is worth keeping: with a NULL provider `evp_is_a`
             * re-derives the number from the *legacy name*, which this caller passed as NULL --
             * so the number becomes 0 -- and then compares it against the name's own number,
             * which is 0 for a name no namemap knows. Two zeros are equal, so an unknown name is
             * "is a" match for a method with no provider. That is the authority's behaviour and
             * not a transcription of it. */
            assert_eq!(
                EVP_MAC_is_a(p, c"whatever".as_ptr()),
                1,
                "unknowable, and the authority says yes"
            );
            assert_eq!(
                EVP_MAC_is_a(ptr::null(), c"whatever".as_ptr()),
                0,
                "and the NULL test is on the method"
            );
            /* `names_do_all` answers 1 -- a *success* -- without visiting anything, because a
             * method with no provider has no name list to walk rather than an empty one. */
            assert_eq!(
                EVP_MAC_names_do_all(p, None, ptr::null_mut()),
                1,
                "nothing to visit is not a failure"
            );
            /* The two `gettable` accessors answer NULL for a missing callback, and the four
             * parameter entry points answer **1** -- the authority's comment says why: a
             * parameter list nothing recognised and a list with no handler are the same answer. */
            assert!(EVP_MAC_gettable_params(p).is_null());
            assert!(EVP_MAC_gettable_ctx_params(p).is_null());
            assert!(EVP_MAC_settable_ctx_params(p).is_null());
            assert_eq!(EVP_MAC_get_params(p.cast_mut(), ptr::null_mut()), 1);
        }
    }

    /// The reference count: `EVP_MAC_up_ref` always answers 1 and `EVP_MAC_free` releases only on
    /// the last reference — with **no origin test**, which is the structural difference from
    /// `EVP_MD_free`. The object here is a stack local, so the test takes the count to 2 and back
    /// to 1 rather than to 0.
    #[test]
    fn the_reference_count_is_the_only_ownership_rule() {
        let mut mac = a_hand_built_mac();
        let p: *mut EvpMac = ptr::addr_of_mut!(mac);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_MAC_up_ref(p), 1, "always 1, never the count");
            assert_eq!(mac.refcnt.load(Ordering::Acquire), 2);
            assert_eq!(EVP_MAC_up_ref(p), 1);
            assert_eq!(mac.refcnt.load(Ordering::Acquire), 3);
            EVP_MAC_free(p);
            EVP_MAC_free(p);
            assert_eq!(
                mac.refcnt.load(Ordering::Acquire),
                1,
                "not the last one yet"
            );
            assert_eq!(mac.name_id, 7, "and the object is untouched");
            EVP_MAC_free(ptr::null_mut());
        }
    }

    /// A context that was never made cannot be made: `EVP_MAC_CTX_new` releases what it allocated
    /// and answers NULL when the method has no constructor, and the release path is the one the
    /// authority takes rather than a leak. The state is unreachable through a fetch -- the
    /// structural check counts `newctx` -- so this is the transcription of an arm and not a
    /// behaviour a caller can rely on.
    #[test]
    fn a_method_without_a_constructor_cannot_make_a_context() {
        let mut mac = a_hand_built_mac();
        let p: *mut EvpMac = ptr::addr_of_mut!(mac);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert!(EVP_MAC_CTX_new(p).is_null());
        }
    }

    /// The two `static` readers of the context's own size question, on a context whose `algctx` is
    /// NULL: **both answer 0 without asking anyone**, which is what makes a failed `EVP_MAC_CTX_new`
    /// safe to query. The provider is never called, so a method with no callbacks at all is enough.
    #[test]
    fn the_context_size_question_answers_zero_without_a_context() {
        let mut mac = a_hand_built_mac();
        let mut ctx = EvpMacCtx {
            meth: ptr::addr_of_mut!(mac),
            algctx: ptr::null_mut(),
        };
        let p: *mut EvpMacCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: `p` is this frame's own live object and its method is this frame's too.
        unsafe {
            assert_eq!(EVP_MAC_CTX_get_mac_size(p), 0);
            assert_eq!(EVP_MAC_CTX_get_block_size(p), 0);
            assert!(EVP_MAC_CTX_get0_mac(p) == ptr::addr_of_mut!(mac));
            assert!(EVP_MAC_CTX_gettable_params(p).is_null());
            assert!(EVP_MAC_CTX_settable_params(p).is_null());
            assert_eq!(EVP_MAC_CTX_get_params(p, ptr::null_mut()), 1);
            assert_eq!(EVP_MAC_CTX_set_params(p, ptr::null()), 1);
        }
    }

    /// `EVP_MAC_final`'s refusals, each with its own coordinate, and the `out == NULL` convention
    /// that is not a refusal at all.
    ///
    /// A NULL context and a NULL method reach **the same** raise, which is why the two arms in the
    /// code share a site. A method with no `final` is the third. And the two length arms are
    /// ordered: a NULL `outl` alongside a NULL `out` is a refusal, while a NULL `out` with an
    /// `outl` is a size query that answers 1.
    #[test]
    fn the_final_refuses_four_ways_and_answers_a_size_query() {
        /// `static int final(void *mctx, unsigned char *out, size_t *outl, size_t outsize)` —
        /// reports nothing and accepts.
        ///
        /// # Safety
        /// The ABI is the authority's; only `outl` is written, and the caller supplies it.
        unsafe extern "C" fn nothing(
            _mctx: *mut c_void,
            _out: *mut c_uchar,
            outl: *mut usize,
            _outsize: usize,
        ) -> c_int {
            if !outl.is_null() {
                // SAFETY: `outl` was checked for NULL and the caller supplies it.
                unsafe { *outl = 0 };
            }
            1
        }

        let mut mac = a_hand_built_mac();
        mac.final_ = Some(nothing);
        let mut ctx = EvpMacCtx {
            meth: ptr::addr_of_mut!(mac),
            algctx: ptr::null_mut(),
        };
        let p: *mut EvpMacCtx = ptr::addr_of_mut!(ctx);
        let mut out = [0u8; 64];
        let mut outl: usize = 0;
        // SAFETY: `p` is this frame's own live object and the buffers are this frame's.
        unsafe {
            assert_eq!(
                EVP_MAC_final(ptr::null_mut(), out.as_mut_ptr(), &mut outl, 64),
                0
            );
            assert_coordinate(&err_sites::MAC_LIB_150);
            /* A NULL *method* reaches the same raise, because the authority tests both. */
            {
                let mut orphan = EvpMacCtx {
                    meth: ptr::null_mut(),
                    algctx: ptr::null_mut(),
                };
                assert_eq!(
                    EVP_MAC_final(ptr::addr_of_mut!(orphan), out.as_mut_ptr(), &mut outl, 64),
                    0
                );
                assert_coordinate(&err_sites::MAC_LIB_150);
            }
            /* The method exists and has no `final` -- which is another hand-built method, since
             * this one needs a `final` for the arms below. */
            {
                let mut bare = a_hand_built_mac();
                let mut barectx = EvpMacCtx {
                    meth: ptr::addr_of_mut!(bare),
                    algctx: ptr::null_mut(),
                };
                assert_eq!(
                    EVP_MAC_final(ptr::addr_of_mut!(barectx), out.as_mut_ptr(), &mut outl, 64),
                    0
                );
                assert_coordinate(&err_sites::MAC_LIB_154);
            }
            /* A size query: NULL `out` with a length is 1 and writes the MAC's size, which is 0
             * here because the context has no algorithm context. */
            outl = 9_999;
            assert_eq!(EVP_MAC_final(p, ptr::null_mut(), &mut outl, 0), 1);
            assert_eq!(outl, 0, "the MAC's size, not the caller's old value");
            /* A size query with neither is the refusal. */
            assert_eq!(EVP_MAC_final(p, ptr::null_mut(), ptr::null_mut(), 0), 0);
            assert_coordinate(&err_sites::MAC_LIB_161);
        }
    }

    /// The two initialise entry points refuse a missing callback rather than calling through it,
    /// and — the point of the test — the missing-callback arm is `EVP_MAC_init` alone: this class
    /// requires `update` and `final` at fetch time but *`init` or `init_skey`*, so a method can
    /// arrive holding neither initialiser.
    #[test]
    fn the_initialise_refuses_a_missing_callback() {
        let mut mac = a_hand_built_mac();
        let mut ctx = EvpMacCtx {
            meth: ptr::addr_of_mut!(mac),
            algctx: ptr::null_mut(),
        };
        let p: *mut EvpMacCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: `p` is this frame's own live object and the arguments are this frame's.
        unsafe {
            assert_eq!(EVP_MAC_init(p, ptr::null(), 0, ptr::null()), 0);
            assert_coordinate(&err_sites::MAC_LIB_119);
            /* `update` has no such test: the structural check guarantees it, so the authority does
             * not ask again and neither does this crate. */
            assert_eq!(EVP_MAC_update(p, ptr::null(), 0), 0);
        }
    }

    /// `EVP_MAC_CTX_dup` answers NULL for a context with no algorithm context — and it does so
    /// **before** allocating, which is why a NULL result here says nothing about memory.
    ///
    /// The second test is the boundary this module's documentation records: a method with **no
    /// `dupctx`** is one the authority calls through and faults on, and this crate answers the NULL
    /// its own next statement would have produced
    /// (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MAC-DUPCTX-NULL-1). It is asserted here rather than
    /// left implicit because the two NULLs — "no algorithm context" and "no duplicator" — are
    /// reached by different arguments and a transcription that conflated them would look right.
    #[test]
    fn a_context_with_no_algorithm_context_cannot_be_duplicated() {
        let mut mac = a_hand_built_mac();
        let ctx = EvpMacCtx {
            meth: ptr::addr_of_mut!(mac),
            algctx: ptr::null_mut(),
        };
        // SAFETY: the context is this frame's own live object.
        unsafe {
            assert!(EVP_MAC_CTX_dup(ptr::addr_of!(ctx)).is_null());
        }
    }

    /// The second NULL of `EVP_MAC_CTX_dup`, reached by a *different* argument from the first:
    /// a live algorithm context and a method with no duplicator.
    ///
    /// The authority calls through the missing `dupctx` and faults
    /// (`docs/SECURITY_DIVERGENCE_POLICY.md` D-MAC-DUPCTX-NULL-1); this crate answers the NULL the
    /// authority's own next statement produces, and — the part worth asserting — **gives back the
    /// reference it took on the method**, so a caller cannot leak one by duplicating a method that
    /// cannot duplicate.
    #[test]
    fn a_method_with_no_duplicator_answers_null_and_returns_its_reference() {
        let mut mac = a_hand_built_mac();
        let ctx = EvpMacCtx {
            meth: ptr::addr_of_mut!(mac),
            // A real, non-NULL pointer that is never read: the duplicate's only use of `algctx` is
            // the `dupctx` call, and this method has no `dupctx` to make it with.
            algctx: c"x".as_ptr() as *mut c_void,
        };
        // SAFETY: the context is this frame's own live object and its method is too.
        unsafe {
            assert!(EVP_MAC_CTX_dup(ptr::addr_of!(ctx)).is_null());
            assert_eq!(
                mac.refcnt.load(Ordering::Acquire),
                1,
                "the reference the duplicate took came back"
            );
        }
    }

    /// The coordinate of the last error raised, against a recorded site: the three strings a
    /// caller reads back through `ERR_get_error_all`.
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
}
