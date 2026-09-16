//! Phase 7.3a — `crypto/evp/digest.c`'s fetch half: the `EVP_MD` object, and `EVP_MD_fetch`.
//!
//! This is the smallest slice of 7.3 that makes the generic fetch *reachable*. Everything 7.1
//! and 7.2 built — the algorithm walk, `ossl_method_construct`, the method store and its query
//! path, `evp_generic_fetch` — is internal: `libcrypto.ld`'s version script hides every `ossl_*`
//! and `evp_*` name from the DSO, and a probe is compiled against the *installed* headers. So
//! until a **class** exists to fetch through, the fetch path has no observation at all, and the
//! plan records that dependency rather than claiming the observation (D147).
//!
//! `EVP_MD` is that class, and it is the smallest of them: no key, no ASN.1, no context
//! parameters of its own beyond two sizes. With `EVP_MD_fetch` in place a probe can register a
//! provider that publishes a digest, fetch it by name, select it with a property query and
//! **reject** it with another — which is `docs/PROVIDER_MODEL.md` §5's gate item 4 and 7.2's
//! exit criterion, met two subphases later than the plan first said and by the subphase that
//! can actually meet it.
//!
//! ## The object is two objects in one struct, and the order of the fields is not
//!
//! `struct evp_md_st` is the legacy `EVP_MD` — `type`, `md_size`, `block_size`, the six
//! `EVP_MD_CTX` function pointers and `pkey_type` — **followed by** the provider-side object:
//! `name_id`, `type_name`, `prov`, `refcnt` and the fifteen `OSSL_FUNC_DIGEST_*` pointers. A
//! method that came from a provider fills the second half and leaves the first at zero except for
//! the two sizes; a method built by `EVP_MD_meth_new` fills the first. Which half is live is
//! exactly what `origin` says, and it is why `EVP_MD_free` refuses a method whose origin is not
//! `EVP_ORIG_DYNAMIC`: the legacy half belongs to the method table, not to the caller.
//!
//! ## `evp_md_cache_constants` is why a provider must answer two parameters
//!
//! `md_size` and `block_size` are **not** read from the dispatch table. They are asked of the
//! provider through `OSSL_FUNC_DIGEST_GET_PARAMS` at fetch time, and a fetch whose provider does
//! not answer `OSSL_DIGEST_PARAM_SIZE` and `OSSL_DIGEST_PARAM_BLOCK_SIZE` **fails** with
//! `EVP_R_CACHE_CONSTANTS_FAILED`. That is a contract fact rather than an implementation detail,
//! and `RT-FETCH`'s resolver provider has to publish both or the court would report the
//! authority's own refusal as a candidate divergence.
//!
//! Three smaller things in the same function are worth keeping: the four parameters are built
//! once and asked in **one** call; `int` overflow of either size is a refusal rather than a
//! truncation; and the two flags (`EVP_MD_FLAG_XOF` and `EVP_MD_FLAG_DIGALGID_ABSENT`) are
//! **set, never cleared** — a fetched method starts with `flags` zero, so the difference is
//! invisible today and would not be if a legacy method were ever fetched through here.
//!
//! ## What is deliberately not here
//!
//! The **contexts**. `EVP_MD_CTX_new`, `_free`, `_init`, `_update`, `_final` and the twenty-odd
//! accessors that go with them are 7.3b's, and `struct evp_md_ctx_st` is not transcribed, so the
//! six legacy function pointers on this struct are typed with an opaque `*mut c_void` where the
//! authority has `EVP_MD_CTX *`. That is a *typing* difference and not a behavioural one — no
//! field is read before 7.3b — and it is stated here rather than silently made.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{evp_generic_fetch, MethodFromAlgorithmFn};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_size_t, OsslParam,
};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::{ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::NID_undef;
use crate::runtime::obj::{OBJ_NAME_get, OBJ_nid2sn};

/// `EVP_CTRL_RET_UNSUPPORTED`, from `crypto/evp/evp_local.h`.
///
/// The answer `evp_do_md_getparams` gives for an object that has **no provider** — which is the
/// legacy half's signal that the caller should take the other path, and not a failure.
const EVP_CTRL_RET_UNSUPPORTED: c_int = -1;

/// `EVP_ORIG_DYNAMIC`, from `include/crypto/evp.h`: an object the caller owns.
const EVP_ORIG_DYNAMIC: c_int = 0;
/// `EVP_ORIG_METH`, from `include/crypto/evp.h`: an object the method table owns.
///
/// Its only reader is `EVP_MD_meth_free`, which is 7.3b's alongside the legacy `EVP_MD_meth_*`
/// setters that build such an object; the constant is here with the other origin so the pair is
/// read together.
#[allow(dead_code)] // unreachable until 7.3b's legacy `EVP_MD_meth_*` object exists
const EVP_ORIG_METH: c_int = 2;

/// `EVP_MD_FLAG_XOF` — `include/openssl/evp.h`.
const EVP_MD_FLAG_XOF: core::ffi::c_ulong = 0x0002;
/// `EVP_MD_FLAG_DIGALGID_ABSENT` — `include/openssl/evp.h`.
const EVP_MD_FLAG_DIGALGID_ABSENT: core::ffi::c_ulong = 0x0008;

/// `OBJ_NAME_TYPE_MD_METH` — `include/openssl/objects.h`. **0x01**, and not one of the type
/// indices `src/runtime/obj.rs` already names, so it is declared here where its one reader is.
const OBJ_NAME_TYPE_MD_METH: c_int = 0x01;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/digest.c".as_ptr();
/// `evp_md_new`'s `OPENSSL_zalloc(sizeof(*md))` (line 944).
const LINE_ZALLOC_MD: c_int = 944;
/// `evp_md_free_int`'s `OPENSSL_free(md->type_name)` (line 863), in `crypto/evp/evp_lib.c`.
const LINE_FREE_TYPE_NAME: c_int = 863;
/// `evp_md_free_int`'s `OPENSSL_free(md)` (line 867), in the same file.
const LINE_FREE_MD: c_int = 867;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the fifteen function-pointer types.
//
// `OSSL_FUNC_DIGEST_*` from `include/openssl/core_dispatch.h`, and each type is what
// `OSSL_CORE_MAKE_FUNC` generates for the corresponding entry. The ids are part of the wire
// format a provider is compiled against, so they are copied rather than derived.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_DIGEST_NEWCTX`.
const OSSL_FUNC_DIGEST_NEWCTX: c_int = 1;
/// `OSSL_FUNC_DIGEST_INIT`.
const OSSL_FUNC_DIGEST_INIT: c_int = 2;
/// `OSSL_FUNC_DIGEST_UPDATE`.
const OSSL_FUNC_DIGEST_UPDATE: c_int = 3;
/// `OSSL_FUNC_DIGEST_FINAL`.
const OSSL_FUNC_DIGEST_FINAL: c_int = 4;
/// `OSSL_FUNC_DIGEST_DIGEST`.
const OSSL_FUNC_DIGEST_DIGEST: c_int = 5;
/// `OSSL_FUNC_DIGEST_FREECTX`.
const OSSL_FUNC_DIGEST_FREECTX: c_int = 6;
/// `OSSL_FUNC_DIGEST_DUPCTX`.
const OSSL_FUNC_DIGEST_DUPCTX: c_int = 7;
/// `OSSL_FUNC_DIGEST_GET_PARAMS`.
const OSSL_FUNC_DIGEST_GET_PARAMS: c_int = 8;
/// `OSSL_FUNC_DIGEST_SET_CTX_PARAMS`.
const OSSL_FUNC_DIGEST_SET_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_DIGEST_GET_CTX_PARAMS`.
const OSSL_FUNC_DIGEST_GET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_DIGEST_GETTABLE_PARAMS`.
const OSSL_FUNC_DIGEST_GETTABLE_PARAMS: c_int = 11;
/// `OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS: c_int = 12;
/// `OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS: c_int = 13;
/// `OSSL_FUNC_DIGEST_SQUEEZE`.
const OSSL_FUNC_DIGEST_SQUEEZE: c_int = 14;
/// `OSSL_FUNC_DIGEST_COPYCTX`.
const OSSL_FUNC_DIGEST_COPYCTX: c_int = 15;

/// `OSSL_FUNC_digest_newctx_fn` — `void *(*)(void *provctx)`.
pub(crate) type DigestNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_digest_init_fn` — `int (*)(void *dctx, const OsslParam params[])`.
pub(crate) type DigestInitFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_digest_update_fn` — `int (*)(void *dctx, const unsigned char *in, size_t inl)`.
pub(crate) type DigestUpdateFn =
    unsafe extern "C" fn(*mut c_void, *const core::ffi::c_uchar, usize) -> c_int;
/// `OSSL_FUNC_digest_final_fn` — `int (*)(void *dctx, unsigned char *out, size_t *outl,
/// size_t outsz)`.
pub(crate) type DigestFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut core::ffi::c_uchar, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_digest_squeeze_fn` — the same signature as `_final`.
pub(crate) type DigestSqueezeFn =
    unsafe extern "C" fn(*mut c_void, *mut core::ffi::c_uchar, *mut usize, usize) -> c_int;
/// `OSSL_FUNC_digest_digest_fn` — the one-shot form: `int (*)(void *provctx,
/// const unsigned char *in, size_t inl, unsigned char *out, size_t *outl, size_t outsz)`.
pub(crate) type DigestDigestFn = unsafe extern "C" fn(
    *mut c_void,
    *const core::ffi::c_uchar,
    usize,
    *mut core::ffi::c_uchar,
    *mut usize,
    usize,
) -> c_int;
/// `OSSL_FUNC_digest_freectx_fn` — `void (*)(void *dctx)`.
pub(crate) type DigestFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_digest_dupctx_fn` — `void *(*)(void *dctx)`.
pub(crate) type DigestDupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_digest_copyctx_fn` — `void (*)(void *outctx, void *inctx)`.
pub(crate) type DigestCopyCtxFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
/// `OSSL_FUNC_digest_get_params_fn` — `int (*)(OsslParam params[])`.
pub(crate) type DigestGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `OSSL_FUNC_digest_set_ctx_params_fn` — `int (*)(void *vctx, const OsslParam params[])`.
pub(crate) type DigestSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_digest_get_ctx_params_fn` — `int (*)(void *vctx, OsslParam params[])`.
pub(crate) type DigestGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_digest_gettable_params_fn` — `const OsslParam *(*)(void *provctx)`.
pub(crate) type DigestGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_digest_settable_ctx_params_fn` — `const OsslParam *(*)(void *dctx,
/// void *provctx)`.
pub(crate) type DigestSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_digest_gettable_ctx_params_fn` — the same signature.
pub(crate) type DigestGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;

/// The legacy `EVP_MD_CTX` function pointers, typed with an **opaque** context.
///
/// `struct evp_md_ctx_st` is 7.3b's and is not transcribed yet, so the authority's `EVP_MD_CTX *`
/// is a `*mut c_void` here. Nothing in this file reads one; the fields exist because they are part
/// of the struct's layout and because `EVP_MD_meth_set_*` fills them in the legacy half.
pub(crate) type MdLegacyInitFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(crate) type MdLegacyUpdateFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> c_int;
pub(crate) type MdLegacyFinalFn =
    unsafe extern "C" fn(*mut c_void, *mut core::ffi::c_uchar) -> c_int;
pub(crate) type MdLegacyCopyFn = unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int;
pub(crate) type MdLegacyCleanupFn = unsafe extern "C" fn(*mut c_void) -> c_int;
pub(crate) type MdLegacyCtrlFn =
    unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;

/// `struct evp_md_st` — `EVP_MD`, from `include/crypto/evp.h`.
///
/// The field order is the authority's, and two runs of it are commented as the authority comments
/// them because the boundary is real: everything above `name_id` is the legacy method object and
/// everything below is the provider-side one. `origin` says which is live.
///
/// Every function-pointer field is an `Option` because the authority tests each one for NULL —
/// `evp_do_md_getparams` refuses an object whose `get_params` is missing, and the dispatch walk
/// fills each field only if it is still NULL, which is how the *first* entry for an id wins.
/// **`pub` for the reason every internal type in an exported signature is**: `EVP_MD_fetch` and
/// its six siblings are exported, Rust requires the type of an exported item's parameter to be at
/// least as visible, and the authority keeps `evp_md_st` in `include/crypto/evp.h`, which is not
/// installed. Every field is `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpMd {
    /// `int type` — the legacy NID, or `NID_undef` for a provider method whose names match no
    /// legacy entry.
    pub(crate) type_: c_int,
    /// `int pkey_type` — the pkey NID a legacy digest is also registered under.
    pub(crate) pkey_type: c_int,
    /// `int md_size` — filled by `evp_md_cache_constants` from the provider.
    pub(crate) md_size: c_int,
    /// `unsigned long flags` — `EVP_MD_FLAG_*`.
    pub(crate) flags: core::ffi::c_ulong,
    /// `int origin` — `EVP_ORIG_DYNAMIC` or `EVP_ORIG_METH`.
    pub(crate) origin: c_int,
    /// `int (*init)(EVP_MD_CTX *)`.
    pub(crate) init: Option<MdLegacyInitFn>,
    /// `int (*update)(EVP_MD_CTX *, const void *, size_t)`.
    pub(crate) update: Option<MdLegacyUpdateFn>,
    /// `int (*final)(EVP_MD_CTX *, unsigned char *)`.
    pub(crate) final_: Option<MdLegacyFinalFn>,
    /// `int (*copy)(EVP_MD_CTX *, const EVP_MD_CTX *)`.
    pub(crate) copy: Option<MdLegacyCopyFn>,
    /// `int (*cleanup)(EVP_MD_CTX *)`.
    pub(crate) cleanup: Option<MdLegacyCleanupFn>,
    /// `int block_size` — filled by `evp_md_cache_constants` from the provider.
    pub(crate) block_size: c_int,
    /// `int ctx_size` — how big `ctx->md_data` must be; the legacy half's business.
    pub(crate) ctx_size: c_int,
    /// `int (*md_ctrl)(EVP_MD_CTX *, int, int, void *)`.
    pub(crate) md_ctrl: Option<MdLegacyCtrlFn>,
    /// `int name_id` — the namemap identity the method was fetched under.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — the provider that published it, holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_digest_newctx_fn *newctx`.
    pub(crate) newctx: Option<DigestNewCtxFn>,
    /// `OSSL_FUNC_digest_init_fn *dinit`.
    pub(crate) dinit: Option<DigestInitFn>,
    /// `OSSL_FUNC_digest_update_fn *dupdate`.
    pub(crate) dupdate: Option<DigestUpdateFn>,
    /// `OSSL_FUNC_digest_final_fn *dfinal`.
    pub(crate) dfinal: Option<DigestFinalFn>,
    /// `OSSL_FUNC_digest_squeeze_fn *dsqueeze`.
    pub(crate) dsqueeze: Option<DigestSqueezeFn>,
    /// `OSSL_FUNC_digest_digest_fn *digest`.
    pub(crate) digest: Option<DigestDigestFn>,
    /// `OSSL_FUNC_digest_freectx_fn *freectx`.
    pub(crate) freectx: Option<DigestFreeCtxFn>,
    /// `OSSL_FUNC_digest_copyctx_fn *copyctx`.
    pub(crate) copyctx: Option<DigestCopyCtxFn>,
    /// `OSSL_FUNC_digest_dupctx_fn *dupctx`.
    pub(crate) dupctx: Option<DigestDupCtxFn>,
    /// `OSSL_FUNC_digest_get_params_fn *get_params`.
    pub(crate) get_params: Option<DigestGetParamsFn>,
    /// `OSSL_FUNC_digest_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<DigestSetCtxParamsFn>,
    /// `OSSL_FUNC_digest_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<DigestGetCtxParamsFn>,
    /// `OSSL_FUNC_digest_gettable_params_fn *gettable_params`.
    pub(crate) gettable_params: Option<DigestGettableParamsFn>,
    /// `OSSL_FUNC_digest_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<DigestSettableCtxParamsFn>,
    /// `OSSL_FUNC_digest_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<DigestGettableCtxParamsFn>,
}

/// `EVP_MD *evp_md_new(void)`.
///
/// A zeroed block and a reference count of 1. **The zeroing is the reason a fetched method's
/// legacy half is inert**: every function pointer in it starts NULL, and the dispatch walk below
/// fills only the provider half, so a fetched `EVP_MD` is `EVP_ORIG_DYNAMIC` with a `type` of
/// `NID_undef` until `evp_md_from_algorithm` says otherwise.
pub(crate) fn evp_md_new() -> *mut EvpMd {
    let md = CRYPTO_zalloc(core::mem::size_of::<EvpMd>(), FILE, LINE_ZALLOC_MD).cast::<EvpMd>();
    if !md.is_null() {
        // SAFETY: `md` is a fresh zeroed block this call owns.
        unsafe { (*md).refcnt = AtomicI32::new(1) };
    }
    md
}

/// `static void set_legacy_nid(const char *name, void *vlegacy_nid)`.
///
/// The namemap visitor that decides whether a fetched method also *is* a legacy method, and the
/// three-way answer is why it is a visitor rather than a lookup:
///
///   * the name is not in the legacy table — the common case in this crate, because nothing has
///     called `EVP_add_digest` yet (that is Phase 13's legacy table) — so `*legacy_nid` is left
///     alone and stays `NID_undef`;
///   * it is, and the NID agrees with what has been seen so far — so it is recorded;
///   * it is, and the NID **disagrees** — so `*legacy_nid` is set to **-1**, which is the clash
///     marker `evp_md_from_algorithm` tests for and turns into a refusal. A method registered
///     under two legacy names with different NIDs is not fetchable, and that is the whole point of
///     the sentinel.
///
/// The authority's own comment says why `OBJ_NAME_get` is used directly rather than
/// `EVP_get_digestbyname`: the latter now looks at providers too, and this function is asking
/// about the legacy table specifically.
///
/// # Safety
/// `name` must be NUL-terminated and `vlegacy_nid` a writable `c_int`.
unsafe extern "C" fn set_legacy_nid(name: *const c_char, vlegacy_nid: *mut c_void) {
    let legacy_nid = vlegacy_nid.cast::<c_int>();
    // SAFETY: `name` is NUL-terminated per the contract.
    let legacy_method = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH) };
    // SAFETY: `legacy_nid` is writable per the contract.
    if unsafe { *legacy_nid } == -1 {
        return;
    }
    if legacy_method.is_null() {
        return;
    }
    // SAFETY: the table's data pointer is an `EVP_MD` for this name type, which is what the
    // authority casts it to.
    let nid = unsafe { (*legacy_method.cast::<EvpMd>()).type_ };
    // SAFETY: `legacy_nid` is writable per the contract.
    unsafe {
        if *legacy_nid != NID_undef && *legacy_nid != nid {
            *legacy_nid = -1;
            return;
        }
        *legacy_nid = nid;
    }
}

/// `int evp_do_md_getparams(const EVP_MD *md, OsslParam params[])`.
///
/// The `PARAM_CHECK` macro's three arms, transcribed: NULL is 0, **no provider is
/// `EVP_CTRL_RET_UNSUPPORTED`** — the signal that a legacy method should be asked another way and
/// not a failure — and a missing `get_params` raises `EVP_R_CANNOT_GET_PARAMETERS` and answers 0.
///
/// # Safety
/// `md` must be NULL or live; `params` a terminated array.
pub(crate) unsafe fn evp_do_md_getparams(md: *const EvpMd, params: *mut OsslParam) -> c_int {
    if md.is_null() {
        return 0;
    }
    // SAFETY: `md` is live per the contract.
    let (prov, get_params) = unsafe { ((*md).prov, (*md).get_params) };
    if prov.is_null() {
        return EVP_CTRL_RET_UNSUPPORTED;
    }
    let Some(f) = get_params else {
        // The authority's `geterr()`: `ERR_raise(ERR_LIB_EVP, EVP_R_CANNOT_GET_PARAMETERS)`.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_UTILS_65) };
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `static int evp_md_cache_constants(EVP_MD *md)`.
///
/// The two sizes, asked of the provider in **one** call with four parameters built up front.
///
/// Two of the four are flags rather than sizes, and the authority's comment says why they are
/// asked here at all: they are constants of the implementation that a fetch discovers once, so a
/// XOF says so at fetch time and its `md_size` is left at whatever the provider answers (zero for
/// a real XOF, which is why the caller must not treat zero as an error).
///
/// An `int` overflow of either size **fails the fetch** rather than truncating: the values are
/// collected as `size_t` and compared against `INT_MAX` before being narrowed.
///
/// # Safety
/// `md` must be a live `EvpMd` whose `prov` is live.
unsafe fn evp_md_cache_constants(md: *mut EvpMd) -> c_int {
    let mut blksz: usize = 0;
    let mut mdsize: usize = 0;
    let mut xof: c_int = 0;
    let mut algid_absent: c_int = 0;
    // The four parameters are a *stack* array whose address the provider writes through, so its
    // five slots live for the duration of the call.
    // `OsslParam` is `Copy` and has no `Default`, so the array is built from the terminator
    // and then overwritten -- which is also what the authority's sequence of
    // `OSSL_PARAM_construct_*` calls produces.
    let mut params: [OsslParam; 5] = [OSSL_PARAM_construct_end(); 5];
    // SAFETY: each constructor writes one entry and `params` has room for all five; the string
    // arguments are literals.
    unsafe {
        params[0] = OSSL_PARAM_construct_size_t(c"blocksize".as_ptr(), &mut blksz);
        params[1] = OSSL_PARAM_construct_size_t(c"size".as_ptr(), &mut mdsize);
        params[2] = OSSL_PARAM_construct_int(c"xof".as_ptr(), &mut xof);
        params[3] = OSSL_PARAM_construct_int(c"algid-absent".as_ptr(), &mut algid_absent);
        params[4] = OSSL_PARAM_construct_end();
    }
    // SAFETY: `md` is live and `params` is a terminated array of local storage.
    let mut ok = unsafe { evp_do_md_getparams(md, params.as_mut_ptr()) } > 0;
    if mdsize > c_int::MAX as usize || blksz > c_int::MAX as usize {
        ok = false;
    }
    if ok {
        // SAFETY: `md` is live per the contract.
        unsafe {
            (*md).block_size = blksz as c_int;
            (*md).md_size = mdsize as c_int;
            // Set, never cleared: a fetched method starts with `flags` zero.
            if xof != 0 {
                (*md).flags |= EVP_MD_FLAG_XOF;
            }
            if algid_absent != 0 {
                (*md).flags |= EVP_MD_FLAG_DIGALGID_ABSENT;
            }
        }
    }
    c_int::from(ok)
}

/// `static void *evp_md_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// The class constructor `evp_generic_fetch` is handed, and the shape a reader has to hold on to
/// is that **the walk over the dispatch table is the whole of it**: an `OSSL_ALGORITHM` is a name
/// list, a property definition and a table of `(id, function)` pairs, and this function is where
/// those pairs become fields of an object.
///
/// Four things are counted and checked rather than assumed:
///
///   * **the first entry for an id wins.** Every arm tests its field for NULL before filling it,
///     so a provider that publishes `OSSL_FUNC_DIGEST_UPDATE` twice is not an error and the first
///     one is the method's. That is why the fields start zeroed;
///   * **the count of "structural" functions is checked against three values.** Six ids
///     (`newctx`, `init`, `update`, `final`, `squeeze`, `freectx`) must be all present or all
///     absent, `digest` stands alone and is not counted, and an implementation with none of the
///     seven is refused. `fncnt != 0 && fncnt != 5 && fncnt != 6` is the authority's test, and the
///     5 is the same set minus `squeeze` — so a digest with an update path and no squeeze is
///     legal, and one with a squeeze and no update is not;
///   * **the provider reference is taken after the structural check**, so a refused method never
///     holds one;
///   * **`EVP_MD_free` is the error path**, which is why the object's `origin` is zero from the
///     start: the releaser refuses anything that is not `EVP_ORIG_DYNAMIC`, and a half-built
///     object must be releasable.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live.
unsafe extern "C" fn evp_md_from_algorithm(
    name_id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let md = evp_md_new();
    if md.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DIGEST_1026) };
        return ptr::null_mut();
    }

    // The legacy NID, if any of the method's names is a legacy name. A clash is -1.
    // SAFETY: `md` is live, `prov` is live and `name_id` came from the namemap.
    unsafe { (*md).type_ = NID_undef };
    // SAFETY: `md` is live, so its `type_` field is writable, and the visitor contract is the
    // namemap's.
    let named = unsafe {
        crate::evp::fetch::evp_names_do_all(
            prov,
            name_id,
            Some(set_legacy_nid),
            ptr::addr_of_mut!((*md).type_).cast::<c_void>(),
        )
    };
    // SAFETY: `md` is live.
    if named == 0 || unsafe { (*md).type_ } == -1 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DIGEST_1034) };
        // SAFETY: `md` is this call's own object.
        unsafe { EVP_MD_free(md) };
        return ptr::null_mut();
    }

    // SAFETY: `md` is live.
    unsafe {
        (*md).name_id = name_id;
        (*md).type_name = ossl_algorithm_get1_first_name(algodef);
    }
    // SAFETY: `md` is live.
    if unsafe { (*md).type_name }.is_null() {
        // SAFETY: `md` is this call's own object.
        unsafe { EVP_MD_free(md) };
        return ptr::null_mut();
    }
    // SAFETY: `md` and `algodef` are live.
    unsafe {
        (*md).description = (*algodef).algorithm_description;
    }

    // The dispatch walk. Each arm fills its field only if it is still NULL, so the first entry
    // for an id wins and a later duplicate is ignored rather than refused.
    let mut fns = fns;
    let mut fncnt = 0;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator.
    unsafe {
        while (*fns).function_id != OSSL_DISPATCH_END {
            let id = (*fns).function_id;
            match id {
                OSSL_FUNC_DIGEST_NEWCTX if (*md).newctx.is_none() => {
                    (*md).newctx = entry_function::<DigestNewCtxFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_INIT if (*md).dinit.is_none() => {
                    (*md).dinit = entry_function::<DigestInitFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_UPDATE if (*md).dupdate.is_none() => {
                    (*md).dupdate = entry_function::<DigestUpdateFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_FINAL if (*md).dfinal.is_none() => {
                    (*md).dfinal = entry_function::<DigestFinalFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_SQUEEZE if (*md).dsqueeze.is_none() => {
                    (*md).dsqueeze = entry_function::<DigestSqueezeFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_DIGEST if (*md).digest.is_none() => {
                    // Not counted: `digest` is the standalone one-shot form.
                    (*md).digest = entry_function::<DigestDigestFn>(fns);
                }
                OSSL_FUNC_DIGEST_FREECTX if (*md).freectx.is_none() => {
                    (*md).freectx = entry_function::<DigestFreeCtxFn>(fns);
                    fncnt += 1;
                }
                OSSL_FUNC_DIGEST_DUPCTX if (*md).dupctx.is_none() => {
                    (*md).dupctx = entry_function::<DigestDupCtxFn>(fns);
                }
                OSSL_FUNC_DIGEST_GET_PARAMS if (*md).get_params.is_none() => {
                    (*md).get_params = entry_function::<DigestGetParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_SET_CTX_PARAMS if (*md).set_ctx_params.is_none() => {
                    (*md).set_ctx_params = entry_function::<DigestSetCtxParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_GET_CTX_PARAMS if (*md).get_ctx_params.is_none() => {
                    (*md).get_ctx_params = entry_function::<DigestGetCtxParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_GETTABLE_PARAMS if (*md).gettable_params.is_none() => {
                    (*md).gettable_params = entry_function::<DigestGettableParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS if (*md).settable_ctx_params.is_none() => {
                    (*md).settable_ctx_params = entry_function::<DigestSettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS if (*md).gettable_ctx_params.is_none() => {
                    (*md).gettable_ctx_params = entry_function::<DigestGettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_DIGEST_COPYCTX if (*md).copyctx.is_none() => {
                    (*md).copyctx = entry_function::<DigestCopyCtxFn>(fns);
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }

    // The structural check: all of the six, or none of them, and at least one way to digest.
    // SAFETY: `md` is live.
    let digest_present = unsafe { (*md).digest.is_some() };
    if (fncnt != 0 && fncnt != 5 && fncnt != 6) || (fncnt == 0 && !digest_present) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DIGEST_1130) };
        // SAFETY: `md` is this call's own object.
        unsafe { EVP_MD_free(md) };
        return ptr::null_mut();
    }

    if !prov.is_null() {
        // SAFETY: `prov` is live per the contract.
        if unsafe { ossl_provider_up_ref(prov) } == 0 {
            // SAFETY: `md` is this call's own object.
            unsafe { EVP_MD_free(md) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `md` is live.
    unsafe { (*md).prov = prov };

    // SAFETY: `md` is live and its provider is the one just referenced.
    if unsafe { evp_md_cache_constants(md) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::DIGEST_1139) };
        // SAFETY: `md` is this call's own object; its reference to `prov` is dropped with it.
        unsafe { EVP_MD_free(md) };
        return ptr::null_mut();
    }

    md.cast::<c_void>()
}

/// `static int evp_md_up_ref(void *md)`.
///
/// # Safety
/// `md` must be a live `EvpMd`.
unsafe extern "C" fn evp_md_up_ref(md: *mut c_void) -> c_int {
    // SAFETY: `md` is live per the contract.
    unsafe { EVP_MD_up_ref(md.cast::<EvpMd>()) }
}

/// `static void evp_md_free(void *md)`.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd` this module owns a reference to.
unsafe extern "C" fn evp_md_free(md: *mut c_void) {
    // SAFETY: `md` is NULL or live per the contract.
    unsafe { EVP_MD_free(md.cast::<EvpMd>()) };
}

/// `void evp_md_free_int(EVP_MD *md)` — the releaser, which the destructor and the legacy
/// `EVP_MD_meth_free` share.
///
/// The order is the authority's: the name, the provider reference, the reference count, the
/// block. Nothing in the legacy half is released, because nothing in it was ever allocated by
/// this crate: `type_name` is the only owned string and `description` is the provider's own.
///
/// # Safety
/// `md` must be a live `EvpMd` with no references left.
unsafe fn evp_md_free_int(md: *mut EvpMd) {
    // SAFETY: `md` is live per the contract.
    unsafe {
        CRYPTO_free((*md).type_name.cast::<c_void>(), FILE, LINE_FREE_TYPE_NAME);
        ossl_provider_free((*md).prov);
        CRYPTO_free(md.cast::<c_void>(), FILE, LINE_FREE_MD);
    }
}

/// `EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)`.
///
/// Three lines, and every one of them is a delegation to machinery this stratum built in 7.1 and
/// 7.2: the operation is `OSSL_OP_DIGEST`, and the three callbacks are the class's.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpMd {
    // SAFETY: the arguments are forwarded under this function's contract, and the three
    // callbacks are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            crate::evp::algorithm::OSSL_OP_DIGEST,
            algorithm,
            properties,
            evp_md_from_algorithm as MethodFromAlgorithmFn,
            evp_md_up_ref as MethodUpRefFn,
            evp_md_free as MethodFreeFn,
        )
    }
    .cast::<EvpMd>()
}

/// `int EVP_MD_up_ref(EVP_MD *md)`.
///
/// **Answers 1 for a legacy method too**, where nothing is incremented — because the legacy half
/// is owned by the method table and a caller taking a reference to it is asking for something the
/// table already guarantees. That is why the return is 1 on both arms rather than the reference
/// count's value.
///
/// `md` is dereferenced unconditionally, as the authority's is; a NULL is a caller error on both
/// sides and not a checked refusal.
///
/// # Safety
/// `md` must be a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_up_ref(md: *mut EvpMd) -> c_int {
    // SAFETY: `md` is live per the contract.
    unsafe {
        if (*md).origin == EVP_ORIG_DYNAMIC {
            (*md).refcnt.fetch_add(1, Ordering::AcqRel);
        }
    }
    1
}

/// `void EVP_MD_free(EVP_MD *md)`.
///
/// Two refusals before anything happens: NULL, and **any origin that is not `EVP_ORIG_DYNAMIC`**.
/// The second is the one that matters: a method the caller obtained from `EVP_sha256()` belongs
/// to the method table, and freeing it would be freeing a static.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_free(md: *mut EvpMd) {
    if md.is_null() {
        return;
    }
    // SAFETY: `md` is live per the contract.
    if unsafe { (*md).origin } != EVP_ORIG_DYNAMIC {
        return;
    }
    // SAFETY: `md` is live.
    let last = unsafe { (*md).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference.
    unsafe { evp_md_free_int(md) };
}

/// `int EVP_MD_get_type(const EVP_MD *md)`.
///
/// The legacy NID, or `NID_undef` for a provider method whose names matched no legacy entry. It
/// takes no reference and reads one field.
///
/// # Safety
/// `md` must be a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_type(md: *const EvpMd) -> c_int {
    // SAFETY: `md` is live per the contract.
    unsafe { (*md).type_ }
}

/// `const char *EVP_MD_get0_name(const EVP_MD *md)`.
///
/// The provider's own name for a fetched method, and the **legacy short name** for one that has a
/// NID — which is the fallback that makes `EVP_MD_get0_name(EVP_sha256())` answer `"SHA256"`
/// without the legacy table being involved at all.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get0_name(md: *const EvpMd) -> *const c_char {
    if md.is_null() {
        return ptr::null();
    }
    // SAFETY: `md` is live per the contract.
    let type_name = unsafe { (*md).type_name };
    if !type_name.is_null() {
        return type_name;
    }
    // SAFETY: `md` is live; `EVP_MD_get_type` is a SAFE-by-contract read of one field.
    let nid = unsafe { (*md).type_ };
    // `OBJ_nid2sn` is a SAFE function in this crate and answers NULL for an unknown NID.
    OBJ_nid2sn(nid)
}

/// `int EVP_MD_get_size(const EVP_MD *md)`.
///
/// **A NULL is a refusal with an error**, not NULL-propagation: the authority raises
/// `EVP_R_MESSAGE_DIGEST_IS_NULL` and answers -1, and a caller that treated -1 as a size would
/// allocate a negative buffer.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_size(md: *const EvpMd) -> c_int {
    if md.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_LIB_812) };
        return -1;
    }
    // SAFETY: `md` is live per the contract.
    unsafe { (*md).md_size }
}

/// `int EVP_MD_get_block_size(const EVP_MD *md)`.
///
/// The same shape as `EVP_MD_get_size`, and the same reason.
///
/// # Safety
/// `md` must be NULL or a live `EvpMd`.
#[no_mangle]
pub unsafe extern "C" fn EVP_MD_get_block_size(md: *const EvpMd) -> c_int {
    if md.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EVP_LIB_803) };
        return -1;
    }
    // SAFETY: `md` is live per the contract.
    unsafe { (*md).block_size }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::ERR_peek_last_error_all;
    use core::ffi::CStr;

    /// The coordinate of the last error raised, against a recorded site: the three strings a
    /// caller reads back through `ERR_get_error_all`. The *coordinate* is the observable here
    /// rather than the reason, because both of the fetch path's refusals are raised from one line
    /// with a computed reason -- see `src/evp/fetch.rs`.
    fn assert_coordinate(site: &err_sites::ErrSite) {
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

    /// An algorithm nobody publishes is a **NULL with an error**, and it is raised from the fetch
    /// path's single computed-reason line. A caller that only checked for NULL would learn nothing
    /// about why, which is why the coordinate is asserted.
    #[test]
    fn an_unpublished_algorithm_answers_null_with_an_error() {
        // SAFETY: a NULL context is the default one and the strings are literals.
        let md = unsafe { EVP_MD_fetch(ptr::null_mut(), c"no-such-digest".as_ptr(), ptr::null()) };
        assert!(md.is_null(), "no provider publishes that name here");
        assert_coordinate(&err_sites::EVP_FETCH_376);

        // A NULL name is not a lookup at all: `inner_evp_generic_fetch` skips the resolution and
        // the walk finds nothing, so the answer is NULL without the name-resolution error.
        // SAFETY: as above.
        let md2 = unsafe { EVP_MD_fetch(ptr::null_mut(), ptr::null(), ptr::null()) };
        assert!(md2.is_null());
    }

    /// The two size accessors refuse a NULL **with an error and -1**, rather than propagating the
    /// NULL: a caller that treated -1 as a size would allocate a negative buffer. The coordinates
    /// differ from the fetch's because they are `evp_lib.c`'s lines.
    #[test]
    fn the_size_accessors_refuse_a_null_at_their_own_coordinates() {
        // SAFETY: the argument is NULL, which both functions accept as a refusal.
        unsafe {
            assert_eq!(EVP_MD_get_size(ptr::null()), -1);
            assert_coordinate(&err_sites::EVP_LIB_812);
            assert_eq!(EVP_MD_get_block_size(ptr::null()), -1);
            assert_coordinate(&err_sites::EVP_LIB_803);
            assert!(
                EVP_MD_get0_name(ptr::null()).is_null(),
                "and this one is silent"
            );
            // `EVP_MD_get_type` is deliberately *not* called with NULL: the authority dereferences
            // it unconditionally, so a NULL there is undefined behaviour on both sides rather than
            // a refusal, and this crate does not reproduce an authority fault
            // (`docs/SECURITY_DIVERGENCE_POLICY.md`).
        }
    }

    /// `EVP_MD_up_ref` answers 1 for a method the caller does not own, and `EVP_MD_free` refuses
    /// it — the pair that makes a legacy method safe to hand out: the table owns it, so taking a
    /// reference is free and releasing one is a no-op rather than a free of a static.
    #[test]
    fn a_method_the_caller_does_not_own_is_not_freed_and_is_refd_for_free() {
        let mut md = EvpMd {
            type_: NID_undef,
            pkey_type: 0,
            md_size: 32,
            flags: 0,
            origin: EVP_ORIG_METH, // not EVP_ORIG_DYNAMIC: the table owns it
            init: None,
            update: None,
            final_: None,
            copy: None,
            cleanup: None,
            block_size: 64,
            ctx_size: 0,
            md_ctrl: None,
            name_id: 0,
            type_name: ptr::null_mut(),
            description: ptr::null(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            dinit: None,
            dupdate: None,
            dfinal: None,
            dsqueeze: None,
            digest: None,
            freectx: None,
            copyctx: None,
            dupctx: None,
            get_params: None,
            set_ctx_params: None,
            get_ctx_params: None,
            gettable_params: None,
            settable_ctx_params: None,
            gettable_ctx_params: None,
        };
        let p: *mut EvpMd = ptr::addr_of_mut!(md);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_MD_up_ref(p), 1, "a reference to a table method is free");
            assert_eq!(
                md.refcnt.load(Ordering::Acquire),
                1,
                "and nothing was counted"
            );
            // The releaser must be a no-op: `md` is a stack object and the origin says so.
            EVP_MD_free(p);
            assert_eq!(md.refcnt.load(Ordering::Acquire), 1);
            assert_eq!(md.md_size, 32, "and the object is untouched");
            // A NULL is the other refusal, before the origin is even read.
            EVP_MD_free(ptr::null_mut());
        }
    }

    /// The sizes a fetched method carries are the provider's answers, and `EVP_MD_FLAG_*` bits are
    /// set rather than assigned — so a method whose provider says `xof=no` keeps whatever flags it
    /// had, which for a fetched method is zero. This asserts the *shape* on a hand-built object,
    /// because a real fetch needs a provider; the provider path is `RT-FETCH`'s.
    #[test]
    fn the_flag_bits_are_set_rather_than_assigned() {
        let md = evp_md_new();
        assert!(!md.is_null());
        // SAFETY: `md` is a fresh object this test owns.
        unsafe {
            (*md).flags = EVP_MD_FLAG_DIGALGID_ABSENT;
            (*md).flags |= EVP_MD_FLAG_XOF;
            assert_eq!(
                (*md).flags,
                EVP_MD_FLAG_DIGALGID_ABSENT | EVP_MD_FLAG_XOF,
                "both bits, and the earlier one survived"
            );
            assert_eq!(
                (*md).origin,
                EVP_ORIG_DYNAMIC,
                "a fresh object is the caller's"
            );
            assert_eq!((*md).refcnt.load(Ordering::Acquire), 1);
            EVP_MD_free(md);
        }
    }
}
