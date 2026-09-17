//! Phase 7.3e — the `EVP_KDF` method object and the context it is run through.
//!
//! `crypto/evp/kdf_meth.c` and `crypto/evp/kdf_lib.c`: the other half of 7.3e, and `EVP_MAC`'s
//! twin in every structural respect. It is written out rather than shared with it because the two
//! differ in four places that a court can see, and each of them is a place where a shared helper
//! would have had to be parameterised into something neither class actually is:
//!
//!   * **`EVP_KDF_CTX_dup` tests its duplicator and `EVP_MAC_CTX_dup` does not.** The MAC class
//!     reaches `src->meth->dupctx(...)` with no test — which is a fault, measured, and recorded as
//!     `docs/SECURITY_DIVERGENCE_POLICY.md` D-MAC-DUPCTX-NULL-1. This class tests `src == NULL &&
//!     src->algctx == NULL && src->meth->dupctx == NULL` and answers NULL for all three. The
//!     difference is between two files of the same stratum, and it is the reason the two functions
//!     are transcribed separately rather than derived from one another.
//!   * **the structural check is `1` and `2`, not `3` and `2`.** `fnkdfcnt` counts `derive` alone,
//!     where the MAC class's three-way count folds `init` and `init_skey` into one flag; `fnctxcnt`
//!     counts `newctx` and `freectx`, and `dupctx` is not counted by either class.
//!   * **a KDF has a `reset`** and a MAC has none, and the reset is a *provider* callback rather
//!     than a re-initialise: `EVP_KDF_CTX_reset` answers `void` and does not touch `algctx`.
//!   * **`EVP_KDF_CTX_new` refuses a NULL method up front**, where `EVP_MAC_CTX_new` dereferences
//!     it. The two classes disagree on the same argument, in the same subphase.
//!
//! ## The two entry points that are 7.3f's
//!
//! `EVP_KDF_CTX_set_SKEY` and `EVP_KDF_derive_SKEY` both take an `EVP_SKEY`, whose `EVP_SKEYMGMT`
//! is 7.3f's and whose every constructor is a scaffold in this crate today. They are handed forward
//! with the dependency named, in `docs/DECISIONS.md` D158's company and in the same way
//! `EVP_MAC_init_SKEY` is — the *fields* the walk fills (`set_skey`, `derive_skey`) are transcribed
//! here, because the structural check and the dispatch walk are this file's, and only the two
//! exported functions' bodies need an `EVP_SKEY` to exist.
//!
//! ## The two size questions are two functions, again
//!
//! `EVP_KDF_CTX_get_kdf_size` asks the context first and the method second, exactly as
//! `EVP_MAC_CTX_get_mac_size` does through `get_size_t_ctx_param` — but it is written out here
//! rather than delegated to that helper, because the KDF form does **not** gate on `algctx` being
//! non-NULL. A KDF whose context never allocated can still answer a size, and a MAC's cannot; that
//! is a difference a caller can observe with two calls and no error.
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
use crate::evp::skeymgmt::{
    evp_skey_alloc, evp_skeymgmt_fetch_from_prov, EVP_SKEYMGMT_fetch, EVP_SKEYMGMT_free,
    EVP_SKEY_export, EVP_SKEY_free, EVP_SKEY_import_SKEYMGMT, EvpSkey, EvpSkeyMgmt,
    OSSL_SKEYMGMT_SELECT_SECRET_KEY, OSSL_SKEY_PARAM_RAW_BYTES,
};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_locate_const, OsslParam,
};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::{
    ossl_provider_ctx, ossl_provider_free, ossl_provider_libctx, ossl_provider_up_ref, OsslProvider,
};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// `OSSL_OP_KDF` — `include/openssl/core_dispatch.h`. The fourth operation the walk visits.
const OSSL_OP_KDF: c_int = 4;

/// `EVP_KDF_CTX_set_SKEY`'s default parameter name — `include/openssl/core_names.h`. Used when the
/// caller does not name the parameter the exported bytes should be set under.
const OSSL_KDF_PARAM_KEY: *const c_char = c"key".as_ptr();

/// The authority's translation unit, so a failing allocation or free records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c".as_ptr();
/// `evp_kdf_new`'s `OPENSSL_zalloc(sizeof(*kdf))` (line 50), in `kdf_meth.c`.
const LINE_ZALLOC_KDF: c_int = 50;
/// `evp_kdf_free`'s `OPENSSL_free(kdf->type_name)`, in `kdf_meth.c`.
const LINE_FREE_TYPE_NAME: c_int = 40;
/// `evp_kdf_free`'s `OPENSSL_free(kdf)`, in `kdf_meth.c`.
const LINE_FREE_KDF: c_int = 43;
/// `EVP_KDF_CTX_new`'s `OPENSSL_zalloc(sizeof(EVP_KDF_CTX))` (line 31).
const LINE_ZALLOC_CTX: c_int = 31;
/// `EVP_KDF_CTX_new`'s `OPENSSL_free(ctx)` (line 38).
const LINE_FREE_CTX_ON_NEW: c_int = 38;
/// `EVP_KDF_CTX_free`'s `OPENSSL_free(ctx)` (line 53).
const LINE_FREE_CTX: c_int = 53;
/// `EVP_KDF_CTX_dup`'s `OPENSSL_malloc(sizeof(*dst))` (line 63).
const LINE_MALLOC_CTX_DUP: c_int = 63;
/// `EVP_KDF_CTX_dup`'s `OPENSSL_free(dst)` (line 70).
const LINE_FREE_CTX_ON_DUP: c_int = 70;
/// `EVP_KDF_derive_SKEY`'s `OPENSSL_zalloc(keylen)` (line 245). The only allocation in this file
/// whose size is a caller's argument rather than a `sizeof`.
const LINE_ZALLOC_DERIVE_SKEY: c_int = 245;
/// `EVP_KDF_derive_SKEY`'s `OPENSSL_free(key)` on the derivation's own failure (line 250).
const LINE_FREE_DERIVE_SKEY_ON_FAIL: c_int = 250;
/// `EVP_KDF_derive_SKEY`'s `OPENSSL_clear_free(key, keylen)` on the success path (line 262).
const LINE_FREE_DERIVE_SKEY: c_int = 262;

/// `OSSL_KDF_PARAM_SIZE` — `include/openssl/core_names.h`.
const OSSL_KDF_PARAM_SIZE: *const c_char = c"size".as_ptr();

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the thirteen function-pointer types.
//
// `OSSL_FUNC_KDF_*` from `include/openssl/core_dispatch.h`, and each type is what
// `OSSL_CORE_MAKE_FUNC` generates for the corresponding entry. The ids are part of the wire format
// a provider is compiled against, so they are copied rather than derived.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_KDF_NEWCTX`.
const OSSL_FUNC_KDF_NEWCTX: c_int = 1;
/// `OSSL_FUNC_KDF_DUPCTX`.
const OSSL_FUNC_KDF_DUPCTX: c_int = 2;
/// `OSSL_FUNC_KDF_FREECTX`.
const OSSL_FUNC_KDF_FREECTX: c_int = 3;
/// `OSSL_FUNC_KDF_RESET`.
const OSSL_FUNC_KDF_RESET: c_int = 4;
/// `OSSL_FUNC_KDF_DERIVE`.
const OSSL_FUNC_KDF_DERIVE: c_int = 5;
/// `OSSL_FUNC_KDF_GETTABLE_PARAMS`.
const OSSL_FUNC_KDF_GETTABLE_PARAMS: c_int = 6;
/// `OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS: c_int = 7;
/// `OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_KDF_GET_PARAMS`.
const OSSL_FUNC_KDF_GET_PARAMS: c_int = 9;
/// `OSSL_FUNC_KDF_GET_CTX_PARAMS`.
const OSSL_FUNC_KDF_GET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_KDF_SET_CTX_PARAMS`.
const OSSL_FUNC_KDF_SET_CTX_PARAMS: c_int = 11;
/// `OSSL_FUNC_KDF_SET_SKEY`. Filled by the walk, called by 7.3f.
const OSSL_FUNC_KDF_SET_SKEY: c_int = 12;
/// `OSSL_FUNC_KDF_DERIVE_SKEY`. Filled by the walk, called by 7.3f.
const OSSL_FUNC_KDF_DERIVE_SKEY: c_int = 13;

/// `OSSL_FUNC_kdf_newctx_fn` — `void *(*)(void *provctx)`.
pub(crate) type KdfNewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_kdf_dupctx_fn` — `void *(*)(void *src)`.
pub(crate) type KdfDupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_kdf_freectx_fn` — `void (*)(void *kctx)`.
pub(crate) type KdfFreeCtxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_kdf_reset_fn` — `void (*)(void *kctx)`.
pub(crate) type KdfResetFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_kdf_derive_fn` — `int (*)(void *kctx, unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])`.
pub(crate) type KdfDeriveFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kdf_gettable_params_fn` — `const OSSL_PARAM *(*)(void *provctx)`.
pub(crate) type KdfGettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_kdf_gettable_ctx_params_fn` — `const OSSL_PARAM *(*)(void *kctx, void *provctx)`.
pub(crate) type KdfGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_kdf_settable_ctx_params_fn` — the same signature.
pub(crate) type KdfSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_kdf_get_params_fn` — `int (*)(OSSL_PARAM params[])`.
pub(crate) type KdfGetParamsFn = unsafe extern "C" fn(*mut OsslParam) -> c_int;
/// `OSSL_FUNC_kdf_get_ctx_params_fn` — `int (*)(void *kctx, OSSL_PARAM params[])`.
pub(crate) type KdfGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_kdf_set_ctx_params_fn` — `int (*)(void *kctx, const OSSL_PARAM params[])`.
pub(crate) type KdfSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kdf_set_skey_fn` — `int (*)(void *kctx, void *key, const char *paramname)`.
pub(crate) type KdfSetSkeyFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> c_int;
/// `OSSL_FUNC_kdf_derive_skey_fn` — `void *(*)(void *ctx, const char *key_type, void *provctx,
/// OSSL_FUNC_skeymgmt_import_fn *import, size_t keylen, const OSSL_PARAM params[])`.
///
/// The fourth parameter is a **function pointer** whose type is `OSSL_FUNC_skeymgmt_import_fn`,
/// which is `EVP_SKEYMGMT`'s and therefore 7.3f's. It is typed with an opaque pointer here rather
/// than with a type this file cannot declare; the field is filled by the walk and read by 7.3f's
/// `EVP_KDF_derive_SKEY`, so nothing in this file loses anything by not naming its pointee.
pub(crate) type KdfDeriveSkeyFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *mut c_void,
    usize,
    *const OsslParam,
) -> *mut c_void;

/// `struct evp_kdf_st` — `EVP_KDF`, from `include/crypto/evp.h`.
///
/// Nine callbacks and four bookkeeping fields, in the authority's order — and two more callbacks
/// than `EvpMac` because this class has `reset` and the symmetric-key pair. Every callback is an
/// `Option` because the authority tests each one before calling it, and because
/// `evp_kdf_from_algorithm` fills each field only if it is still NULL, which is how the *first*
/// entry for an id wins.
///
/// `pub` for the reason every internal type in an exported signature is: twenty exported functions
/// take or return one, Rust requires the type of an exported item's parameter to be at least as
/// visible, and the authority keeps `evp_kdf_st` in `include/crypto/evp.h`, which is not installed.
/// Every field is `pub(crate)`, so nothing outside this crate can name or reach one.
#[repr(C)]
pub struct EvpKdf {
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
    /// `OSSL_FUNC_kdf_newctx_fn *newctx`.
    pub(crate) newctx: Option<KdfNewCtxFn>,
    /// `OSSL_FUNC_kdf_dupctx_fn *dupctx`.
    pub(crate) dupctx: Option<KdfDupCtxFn>,
    /// `OSSL_FUNC_kdf_freectx_fn *freectx`.
    pub(crate) freectx: Option<KdfFreeCtxFn>,
    /// `OSSL_FUNC_kdf_reset_fn *reset`.
    pub(crate) reset: Option<KdfResetFn>,
    /// `OSSL_FUNC_kdf_derive_fn *derive`.
    pub(crate) derive: Option<KdfDeriveFn>,
    /// `OSSL_FUNC_kdf_gettable_params_fn *gettable_params`.
    pub(crate) gettable_params: Option<KdfGettableParamsFn>,
    /// `OSSL_FUNC_kdf_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<KdfGettableCtxParamsFn>,
    /// `OSSL_FUNC_kdf_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<KdfSettableCtxParamsFn>,
    /// `OSSL_FUNC_kdf_get_params_fn *get_params`.
    pub(crate) get_params: Option<KdfGetParamsFn>,
    /// `OSSL_FUNC_kdf_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<KdfGetCtxParamsFn>,
    /// `OSSL_FUNC_kdf_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<KdfSetCtxParamsFn>,
    /// `OSSL_FUNC_kdf_set_skey_fn *set_skey` — filled by the walk, called by 7.3f.
    pub(crate) set_skey: Option<KdfSetSkeyFn>,
    /// `OSSL_FUNC_kdf_derive_skey_fn *derive_skey` — filled by the walk, called by 7.3f.
    pub(crate) derive_skey: Option<KdfDeriveSkeyFn>,
}

/// `struct evp_kdf_ctx_st` — `EVP_KDF_CTX`, from `crypto/evp/evp_local.h`.
///
/// Two fields, the same two as `EVP_MAC_CTX` and in the same order. `meth` is assigned **last** in
/// `EVP_KDF_CTX_new` — that is, only once the algorithm context exists and the reference has been
/// taken — which is why a caller can never see a context whose method is set and whose `algctx` is
/// not.
///
/// `pub` for the same reason `EvpKdf` is.
#[repr(C)]
pub struct EvpKdfCtx {
    /// `EVP_KDF *meth` — the method, holding a reference of this context's own.
    pub(crate) meth: *mut EvpKdf,
    /// `void *algctx` — the provider's context, from `newctx`.
    pub(crate) algctx: *mut c_void,
}

// ---------------------------------------------------------------------------------------------
// The method object
// ---------------------------------------------------------------------------------------------

/// `static int evp_kdf_up_ref(void *vkdf)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vkdf` must be a live `EvpKdf`.
unsafe extern "C" fn evp_kdf_up_ref(vkdf: *mut c_void) -> c_int {
    // SAFETY: `vkdf` is live per the contract.
    unsafe { EVP_KDF_up_ref(vkdf.cast::<EvpKdf>()) }
}

/// `static void evp_kdf_free(void *vkdf)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `vkdf` must be NULL or a live `EvpKdf`.
unsafe extern "C" fn evp_kdf_free(vkdf: *mut c_void) {
    // SAFETY: `vkdf` is NULL or live per the contract.
    unsafe { EVP_KDF_free(vkdf.cast::<EvpKdf>()) };
}

/// `static void *evp_kdf_new(void)`.
///
/// The authority's `|| !CRYPTO_NEW_REF(&kdf->refcnt, 1)` arm releases the block it just allocated,
/// which is what makes a failed reference initialisation a NULL rather than a leak. This crate's
/// reference count is an `AtomicI32` that cannot fail to be created, so the arm is unreachable —
/// but the release is written the way the authority writes it, because the *shape* is what a reader
/// is checking against.
///
/// # Safety
/// No preconditions: it allocates and writes one field.
unsafe fn evp_kdf_new() -> *mut EvpKdf {
    let kdf = CRYPTO_zalloc(core::mem::size_of::<EvpKdf>(), FILE, LINE_ZALLOC_KDF).cast::<EvpKdf>();
    if kdf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `kdf` is a fresh zeroed block this call owns.
    unsafe { (*kdf).refcnt = AtomicI32::new(1) };
    kdf
}

/// `static void *evp_kdf_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// `evp_mac_from_algorithm`'s shape with a **one-sided** arithmetic: `fnkdfcnt == 1` counts `derive`
/// alone, with no fold and no alternative — where the MAC class counts three and folds `init` and
/// `init_skey` into one flag — and `fnctxcnt == 2` counts `newctx` and `freectx` and, as in the MAC
/// class, **not** `dupctx`.
///
/// So the asymmetry the two classes share is that a method with no duplicator is fetchable; the
/// asymmetry they differ in is that a KDF needs exactly one derivation path and a MAC needs three
/// functions of which two may be folded. A transcription that shared one helper between the two
/// would have to be told which arithmetic to use, which is the same as not sharing it.
///
/// # Safety
/// `algodef` must be a live `OSSL_ALGORITHM` whose `algorithm_names` is NUL-terminated and whose
/// `implementation` is a terminated `OSSL_DISPATCH` table; `prov` live or NULL.
unsafe extern "C" fn evp_kdf_from_algorithm(
    name_id: c_int,
    algodef: *const crate::provider::activate::OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: this allocates a fresh object and reads nothing.
    let kdf = unsafe { evp_kdf_new() };
    if kdf.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_METH_67) };
        return ptr::null_mut();
    }

    // SAFETY: `kdf` is live.
    unsafe { (*kdf).name_id = name_id };

    // SAFETY: `algodef` is live per the contract.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `kdf` is this call's own object.
        unsafe { EVP_KDF_free(kdf) };
        return ptr::null_mut();
    }
    // SAFETY: `kdf` is live and `type_name` is the string just allocated for it.
    unsafe { (*kdf).type_name = type_name };
    // SAFETY: `algodef` is live.
    unsafe { (*kdf).description = (*algodef).algorithm_description };

    let mut fns = fns;
    let mut fnkdfcnt = 0;
    let mut fnctxcnt = 0;
    // SAFETY: `fns` is a terminated table per the contract, so the walk leaves it at the
    // terminator. Each arm reads `function_id` before deciding, and fills its field only if the
    // field is still NULL -- so the *first* entry for an id wins, which is every class's rule.
    unsafe {
        while (*fns).function_id != OSSL_DISPATCH_END {
            let id = (*fns).function_id;
            match id {
                OSSL_FUNC_KDF_NEWCTX if (*kdf).newctx.is_none() => {
                    (*kdf).newctx = entry_function::<KdfNewCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_KDF_DUPCTX if (*kdf).dupctx.is_none() => {
                    (*kdf).dupctx = entry_function::<KdfDupCtxFn>(fns);
                }
                OSSL_FUNC_KDF_FREECTX if (*kdf).freectx.is_none() => {
                    (*kdf).freectx = entry_function::<KdfFreeCtxFn>(fns);
                    fnctxcnt += 1;
                }
                OSSL_FUNC_KDF_RESET if (*kdf).reset.is_none() => {
                    (*kdf).reset = entry_function::<KdfResetFn>(fns);
                }
                OSSL_FUNC_KDF_DERIVE if (*kdf).derive.is_none() => {
                    (*kdf).derive = entry_function::<KdfDeriveFn>(fns);
                    fnkdfcnt += 1;
                }
                OSSL_FUNC_KDF_GETTABLE_PARAMS if (*kdf).gettable_params.is_none() => {
                    (*kdf).gettable_params = entry_function::<KdfGettableParamsFn>(fns);
                }
                OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS if (*kdf).gettable_ctx_params.is_none() => {
                    (*kdf).gettable_ctx_params = entry_function::<KdfGettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS if (*kdf).settable_ctx_params.is_none() => {
                    (*kdf).settable_ctx_params = entry_function::<KdfSettableCtxParamsFn>(fns);
                }
                OSSL_FUNC_KDF_GET_PARAMS if (*kdf).get_params.is_none() => {
                    (*kdf).get_params = entry_function::<KdfGetParamsFn>(fns);
                }
                OSSL_FUNC_KDF_GET_CTX_PARAMS if (*kdf).get_ctx_params.is_none() => {
                    (*kdf).get_ctx_params = entry_function::<KdfGetCtxParamsFn>(fns);
                }
                OSSL_FUNC_KDF_SET_CTX_PARAMS if (*kdf).set_ctx_params.is_none() => {
                    (*kdf).set_ctx_params = entry_function::<KdfSetCtxParamsFn>(fns);
                }
                OSSL_FUNC_KDF_SET_SKEY if (*kdf).set_skey.is_none() => {
                    (*kdf).set_skey = entry_function::<KdfSetSkeyFn>(fns);
                }
                OSSL_FUNC_KDF_DERIVE_SKEY if (*kdf).derive_skey.is_none() => {
                    (*kdf).derive_skey = entry_function::<KdfDeriveSkeyFn>(fns);
                }
                _ => {}
            }
            fns = fns.add(1);
        }
    }

    // `!= 1 || != 2`: both counters must be exactly right, so a provider with two derivation paths
    // is refused as loudly as one with none.
    if fnkdfcnt != 1 || fnctxcnt != 2 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_METH_154) };
        // SAFETY: `kdf` is this call's own object.
        unsafe { EVP_KDF_free(kdf) };
        return ptr::null_mut();
    }

    if !prov.is_null() {
        // SAFETY: `prov` is live per the contract.
        if unsafe { ossl_provider_up_ref(prov) } == 0 {
            // SAFETY: `kdf` is this call's own object.
            unsafe { EVP_KDF_free(kdf) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `kdf` is live.
    unsafe { (*kdf).prov = prov };

    kdf.cast::<c_void>()
}

/// `EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `libctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_fetch(
    libctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpKdf {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            libctx,
            OSSL_OP_KDF,
            algorithm,
            properties,
            evp_kdf_from_algorithm as MethodFromAlgorithmFn,
            evp_kdf_up_ref as MethodUpRefFn,
            evp_kdf_free as MethodFreeFn,
        )
    }
    .cast::<EvpKdf>()
}

/// `int EVP_KDF_up_ref(EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_up_ref(kdf: *mut EvpKdf) -> c_int {
    // SAFETY: `kdf` is live per the contract.
    unsafe { (*kdf).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `void EVP_KDF_free(EVP_KDF *kdf)`.
///
/// The order is the authority's: the name, the provider reference, the block.
///
/// # Safety
/// `kdf` must be NULL or a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_free(kdf: *mut EvpKdf) {
    if kdf.is_null() {
        return;
    }
    // SAFETY: `kdf` is live per the contract.
    let last = unsafe { (*kdf).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: the count reached zero, so this is the last reference and the block is this call's.
    unsafe {
        CRYPTO_free((*kdf).type_name.cast::<c_void>(), FILE, LINE_FREE_TYPE_NAME);
        ossl_provider_free((*kdf).prov);
        CRYPTO_free(kdf.cast::<c_void>(), FILE, LINE_FREE_KDF);
    }
}

/// `int evp_kdf_get_number(const EVP_KDF *kdf)` — internal, and the namemap identity.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[allow(dead_code)] // no caller until 7.3f's EVP_SKEYMGMT glue needs it
pub(crate) unsafe fn evp_kdf_get_number(kdf: *const EvpKdf) -> c_int {
    // SAFETY: `kdf` is live per the contract.
    unsafe { (*kdf).name_id }
}

/// `const char *EVP_KDF_get0_name(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_get0_name(kdf: *const EvpKdf) -> *const c_char {
    // SAFETY: `kdf` is live per the contract.
    unsafe { (*kdf).type_name }
}

/// `const char *EVP_KDF_get0_description(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_get0_description(kdf: *const EvpKdf) -> *const c_char {
    // SAFETY: `kdf` is live per the contract.
    unsafe { (*kdf).description }
}

/// `int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name)`.
///
/// The NULL test is on the **method**, as `EVP_MAC_is_a`'s is and `EVP_MD_is_a`'s is not — and for
/// a method with no provider the answer is `evp_is_a`'s, which resolves the number from a NULL
/// legacy name and therefore matches an unknown name. That is the same quirk the MAC court
/// records; it is the authority's, and `RT-EVP-KDF` observes it rather than asserting it away.
///
/// # Safety
/// `kdf` must be NULL or a live `EvpKdf`; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_is_a(kdf: *const EvpKdf, name: *const c_char) -> c_int {
    if kdf.is_null() {
        return 0;
    }
    // SAFETY: `kdf` is live per the contract.
    let (prov, name_id) = unsafe { ((*kdf).prov, (*kdf).name_id) };
    // SAFETY: `prov` is the provider the method was fetched from and the visitor contract is the
    // namemap's.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `const OSSL_PROVIDER *EVP_KDF_get0_provider(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_get0_provider(kdf: *const EvpKdf) -> *const OsslProvider {
    // SAFETY: `kdf` is live per the contract.
    unsafe { (*kdf).prov }
}

/// `const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_gettable_params(kdf: *const EvpKdf) -> *const OsslParam {
    // SAFETY: `kdf` is live per the contract.
    let Some(f) = (unsafe { (*kdf).gettable_params }) else {
        return ptr::null();
    };
    // SAFETY: `kdf` is live, so a method with a `gettable_params` has a provider.
    let provctx = unsafe { ossl_provider_ctx((*kdf).prov) };
    // SAFETY: `f` is the provider's own callback and `provctx` is its context.
    unsafe { f(provctx) }
}

/// `const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_gettable_ctx_params(kdf: *const EvpKdf) -> *const OsslParam {
    // SAFETY: `kdf` is live per the contract.
    let Some(f) = (unsafe { (*kdf).gettable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `kdf` is live, so a method with a `gettable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*kdf).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), alg) }
}

/// `const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_settable_ctx_params(kdf: *const EvpKdf) -> *const OsslParam {
    // SAFETY: `kdf` is live per the contract.
    let Some(f) = (unsafe { (*kdf).settable_ctx_params }) else {
        return ptr::null();
    };
    // SAFETY: `kdf` is live, so a method with a `settable_ctx_params` has a provider.
    let alg = unsafe { ossl_provider_ctx((*kdf).prov) };
    // SAFETY: `f` is the provider's own callback; NULL is the method-level context.
    unsafe { f(ptr::null_mut(), alg) }
}

/// `const OSSL_PARAM *EVP_KDF_CTX_gettable_params(EVP_KDF_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_gettable_params(ctx: *mut EvpKdfCtx) -> *const OsslParam {
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

/// `const OSSL_PARAM *EVP_KDF_CTX_settable_params(EVP_KDF_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be a live context whose `meth` is live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_settable_params(ctx: *mut EvpKdfCtx) -> *const OsslParam {
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

/// `int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[])`.
///
/// Answers **1** for a missing callback, as the MAC class's does and the digest class's does not:
/// the two symmetric classes share the convention because they share an interface, and the digest
/// class predates it.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_get_params(kdf: *mut EvpKdf, params: *mut OsslParam) -> c_int {
    // SAFETY: `kdf` is live per the contract.
    let Some(f) = (unsafe { (*kdf).get_params }) else {
        return 1;
    };
    // SAFETY: `f` is the provider's own callback and `params` is the caller's array.
    unsafe { f(params) }
}

/// `int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_get_params(
    ctx: *mut EvpKdfCtx,
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

/// `int EVP_KDF_CTX_set_params(EVP_KDF_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be a live context; `params` NULL or terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_set_params(
    ctx: *mut EvpKdfCtx,
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

/// `int EVP_KDF_names_do_all(const EVP_KDF *kdf, void (*fn)(const char *name, void *data),
/// void *data)`.
///
/// # Safety
/// `kdf` must be a live `EvpKdf`; `fn_` NULL or a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_names_do_all(
    kdf: *const EvpKdf,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `kdf` is live per the contract.
    let (prov, name_id) = unsafe { ((*kdf).prov, (*kdf).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_KDF *kdf, void *arg),
/// void *arg)`.
///
/// A **NULL visitor is refused** rather than passed to a walk that would call it; the boundary is
/// `EVP_MD_do_all_provided`'s and is measured in `docs/SECURITY_DIVERGENCE_POLICY.md`
/// D-MD-DOALL-NULL-1.
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` is the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpKdf, *mut c_void)>,
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
            OSSL_OP_KDF,
            trampoline,
            arg,
            evp_kdf_from_algorithm as MethodFromAlgorithmFn,
            evp_kdf_up_ref as MethodUpRefFn,
            evp_kdf_free as MethodFreeFn,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------------------------

/// `EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf)`.
///
/// **A NULL method is refused before anything is allocated**, which is where this class and the MAC
/// class part company on an argument they both take: `EVP_MAC_CTX_new(NULL)` dereferences. Four
/// failure shapes follow, and the authority's `||` chain makes each of them fall to the same
/// release:
///
///   * the block is NULL -- `freectx` is **not** called, because the test that would read
///     `ctx->algctx` is never reached;
///   * `newctx` answered NULL -- `freectx` *is* called, with NULL, which the provider is contracted
///     to accept;
///   * the reference would not move -- `freectx` is called with the live context `newctx` produced,
///     so the algorithm context is not leaked;
///   * success -- and only then is `ctx->meth` assigned, which is why a caller can never observe a
///     context with a method and no algorithm context.
///
/// # Safety
/// `kdf` must be NULL or a live `EvpKdf`.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_new(kdf: *mut EvpKdf) -> *mut EvpKdfCtx {
    if kdf.is_null() {
        return ptr::null_mut();
    }
    let ctx =
        CRYPTO_zalloc(core::mem::size_of::<EvpKdfCtx>(), FILE, LINE_ZALLOC_CTX).cast::<EvpKdfCtx>();
    if ctx.is_null() {
        // The authority raises here too: its `ERR_raise` is the first statement of the `if`, and
        // `ctx == NULL` enters that `if`. Only the `freectx` call is guarded away, because the
        // test that would read `ctx->algctx` cannot be evaluated.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_LIB_35) };
        return ptr::null_mut();
    }

    // `newctx` and `freectx` are both non-NULL by the structural check every fetch performs; the
    // refusal below is therefore unreachable and is written as the same release path rather than as
    // a fault.
    // SAFETY: `kdf` is live per the contract.
    let (newctx, freectx) = unsafe { ((*kdf).newctx, (*kdf).freectx) };
    let algctx = match newctx {
        // SAFETY: `newctx` is the provider's own constructor and `provctx` is its context.
        Some(f) => {
            // SAFETY: `kdf` is live, so a method with a `newctx` has a provider.
            let provctx = unsafe { ossl_provider_ctx((*kdf).prov) };
            // SAFETY: `f` is the provider's own constructor and `provctx` is its context.
            unsafe { f(provctx) }
        }
        None => ptr::null_mut(),
    };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).algctx = algctx };

    // **The reference is taken only when the constructor succeeded.** The authority's chain is
    // `ctx == NULL || (ctx->algctx = ...) == NULL || !EVP_KDF_up_ref(kdf)`, and `||` short-circuits
    // -- so a provider that refuses its own context never has a reference taken on the method. A
    // transcription that evaluated both operands up front leaks one reference per refused
    // constructor, silently and forever; this bug was in this crate for one run of the unit tests
    // below, which is the only reason the shape is written out rather than folded into one
    // expression.
    let ok = if algctx.is_null() {
        false
    } else {
        // SAFETY: `kdf` is live per the contract.
        (unsafe { EVP_KDF_up_ref(kdf) }) != 0
    };
    if !ok {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_LIB_35) };
        if let Some(f) = freectx {
            // SAFETY: `f` is the method's own releaser and `algctx` is what its constructor left.
            unsafe { f(algctx) };
        }
        // SAFETY: `ctx` is this call's own block.
        unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_NEW) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live and everything before it succeeded.
    unsafe { (*ctx).meth = kdf };
    ctx
}

/// `void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be NULL or a live context this crate allocated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_free(ctx: *mut EvpKdfCtx) {
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
    // SAFETY: `meth` is live and this is the reference `EVP_KDF_CTX_new` took.
    unsafe { EVP_KDF_free(meth) };
    // SAFETY: `ctx` came from this crate's allocator and has just been released of everything.
    unsafe { CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_FREE_CTX) };
}

/// `EVP_KDF_CTX *EVP_KDF_CTX_dup(const EVP_KDF_CTX *src)`.
///
/// **Three refusals before anything is allocated**, and the third is the one this class has and the
/// MAC class does not: `src->meth->dupctx == NULL` answers NULL. `EVP_MAC_CTX_dup` reaches the
/// missing duplicator and faults — measured, `D-MAC-DUPCTX-NULL-1` — so the two files of this same
/// subphase disagree about what a method without a duplicator means, and that disagreement is the
/// authority's rather than a transcription's.
///
/// The reference on the method is taken **before** the algorithm context is duplicated, so the
/// failure path has a reference to give back.
///
/// # Safety
/// `src` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_dup(src: *const EvpKdfCtx) -> *mut EvpKdfCtx {
    if src.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `src` is live per the contract.
    // SAFETY: `src` is live per the contract.
    if unsafe { (*src).algctx }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `src` is live.
    let meth = unsafe { (*src).meth };
    // SAFETY: `meth` is live.
    if unsafe { (*meth).dupctx }.is_none() {
        return ptr::null_mut();
    }
    let dst = CRYPTO_malloc(core::mem::size_of::<EvpKdfCtx>(), FILE, LINE_MALLOC_CTX_DUP)
        .cast::<EvpKdfCtx>();
    if dst.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dst` is a fresh block of exactly the source's size and `src` is a live object.
    unsafe { ptr::copy_nonoverlapping(src, dst, 1) };

    // SAFETY: `dst` is live and its `meth` is the source's, which is live.
    if unsafe { EVP_KDF_up_ref((*dst).meth) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_LIB_69) };
        // SAFETY: `dst` is this call's own block and nothing else holds it.
        unsafe { CRYPTO_free(dst.cast::<c_void>(), FILE, LINE_FREE_CTX_ON_DUP) };
        return ptr::null_mut();
    }

    // SAFETY: `meth` is live, and its `dupctx` was tested above -- so the `None` arm is
    // unreachable. It is written as the same release-and-refuse the test above performs rather
    // than as a panic, because a panic is not a refusal a caller can catch across the ABI.
    let algctx = match unsafe { (*meth).dupctx } {
        // SAFETY: `f` is the provider's own callback and `src->algctx` is its context.
        Some(f) => unsafe { f((*src).algctx) },
        None => {
            // SAFETY: `dst` is this call's own context and the reference taken above is given
            // back here.
            unsafe { EVP_KDF_CTX_free(dst) };
            return ptr::null_mut();
        }
    };
    // SAFETY: `dst` is live.
    unsafe { (*dst).algctx = algctx };
    if algctx.is_null() {
        // SAFETY: `dst` is this call's own context, and the reference taken above is given back
        // here. `freectx` is called with the NULL the failed duplicate left, which is the state the
        // authority releases from too.
        unsafe { EVP_KDF_CTX_free(dst) };
        return ptr::null_mut();
    }
    dst
}

/// `const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx)`.
///
/// The **borrowed** method, and the answer is `const`: this class is the only one of the three that
/// hands its method back const-qualified, which is a typing difference a caller notices at compile
/// time and a court does not see at all.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_kdf(ctx: *mut EvpKdfCtx) -> *const EvpKdf {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).meth }
}

/// `void EVP_KDF_CTX_reset(EVP_KDF_CTX *ctx)`.
///
/// The provider's own reset, and **nothing else**: the algorithm context is not released and not
/// re-made, and a method with no `reset` is a silent success rather than a refusal. That is the
/// shape a caller uses to derive twice from the same context with different parameters.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_reset(ctx: *mut EvpKdfCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let reset = unsafe { (*meth).reset };
    if let Some(f) = reset {
        // SAFETY: `f` is the provider's own callback and `algctx` is its context.
        unsafe { f((*ctx).algctx) };
    }
}

/// `size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *ctx)`.
///
/// The two questions in the authority's order, and — unlike `EVP_MAC_CTX_get_mac_size` — **with no
/// gate on `algctx`**: a context whose algorithm context is NULL still asks its provider, and a
/// provider that answers without one is believed. The only refusal is a NULL *context*.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_get_kdf_size(ctx: *mut EvpKdfCtx) -> usize {
    let mut s: usize = 0;
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let (get_ctx_params, get_params) = unsafe { ((*meth).get_ctx_params, (*meth).get_params) };
    let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(); 2];
    // SAFETY: the constructor writes one entry and `params` has room for two; the key is a literal
    // and the value pointer is this frame's.
    unsafe { params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &mut s) };
    params[1] = OSSL_PARAM_construct_end();

    if let Some(f) = get_ctx_params {
        // SAFETY: `f` is the provider's own callback, `algctx` is its context and `params` is this
        // frame's array.
        if unsafe { f((*ctx).algctx, params.as_mut_ptr()) } != 0 {
            return s;
        }
    }
    if let Some(f) = get_params {
        // SAFETY: `f` is the provider's own callback and `params` is this frame's array.
        if unsafe { f(params.as_mut_ptr()) } != 0 {
            return s;
        }
    }
    0
}

/// `int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
/// const OSSL_PARAM params[])`.
///
/// A NULL context is refused; the method's `derive` is not tested, because the structural check
/// guarantees it. The `derive` callback receives the *caller's* parameters as well as the ones
/// already set on the context, which is the interface's own way of letting one derivation be
/// parameterised differently from the next.
///
/// # Safety
/// `ctx` must be NULL or a live context; `key` writable for `keylen` bytes; `params` NULL or
/// terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_derive(
    ctx: *mut EvpKdfCtx,
    key: *mut c_uchar,
    keylen: usize,
    params: *const OsslParam,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live and its `derive` is non-NULL by the structural check.
    let Some(f) = (unsafe { (*meth).derive }) else {
        return 0;
    };
    // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
    // arguments.
    unsafe { f((*ctx).algctx, key, keylen, params) }
}

// ---------------------------------------------------------------------------------------------
// The two entry points that take an object
//
// `EVP_KDF_CTX_set_SKEY` and `EVP_KDF_derive_SKEY` both take an `EVP_SKEY`. They were handed
// forward from 7.3e with the dependency named because the object's constructors did not exist yet;
// they landed with `src/evp/skeymgmt.rs`, and both are written here because a function belongs with
// the object it is a method of.
//
// All three raise sites in the file are `EVP_KDF_derive_SKEY`'s, and the first two are one line
// apart: a NULL context and a NULL key *type* raise together, and a fetch that finds no method in
// either the operation's provider or the libctx raises `ERR_R_FETCH_FAILED`.
// ---------------------------------------------------------------------------------------------

/// `struct convert_key { const char *name; OSSL_PARAM *param; }` — the export callback's argument
/// when a KDF can only take the key as *bytes*.
#[repr(C)]
struct ConvertKey {
    /// `const char *name` — the parameter the caller asked the key to be set under.
    name: *const c_char,
    /// `OSSL_PARAM *param` — the caller's slot, written by the callback.
    param: *mut OsslParam,
}

/// `static int convert_key_cb(const OSSL_PARAM params[], void *arg)`.
///
/// It reads exactly one parameter and answers 0 when it is absent, which is what turns "this
/// provider can only take bytes" into a refusal for a key that has no raw bytes to export. The
/// constructed parameter is written **into the caller's array** rather than returned, because the
/// array outlives the callback and a pointer into the export's own storage would not.
///
/// # Safety
/// `params` must be a terminated array; `arg` must point at a live `ConvertKey` whose `param`
/// points at storage for one `OSSL_PARAM`.
unsafe extern "C" fn convert_key_cb(params: *const OsslParam, arg: *mut c_void) -> c_int {
    let ckey = arg.cast::<ConvertKey>();
    if ckey.is_null() {
        return 0;
    }
    // SAFETY: `params` is a terminated array per the contract.
    let raw_bytes = unsafe { OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES) };
    if raw_bytes.is_null() {
        return 0;
    }
    let mut data: *const c_void = ptr::null();
    let mut len: usize = 0;
    // SAFETY: `raw_bytes` is a located entry of the caller's array and the two out-parameters are
    // this frame's own.
    if unsafe { OSSL_PARAM_get_octet_string_ptr(raw_bytes, &mut data, &mut len) } == 0 {
        return 0;
    }
    // SAFETY: `ckey` is live per the contract and its `param` slot is the caller's own storage.
    let (name, slot) = unsafe { ((*ckey).name, (*ckey).param) };
    // SAFETY: `name` is the caller's NUL-terminated string, `slot` is writable for one
    // `OSSL_PARAM`, and `data`/`len` describe the exported bytes.
    unsafe { *slot = OSSL_PARAM_construct_octet_string(name, data.cast_mut(), len) };
    1
}

/// `int EVP_KDF_CTX_set_SKEY(EVP_KDF_CTX *ctx, EVP_SKEY *key, const char *paramname)`.
///
/// **Two paths, and the choice between them is a provider comparison rather than a capability
/// test.** When the context's method publishes `set_skey` *and* the key came from the same provider,
/// the provider's own key data is handed over opaquely. Otherwise the key is **exported to bytes**
/// and set through the ordinary `set_ctx_params`, under a parameter named by the caller (or
/// `OSSL_KDF_PARAM_KEY` by default).
///
/// A context whose method publishes no `set_ctx_params` cannot take the fallback at all and is
/// refused, which is the one arm where a caller can distinguish "this provider takes keys" from
/// "this provider takes bytes".
///
/// Note the first test: a NULL context answers **0 without raising**, alone among the three
/// refusal paths in this pair.
///
/// # Safety
/// `ctx` must be NULL or a live context whose `meth` is live; `key` must be a live key; `paramname`
/// NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_CTX_set_SKEY(
    ctx: *mut EvpKdfCtx,
    key: *mut EvpSkey,
    paramname: *const c_char,
) -> c_int {
    let mut params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];

    if ctx.is_null() {
        return 0;
    }

    let name = if paramname.is_null() {
        OSSL_KDF_PARAM_KEY
    } else {
        paramname
    };

    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let (set_skey, meth_prov) = unsafe { ((*meth).set_skey, (*meth).prov) };
    // SAFETY: `key` is live per the contract.
    let skey_mgmt = unsafe { (*key).skeymgmt };
    // SAFETY: `skey_mgmt` is the method this key holds a reference to.
    let skey_prov = unsafe { (*skey_mgmt).prov };

    if set_skey.is_some() && skey_prov == meth_prov {
        // SAFETY: `ctx` and `key` are live and the callback is the method's own.
        let (algctx, keydata) = unsafe { ((*ctx).algctx, (*key).keydata) };
        let Some(f) = set_skey else {
            return 0;
        };
        // SAFETY: `f` is the provider's own callback and the rest are its context and the caller's
        // parameter name.
        return unsafe { f(algctx, keydata, name) };
    }

    // The fallback: the key is exported to bytes and set the traditional way.
    let mut ckey = ConvertKey {
        name,
        param: params.as_mut_ptr(),
    };
    // SAFETY: `meth` is live.
    let set_ctx_params = unsafe { (*meth).set_ctx_params };
    let Some(f) = set_ctx_params else {
        return 0;
    };
    // SAFETY: `key` is live and `ckey` is this frame's own live object whose address outlives the
    // call.
    if unsafe {
        EVP_SKEY_export(
            key,
            OSSL_SKEYMGMT_SELECT_SECRET_KEY,
            Some(convert_key_cb),
            ptr::addr_of_mut!(ckey).cast::<c_void>(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `ctx` is live, so its `algctx` is the implementation's context; `params` is this
    // frame's own terminated array, written by the callback above.
    unsafe { f((*ctx).algctx, params.as_ptr()) }
}

/// `EVP_SKEY *EVP_KDF_derive_SKEY(EVP_KDF_CTX *ctx, EVP_SKEYMGMT *mgmt, const char *key_type,
/// const char *propquery, size_t keylen, const OSSL_PARAM params[])`.
///
/// The derivation that produces a **key object** rather than a buffer, and the three ways it can
/// be satisfied:
///
///   1. **the caller supplied the method** (`mgmt != NULL`) — and then this function does *not own*
///      it, which is the whole meaning of every `if (mgmt != skeymgmt) EVP_SKEYMGMT_free(skeymgmt)`
///      in the body;
///   2. **the context's own provider** can produce it, so the method is fetched from that provider
///      and, if that fails, from the libctx — the same two-step fallback `evp_skey_alloc_fetch`
///      makes, for the same reason;
///   3. **the destination is a different provider, or has no `derive_skey`** — and then the key is
///      derived into a *buffer* and imported, which is the raw path and the reason
///      `EVP_SKEY_import_SKEYMGMT` exists as a public entry point at all.
///
/// The buffer of the raw path is **cleared** before it is released, which is the one thing in this
/// file that a caller cannot observe and that a transcription must not omit: it is the secret's only
/// copy.
///
/// # Safety
/// `ctx` NULL or a live context whose `meth` is live; `mgmt` NULL or a live method; `key_type` and
/// `propquery` NULL or NUL-terminated; `params` NULL or terminated.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn EVP_KDF_derive_SKEY(
    ctx: *mut EvpKdfCtx,
    mgmt: *mut EvpSkeyMgmt,
    key_type: *const c_char,
    propquery: *const c_char,
    keylen: usize,
    params: *const OsslParam,
) -> *mut EvpSkey {
    if ctx.is_null() || key_type.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KDF_LIB_211) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live per the contract.
    let meth = unsafe { (*ctx).meth };
    // SAFETY: `meth` is live.
    let meth_prov = unsafe { (*meth).prov };

    let skeymgmt: *mut EvpSkeyMgmt = if !mgmt.is_null() {
        mgmt
    } else {
        // SAFETY: `meth_prov` is live and the two strings are NULL or NUL-terminated.
        let mut fetched = unsafe { evp_skeymgmt_fetch_from_prov(meth_prov, key_type, propquery) };
        if fetched.is_null() {
            // The operation's provider does not publish it; the libctx may still have one.
            // SAFETY: `meth_prov` is live, so its libctx is readable.
            let libctx = unsafe { ossl_provider_libctx(meth_prov) };
            // SAFETY: `libctx` is NULL or live and the two strings are NULL or NUL-terminated.
            fetched = unsafe { EVP_SKEYMGMT_fetch(libctx, key_type, propquery) };
        }
        if fetched.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KDF_LIB_230) };
            return ptr::null_mut();
        }
        fetched
    };

    // SAFETY: `skeymgmt` is live.
    let (skeymgmt_prov, skeymgmt_import, derive_skey) =
        unsafe { ((*skeymgmt).prov, (*skeymgmt).import, (*meth).derive_skey) };

    // The raw fallback: a different provider, or a method that cannot derive a key object.
    if skeymgmt_prov != meth_prov || derive_skey.is_none() {
        let mut import_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];

        // SAFETY: `meth` is live.
        let derive = unsafe { (*meth).derive };
        let Some(derive) = derive else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KDF_LIB_241) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        };

        // SAFETY: `ctx` is live, so its `algctx` is the implementation's context.
        let algctx = unsafe { (*ctx).algctx };
        let key = CRYPTO_zalloc(keylen, FILE, LINE_ZALLOC_DERIVE_SKEY).cast::<c_uchar>();
        if key.is_null() {
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        }

        // SAFETY: `derive` is the provider's own callback, `algctx` is its context, `key` is this
        // call's own block of `keylen` bytes and `params` is the caller's.
        if unsafe { derive(algctx, key, keylen, params) } == 0 {
            // SAFETY: `key` is this call's own block and it holds a partial secret.
            unsafe { CRYPTO_free(key.cast::<c_void>(), FILE, LINE_FREE_DERIVE_SKEY_ON_FAIL) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        }

        // SAFETY: the constructor takes a key string and a buffer; the array is already terminated.
        import_params[0] = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_SKEY_PARAM_RAW_BYTES,
                key.cast::<c_void>(),
                keylen,
            )
        };

        // SAFETY: `meth_prov` is live, so its libctx is readable.
        let libctx = unsafe { ossl_provider_libctx(meth_prov) };
        // SAFETY: `libctx` is NULL or live, `skeymgmt` is live, and the array is this frame's own.
        let ret = unsafe {
            EVP_SKEY_import_SKEYMGMT(
                libctx,
                skeymgmt,
                OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                import_params.as_ptr(),
            )
        };

        if mgmt != skeymgmt {
            // SAFETY: `skeymgmt` is live and this is this call's own reference.
            unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        }

        // The secret is cleared before it is released: this buffer is its only copy outside the
        // caller's hands.
        // SAFETY: `key` is this call's own block of `keylen` bytes and is not used again.
        unsafe { CRYPTO_clear_free(key.cast::<c_void>(), keylen, FILE, LINE_FREE_DERIVE_SKEY) };
        return ret;
    }

    // The key-aware path.
    // SAFETY: `skeymgmt` is live.
    let ret = unsafe { evp_skey_alloc(skeymgmt) };
    if ret.is_null() {
        if mgmt != skeymgmt {
            // SAFETY: `skeymgmt` is live and this is this call's own reference.
            unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        }
        return ptr::null_mut();
    }

    // SAFETY: `skeymgmt_prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(skeymgmt_prov) };
    let Some(f) = derive_skey else {
        return ptr::null_mut();
    };
    // SAFETY: `ctx` is live, so its `algctx` is the implementation's context; the rest are the
    // caller's arguments and the destination method's own importer, which is what the callback
    // needs to build the key data it returns.
    let keydata = unsafe {
        f(
            (*ctx).algctx,
            key_type,
            provctx,
            skeymgmt_import.map_or(ptr::null_mut(), |import| import as *mut c_void),
            keylen,
            params,
        )
    };
    if keydata.is_null() {
        // SAFETY: `ret` is this call's own object.
        unsafe { EVP_SKEY_free(ret) };
        if mgmt != skeymgmt {
            // SAFETY: `skeymgmt` is live and this is this call's own reference.
            unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        }
        return ptr::null_mut();
    }
    // SAFETY: `ret` is live and `keydata` is what its method just produced.
    unsafe { (*ret).keydata = keydata };

    if mgmt != skeymgmt {
        // SAFETY: `skeymgmt` is live and this is this call's own reference.
        unsafe { EVP_SKEYMGMT_free(skeymgmt) };
    }
    ret
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_size_t};
    use crate::runtime::err::ERR_peek_last_error_all;
    use core::ffi::CStr;

    /// A method built by hand, so the arms of this file that are not about fetching can be read
    /// without a provider.
    fn a_hand_built_kdf() -> EvpKdf {
        EvpKdf {
            prov: ptr::null_mut(),
            name_id: 11,
            type_name: ptr::null_mut(),
            description: c"a hand-built KDF".as_ptr(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            dupctx: None,
            freectx: None,
            reset: None,
            derive: None,
            gettable_params: None,
            gettable_ctx_params: None,
            settable_ctx_params: None,
            get_params: None,
            get_ctx_params: None,
            set_ctx_params: None,
            set_skey: None,
            derive_skey: None,
        }
    }

    /// The failure path of `EVP_KDF_CTX_new`, reachable because a provider's `newctx` is allowed to
    /// answer NULL: the refusal is raised at the constructor's own coordinate, the method's
    /// `freectx` is **still called** — with the NULL the constructor left, which is the contract
    /// `EVP_MAC_CTX_new` relies on too — and the context block is released rather than leaked.
    ///
    /// A transcription that returned early on a NULL `algctx` would pass every other test in this
    /// module and leak the block here.
    #[test]
    fn a_provider_that_cannot_make_a_context_is_refused_and_released() {
        static FREES: AtomicI32 = AtomicI32::new(0);

        /// `static void *newctx(void *provctx)` — refuses.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn no_context(_provctx: *mut c_void) -> *mut c_void {
            ptr::null_mut()
        }

        /// `static void freectx(void *kctx)` — counts.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn counting_freectx(_kctx: *mut c_void) {
            FREES.fetch_add(1, Ordering::AcqRel);
        }

        let mut kdf = a_hand_built_kdf();
        kdf.newctx = Some(no_context);
        kdf.freectx = Some(counting_freectx);
        // SAFETY: the method is this frame's own live object.
        unsafe {
            assert!(EVP_KDF_CTX_new(ptr::addr_of_mut!(kdf)).is_null());
            assert_coordinate(&err_sites::KDF_LIB_35);
            assert_eq!(
                FREES.load(Ordering::Acquire),
                1,
                "the release ran even though there was nothing to release"
            );
            assert_eq!(
                kdf.refcnt.load(Ordering::Acquire),
                1,
                "and no reference was taken"
            );
        }
    }

    /// The coordinate of the last error raised, against a recorded site: the three strings a
    /// caller reads back through `ERR_get_error_all`.
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

    /// The accessors, the four parameter entry points, and `is_a`'s quirk — the same one the MAC
    /// class has, from a class that reads its own field for it.
    #[test]
    fn the_method_accessors_read_fields_and_guard_null() {
        let kdf = a_hand_built_kdf();
        let p: *const EvpKdf = ptr::addr_of!(kdf);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(evp_kdf_get_number(p), 11);
            assert!(EVP_KDF_get0_name(p).is_null());
            assert_eq!(
                CStr::from_ptr(EVP_KDF_get0_description(p)),
                c"a hand-built KDF"
            );
            assert!(EVP_KDF_get0_provider(p).is_null());
            /* `evp_is_a` with a NULL provider re-derives the number from a NULL legacy name, so
             * the answer is `0 == 0` and an unknown name "is a" match. The authority's own. */
            assert_eq!(EVP_KDF_is_a(p, c"whatever".as_ptr()), 1);
            assert_eq!(EVP_KDF_is_a(ptr::null(), c"whatever".as_ptr()), 0);
            assert_eq!(EVP_KDF_names_do_all(p, None, ptr::null_mut()), 1);
            assert!(EVP_KDF_gettable_params(p).is_null());
            assert!(EVP_KDF_gettable_ctx_params(p).is_null());
            assert!(EVP_KDF_settable_ctx_params(p).is_null());
            assert_eq!(EVP_KDF_get_params(p.cast_mut(), ptr::null_mut()), 1);
        }
    }

    /// `EVP_KDF_CTX_new` refuses a NULL **method** before allocating, which is the argument the MAC
    /// class dereferences — so the two classes of one subphase answer the same call differently and
    /// this asserts which answer is this file's.
    #[test]
    fn a_null_method_is_refused_before_anything_is_allocated() {
        // SAFETY: NULL is the documented refusal for this class.
        unsafe {
            assert!(EVP_KDF_CTX_new(ptr::null_mut()).is_null());
        }
    }

    /// The three refusals `EVP_KDF_CTX_dup` makes before allocating: a NULL context, a context with
    /// no algorithm context, and a method with no duplicator.
    ///
    /// The third is the one the MAC class does **not** make — it calls through the missing
    /// duplicator and faults (`D-MAC-DUPCTX-NULL-1`) — so this test is the pair that makes the
    /// difference visible in the crate's own test suite and not only in a court.
    #[test]
    fn the_three_refusals_of_dup_are_all_before_the_allocation() {
        let mut kdf = a_hand_built_kdf();
        let no_algctx = EvpKdfCtx {
            meth: ptr::addr_of_mut!(kdf),
            algctx: ptr::null_mut(),
        };
        let with_algctx = EvpKdfCtx {
            meth: ptr::addr_of_mut!(kdf),
            algctx: c"x".as_ptr() as *mut c_void,
        };
        // SAFETY: both contexts are this frame's own live objects and their method is too.
        unsafe {
            assert!(EVP_KDF_CTX_dup(ptr::null()).is_null(), "a NULL context");
            assert!(
                EVP_KDF_CTX_dup(ptr::addr_of!(no_algctx)).is_null(),
                "no algorithm context"
            );
            assert!(
                EVP_KDF_CTX_dup(ptr::addr_of!(with_algctx)).is_null(),
                "no duplicator -- and the MAC class faults here"
            );
            assert_eq!(
                kdf.refcnt.load(Ordering::Acquire),
                1,
                "and nothing was allocated or referenced"
            );
        }
    }

    /// `EVP_KDF_CTX_reset` is a provider callback and nothing more: no method, no `reset` is a
    /// **silent success**, which is what makes deriving twice from one context possible.
    #[test]
    fn the_reset_is_the_providers_and_silent_when_absent() {
        static RESETS: AtomicI32 = AtomicI32::new(0);

        /// `static void reset(void *kctx)` — counts and accepts.
        ///
        /// # Safety
        /// The ABI is the authority's; no argument is read.
        unsafe extern "C" fn counting_reset(_kctx: *mut c_void) {
            RESETS.fetch_add(1, Ordering::AcqRel);
        }

        let mut kdf = a_hand_built_kdf();
        let mut ctx = EvpKdfCtx {
            meth: ptr::addr_of_mut!(kdf),
            algctx: c"x".as_ptr() as *mut c_void,
        };
        let p: *mut EvpKdfCtx = ptr::addr_of_mut!(ctx);
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            EVP_KDF_CTX_reset(p);
            assert_eq!(RESETS.load(Ordering::Acquire), 0, "no callback, no call");
            EVP_KDF_CTX_reset(ptr::null_mut());
            assert_eq!(RESETS.load(Ordering::Acquire), 0);

            kdf.reset = Some(counting_reset);
            assert!(kdf.reset.is_some(), "the field the walk would have filled");
            EVP_KDF_CTX_reset(p);
            assert_eq!(RESETS.load(Ordering::Acquire), 1);
            /* And the algorithm context is still the same pointer: a reset resets, it does not
             * release and re-make. */
            assert_eq!(ctx.algctx, c"x".as_ptr() as *mut c_void);
        }
    }

    /// `EVP_KDF_CTX_get_kdf_size` differs from the MAC class's size question in one observable
    /// way: it does **not** gate on `algctx`. A context whose algorithm context is NULL still asks
    /// its provider, and a provider that answers without one is believed — so a caller can learn a
    /// KDF's output size before the context has been made, which is the shape a caller that has to
    /// allocate the output buffer needs.
    ///
    /// The provider here answers 32 through `get_ctx_params`; the same context asked through
    /// `EVP_MAC_CTX_get_mac_size` would answer 0.
    #[test]
    fn the_size_question_does_not_gate_on_the_algorithm_context() {
        /// `static int get_ctx_params(void *kctx, OSSL_PARAM params[])` — answers `size = 32`.
        ///
        /// # Safety
        /// `params` must be a terminated array of the caller's descriptors.
        unsafe extern "C" fn size_32(_kctx: *mut c_void, params: *mut OsslParam) -> c_int {
            // SAFETY: `params` is a terminated array per the contract and the key is a literal.
            let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE) };
            if !p.is_null() {
                // SAFETY: `p` is the caller's own descriptor for `size`.
                if unsafe { OSSL_PARAM_set_size_t(p, 32) } == 0 {
                    return 0;
                }
            }
            1
        }

        let mut kdf = a_hand_built_kdf();
        kdf.get_ctx_params = Some(size_32);
        let mut ctx = EvpKdfCtx {
            meth: ptr::addr_of_mut!(kdf),
            algctx: ptr::null_mut(),
        };
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            assert_eq!(EVP_KDF_CTX_get_kdf_size(ptr::addr_of_mut!(ctx)), 32);
            assert_eq!(EVP_KDF_CTX_get_kdf_size(ptr::null_mut()), 0);
        }
    }

    /// `EVP_KDF_derive` refuses a NULL context and answers 0 for a method with no derivation
    /// callback rather than calling through it. The arm is unreachable through a fetch — the
    /// structural check counts `derive` — so this is a transcription of an arm.
    #[test]
    fn the_derive_refuses_a_null_context_and_a_missing_callback() {
        let mut kdf = a_hand_built_kdf();
        let mut ctx = EvpKdfCtx {
            meth: ptr::addr_of_mut!(kdf),
            algctx: ptr::null_mut(),
        };
        let out = [0u8; 32];
        // SAFETY: the context and its method are this frame's own live objects.
        unsafe {
            assert_eq!(
                EVP_KDF_derive(
                    ptr::addr_of_mut!(ctx),
                    out.as_ptr() as *mut c_uchar,
                    32,
                    ptr::null()
                ),
                0
            );
            assert_eq!(
                EVP_KDF_derive(
                    ptr::null_mut(),
                    out.as_ptr() as *mut c_uchar,
                    32,
                    ptr::null()
                ),
                0
            );
            /* The four parameter entry points answer 1 with no callback, as the MAC class's do. */
            assert_eq!(
                EVP_KDF_CTX_get_params(ptr::addr_of_mut!(ctx), ptr::null_mut()),
                1
            );
            assert_eq!(
                EVP_KDF_CTX_set_params(ptr::addr_of_mut!(ctx), ptr::null()),
                1
            );
            assert!(EVP_KDF_CTX_gettable_params(ptr::addr_of_mut!(ctx)).is_null());
            assert!(EVP_KDF_CTX_settable_params(ptr::addr_of_mut!(ctx)).is_null());
        }
    }

    /// The reference count, which is the only ownership rule this class has.
    #[test]
    fn the_reference_count_is_the_only_ownership_rule() {
        let mut kdf = a_hand_built_kdf();
        let p: *mut EvpKdf = ptr::addr_of_mut!(kdf);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(EVP_KDF_up_ref(p), 1, "always 1, never the count");
            assert_eq!(kdf.refcnt.load(Ordering::Acquire), 2);
            EVP_KDF_free(p);
            assert_eq!(
                kdf.refcnt.load(Ordering::Acquire),
                1,
                "not the last one yet"
            );
            assert_eq!(kdf.name_id, 11);
            EVP_KDF_free(ptr::null_mut());
        }
    }
}
