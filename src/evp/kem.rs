//! Phase 7.4 — the `EVP_KEM` method object.
//!
//! `crypto/evp/kem.c` whole: the **method half** — the object, its lifetime, and the eleven exports
//! that reach it — and the **operation half**: `EVP_PKEY_encapsulate_init`, `EVP_PKEY_encapsulate`,
//! `EVP_PKEY_decapsulate_init`, `EVP_PKEY_decapsulate` and the two `auth_*_init` spellings. The
//! operations are here rather than with the method object because every one of them reads
//! `ctx->operation` and `ctx->op.encap.algctx`, which belong to the `EVP_PKEY_CTX` object that landed
//! in 7.4c-i.
//!
//! ## The structural check is the only one in the family with a *balanced* clause
//!
//! ```text
//! ctxfncnt      == 2                          newctx + freectx, both mandatory
//! encfncnt      in {0, 2, 3}                  encapsulate_init, and/or auth_encapsulate_init,
//!                                             and encapsulate
//! decfncnt      in {0, 2, 3}                  the same three on the decapsulation side
//! encfncnt      == decfncnt                   **the balance clause**
//! gparamfncnt   in {0, 2}                     get_ctx_params + gettable_ctx_params
//! sparamfncnt   in {0, 2}                     set_ctx_params + settable_ctx_params
//! ```
//!
//! The fourth clause has no analogue in the other four classes and is the reason this method half is
//! not a copy of the asymmetric cipher's. A KEM's two directions are **not independently optional the
//! way a cipher's are**: a cipher may publish only an encryptor, but a KEM that publishes only an
//! encapsulator is refused, and one that publishes the *authenticating* initialiser on one side must
//! publish it on the other, because a count of three on either side is only reachable through that
//! initialiser. So the accepted counts are the *pairs* (0,0), (2,2) and (3,3) — never (3,2) — and a
//! transcription that wrote the cipher's `encfncnt != 2 && decfncnt != 2` clause would accept
//! (3,2) and reject (3,3).
//!
//! The `dupctx` arm is **not counted**, exactly as in the `EVP_ASYM_CIPHER` and `EVP_KEYMGMT` classes.
//!
//! ## The failure is a plain `ERR_raise`
//!
//! Like the asymmetric cipher's and unlike the signature class's: one reason code,
//! `EVP_R_INVALID_PROVIDER_FUNCTIONS`, and no message naming the clause that failed. The comment above
//! it is the only place the accepted shapes are written down, and the accepted shapes are what the
//! court has to provoke.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::context::dispatch::{entry_function, OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::algorithm::ossl_algorithm_get1_first_name;
use crate::evp::fetch::{
    evp_generic_do_all, evp_generic_fetch, evp_generic_fetch_from_prov, evp_is_a, evp_names_do_all,
    GenericDoAllFn, MethodFromAlgorithmFn,
};
use crate::evp::keymgmt::{
    evp_keymgmt_fetch_from_prov, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name,
    EVP_KEYMGMT_get0_provider, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::evp_keymgmt_util_query_operation_name;
use crate::evp::pkey::{evp_pkey_export_to_provider, EvpPkey};
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_free_old_ops, EvpPkeyCtx, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE,
    EVP_PKEY_OP_UNDEFINED,
};
use crate::params::OsslParam;
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_OP_KEM` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_KEM: c_int = 14;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/kem.c".as_ptr();
/// `evp_kem_new`'s `OPENSSL_zalloc(sizeof(EVP_KEM))` (line 287).
const LINE_ZALLOC_KEM: c_int = 287;
/// `EVP_KEM_free`'s `OPENSSL_free(kem->type_name)` (line 443).
const LINE_FREE_TYPE_NAME: c_int = 443;
/// `EVP_KEM_free`'s `OPENSSL_free(kem)` (line 446).
const LINE_FREE_KEM: c_int = 446;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the thirteen function-pointer types.
//
// `OSSL_FUNC_KEM_*`, dense from 1 to 13. The two authenticating initialisers are **12** and **13**,
// which is why `encfncnt` and `decfncnt` can reach three and why the balance clause exists.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_KEM_NEWCTX`.
pub(crate) const OSSL_FUNC_KEM_NEWCTX: c_int = 1;
/// `OSSL_FUNC_KEM_ENCAPSULATE_INIT`.
pub(crate) const OSSL_FUNC_KEM_ENCAPSULATE_INIT: c_int = 2;
/// `OSSL_FUNC_KEM_ENCAPSULATE`.
pub(crate) const OSSL_FUNC_KEM_ENCAPSULATE: c_int = 3;
/// `OSSL_FUNC_KEM_DECAPSULATE_INIT`.
pub(crate) const OSSL_FUNC_KEM_DECAPSULATE_INIT: c_int = 4;
/// `OSSL_FUNC_KEM_DECAPSULATE`.
pub(crate) const OSSL_FUNC_KEM_DECAPSULATE: c_int = 5;
/// `OSSL_FUNC_KEM_FREECTX`.
pub(crate) const OSSL_FUNC_KEM_FREECTX: c_int = 6;
/// `OSSL_FUNC_KEM_DUPCTX`.
const OSSL_FUNC_KEM_DUPCTX: c_int = 7;
/// `OSSL_FUNC_KEM_GET_CTX_PARAMS`.
const OSSL_FUNC_KEM_GET_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_KEM_SET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEM_SET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS: c_int = 11;
/// `OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT`.
pub(crate) const OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT: c_int = 12;
/// `OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT`.
pub(crate) const OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT: c_int = 13;

/// `OSSL_FUNC_kem_newctx_fn`.
pub(crate) type KemNewctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_kem_encapsulate_init_fn`.
pub(crate) type KemEncapsulateInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kem_auth_encapsulate_init_fn`.
pub(crate) type KemAuthEncapsulateInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kem_encapsulate_fn`.
pub(crate) type KemEncapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, *mut u8, *mut usize) -> c_int;
/// `OSSL_FUNC_kem_decapsulate_init_fn`.
pub(crate) type KemDecapsulateInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kem_auth_decapsulate_init_fn`.
pub(crate) type KemAuthDecapsulateInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kem_decapsulate_fn`.
pub(crate) type KemDecapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_kem_freectx_fn`.
pub(crate) type KemFreectxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_kem_dupctx_fn`.
pub(crate) type KemDupctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_kem_get_ctx_params_fn`.
pub(crate) type KemGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_kem_gettable_ctx_params_fn`.
pub(crate) type KemGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_kem_set_ctx_params_fn`.
pub(crate) type KemSetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_kem_settable_ctx_params_fn`.
pub(crate) type KemSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;

/// `struct evp_kem_st` — `crypto/evp/evp_local.h`.
#[repr(C)]
pub struct EvpKem {
    /// `int name_id`.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_kem_newctx_fn *newctx` — mandatory.
    pub(crate) newctx: Option<KemNewctxFn>,
    /// `OSSL_FUNC_kem_encapsulate_init_fn *encapsulate_init`.
    pub(crate) encapsulate_init: Option<KemEncapsulateInitFn>,
    /// `OSSL_FUNC_kem_encapsulate_fn *encapsulate`.
    pub(crate) encapsulate: Option<KemEncapsulateFn>,
    /// `OSSL_FUNC_kem_decapsulate_init_fn *decapsulate_init`.
    pub(crate) decapsulate_init: Option<KemDecapsulateInitFn>,
    /// `OSSL_FUNC_kem_decapsulate_fn *decapsulate`.
    pub(crate) decapsulate: Option<KemDecapsulateFn>,
    /// `OSSL_FUNC_kem_freectx_fn *freectx` — mandatory.
    pub(crate) freectx: Option<KemFreectxFn>,
    /// `OSSL_FUNC_kem_dupctx_fn *dupctx` — optional, and **not** counted.
    pub(crate) dupctx: Option<KemDupctxFn>,
    /// `OSSL_FUNC_kem_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<KemGetCtxParamsFn>,
    /// `OSSL_FUNC_kem_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<KemGettableCtxParamsFn>,
    /// `OSSL_FUNC_kem_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<KemSetCtxParamsFn>,
    /// `OSSL_FUNC_kem_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<KemSettableCtxParamsFn>,
    /// `OSSL_FUNC_kem_auth_encapsulate_init_fn *auth_encapsulate_init`.
    pub(crate) auth_encapsulate_init: Option<KemAuthEncapsulateInitFn>,
    /// `OSSL_FUNC_kem_auth_decapsulate_init_fn *auth_decapsulate_init`.
    pub(crate) auth_decapsulate_init: Option<KemAuthDecapsulateInitFn>,
}

/// `static void evp_kem_free(void *data)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `data` must be NULL or a live `EvpKem`.
unsafe extern "C" fn evp_kem_free(data: *mut c_void) {
    // SAFETY: `data` is NULL or live per the contract.
    unsafe { EVP_KEM_free(data.cast::<EvpKem>()) }
}

/// `static int evp_kem_up_ref(void *data)`.
///
/// # Safety
/// `data` must be a live `EvpKem`.
unsafe extern "C" fn evp_kem_up_ref(data: *mut c_void) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { EVP_KEM_up_ref(data.cast::<EvpKem>()) }
}

/// `static EVP_KEM *evp_kem_new(OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `prov` must be live.
unsafe fn evp_kem_new(prov: *mut OsslProvider) -> *mut EvpKem {
    /* `CRYPTO_zalloc` is a safe entry point of this crate: it validates its own argument. */
    let kem = CRYPTO_zalloc(core::mem::size_of::<EvpKem>(), FILE, LINE_ZALLOC_KEM).cast::<EvpKem>();
    if kem.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `kem` is this call's own object and `prov` is live.
    unsafe {
        (*kem).refcnt = AtomicI32::new(1);
        (*kem).prov = prov;
        ossl_provider_up_ref(prov);
    }
    kem
}

/// `static void *evp_kem_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `algodef` must be live; `prov` must be live.
unsafe extern "C" fn evp_kem_from_algorithm(
    name_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: `prov` is live per the contract.
    let kem = unsafe { evp_kem_new(prov) };
    if kem.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `kem` is live.
    unsafe { (*kem).name_id = name_id };
    // SAFETY: `algodef` is live.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `kem` is this call's own object.
        unsafe { EVP_KEM_free(kem) };
        return ptr::null_mut();
    }
    // SAFETY: `kem` is live and `type_name` is the string just allocated for it.
    unsafe { (*kem).type_name = type_name };
    // SAFETY: both are live.
    unsafe { (*kem).description = (*algodef).algorithm_description };

    let mut ctxfncnt = 0;
    let mut encfncnt = 0;
    let mut decfncnt = 0;
    let mut gparamfncnt = 0;
    let mut sparamfncnt = 0;

    // SAFETY: `fns` is a terminated table per the contract.
    let mut entry = fns;
    // SAFETY: `fns` is a terminated table, so the walk leaves it at the terminator.
    unsafe {
        while (*entry).function_id != OSSL_DISPATCH_END {
            match (*entry).function_id {
                OSSL_FUNC_KEM_NEWCTX if (*kem).newctx.is_none() => {
                    (*kem).newctx = entry_function::<KemNewctxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_KEM_ENCAPSULATE_INIT if (*kem).encapsulate_init.is_none() => {
                    (*kem).encapsulate_init = entry_function::<KemEncapsulateInitFn>(entry);
                    encfncnt += 1;
                }
                OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT if (*kem).auth_encapsulate_init.is_none() => {
                    (*kem).auth_encapsulate_init =
                        entry_function::<KemAuthEncapsulateInitFn>(entry);
                    encfncnt += 1;
                }
                OSSL_FUNC_KEM_ENCAPSULATE if (*kem).encapsulate.is_none() => {
                    (*kem).encapsulate = entry_function::<KemEncapsulateFn>(entry);
                    encfncnt += 1;
                }
                OSSL_FUNC_KEM_DECAPSULATE_INIT if (*kem).decapsulate_init.is_none() => {
                    (*kem).decapsulate_init = entry_function::<KemDecapsulateInitFn>(entry);
                    decfncnt += 1;
                }
                OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT if (*kem).auth_decapsulate_init.is_none() => {
                    (*kem).auth_decapsulate_init =
                        entry_function::<KemAuthDecapsulateInitFn>(entry);
                    decfncnt += 1;
                }
                OSSL_FUNC_KEM_DECAPSULATE if (*kem).decapsulate.is_none() => {
                    (*kem).decapsulate = entry_function::<KemDecapsulateFn>(entry);
                    decfncnt += 1;
                }
                OSSL_FUNC_KEM_FREECTX if (*kem).freectx.is_none() => {
                    (*kem).freectx = entry_function::<KemFreectxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_KEM_DUPCTX if (*kem).dupctx.is_none() => {
                    (*kem).dupctx = entry_function::<KemDupctxFn>(entry);
                }
                OSSL_FUNC_KEM_GET_CTX_PARAMS if (*kem).get_ctx_params.is_none() => {
                    (*kem).get_ctx_params = entry_function::<KemGetCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS if (*kem).gettable_ctx_params.is_none() => {
                    (*kem).gettable_ctx_params = entry_function::<KemGettableCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_KEM_SET_CTX_PARAMS if (*kem).set_ctx_params.is_none() => {
                    (*kem).set_ctx_params = entry_function::<KemSetCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS if (*kem).settable_ctx_params.is_none() => {
                    (*kem).settable_ctx_params = entry_function::<KemSettableCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                _ => {}
            }
            entry = entry.add(1);
        }
    }

    /* The balance clause: `encfncnt == decfncnt`. See this module's documentation -- it accepts
     * (0,0), (2,2) and (3,3) and refuses everything else, which no sibling class does. */
    let inconsistent = ctxfncnt != 2
        || (encfncnt != 0 && encfncnt != 2 && encfncnt != 3)
        || (decfncnt != 0 && decfncnt != 2 && decfncnt != 3)
        || encfncnt != decfncnt
        || (gparamfncnt != 0 && gparamfncnt != 2)
        || (sparamfncnt != 0 && sparamfncnt != 2);
    if inconsistent {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_157) };
        // SAFETY: `kem` is this call's own object.
        unsafe { EVP_KEM_free(kem) };
        return ptr::null_mut();
    }

    kem.cast::<c_void>()
}

/// `void EVP_KEM_free(EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_free(kem: *mut EvpKem) {
    if kem.is_null() {
        return;
    }
    // SAFETY: `kem` is live per the contract.
    let last = unsafe { (*kem).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: `kem` is live and this was the last reference.
    let (type_name, prov) = unsafe { ((*kem).type_name, (*kem).prov) };
    // SAFETY: `type_name` was allocated for this object.
    unsafe { CRYPTO_free(type_name.cast(), FILE, LINE_FREE_TYPE_NAME) };
    // SAFETY: `prov` is live and holds the reference `evp_kem_new` took.
    unsafe { ossl_provider_free(prov) };
    // SAFETY: `kem` is this object's own allocation.
    unsafe { CRYPTO_free(kem.cast(), FILE, LINE_FREE_KEM) };
}

/// `int EVP_KEM_up_ref(EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_up_ref(kem: *mut EvpKem) -> c_int {
    // SAFETY: `kem` is live per the contract.
    unsafe { (*kem).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_get0_provider(kem: *const EvpKem) -> *mut OsslProvider {
    // SAFETY: `kem` is live per the contract.
    unsafe { (*kem).prov }
}

/// `EVP_KEM *EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpKem {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_KEM,
            algorithm,
            properties,
            evp_kem_from_algorithm as MethodFromAlgorithmFn,
            evp_kem_up_ref as MethodUpRefFn,
            evp_kem_free as MethodFreeFn,
        )
    }
    .cast::<EvpKem>()
}

/// `EVP_KEM *evp_kem_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `prov` must be live; `algorithm` and `properties` NULL or NUL-terminated.
#[allow(dead_code)] // first live caller is `evp_kem_init`
pub(crate) unsafe fn evp_kem_fetch_from_prov(
    prov: *mut OsslProvider,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpKem {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_KEM,
            algorithm,
            properties,
            evp_kem_from_algorithm as MethodFromAlgorithmFn,
            evp_kem_up_ref as MethodUpRefFn,
            evp_kem_free as MethodFreeFn,
        )
    }
    .cast::<EvpKem>()
}

/// `int EVP_KEM_is_a(const EVP_KEM *kem, const char *name)`.
///
/// # Safety
/// `kem` must be live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_is_a(kem: *const EvpKem, name: *const c_char) -> c_int {
    // SAFETY: `kem` is live per the contract.
    let (prov, name_id) = unsafe { ((*kem).prov, (*kem).name_id) };
    // SAFETY: `prov` is live and `name` is NUL-terminated.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `int evp_kem_get_number(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be live.
#[allow(dead_code)] // read by the `EVP_PKEY_CTX` construction path in 7.4c
pub(crate) unsafe fn evp_kem_get_number(kem: *const EvpKem) -> c_int {
    // SAFETY: `kem` is live per the contract.
    unsafe { (*kem).name_id }
}

/// `const char *EVP_KEM_get0_name(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_get0_name(kem: *const EvpKem) -> *const c_char {
    // SAFETY: `kem` is live per the contract.
    unsafe { (*kem).type_name }
}

/// `const char *EVP_KEM_get0_description(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_get0_description(kem: *const EvpKem) -> *const c_char {
    // SAFETY: `kem` is live per the contract.
    unsafe { (*kem).description }
}

/// `void EVP_KEM_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_KEM *, void *), void *arg)`.
///
/// A **NULL visitor is refused**; the boundary is `EVP_MD_do_all_provided`'s
/// (`D-MD-DOALL-NULL-1`).
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpKem, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(visitor) = fn_ else {
        return;
    };
    // SAFETY: the visitor is the caller's and `arg` is its own; the three callbacks are this
    // module's own.
    unsafe {
        evp_generic_do_all(
            libctx,
            OSSL_OP_KEM,
            core::mem::transmute::<unsafe extern "C" fn(*mut EvpKem, *mut c_void), GenericDoAllFn>(
                visitor,
            ),
            arg,
            evp_kem_from_algorithm as MethodFromAlgorithmFn,
            evp_kem_up_ref as MethodUpRefFn,
            evp_kem_free as MethodFreeFn,
        )
    };
}

/// `int EVP_KEM_names_do_all(const EVP_KEM *kem, void (*fn)(const char *name, void *data),
/// void *data)`.
///
/// # Safety
/// `kem` must be live; `fn_` a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_names_do_all(
    kem: *const EvpKem,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `kem` is live per the contract.
    let (prov, name_id) = unsafe { ((*kem).prov, (*kem).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor's contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *EVP_KEM_gettable_ctx_params(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_gettable_ctx_params(kem: *const EvpKem) -> *const OsslParam {
    if kem.is_null() {
        return ptr::null();
    }
    // SAFETY: `kem` is live per the contract.
    let (f, prov) = unsafe { ((*kem).gettable_ctx_params, (*kem).prov) };
    let Some(gettable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `gettable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { gettable(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_KEM_settable_ctx_params(const EVP_KEM *kem)`.
///
/// # Safety
/// `kem` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEM_settable_ctx_params(kem: *const EvpKem) -> *const OsslParam {
    if kem.is_null() {
        return ptr::null();
    }
    // SAFETY: `kem` is live per the contract.
    let (f, prov) = unsafe { ((*kem).settable_ctx_params, (*kem).prov) };
    let Some(settable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `settable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { settable(ptr::null_mut(), provctx) }
}

// ---------------------------------------------------------------------------------------------
// The operation half — `evp_kem_init` and the six exports over it.
//
// These read `ctx->operation` and `ctx->op.encap.algctx`, which is why they land after the
// `EVP_PKEY_CTX` object (7.4c-i) rather than with the method object above.
// ---------------------------------------------------------------------------------------------

/// The authority's `err:` label — `crypto/evp/kem.c:204`.
///
/// # Safety
/// `ctx` must be live; `tmp_keymgmt` NULL or live.
unsafe fn evp_kem_init_err(
    ctx: *mut EvpPkeyCtx,
    tmp_keymgmt: *mut EvpKeyMgmt,
    ret: c_int,
) -> c_int {
    if ret <= 0 {
        // SAFETY: `ctx` is live.
        unsafe { evp_pkey_ctx_free_old_ops(ctx) };
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
    }
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    ret
}

/// `static int evp_kem_init(EVP_PKEY_CTX *ctx, int operation, const OSSL_PARAM params[],
/// EVP_PKEY *authkey)` — `crypto/evp/kem.c:30`.
///
/// Three things distinguish this from `evp_pkey_asym_cipher_init`, and each is a place a copy would
/// have been wrong:
///
///   * there is **no mark**. The asymmetric cipher brackets its fetches with `ERR_set_mark` and pops
///     them on the way to `legacy:`; a KEM has no legacy fallback to reach, so no fetch error is ever
///     withdrawn;
///   * `ctx->keytype` is tested **as well as** `ctx`, and a NULL `keytype` is refused with
///     `EVP_R_INITIALIZATION_ERROR` rather than `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`;
///   * a mismatched `authkey` returns **0 with the operation still set** — not through `err:`, so
///     the context is not torn down. That is the authority's own asymmetry and it is observable.
///
/// # Safety
/// `ctx` NULL or live; `authkey` NULL or live; `params` NULL or a terminated array.
unsafe fn evp_kem_init(
    ctx: *mut EvpPkeyCtx,
    operation: c_int,
    params: *const OsslParam,
    authkey: *mut EvpPkey,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_42) };
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).keytype }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_42) };
        return 0;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = operation };

    // SAFETY: `ctx` is live.
    let pkey = unsafe { (*ctx).pkey };
    if pkey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_50) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { evp_kem_init_err(ctx, ptr::null_mut(), 0) };
    }

    if !authkey.is_null() {
        // SAFETY: both keys are live.
        let (auth_type, pkey_type) = unsafe { ((*authkey).type_, (*pkey).type_) };
        if auth_type != pkey_type {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KEM_54) };
            /* `return 0`, **not** `goto err`: the operation stays set and the old ops stay freed of
             * nothing. The authority's own report is unambiguous, and it is the one place in this
             * file where a failure does not tear the context down. */
            return 0;
        }
    }

    /* `ossl_assert` under `NDEBUG` is `(x) != 0`, so this is a live refusal (`docs/DECISIONS.md`
     * D167). */
    // SAFETY: `pkey` is live.
    let pkey_keymgmt = unsafe { (*pkey).keymgmt };
    // SAFETY: `ctx` is live.
    if !(pkey_keymgmt.is_null() || pkey_keymgmt == unsafe { (*ctx).keymgmt }) {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_62) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { evp_kem_init_err(ctx, ptr::null_mut(), 0) };
    }

    // SAFETY: `ctx` is live.
    let ctx_keymgmt = unsafe { (*ctx).keymgmt };
    // SAFETY: `ctx_keymgmt` is live — the context is provided-side, so it has a method.
    let supported_kem = unsafe { evp_keymgmt_util_query_operation_name(ctx_keymgmt, OSSL_OP_KEM) };
    if supported_kem.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_68) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { evp_kem_init_err(ctx, ptr::null_mut(), 0) };
    }

    let mut kem: *mut EvpKem = ptr::null_mut();
    let mut tmp_keymgmt: *mut EvpKeyMgmt = ptr::null_mut();
    let mut tmp_prov: *const OsslProvider = ptr::null();
    let mut provkey: *mut c_void = ptr::null_mut();
    let mut provauthkey: *mut c_void = ptr::null_mut();

    let mut iter: c_int = 1;
    while iter < 3 && provkey.is_null() {
        // SAFETY: `kem` is NULL or live.
        unsafe { EVP_KEM_free(kem) };
        // SAFETY: `tmp_keymgmt` is NULL or live.
        unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
        tmp_keymgmt = ptr::null_mut();

        if iter == 1 {
            // SAFETY: `ctx` is live.
            let (libctx, propquery) = unsafe { ((*ctx).libctx, (*ctx).propquery) };
            // SAFETY: `libctx` is live and `supported_kem` is NUL-terminated.
            kem = unsafe { EVP_KEM_fetch(libctx, supported_kem, propquery) };
            if !kem.is_null() {
                // SAFETY: `kem` is live.
                tmp_prov = unsafe { EVP_KEM_get0_provider(kem) };
            }
        } else {
            // SAFETY: `ctx_keymgmt` is live.
            tmp_prov = unsafe { EVP_KEYMGMT_get0_provider(ctx_keymgmt) };
            // SAFETY: `ctx` is live.
            let propquery = unsafe { (*ctx).propquery };
            // SAFETY: `tmp_prov` is live and `supported_kem` is NUL-terminated.
            kem = unsafe { evp_kem_fetch_from_prov(tmp_prov.cast_mut(), supported_kem, propquery) };
            if kem.is_null() {
                /* Unlike the asymmetric cipher's second iteration, this one does **not** fall back:
                 * a KEM has no legacy half, so a provider-specific miss is the final answer. */
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::KEM_116) };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, -2) };
            }
        }

        if !kem.is_null() {
            // SAFETY: `ctx_keymgmt` is live and its name is NUL-terminated; `ctx` is live.
            let (name, propquery) =
                unsafe { (EVP_KEYMGMT_get0_name(ctx_keymgmt), (*ctx).propquery) };
            // SAFETY: `tmp_prov` is live and `name` is NUL-terminated.
            let tmp_keymgmt_tofree =
                unsafe { evp_keymgmt_fetch_from_prov(tmp_prov.cast_mut(), name, propquery) };
            tmp_keymgmt = tmp_keymgmt_tofree;
            if !tmp_keymgmt.is_null() {
                // SAFETY: `ctx` is live.
                let libctx = unsafe { (*ctx).libctx };
                // SAFETY: `pkey` is live, and `tmp_keymgmt` is a live local whose address is valid
                // for the call -- which may replace it.
                provkey = unsafe {
                    evp_pkey_export_to_provider(
                        pkey,
                        libctx,
                        ptr::addr_of_mut!(tmp_keymgmt),
                        propquery,
                    )
                };
                if !provkey.is_null() && !authkey.is_null() {
                    // SAFETY: `authkey` is live and `tmp_keymgmt`'s address is valid for the call.
                    provauthkey = unsafe {
                        evp_pkey_export_to_provider(
                            authkey,
                            libctx,
                            ptr::addr_of_mut!(tmp_keymgmt),
                            propquery,
                        )
                    };
                    if provauthkey.is_null() {
                        // SAFETY: `kem` is live and the caller drops its reference here.
                        unsafe { EVP_KEM_free(kem) };
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::KEM_146) };
                        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, 0) };
                    }
                }
            }
            if tmp_keymgmt.is_null() {
                // SAFETY: `tmp_keymgmt_tofree` is NULL or live and the caller dropped it.
                unsafe { EVP_KEYMGMT_free(tmp_keymgmt_tofree) };
            }
        }
        iter += 1;
    }

    if provkey.is_null() {
        // SAFETY: `kem` is NULL or live.
        unsafe { EVP_KEM_free(kem) };
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_157) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, 0) };
    }

    // SAFETY: `ctx` is live and `kem` is live.
    unsafe { (*ctx).op_encap_kem = kem };
    /* `newctx` is mandatory: a provider that publishes no `OSSL_FUNC_KEM_NEWCTX` is refused by the
     * walk, so the `else` is unreachable and gives the authority's own INITIALIZATION_ERROR. */
    // SAFETY: `kem` is live.
    let Some(newctx) = (unsafe { (*kem).newctx }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_165) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, 0) };
    };
    // SAFETY: `newctx` is the provider's own callback and `(*kem).prov` is live.
    let algctx = unsafe { newctx(ossl_provider_ctx((*kem).prov)) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).op_encap_algctx = algctx };
    if algctx.is_null() {
        /* The provider key can stay in the cache. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_165) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, 0) };
    }

    /* The authenticating initialiser is selected by whether an `authkey` **was exported**, not by
     * whether one was passed: a method that publishes the authenticating initialiser and no plain
     * one is unreachable without an `authkey`, and one that publishes both is asked for the
     * authenticating form exactly when there is a key to authenticate with. */
    let ret = match operation {
        EVP_PKEY_OP_ENCAPSULATE => {
            // SAFETY: `kem` is live.
            let auth_init = unsafe { (*kem).auth_encapsulate_init };
            // SAFETY: `kem` is live.
            let plain_init = unsafe { (*kem).encapsulate_init };
            if !provauthkey.is_null() {
                match auth_init {
                    // SAFETY: the provider's own callback, with the authority's arguments.
                    Some(f) => unsafe { f(algctx, provkey, provauthkey, params) },
                    None => {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::KEM_177) };
                        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, -2) };
                    }
                }
            } else {
                match plain_init {
                    // SAFETY: as above.
                    Some(f) => unsafe { f(algctx, provkey, params) },
                    None => {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::KEM_177) };
                        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, -2) };
                    }
                }
            }
        }
        EVP_PKEY_OP_DECAPSULATE => {
            // SAFETY: `kem` is live.
            let auth_init = unsafe { (*kem).auth_decapsulate_init };
            // SAFETY: `kem` is live.
            let plain_init = unsafe { (*kem).decapsulate_init };
            if !provauthkey.is_null() {
                match auth_init {
                    // SAFETY: the provider's own callback, with the authority's arguments.
                    Some(f) => unsafe { f(algctx, provkey, provauthkey, params) },
                    None => {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::KEM_189) };
                        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, -2) };
                    }
                }
            } else {
                match plain_init {
                    // SAFETY: as above.
                    Some(f) => unsafe { f(algctx, provkey, params) },
                    None => {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::KEM_189) };
                        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                        return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, -2) };
                    }
                }
            }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::KEM_195) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { evp_kem_init_err(ctx, tmp_keymgmt, 0) };
        }
    };

    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };

    if ret > 0 {
        return 1;
    }
    // SAFETY: `ctx` is live and the second argument is a literal NULL.
    unsafe { evp_kem_init_err(ctx, ptr::null_mut(), ret) }
}

/// `int EVP_PKEY_auth_encapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpriv,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `authpriv` must be live (the authority refuses NULL before dereferencing it);
/// `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_auth_encapsulate_init(
    ctx: *mut EvpPkeyCtx,
    authpriv: *mut EvpPkey,
    params: *const OsslParam,
) -> c_int {
    if authpriv.is_null() {
        return 0;
    }
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, params, authpriv) }
}

/// `int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate_init(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, params, ptr::null_mut()) }
}

/// `int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
/// unsigned char *secret, size_t *secretlen)` — `crypto/evp/kem.c:226`.
///
/// Note where the refusals sit relative to each other: a NULL `ctx` answers **0 without raising**,
/// a wrong operation raises `EVP_R_OPERATION_NOT_INITIALIZED` and answers `-1`, and unbound algorithm
/// context raises `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` and answers `-2`. Three different
/// answers for three different mistakes, and none of them is the others'.
///
/// # Safety
/// `ctx` NULL or live; `out` NULL or `*outlen` writable; `secret` NULL or `*secretlen` writable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encapsulate(
    ctx: *mut EvpPkeyCtx,
    out: *mut u8,
    outlen: *mut usize,
    secret: *mut u8,
    secretlen: *mut usize,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } != EVP_PKEY_OP_ENCAPSULATE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_234) };
        return -1;
    }
    // SAFETY: `ctx` is live.
    let algctx = unsafe { (*ctx).op_encap_algctx };
    if algctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_239) };
        return -2;
    }
    if !out.is_null() && secret.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live, the operation is bound, and its KEM is live; the callback is present
    // because `evp_kem_init` refused a method without one.
    let kem = unsafe { (*ctx).op_encap_kem };
    // SAFETY: `kem` is live and its callback is the provider's own.
    match unsafe { (*kem).encapsulate } {
        // SAFETY: the provider's own callback, with the authority's arguments.
        Some(f) => unsafe { f(algctx, out, outlen, secret, secretlen) },
        None => 0,
    }
}

/// `int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decapsulate_init(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, params, ptr::null_mut()) }
}

/// `int EVP_PKEY_auth_decapsulate_init(EVP_PKEY_CTX *ctx, EVP_PKEY *authpub,
/// const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `authpub` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_auth_decapsulate_init(
    ctx: *mut EvpPkeyCtx,
    authpub: *mut EvpPkey,
    params: *const OsslParam,
) -> c_int {
    if authpub.is_null() {
        return 0;
    }
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, params, authpub) }
}

/// `int EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *secret, size_t *secretlen,
/// const unsigned char *in, size_t inlen)` — `crypto/evp/kem.c:263`.
///
/// The argument test is **one** condition over three clauses and it answers 0 without raising:
/// a NULL `ctx`, an absent or empty input, and a call with neither an output buffer nor a length.
/// It happens before the operation is looked at, so a NULL `ctx` answers 0 even though the same
/// function's other refusals answer -1 and -2.
///
/// # Safety
/// `ctx` NULL or live; `secret` NULL or `*secretlen` writable; `in` `inlen` readable.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decapsulate(
    ctx: *mut EvpPkeyCtx,
    secret: *mut u8,
    secretlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    if ctx.is_null() || input.is_null() || inlen == 0 {
        return 0;
    }
    if secret.is_null() && secretlen.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } != EVP_PKEY_OP_DECAPSULATE {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_273) };
        return -1;
    }
    // SAFETY: `ctx` is live.
    let algctx = unsafe { (*ctx).op_encap_algctx };
    if algctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::KEM_278) };
        return -2;
    }
    // SAFETY: `ctx` is live, the operation is bound, and its KEM is live.
    let kem = unsafe { (*ctx).op_encap_kem };
    // SAFETY: `kem` is live and its callback is the provider's own.
    match unsafe { (*kem).decapsulate } {
        // SAFETY: the provider's own callback, with the authority's arguments.
        Some(f) => unsafe { f(algctx, secret, secretlen, input, inlen) },
        None => 0,
    }
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    /// A hand-built method, so the accessors can be read without a provider.
    fn a_hand_built_kem() -> EvpKem {
        EvpKem {
            name_id: 11,
            type_name: c"court-kem".as_ptr().cast_mut(),
            description: c"a hand-built KEM".as_ptr(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            encapsulate_init: None,
            encapsulate: None,
            decapsulate_init: None,
            decapsulate: None,
            freectx: None,
            dupctx: None,
            get_ctx_params: None,
            gettable_ctx_params: None,
            set_ctx_params: None,
            settable_ctx_params: None,
            auth_encapsulate_init: None,
            auth_decapsulate_init: None,
        }
    }

    /// The field readers, and `names_do_all`'s **1** for a method with no provider.
    #[test]
    fn the_accessors_read_fields_and_the_walk_answers_one() {
        let kem = a_hand_built_kem();
        let p: *const EvpKem = ptr::addr_of!(kem);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(CStr::from_ptr(EVP_KEM_get0_name(p)), c"court-kem");
            assert_eq!(
                CStr::from_ptr(EVP_KEM_get0_description(p)),
                c"a hand-built KEM"
            );
            assert_eq!(evp_kem_get_number(p), 11);
            assert!(EVP_KEM_get0_provider(p).is_null());
            assert_eq!(EVP_KEM_names_do_all(p, None, ptr::null_mut()), 1);
        }
    }

    /// The two context-parameter accessors answer NULL for a NULL method and for one with no
    /// callback.
    #[test]
    fn the_context_parameter_accessors_answer_null() {
        let kem = a_hand_built_kem();
        let p: *const EvpKem = ptr::addr_of!(kem);
        // SAFETY: `p` is this frame's own live object; NULL is the other documented input.
        unsafe {
            assert!(EVP_KEM_gettable_ctx_params(p).is_null());
            assert!(EVP_KEM_settable_ctx_params(p).is_null());
            assert!(EVP_KEM_gettable_ctx_params(ptr::null()).is_null());
            assert!(EVP_KEM_settable_ctx_params(ptr::null()).is_null());
        }
    }

    /// The reference count is taken and given back, and the object survives the first release.
    #[test]
    fn the_reference_count_is_taken_and_given_back() {
        // SAFETY: a NULL provider is allowed by the constructor, which up-refs conditionally.
        let kem = unsafe { evp_kem_new(ptr::null_mut()) };
        assert!(!kem.is_null());
        // SAFETY: `kem` is this test's own object.
        unsafe {
            assert_eq!(EVP_KEM_up_ref(kem), 1);
            EVP_KEM_free(kem);
            assert_eq!((*kem).name_id, 0, "the object is still alive");
            EVP_KEM_free(kem);
        }
    }
}
