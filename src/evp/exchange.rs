//! Phase 7.4 — the `EVP_KEYEXCH` method object.
//!
//! `crypto/evp/exchange.c`'s **method half**. The file's other half — `EVP_PKEY_derive_init`,
//! `EVP_PKEY_derive_set_peer`, `EVP_PKEY_derive` and the `_ex` spellings — is `EVP_PKEY_CTX` work and
//! lands with 7.4c's context.
//!
//! ## The structural check collapses two dispatch ids into one flag, which is the odd one out
//!
//! ```text
//! fncnt += derive_found          newctx, init, freectx, and +1 for EITHER derive or derive_skey
//! fncnt         == 4
//! gparamfncnt   in {0, 2}        get_ctx_params + gettable_ctx_params
//! sparamfncnt   in {0, 2}        set_ctx_params + settable_ctx_params
//! ```
//!
//! This is the third distinct shape in the family, and the way it differs from its two siblings is the
//! reason it is transcribed rather than templated:
//!
//!   * `newctx`, `init` and `freectx` each add **1** to one counter, and `derive` and `derive_skey`
//!     each add **1 to a boolean** — so a method that publishes *both* of them has `fncnt == 4`, not
//!     5, and is accepted. A transcription that counted the two arms separately would require 5 and
//!     refuse every method that publishes both, which is the ordinary case for a provider that
//!     supports both an output buffer and an `EVP_SKEY`.
//!   * `fncnt` is therefore a **sum of a counter and a flag**, incremented in three different arms and
//!     then folded once at the end (`fncnt += derive_found;` *after* the walk). Moving that fold
//!     inside the loop would work; moving it into the `derive` arm only would not.
//!   * `set_peer` and `dupctx` are both **uncounted and optional**. `set_peer` is the one callback in
//!     the class whose absence is load-bearing for the *caller* rather than for the check:
//!     `EVP_PKEY_derive_set_peer` refuses with `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` when
//!     the method has none, which is a different answer from a peer that was rejected.
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
use crate::params::OsslParam;
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `OSSL_OP_KEYEXCH` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_KEYEXCH: c_int = 11;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/exchange.c".as_ptr();
/// `evp_keyexch_new`'s `OPENSSL_zalloc(sizeof(EVP_KEYEXCH))` (line 34).
const LINE_ZALLOC_KEYEXCH: c_int = 34;
/// `EVP_KEYEXCH_free`'s `OPENSSL_free(exchange->type_name)` (line 170).
const LINE_FREE_TYPE_NAME: c_int = 170;
/// `EVP_KEYEXCH_free`'s `OPENSSL_free(exchange)` (line 173).
const LINE_FREE_KEYEXCH: c_int = 173;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the eleven function-pointer types.
//
// `OSSL_FUNC_KEYEXCH_*`, dense from 1 to 11 — and note that the two `ctx_params` pairs are
// **set, settable, get, gettable** in id order (7, 8, 9, 10), which is the reverse of the order the
// `EVP_SIGNATURE` class uses. The struct below follows the ids, not the other file's order.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_KEYEXCH_NEWCTX`.
const OSSL_FUNC_KEYEXCH_NEWCTX: c_int = 1;
/// `OSSL_FUNC_KEYEXCH_INIT`.
const OSSL_FUNC_KEYEXCH_INIT: c_int = 2;
/// `OSSL_FUNC_KEYEXCH_DERIVE`.
const OSSL_FUNC_KEYEXCH_DERIVE: c_int = 3;
/// `OSSL_FUNC_KEYEXCH_SET_PEER`.
const OSSL_FUNC_KEYEXCH_SET_PEER: c_int = 4;
/// `OSSL_FUNC_KEYEXCH_FREECTX`.
const OSSL_FUNC_KEYEXCH_FREECTX: c_int = 5;
/// `OSSL_FUNC_KEYEXCH_DUPCTX`.
const OSSL_FUNC_KEYEXCH_DUPCTX: c_int = 6;
/// `OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS`.
const OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS: c_int = 7;
/// `OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS`.
const OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_KEYEXCH_DERIVE_SKEY`.
const OSSL_FUNC_KEYEXCH_DERIVE_SKEY: c_int = 11;

/// `OSSL_FUNC_keyexch_newctx_fn`.
pub(crate) type KeyexchNewctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_keyexch_init_fn`.
pub(crate) type KeyexchInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_keyexch_set_peer_fn`.
pub(crate) type KeyexchSetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `OSSL_FUNC_keyexch_derive_fn`.
pub(crate) type KeyexchDeriveFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize) -> c_int;
/// `OSSL_FUNC_keyexch_freectx_fn`.
pub(crate) type KeyexchFreectxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_keyexch_dupctx_fn`.
pub(crate) type KeyexchDupctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_keyexch_set_ctx_params_fn`.
pub(crate) type KeyexchSetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_keyexch_settable_ctx_params_fn`.
pub(crate) type KeyexchSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_keyexch_get_ctx_params_fn`.
pub(crate) type KeyexchGetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_keyexch_gettable_ctx_params_fn`.
pub(crate) type KeyexchGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_keyexch_derive_skey_fn` — the eleventh arm, and the one that shares a flag with
/// `derive` rather than taking a counter of its own.
pub(crate) type KeyexchDeriveSkeyFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    *mut c_void,
    usize,
    *const OsslParam,
) -> c_int;

/// `struct evp_keyexch_st` — `crypto/evp/evp_local.h`.
#[repr(C)]
pub struct EvpKeyExch {
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
    /// `OSSL_FUNC_keyexch_newctx_fn *newctx` — mandatory by count.
    pub(crate) newctx: Option<KeyexchNewctxFn>,
    /// `OSSL_FUNC_keyexch_init_fn *init` — mandatory by count.
    pub(crate) init: Option<KeyexchInitFn>,
    /// `OSSL_FUNC_keyexch_set_peer_fn *set_peer` — optional **and** uncounted.
    pub(crate) set_peer: Option<KeyexchSetPeerFn>,
    /// `OSSL_FUNC_keyexch_derive_fn *derive` — one of the two arms of `derive_found`.
    pub(crate) derive: Option<KeyexchDeriveFn>,
    /// `OSSL_FUNC_keyexch_freectx_fn *freectx` — mandatory by count.
    pub(crate) freectx: Option<KeyexchFreectxFn>,
    /// `OSSL_FUNC_keyexch_dupctx_fn *dupctx` — optional and uncounted.
    pub(crate) dupctx: Option<KeyexchDupctxFn>,
    /// `OSSL_FUNC_keyexch_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<KeyexchSetCtxParamsFn>,
    /// `OSSL_FUNC_keyexch_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<KeyexchSettableCtxParamsFn>,
    /// `OSSL_FUNC_keyexch_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<KeyexchGetCtxParamsFn>,
    /// `OSSL_FUNC_keyexch_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<KeyexchGettableCtxParamsFn>,
    /// `OSSL_FUNC_keyexch_derive_skey_fn *derive_skey` — the other arm of `derive_found`.
    pub(crate) derive_skey: Option<KeyexchDeriveSkeyFn>,
}

/// `static void evp_keyexch_free(void *data)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `data` must be NULL or a live `EvpKeyExch`.
unsafe extern "C" fn evp_keyexch_free(data: *mut c_void) {
    // SAFETY: `data` is NULL or live per the contract.
    unsafe { EVP_KEYEXCH_free(data.cast::<EvpKeyExch>()) }
}

/// `static int evp_keyexch_up_ref(void *data)`.
///
/// # Safety
/// `data` must be a live `EvpKeyExch`.
unsafe extern "C" fn evp_keyexch_up_ref(data: *mut c_void) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { EVP_KEYEXCH_up_ref(data.cast::<EvpKeyExch>()) }
}

/// `static EVP_KEYEXCH *evp_keyexch_new(OSSL_PROVIDER *prov)`.
///
/// The one difference from its three siblings: `prov` is assigned **after** the reference is taken
/// rather than before, so the failure path leaves `prov` NULL — which is invisible, because the
/// failure path frees the object.
///
/// # Safety
/// `prov` must be live.
unsafe fn evp_keyexch_new(prov: *mut OsslProvider) -> *mut EvpKeyExch {
    // SAFETY: this allocates a fresh object and reads nothing.
    let exchange = CRYPTO_zalloc(
        core::mem::size_of::<EvpKeyExch>(),
        FILE,
        LINE_ZALLOC_KEYEXCH,
    )
    .cast::<EvpKeyExch>();
    if exchange.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `exchange` is this call's own object and `prov` is live.
    unsafe {
        (*exchange).refcnt = AtomicI32::new(1);
        ossl_provider_up_ref(prov);
        (*exchange).prov = prov;
    }
    exchange
}

/// `static void *evp_keyexch_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)`.
///
/// # Safety
/// `algodef` must be live; `prov` must be live.
unsafe extern "C" fn evp_keyexch_from_algorithm(
    name_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: `prov` is live per the contract.
    let exchange = unsafe { evp_keyexch_new(prov) };
    if exchange.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_59) };
        return ptr::null_mut();
    }

    // SAFETY: `exchange` is live.
    unsafe { (*exchange).name_id = name_id };
    // SAFETY: `algodef` is live.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `exchange` is this call's own object.
        unsafe { EVP_KEYEXCH_free(exchange) };
        return ptr::null_mut();
    }
    // SAFETY: `exchange` is live and `type_name` is the string just allocated for it.
    unsafe { (*exchange).type_name = type_name };
    // SAFETY: both are live.
    unsafe { (*exchange).description = (*algodef).algorithm_description };

    let mut fncnt = 0;
    let mut sparamfncnt = 0;
    let mut gparamfncnt = 0;
    /* The **boolean** accumulator. Both `derive` and `derive_skey` set it, and it is folded into
     * `fncnt` once, after the walk -- so publishing both is one unit of the required four, not two. */
    let mut derive_found = 0;

    // SAFETY: `fns` is a terminated table per the contract.
    let mut entry = fns;
    // SAFETY: `fns` is a terminated table, so the walk leaves it at the terminator.
    unsafe {
        while (*entry).function_id != OSSL_DISPATCH_END {
            match (*entry).function_id {
                OSSL_FUNC_KEYEXCH_NEWCTX if (*exchange).newctx.is_none() => {
                    (*exchange).newctx = entry_function::<KeyexchNewctxFn>(entry);
                    fncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_INIT if (*exchange).init.is_none() => {
                    (*exchange).init = entry_function::<KeyexchInitFn>(entry);
                    fncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_SET_PEER if (*exchange).set_peer.is_none() => {
                    (*exchange).set_peer = entry_function::<KeyexchSetPeerFn>(entry);
                }
                OSSL_FUNC_KEYEXCH_DERIVE if (*exchange).derive.is_none() => {
                    (*exchange).derive = entry_function::<KeyexchDeriveFn>(entry);
                    derive_found = 1;
                }
                OSSL_FUNC_KEYEXCH_FREECTX if (*exchange).freectx.is_none() => {
                    (*exchange).freectx = entry_function::<KeyexchFreectxFn>(entry);
                    fncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_DUPCTX if (*exchange).dupctx.is_none() => {
                    (*exchange).dupctx = entry_function::<KeyexchDupctxFn>(entry);
                }
                OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS if (*exchange).set_ctx_params.is_none() => {
                    (*exchange).set_ctx_params = entry_function::<KeyexchSetCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS
                    if (*exchange).settable_ctx_params.is_none() =>
                {
                    (*exchange).settable_ctx_params =
                        entry_function::<KeyexchSettableCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS if (*exchange).get_ctx_params.is_none() => {
                    (*exchange).get_ctx_params = entry_function::<KeyexchGetCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS
                    if (*exchange).gettable_ctx_params.is_none() =>
                {
                    (*exchange).gettable_ctx_params =
                        entry_function::<KeyexchGettableCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_KEYEXCH_DERIVE_SKEY if (*exchange).derive_skey.is_none() => {
                    (*exchange).derive_skey = entry_function::<KeyexchDeriveSkeyFn>(entry);
                    derive_found = 1;
                }
                _ => {}
            }
            entry = entry.add(1);
        }
    }
    /* The fold, *after* the walk rather than inside it. See this module's documentation. */
    fncnt += derive_found;

    if fncnt != 4
        || (gparamfncnt != 0 && gparamfncnt != 2)
        || (sparamfncnt != 0 && sparamfncnt != 2)
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_150) };
        // SAFETY: `exchange` is this call's own object.
        unsafe { EVP_KEYEXCH_free(exchange) };
        return ptr::null_mut();
    }

    exchange.cast::<c_void>()
}

/// `void EVP_KEYEXCH_free(EVP_KEYEXCH *exchange)`.
///
/// # Safety
/// `exchange` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_free(exchange: *mut EvpKeyExch) {
    if exchange.is_null() {
        return;
    }
    // SAFETY: `exchange` is live per the contract.
    let last = unsafe { (*exchange).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: `exchange` is live and this was the last reference.
    let (type_name, prov) = unsafe { ((*exchange).type_name, (*exchange).prov) };
    // SAFETY: `type_name` was allocated for this object.
    unsafe { CRYPTO_free(type_name.cast(), FILE, LINE_FREE_TYPE_NAME) };
    // SAFETY: `prov` is live and holds the reference `evp_keyexch_new` took.
    unsafe { ossl_provider_free(prov) };
    // SAFETY: `exchange` is this object's own allocation.
    unsafe { CRYPTO_free(exchange.cast(), FILE, LINE_FREE_KEYEXCH) };
}

/// `int EVP_KEYEXCH_up_ref(EVP_KEYEXCH *exchange)`.
///
/// # Safety
/// `exchange` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_up_ref(exchange: *mut EvpKeyExch) -> c_int {
    // SAFETY: `exchange` is live per the contract.
    unsafe { (*exchange).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `OSSL_PROVIDER *EVP_KEYEXCH_get0_provider(const EVP_KEYEXCH *exchange)`.
///
/// # Safety
/// `exchange` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_get0_provider(
    exchange: *const EvpKeyExch,
) -> *mut OsslProvider {
    // SAFETY: `exchange` is live per the contract.
    unsafe { (*exchange).prov }
}

/// `EVP_KEYEXCH *EVP_KEYEXCH_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpKeyExch {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_KEYEXCH,
            algorithm,
            properties,
            evp_keyexch_from_algorithm as MethodFromAlgorithmFn,
            evp_keyexch_up_ref as MethodUpRefFn,
            evp_keyexch_free as MethodFreeFn,
        )
    }
    .cast::<EvpKeyExch>()
}

/// `EVP_KEYEXCH *evp_keyexch_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `prov` must be live; `algorithm` and `properties` NULL or NUL-terminated.
#[allow(dead_code)] // first live caller is `EVP_PKEY_derive_init`, which lands with 7.4c's context
pub(crate) unsafe fn evp_keyexch_fetch_from_prov(
    prov: *mut OsslProvider,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpKeyExch {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_KEYEXCH,
            algorithm,
            properties,
            evp_keyexch_from_algorithm as MethodFromAlgorithmFn,
            evp_keyexch_up_ref as MethodUpRefFn,
            evp_keyexch_free as MethodFreeFn,
        )
    }
    .cast::<EvpKeyExch>()
}

/// `int evp_keyexch_get_number(const EVP_KEYEXCH *keyexch)`.
///
/// # Safety
/// `keyexch` must be live.
#[allow(dead_code)] // read by the `EVP_PKEY_CTX` construction path in 7.4c
pub(crate) unsafe fn evp_keyexch_get_number(keyexch: *const EvpKeyExch) -> c_int {
    // SAFETY: `keyexch` is live per the contract.
    unsafe { (*keyexch).name_id }
}

/// `const char *EVP_KEYEXCH_get0_name(const EVP_KEYEXCH *keyexch)`.
///
/// # Safety
/// `keyexch` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_get0_name(keyexch: *const EvpKeyExch) -> *const c_char {
    // SAFETY: `keyexch` is live per the contract.
    unsafe { (*keyexch).type_name }
}

/// `const char *EVP_KEYEXCH_get0_description(const EVP_KEYEXCH *keyexch)`.
///
/// # Safety
/// `keyexch` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_get0_description(keyexch: *const EvpKeyExch) -> *const c_char {
    // SAFETY: `keyexch` is live per the contract.
    unsafe { (*keyexch).description }
}

/// `int EVP_KEYEXCH_is_a(const EVP_KEYEXCH *keyexch, const char *name)`.
///
/// # Safety
/// `keyexch` must be live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_is_a(
    keyexch: *const EvpKeyExch,
    name: *const c_char,
) -> c_int {
    // SAFETY: `keyexch` is live per the contract.
    let (prov, name_id) = unsafe { ((*keyexch).prov, (*keyexch).name_id) };
    // SAFETY: `prov` is live and `name` is NUL-terminated.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `void EVP_KEYEXCH_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_KEYEXCH *, void *),
/// void *arg)`.
///
/// A **NULL visitor is refused**; the boundary is `EVP_MD_do_all_provided`'s
/// (`D-MD-DOALL-NULL-1`).
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpKeyExch, *mut c_void)>,
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
            OSSL_OP_KEYEXCH,
            core::mem::transmute::<
                unsafe extern "C" fn(*mut EvpKeyExch, *mut c_void),
                GenericDoAllFn,
            >(visitor),
            arg,
            evp_keyexch_from_algorithm as MethodFromAlgorithmFn,
            evp_keyexch_up_ref as MethodUpRefFn,
            evp_keyexch_free as MethodFreeFn,
        )
    };
}

/// `int EVP_KEYEXCH_names_do_all(const EVP_KEYEXCH *keyexch,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// # Safety
/// `keyexch` must be live; `fn_` a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_names_do_all(
    keyexch: *const EvpKeyExch,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `keyexch` is live per the contract.
    let (prov, name_id) = unsafe { ((*keyexch).prov, (*keyexch).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor's contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *EVP_KEYEXCH_gettable_ctx_params(const EVP_KEYEXCH *keyexch)`.
///
/// Note the **order of the two arguments** the callback receives here: the authority's
/// `EVP_KEYEXCH_gettable_ctx_params` passes `(NULL, provctx)` exactly as its three siblings do, but
/// the struct's field order in `evp_local.h` lists the set pair before the get pair, so a
/// transcription that walked the struct would be tempted to swap them.
///
/// # Safety
/// `keyexch` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_gettable_ctx_params(
    keyexch: *const EvpKeyExch,
) -> *const OsslParam {
    if keyexch.is_null() {
        return ptr::null();
    }
    // SAFETY: `keyexch` is live per the contract.
    let (f, prov) = unsafe { ((*keyexch).gettable_ctx_params, (*keyexch).prov) };
    let Some(gettable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `gettable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { gettable(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_KEYEXCH_settable_ctx_params(const EVP_KEYEXCH *keyexch)`.
///
/// # Safety
/// `keyexch` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_KEYEXCH_settable_ctx_params(
    keyexch: *const EvpKeyExch,
) -> *const OsslParam {
    if keyexch.is_null() {
        return ptr::null();
    }
    // SAFETY: `keyexch` is live per the contract.
    let (f, prov) = unsafe { ((*keyexch).settable_ctx_params, (*keyexch).prov) };
    let Some(settable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `settable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { settable(ptr::null_mut(), provctx) }
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    /// A hand-built method, so the accessors can be read without a provider.
    fn a_hand_built_keyexch() -> EvpKeyExch {
        EvpKeyExch {
            name_id: 5,
            type_name: c"court-keyexch".as_ptr().cast_mut(),
            description: c"a hand-built KEYEXCH".as_ptr(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            init: None,
            set_peer: None,
            derive: None,
            freectx: None,
            dupctx: None,
            set_ctx_params: None,
            settable_ctx_params: None,
            get_ctx_params: None,
            gettable_ctx_params: None,
            derive_skey: None,
        }
    }

    /// The field readers, and `names_do_all`'s **1** for a method with no provider.
    #[test]
    fn the_accessors_read_fields_and_the_walk_answers_one() {
        let keyexch = a_hand_built_keyexch();
        let p: *const EvpKeyExch = ptr::addr_of!(keyexch);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(CStr::from_ptr(EVP_KEYEXCH_get0_name(p)), c"court-keyexch");
            assert_eq!(
                CStr::from_ptr(EVP_KEYEXCH_get0_description(p)),
                c"a hand-built KEYEXCH"
            );
            assert_eq!(evp_keyexch_get_number(p), 5);
            assert!(EVP_KEYEXCH_get0_provider(p).is_null());
            assert_eq!(EVP_KEYEXCH_names_do_all(p, None, ptr::null_mut()), 1);
        }
    }

    /// The two context-parameter accessors answer NULL for a NULL method and for one with no
    /// callback.
    #[test]
    fn the_context_parameter_accessors_answer_null() {
        let keyexch = a_hand_built_keyexch();
        let p: *const EvpKeyExch = ptr::addr_of!(keyexch);
        // SAFETY: `p` is this frame's own live object; NULL is the other documented input.
        unsafe {
            assert!(EVP_KEYEXCH_gettable_ctx_params(p).is_null());
            assert!(EVP_KEYEXCH_settable_ctx_params(p).is_null());
            assert!(EVP_KEYEXCH_gettable_ctx_params(ptr::null()).is_null());
            assert!(EVP_KEYEXCH_settable_ctx_params(ptr::null()).is_null());
        }
    }

    /// The reference count is taken and given back, and the object survives the first release.
    #[test]
    fn the_reference_count_is_taken_and_given_back() {
        // SAFETY: a NULL provider is allowed by the constructor, which up-refs conditionally.
        let keyexch = unsafe { evp_keyexch_new(ptr::null_mut()) };
        assert!(!keyexch.is_null());
        // SAFETY: `keyexch` is this test's own object.
        unsafe {
            assert_eq!(EVP_KEYEXCH_up_ref(keyexch), 1);
            EVP_KEYEXCH_free(keyexch);
            assert_eq!((*keyexch).name_id, 0, "the object is still alive");
            EVP_KEYEXCH_free(keyexch);
        }
    }
}
