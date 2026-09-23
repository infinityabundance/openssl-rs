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
use crate::evp::keymgmt::{
    evp_keymgmt_fetch_from_prov, evp_keymgmt_newdata, EVP_KEYMGMT_free, EVP_KEYMGMT_get0_name,
    EVP_KEYMGMT_get0_provider, EvpKeyMgmt,
};
use crate::evp::keymgmt_lib::evp_keymgmt_util_query_operation_name;
use crate::evp::pkey::{
    evp_pkey_export_to_provider, EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_type_by_keymgmt,
    EVP_PKEY_up_ref, EvpPkey,
};
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_free_old_ops, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EvpPkeyCtx,
    EVP_PKEY_OP_DERIVE, EVP_PKEY_OP_UNDEFINED,
};
use crate::evp::pmeth_check::EVP_PKEY_public_check;
use crate::evp::skeymgmt::{
    evp_skey_alloc, evp_skeymgmt_fetch_from_prov, EVP_SKEYMGMT_fetch, EVP_SKEYMGMT_free,
    EVP_SKEY_free, EVP_SKEY_import_SKEYMGMT, EvpSkey, EvpSkeyMgmt, SkeymgmtImportFn,
    OSSL_SKEYMGMT_SELECT_SECRET_KEY, OSSL_SKEY_PARAM_RAW_BYTES,
};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam};
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::err::{
    err_sites, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_zalloc};

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
/// `EVP_PKEY_derive_SKEY`'s `key = OPENSSL_zalloc(keylen)` (line 605).
const LINE_ZALLOC_DERIVE_SKEY: c_int = 605;
/// `EVP_PKEY_derive_SKEY`'s `OPENSSL_free(key)` when the provider's derive fails (line 613).
const LINE_FREE_DERIVE_SKEY_ON_DERIVE: c_int = 613;
/// `EVP_PKEY_derive_SKEY`'s `OPENSSL_free(key)` when the provider derived a different length
/// (line 618) — a **different site** from the one above, and the error raised after it says so.
const LINE_FREE_DERIVE_SKEY_ON_LENGTH: c_int = 618;
/// `EVP_PKEY_derive_SKEY`'s `OPENSSL_clear_free(key, keylen)` (line 627): the secret's only copy.
const LINE_CLEAR_FREE_DERIVE_SKEY: c_int = 627;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the eleven function-pointer types.
//
// `OSSL_FUNC_KEYEXCH_*`, dense from 1 to 11 — and note that the two `ctx_params` pairs are
// **set, settable, get, gettable** in id order (7, 8, 9, 10), which is the reverse of the order the
// `EVP_SIGNATURE` class uses. The struct below follows the ids, not the other file's order.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_KEYEXCH_NEWCTX`.
pub(crate) const OSSL_FUNC_KEYEXCH_NEWCTX: c_int = 1;
/// `OSSL_FUNC_KEYEXCH_INIT`.
pub(crate) const OSSL_FUNC_KEYEXCH_INIT: c_int = 2;
/// `OSSL_FUNC_KEYEXCH_DERIVE`.
pub(crate) const OSSL_FUNC_KEYEXCH_DERIVE: c_int = 3;
/// `OSSL_FUNC_KEYEXCH_SET_PEER`.
pub(crate) const OSSL_FUNC_KEYEXCH_SET_PEER: c_int = 4;
/// `OSSL_FUNC_KEYEXCH_FREECTX`.
pub(crate) const OSSL_FUNC_KEYEXCH_FREECTX: c_int = 5;
/// `OSSL_FUNC_KEYEXCH_DUPCTX`.
pub(crate) const OSSL_FUNC_KEYEXCH_DUPCTX: c_int = 6;
/// `OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS: c_int = 7;
/// `OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_KEYEXCH_DERIVE_SKEY`.
pub(crate) const OSSL_FUNC_KEYEXCH_DERIVE_SKEY: c_int = 11;

/// `OSSL_FUNC_keyexch_newctx_fn`.
pub(crate) type KeyexchNewctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_keyexch_init_fn`.
pub(crate) type KeyexchInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_keyexch_set_peer_fn`.
pub(crate) type KeyexchSetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `OSSL_FUNC_keyexch_derive_fn` — **four** arguments, the last being the caller's buffer length,
/// and not three. The header is
/// `OSSL_CORE_MAKE_FUNC(int, keyexch_derive, (void *ctx, unsigned char *secret, size_t *secretlen,
/// size_t outlen))`, and `EVP_PKEY_derive` forwards `key != NULL ? *pkeylen : 0` into it — so a
/// three-argument transcription would leave the provider reading whatever sat in that register.
/// No exported signature can see this: it is a field of `EvpKeyExch`, which is why the prototype
/// court did not catch it and why `docs/DECISIONS.md` D170 records the whole class.
pub(crate) type KeyexchDeriveFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
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
///
/// It returns **`void *`**, not `int`: the header is `OSSL_CORE_MAKE_FUNC(void *,
/// keyexch_derive_skey, (void *ctx, const char *key_type, void *provctx,
/// OSSL_FUNC_skeymgmt_import_fn *import, size_t keylen, const OSSL_PARAM params[]))`. The return
/// value is the key data the destination method builds, which `EVP_PKEY_derive_SKEY` stores in the
/// new `EVP_SKEY` — so an `int` return type would truncate a pointer. The `KdfDeriveSkeyFn` beside
/// this class had it right; this one did not (`docs/DECISIONS.md` D170).
///
/// The fourth parameter is `OSSL_FUNC_skeymgmt_import_fn *import`, and it is typed here as the
/// function pointer it is rather than as `*mut c_void`. D170 corrected this type's arity and its
/// return type and left that parameter opaque; the dispatch plane reported the remainder as a
/// mismatch on its first run (`docs/DECISIONS.md` D180).
pub(crate) type KeyexchDeriveSkeyFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut c_void,
    Option<SkeymgmtImportFn>,
    usize,
    *const OsslParam,
) -> *mut c_void;

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

// ---------------------------------------------------------------------------------------------
// The operation half — `EVP_PKEY_derive_init_ex` and the five exports over it.
// ---------------------------------------------------------------------------------------------

/// The authority's `err:` label — `crypto/evp/exchange.c:362`.
///
/// **Not guarded by `ret`**, unlike the asymmetric cipher's and the KEM's: every arrival tears the
/// operation down and answers 0, taking no argument from the caller.
///
/// # Safety
/// `ctx` must be live; `tmp_keymgmt` NULL or live.
unsafe fn evp_pkey_derive_init_err(ctx: *mut EvpPkeyCtx, tmp_keymgmt: *mut EvpKeyMgmt) -> c_int {
    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = EVP_PKEY_OP_UNDEFINED };
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    0
}

/// The authority's `legacy:` label — `crypto/evp/exchange.c:368`.
///
/// `tmp_keymgmt` is **not** freed on the refusal path, and that is the authority's shape rather than
/// an omission here: the label's only `EVP_KEYMGMT_free(tmp_keymgmt)` sits after the `pmeth` test,
/// which this crate answers with a refusal because `pmeth` is Phase 8's. The reference therefore
/// leaks on this path in the authority and leaks here. It is reproduced rather than repaired
/// because nothing observable distinguishes the two, and a silent improvement is still a silent
/// change (`docs/DECISIONS.md` D170).
///
/// # Safety
/// Nothing — which is why this is a **safe** function: it takes no pointer and touches nothing but
/// the error queue, so its callers need no `unsafe` block of their own (`docs/DECISIONS.md` D113).
fn evp_pkey_derive_init_legacy() -> c_int {
    ERR_pop_to_mark();
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::EXCHANGE_379) };
    -2
}

/// `static int evp_pkey_derive_init(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])` — the body behind
/// `EVP_PKEY_derive_init_ex`, `crypto/evp/exchange.c:214`.
///
/// Like the asymmetric cipher's and unlike the KEM's: there is a mark, and there is a `legacy:`
/// label. Two things are this file's own:
///
///   * **a NULL `pkey` is not a refusal.** The authority *builds* a blank key — `EVP_PKEY_new`,
///     typed by the context's own method, with key data allocated and empty — because the legacy KDFs
///     select a key type with no key. That is what lets `EVP_PKEY_derive` be reached from a context
///     constructed out of a KDF name;
///   * `exchange->init`'s result is **coerced to 0 or 1** (`return ret ? 1 : 0`), so a provider that
///     answers 2 is reported as success and not as 2.
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a terminated array.
unsafe fn evp_pkey_derive_init(ctx: *mut EvpPkeyCtx, params: *const OsslParam) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_225) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = EVP_PKEY_OP_DERIVE };

    ERR_set_mark();

    // SAFETY: `ctx` is live.
    if unsafe { &*ctx }.is_legacy() {
        return evp_pkey_derive_init_legacy();
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).pkey }.is_null() {
        // SAFETY: `ctx` is live.
        let ctx_keymgmt = unsafe { (*ctx).keymgmt };
        // SAFETY: the constructor takes no arguments and returns this call's own object.
        let pkey = unsafe { EVP_PKEY_new() };
        /* The authority's three-way short circuit: a NULL allocation skips both of the later calls
         * rather than guarding them, and a failed type-set leaves the key data NULL. */
        let mut ok = false;
        if !pkey.is_null() {
            // SAFETY: `pkey` is live and `ctx_keymgmt` is live.
            if unsafe { EVP_PKEY_set_type_by_keymgmt(pkey, ctx_keymgmt) } != 0 {
                // SAFETY: `ctx_keymgmt` is live.
                let data = unsafe { evp_keymgmt_newdata(ctx_keymgmt) };
                // SAFETY: `pkey` is this call's own object.
                unsafe { (*pkey).keydata = data };
                ok = !data.is_null();
            }
        }
        if !ok {
            ERR_clear_last_mark();
            // SAFETY: `pkey` is NULL or this call's own object.
            unsafe { EVP_PKEY_free(pkey) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EXCHANGE_249) };
            // SAFETY: `ctx` is live and the second argument is a literal NULL.
            return unsafe { evp_pkey_derive_init_err(ctx, ptr::null_mut()) };
        }
        /* The context takes the reference the constructor returned; there is no `up_ref`. */
        // SAFETY: `ctx` is live and `pkey` is this call's own object.
        unsafe { (*ctx).pkey = pkey };
    }

    /* `ossl_assert` under `NDEBUG` is `(x) != 0`, so this is a live refusal (D167). */
    // SAFETY: `ctx` is live and its `pkey` is non-NULL.
    let pkey_keymgmt = unsafe { (*(*ctx).pkey).keymgmt };
    // SAFETY: `ctx` is live.
    if !(pkey_keymgmt.is_null() || pkey_keymgmt == unsafe { (*ctx).keymgmt }) {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_261) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { evp_pkey_derive_init_err(ctx, ptr::null_mut()) };
    }

    // SAFETY: `ctx` is live.
    let ctx_keymgmt = unsafe { (*ctx).keymgmt };
    // SAFETY: `ctx_keymgmt` is live.
    let supported_exch =
        unsafe { evp_keymgmt_util_query_operation_name(ctx_keymgmt, OSSL_OP_KEYEXCH) };
    if supported_exch.is_null() {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_268) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { evp_pkey_derive_init_err(ctx, ptr::null_mut()) };
    }

    let mut exchange: *mut EvpKeyExch = ptr::null_mut();
    let mut tmp_keymgmt: *mut EvpKeyMgmt = ptr::null_mut();
    let mut tmp_prov: *const OsslProvider = ptr::null();
    let mut provkey: *mut c_void = ptr::null_mut();

    let mut iter: c_int = 1;
    while iter < 3 && provkey.is_null() {
        // SAFETY: `exchange` is NULL or live.
        unsafe { EVP_KEYEXCH_free(exchange) };
        // SAFETY: `tmp_keymgmt` is NULL or live.
        unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
        tmp_keymgmt = ptr::null_mut();

        if iter == 1 {
            // SAFETY: `ctx` is live.
            let (libctx, propquery) = unsafe { ((*ctx).libctx, (*ctx).propquery) };
            // SAFETY: `libctx` is live and `supported_exch` is NUL-terminated.
            exchange = unsafe { EVP_KEYEXCH_fetch(libctx, supported_exch, propquery) };
            if !exchange.is_null() {
                // SAFETY: `exchange` is live.
                tmp_prov = unsafe { EVP_KEYEXCH_get0_provider(exchange) };
            }
        } else {
            // SAFETY: `ctx_keymgmt` is live.
            tmp_prov = unsafe { EVP_KEYMGMT_get0_provider(ctx_keymgmt) };
            // SAFETY: `ctx` is live.
            let propquery = unsafe { (*ctx).propquery };
            // SAFETY: `tmp_prov` is live and `supported_exch` is NUL-terminated.
            exchange = unsafe {
                evp_keyexch_fetch_from_prov(tmp_prov.cast_mut(), supported_exch, propquery)
            };
            if exchange.is_null() {
                return evp_pkey_derive_init_legacy();
            }
        }

        if !exchange.is_null() {
            // SAFETY: `ctx_keymgmt` is live and its name is NUL-terminated; `ctx` is live.
            let (name, propquery) =
                unsafe { (EVP_KEYMGMT_get0_name(ctx_keymgmt), (*ctx).propquery) };
            // SAFETY: `tmp_prov` is live and `name` is NUL-terminated.
            let tmp_keymgmt_tofree =
                unsafe { evp_keymgmt_fetch_from_prov(tmp_prov.cast_mut(), name, propquery) };
            tmp_keymgmt = tmp_keymgmt_tofree;
            if !tmp_keymgmt.is_null() {
                // SAFETY: `ctx` is live.
                let (pkey, libctx) = unsafe { ((*ctx).pkey, (*ctx).libctx) };
                // SAFETY: `pkey` is live and `tmp_keymgmt`'s address is valid for the call.
                provkey = unsafe {
                    evp_pkey_export_to_provider(
                        pkey,
                        libctx,
                        ptr::addr_of_mut!(tmp_keymgmt),
                        propquery,
                    )
                };
            }
            if tmp_keymgmt.is_null() {
                // SAFETY: `tmp_keymgmt_tofree` is NULL or live and the caller dropped it.
                unsafe { EVP_KEYMGMT_free(tmp_keymgmt_tofree) };
            }
        }
        iter += 1;
    }

    if provkey.is_null() {
        // SAFETY: `exchange` is NULL or live.
        unsafe { EVP_KEYEXCH_free(exchange) };
        return evp_pkey_derive_init_legacy();
    }

    ERR_pop_to_mark();

    /* No more legacy from here down to `legacy:`. */

    // SAFETY: `ctx` is live and `exchange` is live.
    unsafe { (*ctx).op_kex_exchange = exchange };
    /* `newctx` is mandatory: a provider that publishes no `OSSL_FUNC_KEYEXCH_NEWCTX` is refused by
     * the walk, so the `else` is unreachable and gives the authority's INITIALIZATION_ERROR. */
    // SAFETY: `exchange` is live.
    let Some(newctx) = (unsafe { (*exchange).newctx }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_355) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_pkey_derive_init_err(ctx, tmp_keymgmt) };
    };
    // SAFETY: `newctx` is the provider's own callback and `(*exchange).prov` is live.
    let algctx = unsafe { newctx(ossl_provider_ctx((*exchange).prov)) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).op_kex_algctx = algctx };
    if algctx.is_null() {
        /* The provider key can stay in the cache. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_355) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_pkey_derive_init_err(ctx, tmp_keymgmt) };
    }

    /* `init` is mandatory by the walk's count, so its absence is unreachable; it answers as the
     * NULL algorithm context does. */
    // SAFETY: `exchange` is live.
    let Some(init) = (unsafe { (*exchange).init }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_355) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { evp_pkey_derive_init_err(ctx, tmp_keymgmt) };
    };
    // SAFETY: `init` is the provider's own callback, `algctx` is its context and `provkey` is the
    // exported key.
    let ret = unsafe { init(algctx, provkey, params) };

    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    /* The coercion is the authority's: a success of 2 is reported as 1. */
    if ret != 0 {
        1
    } else {
        0
    }
}

/// `int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_derive_init(ctx, ptr::null()) }
}

/// `int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_derive_init(ctx, params) }
}

/// `int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *ctx, EVP_PKEY *peer, int validate_peer)` —
/// `crypto/evp/exchange.c:393`.
///
/// Three answers and three distinct reasons: `-1` for a NULL context **or** for a peer that failed
/// its own validation, `-2` for a method that publishes no `set_peer`, and `1` on success after
/// taking a reference and releasing the previous peer.
///
/// `validate_peer` is not a flag on the peer: it builds a **second context** over the peer and calls
/// `EVP_PKEY_public_check` on it, which is the dependency `docs/DECISIONS.md` D169 records — the
/// reason `pmeth_check.c` landed with this subphase rather than the next.
///
/// # Safety
/// `ctx` NULL or live; `peer` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_set_peer_ex(
    ctx: *mut EvpPkeyCtx,
    peer: *mut EvpPkey,
    validate_peer: c_int,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_402) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    let (is_derive_op, algctx) = unsafe { ((*ctx).is_derive_op(), (*ctx).op_kex_algctx) };
    if !is_derive_op || algctx.is_null() {
        return evp_pkey_derive_set_peer_legacy();
    }

    // SAFETY: `ctx` is live and the operation is bound, so the method is live.
    let exchange = unsafe { (*ctx).op_kex_exchange };
    // SAFETY: `exchange` is live.
    if unsafe { (*exchange).set_peer }.is_none() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_410) };
        return -2;
    }

    if validate_peer != 0 {
        // SAFETY: `ctx` is live.
        let (libctx, propquery) = unsafe { ((*ctx).libctx, (*ctx).propquery) };
        // SAFETY: `peer` is NULL or live per the contract.
        let check_ctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, peer, propquery) };
        if check_ctx.is_null() {
            return -1;
        }
        // SAFETY: `check_ctx` is this call's own context.
        let check = unsafe { EVP_PKEY_public_check(check_ctx) };
        // SAFETY: `check_ctx` is this call's own context and is not used again.
        unsafe { EVP_PKEY_CTX_free(check_ctx) };
        if check <= 0 {
            return -1;
        }
    }

    // SAFETY: `ctx` is live and `exchange` is live.
    let (libctx, propquery, ctx_keymgmt) =
        unsafe { ((*ctx).libctx, (*ctx).propquery, (*ctx).keymgmt) };
    // SAFETY: `exchange` is live.
    let exch_prov = unsafe { EVP_KEYEXCH_get0_provider(exchange) };
    // SAFETY: `ctx_keymgmt` is live and its name is NUL-terminated.
    let name = unsafe { EVP_KEYMGMT_get0_name(ctx_keymgmt) };
    // SAFETY: `exch_prov` is live and `name` is NUL-terminated.
    let tmp_keymgmt_tofree = unsafe { evp_keymgmt_fetch_from_prov(exch_prov, name, propquery) };
    let mut tmp_keymgmt = tmp_keymgmt_tofree;
    let mut provkey: *mut c_void = ptr::null_mut();
    if !tmp_keymgmt.is_null() {
        // SAFETY: `peer` is NULL or live and `tmp_keymgmt`'s address is valid for the call.
        provkey = unsafe {
            evp_pkey_export_to_provider(peer, libctx, ptr::addr_of_mut!(tmp_keymgmt), propquery)
        };
    }
    /* Freed unconditionally here, unlike in `evp_pkey_derive_init`'s loop: the authority writes one
     * `EVP_KEYMGMT_free` with no test around it. */
    // SAFETY: `tmp_keymgmt_tofree` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt_tofree) };

    if provkey.is_null() {
        return evp_pkey_derive_set_peer_legacy();
    }

    // SAFETY: `exchange` is live and its `set_peer` was tested non-absent above.
    let Some(set_peer) = (unsafe { (*exchange).set_peer }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_410) };
        return -2;
    };
    // SAFETY: `set_peer` is the provider's own callback, `algctx` is its context and `provkey` is
    // the exported peer.
    let ret = unsafe { set_peer(algctx, provkey) };
    if ret <= 0 {
        return ret;
    }

    /* `goto common`. */
    // SAFETY: `peer` is live per the contract.
    if unsafe { EVP_PKEY_up_ref(peer) } == 0 {
        return -1;
    }
    // SAFETY: `ctx` is live.
    let previous = unsafe { (*ctx).peerkey };
    // SAFETY: `previous` is NULL or live and is the context's own reference.
    unsafe { EVP_PKEY_free(previous) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).peerkey = peer };
    1
}

/// The authority's `legacy:` label — `crypto/evp/exchange.c:455`.
///
/// `ctx->pmeth` is Phase 8's, so the first clause of the authority's test is satisfied on arrival and
/// everything after it — the three operation-bit comparisons, `EVP_PKEY_missing_parameters`,
/// `EVP_PKEY_parameters_eq` and the second `ctrl` — is unreachable here. None of those names is
/// referenced, which is why this label needs no other unit's exports.
///
/// # Safety
/// Nothing — a **safe** function for the reason given on `evp_pkey_derive_init_legacy`.
fn evp_pkey_derive_set_peer_legacy() -> c_int {
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::EXCHANGE_464) };
    -2
}

/// `int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)`.
///
/// # Safety
/// `ctx` NULL or live; `peer` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_set_peer(
    ctx: *mut EvpPkeyCtx,
    peer: *mut EvpPkey,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { EVP_PKEY_derive_set_peer_ex(ctx, peer, 1) }
}

/// `int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen)` —
/// `crypto/evp/exchange.c:524`.
///
/// Two NULL checks with the **same** reason and the same `-1`, then an operation-bit test that is a
/// third. The buffer length is forwarded as the provider's fourth argument — `key != NULL ?
/// *pkeylen : 0` — which is the parameter the crate's `KeyexchDeriveFn` was missing (D170).
///
/// # Safety
/// `ctx` NULL or live; `key` NULL or `*pkeylen` writable; `pkeylen` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive(
    ctx: *mut EvpPkeyCtx,
    key: *mut u8,
    pkeylen: *mut usize,
) -> c_int {
    if ctx.is_null() || pkeylen.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_529) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    let (is_derive_op, algctx) = unsafe { ((*ctx).is_derive_op(), (*ctx).op_kex_algctx) };
    if !is_derive_op {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_534) };
        return -1;
    }
    if algctx.is_null() {
        // The authority's `goto legacy`, which is the refusal below in this crate.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_547) };
        return -2;
    }

    // SAFETY: `ctx` is live and the operation is bound, so the method is live.
    let exchange = unsafe { (*ctx).op_kex_exchange };
    /* `derive` is one of the walk's two required arms, so its absence is unreachable; it answers as
     * the NULL algorithm context does. */
    // SAFETY: `exchange` is live.
    let Some(derive) = (unsafe { (*exchange).derive }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_547) };
        return -2;
    };
    let mut outlen: usize = 0;
    if !key.is_null() {
        // SAFETY: `key` is non-NULL, so `pkeylen` is the caller's valid buffer length per this
        // function's contract.
        outlen = unsafe { *pkeylen };
    }
    // SAFETY: `derive` is the provider's own callback, `algctx` is its context, and the remaining
    // three arguments are the caller's buffers and the length (or 0).
    unsafe { derive(algctx, key, pkeylen, outlen) }
}

/// `EVP_SKEY *EVP_PKEY_derive_SKEY(EVP_PKEY_CTX *ctx, EVP_SKEYMGMT *mgmt, const char *key_type,
/// const char *propquery, size_t keylen, const OSSL_PARAM params[])` —
/// `crypto/evp/exchange.c:554`.
///
/// The same three satisfactions as `EVP_KDF_derive_SKEY` (`src/evp/kdf.rs`): the caller supplied the
/// method and this function does not own it; the context's own provider can produce it, with the
/// libctx as a fallback; or the destination is a different provider or has no `derive_skey`, and
/// then the key is derived into a buffer and imported — which is the raw path, and the reason the
/// buffer is **cleared** before it is released.
///
/// One difference from the KDF's version is worth naming: the fallback fetch passes `ctx->libctx`,
/// not `ossl_provider_libctx(prov)`. The two agree whenever the context was built with the
/// provider's own libctx, and the authority does not rely on that — it uses the context's.
///
/// # Safety
/// `ctx` NULL or live; `mgmt` NULL or live; `key_type` and `propquery` NULL or NUL-terminated;
/// `params` NULL or terminated.
// mirrors the authority's signature exactly
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_derive_SKEY(
    ctx: *mut EvpPkeyCtx,
    mgmt: *mut EvpSkeyMgmt,
    key_type: *const c_char,
    propquery: *const c_char,
    keylen: usize,
    params: *const OsslParam,
) -> *mut EvpSkey {
    if ctx.is_null() || key_type.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_562) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live.
    let (is_derive_op, algctx) = unsafe { ((*ctx).is_derive_op(), (*ctx).op_kex_algctx) };
    if !is_derive_op {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_567) };
        return ptr::null_mut();
    }
    if algctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::EXCHANGE_572) };
        return ptr::null_mut();
    }

    // SAFETY: `ctx` is live and the operation is bound, so the method is live.
    let exchange = unsafe { (*ctx).op_kex_exchange };
    // SAFETY: `exchange` is live.
    let exch_prov = unsafe { (*exchange).prov };

    let skeymgmt: *mut EvpSkeyMgmt = if !mgmt.is_null() {
        mgmt
    } else {
        // SAFETY: `exch_prov` is live and the two strings are NULL or NUL-terminated.
        let mut fetched = unsafe { evp_skeymgmt_fetch_from_prov(exch_prov, key_type, propquery) };
        if fetched.is_null() {
            /* The operation's provider does not publish it; the context's libctx may still have one. */
            // SAFETY: `ctx` is live.
            let libctx = unsafe { (*ctx).libctx };
            // SAFETY: `libctx` is NULL or live and the two strings are NULL or NUL-terminated.
            fetched = unsafe { EVP_SKEYMGMT_fetch(libctx, key_type, propquery) };
        }
        if fetched.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EXCHANGE_589) };
            return ptr::null_mut();
        }
        fetched
    };

    // SAFETY: `skeymgmt` is live and `exchange` is live.
    let (skeymgmt_prov, skeymgmt_import, derive_skey, derive) = unsafe {
        (
            (*skeymgmt).prov,
            (*skeymgmt).import,
            (*exchange).derive_skey,
            (*exchange).derive,
        )
    };

    /* The raw fallback: a different provider, or a method that cannot derive a key object. */
    if skeymgmt_prov != exch_prov || derive_skey.is_none() {
        let Some(derive) = derive else {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EXCHANGE_601) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        };

        // SAFETY: `ctx` is live.
        let libctx = unsafe { (*ctx).libctx };
        let key = CRYPTO_zalloc(keylen, FILE, LINE_ZALLOC_DERIVE_SKEY).cast::<u8>();
        if key.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EXCHANGE_607) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        }

        let mut tmplen = keylen;
        // SAFETY: `derive` is the provider's own callback, `algctx` is its context, `key` is this
        // call's own block of `keylen` bytes and the authority passes the length as `outlen`.
        if unsafe { derive(algctx, key, ptr::addr_of_mut!(tmplen), tmplen) } == 0 {
            // SAFETY: `key` is this call's own block.
            unsafe { CRYPTO_free(key.cast::<c_void>(), FILE, LINE_FREE_DERIVE_SKEY_ON_DERIVE) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        }

        if keylen != tmplen {
            // SAFETY: `key` is this call's own block and it holds part of a secret.
            unsafe { CRYPTO_free(key.cast::<c_void>(), FILE, LINE_FREE_DERIVE_SKEY_ON_LENGTH) };
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::EXCHANGE_619) };
            if mgmt != skeymgmt {
                // SAFETY: `skeymgmt` is live and this is this call's own reference.
                unsafe { EVP_SKEYMGMT_free(skeymgmt) };
            }
            return ptr::null_mut();
        }

        let mut import_params = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
        // SAFETY: the constructor takes a key string and a buffer, and the array is terminated.
        import_params[0] = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_SKEY_PARAM_RAW_BYTES,
                key.cast::<c_void>(),
                keylen,
            )
        };
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
        /* Cleared before it is released: this buffer is the secret's only copy outside the caller. */
        // SAFETY: `key` is this call's own block of `keylen` bytes and is not used again.
        unsafe {
            CRYPTO_clear_free(
                key.cast::<c_void>(),
                keylen,
                FILE,
                LINE_CLEAR_FREE_DERIVE_SKEY,
            )
        };
        return ret;
    }

    /* The key-aware path. */
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
    // SAFETY: `derive_skey` was tested non-absent above.
    let Some(derive_skey) = derive_skey else {
        // SAFETY: `ret` is this call's own object and is not yet reachable by the caller.
        unsafe { EVP_SKEY_free(ret) };
        if mgmt != skeymgmt {
            // SAFETY: `skeymgmt` is live and this is this call's own reference.
            unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        }
        return ptr::null_mut();
    };
    // SAFETY: `derive_skey` is the provider's own callback; `algctx` is its context, `key_type` is
    // the caller's, `provctx` is the destination's, and `skeymgmt_import` is the destination's own
    // importer — which is what the callback needs to build the key data it returns.
    let keydata =
        unsafe { derive_skey(algctx, key_type, provctx, skeymgmt_import, keylen, params) };
    // SAFETY: `ret` is this call's own object.
    unsafe { (*ret).keydata = keydata };
    if keydata.is_null() {
        // SAFETY: `ret` is this call's own object.
        unsafe { EVP_SKEY_free(ret) };
        if mgmt != skeymgmt {
            // SAFETY: `skeymgmt` is live and this is this call's own reference.
            unsafe { EVP_SKEYMGMT_free(skeymgmt) };
        }
        return ptr::null_mut();
    }

    /* `cleanup:`. */
    if mgmt != skeymgmt {
        // SAFETY: `skeymgmt` is live and this is this call's own reference.
        unsafe { EVP_SKEYMGMT_free(skeymgmt) };
    }
    ret
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
