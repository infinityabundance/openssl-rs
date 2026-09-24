//! Phase 7.4 — the `EVP_ASYM_CIPHER` method object.
//!
//! `crypto/evp/asymcipher.c` whole: the **method half** — the object, its lifetime, and the eleven
//! exports that reach it — and the **operation half**, `EVP_PKEY_encrypt_init`, `EVP_PKEY_encrypt`,
//! `EVP_PKEY_decrypt` and their `_init_ex` spellings. The operation half is here rather than with
//! the method object because every one of its six exports begins by reading `ctx->operation` and
//! `ctx->op.ciph.algctx`, and those belong to the `EVP_PKEY_CTX` object that landed in 7.4c-i.
//!
//! ## The structural check is six counters and one cross-product
//!
//! ```text
//! ctxfncnt      == 2                          newctx + freectx, both mandatory
//! encfncnt      in {0, 2}                     encrypt_init + encrypt
//! decfncnt      in {0, 2}                     decrypt_init + decrypt
//! encfncnt != 2 || decfncnt != 2              at least one direction complete
//! gparamfncnt   in {0, 2}                     get_ctx_params + gettable_ctx_params
//! sparamfncnt   in {0, 2}                     set_ctx_params + settable_ctx_params
//! ```
//!
//! The fourth clause is the one that is not a counter, and it is an **`||` over two counters**: a
//! method that publishes only a decryptor is accepted, and so is one that publishes only an encryptor,
//! but one that publishes *neither* is refused. So the refusal can come from either half of the pair
//! or from neither being complete, and a transcription that wrote
//! `encfncnt == 2 && decfncnt == 2` would refuse the single-direction methods — which are the whole
//! reason the clause is spelled the way it is. `ECDH`-style methods have no encryptor at all.
//!
//! The `dupctx` arm is **not counted**, exactly as in the `EVP_KEYMGMT` class: a method without a
//! duplicator is perfectly fetchable and perfectly usable, and only `EVP_PKEY_CTX_dup` notices.
//!
//! ## The two context-parameter accessors pass a NULL context
//!
//! `EVP_ASYM_CIPHER_gettable_ctx_params` and its setter call the provider with
//! `(NULL, provctx)` — a NULL operation context and the provider's own — because the *descriptor table*
//! is a property of the method and not of one context. That is why the callbacks' first parameter is
//! documented as possibly NULL, and it is the one place in this class where an argument is deliberately
//! absent rather than absent by mistake.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};
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
use crate::evp::pkey::evp_pkey_export_to_provider;
use crate::evp::pkey_ctx::{
    evp_pkey_ctx_free_old_ops, EvpPkeyCtx, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCRYPT,
    EVP_PKEY_OP_UNDEFINED,
};
use crate::params::OsslParam;
use crate::property::store::{MethodFreeFn, MethodUpRefFn};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::{ossl_provider_ctx, ossl_provider_free, ossl_provider_up_ref, OsslProvider};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{
    err_sites, raise_site, raise_site_data, ERR_clear_last_mark, ERR_count_to_mark,
    ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// `OSSL_OP_ASYM_CIPHER` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_ASYM_CIPHER: c_int = 13;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c".as_ptr();
/// The buffer size the authority's `ERR_raise_data` messages are formatted into —
/// `ERR_MAX_DATA_SIZE`, `include/internal/err.h`.
const ERR_DATA_BUFFER: usize = 1024;
/// `evp_asym_cipher_new`'s `OPENSSL_zalloc(sizeof(EVP_ASYM_CIPHER))` (line 352).
const LINE_ZALLOC_CIPHER: c_int = 352;
/// `EVP_ASYM_CIPHER_free`'s `OPENSSL_free(cipher->type_name)` (line 494).
const LINE_FREE_TYPE_NAME: c_int = 494;
/// `EVP_ASYM_CIPHER_free`'s `OPENSSL_free(cipher)` (line 497).
const LINE_FREE_CIPHER: c_int = 497;
/// `evp_pkey_decrypt_alloc`'s `OPENSSL_malloc(*outlenp)` (line 337).
const LINE_MALLOC_DECRYPT_ALLOC: c_int = 337;
/// `evp_pkey_decrypt_alloc`'s `OPENSSL_clear_free(*outp, *outlenp)` (line 343).
const LINE_CLEAR_FREE_DECRYPT_ALLOC: c_int = 343;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the eleven function-pointer types.
//
// `OSSL_FUNC_ASYM_CIPHER_*`, copied rather than derived: they are the wire format a provider is
// compiled against. Unlike the `EVP_KEYMGMT` class the ids **are** dense here, from 1 to 11, and the
// difference is worth stating because it is the kind of assumption that transfers badly.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_ASYM_CIPHER_NEWCTX`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_NEWCTX: c_int = 1;
/// `OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT: c_int = 2;
/// `OSSL_FUNC_ASYM_CIPHER_ENCRYPT`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_ENCRYPT: c_int = 3;
/// `OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT: c_int = 4;
/// `OSSL_FUNC_ASYM_CIPHER_DECRYPT`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_DECRYPT: c_int = 5;
/// `OSSL_FUNC_ASYM_CIPHER_FREECTX`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_FREECTX: c_int = 6;
/// `OSSL_FUNC_ASYM_CIPHER_DUPCTX`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_DUPCTX: c_int = 7;
/// `OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS`.
pub(crate) const OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS: c_int = 11;

/// `OSSL_FUNC_asym_cipher_newctx_fn`.
pub(crate) type AsymCipherNewctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_asym_cipher_encrypt_init_fn`.
pub(crate) type AsymCipherEncryptInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_asym_cipher_encrypt_fn`.
pub(crate) type AsymCipherEncryptFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_asym_cipher_decrypt_init_fn`.
pub(crate) type AsymCipherDecryptInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_asym_cipher_decrypt_fn`.
pub(crate) type AsymCipherDecryptFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
/// `OSSL_FUNC_asym_cipher_freectx_fn`.
pub(crate) type AsymCipherFreectxFn = unsafe extern "C" fn(*mut c_void);
/// `OSSL_FUNC_asym_cipher_dupctx_fn`.
pub(crate) type AsymCipherDupctxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
/// `OSSL_FUNC_asym_cipher_get_ctx_params_fn`.
pub(crate) type AsymCipherGetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut OsslParam) -> c_int;
/// `OSSL_FUNC_asym_cipher_gettable_ctx_params_fn`.
pub(crate) type AsymCipherGettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;
/// `OSSL_FUNC_asym_cipher_set_ctx_params_fn`.
pub(crate) type AsymCipherSetCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *const OsslParam) -> c_int;
/// `OSSL_FUNC_asym_cipher_settable_ctx_params_fn`.
pub(crate) type AsymCipherSettableCtxParamsFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OsslParam;

/// `struct evp_asym_cipher_st` — `crypto/evp/evp_local.h`.
#[repr(C)]
pub struct EvpAsymCipher {
    /// `int name_id` — the namemap identity.
    pub(crate) name_id: c_int,
    /// `char *type_name` — the first alias, owned.
    pub(crate) type_name: *mut c_char,
    /// `const char *description` — the provider's own string, **not** owned.
    pub(crate) description: *const c_char,
    /// `OSSL_PROVIDER *prov` — the provider that published it, holding a reference.
    pub(crate) prov: *mut OsslProvider,
    /// `CRYPTO_REF_COUNT refcnt`.
    pub(crate) refcnt: AtomicI32,
    /// `OSSL_FUNC_asym_cipher_newctx_fn *newctx` — mandatory.
    pub(crate) newctx: Option<AsymCipherNewctxFn>,
    /// `OSSL_FUNC_asym_cipher_encrypt_init_fn *encrypt_init`.
    pub(crate) encrypt_init: Option<AsymCipherEncryptInitFn>,
    /// `OSSL_FUNC_asym_cipher_encrypt_fn *encrypt`.
    pub(crate) encrypt: Option<AsymCipherEncryptFn>,
    /// `OSSL_FUNC_asym_cipher_decrypt_init_fn *decrypt_init`.
    pub(crate) decrypt_init: Option<AsymCipherDecryptInitFn>,
    /// `OSSL_FUNC_asym_cipher_decrypt_fn *decrypt`.
    pub(crate) decrypt: Option<AsymCipherDecryptFn>,
    /// `OSSL_FUNC_asym_cipher_freectx_fn *freectx` — mandatory.
    pub(crate) freectx: Option<AsymCipherFreectxFn>,
    /// `OSSL_FUNC_asym_cipher_dupctx_fn *dupctx` — optional, and **not** counted.
    pub(crate) dupctx: Option<AsymCipherDupctxFn>,
    /// `OSSL_FUNC_asym_cipher_get_ctx_params_fn *get_ctx_params`.
    pub(crate) get_ctx_params: Option<AsymCipherGetCtxParamsFn>,
    /// `OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *gettable_ctx_params`.
    pub(crate) gettable_ctx_params: Option<AsymCipherGettableCtxParamsFn>,
    /// `OSSL_FUNC_asym_cipher_set_ctx_params_fn *set_ctx_params`.
    pub(crate) set_ctx_params: Option<AsymCipherSetCtxParamsFn>,
    /// `OSSL_FUNC_asym_cipher_settable_ctx_params_fn *settable_ctx_params`.
    pub(crate) settable_ctx_params: Option<AsymCipherSettableCtxParamsFn>,
}

/// `static void evp_asym_cipher_free(void *data)` — the shape `evp_generic_fetch` wants.
///
/// # Safety
/// `data` must be NULL or a live `EvpAsymCipher`.
unsafe extern "C" fn evp_asym_cipher_free(data: *mut c_void) {
    // SAFETY: `data` is NULL or live per the contract.
    unsafe { EVP_ASYM_CIPHER_free(data.cast::<EvpAsymCipher>()) }
}

/// `static int evp_asym_cipher_up_ref(void *data)`.
///
/// # Safety
/// `data` must be a live `EvpAsymCipher`.
unsafe extern "C" fn evp_asym_cipher_up_ref(data: *mut c_void) -> c_int {
    // SAFETY: `data` is live per the contract.
    unsafe { EVP_ASYM_CIPHER_up_ref(data.cast::<EvpAsymCipher>()) }
}

/// `static EVP_ASYM_CIPHER *evp_asym_cipher_new(OSSL_PROVIDER *prov)` — the constructor the walk
/// starts from, with the provider reference taken **before** the allocation is returned.
///
/// # Safety
/// `prov` must be live.
unsafe fn evp_asym_cipher_new(prov: *mut OsslProvider) -> *mut EvpAsymCipher {
    /* `CRYPTO_zalloc` is a safe entry point of this crate: it validates its own argument. */
    let cipher = CRYPTO_zalloc(
        core::mem::size_of::<EvpAsymCipher>(),
        FILE,
        LINE_ZALLOC_CIPHER,
    )
    .cast::<EvpAsymCipher>();
    if cipher.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cipher` is this call's own object and `prov` is live.
    unsafe {
        (*cipher).refcnt = AtomicI32::new(1);
        (*cipher).prov = prov;
        ossl_provider_up_ref(prov);
    }
    cipher
}

/// `static void *evp_asym_cipher_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
/// OSSL_PROVIDER *prov)` — the walk that fills the object and then decides whether it is a
/// *consistent set of functions*.
///
/// The walk itself is the same guarded shape the whole family uses: every arm is
/// `if (field == NULL)`, so a duplicate dispatch id is a no-op rather than an overwrite, and the
/// counter increments only for the first entry of its pair.
///
/// # Safety
/// `algodef` must be live; `prov` must be live.
unsafe extern "C" fn evp_asym_cipher_from_algorithm(
    name_id: c_int,
    algodef: *const OsslAlgorithm,
    prov: *mut OsslProvider,
) -> *mut c_void {
    // SAFETY: `algodef` is live per the contract.
    let fns = unsafe { (*algodef).implementation.cast::<OsslDispatch>() };

    // SAFETY: `prov` is live per the contract.
    let cipher = unsafe { evp_asym_cipher_new(prov) };
    if cipher.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `cipher` is live.
    unsafe { (*cipher).name_id = name_id };
    // SAFETY: `algodef` is live.
    let type_name = unsafe { ossl_algorithm_get1_first_name(algodef) };
    if type_name.is_null() {
        // SAFETY: `cipher` is this call's own object.
        unsafe { EVP_ASYM_CIPHER_free(cipher) };
        return ptr::null_mut();
    }
    // SAFETY: `cipher` is live and `type_name` is the string just allocated for it.
    unsafe { (*cipher).type_name = type_name };
    // SAFETY: both are live.
    unsafe { (*cipher).description = (*algodef).algorithm_description };

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
                OSSL_FUNC_ASYM_CIPHER_NEWCTX if (*cipher).newctx.is_none() => {
                    (*cipher).newctx = entry_function::<AsymCipherNewctxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT if (*cipher).encrypt_init.is_none() => {
                    (*cipher).encrypt_init = entry_function::<AsymCipherEncryptInitFn>(entry);
                    encfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_ENCRYPT if (*cipher).encrypt.is_none() => {
                    (*cipher).encrypt = entry_function::<AsymCipherEncryptFn>(entry);
                    encfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT if (*cipher).decrypt_init.is_none() => {
                    (*cipher).decrypt_init = entry_function::<AsymCipherDecryptInitFn>(entry);
                    decfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_DECRYPT if (*cipher).decrypt.is_none() => {
                    (*cipher).decrypt = entry_function::<AsymCipherDecryptFn>(entry);
                    decfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_FREECTX if (*cipher).freectx.is_none() => {
                    (*cipher).freectx = entry_function::<AsymCipherFreectxFn>(entry);
                    ctxfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_DUPCTX if (*cipher).dupctx.is_none() => {
                    (*cipher).dupctx = entry_function::<AsymCipherDupctxFn>(entry);
                }
                OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS if (*cipher).get_ctx_params.is_none() => {
                    (*cipher).get_ctx_params = entry_function::<AsymCipherGetCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS
                    if (*cipher).gettable_ctx_params.is_none() =>
                {
                    (*cipher).gettable_ctx_params =
                        entry_function::<AsymCipherGettableCtxParamsFn>(entry);
                    gparamfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS if (*cipher).set_ctx_params.is_none() => {
                    (*cipher).set_ctx_params = entry_function::<AsymCipherSetCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS
                    if (*cipher).settable_ctx_params.is_none() =>
                {
                    (*cipher).settable_ctx_params =
                        entry_function::<AsymCipherSettableCtxParamsFn>(entry);
                    sparamfncnt += 1;
                }
                _ => {}
            }
            entry = entry.add(1);
        }
    }

    /* The sixth clause is an `||` across two counters, not a conjunction: a method that can only
     * encrypt or only decrypt is a complete implementation of one direction, and the authority
     * accepts it. See this module's documentation. */
    let inconsistent = ctxfncnt != 2
        || (encfncnt != 0 && encfncnt != 2)
        || (decfncnt != 0 && decfncnt != 2)
        || (encfncnt != 2 && decfncnt != 2)
        || (gparamfncnt != 0 && gparamfncnt != 2)
        || (sparamfncnt != 0 && sparamfncnt != 2);
    if inconsistent {
        /* A **plain** `ERR_raise`, and the difference from the `EVP_SIGNATURE` class matters: that
         * one names which clause failed in a formatted message, and this one does not. A court that
         * read a message here would be reading one the authority never writes. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_475) };
        // SAFETY: `cipher` is this call's own object.
        unsafe { EVP_ASYM_CIPHER_free(cipher) };
        return ptr::null_mut();
    }

    cipher.cast::<c_void>()
}

/// `void EVP_ASYM_CIPHER_free(EVP_ASYM_CIPHER *cipher)`.
///
/// The release order is the authority's: the type name, then the provider *reference*, then the
/// object — and `ossl_provider_free` is the one that decrements, so a method that outlives its
/// provider keeps the provider alive. There is no other field to release: the callbacks are the
/// provider's own function pointers and nothing here owns them.
///
/// # Safety
/// `cipher` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_free(cipher: *mut EvpAsymCipher) {
    if cipher.is_null() {
        return;
    }
    // SAFETY: `cipher` is live per the contract.
    let last = unsafe { (*cipher).refcnt.fetch_sub(1, Ordering::AcqRel) };
    if last > 1 {
        return;
    }
    // SAFETY: `cipher` is live and this was the last reference.
    let (type_name, prov) = unsafe { ((*cipher).type_name, (*cipher).prov) };
    // SAFETY: `type_name` was allocated for this object.
    unsafe { CRYPTO_free(type_name.cast(), FILE, LINE_FREE_TYPE_NAME) };
    // SAFETY: `prov` is live and holds the reference `evp_asym_cipher_new` took.
    unsafe { ossl_provider_free(prov) };
    // SAFETY: `cipher` is this object's own allocation.
    unsafe { CRYPTO_free(cipher.cast(), FILE, LINE_FREE_CIPHER) };
}

/// `int EVP_ASYM_CIPHER_up_ref(EVP_ASYM_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_up_ref(cipher: *mut EvpAsymCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).refcnt.fetch_add(1, Ordering::AcqRel) };
    1
}

/// `OSSL_PROVIDER *EVP_ASYM_CIPHER_get0_provider(const EVP_ASYM_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_provider(
    cipher: *const EvpAsymCipher,
) -> *mut OsslProvider {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).prov }
}

/// `EVP_ASYM_CIPHER *EVP_ASYM_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
/// const char *properties)`.
///
/// # Safety
/// `ctx` NULL or live; `algorithm` and `properties` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_fetch(
    ctx: *mut c_void,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpAsymCipher {
    // SAFETY: the arguments are forwarded under this function's contract, and the three callbacks
    // are this module's own.
    unsafe {
        evp_generic_fetch(
            ctx,
            OSSL_OP_ASYM_CIPHER,
            algorithm,
            properties,
            evp_asym_cipher_from_algorithm as MethodFromAlgorithmFn,
            evp_asym_cipher_up_ref as MethodUpRefFn,
            evp_asym_cipher_free as MethodFreeFn,
        )
    }
    .cast::<EvpAsymCipher>()
}

/// `EVP_ASYM_CIPHER *evp_asym_cipher_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
/// const char *properties)`.
///
/// The second iteration of the operation half's two-pass fetch: the same algorithm, asked for by
/// *provider* rather than by property query.
///
/// # Safety
/// `prov` must be live; `algorithm` and `properties` NULL or NUL-terminated.
#[allow(dead_code)] // first live caller is `evp_pkey_asym_cipher_init`
pub(crate) unsafe fn evp_asym_cipher_fetch_from_prov(
    prov: *mut OsslProvider,
    algorithm: *const c_char,
    properties: *const c_char,
) -> *mut EvpAsymCipher {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_generic_fetch_from_prov(
            prov,
            OSSL_OP_ASYM_CIPHER,
            algorithm,
            properties,
            evp_asym_cipher_from_algorithm as MethodFromAlgorithmFn,
            evp_asym_cipher_up_ref as MethodUpRefFn,
            evp_asym_cipher_free as MethodFreeFn,
        )
    }
    .cast::<EvpAsymCipher>()
}

/// `int EVP_ASYM_CIPHER_is_a(const EVP_ASYM_CIPHER *cipher, const char *name)`.
///
/// # Safety
/// `cipher` must be live; `name` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_is_a(
    cipher: *const EvpAsymCipher,
    name: *const c_char,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    let (prov, name_id) = unsafe { ((*cipher).prov, (*cipher).name_id) };
    // SAFETY: `prov` is live and `name` is NUL-terminated.
    unsafe { evp_is_a(prov, name_id, ptr::null(), name) }
}

/// `int evp_asym_cipher_get_number(const EVP_ASYM_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be live.
#[allow(dead_code)] // read by the `EVP_PKEY_CTX` construction path in 7.4c
pub(crate) unsafe fn evp_asym_cipher_get_number(cipher: *const EvpAsymCipher) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).name_id }
}

/// `const char *EVP_ASYM_CIPHER_get0_name(const EVP_ASYM_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_name(cipher: *const EvpAsymCipher) -> *const c_char {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).type_name }
}

/// `const char *EVP_ASYM_CIPHER_get0_description(const EVP_ASYM_CIPHER *cipher)`.
///
/// # Safety
/// `cipher` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_description(
    cipher: *const EvpAsymCipher,
) -> *const c_char {
    // SAFETY: `cipher` is live per the contract.
    unsafe { (*cipher).description }
}

/// `void EVP_ASYM_CIPHER_do_all_provided(OSSL_LIB_CTX *libctx, void (*fn)(EVP_ASYM_CIPHER *,
/// void *), void *arg)`.
///
/// A **NULL visitor is refused** rather than passed to a walk that would call it; the boundary is
/// `EVP_MD_do_all_provided`'s, measured in `docs/SECURITY_DIVERGENCE_POLICY.md`
/// D-MD-DOALL-NULL-1.
///
/// # Safety
/// `libctx` NULL or live; `fn_` a valid visitor or NULL; `arg` the visitor's own argument.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_do_all_provided(
    libctx: *mut c_void,
    fn_: Option<unsafe extern "C" fn(*mut EvpAsymCipher, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(visitor) = fn_ else {
        return;
    };
    // SAFETY: the visitor is the caller's and `arg` is its own; the three callbacks are this
    // module's own and `visitor` is transmuted to the walk's uniform signature, which is what the
    // authority does with the same cast.
    unsafe {
        evp_generic_do_all(
            libctx,
            OSSL_OP_ASYM_CIPHER,
            core::mem::transmute::<
                unsafe extern "C" fn(*mut EvpAsymCipher, *mut c_void),
                GenericDoAllFn,
            >(visitor),
            arg,
            evp_asym_cipher_from_algorithm as MethodFromAlgorithmFn,
            evp_asym_cipher_up_ref as MethodUpRefFn,
            evp_asym_cipher_free as MethodFreeFn,
        )
    };
}

/// `int EVP_ASYM_CIPHER_names_do_all(const EVP_ASYM_CIPHER *cipher,
/// void (*fn)(const char *name, void *data), void *data)`.
///
/// Answers **1** for a method with no provider, which is the same answer the namemap walk gives for an
/// id with no names — see `EVP_KEYMGMT_names_do_all`'s note on the same asymmetry.
///
/// # Safety
/// `cipher` must be live; `fn_` a valid visitor.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_names_do_all(
    cipher: *const EvpAsymCipher,
    fn_: Option<unsafe extern "C" fn(*const c_char, *mut c_void)>,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `cipher` is live per the contract.
    let (prov, name_id) = unsafe { ((*cipher).prov, (*cipher).name_id) };
    if !prov.is_null() {
        // SAFETY: `prov` is live and the visitor's contract is the namemap's.
        return unsafe { evp_names_do_all(prov, name_id, fn_, data) };
    }
    1
}

/// `const OSSL_PARAM *EVP_ASYM_CIPHER_gettable_ctx_params(const EVP_ASYM_CIPHER *cip)`.
///
/// A **NULL guard on both** the method and the callback, then a call-through whose first argument is
/// deliberately NULL: the descriptor table is a property of the method, not of one context, so there
/// is no context to pass and `provctx` comes from the provider.
///
/// # Safety
/// `cip` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_gettable_ctx_params(
    cip: *const EvpAsymCipher,
) -> *const OsslParam {
    if cip.is_null() {
        return ptr::null();
    }
    // SAFETY: `cip` is live per the contract.
    let (f, prov) = unsafe { ((*cip).gettable_ctx_params, (*cip).prov) };
    let Some(gettable) = f else {
        return ptr::null();
    };
    // SAFETY: `prov` is live, so its context is readable.
    let provctx = unsafe { ossl_provider_ctx(prov) };
    // SAFETY: `gettable` is the provider's own callback and a NULL operation context is what the
    // authority passes here.
    unsafe { gettable(ptr::null_mut(), provctx) }
}

/// `const OSSL_PARAM *EVP_ASYM_CIPHER_settable_ctx_params(const EVP_ASYM_CIPHER *cip)`.
///
/// # Safety
/// `cip` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn EVP_ASYM_CIPHER_settable_ctx_params(
    cip: *const EvpAsymCipher,
) -> *const OsslParam {
    if cip.is_null() {
        return ptr::null();
    }
    // SAFETY: `cip` is live per the contract.
    let (f, prov) = unsafe { ((*cip).settable_ctx_params, (*cip).prov) };
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
// The operation half — `evp_pkey_asym_cipher_init` and the six exports over it.
//
// These are the functions that read `ctx->operation` and `ctx->op.ciph.algctx`, which is why they
// land after the `EVP_PKEY_CTX` object (7.4c-i) rather than with the method object above.
// ---------------------------------------------------------------------------------------------

/// `cipher->description != NULL ? cipher->description : ""` — the empty string is the authority's
/// fallback and not an accident: a court reads the message to tell one provider from another.
///
/// # Safety
/// `cipher` must be live.
unsafe fn asym_cipher_description(cipher: *const EvpAsymCipher) -> *const c_char {
    // SAFETY: `cipher` is live per the contract.
    let description = unsafe { (*cipher).description };
    if description.is_null() {
        c"".as_ptr()
    } else {
        description
    }
}

/// Raise `EVP_R_PROVIDER_ASYM_CIPHER_NOT_SUPPORTED` with the authority's message for one clause.
///
/// The message is `%s <clause>:%s` — the method's type name, the operation, and its description —
/// which is what makes the failing clause identifiable from the error queue alone.
///
/// # Safety
/// `cipher` must be live.
unsafe fn raise_clause(cipher: *const EvpAsymCipher, site: &err_sites::ErrSite, clause: &CStr) {
    // SAFETY: `cipher` is live and `type_name` is a NUL-terminated string it owns.
    let type_name = unsafe { (*cipher).type_name };
    // SAFETY: `cipher` is live.
    let desc = unsafe { asym_cipher_description(cipher) };
    let mut msg = [0 as c_char; ERR_DATA_BUFFER];
    // SAFETY: `msg` is 1024 writable bytes and `type_name` is NUL-terminated.
    unsafe { BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"%s ".as_ptr(), type_name) };
    let mut full = [0 as c_char; ERR_DATA_BUFFER];
    // SAFETY: `full` is 1024 writable bytes; all four arguments are NUL-terminated.
    unsafe {
        BIO_snprintf(
            full.as_mut_ptr(),
            full.len(),
            c"%s%s:%s".as_ptr(),
            msg.as_ptr(),
            clause.as_ptr(),
            desc,
        )
    };
    // SAFETY: a compile-time-constant site; the message is NUL-terminated.
    unsafe { raise_site_data(site, full.as_ptr()) };
}

/// The authority's `err:` label — `crypto/evp/asymcipher.c:223`.
///
/// `ret` is the caller's running result, so a non-positive one tears the half-built operation back
/// down and leaves the context `UNDEFINED` — which is what makes a failed `_init` re-initialisable
/// rather than half-bound.
///
/// # Safety
/// `ctx` must be live; `tmp_keymgmt` NULL or live.
unsafe fn asym_cipher_init_err(
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

/// The authority's `legacy:` label — `crypto/evp/asymcipher.c:194`.
///
/// Three of the four ways to arrive here have already dropped `cipher` — the second fetch returning
/// NULL, and the post-loop `provkey == NULL` test — and the fourth, the `evp_pkey_ctx_is_legacy`
/// entry, never took one. So the label holds no live method and the authority frees none here
/// either.
///
/// The body is a refusal, and the reason is structural rather than chosen: `ctx->pmeth` belongs to
/// `EVP_PKEY_METHOD`, which is Phase 8's, so `ctx->pmeth == NULL` always and the authority's
/// `if (ctx->pmeth == NULL || ctx->pmeth->encrypt == NULL)` is satisfied on every arrival. The arm
/// it guards is the one that hands the operation to a legacy method, which is the branch this crate
/// cannot represent.
///
/// # Safety
/// `tmp_keymgmt` NULL or live.
unsafe fn asym_cipher_init_legacy(tmp_keymgmt: *mut EvpKeyMgmt) -> c_int {
    ERR_pop_to_mark();
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::ASYMCIPHER_204) };
    -2
}

/// `static int evp_pkey_asym_cipher_init(EVP_PKEY_CTX *ctx, int operation,
/// const OSSL_PARAM params[])` — `crypto/evp/asymcipher.c:34`.
///
/// Two iterations of one fetch, and the second is not a retry: the first asks by *property query*
/// and the second asks the same question of the **provider that owns the key**, which is the only
/// way to reach an algorithm a property query would not select. The key is then exported to
/// whichever provider answered, and when neither does the authority falls through to its legacy
/// half — which in this crate is the refusal above.
///
/// # Safety
/// `ctx` NULL or live; `params` NULL or a terminated array.
unsafe fn evp_pkey_asym_cipher_init(
    ctx: *mut EvpPkeyCtx,
    operation: c_int,
    params: *const OsslParam,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_43) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    unsafe { evp_pkey_ctx_free_old_ops(ctx) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).operation = operation };

    ERR_set_mark();

    // SAFETY: `ctx` is live.
    if unsafe { &*ctx }.is_legacy() {
        // SAFETY: the second argument is a literal NULL and the label holds no live method.
        return unsafe { asym_cipher_init_legacy(ptr::null_mut()) };
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).pkey }.is_null() {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_57) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { asym_cipher_init_err(ctx, ptr::null_mut(), 0) };
    }

    /* The key's own method and the context's must be the same one, or the key must not be bound
     * to a method at all. `ossl_assert` under `NDEBUG` is `(x) != 0`, so this is a live refusal
     * and not a debug-only abort (`docs/DECISIONS.md` D167). */
    // SAFETY: `ctx` is live and its `pkey` is non-NULL.
    let pkey_keymgmt = unsafe { (*(*ctx).pkey).keymgmt };
    // SAFETY: `ctx` is live.
    if !(pkey_keymgmt.is_null() || pkey_keymgmt == unsafe { (*ctx).keymgmt }) {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_67) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { asym_cipher_init_err(ctx, ptr::null_mut(), 0) };
    }

    // SAFETY: `ctx` is live.
    let ctx_keymgmt = unsafe { (*ctx).keymgmt };
    // SAFETY: `ctx_keymgmt` is live — the context is provided-side, so it has a method.
    let supported_ciph =
        unsafe { evp_keymgmt_util_query_operation_name(ctx_keymgmt, OSSL_OP_ASYM_CIPHER) };
    if supported_ciph.is_null() {
        ERR_clear_last_mark();
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_75) };
        // SAFETY: `ctx` is live and the second argument is a literal NULL.
        return unsafe { asym_cipher_init_err(ctx, ptr::null_mut(), 0) };
    }

    let mut cipher: *mut EvpAsymCipher = ptr::null_mut();
    let mut tmp_keymgmt: *mut EvpKeyMgmt = ptr::null_mut();
    let mut tmp_prov: *const OsslProvider = ptr::null();
    let mut provkey: *mut c_void = ptr::null_mut();

    let mut iter: c_int = 1;
    while iter < 3 && provkey.is_null() {
        // SAFETY: `cipher` is NULL or live.
        unsafe { EVP_ASYM_CIPHER_free(cipher) };
        // SAFETY: `tmp_keymgmt` is NULL or live.
        unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
        tmp_keymgmt = ptr::null_mut();

        if iter == 1 {
            // SAFETY: `ctx` is live.
            let (libctx, propquery) = unsafe { ((*ctx).libctx, (*ctx).propquery) };
            // SAFETY: `libctx` is live and `supported_ciph` is NUL-terminated.
            cipher = unsafe { EVP_ASYM_CIPHER_fetch(libctx, supported_ciph, propquery) };
            if !cipher.is_null() {
                // SAFETY: `cipher` is live.
                tmp_prov = unsafe { EVP_ASYM_CIPHER_get0_provider(cipher) };
            }
        } else {
            // SAFETY: `ctx_keymgmt` is live.
            tmp_prov = unsafe { EVP_KEYMGMT_get0_provider(ctx_keymgmt) };
            // SAFETY: `ctx` is live.
            let propquery = unsafe { (*ctx).propquery };
            // SAFETY: `tmp_prov` is live and `supported_ciph` is NUL-terminated.
            cipher = unsafe {
                evp_asym_cipher_fetch_from_prov(tmp_prov.cast_mut(), supported_ciph, propquery)
            };
            if cipher.is_null() {
                // SAFETY: `tmp_keymgmt` is NULL or live at this label, and the arm frees it and refuses without touching another pointer.
                return unsafe { asym_cipher_init_legacy(tmp_keymgmt) };
            }
        }

        if !cipher.is_null() {
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
                // SAFETY: `pkey` is live, and `tmp_keymgmt` is a live local whose address is valid
                // for the call -- which may replace it, and is the whole reason it is passed by
                // address rather than by value.
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
        // SAFETY: `cipher` is NULL or live.
        unsafe { EVP_ASYM_CIPHER_free(cipher) };
        // SAFETY: `tmp_keymgmt` is NULL or live at this label, and the arm frees it and refuses without touching another pointer.
        return unsafe { asym_cipher_init_legacy(tmp_keymgmt) };
    }

    ERR_pop_to_mark();

    /* No more legacy from here down to `legacy:`. */

    // SAFETY: `ctx` is live and `cipher` is live.
    unsafe { (*ctx).op_ciph_cipher = cipher };
    /* `newctx` is mandatory: `evp_asym_cipher_from_algorithm` refuses a provider that publishes no
     * `OSSL_FUNC_ASYM_CIPHER_NEWCTX`, so a fetched method always has one and the `else` below is
     * unreachable. It is written out rather than `unwrap`ped because the crate denies `unwrap_used`,
     * and because the answer it gives is the authority's own INITIALIZATION_ERROR. */
    // SAFETY: `cipher` is live.
    let Some(newctx) = (unsafe { (*cipher).newctx }) else {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_160) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, 0) };
    };
    // SAFETY: `newctx` is the provider's own callback and `(*cipher).prov` is live.
    let algctx = unsafe { newctx(ossl_provider_ctx((*cipher).prov)) };
    // SAFETY: `ctx` is live.
    unsafe { (*ctx).op_ciph_algctx = algctx };
    if algctx.is_null() {
        /* The provider key can stay in the cache. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_160) };
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, 0) };
    }

    let ret = match operation {
        EVP_PKEY_OP_ENCRYPT => {
            // SAFETY: `cipher` is live.
            let encrypt_init = unsafe { (*cipher).encrypt_init };
            let Some(encrypt_init) = encrypt_init else {
                // SAFETY: `cipher` is live.
                unsafe { raise_clause(cipher, &err_sites::ASYMCIPHER_168, c"encrypt_init") };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: `algctx` is non-NULL, `provkey` is non-NULL, and `params` is NULL or a
            // terminated array — the provider's own callback contract.
            unsafe { encrypt_init(algctx, provkey, params) }
        }
        EVP_PKEY_OP_DECRYPT => {
            // SAFETY: `cipher` is live.
            let decrypt_init = unsafe { (*cipher).decrypt_init };
            let Some(decrypt_init) = decrypt_init else {
                // SAFETY: `cipher` is live.
                unsafe { raise_clause(cipher, &err_sites::ASYMCIPHER_177, c"decrypt_init") };
                // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
                return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, -2) };
            };
            // SAFETY: as above.
            unsafe { decrypt_init(algctx, provkey, params) }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYMCIPHER_185) };
            // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
            return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, 0) };
        }
    };

    if ret <= 0 {
        // SAFETY: `ctx` is live and `tmp_keymgmt` is NULL or live.
        return unsafe { asym_cipher_init_err(ctx, tmp_keymgmt, ret) };
    }
    // SAFETY: `tmp_keymgmt` is NULL or live.
    unsafe { EVP_KEYMGMT_free(tmp_keymgmt) };
    1
}

/// `int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, ptr::null()) }
}

/// `int EVP_PKEY_encrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, params) }
}

/// `int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
/// const unsigned char *in, size_t inlen)` — `crypto/evp/asymcipher.c:242`.
///
/// The `out == NULL` case is not a query here: the authority passes **0** as the caller's buffer
/// length rather than skipping the operation, so a provider that sizes its answer from `*outlen`
/// sees a zero and a provider that ignores it sees a NULL buffer. The distinction is the
/// provider's, and this function must not make it.
///
/// The mark discipline is the other half: the provider's own error survives, and
/// `EVP_R_PROVIDER_ASYM_CIPHER_FAILURE` is raised **only** when it failed silently
/// (`ERR_count_to_mark() == 0`).
///
/// # Safety
/// `ctx` NULL or live; `out` NULL or `*outlen` writable bytes; `in` `inlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_encrypt(
    ctx: *mut EvpPkeyCtx,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_pkey_asym_cipher_operate(
            ctx,
            EVP_PKEY_OP_ENCRYPT,
            out,
            outlen,
            input,
            inlen,
            &err_sites::ASYMCIPHER_251,
            &err_sites::ASYMCIPHER_256,
            &err_sites::ASYMCIPHER_268,
            &err_sites::ASYMCIPHER_275,
            c"encrypt",
        )
    }
}

/// `int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt_init(ctx: *mut EvpPkeyCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_DECRYPT, ptr::null()) }
}

/// `int EVP_PKEY_decrypt_init_ex(EVP_PKEY_CTX *ctx, const OSSL_PARAM params[])`.
///
/// # Safety
/// `ctx` must be live; `params` NULL or a terminated array.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt_init_ex(
    ctx: *mut EvpPkeyCtx,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe { evp_pkey_asym_cipher_init(ctx, EVP_PKEY_OP_DECRYPT, params) }
}

/// `int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
/// const unsigned char *in, size_t inlen)`.
///
/// # Safety
/// `ctx` NULL or live; `out` NULL or `*outlen` writable bytes; `in` `inlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_decrypt(
    ctx: *mut EvpPkeyCtx,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        evp_pkey_asym_cipher_operate(
            ctx,
            EVP_PKEY_OP_DECRYPT,
            out,
            outlen,
            input,
            inlen,
            &err_sites::ASYMCIPHER_300,
            &err_sites::ASYMCIPHER_305,
            &err_sites::ASYMCIPHER_317,
            &err_sites::ASYMCIPHER_325,
            c"decrypt",
        )
    }
}

/// `int evp_pkey_decrypt_alloc(EVP_PKEY_CTX *ctx, unsigned char **outp, size_t *outlenp,
/// size_t expected_outlen, const unsigned char *in, size_t inlen)` —
/// `crypto/evp/asymcipher.c:332`.
///
/// The two-pass auto-allocating decrypt: the authority asks `EVP_PKEY_decrypt(ctx, NULL, outlenp,
/// in, inlen)` for the length, allocates it, calls again with the buffer, and refuses if the second
/// call failed, if the length came back zero, or if a non-zero `expected_outlen` disagrees with it.
/// **Two of its three failure arms free the buffer and null the caller's slot and one does not** —
/// the first `||` arm returns `-1` with `*outp` untouched, because the allocation is what failed and
/// there is nothing to free. That is why the first test is written as its own `if` here and not
/// folded into one condition.
///
/// It is declared in `include/crypto/evp.h`, so it is this stratum's internal and lands with the
/// operation half it sits in. Nothing in this crate reaches it yet: its two callers are
/// `crypto/pkcs7/pk7_doit.c` and `crypto/cms/cms_env.c`, both Phase 12's, which is why the
/// `#[allow(dead_code)]` names the stratum that will reference it rather than leaving a warning.
///
/// # Safety
/// `ctx` NULL or live and armed for `EVP_PKEY_OP_DECRYPT`; `outp` and `outlenp` writable; `in`
/// `inlen` readable bytes.
#[allow(dead_code)] // the first caller is `crypto/pkcs7/pk7_doit.c`'s, which is Phase 12's
pub(crate) unsafe fn evp_pkey_decrypt_alloc(
    ctx: *mut EvpPkeyCtx,
    outp: *mut *mut u8,
    outlenp: *mut usize,
    expected_outlen: usize,
    input: *const u8,
    inlen: usize,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract.
    if unsafe { EVP_PKEY_decrypt(ctx, ptr::null_mut(), outlenp, input, inlen) } <= 0 {
        return -1;
    }
    // SAFETY: `outlenp` is writable and the first call wrote the required length into it.
    let buffer = unsafe { CRYPTO_malloc(*outlenp, FILE, LINE_MALLOC_DECRYPT_ALLOC) }.cast::<u8>();
    if buffer.is_null() {
        return -1;
    }
    // SAFETY: `outp` is writable and this call's own allocation is `*outlenp` bytes.
    unsafe { *outp = buffer };
    // SAFETY: `buffer` is `*outlenp` writable bytes and `input` is `inlen` readable ones.
    if unsafe { EVP_PKEY_decrypt(ctx, buffer, outlenp, input, inlen) } <= 0
        // SAFETY: the second call wrote the produced length into `outlenp`.
        || unsafe { *outlenp } == 0
        // SAFETY: as above.
        || (expected_outlen != 0 && unsafe { *outlenp } != expected_outlen)
    {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYMCIPHER_342) };
        // SAFETY: `buffer` is this call's own allocation of `*outlenp` bytes.
        unsafe {
            let produced = *outlenp;
            CRYPTO_clear_free(buffer.cast(), produced, FILE, LINE_CLEAR_FREE_DECRYPT_ALLOC);
        }
        // SAFETY: `outp` is writable and its value is this call's own allocation.
        unsafe { *outp = ptr::null_mut() };
        return 0;
    }
    1
}

/// The shared body of `EVP_PKEY_encrypt` and `EVP_PKEY_decrypt`, which differ in four constants
/// and one callback. Written as one function because the authority writes them as two functions of
/// thirteen lines each that are the same thirteen lines — and because the *marks* have to be the
/// same three calls in the same order for the error queue to match.
/// # Safety
/// `ctx` NULL or live; `out` NULL or `*outlen` writable bytes; `in` `inlen` readable bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's two signatures exactly
unsafe fn evp_pkey_asym_cipher_operate(
    ctx: *mut EvpPkeyCtx,
    operation: c_int,
    out: *mut u8,
    outlen: *mut usize,
    input: *const u8,
    inlen: usize,
    null_site: &err_sites::ErrSite,
    not_init_site: &err_sites::ErrSite,
    failure_site: &err_sites::ErrSite,
    legacy_site: &err_sites::ErrSite,
    clause: &CStr,
) -> c_int {
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(null_site) };
        return -2;
    }

    // SAFETY: `ctx` is live.
    if unsafe { (*ctx).operation } != operation {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(not_init_site) };
        return -1;
    }

    // SAFETY: `ctx` is live.
    let algctx = unsafe { (*ctx).op_ciph_algctx };
    if algctx.is_null() {
        /* The authority's `goto legacy`. `ctx->pmeth` is Phase 8's and always NULL here, so
         * `ctx->pmeth == NULL || ctx->pmeth->encrypt == NULL` is satisfied on arrival. */
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(legacy_site) };
        return -2;
    }

    // SAFETY: `ctx` is live and the operation is bound, so the method is live.
    let cipher = unsafe { (*ctx).op_ciph_cipher };
    ERR_set_mark();
    /* The authority passes the caller's own length, or **0** when there is no output buffer — it
     * does not skip the operation. Which of the two the provider sees is the provider's business,
     * so this function must not decide it. */
    let mut outlen_in: usize = 0;
    if !out.is_null() {
        // SAFETY: `out` is non-NULL, so `outlen` is the caller's valid buffer length per this
        // function's contract.
        outlen_in = unsafe { *outlen };
    }
    // SAFETY: `cipher` is live, and the callback for the operation that bound it is present:
    // `evp_pkey_asym_cipher_init` refused a method whose callback was absent, and
    // `operation == (*ctx).operation` above is what establishes which one was selected.
    let f = unsafe {
        if operation == EVP_PKEY_OP_ENCRYPT {
            (*cipher).encrypt
        } else {
            (*cipher).decrypt
        }
    };
    let ret = match f {
        // SAFETY: the provider's own callback, called with exactly the arguments the authority
        // passes: the operation context, the caller's buffers, and the length or 0.
        Some(f) => unsafe { f(algctx, out, outlen, outlen_in, input, inlen) },
        None => 0,
    };
    if ret <= 0 && ERR_count_to_mark() == 0 {
        // SAFETY: `cipher` is live.
        unsafe { raise_clause(cipher, failure_site, clause) };
    }
    ERR_clear_last_mark();
    ret
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    /// An all-NULL method object built by hand, so the accessors can be read without a provider.
    fn a_hand_built_cipher() -> EvpAsymCipher {
        EvpAsymCipher {
            name_id: 7,
            type_name: c"court-cipher".as_ptr().cast_mut(),
            description: c"a hand-built ASYM_CIPHER".as_ptr(),
            prov: ptr::null_mut(),
            refcnt: AtomicI32::new(1),
            newctx: None,
            encrypt_init: None,
            encrypt: None,
            decrypt_init: None,
            decrypt: None,
            freectx: None,
            dupctx: None,
            get_ctx_params: None,
            gettable_ctx_params: None,
            set_ctx_params: None,
            settable_ctx_params: None,
        }
    }

    /// The three field readers, and `names_do_all`'s answer for a method with no provider: **1**,
    /// because the walk had nothing to do rather than because it failed.
    #[test]
    fn the_accessors_read_fields_and_the_walk_answers_one() {
        let cipher = a_hand_built_cipher();
        let p: *const EvpAsymCipher = ptr::addr_of!(cipher);
        // SAFETY: `p` is this frame's own live object.
        unsafe {
            assert_eq!(
                CStr::from_ptr(EVP_ASYM_CIPHER_get0_name(p)),
                c"court-cipher"
            );
            assert_eq!(
                CStr::from_ptr(EVP_ASYM_CIPHER_get0_description(p)),
                c"a hand-built ASYM_CIPHER"
            );
            assert_eq!(evp_asym_cipher_get_number(p), 7);
            assert!(EVP_ASYM_CIPHER_get0_provider(p).is_null());
            assert_eq!(EVP_ASYM_CIPHER_names_do_all(p, None, ptr::null_mut()), 1);
            /* `is_a` on a method with no provider: `evp_is_a`'s NULL-provider arm replaces the id
             * with `name2num(NULL)` == 0, so the answer is "is this name unknown?". */
            assert_eq!(
                EVP_ASYM_CIPHER_is_a(p, c"absent-from-the-namemap".as_ptr()),
                1
            );
        }
    }

    /// The two context-parameter accessors answer NULL for a NULL method and for one with no
    /// callback -- the same answer, from two different reasons.
    #[test]
    fn the_context_parameter_accessors_answer_null() {
        let cipher = a_hand_built_cipher();
        let p: *const EvpAsymCipher = ptr::addr_of!(cipher);
        // SAFETY: `p` is this frame's own live object; NULL is the other documented input.
        unsafe {
            assert!(EVP_ASYM_CIPHER_gettable_ctx_params(p).is_null());
            assert!(EVP_ASYM_CIPHER_settable_ctx_params(p).is_null());
            assert!(EVP_ASYM_CIPHER_gettable_ctx_params(ptr::null()).is_null());
            assert!(EVP_ASYM_CIPHER_settable_ctx_params(ptr::null()).is_null());
        }
    }

    /// `up_ref` answers 1 and `free` on the last reference releases exactly once, taking the
    /// provider reference with it. A second release through a stale pointer is not called, because
    /// the object is gone.
    #[test]
    fn the_reference_count_is_taken_and_given_back() {
        // SAFETY: a NULL provider is allowed by the constructor, which up-refs conditionally.
        let cipher = unsafe { evp_asym_cipher_new(ptr::null_mut()) };
        assert!(!cipher.is_null());
        // SAFETY: `cipher` is this test's own object.
        unsafe {
            assert_eq!(EVP_ASYM_CIPHER_up_ref(cipher), 1);
            /* Two references held: the first free must not release. */
            EVP_ASYM_CIPHER_free(cipher);
            assert_eq!((*cipher).name_id, 0, "the object is still alive");
            EVP_ASYM_CIPHER_free(cipher);
        }
    }
}
