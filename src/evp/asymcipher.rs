//! Phase 7.4 — the `EVP_ASYM_CIPHER` method object.
//!
//! `crypto/evp/asymcipher.c`'s **method half**: the object, its lifetime, and the eleven exports that
//! reach it. The file's other half — `EVP_PKEY_encrypt_init`, `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt`
//! and their `_init_ex` spellings — is `EVP_PKEY_CTX` work and lands with 7.4c's context, because every
//! one of them begins by reading `ctx->operation` and `ctx->op.ciph.algctx`.
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

/// `OSSL_OP_ASYM_CIPHER` — `include/openssl/core_dispatch.h`.
pub(crate) const OSSL_OP_ASYM_CIPHER: c_int = 13;

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c".as_ptr();
/// `evp_asym_cipher_new`'s `OPENSSL_zalloc(sizeof(EVP_ASYM_CIPHER))` (line 352).
const LINE_ZALLOC_CIPHER: c_int = 352;
/// `EVP_ASYM_CIPHER_free`'s `OPENSSL_free(cipher->type_name)` (line 494).
const LINE_FREE_TYPE_NAME: c_int = 494;
/// `EVP_ASYM_CIPHER_free`'s `OPENSSL_free(cipher)` (line 497).
const LINE_FREE_CIPHER: c_int = 497;

// ---------------------------------------------------------------------------------------------
// The dispatch ids and the eleven function-pointer types.
//
// `OSSL_FUNC_ASYM_CIPHER_*`, copied rather than derived: they are the wire format a provider is
// compiled against. Unlike the `EVP_KEYMGMT` class the ids **are** dense here, from 1 to 11, and the
// difference is worth stating because it is the kind of assumption that transfers badly.
// ---------------------------------------------------------------------------------------------

/// `OSSL_FUNC_ASYM_CIPHER_NEWCTX`.
const OSSL_FUNC_ASYM_CIPHER_NEWCTX: c_int = 1;
/// `OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT`.
const OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT: c_int = 2;
/// `OSSL_FUNC_ASYM_CIPHER_ENCRYPT`.
const OSSL_FUNC_ASYM_CIPHER_ENCRYPT: c_int = 3;
/// `OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT`.
const OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT: c_int = 4;
/// `OSSL_FUNC_ASYM_CIPHER_DECRYPT`.
const OSSL_FUNC_ASYM_CIPHER_DECRYPT: c_int = 5;
/// `OSSL_FUNC_ASYM_CIPHER_FREECTX`.
const OSSL_FUNC_ASYM_CIPHER_FREECTX: c_int = 6;
/// `OSSL_FUNC_ASYM_CIPHER_DUPCTX`.
const OSSL_FUNC_ASYM_CIPHER_DUPCTX: c_int = 7;
/// `OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS`.
const OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS: c_int = 8;
/// `OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS`.
const OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS: c_int = 9;
/// `OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS`.
const OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS: c_int = 10;
/// `OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS`.
const OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS: c_int = 11;

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
#[allow(dead_code)] // first live caller is `evp_pkey_asym_cipher_init`, which lands with 7.4c's context
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
