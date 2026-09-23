//! Phase 8 — the default provider's `OSSL_OP_KEYEXCH` rows, and the exchange units behind them.
//!
//! The authority publishes seven rows of `providers/defltprov.c`'s `deflt_keyexch[]`, and this
//! module is where the crate's own `deflt_query(OSSL_OP_KEYEXCH)` answers them. **This is the arm
//! D384 withheld and D385 measured the gate for**: `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)`
//! fetches the `DH` **keymgmt** row `OSSL_OP_KEYMGMT` before it can reach any keyexch row, so the
//! `OSSL_OP_KEYMGMT` arm (`src/provider/keymgmt.rs`) had to exist before any of these rows was
//! drivable at all.
//!
//! ## What is landed here
//!
//! This module currently carries the `kdf_exch.c` unit, whose three rows (`TLS1-PRF`, `HKDF`,
//! `SCRYPT`) all dispatch to the authority's one `ossl_kdf_hkdf_keyexch_functions`-family — one
//! `PROV_KDF_CTX` that is a thin wrapper over an `EVP_KDF_CTX` fetched **by name** at `newctx`
//! (`kdf_exch.c:59`). The three dispatch tables differ only in the `newctx` slot, which is what
//! the authority's `KDF_NEWCTX`/`KDF_SETTABLE_CTX_PARAMS`/`KDF_GETTABLE_CTX_PARAMS` macros make
//! explicit; the crate spells the three wrappers out rather than using a macro, and shares the
//! other eight slots' function pointers exactly as the authority shares them.
//!
//! The `DH`, `ECDH`, `X25519` and `X448` exchange units are **not** landed yet; their keymgmt rows
//! are the prerequisite and `DH` is the next keymgmt unit (its only missing callee is the
//! fifteen-line `ossl_dh_gen_type_name2id`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::evp::exchange::{
    OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX, OSSL_FUNC_KEYEXCH_FREECTX,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX, OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
};
use crate::evp::kdf::{
    EVP_KDF_CTX_dup, EVP_KDF_CTX_free, EVP_KDF_CTX_get_kdf_size, EVP_KDF_CTX_get_params,
    EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    EVP_KDF_gettable_ctx_params, EVP_KDF_settable_ctx_params, EvpKdfCtx,
};
use crate::params::OsslParam;
use crate::provider::activate::OsslAlgorithm;
use crate::provider::ctx::prov_libctx_of;
use crate::provider::keymgmt::{ossl_kdf_data_free, ossl_kdf_data_up_ref, KdfData};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

/// `struct { void *provctx; EVP_KDF_CTX *kdfctx; KDF_DATA *kdfdata; }` — `kdf_exch.c:39-43`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvKdfCtx {
    /// `void *provctx`.
    provctx: *mut c_void,
    /// `EVP_KDF_CTX *kdfctx`.
    kdfctx: *mut EvpKdfCtx,
    /// `KDF_DATA *kdfdata`.
    kdfdata: *mut KdfData,
}

/// The default provider is always in a happy state on this build; see `src/provider/keymgmt.rs`.
#[inline]
fn is_running() -> c_int {
    1
}

/// `static void *kdf_newctx(const char *kdfname, void *provctx)` — `kdf_exch.c:45-72`. The `err:`
/// label is the single exit that releases the context when the fetch or the `EVP_KDF_CTX_new`
/// fails.
///
/// # Safety
/// `kdfname` is a NUL-terminated name; `provctx` is the caller's provider context, or NULL.
unsafe fn kdf_newctx(kdfname: *const c_char, provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0 {
            return ptr::null_mut();
        }

        let kdfctx = CRYPTO_zalloc(
            core::mem::size_of::<ProvKdfCtx>(),
            c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
            53,
        )
        .cast::<ProvKdfCtx>();
        if kdfctx.is_null() {
            return ptr::null_mut();
        }

        (*kdfctx).provctx = provctx;

        let kdf = EVP_KDF_fetch(prov_libctx_of(provctx), kdfname, ptr::null());
        if kdf.is_null() {
            // SAFETY: `kdfctx` is this call's own allocation and no key context was built.
            CRYPTO_free(
                kdfctx.cast(),
                c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
                70,
            );
            return ptr::null_mut();
        }
        (*kdfctx).kdfctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);

        if (*kdfctx).kdfctx.is_null() {
            // SAFETY: as above; `EVP_KDF_CTX_new` failed, so there is nothing else to release.
            CRYPTO_free(
                kdfctx.cast(),
                c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
                70,
            );
            return ptr::null_mut();
        }

        kdfctx.cast()
    }
}

/// `kdf_tls1_prf_newctx` — `kdf_exch.c:80`. `KDF_NEWCTX(tls1_prf, "TLS1-PRF")`.
///
/// # Safety
/// The `newctx` dispatch contract.
unsafe extern "C" fn kdf_tls1_prf_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { kdf_newctx(c"TLS1-PRF".as_ptr(), provctx) }
}

/// `kdf_hkdf_newctx` — `kdf_exch.c:81`.
///
/// # Safety
/// The `newctx` dispatch contract.
unsafe extern "C" fn kdf_hkdf_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { kdf_newctx(c"HKDF".as_ptr(), provctx) }
}

/// `kdf_scrypt_newctx` — `kdf_exch.c:82`.
///
/// # Safety
/// The `newctx` dispatch contract.
unsafe extern "C" fn kdf_scrypt_newctx(provctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { kdf_newctx(c"SCRYPT".as_ptr(), provctx) }
}

/// `static int kdf_init(void *vpkdfctx, void *vkdf, const OSSL_PARAM params[])` —
/// `kdf_exch.c:84-96`. The key handle is the `KDF_DATA` the keymgmt row made; taking a reference to
/// it is what makes `kdf_exch` and `kdf_legacy_kmgmt` share one object.
///
/// # Safety
/// The `init` dispatch contract.
unsafe extern "C" fn kdf_init(
    vpkdfctx: *mut c_void,
    vkdf: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let pkdfctx = vpkdfctx.cast::<ProvKdfCtx>();

        if is_running() == 0
            || pkdfctx.is_null()
            || vkdf.is_null()
            || ossl_kdf_data_up_ref(vkdf.cast()) == 0
        {
            return 0;
        }
        (*pkdfctx).kdfdata = vkdf.cast();

        kdf_set_ctx_params(vpkdfctx, params)
    }
}

/// `static int kdf_derive(void *vpkdfctx, unsigned char *secret, size_t *secretlen, size_t outlen)`
/// — `kdf_exch.c:98-129`. The `SIZE_MAX` test is the authority's "this KDF has no fixed size"
/// convention, and the one raise in the unit is the `OUTPUT_BUFFER_TOO_SMALL` refusal at `:117`.
///
/// # Safety
/// The `derive` dispatch contract.
unsafe extern "C" fn kdf_derive(
    vpkdfctx: *mut c_void,
    secret: *mut u8,
    secretlen: *mut usize,
    mut outlen: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let pkdfctx = vpkdfctx.cast::<ProvKdfCtx>();

        if is_running() == 0 {
            return 0;
        }

        let kdfsize = EVP_KDF_CTX_get_kdf_size((*pkdfctx).kdfctx);

        if secret.is_null() {
            *secretlen = kdfsize;
            return 1;
        }

        if kdfsize != usize::MAX {
            if outlen < kdfsize {
                raise_site(&err_sites::PROV_KDF_EXCH_117);
                return 0;
            }
            outlen = kdfsize;
        }

        let ret = EVP_KDF_derive((*pkdfctx).kdfctx, secret, outlen, ptr::null());
        if ret <= 0 {
            return 0;
        }

        *secretlen = outlen;
        1
    }
}

/// `static void kdf_freectx(void *vpkdfctx)` — `kdf_exch.c:131-139`.
///
/// # Safety
/// The `freectx` dispatch contract.
unsafe extern "C" fn kdf_freectx(vpkdfctx: *mut c_void) {
    // SAFETY: the caller's contract.
    unsafe {
        let pkdfctx = vpkdfctx.cast::<ProvKdfCtx>();

        EVP_KDF_CTX_free((*pkdfctx).kdfctx);
        ossl_kdf_data_free((*pkdfctx).kdfdata);

        CRYPTO_free(
            pkdfctx.cast(),
            c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
            138,
        );
    }
}

/// `static void *kdf_dupctx(void *vpkdfctx)` — `kdf_exch.c:141-167`. The shallow struct copy is the
/// authority's `*dstctx = *srcctx;`, then the `EVP_KDF_CTX` is duplicated and the `KDF_DATA`
/// reference taken.
///
/// # Safety
/// The `dupctx` dispatch contract.
unsafe extern "C" fn kdf_dupctx(vpkdfctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe {
        let srcctx = vpkdfctx.cast::<ProvKdfCtx>();

        if is_running() == 0 {
            return ptr::null_mut();
        }

        let dstctx = CRYPTO_zalloc(
            core::mem::size_of::<ProvKdfCtx>(),
            c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
            149,
        )
        .cast::<ProvKdfCtx>();
        if dstctx.is_null() {
            return ptr::null_mut();
        }

        *dstctx = *srcctx;

        (*dstctx).kdfctx = EVP_KDF_CTX_dup((*srcctx).kdfctx);
        if (*dstctx).kdfctx.is_null() {
            CRYPTO_free(
                dstctx.cast(),
                c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
                157,
            );
            return ptr::null_mut();
        }
        if ossl_kdf_data_up_ref((*dstctx).kdfdata) == 0 {
            EVP_KDF_CTX_free((*dstctx).kdfctx);
            CRYPTO_free(
                dstctx.cast(),
                c"providers/implementations/exchange/kdf_exch.c".as_ptr(),
                162,
            );
            return ptr::null_mut();
        }

        dstctx.cast()
    }
}

/// `static int kdf_set_ctx_params(void *vpkdfctx, const OSSL_PARAM params[])` —
/// `kdf_exch.c:169-174`.
///
/// # Safety
/// The `set_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_set_ctx_params(vpkdfctx: *mut c_void, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let pkdfctx = vpkdfctx.cast::<ProvKdfCtx>();
        EVP_KDF_CTX_set_params((*pkdfctx).kdfctx, params)
    }
}

/// `static int kdf_get_ctx_params(void *vpkdfctx, OSSL_PARAM params[])` — `kdf_exch.c:176-181`.
///
/// # Safety
/// The `get_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_get_ctx_params(vpkdfctx: *mut c_void, params: *mut OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let pkdfctx = vpkdfctx.cast::<ProvKdfCtx>();
        EVP_KDF_CTX_get_params((*pkdfctx).kdfctx, params)
    }
}

/// `static const OSSL_PARAM *kdf_settable_ctx_params(ossl_unused void *vpkdfctx, void *provctx,
/// const char *kdfname)` — `kdf_exch.c:183-198`. The fetch is on `PROV_LIBCTX_OF(provctx)`, so the
/// parameters are the row's own.
///
/// # Safety
/// `provctx` is the caller's; `kdfname` is NUL-terminated.
unsafe fn kdf_settable_ctx_params(
    _vpkdfctx: *mut c_void,
    provctx: *mut c_void,
    kdfname: *const c_char,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe {
        let kdf = EVP_KDF_fetch(prov_libctx_of(provctx), kdfname, ptr::null());
        if kdf.is_null() {
            return ptr::null();
        }
        let params = EVP_KDF_settable_ctx_params(kdf);
        EVP_KDF_free(kdf);
        params
    }
}

/// `static const OSSL_PARAM *kdf_gettable_ctx_params(ossl_unused void *vpkdfctx, void *provctx,
/// const char *kdfname)` — `kdf_exch.c:211-226`.
///
/// # Safety
/// As [`kdf_settable_ctx_params`].
unsafe fn kdf_gettable_ctx_params(
    _vpkdfctx: *mut c_void,
    provctx: *mut c_void,
    kdfname: *const c_char,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe {
        let kdf = EVP_KDF_fetch(prov_libctx_of(provctx), kdfname, ptr::null());
        if kdf.is_null() {
            return ptr::null();
        }
        let params = EVP_KDF_gettable_ctx_params(kdf);
        EVP_KDF_free(kdf);
        params
    }
}

/// `kdf_tls1_prf_settable_ctx_params` — `kdf_exch.c:207`.
///
/// # Safety
/// The `settable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_tls1_prf_settable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_settable_ctx_params(vpkdfctx, provctx, c"TLS1-PRF".as_ptr()) }
}

/// `kdf_hkdf_settable_ctx_params` — `kdf_exch.c:208`.
///
/// # Safety
/// The `settable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_hkdf_settable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_settable_ctx_params(vpkdfctx, provctx, c"HKDF".as_ptr()) }
}

/// `kdf_scrypt_settable_ctx_params` — `kdf_exch.c:209`.
///
/// # Safety
/// The `settable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_scrypt_settable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_settable_ctx_params(vpkdfctx, provctx, c"SCRYPT".as_ptr()) }
}

/// `kdf_tls1_prf_gettable_ctx_params` — `kdf_exch.c:235`.
///
/// # Safety
/// The `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_tls1_prf_gettable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_gettable_ctx_params(vpkdfctx, provctx, c"TLS1-PRF".as_ptr()) }
}

/// `kdf_hkdf_gettable_ctx_params` — `kdf_exch.c:236`.
///
/// # Safety
/// The `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_hkdf_gettable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_gettable_ctx_params(vpkdfctx, provctx, c"HKDF".as_ptr()) }
}

/// `kdf_scrypt_gettable_ctx_params` — `kdf_exch.c:237`.
///
/// # Safety
/// The `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn kdf_scrypt_gettable_ctx_params(
    vpkdfctx: *mut c_void,
    provctx: *mut c_void,
) -> *const OsslParam {
    // SAFETY: the caller's contract.
    unsafe { kdf_gettable_ctx_params(vpkdfctx, provctx, c"SCRYPT".as_ptr()) }
}

/// `ossl_kdf_tls1_prf_keyexch_functions` — `kdf_exch.c:255` (`KDF_KEYEXCH_FUNCTIONS(tls1_prf)`).
pub(crate) static KDF_TLS1_PRF_KEYEXCH_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: kdf_tls1_prf_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: kdf_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: kdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: kdf_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: kdf_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        function: kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        function: kdf_tls1_prf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: kdf_tls1_prf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `ossl_kdf_hkdf_keyexch_functions` — `kdf_exch.c:256`.
pub(crate) static KDF_HKDF_KEYEXCH_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: kdf_hkdf_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: kdf_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: kdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: kdf_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: kdf_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        function: kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        function: kdf_hkdf_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: kdf_hkdf_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `ossl_kdf_scrypt_keyexch_functions` — `kdf_exch.c:257`.
pub(crate) static KDF_SCRYPT_KEYEXCH_FUNCTIONS: [OsslDispatch; 10] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: kdf_scrypt_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: kdf_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: kdf_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: kdf_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: kdf_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        function: kdf_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: kdf_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        function: kdf_scrypt_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: kdf_scrypt_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_keyexch[]` — `providers/defltprov.c:384-402`, **the rows this
/// module has landed**, in the authority's order. The KDF rows are the authority's last three
/// (`:395-400`); the `DH`/`ECDH`/`X25519`/`X448` rows are theirs and are not landed.
pub(crate) static DEFLT_KEYEXCH: [OsslAlgorithm; 4] = [
    OsslAlgorithm {
        // `PROV_NAMES_TLS1_PRF` — the primary name alone.
        algorithm_names: c"TLS1-PRF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_TLS1_PRF_KEYEXCH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HKDF`.
        algorithm_names: c"HKDF".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_HKDF_KEYEXCH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SCRYPT` — the OID alias is part of the row.
        algorithm_names: c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: KDF_SCRYPT_KEYEXCH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
