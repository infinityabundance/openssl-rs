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

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::ptr;

use crate::bn::bignum::BigNum;
use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::dh::kdf::ossl_dh_kdf_X9_42_asn1;
use crate::dh::key::{DH_compute_key, DH_compute_key_padded};
use crate::dh::object::{ossl_dh_get0_params, DH_free, DH_get0_key, DH_size, DH_up_ref};
use crate::dh::Dh;
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get0_name, EVP_MD_up_ref, EVP_MD_xof, EvpMd,
};
use crate::evp::exchange::{
    OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX, OSSL_FUNC_KEYEXCH_FREECTX,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX, OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SET_PEER,
};
use crate::evp::kdf::{
    EVP_KDF_CTX_dup, EVP_KDF_CTX_free, EVP_KDF_CTX_get_kdf_size, EVP_KDF_CTX_get_params,
    EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    EVP_KDF_gettable_ctx_params, EVP_KDF_settable_ctx_params, EvpKdfCtx,
};
use crate::evp::pkey_ctx::{
    OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_TYPE,
    OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_EXCHANGE_PARAM_PAD, OSSL_KDF_PARAM_CEK_ALG,
};
use crate::ffc::params::ossl_ffc_params_cmp;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate_const, OSSL_PARAM_set_octet_ptr,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string, OsslParam, END,
};
use crate::provider::activate::OsslAlgorithm;
use crate::provider::cipher::{
    param_int, param_octet_ptr, param_octet_string, param_size_t, param_utf8_string,
};
use crate::provider::ctx::prov_libctx_of;
use crate::provider::keymgmt::{ossl_kdf_data_free, ossl_kdf_data_up_ref, KdfData};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc,
};
use crate::runtime::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

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

// ---------------------------------------------------------------------------------------------
// `providers/implementations/exchange/dh_exch.c.in` — the `DH` key exchange row (D387)
//
// The `.c.in` template's two generated blocks (`dh_set_ctx_params`'s and `dh_get_ctx_params`'s
// decoders and settable/gettable lists) are transcribed the way `src/provider/mac.rs` and
// `src/provider/rand.rs` transcribe the same generated machinery: one repeated-key scan plus one
// `OSSL_PARAM_locate_const` per field. The line numbers of the generated raise sites are read from
// the **generated** `providers/implementations/exchange/dh_exch.c` in the authority's build tree,
// which is what the compiler saw, so the `PROV_DH_EXCH_*` coordinates are the authority's.
// ---------------------------------------------------------------------------------------------

/// `OSSL_KDF_NAME_X942KDF_ASN1` — `core_names.h:80`.
const OSSL_KDF_NAME_X942KDF_ASN1: *const c_char = c"X942KDF-ASN1".as_ptr();
/// `OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS` — `core_names.h:266`.
const OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS: *const c_char = c"kdf-digest-props".as_ptr();

/// `OSSL_MAX_NAME_SIZE` — the 80-byte stack name the authority's `dh_set_ctx_params` reads into.
const DH_EXCH_NAME_SIZE: usize = 80;

/// `FILE_DH_EXCH` — the generated unit's own `__FILE__`, which carries no source-tree prefix.
const FILE_DH_EXCH: *const c_char = c"providers/implementations/exchange/dh_exch.c".as_ptr();

/// `enum kdf_type` — `dh_exch.c:57-60`.
const PROV_DH_KDF_NONE: c_int = 0;
/// `PROV_DH_KDF_X9_42_ASN1`.
const PROV_DH_KDF_X9_42_ASN1: c_int = 1;

/// `PROV_DH_CTX` — `dh_exch.c:68-86`. `OSSL_FIPS_IND_DECLARE` contributes no field on this build
/// (`src/provider/mac.rs` and `src/provider/rand.rs` carry the same note), and `unsigned int pad : 1`
/// is modelled as its storage unit with every writer storing 0 or 1.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProvDhCtx {
    /// `OSSL_LIB_CTX *libctx`.
    libctx: *mut c_void,
    /// `DH *dh`.
    dh: *mut Dh,
    /// `DH *dhpeer`.
    dhpeer: *mut Dh,
    /// `unsigned int pad : 1` — the storage unit.
    pad: c_uint,
    /// `enum kdf_type kdf_type`.
    kdf_type: c_int,
    /// `EVP_MD *kdf_md`.
    kdf_md: *mut EvpMd,
    /// `unsigned char *kdf_ukm`.
    kdf_ukm: *mut u8,
    /// `size_t kdf_ukmlen`.
    kdf_ukmlen: usize,
    /// `size_t kdf_outlen`.
    kdf_outlen: usize,
    /// `char *kdf_cekalg`.
    kdf_cekalg: *mut c_char,
}

/// `static void *dh_newctx(void *provctx)` — `dh_exch.c:88-102`. The `OSSL_FIPS_IND_INIT` between
/// the two assignments is the no-op the macro expands to without `FIPS_MODULE`.
///
/// # Safety
/// The keyexch `newctx` dispatch contract.
unsafe extern "C" fn dh_newctx(provctx: *mut c_void) -> *mut c_void {
    if is_running() == 0 {
        return ptr::null_mut();
    }

    let pdhctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvDhCtx>(), FILE_DH_EXCH, 95).cast::<ProvDhCtx>();
    if pdhctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pdhctx` is this call's own allocation; `provctx` is the caller's.
    unsafe {
        (*pdhctx).libctx = prov_libctx_of(provctx);
        (*pdhctx).kdf_type = PROV_DH_KDF_NONE;
    }
    pdhctx.cast()
}

/// `static int dh_init(void *vpdhctx, void *vdh, const OSSL_PARAM params[])` —
/// `dh_exch.c:128-149`. The `#ifdef FIPS_MODULE` `dh_check_key` arm is not this profile's.
///
/// # Safety
/// The keyexch `init` dispatch contract.
unsafe extern "C" fn dh_init(
    vpdhctx: *mut c_void,
    vdh: *mut c_void,
    params: *const OsslParam,
) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    let dh = vdh.cast::<Dh>();

    // SAFETY: the caller's contract; `DH_up_ref` takes the object or NULL.
    unsafe {
        if is_running() == 0 || pdhctx.is_null() || vdh.is_null() || DH_up_ref(dh) == 0 {
            return 0;
        }
        DH_free((*pdhctx).dh);
        (*pdhctx).dh = dh;
        (*pdhctx).kdf_type = PROV_DH_KDF_NONE;

        // `OSSL_FIPS_IND_SET_APPROVED(pdhctx)` is empty without `FIPS_MODULE`.
        if dh_set_ctx_params(vpdhctx, params) == 0 {
            return 0;
        }
    }
    1
}

/// `static int dh_match_params(DH *priv, DH *peer)` — `dh_exch.c:152-167`. The independent
/// variable is `ignore_q`, which is cleared only when the private side carries a `q`.
///
/// # Safety
/// `priv` and `peer` are live objects.
unsafe fn dh_match_params(priv_: *mut Dh, peer: *mut Dh) -> c_int {
    let mut ignore_q = 1;

    // SAFETY: `priv_`/`peer` are live per the contract.
    let ret = unsafe {
        let dhparams_priv = ossl_dh_get0_params(priv_);
        let dhparams_peer = ossl_dh_get0_params(peer);

        if !dhparams_priv.is_null() && !(*dhparams_priv).q.is_null() {
            ignore_q = 0;
        }
        c_int::from(
            !dhparams_priv.is_null()
                && !dhparams_peer.is_null()
                && ossl_ffc_params_cmp(dhparams_priv, dhparams_peer, ignore_q) != 0,
        )
    };
    if ret == 0 {
        // SAFETY: a compile-time-constant site (`dh_exch.c:165`).
        unsafe { raise_site(&err_sites::PROV_DH_EXCH_163) };
    }
    ret
}

/// `static int dh_set_peer(void *vpdhctx, void *vdh)` — `dh_exch.c:169-182`.
///
/// # Safety
/// The keyexch `set_peer` dispatch contract.
unsafe extern "C" fn dh_set_peer(vpdhctx: *mut c_void, vdh: *mut c_void) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    let dh = vdh.cast::<Dh>();

    // SAFETY: the caller's contract.
    unsafe {
        if is_running() == 0
            || pdhctx.is_null()
            || vdh.is_null()
            || dh_match_params(dh, (*pdhctx).dh) == 0
            || DH_up_ref(dh) == 0
        {
            return 0;
        }
        DH_free((*pdhctx).dhpeer);
        (*pdhctx).dhpeer = dh;
    }
    1
}

/// `static int dh_plain_derive(void *vpdhctx, unsigned char *secret, size_t *secretlen,
/// size_t outlen, unsigned int pad)` — `dh_exch.c:184-218`.
///
/// # Safety
/// `vpdhctx` is a live `ProvDhCtx`; `secret` is NULL or writable for `outlen` bytes; `secretlen`
/// is writable.
unsafe fn dh_plain_derive(
    vpdhctx: *mut c_void,
    secret: *mut u8,
    secretlen: *mut usize,
    outlen: usize,
    pad: c_uint,
) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();

    // SAFETY: the caller's contract.
    unsafe {
        if (*pdhctx).dh.is_null() || (*pdhctx).dhpeer.is_null() {
            raise_site(&err_sites::PROV_DH_EXCH_192);
            return 0;
        }

        let dhsize = DH_size((*pdhctx).dh) as usize;
        if secret.is_null() {
            *secretlen = dhsize;
            return 1;
        }
        if outlen < dhsize {
            raise_site(&err_sites::PROV_DH_EXCH_202);
            return 0;
        }

        let mut pub_key: *const BigNum = ptr::null();
        DH_get0_key((*pdhctx).dhpeer, &mut pub_key, ptr::null_mut());
        let ret = if pad != 0 {
            DH_compute_key_padded(secret, pub_key, (*pdhctx).dh)
        } else {
            DH_compute_key(secret, pub_key, (*pdhctx).dh)
        };
        if ret <= 0 {
            return 0;
        }

        *secretlen = ret as usize;
    }
    1
}

/// `static int dh_X9_42_kdf_derive(void *vpdhctx, unsigned char *secret, size_t *secretlen,
/// size_t outlen)` — `dh_exch.c:220-260`.
///
/// # Safety
/// `vpdhctx` is a live `ProvDhCtx`; `secret` is NULL or writable for `outlen` bytes; `secretlen`
/// is writable.
#[allow(non_snake_case)] // the authority's own symbol name
unsafe fn dh_X9_42_kdf_derive(
    vpdhctx: *mut c_void,
    secret: *mut u8,
    secretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    let mut stmplen: usize = 0;

    // SAFETY: the caller's contract; every pointer read is a field of `pdhctx`.
    unsafe {
        if secret.is_null() {
            *secretlen = (*pdhctx).kdf_outlen;
            return 1;
        }

        if (*pdhctx).kdf_outlen > outlen {
            raise_site(&err_sites::PROV_DH_EXCH_232);
            return 0;
        }
        if dh_plain_derive(vpdhctx, ptr::null_mut(), &mut stmplen, 0, 1) == 0 {
            return 0;
        }
        let stmp = CRYPTO_secure_malloc(stmplen, FILE_DH_EXCH, 239).cast::<u8>();
        if stmp.is_null() {
            return 0;
        }
        if dh_plain_derive(vpdhctx, stmp, &mut stmplen, stmplen, 1) == 0 {
            CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_DH_EXCH, 258);
            return 0;
        }

        /* Do KDF stuff */
        if (*pdhctx).kdf_type == PROV_DH_KDF_X9_42_ASN1
            && ossl_dh_kdf_X9_42_asn1(
                secret,
                (*pdhctx).kdf_outlen,
                stmp,
                stmplen,
                (*pdhctx).kdf_cekalg,
                (*pdhctx).kdf_ukm,
                (*pdhctx).kdf_ukmlen,
                (*pdhctx).kdf_md,
                (*pdhctx).libctx,
                ptr::null(),
            ) == 0
        {
            CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_DH_EXCH, 258);
            return 0;
        }
        *secretlen = (*pdhctx).kdf_outlen;
        CRYPTO_secure_clear_free(stmp.cast(), stmplen, FILE_DH_EXCH, 258);
    }
    1
}

/// `static int dh_derive(void *vpdhctx, unsigned char *secret, size_t *psecretlen,
/// size_t outlen)` — `dh_exch.c:262-280`.
///
/// # Safety
/// The keyexch `derive` dispatch contract.
unsafe extern "C" fn dh_derive(
    vpdhctx: *mut c_void,
    secret: *mut u8,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();

    if is_running() == 0 {
        return 0;
    }

    // SAFETY: the caller's contract.
    unsafe {
        match (*pdhctx).kdf_type {
            PROV_DH_KDF_NONE => dh_plain_derive(vpdhctx, secret, psecretlen, outlen, (*pdhctx).pad),
            PROV_DH_KDF_X9_42_ASN1 => dh_X9_42_kdf_derive(vpdhctx, secret, psecretlen, outlen),
            _ => 0,
        }
    }
}

/// `static void dh_freectx(void *vpdhctx)` — `dh_exch.c:282-293`.
///
/// # Safety
/// The keyexch `freectx` dispatch contract.
unsafe extern "C" fn dh_freectx(vpdhctx: *mut c_void) {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    if pdhctx.is_null() {
        return;
    }

    // SAFETY: `pdhctx` is this provider's own context.
    unsafe {
        CRYPTO_free((*pdhctx).kdf_cekalg.cast(), FILE_DH_EXCH, 286);
        DH_free((*pdhctx).dh);
        DH_free((*pdhctx).dhpeer);
        EVP_MD_free((*pdhctx).kdf_md);
        CRYPTO_clear_free(
            (*pdhctx).kdf_ukm.cast(),
            (*pdhctx).kdf_ukmlen,
            FILE_DH_EXCH,
            290,
        );
        CRYPTO_free(pdhctx.cast(), FILE_DH_EXCH, 292);
    }
}

/// `static void *dh_dupctx(void *vpdhctx)` — `dh_exch.c:295-347`. The struct copy nulls every
/// owned pointer before each `up_ref`/duplicate, so a failure on the `err:` label releases only
/// what this call actually took.
///
/// # Safety
/// The keyexch `dupctx` dispatch contract.
unsafe extern "C" fn dh_dupctx(vpdhctx: *mut c_void) -> *mut c_void {
    let srcctx = vpdhctx.cast::<ProvDhCtx>();

    if is_running() == 0 {
        return ptr::null_mut();
    }

    let dstctx =
        CRYPTO_zalloc(core::mem::size_of::<ProvDhCtx>(), FILE_DH_EXCH, 303).cast::<ProvDhCtx>();
    if dstctx.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `srcctx` is the caller's live context and `dstctx` is this call's own.
    unsafe {
        *dstctx = *srcctx;
        (*dstctx).dh = ptr::null_mut();
        (*dstctx).dhpeer = ptr::null_mut();
        (*dstctx).kdf_md = ptr::null_mut();
        (*dstctx).kdf_ukm = ptr::null_mut();
        (*dstctx).kdf_cekalg = ptr::null_mut();

        if !(*srcctx).dh.is_null() && DH_up_ref((*srcctx).dh) == 0 {
            dh_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).dh = (*srcctx).dh;

        if !(*srcctx).dhpeer.is_null() && DH_up_ref((*srcctx).dhpeer) == 0 {
            dh_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).dhpeer = (*srcctx).dhpeer;

        if !(*srcctx).kdf_md.is_null() && EVP_MD_up_ref((*srcctx).kdf_md) == 0 {
            dh_freectx(dstctx.cast());
            return ptr::null_mut();
        }
        (*dstctx).kdf_md = (*srcctx).kdf_md;

        /* Duplicate UKM data if present */
        if !(*srcctx).kdf_ukm.is_null() && (*srcctx).kdf_ukmlen > 0 {
            (*dstctx).kdf_ukm = CRYPTO_memdup(
                (*srcctx).kdf_ukm.cast(),
                (*srcctx).kdf_ukmlen,
                FILE_DH_EXCH,
                331,
            )
            .cast();
            if (*dstctx).kdf_ukm.is_null() {
                dh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }

        if !(*srcctx).kdf_cekalg.is_null() {
            (*dstctx).kdf_cekalg = CRYPTO_strdup((*srcctx).kdf_cekalg, FILE_DH_EXCH, 338);
            if (*dstctx).kdf_cekalg.is_null() {
                dh_freectx(dstctx.cast());
                return ptr::null_mut();
            }
        }
    }
    dstctx.cast()
}

/// The repeated-key scan the two generated decoders share, keyed on the header that raised
/// (`dh_exch.c`'s generated `PROV_R_REPEATED_PARAMETER` sites).
///
/// # Safety
/// `params` is NULL or a key-terminated array.
unsafe fn dh_repeated_param_site(
    params: *const OsslParam,
    keys: &[(
        &'static crate::runtime::err::err_sites::ErrSite,
        *const c_char,
    )],
) -> Option<&'static crate::runtime::err::err_sites::ErrSite> {
    if params.is_null() {
        return None;
    }
    // SAFETY: the array is key-terminated per the contract; the walk stops at the NULL key.
    unsafe {
        let mut seen: u32 = 0;
        let mut p = params;
        while !(*p).key.is_null() {
            let k = CStr::from_ptr((*p).key).to_bytes();
            for (i, (site, name)) in keys.iter().enumerate() {
                if CStr::from_ptr(*name).to_bytes() == k {
                    let bit = 1u32 << i;
                    if seen & bit != 0 {
                        return Some(site);
                    }
                    seen |= bit;
                    break;
                }
            }
            p = p.add(1);
        }
    }
    None
}

/// `struct dh_set_ctx_params_st` — the generated `dh_exch.c:369-383`, without the two
/// `FIPS_MODULE`-only `ind_k`/`ind_d` members.
struct DhSetCtxParams {
    cekalg: *const OsslParam,
    digest: *const OsslParam,
    kdf: *const OsslParam,
    len: *const OsslParam,
    pad: *const OsslParam,
    propq: *const OsslParam,
    ukm: *const OsslParam,
}

/// `static const OSSL_PARAM dh_set_ctx_params_list[]` — generated `dh_exch.c:350-365`, with the
/// two `FIPS_MODULE`-guarded entries absent.
static DH_SET_CTX_PARAMS_LIST: [OsslParam; 8] = [
    param_int(OSSL_EXCHANGE_PARAM_PAD),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS),
    param_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    param_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM),
    param_utf8_string(OSSL_KDF_PARAM_CEK_ALG),
    END,
];

/// The set-decoder's repeated-key coordinates, from the generated `dh_exch.c`'s non-FIPS arms.
const DH_SET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 7] = [
    (&err_sites::PROV_DH_EXCH_402, OSSL_KDF_PARAM_CEK_ALG),
    (
        &err_sites::PROV_DH_EXCH_466,
        OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
    ),
    (&err_sites::PROV_DH_EXCH_475, OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    (&err_sites::PROV_DH_EXCH_491, OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    (&err_sites::PROV_DH_EXCH_502, OSSL_EXCHANGE_PARAM_KDF_TYPE),
    (&err_sites::PROV_DH_EXCH_513, OSSL_EXCHANGE_PARAM_KDF_UKM),
    (&err_sites::PROV_DH_EXCH_542, OSSL_EXCHANGE_PARAM_PAD),
];

/// `dh_set_ctx_params_decoder` — generated `dh_exch.c:386-551`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn dh_set_ctx_params_decoder(params: *const OsslParam, r: &mut DhSetCtxParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = dh_repeated_param_site(params, &DH_SET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.cekalg = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
        r.digest = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        r.kdf = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
        r.len = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        r.pad = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_PAD);
        r.propq = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
        r.ukm = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
        1
    }
}

/// `static int dh_set_ctx_params(void *vpdhctx, const OSSL_PARAM params[])` —
/// `dh_exch.c:555-660` (the generated file's numbering; the body is `dh_exch.c.in:363-467`).
///
/// # Safety
/// The keyexch `set_ctx_params` dispatch contract.
unsafe extern "C" fn dh_set_ctx_params(vpdhctx: *mut c_void, params: *const OsslParam) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    let mut p = DhSetCtxParams {
        cekalg: ptr::null(),
        digest: ptr::null(),
        kdf: ptr::null(),
        len: ptr::null(),
        pad: ptr::null(),
        propq: ptr::null(),
        ukm: ptr::null(),
    };
    let mut pad: c_uint = 0;
    let mut name = [0 as c_char; DH_EXCH_NAME_SIZE];
    let mut mdprops = [0 as c_char; DH_EXCH_NAME_SIZE];

    // SAFETY: `pdhctx` and `params` are the caller's; `name`/`mdprops` are this call's buffers.
    unsafe {
        if pdhctx.is_null() || dh_set_ctx_params_decoder(params, &mut p) == 0 {
            return 0;
        }

        // `OSSL_FIPS_IND_SET_CTX_FROM_PARAM(pdhctx, SETTABLE0, p.ind_k)` and its SETTABLE1 twin
        // are the literal 1 without `FIPS_MODULE`.

        if !p.kdf.is_null() {
            let mut str_ = name.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.kdf, &mut str_, DH_EXCH_NAME_SIZE) == 0 {
                return 0;
            }

            if name[0] == 0 {
                (*pdhctx).kdf_type = PROV_DH_KDF_NONE;
            } else if crate::runtime::bio::sys::strcmp(name.as_ptr(), OSSL_KDF_NAME_X942KDF_ASN1)
                == 0
            {
                (*pdhctx).kdf_type = PROV_DH_KDF_X9_42_ASN1;
            } else {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let mut str_ = name.as_mut_ptr();
            if OSSL_PARAM_get_utf8_string(p.digest, &mut str_, DH_EXCH_NAME_SIZE) == 0 {
                return 0;
            }

            let mut str_ = mdprops.as_mut_ptr();
            if !p.propq.is_null()
                && OSSL_PARAM_get_utf8_string(p.propq, &mut str_, DH_EXCH_NAME_SIZE) == 0
            {
                return 0;
            }

            EVP_MD_free((*pdhctx).kdf_md);
            (*pdhctx).kdf_md = EVP_MD_fetch((*pdhctx).libctx, name.as_ptr(), mdprops.as_ptr());
            if (*pdhctx).kdf_md.is_null() {
                return 0;
            }
            /* XOF digests are not allowed */
            if EVP_MD_xof((*pdhctx).kdf_md) != 0 {
                raise_site(&err_sites::PROV_DH_EXCH_603);
                return 0;
            }
        }

        if !p.len.is_null() {
            let mut outlen: usize = 0;
            if OSSL_PARAM_get_size_t(p.len, &mut outlen) == 0 {
                return 0;
            }
            (*pdhctx).kdf_outlen = outlen;
        }

        if !p.ukm.is_null() {
            let mut tmp_ukm: *mut c_void = ptr::null_mut();
            let mut tmp_ukmlen: usize = 0;

            CRYPTO_free((*pdhctx).kdf_ukm.cast(), FILE_DH_EXCH, 435);
            (*pdhctx).kdf_ukm = ptr::null_mut();
            (*pdhctx).kdf_ukmlen = 0;
            /* ukm is an optional field so it can be NULL */
            if !(*p.ukm).data.is_null() && (*p.ukm).data_size != 0 {
                if OSSL_PARAM_get_octet_string(p.ukm, &mut tmp_ukm, 0, &mut tmp_ukmlen) == 0 {
                    return 0;
                }
                (*pdhctx).kdf_ukm = tmp_ukm.cast::<u8>();
                (*pdhctx).kdf_ukmlen = tmp_ukmlen;
            }
        }

        if !p.pad.is_null() {
            if OSSL_PARAM_get_uint(p.pad, &mut pad) == 0 {
                return 0;
            }
            (*pdhctx).pad = c_uint::from(pad != 0);
        }

        if !p.cekalg.is_null() {
            CRYPTO_free((*pdhctx).kdf_cekalg.cast(), FILE_DH_EXCH, 456);
            (*pdhctx).kdf_cekalg = ptr::null_mut();
            if !(*p.cekalg).data.is_null() && (*p.cekalg).data_size != 0 {
                let mut str_ = name.as_mut_ptr();
                if OSSL_PARAM_get_utf8_string(p.cekalg, &mut str_, DH_EXCH_NAME_SIZE) == 0 {
                    return 0;
                }
                (*pdhctx).kdf_cekalg = CRYPTO_strdup(name.as_ptr(), FILE_DH_EXCH, 461);
                if (*pdhctx).kdf_cekalg.is_null() {
                    return 0;
                }
            }
        }
    }
    1
}

/// `static const OSSL_PARAM *dh_settable_ctx_params(...)` — `dh_exch.c:661-665`.
///
/// # Safety
/// The keyexch `settable_ctx_params` dispatch contract.
unsafe extern "C" fn dh_settable_ctx_params(
    _vpdhctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DH_SET_CTX_PARAMS_LIST.as_ptr()
}

/// `struct dh_get_ctx_params_st` — the generated `dh_exch.c:683-694`, without the
/// `FIPS_MODULE`-only `ind` member.
struct DhGetCtxParams {
    cekalg: *const OsslParam,
    digest: *const OsslParam,
    kdf: *const OsslParam,
    len: *const OsslParam,
    ukm: *const OsslParam,
}

/// `static const OSSL_PARAM dh_get_ctx_params_list[]` — generated `dh_exch.c:670-680`, with the
/// `FIPS_MODULE`-guarded entry absent.
static DH_GET_CTX_PARAMS_LIST: [OsslParam; 6] = [
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE),
    param_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    param_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    param_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM),
    param_utf8_string(OSSL_KDF_PARAM_CEK_ALG),
    END,
];

/// The get-decoder's repeated-key coordinates, from the generated `dh_exch.c`'s non-FIPS arms.
const DH_GET_PARAMS_DECODER_KEYS: [(&err_sites::ErrSite, *const c_char); 5] = [
    (&err_sites::PROV_DH_EXCH_712, OSSL_KDF_PARAM_CEK_ALG),
    (&err_sites::PROV_DH_EXCH_752, OSSL_EXCHANGE_PARAM_KDF_DIGEST),
    (&err_sites::PROV_DH_EXCH_763, OSSL_EXCHANGE_PARAM_KDF_OUTLEN),
    (&err_sites::PROV_DH_EXCH_774, OSSL_EXCHANGE_PARAM_KDF_TYPE),
    (&err_sites::PROV_DH_EXCH_785, OSSL_EXCHANGE_PARAM_KDF_UKM),
];

/// `dh_get_ctx_params_decoder` — generated `dh_exch.c:696-798`.
///
/// # Safety
/// `params` is NULL or key-terminated; `r` is writable.
unsafe fn dh_get_ctx_params_decoder(params: *const OsslParam, r: &mut DhGetCtxParams) -> c_int {
    // SAFETY: the arguments are per the contract.
    unsafe {
        if let Some(site) = dh_repeated_param_site(params, &DH_GET_PARAMS_DECODER_KEYS) {
            raise_site(site);
            return 0;
        }
        r.cekalg = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
        r.digest = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        r.kdf = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
        r.len = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        r.ukm = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
        1
    }
}

/// `static const OSSL_PARAM *dh_gettable_ctx_params(...)` — `dh_exch.c:802-806`.
///
/// # Safety
/// The keyexch `gettable_ctx_params` dispatch contract.
unsafe extern "C" fn dh_gettable_ctx_params(
    _vpdhctx: *mut c_void,
    _provctx: *mut c_void,
) -> *const OsslParam {
    DH_GET_CTX_PARAMS_LIST.as_ptr()
}

/// `static int dh_get_ctx_params(void *vpdhctx, OSSL_PARAM params[])` — `dh_exch.c:808-849`.
///
/// # Safety
/// The keyexch `get_ctx_params` dispatch contract.
unsafe extern "C" fn dh_get_ctx_params(vpdhctx: *mut c_void, params: *mut OsslParam) -> c_int {
    let pdhctx = vpdhctx.cast::<ProvDhCtx>();
    let mut p = DhGetCtxParams {
        cekalg: ptr::null(),
        digest: ptr::null(),
        kdf: ptr::null(),
        len: ptr::null(),
        ukm: ptr::null(),
    };

    // SAFETY: `pdhctx` and `params` are the caller's.
    unsafe {
        if pdhctx.is_null() || dh_get_ctx_params_decoder(params.cast_const(), &mut p) == 0 {
            return 0;
        }

        if !p.kdf.is_null() {
            let kdf_type: *const c_char = match (*pdhctx).kdf_type {
                PROV_DH_KDF_NONE => c"".as_ptr(),
                PROV_DH_KDF_X9_42_ASN1 => OSSL_KDF_NAME_X942KDF_ASN1,
                _ => return 0,
            };

            if OSSL_PARAM_set_utf8_string(p.kdf.cast_mut(), kdf_type) == 0 {
                return 0;
            }
        }

        if !p.digest.is_null() {
            let name = if (*pdhctx).kdf_md.is_null() {
                c"".as_ptr()
            } else {
                EVP_MD_get0_name((*pdhctx).kdf_md)
            };
            if OSSL_PARAM_set_utf8_string(p.digest.cast_mut(), name) == 0 {
                return 0;
            }
        }

        if !p.len.is_null() && OSSL_PARAM_set_size_t(p.len.cast_mut(), (*pdhctx).kdf_outlen) == 0 {
            return 0;
        }

        if !p.ukm.is_null()
            && OSSL_PARAM_set_octet_ptr(
                p.ukm.cast_mut(),
                (*pdhctx).kdf_ukm.cast(),
                (*pdhctx).kdf_ukmlen,
            ) == 0
        {
            return 0;
        }

        if !p.cekalg.is_null() {
            let alg = if (*pdhctx).kdf_cekalg.is_null() {
                c"".as_ptr()
            } else {
                (*pdhctx).kdf_cekalg
            };
            if OSSL_PARAM_set_utf8_string(p.cekalg.cast_mut(), alg) == 0 {
                return 0;
            }
        }

        // `OSSL_FIPS_IND_GET_CTX_FROM_PARAM(pdhctx, p.ind)` is the literal 1 here.
    }
    1
}

/// `const OSSL_DISPATCH ossl_dh_keyexch_functions[]` — `dh_exch.c:851-865` (the generated
/// file's numbering). Ten slots, the authority's, in its order.
pub(crate) static DH_KEYEXCH_FUNCTIONS: [OsslDispatch; 11] = [
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_NEWCTX,
        function: dh_newctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_INIT,
        function: dh_init as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DERIVE,
        function: dh_derive as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_PEER,
        function: dh_set_peer as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_FREECTX,
        function: dh_freectx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_DUPCTX,
        function: dh_dupctx as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        function: dh_set_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        function: dh_settable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        function: dh_get_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        function: dh_gettable_ctx_params as *mut c_void,
    },
    OsslDispatch {
        function_id: OSSL_DISPATCH_END,
        function: ptr::null_mut(),
    },
];

/// `static const OSSL_ALGORITHM deflt_keyexch[]` — `providers/defltprov.c:384-402`, **the rows
/// this module has landed**, in the authority's order. The `DH` row is the authority's first
/// (`:386`); the KDF rows are its last three (`:395-400`); the `ECDH`/`X25519`/`X448` rows are
/// theirs and are not landed. The order matters beyond fidelity: the census requires the crate's
/// rows to be a **subsequence** of the authority's, so `DH` must precede the KDF trio.
pub(crate) static DEFLT_KEYEXCH: [OsslAlgorithm; 5] = [
    OsslAlgorithm {
        // `PROV_NAMES_DH`.
        algorithm_names: c"DH:dhKeyAgreement:1.2.840.113549.1.3.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DH_KEYEXCH_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
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
