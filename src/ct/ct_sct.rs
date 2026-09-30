//! `crypto/ct/ct_sct.c` — the `SCT` object, its accessors, and single/list validation. Phase
//! 10.14.15's CT layer.
//!
//! `crypto/ct/ct_sct.c` is 385 lines and transcribes whole. It owns the `SCT` structure
//! (`crypto/ct/ct_local.h:58-84`), every one of its setters and getters, `SCT_free`/`SCT_LIST_free`,
//! the two completeness predicates the internal header declares (so they are **not** exports), and
//! `SCT_validate`/`SCT_LIST_validate` over the policy-evaluation context.
//!
//! The unit defines the `CT_V1_HASHLEN` (`include/openssl/ct.h.in:42`) and
//! `SCT_VERSION_*`/`CT_LOG_ENTRY_TYPE_*`/`SCT_SOURCE_*`/`SCT_VALIDATION_STATUS_*` values
//! (`ct.h.in:51-76`) as module-local constants, so the sibling CT units reach them by path rather
//! than by a second copy.
//!
//! **Withheld by name**: none. Every function of `ct_sct.c` lands, and the file needs no helper
//! absent from the crate (`X509_get0_pubkey`, `X509_PUBKEY_set`/`_free`, `EVP_PKEY_free` and the
//! `SCT_CTX_*`/`CTLOG_*` siblings are all present).
//!
//! ## The raise sites
//!
//! `crypto/ct/ct_sct.c` is not an entry in `gen_err_raise_sites.py`, so its five coordinates are
//! **declared locally**, their reason values read from the authority's `include/openssl/cterr.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_uchar, c_void, CStr};
use core::ptr;

use crate::ct::ct_log::{CTLOG_STORE_get0_log_by_id, CTLOG_get0_public_key, Ctlog};
use crate::ct::ct_policy::CtPolicyEvalCtx;
use crate::ct::ct_sct_ctx::{
    SCT_CTX_free, SCT_CTX_new, SCT_CTX_set1_cert, SCT_CTX_set1_issuer_pubkey, SCT_CTX_set1_pubkey,
    SCT_CTX_set_time, SctCtx,
};
use crate::ct::ct_vfy::SCT_CTX_verify;
use crate::evp::pkey::EvpPkey;
use crate::runtime::err::err_reasons::{
    CT_R_INVALID_LOG_ID_LENGTH, CT_R_UNRECOGNIZED_SIGNATURE_NID, CT_R_UNSUPPORTED_ENTRY_TYPE,
    CT_R_UNSUPPORTED_VERSION,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc};
use crate::runtime::obj::{NID_ecdsa_with_SHA256, NID_sha256WithRSAEncryption, NID_undef};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x_pubkey::{X509Pubkey, X509_PUBKEY_free, X509_PUBKEY_set};

/// `ERR_LIB_CT` — `include/openssl/err.h.in:115`.
const ERR_LIB_CT: c_int = 50;

/// `CT_V1_HASHLEN` — `include/openssl/ct.h.in:42`, `SHA256_DIGEST_LENGTH`.
pub(crate) const CT_V1_HASHLEN: usize = 32;

/// `SCT_VERSION_NOT_SET` — `include/openssl/ct.h.in:58`.
pub(crate) const SCT_VERSION_NOT_SET: c_int = -1;
/// `SCT_VERSION_V1` — `include/openssl/ct.h.in:59`.
pub(crate) const SCT_VERSION_V1: c_int = 0;

/// `CT_LOG_ENTRY_TYPE_NOT_SET` — `include/openssl/ct.h.in:52`.
pub(crate) const CT_LOG_ENTRY_TYPE_NOT_SET: c_int = -1;
/// `CT_LOG_ENTRY_TYPE_X509` — `include/openssl/ct.h.in:53`.
pub(crate) const CT_LOG_ENTRY_TYPE_X509: c_int = 0;
/// `CT_LOG_ENTRY_TYPE_PRECERT` — `include/openssl/ct.h.in:54`.
pub(crate) const CT_LOG_ENTRY_TYPE_PRECERT: c_int = 1;

/// `SCT_SOURCE_UNKNOWN` — `include/openssl/ct.h.in:63`.
#[allow(dead_code)] // the wildcard arm of `SCT_set_source` already answers this value
pub(crate) const SCT_SOURCE_UNKNOWN: c_int = 0;
/// `SCT_SOURCE_TLS_EXTENSION` — `include/openssl/ct.h.in:64`.
pub(crate) const SCT_SOURCE_TLS_EXTENSION: c_int = 1;
/// `SCT_SOURCE_X509V3_EXTENSION` — `include/openssl/ct.h.in:65`.
pub(crate) const SCT_SOURCE_X509V3_EXTENSION: c_int = 2;
/// `SCT_SOURCE_OCSP_STAPLED_RESPONSE` — `include/openssl/ct.h.in:66`.
pub(crate) const SCT_SOURCE_OCSP_STAPLED_RESPONSE: c_int = 3;

/// `SCT_VALIDATION_STATUS_NOT_SET` — `include/openssl/ct.h.in:70`.
pub(crate) const SCT_VALIDATION_STATUS_NOT_SET: c_int = 0;
/// `SCT_VALIDATION_STATUS_UNKNOWN_LOG` — `include/openssl/ct.h.in:71`.
pub(crate) const SCT_VALIDATION_STATUS_UNKNOWN_LOG: c_int = 1;
/// `SCT_VALIDATION_STATUS_VALID` — `include/openssl/ct.h.in:72`.
pub(crate) const SCT_VALIDATION_STATUS_VALID: c_int = 2;
/// `SCT_VALIDATION_STATUS_INVALID` — `include/openssl/ct.h.in:73`.
pub(crate) const SCT_VALIDATION_STATUS_INVALID: c_int = 3;
/// `SCT_VALIDATION_STATUS_UNVERIFIED` — `include/openssl/ct.h.in:74`.
pub(crate) const SCT_VALIDATION_STATUS_UNVERIFIED: c_int = 4;
/// `SCT_VALIDATION_STATUS_UNKNOWN_VERSION` — `include/openssl/ct.h.in:75`.
pub(crate) const SCT_VALIDATION_STATUS_UNKNOWN_VERSION: c_int = 5;

/// `TLSEXT_hash_sha256` — `include/openssl/tls1.h:198`.
const TLSEXT_hash_sha256: c_uchar = 4;
/// `TLSEXT_signature_rsa` — `include/openssl/tls1.h:184`.
const TLSEXT_signature_rsa: c_uchar = 1;
/// `TLSEXT_signature_ecdsa` — `include/openssl/tls1.h:186`.
const TLSEXT_signature_ecdsa: c_uchar = 3;

/// One `ct_sct.c` raise coordinate, declared locally (see the module doc).
const fn ct_sct_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ct/ct_sct.c",
        line,
        func,
        lib: ERR_LIB_CT,
        reason,
        dynamic_reason: false,
    }
}

/// `SCT_set_version` at `crypto/ct/ct_sct.c:54`.
const CT_SCT_54: ErrSite = ct_sct_site(54, c"SCT_set_version", CT_R_UNSUPPORTED_VERSION);
/// `SCT_set_log_entry_type` at `crypto/ct/ct_sct.c:74`.
const CT_SCT_74: ErrSite = ct_sct_site(74, c"SCT_set_log_entry_type", CT_R_UNSUPPORTED_ENTRY_TYPE);
/// `SCT_set0_log_id` at `crypto/ct/ct_sct.c:81`.
const CT_SCT_81: ErrSite = ct_sct_site(81, c"SCT_set0_log_id", CT_R_INVALID_LOG_ID_LENGTH);
/// `SCT_set1_log_id` at `crypto/ct/ct_sct.c:95`.
const CT_SCT_95: ErrSite = ct_sct_site(95, c"SCT_set1_log_id", CT_R_INVALID_LOG_ID_LENGTH);
/// `SCT_set_signature_nid` at `crypto/ct/ct_sct.c:133`.
const CT_SCT_133: ErrSite = ct_sct_site(
    133,
    c"SCT_set_signature_nid",
    CT_R_UNRECOGNIZED_SIGNATURE_NID,
);

/// `struct sct_st` — `SCT`, from `crypto/ct/ct_local.h:58-84`.
#[repr(C)]
pub struct Sct {
    /// `sct_version_t version`.
    pub(crate) version: c_int,
    /// `unsigned char *sct` — the cached encoding when `version` is not `V1`.
    pub(crate) sct: *mut c_uchar,
    /// `size_t sct_len`.
    pub(crate) sct_len: usize,
    /// `unsigned char *log_id`.
    pub(crate) log_id: *mut c_uchar,
    /// `size_t log_id_len`.
    pub(crate) log_id_len: usize,
    /// `uint64_t timestamp` — epoch milliseconds.
    pub(crate) timestamp: u64,
    /// `unsigned char *ext`.
    pub(crate) ext: *mut c_uchar,
    /// `size_t ext_len`.
    pub(crate) ext_len: usize,
    /// `unsigned char hash_alg`.
    pub(crate) hash_alg: c_uchar,
    /// `unsigned char sig_alg`.
    pub(crate) sig_alg: c_uchar,
    /// `unsigned char *sig`.
    pub(crate) sig: *mut c_uchar,
    /// `size_t sig_len`.
    pub(crate) sig_len: usize,
    /// `ct_log_entry_type_t entry_type`.
    pub(crate) entry_type: c_int,
    /// `sct_source_t source`.
    pub(crate) source: c_int,
    /// `sct_validation_status_t validation_status`.
    pub(crate) validation_status: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<Sct>() == 104);
    assert!(core::mem::offset_of!(Sct, version) == 0);
    assert!(core::mem::offset_of!(Sct, sct) == 8);
    assert!(core::mem::offset_of!(Sct, sct_len) == 16);
    assert!(core::mem::offset_of!(Sct, log_id) == 24);
    assert!(core::mem::offset_of!(Sct, log_id_len) == 32);
    assert!(core::mem::offset_of!(Sct, timestamp) == 40);
    assert!(core::mem::offset_of!(Sct, ext) == 48);
    assert!(core::mem::offset_of!(Sct, ext_len) == 56);
    assert!(core::mem::offset_of!(Sct, hash_alg) == 64);
    assert!(core::mem::offset_of!(Sct, sig_alg) == 65);
    assert!(core::mem::offset_of!(Sct, sig) == 72);
    assert!(core::mem::offset_of!(Sct, sig_len) == 80);
    assert!(core::mem::offset_of!(Sct, entry_type) == 88);
    assert!(core::mem::offset_of!(Sct, source) == 92);
    assert!(core::mem::offset_of!(Sct, validation_status) == 96);
};

/// `SCT *SCT_new(void)` — `crypto/ct/ct_sct.c:22-32`.
#[no_mangle]
pub extern "C" fn SCT_new() -> *mut Sct {
    let sct = CRYPTO_zalloc(core::mem::size_of::<Sct>(), ptr::null(), 0).cast::<Sct>();
    if sct.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `sct` is a fresh zeroed allocation of exactly `Sct`.
    unsafe {
        (*sct).entry_type = CT_LOG_ENTRY_TYPE_NOT_SET;
        (*sct).version = SCT_VERSION_NOT_SET;
    }
    sct
}

/// `void SCT_free(SCT *sct)` — `crypto/ct/ct_sct.c:34-44`.
///
/// # Safety
///
/// `sct` is NULL or a live `SCT` this crate's item layer owns and that is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn SCT_free(sct: *mut Sct) {
    if sct.is_null() {
        return;
    }
    // SAFETY: `sct` is live per the contract; each field is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).log_id.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sct).ext.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sct).sig.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free((*sct).sct.cast::<c_void>(), ptr::null(), 0);
        CRYPTO_free(sct.cast::<c_void>(), ptr::null(), 0);
    }
}

/// `void sct_free_void(void *p)` — the `FreeFn` thunk `SCT_LIST_free` installs.
///
/// # Safety
///
/// `p` is NULL or a live `SCT` the stack owns.
unsafe extern "C" fn sct_free_void(p: *mut c_void) {
    // SAFETY: the stack holds `SCT *` elements per the contract.
    unsafe { SCT_free(p.cast::<Sct>()) };
}

/// `void SCT_LIST_free(STACK_OF(SCT) *a)` — `crypto/ct/ct_sct.c:46-49`.
///
/// # Safety
///
/// `a` is NULL or a live `STACK_OF(SCT)` this crate owns.
#[no_mangle]
pub unsafe extern "C" fn SCT_LIST_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live stack of `SCT` pointers per the contract.
    unsafe { OPENSSL_sk_pop_free(a, Some(sct_free_void)) };
}

/// `int SCT_set_version(SCT *sct, sct_version_t version)` — `crypto/ct/ct_sct.c:51-60`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_set_version(sct: *mut Sct, version: c_int) -> c_int {
    if version != SCT_VERSION_V1 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_SCT_54) };
        return 0;
    }
    // SAFETY: `sct` is live per the contract.
    unsafe {
        (*sct).version = version;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    1
}

/// `int SCT_set_log_entry_type(SCT *sct, ct_log_entry_type_t entry_type)` —
/// `crypto/ct/ct_sct.c:62-76`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_set_log_entry_type(sct: *mut Sct, entry_type: c_int) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET };
    match entry_type {
        CT_LOG_ENTRY_TYPE_X509 | CT_LOG_ENTRY_TYPE_PRECERT => {
            // SAFETY: `sct` is live per the contract.
            unsafe { (*sct).entry_type = entry_type };
            1
        }
        CT_LOG_ENTRY_TYPE_NOT_SET => {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_SCT_74) };
            0
        }
        _ => {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_SCT_74) };
            0
        }
    }
}

/// `int SCT_set0_log_id(SCT *sct, unsigned char *log_id, size_t log_id_len)` —
/// `crypto/ct/ct_sct.c:78-90`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `log_id` is NULL or an owned block this call takes over.
#[no_mangle]
pub unsafe extern "C" fn SCT_set0_log_id(
    sct: *mut Sct,
    log_id: *mut c_uchar,
    log_id_len: usize,
) -> c_int {
    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } == SCT_VERSION_V1 && log_id_len != CT_V1_HASHLEN {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_SCT_81) };
        return 0;
    }
    // SAFETY: `sct` is live; its old `log_id` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).log_id.cast::<c_void>(), ptr::null(), 0);
        (*sct).log_id = log_id;
        (*sct).log_id_len = log_id_len;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    1
}

/// `int SCT_set1_log_id(SCT *sct, const unsigned char *log_id, size_t log_id_len)` —
/// `crypto/ct/ct_sct.c:92-111`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `log_id` is NULL or readable for `log_id_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SCT_set1_log_id(
    sct: *mut Sct,
    log_id: *const c_uchar,
    log_id_len: usize,
) -> c_int {
    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } == SCT_VERSION_V1 && log_id_len != CT_V1_HASHLEN {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&CT_SCT_95) };
        return 0;
    }
    // SAFETY: `sct` is live; its old `log_id` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).log_id.cast::<c_void>(), ptr::null(), 0);
        (*sct).log_id = ptr::null_mut();
        (*sct).log_id_len = 0;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    if !log_id.is_null() && log_id_len > 0 {
        // SAFETY: `log_id` is readable for `log_id_len` bytes per the contract.
        let dup = unsafe { CRYPTO_memdup(log_id.cast::<c_void>(), log_id_len, ptr::null(), 0) }
            .cast::<c_uchar>();
        if dup.is_null() {
            return 0;
        }
        // SAFETY: `sct` is live; `dup` is the fresh copy this call owns.
        unsafe {
            (*sct).log_id = dup;
            (*sct).log_id_len = log_id_len;
        }
    }
    1
}

/// `void SCT_set_timestamp(SCT *sct, uint64_t timestamp)` — `crypto/ct/ct_sct.c:113-117`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_set_timestamp(sct: *mut Sct, timestamp: u64) {
    // SAFETY: `sct` is live per the contract.
    unsafe {
        (*sct).timestamp = timestamp;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
}

/// `int SCT_set_signature_nid(SCT *sct, int nid)` — `crypto/ct/ct_sct.c:119-136`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_set_signature_nid(sct: *mut Sct, nid: c_int) -> c_int {
    match nid {
        NID_sha256WithRSAEncryption => {
            // SAFETY: `sct` is live per the contract.
            unsafe {
                (*sct).hash_alg = TLSEXT_hash_sha256;
                (*sct).sig_alg = TLSEXT_signature_rsa;
                (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
            }
            1
        }
        NID_ecdsa_with_SHA256 => {
            // SAFETY: `sct` is live per the contract.
            unsafe {
                (*sct).hash_alg = TLSEXT_hash_sha256;
                (*sct).sig_alg = TLSEXT_signature_ecdsa;
                (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
            }
            1
        }
        _ => {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&CT_SCT_133) };
            0
        }
    }
}

/// `void SCT_set0_extensions(SCT *sct, unsigned char *ext, size_t ext_len)` —
/// `crypto/ct/ct_sct.c:138-144`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `ext` is NULL or an owned block this call takes over.
#[no_mangle]
pub unsafe extern "C" fn SCT_set0_extensions(sct: *mut Sct, ext: *mut c_uchar, ext_len: usize) {
    // SAFETY: `sct` is live; its old `ext` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).ext.cast::<c_void>(), ptr::null(), 0);
        (*sct).ext = ext;
        (*sct).ext_len = ext_len;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
}

/// `int SCT_set1_extensions(SCT *sct, const unsigned char *ext, size_t ext_len)` —
/// `crypto/ct/ct_sct.c:146-160`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `ext` is NULL or readable for `ext_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SCT_set1_extensions(
    sct: *mut Sct,
    ext: *const c_uchar,
    ext_len: usize,
) -> c_int {
    // SAFETY: `sct` is live; its old `ext` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).ext.cast::<c_void>(), ptr::null(), 0);
        (*sct).ext = ptr::null_mut();
        (*sct).ext_len = 0;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    if !ext.is_null() && ext_len > 0 {
        // SAFETY: `ext` is readable for `ext_len` bytes per the contract.
        let dup = unsafe { CRYPTO_memdup(ext.cast::<c_void>(), ext_len, ptr::null(), 0) }
            .cast::<c_uchar>();
        if dup.is_null() {
            return 0;
        }
        // SAFETY: `sct` is live; `dup` is the fresh copy this call owns.
        unsafe {
            (*sct).ext = dup;
            (*sct).ext_len = ext_len;
        }
    }
    1
}

/// `void SCT_set0_signature(SCT *sct, unsigned char *sig, size_t sig_len)` —
/// `crypto/ct/ct_sct.c:162-168`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `sig` is NULL or an owned block this call takes over.
#[no_mangle]
pub unsafe extern "C" fn SCT_set0_signature(sct: *mut Sct, sig: *mut c_uchar, sig_len: usize) {
    // SAFETY: `sct` is live; its old `sig` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).sig.cast::<c_void>(), ptr::null(), 0);
        (*sct).sig = sig;
        (*sct).sig_len = sig_len;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
}

/// `int SCT_set1_signature(SCT *sct, const unsigned char *sig, size_t sig_len)` —
/// `crypto/ct/ct_sct.c:170-184`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `sig` is NULL or readable for `sig_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SCT_set1_signature(
    sct: *mut Sct,
    sig: *const c_uchar,
    sig_len: usize,
) -> c_int {
    // SAFETY: `sct` is live; its old `sig` is NULL or an owned block.
    unsafe {
        CRYPTO_free((*sct).sig.cast::<c_void>(), ptr::null(), 0);
        (*sct).sig = ptr::null_mut();
        (*sct).sig_len = 0;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    if !sig.is_null() && sig_len > 0 {
        // SAFETY: `sig` is readable for `sig_len` bytes per the contract.
        let dup = unsafe { CRYPTO_memdup(sig.cast::<c_void>(), sig_len, ptr::null(), 0) }
            .cast::<c_uchar>();
        if dup.is_null() {
            return 0;
        }
        // SAFETY: `sct` is live; `dup` is the fresh copy this call owns.
        unsafe {
            (*sct).sig = dup;
            (*sct).sig_len = sig_len;
        }
    }
    1
}

/// `sct_version_t SCT_get_version(const SCT *sct)` — `crypto/ct/ct_sct.c:186-189`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_version(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).version }
}

/// `ct_log_entry_type_t SCT_get_log_entry_type(const SCT *sct)` —
/// `crypto/ct/ct_sct.c:191-194`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_log_entry_type(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).entry_type }
}

/// `size_t SCT_get0_log_id(const SCT *sct, unsigned char **log_id)` —
/// `crypto/ct/ct_sct.c:196-200`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `log_id` is writable.
#[no_mangle]
pub unsafe extern "C" fn SCT_get0_log_id(sct: *const Sct, log_id: *mut *mut c_uchar) -> usize {
    // SAFETY: `sct` is live and `log_id` is writable per the contract.
    unsafe {
        *log_id = (*sct).log_id;
        (*sct).log_id_len
    }
}

/// `uint64_t SCT_get_timestamp(const SCT *sct)` — `crypto/ct/ct_sct.c:202-205`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_timestamp(sct: *const Sct) -> u64 {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).timestamp }
}

/// `int SCT_get_signature_nid(const SCT *sct)` — `crypto/ct/ct_sct.c:207-222`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_signature_nid(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe {
        if (*sct).version == SCT_VERSION_V1 && (*sct).hash_alg == TLSEXT_hash_sha256 {
            return match (*sct).sig_alg {
                TLSEXT_signature_ecdsa => NID_ecdsa_with_SHA256,
                TLSEXT_signature_rsa => NID_sha256WithRSAEncryption,
                _ => NID_undef,
            };
        }
    }
    NID_undef
}

/// `size_t SCT_get0_extensions(const SCT *sct, unsigned char **ext)` —
/// `crypto/ct/ct_sct.c:224-228`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `ext` is writable.
#[no_mangle]
pub unsafe extern "C" fn SCT_get0_extensions(sct: *const Sct, ext: *mut *mut c_uchar) -> usize {
    // SAFETY: `sct` is live and `ext` is writable per the contract.
    unsafe {
        *ext = (*sct).ext;
        (*sct).ext_len
    }
}

/// `size_t SCT_get0_signature(const SCT *sct, unsigned char **sig)` —
/// `crypto/ct/ct_sct.c:230-234`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `sig` is writable.
#[no_mangle]
pub unsafe extern "C" fn SCT_get0_signature(sct: *const Sct, sig: *mut *mut c_uchar) -> usize {
    // SAFETY: `sct` is live and `sig` is writable per the contract.
    unsafe {
        *sig = (*sct).sig;
        (*sct).sig_len
    }
}

/// `int SCT_is_complete(const SCT *sct)` — `crypto/ct/ct_sct.c:236-246`.
///
/// Declared in `crypto/ct/ct_local.h:184`, not in `include/openssl/ct.h`, so it is **not** an
/// export and carries no `#[no_mangle]`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
pub(crate) unsafe fn SCT_is_complete(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    match unsafe { (*sct).version } {
        SCT_VERSION_NOT_SET => 0,
        SCT_VERSION_V1 => {
            // SAFETY: `sct` is live per the contract.
            let log_id_ok = unsafe { !(*sct).log_id.is_null() };
            // SAFETY: `sct` is live per the contract.
            let sig_ok = unsafe { SCT_signature_is_complete(sct) } != 0;
            if log_id_ok && sig_ok {
                1
            } else {
                0
            }
        }
        // SAFETY: "Just need cached encoding".
        _ => (unsafe { !(*sct).sct.is_null() }) as c_int,
    }
}

/// `int SCT_signature_is_complete(const SCT *sct)` — `crypto/ct/ct_sct.c:248-251`.
///
/// Declared in `crypto/ct/ct_local.h:192`, so it is **not** an export.
///
/// # Safety
///
/// `sct` is a live `SCT`.
pub(crate) unsafe fn SCT_signature_is_complete(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe {
        let nid_ok = SCT_get_signature_nid(sct) != NID_undef;
        (nid_ok && !(*sct).sig.is_null() && (*sct).sig_len > 0) as c_int
    }
}

/// `sct_source_t SCT_get_source(const SCT *sct)` — `crypto/ct/ct_sct.c:253-256`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_source(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).source }
}

/// `int SCT_set_source(SCT *sct, sct_source_t source)` — `crypto/ct/ct_sct.c:258-273`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_set_source(sct: *mut Sct, source: c_int) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe {
        (*sct).source = source;
        (*sct).validation_status = SCT_VALIDATION_STATUS_NOT_SET;
    }
    match source {
        SCT_SOURCE_TLS_EXTENSION | SCT_SOURCE_OCSP_STAPLED_RESPONSE => {
            // SAFETY: `sct` is live per the contract.
            unsafe { SCT_set_log_entry_type(sct, CT_LOG_ENTRY_TYPE_X509) }
        }
        SCT_SOURCE_X509V3_EXTENSION => {
            // SAFETY: `sct` is live per the contract.
            unsafe { SCT_set_log_entry_type(sct, CT_LOG_ENTRY_TYPE_PRECERT) }
        }
        // "if we aren't sure, leave the log entry type alone".
        _ => 1,
    }
}

/// `sct_validation_status_t SCT_get_validation_status(const SCT *sct)` —
/// `crypto/ct/ct_sct.c:275-278`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_get_validation_status(sct: *const Sct) -> c_int {
    // SAFETY: `sct` is live per the contract.
    unsafe { (*sct).validation_status }
}

/// `int SCT_validate(SCT *sct, const CT_POLICY_EVAL_CTX *ctx)` — `crypto/ct/ct_sct.c:280-363`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `ctx` is a live `CT_POLICY_EVAL_CTX`. `ctx`'s `cert`, `issuer` and
/// `log_store` are live as their owning APIs require.
#[no_mangle]
pub unsafe extern "C" fn SCT_validate(sct: *mut Sct, ctx: *const CtPolicyEvalCtx) -> c_int {
    let mut is_sct_valid: c_int = -1;
    let sctx: *mut SctCtx;
    let mut pub_: *mut X509Pubkey = ptr::null_mut();
    let mut log_pkey: *mut X509Pubkey = ptr::null_mut();

    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } != SCT_VERSION_V1 {
        // SAFETY: `sct` is live per the contract.
        unsafe { (*sct).validation_status = SCT_VALIDATION_STATUS_UNKNOWN_VERSION };
        return 0;
    }

    // SAFETY: `ctx` and its `log_store` are live per the contract.
    let log: *const Ctlog =
        unsafe { CTLOG_STORE_get0_log_by_id((*ctx).log_store, (*sct).log_id, (*sct).log_id_len) };

    if log.is_null() {
        // SAFETY: `sct` is live per the contract.
        unsafe { (*sct).validation_status = SCT_VALIDATION_STATUS_UNKNOWN_LOG };
        return 0;
    }

    'blk: {
        // SAFETY: `ctx` is live per the contract.
        sctx = unsafe { SCT_CTX_new((*ctx).libctx, (*ctx).propq) };
        if sctx.is_null() {
            break 'blk;
        }
        // SAFETY: `log` is live; `&mut log_pkey` is a writable slot.
        if unsafe { X509_PUBKEY_set(&mut log_pkey, CTLOG_get0_public_key(log)) } != 1 {
            break 'blk;
        }
        // SAFETY: `sctx` is live and `log_pkey` is the wrapper this call built.
        if unsafe { SCT_CTX_set1_pubkey(sctx, log_pkey) } != 1 {
            break 'blk;
        }

        // SAFETY: `sct` is live per the contract.
        if unsafe { SCT_get_log_entry_type(sct) } == CT_LOG_ENTRY_TYPE_PRECERT {
            // SAFETY: `ctx` is live per the contract.
            if unsafe { (*ctx).issuer.is_null() } {
                // SAFETY: `sct` is live per the contract.
                unsafe { (*sct).validation_status = SCT_VALIDATION_STATUS_UNVERIFIED };
                is_sct_valid = 0;
                break 'blk;
            }
            // SAFETY: `ctx` and its `issuer` are live per the contract.
            let issuer_pkey: *mut EvpPkey = unsafe { X509_get0_pubkey((*ctx).issuer) };
            // SAFETY: `&mut pub_` is a writable slot and `issuer_pkey` is live or NULL.
            if unsafe { X509_PUBKEY_set(&mut pub_, issuer_pkey) } != 1 {
                break 'blk;
            }
            // SAFETY: `sctx` is live and `pub_` is the wrapper this call built.
            if unsafe { SCT_CTX_set1_issuer_pubkey(sctx, pub_) } != 1 {
                break 'blk;
            }
        }

        // SAFETY: `sctx` is live; `ctx` is live per the contract.
        unsafe { SCT_CTX_set_time(sctx, (*ctx).epoch_time_in_ms) };

        // SAFETY: `sctx` is live; `ctx` and its `cert` are live per the contract.
        if unsafe { SCT_CTX_set1_cert(sctx, (*ctx).cert, ptr::null_mut()) } != 1 {
            // SAFETY: `sct` is live per the contract.
            unsafe { (*sct).validation_status = SCT_VALIDATION_STATUS_UNVERIFIED };
        } else {
            // SAFETY: `sctx` and `sct` are live per the contract.
            let valid = unsafe { SCT_CTX_verify(sctx, sct) } == 1;
            // SAFETY: `sct` is live per the contract.
            unsafe {
                (*sct).validation_status = if valid {
                    SCT_VALIDATION_STATUS_VALID
                } else {
                    SCT_VALIDATION_STATUS_INVALID
                };
            }
        }
        // SAFETY: `sct` is live per the contract.
        is_sct_valid =
            (unsafe { (*sct).validation_status } == SCT_VALIDATION_STATUS_VALID) as c_int;
    }

    // SAFETY: `pub_` and `log_pkey` are NULL or wrappers this call built; `sctx` is NULL or live.
    unsafe {
        X509_PUBKEY_free(pub_);
        X509_PUBKEY_free(log_pkey);
        SCT_CTX_free(sctx);
    }

    is_sct_valid
}

/// `int SCT_LIST_validate(const STACK_OF(SCT) *scts, CT_POLICY_EVAL_CTX *ctx)` —
/// `crypto/ct/ct_sct.c:365-385`.
///
/// # Safety
///
/// `scts` is NULL or a live `STACK_OF(SCT)`; `ctx` is a live `CT_POLICY_EVAL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn SCT_LIST_validate(
    scts: *const OpenSslStack,
    ctx: *mut CtPolicyEvalCtx,
) -> c_int {
    let mut are_scts_valid: c_int = 1;
    // `scts` is NULL or a live stack per the contract.
    let sct_count = if scts.is_null() {
        0
    } else {
        // SAFETY: `scts` is non-NULL, hence live, per the contract.
        unsafe { OPENSSL_sk_num(scts) }
    };
    let mut i = 0;
    while i < sct_count {
        // SAFETY: `scts` is live and `i` is in bounds.
        let sct = unsafe { OPENSSL_sk_value(scts, i) }.cast::<Sct>();
        if !sct.is_null() {
            // SAFETY: `sct` is a live element; `ctx` is live per the contract.
            let is_sct_valid = unsafe { SCT_validate(sct, ctx) };
            if is_sct_valid < 0 {
                return is_sct_valid;
            }
            are_scts_valid &= is_sct_valid;
        }
        i += 1;
    }
    are_scts_valid
}
