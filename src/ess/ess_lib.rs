//! `crypto/ess/ess_lib.c` — the ESS signing-certificate builders and checker. Phase 12.7.
//!
//! The three exports `ess_lib.c` publishes: `OSSL_ESS_signing_cert_new_init` and
//! `OSSL_ESS_signing_cert_v2_new_init`, which digest a signer certificate (and, for v2, choose the
//! hash algorithm) into an `ESS_SIGNING_CERT[_V2]`, and `OSSL_ESS_check_signing_certs`, which finds
//! each `ESSCertID`'s certificate in the chain and enforces the "first cert iff index 0" order.
//!
//! The two static helpers the builders share (`ESS_CERT_ID_new_init`, `ESS_CERT_ID_V2_new_init`)
//! and the checker's `ess_issuer_serial_cmp`/`find` are transcribed as Rust free functions.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uchar, c_uint};
use core::ptr;

use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_dup};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_set};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_free, X509_ALGOR_new, X509_ALGOR_set_md};
use crate::ess::ess_asn1::{
    ESS_CERT_ID_V2_free, ESS_CERT_ID_V2_new, ESS_CERT_ID_free, ESS_CERT_ID_new,
    ESS_ISSUER_SERIAL_new, ESS_SIGNING_CERT_V2_free, ESS_SIGNING_CERT_V2_new,
    ESS_SIGNING_CERT_free, ESS_SIGNING_CERT_new, EssCertId, EssCertIdV2, EssIssuerSerial,
    EssSigningCert, EssSigningCertV2,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_is_a, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::legacy_sha::EVP_sha1;
use crate::runtime::err::err_reasons::*;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::obj::OBJ_obj2txt;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_genn::{GENERAL_NAME_free, GENERAL_NAME_new, GeneralName, GEN_DIRNAME};
use crate::x509::x509_cmp::{X509_NAME_cmp, X509_get0_serialNumber, X509_get_issuer_name};
use crate::x509::x_all::X509_digest;
use crate::x509::x_name::X509_NAME_dup;
use crate::x509::x_x509::X509;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ess/ess_lib.c";

/// `ERR_LIB_ESS` — `include/openssl/err.h.in:119`.
const ERR_LIB_ESS: c_int = 54;
/// `ERR_R_ESS_LIB` — `include/openssl/err.h.in:347`.
const ERR_R_ESS_LIB: c_int = 54 | (0x2 << 18);
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`.
const ERR_R_CRYPTO_LIB: c_int = 15 | (0x2 << 18);
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in:328`.
const ERR_R_ASN1_LIB: c_int = 13 | (0x2 << 18);
/// `ERR_R_X509_LIB` — `include/openssl/err.h.in:327`.
const ERR_R_X509_LIB: c_int = 11 | (0x2 << 18);
/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`.
const SHA_DIGEST_LENGTH: usize = 20;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `SN_sha256` — `include/openssl/obj_mac.h`.
const SN_sha256: &core::ffi::CStr = c"SHA256";

/// `ERR_raise(ERR_LIB_ESS, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_ess(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_ESS,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `strcpy(dst, src)` for a C string literal; `dst` is a fixed 50-byte buffer.
///
/// # Safety
/// `dst` is writable for `OSSL_MAX_NAME_SIZE` bytes; `src` is NUL-terminated and short enough.
unsafe fn strcpy_name(dst: *mut c_char, src: &core::ffi::CStr) {
    let bytes = src.to_bytes_with_nul();
    // SAFETY: `dst` is writable for the buffer's length and `src` fits per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), dst, bytes.len()) };
}

/// `memcmp(a, b, n) == 0`.
///
/// # Safety
/// `a` and `b` are readable for `n` bytes.
unsafe fn memeq(a: *const c_uchar, b: *const u8, n: usize) -> bool {
    for i in 0..n {
        // SAFETY: both pointers are readable for `n` bytes per the contract.
        if unsafe { *a.add(i) } != unsafe { *b.add(i) } {
            return false;
        }
    }
    true
}

/// `static ESS_CERT_ID *ESS_CERT_ID_new_init(const X509 *cert, int set_issuer_serial)` —
/// `ess_lib.c:67-123`.
///
/// # Safety
/// `cert` is a live `X509`; the returned value is owned by the caller.
unsafe fn ESS_CERT_ID_new_init(cert: *const X509, set_issuer_serial: c_int) -> *mut EssCertId {
    let mut cert_sha1 = [0u8; SHA_DIGEST_LENGTH];
    // SAFETY: the accessor answers a fresh item value.
    let cid = ESS_CERT_ID_new();
    if cid.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_ess(75, c"ESS_CERT_ID_new_init", ERR_R_ESS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `cert` is live; `EVP_sha1` answers a static method; `cert_sha1` is writable.
    if unsafe { X509_digest(cert, EVP_sha1(), cert_sha1.as_mut_ptr(), ptr::null_mut()) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(79, c"ESS_CERT_ID_new_init", ERR_R_X509_LIB);
            ESS_CERT_ID_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: `cid` is live and its `hash` is a fresh octet string.
    if unsafe { ASN1_OCTET_STRING_set((*cid).hash, cert_sha1.as_ptr(), SHA_DIGEST_LENGTH as c_int) }
        == 0
    {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(83, c"ESS_CERT_ID_new_init", ERR_R_ASN1_LIB);
            ESS_CERT_ID_free(cid);
        };
        return ptr::null_mut();
    }
    if set_issuer_serial == 0 {
        return cid;
    }
    // SAFETY: `cid` is live; its `issuer_serial` is optionally NULL.
    unsafe {
        if (*cid).issuer_serial.is_null() {
            (*cid).issuer_serial = ESS_ISSUER_SERIAL_new();
            if (*cid).issuer_serial.is_null() {
                raise_ess(93, c"ESS_CERT_ID_new_init", ERR_R_ESS_LIB);
                ESS_CERT_ID_free(cid);
                return ptr::null_mut();
            }
        }
    }
    // SAFETY: the accessor answers a fresh general name.
    let name = GENERAL_NAME_new();
    if name.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(97, c"ESS_CERT_ID_new_init", ERR_R_ASN1_LIB);
            ESS_CERT_ID_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: `name` is live; `cert` is live.
    unsafe {
        (*name).type_ = GEN_DIRNAME;
        (*name).d.directoryName = X509_NAME_dup(X509_get_issuer_name(cert));
        if (*name).d.directoryName.is_null() {
            raise_ess(102, c"ESS_CERT_ID_new_init", ERR_R_X509_LIB);
            GENERAL_NAME_free(name);
            ESS_CERT_ID_free(cid);
            return ptr::null_mut();
        }
        let is = (*cid).issuer_serial;
        if OPENSSL_sk_push((*is).issuer, name.cast()) == 0 {
            raise_ess(106, c"ESS_CERT_ID_new_init", ERR_R_CRYPTO_LIB);
            GENERAL_NAME_free(name);
            ESS_CERT_ID_free(cid);
            return ptr::null_mut();
        }
        // ownership of `name` is lost to the stack
        ASN1_INTEGER_free((*is).serial);
        (*is).serial = ASN1_INTEGER_dup(X509_get0_serialNumber(cert));
        if (*is).serial.is_null() {
            raise_ess(114, c"ESS_CERT_ID_new_init", ERR_R_ASN1_LIB);
            ESS_CERT_ID_free(cid);
            return ptr::null_mut();
        }
    }
    cid
}

/// `static ESS_CERT_ID_V2 *ESS_CERT_ID_V2_new_init(const EVP_MD *hash_alg, const X509 *cert, int`
/// `set_issuer_serial)` — `ess_lib.c:170-248`.
///
/// # Safety
/// `hash_alg` is live; `cert` is a live `X509`; the returned value is owned by the caller.
unsafe fn ESS_CERT_ID_V2_new_init(
    hash_alg: *const EvpMd,
    cert: *const X509,
    set_issuer_serial: c_int,
) -> *mut EssCertIdV2 {
    let mut hash = [0u8; EVP_MAX_MD_SIZE];
    let mut hash_len: c_uint = EVP_MAX_MD_SIZE as c_uint;
    let mut alg: *mut X509Algor = ptr::null_mut();
    // SAFETY: the accessor answers a fresh item value.
    let cid = ESS_CERT_ID_V2_new();
    if cid.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_ess(183, c"ESS_CERT_ID_V2_new_init", ERR_R_ESS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `hash_alg` is live per the contract.
    if unsafe { EVP_MD_is_a(hash_alg, SN_sha256.as_ptr()) } == 0 {
        // SAFETY: the accessor answers a fresh algorithm.
        alg = X509_ALGOR_new();
        if alg.is_null() {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(190, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
                ESS_CERT_ID_V2_free(cid);
            };
            return ptr::null_mut();
        }
        // SAFETY: `alg` is live; `hash_alg` is live.
        unsafe { X509_ALGOR_set_md(alg, hash_alg) };
        // SAFETY: `alg` is live.
        if unsafe { (*alg).algorithm }.is_null() {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(195, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
                X509_ALGOR_free(alg);
                ESS_CERT_ID_V2_free(cid);
            };
            return ptr::null_mut();
        }
        // SAFETY: `cid` is live.
        unsafe {
            (*cid).hash_alg = alg;
            alg = ptr::null_mut();
        }
    } else {
        // SAFETY: `cid` is live.
        unsafe { (*cid).hash_alg = ptr::null_mut() };
    }
    // SAFETY: `cert` is live; `hash_alg` is live; `hash` is writable.
    if unsafe { X509_digest(cert, hash_alg, hash.as_mut_ptr(), &mut hash_len) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(205, c"ESS_CERT_ID_V2_new_init", ERR_R_X509_LIB);
            X509_ALGOR_free(alg);
            ESS_CERT_ID_V2_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: `cid` is live and its `hash` is a fresh octet string.
    if unsafe { ASN1_OCTET_STRING_set((*cid).hash, hash.as_ptr(), hash_len as c_int) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(210, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
            X509_ALGOR_free(alg);
            ESS_CERT_ID_V2_free(cid);
        };
        return ptr::null_mut();
    }
    if set_issuer_serial == 0 {
        return cid;
    }
    // SAFETY: the accessor answers a fresh item value; `cid` is live.
    let is = ESS_ISSUER_SERIAL_new();
    if is.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(218, c"ESS_CERT_ID_V2_new_init", ERR_R_ESS_LIB);
            ESS_CERT_ID_V2_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: `cid` is live.
    unsafe { (*cid).issuer_serial = is };
    // SAFETY: the accessor answers a fresh general name.
    let name = GENERAL_NAME_new();
    if name.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(222, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
            ESS_CERT_ID_V2_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: `name`, `is` and `cert` are live.
    unsafe {
        (*name).type_ = GEN_DIRNAME;
        (*name).d.directoryName = X509_NAME_dup(X509_get_issuer_name(cert));
        if (*name).d.directoryName.is_null() {
            raise_ess(227, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
            GENERAL_NAME_free(name);
            ESS_CERT_ID_V2_free(cid);
            return ptr::null_mut();
        }
        if OPENSSL_sk_push((*is).issuer, name.cast()) == 0 {
            raise_ess(231, c"ESS_CERT_ID_V2_new_init", ERR_R_CRYPTO_LIB);
            GENERAL_NAME_free(name);
            ESS_CERT_ID_V2_free(cid);
            return ptr::null_mut();
        }
        // ownership of `name` is lost to the stack
        ASN1_INTEGER_free((*is).serial);
        (*is).serial = ASN1_INTEGER_dup(X509_get0_serialNumber(cert));
        if (*is).serial.is_null() {
            raise_ess(238, c"ESS_CERT_ID_V2_new_init", ERR_R_ASN1_LIB);
            ESS_CERT_ID_V2_free(cid);
            return ptr::null_mut();
        }
    }
    cid
}

/// `ESS_SIGNING_CERT *OSSL_ESS_signing_cert_new_init(const X509 *signcert, const STACK_OF(X509)`
/// `*certs, int set_issuer_serial)` — `ess_lib.c:24-65`.
///
/// # Safety
/// `signcert` is a live `X509`; `certs` is NULL or a live stack of `X509`; the returned value is
/// owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ESS_signing_cert_new_init(
    signcert: *const X509,
    certs: *const OpenSslStack,
    set_issuer_serial: c_int,
) -> *mut EssSigningCert {
    let mut cid: *mut EssCertId;
    // SAFETY: the accessor answers a fresh item value.
    let sc = ESS_SIGNING_CERT_new();
    if sc.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_ess(33, c"OSSL_ESS_signing_cert_new_init", ERR_R_ESS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `sc` is live.
    unsafe {
        if (*sc).cert_ids.is_null() {
            (*sc).cert_ids = OPENSSL_sk_new_null();
        }
        if (*sc).cert_ids.is_null() {
            raise_ess(38, c"OSSL_ESS_signing_cert_new_init", ERR_R_CRYPTO_LIB);
            ESS_SIGNING_CERT_free(sc);
            return ptr::null_mut();
        }
        cid = ESS_CERT_ID_new_init(signcert, set_issuer_serial);
        if cid.is_null() || OPENSSL_sk_push((*sc).cert_ids, cid.cast()) == 0 {
            raise_ess(44, c"OSSL_ESS_signing_cert_new_init", ERR_R_ESS_LIB);
            ESS_SIGNING_CERT_free(sc);
            ESS_CERT_ID_free(cid);
            return ptr::null_mut();
        }
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    let n = unsafe { OPENSSL_sk_num(certs) };
    for i in 0..n {
        // SAFETY: `i` is a valid index per the count.
        let cert = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `cert` is live.
        cid = unsafe { ESS_CERT_ID_new_init(cert, 1) };
        if cid.is_null() {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(51, c"OSSL_ESS_signing_cert_new_init", ERR_R_ESS_LIB);
                ESS_SIGNING_CERT_free(sc);
                ESS_CERT_ID_free(cid);
            };
            return ptr::null_mut();
        }
        // SAFETY: `sc` is live and `cid` is fresh.
        if unsafe { OPENSSL_sk_push((*sc).cert_ids, cid.cast()) } == 0 {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(55, c"OSSL_ESS_signing_cert_new_init", ERR_R_CRYPTO_LIB);
                ESS_SIGNING_CERT_free(sc);
                ESS_CERT_ID_free(cid);
            };
            return ptr::null_mut();
        }
    }
    sc
}

/// `ESS_SIGNING_CERT_V2 *OSSL_ESS_signing_cert_v2_new_init(const EVP_MD *hash_alg, const X509`
/// `*signcert, const STACK_OF(X509) *certs, int set_issuer_serial)` — `ess_lib.c:125-168`.
///
/// # Safety
/// `hash_alg` is live; `signcert` is a live `X509`; `certs` is NULL or a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ESS_signing_cert_v2_new_init(
    hash_alg: *const EvpMd,
    signcert: *const X509,
    certs: *const OpenSslStack,
    set_issuer_serial: c_int,
) -> *mut EssSigningCertV2 {
    let mut cid: *mut EssCertIdV2;
    // SAFETY: the accessor answers a fresh item value.
    let sc = ESS_SIGNING_CERT_V2_new();
    if sc.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_ess(134, c"OSSL_ESS_signing_cert_v2_new_init", ERR_R_ESS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: the arguments are the caller's; the returned value is fresh.
    cid = unsafe { ESS_CERT_ID_V2_new_init(hash_alg, signcert, set_issuer_serial) };
    if cid.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(140, c"OSSL_ESS_signing_cert_v2_new_init", ERR_R_ESS_LIB);
            ESS_SIGNING_CERT_V2_free(sc);
        };
        return ptr::null_mut();
    }
    // SAFETY: `sc` is live; its `cert_ids` is a fresh non-NULL stack from the item layer.
    if unsafe { OPENSSL_sk_push((*sc).cert_ids, cid.cast()) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(144, c"OSSL_ESS_signing_cert_v2_new_init", ERR_R_CRYPTO_LIB);
            ESS_SIGNING_CERT_V2_free(sc);
            ESS_CERT_ID_V2_free(cid);
        };
        return ptr::null_mut();
    }
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    let n = unsafe { OPENSSL_sk_num(certs) };
    for i in 0..n {
        // SAFETY: `i` is a valid index per the count.
        let cert = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: `cert` and `hash_alg` are live.
        cid = unsafe { ESS_CERT_ID_V2_new_init(hash_alg, cert, 1) };
        if cid.is_null() {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(153, c"OSSL_ESS_signing_cert_v2_new_init", ERR_R_ESS_LIB);
                ESS_SIGNING_CERT_V2_free(sc);
                ESS_CERT_ID_V2_free(cid);
            };
            return ptr::null_mut();
        }
        // SAFETY: `sc` is live and `cid` is fresh.
        if unsafe { OPENSSL_sk_push((*sc).cert_ids, cid.cast()) } == 0 {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_ess(157, c"OSSL_ESS_signing_cert_v2_new_init", ERR_R_CRYPTO_LIB);
                ESS_SIGNING_CERT_V2_free(sc);
                ESS_CERT_ID_V2_free(cid);
            };
            return ptr::null_mut();
        }
    }
    sc
}

/// `static int ess_issuer_serial_cmp(const ESS_ISSUER_SERIAL *is, const X509 *cert)` —
/// `ess_lib.c:250-263`.
///
/// # Safety
/// `is` and `cert` are NULL or live.
unsafe fn ess_issuer_serial_cmp(is: *const EssIssuerSerial, cert: *const X509) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    if is.is_null() || cert.is_null() || unsafe { OPENSSL_sk_num((*is).issuer) } != 1 {
        return -1;
    }
    // SAFETY: the stack holds exactly one element per the check.
    let issuer = unsafe { OPENSSL_sk_value((*is).issuer, 0) }.cast::<GeneralName>();
    // SAFETY: `issuer` is live; its union arm is the directory name per the type check.
    if unsafe { (*issuer).type_ } != GEN_DIRNAME
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || unsafe { X509_NAME_cmp((*issuer).d.directoryName, X509_get_issuer_name(cert)) } != 0
    {
        return -1;
    }
    // SAFETY: `is` and `cert` are live; their serials are live.
    unsafe { ASN1_INTEGER_cmp((*is).serial, X509_get0_serialNumber(cert)) }
}

/// `static int find(const ESS_CERT_ID *cid, const ESS_CERT_ID_V2 *cid_v2, int index, const`
/// `STACK_OF(X509) *certs)` — `ess_lib.c:270-338`.
///
/// # Safety
/// Exactly one of `cid`/`cid_v2` is non-NULL and live; `certs` is NULL or a live stack of `X509`.
unsafe fn find(
    cid: *const EssCertId,
    cid_v2: *const EssCertIdV2,
    index: c_int,
    certs: *const OpenSslStack,
) -> c_int {
    let mut md: *mut EvpMd;
    let mut name = [0i8; OSSL_MAX_NAME_SIZE];
    let mut cert_digest = [0u8; EVP_MAX_MD_SIZE];
    let ret: c_int;
    if cid.is_null() && cid_v2.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_ess(283, c"find", ERR_R_PASSED_INVALID_ARGUMENT) };
        return -1;
    }
    // SAFETY: exactly one of the two is non-NULL per the contract.
    unsafe {
        if !cid.is_null() {
            strcpy_name(name.as_mut_ptr(), c"SHA1");
        } else if (*cid_v2).hash_alg.is_null() {
            strcpy_name(name.as_mut_ptr(), c"SHA256");
        } else {
            OBJ_obj2txt(
                name.as_mut_ptr(),
                name.len() as c_int,
                (*(*cid_v2).hash_alg).algorithm,
                0,
            );
        }
    }
    // SAFETY: no preconditions.
    ERR_set_mark();
    // SAFETY: `name` is NUL-terminated.
    md = unsafe { EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
    if md.is_null() {
        // SAFETY: `name` is NUL-terminated.
        md = unsafe { EVP_get_digestbyname(name.as_ptr()) } as *mut EvpMd;
    }
    if md.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            ERR_clear_last_mark();
            raise_ess(302, c"find", ESS_R_ESS_DIGEST_ALG_UNKNOWN);
        };
        return -1;
    }
    // SAFETY: no preconditions.
    ERR_pop_to_mark();

    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    let n = unsafe { OPENSSL_sk_num(certs) };
    for i in 0..n {
        // SAFETY: `i` is a valid index per the count.
        let cert = unsafe { OPENSSL_sk_value(certs, i) }.cast::<X509>();
        // SAFETY: exactly one of the two is non-NULL; its hash is a live octet string.
        let cid_hash_len = unsafe {
            if !cid.is_null() {
                (*(*cid).hash).length as u32
            } else {
                (*(*cid_v2).hash).length as u32
            }
        };
        let mut len: c_uint = 0;
        // SAFETY: `cert` and `md` are live; `cert_digest` is writable.
        if unsafe { X509_digest(cert, md, cert_digest.as_mut_ptr(), &mut len) } == 0
            || cid_hash_len != len
        {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe { raise_ess(313, c"find", ESS_R_ESS_CERT_DIGEST_ERROR) };
            // SAFETY: `md` is owned here.
            unsafe { EVP_MD_free(md) };
            return -1;
        }
        // SAFETY: the digest data is readable for `len` bytes.
        let cmp = unsafe {
            if !cid.is_null() {
                memeq((*(*cid).hash).data, cert_digest.as_ptr(), len as usize)
            } else {
                memeq((*(*cid_v2).hash).data, cert_digest.as_ptr(), len as usize)
            }
        };
        if cmp {
            // SAFETY: exactly one is non-NULL per the contract.
            let is = unsafe {
                if !cid.is_null() {
                    (*cid).issuer_serial
                } else {
                    (*cid_v2).issuer_serial
                }
            };
            // SAFETY: `is` is NULL or live; `cert` is live.
            if is.is_null() || unsafe { ess_issuer_serial_cmp(is, cert) } == 0 {
                if c_int::from(i == 0) == c_int::from(index == 0) {
                    ret = i + 1;
                    // SAFETY: `md` is owned here.
                    unsafe { EVP_MD_free(md) };
                    return ret;
                }
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { raise_ess(327, c"find", ESS_R_ESS_CERT_ID_WRONG_ORDER) };
                // SAFETY: `md` is owned here.
                unsafe { EVP_MD_free(md) };
                return -1;
            }
        }
    }
    ret = 0;
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    unsafe { raise_ess(334, c"find", ESS_R_ESS_CERT_ID_NOT_FOUND) };
    // SAFETY: `md` is owned here.
    unsafe { EVP_MD_free(md) };
    ret
}

/// `int OSSL_ESS_check_signing_certs(const ESS_SIGNING_CERT *ss, const ESS_SIGNING_CERT_V2 *ssv2,`
/// `const STACK_OF(X509) *chain, int require_signing_cert)` — `ess_lib.c:340-369`.
///
/// # Safety
/// `ss`/`ssv2` are NULL or live; `chain` is NULL or a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ESS_check_signing_certs(
    ss: *const EssSigningCert,
    ssv2: *const EssSigningCertV2,
    chain: *const OpenSslStack,
    require_signing_cert: c_int,
) -> c_int {
    // SAFETY: `ss` is NULL or live per the contract.
    let n_v1: c_int = if ss.is_null() {
        -1
    } else {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { OPENSSL_sk_num((*ss).cert_ids) }
    };
    // SAFETY: `ssv2` is NULL or live per the contract.
    let n_v2: c_int = if ssv2.is_null() {
        -1
    } else {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { OPENSSL_sk_num((*ssv2).cert_ids) }
    };
    if require_signing_cert != 0 && ss.is_null() && ssv2.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(
                350,
                c"OSSL_ESS_check_signing_certs",
                ESS_R_MISSING_SIGNING_CERTIFICATE_ATTRIBUTE,
            )
        };
        return -1;
    }
    if n_v1 == 0 || n_v2 == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_ess(
                354,
                c"OSSL_ESS_check_signing_certs",
                ESS_R_EMPTY_ESS_CERT_ID_LIST,
            )
        };
        return -1;
    }
    for i in 0..n_v1 {
        // SAFETY: `i` is a valid index per the count.
        let cid = unsafe { OPENSSL_sk_value((*ss).cert_ids, i) }.cast::<EssCertId>();
        // SAFETY: the arguments are the caller's.
        let ret = unsafe { find(cid, ptr::null(), i, chain) };
        if ret <= 0 {
            return ret;
        }
    }
    for i in 0..n_v2 {
        // SAFETY: `i` is a valid index per the count.
        let cid = unsafe { OPENSSL_sk_value((*ssv2).cert_ids, i) }.cast::<EssCertIdV2>();
        // SAFETY: the arguments are the caller's.
        let ret = unsafe { find(ptr::null(), cid, i, chain) };
        if ret <= 0 {
            return ret;
        }
    }
    1
}
