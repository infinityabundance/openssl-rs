//! Phase 14.7 — `ssl/ssl_rsa_legacy.c`: the deprecated `use_RSAPrivateKey` spellings.
//!
//! The six exports the plan names for this unit. Each wraps an `RSA *` into an `EVP_PKEY` and
//! forwards to the modern `ssl_rsa.c` entry point; the two `_file` spellings open a file and the
//! two `_ASN1` spellings decode DER in memory. They are the exact bodies at
//! `ssl/ssl_rsa_legacy.c:17-198`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`EVP_PKEY_assign_RSA` is `EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa)`.** The authority's
//!   `EVP_PKEY_assign_RSA` macro is that call; the crate's `EVP_PKEY_assign` is the same function.
//! * **The `_file` wrappers open a file and are not driven.** `docs/PHASE-14-SUBPHASES.md` records
//!   that the differential court drives the loaders over fixed in-memory PEM/DER fixtures, so the
//!   `_ASN1` and object spellings are the observed surface and the `_file` spellings are not.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_new, EvpPkey};
use crate::ffi::guard_ffi;
use crate::pem::key_legacy::PEM_read_bio_RSAPrivateKey;
use crate::rsa::object::{RSA_free, RSA_up_ref};
use crate::rsa::Rsa;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::{BIO_free, BIO_new, BIO_CLOSE, BIO_C_SET_FILENAME, BIO_FP_READ};
use crate::runtime::err::raise_with;
use crate::ssl::ssl_lib::{Ssl, SslCtx};
use crate::ssl::ssl_rsa::{SSL_CTX_use_PrivateKey, SSL_use_PrivateKey};
use crate::x509::x_all::d2i_RSAPrivateKey_bio;

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_rsa_legacy.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_RFLAG_COMMON` — `err.h:239`.
const ERR_RFLAG_COMMON: c_int = 2 << 18;
/// `ERR_RFLAG_FATAL` — `err.h:238`.
const ERR_RFLAG_FATAL: c_int = 1 << 18;
/// `ERR_R_PASSED_NULL_PARAMETER`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;
/// `ERR_R_EVP_LIB`.
const ERR_R_EVP_LIB: c_int = 6 | ERR_RFLAG_COMMON;
/// `ERR_R_BUF_LIB`.
const ERR_R_BUF_LIB: c_int = 7 | ERR_RFLAG_COMMON;
/// `ERR_R_PEM_LIB`.
const ERR_R_PEM_LIB: c_int = 9 | ERR_RFLAG_COMMON;
/// `ERR_R_ASN1_LIB`.
const ERR_R_ASN1_LIB: c_int = 13 | ERR_RFLAG_COMMON;
/// `ERR_R_SYS_LIB`.
const ERR_R_SYS_LIB: c_int = 2 | ERR_RFLAG_COMMON;
/// `SSL_R_BAD_SSL_FILETYPE` — `sslerr.h:59`.
const SSL_R_BAD_SSL_FILETYPE: c_int = 124;
/// `SSL_FILETYPE_PEM`.
const SSL_FILETYPE_PEM: c_int = 1;
/// `SSL_FILETYPE_ASN1`.
const SSL_FILETYPE_ASN1: c_int = 2;

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_rsa_legacy.c:line`.
fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// The shared body of `SSL_use_RSAPrivateKey`/`SSL_CTX_use_RSAPrivateKey`: wrap an up-reffed `RSA`
/// in a fresh `EVP_PKEY` and hand it to the modern loader.
///
/// # Safety
/// `rsa` must be NULL or a live key.
unsafe fn use_rsa_private_key(rsa: *mut Rsa) -> Option<*mut EvpPkey> {
    if rsa.is_null() {
        raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 42);
        return None;
    }
    // SAFETY: `EVP_PKEY_new` builds a fresh key.
    let pkey = unsafe { EVP_PKEY_new() };
    if pkey.is_null() {
        raise_ssl(ERR_R_EVP_LIB, 27);
        return None;
    }
    // SAFETY: `rsa` is live per the contract.
    if unsafe { RSA_up_ref(rsa) } == 0 {
        // SAFETY: `pkey` is owned here.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return None;
    }
    // SAFETY: `EVP_PKEY_assign` takes ownership of `rsa`.
    if unsafe { EVP_PKEY_assign(pkey, crate::evp::pkey_ctx::EVP_PKEY_RSA, rsa.cast()) } <= 0 {
        // SAFETY: `rsa` is owned here on failure.
        unsafe { RSA_free(rsa) };
        // SAFETY: `pkey` is owned here.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        return None;
    }
    Some(pkey)
}

/// `int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)` — `ssl/ssl_rsa_legacy.c:17-45`.
///
/// # Safety
/// `ssl` must be live; `rsa` NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_RSAPrivateKey(ssl: *mut Ssl, rsa: *mut Rsa) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the helper validates and raises.
        let Some(pkey) = (unsafe { use_rsa_private_key(rsa) }) else {
            return 0;
        };
        // SAFETY: `ssl` is live per the caller's contract.
        let ret = unsafe { SSL_use_PrivateKey(ssl, pkey) };
        // SAFETY: `pkey` is owned here.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        ret
    })
}

/// `int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)` — `ssl/ssl_rsa_legacy.c:108-136`.
///
/// # Safety
/// `ctx` must be live; `rsa` NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_RSAPrivateKey(ctx: *mut SslCtx, rsa: *mut Rsa) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the helper validates and raises.
        let Some(pkey) = (unsafe { use_rsa_private_key(rsa) }) else {
            return 0;
        };
        // SAFETY: `ctx` is live per the caller's contract.
        let ret = unsafe { SSL_CTX_use_PrivateKey(ctx, pkey) };
        // SAFETY: `pkey` is owned here.
        unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
        ret
    })
}

/// `int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, const unsigned char *d, long len)` —
/// `ssl/ssl_rsa_legacy.c:91-106`.
///
/// # Safety
/// `ssl` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_RSAPrivateKey_ASN1(
    ssl: *mut Ssl,
    d: *const u8,
    len: c_long,
) -> c_int {
    guard_ffi(0, || {
        let mut p = d;
        // SAFETY: `d` is readable for `len` bytes; the RPK decoder allocates.
        let rsa = unsafe { crate::rsa::asn1::d2i_RSAPrivateKey(ptr::null_mut(), &mut p, len) };
        if rsa.is_null() {
            raise_ssl(ERR_R_ASN1_LIB, 99);
            return 0;
        }
        // SAFETY: `ssl` is live per the caller's contract.
        let ret = unsafe { SSL_use_RSAPrivateKey(ssl, rsa) };
        // SAFETY: `rsa` is owned here.
        unsafe { RSA_free(rsa) };
        ret
    })
}

/// `int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len)` —
/// `ssl/ssl_rsa_legacy.c:182-198`.
///
/// # Safety
/// `ctx` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_RSAPrivateKey_ASN1(
    ctx: *mut SslCtx,
    d: *const u8,
    len: c_long,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `d` is readable for `len` bytes.
        let mut p = d;
        // SAFETY: the RPK decoder allocates.
        let rsa = unsafe { crate::rsa::asn1::d2i_RSAPrivateKey(ptr::null_mut(), &mut p, len) };
        if rsa.is_null() {
            raise_ssl(ERR_R_ASN1_LIB, 190);
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        let ret = unsafe { SSL_CTX_use_RSAPrivateKey(ctx, rsa) };
        // SAFETY: `rsa` is owned here.
        unsafe { RSA_free(rsa) };
        ret
    })
}

/// Open a file BIO for the two `_file` spellings.
///
/// # Safety
/// `file` must be NUL-terminated.
unsafe fn open_file(file: *const c_char) -> *mut crate::runtime::bio::Bio {
    // SAFETY: `BIO_s_file` is a static method table.
    let in_ = unsafe { BIO_new(BIO_s_file()) };
    if in_.is_null() {
        raise_ssl(ERR_R_BUF_LIB, 59);
        return ptr::null_mut();
    }
    // SAFETY: `in_` is a live file BIO; `file` is the caller's.
    if unsafe {
        BIO_ctrl(
            in_,
            BIO_C_SET_FILENAME,
            (BIO_CLOSE | BIO_FP_READ) as _,
            file as *mut c_void,
        )
    } <= 0
    {
        raise_ssl(ERR_R_SYS_LIB, 65);
        // SAFETY: `in_` is this frame's own BIO.
        unsafe { BIO_free(in_) };
        return ptr::null_mut();
    }
    in_
}

/// `int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)` —
/// `ssl/ssl_rsa_legacy.c:47-89`.
///
/// # Safety
/// `ssl` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_RSAPrivateKey_file(
    ssl: *mut Ssl,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        if file.is_null() {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 53);
            return 0;
        }
        // SAFETY: `file` is NUL-terminated.
        let in_ = unsafe { open_file(file) };
        if in_.is_null() {
            return 0;
        }
        let j;
        let rsa: *mut Rsa;
        // SAFETY: `in_` is a live readable BIO; `ssl` is the caller's.
        unsafe {
            if type_ == SSL_FILETYPE_ASN1 {
                j = ERR_R_ASN1_LIB;
                rsa = d2i_RSAPrivateKey_bio(in_, ptr::null_mut());
            } else if type_ == SSL_FILETYPE_PEM {
                j = ERR_R_PEM_LIB;
                rsa = PEM_read_bio_RSAPrivateKey(
                    in_,
                    ptr::null_mut(),
                    crate::ssl::ssl_lib::SSL_get_default_passwd_cb(ssl),
                    crate::ssl::ssl_lib::SSL_get_default_passwd_cb_userdata(ssl),
                );
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 77);
                BIO_free(in_);
                return 0;
            }
        }
        if rsa.is_null() {
            raise_ssl(j, 81);
            // SAFETY: `in_` is this frame's own BIO.
            unsafe { BIO_free(in_) };
            return 0;
        }
        // SAFETY: `ssl` is live per the caller's contract.
        let ret = unsafe { SSL_use_RSAPrivateKey(ssl, rsa) };
        // SAFETY: `rsa`/`in_` are owned here.
        unsafe {
            RSA_free(rsa);
            BIO_free(in_);
        }
        ret
    })
}

/// `int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)` —
/// `ssl/ssl_rsa_legacy.c:138-180`.
///
/// # Safety
/// `ctx` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_RSAPrivateKey_file(
    ctx: *mut SslCtx,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        if file.is_null() {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 144);
            return 0;
        }
        // SAFETY: `file` is NUL-terminated.
        let in_ = unsafe { open_file(file) };
        if in_.is_null() {
            return 0;
        }
        let j;
        let rsa: *mut Rsa;
        // SAFETY: `in_` is a live readable BIO; `ctx` is the caller's.
        unsafe {
            if type_ == SSL_FILETYPE_ASN1 {
                j = ERR_R_ASN1_LIB;
                rsa = d2i_RSAPrivateKey_bio(in_, ptr::null_mut());
            } else if type_ == SSL_FILETYPE_PEM {
                j = ERR_R_PEM_LIB;
                rsa = PEM_read_bio_RSAPrivateKey(
                    in_,
                    ptr::null_mut(),
                    crate::ssl::ssl_lib::SSL_CTX_get_default_passwd_cb(ctx),
                    crate::ssl::ssl_lib::SSL_CTX_get_default_passwd_cb_userdata(ctx),
                );
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 168);
                BIO_free(in_);
                return 0;
            }
        }
        if rsa.is_null() {
            raise_ssl(j, 172);
            // SAFETY: `in_` is this frame's own BIO.
            unsafe { BIO_free(in_) };
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        let ret = unsafe { SSL_CTX_use_RSAPrivateKey(ctx, rsa) };
        // SAFETY: `rsa`/`in_` are owned here.
        unsafe {
            RSA_free(rsa);
            BIO_free(in_);
        }
        ret
    })
}

// The `_file` wrappers forward through `open_file`; nothing else is referenced here.
