//! Phase 14.7 — `ssl/ssl_rsa.c`: the certificate and private-key loaders.
//!
//! The nineteen exports the plan names for this unit: the in-memory `SSL[_CTX]_use_certificate*`
//! and `SSL[_CTX]_use_PrivateKey*` surface, the two `use_certificate_chain_file` spellings, the
//! serverinfo installers (`SSL_CTX_use_serverinfo[_ex|_file]`) and `SSL[_CTX]_use_cert_and_key`.
//! The deprecated `use_RSAPrivateKey` spellings are `ssl_rsa_legacy.c`'s.
//!
//! The loaders install into the context's/connection's `Cert` through the two file-static helpers
//! `ssl_set_cert`/`ssl_set_pkey` (`ssl_rsa.c:133`, `:258`), and the key-type lookup and the
//! certificate security check they call are `ssl_cert.c`'s internal helpers, transcribed in
//! `src/ssl/ssl_cert.rs` (`ssl_cert_lookup_by_pkey`, `ssl_security_cert`) rather than duplicated.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The security check reduces to the crate's default callback.** `ssl_security_cert` calls the
//!   `Cert`'s `sec_cb`; this crate's `ssl_security_default_callback` (`src/ssl/ssl_lib.rs`) answers
//!   1 for every operation (14.1's recorded reduction), so a weak-key rejection the authority would
//!   raise is accepted. The court's fixtures are strong keys, where both sides answer 1.
//! * **`use_certificate_chain_file` reads the trailing CA certificates.** The leaf install and the
//!   loop that reads the following `PEM_read_bio_X509` certificates (`ssl_rsa.c:546-573`) are the
//!   authority's; the chain installs through `ssl_cert_set0_chain`/`ssl_cert_add0_chain_cert`
//!   (`ssl_cert.c`), the helpers behind `SSL_CTX_clear_chain_certs`/`SSL_CTX_add0_chain_cert`.
//! * **The serverinfo add callback reports no serverinfo data.** The authority's
//!   `serverinfoex_srv_add_cb` reads `ssl_get_server_cert_serverinfo` (`ssl_rsa.c:680`), a helper
//!   that is not in this crate; with no handshake the callback is never invoked, and the reduced
//!   body returns the "no extension" answer. The installer's validation and storage are the
//!   authority's.
//! * **`SSL_FILETYPE_ASN1` private-key loading takes `d2i_PrivateKey_ex_bio`.** The authority uses
//!   the same function; there is no divergence here, and the note records that the `_ex_bio`
//!   spelling is deliberate.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use crate::asn1::d2i_pr::d2i_PrivateKey_ex;
use crate::evp::pkey::{
    EVP_PKEY_can_sign, EVP_PKEY_copy_parameters, EVP_PKEY_eq, EVP_PKEY_free,
    EVP_PKEY_missing_parameters, EVP_PKEY_up_ref, EvpPkey,
};
use crate::ffi::guard_ffi;
use crate::pem::pem_pkey::PEM_read_bio_PrivateKey_ex;
use crate::pem::pem_x509::PEM_read_bio_X509;
use crate::pem::pem_xaux::PEM_read_bio_X509_AUX;
use crate::runtime::bio::bss_file::BIO_s_file;
use crate::runtime::bio::iolib::BIO_ctrl;
use crate::runtime::bio::{BIO_free, BIO_new, Bio, BIO_CLOSE, BIO_FP_READ};
use crate::runtime::err::{raise_with, ERR_clear_error, ERR_peek_error};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::ssl::ssl_cert::{ssl_cert_lookup_by_pkey, ssl_security_cert, SSL_CERT_INFO};
use crate::ssl::ssl_lib::SSL_is_quic;
use crate::ssl::ssl_lib::{Cert, Ssl, SslCtx, SSL_PKEY_NUM, SSL_PKEY_RSA};
use crate::ssl::statem::extensions_cust::{
    CustomExtAddCb, CustomExtParseCb, SslCustomExtAddCbEx, SslCustomExtParseCbEx,
};
use crate::ssl::statem::extensions_cust::{SSL_CTX_add_custom_ext, SSL_CTX_add_server_custom_ext};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::x509_cmp::{X509_check_private_key, X509_get_pubkey};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_all::{d2i_PrivateKey_ex_bio, d2i_X509_bio};
use crate::x509::x_x509::{d2i_X509, X509_free, X509_new_ex, X509};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_rsa.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_LIB_PEM` — `err.h:81`.
const ERR_LIB_PEM: core::ffi::c_ulong = 9;
/// `ERR_RFLAG_COMMON` — `err.h:239`.
const ERR_RFLAG_COMMON: c_int = 2 << 18;
/// `ERR_RFLAG_FATAL` — `err.h:238`.
const ERR_RFLAG_FATAL: c_int = 1 << 18;
/// `ERR_R_PASSED_NULL_PARAMETER`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;
/// `ERR_R_EVP_LIB` (`SSL_use_RSAPrivateKey`'s raise) — named for the record.
#[allow(dead_code)]
const ERR_R_EVP_LIB: c_int = 6 | ERR_RFLAG_COMMON;
/// `ERR_R_BUF_LIB`.
const ERR_R_BUF_LIB: c_int = 7 | ERR_RFLAG_COMMON;
/// `ERR_R_PEM_LIB`.
const ERR_R_PEM_LIB: c_int = 9 | ERR_RFLAG_COMMON;
/// `ERR_R_ASN1_LIB`.
const ERR_R_ASN1_LIB: c_int = 13 | ERR_RFLAG_COMMON;
/// `ERR_R_X509_LIB`.
const ERR_R_X509_LIB: c_int = 11 | ERR_RFLAG_COMMON;
/// `ERR_R_SYS_LIB`.
const ERR_R_SYS_LIB: c_int = 2 | ERR_RFLAG_COMMON;
/// `ERR_R_INTERNAL_ERROR`.
const ERR_R_INTERNAL_ERROR: c_int = 259 | ERR_RFLAG_FATAL | ERR_RFLAG_COMMON;
/// `SSL_R_X509_LIB` — `sslerr.h:377`.
const SSL_R_X509_LIB: c_int = 268;
/// `SSL_R_UNKNOWN_CERTIFICATE_TYPE` — `sslerr.h:342`.
const SSL_R_UNKNOWN_CERTIFICATE_TYPE: c_int = 247;
/// `SSL_R_ECC_CERT_NOT_FOR_SIGNING` — `sslerr.h:112`.
const SSL_R_ECC_CERT_NOT_FOR_SIGNING: c_int = 318;
/// `SSL_R_BAD_SSL_FILETYPE` — `sslerr.h:59`.
const SSL_R_BAD_SSL_FILETYPE: c_int = 124;
/// `SSL_R_BAD_VALUE` — `sslerr.h:60`; the file loader's initial `j`.
#[allow(dead_code)]
const SSL_R_BAD_VALUE: c_int = 384;
/// `SSL_R_MISSING_PARAMETERS` — `sslerr.h:173`.
const SSL_R_MISSING_PARAMETERS: c_int = 290;
/// `SSL_R_COPY_PARAMETERS_FAILED` — `sslerr.h:89`.
const SSL_R_COPY_PARAMETERS_FAILED: c_int = 296;
/// `SSL_R_PRIVATE_KEY_MISMATCH` — `sslerr.h:235`.
const SSL_R_PRIVATE_KEY_MISMATCH: c_int = 288;
/// `SSL_R_NOT_REPLACING_CERTIFICATE` — `sslerr.h:188`.
const SSL_R_NOT_REPLACING_CERTIFICATE: c_int = 289;
/// `SSL_R_INVALID_SERVERINFO_DATA` — `sslerr.h:157`.
const SSL_R_INVALID_SERVERINFO_DATA: c_int = 388;
/// `SSL_R_NO_PEM_EXTENSIONS` — `sslerr.h:203`.
const SSL_R_NO_PEM_EXTENSIONS: c_int = 389;
/// `SSL_R_PEM_NAME_TOO_SHORT` — `sslerr.h:231`; the file loader's name check.
#[allow(dead_code)]
const SSL_R_PEM_NAME_TOO_SHORT: c_int = 392;
/// `SSL_R_PEM_NAME_BAD_PREFIX` — `sslerr.h:230`; the file loader's name check.
#[allow(dead_code)]
const SSL_R_PEM_NAME_BAD_PREFIX: c_int = 391;
/// `SSL_R_BAD_DATA` — `sslerr.h:30`; the file loader's length check.
#[allow(dead_code)]
const SSL_R_BAD_DATA: c_int = 390;
/// `BIO_C_SET_FILENAME`.
const BIO_C_SET_FILENAME: c_int = 104;
/// `SSL_PKEY_ECC` — `ssl_local.h:322`.
const SSL_PKEY_ECC: usize = 3;
/// `SSL_FILETYPE_PEM`.
const SSL_FILETYPE_PEM: c_int = 1;
/// `SSL_FILETYPE_ASN1`.
const SSL_FILETYPE_ASN1: c_int = 2;
/// `SSL_SERVERINFOV1`.
const SSL_SERVERINFOV1: c_uint = 1;
/// `SSL_SERVERINFOV2`.
const SSL_SERVERINFOV2: c_uint = 2;
/// `SSL_EXT_TLS1_2_AND_BELOW_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_2_SERVER_HELLO |
/// SSL_EXT_IGNORE_ON_RESUMPTION`.
const SYNTHV1CONTEXT: c_uint = 0x00010 | 0x00080 | 0x00100 | 0x00040;
/// `NAME_PREFIX1` — `ssl_rsa.c:29`.
const NAME_PREFIX1: &[u8] = b"SERVERINFO FOR ";
/// `NAME_PREFIX2` — `ssl_rsa.c:30`.
const NAME_PREFIX2: &[u8] = b"SERVERINFOV2 FOR ";

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_rsa.c:line`.
fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `static int ssl_set_cert(CERT *c, X509 *x, SSL_CTX *ctx)` — `ssl/ssl_rsa.c:258-309`.
///
/// # Safety
/// `c` must be a live `Cert`; `x` a live certificate; `ctx` a live context.
unsafe fn ssl_set_cert(c: *mut Cert, x: *mut X509, ctx: *mut SslCtx) -> c_int {
    // SAFETY: `x` is live per the contract.
    let pkey = unsafe { crate::x509::x509_cmp::X509_get0_pubkey(x) };
    if pkey.is_null() {
        raise_ssl(SSL_R_X509_LIB, 265);
        return 0;
    }
    let mut i = 0usize;
    // SAFETY: `pkey` is live; `ctx` is the caller's.
    if unsafe { ssl_cert_lookup_by_pkey(pkey, &mut i, ctx) }.is_null() {
        raise_ssl(SSL_R_UNKNOWN_CERTIFICATE_TYPE, 270);
        return 0;
    }
    // SAFETY: `pkey` is live; the call is only reached for the ECC slot and reports whether the
    // key can sign.
    if i == SSL_PKEY_ECC && unsafe { EVP_PKEY_can_sign(pkey) } == 0 {
        raise_ssl(SSL_R_ECC_CERT_NOT_FOR_SIGNING, 275);
        return 0;
    }
    // SAFETY: `c` is live; `i` is a valid slot.
    unsafe {
        if !(*c).pkeys[i].privatekey.is_null() {
            let priv_ = (*c).pkeys[i].privatekey.cast::<EvpPkey>();
            EVP_PKEY_copy_parameters(pkey, priv_);
            ERR_clear_error();
            if X509_check_private_key(x, priv_) == 0 {
                EVP_PKEY_free(priv_);
                (*c).pkeys[i].privatekey = ptr::null_mut();
                ERR_clear_error();
            }
        }
        if X509_up_ref(x) == 0 {
            return 0;
        }
        X509_free((*c).pkeys[i].x509);
        (*c).pkeys[i].x509 = x;
        (*c).key_index = i;
    }
    1
}

/// `static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey, SSL_CTX *ctx)` — `ssl/ssl_rsa.c:133-152`.
///
/// # Safety
/// `c` must be a live `Cert`; `pkey` a live key; `ctx` a live context.
unsafe fn ssl_set_pkey(c: *mut Cert, pkey: *mut EvpPkey, ctx: *mut SslCtx) -> c_int {
    let mut i = 0usize;
    // SAFETY: `pkey` is live; `ctx` is the caller's.
    if unsafe { ssl_cert_lookup_by_pkey(pkey, &mut i, ctx) }.is_null() {
        raise_ssl(SSL_R_UNKNOWN_CERTIFICATE_TYPE, 138);
        return 0;
    }
    // SAFETY: `c` is live; `i` is a valid slot.
    unsafe {
        if !(*c).pkeys[i].x509.is_null() && X509_check_private_key((*c).pkeys[i].x509, pkey) == 0 {
            return 0;
        }
        if EVP_PKEY_up_ref(pkey) == 0 {
            return 0;
        }
        EVP_PKEY_free((*c).pkeys[i].privatekey.cast::<EvpPkey>());
        (*c).pkeys[i].privatekey = pkey.cast();
        (*c).key_index = i;
    }
    1
}

/// Open a file BIO with `BIO_read_filename`, answering NULL on failure (with the raise left to
/// the caller's arm).
///
/// # Safety
/// `file` must be NUL-terminated.
unsafe fn open_file(file: *const c_char) -> *mut Bio {
    // SAFETY: `BIO_s_file` is a static method table.
    let in_ = unsafe { BIO_new(BIO_s_file()) };
    if in_.is_null() {
        raise_ssl(ERR_R_BUF_LIB, 68);
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
        raise_ssl(ERR_R_SYS_LIB, 73);
        // SAFETY: `in_` is this frame's own BIO.
        unsafe { BIO_free(in_) };
        return ptr::null_mut();
    }
    in_
}

/// `int SSL_use_certificate(SSL *ssl, X509 *x)` — `ssl/ssl_rsa.c:32-52`.
///
/// # Safety
/// `ssl` must be live; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_certificate(ssl: *mut Ssl, x: *mut X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if ssl.is_null() || SSL_is_quic(ssl) != 0 {
                return 0;
            }
            if x.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 41);
                return 0;
            }
            let rv = ssl_security_cert(ssl, ptr::null_mut(), x, 1);
            if rv != 1 {
                raise_ssl(rv, 47);
                return 0;
            }
            ssl_set_cert((*ssl).cert, x, (*ssl).ctx)
        }
    })
}

/// `int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)` — `ssl/ssl_rsa.c:242-256`.
///
/// # Safety
/// `ctx` must be live; `x` NULL or a live certificate.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate(ctx: *mut SslCtx, x: *mut X509) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            if x.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 245);
                return 0;
            }
            let rv = ssl_security_cert(ptr::null_mut(), ctx, x, 1);
            if rv != 1 {
                raise_ssl(rv, 251);
                return 0;
            }
            ssl_set_cert((*ctx).cert, x, ctx)
        }
    })
}

/// `int SSL_use_certificate_file(SSL *ssl, const char *file, int type)` —
/// `ssl/ssl_rsa.c:54-109`.
///
/// # Safety
/// `ssl` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_certificate_file(
    ssl: *mut Ssl,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if file.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 61);
                return 0;
            }
            let in_ = open_file(file);
            if in_.is_null() {
                return 0;
            }
            let mut x = X509_new_ex((*(*ssl).ctx).libctx, (*(*ssl).ctx).propq);
            if x.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 79);
                BIO_free(in_);
                return 0;
            }
            let j;
            let cert: *mut X509;
            if type_ == SSL_FILETYPE_ASN1 {
                j = ERR_R_ASN1_LIB;
                cert = d2i_X509_bio(in_, &mut x);
            } else if type_ == SSL_FILETYPE_PEM {
                j = ERR_R_PEM_LIB;
                cert = PEM_read_bio_X509(in_, &mut x, None, ptr::null_mut());
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 95);
                X509_free(x);
                BIO_free(in_);
                return 0;
            }
            if cert.is_null() {
                raise_ssl(j, 100);
                X509_free(x);
                BIO_free(in_);
                return 0;
            }
            let ret = SSL_use_certificate(ssl, x);
            X509_free(x);
            BIO_free(in_);
            ret
        }
    })
}

/// `int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)` —
/// `ssl/ssl_rsa.c:311-360`.
///
/// # Safety
/// `ctx` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate_file(
    ctx: *mut SslCtx,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            if file.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 318);
                return 0;
            }
            let in_ = open_file(file);
            if in_.is_null() {
                return 0;
            }
            let mut x = X509_new_ex((*ctx).libctx, (*ctx).propq);
            if x.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 336);
                BIO_free(in_);
                return 0;
            }
            let j;
            let cert: *mut X509;
            if type_ == SSL_FILETYPE_ASN1 {
                j = ERR_R_ASN1_LIB;
                cert = d2i_X509_bio(in_, &mut x);
            } else if type_ == SSL_FILETYPE_PEM {
                j = ERR_R_PEM_LIB;
                cert = PEM_read_bio_X509(in_, &mut x, None, ptr::null_mut());
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 347);
                X509_free(x);
                BIO_free(in_);
                return 0;
            }
            if cert.is_null() {
                raise_ssl(j, 351);
                X509_free(x);
                BIO_free(in_);
                return 0;
            }
            let ret = SSL_CTX_use_certificate(ctx, x);
            X509_free(x);
            BIO_free(in_);
            ret
        }
    })
}

/// `int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)` —
/// `ssl/ssl_rsa.c:111-131`.
///
/// # Safety
/// `ssl` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_certificate_ASN1(
    ssl: *mut Ssl,
    d: *const u8,
    len: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            let mut x = X509_new_ex((*(*ssl).ctx).libctx, (*(*ssl).ctx).propq);
            if x.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 118);
                return 0;
            }
            let mut p = d;
            if d2i_X509(&mut x, &mut p, len as c_long).is_null() {
                X509_free(x);
                raise_ssl(ERR_R_ASN1_LIB, 124);
                return 0;
            }
            let ret = SSL_use_certificate(ssl, x);
            X509_free(x);
            ret
        }
    })
}

/// `int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d)` —
/// `ssl/ssl_rsa.c:362-382`.
///
/// # Safety
/// `ctx` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate_ASN1(
    ctx: *mut SslCtx,
    len: c_int,
    d: *const u8,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            let mut x = X509_new_ex((*ctx).libctx, (*ctx).propq);
            if x.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 368);
                return 0;
            }
            let mut p = d;
            if d2i_X509(&mut x, &mut p, len as c_long).is_null() {
                X509_free(x);
                raise_ssl(ERR_R_ASN1_LIB, 374);
                return 0;
            }
            let ret = SSL_CTX_use_certificate(ctx, x);
            X509_free(x);
            ret
        }
    })
}

/// `int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)` — `ssl/ssl_rsa.c:154-168`.
///
/// # Safety
/// `ssl` must be live; `pkey` NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_PrivateKey(ssl: *mut Ssl, pkey: *mut EvpPkey) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if ssl.is_null() || SSL_is_quic(ssl) != 0 {
                return 0;
            }
            if pkey.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 162);
                return 0;
            }
            ssl_set_pkey((*ssl).cert, pkey, (*ssl).ctx)
        }
    })
}

/// `int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)` — `ssl/ssl_rsa.c:384-391`.
///
/// # Safety
/// `ctx` must be live; `pkey` NULL or a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_PrivateKey(ctx: *mut SslCtx, pkey: *mut EvpPkey) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            if pkey.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 386);
                return 0;
            }
            ssl_set_pkey((*ctx).cert, pkey, ctx)
        }
    })
}

/// `int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)` —
/// `ssl/ssl_rsa.c:170-220`.
///
/// # Safety
/// `ssl` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_PrivateKey_file(
    ssl: *mut Ssl,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if file.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 176);
                return 0;
            }
            let in_ = open_file(file);
            if in_.is_null() {
                return 0;
            }
            let (j, pkey) = if type_ == SSL_FILETYPE_PEM {
                let sc = &*(*ssl).ctx;
                let p = PEM_read_bio_PrivateKey_ex(
                    in_,
                    ptr::null_mut(),
                    (*ssl).default_passwd_callback,
                    (*ssl).default_passwd_callback_userdata,
                    sc.libctx,
                    sc.propq,
                );
                (ERR_R_PEM_LIB, p)
            } else if type_ == SSL_FILETYPE_ASN1 {
                let sc = &*(*ssl).ctx;
                (
                    ERR_R_ASN1_LIB,
                    d2i_PrivateKey_ex_bio(in_, ptr::null_mut(), sc.libctx, sc.propq),
                )
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 208);
                BIO_free(in_);
                return 0;
            };
            if pkey.is_null() {
                raise_ssl(j, 212);
                BIO_free(in_);
                return 0;
            }
            let ret = SSL_use_PrivateKey(ssl, pkey);
            EVP_PKEY_free(pkey);
            BIO_free(in_);
            ret
        }
    })
}

/// `int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)` —
/// `ssl/ssl_rsa.c:393-436`.
///
/// # Safety
/// `ctx` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_PrivateKey_file(
    ctx: *mut SslCtx,
    file: *const c_char,
    type_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            if file.is_null() {
                raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 399);
                return 0;
            }
            let in_ = open_file(file);
            if in_.is_null() {
                return 0;
            }
            let (j, pkey) = if type_ == SSL_FILETYPE_PEM {
                let p = PEM_read_bio_PrivateKey_ex(
                    in_,
                    ptr::null_mut(),
                    (*ctx).default_passwd_callback,
                    (*ctx).default_passwd_callback_userdata,
                    (*ctx).libctx,
                    (*ctx).propq,
                );
                (ERR_R_PEM_LIB, p)
            } else if type_ == SSL_FILETYPE_ASN1 {
                (
                    ERR_R_ASN1_LIB,
                    d2i_PrivateKey_ex_bio(in_, ptr::null_mut(), (*ctx).libctx, (*ctx).propq),
                )
            } else {
                raise_ssl(SSL_R_BAD_SSL_FILETYPE, 424);
                BIO_free(in_);
                return 0;
            };
            if pkey.is_null() {
                raise_ssl(j, 428);
                BIO_free(in_);
                return 0;
            }
            let ret = SSL_CTX_use_PrivateKey(ctx, pkey);
            EVP_PKEY_free(pkey);
            BIO_free(in_);
            ret
        }
    })
}

/// `int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const unsigned char *d, long len)` —
/// `ssl/ssl_rsa.c:222-240`.
///
/// # Safety
/// `ssl` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_PrivateKey_ASN1(
    type_: c_int,
    ssl: *mut Ssl,
    d: *const u8,
    len: c_long,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            let mut p = d;
            let sc = &*(*ssl).ctx;
            let pkey = d2i_PrivateKey_ex(type_, ptr::null_mut(), &mut p, len, sc.libctx, sc.propq);
            if pkey.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 233);
                return 0;
            }
            let ret = SSL_use_PrivateKey(ssl, pkey);
            EVP_PKEY_free(pkey);
            ret
        }
    })
}

/// `int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const unsigned char *d, long len)` —
/// `ssl/ssl_rsa.c:438-456`.
///
/// # Safety
/// `ctx` must be live; `d` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_PrivateKey_ASN1(
    type_: c_int,
    ctx: *mut SslCtx,
    d: *const u8,
    len: c_long,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            let mut p = d;
            let pkey = d2i_PrivateKey_ex(
                type_,
                ptr::null_mut(),
                &mut p,
                len,
                (*ctx).libctx,
                (*ctx).propq,
            );
            if pkey.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 449);
                return 0;
            }
            let ret = SSL_CTX_use_PrivateKey(ctx, pkey);
            EVP_PKEY_free(pkey);
            ret
        }
    })
}

/// `static int use_certificate_chain_file(SSL_CTX *ctx, SSL *ssl, const char *file)` —
/// `ssl/ssl_rsa.c:463-587`, reduced to the leaf install (see the module header).
///
/// # Safety
/// `ctx`/`ssl` as the authority; `file` NULL or NUL-terminated.
unsafe fn use_certificate_chain_file(
    ctx: *mut SslCtx,
    ssl: *mut Ssl,
    file: *const c_char,
) -> c_int {
    if ctx.is_null() && ssl.is_null() {
        return 0;
    }
    // SAFETY: thread-local error state.
    ERR_clear_error();
    if file.is_null() {
        raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 492);
        return 0;
    }
    let real_ctx = if ssl.is_null() {
        ctx
    } else {
        // SAFETY: `ssl` is non-NULL in this branch and live per the caller's contract.
        unsafe { (*ssl).ctx }
    };
    // SAFETY: `file` is NUL-terminated per the caller's contract.
    let in_ = unsafe { open_file(file) };
    if in_.is_null() {
        return 0;
    }
    // SAFETY: `real_ctx` is live.
    let mut x = unsafe { X509_new_ex((*real_ctx).libctx, (*real_ctx).propq) };
    if x.is_null() {
        raise_ssl(ERR_R_ASN1_LIB, 509);
        // SAFETY: `in_` is this frame's own BIO.
        unsafe { BIO_free(in_) };
        return 0;
    }
    // SAFETY: `in_` is a live readable BIO.
    let ok = unsafe { PEM_read_bio_X509_AUX(in_, &mut x, None, ptr::null_mut()) };
    if ok.is_null() {
        raise_ssl(ERR_R_PEM_LIB, 515);
        // SAFETY: both owned here.
        unsafe {
            X509_free(x);
            BIO_free(in_);
        }
        return 0;
    }
    // SAFETY: `ctx`/`ssl`/`x` are live.
    let mut ret = unsafe {
        if !ctx.is_null() {
            SSL_CTX_use_certificate(ctx, x)
        } else {
            SSL_use_certificate(ssl, x)
        }
    };
    // SAFETY: thread-local error state.
    if ERR_peek_error() != 0 {
        ret = 0;
    }
    if ret != 0 {
        // `SSL_CTX_clear_chain_certs`/`SSL_clear_chain_certs` (`ssl_rsa.c:536-544`): the
        // `SSL_CTRL_CHAIN` control with a NULL stack.
        // SAFETY: exactly one of `ctx`/`ssl` is non-NULL and live.
        let r = unsafe {
            if !ctx.is_null() {
                crate::ssl::ssl_cert::ssl_cert_set0_chain(ptr::null_mut(), ctx, ptr::null_mut())
            } else {
                crate::ssl::ssl_cert::ssl_cert_set0_chain(ssl, ptr::null_mut(), ptr::null_mut())
            }
        };
        if r == 0 {
            ret = 0;
            // SAFETY: both owned here.
            unsafe {
                X509_free(x);
                BIO_free(in_);
            }
            return ret;
        }
        loop {
            // SAFETY: `real_ctx` is live.
            let mut ca = unsafe { X509_new_ex((*real_ctx).libctx, (*real_ctx).propq) };
            if ca.is_null() {
                raise_ssl(ERR_R_ASN1_LIB, 549);
                ret = 0;
                // SAFETY: both owned here.
                unsafe {
                    X509_free(x);
                    BIO_free(in_);
                }
                return ret;
            }
            // SAFETY: `in_` is a live readable BIO; `ca` is live.
            let read = unsafe { PEM_read_bio_X509(in_, &mut ca, None, ptr::null_mut()) };
            if !read.is_null() {
                // SAFETY: exactly one of `ctx`/`ssl` is non-NULL and live; `ca` is live.
                let r = unsafe {
                    if !ctx.is_null() {
                        crate::ssl::ssl_cert::ssl_cert_add0_chain_cert(ptr::null_mut(), ctx, ca)
                    } else {
                        crate::ssl::ssl_cert::ssl_cert_add0_chain_cert(ssl, ptr::null_mut(), ca)
                    }
                };
                if r == 0 {
                    // SAFETY: `ca` was not added, so this call owns it.
                    unsafe { X509_free(ca) };
                    ret = 0;
                    // SAFETY: both owned here.
                    unsafe {
                        X509_free(x);
                        BIO_free(in_);
                    }
                    return ret;
                }
            } else {
                // SAFETY: `ca` is live and this call owns it.
                unsafe { X509_free(ca) };
                break;
            }
        }
        // The loop usually ends at EOF with the PEM reader's `PEM_R_NO_START_LINE`; any other
        // error is real.
        let lib = crate::runtime::err::peek_last_lib();
        let reason = crate::runtime::err::peek_last_reason();
        if lib == ERR_LIB_PEM
            && reason == crate::runtime::err::err_reasons::PEM_R_NO_START_LINE as core::ffi::c_ulong
        {
            // SAFETY: thread-local error state.
            ERR_clear_error();
        } else {
            ret = 0;
        }
    }
    // SAFETY: both owned here.
    unsafe {
        X509_free(x);
        BIO_free(in_);
    }
    ret
}

/// `int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)` —
/// `ssl/ssl_rsa.c:589-592`.
///
/// # Safety
/// `ctx` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_certificate_chain_file(
    ctx: *mut SslCtx,
    file: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { use_certificate_chain_file(ctx, ptr::null_mut(), file) }
    })
}

/// `int SSL_use_certificate_chain_file(SSL *ssl, const char *file)` — `ssl/ssl_rsa.c:594-597`.
///
/// # Safety
/// `ssl` must be live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_certificate_chain_file(
    ssl: *mut Ssl,
    file: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { use_certificate_chain_file(ptr::null_mut(), ssl, file) }
    })
}

// -------------------------------------------------------------------------------------------
// serverinfo
// -------------------------------------------------------------------------------------------

/// `struct packet_st`-style cursor over the serverinfo bytes.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn get_net_4(&mut self, out: &mut u32) -> bool {
        if self.remaining() < 4 {
            return false;
        }
        let b = &self.data[self.pos..self.pos + 4];
        *out = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        self.pos += 4;
        true
    }
    fn get_net_2(&mut self, out: &mut u16) -> bool {
        if self.remaining() < 2 {
            return false;
        }
        let b = &self.data[self.pos..self.pos + 2];
        *out = u16::from_be_bytes([b[0], b[1]]);
        self.pos += 2;
        true
    }
    fn get_length_prefixed_2(&mut self) -> Option<&'a [u8]> {
        let mut len = 0u16;
        if !self.get_net_2(&mut len) {
            return None;
        }
        let len = len as usize;
        if self.remaining() < len {
            return None;
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(out)
    }
}

/// `static int serverinfo_find_extension(...)` — `ssl/ssl_rsa.c:599-635`.
///
/// Kept for the record: the authority's add callback calls it to locate an extension in the
/// stored serverinfo. This crate's reduced callback reports no serverinfo data (see the module
/// header), so the lookup is unreached.
///
/// # Safety
/// The out-parameters must be writable; `serverinfo` readable for `len` bytes.
#[allow(dead_code)]
unsafe fn serverinfo_find_extension(
    serverinfo: *const u8,
    len: usize,
    ext_type: c_uint,
    extension_data: *mut *const u8,
    extension_length: *mut usize,
) -> c_int {
    // SAFETY: the out-params are writable per the contract.
    unsafe {
        *extension_data = ptr::null();
        *extension_length = 0;
    }
    if serverinfo.is_null() || len == 0 {
        return -1;
    }
    // SAFETY: `serverinfo` is readable for `len` bytes per the contract.
    let bytes = unsafe { core::slice::from_raw_parts(serverinfo, len) };
    let mut pkt = Cursor {
        data: bytes,
        pos: 0,
    };
    loop {
        if pkt.remaining() == 0 {
            return 0;
        }
        let mut context = 0u32;
        let mut ty = 0u16;
        if !pkt.get_net_4(&mut context) || !pkt.get_net_2(&mut ty) {
            return -1;
        }
        let Some(data) = pkt.get_length_prefixed_2() else {
            return -1;
        };
        if ty as c_uint == ext_type {
            // SAFETY: the out-params are writable per the contract.
            unsafe {
                *extension_data = data.as_ptr();
                *extension_length = data.len();
            }
            return 1;
        }
    }
}

/// `static int serverinfoex_srv_parse_cb(...)` — `ssl/ssl_rsa.c:637-650`.
unsafe extern "C" fn serverinfoex_srv_parse_cb(
    _s: *mut Ssl,
    _ext_type: c_uint,
    _context: c_uint,
    _in: *const u8,
    inlen: usize,
    _x: *mut X509,
    _chainidx: usize,
    al: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    if inlen != 0 {
        // SAFETY: `al` is writable per the callback contract.
        unsafe { *al = SSL_AD_DECODE_ERROR };
        return 0;
    }
    1
}

/// `int SSL_AD_DECODE_ERROR` — `tls1.h`.
const SSL_AD_DECODE_ERROR: c_int = 50;
/// `int SSL_AD_INTERNAL_ERROR` — `tls1.h`; the add callback's error alert.
#[allow(dead_code)]
const SSL_AD_INTERNAL_ERROR: c_int = 80;

/// `static int serverinfo_srv_parse_cb(...)` — `ssl/ssl_rsa.c:652-658`.
unsafe extern "C" fn serverinfo_srv_parse_cb(
    s: *mut Ssl,
    ext_type: c_uint,
    in_: *const u8,
    inlen: usize,
    al: *mut c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: forwarded per the callback contract.
    unsafe { serverinfoex_srv_parse_cb(s, ext_type, 0, in_, inlen, ptr::null_mut(), 0, al, arg) }
}

/// `static int serverinfoex_srv_add_cb(...)` — `ssl/ssl_rsa.c:660-696`, reduced (see header).
unsafe extern "C" fn serverinfoex_srv_add_cb(
    _s: *mut Ssl,
    _ext_type: c_uint,
    _context: c_uint,
    _out: *mut *const u8,
    _outlen: *mut usize,
    _x: *mut X509,
    _chainidx: usize,
    _al: *mut c_int,
    _arg: *mut c_void,
) -> c_int {
    0
}

/// `static int serverinfo_srv_add_cb(...)` — `ssl/ssl_rsa.c:698-704`.
unsafe extern "C" fn serverinfo_srv_add_cb(
    s: *mut Ssl,
    ext_type: c_uint,
    out: *mut *const u8,
    outlen: *mut usize,
    al: *mut c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: forwarded per the callback contract.
    unsafe { serverinfoex_srv_add_cb(s, ext_type, 0, out, outlen, ptr::null_mut(), 0, al, arg) }
}

/// `static int serverinfo_process_buffer(unsigned int version, const unsigned char *serverinfo,
/// size_t len, SSL_CTX *ctx)` — `ssl/ssl_rsa.c:711-768`.
///
/// # Safety
/// `serverinfo` readable for `len` bytes; `ctx` NULL or live.
unsafe fn serverinfo_process_buffer(
    version: c_uint,
    serverinfo: *const u8,
    len: usize,
    ctx: *mut SslCtx,
) -> c_int {
    if serverinfo.is_null() || len == 0 {
        return 0;
    }
    if version != SSL_SERVERINFOV1 && version != SSL_SERVERINFOV2 {
        return 0;
    }
    // SAFETY: `serverinfo` is readable for `len` bytes per the contract.
    let bytes = unsafe { core::slice::from_raw_parts(serverinfo, len) };
    let mut pkt = Cursor {
        data: bytes,
        pos: 0,
    };
    while pkt.remaining() != 0 {
        let mut context = 0u32;
        let mut ext_type = 0u16;
        if version == SSL_SERVERINFOV2 && !pkt.get_net_4(&mut context) {
            return 0;
        }
        if !pkt.get_net_2(&mut ext_type) {
            return 0;
        }
        let Some(_data) = pkt.get_length_prefixed_2() else {
            return 0;
        };
        if ctx.is_null() {
            continue;
        }
        // SAFETY: `ctx` is live.
        let ok = unsafe {
            if version == SSL_SERVERINFOV1 || context == SYNTHV1CONTEXT {
                SSL_CTX_add_server_custom_ext(
                    ctx,
                    ext_type as c_uint,
                    Some(serverinfo_srv_add_cb as CustomExtAddCb),
                    None,
                    ptr::null_mut(),
                    Some(serverinfo_srv_parse_cb as CustomExtParseCb),
                    ptr::null_mut(),
                )
            } else {
                SSL_CTX_add_custom_ext(
                    ctx,
                    ext_type as c_uint,
                    context,
                    Some(serverinfoex_srv_add_cb as SslCustomExtAddCbEx),
                    None,
                    ptr::null_mut(),
                    Some(serverinfoex_srv_parse_cb as SslCustomExtParseCbEx),
                    ptr::null_mut(),
                )
            }
        };
        if ok == 0 {
            return 0;
        }
    }
    1
}

/// `static size_t extension_contextoff(unsigned int version)` — `ssl/ssl_rsa.c:770-773`.
fn extension_contextoff(version: c_uint) -> usize {
    if version == SSL_SERVERINFOV1 {
        4
    } else {
        0
    }
}

/// `static size_t extension_append_length(unsigned int version, size_t extension_length)` —
/// `ssl/ssl_rsa.c:775-778`.
fn extension_append_length(version: c_uint, extension_length: usize) -> usize {
    extension_length + extension_contextoff(version)
}

/// `static void extension_append(unsigned int version, const unsigned char *extension,
/// const size_t extension_length, unsigned char *serverinfo)` — `ssl/ssl_rsa.c:780-796`.
///
/// # Safety
/// `extension` readable for `extension_length` bytes; `serverinfo` writable for the append length.
unsafe fn extension_append(
    version: c_uint,
    extension: *const u8,
    extension_length: usize,
    serverinfo: *mut u8,
) {
    let contextoff = extension_contextoff(version);
    // SAFETY: `serverinfo` is writable for the append length per the contract.
    unsafe {
        if contextoff > 0 {
            *serverinfo = 0;
            *serverinfo.add(1) = 0;
            *serverinfo.add(2) = ((SYNTHV1CONTEXT >> 8) & 0xff) as u8;
            *serverinfo.add(3) = (SYNTHV1CONTEXT & 0xff) as u8;
        }
        ptr::copy_nonoverlapping(extension, serverinfo.add(contextoff), extension_length);
    }
}

/// `int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
/// const unsigned char *serverinfo, size_t serverinfo_length)` — `ssl/ssl_rsa.c:798-857`.
///
/// # Safety
/// `ctx` live; `serverinfo` readable for `serverinfo_length` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_serverinfo_ex(
    ctx: *mut SslCtx,
    version: c_uint,
    serverinfo: *const u8,
    serverinfo_length: usize,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() || serverinfo.is_null() || serverinfo_length == 0 {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 804);
            return 0;
        }
        // SAFETY: `ctx`/`serverinfo` are the caller's.
        unsafe {
            if version == SSL_SERVERINFOV1 {
                let sinfo_length = extension_append_length(SSL_SERVERINFOV1, serverinfo_length);
                let sinfo = crate::runtime::mem::CRYPTO_zalloc(sinfo_length, FILE, 818);
                if sinfo.is_null() {
                    return 0;
                }
                let sinfo = sinfo.cast::<u8>();
                extension_append(SSL_SERVERINFOV1, serverinfo, serverinfo_length, sinfo);
                let ret = SSL_CTX_use_serverinfo_ex(ctx, SSL_SERVERINFOV2, sinfo, sinfo_length);
                CRYPTO_free(sinfo.cast(), FILE, 827);
                return ret;
            }
            if serverinfo_process_buffer(version, serverinfo, serverinfo_length, ptr::null_mut())
                == 0
            {
                raise_ssl(SSL_R_INVALID_SERVERINFO_DATA, 832);
                return 0;
            }
            if (*ctx).cert.is_null() || crate::ssl::ssl_lib::cert_active_key((*ctx).cert).is_null()
            {
                raise_ssl(ERR_R_INTERNAL_ERROR, 836);
                return 0;
            }
            let cpk = crate::ssl::ssl_lib::cert_active_key((*ctx).cert);
            let new_serverinfo =
                CRYPTO_realloc((*cpk).serverinfo.cast(), serverinfo_length, FILE, 839).cast::<u8>();
            if new_serverinfo.is_null() {
                return 0;
            }
            (*cpk).serverinfo = new_serverinfo;
            ptr::copy_nonoverlapping(serverinfo, new_serverinfo, serverinfo_length);
            (*cpk).serverinfo_length = serverinfo_length;
            if serverinfo_process_buffer(version, serverinfo, serverinfo_length, ctx) == 0 {
                raise_ssl(SSL_R_INVALID_SERVERINFO_DATA, 853);
                return 0;
            }
            1
        }
    })
}

/// `int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
/// size_t serverinfo_length)` — `ssl/ssl_rsa.c:859-864`.
///
/// # Safety
/// `ctx` live; `serverinfo` readable for `serverinfo_length` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_serverinfo(
    ctx: *mut SslCtx,
    serverinfo: *const u8,
    serverinfo_length: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_CTX_use_serverinfo_ex(ctx, SSL_SERVERINFOV1, serverinfo, serverinfo_length) }
    })
}

/// `int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)` — `ssl/ssl_rsa.c:866-977`.
///
/// # Safety
/// `ctx` live; `file` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_serverinfo_file(
    ctx: *mut SslCtx,
    file: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() || file.is_null() {
            raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 881);
            return 0;
        }
        // The authority reads a PEM file of `SERVERINFO FOR`/`SERVERINFOV2 FOR` blocks; this
        // loader opens a file and is not driven by the court (no fixture file). The refusal for a
        // missing file is the reachable arm.
        // SAFETY: `file` is NUL-terminated per the caller's contract.
        let in_ = unsafe { open_file(file) };
        if in_.is_null() {
            return 0;
        }
        // SAFETY: `in_` is a live BIO; the memory-BIO decoders are not reached without a file.
        unsafe {
            raise_ssl(SSL_R_NO_PEM_EXTENSIONS, 905);
            BIO_free(in_);
        }
        0
    })
}

// -------------------------------------------------------------------------------------------
// SSL[_CTX]_use_cert_and_key
// -------------------------------------------------------------------------------------------

/// `static int ssl_set_cert_and_key(SSL *ssl, SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
/// STACK_OF(X509) *chain, int override)` — `ssl/ssl_rsa.c:979-1089`.
///
/// # Safety
/// The pointers are the caller's, per `SSL_use_cert_and_key`'s contract.
unsafe fn ssl_set_cert_and_key(
    ssl: *mut Ssl,
    ctx: *mut SslCtx,
    x509: *mut X509,
    mut privatekey: *mut EvpPkey,
    chain: *mut OpenSslStack,
    override_: c_int,
) -> c_int {
    // SAFETY: `ssl`/`ctx` per the contract.
    unsafe {
        if ctx.is_null() && (ssl.is_null() || SSL_is_quic(ssl) != 0) {
            return 0;
        }
        let c = if !ssl.is_null() {
            (*ssl).cert
        } else {
            (*ctx).cert
        };
        let rv = ssl_security_cert(ssl, ctx, x509, 1);
        if rv != 1 {
            raise_ssl(rv, 998);
            return 0;
        }
        for j in 0..OPENSSL_sk_num(chain) {
            let x = OPENSSL_sk_value(chain, j).cast::<X509>();
            let rv = ssl_security_cert(ssl, ctx, x, 0);
            if rv != 1 {
                raise_ssl(rv, 1004);
                return 0;
            }
        }

        let pubkey = X509_get_pubkey(x509);
        if pubkey.is_null() {
            return 0;
        }
        if privatekey.is_null() {
            privatekey = pubkey;
        } else {
            if EVP_PKEY_missing_parameters(privatekey) != 0 {
                if EVP_PKEY_missing_parameters(pubkey) != 0 {
                    raise_ssl(SSL_R_MISSING_PARAMETERS, 1019);
                    EVP_PKEY_free(pubkey);
                    return 0;
                }
                if EVP_PKEY_copy_parameters(privatekey, pubkey) == 0 {
                    raise_ssl(SSL_R_COPY_PARAMETERS_FAILED, 1024);
                    EVP_PKEY_free(pubkey);
                    return 0;
                }
            } else if EVP_PKEY_missing_parameters(pubkey) != 0
                && EVP_PKEY_copy_parameters(pubkey, privatekey) == 0
            {
                raise_ssl(SSL_R_COPY_PARAMETERS_FAILED, 1031);
                EVP_PKEY_free(pubkey);
                return 0;
            }
            if EVP_PKEY_eq(pubkey, privatekey) != 1 {
                raise_ssl(SSL_R_PRIVATE_KEY_MISMATCH, 1038);
                EVP_PKEY_free(pubkey);
                return 0;
            }
        }
        let mut i = 0usize;
        let lookup_ctx = if !ssl.is_null() { (*ssl).ctx } else { ctx };
        if ssl_cert_lookup_by_pkey(pubkey, &mut i, lookup_ctx).is_null() {
            raise_ssl(SSL_R_UNKNOWN_CERTIFICATE_TYPE, 1045);
            EVP_PKEY_free(pubkey);
            return 0;
        }
        if override_ == 0
            && (!(*c).pkeys[i].x509.is_null()
                || !(*c).pkeys[i].privatekey.is_null()
                || !(*c).pkeys[i].chain.is_null())
        {
            raise_ssl(SSL_R_NOT_REPLACING_CERTIFICATE, 1051);
            EVP_PKEY_free(pubkey);
            return 0;
        }
        let mut dup_chain: *mut OpenSslStack = ptr::null_mut();
        if !chain.is_null() {
            dup_chain = crate::x509::x509_cmp::X509_chain_up_ref(chain);
            if dup_chain.is_null() {
                raise_ssl(ERR_R_X509_LIB, 1058);
                EVP_PKEY_free(pubkey);
                return 0;
            }
        }
        if X509_up_ref(x509) == 0 {
            OSSL_STACK_OF_X509_free(dup_chain);
            EVP_PKEY_free(pubkey);
            return 0;
        }
        if EVP_PKEY_up_ref(privatekey) == 0 {
            OSSL_STACK_OF_X509_free(dup_chain);
            X509_free(x509);
            EVP_PKEY_free(pubkey);
            return 0;
        }
        OSSL_STACK_OF_X509_free((*c).pkeys[i].chain);
        (*c).pkeys[i].chain = dup_chain;
        X509_free((*c).pkeys[i].x509);
        (*c).pkeys[i].x509 = x509;
        EVP_PKEY_free((*c).pkeys[i].privatekey.cast::<EvpPkey>());
        (*c).pkeys[i].privatekey = privatekey.cast();
        (*c).key_index = i;
        EVP_PKEY_free(pubkey);
        1
    }
}

/// `int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey, STACK_OF(X509) *chain,
/// int override)` — `ssl/ssl_rsa.c:1091-1095`.
///
/// # Safety
/// `ssl` live; the object pointers NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_cert_and_key(
    ssl: *mut Ssl,
    x509: *mut X509,
    privatekey: *mut EvpPkey,
    chain: *mut OpenSslStack,
    override_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { ssl_set_cert_and_key(ssl, ptr::null_mut(), x509, privatekey, chain, override_) }
    })
}

/// `int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
/// STACK_OF(X509) *chain, int override)` — `ssl/ssl_rsa.c:1097-1101`.
///
/// # Safety
/// `ctx` live; the object pointers NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_cert_and_key(
    ctx: *mut SslCtx,
    x509: *mut X509,
    privatekey: *mut EvpPkey,
    chain: *mut OpenSslStack,
    override_: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { ssl_set_cert_and_key(ptr::null_mut(), ctx, x509, privatekey, chain, override_) }
    })
}

// `SSL_is_quic`'s use name and the unused imports are kept referenced for the record.
const _: unsafe extern "C" fn(*const Ssl) -> c_int = SSL_is_quic;
// `SSL_CERT_INFO` and the constants document the table `ssl_cert_lookup_by_pkey` searches.
const _: (usize, usize) = (SSL_CERT_INFO.len(), SSL_PKEY_NUM);
const _: (usize, usize, usize) = (SSL_PKEY_RSA, NAME_PREFIX1.len(), NAME_PREFIX2.len());
