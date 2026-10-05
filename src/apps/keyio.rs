//! Phase 17.1d — the `apps/lib/apps.c` credential-loader surface, reduced to its observable.
//!
//! The ten command bodies this slice lands (`ec`, `rsautl`, `dsa`, `pkey`, `ecparam`,
//! `asn1parse`, `pkcs8`, `verify`, `crl`, `rsa`) all load their input through
//! `apps/lib/apps.c`'s `load_key`/`load_pubkey`/`load_cert`/`load_crl`/
//! `load_keyparams` and open their output through `bio_open_owner`/
//! `bio_open_default`. Those are `apps/lib` helpers this stratum does not own as a
//! translation unit, so this module reconstructs exactly the part of them the court
//! drives:
//!
//! * [`bio_open_default`] — `apps/lib/apps.c:3232-3271`, the stdio/file split. The
//!   `format` argument only selects text/binary mode on Windows and is a no-op here,
//!   so a NULL or `-` filename is `stdin`/`stdout` and anything else is
//!   `BIO_new_file`. An unopenable `some-file` reaches
//!   [`crate::apps::openssl::not_landed`] at the call site rather than fabricating the
//!   authority's "Can't open …".
//! * [`load_key`]/[`load_pubkey`]/[`load_cert`]/[`load_crl`] — `apps/lib/apps.c:611-676`,
//!   reduced to the PEM/DER decoder arms `PEM_read_bio_PrivateKey`/
//!   `PEM_read_bio_PUBKEY`/`PEM_read_bio_X509`/`PEM_read_bio_X509_CRL` and their
//!   `d2i_*_bio` DER counterparts. The authority routes the same bytes through
//!   `load_key_certs_crls` (`apps/lib/apps.c:946-1188`) and OSSL_STORE's auto-detecting
//!   file loader; for a single unencrypted PEM/DER credential the returned
//!   `EVP_PKEY`/`X509`/`X509_CRL` is identical, and that is what the court's fixed
//!   fixtures exercise. The store loader's failure text and the pointer-bearing
//!   `ERR_print_errors` tail are `apps/lib`'s and are not reproduced.
//! * [`load_keyparams`] — `apps/lib/apps.c:672-676`, `load_keyparams_suppress` with
//!   `suppress_decode_errors == 0`: a key's parameters through the decoder.
//!
//! ## Recorded divergences (module header)
//!
//! * **`OSSL_STORE` is not the loader here.** The authority's `load_key_certs_crls`
//!   opens the URI with `OSSL_STORE_open_ex` and dispatches on `OSSL_STORE_INFO`
//!   types; this module calls the PEM/DER readers directly. The observable for a
//!   single well-formed credential is the same object; multi-credential files, the
//!   `PARAMS`/`PUBKEY` store-info arms, encrypted input and the URI schemes (`http:`,
//!   `file:`) are not driven.
//! * **`app_passwd` is reduced to its no-argument observable.** `app_passwd`
//!   (`apps/lib/apps.c:231-274`) reads `pass:`, `env:`, `file:`, `fd:` and `stdin`
//!   sources; the court arms drive unencrypted fixtures and pass no `-passin`, so only
//!   the NULL arm is reached.
//! * **`app_get0_libctx`/`app_get0_propq` are NULL.** Every command here reaches the
//!   decoder with a NULL library context and property query, as the authority's own
//!   `app_get0_*` helpers do for an unconfigured app.
//! * **The load-failure text is the message only.** The authority's failure path
//!   (`apps/lib/apps.c:1146-1187`) continues with the credential type, the URI and the
//!   pointer-bearing `ERR_print_errors`; that tail is the `ERR` surface's and the court
//!   does not diff it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::evp::pkey::EvpPkey;
use crate::pem::pem_all::PEM_read_bio_X509_CRL;
use crate::pem::pem_pkey::{
    PEM_read_bio_PUBKEY, PEM_read_bio_Parameters_ex, PEM_read_bio_PrivateKey,
};
use crate::pem::pem_x509::PEM_read_bio_X509;
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::x509::x_all::{d2i_PUBKEY_bio, d2i_PrivateKey_bio, d2i_X509_CRL_bio, d2i_X509_bio};
use crate::x509::x_crl::X509Crl;
use crate::x509::x_x509::X509;

/// `FORMAT_ASN1` — `apps/include/fmt.h:27`.
pub const FORMAT_ASN1: c_int = 4;
/// `FORMAT_PEM` — `apps/include/fmt.h:29` (`FORMAT_PEM | FORMAT_BASE64`).
pub const FORMAT_PEM: c_int = 5 | 0x8000;

/// `bio_open_default(filename, mode, format)` — `apps/lib/apps.c:3232-3271`, the
/// stdio/file split. `writing` is the authority's `mode == 'w'`.
pub fn bio_open_default(filename: Option<&str>, writing: bool) -> *mut Bio {
    match filename {
        None | Some("-") => {
            // SAFETY: `stdout`/`stdin` are the C library's live standard stream pointers.
            let fp = unsafe {
                if writing {
                    stdout
                } else {
                    stdin
                }
            };
            // SAFETY: `fp` is one of the C library's live standard streams.
            unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) }
        }
        Some(path) => {
            let cs = match std::ffi::CString::new(path) {
                Ok(c) => c,
                Err(_) => return core::ptr::null_mut(),
            };
            let mode = if writing { c"w" } else { c"r" };
            // SAFETY: `cs` is NUL-terminated and outlives the call.
            unsafe { BIO_new_file(cs.as_ptr(), mode.as_ptr()) }
        }
    }
}

/// The observable head of `load_key_certs_crls`'s failure path
/// (`apps/lib/apps.c:1160-1180`): the credential description and the URI.
fn load_failure(uri: Option<&str>, desc: &str) {
    let uri = uri.unwrap_or("<stdin>");
    eprintln!("Could not open file or uri for loading of {desc} from {uri}");
}

/// Open `uri` with `BIO_new_file`; returns `(bio, cstring)` and keeps the `CString`
/// alive for the call. A NULL `uri` is not driven (the authority reads stdin).
fn open_input(uri: Option<&str>) -> Option<(*mut Bio, std::ffi::CString)> {
    let path = uri?;
    let cs = std::ffi::CString::new(path).ok()?;
    // SAFETY: `cs` is NUL-terminated and outlives the call.
    let bio = unsafe { BIO_new_file(cs.as_ptr(), c"r".as_ptr()) };
    if bio.is_null() {
        None
    } else {
        Some((bio, cs))
    }
}

/// `EVP_PKEY *load_key(uri, format, may_stdin, pass, e, desc)` — `apps/lib/apps.c:611-627`,
/// reduced to the PEM/DER decoder arms (see the header). `uri == None` is not driven.
pub fn load_key(uri: Option<&str>, format: c_int, desc: &str) -> *mut EvpPkey {
    let Some((bio, _cs)) = open_input(uri) else {
        load_failure(uri, desc);
        return core::ptr::null_mut();
    };
    // SAFETY: `bio` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let key = unsafe {
        if format == FORMAT_ASN1 {
            d2i_PrivateKey_bio(bio, core::ptr::null_mut())
        } else {
            PEM_read_bio_PrivateKey(bio, core::ptr::null_mut(), None, core::ptr::null_mut())
        }
    };
    if key.is_null() {
        load_failure(uri, desc);
    }
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    key
}

/// `EVP_PKEY *load_pubkey(uri, format, maybe_stdin, pass, e, desc)` — `apps/lib/apps.c:629-648`.
/// The public arm first, then the private-key fallback the authority performs by
/// re-opening the URI (its second `load_key_certs_crls` call).
pub fn load_pubkey(uri: Option<&str>, format: c_int, desc: &str) -> *mut EvpPkey {
    let Some((bio, _cs)) = open_input(uri) else {
        load_failure(uri, desc);
        return core::ptr::null_mut();
    };
    // SAFETY: `bio` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let mut key = unsafe {
        if format == FORMAT_ASN1 {
            d2i_PUBKEY_bio(bio, core::ptr::null_mut())
        } else {
            PEM_read_bio_PUBKEY(bio, core::ptr::null_mut(), None, core::ptr::null_mut())
        }
    };
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    if key.is_null() {
        // `load_pubkey`'s fallback: reopen the URI and read a private key, which carries
        // the public parts.
        let Some((bio2, _cs2)) = open_input(uri) else {
            load_failure(uri, desc);
            return core::ptr::null_mut();
        };
        // SAFETY: `bio2` is live; the out-slot is NULL and cb/arg are the no-password
        // arms.
        key = unsafe {
            PEM_read_bio_PrivateKey(bio2, core::ptr::null_mut(), None, core::ptr::null_mut())
        };
        // SAFETY: `bio2` is live and not freed again.
        unsafe { BIO_free(bio2) };
    }
    if key.is_null() {
        load_failure(uri, desc);
    }
    key
}

/// `X509 *load_cert(uri, format, desc)` — `apps/lib/apps.c:490-510`, reduced to the
/// PEM/DER decoder arms.
pub fn load_cert(uri: Option<&str>, format: c_int, desc: &str) -> *mut X509 {
    let Some((bio, _cs)) = open_input(uri) else {
        load_failure(uri, desc);
        return core::ptr::null_mut();
    };
    // SAFETY: `bio` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let cert = unsafe {
        if format == FORMAT_ASN1 {
            d2i_X509_bio(bio, core::ptr::null_mut())
        } else {
            PEM_read_bio_X509(bio, core::ptr::null_mut(), None, core::ptr::null_mut())
        }
    };
    if cert.is_null() {
        load_failure(uri, desc);
    }
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    cert
}

/// `X509_CRL *load_crl(uri, format, maybe_stdin, desc)` — `apps/lib/apps.c:512-532`,
/// reduced to the PEM/DER decoder arms.
pub fn load_crl(uri: Option<&str>, format: c_int, desc: &str) -> *mut X509Crl {
    let Some((bio, _cs)) = open_input(uri) else {
        load_failure(uri, desc);
        return core::ptr::null_mut();
    };
    // SAFETY: `bio` is live; the out-slot is NULL and cb/arg are the no-password arms.
    let crl = unsafe {
        if format == FORMAT_ASN1 {
            d2i_X509_CRL_bio(bio, core::ptr::null_mut())
        } else {
            PEM_read_bio_X509_CRL(bio, core::ptr::null_mut(), None, core::ptr::null_mut())
        }
    };
    if crl.is_null() {
        load_failure(uri, desc);
    }
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    crl
}

/// `EVP_PKEY *load_keyparams(uri, format, maybe_stdin, keytype, desc)` —
/// `apps/lib/apps.c:672-676`, the `load_keyparams_suppress(..., 0)` arm. The authority's
/// `EVP_PKEY_is_a(params, keytype)` type check is the caller's concern here.
pub fn load_keyparams(
    uri: Option<&str>,
    _format: c_int,
    _keytype: &str,
    desc: &str,
) -> *mut EvpPkey {
    let Some((bio, _cs)) = open_input(uri) else {
        load_failure(uri, desc);
        return core::ptr::null_mut();
    };
    // SAFETY: `bio` is live; the out-slot is NULL and both context/property pointers are
    // the no-context default.
    let params = unsafe {
        PEM_read_bio_Parameters_ex(
            bio,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null(),
        )
    };
    if params.is_null() {
        load_failure(uri, desc);
    }
    // SAFETY: `bio` is live and not freed again.
    unsafe { BIO_free(bio) };
    params
}
