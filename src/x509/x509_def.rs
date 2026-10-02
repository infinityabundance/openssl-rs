//! Phase 10.14.2 / 11.7a — `crypto/x509/x509_def.c`: the default directory and file names.
//!
//! `crypto/x509/x509_def.c` is 116 lines and publishes six functions. **This module lands all
//! six, on the non-Windows branch**: the two environment-variable names
//! `X509_get_default_cert_dir_env` (`:108-111`) and `X509_get_default_cert_file_env` (`:113-116`),
//! which return the fixed strings `X509_CERT_DIR_EVP`/`X509_CERT_FILE_EVP`
//! (`include/internal/common.h:96-97`, `SSL_CERT_DIR`/`SSL_CERT_FILE`); and the four path
//! functions `X509_get_default_private_dir` (`:68-76`), `X509_get_default_cert_area` (`:78-86`),
//! `X509_get_default_cert_dir` (`:88-96`) and `X509_get_default_cert_file` (`:98-106`).
//!
//! The four paths are the compile-time `OPENSSLDIR` and its children: `X509_PRIVATE_DIR`,
//! `X509_CERT_AREA`, `X509_CERT_DIR` and `X509_CERT_FILE` are
//! `OPENSSLDIR`, `OPENSSLDIR`, `OPENSSLDIR "/certs"` and `OPENSSLDIR "/cert.pem"`
//! (`include/internal/common.h:83-86`). They answer from `OPENSSL_RS_OPENSSLDIR`, a build-time
//! constant `build.rs` captures in exactly the way it captures `OPENSSL_RS_MODULESDIR` — a
//! distribution fact, not an authority one.
//!
//! ## An unset `OPENSSL_RS_OPENSSLDIR` answers an empty C string, never a fabricated path
//!
//! The admitted authority returns its own configure-time `OPENSSLDIR`
//! (`…/prefix/openssl-3.6.4-production/ssl`), a directory this substitute distribution is not
//! installed at, so transcribing that value would have `by_file_ctrl_ex`/`dir_ctrl` open the
//! authority's `/certs` or `/cert.pem`. An unset `OPENSSL_RS_OPENSSLDIR` therefore answers the
//! empty string `c""` — the same honest degradation `ossl_get_modulesdir` makes with NULL
//! (`src/runtime/defaults.rs`), and the `""` idiom `CONF_get1_default_config_file` already
//! answers with. The callers then fail to open a default file or directory rather than opening a
//! path the distribution never intended. `ossl_get_openssldir` and the whole directory plane
//! remain Phase 16's (`src/runtime/defaults.rs`); `OpenSSL_version`'s `OPENSSLDIR: N/A` is
//! recorded under `OBL-INIT-VERSION-DIRS`.
//!
//! The Windows arm (`:17-66`, the `CRYPTO_ONCE` setup, which derives the same four paths at
//! runtime from `ossl_get_openssldir`) is not compiled: this crate is built for the non-Windows
//! branch.
//!
//! `crypto/x509/x509_def.c` raises nothing, so it is deliberately **not** listed in
//! `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, CStr};

/// `X509_CERT_DIR_EVP` — `include/internal/common.h:96`, the environment variable
/// `X509_get_default_cert_dir_env` names.
const X509_CERT_DIR_EVP: &CStr = c"SSL_CERT_DIR";
/// `X509_CERT_FILE_EVP` — `include/internal/common.h:97`, the environment variable
/// `X509_get_default_cert_file_env` names.
const X509_CERT_FILE_EVP: &CStr = c"SSL_CERT_FILE";

/// The build-time certification area (`OPENSSLDIR`), or the empty sentinel the build emits when
/// none was given.
///
/// `build.rs` emits the empty string when `OPENSSL_RS_OPENSSLDIR` is unset, and that is the
/// sentinel the four path functions test: they answer `c""` rather than a fabricated prefix.
const OPENSSLDIR: &str = env!("OPENSSL_RS_OPENSSLDIR");

/// `const char *X509_get_default_private_dir(void)` — `crypto/x509/x509_def.c:68-76`.
///
/// The private-key directory, `X509_PRIVATE_DIR` = `OPENSSLDIR "/private"`. A `'static` C string,
/// so the address is stable and the caller must not free it.
#[no_mangle]
pub extern "C" fn X509_get_default_private_dir() -> *const c_char {
    match OPENSSLDIR {
        "" => c"".as_ptr(),
        _ => private_dir_c(),
    }
}

/// `const char *X509_get_default_cert_area(void)` — `crypto/x509/x509_def.c:78-86`.
///
/// The certification area, `X509_CERT_AREA` = `OPENSSLDIR`. A `'static` C string, so the address
/// is stable and the caller must not free it.
#[no_mangle]
pub extern "C" fn X509_get_default_cert_area() -> *const c_char {
    match OPENSSLDIR {
        "" => c"".as_ptr(),
        _ => openssldir_c(),
    }
}

/// `const char *X509_get_default_cert_dir(void)` — `crypto/x509/x509_def.c:88-96`.
///
/// The certificate directory, `X509_CERT_DIR` = `OPENSSLDIR "/certs"`. A `'static` C string, so
/// the address is stable and the caller must not free it.
#[no_mangle]
pub extern "C" fn X509_get_default_cert_dir() -> *const c_char {
    match OPENSSLDIR {
        "" => c"".as_ptr(),
        _ => cert_dir_c(),
    }
}

/// `const char *X509_get_default_cert_file(void)` — `crypto/x509/x509_def.c:98-106`.
///
/// The certificate bundle file, `X509_CERT_FILE` = `OPENSSLDIR "/cert.pem"`. A `'static` C
/// string, so the address is stable and the caller must not free it.
#[no_mangle]
pub extern "C" fn X509_get_default_cert_file() -> *const c_char {
    match OPENSSLDIR {
        "" => c"".as_ptr(),
        _ => cert_file_c(),
    }
}

/// `const char *X509_get_default_cert_dir_env(void)` — `crypto/x509/x509_def.c:108-111`.
///
/// The name of the environment variable a caller reads to override the certificate directory.
#[no_mangle]
pub extern "C" fn X509_get_default_cert_dir_env() -> *const c_char {
    X509_CERT_DIR_EVP.as_ptr()
}

/// `const char *X509_get_default_cert_file_env(void)` — `crypto/x509/x509_def.c:113-116`.
///
/// The name of the environment variable a caller reads to override the certificate bundle file.
#[no_mangle]
pub extern "C" fn X509_get_default_cert_file_env() -> *const c_char {
    X509_CERT_FILE_EVP.as_ptr()
}

/// The compiled-in `OPENSSLDIR` as a C string.
///
/// Built like `defaults.rs::modulesdir_c`: the `env!` expansion appears exactly once, and the
/// terminator is appended at compile time by `concat!`, so no allocation is involved and the
/// address is stable. `build.rs` rejects a value containing a NUL, so the `Err` arm cannot fire —
/// it is a `match` rather than an `unwrap` because `expect` is denied crate-wide.
fn openssldir_c() -> *const c_char {
    match CStr::from_bytes_with_nul(concat!(env!("OPENSSL_RS_OPENSSLDIR"), "\0").as_bytes()) {
        Ok(s) => s.as_ptr(),
        Err(_) => c"".as_ptr(),
    }
}

/// The compiled-in `OPENSSLDIR "/certs"` as a C string.
fn cert_dir_c() -> *const c_char {
    match CStr::from_bytes_with_nul(concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/certs\0").as_bytes()) {
        Ok(s) => s.as_ptr(),
        Err(_) => c"".as_ptr(),
    }
}

/// The compiled-in `OPENSSLDIR "/cert.pem"` as a C string.
fn cert_file_c() -> *const c_char {
    match CStr::from_bytes_with_nul(
        concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/cert.pem\0").as_bytes(),
    ) {
        Ok(s) => s.as_ptr(),
        Err(_) => c"".as_ptr(),
    }
}

/// The compiled-in `OPENSSLDIR "/private"` as a C string.
fn private_dir_c() -> *const c_char {
    match CStr::from_bytes_with_nul(concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/private\0").as_bytes())
    {
        Ok(s) => s.as_ptr(),
        Err(_) => c"".as_ptr(),
    }
}

#[cfg(test)]
mod tests {
    //! The sentinel rule, and that each answer is the same address twice.
    //!
    //! `alloc` is not linked for unit tests, so no `String` appears below; the expected paths are
    //! `concat!`-built `&'static str`s.

    use super::*;

    #[test]
    fn an_unset_openssldir_answers_an_empty_string_rather_than_a_fabricated_path() {
        // The two cases are exactly the two the build can produce.
        if OPENSSLDIR.is_empty() {
            for p in [
                X509_get_default_cert_area(),
                X509_get_default_cert_dir(),
                X509_get_default_cert_file(),
                X509_get_default_private_dir(),
            ] {
                // An empty C string is a valid non-NULL pointer to a zero-length string, which is
                // what `by_file_ctrl_ex`/`dir_ctrl` then fail to open as a path.
                assert!(
                    !p.is_null(),
                    "an unset OPENSSL_RS_OPENSSLDIR is still a C string"
                );
                // SAFETY: a non-NULL answer is a NUL-terminated literal.
                assert_eq!(unsafe { CStr::from_ptr(p) }.to_bytes(), b"");
            }
        } else {
            let expected = [
                (X509_get_default_cert_area(), OPENSSLDIR),
                (
                    X509_get_default_cert_dir(),
                    concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/certs"),
                ),
                (
                    X509_get_default_cert_file(),
                    concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/cert.pem"),
                ),
                (
                    X509_get_default_private_dir(),
                    concat!(env!("OPENSSL_RS_OPENSSLDIR"), "/private"),
                ),
            ];
            for (got, want) in expected {
                assert!(!got.is_null(), "a set OPENSSL_RS_OPENSSLDIR answers a path");
                // SAFETY: a non-NULL answer is a NUL-terminated literal.
                assert_eq!(unsafe { CStr::from_ptr(got) }.to_str(), Ok(want));
            }
        }
    }

    #[test]
    fn each_answer_is_the_same_address_on_every_call_so_a_caller_may_not_free_it() {
        // SAFETY: the functions take no arguments.
        let (area_a, area_b) = (X509_get_default_cert_area(), X509_get_default_cert_area());
        assert_eq!(area_a, area_b, "a `static` answer is stable");
        // SAFETY: as above.
        let (dir_a, dir_b) = (X509_get_default_cert_dir(), X509_get_default_cert_dir());
        assert_eq!(dir_a, dir_b, "a `static` answer is stable");
        // SAFETY: as above.
        let (file_a, file_b) = (X509_get_default_cert_file(), X509_get_default_cert_file());
        assert_eq!(file_a, file_b, "a `static` answer is stable");
        // SAFETY: as above.
        let (priv_a, priv_b) = (
            X509_get_default_private_dir(),
            X509_get_default_private_dir(),
        );
        assert_eq!(priv_a, priv_b, "a `static` answer is stable");
    }
}
