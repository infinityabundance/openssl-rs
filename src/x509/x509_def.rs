//! Phase 10.14.2 — `crypto/x509/x509_def.c`: the default directory and file names.
//!
//! `crypto/x509/x509_def.c` is 116 lines and publishes six functions. **This module lands two of
//! them**: `X509_get_default_cert_dir_env` (`:108-111`) and `X509_get_default_cert_file_env`
//! (`:113-116`), which return the fixed strings `X509_CERT_DIR_EVP`/`X509_CERT_FILE_EVP`
//! (`include/internal/common.h:96-97`, `SSL_CERT_DIR`/`SSL_CERT_FILE`).
//!
//! **The other four are withheld by name, each with its blocker** — the D451 rule, applied at
//! function granularity:
//!
//! | withheld | blocker |
//! |---|---|
//! | `X509_get_default_private_dir` (`:68-76`), `X509_get_default_cert_area` (`:78-86`), `X509_get_default_cert_dir` (`:88-96`), `X509_get_default_cert_file` (`:98-106`) | each returns a compile-time path built from the admitted build's **forensic** `OPENSSLDIR` (`X509_PRIVATE_DIR`/`X509_CERT_AREA`/`X509_CERT_DIR`/`X509_CERT_FILE`, `include/internal/common.h:83-86`). The candidate distribution reports `OPENSSLDIR: N/A` (`src/runtime/init.rs:1133`) and the whole directory plane is Phase 16's (`ossl_get_openssldir`, `src/runtime/defaults.rs`), so a transcription would diverge on every invocation — the same class as D452's `ENGINE_load_builtin_engines`. |
//!
//! The Windows arm (`:17-66`, the `CRYPTO_ONCE` setup) belongs to those four and is withheld with
//! them; this crate is built for the non-Windows branch.
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
