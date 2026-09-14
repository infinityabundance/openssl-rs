//! Phase 4 — the compressed-stream filter methods, in this build profile.
//!
//! `BIO_f_zlib`, `BIO_f_zstd` and `BIO_f_brotli` are exported by the admitted
//! authority's `libcrypto`, but the admitted build defines `OPENSSL_NO_ZLIB`,
//! `OPENSSL_NO_ZSTD` and `OPENSSL_NO_BROTLI` (`configuration.h`), so each body
//! reduces to `return NULL` with its `RUN_ONCE` compiled out:
//!
//! ```c
//! const BIO_METHOD *BIO_f_zlib(void)
//! {
//! #ifndef OPENSSL_NO_ZLIB
//!     if (RUN_ONCE(&zlib_once, ossl_comp_zlib_init))
//!         return &bio_meth_zlib;
//! #endif
//!     return NULL;
//! }
//! ```
//!
//! That is a **build-profile-scoped** behaviour, not a universal one. A build
//! with zlib enabled exposes a real compression filter BIO there, with its own
//! control words (`BIO_C_SET_COMPRESS_LEVEL`, …) and its own error strings. The
//! custodian contract is scoped to the admitted authority, so reproducing the
//! NULL is correct here — but the obligation ledger records these three as
//! *implemented for profile `openssl-3.6.4-production`*, and the day a
//! zlib-enabled profile is admitted they become three real implementations and a
//! new court, not an edit to this file
//! (`docs/BUILD_MATRIX.md`, `docs/PARITY_MODEL.md`).
//!
//! Returning NULL is not a stub: it is the complete behaviour of the admitted
//! authority, and `RT-BIO-COMP` observes it differentially. A `SCAFFOLDED`
//! abstention would abort; this returns the authority's value.

use core::ptr;

use crate::ffi::guard_ffi;

use super::BioMethod;

/// `const BIO_METHOD *BIO_f_zlib(void)`
///
/// `NULL` in this build profile: `OPENSSL_NO_ZLIB` is defined, so the
/// authority's body is exactly `return NULL`.
#[no_mangle]
pub extern "C" fn BIO_f_zlib() -> *const BioMethod {
    guard_ffi(ptr::null(), ptr::null)
}

/// `const BIO_METHOD *BIO_f_zstd(void)`
///
/// `NULL` in this build profile (`OPENSSL_NO_ZSTD`).
#[no_mangle]
pub extern "C" fn BIO_f_zstd() -> *const BioMethod {
    guard_ffi(ptr::null(), ptr::null)
}

/// `const BIO_METHOD *BIO_f_brotli(void)`
///
/// `NULL` in this build profile (`OPENSSL_NO_BROTLI`).
#[no_mangle]
pub extern "C" fn BIO_f_brotli() -> *const BioMethod {
    guard_ffi(ptr::null(), ptr::null)
}
