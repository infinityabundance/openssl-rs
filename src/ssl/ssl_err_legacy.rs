//! Phase 14.10 — `ssl/ssl_err_legacy.c`: the legacy error-string loader.
//!
//! The whole of the unit: `ERR_load_SSL_strings`, the deprecated spelling of the
//! `OPENSSL_INIT_LOAD_SSL_STRINGS` initialisation. The authority's `#ifndef
//! OPENSSL_NO_DEPRECATED_3_0` arm is taken (the profile admits the deprecated API), so the
//! function is not the `NON_EMPTY_TRANSLATION_UNIT` alternative.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::runtime::init::OPENSSL_init_crypto;

/// `OPENSSL_INIT_LOAD_SSL_STRINGS` — `ssl.h:2827`.
const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x0020_0000;

/// `int ERR_load_SSL_strings(void)` — `ssl/ssl_err_legacy.c:15-18`.
///
/// The authority's body is `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_SSL_STRINGS, 0)`. The flag is
/// claimed by the initialiser's `RUN_ONCE_ALT` partnership, so a second call answers the recorded
/// success without reloading, which is the "absence of a duplicate load" 14.10's plan names.
///
/// # Safety
/// The authority's second argument is a null `OPENSSL_INIT_SETTINGS *`; no precondition.
#[no_mangle]
pub extern "C" fn ERR_load_SSL_strings() -> c_int {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_SSL_STRINGS, ptr::null())
}
