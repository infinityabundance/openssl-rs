//! Phase 14.10 — `ssl/ssl_init.c`: `OPENSSL_init_ssl`.
//!
//! The unit's one export. The authority folds the two legacy-adder bits and the config bit into the
//! caller's options, defers to `OPENSSL_init_crypto`, and then runs its one `RUN_ONCE` base step
//! (`ossl_init_ssl_base`, `ssl_init.c:24-39`) which initialises the built-in compression methods and
//! sorts the cipher list.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The `stopped` refusal arm is not reproduced.** The authority's file-local `stopped`
//!   (`ssl_init.c:20`) is read at `ssl_init.c:50` and **never assigned anywhere in the unit**, so
//!   the arm is dead code; the reachable refusal is `OPENSSL_init_crypto`'s own. This crate
//!   therefore omits the dead branch rather than carrying a static that can never become true.
//! * **`ssl_sort_cipher_list` is omitted.** The authority's base step calls it to sort the static
//!   `ssl3_ciphers` table (`ssl_ciph.c`). This crate's cipher tables are the parser's own
//!   (`src/ssl/ssl_ciph.rs`) and carry no order the base step must establish; nothing reads the
//!   sortedness. `SSL_COMP_get_compression_methods` (14.3's) is called as the authority calls it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use std::sync::Once;

use crate::ffi::guard_ffi;
use crate::runtime::init::{
    OPENSSL_init_crypto, OpenSslInitSettings, OPENSSL_INIT_ADD_ALL_CIPHERS,
    OPENSSL_INIT_ADD_ALL_DIGESTS, OPENSSL_INIT_LOAD_CONFIG,
};

/// `OPENSSL_INIT_NO_LOAD_CONFIG` — `crypto.h:172`.
const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;

/// `CRYPTO_ONCE ssl_base` — `ssl_init.c:22`, the one base initialiser.
static SSL_BASE: Once = Once::new();

/// `ossl_init_ssl_base` — `ssl_init.c:24-39`, reduced as the module header records.
fn ossl_init_ssl_base() {
    // SAFETY: the compression-method initialiser touches only the process-global registry.
    unsafe { crate::ssl::ssl_ciph::SSL_COMP_get_compression_methods() };
}

/// `int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)` —
/// `ssl/ssl_init.c:46-77`.
///
/// # Safety
/// `settings` must be NULL or a live `OPENSSL_INIT_SETTINGS` that also satisfies
/// [`OPENSSL_init_crypto`]'s settings contract, because this function forwards the
/// pointer there unchanged: its `filename` and `appname` fields must each be NULL or
/// NUL-terminated C strings that stay live until this function returns, and the object
/// itself must not be moved, freed, or concurrently written for the duration of this
/// call. Stating the full contract here matters: a caller that satisfies only "NULL or
/// a live settings object" could still drive the callee's data race or read past a
/// non-terminated `filename`.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_init_ssl(
    opts: u64,
    settings: *const OpenSslInitSettings,
) -> c_int {
    guard_ffi(0, || {
        let mut opts = opts;
        // `opts |= OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS;` (`ssl_init.c:63-64`).
        opts |= OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS;
        // `#ifndef OPENSSL_NO_AUTOLOAD_CONFIG` (`ssl_init.c:65-68`).
        if opts & OPENSSL_INIT_NO_LOAD_CONFIG == 0 {
            opts |= OPENSSL_INIT_LOAD_CONFIG;
        }
        // SAFETY: `settings` is NULL or a live `OPENSSL_INIT_SETTINGS` whose `filename`
        // and `appname` fields are NUL-terminated and stay live for this call, per this
        // function's contract, which restates the callee's requirement because the
        // pointer is forwarded unchanged.
        if unsafe { OPENSSL_init_crypto(opts, settings) } == 0 {
            return 0;
        }
        // `RUN_ONCE(&ssl_base, ossl_init_ssl_base)` (`ssl_init.c:73`); the step cannot fail here.
        SSL_BASE.call_once(ossl_init_ssl_base);
        1
    })
}
