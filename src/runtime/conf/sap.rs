//! `crypto/conf/conf_sap.c` — the legacy automatic configuration loader.
//!
//! ## Why `OPENSSL_config` is a wrapper and not a loader
//!
//! The authority's body is seven lines and every one of them is a call into
//! something else:
//!
//! ```c
//! void OPENSSL_config(const char *appname)
//! {
//!     OPENSSL_INIT_SETTINGS settings;
//!
//!     memset(&settings, 0, sizeof(settings));
//!     if (appname != NULL)
//!         settings.appname = strdup(appname);
//!     settings.flags = DEFAULT_CONF_MFLAGS;
//!     OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, &settings);
//!
//!     free(settings.appname);
//! }
//! ```
//!
//! So the function's whole content is the *shape of the settings object* it hands
//! over, and that shape is three details worth naming because each is observable
//! in a different way:
//!
//! * the settings are **zeroed on the stack**, not built by `OPENSSL_INIT_new`.
//!   The observable difference is the allocation, not the values: `OPENSSL_INIT_new`
//!   installs the same `DEFAULT_CONF_MFLAGS`, so a reader comparing the two paths
//!   sees the same call into `OPENSSL_init_crypto`.
//! * `appname` is duplicated with **libc `strdup`** and released with **libc
//!   `free`**, not with `CRYPTO_malloc`/`CRYPTO_free`. That matters under an
//!   installable allocator (`CRYPTO_set_mem_functions`) or the secure heap: a
//!   debug build that counted OpenSSL allocations would count this one twice if
//!   the pairing were mismatched, and the authority's pairing is libc-to-libc.
//! * a NULL `appname` leaves the field NULL rather than pointing it at an empty
//!   string, and `free(NULL)` is then the release. Both halves are defined.
//!
//! ## What is not here
//!
//! `ossl_config_int` and `ossl_no_config_int` are internal (declared in
//! `internal/conf.h`, not installed) and are what `OPENSSL_init_crypto`'s
//! `OPENSSL_INIT_LOAD_CONFIG` step calls. That step currently *accepts* having
//! loaded nothing, which is the authority's answer when no config file exists;
//! applying a config that does exist needs `CONF_modules_load_file_ex`, which is
//! Phase 6.9's obligation because the module registry is. This file therefore
//! routes through the same `OPENSSL_init_crypto` the authority uses and inherits
//! exactly that state, rather than growing a second configuration path.

use core::ffi::{c_char, c_void};

use crate::runtime::bio::sys;
use crate::runtime::conf::init_settings::stack_settings;
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_LOAD_CONFIG};

/// `void OPENSSL_config(const char *appname)`
///
/// The deprecated automatic loader. Present in this profile because
/// `OPENSSL_NO_DEPRECATED_1_1_0` is **not** defined — measured in the court, not
/// inferred from the absence of a `no-deprecated` option, because `3_0` and `1_1_0`
/// are separate guards and only one of them being absent would still compile this
/// body out.
///
/// The return value is discarded, as the authority's is: a caller who needs to
/// know whether configuration succeeded calls `OPENSSL_init_crypto` themselves, and
/// every reason string of the failure is on the error queue.
///
/// # Safety
/// `appname` must be NULL or a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_config(appname: *const c_char) {
    let mut dup: *mut c_char = core::ptr::null_mut();
    if !appname.is_null() {
        // SAFETY: `appname` is NUL-terminated per the caller's contract.
        dup = unsafe { sys::strdup(appname) };
    }
    let settings = stack_settings(dup);
    // `OPENSSL_init_crypto` is not an `unsafe fn`: it is a safe C entry point that
    // validates its own arguments and reports failure through the error queue and
    // its return value. The settings object is live and correctly laid out for the
    // duration of the call, which is the most it can require of a caller.
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, &settings);
    // SAFETY: `dup` came from `strdup` and is released exactly once; `free(NULL)`
    // is defined, which is the authority's release path for the NULL case.
    unsafe { sys::free(dup.cast::<c_void>()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::conf::init_settings::{OPENSSL_INIT_free, OPENSSL_INIT_new};

    #[test]
    fn a_null_appname_is_accepted_and_the_crate_survives_it() {
        // The behaviour a caller observes is that this returns, and that the
        // settings it built internally were the same shape `OPENSSL_INIT_new`
        // produces. The second half is checkable without re-running the loader,
        // because the flag word is the same constant.
        // SAFETY: NULL is a defined argument.
        unsafe { OPENSSL_config(core::ptr::null()) };

        // SAFETY: the settings object is live and correctly laid out.
        unsafe {
            let s = OPENSSL_INIT_new();
            assert!(!s.is_null());
            OPENSSL_INIT_free(s);
        }
    }

    #[test]
    fn a_named_appname_is_duplicated_with_libc_semantics() {
        let name = c"openssl-rs-test-app";
        // SAFETY: `name` is a static NUL-terminated literal.
        unsafe { OPENSSL_config(name.as_ptr()) };
    }
}
