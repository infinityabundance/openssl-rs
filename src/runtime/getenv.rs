//! `crypto/getenv.c` — `ossl_safe_getenv`, the environment lookup every part of
//! `libcrypto` uses when it reads an environment variable.
//!
//! ## Why "safe" is a behavioural requirement, not a hardening preference
//!
//! The authority does not call `getenv`. On glibc it calls `secure_getenv`, which
//! returns NULL in a setuid or setgid process — the classic `AT_SECURE` case.
//! That difference is observable: a setuid program that finds `OPENSSL_CONF` set
//! through a plain `getenv` would load an attacker-chosen configuration file,
//! while the authority does not. Reproducing this is therefore part of the
//! contract, not an improvement on it.
//!
//! The authority's other arm — `OPENSSL_issetugid()` followed by `getenv` — is
//! the fallback for platforms without `secure_getenv`. The admitted profile has
//! it, so that arm is not transcribed; a fallback written from a literal would be
//! an unmeasured claim about a platform this crate has not observed.
//!
//! ## Who uses it
//!
//! `conf_def.c` (`ENV` section lookups, `$variable` expansion, the
//! `OPENSSL_CONF_INCLUDE` search path), `conf_mod.c`
//! (`CONF_get1_default_config_file`), and, later, the provider loader's
//! `OPENSSL_MODULES`. It is internal — no symbol is exported — so it lives beside
//! its first consumer stratum rather than in a public header's shadow.

use core::ffi::c_char;

use crate::runtime::bio::sys;

/// `char *ossl_safe_getenv(const char *name)`
///
/// Returns the value, or NULL when the variable is unset *or* when the process is
/// operating with elevated privileges. The returned pointer is owned by the C
/// library: the caller must not free it and must not hold it across a call that
/// could modify the environment.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
pub unsafe fn ossl_safe_getenv(name: *const c_char) -> *mut c_char {
    // SAFETY: `name` is NUL-terminated per the caller's contract.
    unsafe { sys::secure_getenv(name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn reads_a_variable_that_is_set_and_reports_missing_ones() {
        // `std::env::set_var` is the Rust side of the same process environment,
        // so this needs no libc call to arrange. The test is single-threaded
        // with respect to this name.
        std::env::set_var("OPENSSL_RS_GETENV_PROBE", "value");
        let Ok(name) = CString::new("OPENSSL_RS_GETENV_PROBE") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: `name` is a live NUL-terminated string.
        let got = unsafe { ossl_safe_getenv(name.as_ptr()) };
        assert!(!got.is_null());
        // SAFETY: `got` is a NUL-terminated string owned by the C library.
        let text = unsafe { std::ffi::CStr::from_ptr(got) };
        assert_eq!(text.to_str(), Ok("value"));

        let Ok(missing) = CString::new("OPENSSL_RS_GETENV_PROBE_ABSENT") else {
            unreachable!("the literal has no interior NUL");
        };
        // SAFETY: as above.
        assert!(unsafe { ossl_safe_getenv(missing.as_ptr()) }.is_null());
    }
}
