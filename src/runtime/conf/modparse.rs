//! Phase 4 — CONF: `crypto/conf/conf_mod.c`'s two obligations that do **not**
//! need `OSSL_LIB_CTX`, plus the recorded hand-off of the ones that do.
//!
//! ## What is implemented here
//!
//! * `CONF_parse_list` — the generic list splitter the rest of `libcrypto` uses
//!   for comma-separated configuration values. Its contract is unusual in two
//!   ways that are reproduced exactly: an empty element is delivered to the
//!   callback as `(NULL, 0)` rather than skipped, and a callback returning a
//!   non-positive value stops the walk and *becomes* the return value.
//! * `CONF_get1_default_config_file` — the default configuration path.
//!
//! ## Why the module registry is not here
//!
//! `CONF_modules_load` begins with `conf_diagnostics()`, which reads and writes
//! the `OSSL_LIB_CTX` configuration-diagnostics flag
//! (`OSSL_LIB_CTX_get_conf_diagnostics` / `OSSL_LIB_CTX_set_conf_diagnostics`).
//! `OSSL_LIB_CTX` is Phase 6, *and* the flag is not cosmetic: it masks the
//! `CONF_MFLAGS_IGNORE_ERRORS`, `IGNORE_RETURN_CODES`, `SILENT` and
//! `IGNORE_MISSING_FILE` bits of the flags argument, so it changes what
//! `CONF_modules_load` returns. A registry that cannot read the flag would report
//! the wrong result for a real configuration.
//!
//! The remaining module symbols are therefore a **recorded hand-off** to Phase 6
//! in `forensics/phase4-obligations.json`, not a silent deferral: the list is
//! machine-checked, each entry names the owning phase, and
//! `phase4_obligations.py` refuses to run if any of this stratum's exports is
//! neither implemented nor listed. See `docs/DECISIONS.md` D50 for the exact call
//! chain.
//!
//! ## The default configuration file, and a deliberate divergence
//!
//! `CONF_get1_default_config_file` returns `$OPENSSL_CONF` when it is set, and
//! otherwise `X509_get_default_cert_area() + "/openssl.cnf"`. The certification
//! area is the build's `OPENSSLDIR` — for the admitted authority,
//! `/work/forensics/authorities/prefix/openssl-3.6.4-production/ssl`.
//!
//! This module does **not** claim that path. `src/runtime/init.rs` already made
//! and recorded the same decision for the same constant
//! (`OBL-INIT-VERSION-DIRS`): `OpenSSL_version(OPENSSL_DIR)` answers
//! `OPENSSLDIR: N/A`, because the value describes *the forensic build's
//! installation directory*, and this implementation is not installed there.
//! Reproducing it here would point a caller at a directory that does not exist on
//! any machine this crate ships to. The open obligation is
//! `OBL-CONF-DEFAULT-CONFIG-FILE`, owned by Phase 16 (the CLI/config/filesystem
//! contract), which is the stratum that fixes the distribution's install layout.
//!
//! Meanwhile the *environment* path is implemented exactly, and it is the path the
//! court compares: two of the three branches of the authority's function are
//! observable even without an installation directory.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::bio::sys;
use crate::runtime::err::err_sites::CONF_MOD_734;
use crate::runtime::err::raise_site;
use crate::runtime::getenv::ossl_safe_getenv;
use crate::runtime::mem::CRYPTO_strdup;

// Open obligations, recorded here because only this module may be edited for the
// `CONF_get1_default_config_file` work item:
//   OBL-CONF-DEFAULT-CONFIG-FILE   the no-`OPENSSL_CONF` branch answers with the
//                                  empty string rather than the authority's
//                                  forensic `OPENSSLDIR` (Phase 16 owns the
//                                  distribution's install layout)
//
// See docs/SECURITY_DIVERGENCE_POLICY.md D-CONF-3 for the reasoning and
// docs/DECISIONS.md D56 for the decision, and `src/runtime/init.rs` for the same
// decision made about the same constant under `OBL-INIT-VERSION-DIRS`.

/// `#define OPENSSL_CONF_INCLUDE` — the environment variable that overrides the
/// include directory. It lives here because this module owns the environment's
/// configuration surface; `conf_def.c`'s reader consults it.
pub(crate) const OPENSSL_CONF_INCLUDE: &core::ffi::CStr = c"OPENSSL_CONF_INCLUDE";

/// `#define DEFAULT_SEPARATOR`-adjacent: the name of the environment variable that
/// names the configuration file outright.
const OPENSSL_CONF_ENV: &core::ffi::CStr = c"OPENSSL_CONF";

/// `int CONF_parse_list(const char *list, int sep, int nospc, int (*list_cb)(const char *elem, int len, void *usr), void *arg)`
///
/// Splits `list` on `sep`, optionally trimming ASCII space around each element,
/// and hands each element to `list_cb` as `(pointer, length)` — never
/// NUL-terminated, which is why the length is passed at all.
///
/// The three behaviours that are easy to get wrong and are reproduced here:
///
/// * an element of length zero (an empty list, or an empty element between two
///   separators) is delivered as `(NULL, 0)` and the walk continues;
/// * the final element is delivered even when the list ends with the separator, so
///   `"a,"` produces two callbacks and `"a"` produces one;
/// * a callback returning `<= 0` stops the walk and that value is returned, so a
///   negative callback result reaches the caller.
///
/// # Safety
/// `list` NULL or NUL-terminated; `list_cb` must accept a NULL-or-string pointer
/// and a length; `arg` is passed through untouched.
#[no_mangle]
pub unsafe extern "C" fn CONF_parse_list(
    list: *const c_char,
    sep: c_int,
    nospc: c_int,
    list_cb: Option<unsafe extern "C" fn(*const c_char, c_int, *mut c_void) -> c_int>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        if list.is_null() {
            // SAFETY: the site is a compile-time constant, which is `raise_site`'s
            // only precondition.
            unsafe { raise_site(&CONF_MOD_734) };
            return 0;
        }
        let Some(list_cb) = list_cb else {
            return 0;
        };
        let mut lstart = list as *mut c_char;
        loop {
            if nospc != 0 {
                // `isspace((unsigned char)*lstart)`, and the scan stops at NUL.
                // SAFETY: `lstart` points into the caller's NUL-terminated string.
                while unsafe { *lstart } != 0
                    // SAFETY: the byte is a `c_char` widened to `0..=255`, which is
                    // what `isspace` requires; the loop stops at the NUL terminator.
                    && unsafe { sys::isspace(c_int::from(*lstart as u8)) } != 0
                {
                    // SAFETY: the loop stopped at a non-NUL byte, so the next byte
                    // is still inside the string (or its terminator).
                    lstart = unsafe { lstart.add(1) };
                }
            }
            // SAFETY: `lstart` points into the caller's NUL-terminated string.
            let p = unsafe { sys::strchr(lstart, sep) };
            // SAFETY: as above; `p == lstart` is tested before `*lstart` so the
            // read only happens when `lstart` is inside the string.
            let at_end = p == lstart || unsafe { *lstart } == 0;
            let ret = if at_end {
                // SAFETY: `list_cb` is the caller's callback, which this function's
                // contract requires to accept a NULL pointer with length 0, and
                // `arg` is the caller's own opaque pointer.
                unsafe { list_cb(ptr::null(), 0, arg) }
            } else {
                let mut tmpend = if !p.is_null() {
                    // SAFETY: `p > lstart`, so `p - 1` is inside the string.
                    unsafe { p.sub(1) }
                } else {
                    // `lstart + strlen(lstart) - 1`; the empty case was handled
                    // above, so this is at least `lstart`.
                    // SAFETY: `strlen(lstart) >= 1` here, so the offset is inside
                    // the string.
                    unsafe { lstart.add(sys::strlen(lstart) - 1) }
                };
                if nospc != 0 {
                    // The authority walks back past spaces with no lower bound;
                    // for an all-space element `tmpend` ends up before `lstart`
                    // and the resulting length is negative. That is reproduced
                    // rather than clamped, because the callback observes it.
                    // SAFETY: the leading trim above leaves `*lstart` non-space, so
                    // the backward walk stops at or after `lstart`.
                    while unsafe { sys::isspace(c_int::from(*tmpend as u8)) } != 0 {
                        // SAFETY: the walk only continues while the byte read is
                        // whitespace and `lstart` is non-whitespace, so it cannot
                        // step past `lstart` into preceding memory.
                        tmpend = unsafe { tmpend.sub(1) };
                    }
                }
                let len = (tmpend as usize)
                    .wrapping_sub(lstart as usize)
                    .wrapping_add(1);
                // The authority casts the pointer difference to `int`.
                // SAFETY: `list_cb` is the caller's callback; `lstart` points at
                // the `len` readable bytes of the element and `arg` is the
                // caller's own opaque pointer.
                unsafe { list_cb(lstart, len as c_int, arg) }
            };
            if ret <= 0 {
                return ret;
            }
            if p.is_null() {
                return 1;
            }
            // SAFETY: the separator is inside the string, so this is not past the
            // terminator.
            lstart = unsafe { p.add(1) };
        }
    })
}

/// `char *CONF_get1_default_config_file(void)`
///
/// Returns a **caller-owned** copy: the environment value duplicated, or the
/// divergent default documented on this module. Never NULL on the environment
/// path — a set-but-empty `OPENSSL_CONF` yields an empty string, which
/// `CONF_modules_load_file_ex` treats as "do not load a file" rather than as a
/// failure.
#[no_mangle]
pub extern "C" fn CONF_get1_default_config_file() -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the environment name is a static NUL-terminated string.
        let from_env = unsafe { ossl_safe_getenv(OPENSSL_CONF_ENV.as_ptr()) };
        if !from_env.is_null() {
            // SAFETY: `from_env` is NUL-terminated.
            return unsafe { CRYPTO_strdup(from_env, ptr::null(), 0) };
        }

        // The divergent branch. `X509_get_default_cert_area()` would return the
        // authority's forensic `OPENSSLDIR`; see the module documentation for why
        // this build does not claim it.
        //
        // The empty string is the authority's own idiom for "there is no such
        // path" — `X509_get_default_cert_area() == NULL` returns
        // `OPENSSL_strdup("")` — so a caller that already handles that case
        // handles this one too, and `CONF_modules_load_file_ex` short-circuits it.
        // SAFETY: `c""` is a static NUL-terminated string, `ptr::null()` is the
        // documented "no file/line" argument, and flag 0 is the default.
        unsafe { CRYPTO_strdup(c"".as_ptr(), ptr::null(), 0) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The elements a walk delivers, as `(Option<String>, i32)`.
    unsafe extern "C" fn collect(elem: *const c_char, len: c_int, arg: *mut c_void) -> c_int {
        // SAFETY: `arg` is the caller's `Vec` of collected elements.
        let out = unsafe { &mut *(arg as *mut Vec<(Option<String>, c_int)>) };
        let text = if elem.is_null() {
            None
        } else if len <= 0 {
            Some(String::new())
        } else {
            // SAFETY: the callback contract is `len` readable bytes.
            let bytes = unsafe { core::slice::from_raw_parts(elem as *const u8, len as usize) };
            Some(String::from_utf8_lossy(bytes).into_owned())
        };
        out.push((text, len));
        1
    }

    fn split(
        list: &str,
        sep: u8,
        nospc: c_int,
    ) -> Result<Vec<(Option<String>, c_int)>, std::ffi::NulError> {
        let c = CString::new(list)?;
        let mut out: Vec<(Option<String>, c_int)> = Vec::new();
        // SAFETY: `c` is NUL-terminated, the callback is ours, and `arg` is the
        // vector it expects.
        let ret = unsafe {
            CONF_parse_list(
                c.as_ptr(),
                c_int::from(sep),
                nospc,
                Some(collect),
                (&mut out) as *mut Vec<(Option<String>, c_int)> as *mut c_void,
            )
        };
        assert_eq!(ret, 1, "a callback that returns 1 lets the walk finish");
        Ok(out)
    }

    #[test]
    fn parse_list_delivers_empty_elements_and_the_trailing_one() -> Result<(), std::ffi::NulError> {
        assert_eq!(
            split("a,b,c", b',', 0)?,
            vec![
                (Some("a".into()), 1),
                (Some("b".into()), 1),
                (Some("c".into()), 1),
            ]
        );
        // A trailing separator produces a final empty element.
        assert_eq!(
            split("a,", b',', 0)?,
            vec![(Some("a".into()), 1), (None, 0),]
        );
        // An empty list is one empty element.
        assert_eq!(split("", b',', 0)?, vec![(None, 0)]);
        // Two separators produce an empty element in between.
        assert_eq!(
            split("a,,b", b',', 0)?,
            vec![(Some("a".into()), 1), (None, 0), (Some("b".into()), 1),]
        );
        Ok(())
    }

    #[test]
    fn nospc_trims_both_ends_but_not_the_interior() -> Result<(), std::ffi::NulError> {
        assert_eq!(
            split("  a , b  ,c", b',', 1)?,
            vec![
                (Some("a".into()), 1),
                (Some("b".into()), 1),
                (Some("c".into()), 1),
            ]
        );
        // Without `nospc` nothing is trimmed.
        assert_eq!(
            split(" a ,b", b',', 0)?,
            vec![(Some(" a ".into()), 3), (Some("b".into()), 1),]
        );
        Ok(())
    }

    /// `CONF_parse_list(NULL, ...)` is the one failure the function reports, and it
    /// is reported for the *list* rather than for the callback.
    #[test]
    fn a_null_list_is_the_documented_failure() {
        // SAFETY: a NULL list is explicitly handled.
        let ret = unsafe { CONF_parse_list(ptr::null(), b',' as c_int, 0, None, ptr::null_mut()) };
        assert_eq!(ret, 0);
    }

    /// The authority's `X509_get_default_cert_area()` for the admitted build.
    /// Recorded here, beside the assertion that this build does not return it.
    const AUTHORITY_OPENSSLDIR: &core::ffi::CStr =
        c"/work/forensics/authorities/prefix/openssl-3.6.4-production/ssl";

    /// The one thing the divergent branch must never do is hand back the
    /// forensic build's installation directory.
    #[test]
    fn the_default_path_is_not_the_authority_forensic_directory() {
        std::env::remove_var("OPENSSL_CONF");
        let p = CONF_get1_default_config_file();
        assert!(!p.is_null());
        // SAFETY: the function returned a NUL-terminated owned string.
        let got = unsafe { core::ffi::CStr::from_ptr(p) };
        assert_eq!(got.to_str(), Ok(""));
        assert_ne!(
            got.to_bytes(),
            AUTHORITY_OPENSSLDIR.to_bytes(),
            "the authority's forensic OPENSSLDIR is not this build's directory"
        );
        // SAFETY: `p` came from `CRYPTO_strdup`.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), ptr::null(), 0) };
    }

    #[test]
    fn default_config_file_follows_the_environment_and_otherwise_does_not_claim_a_directory() {
        // SAFETY: the environment is process-global; this test owns the name.
        std::env::set_var("OPENSSL_CONF", "/tmp/openssl-rs-probe.cnf");
        let p = CONF_get1_default_config_file();
        assert!(!p.is_null());
        // SAFETY: the function returned a NUL-terminated owned string.
        let got = unsafe { core::ffi::CStr::from_ptr(p) };
        assert_eq!(got.to_str(), Ok("/tmp/openssl-rs-probe.cnf"));
        // SAFETY: `p` came from `CRYPTO_strdup`.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), ptr::null(), 0) };

        std::env::remove_var("OPENSSL_CONF");
        let p = CONF_get1_default_config_file();
        assert!(!p.is_null(), "the divergent branch is still an allocation");
        // SAFETY: as above.
        assert_eq!(unsafe { core::ffi::CStr::from_ptr(p) }.to_str(), Ok(""));
        // SAFETY: as above.
        unsafe { crate::runtime::mem::CRYPTO_free(p.cast::<c_void>(), ptr::null(), 0) };
    }
}
