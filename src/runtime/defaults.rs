//! Phase 6.8c / 16.3 — `crypto/defaults.c`: the compiled-in directory defaults.
//!
//! `ossl_get_modulesdir`, which `provider_init` calls when a provider's module is loaded by
//! name and neither the store's default search path nor `OPENSSL_MODULES` answers one, and
//! `ossl_get_enginesdir`, which the registry's `ENGINE_by_id` (`crypto/engine/eng_list.c:462`)
//! calls when `OPENSSL_ENGINES` is unset and the id is not in the list, to hand the dynamic
//! engine its `DIR_ADD`, are 10.9's and 13.1's. Phase 16.3 adds the two remaining siblings:
//! `ossl_get_openssldir`, the `OPENSSLDIR` directory plane the x509 default paths
//! (`src/x509/x509_def.rs`) and `CONF_get1_default_config_file` measure, and
//! `ossl_get_wininstallcontext`, the install context `OPENSSL_info`'s
//! `OPENSSL_INFO_WINDOWS_CONTEXT` answers. On the non-Windows branch the authority's two
//! functions are `return OPENSSLDIR;` (`crypto/defaults.c:151-160`) and `return "Undefined";`
//! (`:199-206`); the declarations are `include/internal/common.h:247-250`.
//!
//! ## The value is a build fact, and this build has a different one from the authority
//!
//! The authority's `ossl_get_modulesdir` returns its `MODULESDIR` — an absolute path baked
//! into its own configure run, which for the admitted authority is
//! `…/prefix/openssl-3.6.4-production/lib/ossl-modules`. A substitute distribution installs
//! its modules somewhere else, so **the string cannot be equal on both sides and is
//! registered as a divergence rather than compared** — the same reasoning that made
//! `OPENSSL_info(OPENSSL_INFO_MODULES_DIR)` answer NULL since Phase 3. `ossl_get_openssldir`
//! follows the same rule as `src/x509/x509_def.rs`: the answer is the build's
//! `OPENSSL_RS_OPENSSLDIR`, and an unset variable answers the **empty C string** rather than a
//! fabricated prefix, so a caller fails to open a path this distribution never intended.
//! `ossl_get_wininstallcontext` is the one name that *is* equal on both sides: the
//! non-Windows arm is the fixed literal `"Undefined"` on the authority too.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_char;
use core::ptr;

/// The build-time modules directory, or the sentinel the build emits when none was given.
///
/// `build.rs` emits an empty string when `OPENSSL_RS_MODULESDIR` is unset, which is the one
/// value a directory cannot legitimately be — so the sentinel cannot collide with a real
/// prefix.
const MODULESDIR: &str = env!("OPENSSL_RS_MODULESDIR");

/// The build-time engines directory, or the sentinel the build emits when none was given.
///
/// The same sentinel rule as `MODULESDIR` above: an empty string means "no compiled-in
/// engines directory" and answers NULL.
const ENGINESDIR: &str = env!("OPENSSL_RS_ENGINESDIR");

/// The build-time installation directory (`OPENSSLDIR`), or the empty sentinel the build
/// emits when none was given.
///
/// The same sentinel rule as `src/x509/x509_def.rs`'s `OPENSSLDIR`: an unset
/// `OPENSSL_RS_OPENSSLDIR` answers the empty C string, never a fabricated prefix.
const OPENSSLDIR: &str = env!("OPENSSL_RS_OPENSSLDIR");

/// `const char *ossl_get_modulesdir(void)` — `crypto/defaults.c`.
///
/// A `'static` C string, so the answer is the same address on every call and the caller must
/// not free it. `provider_init` passes it straight to `DSO_merge` as the second spec, which is
/// why NULL has to mean "no directory" rather than "" — an empty string would merge as a
/// directory and produce a leading `/`.
pub(crate) fn ossl_get_modulesdir() -> *const c_char {
    // The literal below is a `&'static str` with a terminator appended at compile time by the
    // `c"…"` form, which is why no allocation is involved and the address is stable.
    match MODULESDIR {
        "" => ptr::null(),
        _ => modulesdir_c(),
    }
}

/// `const char *ossl_get_enginesdir(void)` — `crypto/defaults.c`.
///
/// The twin of [`ossl_get_modulesdir`], and the same contract: a `'static` C string the caller
/// must not free, or NULL when the build gave no prefix. The one caller is `ENGINE_by_id`
/// (`crypto/engine/eng_list.c:462`), which passes it to the dynamic engine's `DIR_ADD` exactly
/// as the authority does, so a NULL means "no fallback directory" rather than an empty one.
pub(crate) fn ossl_get_enginesdir() -> *const c_char {
    // SAFETY: the same `'static` literal rule as `ossl_get_modulesdir` above.
    match ENGINESDIR {
        "" => ptr::null(),
        _ => enginesdir_c(),
    }
}

/// `const char *ossl_get_openssldir(void)` — `crypto/defaults.c:151-160`.
///
/// The non-Windows arm is `return OPENSSLDIR;`, so this is the build's own installation
/// directory. The answer is a `'static` C string the caller must not free, and an unset
/// `OPENSSL_RS_OPENSSLDIR` answers the empty C string rather than a fabricated prefix — the
/// rule `src/x509/x509_def.rs` already records, since the authority's own `OPENSSLDIR` is a
/// forensic-build path this distribution is not installed at.
///
/// The callers are `X509_get_default_cert_area`'s `OPENSSLDIR` (`src/x509/x509_def.rs`),
/// `CONF_get1_default_config_file`'s fallback and `OPENSSL_info(OPENSSL_INFO_CONFIG_DIR)`.
pub(crate) fn ossl_get_openssldir() -> *const c_char {
    match OPENSSLDIR {
        "" => c"".as_ptr(),
        _ => openssldir_c(),
    }
}

/// `const char *ossl_get_wininstallcontext(void)` — `crypto/defaults.c:199-206`.
///
/// The non-Windows arm is `return "Undefined";`, a fixed literal that is equal on both sides.
/// The one caller is `OPENSSL_info(OPENSSL_INFO_WINDOWS_CONTEXT)` (`crypto/info.c:285`).
pub(crate) fn ossl_get_wininstallcontext() -> *const c_char {
    c"Undefined".as_ptr()
}

/// The compiled-in path as a C string.
///
/// Spelled as a separate function so that the `env!` expansion appears exactly once and the
/// empty-string test above reads as the sentinel it is.
fn modulesdir_c() -> *const c_char {
    // A `CStr` built from the build-time string. `build.rs` rejects a value containing a NUL,
    // so the unwrap below cannot fire — and it is a `match` rather than an `unwrap` because
    // `expect` is denied crate-wide.
    match core::ffi::CStr::from_bytes_with_nul(
        concat!(env!("OPENSSL_RS_MODULESDIR"), "\0").as_bytes(),
    ) {
        Ok(s) => s.as_ptr(),
        Err(_) => ptr::null(),
    }
}

/// The compiled-in engines path as a C string.
///
/// Spelled as a separate function for the same reason as [`modulesdir_c`]: the `env!`
/// expansion appears exactly once and the sentinel test above reads as the sentinel it is.
fn enginesdir_c() -> *const c_char {
    // SAFETY: `build.rs` rejects a NUL-bearing value, so the `CStr` construction cannot fail
    // and the `Err` arm is unreachable; it answers NULL rather than panicking because `panic`
    // is denied crate-wide.
    match core::ffi::CStr::from_bytes_with_nul(
        concat!(env!("OPENSSL_RS_ENGINESDIR"), "\0").as_bytes(),
    ) {
        Ok(s) => s.as_ptr(),
        Err(_) => ptr::null(),
    }
}

/// The compiled-in `OPENSSLDIR` as a C string.
///
/// Spelled as a separate function for the same reason as [`modulesdir_c`]: the `env!`
/// expansion appears exactly once. `build.rs` rejects a NUL-bearing value, so the `Err` arm
/// cannot fire; it answers the empty sentinel rather than panicking because `panic` is denied
/// crate-wide.
fn openssldir_c() -> *const c_char {
    match core::ffi::CStr::from_bytes_with_nul(
        concat!(env!("OPENSSL_RS_OPENSSLDIR"), "\0").as_bytes(),
    ) {
        Ok(s) => s.as_ptr(),
        Err(_) => c"".as_ptr(),
    }
}

#[cfg(test)]
mod tests {
    //! The sentinel rule, and that the answer is the same address twice.
    //!
    //! `alloc` is not linked for unit tests, so no `String` appears below.

    use super::*;

    #[test]
    fn an_unset_prefix_answers_null_rather_than_an_empty_directory() {
        // The two cases are exactly the two the build can produce, and the distinction is the
        // point: an empty string is a *directory* to `DSO_merge`, and NULL is not.
        if MODULESDIR.is_empty() {
            assert!(
                ossl_get_modulesdir().is_null(),
                "an unset OPENSSL_RS_MODULESDIR answers NULL"
            );
        } else {
            assert!(
                !ossl_get_modulesdir().is_null(),
                "a set OPENSSL_RS_MODULESDIR answers a path"
            );
            // SAFETY: a non-NULL answer is a NUL-terminated literal.
            let s = unsafe { core::ffi::CStr::from_ptr(ossl_get_modulesdir()) };
            assert_eq!(s.to_str(), Ok(MODULESDIR));
        }
    }

    #[test]
    fn the_answer_is_the_same_address_on_every_call_so_a_caller_may_not_free_it() {
        // SAFETY: the function takes no arguments.
        let a = ossl_get_modulesdir();
        // SAFETY: as above.
        let b = ossl_get_modulesdir();
        assert_eq!(a, b, "a `static` answer is stable");
    }

    #[test]
    fn the_openssldir_plane_answers_its_build_path_or_the_empty_sentinel() {
        // The two cases are exactly the two the build can produce, and the distinction is the
        // point: an unset `OPENSSL_RS_OPENSSLDIR` answers the empty C string, never NULL
        // (the same honest degradation `src/x509/x509_def.rs` records).
        let p = ossl_get_openssldir();
        assert!(
            !p.is_null(),
            "an unset OPENSSL_RS_OPENSSLDIR is still a C string"
        );
        // SAFETY: a non-NULL answer is a NUL-terminated literal.
        let s = unsafe { core::ffi::CStr::from_ptr(p) };
        assert_eq!(s.to_str(), Ok(OPENSSLDIR));
        // SAFETY: the function takes no arguments.
        assert_eq!(p, ossl_get_openssldir(), "a `static` answer is stable");
    }

    #[test]
    fn the_install_context_is_the_non_windows_literal() {
        // The one name that is equal on both sides: `crypto/defaults.c:199-206`'s
        // non-Windows arm is `return "Undefined";`.
        // SAFETY: the literal is NUL-terminated.
        let s = unsafe { core::ffi::CStr::from_ptr(ossl_get_wininstallcontext()) };
        assert_eq!(s.to_bytes(), b"Undefined");
        // SAFETY: the function takes no arguments.
        assert_eq!(
            ossl_get_wininstallcontext(),
            ossl_get_wininstallcontext(),
            "a `static` answer is stable"
        );
    }
}
