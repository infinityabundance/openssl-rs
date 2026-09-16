//! Phase 6.8c — `crypto/defaults.c`: the compiled-in directory defaults.
//!
//! Only one function of this file is implemented here: `ossl_get_modulesdir`, which
//! `provider_init` calls when a provider's module is loaded by name and neither the store's
//! default search path nor `OPENSSL_MODULES` answers one. Its siblings
//! (`ossl_get_openssldir`, `ossl_get_enginesdir`, `ossl_get_wininstallcontext`) are Phase
//! 16's, because they are the `OPENSSL_info` strings rather than anything the registry reads.
//!
//! ## The value is a build fact, and this build has a different one from the authority
//!
//! The authority's `ossl_get_modulesdir` returns its `MODULESDIR` — an absolute path baked
//! into its own configure run, which for the admitted authority is
//! `…/prefix/openssl-3.6.4-production/lib/ossl-modules`. A substitute distribution installs
//! its modules somewhere else, so **the string cannot be equal on both sides and is
//! registered as a divergence rather than compared** — the same reasoning that made
//! `OPENSSL_info(OPENSSL_INFO_MODULES_DIR)` answer NULL since Phase 3.
//!
//! The value is captured at build time from `OPENSSL_RS_MODULESDIR`, and when that is unset
//! the function answers **NULL**. That is deliberate rather than a placeholder: NULL is what
//! the caller already has to handle (`provider_init` tests `load_dir == NULL` before using
//! it), so an unset prefix degrades to "no compiled-in directory" rather than to a fabricated
//! path that would send `dlopen` somewhere the distribution never intended. A build that
//! knows its prefix sets the variable, and the behaviour becomes the authority's.
//!
//! SPDX-License-Identifier: Apache-2.0

// The single function this module implements is called by `provider_init`, which is
// unreachable until the `OSSL_PROVIDER_*` exports land in the next commit of this subphase.
// The allowance is removed then.
#![allow(dead_code)] // removed in the commit that declares the exports

use core::ffi::c_char;
use core::ptr;

/// The build-time modules directory, or the sentinel the build emits when none was given.
///
/// `build.rs` emits an empty string when `OPENSSL_RS_MODULESDIR` is unset, which is the one
/// value a directory cannot legitimately be — so the sentinel cannot collide with a real
/// prefix.
const MODULESDIR: &str = env!("OPENSSL_RS_MODULESDIR");

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
}
