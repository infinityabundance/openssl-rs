//! Phase 16.4 — `apps/version.c`: the `openssl version` command.
//!
//! The default arm and `-v` print the build's version text through the public
//! `OpenSSL_version` surface (`apps/version.c:133-135`), which is the same
//! `OpenSSL 3.6.4 25 Aug 2026` string on both the admitted authority and this
//! build (`src/runtime/init.rs`), so the court drives it.
//!
//! ## Recorded divergence (module header)
//!
//! **The build-provenance arms are not driven.** `-b`/`-d`/`-e`/`-m`/`-f`/`-o`/
//! `-p`/`-r`/`-c`/`-a` reach authority metadata this candidate deliberately does
//! not claim (the same divergence `OpenSSL_version` records in
//! `src/runtime/init.rs`), so they reach a `not landed` boundary rather than a
//! value the build does not have. `-help`'s `opt_help` is likewise unlanded
//! (`src/apps/opt.rs` header). See `docs/PHASE-16-SUBPHASES.md` §3.2.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_char;
use core::ffi::c_int;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::VERSION_OPTIONS;

/// `int version_main(int argc, char **argv)` — `apps/version.c:60-166`, the
/// default/`-v` arm.
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, VERSION_OPTIONS);
    let mut version = false;
    let mut dirty = false;
    loop {
        match opts.next() {
            OptMatch::End => break,
            OptMatch::Help => return not_landed("version -help"),
            OptMatch::Flag("v") => {
                version = true;
                dirty = true;
            }
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                return not_landed("version -<metadata>");
            }
        }
    }
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    if !dirty {
        version = true;
    }
    if version {
        // `printf("%s (Library: %s)\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION))`.
        // OPENSSL_VERSION is 0 (`opensslv.h`); both sides answer the same text.
        let text = version_text(0);
        println!("{text} (Library: {text})");
    }
    0
}

/// `OpenSSL_version(OPENSSL_VERSION)` — `crypto/cryptlib.c`, the crate's landed
/// surface (`src/runtime/init.rs:1232`). `OPENSSL_VERSION` is `0`.
fn version_text(t: c_int) -> String {
    // SAFETY: `OpenSSL_version` returns a pointer to a `'static` C string and
    // never NULL (`src/runtime/init.rs:1223-1247`).
    let p: *const c_char = crate::runtime::init::OpenSSL_version(t);
    // SAFETY: `OpenSSL_version` returns a pointer to a `'static` C string and never NULL.
    let s = unsafe { core::ffi::CStr::from_ptr(p) };
    s.to_string_lossy().into_owned()
}
