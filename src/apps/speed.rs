//! Phase 17.1f — `apps/speed.c`: the `openssl speed` command.
//!
//! Only the command's option parse (`apps/speed.c:2119-...`) and the two
//! pre-benchmark algorithm lookups (`apps/speed.c:2134-2160`) are transcribed.
//! The benchmark loop itself — `speed_main`'s several thousand lines of
//! primitives and `run_benchmark`'s wall-clock timing — is deliberately not
//! landed: its output is a function of the machine, not the fixtures, so it
//! cannot be diffed and is not driven.
//!
//! ## What the court drives
//!
//! `speed -bogus`: the option parser's refusal, which is decided before any
//! algorithm is fetched. The `-evp`/`-hmac` refusals reach [`not_landed`] with
//! the authority's message (their exit is still 1).
//!
//! ## Recorded divergences (module header)
//!
//! * **The benchmark is not landed, and is never driven.** `speed` with no
//!   argument runs the default suite; every arm that reaches a benchmark stops at
//!   [`not_landed`]. `speed -evp <valid>`/`-hmac <valid>` are the same.
//! * **`speed -evp NOPE`/`-hmac NOPE` are recorded, not diffed.** The authority's
//!   `opt_cipher_silent`/`opt_md_silent` leave `inner_evp_generic_fetch:
//!   unsupported` errors in the queue, and `speed_main`'s `end:` label calls
//!   `ERR_print_errors`, so the authority's stderr carries a pointer-bearing tail
//!   the candidate's empty queue does not (the `kdf`/`mac` divergence). The
//!   message line and exit are transcribed here; the tail is the `ERR` surface's.
//! * **`-engine`, `-rand`/`-writerand`, `-config` and the provider arms are not
//!   landed.**
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::SPEED_OPTIONS;
use crate::evp::digest::{EVP_DigestInit, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_free, EvpMd};

/// `static int have_md(const char *name)` — `apps/speed.c` (the `-evp`/`-hmac`
/// digest probe), reduced to "does the name resolve to a usable digest".
fn have_md(name: &str) -> bool {
    let cs = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return false,
    };
    // SAFETY: `cs` is NUL-terminated; the context/query are the defaults.
    let fetched = unsafe {
        crate::evp::digest::EVP_MD_fetch(core::ptr::null_mut(), cs.as_ptr(), core::ptr::null())
    };
    let md: *mut EvpMd = if !fetched.is_null() {
        fetched
    } else {
        // SAFETY: `cs` is NUL-terminated.
        let legacy = unsafe { crate::evp::legacy_evp::EVP_get_digestbyname(cs.as_ptr()) };
        if legacy.is_null() {
            return false;
        }
        legacy.cast_mut()
    };
    let ctx = EVP_MD_CTX_new();
    // SAFETY: `ctx` is NULL-or-live and `md` is live; `EVP_DigestInit` accepts the pair.
    let ok = !ctx.is_null() && unsafe { EVP_DigestInit(ctx, md) } > 0;
    // SAFETY: both are live and not freed again.
    unsafe {
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }
    ok
}

/// `int speed_main(int argc, char **argv)` — `apps/speed.c:1955-...`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    let mut opts = Opts::init(argv, SPEED_OPTIONS);

    loop {
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(...); ret = 0; goto end;` —
            // `apps/speed.c:2127-2130`.
            OptMatch::Help => return not_landed("speed -help"),
            // `case OPT_ERR: opterr: ...` — `apps/speed.c:2122-2126`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_EVP: ...` — `apps/speed.c:2134-2153`.
            OptMatch::Value("evp", v) => {
                // `opt_cipher_silent(opt_arg(), &evp_cipher)` is not reconstructed;
                // the cipher arm is not driven. A name that resolves to a digest
                // reaches the benchmark; anything else is the authority's refusal.
                if have_md(&v) {
                    return not_landed("speed benchmark");
                }
                eprintln!("{}: {} is an unknown cipher or digest", opts.prog(), v);
                return 1;
            }
            // `case OPT_HMAC: if (!have_md(opt_arg())) { ... }` — `apps/speed.c:2154-...`.
            OptMatch::Value("hmac", v) => {
                if !have_md(&v) {
                    eprintln!("{}: {} is an unknown digest", opts.prog(), v);
                    return 1;
                }
                return not_landed("speed benchmark");
            }
            // `case OPT_ENGINE: ...` — `apps/speed.c`.
            OptMatch::Value("engine", _) => return not_landed("speed -engine"),
            // `case OPT_CONFIG: conf = app_load_config(opt_arg()); ...` — the config
            // surface is `apps/lib`'s.
            OptMatch::Value("config", _) => return not_landed("speed -config"),
            // `case OPT_R_CASES: ...` — `apps/speed.c`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("speed -rand")
            }
            // `case OPT_PROV_CASES: ...` — `apps/speed.c`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("speed -provider"),
            // Every other option only configures the benchmark loop, which is not
            // landed; a bare `speed` runs the default suite.
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {}
        }
    }

    // `speed` with no benchmark selection runs the default suite.
    not_landed("speed benchmark")
}
