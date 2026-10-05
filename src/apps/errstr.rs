//! Phase 17.1 — `apps/errstr.c`: the `openssl errstr` command.
//!
//! The whole command body (`apps/errstr.c:36-77`): initialise the option parser from the
//! generated `ERRSTR_OPTIONS` table, then decode every remaining argument as an
//! `unsigned long` with `sscanf("%lx")` and print `ERR_error_string_n`'s answer one per
//! line. The failure count is the exit status, so `errstr nothex` exits 1 while
//! `errstr 1` exits 0.
//!
//! ## Why the command initialises SSL at all
//!
//! `errstr` is not an SSL application, so nothing auto-initialises it, but its output is
//! the *reason* and *library* strings: the authority calls
//! `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
//! NULL)` (`apps/errstr.c:57-63`) before decoding, which is what makes libcrypto's and
//! libssl's reason tables visible. This module makes the same call.
//!
//! ## Recorded divergences (module header)
//!
//! * **`-help` is not landed.** `opt_help(errstr_options)` (`apps/errstr.c:51`) formats the
//!   whole option table with section headers and wrapped help text; `opt_help` is the
//!   boundary [`crate::apps::opt`] records, so `-help` reaches [`not_landed`] rather than the
//!   authority's table, exactly as it does on the `help`/`list`/`version` bodies.
//! * **An unknown *system* error renders differently**, and this is the `ERR` surface's
//!   divergence, not the body's. For `errstr 0xdeadbeef` the authority answers
//!   `error:DEADBEEF:system library::reason(1585561327)`: its `openssl_strerror_r`
//!   (`crypto/o_str.c`, the POSIX `strerror_r`) refuses the out-of-range errno and falls back
//!   to `reason(r & ~flags)`. This crate's `strerror_into` (`src/runtime/err.rs:1596`) calls
//!   the GNU `strerror_r`, which answers `Unknown error 1588444911`. The `RT-CLI-BODIES` court
//!   records this input in `recorded_divergences` rather than diffing it; every other `errstr`
//!   arm matches.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_ulong};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::ERRSTR_OPTIONS;

/// `OPENSSL_INIT_LOAD_CRYPTO_STRINGS` — `crypto.h`; the value `src/runtime/init.rs`
/// intercepts (`apps/errstr.c:62`).
const OPENSSL_INIT_LOAD_CRYPTO_STRINGS: u64 = 0x0000_0002;
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` — `ssl.h:2827` (`apps/errstr.c:61`).
const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x0020_0000;

/// `int errstr_main(int argc, char **argv)` — `apps/errstr.c:36-77`.
#[allow(clippy::never_loop)] // every arm breaks or returns; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, errstr_options);` — `apps/errstr.c:43`.
    let mut opts = Opts::init(argv, ERRSTR_OPTIONS);
    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/errstr.c:44`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(errstr_options); ret = 0; goto end;` —
            // `apps/errstr.c:50-53`. `opt_help` is unlanded; see the module header.
            OptMatch::Help => return not_landed("errstr -help"),
            // `case OPT_ERR: BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);`
            // — `apps/errstr.c:47-49`. The parser's own refusal text prints first, as it
            // does in the authority's `opt_next` (`src/apps/opt.rs`).
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `errstr_options` declares no other option, so the authority's `OPT_ERR`
            // arm is the only one a matched non-help option could reach.
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
    // NULL);` — `apps/errstr.c:61-63`.
    // SAFETY: the settings pointer is NULL, which `OPENSSL_init_ssl` accepts.
    unsafe {
        crate::ssl::ssl_init::OPENSSL_init_ssl(
            OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
            core::ptr::null(),
        )
    };

    // `ret = 0; for (argv = opt_rest(); *argv != NULL; argv++) { ... }` —
    // `apps/errstr.c:66-74`.
    let mut ret = 0i32;
    for arg in opts.rest() {
        // `if (sscanf(*argv, "%lx", &l) <= 0) { ret++; } else { ... }` —
        // `apps/errstr.c:68-73`.
        match parse_hex_l(arg) {
            None => ret += 1,
            Some(l) => {
                let mut buf = [0 as c_char; 256];
                // `ERR_error_string_n(l, buf, sizeof(buf));` — `apps/errstr.c:71`.
                // SAFETY: `buf` is 256 writable bytes and `l` is any packed error code.
                unsafe { crate::runtime::err::ERR_error_string_n(l, buf.as_mut_ptr(), buf.len()) };
                // SAFETY: `ERR_error_string_n` NUL-terminates `buf`.
                let s = unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) };
                // `BIO_printf(bio_out, "%s\n", buf);` — `apps/errstr.c:72`.
                println!("{}", s.to_string_lossy());
            }
        }
    }
    // `end: return ret;` — `apps/errstr.c:75-76`.
    ret
}

/// `sscanf(*argv, "%lx", &l)` — `apps/errstr.c:68`, the `strtoul(..., 16)` conversion the
/// format performs.
///
/// Leading `isspace` is skipped, an optional sign is accepted, and a `0x`/`0X` prefix is
/// part of the subject sequence only when a hex digit follows it (so a bare `0x` converts
/// the leading `0`, exactly as `strtoul` does). `None` is the authority's `sscanf(...) <= 0`
/// arm: no hex digit was converted. Overlong input wraps rather than saturating at
/// `ULONG_MAX`; no observed call reaches it.
fn parse_hex_l(s: &str) -> Option<c_ulong> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut negative = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        negative = bytes[i] == b'-';
        i += 1;
    }
    if i + 2 < bytes.len()
        && bytes[i] == b'0'
        && (bytes[i + 1] | 0x20) == b'x'
        && bytes[i + 2].is_ascii_hexdigit()
    {
        i += 2;
    }
    let start = i;
    let mut value: c_ulong = 0;
    while i < bytes.len() {
        // The classification is exhaustive over `is_ascii_hexdigit`, so no
        // fallible `to_digit` is needed and no panic path exists.
        let digit = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => break,
        } as c_ulong;
        value = value.wrapping_mul(16).wrapping_add(digit);
        i += 1;
    }
    if i == start {
        return None;
    }
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}
