//! Phase 17.1 — `apps/prime.c`: the `openssl prime` command.
//!
//! The whole command body (`apps/prime.c:100-223`): parse the generated
//! `PRIME_OPTIONS` table, then either generate a prime (`-generate`, random and
//! therefore not driven) or check each positional number for primality through
//! `BN_check_prime`, printing `BN_print`'s hex followed by
//! ` (input) is prime` / `is not prime`. `process_num` (`apps/prime.c:50-75`)
//! owns the number surface: `check_num` accepts only the digit set the input
//! format allows, and `BN_dec2bn`/`BN_hex2bn` do the conversion.
//!
//! ## What is landed
//!
//! * The option parser arm, the no-number refusal (`Missing number (s) to
//!   check`), the `-generate`-without-`-bits` refusal, the `check_num` +
//!   `BN_dec2bn`/`BN_hex2bn` conversion, `BN_print`, `BN_check_prime`, the
//!   failure text (`Failed to process value (...)`) and the `-in` file loop
//!   (`BIO_get_line`, `strspn` hex-digit truncation, the over-long-line refusal)
//!   are transcribed whole. `BN_check_prime` is landed
//!   (`src/bn/primes.rs:896`) and the fixed inputs the court drives are quick
//!   (small numbers).
//! * `-generate` is transcribed too (`BN_generate_prime_ex`, `BN_bn2hex`/
//!   `BN_bn2dec`), but its output is random, so the court does not drive it; it
//!   drives `-generate` *without* `-bits`, whose refusal text is fixed.
//!
//! ## Recorded divergences (module header)
//!
//! * **`BN_print` renders differently, and the court records the inputs that
//!   expose it.** The authority's `BN_print` (`crypto/bn/bn_print.c`) strips
//!   leading nibbles and writes uppercase (`prime -hex FF` answers `FF (FF) is
//!   not prime`). This crate's `BN_print` (`src/bn/bignum.rs:1655`, via
//!   `hex_of`) writes lowercase and pads to whole bytes (`ff`, and `02` for
//!   `2`). The defect is in the `BN` surface, not this body, so the court drives
//!   `prime 97` (which avoids both differences: `0x61`, two plain digits) and
//!   `prime -hex 0xFF` (the `check_num` refusal) and records `prime 2 3 4` and
//!   `prime -hex FF` in `recorded_divergences` rather than diffing them.
//! * **`-help` is not landed.** `opt_help(prime_options)` (`apps/prime.c:118`)
//!   formats the table; `opt_help` is the boundary [`crate::apps::opt`] records,
//!   so `-help` reaches [`not_landed`].
//! * **The provider-selection arms are not landed.** `-provider`,
//!   `-provider-path`, `-provparam` and `-propquery` reach `opt_provider`
//!   (`apps/prime.c:137-140`), which is an `apps/lib` helper this stratum does
//!   not own, so those arms reach [`not_landed`] rather than silently ignoring a
//!   provider request.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::PRIME_OPTIONS;
use crate::bn::bignum::{BN_dec2bn, BN_free, BN_hex2bn, BN_new, BN_print};
use crate::bn::primes::{BN_check_prime, BN_generate_prime_ex};
use crate::runtime::bio::bss_file::{BIO_new_file, BIO_new_fp};
use crate::runtime::bio::iolib::{BIO_get_line, BIO_write};
use crate::runtime::bio::sys::{stdin, stdout};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::mem::CRYPTO_free;

/// `#define BUFSIZE 4098` — `apps/prime.c:17`.
const BUFSIZE: usize = 4098;

/// The stderr BIO over the process's `stderr`/`stdout` (`apps/lib/apps.c`'s
/// `dup_bio_out`/`dup_bio_err`). `BIO_NOCLOSE` leaves the standard stream open.
fn bio_out() -> *mut Bio {
    // SAFETY: `stdout` is the C library's live `FILE *`; `BIO_new_fp` accepts it.
    unsafe { BIO_new_fp(stdout.cast(), BIO_NOCLOSE) }
}

/// `static int check_num(const char *s, const int is_hex)` — `apps/prime.c:30-48`.
///
/// `true` when the leading run of digits allowed by `is_hex` runs to the string's
/// end (the authority's `s[i] == 0`).
fn check_num(s: &str, is_hex: bool) -> bool {
    let ok = |b: u8| {
        if is_hex {
            b.is_ascii_hexdigit()
        } else {
            b.is_ascii_digit()
        }
    };
    s.bytes().all(ok)
}

/// `static void process_num(const char *s, const int is_hex)` — `apps/prime.c:50-75`.
fn process_num(bio: *mut Bio, s: &str, is_hex: bool) {
    let mut bn = core::ptr::null_mut();
    // `r = check_num(s, is_hex); if (r) r = is_hex ? BN_hex2bn(&bn, s) :
    // BN_dec2bn(&bn, s);` — `apps/prime.c:55-58`.
    let r = if check_num(s, is_hex) {
        let cs = match std::ffi::CString::new(s) {
            Ok(c) => c,
            Err(_) => {
                // A NUL in the argument is not reachable through `argv`.
                eprintln!("Failed to process value ({s})");
                return;
            }
        };
        // SAFETY: `bn` is the local slot `BN_hex2bn`/`BN_dec2bn` fill; `cs` is
        // NUL-terminated and outlives the call.
        unsafe {
            if is_hex {
                BN_hex2bn(&mut bn, cs.as_ptr())
            } else {
                BN_dec2bn(&mut bn, cs.as_ptr())
            }
        }
    } else {
        0
    };
    if r == 0 {
        // `BIO_printf(bio_err, "Failed to process value (%s)\n", s);` —
        // `apps/prime.c:61`.
        eprintln!("Failed to process value ({s})");
        // SAFETY: `bn` is NULL or a live key.
        unsafe { BN_free(bn) };
        return;
    }

    // `BN_print(bio_out, bn);` — `apps/prime.c:66`.
    // SAFETY: `bio` is a live stdout BIO and `bn` is live.
    unsafe { BN_print(bio, bn) };
    // `r = BN_check_prime(bn, NULL, NULL); BN_free(bn);` — `apps/prime.c:67-68`.
    // SAFETY: `bn` is live and the two NULLs are the no-context/no-callback arms.
    let prime = unsafe { BN_check_prime(bn, core::ptr::null_mut(), core::ptr::null_mut()) };
    // SAFETY: `bn` is live.
    unsafe { BN_free(bn) };
    if prime < 0 {
        // `BIO_printf(bio_err, "Error checking prime\n");` — `apps/prime.c:70`.
        eprintln!("Error checking prime");
        return;
    }
    // `BIO_printf(bio_out, " (%s) %s prime\n", s, r == 1 ? "is" : "is not");`
    // — `apps/prime.c:74`.
    let suffix = format!(
        " ({s}) {} prime\n",
        if prime == 1 { "is" } else { "is not" }
    );
    // SAFETY: `bio` is live and the byte slice outlives the call.
    unsafe { BIO_write(bio, suffix.as_ptr().cast(), suffix.len() as c_int) };
}

/// `atoi(opt_arg())` — `apps/prime.c:128`, the `strtol` decimal prefix.
fn atoi(s: &str) -> c_int {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut sign = 1i64;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        if b[i] == b'-' {
            sign = -1;
        }
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((b[i] - b'0') as i64);
        i += 1;
    }
    (sign * v) as c_int
}

/// `bio_open_default_quiet(argv[0], 'r', 0)` — `apps/lib/apps.c:3269-3272`, the
/// file arm. A NULL or `-` filename is stdin; anything else is `BIO_new_file`.
fn open_read_quiet(filename: &str) -> *mut Bio {
    if filename.is_empty() || filename == "-" {
        // SAFETY: `stdin` is the C library's live `FILE *`.
        return unsafe { BIO_new_fp(stdin.cast(), BIO_NOCLOSE) };
    }
    let cs = match std::ffi::CString::new(filename) {
        Ok(c) => c,
        Err(_) => return core::ptr::null_mut(),
    };
    // SAFETY: `cs` is NUL-terminated and outlives the call.
    unsafe { BIO_new_file(cs.as_ptr(), c"r".as_ptr()) }
}

/// `strspn(file_read_buf, "1234567890abcdefABCDEF")` — `apps/prime.c:205`, over a
/// NUL-terminated buffer.
fn hex_digit_prefix(buf: &[c_char]) -> usize {
    let mut n = 0usize;
    while n < buf.len() {
        let b = buf[n] as u8;
        if b == 0 || !b.is_ascii_hexdigit() {
            break;
        }
        n += 1;
    }
    n
}

/// `int prime_main(int argc, char **argv)` — `apps/prime.c:100-223`.
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, prime_options);` — `apps/prime.c:109`.
    let mut opts = Opts::init(argv, PRIME_OPTIONS);
    let (mut hex, mut generate, mut safe, mut in_file) = (false, false, false, false);
    let mut bits = 0 as c_int;
    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/prime.c:110`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(prime_options); ret = 0; goto end;` —
            // `apps/prime.c:117-120`. `opt_help` is unlanded; see the header.
            OptMatch::Help => return not_landed("prime -help"),
            // `case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help for
            // summary.\n", prog);` — `apps/prime.c:112-116`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_HEX: hex = 1; break;` — `apps/prime.c:121-123`.
            OptMatch::Flag("hex") => hex = true,
            // `case OPT_GENERATE: generate = 1; break;` — `apps/prime.c:124-126`.
            OptMatch::Flag("generate") => generate = true,
            // `case OPT_SAFE: safe = 1; break;` — `apps/prime.c:130-132`.
            OptMatch::Flag("safe") => safe = true,
            // `case OPT_IN_FILE: in_file = 1; break;` — `apps/prime.c:141-143`.
            OptMatch::Flag("in") => in_file = true,
            // `case OPT_BITS: bits = atoi(opt_arg()); break;` — `apps/prime.c:127-129`.
            OptMatch::Value("bits", v) => bits = atoi(&v),
            // `case OPT_CHECKS: /* ignore parameter and argument */ opt_arg();` —
            // `apps/prime.c:133-136`. The parser already consumed the value.
            OptMatch::Value("checks", _) => {}
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/prime.c:137-140`. `opt_provider` is unlanded; see the header.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("prime -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (generate && !opt_check_rest_arg(NULL)) goto opthelp;` —
    // `apps/prime.c:148-149`.
    if generate && !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }
    // `argc = opt_num_rest(); argv = opt_rest();` — `apps/prime.c:150-151`.
    let rest: Vec<String> = opts.rest().to_vec();
    // `if (!generate && argc == 0) { BIO_printf(bio_err, "Missing number (s) to
    // check\n"); goto opthelp; }` — `apps/prime.c:152-155`.
    if !generate && rest.is_empty() {
        eprintln!("Missing number (s) to check");
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    let bio = bio_out();
    let mut ret = 1i32;
    if generate {
        // `if (!bits) { BIO_printf(bio_err, "Specify the number of bits.\n");
        // goto end; }` — `apps/prime.c:160-163`.
        if bits == 0 {
            eprintln!("Specify the number of bits.");
        } else {
            // `bn = BN_new(); ... if (!BN_generate_prime_ex(bn, bits, safe, NULL,
            // NULL, NULL)) { ... }` — `apps/prime.c:164-172`. Random, so the court
            // does not drive it; transcribed whole.
            // SAFETY: `BN_new` takes no pointers.
            let bn = unsafe { BN_new() };
            if bn.is_null() {
                eprintln!("Out of memory.");
            } else {
                // SAFETY: `bn` is live; the three NULLs are the no-add/no-rem/no-cb arms.
                let ok = unsafe {
                    BN_generate_prime_ex(
                        bn,
                        bits,
                        safe as c_int,
                        core::ptr::null(),
                        core::ptr::null(),
                        core::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    eprintln!("Failed to generate prime.");
                } else {
                    // `s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);` —
                    // `apps/prime.c:173`. `BN_bn2hex` is uppercase, as in the
                    // authority (`src/bn/bignum.rs:1197`).
                    // SAFETY: `bn` is live; both allocators return an owned string or NULL.
                    let s = unsafe {
                        if hex {
                            crate::bn::bignum::BN_bn2hex(bn)
                        } else {
                            crate::bn::bignum::BN_bn2dec(bn)
                        }
                    };
                    if s.is_null() {
                        eprintln!("Out of memory.");
                    } else {
                        // SAFETY: `s` is a NUL-terminated block `BN_bn2hex`/`BN_bn2dec` allocated.
                        let text = unsafe { core::ffi::CStr::from_ptr(s) }
                            .to_string_lossy()
                            .into_owned();
                        println!("{text}");
                        // `OPENSSL_free(s);` — `apps/prime.c:179`.
                        // SAFETY: `s` is the block just consumed and not freed again.
                        unsafe { CRYPTO_free(s.cast(), core::ptr::null(), 0) };
                    }
                }
                // SAFETY: `bn` is live and not freed again here (the `end:` label
                // frees it in the authority; this arm returns after).
                unsafe { BN_free(bn) };
            }
            ret = 0;
        }
    } else {
        // `for (; *argv; argv++)` — `apps/prime.c:181`.
        for file in &rest {
            if !in_file {
                // `process_num(argv[0], hex);` — `apps/prime.c:185`.
                process_num(bio, file, hex);
            } else {
                // `in = bio_open_default_quiet(argv[0], 'r', 0); if (in == NULL) {
                // BIO_printf(bio_err, "Error opening file %s\n", argv[0]); continue; }`
                // — `apps/prime.c:187-191`.
                let inbio = open_read_quiet(file);
                if inbio.is_null() {
                    eprintln!("Error opening file {file}");
                    continue;
                }
                let mut buf = [0 as c_char; BUFSIZE];
                let mut bytes_read: c_int;
                loop {
                    // `while ((bytes_read = BIO_get_line(in, file_read_buf, BUFSIZE)) > 0)`
                    // — `apps/prime.c:193`.
                    // SAFETY: `inbio` is live and `buf` is `BUFSIZE` writable bytes.
                    bytes_read = unsafe { BIO_get_line(inbio, buf.as_mut_ptr(), BUFSIZE as c_int) };
                    if bytes_read <= 0 {
                        break;
                    }
                    // `if (bytes_read == BUFSIZE - 1 && file_read_buf[BUFSIZE - 2] != '\n')`
                    // — `apps/prime.c:197`.
                    if bytes_read == (BUFSIZE - 1) as c_int && buf[BUFSIZE - 2] != b'\n' as c_char {
                        eprintln!(
                            "Value in {file} is over the maximum size ({} digits)",
                            BUFSIZE - 2
                        );
                        // `while (BIO_get_line(in, file_read_buf, BUFSIZE) == BUFSIZE - 1);`
                        // — `apps/prime.c:200-201`.
                        loop {
                            // SAFETY: `inbio` is live and `buf` is `BUFSIZE` writable bytes.
                            let n =
                                unsafe { BIO_get_line(inbio, buf.as_mut_ptr(), BUFSIZE as c_int) };
                            if n != (BUFSIZE - 1) as c_int {
                                break;
                            }
                        }
                        continue;
                    }
                    // `valid_digits_length = strspn(file_read_buf, "...");
                    // file_read_buf[valid_digits_length] = '\0'; process_num(file_read_buf, hex);`
                    // — `apps/prime.c:205-208`.
                    let n = hex_digit_prefix(&buf);
                    buf[n] = 0;
                    // SAFETY: `buf` holds a NUL-terminated prefix by construction.
                    let line = unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) }
                        .to_string_lossy()
                        .into_owned();
                    process_num(bio, &line, hex);
                }
                if bytes_read < 0 {
                    // `if (bytes_read < 0) BIO_printf(bio_err, "Read error in %s\n",
                    // argv[0]);` — `apps/prime.c:211-212`.
                    eprintln!("Read error in {file}");
                }
                // `BIO_free(in);` — `apps/prime.c:214`.
                // SAFETY: `inbio` is live and not freed again.
                unsafe { BIO_free(inbio) };
            }
        }
        // `ret = 0;` — `apps/prime.c:219`.
        ret = 0;
    }
    // `end: BN_free(bn); return ret;` — `apps/prime.c:220-222`.
    // SAFETY: the stdout BIO is NOCLOSE, so freeing it leaves `stdout` open.
    unsafe { BIO_free(bio) };
    ret
}
