//! Phase 17.1 — `apps/genrsa.c`: the `openssl genrsa` command.
//!
//! The command body (`apps/genrsa.c:84-258`) parses the generated
//! `GENRSA_OPTIONS` table, reads the optional `numbits` argument, then loads the
//! RNG, builds an `RSA` keygen context and writes a private key. The parse and the
//! bitsize validation are transcribed exactly; the generation path reaches
//! [`not_landed`] at `app_RAND_load`.
//!
//! ## What the court drives
//!
//! Only the arms that finish before any randomness: the missing/invalid `numbits`
//! conversions (`genrsa abc`, `genrsa 0`, `genrsa 99999999999999999999`) and the
//! parser refusals (an unknown option, an extra argument). Each has fixed text and
//! an empty error queue, so both sides exit 1 identically.
//!
//! ## Recorded divergences (module header)
//!
//! * **Key generation is not landed.** `app_RAND_load` (`apps/genrsa.c:175-176`),
//!   `opt_cipher`, `app_passwd`, `bio_open_owner`, `init_gen_str` and `app_keygen`
//!   are `apps/lib` helpers this stratum does not own, and the generated key is
//!   random besides, so `genrsa <bits>` reaches [`not_landed`] rather than
//!   fabricating a key. The warning for an over-large `numbits` is transcribed but
//!   that arm is not driven (it continues into generation).
//! * **`opt_int` is reduced to its observable.** The authority parses `numbits`
//!   and `-primes` through `opt_int`/`opt_long` (`apps/lib/opt.c:542-616`); this
//!   module transcribes the `strtol(..., 0)` conversion and its
//!   `Can't parse ... as a number`/`as an octal number`/`as a hexadecimal number`
//!   and `outside integer range` messages.
//! * **`opt_set_unknown_name("cipher")` is not landed.** The authority treats an
//!   otherwise-unknown option as `-<cipher>` (`apps/genrsa.c:103`); this module's
//!   parser has no such mode, so such an option is the parser's `Unknown option`
//!   refusal. Not driven.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-engine`, `-rand`/`-writerand` and provider arms reach unlanded
//!   `apps/lib` helpers (`setup_engine`, `opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::GENRSA_OPTIONS;
use crate::bn::bignum::{BN_free, BN_new};
use crate::bn::ctx::{BN_GENCB_free, BN_GENCB_new};

/// `OPENSSL_RSA_MAX_MODULUS_BITS` — `rsa.h`.
const OPENSSL_RSA_MAX_MODULUS_BITS: c_int = 16384;

/// `strtol(value, &endp, 0)` — `apps/lib/opt.c:590-616`, the base-0 conversion
/// `opt_long` performs. Returns `None` for the authority's refusal arms (a
/// trailing character, no digits, or an out-of-range value).
fn strtol_base0(value: &str) -> Option<c_long> {
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let (radix, mut j) = if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] | 0x20) == b'x' {
        (16u32, i + 2)
    } else if i < b.len() && b[i] == b'0' {
        (8u32, i)
    } else {
        (10u32, i)
    };
    let digits_start = j;
    let mut acc: i128 = 0;
    let mut overflow = false;
    while j < b.len() {
        let d = match b[j] {
            b'0'..=b'9' => u32::from(b[j] - b'0'),
            b'a'..=b'f' if radix == 16 => u32::from(b[j] - b'a') + 10,
            b'A'..=b'F' if radix == 16 => u32::from(b[j] - b'A') + 10,
            _ => break,
        };
        if d >= radix {
            break;
        }
        acc = acc * i128::from(radix) + i128::from(d);
        if acc > i128::from(c_long::MAX) + 1 {
            overflow = true;
            acc = 0;
        }
        j += 1;
    }
    // `endp == value` when no digit was converted (an empty subject sequence, an
    // optional sign alone, or a radix prefix with no digit after it).
    if j == digits_start {
        return None;
    }
    if j != b.len() {
        return None;
    }
    let mag = if overflow {
        i128::from(c_long::MAX) + 1
    } else {
        acc
    };
    let signed = if neg { -mag } else { mag };
    if signed < i128::from(c_long::MIN) || signed > i128::from(c_long::MAX) {
        return None;
    }
    Some(signed as c_long)
}

/// `static void opt_number_error(const char *v)` — `apps/lib/opt.c:568-587`.
fn opt_number_error(prog: &str, v: &str) {
    if v.starts_with("0x") || v.starts_with("0X") {
        eprintln!("{prog}: Can't parse \"{v}\" as a hexadecimal number");
    } else if v.starts_with('0') {
        eprintln!("{prog}: Can't parse \"{v}\" as an octal number");
    } else {
        eprintln!("{prog}: Can't parse \"{v}\" as a number");
    }
}

/// `int opt_long(const char *value, long *result)` — `apps/lib/opt.c:590-616`.
fn opt_long(prog: &str, value: &str) -> Option<c_long> {
    match strtol_base0(value) {
        Some(l) => Some(l),
        None => {
            opt_number_error(prog, value);
            None
        }
    }
}

/// `int opt_int(const char *value, int *result)` — `apps/lib/opt.c:542-556`.
fn opt_int(prog: &str, value: &str) -> Option<c_int> {
    let l = opt_long(prog, value)?;
    let r = l as c_int;
    if c_long::from(r) != l {
        eprintln!("{prog}: Value \"{value}\" outside integer range");
        return None;
    }
    Some(r)
}

/// `int genrsa_main(int argc, char **argv)` — `apps/genrsa.c:84-258`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `BN_GENCB *cb = BN_GENCB_new(); BIGNUM *bn = BN_new(); ... if (bn == NULL ||
    // cb == NULL) goto end;` — `apps/genrsa.c:86-101`.
    // SAFETY: the constructors return NULL or a live object.
    let cb = unsafe { BN_GENCB_new() };
    // SAFETY: the constructor returns NULL or a live object.
    let bn = unsafe { BN_new() };
    let ret = 1i32;
    if bn.is_null() || cb.is_null() {
        // SAFETY: both pointers are NULL or live and not freed again.
        unsafe { BN_free(bn) };
        // SAFETY: both pointers are NULL or live and not freed again.
        unsafe { BN_GENCB_free(cb) };
        return ret;
    }

    // `opt_set_unknown_name("cipher"); prog = opt_init(argc, argv,
    // genrsa_options);` — `apps/genrsa.c:103-104`. The unknown-name mode is an
    // `apps/lib` behaviour (see the header).
    let mut opts = Opts::init(argv, GENRSA_OPTIONS);

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/genrsa.c:105`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: ret = 0; opt_help(genrsa_options); goto end;` —
            // `apps/genrsa.c:112-115`.
            OptMatch::Help => {
                // SAFETY: both pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: both pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return not_landed("genrsa -help");
            }
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/genrsa.c:107-111`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                // SAFETY: both pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: both pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return 1;
            }
            // `case OPT_3: f4 = RSA_3; break;` — `apps/genrsa.c:117-119`.
            OptMatch::Flag("3") => {}
            // `case OPT_F4: f4 = RSA_F4; break;` — the table's `F4` and `f4` rows
            // both name this arm (`apps/genrsa.c:121-124`).
            OptMatch::Flag("F4") | OptMatch::Flag("f4") => {}
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/genrsa.c:124-126`.
            OptMatch::Value("out", _) => {}
            // `case OPT_ENGINE: eng = setup_engine(opt_arg(), 0); break;` —
            // `apps/genrsa.c:127-129`.
            OptMatch::Value("engine", _) => {
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return not_landed("genrsa -engine");
            }
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/genrsa.c:130-133`. `opt_rand` is an `apps/lib` helper.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return not_landed("genrsa -rand");
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/genrsa.c:134-137`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => {
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return not_landed("genrsa -provider");
            }
            // `case OPT_PASSOUT: passoutarg = opt_arg(); break;` —
            // `apps/genrsa.c:138-140`.
            OptMatch::Value("passout", _) => {
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return not_landed("genrsa -passout");
            }
            // `case OPT_CIPHER: ciphername = opt_unknown(); break;` —
            // `apps/genrsa.c:141-143`.
            OptMatch::Value("", _) => {}
            // `case OPT_PRIMES: primes = opt_int_arg(); break;` —
            // `apps/genrsa.c:144-146`.
            OptMatch::Value("primes", v) => {
                let _ = opt_int(opts.prog(), &v);
            }
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/genrsa.c:147-149`.
            OptMatch::Flag("verbose") => {}
            // `case OPT_QUIET: verbose = 0; break;` — `apps/genrsa.c:150-152`.
            OptMatch::Flag("quiet") => {}
            // `case OPT_TRADITIONAL: traditional = 1; break;` —
            // `apps/genrsa.c:153-155`.
            OptMatch::Flag("traditional") => {}
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (argc == 1) { if
    // (!opt_int(argv[0], &num) || num <= 0) goto end; if (num >
    // OPENSSL_RSA_MAX_MODULUS_BITS) BIO_printf(...); } else if
    // (!opt_check_rest_arg(NULL)) { goto opthelp; }` — `apps/genrsa.c:159-173`.
    if opts.num_rest() == 1 {
        match opt_int(opts.prog(), opts.rest()[0].as_str()) {
            Some(n) if n > 0 => {
                if n > OPENSSL_RSA_MAX_MODULUS_BITS {
                    eprintln!(
                        "Warning: It is not recommended to use more than {OPENSSL_RSA_MAX_MODULUS_BITS} bit for RSA keys.\n\
                         \x20        Your key size is {n}! Larger key size may behave not as expected."
                    );
                }
            }
            _ => {
                // `goto end;` — `apps/genrsa.c:164-165`.
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_free(bn) };
                // SAFETY: the pointers are live and not freed again.
                unsafe { BN_GENCB_free(cb) };
                return ret;
            }
        }
    } else if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        // SAFETY: the pointers are live and not freed again.
        unsafe { BN_free(bn) };
        // SAFETY: the pointers are live and not freed again.
        unsafe { BN_GENCB_free(cb) };
        return ret;
    }

    // `if (!app_RAND_load()) goto end;` — `apps/genrsa.c:175-176`. The RNG load
    // and every step after it are `apps/lib` helpers this stratum does not own
    // (see the header), so the body stops here.
    // SAFETY: the pointers are live and not freed again.
    unsafe { BN_free(bn) };
    // SAFETY: the pointers are live and not freed again.
    unsafe { BN_GENCB_free(cb) };
    not_landed("genrsa key generation (app_RAND_load absent)")
}
