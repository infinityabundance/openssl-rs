//! Phase 17.1 — `apps/dsaparam.c`: the `openssl dsaparam` command.
//!
//! The command body (`apps/dsaparam.c:74-262`) parses the generated
//! `DSAPARAM_OPTIONS` table, reads the optional `numbits`/`numqbits` arguments,
//! then loads the RNG and either generates DSA parameters or reads them from
//! `-in`. The parse and the bitsize validation are transcribed exactly; the
//! generation/load path reaches [`not_landed`] at `app_RAND_load`.
//!
//! ## What the court drives
//!
//! Only the arms that finish before any randomness: the missing/invalid
//! `numbits` conversions (`dsaparam abc`, `dsaparam -text abc`, the two-argument
//! conversions) and the parser refusals (an unknown option, three positional
//! arguments, a bad `-inform`). Each has fixed text and an empty error queue.
//!
//! ## Recorded divergences (module header)
//!
//! * **Parameter generation and `-in` loading are not landed.** `app_RAND_load`
//!   (`apps/dsaparam.c:155-156`), `load_keyparams`, `app_paramgen`, `app_keygen`
//!   and `bio_open_owner` are `apps/lib` helpers this stratum does not own, and
//!   generated parameters are random besides, so a numeric `numbits` reaches
//!   [`not_landed`] rather than fabricating parameters.
//! * **`opt_int` is reduced to its observable.** The authority parses the numeric
//!   arguments through `opt_int`/`opt_long` (`apps/lib/opt.c:542-616`); this
//!   module transcribes the `strtol(..., 0)` conversion and its messages.
//! * **`opt_format` is reduced to its observable.** The authority parses
//!   `-inform`/`-outform` through `opt_format` (`apps/lib/opt.c:277-365`); this
//!   module transcribes the PEM/DER arms and their `Bad format` messages.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//! * The `-engine`, `-rand`/`-writerand` and provider arms reach unlanded
//!   `apps/lib` helpers (`setup_engine`, `opt_rand`, `opt_provider`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::DSAPARAM_OPTIONS;

/// `FORMAT_ASN1` — `apps/include/fmt.h:27`.
const FORMAT_ASN1: c_int = 4;
/// `FORMAT_PEM` — `apps/include/fmt.h:29`.
const FORMAT_PEM: c_int = 5 | 0x8000;

/// `strtol(value, &endp, 0)` — `apps/lib/opt.c:590-616`, the base-0 conversion
/// `opt_long` performs.
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

/// `int opt_int(const char *value, int *result)` — `apps/lib/opt.c:542-556`.
fn opt_int(prog: &str, value: &str) -> Option<c_int> {
    let l = match strtol_base0(value) {
        Some(l) => l,
        None => {
            opt_number_error(prog, value);
            return None;
        }
    };
    let r = l as c_int;
    if c_long::from(r) != l {
        eprintln!("{prog}: Value \"{value}\" outside integer range");
        return None;
    }
    Some(r)
}

/// `opt_format(s, OPT_FMT_PEMDER, result)` — the `P`, `D` and `default` arms of
/// `apps/lib/opt.c:277-365`.
fn opt_format(prog: &str, s: &str, result: &mut c_int) -> bool {
    let b = s.as_bytes();
    match b.first().copied() {
        Some(b'P') | Some(b'p') if b.len() == 1 || s == "PEM" || s == "pem" => {
            *result = FORMAT_PEM;
            true
        }
        Some(b'D') | Some(b'd') => {
            *result = FORMAT_ASN1;
            true
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

/// `int dsaparam_main(int argc, char **argv)` — `apps/dsaparam.c:74-262`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, dsaparam_options);` — `apps/dsaparam.c:86`.
    let mut opts = Opts::init(argv, DSAPARAM_OPTIONS);
    let ret = 1i32;
    let numbits: c_int = -1;
    let mut numqbits: c_int = -1;
    let mut num: c_int = 0;
    let mut informat = 0; // FORMAT_UNDEF
    let mut outformat = FORMAT_PEM;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/dsaparam.c:87`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(dsaparam_options); ret = 0; goto end;` —
            // `apps/dsaparam.c:94-97`.
            OptMatch::Help => return not_landed("dsaparam -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/dsaparam.c:89-93`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &informat)) goto opthelp;` — `apps/dsaparam.c:98-101`.
            OptMatch::Value("inform", v) => {
                if !opt_format(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/dsaparam.c:102-104`.
            OptMatch::Value("in", _) => {}
            // `case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER,
            // &outformat)) goto opthelp;` — `apps/dsaparam.c:105-108`.
            OptMatch::Value("outform", v) => {
                if !opt_format(opts.prog(), &v, &mut outformat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/dsaparam.c:109-111`.
            OptMatch::Value("out", _) => {}
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/dsaparam.c:112-114`.
            OptMatch::Value("engine", _) => return not_landed("dsaparam -engine"),
            // `case OPT_TEXT: text = 1; break;` — `apps/dsaparam.c:115-117`.
            OptMatch::Flag("text") => {}
            // `case OPT_GENKEY: genkey = 1; break;` — `apps/dsaparam.c:118-120`.
            OptMatch::Flag("genkey") => {}
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` —
            // `apps/dsaparam.c:121-124`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("dsaparam -rand");
            }
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/dsaparam.c:125-128`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("dsaparam -provider"),
            // `case OPT_NOOUT: noout = 1; break;` — `apps/dsaparam.c:129-131`.
            OptMatch::Flag("noout") => {}
            // `case OPT_VERBOSE: verbose = 1; break;` — `apps/dsaparam.c:132-134`.
            OptMatch::Flag("verbose") => {}
            // `case OPT_QUIET: verbose = 0; break;` — `apps/dsaparam.c:135-137`.
            OptMatch::Flag("quiet") => {}
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (argc == 2) { if
    // (!opt_int(argv[0], &num) || num < 0) goto opthelp; if (!opt_int(argv[1],
    // &numqbits) || numqbits < 0) goto opthelp; } else if (argc == 1) { if
    // (!opt_int(argv[0], &num) || num < 0) goto opthelp; } else if
    // (!opt_check_rest_arg(NULL)) { goto opthelp; }` — `apps/dsaparam.c:144-154`.
    match opts.num_rest() {
        2 => {
            match opt_int(opts.prog(), opts.rest()[0].as_str()) {
                Some(n) if n >= 0 => num = n,
                _ => {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return ret;
                }
            }
            match opt_int(opts.prog(), opts.rest()[1].as_str()) {
                Some(n) if n >= 0 => numqbits = n,
                _ => {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return ret;
                }
            }
        }
        1 => match opt_int(opts.prog(), opts.rest()[0].as_str()) {
            Some(n) if n >= 0 => num = n,
            _ => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return ret;
            }
        },
        _ => {
            if !opts.check_rest_arg(None) {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return ret;
            }
        }
    }

    // `if (!app_RAND_load()) goto end;` — `apps/dsaparam.c:155-156`. The RNG load
    // and every step after it (parameter generation or `-in` loading) are
    // `apps/lib` helpers this stratum does not own (see the header).
    let _ = (numbits, numqbits, num, informat, outformat);
    not_landed("dsaparam parameter generation (app_RAND_load absent)")
}
