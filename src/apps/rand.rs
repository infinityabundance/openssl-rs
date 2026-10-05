//! Phase 17.1e — `apps/rand.c`: the `openssl rand` command.
//!
//! The command body (`apps/rand.c:53-232`): parse the generated `RAND_OPTIONS`
//! table, read the optional `num[K|M|G|T]` argument (its suffix/shift/overflow
//! checks), open the output, then write `scaled_num` random bytes through
//! `RAND_bytes_ex`, optionally base64-wrapped or hex-rendered. The parse, the
//! `max` special case, the suffix/shift/overflow checks and the output shape are
//! transcribed.
//!
//! ## What the court drives
//!
//! The arms that are a pure function of the argv: `rand` (no argument, whose
//! `scaled_num` stays 0 and whose output is empty), `rand 0` (the `num <= 0`
//! refusal) and `rand abc`/`rand -hex abc` (the `Invalid size suffix` refusal).
//! Every arm that emits the random stream itself is recorded: the stream is a
//! fresh DRBG output on both sides and cannot be diffed.
//!
//! ## Recorded divergences (module header)
//!
//! * **The random stream is not driven.** `rand <n>`, `rand <n>K`, `rand -hex
//!   <n>` and `rand -base64 <n>` write a fresh DRBG stream; the streams are
//!   independent, so those argv are recorded rather than diffed.
//! * **`app_RAND_load` is not called.** The authority's `app_RAND_load()`
//!   (`apps/rand.c:187-188`) is an `apps/lib` helper this stratum does not own.
//!   The landed body opens the output and writes through `RAND_bytes_ex`
//!   ([`crate::rand::rand_lib::RAND_bytes_ex`]); for the zero-length arms the
//!   observable is identical, because the loop body never runs.
//! * **`-engine`, `-rand`/`-writerand` and the provider arms are not landed.**
//!   They call `setup_engine`/`opt_rand`/`opt_provider` (`apps/rand.c:80-96`), the
//!   `apps/lib` boundaries.
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long};

use crate::apps::keyio::bio_open_default;
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::RAND_OPTIONS;
use crate::evp::bio_enc::BIO_f_base64;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::{BIO_free_all, BIO_new, BIO_push};

/// `FORMAT_BINARY` — `apps/include/fmt.h:29`.
const FORMAT_BINARY: c_int = 2;
/// `FORMAT_TEXT` — `apps/include/fmt.h:28`.
const FORMAT_TEXT: c_int = 1 | 0x8000;
/// `FORMAT_BASE64` — `apps/include/fmt.h:30`.
const FORMAT_BASE64: c_int = 3 | 0x8000;

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

/// `int rand_main(int argc, char **argv)` — `apps/rand.c:53-232`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, rand_options);` — `apps/rand.c:65`.
    let mut opts = Opts::init(argv, RAND_OPTIONS);
    let mut outfile: Option<String> = None;
    let mut format = FORMAT_BINARY;
    let mut num: c_long = -1;
    let mut scaled_num: u64 = 0;

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/rand.c:66`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(rand_options); ret = 0; goto end;` —
            // `apps/rand.c:73-76`.
            OptMatch::Help => return not_landed("rand -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use
            // -help for summary.\n", prog); goto end;` — `apps/rand.c:68-72`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_OUT: outfile = opt_arg(); break;` — `apps/rand.c:77-79`.
            OptMatch::Value("out", v) => outfile = Some(v),
            // `case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;` —
            // `apps/rand.c:80-82`.
            OptMatch::Value("engine", _) => return not_landed("rand -engine"),
            // `case OPT_R_CASES: if (!opt_rand(o)) goto end;` — `apps/rand.c:83-86`.
            OptMatch::Value("rand", _) | OptMatch::Value("writerand", _) => {
                return not_landed("rand -rand")
            }
            // `case OPT_BASE64: format = FORMAT_BASE64; break;` — `apps/rand.c:87-89`.
            OptMatch::Flag("base64") => format = FORMAT_BASE64,
            // `case OPT_HEX: format = FORMAT_TEXT; break;` — `apps/rand.c:90-92`.
            OptMatch::Flag("hex") => format = FORMAT_TEXT,
            // `case OPT_PROV_CASES: if (!opt_provider(o)) goto end;` —
            // `apps/rand.c:93-96`.
            OptMatch::Value("provider-path", _)
            | OptMatch::Value("provider", _)
            | OptMatch::Value("provparam", _)
            | OptMatch::Value("propquery", _) => return not_landed("rand -provider"),
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `argc = opt_num_rest(); argv = opt_rest(); if (argc == 1) { ... } else if
    // (!opt_check_rest_arg(NULL)) { goto opthelp; }` — `apps/rand.c:101-185`.
    if opts.num_rest() == 1 {
        let arg = opts.rest()[0].clone();
        let mut shift = 0u32;

        // `if (!strcmp(argv[0], "max")) { scaled_num = UINT64_MAX >> 3; }` —
        // `apps/rand.c:111-117`.
        if arg == "max" {
            scaled_num = u64::MAX >> 3;
        } else {
            // `while (argv[0][factoridx]) { if (!isdigit(...)) { switch(...) ... } }`
            // — `apps/rand.c:129-159`.
            let bytes = arg.as_bytes();
            let mut factoridx = 0usize;
            while factoridx < bytes.len() {
                if !bytes[factoridx].is_ascii_digit() {
                    match bytes[factoridx] {
                        b'K' => shift = 10,
                        b'M' => shift = 20,
                        b'G' => shift = 30,
                        b'T' => shift = 40,
                        _ => {
                            eprintln!("Invalid size suffix {}", &arg[factoridx..]);
                            eprintln!("{}: Use -help for summary.", opts.prog());
                            return 1;
                        }
                    }
                    break;
                }
                factoridx += 1;
            }
            if shift != 0 && arg.len() - factoridx != 1 {
                eprintln!("Invalid size suffix {}", &arg[factoridx..]);
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            let numeric = &arg[..factoridx];

            // `if ((scaled_num == 0) && (!opt_long(argv[0], &num) || num <= 0)) goto
            // opthelp;` — `apps/rand.c:164-165`.
            if scaled_num == 0 {
                match opt_long(opts.prog(), numeric) {
                    Some(n) if n > 0 => num = n,
                    _ => {
                        eprintln!("{}: Use -help for summary.", opts.prog());
                        return 1;
                    }
                }
            }

            if shift != 0 {
                // `if ((UINT64_MAX >> shift) < (size_t)num) { ... overflows ... }` —
                // `apps/rand.c:167-178`.
                if (u64::MAX >> shift) < num as u64 {
                    eprintln!("{num} bytes with suffix overflows");
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
                scaled_num = (num as u64) << shift;
                if scaled_num > (u64::MAX >> 3) {
                    eprintln!("Request exceeds max allowed output");
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            } else if scaled_num == 0 {
                scaled_num = num as u64;
            }
        }
    } else if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // `if (!app_RAND_load()) goto end;` — `apps/rand.c:187-188`. The RNG load is
    // an `apps/lib` helper; it is not called (see the header).

    // `out = bio_open_default(outfile, 'w', format); if (out == NULL) goto end;`
    // — `apps/rand.c:190-192`.
    let mut out = bio_open_default(outfile.as_deref(), true);
    if out.is_null() {
        return 1;
    }

    // `if (format == FORMAT_BASE64) { BIO *b64 = BIO_new(BIO_f_base64()); ...
    // out = BIO_push(b64, out); }` — `apps/rand.c:194-199`.
    if format == FORMAT_BASE64 {
        // SAFETY: `BIO_f_base64` is this crate's method table.
        let b64 = unsafe { BIO_new(BIO_f_base64()) };
        if b64.is_null() {
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            return 1;
        }
        // SAFETY: both are live and the chain is owned by `out`.
        out = unsafe { BIO_push(b64, out) };
    }

    // `buf = app_malloc(buflen, ...); while (scaled_num > 0) { ... }` —
    // `apps/rand.c:201-218`.
    let buflen = 1usize << 16;
    let mut buf = vec![0u8; buflen];
    let ret;
    'outer: loop {
        if scaled_num == 0 {
            ret = 0i32;
            break;
        }
        let chunk = if scaled_num > buflen as u64 {
            buflen
        } else {
            scaled_num as usize
        };
        // `r = RAND_bytes_ex(app_get0_libctx(), buf, chunk, 0);` —
        // `apps/rand.c:206`. `app_get0_libctx()` is NULL.
        // SAFETY: `buf` is a live buffer of `chunk` bytes; the libctx is NULL.
        let r = unsafe { RAND_bytes_ex(core::ptr::null_mut(), buf.as_mut_ptr(), chunk, 0) };
        if r <= 0 {
            ret = 1;
            break 'outer;
        }
        if format != FORMAT_TEXT {
            // SAFETY: `out` is live and `buf[..chunk]` is readable.
            let w = unsafe { BIO_write(out, buf.as_ptr().cast(), chunk as c_int) };
            if w != chunk as c_int {
                ret = 1;
                break 'outer;
            }
        } else {
            let mut hex = String::with_capacity(chunk * 2);
            for b in &buf[..chunk] {
                hex.push_str(&format!("{b:02x}"));
            }
            // SAFETY: `out` is live; the string is this frame's.
            let w = unsafe { BIO_write(out, hex.as_ptr().cast(), hex.len() as c_int) };
            if w != hex.len() as c_int {
                ret = 1;
                break 'outer;
            }
        }
        scaled_num -= chunk as u64;
    }

    // `if (format == FORMAT_TEXT) BIO_puts(out, "\n"); if (BIO_flush(out) <= 0)
    // goto end;` — `apps/rand.c:219-222`.
    if ret == 0 {
        if format == FORMAT_TEXT {
            // SAFETY: `out` is live; the literal is static.
            unsafe { crate::runtime::bio::iolib::BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: `out` is live.
        let flushed = unsafe {
            crate::runtime::bio::BIO_ctrl(
                out,
                crate::runtime::bio::BIO_CTRL_FLUSH,
                0,
                core::ptr::null_mut(),
            )
        };
        if flushed <= 0 {
            // SAFETY: `out` is live and not freed again.
            unsafe { BIO_free_all(out) };
            return 1;
        }
    }

    // SAFETY: `out` is live and not freed again.
    unsafe { BIO_free_all(out) };
    ret
}
