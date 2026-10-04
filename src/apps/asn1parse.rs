//! Phase 17.1d — `apps/asn1parse.c`: the `openssl asn1parse` command.
//!
//! The command body (`apps/asn1parse.c:72-329`): parse the generated
//! `ASN1PARSE_OPTIONS` table, read the input as PEM (through `PEM_read_bio`'s generic
//! name/header/data reader) or as raw DER/B64 bytes, then dump the structure through
//! `ASN1_parse_dump`. The parse, the PEM/raw read and the dump are transcribed whole;
//! the `-genstr`/`-genconf` generator, the `-oid` file, the `-strparse` dig and the
//! `-item` printer reach surfaces this stratum does not own and are recorded.
//!
//! ## What the court drives
//!
//! `asn1parse -in <certs.pem>` (the generic PEM reader over the fixed certificate
//! fixture) and `asn1parse -in <cert.der> -inform DER` (the raw-byte reader, with the
//! `D` `opt_format` arm). Both dump through `ASN1_parse_dump`, whose output is a pure
//! function of the input DER, and `-noout` (the empty-output arm).
//!
//! ## Recorded divergences (module header)
//!
//! * **`-genstr`/`-genconf` are not landed.** `do_generate` (`apps/asn1parse.c:331-375`)
//!   reaches `ASN1_generate_nconf` and the `CONF` loader (`app_load_config`), an
//!   `apps/lib` helper this stratum does not own; an input that selects them reaches
//!   [`not_landed`](crate::apps::openssl::not_landed).
//! * **`-oid`, `-strparse` and `-item` are not landed.** `OBJ_create_objects`, the
//!   `d2i_ASN1_TYPE` dig loop (`apps/asn1parse.c:242-279`) and `ASN1_item_d2i`/
//!   `ASN1_item_print` (`apps/asn1parse.c:300-308`) are reachable but not driven by the
//!   court's fixed argv; each reaches [`not_landed`](crate::apps::openssl::not_landed)
//!   rather than a fabricated dump. The `-item` not-found listing is transcribed.
//! * **`opt_format` is reduced to its observable.** The authority parses `-inform`
//!   through `opt_format` (`apps/lib/opt.c:277-365`) with `OPT_FMT_ASN1` (PEM/DER/B64);
//!   this module transcribes the `P`, `D`, `B` and `default` arms and their
//!   `Bad format` messages.
//! * **`strtol(opt_arg(), NULL, 0)`** for `-offset`/`-length`/`-dlimit` is transcribed
//!   best-effort (a failed conversion answers 0, as `strtol` does).
//! * **`-help` is not landed.** `opt_help` is the boundary
//!   [`crate::apps::opt`] records.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar};

use crate::apps::keyio::{bio_open_default, FORMAT_ASN1, FORMAT_PEM};
use crate::apps::openssl::not_landed;
use crate::apps::opt::{OptMatch, Opts};
use crate::apps::tables::ASN1PARSE_OPTIONS;
use crate::asn1::der::ASN1_parse_dump;
use crate::asn1::layout::Asn1Item;
use crate::evp::pem_bridge::PEM_read_bio;
use crate::runtime::bio::iolib::BIO_read;
use crate::runtime::buffer::{BUF_MEM_free, BUF_MEM_grow, BUF_MEM_new};

/// `FORMAT_BASE64` — `apps/include/fmt.h:30`.
const FORMAT_BASE64: c_int = 3 | 0x8000;
/// `BUFSIZ` — the C library's stdio buffer size.
const BUFSIZ: usize = 8192;

/// `strtol(value, NULL, 0)` — the base-0 conversion the authority uses for
/// `-offset`/`-length`/`-dlimit`; a failed conversion answers 0, as `strtol` does.
fn strtol_base0(value: &str) -> c_long {
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
    let mut acc: i128 = 0;
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
        acc = acc
            .saturating_mul(i128::from(radix))
            .saturating_add(i128::from(d));
        j += 1;
    }
    let signed = if neg { -acc } else { acc };
    signed.clamp(i128::from(c_long::MIN), i128::from(c_long::MAX)) as c_long
}

/// `opt_format(s, OPT_FMT_ASN1, result)` — the `P`, `D`, `B` and `default` arms of
/// `apps/lib/opt.c:277-365`, with `OPT_FMT_ASN1` (`OPT_FMT_PEM | OPT_FMT_DER |
/// OPT_FMT_B64`). Returns the authority's 0/1 and prints its refusal text to stderr.
fn opt_format_asn1(prog: &str, s: &str, result: &mut c_int) -> bool {
    match s.as_bytes().first().copied() {
        Some(b'B') | Some(b'b')
            if s.len() == 1 || s == "B64" || s == "b64" || s == "BASE64" || s == "base64" =>
        {
            *result = FORMAT_BASE64;
            true
        }
        Some(b'D') | Some(b'd') => {
            *result = FORMAT_ASN1;
            true
        }
        Some(b'P') | Some(b'p') if s.len() == 1 || s == "PEM" || s == "pem" => {
            *result = FORMAT_PEM;
            true
        }
        Some(b'B') | Some(b'b') | Some(b'P') | Some(b'p') => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
        _ => {
            eprintln!("{prog}: Bad format \"{s}\"");
            false
        }
    }
}

/// `int asn1parse_main(int argc, char **argv)` — `apps/asn1parse.c:72-329`.
#[allow(clippy::never_loop)] // every arm returns or breaks; the authority's loop never iterates
pub fn main(argv: &[String]) -> i32 {
    // `prog = opt_init(argc, argv, asn1parse_options);` — `apps/asn1parse.c:91`.
    let mut opts = Opts::init(argv, ASN1PARSE_OPTIONS);
    let mut infile: Option<String> = None;
    let mut derfile: Option<String> = None;
    let mut oidfile: Option<String> = None;
    let mut genstr: Option<String> = None;
    let mut genconf: Option<String> = None;
    let mut strparse = false;
    let mut indent = false;
    let mut noout = false;
    let mut dump: c_int = 0;
    let mut informat = FORMAT_PEM;
    let mut offset: c_long = 0;
    let mut length: c_long = 0;
    let mut item: *const Asn1Item = core::ptr::null();

    loop {
        // `while ((o = opt_next()) != OPT_EOF)` — `apps/asn1parse.c:98`.
        match opts.next() {
            OptMatch::End => break,
            // `case OPT_HELP: opt_help(asn1parse_options); ret = 0; goto end;` —
            // `apps/asn1parse.c:105-108`.
            OptMatch::Help => return not_landed("asn1parse -help"),
            // `case OPT_EOF: case OPT_ERR: opthelp: BIO_printf(bio_err, "%s: Use -help
            // for summary.\n", prog); goto end;` — `apps/asn1parse.c:100-104`.
            OptMatch::Error(e) => {
                eprintln!("{e}");
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
            // `case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ASN1, &informat))
            // goto opthelp;` — `apps/asn1parse.c:109-112`.
            OptMatch::Value("inform", v) => {
                if !opt_format_asn1(opts.prog(), &v, &mut informat) {
                    eprintln!("{}: Use -help for summary.", opts.prog());
                    return 1;
                }
            }
            // `case OPT_IN: infile = opt_arg(); break;` — `apps/asn1parse.c:113-115`.
            OptMatch::Value("in", v) => infile = Some(v),
            // `case OPT_OUT: derfile = opt_arg(); break;` — `apps/asn1parse.c:116-118`.
            OptMatch::Value("out", v) => derfile = Some(v),
            // `case OPT_INDENT: indent = 1; break;` — `apps/asn1parse.c:119-121`.
            OptMatch::Flag("i") => indent = true,
            // `case OPT_NOOUT: noout = 1; break;` — `apps/asn1parse.c:122-124`.
            OptMatch::Flag("noout") => noout = true,
            // `case OPT_OID: oidfile = opt_arg(); break;` — `apps/asn1parse.c:125-127`.
            OptMatch::Value("oid", v) => oidfile = Some(v),
            // `case OPT_OFFSET: offset = strtol(opt_arg(), NULL, 0); break;` —
            // `apps/asn1parse.c:128-130`.
            OptMatch::Value("offset", v) => offset = strtol_base0(&v),
            // `case OPT_LENGTH: length = strtol(opt_arg(), NULL, 0); break;` —
            // `apps/asn1parse.c:131-133`.
            OptMatch::Value("length", v) => length = strtol_base0(&v),
            // `case OPT_DUMP: dump = -1; break;` — `apps/asn1parse.c:134-136`.
            OptMatch::Flag("dump") => dump = -1,
            // `case OPT_DLIMIT: dump = strtol(opt_arg(), NULL, 0); break;` —
            // `apps/asn1parse.c:137-139`.
            OptMatch::Value("dlimit", v) => dump = strtol_base0(&v) as c_int,
            // `case OPT_STRPARSE: if (sk_OPENSSL_STRING_push(osk, opt_arg()) <= 0)
            // goto end;` — `apps/asn1parse.c:140-143`. Not driven; see the header.
            OptMatch::Value("strparse", _) => strparse = true,
            // `case OPT_GENSTR: genstr = opt_arg(); break;` — `apps/asn1parse.c:144-146`.
            OptMatch::Value("genstr", v) => genstr = Some(v),
            // `case OPT_GENCONF: genconf = opt_arg(); break;` — `apps/asn1parse.c:147-149`.
            OptMatch::Value("genconf", v) => genconf = Some(v),
            // `case OPT_STRICTPEM: informat = FORMAT_PEM; break;` —
            // `apps/asn1parse.c:150-153`.
            OptMatch::Flag("strictpem") => informat = FORMAT_PEM,
            // `case OPT_ITEM: it = ASN1_ITEM_lookup(opt_arg()); if (it == NULL) { ...
            // }` — `apps/asn1parse.c:154-169`.
            OptMatch::Value("item", v) => {
                // SAFETY: `v` is a Rust string; the NUL-terminated copy outlives the call.
                let cs = match std::ffi::CString::new(v.clone()) {
                    Ok(c) => c,
                    Err(_) => return 1,
                };
                // SAFETY: `cs` is NUL-terminated and outlives the call.
                item = unsafe { crate::asn1::asn1_item_list::ASN1_ITEM_lookup(cs.as_ptr()) };
                if item.is_null() {
                    eprintln!("Unknown item name {v}");
                    eprintln!("Supported types:");
                    let mut tmp = 0usize;
                    loop {
                        // SAFETY: `ASN1_ITEM_get` answers NULL past the table's end.
                        let it = unsafe { crate::asn1::asn1_item_list::ASN1_ITEM_get(tmp) };
                        if it.is_null() {
                            break;
                        }
                        // SAFETY: `it` is a table entry; `sname` is a static literal.
                        let sname = unsafe { (*it).sname };
                        // SAFETY: `sname` is a NUL-terminated static.
                        let s = unsafe { std::ffi::CStr::from_ptr(sname) }
                            .to_string_lossy()
                            .into_owned();
                        eprintln!("    {s}");
                        tmp += 1;
                    }
                    return 1;
                }
            }
            OptMatch::Flag(_) | OptMatch::Value(_, _) => {
                eprintln!("{}: Use -help for summary.", opts.prog());
                return 1;
            }
        }
    }

    // `if (!opt_check_rest_arg(NULL)) goto opthelp;` — `apps/asn1parse.c:173-175`.
    if !opts.check_rest_arg(None) {
        eprintln!("{}: Use -help for summary.", opts.prog());
        return 1;
    }

    // Arms this stratum does not own (see the header).
    if oidfile.is_some() {
        return not_landed("asn1parse -oid");
    }
    if genstr.is_some() || genconf.is_some() {
        return not_landed("asn1parse -genstr/-genconf");
    }
    if strparse {
        return not_landed("asn1parse -strparse");
    }
    if informat == FORMAT_BASE64 {
        return not_landed("asn1parse -inform B64");
    }
    if !item.is_null() {
        return not_landed("asn1parse -item");
    }

    // `in = bio_open_default(infile, 'r', informat); if (in == NULL) goto end;` —
    // `apps/asn1parse.c:185-186`.
    let inbio = bio_open_default(infile.as_deref(), false);
    if inbio.is_null() {
        return not_landed("asn1parse -in (unopenable)");
    }
    // `derout = bio_open_default(derfile, 'w', FORMAT_ASN1);` —
    // `apps/asn1parse.c:188-189`.
    let derout = if derfile.is_some() {
        let b = bio_open_default(derfile.as_deref(), true);
        if b.is_null() {
            // SAFETY: `inbio` is live.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            return not_landed("asn1parse -out (unopenable)");
        }
        b
    } else {
        core::ptr::null_mut()
    };

    let ret = 1i32;
    // `buf = BUF_MEM_new(); if (buf == NULL) goto end;` — `apps/asn1parse.c:191-192`.
    let buf = BUF_MEM_new();
    if buf.is_null() {
        // SAFETY: all three are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(derout) };
        // SAFETY: all three are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        return ret;
    }

    // The `str`/`num` pair the read arms fill.
    let mut strp: *mut c_uchar = core::ptr::null_mut();
    let mut num: c_long = 0;

    if informat == FORMAT_PEM {
        // `PEM_read_bio(in, &name, &header, &str, &num) != 1` —
        // `apps/asn1parse.c:193-200`.
        let mut name: *mut c_char = core::ptr::null_mut();
        let mut header: *mut c_char = core::ptr::null_mut();
        // SAFETY: `inbio` is live; the three out-parameters are this frame's.
        let ok = unsafe { PEM_read_bio(inbio, &mut name, &mut header, &mut strp, &mut num) };
        if ok != 1 {
            eprintln!("Error reading PEM file");
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(derout) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            // SAFETY: all three are live and not freed again.
            unsafe { BUF_MEM_free(buf) };
            return ret;
        }
        // `buf->data = (char *)str; buf->length = buf->max = num;` —
        // `apps/asn1parse.c:199-200`.
        // SAFETY: `buf` is live and uniquely owned here.
        unsafe {
            (*buf).data = strp.cast::<c_char>();
            (*buf).length = num as usize;
            (*buf).max = num as usize;
        }
        // The authority leaks `name`/`header` into locals it frees at `end`; mirror the
        // free here (they are the reader's own allocations).
        // SAFETY: `name`/`header` are NULL or the `PEM_read_bio` allocations.
        unsafe {
            if !name.is_null() {
                libc_free(name.cast());
            }
            if !header.is_null() {
                libc_free(header.cast());
            }
        }
        // SAFETY: `buf` is live.
        strp = unsafe { (*buf).data.cast::<c_uchar>() };
    } else {
        // `if (!BUF_MEM_grow(buf, BUFSIZ * 8)) goto end;` — `apps/asn1parse.c:202-203`.
        // SAFETY: `buf` is live.
        if unsafe { BUF_MEM_grow(buf, BUFSIZ * 8) } == 0 {
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(derout) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            // SAFETY: all three are live and not freed again.
            unsafe { BUF_MEM_free(buf) };
            return ret;
        }
        // The `FORMAT_BASE64` arm wraps the input in a base64 filter; the court's DER arm
        // does not select it. `BIO_read` on the raw input follows.
        // SAFETY: `buf` is live.
        let mut n: c_long = 0;
        loop {
            // SAFETY: `buf` is live.
            if unsafe { BUF_MEM_grow(buf, (n as usize) + BUFSIZ) } == 0 {
                break;
            }
            // SAFETY: `inbio` is live; the destination is `buf->data` with room for BUFSIZ.
            let i = unsafe { BIO_read(inbio, (*buf).data.add(n as usize).cast(), BUFSIZ as c_int) };
            if i <= 0 {
                break;
            }
            n += c_long::from(i);
        }
        num = n;
        // SAFETY: `buf` is live.
        strp = unsafe { (*buf).data.cast::<c_uchar>() };
    }

    // `if (offset < 0 || offset >= num) { ... "Error: offset out of range" ... }` —
    // `apps/asn1parse.c:281-284`.
    if offset < 0 || offset >= num {
        eprintln!("Error: offset out of range");
        // SAFETY: all three are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(derout) };
        // SAFETY: all three are live and not freed again.
        unsafe { crate::runtime::bio::BIO_free(inbio) };
        // SAFETY: all three are live and not freed again.
        unsafe { BUF_MEM_free(buf) };
        return ret;
    }
    num -= offset;
    // `if (length == 0 || length > (unsigned int)num) length = (unsigned int)num;` —
    // `apps/asn1parse.c:288-289`.
    if length == 0 || length > num {
        length = num;
    }

    if !derout.is_null() {
        // `BIO_write(derout, str + offset, length) != (int)length` —
        // `apps/asn1parse.c:290-296`.
        // SAFETY: `strp` points into the live buffer; `offset`/`length` are in bounds.
        let w = unsafe {
            crate::runtime::bio::iolib::BIO_write(
                derout,
                strp.add(offset as usize).cast(),
                length as c_int,
            )
        };
        if c_long::from(w) != length {
            eprintln!("Error writing output");
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(derout) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            // SAFETY: all three are live and not freed again.
            unsafe { BUF_MEM_free(buf) };
            return ret;
        }
    }

    let mut ret = ret;
    if !noout {
        // `ASN1_parse_dump(bio_out, p, length, indent, dump)` —
        // `apps/asn1parse.c:298-315`. `bio_out` is the program's stdout.
        let bio_out = bio_open_default(None, true);
        // SAFETY: `strp` points into the live buffer; `bio_out` is live.
        let ok = unsafe {
            ASN1_parse_dump(
                bio_out,
                strp.add(offset as usize),
                length,
                c_int::from(indent),
                dump,
            )
        };
        // SAFETY: `bio_out` is this frame's own BIO; the caller's stdout stream is
        // `BIO_NOCLOSE`, so the underlying `FILE *` is untouched.
        unsafe { crate::runtime::bio::BIO_free(bio_out) };
        if ok == 0 {
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(derout) };
            // SAFETY: all three are live and not freed again.
            unsafe { crate::runtime::bio::BIO_free(inbio) };
            // SAFETY: all three are live and not freed again.
            unsafe { BUF_MEM_free(buf) };
            return ret;
        }
    }
    ret = 0;

    // `end: BIO_free(derout); BIO_free(in); BIO_free(b64); BUF_MEM_free(buf); ...` —
    // `apps/asn1parse.c:317-327`.
    // SAFETY: all three are NULL or live and not freed again.
    unsafe { crate::runtime::bio::BIO_free(derout) };
    // SAFETY: all three are NULL or live and not freed again.
    unsafe { crate::runtime::bio::BIO_free(inbio) };
    // SAFETY: all three are NULL or live and not freed again.
    unsafe { BUF_MEM_free(buf) };
    ret
}

/// `OPENSSL_free` for the generic PEM reader's allocations. `PEM_read_bio` allocates
/// `name`/`header` with `OPENSSL_malloc`, which for this crate is the C allocator.
///
/// # Safety
/// `p` must be NULL or an `OPENSSL_malloc` block not freed elsewhere.
unsafe fn libc_free(p: *mut core::ffi::c_void) {
    // SAFETY: the caller's contract.
    unsafe { crate::runtime::mem::CRYPTO_free(p, core::ptr::null(), 0) };
}
