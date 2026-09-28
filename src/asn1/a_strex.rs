//! Phase 5 — `crypto/asn1/a_strex.c`: the escaping printer and the UTF-8 converter.
//!
//! Three exports landed in Phase 5. Phase 10.11 adds the unit's **`X509_NAME` print half**
//! (`do_indent`, `do_name_ex`, `X509_NAME_print_ex`, `X509_NAME_print_ex_fp`) now that the
//! `X509_NAME` object model and its per-entry accessors are landed; nothing of the unit is
//! withheld after that.
//!
//! * `ASN1_STRING_print_ex` and `ASN1_STRING_print_ex_fp` are one implementation
//!   with two sinks. The sink is a `char_io` callback, so the *counting* pass and
//!   the *writing* pass run the same code — `do_print_ex` calls `do_buf` twice,
//!   once with a null sink to measure and once to emit. That is why the return
//!   value can be a length and why a value that escapes differently on the second
//!   pass cannot be produced.
//! * `ASN1_STRING_to_UTF8` turns any of the six character types into UTF-8 by
//!   routing through `ASN1_mbstring_copy` with a `MBSTRING_*` flag derived from the
//!   type, which is why it shares the `tag2nbyte` table with the printer.
//!
//! ## `tag2nbyte` is three things in one column
//!
//! The table maps a `V_ASN1_*` to `-1` (not a character type), `0` (UTF-8, so
//! variable width) or the bytes per character. Both callers read it, and each
//! reads a different aspect: the printer wants the *width* and uses `-1` to mean
//! "dump", while `ASN1_STRING_to_UTF8` wants `-1` to mean "refuse" and turns the
//! width into an `MBSTRING_*` flag by adding `MBSTRING_FLAG`. Note that the widths
//! `1` and `0` both become `MBSTRING_ASC` and `MBSTRING_UTF8` respectively, and
//! that a width of `1` for `V_ASN1_UTCTIME` and `V_ASN1_GENERALIZEDTIME` is not an
//! accident: a time is an ASCII string.
//!
//! ## The escape decision, and the two subtle branches
//!
//! `do_esc_char` is a priority ladder over one character, and two of its branches
//! are the ones a reimplementation gets wrong:
//!
//! * `CHARTYPE_BS_ESC` is the *union* of "escape this with a backslash" and "escape
//!   this only when it is first or last". The `orflags` mechanism in `do_buf` is
//!   what turns the position flags on for exactly the first and last characters,
//!   and it is applied as `flags | orflags` — the *union* is the test, and the
//!   `ASN1_STRFLGS_ESC_QUOTE` bit inside the same value is what decides between a
//!   quote and a backslash.
//! * A byte above `0x7f` is tested against `ASN1_STRFLGS_ESC_MSB` **alone**,
//!   bypassing the table. `char_type[]` has no entry for it, so the table is not
//!   consulted at all — and a caller that set only `ESC_CTRL` therefore leaves
//!   high bytes alone where a table lookup would have escaped them.
//!
//! ## `char_type[]` is read from the authority's generated header
//!
//! The 128-entry table below is the *generated* artifact `crypto/asn1/charmap.h`,
//! whose own generator is `crypto/asn1/charmap.pl` in the authority tree. It is
//! reproduced as the numbers that file contains rather than re-derived from the
//! generator's rules, because re-deriving it would be a second implementation of a
//! generator that could drift; the numbers are a generated artifact and the probe
//! pins them behaviourally by printing every one of the 128 bytes under several
//! flag sets, which is a stronger check than a transcription comparison.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void};

use crate::asn1::a_mbstr::ASN1_mbstring_copy;
use crate::asn1::a_type::i2d_ASN1_TYPE;
use crate::asn1::der::ASN1_tag2str;
use crate::asn1::layout::*;
use crate::asn1::string::as_str;
use crate::asn1::text::to_hex;
use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_file::BIO_new_fp;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{fwrite, FILE};
use crate::runtime::bio::{BIO_free, Bio, BIO_NOCLOSE};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{NID_undef, OBJ_nid2ln, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::str::OPENSSL_strnlen;
use crate::x509::x509name::{
    X509_NAME_ENTRY_get_data, X509_NAME_ENTRY_get_object, X509_NAME_ENTRY_set,
    X509_NAME_entry_count, X509_NAME_get_entry,
};
use crate::x509::x_name::{X509Name, X509_NAME_print};

/// The authority translation unit for the escaping printer.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/a_strex.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `CHARTYPE_FIRST_ESC_2253` — escaped with a backslash if it is first.
pub(crate) const CHARTYPE_FIRST_ESC_2253: u16 = 0x20;
/// `CHARTYPE_LAST_ESC_2253` — escaped with a backslash if it is last.
pub(crate) const CHARTYPE_LAST_ESC_2253: u16 = 0x40;

/// `CHARTYPE_BS_ESC` — the authority's union of "always" and "if first or last".
const CHARTYPE_BS_ESC: u16 =
    (ASN1_STRFLGS_ESC_2253 as u16) | CHARTYPE_FIRST_ESC_2253 | CHARTYPE_LAST_ESC_2253;

/// `ESC_FLAGS` — the bits `do_print_ex` keeps out of the full flag word.
const ESC_FLAGS: c_ulong = ASN1_STRFLGS_ESC_2253
    | ASN1_STRFLGS_ESC_2254
    | ASN1_STRFLGS_ESC_QUOTE
    | ASN1_STRFLGS_ESC_CTRL
    | ASN1_STRFLGS_ESC_MSB;

/// `BUF_TYPE_WIDTH_MASK` — the low bits of `do_buf`'s `type`, the character width.
const BUF_TYPE_WIDTH_MASK: c_int = 0x7;
/// `BUF_TYPE_CONVUTF8` — convert each character to UTF-8 on the way out.
const BUF_TYPE_CONVUTF8: c_int = 0x8;

/// `char_type[]` — the per-character property table.
///
/// Read out of `crypto/asn1/charmap.h`, which `crypto/asn1/charmap.pl` generates;
/// see the module documentation for why it is the generated numbers rather than a
/// re-derivation of the generator.
///
/// An indexed read is always inside this array: `do_esc_char` tests `chtmp > 0x7f`
/// first and a byte is at most `0xff`, so the high bit can never reach here.
#[rustfmt::skip]
static CHAR_TYPE: [u16; 128] = [
     1026,     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
        2,     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
        2,     2,     2,     2,     2,     2,     2,     2,   120,     0,     1,    40,
        0,     0,     0,    16,  1040,  1040, 33792,    25,    25, 16400,  8208,    16,
     4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,    16,     9,
        9,    16,     9,    16,     0,  4112,  4112,  4112,  4112,  4112,  4112,  4112,
     4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,
     4112,  4112,  4112,  4112,  4112,  4112,  4112,     0,  1025,     0,     0,     0,
        0,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,
     4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,  4112,
     4112,  4112,  4112,     0,     0,     0,     0,     2,
];

/// `tag2nbyte[]` — the character width for each `V_ASN1_*`, or `-1` for "not a
/// character type".
#[rustfmt::skip]
static TAG2NBYTE: [i8; 31] = [
    -1, -1, -1, -1, -1, /* 0-4 */
    -1, -1, -1, -1, -1, /* 5-9 */
    -1, -1,             /* 10-11 */
     0,                 /* 12 V_ASN1_UTF8STRING */
    -1, -1, -1, -1, -1, /* 13-17 */
     1,                 /* 18 V_ASN1_NUMERICSTRING */
     1,                 /* 19 V_ASN1_PRINTABLESTRING */
     1,                 /* 20 V_ASN1_T61STRING */
    -1,                 /* 21 */
     1,                 /* 22 V_ASN1_IA5STRING */
     1,                 /* 23 V_ASN1_UTCTIME */
     1,                 /* 24 V_ASN1_GENERALIZEDTIME */
    -1,                 /* 25 */
     1,                 /* 26 V_ASN1_ISO64STRING */
    -1,                 /* 27 */
     4,                 /* 28 V_ASN1_UNIVERSALSTRING */
    -1,                 /* 29 */
     2,                 /* 30 V_ASN1_BMPSTRING */
];

/// `char_io` — where a rendered character goes.
///
/// The counting pass passes a null sink and the writing pass the real one, so the
/// same code produces the length and the bytes. That is why the parameter is a raw
/// pointer rather than an `Option<&mut …>`: it is the authority's own convention
/// and the two `send_*_chars` functions test it.
type CharIo = unsafe extern "C" fn(*mut c_void, *const c_void, c_int) -> c_int;

/// `static int send_bio_chars(void *arg, const void *buf, int len)`
///
/// # Safety
///
/// `arg` must be null or a live `BIO *`; `buf` must be readable for `len` bytes.
unsafe extern "C" fn send_bio_chars(arg: *mut c_void, buf: *const c_void, len: c_int) -> c_int {
    if arg.is_null() {
        return 1;
    }
    // SAFETY: the caller's contract makes `arg` a live BIO.
    if unsafe { BIO_write(arg.cast::<Bio>(), buf, len) } != len {
        return 0;
    }
    1
}

/// `static int send_fp_chars(void *arg, const void *buf, int len)`
///
/// # Safety
///
/// `arg` must be null or a live `FILE *`; `buf` must be readable for `len` bytes.
unsafe extern "C" fn send_fp_chars(arg: *mut c_void, buf: *const c_void, len: c_int) -> c_int {
    if arg.is_null() {
        return 1;
    }
    // SAFETY: the caller's contract makes `arg` a live FILE.
    if unsafe { fwrite(buf, 1, len as usize, arg.cast::<FILE>()) } != len as usize {
        return 0;
    }
    1
}

/// The size of `do_esc_char`'s `tmphex`, `HEX_SIZE(long) + 3`.
///
/// `HEX_SIZE(x)` is `sizeof(x) * 2 + 1`, so for a `long` it is 17 and the buffer is
/// 20. The `\W%08X` form writes 10 bytes and the `\U%04X` form 6, both of which
/// fit; the size is only what `BIO_snprintf` is told.
const TMPHEX: usize = 17 + 3;

/// `static int do_esc_char(unsigned long c, unsigned short flags, char *do_quotes,
/// char_io *io_ch, void *arg)`
///
/// Answers the number of bytes written (or that *would* be written, for a null
/// sink), or `-1` on failure.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` must be null or whatever `io_ch` expects;
/// `do_quotes` must be null or writable.
unsafe fn do_esc_char(
    c: c_ulong,
    flags: u16,
    do_quotes: *mut c_char,
    io_ch: CharIo,
    arg: *mut c_void,
) -> c_int {
    let mut tmphex = [0 as c_char; TMPHEX];

    if c > 0xffff_ffff {
        return -1;
    }
    if c > 0xffff {
        // SAFETY: `tmphex` holds the format's output and the format matches.
        unsafe { BIO_snprintf(tmphex.as_mut_ptr(), tmphex.len(), c"\\W%08lX".as_ptr(), c) };
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, tmphex.as_ptr().cast(), 10) } == 0 {
            return -1;
        }
        return 10;
    }
    if c > 0xff {
        // SAFETY: as above.
        unsafe { BIO_snprintf(tmphex.as_mut_ptr(), tmphex.len(), c"\\U%04lX".as_ptr(), c) };
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, tmphex.as_ptr().cast(), 6) } == 0 {
            return -1;
        }
        return 6;
    }
    let chtmp = c as c_uchar;
    let chflgs: u16 = if chtmp > 0x7f {
        // A byte the table has no entry for is tested against `ESC_MSB` alone.
        flags & (ASN1_STRFLGS_ESC_MSB as u16)
    } else {
        CHAR_TYPE[chtmp as usize] & flags
    };
    if chflgs & CHARTYPE_BS_ESC != 0 {
        // "If we don't escape with quotes, signal we need quotes."
        if chflgs & (ASN1_STRFLGS_ESC_QUOTE as u16) != 0 {
            if !do_quotes.is_null() {
                // SAFETY: the caller's contract makes `do_quotes` writable.
                unsafe { *do_quotes = 1 };
            }
            // SAFETY: the caller's contract is `io_ch`'s.
            if unsafe { io_ch(arg, (&raw const chtmp).cast(), 1) } == 0 {
                return -1;
            }
            return 1;
        }
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, c"\\".as_ptr().cast(), 1) } == 0 {
            return -1;
        }
        // SAFETY: as above.
        if unsafe { io_ch(arg, (&raw const chtmp).cast(), 1) } == 0 {
            return -1;
        }
        return 2;
    }
    if chflgs & ((ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB | ASN1_STRFLGS_ESC_2254) as u16) != 0
    {
        // SAFETY: `tmphex` holds the format's output and the format matches.
        unsafe {
            BIO_snprintf(
                tmphex.as_mut_ptr(),
                11,
                c"\\%02X".as_ptr(),
                c_int::from(chtmp),
            )
        };
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, tmphex.as_ptr().cast(), 3) } == 0 {
            return -1;
        }
        return 3;
    }
    // "If we get this far and do any escaping at all must escape the escape
    // character itself: backslash."
    if chtmp == b'\\' && (c_ulong::from(flags) & ESC_FLAGS) != 0 {
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, c"\\\\".as_ptr().cast(), 2) } == 0 {
            return -1;
        }
        return 2;
    }
    // SAFETY: the caller's contract is `io_ch`'s.
    if unsafe { io_ch(arg, (&raw const chtmp).cast(), 1) } == 0 {
        return -1;
    }
    1
}

/// `static int do_buf(unsigned char *buf, int buflen, int type,
/// unsigned short flags, char *quotes, char_io *io_ch, void *arg)`
///
/// Reads the buffer as characters of `type`'s width, converting from or to UTF-8
/// where the type says so, and sends each to `do_esc_char`.
///
/// Two details that are easy to miss: the `buflen` decrement in the UTF-8 arm is
/// *local*, because the `case 0` body is the only one that consumes a variable
/// number of bytes — the other arms advance `p` by their width and the loop
/// compares `p` to `q` rather than counting; and `orflags` is recomputed inside the
/// loop from `p == buf` and `p == q`, so a `CONVUTF8` byte above `0x7f` expands to
/// two or more characters and acquires neither position flag, which the authority
/// notes in a comment.
///
/// # Safety
///
/// `buf` must be readable for `buflen` bytes; `io_ch` must be a `char_io`; `arg`
/// must be null or whatever `io_ch` expects; `quotes` must be null or writable.
unsafe fn do_buf(
    buf: *mut c_uchar,
    buflen: c_int,
    type_: c_int,
    flags: u16,
    quotes: *mut c_char,
    io_ch: CharIo,
    arg: *mut c_void,
) -> c_int {
    let mut buflen = buflen;
    let charwidth = type_ & BUF_TYPE_WIDTH_MASK;
    // A fixed-width type whose content is not a whole number of characters is
    // malformed, and the two failures have their own reasons.
    if charwidth == 4 {
        if buflen & 3 != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::A_STREX_150) };
            return -1;
        }
    } else if charwidth == 2 && buflen & 1 != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::A_STREX_156) };
        return -1;
    }

    let mut p = buf;
    // SAFETY: the caller's contract makes `buf` readable for `buflen` bytes.
    let q = unsafe { buf.add(buflen.max(0) as usize) };
    let mut outlen = 0;

    while p != q {
        let mut orflags: u16 = if p == buf && flags & (ASN1_STRFLGS_ESC_2253 as u16) != 0 {
            CHARTYPE_FIRST_ESC_2253
        } else {
            0
        };

        let c: c_ulong = match charwidth {
            4 => {
                // SAFETY: the caller guarantees a multiple of four bytes remain.
                let v = unsafe {
                    (c_ulong::from(*p) << 24)
                        | (c_ulong::from(*p.add(1)) << 16)
                        | (c_ulong::from(*p.add(2)) << 8)
                        | c_ulong::from(*p.add(3))
                };
                // SAFETY: four bytes were consumed.
                p = unsafe { p.add(4) };
                v
            }
            2 => {
                // SAFETY: the caller guarantees a multiple of two bytes remain.
                let v = unsafe { (c_ulong::from(*p) << 8) | c_ulong::from(*p.add(1)) };
                // SAFETY: two bytes were consumed.
                p = unsafe { p.add(2) };
                v
            }
            1 => {
                // SAFETY: at least one byte remains.
                let v = c_ulong::from(unsafe { *p });
                // SAFETY: one byte was consumed.
                p = unsafe { p.add(1) };
                v
            }
            0 => {
                let mut v: c_ulong = 0;
                // SAFETY: `p` is readable for the remaining `buflen` bytes.
                let i = unsafe { crate::asn1::a_utf8::UTF8_getc(p, buflen, &mut v) };
                if i < 0 {
                    return -1;
                }
                buflen -= i;
                // SAFETY: `i` bytes were consumed.
                p = unsafe { p.add(i as usize) };
                v
            }
            _ => return -1,
        };
        if p == q && flags & (ASN1_STRFLGS_ESC_2253 as u16) != 0 {
            orflags = CHARTYPE_LAST_ESC_2253;
        }

        if type_ & BUF_TYPE_CONVUTF8 != 0 {
            let mut utfbuf = [0 as c_uchar; 6];
            // SAFETY: `utfbuf` is six bytes, which is the widest encoding.
            let utflen = unsafe { crate::asn1::a_utf8::UTF8_putc(utfbuf.as_mut_ptr(), 6, c) };
            if utflen < 0 {
                return -1;
            }
            for i in 0..utflen {
                // SAFETY: `utfbuf` holds `utflen` bytes and `i < utflen`.
                let len = unsafe {
                    do_esc_char(
                        c_ulong::from(utfbuf[i as usize]),
                        flags | orflags,
                        quotes,
                        io_ch,
                        arg,
                    )
                };
                if len < 0 {
                    return -1;
                }
                outlen += len;
            }
        } else {
            // SAFETY: the caller's contract is `do_esc_char`'s.
            let len = unsafe { do_esc_char(c, flags | orflags, quotes, io_ch, arg) };
            if len < 0 {
                return -1;
            }
            outlen += len;
        }
    }
    outlen
}

/// `static int do_hex_dump(char_io *io_ch, void *arg, unsigned char *buf,
/// int buflen)`
///
/// Answers twice the length — the number of hex digits the dump *would* be — even
/// when the sink is null, which is what lets `do_dump` return a length without
/// writing.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` must be null or whatever `io_ch` expects;
/// `buf` must be readable for `buflen` bytes.
unsafe fn do_hex_dump(io_ch: CharIo, arg: *mut c_void, buf: *mut c_uchar, buflen: c_int) -> c_int {
    if !arg.is_null() {
        for i in 0..buflen.max(0) {
            let mut hextmp = [0u8; 2];
            // SAFETY: `buf` is readable for `buflen` bytes and `i < buflen`.
            to_hex(&mut hextmp, unsafe { *buf.add(i as usize) });
            // SAFETY: the caller's contract is `io_ch`'s.
            if unsafe { io_ch(arg, hextmp.as_ptr().cast(), 2) } == 0 {
                return -1;
            }
        }
    }
    buflen << 1
}

/// `static int do_dump(unsigned long lflags, char_io *io_ch, void *arg,
/// const ASN1_STRING *str)`
///
/// The RFC 2253 `#`-prefixed form. Without `DUMP_DER` it is the content octets;
/// with it, the whole encoding — produced by wrapping the string in a stack
/// `ASN1_TYPE` and running the encoder twice, once to size and once to fill.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` must be null or whatever `io_ch` expects;
/// `str` must be a live `ASN1_STRING`.
unsafe fn do_dump(
    lflags: c_ulong,
    io_ch: CharIo,
    arg: *mut c_void,
    str_: *const Asn1String,
) -> c_int {
    // SAFETY: the caller's contract is `io_ch`'s.
    if unsafe { io_ch(arg, c"#".as_ptr().cast(), 1) } == 0 {
        return -1;
    }
    // SAFETY: the caller's contract makes `str_` readable.
    let Some(s) = (unsafe { as_str(str_) }) else {
        return -1;
    };
    if lflags & ASN1_STRFLGS_DUMP_DER == 0 {
        // SAFETY: the string's contract makes `data` readable for `length`.
        let outlen = unsafe { do_hex_dump(io_ch, arg, s.data, s.length) };
        if outlen < 0 {
            return -1;
        }
        return outlen + 1;
    }
    let t = Asn1Type {
        type_: s.type_,
        value: Asn1TypeValue {
            ptr: str_.cast_mut().cast(),
        },
    };
    // SAFETY: `t` is a live local whose value pointer is the caller's string.
    let der_len = unsafe { i2d_ASN1_TYPE(&t, core::ptr::null_mut()) };
    if der_len <= 0 {
        return -1;
    }
    // SAFETY: `CRYPTO_malloc` answers null or `der_len` bytes.
    let der_buf = CRYPTO_malloc(der_len as usize, FILE.as_ptr(), LINE).cast::<c_uchar>();
    if der_buf.is_null() {
        return -1;
    }
    let mut p = der_buf;
    // SAFETY: `der_buf` owns `der_len` bytes and `p` advances within it.
    unsafe { i2d_ASN1_TYPE(&t, &mut p) };
    // SAFETY: `der_buf` holds `der_len` bytes.
    let outlen = unsafe { do_hex_dump(io_ch, arg, der_buf, der_len) };
    // SAFETY: `der_buf` came from this allocator and is not owned elsewhere.
    unsafe { CRYPTO_free(der_buf.cast(), FILE.as_ptr(), LINE) };
    if outlen < 0 {
        return -1;
    }
    outlen + 1
}

/// `static int do_print_ex(char_io *io_ch, void *arg, unsigned long lflags,
/// const ASN1_STRING *str)`
///
/// The whole decision: show the type name, choose between display and dump, and
/// then render twice — once to measure and once to write.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` must be null or whatever `io_ch` expects;
/// `str` must be null or a live `ASN1_STRING`.
unsafe fn do_print_ex(
    io_ch: CharIo,
    arg: *mut c_void,
    lflags: c_ulong,
    str_: *const Asn1String,
) -> c_int {
    // SAFETY: the caller's contract is `as_str`'s.
    let Some(s) = (unsafe { as_str(str_) }) else {
        return -1;
    };
    let mut quotes: c_char = 0;
    let flags: u16 = (lflags & ESC_FLAGS) as u16;
    let mut type_ = s.type_;
    let mut outlen: c_int = 0;

    if lflags & ASN1_STRFLGS_SHOW_TYPE != 0 {
        let tagname = ASN1_tag2str(type_);
        // SAFETY: the caller's contract makes `tagname` a NUL-terminated string.
        let n = unsafe { crate::runtime::str::OPENSSL_strnlen(tagname, usize::MAX) } as c_int;
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, tagname.cast(), n) } == 0
            // SAFETY: as above.
            || unsafe { io_ch(arg, c":".as_ptr().cast(), 1) } == 0
        {
            return -1;
        }
        outlen += n;
        outlen += 1;
    }

    if lflags & ASN1_STRFLGS_DUMP_ALL != 0 {
        type_ = -1;
    } else if lflags & ASN1_STRFLGS_IGNORE_TYPE != 0 {
        type_ = 1;
    } else {
        type_ = if type_ > 0 && type_ < 31 {
            c_int::from(TAG2NBYTE[type_ as usize])
        } else {
            -1
        };
        if type_ == -1 && lflags & ASN1_STRFLGS_DUMP_UNKNOWN == 0 {
            type_ = 1;
        }
    }

    if type_ == -1 {
        // SAFETY: the caller's contract is `do_dump`'s.
        let len = unsafe { do_dump(lflags, io_ch, arg, str_) };
        if len < 0 || len > c_int::MAX - outlen {
            return -1;
        }
        return outlen + len;
    }

    if lflags & ASN1_STRFLGS_UTF8_CONVERT != 0 {
        // "If string is UTF8 and we want to convert to UTF8 then we just interpret
        // it as 1 byte per character to avoid converting twice."
        if type_ == 0 {
            type_ = 1;
        } else {
            type_ |= BUF_TYPE_CONVUTF8;
        }
    }

    // SAFETY: `s.data` is readable for `s.length` bytes and the sink counts.
    let len = unsafe {
        do_buf(
            s.data,
            s.length,
            type_,
            flags,
            &mut quotes,
            io_ch,
            core::ptr::null_mut(),
        )
    };
    if len < 0 || len > c_int::MAX - 2 - outlen {
        return -1;
    }
    outlen += len;
    if quotes != 0 {
        outlen += 2;
    }
    if arg.is_null() {
        return outlen;
    }
    if quotes != 0 {
        // SAFETY: the caller's contract is `io_ch`'s.
        if unsafe { io_ch(arg, c"\"".as_ptr().cast(), 1) } == 0 {
            return -1;
        }
    }
    // SAFETY: as above; `quotes` is null here so only `io_ch` and `arg` matter.
    if unsafe {
        do_buf(
            s.data,
            s.length,
            type_,
            flags,
            core::ptr::null_mut(),
            io_ch,
            arg,
        )
    } < 0
    {
        return -1;
    }
    if quotes != 0 {
        // SAFETY: as above.
        if unsafe { io_ch(arg, c"\"".as_ptr().cast(), 1) } == 0 {
            return -1;
        }
    }
    outlen
}

/// `int ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str,
/// unsigned long flags)`
///
/// # Safety
///
/// `out` must be null or a live BIO; `str` must be null or a live `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print_ex(
    out: *mut Bio,
    str_: *const Asn1String,
    flags: c_ulong,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the caller's contract is `do_print_ex`'s.
        unsafe { do_print_ex(send_bio_chars, out.cast(), flags, str_) }
    })
}

/// `int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str,
/// unsigned long flags)`
///
/// # Safety
///
/// `fp` must be null or a live `FILE`; `str` must be null or a live `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_print_ex_fp(
    fp: *mut FILE,
    str_: *const Asn1String,
    flags: c_ulong,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the caller's contract is `do_print_ex`'s.
        unsafe { do_print_ex(send_fp_chars, fp.cast(), flags, str_) }
    })
}

/// `int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in)`
///
/// Answers the number of bytes written, or a negative code: `-1` for a null input
/// or a type outside `0..=30`, `-1` again for a type `tag2nbyte` rejects, and
/// `ASN1_mbstring_copy`'s own negative answer otherwise. Note that the output is
/// `stmp.data` — the allocation `ASN1_mbstring_copy` made on the *stack* string's
/// `out` — and the caller owns it.
///
/// # Safety
///
/// `out` must be writable; `in` must be null or a live `ASN1_STRING`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_STRING_to_UTF8(
    out: *mut *mut c_uchar,
    in_: *const Asn1String,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the caller's contract is `as_str`'s.
        let Some(s) = (unsafe { as_str(in_) }) else {
            return -1;
        };
        let type_ = s.type_;
        if !(0..=30).contains(&type_) {
            return -1;
        }
        let mbflag = TAG2NBYTE[type_ as usize];
        if mbflag == -1 {
            return -1;
        }
        let mbflag = c_int::from(mbflag) | MBSTRING_FLAG;
        // The stack string is the authority's `out` target; `ASN1_mbstring_copy`
        // fills its `data` and `length` and the caller takes the pointer.
        let mut stmp = Asn1String {
            length: 0,
            type_: 0,
            data: core::ptr::null_mut(),
            flags: 0,
        };
        let mut str_: *mut Asn1String = &raw mut stmp;
        // SAFETY: `stmp` is a live local and the caller's string is readable.
        let ret =
            unsafe { ASN1_mbstring_copy(&mut str_, s.data, s.length, mbflag, B_ASN1_UTF8STRING) };
        if ret < 0 {
            return ret;
        }
        // SAFETY: the caller's contract makes `out` writable.
        unsafe { *out = stmp.data };
        stmp.length
    })
}

// ---------------------------------------------------------------------------------------------
// Phase 10.11 — the `X509_NAME` print half (`a_strex.c:406-581`)
// ---------------------------------------------------------------------------------------------

/// `XN_FLAG_SEP_MASK` — `include/openssl/x509.h:157`, the separator group selector.
const XN_FLAG_SEP_MASK: c_ulong = 0xf << 16;
/// `XN_FLAG_COMPAT` — `:159`; selects the old [`X509_NAME_print`].
const XN_FLAG_COMPAT: c_ulong = 0;
/// `XN_FLAG_SEP_COMMA_PLUS` — `:160`; RFC 2253's `,`/`+` with no spaces.
const XN_FLAG_SEP_COMMA_PLUS: c_ulong = 1 << 16;
/// `XN_FLAG_SEP_CPLUS_SPC` — `:161`; `, `/` + `.
const XN_FLAG_SEP_CPLUS_SPC: c_ulong = 2 << 16;
/// `XN_FLAG_SEP_SPLUS_SPC` — `:162`; `; `/` + `.
const XN_FLAG_SEP_SPLUS_SPC: c_ulong = 3 << 16;
/// `XN_FLAG_SEP_MULTILINE` — `:163`; one field per line.
const XN_FLAG_SEP_MULTILINE: c_ulong = 4 << 16;
/// `XN_FLAG_DN_REV` — `:165`; reverse the entry order.
const XN_FLAG_DN_REV: c_ulong = 1 << 20;
/// `XN_FLAG_FN_MASK` — `:169`, the field-name group selector.
const XN_FLAG_FN_MASK: c_ulong = 0x3 << 21;
/// `XN_FLAG_FN_SN` — `:171`; short name.
const XN_FLAG_FN_SN: c_ulong = 0;
/// `XN_FLAG_FN_LN` — `:172`; long name.
const XN_FLAG_FN_LN: c_ulong = 1 << 21;
/// `XN_FLAG_FN_OID` — `:173`; always the numeric OID.
const XN_FLAG_FN_OID: c_ulong = 2 << 21;
/// `XN_FLAG_FN_NONE` — `:174`; no field names.
const XN_FLAG_FN_NONE: c_ulong = 3 << 21;
/// `XN_FLAG_SPC_EQ` — `:176`; spaces round `=`.
const XN_FLAG_SPC_EQ: c_ulong = 1 << 23;
/// `XN_FLAG_DUMP_UNKNOWN_FIELDS` — `:183`; DER-dump values of unrecognised OIDs.
const XN_FLAG_DUMP_UNKNOWN_FIELDS: c_ulong = 1 << 24;
/// `XN_FLAG_FN_ALIGN` — `:185`; pad short field names to the long-name width.
const XN_FLAG_FN_ALIGN: c_ulong = 1 << 25;

/// `FN_WIDTH_LN` — `crypto/asn1/a_strex.c:417`.
const FN_WIDTH_LN: c_int = 25;
/// `FN_WIDTH_SN` — `crypto/asn1/a_strex.c:418`.
const FN_WIDTH_SN: c_int = 10;

/// `static int do_indent(char_io *io_ch, void *arg, int indent)` —
/// `crypto/asn1/a_strex.c:408-415`.
///
/// Writes `indent` spaces (or measures them when `arg` is null) and answers 1, or 0 if the sink
/// refuses. A negative `indent` loops zero times, because the loop tests `i < indent`.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` null or whatever `io_ch` expects.
unsafe fn do_indent(io_ch: CharIo, arg: *mut c_void, indent: c_int) -> c_int {
    let mut i = 0;
    while i < indent {
        // SAFETY: `io_ch` is a live callback and the one-byte literal is static.
        if unsafe { io_ch(arg, c" ".as_ptr().cast(), 1) } == 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `static int do_name_ex(char_io *io_ch, void *arg, const X509_NAME *n, int indent,
/// unsigned long flags)` — `crypto/asn1/a_strex.c:420-554`.
///
/// Renders an `X509_NAME` under `flags`: the `XN_FLAG_SEP_*` group chooses the inter-RDN and
/// inter-entry separators, `XN_FLAG_DN_REV` reverses the entry order, the `XN_FLAG_FN_*` group
/// chooses the field-name spelling, `XN_FLAG_SPC_EQ`/`XN_FLAG_FN_ALIGN` adjust spacing, and
/// `XN_FLAG_DUMP_UNKNOWN_FIELDS` forces a DER dump for entries whose OID is unrecognised -- by
/// setting `ASN1_STRFLGS_DUMP_ALL` in the **value's** flag word, not the name's. Answers the
/// number of bytes written, or -1.
///
/// The counting pass and the writing pass are the same code: the two `do_indent`/`do_print_ex`
/// helpers measure with a null sink and write with the real one, so `outlen` cannot disagree with
/// the bytes emitted.
///
/// # Safety
///
/// `io_ch` must be a `char_io`; `arg` null or whatever `io_ch` expects; `n` NULL or a live name.
unsafe fn do_name_ex(
    io_ch: CharIo,
    arg: *mut c_void,
    n: *const X509Name,
    indent: c_int,
    flags: c_ulong,
) -> c_int {
    let indent = if indent < 0 { 0 } else { indent };
    let mut outlen = indent;
    // SAFETY: the caller's contract is `do_indent`'s.
    if unsafe { do_indent(io_ch, arg, indent) } == 0 {
        return -1;
    }

    let sep_dn: &[u8];
    let sep_mv: &[u8];
    let mut indent = indent;
    let sep_mask = flags & XN_FLAG_SEP_MASK;
    if sep_mask == XN_FLAG_SEP_MULTILINE {
        sep_dn = b"\n";
        sep_mv = b" + ";
    } else if sep_mask == XN_FLAG_SEP_COMMA_PLUS {
        sep_dn = b",";
        sep_mv = b"+";
        indent = 0;
    } else if sep_mask == XN_FLAG_SEP_CPLUS_SPC {
        sep_dn = b", ";
        sep_mv = b" + ";
        indent = 0;
    } else if sep_mask == XN_FLAG_SEP_SPLUS_SPC {
        sep_dn = b"; ";
        sep_mv = b" + ";
        indent = 0;
    } else {
        return -1;
    }

    let sep_eq: &[u8] = if flags & XN_FLAG_SPC_EQ != 0 {
        b" = "
    } else {
        b"="
    };

    let fn_opt = flags & XN_FLAG_FN_MASK;

    // SAFETY: `n` is NULL or live per the contract; a NULL name counts zero entries.
    let cnt = unsafe { X509_NAME_entry_count(n) };
    let mut prev: c_int = -1;
    let mut i: c_int = 0;
    while i < cnt {
        let ent = if flags & XN_FLAG_DN_REV != 0 {
            // SAFETY: `n` is live when `cnt` is positive and the index is in range.
            unsafe { X509_NAME_get_entry(n, cnt - i - 1) }
        } else {
            // SAFETY: as above; the index is in range.
            unsafe { X509_NAME_get_entry(n, i) }
        };
        if prev != -1 {
            // SAFETY: `ent` came from a valid index and is live.
            if prev == unsafe { X509_NAME_ENTRY_set(ent) } {
                // SAFETY: the literal is static and `io_ch` is a live callback.
                if unsafe { io_ch(arg, sep_mv.as_ptr().cast(), sep_mv.len() as c_int) } == 0 {
                    return -1;
                }
                outlen += sep_mv.len() as c_int;
            } else {
                // SAFETY: as above.
                if unsafe { io_ch(arg, sep_dn.as_ptr().cast(), sep_dn.len() as c_int) } == 0 {
                    return -1;
                }
                outlen += sep_dn.len() as c_int;
                // SAFETY: `io_ch`/`arg` are the caller's.
                if unsafe { do_indent(io_ch, arg, indent) } == 0 {
                    return -1;
                }
                outlen += indent;
            }
        }
        // SAFETY: `ent` is live.
        prev = unsafe { X509_NAME_ENTRY_set(ent) };
        // SAFETY: `ent` is live.
        let fn_ = unsafe { X509_NAME_ENTRY_get_object(ent) };
        // SAFETY: `ent` is live.
        let val = unsafe { X509_NAME_ENTRY_get_data(ent) };
        // SAFETY: `fn_` is a live object.
        let fn_nid = unsafe { OBJ_obj2nid(fn_) };
        if fn_opt != XN_FLAG_FN_NONE {
            let mut objtmp = [0 as c_char; 80];
            let fld_len: c_int;
            let objbuf: *const c_char;
            if fn_opt == XN_FLAG_FN_OID || fn_nid == NID_undef {
                // SAFETY: `objtmp` is an 80-byte buffer and `fn_` is live.
                unsafe { OBJ_obj2txt(objtmp.as_mut_ptr(), 80, fn_, 1) };
                fld_len = 0;
                objbuf = objtmp.as_ptr();
            } else if fn_opt == XN_FLAG_FN_SN {
                fld_len = FN_WIDTH_SN;
                // SAFETY: `fn_nid` names an object in the table.
                objbuf = OBJ_nid2sn(fn_nid);
            } else if fn_opt == XN_FLAG_FN_LN {
                fld_len = FN_WIDTH_LN;
                // SAFETY: `fn_nid` names an object in the table.
                objbuf = OBJ_nid2ln(fn_nid);
            } else {
                fld_len = 0;
                objbuf = c"".as_ptr();
            }
            // SAFETY: `objbuf` is a NUL-terminated string.
            let objlen = unsafe { OPENSSL_strnlen(objbuf, usize::MAX) } as c_int;
            // SAFETY: `objbuf` is readable for `objlen` bytes and `io_ch` is live.
            if unsafe { io_ch(arg, objbuf.cast(), objlen) } == 0 {
                return -1;
            }
            if objlen < fld_len && flags & XN_FLAG_FN_ALIGN != 0 {
                // SAFETY: `io_ch`/`arg` are the caller's.
                if unsafe { do_indent(io_ch, arg, fld_len - objlen) } == 0 {
                    return -1;
                }
                outlen += fld_len - objlen;
            }
            // SAFETY: the literal is static and `io_ch` is live.
            if unsafe { io_ch(arg, sep_eq.as_ptr().cast(), sep_eq.len() as c_int) } == 0 {
                return -1;
            }
            outlen += objlen + sep_eq.len() as c_int;
        }
        let orflags: c_ulong = if fn_nid == NID_undef && flags & XN_FLAG_DUMP_UNKNOWN_FIELDS != 0 {
            ASN1_STRFLGS_DUMP_ALL
        } else {
            0
        };
        // SAFETY: `io_ch`/`arg` are the caller's and `val` is a live entry value.
        let len = unsafe { do_print_ex(io_ch, arg, flags | orflags, val.cast::<Asn1String>()) };
        if len < 0 {
            return -1;
        }
        outlen += len;
        i += 1;
    }
    outlen
}

/// `int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags)` —
/// `crypto/asn1/a_strex.c:558-564`.
///
/// `XN_FLAG_COMPAT` selects the old [`X509_NAME_print`]; anything else goes to [`do_name_ex`]
/// over a BIO sink.
///
/// # Safety
///
/// `out` must be a live BIO; `nm` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_print_ex(
    out: *mut Bio,
    nm: *const X509Name,
    indent: c_int,
    flags: c_ulong,
) -> c_int {
    if flags == XN_FLAG_COMPAT {
        // SAFETY: `out` and `nm` are the caller's.
        return unsafe { X509_NAME_print(out, nm, indent) };
    }
    // SAFETY: `send_bio_chars` is the BIO sink and `out` is live per the contract.
    unsafe { do_name_ex(send_bio_chars, out.cast(), nm, indent, flags) }
}

/// `int X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, int indent, unsigned long flags)` —
/// `crypto/asn1/a_strex.c:567-581`.
///
/// The `XN_FLAG_COMPAT` arm wraps `fp` in a no-close BIO, prints the old way, and releases the
/// BIO; anything else writes straight through the `FILE` sink.
///
/// # Safety
///
/// `fp` must be a live `FILE`; `nm` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_print_ex_fp(
    fp: *mut FILE,
    nm: *const X509Name,
    indent: c_int,
    flags: c_ulong,
) -> c_int {
    if flags == XN_FLAG_COMPAT {
        // SAFETY: `fp` is live per the contract.
        let btmp = unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) };
        if btmp.is_null() {
            return -1;
        }
        // SAFETY: `btmp` is live and `nm` is the caller's.
        let ret = unsafe { X509_NAME_print(btmp, nm, indent) };
        // SAFETY: `btmp` is this call's own BIO.
        unsafe { BIO_free(btmp) };
        return ret;
    }
    // SAFETY: `send_fp_chars` is the FILE sink and `fp` is live per the contract.
    unsafe { do_name_ex(send_fp_chars, fp.cast(), nm, indent, flags) }
}
