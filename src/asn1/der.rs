//! Phase 5 — the DER header codec and the diagnostic parser.
//!
//! `ASN1_get_object` is the only place in the stratum where a *stream* becomes a
//! tag, a class and a length, so its return value is unusually dense and
//! unusually observable. The authority packs four things into one `int`:
//!
//! ```text
//! bit 7 (0x80)  set on failure, and also on the "length exceeds the buffer"
//!               path, where the tag and class are still written
//! bit 5 (0x20)  the constructed bit
//! bit 6 (0x40)  the class, one of V_ASN1_UNIVERSAL .. V_ASN1_PRIVATE
//! bit 0 (0x01)  set when the length was indefinite (the 0x80 first byte)
//! ```
//!
//! So `0x21` is "constructed, universal, indefinite length", and a caller
//! distinguishes "error" from "long length" by testing bit 7 — which is why a
//! caller that read only the low bits would treat a truncated object as a valid
//! one. `RT-ASN1` drives every branch: short form, long form, leading zeroes in the
//! long form, a length that overflows the buffer, a high-tag-number form, an
//! indefinite length on a primitive, and a header that runs past its own bound.
//!
//! `ASN1_parse` is the diagnostic dumper behind `openssl asn1parse`, and it is
//! here rather than treated as a CLI convenience because its output is what a
//! caller sees when a structure is wrong.

use core::ffi::{c_char, c_int, c_long, c_uchar};

use crate::asn1::layout::*;
use crate::ffi::guard_ffi;
use crate::runtime::bio::{Bio, BIO_CTRL_GET_INDENT, BIO_CTRL_SET_INDENT, BIO_CTRL_SET_PREFIX};
use crate::runtime::err::raise_site;
use crate::runtime::err_sites;

/// `ASN1_PARSE_MAXDEPTH` — the depth `ASN1_parse_dump` refuses to exceed.
const ASN1_PARSE_MAXDEPTH: c_int = 128;

/// `_asn1_check_infinite_end` — consume a two-byte end-of-contents marker.
///
/// The first branch is the interesting one: a **non-positive** length answers
/// "found". An exhausted buffer therefore reads the same as one holding `00 00`.
///
/// # Safety
///
/// When `len >= 2`, `*p` must point to two readable bytes.
unsafe fn check_infinite_end(p: *mut *const c_uchar, len: c_long) -> c_int {
    if len <= 0 {
        return 1;
    }
    if len >= 2 {
        // SAFETY: the caller guarantees two readable bytes at `*p`.
        let (a, b) = unsafe { (*(*p), *(*p).add(1)) };
        if a == 0 && b == 0 {
            // SAFETY: the caller's pointer slot is writable.
            unsafe { *p = (*p).add(2) };
            return 1;
        }
    }
    0
}

/// `int ASN1_check_infinite_end(unsigned char **p, long len)`
///
/// # Safety
///
/// `p` must be null or point to a readable/writable byte pointer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_check_infinite_end(p: *mut *mut c_uchar, len: c_long) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's.
        unsafe { check_infinite_end(p.cast::<*const c_uchar>(), len) }
    })
}

/// `int ASN1_const_check_infinite_end(const unsigned char **p, long len)`
///
/// # Safety
///
/// `p` must be null or point to a readable/writable byte pointer.
#[no_mangle]
pub unsafe extern "C" fn ASN1_const_check_infinite_end(
    p: *mut *const c_uchar,
    len: c_long,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract is this function's.
        unsafe { check_infinite_end(p, len) }
    })
}

/// `asn1_get_length` — the length field, and whether it was indefinite.
///
/// # Safety
///
/// `pp` must point to a byte pointer into `max` readable bytes.
unsafe fn get_length(
    pp: *mut *const c_uchar,
    inf: *mut c_int,
    rl: *mut c_long,
    mut max: c_long,
) -> c_int {
    // SAFETY: the caller guarantees `pp` is readable.
    let mut p = unsafe { *pp };
    let mut ret: u64 = 0;
    max -= 1;
    if max < 1 {
        return 0;
    }
    // SAFETY: `max >= 1` means one readable byte at `p`.
    if unsafe { *p } == 0x80 {
        // SAFETY: the caller's slot is writable.
        unsafe { *inf = 1 };
        // SAFETY: as above.
        p = unsafe { p.add(1) };
    } else {
        // SAFETY: the byte at `p` is readable.
        let first = unsafe { *p };
        // SAFETY: the caller's slot is writable.
        unsafe { *inf = 0 };
        let mut i = (first & 0x7f) as c_long;
        // SAFETY: as above.
        p = unsafe { p.add(1) };
        if first & 0x80 != 0 {
            if max < i {
                return 0;
            }
            // Skip leading zeroes: the authority accepts the long form with
            // redundant leading bytes.
            // SAFETY: `max >= i` keeps the bytes below readable.
            while i > 0 && unsafe { *p } == 0 {
                // SAFETY: still within the length's bytes.
                p = unsafe { p.add(1) };
                i -= 1;
            }
            if i > core::mem::size_of::<c_long>() as c_long {
                return 0;
            }
            while i > 0 {
                ret <<= 8;
                // SAFETY: within the length's bytes.
                ret |= unsafe { *p } as u64;
                // SAFETY: as above.
                p = unsafe { p.add(1) };
                i -= 1;
            }
            if ret > c_long::MAX as u64 {
                return 0;
            }
        } else {
            ret = i as u64;
        }
    }
    // SAFETY: the caller's slots are writable.
    unsafe {
        *pp = p;
        *rl = ret as c_long;
    }
    1
}

/// `int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag, int
/// *pclass, long omax)`
///
/// # Safety
///
/// `pp`, `plength`, `ptag` and `pclass` must be writable and non-null, and `*pp`
/// must point into `omax` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_get_object(
    pp: *mut *const c_uchar,
    plength: *mut c_long,
    ptag: *mut c_int,
    pclass: *mut c_int,
    omax: c_long,
) -> c_int {
    guard_ffi(0x80, || {
        if omax <= 0 {
            // SAFETY: the raise is at the authority's own coordinate.
            unsafe { raise_site(&err_sites::ASN1_LIB_56) };
            return 0x80;
        }
        // SAFETY: the caller guarantees `*pp` is readable.
        let start = unsafe { *pp };
        let mut p = start;
        let mut max = omax;
        // SAFETY: the byte at `p` is readable because `omax >= 1`.
        let first = unsafe { *p };
        let mut ret: c_int = (first & V_ASN1_CONSTRUCTED as u8) as c_int;
        let xclass = (first & V_ASN1_PRIVATE as u8) as c_int;
        let mut head = (first & V_ASN1_PRIMITIVE_TAG as u8) as c_int;
        if head == V_ASN1_PRIMITIVE_TAG {
            // SAFETY: as above.
            p = unsafe { p.add(1) };
            max -= 1;
            if max == 0 {
                return header_too_long();
            }
            let mut len: i64 = 0;
            // SAFETY: `max >= 1` keeps `p` readable.
            while unsafe { *p } & 0x80 != 0 {
                len <<= 7;
                // SAFETY: `p` is readable.
                len |= (unsafe { *p } & 0x7f) as i64;
                // SAFETY: as above.
                p = unsafe { p.add(1) };
                max -= 1;
                if max == 0 {
                    return header_too_long();
                }
                if len > (c_int::MAX >> 7) as i64 {
                    return header_too_long();
                }
            }
            len <<= 7;
            // SAFETY: `p` is readable.
            len |= (unsafe { *p } & 0x7f) as i64;
            // SAFETY: as above.
            p = unsafe { p.add(1) };
            head = len as c_int;
            max -= 1;
            if max == 0 {
                return header_too_long();
            }
        } else {
            // SAFETY: `p` is readable.
            p = unsafe { p.add(1) };
            max -= 1;
            if max == 0 {
                return header_too_long();
            }
        }
        // SAFETY: the caller's slots are writable.
        unsafe {
            *ptag = head;
            *pclass = xclass;
        }
        let mut inf: c_int = 0;
        // SAFETY: `p` is readable for `max` bytes and `plength` is writable.
        if unsafe { get_length(&mut p, &mut inf, plength, max) } == 0 {
            return header_too_long();
        }
        // SAFETY: `plength` and `inf` were just written.
        let (len, inf) = unsafe { (*plength, inf) };
        if inf != 0 && ret & V_ASN1_CONSTRUCTED == 0 {
            return header_too_long();
        }
        let consumed = (p as usize).wrapping_sub(start as usize) as c_long;
        if len > omax - consumed {
            // SAFETY: the raise is at the authority's own coordinate.
            unsafe { raise_site(&err_sites::ASN1_LIB_95) };
            ret |= 0x80;
        }
        // SAFETY: the caller's slot is writable.
        unsafe { *pp = p };
        ret | inf
    })
}

/// The `err:` arm of [`ASN1_get_object`], a distinct raise coordinate.
fn header_too_long() -> c_int {
    // SAFETY: the raise is at the authority's own coordinate.
    unsafe { raise_site(&err_sites::ASN1_LIB_105) };
    0x80
}

/// `asn1_put_length` — the length field an encoder writes.
///
/// # Safety
///
/// `pp` must point to a writable pointer with room for the encoding.
unsafe fn put_length(pp: *mut *mut c_uchar, mut length: c_int) {
    // SAFETY: the caller guarantees room.
    let mut p = unsafe { *pp };
    if length <= 127 {
        // SAFETY: one writable byte.
        unsafe {
            *p = length as c_uchar;
            p = p.add(1);
        }
    } else {
        let mut i = 0;
        let mut len = length;
        while len > 0 {
            len >>= 8;
            i += 1;
        }
        // SAFETY: `i` bytes plus the marker are writable.
        unsafe {
            *p = (i | 0x80) as c_uchar;
            p = p.add(1);
        }
        let count = i;
        while i > 0 {
            i -= 1;
            // SAFETY: `i < count` is within the length bytes.
            unsafe { *p.add(i as usize) = (length & 0xff) as c_uchar };
            length >>= 8;
        }
        // SAFETY: as above.
        p = unsafe { p.add(count as usize) };
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *pp = p };
}

/// `void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
/// int xclass)`
///
/// `constructed == 2` is the authority's "constructed, indefinite length": the
/// length byte becomes `0x80` instead of a length.
///
/// # Safety
///
/// `pp` must point to a writable pointer with room for the header.
#[no_mangle]
pub unsafe extern "C" fn ASN1_put_object(
    pp: *mut *mut c_uchar,
    constructed: c_int,
    length: c_int,
    tag: c_int,
    xclass: c_int,
) {
    guard_ffi((), || {
        // SAFETY: the caller guarantees room for the header.
        let mut p = unsafe { *pp };
        let mut i = if constructed != 0 {
            V_ASN1_CONSTRUCTED
        } else {
            0
        };
        i |= xclass & V_ASN1_PRIVATE;
        if tag < 31 {
            // SAFETY: one writable byte.
            unsafe {
                *p = (i | (tag & V_ASN1_PRIMITIVE_TAG)) as c_uchar;
                p = p.add(1);
            }
        } else {
            // SAFETY: as above.
            unsafe {
                *p = (i | V_ASN1_PRIMITIVE_TAG) as c_uchar;
                p = p.add(1);
            }
            let mut digits = 0;
            let mut ttag = tag;
            while ttag > 0 {
                ttag >>= 7;
                digits += 1;
            }
            let total = digits;
            let mut j = digits;
            let mut t = tag;
            while j > 0 {
                j -= 1;
                // SAFETY: `j < total` is within the tag bytes.
                unsafe {
                    let mut byte = (t & 0x7f) as c_uchar;
                    if j != total - 1 {
                        byte |= 0x80;
                    }
                    *p.add(j as usize) = byte;
                }
                t >>= 7;
            }
            // SAFETY: as above.
            p = unsafe { p.add(total as usize) };
        }
        if constructed == 2 {
            // SAFETY: one writable byte.
            unsafe {
                *p = 0x80;
                p = p.add(1);
            }
        } else {
            // SAFETY: the caller guarantees room for the length.
            unsafe { put_length(&mut p, length) };
        }
        // SAFETY: the caller's slot is writable.
        unsafe { *pp = p };
    });
}

/// `int ASN1_put_eoc(unsigned char **pp)`
///
/// # Safety
///
/// `pp` must point to a writable pointer with two writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_put_eoc(pp: *mut *mut c_uchar) -> c_int {
    guard_ffi(2, || {
        // SAFETY: the caller guarantees two writable bytes.
        unsafe {
            let p = *pp;
            *p = 0;
            *p.add(1) = 0;
            *pp = p.add(2);
        }
        2
    })
}

/// `int ASN1_object_size(int constructed, int length, int tag)`
///
/// Answers the total encoded size, or -1 for a negative length and for a size that
/// would not fit an `int`.
#[no_mangle]
pub extern "C" fn ASN1_object_size(constructed: c_int, length: c_int, tag: c_int) -> c_int {
    guard_ffi(-1, || {
        let mut ret = 1;
        if length < 0 {
            return -1;
        }
        if tag >= 31 {
            let mut t = tag;
            while t > 0 {
                t >>= 7;
                ret += 1;
            }
        }
        if constructed == 2 {
            ret += 3;
        } else {
            ret += 1;
            if length > 127 {
                let mut tmplen = length;
                while tmplen > 0 {
                    tmplen >>= 8;
                    ret += 1;
                }
            }
        }
        if ret >= c_int::MAX - length {
            return -1;
        }
        ret + length
    })
}

/// `unsigned long ASN1_tag2bit(int tag)`
///
/// The table is `tasn_dec.c`'s `tag2bit`, and it is *not* a bijection between tags
/// and masks: several tags share `B_ASN1_UNKNOWN` and several read 0. It is what a
/// `MSTRING` item is matched against, so a wrong entry changes which string types a
/// decode accepts.
#[no_mangle]
pub extern "C" fn ASN1_tag2bit(tag: c_int) -> core::ffi::c_ulong {
    const TAG2BIT: [core::ffi::c_ulong; 32] = [
        0,
        0,
        0,
        B_ASN1_BIT_STRING,
        B_ASN1_OCTET_STRING,
        0,
        0,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        0,
        B_ASN1_UNKNOWN,
        B_ASN1_UTF8STRING,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_SEQUENCE,
        0,
        B_ASN1_NUMERICSTRING,
        B_ASN1_PRINTABLESTRING,
        B_ASN1_T61STRING,
        B_ASN1_VIDEOTEXSTRING,
        B_ASN1_IA5STRING,
        B_ASN1_UTCTIME,
        B_ASN1_GENERALIZEDTIME,
        B_ASN1_GRAPHICSTRING,
        B_ASN1_ISO64STRING,
        B_ASN1_GENERALSTRING,
        B_ASN1_UNIVERSALSTRING,
        B_ASN1_UNKNOWN,
        B_ASN1_BMPSTRING,
        B_ASN1_UNKNOWN,
    ];
    if !(0..=30).contains(&tag) {
        return 0;
    }
    guard_ffi(0, || TAG2BIT[tag as usize])
}

/// The printed names of the universal tags, as `ASN1_tag2str` spells them.
static TAG2STR: [&core::ffi::CStr; 31] = [
    c"EOC",
    c"BOOLEAN",
    c"INTEGER",
    c"BIT STRING",
    c"OCTET STRING",
    c"NULL",
    c"OBJECT",
    c"OBJECT DESCRIPTOR",
    c"EXTERNAL",
    c"REAL",
    c"ENUMERATED",
    c"<ASN1 11>",
    c"UTF8STRING",
    c"<ASN1 13>",
    c"<ASN1 14>",
    c"<ASN1 15>",
    c"SEQUENCE",
    c"SET",
    c"NUMERICSTRING",
    c"PRINTABLESTRING",
    c"T61STRING",
    c"VIDEOTEXSTRING",
    c"IA5STRING",
    c"UTCTIME",
    c"GENERALIZEDTIME",
    c"GRAPHICSTRING",
    c"VISIBLESTRING",
    c"GENERALSTRING",
    c"UNIVERSALSTRING",
    c"<ASN1 29>",
    c"BMPSTRING",
];

/// `const char *ASN1_tag2str(int tag)`
///
/// The two `V_ASN1_NEG_*` tags are folded to their positive form before the range
/// test, so a negative integer prints as `INTEGER`.
#[no_mangle]
pub extern "C" fn ASN1_tag2str(tag: c_int) -> *const c_char {
    guard_ffi(c"(unknown)".as_ptr(), || {
        let mut tag = tag;
        if tag == V_ASN1_NEG_INTEGER || tag == V_ASN1_NEG_ENUMERATED {
            tag &= !0x100;
        }
        if !(0..=30).contains(&tag) {
            return c"(unknown)".as_ptr();
        }
        TAG2STR[tag as usize].as_ptr()
    })
}

/// `asn1_print_info` — the `hl`/`l` line every parsed object starts with.
///
/// # Safety
///
/// `bp` must be null or a live BIO.
unsafe fn print_info(
    bp: *mut Bio,
    offset: c_long,
    depth: c_int,
    hl: c_int,
    len: c_long,
    tag: c_int,
    xclass: c_int,
    constructed: c_int,
    indent: c_int,
) -> c_int {
    let mut buf = [0 as c_char; 128];
    let prim = if constructed & V_ASN1_CONSTRUCTED != 0 {
        c"cons: ".as_ptr()
    } else {
        c"prim: ".as_ptr()
    };
    // SAFETY: `buf` is a 128-byte buffer and the formats are `bio_variadic.c`'s.
    let ok = unsafe {
        if constructed != V_ASN1_CONSTRUCTED | 1 {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"%5ld:d=%-2d hl=%ld l=%4ld %s".as_ptr(),
                offset,
                depth,
                hl as c_long,
                len,
                prim,
            )
        } else {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"%5ld:d=%-2d hl=%ld l=inf  %s".as_ptr(),
                offset,
                depth,
                hl as c_long,
                prim,
            )
        }
    };
    if ok <= 0 {
        return 0;
    }
    if bp.is_null() {
        return 1;
    }
    // SAFETY: `bp` is a live BIO and `buf` is NUL-terminated.
    let mut bp = bp;
    let mut pop_f_prefix = false;
    let mut saved_indent: c_long = -1;
    // SAFETY: as above.
    if unsafe { crate::runtime::bio::BIO_ctrl(bp, BIO_CTRL_SET_PREFIX, 0, buf.as_ptr().cast()) }
        <= 0
    {
        // The sink has no prefix filter, so push one; the authority does this so a
        // nested structure is indented by its parent.
        // SAFETY: `BIO_f_prefix` answers a method and `BIO_new`/`BIO_push` take it.
        let pushed = unsafe {
            let m = crate::runtime::bio::BIO_f_prefix();
            let b = crate::runtime::bio::BIO_new(m);
            if b.is_null() {
                return 0;
            }
            let pushed = crate::runtime::bio::BIO_push(b, bp);
            if pushed.is_null() {
                return 0;
            }
            pushed
        };
        bp = pushed;
        pop_f_prefix = true;
    }
    // SAFETY: `bp` is live.
    saved_indent =
        unsafe { crate::runtime::bio::BIO_ctrl(bp, BIO_CTRL_GET_INDENT, 0, core::ptr::null_mut()) }
            as c_long;
    // SAFETY: as above.
    if unsafe { crate::runtime::bio::BIO_ctrl(bp, BIO_CTRL_SET_PREFIX, 0, buf.as_ptr().cast()) }
        <= 0
        || unsafe {
            crate::runtime::bio::BIO_ctrl(bp, BIO_CTRL_SET_INDENT, indent, core::ptr::null_mut())
        } <= 0
    {
        if saved_indent >= 0 {
            // SAFETY: `bp` is live.
            unsafe {
                crate::runtime::bio::BIO_ctrl(
                    bp,
                    BIO_CTRL_SET_INDENT,
                    saved_indent as c_int,
                    core::ptr::null_mut(),
                )
            };
        }
        if pop_f_prefix {
            // SAFETY: `bp` is the pushed prefix BIO.
            unsafe { crate::runtime::bio::BIO_pop(bp) };
        }
        return 0;
    }
    // `BIO_set_prefix` copied the string, so `buf` can be reused for the tag.
    let name: *const c_char = unsafe {
        if (xclass & V_ASN1_PRIVATE) == V_ASN1_PRIVATE {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"priv [ %d ] ".as_ptr(),
                tag,
            );
            buf.as_ptr()
        } else if (xclass & V_ASN1_CONTEXT_SPECIFIC) == V_ASN1_CONTEXT_SPECIFIC {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"cont [ %d ]".as_ptr(),
                tag,
            );
            buf.as_ptr()
        } else if (xclass & V_ASN1_APPLICATION) == V_ASN1_APPLICATION {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"appl [ %d ]".as_ptr(),
                tag,
            );
            buf.as_ptr()
        } else if tag > 30 {
            crate::runtime::bio::BIO_snprintf(
                buf.as_mut_ptr(),
                buf.len(),
                c"<ASN1 %d>".as_ptr(),
                tag,
            );
            buf.as_ptr()
        } else {
            ASN1_tag2str(tag)
        }
    };
    // SAFETY: `bp` is a live BIO and `name` is NUL-terminated.
    let i = (unsafe { crate::runtime::bio::BIO_printf(bp, c"%-18s".as_ptr(), name) } > 0) as c_int;
    if saved_indent >= 0 {
        // SAFETY: `bp` is live.
        unsafe {
            crate::runtime::bio::BIO_ctrl(
                bp,
                BIO_CTRL_SET_INDENT,
                saved_indent as c_int,
                core::ptr::null_mut(),
            )
        };
    }
    if pop_f_prefix {
        // SAFETY: `bp` is the pushed prefix BIO.
        unsafe { crate::runtime::bio::BIO_pop(bp) };
    }
    i
}

/// `int ASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent)`
///
/// # Safety
///
/// `bp` must be a live BIO and `pp` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ASN1_parse(
    bp: *mut Bio,
    pp: *const c_uchar,
    len: c_long,
    indent: c_int,
) -> c_int {
    guard_ffi(0, || {
        let mut p = pp;
        // SAFETY: the caller's contract is this function's.
        unsafe { parse2(bp, &mut p, len, 0, 0, indent, 0) }
    })
}

/// `int ASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent, int
/// dump)`
///
/// # Safety
///
/// As [`ASN1_parse`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_parse_dump(
    bp: *mut Bio,
    pp: *const c_uchar,
    len: c_long,
    indent: c_int,
    dump: c_int,
) -> c_int {
    guard_ffi(0, || {
        let mut p = pp;
        // SAFETY: the caller's contract is this function's.
        unsafe { parse2(bp, &mut p, len, 0, 0, indent, dump) }
    })
}

/// `asn1_parse2` — the parser proper.
///
/// Returns 1 when the buffer was consumed, 2 when an end-of-contents was reached,
/// and 0 on failure. The `2` is what lets an indefinite-length container stop at
/// its own marker rather than at the end of the buffer. Note that `ret` is only
/// advanced at the *end* of a successful iteration, so a failure on the first
/// object answers 0 and a failure later answers 1 — which is what the authority
/// does and is why a caller must check the transcript, not the return alone.
///
/// # Safety
///
/// `bp` must be a live BIO; `pp` a readable/writable byte pointer into `length`
/// readable bytes.
unsafe fn parse2(
    bp: *mut Bio,
    pp: *mut *const c_uchar,
    length: c_long,
    offset: c_int,
    depth: c_int,
    indent: c_int,
    dump: c_int,
) -> c_int {
    if depth > ASN1_PARSE_MAXDEPTH {
        // SAFETY: `bp` is a live BIO.
        unsafe { crate::runtime::bio::BIO_puts(bp, c"BAD RECURSION DEPTH\n".as_ptr()) };
        return 0;
    }
    let dump_indent = 6;
    // SAFETY: the caller guarantees `*pp` is readable for `length`.
    let base = unsafe { *pp };
    // SAFETY: as above.
    let mut p = unsafe { *pp };
    // SAFETY: `length` bytes from `p` are readable.
    let tot = unsafe { p.add(length.max(0) as usize) };
    let mut remaining = length;
    let mut ret: c_int = 0;
    let mut nl = 0;

    'outer: while remaining > 0 {
        let op = p;
        let mut len: c_long = 0;
        let mut tag: c_int = 0;
        let mut xclass: c_int = 0;
        // SAFETY: `p` is readable for `remaining` bytes.
        let j = unsafe { ASN1_get_object(&mut p, &mut len, &mut tag, &mut xclass, remaining) };
        if j & 0x80 != 0 {
            // SAFETY: `bp` is a live BIO.
            unsafe { crate::runtime::bio::BIO_puts(bp, c"Error in encoding\n".as_ptr()) };
            break 'outer;
        }
        let hl = (p as usize).wrapping_sub(op as usize) as c_int;
        remaining -= hl as c_long;
        // SAFETY: `bp` is live and the coordinates are the parser's own.
        if unsafe {
            print_info(
                bp,
                offset as c_long + (op as usize).wrapping_sub(base as usize) as c_long,
                depth,
                hl,
                len,
                tag,
                xclass,
                j,
                if indent != 0 { depth } else { 0 },
            )
        } == 0
        {
            break 'outer;
        }
        if j & V_ASN1_CONSTRUCTED != 0 {
            let mut sp = p;
            // SAFETY: `p` holds `len` bytes when the length check passed.
            let ep = unsafe { p.add(len.max(0) as usize) };
            // SAFETY: `bp` is a live BIO.
            if unsafe { crate::runtime::bio::BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
                break 'outer;
            }
            if len > remaining {
                // SAFETY: `bp` is a live BIO.
                unsafe {
                    crate::runtime::bio::BIO_printf(
                        bp,
                        c"length is greater than %ld\n".as_ptr(),
                        remaining,
                    )
                };
                break 'outer;
            }
            if j == 0x21 && len == 0 {
                // Indefinite length: parse until the end-of-contents marker or the
                // end of the buffer.
                loop {
                    let avail = (tot as usize).wrapping_sub(p as usize) as c_long;
                    // SAFETY: `p` is within `tot` and `avail` bytes are readable.
                    let r = unsafe {
                        parse2(
                            bp,
                            &mut p,
                            avail,
                            offset + (p as usize).wrapping_sub(base as usize) as c_int,
                            depth + 1,
                            indent,
                            dump,
                        )
                    };
                    if r == 0 {
                        break 'outer;
                    }
                    if r == 2 || p >= tot {
                        len = (p as usize).wrapping_sub(sp as usize) as c_long;
                        break;
                    }
                }
            } else {
                let mut tmp = len;
                while p < ep {
                    sp = p;
                    // SAFETY: `p` is within the constructed value's content.
                    let r = unsafe {
                        parse2(
                            bp,
                            &mut p,
                            tmp,
                            offset + (p as usize).wrapping_sub(base as usize) as c_int,
                            depth + 1,
                            indent,
                            dump,
                        )
                    };
                    if r == 0 {
                        break 'outer;
                    }
                    tmp -= (p as usize).wrapping_sub(sp as usize) as c_long;
                }
            }
        } else if xclass != 0 {
            // SAFETY: `p` holds `len` bytes.
            p = unsafe { p.add(len.max(0) as usize) };
            // SAFETY: `bp` is a live BIO.
            if unsafe { crate::runtime::bio::BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
                break 'outer;
            }
        } else {
            // SAFETY: `p` holds `len` bytes.
            let content = unsafe { core::slice::from_raw_parts(p, len.max(0) as usize) };
            let mut dump_cont = false;
            if matches!(
                tag,
                V_ASN1_PRINTABLESTRING
                    | V_ASN1_T61STRING
                    | V_ASN1_IA5STRING
                    | V_ASN1_VISIBLESTRING
                    | V_ASN1_NUMERICSTRING
                    | V_ASN1_UTF8STRING
                    | V_ASN1_UTCTIME
                    | V_ASN1_GENERALIZEDTIME
            ) {
                // SAFETY: `bp` is a live BIO.
                if unsafe { crate::runtime::bio::BIO_write(bp, c":".as_ptr().cast(), 1) } <= 0 {
                    break 'outer;
                }
                // SAFETY: `bp` is a live BIO.
                if !content.is_empty()
                    && unsafe {
                        crate::runtime::bio::BIO_write(
                            bp,
                            content.as_ptr().cast(),
                            content.len() as c_int,
                        )
                    } != content.len() as c_int
                {
                    break 'outer;
                }
            } else if tag == V_ASN1_OBJECT {
                let mut opp = op;
                // SAFETY: `op` heads `len + hl` readable bytes.
                let o = unsafe {
                    crate::asn1::prim::d2i_ASN1_OBJECT(
                        core::ptr::null_mut(),
                        &mut opp,
                        len + hl as c_long,
                    )
                };
                if !o.is_null() {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_write(bp, c":".as_ptr().cast(), 1) } <= 0 {
                        // SAFETY: `o` is ours.
                        unsafe { crate::asn1::prim::ASN1_OBJECT_free(o) };
                        break 'outer;
                    }
                    // SAFETY: `bp` is live and `o` is a live object.
                    unsafe { crate::asn1::text::i2a_ASN1_OBJECT(bp, o) };
                    // SAFETY: `o` is ours.
                    unsafe { crate::asn1::prim::ASN1_OBJECT_free(o) };
                } else {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_puts(bp, c":BAD OBJECT".as_ptr()) } <= 0 {
                        break 'outer;
                    }
                    dump_cont = true;
                }
            } else if tag == V_ASN1_BOOLEAN {
                if len != 1 {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_puts(bp, c":BAD BOOLEAN".as_ptr()) } <= 0 {
                        break 'outer;
                    }
                    dump_cont = true;
                }
                if len > 0 {
                    // SAFETY: `bp` is a live BIO and `p` holds at least one byte.
                    unsafe { crate::runtime::bio::BIO_printf(bp, c":%u".as_ptr(), *p as u32) };
                }
            } else if tag == V_ASN1_BMPSTRING {
                // The authority prints nothing for a BMPString.
            } else if tag == V_ASN1_OCTET_STRING {
                let mut opp = op;
                // SAFETY: `op` heads `len + hl` readable bytes.
                let os = unsafe {
                    crate::asn1::d2i::d2i_ASN1_OCTET_STRING(
                        core::ptr::null_mut(),
                        &mut opp,
                        len + hl as c_long,
                    )
                };
                if !os.is_null() {
                    // SAFETY: `os` is a live string.
                    let (olen, odata) = unsafe { ((*os).length, (*os).data) };
                    if olen > 0 {
                        // SAFETY: `odata` holds `olen` bytes.
                        let ob = unsafe { core::slice::from_raw_parts(odata, olen as usize) };
                        let printable = ob.iter().all(|&c| {
                            (c >= b' ' || c == b'\n' || c == b'\r' || c == b'\t') && c <= b'~'
                        });
                        if printable {
                            // SAFETY: `bp` is a live BIO.
                            if unsafe {
                                crate::runtime::bio::BIO_write(bp, c":".as_ptr().cast(), 1)
                            } <= 0
                            {
                                // SAFETY: `os` is ours.
                                unsafe { crate::asn1::string::ASN1_STRING_free(os) };
                                break 'outer;
                            }
                            // SAFETY: as above.
                            if unsafe { crate::runtime::bio::BIO_write(bp, odata.cast(), olen) }
                                <= 0
                            {
                                // SAFETY: `os` is ours.
                                unsafe { crate::asn1::string::ASN1_STRING_free(os) };
                                break 'outer;
                            }
                        } else if dump == 0 {
                            // SAFETY: `bp` is a live BIO.
                            if unsafe {
                                crate::runtime::bio::BIO_write(
                                    bp,
                                    c"[HEX DUMP]:".as_ptr().cast(),
                                    11,
                                )
                            } <= 0
                            {
                                // SAFETY: `os` is ours.
                                unsafe { crate::asn1::string::ASN1_STRING_free(os) };
                                break 'outer;
                            }
                            for &byte in ob {
                                // SAFETY: `bp` is a live BIO.
                                if unsafe {
                                    crate::runtime::bio::BIO_printf(
                                        bp,
                                        c"%02X".as_ptr(),
                                        byte as u32,
                                    )
                                } <= 0
                                {
                                    break;
                                }
                            }
                        } else {
                            if nl == 0 {
                                // SAFETY: `bp` is a live BIO.
                                unsafe {
                                    crate::runtime::bio::BIO_write(bp, c"\n".as_ptr().cast(), 1)
                                };
                            }
                            let n = if dump == -1 || dump > olen {
                                olen
                            } else {
                                dump
                            };
                            // SAFETY: `bp` is a live BIO and `ob` is readable.
                            unsafe {
                                crate::runtime::bio::BIO_dump_indent(
                                    bp,
                                    odata.cast(),
                                    n,
                                    dump_indent,
                                )
                            };
                            nl = 1;
                        }
                    }
                    // SAFETY: `os` is ours.
                    unsafe { crate::asn1::string::ASN1_STRING_free(os) };
                }
            } else if tag == V_ASN1_INTEGER || tag == V_ASN1_ENUMERATED {
                let mut opp = op;
                // SAFETY: `op` heads `len + hl` readable bytes.
                let ai = unsafe {
                    if tag == V_ASN1_INTEGER {
                        crate::asn1::d2i::d2i_ASN1_INTEGER(
                            core::ptr::null_mut(),
                            &mut opp,
                            len + hl as c_long,
                        )
                    } else {
                        crate::asn1::d2i::d2i_ASN1_ENUMERATED(
                            core::ptr::null_mut(),
                            &mut opp,
                            len + hl as c_long,
                        )
                    }
                };
                if !ai.is_null() {
                    // SAFETY: `ai` is a live string.
                    let (atype, alen, adata) = unsafe { ((*ai).type_, (*ai).length, (*ai).data) };
                    let neg_type = if tag == V_ASN1_INTEGER {
                        V_ASN1_NEG_INTEGER
                    } else {
                        V_ASN1_NEG_ENUMERATED
                    };
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_write(bp, c":".as_ptr().cast(), 1) } <= 0 {
                        // SAFETY: `ai` is ours.
                        unsafe { crate::asn1::string::ASN1_STRING_free(ai) };
                        break 'outer;
                    }
                    // SAFETY: `bp` is a live BIO.
                    if atype == neg_type
                        && unsafe { crate::runtime::bio::BIO_write(bp, c"-".as_ptr().cast(), 1) }
                            <= 0
                    {
                        // SAFETY: `ai` is ours.
                        unsafe { crate::asn1::string::ASN1_STRING_free(ai) };
                        break 'outer;
                    }
                    // SAFETY: `adata` holds `alen` bytes.
                    let ab = unsafe { core::slice::from_raw_parts(adata, alen.max(0) as usize) };
                    for &byte in ab {
                        // SAFETY: `bp` is a live BIO.
                        if unsafe {
                            crate::runtime::bio::BIO_printf(bp, c"%02X".as_ptr(), byte as u32)
                        } <= 0
                        {
                            break;
                        }
                    }
                    if alen == 0 {
                        // SAFETY: `bp` is a live BIO.
                        unsafe { crate::runtime::bio::BIO_write(bp, c"00".as_ptr().cast(), 2) };
                    }
                } else if tag == V_ASN1_INTEGER {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_puts(bp, c":BAD INTEGER".as_ptr()) } <= 0 {
                        break 'outer;
                    }
                    dump_cont = true;
                } else {
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_puts(bp, c":BAD ENUMERATED".as_ptr()) }
                        <= 0
                    {
                        break 'outer;
                    }
                    dump_cont = true;
                }
                // SAFETY: `ai` is null or ours.
                unsafe { crate::asn1::string::ASN1_STRING_free(ai) };
            } else if len > 0 && dump != 0 {
                if nl == 0 {
                    // SAFETY: `bp` is a live BIO.
                    unsafe { crate::runtime::bio::BIO_write(bp, c"\n".as_ptr().cast(), 1) };
                }
                let n = if dump == -1 || dump > len { len } else { dump };
                // SAFETY: `bp` is a live BIO and `p` holds `len` bytes.
                unsafe {
                    crate::runtime::bio::BIO_dump_indent(bp, p.cast(), n as c_int, dump_indent)
                };
                nl = 1;
            }
            if dump_cont {
                // SAFETY: `op + hl` heads `len` readable bytes.
                let tmp = unsafe { op.add(hl as usize) };
                // SAFETY: `bp` is a live BIO.
                if unsafe { crate::runtime::bio::BIO_puts(bp, c":[".as_ptr()) } <= 0 {
                    break 'outer;
                }
                for i in 0..len {
                    // SAFETY: `i < len` keeps `tmp` readable.
                    let b = unsafe { *tmp.add(i as usize) };
                    // SAFETY: `bp` is a live BIO.
                    if unsafe { crate::runtime::bio::BIO_printf(bp, c"%02X".as_ptr(), b as u32) }
                        <= 0
                    {
                        break;
                    }
                }
                // SAFETY: `bp` is a live BIO.
                if unsafe { crate::runtime::bio::BIO_puts(bp, c"]".as_ptr()) } <= 0 {
                    break 'outer;
                }
            }
            if nl == 0 {
                // SAFETY: `bp` is a live BIO.
                if unsafe { crate::runtime::bio::BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
                    break 'outer;
                }
            }
            // SAFETY: `p` holds `len` bytes.
            p = unsafe { p.add(len.max(0) as usize) };
            if tag == V_ASN1_EOC && xclass == 0 {
                ret = 2;
                break 'outer;
            }
        }
        remaining -= len;
        ret = 1;
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *pp = p };
    ret
}
