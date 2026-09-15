//! Phase 5 — `crypto/asn1/asn1_gen.c`: the tag-name tables and `ASN1_str2mask`.
//!
//! `asn1_gen.c` is 794 lines and three of its exports are this stratum's:
//! `ASN1_generate_v3`, `ASN1_generate_nconf` and `ASN1_str2mask`. Only the last
//! one is implementable here, and the reason is in the signature of the other two:
//! they take an `X509V3_CTX *` — `x509v3.h`'s structure, Phase 11 — and
//! `ASN1_generate_nconf` *constructs* one through the `X509V3_set_nconf` macro, so
//! even the null-`CONF` path goes through a structure this stratum does not own.
//! The two are handed to Phase 11 by the ledger.
//!
//! ## What `asn1_str2tag` is, and why it is here rather than later
//!
//! It is one table and one case-insensitive search: fifty-four names, from `BOOL`
//! and `NULL` through the fifteen string types to the six *modifiers* — `EXP`,
//! `IMP`, `OCTWRAP`, `SEQWRAP`, `SETWRAP`, `BITWRAP`, `FORMAT` — whose values live
//! in a flag space above `0x10000` rather than in the `V_ASN1_*` range. That
//! division is load-bearing for `ASN1_str2mask`, which rejects a modifier with
//! `if (!tag || (tag & ASN1_GEN_FLAG)) return 0` — a mask names a *type*, and the
//! test is a range test on the shared table, not a second lookup.
//!
//! It lives in this module rather than with the two generator functions because
//! `ASN1_str2mask` needs it now and Phase 11 will need the same table. A second
//! copy of fifty-four names is exactly the kind of duplicated registry this project
//! eliminates.
//!
//! ## `ASN1_str2mask` and the `DIR` special case
//!
//! The mask is a `|`-separated list of type names, parsed by `CONF_parse_list`
//! with `nospc = 1`. One name is not in the table: a three-character `DIR`, which
//! means `B_ASN1_DIRECTORYSTRING` — a *mask of four types*, where every other name
//! is one. The check is `HAS_PREFIX(elem, "DIR")`, which is a `strncmp` over three
//! bytes, and it is made *before* the table lookup, so `DIR` cannot be shadowed.
//!
//! A rejected name leaves `*pmask` at whatever the callback has accumulated: the
//! authority writes `*pmask = 0` once, at the top, and `CONF_parse_list` returns 0
//! on the first refusal without undoing the earlier names. That is observable — a
//! caller that ignores the return value sees a partial mask — and it is why the
//! probe checks the mask on both sides of a failure.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_ulong, c_void};

use crate::asn1::der::ASN1_tag2bit;
use crate::asn1::layout::*;
use crate::runtime::bio::sys::strncmp;
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::str::OPENSSL_strncasecmp;

/// `ASN1_GEN_FLAG` — the base of the modifier tag space.
pub(crate) const ASN1_GEN_FLAG: c_int = 0x10000;

/// One `ASN1_GEN_STR` row: the name, its length, and the tag it names.
///
/// The length is `sizeof(name) - 1` in the authority, i.e. the name without its
/// NUL — which is why this table is compared by length *and* by bytes rather than
/// by a `CStr` comparison: a caller's string is a `(ptr, len)` pair and may not be
/// NUL-terminated at `len`.
struct TagName {
    /// The name, without its NUL.
    name: &'static [u8],
    /// `V_ASN1_*` or an `ASN1_GEN_FLAG`-based modifier value.
    tag: c_int,
}

/// The authority's `tnst[]`, in its own order.
///
/// Order does not decide anything — the search rejects two candidates by length
/// before comparing bytes, and no two names of the same length differ only in case
/// — but it is preserved so that a future reader can diff it against the header.
#[rustfmt::skip]
static TAG2STR: [TagName; 49] = [
    TagName { name: b"BOOL",              tag: V_ASN1_BOOLEAN },
    TagName { name: b"BOOLEAN",           tag: V_ASN1_BOOLEAN },
    TagName { name: b"NULL",              tag: V_ASN1_NULL },
    TagName { name: b"INT",               tag: V_ASN1_INTEGER },
    TagName { name: b"INTEGER",           tag: V_ASN1_INTEGER },
    TagName { name: b"ENUM",              tag: V_ASN1_ENUMERATED },
    TagName { name: b"ENUMERATED",        tag: V_ASN1_ENUMERATED },
    TagName { name: b"OID",               tag: V_ASN1_OBJECT },
    TagName { name: b"OBJECT",            tag: V_ASN1_OBJECT },
    TagName { name: b"UTCTIME",           tag: V_ASN1_UTCTIME },
    TagName { name: b"UTC",               tag: V_ASN1_UTCTIME },
    TagName { name: b"GENERALIZEDTIME",   tag: V_ASN1_GENERALIZEDTIME },
    TagName { name: b"GENTIME",           tag: V_ASN1_GENERALIZEDTIME },
    TagName { name: b"OCT",               tag: V_ASN1_OCTET_STRING },
    TagName { name: b"OCTETSTRING",       tag: V_ASN1_OCTET_STRING },
    TagName { name: b"BITSTR",            tag: V_ASN1_BIT_STRING },
    TagName { name: b"BITSTRING",         tag: V_ASN1_BIT_STRING },
    TagName { name: b"UNIVERSALSTRING",   tag: V_ASN1_UNIVERSALSTRING },
    TagName { name: b"UNIV",              tag: V_ASN1_UNIVERSALSTRING },
    TagName { name: b"IA5",               tag: V_ASN1_IA5STRING },
    TagName { name: b"IA5STRING",         tag: V_ASN1_IA5STRING },
    TagName { name: b"UTF8",              tag: V_ASN1_UTF8STRING },
    TagName { name: b"UTF8String",        tag: V_ASN1_UTF8STRING },
    TagName { name: b"BMP",               tag: V_ASN1_BMPSTRING },
    TagName { name: b"BMPSTRING",         tag: V_ASN1_BMPSTRING },
    TagName { name: b"VISIBLESTRING",     tag: V_ASN1_VISIBLESTRING },
    TagName { name: b"VISIBLE",           tag: V_ASN1_VISIBLESTRING },
    TagName { name: b"PRINTABLESTRING",   tag: V_ASN1_PRINTABLESTRING },
    TagName { name: b"PRINTABLE",         tag: V_ASN1_PRINTABLESTRING },
    TagName { name: b"T61",               tag: V_ASN1_T61STRING },
    TagName { name: b"T61STRING",         tag: V_ASN1_T61STRING },
    TagName { name: b"TELETEXSTRING",     tag: V_ASN1_T61STRING },
    TagName { name: b"GeneralString",     tag: V_ASN1_GENERALSTRING },
    TagName { name: b"GENSTR",            tag: V_ASN1_GENERALSTRING },
    TagName { name: b"NUMERIC",           tag: V_ASN1_NUMERICSTRING },
    TagName { name: b"NUMERICSTRING",     tag: V_ASN1_NUMERICSTRING },
    TagName { name: b"SEQUENCE",          tag: V_ASN1_SEQUENCE },
    TagName { name: b"SEQ",               tag: V_ASN1_SEQUENCE },
    TagName { name: b"SET",               tag: V_ASN1_SET },
    TagName { name: b"EXP",               tag: ASN1_GEN_FLAG | 2 },
    TagName { name: b"EXPLICIT",          tag: ASN1_GEN_FLAG | 2 },
    TagName { name: b"IMP",               tag: ASN1_GEN_FLAG | 1 },
    TagName { name: b"IMPLICIT",          tag: ASN1_GEN_FLAG | 1 },
    TagName { name: b"OCTWRAP",           tag: ASN1_GEN_FLAG | 5 },
    TagName { name: b"SEQWRAP",           tag: ASN1_GEN_FLAG | 6 },
    TagName { name: b"SETWRAP",           tag: ASN1_GEN_FLAG | 7 },
    TagName { name: b"BITWRAP",           tag: ASN1_GEN_FLAG | 4 },
    TagName { name: b"FORM",              tag: ASN1_GEN_FLAG | 8 },
    TagName { name: b"FORMAT",            tag: ASN1_GEN_FLAG | 8 },
];

/// `static int asn1_str2tag(const char *tagstr, int len)`
///
/// A length of `-1` means "measure the NUL-terminated string". Answers the tag, or
/// `-1` for a name that is not in the table — a value that is *itself* a rejection
/// signal in the two callers, which is why it is `-1` and not 0.
///
/// The comparison is `OPENSSL_strncasecmp` over exactly `len` bytes once the
/// lengths agree, so a caller's buffer need not be terminated.
///
/// # Safety
///
/// `tagstr` must be a NUL-terminated string when `len` is negative, and readable
/// for `len` bytes otherwise.
pub(crate) unsafe fn asn1_str2tag(tagstr: *const c_char, len: c_int) -> c_int {
    let len = if len == -1 {
        // SAFETY: the caller's contract makes `tagstr` NUL-terminated.
        unsafe { crate::runtime::str::OPENSSL_strnlen(tagstr, usize::MAX) as c_int }
    } else {
        len
    };
    for t in TAG2STR.iter() {
        if t.name.len() as c_int == len {
            // SAFETY: the caller's contract makes `tagstr` readable for `len`
            // bytes, and `t.name` is `len` bytes long.
            if unsafe {
                OPENSSL_strncasecmp(tagstr, t.name.as_ptr().cast::<c_char>(), len as usize)
            } == 0
            {
                return t.tag;
            }
        }
    }
    -1
}

/// `static int mask_cb(const char *elem, int len, void *arg)`
///
/// One `|`-separated name, applied to the accumulating mask.
///
/// # Safety
///
/// `arg` must be a `*mut unsigned long`; `elem` must be readable for `len` bytes.
unsafe extern "C" fn mask_cb(elem: *const c_char, len: c_int, arg: *mut c_void) -> c_int {
    if elem.is_null() {
        return 0;
    }
    // `if (len == 3 && HAS_PREFIX(elem, "DIR"))` — a `strncmp` over three bytes,
    // made before the table so that `DIR` cannot be shadowed by a table entry.
    // SAFETY: `elem` is readable for `len` bytes and `len == 3` here.
    if len == 3 && unsafe { strncmp(elem, c"DIR".as_ptr(), 3) } == 0 {
        // SAFETY: the caller's contract makes `arg` a `*mut unsigned long`.
        unsafe { *(arg as *mut c_ulong) |= B_ASN1_DIRECTORYSTRING };
        return 1;
    }
    // SAFETY: `elem` is readable for `len` bytes.
    let tag = unsafe { asn1_str2tag(elem, len) };
    if tag == -1 || (tag & ASN1_GEN_FLAG) != 0 {
        return 0;
    }
    let tmpmask = ASN1_tag2bit(tag);
    if tmpmask == 0 {
        return 0;
    }
    // SAFETY: the caller's contract makes `arg` a `*mut unsigned long`.
    unsafe { *(arg as *mut c_ulong) |= tmpmask };
    1
}

/// `int ASN1_str2mask(const char *str, unsigned long *pmask)`
///
/// `*pmask` is zeroed *before* the parse and written in place by each accepted
/// name, so a rejected list leaves whatever the earlier names accumulated. That is
/// the authority's behaviour and the probe measures the mask on both sides of a
/// failure.
///
/// # Safety
///
/// `str` must be a NUL-terminated string; `pmask` must be writable.
#[no_mangle]
pub unsafe extern "C" fn ASN1_str2mask(str_: *const c_char, pmask: *mut c_ulong) -> c_int {
    // SAFETY: the caller's contract makes `pmask` writable.
    unsafe { *pmask = 0 };
    // SAFETY: `str` is NUL-terminated and `pmask` is a `*mut unsigned long` for
    // the callback; `CONF_parse_list` blocks the separator (`|`) and passes no
    // spaces through.
    unsafe {
        CONF_parse_list(
            str_,
            c_int::from(b'|'),
            1,
            Some(mask_cb),
            pmask.cast::<c_void>(),
        )
    }
}
