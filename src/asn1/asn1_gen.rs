//! `crypto/asn1/asn1_gen.c` — `ASN1_generate_v3`/`ASN1_generate_nconf`, the tag-name
//! tables and `ASN1_str2mask`. Phase 5's deferred pair lands here under Phase 10.14's
//! table layer.
//!
//! `asn1_gen.c` is 794 lines. Phase 5 landed only `ASN1_str2mask` and its table,
//! because the other two exports take an `X509V3_CTX *` — `x509v3.h`'s structure —
//! and `ASN1_generate_nconf` *constructs* one through `X509V3_set_nconf`. That
//! structure now lives in `src/x509/v3_conf.rs` (10.14.4), so the pair is landable
//! and is landed here; it is the one function that closes the `v2i` cluster in
//! `v3_san.c` (D465).
//!
//! ## What lands
//!
//! * [`ASN1_generate_v3`] (`:90-97`) and [`ASN1_generate_nconf`] (`:79-88`), the two
//!   exports;
//! * the generator core: [`generate_v3`] (`:99-247`), its parse callback [`asn1_cb`]
//!   (`:249-352`), the tag parser [`parse_tagging`] (`:354-402`), the
//!   `SEQUENCE`/`SET` recursion [`asn1_multi`] (`:406-467`), the explicit/implicit
//!   list builder [`append_exp`] (`:469-503`) and the scalar builder [`asn1_str2type`]
//!   (`:583-748`), with the bit-list callback [`bitstr_cb`] (`:750-768`);
//! * [`asn1_str2tag`] (`:505-581`), the tables [`TAG2STR`], [`mask_cb`] (`:770-788`)
//!   and [`ASN1_str2mask`] (`:790-794`), which Phase 5 already landed.
//!
//! ## The generator, and the two shapes a reader gets wrong
//!
//! `generate_v3` parses a comma-separated list left to right. [`asn1_cb`] returns `1`
//! for every *modifier* (`IMP`, `EXP`, `OCTWRAP`, …, `FORMAT`) and `0` for the single
//! **type** element; `CONF_parse_list` stops on the first non-positive answer, so the
//! list ends at the type and `CONF_parse_list(...) != 0` is the *failure* test — the
//! type was never seen. That inversion is the authority's and is reproduced.
//!
//! The type is then built by [`asn1_str2type`] (a scalar) or, for `SEQUENCE`/`SET`,
//! by [`asn1_multi`], which needs a config database (`X509V3_get_section`) and the
//! recursion depth cap `ASN1_GEN_SEQ_MAX_DEPTH`. If no tagging modifier was seen the
//! base type is returned directly; otherwise the encoding is regenerated with the
//! `IMP`/`EXP` wrappers, and **re-decoded through `d2i_ASN1_TYPE`**, so a generator
//! result is always a value the item layer could have read.
//!
//! ## The raise sites
//!
//! `crypto/asn1/asn1_gen.c` has been in `gen_err_raise_sites.py`'s covered set since
//! Phase 5, so every site is the generated `ASN1_GEN_*` coordinate. `ASN1_generate_v3`'s
//! own raise (`:95`) is a `dynamic_reason` site: the reason is the `perr` the failed
//! builder accumulated, so it goes through `raise_site_dynamic`. The
//! `asn1_cb`/`asn1_str2type` `ERR_raise_data` sites (`:275`, `:394`) append their
//! formatted operand through `openssl_rs_err_add_data`, with the authority's own `%s`/
//! `%c` spellings.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_mbstr::ASN1_mbstring_copy;
use crate::asn1::a_type::{d2i_ASN1_TYPE, i2d_ASN1_TYPE, ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::bitstr::{set_bits_left, ASN1_BIT_STRING_set_bit};
use crate::asn1::der::{ASN1_get_object, ASN1_object_size, ASN1_put_object, ASN1_tag2bit};
use crate::asn1::layout::*;
use crate::asn1::string::{ASN1_STRING_new, ASN1_STRING_set, ASN1_STRING_type_new};
use crate::asn1::time::ASN1_TIME_check;
use crate::asn1::typ::{i2d_ASN1_SEQUENCE_ANY, i2d_ASN1_SET_ANY};
use crate::runtime::bio::sys::{memcpy, strncmp, strtoul};
use crate::runtime::conf::modparse::CONF_parse_list;
use crate::runtime::conf::types::Conf;
use crate::runtime::err::err_reasons::*;
use crate::runtime::err::err_sites;
use crate::runtime::err::{
    openssl_rs_err_add_data, raise_site, raise_site_data, raise_site_dynamic,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::OBJ_txt2obj;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::str::{OPENSSL_hexstr2buf, OPENSSL_strncasecmp, OPENSSL_strnlen};
use crate::x509::v3_conf::{X509V3Ctx, X509V3_get_section, X509V3_section_free, X509V3_set_nconf};
use crate::x509::v3_utl::{s2i_ASN1_INTEGER, X509V3_get_value_bool};

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc`/`OPENSSL_free` expansions —
/// `crypto/asn1/asn1_gen.c`.
const FILE: &CStr = c"crypto/asn1/asn1_gen.c";

/// `ASN1_GEN_FLAG` — the base of the modifier tag space (`asn1_gen.c:15`).
pub(crate) const ASN1_GEN_FLAG: c_int = 0x10000;
/// `ASN1_GEN_FLAG_IMP` — `(ASN1_GEN_FLAG | 1)` (`asn1_gen.c:16`).
const ASN1_GEN_FLAG_IMP: c_int = ASN1_GEN_FLAG | 1;
/// `ASN1_GEN_FLAG_EXP` — `(ASN1_GEN_FLAG | 2)` (`asn1_gen.c:17`).
const ASN1_GEN_FLAG_EXP: c_int = ASN1_GEN_FLAG | 2;
/// `ASN1_GEN_FLAG_SEQWRAP` — `(ASN1_GEN_FLAG | 6)` (`asn1_gen.c:21`).
const ASN1_GEN_FLAG_SEQWRAP: c_int = ASN1_GEN_FLAG | 6;
/// `ASN1_GEN_FLAG_SETWRAP` — `(ASN1_GEN_FLAG | 7)` (`asn1_gen.c:22`).
const ASN1_GEN_FLAG_SETWRAP: c_int = ASN1_GEN_FLAG | 7;
/// `ASN1_GEN_FLAG_BITWRAP` — `(ASN1_GEN_FLAG | 4)` (`asn1_gen.c:19`).
const ASN1_GEN_FLAG_BITWRAP: c_int = ASN1_GEN_FLAG | 4;
/// `ASN1_GEN_FLAG_OCTWRAP` — `(ASN1_GEN_FLAG | 5)` (`asn1_gen.c:20`).
const ASN1_GEN_FLAG_OCTWRAP: c_int = ASN1_GEN_FLAG | 5;
/// `ASN1_GEN_FLAG_FORMAT` — `(ASN1_GEN_FLAG | 8)` (`asn1_gen.c:23`).
const ASN1_GEN_FLAG_FORMAT: c_int = ASN1_GEN_FLAG | 8;
/// `ASN1_FLAG_EXP_MAX` — `20` (`asn1_gen.c:27`).
const ASN1_FLAG_EXP_MAX: usize = 20;
/// `ASN1_GEN_SEQ_MAX_DEPTH` — `50` (`asn1_gen.c:29`).
const ASN1_GEN_SEQ_MAX_DEPTH: c_int = 50;

/// `ASN1_GEN_FORMAT_ASCII` — `1` (`asn1_gen.c:34`).
const ASN1_GEN_FORMAT_ASCII: c_int = 1;
/// `ASN1_GEN_FORMAT_UTF8` — `2` (`asn1_gen.c:36`).
const ASN1_GEN_FORMAT_UTF8: c_int = 2;
/// `ASN1_GEN_FORMAT_HEX` — `3` (`asn1_gen.c:38`).
const ASN1_GEN_FORMAT_HEX: c_int = 3;
/// `ASN1_GEN_FORMAT_BITLIST` — `4` (`asn1_gen.c:40`).
const ASN1_GEN_FORMAT_BITLIST: c_int = 4;

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

/// `static int asn1_str2tag(const char *tagstr, int len)` — `crypto/asn1/asn1_gen.c:505-581`.
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
        unsafe { OPENSSL_strnlen(tagstr, usize::MAX) as c_int }
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

/// `static int mask_cb(const char *elem, int len, void *arg)` — `crypto/asn1/asn1_gen.c:770-788`.
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

/// `int ASN1_str2mask(const char *str, unsigned long *pmask)` — `crypto/asn1/asn1_gen.c:790-794`.
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

/// `struct tag_exp_type` — `asn1_gen.c:48-54`.
///
/// A single explicit/implicit wrapper: its tag, class, constructed bit, padding and
/// the content length the generator computes from the end of the list.
#[repr(C)]
#[derive(Clone, Copy)]
struct TagExpType {
    /// `int exp_tag`.
    exp_tag: c_int,
    /// `int exp_class`.
    exp_class: c_int,
    /// `int exp_constructed`.
    exp_constructed: c_int,
    /// `int exp_pad`.
    exp_pad: c_int,
    /// `long exp_len`.
    exp_len: c_long,
}

/// `struct tag_exp_arg` — `asn1_gen.c:56-64`, the callback's accumulator.
///
/// The `utype`/`format`/`str` triple is what the type element sets; the `exp_list`
/// is the explicit-wrapper list `append_exp` fills; the `imp_tag`/`imp_class` pair
/// is the one `IMP` modifier, reset once consumed.
#[repr(C)]
struct TagExpArg {
    /// `int imp_tag` — `-1` until an `IMP` is seen.
    imp_tag: c_int,
    /// `int imp_class`.
    imp_class: c_int,
    /// `int utype` — the type element's tag.
    utype: c_int,
    /// `int format` — one of the `ASN1_GEN_FORMAT_*` values.
    format: c_int,
    /// `const char *str` — the type element's value, or NULL.
    str_: *const c_char,
    /// `tag_exp_type exp_list[ASN1_FLAG_EXP_MAX]`.
    exp_list: [TagExpType; ASN1_FLAG_EXP_MAX],
    /// `int exp_count`.
    exp_count: c_int,
}

/// Initialise an accumulator the way `generate_v3` does (`asn1_gen.c:117-120`).
fn new_tag_exp_arg() -> TagExpArg {
    TagExpArg {
        imp_tag: -1,
        imp_class: -1,
        utype: 0,
        format: ASN1_GEN_FORMAT_ASCII,
        str_: ptr::null(),
        exp_list: [TagExpType {
            exp_tag: 0,
            exp_class: 0,
            exp_constructed: 0,
            exp_pad: 0,
            exp_len: 0,
        }; ASN1_FLAG_EXP_MAX],
        exp_count: 0,
    }
}

/// The `value` union's first word, as a writable `void **` slot.
///
/// # Safety
///
/// `a` must be a live `ASN1_TYPE`.
unsafe fn value_slot(a: *mut Asn1Type) -> *mut *mut c_void {
    // SAFETY: `a` is live per the contract; the union's first word is pointer-sized.
    unsafe { &raw mut (*a).value.ptr }
}

/// Append the bytes of a NUL-terminated C string to a buffer, no `%` formatting.
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, s: *const c_char) {
    if s.is_null() {
        buf.extend_from_slice(b"<NULL>");
        return;
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    buf.extend_from_slice(unsafe { CStr::from_ptr(s) }.to_bytes());
}

/// `static int parse_tagging(const char *vstart, int vlen, int *ptag, int *pclass)` —
/// `crypto/asn1/asn1_gen.c:354-402`.
///
/// Parses one `IMP`/`EXP` operand: a decimal tag number followed by an optional
/// one-letter class (`U`/`A`/`P`/`C`). No class letter means
/// `V_ASN1_CONTEXT_SPECIFIC`, which is the modifier's own default.
///
/// # Safety
///
/// `vstart` is NULL or points into a NUL-terminated buffer; `ptag`/`pclass` are
/// writable.
unsafe fn parse_tagging(
    vstart: *const c_char,
    vlen: c_int,
    ptag: *mut c_int,
    pclass: *mut c_int,
) -> c_int {
    if vstart.is_null() {
        return 0;
    }
    let mut eptr: *mut c_char = ptr::null_mut();
    // SAFETY: `vstart` points into a NUL-terminated buffer and `eptr` is writable.
    let tag_num = unsafe { strtoul(vstart, &mut eptr, 10) };
    // `if (eptr && *eptr && (eptr > vstart + vlen))` — `strtoul` always answers a
    // non-null end pointer, so the first two clauses are the "there is leftover
    // input" test.
    // SAFETY: `eptr` points inside the caller's buffer.
    if !eptr.is_null() && unsafe { *eptr } != 0 {
        // SAFETY: comparing two pointers into the caller's buffer.
        if eptr.cast_const() > unsafe { vstart.add(vlen as usize) } {
            return 0;
        }
    }
    let mut vlen = vlen;
    // assigned to `long tag_num`, so an overflowing `strtoul` result is negative.
    #[allow(clippy::cast_possible_wrap)]
    let tag_num = tag_num as c_long;
    if tag_num < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_365) };
        return 0;
    }
    // SAFETY: `ptag` is writable per the contract.
    unsafe { *ptag = tag_num as c_int };
    if !eptr.is_null() {
        // SAFETY: `eptr` is at or after `vstart` within the caller's buffer.
        vlen -= (eptr as usize).wrapping_sub(vstart as usize) as c_int;
    } else {
        vlen = 0;
    }
    if vlen != 0 {
        // SAFETY: `eptr` points inside the caller's buffer.
        match unsafe { *eptr } as u8 {
            b'U' => {
                // SAFETY: `pclass` is writable per the contract.
                unsafe { *pclass = V_ASN1_UNIVERSAL };
            }
            b'A' => {
                // SAFETY: `pclass` is writable per the contract.
                unsafe { *pclass = V_ASN1_APPLICATION };
            }
            b'P' => {
                // SAFETY: `pclass` is writable per the contract.
                unsafe { *pclass = V_ASN1_PRIVATE };
            }
            b'C' => {
                // SAFETY: `pclass` is writable per the contract.
                unsafe { *pclass = V_ASN1_CONTEXT_SPECIFIC };
            }
            _ => {
                // `ERR_raise_data(ERR_LIB_ASN1, ASN1_R_INVALID_MODIFIER, "Char=%c", *eptr)`.
                let mut msg = b"Char=".to_vec();
                // SAFETY: `eptr` points inside the caller's buffer.
                msg.push(unsafe { *eptr } as u8);
                msg.push(0);
                // SAFETY: `msg` is NUL-terminated; the site is a constant.
                unsafe { raise_site_data(&err_sites::ASN1_GEN_394, msg.as_ptr().cast()) };
                return 0;
            }
        }
    } else {
        // SAFETY: `pclass` is writable per the contract.
        unsafe { *pclass = V_ASN1_CONTEXT_SPECIFIC };
    }
    1
}

/// `static int append_exp(tag_exp_arg *arg, int exp_tag, int exp_class, int exp_constructed,
/// int exp_pad, int imp_ok)` — `crypto/asn1/asn1_gen.c:469-503`.
///
/// Pushes one explicit wrapper, consuming a pending `IMP` if one is set and permitted.
///
/// # Safety
///
/// `arg` must be live.
unsafe fn append_exp(
    arg: *mut TagExpArg,
    exp_tag: c_int,
    exp_class: c_int,
    exp_constructed: c_int,
    exp_pad: c_int,
    imp_ok: c_int,
) -> c_int {
    // SAFETY: `arg` is live per the contract.
    if unsafe { (*arg).imp_tag } != -1 && imp_ok == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_475) };
        return 0;
    }
    // SAFETY: `arg` is live per the contract.
    if unsafe { (*arg).exp_count } as usize == ASN1_FLAG_EXP_MAX {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_480) };
        return 0;
    }
    // SAFETY: `exp_count < ASN1_FLAG_EXP_MAX`, so the index is in bounds.
    let exp_tmp = unsafe { &raw mut (*arg).exp_list[(*arg).exp_count as usize] };
    // SAFETY: `arg` is live.
    unsafe { (*arg).exp_count += 1 };
    // SAFETY: `arg`/`exp_tmp` are live and distinct.
    unsafe {
        if (*arg).imp_tag != -1 {
            (*exp_tmp).exp_tag = (*arg).imp_tag;
            (*exp_tmp).exp_class = (*arg).imp_class;
            (*arg).imp_tag = -1;
            (*arg).imp_class = -1;
        } else {
            (*exp_tmp).exp_tag = exp_tag;
            (*exp_tmp).exp_class = exp_class;
        }
        (*exp_tmp).exp_constructed = exp_constructed;
        (*exp_tmp).exp_pad = exp_pad;
    }
    1
}

/// `static int asn1_cb(const char *elem, int len, void *arg)` — `crypto/asn1/asn1_gen.c:249-352`.
///
/// The `CONF_parse_list` callback. Splits `elem` at its `:`, looks the name up,
/// records the type element (answering `0`, which stops the parse) or handles one
/// modifier (answering `1`).
///
/// # Safety
///
/// `arg` must be a live [`TagExpArg`]; `elem` is NULL or readable for `len` bytes.
unsafe extern "C" fn asn1_cb(elem: *const c_char, len: c_int, arg: *mut c_void) -> c_int {
    let arg = arg.cast::<TagExpArg>();
    if elem.is_null() {
        return -1;
    }
    let mut len = len;
    let mut vstart: *const c_char = ptr::null();
    let mut vlen: c_int = 0;
    let mut i: c_int = 0;
    let mut p = elem;
    while i < len {
        // SAFETY: the loop's index stays inside the caller's `len` bytes.
        if unsafe { *p } == b':' as c_char {
            // SAFETY: as above; `p + 1` is within the element.
            vstart = unsafe { p.add(1) };
            vlen = len - (vstart as usize - elem as usize) as c_int;
            len = (p as usize - elem as usize) as c_int;
            break;
        }
        // SAFETY: advancing within the caller's `len` bytes.
        p = unsafe { p.add(1) };
        i += 1;
    }

    // SAFETY: `elem` is readable for `len` bytes.
    let utype = unsafe { asn1_str2tag(elem, len) };
    if utype == -1 {
        // `ERR_raise_data(ERR_LIB_ASN1, ASN1_R_UNKNOWN_TAG, "tag=%s", elem)`.
        let mut msg = b"tag=".to_vec();
        // SAFETY: `elem` is the caller's NUL-terminated operand.
        unsafe { push_cstr(&mut msg, elem) };
        msg.push(0);
        // SAFETY: `msg` is NUL-terminated; the site is a constant.
        unsafe { raise_site_data(&err_sites::ASN1_GEN_275, msg.as_ptr().cast()) };
        return -1;
    }

    if (utype & ASN1_GEN_FLAG) == 0 {
        // SAFETY: `arg` is live per the contract.
        unsafe {
            (*arg).utype = utype;
            (*arg).str_ = vstart;
        }
        // `if (!vstart && elem[len])` — no value and trailing input in this element.
        // SAFETY: `elem` is readable for `len` bytes; `elem[len]` is inside the
        // caller's NUL-terminated buffer.
        if vstart.is_null() && unsafe { *elem.add(len as usize) } != 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&err_sites::ASN1_GEN_285) };
            return -1;
        }
        return 0;
    }

    match utype {
        ASN1_GEN_FLAG_IMP => {
            // SAFETY: `arg` is live per the contract.
            if unsafe { (*arg).imp_tag } != -1 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::ASN1_GEN_296) };
                return -1;
            }
            // SAFETY: `arg` is live; the two out-parameters are its own fields.
            if unsafe {
                parse_tagging(
                    vstart,
                    vlen,
                    &raw mut (*arg).imp_tag,
                    &raw mut (*arg).imp_class,
                )
            } == 0
            {
                return -1;
            }
        }
        ASN1_GEN_FLAG_EXP => {
            let mut tmp_tag: c_int = 0;
            let mut tmp_class: c_int = 0;
            // SAFETY: `vstart` is the operand; the two locals are writable.
            if unsafe { parse_tagging(vstart, vlen, &raw mut tmp_tag, &raw mut tmp_class) } == 0 {
                return -1;
            }
            // SAFETY: `arg` is live per the contract.
            if unsafe { append_exp(arg, tmp_tag, tmp_class, 1, 0, 0) } == 0 {
                return -1;
            }
        }
        ASN1_GEN_FLAG_SEQWRAP => {
            // SAFETY: `arg` is live per the contract.
            if unsafe { append_exp(arg, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, 1, 0, 1) } == 0 {
                return -1;
            }
        }
        ASN1_GEN_FLAG_SETWRAP => {
            // SAFETY: `arg` is live per the contract.
            if unsafe { append_exp(arg, V_ASN1_SET, V_ASN1_UNIVERSAL, 1, 0, 1) } == 0 {
                return -1;
            }
        }
        ASN1_GEN_FLAG_BITWRAP => {
            // SAFETY: `arg` is live per the contract.
            if unsafe { append_exp(arg, V_ASN1_BIT_STRING, V_ASN1_UNIVERSAL, 0, 1, 1) } == 0 {
                return -1;
            }
        }
        ASN1_GEN_FLAG_OCTWRAP => {
            // SAFETY: `arg` is live per the contract.
            if unsafe { append_exp(arg, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL, 0, 0, 1) } == 0 {
                return -1;
            }
        }
        ASN1_GEN_FLAG_FORMAT => {
            if vstart.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::ASN1_GEN_333) };
                return -1;
            }
            // `HAS_PREFIX(vstart, "ASCII")` and its siblings are `strncmp`s; each
            // literal is static and `vstart` is NUL-terminated.
            // SAFETY: `vstart` is NUL-terminated; the literals are static.
            let fmt = unsafe {
                if strncmp(vstart, c"ASCII".as_ptr(), 5) == 0 {
                    Some(ASN1_GEN_FORMAT_ASCII)
                } else if strncmp(vstart, c"UTF8".as_ptr(), 4) == 0 {
                    Some(ASN1_GEN_FORMAT_UTF8)
                } else if strncmp(vstart, c"HEX".as_ptr(), 3) == 0 {
                    Some(ASN1_GEN_FORMAT_HEX)
                } else if strncmp(vstart, c"BITLIST".as_ptr(), 7) == 0 {
                    Some(ASN1_GEN_FORMAT_BITLIST)
                } else {
                    None
                }
            };
            match fmt {
                // SAFETY: `arg` is live per the contract.
                Some(f) => unsafe { (*arg).format = f },
                None => {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_345) };
                    return -1;
                }
            }
        }
        _ => {}
    }

    1
}

/// `static int bitstr_cb(const char *elem, int len, void *bitstr)` —
/// `crypto/asn1/asn1_gen.c:750-768`.
///
/// One comma-separated bit number, set into the `ASN1_BIT_STRING`.
///
/// # Safety
///
/// `bitstr` must be a live `ASN1_BIT_STRING`; `elem` readable for `len` bytes.
unsafe extern "C" fn bitstr_cb(elem: *const c_char, len: c_int, bitstr: *mut c_void) -> c_int {
    if elem.is_null() {
        return 0;
    }
    let mut eptr: *mut c_char = ptr::null_mut();
    // SAFETY: `elem` is readable for `len` bytes and `eptr` is writable.
    let bitnum = unsafe { strtoul(elem, &mut eptr, 10) };
    // `if (eptr && *eptr && (eptr != elem + len))`.
    if !eptr.is_null() {
        // SAFETY: `eptr` is non-null and points inside the caller's buffer.
        let leftover = unsafe { *eptr };
        // SAFETY: comparing two pointers into the caller's buffer.
        let at_end = eptr.cast_const() == unsafe { elem.add(len as usize) };
        if leftover != 0 && !at_end {
            return 0;
        }
    }
    #[allow(clippy::cast_possible_wrap)]
    let bitnum = bitnum as c_long;
    if bitnum < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_760) };
        return 0;
    }
    // SAFETY: `bitstr` is a live bit string per the contract.
    if unsafe { ASN1_BIT_STRING_set_bit(bitstr.cast::<Asn1String>(), bitnum as c_int, 1) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_764) };
        return 0;
    }
    1
}

/// `static ASN1_TYPE *asn1_str2type(const char *str, int format, int utype)` —
/// `crypto/asn1/asn1_gen.c:583-748`.
///
/// Builds one scalar value from its textual form. `format` is the `ASN1_GEN_FORMAT_*`
/// the `FORMAT` modifier selected, and is rewritten to `MBSTRING_ASC`/`MBSTRING_UTF8`
/// in the string arm — which is why the parameter is by value and mutable.
///
/// # Safety
///
/// `str` is NULL or NUL-terminated.
unsafe fn asn1_str2type(str_: *const c_char, format: c_int, utype: c_int) -> *mut Asn1Type {
    let mut format = format;
    // SAFETY: `ASN1_TYPE_new` is the item allocator; it answers NULL or a live value.
    let atmp = ASN1_TYPE_new();
    if atmp.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::ASN1_GEN_592) };
        return ptr::null_mut();
    }
    let mut str_ = str_;
    if str_.is_null() {
        str_ = c"".as_ptr();
    }

    // A single `'fail`-labelled block keeps the authority's `bad_str`/`bad_form` tail,
    // which frees `atmp` and answers NULL on every refusal.
    'build: {
        match utype {
            V_ASN1_NULL => {
                // SAFETY: `str_` is NUL-terminated per the contract.
                if unsafe { *str_ } != 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_603) };
                    break 'build;
                }
            }
            V_ASN1_BOOLEAN => {
                if format != ASN1_GEN_FORMAT_ASCII {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_610) };
                    break 'build;
                }
                let vtmp = crate::runtime::conf::types::ConfValue {
                    section: ptr::null_mut(),
                    name: ptr::null_mut(),
                    value: str_ as *mut c_char,
                };
                // SAFETY: `vtmp` is a live `CONF_VALUE`; the destination is the
                // union's `boolean` word.
                if unsafe { X509V3_get_value_bool(&raw const vtmp, &raw mut (*atmp).value.boolean) }
                    == 0
                {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_617) };
                    break 'build;
                }
            }
            V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
                if format != ASN1_GEN_FORMAT_ASCII {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_625) };
                    break 'build;
                }
                // SAFETY: `s2i_ASN1_INTEGER` with a NULL method reads only `str_`.
                let integer = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), str_) };
                if integer.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_631) };
                    break 'build;
                }
                // SAFETY: `atmp` is live and uniquely owned here.
                unsafe { *value_slot(atmp) = integer.cast() };
            }
            V_ASN1_OBJECT => {
                if format != ASN1_GEN_FORMAT_ASCII {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_638) };
                    break 'build;
                }
                // SAFETY: `str_` is NUL-terminated.
                let object = unsafe { OBJ_txt2obj(str_, 0) };
                if object.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_642) };
                    break 'build;
                }
                // SAFETY: `atmp` is live and uniquely owned here.
                unsafe { *value_slot(atmp) = object.cast() };
            }
            V_ASN1_UTCTIME | V_ASN1_GENERALIZEDTIME => {
                if format != ASN1_GEN_FORMAT_ASCII {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_650) };
                    break 'build;
                }
                let s = ASN1_STRING_new();
                if s.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_654) };
                    break 'build;
                }
                // SAFETY: `atmp` is live and uniquely owned here.
                unsafe { *value_slot(atmp) = s.cast() };
                // SAFETY: `s` is live; `str_` is NUL-terminated so `-1` measures it.
                if unsafe { ASN1_STRING_set(s, str_.cast(), -1) } == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_658) };
                    break 'build;
                }
                // SAFETY: `s` is live; the authority re-tags the copied string.
                unsafe { (*s).type_ = utype };
                // SAFETY: `s` is live.
                if unsafe { ASN1_TIME_check(s) } == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_663) };
                    break 'build;
                }
            }
            V_ASN1_BMPSTRING
            | V_ASN1_PRINTABLESTRING
            | V_ASN1_IA5STRING
            | V_ASN1_T61STRING
            | V_ASN1_UTF8STRING
            | V_ASN1_VISIBLESTRING
            | V_ASN1_UNIVERSALSTRING
            | V_ASN1_GENERALSTRING
            | V_ASN1_NUMERICSTRING => {
                if format == ASN1_GEN_FORMAT_ASCII {
                    format = MBSTRING_ASC;
                } else if format == ASN1_GEN_FORMAT_UTF8 {
                    format = MBSTRING_UTF8;
                } else {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_683) };
                    break 'build;
                }
                // SAFETY: the destination slot is `atmp`'s union; `str_` is
                // NUL-terminated so `-1` measures it.
                let copied = unsafe {
                    ASN1_mbstring_copy(
                        value_slot(atmp).cast::<*mut Asn1String>(),
                        str_.cast(),
                        -1,
                        format,
                        ASN1_tag2bit(utype),
                    )
                };
                if copied <= 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_690) };
                    break 'build;
                }
            }
            V_ASN1_BIT_STRING | V_ASN1_OCTET_STRING => {
                let s = ASN1_STRING_new();
                if s.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_699) };
                    break 'build;
                }
                // SAFETY: `atmp` is live and uniquely owned here.
                unsafe { *value_slot(atmp) = s.cast() };
                let mut no_unused = 1;
                if format == ASN1_GEN_FORMAT_HEX {
                    let mut rdlen: c_long = 0;
                    // SAFETY: `str_` is NUL-terminated; `rdlen` is writable.
                    let rdata = unsafe { OPENSSL_hexstr2buf(str_, &mut rdlen) };
                    if rdata.is_null() {
                        // SAFETY: the site is a compile-time constant.
                        unsafe { raise_site(&err_sites::ASN1_GEN_705) };
                        break 'build;
                    }
                    // SAFETY: `s` is live; the authority hands the buffer over.
                    unsafe {
                        (*s).data = rdata;
                        (*s).length = rdlen as c_int;
                        (*s).type_ = utype;
                    }
                } else if format == ASN1_GEN_FORMAT_ASCII {
                    // SAFETY: `s` is live; `str_` is NUL-terminated.
                    if unsafe { ASN1_STRING_set(s, str_.cast(), -1) } == 0 {
                        // SAFETY: the site is a compile-time constant.
                        unsafe { raise_site(&err_sites::ASN1_GEN_713) };
                        break 'build;
                    }
                } else if format == ASN1_GEN_FORMAT_BITLIST && utype == V_ASN1_BIT_STRING {
                    // SAFETY: `s` is a live bit string and `bitstr_cb` is its
                    // setter; `str_` is NUL-terminated.
                    if unsafe {
                        CONF_parse_list(str_, c_int::from(b','), 1, Some(bitstr_cb), s.cast())
                    } == 0
                    {
                        // SAFETY: the site is a compile-time constant.
                        unsafe { raise_site(&err_sites::ASN1_GEN_719) };
                        break 'build;
                    }
                    no_unused = 0;
                } else {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::ASN1_GEN_725) };
                    break 'build;
                }
                if utype == V_ASN1_BIT_STRING && no_unused != 0 {
                    // SAFETY: `s` is a live bit string.
                    unsafe { set_bits_left(s, 0) };
                }
            }
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::ASN1_GEN_735) };
                break 'build;
            }
        }

        // SAFETY: `atmp` is live and uniquely owned here.
        unsafe { (*atmp).type_ = utype };
        return atmp;
    }

    // `bad_str: ERR_add_error_data(2, "string=", str);` then `bad_form: ASN1_TYPE_free`.
    let mut msg = b"string=".to_vec();
    // SAFETY: `str_` is NUL-terminated per the contract.
    unsafe { push_cstr(&mut msg, str_) };
    msg.push(0);
    // SAFETY: `msg` is NUL-terminated.
    unsafe { openssl_rs_err_add_data(msg.as_ptr().cast()) };
    // SAFETY: `atmp` is live and this call owns it.
    unsafe { ASN1_TYPE_free(atmp) };
    ptr::null_mut()
}

/// `static ASN1_TYPE *asn1_multi(int utype, const char *section, X509V3_CTX *cnf, int depth,
/// int *perr)` — `crypto/asn1/asn1_gen.c:406-467`.
///
/// Builds a `SEQUENCE`/`SET` from a config section, recursing through [`generate_v3`]
/// for each entry, and re-encodes the stack through `i2d_ASN1_SEQUENCE_ANY`/
/// `i2d_ASN1_SET_ANY` so the result's content is the members' DER.
///
/// # Safety
///
/// `section` is NULL or NUL-terminated; `cnf` is NULL or a live `X509V3_CTX`; `perr`
/// is writable.
unsafe fn asn1_multi(
    utype: c_int,
    section: *const c_char,
    cnf: *mut X509V3Ctx,
    depth: c_int,
    perr: *mut c_int,
) -> *mut Asn1Type {
    let mut ret: *mut Asn1Type = ptr::null_mut();
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: `OPENSSL_sk_new_null` allocates a fresh stack.
    let sk = OPENSSL_sk_new_null();
    let mut sect: *mut OpenSslStack = ptr::null_mut();

    'build: {
        if sk.is_null() {
            break 'build;
        }
        if !section.is_null() {
            if cnf.is_null() {
                break 'build;
            }
            // SAFETY: `cnf` is live and `section` is NUL-terminated.
            sect = unsafe { X509V3_get_section(cnf, section) };
            if sect.is_null() {
                break 'build;
            }
            // SAFETY: `sect` is a live stack of `CONF_VALUE`.
            let num = unsafe { OPENSSL_sk_num(sect) };
            let mut i = 0;
            while i < num {
                // SAFETY: `sect` is live and `i` is in bounds.
                let cnfv = unsafe { OPENSSL_sk_value(sect, i) }
                    .cast::<crate::runtime::conf::types::ConfValue>();
                // SAFETY: `cnfv` is a live `CONF_VALUE`; its `value` is the member.
                let value = unsafe { (*cnfv).value };
                // SAFETY: `value` is NUL-terminated; `cnf`/`perr` are per the contract.
                let typ = unsafe { generate_v3(value, cnf, depth + 1, perr) };
                if typ.is_null() {
                    break 'build;
                }
                // SAFETY: `sk` is live and `typ` is this call's own value.
                if unsafe { OPENSSL_sk_push(sk, typ.cast::<c_void>()) } == 0 {
                    // SAFETY: `typ` is live and this call owns it.
                    unsafe { ASN1_TYPE_free(typ) };
                    break 'build;
                }
                i += 1;
            }
        }

        // SAFETY: `sk` is a live stack; `der` is a writable slot.
        let derlen = unsafe {
            if utype == V_ASN1_SET {
                i2d_ASN1_SET_ANY(sk, &mut der)
            } else {
                i2d_ASN1_SEQUENCE_ANY(sk, &mut der)
            }
        };
        if derlen < 0 {
            break 'build;
        }
        // SAFETY: the item allocator answers NULL or a live value.
        ret = ASN1_TYPE_new();
        if ret.is_null() {
            break 'build;
        }
        // SAFETY: the string-type allocator answers NULL or a live value.
        let st = ASN1_STRING_type_new(utype);
        if st.is_null() {
            break 'build;
        }
        // SAFETY: `ret` and `st` are live and uniquely owned here.
        unsafe {
            (*ret).value.ptr = st.cast();
            (*ret).type_ = utype;
            (*st).data = der;
            (*st).length = derlen;
        }
        der = ptr::null_mut();
    }

    // SAFETY: `der` is this call's own or NULL.
    unsafe { CRYPTO_free(der.cast::<c_void>(), FILE.as_ptr(), 461) };
    // SAFETY: `sk` is NULL or this call's own stack of `ASN1_TYPE` pointers; each
    // element is freed by the thunk, which is `ASN1_TYPE_free`.
    unsafe { OPENSSL_sk_pop_free(sk, Some(asn1_type_free_thunk)) };
    // SAFETY: `cnf` is NULL or live and `sect` is NULL or this call's own section.
    unsafe { X509V3_section_free(cnf, sect) };
    ret
}

/// The `void (*)(void *)` thunk `sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free)` installs.
///
/// # Safety
///
/// `p` must be NULL or a live `ASN1_TYPE`.
unsafe extern "C" fn asn1_type_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_TYPE` pointers per the stack contract.
    unsafe { ASN1_TYPE_free(p.cast::<Asn1Type>()) };
}

/// `static ASN1_TYPE *generate_v3(const char *str, X509V3_CTX *cnf, int depth, int *perr)` —
/// `crypto/asn1/asn1_gen.c:99-247`.
///
/// The generator core. Parses the modifier/type list, builds the base value, and — when
/// any tagging modifier was seen — regenerates the encoding from the base value's DER
/// and re-decodes it, so the answer is always an item-layer value.
///
/// # Safety
///
/// `str` must be NUL-terminated; `cnf` is NULL or a live `X509V3_CTX`; `perr` is
/// writable.
unsafe fn generate_v3(
    str_: *const c_char,
    cnf: *mut X509V3Ctx,
    depth: c_int,
    perr: *mut c_int,
) -> *mut Asn1Type {
    let mut asn1_tags = new_tag_exp_arg();
    let mut orig_der: *mut c_uchar = ptr::null_mut();
    let mut new_der: *mut c_uchar = ptr::null_mut();
    let mut ret: *mut Asn1Type;

    // SAFETY: `str_` is NUL-terminated and `asn1_tags` is a live accumulator.
    if unsafe {
        CONF_parse_list(
            str_,
            c_int::from(b','),
            1,
            Some(asn1_cb),
            (&raw mut asn1_tags).cast::<c_void>(),
        )
    } != 0
    {
        // SAFETY: `perr` is writable per the contract.
        unsafe { *perr = ASN1_R_UNKNOWN_TAG };
        return ptr::null_mut();
    }

    if asn1_tags.utype == V_ASN1_SEQUENCE || asn1_tags.utype == V_ASN1_SET {
        if cnf.is_null() {
            // SAFETY: `perr` is writable per the contract.
            unsafe { *perr = ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG };
            return ptr::null_mut();
        }
        if depth >= ASN1_GEN_SEQ_MAX_DEPTH {
            // SAFETY: `perr` is writable per the contract.
            unsafe { *perr = ASN1_R_ILLEGAL_NESTED_TAGGING };
            return ptr::null_mut();
        }
        // SAFETY: `cnf` is live and `perr` is writable per the contract.
        ret = unsafe { asn1_multi(asn1_tags.utype, asn1_tags.str_, cnf, depth, perr) };
    } else {
        // SAFETY: `str_` is NUL-terminated.
        ret = unsafe { asn1_str2type(asn1_tags.str_, asn1_tags.format, asn1_tags.utype) };
    }

    if ret.is_null() {
        return ptr::null_mut();
    }

    // No tagging: the base type is the answer.
    if asn1_tags.imp_tag == -1 && asn1_tags.exp_count == 0 {
        return ret;
    }

    // SAFETY: `ret` is live; `orig_der` is a writable slot. i2d consumes nothing.
    let cpy_len_raw = unsafe { i2d_ASN1_TYPE(ret, &mut orig_der) };
    // SAFETY: `ret` is live and this call owns it.
    unsafe { ASN1_TYPE_free(ret) };
    ret = ptr::null_mut();
    if orig_der.is_null() {
        return ptr::null_mut();
    }
    let mut cpy_len = cpy_len_raw;
    let mut cpy_start: *const c_uchar = orig_der;
    let mut hdr_len: c_long = 0;
    let mut hdr_constructed: c_int = 0;
    let mut hdr_tag: c_int = 0;
    let mut hdr_class: c_int = 0;
    let len: c_int;

    'tag: {
        if asn1_tags.imp_tag != -1 {
            // SAFETY: `cpy_start` points into `orig_der`; the three outs are writable.
            let r = unsafe {
                ASN1_get_object(
                    &mut cpy_start,
                    &mut hdr_len,
                    &mut hdr_tag,
                    &mut hdr_class,
                    cpy_len as c_long,
                )
            };
            if r & 0x80 != 0 {
                break 'tag;
            }
            cpy_len -= (cpy_start as usize).wrapping_sub(orig_der as usize) as c_int;
            if r & 0x1 != 0 {
                hdr_constructed = 2;
                hdr_len = 0;
            } else {
                hdr_constructed = r & V_ASN1_CONSTRUCTED;
            }
            let l = ASN1_object_size(0, hdr_len as c_int, asn1_tags.imp_tag);
            if l == -1 {
                break 'tag;
            }
            len = l;
        } else {
            len = cpy_len;
        }

        // Explicit wrappers, computed from the end of the list.
        let mut len = len;
        let mut i = 0;
        while i < asn1_tags.exp_count {
            let idx = (asn1_tags.exp_count - 1 - i) as usize;
            let etmp = &raw mut asn1_tags.exp_list[idx];
            // SAFETY: `etmp` is in bounds.
            len += unsafe { (*etmp).exp_pad };
            // SAFETY: `etmp` is live.
            unsafe { (*etmp).exp_len = len as c_long };
            let l = ASN1_object_size(0, len, unsafe {
                // SAFETY: `etmp` is in bounds of `exp_list`.
                (*etmp).exp_tag
            });
            if l == -1 {
                break 'tag;
            }
            len = l;
            i += 1;
        }

        // SAFETY: the allocator answers NULL or `len` writable bytes.
        new_der = CRYPTO_malloc(len as usize, FILE.as_ptr(), 205).cast::<c_uchar>();
        if new_der.is_null() {
            break 'tag;
        }
        let mut p = new_der;

        // Explicit tags first, in list order.
        let mut i = 0;
        while i < asn1_tags.exp_count {
            let etmp = &raw const asn1_tags.exp_list[i as usize];
            // SAFETY: `p` has room for the header this writes (`len` counted it).
            unsafe {
                ASN1_put_object(
                    &mut p,
                    (*etmp).exp_constructed,
                    (*etmp).exp_len as c_int,
                    (*etmp).exp_tag,
                    (*etmp).exp_class,
                );
            }
            // SAFETY: `etmp` is live; the padding byte was counted in `len`.
            if unsafe { (*etmp).exp_pad } != 0 {
                // SAFETY: `p` has at least one writable byte here.
                unsafe { *p = 0 };
                // SAFETY: one byte was consumed.
                p = unsafe { p.add(1) };
            }
            i += 1;
        }

        if asn1_tags.imp_tag != -1 {
            if asn1_tags.imp_class == V_ASN1_UNIVERSAL
                && (asn1_tags.imp_tag == V_ASN1_SEQUENCE || asn1_tags.imp_tag == V_ASN1_SET)
            {
                hdr_constructed = V_ASN1_CONSTRUCTED;
            }
            // SAFETY: `p` has room for the header this writes.
            unsafe {
                ASN1_put_object(
                    &mut p,
                    hdr_constructed,
                    hdr_len as c_int,
                    asn1_tags.imp_tag,
                    asn1_tags.imp_class,
                );
            }
        }

        // SAFETY: `p` has `cpy_len` writable bytes here and the ranges are disjoint.
        unsafe { memcpy(p.cast(), cpy_start.cast(), cpy_len as usize) };

        let mut cp: *const c_uchar = new_der;
        // SAFETY: `cp` points at the `len`-byte buffer just built.
        ret = unsafe { d2i_ASN1_TYPE(ptr::null_mut(), &mut cp, len as c_long) };
    }

    // SAFETY: both are this call's own or NULL.
    unsafe {
        CRYPTO_free(orig_der.cast::<c_void>(), FILE.as_ptr(), 243);
        CRYPTO_free(new_der.cast::<c_void>(), FILE.as_ptr(), 244);
    }
    ret
}

/// `ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf)` —
/// `crypto/asn1/asn1_gen.c:79-88`.
///
/// A NULL `nconf` goes straight to [`ASN1_generate_v3`] with a NULL context; otherwise
/// the `CONF` is wrapped in an `X509V3_CTX` through `X509V3_set_nconf`.
///
/// # Safety
///
/// `str` must be NUL-terminated; `nconf` is NULL or a live `CONF`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_generate_nconf(
    str_: *const c_char,
    nconf: *mut Conf,
) -> *mut Asn1Type {
    if nconf.is_null() {
        // SAFETY: `str_` is NUL-terminated per the contract.
        return unsafe { ASN1_generate_v3(str_, ptr::null_mut()) };
    }
    let mut cnf = X509V3Ctx {
        flags: 0,
        issuer_cert: ptr::null_mut(),
        subject_cert: ptr::null_mut(),
        subject_req: ptr::null_mut(),
        crl: ptr::null_mut(),
        db_meth: ptr::null_mut(),
        db: ptr::null_mut(),
        issuer_pkey: ptr::null_mut(),
    };
    // SAFETY: `cnf` is a live local and `nconf` is live per the contract.
    unsafe { X509V3_set_nconf(&raw mut cnf, nconf) };
    // SAFETY: `str_` is NUL-terminated and `cnf` outlives the call.
    unsafe { ASN1_generate_v3(str_, &raw mut cnf) }
}

/// `ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf)` —
/// `crypto/asn1/asn1_gen.c:90-97`.
///
/// The generator's one exporting door. The `err` accumulator is the *reason* rather
/// than a boolean: `generate_v3` records the first reason it refuses with, and this
/// wrapper raises it once (`ERR_raise(ERR_LIB_ASN1, err)`), which is a
/// `dynamic_reason` site in the generated table.
///
/// # Safety
///
/// `str` must be NUL-terminated; `cnf` is NULL or a live `X509V3_CTX`.
#[no_mangle]
pub unsafe extern "C" fn ASN1_generate_v3(
    str_: *const c_char,
    cnf: *mut X509V3Ctx,
) -> *mut Asn1Type {
    let mut err: c_int = 0;
    // SAFETY: `str_` is NUL-terminated; `cnf` is NULL or live; `perr` is writable.
    let ret = unsafe { generate_v3(str_, cnf, 0, &raw mut err) };
    if err != 0 {
        // SAFETY: `ASN1_GEN_95` is the authority's own dynamic-reason site.
        unsafe { raise_site_dynamic(&err_sites::ASN1_GEN_95, err) };
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::err::{peek_last_lib, peek_last_reason, ERR_clear_error};

    /// The scalar arms generate a value of the asked-for type, and the value re-encodes
    /// to DER the item layer reads back to the same type.
    #[test]
    fn scalars_generate_and_re_encode() {
        let _guard = crate::test_support::lock_global_state();
        ERR_clear_error();
        for (text, want) in [
            (c"NULL", V_ASN1_NULL),
            (c"INT:42", V_ASN1_INTEGER),
            (c"ENUM:7", V_ASN1_ENUMERATED),
            (c"UTF8:hello", V_ASN1_UTF8STRING),
            (c"IA5:a@b", V_ASN1_IA5STRING),
            (c"OID:1.2.3.4", V_ASN1_OBJECT),
            (c"BOOL:TRUE", V_ASN1_BOOLEAN),
        ] {
            // SAFETY: `text` is a static NUL-terminated literal; a NULL context is legal.
            let v = unsafe { ASN1_generate_v3(text.as_ptr(), ptr::null_mut()) };
            assert!(!v.is_null(), "generating {text:?}");
            // SAFETY: `v` is a live value this test owns.
            unsafe {
                assert_eq!((*v).type_, want, "type of {text:?}");
                let mut out: *mut c_uchar = ptr::null_mut();
                let n = i2d_ASN1_TYPE(v, &mut out);
                assert!(n > 0, "encoding {text:?}");
                assert!(!out.is_null());
                let mut p: *const c_uchar = out;
                let back = d2i_ASN1_TYPE(ptr::null_mut(), &mut p, n as c_long);
                assert!(!back.is_null(), "decoding {text:?}");
                assert_eq!((*back).type_, want);
                ASN1_TYPE_free(back);
                CRYPTO_free(out.cast::<c_void>(), FILE.as_ptr(), 205);
                ASN1_TYPE_free(v);
            }
        }
    }

    /// `IMP`/`EXP` wrappers re-encode through the generator's tagging path and come back as
    /// values the item layer reads — the one shape a plain copy would get wrong.
    #[test]
    fn explicit_and_implicit_tagging_re_encode() {
        let _guard = crate::test_support::lock_global_state();
        ERR_clear_error();
        for text in [c"IMP:2,INT:5", c"EXP:0,UTF8:x", c"IMP:3,OCTWRAP,INT:1"] {
            // SAFETY: `text` is a static literal; a NULL context is legal.
            let v = unsafe { ASN1_generate_v3(text.as_ptr(), ptr::null_mut()) };
            assert!(!v.is_null(), "generating {text:?}");
            // SAFETY: `v` is this test's own value.
            unsafe { ASN1_TYPE_free(v) };
        }
    }

    /// The two refusal paths the entry door owns: an unknown tag, and a `SEQUENCE` with no
    /// config database.
    #[test]
    fn refusals_raise_their_reasons() {
        let _guard = crate::test_support::lock_global_state();
        ERR_clear_error();
        // SAFETY: static literal; NULL context.
        let v = unsafe { ASN1_generate_v3(c"NOSUCH:1".as_ptr(), ptr::null_mut()) };
        assert!(v.is_null());
        assert_eq!(peek_last_lib(), 13);
        assert_eq!(peek_last_reason(), u64::from(ASN1_R_UNKNOWN_TAG as u32));

        ERR_clear_error();
        // SAFETY: static literal; NULL context.
        let v = unsafe { ASN1_generate_v3(c"SEQUENCE:sec".as_ptr(), ptr::null_mut()) };
        assert!(v.is_null());
        assert_eq!(
            peek_last_reason(),
            u64::from(ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG as u32)
        );
        ERR_clear_error();
    }
}
