//! `crypto/x509/v3_prn.c` — the X.509v3 extension printers. Phase 11.5, landed whole.
//!
//! `crypto/x509/v3_prn.c` is 215 lines and defines four public exports plus the one `static`
//! helper [`unknown_ext_print`]:
//!
//! * [`X509V3_EXT_val_prn`] (`:24-65`) — the `name:value` stack printer, in its multiline and
//!   inline forms;
//! * [`X509V3_EXT_print`] (`:69-136`) — the main routine: looks the method up through
//!   [`crate::x509::v3_lib::X509V3_EXT_get`], decodes the octets through the method's `it` or
//!   old-style `d2i`, and prints through whichever of `i2s`/`i2v`/`i2r` is set, falling back to
//!   [`unknown_ext_print`] when there is no method or the decode fails;
//! * [`X509V3_extensions_print`] (`:138-176`) — the whole-stack printer, with the
//!   `X509_FLAG_EXTENSIONS_ONLY_KID` filter and the raw-octet fallback when a member fails to
//!   print;
//! * [`X509V3_EXT_print_fp`] (`:204-214`) — the `FILE *` wrapper, `#ifndef OPENSSL_NO_STDIO` in
//!   the authority and always compiled in this profile.
//!
//! Every name lands: the four are declared in `include/openssl/x509v3.h.in` (`:736`, `:738`,
//! `:741`, `:743`), so all four are `#[no_mangle]` exports; `unknown_ext_print` (`:178-201`) is
//! `static` and stays a private `unsafe fn`. Nothing is withheld by name and nothing is stubbed.
//!
//! ## No raise
//!
//! The unit raises nothing — every path is a `BIO_*` return value or a per-method callback result
//! — so `crypto/x509/v3_prn.c` is deliberately not an entry in `gen_err_raise_sites.py`'s covered
//! set and no `ErrSite` is declared. The three `X509V3_EXT_UNKNOWN_MASK` selectors and
//! `X509_FLAG_EXTENSIONS_ONLY_KID` are declared here from the header (they are modelled nowhere
//! else).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::der::ASN1_parse_dump;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::{BIO_free, BIO_new_fp, Bio, BIO_NOCLOSE};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{NID_authority_key_identifier, NID_subject_key_identifier, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3_EXT_get, X509V3_EXT_MULTILINE};
use crate::x509::v3_utl::X509V3_conf_free;
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
};
use crate::x509::x_exten::X509Extension;

/// `OPENSSL_FILE` for this unit's allocation expansions — `crypto/x509/v3_prn.c`.
const FILE: &CStr = c"crypto/x509/v3_prn.c";
/// `X509V3_EXT_print`'s `err:` `OPENSSL_free(value)` — `crypto/x509/v3_prn.c:130`.
const LINE_FREE_VALUE: c_int = 130;

/// `#define X509V3_EXT_UNKNOWN_MASK (0xfL << 16)` — `include/openssl/x509v3.h.in:518`.
const X509V3_EXT_UNKNOWN_MASK: c_ulong = 0xf << 16;
/// `#define X509V3_EXT_DEFAULT 0` — `include/openssl/x509v3.h.in:520`.
const X509V3_EXT_DEFAULT: c_ulong = 0;
/// `#define X509V3_EXT_ERROR_UNKNOWN (1L << 16)` — `include/openssl/x509v3.h.in:522`.
const X509V3_EXT_ERROR_UNKNOWN: c_ulong = 1 << 16;
/// `#define X509V3_EXT_PARSE_UNKNOWN (2L << 16)` — `include/openssl/x509v3.h.in:524`.
const X509V3_EXT_PARSE_UNKNOWN: c_ulong = 2 << 16;
/// `#define X509V3_EXT_DUMP_UNKNOWN (3L << 16)` — `include/openssl/x509v3.h.in:526`.
const X509V3_EXT_DUMP_UNKNOWN: c_ulong = 3 << 16;
/// `#define X509_FLAG_EXTENSIONS_ONLY_KID (1L << 13)` — `include/openssl/x509.h.in:151`.
const X509_FLAG_EXTENSIONS_ONLY_KID: c_ulong = 1 << 13;

/// The `void (*)(void *)` thunk `sk_CONF_VALUE_pop_free(nval, X509V3_conf_free)` installs —
/// `crypto/x509/v3_prn.c:129`.
///
/// # Safety
///
/// `p` must be NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent, int ml)` —
/// `crypto/x509/v3_prn.c:24-65`.
///
/// A NULL stack prints nothing. Otherwise the `indent`-space prefix is written once for the
/// non-multiline or empty case (and `<EMPTY>\n` when empty), and each entry is written inline
/// (`name:value`, comma-separated) or one per line (`ml` non-zero).
///
/// # Safety
///
/// `out` must be a live BIO; `val` NULL or a live `CONF_VALUE` stack.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_val_prn(
    out: *mut Bio,
    val: *mut OpenSslStack,
    indent: c_int,
    ml: c_int,
) {
    if val.is_null() {
        return;
    }
    // SAFETY: `val` is live.
    let num = unsafe { OPENSSL_sk_num(val) };
    if ml == 0 || num == 0 {
        // SAFETY: `out` is live; the format and the empty argument are static literals.
        unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
        if num == 0 {
            // SAFETY: `out` is live; the literal is static NUL-terminated.
            unsafe { BIO_puts(out, c"<EMPTY>\n".as_ptr()) };
        }
    }
    for i in 0..num {
        if ml != 0 {
            if i > 0 {
                // SAFETY: `out` is live; the format is a static literal.
                unsafe { BIO_printf(out, c"\n".as_ptr()) };
            }
            // SAFETY: `out` is live; the format and the empty argument are static literals.
            unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
        } else if i > 0 {
            // SAFETY: `out` is live; the format is a static literal.
            unsafe { BIO_printf(out, c", ".as_ptr()) };
        }
        // SAFETY: `val` is live and `i` is within its count.
        let nval = unsafe { OPENSSL_sk_value(val, i) }.cast::<ConfValue>();
        // SAFETY: `nval` is a live `CONF_VALUE`.
        let (name, value) = unsafe { ((*nval).name, (*nval).value) };
        if name.is_null() {
            // SAFETY: `out` is live; a NULL-name entry's `value` is NUL-terminated.
            unsafe { BIO_puts(out, value) };
        } else if value.is_null() {
            // SAFETY: `out` is live; a NULL-value entry's `name` is NUL-terminated.
            unsafe { BIO_puts(out, name) };
        } else {
            // SAFETY: `out` is live; both strings are NUL-terminated.
            unsafe { BIO_printf(out, c"%s:%s".as_ptr(), name, value) };
        }
    }
}

/// `static int unknown_ext_print(BIO *out, const unsigned char *ext, int extlen,
/// unsigned long flag, int indent, int supported)` — `crypto/x509/v3_prn.c:178-201`.
///
/// Dispatches on the `X509V3_EXT_UNKNOWN_MASK` selector: default refuses, `ERROR_UNKNOWN` prints
/// `<Parse Error>`/`<Not Supported>` (by `supported`), `PARSE_UNKNOWN` dumps through
/// `ASN1_parse_dump`, `DUMP_UNKNOWN` through `BIO_dump_indent`.
///
/// # Safety
///
/// `out` must be a live BIO; `ext` must be `extlen` readable bytes.
unsafe fn unknown_ext_print(
    out: *mut Bio,
    ext: *const c_uchar,
    extlen: c_int,
    flag: c_ulong,
    indent: c_int,
    supported: c_int,
) -> c_int {
    match flag & X509V3_EXT_UNKNOWN_MASK {
        X509V3_EXT_DEFAULT => 0,
        X509V3_EXT_ERROR_UNKNOWN => {
            if supported != 0 {
                // SAFETY: `out` is live; the format and empty argument are static literals.
                unsafe { BIO_printf(out, c"%*s<Parse Error>".as_ptr(), indent, c"".as_ptr()) };
            } else {
                // SAFETY: as above.
                unsafe { BIO_printf(out, c"%*s<Not Supported>".as_ptr(), indent, c"".as_ptr()) };
            }
            1
        }
        X509V3_EXT_PARSE_UNKNOWN => {
            // SAFETY: `out` is live; `ext` is `extlen` readable bytes.
            c_int::from(unsafe { ASN1_parse_dump(out, ext, extlen as c_long, indent, -1) } > 0)
        }
        X509V3_EXT_DUMP_UNKNOWN => {
            // SAFETY: `out` is live; `ext` is `extlen` readable bytes.
            c_int::from(unsafe { BIO_dump_indent(out, ext.cast::<c_void>(), extlen, indent) } > 0)
        }
        _ => 1,
    }
}

/// `int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent)` —
/// `crypto/x509/v3_prn.c:69-136`.
///
/// Decodes the extension's octet string through the method looked up by [`X509V3_EXT_get`] and
/// prints through the first of `i2s`/`i2v`/`i2r` that is set; a missing method or a failed decode
/// is handed to [`unknown_ext_print`]. The `err:` tail always drains the value stack and frees the
/// decoded structure, as in the authority.
///
/// # Safety
///
/// `out` must be a live BIO; `ext` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_print(
    out: *mut Bio,
    ext: *mut X509Extension,
    flag: c_ulong,
    indent: c_int,
) -> c_int {
    let mut value: *mut c_char = ptr::null_mut();
    // SAFETY: `ext` is live per the contract.
    let extoct = unsafe { X509_EXTENSION_get_data(ext) };
    // SAFETY: `extoct` is the extension's embedded octet string.
    let mut p = unsafe { ASN1_STRING_get0_data(extoct) };
    // SAFETY: `extoct` is live.
    let extlen = unsafe { ASN1_STRING_length(extoct) };
    let mut ok = 1;

    // SAFETY: `ext` is live.
    let method = unsafe { X509V3_EXT_get(ext) };
    if method.is_null() {
        // SAFETY: `out` is live; `p`/`extlen` describe the (still raw) value.
        return unsafe { unknown_ext_print(out, p, extlen, flag, indent, 0) };
    }
    // SAFETY: `method` is live.
    let it = unsafe { (*method).it };
    let mut ext_str: *mut c_void = ptr::null_mut();
    if let Some(it) = it {
        // SAFETY: `p` borrows the value for `extlen` bytes; `it()` answers the item the
        // `ASN1_ITEM_ref` macro names.
        ext_str = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, extlen as c_long, it()) };
    } else {
        // SAFETY: `method` is live.
        let d2i = unsafe { (*method).d2i };
        if let Some(f) = d2i {
            // SAFETY: `f` is the old-style decoder; `p` borrows the value for `extlen` bytes.
            ext_str = unsafe { f(ptr::null_mut(), &raw mut p, extlen as c_long) };
        }
    }
    if ext_str.is_null() {
        // SAFETY: `out` is live; `p`/`extlen` describe the value.
        return unsafe { unknown_ext_print(out, p, extlen, flag, indent, 1) };
    }

    // SAFETY: `method` is live.
    let (i2s, i2v, i2r, ext_flags, ext_free) = unsafe {
        (
            (*method).i2s,
            (*method).i2v,
            (*method).i2r,
            (*method).ext_flags,
            (*method).ext_free,
        )
    };
    let mut nval: *mut OpenSslStack = ptr::null_mut();
    if let Some(f) = i2s {
        // SAFETY: `method`/`ext_str` are the callback's contract.
        value = unsafe { f(method, ext_str) };
        if value.is_null() {
            ok = 0;
        } else {
            // SAFETY: `out` is live; `value` is NUL-terminated.
            unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), value) };
        }
    } else if let Some(f) = i2v {
        // SAFETY: `method`/`ext_str` are the callback's contract; the destination slot is NULL.
        nval = unsafe { f(method, ext_str, ptr::null_mut()) };
        if nval.is_null() {
            ok = 0;
        } else {
            // SAFETY: `out` is live; `nval` is the callback's own `CONF_VALUE` stack.
            unsafe { X509V3_EXT_val_prn(out, nval, indent, ext_flags & X509V3_EXT_MULTILINE) };
        }
    } else if let Some(f) = i2r {
        // SAFETY: `method`/`ext_str`/`out` are the callback's contract.
        if unsafe { f(method, ext_str, out, indent) } == 0 {
            ok = 0;
        }
    } else {
        ok = 0;
    }

    // SAFETY: `nval` is NULL or this call's own `CONF_VALUE` stack.
    unsafe { OPENSSL_sk_pop_free(nval, Some(conf_value_free_thunk)) };
    // SAFETY: `value` is NULL or this call's own; the site is constant.
    unsafe { CRYPTO_free(value.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_VALUE) };
    if let Some(it) = it {
        // SAFETY: `ext_str` is the item value; `it()` answers the item it describes.
        unsafe { ASN1_item_free(ext_str, it()) };
    } else if let Some(f) = ext_free {
        // SAFETY: `ext_str` is the old-style value `f` releases.
        unsafe { f(ext_str) };
    }
    ok
}

/// `int X509V3_extensions_print(BIO *bp, const char *title, const STACK_OF(X509_EXTENSION) *exts,
/// unsigned long flag, int indent)` — `crypto/x509/v3_prn.c:138-176`.
///
/// An empty stack answers success and prints nothing. Otherwise an optional `title` heading is
/// written, and each extension is printed (or, when it cannot be, its raw octets are shown).
///
/// # Safety
///
/// `bp` must be a live BIO; `title` NULL or NUL-terminated; `exts` NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509V3_extensions_print(
    bp: *mut Bio,
    title: *const c_char,
    exts: *const OpenSslStack,
    flag: c_ulong,
    mut indent: c_int,
) -> c_int {
    // SAFETY: `exts` is NULL or a live extension stack.
    if unsafe { OPENSSL_sk_num(exts) } <= 0 {
        return 1;
    }
    if !title.is_null() {
        // SAFETY: `bp` is live; the format is a static literal; `title` is NUL-terminated.
        unsafe { BIO_printf(bp, c"%*s%s:\n".as_ptr(), indent, c"".as_ptr(), title) };
        indent += 4;
    }
    // SAFETY: `exts` is live.
    let num = unsafe { OPENSSL_sk_num(exts) };
    for i in 0..num {
        // SAFETY: `exts` is live and `i` is within its count.
        let ex = unsafe { OPENSSL_sk_value(exts, i) }.cast::<X509Extension>();
        // SAFETY: `ex` is a live extension.
        let obj = unsafe { X509_EXTENSION_get_object(ex) };
        if flag & X509_FLAG_EXTENSIONS_ONLY_KID != 0
            // SAFETY: `obj` is live.
            && unsafe { OBJ_obj2nid(obj) } != NID_subject_key_identifier
            // SAFETY: as above.
            && unsafe { OBJ_obj2nid(obj) } != NID_authority_key_identifier
        {
            continue;
        }
        if indent != 0
            // SAFETY: `bp` is live; the format and empty argument are static literals.
            && unsafe { BIO_printf(bp, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0
        {
            return 0;
        }
        // SAFETY: `bp` is live; `obj` is live.
        unsafe { i2a_ASN1_OBJECT(bp, obj) };
        // SAFETY: `ex` is live.
        let j = unsafe { X509_EXTENSION_get_critical(ex) };
        // SAFETY: `bp` is live; the format and both arguments are static or NUL-terminated.
        if unsafe {
            BIO_printf(
                bp,
                c": %s\n".as_ptr(),
                if j != 0 {
                    c"critical".as_ptr()
                } else {
                    c"".as_ptr()
                },
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `bp` is live; `ex` is live.
        if unsafe { X509V3_EXT_print(bp, ex, flag, indent + 4) } == 0 {
            // SAFETY: `bp` is live; the format and empty argument are static literals.
            unsafe { BIO_printf(bp, c"%*s".as_ptr(), indent + 4, c"".as_ptr()) };
            // SAFETY: `bp` is live; `ex`'s data is the extension's own octet string.
            unsafe { ASN1_STRING_print(bp, X509_EXTENSION_get_data(ex)) };
        }
        // SAFETY: `bp` is live; the byte is a static one-byte literal.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) } <= 0 {
            return 0;
        }
    }
    1
}

/// `int X509V3_EXT_print_fp(FILE *fp, X509_EXTENSION *ext, int flag, int indent)` —
/// `crypto/x509/v3_prn.c:204-214`.
///
/// Wraps the `FILE *` in a non-closing BIO, delegates to [`X509V3_EXT_print`], and frees it.
///
/// # Safety
///
/// `fp` must be a live `FILE *`; `ext` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_print_fp(
    fp: *mut FILE,
    ext: *mut X509Extension,
    flag: c_int,
    indent: c_int,
) -> c_int {
    // SAFETY: `fp` is a live `FILE *`.
    let bio_tmp = unsafe { BIO_new_fp(fp.cast::<c_void>(), BIO_NOCLOSE) };
    if bio_tmp.is_null() {
        return 0;
    }
    // SAFETY: `bio_tmp` is live; `ext` is live; the flag widens to the print routine's `unsigned
    // long`, as in the authority's own implicit conversion.
    let ret = unsafe { X509V3_EXT_print(bio_tmp, ext, flag as c_ulong, indent) };
    // SAFETY: `bio_tmp` is this call's own.
    unsafe { BIO_free(bio_tmp) };
    ret
}
