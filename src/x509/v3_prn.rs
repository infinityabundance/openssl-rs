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
use crate::asn1::layout::Asn1Item;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::FILE;
use crate::runtime::bio::{BIO_free, BIO_new_fp, Bio, BIO_NOCLOSE};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::obj::{NID_authority_key_identifier, NID_subject_key_identifier, OBJ_obj2nid};
use crate::runtime::owned_str::OwnedStr;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_get, X509V3_EXT_MULTILINE};
use crate::x509::v3_utl::X509V3_conf_free;
use crate::x509::x509_v3::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
};
use crate::x509::x_exten::X509Extension;

/// `OPENSSL_FILE` for this unit's allocation expansions — `crypto/x509/v3_prn.c`.
const FILE: &CStr = c"crypto/x509/v3_prn.c";
/// `X509V3_EXT_print`'s `err:` `OPENSSL_free(value)` — `crypto/x509/v3_prn.c:130`.
const LINE_FREE_VALUE: c_int = 130;

// An `i2s` callback result owned by the frame that received it (`OwnedStr`).
//
// The authority's `X509V3_EXT_print` writes the callback result to `char *value` and its `err:`
// label runs `OPENSSL_free(value)` (`crypto/x509/v3_prn.c:106,130`); the public `i2s_ASN1_*`
// family says "It is the caller's responsibility to free the returned string"
// (`doc/man3/s2i_ASN1_IA5STRING.pod`). The corresponding caller obligation is stated on
// `X509V3ExtI2s` in `v3_lib.rs`: a non-NULL result is the base of one whole `OPENSSL_malloc`/
// `CRYPTO_strdup` block, NUL-terminated within its `strlen + 1`-byte C-string extent, whose
// ownership transfers to this print path. The shared owner makes the release here the only one.

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

/// Resolve a method row's declared `ASN1_ITEM` exactly once.
///
/// `X509V3_EXT_METHOD.it` is an `ASN1_ITEM_EXP *`: a function returning the item the row's
/// value has (`include/openssl/asn1.h.in:378-384`). The authority expands
/// `ASN1_ITEM_ptr(method->it)` separately at its decode site and at its release site
/// (`crypto/x509/v3_prn.c:86-89,131-135`). One resolution makes those two halves agree even
/// for a caller-registered row whose accessor is not stable, and it is the dispatcher's
/// guard for the `i2r` family: that slot is reached only with a value decoded by the row's
/// declared item, never with a NULL item.
///
/// # Safety
///
/// `method` must be a live `X509V3_EXT_METHOD`. `Ok(None)` means the row declares no `it`
/// (its old-style `d2i`/`ext_free` pair is the codec); `Err(())` means the declared
/// accessor answered NULL, which the caller must treat as a failed decode rather than pass a
/// NULL item to `ASN1_item_d2i`/`ASN1_item_free`.
unsafe fn ext_method_item(method: *const X509V3ExtMethod) -> Result<Option<*const Asn1Item>, ()> {
    // SAFETY: `method` is live per the contract.
    let Some(it) = (unsafe { (*method).it }) else {
        return Ok(None);
    };
    // SAFETY: `it` is the row's `ASN1_ITEM_ref` accessor.
    let item = unsafe { it() };
    if item.is_null() {
        Err(())
    } else {
        Ok(Some(item))
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
/// `out` must be a live BIO and `ext` a live `X509_EXTENSION`; the prologue refuses NULL for either with 0 before the first dereference, establishing non-NULLness only.
/// The method row `X509V3_EXT_get` resolves must stay live and unmodified for the whole call: no `X509V3_EXT_add`/`_add_alias`/`_cleanup` may run concurrently with it (B49-R10).
/// An `_add_alias` copy is DYNAMIC and released by `_cleanup` while the dynamic list is unlocked, as in the authority; liveness remains the caller's obligation.
#[no_mangle]
pub unsafe extern "C" fn X509V3_EXT_print(
    out: *mut Bio,
    ext: *mut X509Extension,
    flag: c_ulong,
    indent: c_int,
) -> c_int {
    // The `i2s`/`i2v`/`i2r` slots all require a live output BIO, and the `i2r` slot is handed
    // the extension this frame decodes. Both are cheap necessary conditions the dispatcher
    // can refuse before any callback runs; the authority faults on either.
    if out.is_null() || ext.is_null() {
        return 0;
    }
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
    // Resolve the row's declared item once, before the decode, and reuse that same item for
    // the release below. The authority expands `ASN1_ITEM_ptr(method->it)` at both sites
    // (`crypto/x509/v3_prn.c:86-89,131-135`); resolving once makes the decode and the free
    // agree even if a caller-registered row supplies an accessor that does not answer a
    // stable item, and it refuses a NULL item instead of passing it to `ASN1_item_d2i` /
    // `ASN1_item_free`, whose contracts require a live item. This is the dispatcher's
    // `i2r`-family guard: the slot is reached only with a value decoded by the declared item.
    // SAFETY: `method` is live.
    let item = match unsafe { ext_method_item(method) } {
        Ok(item) => item,
        // The row's accessor answered NULL: there is no type to decode with, so the printer
        // is never handed a value. This is the authority's failed-decode path.
        Err(()) => {
            // SAFETY: `out` is live; `p`/`extlen` describe the raw value.
            return unsafe { unknown_ext_print(out, p, extlen, flag, indent, 1) };
        }
    };
    let mut ext_str: *mut c_void = ptr::null_mut();
    if let Some(item) = item {
        // SAFETY: `p` borrows the value for `extlen` bytes; `item` is the row's live item.
        ext_str = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, extlen as c_long, item) };
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
    let mut value: Option<OwnedStr> = None;
    if let Some(f) = i2s {
        // SAFETY: `method`/`ext_str` are the callback's contract. The result is NULL or the
        // callback's exclusively owned seam block per `X509V3ExtI2s`: whole-block base,
        // NUL-terminated within its `strlen + 1`-byte C-string extent, ownership transferred to
        // this frame, whose `Drop` is its single release at `v3_prn.c:130`.
        value =
            unsafe { OwnedStr::adopt(f(method, ext_str), SeamFile::new(FILE), LINE_FREE_VALUE) };
        if let Some(v) = value.as_ref() {
            // SAFETY: `out` is live; `v` is NUL-terminated.
            unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), v.as_ptr()) };
        } else {
            ok = 0;
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
    // The authority's `err:` order: release the value at :130, then the decoded structure.
    drop(value);
    if let Some(item) = item {
        // SAFETY: `ext_str` is the value the same `item` decoded; the one resolution is used
        // for both halves, so a value is never released through a different item.
        unsafe { ASN1_item_free(ext_str, item) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::string::{
        ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    };
    use crate::asn1::typ::i2d_ASN1_OCTET_STRING;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{BIO_free, BIO_new};
    use crate::runtime::obj::NID_issued_on_behalf_of;
    use crate::x509::x509_v3::X509_EXTENSION_create_by_NID;
    use crate::x509::x_exten::X509_EXTENSION_free;

    /// A minimal live row for the item-resolution guard: only `it` is read.
    fn probe_row(it: Option<unsafe extern "C" fn() -> *const Asn1Item>) -> X509V3ExtMethod {
        X509V3ExtMethod {
            ext_nid: 0,
            ext_flags: 0,
            it,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: None,
            i2r: None,
            r2i: None,
            usr_data: ptr::null_mut(),
        }
    }

    /// A row's `it` accessor that answers NULL: there is no item to decode with.
    unsafe extern "C" fn null_item() -> *const Asn1Item {
        ptr::null()
    }

    /// The guard's canary: a row whose `it` accessor answers NULL is reported as a failed
    /// resolution, so the dispatcher never hands `ASN1_item_d2i`/`ASN1_item_free` a NULL
    /// item. Removing the `is_null` refusal resolves `Some(null)` and this assertion fails.
    #[test]
    fn ext_method_item_refuses_an_accessor_that_answers_null() {
        let row = probe_row(Some(null_item));
        // SAFETY: `row` is a live local row.
        let resolved = unsafe { ext_method_item(&raw const row) };
        assert_eq!(resolved, Err(()), "a NULL ASN.1 item must not be resolved");
    }

    /// The same helper still resolves a real accessor, and reports a row that declares none.
    #[test]
    fn ext_method_item_resolves_the_declared_item() {
        let row = probe_row(Some(crate::x509::v3_genn::GENERAL_NAME_it));
        let expected = crate::x509::v3_genn::GENERAL_NAME_it();
        // SAFETY: `row` is a live local row and its accessor is the item function itself.
        let resolved = unsafe { ext_method_item(&raw const row) };
        assert_eq!(resolved, Ok(Some(expected)));
        let none = probe_row(None);
        // SAFETY: `none` is a live local row.
        let absent = unsafe { ext_method_item(&raw const none) };
        assert_eq!(absent, Ok(None));
    }

    /// Build an extension of `nid` whose value is `der`. `issuedOnBehalfOf` carries a bare
    /// `GENERAL_NAME` and its row installs no `i2s`/`i2v`, so printing it runs the `i2r` arm
    /// this family is about; a `dNSName` (`[2] IA5String`) is `82 03 66 6f 6f`.
    fn extension_with_der(nid: c_int, der: &[u8]) -> *mut X509Extension {
        let value = ASN1_OCTET_STRING_new();
        assert!(!value.is_null(), "the extension value must be allocatable");
        // SAFETY: `value` is live and uniquely owned; `der` is `der.len()` readable bytes.
        let set = unsafe { ASN1_OCTET_STRING_set(value, der.as_ptr(), der.len() as c_int) };
        assert_eq!(set, 1);
        // SAFETY: `value` is live; the constructor copies its contents.
        let ext = unsafe { X509_EXTENSION_create_by_NID(ptr::null_mut(), nid, 0, value) };
        // SAFETY: the extension copied the octets; release this test's reference.
        unsafe { ASN1_OCTET_STRING_free(value) };
        assert!(!ext.is_null(), "the extension must be created");
        ext
    }

    fn issued_on_behalf_of_extension() -> *mut X509Extension {
        extension_with_der(NID_issued_on_behalf_of, &[0x82, 0x03, b'f', b'o', b'o'])
    }

    /// The `i2r` arm still runs for a well-formed value.
    #[test]
    fn i2r_printer_still_prints_through_a_live_bio() {
        let ext = issued_on_behalf_of_extension();
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // A non-zero indent: the authority's body treats a zero-length first write as a
        // refusal, so indent 0 would make this printer answer 0 by design.
        // SAFETY: `bio` and `ext` are live; this row's only print slot is `i2r`.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        assert_eq!(ret, 1, "the i2r path must print successfully");
        // SAFETY: both objects are this test's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
    }

    /// The prologue refuses a NULL `out` or `ext` with 0 before the method lookup, the decode
    /// or any callback. `X509V3_EXT_ERROR_UNKNOWN` makes the refusal observable: without the
    /// guard the NULL-`ext` call takes the unknown path and answers 1, and the NULL-`out` call
    /// reaches the failed-decode path and answers 1 as well.
    #[test]
    fn null_out_or_ext_is_refused_by_the_prologue() {
        let malformed = extension_with_der(NID_issued_on_behalf_of, &[0xFF, 0xFF]);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: each call passes one NULL argument to the prologue's refusal path. The
        // implementation returns before dereferencing it and before the lookup, so no invalid
        // access occurs; the other argument is live. Without the guard the first calls would
        // reach the decode/unknown paths and answer 1 under `X509V3_EXT_ERROR_UNKNOWN`.
        unsafe {
            assert_eq!(
                X509V3_EXT_print(ptr::null_mut(), malformed, X509V3_EXT_ERROR_UNKNOWN, 4),
                0,
                "a NULL out must be refused"
            );
            assert_eq!(
                X509V3_EXT_print(bio, ptr::null_mut(), X509V3_EXT_ERROR_UNKNOWN, 4),
                0,
                "a NULL ext must be refused"
            );
            assert_eq!(
                X509V3_EXT_print(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    X509V3_EXT_ERROR_UNKNOWN,
                    4
                ),
                0,
                "two NULL arguments must be refused"
            );
            BIO_free(bio);
            X509_EXTENSION_free(malformed);
        }
    }

    /// A value that does not decode as the row's item never reaches `i2r`, so the printers
    /// that dereference the decoded value unconditionally (e.g. `sxnet_i2r`) are never handed
    /// NULL. This is the decode guard the `i2r` contracts name as their establishing path.
    #[test]
    fn i2r_printer_is_refused_when_the_value_does_not_decode() {
        let ext = extension_with_der(NID_issued_on_behalf_of, &[0xFF, 0xFF]);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: `bio` and `ext` are live; the default unknown-extension policy answers 0.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        assert_eq!(ret, 0, "a failed decode must not reach the i2r slot");
        // SAFETY: both objects are this test's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
    }

    /// Drive the `method->i2s` arm that owns the callback result through
    /// `OwnedStr`: the standard subject-key-identifier method builds its string
    /// with `CRYPTO_strdup`, this call adopts it, and `Drop` releases it once.
    #[test]
    fn print_an_octet_string_extension_owns_the_i2s_result() {
        let oct = ASN1_OCTET_STRING_new();
        assert!(!oct.is_null(), "the octet string must be allocatable");
        let bytes = [0xA1u8, 0xB2, 0xC3, 0xD4];
        // SAFETY: `oct` is live and uniquely owned; `bytes` is readable for 4 bytes.
        assert_eq!(unsafe { ASN1_OCTET_STRING_set(oct, bytes.as_ptr(), 4) }, 1);
        // SAFETY: `oct` is live; a NULL `out` asks only for the encoded length.
        let der_len = unsafe { i2d_ASN1_OCTET_STRING(oct, ptr::null_mut()) };
        assert!(der_len > 0, "the DER length must be positive");
        let mut der = vec![0u8; der_len as usize];
        let mut out = der.as_mut_ptr();
        // SAFETY: `oct` is live and `der` has room for `der_len` bytes.
        assert_eq!(unsafe { i2d_ASN1_OCTET_STRING(oct, &raw mut out) }, der_len);
        let ext_value = ASN1_OCTET_STRING_new();
        assert!(
            !ext_value.is_null(),
            "the extension value must be allocatable"
        );
        // SAFETY: `ext_value` is live and uniquely owned; `der` is `der_len` bytes.
        let set_ok = unsafe { ASN1_OCTET_STRING_set(ext_value, der.as_ptr(), der_len) };
        assert_eq!(set_ok, 1);
        // SAFETY: `ext_value` is live and `X509_EXTENSION_create_by_NID` copies its contents.
        let ext = unsafe {
            X509_EXTENSION_create_by_NID(ptr::null_mut(), NID_subject_key_identifier, 0, ext_value)
        };
        // SAFETY: the extension copied the octets; release this test's references.
        unsafe {
            ASN1_OCTET_STRING_free(oct);
            ASN1_OCTET_STRING_free(ext_value);
        }
        assert!(!ext.is_null(), "the extension must be created");

        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: `bio` and `ext` are live; the standard SKID method's `i2s` runs,
        // and this call's `OwnedStr` is the result's sole release.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 0) };
        assert_eq!(ret, 1, "the i2s path must print successfully");

        // SAFETY: both objects are this test's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
    }
}
