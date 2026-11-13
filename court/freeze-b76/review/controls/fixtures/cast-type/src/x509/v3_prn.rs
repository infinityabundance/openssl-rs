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
use crate::x509::v3_lib::{
    RegistryReadGuard, X509V3ExtMethod, X509V3_EXT_get, X509V3_EXT_MULTILINE,
};
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
/// `method` must be a live `X509V3_EXT_METHOD`. `X509V3_EXT_print` establishes this by holding
/// the extension registry's read hold for the whole call, so a concurrent
/// `X509V3_EXT_add`/`_add_alias`/`_cleanup` cannot release a DYNAMIC row underneath it. `Ok(None)`
/// means the row declares no `it` (its old-style `d2i`/`ext_free` pair is the codec); `Err(())`
/// means the declared accessor answered NULL, which the caller must treat as a failed decode
/// rather than pass a NULL item to `ASN1_item_d2i`/`ASN1_item_free`.
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
/// The method row `X509V3_EXT_get` resolves is protected for the whole call by the extension
/// registry's read hold: `X509V3_EXT_add`/`_add_list`/`_add_alias`/`_cleanup` take the write hold,
/// so a DYNAMIC alias row cannot be released while this frame resolves or uses it (B49-R10). The
/// 22 i2r printers and their helpers do not call any registry entry point, so the nested read
/// taken by `X509V3_EXT_get` is a reader/reader acquisition. A caller-registered `i2s`/`i2v`/`i2r`
/// callback that itself calls a registry **writer** will block until this call returns; the
/// authority would instead free the in-use row (see the §17 divergence in the B49 receipt).
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
    // Hold the registry read lock across the row resolution **and** every use of that row below.
    // A DYNAMIC row (an `X509V3_EXT_add_alias` copy) is released by `X509V3_EXT_cleanup`; the
    // writer's write hold cannot be taken while this guard is alive, so the row stays live for
    // this whole call (B49-R10). The printers never touch the registry, so the nested read inside
    // `X509V3_EXT_get` is a reader/reader acquisition rather than a self-deadlock.
    let Some(_registry) = RegistryReadGuard::acquire() else {
        return 0;
    };
    // SAFETY: `ext` is live per the contract.
    let extoct = unsafe { X509_EXTENSION_get_data(ext) };
    // SAFETY: `extoct` is the extension's embedded octet string.
    let mut p = unsafe { ASN1_STRING_get0_data(extoct) };
    // SAFETY: `extoct` is live.
    let extlen = unsafe { ASN1_STRING_length(extoct) };
    let mut ok = 1;

    // SAFETY: `ext` is live, and the read hold taken above protects the row this resolves.
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
        // The row stays live across this call: the read hold taken at :271 is held until
        // dispatch ends, and `i2s` receives `method` (the enumerated-table slot reads
        // `method->usr_data`), so a DYNAMIC alias row must not be released until this callback
        // returns. The hold is required for the whole callback, not only for the slot read
        // above (B49-R10).
        //
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
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::asn1::layout::Asn1String;
    use crate::asn1::string::{
        ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    };
    use crate::asn1::typ::i2d_ASN1_OCTET_STRING;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_CTRL_INFO};
    use crate::runtime::obj::{
        NID_crl_number, NID_crl_reason, NID_group_ac, NID_issued_on_behalf_of, OBJ_create,
    };
    use crate::x509::v3_lib::{X509V3_EXT_add, X509V3_EXT_add_alias, X509V3_EXT_cleanup};
    use crate::x509::x509_v3::X509_EXTENSION_create_by_NID;
    use crate::x509::x_exten::X509_EXTENSION_free;
    use core::sync::atomic::{AtomicI32, Ordering};

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

    /// Positive path: three of the eleven `i2s` slots run end-to-end through
    /// `X509V3_EXT_print` over standard rows: a constant slot, the enumerated-table slot and
    /// the integer-forwarding slot. Each printed string is the callback's answer, and each
    /// result is released once by the dispatcher's `OwnedStr`.
    #[test]
    fn i2s_callbacks_print_end_to_end() {
        let cases: [(c_int, &[u8], &[u8]); 3] = [
            // group_ac: an ASN.1 NULL; `i2s_GROUP_AC` answers a fresh "NULL".
            (NID_group_ac, &[0x05, 0x00], b"NULL"),
            // crl_reason: ENUMERATED 1; `enum_i2s` walks the row's table to "Key Compromise".
            (NID_crl_reason, &[0x0A, 0x01, 0x01], b"Key Compromise"),
            // crl_number: INTEGER 42; `int_i2s` forwards to `i2s_ASN1_INTEGER`.
            (NID_crl_number, &[0x02, 0x01, 0x2A], b"42"),
        ];
        for (nid, der, expected) in cases {
            let ext = extension_with_der(nid, der);
            // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
            let bio = unsafe { BIO_new(BIO_s_mem()) };
            assert!(!bio.is_null(), "the memory BIO must be created");
            // SAFETY: `bio`/`ext` are live and the standard row's print slot is `i2s`.
            let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 0) };
            assert_eq!(ret, 1, "the i2s path must print successfully for NID {nid}");
            // SAFETY: `bio` is the live memory BIO just written.
            let text = unsafe { bio_bytes(bio) };
            assert_eq!(text, expected, "NID {nid} i2s output");
            // SAFETY: both objects are this test's own.
            unsafe {
                BIO_free(bio);
                X509_EXTENSION_free(ext);
            }
        }
    }

    /// A probe `i2s` that records that it ran and answers NULL.
    static I2S_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// The recording callback: it must never run for a value that failed to decode.
    unsafe extern "C" fn recording_i2s(
        _method: *const X509V3ExtMethod,
        _value: *mut c_void,
    ) -> *mut c_char {
        I2S_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
        ptr::null_mut()
    }

    /// A dynamic row whose `it` is `GENERAL_NAME` and whose only slot is the recording `i2s`.
    fn i2s_probe_row(nid: c_int) -> X509V3ExtMethod {
        X509V3ExtMethod {
            ext_nid: nid,
            ext_flags: 0,
            it: Some(crate::x509::v3_genn::GENERAL_NAME_it),
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: Some(recording_i2s),
            s2i: None,
            i2v: None,
            v2i: None,
            i2r: None,
            r2i: None,
            usr_data: ptr::null_mut(),
        }
    }

    /// The `i2s` decode guard: a value that does not decode as the row's item answers before
    /// the slot, exactly as the `i2r` family does. Removing the `ext_str.is_null()` refusal
    /// (`src/x509/v3_prn.rs:317-320`) hands the callback a NULL value and this test fails on
    /// the recorded call.
    #[test]
    fn i2s_is_not_called_when_the_value_does_not_decode() {
        let _serial = crate::test_support::lock_global_state();
        I2S_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
        let nid = fresh_nid(
            c"1.3.6.1.4.1.57264.50.1",
            c"b50-i2s-guard",
            c"B50 i2s decode guard",
        );
        let mut row = i2s_probe_row(nid);
        // SAFETY: `row` is a live stack row that outlives the registry (cleanup runs below);
        // the call takes the write hold.
        let added = unsafe { X509V3_EXT_add(&raw mut row) };
        assert_eq!(added, 1, "the probe row must register");
        // A `GENERAL_NAME` row whose value is not a valid name.
        let ext = extension_with_der(nid, &[0xFF, 0xFF]);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: `bio`/`ext` are live; the default policy answers 0 for a failed decode.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        assert_eq!(ret, 0, "a failed decode must not print");
        assert!(
            !I2S_CALLED.load(std::sync::atomic::Ordering::SeqCst),
            "the i2s callback must not run when the value did not decode"
        );
        // SAFETY: both objects are this test's own; cleanup releases the dynamic probe row.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
            X509V3_EXT_cleanup();
        }
    }

    /// Register a fresh object and answer its NID. A fresh NID has no `STANDARD_EXTS` row, so a
    /// dynamic alias registered for it is reached only through the dynamic `EXT_LIST` fallback.
    fn fresh_nid(oid: &CStr, sn: &CStr, ln: &CStr) -> c_int {
        // SAFETY: all three strings are NUL-terminated and `OBJ_create` copies them.
        let nid = unsafe { OBJ_create(oid.as_ptr(), sn.as_ptr(), ln.as_ptr()) };
        assert_ne!(nid, 0, "the object must be registered under a fresh NID");
        nid
    }

    /// A live row over `GENERAL_NAME` carrying `i2r`; used only by the registry tests below.
    fn general_name_row(nid: c_int, i2r: crate::x509::v3_lib::X509V3ExtI2r) -> X509V3ExtMethod {
        X509V3ExtMethod {
            ext_nid: nid,
            ext_flags: 0,
            it: Some(crate::x509::v3_genn::GENERAL_NAME_it),
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: None,
            s2i: None,
            i2v: None,
            v2i: None,
            i2r,
            r2i: None,
            usr_data: ptr::null_mut(),
        }
    }

    /// Read a memory BIO's contents as a byte slice.
    ///
    /// # Safety
    /// `bio` must be a live memory BIO; the returned slice borrows its buffer and must not
    /// outlive the BIO or a write to it.
    unsafe fn bio_bytes<'a>(bio: *mut Bio) -> &'a [u8] {
        let mut data: *mut c_char = ptr::null_mut();
        // SAFETY: `bio` is live; `data` is this frame's out-parameter slot.
        let len = unsafe { BIO_ctrl(bio, BIO_CTRL_INFO, 0, ptr::addr_of_mut!(data).cast()) };
        assert!(len > 0 && !data.is_null(), "the memory BIO must hold text");
        // SAFETY: the control answered the BIO's own buffer and byte count.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), len as usize) }
    }

    /// B49 functional: a DYNAMIC alias of a standard row prints through the copied `i2r`, and
    /// `X509V3_EXT_cleanup` then releases it. The read hold keeps the row live for the print.
    #[test]
    fn a_dynamic_alias_prints_and_cleanup_releases_it() {
        let _serial = crate::test_support::lock_global_state();
        let nid_to = fresh_nid(
            c"1.3.6.1.4.1.57264.49.1",
            c"b49-alias-print",
            c"B49 alias print test",
        );
        // SAFETY: two integer NIDs; `nid_from` names a STANDARD_EXTS row.
        let added = unsafe { X509V3_EXT_add_alias(nid_to, NID_issued_on_behalf_of) };
        assert_eq!(added, 1, "the alias must register");
        let ext = extension_with_der(nid_to, &[0x82, 0x03, b'f', b'o', b'o']);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: both live; the alias row carries the standard row's i2r.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        assert_eq!(ret, 1, "the alias's i2r must print");
        // SAFETY: `bio` is the live memory BIO just written.
        let text = unsafe { bio_bytes(bio) };
        assert!(
            text.windows(3).any(|window| window == b"foo"),
            "the copied printer must emit the dNSName: {text:?}"
        );
        // SAFETY: both objects are this frame's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
        // SAFETY: no pointer arguments; the write hold releases every DYNAMIC row.
        unsafe { X509V3_EXT_cleanup() };

        // After cleanup the alias no longer resolves, so the default unknown path answers 0.
        let gone = extension_with_der(nid_to, &[0x82, 0x03, b'f', b'o', b'o']);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: `bio`/`gone` are live; the row is gone and the flag is the default.
        let ret = unsafe { X509V3_EXT_print(bio, gone, 0, 4) };
        assert_eq!(ret, 0, "cleanup must have released the alias");
        // SAFETY: both objects are this frame's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(gone);
        }
    }

    /// The load-bearing canary: a print that is inside its row's `i2r` must prevent
    /// `X509V3_EXT_cleanup` from completing. Removing the read hold in `X509V3_EXT_print` (or
    /// the write hold in `X509V3_EXT_cleanup`) lets the cleanup thread finish while the printer
    /// is still using the row, and this test fails on the recorded observation.
    static PRINT_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static CLEANUP_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static CLEANUP_RAN_DURING_PRINT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// An `i2r` that keeps the print inside its use of the row long enough for a concurrent
    /// `X509V3_EXT_cleanup` to try to free it, and records whether that cleanup completed.
    unsafe extern "C" fn blocking_i2r(
        _method: *const X509V3ExtMethod,
        _value: *mut c_void,
        _out: *mut Bio,
        _indent: c_int,
    ) -> c_int {
        use std::sync::atomic::Ordering as AtomicOrdering;
        PRINT_ENTERED.store(true, AtomicOrdering::SeqCst);
        // Bounded, so a broken lock cannot hang the suite. With the read hold absent the
        // cleanup thread completes in microseconds; with it present it cannot complete at all.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            if CLEANUP_DONE.load(AtomicOrdering::SeqCst) {
                CLEANUP_RAN_DURING_PRINT.store(true, AtomicOrdering::SeqCst);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        1
    }

    #[test]
    fn cleanup_cannot_release_a_row_while_a_print_uses_it() {
        use std::sync::atomic::Ordering as AtomicOrdering;
        let _serial = crate::test_support::lock_global_state();
        PRINT_ENTERED.store(false, AtomicOrdering::SeqCst);
        CLEANUP_DONE.store(false, AtomicOrdering::SeqCst);
        CLEANUP_RAN_DURING_PRINT.store(false, AtomicOrdering::SeqCst);

        let nid_src = fresh_nid(
            c"1.3.6.1.4.1.57264.49.2",
            c"b49-blocking-src",
            c"B49 blocking source",
        );
        let nid_dst = fresh_nid(
            c"1.3.6.1.4.1.57264.49.3",
            c"b49-blocking-dst",
            c"B49 blocking destination",
        );
        let mut row = general_name_row(nid_src, Some(blocking_i2r));
        // SAFETY: `row` is a live local that outlives the registry entry; `_cleanup` below runs
        // before this frame returns.
        let added = unsafe { X509V3_EXT_add(&raw mut row) };
        assert_eq!(added, 1);
        // SAFETY: two integer NIDs; `nid_src` now names the caller-owned row above.
        let aliased = unsafe { X509V3_EXT_add_alias(nid_dst, nid_src) };
        assert_eq!(aliased, 1);

        let ext = extension_with_der(nid_dst, &[0x82, 0x03, b'f', b'o', b'o']);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");

        let cleanup = std::thread::spawn(|| {
            use std::sync::atomic::Ordering as AtomicOrdering;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !PRINT_ENTERED.load(AtomicOrdering::SeqCst)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            // SAFETY: no pointer arguments; the registry lock serialises this with the print.
            unsafe { X509V3_EXT_cleanup() };
            CLEANUP_DONE.store(true, AtomicOrdering::SeqCst);
        });

        // SAFETY: both live; the alias is a DYNAMIC copy of `row` and runs `blocking_i2r`.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        assert_eq!(ret, 1, "the blocking printer must run");
        let joined = cleanup.join();
        assert!(joined.is_ok(), "the cleanup thread must not panic");
        assert!(
            !CLEANUP_RAN_DURING_PRINT.load(AtomicOrdering::SeqCst),
            "X509V3_EXT_cleanup completed while X509V3_EXT_print was still using the row: \
             the registry read hold is not excluding the writer"
        );
        // SAFETY: both objects are this frame's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
    }

    // ---------------------------------------------------------------------------------------
    // B54: the print/encode dispatch hands each slot the object the row's own item decoded.
    // ---------------------------------------------------------------------------------------

    /// The ASN.1 tag of the object the last probe received (`-1` before any call).
    static SEEN_TAG: AtomicI32 = AtomicI32::new(-1);
    /// The tag the probe expects: the type its audited callback casts the object to.
    static EXPECTED_TAG: AtomicI32 = AtomicI32::new(-1);

    fn set_expected(tag: c_int) {
        EXPECTED_TAG.store(tag, Ordering::SeqCst);
        SEEN_TAG.store(-1, Ordering::SeqCst);
    }

    /// A probe standing in for an audited printer: it records the tag of the object the
    /// dispatcher supplied and succeeds only when that tag is the one the audited callback
    /// casts to. Every item used with this probe is `ASN1_STRING`-shaped (`INTEGER`,
    /// `OCTET STRING`, `UTF8String`), so reading `type_` is valid for all of them.
    unsafe extern "C" fn tag_probe_i2r(
        _method: *const X509V3ExtMethod,
        value: *mut c_void,
        _out: *mut Bio,
        _indent: c_int,
    ) -> c_int {
        // SAFETY: `value` is the object this row's item decoded (an `ASN1_STRING` shape).
        let seen = unsafe { (*value.cast::<Asn1String>()).type_ };
        SEEN_TAG.store(seen, Ordering::SeqCst);
        c_int::from(seen == EXPECTED_TAG.load(Ordering::SeqCst))
    }

    /// The `i2s` twin of [`tag_probe_i2r`]: same tag check, and on success it returns the one
    /// whole seam allocation the `i2s` contract owes the dispatcher.
    unsafe extern "C" fn tag_probe_i2s(
        _method: *const X509V3ExtMethod,
        value: *mut c_void,
    ) -> *mut c_char {
        // SAFETY: `value` is the object this row's item decoded (an `ASN1_STRING` shape).
        let seen = unsafe { (*value.cast::<Asn1String>()).type_ };
        SEEN_TAG.store(seen, Ordering::SeqCst);
        if seen != EXPECTED_TAG.load(Ordering::SeqCst) {
            return ptr::null_mut();
        }
        // SAFETY: the literal is a static NUL-terminated string; the allocator answers NULL or a
        // fresh block the dispatcher releases once.
        unsafe { crate::runtime::mem::CRYPTO_strdup(c"b54".as_ptr(), ptr::null(), 0) }
    }

    /// The `i2v` twin of [`tag_probe_i2r`]: it checks the tag and, on success, answers a fresh
    /// `CONF_VALUE` stack whose ownership the dispatcher takes (it pops it free at
    /// `src/x509/v3_prn.rs:372`).
    unsafe extern "C" fn tag_probe_i2v(
        _method: *const X509V3ExtMethod,
        value: *mut c_void,
        _sink: *mut OpenSslStack,
    ) -> *mut OpenSslStack {
        // SAFETY: `value` is the object this row's item decoded (an `ASN1_STRING` shape).
        let seen = unsafe { (*value.cast::<Asn1String>()).type_ };
        SEEN_TAG.store(seen, Ordering::SeqCst);
        if seen != EXPECTED_TAG.load(Ordering::SeqCst) {
            return ptr::null_mut();
        }
        // SAFETY: `line` is NUL-terminated; the returned stack is this call's own and is
        // transferred to the dispatcher.
        unsafe { crate::x509::v3_utl::X509V3_parse_list(c"b54:probe".as_ptr()) }
    }

    /// One caller-owned row for the probes: `it` is `item`, and exactly one slot is set.
    fn probe_tag_row(
        nid: c_int,
        item: Option<unsafe extern "C" fn() -> *const Asn1Item>,
        i2r: bool,
        i2s: bool,
        i2v: bool,
    ) -> X509V3ExtMethod {
        X509V3ExtMethod {
            ext_nid: nid,
            ext_flags: 0,
            it: item,
            ext_new: None,
            ext_free: None,
            d2i: None,
            i2d: None,
            i2s: if i2s { Some(tag_probe_i2s) } else { None },
            s2i: None,
            i2v: if i2v { Some(tag_probe_i2v) } else { None },
            v2i: None,
            i2r: if i2r { Some(tag_probe_i2r) } else { None },
            r2i: None,
            usr_data: ptr::null_mut(),
        }
    }

    /// Print one extension of `nid` whose value is `der`, through the probe rows, and answer
    /// what the probe saw and what `X509V3_EXT_print` returned.
    fn print_and_observe(nid: c_int, der: &[u8]) -> (c_int, c_int) {
        let ext = extension_with_der(nid, der);
        // SAFETY: `BIO_s_mem` is a live method table and `BIO_new` returns a fresh BIO.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must be created");
        // SAFETY: both live; the row was registered by the caller of this helper.
        let ret = unsafe { X509V3_EXT_print(bio, ext, 0, 4) };
        let seen = SEEN_TAG.load(Ordering::SeqCst);
        // SAFETY: both objects are this frame's own.
        unsafe {
            BIO_free(bio);
            X509_EXTENSION_free(ext);
        }
        (ret, seen)
    }

    /// B54-C1 (print path, `i2s` and `i2r`): the dispatcher decodes with the row's `it` and
    /// hands that object to the same row's slot, so a callback that casts to the item's type is
    /// sound. The third row is deliberately mispaired: its item decodes an `OCTET STRING` while
    /// its probe expects an `INTEGER`. The harness observes the actual tag and refuses, so the
    /// violation is caught by the type check rather than silently reinterpreted.
    #[test]
    fn print_slots_receive_the_tag_their_rows_item_decodes() {
        let _serial = crate::test_support::lock_global_state();
        let int_i2r = fresh_nid(
            c"1.3.6.1.4.1.57264.54.1",
            c"b54-int-i2r",
            c"B54 i2r integer",
        );
        let oct_i2r = fresh_nid(c"1.3.6.1.4.1.57264.54.2", c"b54-oct-i2r", c"B54 i2r octet");
        let int_i2s = fresh_nid(
            c"1.3.6.1.4.1.57264.54.3",
            c"b54-int-i2s",
            c"B54 i2s integer",
        );
        let bad_i2s = fresh_nid(
            c"1.3.6.1.4.1.57264.54.4",
            c"b54-bad-i2s",
            c"B54 i2s mispaired",
        );
        let rows = [
            (
                int_i2r,
                probe_tag_row(
                    int_i2r,
                    Some(crate::asn1::items::ASN1_INTEGER_it),
                    true,
                    false,
                    false,
                ),
            ),
            (
                oct_i2r,
                probe_tag_row(
                    oct_i2r,
                    Some(crate::asn1::items::ASN1_OCTET_STRING_it),
                    true,
                    false,
                    false,
                ),
            ),
            (
                int_i2s,
                probe_tag_row(
                    int_i2s,
                    Some(crate::asn1::items::ASN1_INTEGER_it),
                    false,
                    true,
                    false,
                ),
            ),
            (
                bad_i2s,
                probe_tag_row(
                    bad_i2s,
                    Some(crate::asn1::items::ASN1_OCTET_STRING_it),
                    false,
                    true,
                    false,
                ),
            ),
        ];
        for (_, row) in rows {
            // SAFETY: the boxed row is leaked so it outlives the registry borrow; the call takes
            // the write hold.
            let leaked: &'static mut X509V3ExtMethod = Box::leak(Box::new(row));
            assert_eq!(
                unsafe {
                    // SAFETY: `leaked` is a live row that outlives the registry entry.
                    X509V3_EXT_add(leaked)
                },
                1,
                "the probe row must register"
            );
        }

        // The `i2r` arm: an INTEGER row's printer sees an INTEGER, an OCTET row's sees an OCTET.
        set_expected(crate::asn1::layout::V_ASN1_INTEGER);
        let (ret, seen) = print_and_observe(int_i2r, &[0x02, 0x01, 0x2A]);
        assert_eq!(
            seen,
            crate::asn1::layout::V_ASN1_INTEGER,
            "i2r saw the wrong tag"
        );
        assert_eq!(ret, 1, "the correctly paired i2r must succeed");

        set_expected(crate::asn1::layout::V_ASN1_OCTET_STRING);
        let (ret, seen) = print_and_observe(oct_i2r, &[0x04, 0x01, 0x41]);
        assert_eq!(
            seen,
            crate::asn1::layout::V_ASN1_OCTET_STRING,
            "i2r saw the wrong tag"
        );
        assert_eq!(ret, 1, "the correctly paired i2r must succeed");

        // The `i2s` arm: same object, same check, and the returned block is the dispatcher's.
        set_expected(crate::asn1::layout::V_ASN1_INTEGER);
        let (ret, seen) = print_and_observe(int_i2s, &[0x02, 0x01, 0x2A]);
        assert_eq!(seen, crate::asn1::layout::V_ASN1_INTEGER);
        assert_eq!(ret, 1, "the correctly paired i2s must succeed");

        // The type fact violated: an OCTET STRING item with an INTEGER-expecting callback. The
        // probe sees the real tag, refuses, and the dispatcher reports the print failure; the
        // object is never reinterpreted as an integer.
        set_expected(crate::asn1::layout::V_ASN1_INTEGER);
        let (ret, seen) = print_and_observe(bad_i2s, &[0x04, 0x01, 0x41]);
        assert_eq!(
            seen,
            crate::asn1::layout::V_ASN1_OCTET_STRING,
            "the probe must observe the object's real tag, not the one it expects"
        );
        assert_eq!(ret, 0, "the mispaired i2s must be refused");
    }

    /// B54-C2 (encode path, `i2v`): the `i2v` slot receives the same decoded object and returns
    /// a stack whose ownership transfers to the dispatcher exactly once. The mispaired row is
    /// refused by the same tag check.
    #[test]
    fn i2v_slot_receives_the_tag_its_rows_item_decodes() {
        let _serial = crate::test_support::lock_global_state();
        let int_i2v = fresh_nid(
            c"1.3.6.1.4.1.57264.54.5",
            c"b54-int-i2v",
            c"B54 i2v integer",
        );
        let bad_i2v = fresh_nid(
            c"1.3.6.1.4.1.57264.54.6",
            c"b54-bad-i2v",
            c"B54 i2v mispaired",
        );
        for row in [
            probe_tag_row(
                int_i2v,
                Some(crate::asn1::items::ASN1_INTEGER_it),
                false,
                false,
                true,
            ),
            probe_tag_row(
                bad_i2v,
                Some(crate::asn1::items::ASN1_OCTET_STRING_it),
                false,
                false,
                true,
            ),
        ] {
            // SAFETY: leaked so the row outlives the registry borrow; the call takes the write
            // hold.
            let leaked: &'static mut X509V3ExtMethod = Box::leak(Box::new(row));
            assert_eq!(
                unsafe {
                    // SAFETY: `leaked` is a live row that outlives the registry entry.
                    X509V3_EXT_add(leaked)
                },
                1,
                "the probe row must register"
            );
        }

        set_expected(crate::asn1::layout::V_ASN1_INTEGER);
        let (ret, seen) = print_and_observe(int_i2v, &[0x02, 0x01, 0x2A]);
        assert_eq!(
            seen,
            crate::asn1::layout::V_ASN1_INTEGER,
            "i2v saw the wrong tag"
        );
        assert_eq!(ret, 1, "the correctly paired i2v must succeed");

        set_expected(crate::asn1::layout::V_ASN1_INTEGER);
        let (ret, seen) = print_and_observe(bad_i2v, &[0x04, 0x01, 0x41]);
        assert_eq!(seen, crate::asn1::layout::V_ASN1_OCTET_STRING);
        assert_eq!(ret, 0, "the mispaired i2v must be refused");
    }

    /// B54-W (per-call-site witness): every production row below declares the item its audited
    /// callback was written for. The decode the dispatcher performs and the cast the callback
    /// makes therefore agree. Swapping any row's `it` for a different item makes this fail.
    #[test]
    fn standard_rows_declare_the_item_their_callbacks_were_written_for() {
        type It = unsafe extern "C" fn() -> *const Asn1Item;
        use crate::asn1::items::{
            ASN1_ENUMERATED_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_OCTET_STRING_it,
            ASN1_UTF8STRING_it,
        };
        use crate::runtime::obj::{
            NID_authority_key_identifier, NID_basic_constraints, NID_crl_distribution_points,
            NID_crl_number, NID_crl_reason, NID_ext_key_usage, NID_id_pkix_OCSP_CrlID,
            NID_id_pkix_OCSP_archiveCutoff, NID_info_access, NID_issuer_alt_name,
            NID_issuing_distribution_point, NID_name_constraints, NID_policy_constraints,
            NID_policy_mappings, NID_proxyCertInfo, NID_sbgp_autonomousSysNum, NID_subjectSignTool,
            NID_subject_alt_name, NID_subject_key_identifier, NID_target_information,
        };
        use crate::x509::v3_ac_tgt::OSSL_TARGETING_INFORMATION_it;
        use crate::x509::v3_akeya::AUTHORITY_KEYID_it;
        use crate::x509::v3_asid::ASIdentifiers_it;
        use crate::x509::v3_bcons::BASIC_CONSTRAINTS_it;
        use crate::x509::v3_crld::{CRL_DIST_POINTS_it, ISSUING_DIST_POINT_it};
        use crate::x509::v3_extku::EXTENDED_KEY_USAGE_it;
        use crate::x509::v3_genn::GENERAL_NAMES_it;
        use crate::x509::v3_info::AUTHORITY_INFO_ACCESS_it;
        use crate::x509::v3_ncons::NAME_CONSTRAINTS_it;
        use crate::x509::v3_pcia::PROXY_CERT_INFO_EXTENSION_it;
        use crate::x509::v3_pcons::POLICY_CONSTRAINTS_it;
        use crate::x509::v3_pmaps::POLICY_MAPPINGS_it;

        let cases: &[(c_int, It)] = &[
            // `i2s` rows
            (NID_crl_number, ASN1_INTEGER_it),
            (NID_crl_reason, ASN1_ENUMERATED_it),
            (NID_subject_key_identifier, ASN1_OCTET_STRING_it),
            (NID_subjectSignTool, ASN1_UTF8STRING_it),
            // `i2v`/`v2i` rows
            (NID_basic_constraints, BASIC_CONSTRAINTS_it),
            (NID_policy_constraints, POLICY_CONSTRAINTS_it),
            (NID_policy_mappings, POLICY_MAPPINGS_it),
            (NID_authority_key_identifier, AUTHORITY_KEYID_it),
            (NID_info_access, AUTHORITY_INFO_ACCESS_it),
            (NID_ext_key_usage, EXTENDED_KEY_USAGE_it),
            (NID_subject_alt_name, GENERAL_NAMES_it),
            (NID_issuer_alt_name, GENERAL_NAMES_it),
            (NID_crl_distribution_points, CRL_DIST_POINTS_it),
            (NID_issuing_distribution_point, ISSUING_DIST_POINT_it),
            (NID_sbgp_autonomousSysNum, ASIdentifiers_it),
            (NID_name_constraints, NAME_CONSTRAINTS_it),
            // `i2r` rows (including the nested target-information printers)
            (NID_id_pkix_OCSP_CrlID, crate::ocsp::ocsp_asn::OCSP_CRLID_it),
            (NID_id_pkix_OCSP_archiveCutoff, ASN1_GENERALIZEDTIME_it),
            (NID_target_information, OSSL_TARGETING_INFORMATION_it),
            (NID_proxyCertInfo, PROXY_CERT_INFO_EXTENSION_it),
        ];
        for (nid, expected) in cases {
            // SAFETY: `nid` is an integer; the lookup takes the registry read hold itself.
            let row = unsafe { crate::x509::v3_lib::X509V3_EXT_get_nid(*nid) };
            assert!(!row.is_null(), "NID {nid} must resolve to a standard row");
            // SAFETY: `row` is live under the registry read hold for this call.
            let declared = unsafe { (*row).it }.expect("the row must declare an item");
            // SAFETY: `declared` is the row's item accessor.
            let resolved = unsafe { declared() };
            // SAFETY: `expected` is the item the audited callback casts to.
            let wanted = unsafe { expected() };
            assert_eq!(
                resolved, wanted,
                "NID {nid}: the row declares a different item than the audited callback casts to"
            );
        }
    }
}
