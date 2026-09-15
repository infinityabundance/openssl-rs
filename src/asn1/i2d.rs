//! Phase 5 — the shared DER encoder: `asn1_i2d_ex_primitive` and the dispatch
//! that reaches it.
//!
//! This module reproduces `crypto/asn1/tasn_enc.c`. Like [`crate::asn1::d2i`] it
//! holds no exported function: every `i2d_*` wrapper is one call to
//! `ASN1_item_i2d` with the matching item, and those wrappers live beside the type
//! they encode.
//!
//! ## The shape of an encode, which is not the shape of a decode
//!
//! A decode has the bytes and asks what they mean. An encode has the value and has
//! to *size* the output before it can write it, and the authority does that by
//! calling the content codec **twice**: once with a null destination to learn the
//! length, and once to fill. [`i2d_ex_primitive`] is that two-call structure, and
//! it is the reason the content codecs return a length rather than writing
//! unconditionally.
//!
//! Three consequences are easy to get wrong and each is observable:
//!
//! * `len == -1` means **omit the type entirely** — the caller's field is absent
//!   from the encoding — and `i2d_ex_primitive` answers 0 without writing.
//! * `len == -2` means **use indefinite length**: the content length becomes 0, the
//!   header is written constructed-indefinite, and a two-byte end-of-contents
//!   marker follows. `ASN1_put_object(.., ndef = 2, ..)` and
//!   `ASN1_object_size(2, ..)` are what implement the two halves of that.
//! * For `SEQUENCE`, `SET` and `OTHER` the header is part of what the content
//!   codec returns, so **no tag is written** (`usetag = 0`) and the returned length
//!   is the answer as-is. `utype` can change inside the content codec — an
//!   `ASN1_TYPE` does exactly that — which is why the decision is made *after* the
//!   sizing call and not before.
//!
//! ## The `out == NULL` convention
//!
//! `i2d_*(val, NULL)` answers the encoded length without encoding; `i2d_*(val, &p)`
//! writes into the caller's buffer and advances `p`; `i2d_*(val, &null)` allocates
//! and writes. The third form is [`item_i2d`]'s, and it is the only place an
//! allocation decision is made — which is why the length is computed first and a
//! length of zero or less is passed straight through rather than being turned into
//! an allocation of zero bytes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};

use crate::asn1::bitstr::ossl_i2c_ASN1_BIT_STRING;
use crate::asn1::layout::*;
use crate::asn1::prim::ossl_i2c_ASN1_INTEGER;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::Asn1Object;

/// The authority translation unit for the encoder these functions reproduce.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_enc.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `ASN1_item_i2d` — and only that.
///
/// The three output conventions are handled here and nowhere else. Note that the
/// allocation path runs the encoder twice: once to size it against a null
/// destination, and once to fill the buffer. The buffer's size is exactly the
/// length the first pass reported, so a content codec whose two passes disagree
/// would overflow it — which is why the authority's codecs return the length
/// rather than writing and reporting.
///
/// # Safety
///
/// `val` must be null or a live value of the item's type. `out` must be null or
/// point to a slot holding null or a pointer with room for the encoding; `it` must
/// be a live item of one of the shapes [`ex_i2d`] admits.
pub(crate) unsafe fn item_i2d(
    val: *const Asn1String,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the caller's slot is readable when `out` is non-null.
    if !out.is_null() && unsafe { *out }.is_null() {
        let v = val;
        // SAFETY: `v` is a live slot holding the caller's value; `it` is the
        // caller's item.
        let len = unsafe { ex_i2d(&v, core::ptr::null_mut(), it, -1, 0) };
        if len <= 0 {
            return len;
        }
        // SAFETY: `len` is the size the sizing pass just computed, and it is
        // positive here.
        let buf = CRYPTO_malloc(len as usize, FILE.as_ptr(), LINE) as *mut c_uchar;
        if buf.is_null() {
            // The authority returns -1 here without raising: a caller distinguishes
            // "could not allocate" from "would not fit" by the sign, not by the
            // queue.
            return -1;
        }
        let mut p = buf;
        // SAFETY: `p` has room for `len` bytes and `v` is a live slot.
        unsafe { ex_i2d(&v, &mut p, it, -1, 0) };
        // SAFETY: the caller's slot is writable and now owns `buf`.
        unsafe { *out = buf };
        return len;
    }
    let v = val;
    // SAFETY: `v` is a live slot; `out` is the caller's, possibly null.
    unsafe { ex_i2d(&v, out, it, -1, 0) }
}

/// `ASN1_item_ex_i2d`, restricted to the `PRIMITIVE`-without-templates and
/// `MSTRING` arms.
///
/// The `PRIMITIVE` guard runs *before* anything dereferences `*pval`, and it is not
/// symmetric: it skips the check only for a primitive item, because a primitive's
/// value lives in the slot rather than through it — a `BOOLEAN` item's value *is*
/// the slot's low four bytes.
///
/// # Safety
///
/// `pval` must point to a live slot. `out` must be null or point to a slot with
/// room; `it` must be a live item.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's `pval` contract
unsafe fn ex_i2d(
    pval: *const *const Asn1String,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    if pval.is_null() || it.is_null() {
        return 0;
    }
    // SAFETY: `it` is non-null, and the caller owns it for the duration.
    let it = unsafe { &*it };
    // SAFETY: `pval` is a live slot per the caller's contract.
    let value_is_null = unsafe { *pval }.is_null();
    if it.itype != ASN1_ITYPE_PRIMITIVE && value_is_null {
        return 0;
    }
    if it.itype == ASN1_ITYPE_MSTRING {
        if tag != -1 {
            // The authority's own comment: it never makes sense for a multi-string
            // to be implicitly tagged, so this is a template error rather than a
            // caller error.
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_ENC_112) };
            return -1;
        }
        // SAFETY: the caller's contract passes through unchanged.
        return unsafe { i2d_ex_primitive(pval, out, it, -1, aclass) };
    }
    debug_assert!(
        it.itype == ASN1_ITYPE_PRIMITIVE && it.templates.is_null(),
        "item dispatch beyond the primitive and MSTRING arms is subphase 5.4"
    );
    if it.itype != ASN1_ITYPE_PRIMITIVE || !it.templates.is_null() {
        // Unreachable by construction; failing closed rather than answering.
        return 0;
    }
    // SAFETY: the caller's contract passes through unchanged.
    unsafe { i2d_ex_primitive(pval, out, it, tag, aclass) }
}

/// `asn1_i2d_ex_primitive` — size the content, write the header, write the content.
///
/// # Safety
///
/// As [`ex_i2d`]. When `out` is non-null and `*out` is non-null, the buffer it
/// points at must have room for the whole encoding.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's `pval` contract
unsafe fn i2d_ex_primitive(
    pval: *const *const Asn1String,
    out: *mut *mut c_uchar,
    it: &Asn1Item,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    let mut utype = it.utype as c_int;

    // First pass: size only, and let the codec tell us the real underlying type.
    // SAFETY: the caller's contract; a null destination is the authority's own
    // sizing convention.
    let sized = unsafe { ex_i2c(pval, core::ptr::null_mut(), &mut utype, it) };

    // The `usetag` decision is made *after* the sizing pass, because the codec is
    // what may have changed `utype`.
    let usetag = !matches!(utype, V_ASN1_SEQUENCE | V_ASN1_SET | V_ASN1_OTHER);

    // `-1` means the value is absent and its type must not appear at all.
    if sized == -1 {
        return 0;
    }
    // `-2` means "indefinite length constructed": no content length, and a
    // two-byte end-of-contents marker instead.
    let ndef = if sized == -2 { 2 } else { 0 };
    let len = if sized == -2 { 0 } else { sized };

    // An implicitly tagged caller supplies its own tag; otherwise the tag is the
    // underlying type's.
    let tag = if tag == -1 { utype } else { tag };

    if !out.is_null() {
        if usetag {
            // SAFETY: `out` is a live slot and the caller guarantees room for the
            // header.
            unsafe { crate::asn1::der::ASN1_put_object(out, ndef, len, tag, aclass) };
        }
        // SAFETY: `*out` has room for `len` content bytes, and this is the pass
        // that writes them.
        unsafe { ex_i2c(pval, *out, &mut utype, it) };
        if ndef != 0 {
            // SAFETY: `out` is a live slot with room for the two-byte marker.
            unsafe { crate::asn1::der::ASN1_put_eoc(out) };
        } else {
            // SAFETY: the caller's slot is writable.
            unsafe { *out = (*out).add(len.max(0) as usize) };
        }
    }

    if usetag {
        return crate::asn1::der::ASN1_object_size(ndef, len, tag);
    }
    len
}

/// `asn1_ex_i2c` — produce the content octets from a value.
///
/// Returns the content length, `-1` for "omit the type", or `-2` for "use
/// indefinite length".
///
/// # Safety
///
/// As [`ex_i2d`]. `cout` must be null or writable for the content length; `putype`
/// must be a live slot holding the item's `utype` on entry.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's `pval` contract
unsafe fn ex_i2c(
    pval: *const *const Asn1String,
    cout: *mut c_uchar,
    putype: *mut c_int,
    it: &Asn1Item,
) -> c_int {
    // A caller's primitive hooks own the whole conversion, including any change to
    // `*putype`. No item this stratum defines carries one — the numeric items and
    // `BIGNUM_it` are subphase 5.4 — but a caller can build such an item itself.
    let pf = it.funcs.cast::<Asn1PrimitiveFuncs>();
    if !pf.is_null() {
        // SAFETY: for a PRIMITIVE item the authority's own cast reads `funcs` as an
        // `ASN1_PRIMITIVE_FUNCS *`.
        let pf = unsafe { &*pf };
        if let Some(prim_i2c) = pf.prim_i2c {
            // SAFETY: the hook is the caller's, with the authority's signature.
            return unsafe { prim_i2c(pval.cast(), cout, putype, it) };
        }
    }

    // "Should the type be omitted?" A null value means an absent optional field,
    // except for a `BOOLEAN` item, whose value is stored in the slot itself and for
    // which a null slot is a legal `false`.
    if it.itype != ASN1_ITYPE_PRIMITIVE || it.utype != c_long::from(V_ASN1_BOOLEAN) {
        // SAFETY: `pval` is a live slot.
        if unsafe { *pval }.is_null() {
            return -1;
        }
    }

    let utype: c_int;
    if it.itype == ASN1_ITYPE_MSTRING {
        // A multi-string's type is a property of the value, not of the item, which
        // is the whole point of the item type.
        // SAFETY: the value is non-null, checked above.
        utype = unsafe { (*(*pval)).type_ };
        // SAFETY: `putype` is the caller's live slot.
        unsafe { *putype = utype };
    } else if it.utype == c_long::from(V_ASN1_ANY) {
        // `ASN1_ANY` takes its type from the `ASN1_TYPE` and re-points `pval` into
        // the union: subphase 5.7, and unreachable from the items this stratum
        // defines other than `ASN1_ANY_it`, whose only consumer is
        // `ASN1_item_i2d`.
        debug_assert!(false, "V_ASN1_ANY is subphase 5.7");
        return 0;
    } else {
        // SAFETY: `putype` is the caller's live slot, seeded with the item's type.
        utype = unsafe { *putype };
    }

    // The content is described by `cont`/`len`, which the switch fills in; two arms
    // answer directly instead because their codecs are the length.
    let cont: *const u8;
    let len: c_int;
    match utype {
        V_ASN1_OBJECT => {
            // SAFETY: the value is non-null and is an `ASN1_OBJECT`.
            let otmp = unsafe { *pval }.cast::<Asn1Object>();
            // SAFETY: `otmp` is live.
            let (data, olen) = unsafe { ((*otmp).data, (*otmp).length) };
            // An object with no content has no encoding at all, which the authority
            // reports as "omit".
            if data.is_null() || olen == 0 {
                return -1;
            }
            cont = data;
            len = olen;
        }

        V_ASN1_UNDEF => {
            // `V_ASN1_UNDEF` is how a `CHOICE` records "no alternative selected",
            // and it encodes as an indefinite-length empty rather than as bytes.
            return -2;
        }

        V_ASN1_NULL => {
            // A `NULL` has no content and a zero length; the header carries all of
            // it.
            cont = core::ptr::null();
            len = 0;
        }

        V_ASN1_BOOLEAN => {
            // The value lives in the slot itself: `tbool = (ASN1_BOOLEAN *)pval`.
            // Only the low four bytes are read, which is why a caller must pass the
            // boolean as the pointer's own bits rather than as a pointee.
            let tbool = pval as *const c_int;
            // SAFETY: `pval` points at a slot at least `size_of::<c_int>()` bytes
            // wide, because it holds a pointer.
            let value = unsafe { *tbool };
            if value == -1 {
                // `-1` is the "absent" marker `ASN1_TYPE_free` writes back.
                return -1;
            }
            if it.utype != c_long::from(V_ASN1_ANY) {
                // A default: a `TRUE` value for an item whose default is `TRUE`
                // (`ASN1_TBOOLEAN`) and a `FALSE` for one whose default is `FALSE`
                // (`ASN1_FBOOLEAN`) are both omitted.
                if value != 0 && it.size > 0 {
                    return -1;
                }
                if value == 0 && it.size == 0 {
                    return -1;
                }
            }
            // The single content octet, by address: it lives in this frame's local,
            // and `cont` is copied out before the frame ends.
            let c = [value as u8];
            // SAFETY: `c` is a live local array of one byte.
            if cout.is_null() {
                return 1;
            }
            // SAFETY: `cout` is writable for the one byte returned.
            unsafe { *cout = c[0] };
            return 1;
        }

        V_ASN1_BIT_STRING => {
            // The bit-string codec *is* the length: its return value is the content
            // length, and it writes when given a destination. The extra indirection
            // the authority writes as `cout ? &cout : NULL` is a local holding the
            // destination.
            let mut slot = cout;
            // SAFETY: the value is non-null (or this is a legal `BOOLEAN` case,
            // which this arm is not) and is a bit string.
            return unsafe {
                ossl_i2c_ASN1_BIT_STRING(
                    (*pval).cast_mut(),
                    if cout.is_null() {
                        core::ptr::null_mut()
                    } else {
                        &mut slot
                    },
                )
            };
        }

        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            // As the bit string: the integer codec returns the content length.
            let mut slot = cout;
            // SAFETY: the value is non-null and is an integer.
            return unsafe {
                ossl_i2c_ASN1_INTEGER(
                    (*pval).cast_mut(),
                    if cout.is_null() {
                        core::ptr::null_mut()
                    } else {
                        &mut slot
                    },
                )
            };
        }

        _ => {
            // Everything else is `ASN1_STRING`-based and handled the same way:
            // `OCTET STRING`, the string types, `OTHER`, `SET` and `SEQUENCE`.
            // The authority casts the const value away to write the destination
            // into the string, because an NDEF octet string *becomes* the
            // caller's buffer: `strtmp->data = cout; strtmp->length = 0;` are how
            // it records that the content will be written later through
            // `ASN1_STRING_set0`. The cast is confined to this arm and is only
            // taken when the caller supplied a destination.
            // SAFETY: `*pval` is non-null, checked above.
            let strtmp = unsafe { *pval }.cast_mut();
            // SAFETY: as above.
            unsafe {
                cont = (*strtmp).data;
                len = (*strtmp).length;
            }
            // An NDEF octet string hands its *destination* to the string and reports
            // indefinite length, so the caller writes the content later. That is how
            // `BIO_new_NDEF` streams a structure it has not built yet.
            // SAFETY: `strtmp` is non-null, checked above.
            if it.size == ASN1_TFLG_NDEF as c_long
                // SAFETY: `strtmp` is non-null, checked above.
                && unsafe { (*strtmp).flags } & ASN1_STRING_FLAG_NDEF != 0
            {
                if !cout.is_null() {
                    // SAFETY: `strtmp` is live and the caller allows the write,
                    // per this arm's comment.
                    unsafe {
                        (*strtmp).data = cout;
                        (*strtmp).length = 0;
                    };
                }
                return -2;
            }
        }
    }

    if !cout.is_null() && len != 0 {
        // SAFETY: `cont` is readable for `len` bytes and `cout` is writable for the
        // same, per the caller's contract and the arm that set them.
        unsafe { core::ptr::copy_nonoverlapping(cont, cout, len as usize) };
    }
    len
}
