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

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::bitstr::ossl_i2c_ASN1_BIT_STRING;
use crate::asn1::layout::*;
use crate::asn1::prim::ossl_i2c_ASN1_INTEGER;
use crate::asn1::utl;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_set, OPENSSL_sk_value, OpenSslStack};

/// The authority translation unit for the encoder these functions reproduce.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_enc.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `asn1_item_flags_i2d` — the shared body of `ASN1_item_i2d` and
/// `ASN1_item_ndef_i2d`.
///
/// The three output conventions are handled here and nowhere else. Note that the
/// allocation path runs the encoder twice: once to size it against a null
/// destination, and once to fill the buffer. The buffer's size is exactly the
/// length the first pass reported, so a content codec whose two passes disagree
/// would overflow it — which is why the authority's codecs return the length
/// rather than writing and reporting.
///
/// `flags` is the only difference between the two public entry points: `NDEF` asks
/// for indefinite-length constructed encoding wherever a template allows it.
///
/// # Safety
///
/// `val` must be null or a live value of the item's type. `out` must be null or
/// point to a slot holding null or a pointer with room for the encoding; `it` must
/// be a live item.
unsafe fn item_flags_i2d(
    val: *const Asn1String,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's slot is readable when `out` is non-null.
    if !out.is_null() && unsafe { *out }.is_null() {
        let v = val;
        // SAFETY: `v` is a live slot holding the caller's value; `it` is the
        // caller's item.
        let len = unsafe { item_ex_i2d(&v, core::ptr::null_mut(), it, -1, flags) };
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
        unsafe { item_ex_i2d(&v, &mut p, it, -1, flags) };
        // SAFETY: the caller's slot is writable and now owns `buf`.
        unsafe { *out = buf };
        return len;
    }
    let v = val;
    // SAFETY: `v` is a live slot; `out` is the caller's, possibly null.
    unsafe { item_ex_i2d(&v, out, it, -1, flags) }
}

/// `int ASN1_item_i2d(const ASN1_VALUE *val, unsigned char **out,
/// const ASN1_ITEM *it)`
///
/// # Safety
///
/// As [`item_flags_i2d`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_i2d(
    val: *const c_void,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
) -> c_int {
    // `0` is the no-unwind answer, and it is the same value the item layer already
    // returns for a value that is absent rather than malformed.
    guard_ffi(0, || {
        // SAFETY: the caller's contract.
        unsafe { item_flags_i2d(val.cast::<Asn1String>(), out, it, 0) }
    })
}

/// `int ASN1_item_ndef_i2d(const ASN1_VALUE *val, unsigned char **out,
/// const ASN1_ITEM *it)`
///
/// The indefinite-length variant: a template that carries `ASN1_TFLG_NDEF` and is
/// told to use it encodes with an end-of-contents marker instead of a length.
///
/// # Safety
///
/// As [`item_flags_i2d`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ndef_i2d(
    val: *const c_void,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract.
        unsafe { item_flags_i2d(val.cast::<Asn1String>(), out, it, ASN1_TFLG_NDEF as c_int) }
    })
}

/// `int ASN1_item_ex_i2d(const ASN1_VALUE **pval, unsigned char **out,
/// const ASN1_ITEM *it, int tag, int aclass)`
///
/// # Safety
///
/// As [`item_ex_i2d`].
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ex_i2d(
    pval: *mut *const c_void,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
    tag: c_int,
    aclass: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller's contract.
        unsafe { item_ex_i2d(pval.cast::<*const Asn1String>(), out, it, tag, aclass) }
    })
}

/// `ASN1_item_i2d`'s internal form, for this crate's own callers.
///
/// # Safety
///
/// As [`item_flags_i2d`].
pub(crate) unsafe fn item_i2d(
    val: *const Asn1String,
    out: *mut *mut c_uchar,
    it: *const Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract passes through unchanged.
    unsafe { item_flags_i2d(val, out, it, 0) }
}

/// `ASN1_item_ex_i2d` — the encoder's item dispatch, in full.
///
/// The `PRIMITIVE` guard runs *before* anything dereferences `*pval`, and it is not
/// symmetric: it skips the check only for a primitive item, because a primitive's
/// value lives in the slot rather than through it — a `BOOLEAN` item's value *is*
/// the slot's low four bytes.
///
/// The `SEQUENCE` arm encodes in two passes over the templates, and the cached-encoding
/// check comes first: a structure that was decoded and not touched answers the bytes it
/// arrived with rather than a re-derivation, which is how a signature over a
/// non-canonical encoding survives a round trip.
///
/// # Safety
///
/// `pval` must point to a live slot. `out` must be null or point to a slot with
/// room; `it` must be a live item.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's `pval` contract
unsafe fn item_ex_i2d(
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
    let aux = it.funcs.cast::<Asn1Aux>();
    // The const view of the caller's slot, which is what every helper below and the
    // caller's own hooks take.
    let cv = pval.cast::<*const c_void>();

    match it.itype {
        ASN1_ITYPE_PRIMITIVE => {
            if !it.templates.is_null() {
                // A primitive *item* with a template is how an item-level tag is
                // spelled; the flags travel in the template, which is why the
                // decoder refuses tag and OPTIONAL here.
                // SAFETY: the caller's contract.
                return unsafe { template_ex_i2d(pval, out, it.templates, tag, aclass) };
            }
            // SAFETY: the caller's contract.
            unsafe { i2d_ex_primitive(pval, out, it, tag, aclass) }
        }

        ASN1_ITYPE_MSTRING => {
            if tag != -1 {
                // The authority's own comment: it never makes sense for a multi-string
                // to be implicitly tagged, so this is a template error rather than a
                // caller error.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_ENC_112) };
                return -1;
            }
            // SAFETY: the caller's contract passes through unchanged.
            unsafe { i2d_ex_primitive(pval, out, it, -1, aclass) }
        }

        ASN1_ITYPE_CHOICE => {
            if tag != -1 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_ENC_123) };
                return -1;
            }
            let cb = aux_const_cb(aux);
            if let Some(cb) = cb {
                // SAFETY: the callback is the caller's, with the authority's signature.
                if unsafe { cb(ASN1_OP_I2D_PRE, cv, it, core::ptr::null_mut()) } == 0 {
                    return 0;
                }
            }
            // SAFETY: `pval` is a live slot holding a `CHOICE` value.
            let i = unsafe { utl::get_choice_selector_const(cv, it) };
            if i >= 0 && c_long::from(i) < it.tcount {
                // SAFETY: `i` indexes the item's own template array.
                let chtt = unsafe { it.templates.add(i as usize) };
                // SAFETY: `chtt` is live and `*pval` is the enclosing value.
                let pchval = unsafe { utl::get_const_field_ptr(cv, &*chtt) };
                // SAFETY: the field's own template governs it.
                return unsafe {
                    template_ex_i2d(pchval.cast::<*const Asn1String>(), out, chtt, -1, aclass)
                };
            }
            // A selector outside the template array is not an error the authority
            // reports: it falls through to the post callback and answers 0.
            if let Some(cb) = cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_I2D_POST, cv, it, core::ptr::null_mut()) } == 0 {
                    return 0;
                }
            }
            0
        }

        ASN1_ITYPE_EXTERN => {
            let ef = it.funcs.cast::<Asn1ExternFuncs>();
            if ef.is_null() {
                return 0;
            }
            // SAFETY: for an `EXTERN` item `funcs` is its `ASN1_EXTERN_FUNCS`.
            let ef = unsafe { &*ef };
            match ef.asn1_ex_i2d {
                // SAFETY: the hook is the caller's, with the authority's signature.
                Some(f) => unsafe { f(cv, out, it, tag, aclass) },
                None => 0,
            }
        }

        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            // Only the `NDEF` item type turns an `NDEF` request into an actual
            // indefinite-length encoding.
            let ndef =
                if it.itype == ASN1_ITYPE_NDEF_SEQUENCE && aclass & ASN1_TFLG_NDEF as c_int != 0 {
                    2
                } else {
                    1
                };

            let mut seqcontlen: c_int = 0;
            // SAFETY: `cv` is a live slot holding a live value of the item's type.
            let restored = unsafe { utl::enc_restore(&mut seqcontlen, out, cv, it) };
            if restored < 0 {
                return 0;
            }
            if restored > 0 {
                return seqcontlen;
            }
            seqcontlen = 0;

            let mut tag = tag;
            let mut aclass = aclass;
            if tag == -1 {
                tag = V_ASN1_SEQUENCE;
                // Any other flags in `aclass` are retained.
                aclass = (aclass & !(ASN1_TFLG_TAG_CLASS as c_int)) | V_ASN1_UNIVERSAL;
            }
            let cb = aux_const_cb(aux);
            if let Some(cb) = cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_I2D_PRE, cv, it, core::ptr::null_mut()) } == 0 {
                    return 0;
                }
            }

            // First pass: the content length, with a null destination.
            let mut i: c_long = 0;
            let mut tt = it.templates;
            while i < it.tcount {
                // SAFETY: `*cv` is a live value of the item's type.
                let seqtt = unsafe { utl::do_adb(*cv, tt, 1) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: `seqtt` is live and `*cv` is the enclosing value.
                let pseqval = unsafe { utl::get_const_field_ptr(cv, &*seqtt) };
                // SAFETY: the field's own template governs it.
                let tmplen = unsafe {
                    template_ex_i2d(
                        pseqval.cast::<*const Asn1String>(),
                        core::ptr::null_mut(),
                        seqtt,
                        -1,
                        aclass,
                    )
                };
                if tmplen == -1 || tmplen > c_int::MAX - seqcontlen {
                    return -1;
                }
                seqcontlen += tmplen;
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }

            let seqlen = crate::asn1::der::ASN1_object_size(ndef, seqcontlen, tag);
            if out.is_null() || seqlen == -1 {
                return seqlen;
            }
            // SAFETY: `out` is a live slot with room for the header.
            unsafe { crate::asn1::der::ASN1_put_object(out, ndef, seqcontlen, tag, aclass) };

            // Second pass: the fields themselves.
            i = 0;
            tt = it.templates;
            while i < it.tcount {
                // SAFETY: `*cv` is a live value of the item's type.
                let seqtt = unsafe { utl::do_adb(*cv, tt, 1) };
                if seqtt.is_null() {
                    return 0;
                }
                // SAFETY: `seqtt` is live and `*cv` is the enclosing value.
                let pseqval = unsafe { utl::get_const_field_ptr(cv, &*seqtt) };
                // The authority's own `FIXME` sits here: this pass does not check for
                // errors, because the sizing pass above has already established that the
                // content fits.
                // SAFETY: the field's own template governs it.
                unsafe {
                    template_ex_i2d(pseqval.cast::<*const Asn1String>(), out, seqtt, -1, aclass)
                };
                // SAFETY: still inside the item's template array.
                tt = unsafe { tt.add(1) };
                i += 1;
            }
            if ndef == 2 {
                // SAFETY: `out` is a live slot with room for the two-byte marker.
                unsafe { crate::asn1::der::ASN1_put_eoc(out) };
            }
            if let Some(cb) = cb {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_I2D_POST, cv, it, core::ptr::null_mut()) } == 0 {
                    return 0;
                }
            }
            seqlen
        }

        _ => 0,
    }
}

/// `ASN1_AUX`'s encoder callback, as the const-correct shape.
///
/// The two callback shapes differ only in the constness of the value pointer, which
/// the authority casts away when `ASN1_AFLG_CONST_CB` is clear; the transmute below is
/// that cast, spelled in the one place it is needed.
fn aux_const_cb(aux: *const Asn1Aux) -> Option<Asn1AuxConstCb> {
    if aux.is_null() {
        return None;
    }
    // SAFETY: the caller established `aux` is the item's own block or null.
    let aux = unsafe { &*aux };
    if aux.flags & ASN1_AFLG_CONST_CB != 0 {
        aux.asn1_const_cb
    } else {
        // SAFETY: the two function-pointer types have the same representation, and the
        // authority itself reinterprets one as the other.
        aux.asn1_cb
            .map(|f| unsafe { core::mem::transmute::<Asn1AuxCb, Asn1AuxConstCb>(f) })
    }
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
    // Rebound because the `ANY` arm below redirects it into the type's union.
    let mut pval = pval;
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
        // The `ASN1_TYPE` carries the type and the value is the union member beside
        // it, so the selector is read from the structure and `pval` is redirected
        // into the union. From here down the arm below sees only the payload.
        // SAFETY: the value is non-null, checked above, and is an `ASN1_TYPE`.
        let typ = unsafe { *pval }.cast::<Asn1Type>();
        // SAFETY: `typ` is live.
        utype = unsafe { (*typ).type_ };
        // SAFETY: `putype` is the caller's live slot.
        unsafe { *putype = utype };
        // SAFETY: `typ` is live; the union's `ptr` member is the value slot.
        pval = unsafe { core::ptr::addr_of!((*typ).value.ptr) }.cast::<*const Asn1String>();
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

/// `asn1_template_ex_i2d` — a field's tags, `SET OF`/`SEQUENCE OF`, and the
/// embedded-field indirection.
///
/// The tag to use comes from the template **or** the arguments, never both: a template
/// that asks for a tag and a caller that supplies one is a template error rather than a
/// case to resolve, which is why the first branch answers `-1` instead of choosing.
///
/// # Safety
///
/// `pval` must be a live field slot; `out` must be null or point to a slot with room;
/// `tt` must be a live template.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's `pval` contract
unsafe fn template_ex_i2d(
    pval: *const *const Asn1String,
    out: *mut *mut c_uchar,
    tt: *const Asn1Template,
    tag: c_int,
    iclass: c_int,
) -> c_int {
    if tt.is_null() {
        return 0;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    let flags = t.flags;

    // An embedded field's value *is* the field's storage, so the address of the caller's
    // slot stands in for it: `tval` holds it and the encode reads through `&tval`.
    let tval: *const c_void = pval as *const c_void;
    let pval = if flags & ASN1_TFLG_EMBED != 0 {
        &tval as *const *const c_void
    } else {
        pval.cast::<*const c_void>()
    };

    // The tag and class to use. A template tag and an argument tag cannot both be
    // present: the template's flags cannot be reconciled with the caller's intent, and
    // the authority answers -1 rather than guessing.
    let (ttag, tclass) = if flags & ASN1_TFLG_TAG_MASK != 0 {
        if tag != -1 {
            return -1;
        }
        (t.tag as c_int, (flags & ASN1_TFLG_TAG_CLASS) as c_int)
    } else if tag != -1 {
        (tag, iclass & (ASN1_TFLG_TAG_CLASS as c_int))
    } else {
        (-1, 0)
    };
    let iclass = iclass & !(ASN1_TFLG_TAG_CLASS as c_int);

    // Indefinite length needs *both* the template and the caller to ask for it, which is
    // how `ASN1_item_ndef_i2d` reaches a template that was written to allow it.
    let ndef = if flags & ASN1_TFLG_NDEF != 0 && iclass & ASN1_TFLG_NDEF as c_int != 0 {
        2
    } else {
        1
    };

    // SAFETY: `t.item` is the field's `ASN1_ITEM_EXP`.
    let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
    if sub.is_null() {
        return 0;
    }

    if flags & ASN1_TFLG_SK_MASK != 0 {
        // `SET OF` and `SEQUENCE OF` are a constructed tag whose *content* is a
        // repetition of one element.
        // SAFETY: for a `SK_MASK` field the slot holds the stack.
        let sk = unsafe { *pval } as *mut OpenSslStack;
        if sk.is_null() {
            return 0;
        }
        // `isset` is 1 for `SET OF`, 2 for `SET OF` with `SET_ORDER` — and 2 means the
        // stack itself is reordered to match the emitted order, which is observable to
        // the caller afterwards.
        let isset = if flags & ASN1_TFLG_SET_OF != 0 {
            if flags & ASN1_TFLG_SEQUENCE_OF != 0 {
                2
            } else {
                1
            }
        } else {
            0
        };
        // An explicit or absent tag means the inner tag is the underlying one.
        let (sktag, skaclass) = if ttag != -1 && flags & ASN1_TFLG_EXPTAG == 0 {
            (ttag, tclass)
        } else if isset != 0 {
            (V_ASN1_SET, V_ASN1_UNIVERSAL)
        } else {
            (V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)
        };

        // SAFETY: `sk` is the caller's live stack.
        let n = unsafe { OPENSSL_sk_num(sk) };
        let mut skcontlen: c_int = 0;
        let mut i: c_int = 0;
        while i < n {
            // SAFETY: `i` indexes the caller's stack.
            let skitem = unsafe { OPENSSL_sk_value(sk, i) } as *const Asn1String;
            // SAFETY: the element's item is the template's own.
            let len = unsafe { item_ex_i2d(&skitem, core::ptr::null_mut(), sub, -1, iclass) };
            if len == -1 || skcontlen > c_int::MAX - len {
                return -1;
            }
            if len == 0 && t.flags & ASN1_TFLG_OPTIONAL == 0 {
                // An element that encodes to nothing would make the `OF` unreadable, so
                // it is rejected unless the field was declared OPTIONAL.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_ENC_309) };
                return -1;
            }
            skcontlen += len;
            i += 1;
        }
        let sklen = crate::asn1::der::ASN1_object_size(ndef, skcontlen, sktag);
        if sklen == -1 {
            return -1;
        }
        let ret = if flags & ASN1_TFLG_EXPTAG != 0 {
            crate::asn1::der::ASN1_object_size(ndef, sklen, ttag)
        } else {
            sklen
        };
        if out.is_null() || ret == -1 {
            return ret;
        }

        if flags & ASN1_TFLG_EXPTAG != 0 {
            // SAFETY: `out` is a live slot with room for the header.
            unsafe { crate::asn1::der::ASN1_put_object(out, ndef, sklen, ttag, tclass) };
        }
        // SAFETY: as above.
        unsafe { crate::asn1::der::ASN1_put_object(out, ndef, skcontlen, sktag, skaclass) };
        // SAFETY: `out` is a live slot with room for the content.
        unsafe { set_seq_out(sk, out, skcontlen, sub, isset, iclass) };
        if ndef == 2 {
            // SAFETY: `out` is a live slot with room for each two-byte marker.
            unsafe {
                crate::asn1::der::ASN1_put_eoc(out);
                if flags & ASN1_TFLG_EXPTAG != 0 {
                    crate::asn1::der::ASN1_put_eoc(out);
                }
            }
        }
        return ret;
    }

    if flags & ASN1_TFLG_EXPTAG != 0 {
        // An explicit tag wraps the field in a constructed value of its own, so the
        // field is sized and written on its own before the wrapper's header is emitted.
        // SAFETY: the caller's contract.
        let i = unsafe {
            item_ex_i2d(
                pval.cast::<*const Asn1String>(),
                core::ptr::null_mut(),
                sub,
                -1,
                iclass,
            )
        };
        if i == 0 {
            if t.flags & ASN1_TFLG_OPTIONAL == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_ENC_350) };
                return -1;
            }
            return 0;
        }
        let ret = crate::asn1::der::ASN1_object_size(ndef, i, ttag);
        if !out.is_null() && ret != -1 {
            // SAFETY: `out` is a live slot with room for a header and the field.
            unsafe {
                crate::asn1::der::ASN1_put_object(out, ndef, i, ttag, tclass);
                item_ex_i2d(pval.cast::<*const Asn1String>(), out, sub, -1, iclass);
                if ndef == 2 {
                    crate::asn1::der::ASN1_put_eoc(out);
                }
            }
        }
        return ret;
    }

    // Either no tagging or IMPLICIT tagging: the class and the caller's flags combine
    // into the `aclass` the item layer is handed.
    // SAFETY: the caller's contract.
    let len = unsafe {
        item_ex_i2d(
            pval.cast::<*const Asn1String>(),
            out,
            sub,
            ttag,
            tclass | iclass,
        )
    };
    if len == 0 && t.flags & ASN1_TFLG_OPTIONAL == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::TASN_ENC_371) };
        return -1;
    }
    len
}

/// One element's DER encoding, held while a `SET OF` is put in canonical order.
struct DerEnc {
    /// Where the encoding starts.
    data: *mut c_uchar,
    /// How long it is.
    length: c_int,
    /// The value it came from, so the stack can be reordered to match.
    field: *const c_void,
}

/// `der_cmp` — the overlapping-prefix byte comparison, then shorter-first.
///
/// This is `memcmp` over the common prefix, then the length difference, which is the
/// canonical `SET OF` order rather than a lexicographic one.
fn der_cmp(a: &DerEnc, b: &DerEnc) -> core::cmp::Ordering {
    let cmplen = if a.length < b.length {
        a.length
    } else {
        b.length
    };
    let n = cmplen.max(0) as usize;
    // SAFETY: both encodings are live for at least `cmplen` bytes, and a zero-length
    // slice of a possibly-null pointer is allowed.
    let ord = unsafe {
        core::slice::from_raw_parts(a.data, n).cmp(core::slice::from_raw_parts(b.data, n))
    };
    if ord != core::cmp::Ordering::Equal {
        return ord;
    }
    a.length.cmp(&b.length)
}

/// `asn1_set_seq_out` — the content octets of a `SET OF` or `SEQUENCE OF`.
///
/// The `do_sort` argument is three-valued: `0` writes the elements in stack order, `1`
/// sorts the *encoding* and leaves the stack alone, and `2` sorts the encoding **and**
/// reorders the stack, so a caller that keeps the stack sees the canonical order too.
///
/// The sort is a stable sort by the canonical comparator. `qsort` in the authority is not
/// specified to be stable, so for two elements whose encodings are byte-identical the
/// emitted bytes are the same either way but the resulting stack order — which only the
/// `do_sort == 2` case exposes — is tied to the original order here. That is recorded as
/// an evidence question rather than asserted as equal.
///
/// # Safety
///
/// `sk` must be a live stack of values of `item`'s type; `out` must be a live slot whose
/// pointee has room for `skcontlen` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
unsafe fn set_seq_out(
    sk: *mut OpenSslStack,
    out: *mut *mut c_uchar,
    skcontlen: c_int,
    item: *const Asn1Item,
    mut do_sort: c_int,
    iclass: c_int,
) -> c_int {
    // SAFETY: `sk` is the caller's live stack.
    let n = unsafe { OPENSSL_sk_num(sk) };
    if do_sort != 0 && n < 2 {
        // Nothing to reorder.
        do_sort = 0;
    }
    if do_sort == 0 {
        let mut i: c_int = 0;
        while i < n {
            // SAFETY: `i` indexes the caller's stack.
            let skitem = unsafe { OPENSSL_sk_value(sk, i) } as *const Asn1String;
            // SAFETY: the element's item is the caller's.
            unsafe { item_ex_i2d(&skitem, out, item, -1, iclass) };
            i += 1;
        }
        return 1;
    }

    // Each element is encoded to a scratch buffer, then the encodings are ordered and
    // emitted. The scratch buffer is sized by the caller's own measurement of the total.
    let count = n.max(0) as usize;
    // SAFETY: the caller's measurement, non-negative because it was accumulated.
    let buflen = skcontlen.max(0) as usize;
    let derlst =
        CRYPTO_malloc(count * core::mem::size_of::<DerEnc>(), FILE.as_ptr(), LINE) as *mut DerEnc;
    if derlst.is_null() {
        return 0;
    }
    let tmpdat = CRYPTO_malloc(buflen, FILE.as_ptr(), LINE) as *mut c_uchar;
    if tmpdat.is_null() {
        // SAFETY: `derlst` came from this allocator and is not owned elsewhere.
        unsafe { CRYPTO_free(derlst.cast::<c_void>(), FILE.as_ptr(), LINE) };
        return 0;
    }

    let mut p = tmpdat;
    let mut i: c_int = 0;
    while i < n {
        // SAFETY: `i` indexes the caller's stack.
        let skitem = unsafe { OPENSSL_sk_value(sk, i) } as *const Asn1String;
        let start = p;
        // SAFETY: `p` has room for the remaining elements per the caller's measurement.
        let len = unsafe { item_ex_i2d(&skitem, &mut p, item, -1, iclass) };
        // SAFETY: `i` is inside the list just allocated.
        unsafe {
            let e = derlst.add(i as usize);
            (*e).data = start;
            (*e).length = len;
            (*e).field = skitem.cast::<c_void>();
        }
        i += 1;
    }

    // SAFETY: `derlst` holds `count` initialised entries.
    let list = unsafe { core::slice::from_raw_parts_mut(derlst, count) };
    list.sort_by(der_cmp);

    // SAFETY: `out` is a live slot whose pointee has room for `skcontlen` bytes.
    let mut w = unsafe { *out };
    for e in list.iter() {
        if e.length > 0 {
            // SAFETY: the entry's encoding is live for `length` bytes, and the
            // destination has room for the total the caller measured.
            unsafe { core::ptr::copy_nonoverlapping(e.data, w, e.length as usize) };
            // SAFETY: advanced within the destination's measured extent.
            w = unsafe { w.add(e.length as usize) };
        }
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *out = w };

    if do_sort == 2 {
        // The stack is reordered to match, which is why `field` is carried beside the
        // encoding rather than the encoding alone deciding the output.
        for (k, e) in list.iter().enumerate() {
            // SAFETY: `k` indexes the caller's stack and `e.field` is the element that
            // was read from it.
            unsafe { OPENSSL_sk_set(sk, k as c_int, e.field.cast_mut().cast::<c_void>()) };
        }
    }

    // SAFETY: both buffers came from this allocator and are not owned elsewhere.
    unsafe {
        CRYPTO_free(derlst.cast::<c_void>(), FILE.as_ptr(), LINE);
        CRYPTO_free(tmpdat.cast::<c_void>(), FILE.as_ptr(), LINE);
    }
    1
}
