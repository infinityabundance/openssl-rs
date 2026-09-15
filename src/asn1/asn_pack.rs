//! Phase 5 — `asn_pack.c`: the pack/unpack pair.
//!
//! These two functions are the bridge between an encoded structure and an
//! `ASN1_STRING`, and they are what `ASN1_TYPE_pack_sequence` and
//! `ASN1_TYPE_unpack_sequence` are built from.
//!
//! `ASN1_item_pack` is where the ownership of `oct` matters. The `oct` parameter is a
//! second in/out slot with three cases, and they differ in who ends up owning the
//! string on failure: a null `oct` or a null `*oct` means this call allocates, so this
//! call releases on failure; a non-null `*oct` means the caller's string is reused — and
//! it is **not** released, because it is not this call's to release. The asymmetry is
//! the whole reason the `err:` tail tests `oct == NULL || *oct == NULL` rather than
//! simply freeing.
//!
//! The string is emptied first with `ASN1_STRING_set0(octmp, NULL, 0)`, so a reused
//! string does not accumulate and does not leak its previous content. That is also
//! what makes the `*oct` write-back below correct: the caller's string already owns the
//! buffer `ASN1_item_i2d` allocated, because the encode was asked to allocate into the
//! string's own `data` field.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_long, c_uchar, c_void};

use crate::asn1::d2i::{ASN1_item_d2i, ASN1_item_d2i_ex};
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set0};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_STRING **oct)`
///
/// Encodes `obj` through `it` into an `ASN1_STRING`. See the module documentation for
/// the ownership rule that makes the failure path asymmetric.
///
/// # Safety
///
/// `obj` must be null or a live value of `it`'s type. `it` must be a live item. `oct`
/// must be null or point to a slot holding null or a live `ASN1_STRING` owned by the
/// caller.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_pack(
    obj: *mut c_void,
    it: *const Asn1Item,
    oct: *mut *mut Asn1String,
) -> *mut Asn1String {
    guard_ffi(core::ptr::null_mut(), || {
        // The caller's slot is read only when it is non-null.
        // SAFETY: when `oct` is non-null the caller guarantees its pointee is null or
        // a live string.
        let slot_empty = oct.is_null() || unsafe { *oct }.is_null();
        let octmp: *mut Asn1String;
        if slot_empty {
            octmp = ASN1_STRING_new();
            if octmp.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::ASN_PACK_22) };
                return core::ptr::null_mut();
            }
        } else {
            // SAFETY: `slot_empty` is false, so `oct` is non-null and its pointee is
            // the caller's live string.
            octmp = unsafe { *oct };
        }

        // SAFETY: `octmp` is this call's or the caller's live string.
        unsafe { ASN1_STRING_set0(octmp, core::ptr::null_mut(), 0) };

        // The encode is asked to allocate into the string's own `data` field, which is
        // what makes the string the owner of the buffer without a copy.
        // SAFETY: `octmp` is live and `obj`/`it` are the caller's.
        let len = unsafe { ASN1_item_i2d(obj, core::ptr::addr_of_mut!((*octmp).data), it) };
        // SAFETY: `octmp` is live.
        unsafe { (*octmp).length = len };
        if len <= 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASN_PACK_32) };
            if slot_empty {
                // SAFETY: `octmp` was allocated by this call.
                unsafe { ASN1_STRING_free(octmp) };
            }
            return core::ptr::null_mut();
        }
        // SAFETY: `octmp` is live.
        if unsafe { (*octmp).data }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASN_PACK_36) };
            if slot_empty {
                // SAFETY: `octmp` was allocated by this call.
                unsafe { ASN1_STRING_free(octmp) };
            }
            return core::ptr::null_mut();
        }

        // SAFETY: when `oct` is non-null the caller guarantees its pointee is a live
        // string owned by the caller.
        if !oct.is_null() && unsafe { *oct }.is_null() {
            // SAFETY: the caller's slot is writable.
            unsafe { *oct = octmp };
        }
        octmp
    })
}

/// `void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it)`
///
/// Decodes the string's content through `it`. The decode is asked for a fresh value
/// (`a` is null), so a failure answers null and raises `ASN1_R_DECODE_ERROR` on top of
/// whatever the decoder itself raised — the two are both visible on the queue, in that
/// order.
///
/// # Safety
///
/// `oct` must be a live `ASN1_STRING`. `it` must be a live item.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_unpack(
    oct: *const Asn1String,
    it: *const Asn1Item,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `oct` is the caller's live string.
        let (data, len) = unsafe { ((*oct).data, (*oct).length) };
        let mut p: *const c_uchar = data;
        // SAFETY: `p` points to the string's content, `len` bytes of it; the item is
        // the caller's.
        let ret = unsafe { ASN1_item_d2i(core::ptr::null_mut(), &mut p, c_long::from(len), it) };
        if ret.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASN_PACK_59) };
        }
        ret
    })
}

/// `void *ASN1_item_unpack_ex(const ASN1_STRING *oct, const ASN1_ITEM *it,
/// OSSL_LIB_CTX *libctx, const char *propq)`
///
/// The library-context-carrying variant, which is what a decoder that fetches an
/// algorithm needs.
///
/// # Safety
///
/// As [`ASN1_item_unpack`]; `libctx` must be null or a live library context and
/// `propq` null or NUL-terminated, whatever the item's hooks require.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_unpack_ex(
    oct: *const Asn1String,
    it: *const Asn1Item,
    libctx: *mut c_void,
    propq: *const core::ffi::c_char,
) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `oct` is the caller's live string.
        let (data, len) = unsafe { ((*oct).data, (*oct).length) };
        let mut p: *const c_uchar = data;
        // SAFETY: `p` points to the string's content, `len` bytes of it.
        let ret = unsafe {
            ASN1_item_d2i_ex(
                core::ptr::null_mut(),
                &mut p,
                c_long::from(len),
                it,
                libctx,
                propq,
            )
        };
        if ret.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASN_PACK_73) };
        }
        ret
    })
}
