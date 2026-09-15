//! Phase 5 — the free path: `ossl_asn1_item_embed_free` and
//! `ossl_asn1_primitive_free`, from `crypto/asn1/tasn_fre.c`.
//!
//! ## Why this exists before the template machinery does
//!
//! `asn1_item_ex_d2i_intern` — the function `ASN1_item_d2i` actually calls — ends
//! with
//!
//! ```text
//! rv = asn1_item_embed_d2i(pval, in, len, it, tag, aclass, opt, ctx, 0, ...);
//! if (rv <= 0)
//!     ASN1_item_ex_free(pval, it);
//! return rv;
//! ```
//!
//! so **a failed decode frees the caller's value and nulls the caller's slot**. That
//! is not a detail of the failure path: it is the ownership contract. A failed
//! `d2i_ASN1_OCTET_STRING(&existing, ...)` destroys `existing`, and the caller's
//! pointer is null afterwards rather than pointing at a half-filled object. The
//! `RT-ASN1` court found this the first time a decode was asked to reuse a string
//! and fail: the candidate left the slot alone and the authority did not.
//!
//! It also explains a shape in `asn1_ex_c2i` that looks redundant: its string arm
//! frees the value *and* writes `*pval = NULL` on an allocation failure, when the
//! item layer is about to call this module anyway. Writing the null first is what
//! stops this module freeing the same string twice.
//!
//! ## What is here, and what is 5.4's
//!
//! The reachable arms of a free of a `PRIMITIVE`-without-templates or `MSTRING`
//! item. `CHOICE`, `EXTERN`, `SEQUENCE` and `NDEF_SEQUENCE` need the template
//! machinery and `ossl_asn1_do_lock`, and the `ASN1_TYPE` arm of
//! `ossl_asn1_primitive_free` needs the type/value union to be understood — both are
//! asserted rather than guessed at.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::string_embed_free;
use crate::runtime::obj::Asn1Object;

/// `ossl_asn1_primitive_free` — release a primitive value and clear the slot.
///
/// The `BOOLEAN` arm is the one that surprises: a `BOOLEAN`'s value lives in the
/// slot itself, and freeing one writes the item's `size` — its *default* — back
/// into the slot rather than clearing it. So a freed `ASN1_TBOOLEAN` reads as
/// `TRUE`, and a freed `ASN1_FBOOLEAN` as `FALSE`. That is why the arm returns
/// early instead of falling through to the `*pval = NULL` at the bottom.
///
/// # Safety
///
/// `pval` must be a live slot. `it` must be null or a live item. When `it` is null
/// the value must be a live `ASN1_TYPE`, whose reachable arm is subphase 5.7.
pub(crate) unsafe fn primitive_free(pval: *mut *mut c_void, it: *const Asn1Item, embed: c_int) {
    // A caller's hooks own the whole release, including leaving the slot alone.
    if !it.is_null() {
        // SAFETY: for a `PRIMITIVE` item the authority's own cast reads `funcs` as
        // an `ASN1_PRIMITIVE_FUNCS *`.
        let pf = unsafe { (*it).funcs.cast::<Asn1PrimitiveFuncs>() };
        if !pf.is_null() {
            // SAFETY: `pf` is the item's own block.
            let pf = unsafe { &*pf };
            if embed != 0 {
                if let Some(prim_clear) = pf.prim_clear {
                    // SAFETY: the hook is the item's, with the authority's
                    // signature.
                    unsafe { prim_clear(pval, it) };
                    return;
                }
            } else if let Some(prim_free) = pf.prim_free {
                // SAFETY: as above.
                unsafe { prim_free(pval, it) };
                return;
            }
        }
    }

    if it.is_null() {
        // The `ASN1_TYPE` arm reads the selector out of the type and then reaches
        // through the union: subphase 5.7, where `ASN1_TYPE` is implemented.
        debug_assert!(
            false,
            "the ASN1_TYPE arm of ossl_asn1_primitive_free is subphase 5.7"
        );
        return;
    }
    // SAFETY: `it` is non-null.
    let item = unsafe { &*it };
    // SAFETY: `pval` is a live slot.
    let value = unsafe { *pval };

    let utype: c_int;
    if item.itype == ASN1_ITYPE_MSTRING {
        // A multi-string's value is an `ASN1_STRING` whatever its type, and the
        // authority encodes that as `utype = -1`, which the match below sends to
        // the string arm.
        utype = V_ASN1_UNDEF;
        if value.is_null() {
            return;
        }
    } else {
        utype = item.utype as c_int;
        // The `BOOLEAN` exception again: its value is in the slot, so a null slot
        // is a legal value rather than an empty one.
        if utype != V_ASN1_BOOLEAN && value.is_null() {
            return;
        }
    }

    match utype {
        V_ASN1_OBJECT => {
            // SAFETY: the value is an `ASN1_OBJECT`, which is its own reference-
            // counted type.
            unsafe { ASN1_OBJECT_free(value.cast::<Asn1Object>()) };
        }
        V_ASN1_BOOLEAN => {
            // SAFETY: `pval` is at least `size_of::<c_int>()` bytes wide, because
            // it holds a pointer. The truncation from `long` is the authority's.
            unsafe { *(pval as *mut c_int) = item.size as c_int };
            return;
        }
        V_ASN1_NULL => {
            // Nothing is behind the sentinel, so there is nothing to release — but
            // the slot is still cleared below.
        }
        V_ASN1_ANY => {
            // Needs the `ASN1_TYPE` union arm: subphase 5.7.
            debug_assert!(false, "the V_ASN1_ANY arm of the free path is subphase 5.7");
            return;
        }
        _ => {
            // Everything else is `ASN1_STRING`-based: the string types, the
            // integer family, `OBJECT`'s siblings, `SET`, `SEQUENCE` and the
            // `V_ASN1_UNDEF` a MSTRING uses.
            // SAFETY: the value is an `ASN1_STRING`-based object.
            unsafe { string_embed_free(value.cast::<Asn1String>(), embed) };
        }
    }
    // SAFETY: the caller's slot is writable.
    unsafe { *pval = core::ptr::null_mut() };
}

/// `ossl_asn1_item_embed_free`, restricted to the `PRIMITIVE`-without-templates and
/// `MSTRING` arms.
///
/// The first guard is asymmetric in the authority and stays so here: a
/// non-primitive item with a null value returns immediately, while a primitive one
/// does not, because a primitive's value may live in the slot.
///
/// # Safety
///
/// `pval` must be a live slot. `it` must be a live item of one of the two admitted
/// shapes.
pub(crate) unsafe fn item_embed_free(pval: *mut *mut c_void, it: *const Asn1Item, embed: c_int) {
    if pval.is_null() {
        return;
    }
    // The authority dereferences `it` immediately (`const ASN1_AUX *aux =
    // it->funcs`), so a null item faults there. Returning instead is the
    // documented divergence (docs/SECURITY_DIVERGENCE_POLICY.md).
    if it.is_null() {
        return;
    }
    // SAFETY: `it` is non-null.
    let item = unsafe { &*it };
    // SAFETY: `pval` is a live slot.
    let value = unsafe { *pval };
    if item.itype != ASN1_ITYPE_PRIMITIVE && value.is_null() {
        return;
    }
    debug_assert!(
        item.itype == ASN1_ITYPE_PRIMITIVE || item.itype == ASN1_ITYPE_MSTRING,
        "item free beyond the primitive and MSTRING arms is subphase 5.4"
    );
    if item.itype != ASN1_ITYPE_PRIMITIVE && item.itype != ASN1_ITYPE_MSTRING {
        return;
    }
    if item.itype == ASN1_ITYPE_PRIMITIVE && !item.templates.is_null() {
        debug_assert!(
            false,
            "a template-bearing primitive item's free is subphase 5.4"
        );
        return;
    }
    // SAFETY: the caller's contract, and the arm checks above.
    unsafe { primitive_free(pval, it, embed) };
}

/// `ASN1_item_ex_free` — release a value through its item.
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live value of the item's type; `it`
/// must be a live item of one of the two shapes [`item_embed_free`] admits.
pub(crate) unsafe fn item_ex_free(pval: *mut *mut Asn1String, it: *const Asn1Item) {
    // SAFETY: an `ASN1_VALUE **` and a string slot have the same representation,
    // and the caller's contract covers both readings.
    unsafe { item_embed_free(pval.cast::<*mut c_void>(), it, 0) };
}
