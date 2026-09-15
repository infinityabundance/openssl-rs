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
//! ## What is here
//!
//! Every arm of `ossl_asn1_item_embed_free` and `ossl_asn1_primitive_free`, including
//! the one that reads an `ASN1_TYPE`'s union when the item is null: `PRIMITIVE` with
//! and without a template, `MSTRING`, `CHOICE`, `EXTERN`, `SEQUENCE` and the bare
//! `ASN1_TYPE`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_void};

use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::string_embed_free;
use crate::asn1::utl;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::Asn1Object;

/// The authority translation unit for the free path.
///
/// It is `tasn_fre.c` and not `tasn_new.c` because the authority keeps them apart, and
/// the two raise at different coordinates: the allocator's failures come from
/// `tasn_new.c` and the free path raises nothing at all. The `file`/`line` recorded when
/// a release fails to allocate is therefore the allocator's, which is why this constant
/// is used by the frees below rather than being left out.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_fre.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

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
/// the slot must hold a live `ASN1_TYPE`.
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

    // A null item means the value is an `ASN1_TYPE`: the selector is a field of the
    // structure and the payload the union beside it, so both are re-read from the
    // value itself rather than from an item. `pval` is rebound to the union member,
    // which is what makes every arm below — including the `BOOLEAN` one, which writes
    // into the slot — operate on the right storage.
    let mut pval = pval;
    let utype: c_int;
    let value: *mut c_void;
    if it.is_null() {
        // SAFETY: the caller passes the address of an `ASN1_TYPE *` slot.
        let typ = unsafe { *pval }.cast::<Asn1Type>();
        // SAFETY: `typ` is the caller's live `ASN1_TYPE`.
        utype = unsafe { (*typ).type_ };
        // SAFETY: `typ` is live; the union's `ptr` member is the value slot.
        pval = unsafe { core::ptr::addr_of_mut!((*typ).value.ptr) };
        // SAFETY: `pval` is a live slot.
        value = unsafe { *pval };
        if value.is_null() {
            return;
        }
    } else {
        // SAFETY: `it` is non-null.
        let item = unsafe { &*it };
        // SAFETY: `pval` is a live slot.
        value = unsafe { *pval };

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
    }

    match utype {
        V_ASN1_OBJECT => {
            // SAFETY: the value is an `ASN1_OBJECT`, which is its own reference-
            // counted type.
            unsafe { ASN1_OBJECT_free(value.cast::<Asn1Object>()) };
        }
        V_ASN1_BOOLEAN => {
            // A freed item's BOOLEAN reads back as the item's own `size`, which is its
            // default; a freed bare `ASN1_TYPE` reads back as `-1`, because there is no
            // item to ask. SAFETY: `pval` is at least `size_of::<c_int>()` bytes wide,
            // because it holds a pointer. The truncation from `long` is the authority's.
            let fill = if it.is_null() {
                -1
            } else {
                // SAFETY: `it` is non-null in this arm.
                unsafe { (*it).size as c_int }
            };
            // SAFETY: as above.
            unsafe { *(pval as *mut c_int) = fill };
            return;
        }
        V_ASN1_NULL => {
            // Nothing is behind the sentinel, so there is nothing to release — but
            // the slot is still cleared below.
        }
        V_ASN1_ANY => {
            // An ANY *inside* an ANY is another `ASN1_TYPE`, released the same way; the
            // authority then frees the inner structure itself. The inner call leaves the
            // slot null on every path that reaches its bottom, so the free below is the
            // no-op it looks like — and it is written out because the authority writes it.
            // SAFETY: `pval` holds a live `ASN1_TYPE` in this arm.
            unsafe { primitive_free(pval, core::ptr::null(), 0) };
            // SAFETY: `pval` holds a pointer this crate allocated, or null.
            unsafe { CRYPTO_free(*pval, FILE.as_ptr(), LINE) };
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

/// `ossl_asn1_item_embed_free` — release a value through its item.
///
/// The first guard is asymmetric in the authority and stays so here: a
/// non-primitive item with a null value returns immediately, while a primitive one
/// does not, because a primitive's value may live in the slot.
///
/// The `SEQUENCE` arm is where the design shows: it walks the templates **in reverse**,
/// because freeing forwards would invalidate an `ANY DEFINED BY` field before the fields
/// after it could be typed, and it refuses to go past a reference count that is still
/// positive — a value another owner holds is not this caller's to release.
///
/// # Safety
///
/// `pval` must be a live slot. `it` must be a live item. When `embed` is non-zero the
/// value's storage belongs to the caller, which is why it must not be released.
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

    // The callback is only consulted by the `CHOICE` and `SEQUENCE` arms, so it is read
    // only there. The authority reads `it->funcs` as an `ASN1_AUX` for every item type,
    // including primitives whose `funcs` is an `ASN1_PRIMITIVE_FUNCS` — a read whose
    // result is never used and which would be a nonsense cast here.
    let asn1_cb = |i: &Asn1Item| -> Option<Asn1AuxCb> {
        let aux = i.funcs.cast::<Asn1Aux>();
        if aux.is_null() {
            None
        } else {
            // SAFETY: for a `CHOICE` or `SEQUENCE` item `funcs` is its `ASN1_AUX`.
            unsafe { (*aux).asn1_cb }
        }
    };

    match item.itype {
        ASN1_ITYPE_PRIMITIVE => {
            if !item.templates.is_null() {
                // SAFETY: the item's own template, and the caller's value slot.
                unsafe { template_free(pval, item.templates) };
            } else {
                // SAFETY: the caller's contract.
                unsafe { primitive_free(pval, it, embed) };
            }
        }

        ASN1_ITYPE_MSTRING => {
            // SAFETY: the caller's contract.
            unsafe { primitive_free(pval, it, embed) };
        }

        ASN1_ITYPE_CHOICE => {
            if let Some(cb) = asn1_cb(item) {
                // SAFETY: the callback is the caller's, with the authority's signature.
                if unsafe { cb(ASN1_OP_FREE_PRE, pval, it, core::ptr::null_mut()) } == 2 {
                    // "Handled": the callback owns the rest, including the value.
                    return;
                }
            }
            // SAFETY: `*pval` is a live `CHOICE` value.
            let i = unsafe { utl::get_choice_selector(pval, item) };
            if i >= 0 && c_long::from(i) < item.tcount {
                // SAFETY: `i` indexes the item's own template array.
                let tt = unsafe { item.templates.add(i as usize) };
                // SAFETY: `tt` is live and `*pval` is the enclosing value.
                let field = unsafe { utl::get_field_ptr(pval, &*tt) };
                // SAFETY: the field's own template governs it.
                unsafe { template_free(field, tt) };
            }
            if let Some(cb) = asn1_cb(item) {
                // SAFETY: the callback is the caller's.
                unsafe { cb(ASN1_OP_FREE_POST, pval, it, core::ptr::null_mut()) };
            }
            if embed == 0 {
                // SAFETY: `*pval` came from this allocator and is not reused.
                unsafe { CRYPTO_free(*pval, FILE.as_ptr(), LINE) };
                // SAFETY: the caller's slot is writable.
                unsafe { *pval = core::ptr::null_mut() };
            }
        }

        ASN1_ITYPE_EXTERN => {
            let ef = item.funcs.cast::<Asn1ExternFuncs>();
            if !ef.is_null() {
                // SAFETY: for an `EXTERN` item `funcs` is its `ASN1_EXTERN_FUNCS`.
                if let Some(free) = unsafe { (*ef).asn1_ex_free } {
                    // SAFETY: the hook is the caller's.
                    unsafe { free(pval, it) };
                }
            }
        }

        ASN1_ITYPE_NDEF_SEQUENCE | ASN1_ITYPE_SEQUENCE => {
            // A non-zero answer means either a failure or a count another owner still
            // holds, and in both cases this call must not release anything. The
            // authority asserts the value was not embedded, because a caller cannot
            // share a value whose storage it owns.
            // SAFETY: `*pval` is a live value of the item's type.
            let r = unsafe { utl::do_lock(pval, -1, item) };
            if r != 0 {
                debug_assert!(embed == 0, "a shared value cannot be embedded");
                // SAFETY: the caller's slot is writable.
                unsafe { *pval = core::ptr::null_mut() };
                return;
            }
            if let Some(cb) = asn1_cb(item) {
                // SAFETY: the callback is the caller's.
                if unsafe { cb(ASN1_OP_FREE_PRE, pval, it, core::ptr::null_mut()) } == 2 {
                    return;
                }
            }
            // The received encoding is released first: it is a copy of bytes the
            // caller was given, and it is not reachable from any field.
            // SAFETY: `*pval` is a live value of the item's type.
            unsafe { utl::enc_free(pval, item) };
            // Reverse order, for the reason the authority's comment gives: freeing an
            // `ANY DEFINED BY` field first would destroy the selector that tells the
            // remaining fields' templates how to read themselves.
            let mut i: c_long = 0;
            let mut tt = if item.templates.is_null() {
                core::ptr::null()
            } else {
                // SAFETY: one past the end is the starting point of a reverse walk.
                unsafe { item.templates.add(item.tcount.max(0) as usize) }
            };
            while i < item.tcount {
                // SAFETY: the walk stays inside the item's template array.
                tt = unsafe { tt.sub(1) };
                // SAFETY: `tt` is inside the array and `*pval` is the enclosing value.
                let seqtt = unsafe { utl::do_adb(*pval, tt, 0) };
                if !seqtt.is_null() {
                    // SAFETY: `seqtt` is live and `*pval` is the enclosing value.
                    let field = unsafe { utl::get_field_ptr(pval, &*seqtt) };
                    // SAFETY: the field's own template governs it.
                    unsafe { template_free(field, seqtt) };
                }
                i += 1;
            }
            if let Some(cb) = asn1_cb(item) {
                // SAFETY: the callback is the caller's.
                unsafe { cb(ASN1_OP_FREE_POST, pval, it, core::ptr::null_mut()) };
            }
            if embed == 0 {
                // SAFETY: `*pval` came from this allocator and is not reused.
                unsafe { CRYPTO_free(*pval, FILE.as_ptr(), LINE) };
                // SAFETY: the caller's slot is writable.
                unsafe { *pval = core::ptr::null_mut() };
            }
        }

        _ => {}
    }
}

/// `ossl_asn1_template_free` — release one field through its template.
///
/// A `SET OF`/`SEQUENCE OF` field is a stack of values, each of which is released
/// through the template's own item before the stack itself is released.
///
/// # Safety
///
/// `pval` must be a live field slot of the enclosing value; `tt` must be a live
/// template. When `ASN1_TFLG_EMBED` is set the field itself is the value's storage.
pub(crate) unsafe fn template_free(pval: *mut *mut c_void, tt: *const Asn1Template) {
    if tt.is_null() {
        return;
    }
    // SAFETY: `tt` is live.
    let t = unsafe { &*tt };
    let embed = c_int::from(t.flags & ASN1_TFLG_EMBED != 0);
    // An embedded field's value is the field itself, so the item machinery is handed
    // the address of a local holding the field's address. The authority does the same.
    // SAFETY: the caller's contract covers this slot.
    let mut tval: *mut c_void = unsafe { *pval };
    let pval = if embed != 0 {
        // SAFETY: `pval` is a live slot; `tval` is this frame's copy.
        unsafe { pval.write(tval) };
        tval = pval as *mut c_void;
        &mut tval as *mut *mut c_void
    } else {
        pval
    };

    if t.flags & ASN1_TFLG_SK_MASK != 0 {
        // SAFETY: the field holds the stack.
        let sk = unsafe { *pval } as *mut crate::runtime::stack::OpenSslStack;
        // SAFETY: `sk` is live, and `OPENSSL_sk_num` reads only its length.
        let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(sk) };
        let mut i: c_int = 0;
        while i < n {
            // SAFETY: `i < n`, so the element exists.
            let mut vtmp = unsafe { crate::runtime::stack::OPENSSL_sk_value(sk, i) };
            // SAFETY: `vtmp` is a live element and `t.item` is its item accessor.
            let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
            // SAFETY: as above.
            unsafe { item_embed_free(&mut vtmp, sub, embed) };
            i += 1;
        }
        // SAFETY: `sk` is live and the elements have been released.
        unsafe { crate::runtime::stack::OPENSSL_sk_free(sk) };
        // SAFETY: the caller's field slot is writable.
        unsafe { *pval = core::ptr::null_mut() };
        return;
    }
    // SAFETY: `t.item` is the field's `ASN1_ITEM_EXP`.
    let sub = unsafe { utl::call_item_exp(t.item) } as *const Asn1Item;
    // SAFETY: the caller's contract covers the field's own item.
    unsafe { item_embed_free(pval, sub, embed) };
}

/// `ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)`
///
/// Takes the value by value and frees through a local slot, so there is nothing for the
/// caller to null afterwards.
///
/// # Safety
///
/// `val` must be null or a live value of the item's type; `it` must be a live item.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // the authority's own contract
pub unsafe extern "C" fn ASN1_item_free(val: *mut c_void, it: *const Asn1Item) {
    let mut local = val;
    // SAFETY: the caller's contract; `local` is a live slot.
    unsafe { item_embed_free(&mut local, it, 0) };
}

/// `void ASN1_item_ex_free(ASN1_VALUE **pval, const ASN1_ITEM *it)`
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live value of the item's type; `it`
/// must be a live item.
#[no_mangle]
pub unsafe extern "C" fn ASN1_item_ex_free(pval: *mut *mut c_void, it: *const Asn1Item) {
    // SAFETY: the caller's contract.
    unsafe { item_embed_free(pval, it, 0) }
}
