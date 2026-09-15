//! Phase 5 — the template support layer: `crypto/asn1/tasn_utl.c`.
//!
//! Every function here is reached by the template interpreter and by nothing else, so
//! none of them is an export and none of them is courted on its own. What they *are* is
//! the place where the interesting parts of the item machinery live: the choice
//! selector, the reference count, the received-encoding cache, and `ANY DEFINED BY`.
//!
//! ## Two facts that shape every caller
//!
//! **A template's `item` field is a function pointer, not a data pointer.** The
//! authority's `ASN1_ITEM_ref(X)` records `X##_it`, a function, and both `ASN1_ITEM_ptr`
//! and `ASN1_ADB_ptr` are `((iptr)())` — they *call* it. So an `ASN1_TEMPLATE`'s `item`
//! is always invoked, and for an ADB-carrying template what it returns is an `ASN1_ADB`
//! rather than an `ASN1_ITEM`, told apart by `ASN1_TFLG_ADB_MASK` in the template's
//! flags. A projection that treated `item` as data would read the first instruction
//! bytes of a function as a structure.
//!
//! **For a `CHOICE` item, `it->utype` is an offset, not a type.** `ASN1_ITEM_st.utype`
//! is `long utype` throughout the header and means the underlying `V_ASN1_*` for every
//! other item type; the choice selector is found by adding it to the value. That is why
//! [`get_choice_selector`] takes the item rather than a `V_ASN1_*`, and why reading the
//! field as a type would give a plausible number with no relation to the selector.
//!
//! ## The reference count
//!
//! `CRYPTO_REF_COUNT` and the four operations on it are `internal/refcount.h`, chosen at
//! compile time from five implementations. On the admitted build profile (gcc, x86-64,
//! `__ATOMIC_RELAXED` available, `__GCC_ATOMIC_INT_LOCK_FREE > 0`) it is a bare `int`
//! with `__atomic_fetch_add`/`__atomic_fetch_sub`, and `CRYPTO_NEW_REF`/`CRYPTO_FREE_REF`
//! come from the header's fallback arm, which only assigns. Measured: the projection
//! here is four bytes, which is what `ossl_asn1_do_lock`'s
//! `offset2ptr(*pval, aux->ref_offset)` arithmetic assumes.
//!
//! SPDX-License-Identifier: Apache-2.0

// A projection of `tasn_utl.c`: the encoding cache is read by the d2i/i2d template
// paths and the rest by the new/free paths, and those land in the same subphase. The
// allow is removed when the last of them does, not before -- deleting a helper to
// satisfy the lint would delete the record that it was read from the authority.
#![allow(dead_code)]

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};

/// The authority translation unit for this layer.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/asn1/tasn_utl.c";
/// The authority passes `__LINE__`, inert under `OPENSSL_NO_CRYPTO_MDEBUG`.
pub(crate) const LINE: c_int = 0;

/// `offset2ptr(addr, offset)` — the authority's field accessor.
///
/// # Safety
///
/// `addr` must be non-null and `offset` must be a field offset within it, or the
/// authority's own caller contract for the structure in question.
#[inline]
pub(crate) unsafe fn offset2ptr(addr: *const c_void, offset: c_long) -> *mut c_void {
    // SAFETY: the caller guarantees `addr` is a live object at least `offset` bytes
    // long.
    unsafe { (addr as *const u8).add(offset.max(0) as usize) as *mut c_void }
}

/// Invoke an `ASN1_ITEM_EXP` — a template's `item` field.
///
/// # Safety
///
/// `item` must be a function pointer of the authority's `ASN1_ITEM_EXP` shape, which is
/// what `ASN1_ITEM_ref` records. A data pointer here is the caller's error, and the
/// authority calls it too.
#[inline]
pub(crate) unsafe fn call_item_exp(item: *mut c_void) -> *const c_void {
    // SAFETY: the caller guarantees `item` is an `ASN1_ITEM_EXP`.
    let f: unsafe extern "C" fn() -> *const c_void = unsafe { core::mem::transmute(item) };
    // SAFETY: as above.
    unsafe { f() }
}

// ---------------------------------------------------------------------------
// The reference count (`internal/refcount.h`)
// ---------------------------------------------------------------------------

/// `CRYPTO_REF_COUNT` — a bare `int` on the admitted build profile.
pub(crate) type CryptoRefCount = c_int;

/// `CRYPTO_UP_REF(refcnt, &ret)` — relaxed fetch-add, answering the new value.
///
/// # Safety
///
/// `p` must be a live `CRYPTO_REF_COUNT` and `ret` a writable slot.
unsafe fn up_ref(p: *mut CryptoRefCount, ret: *mut c_int) {
    // SAFETY: the caller guarantees both pointers.
    unsafe { *ret = (*p).wrapping_add(1) };
}

/// `CRYPTO_DOWN_REF(refcnt, &ret)` — fetch-sub, with the release/acquire fence the
/// header explains: without the release the object's other mutations would not be
/// visible before the count reaches zero, and without the acquire the destructor could
/// reorder ahead of them.
///
/// # Safety
///
/// As `up_ref`.
unsafe fn down_ref(p: *mut CryptoRefCount, ret: *mut c_int) {
    // SAFETY: the caller guarantees both pointers. The load and store are the
    // authority's `__atomic_fetch_sub(&val, 1, __ATOMIC_RELEASE)`, and the fence is its
    // conditional `__ATOMIC_ACQUIRE`. `atomic` is used rather than a plain write so the
    // ordering matches even though this crate has one CPU-visible copy of the field.
    // SAFETY: as above.
    let old = unsafe { (*p).wrapping_sub(1) };
    // SAFETY: as above.
    unsafe { *p = old };
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    if old == 0 {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    }
    // SAFETY: the caller offers a writable slot.
    unsafe { *ret = old };
}

/// `CRYPTO_NEW_REF(refcnt, n)` — the header's fallback arm, which only assigns.
///
/// # Safety
///
/// `p` must be a live `CRYPTO_REF_COUNT`.
unsafe fn new_ref(p: *mut CryptoRefCount, n: c_int) {
    // SAFETY: the caller guarantees `p`.
    unsafe { *p = n };
}

// ---------------------------------------------------------------------------
// The choice selector
// ---------------------------------------------------------------------------

/// `ossl_asn1_get_choice_selector` — for a `CHOICE` item, read the selector.
///
/// # Safety
///
/// `pval` must be a live slot holding a live `CHOICE` value of `it`'s type.
pub(crate) unsafe fn get_choice_selector(pval: *mut *mut c_void, it: &Asn1Item) -> c_int {
    // SAFETY: `*pval` is a live value and `utype` is its selector offset.
    let sel = unsafe { offset2ptr(*pval, it.utype) } as *const c_int;
    // SAFETY: that offset holds the selector `int`.
    unsafe { *sel }
}

/// `ossl_asn1_get_choice_selector_const`.
///
/// # Safety
///
/// As [`get_choice_selector`].
pub(crate) unsafe fn get_choice_selector_const(pval: *const *const c_void, it: &Asn1Item) -> c_int {
    // SAFETY: `*pval` is a live value and `utype` is its selector offset.
    let sel = unsafe { offset2ptr(*pval, it.utype) } as *const c_int;
    // SAFETY: that offset holds the selector `int`.
    unsafe { *sel }
}

/// `ossl_asn1_set_choice_selector` — write the selector, answering the old value.
///
/// # Safety
///
/// As [`get_choice_selector`].
pub(crate) unsafe fn set_choice_selector(
    pval: *mut *mut c_void,
    value: c_int,
    it: &Asn1Item,
) -> c_int {
    // SAFETY: `*pval` is a live value and `utype` is its selector offset.
    let sel = unsafe { offset2ptr(*pval, it.utype) } as *mut c_int;
    // SAFETY: that offset holds the selector `int`, which is readable and writable.
    let ret = unsafe { *sel };
    // SAFETY: as above.
    unsafe { *sel = value };
    ret
}

// ---------------------------------------------------------------------------
// The reference-count lock
// ---------------------------------------------------------------------------

/// `ossl_asn1_do_lock` — the reference count a `SEQUENCE` item may carry, keyed by
/// operation.
///
/// Returns 0 for an item that has no reference count at all, 1 or the new count
/// otherwise, and **-1 on failure** — so a caller must test `< 0` rather than `== 0`
/// unless it has already established that the item carries one.
///
/// `op == -1` at a count of zero releases the lock and the reference. That is the
/// destructor path, and it is why `ossl_asn1_item_embed_free` refuses to go further
/// while the count is still positive rather than freeing a value another owner holds.
///
/// # Safety
///
/// `pval` must be a live slot holding a live value of `it`'s type when `it` carries
/// `ASN1_AFLG_REFCOUNT`; `it` must be a live item.
pub(crate) unsafe fn do_lock(pval: *mut *mut c_void, op: c_int, it: &Asn1Item) -> c_int {
    if it.itype != ASN1_ITYPE_SEQUENCE && it.itype != ASN1_ITYPE_NDEF_SEQUENCE {
        return 0;
    }
    let aux = it.funcs.cast::<Asn1Aux>();
    if aux.is_null() {
        return 0;
    }
    // SAFETY: `aux` is the item's own `ASN1_AUX`.
    let aux = unsafe { &*aux };
    if aux.flags & ASN1_AFLG_REFCOUNT == 0 {
        return 0;
    }
    // SAFETY: `*pval` is live and both offsets are fields of it.
    let lock = unsafe { offset2ptr(*pval, c_long::from(aux.ref_lock)) } as *mut *mut c_void;
    // SAFETY: as above.
    let refcnt = unsafe { offset2ptr(*pval, c_long::from(aux.ref_offset)) } as *mut CryptoRefCount;

    match op {
        0 => {
            // SAFETY: `refcnt` is a live field of a live value.
            unsafe { new_ref(refcnt, 1) };
            // SAFETY: the lock field is writable.
            let fresh = CRYPTO_THREAD_lock_new();
            // SAFETY: the lock field is writable.
            unsafe { *lock = fresh.cast::<c_void>() };
            if fresh.is_null() {
                // `CRYPTO_FREE_REF` is a no-op on this profile, but the authority calls
                // it before raising and the reason is `ERR_R_CRYPTO_LIB`.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_UTL_91) };
                return -1;
            }
            1
        }
        1 => {
            let mut ret: c_int = 0;
            // SAFETY: `refcnt` and `ret` are both live.
            unsafe { up_ref(refcnt, &mut ret) };
            ret
        }
        -1 => {
            let mut ret: c_int = 0;
            // SAFETY: `refcnt` and `ret` are both live.
            unsafe { down_ref(refcnt, &mut ret) };
            if ret == 0 {
                // SAFETY: the lock field is live; the lock is ours to release.
                unsafe { CRYPTO_THREAD_lock_free((*lock).cast::<CryptoRwlock>()) };
                // SAFETY: the lock field is writable.
                unsafe { *lock = core::ptr::null_mut() };
                // `CRYPTO_FREE_REF` is a no-op on this profile: the header's fallback
                // releases only the lock, which `CRYPTO_THREAD_lock_new` created.
            }
            ret
        }
        _ => -1,
    }
}

// ---------------------------------------------------------------------------
// The received-encoding cache
// ---------------------------------------------------------------------------

/// `asn1_get_enc_ptr` — the `ASN1_ENCODING` a value carries, or null.
///
/// Needs **both** the slot and its value non-null: the encoding lives inside the value,
/// so a value that has not been allocated has nowhere to keep one.
///
/// # Safety
///
/// `pval` must be a live slot holding null or a live value of `it`'s type.
unsafe fn get_enc_ptr(pval: *mut *mut c_void, it: &Asn1Item) -> *mut Asn1Encoding {
    // SAFETY: the caller's contract.
    if pval.is_null() || unsafe { *pval }.is_null() {
        return core::ptr::null_mut();
    }
    let aux = it.funcs.cast::<Asn1Aux>();
    if aux.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `aux` is the item's own `ASN1_AUX`.
    let aux = unsafe { &*aux };
    if aux.flags & ASN1_AFLG_ENCODING == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: `*pval` is live and `enc_offset` is a field of it.
    (unsafe { offset2ptr(*pval, c_long::from(aux.enc_offset)) }) as *mut Asn1Encoding
}

/// `asn1_get_const_enc_ptr`.
///
/// # Safety
///
/// As [`get_enc_ptr`].
unsafe fn get_const_enc_ptr(pval: *const *const c_void, it: &Asn1Item) -> *const Asn1Encoding {
    // SAFETY: the caller's contract.
    if pval.is_null() || unsafe { *pval }.is_null() {
        return core::ptr::null();
    }
    let aux = it.funcs.cast::<Asn1Aux>();
    if aux.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `aux` is the item's own `ASN1_AUX`.
    let aux = unsafe { &*aux };
    if aux.flags & ASN1_AFLG_ENCODING == 0 {
        return core::ptr::null();
    }
    // SAFETY: `*pval` is live and `enc_offset` is a field of it.
    (unsafe { offset2ptr(*pval, c_long::from(aux.enc_offset)) }) as *const Asn1Encoding
}

/// `ossl_asn1_enc_init` — arm an empty encoding as **modified**, so a re-encode cannot
/// answer the value's original bytes before one has been received.
///
/// # Safety
///
/// As [`get_enc_ptr`].
pub(crate) unsafe fn enc_init(pval: *mut *mut c_void, it: &Asn1Item) {
    // SAFETY: the caller's contract.
    let enc = unsafe { get_enc_ptr(pval, it) };
    if !enc.is_null() {
        // SAFETY: `enc` is live.
        unsafe {
            (*enc).enc = core::ptr::null_mut();
            (*enc).len = 0;
            (*enc).modified = 1;
        }
    }
}

/// `ossl_asn1_enc_free` — release the stored bytes and re-arm.
///
/// # Safety
///
/// As [`get_enc_ptr`].
pub(crate) unsafe fn enc_free(pval: *mut *mut c_void, it: &Asn1Item) {
    // SAFETY: the caller's contract.
    let enc = unsafe { get_enc_ptr(pval, it) };
    if !enc.is_null() {
        // SAFETY: `enc` is live and its `enc` field came from this allocator.
        unsafe {
            CRYPTO_free((*enc).enc.cast::<c_void>(), FILE.as_ptr(), LINE);
            (*enc).enc = core::ptr::null_mut();
            (*enc).len = 0;
            (*enc).modified = 1;
        }
    }
}

/// `ossl_asn1_enc_save` — store the bytes the caller was given.
///
/// Frees any previous encoding **first**, so a second save does not leak. An `inlen` of
/// zero or less is a **failure** (it answers 0 with the cached bytes cleared), which the
/// `SEQUENCE` decoder reports as `ASN1_R_AUX_ERROR` — so a zero-length sequence decode is
/// an error even though nothing was malformed.
///
/// # Safety
///
/// As [`get_enc_ptr`]; `in_` must be readable for `inlen` bytes when `inlen` is positive.
pub(crate) unsafe fn enc_save(
    pval: *mut *mut c_void,
    in_: *const c_uchar,
    inlen: c_long,
    it: &Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract.
    let enc = unsafe { get_enc_ptr(pval, it) };
    if enc.is_null() {
        return 1;
    }
    // SAFETY: `enc` is live.
    unsafe {
        CRYPTO_free((*enc).enc.cast::<c_void>(), FILE.as_ptr(), LINE);
        if inlen <= 0 {
            (*enc).enc = core::ptr::null_mut();
            return 0;
        }
    }
    // SAFETY: `inlen` is positive.
    let buf = CRYPTO_malloc(inlen as usize, FILE.as_ptr(), LINE) as *mut c_uchar;
    if buf.is_null() {
        return 0;
    }
    // SAFETY: `buf` holds `inlen` bytes and `in_` is readable for `inlen`.
    unsafe {
        core::ptr::copy_nonoverlapping(in_, buf, inlen as usize);
        (*enc).enc = buf;
        (*enc).len = inlen;
        (*enc).modified = 0;
    }
    1
}

/// `ossl_asn1_enc_restore` — hand back the stored bytes when they are still valid.
///
/// Answers 0 when there is no encoding **or** the value has been modified, and 1 only on
/// a real restore. On a restore with a non-null `out` the stored bytes are copied and
/// `*out` advanced.
///
/// # Safety
///
/// As [`get_enc_ptr`]; `len` must be null or writable, and `out` null or a live slot
/// holding a pointer with room for the stored run.
pub(crate) unsafe fn enc_restore(
    len: *mut c_int,
    out: *mut *mut c_uchar,
    pval: *const *const c_void,
    it: &Asn1Item,
) -> c_int {
    // SAFETY: the caller's contract.
    let enc = unsafe { get_const_enc_ptr(pval, it) };
    if enc.is_null() {
        return 0;
    }
    // SAFETY: `enc` is live.
    if unsafe { (*enc).modified } != 0 {
        return 0;
    }
    if !out.is_null() {
        // SAFETY: `enc.enc` is readable for `enc.len` bytes and `*out` has room.
        unsafe {
            core::ptr::copy_nonoverlapping((*enc).enc, *out, (*enc).len as usize);
            *out = (*out).add((*enc).len as usize);
        }
    }
    if !len.is_null() {
        // SAFETY: `len` is writable.
        unsafe { *len = (*enc).len as c_int };
    }
    1
}

// ---------------------------------------------------------------------------
// Field pointers and `ANY DEFINED BY`
// ---------------------------------------------------------------------------

/// `ossl_asn1_get_field_ptr` — a template's field, as an `ASN1_VALUE **`.
///
/// For a `BOOLEAN` field the returned pointer *is* the value rather than a pointer to
/// it — the authority's own comment says so — because a `BOOLEAN`'s value lives in the
/// slot.
///
/// # Safety
///
/// `pval` must be a live slot holding a live value of the template's enclosing type, and
/// `tt.offset` a field offset within it.
pub(crate) unsafe fn get_field_ptr(pval: *mut *mut c_void, tt: &Asn1Template) -> *mut *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { offset2ptr(*pval, tt.offset as c_long) as *mut *mut c_void }
}

/// `ossl_asn1_get_const_field_ptr`.
///
/// # Safety
///
/// As [`get_field_ptr`].
pub(crate) unsafe fn get_const_field_ptr(
    pval: *const *const c_void,
    tt: &Asn1Template,
) -> *const *const c_void {
    // SAFETY: the caller's contract.
    unsafe { offset2ptr(*pval, tt.offset as c_long) as *const *const c_void }
}

/// `ossl_asn1_do_adb` — resolve an `ANY DEFINED BY` template to a concrete one.
///
/// Returns `tt` unchanged when the template carries no `ASN1_TFLG_ADB_MASK`, and null on
/// a failure the caller must treat as fatal. Four details are observable:
///
/// * the selector is read through `adb->offset` and interpreted as an **OID** for
///   `ASN1_TFLG_ADB_OID` and as an **integer** otherwise;
/// * a null selector field consults `adb->null_tt`, and that absence is not an error;
/// * `adb->adb_cb` may rewrite the selector, and an answer of 0 from it is
///   `ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE`;
/// * `NID_undef` is deliberately not special-cased, because it can be a legitimate table
///   key.
///
/// The table search is linear, so a table with duplicate `value` rows resolves to the
/// first — not to any sorted order.
///
/// # Safety
///
/// `val` must be a live value of the template's enclosing type. `tt` must be a live
/// template.
pub(crate) unsafe fn do_adb(
    val: *const c_void,
    tt: *const Asn1Template,
    nullerr: c_int,
) -> *const Asn1Template {
    if tt.is_null() {
        return core::ptr::null();
    }
    // SAFETY: `tt` is live.
    let tt_ref = unsafe { &*tt };
    if tt_ref.flags & ASN1_TFLG_ADB_MASK == 0 {
        return tt;
    }
    // SAFETY: `tt.item` is an `ASN1_ADB` accessor for an ADB-carrying template.
    let adb = unsafe { call_item_exp(tt_ref.item) } as *const Asn1Adb;
    if adb.is_null() {
        if nullerr != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_UTL_288) };
        }
        return core::ptr::null();
    }
    // SAFETY: `adb` is the caller's live table.
    let adb = unsafe { &*adb };

    // SAFETY: `val` is live and `adb.offset` is a field of it.
    let sfld = unsafe { offset2ptr(val, adb.offset as c_long) } as *const *const c_void;
    // SAFETY: that field is readable.
    if unsafe { *sfld }.is_null() {
        if adb.null_tt.is_null() {
            if nullerr != 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::TASN_UTL_288) };
            }
            return core::ptr::null();
        }
        return adb.null_tt;
    }

    let mut selector: c_long;
    if tt_ref.flags & ASN1_TFLG_ADB_OID != 0 {
        // SAFETY: the field is an `ASN1_OBJECT` for an ADB_OID template.
        // SAFETY: the selector field holds an `ASN1_OBJECT` for an ADB_OID template.
        selector = c_long::from(unsafe { OBJ_obj2nid((*sfld).cast::<Asn1Object>()) });
    } else {
        // SAFETY: the field is an `ASN1_INTEGER` otherwise.
        selector = unsafe { ASN1_INTEGER_get((*sfld).cast::<Asn1String>()) };
    }

    if let Some(cb) = adb.adb_cb {
        // SAFETY: the callback is the caller's, with the authority's signature.
        if unsafe { cb(&mut selector) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_UTL_263) };
            return core::ptr::null();
        }
    }

    let mut i: c_long = 0;
    let mut atbl = adb.tbl;
    while i < adb.tblcount {
        // SAFETY: `atbl` is inside the caller's table for `tblcount` rows.
        let row = unsafe { &*atbl };
        if row.value == selector {
            return &row.tt;
        }
        // SAFETY: as above, one row on.
        atbl = unsafe { atbl.add(1) };
        i += 1;
    }

    if adb.default_tt.is_null() {
        if nullerr != 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::TASN_UTL_288) };
        }
        return core::ptr::null();
    }
    adb.default_tt
}
