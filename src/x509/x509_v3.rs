//! Phase 10.11 — `crypto/x509/x509_v3.c`: the X.509v3 extension add/get/count/delete surface,
//! whole.
//!
//! The unit publishes fifteen functions and all fifteen land here. It is the `v3` half of the
//! name/print/`v3` dispatch layer: the extension **list** operations (`X509v3_get_ext_count`,
//! `_get_ext_by_NID`/`_by_OBJ`/`_by_critical`, `_get_ext`, `_delete_ext`, `X509v3_add_ext`,
//! `X509v3_add_extensions`) and the two `X509_EXTENSION` creators that pair an object with a
//! critical flag and data (`X509_EXTENSION_create_by_NID`/`_by_OBJ`), plus the four field
//! accessors the authority keeps in this unit rather than in `x_exten.c`.
//!
//! Nothing of the unit is withheld. Every callee is landed: `X509_EXTENSION_new`/`_free`/`_dup`
//! and the item are 10.8's `x_exten.rs`; `OBJ_nid2obj`/`OBJ_cmp`/`OBJ_dup` and
//! `ASN1_OCTET_STRING_set` are Phases 4-6's; and the `OPENSSL_sk_*` primitives are the stack
//! layer. The one thing worth naming is that `X509_EXTENSION_set_object`/`_set_critical`/`_set_data`
//! and `X509_EXTENSION_get_object`/`_get_data`/`_get_critical` are declared in `x509.h` and live
//! in *this* translation unit -- a reader looking for them in `x_exten.c` will not find them.
//!
//! ## The two insert positions, and the `add_extensions` replace loop
//!
//! `X509v3_add_ext` clamps `loc` to `[0, n]` (`loc > n` and `loc < 0` both become `n`, an append)
//! and inserts a **duplicate** of the caller's extension, so the caller keeps ownership. The
//! error tail frees the duplicate and, only when the caller's stack pointer was NULL to begin
//! with, the stack it built -- a non-NULL `*x` is the caller's and must survive a failed insert.
//!
//! `X509v3_add_extensions` is the batch spelling and is *not* a plain loop: for each source
//! extension it first deletes **every** extension in the target whose OID matches, then appends
//! the source's, so a batch add replaces rather than accumulates. Its own return value is
//! `*target`, which the authority's comment marks as NULL both on error and when `*target` was
//! NULL and `exts` was empty.
//!
//! ## The raise sites
//!
//! Six `ERR_raise*` sites in the unit; every one this transcription reaches is the generated
//! constant `X509_V3_*` in [`crate::runtime::err::err_sites`], because `crypto/x509/x509_v3.c`
//! joins `gen_err_raise_sites.py`'s covered set with this subphase. They are `ERR_LIB_X509`
//! with `ERR_R_PASSED_NULL_PARAMETER`, `ERR_R_CRYPTO_LIB`, `ERR_R_ASN1_LIB` and
//! `X509_R_UNKNOWN_NID`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::ASN1_OCTET_STRING_set;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{Asn1Object, OBJ_cmp, OBJ_dup, OBJ_nid2obj};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x_exten::{
    X509Extension, X509_EXTENSION_dup, X509_EXTENSION_free, X509_EXTENSION_new,
};

/// `int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)` — `crypto/x509/x509_v3.c:20-28`.
///
/// A NULL stack answers 0, and a stack the underlying `OPENSSL_sk_num` reports as non-positive is
/// clamped to 0 rather than returned as a negative count.
///
/// # Safety
///
/// `x` must be NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_get_ext_count(x: *const OpenSslStack) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is non-NULL and a live stack per the contract.
    let ret = unsafe { OPENSSL_sk_num(x) };
    if ret > 0 {
        ret
    } else {
        0
    }
}

/// `int X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x, int nid, int lastpos)` —
/// `crypto/x509/x509_v3.c:30-39`.
///
/// A NID with no object answers `-2`, distinct from the `-1` "not present" of `_by_OBJ`.
///
/// # Safety
///
/// `x` must be NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_get_ext_by_NID(
    x: *const OpenSslStack,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `OBJ_nid2obj` takes an integer NID and answers a table object or NULL.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -2;
    }
    // SAFETY: `x` is NULL or live and `obj` is a live table object.
    unsafe { X509v3_get_ext_by_OBJ(x, obj, lastpos) }
}

/// `int X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *sk, const ASN1_OBJECT *obj,
/// int lastpos)` — `crypto/x509/x509_v3.c:41-59`.
///
/// Searches from `lastpos + 1` (a negative `lastpos` becomes 0) and answers the first index whose
/// extension object equals `obj`, or `-1`.
///
/// # Safety
///
/// `sk` must be NULL or a live extension stack; `obj` must be a live object.
#[no_mangle]
pub unsafe extern "C" fn X509v3_get_ext_by_OBJ(
    sk: *const OpenSslStack,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    if sk.is_null() {
        return -1;
    }
    let mut lastpos = lastpos + 1;
    if lastpos < 0 {
        lastpos = 0;
    }
    // SAFETY: `sk` is non-NULL and live per the contract.
    let n = unsafe { OPENSSL_sk_num(sk) };
    while lastpos < n {
        // SAFETY: `lastpos` is within `0..n`.
        let ex = unsafe { OPENSSL_sk_value(sk, lastpos) }.cast::<X509Extension>();
        // SAFETY: every element of the stack is an `X509_EXTENSION` and `obj` is live.
        if unsafe { OBJ_cmp((*ex).object, obj) } == 0 {
            return lastpos;
        }
        lastpos += 1;
    }
    -1
}

/// `int X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *sk, int crit, int lastpos)` —
/// `crypto/x509/x509_v3.c:61-81`.
///
/// `crit` is normalised to a boolean on **every** iteration before the comparison, which is the
/// authority's own spelling and observable only through a side-effecting accessor.
///
/// # Safety
///
/// `sk` must be NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_get_ext_by_critical(
    sk: *const OpenSslStack,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    if sk.is_null() {
        return -1;
    }
    let mut lastpos = lastpos + 1;
    if lastpos < 0 {
        lastpos = 0;
    }
    // SAFETY: `sk` is non-NULL and live per the contract.
    let n = unsafe { OPENSSL_sk_num(sk) };
    while lastpos < n {
        // SAFETY: `lastpos` is within `0..n`.
        let ex = unsafe { OPENSSL_sk_value(sk, lastpos) }.cast::<X509Extension>();
        // SAFETY: every element is an `X509_EXTENSION`.
        let c = unsafe { X509_EXTENSION_get_critical(ex) };
        let crit = c_int::from(crit != 0);
        if c == crit {
            return lastpos;
        }
        lastpos += 1;
    }
    -1
}

/// `X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc)` —
/// `crypto/x509/x509_v3.c:83-89`.
///
/// # Safety
///
/// `x` must be NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_get_ext(x: *const OpenSslStack, loc: c_int) -> *mut X509Extension {
    if x.is_null()
        // SAFETY: `x` is non-NULL and live per the contract.
        || unsafe { OPENSSL_sk_num(x) } <= loc
        || loc < 0
    {
        ptr::null_mut()
    } else {
        // SAFETY: `0 <= loc < num` per the guard above.
        unsafe { OPENSSL_sk_value(x, loc) }.cast::<X509Extension>()
    }
}

/// `X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc)` —
/// `crypto/x509/x509_v3.c:91-99`.
///
/// The removed element is returned and the caller owns it.
///
/// # Safety
///
/// `x` must be NULL or a live extension stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_delete_ext(x: *mut OpenSslStack, loc: c_int) -> *mut X509Extension {
    if x.is_null()
        // SAFETY: `x` is non-NULL and live per the contract.
        || unsafe { OPENSSL_sk_num(x) } <= loc
        || loc < 0
    {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live and `0 <= loc < num`.
    unsafe { OPENSSL_sk_delete(x, loc) }.cast::<X509Extension>()
}

/// `STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x, X509_EXTENSION *ex,
/// int loc)` — `crypto/x509/x509_v3.c:101-143`.
///
/// A **duplicate** of `ex` is inserted at the clamped `loc`, so the caller keeps its extension.
/// A NULL `x` is refused; a `*x` that is NULL builds the stack. On failure the duplicate is freed
/// and the locally built stack is freed too, but only when the caller's pointer was NULL -- a
/// non-NULL `*x` is the caller's stack and must outlive a failed insert.
///
/// # Safety
///
/// `x` must be NULL or point at a writable stack slot; `ex` must be a live extension.
#[no_mangle]
pub unsafe extern "C" fn X509v3_add_ext(
    x: *mut *mut OpenSslStack,
    ex: *mut X509Extension,
    loc: c_int,
) -> *mut OpenSslStack {
    if x.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_V3_109) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is non-NULL per the guard above.
    let sk = if unsafe { *x }.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_V3_115) };
            return ptr::null_mut();
        }
        fresh
    } else {
        // SAFETY: `x` is non-NULL and `*x` is a live stack.
        unsafe { *x }
    };

    // SAFETY: `sk` is a live stack (either freshly built or the caller's).
    let n = unsafe { OPENSSL_sk_num(sk) };
    let loc = if loc > n || loc < 0 { n } else { loc };

    // SAFETY: `ex` is live per the contract.
    let new_ex = unsafe { X509_EXTENSION_dup(ex) };
    if new_ex.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_V3_128) };
        // SAFETY: `ex`'s duplicate is NULL; the stack is this call's only when `*x` was NULL.
        return unsafe { add_ext_err(x, sk, new_ex) };
    }
    // SAFETY: `sk` is live and `loc` is within `0..=n`; `new_ex` is this call's own.
    if unsafe { OPENSSL_sk_insert(sk, new_ex.cast::<c_void>(), loc) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_V3_132) };
        // SAFETY: as above.
        return unsafe { add_ext_err(x, sk, new_ex) };
    }
    // SAFETY: `x` is non-NULL per the guard above.
    if unsafe { *x }.is_null() {
        // SAFETY: `x` is writable per the contract.
        unsafe { *x = sk };
    }
    sk
}

/// `crypto/x509/x509_v3.c:138-142`'s `err:` label of [`X509v3_add_ext`].
///
/// Frees the duplicate, and the stack only when the caller's slot was NULL.
///
/// # Safety
///
/// `x` must be non-NULL and writable; `sk` NULL or a live stack this call owns; `new_ex` NULL or
/// the duplicate this call owns.
unsafe fn add_ext_err(
    x: *mut *mut OpenSslStack,
    sk: *mut OpenSslStack,
    new_ex: *mut X509Extension,
) -> *mut OpenSslStack {
    // SAFETY: `new_ex` is NULL or this call's duplicate.
    unsafe { X509_EXTENSION_free(new_ex) };
    // SAFETY: `x` is non-NULL per the contract.
    if unsafe { *x }.is_null() && !sk.is_null() {
        // SAFETY: `sk` is this call's own stack (the caller's slot was NULL).
        unsafe { OPENSSL_sk_free(sk) };
    }
    ptr::null_mut()
}

/// `STACK_OF(X509_EXTENSION) *X509v3_add_extensions(STACK_OF(X509_EXTENSION) **target,
/// const STACK_OF(X509_EXTENSION) *exts)` — `crypto/x509/x509_v3.c:146-173`.
///
/// For each source extension, every target extension with the same OID is deleted and the
/// source's is appended: a batch add **replaces**. A NULL `target` is refused. The answer is
/// `*target`, which is NULL both on failure and when the target stayed NULL because `exts` was
/// empty -- the authority's comment says so at `:145`.
///
/// # Safety
///
/// `target` must be NULL or point at a writable stack slot; `exts` must be NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn X509v3_add_extensions(
    target: *mut *mut OpenSslStack,
    exts: *const OpenSslStack,
) -> *mut OpenSslStack {
    if target.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_V3_152) };
        return ptr::null_mut();
    }

    // SAFETY: `exts` is NULL or a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(exts) };
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is within `0..num`.
        let ext = unsafe { OPENSSL_sk_value(exts, i) }.cast::<X509Extension>();
        // SAFETY: every element is an `X509_EXTENSION`.
        let obj = unsafe { X509_EXTENSION_get_object(ext) };
        // SAFETY: `target` is non-NULL and writable; `obj` is a live object.
        let mut idx = unsafe { X509v3_get_ext_by_OBJ(*target, obj, -1) };

        if idx != -1 {
            loop {
                // SAFETY: `target` is non-NULL and writable; `*target` is a live stack when
                // `_get_ext_by_OBJ` answered a valid index; the removed element is owned here.
                unsafe {
                    X509_EXTENSION_free(X509v3_delete_ext(*target, idx));
                }
                // SAFETY: as above.
                idx = unsafe { X509v3_get_ext_by_OBJ(*target, obj, -1) };
                if idx == -1 {
                    break;
                }
            }
        }
        // SAFETY: `target` is non-NULL and writable; `ext` is live.
        if unsafe { X509v3_add_ext(target, ext, -1) }.is_null() {
            return ptr::null_mut();
        }
        i += 1;
    }
    // SAFETY: `target` is non-NULL and writable.
    unsafe { *target }
}

/// `X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid, int crit,
/// ASN1_OCTET_STRING *data)` — `crypto/x509/x509_v3.c:175-191`.
///
/// # Safety
///
/// `ex` must be NULL or point at a writable extension slot; `data` must be a live octet string.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_create_by_NID(
    ex: *mut *mut X509Extension,
    nid: c_int,
    crit: c_int,
    data: *mut crate::asn1::layout::Asn1String,
) -> *mut X509Extension {
    // SAFETY: `OBJ_nid2obj` takes an integer NID.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_V3_184) };
        return ptr::null_mut();
    }
    // SAFETY: `ex` is NULL or writable; `obj`/`data` are live.
    let ret = unsafe { X509_EXTENSION_create_by_OBJ(ex, obj, crit, data) };
    if ret.is_null() {
        // SAFETY: `obj` came from `OBJ_nid2obj` and its reference is dropped here as the
        // authority drops it.
        unsafe { ASN1_OBJECT_free(obj) };
    }
    ret
}

/// `X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex, const ASN1_OBJECT *obj,
/// int crit, ASN1_OCTET_STRING *data)` — `crypto/x509/x509_v3.c:193-221`.
///
/// Builds an extension when the caller has none, otherwise fills the caller's; on failure the
/// fresh one is freed but a caller-supplied one is left untouched.
///
/// # Safety
///
/// `ex` must be NULL or point at a writable extension slot; `obj`/`data` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_create_by_OBJ(
    ex: *mut *mut X509Extension,
    obj: *const Asn1Object,
    crit: c_int,
    data: *mut crate::asn1::layout::Asn1String,
) -> *mut X509Extension {
    let ret: *mut X509Extension;

    if ex.is_null()
        // SAFETY: `ex` may be NULL; a non-NULL `ex` is a readable slot per the contract.
        || unsafe { (*ex).is_null() }
    {
        // SAFETY: no preconditions.
        ret = X509_EXTENSION_new();
        if ret.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_V3_201) };
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `ex` is non-NULL and its slot is non-NULL per the guard above.
        ret = unsafe { *ex };
    }

    // SAFETY: `ret` is live; `obj` is live.
    if unsafe { X509_EXTENSION_set_object(ret, obj) } == 0
        // SAFETY: `ret` is live.
        || unsafe { X509_EXTENSION_set_critical(ret, crit) } == 0
        // SAFETY: `ret` is live; `data` is live.
        || unsafe { X509_EXTENSION_set_data(ret, data) } == 0
    {
        // SAFETY: `ex` may be NULL; `*ex` is read only when `ex` is non-NULL.
        if ex.is_null() || unsafe { ret != *ex } {
            // SAFETY: `ret` is this call's own fresh extension in that case.
            unsafe { X509_EXTENSION_free(ret) };
        }
        return ptr::null_mut();
    }

    // SAFETY: `ex` may be NULL; `*ex` is read only when `ex` is non-NULL.
    if !ex.is_null() && unsafe { (*ex).is_null() } {
        // SAFETY: `ex` is writable per the contract.
        unsafe { *ex = ret };
    }
    ret
}

/// `int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj)` —
/// `crypto/x509/x509_v3.c:223-230`.
///
/// Note this one **returns 0 for a NULL argument without raising**, unlike its two `set_*`
/// siblings; it is the `OBJ_dup` failure that is the observable refusal.
///
/// # Safety
///
/// `ex` must be NULL or live; `obj` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_set_object(
    ex: *mut X509Extension,
    obj: *const Asn1Object,
) -> c_int {
    if ex.is_null() || obj.is_null() {
        return 0;
    }
    // SAFETY: `ex` is live; its `object` slot is either NULL or the crate's own object.
    unsafe {
        ASN1_OBJECT_free((*ex).object);
        (*ex).object = OBJ_dup(obj);
    }
    // SAFETY: `ex` is live.
    c_int::from(!(unsafe { (*ex).object }).is_null())
}

/// `int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit)` —
/// `crypto/x509/x509_v3.c:232-238`.
///
/// # Safety
///
/// `ex` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_set_critical(ex: *mut X509Extension, crit: c_int) -> c_int {
    if ex.is_null() {
        return 0;
    }
    // SAFETY: `ex` is live and writable.
    unsafe { (*ex).critical = if crit != 0 { 0xFF } else { 0 } };
    1
}

/// `int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data)` —
/// `crypto/x509/x509_v3.c:240-250`.
///
/// # Safety
///
/// `ex` must be NULL or live; `data` must be a live octet string when `ex` is non-NULL.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_set_data(
    ex: *mut X509Extension,
    data: *mut crate::asn1::layout::Asn1String,
) -> c_int {
    if ex.is_null() {
        return 0;
    }
    // SAFETY: `ex` is live and its `value` is embedded; `data` is live per the contract.
    let i = unsafe { ASN1_OCTET_STRING_set(&raw mut (*ex).value, (*data).data, (*data).length) };
    if i == 0 {
        return 0;
    }
    1
}

/// `ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)` —
/// `crypto/x509/x509_v3.c:252-257`.
///
/// # Safety
///
/// `ex` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_get_object(ex: *mut X509Extension) -> *mut Asn1Object {
    if ex.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ex` is live.
    unsafe { (*ex).object }
}

/// `ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex)` —
/// `crypto/x509/x509_v3.c:259-264`.
///
/// The answer points at the extension's **embedded** value, not a copy.
///
/// # Safety
///
/// `ex` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_get_data(
    ex: *mut X509Extension,
) -> *mut crate::asn1::layout::Asn1String {
    if ex.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ex` is live; its `value` is embedded, so the address is the field's own.
    unsafe { &raw mut (*ex).value }
}

/// `int X509_EXTENSION_get_critical(const X509_EXTENSION *ex)` —
/// `crypto/x509/x509_v3.c:266-273`.
///
/// # Safety
///
/// `ex` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_EXTENSION_get_critical(ex: *const X509Extension) -> c_int {
    if ex.is_null() {
        return 0;
    }
    // SAFETY: `ex` is live.
    if unsafe { (*ex).critical } > 0 {
        return 1;
    }
    0
}
