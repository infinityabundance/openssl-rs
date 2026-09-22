//! `crypto/x509/x509_att.c` — the `X509_ATTRIBUTE` collection and constructor layer,
//! transcribed whole. Phase 11 (D368).
//!
//! The file is 446 lines and 19 exports plus 5 internals. It is two families that share the
//! `X509_ATTRIBUTE` type [`crate::x509::x_attrib`] defines:
//!
//! * the **`STACK_OF(X509_ATTRIBUTE)` collection** — the `X509at_get_*`/`X509at_delete_attr`
//!   lookups, the four `add1_attr` spellings and their `ossl_` internal twins, and
//!   `ossl_x509at_dup`; and
//! * the **`X509_ATTRIBUTE` constructors** — `X509_ATTRIBUTE_create_by_{NID,OBJ,txt}`, the
//!   `set1_object`/`set1_data` pair they build with, and the four readers.
//!
//! ## Why it is here
//!
//! `crypto/asn1/p8_pkey.c`'s three `PKCS8_pkey_add1_attr*` exports are each one call to
//! `X509at_add1_attr_by_NID`/`_by_OBJ`/`X509at_add1_attr` (`:95`, `:103`, `:108`), which
//! D349 withheld with this file. The unit is Phase 11's -- `x509.h` declares every export --
//! so landing it moves no Phase 8 or Phase 7 obligation count; it completes the PKCS#8
//! attribute path the `PKCS8_PRIV_KEY_INFO` template's `attributes` column needs, and it is
//! the file `forensics/prerequisites.json`'s `divergence` for `x509_att.c` no longer has to
//! mention.
//!
//! ## The two guards that differ between the `ossl_` twins and their wrappers
//!
//! The `ossl_x509at_add1_attr*` internals are the allocation-and-push half and can be called
//! with `x` non-NULL and `*x` NULL, in which case they build the stack. The four public
//! spellings are the guard half: they refuse a NULL argument, refuse a **duplicate** OID with
//! `X509_R_DUPLICATE_ATTRIBUTE` and then delegate. A caller can therefore reach the internals
//! for an unguarded append, which is why both halves are transcribed rather than one.
//!
//! ## The `set1_data` arm that stores nothing
//!
//! `attrtype == 0` is not an error: the authority frees the `ASN1_STRING` it may have built
//! and answers 1, because "some types use and zero length SET and require this" (`:374-379`).
//! That arm is kept rather than normalised away, because it is the one that lets an empty
//! `SET OF` round-trip.
//!
//! ## The court
//!
//! The unit raises, so it is an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`; the
//! `err_sites::X509_ATT_*` coordinates below are generated from it. The evidence is the round
//! trip in the test module: a created attribute is pushed onto an initially-NULL stack, the
//! duplicate OID is refused, and the data comes back through the reader with its type.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_strnid::ASN1_STRING_set_by_NID;
use crate::asn1::a_type::{
    ASN1_TYPE_free, ASN1_TYPE_get, ASN1_TYPE_new, ASN1_TYPE_set, ASN1_TYPE_set1,
};
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_type_new};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::obj::{
    Asn1Object, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_txt2obj,
};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x_attrib::{
    X509Attribute, X509_ATTRIBUTE_dup, X509_ATTRIBUTE_free, X509_ATTRIBUTE_new,
};

/// The destructor `sk_X509_ATTRIBUTE_pop_free` passes to `OPENSSL_sk_pop_free` — the
/// authority spells it `X509_ATTRIBUTE_free`.
///
/// # Safety
/// `elem` must be NULL or an `X509_ATTRIBUTE` this crate allocated.
unsafe extern "C" fn free_x509_attribute(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or an `X509_ATTRIBUTE`, and `X509_ATTRIBUTE_free` accepts NULL.
    unsafe { X509_ATTRIBUTE_free(elem.cast::<X509Attribute>()) };
}

/// `int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x)` — `crypto/x509/x509_att.c:21`.
///
/// # Safety
/// `x` must be NULL or a live `X509_ATTRIBUTE` stack.
#[no_mangle]
pub unsafe extern "C" fn X509at_get_attr_count(x: *const OpenSslStack) -> c_int {
    // SAFETY: `x` is NULL or a live stack; `OPENSSL_sk_num` accepts NULL.
    unsafe { OPENSSL_sk_num(x) }
}

/// `int X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, int nid, int lastpos)` —
/// `crypto/x509/x509_att.c:26`.
///
/// An unknown `nid` answers `-2`, which is the authority's own value and is distinct from the
/// `-1` a search miss answers.
///
/// # Safety
/// `x` must be NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn X509at_get_attr_by_NID(
    x: *const OpenSslStack,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `OBJ_nid2obj` takes an integer and answers a static object or NULL.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -2;
    }
    // SAFETY: `x` is NULL or a live stack and `obj` is live.
    unsafe { X509at_get_attr_by_OBJ(x, obj, lastpos) }
}

/// `int X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk, const ASN1_OBJECT *obj,
/// int lastpos)` — `crypto/x509/x509_att.c:36`.
///
/// `lastpos` is the *previous* answer and the search resumes after it; a negative value is
/// clamped to 0 so `-1` means "from the start".
///
/// # Safety
/// `sk` must be NULL or a live stack of `X509_ATTRIBUTE`; `obj` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509at_get_attr_by_OBJ(
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
    // SAFETY: `sk` is a live stack of `X509_ATTRIBUTE`.
    let n = unsafe { OPENSSL_sk_num(sk) };
    while lastpos < n {
        // SAFETY: `lastpos` is in range and the stack holds `X509_ATTRIBUTE` elements.
        let ex = unsafe { OPENSSL_sk_value(sk, lastpos) }.cast::<X509Attribute>();
        // SAFETY: `ex` is a live attribute and `obj` is live.
        if unsafe { OBJ_cmp((*ex).object, obj) } == 0 {
            return lastpos;
        }
        lastpos += 1;
    }
    -1
}

/// `X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, int loc)` —
/// `crypto/x509/x509_att.c:56`.
///
/// A NULL stack and an out-of-range `loc` are two different raises, and both answer NULL.
///
/// # Safety
/// `x` must be NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn X509at_get_attr(x: *const OpenSslStack, loc: c_int) -> *mut X509Attribute {
    if x.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_59) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a live stack.
    if unsafe { OPENSSL_sk_num(x) } <= loc || loc < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_63) };
        return ptr::null_mut();
    }
    // SAFETY: `loc` is in range and the stack holds `X509_ATTRIBUTE` elements.
    unsafe { OPENSSL_sk_value(x, loc) }.cast::<X509Attribute>()
}

/// `X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc)` —
/// `crypto/x509/x509_att.c:69`.
///
/// The element is removed and returned; the caller owns it.
///
/// # Safety
/// `x` must be NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn X509at_delete_attr(
    x: *mut OpenSslStack,
    loc: c_int,
) -> *mut X509Attribute {
    if x.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_72) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a live stack.
    if unsafe { OPENSSL_sk_num(x) } <= loc || loc < 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_76) };
        return ptr::null_mut();
    }
    // SAFETY: `loc` is in range.
    unsafe { OPENSSL_sk_delete(x, loc) }.cast::<X509Attribute>()
}

/// `STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
/// const X509_ATTRIBUTE *attr)` — `crypto/x509/x509_att.c:82`.
///
/// The unguarded append: the attribute is **duplicated** onto the stack, and a stack is built
/// when `*x` is NULL. On failure the duplicate and, when this call built it, the stack are
/// released.
///
/// # Safety
/// `x` must be NULL or point at a writable stack slot; `attr` must be live.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509at_add1_attr(
    x: *mut *mut OpenSslStack,
    attr: *const X509Attribute,
) -> *mut OpenSslStack {
    if x.is_null() || attr.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_89) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a writable slot.
    let existing = unsafe { *x };
    let sk = if existing.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_ATT_95) };
            return ptr::null_mut();
        }
        fresh
    } else {
        existing
    };

    // SAFETY: `attr` is live.
    let new_attr = unsafe { X509_ATTRIBUTE_dup(attr) };
    if new_attr.is_null() {
        // SAFETY: `existing` is NULL exactly when this call built `sk`.
        return unsafe { add1_attr_err(x, existing, sk) };
    }
    // SAFETY: `sk` is live and `new_attr` is a live attribute that the push adopts.
    if unsafe { OPENSSL_sk_push(sk, new_attr.cast()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_105) };
        // SAFETY: `new_attr` is live and this call owns it on the failure path.
        unsafe { X509_ATTRIBUTE_free(new_attr) };
        // SAFETY: `existing` is NULL exactly when this call built `sk`.
        return unsafe { add1_attr_err(x, existing, sk) };
    }
    if existing.is_null() {
        // SAFETY: `x` is the caller's writable slot.
        unsafe { *x = sk };
    }
    sk
}

/// The authority's `err:` label — `x509_att.c:111-115`.
///
/// # Safety
/// `x` must be a live slot whose `*x` is `existing`; `sk` must be live and this call's own
/// when `existing` is NULL.
unsafe fn add1_attr_err(
    x: *mut *mut OpenSslStack,
    existing: *mut OpenSslStack,
    sk: *mut OpenSslStack,
) -> *mut OpenSslStack {
    if existing.is_null() {
        // SAFETY: this call built `sk` and owns it.
        unsafe { OPENSSL_sk_free(sk) };
    }
    let _ = x;
    ptr::null_mut()
}

/// `STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
/// X509_ATTRIBUTE *attr)` — `crypto/x509/x509_att.c:118`.
///
/// The guarded spelling: a duplicate OID on the existing stack is refused with
/// `X509_R_DUPLICATE_ATTRIBUTE`, and the message names the OID's short name.
///
/// # Safety
/// `x` must be NULL or a writable slot; `attr` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509at_add1_attr(
    x: *mut *mut OpenSslStack,
    attr: *mut X509Attribute,
) -> *mut OpenSslStack {
    if x.is_null() || attr.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_122) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a writable slot and `attr` is live.
    unsafe {
        if !(*x).is_null() && X509at_get_attr_by_OBJ(*x, (*attr).object, -1) != -1 {
            let mut msg = [0 as c_char; 80];
            // SAFETY: `msg` is an 80-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s".as_ptr(),
                OBJ_nid2sn(OBJ_obj2nid((*attr).object)),
            );
            raise_site_data(&err_sites::X509_ATT_126, msg.as_ptr());
            return ptr::null_mut();
        }
    }
    // SAFETY: `x` is a writable slot and `attr` is live.
    unsafe { ossl_x509at_add1_attr(x, attr) }
}

/// `STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE) **x,
/// const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len)` —
/// `crypto/x509/x509_att.c:134`.
///
/// # Safety
/// `x` must be NULL or a writable slot; `obj` must be live; `bytes` must be readable for
/// `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509at_add1_attr_by_OBJ(
    x: *mut *mut OpenSslStack,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    // SAFETY: `obj` is live and the caller's contract covers `bytes`/`len`.
    let attr =
        unsafe { X509_ATTRIBUTE_create_by_OBJ(ptr::null_mut(), obj, type_, bytes.cast(), len) };
    if attr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is the caller's slot and `attr` is live.
    let ret = unsafe { ossl_x509at_add1_attr(x, attr) };
    // SAFETY: `attr` is live and this call owns it.
    unsafe { X509_ATTRIBUTE_free(attr) };
    ret
}

/// `STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE) **x,
/// const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len)` —
/// `crypto/x509/x509_att.c:151`.
///
/// # Safety
/// `x` must be NULL or a writable slot; `obj` must be live; `bytes` must be readable for
/// `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509at_add1_attr_by_OBJ(
    x: *mut *mut OpenSslStack,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    if x.is_null() || obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_159) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a writable slot and `obj` is live.
    unsafe {
        if !(*x).is_null() && X509at_get_attr_by_OBJ(*x, obj, -1) != -1 {
            let mut msg = [0 as c_char; 80];
            // SAFETY: `msg` is an 80-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s".as_ptr(),
                OBJ_nid2sn(OBJ_obj2nid(obj)),
            );
            raise_site_data(&err_sites::X509_ATT_163, msg.as_ptr());
            return ptr::null_mut();
        }
    }
    // SAFETY: `x` is a writable slot; `obj` is live; `bytes`/`len` are the caller's.
    unsafe { ossl_x509at_add1_attr_by_OBJ(x, obj, type_, bytes, len) }
}

/// `STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE) **x,
/// int nid, int type, const unsigned char *bytes, int len)` — `crypto/x509/x509_att.c:171`.
///
/// # Safety
/// `x` must be NULL or a writable slot; `bytes` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509at_add1_attr_by_NID(
    x: *mut *mut OpenSslStack,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract covers `bytes`/`len`.
    let attr =
        unsafe { X509_ATTRIBUTE_create_by_NID(ptr::null_mut(), nid, type_, bytes.cast(), len) };
    if attr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is the caller's slot and `attr` is live.
    let ret = unsafe { ossl_x509at_add1_attr(x, attr) };
    // SAFETY: `attr` is live and this call owns it.
    unsafe { X509_ATTRIBUTE_free(attr) };
    ret
}

/// `STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE) **x,
/// int nid, int type, const unsigned char *bytes, int len)` — `crypto/x509/x509_att.c:187`.
///
/// Note the NULL check is on `x` **alone**: unlike its `_by_OBJ` sibling the authority does
/// not test `nid`, and an unknown `nid` fails in the constructor instead.
///
/// # Safety
/// `x` must be NULL or a writable slot; `bytes` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509at_add1_attr_by_NID(
    x: *mut *mut OpenSslStack,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    if x.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_194) };
        return ptr::null_mut();
    }
    // SAFETY: `x` is a writable slot.
    unsafe {
        if !(*x).is_null() && X509at_get_attr_by_NID(*x, nid, -1) != -1 {
            let mut msg = [0 as c_char; 80];
            // SAFETY: `msg` is an 80-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s".as_ptr(),
                OBJ_nid2sn(nid),
            );
            raise_site_data(&err_sites::X509_ATT_198, msg.as_ptr());
            return ptr::null_mut();
        }
    }
    // SAFETY: `x` is a writable slot; `bytes`/`len` are the caller's.
    unsafe { ossl_x509at_add1_attr_by_NID(x, nid, type_, bytes, len) }
}

/// `STACK_OF(X509_ATTRIBUTE) *ossl_x509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE) **x,
/// const char *attrname, int type, const unsigned char *bytes, int len)` —
/// `crypto/x509/x509_att.c:206`.
///
/// # Safety
/// `x` must be NULL or a writable slot; `attrname` must be a NUL-terminated string; `bytes`
/// must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509at_add1_attr_by_txt(
    x: *mut *mut OpenSslStack,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract covers `attrname` and `bytes`/`len`.
    let attr =
        unsafe { X509_ATTRIBUTE_create_by_txt(ptr::null_mut(), attrname, type_, bytes, len) };
    if attr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is the caller's slot and `attr` is live.
    let ret = unsafe { ossl_x509at_add1_attr(x, attr) };
    // SAFETY: `attr` is live and this call owns it.
    unsafe { X509_ATTRIBUTE_free(attr) };
    ret
}

/// `STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE) **x,
/// const char *attrname, int type, const unsigned char *bytes, int len)` —
/// `crypto/x509/x509_att.c:223`.
///
/// The guarded spelling calls `X509at_add1_attr`, whose own duplicate check uses the
/// **attribute's** object rather than re-resolving the name.
///
/// # Safety
/// `x` must be NULL or a writable slot; `attrname` must be a NUL-terminated string; `bytes`
/// must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509at_add1_attr_by_txt(
    x: *mut *mut OpenSslStack,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract covers `attrname` and `bytes`/`len`.
    let attr =
        unsafe { X509_ATTRIBUTE_create_by_txt(ptr::null_mut(), attrname, type_, bytes, len) };
    if attr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is the caller's slot and `attr` is live.
    let ret = unsafe { X509at_add1_attr(x, attr) };
    // SAFETY: `attr` is live and this call owns it.
    unsafe { X509_ATTRIBUTE_free(attr) };
    ret
}

/// `void *X509at_get0_data_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *x, const ASN1_OBJECT *obj,
/// int lastpos, int type)` — `crypto/x509/x509_att.c:241`.
///
/// The two negative `lastpos` thresholds are the "must be unique" and "must be single-valued"
/// guards: `<= -2` refuses a second occurrence of the OID, `<= -3` refuses a value set of
/// more than one.
///
/// # Safety
/// `x` must be NULL or a live stack; `obj` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509at_get0_data_by_OBJ(
    x: *const OpenSslStack,
    obj: *const Asn1Object,
    lastpos: c_int,
    type_: c_int,
) -> *mut c_void {
    // SAFETY: `x` is NULL or a live stack and `obj` is live.
    let i = unsafe { X509at_get_attr_by_OBJ(x, obj, lastpos) };
    if i == -1 {
        return ptr::null_mut();
    }
    if lastpos <= -2 {
        // SAFETY: as above.
        if unsafe { X509at_get_attr_by_OBJ(x, obj, i) } != -1 {
            return ptr::null_mut();
        }
    }
    // SAFETY: `x` is NULL or a live stack.
    let at = unsafe { X509at_get_attr(x, i) };
    if lastpos <= -3 {
        // SAFETY: `at` is live when the lookup above answered non-NULL.
        if unsafe { X509_ATTRIBUTE_count(at) } != 1 {
            return ptr::null_mut();
        }
    }
    // SAFETY: `at` is live when reached.
    unsafe { X509_ATTRIBUTE_get0_data(at, 0, type_, ptr::null_mut()) }
}

/// `STACK_OF(X509_ATTRIBUTE) *ossl_x509at_dup(const STACK_OF(X509_ATTRIBUTE) *x)` —
/// `crypto/x509/x509_att.c:257`.
///
/// A deep copy: each attribute is appended through the guarded `X509at_add1_attr`, so a
/// duplicate OID aborts the copy and releases what was built.
///
/// # Safety
/// `x` must be NULL or a live stack.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509at_dup(x: *const OpenSslStack) -> *mut OpenSslStack {
    let mut sk: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `x` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(x) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is in range and the stack holds `X509_ATTRIBUTE` elements.
        let value = unsafe { OPENSSL_sk_value(x, i) }.cast::<X509Attribute>();
        // SAFETY: `sk` is this call's slot and `value` is live.
        if unsafe { X509at_add1_attr(&mut sk, value) }.is_null() {
            // SAFETY: `sk` is NULL or a stack this call built.
            unsafe { OPENSSL_sk_pop_free(sk, Some(free_x509_attribute)) };
            return ptr::null_mut();
        }
        i += 1;
    }
    sk
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid, int atrtype,
/// const void *data, int len)` — `crypto/x509/x509_att.c:271`.
///
/// An unknown `nid` raises `X509_R_UNKNOWN_NID` before anything is allocated.
///
/// # Safety
/// `attr` must be NULL or a writable slot; `data` must be the pointer type `atrtype` names.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_NID(
    attr: *mut *mut X509Attribute,
    nid: c_int,
    atrtype: c_int,
    data: *const c_void,
    len: c_int,
) -> *mut X509Attribute {
    // SAFETY: `OBJ_nid2obj` takes an integer and answers a static object or NULL.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_279) };
        return ptr::null_mut();
    }
    // SAFETY: `attr` is NULL or a writable slot; `obj` is live; `data` is the caller's.
    let ret = unsafe { X509_ATTRIBUTE_create_by_OBJ(attr, obj, atrtype, data, len) };
    if ret.is_null() {
        // SAFETY: `obj` is a static table entry and `ASN1_OBJECT_free` respects its flag.
        unsafe { ASN1_OBJECT_free(obj) };
    }
    ret
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr, const ASN1_OBJECT *obj,
/// int atrtype, const void *data, int len)` — `crypto/x509/x509_att.c:288`.
///
/// The caller's existing attribute is reused when one is supplied, so the failure path frees
/// only what this call allocated — the test is pointer identity, as everywhere in this layer.
///
/// # Safety
/// `attr` must be NULL or a writable slot; `obj` must be live; `data` must be the pointer type
/// `atrtype` names.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_OBJ(
    attr: *mut *mut X509Attribute,
    obj: *const Asn1Object,
    atrtype: c_int,
    data: *const c_void,
    len: c_int,
) -> *mut X509Attribute {
    let reuse = !attr.is_null()
        && !(
            // SAFETY: `attr` is non-NULL here, so reading its slot is the caller's contract.
            unsafe { *attr }
        )
        .is_null();
    let ret = if !reuse {
        // SAFETY: no preconditions.
        let fresh = X509_ATTRIBUTE_new();
        if fresh.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_ATT_297) };
            return ptr::null_mut();
        }
        fresh
    } else {
        // SAFETY: `attr` is non-NULL and `*attr` is live.
        unsafe { *attr }
    };

    let ok = 'body: {
        // SAFETY: `ret` is live and `obj` is live.
        if unsafe { X509_ATTRIBUTE_set1_object(ret, obj) } == 0 {
            break 'body false;
        }
        // SAFETY: `ret` is live and `data` is the caller's.
        if unsafe { X509_ATTRIBUTE_set1_data(ret, atrtype, data, len) } == 0 {
            break 'body false;
        }
        if !attr.is_null() {
            // SAFETY: `attr` is a writable slot.
            if unsafe { *attr }.is_null() {
                // SAFETY: `attr` is writable.
                unsafe { *attr = ret };
            }
        }
        true
    };
    if !ok {
        // SAFETY: `attr` is NULL or a live slot.
        if attr.is_null() || unsafe { *attr } != ret {
            // SAFETY: `ret` is a live attribute this call owns.
            unsafe { X509_ATTRIBUTE_free(ret) };
        }
        return ptr::null_mut();
    }
    ret
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr, const char *atrname,
/// int type, const unsigned char *bytes, int len)` — `crypto/x509/x509_att.c:318`.
///
/// The name is resolved with `OBJ_txt2obj(atrname, 0)` — numeric or short-name, not
/// "no_name" — and the temporary object is released whichever way the constructor goes.
///
/// # Safety
/// `attr` must be NULL or a writable slot; `atrname` must be a NUL-terminated string; `bytes`
/// must be the pointer type `type` names.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create_by_txt(
    attr: *mut *mut X509Attribute,
    atrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut X509Attribute {
    // SAFETY: `atrname` is a NUL-terminated string per the contract.
    let obj = unsafe { OBJ_txt2obj(atrname, 0) };
    if obj.is_null() {
        let mut msg = [0 as c_char; 80];
        // SAFETY: `msg` is an 80-byte buffer and the format is the authority's.
        unsafe { BIO_snprintf(msg.as_mut_ptr(), msg.len(), c"name=%s".as_ptr(), atrname) };
        // SAFETY: a compile-time-constant site; the message is NUL-terminated.
        unsafe { raise_site_data(&err_sites::X509_ATT_327, msg.as_ptr()) };
        return ptr::null_mut();
    }
    // SAFETY: `attr` is NULL or a writable slot; `obj` is live; `bytes`/`len` are the caller's.
    let nattr = unsafe { X509_ATTRIBUTE_create_by_OBJ(attr, obj, type_, bytes.cast(), len) };
    // SAFETY: `obj` is a fresh object this call owns.
    unsafe { ASN1_OBJECT_free(obj) };
    nattr
}

/// `int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj)` —
/// `crypto/x509/x509_att.c:336`.
///
/// The attribute's current object is released **before** the copy, so a failed `OBJ_dup`
/// leaves it NULL rather than stale.
///
/// # Safety
/// `attr` must be NULL or live; `obj` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_set1_object(
    attr: *mut X509Attribute,
    obj: *const Asn1Object,
) -> c_int {
    if attr.is_null() || obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_339) };
        return 0;
    }
    // SAFETY: `attr` is live.
    unsafe {
        ASN1_OBJECT_free((*attr).object);
        (*attr).object = OBJ_dup(obj);
        c_int::from(!(*attr).object.is_null())
    }
}

/// `int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype, const void *data,
/// int len)` — `crypto/x509/x509_att.c:347`.
///
/// Three shapes: an `MBSTRING_*` selector is converted through
/// `ASN1_STRING_set_by_NID`; a non-negative `len` copies `data` into a fresh `ASN1_STRING`; and
/// `len == -1` with no multi-byte flag makes `ASN1_TYPE_set1` duplicate the value itself. The
/// `attrtype == 0` arm stores nothing and answers 1.
///
/// # Safety
/// `attr` must be NULL or live; `data` must be readable for `len` bytes or the pointer type
/// `attrtype` names.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_set1_data(
    attr: *mut X509Attribute,
    attrtype: c_int,
    data: *const c_void,
    len: c_int,
) -> c_int {
    if attr.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_355) };
        return 0;
    }
    let mut ttmp: *mut Asn1Type = ptr::null_mut();
    let mut stmp: *mut Asn1String = ptr::null_mut();
    let mut atype = 0;

    if (attrtype & MBSTRING_FLAG) != 0 {
        // SAFETY: `attr` is live and `data`/`len` are the caller's; the out-slot is NULL so
        // the constructor builds and returns the string.
        stmp = unsafe {
            ASN1_STRING_set_by_NID(
                ptr::null_mut(),
                data.cast::<c_uchar>(),
                len,
                attrtype,
                OBJ_obj2nid((*attr).object),
            )
        };
        if stmp.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_ATT_362) };
            return 0;
        }
        // SAFETY: `stmp` is live.
        atype = unsafe { (*stmp).type_ };
    } else if len != -1 {
        // SAFETY: no preconditions.
        stmp = ASN1_STRING_type_new(attrtype);
        // SAFETY: `stmp` is NULL or live; `data`/`len` are the caller's.
        if stmp.is_null() || unsafe { ASN1_STRING_set(stmp, data, len) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_ATT_369) };
            // SAFETY: `ttmp` is NULL and `stmp` is NULL or this call's own.
            return unsafe { set1_data_err(ttmp, stmp) };
        }
        atype = attrtype;
    }
    if attrtype == 0 {
        // SAFETY: `stmp` is NULL or this call's own.
        unsafe { ASN1_STRING_free(stmp) };
        return 1;
    }
    // SAFETY: no preconditions.
    ttmp = ASN1_TYPE_new();
    if ttmp.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_384) };
        // SAFETY: `stmp` is NULL or this call's own.
        return unsafe { set1_data_err(ttmp, stmp) };
    }
    if len == -1 && (attrtype & MBSTRING_FLAG) == 0 {
        // SAFETY: `ttmp` is live and `data` is the caller's pointer for `attrtype`.
        if unsafe { ASN1_TYPE_set1(ttmp, attrtype, data) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::X509_ATT_389) };
            // SAFETY: `ttmp` is this call's own and `stmp` is NULL here.
            return unsafe { set1_data_err(ttmp, stmp) };
        }
    } else {
        // SAFETY: `ttmp` is live; `stmp` is adopted (or NULL when `len == -1`), so it is
        // cleared afterwards and not released by the failure path.
        unsafe { ASN1_TYPE_set(ttmp, atype, stmp.cast::<c_void>()) };
        stmp = ptr::null_mut();
    }
    // SAFETY: `attr` is live and its `set` is the stack the item layer allocated.
    if unsafe { OPENSSL_sk_push((*attr).set, ttmp.cast()) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_397) };
        // SAFETY: `ttmp` is this call's own and `stmp` is NULL here.
        return unsafe { set1_data_err(ttmp, stmp) };
    }
    1
}

/// The authority's `err:` label — `x509_att.c:401-404`.
///
/// # Safety
/// `ttmp` and `stmp` must each be NULL or a value this call owns.
unsafe fn set1_data_err(ttmp: *mut Asn1Type, stmp: *mut Asn1String) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_TYPE_free(ttmp) };
    // SAFETY: the caller's contract.
    unsafe { ASN1_STRING_free(stmp) };
    0
}

/// `int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr)` — `crypto/x509/x509_att.c:407`.
///
/// A NULL attribute answers 0 rather than raising.
///
/// # Safety
/// `attr` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_count(attr: *const X509Attribute) -> c_int {
    if attr.is_null() {
        return 0;
    }
    // SAFETY: `attr` is live and its `set` is a live stack.
    unsafe { OPENSSL_sk_num((*attr).set) }
}

/// `ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr)` —
/// `crypto/x509/x509_att.c:414`.
///
/// # Safety
/// `attr` must be NULL or live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_object(attr: *mut X509Attribute) -> *mut Asn1Object {
    if attr.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_417) };
        return ptr::null_mut();
    }
    // SAFETY: `attr` is live.
    unsafe { (*attr).object }
}

/// `void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atrtype, void *data)` —
/// `crypto/x509/x509_att.c:423`.
///
/// The type must match exactly, and `BOOLEAN`/`NULL` are refused outright because neither
/// stores a pointer the caller could receive.
///
/// # Safety
/// `attr` must be NULL or live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_data(
    attr: *mut X509Attribute,
    idx: c_int,
    atrtype: c_int,
    data: *mut c_void,
) -> *mut c_void {
    let _ = data;
    // SAFETY: `attr` is NULL or live.
    let ttmp = unsafe { X509_ATTRIBUTE_get0_type(attr, idx) };
    if ttmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ttmp` is live.
    let stored = unsafe { ASN1_TYPE_get(ttmp) };
    if atrtype == V_ASN1_BOOLEAN || atrtype == V_ASN1_NULL || atrtype != stored {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_433) };
        return ptr::null_mut();
    }
    // SAFETY: `ttmp` is live and its union holds a pointer for a pointer type.
    unsafe { (*ttmp).value.ptr }
}

/// `ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx)` —
/// `crypto/x509/x509_att.c:439`.
///
/// # Safety
/// `attr` must be NULL or live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_get0_type(
    attr: *mut X509Attribute,
    idx: c_int,
) -> *mut Asn1Type {
    if attr.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509_ATT_442) };
        return ptr::null_mut();
    }
    // SAFETY: `attr` is live and its `set` is a live stack of `ASN1_TYPE`.
    unsafe { OPENSSL_sk_value((*attr).set, idx) }.cast::<Asn1Type>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_long;

    /// `X509_ATTRIBUTE_create_by_NID` builds an attribute, the guarded `X509at_add1_attr`
    /// pushes it onto an initially-NULL stack, a second attribute with the same OID is
    /// refused, and the value comes back through the readers. The value is a small integer
    /// literal the probe chose, so nothing random or private is touched.
    #[test]
    fn add1_then_read_back_and_refuse_the_duplicate() {
        /* A one-octet integer content, which is what `ASN1_STRING_set` stores for an
         * `V_ASN1_INTEGER`: the big-endian two's-complement magnitude. */
        let value: [c_uchar; 1] = [7];
        // SAFETY: the buffer is one readable octet and the constructor copies it.
        let attr = unsafe {
            X509_ATTRIBUTE_create_by_NID(
                ptr::null_mut(),
                crate::runtime::obj::NID_commonName,
                V_ASN1_INTEGER,
                value.as_ptr().cast(),
                1,
            )
        };
        assert!(!attr.is_null());

        let mut sk: *mut OpenSslStack = ptr::null_mut();
        // SAFETY: `sk` is this frame's slot and `attr` is live.
        let pushed = unsafe { X509at_add1_attr(&mut sk, attr) };
        assert!(!pushed.is_null() && pushed == sk);
        // SAFETY: `sk` is live and holds one attribute.
        unsafe { assert_eq!(X509at_get_attr_count(sk), 1) };

        // A second attribute with the same OID is refused while the stack is non-NULL.
        // SAFETY: the buffer is one readable octet and the constructor copies it.
        let dup = unsafe {
            X509_ATTRIBUTE_create_by_NID(
                ptr::null_mut(),
                crate::runtime::obj::NID_commonName,
                V_ASN1_INTEGER,
                value.as_ptr().cast(),
                1,
            )
        };
        assert!(!dup.is_null());
        // SAFETY: `sk` is this frame's slot and `dup` is live.
        let refused = unsafe { X509at_add1_attr(&mut sk, dup) };
        assert!(refused.is_null());

        // The reader answers the borrowed value for the requested type.
        // SAFETY: the stack holds the attribute created above.
        let at = unsafe { X509at_get_attr(sk, 0) };
        assert!(!at.is_null());
        // SAFETY: `at` is live and holds one value.
        let got = unsafe { X509_ATTRIBUTE_get0_data(at, 0, V_ASN1_INTEGER, ptr::null_mut()) };
        assert!(!got.is_null());
        // SAFETY: the answer is an `ASN1_INTEGER` carrying the constant.
        unsafe {
            assert_eq!(
                crate::asn1::prim::ASN1_INTEGER_get(got.cast()),
                c_long::from(value[0])
            )
        };

        // The wrong type is refused.
        // SAFETY: `at` is live.
        let wrong =
            unsafe { X509_ATTRIBUTE_get0_data(at, 0, V_ASN1_OCTET_STRING, ptr::null_mut()) };
        assert!(wrong.is_null());

        // SAFETY: `sk`, `attr` and `dup` are this frame's own.
        unsafe {
            X509_ATTRIBUTE_free(attr);
            X509_ATTRIBUTE_free(dup);
            OPENSSL_sk_pop_free(sk, Some(free_x509_attribute));
        }
    }
}
