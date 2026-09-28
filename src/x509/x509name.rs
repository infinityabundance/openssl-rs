//! Phase 10.11 — `crypto/x509/x509name.c`: the `X509_NAME` convenience entry points, whole.
//!
//! The unit publishes eighteen functions and all eighteen land here: the value lookups
//! (`X509_NAME_get_text_by_NID`/`_by_OBJ`), the count and index searches
//! (`X509_NAME_entry_count`, `X509_NAME_get_index_by_NID`/`_by_OBJ`), the entry accessors
//! (`X509_NAME_get_entry`, `X509_NAME_delete_entry`), the four `add_entry` spellings and the
//! `add_entry_by_{OBJ,NID,txt}` wrappers over them, and the `X509_NAME_ENTRY` constructors and
//! field accessors (`X509_NAME_ENTRY_create_by_{OBJ,NID,txt}`, `_set_object`, `_set_data`,
//! `_get_object`, `_get_data`, `_set`).
//!
//! `x_name.c` (10.8/10.10) owns the `X509_NAME`/`X509_NAME_ENTRY` **object model and its item**;
//! this unit is the *convenience* layer over that model, which is why it is `x509name.c` and not
//! `x_name.c`. Nothing is withheld: `X509_NAME_ENTRY_new`/`_free`/`_dup` are `x_name.rs`'s,
//! `OBJ_txt2obj`/`OBJ_nid2obj`/`OBJ_cmp`/`OBJ_dup`/`OBJ_obj2nid` are the object database's, and
//! `ASN1_STRING_set`/`ASN1_STRING_set_by_NID`/`ASN1_PRINTABLE_type` are the string layer's.
//!
//! ## `add_entry` is where the RDN `set` numbering lives
//!
//! Every entry carries a `set` number: entries with the same number are one multi-valued RDN
//! (printed joined by `+`), and a differing number starts a new RDN. `X509_NAME_add_entry`
//! computes the new entry's number from its `set` argument and the position, and when it inserts
//! a **new** RDN (`inc`) it renumbers every following entry up by one. Getting this wrong is not
//! visible in a single-entry DN and is exactly what the `, ` vs `+` separator in
//! `X509_NAME_print_ex` observes -- which is why the court drives a two-entry and a plus-joined
//! name rather than a lone `CN`.
//!
//! ## `delete_entry`'s set fixup mirrors `add_entry`'s
//!
//! Removing an entry can leave two adjacent runs of equal `set` numbers that were one run before
//! the removal; the fixup renumbers down by one only when the previous and next numbers differ
//! by more than one (`set_prev + 1 < set_next`), which is the authority's own four-line comment
//! at `:125-134`.
//!
//! ## The raise sites
//!
//! Four `ERR_raise*` sites in the unit. `crypto/x509/x509name.c` joins
//! `gen_err_raise_sites.py`'s covered set with this subphase under the stem `X509NAME` (distinct
//! from `x_name.c`'s `X509_NAME` so line numbers cannot collide): `ERR_LIB_X509` with
//! `ERR_R_CRYPTO_LIB`, `ERR_R_PASSED_NULL_PARAMETER`, `X509_R_INVALID_FIELD_NAME` (through
//! `ERR_raise_data`) and `X509_R_UNKNOWN_NID`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_print::ASN1_PRINTABLE_type;
use crate::asn1::a_strnid::ASN1_STRING_set_by_NID;
use crate::asn1::layout::*;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::ASN1_STRING_set;
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::obj::{Asn1Object, OBJ_cmp, OBJ_dup, OBJ_nid2obj, OBJ_obj2nid, OBJ_txt2obj};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_insert, OPENSSL_sk_num, OPENSSL_sk_value,
};
use crate::x509::x_name::{
    X509Name, X509NameEntry, X509_NAME_ENTRY_dup, X509_NAME_ENTRY_free, X509_NAME_ENTRY_new,
};

/// `int X509_NAME_get_text_by_NID(const X509_NAME *name, int nid, char *buf, int len)` —
/// `crypto/x509/x509name.c:19-28`.
///
/// # Safety
///
/// `name` must be NULL or live; `buf` must be NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_text_by_NID(
    name: *const X509Name,
    nid: c_int,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `OBJ_nid2obj` takes an integer NID.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -1;
    }
    // SAFETY: `name` is NULL or live; `obj` is live; `buf`/`len` are the caller's.
    unsafe { X509_NAME_get_text_by_OBJ(name, obj, buf, len) }
}

/// `int X509_NAME_get_text_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj, char *buf,
/// int len)` — `crypto/x509/x509name.c:30-48`.
///
/// With a NULL `buf` this is a length query; with a non-NULL `buf` it copies at most `len - 1`
/// bytes and NUL-terminates. A `len` of zero or less is a refusal that answers 0, not an error.
///
/// # Safety
///
/// `name` must be NULL or live; `obj` live; `buf` NULL or writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_text_by_OBJ(
    name: *const X509Name,
    obj: *const Asn1Object,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    // SAFETY: `name` is NULL or live and `obj` is live.
    let i = unsafe { X509_NAME_get_index_by_OBJ(name, obj, -1) };
    if i < 0 {
        return -1;
    }
    // SAFETY: `i` is a valid entry index; `name` is non-NULL (the index was found) and live.
    let data = unsafe { X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i)) };
    if buf.is_null() {
        // SAFETY: `data` is a live entry value.
        return unsafe { (*data).length };
    }
    if len <= 0 {
        return 0;
    }
    // SAFETY: `data` is a live entry value.
    let dl = unsafe { (*data).length };
    let i = if dl > len - 1 { len - 1 } else { dl };
    // SAFETY: `buf` is writable for `len` bytes and `i <= len - 1`; the source is readable for
    // `i` bytes.
    unsafe {
        ptr::copy_nonoverlapping((*data).data, buf.cast::<c_uchar>(), i as usize);
        *buf.add(i as usize) = 0;
    }
    i
}

/// `int X509_NAME_entry_count(const X509_NAME *name)` — `crypto/x509/x509name.c:50-58`.
///
/// # Safety
///
/// `name` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_entry_count(name: *const X509Name) -> c_int {
    if name.is_null() {
        return 0;
    }
    // SAFETY: `name` is non-NULL and live per the contract.
    let ret = unsafe { OPENSSL_sk_num((*name).entries) };
    if ret > 0 {
        ret
    } else {
        0
    }
}

/// `int X509_NAME_get_index_by_NID(const X509_NAME *name, int nid, int lastpos)` —
/// `crypto/x509/x509name.c:60-68`.
///
/// # Safety
///
/// `name` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_index_by_NID(
    name: *const X509Name,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `OBJ_nid2obj` takes an integer NID.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        return -2;
    }
    // SAFETY: `name` is NULL or live; `obj` is live.
    unsafe { X509_NAME_get_index_by_OBJ(name, obj, lastpos) }
}

/// `int X509_NAME_get_index_by_OBJ(const X509_NAME *name, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/x509/x509name.c:71-90`.
///
/// The authority's own note at `:70` is kept: pass `-1`, not `0`, for the first search, because
/// the loop increments before testing. A `lastpos` below `-1` is clamped to `-1`.
///
/// # Safety
///
/// `name` must be NULL or live; `obj` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_index_by_OBJ(
    name: *const X509Name,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    if name.is_null() {
        return -1;
    }
    let mut lastpos = if lastpos < 0 { -1 } else { lastpos };
    // SAFETY: `name` is non-NULL and live per the contract.
    let sk = unsafe { (*name).entries };
    // SAFETY: `sk` is the name's always-non-NULL entry stack.
    let n = unsafe { OPENSSL_sk_num(sk) };
    lastpos += 1;
    while lastpos < n {
        // SAFETY: `lastpos` is within `0..n`.
        let ne = unsafe { OPENSSL_sk_value(sk, lastpos) }.cast::<X509NameEntry>();
        // SAFETY: every element is an `X509_NAME_ENTRY`; `obj` is live.
        if unsafe { OBJ_cmp((*ne).object, obj) } == 0 {
            return lastpos;
        }
        lastpos += 1;
    }
    -1
}

/// `X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc)` —
/// `crypto/x509/x509name.c:92-99`.
///
/// # Safety
///
/// `name` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_get_entry(
    name: *const X509Name,
    loc: c_int,
) -> *mut X509NameEntry {
    if name.is_null()
        // SAFETY: `name` is non-NULL and live per the contract.
        || unsafe { OPENSSL_sk_num((*name).entries) } <= loc
        || loc < 0
    {
        return ptr::null_mut();
    }
    // SAFETY: `0 <= loc < num` per the guard above and `name` is live.
    unsafe { OPENSSL_sk_value((*name).entries, loc) }.cast::<X509NameEntry>()
}

/// `X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc)` —
/// `crypto/x509/x509name.c:101-139`.
///
/// Removes the entry, marks the name modified, and fixes up the `set` numbering of the entries
/// that followed it; see the module documentation for the fixup's condition. The removed entry
/// is returned and the caller owns it.
///
/// # Safety
///
/// `name` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_delete_entry(
    name: *mut X509Name,
    loc: c_int,
) -> *mut X509NameEntry {
    if name.is_null()
        // SAFETY: `name` is non-NULL and live per the contract.
        || unsafe { OPENSSL_sk_num((*name).entries) } <= loc
        || loc < 0
    {
        return ptr::null_mut();
    }

    // SAFETY: `name` is live.
    let sk = unsafe { (*name).entries };
    // SAFETY: `sk` is live and `0 <= loc < num`.
    let ret = unsafe { OPENSSL_sk_delete(sk, loc) }.cast::<X509NameEntry>();
    // SAFETY: `sk` is live.
    let n = unsafe { OPENSSL_sk_num(sk) };
    // SAFETY: `name` is live and writable.
    unsafe { (*name).modified = 1 };
    if loc == n {
        return ret;
    }

    // SAFETY: `ret` is the entry just removed and is live.
    let set_prev = if loc != 0 {
        // SAFETY: `loc - 1` is within `0..n`.
        let e = unsafe { OPENSSL_sk_value(sk, loc - 1) }.cast::<X509NameEntry>();
        // SAFETY: `e` is a live entry.
        unsafe { (*e).set }
    } else {
        // SAFETY: `ret` is live.
        unsafe { (*ret).set - 1 }
    };
    // SAFETY: `loc` is within `0..n` (the `loc == n` case returned above).
    let e_next = unsafe { OPENSSL_sk_value(sk, loc) }.cast::<X509NameEntry>();
    // SAFETY: `e_next` is a live entry.
    let set_next = unsafe { (*e_next).set };

    // `set_prev + 1 < set_next` is the only case where the runs on either side of the removed
    // entry are still distinct and every following entry must move down by one.
    if set_prev + 1 < set_next {
        let mut i = loc;
        while i < n {
            // SAFETY: `i` is within `0..n`.
            let e = unsafe { OPENSSL_sk_value(sk, i) }.cast::<X509NameEntry>();
            // SAFETY: every element is an `X509_NAME_ENTRY`, live and writable.
            unsafe { (*e).set -= 1 };
            i += 1;
        }
    }
    ret
}

/// `int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
/// const unsigned char *bytes, int len, int loc, int set)` —
/// `crypto/x509/x509name.c:141-154`.
///
/// Builds a temporary entry, adds it, and releases the temporary; the name holds a duplicate.
///
/// # Safety
///
/// `name` must be live; `obj` live; `bytes` readable for `len` bytes or NULL when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_OBJ(
    name: *mut X509Name,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
    loc: c_int,
    set: c_int,
) -> c_int {
    // SAFETY: `obj` is live and `bytes`/`len` describe a readable range.
    let ne = unsafe { X509_NAME_ENTRY_create_by_OBJ(ptr::null_mut(), obj, type_, bytes, len) };
    if ne.is_null() {
        return 0;
    }
    // SAFETY: `name` is live; `ne` is this call's own.
    let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
    // SAFETY: `ne` is this call's own temporary.
    unsafe { X509_NAME_ENTRY_free(ne) };
    ret
}

/// `int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, const unsigned char
/// *bytes, int len, int loc, int set)` — `crypto/x509/x509name.c:156-168`.
///
/// # Safety
///
/// `name` must be live; `bytes` readable for `len` bytes or NULL when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_NID(
    name: *mut X509Name,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
    loc: c_int,
    set: c_int,
) -> c_int {
    // SAFETY: no preconditions on `nid`; `bytes`/`len` describe a readable range.
    let ne = unsafe { X509_NAME_ENTRY_create_by_NID(ptr::null_mut(), nid, type_, bytes, len) };
    if ne.is_null() {
        return 0;
    }
    // SAFETY: `name` is live; `ne` is this call's own.
    let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
    // SAFETY: `ne` is this call's own temporary.
    unsafe { X509_NAME_ENTRY_free(ne) };
    ret
}

/// `int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned
/// char *bytes, int len, int loc, int set)` — `crypto/x509/x509name.c:170-182`.
///
/// # Safety
///
/// `name` must be live; `field` a NUL-terminated string; `bytes` readable for `len` bytes or NULL
/// when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry_by_txt(
    name: *mut X509Name,
    field: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
    loc: c_int,
    set: c_int,
) -> c_int {
    // SAFETY: `field` is NUL-terminated; `bytes`/`len` describe a readable range.
    let ne = unsafe { X509_NAME_ENTRY_create_by_txt(ptr::null_mut(), field, type_, bytes, len) };
    if ne.is_null() {
        return 0;
    }
    // SAFETY: `name` is live; `ne` is this call's own.
    let ret = unsafe { X509_NAME_add_entry(name, ne, loc, set) };
    // SAFETY: `ne` is this call's own temporary.
    unsafe { X509_NAME_ENTRY_free(ne) };
    ret
}

/// `int X509_NAME_add_entry(X509_NAME *name, const X509_NAME_ENTRY *ne, int loc, int set)` —
/// `crypto/x509/x509name.c:188-240`.
///
/// Adds a duplicate of `ne` at the clamped `loc`, computing the new entry's RDN `set` number from
/// the argument and the neighbouring entries, and renumbering the following entries when a new
/// RDN is opened. The authority's comment at `:184-187` is the specification of the `set`
/// argument: `-1` appends to the previous set, `0` starts a new one, `1` prepends to the entry
/// about to be displaced.
///
/// # Safety
///
/// `name` must be NULL or live; `ne` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_add_entry(
    name: *mut X509Name,
    ne: *const X509NameEntry,
    loc: c_int,
    set: c_int,
) -> c_int {
    if name.is_null() {
        return 0;
    }
    // SAFETY: `name` is non-NULL and live per the contract.
    let sk = unsafe { (*name).entries };
    // SAFETY: `sk` is live.
    let n = unsafe { OPENSSL_sk_num(sk) };
    // The authority clamps both `loc > n` and `loc < 0` to `n` (an append).
    let loc = if loc > n || loc < 0 { n } else { loc };
    let mut inc = c_int::from(set == 0);
    // SAFETY: `name` is live and writable.
    unsafe { (*name).modified = 1 };
    let mut set = set;

    if set == -1 {
        if loc == 0 {
            set = 0;
            inc = 1;
        } else {
            // SAFETY: `loc - 1` is within `0..n`.
            let e = unsafe { OPENSSL_sk_value(sk, loc - 1) }.cast::<X509NameEntry>();
            // SAFETY: `e` is a live entry.
            set = unsafe { (*e).set };
        }
    } else {
        // if (set >= 0)
        if loc >= n {
            if loc != 0 {
                // SAFETY: `loc - 1` is within `0..n`.
                let e = unsafe { OPENSSL_sk_value(sk, loc - 1) }.cast::<X509NameEntry>();
                // SAFETY: `e` is a live entry.
                set = unsafe { (*e).set + 1 };
            } else {
                set = 0;
            }
        } else {
            // SAFETY: `loc` is within `0..n`.
            let e = unsafe { OPENSSL_sk_value(sk, loc) }.cast::<X509NameEntry>();
            // SAFETY: `e` is a live entry.
            set = unsafe { (*e).set };
        }
    }

    // SAFETY: `ne` is live per the contract.
    let new_name = unsafe { X509_NAME_ENTRY_dup(ne) };
    if new_name.is_null() {
        return 0;
    }
    // SAFETY: `new_name` is this call's own duplicate.
    unsafe { (*new_name).set = set };
    // SAFETY: `sk` is live and `loc` is within `0..=n`; `new_name` is this call's own.
    if unsafe { OPENSSL_sk_insert(sk, new_name.cast::<c_void>(), loc) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509NAME_228) };
        // SAFETY: `new_name` is this call's own duplicate.
        unsafe { X509_NAME_ENTRY_free(new_name) };
        return 0;
    }
    if inc != 0 {
        // SAFETY: `sk` is live.
        let n = unsafe { OPENSSL_sk_num(sk) };
        let mut i = loc + 1;
        while i < n {
            // SAFETY: `i` is within `0..n`.
            let e = unsafe { OPENSSL_sk_value(sk, i) }.cast::<X509NameEntry>();
            // SAFETY: every element is a live, writable `X509_NAME_ENTRY`.
            unsafe { (*e).set += 1 };
            i += 1;
        }
    }
    1
}

/// `X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne, const char *field,
/// int type, const unsigned char *bytes, int len)` — `crypto/x509/x509name.c:242-259`.
///
/// The field name goes through `OBJ_txt2obj`; an unknown one raises
/// `X509_R_INVALID_FIELD_NAME` **with the name in the data string**, which is why the raise is
/// `ERR_raise_data` and not `ERR_raise`.
///
/// # Safety
///
/// `ne` must be NULL or point at a writable entry slot; `field` a NUL-terminated string; `bytes`
/// readable for `len` bytes or NULL when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_txt(
    ne: *mut *mut X509NameEntry,
    field: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut X509NameEntry {
    // SAFETY: `field` is NUL-terminated per the contract.
    let obj = unsafe { OBJ_txt2obj(field, 0) };
    if obj.is_null() {
        let mut msg = [0 as c_char; 256];
        // SAFETY: `msg` is a live buffer and the format/argument are the authority's.
        unsafe {
            crate::runtime::bio::print::BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"name=%s".as_ptr(),
                field,
            )
        };
        // SAFETY: a compile-time-constant site; `msg` is NUL-terminated.
        unsafe { raise_site_data(&err_sites::X509NAME_252, msg.as_ptr()) };
        return ptr::null_mut();
    }
    // SAFETY: `ne` is NULL or writable; `obj`/`bytes`/`len` are the caller's.
    let nentry = unsafe { X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_, bytes, len) };
    // SAFETY: `obj` came from `OBJ_txt2obj` and is this call's own.
    unsafe { ASN1_OBJECT_free(obj) };
    nentry
}

/// `X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid, int type,
/// const unsigned char *bytes, int len)` — `crypto/x509/x509name.c:261-277`.
///
/// # Safety
///
/// `ne` must be NULL or point at a writable entry slot; `bytes` readable for `len` bytes or NULL
/// when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_NID(
    ne: *mut *mut X509NameEntry,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut X509NameEntry {
    // SAFETY: `OBJ_nid2obj` takes an integer NID.
    let obj = OBJ_nid2obj(nid);
    if obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509NAME_271) };
        return ptr::null_mut();
    }
    // SAFETY: `ne` is NULL or writable; `obj`/`bytes`/`len` are the caller's.
    let nentry = unsafe { X509_NAME_ENTRY_create_by_OBJ(ne, obj, type_, bytes, len) };
    // SAFETY: `obj` came from `OBJ_nid2obj` and its reference is dropped here.
    unsafe { ASN1_OBJECT_free(obj) };
    nentry
}

/// `X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne, const ASN1_OBJECT *obj,
/// int type, const unsigned char *bytes, int len)` — `crypto/x509/x509name.c:279-304`.
///
/// # Safety
///
/// `ne` must be NULL or point at a writable entry slot; `obj` live; `bytes` readable for `len`
/// bytes or NULL when `len` is zero.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_create_by_OBJ(
    ne: *mut *mut X509NameEntry,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> *mut X509NameEntry {
    let ret: *mut X509NameEntry;

    if ne.is_null()
        // SAFETY: `ne` may be NULL; a non-NULL `ne` is a readable slot per the contract.
        || unsafe { (*ne).is_null() }
    {
        // SAFETY: no preconditions.
        ret = X509_NAME_ENTRY_new();
        if ret.is_null() {
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `ne` is non-NULL and its slot is non-NULL per the guard above.
        ret = unsafe { *ne };
    }

    // SAFETY: `ret`/`obj` are live.
    if unsafe { X509_NAME_ENTRY_set_object(ret, obj) } == 0
        // SAFETY: `ret` is live; `bytes`/`len` are the caller's.
        || unsafe { X509_NAME_ENTRY_set_data(ret, type_, bytes, len) } == 0
    {
        // SAFETY: `ne` may be NULL; `*ne` is read only when `ne` is non-NULL.
        if ne.is_null() || unsafe { ret != *ne } {
            // SAFETY: `ret` is this call's own fresh entry in that case.
            unsafe { X509_NAME_ENTRY_free(ret) };
        }
        return ptr::null_mut();
    }

    // SAFETY: `ne` may be NULL; `*ne` is read only when `ne` is non-NULL.
    if !ne.is_null() && unsafe { (*ne).is_null() } {
        // SAFETY: `ne` is writable per the contract.
        unsafe { *ne = ret };
    }
    ret
}

/// `int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne, const ASN1_OBJECT *obj)` —
/// `crypto/x509/x509name.c:306-315`.
///
/// Unlike `X509_EXTENSION_set_object`, this one raises `ERR_R_PASSED_NULL_PARAMETER` on a NULL
/// argument.
///
/// # Safety
///
/// `ne`/`obj` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set_object(
    ne: *mut X509NameEntry,
    obj: *const Asn1Object,
) -> c_int {
    if ne.is_null() || obj.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::X509NAME_309) };
        return 0;
    }
    // SAFETY: `ne` is live; its `object` slot is either NULL or the crate's own.
    unsafe {
        ASN1_OBJECT_free((*ne).object);
        (*ne).object = OBJ_dup(obj);
    }
    // SAFETY: `ne` is live.
    c_int::from(!(unsafe { (*ne).object }).is_null())
}

/// `int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type, const unsigned char *bytes,
/// int len)` — `crypto/x509/x509name.c:317-342`.
///
/// A `type` carrying the `MBSTRING_FLAG` bit routes through `ASN1_STRING_set_by_NID` and lets the
/// NID-specific converter choose the string type; otherwise `len < 0` means "`strlen`", a
/// `V_ASN1_APP_CHOOSE` type is resolved by `ASN1_PRINTABLE_type`, and any other non-`V_ASN1_UNDEF`
/// type is written verbatim.
///
/// # Safety
///
/// `ne` must be NULL or live; `bytes` readable for `len` bytes (or NUL-terminated when `len` is
/// negative) and required non-NULL unless `len` is 0.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set_data(
    ne: *mut X509NameEntry,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    if ne.is_null() || (bytes.is_null() && len != 0) {
        return 0;
    }
    if type_ > 0 && (type_ & MBSTRING_FLAG) != 0 {
        // SAFETY: `ne` is live; `bytes`/`len` are the caller's; `ne->object` is live (the
        // authority calls `OBJ_obj2nid` on it unconditionally). The function answers the string
        // it built, or NULL.
        return c_int::from(
            !unsafe {
                ASN1_STRING_set_by_NID(
                    &raw mut (*ne).value,
                    bytes,
                    len,
                    type_,
                    OBJ_obj2nid((*ne).object),
                )
            }
            .is_null(),
        );
    }
    let len = if len < 0 {
        // SAFETY: `bytes` is NUL-terminated when `len` is negative, per the contract.
        unsafe { crate::runtime::str::OPENSSL_strnlen(bytes.cast::<c_char>(), usize::MAX) as c_int }
    } else {
        len
    };
    // SAFETY: `ne` is live; `bytes` is readable for `len` bytes.
    let i = unsafe { ASN1_STRING_set((*ne).value, bytes.cast::<c_void>(), len) };
    if i == 0 {
        return 0;
    }
    if type_ != V_ASN1_UNDEF {
        // SAFETY: `ne` is live and `(*ne).value` is a live string.
        unsafe {
            if type_ == V_ASN1_APP_CHOOSE {
                (*(*ne).value).type_ = ASN1_PRINTABLE_type(bytes, len);
            } else {
                (*(*ne).value).type_ = type_;
            }
        }
    }
    1
}

/// `ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne)` —
/// `crypto/x509/x509name.c:344-349`.
///
/// # Safety
///
/// `ne` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_get_object(ne: *const X509NameEntry) -> *mut Asn1Object {
    if ne.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ne` is live.
    unsafe { (*ne).object }
}

/// `ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne)` —
/// `crypto/x509/x509name.c:351-356`.
///
/// # Safety
///
/// `ne` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_get_data(ne: *const X509NameEntry) -> *mut Asn1String {
    if ne.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ne` is live.
    unsafe { (*ne).value }
}

/// `int X509_NAME_ENTRY_set(const X509_NAME_ENTRY *ne)` — `crypto/x509/x509name.c:358-361`.
///
/// The authority dereferences without a NULL test; so does this transcription.
///
/// # Safety
///
/// `ne` must be a live entry.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_ENTRY_set(ne: *const X509NameEntry) -> c_int {
    // SAFETY: `ne` is live per the contract.
    unsafe { (*ne).set }
}
