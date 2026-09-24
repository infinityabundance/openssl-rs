//! `crypto/x509/x_attrib.c` — the `X509_ATTRIBUTE` family, transcribed whole except its printer.
//!
//! `crypto/x509/x_attrib.c` is 249 lines and 8 exports: the `ASN1_SEQUENCE(X509_ATTRIBUTE)`
//! template and the `IMPLEMENT_ASN1_FUNCTIONS`/`IMPLEMENT_ASN1_DUP_FUNCTION` groups over it
//! (`_it`, `_new`, `_free`, `_dup`, `d2i_`, `i2d_`), the hand-written `X509_ATTRIBUTE_create`
//! (`:37-59`), and `ossl_print_attribute_value` (`:76-249`). It lands here because
//! `crypto/asn1/p8_pkey.c`'s `PKCS8_PRIV_KEY_INFO` template names `X509_ATTRIBUTE_it` for its
//! `attributes` column, which D349 recorded as the block on that item; the cycle it names is
//! gone and the item can be built.
//!
//! ## The layout
//!
//! `X509_ATTRIBUTE` is the two fields the file's own comment spells (`:18-27`):
//! `ASN1_OBJECT *object` then `STACK_OF(ASN1_TYPE) *set`. The `set` column is `ASN1_SET_OF`, so
//! its value is an [`OpenSslStack`] and the decoder sorts it into canonical order.
//!
//! ## What is withheld, with its coordinate
//!
//! `ossl_print_attribute_value` (`:76-249`) is an **internal** printer: a `switch` over every
//! `V_ASN1_*` tag that reaches `ossl_bio_print_hex`, `ASN1_ENUMERATED_get_int64`,
//! `d2i_X509_NAME`, `X509_NAME_print_ex`, `X509_NAME_free` and `ASN1_parse_dump`, of which the
//! two `X509_NAME` names are the X.509 name layer's and unlanded. No landed caller reaches it, so
//! it is withheld as one named block rather than transcribed into six unwired calls. The unit
//! defines exactly this one internal, so that is the whole remainder.
//!
//! ## No raise, and the court
//!
//! The file raises nothing, so it is deliberately **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`. The unit's evidence is `src/asn1/x_attrib_roundtrip.rs`'s sibling test below:
//! `X509_ATTRIBUTE_create` builds the two-field value, `i2d_`/`d2i_` round-trip it, and `_dup`
//! answers a distinct object with the same OID.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_ANY_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::obj::{Asn1Object, OBJ_nid2obj};
use crate::runtime::stack::{OPENSSL_sk_push, OpenSslStack};

/// `struct x509_attributes_st` — `X509_ATTRIBUTE`, from `include/openssl/x509.h`.
///
/// The authority's two fields in order: the attribute's OID and the SET OF its values. The item
/// layer reads the offsets below, so they are asserted rather than typed twice.
#[repr(C)]
pub struct X509Attribute {
    /// `ASN1_OBJECT *object` — the attribute's OID, taken by `X509_ATTRIBUTE_create`.
    pub(crate) object: *mut Asn1Object,
    /// `STACK_OF(ASN1_TYPE) *set` — the values, an `ASN1_SET_OF` column.
    pub(crate) set: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<X509Attribute>() == 16);
    assert!(core::mem::offset_of!(X509Attribute, object) == 0);
    assert!(core::mem::offset_of!(X509Attribute, set) == 8);
};

/// `X509_ATTRIBUTE_seq_tt` — `crypto/x509/x_attrib.c:29-32`'s `ASN1_SEQUENCE(X509_ATTRIBUTE)`:
/// `ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT)` and
/// `ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)`.
static X509_ATTRIBUTE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"object".as_ptr(),
        item: ASN1_OBJECT_it as *mut core::ffi::c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"set".as_ptr(),
        item: ASN1_ANY_it as *mut core::ffi::c_void,
    },
];

/// `X509_ATTRIBUTE_it`'s descriptor — `ASN1_SEQUENCE_END(X509_ATTRIBUTE)` at
/// `crypto/x509/x_attrib.c:32`.
static X509_ATTRIBUTE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ATTRIBUTE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Attribute>() as c_long,
    sname: c"X509_ATTRIBUTE".as_ptr(),
};

/// `const ASN1_ITEM *X509_ATTRIBUTE_it(void)` — `include/openssl/x509.h`, from
/// `ASN1_SEQUENCE_END(X509_ATTRIBUTE)`.
#[no_mangle]
pub extern "C" fn X509_ATTRIBUTE_it() -> *const Asn1Item {
    &X509_ATTRIBUTE_ITEM
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_new(void)` — `crypto/x509/x_attrib.c:34`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)`.
#[no_mangle]
pub extern "C" fn X509_ATTRIBUTE_new() -> *mut X509Attribute {
    // SAFETY: `X509_ATTRIBUTE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_ATTRIBUTE_it()).cast::<X509Attribute>() }
}

/// `void X509_ATTRIBUTE_free(X509_ATTRIBUTE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_free(a: *mut X509Attribute) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_ATTRIBUTE_it()) }
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_dup(const X509_ATTRIBUTE *a)` —
/// `crypto/x509/x_attrib.c:35`, from `IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)`.
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_dup(a: *const X509Attribute) -> *mut X509Attribute {
    // SAFETY: `a` is NULL or live per the contract; `X509_ATTRIBUTE_it()` is a static item.
    unsafe { ASN1_item_dup(X509_ATTRIBUTE_it(), a.cast()).cast::<X509Attribute>() }
}

/// `X509_ATTRIBUTE *d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a, const unsigned char **in, long len)` —
/// `crypto/x509/x_attrib.c:34`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ATTRIBUTE(
    a: *mut *mut X509Attribute,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Attribute {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_ATTRIBUTE_it()).cast::<X509Attribute>() }
}

/// `int i2d_X509_ATTRIBUTE(const X509_ATTRIBUTE *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ATTRIBUTE(
    a: *const X509Attribute,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_ATTRIBUTE_it()) }
}

/// `X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)` —
/// `crypto/x509/x_attrib.c:37-59`.
///
/// The OID is taken by reference (`OBJ_nid2obj` answers the static table entry), and the value is
/// **adopted** by [`ASN1_TYPE_set`] rather than copied — which is why the failure path frees the
/// `ASN1_TYPE` separately from the attribute.
///
/// # Safety
///
/// `nid` need not be a known one; `value` is the pointer type `atrtype` names and is adopted by
/// the answer on success.
#[no_mangle]
pub unsafe extern "C" fn X509_ATTRIBUTE_create(
    nid: c_int,
    atrtype: c_int,
    value: *mut core::ffi::c_void,
) -> *mut X509Attribute {
    // SAFETY: `OBJ_nid2obj` takes an integer and answers a static object or NULL.
    let oid = OBJ_nid2obj(nid);
    if oid.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let attr = X509_ATTRIBUTE_new();
    if attr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `attr` is live.
    unsafe { (*attr).object = oid };

    // SAFETY: no preconditions.
    let val = ASN1_TYPE_new();
    if val.is_null() {
        // SAFETY: `attr` is live and this call owns it.
        unsafe { X509_ATTRIBUTE_free(attr) };
        return ptr::null_mut();
    }
    // SAFETY: `attr`'s `set` is the empty stack the item layer allocated, and `val` is live.
    unsafe {
        if OPENSSL_sk_push((*attr).set, val.cast()) <= 0 {
            X509_ATTRIBUTE_free(attr);
            ASN1_TYPE_free(val);
            return ptr::null_mut();
        }
        ASN1_TYPE_set(val, atrtype, value);
    }
    attr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::layout::V_ASN1_INTEGER;
    use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
    use crate::asn1::string::ASN1_INTEGER_new;
    use crate::runtime::obj::{NID_commonName, OBJ_obj2nid};
    use crate::runtime::stack::OPENSSL_sk_value;

    /// `X509_ATTRIBUTE_create` builds a two-field value, the item round-trips it, and `_dup`
    /// answers a distinct object with the same OID. The value is a small integer literal the
    /// probe chose, so nothing random or private is touched.
    #[test]
    fn create_round_trips_and_dup_is_distinct() {
        let i = ASN1_INTEGER_new();
        // SAFETY: `i` is live and the value is a constant.
        unsafe { ASN1_INTEGER_set(i, 1) };
        // SAFETY: `i` is a fresh `ASN1_INTEGER` and `X509_ATTRIBUTE_create` adopts it.
        let attr =
            unsafe { X509_ATTRIBUTE_create(NID_commonName, V_ASN1_INTEGER as c_int, i.cast()) };
        assert!(!attr.is_null());

        let mut out: *mut c_uchar = ptr::null_mut();
        // SAFETY: `attr` is live and `out` is this frame's own cursor.
        let len = unsafe { i2d_X509_ATTRIBUTE(attr, &mut out) };
        assert!(len > 0 && !out.is_null());

        let decoded = {
            let mut p: *const c_uchar = out;
            // SAFETY: the cursor is this frame's own and `out`/`len` describe a fresh encoding.
            unsafe { d2i_X509_ATTRIBUTE(ptr::null_mut(), &mut p, len as c_long) }
        };
        assert!(!decoded.is_null());
        // SAFETY: `decoded` and `attr` are live.
        unsafe {
            assert_eq!(OBJ_obj2nid((*decoded).object), NID_commonName);
            assert_eq!((*decoded).object, (*attr).object);
            let dup = X509_ATTRIBUTE_dup(attr);
            assert!(!dup.is_null() && dup != attr);
            /* The decoded value carries the same integer the probe chose. */
            let val = OPENSSL_sk_value((*decoded).set, 0) as *mut Asn1Type;
            assert!(!val.is_null());
            assert_eq!((*val).type_, V_ASN1_INTEGER);
            let integer = (*val).value.ptr.cast::<Asn1String>();
            assert_eq!(ASN1_INTEGER_get(integer), 1);
            X509_ATTRIBUTE_free(dup);
            X509_ATTRIBUTE_free(decoded);
            X509_ATTRIBUTE_free(attr);
            crate::runtime::mem::CRYPTO_free(out.cast(), ptr::null(), 0);
        }
    }
}
