//! `crypto/pkcs12/p12_attr.c` — the `PKCS12` attribute helpers. Phase 10 (10.2).
//!
//! The unit is 134 lines and twelve exports, all thin: nine add an attribute to a `SafeBag` (or,
//! for `PKCS8_add_keyusage`, to a `PKCS8_PRIV_KEY_INFO`), `PKCS12_get_attr_gen` reads one back
//! from an attribute stack, `PKCS12_get_friendlyname` decodes the `BMPString` one, and
//! `PKCS12_SAFEBAG_get0_attrs`/`set0_attrs` are the accessor pair over the bag's attribute stack.
//!
//! ## `set0_attrs` frees the old stack **shallowly**, and that is the authority's own call
//!
//! `p12_attr.c:128-133` compares the new stack against the old and, when they differ, calls
//! `sk_X509_ATTRIBUTE_free(bag->attrib)` — the *shallow* `OPENSSL_sk_free`, not
//! `sk_X509_ATTRIBUTE_pop_free`, so only the stack container is released. That is transcribed
//! rather than "fixed", because the same set-then-replace shape is observable through
//! `PKCS12_SAFEBAG_get0_attrs`.
//!
//! ## The unit raises nothing directly, and its coordinates are its callees'
//!
//! Every failure is a NULL/`-1` handed back from `X509at_add1_attr_by_*` or the readers, so the
//! raise sites a caller sees are `crypto/x509/x509_att.c`'s — already covered by that unit's own
//! `COVERED_FILES` entry. This file is therefore deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`: an entry for it would read as coverage that does
//! not exist.
//!
//! ## `PKCS12_get_friendlyname` reaches `p12_utl.c`
//!
//! It is the one function here with a non-trivial body: it reads the `NID_friendlyName`
//! attribute, insists the value is a `V_ASN1_BMPSTRING`, and hands its bytes to
//! [`crate::pkcs12::p12_utl::OPENSSL_uni2utf8`], which is why the two units land together.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use crate::asn1::layout::{
    Asn1String, Asn1Type, MBSTRING_ASC, MBSTRING_BMP, MBSTRING_UTF8, V_ASN1_BIT_STRING,
    V_ASN1_BMPSTRING, V_ASN1_OCTET_STRING,
};
use crate::asn1::p8_pkey::{PKCS8_pkey_add1_attr_by_NID, Pkcs8PrivKeyInfo};
use crate::pkcs12::p12_asn::Pkcs12Safebag;
use crate::pkcs12::p12_sbag::PKCS12_SAFEBAG_get0_attr;
use crate::pkcs12::p12_utl::OPENSSL_uni2utf8;
use crate::runtime::obj::{NID_friendlyName, NID_key_usage, NID_localKeyID, NID_ms_csp_name};
use crate::runtime::stack::{OPENSSL_sk_free, OpenSslStack};
use crate::x509::x509_att::{
    X509_ATTRIBUTE_get0_type, X509at_add1_attr_by_NID, X509at_add1_attr_by_txt, X509at_get_attr,
    X509at_get_attr_by_NID,
};

/// `ASN1_TYPE *PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs, int attr_nid)` —
/// `crypto/pkcs12/p12_attr.c:100-108`.
///
/// A negative search index answers NULL; otherwise the first value of the matching attribute is
/// returned, borrowed.
///
/// # Safety
/// `attrs` is NULL or a live stack of `X509_ATTRIBUTE`; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_get_attr_gen(
    attrs: *const OpenSslStack,
    attr_nid: c_int,
) -> *mut Asn1Type {
    // SAFETY: `attrs` is NULL or a live stack.
    let i = unsafe { X509at_get_attr_by_NID(attrs, attr_nid, -1) };
    if i < 0 {
        return ptr::null_mut();
    }
    // SAFETY: `i` is in range and names a live attribute.
    unsafe { X509_ATTRIBUTE_get0_type(X509at_get_attr(attrs, i), 0) }
}

/// `int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen)` —
/// `crypto/pkcs12/p12_attr.c:17-26`.
///
/// # Safety
/// `bag` is live; `name` is readable for `namelen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_localkeyid(
    bag: *mut Pkcs12Safebag,
    name: *mut c_uchar,
    namelen: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `name`/`namelen` are the caller's.
    let ret = unsafe {
        X509at_add1_attr_by_NID(
            &raw mut (*bag).attrib,
            NID_localKeyID,
            V_ASN1_OCTET_STRING,
            name,
            namelen,
        )
    };
    c_int::from(!ret.is_null())
}

/// `int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage)` —
/// `crypto/pkcs12/p12_attr.c:30-35`.
///
/// The usage is narrowed to one byte before it is added, because a key-usage extension is a
/// `BIT STRING` of one octet. The answer is the callee's status directly.
///
/// # Safety
/// `p8` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_add_keyusage(p8: *mut Pkcs8PrivKeyInfo, usage: c_int) -> c_int {
    let us_val = usage as c_uchar;
    // SAFETY: `p8` is live and `us_val` is one readable byte.
    unsafe {
        PKCS8_pkey_add1_attr_by_NID(p8, NID_key_usage, V_ASN1_BIT_STRING, &raw const us_val, 1)
    }
}

/// `int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name, int namelen)` —
/// `crypto/pkcs12/p12_attr.c:39-48`.
///
/// # Safety
/// `bag` is live; `name` is readable for `namelen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_friendlyname_asc(
    bag: *mut Pkcs12Safebag,
    name: *const c_char,
    namelen: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `name`/`namelen` are the caller's.
    let ret = unsafe {
        X509at_add1_attr_by_NID(
            &raw mut (*bag).attrib,
            NID_friendlyName,
            MBSTRING_ASC,
            name.cast::<c_uchar>(),
            namelen,
        )
    };
    c_int::from(!ret.is_null())
}

/// `int PKCS12_add_friendlyname_utf8(PKCS12_SAFEBAG *bag, const char *name, int namelen)` —
/// `crypto/pkcs12/p12_attr.c:50-59`.
///
/// # Safety
/// `bag` is live; `name` is readable for `namelen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_friendlyname_utf8(
    bag: *mut Pkcs12Safebag,
    name: *const c_char,
    namelen: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `name`/`namelen` are the caller's.
    let ret = unsafe {
        X509at_add1_attr_by_NID(
            &raw mut (*bag).attrib,
            NID_friendlyName,
            MBSTRING_UTF8,
            name.cast::<c_uchar>(),
            namelen,
        )
    };
    c_int::from(!ret.is_null())
}

/// `int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag, const unsigned char *name,
/// int namelen)` — `crypto/pkcs12/p12_attr.c:61-70`.
///
/// # Safety
/// `bag` is live; `name` is readable for `namelen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_friendlyname_uni(
    bag: *mut Pkcs12Safebag,
    name: *const c_uchar,
    namelen: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `name`/`namelen` are the caller's.
    let ret = unsafe {
        X509at_add1_attr_by_NID(
            &raw mut (*bag).attrib,
            NID_friendlyName,
            MBSTRING_BMP,
            name,
            namelen,
        )
    };
    c_int::from(!ret.is_null())
}

/// `int PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag, const char *name, int namelen)` —
/// `crypto/pkcs12/p12_attr.c:72-80`.
///
/// # Safety
/// `bag` is live; `name` is readable for `namelen` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_CSPName_asc(
    bag: *mut Pkcs12Safebag,
    name: *const c_char,
    namelen: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `name`/`namelen` are the caller's.
    let ret = unsafe {
        X509at_add1_attr_by_NID(
            &raw mut (*bag).attrib,
            NID_ms_csp_name,
            MBSTRING_ASC,
            name.cast::<c_uchar>(),
            namelen,
        )
    };
    c_int::from(!ret.is_null())
}

/// `int PKCS12_add1_attr_by_NID(PKCS12_SAFEBAG *bag, int nid, int type,
/// const unsigned char *bytes, int len)` — `crypto/pkcs12/p12_attr.c:82-89`.
///
/// # Safety
/// `bag` is live; `bytes` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add1_attr_by_NID(
    bag: *mut Pkcs12Safebag,
    nid: c_int,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `bytes`/`len` are the caller's.
    let ret = unsafe { X509at_add1_attr_by_NID(&raw mut (*bag).attrib, nid, type_, bytes, len) };
    c_int::from(!ret.is_null())
}

/// `int PKCS12_add1_attr_by_txt(PKCS12_SAFEBAG *bag, const char *attrname, int type,
/// const unsigned char *bytes, int len)` — `crypto/pkcs12/p12_attr.c:91-98`.
///
/// # Safety
/// `bag` is live; `attrname` is a NUL-terminated string; `bytes` is readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add1_attr_by_txt(
    bag: *mut Pkcs12Safebag,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `bag` is live, so its `attrib` slot is writable; the rest are the caller's.
    let ret =
        unsafe { X509at_add1_attr_by_txt(&raw mut (*bag).attrib, attrname, type_, bytes, len) };
    c_int::from(!ret.is_null())
}

/// `char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag)` — `crypto/pkcs12/p12_attr.c:110-120`.
///
/// The `NID_friendlyName` value must be a `V_ASN1_BMPSTRING`; anything else answers NULL. The
/// answer is a fresh `OPENSSL_malloc` UTF-8 string the caller owns, decoded by
/// [`OPENSSL_uni2utf8`].
///
/// # Safety
/// `bag` is live. The answer is a fresh allocation the caller owns.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_get_friendlyname(bag: *mut Pkcs12Safebag) -> *mut c_char {
    // SAFETY: `bag` is live.
    let atype = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName) };
    if atype.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `atype` is a live `ASN1_TYPE`.
    if unsafe { (*atype).type_ } != V_ASN1_BMPSTRING {
        return ptr::null_mut();
    }
    // SAFETY: the selector is `V_ASN1_BMPSTRING`, so the union holds an `ASN1_STRING`.
    let bmp = unsafe { (*atype).value.ptr.cast::<Asn1String>() };
    // SAFETY: `bmp` is live and its `data`/`length` describe its content.
    unsafe { OPENSSL_uni2utf8((*bmp).data, (*bmp).length) }
}

/// `const STACK_OF(X509_ATTRIBUTE) *PKCS12_SAFEBAG_get0_attrs(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_attr.c:122-126`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_attrs(
    bag: *const Pkcs12Safebag,
) -> *const OpenSslStack {
    // SAFETY: `bag` is live per the contract.
    unsafe { (*bag).attrib }
}

/// `void PKCS12_SAFEBAG_set0_attrs(PKCS12_SAFEBAG *bag, STACK_OF(X509_ATTRIBUTE) *attrs)` —
/// `crypto/pkcs12/p12_attr.c:128-133`.
///
/// The old stack is released **shallowly** when it is not the same pointer, following the
/// authority's `sk_X509_ATTRIBUTE_free`; ownership of `attrs` passes to `bag`.
///
/// # Safety
/// `bag` is live; `attrs` is NULL or a stack the caller transfers to `bag`.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_set0_attrs(
    bag: *mut Pkcs12Safebag,
    attrs: *mut OpenSslStack,
) {
    // SAFETY: `bag` is live per the contract.
    unsafe {
        if (*bag).attrib != attrs {
            OPENSSL_sk_free((*bag).attrib);
        }
        (*bag).attrib = attrs;
    }
}

/// `const ASN1_TYPE *PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag, int attr_nid)` —
/// `crypto/pkcs12/p12_sbag.c:23-27`. It is defined in that unit; this module reads it only for
/// [`PKCS12_get_friendlyname`].
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, PKCS12_SAFEBAG_new};
    use crate::pkcs12::p12_sbag::PKCS12_SAFEBAG_get0_attr;
    use crate::x509::x509_att::X509at_get_attr_count;

    /// A fresh `SafeBag` takes a friendlyname and a local key id, both are readable back, and a
    /// duplicate friendlyname is refused (the duplicate guard is `x509_att.c`'s). The values are
    /// literals the test chose.
    #[test]
    fn attributes_add_and_read_back() {
        // The object table and the error queue are process-global state, and the duplicate arm
        // raises into the queue.
        let _guard = crate::test_support::lock_global_state();
        let name = c"probe";
        let keyid: [c_uchar; 4] = [1, 2, 3, 4];
        // SAFETY: no preconditions.
        let bag = PKCS12_SAFEBAG_new();
        assert!(!bag.is_null());
        // SAFETY: `bag` is live and the inputs are this frame's.
        unsafe {
            assert_eq!(PKCS12_add_friendlyname_asc(bag, name.as_ptr(), -1), 1);
            assert_eq!(PKCS12_add_localkeyid(bag, keyid.as_ptr().cast_mut(), 4), 1);
            let attr = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName);
            assert!(!attr.is_null());
            assert!(!PKCS12_SAFEBAG_get0_attrs(bag).is_null());
            assert_eq!(X509at_get_attr_count(PKCS12_SAFEBAG_get0_attrs(bag)), 2);
            // The second friendlyname is refused because the OID is already present.
            assert_eq!(PKCS12_add_friendlyname_asc(bag, name.as_ptr(), -1), 0);
            PKCS12_SAFEBAG_free(bag);
        }
    }
}
