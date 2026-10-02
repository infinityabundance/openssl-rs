//! `crypto/cms/cms_att.c` — the signed and unsigned attribute stacks of a `CMS_SignerInfo`,
//! and the attribute-rule checker the signer-info engine calls. Phase 12.3.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_void};

use crate::runtime::obj::{
    Asn1Object, NID_id_smime_aa_receiptRequest, NID_id_smime_aa_signingCertificate,
    NID_id_smime_aa_signingCertificateV2, NID_pkcs9_contentType, NID_pkcs9_countersignature,
    NID_pkcs9_messageDigest, NID_pkcs9_signingTime,
};
use crate::x509::x509_att::{
    ossl_x509at_add1_attr, ossl_x509at_add1_attr_by_NID, ossl_x509at_add1_attr_by_OBJ,
    ossl_x509at_add1_attr_by_txt, X509at_delete_attr, X509at_get0_data_by_OBJ, X509at_get_attr,
    X509at_get_attr_by_NID, X509at_get_attr_by_OBJ, X509at_get_attr_count,
};
use crate::x509::x_attrib::X509Attribute;

use super::cms_asn1::CmsSignerInfo;
use super::cms_lib::raise_cms;

/// The authority's `ossl_x509at_add1_attr*` returns the stack on success and NULL on failure;
/// its `CMS_*_add1_attr*` wrappers answer `1` in the first case. This is that mapping.
fn added(p: *mut crate::runtime::stack::OpenSslStack) -> c_int {
    c_int::from(!p.is_null())
}

/// `CMS_ATTR_F_SIGNED` — `cms_att.c:28`.
const CMS_ATTR_F_SIGNED: c_int = 0x01;
/// `CMS_ATTR_F_UNSIGNED` — `cms_att.c:30`.
const CMS_ATTR_F_UNSIGNED: c_int = 0x02;
/// `CMS_ATTR_F_REQUIRED_COND` — `cms_att.c:32`.
const CMS_ATTR_F_REQUIRED_COND: c_int = 0x10;
/// `CMS_ATTR_F_ONLY_ONE` — `cms_att.c:34`.
const CMS_ATTR_F_ONLY_ONE: c_int = 0x20;
/// `CMS_ATTR_F_ONE_ATTR_VALUE` — `cms_att.c:36`.
const CMS_ATTR_F_ONE_ATTR_VALUE: c_int = 0x40;

/// `cms_attribute_properties[]` — `cms_att.c:39-52`.
static CMS_ATTRIBUTE_PROPERTIES: [(c_int, c_int); 7] = [
    (
        NID_pkcs9_contentType,
        CMS_ATTR_F_SIGNED
            | CMS_ATTR_F_ONLY_ONE
            | CMS_ATTR_F_ONE_ATTR_VALUE
            | CMS_ATTR_F_REQUIRED_COND,
    ),
    (
        NID_pkcs9_messageDigest,
        CMS_ATTR_F_SIGNED
            | CMS_ATTR_F_ONLY_ONE
            | CMS_ATTR_F_ONE_ATTR_VALUE
            | CMS_ATTR_F_REQUIRED_COND,
    ),
    (
        NID_pkcs9_signingTime,
        CMS_ATTR_F_SIGNED | CMS_ATTR_F_ONLY_ONE | CMS_ATTR_F_ONE_ATTR_VALUE,
    ),
    (NID_pkcs9_countersignature, CMS_ATTR_F_UNSIGNED),
    (
        NID_id_smime_aa_signingCertificate,
        CMS_ATTR_F_SIGNED | CMS_ATTR_F_ONLY_ONE | CMS_ATTR_F_ONE_ATTR_VALUE,
    ),
    (
        NID_id_smime_aa_signingCertificateV2,
        CMS_ATTR_F_SIGNED | CMS_ATTR_F_ONLY_ONE | CMS_ATTR_F_ONE_ATTR_VALUE,
    ),
    (
        NID_id_smime_aa_receiptRequest,
        CMS_ATTR_F_SIGNED | CMS_ATTR_F_ONLY_ONE | CMS_ATTR_F_ONE_ATTR_VALUE,
    ),
];

/// `int CMS_signed_get_attr_count(const CMS_SignerInfo *si)` — `cms_att.c:56-59`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_get_attr_count(si: *const CmsSignerInfo) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_count((*si).signed_attrs) }
}

/// `int CMS_signed_get_attr_by_NID(const CMS_SignerInfo *si, int nid, int lastpos)` —
/// `cms_att.c:61-64`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_get_attr_by_NID(
    si: *const CmsSignerInfo,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_by_NID((*si).signed_attrs, nid, lastpos) }
}

/// `int CMS_signed_get_attr_by_OBJ(const CMS_SignerInfo *si, const ASN1_OBJECT *obj, int lastpos)`.
///
/// # Safety
/// `si` is live; `obj` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_get_attr_by_OBJ(
    si: *const CmsSignerInfo,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_by_OBJ((*si).signed_attrs, obj, lastpos) }
}

/// `X509_ATTRIBUTE *CMS_signed_get_attr(const CMS_SignerInfo *si, int loc)` — `cms_att.c:72-75`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_get_attr(
    si: *const CmsSignerInfo,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr((*si).signed_attrs, loc) }
}

/// `X509_ATTRIBUTE *CMS_signed_delete_attr(CMS_SignerInfo *si, int loc)` — `cms_att.c:77-80`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_delete_attr(
    si: *mut CmsSignerInfo,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `si` is live.
    unsafe { X509at_delete_attr((*si).signed_attrs, loc) }
}

/// `int CMS_signed_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr)` — `cms_att.c:82-87`.
///
/// # Safety
/// `si` and `attr` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_add1_attr(
    si: *mut CmsSignerInfo,
    attr: *mut X509Attribute,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe { ossl_x509at_add1_attr(&mut (*si).signed_attrs, attr) })
}

/// `int CMS_signed_add1_attr_by_OBJ(CMS_SignerInfo *si, const ASN1_OBJECT *obj, int type,`
/// `const void *bytes, int len)` — `cms_att.c:89-96`.
///
/// # Safety
/// `si` is live; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_add1_attr_by_OBJ(
    si: *mut CmsSignerInfo,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_OBJ(&mut (*si).signed_attrs, obj, type_, bytes.cast(), len)
    })
}

/// `int CMS_signed_add1_attr_by_NID(CMS_SignerInfo *si, int nid, int type, const void *bytes,`
/// `int len)` — `cms_att.c:98-104`.
///
/// # Safety
/// `si` is live; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_add1_attr_by_NID(
    si: *mut CmsSignerInfo,
    nid: c_int,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_NID(&mut (*si).signed_attrs, nid, type_, bytes.cast(), len)
    })
}

/// `int CMS_signed_add1_attr_by_txt(CMS_SignerInfo *si, const char *attrname, int type,`
/// `const void *bytes, int len)` — `cms_att.c:106-114`.
///
/// # Safety
/// `si` is live; `attrname` NUL-terminated; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_add1_attr_by_txt(
    si: *mut CmsSignerInfo,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_txt(&mut (*si).signed_attrs, attrname, type_, bytes.cast(), len)
    })
}

/// `void *CMS_signed_get0_data_by_OBJ(const CMS_SignerInfo *si, const ASN1_OBJECT *oid,`
/// `int lastpos, int type)` — `cms_att.c:116-121`.
///
/// # Safety
/// `si` is live; `oid` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_signed_get0_data_by_OBJ(
    si: *const CmsSignerInfo,
    oid: *const Asn1Object,
    lastpos: c_int,
    type_: c_int,
) -> *mut c_void {
    // SAFETY: `si` is live.
    unsafe { X509at_get0_data_by_OBJ((*si).signed_attrs, oid, lastpos, type_) }
}

/// `int CMS_unsigned_get_attr_count(const CMS_SignerInfo *si)` — `cms_att.c:123-126`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_get_attr_count(si: *const CmsSignerInfo) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_count((*si).unsigned_attrs) }
}

/// `int CMS_unsigned_get_attr_by_NID(const CMS_SignerInfo *si, int nid, int lastpos)`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_get_attr_by_NID(
    si: *const CmsSignerInfo,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_by_NID((*si).unsigned_attrs, nid, lastpos) }
}

/// `int CMS_unsigned_get_attr_by_OBJ(const CMS_SignerInfo *si, const ASN1_OBJECT *obj, int lastpos)`.
///
/// # Safety
/// `si` is live; `obj` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_get_attr_by_OBJ(
    si: *const CmsSignerInfo,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr_by_OBJ((*si).unsigned_attrs, obj, lastpos) }
}

/// `X509_ATTRIBUTE *CMS_unsigned_get_attr(const CMS_SignerInfo *si, int loc)`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_get_attr(
    si: *const CmsSignerInfo,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `si` is live.
    unsafe { X509at_get_attr((*si).unsigned_attrs, loc) }
}

/// `X509_ATTRIBUTE *CMS_unsigned_delete_attr(CMS_SignerInfo *si, int loc)`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_delete_attr(
    si: *mut CmsSignerInfo,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `si` is live.
    unsafe { X509at_delete_attr((*si).unsigned_attrs, loc) }
}

/// `int CMS_unsigned_add1_attr(CMS_SignerInfo *si, X509_ATTRIBUTE *attr)` — `cms_att.c:150-155`.
///
/// # Safety
/// `si` and `attr` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_add1_attr(
    si: *mut CmsSignerInfo,
    attr: *mut X509Attribute,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe { ossl_x509at_add1_attr(&mut (*si).unsigned_attrs, attr) })
}

/// `int CMS_unsigned_add1_attr_by_OBJ(CMS_SignerInfo *si, const ASN1_OBJECT *obj, int type,`
/// `const void *bytes, int len)` — `cms_att.c:157-164`.
///
/// # Safety
/// `si` is live; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_add1_attr_by_OBJ(
    si: *mut CmsSignerInfo,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_OBJ(&mut (*si).unsigned_attrs, obj, type_, bytes.cast(), len)
    })
}

/// `int CMS_unsigned_add1_attr_by_NID(CMS_SignerInfo *si, int nid, int type, const void *bytes,`
/// `int len)` — `cms_att.c:166-173`.
///
/// # Safety
/// `si` is live; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_add1_attr_by_NID(
    si: *mut CmsSignerInfo,
    nid: c_int,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_NID(&mut (*si).unsigned_attrs, nid, type_, bytes.cast(), len)
    })
}

/// `int CMS_unsigned_add1_attr_by_txt(CMS_SignerInfo *si, const char *attrname, int type,`
/// `const void *bytes, int len)` — `cms_att.c:175-183`.
///
/// # Safety
/// `si` is live; `attrname` NUL-terminated; `bytes` readable for `len`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_add1_attr_by_txt(
    si: *mut CmsSignerInfo,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `si` is live.
    added(unsafe {
        ossl_x509at_add1_attr_by_txt(
            &mut (*si).unsigned_attrs,
            attrname,
            type_,
            bytes.cast(),
            len,
        )
    })
}

/// `void *CMS_unsigned_get0_data_by_OBJ(CMS_SignerInfo *si, ASN1_OBJECT *oid, int lastpos,`
/// `int type)` — `cms_att.c:185-189`.
///
/// # Safety
/// `si` is live; `oid` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_unsigned_get0_data_by_OBJ(
    si: *mut CmsSignerInfo,
    oid: *mut Asn1Object,
    lastpos: c_int,
    type_: c_int,
) -> *mut c_void {
    // SAFETY: `si` is live.
    unsafe { X509at_get0_data_by_OBJ((*si).unsigned_attrs, oid, lastpos, type_) }
}

/// `X509_ATTRIBUTE *cms_attrib_get(int nid, const STACK_OF(X509_ATTRIBUTE) *attrs, int *lastpos)`.
///
/// # Safety
/// `attrs` is NULL or live; `lastpos` is writable.
unsafe fn cms_attrib_get(
    nid: c_int,
    attrs: *const crate::runtime::stack::OpenSslStack,
    lastpos: *mut c_int,
) -> *mut X509Attribute {
    // SAFETY: `attrs`/`lastpos` are per the contract.
    unsafe {
        let loc = X509at_get_attr_by_NID(attrs, nid, *lastpos);
        if loc < 0 {
            return core::ptr::null_mut();
        }
        let at = X509at_get_attr(attrs, loc);
        *lastpos = loc;
        at
    }
}

/// `int cms_check_attribute(int nid, int flags, int type, const STACK_OF(X509_ATTRIBUTE) *attrs,`
/// `int have_attrs)` — `cms_att.c:213-242`.
///
/// # Safety
/// `attrs` is NULL or live.
unsafe fn cms_check_attribute(
    nid: c_int,
    flags: c_int,
    type_: c_int,
    attrs: *const crate::runtime::stack::OpenSslStack,
    have_attrs: c_int,
) -> c_int {
    let mut lastpos = -1;
    // SAFETY: `attrs` is per the contract.
    let at = unsafe { cms_attrib_get(nid, attrs, &mut lastpos) };
    if !at.is_null() {
        // SAFETY: `at` is live.
        let count = unsafe { crate::x509::x509_att::X509_ATTRIBUTE_count(at) };
        let is_dup = (flags & CMS_ATTR_F_ONLY_ONE) != 0
            // SAFETY: `attrs` is per the contract.
            && !unsafe { cms_attrib_get(nid, attrs, &mut lastpos) }.is_null();
        if (flags & type_) == 0
            || is_dup
            || ((flags & CMS_ATTR_F_ONE_ATTR_VALUE) != 0 && count != 1)
            || count == 0
        {
            return 0;
        }
    } else if have_attrs != 0 && (flags & CMS_ATTR_F_REQUIRED_COND) != 0 && (flags & type_) != 0 {
        return 0;
    }
    1
}

/// `int ossl_cms_si_check_attributes(const CMS_SignerInfo *si)` — `cms_att.c:254-273`.
///
/// # Safety
/// `si` is live.
pub(crate) unsafe fn ossl_cms_si_check_attributes(si: *const CmsSignerInfo) -> c_int {
    // SAFETY: `si` is live.
    let have_signed = unsafe { CMS_signed_get_attr_count(si) } > 0;
    // SAFETY: `si` is live.
    let have_unsigned = unsafe { CMS_unsigned_get_attr_count(si) } > 0;
    for (nid, flags) in CMS_ATTRIBUTE_PROPERTIES {
        // SAFETY: `si` is live.
        let signed_ok = unsafe {
            cms_check_attribute(
                nid,
                flags,
                CMS_ATTR_F_SIGNED,
                (*si).signed_attrs,
                c_int::from(have_signed),
            )
        } != 0;
        // SAFETY: `si` is live.
        let unsigned_ok = unsafe {
            cms_check_attribute(
                nid,
                flags,
                CMS_ATTR_F_UNSIGNED,
                (*si).unsigned_attrs,
                c_int::from(have_unsigned),
            )
        } != 0;
        if !signed_ok || !unsigned_ok {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    268,
                    c"ossl_cms_si_check_attributes",
                    crate::runtime::err::err_reasons::CMS_R_ATTRIBUTE_ERROR,
                )
            };
            return 0;
        }
    }
    1
}
