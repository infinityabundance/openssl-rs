//! `crypto/x509/v3_audit_id.c` — the `auditIdentity` table. Phase 10.14 table layer (10.14.8 owns
//! the `ac_*` rows).
//!
//! `crypto/x509/v3_audit_id.c` is 20 lines and its whole body is the `ossl_v3_audit_identity` row
//! (`:13-20`), which dispatches `NID_ac_auditIdentity` through the `ASN1_OCTET_STRING` item with
//! the `i2s_`/`s2i_ASN1_OCTET_STRING` pair landed in `v3_skid.rs`. The table now transcribes; it is
//! the row 10.12 withheld as "dead data with no court" and D463 named as one of the 63.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the
//! array is the last thing to land, not the first. The row itself is internal data the admitted DSO
//! does not export (`nm -D` shows no `ossl_v3_*`), so no court can name it; its drivable surface is
//! the `ASN1_OCTET_STRING` item and the two `v3_skid` helpers, both driven by `RT-STORE`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_void};

use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::Asn1String;
use crate::runtime::obj::NID_ac_auditIdentity;
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_skid::{i2s_ASN1_OCTET_STRING, s2i_ASN1_OCTET_STRING};

/// The `i2s` slot for `i2s_ASN1_OCTET_STRING`.
unsafe extern "C" fn audit_i2s(meth: *const X509V3ExtMethod, value: *mut c_void) -> *mut c_char {
    // SAFETY: `meth` is the table's live row (read only by the implementation); `value` is the
    // `ASN1_OCTET_STRING` the caller stored in the slot.
    unsafe { i2s_ASN1_OCTET_STRING(meth.cast_mut().cast::<c_void>(), value.cast::<Asn1String>()) }
}

/// The `s2i` slot for `s2i_ASN1_OCTET_STRING`.
unsafe extern "C" fn audit_s2i(
    meth: *const X509V3ExtMethod,
    ctx: *mut c_void,
    value: *const c_char,
) -> *mut c_void {
    // SAFETY: as `audit_i2s`; the answer is a fresh `ASN1_OCTET_STRING`.
    unsafe { s2i_ASN1_OCTET_STRING(meth.cast_mut().cast::<c_void>(), ctx, value).cast::<c_void>() }
}

/// `const X509V3_EXT_METHOD ossl_v3_audit_identity` — `crypto/x509/v3_audit_id.c:13-20`.
///
/// The `it` field is `ASN1_ITEM_ref(ASN1_OCTET_STRING)`, the function designator
/// `ASN1_OCTET_STRING_it`.
pub static ossl_v3_audit_identity: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_ac_auditIdentity,
    ext_flags: 0,
    it: Some(ASN1_OCTET_STRING_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(audit_i2s),
    s2i: Some(audit_s2i),
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: core::ptr::null_mut(),
};
