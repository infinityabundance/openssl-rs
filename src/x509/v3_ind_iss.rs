//! `crypto/x509/v3_ind_iss.c` — the `indirectIssuer` table. Phase 10.14 table layer (10.12 owned
//! the unit's withholding).
//!
//! `crypto/x509/v3_ind_iss.c` is 53 lines and now transcribes whole: the four `static` callbacks
//! (`:17-40`) and the `ossl_v3_indirect_issuer` row (`:44-53`) they fill. The extension is defined
//! by ITU-T X.509 (2019) §17.5.2.5 and dispatches through the `ASN1_NULL` item.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes one of the 63. `ossl_v3_indirect_issuer` is unnameable from the
//! admitted DSO; the `ASN1_NULL` item is the drivable surface.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::items::ASN1_NULL_it;
use crate::asn1::typ::ASN1_NULL_new;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::NID_indirect_issuer;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup` expansion — `crypto/x509/v3_ind_iss.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_ind_iss.c";
/// `i2s_INDIRECT_ISSUER`'s `OPENSSL_strdup("NULL")` (`crypto/x509/v3_ind_iss.c:32`).
const LINE_STRDUP: c_int = 32;

/// `static int i2r_INDIRECT_ISSUER(...)` — `crypto/x509/v3_ind_iss.c:17-22`. A bare `1`.
unsafe extern "C" fn i2r_INDIRECT_ISSUER(
    _method: *const X509V3ExtMethod,
    _su: *mut c_void,
    _out: *mut Bio,
    _indent: c_int,
) -> c_int {
    1
}

/// `static void *r2i_INDIRECT_ISSUER(...)` — `crypto/x509/v3_ind_iss.c:24-28`.
unsafe extern "C" fn r2i_INDIRECT_ISSUER(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _value: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static char *i2s_INDIRECT_ISSUER(const X509V3_EXT_METHOD *method, void *val)`
/// — `crypto/x509/v3_ind_iss.c:30-33`.
unsafe extern "C" fn i2s_INDIRECT_ISSUER(
    _method: *const X509V3ExtMethod,
    _val: *mut c_void,
) -> *mut c_char {
    // SAFETY: `s` is a compile-time constant NUL-terminated string.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), FILE.as_ptr(), LINE_STRDUP) }
}

/// `static void *s2i_INDIRECT_ISSUER(...)` — `crypto/x509/v3_ind_iss.c:35-40`.
unsafe extern "C" fn s2i_INDIRECT_ISSUER(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_indirect_issuer` — `crypto/x509/v3_ind_iss.c:44-53`.
pub static ossl_v3_indirect_issuer: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_indirect_issuer,
    ext_flags: 0,
    it: Some(ASN1_NULL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(i2s_INDIRECT_ISSUER),
    s2i: Some(s2i_INDIRECT_ISSUER),
    i2v: None,
    v2i: None,
    i2r: Some(i2r_INDIRECT_ISSUER),
    r2i: Some(r2i_INDIRECT_ISSUER),
    usr_data: core::ptr::null_mut(),
};
