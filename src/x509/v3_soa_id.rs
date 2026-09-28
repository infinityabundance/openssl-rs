//! `crypto/x509/v3_soa_id.c` — the `sOAIdentifier` table. Phase 10.14 table layer (10.13 owned the
//! unit's withholding).
//!
//! `crypto/x509/v3_soa_id.c` is 53 lines and now transcribes whole: the four `static` callbacks
//! (`:17-40`) and the `ossl_v3_soa_identifier` row (`:44-53`) they fill. The extension is defined by
//! ITU-T X.509 (2019) §17.3.2.1.1 and dispatches through the `ASN1_NULL` item.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes one of the 63. `ossl_v3_soa_identifier` is unnameable from the
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
use crate::runtime::obj::NID_soa_identifier;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup` expansion — `crypto/x509/v3_soa_id.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_soa_id.c";
/// `i2s_SOA_IDENTIFIER`'s `OPENSSL_strdup("NULL")` (`crypto/x509/v3_soa_id.c:32`).
const LINE_STRDUP: c_int = 32;

/// `static int i2r_SOA_IDENTIFIER(...)` — `crypto/x509/v3_soa_id.c:17-22`. A bare `1`.
unsafe extern "C" fn i2r_SOA_IDENTIFIER(
    _method: *const X509V3ExtMethod,
    _su: *mut c_void,
    _out: *mut Bio,
    _indent: c_int,
) -> c_int {
    1
}

/// `static void *r2i_SOA_IDENTIFIER(...)` — `crypto/x509/v3_soa_id.c:24-28`.
unsafe extern "C" fn r2i_SOA_IDENTIFIER(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _value: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static char *i2s_SOA_IDENTIFIER(const X509V3_EXT_METHOD *method, void *val)`
/// — `crypto/x509/v3_soa_id.c:30-33`.
unsafe extern "C" fn i2s_SOA_IDENTIFIER(
    _method: *const X509V3ExtMethod,
    _val: *mut c_void,
) -> *mut c_char {
    // SAFETY: `s` is a compile-time constant NUL-terminated string.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), FILE.as_ptr(), LINE_STRDUP) }
}

/// `static void *s2i_SOA_IDENTIFIER(...)` — `crypto/x509/v3_soa_id.c:35-40`.
unsafe extern "C" fn s2i_SOA_IDENTIFIER(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_soa_identifier` — `crypto/x509/v3_soa_id.c:44-53`.
pub static ossl_v3_soa_identifier: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_soa_identifier,
    ext_flags: 0,
    it: Some(ASN1_NULL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(i2s_SOA_IDENTIFIER),
    s2i: Some(s2i_SOA_IDENTIFIER),
    i2v: None,
    v2i: None,
    i2r: Some(i2r_SOA_IDENTIFIER),
    r2i: Some(r2i_SOA_IDENTIFIER),
    usr_data: core::ptr::null_mut(),
};
