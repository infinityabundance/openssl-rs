//! `crypto/x509/v3_no_ass.c` — the `noAssertion` table. Phase 10.14 table layer (10.12 owned the
//! unit's withholding).
//!
//! `crypto/x509/v3_no_ass.c` is 53 lines and now transcribes whole: the four `static` callbacks
//! (`:17-40`) and the `ossl_v3_no_assertion` row (`:44-53`) they fill. The extension is defined by
//! ITU-T X.509 (2019) §17.5.2.7 and dispatches through the `ASN1_NULL` item; `r2i` and `s2i` both
//! answer `ASN1_NULL_new()`'s sentinel `1`, and `i2s` answers a fresh `"NULL"`.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456), so the array is withheld until all 63 tables exist; this unit contributes one of them.
//! No court can name `ossl_v3_no_assertion` (the admitted DSO exports no `ossl_v3_*`); the
//! `ASN1_NULL` item is the drivable surface, driven by `RT-STORE`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::items::ASN1_NULL_it;
use crate::asn1::typ::ASN1_NULL_new;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::NID_no_assertion;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup` expansion — `crypto/x509/v3_no_ass.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_no_ass.c";
/// `i2s_NO_ASSERTION`'s `OPENSSL_strdup("NULL")` (`crypto/x509/v3_no_ass.c:32`).
const LINE_STRDUP: c_int = 32;

/// `static int i2r_NO_ASSERTION(X509V3_EXT_METHOD *method, void *su, BIO *out, int indent)`
/// — `crypto/x509/v3_no_ass.c:17-22`. The authority returns a bare `1` and reads nothing.
unsafe extern "C" fn i2r_NO_ASSERTION(
    _method: *const X509V3ExtMethod,
    _su: *mut c_void,
    _out: *mut Bio,
    _indent: c_int,
) -> c_int {
    1
}

/// `static void *r2i_NO_ASSERTION(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *value)`
/// — `crypto/x509/v3_no_ass.c:24-28`. Answers the `ASN1_NULL` sentinel.
unsafe extern "C" fn r2i_NO_ASSERTION(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _value: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static char *i2s_NO_ASSERTION(const X509V3_EXT_METHOD *method, void *val)`
/// — `crypto/x509/v3_no_ass.c:30-33`. A fresh `"NULL"` on every call.
unsafe extern "C" fn i2s_NO_ASSERTION(
    _method: *const X509V3ExtMethod,
    _val: *mut c_void,
) -> *mut c_char {
    // SAFETY: `s` is a compile-time constant NUL-terminated string.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), FILE.as_ptr(), LINE_STRDUP) }
}

/// `static void *s2i_NO_ASSERTION(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)`
/// — `crypto/x509/v3_no_ass.c:35-40`. The input is checked by nobody, as in the authority.
unsafe extern "C" fn s2i_NO_ASSERTION(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_no_assertion` — `crypto/x509/v3_no_ass.c:44-53`.
///
/// `it` is `ASN1_ITEM_ref(ASN1_NULL)`; the `i2s`/`s2i`/`i2r`/`r2i` slots are the four callbacks
/// above, and the multi-value slots are zero as the authority leaves them.
pub static ossl_v3_no_assertion: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_no_assertion,
    ext_flags: 0,
    it: Some(ASN1_NULL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(i2s_NO_ASSERTION),
    s2i: Some(s2i_NO_ASSERTION),
    i2v: None,
    v2i: None,
    i2r: Some(i2r_NO_ASSERTION),
    r2i: Some(r2i_NO_ASSERTION),
    usr_data: core::ptr::null_mut(),
};
