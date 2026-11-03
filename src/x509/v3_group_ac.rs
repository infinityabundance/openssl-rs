//! `crypto/x509/v3_group_ac.c` — the `groupAC` table. Phase 10.14 table layer (10.12 owned the
//! unit's withholding).
//!
//! `crypto/x509/v3_group_ac.c` is 53 lines and now transcribes whole: the four `static` callbacks
//! (`:17-40`) and the `ossl_v3_group_ac` row (`:44-53`) they fill. The extension is defined by ITU-T
//! X.509 (2019) §17.1.2.6 and dispatches through the `ASN1_NULL` item.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes one of the 63. `ossl_v3_group_ac` is unnameable from the admitted
//! DSO; the `ASN1_NULL` item is the drivable surface.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};

use crate::asn1::items::ASN1_NULL_it;
use crate::asn1::typ::ASN1_NULL_new;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::NID_group_ac;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup` expansion — `crypto/x509/v3_group_ac.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_group_ac.c";
/// `i2s_GROUP_AC`'s `OPENSSL_strdup("NULL")` (`crypto/x509/v3_group_ac.c:32`).
const LINE_STRDUP: c_int = 32;

/// `static int i2r_GROUP_AC(...)` — `crypto/x509/v3_group_ac.c:17-22`. A bare `1`.
///
/// # Safety
///
/// The `i2r` slot contract stated on [`X509V3ExtMethod`] (`src/x509/v3_lib.rs`). Caller:
/// `X509V3_EXT_print`'s `i2r` arm (`src/x509/v3_prn.rs:341`), which decoded the extension
/// through the row's `ASN1_NULL` item and refused a NULL result (`:300-303`), and refused a
/// NULL `out`/`ext` prologue (`:254-256`). The body reads none of `method`, `su`, `out` or
/// `indent`; those are non-NULL per the dispatcher where the parameter is a pointer, and stay
/// live for the call. No further property is required.
///
/// Authority-derived: `crypto/x509/v3_group_ac.c:17-22` reads nothing and answers 1.
unsafe extern "C" fn i2r_GROUP_AC(
    _method: *const X509V3ExtMethod,
    _su: *mut c_void,
    _out: *mut Bio,
    _indent: c_int,
) -> c_int {
    1
}

/// `static void *r2i_GROUP_AC(...)` — `crypto/x509/v3_group_ac.c:24-28`.
unsafe extern "C" fn r2i_GROUP_AC(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _value: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static char *i2s_GROUP_AC(const X509V3_EXT_METHOD *method, void *val)`
/// — `crypto/x509/v3_group_ac.c:30-33`.
///
/// # Safety
///
/// The `i2s` slot contract stated on [`X509V3ExtMethod`] (`src/x509/v3_lib.rs`). Caller:
/// `X509V3_EXT_print`'s `i2s` arm (`src/x509/v3_prn.rs:334-352`), which resolved the row under
/// the extension registry's read hold and decoded a non-NULL value through the row's item.
/// Neither argument is read, so no further property is required.
///
/// Authority-derived: `crypto/x509/v3_group_ac.c:30-33` reads no argument and duplicates
/// `"NULL"`.
unsafe extern "C" fn i2s_GROUP_AC(
    _method: *const X509V3ExtMethod,
    _val: *mut c_void,
) -> *mut c_char {
    // SAFETY: `s` is a compile-time constant NUL-terminated string.
    //
    // The returned block belongs to the caller: the extension machinery owns the returned
    // `char *` and releases it through the allocator seam. There is no local release, so the
    // transfer edge is this raw return rather than an owner that would free a returned block.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), FILE.as_ptr(), LINE_STRDUP) }
}

/// `static void *s2i_GROUP_AC(...)` — `crypto/x509/v3_group_ac.c:35-40`.
///
/// # Safety
///
/// The `s2i` slot contract stated on [`X509V3ExtMethod`] (`src/x509/v3_lib.rs`). Caller:
/// `do_ext_nconf`'s `s2i` arm (`src/x509/v3_conf.rs:1095`), which resolved `method` under the
/// extension registry's read hold (held across the lookup, this callback and `do_ext_i2d`) and
/// passes the caller's NUL-terminated configuration `value`; `ctx` is NULL or live. This
/// callback reads no argument, so no further property is required. `method` stays live for the
/// call, and `value` is borrowed, not freed or retained. The `ASN1_NULL` sentinel it returns
/// belongs to the dispatcher, which encodes it with this row's `ASN1_NULL_it` and releases it
/// once (`src/x509/v3_conf.rs:1126-1132`).
///
/// Authority-derived: `crypto/x509/v3_group_ac.c:35-40` returns `ASN1_NULL_new()` and reads no
/// argument.
unsafe extern "C" fn s2i_GROUP_AC(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_group_ac` — `crypto/x509/v3_group_ac.c:44-53`.
pub static ossl_v3_group_ac: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_group_ac,
    ext_flags: 0,
    it: Some(ASN1_NULL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: Some(i2s_GROUP_AC),
    s2i: Some(s2i_GROUP_AC),
    i2v: None,
    v2i: None,
    i2r: Some(i2r_GROUP_AC),
    r2i: Some(r2i_GROUP_AC),
    usr_data: core::ptr::null_mut(),
};
