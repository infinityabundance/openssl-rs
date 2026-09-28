//! `crypto/x509/v3_int.c` — the three integer-backed extension rows. Phase 10.14 table layer
//! (10.14.6 owns these rows).
//!
//! `crypto/x509/v3_int.c` is 43 lines and now transcribes whole: the two integer rows
//! `ossl_v3_crl_num` (`:15-21`) and `ossl_v3_delta_crl` (`:23-29`), the `static` `s2i_asn1_int`
//! wrapper (`:31-35`), and `ossl_v3_inhibit_anyp` (`:37-43`), the one row that also answers `s2i`.
//! Every row dispatches through the `ASN1_INTEGER` item and prints with `i2s_ASN1_INTEGER`
//! (`v3_utl.rs`, 10.14.3).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes three of the 63. The rows are unnameable from the admitted DSO;
//! `i2s_ASN1_INTEGER`/`s2i_ASN1_INTEGER` and the `ASN1_INTEGER` item are the drivable surface.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_void};

use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::Asn1String;
use crate::runtime::obj::{NID_crl_number, NID_delta_crl, NID_inhibit_any_policy};
use crate::x509::v3_lib::{X509V3ExtI2s, X509V3ExtMethod};
use crate::x509::v3_utl::{i2s_ASN1_INTEGER, s2i_ASN1_INTEGER};

/// `(X509V3_EXT_I2S)i2s_ASN1_INTEGER` — the cast every row's initialiser writes.
const fn as_i2s(
    f: unsafe extern "C" fn(*mut X509V3ExtMethod, *const Asn1String) -> *mut c_char,
) -> X509V3ExtI2s {
    // SAFETY: both function types take two pointer arguments and answer a pointer; the authority
    // writes exactly this cast in the rows.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*mut X509V3ExtMethod, *const Asn1String) -> *mut c_char,
            unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void) -> *mut c_char,
        >(f)
    })
}

/// `static void *s2i_asn1_int(X509V3_EXT_METHOD *meth, X509V3_CTX *ctx, const char *value)`
/// — `crypto/x509/v3_int.c:31-35`.
///
/// The authority ignores `ctx` and forwards to `s2i_ASN1_INTEGER`.
unsafe extern "C" fn s2i_asn1_int(
    meth: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    value: *const c_char,
) -> *mut c_void {
    // SAFETY: the caller's contract is `s2i_ASN1_INTEGER`'s; the first argument's constness differs
    // only in Rust's type system.
    unsafe { s2i_ASN1_INTEGER(meth.cast_mut(), value).cast::<c_void>() }
}

/// `const X509V3_EXT_METHOD ossl_v3_crl_num` — `crypto/x509/v3_int.c:15-21`.
///
/// Only `i2s` is set; `s2i` is zero, so a config parser cannot build this one.
pub static ossl_v3_crl_num: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_crl_number,
    ext_flags: 0,
    it: Some(ASN1_INTEGER_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: as_i2s(i2s_ASN1_INTEGER),
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: core::ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_delta_crl` — `crypto/x509/v3_int.c:23-29`. Same shape as
/// [`ossl_v3_crl_num`], a distinct NID.
pub static ossl_v3_delta_crl: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_delta_crl,
    ext_flags: 0,
    it: Some(ASN1_INTEGER_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: as_i2s(i2s_ASN1_INTEGER),
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: core::ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_inhibit_anyp` — `crypto/x509/v3_int.c:37-43`.
///
/// The one row here that carries `s2i` (through the `s2i_asn1_int` wrapper).
pub static ossl_v3_inhibit_anyp: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_inhibit_any_policy,
    ext_flags: 0,
    it: Some(ASN1_INTEGER_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: as_i2s(i2s_ASN1_INTEGER),
    s2i: Some(s2i_asn1_int),
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: core::ptr::null_mut(),
};
