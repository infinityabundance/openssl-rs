//! `crypto/x509/v3_iobo.c` — the `issuedOnBehalfOf` table. Phase 10.14.8's table layer, landed
//! whole.
//!
//! `crypto/x509/v3_iobo.c` is 32 lines and transcribes whole: the `static` printer
//! [`i2r_ISSUED_ON_BEHALF_OF`] (`:13-22`) and the row [`ossl_v3_issued_on_behalf_of`] (`:24-32`),
//! whose item is `ASN1_ITEM_ref(GENERAL_NAME)` and whose only callback is that printer. It is the
//! row D466 named among the 23 closure-ready units; its closure is `v3_genn.rs`'s `GENERAL_NAME_it`
//! and `v3_san.rs`'s `GENERAL_NAME_print`, both landed.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the
//! array is the last thing to land, not the first. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`), so no court can name it; its printer's drivable
//! surface is `GENERAL_NAME_print`, driven by `RT-STORE`.
//!
//! ## No raise
//!
//! The unit raises nothing, so `crypto/x509/v3_iobo.c` is deliberately not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_void};

use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_issued_on_behalf_of;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::GENERAL_NAME_print;

/// `static int i2r_ISSUED_ON_BEHALF_OF(X509V3_EXT_METHOD *method, GENERAL_NAME *gn, BIO *out,
/// int indent)` — `crypto/x509/v3_iobo.c:13-22`.
///
/// Indents, prints the `GENERAL_NAME` through the shared printer, then a newline. Each of the three
/// writes is a refusal arm: a non-positive answer aborts with 0.
unsafe extern "C" fn i2r_ISSUED_ON_BEHALF_OF(
    _method: *const X509V3ExtMethod,
    gn: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `out` is a live BIO; the format and its arguments are compile-time constants.
    if unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `gn` is a live `GENERAL_NAME` per the caller's contract; `out` is live.
    if unsafe { GENERAL_NAME_print(out, gn.cast::<GeneralName>()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    c_int::from(unsafe { BIO_puts(out, c"\n".as_ptr()) } > 0)
}

/// `const X509V3_EXT_METHOD ossl_v3_issued_on_behalf_of` — `crypto/x509/v3_iobo.c:24-32`.
///
/// `it` is `ASN1_ITEM_ref(GENERAL_NAME)`, the function designator `GENERAL_NAME_it`; `i2r` is the
/// printer; every other slot is zero.
pub static ossl_v3_issued_on_behalf_of: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_issued_on_behalf_of,
    ext_flags: 0,
    it: Some(GENERAL_NAME_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ISSUED_ON_BEHALF_OF),
    r2i: None,
    usr_data: core::ptr::null_mut(),
};
