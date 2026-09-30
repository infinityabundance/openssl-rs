//! `crypto/x509/v3_pku.c` — the `PKEY_USAGE_PERIOD` item and its table. Phase 10.13, table landed
//! under 10.14's table layer.
//!
//! `crypto/x509/v3_pku.c` is 52 lines and now transcribes whole:
//!
//! * `PKEY_USAGE_PERIOD ::= SEQUENCE { notBefore [0] GeneralizedTime OPTIONAL, notAfter [1]
//!   GeneralizedTime OPTIONAL }` (`:29-32`) lands, with `PKEY_USAGE_PERIOD_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:34`). All five are
//!   public exports (`x509v3.h`), so the differential plane can build one, encode it and decode
//!   the bytes back.
//! * `ossl_v3_pkey_usage_period` (`:21-27`) lands as a `pub static` row whose `i2r` is the
//!   `static` printer `i2r_PKEY_USAGE_PERIOD` (`:36-52`). It was withheld through 10.13; D463
//!   named it one of the 63 tables the published array needs.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). The row and its printer are unnameable from the admitted DSO; the item group is the
//! drivable surface.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms build a `PKEY_USAGE_PERIOD`, set both fields through the public
//! structure, encode it, decode the bytes back and re-encode, comparing byte for byte on both
//! sides.
//!
//! ## No raise
//!
//! The unit raises nothing, so it is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_GENERALIZEDTIME_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_private_key_usage_period;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `struct PKEY_USAGE_PERIOD_st` — from `include/openssl/x509v3.h:137-140`.
#[repr(C)]
pub struct PkeyUsagePeriod {
    /// `ASN1_GENERALIZEDTIME *notBefore` — `[0]` implicit, optional.
    pub(crate) notBefore: *mut Asn1String,
    /// `ASN1_GENERALIZEDTIME *notAfter` — `[1]` implicit, optional.
    pub(crate) notAfter: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<PkeyUsagePeriod>() == 16);
    assert!(core::mem::offset_of!(PkeyUsagePeriod, notBefore) == 0);
    assert!(core::mem::offset_of!(PkeyUsagePeriod, notAfter) == 8);
};

/// `PKEY_USAGE_PERIOD_seq_tt` — `ASN1_SEQUENCE(PKEY_USAGE_PERIOD)`
/// (`crypto/x509/v3_pku.c:29-32`): two `ASN1_IMP_OPT(..., ASN1_GENERALIZEDTIME, n)` rows.
///
/// `ASN1_IMP_OPT` is `ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL`, i.e. the `[n]` wrapper is
/// context-class and **implicit** (the `a0`/`a1` tags wrap the `GeneralizedTime` content
/// directly, with no inner universal tag).
static PKEY_USAGE_PERIOD_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"notBefore".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"notAfter".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
];

/// `PKEY_USAGE_PERIOD_it`'s descriptor — `ASN1_SEQUENCE_END(PKEY_USAGE_PERIOD)` at
/// `crypto/x509/v3_pku.c:32`.
static PKEY_USAGE_PERIOD_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKEY_USAGE_PERIOD_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PkeyUsagePeriod>() as c_long,
    sname: c"PKEY_USAGE_PERIOD".as_ptr(),
};

/// `const ASN1_ITEM *PKEY_USAGE_PERIOD_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)`.
#[no_mangle]
pub extern "C" fn PKEY_USAGE_PERIOD_it() -> *const Asn1Item {
    &PKEY_USAGE_PERIOD_ITEM
}

/// `PKEY_USAGE_PERIOD *PKEY_USAGE_PERIOD_new(void)` — `crypto/x509/v3_pku.c:34`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)`.
#[no_mangle]
pub extern "C" fn PKEY_USAGE_PERIOD_new() -> *mut PkeyUsagePeriod {
    // SAFETY: `PKEY_USAGE_PERIOD_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKEY_USAGE_PERIOD_it()).cast::<PkeyUsagePeriod>() }
}

/// `void PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKEY_USAGE_PERIOD_free(a: *mut PkeyUsagePeriod) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKEY_USAGE_PERIOD_it()) }
}

/// `PKEY_USAGE_PERIOD *d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKEY_USAGE_PERIOD(
    a: *mut *mut PkeyUsagePeriod,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut PkeyUsagePeriod {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKEY_USAGE_PERIOD_it()).cast::<PkeyUsagePeriod>() }
}

/// `int i2d_PKEY_USAGE_PERIOD(const PKEY_USAGE_PERIOD *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKEY_USAGE_PERIOD(
    a: *const PkeyUsagePeriod,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PKEY_USAGE_PERIOD_it()) }
}

/// `static int i2r_PKEY_USAGE_PERIOD(X509V3_EXT_METHOD *method, PKEY_USAGE_PERIOD *usage,
/// BIO *out, int indent)` — `crypto/x509/v3_pku.c:36-52`.
///
/// Brackets the two `ASN1_GENERALIZEDTIME` fields with the authority's labels; the indent is the
/// caller's, and the separating `", "` appears only when a `notAfter` follows a `notBefore`.
unsafe extern "C" fn i2r_PKEY_USAGE_PERIOD(
    _method: *const X509V3ExtMethod,
    usage: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: the caller's contract is a live `PKEY_USAGE_PERIOD`.
    let usage = usage.cast::<PkeyUsagePeriod>();
    // SAFETY: `out` is a live BIO; the format and its argument are compile-time constants.
    unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `usage` is live per the contract.
    unsafe {
        if !(*usage).notBefore.is_null() {
            BIO_write(out, c"Not Before: ".as_ptr().cast(), 12);
            ASN1_GENERALIZEDTIME_print(out, (*usage).notBefore);
            if !(*usage).notAfter.is_null() {
                BIO_write(out, c", ".as_ptr().cast(), 2);
            }
        }
        if !(*usage).notAfter.is_null() {
            BIO_write(out, c"Not After: ".as_ptr().cast(), 11);
            ASN1_GENERALIZEDTIME_print(out, (*usage).notAfter);
        }
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_pkey_usage_period` — `crypto/x509/v3_pku.c:21-27`.
///
/// Only `i2r` is set: the extension is printed from its item and has no `i2v`/`v2i` pair and no
/// string form.
pub static ossl_v3_pkey_usage_period: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_private_key_usage_period,
    ext_flags: 0,
    it: Some(PKEY_USAGE_PERIOD_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_PKEY_USAGE_PERIOD),
    r2i: None,
    usr_data: core::ptr::null_mut(),
};
