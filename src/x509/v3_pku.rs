//! `crypto/x509/v3_pku.c` — the `PKEY_USAGE_PERIOD` item. Phase 10.13.
//!
//! `crypto/x509/v3_pku.c` is 52 lines. **The item and its generated lifecycle land; the
//! extension method and its printer are withheld by name**:
//!
//! * `PKEY_USAGE_PERIOD ::= SEQUENCE { notBefore [0] GeneralizedTime OPTIONAL, notAfter [1]
//!   GeneralizedTime OPTIONAL }` (`:29-32`) lands, with `PKEY_USAGE_PERIOD_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:34`). All five are
//!   public exports (`x509v3.h`), so the differential plane can build one, encode it and decode
//!   the bytes back.
//! * `ossl_v3_pkey_usage_period` (`:21-27`) is **withheld by name**: internal, the admitted DSO
//!   exports no `ossl_v3_*` (`nm -D`), and its only authority caller is
//!   `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`). That caller lands in
//!   [`crate::x509::v3_lib`], but the *dispatch* that would make the table observable --
//!   `X509V3_EXT_get_nid` -- is itself withheld there: it searches `standard_exts[]`
//!   (`standard_exts.h:15-95`), which names ~63 `ossl_v3_*` tables from units this subphase does
//!   not own. See [`crate::x509::v3_lib`] for the whole blocker.
//! * `i2r_PKEY_USAGE_PERIOD` (`:36-52`) is **withheld by name**: a `static` callback reached only
//!   through the withheld table, so landing it would be dead code with no court.
//!
//! Nothing is stubbed: the two withheld names are named rather than declared.
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

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_GENERALIZEDTIME_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;

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
