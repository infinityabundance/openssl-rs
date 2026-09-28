//! `crypto/x509/v3_enum.c` — the `cRLReason` table and its printer. Phase 10.14 table layer
//! (10.14.8 owns the row).
//!
//! `crypto/x509/v3_enum.c` is 53 lines and now transcribes whole: the ten-entry `crl_reasons`
//! table (`:15-30`), the `ossl_v3_crl_reason` row (`:32-39`) and `i2s_ASN1_ENUMERATED_TABLE`
//! (`:41-53`). The row dispatches through the `ASN1_ENUMERATED` item and its `usr_data` is the
//! `crl_reasons` array; the printer is the unit's only **export** (`x509v3.h`), so it is both the
//! row's `i2s` and a court-drivable symbol in its own right.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array silently changes `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes one of the 63. The row itself is unnameable from the admitted DSO;
//! `i2s_ASN1_ENUMERATED_TABLE` and the `ASN1_ENUMERATED` item are the drivable surface.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::asn1::items::ASN1_ENUMERATED_it;
use crate::asn1::layout::{Asn1String, BitStringBitname};
use crate::asn1::prim::ASN1_ENUMERATED_get;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::NID_crl_reason;
use crate::x509::v3_lib::{X509V3ExtI2s, X509V3ExtMethod};
use crate::x509::v3_utl::i2s_ASN1_ENUMERATED;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup` expansion — `crypto/x509/v3_enum.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_enum.c";
/// `i2s_ASN1_ENUMERATED_TABLE`'s `OPENSSL_strdup(enam->lname)` (`crypto/x509/v3_enum.c:50`).
const LINE_STRDUP: c_int = 50;

/// `CRL_REASON_*` — `include/openssl/x509v3.h:223-233`. The reason `bitnum`s the table names.
const CRL_REASON_UNSPECIFIED: c_int = 0;
/// `include/openssl/x509v3.h:224`.
const CRL_REASON_KEY_COMPROMISE: c_int = 1;
/// `include/openssl/x509v3.h:225`.
const CRL_REASON_CA_COMPROMISE: c_int = 2;
/// `include/openssl/x509v3.h:226`.
const CRL_REASON_AFFILIATION_CHANGED: c_int = 3;
/// `include/openssl/x509v3.h:227`.
const CRL_REASON_SUPERSEDED: c_int = 4;
/// `include/openssl/x509v3.h:228`.
const CRL_REASON_CESSATION_OF_OPERATION: c_int = 5;
/// `include/openssl/x509v3.h:229`.
const CRL_REASON_CERTIFICATE_HOLD: c_int = 6;
/// `include/openssl/x509v3.h:230`.
const CRL_REASON_REMOVE_FROM_CRL: c_int = 8;
/// `include/openssl/x509v3.h:231`.
const CRL_REASON_PRIVILEGE_WITHDRAWN: c_int = 9;
/// `include/openssl/x509v3.h:232`.
const CRL_REASON_AA_COMPROMISE: c_int = 10;

/// `static ENUMERATED_NAMES crl_reasons[]` — `crypto/x509/v3_enum.c:15-30`.
///
/// `ENUMERATED_NAMES` is `typedef BIT_STRING_BITNAME ENUMERATED_NAMES` (`x509v3.h:125`), so the
/// array is [`BitStringBitname`] rows terminated by a null `lname` (the last row here, `{-1, NULL,
/// NULL}`).
static CRL_REASONS: [BitStringBitname; 11] = [
    BitStringBitname {
        bitnum: CRL_REASON_UNSPECIFIED,
        lname: c"Unspecified".as_ptr(),
        sname: c"unspecified".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_KEY_COMPROMISE,
        lname: c"Key Compromise".as_ptr(),
        sname: c"keyCompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_CA_COMPROMISE,
        lname: c"CA Compromise".as_ptr(),
        sname: c"CACompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_AFFILIATION_CHANGED,
        lname: c"Affiliation Changed".as_ptr(),
        sname: c"affiliationChanged".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_SUPERSEDED,
        lname: c"Superseded".as_ptr(),
        sname: c"superseded".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_CESSATION_OF_OPERATION,
        lname: c"Cessation Of Operation".as_ptr(),
        sname: c"cessationOfOperation".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_CERTIFICATE_HOLD,
        lname: c"Certificate Hold".as_ptr(),
        sname: c"certificateHold".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_REMOVE_FROM_CRL,
        lname: c"Remove From CRL".as_ptr(),
        sname: c"removeFromCRL".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_PRIVILEGE_WITHDRAWN,
        lname: c"Privilege Withdrawn".as_ptr(),
        sname: c"privilegeWithdrawn".as_ptr(),
    },
    BitStringBitname {
        bitnum: CRL_REASON_AA_COMPROMISE,
        lname: c"AA Compromise".as_ptr(),
        sname: c"AACompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: -1,
        lname: core::ptr::null(),
        sname: core::ptr::null(),
    },
];

/// `(X509V3_EXT_I2S)i2s_ASN1_ENUMERATED_TABLE` — the cast the row's initialiser writes.
const fn as_i2s(
    f: unsafe extern "C" fn(*mut X509V3ExtMethod, *const Asn1String) -> *mut c_char,
) -> X509V3ExtI2s {
    // SAFETY: both function types take two pointer arguments and answer a pointer.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*mut X509V3ExtMethod, *const Asn1String) -> *mut c_char,
            unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void) -> *mut c_char,
        >(f)
    })
}

/// `char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *method, const ASN1_ENUMERATED *e)`
/// — `crypto/x509/v3_enum.c:41-53`.
///
/// Walks the row's own `usr_data` name table and answers the long name of the first row whose
/// `bitnum` equals the enumerated value under `c_long` promotion; a value no row names falls back to
/// [`i2s_ASN1_ENUMERATED`]. The authority does not null-check `method` or `e`, so neither does this.
///
/// # Safety
///
/// `method` is a live row whose `usr_data` is a `BitStringBitname` array terminated by a null
/// `lname`, and `e` is NULL or a live enumerated value.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_ENUMERATED_TABLE(
    method: *mut X509V3ExtMethod,
    e: *const Asn1String,
) -> *mut c_char {
    // SAFETY: `e` is NULL or live per the contract.
    let strval = unsafe { ASN1_ENUMERATED_get(e) };
    // SAFETY: `method` is live and its `usr_data` is the contracted array.
    let mut enam = unsafe { (*method).usr_data.cast::<BitStringBitname>() };
    // SAFETY: the array is `lname`-terminated, so the loop stops at the sentinel.
    unsafe {
        while !(*enam).lname.is_null() {
            if strval == c_long::from((*enam).bitnum) {
                return CRYPTO_strdup((*enam).lname, FILE.as_ptr(), LINE_STRDUP);
            }
            enam = enam.add(1);
        }
    }
    // SAFETY: the caller's contract is forwarded to `i2s_ASN1_ENUMERATED`.
    unsafe { i2s_ASN1_ENUMERATED(method, e) }
}

/// `const X509V3_EXT_METHOD ossl_v3_crl_reason` — `crypto/x509/v3_enum.c:32-39`.
pub static ossl_v3_crl_reason: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_crl_reason,
    ext_flags: 0,
    it: Some(ASN1_ENUMERATED_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: as_i2s(i2s_ASN1_ENUMERATED_TABLE),
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    // `crl_reasons` — the row's own `usr_data`.
    usr_data: core::ptr::addr_of!(CRL_REASONS).cast_mut().cast::<c_void>(),
};
