//! `crypto/ts/ts_rsp_print.c` — the response text forms. Phase 12.5.
//!
//! `TS_RESP_print_bio`, `TS_STATUS_INFO_print_bio` and `TS_TST_INFO_print_bio`, plus the two
//! private helpers `ts_status_map_print` and `ts_ACCURACY_print_bio`. The status and failure maps
//! are the authority's own string tables; `TS_TST_INFO`'s `tsa` arm prints through
//! `i2v_GENERAL_NAME`/`X509V3_EXT_val_prn`.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_void};

use crate::asn1::a_strex::ASN1_STRING_print_ex;
use crate::asn1::bitstr::ASN1_BIT_STRING_get_bit;
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::v3_prn::X509V3_EXT_val_prn;
use crate::x509::v3_san::i2v_GENERAL_NAME;
use crate::x509::v3_utl::X509V3_conf_free;

use super::ts_asn1::{TsAccuracy, TsResp, TsStatusInfo, TsTstInfo};
use super::ts_lib::TS_ext_print_bio;
use super::ts_lib::{TS_ASN1_INTEGER_print_bio, TS_MSG_IMPRINT_print_bio, TS_OBJ_print_bio};

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509V3_conf_free`.
///
/// # Safety
/// `p` is a `CONF_VALUE` per the stack's element type.
unsafe extern "C" fn x509v3_conf_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509V3_conf_free(p.cast()) };
}

/// `struct status_map_st` — `ts_rsp_print.c:18-21`.
#[repr(C)]
struct StatusMap {
    bit: c_int,
    text: &'static core::ffi::CStr,
}

/// `TS_INFO_BAD_ALG` — `include/openssl/ts.h`.
const TS_INFO_BAD_ALG: c_int = 0;
/// `TS_INFO_BAD_REQUEST` — `include/openssl/ts.h`.
const TS_INFO_BAD_REQUEST: c_int = 2;
/// `TS_INFO_BAD_DATA_FORMAT` — `include/openssl/ts.h`.
const TS_INFO_BAD_DATA_FORMAT: c_int = 5;
/// `TS_INFO_TIME_NOT_AVAILABLE` — `include/openssl/ts.h`.
const TS_INFO_TIME_NOT_AVAILABLE: c_int = 14;
/// `TS_INFO_UNACCEPTED_POLICY` — `include/openssl/ts.h`.
const TS_INFO_UNACCEPTED_POLICY: c_int = 15;
/// `TS_INFO_UNACCEPTED_EXTENSION` — `include/openssl/ts.h`.
const TS_INFO_UNACCEPTED_EXTENSION: c_int = 16;
/// `TS_INFO_ADD_INFO_NOT_AVAILABLE` — `include/openssl/ts.h`.
const TS_INFO_ADD_INFO_NOT_AVAILABLE: c_int = 17;
/// `TS_INFO_SYSTEM_FAILURE` — `include/openssl/ts.h`.
const TS_INFO_SYSTEM_FAILURE: c_int = 25;

/// `int TS_RESP_print_bio(BIO *bio, TS_RESP *a)` — `ts_rsp_print.c:27-39`.
///
/// # Safety
/// `bio` is live; `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_print_bio(bio: *mut Bio, a: *mut TsResp) -> c_int {
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Status info:\n".as_ptr()) };
    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_STATUS_INFO_print_bio(bio, (*a).status_info) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"\nTST info:\n".as_ptr()) };
    // SAFETY: `a` is live.
    if !unsafe { (*a).tst_info }.is_null() {
        // SAFETY: `bio` is live and `tst_info` is live.
        unsafe { TS_TST_INFO_print_bio(bio, (*a).tst_info) };
    } else {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"Not included.\n".as_ptr()) };
    }

    1
}

/// `int TS_STATUS_INFO_print_bio(BIO *bio, TS_STATUS_INFO *a)` — `ts_rsp_print.c:41-99`.
///
/// # Safety
/// `bio` is live; `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_print_bio(
    bio: *mut Bio,
    a: *mut TsStatusInfo,
) -> c_int {
    static STATUS_MAP: [&core::ffi::CStr; 6] = [
        c"Granted.",
        c"Granted with modifications.",
        c"Rejected.",
        c"Waiting.",
        c"Revocation warning.",
        c"Revoked.",
    ];
    static FAILURE_MAP: [StatusMap; 9] = [
        StatusMap {
            bit: TS_INFO_BAD_ALG,
            text: c"unrecognized or unsupported algorithm identifier",
        },
        StatusMap {
            bit: TS_INFO_BAD_REQUEST,
            text: c"transaction not permitted or supported",
        },
        StatusMap {
            bit: TS_INFO_BAD_DATA_FORMAT,
            text: c"the data submitted has the wrong format",
        },
        StatusMap {
            bit: TS_INFO_TIME_NOT_AVAILABLE,
            text: c"the TSA's time source is not available",
        },
        StatusMap {
            bit: TS_INFO_UNACCEPTED_POLICY,
            text: c"the requested TSA policy is not supported by the TSA",
        },
        StatusMap {
            bit: TS_INFO_UNACCEPTED_EXTENSION,
            text: c"the requested extension is not supported by the TSA",
        },
        StatusMap {
            bit: TS_INFO_ADD_INFO_NOT_AVAILABLE,
            text: c"the additional information requested could not be understood \
                   or is not available",
        },
        StatusMap {
            bit: TS_INFO_SYSTEM_FAILURE,
            text: c"the request cannot be handled due to system failure",
        },
        StatusMap { bit: -1, text: c"" },
    ];
    let mut lines = 0;

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Status: ".as_ptr()) };
    // SAFETY: `a` is live.
    let status = unsafe { ASN1_INTEGER_get((*a).status) };
    if (0..STATUS_MAP.len() as c_long).contains(&status) {
        // SAFETY: `bio` is live and the entry is a static literal.
        unsafe { BIO_printf(bio, c"%s\n".as_ptr(), STATUS_MAP[status as usize].as_ptr()) };
    } else {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"out of bounds\n".as_ptr()) };
    }

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Status description: ".as_ptr()) };
    // SAFETY: `a` is live.
    let text = unsafe { (*a).text };
    // SAFETY: `text` is NULL or live.
    let num = unsafe { OPENSSL_sk_num(text) };
    let mut i = 0;
    while i < num {
        if i > 0 {
            // SAFETY: `bio` is live.
            unsafe { crate::runtime::bio::iolib::BIO_puts(bio, c"\t".as_ptr()) };
        }
        // SAFETY: `text` is live and `i` is in range.
        let s = unsafe { OPENSSL_sk_value(text, i) }.cast::<Asn1String>();
        // SAFETY: `bio` and `s` are live.
        unsafe { ASN1_STRING_print_ex(bio, s, 0) };
        // SAFETY: `bio` is live.
        unsafe { crate::runtime::bio::iolib::BIO_puts(bio, c"\n".as_ptr()) };
        i += 1;
    }
    if i == 0 {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified\n".as_ptr()) };
    }

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Failure info: ".as_ptr()) };
    // SAFETY: `a` is live.
    if !unsafe { (*a).failure_info }.is_null() {
        // SAFETY: `bio` is live and `failure_info` is live.
        lines = unsafe { ts_status_map_print(bio, FAILURE_MAP.as_ptr(), (*a).failure_info) };
    }
    if lines == 0 {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"\n".as_ptr()) };

    1
}

/// `ts_status_map_print(BIO *bio, const struct status_map_st *a, const ASN1_BIT_STRING *v)` —
/// `ts_rsp_print.c:101-115`.
///
/// # Safety
/// `bio` is live; `a` points at a `-1`-terminated table; `v` is live.
unsafe fn ts_status_map_print(
    bio: *mut Bio,
    mut a: *const StatusMap,
    v: *const Asn1String,
) -> c_int {
    let mut lines = 0;

    // SAFETY: `a` walks a `-1`-terminated table.
    while unsafe { (*a).bit } >= 0 {
        // SAFETY: `v` is live and the bit number is the table's.
        if unsafe { ASN1_BIT_STRING_get_bit(v, (*a).bit) } != 0 {
            lines += 1;
            if lines > 1 {
                // SAFETY: `bio` is live.
                unsafe { BIO_printf(bio, c", ".as_ptr()) };
            }
            // SAFETY: `bio` is live and the text is a static literal.
            unsafe { BIO_printf(bio, c"%s".as_ptr(), (*a).text.as_ptr()) };
        }
        // SAFETY: advancing over the table.
        a = unsafe { a.add(1) };
    }

    lines
}

/// `int TS_TST_INFO_print_bio(BIO *bio, TS_TST_INFO *a)` — `ts_rsp_print.c:117-173`.
///
/// # Safety
/// `bio` is live; `a` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_print_bio(bio: *mut Bio, a: *mut TsTstInfo) -> c_int {
    if a.is_null() {
        return 0;
    }

    // SAFETY: `a` is live.
    let v = unsafe { ASN1_INTEGER_get((*a).version) };
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Version: %d\n".as_ptr(), v as c_int) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Policy OID: ".as_ptr()) };
    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_OBJ_print_bio(bio, (*a).policy_id) };

    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_MSG_IMPRINT_print_bio(bio, (*a).msg_imprint) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Serial number: ".as_ptr()) };
    // SAFETY: `a` is live.
    if unsafe { (*a).serial }.is_null() {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    } else {
        // SAFETY: `bio` is live and `serial` is live.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, (*a).serial) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Time stamp: ".as_ptr()) };
    // SAFETY: `bio` is live and `a` is live.
    unsafe { ASN1_GENERALIZEDTIME_print(bio, (*a).time) };
    // SAFETY: `bio` is live.
    unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Accuracy: ".as_ptr()) };
    // SAFETY: `a` is live.
    if unsafe { (*a).accuracy }.is_null() {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    } else {
        // SAFETY: `bio` is live and `accuracy` is live.
        unsafe { ts_ACCURACY_print_bio(bio, (*a).accuracy) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };

    // SAFETY: `a` is live.
    let ordering = if unsafe { (*a).ordering } != 0 {
        c"yes"
    } else {
        c"no"
    };
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Ordering: %s\n".as_ptr(), ordering.as_ptr()) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Nonce: ".as_ptr()) };
    // SAFETY: `a` is live.
    if unsafe { (*a).nonce }.is_null() {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    } else {
        // SAFETY: `bio` is live and `nonce` is live.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, (*a).nonce) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"TSA: ".as_ptr()) };
    // SAFETY: `a` is live.
    if unsafe { (*a).tsa }.is_null() {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    } else {
        // SAFETY: `bio` is live and `tsa` is live.
        let nval =
            unsafe { i2v_GENERAL_NAME(core::ptr::null_mut(), (*a).tsa, core::ptr::null_mut()) };
        if !nval.is_null() {
            // SAFETY: `bio` is live and `nval` is live.
            unsafe { X509V3_EXT_val_prn(bio, nval, 0, 0) };
        }
        // SAFETY: `nval` is NULL or a stack of `CONF_VALUE`.
        unsafe { OPENSSL_sk_pop_free(nval, Some(x509v3_conf_free_void)) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_write(bio, c"\n".as_ptr().cast(), 1) };

    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_ext_print_bio(bio, (*a).extensions) };

    1
}

/// `ts_ACCURACY_print_bio(BIO *bio, const TS_ACCURACY *a)` — `ts_rsp_print.c:175-194`.
///
/// # Safety
/// `bio` is live; `a` is live.
unsafe fn ts_ACCURACY_print_bio(bio: *mut Bio, a: *const TsAccuracy) -> c_int {
    // SAFETY: `a` is live.
    if !unsafe { (*a).seconds }.is_null() {
        // SAFETY: `bio` is live and `seconds` is live.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, (*a).seconds) };
    } else {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c" seconds, ".as_ptr()) };
    // SAFETY: `a` is live.
    if !unsafe { (*a).millis }.is_null() {
        // SAFETY: `bio` is live and `millis` is live.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, (*a).millis) };
    } else {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c" millis, ".as_ptr()) };
    // SAFETY: `a` is live.
    if !unsafe { (*a).micros }.is_null() {
        // SAFETY: `bio` is live and `micros` is live.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, (*a).micros) };
    } else {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified".as_ptr()) };
    }
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c" micros".as_ptr()) };

    1
}
