//! `crypto/ct/ct_prn.c` — the SCT pretty-printer and the validation-status string. Phase
//! 10.14.15's CT layer. This unit carries `SCT_LIST_print`, one of the names `ct_x509v3.c` is
//! blocked on.
//!
//! `crypto/ct/ct_prn.c` is 127 lines and transcribes whole: the two `static` printers
//! `SCT_signature_algorithms_print` and `timestamp_print`, and the three exports
//! `SCT_validation_status_string`, `SCT_print` and `SCT_LIST_print`.
//!
//! **Withheld by name**: none. The unit raises nothing, so it declares no coordinates.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{
    ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_new, ASN1_STRING_get0_data,
};
use crate::asn1::time::{
    ASN1_GENERALIZEDTIME_adj, ASN1_GENERALIZEDTIME_print, ASN1_GENERALIZEDTIME_set_string,
};
use crate::ct::ct_log::{CTLOG_STORE_get0_log_by_id, CTLOG_get0_name, Ctlog, CtlogStore};
use crate::ct::ct_sct::{
    SCT_get_signature_nid, SCT_get_validation_status, Sct, SCT_VALIDATION_STATUS_INVALID,
    SCT_VALIDATION_STATUS_NOT_SET, SCT_VALIDATION_STATUS_UNKNOWN_LOG,
    SCT_VALIDATION_STATUS_UNKNOWN_VERSION, SCT_VALIDATION_STATUS_UNVERIFIED,
    SCT_VALIDATION_STATUS_VALID, SCT_VERSION_V1,
};
use crate::runtime::bio::dump::BIO_hex_string;
use crate::runtime::bio::print::{BIO_printf, BIO_snprintf};
use crate::runtime::bio::Bio;
use crate::runtime::obj::{NID_undef, OBJ_nid2ln};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};

/// `static void SCT_signature_algorithms_print(const SCT *sct, BIO *out)` —
/// `crypto/ct/ct_prn.c:132-140`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `out` is a live `BIO`.
unsafe fn SCT_signature_algorithms_print(sct: *const Sct, out: *mut Bio) {
    // SAFETY: `sct` is live per the contract.
    let nid = unsafe { SCT_get_signature_nid(sct) };
    if nid == NID_undef {
        // SAFETY: `out` is live and `sct` is live per the contract.
        unsafe {
            BIO_printf(
                out,
                c"%02X%02X".as_ptr(),
                (*sct).hash_alg as c_int,
                (*sct).sig_alg as c_int,
            );
        }
    } else {
        // SAFETY: `out` is live; `OBJ_nid2ln` answers a static string.
        unsafe { BIO_printf(out, c"%s".as_ptr(), OBJ_nid2ln(nid)) };
    }
}

/// `static void timestamp_print(uint64_t timestamp, BIO *out)` — `crypto/ct/ct_prn.c:142-161`.
///
/// # Safety
///
/// `out` is a live `BIO`.
unsafe fn timestamp_print(timestamp: u64, out: *mut Bio) {
    // SAFETY: no preconditions; the constructor answers NULL or a live value.
    let gen: *mut Asn1String = ASN1_GENERALIZEDTIME_new();
    if gen.is_null() {
        return;
    }
    // SAFETY: `gen` is live; the offsets are the authority's own divisions.
    unsafe {
        ASN1_GENERALIZEDTIME_adj(
            gen,
            0,
            (timestamp / 86_400_000) as c_int,
            ((timestamp % 86_400_000) / 1000) as core::ffi::c_long,
        );
    }

    // `BIO_snprintf(genstr, sizeof(genstr), "%.14s.%03dZ", ASN1_STRING_get0_data(gen),
    // (unsigned int)(timestamp % 1000))`.
    let mut genstr = [0 as c_char; 20];
    // SAFETY: `gen` is live; `genstr` is a 20-byte writable buffer.
    unsafe {
        let data = ASN1_STRING_get0_data(gen);
        BIO_snprintf(
            genstr.as_mut_ptr(),
            genstr.len(),
            c"%.14s.%03dZ".as_ptr(),
            data.cast::<c_char>(),
            (timestamp % 1000) as c_int,
        );
    }
    // SAFETY: `gen` is live; `genstr` is NUL-terminated by `BIO_snprintf`.
    if unsafe { ASN1_GENERALIZEDTIME_set_string(gen, genstr.as_ptr()) } != 0 {
        // SAFETY: `out` and `gen` are live per the contract/construction.
        unsafe { ASN1_GENERALIZEDTIME_print(out, gen) };
    }
    // SAFETY: `gen` is the value this call constructed.
    unsafe { ASN1_GENERALIZEDTIME_free(gen) };
}

/// `const char *SCT_validation_status_string(const SCT *sct)` — `crypto/ct/ct_prn.c:163-181`.
///
/// # Safety
///
/// `sct` is a live `SCT`.
#[no_mangle]
pub unsafe extern "C" fn SCT_validation_status_string(sct: *const Sct) -> *const c_char {
    // SAFETY: `sct` is live per the contract.
    match unsafe { SCT_get_validation_status(sct) } {
        SCT_VALIDATION_STATUS_NOT_SET => c"not set".as_ptr(),
        SCT_VALIDATION_STATUS_UNKNOWN_VERSION => c"unknown version".as_ptr(),
        SCT_VALIDATION_STATUS_UNKNOWN_LOG => c"unknown log".as_ptr(),
        SCT_VALIDATION_STATUS_UNVERIFIED => c"unverified".as_ptr(),
        SCT_VALIDATION_STATUS_INVALID => c"invalid".as_ptr(),
        SCT_VALIDATION_STATUS_VALID => c"valid".as_ptr(),
        _ => c"unknown status".as_ptr(),
    }
}

/// `void SCT_print(const SCT *sct, BIO *out, int indent, const CTLOG_STORE *log_store)` —
/// `crypto/ct/ct_prn.c:183-225`.
///
/// # Safety
///
/// `sct` is a live `SCT`; `out` is a live `BIO`; `log_store` is NULL or a live `CTLOG_STORE`.
#[no_mangle]
pub unsafe extern "C" fn SCT_print(
    sct: *const Sct,
    out: *mut Bio,
    indent: c_int,
    log_store: *const CtlogStore,
) {
    let mut log: *const Ctlog = ptr::null();

    if !log_store.is_null() {
        // SAFETY: `log_store` and `sct` are live per the contract.
        log = unsafe { CTLOG_STORE_get0_log_by_id(log_store, (*sct).log_id, (*sct).log_id_len) };
    }

    // SAFETY: `out` is live per the contract.
    unsafe {
        BIO_printf(
            out,
            c"%*sSigned Certificate Timestamp:".as_ptr(),
            indent,
            c"".as_ptr(),
        );
        BIO_printf(out, c"\n%*sVersion   : ".as_ptr(), indent + 4, c"".as_ptr());
    }

    // SAFETY: `sct` is live per the contract.
    if unsafe { (*sct).version } != SCT_VERSION_V1 {
        // SAFETY: `out` and `sct` are live per the contract.
        unsafe {
            BIO_printf(out, c"unknown\n%*s".as_ptr(), indent + 16, c"".as_ptr());
            BIO_hex_string(
                out,
                indent + 16,
                16,
                (*sct).sct.cast(),
                (*sct).sct_len as c_int,
            );
        }
        return;
    }

    // SAFETY: `out` is live per the contract.
    unsafe { BIO_printf(out, c"v1 (0x0)".as_ptr()) };

    if !log.is_null() {
        // SAFETY: `out` is live; `log` is non-NULL per the check and `CTLOG_get0_name` answers a
        // static string.
        unsafe {
            BIO_printf(
                out,
                c"\n%*sLog       : %s".as_ptr(),
                indent + 4,
                c"".as_ptr(),
                CTLOG_get0_name(log),
            );
        }
    }

    // SAFETY: `out` and `sct` are live per the contract.
    unsafe {
        BIO_printf(out, c"\n%*sLog ID    : ".as_ptr(), indent + 4, c"".as_ptr());
        BIO_hex_string(
            out,
            indent + 16,
            16,
            (*sct).log_id.cast(),
            (*sct).log_id_len as c_int,
        );

        BIO_printf(out, c"\n%*sTimestamp : ".as_ptr(), indent + 4, c"".as_ptr());
    }
    // SAFETY: `out` is live and `sct` is live per the contract.
    unsafe { timestamp_print((*sct).timestamp, out) };

    // SAFETY: `out` and `sct` are live per the contract.
    unsafe {
        BIO_printf(out, c"\n%*sExtensions: ".as_ptr(), indent + 4, c"".as_ptr());
        if (*sct).ext_len == 0 {
            BIO_printf(out, c"none".as_ptr());
        } else {
            BIO_hex_string(
                out,
                indent + 16,
                16,
                (*sct).ext.cast(),
                (*sct).ext_len as c_int,
            );
        }

        BIO_printf(out, c"\n%*sSignature : ".as_ptr(), indent + 4, c"".as_ptr());
    }
    // SAFETY: `sct` and `out` are live per the contract.
    unsafe { SCT_signature_algorithms_print(sct, out) };
    // SAFETY: `out` and `sct` are live per the contract.
    unsafe {
        BIO_printf(out, c"\n%*s            ".as_ptr(), indent + 4, c"".as_ptr());
        BIO_hex_string(
            out,
            indent + 16,
            16,
            (*sct).sig.cast(),
            (*sct).sig_len as c_int,
        );
    }
}

/// `void SCT_LIST_print(const STACK_OF(SCT) *sct_list, BIO *out, int indent, const char
/// *separator, const CTLOG_STORE *log_store)` — `crypto/ct/ct_prn.c:227-240`.
///
/// # Safety
///
/// `sct_list` is a live `STACK_OF(SCT)`; `out` is a live `BIO`; `separator` is a NUL-terminated
/// string; `log_store` is NULL or a live `CTLOG_STORE`.
#[no_mangle]
pub unsafe extern "C" fn SCT_LIST_print(
    sct_list: *const OpenSslStack,
    out: *mut Bio,
    indent: c_int,
    separator: *const c_char,
    log_store: *const CtlogStore,
) {
    // SAFETY: `sct_list` is live per the contract.
    let sct_count = unsafe { OPENSSL_sk_num(sct_list) };
    let mut i = 0;
    while i < sct_count {
        // SAFETY: `sct_list` is live and `i` is in bounds.
        let sct = unsafe { OPENSSL_sk_value(sct_list, i) }.cast::<Sct>();

        // SAFETY: `sct` is a live element; `out` and `log_store` are the caller's.
        unsafe { SCT_print(sct, out, indent, log_store) };
        // SAFETY: `sct_list` is live per the contract.
        if i < unsafe { OPENSSL_sk_num(sct_list) } - 1 {
            // SAFETY: `out` is live; `separator` is NUL-terminated per the contract.
            unsafe { BIO_printf(out, c"%s".as_ptr(), separator) };
        }
        i += 1;
    }
}
