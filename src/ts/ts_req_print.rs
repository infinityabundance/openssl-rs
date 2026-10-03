//! `crypto/ts/ts_req_print.c` — `TS_REQ_print_bio`. Phase 12.5.
//!
//! The request's text form, composed from the [`super::ts_lib`] helpers and fixed literals. The
//! court compares its bytes against the authority's, which is why the literals are the authority's
//! own spelling rather than an equivalent one.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::c_int;

use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;

use super::ts_asn1::TsReq;
use super::ts_lib::{TS_ASN1_INTEGER_print_bio, TS_MSG_IMPRINT_print_bio, TS_OBJ_print_bio};
use super::ts_req_utils::TS_REQ_get_policy_id;
use super::{ts_lib::TS_ext_print_bio, ts_req_utils::TS_REQ_get_version};

/// `int TS_REQ_print_bio(BIO *bio, TS_REQ *a)` — `ts_req_print.c:18-51`.
///
/// # Safety
/// `bio` is live; `a` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_print_bio(bio: *mut Bio, a: *mut TsReq) -> c_int {
    if a.is_null() {
        return 0;
    }

    // SAFETY: `a` is live.
    let v = unsafe { TS_REQ_get_version(a) };
    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Version: %d\n".as_ptr(), v as c_int) };

    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_MSG_IMPRINT_print_bio(bio, (*a).msg_imprint) };

    // SAFETY: `bio` is live.
    unsafe { BIO_printf(bio, c"Policy OID: ".as_ptr()) };
    // SAFETY: `a` is live.
    let policy_id = unsafe { TS_REQ_get_policy_id(a) };
    if policy_id.is_null() {
        // SAFETY: `bio` is live.
        unsafe { BIO_printf(bio, c"unspecified\n".as_ptr()) };
    } else {
        // SAFETY: `bio` and `policy_id` are live.
        unsafe { TS_OBJ_print_bio(bio, policy_id) };
    }

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

    // SAFETY: `a` is live.
    let cert_req = if unsafe { (*a).cert_req } != 0 {
        c"yes"
    } else {
        c"no"
    };
    // SAFETY: `bio` is live.
    unsafe {
        BIO_printf(
            bio,
            c"Certificate required: %s\n".as_ptr(),
            cert_req.as_ptr(),
        )
    };

    // SAFETY: `bio` is live and `a` is live.
    unsafe { TS_ext_print_bio(bio, (*a).extensions) };

    1
}
