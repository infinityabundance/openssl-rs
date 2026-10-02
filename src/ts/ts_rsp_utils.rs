//! `crypto/ts/ts_rsp_utils.c` — the `TS_RESP`/`TS_TST_INFO`/`TS_STATUS_INFO`/`TS_ACCURACY`
//! accessors. Phase 12.5.
//!
//! Every setter dup'ing its argument is the authority's own rule, and `TS_RESP_set_tst_info` is
//! the one that *adopts* (`Caller loses ownership of PKCS7 and TS_TST_INFO objects`). The
//! `TS_TST_INFO` extension stack mirrors `TS_REQ`'s, over the same `X509V3_*` family.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_void};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_dup, ASN1_INTEGER_get, ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{ASN1_GENERALIZEDTIME_free, ASN1_INTEGER_free, ASN1_STRING_dup};
use crate::pkcs7::pk7_asn1::{PKCS7_free, Pkcs7};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{OPENSSL_sk_pop_free, OpenSslStack};
use crate::x509::v3_genn::{GENERAL_NAME_dup, GENERAL_NAME_free, GeneralName};
use crate::x509::v3_lib::X509V3_get_d2i;
use crate::x509::x509_v3::{
    X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};

use super::ts_asn1::{
    TS_ACCURACY_dup, TS_ACCURACY_free, TS_MSG_IMPRINT_dup, TS_MSG_IMPRINT_free, TS_STATUS_INFO_dup,
    TS_STATUS_INFO_free, TS_TST_INFO_free, TsAccuracy, TsMsgImprint, TsResp, TsStatusInfo,
    TsTstInfo,
};
use super::{raise_ts, ERR_R_ASN1_LIB, ERR_R_OBJ_LIB, ERR_R_TS_LIB};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_rsp_utils.c";

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509_EXTENSION_free`.
///
/// # Safety
/// `p` is an `X509_EXTENSION` per the stack's element type.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// TS_RESP
// ---------------------------------------------------------------------------------------------

/// `int TS_RESP_set_status_info(TS_RESP *a, TS_STATUS_INFO *status_info)` — `ts_rsp_utils.c:17-32`.
///
/// # Safety
/// `a` is live; `status_info` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_set_status_info(
    a: *mut TsResp,
    status_info: *mut TsStatusInfo,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).status_info }, status_info) {
        return 1;
    }
    // SAFETY: `status_info` is live.
    let new_status_info = unsafe { TS_STATUS_INFO_dup(status_info) };
    if new_status_info.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 24, c"TS_RESP_set_status_info", ERR_R_TS_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        TS_STATUS_INFO_free((*a).status_info);
        (*a).status_info = new_status_info;
    }
    1
}

/// `TS_STATUS_INFO *TS_RESP_get_status_info(TS_RESP *a)` — `ts_rsp_utils.c:34-37`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_get_status_info(a: *mut TsResp) -> *mut TsStatusInfo {
    // SAFETY: `a` is live.
    unsafe { (*a).status_info }
}

/// `void TS_RESP_set_tst_info(TS_RESP *a, PKCS7 *p7, TS_TST_INFO *tst_info)` — `ts_rsp_utils.c:40-46`.
///
/// # Safety
/// `a` is live; `p7` and `tst_info` are NULL or owned values whose ownership transfers.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_set_tst_info(
    a: *mut TsResp,
    p7: *mut Pkcs7,
    tst_info: *mut TsTstInfo,
) {
    // SAFETY: `a` is live.
    unsafe {
        PKCS7_free((*a).token);
        (*a).token = p7;
        TS_TST_INFO_free((*a).tst_info);
        (*a).tst_info = tst_info;
    }
}

/// `PKCS7 *TS_RESP_get_token(TS_RESP *a)` — `ts_rsp_utils.c:48-51`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_get_token(a: *mut TsResp) -> *mut Pkcs7 {
    // SAFETY: `a` is live.
    unsafe { (*a).token }
}

/// `TS_TST_INFO *TS_RESP_get_tst_info(TS_RESP *a)` — `ts_rsp_utils.c:53-56`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_RESP_get_tst_info(a: *mut TsResp) -> *mut TsTstInfo {
    // SAFETY: `a` is live.
    unsafe { (*a).tst_info }
}

// ---------------------------------------------------------------------------------------------
// TS_TST_INFO
// ---------------------------------------------------------------------------------------------

/// `int TS_TST_INFO_set_version(TS_TST_INFO *a, long version)` — `ts_rsp_utils.c:58-61`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_version(
    a: *mut TsTstInfo,
    version: c_long,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { ASN1_INTEGER_set((*a).version, version) }
}

/// `long TS_TST_INFO_get_version(const TS_TST_INFO *a)` — `ts_rsp_utils.c:63-66`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_version(a: *const TsTstInfo) -> c_long {
    // SAFETY: `a` is live.
    unsafe { ASN1_INTEGER_get((*a).version) }
}

/// `int TS_TST_INFO_set_policy_id(TS_TST_INFO *a, ASN1_OBJECT *policy)` — `ts_rsp_utils.c:68-82`.
///
/// # Safety
/// `a` is live; `policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_policy_id(
    a: *mut TsTstInfo,
    policy: *mut Asn1Object,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).policy_id }, policy) {
        return 1;
    }
    // SAFETY: `policy` is live.
    let new_policy = unsafe { OBJ_dup(policy) };
    if new_policy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 76, c"TS_TST_INFO_set_policy_id", ERR_R_OBJ_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_OBJECT_free((*a).policy_id);
        (*a).policy_id = new_policy;
    }
    1
}

/// `ASN1_OBJECT *TS_TST_INFO_get_policy_id(TS_TST_INFO *a)` — `ts_rsp_utils.c:84-87`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_policy_id(a: *mut TsTstInfo) -> *mut Asn1Object {
    // SAFETY: `a` is live.
    unsafe { (*a).policy_id }
}

/// `int TS_TST_INFO_set_msg_imprint(TS_TST_INFO *a, TS_MSG_IMPRINT *msg_imprint)` —
/// `ts_rsp_utils.c:89-103`.
///
/// # Safety
/// `a` is live; `msg_imprint` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_msg_imprint(
    a: *mut TsTstInfo,
    msg_imprint: *mut TsMsgImprint,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).msg_imprint }, msg_imprint) {
        return 1;
    }
    // SAFETY: `msg_imprint` is live.
    let new_msg_imprint = unsafe { TS_MSG_IMPRINT_dup(msg_imprint) };
    if new_msg_imprint.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 97, c"TS_TST_INFO_set_msg_imprint", ERR_R_TS_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        TS_MSG_IMPRINT_free((*a).msg_imprint);
        (*a).msg_imprint = new_msg_imprint;
    }
    1
}

/// `TS_MSG_IMPRINT *TS_TST_INFO_get_msg_imprint(TS_TST_INFO *a)` — `ts_rsp_utils.c:105-108`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_msg_imprint(
    a: *mut TsTstInfo,
) -> *mut TsMsgImprint {
    // SAFETY: `a` is live.
    unsafe { (*a).msg_imprint }
}

/// `int TS_TST_INFO_set_serial(TS_TST_INFO *a, const ASN1_INTEGER *serial)` —
/// `ts_rsp_utils.c:110-124`.
///
/// # Safety
/// `a` is live; `serial` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_serial(
    a: *mut TsTstInfo,
    serial: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).serial }, serial) {
        return 1;
    }
    // SAFETY: `serial` is live.
    let new_serial = unsafe { ASN1_INTEGER_dup(serial) };
    if new_serial.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 118, c"TS_TST_INFO_set_serial", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).serial);
        (*a).serial = new_serial;
    }
    1
}

/// `const ASN1_INTEGER *TS_TST_INFO_get_serial(const TS_TST_INFO *a)` — `ts_rsp_utils.c:126-129`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_serial(a: *const TsTstInfo) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).serial }
}

/// `int TS_TST_INFO_set_time(TS_TST_INFO *a, const ASN1_GENERALIZEDTIME *gtime)` —
/// `ts_rsp_utils.c:131-145`.
///
/// # Safety
/// `a` is live; `gtime` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_time(
    a: *mut TsTstInfo,
    gtime: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).time }, gtime) {
        return 1;
    }
    // SAFETY: `gtime` is live.
    let new_time = unsafe { ASN1_STRING_dup(gtime) };
    if new_time.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 139, c"TS_TST_INFO_set_time", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_GENERALIZEDTIME_free((*a).time);
        (*a).time = new_time;
    }
    1
}

/// `const ASN1_GENERALIZEDTIME *TS_TST_INFO_get_time(const TS_TST_INFO *a)` —
/// `ts_rsp_utils.c:147-150`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_time(a: *const TsTstInfo) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).time }
}

/// `int TS_TST_INFO_set_accuracy(TS_TST_INFO *a, TS_ACCURACY *accuracy)` —
/// `ts_rsp_utils.c:152-166`.
///
/// # Safety
/// `a` is live; `accuracy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_accuracy(
    a: *mut TsTstInfo,
    accuracy: *mut TsAccuracy,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).accuracy }, accuracy) {
        return 1;
    }
    // SAFETY: `accuracy` is live.
    let new_accuracy = unsafe { TS_ACCURACY_dup(accuracy) };
    if new_accuracy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 160, c"TS_TST_INFO_set_accuracy", ERR_R_TS_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        TS_ACCURACY_free((*a).accuracy);
        (*a).accuracy = new_accuracy;
    }
    1
}

/// `TS_ACCURACY *TS_TST_INFO_get_accuracy(TS_TST_INFO *a)` — `ts_rsp_utils.c:168-171`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_accuracy(a: *mut TsTstInfo) -> *mut TsAccuracy {
    // SAFETY: `a` is live.
    unsafe { (*a).accuracy }
}

/// `int TS_ACCURACY_set_seconds(TS_ACCURACY *a, const ASN1_INTEGER *seconds)` —
/// `ts_rsp_utils.c:173-187`.
///
/// # Safety
/// `a` is live; `seconds` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_set_seconds(
    a: *mut TsAccuracy,
    seconds: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).seconds }, seconds) {
        return 1;
    }
    // SAFETY: `seconds` is live.
    let new_seconds = unsafe { ASN1_INTEGER_dup(seconds) };
    if new_seconds.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 181, c"TS_ACCURACY_set_seconds", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).seconds);
        (*a).seconds = new_seconds;
    }
    1
}

/// `const ASN1_INTEGER *TS_ACCURACY_get_seconds(const TS_ACCURACY *a)` — `ts_rsp_utils.c:189-192`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_get_seconds(a: *const TsAccuracy) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).seconds }
}

/// `int TS_ACCURACY_set_millis(TS_ACCURACY *a, const ASN1_INTEGER *millis)` —
/// `ts_rsp_utils.c:194-210`.
///
/// # Safety
/// `a` is live; `millis` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_set_millis(
    a: *mut TsAccuracy,
    millis: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).millis }, millis) {
        return 1;
    }
    let mut new_millis: *mut Asn1String = core::ptr::null_mut();
    if !millis.is_null() {
        // SAFETY: `millis` is live.
        new_millis = unsafe { ASN1_INTEGER_dup(millis) };
        if new_millis.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 203, c"TS_ACCURACY_set_millis", ERR_R_ASN1_LIB) };
            return 0;
        }
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).millis);
        (*a).millis = new_millis;
    }
    1
}

/// `const ASN1_INTEGER *TS_ACCURACY_get_millis(const TS_ACCURACY *a)` — `ts_rsp_utils.c:212-215`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_get_millis(a: *const TsAccuracy) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).millis }
}

/// `int TS_ACCURACY_set_micros(TS_ACCURACY *a, const ASN1_INTEGER *micros)` —
/// `ts_rsp_utils.c:217-233`.
///
/// # Safety
/// `a` is live; `micros` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_set_micros(
    a: *mut TsAccuracy,
    micros: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).micros }, micros) {
        return 1;
    }
    let mut new_micros: *mut Asn1String = core::ptr::null_mut();
    if !micros.is_null() {
        // SAFETY: `micros` is live.
        new_micros = unsafe { ASN1_INTEGER_dup(micros) };
        if new_micros.is_null() {
            // SAFETY: a compile-time coordinate.
            unsafe { raise_ts(FILE, 226, c"TS_ACCURACY_set_micros", ERR_R_ASN1_LIB) };
            return 0;
        }
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).micros);
        (*a).micros = new_micros;
    }
    1
}

/// `const ASN1_INTEGER *TS_ACCURACY_get_micros(const TS_ACCURACY *a)` — `ts_rsp_utils.c:235-238`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_ACCURACY_get_micros(a: *const TsAccuracy) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).micros }
}

/// `int TS_TST_INFO_set_ordering(TS_TST_INFO *a, int ordering)` — `ts_rsp_utils.c:240-244`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_ordering(
    a: *mut TsTstInfo,
    ordering: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { (*a).ordering = if ordering != 0 { 0xFF } else { 0x00 } };
    1
}

/// `int TS_TST_INFO_get_ordering(const TS_TST_INFO *a)` — `ts_rsp_utils.c:246-249`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ordering(a: *const TsTstInfo) -> c_int {
    // SAFETY: `a` is live.
    (if unsafe { (*a).ordering } != 0 { 1 } else { 0 }) as c_int
}

/// `int TS_TST_INFO_set_nonce(TS_TST_INFO *a, const ASN1_INTEGER *nonce)` —
/// `ts_rsp_utils.c:251-265`.
///
/// # Safety
/// `a` is live; `nonce` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_nonce(
    a: *mut TsTstInfo,
    nonce: *const Asn1String,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).nonce }, nonce) {
        return 1;
    }
    // SAFETY: `nonce` is live.
    let new_nonce = unsafe { ASN1_INTEGER_dup(nonce) };
    if new_nonce.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 259, c"TS_TST_INFO_set_nonce", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).nonce);
        (*a).nonce = new_nonce;
    }
    1
}

/// `const ASN1_INTEGER *TS_TST_INFO_get_nonce(const TS_TST_INFO *a)` — `ts_rsp_utils.c:267-270`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_nonce(a: *const TsTstInfo) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).nonce }
}

/// `int TS_TST_INFO_set_tsa(TS_TST_INFO *a, GENERAL_NAME *tsa)` — `ts_rsp_utils.c:272-286`.
///
/// # Safety
/// `a` is live; `tsa` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_set_tsa(
    a: *mut TsTstInfo,
    tsa: *mut GeneralName,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).tsa }, tsa) {
        return 1;
    }
    // SAFETY: `tsa` is live.
    let new_tsa = unsafe { GENERAL_NAME_dup(tsa) };
    if new_tsa.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 280, c"TS_TST_INFO_set_tsa", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        GENERAL_NAME_free((*a).tsa);
        (*a).tsa = new_tsa;
    }
    1
}

/// `GENERAL_NAME *TS_TST_INFO_get_tsa(TS_TST_INFO *a)` — `ts_rsp_utils.c:288-291`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_tsa(a: *mut TsTstInfo) -> *mut GeneralName {
    // SAFETY: `a` is live.
    unsafe { (*a).tsa }
}

/// `STACK_OF(X509_EXTENSION) *TS_TST_INFO_get_exts(TS_TST_INFO *a)` — `ts_rsp_utils.c:293-296`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_exts(a: *mut TsTstInfo) -> *mut OpenSslStack {
    // SAFETY: `a` is live.
    unsafe { (*a).extensions }
}

/// `void TS_TST_INFO_ext_free(TS_TST_INFO *a)` — `ts_rsp_utils.c:298-304`.
///
/// # Safety
/// `a` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_ext_free(a: *mut TsTstInfo) {
    if a.is_null() {
        return;
    }
    // SAFETY: `a` is live.
    unsafe {
        OPENSSL_sk_pop_free((*a).extensions, Some(x509_extension_free_void));
        (*a).extensions = core::ptr::null_mut();
    }
}

/// `int TS_TST_INFO_get_ext_count(TS_TST_INFO *a)` — `ts_rsp_utils.c:306-309`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext_count(a: *mut TsTstInfo) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_count((*a).extensions) }
}

/// `int TS_TST_INFO_get_ext_by_NID(TS_TST_INFO *a, int nid, int lastpos)` —
/// `ts_rsp_utils.c:311-314`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext_by_NID(
    a: *mut TsTstInfo,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_NID((*a).extensions, nid, lastpos) }
}

/// `int TS_TST_INFO_get_ext_by_OBJ(TS_TST_INFO *a, const ASN1_OBJECT *obj, int lastpos)` —
/// `ts_rsp_utils.c:316-319`.
///
/// # Safety
/// `a` is live; `obj` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext_by_OBJ(
    a: *mut TsTstInfo,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_OBJ((*a).extensions, obj, lastpos) }
}

/// `int TS_TST_INFO_get_ext_by_critical(TS_TST_INFO *a, int crit, int lastpos)` —
/// `ts_rsp_utils.c:321-324`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext_by_critical(
    a: *mut TsTstInfo,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_critical((*a).extensions, crit, lastpos) }
}

/// `X509_EXTENSION *TS_TST_INFO_get_ext(TS_TST_INFO *a, int loc)` — `ts_rsp_utils.c:326-329`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext(
    a: *mut TsTstInfo,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext((*a).extensions, loc) }
}

/// `X509_EXTENSION *TS_TST_INFO_delete_ext(TS_TST_INFO *a, int loc)` — `ts_rsp_utils.c:331-334`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_delete_ext(
    a: *mut TsTstInfo,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `a` is live.
    unsafe { X509v3_delete_ext((*a).extensions, loc) }
}

/// `int TS_TST_INFO_add_ext(TS_TST_INFO *a, X509_EXTENSION *ex, int loc)` — `ts_rsp_utils.c:336-339`.
///
/// # Safety
/// `a` is live; `ex` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_add_ext(
    a: *mut TsTstInfo,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    (!unsafe { X509v3_add_ext(&mut (*a).extensions, ex, loc) }.is_null()) as c_int
}

/// `void *TS_TST_INFO_get_ext_d2i(TS_TST_INFO *a, int nid, int *crit, int *idx)` —
/// `ts_rsp_utils.c:341-344`.
///
/// # Safety
/// `a` is live; `crit`/`idx` are NULL or writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_TST_INFO_get_ext_d2i(
    a: *mut TsTstInfo,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `a` is live.
    unsafe { X509V3_get_d2i((*a).extensions, nid, crit, idx) }
}

// ---------------------------------------------------------------------------------------------
// TS_STATUS_INFO
// ---------------------------------------------------------------------------------------------

/// `int TS_STATUS_INFO_set_status(TS_STATUS_INFO *a, int i)` — `ts_rsp_utils.c:346-349`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_set_status(a: *mut TsStatusInfo, i: c_int) -> c_int {
    // SAFETY: `a` is live.
    unsafe { ASN1_INTEGER_set((*a).status, i as c_long) }
}

/// `const ASN1_INTEGER *TS_STATUS_INFO_get0_status(const TS_STATUS_INFO *a)` —
/// `ts_rsp_utils.c:351-354`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_get0_status(
    a: *const TsStatusInfo,
) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).status }
}

/// `const STACK_OF(ASN1_UTF8STRING) *TS_STATUS_INFO_get0_text(const TS_STATUS_INFO *a)` —
/// `ts_rsp_utils.c:356-360`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_get0_text(
    a: *const TsStatusInfo,
) -> *const OpenSslStack {
    // SAFETY: `a` is live.
    unsafe { (*a).text }
}

/// `const ASN1_BIT_STRING *TS_STATUS_INFO_get0_failure_info(const TS_STATUS_INFO *a)` —
/// `ts_rsp_utils.c:362-365`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_STATUS_INFO_get0_failure_info(
    a: *const TsStatusInfo,
) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).failure_info }
}
