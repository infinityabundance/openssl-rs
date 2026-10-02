//! `crypto/ts/ts_req_utils.c` — the `TS_REQ` accessors. Phase 12.5.
//!
//! `TS_REQ`'s scalar setters dup their argument (the authority never adopts the caller's object),
//! the extension stack is the `X509V3_*` family's, and `cert_req` is the `ASN1_BOOLEAN` the
//! template stores as an `int` with `0xFF` for true.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_dup, ASN1_INTEGER_get, ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_OCTET_STRING_set};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_dup, X509_ALGOR_free};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{OPENSSL_sk_pop_free, OpenSslStack};
use crate::x509::v3_lib::X509V3_get_d2i;
use crate::x509::x509_v3::{
    X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};

use super::ts_asn1::{TS_MSG_IMPRINT_dup, TS_MSG_IMPRINT_free, TsMsgImprint, TsReq};
use super::{raise_ts, ERR_R_ASN1_LIB, ERR_R_OBJ_LIB, ERR_R_TS_LIB};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/ts/ts_req_utils.c";

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `X509_EXTENSION_free`.
///
/// # Safety
/// `p` is an `X509_EXTENSION` per the stack's element type.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// `int TS_REQ_set_version(TS_REQ *a, long version)` — `ts_req_utils.c:17-20`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_set_version(a: *mut TsReq, version: c_long) -> c_int {
    // SAFETY: `a` is live.
    unsafe { ASN1_INTEGER_set((*a).version, version) }
}

/// `long TS_REQ_get_version(const TS_REQ *a)` — `ts_req_utils.c:22-25`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_version(a: *const TsReq) -> c_long {
    // SAFETY: `a` is live.
    unsafe { ASN1_INTEGER_get((*a).version) }
}

/// `int TS_REQ_set_msg_imprint(TS_REQ *a, TS_MSG_IMPRINT *msg_imprint)` — `ts_req_utils.c:27-41`.
///
/// # Safety
/// `a` is live; `msg_imprint` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_set_msg_imprint(
    a: *mut TsReq,
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
        unsafe { raise_ts(FILE, 35, c"TS_REQ_set_msg_imprint", ERR_R_TS_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        TS_MSG_IMPRINT_free((*a).msg_imprint);
        (*a).msg_imprint = new_msg_imprint;
    }
    1
}

/// `TS_MSG_IMPRINT *TS_REQ_get_msg_imprint(TS_REQ *a)` — `ts_req_utils.c:43-46`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_msg_imprint(a: *mut TsReq) -> *mut TsMsgImprint {
    // SAFETY: `a` is live.
    unsafe { (*a).msg_imprint }
}

/// `int TS_MSG_IMPRINT_set_algo(TS_MSG_IMPRINT *a, X509_ALGOR *alg)` — `ts_req_utils.c:48-62`.
///
/// # Safety
/// `a` is live; `alg` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_set_algo(
    a: *mut TsMsgImprint,
    alg: *mut X509Algor,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).hash_algo }, alg) {
        return 1;
    }
    // SAFETY: `alg` is live.
    let new_alg = unsafe { X509_ALGOR_dup(alg) };
    if new_alg.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 56, c"TS_MSG_IMPRINT_set_algo", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        X509_ALGOR_free((*a).hash_algo);
        (*a).hash_algo = new_alg;
    }
    1
}

/// `X509_ALGOR *TS_MSG_IMPRINT_get_algo(TS_MSG_IMPRINT *a)` — `ts_req_utils.c:64-67`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_get_algo(a: *mut TsMsgImprint) -> *mut X509Algor {
    // SAFETY: `a` is live.
    unsafe { (*a).hash_algo }
}

/// `int TS_MSG_IMPRINT_set_msg(TS_MSG_IMPRINT *a, unsigned char *d, int len)` —
/// `ts_req_utils.c:69-72`.
///
/// # Safety
/// `a` is live; `d` points at `len` bytes.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_set_msg(
    a: *mut TsMsgImprint,
    d: *mut c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `a` is live and `d` holds `len` bytes.
    unsafe { ASN1_OCTET_STRING_set((*a).hashed_msg, d, len) }
}

/// `ASN1_OCTET_STRING *TS_MSG_IMPRINT_get_msg(TS_MSG_IMPRINT *a)` — `ts_req_utils.c:74-77`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_MSG_IMPRINT_get_msg(a: *mut TsMsgImprint) -> *mut Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).hashed_msg }
}

/// `int TS_REQ_set_policy_id(TS_REQ *a, const ASN1_OBJECT *policy)` — `ts_req_utils.c:79-93`.
///
/// # Safety
/// `a` is live; `policy` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_set_policy_id(
    a: *mut TsReq,
    policy: *const Asn1Object,
) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).policy_id }, policy) {
        return 1;
    }
    // SAFETY: `policy` is live.
    let new_policy = unsafe { OBJ_dup(policy) };
    if new_policy.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 87, c"TS_REQ_set_policy_id", ERR_R_OBJ_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_OBJECT_free((*a).policy_id);
        (*a).policy_id = new_policy;
    }
    1
}

/// `ASN1_OBJECT *TS_REQ_get_policy_id(TS_REQ *a)` — `ts_req_utils.c:95-98`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_policy_id(a: *mut TsReq) -> *mut Asn1Object {
    // SAFETY: `a` is live.
    unsafe { (*a).policy_id }
}

/// `int TS_REQ_set_nonce(TS_REQ *a, const ASN1_INTEGER *nonce)` — `ts_req_utils.c:100-114`.
///
/// # Safety
/// `a` is live; `nonce` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_set_nonce(a: *mut TsReq, nonce: *const Asn1String) -> c_int {
    // SAFETY: `a` is live.
    if core::ptr::eq(unsafe { (*a).nonce }, nonce) {
        return 1;
    }
    // SAFETY: `nonce` is live.
    let new_nonce = unsafe { ASN1_INTEGER_dup(nonce) };
    if new_nonce.is_null() {
        // SAFETY: a compile-time coordinate.
        unsafe { raise_ts(FILE, 108, c"TS_REQ_set_nonce", ERR_R_ASN1_LIB) };
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        ASN1_INTEGER_free((*a).nonce);
        (*a).nonce = new_nonce;
    }
    1
}

/// `const ASN1_INTEGER *TS_REQ_get_nonce(const TS_REQ *a)` — `ts_req_utils.c:116-119`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_nonce(a: *const TsReq) -> *const Asn1String {
    // SAFETY: `a` is live.
    unsafe { (*a).nonce }
}

/// `int TS_REQ_set_cert_req(TS_REQ *a, int cert_req)` — `ts_req_utils.c:121-125`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_set_cert_req(a: *mut TsReq, cert_req: c_int) -> c_int {
    // SAFETY: `a` is live.
    unsafe { (*a).cert_req = if cert_req != 0 { 0xFF } else { 0x00 } };
    1
}

/// `int TS_REQ_get_cert_req(const TS_REQ *a)` — `ts_req_utils.c:127-130`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_cert_req(a: *const TsReq) -> c_int {
    // SAFETY: `a` is live.
    (if unsafe { (*a).cert_req } != 0 { 1 } else { 0 }) as c_int
}

/// `STACK_OF(X509_EXTENSION) *TS_REQ_get_exts(TS_REQ *a)` — `ts_req_utils.c:132-135`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_exts(a: *mut TsReq) -> *mut OpenSslStack {
    // SAFETY: `a` is live.
    unsafe { (*a).extensions }
}

/// `void TS_REQ_ext_free(TS_REQ *a)` — `ts_req_utils.c:137-143`.
///
/// # Safety
/// `a` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_ext_free(a: *mut TsReq) {
    if a.is_null() {
        return;
    }
    // SAFETY: `a` is live.
    unsafe {
        OPENSSL_sk_pop_free((*a).extensions, Some(x509_extension_free_void));
        (*a).extensions = core::ptr::null_mut();
    }
}

/// `int TS_REQ_get_ext_count(TS_REQ *a)` — `ts_req_utils.c:145-148`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext_count(a: *mut TsReq) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_count((*a).extensions) }
}

/// `int TS_REQ_get_ext_by_NID(TS_REQ *a, int nid, int lastpos)` — `ts_req_utils.c:150-153`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext_by_NID(
    a: *mut TsReq,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_NID((*a).extensions, nid, lastpos) }
}

/// `int TS_REQ_get_ext_by_OBJ(TS_REQ *a, const ASN1_OBJECT *obj, int lastpos)` —
/// `ts_req_utils.c:155-158`.
///
/// # Safety
/// `a` is live; `obj` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext_by_OBJ(
    a: *mut TsReq,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_OBJ((*a).extensions, obj, lastpos) }
}

/// `int TS_REQ_get_ext_by_critical(TS_REQ *a, int crit, int lastpos)` — `ts_req_utils.c:160-163`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext_by_critical(
    a: *mut TsReq,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext_by_critical((*a).extensions, crit, lastpos) }
}

/// `X509_EXTENSION *TS_REQ_get_ext(TS_REQ *a, int loc)` — `ts_req_utils.c:165-168`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext(a: *mut TsReq, loc: c_int) -> *mut X509Extension {
    // SAFETY: `a` is live.
    unsafe { X509v3_get_ext((*a).extensions, loc) }
}

/// `X509_EXTENSION *TS_REQ_delete_ext(TS_REQ *a, int loc)` — `ts_req_utils.c:170-173`.
///
/// # Safety
/// `a` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_delete_ext(a: *mut TsReq, loc: c_int) -> *mut X509Extension {
    // SAFETY: `a` is live.
    unsafe { X509v3_delete_ext((*a).extensions, loc) }
}

/// `int TS_REQ_add_ext(TS_REQ *a, X509_EXTENSION *ex, int loc)` — `ts_req_utils.c:175-178`.
///
/// # Safety
/// `a` is live; `ex` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_add_ext(
    a: *mut TsReq,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `a` is live.
    (!unsafe { X509v3_add_ext(&mut (*a).extensions, ex, loc) }.is_null()) as c_int
}

/// `void *TS_REQ_get_ext_d2i(TS_REQ *a, int nid, int *crit, int *idx)` — `ts_req_utils.c:180-183`.
///
/// # Safety
/// `a` is live; `crit`/`idx` are NULL or writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn TS_REQ_get_ext_d2i(
    a: *mut TsReq,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `a` is live.
    unsafe { X509V3_get_d2i((*a).extensions, nid, crit, idx) }
}
