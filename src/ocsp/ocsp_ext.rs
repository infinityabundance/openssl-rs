//! `crypto/ocsp/ocsp_ext.c` — the OCSP extension wrapper families, the nonce handling and the
//! four extension constructors. Phase 12.6's largest unit, landed whole.
//!
//! `crypto/ocsp/ocsp_ext.c` is 466 lines and exports 44 names, in source order:
//!
//! * the nine `OCSP_REQUEST_*` wrappers (`:23-69`) over `tbsRequest.requestExtensions`.
//! * the nine `OCSP_ONEREQ_*` wrappers (`:73-119`) over `singleRequestExtensions`.
//! * the nine `OCSP_BASICRESP_*` wrappers (`:123-173`) over `tbsResponseData.responseExtensions`.
//! * the nine `OCSP_SINGLERESP_*` wrappers (`:177-224`) over `singleExtensions`.
//! * `static ocsp_add1_nonce` (`:236-271`) and its two callers `OCSP_request_add1_nonce` (`:275-278`)
//!   and `OCSP_basic_add1_nonce` (`:282-286`): the nonce is hand-built as a raw `OCTET STRING`
//!   (header plus content) rather than through an item.
//! * `OCSP_check_nonce` (`:302-334`) and `OCSP_copy_nonce` (`:340-351`): the presence/equality
//!   decision and the request-to-response copy.
//! * the four constructors `OCSP_crlID_new` (`:353-382`), `OCSP_accept_responses_new` (`:385-404`),
//!   `OCSP_archive_cutoff_new` (`:407-420`) and `OCSP_url_svcloc_new` (`:427-465`), each ending in
//!   `X509V3_EXT_i2d`.
//!
//! `crypto/ocsp/ocsp_ext.c` has **no** `ERR_raise` and no declared raise coordinate.
//!
//! **Withheld by name**: none.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::der::{ASN1_object_size, ASN1_put_object};
use crate::asn1::layout::{Asn1String, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL};
use crate::asn1::prim::{ASN1_INTEGER_set, ASN1_OBJECT_free};
use crate::asn1::string::{
    ASN1_GENERALIZEDTIME_free, ASN1_GENERALIZEDTIME_new, ASN1_IA5STRING_free, ASN1_IA5STRING_new,
    ASN1_INTEGER_new, ASN1_OCTET_STRING_cmp, ASN1_STRING_set,
};
use crate::asn1::time::ASN1_GENERALIZEDTIME_set_string;
use crate::ocsp::ocsp_asn::{
    OCSP_CRLID_free, OCSP_CRLID_new, OCSP_SERVICELOC_free, OCSP_SERVICELOC_new, OcspBasicResp,
    OcspOneReq, OcspRequest, OcspSingleResp,
};
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::obj::{
    Asn1Object, NID_ad_OCSP, NID_id_pkix_OCSP_CrlID, NID_id_pkix_OCSP_Nonce,
    NID_id_pkix_OCSP_acceptableResponses, NID_id_pkix_OCSP_archiveCutoff,
    NID_id_pkix_OCSP_serviceLocator, NID_undef, OBJ_nid2obj, OBJ_txt2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_pop_free, OPENSSL_sk_push, OpenSslStack,
};
use crate::x509::v3_conf::X509V3_EXT_i2d;
use crate::x509::v3_genn::GEN_URI;
use crate::x509::v3_info::{ACCESS_DESCRIPTION_free, ACCESS_DESCRIPTION_new, AccessDescription};
use crate::x509::v3_lib::{X509V3_add1_i2d, X509V3_get_d2i};
use crate::x509::x509_v3::{
    X509_EXTENSION_get_data, X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext,
    X509v3_get_ext_by_NID, X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509::x_exten::X509Extension;
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};

/// `OCSP_DEFAULT_NONCE_LENGTH` — `include/openssl/ocsp.h.in:75`.
const OCSP_DEFAULT_NONCE_LENGTH: c_int = 16;
/// `X509V3_ADD_REPLACE` — `include/openssl/x509v3.h.in:533`.
const X509V3_ADD_REPLACE: c_ulong = 2;

/// The `void (*)(void *)` thunk `sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free)` installs.
///
/// # Safety
/// `p` must be NULL or a live `ASN1_OBJECT` (the stack contract).
unsafe extern "C" fn asn1_object_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_OBJECT` pointers per the contract.
    unsafe { ASN1_OBJECT_free(p.cast::<Asn1Object>()) };
}

// ---------------------------------------------------------------------------------------------
// OCSP_REQUEST_* — `ocsp_ext.c:23-69`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x)` — `crypto/ocsp/ocsp_ext.c:23-26`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext_count(x: *mut OcspRequest) -> c_int {
    // SAFETY: `x` is live per the contract; the extension accessor accepts NULL or live.
    unsafe { X509v3_get_ext_count((*x).tbsRequest.requestExtensions) }
}

/// `int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:28-31`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_NID(
    x: *mut OcspRequest,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).tbsRequest.requestExtensions, nid, lastpos) }
}

/// `int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:33-37`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`; `obj` must be a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_OBJ(
    x: *mut OcspRequest,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` and `obj` are live per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).tbsRequest.requestExtensions, obj, lastpos) }
}

/// `int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:39-42`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext_by_critical(
    x: *mut OcspRequest,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).tbsRequest.requestExtensions, crit, lastpos) }
}

/// `X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:44-47`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get_ext(
    x: *mut OcspRequest,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).tbsRequest.requestExtensions, loc) }
}

/// `X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:49-52`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_delete_ext(
    x: *mut OcspRequest,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_delete_ext((*x).tbsRequest.requestExtensions, loc) }
}

/// `void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx)` —
/// `crypto/ocsp/ocsp_ext.c:54-57`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`; `crit` and `idx` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_get1_ext_d2i(
    x: *mut OcspRequest,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `x` is live and the out-pointers are NULL-or-writable per the contract.
    unsafe { X509V3_get_d2i((*x).tbsRequest.requestExtensions, nid, crit, idx) }
}

/// `int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit, unsigned long
/// flags)` — `crypto/ocsp/ocsp_ext.c:59-64`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`; `value` must be the internal structure the `nid` method
/// encodes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_add1_ext_i2d(
    x: *mut OcspRequest,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `x` is live and `value` is the caller's structure per the contract.
    unsafe {
        X509V3_add1_i2d(
            ptr::addr_of_mut!((*x).tbsRequest.requestExtensions),
            nid,
            value,
            crit,
            flags,
        )
    }
}

/// `int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:66-69`.
///
/// # Safety
/// `x` must be a live `OCSP_REQUEST`; `ex` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_add_ext(
    x: *mut OcspRequest,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` and `ex` are live per the contract.
    unsafe {
        c_int::from(
            !X509v3_add_ext(
                ptr::addr_of_mut!((*x).tbsRequest.requestExtensions),
                ex,
                loc,
            )
            .is_null(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// OCSP_ONEREQ_* — `ocsp_ext.c:73-119`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x)` — `crypto/ocsp/ocsp_ext.c:73-76`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_count(x: *mut OcspOneReq) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_count((*x).singleRequestExtensions) }
}

/// `int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:78-81`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_NID(
    x: *mut OcspOneReq,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).singleRequestExtensions, nid, lastpos) }
}

/// `int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:83-87`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`; `obj` must be a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_OBJ(
    x: *mut OcspOneReq,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` and `obj` are live per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).singleRequestExtensions, obj, lastpos) }
}

/// `int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:89-92`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get_ext_by_critical(
    x: *mut OcspOneReq,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).singleRequestExtensions, crit, lastpos) }
}

/// `X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:94-97`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get_ext(x: *mut OcspOneReq, loc: c_int) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).singleRequestExtensions, loc) }
}

/// `X509_EXTENSION *OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:99-102`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_delete_ext(
    x: *mut OcspOneReq,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_delete_ext((*x).singleRequestExtensions, loc) }
}

/// `void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx)` —
/// `crypto/ocsp/ocsp_ext.c:104-107`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`; `crit` and `idx` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_get1_ext_d2i(
    x: *mut OcspOneReq,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `x` is live and the out-pointers are NULL-or-writable per the contract.
    unsafe { X509V3_get_d2i((*x).singleRequestExtensions, nid, crit, idx) }
}

/// `int OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit, unsigned long
/// flags)` — `crypto/ocsp/ocsp_ext.c:109-114`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`; `value` must be the internal structure the `nid` method
/// encodes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_add1_ext_i2d(
    x: *mut OcspOneReq,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `x` is live and `value` is the caller's structure per the contract.
    unsafe {
        X509V3_add1_i2d(
            ptr::addr_of_mut!((*x).singleRequestExtensions),
            nid,
            value,
            crit,
            flags,
        )
    }
}

/// `int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:116-119`.
///
/// # Safety
/// `x` must be a live `OCSP_ONEREQ`; `ex` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_add_ext(
    x: *mut OcspOneReq,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` and `ex` are live per the contract.
    unsafe {
        c_int::from(
            !X509v3_add_ext(ptr::addr_of_mut!((*x).singleRequestExtensions), ex, loc).is_null(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// OCSP_BASICRESP_* — `ocsp_ext.c:123-173`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x)` — `crypto/ocsp/ocsp_ext.c:123-126`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_count(x: *mut OcspBasicResp) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_count((*x).tbsResponseData.responseExtensions) }
}

/// `int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:128-131`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_NID(
    x: *mut OcspBasicResp,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).tbsResponseData.responseExtensions, nid, lastpos) }
}

/// `int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:133-137`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`; `obj` must be a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_OBJ(
    x: *mut OcspBasicResp,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` and `obj` are live per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).tbsResponseData.responseExtensions, obj, lastpos) }
}

/// `int OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:139-143`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext_by_critical(
    x: *mut OcspBasicResp,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).tbsResponseData.responseExtensions, crit, lastpos) }
}

/// `X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:145-148`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get_ext(
    x: *mut OcspBasicResp,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).tbsResponseData.responseExtensions, loc) }
}

/// `X509_EXTENSION *OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:150-153`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_delete_ext(
    x: *mut OcspBasicResp,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_delete_ext((*x).tbsResponseData.responseExtensions, loc) }
}

/// `void *OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit, int *idx)` —
/// `crypto/ocsp/ocsp_ext.c:155-160`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`; `crit` and `idx` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_get1_ext_d2i(
    x: *mut OcspBasicResp,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `x` is live and the out-pointers are NULL-or-writable per the contract.
    unsafe { X509V3_get_d2i((*x).tbsResponseData.responseExtensions, nid, crit, idx) }
}

/// `int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value, int crit, unsigned long
/// flags)` — `crypto/ocsp/ocsp_ext.c:162-167`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`; `value` must be the internal structure the `nid` method
/// encodes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_add1_ext_i2d(
    x: *mut OcspBasicResp,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `x` is live and `value` is the caller's structure per the contract.
    unsafe {
        X509V3_add1_i2d(
            ptr::addr_of_mut!((*x).tbsResponseData.responseExtensions),
            nid,
            value,
            crit,
            flags,
        )
    }
}

/// `int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:169-173`.
///
/// # Safety
/// `x` must be a live `OCSP_BASICRESP`; `ex` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_add_ext(
    x: *mut OcspBasicResp,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` and `ex` are live per the contract.
    unsafe {
        c_int::from(
            !X509v3_add_ext(
                ptr::addr_of_mut!((*x).tbsResponseData.responseExtensions),
                ex,
                loc,
            )
            .is_null(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// OCSP_SINGLERESP_* — `ocsp_ext.c:177-224`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x)` — `crypto/ocsp/ocsp_ext.c:177-180`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_count(x: *mut OcspSingleResp) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_count((*x).singleExtensions) }
}

/// `int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:182-185`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_NID(
    x: *mut OcspSingleResp,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).singleExtensions, nid, lastpos) }
}

/// `int OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:187-191`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`; `obj` must be a live `ASN1_OBJECT`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_OBJ(
    x: *mut OcspSingleResp,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` and `obj` are live per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).singleExtensions, obj, lastpos) }
}

/// `int OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit, int lastpos)` —
/// `crypto/ocsp/ocsp_ext.c:193-197`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext_by_critical(
    x: *mut OcspSingleResp,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).singleExtensions, crit, lastpos) }
}

/// `X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:199-202`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get_ext(
    x: *mut OcspSingleResp,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).singleExtensions, loc) }
}

/// `X509_EXTENSION *OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:204-207`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_delete_ext(
    x: *mut OcspSingleResp,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_delete_ext((*x).singleExtensions, loc) }
}

/// `void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit, int *idx)` —
/// `crypto/ocsp/ocsp_ext.c:209-213`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`; `crit` and `idx` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_get1_ext_d2i(
    x: *mut OcspSingleResp,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `x` is live and the out-pointers are NULL-or-writable per the contract.
    unsafe { X509V3_get_d2i((*x).singleExtensions, nid, crit, idx) }
}

/// `int OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value, int crit, unsigned
/// long flags)` — `crypto/ocsp/ocsp_ext.c:215-219`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`; `value` must be the internal structure the `nid` method
/// encodes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_add1_ext_i2d(
    x: *mut OcspSingleResp,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `x` is live and `value` is the caller's structure per the contract.
    unsafe {
        X509V3_add1_i2d(
            ptr::addr_of_mut!((*x).singleExtensions),
            nid,
            value,
            crit,
            flags,
        )
    }
}

/// `int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/ocsp/ocsp_ext.c:221-224`.
///
/// # Safety
/// `x` must be a live `OCSP_SINGLERESP`; `ex` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_add_ext(
    x: *mut OcspSingleResp,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` and `ex` are live per the contract.
    unsafe {
        c_int::from(!X509v3_add_ext(ptr::addr_of_mut!((*x).singleExtensions), ex, loc).is_null())
    }
}

// ---------------------------------------------------------------------------------------------
// Nonce handling — `ocsp_ext.c:236-351`
// ---------------------------------------------------------------------------------------------

/// `static int ocsp_add1_nonce(STACK_OF(X509_EXTENSION) **exts, unsigned char *val, int len)` —
/// `crypto/ocsp/ocsp_ext.c:236-271`.
///
/// A non-positive `len` means [`OCSP_DEFAULT_NONCE_LENGTH`]. The nonce is built by hand: an
/// `ASN1_OCTET_STRING` value whose `length`/`data` hold a complete DER `OCTET STRING` (header
/// written by `ASN1_put_object`, content copied from `val` or filled by `RAND_bytes`). It is then
/// installed with `X509V3_add1_i2d` under `X509V3_ADD_REPLACE`. Answers 1 on success, 0 otherwise.
unsafe fn ocsp_add1_nonce(exts: *mut *mut OpenSslStack, val: *mut c_uchar, len: c_int) -> c_int {
    // SAFETY: `exts` is a writable slot per the contract; `val` is NULL or readable for `len`
    // bytes. The scratch `os` value is this frame's own.
    unsafe {
        let len = if len <= 0 {
            OCSP_DEFAULT_NONCE_LENGTH
        } else {
            len
        };
        let os_length = ASN1_object_size(0, len, V_ASN1_OCTET_STRING);
        if os_length < 0 {
            return 0;
        }

        let mut buf = vec![0u8; os_length as usize];
        let mut os = Asn1String {
            length: os_length,
            type_: V_ASN1_OCTET_STRING,
            data: buf.as_mut_ptr(),
            flags: 0,
        };
        let mut tmpval = os.data;
        ASN1_put_object(&mut tmpval, 0, len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
        if !val.is_null() {
            ptr::copy_nonoverlapping(val, tmpval, len as usize);
        } else if RAND_bytes(tmpval, len) <= 0 {
            return 0;
        }
        if X509V3_add1_i2d(
            exts,
            NID_id_pkix_OCSP_Nonce,
            ptr::addr_of_mut!(os).cast::<c_void>(),
            0,
            X509V3_ADD_REPLACE,
        ) <= 0
        {
            return 0;
        }
        // The buffer backs `os.data` and outlives the call above; drop it explicitly for symmetry
        // with the authority's `OPENSSL_free(os.data)`.
        drop(buf);
        1
    }
}

/// `int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len)` —
/// `crypto/ocsp/ocsp_ext.c:275-278`.
///
/// # Safety
/// `req` must be a live `OCSP_REQUEST`; `val` must be NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_add1_nonce(
    req: *mut OcspRequest,
    val: *mut c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `req` is live per the contract.
    unsafe {
        ocsp_add1_nonce(
            ptr::addr_of_mut!((*req).tbsRequest.requestExtensions),
            val,
            len,
        )
    }
}

/// `int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len)` —
/// `crypto/ocsp/ocsp_ext.c:282-286`.
///
/// # Safety
/// `resp` must be a live `OCSP_BASICRESP`; `val` must be NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_add1_nonce(
    resp: *mut OcspBasicResp,
    val: *mut c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `resp` is live per the contract.
    unsafe {
        ocsp_add1_nonce(
            ptr::addr_of_mut!((*resp).tbsResponseData.responseExtensions),
            val,
            len,
        )
    }
}

/// `int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs)` — `crypto/ocsp/ocsp_ext.c:302-334`.
///
/// Answers 1 when both nonces are present and equal, 2 when both are absent, 3 when only the
/// response carries one, 0 when both are present and differ, and -1 when only the request does.
///
/// # Safety
/// `req` must be a live `OCSP_REQUEST`; `bs` must be a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_check_nonce(req: *mut OcspRequest, bs: *mut OcspBasicResp) -> c_int {
    // SAFETY: `req` and `bs` are live per the contract; the wrapper accessors obey their own.
    unsafe {
        let req_idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
        let resp_idx = OCSP_BASICRESP_get_ext_by_NID(bs, NID_id_pkix_OCSP_Nonce, -1);
        // Check both absent.
        if req_idx < 0 && resp_idx < 0 {
            return 2;
        }
        // Check in request only.
        if req_idx >= 0 && resp_idx < 0 {
            return -1;
        }
        // Check in response but not request.
        if req_idx < 0 && resp_idx >= 0 {
            return 3;
        }
        let req_ext = OCSP_REQUEST_get_ext(req, req_idx);
        let resp_ext = OCSP_BASICRESP_get_ext(bs, resp_idx);
        if ASN1_OCTET_STRING_cmp(
            X509_EXTENSION_get_data(req_ext),
            X509_EXTENSION_get_data(resp_ext),
        ) != 0
        {
            return 0;
        }
        1
    }
}

/// `int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req)` — `crypto/ocsp/ocsp_ext.c:340-351`.
///
/// Copies the request's nonce extension (if any) into the response. Answers 2 when the request has
/// no nonce, else the result of the append.
///
/// # Safety
/// `resp` must be a live `OCSP_BASICRESP`; `req` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_copy_nonce(resp: *mut OcspBasicResp, req: *mut OcspRequest) -> c_int {
    // SAFETY: `resp` and `req` are live per the contract.
    unsafe {
        let req_idx = OCSP_REQUEST_get_ext_by_NID(req, NID_id_pkix_OCSP_Nonce, -1);
        if req_idx < 0 {
            return 2;
        }
        let req_ext = OCSP_REQUEST_get_ext(req, req_idx);
        OCSP_BASICRESP_add_ext(resp, req_ext, -1)
    }
}

// ---------------------------------------------------------------------------------------------
// The four constructors — `ocsp_ext.c:353-465`
// ---------------------------------------------------------------------------------------------

/// `X509_EXTENSION *OCSP_crlID_new(const char *url, long *n, char *tim)` —
/// `crypto/ocsp/ocsp_ext.c:353-382`.
///
/// Builds an `OCSP_CRLID` carrying whichever of the URL, CRL number and time were supplied, and
/// encodes it under `id-pkix-ocsp-crl`. Answers NULL on any allocation or set failure.
///
/// # Safety
/// `url` and `tim` must be NULL or NUL-terminated; `n` must be NULL or readable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_crlID_new(
    url: *const c_char,
    n: *mut c_long,
    tim: *mut c_char,
) -> *mut X509Extension {
    // SAFETY: the pointers are NULL-or-live per the contract; every value built is freed on error.
    unsafe {
        let cid = OCSP_CRLID_new();
        if cid.is_null() {
            return ptr::null_mut();
        }
        if !url.is_null() {
            (*cid).crlUrl = ASN1_IA5STRING_new();
            if (*cid).crlUrl.is_null() {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
            if ASN1_STRING_set((*cid).crlUrl, url.cast::<c_void>(), -1) == 0 {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
        }
        if !n.is_null() {
            (*cid).crlNum = ASN1_INTEGER_new();
            if (*cid).crlNum.is_null() {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
            if ASN1_INTEGER_set((*cid).crlNum, *n) == 0 {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
        }
        if !tim.is_null() {
            (*cid).crlTime = ASN1_GENERALIZEDTIME_new();
            if (*cid).crlTime.is_null() {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
            if ASN1_GENERALIZEDTIME_set_string((*cid).crlTime, tim) == 0 {
                OCSP_CRLID_free(cid);
                return ptr::null_mut();
            }
        }
        let x = X509V3_EXT_i2d(NID_id_pkix_OCSP_CrlID, 0, cid.cast::<c_void>());
        OCSP_CRLID_free(cid);
        x
    }
}

/// `X509_EXTENSION *OCSP_accept_responses_new(char **oids)` — `crypto/ocsp/ocsp_ext.c:385-404`.
///
/// Builds a `SEQUENCE OF OBJECT IDENTIFIER` from the NUL-terminated `oids` array (each named by its
/// textual OID) and encodes it under `id-pkix-ocsp-acceptable-responses`. Unknown names are skipped.
///
/// # Safety
/// `oids` must be NULL or a NUL-terminated array of NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn OCSP_accept_responses_new(oids: *mut *mut c_char) -> *mut X509Extension {
    // SAFETY: `oids` is NULL or a NUL-terminated array per the contract; `sk` is this call's own.
    unsafe {
        let sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            return ptr::null_mut();
        }
        let mut p = oids;
        while !p.is_null() && !(*p).is_null() {
            let nid = OBJ_txt2nid(*p);
            if nid != NID_undef {
                let o = OBJ_nid2obj(nid);
                if !o.is_null() && OPENSSL_sk_push(sk, o.cast()) == 0 {
                    OPENSSL_sk_pop_free(sk, Some(asn1_object_free_thunk));
                    return ptr::null_mut();
                }
            }
            p = p.add(1);
        }
        let x = X509V3_EXT_i2d(NID_id_pkix_OCSP_acceptableResponses, 0, sk.cast::<c_void>());
        OPENSSL_sk_pop_free(sk, Some(asn1_object_free_thunk));
        x
    }
}

/// `X509_EXTENSION *OCSP_archive_cutoff_new(char *tim)` — `crypto/ocsp/ocsp_ext.c:407-420`.
///
/// Builds an `ASN1_GENERALIZEDTIME` from `tim` and encodes it under `id-pkix-ocsp-archive-cutoff`.
///
/// # Safety
/// `tim` must be a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn OCSP_archive_cutoff_new(tim: *mut c_char) -> *mut X509Extension {
    // SAFETY: `tim` is NUL-terminated per the contract; every value built is freed on error.
    unsafe {
        let gt = ASN1_GENERALIZEDTIME_new();
        if gt.is_null() {
            return ptr::null_mut();
        }
        if ASN1_GENERALIZEDTIME_set_string(gt, tim) == 0 {
            ASN1_GENERALIZEDTIME_free(gt);
            return ptr::null_mut();
        }
        let x = X509V3_EXT_i2d(NID_id_pkix_OCSP_archiveCutoff, 0, gt.cast::<c_void>());
        ASN1_GENERALIZEDTIME_free(gt);
        x
    }
}

/// `X509_EXTENSION *OCSP_url_svcloc_new(const X509_NAME *issuer, const char **urls)` —
/// `crypto/ocsp/ocsp_ext.c:427-465`.
///
/// Builds an `OCSP_SERVICELOC` whose issuer is a copy of `issuer` and whose locator holds one
/// `id-ad-ocsp` `uniformResourceLocator` `ACCESS_DESCRIPTION` per NUL-terminated URL, then encodes
/// it under `id-pkix-ocsp-service-locator`. Only `NID_ad_OCSP`/`GEN_URI` are produced.
///
/// # Safety
/// `issuer` must be a live `X509_NAME`; `urls` must be NULL or a NUL-terminated array of
/// NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn OCSP_url_svcloc_new(
    issuer: *const X509Name,
    urls: *mut *const c_char,
) -> *mut X509Extension {
    // SAFETY: the pointers are NULL-or-live per the contract; every value built is freed on error.
    unsafe {
        let sloc = OCSP_SERVICELOC_new();
        if sloc.is_null() {
            return ptr::null_mut();
        }
        X509_NAME_free((*sloc).issuer);
        (*sloc).issuer = X509_NAME_dup(issuer);
        if (*sloc).issuer.is_null() {
            OCSP_SERVICELOC_free(sloc);
            return ptr::null_mut();
        }
        if !urls.is_null() && !(*urls).is_null() {
            (*sloc).locator = OPENSSL_sk_new_null();
            if (*sloc).locator.is_null() {
                OCSP_SERVICELOC_free(sloc);
                return ptr::null_mut();
            }
        }
        let mut ia5: *mut Asn1String = ptr::null_mut();
        let mut ad: *mut AccessDescription = ptr::null_mut();
        let mut p = urls;
        while !p.is_null() && !(*p).is_null() {
            ad = ACCESS_DESCRIPTION_new();
            if ad.is_null() {
                break;
            }
            (*ad).method = OBJ_nid2obj(NID_ad_OCSP);
            if (*ad).method.is_null() {
                break;
            }
            ia5 = ASN1_IA5STRING_new();
            if ia5.is_null() {
                break;
            }
            if ASN1_STRING_set(ia5, (*p).cast::<c_void>(), -1) == 0 {
                break;
            }
            // `ad->location` is allocated inside `ACCESS_DESCRIPTION_new`.
            (*(*ad).location).type_ = GEN_URI;
            (*(*ad).location).d.ia5 = ia5;
            ia5 = ptr::null_mut();
            if OPENSSL_sk_push((*sloc).locator, ad.cast()) == 0 {
                break;
            }
            ad = ptr::null_mut();
            p = p.add(1);
        }
        let ok = p.is_null() || (*p).is_null();
        let x = if ok {
            X509V3_EXT_i2d(NID_id_pkix_OCSP_serviceLocator, 0, sloc.cast::<c_void>())
        } else {
            ptr::null_mut()
        };
        ASN1_IA5STRING_free(ia5);
        ACCESS_DESCRIPTION_free(ad);
        OCSP_SERVICELOC_free(sloc);
        x
    }
}
