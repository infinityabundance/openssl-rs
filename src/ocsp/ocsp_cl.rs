//! `crypto/ocsp/ocsp_cl.rs` — the OCSP response reader. Phase 11.2b's third OCSP-function unit,
//! landed as an **internal** transcription: every name is `pub(crate)` and none carries
//! `#[no_mangle]`, because the `OCSP_*` exports are Phase 12's.
//!
//! `crypto/ocsp/ocsp_cl.c` is 367 lines. The requested names, in source order:
//!
//! * [`OCSP_response_status`] (`:116-119`) — the top-level response status enumerated.
//! * [`OCSP_response_get1_basic`] (`:125-139`) — unpack the `[0] EXPLICIT ResponseBytes` into a
//!   fresh `OCSP_BASICRESP`, refusing a missing body or a non-`id-pkix-ocsp-basic` type.
//! * [`OCSP_resp_count`] (`:158-163`) — the `SingleResponse` count, `-1` for a NULL response.
//! * [`OCSP_resp_get0`] (`:166-171`) — the indexed `OCSP_SINGLERESP`, NULL for a NULL response.
//! * [`OCSP_resp_find`] (`:222-241`) — the index of the first `SingleResponse` whose `certId`
//!   matches, scanning from `last` (negative means the start, non-negative means `last + 1`).
//! * [`OCSP_single_get0_status`] (`:248-277`) — the `CertStatus` selector plus, for a revoked
//!   entry, the revocation time and reason. The time out-pointers are set unconditionally; the
//!   reason only on the revoked arm.
//! * [`OCSP_resp_find_status`] (`:283-300`) — [`OCSP_resp_find`] then
//!   [`OCSP_single_get0_status`]; answers 1 whenever an entry was found.
//! * [`OCSP_check_validity`] (`:310-363`) — the `thisUpdate`/`nextUpdate` freshness window.
//! * [`OCSP_SINGLERESP_get0_id`] (`:365-368`) — the `certId` of a single response.
//!
//! These are the accessors the Phase-11 engine's OCSP arm (`check_cert_ocsp_resp`) reads.
//!
//! ## The raise sites
//!
//! `crypto/ocsp/ocsp_cl.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! eight coordinates are **declared locally** in the `err_sites::ErrSite` shape, as `v3_ocsp.rs`
//! does. The reasons are read from the authority's own `include/openssl/ocsperr.h` (`108`, `104`,
//! `123`, `126`, `127`, `122`, `125`, `124`) against `ERR_LIB_OCSP` = 39
//! (`include/openssl/err.h.in:104`).
//!
//! **Withheld by name**: none of the requested names. The rest of `ocsp_cl.c` (the request builder,
//! `OCSP_resp_get0_signature`/`_tbs_sigalg`/`_respdata`/`_produced_at`/`_certs`/`_id`/`get1_id`,
//! and the `OCSP_request_*` half) is not part of this pull-forward.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long};
use core::ptr;

use crate::asn1::asn_pack::ASN1_item_unpack;
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_ENUMERATED_get;
use crate::asn1::string::ASN1_STRING_cmp;
use crate::asn1::time::ASN1_GENERALIZEDTIME_check;
use crate::ocsp::ocsp_asn::{
    OCSP_BASICRESP_it, OcspBasicResp, OcspCertId, OcspResponse, OcspSingleResp,
};
use crate::ocsp::ocsp_lib::OCSP_id_cmp;
use crate::runtime::bio::sys::time;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{NID_id_pkix_OCSP_basic, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::runtime::time::TimeT;
use crate::x509::x509_vfy::X509_cmp_time;

/// `ERR_LIB_OCSP` — `include/openssl/err.h.in:104`.
const ERR_LIB_OCSP: c_int = 39;
/// `OCSP_R_NO_RESPONSE_DATA` — `include/openssl/ocsperr.h:34`.
const OCSP_R_NO_RESPONSE_DATA: c_int = 108;
/// `OCSP_R_NOT_BASIC_RESPONSE` — `include/openssl/ocsperr.h:32`.
const OCSP_R_NOT_BASIC_RESPONSE: c_int = 104;
/// `OCSP_R_ERROR_IN_THISUPDATE_FIELD` — `include/openssl/ocsperr.h:29`.
const OCSP_R_ERROR_IN_THISUPDATE_FIELD: c_int = 123;
/// `OCSP_R_STATUS_NOT_YET_VALID` — `include/openssl/ocsperr.h:44`.
const OCSP_R_STATUS_NOT_YET_VALID: c_int = 126;
/// `OCSP_R_STATUS_TOO_OLD` — `include/openssl/ocsperr.h:45`.
const OCSP_R_STATUS_TOO_OLD: c_int = 127;
/// `OCSP_R_ERROR_IN_NEXTUPDATE_FIELD` — `include/openssl/ocsperr.h:28`.
const OCSP_R_ERROR_IN_NEXTUPDATE_FIELD: c_int = 122;
/// `OCSP_R_STATUS_EXPIRED` — `include/openssl/ocsperr.h:43`.
const OCSP_R_STATUS_EXPIRED: c_int = 125;
/// `OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE` — `include/openssl/ocsperr.h:31`.
const OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE: c_int = 124;

/// `V_OCSP_CERTSTATUS_REVOKED` — `include/openssl/ocsp.h.in:125`.
const V_OCSP_CERTSTATUS_REVOKED: c_int = 1;

/// One `ocsp_cl.c` raise coordinate, declared locally (see the module doc).
const fn ocsp_cl_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ocsp/ocsp_cl.c",
        line,
        func,
        lib: ERR_LIB_OCSP,
        reason,
        dynamic_reason: false,
    }
}

/// `OCSP_response_get1_basic`'s missing-body arm at `ocsp_cl.c:130`.
const OCSP_CL_130: ErrSite =
    ocsp_cl_site(130, c"OCSP_response_get1_basic", OCSP_R_NO_RESPONSE_DATA);
/// `OCSP_response_get1_basic`'s wrong-type arm at `ocsp_cl.c:134`.
const OCSP_CL_134: ErrSite =
    ocsp_cl_site(134, c"OCSP_response_get1_basic", OCSP_R_NOT_BASIC_RESPONSE);
/// `OCSP_check_validity`'s invalid-`thisUpdate` arm at `ocsp_cl.c:319`.
const OCSP_CL_319: ErrSite = ocsp_cl_site(
    319,
    c"OCSP_check_validity",
    OCSP_R_ERROR_IN_THISUPDATE_FIELD,
);
/// `OCSP_check_validity`'s not-yet-valid arm at `ocsp_cl.c:324`.
const OCSP_CL_324: ErrSite = ocsp_cl_site(324, c"OCSP_check_validity", OCSP_R_STATUS_NOT_YET_VALID);
/// `OCSP_check_validity`'s too-old arm at `ocsp_cl.c:335`.
const OCSP_CL_335: ErrSite = ocsp_cl_site(335, c"OCSP_check_validity", OCSP_R_STATUS_TOO_OLD);
/// `OCSP_check_validity`'s invalid-`nextUpdate` arm at `ocsp_cl.c:346`.
const OCSP_CL_346: ErrSite = ocsp_cl_site(
    346,
    c"OCSP_check_validity",
    OCSP_R_ERROR_IN_NEXTUPDATE_FIELD,
);
/// `OCSP_check_validity`'s expired arm at `ocsp_cl.c:351`.
const OCSP_CL_351: ErrSite = ocsp_cl_site(351, c"OCSP_check_validity", OCSP_R_STATUS_EXPIRED);
/// `OCSP_check_validity`'s ordering arm at `ocsp_cl.c:358`.
const OCSP_CL_358: ErrSite = ocsp_cl_site(
    358,
    c"OCSP_check_validity",
    OCSP_R_NEXTUPDATE_BEFORE_THISUPDATE,
);

// ---------------------------------------------------------------------------------------------
// The functions
// ---------------------------------------------------------------------------------------------

/// `int OCSP_response_status(OCSP_RESPONSE *resp)` — `crypto/ocsp/ocsp_cl.c:116-119`.
///
/// # Safety
/// `resp` must be a live `OCSP_RESPONSE`.
pub(crate) unsafe extern "C" fn OCSP_response_status(resp: *mut OcspResponse) -> c_int {
    // SAFETY: `resp` is live per the contract; the getter reads its status string.
    unsafe { ASN1_ENUMERATED_get((*resp).responseStatus) as c_int }
}

/// `OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp)` — `crypto/ocsp/ocsp_cl.c:125-139`.
///
/// A missing `responseBytes` raises `OCSP_R_NO_RESPONSE_DATA`; a body whose type OID is not
/// `id-pkix-ocsp-basic` raises `OCSP_R_NOT_BASIC_RESPONSE`. Both answer NULL. Otherwise the
/// `response` octet string is unpacked as a fresh `OCSP_BASICRESP` the caller owns.
///
/// # Safety
/// `resp` must be a live `OCSP_RESPONSE`.
pub(crate) unsafe extern "C" fn OCSP_response_get1_basic(
    resp: *mut OcspResponse,
) -> *mut OcspBasicResp {
    // SAFETY: `resp` is live per the contract; `ASN1_item_unpack` decodes the caller's string.
    unsafe {
        let rb = (*resp).responseBytes;
        if rb.is_null() {
            raise_site(&OCSP_CL_130);
            return ptr::null_mut();
        }
        if OBJ_obj2nid((*rb).responseType) != NID_id_pkix_OCSP_basic {
            raise_site(&OCSP_CL_134);
            return ptr::null_mut();
        }
        ASN1_item_unpack((*rb).response, OCSP_BASICRESP_it()).cast::<OcspBasicResp>()
    }
}

/// `int OCSP_resp_count(OCSP_BASICRESP *bs)` — `crypto/ocsp/ocsp_cl.c:158-163`.
///
/// # Safety
/// `bs` must be NULL or a live `OCSP_BASICRESP`.
pub(crate) unsafe extern "C" fn OCSP_resp_count(bs: *mut OcspBasicResp) -> c_int {
    // SAFETY: `bs` is NULL-or-live per the contract; the stack accessor accepts both.
    unsafe {
        if bs.is_null() {
            return -1;
        }
        OPENSSL_sk_num((*bs).tbsResponseData.responses)
    }
}

/// `OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx)` —
/// `crypto/ocsp/ocsp_cl.c:166-171`.
///
/// # Safety
/// `bs` must be NULL or a live `OCSP_BASICRESP`.
pub(crate) unsafe extern "C" fn OCSP_resp_get0(
    bs: *mut OcspBasicResp,
    idx: c_int,
) -> *mut OcspSingleResp {
    // SAFETY: `bs` is NULL-or-live per the contract; the stack accessor accepts both.
    unsafe {
        if bs.is_null() {
            return ptr::null_mut();
        }
        OPENSSL_sk_value((*bs).tbsResponseData.responses, idx).cast::<OcspSingleResp>()
    }
}

/// `int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last)` —
/// `crypto/ocsp/ocsp_cl.c:222-241`.
///
/// # Safety
/// `bs` must be NULL or a live `OCSP_BASICRESP`; `id` must be a live `OCSP_CERTID`.
pub(crate) unsafe extern "C" fn OCSP_resp_find(
    bs: *mut OcspBasicResp,
    id: *mut OcspCertId,
    last: c_int,
) -> c_int {
    // SAFETY: `bs` and `id` are live per the contract; the stack accessor bounds-checks.
    unsafe {
        if bs.is_null() {
            return -1;
        }
        let last = if last < 0 { 0 } else { last + 1 };
        let sresp = (*bs).tbsResponseData.responses;
        let mut i = last;
        while i < OPENSSL_sk_num(sresp) {
            let single = OPENSSL_sk_value(sresp, i).cast::<OcspSingleResp>();
            if OCSP_id_cmp(id, (*single).certId) == 0 {
                return i;
            }
            i += 1;
        }
        -1
    }
}

/// `int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,
/// ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME
/// **nextupd)` — `crypto/ocsp/ocsp_cl.c:248-277`.
///
/// # Safety
/// `single` must be NULL or a live `OCSP_SINGLERESP`; each non-NULL out-pointer must be writable.
pub(crate) unsafe extern "C" fn OCSP_single_get0_status(
    single: *mut OcspSingleResp,
    reason: *mut c_int,
    revtime: *mut *mut Asn1String,
    thisupd: *mut *mut Asn1String,
    nextupd: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `single` is NULL-or-live and the out-pointers are NULL-or-writable per the contract.
    unsafe {
        if single.is_null() {
            return -1;
        }
        let cst = (*single).certStatus;
        let ret = (*cst).type_;
        if ret == V_OCSP_CERTSTATUS_REVOKED {
            let rev = (*cst).value.revoked;
            if !revtime.is_null() {
                *revtime = (*rev).revocationTime;
            }
            if !reason.is_null() {
                if !(*rev).revocationReason.is_null() {
                    *reason = ASN1_ENUMERATED_get((*rev).revocationReason) as c_int;
                } else {
                    *reason = -1;
                }
            }
        }
        if !thisupd.is_null() {
            *thisupd = (*single).thisUpdate;
        }
        if !nextupd.is_null() {
            *nextupd = (*single).nextUpdate;
        }
        ret
    }
}

/// `int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status, int *reason,
/// ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME
/// **nextupd)` — `crypto/ocsp/ocsp_cl.c:283-300`.
///
/// # Safety
/// `bs` and `id` must be live; each non-NULL out-pointer must be writable.
pub(crate) unsafe extern "C" fn OCSP_resp_find_status(
    bs: *mut OcspBasicResp,
    id: *mut OcspCertId,
    status: *mut c_int,
    reason: *mut c_int,
    revtime: *mut *mut Asn1String,
    thisupd: *mut *mut Asn1String,
    nextupd: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: the pointers are live per the contract; the callees obey their own contracts.
    unsafe {
        let i = OCSP_resp_find(bs, id, -1);
        if i < 0 {
            return 0;
        }
        let single = OCSP_resp_get0(bs, i);
        let i = OCSP_single_get0_status(single, reason, revtime, thisupd, nextupd);
        if !status.is_null() {
            *status = i;
        }
        1
    }
}

/// `int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long
/// nsec, long maxsec)` — `crypto/ocsp/ocsp_cl.c:310-363`.
///
/// Checks that `thisUpdate` parses and is no more than `nsec` in the future; when `maxsec >= 0`
/// that it is no more than `maxsec` in the past; when `nextUpdate` is present that it parses, is no
/// more than `nsec` in the past, and does not precede `thisUpdate`. Every failure raises its own
/// reason but the checks continue, so the answer is 0 if any failed rather than the first.
///
/// # Safety
/// `thisupd` must be a live `ASN1_GENERALIZEDTIME`; `nextupd` must be NULL or live.
pub(crate) unsafe extern "C" fn OCSP_check_validity(
    thisupd: *mut Asn1String,
    nextupd: *mut Asn1String,
    nsec: c_long,
    maxsec: c_long,
) -> c_int {
    // SAFETY: `thisupd` is live and `nextupd` is NULL-or-live per the contract; the time helpers
    // read their operands and the two locals are this frame's.
    unsafe {
        let mut ret = 1;
        let mut t_now: TimeT = 0;
        time(&mut t_now);

        // Check thisUpdate is valid and not more than nsec in the future.
        if ASN1_GENERALIZEDTIME_check(thisupd) == 0 {
            raise_site(&OCSP_CL_319);
            ret = 0;
        } else {
            let mut t_tmp = t_now + nsec;
            if X509_cmp_time(thisupd, &mut t_tmp) > 0 {
                raise_site(&OCSP_CL_324);
                ret = 0;
            }

            // If maxsec specified check thisUpdate is not more than maxsec in the past.
            if maxsec >= 0 {
                t_tmp = t_now - maxsec;
                if X509_cmp_time(thisupd, &mut t_tmp) < 0 {
                    raise_site(&OCSP_CL_335);
                    ret = 0;
                }
            }
        }

        if nextupd.is_null() {
            return ret;
        }

        // Check nextUpdate is valid and not more than nsec in the past.
        if ASN1_GENERALIZEDTIME_check(nextupd) == 0 {
            raise_site(&OCSP_CL_346);
            ret = 0;
        } else {
            let mut t_tmp = t_now - nsec;
            if X509_cmp_time(nextupd, &mut t_tmp) < 0 {
                raise_site(&OCSP_CL_351);
                ret = 0;
            }
        }

        // Also don't allow nextUpdate to precede thisUpdate.
        if ASN1_STRING_cmp(nextupd, thisupd) < 0 {
            raise_site(&OCSP_CL_358);
            ret = 0;
        }

        ret
    }
}

/// `const OCSP_CERTID *OCSP_SINGLERESP_get0_id(const OCSP_SINGLERESP *x)` —
/// `crypto/ocsp/ocsp_cl.c:365-368`.
///
/// # Safety
/// `single` must be a live `OCSP_SINGLERESP`.
pub(crate) unsafe extern "C" fn OCSP_SINGLERESP_get0_id(
    single: *const OcspSingleResp,
) -> *const OcspCertId {
    // SAFETY: `single` is live per the contract; the returned pointer is its own member.
    unsafe { (*single).certId }
}
