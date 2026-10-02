//! `crypto/ocsp/ocsp_srv.rs` — the OCSP responder's builder surface. Phase 11.2b landed
//! `OCSP_id_get0_info` as an **internal** transcription for the engine's OCSP arm; Phase 12.6 (this
//! subphase) promotes it and lands the other fourteen `ocsp_srv.c` exports, reusing the Phase-11
//! body verbatim.
//!
//! `crypto/ocsp/ocsp_srv.c` is 326 lines. The fifteen exports, in source order:
//!
//! * [`OCSP_request_onereq_count`] (`:23-26`), [`OCSP_request_onereq_get0`] (`:28-31`),
//!   [`OCSP_onereq_get0_id`] (`:33-36`) — the request's `Request` list and one `CertID`.
//! * [`OCSP_id_get0_info`] (`:38-53`) — hand back the four `OCSP_CERTID` members.
//! * [`OCSP_request_is_signed`] (`:55-60`), [`OCSP_response_create`] (`:62-82`) — the optional
//!   signature's presence and a fresh top-level response.
//! * [`OCSP_basic_add1_status`] (`:84-152`) — append a `SingleResponse` for a `CertID` and status.
//! * `OCSP_basic_add1_cert` (`:154-158`), `OCSP_basic_sign_ctx` (`:165-210`), `OCSP_basic_sign`
//!   (`:212-231`) — the response signer.
//! * `OCSP_RESPID_set_by_name`/`_by_key`/`_by_key_ex` (`:233-281`) and
//!   `OCSP_RESPID_match`/`_match_ex` (`:283-326`) — the responder id's two setters and matchers.
//!
//! ## The raise sites
//!
//! `crypto/ocsp/ocsp_srv.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! three coordinates are **declared locally** in the `err_sites::ErrSite` shape, as `v3_ocsp.rs`
//! does. The reasons are read from the authority's own `include/openssl/ocsperr.h` (`109`, `130`,
//! `110`) against `ERR_LIB_OCSP` = 39 (`include/openssl/err.h.in:104`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_sign::ASN1_item_sign_ctx;
use crate::asn1::asn_pack::ASN1_item_pack;
use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_ENUMERATED_set;
use crate::asn1::string::{
    ASN1_ENUMERATED_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set,
    ASN1_STRING_get0_data, ASN1_STRING_length,
};
use crate::asn1::time::ASN1_TIME_to_generalizedtime;
use crate::asn1::typ::ASN1_NULL_new;
use crate::evp::digest::{
    EVP_DigestSignInit_ex, EVP_MD_CTX_free, EVP_MD_CTX_get_pkey_ctx, EVP_MD_CTX_new, EVP_MD_fetch,
    EVP_MD_free, EVP_MD_get0_name, EvpMd, EvpMdCtx,
};
use crate::evp::pkey::EvpPkey;
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_get0_pkey, EvpPkeyCtx};
use crate::ocsp::ocsp_asn::{
    OCSP_BASICRESP_it, OCSP_CERTID_free, OCSP_RESPBYTES_new, OCSP_RESPDATA_it, OCSP_RESPONSE_free,
    OCSP_RESPONSE_new, OCSP_REVOKEDINFO_new, OCSP_SINGLERESP_free, OCSP_SINGLERESP_new,
    OcspBasicResp, OcspCertId, OcspOneReq, OcspRequest, OcspRespid, OcspResponse, OcspSingleResp,
};
use crate::ocsp::ocsp_lib::OCSP_CERTID_dup;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{Asn1Object, NID_id_pkix_OCSP_basic, OBJ_nid2obj};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_cmp::{
    ossl_x509_add_cert_new, X509_NAME_cmp, X509_add_certs, X509_check_private_key,
    X509_get_subject_name,
};
use crate::x509::x509_vfy::X509_gmtime_adj;
use crate::x509::x_all::X509_pubkey_digest;
use crate::x509::x_name::X509_NAME_set;
use crate::x509::x_x509::X509;

/// `ERR_LIB_OCSP` — `include/openssl/err.h.in:104`.
const ERR_LIB_OCSP: c_int = 39;
/// `OCSP_R_NO_REVOKED_TIME` — `include/openssl/ocsperr.h:35`.
const OCSP_R_NO_REVOKED_TIME: c_int = 109;
/// `OCSP_R_NO_SIGNER_KEY` — `include/openssl/ocsperr.h:36`.
const OCSP_R_NO_SIGNER_KEY: c_int = 130;
/// `OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE` — `include/openssl/ocsperr.h:37`.
const OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE: c_int = 110;

/// `V_OCSP_CERTSTATUS_GOOD` — `include/openssl/ocsp.h.in:124`.
const V_OCSP_CERTSTATUS_GOOD: c_int = 0;
/// `V_OCSP_CERTSTATUS_REVOKED` — `include/openssl/ocsp.h.in:125`.
const V_OCSP_CERTSTATUS_REVOKED: c_int = 1;
/// `V_OCSP_CERTSTATUS_UNKNOWN` — `include/openssl/ocsp.h.in:126`.
const V_OCSP_CERTSTATUS_UNKNOWN: c_int = 2;
/// `OCSP_REVOKED_STATUS_NOSTATUS` — `include/openssl/ocsp.h.in:50`, `-1`.
const OCSP_REVOKED_STATUS_NOSTATUS: c_int = -1;
/// `V_OCSP_RESPID_NAME` — `include/openssl/ocsp.h.in:113`.
const V_OCSP_RESPID_NAME: c_int = 0;
/// `V_OCSP_RESPID_KEY` — `include/openssl/ocsp.h.in:114`.
const V_OCSP_RESPID_KEY: c_int = 1;

/// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h`, `20`; RFC 2560's responder-key hash width.
const SHA_DIGEST_LENGTH: c_int = 20;
/// `OCSP_NOCERTS` — `include/openssl/ocsp.h.in:77`.
const OCSP_NOCERTS: c_ulong = 0x1;
/// `OCSP_RESPID_KEY` — `include/openssl/ocsp.h.in:87`.
const OCSP_RESPID_KEY: c_ulong = 0x400;
/// `OCSP_NOTIME` — `include/openssl/ocsp.h.in:88`.
const OCSP_NOTIME: c_ulong = 0x800;
/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `SHA1` — the digest name `EVP_MD_fetch` is asked for; RFC 2560 requires it.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();

/// One `ocsp_srv.c` raise coordinate, declared locally (see the module doc).
const fn ocsp_srv_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ocsp/ocsp_srv.c",
        line,
        func,
        lib: ERR_LIB_OCSP,
        reason,
        dynamic_reason: false,
    }
}

/// `OCSP_basic_add1_status`'s missing-revocation-time arm at `ocsp_srv.c:118`.
const OCSP_SRV_118: ErrSite = ocsp_srv_site(118, c"OCSP_basic_add1_status", OCSP_R_NO_REVOKED_TIME);
/// `OCSP_basic_sign_ctx`'s missing-signer-key arm at `ocsp_srv.c:173`.
const OCSP_SRV_173: ErrSite = ocsp_srv_site(173, c"OCSP_basic_sign_ctx", OCSP_R_NO_SIGNER_KEY);
/// `OCSP_basic_sign_ctx`'s mismatched-key arm at `ocsp_srv.c:179`.
const OCSP_SRV_179: ErrSite = ocsp_srv_site(
    179,
    c"OCSP_basic_sign_ctx",
    OCSP_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE,
);

/// `memcmp` — `<string.h>`; answers the difference of the first differing octets, or 0.
///
/// # Safety
/// `a` and `b` must each point to `n` readable bytes.
unsafe fn memcmp(a: *const c_uchar, b: *const c_uchar, n: c_int) -> c_int {
    let mut i = 0;
    while i < n {
        // SAFETY: `0 <= i < n`, so both offsets are within the readable ranges.
        let (x, y) = unsafe { (*a.add(i as usize), *b.add(i as usize)) };
        if x != y {
            return c_int::from(x) - c_int::from(y);
        }
        i += 1;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// The request accessors and the id getter
// ---------------------------------------------------------------------------------------------

/// `int OCSP_request_onereq_count(OCSP_REQUEST *req)` — `crypto/ocsp/ocsp_srv.c:23-26`.
///
/// # Safety
/// `req` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_onereq_count(req: *mut OcspRequest) -> c_int {
    // SAFETY: `req` is live per the contract; the stack accessor accepts NULL or live.
    unsafe { OPENSSL_sk_num((*req).tbsRequest.requestList) }
}

/// `OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i)` —
/// `crypto/ocsp/ocsp_srv.c:28-31`.
///
/// # Safety
/// `req` must be a live `OCSP_REQUEST`; `i` must be an in-range index.
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_onereq_get0(
    req: *mut OcspRequest,
    i: c_int,
) -> *mut OcspOneReq {
    // SAFETY: `req` is live per the contract; the stack accessor bounds-checks `i`.
    unsafe { OPENSSL_sk_value((*req).tbsRequest.requestList, i).cast::<OcspOneReq>() }
}

/// `OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one)` — `crypto/ocsp/ocsp_srv.c:33-36`.
///
/// # Safety
/// `one` must be a live `OCSP_ONEREQ`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_onereq_get0_id(one: *mut OcspOneReq) -> *mut OcspCertId {
    // SAFETY: `one` is live per the contract; the returned pointer is its own member.
    unsafe { (*one).reqCert }
}

/// `int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
/// ASN1_OCTET_STRING **pikeyHash, ASN1_INTEGER **pserial, OCSP_CERTID *cid)` —
/// `crypto/ocsp/ocsp_srv.c:38-53`.
///
/// Writes each non-NULL out-pointer and answers 1; a NULL `cid` writes nothing and answers 0. The
/// string out-pointers receive interior pointers, not copies.
///
/// # Safety
/// `cid` must be NULL or a live `OCSP_CERTID`; each non-NULL `p*` out-pointer must be writable.
#[no_mangle]
pub unsafe extern "C" fn OCSP_id_get0_info(
    piNameHash: *mut *mut Asn1String,
    pmd: *mut *mut Asn1Object,
    pikeyHash: *mut *mut Asn1String,
    pserial: *mut *mut Asn1String,
    cid: *mut OcspCertId,
) -> c_int {
    // SAFETY: `cid` is NULL-or-live and the out-pointers are NULL-or-writable per the contract.
    unsafe {
        if cid.is_null() {
            return 0;
        }
        if !pmd.is_null() {
            *pmd = (*cid).hashAlgorithm.algorithm;
        }
        if !piNameHash.is_null() {
            *piNameHash = &mut (*cid).issuerNameHash;
        }
        if !pikeyHash.is_null() {
            *pikeyHash = &mut (*cid).issuerKeyHash;
        }
        if !pserial.is_null() {
            *pserial = &mut (*cid).serialNumber;
        }
        1
    }
}

// ---------------------------------------------------------------------------------------------
// The responder's response builder — `ocsp_srv.c:55-231`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_request_is_signed(OCSP_REQUEST *req)` — `crypto/ocsp/ocsp_srv.c:55-60`.
///
/// # Safety
/// `req` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_request_is_signed(req: *mut OcspRequest) -> c_int {
    // SAFETY: `req` is live per the contract; the field read is its own.
    unsafe { c_int::from(!(*req).optionalSignature.is_null()) }
}

/// `OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs)` —
/// `crypto/ocsp/ocsp_srv.c:62-82`.
///
/// Builds a fresh top-level response and sets its `responseStatus`. A non-NULL `bs` is DER-packed
/// into a fresh `OCSP_RESPBYTES` typed `id-pkix-ocsp-basic`. Any failure frees the partial response
/// and answers NULL.
///
/// # Safety
/// `bs` must be NULL or a live `OCSP_BASICRESP`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_response_create(
    status: c_int,
    bs: *mut OcspBasicResp,
) -> *mut OcspResponse {
    // SAFETY: the item layer owns every value it builds; `bs` is NULL-or-live per the contract.
    unsafe {
        let rsp = OCSP_RESPONSE_new();
        if rsp.is_null() {
            return ptr::null_mut();
        }
        if ASN1_ENUMERATED_set((*rsp).responseStatus, status as c_long) == 0 {
            OCSP_RESPONSE_free(rsp);
            return ptr::null_mut();
        }
        if bs.is_null() {
            return rsp;
        }
        (*rsp).responseBytes = OCSP_RESPBYTES_new();
        if (*rsp).responseBytes.is_null() {
            OCSP_RESPONSE_free(rsp);
            return ptr::null_mut();
        }
        (*(*rsp).responseBytes).responseType = OBJ_nid2obj(NID_id_pkix_OCSP_basic);
        if ASN1_item_pack(
            bs.cast::<c_void>(),
            OCSP_BASICRESP_it(),
            ptr::addr_of_mut!((*(*rsp).responseBytes).response),
        )
        .is_null()
        {
            OCSP_RESPONSE_free(rsp);
            return ptr::null_mut();
        }
        rsp
    }
}

/// `OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp, OCSP_CERTID *cid, int status, int
/// reason, ASN1_TIME *revtime, ASN1_TIME *thisupd, ASN1_TIME *nextupd)` —
/// `crypto/ocsp/ocsp_srv.c:84-152`.
///
/// Appends a `SingleResponse` for `cid` and `status` to `rsp`: the times are converted to
/// `GeneralizedTime`, the id is duplicated, and the `CertStatus` choice is filled (a `revoked`
/// entry requires `revtime`, raising `OCSP_R_NO_REVOKED_TIME` otherwise, and carries `reason` unless
/// it is `OCSP_REVOKED_STATUS_NOSTATUS`). Any failure frees the partial single response and answers
/// NULL.
///
/// # Safety
/// `rsp` and `cid` must be live; `revtime`/`thisupd`/`nextupd` must be NULL or live `ASN1_TIME`s.
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_add1_status(
    rsp: *mut OcspBasicResp,
    cid: *mut OcspCertId,
    status: c_int,
    reason: c_int,
    revtime: *mut Asn1String,
    thisupd: *mut Asn1String,
    nextupd: *mut Asn1String,
) -> *mut OcspSingleResp {
    // SAFETY: every pointer is NULL-or-live per the contract; the item layer owns each value built.
    unsafe {
        if (*rsp).tbsResponseData.responses.is_null() {
            (*rsp).tbsResponseData.responses = OPENSSL_sk_new_null();
            if (*rsp).tbsResponseData.responses.is_null() {
                return ptr::null_mut();
            }
        }

        let single = OCSP_SINGLERESP_new();
        if single.is_null() {
            return ptr::null_mut();
        }

        if ASN1_TIME_to_generalizedtime(thisupd, ptr::addr_of_mut!((*single).thisUpdate)).is_null()
        {
            OCSP_SINGLERESP_free(single);
            return ptr::null_mut();
        }
        if !nextupd.is_null()
            && ASN1_TIME_to_generalizedtime(nextupd, ptr::addr_of_mut!((*single).nextUpdate))
                .is_null()
        {
            OCSP_SINGLERESP_free(single);
            return ptr::null_mut();
        }

        OCSP_CERTID_free((*single).certId);
        (*single).certId = OCSP_CERTID_dup(cid);
        if (*single).certId.is_null() {
            OCSP_SINGLERESP_free(single);
            return ptr::null_mut();
        }

        let cs = (*single).certStatus;
        (*cs).type_ = status;
        match status {
            V_OCSP_CERTSTATUS_REVOKED => {
                if revtime.is_null() {
                    raise_site(&OCSP_SRV_118);
                    OCSP_SINGLERESP_free(single);
                    return ptr::null_mut();
                }
                let ri = OCSP_REVOKEDINFO_new();
                (*cs).value.revoked = ri;
                if ri.is_null() {
                    OCSP_SINGLERESP_free(single);
                    return ptr::null_mut();
                }
                if ASN1_TIME_to_generalizedtime(revtime, ptr::addr_of_mut!((*ri).revocationTime))
                    .is_null()
                {
                    OCSP_SINGLERESP_free(single);
                    return ptr::null_mut();
                }
                if reason != OCSP_REVOKED_STATUS_NOSTATUS {
                    (*ri).revocationReason = ASN1_ENUMERATED_new();
                    if (*ri).revocationReason.is_null() {
                        OCSP_SINGLERESP_free(single);
                        return ptr::null_mut();
                    }
                    if ASN1_ENUMERATED_set((*ri).revocationReason, reason as c_long) == 0 {
                        OCSP_SINGLERESP_free(single);
                        return ptr::null_mut();
                    }
                }
            }
            V_OCSP_CERTSTATUS_GOOD => {
                (*cs).value.good = ASN1_NULL_new();
                if (*cs).value.good.is_null() {
                    OCSP_SINGLERESP_free(single);
                    return ptr::null_mut();
                }
            }
            V_OCSP_CERTSTATUS_UNKNOWN => {
                (*cs).value.unknown = ASN1_NULL_new();
                if (*cs).value.unknown.is_null() {
                    OCSP_SINGLERESP_free(single);
                    return ptr::null_mut();
                }
            }
            _ => {
                OCSP_SINGLERESP_free(single);
                return ptr::null_mut();
            }
        }
        if OPENSSL_sk_push((*rsp).tbsResponseData.responses, single.cast()) == 0 {
            OCSP_SINGLERESP_free(single);
            return ptr::null_mut();
        }
        single
    }
}

/// `int OCSP_basic_add1_cert(OCSP_BASICRESP *resp, X509 *cert)` — `crypto/ocsp/ocsp_srv.c:154-158`.
///
/// # Safety
/// `resp` must be a live `OCSP_BASICRESP`; `cert` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_add1_cert(resp: *mut OcspBasicResp, cert: *mut X509) -> c_int {
    // SAFETY: `resp` and `cert` are live per the contract.
    unsafe { ossl_x509_add_cert_new(ptr::addr_of_mut!((*resp).certs), cert, X509_ADD_FLAG_UP_REF) }
}

/// `int OCSP_basic_sign_ctx(OCSP_BASICRESP *brsp, X509 *signer, EVP_MD_CTX *ctx, STACK_OF(X509)
/// *certs, unsigned long flags)` — `crypto/ocsp/ocsp_srv.c:165-210`.
///
/// Signs the response with the key already bound into `ctx`: a missing signing context or key
/// raises the matching reason; unless `OCSP_NOCERTS`, `signer` and `certs` are added; the responder
/// id is set by key (`OCSP_RESPID_KEY`) or by name; `producedAt` is stamped unless `OCSP_NOTIME`;
/// and the `ResponseData` is signed through the `OCSP_BASICRESP_sign_ctx` macro, i.e.
/// `ASN1_item_sign_ctx` over `OCSP_RESPDATA`. Answers 1 on success, 0 on any failure.
///
/// # Safety
/// `brsp` and `signer` must be live; `ctx` NULL or a live signing context; `certs` NULL or a live
/// stack of live `X509`s.
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_sign_ctx(
    brsp: *mut OcspBasicResp,
    signer: *mut X509,
    ctx: *mut EvpMdCtx,
    certs: *mut OpenSslStack,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the pointers are live or NULL per the contract; every callee obeys its own contract.
    unsafe {
        if ctx.is_null() || EVP_MD_CTX_get_pkey_ctx(ctx).is_null() {
            raise_site(&OCSP_SRV_173);
            return 0;
        }

        let pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_get_pkey_ctx(ctx));
        if pkey.is_null() || X509_check_private_key(signer, pkey) == 0 {
            raise_site(&OCSP_SRV_179);
            return 0;
        }

        if (flags & OCSP_NOCERTS) == 0
            && (OCSP_basic_add1_cert(brsp, signer) == 0
                || X509_add_certs((*brsp).certs, certs, X509_ADD_FLAG_UP_REF) == 0)
        {
            return 0;
        }

        let rid = ptr::addr_of_mut!((*brsp).tbsResponseData.responderId);
        if (flags & OCSP_RESPID_KEY) != 0 {
            if OCSP_RESPID_set_by_key(rid, signer) == 0 {
                return 0;
            }
        } else if OCSP_RESPID_set_by_name(rid, signer) == 0 {
            return 0;
        }

        if (flags & OCSP_NOTIME) == 0
            && X509_gmtime_adj((*brsp).tbsResponseData.producedAt, 0).is_null()
        {
            return 0;
        }

        // `OCSP_BASICRESP_sign_ctx(brsp, ctx, 0)`.
        if ASN1_item_sign_ctx(
            OCSP_RESPDATA_it(),
            ptr::addr_of_mut!((*brsp).signatureAlgorithm),
            ptr::null_mut(),
            (*brsp).signature,
            ptr::addr_of!((*brsp).tbsResponseData).cast::<c_void>(),
            ctx,
        ) == 0
        {
            return 0;
        }

        1
    }
}

/// `int OCSP_basic_sign(OCSP_BASICRESP *brsp, X509 *signer, EVP_PKEY *key, const EVP_MD *dgst,
/// STACK_OF(X509) *certs, unsigned long flags)` — `crypto/ocsp/ocsp_srv.c:212-231`.
///
/// Wraps [`OCSP_basic_sign_ctx`]: a fresh `EVP_MD_CTX` is initialised for `key` under `dgst`'s name
/// and the signer's own library context and property query, then handed to the `_ctx` form. Answers
/// 0 when the context cannot be built or initialised.
///
/// # Safety
/// `brsp` and `signer` must be live; `key` NULL or live; `dgst` NULL or live; `certs` NULL or a live
/// stack of live `X509`s.
#[no_mangle]
pub unsafe extern "C" fn OCSP_basic_sign(
    brsp: *mut OcspBasicResp,
    signer: *mut X509,
    key: *mut EvpPkey,
    dgst: *const EvpMd,
    certs: *mut OpenSslStack,
    flags: c_ulong,
) -> c_int {
    // SAFETY: the pointers are live or NULL per the contract.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live; the key and signer are the caller's.
    unsafe {
        let mut pkctx: *mut EvpPkeyCtx = ptr::null_mut();
        if EVP_DigestSignInit_ex(
            ctx,
            &mut pkctx,
            EVP_MD_get0_name(dgst),
            (*signer).libctx,
            (*signer).propq,
            key,
            ptr::null(),
        ) == 0
        {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        let i = OCSP_basic_sign_ctx(brsp, signer, ctx, certs, flags);
        EVP_MD_CTX_free(ctx);
        i
    }
}

// ---------------------------------------------------------------------------------------------
// The responder id's setters and matchers — `ocsp_srv.c:233-326`
// ---------------------------------------------------------------------------------------------

/// `int OCSP_RESPID_set_by_name(OCSP_RESPID *respid, X509 *cert)` — `crypto/ocsp/ocsp_srv.c:233-241`.
///
/// Copies the certificate's subject name into `respid` and selects the `byName` arm. Answers 0 when
/// the copy fails.
///
/// # Safety
/// `respid` must be a live `OCSP_RESPID`; `cert` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_set_by_name(
    respid: *mut OcspRespid,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `respid` and `cert` are live per the contract.
    unsafe {
        if X509_NAME_set(
            ptr::addr_of_mut!((*respid).value.byName),
            X509_get_subject_name(cert),
        ) == 0
        {
            return 0;
        }
        (*respid).type_ = V_OCSP_RESPID_NAME;
        1
    }
}

/// `int OCSP_RESPID_set_by_key_ex(OCSP_RESPID *respid, X509 *cert, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/ocsp/ocsp_srv.c:243-274`.
///
/// Fetches `SHA1`, hashes the certificate's public key, and installs the digest as the responder id
/// with the `byKey` arm. Answers 0 when the fetch, digest or allocation fails.
///
/// # Safety
/// `respid` and `cert` must be live; `libctx` NULL or the context's own; `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_set_by_key_ex(
    respid: *mut OcspRespid,
    cert: *mut X509,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the pointers are live or NULL per the contract; the fetched digest is this call's.
    unsafe {
        let mut md = [0u8; SHA_DIGEST_LENGTH as usize];
        let sha1 = EVP_MD_fetch(libctx, SN_SHA1, propq);
        if sha1.is_null() {
            return 0;
        }

        let mut ret = 0;
        'body: {
            if X509_pubkey_digest(cert, sha1, md.as_mut_ptr(), ptr::null_mut()) == 0 {
                break 'body;
            }
            let bykey = ASN1_OCTET_STRING_new();
            if bykey.is_null() {
                break 'body;
            }
            if ASN1_OCTET_STRING_set(bykey, md.as_ptr(), SHA_DIGEST_LENGTH) == 0 {
                ASN1_OCTET_STRING_free(bykey);
                break 'body;
            }
            (*respid).type_ = V_OCSP_RESPID_KEY;
            (*respid).value.byKey = bykey;
            ret = 1;
        }
        EVP_MD_free(sha1);
        ret
    }
}

/// `int OCSP_RESPID_set_by_key(OCSP_RESPID *respid, X509 *cert)` — `crypto/ocsp/ocsp_srv.c:276-281`.
///
/// The certificate-identity half of [`OCSP_RESPID_set_by_key_ex`].
///
/// # Safety
/// `respid` must be a live `OCSP_RESPID`; `cert` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_set_by_key(respid: *mut OcspRespid, cert: *mut X509) -> c_int {
    // SAFETY: `respid` is live and `cert` is NULL-or-live per the contract.
    unsafe {
        if cert.is_null() {
            return 0;
        }
        OCSP_RESPID_set_by_key_ex(respid, cert, (*cert).libctx, (*cert).propq)
    }
}

/// `int OCSP_RESPID_match_ex(OCSP_RESPID *respid, X509 *cert, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `crypto/ocsp/ocsp_srv.c:283-319`.
///
/// A `byKey` id must be exactly `SHA_DIGEST_LENGTH` octets and equal the SHA-1 digest of `cert`'s
/// public key; a `byName` id must compare equal to `cert`'s subject name. Answers 0 for any other
/// arm.
///
/// # Safety
/// `respid` and `cert` must be live; `libctx` NULL or the context's own; `propq` NULL or
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_match_ex(
    respid: *mut OcspRespid,
    cert: *mut X509,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the pointers are live or NULL per the contract; the union arm read is the one the
    // selector names.
    unsafe {
        let mut ret = 0;
        let mut sha1: *mut EvpMd = ptr::null_mut();

        if (*respid).type_ == V_OCSP_RESPID_KEY {
            let mut md = [0u8; SHA_DIGEST_LENGTH as usize];
            sha1 = EVP_MD_fetch(libctx, SN_SHA1, propq);
            if sha1.is_null() {
                EVP_MD_free(sha1);
                return ret;
            }
            let bykey = (*respid).value.byKey;
            if bykey.is_null() {
                EVP_MD_free(sha1);
                return ret;
            }
            if X509_pubkey_digest(cert, sha1, md.as_mut_ptr(), ptr::null_mut()) == 0 {
                EVP_MD_free(sha1);
                return ret;
            }
            ret = c_int::from(
                ASN1_STRING_length(bykey) == SHA_DIGEST_LENGTH
                    && memcmp(ASN1_STRING_get0_data(bykey), md.as_ptr(), SHA_DIGEST_LENGTH) == 0,
            );
        } else if (*respid).type_ == V_OCSP_RESPID_NAME {
            let byname = (*respid).value.byName;
            if byname.is_null() {
                return 0;
            }
            return c_int::from(X509_NAME_cmp(byname, X509_get_subject_name(cert)) == 0);
        }

        EVP_MD_free(sha1);
        ret
    }
}

/// `int OCSP_RESPID_match(OCSP_RESPID *respid, X509 *cert)` — `crypto/ocsp/ocsp_srv.c:321-326`.
///
/// The certificate-identity half of [`OCSP_RESPID_match_ex`].
///
/// # Safety
/// `respid` must be a live `OCSP_RESPID`; `cert` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_match(respid: *mut OcspRespid, cert: *mut X509) -> c_int {
    // SAFETY: `respid` is live and `cert` is NULL-or-live per the contract.
    unsafe {
        if cert.is_null() {
            return 0;
        }
        OCSP_RESPID_match_ex(respid, cert, (*cert).libctx, (*cert).propq)
    }
}
