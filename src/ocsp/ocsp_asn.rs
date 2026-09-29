//! `crypto/ocsp/ocsp_asn.c` — the OCSP ASN.1 item groups and their generated lifecycles. Phase
//! 10.14.14's first unit, landed whole.
//!
//! `crypto/ocsp/ocsp_asn.c` is 135 lines and transcribes whole. It is a pure template file: no
//! raise sites, no `static` helper functions, and every declaration is either an `ASN1_SEQUENCE`/
//! `ASN1_CHOICE` template or its `IMPLEMENT_ASN1_FUNCTIONS` expansion. The fifteen item groups, in
//! source order:
//!
//! * `OCSP_SIGNATURE ::= SEQUENCE { signatureAlgorithm X509_ALGOR, signature BIT STRING, certs [0]
//!   EXPLICIT SEQUENCE OF Certificate OPTIONAL }` (`:15-19`).
//! * `OCSP_CERTID ::= SEQUENCE { hashAlgorithm X509_ALGOR, issuerNameHash OCTET STRING, issuerKeyHash
//!   OCTET STRING, serialNumber ASN1_INTEGER }` (`:23-28`), each member embedded.
//! * `OCSP_ONEREQ ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT Extensions
//!   OPTIONAL }` (`:32-35`).
//! * `OCSP_REQINFO ::= SEQUENCE { version [0] EXPLICIT INTEGER OPTIONAL, requestorName [1] EXPLICIT
//!   GeneralName OPTIONAL, requestList SEQUENCE OF Request, requestExtensions [2] EXPLICIT Extensions
//!   OPTIONAL }` (`:39-44`).
//! * `OCSP_REQUEST ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] EXPLICIT Signature
//!   OPTIONAL }` (`:48-51`).
//! * `OCSP_RESPBYTES ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }`
//!   (`:57-60`).
//! * `OCSP_RESPONSE ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ResponseBytes
//!   OPTIONAL }` (`:64-67`).
//! * `OCSP_RESPID ::= CHOICE { byName [1] EXPLICIT Name, byKey [2] EXPLICIT OCTET STRING }` (`:71-74`),
//!   over the `value` union.
//! * `OCSP_REVOKEDINFO ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0] EXPLICIT
//!   ENUMERATED OPTIONAL }` (`:78-81`).
//! * `OCSP_CERTSTATUS ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown
//!   [2] IMPLICIT UnknownInfo }` (`:85-89`), over the `value` union.
//! * `OCSP_SINGLERESP ::= SEQUENCE { certId CertID, certStatus CertStatus, thisUpdate GeneralizedTime,
//!   nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions [1] EXPLICIT Extensions
//!   OPTIONAL }` (`:93-99`).
//! * `OCSP_RESPDATA ::= SEQUENCE { version [0] EXPLICIT INTEGER OPTIONAL, responderID ResponderID,
//!   producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse, responseExtensions [1] EXPLICIT
//!   Extensions OPTIONAL }` (`:103-109`).
//! * `OCSP_BASICRESP ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm X509_ALGOR,
//!   signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }` (`:113-118`).
//! * `OCSP_CRLID ::= SEQUENCE { crlUrl [0] EXPLICIT IA5String OPTIONAL, crlNum [1] EXPLICIT INTEGER
//!   OPTIONAL, crlTime [2] EXPLICIT GeneralizedTime OPTIONAL }` (`:122-126`).
//! * `OCSP_SERVICELOC ::= SEQUENCE { issuer Name, locator SEQUENCE OF ACCESS_DESCRIPTION OPTIONAL }`
//!   (`:130-133`).
//!
//! Every one closes with the non-`static_` end macro, so each `_it` accessor is exported, and every
//! `IMPLEMENT_ASN1_FUNCTIONS` emits the `_it`/`_new`/`_free`/`d2i_`/`i2d_` quintet. The header
//! declares exactly these fifteen with `DECLARE_ASN1_FUNCTIONS` (`include/openssl/ocsp.h.in:361-375`),
//! matching `nm -D` on the admitted `libcrypto-shlib-ocsp_asn.o`, which shows 75 exported text
//! symbols and no others. The per-item template arrays and item descriptors are file-local `static`/
//! `d` data in the object, mirrored here by un-`no_mangle`d `static`s.
//!
//! The layouts live in `crypto/ocsp/ocsp_local.h` (the two `int`-flagged unions included) and match
//! the `#[repr(C)]` models below on LP64; every `size_of`/`offset_of!` is asserted.
//!
//! **Withheld by name**: none. `crypto/ocsp/ocsp_asn.c` has no raise sites (no `ERR_raise`), no
//! `static` helpers, and requires no missing crate helper.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_GENERALIZEDTIME_it, ASN1_IA5STRING_it,
    ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::runtime::obj::Asn1Object;
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_info::ACCESS_DESCRIPTION_it;
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_x509::X509_it;

// ---------------------------------------------------------------------------------------------
// The structures
// ---------------------------------------------------------------------------------------------

/// `struct ocsp_signature_st` — `OCSP_SIGNATURE`, from `crypto/ocsp/ocsp_local.h:52-56`.
#[repr(C)]
pub struct OcspSignature {
    /// `X509_ALGOR signatureAlgorithm` — embedded.
    pub signatureAlgorithm: X509Algor,
    /// `ASN1_BIT_STRING *signature`.
    pub signature: *mut Asn1String,
    /// `STACK_OF(X509) *certs` — the `[0] EXPLICIT SEQUENCE OF Certificate`, optional.
    pub certs: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspSignature>() == 32);
    assert!(core::mem::offset_of!(OcspSignature, signatureAlgorithm) == 0);
    assert!(core::mem::offset_of!(OcspSignature, signature) == 16);
    assert!(core::mem::offset_of!(OcspSignature, certs) == 24);
};

/// `struct ocsp_cert_id_st` — `OCSP_CERTID`, from `crypto/ocsp/ocsp_local.h:18-23`.
#[repr(C)]
pub struct OcspCertId {
    /// `X509_ALGOR hashAlgorithm` — embedded.
    pub hashAlgorithm: X509Algor,
    /// `ASN1_OCTET_STRING issuerNameHash` — embedded.
    pub issuerNameHash: Asn1String,
    /// `ASN1_OCTET_STRING issuerKeyHash` — embedded.
    pub issuerKeyHash: Asn1String,
    /// `ASN1_INTEGER serialNumber` — embedded.
    pub serialNumber: Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OcspCertId>() == 88);
    assert!(core::mem::offset_of!(OcspCertId, hashAlgorithm) == 0);
    assert!(core::mem::offset_of!(OcspCertId, issuerNameHash) == 16);
    assert!(core::mem::offset_of!(OcspCertId, issuerKeyHash) == 40);
    assert!(core::mem::offset_of!(OcspCertId, serialNumber) == 64);
};

/// `struct ocsp_one_request_st` — `OCSP_ONEREQ`, from `crypto/ocsp/ocsp_local.h:29-32`.
#[repr(C)]
pub struct OcspOneReq {
    /// `OCSP_CERTID *reqCert`.
    pub reqCert: *mut OcspCertId,
    /// `STACK_OF(X509_EXTENSION) *singleRequestExtensions` — the `[0] EXPLICIT SEQUENCE OF`, optional.
    pub singleRequestExtensions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspOneReq>() == 16);
    assert!(core::mem::offset_of!(OcspOneReq, reqCert) == 0);
    assert!(core::mem::offset_of!(OcspOneReq, singleRequestExtensions) == 8);
};

/// `struct ocsp_req_info_st` — `OCSP_REQINFO`, from `crypto/ocsp/ocsp_local.h:40-45`.
#[repr(C)]
pub struct OcspReqInfo {
    /// `ASN1_INTEGER *version` — the `[0] EXPLICIT Version`, optional.
    pub version: *mut Asn1String,
    /// `GENERAL_NAME *requestorName` — the `[1] EXPLICIT GeneralName`, optional.
    pub requestorName: *mut GeneralName,
    /// `STACK_OF(OCSP_ONEREQ) *requestList` — the `SEQUENCE OF Request`.
    pub requestList: *mut OpenSslStack,
    /// `STACK_OF(X509_EXTENSION) *requestExtensions` — the `[2] EXPLICIT Extensions`, optional.
    pub requestExtensions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspReqInfo>() == 32);
    assert!(core::mem::offset_of!(OcspReqInfo, version) == 0);
    assert!(core::mem::offset_of!(OcspReqInfo, requestorName) == 8);
    assert!(core::mem::offset_of!(OcspReqInfo, requestList) == 16);
    assert!(core::mem::offset_of!(OcspReqInfo, requestExtensions) == 24);
};

/// `struct ocsp_request_st` — `OCSP_REQUEST`, from `crypto/ocsp/ocsp_local.h:62-65`.
#[repr(C)]
pub struct OcspRequest {
    /// `OCSP_REQINFO tbsRequest` — embedded.
    pub tbsRequest: OcspReqInfo,
    /// `OCSP_SIGNATURE *optionalSignature` — the `[0] EXPLICIT Signature`, optional.
    pub optionalSignature: *mut OcspSignature,
}

const _: () = {
    assert!(core::mem::size_of::<OcspRequest>() == 40);
    assert!(core::mem::offset_of!(OcspRequest, tbsRequest) == 0);
    assert!(core::mem::offset_of!(OcspRequest, optionalSignature) == 32);
};

/// `struct ocsp_resp_bytes_st` — `OCSP_RESPBYTES`, from `crypto/ocsp/ocsp_local.h:82-85`.
#[repr(C)]
pub struct OcspRespBytes {
    /// `ASN1_OBJECT *responseType`.
    pub responseType: *mut Asn1Object,
    /// `ASN1_OCTET_STRING *response`.
    pub response: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OcspRespBytes>() == 16);
    assert!(core::mem::offset_of!(OcspRespBytes, responseType) == 0);
    assert!(core::mem::offset_of!(OcspRespBytes, response) == 8);
};

/// `struct ocsp_response_st` — `OCSP_RESPONSE`, from `crypto/ocsp/ocsp_local.h:91-94`.
#[repr(C)]
pub struct OcspResponse {
    /// `ASN1_ENUMERATED *responseStatus`.
    pub responseStatus: *mut Asn1String,
    /// `OCSP_RESPBYTES *responseBytes` — the `[0] EXPLICIT ResponseBytes`, optional.
    pub responseBytes: *mut OcspRespBytes,
}

const _: () = {
    assert!(core::mem::size_of::<OcspResponse>() == 16);
    assert!(core::mem::offset_of!(OcspResponse, responseStatus) == 0);
    assert!(core::mem::offset_of!(OcspResponse, responseBytes) == 8);
};

/// The `value` union of `struct ocsp_responder_id_st` — `crypto/ocsp/ocsp_local.h:102-105`. Both arms
/// are a pointer.
#[repr(C)]
pub union OcspRespidValue {
    /// `X509_NAME *byName` — the `[1]` arm.
    pub byName: *mut X509Name,
    /// `ASN1_OCTET_STRING *byKey` — the `[2]` arm.
    pub byKey: *mut Asn1String,
}

/// `struct ocsp_responder_id_st` — `OCSP_RESPID`, from `crypto/ocsp/ocsp_local.h:100-106`.
#[repr(C)]
pub struct OcspRespid {
    /// `int type` — the `CHOICE` selector.
    pub type_: c_int,
    /// The `value` union.
    pub value: OcspRespidValue,
}

const _: () = {
    assert!(core::mem::size_of::<OcspRespidValue>() == 8);
    assert!(core::mem::size_of::<OcspRespid>() == 16);
    assert!(core::mem::offset_of!(OcspRespid, type_) == 0);
    assert!(core::mem::offset_of!(OcspRespid, value) == 8);
};

/// `struct ocsp_revoked_info_st` — `OCSP_REVOKEDINFO`, from `crypto/ocsp/ocsp_local.h:116-119`.
#[repr(C)]
pub struct OcspRevokedInfo {
    /// `ASN1_GENERALIZEDTIME *revocationTime`.
    pub revocationTime: *mut Asn1String,
    /// `ASN1_ENUMERATED *revocationReason` — the `[0] EXPLICIT CRLReason`, optional.
    pub revocationReason: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OcspRevokedInfo>() == 16);
    assert!(core::mem::offset_of!(OcspRevokedInfo, revocationTime) == 0);
    assert!(core::mem::offset_of!(OcspRevokedInfo, revocationReason) == 8);
};

/// The `value` union of `struct ocsp_cert_status_st` — `crypto/ocsp/ocsp_local.h:128-132`. `ASN1_NULL`
/// is `typedef int` (`crate::asn1::typ`), so its two arms are `int *`.
#[repr(C)]
pub union OcspCertStatusValue {
    /// `ASN1_NULL *good` — the `[0] IMPLICIT` arm, an `int *` sentinel.
    pub good: *mut c_int,
    /// `OCSP_REVOKEDINFO *revoked` — the `[1] IMPLICIT` arm.
    pub revoked: *mut OcspRevokedInfo,
    /// `ASN1_NULL *unknown` — the `[2] IMPLICIT` arm, an `int *` sentinel.
    pub unknown: *mut c_int,
}

/// `struct ocsp_cert_status_st` — `OCSP_CERTSTATUS`, from `crypto/ocsp/ocsp_local.h:126-133`.
#[repr(C)]
pub struct OcspCertStatus {
    /// `int type` — the `CHOICE` selector.
    pub type_: c_int,
    /// The `value` union.
    pub value: OcspCertStatusValue,
}

const _: () = {
    assert!(core::mem::size_of::<OcspCertStatusValue>() == 8);
    assert!(core::mem::size_of::<OcspCertStatus>() == 16);
    assert!(core::mem::offset_of!(OcspCertStatus, type_) == 0);
    assert!(core::mem::offset_of!(OcspCertStatus, value) == 8);
};

/// `struct ocsp_single_response_st` — `OCSP_SINGLERESP`, from `crypto/ocsp/ocsp_local.h:142-148`.
#[repr(C)]
pub struct OcspSingleResp {
    /// `OCSP_CERTID *certId`.
    pub certId: *mut OcspCertId,
    /// `OCSP_CERTSTATUS *certStatus`.
    pub certStatus: *mut OcspCertStatus,
    /// `ASN1_GENERALIZEDTIME *thisUpdate`.
    pub thisUpdate: *mut Asn1String,
    /// `ASN1_GENERALIZEDTIME *nextUpdate` — the `[0] EXPLICIT`, optional.
    pub nextUpdate: *mut Asn1String,
    /// `STACK_OF(X509_EXTENSION) *singleExtensions` — the `[1] EXPLICIT SEQUENCE OF`, optional.
    pub singleExtensions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspSingleResp>() == 40);
    assert!(core::mem::offset_of!(OcspSingleResp, certId) == 0);
    assert!(core::mem::offset_of!(OcspSingleResp, certStatus) == 8);
    assert!(core::mem::offset_of!(OcspSingleResp, thisUpdate) == 16);
    assert!(core::mem::offset_of!(OcspSingleResp, nextUpdate) == 24);
    assert!(core::mem::offset_of!(OcspSingleResp, singleExtensions) == 32);
};

/// `struct ocsp_response_data_st` — `OCSP_RESPDATA`, from `crypto/ocsp/ocsp_local.h:157-163`.
#[repr(C)]
pub struct OcspRespData {
    /// `ASN1_INTEGER *version` — the `[0] EXPLICIT Version`, optional.
    pub version: *mut Asn1String,
    /// `OCSP_RESPID responderId` — embedded.
    pub responderId: OcspRespid,
    /// `ASN1_GENERALIZEDTIME *producedAt`.
    pub producedAt: *mut Asn1String,
    /// `STACK_OF(OCSP_SINGLERESP) *responses` — the `SEQUENCE OF SingleResponse`.
    pub responses: *mut OpenSslStack,
    /// `STACK_OF(X509_EXTENSION) *responseExtensions` — the `[1] EXPLICIT Extensions`, optional.
    pub responseExtensions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspRespData>() == 48);
    assert!(core::mem::offset_of!(OcspRespData, version) == 0);
    assert!(core::mem::offset_of!(OcspRespData, responderId) == 8);
    assert!(core::mem::offset_of!(OcspRespData, producedAt) == 24);
    assert!(core::mem::offset_of!(OcspRespData, responses) == 32);
    assert!(core::mem::offset_of!(OcspRespData, responseExtensions) == 40);
};

/// `struct ocsp_basic_response_st` — `OCSP_BASICRESP`, from `crypto/ocsp/ocsp_local.h:191-196`.
#[repr(C)]
pub struct OcspBasicResp {
    /// `OCSP_RESPDATA tbsResponseData` — embedded.
    pub tbsResponseData: OcspRespData,
    /// `X509_ALGOR signatureAlgorithm` — embedded.
    pub signatureAlgorithm: X509Algor,
    /// `ASN1_BIT_STRING *signature`.
    pub signature: *mut Asn1String,
    /// `STACK_OF(X509) *certs` — the `[0] EXPLICIT SEQUENCE OF Certificate`, optional.
    pub certs: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspBasicResp>() == 80);
    assert!(core::mem::offset_of!(OcspBasicResp, tbsResponseData) == 0);
    assert!(core::mem::offset_of!(OcspBasicResp, signatureAlgorithm) == 48);
    assert!(core::mem::offset_of!(OcspBasicResp, signature) == 64);
    assert!(core::mem::offset_of!(OcspBasicResp, certs) == 72);
};

/// `struct ocsp_crl_id_st` — `OCSP_CRLID`, from `crypto/ocsp/ocsp_local.h:204-208`.
#[repr(C)]
pub struct OcspCrlId {
    /// `ASN1_IA5STRING *crlUrl` — the `[0] EXPLICIT IA5String`, optional.
    pub crlUrl: *mut Asn1String,
    /// `ASN1_INTEGER *crlNum` — the `[1] EXPLICIT INTEGER`, optional.
    pub crlNum: *mut Asn1String,
    /// `ASN1_GENERALIZEDTIME *crlTime` — the `[2] EXPLICIT GeneralizedTime`, optional.
    pub crlTime: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OcspCrlId>() == 24);
    assert!(core::mem::offset_of!(OcspCrlId, crlUrl) == 0);
    assert!(core::mem::offset_of!(OcspCrlId, crlNum) == 8);
    assert!(core::mem::offset_of!(OcspCrlId, crlTime) == 16);
};

/// `struct ocsp_service_locator_st` — `OCSP_SERVICELOC`, from `crypto/ocsp/ocsp_local.h:215-218`.
#[repr(C)]
pub struct OcspServiceLoc {
    /// `X509_NAME *issuer`.
    pub issuer: *mut X509Name,
    /// `STACK_OF(ACCESS_DESCRIPTION) *locator` — the `SEQUENCE OF ACCESS_DESCRIPTION`, optional.
    pub locator: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OcspServiceLoc>() == 16);
    assert!(core::mem::offset_of!(OcspServiceLoc, issuer) == 0);
    assert!(core::mem::offset_of!(OcspServiceLoc, locator) == 8);
};

// ---------------------------------------------------------------------------------------------
// OCSP_SIGNATURE — `ASN1_SEQUENCE(OCSP_SIGNATURE)` (`crypto/ocsp/ocsp_asn.c:15-19`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_SIGNATURE_seq_tt` — `ASN1_SEQUENCE(OCSP_SIGNATURE)` (`crypto/ocsp/ocsp_asn.c:15-19`):
/// `ASN1_EMBED(signatureAlgorithm, X509_ALGOR)`, `ASN1_SIMPLE(signature, ASN1_BIT_STRING)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(certs, X509, 0)`.
static OCSP_SIGNATURE_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"signatureAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"certs".as_ptr(),
        item: X509_it as *mut c_void,
    },
];

/// `OCSP_SIGNATURE_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_SIGNATURE)` at
/// `crypto/ocsp/ocsp_asn.c:19`.
static OCSP_SIGNATURE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_SIGNATURE_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspSignature>() as c_long,
    sname: c"OCSP_SIGNATURE".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_SIGNATURE_it(void)` — `include/openssl/ocsp.h.in:372`, from
/// `DECLARE_ASN1_FUNCTIONS(OCSP_SIGNATURE)`.
#[no_mangle]
pub extern "C" fn OCSP_SIGNATURE_it() -> *const Asn1Item {
    &OCSP_SIGNATURE_ITEM
}

/// `OCSP_SIGNATURE *OCSP_SIGNATURE_new(void)` — `crypto/ocsp/ocsp_asn.c:21`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_SIGNATURE)`.
#[no_mangle]
pub extern "C" fn OCSP_SIGNATURE_new() -> *mut OcspSignature {
    // SAFETY: `OCSP_SIGNATURE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_SIGNATURE_it()).cast::<OcspSignature>() }
}

/// `void OCSP_SIGNATURE_free(OCSP_SIGNATURE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SIGNATURE_free(a: *mut OcspSignature) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_SIGNATURE_it()) }
}

/// `OCSP_SIGNATURE *d2i_OCSP_SIGNATURE(OCSP_SIGNATURE **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_SIGNATURE(
    a: *mut *mut OcspSignature,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspSignature {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_SIGNATURE_it()).cast::<OcspSignature>() }
}

/// `int i2d_OCSP_SIGNATURE(const OCSP_SIGNATURE *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_SIGNATURE(
    a: *const OcspSignature,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_SIGNATURE_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_CERTID — `ASN1_SEQUENCE(OCSP_CERTID)` (`crypto/ocsp/ocsp_asn.c:23-28`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_CERTID_seq_tt` — `ASN1_SEQUENCE(OCSP_CERTID)` (`crypto/ocsp/ocsp_asn.c:23-28`): four
/// `ASN1_EMBED` members — `X509_ALGOR`, `ASN1_OCTET_STRING`, `ASN1_OCTET_STRING`, `ASN1_INTEGER`.
static OCSP_CERTID_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"hashAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 16,
        field_name: c"issuerNameHash".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 40,
        field_name: c"issuerKeyHash".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 64,
        field_name: c"serialNumber".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `OCSP_CERTID_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_CERTID)` at `crypto/ocsp/ocsp_asn.c:28`.
static OCSP_CERTID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_CERTID_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspCertId>() as c_long,
    sname: c"OCSP_CERTID".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_CERTID_it(void)` — `include/openssl/ocsp.h.in:370`.
#[no_mangle]
pub extern "C" fn OCSP_CERTID_it() -> *const Asn1Item {
    &OCSP_CERTID_ITEM
}

/// `OCSP_CERTID *OCSP_CERTID_new(void)` — `crypto/ocsp/ocsp_asn.c:30`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTID)`.
#[no_mangle]
pub extern "C" fn OCSP_CERTID_new() -> *mut OcspCertId {
    // SAFETY: `OCSP_CERTID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_CERTID_it()).cast::<OcspCertId>() }
}

/// `void OCSP_CERTID_free(OCSP_CERTID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_CERTID_free(a: *mut OcspCertId) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_CERTID_it()) }
}

/// `OCSP_CERTID *d2i_OCSP_CERTID(OCSP_CERTID **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_CERTID(
    a: *mut *mut OcspCertId,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspCertId {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_CERTID_it()).cast::<OcspCertId>() }
}

/// `int i2d_OCSP_CERTID(const OCSP_CERTID *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_CERTID(a: *const OcspCertId, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_CERTID_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_ONEREQ — `ASN1_SEQUENCE(OCSP_ONEREQ)` (`crypto/ocsp/ocsp_asn.c:32-35`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_ONEREQ_seq_tt` — `ASN1_SEQUENCE(OCSP_ONEREQ)`: `ASN1_SIMPLE(reqCert, OCSP_CERTID)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(singleRequestExtensions, X509_EXTENSION, 0)`.
static OCSP_ONEREQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"reqCert".as_ptr(),
        item: OCSP_CERTID_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"singleRequestExtensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `OCSP_ONEREQ_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_ONEREQ)` at `crypto/ocsp/ocsp_asn.c:35`.
static OCSP_ONEREQ_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_ONEREQ_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspOneReq>() as c_long,
    sname: c"OCSP_ONEREQ".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_ONEREQ_it(void)` — `include/openssl/ocsp.h.in:369`.
#[no_mangle]
pub extern "C" fn OCSP_ONEREQ_it() -> *const Asn1Item {
    &OCSP_ONEREQ_ITEM
}

/// `OCSP_ONEREQ *OCSP_ONEREQ_new(void)` — `crypto/ocsp/ocsp_asn.c:37`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_ONEREQ)`.
#[no_mangle]
pub extern "C" fn OCSP_ONEREQ_new() -> *mut OcspOneReq {
    // SAFETY: `OCSP_ONEREQ_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_ONEREQ_it()).cast::<OcspOneReq>() }
}

/// `void OCSP_ONEREQ_free(OCSP_ONEREQ *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_ONEREQ_free(a: *mut OcspOneReq) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_ONEREQ_it()) }
}

/// `OCSP_ONEREQ *d2i_OCSP_ONEREQ(OCSP_ONEREQ **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_ONEREQ(
    a: *mut *mut OcspOneReq,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspOneReq {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_ONEREQ_it()).cast::<OcspOneReq>() }
}

/// `int i2d_OCSP_ONEREQ(const OCSP_ONEREQ *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_ONEREQ(a: *const OcspOneReq, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_ONEREQ_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_REQINFO — `ASN1_SEQUENCE(OCSP_REQINFO)` (`crypto/ocsp/ocsp_asn.c:39-44`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_REQINFO_seq_tt` — `ASN1_SEQUENCE(OCSP_REQINFO)`: `ASN1_EXP_OPT(version, ASN1_INTEGER, 0)`,
/// `ASN1_EXP_OPT(requestorName, GENERAL_NAME, 1)`, `ASN1_SEQUENCE_OF(requestList, OCSP_ONEREQ)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(requestExtensions, X509_EXTENSION, 2)`.
static OCSP_REQINFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"requestorName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 16,
        field_name: c"requestList".as_ptr(),
        item: OCSP_ONEREQ_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 24,
        field_name: c"requestExtensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `OCSP_REQINFO_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_REQINFO)` at `crypto/ocsp/ocsp_asn.c:44`.
static OCSP_REQINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_REQINFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspReqInfo>() as c_long,
    sname: c"OCSP_REQINFO".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_REQINFO_it(void)` — `include/openssl/ocsp.h.in:373`.
#[no_mangle]
pub extern "C" fn OCSP_REQINFO_it() -> *const Asn1Item {
    &OCSP_REQINFO_ITEM
}

/// `OCSP_REQINFO *OCSP_REQINFO_new(void)` — `crypto/ocsp/ocsp_asn.c:46`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_REQINFO)`.
#[no_mangle]
pub extern "C" fn OCSP_REQINFO_new() -> *mut OcspReqInfo {
    // SAFETY: `OCSP_REQINFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_REQINFO_it()).cast::<OcspReqInfo>() }
}

/// `void OCSP_REQINFO_free(OCSP_REQINFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQINFO_free(a: *mut OcspReqInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_REQINFO_it()) }
}

/// `OCSP_REQINFO *d2i_OCSP_REQINFO(OCSP_REQINFO **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REQINFO(
    a: *mut *mut OcspReqInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspReqInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_REQINFO_it()).cast::<OcspReqInfo>() }
}

/// `int i2d_OCSP_REQINFO(const OCSP_REQINFO *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REQINFO(a: *const OcspReqInfo, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_REQINFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_REQUEST — `ASN1_SEQUENCE(OCSP_REQUEST)` (`crypto/ocsp/ocsp_asn.c:48-51`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_REQUEST_seq_tt` — `ASN1_SEQUENCE(OCSP_REQUEST)`: `ASN1_EMBED(tbsRequest, OCSP_REQINFO)` and
/// `ASN1_EXP_OPT(optionalSignature, OCSP_SIGNATURE, 0)`.
static OCSP_REQUEST_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"tbsRequest".as_ptr(),
        item: OCSP_REQINFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"optionalSignature".as_ptr(),
        item: OCSP_SIGNATURE_it as *mut c_void,
    },
];

/// `OCSP_REQUEST_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_REQUEST)` at `crypto/ocsp/ocsp_asn.c:51`.
static OCSP_REQUEST_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_REQUEST_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspRequest>() as c_long,
    sname: c"OCSP_REQUEST".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_REQUEST_it(void)` — `include/openssl/ocsp.h.in:371`.
#[no_mangle]
pub extern "C" fn OCSP_REQUEST_it() -> *const Asn1Item {
    &OCSP_REQUEST_ITEM
}

/// `OCSP_REQUEST *OCSP_REQUEST_new(void)` — `crypto/ocsp/ocsp_asn.c:53`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_REQUEST)`.
#[no_mangle]
pub extern "C" fn OCSP_REQUEST_new() -> *mut OcspRequest {
    // SAFETY: `OCSP_REQUEST_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_REQUEST_it()).cast::<OcspRequest>() }
}

/// `void OCSP_REQUEST_free(OCSP_REQUEST *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_free(a: *mut OcspRequest) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_REQUEST_it()) }
}

/// `OCSP_REQUEST *d2i_OCSP_REQUEST(OCSP_REQUEST **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REQUEST(
    a: *mut *mut OcspRequest,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspRequest {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_REQUEST_it()).cast::<OcspRequest>() }
}

/// `int i2d_OCSP_REQUEST(const OCSP_REQUEST *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REQUEST(a: *const OcspRequest, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_REQUEST_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_RESPBYTES — `ASN1_SEQUENCE(OCSP_RESPBYTES)` (`crypto/ocsp/ocsp_asn.c:57-60`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_RESPBYTES_seq_tt` — `ASN1_SEQUENCE(OCSP_RESPBYTES)`: `ASN1_SIMPLE(responseType,
/// ASN1_OBJECT)` and `ASN1_SIMPLE(response, ASN1_OCTET_STRING)`.
static OCSP_RESPBYTES_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"responseType".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"response".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `OCSP_RESPBYTES_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_RESPBYTES)` at
/// `crypto/ocsp/ocsp_asn.c:60`.
static OCSP_RESPBYTES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_RESPBYTES_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspRespBytes>() as c_long,
    sname: c"OCSP_RESPBYTES".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_RESPBYTES_it(void)` — `include/openssl/ocsp.h.in:368`.
#[no_mangle]
pub extern "C" fn OCSP_RESPBYTES_it() -> *const Asn1Item {
    &OCSP_RESPBYTES_ITEM
}

/// `OCSP_RESPBYTES *OCSP_RESPBYTES_new(void)` — `crypto/ocsp/ocsp_asn.c:62`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPBYTES)`.
#[no_mangle]
pub extern "C" fn OCSP_RESPBYTES_new() -> *mut OcspRespBytes {
    // SAFETY: `OCSP_RESPBYTES_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_RESPBYTES_it()).cast::<OcspRespBytes>() }
}

/// `void OCSP_RESPBYTES_free(OCSP_RESPBYTES *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPBYTES_free(a: *mut OcspRespBytes) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_RESPBYTES_it()) }
}

/// `OCSP_RESPBYTES *d2i_OCSP_RESPBYTES(OCSP_RESPBYTES **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPBYTES(
    a: *mut *mut OcspRespBytes,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspRespBytes {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_RESPBYTES_it()).cast::<OcspRespBytes>() }
}

/// `int i2d_OCSP_RESPBYTES(const OCSP_RESPBYTES *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPBYTES(
    a: *const OcspRespBytes,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_RESPBYTES_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_RESPONSE — `ASN1_SEQUENCE(OCSP_RESPONSE)` (`crypto/ocsp/ocsp_asn.c:64-67`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_RESPONSE_seq_tt` — `ASN1_SEQUENCE(OCSP_RESPONSE)`: `ASN1_SIMPLE(responseStatus,
/// ASN1_ENUMERATED)` and `ASN1_EXP_OPT(responseBytes, OCSP_RESPBYTES, 0)`.
static OCSP_RESPONSE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"responseStatus".as_ptr(),
        item: ASN1_ENUMERATED_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"responseBytes".as_ptr(),
        item: OCSP_RESPBYTES_it as *mut c_void,
    },
];

/// `OCSP_RESPONSE_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_RESPONSE)` at `crypto/ocsp/ocsp_asn.c:67`.
static OCSP_RESPONSE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_RESPONSE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspResponse>() as c_long,
    sname: c"OCSP_RESPONSE".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_RESPONSE_it(void)` — `include/openssl/ocsp.h.in:367`.
#[no_mangle]
pub extern "C" fn OCSP_RESPONSE_it() -> *const Asn1Item {
    &OCSP_RESPONSE_ITEM
}

/// `OCSP_RESPONSE *OCSP_RESPONSE_new(void)` — `crypto/ocsp/ocsp_asn.c:69`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPONSE)`.
#[no_mangle]
pub extern "C" fn OCSP_RESPONSE_new() -> *mut OcspResponse {
    // SAFETY: `OCSP_RESPONSE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_RESPONSE_it()).cast::<OcspResponse>() }
}

/// `void OCSP_RESPONSE_free(OCSP_RESPONSE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPONSE_free(a: *mut OcspResponse) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_RESPONSE_it()) }
}

/// `OCSP_RESPONSE *d2i_OCSP_RESPONSE(OCSP_RESPONSE **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPONSE(
    a: *mut *mut OcspResponse,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspResponse {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_RESPONSE_it()).cast::<OcspResponse>() }
}

/// `int i2d_OCSP_RESPONSE(const OCSP_RESPONSE *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPONSE(
    a: *const OcspResponse,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_RESPONSE_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_RESPID — `ASN1_CHOICE(OCSP_RESPID)` (`crypto/ocsp/ocsp_asn.c:71-74`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_RESPID_ch_tt` — `ASN1_CHOICE(OCSP_RESPID)`: `ASN1_EXP(value.byName, X509_NAME, 1)` and
/// `ASN1_EXP(value.byKey, ASN1_OCTET_STRING, 2)`. Both arms live at the union's offset 8.
static OCSP_RESPID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"value.byName".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"value.byKey".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `OCSP_RESPID_it`'s descriptor — `ASN1_CHOICE_END(OCSP_RESPID)` at `crypto/ocsp/ocsp_asn.c:74`.
/// The `utype` of a `CHOICE` is the selector's offset; `funcs` is NULL (no `ASN1_AUX`).
static OCSP_RESPID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OcspRespid, type_) as c_long,
    templates: OCSP_RESPID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspRespid>() as c_long,
    sname: c"OCSP_RESPID".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_RESPID_it(void)` — `include/openssl/ocsp.h.in:366`.
#[no_mangle]
pub extern "C" fn OCSP_RESPID_it() -> *const Asn1Item {
    &OCSP_RESPID_ITEM
}

/// `OCSP_RESPID *OCSP_RESPID_new(void)` — `crypto/ocsp/ocsp_asn.c:76`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPID)`.
#[no_mangle]
pub extern "C" fn OCSP_RESPID_new() -> *mut OcspRespid {
    // SAFETY: `OCSP_RESPID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_RESPID_it()).cast::<OcspRespid>() }
}

/// `void OCSP_RESPID_free(OCSP_RESPID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPID_free(a: *mut OcspRespid) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_RESPID_it()) }
}

/// `OCSP_RESPID *d2i_OCSP_RESPID(OCSP_RESPID **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPID(
    a: *mut *mut OcspRespid,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspRespid {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_RESPID_it()).cast::<OcspRespid>() }
}

/// `int i2d_OCSP_RESPID(const OCSP_RESPID *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPID(a: *const OcspRespid, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_RESPID_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_REVOKEDINFO — `ASN1_SEQUENCE(OCSP_REVOKEDINFO)` (`crypto/ocsp/ocsp_asn.c:78-81`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_REVOKEDINFO_seq_tt` — `ASN1_SEQUENCE(OCSP_REVOKEDINFO)`: `ASN1_SIMPLE(revocationTime,
/// ASN1_GENERALIZEDTIME)` and `ASN1_EXP_OPT(revocationReason, ASN1_ENUMERATED, 0)`.
static OCSP_REVOKEDINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"revocationTime".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"revocationReason".as_ptr(),
        item: ASN1_ENUMERATED_it as *mut c_void,
    },
];

/// `OCSP_REVOKEDINFO_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_REVOKEDINFO)` at
/// `crypto/ocsp/ocsp_asn.c:81`.
static OCSP_REVOKEDINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_REVOKEDINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspRevokedInfo>() as c_long,
    sname: c"OCSP_REVOKEDINFO".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_REVOKEDINFO_it(void)` — `include/openssl/ocsp.h.in:363`.
#[no_mangle]
pub extern "C" fn OCSP_REVOKEDINFO_it() -> *const Asn1Item {
    &OCSP_REVOKEDINFO_ITEM
}

/// `OCSP_REVOKEDINFO *OCSP_REVOKEDINFO_new(void)` — `crypto/ocsp/ocsp_asn.c:83`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)`.
#[no_mangle]
pub extern "C" fn OCSP_REVOKEDINFO_new() -> *mut OcspRevokedInfo {
    // SAFETY: `OCSP_REVOKEDINFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_REVOKEDINFO_it()).cast::<OcspRevokedInfo>() }
}

/// `void OCSP_REVOKEDINFO_free(OCSP_REVOKEDINFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REVOKEDINFO_free(a: *mut OcspRevokedInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_REVOKEDINFO_it()) }
}

/// `OCSP_REVOKEDINFO *d2i_OCSP_REVOKEDINFO(OCSP_REVOKEDINFO **a, const unsigned char **in, long
/// len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_REVOKEDINFO(
    a: *mut *mut OcspRevokedInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspRevokedInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_REVOKEDINFO_it()).cast::<OcspRevokedInfo>() }
}

/// `int i2d_OCSP_REVOKEDINFO(const OCSP_REVOKEDINFO *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_REVOKEDINFO(
    a: *const OcspRevokedInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_REVOKEDINFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_CERTSTATUS — `ASN1_CHOICE(OCSP_CERTSTATUS)` (`crypto/ocsp/ocsp_asn.c:85-89`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_CERTSTATUS_ch_tt` — `ASN1_CHOICE(OCSP_CERTSTATUS)`: `ASN1_IMP(value.good, ASN1_NULL, 0)`,
/// `ASN1_IMP(value.revoked, OCSP_REVOKEDINFO, 1)` and `ASN1_IMP(value.unknown, ASN1_NULL, 2)`. Every
/// arm lives at the union's offset 8.
static OCSP_CERTSTATUS_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value.good".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"value.revoked".as_ptr(),
        item: OCSP_REVOKEDINFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"value.unknown".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
];

/// `OCSP_CERTSTATUS_it`'s descriptor — `ASN1_CHOICE_END(OCSP_CERTSTATUS)` at
/// `crypto/ocsp/ocsp_asn.c:89`.
static OCSP_CERTSTATUS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OcspCertStatus, type_) as c_long,
    templates: OCSP_CERTSTATUS_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspCertStatus>() as c_long,
    sname: c"OCSP_CERTSTATUS".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_CERTSTATUS_it(void)` — `include/openssl/ocsp.h.in:362`.
#[no_mangle]
pub extern "C" fn OCSP_CERTSTATUS_it() -> *const Asn1Item {
    &OCSP_CERTSTATUS_ITEM
}

/// `OCSP_CERTSTATUS *OCSP_CERTSTATUS_new(void)` — `crypto/ocsp/ocsp_asn.c:91`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_CERTSTATUS)`.
#[no_mangle]
pub extern "C" fn OCSP_CERTSTATUS_new() -> *mut OcspCertStatus {
    // SAFETY: `OCSP_CERTSTATUS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_CERTSTATUS_it()).cast::<OcspCertStatus>() }
}

/// `void OCSP_CERTSTATUS_free(OCSP_CERTSTATUS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_CERTSTATUS_free(a: *mut OcspCertStatus) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_CERTSTATUS_it()) }
}

/// `OCSP_CERTSTATUS *d2i_OCSP_CERTSTATUS(OCSP_CERTSTATUS **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_CERTSTATUS(
    a: *mut *mut OcspCertStatus,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspCertStatus {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_CERTSTATUS_it()).cast::<OcspCertStatus>() }
}

/// `int i2d_OCSP_CERTSTATUS(const OCSP_CERTSTATUS *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_CERTSTATUS(
    a: *const OcspCertStatus,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_CERTSTATUS_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_SINGLERESP — `ASN1_SEQUENCE(OCSP_SINGLERESP)` (`crypto/ocsp/ocsp_asn.c:93-99`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_SINGLERESP_seq_tt` — `ASN1_SEQUENCE(OCSP_SINGLERESP)`: `ASN1_SIMPLE(certId, OCSP_CERTID)`,
/// `ASN1_SIMPLE(certStatus, OCSP_CERTSTATUS)`, `ASN1_SIMPLE(thisUpdate, ASN1_GENERALIZEDTIME)`,
/// `ASN1_EXP_OPT(nextUpdate, ASN1_GENERALIZEDTIME, 0)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(singleExtensions, X509_EXTENSION, 1)`.
static OCSP_SINGLERESP_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"certId".as_ptr(),
        item: OCSP_CERTID_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"certStatus".as_ptr(),
        item: OCSP_CERTSTATUS_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"thisUpdate".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"nextUpdate".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"singleExtensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `OCSP_SINGLERESP_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_SINGLERESP)` at
/// `crypto/ocsp/ocsp_asn.c:99`.
static OCSP_SINGLERESP_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_SINGLERESP_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspSingleResp>() as c_long,
    sname: c"OCSP_SINGLERESP".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_SINGLERESP_it(void)` — `include/openssl/ocsp.h.in:361`.
#[no_mangle]
pub extern "C" fn OCSP_SINGLERESP_it() -> *const Asn1Item {
    &OCSP_SINGLERESP_ITEM
}

/// `OCSP_SINGLERESP *OCSP_SINGLERESP_new(void)` — `crypto/ocsp/ocsp_asn.c:101`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_SINGLERESP)`.
#[no_mangle]
pub extern "C" fn OCSP_SINGLERESP_new() -> *mut OcspSingleResp {
    // SAFETY: `OCSP_SINGLERESP_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_SINGLERESP_it()).cast::<OcspSingleResp>() }
}

/// `void OCSP_SINGLERESP_free(OCSP_SINGLERESP *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SINGLERESP_free(a: *mut OcspSingleResp) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_SINGLERESP_it()) }
}

/// `OCSP_SINGLERESP *d2i_OCSP_SINGLERESP(OCSP_SINGLERESP **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_SINGLERESP(
    a: *mut *mut OcspSingleResp,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspSingleResp {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_SINGLERESP_it()).cast::<OcspSingleResp>() }
}

/// `int i2d_OCSP_SINGLERESP(const OCSP_SINGLERESP *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_SINGLERESP(
    a: *const OcspSingleResp,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_SINGLERESP_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_RESPDATA — `ASN1_SEQUENCE(OCSP_RESPDATA)` (`crypto/ocsp/ocsp_asn.c:103-109`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_RESPDATA_seq_tt` — `ASN1_SEQUENCE(OCSP_RESPDATA)`: `ASN1_EXP_OPT(version, ASN1_INTEGER, 0)`,
/// `ASN1_EMBED(responderId, OCSP_RESPID)`, `ASN1_SIMPLE(producedAt, ASN1_GENERALIZEDTIME)`,
/// `ASN1_SEQUENCE_OF(responses, OCSP_SINGLERESP)` and
/// `ASN1_EXP_SEQUENCE_OF_OPT(responseExtensions, X509_EXTENSION, 1)`.
static OCSP_RESPDATA_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"responderId".as_ptr(),
        item: OCSP_RESPID_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"producedAt".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 32,
        field_name: c"responses".as_ptr(),
        item: OCSP_SINGLERESP_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 40,
        field_name: c"responseExtensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `OCSP_RESPDATA_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_RESPDATA)` at
/// `crypto/ocsp/ocsp_asn.c:109`.
static OCSP_RESPDATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_RESPDATA_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspRespData>() as c_long,
    sname: c"OCSP_RESPDATA".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_RESPDATA_it(void)` — `include/openssl/ocsp.h.in:365`.
#[no_mangle]
pub extern "C" fn OCSP_RESPDATA_it() -> *const Asn1Item {
    &OCSP_RESPDATA_ITEM
}

/// `OCSP_RESPDATA *OCSP_RESPDATA_new(void)` — `crypto/ocsp/ocsp_asn.c:111`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_RESPDATA)`.
#[no_mangle]
pub extern "C" fn OCSP_RESPDATA_new() -> *mut OcspRespData {
    // SAFETY: `OCSP_RESPDATA_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_RESPDATA_it()).cast::<OcspRespData>() }
}

/// `void OCSP_RESPDATA_free(OCSP_RESPDATA *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPDATA_free(a: *mut OcspRespData) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_RESPDATA_it()) }
}

/// `OCSP_RESPDATA *d2i_OCSP_RESPDATA(OCSP_RESPDATA **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_RESPDATA(
    a: *mut *mut OcspRespData,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspRespData {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_RESPDATA_it()).cast::<OcspRespData>() }
}

/// `int i2d_OCSP_RESPDATA(const OCSP_RESPDATA *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_RESPDATA(
    a: *const OcspRespData,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_RESPDATA_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_BASICRESP — `ASN1_SEQUENCE(OCSP_BASICRESP)` (`crypto/ocsp/ocsp_asn.c:113-118`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_BASICRESP_seq_tt` — `ASN1_SEQUENCE(OCSP_BASICRESP)`: `ASN1_EMBED(tbsResponseData,
/// OCSP_RESPDATA)`, `ASN1_EMBED(signatureAlgorithm, X509_ALGOR)`, `ASN1_SIMPLE(signature,
/// ASN1_BIT_STRING)` and `ASN1_EXP_SEQUENCE_OF_OPT(certs, X509, 0)`.
static OCSP_BASICRESP_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"tbsResponseData".as_ptr(),
        item: OCSP_RESPDATA_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 48,
        field_name: c"signatureAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 64,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 72,
        field_name: c"certs".as_ptr(),
        item: X509_it as *mut c_void,
    },
];

/// `OCSP_BASICRESP_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_BASICRESP)` at
/// `crypto/ocsp/ocsp_asn.c:118`.
static OCSP_BASICRESP_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_BASICRESP_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspBasicResp>() as c_long,
    sname: c"OCSP_BASICRESP".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_BASICRESP_it(void)` — `include/openssl/ocsp.h.in:364`.
#[no_mangle]
pub extern "C" fn OCSP_BASICRESP_it() -> *const Asn1Item {
    &OCSP_BASICRESP_ITEM
}

/// `OCSP_BASICRESP *OCSP_BASICRESP_new(void)` — `crypto/ocsp/ocsp_asn.c:120`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_BASICRESP)`.
#[no_mangle]
pub extern "C" fn OCSP_BASICRESP_new() -> *mut OcspBasicResp {
    // SAFETY: `OCSP_BASICRESP_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_BASICRESP_it()).cast::<OcspBasicResp>() }
}

/// `void OCSP_BASICRESP_free(OCSP_BASICRESP *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_BASICRESP_free(a: *mut OcspBasicResp) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_BASICRESP_it()) }
}

/// `OCSP_BASICRESP *d2i_OCSP_BASICRESP(OCSP_BASICRESP **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_BASICRESP(
    a: *mut *mut OcspBasicResp,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspBasicResp {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_BASICRESP_it()).cast::<OcspBasicResp>() }
}

/// `int i2d_OCSP_BASICRESP(const OCSP_BASICRESP *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_BASICRESP(
    a: *const OcspBasicResp,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_BASICRESP_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_CRLID — `ASN1_SEQUENCE(OCSP_CRLID)` (`crypto/ocsp/ocsp_asn.c:122-126`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_CRLID_seq_tt` — `ASN1_SEQUENCE(OCSP_CRLID)`: `ASN1_EXP_OPT(crlUrl, ASN1_IA5STRING, 0)`,
/// `ASN1_EXP_OPT(crlNum, ASN1_INTEGER, 1)` and `ASN1_EXP_OPT(crlTime, ASN1_GENERALIZEDTIME, 2)`.
static OCSP_CRLID_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"crlUrl".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"crlNum".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"crlTime".as_ptr(),
        item: ASN1_GENERALIZEDTIME_it as *mut c_void,
    },
];

/// `OCSP_CRLID_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_CRLID)` at `crypto/ocsp/ocsp_asn.c:126`.
static OCSP_CRLID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_CRLID_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspCrlId>() as c_long,
    sname: c"OCSP_CRLID".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_CRLID_it(void)` — `include/openssl/ocsp.h.in:374`.
#[no_mangle]
pub extern "C" fn OCSP_CRLID_it() -> *const Asn1Item {
    &OCSP_CRLID_ITEM
}

/// `OCSP_CRLID *OCSP_CRLID_new(void)` — `crypto/ocsp/ocsp_asn.c:128`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_CRLID)`.
#[no_mangle]
pub extern "C" fn OCSP_CRLID_new() -> *mut OcspCrlId {
    // SAFETY: `OCSP_CRLID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_CRLID_it()).cast::<OcspCrlId>() }
}

/// `void OCSP_CRLID_free(OCSP_CRLID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_CRLID_free(a: *mut OcspCrlId) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_CRLID_it()) }
}

/// `OCSP_CRLID *d2i_OCSP_CRLID(OCSP_CRLID **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_CRLID(
    a: *mut *mut OcspCrlId,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspCrlId {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_CRLID_it()).cast::<OcspCrlId>() }
}

/// `int i2d_OCSP_CRLID(const OCSP_CRLID *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_CRLID(a: *const OcspCrlId, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_CRLID_it()) }
}

// ---------------------------------------------------------------------------------------------
// OCSP_SERVICELOC — `ASN1_SEQUENCE(OCSP_SERVICELOC)` (`crypto/ocsp/ocsp_asn.c:130-133`)
// ---------------------------------------------------------------------------------------------

/// `OCSP_SERVICELOC_seq_tt` — `ASN1_SEQUENCE(OCSP_SERVICELOC)`: `ASN1_SIMPLE(issuer, X509_NAME)`
/// and `ASN1_SEQUENCE_OF_OPT(locator, ACCESS_DESCRIPTION)`.
static OCSP_SERVICELOC_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"locator".as_ptr(),
        item: ACCESS_DESCRIPTION_it as *mut c_void,
    },
];

/// `OCSP_SERVICELOC_it`'s descriptor — `ASN1_SEQUENCE_END(OCSP_SERVICELOC)` at
/// `crypto/ocsp/ocsp_asn.c:133`.
static OCSP_SERVICELOC_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OCSP_SERVICELOC_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OcspServiceLoc>() as c_long,
    sname: c"OCSP_SERVICELOC".as_ptr(),
};

/// `const ASN1_ITEM *OCSP_SERVICELOC_it(void)` — `include/openssl/ocsp.h.in:375`.
#[no_mangle]
pub extern "C" fn OCSP_SERVICELOC_it() -> *const Asn1Item {
    &OCSP_SERVICELOC_ITEM
}

/// `OCSP_SERVICELOC *OCSP_SERVICELOC_new(void)` — `crypto/ocsp/ocsp_asn.c:135`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OCSP_SERVICELOC)`.
#[no_mangle]
pub extern "C" fn OCSP_SERVICELOC_new() -> *mut OcspServiceLoc {
    // SAFETY: `OCSP_SERVICELOC_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OCSP_SERVICELOC_it()).cast::<OcspServiceLoc>() }
}

/// `void OCSP_SERVICELOC_free(OCSP_SERVICELOC *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OCSP_SERVICELOC_free(a: *mut OcspServiceLoc) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OCSP_SERVICELOC_it()) }
}

/// `OCSP_SERVICELOC *d2i_OCSP_SERVICELOC(OCSP_SERVICELOC **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OCSP_SERVICELOC(
    a: *mut *mut OcspServiceLoc,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OcspServiceLoc {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OCSP_SERVICELOC_it()).cast::<OcspServiceLoc>() }
}

/// `int i2d_OCSP_SERVICELOC(const OCSP_SERVICELOC *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OCSP_SERVICELOC(
    a: *const OcspServiceLoc,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OCSP_SERVICELOC_it()) }
}
