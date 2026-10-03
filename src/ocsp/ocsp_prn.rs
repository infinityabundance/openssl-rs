//! `crypto/ocsp/ocsp_prn.c` — the OCSP text printers and the three name tables. Phase 12.6.
//!
//! `crypto/ocsp/ocsp_prn.c` is 251 lines and exports five names, in source order:
//!
//! * `OCSP_response_status_str` (`:49-60`), `OCSP_cert_status_str` (`:62-70`),
//!   `OCSP_crl_reason_str` (`:72-87`) — the three `(value, name)` tables, each answering
//!   `(UNKNOWN)` for an unlisted value.
//! * [`OCSP_REQUEST_print`] (`:89-132`) and [`OCSP_RESPONSE_print`] (`:134-251`) — the request and
//!   response transcripts, driven by the static [`ocsp_certid_print`] helper (`:17-31`).
//!
//! `crypto/ocsp/ocsp_prn.c` has **no** `ERR_raise` and no declared raise coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::asn1::prim::{ASN1_ENUMERATED_get, ASN1_INTEGER_get};
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT, i2a_ASN1_STRING};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::ocsp::ocsp_asn::{
    OCSP_BASICRESP_free, OcspBasicResp, OcspCertId, OcspCertStatus, OcspRequest, OcspRespid,
    OcspResponse, OcspRevokedInfo, OcspSingleResp,
};
use crate::ocsp::ocsp_cl::OCSP_response_get1_basic;
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{NID_id_pkix_OCSP_basic, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::t_x509::{X509_print, X509_signature_print};
use crate::x509::v3_prn::X509V3_extensions_print;
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::x_x509::X509;

/// `OCSP_RESPONSE_STATUS_SUCCESSFUL` — `include/openssl/ocsp.h.in:104`.
const OCSP_RESPONSE_STATUS_SUCCESSFUL: c_long = 0;
/// `OCSP_RESPONSE_STATUS_MALFORMEDREQUEST` — `include/openssl/ocsp.h.in:105`.
const OCSP_RESPONSE_STATUS_MALFORMEDREQUEST: c_long = 1;
/// `OCSP_RESPONSE_STATUS_INTERNALERROR` — `include/openssl/ocsp.h.in:106`.
const OCSP_RESPONSE_STATUS_INTERNALERROR: c_long = 2;
/// `OCSP_RESPONSE_STATUS_TRYLATER` — `include/openssl/ocsp.h.in:107`.
const OCSP_RESPONSE_STATUS_TRYLATER: c_long = 3;
/// `OCSP_RESPONSE_STATUS_SIGREQUIRED` — `include/openssl/ocsp.h.in:108`.
const OCSP_RESPONSE_STATUS_SIGREQUIRED: c_long = 5;
/// `OCSP_RESPONSE_STATUS_UNAUTHORIZED` — `include/openssl/ocsp.h.in:109`.
const OCSP_RESPONSE_STATUS_UNAUTHORIZED: c_long = 6;

/// `V_OCSP_CERTSTATUS_GOOD` — `include/openssl/ocsp.h.in:124`.
const V_OCSP_CERTSTATUS_GOOD: c_long = 0;
/// `V_OCSP_CERTSTATUS_REVOKED` — `include/openssl/ocsp.h.in:125`.
const V_OCSP_CERTSTATUS_REVOKED: c_long = 1;
/// `V_OCSP_CERTSTATUS_UNKNOWN` — `include/openssl/ocsp.h.in:126`.
const V_OCSP_CERTSTATUS_UNKNOWN: c_long = 2;

/// `OCSP_REVOKED_STATUS_UNSPECIFIED` — `include/openssl/ocsp.h.in:51`.
const OCSP_REVOKED_STATUS_UNSPECIFIED: c_long = 0;
/// `OCSP_REVOKED_STATUS_KEYCOMPROMISE` — `include/openssl/ocsp.h.in:52`.
const OCSP_REVOKED_STATUS_KEYCOMPROMISE: c_long = 1;
/// `OCSP_REVOKED_STATUS_CACOMPROMISE` — `include/openssl/ocsp.h.in:53`.
const OCSP_REVOKED_STATUS_CACOMPROMISE: c_long = 2;
/// `OCSP_REVOKED_STATUS_AFFILIATIONCHANGED` — `include/openssl/ocsp.h.in:54`.
const OCSP_REVOKED_STATUS_AFFILIATIONCHANGED: c_long = 3;
/// `OCSP_REVOKED_STATUS_SUPERSEDED` — `include/openssl/ocsp.h.in:55`.
const OCSP_REVOKED_STATUS_SUPERSEDED: c_long = 4;
/// `OCSP_REVOKED_STATUS_CESSATIONOFOPERATION` — `include/openssl/ocsp.h.in:56`.
const OCSP_REVOKED_STATUS_CESSATIONOFOPERATION: c_long = 5;
/// `OCSP_REVOKED_STATUS_CERTIFICATEHOLD` — `include/openssl/ocsp.h.in:57`.
const OCSP_REVOKED_STATUS_CERTIFICATEHOLD: c_long = 6;
/// `OCSP_REVOKED_STATUS_REMOVEFROMCRL` — `include/openssl/ocsp.h.in:58`.
const OCSP_REVOKED_STATUS_REMOVEFROMCRL: c_long = 8;
/// `OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN` — `include/openssl/ocsp.h.in:59`.
const OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN: c_long = 9;
/// `OCSP_REVOKED_STATUS_AACOMPROMISE` — `include/openssl/ocsp.h.in:60`.
const OCSP_REVOKED_STATUS_AACOMPROMISE: c_long = 10;

/// `V_OCSP_RESPID_NAME` — `include/openssl/ocsp.h.in:113`.
const V_OCSP_RESPID_NAME: c_int = 0;
/// `V_OCSP_RESPID_KEY` — `include/openssl/ocsp.h.in:114`.
const V_OCSP_RESPID_KEY: c_int = 1;

/// `static const char *do_table2string(long s, const OCSP_TBLSTR *ts, size_t len)` —
/// `crypto/ocsp/ocsp_prn.c:38-45`.
///
/// The first entry whose value equals `s`, or the literal `(UNKNOWN)`.
fn do_table2string(s: c_long, ts: &[(c_long, *const c_char)]) -> *const c_char {
    for &(t, m) in ts {
        if t == s {
            return m;
        }
    }
    c"(UNKNOWN)".as_ptr()
}

/// `static int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent)` —
/// `crypto/ocsp/ocsp_prn.c:17-31`.
///
/// The `Certificate ID:` block: hash algorithm, issuer-name hash, issuer-key hash and serial,
/// each on its own `indent`-spaced line.
///
/// # Safety
/// `bp` must be a live BIO; `a` must be a live `OCSP_CERTID`.
unsafe fn ocsp_certid_print(bp: *mut Bio, a: *mut OcspCertId, indent: c_int) -> c_int {
    // SAFETY: `bp` is live and `a` is live per the contract; every printed member is the id's own.
    unsafe {
        BIO_printf(bp, c"%*sCertificate ID:\n".as_ptr(), indent, c"".as_ptr());
        let indent = indent + 2;
        BIO_printf(bp, c"%*sHash Algorithm: ".as_ptr(), indent, c"".as_ptr());
        i2a_ASN1_OBJECT(bp, (*a).hashAlgorithm.algorithm);
        BIO_printf(
            bp,
            c"\n%*sIssuer Name Hash: ".as_ptr(),
            indent,
            c"".as_ptr(),
        );
        i2a_ASN1_STRING(bp, &(*a).issuerNameHash, 0);
        BIO_printf(bp, c"\n%*sIssuer Key Hash: ".as_ptr(), indent, c"".as_ptr());
        i2a_ASN1_STRING(bp, &(*a).issuerKeyHash, 0);
        BIO_printf(bp, c"\n%*sSerial Number: ".as_ptr(), indent, c"".as_ptr());
        i2a_ASN1_INTEGER(bp, &(*a).serialNumber);
        BIO_printf(bp, c"\n".as_ptr());
        1
    }
}

/// `const char *OCSP_response_status_str(long s)` — `crypto/ocsp/ocsp_prn.c:49-60`.
///
/// # Safety
/// This function is safe to call for any `s`.
#[no_mangle]
pub extern "C" fn OCSP_response_status_str(s: c_long) -> *const c_char {
    let table: [(c_long, *const c_char); 6] = [
        (OCSP_RESPONSE_STATUS_SUCCESSFUL, c"successful".as_ptr()),
        (
            OCSP_RESPONSE_STATUS_MALFORMEDREQUEST,
            c"malformedrequest".as_ptr(),
        ),
        (
            OCSP_RESPONSE_STATUS_INTERNALERROR,
            c"internalerror".as_ptr(),
        ),
        (OCSP_RESPONSE_STATUS_TRYLATER, c"trylater".as_ptr()),
        (OCSP_RESPONSE_STATUS_SIGREQUIRED, c"sigrequired".as_ptr()),
        (OCSP_RESPONSE_STATUS_UNAUTHORIZED, c"unauthorized".as_ptr()),
    ];
    do_table2string(s, &table)
}

/// `const char *OCSP_cert_status_str(long s)` — `crypto/ocsp/ocsp_prn.c:62-70`.
///
/// # Safety
/// This function is safe to call for any `s`.
#[no_mangle]
pub extern "C" fn OCSP_cert_status_str(s: c_long) -> *const c_char {
    let table: [(c_long, *const c_char); 3] = [
        (V_OCSP_CERTSTATUS_GOOD, c"good".as_ptr()),
        (V_OCSP_CERTSTATUS_REVOKED, c"revoked".as_ptr()),
        (V_OCSP_CERTSTATUS_UNKNOWN, c"unknown".as_ptr()),
    ];
    do_table2string(s, &table)
}

/// `const char *OCSP_crl_reason_str(long s)` — `crypto/ocsp/ocsp_prn.c:72-87`.
///
/// # Safety
/// This function is safe to call for any `s`.
#[no_mangle]
pub extern "C" fn OCSP_crl_reason_str(s: c_long) -> *const c_char {
    let table: [(c_long, *const c_char); 10] = [
        (OCSP_REVOKED_STATUS_UNSPECIFIED, c"unspecified".as_ptr()),
        (OCSP_REVOKED_STATUS_KEYCOMPROMISE, c"keyCompromise".as_ptr()),
        (OCSP_REVOKED_STATUS_CACOMPROMISE, c"cACompromise".as_ptr()),
        (
            OCSP_REVOKED_STATUS_AFFILIATIONCHANGED,
            c"affiliationChanged".as_ptr(),
        ),
        (OCSP_REVOKED_STATUS_SUPERSEDED, c"superseded".as_ptr()),
        (
            OCSP_REVOKED_STATUS_CESSATIONOFOPERATION,
            c"cessationOfOperation".as_ptr(),
        ),
        (
            OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
            c"certificateHold".as_ptr(),
        ),
        (OCSP_REVOKED_STATUS_REMOVEFROMCRL, c"removeFromCRL".as_ptr()),
        (
            OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN,
            c"privilegeWithdrawn".as_ptr(),
        ),
        (OCSP_REVOKED_STATUS_AACOMPROMISE, c"aACompromise".as_ptr()),
    ];
    do_table2string(s, &table)
}

/// `int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST *o, unsigned long flags)` —
/// `crypto/ocsp/ocsp_prn.c:89-132`.
///
/// Prints the version, the optional requestor name, every request entry (with its `CertID` and
/// single extensions), the request extensions, and the optional signature block. Every write is a
/// refusal arm: a non-positive answer aborts with 0.
///
/// # Safety
/// `bp` must be a live BIO; `o` must be a live `OCSP_REQUEST`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_REQUEST_print(
    bp: *mut Bio,
    o: *mut OcspRequest,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `bp` and `o` are live per the contract; each callee obeys its own contract.
    unsafe {
        let inf = core::ptr::addr_of_mut!((*o).tbsRequest);
        let sig = (*o).optionalSignature;

        if BIO_write(bp, c"OCSP Request Data:\n".as_ptr().cast::<c_void>(), 19) <= 0 {
            return 0;
        }
        let l = ASN1_INTEGER_get((*inf).version);
        if BIO_printf(bp, c"    Version: %lu (0x%lx)".as_ptr(), l + 1, l) <= 0 {
            return 0;
        }
        if !(*inf).requestorName.is_null() {
            if BIO_write(bp, c"\n    Requestor Name: ".as_ptr().cast::<c_void>(), 21) <= 0 {
                return 0;
            }
            GENERAL_NAME_print(bp, (*inf).requestorName);
        }
        if BIO_write(bp, c"\n    Requestor List:\n".as_ptr().cast::<c_void>(), 21) <= 0 {
            return 0;
        }
        let mut i = 0;
        while i < OPENSSL_sk_num((*inf).requestList) {
            let one =
                OPENSSL_sk_value((*inf).requestList, i).cast::<crate::ocsp::ocsp_asn::OcspOneReq>();
            let cid = (*one).reqCert;
            ocsp_certid_print(bp, cid, 8);
            if X509V3_extensions_print(
                bp,
                c"Request Single Extensions".as_ptr(),
                (*one).singleRequestExtensions,
                flags,
                8,
            ) == 0
            {
                return 0;
            }
            i += 1;
        }
        if X509V3_extensions_print(
            bp,
            c"Request Extensions".as_ptr(),
            (*inf).requestExtensions,
            flags,
            4,
        ) == 0
        {
            return 0;
        }
        if !sig.is_null() {
            X509_signature_print(
                bp,
                core::ptr::addr_of!((*sig).signatureAlgorithm),
                (*sig).signature,
            );
            let mut i = 0;
            while i < OPENSSL_sk_num((*sig).certs) {
                let x = OPENSSL_sk_value((*sig).certs, i).cast::<X509>();
                X509_print(bp, x);
                PEM_write_bio_X509(bp, x);
                i += 1;
            }
        }
        1
    }
}

/// `int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE *o, unsigned long flags)` —
/// `crypto/ocsp/ocsp_prn.c:134-251`.
///
/// Prints the response status, the response type, and — for a basic response — the version, the
/// responder id, `producedAt`, every `SingleResponse`, the response extensions and the signature
/// block. A response with no body answers 1 after the status line; an unknown response type stops
/// after the type. The unpacked basic response is freed on every path.
///
/// # Safety
/// `bp` must be a live BIO; `o` must be a live `OCSP_RESPONSE`.
#[no_mangle]
pub unsafe extern "C" fn OCSP_RESPONSE_print(
    bp: *mut Bio,
    o: *mut OcspResponse,
    flags: c_ulong,
) -> c_int {
    // SAFETY: `bp` and `o` are live per the contract; each callee obeys its own contract.
    unsafe {
        let mut ret = 0;
        let mut br: *mut OcspBasicResp = core::ptr::null_mut();
        let rb = (*o).responseBytes;

        'body: {
            if BIO_puts(bp, c"OCSP Response Data:\n".as_ptr()) <= 0 {
                break 'body;
            }
            let l = ASN1_ENUMERATED_get((*o).responseStatus);
            if BIO_printf(
                bp,
                c"    OCSP Response Status: %s (0x%lx)\n".as_ptr(),
                OCSP_response_status_str(l),
                l,
            ) <= 0
            {
                break 'body;
            }
            if rb.is_null() {
                OCSP_BASICRESP_free(br);
                return 1;
            }
            if BIO_puts(bp, c"    Response Type: ".as_ptr()) <= 0 {
                break 'body;
            }
            if i2a_ASN1_OBJECT(bp, (*rb).responseType) <= 0 {
                break 'body;
            }
            if OBJ_obj2nid((*rb).responseType) != NID_id_pkix_OCSP_basic {
                BIO_puts(bp, c" (unknown response type)\n".as_ptr());
                OCSP_BASICRESP_free(br);
                return 1;
            }

            br = OCSP_response_get1_basic(o);
            if br.is_null() {
                break 'body;
            }
            let rd = core::ptr::addr_of_mut!((*br).tbsResponseData);
            let l = ASN1_INTEGER_get((*rd).version);
            if BIO_printf(bp, c"\n    Version: %lu (0x%lx)\n".as_ptr(), l + 1, l) <= 0 {
                break 'body;
            }
            if BIO_puts(bp, c"    Responder Id: ".as_ptr()) <= 0 {
                break 'body;
            }

            let rid: *mut OcspRespid = core::ptr::addr_of_mut!((*rd).responderId);
            match (*rid).type_ {
                V_OCSP_RESPID_NAME => {
                    X509_NAME_print_ex(bp, (*rid).value.byName, 0, XN_FLAG_ONELINE);
                }
                V_OCSP_RESPID_KEY => {
                    i2a_ASN1_STRING(bp, (*rid).value.byKey, 0);
                }
                _ => {}
            }

            if BIO_printf(bp, c"\n    Produced At: ".as_ptr()) <= 0 {
                break 'body;
            }
            if ASN1_GENERALIZEDTIME_print(bp, (*rd).producedAt) == 0 {
                break 'body;
            }
            if BIO_printf(bp, c"\n    Responses:\n".as_ptr()) <= 0 {
                break 'body;
            }
            let mut i = 0;
            while i < OPENSSL_sk_num((*rd).responses) {
                let single = OPENSSL_sk_value((*rd).responses, i).cast::<OcspSingleResp>();
                if single.is_null() {
                    i += 1;
                    continue;
                }
                let cid = (*single).certId;
                if ocsp_certid_print(bp, cid, 4) <= 0 {
                    break 'body;
                }
                let cst: *mut OcspCertStatus = (*single).certStatus;
                if BIO_printf(
                    bp,
                    c"    Cert Status: %s".as_ptr(),
                    OCSP_cert_status_str((*cst).type_ as c_long),
                ) <= 0
                {
                    break 'body;
                }
                if (*cst).type_ == V_OCSP_CERTSTATUS_REVOKED as c_int {
                    let rev: *mut OcspRevokedInfo = (*cst).value.revoked;
                    if BIO_printf(bp, c"\n    Revocation Time: ".as_ptr()) <= 0 {
                        break 'body;
                    }
                    if ASN1_GENERALIZEDTIME_print(bp, (*rev).revocationTime) == 0 {
                        break 'body;
                    }
                    if !(*rev).revocationReason.is_null() {
                        let l = ASN1_ENUMERATED_get((*rev).revocationReason);
                        if BIO_printf(
                            bp,
                            c"\n    Revocation Reason: %s (0x%lx)".as_ptr(),
                            OCSP_crl_reason_str(l),
                            l,
                        ) <= 0
                        {
                            break 'body;
                        }
                    }
                }
                if BIO_printf(bp, c"\n    This Update: ".as_ptr()) <= 0 {
                    break 'body;
                }
                if ASN1_GENERALIZEDTIME_print(bp, (*single).thisUpdate) == 0 {
                    break 'body;
                }
                if !(*single).nextUpdate.is_null() {
                    if BIO_printf(bp, c"\n    Next Update: ".as_ptr()) <= 0 {
                        break 'body;
                    }
                    if ASN1_GENERALIZEDTIME_print(bp, (*single).nextUpdate) == 0 {
                        break 'body;
                    }
                }
                if BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) <= 0 {
                    break 'body;
                }
                if X509V3_extensions_print(
                    bp,
                    c"Response Single Extensions".as_ptr(),
                    (*single).singleExtensions,
                    flags,
                    8,
                ) == 0
                {
                    break 'body;
                }
                if BIO_write(bp, c"\n".as_ptr().cast::<c_void>(), 1) <= 0 {
                    break 'body;
                }
                i += 1;
            }
            if X509V3_extensions_print(
                bp,
                c"Response Extensions".as_ptr(),
                (*rd).responseExtensions,
                flags,
                4,
            ) == 0
            {
                break 'body;
            }
            if X509_signature_print(
                bp,
                core::ptr::addr_of!((*br).signatureAlgorithm),
                (*br).signature,
            ) <= 0
            {
                break 'body;
            }

            let mut i = 0;
            while i < OPENSSL_sk_num((*br).certs) {
                let x = OPENSSL_sk_value((*br).certs, i).cast::<X509>();
                X509_print(bp, x);
                PEM_write_bio_X509(bp, x);
                i += 1;
            }

            ret = 1;
        }

        OCSP_BASICRESP_free(br);
        ret
    }
}
