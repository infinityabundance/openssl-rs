//! `crypto/ocsp/ocsp_lib.c` — the `OCSP_CERTID` builder and the two id comparators. Phase 11.2b's
//! first OCSP-function unit, landed as an **internal** transcription: every name here is
//! `pub(crate)` and none carries `#[no_mangle]`, because the `OCSP_*` exports are Phase 12's.
//!
//! `crypto/ocsp/ocsp_lib.c` is 113 lines. The five requested names, in source order:
//!
//! * [`OCSP_cert_to_id`] (`:22-40`) — pick the issuer name and serial from `subject` (or from
//!   `issuer` when `subject` is NULL) and delegate to [`OCSP_cert_id_new`].
//! * [`OCSP_cert_id_new`] (`:42-90`) — allocate the `OCSP_CERTID`, install the digest algorithm
//!   `X509_ALGOR` (with an explicit `NULL` parameter), hash the issuer name and the issuer key
//!   bit-string, and copy the serial.
//! * [`OCSP_id_issuer_cmp`] (`:92-102`) — algorithm OID, issuer-name hash, issuer-key hash.
//! * [`OCSP_id_cmp`] (`:104-111`) — the above, then the serial.
//! * `OCSP_CERTID_dup` (`:113`, `IMPLEMENT_ASN1_DUP_FUNCTION(OCSP_CERTID)`) — the ASN.1 duplicate.
//!
//! The sibling `OCSP_cert_to_id`/`OCSP_cert_id_new` are reached by the Phase-11 verification
//! engine's OCSP arm (`X509_vfy.c`'s `check_cert_ocsp_resp`). `OCSP_CERTID_dup` awaits Phase 12's
//! exports and carries its own item-level allow.
//!
//! ## The raise sites
//!
//! `crypto/ocsp/ocsp_lib.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! two coordinates (`:59` `OCSP_R_UNKNOWN_NID`, `:86` `OCSP_R_DIGEST_ERR`) are **declared locally**
//! in the `err_sites::ErrSite` shape, as `v3_ocsp.rs` does. Both reasons are read from the
//! authority's own `include/openssl/ocsperr.h` (`120`, `102`) against `ERR_LIB_OCSP` = 39
//! (`include/openssl/err.h.in:104`).
//!
//! **Withheld by name**: none of the requested names. The rest of `ocsp_lib.c` (the serial/name
//! getters and the `OCSP_cert_to_id`-adjacent `OCSP_id_get0_info`) is not part of this pull-forward.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_uint, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_type::ASN1_TYPE_new;
use crate::asn1::layout::{Asn1String, V_ASN1_NULL};
use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_OBJECT_free};
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_OCTET_STRING_set, ASN1_STRING_copy};
use crate::asn1::x_algor::X509Algor;
use crate::evp::digest::{EVP_Digest, EVP_MD_get_type, EvpMd};
use crate::evp::legacy_sha::EVP_sha1;
use crate::ocsp::ocsp_asn::{OCSP_CERTID_free, OCSP_CERTID_it, OCSP_CERTID_new, OcspCertId};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{NID_undef, OBJ_cmp, OBJ_nid2obj};
use crate::x509::x509_cmp::{X509_get0_serialNumber, X509_get_issuer_name, X509_get_subject_name};
use crate::x509::x_all::X509_NAME_digest;
use crate::x509::x_name::X509Name;
use crate::x509::x_pubkey::X509_get0_pubkey_bitstr;
use crate::x509::x_x509::X509;

/// `ERR_LIB_OCSP` — `include/openssl/err.h.in:104`.
const ERR_LIB_OCSP: c_int = 39;
/// `OCSP_R_UNKNOWN_NID` — `include/openssl/ocsperr.h:47`.
const OCSP_R_UNKNOWN_NID: c_int = 120;
/// `OCSP_R_DIGEST_ERR` — `include/openssl/ocsperr.h:25`.
const OCSP_R_DIGEST_ERR: c_int = 102;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`: the `md` scratch array's width.
const EVP_MAX_MD_SIZE: usize = 64;

/// One `ocsp_lib.c` raise coordinate, declared locally (see the module doc).
const fn ocsp_lib_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ocsp/ocsp_lib.c",
        line,
        func,
        lib: ERR_LIB_OCSP,
        reason,
        dynamic_reason: false,
    }
}

/// `OCSP_cert_id_new`'s unknown-digest refusal at `ocsp_lib.c:59`.
const OCSP_LIB_59: ErrSite = ocsp_lib_site(59, c"OCSP_cert_id_new", OCSP_R_UNKNOWN_NID);
/// `OCSP_cert_id_new`'s `digerr:` label at `ocsp_lib.c:86`.
const OCSP_LIB_86: ErrSite = ocsp_lib_site(86, c"OCSP_cert_id_new", OCSP_R_DIGEST_ERR);

// ---------------------------------------------------------------------------------------------
// The functions
// ---------------------------------------------------------------------------------------------

/// `OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject, const X509 *issuer)` —
/// `crypto/ocsp/ocsp_lib.c:22-40`.
///
/// `dgst` NULL means SHA-1. With `subject` non-NULL the issuer name and serial come from it,
/// otherwise the issuer name is the issuer's own subject and the serial is NULL.
///
/// # Safety
/// `subject` and `issuer` must be NULL or live `X509`s; `issuer` must be live so its public-key
/// bit string can be read, and `dgst` must be NULL or a live `EVP_MD`.
pub(crate) unsafe extern "C" fn OCSP_cert_to_id(
    dgst: *const EvpMd,
    subject: *const X509,
    issuer: *const X509,
) -> *mut OcspCertId {
    // SAFETY: every pointer is NULL-or-live per the contract; the getters are read-only.
    unsafe {
        let dgst = if dgst.is_null() { EVP_sha1() } else { dgst };
        let (iname, serial): (*const X509Name, *const Asn1String) = if !subject.is_null() {
            (
                X509_get_issuer_name(subject),
                X509_get0_serialNumber(subject),
            )
        } else {
            (X509_get_subject_name(issuer), ptr::null())
        };
        let ikey = X509_get0_pubkey_bitstr(issuer) as *const Asn1String;
        OCSP_cert_id_new(dgst, iname, ikey, serial)
    }
}

/// `OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst, const X509_NAME *issuerName, const
/// ASN1_BIT_STRING *issuerKey, const ASN1_INTEGER *serialNumber)` — `crypto/ocsp/ocsp_lib.c:42-90`.
///
/// Builds a fresh `OCSP_CERTID`: the hash `X509_ALGOR`, the digest of `issuerName` into
/// `issuerNameHash`, the digest of `issuerKey`'s content octets (tag and length excluded) into
/// `issuerKeyHash`, and a copy of `serialNumber` when non-NULL. Every failure frees the partial id
/// and answers NULL; the name-digest arm additionally raises `OCSP_R_DIGEST_ERR`.
///
/// # Safety
/// `dgst` must be a live `EVP_MD`; `issuerName`, `issuerKey` and `serialNumber` must be live where
/// non-NULL, and `issuerKey`'s content octets must be readable for its length.
pub(crate) unsafe extern "C" fn OCSP_cert_id_new(
    dgst: *const EvpMd,
    issuerName: *const X509Name,
    issuerKey: *const Asn1String,
    serialNumber: *const Asn1String,
) -> *mut OcspCertId {
    let mut i: c_uint = 0;
    let mut md = [0u8; EVP_MAX_MD_SIZE];

    // SAFETY: `dgst` is live per the contract; the getters and setters obey their own contracts.
    unsafe {
        let cid = OCSP_CERTID_new();
        if cid.is_null() {
            return ptr::null_mut();
        }

        let digerr: bool;
        'body: {
            let alg: *mut X509Algor = &mut (*cid).hashAlgorithm;
            ASN1_OBJECT_free((*alg).algorithm);

            let nid = EVP_MD_get_type(dgst);
            if nid == NID_undef {
                raise_site(&OCSP_LIB_59);
                digerr = false;
                break 'body;
            }
            (*alg).algorithm = OBJ_nid2obj(nid);
            if (*alg).algorithm.is_null() {
                digerr = false;
                break 'body;
            }
            (*alg).parameter = ASN1_TYPE_new();
            if (*alg).parameter.is_null() {
                digerr = false;
                break 'body;
            }
            (*(*alg).parameter).type_ = V_ASN1_NULL;

            if X509_NAME_digest(issuerName, dgst, md.as_mut_ptr(), &mut i) == 0 {
                digerr = true;
                break 'body;
            }
            if ASN1_OCTET_STRING_set(&mut (*cid).issuerNameHash, md.as_ptr(), i as c_int) == 0 {
                digerr = false;
                break 'body;
            }

            // Calculate the issuerKey hash, excluding tag and length.
            if EVP_Digest(
                (*issuerKey).data.cast::<c_void>(),
                (*issuerKey).length as usize,
                md.as_mut_ptr(),
                &mut i,
                dgst,
                ptr::null_mut(),
            ) == 0
            {
                digerr = false;
                break 'body;
            }
            if ASN1_OCTET_STRING_set(&mut (*cid).issuerKeyHash, md.as_ptr(), i as c_int) == 0 {
                digerr = false;
                break 'body;
            }

            if !serialNumber.is_null()
                && ASN1_STRING_copy(&mut (*cid).serialNumber, serialNumber) == 0
            {
                digerr = false;
                break 'body;
            }
            return cid;
        }

        if digerr {
            raise_site(&OCSP_LIB_86);
        }
        OCSP_CERTID_free(cid);
        ptr::null_mut()
    }
}

/// `int OCSP_id_issuer_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)` —
/// `crypto/ocsp/ocsp_lib.c:92-102`.
///
/// Compares the hash algorithm OID, then the issuer-name hash, then the issuer-key hash, in that
/// order, and answers the first non-zero comparison.
///
/// # Safety
/// `a` and `b` must be live `OCSP_CERTID`s.
pub(crate) unsafe extern "C" fn OCSP_id_issuer_cmp(
    a: *const OcspCertId,
    b: *const OcspCertId,
) -> c_int {
    // SAFETY: `a` and `b` are live per the contract; the comparators accept live operands.
    unsafe {
        let mut ret = OBJ_cmp((*a).hashAlgorithm.algorithm, (*b).hashAlgorithm.algorithm);
        if ret != 0 {
            return ret;
        }
        ret = ASN1_OCTET_STRING_cmp(&(*a).issuerNameHash, &(*b).issuerNameHash);
        if ret != 0 {
            return ret;
        }
        ASN1_OCTET_STRING_cmp(&(*a).issuerKeyHash, &(*b).issuerKeyHash)
    }
}

/// `int OCSP_id_cmp(const OCSP_CERTID *a, const OCSP_CERTID *b)` — `crypto/ocsp/ocsp_lib.c:104-111`.
///
/// [`OCSP_id_issuer_cmp`] first, then the serial numbers.
///
/// # Safety
/// `a` and `b` must be live `OCSP_CERTID`s.
pub(crate) unsafe extern "C" fn OCSP_id_cmp(a: *const OcspCertId, b: *const OcspCertId) -> c_int {
    // SAFETY: `a` and `b` are live per the contract; the comparators accept live operands.
    unsafe {
        let ret = OCSP_id_issuer_cmp(a, b);
        if ret != 0 {
            return ret;
        }
        ASN1_INTEGER_cmp(&(*a).serialNumber, &(*b).serialNumber)
    }
}

/// `OCSP_CERTID *OCSP_CERTID_dup(const OCSP_CERTID *x)` — `crypto/ocsp/ocsp_lib.c:113`, from
/// `IMPLEMENT_ASN1_DUP_FUNCTION(OCSP_CERTID)` (`include/openssl/asn1t.h.in:842-846`), declared by
/// `DECLARE_ASN1_DUP_FUNCTION(OCSP_CERTID)` (`include/openssl/ocsp.h.in:178`).
///
/// # Safety
/// `x` must be NULL or a live `OCSP_CERTID`.
#[allow(dead_code)] // the engine's OCSP arm reads `OCSP_id_cmp`; the dup awaits Phase 12's exports
pub(crate) unsafe extern "C" fn OCSP_CERTID_dup(x: *const OcspCertId) -> *mut OcspCertId {
    // SAFETY: `x` is NULL-or-live per the contract; `OCSP_CERTID_it()` is this crate's static item.
    unsafe { ASN1_item_dup(OCSP_CERTID_it(), x.cast()).cast::<OcspCertId>() }
}
