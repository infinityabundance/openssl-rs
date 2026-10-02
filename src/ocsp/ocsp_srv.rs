//! `crypto/ocsp/ocsp_srv.rs` — `crypto/ocsp/ocsp_srv.c`'s `OCSP_id_get0_info`. Phase 11.2b's
//! second OCSP-function unit, landed as an **internal** transcription: the name is `pub(crate)` and
//! carries no `#[no_mangle]`, because the `OCSP_*` exports are Phase 12's.
//!
//! `crypto/ocsp/ocsp_srv.c` is 327 lines. The pull-forward needs exactly one name from it:
//!
//! * [`OCSP_id_get0_info`] (`:38-53`) — hand back the four `OCSP_CERTID` members whose out-pointers
//!   the caller supplied. A NULL `cid` answers 0; the algorithm returns the stored OID, and the
//!   three string members return interior pointers into the id, which is why the C signature takes
//!   `ASN1_OCTET_STRING **`/`ASN1_INTEGER **` rather than duplicating.
//!
//! The remaining `ocsp_srv.c` surface (`OCSP_request_is_signed`, `OCSP_response_create`,
//! `OCSP_basic_add1_status`, `OCSP_basic_sign*`, `OCSP_RESPID_set_by_*`, `OCSP_RESPID_match*`) is
//! not part of this pull-forward; it is the responder's builder and belongs with Phase 12's exports.
//!
//! The one function's landing caller is the Phase-11 engine's OCSP arm.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::c_int;

use crate::asn1::layout::Asn1String;
use crate::ocsp::ocsp_asn::OcspCertId;
use crate::runtime::obj::Asn1Object;

/// `int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
/// ASN1_OCTET_STRING **pikeyHash, ASN1_INTEGER **pserial, OCSP_CERTID *cid)` —
/// `crypto/ocsp/ocsp_srv.c:38-53`.
///
/// Writes each non-NULL out-pointer and answers 1; a NULL `cid` writes nothing and answers 0. The
/// string out-pointers receive interior pointers, not copies.
///
/// # Safety
/// `cid` must be NULL or a live `OCSP_CERTID`; each non-NULL `p*` out-pointer must be writable.
pub(crate) unsafe extern "C" fn OCSP_id_get0_info(
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
