//! Phase 10 (10.14.14) — `crypto/ocsp/`: the OCSP object model and its ASN.1.
//!
//! This directory lands the OCSP sub-subphase's units one at a time. The first is
//! [`ocsp_asn`], the item groups every later OCSP unit names.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod ocsp_asn;

// `crypto/ocsp/v3_ocsp.c` -- the five OCSP extension tables (`ossl_v3_ocsp_nonce`,
// `ossl_v3_ocsp_crlid`, `ossl_v3_ocsp_acutoff`, `ossl_v3_ocsp_serviceloc`, `ossl_v3_ocsp_nocheck`),
// now closure-ready because `ocsp_asn.c`'s `OCSP_CRLID_it`/`OCSP_SERVICELOC_it` are landed above.
// It withholds only the published `standard_exts[]` and the six `v3_lib.rs` lookup names (D456).
pub mod v3_ocsp;

// Phase 11.2b -- the OCSP *functions* the Phase-11 verification engine's OCSP arm
// (`crypto/x509/x509_vfy.c`'s `check_cert_ocsp_resp`) needs, pulled forward as internal
// `pub(crate)` transcriptions. Phase 12.6 promotes them to the exported surface and lands the
// remaining `crypto/ocsp/` units.
//
// * [`ocsp_lib`] -- `OCSP_cert_to_id`, `OCSP_cert_id_new`, `OCSP_id_issuer_cmp`, `OCSP_id_cmp`,
//   `OCSP_CERTID_dup` (`crypto/ocsp/ocsp_lib.c`).
// * [`ocsp_srv`] -- the responder builder (`crypto/ocsp/ocsp_srv.c`).
// * [`ocsp_cl`] -- the request builder and response reader (`crypto/ocsp/ocsp_cl.c`).
// * [`ocsp_vfy`] -- the signer/id helpers and `OCSP_basic_verify` (`crypto/ocsp/ocsp_vfy.c`).
// * [`ocsp_ext`] -- the extension wrappers, nonce handling and constructors
//   (`crypto/ocsp/ocsp_ext.c`).
// * [`ocsp_prn`] -- the text printers (`crypto/ocsp/ocsp_prn.c`).
// * [`ocsp_http`] -- `OCSP_sendreq_new`/`OCSP_sendreq_bio` (`crypto/ocsp/ocsp_http.c`).
pub mod ocsp_cl;
pub mod ocsp_ext;
pub mod ocsp_http;
pub mod ocsp_lib;
pub mod ocsp_prn;
pub mod ocsp_srv;
pub mod ocsp_vfy;
