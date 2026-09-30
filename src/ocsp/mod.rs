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
