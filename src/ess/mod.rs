//! `crypto/ess/` — Enhanced Security Services for S/MIME (RFC 2634/5035). Phase 12.7.
//!
//! The directory is new here. It lands the two units the `ess.h` surface names: [`ess_asn1`]'s
//! five item groups (the `SigningCertificate`/`SigningCertificateV2` structures CMS's
//! `ESSCertID` attributes carry) and [`ess_lib`]'s builders and checker.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub(crate) mod ess_asn1;
pub(crate) mod ess_lib;

pub use ess_asn1::*;
pub use ess_lib::*;
