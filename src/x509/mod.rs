//! Phase 8.8's `crypto/x509/` substream — the accessor slices of `x_pubkey.c`,
//! `x509_set.c` and `t_x509.c` that the ASN.1 method objects call by name (D349).
//!
//! This directory did not exist before D349. The transcription atlas maps a crate
//! module to the authority translation unit its definitions dominantly come from
//! (`forensics/atlas/transcription-edges.json`'s `body.modules`, `build_edges`'s
//! "the unit is the dominant authority translation unit among the symbols the module
//! defines"), so each of the three units below gets one module named for its file,
//! exactly as `src/asn1/x_algor.rs` does for `crypto/asn1/x_algor.c`:
//!
//! ```text
//! src/x509/x_pubkey.rs   <-  crypto/x509/x_pubkey.c
//! src/x509/x509_set.rs   <-  crypto/x509/x509_set.c
//! src/x509/t_x509.rs     <-  crypto/x509/t_x509.c
//! ```
//!
//! All three are **partial** transcriptions. `crypto/x509/x_pubkey.c` is 1,079 lines
//! whose `i2d_*_PUBKEY` family reaches `EVP_PKEY_assign` and the empty
//! `standard_methods[]` table (the D341 cycle); `x509_set.c` and `t_x509.c` are the
//! X.509 object and print layers, which are not this subphase's. Each module withholds
//! what it does not build and names it, in both directions, in
//! `forensics/prerequisites.json`'s `divergences` — the mechanism D345 established for
//! `src/dh/ameth.rs`.
//!
//! The one `#[repr(C)]` structure each module is a canonical definition for —
//! [`x_pubkey::X509Pubkey`], [`x509_set::X509SigInfo`] and
//! [`crate::asn1::p8_pkey::Pkcs8PrivKeyInfo`] — is the authority's own layout, with its
//! offsets asserted by `core::mem::offset_of!` and a `const _: () = { assert!(...) }`
//! block. `src/evp/pkey_asn1.rs` re-exports the three rather than declaring placeholders,
//! which is what D348 did for `X509Algor`.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod t_x509;
pub mod x509_set;
pub mod x_pubkey;
