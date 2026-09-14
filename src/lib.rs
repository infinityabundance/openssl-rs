//! # openssl-rs
//!
//! A native-Rust, custodian-level reconstruction of the externally observable
//! contract of a pinned OpenSSL distribution.
//!
//! This crate is **not** a wrapper, binding or façade. It does not use OpenSSL
//! or any other cryptographic implementation as a backend. Its objective is that
//! unmodified OpenSSL consumers can compile, link, load, execute and behave
//! correctly with `openssl-rs` substituted for OpenSSL, for an explicitly stated
//! authority, build profile and platform.
//!
//! ## Read this first
//!
//! The governing documents are the Phase 0 constitution in `docs/`:
//!
//! * [`docs/CUSTODIAN_CONTRACT.md`] — mission, the single-crate rule, the
//!   definition of "custodian compatible", and what must never be done.
//! * [`docs/PARITY_MODEL.md`] — what a parity obligation is and how it is
//!   promoted. Read this before interpreting any status.
//! * [`docs/AUTHORITY_POLICY.md`] — the admitted authorities and build profiles.
//! * [`docs/RELEASE_GATES.md`] — the phase order and maturity levels.
//! * [`docs/NON_CLAIMS.md`] — what this project explicitly does **not** claim.
//!
//! ## Current state
//!
//! Phase 0 (constitution) and Phase 1 (archaeology / atlas) are in progress.
//! **No product subsystem is implemented yet, and none is claimed.** The crate
//! exists so that the archaeology, the court machinery and the product share one
//! canonical home, and so that the evidence binding below is a compile-time
//! fact.
//!
//! The authoritative state is machine-readable, not prose: see [`status`].
//!
//! ## Evidence binding
//!
//! `build.rs` refuses to build without the constitution and the admitted
//! authority registry, and exposes the authority identity to the crate:
//!
//! ```
//! use openssl_rs::status;
//! assert_eq!(status::PRODUCTION_AUTHORITY_ID, "openssl-3.6.4-production");
//! assert_eq!(status::AUTHORITY_ARCHIVE_SHA256.len(), 64);
//! ```
//!
//! A binary therefore cannot exist without naming the authority it was built
//! against.
//!
//! [`docs/CUSTODIAN_CONTRACT.md`]: ../docs/CUSTODIAN_CONTRACT.md
//! [`docs/PARITY_MODEL.md`]: ../docs/PARITY_MODEL.md
//! [`docs/AUTHORITY_POLICY.md`]: ../docs/AUTHORITY_POLICY.md
//! [`docs/RELEASE_GATES.md`]: ../docs/RELEASE_GATES.md
//! [`docs/NON_CLAIMS.md`]: ../docs/NON_CLAIMS.md

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

pub mod ffi;
pub mod runtime;
pub mod status;
