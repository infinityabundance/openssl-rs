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
//! Phases 0 (constitution), 1 (archaeology / atlas), 2 (distribution and ABI
//! shell) and 3 (core runtime) are **complete** in the derived phase state. The
//! core runtime — allocation, the thread-local error queue, stacks, `ex_data`,
//! the hash table, the secure heap, threads and atomics, initialisation and the
//! object/NID database — is implemented and differentially courted against the
//! authority; BIO, CONF, BN, ASN.1, the provider and EVP layers, the algorithms,
//! X.509 and libssl are not started.
//!
//! **No symbol is `PARITY_VERIFIED`.** "Implemented" means the crate's compiled
//! output defines a symbol with that name; parity is promoted only by courts,
//! dimension by dimension (`docs/PARITY_MODEL.md`). Everything outside the Phase
//! 3 families is `SCAFFOLDED` and aborts rather than returning a plausible value.
//!
//! The authoritative state is machine-readable, not prose: see [`status`] and
//! `forensics/phase-state.json`.
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

pub mod aes;
pub mod asn1;
pub mod bn;
pub mod context;
pub mod digest;
pub mod dso;
pub mod evp;
pub mod ffi;
pub mod hpke;
pub mod mac;
pub mod modes;
pub mod params;
pub mod pem;
pub mod property;
pub mod provider;
pub mod runtime;
pub mod selftest;
pub mod status;
