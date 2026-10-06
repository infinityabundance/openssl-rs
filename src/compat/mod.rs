//! Phase 23 — the compatibility-policy layer and the historical ABI / history façades.
//!
//! Phase 23.7 (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2, row 23.7) is the
//! compatibility-policy layer and the historical ABI façades, each a **narrow typed adapter over
//! the shared implementation** rather than a per-version fork. It has four parts:
//!
//!   * [`policy`] — the typed policy layer ([`policy::AuthoritySpec`] and its meaningful enums),
//!     consumed by `build.rs`. The default is the committed alias
//!     `forensics/multitrack/default-authority.json`; authority selection is explicit, singular,
//!     validated and recorded, and there is no Cargo feature per authority (D534).
//!   * [`arch`] — the explicit ENGINE -> Provider -> no-ENGINE architecture model, and the
//!     initialisation/threading epochs (application locking callbacks and explicit global init for
//!     the historical track; automatic init and `OPENSSL_cleanup` for the later one).
//!   * [`prototypes`] — the authority-specific prototype contracts for a symbol whose declaration
//!     differs across eras, with safe wrappers onto the shared implementation.
//!   * [`layout_generated`] and [`adapters`] — the historical `#[repr(C)]` public-layout façades,
//!     the generated compile-time `sizeof`/`alignof`/`offsetof` assertions, and the explicit
//!     field-by-field adapters to the canonical internals.
//!
//! **Why the façades are cfg-gated.** `build.rs` sets the `openssl_rs_compat_facades` cfg only
//! when the compatibility selection is a historical epoch, so the default 3.6.4 production
//! candidate does not compile a single façade and its artefacts, symbols, layouts and semantics
//! are unchanged. The modules are also compiled under `cfg(test)`, so `cargo test`/`cargo clippy
//! --all-targets` exercise the generated layout assertions and the adapters on every change.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod policy;

#[cfg(any(test, openssl_rs_compat_facades))]
pub mod adapters;
#[cfg(any(test, openssl_rs_compat_facades))]
pub mod arch;
#[cfg(any(test, openssl_rs_compat_facades))]
pub mod layout_generated;
#[cfg(any(test, openssl_rs_compat_facades))]
pub mod prototypes;
