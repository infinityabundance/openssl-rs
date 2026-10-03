//! `src/ssl/quic/`: the QUIC units Phase 14 and Phase 15 own.
//!
//! `ssl/quic/quic_tls_api.c` (14.10) and `ssl/quic/quic_impl.c`'s one export (14.10) are laid out
//! here, as `forensics/tools/phase14_obligations.py`'s `crate_module` maps
//! `ssl/quic/<stem>.c` -> `src/ssl/quic/<stem>.rs`. The rest of `quic_impl.c` is the QUIC
//! implementation object a later stratum owns.
//!
//! `ssl/quic/quic_method.c` (15.0) is the whole of `quic.h`'s export set — the three
//! `OSSL_QUIC_*_method` constructors — and `src/ssl/quic/quic_method.rs` lays it out the same way.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod quic_impl;
pub mod quic_method;
pub mod quic_tls_api;
