//! `src/ssl/quic/`: the QUIC bridge units Phase 14 owns.
//!
//! `ssl/quic/quic_tls_api.c` (14.10) and `ssl/quic/quic_impl.c`'s one export (14.10) are laid out
//! here, as `forensics/tools/phase14_obligations.py`'s `crate_module` maps
//! `ssl/quic/<stem>.c` -> `src/ssl/quic/<stem>.rs`. The rest of `quic_impl.c` is Phase 15's
//! (`quic.h`'s exports), so this directory holds only the two units this stratum lands.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod quic_impl;
pub mod quic_tls_api;
