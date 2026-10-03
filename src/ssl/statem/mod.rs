//! Phase 14.5 — `ssl/statem/`: the handshake state machine.
//!
//! `forensics/tools/phase14_obligations.py`'s `crate_module` maps `ssl/statem/<stem>.c` to
//! `src/ssl/statem/<stem>.rs`, so this directory is the crate's layout of the authority's
//! `ssl/statem/` subtree.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod extensions_cust;
// Phase 14.7b lands the protocol-version helpers of `ssl/statem/statem_lib.c` (no exports), so the
// crate's layout of that unit appears here without the rest of its message layer.
pub mod statem_lib;
// The authority's unit is `ssl/statem/statem.c`, so the crate's file is `statem/statem.rs` and the
// module path is `statem::statem`; the inception is the layout, not a naming accident.
#[allow(clippy::module_inception)]
pub mod statem;
