//! Phase 14.4 — `ssl/rio/`: the record I/O layer.
//!
//! `forensics/tools/phase14_obligations.py`'s `crate_module` maps `ssl/rio/<stem>.c` to
//! `src/ssl/rio/<stem>.rs`. Only the non-blocking poll unit is this stratum's, and only its
//! exported `SSL_poll` row is measured.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod poll_immediate;
