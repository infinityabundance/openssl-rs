//! Phase 16.4 — `apps/`: the `openssl` CLI, its option parser and its tables.
//!
//! `forensics/tools/phase16_obligations.py`'s `crate_module` maps `apps/<stem>.c`
//! to `src/apps/<stem>.rs`, so this directory is the crate's layout of the
//! authority's `apps/` subtree. The `openssl` executable the Phase-2 link
//! machinery emits is built from [`openssl::run`] rather than the Phase-2
//! scaffold (`forensics/tools/phase2_shell.py`).
//!
//! SPDX-License-Identifier: Apache-2.0

// `apps/errstr.c` is the first of the 52 command bodies Phase 17.1 lands behind the
// dispatcher; see its module header for the recorded `-help` divergence.
pub mod configutl;
pub mod errstr;
pub mod info;
pub mod list;
pub mod nseq;
// The authority's unit is `apps/openssl.c`, so the crate's file is
// `apps/openssl.rs` and the module path is `apps::openssl`; the inception is the
// layout, not a naming accident.
#[allow(clippy::module_inception)]
pub mod openssl;
pub mod opt;
pub mod pkeyparam;
pub mod prime;
pub mod skeyutl;
// `apps/list.c`'s option-list arm (`-options`) and standard-command listing are
// the surface 16.4's capture measures; `apps/version.c`'s default arm is
// build-independent. Both are pulled forward; see their module headers.
pub mod tables;
pub mod version;
