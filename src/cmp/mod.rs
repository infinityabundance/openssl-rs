//! `crypto/cmp/` — the Certificate Management Protocol. Phase 12.4.
//!
//! This module is being landed unit by unit. The first slice is the CMP object model: the
//! `cmp_asn.c` item groups (and, pulled forward crate-internally, the `crmf_asn.c` item groups
//! CMP's message engine carries — see [`crmf_asn`]), the `cmp_ctx.c` context, and the
//! `cmp_util.c`/`cmp_status.c`/`cmp_hdr.c` helpers.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub(crate) mod cmp_asn;
pub(crate) mod cmp_client;
pub(crate) mod cmp_ctx;
pub(crate) mod cmp_genm;
pub(crate) mod cmp_hdr;
pub(crate) mod cmp_http;
pub(crate) mod cmp_msg;
pub(crate) mod cmp_protect;
pub(crate) mod cmp_server;
pub(crate) mod cmp_status;
pub(crate) mod cmp_util;
pub(crate) mod cmp_vfy;
// The `crmf_asn.c` item groups 12.4 pulled forward live in `src/crmf/` as of 12.7; this alias keeps
// the CMP modules that name them compiling unchanged.
pub(crate) use crate::crmf::crmf_asn;

pub use cmp_asn::*;
pub use cmp_client::*;
pub use cmp_ctx::*;
pub use cmp_genm::*;
pub use cmp_hdr::*;
pub use cmp_http::*;
pub use cmp_msg::*;
pub use cmp_server::*;
pub use cmp_status::*;
pub use cmp_util::*;
pub use cmp_vfy::*;
