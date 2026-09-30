//! Phase 10.14.4's dependency — `crypto/http/`: the URL parser. The directory is new here.
//!
//! The only name `crypto/x509/v3_ncons.c` needs from this tree is `OSSL_parse_url`; the rest of
//! `http_lib.c`'s surface is withheld by name with its blocker in [`http_lib`]'s module doc rather
//! than stubbed.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod http_lib;
