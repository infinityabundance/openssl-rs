//! Phase 12.1's `crypto/http/`: the URL parser, the proxy selector and the HTTP/1.0 client.
//!
//! Subphase 10.14.4 landed [`http_lib`]'s `OSSL_parse_url` alone, for `crypto/x509/v3_ncons.c`;
//! its doc withheld the rest of the unit by name because the HTTP transport entry points were
//! not built. Subphase 12.1 lifts that withholding: [`http_lib`] now carries
//! `OSSL_HTTP_parse_url` and `OSSL_HTTP_adapt_proxy` as well, and [`http_client`] carries the
//! whole `http_client.c` surface — the low-level `OSSL_HTTP_REQ_CTX_*` engine and the
//! high-level `OSSL_HTTP_open`/`_get`/`_transfer`/`_close` entry points. The network their
//! high-level paths use is the BIO layer's connection BIOs (`src/runtime/bio/bss_conn.rs`),
//! which are landed; this tree opens no socket of its own.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod http_client;
pub mod http_lib;
