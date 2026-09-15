//! Phase 5 — the `ASN.1` stratum: the coded value types, their DER encoding, and
//! the template machinery that reads and writes structures made of them.
//!
//! The module tree is deliberately split along the authority's own file
//! boundaries, because those boundaries are what the raise-site coordinates and
//! the ownership atlas are keyed on:
//!
//! * [`layout`] — the `#[repr(C)]` projections of every structure an installed
//!   header exposes, and every constant those headers define. No behaviour.
//! * [`string`] — `ASN1_STRING` and the fifteen types that are one
//!   (`crypto/asn1/asn1_lib.c`, `a_octet.c`).
//! * [`der`] — the low-level header codec: `ASN1_get_object`, `ASN1_put_object`,
//!   `ASN1_object_size`, `ASN1_tag2bit`, `ASN1_tag2str`, and the two parsers
//!   (`asn1_lib.c`, `tasn_dec.c`'s `ASN1_tag2bit`).
//! * [`prim`] — `ASN1_OBJECT` and the `ASN1_INTEGER`/`ASN1_ENUMERATED` family,
//!   including the two's-complement content codecs (`a_object.c`, `a_int.c`).
//! * [`text`] — the text conversions a BIO reads and writes (`f_int.c`,
//!   `f_string.c`, and `i2a_ASN1_OBJECT` from `a_object.c`).
//!
//! What is *not* here yet is the template machinery (`ASN1_item_*`) and the
//! `d2i_*`/`i2d_*` wrappers built on it. `docs/PHASE-5-SUBPHASES.md` orders those
//! after the leaf types they are made of, and D73 explains why: the wrappers look
//! like the natural starting point, but each is a thin layer over
//! `asn1_d2i_ex_primitive`, and doing them first would mean writing that path by
//! hand and drifting from it.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod d2i;
pub mod der;
pub mod layout;
pub mod prim;
pub mod string;
pub mod text;
