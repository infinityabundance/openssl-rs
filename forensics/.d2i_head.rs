//! Phase 5 — the shared DER decoder: `asn1_d2i_ex_primitive` and the dispatch
//! that reaches it.
//!
//! This module reproduces `crypto/asn1/tasn_dec.c`. It holds no exported
//! function: every `d2i_*` wrapper is one call to `ASN1_item_d2i` with the
//! matching item, and those wrappers live beside the type they decode
//! (`asn1::typ` for the `tasn_typ.c` family, `asn1::prim` for the two
//! `a_object.c` and `a_int.c` ones) so that the module a symbol lives in is the
//! module the authority defines it in.
//!
//! ## What this decode path is, and what it is not
//!
//! [`item_d2i`] is `ASN1_item_d2i_ex`: it redirects a null value slot to a local
//! and clears a cache. [`embed_d2i`] is `asn1_item_embed_d2i` restricted to the
//! two of its nine arms the items in [`crate::asn1::items`] reach — `PRIMITIVE`
//! with no templates, and `MSTRING`. [`d2i_ex_primitive`] is
//! `asn1_d2i_ex_primitive` and [`ex_c2i`] is `asn1_ex_c2i`.
//!
//! The exclusions are named and asserted rather than left implied, because each
//! one is a place where a silently-wrong answer would look like a decode:
//!
//! * `it->templates != NULL` (a `SEQUENCE`, a `SEQUENCE OF`, `ASN1_TIME`'s
//!   sibling forms) and every `CHOICE`/`EXTERN` item — subphase 5.4.
//! * `utype == V_ASN1_ANY` — subphase 5.7, which is where the `ASN1_TYPE` that
//!   arm allocates belongs.
//! * `V_ASN1_SEQUENCE`, `V_ASN1_SET` and `V_ASN1_OTHER`, whose content is kept
//!   in encoded form by `asn1_find_end` — subphase 5.4, and reachable only
//!   through `ASN1_SEQUENCE_it`.
//!
//! Each of those is guarded by a `debug_assert!` so the claim is checked where
//! it can be, and each is unreachable from the exports the stratum currently
//! provides: not one of them names an item with a template, and `d2i_ASN1_TYPE`
//! and `d2i_ASN1_SEQUENCE_ANY` are still `open` in
//! `forensics/phase5-obligations.json` and abort loudly.
//!
//! ## The three branches a reader is most likely to get wrong
//!
//! **The `TOO_LONG` check runs before the header check.** `asn1_check_tlen` is
//! given a non-null `ctx` by `ASN1_item_d2i`, so it takes the caching branch, and
//! in that branch it validates `plen + hdrlen <= len` *before* it looks at the
//! header's error bit. Reordering those two reports `BAD_OBJECT_HEADER` where the
//! authority reports `TOO_LONG`.
//!
//! **A constructed string is collected, not rejected.** `OCTET STRING` has a legal
//! constructed form, so the decoder concatenates the contents of its elements into
//! one buffer and hands *that* to the content codec with ownership transferred.
//! Only `NULL`, `BOOLEAN`, `OBJECT`, `INTEGER` and `ENUMERATED` are refused in
//! constructed form (`TYPE_NOT_PRIMITIVE`). The collected buffer is allocated with
//! the `CRYPTO_*` allocator rather than a Rust `Vec`, because `ASN1_STRING_set0`
//! takes ownership of it and releases it with `CRYPTO_free` — a `Vec`'s pointer
//! would be a mismatch no test would notice until a heap hook was installed.
//!
//! **The per-type length checks live in the content codec, not the collector.**
//! `BMPSTRING`'s odd length, `UNIVERSALSTRING`'s non-multiple-of-four,
//! `GENERALIZEDTIME`'s `< 15` and `UTCTIME`'s `< 13` are checked *after* the
//! content is in hand, and each raises its own reason. Checking them earlier
//! would report the same failure with a different reason code, which is exactly
//! what `RT-ASN1` compares.
//!
//! ## The defect this rewrite removes
//!
//! The previous version of this file reproduced the string arm's allocation
//! failure as `string_embed_free(stmp)` only when the string had just been
//! allocated. The authority frees `stmp` unconditionally and nulls the caller's
//! slot: `asn1_ex_c2i`'s `if (!ASN1_STRING_set(...))` arm does
//! `ASN1_STRING_free(stmp); *pval = NULL;` whatever `stmp` was. Reproducing it
//! conditionally would have leaked or double-freed exactly one caller pattern —
//! a `d2i_*` into an existing string on an allocation failure.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};

use crate::asn1::bitstr::ossl_c2i_ASN1_BIT_STRING;
use crate::asn1::layout::*;
use crate::asn1::prim::{ossl_c2i_ASN1_INTEGER, ossl_c2i_ASN1_OBJECT};
use crate::asn1::string::{string_type_new, ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_set0};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_realloc};
use crate::runtime::obj::Asn1Object;
