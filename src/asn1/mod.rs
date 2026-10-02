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
//! * [`bitstr`] — `ASN1_BIT_STRING`'s bit operations and its two content codecs
//!   (`a_bitstr.c`, `t_bitst.c`).
//! * [`fre`] — the free path (`tasn_fre.c`), which is what makes a failed decode
//!   destroy the caller's value rather than leave it half-filled.
//! * [`i2d`] — the shared encoder (`tasn_enc.c`).
//! * [`items`] — the `ASN1_ITEM` descriptors for the coded types and the
//!   `*_it()` accessors that hand them out (`tasn_typ.c`, `a_time.c`). The
//!   template machinery of subphase 5.4 reads these; so does every `d2i_*`/`i2d_*`
//!   wrapper, because each wrapper is one call to `ASN1_item_*` with the matching
//!   item.
//! * [`typ`] — the `d2i_*`/`i2d_*` wrapper family those items name, and
//!   `ASN1_NULL`'s allocator (`tasn_typ.c`).
//! * [`text`] — the text conversions a BIO reads and writes (`f_int.c`,
//!   `f_string.c`, and `i2a_ASN1_OBJECT` from `a_object.c`).
//!
//! What is *not* here yet is the template machinery (`ASN1_item_*`), the time
//! accessors, the `ASN1_TYPE` operations, the NDEF BIO layer and PEM.
//! `docs/PHASE-5-SUBPHASES.md` orders them, and D73 explains why the shared codec
//! had to land before the wrappers that name it: each wrapper is a thin layer over
//! `asn1_d2i_ex_primitive`, and doing the wrappers first would mean writing that
//! path by hand and drifting from it.
//!
//! ## Phase 10.10 — the ASN.1 digest/sign layer
//!
//! 10.10 lands `crypto/asn1/a_digest.c` ([`a_digest`]) and `crypto/asn1/a_sign.c` ([`a_sign`])
//! whole, and **completes `crypto/asn1/asn1_lib.c`** — already transcribed as [`der`] (the header
//! codec) and [`string`] (the string lifecycle) — with one exception: `ossl_sk_ASN1_UTF8STRING2text`
//! (`asn1_lib.c:435-473`) is **withheld by name** because its only authority callers,
//! `crypto/ts/ts_rsp_verify.c` and `crypto/cmp/cmp_client.c`, are unlanded; its own closure (the
//! stack and `ASN1_STRING` accessors) is landed, so it can land the day a caller does.
//! `crypto/evp/digest.c` — landed before as `src/evp/digest.rs` — gained `evp_md_ctx_new_ex` and
//! withholds `evp_digest_fetch_from_prov` for the same no-caller reason, which its own doc records.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod a_d2i_fp;
// Phase 10.10's `crypto/asn1/a_digest.c` -- `ASN1_item_digest`/`ASN1_digest` and the
// `ossl_asn1_item_digest_ex` that `X509_digest` reaches.
pub mod a_digest;
pub mod a_dup;
pub mod a_i2d_fp;
pub mod a_mbstr;
pub mod a_print;
// Phase 10.10's `crypto/asn1/a_sign.c` -- `ASN1_item_sign(_ex/_ctx)` and the deprecated
// `ASN1_sign`; the `evp_md_ctx_new_ex` it needs landed with the subphase in `src/evp/digest.rs`.
pub mod a_sign;
pub mod a_strex;
pub mod a_strnid;
pub mod a_type;
pub mod a_utf8;
// Phase 10.11's `crypto/asn1/a_verify.c` -- `ASN1_item_verify(_ex/_ctx)` and the deprecated
// `ASN1_verify`. `ASN1_item_verify_ctx` is the single blocker 10.10 left on the Phase-7 row.
pub mod a_verify;
pub mod asn1_gen;
pub mod asn_mime;
pub mod asn_pack;
pub mod bio_asn1;
pub mod bitstr;
pub mod d2i;
// Phase 8.8's `d2i_KeyParams`/`d2i_KeyParams_bio` (`crypto/asn1/d2i_param.c`) and `d2i_PublicKey`
// (`crypto/asn1/d2i_pu.c`). Each is its own authority unit and therefore its own module.
pub mod d2i_param;
pub mod d2i_pr;
pub mod d2i_pu;
pub mod der;
pub mod evp_asn1;
pub mod fre;
pub mod i2d;
pub mod i2d_evp;
pub mod items;
pub mod layout;
pub mod new;
// Phase 11.6's `crypto/asn1/nsseq.c` -- the `NETSCAPE_CERT_SEQUENCE` item, landed with the
// `pem_all.c` container readers and writers that name its `d2i_*`/`i2d_*` (section 2 row 11.6).
pub mod nsseq;
// D443's pull-forward: `crypto/asn1/p5_pbe.c` and `crypto/asn1/p5_pbev2.c` are Phase 11's
// `x509.h` units, landed early because `PKCS8_encrypt_ex`'s only unlanded names are their
// `PKCS5_pbe_set_ex`/`PKCS5_pbe2_set_iv_ex` (and the MAC setters need `PKCS5_pbkdf2_set` and
// the `PBMAC1PARAM` group). See the module docs and `docs/DECISIONS.md` D442's precedent.
pub mod p5_pbe;
pub mod p5_pbev2;
// Phase 11.7's `crypto/asn1/p5_scrypt.c` half -- the `SCRYPT_PARAMS` item and
// `PKCS5_pbe2_set_scrypt`; the unit's Phase 7 half is `src/evp/p5_scrypt.rs`.
pub mod p5_scrypt;
// Phase 11.7's `crypto/asn1/t_spki.c` and `crypto/asn1/asn_mstbl.c` -- the SPKI printer and the
// `stbl_section` configuration module.
pub mod asn_mstbl;
pub mod t_spki;
// Phase 8.8's `crypto/asn1/p8_pkey.c` pair, `PKCS8_pkey_set0`/`PKCS8_pkey_get0`, and the
// `PKCS8_PRIV_KEY_INFO` layout (D349). D368 completes the unit's item half; the `add1_attr`
// family lands with `crypto/x509/x509_att.c`.
pub mod p8_pkey;
pub mod prim;
pub mod string;
pub mod t_pkey;
pub mod tasn_prn;
pub mod text;
pub mod time;
pub mod typ;
pub mod utl;
pub mod x_algor;
pub mod x_bignum;
pub mod x_int64;
pub mod x_long;
// Phase 10.8's `crypto/asn1/x_val.c` -- the `X509_VAL` item the `X509_CINF` template embeds.
pub mod x_val;
// Phase 10's `crypto/asn1/x_sig.c` -- the `X509_SIG` (EncryptedPrivateKeyInfo) family, landed
// early because `PKCS8_decrypt` reads it through `X509_SIG_get0` (D368).
// Phase 11.6's `crypto/asn1/x_info.c` and `crypto/asn1/x_pkey.c` -- the `X509_INFO` record and
// its private-key slot, landed with `crypto/pem/pem_info.c`'s bundle reader and writer.
pub mod x_info;
pub mod x_pkey;
pub mod x_sig;
// Phase 10.14.2's `crypto/asn1/x_spki.c` -- the `NETSCAPE_SPKAC`/`NETSCAPE_SPKI` items, landed
// with the `x509spki.c` surface and the two `x_all.c` faces that name them.
pub mod x_spki;
