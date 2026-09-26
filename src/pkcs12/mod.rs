//! Phase 10's `crypto/pkcs12/` substream — the units `PKCS8_decrypt` and the `PKCS12` object need.
//!
//! `crypto/pkcs12/p12_decr.c` is the PBE buffer crypt and the ASN.1 decrypt/encrypt pair over
//! it; `crypto/pkcs12/p12_p8d.c` is the pair of `PKCS8_decrypt` spellings that read a
//! `PKCS8_PRIV_KEY_INFO` out of an `X509_SIG`. They are one directory because they are one
//! authority directory, each unit getting one module named for its file (D349's rule).
//!
//! 10.2 adds four more: [`p12_asn`] (the `PKCS12`/`PKCS12_SAFEBAG`/`PKCS12_BAGS`/
//! `PKCS12_MAC_DATA` item groups), [`p12_sbag`] (the `SafeBag` accessors and constructors),
//! [`p12_attr`] (the attribute helpers) and [`p12_utl`] (the ASCII/BMPString/UTF-8 conversions).
//!
//! 10.3 adds the two whose closure is inside it: [`p12_add`] (the `SafeBag` packer and the two
//! shrouded-key readers) and [`p12_crt`] (the `add_*` surface — the one export with a landed
//! closure). Their `PKCS#7`-dependent siblings stay open on `crypto/pkcs7/pk7_asn1.c`, which is
//! Phase 12's.
//!
//! **The `PKCS7` subset was then pulled forward** (D441's stratum-ordering defect; see
//! [`crate::pkcs7`]), which unblocks the container rows: [`p12_init`] (`PKCS12_init(_ex)` and the
//! `ossl_pkcs12_get0_pkcs7ctx` borrow) and [`p12_mutl`] (the `MacData` accessors and
//! `PKCS12_setup_mac`), plus the `PKCS12` item group and the five `PKCS#7` spellings whose
//! blocker was the object itself. The rows still `open` need Phase 11's `X509_it`/`EVP_PKEY2PKCS8`/
//! `PKCS5_pbe*set*_ex` or 10.4's `PKCS8_encrypt`/`PKCS12_key_gen_utf8_ex`, and are named where
//! they live.
//!
//! `PKCS8_decrypt` is the name `pem_read_bio_key_legacy` (`crypto/pem/pem_pkey.c:165`) reaches
//! for a `PEM_STRING_PKCS8` block, and `PKCS12_item_decrypt_d2i_ex` is what it decrypts
//! through; the `crypto/asn1/x_sig.c` module landed the `X509_SIG` these read.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod p12_add;
pub mod p12_asn;
pub mod p12_attr;
pub mod p12_crt;
pub mod p12_decr;
pub mod p12_init;
pub mod p12_mutl;
pub mod p12_p8d;
pub mod p12_sbag;
pub mod p12_utl;
