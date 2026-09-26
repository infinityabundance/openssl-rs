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
//! `PKCS8_decrypt` is the name `pem_read_bio_key_legacy` (`crypto/pem/pem_pkey.c:165`) reaches
//! for a `PEM_STRING_PKCS8` block, and `PKCS12_item_decrypt_d2i_ex` is what it decrypts
//! through; the `crypto/asn1/x_sig.c` module landed the `X509_SIG` these read.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod p12_asn;
pub mod p12_attr;
pub mod p12_decr;
pub mod p12_p8d;
pub mod p12_sbag;
pub mod p12_utl;
