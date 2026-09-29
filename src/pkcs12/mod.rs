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
//! 10.3 adds the two whose closure is inside it: [`p12_add`] (the `SafeBag` packer, the two
//! shrouded-key readers and the two `p7encdata` writers) and [`p12_crt`] (the `add_*` surface),
//! plus [`p12_npas`] (`PKCS12_newpass` and its three workers).
//!
//! **The `PKCS7` subset was then pulled forward** (D441's stratum-ordering defect; see
//! [`crate::pkcs7`]), which unblocks the container rows: [`p12_init`] (`PKCS12_init(_ex)` and the
//! `ossl_pkcs12_get0_pkcs7ctx` borrow) and [`p12_mutl`] (the `MacData` accessors and
//! `PKCS12_setup_mac`), plus the `PKCS12` item group and the five `PKCS#7` spellings whose
//! blocker was the object itself. **D443's and D444's measured pull-forwards then supplied the
//! PBE builders (`PKCS5_pbe*set*_ex`) and `EVP_PKEY2PKCS8`, and 10.4 landed the PKCS#12 KDF**, so
//! the rest of 10.3 lands too: `p12_mutl`'s four MAC names, `p12_add`'s two `p7encdata` writers,
//! `p12_crt`'s `PKCS12_add_key(_ex)`/`PKCS12_add_safe(_ex)`, and `p12_npas`'s `PKCS12_newpass`.
//!
//! **The `X509`-graph rows this substream once withheld have all landed.** The
//! `nm --undefined-only` closure over the authority's `crypto/pkcs12/` objects named
//! `X509_check_private_key`/`X509_digest`/`X509_alias_get0`/`X509_keyid_get0` (the
//! `PKCS12_create(_ex/_ex2)`/`PKCS12_add_cert` builder), `X509_it`/`X509_CRL_it`/
//! `ossl_x509*_set0_libctx` (the `PKCS12_SAFEBAG_create_cert`/`_crl` and `get1_*` pair) and
//! `ossl_x509_add_cert_new` (for `PKCS12_parse`). Each has since landed — the last of them, the
//! `x509_cmp.c` add family, with the Phase 11 slice — so no `crypto/pkcs12/` export is withheld
//! on the `X509` graph any longer.
//!
//! 10.4 adds [`p12_key`] (the six `PKCS12_key_gen_*` spellings over the provider `PKCS12KDF` row),
//! [`p12_crpt`] (the two `PKCS12_PBE_keyivgen` spellings and the empty `PKCS12_PBE_add`, which is
//! what retires D-PBE-PKCS12-KEYGEN-1) and [`p12_p8e`] (`PKCS8_set0_pbe`/`_ex`; D444's pulled-forward
//! subset landed `PKCS5_pbe_set_ex`/`PKCS5_pbe2_set_iv_ex`, so the `PKCS8_encrypt`/`_ex` pair lands
//! too — all four of that unit's exports).
//!
//! **10.15 opened 10.3's last withheld unit**: [`p12_kiss`] (`PKCS12_parse` and its three
//! `static` workers) is now landable whole. Its former blockers — `PKCS12_SAFEBAG_get1_cert_ex`
//! (landed in 10.15) and `ossl_x509_add_cert_new` (`crypto/x509/x509_cmp.c`, landed by the
//! Phase 11 slice) — are both present, so the read path that closes the `PKCS12_parse` export
//! is transcribed here rather than deferred a second time.
//!
//! `PKCS8_decrypt` is the name `pem_read_bio_key_legacy` (`crypto/pem/pem_pkey.c:165`) reaches
//! for a `PEM_STRING_PKCS8` block, and `PKCS12_item_decrypt_d2i_ex` is what it decrypts
//! through; the `crypto/asn1/x_sig.c` module landed the `X509_SIG` these read.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod p12_add;
pub mod p12_asn;
pub mod p12_attr;
pub mod p12_crpt;
pub mod p12_crt;
pub mod p12_decr;
pub mod p12_init;
pub mod p12_key;
pub mod p12_kiss;
pub mod p12_mutl;
pub mod p12_npas;
pub mod p12_p8d;
pub mod p12_p8e;
pub mod p12_sbag;
pub mod p12_utl;
