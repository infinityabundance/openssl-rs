//! Phase 10's pulled-forward subset of `crypto/pkcs7/` — the `PKCS7` object PKCS#12's `PFX`
//! container reaches. Phase 12 owns `pkcs7.h` in `forensics/atlas/symbol-ownership.json`; the
//! symbols landed here therefore read `implemented` with `owning_phase: 12` while Phase 12 stays
//! `not-started`, the precedent Phase 8 set by landing 87 exports the atlas assigns to Phase 10.
//!
//! ## Why a subset, and how it was measured
//!
//! `docs/DECISIONS.md` D441 measured that 27 of 10.3's 31 exports were blocked on Phase 12's
//! `PKCS7` object because the `PFX` structure's `authsafes` column *is* a `PKCS7`
//! (`crypto/pkcs12/p12_asn.c:21`). The corpus here is the set of `PKCS7*`/`ossl_pkcs7*` symbols
//! the authority's own `crypto/pkcs12/` build objects leave undefined —
//! `nm --undefined-only forensics/authorities/build/openssl-3.6.4-production/crypto/pkcs12/*.o`
//! filtered to those two prefixes — and no more:
//!
//! ```text
//! PKCS7_free  PKCS7_it  PKCS7_new  PKCS7_new_ex  PKCS7_set_type
//! ossl_pkcs7_ctx_get0_libctx  ossl_pkcs7_ctx_get0_propq  ossl_pkcs7_ctx_propagate
//! ossl_pkcs7_set0_libctx  ossl_pkcs7_set1_propq
//! ```
//!
//! ## The arms this subset does not carry, and why they are not stubbed
//!
//! `pk7_asn1.c`'s `ASN1_ADB(PKCS7)` table has six arms. Three of them — `signed`, `enveloped`
//! and `signedAndEnveloped` — are item groups over Phase 11's `X509_it`, `X509_CRL_it` and
//! `X509_NAME_it` (`PKCS7_SIGNED`'s `cert`/`crl` columns and `PKCS7_ISSUER_AND_SERIAL`'s
//! `issuer`), none of which is landed, so their item descriptors cannot be built. **PKCS#12 never
//! reaches them**: an `authsafes` column is *always* a `NID_pkcs7_data` contentInfo
//! (`PKCS12_pack_p7data`, `PKCS12_init_ex`, and the `PKCS7_type_is_data` guard on every reader),
//! and the encrypted arm a `p7encdata` safe produces is `NID_pkcs7_encrypted`. So the subset is
//! exactly the arms whose closure is landed — `data`, `digest` and `encrypted` — transcribed
//! from the authority with its templates, tags and optionality; the three withheld arms and the
//! streaming callback's four arms are recorded, not stubbed.
//!
//! `pk7_lib.rs` transcribes `PKCS7_set_type`'s body for exactly those three arms; the three
//! withheld arms fall to the authority's own `default:` arm, which raises
//! `PKCS7_R_UNSUPPORTED_CONTENT_TYPE`. `pk7_doit.c` and `pk7_attr.c` raise nothing the corpus
//! names, so neither is transcribed.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod pk7_asn1;
pub mod pk7_lib;

pub use pk7_asn1::{
    PKCS7_DIGEST_free, PKCS7_DIGEST_it, PKCS7_DIGEST_new, PKCS7_ENCRYPT_free, PKCS7_ENCRYPT_it,
    PKCS7_ENCRYPT_new, PKCS7_ENC_CONTENT_free, PKCS7_ENC_CONTENT_it, PKCS7_ENC_CONTENT_new,
    PKCS7_free, PKCS7_it, PKCS7_new, PKCS7_new_ex, Pkcs7, Pkcs7Ctx, Pkcs7D, Pkcs7Digest,
    Pkcs7EncContent, Pkcs7Encrypt,
};
pub use pk7_lib::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_ctx_propagate,
    ossl_pkcs7_get0_ctx, ossl_pkcs7_set0_libctx, ossl_pkcs7_set1_propq, PKCS7_set_type,
};
