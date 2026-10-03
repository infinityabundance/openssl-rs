//! `crypto/pkcs7/` — the `PKCS7` container: the six content types, their item groups, the
//! sign/verify/envelop/decrypt chain and the S/MIME wrappers. Phase 12.2.
//!
//! Phase 10 landed a pulled-forward subset (the `data`, `digest` and `encrypted` arms and the
//! five `ossl_pkcs7_*` context helpers) because PKCS#12's `PFX` reaches the object; Phase 12.2
//! lands the rest of the unit, so the withholding tables the Phase-10 modules carried are gone:
//!
//! * `pk7_asn1.rs` now carries all six `ASN1_ADB(PKCS7)` arms — `data`, `signed`, `enveloped`,
//!   `signedAndEnveloped`, `digest` and `encrypted` — over Phase 11's landed `X509_it`,
//!   `X509_CRL_it` and `X509_NAME_it`, and the streaming callback's four arms, which reach the
//!   landed `PKCS7_stream`/`PKCS7_dataInit`/`PKCS7_dataFinal`.
//! * `pk7_lib.rs` carries every `PKCS7_set_type` arm and the signer, certificate, recipient and
//!   cipher surface.
//! * `pk7_doit.rs`, `pk7_attr.rs`, `pk7_smime.rs`, `pk7_mime.rs` and `bio_pk7.rs` are new.
//!
//! The `SMIME_read_ASN1_ex`/`SMIME_write_ASN1_ex`/`SMIME_text` delegates remain Phase 12.9's
//! `crypto/asn1/asn_mime.c` hand-off; `pk7_mime.rs` and `pk7_smime.rs` name them as the
//! authority's own prototypes rather than re-landing the unit.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod bio_pk7;
pub mod pk7_asn1;
pub mod pk7_attr;
pub mod pk7_doit;
pub mod pk7_lib;
pub mod pk7_mime;
pub mod pk7_smime;

pub use bio_pk7::BIO_new_PKCS7;
pub use pk7_asn1::{
    d2i_PKCS7, d2i_PKCS7_DIGEST, d2i_PKCS7_ENCRYPT, d2i_PKCS7_ENC_CONTENT, d2i_PKCS7_ENVELOPE,
    d2i_PKCS7_ISSUER_AND_SERIAL, d2i_PKCS7_RECIP_INFO, d2i_PKCS7_SIGNED, d2i_PKCS7_SIGNER_INFO,
    d2i_PKCS7_SIGN_ENVELOPE, i2d_PKCS7, i2d_PKCS7_DIGEST, i2d_PKCS7_ENCRYPT, i2d_PKCS7_ENC_CONTENT,
    i2d_PKCS7_ENVELOPE, i2d_PKCS7_ISSUER_AND_SERIAL, i2d_PKCS7_NDEF, i2d_PKCS7_RECIP_INFO,
    i2d_PKCS7_SIGNED, i2d_PKCS7_SIGNER_INFO, i2d_PKCS7_SIGN_ENVELOPE, PKCS7_ATTR_SIGN_it,
    PKCS7_ATTR_VERIFY_it, PKCS7_DIGEST_free, PKCS7_DIGEST_it, PKCS7_DIGEST_new, PKCS7_ENCRYPT_free,
    PKCS7_ENCRYPT_it, PKCS7_ENCRYPT_new, PKCS7_ENC_CONTENT_free, PKCS7_ENC_CONTENT_it,
    PKCS7_ENC_CONTENT_new, PKCS7_ENVELOPE_free, PKCS7_ENVELOPE_it, PKCS7_ENVELOPE_new,
    PKCS7_ISSUER_AND_SERIAL_free, PKCS7_ISSUER_AND_SERIAL_it, PKCS7_ISSUER_AND_SERIAL_new,
    PKCS7_RECIP_INFO_free, PKCS7_RECIP_INFO_it, PKCS7_RECIP_INFO_new, PKCS7_SIGNED_free,
    PKCS7_SIGNED_it, PKCS7_SIGNED_new, PKCS7_SIGNER_INFO_free, PKCS7_SIGNER_INFO_it,
    PKCS7_SIGNER_INFO_new, PKCS7_SIGN_ENVELOPE_free, PKCS7_SIGN_ENVELOPE_it,
    PKCS7_SIGN_ENVELOPE_new, PKCS7_dup, PKCS7_free, PKCS7_it, PKCS7_new, PKCS7_new_ex,
    PKCS7_print_ctx, Pkcs7, Pkcs7Ctx, Pkcs7D, Pkcs7Digest, Pkcs7EncContent, Pkcs7Encrypt,
    Pkcs7Envelope, Pkcs7IssuerAndSerial, Pkcs7RecipInfo, Pkcs7SignEnvelope, Pkcs7Signed,
    Pkcs7SignerInfo,
};
pub use pk7_attr::{
    PKCS7_add0_attrib_signing_time, PKCS7_add1_attrib_digest, PKCS7_add_attrib_content_type,
    PKCS7_add_attrib_smimecap, PKCS7_get_smimecap, PKCS7_simple_smimecap,
};
pub use pk7_doit::{
    PKCS7_SIGNER_INFO_sign, PKCS7_add_attribute, PKCS7_add_signed_attribute, PKCS7_dataDecode,
    PKCS7_dataFinal, PKCS7_dataInit, PKCS7_dataVerify, PKCS7_digest_from_attributes,
    PKCS7_get_attribute, PKCS7_get_issuer_and_serial, PKCS7_get_octet_string,
    PKCS7_get_signed_attribute, PKCS7_set_attributes, PKCS7_set_signed_attributes,
    PKCS7_signatureVerify, PKCS7_type_is_other,
};
pub use pk7_lib::{
    ossl_pkcs7_ctx_get0_libctx, ossl_pkcs7_ctx_get0_propq, ossl_pkcs7_ctx_propagate,
    ossl_pkcs7_get0_ctx, ossl_pkcs7_resolve_libctx, ossl_pkcs7_set0_libctx, ossl_pkcs7_set1_propq,
    PKCS7_RECIP_INFO_get0_alg, PKCS7_RECIP_INFO_set, PKCS7_SIGNER_INFO_get0_algs,
    PKCS7_SIGNER_INFO_set, PKCS7_add_certificate, PKCS7_add_crl, PKCS7_add_recipient,
    PKCS7_add_recipient_info, PKCS7_add_signature, PKCS7_add_signer, PKCS7_cert_from_signer_info,
    PKCS7_content_new, PKCS7_ctrl, PKCS7_get_signer_info, PKCS7_set0_type_other, PKCS7_set_cipher,
    PKCS7_set_content, PKCS7_set_digest, PKCS7_set_type, PKCS7_stream,
};
pub use pk7_mime::{
    i2d_PKCS7_bio_stream, PEM_write_bio_PKCS7_stream, SMIME_read_PKCS7, SMIME_read_PKCS7_ex,
    SMIME_write_PKCS7,
};
pub use pk7_smime::{
    PKCS7_decrypt, PKCS7_encrypt, PKCS7_encrypt_ex, PKCS7_final, PKCS7_get0_signers, PKCS7_sign,
    PKCS7_sign_add_signer, PKCS7_sign_ex, PKCS7_verify,
};
