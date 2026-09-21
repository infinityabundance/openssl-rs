//! Phase 5 / Phase 9 — PEM: the encoding of a value as a `-----BEGIN …-----` block.
//!
//! The heading of the `pem.h` surface is deferred by *dependency* rather than by
//! preference. The reader and the writer are both built on `EVP_ENCODE_CTX`
//! (`crypto/evp/encode.c`), which is `evp.h`'s and therefore Phase 7's; the
//! password callback calls `EVP_read_pw_string_min`; the encrypted writer and reader
//! need `EVP_CIPHER`/`EVP_CIPHER_CTX` and `EVP_BytesToKey`; the signing pair needs
//! `EVP_MD_CTX`; and everything carrying a certificate, a request, an `X509_INFO` or
//! a private key needs the `X509` and `EVP_PKEY` types that Phase 7 and Phase 11
//! own.
//!
//! Three modules now live here, one per authority translation unit:
//!
//! ```text
//! src/pem/pem_lib.rs      <-  crypto/pem/pem_lib.c    (Phase 5's two header formatters,
//!                                                      then Phase 9's plumbing, D350)
//! src/pem/pem_oth.rs      <-  crypto/pem/pem_oth.c    (the "other PEM" reader, D350)
//! src/pem/key_legacy.rs   <-  crypto/pem/pem_all.c    (Phase 8.9's thirty `pem.h` names)
//! ```
//!
//! `crypto/pem/pem_lib.c`'s reader and writer are split between two modules for a
//! reason worth keeping in view: the block codec (`PEM_read_bio_ex`, `PEM_write_bio`,
//! `PEM_get_EVP_CIPHER_INFO`, `PEM_read`, `PEM_write`, `PEM_SignInit`/`Update`/`Final`)
//! landed in Phase 7's `src/evp/pem_bridge.rs`, because that is where `EVP_ENCODE_CTX`
//! is, and the password-and-plumbing half (`PEM_def_callback`, `PEM_bytes_read_bio`,
//! `PEM_do_header`, `PEM_ASN1_*`) landed in Phase 9. The two halves call each other in
//! both directions — `pem_bytes_read_bio_flags` calls `PEM_read_bio_ex`, and
//! `PEM_ASN1_write_bio_internal` calls `PEM_write_bio` — so one of the two imports must
//! cross the module boundary, and it does so in the dependency's direction.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod key_legacy;
pub mod pem_lib;
pub mod pem_oth;
