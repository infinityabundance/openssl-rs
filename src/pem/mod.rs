//! Phase 5 — PEM: the encoding of a value as a `-----BEGIN …-----` block.
//!
//! The heading of the `pem.h` surface is deferred by *dependency* rather than by
//! preference. The reader and the writer are both built on `EVP_ENCODE_CTX`
//! (`crypto/evp/encode.c`), which is `evp.h`'s and therefore Phase 7's; the
//! password callback calls `EVP_read_pw_string_min`; the encrypted writer and reader
//! need `EVP_CIPHER`/`EVP_CIPHER_CTX` and `EVP_BytesToKey`; the signing pair needs
//! `EVP_MD_CTX`; and everything carrying a certificate, a request, an `X509_INFO` or
//! a private key needs the `X509` and `EVP_PKEY` types that Phase 7 and Phase 11
//! own. `forensics/phase5-obligations.json` records each of those with the
//! dependency it is waiting on.
//!
//! What this module holds is the two exports of `crypto/pem/pem_lib.c` that need
//! nothing but `BIO_snprintf`: [`pem_lib::PEM_proc_type`] and
//! [`pem_lib::PEM_dek_info`]. Both *append* to the caller's `PEM_BUFSIZE` buffer,
//! which is how `PEM_ASN1_write_bio_internal` assembles a header before writing the
//! item itself.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod pem_lib;
