//! `crypto/x509/t_acert.c` -- the attribute-certificate printer. Phase 11.3.
//!
//! `crypto/x509/t_acert.c` is 289 lines and publishes exactly two functions:
//! `X509_ACERT_print_ex` (`:83-284`) and its `X509_ACERT_print` wrapper (`:286-289`), plus the
//! file-local `print_attribute` helper (`:17-81`). **Both exports are withheld here, with their
//! blocker named, rather than stubbed or partially transcribed.**
//!
//! ## Why the whole unit is withheld
//!
//! `X509_ACERT_print_ex` prints every section of the certificate and finally, when
//! `X509_FLAG_NO_SIGDUMP` is clear, reaches
//!
//! ```text
//! X509_ACERT_get0_signature(x, &sig, &sig_alg);
//! if (X509_signature_print(bp, sig_alg, sig) <= 0)      /* t_acert.c:275 */
//!     return 0;
//! ```
//!
//! `X509_signature_print` is `crypto/x509/t_x509.c`'s (`:292-316`), and that unit is **not
//! landed** -- it is one of the nine printers `src/x509/t_x509.rs` withholds by name, and the
//! candidate distribution shell still scaffolds it. The same is true of every other printer in
//! this stratum: `crypto/x509/t_req.rs`'s `X509_REQ_print*` and `crypto/x509/t_crl.rs`'s
//! `X509_CRL_print*` are open in the ledger for the same reason, and `crypto/asn1/t_spki.c`'s
//! `NETSCAPE_SPKI_print` with them. `X509_ACERT_print` is `X509_ACERT_print_ex` under
//! `XN_FLAG_COMPAT`/`X509_FLAG_COMPAT` (`= 0`), so its `cflag` carries no `X509_FLAG_NO_SIGDUMP`
//! bit and it *always* takes that arm.
//!
//! Every other callee of the pair is landed -- `X509_ACERT_get_version`/`get0_serialNumber`/
//! `get0_holder_entityName`/`get0_holder_baseCertId`/`get0_holder_digest`/`get0_issuerName`/
//! `get0_issuerUID`/`get0_notBefore`/`get0_notAfter`/`get0_signature`/`get0_extensions`/
//! `get_attr_count`/`get_attr` (this module's sibling, `src/x509/x509_acert.rs`),
//! `X509_ATTRIBUTE_get0_object`/`_count`/`_get0_type` (`src/x509/x_attrib.rs`),
//! `GENERAL_NAME_print` (`src/x509/v3_san.rs`), `X509_NAME_print_ex` (`src/asn1/a_strex.rs`),
//! `X509_signature_dump` (`src/x509/t_x509.rs`), `X509V3_EXT_print` (`src/x509/v3_prn.rs`),
//! `i2a_ASN1_OBJECT`/`i2a_ASN1_INTEGER`/`ASN1_parse_dump`/`ASN1_STRING_print`
//! (`src/asn1/`) and `ASN1_GENERALIZEDTIME_print` (`src/asn1/time.rs`). The single unlanded
//! name is `X509_signature_print`, and it is outside this slice's authority units.
//!
//! ## The raise sites
//!
//! For the record of what a later slice must transcribe: the unit raises
//! `ERR_raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES)` for a zero-count attribute
//! (`t_acert.c:32`) and `ERR_raise(ERR_LIB_X509, ERR_R_BUF_LIB)` from its `err:` label
//! (`t_acert.c:282`).
//!
//! SPDX-License-Identifier: Apache-2.0
