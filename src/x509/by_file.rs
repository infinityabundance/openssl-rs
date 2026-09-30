//! `crypto/x509/by_file.c` — the `X509_LOOKUP_file` method and its two file loaders. **This slice
//! lands none of it**: the unit becomes a documented module whose every name is withheld, each
//! with the one unlanded dependency that blocks it. It is the shape D454 gave `x509rset.rs` — "a
//! module that is a doc and three withholds is the honest shape when the unit cannot be named yet"
//! (`docs/DECISIONS.md`) — and it is the shape `court/unit_ready.py` measures for this unit: six
//! blockers, none of them a name this unit could land itself.
//!
//! `crypto/x509/by_file.c` is 284 lines. Its two loaders read a certificate bundle through the
//! `pem.h` X.509 readers, which are Phase 11.6's (`pem_all.c`, `pem_xaux.c`, `pem_info.c`), plus
//! the `X509_INFO` item that is `crypto/asn1/x_info.c`'s; its `ctrl` door also reads the
//! compiled-in certificate-bundle path, which is `x509_def.c`'s and Phase 11.7's. Every name below
//! sits behind one of those, so **the unit cannot be transcribed whole and nothing in it is
//! transcribed** — a reader cannot be written that calls a function no module defines
//! (`docs/DECISIONS.md` D369's rule, applied to `pem_all.c`'s six readers the same way).
//!
//! ## Withheld by name, with each name's blocker
//!
//! The six open exports and the three `static` members they are built on:
//!
//! * `X509_LOOKUP_file` (`:41-44`) and its table `x509_file_lookup` (`:26-39`) — the method
//!   constructor. The table's `ctrl`/`ctrl_ex` slots are `by_file_ctrl`/`by_file_ctrl_ex`, both
//!   withheld below, so the row cannot be built and the constructor is withheld with it.
//! * `by_file_ctrl_ex` (`:46-82`) and `by_file_ctrl` (`:84-88`) — the method's control door. It
//!   calls `X509_load_cert_crl_file_ex`/`X509_load_cert_file_ex` (this unit, withheld below) and,
//!   in the `X509_FILETYPE_DEFAULT` arm, `X509_get_default_cert_file` (`crypto/x509/x509_def.c`,
//!   Phase 11.7: its path is built from the admitted build's forensic `OPENSSLDIR`, so it is
//!   withheld there as a D451-class divergence).
//! * `X509_load_cert_file_ex` (`:90-165`) and its wrapper `X509_load_cert_file` (`:167-170`) — the
//!   certificate-file loader. Its `X509_FILETYPE_ASN1` arm reaches the landed `d2i_X509_bio`
//!   (`x_all.rs`), but its `X509_FILETYPE_PEM` arm calls `PEM_read_bio_X509_AUX`
//!   (`crypto/pem/pem_xaux.c`, Phase 11.6), so the whole function waits on it.
//! * `X509_load_crl_file` (`:172-230`) — the CRL-file loader. Its PEM arm calls
//!   `PEM_read_bio_X509_CRL` (`crypto/pem/pem_all.c`, Phase 11.6); its ASN.1 arm reaches the
//!   landed `d2i_X509_CRL_bio`.
//! * `X509_load_cert_crl_file_ex` (`:232-279`) and its wrapper `X509_load_cert_crl_file`
//!   (`:281-284`) — the mixed loader, and the one the control door's PEM arm calls. It reads
//!   through `PEM_X509_INFO_read_bio_ex` (`crypto/pem/pem_info.c`, Phase 11.6) into an
//!   `X509_INFO` (`crypto/asn1/x_info.c`, Phase 11.7: both the item and its `X509_INFO_free`),
//!   so it waits on both phases.
//!
//! The three callers of these — `X509_LOOKUP_file`, `X509_STORE_load_file(_ex)` and
//! `X509_STORE_set_default_paths(_ex)` in [`crate::x509::x509_d2`] — are withheld for naming
//! `X509_LOOKUP_file`, and land when 11.6 and 11.7 do.
//!
//! Every callee that is *not* named above is landed: `ossl_safe_getenv` and the two
//! `X509_get_default_cert_*_env` accessors (`x509_def.rs`), `BIO_new`/`BIO_s_file`/
//! `BIO_read_filename`/`BIO_free`, `X509_new_ex`/`X509_free`,
//! [`X509_STORE_add_cert`](crate::x509::x509_lu::X509_STORE_add_cert)/
//! [`X509_STORE_add_crl`](crate::x509::x509_lu::X509_STORE_add_crl) and the `ERR_*` queue. What
//! waits is the PEM X.509 container surface, and only that.
//!
//! ## The raise sites
//!
//! `crypto/x509/by_file.c` raises in `by_file_ctrl_ex` (`:68`) and in both loaders (`:98`, `:105`,
//! `:111`, `:125`, `:127`, `:145`, `:153`, `:158`, `:179`, `:185`, `:199`, `:201`, `:218`, `:223`,
//! `:248`, `:254`, `:275`). Every one of them is reachable only from a withheld name, so no
//! coordinate is declared (the rule `x509_lu.rs` applied to its own withheld `X509_STORE_new`).
//!
//! SPDX-License-Identifier: Apache-2.0
