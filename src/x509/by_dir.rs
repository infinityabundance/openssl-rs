//! `crypto/x509/by_dir.c` — the `X509_LOOKUP_hash_dir` method: the hashed-directory lookup. **This
//! slice lands none of it**: like its sibling [`crate::x509::by_file`], the unit becomes a
//! documented module whose every name is withheld, each with the one unlanded dependency that
//! blocks it. `court/unit_ready.py` measures this unit's blocker set as `X509_get_default_cert_dir`
//! (`x509_def.c`), `X509_load_cert_file_ex` and `X509_load_crl_file` (`by_file.c`) — three names,
//! none of them a name this unit could land itself.
//!
//! `crypto/x509/by_dir.c` is 448 lines and publishes exactly one export, `X509_LOOKUP_hash_dir`
//! (`:77-80`), which returns the address of the file-static method row `x509_dir_lookup`
//! (`:62-75`). The row cannot be built while `dir_ctrl` and the two `get_cert_by_subject*` members
//! are withheld, so the export is withheld with them.
//!
//! ## Withheld by name, with each name's blocker
//!
//! * `X509_LOOKUP_hash_dir` (`:77-80`) and its table `x509_dir_lookup` (`:62-75`) — the method
//!   constructor. Its `ctrl`, `get_by_subject` and `get_by_subject_ex` slots are the three
//!   withheld callbacks below, so the row cannot be filled and the constructor waits on them.
//! * `dir_ctrl` (`:82-106`) — the method's control door. Its `X509_FILETYPE_DEFAULT` arm reads
//!   `X509_get_default_cert_dir` (`crypto/x509/x509_def.c`, Phase 11.7: a compile-time path built
//!   from the admitted build's forensic `OPENSSLDIR`, which the candidate distribution reports as
//!   `N/A`, so it is withheld there as a D451-class divergence). The env-var half —
//!   `ossl_safe_getenv` and `X509_get_default_cert_dir_env` — is landed. `dir_ctrl` is also the
//!   only caller of `add_cert_dir`, so the two are withheld together.
//! * `get_cert_by_subject_ex` (`:222-442`) and its wrapper `get_cert_by_subject` (`:444-448`) —
//!   the subject lookup. It builds a `hash.suffix` path per directory and loads each hit through
//!   `X509_load_cert_file_ex` and `X509_load_crl_file` (`crypto/x509/by_file.c`, withheld above),
//!   so it waits on the same 11.6 PEM X.509 readers that block `by_file.c`.
//! * The four supporting `static`s that exist only to serve the three names above —
//!   `new_dir` (`:108-132`), `free_dir` (`:156-164`), `add_cert_dir` (`:166-220`) and
//!   `get_cert_by_subject`'s helper closure `by_dir_hash_free` (`:134-137`),
//!   `by_dir_hash_cmp` (`:139-147`), `by_dir_entry_free` (`:149-154`) — together with the three
//!   layouts they operate on, `BY_DIR` (`:45-49`), `BY_DIR_HASH` (`:34-37`) and `BY_DIR_ENTRY`
//!   (`:39-43`). Each of these has a complete, landed closure — `BUF_MEM_*`, `CRYPTO_THREAD_*`,
//!   `OPENSSL_sk_*`, `OPENSSL_strndup` — but its only authority caller is a name withheld above, so
//!   it has **no reachable caller** and is withheld under the second reason `docs/DECISIONS.md`
//!   D453 names ("a function whose closure is complete is still withheld when no reachable caller
//!   exists"). They land with the table they belong to.
//!
//! The two callers of these — `X509_STORE_load_path` and `X509_STORE_set_default_paths(_ex)` in
//! [`crate::x509::x509_d2`] — are withheld for naming `X509_LOOKUP_hash_dir`, and land when 11.6
//! and 11.7 do.
//!
//! ## The raise sites
//!
//! `crypto/x509/by_dir.c` raises in `new_dir` (`:116`, `:123`), `add_cert_dir` (`:173`, `:198`,
//! `:214`), `dir_ctrl` (`:99`) and `get_cert_by_subject_ex` (`:250`, `:255`, `:271`, `:400`).
//! Every one is reachable only from a withheld name, so no coordinate is declared (the rule
//! `x509_lu.rs` applied to its own withheld `X509_STORE_new`).
//!
//! SPDX-License-Identifier: Apache-2.0
