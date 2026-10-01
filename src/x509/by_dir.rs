//! `crypto/x509/by_dir.c` — the `X509_LOOKUP_hash_dir` method: the hashed-directory lookup. **This
//! slice lands none of it**: like its sibling [`crate::x509::by_file`] (whose five loaders this
//! unit's only export reaches), the unit stays a documented module whose every name is withheld.
//! Its sole remaining blocker is `X509_get_default_cert_dir` (`x509_def.c`) — not a name this unit
//! could land itself. (The one other name `court/unit_ready.py` lists, `ossl_safe_getenv`, is
//! landed in `src/runtime/getenv.rs`; unit_ready reports it because `ossl_safe_getenv` is not an
//! exported `libcrypto` symbol, not because it is missing.) The two names that once also blocked
//! it — `X509_load_cert_file_ex` and `X509_load_crl_file` (`crypto/x509/by_file.c`) — are
//! **discharged**: 11.6's PEM X.509 readers landed, and this slice's sibling now transcribes both
//! loaders.
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
//!   `X509_get_default_cert_dir` (`crypto/x509/x509_def.c:88-96`). That name is withheld in its own
//!   unit as a D451-class divergence: its answer is a compile-time path built from the admitted
//!   build's forensic `OPENSSLDIR`, while the candidate distribution reports `OPENSSLDIR: N/A`
//!   (`src/runtime/init.rs:1133`) and the directory plane is Phase 16's (`ossl_get_openssldir`,
//!   `src/runtime/defaults.rs`). The candidate's symbol of that name is a **scaffolded abort**
//!   (`artifacts/phase2/shell/libcrypto.shell.rs:5767`), so a transcription that called it would
//!   abort on every `X509_FILETYPE_DEFAULT` add rather than add the default directory — the reason
//!   the name is left withheld rather than stubbed. The env-var half — `ossl_safe_getenv`
//!   (`runtime/getenv.rs`) and `X509_get_default_cert_dir_env` (`x509_def.rs`) — is landed.
//!   `dir_ctrl` is also the only caller of `add_cert_dir`, so the two are withheld together.
//! * `get_cert_by_subject_ex` (`:222-442`) and its wrapper `get_cert_by_subject` (`:444-448`) —
//!   the subject lookup. Its two loader calls are now landed
//!   ([`X509_load_cert_file_ex`](crate::x509::by_file::X509_load_cert_file_ex) and
//!   [`X509_load_crl_file`](crate::x509::by_file::X509_load_crl_file)), but its `#ifndef
//!   OPENSSL_NO_POSIX_IO` existence probe (`by_dir.c:326-337`) needs the `lstat`/`stat` pair, for
//!   which the crate has **no landed binding** (the only `stat` wrapper,
//!   `rand/sys.rs`'s `pub(crate) fn stat`, is RAND's own private one and there is no `lstat` at
//!   all), so it cannot be transcribed faithfully yet. It would in any case be withheld under the
//!   second reason `docs/DECISIONS.md` D453 names ("a function whose closure is complete is still
//!   withheld when no reachable caller exists"): its only authority callers are
//!   `x509_dir_lookup`'s `get_by_subject`/`get_by_subject_ex` slots, and that row is withheld for
//!   `dir_ctrl` above.
//! * The four supporting `static`s that exist only to serve the names above —
//!   `new_dir` (`:108-132`), `free_dir` (`:156-164`), `add_cert_dir` (`:166-220`) and
//!   `get_cert_by_subject`'s helper closure `by_dir_hash_free` (`:134-137`),
//!   `by_dir_hash_cmp` (`:139-147`), `by_dir_entry_free` (`:149-154`) — together with the three
//!   layouts they operate on, `BY_DIR` (`:45-49`), `BY_DIR_HASH` (`:34-37`) and `BY_DIR_ENTRY`
//!   (`:39-43`). Each of these has a complete, landed closure — `BUF_MEM_*`, `CRYPTO_THREAD_*`,
//!   `OPENSSL_sk_*`, `CRYPTO_strndup` (the `OPENSSL_strndup` macro) — but its only authority caller
//!   is a name withheld above, so it has **no reachable caller** and is withheld under the same D453
//!   reason. They land with the table they belong to.
//!
//! The two callers of these — `X509_STORE_load_path` and `X509_STORE_set_default_paths(_ex)` in
//! [`crate::x509::x509_d2`] — are withheld for naming `X509_LOOKUP_hash_dir`, and land when 11.7
//! (and the `lstat`/`stat` binding) does.
//!
//! ## The raise sites
//!
//! `crypto/x509/by_dir.c` raises in `new_dir` (`:116`, `:123`), `add_cert_dir` (`:173`, `:198`,
//! `:214`), `dir_ctrl` (`:99`) and `get_cert_by_subject_ex` (`:250`, `:255`, `:271`, `:400`).
//! Every one is reachable only from a withheld name, so no coordinate is declared (the rule
//! `x509_lu.rs` applied to its own withheld `X509_STORE_new`).
//!
//! SPDX-License-Identifier: Apache-2.0
