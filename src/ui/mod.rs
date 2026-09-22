//! Phase 13 staging — `crypto/ui/`: the `UI` program the password path is built on.
//!
//! This directory lands three of `crypto/ui/`'s translation units, each as one module named for
//! its file, because the transcription atlas maps a crate module to the authority unit its
//! definitions dominantly come from (`forensics/atlas/transcription-edges.json`'s
//! `build_edges`):
//!
//! ```text
//! src/ui/ui_lib.rs      <-  crypto/ui/ui_lib.c       (whole: 57 exports)
//! src/ui/ui_openssl.rs  <-  crypto/ui/ui_openssl.c   (the platform's console method)
//! src/ui/ui_null.rs     <-  crypto/ui/ui_null.c      (the do-nothing method)
//! src/ui/ui_util.rs     <-  crypto/ui/ui_util.c      (the three `UI_UTIL_*` exports, D358)
//! ```
//!
//! `crypto/ui/ui_err.c` is **not** here. It defines no exports at all -- it is the reason-string
//! table, and this crate's `src/runtime/err_reasons.rs` already carries every `UI_R_*` code from
//! the installed `uierr.h`, read by `gen_err_reasons.py` rather than by hand.
//!
//! `crypto/ui/ui_util.c` was deliberately absent until D358: its three exports are not on the
//! `EVP_read_pw_string_min -> PEM_def_callback -> PEM_do_header` chain this directory first landed
//! for, because `EVP_read_pw_string_min` is `UI_new`/`UI_add_*`/`UI_process`/`UI_free` and nothing
//! else. It is here now for a different caller: `crypto/passphrase.c`'s `ossl_pw_get_passphrase`
//! calls `UI_UTIL_wrap_read_pem_callback` to bridge a `pem_password_cb` to a `UI_METHOD`, and the
//! encoder's `encoder_process` needs that dispatcher. See `src/ui/ui_util.rs`'s module doc.
//!
//! ## What this directory is for, one stratum early
//!
//! The chain is what makes these units landable together with the PEM plumbing: `PEM_def_callback`
//! (`crypto/pem/pem_lib.c:36`) is `EVP_read_pw_string_min`, which is this program. Building the
//! PEM half without the UI half would be a module whose own doc names a symbol no crate function
//! defines. The obligation move each unit makes is recorded where it belongs:
//! `EVP_read_pw_string*` are Phase 7's names and this slice moves *Phase 7's* ledger,
//! `PEM_def_callback`/`PEM_ASN1_*`/`PEM_bytes_read_bio*`/`PEM_do_header` move Phase 9's, and the
//! thirty `pem.h` helpers move Phase 8's. No `UI_*` export is in any phase ledger yet — `ui.h` is
//! Phase 13's and Phase 13 has no ledger — so the 61 `UI_*` exports below are recorded in
//! `implemented-surface.json` and in no obligation ledger's `implemented` list.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod ui_lib;
pub mod ui_null;
pub mod ui_openssl;
pub mod ui_util;
