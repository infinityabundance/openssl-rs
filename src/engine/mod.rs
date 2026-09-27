//! Phase 10.9 — the digest substrate: the engine registry `X509_digest` reaches through
//! `ossl_asn1_item_digest_ex`, plus the string and character-class units that same
//! authority path is written over.
//!
//! ## Why this subphase exists
//!
//! `X509_digest` (`crypto/x509/x_all.c:498`) calls `ossl_asn1_item_digest_ex`
//! (`crypto/asn1/a_digest.c:54`), which asks the engine registry for a functional
//! reference — `ENGINE_get_digest_engine(EVP_MD_get_type(md))` (`:68`) — and releases it
//! with `ENGINE_finish` (`:71`). Section 6 of `docs/PHASE-10-SUBPHASES.md` measured the
//! closure of that call as twelve authority units and 2,975 lines:
//!
//! ```text
//! crypto/engine/eng_all.c     (24)   crypto/o_str.c      (451)
//! crypto/engine/eng_ctrl.c   (318)   crypto/ctype.c      (313)
//! crypto/engine/eng_init.c   (121)   crypto/defaults.c   (206)
//! crypto/engine/eng_lib.c    (309)
//! crypto/engine/eng_list.c   (484)
//! crypto/engine/eng_table.c  (316)
//! crypto/engine/tb_asnmth.c  (221)
//! crypto/engine/tb_digest.c   (95)
//! crypto/engine/tb_pkmeth.c  (117)
//! ```
//!
//! D451's correction governs what "land" means: the frontier is the **call graph**, not
//! the unit, so each module lands every function whose closure is landed and withholds by
//! name every function whose closure is not. This module directory is that landing.
//!
//! ## What lands, and what is withheld by name
//!
//! **Landed, whole:**
//!
//! * `crypto/engine/eng_ctrl.c` — `eng_ctrl.rs`. Self-contained: libc and `ERR` only.
//! * `crypto/engine/eng_init.c` — `eng_init.rs`. The functional-reference pair.
//! * `crypto/engine/eng_table.c` — `eng_table.rs`. The implementation table the select is.
//! * `crypto/engine/eng_list.c`'s list core — `eng_list.rs` (see the withhold below).
//! * `crypto/engine/eng_lib.c`'s object and registry core — `eng_lib.rs`.
//! * `crypto/engine/tb_digest.c`, `tb_pkmeth.c`, `tb_asnmth.c` — the three algorithm
//!   tables `engine_free_util` and the digest path name.
//!
//! **Already landed, before this subphase, and therefore not re-transcribed:**
//!
//! * `crypto/ctype.c` — `src/runtime/ctype.rs` (Phase 5) plus the generated
//!   `src/runtime/ctype_table.rs`. Every class the engine files use is present.
//! * `crypto/o_str.c` — `src/runtime/str.rs` (Phase 3, D51) and `src/runtime/mem.rs`'s
//!   `CRYPTO_strdup`/`_strndup`/`_memdup`. Nothing the twelve units call is missing.
//! * `crypto/defaults.c` — only `ossl_get_modulesdir` was reachable before this subphase
//!   (`src/runtime/defaults.rs`). Its `ossl_get_enginesdir` is the one this stratum could
//!   add, but its **only** caller is `ENGINE_by_id` (`eng_list.c:462`), which is withheld
//!   (below); it is therefore still withheld, with the same blocker, rather than landed
//!   dark. `ossl_get_openssldir` and `ossl_get_wininstallcontext` stay Phase 16's.
//!
//! **Withheld by name, each with its blocker:**
//!
//! * `ENGINE_load_builtin_engines` (`eng_all.c`) — the crate's `OPENSSL_init_crypto`
//!   refuses the `ENGINE_*` bits (`src/runtime/init.rs:254`), so the call it is would
//!   diverge on every invocation. See `eng_all.rs`.
//! * `ENGINE_by_id` (`eng_list.c:408-473`) — its closure names the withheld
//!   `ENGINE_load_builtin_engines` and the dynamic engine (`crypto/engine/eng_dyn.c`, not
//!   this stratum's unit). See `eng_list.rs`.
//! * `engine_cleanup_int` (`eng_lib.c:175-184`) — its closure is landed, but the crate's
//!   landed `OPENSSL_cleanup` does not yet name it. See `eng_lib.rs`.
//! * `ENGINE_get_pkey_meth` (`tb_pkmeth.c:74-83`) — its only caller is Phase 7's deferred
//!   `EVP_PKEY_set1_engine`. See `tb_pkmeth.rs`.
//! * `crypto/engine/eng_dyn.c`, `eng_cnf.c`, `eng_fat.c`, `eng_err.c`, `eng_pkey.c`,
//!   `eng_openssl.c`, `eng_rdrand.c` and `tb_cipher.c`/`tb_rsa.c`/`tb_dsa.c`/`tb_dh.c`/
//!   `tb_eckey.c`/`tb_rand.c` — not among section 6's twelve; the dynamic engine, the
//!   config module, the five legacy method tables and the key loaders are therefore not
//!   transcribed, which is what leaves the withholds above genuinely blocked.
//!
//! ## Ownership is unchanged
//!
//! Every `ENGINE_*` export the atlas assigns to Phase 13 stays Phase 13's: this subphase
//! defines the symbols but creates no Phase-10 export, no provider row, and no Phase 11
//! evidence, ledger, plan, seal or state row. `phase_state.py` still derives Phase 11
//! `not-started`.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod eng_all;
pub mod eng_ctrl;
pub mod eng_init;
pub mod eng_lib;
pub mod eng_list;
pub mod eng_table;
pub mod tb_asnmth;
pub mod tb_digest;
pub mod tb_pkmeth;
