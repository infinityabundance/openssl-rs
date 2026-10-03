//! Phase 10.9 — the digest substrate: the engine registry `X509_digest` reaches through
//! `ossl_asn1_item_digest_ex`, plus the string and character-class units that same
//! authority path is written over. Phase 13.1 adds the registry's public entry points and
//! the built-in/config loaders.
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
//! name every function whose closure is not. This module directory is that landing, and
//! Phase 13.1 is the subphase that closes the three exports 10.9 could not.
//!
//! ## What lands, and what is withheld by name
//!
//! **Landed, whole:**
//!
//! * `crypto/engine/eng_ctrl.c` — `eng_ctrl.rs`. Self-contained: libc and `ERR` only.
//! * `crypto/engine/eng_init.c` — `eng_init.rs`. The functional-reference pair.
//! * `crypto/engine/eng_table.c` — `eng_table.rs`. The implementation table the select is.
//! * `crypto/engine/eng_list.c` — `eng_list.rs`. The list core 10.9 landed, plus 13.1's
//!   `ENGINE_by_id` and the `ENGINE_FLAGS_BY_ID_COPY` helpers it reaches.
//! * `crypto/engine/eng_lib.c`'s object and registry core — `eng_lib.rs`.
//! * `crypto/engine/tb_digest.c`, `tb_pkmeth.c`, `tb_asnmth.c` — the three algorithm
//!   tables `engine_free_util` and the digest path name.
//!
//! **Phase 13.1 lands three more exports, closing the plan's three open rows:**
//!
//! * `crypto/engine/eng_all.c` — `eng_all.rs`, `ENGINE_load_builtin_engines` (`:13-16`).
//! * `crypto/engine/eng_list.c`'s `ENGINE_by_id` (`:408-473`).
//! * `crypto/engine/eng_cnf.c` — `eng_cnf.rs`, `ENGINE_add_conf_module` (`:180-184`) and the
//!   `engines` configuration module's init/finish callbacks.
//!
//! **Already landed, before this subphase, and therefore not re-transcribed:**
//!
//! * `crypto/ctype.c` — `src/runtime/ctype.rs` (Phase 5) plus the generated
//!   `src/runtime/ctype_table.rs`. Every class the engine files use is present.
//! * `crypto/o_str.c` — `src/runtime/str.rs` (Phase 3, D51) and `src/runtime/mem.rs`'s
//!   `CRYPTO_strdup`/`_strndup`/`_memdup`. Nothing the twelve units call is missing.
//! * `crypto/defaults.c` — `src/runtime/defaults.rs`. 10.9 landed `ossl_get_modulesdir`
//!   (Phase 6.8c); 13.1 adds its twin `ossl_get_enginesdir`, whose only caller is
//!   `ENGINE_by_id` (`eng_list.c:462`). `ossl_get_openssldir` and
//!   `ossl_get_wininstallcontext` stay Phase 16's.
//!
//! **Withheld by name, each with its blocker:**
//!
//! * `engine_cleanup_int` (`eng_lib.c:175-184`) — its closure is landed, but the crate's
//!   landed `OPENSSL_cleanup` does not yet name it. See `eng_lib.rs`.
//! * `ENGINE_get_pkey_meth` (`tb_pkmeth.c:74-83`) — its only caller is Phase 7's deferred
//!   `EVP_PKEY_set1_engine`. See `tb_pkmeth.rs`.
//! * `crypto/engine/eng_dyn.c` — the dynamic engine `ENGINE_by_id`'s miss path would drive.
//!   No subphase owns it yet, so no dynamic engine is registered and the recursion answers
//!   NULL; `ENGINE_by_id` transcribes the authority's own `goto notfound` for that arm.
//! * `crypto/engine/eng_fat.c`, `eng_err.c`, `eng_pkey.c`, `eng_openssl.c`, `eng_rdrand.c`
//!   and `tb_cipher.c`/`tb_rsa.c`/`tb_dsa.c`/`tb_dh.c`/`tb_eckey.c`/`tb_rand.c` — later
//!   13.x subphases' units; the five legacy method tables, the key loaders and the built-in
//!   `openssl`/`rdrand` engines are therefore not transcribed.
//!
//! ## Ownership is unchanged
//!
//! Every `ENGINE_*` export the atlas assigns to Phase 13 stays Phase 13's: 10.9 defined
//! symbols but created no Phase-10 export, no provider row, and no Phase 11 evidence. 13.1
//! moves three Phase-13 rows from open to implemented in
//! `forensics/phase13-obligations.json`; `phase_state.py` still holds Phase 13 `in-progress`.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod eng_all;
pub mod eng_cnf;
pub mod eng_ctrl;
pub mod eng_init;
pub mod eng_lib;
pub mod eng_list;
pub mod eng_table;
pub mod tb_asnmth;
pub mod tb_digest;
pub mod tb_pkmeth;
