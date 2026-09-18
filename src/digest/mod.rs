//! Phase 8.1a — the native digest primitives.
//!
//! `docs/PHASE-8-SUBPHASES.md` is this stratum's plan and `forensics/phase8-obligations.json`
//! is its arithmetic. This module is the first half of 8.1: the **constructions** — MD4, MD5,
//! RIPEMD-160, Whirlpool, SHA-1 and the two SHA-2 widths — with their low-level
//! `X_Init`/`X_Update`/`X_Final`/`X_Transform` exports and the one-shot spellings that are
//! written over them.
//!
//! ## What 8.1 has two halves of, and which half this is
//!
//! The plan's 8.1 row is one subphase with two dependencies, and the split is a measurement
//! rather than a size boundary (`docs/DECISIONS.md` D197):
//!
//! * **8.1a — this module.** The constructions and their collector. Thirty-eight exports.
//! * **8.1b — the provider half.** `PROV_DIGEST` and `providers/implementations/digests/`,
//!   the internal `ossl_sm3_*`/`ossl_sha3_*`/`sha512_224_init` families, and the digest half
//!   of `ossl_default_provider_init`. It lands with what it needs, and it is what makes
//!   **`SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512` themselves** work: those five one-shots are
//!   `EVP_Q_digest(NULL, …)` (`crypto/sha/sha1_one.c:36-70`), so they fetch the digest through
//!   the default library context and are the provider's, not the construction's. `MD4`, `MD5`,
//!   `RIPEMD160` and `WHIRLPOOL` are one-shots in the older sense and are here.
//!
//! ## What is *not* here, and why that is a reading rather than an omission
//!
//! * **MDC2.** The plan's 8.1 row names it and it cannot be written here: its body is
//!   `DES_set_odd_parity`, `DES_set_key_unchecked` and `DES_encrypt1`
//!   (`crypto/mdc2/mdc2dgst.c:79-85`), which are 8.2's. The inversion is recorded in the
//!   plan and MDC2's four labels stay in the ledger's `open` list.
//! * **A low-level SHA-3, SHAKE, SHA-512/224, SHA-512/256 or SM3 API.** The authority
//!   exports none: `include/openssl/sha.h` declares no `SHA3_*` and no `SHAKE*`, the symbol
//!   inventory has no record for `SHA3_absorb` or `SHA3_squeeze`, and `crypto/sha/sha3.c`'s
//!   and `crypto/sm3/sm3.c`'s entry points are `ossl_*`. Those constructions are provider
//!   work with nothing to export, and they are 8.1b's.
//!
//! ## The tables are generated, the structure is transcribed
//!
//! Every round constant, message-word order and rotation this module reads comes from
//! [`crate::digest::tables`], which `forensics/tools/gen_phase8_tables.py` derives from the
//! authority's own `crypto/` sources on every run (`docs/DECISIONS.md` D33). What is written
//! by hand is the *structure* — the register cycles, the round function selection, the
//! collector's two length words — and `RT-DIGEST` is what decides whether it is the same
//! function the authority publishes: the same probe program compiled against both libraries,
//! comparing digest bytes, sizes, split updates, boundary lengths and `Transform`.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod md32;
pub mod md4;
pub mod md5;
pub mod md5_sha1;
pub mod ripemd;
pub mod sha1;
pub mod sha2;
pub mod tables;
pub mod wp;
