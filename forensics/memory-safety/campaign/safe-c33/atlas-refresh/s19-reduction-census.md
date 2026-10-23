# S19 — census of campaign-recorded reductions

**Source identity:** `integrate/safe-c33`, HEAD `bcbc69d78` + the S19 working-tree changes
(this subagent did not commit or push).
**Question:** where did a prior wave justify a change by making something unreachable,
always-NULL, default, inert, stubbed, or "no caller can reach this", and was that claim true?

**Classification** (AGENTS.md §17 and §6):

| class | meaning |
|---|---|
| **BENIGN** | a genuinely dead path, a documented OpenSSL-invalid input, or a record that is merely stale with no behavioural difference. |
| **DIVERGENCE** | a deliberate, explicit divergence with the compatibility consequence stated (including an explicit refusal where the authority would adopt). |
| **LATENT REGRESSION** | a reachable behaviour was removed and the evidence described it as a safety win. The S18 class. |

**Method.** Searched `forensics/memory-safety/campaign/safe-c33/**` (336 matching lines
in 78 files: `PROGRESS.md`, `CAMPAIGN-STATUS.json`, `STATUS-2026-10-20.md`, the
`atlas-refresh/mechanism-sweep-*.json`, `boundary-sweep-*.json`, `s16`/`s17`/`s18`
receipts, and the nine `per-file/*.md` receipts) and `src/**/*.rs` (749 matching
comment lines). Distinct mechanisms were then checked against the current code.

**Honesty limits.** The campaign does not contain a separate "W1–W5" receipt directory;
the wave records present are the mechanism-sweep/boundary-sweep JSONs and the
per-file receipts, and they are used as such. Family counts below are **estimates**:
this FAST subphase did not re-run a per-consumer symbol-use analysis against the 166
loaded rows. Exposure is the S19 analyst's judgement, not a measurement.

---

## 1. LATENT REGRESSION — open (ordered by exposure × families)

Score = exposure (1–5) × families of the 166 loaded rows plausibly affected.

| # | file:line | recorded reduction | reachable behaviour today | §17 note | exp | fam | score |
|---|---|---|---|---|---|---|---|
| L01 | `src/evp/pkey.rs:3609-3633` | "the ameth half is Phase 8's and unreachable — nothing in this crate sets `ameth`" | `evp_pkey_asn1_ctrl` returns `-2` for **every** key with an ameth. Every legacy origin key has one (`pkey_set_type` sets it; `EVP_PKEY_set1_RSA`, `EVP_PKEY_assign_*`, `EVP_PKEY_new_raw_private_key` all produce such keys). `EVP_PKEY_get_default_digest_nid`, `EVP_PKEY_set1_encoded_public_key`, `EVP_PKEY_get1_encoded_public_key` and `EVP_PKEY_get_default_digest_name` all inherit the refusal. | authority calls `ameth->pkey_ctrl`; this crate refuses. §17: implementation omission, not a safety improvement. | 4 | 25 | **100** |
| L02 | `src/evp/pkey.rs:1781-1806` | "the error is raised for a NULL key and for a legacy key alike" | `EVP_PKEY_get_params` raises `P_LIB_2455` and returns 0 for a key with `keymgmt == NULL`, where the authority dispatches to `evp_pkey_get_params_to_ctrl`. The whole translator chain is dead-coded on the same false premise (`src/evp/pkey_ctx.rs:6260-6285` still says the legacy block is absent, but `EvpPkey` models it in full). | authority returns translated parameters; this crate refuses. | 3 | 20 | **60** |
| L03 | `src/evp/pkey.rs:2422-2469` | "`ameth` always NULL here the second path is unreachable" | `EVP_PKEY_get_raw_private_key` on a legacy X25519/Ed25519/X448/Ed448 key (built by `EVP_PKEY_new_raw_private_key(type, NULL, ...)`) returns 0 and raises, although the ecx ameth publishes `get_priv_key`. | authority exports the raw key; this crate refuses. | 4 | 12 | **48** |
| L04 | `src/evp/pmeth_check.rs:154-308` | "the legacy half … unreachable for the reason given on `evp_pkey_public_check_combined`" | `EVP_PKEY_public_check`, `_quick`, `_private_check` and `_pairwise_check` answer `-2` for legacy keys; `ctx->pmeth->check` / `pkey->ameth->pkey_check` are never called. `mechanism-sweep-M57.json` records the same claim and even notes the wrong raise coordinate. | authority runs the legacy check; this crate refuses. | 4 | 12 | **48** |
| L05 | `src/evp/pkey.rs:2471-2513` | same "ameth always NULL" record as L03 | `EVP_PKEY_get_raw_public_key` refuses a legacy ecx key whose ameth publishes `get_pub_key`. | authority exports; crate refuses. | 4 | 10 | **40** |
| L06 | `src/evp/pkey.rs:998-1025` | "the `pkey->ameth->info` arm is Phase 8's and unreachable" | `EVP_PKEY_get0_description` tests only `keydata != NULL`, so a legacy origin key (data in `pkey`, not `keydata`) returns NULL instead of `ameth->info`. | authority returns the method's description. | 3 | 10 | **30** |
| L07 | `src/evp/pmeth_gn.rs:745-772` | "this crate's `ameth` is always NULL — so the arm is unreachable" | `EVP_PKEY_export` returns 0 for every legacy key instead of calling `ameth->export_to`; `EVP_PKEY_todata` shares the provider-only helper. | authority exports the legacy key; crate reports failure. | 3 | 12 | **36** |
| L08 | `src/ec/ctrl.rs:30-39` | "the first clause is false for every context this crate can build" | The authority's key-type guard (`is_legacy && pmeth != NULL && pmeth->pkey_id != EVP_PKEY_EC → -1`) is now reachable: an engine/foreign EC context has `keymgmt == NULL` and a non-NULL `pmeth`. A ctrl on a mismatched-key engine context is silently accepted. `mechanism-sweep-M49.json` records the reduction. | authority refuses; crate accepts. | 2 | 3 | **6** |
| L09 | `src/dh/ctrl.rs:32-40,131` | "the first clause is false for every context this crate can build" | Same `is_legacy` guard for DH/DHX omitted. `mechanism-sweep-M48.json`'s sibling argument is also stale. | authority refuses; crate accepts. | 2 | 2 | **4** |
| L10 | `src/dsa/ctrl.rs:19-24,62-64` | "this crate's `EvpPkeyCtx` has no `pmeth`" | `dsa_paramgen_check`'s `pmeth != NULL && pmeth->pkey_id != EVP_PKEY_DSA → -1` arm is now reachable and omitted. | authority refuses; crate accepts. | 2 | 1 | **2** |
| L11 | `src/evp/pkey.rs:3635-3720` | "the delegation always goes through `legacy_asn1_ctrl_to_param`" | User-visible symptom of L01: `EVP_PKEY_get_default_digest_nid`/`_name` return `-2`/fail for a legacy key with `pkey_ctrl`, including RSA/DSA/DH legacy keys. Signing init has a fallback, so not every caller breaks, but callers that read the default digest directly do. | authority answers the ameth NID; crate refuses. | 4 | 20 | **80** |

**These are reachable now, not hypothetically.** `EVP_PKEY_set1_RSA`/`_assign_*` and
`EVP_PKEY_new_raw_private_key(type, NULL, ...)` are ordinary public entry points, and
`pkey_set_type` populates `ameth` from the landed `standard_methods[]` (D353/D372).
The S18 h2o/neverbleed fixture itself builds a legacy RSA key this way.

## 2. LATENT REGRESSION — already repaired (S18, S19, M6)

| # | file:line (record) | reduction | status |
|---|---|---|---|
| F01 | `src/rsa/object.rs:340-350` (old) | `rsa_new_intern` ignored its ENGINE argument | **FIXED S18**; h2o L5→L7 |
| F02 | `src/evp/pkey_ctx.rs:507-518` (old) | `int_ctx_new`/`do_sigver_init`/`EVP_PKEY_sign` provider-only; `pkey->foreign` ignored | **FIXED S18** |
| F03 | `src/evp/signature.rs:2070-2126` | legacy one-shot sign half only | **FIXED S18**; verify added S19 (F07) |
| F04 | `src/ec/kmeth.rs:344-359,427` | `EC_KEY_new_method` engine ignored; `EC_KEY_free`/`set_method`/`copy` omitted finishes | **FIXED S19** |
| F05 | `src/dsa/object.rs:131-137,168` | `DSA_new_method` engine ignored; `DSA_free`/`set_method` omitted finishes | **FIXED S19** |
| F06 | `src/dh/object.rs:191-197,229` | `DH_new_method` engine ignored; `DH_free`/`set_method` omitted finishes | **FIXED S19** |
| F07 | `src/evp/signature.rs:1180-1186,2242` | `EVP_PKEY_verify`/`_verify_recover` legacy arms stubbed as `-2` | **FIXED S19** |
| F08 | `src/evp/digest.rs:453-557,712-751` | `EVP_DigestVerifyUpdate/Final`/`EVP_DigestVerify` legacy arms stubbed; `update` declared dead code | **FIXED S19** |
| F09 | `src/evp/asymcipher.rs:194,325` | `EVP_PKEY_encrypt/decrypt` legacy arms stubbed as `-2` | **FIXED S19** |
| F10 | `src/evp/pkey.rs:2518-2554` | `EVP_PKEY_new_raw_*` ignored its engine argument | **FIXED S19** |
| F11 | `src/evp/pkey.rs:3359,3449` | `EVP_PKEY_new_CMAC_key` dropped `ENGINE_get_id` / `OSSL_ALG_PARAM_ENGINE` | **FIXED S19** |
| F12 | `mechanism-sweep-M6.json:39` | "`r->pss` was unreachable" — the writer's caller chain had landed; `RSA_PSS_PARAMS_free` omitted | **FIXED M6** |
| F13 | `src/evp/pkey.rs:1777-1830` (authority) / old `evp_pkey_free_legacy` | "nothing writes `pkey->engine`/`pmeth_engine`" — `EVP_PKEY_set1_engine` writes `pmeth_engine`, and S19's raw-key adoption writes `engine`; neither was released | **FIXED S19** (release added) |

## 3. DIVERGENCE (explicit, recorded)

| # | file:line | divergence | compatibility consequence |
|---|---|---|---|
| D01 | `src/evp/digest.rs:95-105,1781-1798,2125` | `EVP_DigestInit_ex`'s non-NULL `impl` is refused at `DIGEST_311` rather than adopting the engine | an engine-backed digest cannot be selected through this entry point; the refusal is explicit (`EVP_R_INITIALIZATION_ERROR`), not a silent default |
| D02 | `src/evp/cipher_ctx.rs:1928-1936,2460` | `EVP_CipherInit_ex`'s non-NULL `impl` is refused at `EVP_ENC_296`; `ctx->engine` is never set | same as D01 for ciphers; engine-backed ciphers unavailable |
| D03 | `src/evp/pkey.rs:2521-2527` | `new_raw_key_int` still writes `ameth = NULL` instead of the authority's ASN.1 lookup when `e == NULL`, so the provider branch is tried first | for a type with both provider and legacy methods the authority may build a legacy key while this crate builds a provider key; the engine argument itself is now adopted (F10) |
| D04 | `mechanism-sweep-M57.json:78` | the pmeth-check legacy raise coordinate is wrong (`PMETH_CHECK_78` vs `NO_KEY_SET`) and no authority differential was run | evidence gap; the legacy arm itself is L04 |
| D05 | `per-file/src__evp__digest.rs.md:317-322` (D249/D253/D254) | `sigver_legacy`'s "unreachable `pmeth` tail" and `update` as "no caller (dead code)" | both are live after S18/S19; the evidence rows are stale, not a separate behaviour change |

## 4. BENIGN / stale records (no behaviour removed)

| # | source | disposition |
|---|---|---|
| B01 | `src/ssl/ssl_conf.rs:27-31,1254` — `canames` always NULL, `cert_filename` never installed | BENIGN while `SSL_CONF` installs no filename; revisit when certificate loading is wired through `SSL_CONF` |
| B02 | `mechanism-sweep-M45.json:41,128` — DER writer has no caller in authority or crate | BENIGN; the corrected success tests change no observable |
| B03 | `mechanism-sweep-M67.json:46-47,167` — `ProvEcxCtx::propq` never assigned | BENIGN; authority-identical inert field |
| B04 | `mechanism-sweep-M28.json:36` — Ed448 `dom2` cleared but never read | BENIGN; setup re-checks the key type |
| B05 | `mechanism-sweep-M64.json:33` — NULL property definition; function dead | BENIGN; no production caller |
| B06 | `src/evp/pkey.rs:3016-3019` says the legacy-origin arm of `evp_pkey_export_to_provider` is absent, while `src/evp/pkey.rs:1825-1832` says it is live | BENIGN documentation contradiction; the code is live (verify at next BATCH) |
| B07 | `#[allow(dead_code)]` chains for strata not landed (`evp/mac.rs:551`, `evp/fetch.rs:50`, `evp/rand.rs:722`, `evp/kdf.rs:511`, `evp/encode.rs:74`, `evp/keymgmt.rs:809`, `runtime/thread.rs:1866`) | BENIGN; genuinely no caller yet |

---

## 5. Tally

| class | count |
|---|---|
| BENIGN | 7 |
| DIVERGENCE | 5 |
| LATENT REGRESSION | 24 (11 open + 13 repaired in S18/S19/M6) |

The census **confirms the S18 diagnosis is systemic, not a one-off**: the campaign
repeatedly used "no caller can reach this" / "always NULL" as a licence to delete a
half, and at least two later landings (the ASN.1 method table and the ENGINE registry)
falsified those premises without revisiting the deleted halves. The largest open cluster
is the `EVP_PKEY` ameth/legacy-key family (L01–L07, L11), not the ENGINE constructors.

No item in §1–§4 was repaired in this subphase beyond the ENGINE class listed in
Deliverable A / F04–F11 and F13.
