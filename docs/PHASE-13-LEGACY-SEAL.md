# Phase 13 — Legacy / deprecated compatibility: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's export ledger is empty of open rows —
`forensics/phase13-obligations.json:9` reads `open_in_this_stratum: 0` — the stratum ships no
provider registration row (§1), every earlier stratum is `complete`, and the FRF/Gemel chain entry
§8 records has landed, so `forensics/phase-state.json` reports phase 13 **`complete`** with an empty
blocking reason. That derived state is the phase-exit predicate, and D525 records that the ledger's
own `complete` is *not* it (`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is
named in `forensics/tools/atlas_common.py`'s `SEAL_DOCS` table, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum has
reached the state a seal *records* (D421); it is **not** a parity claim, and this document is where
what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97), and the census's own header says so. The one
table this document *does* carry — §3's court list — is copied from `artifacts/phase13/COURTS.json`,
and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the candidate distribution defines the names this stratum
owns and that the behaviours its nine courts exercise match the pinned authority's over fixed
fixtures, observation for observation. It does **not** show that the crate's ENGINE registry, its
UI prompts or its text-database codec are safe against a hostile input — no court here is a
security or fuzz gate — and it does **not** show that the crate is a usable OpenSSL.
`docs/PARITY_MODEL.md` is the authority on what the labels mean: `implemented` means a symbol with
that name is defined, and a passing bounded court is a differential result over the behaviours that
court exercises. `PARITY_VERIFIED` is not claimed for any symbol here, and `forensics/STATUS.md`'s
non-claims are the generated projection's. All 603 `libssl` exports remain `SCAFFOLDED` — a stub
present, which cannot count as parity (`docs/PARITY_MODEL.md:22`) — exactly as
`docs/SEAL-CENSUS.md:21` and `forensics/STATUS.md:127-129` record.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase13/COURTS.json:2`
- Court results: `artifacts/phase13/COURTS.json` — nine courts, `all_pass` true
  (`artifacts/phase13/COURTS.json:4`), zero residuals; the per-court table is §3. Eight are
  **differential** courts and one (`RT-PHASE13-REF`) is the reference basis; this stratum
  registers no correctness `CT-*` court, and §3 states why.
- Obligation ledger: `forensics/phase13-obligations.json` — `open_in_this_stratum` 0
  (`forensics/phase13-obligations.json:9`), `deferred_to_later_phase` 0
  (`forensics/phase13-obligations.json:7`); the working-set rule it enforces is the ledger's own.
- Court coverage: `forensics/atlas/court-coverage.json` — phase 13's block at
  `forensics/atlas/court-coverage.json:44712`, its counts `implemented` 377, `directly_courted`
  377 (348 `called`, 29 `referenced`), 0 indirect, 0 non-observable, 0 `unmatched`; the weaker
  meaning of `directly_courted` is stated in §3 and in §1 below (D199).
- Derived state: `forensics/phase-state.json`, phase 13; it owns **no provider row**, so its
  `provider_rows` reads `owned` 0 rather than a count (§1).
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries eight
  receipts for the eight declarable courts
  (`receipt-run-openssl-rs-rt-{engine,engine-table,engine-ctrl,ui,txtdb,evp-legacy,legacy-remainder,handoff}-*`),
  sixteen adjudicated challenge records (both operators on every court) and the
  `sensitivity-backed` claim
  `28423ad27ef5293c1bf5337cb82ce464f500a4d61aa6741ea32fcb9632a49ff9`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.24` with zero blockers and all eight premises carrying
  stdout and exit. §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 13's `C99` and its `current:` is
  `checkpoint.80d5b1bc4e22d27af750f51dfacc1f2aab7b1803f3a3369e177852e588b8c715` (`K53`), whose
  summary names Phase 13 and the FRF chain. §8 states what that is.
- Deciding record: `docs/DECISIONS.md` — **D524** (the FRF requirement is read from the court
  inventory) is the predicate this stratum's chain engages, and **D525** is this seal, with
  `docs/PHASE-13-SUBPHASES.md` for the subphase plan this seal closes. §10 is where the
  corrections this seal records are summarised.

## 1. What this phase owns, and how that was decided

Phase 13 is **the legacy/deprecated-compatibility stratum**: the `ENGINE` framework, the `UI`
dialog framework, the `TXT_DB` text database the `ca` app reads, and the deprecated METHOD-era
surface the earlier strata hand it rather than transcribe (`docs/PHASE-13-SUBPHASES.md:3-12`). It
is deliberately **not** the algorithms the legacy statics call — `AES_encrypt`, `SHA256_Update` and
`Camellia_EncryptBlock` are Phase 8's, and the statics reach them as callers — **not** the `EVP`
framework the statics register into (Phase 7's), and **not** the CLI that consumes `TXT_DB` and
`UI` (Phase 16's).

**The working set is derived, not chosen.** `forensics/atlas/symbol-ownership.json` assigns it 189
exports over **three headers** — `engine.h` 121, `ui.h` 62, `txt_db.h` 6 — and a further 188 arrive
as recorded edges every earlier stratum's ledger hands here: 22 `async.h` names from Phase 3 (the
`ASYNC_*` job framework), 163 `evp.h`/`pem.h` names from Phase 7 (the deprecated METHOD-era
`EVP_CIPHER`/`EVP_MD` statics and the four `PEM_read[_bio]_PrivateKey` spellings with their `_ex`
twins), and 3 from Phase 12 (`TS_CONF_set_crypto_device`, `TS_CONF_set_default_engine` and
`SRP_VBASE_init`). The census's per-stratum row (`docs/SEAL-CENSUS.md:41`) reads `atlas-owned` 189,
`ledger owned` 377, `implemented` 377, `deferred` 0, `open` 0.

**Like Phases 10, 11 and 12, this stratum did not start with its whole working set open.** 127 of
its 377 exports were already `implemented` at activation: 123 atlas-owned landings — 61 of the
`ENGINE_*` object, accessor and table names and the whole 62-name `UI_*` framework — plus the four
Phase 7 → 13 `PEM_read[_bio]_PrivateKey` spellings Phase 8 landed (D369), so `open_in_this_stratum`
opened at **250**, not 377 (`docs/PHASE-13-SUBPHASES.md:25-33`). The split moves as the stratum
lands its own units, so the ledger's `counts` is the live record and §1 of the plan is the
activation measurement.

**The 377 symbols are defined by 52 authority translation units**, under `crypto/engine/` (23
units), `crypto/ui/` (4), `crypto/txt_db/` (1), `crypto/evp/` (21), `crypto/async/` (3) and
`crypto/sm3/` (1) (`forensics/atlas/export-defining-units.json`); the ledger's `owned_by_module`
block records the per-crate-module shape reached at closure. The eight subphase rows above the seal
partition the 250 activation-open exports exactly, 3 + 53 + 4 + 0 + 6 + 148 + 33 + 3 = 250, and
the partition is derived from the defining units joined to the ledger's `open` list, not typed
(`docs/PHASE-13-SUBPHASES.md:116-119`).

**This stratum publishes no provider registration row, and the census records where the legacy rows
went.** The 39 legacy digest and cipher rows `providers/legacyprov.c` publishes — the loadable
module the candidate ships as a scaffold `ossl-modules/legacy.so` — are handed by
`forensics/atlas/provider-algorithm-plans.json` to the distribution stratum (Phase 16), which owns
the installed module contract, because this stratum's subphases deliberately do not activate the
legacy provider (`docs/PHASE-13-SUBPHASES.md` §3.6: only the default provider is active). The
ledger's `provider_rows_owned` is therefore `0`, and `phase_state.py`'s provider-row rule has
nothing to hold against this stratum; §6 states this as a non-claim.

**The order is the dependency the plan measured.** 13.1 before 13.2, 13.3 and 13.6 because the
method tables, the control dispatch and the legacy statics all bind to an `ENGINE` object the
registry hands out; 13.1 before 13.8 because `TS_CONF_set_default_engine`'s body is `ENGINE_by_id`
and `ENGINE_set_default`; 13.5 before 13.8 because `SRP_VBASE_init` reads and releases a verifier
file through `TXT_DB_read`/`TXT_DB_free`; 13.4 is independent of the ENGINE chain; and 13.7 after
13.6 because the PEM private-key readers dispatch into the legacy statics 13.6 lands
(`docs/PHASE-13-SUBPHASES.md:121-130`, D525).

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work, and this stratum emits no primitive: it has **eight behavioural
differential courts and one reference-basis court, and no `CT-*` court**. The reference basis is
`RT-PHASE13-REF`, the court D199 requires for a stratum whose exports an earlier stratum landed: it
takes the address of each of the 127 inherited `implemented` exports and prints whether each is
non-NULL, so a symbol covered only by it is a proof of *reference* and not that any arm of it was
driven (`artifacts/phase13/COURTS.json:6`). §3 is where the two readings are tabulated.

## 2. What has been built

**13.0, the plan and the census.** `docs/PHASE-13-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase13-obligations.json` and its generator, the runner
`forensics/tools/phase13_courts.py`, and the reference-basis probe
`courts/phase13/rt_coverage_ref_probe.c` — all landed together, because §4.3 of the plan makes the
runner and the reference probe a precondition rather than a later slice
(`docs/PHASE-13-SUBPHASES.md:237-259`).

**13.1, the ENGINE object, registry and dynamic loading.** `src/engine/eng_list.rs`
(`ENGINE_by_id`), `src/engine/eng_all.rs` (`ENGINE_load_builtin_engines`), `src/engine/eng_cnf.rs`
(`ENGINE_add_conf_module`) and `ossl_get_enginesdir`: the object lifecycle, the registry walk, the
built-in loader and the dynamic (`OPENSSL_ENGINES`) loader — 3 open rows over 5 units, now zero.
`RT-ENGINE` (30 observations) **calls** `ENGINE_by_id`, `ENGINE_load_builtin_engines` and
`ENGINE_add_conf_module` and compares the registry's observed `id`/`name`, object identity, the
NULL/absent refusals, the refcount effect and the built-in loader's shared registry arm. The absent
`crypto/engine/eng_dyn.c` is a recorded boundary (§5).

**13.2, the ENGINE table and method binding.** `src/engine/eng_pkey.rs`, `tb_cipher.rs`,
`tb_pkmeth.rs`, `tb_digest.rs`, `tb_asnmth.rs`, `tb_rand.rs`, `tb_rsa.rs`, `tb_dsa.rs`, `tb_dh.rs`
and `tb_eckey.rs`: the per-algorithm method tables and the
`ENGINE_set_default_*`/`ENGINE_register_*`/`ENGINE_get_*` binding surface — 53 open rows over 10
units, now zero. `RT-ENGINE-TABLE` (76 observations) drives the bound method identities, the
register/select/unregister cycle, the `ENGINE_register_all_*` walk, the `dummy_nid` default select
and the NULL/uninitialised/no-loader refusals over a synthetic ENGINE. Landing
`ENGINE_get_pkey_meth` falsified Phase 7's one `BLOCKED_HANDOFFS` row, which is retargeted to
`UNBLOCKED_HANDOFFS` (D524's mechanism, applied here as 13.2 did).

**13.3, the ENGINE control and command surface.** `src/engine/eng_fat.rs` and `eng_ctrl.rs`: the
`ENGINE_METHOD_*` mask dispatch, every `int_def_cb` string spelling, the nine-arm
`ENGINE_register_complete` and the `ENGINE_register_all_complete` walk and its
`ENGINE_FLAGS_NO_REGISTER_ALL` skip — 4 open rows over 2 units, now zero. `RT-ENGINE-CTRL` (73
observations) drives the four fat helpers and the unknown/partial/NULL/empty refusals.

**13.4, the UI framework driven rather than landed.** All 62 `ui.h` names (`src/ui/ui_lib.rs`,
`ui_openssl.rs`, `ui_util.rs`, `ui_null.rs`) had landed before activation as substrate the earlier
strata needed, so the subphase's act is `RT-UI` (278 observations): it **calls** every name over a
deterministic in-process `UI_METHOD` with the writer observing every `UI_STRING` and the reader
supplying fixed answers, so the coverage basis of those 62 names moves from `referenced` to
`called` and 13.4's commit records the movement 99 → 158 called.

**13.5, TXT_DB.** `src/txt_db/txt_db.rs`: `TXT_DB_read`/`_write`/`_insert`/`_create_index`/
`_get_by_index`/`_free`, the whole of `txt_db.h` — 6 open rows over 1 unit, now zero.
`RT-TXTDB` (57 observations) compares the parsed rows field by field, the `TXT_DB_write` bytes and
their re-read, the indexed lookup's hit/miss/out-of-range/no-index arms by `DB_ERROR_*`, the
duplicate-key clash, the two wrong-field-count read failures and `TXT_DB_free`.

**13.6, the legacy EVP method statics.** `src/evp/e_aes.rs` (42 rows with the four stitched
CBC-HMAC statics, 13.6a), `e_aria.rs`/`e_camellia.rs` (48 rows, 13.6b), the remaining cipher units
`e_des3.rs`/`e_des.rs`/`e_rc2.rs`/`e_sm4.rs`/`e_bf.rs`/`e_cast.rs`/`e_idea.rs`/`e_seed.rs`/
`e_rc4.rs`/`e_chacha20_poly1305.rs`/`e_rc4_hmac_md5.rs`/`e_xcbc_d.rs` (52 rows, 13.6c), and the
four `EVP_MD` statics `src/evp/legacy_md4.rs`/`legacy_mdc2.rs`/`legacy_wp.rs` and
`src/sm3/legacy_sm3.rs` with `src/evp/p_lib.rs`'s pair (13.6d) — 148 open rows over 21 units, the
largest subphase, now zero. `RT-EVP-LEGACY` (1167 observations) compares each object's sizes,
`flags` and a fixed-key/fixed-IV round trip, with AEAD, wrap and the stitched statics driven by
their own sequences; the fetched-identity `pending.` arms are §5.

**13.7, the PEM private-key readers and the ASYNC framework.** `src/pem/pem_pkey.rs` (the five
write spellings and the two `PEM_read_bio_Parameters*` readers), `src/pem/pem_pk8.rs` (the four
`PEM_write[_bio]_PKCS8PrivateKey[_nid]` wrappers), and `src/async/async.rs`,
`src/async/async_wait.rs` and `src/async/arch/async_posix.rs` with the platform's `ucontext_t`
fibre primitives kept on the C side of the ABI (`src/async/arch/async_ucontext.c`) — 33 open rows
over 5 units, now zero. `RT-LEGACY-REMAINDER` (78 observations) drives the PEM round trip over a
fixed in-process key and the whole `ASYNC_*` job-and-wait contract; the decoder-absent
`DH PARAMETERS` arm is §5.

**13.8, the received TS_CONF and SRP hand-offs.** `src/ts/ts_conf.rs`'s
`TS_CONF_set_crypto_device`/`TS_CONF_set_default_engine` (over `ENGINE_by_id` and
`ENGINE_set_default`) and `src/srp/srp_vfy.rs`'s `SRP_VBASE_init` (over `TXT_DB_read`/
`TXT_DB_free`) — the three Phase 12 rows, 3 open rows over 2 units, now zero. `RT-HANDOFF` (30
observations) drives exactly the arms the plan §3.8 names over fixed `CONF` and verifier files.
Phase 12's `BLOCKED_HANDOFFS` is now empty; the three rows moved to a new `UNBLOCKED_HANDOFFS`
table, so both ledgers stay honest and `ownership_audit` reports the three discharged edges.

**The books that moved with the code.** The implemented surface ended where the census states it:
`docs/SEAL-CENSUS.md:20-22` is the `libcrypto`/`libssl`/total table, and the live internal
`c_style` count is what `docs/CI.md:108` records and `docs_consistency.py` checks against
`forensics/atlas/implemented-surface.json`. Phase 13's own ledger reads `implemented` 377 of
`owned` 377 with `deferred` 0 and `open` 0 (`forensics/phase13-obligations.json:5-12`), and it
discharged its 188 received hand-offs rather than passing them on
(`docs/SEAL-CENSUS.md:448-450`).

## 3. The evidence

Copied from `artifacts/phase13/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. Nine courts are differential; the stratum registers no correctness
`CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-PHASE13-REF` | differential (reference basis) | 127 | `courts/phase13/rt_coverage_ref_probe.c` |
| `RT-ENGINE` | differential | 30 | `courts/phase13/rt_engine_probe.c` |
| `RT-ENGINE-TABLE` | differential | 76 | `courts/phase13/rt_engine_table_probe.c` |
| `RT-ENGINE-CTRL` | differential | 73 | `courts/phase13/rt_engine_ctrl_probe.c` |
| `RT-UI` | differential | 278 | `courts/phase13/rt_ui_probe.c` |
| `RT-TXTDB` | differential | 57 | `courts/phase13/rt_txtdb_probe.c` |
| `RT-EVP-LEGACY` | differential | 1167 | `courts/phase13/rt_evp_legacy_probe.c` |
| `RT-LEGACY-REMAINDER` | differential | 78 | `courts/phase13/rt_legacy_remainder_probe.c` |
| `RT-HANDOFF` | differential | 30 | `courts/phase13/rt_handoff_probe.c` |

Every row carries `residual_count: 0` and `verdict: "pass"` (`artifacts/phase13/COURTS.json:7-160`),
and the summary reads `pass` 9 of `total` 9 with `pending_courts` empty
(`artifacts/phase13/COURTS.json:162-167`). The totals over the nine transcript courts are
`docs/SEAL-CENSUS.md`'s (`docs/SEAL-CENSUS.md:452`, **1916** authority observations), and the
per-court rows there (`docs/SEAL-CENSUS.md:456-464`) are the same computation.

**`RT-PHASE13-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe takes
the address of each of the stratum's 127 inherited `implemented` exports and prints whether each is
non-NULL, so a symbol covered only by it means the candidate distribution defines the name — which
the link proves — and **not** that any arm of it was driven (`artifacts/phase13/COURTS.json:6`,
`courts/phase13/rt_coverage_ref_probe.c`). The court coverage atlas records those at basis
`referenced`, never `called` (D199). Eight courts are behavioural: `RT-ENGINE`, `RT-ENGINE-TABLE`
and `RT-ENGINE-CTRL` drive the ENGINE object, registry, method tables and control dispatch;
`RT-UI` drives the whole `ui.h` framework; `RT-TXTDB` drives the text-database codec;
`RT-EVP-LEGACY` drives the deprecated METHOD-era statics; `RT-LEGACY-REMAINDER` drives the PEM
private-key readers and the ASYNC framework; and `RT-HANDOFF` drives the three received hand-offs
(`courts/phase13/*_probe.c`, `docs/PHASE-13-SUBPHASES.md:138-215`).

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: every subphase builds a
registry, a dialog framework, a text codec or a deprecated wrapper over Phase 8's primitives, and a
`CT-*` court is a vector-driven construction check with no authority transcript to diff (D13,
D201). The stratum's evidence is therefore **differential only**, which is a measurement and not an
omission, and every arm that could not be driven is named `pending.` or left undriven rather than
counted as passing (§5).

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md:523` reads phase 13 as 377 implemented, 377 `directly_courted` (348 of them
`called` and 29 `referenced`), 0 indirect, 0 non-observable, 0 unmatched; the block is
`forensics/atlas/court-coverage.json:44712`. `directly_courted` means *referenced by a staged
candidate probe that ran and produced a transcript*, a proof of **reference** rather than that every
arm of the symbol was driven — the same reading Phase 8's through Phase 12's seals adopt. The
referenced 29 are the inherited `RT-PHASE13-REF` names the behavioural courts do not call, and the
called 348 are the names — the stratum's own work, the 62 UI names 13.4 moved from `referenced` to
`called`, and the inherited names its courts reach — that a probe actually invokes.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found real defects, in the candidate and in the instrument.

**The 13.6c court found and fixed two real candidate bugs.** `RT-EVP-LEGACY` exposed the `iv_len`
of the `IDEA_ECB` and `SEED_ECB` legacy statics, which the candidate had published wrongly; both
were corrected in 13.6c, and the court grew 720 → 1135 observations with 0 residuals on the fixed
objects. That is exactly the class the differential court exists to reach: a field the authority
publishes and a transcription can get wrong without any caller noticing.

**A lower-unit identity divergence surfaced and was then closed.** While the legacy `OBJ_NAME`
cipher table was empty, `EVP_get_cipherbyname(name)` could not resolve the fetched identity the
authority resolves, and every such arm was printed as a `pending.` line with its reason rather than
compared (`courts/phase13/rt_evp_legacy_probe.c:376-383`). The registration the table needs then
landed (D526): `src/evp/c_allc.rs`/`c_alld.rs` transcribe `crypto/evp/c_allc.c`/`c_alld.c`,
`src/runtime/init.rs`'s `add_all_legacy_methods` calls them for the two `OPENSSL_INIT_ADD_ALL_*`
bits, and `src/context/namemap.rs`'s `ossl_namemap_stored` runs the authority's first-use
pre-population, so the table is filled on the fetch path too. The arms now compare the values, and
`EVP_CIPHER_get_nid` on a fetched `DES-CBC` answers `NID_des_cbc` as the authority does.

**A random boundary is named rather than compared.** `EVP_des_ede3_wrap` draws its eight-byte IV
with `RAND_bytes`, so its round-trip value is not a function of the library alone; the arm is
printed as `pending.` with that reason (`courts/phase13/rt_evp_legacy_probe.c:401-407`), while the
object's sizes and flags are still compared.

**The reference basis is what made the coverage join green at activation, and its meaning is the
weaker one.** 13.0 landed `RT-PHASE13-REF` so that `court_coverage.py`'s refusal of the inherited
`implemented` exports could be satisfied without fabricating behavioural evidence; the atlas records
those names at basis `referenced` (D199, `docs/PHASE-13-SUBPHASES.md:237-259`). The behavioural
courts then moved as many names as they could from `referenced` to `called` — the whole UI framework
among them (13.4) — and the 29 that remain `referenced` are the honest residue.

**The ENGINE built-in registry and the error queue are deliberately not observed.** The candidate's
`OPENSSL_init_crypto` registers nothing, so the authority's built-in registry (`rdrand`,
`dynamic`) is not compared; the court drives the registry it can build and records the built-in
loader's shared arm instead (D525, `courts/phase13/rt_engine_probe.c`). No court here reads the
error queue, so the `ENGINE_R_*` raises on the refusal arms cannot leak into a comparison — the
convention Phases 9 through 12 established.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or crashes, the court does not
call it and the divergence is recorded. **One divergence obligation named Phase 13 as its
`current_owner`, and it did not block.** `forensics/divergence-obligations.json` read 10 rows and
**0 blocking** at seal time; `D-EVP-CIPHER-LEGACY-NID-1` was Phase 13's, its trigger basis is
`manual`, and its derived `blocking` was false, so no live obligation outran this stratum's
evidence and `phase_state.py` derives `complete`. D526 then retired the row to `fixed` by landing
the legacy `OBJ_NAME` registration the entry records as missing. The boundaries this stratum
actually met are recorded in the places below.

- **The legacy `OBJ_NAME` / `EVP_get_cipherbyname` divergence was named, then closed.** While the
  legacy `OBJ_NAME` cipher table was empty in the candidate, every `EVP_get_cipherbyname(name)` arm
  was a `pending.<name>.byname=` line whose value was
  `legacy-OBJ_NAME-cipher-table-empty-in-candidate` (`courts/phase13/rt_evp_legacy_probe.c:25-28,376-383`).
  D526 landed the registration (`src/evp/c_allc.rs`, `src/runtime/init.rs`,
  `src/context/namemap.rs`), so the arms are compared now; the accessors, the object sizes and the
  round trips always were.
- **The `EVP_des_ede3_wrap` random IV is not compared.** Its round trip draws an eight-byte IV with
  `RAND_bytes`, so the arm is `pending.<name>.roundtrip=tdes-wrap-draws-a-random-iv`
  (`courts/phase13/rt_evp_legacy_probe.c:401-407`); the object's sizes and flags are still compared.
- **The `DH PARAMETERS` reader is left undriven rather than compared.** The two
  `PEM_read_bio_Parameters*` readers answer NULL where the authority answers a key for a written
  `DH PARAMETERS` block — the decoder-absence divergence `D-DECODER-ABSENT-1` already names — so
  `RT-LEGACY-REMAINDER` drives them over an empty BIO and leaves the divergent arm undriven
  (`courts/phase13/rt_legacy_remainder_probe.c:25-25`,
  `docs/PHASE-13-SUBPHASES.md:417-420`).
- **`crypto/engine/eng_dyn.c` is absent, and the dynamic fallback is recorded rather than
  fabricated.** No subphase owns the dynamic-engine unit, so no dynamic engine is registered and
  `ENGINE_by_id`'s miss path takes the authority's own `goto notfound`; the `<id>`-in-list half is
  transcribed whole. The boundary is recorded in `src/engine/eng_list.rs:9-19`,
  `src/engine/mod.rs:77-79` and D525, and it is why the built-in `dynamic`/`rdrand` ids are not
  observed (`courts/phase13/rt_engine_probe.c`).
- **The legacy provider is a scaffold, and its rows are not this stratum's.** `ossl-modules/
  legacy.so` is the candidate's Phase-2 distribution-shell module, and this stratum's subphases do
  not activate it, so the 39 legacy digest/cipher rows are handed to Phase 16 (§1); the
  legacy-provider-only digests `EVP_md4`, `EVP_mdc2` and `EVP_whirlpool` are refused identically on
  both sides because only the default provider is active (`docs/PHASE-13-SUBPHASES.md:377-395`).
- **The UI, ENGINE and TXT_DB NULL arms are recorded in the probes.** A NULL `UI` handed to an
  accessor, `UI_create_method(NULL)`, a NULL engine handed to a method getter, and a negative index
  or field into `TXT_DB` all dereference or index out of bounds in the authority, so the probes name
  the arms instead of driving them (`docs/PHASE-13-SUBPHASES.md:162-175`,
  `courts/phase13/rt_ui_probe.c`, `rt_engine_table_probe.c`, `rt_txtdb_probe.c`).
- **The `pending.` set and the undriven arms are the register's machine form.** The boundaries above
  are recorded in the probes, in the plan's §3, and in D525;
  `forensics/divergence-obligations.json`'s 10 rows and 0 blocking are why no live obligation outran
  this stratum's evidence.

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current non-claims. The `PARITY_MODEL.md`
   labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a bounded `SEMANTIC_PASS`
   over the behaviours its courts exercise — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the names are defined and the courts' fixtures match; it does **not** show the crate's ENGINE
   registry, UI prompts or text-database codec are safe against a hostile input, and no court here
   is a fuzz or security gate. `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a
   boundary not exercised is recorded, not a safety guarantee.
3. **`libssl` is entirely scaffolded.** All 603 `libssl` exports remain `SCAFFOLDED` — a stub
   present, which cannot count as parity (`docs/PARITY_MODEL.md:22`, `docs/SEAL-CENSUS.md:21`,
   `forensics/STATUS.md:127-129`) — this stratum owns no `libssl` export and touches no TLS code.
4. **This stratum ships no provider registration row, and claims none.** The 39 legacy digest and
   cipher rows `providers/legacyprov.c` publishes belong to the loadable module the candidate ships
   as a scaffold `ossl-modules/legacy.so`, handed to the distribution stratum (Phase 16);
   `provider_rows_owned: 0` is a measurement, not an omission, and §1 states why.
5. **The deprecated statics are method objects, not provider fetches.** A deprecated `EVP_MD` static
   is handed to `EVP_DigestInit_ex`, which fetches the provider counterpart by short name; `EVP_sm3`
   is the default provider's and digests for real, while the legacy-provider-only `EVP_md4`,
   `EVP_mdc2` and `EVP_whirlpool` are refused identically on both sides. A green round trip is a
   statement about the fixture, not about every key size or mode.
6. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran* — 348 of the stratum's are `called` and 29
   are `referenced` (`docs/SEAL-CENSUS.md:523`) — and `RT-PHASE13-REF` in particular proves only
   that the candidate distribution defines the inherited names. Nothing here claims stderr
   equivalence, full CLI compatibility, build-profile independence beyond the admitted one, or
   drop-in substitution.
7. **The ENGINE built-in registry, the error queue and `eng_dyn` are boundaries, not passes.**
   `ENGINE_by_id`'s dynamic fallback answers NULL because `crypto/engine/eng_dyn.c` is absent, and
   the authority's built-in ids `dynamic`/`rdrand` diverge; those arms are recorded (§5), not driven
   to a shared answer.
8. **The FRF and Gemel evidence is established, and §8 records what it is.** `docs/RELEASE_GATES.md`
   §2 items 6, 8 and 10 are met by the chain entry §8 records: eight receipts, sixteen adjudicated
   challenge records, the `sensitivity-backed` claim
   `28423ad27ef5293c1bf5337cb82ce464f500a4d61aa6741ea32fcb9632a49ff9` with zero blockers, and the
   Gemel checkpoint `K53` whose summary names Phase 13 and the FRF chain. Phase 13's derived state
   is `complete`.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-13-SUBPHASES.md:269-277`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); every provider row it publishes is named by a court (D245, which this stratum has
nothing to hold against it) — and its §4.3 precondition (the reference-basis probe and the runner
land **with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase13-obligations.json`: `open_in_this_stratum` 0 (`:9`) and `deferred_to_later_phase` 0 (`:7`); the generator fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-13 block (`:44712`); `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` |
| the reference basis covers the inherited exports | `RT-PHASE13-REF` (`courts/phase13/rt_coverage_ref_probe.c`), registered with the ledger and runner (`docs/PHASE-13-SUBPHASES.md:237-259`); D199/D236 |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and D525 |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; `D-EVP-CIPHER-LEGACY-NID-1` was Phase 13's and did not block, and D526 has since retired it to `fixed` |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty, `implemented_by_two_strata` empty |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json`'s rule line |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is
the authority's own list (`docs/RELEASE_GATES.md:54-63`); the second says what this stratum's
evidence for it is, and, where an item is **not met**, says so plainly rather than leaving the row
empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase13/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase13-obligations.json` (`:5-12`); this stratum owns no provider row |
| 3 | court manifests | `artifacts/phase13/COURTS.json` |
| 4 | raw captures | **met.** The nine staged `artifacts/phase13/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (`artifacts/phase13/COURTS.json:19-22` and each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the eight declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty (`artifacts/phase13/COURTS.json:7-160`), `summary` reads `pass` 9 of 9 and `pending_courts` is empty (`:162-167`) |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries sixteen adjudicated Phase-13 records — both declared axes (`stdout-first-line`, `exit-class`) on each of the eight declarable courts, every one `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-13 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries one receipt per declarable court (`receipt-run-openssl-rs-rt-{engine,engine-table,engine-ctrl,ui,txtdb,evp-legacy,legacy-remainder,handoff}-*`), each with an empty `residuals` list |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 13's `C99` and its `current:` is `K53`, whose summary names Phase 13 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-13 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Eight declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-13 block — `("rt-engine", 13, …)` through `("rt-handoff", 13, …)` — and `gen_frf_courts.py`
  wrote the declarations under
  `forensics/frf/courts/openssl-rs-rt-{engine,engine-table,engine-ctrl,ui,txtdb,evp-legacy,legacy-remainder,handoff}`.
  `gen_frf_courts.py --check` reads `ok: 230 file(s) match the table (115 courts)`, and
  `forensics/frf/README.md:160` counts **115 runtime courts** — the Phase-13 eight among them, which
  moves the manifest count `docs/RELEASE_GATES.md`'s alternative names with it
  (D200/D413/D424/D475). **`RT-PHASE13-REF` is not declared**, because its probe takes addresses
  and diffs no transcript, so it is a reference basis with nothing to stage and cannot carry a
  declaration (D199).
- **The chain's objects are on disk.** `.frf/receipts/` carries eight Phase-13 receipts, one per
  declarable court
  (`receipt-run-openssl-rs-rt-{engine,engine-table,engine-ctrl,ui,txtdb,evp-legacy,legacy-remainder,handoff}-*`),
  each with an empty `residuals` list. `.frf/challenges/` carries sixteen adjudicated challenge
  records — both declared axes (`stdout-first-line` and `exit-class`) on each of the eight courts,
  every one `saw_defect` and `specificity_clean` — which is what makes the claim
  `sensitivity-backed` rather than merely green (D13). `.frf/claims/` carries the compiled claim
  `28423ad27ef5293c1bf5337cb82ce464f500a4d61aa6741ea32fcb9632a49ff9`, compiled at
  `--policy sensitivity-backed` over the eight receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.24` with zero blockers and all eight premises asserting both `stdout`
  and `exit`.
  **The identity moved with the 0.0.24 release.** The store was recreated from clean at candidate
  0.0.24 — FRF run identities are content-addressed on the declaration, which carries the candidate
  version, so every claim identity moves with a release — and the id quoted here supersedes the
  previous generation's `3a7a20d4…`, the 0.0.19 claim.
- **The Gemel change and checkpoint are this stratum's.** The change `C99` names Phase 13 and the
  FRF chain, and the checkpoint `K53`
  (`checkpoint.80d5b1bc4e22d27af750f51dfacc1f2aab7b1803f3a3369e177852e588b8c715`) closes it; the
  projection `forensics/GEMEL_TRAJECTORY.md` carries both, and the checkpoint's summary names
  Phase 13 and the FRF chain. Items 6, 8 and 10 of §7 retired with that entry, exactly as they did
  for Phase 9's `C94`, Phase 10's `C95`, Phase 11's `C97` and Phase 12's `C98`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase13-obligations.json`'s
`deferred` list is empty and its `deferred_by_phase` reads `{}`; every export this stratum owns is
implemented, and the 188 it *received* are discharged rather than passed on
(`docs/SEAL-CENSUS.md:447-451`). The one hand-off this seal makes is not of an export but of a
provider module: the 39 legacy-provider rows are handed to Phase 16 (§1), because Phase 13's
subphases deliberately do not activate the legacy provider.

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the eight
  declarations, eight receipts, sixteen adjudicated challenges, the claim
  `28423ad27ef5293c1bf5337cb82ce464f500a4d61aa6741ea32fcb9632a49ff9` and the checkpoint `K53`.
  This stratum registers no `CT-*` court, so the entry covers the eight behavioural differential
  courts and nothing is recorded as not declarable; `RT-PHASE13-REF` is the reference basis and is
  not declarable. Items 6, 8 and 10 of §7 retired with it, and `phase_state.py` derives `complete`.
- **This seal's §7 and §8 were corrected, and its bytes moved with the correction.** The receipts,
  claim id and checkpoint id were produced by running the chain in the FRF tooling container, never
  on the host, and `seal_sha256` is recomputed from the document's new bytes.
- **Phase 14 begins on a landed ENGINE, UI and TXT_DB substrate.** The `ENGINE_*`, `UI_*` and
  `TXT_DB_*` surfaces are now Phase 13's (`src/engine/`, `src/ui/`, `src/txt_db/`), and the
  deprecated METHOD-era statics, the PEM private-key spellings and the ASYNC framework are
  discharged rather than passed on.
- **`forensics/phase13-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the plan's own account, and the corrections
the evidence forced rather than the ones a reviewer might have preferred.

1. **The stratum's export ledger reaches zero open before the stratum is complete, and D525 writes
   the distinction down.** `phase13_obligations.py`'s `complete` is the ledger-level emptiness
   check, not the phase-exit predicate; the stratum is not complete until 13.9's seal and the
   FRF/Gemel chain (D525). This seal is that 13.9 document, and §7's item 6/8/10 rows are the
   predicate's remaining input.
2. **The plan's §4.2 assigned the 39 legacy-provider rows to Phase 13, and the census now hands them
   to Phase 16.** Phase 13's subphases deliberately do not activate the legacy provider
   (`docs/PHASE-13-SUBPHASES.md` §3.6), so `provider-algorithm-plans.json` hands the loadable
   module's rows to the distribution stratum that owns the installed `ossl-modules/` contract; the
   ledger's `provider_rows_owned` moves 39 → 0 and the plan's §1 and §4.2 are corrected to match
   (D525). A row the plan gives a later stratum is a decision this project allows, and taking it
   back is a decision too (D295).
3. **`crypto/engine/eng_dyn.c` is genuinely absent, and no subphase owns it.** 13.1 transcribes
   `ENGINE_by_id`'s miss path whole and takes the authority's own `notfound` arm, so the dynamic
   fallback is recorded rather than fabricated; the built-in `rdrand`/`dynamic` ids are therefore
   not observed (`src/engine/eng_list.rs:9-19`, `src/engine/mod.rs:77-79`).
4. **The legacy `OBJ_NAME` table was empty in the candidate, and D526 later filled it.** The
   `EVP_get_cipherbyname` arms were `pending.` with the reason rather than compared
   (`courts/phase13/rt_evp_legacy_probe.c:25-28,376-383`); 13.6's registration
   (`src/evp/c_allc.rs`/`c_alld.rs`, wired by `src/runtime/init.rs`'s `add_all_legacy_methods`, with
   `ossl_namemap_stored`'s first-use pre-population) closed it, and `D-EVP-CIPHER-LEGACY-NID-1` is
   now `fixed`.
5. **Two candidate bugs were found and fixed by the court.** `RT-EVP-LEGACY` exposed the
   `IDEA_ECB`/`SEED_ECB` `iv_len`, corrected in 13.6c; the court grew 720 → 1135 observations and
   the authority-tier atlas re-derives byte-identically (D525).
6. **The `DH PARAMETERS` reader is left undriven, and the reason is the decoder absence.** The two
   `PEM_read_bio_Parameters*` readers answer NULL where the authority answers a key, so the arm is
   recorded rather than compared (`docs/PHASE-13-SUBPHASES.md:417-420`,
   `courts/phase13/rt_legacy_remainder_probe.c:25`).
7. **The activation partition in the plan's §1 is an activation measurement, and the ledger is the
   live record.** `docs/PHASE-13-SUBPHASES.md:58-63` reads 250 open at activation and 127 already
   implemented; the ledger reads `implemented` 377, `deferred` 0, `open` 0 and the census reads the
   same. A number inside an older plan section is the value current when that section was written
   and is not this document's count.
8. **The FRF/Gemel chain entry landed after the seal was first written, and §7 and §8 record it.**
   The seal's first revision recorded items 6, 8 and 10 as owed; the chain entry added the eight
   declarations, eight receipts, sixteen adjudicated challenges, the `sensitivity-backed` claim
   `28423ad27ef5293c1bf5337cb82ce464f500a4d61aa6741ea32fcb9632a49ff9` and the Gemel change `C99` /
   checkpoint `K53`, so the three items retired and `phase_state.py` derives `complete`. The
   correction is appended here for the reason item 1 gives.
9. **The Phase-13 slices left the pipeline's generated atlases stale, and 13.9 regenerates and
   reconciles them.** 13.5–13.7 landed units without re-running the whole pipeline, so three
   artefacts drifted from their generators and only surfaced when 13.9 derived the stratum
   `complete`: `phase7_obligations.py`'s `LEGACY_HANDOFFS` still retired the landed statics' edges,
   reproducing `court_coverage.py`'s `implemented by both phase 7 and phase 13` fatal on a fresh
   regeneration; `dispatch_court.py` found five of the new `.c`-local callback aliases
   (`XtsStreamF`, `DesCbcF`, `DesEdeCbcF`, `QualFn`, `HashFn`) unlinked; and `prerequisites.json`'s
   `units` block still deferred 27 units to Phase 13. 13.9 retires the three digest families Phase 7
   itself implements (`EVP_sha`/`EVP_shake`, `EVP_blake2`, `EVP_ripemd`) from `LEGACY_HANDOFFS` and
   keeps the landed legacy edge rather than reclaiming it, exempts the five aliases with reasons,
   reclassifies the 27 records as `reached_by_a_named_construct`, and corrects the plan's
   `arch/async_posix.c` to `crypto/async/arch/async_posix.c`; every artefact re-derives green
   (`evidence_determinism.py --keep`, 33 artefacts).
