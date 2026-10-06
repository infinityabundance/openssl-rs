# Phase 16 — CLI / config / filesystem contract: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's obligation ledger is empty of open rows —
`forensics/phase16-obligations.json:36` reads `open_in_this_stratum: 0` — every earlier stratum
is `complete`, and the FRF/Gemel chain entry §8 records has landed, so
`forensics/phase-state.json` reports phase 16 **`complete`** with an empty blocking reason. That
derived state is the phase-exit predicate, and D529 records that a ledger's own `complete` is
*not* it (`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table at `16`, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum
has reached the state a seal *records* (D421); it is **not** a parity claim, and this document is
where what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This
seal cites that document rather than restating its arithmetic, because a number typed here is a
number that can drift from the evidence it summarises (D97). The one table this document *does*
carry — §3's court list — is copied from `artifacts/phase16/COURTS.json`, and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the behaviours the stratum's six differential courts
exercise match the pinned authority's over fixed fixtures, observation for observation. It does
**not** show that the crate's CLI is a drop-in replacement for the `openssl` program, that its
configuration loader handles every directive, that its `legacy` provider module is interchangeable
with the authority's, or that any of it is safe against a hostile input. `docs/PARITY_MODEL.md` is
the authority on what the labels mean: a passing bounded court is a differential result over the
behaviours that court exercises. `PARITY_VERIFIED` is not claimed for any symbol here — indeed this
stratum owns none — and `forensics/STATUS.md`'s non-claims are the generated projection's.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase16/COURTS.json:2`
- Court results: `artifacts/phase16/COURTS.json` — six courts, `all_pass` true
  (`artifacts/phase16/COURTS.json:5`), zero residuals; the per-court table is §3. All six are
  **differential** and all six declare an FRF court; this stratum registers **no reference basis**
  and no correctness `CT-*` court, and §1 and §3 state why.
- Obligation ledger: `forensics/phase16-obligations.json` — `owned` 42 (`:37`), `implemented` 42
  (`:35`), `deferred_to_later_phase` 0 (`:34`), `open_in_this_stratum` 0 (`:36`); its unit is
  `cli-config contract` (`:401`), a non-export unit, and its `atlas_owned` count is 0 (`:31`).
  `provider_rows_owned` 39 (`:39`, all `implemented`), `provider_rows_open` 0 (`:38`),
  `contract_units` 3 (`:32`), `deferrals_received` 0 (`:33`), `unit_deferrals_received` 0 (`:40`).
- Court coverage: `forensics/atlas/court-coverage.json` records **no phase-16 row**, and that is
  the join's own definition rather than an omission: `court_coverage.py` skips a ledger whose unit
  is in `atlas_common.NON_EXPORT_UNITS` (the same rule Phase 22's `compatibility plane` meets), so
  a stratum with no export universe can have no row and no unmatched export. §1 and §3 state the
  reading; `docs/DECISIONS.md` D485 records the marker.
- Provider-row coverage: `forensics/atlas/provider-court-coverage.json` joins the 39 `legacy` rows
  this stratum owns to the probes that name them, and `provider_rows_open` reads 0 (D245).
- Derived state: `forensics/phase-state.json`, phase 16, `complete` with empty blocking. It owns
  **no exported symbol**, so its `atlas_owned` count is 0 and its `provider_rows` projection is
  the 39 legacy rows (§1).
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries six
  receipts, one per declarable court; twelve adjudicated challenge records (both operators on every
  court); and the `sensitivity-backed` claim
  `9c22f43cf76a18ec7fa4d91b0e36a80d148340c856f61a3c699e2d8e5db973e9`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.25` with zero blockers and both stdout and exit
  asserted. §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s `current:`
  is the checkpoint `K59`
  (`checkpoint.8d19e4035974caf2073341c69b7cb97e40151d898762e984ae09269420310f8f`), whose summary
  names Phase 16 and the FRF chain; the change that closes it is
  `C106` (`change.c99a2fa221d37f65ba0a558c05a4ada1ce4db00151b5a2e14f0d5c1402cd71c5`). §8 states
  what that is.
- Deciding record: `docs/DECISIONS.md` — **D524** (the FRF requirement is read from the court
  inventory) is the predicate this stratum's chain engages through `artifacts/phase16/COURTS.json`,
  **D529** is the Phase-14 seal whose chain this one mirrors, **D525** hands the 39 legacy provider
  rows to this stratum, **D528** makes the absent dynamic ENGINE loader a Phase-16 obligation,
  **D490** records the CLI capture defect this stratum repairs, and `docs/PHASE-16-SUBPHASES.md` is
  the subphase plan this seal closes. §10 summarises the corrections this seal records.

## 1. What this phase owns, and how that was decided

Phase 16 is **the CLI / config / filesystem contract stratum**, and unlike every stratum from 3 to
15 it owns **no exported symbol**. Reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 16` yields nothing (`docs/PHASE-16-SUBPHASES.md:6-9`), because the
declaring-header rule assigns no installed header to this stratum; its ledger's `atlas_owned` count
is therefore `0` (`forensics/phase16-obligations.json:31`) and the ledger fails closed if that ever
stops being true rather than counting a symbol through a non-export unit
(`forensics/tools/phase16_obligations.py`).

**The working set is its rows, not its exports.** `forensics/phase16-obligations.json`'s `rule`
names three kinds of row, every one read from an atlas this stratum does not type:

* **the 39 `legacy` provider registration rows.** `forensics/atlas/provider-algorithms.json`
  assigns `providers/legacyprov.c`'s 4 `OSSL_OP_DIGEST` (MD4, MDC2, WHIRLPOOL, RIPEMD-160), 32
  `OSSL_OP_CIPHER` (CAST5, BF, IDEA, SEED, RC2, RC4, DESX, DES), 2 `OSSL_OP_KDF` (PBKDF1, PVKKDF)
  and 1 `OSSL_OP_SKEYMGMT` (GENERIC-SECRET) row to Phase 16, because Phase 13's subphases
  deliberately do not activate the legacy provider (D525, `docs/PHASE-13-SUBPHASES.md` §3.6). The
  loadable module the candidate ships as `ossl-modules/legacy.so` is the installed-module contract,
  and this stratum owns it. All 39 are published, so `provider_rows_open` reads 0 (`:38`).
* **the prerequisite deferrals.** `forensics/prerequisites.json` recorded the `OPENSSLDIR` /
  install-context strings (`ossl_get_openssldir`, `ossl_get_wininstallcontext`), the absent dynamic
  ENGINE loader (`engine_load_dynamic_int`, D528), the CLI option-list capture defect
  (`cli_option_list_parse`, D490) and the two TLS message-layer units Phase 15 sealed without (D525)
  with `owner_phase: 16`. **All six are retired**: 16.2 the loader, 16.3 the directory plane, 16.4
  the capture defect, and 16.5 the two message-layer units.
* **the CLI / config / filesystem contract** proper: the `openssl` CLI, config loading and the
  installed distribution layout, whose authority surface the Phase-1 capture and the Phase-22
  atlases measure. `forensics/phase16-obligations.json`'s `contract_units` reads 3 (`:32`), all
  `implemented`.

**This stratum publishes provider rows, and the census records it.** Unlike Phases 12, 13, 14 and
15, `provider_rows_owned` is **39** (`:39`), not 0: this is the stratum that owns the installed
module. The provider-row rule in `phase_state.py` (D237) and `provider_court_coverage.py` (D245)
hold it: every row is `implemented` and every row is named by a probe of the court that covers it.
`RT-LEGACY-MODULE` is that court (§3).

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work. This stratum emits no primitive: the CLI, the config loader
and the directory plane are *programs and strings over* the libraries, and the legacy provider's
rows publish registration tables and mode bodies over Phase 8's cipher engines. Its evidence is
therefore **differential only** — six `RT-*` courts and no `CT-*` court — which is a measurement
and not an omission (`docs/PHASE-16-SUBPHASES.md` §3.4). **There is no reference basis here**: every
court diffs a real transcript and stages an authority/candidate probe pair, so all six are
declarable and nothing is left to an address-taking `RT-*-REF` (contrast Phases 13, 14 and 15).

**It begins on nothing of its own, and ends owning everything it began with.** No module of this
stratum had landed at activation (`docs/PHASE-16-SUBPHASES.md:80-84`): there was no `apps/` CLI, no
dynamic ENGINE loader, no activated legacy provider table and no regenerated CLI capture, so
`open_in_this_stratum` opened at the whole working set and moved to zero as 16.1 through 16.5 landed
their rows and units. The ledger's `counts` is the live record; §1's activation measurement is the
plan's.

**This stratum is a non-export unit, and the export-partitioning tools say so by the document's own
field.** `forensics/phase16-obligations.json` publishes `unit: "cli-config contract"`, which
`atlas_common.NON_EXPORT_UNITS` contains, so `court_coverage.py` and `ownership_audit.py` skip the
ledger rather than reconcile a symbol set that does not exist — exactly as they skip Phase 22's
`compatibility plane` (D485). The export-coverage rule in `phase_state.py` was reconciled to the same
reading by this seal (D199/D236; §10), because a stratum with no export universe can have no
`court-coverage.json` row and no unmatched export.

## 2. What has been built

**16.0, the plan and the ledger.** `docs/PHASE-16-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase16-obligations.json` and its generator, and the runner
`forensics/tools/phase16_courts.py` with the empty registry it writes. The runner could not be
deferred (`docs/PHASE-16-SUBPHASES.md` §4.2): `run_courts.py` refuses a stratum that is not
`not-started` and has no runner, and this stratum's obligations are not exports, so its first
runnable court is a later subphase's. It landed with `PENDING_COURTS` naming all six, which 16.1
through 16.5 emptied.

**16.1, the legacy provider module.** `src/provider/legacyprov.rs` (the module's
`OSSL_provider_init`, `legacy_gettable_params`, `legacy_get_params`, `legacy_query`,
`legacy_teardown` and dispatch table), the four `legacy_digests` and one `legacy_skeymgmt` rows in
slice 1; the 32 `legacy_ciphers` rows as the `legacy` submodule of `src/provider/cipher.rs` in slice
2; and the two `legacy_kdfs` rows in `src/provider/kdf.rs` in slice 3. The module's loadable
contract is `ossl-modules/legacy.so`, whose one exported symbol is `OSSL_provider_init`
(`docs/PHASE-16-SUBPHASES.md` §3.5). `RT-LEGACY-MODULE` (344 observations) loads it through
`OSSL_PROVIDER_load`, reads its name, queries all four operation tables, fetches and drives the
digest, cipher and KDF rows, and exercises the refusal arms.

**16.2, the dynamic ENGINE loader.** `crypto/engine/eng_dyn.c` as `src/engine/eng_dyn.rs`:
`engine_load_dynamic_int`, the `dynamic` engine's command table, the `ex_data` context,
`dynamic_load`, `int_load` and the `DynamicFns` ABI, over 13.1's `ENGINE_by_id` and the DSO surface.
`src/runtime/init.rs` runs `ossl_init_engine_dynamic` for the `OPENSSL_INIT_ENGINE_DYNAMIC` bit,
which left `INIT_UNSUPPORTED`. `RT-ENGINE-DYN` (10 observations) drives it to a refusing `LOAD`.

**16.3, the directory and install-context plane.** `ossl_get_openssldir` and
`ossl_get_wininstallcontext` in `src/runtime/defaults.rs`, routed from `OPENSSL_info`'s `CONFIG_DIR`,
`ENGINES_DIR`, `MODULES_DIR` and `WINDOWS_CONTEXT` codes. `RT-DEFAULTS` (10 observations) reads
`OPENSSL_info(1001)` and checks it against `X509_get_default_cert_area()`, the four
`X509_get_default_*` paths and the install context.

**16.4, the `openssl` CLI and config loading.** `apps/openssl.c` as `src/apps/openssl.rs`, the
option parser `apps/lib/opt.c` as `src/apps/opt.rs`, and the `functions[]` dispatch table plus every
command's `OPTIONS[]` table as the generated `src/apps/tables.rs`
(`forensics/tools/gen_cli_tables.py`). The Phase-2 link machinery's `openssl` executable forwards to
the crate. Three command bodies are landed because their output is build-independent and the court
drives them — `help`, `list` and `version`; the other 52 `apps/<name>.c` bodies reach a `not landed`
boundary (`docs/PHASE-16-SUBPHASES.md` §3.8). The regenerated Phase-1 captures are
`forensics/atlas/openssl-3.6.4-production/cli-commands.json` and
`forensics/atlas/openssl-3.6.3-historical/cli-commands.json`, produced in lockstep (D490).
`RT-CLI` (252 observations) runs the two executables over a fixed argv and drives
`atlas_runtime.parse_option_list` over every captured option table; `RT-CONFIG` (31 observations)
drives the config loader over a fixed in-memory configuration.

**16.5, the TLS message layer units.** `ssl/statem/statem_clnt.c` and `statem_srvr.c` as
`src/ssl/statem/statem_clnt.rs` and `statem_srvr.rs`: the read/write *transition* functions and the
`received_*` predicates. `RT-STATEM-REMAINDER` (20 observations) drives the state the landed
transitions leave a fresh connection in. The **message bodies** the transitions select are not
landed and are a stated boundary (§5).

**The books that moved with the code.** Phase 16's own ledger reads `owned` 42, `implemented` 42,
`deferred_to_later_phase` 0 and `open_in_this_stratum` 0 (`forensics/phase16-obligations.json:34-37`),
with all 39 provider rows published (`:38-39`). It received no export hand-off
(`deferrals_received` 0) and passed none on (`deferred_to_later_phase` 0); the six prerequisite
deferrals it received were *unit* and *symbol* deferrals, discharged in stride, and do not move
those counts.

## 3. The evidence

Copied from `artifacts/phase16/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. Every court is differential; the stratum registers no correctness
`CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-LEGACY-MODULE` | differential | 344 | `courts/phase16/rt_legacy_module_probe.c` |
| `RT-ENGINE-DYN` | differential | 10 | `courts/phase16/rt_engine_dyn_probe.c` |
| `RT-DEFAULTS` | differential | 10 | `courts/phase16/rt_defaults_probe.c` |
| `RT-CONFIG` | differential | 31 | `courts/phase16/rt_config_probe.c` |
| `RT-STATEM-REMAINDER` | differential | 20 | `courts/phase16/rt_statem_remainder_probe.c` |
| `RT-CLI` | differential | 252 | `courts/phase16/rt_cli_probe.sh` (shell probe) |

Every row carries `residual_count: 0` and `verdict: "pass"` (`artifacts/phase16/COURTS.json`), and
the summary reads `pass` 6 of `total` 6 with `pending_courts` empty. The total over the six
transcript courts is `docs/SEAL-CENSUS.md`'s (**667** authority observations), and the per-court rows
there are the same computation.

**`RT-CLI` is a shell probe, and it is declared honestly.** The CLI is an executable, not a linkable
symbol, so `courts/phase16/rt_cli_probe.sh` is the instrument: it drives one side's `openssl` over
the fixed 63-case argv and prints the same `case.N.*` transcript the court venue diffs.
`forensics/tools/phase16_courts.py` stages it as the
`artifacts/phase16/probes/rt_cli_probe.{authority,candidate}` shim pair the FRF runtime harness
runs, and `gen_frf_courts.py` declares that `.sh` source as the court's data artifact rather than a
`rt_cli_probe.c` (`PROBE_SOURCES`). The other five courts are the compiled C probes 16.1–16.5
landed.

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: it lands a CLI, a
config loader, a directory plane, a provider registration table and a message-layer transition
surface, and a `CT-*` court is a vector-driven construction check with no authority transcript to
diff (D13, D201). The stratum's evidence is therefore **differential only**, which is a
measurement and not an omission, and every arm that could not be driven is named in the module or
the court rather than counted as passing (§5).

**The court coverage join does not have a phase-16 row, and that is the join's own definition.**
`docs/SEAL-CENSUS.md`'s coverage table lists phases 3 through 15 and no phase 16, exactly as it lists
no phase 22: both are non-export units, so `court_coverage.py` skips their ledgers and there is no
export to partition. `directly_courted` in this project means *referenced by a staged candidate
probe that ran and produced a transcript* — a proof of **reference** rather than that every arm of
a symbol was driven (D199/D236); with zero exports the join is vacuous here. The provider-row join
(D245) is the one that is not vacuous: all 39 rows are named by `RT-LEGACY-MODULE`.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found no defect in the candidate. It did find a defect in the *harness*, which is why this
section is not empty.

**The legacy provider module is held to the authority's own tables.** `RT-LEGACY-MODULE` established
that the module loads through `OSSL_PROVIDER_load` with each side's own `OPENSSL_MODULES`, that
`OSSL_PROVIDER_get_params` reports the same provider name, that the four operation tables carry the
same row counts and first-row alias sequences, that the four digests match a fixed `"abc"` digest by
name and by OID, that all 32 ciphers encrypt-and-decrypt a fixed key/IV round trip and that both
KDFs derive the same 32 bytes — and that the refusal arms (unknown names, a legacy name asked of
`default`, and the two `PBKDF1` refusals) agree.

**The engine loader, directory plane, CLI and config loader agree with the authority.** `RT-ENGINE-DYN`
holds the `dynamic` engine's registration, `ENGINE_by_id`'s fallback chain and its refusals;
`RT-DEFAULTS` holds the `OPENSSLDIR`/install-context plane; `RT-CLI` holds the dispatcher's arms,
the three build-independent command bodies and every command's option table; `RT-CONFIG` holds the
config loader over fixed memory and the default-config-file path.

**The one finding: the runtime harness's `OPENSSL_MODULES` gap, and it was fixed in the probe.**
The FRF run of `RT-LEGACY-MODULE` diverged on both axes (authority exit 0, candidate exit 1) while
the court venue passed it. The cause is that the shared
`forensics/frf/refs/{authority,candidate}-runtime-probe.sh` set `LD_LIBRARY_PATH` but not
`OPENSSL_MODULES`, which the court venue's `side_env` sets. The candidate distribution shell is not
installed, so its compiled-in `MODULESDIR` is empty — the recorded divergence §5.4 names — and its
side therefore failed to find `legacy.so`. The shared harness is **not** changed, because its
`candidate-runtime-probe.sh` hash is the candidate `identity_hash e4f60d8b` every compiled claim in
the store records. The fix is in the probe instead: `courts/phase16/rt_legacy_module_probe.c` now
sets `OPENSSL_MODULES` to its own side's `ossl-modules/` when the variable is unset, deriving the
side from `argv[0]`, so one source serves both sides and the court is reproducible under either
harness. §10 records the correction.

**No generator drift the stratum's own slices left went unreconciled.** Unlike Phase 14 (D529),
whose later slices left four artefacts that only surfaced when the stratum was derived `complete`,
this stratum's slices are one plan, one ledger, one runner and six courts, and deriving `complete`
surfaced four reconciliations: the export-coverage scope-out, the `RT-CLI` shell-probe declaration
(the declaration template learned a probe source need not be C), the two `prerequisites.json` unit
records `plan_reconciliation.py` required, and the probe's module path. All four are recorded in
§10.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or builds an object this crate
does not, the court does not call it and the divergence is recorded. **No divergence obligation
names Phase 16 as its `current_owner`.** `forensics/divergence-obligations.json` reads 10 rows and
**0 blocking** at seal time; no live obligation outran this stratum's evidence, so `phase_state.py`
derives `complete`. The boundaries this stratum actually met are recorded in the places below.

1. **The monolithic crate's `legacy.so` object set.** The authority's `legacy.so` is self-contained
   — it carries its own legacy primitives and reaches libcrypto only through the core dispatch — but
   this crate is monolithic (`Cargo.toml`: one implementation crate), so
   `forensics/tools/build_phase2.sh` builds `legacy.so` from the crate's own archive plus a generated
   entry object. The **loadable contract** is unchanged (`NEEDED libcrypto.so.3`, one exported
   symbol, `OSSL_provider_init`); the divergence is the object set behind it
   (`docs/PHASE-16-SUBPHASES.md` §3.5).
2. **The TLS message bodies remain unlanded, and the 56 omitted names are machine-recorded.**
   16.5 transcribed the read/write *transition* surface of `ssl/statem/statem_clnt.c` and
   `statem_srvr.c` but not the bodies those transitions select, because they build and parse bytes
   through the record layer, the extension units and the key schedule, none of which is landed. The
   56 omitted names are a `reduced_transcription` divergence in `forensics/prerequisites.json`
   (`covers`, 56 names), so the boundary is stated rather than silent. No arm of
   `RT-STATEM-REMAINDER` builds or parses a flight.
3. **`OPENSSL_INIT_ENGINE_ALL_BUILTIN` is still refused.** 16.2 landed the `_DYNAMIC` bit, but
   `eng_openssl.c` and `eng_rdrand.c` are not landed, so the remaining engine bits still trip
   `INIT_UNSUPPORTED` and `ENGINE_load_builtin_engines` remains the recorded boundary
   `src/engine/eng_all.rs` names (`src/runtime/init.rs:32-33`). `RT-ENGINE-DYN` does not drive the
   all-builtin mask.
4. **The raw `OPENSSLDIR` value is a distribution fact, not an authority fact.** The `OPENSSLDIR`
   strings name the admitted build's forensic tree; the candidate answers its own
   `OPENSSL_RS_OPENSSLDIR` or the **empty C string** when unset, and the engines/modules dirs are
   NULL when no prefix was built. `RT-DEFAULTS` compares the *relationship*
   (`OPENSSL_info(1001) == X509_get_default_cert_area()`, and the four paths' suffixes), not the
   raw path, and records the difference as a value the stratum does not claim
   (`src/runtime/defaults.rs`; `docs/PHASE-16-SUBPHASES.md` §3.2 and §3.7).
5. **The CLI command bodies are a boundary.** 52 of the 55 `apps/<name>.c` bodies are not landed, so
   a command that reaches one is not driven; `RT-CLI` exercises the dispatcher and the
   build-independent bodies and reaches a `not landed` boundary for the rest
   (`docs/PHASE-16-SUBPHASES.md` §3.8). No engine module is installed either, so a real `.so` load
   waits on the distribution's engine-module contract.
6. **The `pending.` set is empty, and that is a measurement.** Every court the plan names is
   registered in `artifacts/phase16/COURTS.json`, and `PENDING_COURTS` is empty; this stratum owns no
   exported symbol, so nothing is counted as pending rather than dropped (§3).

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable drop-in OpenSSL.** `implemented` in the ledgers means a symbol
   with that name is defined, and this stratum defines none. `docs/PARITY_MODEL.md` states what each
   label means; no symbol here is `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current
   non-claims. The labels this stratum's evidence reaches are at most `IMPLEMENTED` for the 39
   provider rows, plus a bounded `SEMANTIC_PASS` over the behaviours its six courts exercise — never
   `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the courts' fixtures match; it does **not** show the crate's CLI, config loader, directory plane,
   legacy module or message-layer transitions are safe against a hostile input, and no court here is
   a fuzz or security gate. `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a boundary
   not exercised is recorded, not a safety guarantee.
3. **No drop-in CLI claim.** `RT-CLI` compares the dispatcher's arms, three build-independent
   command bodies and every command's option table over a fixed argv. It does not establish
   byte-identical stderr, the 52 unlanded command bodies, full CLI compatibility, or that
   `openssl <command>` works for any command whose body is not landed.
4. **No working-provider claim beyond the registration table and the driven rows.** A published
   provider row says the module publishes the registration, not that every arm of the algorithm
   matches; `RT-LEGACY-MODULE` drives a fixed digest, a fixed encrypt/decrypt and a fixed derive per
   row and the refusal arms, and nothing more. §5.1's object-set divergence stands.
5. **No completed-handshake claim.** No court here builds or parses a TLS flight: the message bodies
   are the 56-name `reduced_transcription` boundary (§5.2), and `RT-STATEM-REMAINDER` compares the
   state a fresh connection is left in, not a handshake.
6. **This stratum publishes provider rows, and claims only what the join holds.** All 39 rows are
   `implemented` and every one is named by a probe (D237, D245); the claim is publication and
   observation, not parity.
7. **A passing court is a differential result over the behaviours its probe exercises.** Nothing
   here claims stderr equivalence, full CLI compatibility, build-profile independence beyond the
   admitted one, or drop-in substitution.
8. **The FRF and Gemel evidence is established, and §8 records what it is.**
   `docs/RELEASE_GATES.md` §2 items 6, 8 and 10 are met by the chain entry §8 records: six
   receipts, twelve adjudicated challenge records, the `sensitivity-backed` claim
   `9c22f43cf76a18ec7fa4d91b0e36a80d148340c856f61a3c699e2d8e5db973e9` with zero blockers, and the
   Gemel checkpoint `K59` whose summary names Phase 16 and the FRF chain. Phase 16's derived state
   is `complete`.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own
gates are its §5 process (`docs/PHASE-16-SUBPHASES.md:231-236`) — a subphase lands its code, its
court and its regenerated artefacts in **one commit**; every name a subphase lands carries a court
edge where it has one; and an artefact a source change moves is regenerated in the same commit — and
its §4.2 precondition (the runner lands **with** the ledger). Every clause below is checked against
a generated artefact rather than asserted.

| criterion | evidence |
|---|---|
| every row this stratum owns is implemented or handed on with the dependency named | `forensics/phase16-obligations.json`: `open_in_this_stratum` 0 (`:36`) and `deferred_to_later_phase` 0 (`:34`); its 39 provider rows are all `implemented` (`:38-39`) |
| every provider row is observed | `forensics/atlas/provider-court-coverage.json`; `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` (D245) |
| the export-coverage join is vacuous here, and that is the marker's rule | no phase-16 row in `forensics/atlas/court-coverage.json`, because `phase16-obligations.json`'s `unit` is in `atlas_common.NON_EXPORT_UNITS` (D485); `phase_state.py` scopes the rule out for such a ledger |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and the modules |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 16 |
| `ABI-PROTOTYPE`, `ABI-SYMBOL` and `ABI-DYNAMIC` stay clean | `forensics/atlas/ownership-audit.json`: `problems` empty, `implemented_by_two_strata` empty |
| the prototype court clean | `forensics/atlas/prototype-court.json`: `mismatches` 0 |
| the dispatch court clean | `forensics/atlas/dispatch-court.json`: `problems` 0 |
| the prerequisite gate at zero findings | `forensics/atlas/prerequisite-gate.json`: `findings` empty |
| the plan reconciliation at zero findings | `forensics/atlas/plan-reconciliation.json`: `findings` empty |
| the earlier strata are complete, which the rule requires | `forensics/phase-state.json`'s rule line |
| the courts are re-derived on every push, not trusted from a committed file | the `courts` job in `.github/workflows/ci.yml` runs `court/pipeline.sh` |
| a commit may not undo an earlier commit's evidence | `forensics/tools/regression_guard.py` against the branch's previous head and against `origin/main` |

**`docs/RELEASE_GATES.md` §2's ten items, each checked rather than assumed.** The first column is the
authority's own list (`docs/RELEASE_GATES.md:54-63`); the second says what this stratum's evidence
for it is, and, where an item is **not met**, says so plainly rather than leaving the row empty.

| # | item | this stratum's evidence |
|---|---|---|
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase16/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase16-obligations.json` (`:30-41`); 39 provider rows, 3 contract units, 3 non-export rows |
| 3 | court manifests | `artifacts/phase16/COURTS.json` |
| 4 | raw captures | **met.** The six staged `artifacts/phase16/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the six declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty, `summary` reads `pass` 6 of 6 and `pending_courts` is empty |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries twelve adjudicated Phase-16 records — both declared axes (`stdout-first-line`, `exit-class`) on all six declarable courts, each `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-16 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries six receipts, one per declarable court, each with an empty `residuals` list |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s `current:` is `K59` (`checkpoint.8d19e4035974caf2073341c69b7cb97e40151d898762e984ae09269420310f8f`), whose summary names Phase 16 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-16 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Six declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-16 block — `rt-legacy-module`, `rt-engine-dyn`, `rt-defaults`, `rt-config`,
  `rt-statem-remainder` and `rt-cli` — and `gen_frf_courts.py` wrote the six declarations under
  `forensics/frf/courts/openssl-rs-rt-<court>`. `gen_frf_courts.py --check` reports
  `ok: 264 file(s) match the table (132 courts)`, and `forensics/frf/README.md` counts **132 runtime
  courts** — the six Phase-16 ones among them, which moves the manifest count `docs/RELEASE_GATES.md`
  names with it. **There is no reference basis**, so no row is left undeclared; every court diffs a
  transcript. `rt-cli`'s data artifact is `courts/phase16/rt_cli_probe.sh` (a shell probe) rather
  than a `.c` file, and `forensics/tools/gen_frf_courts.py`'s `PROBE_SOURCES` records that.
- **The chain's objects are on disk.** `.frf/receipts/` carries six Phase-16 receipts, each with an
  empty `residuals` list. `.frf/challenges/` carries twelve adjudicated challenge records — both
  declared axes (`stdout-first-line`, `exit-class`) on all six courts, every one `saw_defect` and
  `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green
  (D13). `.frf/claims/` carries the compiled claim
  `9c22f43cf76a18ec7fa4d91b0e36a80d148340c856f61a3c699e2d8e5db973e9`, compiled at
  `--policy sensitivity-backed` over the six receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.25` (`identity_hash e4f60d8b`) with zero blockers and the premises
  asserting both `stdout` and `exit`.
  **The identity is the current 0.0.25 release.** The chain was cut into the store the 0.0.25 release
  regenerated from clean — FRF run identities are content-addressed on the declaration, which
  carries the candidate version — so this claim records the candidate the tree is
  (`gen_frf_courts.CANDIDATE_VERSION`), which is what the fix-4 identity clause requires.
- **The Gemel change and checkpoint are this stratum's.** The change `C106`
  (`change.c99a2fa221d37f65ba0a558c05a4ada1ce4db00151b5a2e14f0d5c1402cd71c5`) names Phase 16 and the
  FRF chain, and the checkpoint `K59`
  (`checkpoint.8d19e4035974caf2073341c69b7cb97e40151d898762e984ae09269420310f8f`) closes it; the
  projection `forensics/GEMEL_TRAJECTORY.md` carries both, and the checkpoint's summary names Phase
  16 and the FRF chain. Items 6, 8 and 10 of §7 retired with that entry, exactly as they did for
  Phase 8's `C74`, Phase 9's `C94`, Phase 10's `C95`, Phase 11's `C97`, Phase 12's `C98`, Phase 13's
  `C99`, Phase 14's `C101` and Phase 15's `C103`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase16-obligations.json`'s
`deferred` list is empty and its `deferred_to_later_phase` reads 0; every row this stratum owns is
implemented or, for the provider rows, published, and it received no export hand-off. The CLI's 52
unlanded command bodies, the unbuilt QUIC object and the TLS message bodies are not rows this
stratum's ledger owns — the last is a named divergence rather than a deferral (§5.2) — so nothing
moves to Phase 17.

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the six
  declarations, six receipts, twelve adjudicated challenges, the claim
  `9c22f43cf76a18ec7fa4d91b0e36a80d148340c856f61a3c699e2d8e5db973e9` and the checkpoint `K59`.
  This stratum registers no `CT-*` court, so the entry covers the six behavioural differential
  courts and nothing is recorded as not declarable. Items 6, 8 and 10 of §7 retired with it, and
  `phase_state.py` derives `complete`.
- **The harness `OPENSSL_MODULES` gap is fixed where it belongs and recorded here.** §4 tells a
  later module-loading court why it does not have to rediscover it: the probe names its own side's
  module directory, and the shared harness and the candidate reference wrapper — whose hash is the
  store's candidate identity — are untouched.
- **`forensics/phase16-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and row figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the evidence and the tools, and the
corrections the evidence forced rather than the ones a reviewer might have preferred.

1. **The export-coverage rule in `phase_state.py` is scoped out for a non-export unit.** The rule
   required every begun stratum to have a `court-coverage.json` row with no unmatched export, but
   `court_coverage.py` skips a ledger whose `unit` is in `atlas_common.NON_EXPORT_UNITS` — so Phase
   16 (and Phase 22) can never have a row, and the rule demanded one the join cannot produce. Deriving
   Phase 16 `complete` exposed it. The rule now reads the ledger's `unit` and applies the export join
   only to a stratum with an export universe, which is the same marker the partitioning tools use
   (D199/D236, D485).
2. **`RT-CLI`'s instrument is a shell probe, and the declaration template learned that a probe source
   need not be C.** The CLI is an executable, not a linkable symbol, so 16.4 implements the court in
   `phase16_courts.py` by staging a shell probe. Declaring it exposed that `gen_frf_courts.py`'s
   manifest hard-coded `courts/phaseN/<probe>.c` as the data artifact and a "one C program" preamble.
   The seal adds `PROBE_SOURCES` and a `preamble_cli` variant, and `phase16_courts.py` stages
   `courts/phase16/rt_cli_probe.sh` plus the two per-side shims and records them in the `RT-CLI`
   row, so the declaration is honest about its instrument.
3. **The `RT-LEGACY-MODULE` probe names its own side's `ossl-modules/`.** The FRF venue found a
   divergence the court venue did not, and the cause was an environment gap in the shared runtime
   harness: it set `LD_LIBRARY_PATH` but not `OPENSSL_MODULES`, while the court venue's `side_env`
   sets it. The candidate shell's compiled-in `MODULESDIR` is empty (a recorded divergence, §5.4),
   so its side failed to load `legacy.so`. The shared harness could not be changed — its candidate
   wrapper's hash is the store's candidate `identity_hash` — so the probe now sets the variable when
   unset, deriving its side from `argv[0]`. This is the "record the boundary rather than fabricate"
   disposition of `docs/PHASE-16-SUBPHASES.md` §4 applied to the instrument itself.
4. **Two authority units the plan names are recorded as reached in `forensics/prerequisites.json`'s
   `units` block.** Deriving Phase 16 `complete` made `plan_reconciliation.py` refuse it with
   `plan_named_unit_not_reached` for `providers/legacyprov.c` (16.1) and `apps/openssl.c` (16.4):
   the crate lands them in `src/provider/legacyprov.rs` and `src/apps/openssl.rs`, but neither is a
   *dominant* transcription edge -- `legacyprov.rs` maps to `providers/prov_running.c` through
   `ossl_prov_is_running`, and the CLI is a `main`-bearing program with no library internal -- so
   the three mechanical signals cannot see them. The seal adds one `reached_by_a_named_construct`
   record per unit, each naming the crate module and the crate's own constructs (D132's mechanism),
   so the plan's rows are read as reached rather than as promises.
5. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the six
   declarations, six receipts, twelve adjudicated challenges, the `sensitivity-backed` claim
   `9c22f43cf76a18ec7fa4d91b0e36a80d148340c856f61a3c699e2d8e5db973e9` and the Gemel change
   `C106` / checkpoint `K59`
   (`checkpoint.8d19e4035974caf2073341c69b7cb97e40151d898762e984ae09269420310f8f`), so items 6, 8
   and 10 retired and `phase_state.py` derives `complete`. `seal_sha256` is recomputed from the
   document's new bytes.
