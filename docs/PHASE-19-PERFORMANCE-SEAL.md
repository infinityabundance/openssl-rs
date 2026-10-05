# Phase 19 — the performance / CPU dispatch stratum: seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's obligation ledger is empty of open rows —
`forensics/phase19-obligations.json` reads `open_in_this_stratum: 0` — every earlier stratum is
`complete`, and the FRF/Gemel chain entry §8 records has landed, so `forensics/phase-state.json`
reports phase 19 **`complete`** with an empty blocking reason. That derived state is the
phase-exit predicate, and D529 records that a ledger's own `complete` is *not* it
(`docs/DECISIONS.md`). `seal_sha256` is derived too: this document is named in
`forensics/tools/atlas_common.py`'s `SEAL_DOCS` table at `19`, which
`forensics/tools/render_seal_census.py` and `phase_state.py` read, so the line is recomputed
whenever this document changes and is not restated here. Reaching `complete` means the stratum has
reached the state a seal *records* (D421); it is **not** a performance or parity claim, and this
document is where what the derivation does and does not cover is written down.

**For every count in this document, read `docs/SEAL-CENSUS.md`**, which
`forensics/tools/render_seal_census.py` generates from the ledgers and the court results. This seal
cites that document rather than restating its arithmetic, because a number typed here is a number
that can drift from the evidence it summarises (D97). The tables this document *does* carry — §3's
court list and §7's criterion tables — each name the artefact they were read from.

**This seal records performance-dispatch and deterministic-work evidence over the finished
implementation, and it is neither a benchmark nor a parity claim.** Its evidence shows that the
candidate's CPU-capability surface and its EVP/cipher selection were driven under fixed and faulted
capability sets against the admitted authority, that a deterministically slowed path was caught by
the work instrument the stratum introduces, and that the register cannot claim more than the courts
measured. It does **not** show that the candidate is as fast as the authority anywhere, that any
assembly path and any Rust path are equivalent work, that any wall-clock or instruction-count
figure, or that any throughput ratio, is a claim. `docs/PARITY_MODEL.md` is the authority on what
the labels mean, and `docs/NON_CLAIMS.md`, `docs/SECURITY_DIVERGENCE_POLICY.md` and
`docs/UNSAFE.md` are the authorities on what may be said. `PARITY_VERIFIED` is not claimed for any
symbol here — indeed this stratum owns none — and `forensics/STATUS.md`'s non-claims are the
generated projection's.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json`), named as the
  authority by `artifacts/phase19/COURTS.json`. The FRF chain binds the runtime authority identity
  `openssl-rt-3.6.4-r2`.
- Court results: `artifacts/phase19/COURTS.json` — five courts, `all_pass` true, `summary` `pass`
  5 of 5, `pending_courts` empty; the per-court table is §3. Three are **differential transcript
  courts** that declare an FRF court (`RT-CPU-CAPABILITY`, `RT-EVP-DISPATCH`,
  `RT-PERFORMANCE-WORK`); `RT-PERFORMANCE-SENSITIVITY` is **candidate-only** (there is no authority
  transcript for a deliberately slowed harness construction) and `PERFORMANCE-BOUNDARY-REGISTER` is
  a **data-validation** court whose own row is marked `frf_declarable: false`, and §1, §3 and §5
  state why neither is declared.
- Obligation ledger: `forensics/phase19-obligations.json` — `owned` 5, `implemented` 5,
  `deferred_to_later_phase` 0, `open_in_this_stratum` 0; its unit is `performance dispatch
  contract`, a non-export unit, and its `atlas_owned` count is 0. `contract_units` 5,
  `provider_rows_owned` 0, `provider_rows_open` 0, `deferrals_received` 0 and
  `unit_deferrals_received` 0: it receives and hands forward nothing.
- Court coverage: `forensics/atlas/court-coverage.json` records **no phase-19 row**, and that is
  the join's own definition rather than an omission: `court_coverage.py` skips a ledger whose unit
  is in `atlas_common.NON_EXPORT_UNITS` (the same rule Phase 16's `cli-config contract`, Phase 17's
  `downstream replacement contract` and Phase 18's `hostile hardening contract` meet), so a stratum
  with no export universe can have no row and no unmatched export. §1 and §3 state the reading;
  `docs/DECISIONS.md` D485 records the marker.
- Derived state: `forensics/phase-state.json`, phase 19, `complete` with empty blocking. It owns
  **no exported symbol**, so its `atlas_owned` count is 0 and it registers no provider row.
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries three
  receipts, one per declarable court; six adjudicated challenge records (both declared operators
  on every court); and the `sensitivity-backed` claim
  `4293b9a67fa11c4543b8706e68ecce08ee5ac87b6b49517ea61013f304a6853d`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.24` (`identity_hash e4f60d8b`) with zero blockers. Two
  of the three premises are narrowed to the exit class, and §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s
  `current:` is the checkpoint `K66`
  (`checkpoint.0bf45588d399b1403893ddee3b717149efc556c23272cedad51b3b5f0a686237`), whose summary
  names Phase 19 and the FRF chain; the change that closes it is `C112`
  (`change.0084009a48bc9d12daa15d0cac4603836d7cac35ee47be3034a0e6392522f1ea`). §8 states what
  that is.
- Deciding record: `docs/DECISIONS.md` — **D485** is the non-export-unit marker Phase 16, 17 and 18
  share, **D13** and **D201** are the rules under which a candidate-only court is not
  FRF-declarable, and `docs/PHASE-19-SUBPHASES.md` is the subphase plan this seal closes. §10
  summarises the corrections this seal records.

## 1. What this phase owns, and how that was decided

Phase 19 is **the performance / CPU dispatch contract stratum**, and like Phases 16, 17 and 18 it
owns **no exported symbol**. Reading `forensics/atlas/symbol-ownership.json` for `owner_phase == 19`
yields nothing (`docs/PHASE-19-SUBPHASES.md:47-50`), because the declaring-header rule assigns no
installed header to this stratum; its ledger's `atlas_owned` count is therefore `0` and the ledger
fails closed if that ever stops being true rather than counting a symbol through a non-export unit
(`forensics/tools/phase19_obligations.py`).

**Its working set is its five contract units, and it receives and hands forward nothing.** Like
Phase 18 it takes no unit or symbol deferral from an earlier stratum and defers none: the
implementation whose dispatch behaviour and deterministic work it measures is the one Phases 3
through 18 completed. It receives zero provider registration rows and owns none, and reading
`forensics/prerequisites.json` for `owner_phase == 19` gives neither a `deferrals` row nor a `units`
row (`docs/PHASE-19-SUBPHASES.md` §1 and §4.4). The ledger fails closed if the ownership atlas
assigns it an export, the provider census a row, or the prerequisite plane a deferral or a unit.

**The contract is five units**, each derived from a court that measures it: `cpu-capability`
(`RT-CPU-CAPABILITY`), `evp-dispatch` (`RT-EVP-DISPATCH`), `performance-work`
(`RT-PERFORMANCE-WORK`), `performance-sensitivity` (`RT-PERFORMANCE-SENSITIVITY`) and
`performance-boundary-register` (`PERFORMANCE-BOUNDARY-REGISTER`). The ledger's `contract_units`
reads 5 and all five are `implemented`. At activation the runner registered all five as `pending`,
so `open_in_this_stratum` opened at the whole working set (five) and moved to zero as 19.1 through
19.5 landed their rows and units; the ledger's `counts` is the live record and §1's activation
measurement is the plan's.

**The ledger's unit is not an exported symbol.** `forensics/phase19-obligations.json` publishes
`unit: "performance dispatch contract"`, its `implemented`/`open` *export* lists are empty by
measurement, and its working set is counted in `open_in_this_stratum` over the five contract units.
`atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export universe
(`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a symbol set that
does not exist (D485).

**The two axes are recorded separately, and that is the point of the ledger shape.** Each contract
unit carries `measurement_state` (the instrument ran and its control was honest) beside
`property_status` and `findings` (what, if anything, the unit claims about performance).
`performance-work` is the unit where the two diverge: `RT-PERFORMANCE-WORK` passes while recording
the two paths whose deterministic work differs from the authority's (`ec-p256-mul`,
`rsa-1024-private`) as `findings`, so the property reads `NOT_CLAIMED` with `findings_present`.
**A passing `RT-PERFORMANCE-WORK` must never be read as "performance parity achieved".** The
findings are read from the court row rather than typed, and the ledger carries both axes for every
unit.

**This stratum's evidence is measurement over a finished implementation rather than adversarial
input.** It emits no primitive and owns no symbol: the subject is what the candidate *reports* and
*selects* under a capability set, and the deterministic work a fixed primitive set performs. Three
of its five courts are differential transcript courts and are FRF declarable; the fourth is
candidate-only and the fifth validates data, so neither carries a declaration (D13, D201) and §3
states why.

**The activation measurement.** `docs/PHASE-19-SUBPHASES.md` §1 was taken against `main` `86177a3f`
(openssl-rs 0.0.23, Phase 18 released): `atlas_owned` 0, `provider_rows_owned` 0, zero unit and
symbol deferrals, `contract_units` 5 and all five open because no court existed at activation. The
runner `forensics/tools/phase19_courts.py` and its pending registry landed **with** the ledger and
the plan, because `run_courts.py` refuses a stratum that is not `not-started` and has no runner
(`docs/PHASE-19-SUBPHASES.md` §4.2); the direction of the `phase19_courts.py` <->
`phase19_obligations.py` edge is the reverse of Phase 16's, since the ledger's contract-unit states
are measured from the courts registry.

**This stratum is a non-export unit, and the export-partitioning tools say so by the document's own
field.** `forensics/phase19-obligations.json` publishes `unit: "performance dispatch contract"`,
which `atlas_common.NON_EXPORT_UNITS` contains, so `court_coverage.py` and `ownership_audit.py`
skip the ledger rather than reconcile a symbol set that does not exist — exactly as they skip Phase
16's `cli-config contract`, Phase 17's `downstream replacement contract` and Phase 18's
`hostile hardening contract` (D485).

## 2. What has been built

**19.0, the plan and the ledger.** `docs/PHASE-19-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase19-obligations.json` and its generator, and the runner
`forensics/tools/phase19_courts.py` with the registry it writes. The runner could not be deferred
(`docs/PHASE-19-SUBPHASES.md` §4.2): it landed with `PENDING_COURTS` naming the five planned courts,
which 19.1 through 19.5 emptied.

**19.1, the CPU-capability dispatch audit.** `RT-CPU-CAPABILITY` compiles
`courts/phase19/rt_cpu_capability_probe.c` twice (authority and candidate) and reports the
capability surface deterministically — `OPENSSL_ia32cap_P[0..3]`, the synthetic words
`cap.synthetic.pair`/`.word.4`/`.word.5` the fixed literal's override derives, whether
`OPENSSL_cpuid_setup` and `OPENSSL_ia32_cpuid` were reachable and callable, and the
capability-derived selection observable through the public API (`OpenSSL_version(OPENSSL_CPU_INFO)`,
`OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` and the four `EVP_aes_*_cbc_hmac_sha*` constructors,
which answer NULL when `AESNI_CAPABLE` is clear). The raw vector `OPENSSL_ia32_cpuid` returns is
not recorded: it is the runner's own CPUID, independent of the facade, and would make the record
machine-specific. The probe is driven under three fixed capability sets through fixed
`OPENSSL_ia32cap` literals — a synthetic reference set, an AES-NI-cleared set and a fully cleared
set — so the reported vector is the same fictional CPU on any runner, never the capture host's;
27 observations each, 81 in total, with an authority-linked differential control.

**19.2, the EVP / cipher dispatch comparison.** `RT-EVP-DISPATCH` compiles
`courts/phase19/rt_evp_dispatch_probe.c` twice and reports, for a fixed operation set
(AES-128/256-CBC/GCM, ChaCha20-Poly1305, SHA-1/256 and the four `EVP_aes_*_cbc_hmac_sha*`
constructors), which implementation each path selects — the legacy constructor, the provider fetch,
the legacy name lookup and the cipher/digest context — as the selected method's
name/NID/type/flags/sizes and, for a fetch, its provider name, under the same three capability sets.
259 observations per set, 777 in total, with an authority-linked differential control.

**19.3, the deterministic work court.** `RT-PERFORMANCE-WORK` compiles
`courts/phase19/rt_performance_work_probe.c` twice and reports the deterministic work a fixed
operation set performs — AES-128/256-CBC/GCM, ChaCha20-Poly1305, SHA-256, a P-256 scalar
multiplication and an RSA-1024 private decrypt. The library exposes no total instruction, block or
operation counter, so the instrument is a counting `CRYPTO` allocator the stratum introduces (the
number of malloc/realloc operations and the total bytes the library requests for a fixed primitive
— a deterministic proxy for its memory work; the shims forward to the default allocator and change
no behaviour) plus the method-derived input/blocks/output/tag sizes. No address, clock or duration
is observed. Eight paths run on both sides, 84 observations, no `pending` path.

**19.4, the instrument-sensitivity control.** `RT-PERFORMANCE-SENSITIVITY` is candidate-only and
compiles `courts/phase19/rt_performance_sensitivity_probe.c` once against the candidate distribution
shell. It drives two arms under the same 19.3 work instrument: the reference (`aes-128-cbc`, the
real path, which must equal the authority vector 19.3 recorded) and `control-extra-pass` (the same
path with an injected extra full pass over the primitive inside the measured region, never product
code). 26 candidate observations, and the §3.2 rule is mechanical: a control that cannot fail is
not evidence, so if the instrument cannot tell the slowed path from the reference the verdict is
`fail`, never a vacuous `pass`.

**19.5, the performance-boundary register.** `PERFORMANCE-BOUNDARY-REGISTER` stages no probe: its
subject is `artifacts/phase19/performance-boundary-register.json`, the authored register that
records, per surface, whether it is `measured` (a passing court covers it), `not-measured` (named,
with the reason it is not driven) or `not-claimed` (explicitly outside this stratum) — 7 `measured`,
1 `not-measured` and 6 `not-claimed` of 14 surfaces. The court re-reads the live courts registry and
fails the stratum if any recorded classification, surface key or stated count/evidence value has
drifted from what the courts show.

**19.6, the seal.** This document, the FRF/Gemel chain §8 records, and the registry rows the chain
requires.

**The books that moved with the code.** Phase 19's own ledger reads `owned` 5, `implemented` 5,
`deferred_to_later_phase` 0 and `open_in_this_stratum` 0, with `contract_units` 5, no provider row
and no deferral either way. The split moved as the subphases landed their rows, so this note does
not restate counts the ledger is the live record of.

## 3. The evidence

Copied from `artifacts/phase19/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. Three courts are differential transcript courts;
`RT-PERFORMANCE-SENSITIVITY` is candidate-only and `PERFORMANCE-BOUNDARY-REGISTER` validates the
registry, so neither observes an authority transcript.

| court | plane | observations | instrument |
|---|---|---|---|
| `RT-CPU-CAPABILITY` | differential (CPU-capability, 3 sets) | 81 | `courts/phase19/rt_cpu_capability_probe.c` |
| `RT-EVP-DISPATCH` | differential (EVP/cipher selection, 3 sets) | 777 | `courts/phase19/rt_evp_dispatch_probe.c` |
| `RT-PERFORMANCE-WORK` | differential (deterministic work, 8 paths) | 84 | `courts/phase19/rt_performance_work_probe.c` |
| `RT-PERFORMANCE-SENSITIVITY` | candidate-only (instrument control) | 26 (candidate) | `courts/phase19/rt_performance_sensitivity_probe.c` |
| `PERFORMANCE-BOUNDARY-REGISTER` | data-validation (register + registry) | — (structural) | `artifacts/phase19/performance-boundary-register.json` |

Every differential row carries `verdict: "pass"`, and the summary reads `pass` 5 of `total` 5 with
`pending_courts` empty. `RT-CPU-CAPABILITY` records 68 divergences (20 under the reference set and
24 under each faulted set), `RT-EVP-DISPATCH` 176 (0 under the reference set and 88 under each
faulted set) and `RT-PERFORMANCE-WORK` 4 (the two divergent-work findings); each is a recorded
disposition rather than a residual, and the per-court rows in `docs/SEAL-CENSUS.md` are the same
computation.

**The differential control is what keeps the expectation honest.** `RT-CPU-CAPABILITY` is `pass`
only when the authority's capability surface was actually reached and the faulted facade moved the
authority's selection; `RT-EVP-DISPATCH` only when the authority's selection surface was driven and
the facade moved it; `RT-PERFORMANCE-WORK` only when the authority installed the counting hook and
the paths ran. A court whose authority control the authority could not reach would make the court
`fail` rather than pass on vacuous agreement (`docs/PHASE-19-SUBPHASES.md` §3.2, §3.4).

**The candidate-only and data-validation courts are not transcript courts, and their rows say so.**
`RT-PERFORMANCE-SENSITIVITY` has no authority transcript to diff — the slowed variant is a
construction of the harness, and a sensitivity property is not an authority behaviour — so it is
compiled once against the candidate and carries a sensitivity control instead; its own
`artifacts/phase19/COURTS.json` row is marked `frf_declarable: false` and it is not declared in
`gen_frf_courts.py` (D13, D201), exactly as Phase 8's, 9's and 10's `CT-*` courts and Phase 18's
`CT-PRIMITIVES` are not. `PERFORMANCE-BOUNDARY-REGISTER` stages no probe pair and re-reads the live
courts registry and the authored register, so its own row is marked `frf_declarable: false` and no
declaration is generated for it.

**The court coverage join does not have a phase-19 row, and that is the join's own definition.**
`docs/SEAL-CENSUS.md`'s coverage table lists no phase-19 row for the same reason it lists no
phase-16, phase-17 or phase-18 row: all four are non-export units, so `court_coverage.py` skips
their ledgers and there is no export to partition. The provider-row join (D245) is likewise vacuous:
this stratum owns no provider row.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
courts did look. They found real dispositions in the candidate, and a measurement record that is
honest about what each instrument can and cannot drive.

**The capability court found the three capability names are not implemented, and the dispatch
selection is invariant where the authority's moves.** `RT-CPU-CAPABILITY` records
`probe.reachable.cpuid_setup`, `probe.reachable.ia32_cpuid` and `probe.reachable.ia32cap_p` as `1`
on the authority and `0` on the candidate: `OPENSSL_ia32cap_P` is `.hidden` in the authority and
`OPENSSL_cpuid_setup`/`OPENSSL_ia32_cpuid` live only in the static archive, and the candidate
provides none of the three (its CPU-dispatch string is `CPUINFO: N/A` and
`OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS)` is NULL). That is the `symbols_not_reached` census the
plan records, and it is *recorded* in the court's `divergences` block rather than failed. The
capability-derived selection is invariant in a way the authority's is not: under the reference set
the four `EVP_aes_*_cbc_hmac_sha*` constructors answer non-NULL on both sides, but under the
AES-NI-cleared facade the authority's `AESNI_CAPABLE` test moves its selection to the non-AES-NI
arm while the candidate's does not — the reduced engine does not model `OPENSSL_ia32cap` masking.
The differential control is explicit and honest: `authority_surface_reached` true,
`facade_moved_selection` true, `facade_key` `sel.aes128cbcsha1.null` moving `0 -> 1`. 68 divergences
are recorded, all class `value`.

**The dispatch court found the reference set agrees exactly and the masked sets diverge by design.**
`RT-EVP-DISPATCH` records **0 divergences under the reference capability set** — over the fixed
synthetic vector, every operation's selected implementation is identical on both sides — and **88
divergences under each of the two faulted sets**. The mechanism is the authority's default provider
filtering its `AES-*-CBC-HMAC-*` rows through `ossl_cipher_capable_aes_cbc_hmac_sha*`
(`AESNI_CBC_HMAC_SHA_CAPABLE`): clearing the AES-NI bit makes the authority's fetch, legacy and
lookup paths for those four algorithms answer NULL (the twelve `aes_cbc_hmac_selection` keys all
move `reference=0` -> `aesni_off=1`), while the candidate reads CPUID directly and does not model
the mask, so its selection does not move. The control drives three of the twelve keys explicitly and
`authority_selection_driven` is true. The **engine path is not driven**: no engine is configured
and the reduced engine does not export the enumeration it would need, so the register records
`evp-engine-path` `not-measured` rather than assuming it. All 176 divergences are class `value`.

**The work court found the symmetric and digest paths agree, and the EC and RSA paths diverge.**
`RT-PERFORMANCE-WORK` records the six symmetric/digest paths — `aes-128-cbc`, `aes-256-cbc`,
`aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305` and `sha256` — with an **empty**
`divergent_work_keys` set: their library-side work vector equals the authority's on every counter
the instrument observes. Two paths are recorded as `findings`, not failed: `ec-p256-mul` differs on
`allocs` (authority 3, candidate 4) and `bytes` (authority 2121, candidate 160), and
`rsa-1024-private` on `allocs` (authority 46, candidate 31) and `bytes` (authority 4541, candidate
2669). These are real measurements of the reduced engine's allocation behaviour on the EC and RSA
paths, and the ledger, the courts registry and the register all carry them with
`property_status: NOT_CLAIMED`. **This is a work result, not a throughput or parity claim**: the
counting allocator observes heap operations, not total CPU instructions, and the block counts are
input-implied.

**The sensitivity control caught its deliberately slowed path on the counter the stratum
introduces.** `RT-PERFORMANCE-SENSITIVITY` records `control-extra-pass` caught
(`caught` true, `counter_caught` true): the slowed arm differs from the reference on the
library-side counter keys `allocs` (2 -> 4) and `bytes` (640 -> 1280), and the driver-side `calls`
movement (7 -> 14) is recorded separately because 19.3 excludes `calls` from its findings. The
reference arm equals the authority's recorded `aes-128-cbc` vector exactly, so the reference is the
real measured path and not a broken instrument's constant. **This is an instrument-resolution
result** — it proves the work counter can tell a slow path from a fast one — and it makes no
throughput claim.

**The register binds the non-claims and cannot claim more than the courts measured.** 7 surfaces
are `measured` by a passing court (`cpu-names-not-reached`, `cpu-dispatch-invariance`,
`evp-reference-agreement`, `evp-masked-divergence`, `work-agreement`, `work-divergence`,
`sensitivity-control`); 1 is `not-measured` (`evp-engine-path`, the engine path above); and 6 are
`not-claimed`: `nc-benchmark-parity`, `nc-asm-rust-equivalence`, `nc-wallclock`, `nc-instruction-count`,
`nc-parity` and `nc-guarantee`. The court re-reads the live courts registry and fails the stratum
if a measured row's court no longer covers its surface, a not-measured or not-claimed row a passing
court now covers, or a stated count/evidence value has moved.

**No generator drift the stratum's own slices left went unreconciled, and the seal forced none.**
Unlike Phase 14 (D529), whose later slices left four artefacts that only surfaced when the stratum
was derived `complete`, this stratum's slices are one plan, one ledger, one runner and five courts,
and deriving `complete` surfaced no reconciliation the slices had not already made. §10 records the
corrections this seal does make.

## 5. Fault boundaries — recorded, not reproduced

Where the authority depends on a surface this crate does not build, the court does not call it and
the divergence is recorded. **No divergence obligation names Phase 19 as its `current_owner`.**
`forensics/divergence-obligations.json` reads 10 rows and **0 blocking** at seal time; no live
obligation outran this stratum's evidence, so `phase_state.py` derives `complete`. The boundaries
this stratum actually met are recorded in the places below.

1. **The three capability names are not implemented and are recorded, not failed.**
   `OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup` and `OPENSSL_ia32_cpuid` answer `reachable=0` on the
   candidate; the court records the `symbols_not_reached` disposition and its selection invariance
   as divergences (`docs/PHASE-19-SUBPHASES.md` §3.4).
2. **The dispatch selection is invariant under masking, and that is recorded.** The reduced engine
   does not model `OPENSSL_ia32cap` masking, so the 88 divergences under each faulted set are
   recorded rather than failed; the reference set agrees exactly.
3. **The ENGINE path is not driven.** No engine is configured and the reduced engine does not
   export the enumeration it would need; the register records `evp-engine-path` `not-measured`.
4. **The work instrument is a proxy, and the seal says so.** The counting allocator and the
   method-derived geometry are deterministic functions of the library and the fixed inputs, but they
   are not a total instruction count; the EC and RSA findings are heap-operation differences, not
   throughput results.
5. **`RT-PERFORMANCE-SENSITIVITY` is candidate-only, and that is the instrument.** The slowed
   variant is a construction of the harness, so there is no authority transcript to diff and no
   staged `.authority` pair; its row is marked `frf_declarable: false` (D13, D201).
6. **`PERFORMANCE-BOUNDARY-REGISTER` stages no probe.** Its subject is the authored register and
   the live courts registry, so it carries no `artifacts/phase19/probes/` pair and no FRF
   declaration; `frf_declarable` is false.
7. **The FRF venue narrows two premises rather than disposing their residuals.** §4 and §8 record
   why leaving the first-line residual open is the honest reading; `rt-evp-dispatch` carries both
   stdout and exit.
8. **The `pending.` set is empty, and that is a measurement.** Every court the plan names is
   registered in `artifacts/phase19/COURTS.json`, and `PENDING_COURTS` is empty; this stratum owns
   no exported symbol, so nothing is counted as pending rather than dropped (§3).

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable drop-in OpenSSL.** `implemented` in the ledgers means a symbol
   with that name is defined, and this stratum defines none. `docs/PARITY_MODEL.md` states what each
   label means; no symbol here is `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current
   non-claims. A passing performance court is at most a bounded deterministic-work comparison over
   the paths it drives — never `PARITY_VERIFIED`.
2. **No benchmark-parity claim.** No throughput ratio to the authority is asserted anywhere in this
   stratum; the register records `nc-benchmark-parity` `not-claimed`. A deterministic work count is
   a proxy for work, not for elapsed time.
3. **No assembly-versus-Rust equivalence claim.** The authority's per-CPU assembly paths and the
   candidate's reduced implementations are not asserted to be the same work; the register records
   `nc-asm-rust-equivalence` `not-claimed`.
4. **No wall-clock or instruction-count verdict.** No verdict is ever taken from wall-clock time
   alone, and no total instruction count is claimed; the register records `nc-wallclock` and
   `nc-instruction-count` `not-claimed`. The counts the courts record are memory-work and method
   geometry, not throughput (`docs/PHASE-19-SUBPHASES.md` §3.3, §3.6).
5. **Not a guarantee about dispatch, and not a security claim.** The dispatch courts compare
   *selection* over the capability sets they drive; a set they do not reach is named, not assumed.
   Nothing here is a constant-time, correctness or safety claim.
6. **The FRF and Gemel evidence is established, and §8 records what it is.**
   `docs/RELEASE_GATES.md` §2 items 6, 8 and 10 are met by the chain entry §8 records: three
   receipts, six adjudicated challenge records, the `sensitivity-backed` claim
   `4293b9a67fa11c4543b8706e68ecce08ee5ac87b6b49517ea61013f304a6853d` with zero blockers, and the
   Gemel checkpoint `K66` whose summary names Phase 19 and the FRF chain. Phase 19's derived state
   is `complete`. Two premises are narrowed to the exit class (§4), and that is recorded rather
   than smoothed.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process — a subphase lands its code, its court and its regenerated artefacts in **one
commit**; every name a subphase lands carries a court edge where it has one; and an artefact a
source change moves is regenerated in the same commit — and its §4.2 precondition (the runner lands
**with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every row this stratum owns is implemented or handed on with the dependency named | `forensics/phase19-obligations.json`: `open_in_this_stratum` 0, `deferred_to_later_phase` 0, `contract_units` 5 all `implemented`, no deferral either way |
| the export-coverage join is vacuous here, and that is the marker's rule | no phase-19 row in `forensics/atlas/court-coverage.json`, because `phase19-obligations.json`'s `unit` is in `atlas_common.NON_EXPORT_UNITS` (D485); `phase_state.py` scopes the rule out for such a ledger |
| no authority fault is reproduced | §5, and the boundaries recorded in the probes and the register |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 19 |
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
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json` pins `openssl-3.6.4-production`; `artifacts/phase19/COURTS.json` names it |
| 2 | obligation inventory | `forensics/phase19-obligations.json`; 5 contract units, 0 provider rows, 0 export rows |
| 3 | court manifests | `artifacts/phase19/COURTS.json` |
| 4 | raw captures | **met.** The three staged `artifacts/phase19/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs, and `.frf/captures/` carries the FRF venue's captures for the three declarable courts, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every differential court's `verdict` is `pass`, `summary` reads `pass` 5 of 5 and `pending_courts` is empty; the 68 capability, 176 dispatch and 4 work divergences are recorded dispositions, not residuals. In the FRF venue, two premises carry one `open` first-line residual each, narrowed around by the claim and recorded in §4 |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries six adjudicated Phase-19 records — both declared axes (`stdout-first-line`, `exit-class`) on all three declarable courts, each `saw_defect` and `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green (D13) |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-19 FRF residual is disposed `fixed` |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries three Phase-19 receipts, one per declarable court |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s `current:` is `K66` (`checkpoint.0bf45588d399b1403893ddee3b717149efc556c23272cedad51b3b5f0a686237`), whose summary names Phase 19 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-19 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

**The seal depends on the register, and that dependency is mechanical.**
`PERFORMANCE-BOUNDARY-REGISTER` re-reads the live courts registry and the authored register and
fails the stratum if a recorded classification, surface key or count has drifted. `phase_state.py`
blocks a stratum on any non-`pass` court in `artifacts/phase19/COURTS.json`, so the seal cannot
derive `complete` while the register has drifted; the register is the stratum's own non-claim, and
it may not claim more than the courts above measured.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **Three declarations are on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-19 block — `rt-cpu-capability`, `rt-evp-dispatch` and `rt-performance-work` — and
  `gen_frf_courts.py` wrote the three declarations under
  `forensics/frf/courts/openssl-rs-rt-<court>`. `gen_frf_courts.py --check` reports
  `ok: 286 file(s) match the table (143 courts)`, and `forensics/frf/README.md` counts **143 runtime
  courts** — the three Phase-19 ones among them, which moves the manifest count
  `docs/RELEASE_GATES.md` names with it. `RT-PERFORMANCE-SENSITIVITY` is candidate-only and
  `PERFORMANCE-BOUNDARY-REGISTER` validates data, so neither is declared and no declaration is
  generated for them; their evidence is the court table and the register.
- **The chain's objects are on disk.** `.frf/receipts/` carries three Phase-19 receipts, one per
  declarable court. `.frf/challenges/` carries six adjudicated challenge records — both declared
  axes (`stdout-first-line`, `exit-class`) on all three courts, every one `saw_defect` and
  `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely green
  (D13). `.frf/claims/` carries the compiled claim
  `4293b9a67fa11c4543b8706e68ecce08ee5ac87b6b49517ea61013f304a6853d`, compiled at
  `--policy sensitivity-backed` over the three receipts, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.24` (`identity_hash e4f60d8b`) with zero blockers. **The identity is the
  current 0.0.24 release**: the claim records the candidate the tree is
  (`gen_frf_courts.CANDIDATE_VERSION`), which is what the fix-4 identity clause requires. Two
  premises — `rt-cpu-capability` and `rt-performance-work` — are narrowed to the exit class because
  the reduced engine's transcripts legitimately differ on the harness's first-line digest; §4 records
  why leaving the residual open is the honest reading.
- **The Gemel change and checkpoint are this stratum's.** The change `C112`
  (`change.0084009a48bc9d12daa15d0cac4603836d7cac35ee47be3034a0e6392522f1ea`) names Phase 19, its
  three declarable courts, the six adjudicated challenges, the claim and the five contract units;
  the checkpoint `K66`
  (`checkpoint.0bf45588d399b1403893ddee3b717149efc556c23272cedad51b3b5f0a686237`) closes it. The
  projection `forensics/GEMEL_TRAJECTORY.md` carries both, and the checkpoint's summary names Phase
  19 and the FRF chain. Items 6, 8 and 10 of §7 retired with that entry, exactly as they did for
  Phase 8's `C74`, Phase 9's `C94`, Phase 10's `C95`, Phase 11's `C97`, Phase 12's `C98`, Phase 13's
  `C99`, Phase 14's `C101`, Phase 15's `C103`, Phase 16's `C106`, Phase 17's `C108` and Phase 18's
  `C110`.

**The declarations are produced by `gen_frf_courts.py`; the receipts, challenges, claim and
checkpoint were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase19-obligations.json`'s
`deferred` list is empty and its `deferred_to_later_phase` reads 0; every row this stratum owns is
implemented, and it received no unit or symbol deferral from an earlier stratum. The three
capability names the candidate does not reach, the ENGINE path, the masked dispatch divergences and
the EC/RSA work findings are not rows this stratum's ledger owns — they are named boundaries rather
than deferrals (§5) — so nothing moves forward.

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the three
  declarations, three receipts, six adjudicated challenges, the claim
  `4293b9a67fa11c4543b8706e68ecce08ee5ac87b6b49517ea61013f304a6853d` and the checkpoint `K66`. This
  stratum registers no candidate-only or data-validation court in the FRF registry, so the entry
  covers the three behavioural differential courts and records the other two as not declarable.
  Items 6, 8 and 10 of §7 retired with it, and `phase_state.py` derives `complete`.
- **The register is the seal's live dependency.** The authored
  `artifacts/phase19/performance-boundary-register.json` is data, not an assertion: a classification,
  surface key or count that drifts turns `PERFORMANCE-BOUNDARY-REGISTER` to `fail` and blocks the
  stratum.
- **`forensics/phase19-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and row figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the evidence and the tools, and the
corrections the evidence forced rather than the ones a reviewer might have preferred.

1. **The FRF declaration table learned the Phase-19 rows and the manifest count moved with it.**
   `gen_frf_courts.py`'s `COURTS` table gained `rt-cpu-capability`, `rt-evp-dispatch` and
   `rt-performance-work`, so `--check` moved from `280 file(s) (140 courts)` to
   `286 file(s) (143 courts)`, and `forensics/frf/README.md` and `docs/RELEASE_GATES.md`'s
   manifest-count sentence were moved with it, because `docs_consistency.py` binds both to the
   registry. `RT-PERFORMANCE-SENSITIVITY` and `PERFORMANCE-BOUNDARY-REGISTER` take no declaration,
   and the table's Phase-19 block records each omission with its reason.
2. **A candidate-only court now records `frf_declarable: false` in its own row, rather than relying
   on a name convention.** `phase19_courts.py`'s `performance_sensitivity_court` emits the
   `frf_declarable`/`frf_exclusion` pair for `RT-PERFORMANCE-SENSITIVITY`, so
   `phase_state.py`'s `_frf_court_inventory` reads the non-declarability from the stratum's own
   court record instead of requiring a `CT-` name (D524's "a runner emits it" branch). This is why
   the candidate-only court did not become an accidental fourth required court.
3. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the three
   declarations, three receipts, six adjudicated challenges, the `sensitivity-backed` claim
   `4293b9a67fa11c4543b8706e68ecce08ee5ac87b6b49517ea61013f304a6853d` and the Gemel change `C112`
   / checkpoint `K66`
   (`checkpoint.0bf45588d399b1403893ddee3b717149efc556c23272cedad51b3b5f0a686237`), so items 6, 8
   and 10 retired and `phase_state.py` derives `complete`. `seal_sha256` is recomputed from the
   document's new bytes.
4. **`atlas_common.SEAL_DOCS` gained `19: docs/PHASE-19-PERFORMANCE-SEAL.md`**, so
   `render_seal_census.py` and `phase_state.py` recompute this document's `seal_sha256`, exactly as
   Phase 18's seal is recorded.
5. **The plan named the authority's capability symbols as the candidate's surface, and the seal
   corrected the row.** `docs/PHASE-19-SUBPHASES.md` row 19.1 wrote "the candidate's CPU-capability
   surface (`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`)". Deriving Phase 19
   `complete` turned on `plan_reconciliation.py`'s P2 check, and it reported all three as
   `plan_named_symbol_not_reached`: they are authority internals the reduced candidate builds
   nowhere (`RT-CPU-CAPABILITY` records `probe.reachable.*=0`), no deferral records them (there is
   no later implementation stratum the candidate's direct-CPUID model defers them to) and no
   divergence covers them (the crate never references them, so a `covers` entry would fail the
   prerequisite gate's direction D). The row now names the surface the driver drives without
   promising crate symbols; the plan's §4.5 records the correction and the three names remain the
   disposition §4 of this seal and §3 of `docs/PHASE-19-SUBPHASES.md` describe. This is the one
   reconciliation the stratum's own completeness forced.
6. **The capability court was made runner-independent, and its host readouts replaced with
   portable ones.** The first version drove its first set with `OPENSSL_ia32cap` unset and its
   faulted sets as `~` masks over the runner's own CPUID, so `cap.word.*`,
   `api.cpuinfo`/`api.cpu_settings` and the raw `OPENSSL_ia32_cpuid` return embedded the capture
   host's capability words and could not reproduce on a runner with a different CPU.
   `CAPABILITY_SETS` now drives all three sets under explicit fixed `OPENSSL_ia32cap` literals
   (`0x0200000100000000`, `0x0000000100000000`, `0x0`) over a synthetic reference CPU. The raw
   `OPENSSL_ia32_cpuid` readouts (`probe.cpuid.ret`, `cap.raw.word.2`, `cap.raw.word.3`) are the
   runner's own CPUID and independent of the facade; they are not recorded, and three portable
   observations of the synthetic vector the literal derives (`cap.synthetic.pair`,
   `cap.synthetic.word.4`, `cap.synthetic.word.5`) take their place, so the observation count is
   unchanged at 81 and the capability divergences at 68 while the record reproduces byte for byte
   on any runner. Reachability and callability are still observed. The masking still moves the
   authority's selection, so the differential control is unchanged; the register's
   `evp-host-agreement` row is now `evp-reference-agreement` (key `evp.reference`) and the
   `facade_host` evidence field is now `facade_reference`. See the fix's own gate run for the
   two-re-derivation and differing-ambient-`OPENSSL_ia32cap` portability proof.
