# Phase 15 — QUIC / ECH and modern SSL surface (`quic.h`): seal

**STATUS: derived.** This status is not typed; it is the state `forensics/tools/phase_state.py`
derives from artefact existence. The stratum's export ledger is empty of open rows —
`forensics/phase15-obligations.json:9` reads `open_in_this_stratum: 0` — the stratum ships no
provider registration row (§1), every earlier stratum is `complete`, and the FRF/Gemel chain entry
§8 records has landed, so `forensics/phase-state.json` reports phase 15 **`complete`** with an empty
blocking reason. That derived state is the phase-exit predicate, and D529 records that the ledger's
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
table this document *does* carry — §3's court list — is copied from `artifacts/phase15/COURTS.json`,
and it says so.

**This seal records a candidate-transcription claim, and it is neither a security claim nor a
parity claim.** Its evidence shows that the candidate distribution defines the three names this
stratum owns and that the behaviours its one behavioural court exercises match the pinned
authority's over fixed fixtures, observation for observation. It does **not** show that the crate
builds a QUIC connection, a QUIC handshake or the QUIC implementation object those methods name —
no court here builds or drives a connection — and it does **not** show that the crate's QUIC
surface is safe against a hostile input. `docs/PARITY_MODEL.md` is the authority on what the labels
mean: `implemented` means a symbol with that name is defined, and a passing bounded court is a
differential result over the behaviours that court exercises. `PARITY_VERIFIED` is not claimed for
any symbol here, and `forensics/STATUS.md`'s non-claims are the generated projection's. A defined
`OSSL_QUIC_*_method` is a method table, not a working QUIC stack, and `docs/SEAL-CENSUS.md` and
`forensics/STATUS.md` record the live implemented surface.

- Authority: `openssl-3.6.4-production` (`forensics/authorities/AUTHORITIES.json:39`), named as the
  authority by `artifacts/phase15/COURTS.json:2`
- Court results: `artifacts/phase15/COURTS.json` — two courts, `all_pass` true
  (`artifacts/phase15/COURTS.json:4`), zero residuals; the per-court table is §3. One (`RT-QUIC`)
  is **differential** and declares an FRF court; one (`RT-PHASE15-REF`) is the reference basis and
  is not declarable; this stratum registers no correctness `CT-*` court, and §3 states why.
- Obligation ledger: `forensics/phase15-obligations.json` — `owned` 3 (`:10`), `implemented` 3
  (`:8`), `deferred_to_later_phase` 0 (`:7`), `open_in_this_stratum` 0 (`:9`), `received_by_handoff`
  0 (`:11`); the working-set rule it enforces is the ledger's own.
- Court coverage: `forensics/atlas/court-coverage.json` — phase 15's block, its counts
  `implemented` 3, `directly_courted` 3 (3 `called`, 0 `referenced`), 0 indirect, 0
  non-observable, 0 `unmatched`; the weaker meaning of `directly_courted` is stated in §3 and in
  §1 below (D199).
- Derived state: `forensics/phase-state.json`, phase 15; it owns **no provider row**, so its
  `provider_rows` reads `null` rather than a count (§1).
- FRF receipts and claim: **present, and the chain's objects are on disk.** `.frf` carries one
  receipt for the one declarable court
  (`receipt-run-openssl-rs-rt-quic-b22aa2c1dd608efc359f63964dbcef3a44c3de502e60260cd8412bd140ea1a70-2cfb6f8ef8264aa172afe40a56184da5774f162c47e9b38a2852ec725b32623c`),
  two adjudicated challenge records (both operators on the court) and the `sensitivity-backed`
  claim `5b886f1078bec71f60cf65f0f80e89eed5978806034257a9d9f6b3667a708d16`, binding
  `openssl-rt-3.6.4-r2` to `openssl-rs 0.0.26` with zero blockers and both stdout and exit
  asserted. §8 states what that is.
- Gemel checkpoint: **present, and it is this stratum's.** `forensics/GEMEL_TRAJECTORY.md`'s head
  change is Phase 15's `C103` and its `current:` is the checkpoint `K57`
  (`checkpoint.7a0b3ab7a5a78ded487e58ea534f15eeaec68e8d27beb9d4b33f15a6ce75b6f3`), whose
  summary names Phase 15 and the FRF chain. §8 states what that is.
- Deciding record: `docs/DECISIONS.md` — **D524** (the FRF requirement is read from the court
  inventory) is the predicate this stratum's chain engages through `artifacts/phase15/COURTS.json`,
  **D529** is the Phase-14 seal whose chain this one mirrors, and `docs/PHASE-15-SUBPHASES.md` is
  the subphase plan this seal closes. §10 is where the corrections this seal records are
  summarised.

## 1. What this phase owns, and how that was decided

Phase 15 is **the QUIC / ECH and modern SSL surface stratum**, and by
`forensics/atlas/symbol-ownership.json`'s declaring-header rule it owns **exactly three exports**,
all `libssl`, all declared in `quic.h`: `OSSL_QUIC_client_method`,
`OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`
(`docs/PHASE-15-SUBPHASES.md:3-21`). They sit in libssl's DSO beside Phase 14's 600
`ssl.h`/`tls1.h`/`srtp.h`/`sslerr_legacy.h` exports, and Phase 14's plan and seal name them as this
stratum's by their declaring header and land none of them
(`docs/PHASE-14-TLS-SEAL.md` §9). It is deliberately **not** the QUIC implementation object the
method table points at (`quic_impl.c`'s `ossl_quic_new`, `_free`, `_connect`, `_accept` and the
rest), **not** the TLS message layer Phase 14 deferred, and **not** the ECH extension surface,
which is `ssl.h`'s and so Phase 14's.

**The working set is derived, not chosen.** `forensics/atlas/symbol-ownership.json` assigns it 3
exports over **one header** — `quic.h` 3
(`forensics/phase15-obligations.json:26-28`) — and no earlier stratum's ledger records an
`owning_phase == 15` hand-off, so `received_by_handoff` reads **0**
(`forensics/phase15-obligations.json:11`). Like Phase 14, this is a stratum whose working set *is*
its atlas-owned universe: the census's per-stratum row records `atlas-owned` 3, `ledger owned` 3,
`implemented` 3, `deferred` 0, `open` 0.

**It begins on a landed `libssl` substrate.** Phase 14 is `complete`, so
`forensics/atlas/implemented-surface.json` already records its 600 `libssl` exports as
implemented; the three `quic.h` names were the only `libssl` exports that stratum did not own and
at activation were present only as the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called, so the ledger's `open` count
opened at **3** and moved to zero as 15.1 landed them
(`docs/PHASE-15-SUBPHASES.md:41-48`). `libssl` now reads **603 of 603** in
`forensics/atlas/implemented-surface.json`.

**The three exports are defined by one authority translation unit**, `ssl/quic/quic_method.c`
(`forensics/atlas/export-defining-units.json`), and 15.1 lays it out as
`src/ssl/quic/quic_method.rs`. That module is the whole of this stratum's landed crate surface.

**This stratum publishes no provider registration row, and the census records the zero.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 15` yields nothing: QUIC is not a
provider and this stratum's subphases activate none, so the ledger's `provider_rows_owned` is `0`
(`forensics/phase15-obligations.json:32`) and `phase_state.py`'s provider-row rule and
`provider_court_coverage.py` have nothing to hold against this stratum — the mirror of Phases 12,
13 and 14.

**The plane, and which one this stratum's evidence is.** D201's commitment — every
*primitive-bearing* subphase carries a differential `RT-*` court *and* a correctness `CT-*` court —
is scoped to primitive-bearing work, and this stratum emits no primitive: it has **one behavioural
differential court and one reference-basis court, and no `CT-*` court**. The reference basis is
`RT-PHASE15-REF`, the court the plan's §4.2 precondition requires: it takes the address of each of
the stratum's three atlas-owned exports and prints whether each is non-NULL, so a symbol covered
only by it is a proof of *reference* and not that any arm of it was driven
(`artifacts/phase15/COURTS.json:6`). §3 is where the two readings are tabulated.

## 2. What has been built

**15.0, the plan and the census.** `docs/PHASE-15-SUBPHASES.md` and the measurement in its §1, the
ledger `forensics/phase15-obligations.json` and its generator, the runner
`forensics/tools/phase15_courts.py`, and the reference-basis probe
`courts/phase15/rt_coverage_ref_probe.c` — all landed together, because §4.2 of the plan makes the
runner and the reference probe a precondition rather than a later slice: `run_courts.py` refuses a
stratum that is not `not-started` and has no runner, and `RT-PHASE15-REF` is the stratum's only
court until 15.1 lands a unit (`docs/PHASE-15-SUBPHASES.md:101-112`).

**15.1, the three QUIC method constructors.** `src/ssl/quic/quic_method.rs`: the three
`OSSL_QUIC_*_method` constructors, each the `IMPLEMENT_quic_meth_func` expansion — a
process-lifetime `static const SSL_METHOD` carrying `OSSL_QUIC_ANY_VERSION`, no flags, no mask, the
TLS default timeout reduced to seconds, the undefined enc-method table and the
`q_accept`/`q_connect` role pair. `RT-QUIC` (30 observations) drives the constructors and the
context each installs: the non-NULL returns and the distinctness of the three statics,
`SSL_CTX_new`'s acceptance of each and the identity `SSL_CTX_get_ssl_method` reports back, the
method's `tls1_default_timeout` through `SSL_CTX_get_timeout`, the version-inflexible
protocol-bound arm, and the NULL-method refusal. **The QUIC dispatch table and the QUIC object are
not built here** (§5); the module records the reduction.

**The books that moved with the code.** Phase 15's own ledger reads `owned` 3, `implemented` 3,
`deferred_to_later_phase` 0 and `open_in_this_stratum` 0
(`forensics/phase15-obligations.json:5-11`), and the census records the `libssl`/total implemented
surface (`docs/SEAL-CENSUS.md`). It received no hand-off and passed none on
(`received_by_handoff` 0).

## 3. The evidence

Copied from `artifacts/phase15/COURTS.json`. Observation counts are the court's own
`authority_observations`, which `forensics/tools/atlas_common.py` requires to equal the candidate's
before a row may be called true. One court is differential; the stratum registers no correctness
`CT-*` court, so no row here carries a `vectors_checked` count.

| court | plane | observations | probe |
|---|---|---|---|
| `RT-PHASE15-REF` | differential (reference basis) | 3 | `courts/phase15/rt_coverage_ref_probe.c` |
| `RT-QUIC` | differential | 30 | `courts/phase15/rt_quic_probe.c` |

Every row carries `residual_count: 0` and `verdict: "pass"` (`artifacts/phase15/COURTS.json`), and
the summary reads `pass` 2 of `total` 2 with `pending_courts` empty (`artifacts/phase15/COURTS.json`,
`pending_courts`). The total over the two transcript courts is
`docs/SEAL-CENSUS.md`'s (**33** authority observations), and the per-court rows there are the same
computation.

**`RT-PHASE15-REF` is not a behavioural court, and its meaning is the weaker one.** Its probe takes
the address of each of the stratum's three atlas-owned exports into a `volatile` table and prints
whether each is non-NULL, so a symbol covered only by it means the candidate distribution defines
the name — which the link proves — and **not** that any arm of it was driven
(`artifacts/phase15/COURTS.json:6`, `courts/phase15/rt_coverage_ref_probe.c`). The court coverage
atlas records those at basis `referenced`, never `called` (D199). **`RT-QUIC` is the stratum's one
behavioural court**: it drives the three constructors and the method and context surface each
installs (`courts/phase15/rt_quic_probe.c`, `docs/PHASE-15-SUBPHASES.md:74-92`).

**Why there is no correctness plane, stated rather than left to inference.** D201's commitment is
scoped to primitive-bearing subphases, and this stratum emits no primitive: it builds a method
table over Phase 7 and 8's primitives and no arm of it performs cryptography, and a `CT-*` court is
a vector-driven construction check with no authority transcript to diff (D13, D201). The stratum's
evidence is therefore **differential only**, which is a measurement and not an omission, and every
arm that could not be driven is named in the module rather than counted as passing (§5).

**The court coverage join is clean, and its meaning is the weaker one.**
`docs/SEAL-CENSUS.md` reads phase 15 as 3 implemented, 3 `directly_courted` (all 3 `called`, 0
`referenced`), 0 indirect, 0 non-observable, 0 unmatched; the block is
`forensics/atlas/court-coverage.json`. `directly_courted` means *referenced by a staged candidate
probe that ran and produced a transcript*, a proof of **reference** rather than that every arm of
the symbol was driven — the same reading Phases 8 through 14's seals adopt. Here every atlas-owned
name is `called`: `RT-QUIC` invokes all three constructors, so no name is left to the reference
basis alone.

## 4. What the courts found

A court whose results never surprised anyone is a court that is not looking, and this stratum's
evidence found no defect in the candidate — the method table is a small, faithful reduction of the
authority's own constants, and the two transcripts agree observation for observation.

**The differential court held the transcription to the authority's own returns.** `RT-QUIC`
established that each constructor returns its own non-NULL process-lifetime static, that the three
are distinct, that `SSL_CTX_new` accepts each and `SSL_CTX_get_ssl_method` reports the same
identity back, that the method's `tls1_default_timeout` is the context's default timeout, and that
the version-inflexible protocol-bound arm leaves a QUIC context's minimum at zero — because the
method's `version` is `OSSL_QUIC_ANY_VERSION`, neither `TLS_ANY_VERSION` nor `DTLS_ANY_VERSION`, so
`ssl_set_version_bound` ignores the bound (`docs/PHASE-15-SUBPHASES.md:74-92`).

**The arms the court cannot reach are named rather than compared.** The QUIC connection object and
the dispatch bodies are not this unit's, so `SSL_new` on these methods is not driven: the authority
builds a `QUIC_CONNECTION` (and refuses `OSSL_QUIC_server_method`) while a candidate connection from
these methods is an ordinary `SSL` object, so the two would report different `SSL_is_quic` and
`SSL_version`. The divergence is recorded in `src/ssl/quic/quic_method.rs` rather than diffed as a
residual (§5).

**The reference basis is what made the coverage join green at activation, and its meaning is the
weaker one.** 15.0 landed `RT-PHASE15-REF` so that the atlas's phase-15 row could bind every
atlas-owned name from the day the stratum began; at activation not one of the three was
implemented for real, and taking an address rather than calling was what kept the Phase 2 scaffold
(it aborts on call) from firing. Once 15.1 landed the module, `RT-QUIC` moved all three names from
`referenced` to `called`, so the honest residue is zero.

**No generator drift the stratum's own slices left went unreconciled.** Unlike Phase 14 (D529),
whose later slices left four artefacts that only surfaced when the stratum was derived `complete`,
this stratum's slices are one ledger, one plan, one runner and one court, and deriving `complete`
surfaced two corrections in the plan-versus-crate reconciliation, both recorded in §10.

## 5. Fault boundaries — recorded, not reproduced

Where the authority dereferences a NULL, relies on an unset field, or builds an object this crate
does not, the court does not call it and the divergence is recorded. **No divergence obligation
names Phase 15 as its `current_owner`.** `forensics/divergence-obligations.json` reads 10 rows and
**0 blocking** at seal time; no live obligation outran this stratum's evidence, so `phase_state.py`
derives `complete`. The boundaries this stratum actually met are recorded in the places below.

- **`SSL_new` on a QUIC method is not the authority's.** The authority's `ossl_quic_new`
  (`quic_impl.c:591`) builds a `QUIC_CONNECTION` and refuses `OSSL_QUIC_server_method` outright with
  `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`; this crate builds no QUIC object, so a candidate connection
  from these methods is an ordinary `SSL` object reporting `SSL_is_quic == 0` and an
  `SSL_version` of `0xFFFFF`, where the authority reports `1` and `OSSL_QUIC1_VERSION`
  (`courts/phase15/rt_quic_probe.c`, `src/ssl/quic/quic_method.rs:31-45`). The probe does not drive
  `SSL_new`, and the divergence is recorded in the module rather than diffed.
- **The `SSL_CTX_set_ssl_version` `IS_QUIC_CTX` refusal is not modelled.** The contexts this crate
  builds never reach that arm, so the refusal is absent rather than reproduced
  (`courts/phase15/rt_quic_probe.c`, `src/ssl/ssl_lib.rs:8701`).
- **The QUIC implementation object is a later stratum's.** `ossl_quic_new`, `_free`, `_connect`,
  `_accept` and the rest of `quic_impl.c`'s dispatch bodies are not built by this stratum, and no
  arm of the court calls one (`src/ssl/quic/quic_method.rs:26-31`,
  `docs/PHASE-15-SUBPHASES.md:83-88`).
- **The TLS message layer remains unlanded.** Phase 14 deferred `ssl/statem/statem_clnt.c` and
  `ssl/statem/statem_srvr.c` to this stratum's engine; this stratum lands only the three
  constructors, so the two units are not built here and their deferral is corrected to Phase 16
  (§10, `forensics/prerequisites.json`). No arm of this stratum's court builds or parses a flight.
- **The `pending.` set is empty, and that is a measurement.** Every court the plan names is
  registered in `artifacts/phase15/COURTS.json`, and `RT-QUIC` covers all three exports; the
  stratum's whole atlas-owned universe is three constructors, so nothing is counted as pending
  rather than dropped (§3).

## 6. What is explicitly NOT claimed

1. **Not parity, and not a usable OpenSSL.** `implemented` in the ledgers means a symbol with that
   name is defined. `docs/PARITY_MODEL.md` states what each label means; no symbol here is
   `PARITY_VERIFIED`, and `forensics/STATUS.md` carries the current non-claims. The `PARITY_MODEL.md`
   labels this stratum's evidence reaches are at most `IMPLEMENTED`, plus a bounded `SEMANTIC_PASS`
   over the behaviours its court exercises — never `PARITY_VERIFIED`.
2. **This is a candidate-transcription claim, and it is not a security claim.** The evidence shows
   the names are defined and the court's fixtures match; it does **not** show the crate's QUIC
   surface is safe against a hostile input, and no court here is a fuzz or security gate.
   `docs/SECURITY_DIVERGENCE_POLICY.md` records the boundaries; a boundary not exercised is
   recorded, not a safety guarantee.
3. **No completed-QUIC-handshake claim, and no connection at all.** No arm of the court builds or
   drives a connection: the QUIC object is unbuilt (§5), so the measured surface is the
   constructors and the context each installs. A transcription that returns each constructor's own
   static and the authority's default timeout has not been shown to carry a QUIC handshake the
   authority would.
4. **`libssl` is no longer scaffolded, which is not the same as parity.** The Phase 2 ABI scaffold's
   `libssl` exports are superseded by this stratum's own definitions for the three `quic.h` names,
   so the namespace is implemented; `docs/SEAL-CENSUS.md` and `forensics/STATUS.md` record the live
   surface. A defined `OSSL_QUIC_*_method` is a method table, not a working QUIC stack.
5. **This stratum ships no provider registration row, and claims none.** QUIC is not a provider and
   this stratum activates none; `provider_rows_owned: 0` is a measurement, not an omission, and §1
   states why.
6. **The QUIC implementation object and the TLS message layer are boundaries, not passes.** The
   dispatch bodies `quic_impl.c` defines are a later stratum's, `SSL_new` on these methods is not
   driven, and the two message-layer units Phase 14 named are deferred onward; §5 records them
   (`src/ssl/quic/quic_method.rs:26-45`, `forensics/prerequisites.json`).
7. **A passing court is a differential result over the behaviours its probe exercises, and
   implemented-and-courted is not "is a drop-in replacement".** A symbol recorded `directly_courted`
   is *referenced by a staged candidate probe that ran* — all 3 of the stratum's are `called`
   (`docs/SEAL-CENSUS.md`) — and `RT-PHASE15-REF` in particular proves only that the candidate
   distribution defines the atlas-owned names. Nothing here claims stderr equivalence, full CLI
   compatibility, build-profile independence beyond the admitted one, or drop-in substitution.
8. **The FRF and Gemel evidence is established, and §8 records what it is.** `docs/RELEASE_GATES.md`
   §2 items 6, 8 and 10 are met by the chain entry §8 records: one receipt, two adjudicated
   challenge records, the `sensitivity-backed` claim
   `5b886f1078bec71f60cf65f0f80e89eed5978806034257a9d9f6b3667a708d16` with zero blockers, and the
   Gemel checkpoint `K57` whose summary names Phase 15 and the FRF chain. Phase 15's derived state
   is `complete`.

## 7. Exit criteria

The project's rule for every stratum is `docs/RELEASE_GATES.md` §2 (`docs/RELEASE_GATES.md:49-66`):
ten items, and any open residual intersecting the claim scope blocks the claim. The plan's own gates
are its §5 process (`docs/PHASE-15-SUBPHASES.md:119-125`) — a subphase lands its code, its court and
its regenerated artefacts in **one commit**; every export carries a court edge on the commit that
lands it (D236); every provider row it publishes is named by a court (D245, which this stratum has
nothing to hold against it) — and its §4.2 precondition (the reference-basis probe and the runner
land **with** the ledger). Every clause below is checked against a generated artefact rather than
asserted.

| criterion | evidence |
|---|---|
| every export is implemented or handed on with the dependency named | `forensics/phase15-obligations.json`: `open_in_this_stratum` 0 (`:9`) and `deferred_to_later_phase` 0 (`:7`); the generator fails closed, so `implemented + deferred + open == owned` |
| every implemented export is observed by a court | `forensics/atlas/court-coverage.json` phase-15 block; `unmatched` 0, enforced for `complete` by `forensics/tools/phase_state.py` |
| the reference basis covers the atlas-owned exports | `RT-PHASE15-REF` (`courts/phase15/rt_coverage_ref_probe.c`), registered with the ledger and runner (`docs/PHASE-15-SUBPHASES.md:101-112`); D199/D236 |
| no authority fault is reproduced | §5, and the boundaries recorded in the probe and `src/ssl/quic/quic_method.rs` |
| no blocking divergence obligation names this stratum | `forensics/divergence-obligations.json`: 10 rows, 0 blocking; none names Phase 15 |
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
| 1 | authority identity | `forensics/authorities/AUTHORITIES.json:39` pins `openssl-3.6.4-production`; `artifacts/phase15/COURTS.json:2` names it |
| 2 | obligation inventory | `forensics/phase15-obligations.json` (`:5-11`); this stratum owns no provider row |
| 3 | court manifests | `artifacts/phase15/COURTS.json` |
| 4 | raw captures | **met.** The two staged `artifacts/phase15/probes/<probe>.{authority,candidate}` pairs are the captures the court venue diffs (each row's `staged_binaries`), and `.frf/captures/` carries the FRF venue's captures for the one declarable court, produced by §8's chain |
| 5 | residual set | **met in the court venue.** Every court's `residual_count` is 0 and its `residuals` list empty, `summary` reads `pass` 2 of 2 and `pending_courts` is empty |
| 6 | mutation / sensitivity evidence | **met.** `.frf/challenges/` carries two adjudicated Phase-15 records — both declared axes (`stdout-first-line`, `exit-class`) on the one declarable court, each `saw_defect` and `specificity_clean` |
| 7 | resolution runs | **not applicable, and therefore not met.** `--resolution-run` is required only for a `fixed` disposition, and no Phase-15 FRF residual exists to carry one |
| 8 | FRF receipts | **met.** `.frf/receipts/` carries one receipt for the declarable court (`receipt-run-openssl-rs-rt-quic-*`), with an empty `residuals` list |
| 9 | generated parity projection | `forensics/STATUS.md`, rendered by `forensics/tools/render_status.py`; the seal-facing arithmetic is `docs/SEAL-CENSUS.md` |
| 10 | Gemel checkpoint | **met.** `forensics/GEMEL_TRAJECTORY.md`'s head change is Phase 15's `C103` and its `current:` is `K57` (`checkpoint.7a0b3ab7a5a78ded487e58ea534f15eeaec68e8d27beb9d4b33f15a6ce75b6f3`), whose summary names Phase 15 and the FRF chain |

**Nine of the ten items are met — 1, 2, 3, 4, 5, 6, 8, 9 and 10 — and item 7 is not applicable
rather than wanting, because `--resolution-run` is required only for a `fixed` disposition and none
attaches to a Phase-15 FRF residual.** Items 6, 8 and 10 retired when §8's chain landed, and
`phase_state.py` now derives `complete` with an empty blocking reason.

## 8. FRF and Gemel

**The FRF chain entry this stratum needs has landed, and this section records what it is.**

- **One declaration is on disk.** `forensics/tools/gen_frf_courts.py`'s `COURTS` table gained a
  Phase-15 block — `("rt-quic", 15, …)` — and `gen_frf_courts.py` wrote the declaration under
  `forensics/frf/courts/openssl-rs-rt-quic`. `gen_frf_courts.py --check` reads
  `ok: 252 file(s) match the table (126 courts)`, and `forensics/frf/README.md` counts **126
  runtime courts** — the Phase-15 one among them, which moves the manifest count
  `docs/RELEASE_GATES.md`'s alternative names with it (D200/D413/D424/D475). **`RT-PHASE15-REF` is
  not declared**, because its probe takes addresses and diffs no transcript, so it is a reference
  basis with nothing to stage and cannot carry a declaration (D199).
- **The chain's objects are on disk.** `.frf/receipts/` carries the Phase-15 receipt
  `receipt-run-openssl-rs-rt-quic-b22aa2c1dd608efc359f63964dbcef3a44c3de502e60260cd8412bd140ea1a70-2cfb6f8ef8264aa172afe40a56184da5774f162c47e9b38a2852ec725b32623c`,
  with an empty `residuals` list. `.frf/challenges/` carries two adjudicated challenge records —
  both declared axes (`stdout-first-line`, `exit-class`) on the one court, every one `saw_defect`
  and `specificity_clean` — which is what makes the claim `sensitivity-backed` rather than merely
  green (D13). `.frf/claims/` carries the compiled claim
  `5b886f1078bec71f60cf65f0f80e89eed5978806034257a9d9f6b3667a708d16`, compiled at
  `--policy sensitivity-backed` over the receipt, binding authority `openssl-rt-3.6.4-r2` to
  candidate `openssl-rs 0.0.26` (`identity_hash e4f60d8b…`) with zero blockers and the premise
  asserting both `stdout` and `exit`.
  **The identity is the current 0.0.26 release.** The chain was cut into the store the 0.0.26
  release regenerated from clean — FRF run identities are content-addressed on the declaration,
  which carries the candidate version — so this claim records the candidate the tree is
  (`gen_frf_courts.CANDIDATE_VERSION`), which is what the fix-4 identity clause requires.
- **The Gemel change and checkpoint are this stratum's.** The change `C103` names Phase 15 and
  the FRF chain, and the checkpoint `K57`
  (`checkpoint.7a0b3ab7a5a78ded487e58ea534f15eeaec68e8d27beb9d4b33f15a6ce75b6f3`) closes it; the
  projection `forensics/GEMEL_TRAJECTORY.md`
  carries both, and the checkpoint's summary names Phase 15 and the FRF chain. Items 6, 8 and 10 of
  §7 retired with that entry, exactly as they did for Phase 8's `C74`, Phase 9's `C94`, Phase 10's
  `C95`, Phase 11's `C97`, Phase 12's `C98`, Phase 13's `C99` and Phase 14's `C101`.

**The declaration is produced by `gen_frf_courts.py`; the receipt, challenges, claim and checkpoint
were produced by running the chain in the FRF tooling container, never on the host.**
`forensics/GEMEL_TRAJECTORY.md` is the generated projection of a store Gemel keeps untracked (D17).
This section records the objects that are on disk.

## 9. What happens next

**Nothing is handed from this stratum to a later one.** `forensics/phase15-obligations.json`'s
`deferred` list is empty and its `deferred_by_phase` reads `{}`; every export this stratum owns is
implemented, and it received no hand-off to pass on (`received_by_handoff` 0). The QUIC
implementation object (`quic_impl.c`) and the TLS message layer are not exports of `quic.h` and were
never this stratum's (`docs/PHASE-15-SUBPHASES.md:13-21,83-88`).

**The immediate next actions this seal's own state points at**, recorded so they are not lost:

- **The FRF/Gemel chain entry has landed.** §8's subject is now the objects on disk: the one
  declaration, one receipt, two adjudicated challenges, the claim
  `5b886f1078bec71f60cf65f0f80e89eed5978806034257a9d9f6b3667a708d16` and the checkpoint `K57`.
  This stratum registers no `CT-*` court, so the entry covers the one behavioural differential court
  and nothing is recorded as not declarable; `RT-PHASE15-REF` is the reference basis and is not
  declarable. Items 6, 8 and 10 of §7 retired with it, and `phase_state.py` derives `complete`.
- **The QUIC object and the TLS message layer remain for later strata.** `quic_impl.c`'s dispatch
  bodies and the TLS handshake the methods would drive are unbuilt (§5); the two message-layer units
  Phase 14 named are deferred to Phase 16 (§10, `forensics/prerequisites.json`), and no arm of this
  stratum builds or parses a flight.
- **`forensics/phase15-obligations.json` is the place a reader should look before believing any
  figure in this document**, because this document types no census figure of its own: §3's table and
  the head matter's court and coverage figures each name the artefact they were read from.

## 10. Corrections this seal records

Appended rather than folded into the sections above, for the reason the Phase 9 seal's §10 gives: a
correction that has been merged into the prose it corrects cannot be checked against the prose it
replaced. These are the corrections this seal makes to the plan's own account, and the corrections
the evidence forced rather than the ones a reviewer might have preferred.

1. **The stratum's export ledger reaches zero open before the stratum is complete, and this seal
   writes the distinction down.** `phase15_obligations.py`'s `complete` is the ledger-level emptiness
   check, not the phase-exit predicate; the stratum is not complete until 15.2's seal and the
   FRF/Gemel chain (as D529 records for Phase 14). This seal is that 15.2 document, and §7's
   items 6/8/10 rows are the predicate's remaining input.
2. **The 15.1 row named two authority-internal functions the crate reduces rather than builds.**
   The row's cell carried `tls1_default_timeout` and `ssl3_undef_enc_method` in backticks, and the
   crate's `src/ssl/quic/quic_method.rs` builds the method table with the timeout reduced to a
   second count and the enc method left undefined rather than as the two named functions. Deriving
   the stratum `complete` made `plan_reconciliation.py` refuse it with a
   `plan_named_symbol_not_reached` finding for each; the row now describes the timeout and the
   enc-method table as behaviour, and §3.1 keeps the technical detail where no gate reads it as a
   promise (`docs/PHASE-15-SUBPHASES.md:65,74-92`).
3. **The two message-layer unit deferrals Phase 14 pointed at this stratum are corrected to
   Phase 16.** Phase 14's 14.5b row named `ssl/statem/statem_clnt.c` and `ssl/statem/statem_srvr.c`
   and `forensics/prerequisites.json` recorded them as `deferred_to_later_stratum` to Phase 15;
   this stratum lands only the three `quic.h` constructors, so sealing it made the two records read
   as stale deferrals (`unit_record_defers_to_a_stratum_that_has_sealed`). Both are now deferred to
   Phase 16, the next later stratum in `phase_state.py`'s `REQUIRES` DAG, with the correction
   recorded in the record's own `reason`.
4. **`received_by_handoff` is 0, and this stratum inherits nothing.** No earlier stratum's ledger
   records an `owning_phase == 15` hand-off, and the plan's §4.1 measures it rather than asserting
   it (`docs/PHASE-15-SUBPHASES.md:35-39,96-99`). The two message-layer units are *unit* deferrals
   for the prerequisite gate, not export hand-offs, and do not move that count.
5. **The plan's seal path is corrected to the document that actually lands.** The 15.2 row named
   `docs/PHASE-15-QUIC-ECH-SEAL.md`; the seal this landing writes is `docs/PHASE-15-QUIC-SEAL.md`
   (its subject is the QUIC method constructors, not the ECH extension surface, which is Phase
   14's), and the row now names it (`docs/PHASE-15-SUBPHASES.md:66`).
6. **The FRF/Gemel chain entry landed, and §7 and §8 record it.** The seal's §8 records the one
   declaration, one receipt, two adjudicated challenges, the `sensitivity-backed` claim
   `5b886f1078bec71f60cf65f0f80e89eed5978806034257a9d9f6b3667a708d16` and the Gemel change
   `C103` / checkpoint `K57`
   (`checkpoint.7a0b3ab7a5a78ded487e58ea534f15eeaec68e8d27beb9d4b33f15a6ce75b6f3`), so items 6, 8
   and 10 retired and `phase_state.py` derives `complete`.
   `seal_sha256` is recomputed from the document's new bytes.
