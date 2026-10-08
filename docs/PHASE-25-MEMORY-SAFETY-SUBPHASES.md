# Phase 25 — the memory-safety stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 25 is the stratum `docs/RELEASE_GATES.md` §1 names "Memory-safety atlas, unsafe
trusted-computing-base census and historical CVE extinction court". It is admitted once the
downstream-1000 stratum (Phase 24) is complete, and it is dependency-ordered after it rather than
after the highest number: `forensics/tools/phase_state.py`'s `REQUIRES[25]` is `(24,)`, and because
Phase 24 requires Phase 23 (which requires Phase 21, which requires Phase 22) that single edge
transitively requires the multitrack authority lineage, the maintenance-delta machinery and the
authority archaeology. Its crosswalks read Phase-18 hostile-fuzz evidence and Phase-22
whole-program reachability evidence as well, so it depends on Phases 18, 22, 23 and 24 — the edge
declares 24, and the crosswalk courts declare the rest. No existing phase is renumbered.

Like Phases 16 through 24 it owns **no exported symbol**: reading
`forensics/atlas/symbol-ownership.json` for `owner_phase == 25` yields nothing, because the
declaring-header rule assigns no installed header to this stratum. Its unit is therefore not a
symbol. As with Phases 18 through 24 it **hands nothing forward and receives nothing**: it adds no
library surface, takes no unit or symbol deferral from an earlier stratum, and activates no
provider.

What it owes is a **memory-safety atlas, an unsafe trusted-computing-base census and a historical
CVE extinction court** over the exact admitted candidate's first-party shipped source/build surface.
The vocabulary is fixed here:

* an **unsafe site** — the **primary unit**: one unsafe operation the **compiler** establishes, at
  a file/line/column, with the toolchain that derived it. A regular-expression scan or a text grep
  is a *projection* of the source, not the source's unsafe operations, so it is never the unit.
* a **source-census row** — one shipped first-party source/build file, its kind, its origin
  (`FIRST_PARTY`, `VENDORED`, `GENERATED`) and its compiler-derived unsafe-operation count. A
  vendored dependency is recorded but is **not** part of the claimed trusted computing base.
* an **unsafe context** — the enclosing unsafe block/fn/impl/extern block, where a **safety
  contract** is stated. A context with sites and no contract is the unexplained site the bounded
  claim forbids.
* a **safety obligation** — the property an unsafe site must establish, along one **obligation
  dimension** (`NULLABILITY`, `LIFETIME`, `ALIASING`, `ALIGNMENT`, `INITIALIZATION`, `BOUNDS`,
  `OWNERSHIP`, `REFCOUNT`, `THREAD_AFFINITY`, `ABI`, `UNWIND`, `TYPE_VALIDITY` and the rest), and
  how it is discharged.
* a **tool result** — a Miri, ASan, MSan, TSan or Kani result, each naming a **tool state**
  (`PASS`, `FAIL`, `NOT_REACHABLE`, `UNSUPPORTED`). `UNSUPPORTED` records that the tool could not
  express the question, and it is **never** `PASS`.
* a **historical CVE** and its **replay** — a memory-safety-relevant OpenSSL CVE, classified from
  the closed **CVE taxonomy**, and the candidate's disposition in the closed **CVE replay states**
  (`UPSTREAM_VULNERABLE_REPRODUCED`, `CANDIDATE_STRUCTURALLY_EXCLUDED`, `CANDIDATE_SAFE_REJECTION`,
  `CANDIDATE_NO_MEMORY_FAULT_OBSERVED`, `CANDIDATE_UNSAFE_PATH_REMAINS`,
  `CANDIDATE_REPRODUCES_MEMORY_FAULT`, `CANDIDATE_FEATURE_NOT_APPLICABLE`, `UNKNOWN`). A
  `CANDIDATE_STRUCTURALLY_EXCLUDED` disposition is a claim about a **mechanism**, so it must cite
  its evidence.

The **bounded claim** this stratum records — in the plan, not as a proof — is: *the
memory-safety-relevant trusted computing base of the exact admitted candidate has been exhaustively
inventoried over its first-party shipped source/build surface; unsafe operations are mapped to their
safety contracts, Phase-22 reachability, Phase-24 downstream usage and available dynamic/formal
evidence, with no unexplained reachable unsafe site in the claimed profile.*

It is **not** "no memory-safety bug can exist" and it is **not** "100% memory safe". The
load-bearing **non-claims** belong to every subphase, and they are recorded in the ledger's
`ledger_note` and here:

* **safe Rust does not prove protocol correctness** — memory safety is not behavioural correctness,
  and a sound unsafe site is not a correct protocol;
* **unsafe Rust is not inherently vulnerable** — an unsafe operation with a discharged contract is
  a sound operation, so an unsafe site is not a defect;
* **unsafe LOC is not a vulnerability count** — lines of unsafe code are a **secondary projection**
  of the compiler-derived census, and a count is not a risk;
* **Miri, ASan and TSan are not exhaustive** — a tool that instruments a target records what it
  observed, and `NOT_REACHABLE` and `UNSUPPORTED` are not clean results;
* **Kani does not prove unsupported or concurrent whole-program behaviour** — a proof is only as
  wide as the harness that expresses it;
* **historical CVE extinction does not predict a future CVE count** — replaying the past is not a
  statement about an unmeasured future;
* **compatibility is not security** — passing the compatibility strata is not memory safety;
* **memory safety is not cryptographic correctness** — a sound implementation can still be
  cryptographically wrong;
* **absence of a crash is not structural proof** — a run that did not crash is not a proof that no
  path can.

A site whose exposure cannot be classified is recorded in the closed exposure vocabulary; a tool
result that cannot express its target is recorded `UNSUPPORTED` with its reason; a CVE whose replay
cannot be established is recorded `UNKNOWN`. `docs/UNSAFE.md`, `docs/NON_CLAIMS.md`,
`docs/ABI_POLICY.md`, `docs/CONCURRENCY_MODEL.md` and `docs/REPRODUCIBILITY.md` are the authorities
on what may be said; a subphase that discovers its unit is somewhere else records that rather than
forcing the row (§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase25-obligations.json` is
authoritative for the present. The activation measurement was taken against `phase25-memory-safety`
off merged `main` (Phase 24 complete).

**Phase 25 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for `owner_phase ==
25` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger fails closed if
that ever stops being true rather than silently counting a symbol through a non-export unit.

**It receives zero provider registration rows.** Reading `forensics/atlas/provider-algorithms.json`
for `owning_phase == 25` gives no row: this stratum activates no provider. The ledger fails closed
if the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading `forensics/prerequisites.json`
for `owner_phase == 25`: no `deferrals` row and no `units` row. The plane's records and deferrals
are all owned by earlier strata, so this stratum's working set is entirely its own authored
contract.

**The memory-safety contract is twenty-two units**, each derived from the court that measures it,
and each court lands with the subphase that builds its instrument: the constitution,
`source-census`, `non-rust-tcb`, `safety-obligations`, `ownership-planes`, `phase22-crosswalk`,
`phase24-crosswalk`, `exposure-classification`, `unsafe-reduction`, `miri`, `asan-msan`, `tsan`,
`kani`, `phase18-fuzz-crosswalk`, `phase24-safety-coverage`, `historical-cve-census`, `cve-replay`,
`mechanism-reconciliation`, `red-team`, `clean-regeneration`, `frf-gemel-closure` and
`memory-safety-seal`. All twenty-two are open at activation, so the ledger's live
`counts.open_in_this_stratum` is twenty-two, and the activation measurement is twenty-two `pending`
courts over twenty-two units.

**The memory-safety evidence plane already has its schema.** 25.0 lands
`forensics/tools/memory_safety_schemas.py`, which defines and validates the record kinds the later
subphases populate and fixes the closed vocabularies (the unsafe-operation kinds, the obligation
dimensions, the exposure classes, the tool states, the CVE taxonomy, the CVE replay states, the risk
tiers and the panic/unwind classes). The schema refuses a non-compiler-derived unsafe site, a
seal-class summary that marks an externally reachable unsafe site's tool state `UNSUPPORTED` as a
pass, and a `CANDIDATE_STRUCTURALLY_EXCLUDED` replay with no evidence. 25.0 invents none of the
evidence: it names the record kinds the later subphases will fill.

**This stratum begins on nothing of its own.** No Phase-25 court exists at activation, so
`open_in_this_stratum` opens at the whole working set (twenty-two) and moves only as the subphases
below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the live
record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 25.0 | **The constitution, the schemas, the guard, the ledger and the runner** | `docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`, `forensics/tools/memory_safety_schemas.py`, the Docker-only execution guard `forensics/tools/phase25_guard.py`, the committed venue manifest `forensics/memory-safety/container.json` and the measurement in §1. The ledger (`forensics/phase25-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase25_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 24 | `MS-CONSTITUTION` |
| 25.1 | **The compiler-backed source census** | the shipped first-party source/build census (`artifacts/phase25/source-census.json`), one row per file with its kind, origin and the **compiler-derived** unsafe operations it contains, and the per-unit compiler provenance. | 25.0 | `MS-SOURCE-CENSUS` |
| 25.2 | **The non-Rust trusted computing base** | the first-party C sources and headers, the inline assembly, the exported FFI boundaries, the C adapters and the variadic boundaries (`artifacts/phase25/non-rust-tcb.json`), so the unsafe TCB is not read as Rust-only. | 25.1 | `MS-NON-RUST-TCB` |
| 25.3 | **The safety obligations** | one obligation per compiler-derived unsafe site along its dimension, with how it is discharged or why it is open (`artifacts/phase25/safety-obligations.json`), so no reachable unsafe site is left unexplained. | 25.1, 25.2 | `MS-SAFETY-OBLIGATIONS` |
| 25.4 | **The ownership, allocation and callback planes** | the allocation/deallocation associations, the ownership edges across the Rust/C boundary, the callback lifetimes, the unsafe `Send`/`Sync` impls, the global/static state and the panic/unwind boundaries (`artifacts/phase25/ownership-planes.json`). | 25.3 | `MS-OWNERSHIP-PLANES` |
| 25.5 | **The Phase-22 reachability crosswalk** | the crosswalk from each unsafe site to the Phase-22 whole-program reachability atlas (`artifacts/phase25/phase22-crosswalk.json`), so reachability is the Phase-22 authority's answer rather than a second one. | 25.3 | `MS-PHASE22-CROSSWALK` |
| 25.6 | **The Phase-24 downstream crosswalk** | the crosswalk from each unsafe site to the Phase-24 downstream-1000 usage evidence (`artifacts/phase25/phase24-crosswalk.json`), so downstream usage is the Phase-24 measurement's answer rather than a typed one. | 25.3, 24 | `MS-PHASE24-CROSSWALK` |
| 25.7 | **The exposure/data-flow classification** | the classification of every unsafe site into the closed exposure classes (`artifacts/phase25/exposure.json`), so a site is reachable by measurement rather than by assertion, and a site reachable only in an unclaimed profile is recorded as such. | 25.5, 25.6 | `MS-EXPOSURE-CLASSIFICATION` |
| 25.8 | **The unsafe reduction** | the reduction worklist (`artifacts/phase25/unsafe-reduction.json`): the reachable unsafe sites reduced by a safe intrinsic or a checked wrapper where the venue can, each with its before/after compiler-derived sites, and the sites that remain named rather than dropped. It never weakens the ABI or an unsafe lint to shrink the count. | 25.7 | `MS-UNSAFE-REDUCTION` |
| 25.9 | **Miri** | the Miri results over the claimed profile (`artifacts/phase25/miri.json`), each with its tool state and its unsupported reason where it could not express the question. | 25.4, 25.8 | `MS-MIRI` |
| 25.10 | **ASan/MSan** | the ASan and MSan results over the claimed profile (`artifacts/phase25/asan-msan.json`), each with its tool state and its unsupported reason. | 25.4, 25.8 | `MS-ASAN-MSMAN` |
| 25.11 | **TSan** | the TSan results over the concurrency-relevant surface (`artifacts/phase25/tsan.json`), each with its tool state and its unsupported reason, so a race the tool could not observe is not read as absent. | 25.4, 25.8 | `MS-TSAN` |
| 25.12 | **Kani** | the Kani harness results over the stated harnesses and their targets (`artifacts/phase25/kani.json`), each with its tool state and its unsupported reason, and no claim beyond the harnesses that exist. | 25.4, 25.8 | `MS-KANI` |
| 25.13 | **The Phase-18 fuzz crosswalk** | the crosswalk from the memory-safety census to the Phase-18 hostile-fuzz courts (`artifacts/phase25/phase18-fuzz-crosswalk.json`), so a discovered memory-safety failure is a preserved Phase-18 record rather than a discarded run. | 25.7, 18 | `MS-PHASE18-FUZZ-CROSSWALK` |
| 25.14 | **The Phase-24 downstream safety coverage** | the coverage of the unreduced unsafe sites by the Phase-24 downstream runs (`artifacts/phase25/phase24-safety-coverage.json`), naming the reachable sites no downstream measurement observes, so a reachable site is never assumed exercised. | 25.6, 25.8 | `MS-PHASE24-SAFETY-COVERAGE` |
| 25.15 | **The historical CVE census** | the historical memory-safety-relevant OpenSSL CVE census (`artifacts/phase25/historical-cves.json`), each classified from the closed CVE taxonomy with its affected versions and its fix. | 25.2 | `MS-HISTORICAL-CVE` |
| 25.16 | **The historical CVE replay** | the replay of the historical CVEs against the exact admitted candidate (`artifacts/phase25/cve-replay/`), each in the closed replay states, where a structural exclusion cites its structure and an unsafe path that remains is named. | 25.15 | `MS-CVE-REPLAY` |
| 25.17 | **The vulnerability-mechanism reconciliation** | the mechanism reconciliation (`artifacts/phase25/mechanisms.json`): each mechanism class joined to the candidate's structure and the replay evidence, with a structural immunity stated with its reason and its evidence, so extinction is a mechanism statement and never a future-CVE-count prediction. | 25.16 | `MS-MECHANISM-RECONCILIATION` |
| 25.18 | **The red team** | the red-team pass over the claimed profile (`artifacts/phase25/red-team.json`): the reachable unsafe sites attacked with adversarial inputs and configurations, each attempt recorded with its outcome, so an unexplained reachable unsafe site is a finding rather than an omission. | 25.8, 25.13, 25.14, 25.17 | `MS-RED-TEAM` |
| 25.19 | **The full clean regeneration** | the full clean regeneration of the census and its evidence from the frozen candidate and the frozen toolchain (`artifacts/phase25/regeneration.json`), so the atlas is reproducible rather than assembled, and a `PASS` that does not survive the regeneration is a finding. | 25.7, 25.9-25.14, 25.18 | `MS-CLEAN-REGEN` |
| 25.20 | **The FRF/Gemel closure** | the FRF/Gemel chain closure where the stratum stages a declarable court (`forensics/atlas/phase25/frf-closure.json`), so a passing atlas is not read as a chain that never ran. | 25.19 | `MS-FRF-CLOSURE` |
| 25.21 | **The seal** | the closure of the bounded claim and the non-claims it never exceeds. Evidence: `docs/PHASE-25-MEMORY-SAFETY-SEAL.md` (at the seal). | 25.0-25.20 | `MS-SEAL` |

The rows partition the working set by source: each subphase row lands the instrument for exactly one
of the twenty-two contract units. The partition is derived from `forensics/phase25-obligations.json`
joined to `artifacts/phase25/COURTS.json`, not typed.

**The evidence artefacts this stratum produces.** The later subphases populate the **memory-safety
evidence plane**, each artefact validated against a record kind in
`forensics/tools/memory_safety_schemas.py`:

| artefact | record kind | schema |
|---|---|---|
| `artifacts/phase25/source-census.json` | the shipped first-party files and their compiler-derived unsafe operations | `source_census`, `unsafe_context` |
| `artifacts/phase25/unsafe-sites.json` | the compiler-derived unsafe operations | `unsafe_site` |
| `artifacts/phase25/non-rust-tcb.json` | the C/asm/FFI trusted computing base | `c_adapter`, `ffi_boundary` |
| `artifacts/phase25/safety-obligations.json` | the obligations per unsafe site | `safety_obligation` |
| `artifacts/phase25/ownership-planes.json` | allocations, ownership edges, callbacks, Send/Sync, globals, panic boundaries | `allocation_site`, `ownership_edge`, `callback_lifetime`, `send_sync_impl`, `global_state`, `panic_boundary` |
| `artifacts/phase25/phase22-crosswalk.json`, `phase24-crosswalk.json` | the crosswalks to Phases 22 and 24 | the crosswalk courts' own checks |
| `artifacts/phase25/exposure.json` | the exposure/data-flow classification | the exposure court's own checks |
| `artifacts/phase25/unsafe-reduction.json` | the reduction worklist | the reduction court's own checks |
| `artifacts/phase25/miri.json` | the Miri results | `miri_result` |
| `artifacts/phase25/asan-msan.json` | the ASan/MSan results | `sanitizer_result` |
| `artifacts/phase25/tsan.json` | the TSan results | `sanitizer_result` |
| `artifacts/phase25/kani.json` | the Kani harness results | `kani_result` |
| `artifacts/phase25/phase18-fuzz-crosswalk.json` | the Phase-18 fuzz crosswalk | `fuzz_crosswalk` |
| `artifacts/phase25/phase24-safety-coverage.json` | the downstream safety coverage | `coverage` |
| `artifacts/phase25/historical-cves.json` | the historical CVE census | `historical_cve` |
| `artifacts/phase25/cve-replay/` | the per-CVE dispositions | `cve_replay` |
| `artifacts/phase25/mechanisms.json` | the mechanism reconciliation | `vulnerability_mechanism` |
| `artifacts/phase25/red-team.json` | the red-team outcomes and residuals | `residual` |
| `artifacts/phase25/summary.json` | the seal-class closure record | `summary` |
| `docs/PHASE-25-MEMORY-SAFETY-SEAL.md` | the seal | — |

25.0 invents none of these artefacts: it defines and self-tests the schemas the later subphases will
be validated against, and the runner records the schema inventory and the closed vocabularies so the
record kinds are a file the evidence points at rather than prose.

## 3. What each subphase must honour

**3.1 The compiler is the authority for unsafe operations, never a regex.** Every unsafe site is
derived from the compiler's own view of the source, with the toolchain named. A regular-expression
scan or a text grep is a projection, and a metric built on it would move when a comment moves;
`validate_unsafe_site` refuses a site that is not compiler-derived.

**3.2 The primary unit is a compiler-derived unsafe operation, and LOC is a secondary projection.**
A subphase that reports a ratio of unsafe lines reports a projection of the census, never the
security claim. The atlas counts operations, and a count is not a risk.

**3.3 Nothing executes on the host.** Every entry point calls the Docker-only execution guard
(`forensics/tools/phase25_guard.py`) first, so a host invocation is refused rather than producing
unreproducible evidence (`docs/REPRODUCIBILITY.md` §1). The tool-specific environments (census,
miri, asan, tsan, msan, kani, cve-replay) are derived from the one committed base
`forensics/memory-safety/container.json` names, never from one mutable kitchen-sink image.

**3.4 No subphase weakens the ABI or an unsafe lint to shrink the count.** A reduction is a real
safe intrinsic or a checked wrapper, recorded with its before/after compiler-derived sites; a lint
is never silenced to make a site disappear, and the unsafe budget gate (§3.5) is not relaxed to let
a candidate pass.

**3.5 The unsafe budget gate.** The stratum fixes an authored **unsafe budget**: the maximum number
of unreduced reachable unsafe sites in the claimed profile. The gate fails a candidate whose
compiler-derived reachable unsafe site count exceeds the budget, and the budget moves only by an
explicit recorded decision, not as a side effect of a measurement. The budget is a bound on the
atlas's residual, never a claim that the sites within it are safe.

**3.6 A tool state of `UNSUPPORTED` is never `PASS`.** A tool that could not express the question
records `UNSUPPORTED` with its reason, and the seal-class summary refuses a pass while an externally
reachable unsafe site carries `UNSUPPORTED`. `NOT_REACHABLE` is likewise not a clean result.

**3.7 A `CANDIDATE_STRUCTURALLY_EXCLUDED` CVE replay cites its evidence.** Structural exclusion is
a claim about a mechanism; the structure that makes the mechanism inexpressible is named, and a
disposition without evidence is refused by the schema.

**3.8 The instrument-versus-property split keeps a pass from being read as the property.** A
passing court is an instrument: it ran and its control was honest. The property it names — a fully
reconciled mechanism set, a fully classified site set — is carried by `property_status` and
`findings`, and where the evidence falls short the unit reads `NOT_CLAIMED` with the gap named. The
seal records the non-claims as findings, so a passing seal is never "the candidate is memory safe".

**3.9 The twenty-two units land in one ordered chain behind the runner.** 25.0 lands the
constitution; 25.1 through 25.20 land the twenty instruments; 25.21 lands the seal that closes the
bounded claim; each lands its code, its court and its regenerated artefacts in one commit, and the
ledger's `open_in_this_stratum` moves only when a court in `artifacts/phase25/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase25-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `memory-safety contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase 16's
`cli-config contract` through Phase 24's `downstream 1000 contract` are. The ledger fails closed if
the ownership atlas ever assigns this stratum an export, if the provider census assigns it a
registration row, or if the prerequisite plane assigns it a deferral or a translation unit, because
then the non-export unit would be the wrong shape.

**4.2 The precondition this plan places on 25.0, and it is not optional.** `run_courts.py` refuses
a stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase25_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its twenty-two courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase25_courts.py` ↔ `phase25_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase25_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. So the activation order is: the runner
and its pending registry, the ledger, the schemas and the guard land **together**, or
`run_courts.py` fails and the tree carries an activation whose runner is refused.

**4.3 The Docker-only execution guard is the stratum's first-class precondition, and one base is
derived.** Phase 25's subject is the output of a compiler-backed census, the sanitizers, the proof
harnesses and the CVE replays, so `docs/REPRODUCIBILITY.md` §1's "nothing executes on the host" is
the stratum's own precondition rather than a procedural rule. 25.0 lands
`forensics/tools/phase25_guard.py`, which fails closed unless the container marker (`/.dockerenv`)
is present **and** `PHASE25_CONTAINER` is `1` **and** the environment records an admitted image
identity and platform matching the committed manifest `forensics/memory-safety/container.json`. The
manifest names one **canonical base** — the minimal Debian image the court is built from, pinned by
digest — and records the **derivation policy**: the census, Miri, ASan, MSan, TSan, Kani and the CVE
replay environments are each derived from that one base in the subphase that lands them, rather than
one mutable kitchen-sink image that accumulates every tool. The venue records the admitted values:
every `docker/openssl-rs-court.sh exec` sets the three variables, so a host invocation -- which has
no marker -- is refused with a clear message. The guard exposes the check as a pure function, so the
runner's self-test proves a host invocation is refused without running on a host. The manifest lists
the Phase-25 **metadata-only** generators (`phase25_obligations.py`), which read committed atlases
and execute nothing: the guard admits them on any host exactly as the other strata's obligation
generators run host-side, and a generator that would compile, instrument, prove or replay is
deliberately absent from the list. Widening the list is a reviewable act, not a silent one.

**4.4 The prerequisite and provider planes are not this stratum's universe, and the plan says so.**
No row of `forensics/prerequisites.json` and no row of `forensics/atlas/provider-algorithms.json` is
owned by phase 25, so this plan names no prerequisite unit and no provider row for it and plan
reconciliation has no unit of this stratum's to judge; a subphase that discovers its unit is
elsewhere records that rather than forcing a row (§0, §5).

**4.5 The seal will correct this plan if the record kinds differ.** Phase 25 activates over record
kinds it defines in 25.0 but does not yet populate, so §1's measurement is a read of what exists and
a design of what will. If a subphase finds that a record kind the brief names is better split, or
that a class list needs a member the schema does not have, it records the correction here and in the
seal rather than folding it into the prose it corrects. The correction is checked by the subphase's
court rather than asserted.

**4.6 The bounded claim is bounded, and the non-claims are its boundary.** The plan's claim is about
the **inventory** of a fixed candidate's first-party surface, not about the absence of bugs. Every
subphase records the non-claims where it can be read as more than it is, and the seal records them
as findings, so a passing seal is an instrument plus an observation record. A rate or a count is a
measurement of the claimed profile, never of all profiles or of an unmeasured future.

**4.7 The primary unit is compiler-derived, and the LOC projection is labelled as one.** The brief
fixes the unit at the compiler-derived unsafe operation. A later subphase that publishes an unsafe
LOC ratio publishes it as a projection of the census, with the census beside it, so the projection
can never be read as the security claim. The `MS-SOURCE-CENSUS` court checks this rather than this
paragraph asserting it.

## 5. Process

This stratum inherits Phases 8 through 24's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the twenty-two-unit measurement in §1. A subphase that discovers its
unit is elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the twenty-two memory-safety contract
units, recorded in the ledger's contract-unit block rather than as open exports.
