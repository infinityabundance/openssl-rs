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
| 25.1 | **The compiler-backed source census** | the shipped first-party source/build census (`artifacts/phase25/source-census.json`), one row per file with its kind, origin and the **compiler-derived unsafe operations** it contains, one site per operation (each with its own source span and stable id) anchored in its compiler-identified unsafe context, and the per-unit compiler provenance. | 25.0 | `MS-SOURCE-CENSUS` |
| 25.2 | **The non-Rust trusted computing base** | the first-party C sources and headers, the inline assembly, the exported FFI boundaries, the C adapters and the variadic boundaries (`artifacts/phase25/non-rust-tcb.json`), so the unsafe TCB is not read as Rust-only. | 25.1 | `MS-NON-RUST-TCB` |
| 25.3 | **The safety obligations** | one obligation per compiler-derived unsafe site along its dimension, with how it is discharged or why it is open (`artifacts/phase25/safety-obligations.json`), so no reachable unsafe site is left unexplained. | 25.1, 25.2 | `MS-SAFETY-OBLIGATIONS` |
| 25.4 | **The ownership, allocation and callback planes** | the allocation/deallocation associations, the ownership edges across the Rust/C boundary, the callback lifetimes, the unsafe `Send`/`Sync` impls, the global/static state and the panic/unwind boundaries (`artifacts/phase25/ownership-planes.json`). | 25.3 | `MS-OWNERSHIP-PLANES` |
| 25.5 | **The Phase-22 reachability crosswalk** | the crosswalk from each unsafe site to the Phase-22 whole-program reachability atlas (`artifacts/phase25/phase22-crosswalk.json`), so reachability is the Phase-22 authority's answer rather than a second one. | 25.3 | `MS-PHASE22-CROSSWALK` |
| 25.6 | **The Phase-24 downstream crosswalk** | the crosswalk from each unsafe site to the Phase-24 downstream-1000 usage evidence (`artifacts/phase25/phase24-crosswalk.json`), so downstream usage is the Phase-24 measurement's answer rather than a typed one. | 25.3, 24 | `MS-PHASE24-CROSSWALK` |
| 25.7 | **The exposure/data-flow classification** | the classification of every unsafe site into the closed exposure classes (`artifacts/phase25/exposure.json`), so a site is reachable by measurement rather than by assertion, and a site reachable only in an unclaimed profile is recorded as such. | 25.5, 25.6 | `MS-EXPOSURE-CLASSIFICATION` |
| 25.8 | **The unsafe reduction** | the reduction worklist (`artifacts/phase25/unsafe-reduction.json`): the reachable unsafe sites reduced by a safe intrinsic or a checked wrapper where the venue can, each with its before/after compiler-derived sites, and the sites that remain named rather than dropped. It proves a **safe-core reconstruction** by construction: a genuinely internal unsafe mechanism is replaced with safe Rust, every removed operation classified `ELIMINATED` or `RELOCATED_TO_BOUNDARY` and never `HIDDEN`, the before/after counts re-derived from the re-run census, and the Phase-24 downstream headline required unchanged. It never weakens the ABI or an unsafe lint to shrink the count. | 25.7 | `MS-UNSAFE-REDUCTION` |
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
| `artifacts/phase25/unsafe-reduction.json` | the reduction worklist and the safe-core reconstruction record | the reduction court's own checks |
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

**3.4 No subphase weakens the ABI or an unsafe lint to shrink the count, and a reconstruction is
never `HIDDEN`.** A reduction is a real safe intrinsic or a checked wrapper, recorded with its
before/after compiler-derived sites; a lint is never silenced to make a site disappear, and the
unsafe budget gate (§3.5) is not relaxed to let a candidate pass. 25.8 additionally proves a
**safe-core reconstruction** by construction: a genuinely internal unsafe mechanism is replaced with
safe Rust, and every removed operation is classified `ELIMINATED` (the dangerous operation is gone
from the census) or `RELOCATED_TO_BOUNDARY` (it survives only in an unavoidable, isolated FFI
boundary). A `HIDDEN` reduction -- a mere wrapper that leaves the operation where it was -- is
refused. The reconstruction conserves observable behaviour: the crate's tests pass, every court
passes, and the Phase-24 downstream headline (the `DROP_IN_PASS` verdicts, the `p1000-run.json`
ladder and the eight functional workloads) is re-read from the committed measurement and required
unchanged.

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

**25.6 recorded one such correction, and it is checked rather than asserted.** The Phase-24
downstream crosswalk's join is partial wherever the evidence is: an imported OpenSSL symbol with no
clean Phase-22 entity mapping, or a family observed at runtime with no committed usage fingerprint,
is a leftover that the residual vocabulary's `evidence_missing` (which names a site with no authority
translation unit) does not describe. 25.6 therefore added the member `join_evidence_missing` to
`memory_safety_schemas.RESIDUAL_CLASSES`, and the `MS-PHASE24-CROSSWALK` court validates every one of
the crosswalk's residuals against that vocabulary, so a partial join is recorded rather than zeroed
or guessed.

**25.7 recorded one such correction, and it is checked rather than asserted.** The plan's exposure
vocabulary (brief section 7) names two classes the 25.0 schema did not carry: `TOOLING_ONLY`, for a
site only in a tooling module, and `LOCAL_FILE_INPUT_REACHABLE`, for a site reached by a local file
input. 25.7 therefore added both to `memory_safety_schemas.EXPOSURE_CLASSES`, added
`LOCAL_FILE_INPUT_REACHABLE` to `EXTERNALLY_REACHABLE_EXPOSURE`, and the `MS-EXPOSURE-CLASSIFICATION`
court validates every site's class against that vocabulary, so a class the schema lacked is recorded
rather than folded into the prose it corrects. It also records that the Phase-22 compatibility
closure leaves its `protocol` family unpopulated, so a network exposure class is grounded in the
site's committed parser role and the entry semantics it names rather than in a Phase-22 root.

**A second 25.7 correction records `UNKNOWN_REACHABILITY` and requires a witness for
`UNREACHABLE_PROFILE`, and it is checked rather than asserted.** The classification first treated an
unresolved Phase-22 mapping as `UNREACHABLE_PROFILE`, but a missing mapping is missing evidence: it
does not establish that the claimed profile cannot reach the site, and reading it as unreachability
understates risk exactly where the mapping is weakest. 25.7 therefore added
`UNKNOWN_REACHABILITY` to `memory_safety_schemas.EXPOSURE_CLASSES`, deliberately **not** in
`EXTERNALLY_REACHABLE_EXPOSURE` (an unknown is not a reachability claim in either direction), and
made the derivation award `UNREACHABLE_PROFILE` only to a site that carries a justified exclusion
witness recorded on it (a committed exclusion residual, or a resolved authority unit no root
reaches); every other unresolved site is `UNKNOWN_REACHABILITY`, and no site is dropped. The counts
record `sites_unknown_reachability` beside `unreachable_profile`, so an unknown is never read as a
zero, and the `MS-EXPOSURE-CLASSIFICATION` court's sensitivity control catches a mutation that maps
an unresolved site to `UNREACHABLE_PROFILE` with no witness and one that maps it to an external
class.

**25.7 recorded a third correction: unknown exposure is tier `SU`, not `S0`, and it is checked
rather than asserted.** The second 25.7 correction made an unresolved site `UNKNOWN_REACHABILITY`
rather than `UNREACHABLE_PROFILE`, but the risk tier left every non-externally-reachable class -- the
unknown included -- in `S0`, so an unknown shipped in the same bucket as a genuinely non-exposed
site: uncertainty was read as the lowest review priority, the wrong consequence of uncertainty. 25.7
therefore added `SU` (unknown exposure) to `memory_safety_schemas.RISK_TIERS` and assigns it to every
`UNKNOWN_REACHABILITY` site, while a genuinely non-exposed site stays `S0`; a site with unknown
exposure stays eligible for high-priority investigation until evidence narrows it, because an unknown
is not the lowest priority. The `MS-EXPOSURE-CLASSIFICATION` court's sensitivity control catches a
mutation that assigns an unknown-reachability site `S0` with specificity holding, and the risk-tier
rule and the plane's `counts.sites_by_risk_tier` record `SU` beside `S0`.

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

**25.1 recorded one such correction, and it is checked rather than asserted.** §3.2 fixes the
primary unit at a **compiler-derived unsafe operation**, but the 25.1 census first enumerated a
compiler-identified *context* and recorded **one site per context**, so a context holding several
operations -- `unsafe { *first = 1; *second = 2; }` -- became one site rather than two. 25.1
corrected the extractor to enumerate every operation inside the compiler-established context span,
so a context with N operations yields N sites, each with its own source span and a stable `site_id`
derived from `(file, span, operation kind)`, while the enclosing `context_id` still names the
compiler context the operation sits in and `classification_method` records the method on every row.
A HIR/MIR-backed enumerator was investigated first, with the pinned nightly, and is recorded as the
measured reason the operation-level extractor is the compiler-anchored span scan:
`-Zunpretty=hir-tree` and `-Zunpretty=thir-tree` are not reproducible at this crate's scale (the lib
aborts with `memory allocation of 2147483648 bytes failed` and `memory allocation of 1207468032
bytes failed`), and `-Zunpretty=mir -Zmir-include-spans` -- producible at 4,922,910 lines / 364 MB,
with spans that align with the compiler's context spans -- is post-desugaring, so a method call and
a free-function call print identically, a union access is unlabelled and the
`ptr::read`/`read_unaligned`/`assert_unchecked` family is indistinguishable from any other call. The
**unchanged context-level kind classifier is kept as the independent cross-check**, reconciled with
the operation-level sites, and each of the 428 contexts where they disagree (a token that is both a
raw read/write and a method call) is a recorded residual. The `MS-SOURCE-CENSUS` court re-derives
each context's operations from the shipped source and **fails a census that fuses two operations
into one site**, and its sensitivity control seeds exactly that fusion -- with the context's
`site_ids` edited to match -- among its six mutations. The correction changed the site ids, so every
dependent plane (25.3 through 25.8) and the 25.2 non-Rust TCB that cross-references the FFI site ids
were re-derived.

**25.1 recorded a second such correction, and it is checked rather than asserted.** The census and
its seven derived measurement artefacts were written one JSON object per record, so a file path, a
module, a kind, a method and a compiler clause were repeated on every record: `source-census.json`
was 120 MB, the seven Phase-25 artefacts were 267 MB together, and GitHub's pre-receive hook -- which
refuses any file over 100 MB -- refused the commit. The encoding was the whole cost and the
evidence was not: every artefact is now stored in a **lossless, deterministic, self-describing
columnar form** (`forensics/tools/ms_codec.py`, named by `body.encoding = "ms-columnar-v1"`), where
each repeated string is stored once in a `tables` block and each record is a short array of indices
and integers; the census strips the fields that re-derive from the committed source (`site_id`,
`context_id`, `module`, `line`, `column` and `span` are functions of `(file, byte_start, byte_end,
kind)` and the committed bytes) and rebuilds them on decode, and every derived plane references the
census's ordered site/context ids by index rather than repeating them. `decode(encode(view)) ==
view` for every artefact, so no count, id, ordering or finding is lost -- only its spelling on disk
changes -- and each writer and its court decode through the one codec. **The plan records the size
budget as a correction: `artifacts/phase25/source-census.json` must stay under a committed budget of
20 MiB** (comfortably under the 100 MB hook; the columnar census is ~10.5 MiB), and the
`MS-SOURCE-CENSUS` court **fails** when the committed file exceeds it, so this cannot recur silently.
The correction is checked by the subphases' courts rather than asserted: each court re-derives every
invariant from the decoded view, and the census court additionally enforces the budget (`docs/
PHASE-25-MEMORY-SAFETY-SUBPHASES.md` sections 3.2, 4).

**25.8 records the safe-core reconstruction, and it is checked rather than asserted.** The landed
25.8 first published only the reduction worklist and applied **zero** reductions, reasoning that the
reachable unsafe is the ABI contract. That is true of the reachable *boundary* sites, but it is not
the whole of the unsafe TCB: `src/runtime/sparse_array.rs` held a genuinely **internal** unsafe
mechanism -- a sixteen-way tree of raw `*mut *mut c_void` nodes reached by pointer arithmetic,
raw dereferences and a `transmute` trampoline -- whose internals no public OpenSSL ABI symbol
depends on. 25.8 reconstructs it as an owned `enum Node` whose children are `Box`es and whose
deepest slots are the caller's values, with every descent, growth and walk written as safe
indexing/recursion; the three observable fields (`levels`, `top`, `nelem`) and every entry-point
signature are unchanged. Every removed operation is classified `ELIMINATED` (the operation is gone
from the census) or `RELOCATED_TO_BOUNDARY` (it survives only in a thin wrapper whose whole body is
the opaque-handle dereference, the caller's leaf call and the header release), never `HIDDEN`. The
committed declaration `forensics/memory-safety/unsafe-reconstruction.json` names each removed site
and its class; `ms_reduction.py` re-derives the before count as `after + the ELIMINATED set`, checks
each removed site is absent from the live census and every relocation has a remaining boundary
operation of its kind, and re-reads the Phase-24 downstream headline from the committed measurement
and requires it unchanged. The reconstruction removed 50 net operations from the crate (subsystem
212 -> 162 sites; crate 172122 -> 172072, the re-derived counts of the operation-granular census),
and the `MS-UNSAFE-REDUCTION` court refuses a `HIDDEN`
claim, a still-present "removed" site, a typed count, a changed downstream verdict and a weakened
lint (fifteen seeded mutations, each caught with specificity holding, including a count increase
labelled a reduction and a dropped negative result). The census and every dependent
plane (25.3 through 25.7) and the 25.2 non-Rust TCB were re-derived from the modified tree in the
same commit.

**25.8 also records a measured negative result and the metric axis it taught, and the court checks
both.** A conversion of the **EVP operation cache** -- `EVP_PKEY::operation_cache`, the per-key
`STACK_OF(OP_CACHE_ELEM)` -- was implemented, built and differentially tested against OpenSSL
3.6.4: every behavioural field matched (install, push_ret, the find vector, clear_ret and the
failure-injection block), and only the internal container allocation representation diverged. But
the compiler census showed it is **not a reduction**: the subsystem rose 287 -> 313 operation sites
(+26) and the crate 172072 -> 172139 (+67), because the owned representation adds the allocator
seam, `Deref`/`Drop`, slice construction and a required re-entrancy test, while a linear cache has
almost no interior unsafe to eliminate. It was reverted, and is recorded in an
`attempted_conversions` list with the verdict `REVERTED_NOT_A_REDUCTION`, its measured before/after
counts, the differential outcome, the classification in the closed vocabulary (ELIMINATED /
RELOCATED_TO_BOUNDARY / HIDDEN=0) and a precise obstruction -- rather than omitted or labelled a
reduction. The record also states the campaign's **axis** explicitly: a conversion is judged on (a)
dangerous operations ELIMINATED, (b) a smaller, auditable residual boundary, and (c) HIDDEN=0, so a
conversion that replaces a large unsafe interior with a small explicit boundary can be
architecturally safer even when its raw site count rises -- **and** a net site-count increase is
still never labelled a reduction, the two facts stated side by side and never conflated. The
`MS-UNSAFE-REDUCTION` court refuses a record that conflates the two or that drops the negative
result. The next target is sized, not claimed: the **X.509 policy tree**
(`src/x509/pcy_{tree,cache,node,lib,data}.rs`), whose measured interior is 649 census operations (246
raw node dereferences and 124 unsafe method calls over a self-contained policy graph, with only
eleven exported accessors), is recorded as a campaign worklist entry -- a plan whose attempt must
itself net-reduce or be recorded `REVERTED_NOT_A_REDUCTION`, not a claim that it will.

**25.10 records the ASan environment's one deviation from the court's `exec`, and it is checked
rather than asserted.** The court's OOM guard applies a hard per-process `RLIMIT_DATA` (default
4 GiB) to every `exec`, and AddressSanitizer reserves a ~15.4 TB sparse shadow before it instruments
anything, so an ASan binary cannot *start* under that cap. The court's cap is kept for the hostile
courts (`docs/DECISIONS.md` D105); rather than weaken it, 25.10 records the ASan environment as a
**derivation of the admitted court venue** -- the same admitted image (`openssl-rs-court:1`) executed
with the venue's own documented `OPENSSL_RS_COURT_DATA` override, which removes *only* that
per-process virtual-space cap. Every bound that bounds resident resources -- the container cgroup
memory cap, PIDs, CPUs, the wall clock and `no-new-privileges` -- is unchanged, because ASan's shadow
is `PROT_NONE` + `MAP_NORESERVE` virtual address space the cgroup does not count as resident. This is
the same derivation the Phase-18 ASan venue records for the same reason. The venue, the canary and
the crate-level state (`ASAN_RAN` or `ASAN_UNSUPPORTED`) are recorded in
`artifacts/phase25/asan-msan.json` and in the venue manifest's `environment_derivations`, and the
`MS-ASAN-MSMAN` court re-runs the plane's pure checks over the committed evidence; the recorded
per-site states are ASAN_PASS / ASAN_FAIL / ASAN_NOT_REACHABLE / ASAN_UNSUPPORTED, and an
`UNSUPPORTED` site is never a pass.

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
