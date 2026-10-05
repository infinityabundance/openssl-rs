# Phase 19 — the performance / CPU dispatch stratum, as subphases

## 0. What this stratum is, and what it is not

Phase 19 is the stratum `docs/RELEASE_GATES.md` §1 names "Performance / CPU dispatch". Like Phases
16 through 18 it owns **no exported symbol**: reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 19` yields nothing, because the declaring-header rule assigns no installed header
to this stratum. Its unit is therefore not a symbol. As with Phase 18 it **hands nothing forward
and receives nothing**: the implementation whose dispatch and arithmetic it measures is already the
one Phases 3 through 18 completed, so it adds no library surface and takes no unit or symbol
deferral from an earlier stratum.

What it owes is *performance-dispatch evidence over the finished implementation*, and that
evidence is about **dispatch behaviour and deterministic work** rather than about the authority's
throughput on this host. The four things it must produce, and the plan's subphases below are these:

* a **CPU-capability dispatch audit**: how the candidate's CPU-capability surface
  (`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`) reports under a fixed
  capability set, against the admitted authority, with an authority-linked differential control;
* an **EVP / cipher dispatch comparison**: which implementation a fetch or cipher context selects
  for a given capability set, against the authority over the same set, so the *selection* is
  compared rather than assumed;
* a **deterministic performance court**: work measures over the primitive paths — operation and
  block counts through the crate's own counters, **not wall-clock-only** — driven on the authority
  and the candidate over the same inputs, with a **sensitivity control** that a deliberately slowed
  path is caught; if the instrument cannot tell a slow path from a fast one it is `fail`;
* the **performance-boundary register**, recording what is measured, what is not, and the explicit
  non-claims.

It is **not** a benchmark, and it is not a parity claim. A passing performance court is a bounded
deterministic-work comparison at the resolution it declares; a passing dispatch court is a bounded
comparison of *selection* over the capability sets it drives; and a register entry is a record of a
boundary, not a guarantee about throughput. Two non-claims are named here and belong to every
subphase: **this stratum makes no benchmark-parity claim** (no throughput ratio to the authority is
asserted), and **it makes no assembly-versus-Rust equivalence claim** (the authority's per-CPU
assembly paths and the candidate's reduced implementations are not asserted to be the same work).
`docs/NON_CLAIMS.md` and `docs/SECURITY_DIVERGENCE_POLICY.md` are the authorities on what may be
said; a subphase that discovers its unit is somewhere else records that rather than forcing the row
(§4).

## 1. The measurement this plan rests on

Every number below is read from an atlas, not typed, and `forensics/phase19-obligations.json` is
authoritative for the present. The activation measurement was taken against `main` `86177a3f`
(openssl-rs 0.0.23, Phase 18 released).

**Phase 19 owns zero exports.** Reading `forensics/atlas/symbol-ownership.json` for
`owner_phase == 19` returns no record: the stratum's `atlas_owned` count is `0`, and the ledger
fails closed if that ever stops being true rather than silently counting a symbol through a
non-export unit.

**It receives zero provider registration rows.** Reading
`forensics/atlas/provider-algorithms.json` for `owning_phase == 19` gives no row: this stratum
activates no provider. The ledger fails closed if the census ever assigns it one.

**It receives zero unit deferrals and zero symbol deferrals.** Reading
`forensics/prerequisites.json` for `owner_phase == 19`: no `deferrals` row and no `units` row. (The
plane holds 152 unit records and one symbol deferral in total, all owned by earlier strata.) The
eighteen `forensics/phase*-obligations.json` files that exist record no hand-off owned by phase 19 —
the only `deferred` rows any earlier ledger carries point at phases 12 and 13 — so its working set
is entirely its own authored contract.

**The performance dispatch contract is five units**, each derived from the court that measures it:
`cpu-capability` (`RT-CPU-CAPABILITY`), `evp-dispatch` (`RT-EVP-DISPATCH`), `performance-work`
(`RT-PERFORMANCE-WORK`), `performance-sensitivity` (`RT-PERFORMANCE-SENSITIVITY`) and
`performance-boundary-register` (`PERFORMANCE-BOUNDARY-REGISTER`). At activation the runner
registers all five as `pending`, so all five units are open.

**A passing performance court is a measurement result, not a property claim, and the ledger records
the two axes separately.** Each contract unit carries `measurement_state` (the instrument ran and
its control was honest) beside `property_status` and `findings` (what, if anything, the unit claims
about performance). `performance-work` is the unit where the two diverge: `RT-PERFORMANCE-WORK`
passes while recording every path whose deterministic work differs from the authority's as a
`finding`, so the property reads `NOT_CLAIMED` with `findings_present`. **A passing
`RT-PERFORMANCE-WORK` must never be read as "performance parity achieved".** The findings are read
from the court row rather than typed, and `forensics/phase19-obligations.json` carries both axes for
every unit.

**The ledger's unit is not an exported symbol.** `forensics/phase19-obligations.json` publishes
`unit: "performance dispatch contract"`, its `implemented`/`open` export lists are empty *by
measurement*, and its working set is counted in `open_in_this_stratum` over the five contract units.
`atlas_common.NON_EXPORT_UNITS` names the unit, so the two tools that partition the export universe
(`court_coverage.py`, `ownership_audit.py`) skip this ledger rather than reconcile a symbol set that
does not exist.

**Phase 19 begins on nothing of its own.** No performance or dispatch court exists at activation,
so `open_in_this_stratum` opens at the whole working set (five) and moves only as the subphases
below land. **That split moves as the stratum lands its own units: the ledger's `counts` is the live
record and this section is the activation measurement.**

## 2. The subphases

| # | Subphase | Owns | Depends on | Courts |
|---|---|---|---|---|
| 19.0 | **The plan and the ledger** | `docs/PHASE-19-SUBPHASES.md` and the measurement in §1. The ledger (`forensics/phase19-obligations.json`) and its generator land with it, together with the runner `forensics/tools/phase19_courts.py` and the registry it writes. **The runner cannot be deferred**: `run_courts.py` refuses a stratum in `in-progress` with no runner, and this stratum's obligations are not exports, so its first runnable court is a later subphase's. | 18 | — |
| 19.1 | **The CPU-capability dispatch audit** | the capability-set driver over the CPU-capability surface -- the ia32cap array words and the reachability of the cpuid units the authority defines, none of which the reduced candidate implements and whose not-reached disposition `RT-CPU-CAPABILITY` records -- and its report under fixed synthetic `OPENSSL_ia32cap` literals (so the record is runner-independent; the raw cpuid vector's return is not recorded because it is the runner's own CPUID), against the admitted authority, with an authority-linked differential control. | 19.0 | `RT-CPU-CAPABILITY` |
| 19.2 | **The EVP / cipher dispatch comparison** | the selection surface: which implementation a fetch or a cipher context selects for a given capability set, driven on both sides over the same set, with an authority-linked differential control. | 19.1 | `RT-EVP-DISPATCH` |
| 19.3 | **The deterministic work court** | work measures over the primitive-bearing paths — operation and block counts through the crate's own counters, **not wall-clock-only** — driven on the authority and the candidate over the same inputs, recording every path whose work differs as a finding. | 19.0 | `RT-PERFORMANCE-WORK` |
| 19.4 | **The sensitivity court** | the instrument-sensitivity control: a deliberately slowed path must be caught, so a court whose measure cannot tell a slow path from a fast one is `fail` rather than `pass`. Candidate-only, in the shape Phases 8 and 18 use for a `CT-*`-style control. | 19.3 | `RT-PERFORMANCE-SENSITIVITY` |
| 19.5 | **The performance-boundary register** | the register that records what is measured, what is not, and the explicit non-claims — no benchmark-parity claim, no assembly-versus-Rust equivalence claim — and that fails the stratum if a recorded boundary drifts from its evidence. | 19.1–19.4 | `PERFORMANCE-BOUNDARY-REGISTER` |
| 19.6 | **The seal** | nothing in the crate — evidence: `docs/PHASE-19-PERFORMANCE-SEAL.md` (at the seal) | 19.0–19.5 | — |

The rows above the seal partition the working set by source: each subphase row lands the instrument
for exactly one of the five contract units. The partition is derived from
`forensics/phase19-obligations.json` joined to `artifacts/phase19/COURTS.json`, not typed.

## 3. What each subphase must honour

**3.1 A performance court is bounded to its measured paths, and it says so.** A passing
`RT-PERFORMANCE-WORK` says the instrument ran over the paths it names and produced the observations
it recorded, not that the candidate is as fast as the authority everywhere. The path list, its
inputs and the work counter each path uses are recorded in the court's row, and a path the court
does not reach is named `pending` rather than counted as passing (§3.5).

**3.2 The differential control keeps the expectation honest, and the sensitivity control keeps it
from being vacuous.** Where a surface has an authority behaviour — capability report, dispatch
selection, deterministic work count — the authority and the candidate are driven over the same
input and the two observations are compared, so a value cannot be invented. Because the work
counter is an instrument the stratum introduces, `RT-PERFORMANCE-SENSITIVITY` additionally drives a
**deliberately slowed path** and requires it to be caught; a control that cannot fail is not
evidence. The sensitivity court's verdict is about the instrument's resolution, so it passes with
`measurement_state: complete` while making no throughput claim, and `RT-PERFORMANCE-WORK` records
its divergences as findings with `property_status: NOT_CLAIMED`.

**3.3 Work is measured deterministically; wall clock is at most a recorded cross-check.**
`RT-PERFORMANCE-WORK` counts the work the crate performs — operation counts, block counts, inner-loop
iterations through the crate's own counters — because a wall-clock measurement on a shared host is
not reproducible and would make the court's verdict a function of the machine. Where a wall-clock
figure is recorded at all it is recorded as an observation with its bound, and **no verdict is ever
taken from it alone**; a court that could only pass or fail on elapsed time is the failure mode this
rule removes.

**3.4 The dispatch audit names the capability set and the façade it drives.** 19.1 and 19.2's
subject is what the candidate *reports* and *selects* under a given CPU-capability set, so the set is
fixed and recorded, and a surface the set does not reach is recorded rather than assumed. A
capability the reduced engine deliberately does not implement is a recorded disposition, not a
silently substituted one.

**3.5 The register is the stratum's own non-claims, and it is mechanical.** 19.5 records, per
surface, whether it is *measured* (a passing court covers it) or *not claimed* (explicitly outside
this stratum — including **benchmark parity** and **assembly-versus-Rust equivalence**), and the
`PERFORMANCE-BOUNDARY-REGISTER` court fails the stratum if a recorded boundary drifts from the
evidence that establishes it. It is the stratum's answer to `docs/NON_CLAIMS.md`, and it may not
claim more than the courts above measured.

**3.6 Nothing here is a throughput or parity claim about the library.** A passing performance court
is a bounded deterministic-work comparison, and a register entry is a record. `PARITY_VERIFIED` is
not claimed for any symbol by this stratum, and a name that cannot be driven is named `pending`
rather than counted as passing.

**3.7 The five units land in one ordered chain behind the runner.** 19.1 and 19.2 land the two
dispatch courts; 19.3 and 19.4 land the measurement and its sensitivity control; 19.5 lands the
register that binds them; each lands its code, its court and its regenerated artefacts in one
commit, and the ledger's `open_in_this_stratum` moves only when a court in
`artifacts/phase19/COURTS.json` passes.

## 4. Measured corrections, and the precondition

**4.1 The working set is not an export projection, and the ledger says so by its unit.** The atlas
gives this stratum zero exports, so `forensics/phase19-obligations.json` cannot be the export
projection Phases 3 through 15 publish. Its unit is `performance dispatch contract`, recorded in
`atlas_common.NON_EXPORT_UNITS` so that the export-partitioning tools skip it, exactly as Phase 16's
`cli-config contract`, Phase 17's `downstream replacement contract` and Phase 18's `hostile
hardening contract` are (D485). The ledger fails closed if the ownership atlas ever assigns this
stratum an export, if the provider census assigns it a registration row, or if the prerequisite
plane assigns it a deferral or a translation unit, because then the non-export unit would be the
wrong shape.

**4.2 The precondition this plan places on 19.0, and it is not optional.** `run_courts.py` refuses a
stratum that is not `not-started` and has no runner, so this stratum lands
`forensics/tools/phase19_courts.py` with **no runnable court**: its obligations are not exports, so
no differential probe over a symbol set is its evidence, and its five courts are named in
`PENDING_COURTS` and land with the subphases that build the instruments they drive. **The direction
of the `phase19_courts.py` <-> `phase19_obligations.py` edge is the reverse of Phase 16's**: the
ledger's contract-unit states are measured from the courts registry, so the registry is generated
first and `phase19_courts.py` does **not** bind the ledger as an input. A cycle in which each
embedded the other's digest would make neither reproducible. **No court is registered in
`gen_frf_courts.py`**: that registry is the stratum's seal. So the activation order is: the runner
and its pending registry, the ledger, and the plan land **together**, or `run_courts.py` fails and
the tree carries an activation whose runner is refused.

**4.3 "Performance" here is bounded evidence, not a benchmark.** Phase 18 *attacked* the candidate's
parsers and arithmetic; Phase 19 *measures* the candidate's dispatch behaviour and deterministic
work. The two are different strata and different planes, and this plan reconciles them by naming
which surface each contract unit is measured against rather than by widening the ownership table.
The non-claims this stratum carries are the register's, and the two that are load-bearing are named
in §0: **no benchmark-parity claim** and **no assembly-versus-Rust equivalence claim**. A
deterministic work count is a proxy for work, not for elapsed time, and this plan does not let the
proxy become the claim.

**4.4 The prerequisite plane is not this stratum's universe, and the plan says so.** No row of
`forensics/prerequisites.json` is owned by phase 19, so this plan names no prerequisite unit and
plan reconciliation has no unit of this stratum's to judge; a subphase that discovers its unit is
elsewhere records that rather than forcing a row (§0, §5).

**4.5 The plan named the authority's capability symbols as the candidate's surface, and the seal
corrected it (measured).** Row 19.1 originally wrote "the candidate's CPU-capability surface
(`OPENSSL_ia32cap_P`, `OPENSSL_cpuid_setup`, `OPENSSL_ia32_cpuid`)". Deriving Phase 19 `complete`
turned on `plan_reconciliation.py`'s `plan_named_symbol_not_reached` (P2) for the stratum, and it
reported all three: they are authority internals (of the legacy-DSO `cpuid` units) that the reduced
candidate builds nowhere -- `RT-CPU-CAPABILITY` records `probe.reachable.*=0` for each -- and no
deferral records them (there is no later implementation stratum the candidate's direct-CPUID model
defers them to) and no divergence covers them (the crate never references them, so a `covers` entry
would fail the prerequisite gate's direction D). The row now names the surface the driver drives
without promising crate symbols, and the three names are recorded as the not-reached disposition in
`artifacts/phase19/COURTS.json` and `docs/PHASE-19-PERFORMANCE-SEAL.md` §4. This is the one
reconciliation deriving `complete` forced; §0's and §1's prose still name the authority symbols,
which is where the surface belongs.

## 5. Process

This stratum inherits Phases 8 through 18's process unchanged: a subphase lands its code, its court
and its regenerated artefacts in **one commit**; every name a subphase lands carries a court edge
where it has one; and an artefact that a source change moves is regenerated in the same commit.
`docs/DECISIONS.md` is append-only and this document is not a decision record.

**This plan's own boundaries are the evidence plane's, and it will correct them.** The subphase
table above was written from the five-row measurement in §1. A subphase that discovers its unit is
elsewhere records that rather than forcing the row. The activation is recorded in
`docs/PHASE-19-SUBPHASES.md` itself and in `forensics/phase-state.json`.

**Landed exports (checked against the ledger):**

None. The ownership atlas assigns this stratum zero exports, so the clause binds nothing: the
ledger's implemented list is empty by measurement, not by omission.

**Open exports (checked against the ledger):**

None. This stratum owns no export, so its obligations are the five performance dispatch contract
units, recorded in the ledger's contract-unit block rather than as open exports.
