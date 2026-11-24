# Verification economics — what verification costs, and why cost is not an argument

> **A cost is a measurement of a resource on a stated machine. It is never a
> reason to skip a required check, and a figure without a measurement behind it
> is not evidence.** This document states the rule, the record that carries a
> measurement, the units, the budget and the one thing a waiver may be, and the
> conclusions that may not be drawn from any of it.

The item is A26 in `docs/ETP-TODO.md`. The implementation is
`forensics/tools/verification_economics.py`; the controls are
`forensics/tools/tests/test_verification_economics.py`; the measurements are
`evidence/a26/MEASUREMENTS.json`, and the records produced from them are
`evidence/a26/COSTS.json`, `evidence/a26/BUDGET.json` and
`evidence/a26/CONTROLS.json`, written by `evidence/a26/build_evidence.py`.

## 1. Why cost is a resource and not an argument

Verification is work: it consumes wall-clock time, CPU time, memory and disk.
Recording that cost is what makes the verification programme affordable to plan
and honest to describe. But a cost recorded in the same breath as a verdict
invites a false inference — *this check is expensive, therefore it may be
skipped, or counted as passed, or replaced by a cheaper check that is not the
same check*. The rule that prevents it is small:

1. **A check is required or it is not; its cost does not change that.** A
   required check that is too expensive is recorded `NOT_RUN` with the reason it
   did not run, never dropped because the budget is tight.
2. **A figure with no measurement is not a figure.** It is either measured, or
   cited to a measurement, or it is refused.
3. **A measurement belongs to the machine that produced it.** It cannot be
   moved to a different machine without saying so.
4. **A budget is a declared bound, not a target that shrinks when a check is
   inconvenient.** Exceeding it is reported with the excess.
5. **A waiver is a recorded fact, never permission.** There is no authority in
   this project that can grant one; A14 records none.

Enforced by `EC_REFUSED_SKIP_AS_SAVING` and `EC_REFUSED_UNCITED_COST`
(`test_a_required_check_skipped_for_cost_is_refused` and
`test_an_uncited_cost_is_refused`, and the `skip-as-saving` and `uncited-cost`
rows of `evidence/a26/CONTROLS.json`).

## 2. The cost record and the machine rule

One record per verification step:

```json
{
  "step": "a23-differential",
  "tier": "BATCH",
  "wallSeconds": 19.98,
  "cpuSeconds": 19.95,
  "peakRssMiB": 22.79,
  "artefactsBytes": 0,
  "machine": {
    "identifier": "openssl-rs-court-tools:1 (container openssl-rs-court)",
    "cores": 8,
    "memGiB": 6.0,
    "interpreter": "CPython 3.11.2",
    "courtMemCapGiB": 6.0
  },
  "method": "os.wait4 ...",
  "measuredAt": "2026-11-24T...Z",
  "citedBy": ["forensics/tools/verifier_formalisation.py"],
  "status": "MEASURED",
  "candidate": "46f3857722e1a79c0756e7d1b495782aac259687",
  "units": {"wallSeconds": "s", "cpuSeconds": "s", "peakRssMiB": "MiB", "artefactsBytes": "bytes"}
}
```

**The machine must be populated.** Every record carries the identifier of the
venue, its core count, its memory, the interpreter and the court's memory cap. A
record whose `machine` is empty or missing one of those fields is refused: a
figure from an unstated machine cannot be compared with another, and a cost
measured on one machine does not transfer to another without saying so. The
machine is read, never guessed: the memory ceiling comes from
`/sys/fs/cgroup/memory.max`, the core count from the `cpu.max` quota, the
interpreter from the running Python, and the image identity is supplied by the
caller that started the court. A host CPU model is not readable from inside the
container and is therefore recorded as `null`, not invented.

Enforced by `EC_REFUSED_MACHINE_UNSTATED` (`test_a_cost_without_its_machine_is_refused`,
`test_a_machine_missing_one_field_is_refused`).

**A reading that cannot be taken is `null` with a reason.** `verification_economics.py`
observes wall, child CPU and peak RSS together with `os.wait4`, so the peak
resident set is the child's own. If a reading is unavailable, the field is
`null` and the reason is in `unavailable`; an invented number is a refusal.

**A `NOT_RUN` record is a different state with its own discipline.** Its cost
fields are `null`, it carries `notRunReason`, and it is never a zero. A check
that did not run is not free and is not a measured zero.

Enforced by `EC_REFUSED_NOT_RUN_AS_ZERO` (`test_a_not_run_recorded_as_zero_is_refused`,
`test_a_not_run_counted_as_zero_is_refused`).

**A stale measurement is refused.** Each record names the candidate it measured.
When a report or a budget is about candidate `X`, a record measured at candidate
`Y` is refused rather than silently included: the number does not describe `X`.

Enforced by `EC_REFUSED_STALE_MEASUREMENT` (`test_a_cost_from_another_candidate_is_refused`).

## 3. Units

The unit is part of the field name and is not negotiable:

| field | unit | meaning |
|---|---|---|
| `wallSeconds` | seconds | monotonic elapsed time of the command |
| `cpuSeconds` | seconds | the child's `ru_utime + ru_stime` |
| `peakRssMiB` | mebibytes | the child's `ru_maxrss / 1024` |
| `artefactsBytes` | bytes | the size of the artefacts the step produced |

A record that declares another unit (`wallSeconds: "ms"`, `peakRssMiB: "MB"`) is
refused, and a record that renames a field to `wallMs` or `peakRssMB` is refused.
Fifty milliseconds is not 50 seconds and a megabyte is not a mebibyte; a silently
converted figure is a different number wearing this one's name.

Enforced by `EC_REFUSED_UNIT_MISMATCH` (`test_milliseconds_declared_for_seconds_is_refused`,
`test_mebibytes_against_megabytes_is_refused`, `test_a_millisecond_named_field_is_refused`).

## 4. The budget and the waiver rule

A budget is declared per tier and in total, in the same units, in
`evidence/a26/POLICY.json`. `budget(records, policy)` sums the measured wall and
CPU, takes the maximum peak RSS, sums the artefact bytes, and compares each tier
and the total with its declared bound. A tier over its bound is `OVER` and
carries the excess; it is never `UNDER` because a waiver exists.

| tier | wall (s) | CPU (s) | peak RSS (MiB) | artefacts (bytes) |
|---|---:|---:|---:|---:|
| FAST | 120 | 120 | 512 | 1 048 576 |
| BATCH | 1 800 | 1 800 | 2 048 | 67 108 864 |
| BOUNDARY | 600 | 600 | 2 048 | 33 554 432 |
| SEAL | 7 200 | 7 200 | 4 096 | 4 294 967 296 |
| EXTERNAL | 3 600 | 3 600 | 2 048 | 1 073 741 824 |
| TOTAL | 10 800 | 10 800 | 4 096 | 4 294 967 296 |

The bounds were declared before the measurements were taken, with headroom
rather than fitted to the result: BATCH is about twice the observed full tools
discovery, so a slower machine or a larger suite is not silently a budget
failure. The policy records that basis.

**Over budget without a recorded waiver is a refusal** (`EC_REFUSED_BUDGET_OVER`).
**A waiver is allowed only as a recorded, non-authorising note.** It appears in
the record beside the `OVER`, it has `authorising: false`, and it does not change
the status, the excess or the overall result. There is no authority in this
project to grant a waiver — A14 records no declared identity that could — so a
waiver that names an authority, grants permission, or converts an `OVER` into a
pass is refused (`EC_REFUSED_WAIVER_AS_AUTHORITY`), and a waiver claimed without
being recorded is refused (`EC_REFUSED_WAIVER_UNRECORDED`). A recorded waiver is
a fact about a decision to proceed, not a licence to call the tier compliant.

Enforced by `EC_REFUSED_BUDGET_OVER`, `EC_REFUSED_WAIVER_UNRECORDED` and
`EC_REFUSED_WAIVER_AS_AUTHORITY` (`test_over_budget_without_a_waiver_is_refused`,
`test_a_recorded_waiver_is_a_fact_not_permission`,
`test_a_waiver_naming_an_authority_is_refused`, `test_an_unrecorded_waiver_is_refused`).

## 5. Reuse only under a freshness identity

Reuse is permitted — re-running an expensive check for an unchanged input is
waste — but only when the record is bound to an applicability identity: the
source, the tool, the instrument, the target and the population. This is the
same five-field identity the freshness and scheduling machinery already owns;
this item does not invent a second one. A record that says `reused` without the
complete identity is refused. A logical match does not authorise transfer of a
cost figure across candidates.

Enforced by `EC_REFUSED_CACHE_UNBOUND` (`test_reuse_without_an_identity_is_refused`,
with `test_reuse_with_the_complete_identity_is_accepted` as the positive control).

**One measured point is not a curve.** A figure for an unmeasured input derived
from a single measurement is refused; a derived figure needs at least two
measured points, and even then it is an interpolation over a stated domain, not
a general law.

Enforced by `EC_REFUSED_EXTRAPOLATION` (`test_one_point_is_not_a_curve`, with
`test_two_points_permit_a_derived_figure` as the positive control).

## 6. What may not be concluded

The records do not support any of the following, and this document does not claim
them:

* **A cost on this machine is not a cost on another.** The machine is recorded
  so a reader can see what the figure belongs to; it is not a licence to apply
  it elsewhere.
* **A not-run is not free.** It is absent, not zero, and the budget does not
  count it as a measured step.
* **One measured point does not give a curve.** A single reading of a suite says
  nothing about a different suite, a different input or a different candidate.
* **A green budget is not a green verification.** Being under the declared cost
  says nothing about whether a check is meaningful, correct or complete. It is a
  resource result, on its own axis.
* **A waiver is not a pass.** It is a recorded decision to proceed while `OVER`,
  and nothing more.
* **A timing is a measurement at a named time, not a deterministic artefact.**
  Re-running the harness changes the numbers; `build_evidence.py` reproduces the
  *records* from the measured values, not the values themselves.

## 7. The real measurements

Taken on **2026-11-24** in the already-running court, one command at a time.
Machine: image `openssl-rs-court-tools:1`, container `openssl-rs-court`, memory
cap **6 GiB** (`memory.max = 6442450944`), CPU quota **8 cores**
(`cpu.max = 800000 100000`), interpreter **CPython 3.11.2**. The host reported
`free -g`: `Mem: 45 32 6 0 6 13` (available **13 GiB**) and
`Swap: 45 40 5`; available was below the 24 GiB build floor, so the 6 GiB court
was reused and no build ran. The host CPU model is not read and is `null` in the
record.

| step | tier | wall (s) | CPU (s) | peak RSS (MiB) | artefacts (B) | machine |
|---|---|---:|---:|---:|---:|---|
| `docs-consistency` | FAST | 0.060638 | 0.040735 | 21.578 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `spec-guard-check` | FAST | 0.663781 | 0.655551 | 27.246 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `a23-differential` | BATCH | 19.981104 | 19.948726 | 22.793 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `a8-export` | BATCH | 0.382215 | 0.368553 | 94.766 | 8 703 751 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `a8-export-verify` | BATCH | 0.161081 | 0.140973 | 105.137 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `tools-discovery` | BATCH | 425.062713 | 425.771105 | 289.820 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `a24-package-verify` | BOUNDARY | 47.798110 | 47.707580 | 28.285 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |
| `a22-qualification-run` | BOUNDARY | 4.465221 | 4.552989 | 149.031 | 0 | court, 8 cores, 6 GiB, CPython 3.11.2 |

The full tools discovery (`tools-discovery`) is the whole
`python3 -m unittest discover -s forensics/tools/tests`. The three refused
gates are recorded, not omitted:

| step | tier | state | reason |
|---|---|---|---|
| `verify-all` | SEAL | `NOT_RUN` | includes rebuild and differential, which need a Rust build; `available` was below the 24 GiB floor and the court cap is 6 GiB |
| `rust-library-suite` | BATCH | `NOT_RUN` | the Rust library suite needs a build; `available` was below the 24 GiB floor and the court cap is 6 GiB |
| `external-reproduction` | EXTERNAL | `NOT_RUN` | no party outside this project has run the A24 package; A24 records `EXTERNAL_REVIEW_PENDING` |

**Budget result: `UNDER`.** The measured total across all eight measured steps is
**498.574863 s wall**, **499.186212 s CPU**, **289.82 MiB peak** and
**8 703 751 artefact bytes**; the BATCH tier is 445.587113 s of that wall and
all of the artefacts. The peak is the full tools discovery (289.82 MiB). Every
tier is within its declared bound and no waiver is declared. The exact totals
are in `evidence/a26/BUDGET.json`.

`COSTS.json` carries each record with its machine, method and citation;
`MEASUREMENTS.json` is the measured input. Re-running
`evidence/a26/build_evidence.py` reproduces `COSTS.json`, `BUDGET.json` and
`CONTROLS.json` byte for byte; re-running `evidence/a26/measure.py` re-measures
and will produce different timings, which is why the timings are recorded as
measurements at a named time rather than as a deterministic artefact.

## 8. The controls

`evidence/a26/CONTROLS.json` holds **13 `controlOnly` rows, one per refusal
code**, and `coversEveryCode` is true. Each row mutates a record, a policy or an
invocation in memory and asserts the exact code that fires; none is a shipped
configuration and none edits a source file. The required wrong conclusions are
present: a skipped required check, an unbound cache reuse, a single-point
extrapolation, a `NOT_RUN` recorded as zero, and a waiver presented as
permission. `forensics/tools/tests/test_verification_economics.py` also exercises
each rule individually, the positive controls that show the procedure can accept
a figure, the real measurements, the producer's reproduction and the command line.

## 9. The refusal table

Every code is stable and documented with the wrong conclusion it prevents. The
"enforced by" column names the test or the control row that establishes it.

| code | wrong conclusion it prevents | enforced by |
|---|---|---|
| `EC_REFUSED_UNCITED_COST` | a cost figure with no measurement and no citation would be read as evidence | `test_an_uncited_cost_is_refused`; control `uncited-cost` |
| `EC_REFUSED_MACHINE_UNSTATED` | a figure from an unstated machine would be compared with, or transferred to, another | `test_a_cost_without_its_machine_is_refused`; control `machine-unstated` |
| `EC_REFUSED_UNIT_MISMATCH` | a converted figure (ms for s, MB for MiB) would be read as this figure | `test_milliseconds_declared_for_seconds_is_refused`; control `unit-mismatch` |
| `EC_REFUSED_SKIP_AS_SAVING` | a required check omitted because it costs time would look like a scheduling choice | `test_a_required_check_skipped_for_cost_is_refused`; control `skip-as-saving` |
| `EC_REFUSED_CACHE_UNBOUND` | reuse without an applicability identity would present another check's result as this one's | `test_reuse_without_an_identity_is_refused`; control `cache-unbound` |
| `EC_REFUSED_EXTRAPOLATION` | one measured point would be presented as a curve for an unmeasured input | `test_one_point_is_not_a_curve`; control `single-point-extrapolation` |
| `EC_REFUSED_BUDGET_OVER` | an over-budget tier with no recorded waiver would be hidden | `test_over_budget_without_a_waiver_is_refused`; control `budget-over` |
| `EC_REFUSED_WAIVER_UNRECORDED` | an unrecorded exception would be indistinguishable from an omission | `test_an_unrecorded_waiver_is_refused`; control `waiver-unrecorded` |
| `EC_REFUSED_WAIVER_AS_AUTHORITY` | a waiver would be read as permission, though no authority can grant one | `test_a_waiver_naming_an_authority_is_refused`; control `waiver-as-authority` |
| `EC_REFUSED_NOT_RUN_AS_ZERO` | a check that did not run would be counted as costing nothing | `test_a_not_run_recorded_as_zero_is_refused`; control `not-run-as-zero` |
| `EC_REFUSED_STALE_MEASUREMENT` | a cost measured at another candidate would be presented as this candidate's | `test_a_cost_from_another_candidate_is_refused`; control `stale-measurement` |
| `EC_REFUSED_RECORD_INVALID` | a non-record would be read as a cost record, inventing fields | `test_a_record_whose_tier_is_unknown_is_refused`; control `record-invalid` |
| `EC_REFUSED_USAGE` | a malformed invocation would report a result | `test_a_usage_error_exits_two_and_prints_the_code`; control `malformed-invocation` |

The tool always prints `code=...`: `code=EC_OK` when nothing is refused, the
fired code otherwise, and `EC_REFUSED_USAGE` on a malformed command line. It
exits 0 when nothing is refused, 1 when a refusal or an `OVER` is reported, and
2 for a usage error.

## 10. `NOT_RUN`

* `verify all` and the Rust library suite: no build was run. The host reported
  `available` below the 24 GiB floor `AGENTS.md` §6.1 sets before a build, and
  the court is capped at 6 GiB. Both are recorded `NOT_RUN` with that reason and
  no cost, not zero.
* External reproduction of the A24 package by a party in a distinct trust
  domain. A24 records `EXTERNAL_REVIEW_PENDING`; this item does not change that
  status.
* A measurement on a second machine. Every figure here is bound to the court
  named above; none is claimed for another machine.
* A full re-measurement after every change. The cost record is a measurement at
  a named candidate and time, not a continuously regenerated artefact.
* A BOUNDARY audit, a SEAL and any Rust result: no `src/` file was modified by
  this item.
