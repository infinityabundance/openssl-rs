# A26 receipt — verification economics: measured, stated, and bounded

## 1. Identity of this batch

| field | value |
|---|---|
| item | A26 (verification economics: measure what verification costs on a stated machine, declare a budget, and refuse to let cost become a reason to skip a required check) |
| branch | `staging` |
| HEAD at the start | `46f3857722e1a79c0756e7d1b495782aac259687` (`a25: re-derive the surface after the repair and freeze its identity`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 32 6 0 6 13` (available **13** GiB); `Swap: 45 40 5` |
| `free -g` before the final suite | `Mem: 45 31 7 0 7 13` (available **13** GiB); `Swap: 45 43 2` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), cgroup `memory.max` `6442450944`, CPU quota **8 cores** (`cpu.max = 800000 100000`), repository at `/work`; reused, not restarted |
| interpreter in the court | CPython **3.11.2** |
| host CPU model | not read; recorded as `null` rather than invented |
| heavy commands | one at a time; no Rust build |

The host had 13 GiB available before the work and 13 GiB before the final suite,
below the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed —
every measurement and gate is Python — and the derived cap would be negative,
below the 2 GiB floor, so **no new court was started**. The already-running 6 GiB
court was reused and every command ran inside it.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/verification_economics.py` | 1,262 | the implementation: `measure` (wall/CPU/peak RSS via `os.wait4`), `record_from`, `not_run`, `machine` (cgroup memory/CPU quota and interpreter, host CPU model `null`), `record_problems`, `validate_records`, `budget`, `report`, `build_controls`; CLI `measure`, `report`, `budget`, exit 0/1/2, always printing `code=...`; 13 stable refusal codes |
| `forensics/tools/tests/test_verification_economics.py` | 424 | 43 controls: one per refusal code, the unit rule, the machine rule, the waiver rules, a `NOT_RUN` not recorded as zero, cache identity, two-point derivation, staleness, the real measurements, the producer's reproduction, the command line, document synchronisation |
| `docs/VERIFICATION-ECONOMICS.md` | 298 | the normative document: cost as a resource; the record and the machine rule; the units; the budget and the waiver rule; reuse under a freshness identity; what may not be concluded; the real measurements; the controls; the full refusal table; `NOT_RUN` |
| `evidence/a26/build_evidence.py` | 149 | deterministic producer: takes `MEASUREMENTS.json` and `POLICY.json` as inputs, validates, runs the controls, writes the three records, exits nonzero on any disagreement |
| `evidence/a26/measure.py` | 202 | the measurement harness; re-running it re-measures and changes the timings |
| `evidence/a26/POLICY.json` | 54 | the declared budget per tier and total, the units, the candidate, and the declared basis |
| `evidence/a26/MEASUREMENTS.json` | 437 | the measured input: 11 records (8 `MEASURED`, 3 `NOT_RUN`), each with its machine, method, time and citation |
| `evidence/a26/COSTS.json` | 448 | the published cost record, produced from the measurements |
| `evidence/a26/BUDGET.json` | 177 | the measured totals against the declared budget, every tier and the total |
| `evidence/a26/CONTROLS.json` | 161 | 13 `controlOnly` rows, one per refusal code; `coversEveryCode` true, `failing` empty |
| `docs/ETP-TODO.md` | 1 row | the A26 row replaced from `TODO`; no other row touched |
| `evidence/a26/RECEIPT.md` | this file | the receipt |

Content digests (SHA-256, full):

| file | sha256 |
|---|---|
| `verification_economics.py` | `6741a13e0ae2886656de5559587c1f14f9d1f60f88f725ebd6d0cecb2ad57f1e` |
| `test_verification_economics.py` | `769beb18cb5684c84b32330bb8c290b4ff53980f06993f9245847ba964d54061` |
| `VERIFICATION-ECONOMICS.md` | `5defb6327b8cefe636fdd4ea471d50d19b242d1d0cff1b70f2bd363811e02be9` |
| `build_evidence.py` | `1bdd21fb4a5eaca00096f0ff034271ced9b0fa10a16842e11d2b53a4e5d9c757` |
| `measure.py` | `56621d8ff9f74e1975c9a6243742f3ca0c035f343cc51ed6120566c0c6668e1b` |
| `POLICY.json` | `e19e5d9085cd2498c094d12f4148cfb0a9d751c94baad618d846f35418292985` |
| `MEASUREMENTS.json` | `5311f0b8a61a8300b19dfde15c059d7406d5803c879d7a8a3b03e23b04afca9b` |
| `COSTS.json` | `46472eadff27622ec1dba8d525022dfb053cfb928460a7d1155f126581ec64e9` |
| `BUDGET.json` | `5dc8a868f1712df8a536c629ffd63823277443676f82aa63ec3424f42d2a8ab6` |
| `CONTROLS.json` | `09e9551930038899244f2069dbf1d091ce60770b554b777d1930267b0b9da39a` |

`COSTS.json`, `BUDGET.json` and `CONTROLS.json` name the producer and the tool by
digest, so an edit to either invalidates them until the producer is re-run.
`MEASUREMENTS.json` and `POLICY.json` are inputs and carry no producer stamp.

## 3. The rule

> **A cost is a measurement of a resource on a stated machine. It is never a
> reason to skip a required check, and a figure without a measurement behind it
> is not evidence.**

Five consequences are mechanical:

1. a required check is measured or recorded `NOT_RUN` with the reason it did not
   run — never dropped because it is expensive (`EC_REFUSED_SKIP_AS_SAVING`);
2. a figure with no numeric reading and no citation is refused
   (`EC_REFUSED_UNCITED_COST`);
3. every record carries its machine, read from the live cgroup, and a host CPU
   model that cannot be read is `null` (`EC_REFUSED_MACHINE_UNSTATED`);
4. a tier over its declared bound is `OVER` with the excess
   (`EC_REFUSED_BUDGET_OVER`);
5. a waiver is a recorded fact with `authorising: false`; there is no authority
   to grant one, so a waiver that authorises is refused
   (`EC_REFUSED_WAIVER_AS_AUTHORITY`).

Units are fixed by the field name: `wallSeconds` and `cpuSeconds` are seconds,
`peakRssMiB` is mebibytes, `artefactsBytes` is bytes. A record declaring
milliseconds or megabytes is refused (`EC_REFUSED_UNIT_MISMATCH`), as is a
renamed field (`wallMs`). A unavailable reading is `null` with a reason in
`unavailable`, never a number. A `NOT_RUN` record has null cost fields and is
never zero (`EC_REFUSED_NOT_RUN_AS_ZERO`). Reuse requires the complete five-field
identity (`EC_REFUSED_CACHE_UNBOUND`); a derived figure needs at least two
measured points (`EC_REFUSED_EXTRAPOLATION`); a record measured at another
candidate is refused (`EC_REFUSED_STALE_MEASUREMENT`).

The declared budget is in `evidence/a26/POLICY.json`: FAST 120 s / 512 MiB,
BATCH 1,800 s / 2,048 MiB / 64 MiB artefacts, BOUNDARY 600 s / 2,048 MiB,
SEAL 7,200 s / 4,096 MiB, EXTERNAL 3,600 s / 2,048 MiB, TOTAL 10,800 s /
4,096 MiB. It was declared before the measurements with headroom, not fitted to
the result. **No waiver is declared and none can be granted.**

## 4. The measured table

Taken **2026-11-24** in the reused court, one command at a time. Machine: image
`openssl-rs-court-tools:1`, container `openssl-rs-court`, 6 GiB cap
(`memory.max = 6442450944`), 8-core quota (`cpu.max = 800000 100000`), CPython
3.11.2; host CPU model not read.

| step | tier | wall (s) | CPU (s) | peak RSS (MiB) | artefacts (B) |
|---|---|---:|---:|---:|---:|
| `docs-consistency` | FAST | 0.060638 | 0.040735 | 21.578 | 0 |
| `spec-guard-check` | FAST | 0.663781 | 0.655551 | 27.246 | 0 |
| `a23-differential` | BATCH | 19.981104 | 19.948726 | 22.793 | 0 |
| `a8-export` | BATCH | 0.382215 | 0.368553 | 94.766 | 8,703,751 |
| `a8-export-verify` | BATCH | 0.161081 | 0.140973 | 105.137 | 0 |
| `tools-discovery` | BATCH | 425.062713 | 425.771105 | 289.820 | 0 |
| `a24-package-verify` | BOUNDARY | 47.798110 | 47.707580 | 28.285 | 0 |
| `a22-qualification-run` | BOUNDARY | 4.465221 | 4.552989 | 149.031 | 0 |

**Total: 498.574863 s wall, 499.186212 s CPU, 289.82 MiB peak, 8,703,751 B.**
BATCH is 445.587113 s wall of the total. The full tools discovery is
`python3 -m unittest discover -s forensics/tools/tests`.

**The refused gates, recorded `NOT_RUN` and not as zero:**

| step | tier | reason |
|---|---|---|
| `verify-all` | SEAL | includes rebuild and differential, which need a Rust build; `available` was below the 24 GiB floor and the court cap is 6 GiB |
| `rust-library-suite` | BATCH | the Rust library suite needs a build; `available` was below the 24 GiB floor and the court cap is 6 GiB |
| `external-reproduction` | EXTERNAL | no party outside this project has run the A24 package; A24 records `EXTERNAL_REVIEW_PENDING` |

**Budget result: `UNDER`.** Every tier and the total are within their declared
bounds; no waiver is declared; `codes=EC_OK`. Exact numbers are in
`evidence/a26/BUDGET.json`.

## 5. The controls

`evidence/a26/CONTROLS.json` holds **13 `controlOnly` rows, one per refusal
code**, `coversEveryCode` true, `failing` empty. Each row mutates a record, a
policy or an invocation in memory and asserts the exact code that fires. The
required wrong conclusions are present: a skipped required check, an unbound
cache reuse, a single-point extrapolation, a `NOT_RUN` recorded as zero, and a
waiver presented as permission. Positive controls establish that the procedure
can accept an uncited-free record with a numeric reading, a two-point derived
figure, and a complete reuse identity.

| control | code observed |
|---|---|
| `machine-unstated` | `EC_REFUSED_MACHINE_UNSTATED` |
| `uncited-cost` | `EC_REFUSED_UNCITED_COST` |
| `unit-mismatch` | `EC_REFUSED_UNIT_MISMATCH` |
| `skip-as-saving` | `EC_REFUSED_SKIP_AS_SAVING` |
| `cache-unbound` | `EC_REFUSED_CACHE_UNBOUND` |
| `single-point-extrapolation` | `EC_REFUSED_EXTRAPOLATION` |
| `budget-over` | `EC_REFUSED_BUDGET_OVER` |
| `waiver-unrecorded` | `EC_REFUSED_WAIVER_UNRECORDED` |
| `waiver-as-authority` | `EC_REFUSED_WAIVER_AS_AUTHORITY` |
| `not-run-as-zero` | `EC_REFUSED_NOT_RUN_AS_ZERO` |
| `stale-measurement` | `EC_REFUSED_STALE_MEASUREMENT` |
| `record-invalid` | `EC_REFUSED_RECORD_INVALID` |
| `malformed-invocation` | `EC_REFUSED_USAGE` |

`forensics/tools/tests/test_verification_economics.py` runs **43 tests**, all
passing, including a per-code control, the unit rule, the machine rule, the
waiver rules, the not-run rule, the real measurements, the producer's
reproduction and the command line.

## 6. Defects found

**Existing records:** **none.** No gate rejected an existing record, no check was
relaxed, no expected value was changed, and no other item's tool or evidence was
modified.

**Development defects in this item's own machinery** (recorded because a control
that passes for the wrong reason is the defect this item exists to catch):

* The first `malformed-invocation` control searched stdout for `code=…` while the
  tool prints `codes=…`, so the observed code list was empty and the control did
  not fire. The control now searches for the code token itself; the refusal was
  not changed.
* The first document test selected every line containing "enforced by", including
  the table header and a prose sentence, so it could never pass. It now selects
  the refusal table's data rows and requires the enforced-by cell to name a test
  or a control.
* The first `a8-export-verify` record cited `/tmp/a26-a8-export/MANIFEST.json`, a
  transient path that does not survive the container. It was re-measured with a
  durable citation to the committed `evidence/a8/MANIFEST.json` and
  `evidence/a8/SHARD-000.sarif`; the earlier record is superseded, not erased.
* The producer's first run reported `records=10`; after the discovery measurement
  was added it reports `records=11`. The earlier value is history, preserved in
  the measurement sequence, and the committed records are the 11-record form.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | `Mem: 45 31 7 0 7 13` (available 13 GiB); `Swap: 45 43 2` |
| 1. court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'`; cgroup | `6442450944 6442450944 running`; `memory.max 6442450944`; `cpu.max 800000 100000`; `Python 3.11.2` |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1886 tests in 422.865s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,843 pre-existing tests are present (1,843 + 43), none removed, none ignored |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on `COSTS`, `BUDGET`, `CONTROLS`, `MEASUREMENTS`, `POLICY` | all five: `json.tool ok` |
| 5. producer, twice | `python3 evidence/a26/build_evidence.py` twice in the court | both: `a26: candidate=46f3857722e1a79c0756e7d1b495782aac259687 records=11 measured=8 notRun=3 controls=13 codesCovered=13/13 failing=0 overall=UNDER codes=NONE`; `diff` before vs run 1: `identical`; run 1 vs run 2: `identical` |
| 6. report | `python3 forensics/tools/verification_economics.py report --records evidence/a26/COSTS.json --policy evidence/a26/POLICY.json` | every tier `UNDER`; `overall=UNDER`; `codes=EC_OK`; `REPORT_EXIT=0` |
| 6. budget | `python3 forensics/tools/verification_economics.py budget --records evidence/a26/COSTS.json --policy evidence/a26/POLICY.json` | `FAST UNDER wall=0.724419s …`, `BATCH UNDER wall=445.587113s …`, `BOUNDARY UNDER wall=52.263331s …`, `SEAL UNDER wall=0s …`, `EXTERNAL UNDER wall=0s …`, `TOTAL UNDER wall=498.574863s cpu=499.186212s rss=289.82MiB artefacts=8703751B`; `overall=UNDER`; `codes=EC_OK`; `BUDGET_EXIT=0` |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; exit 0 |
| 8. worktree | `git --no-pager status --porcelain` | see below |

Gate 5's byte identity is of the *record*: two producer runs reproduce the same
bytes because the timings are inputs. The timings themselves are a measurement
at a named time, not a deterministic artefact; re-running `measure.py` changes
them.

After gate 2 ran, the A26 row's prose was corrected once (it said "two
development defects" where the receipt records three development corrections).
That is a documentation-only edit to `docs/ETP-TODO.md`; the only pinned consumer
of that file is `spec_guard.py`, and `python3 forensics/tools/spec_guard.py check`
and `python3 -m unittest forensics.tools.tests.test_spec_guard` (`Ran 17 tests …
OK`) were re-run after the edit and pass. No measured command, record or test
input changed.

## 8. Obligations retained

* **A cost on this machine is not a cost on another.** Every figure is bound to
  the court named in §1 and is not claimed for another machine.
* **A not-run is not free.** `verify-all`, `rust-library-suite` and
  `external-reproduction` have no measured cost and are not counted as measured
  steps.
* **A green budget is not a green verification.** `UNDER` is a resource result on
  its own axis; it says nothing about whether any check is meaningful, correct or
  complete.
* **A waiver is not a pass.** No waiver is declared, and the mechanism refuses
  one that is presented as authority.
* **The measurement harness re-measures.** `measure.py` is a harness, not a
  deterministic generator; only `build_evidence.py` is byte-stable.
* **The description's "sign immutable manifests rather than every report" clause
  is not re-implemented here.** A10 and A17 own DSSE signing and the forward
  freeze; this item cites them rather than duplicating a second signing scheme.

## 9. `NOT_RUN`

* `verify all` and the Rust library suite: no build was run, because available
  memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a build and the
  court is capped at 6 GiB. Both are recorded `NOT_RUN` with the reason.
* External reproduction of the A24 package by a party in a distinct trust domain.
  A24 records `EXTERNAL_REVIEW_PENDING`; this item does not change that status.
* A measurement on a second machine.
* A full re-measurement after every change: the cost record is bound to a named
  candidate and time.
* A BOUNDARY audit, a SEAL, and any Rust result (no `src/` file was modified).

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A26 member:

* **satisfied:** `a26-receipt` — `evidence/a26/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

The freeze remains `state: OPEN`; it was not amended and not closed, and this
receipt claims no other member.

`git --no-pager status --porcelain` at the end of this batch:

```
M docs/ETP-TODO.md
?? docs/VERIFICATION-ECONOMICS.md
?? evidence/a26/
?? forensics/tools/tests/test_verification_economics.py
?? forensics/tools/verification_economics.py
```
