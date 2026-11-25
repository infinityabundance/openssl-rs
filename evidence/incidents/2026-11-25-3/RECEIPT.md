# Incident 2026-11-25-3 — the court OOM-killed the sigstore-bundle module

AGENTS.md §24. The full `forensics/tools/tests/test_sigstore_bundle.py` module
was run in the already-running court and the court's cgroup killed it at its
4 GiB memory limit. This receipt records the command, the measurements, the OOM
evidence, what was lost, and the reduced units that replaced it. It is written
by the batch that saw the incident; it is not a claim about the code under test.
It is the same venue limitation recorded in `evidence/incidents/2026-11-25-2`
(the module cannot complete under the 4 GiB cap because its producer test is the
peak).

## 1. The command and the venue

| field | value |
|---|---|
| command | `docker exec openssl-rs-court sh -lc 'cd /work && python3 -m unittest forensics.tools.tests.test_sigstore_bundle'` |
| venue | the pre-existing `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=4294967296` (4 GiB), `MemorySwap=4294967296`, running |
| started | 2026-11-25, during the A22 identity re-bind batch |
| concurrent heavy commands | one: nothing else ran in the court |

## 2. Measurements

| field | value |
|---|---|
| host `free -g` immediately before the module run | `Mem: 45 16 23 0 6 29` — available **29 GiB**; `Swap: 45 18 27` |
| cap in force | the container's own 4 GiB cgroup limit (`memory.max = 4294967296`) |
| §24.4 derived cap for a *new* court in this batch | `min(4g, 29 − 8) = 4g`; no new court was started |
| observed peak | `memory.peak = 4294967296` (the 4 GiB limit) |

## 3. OOM evidence

Read from the container's cgroup after the kill:

```
memory.events:
low 0
high 0
max 19174
oom 4
oom_kill 4
oom_group_kill 0
sock_throttled 0
memory.peak  4294967296
memory.current 18067456
memory.max   4294967296
```

`docker inspect openssl-rs-court` reported
`Status=running Running=true OOMKilled=true ExitCode=0`. The `docker exec`
output ended with the literal `Killed` and no Python traceback, which is the
cgroup OOM kill rather than a test failure. The container stayed up; only the
test process was killed.

## 4. What was lost

* The full `test_sigstore_bundle` module result. It reached 12 completed tests
  (11 pass, 1 drift failure) and was killed at the 13th,
  `DeterminismAndRecords.test_the_producer_is_deterministic_in_process`, the
  sigstore producer. Per §24.7 that test's result is **`NOT_RUN`**, not a
  failure of the code and not a pass.
* The remaining `DeterminismAndRecords` and `FrozenPopulation` tests that the
  single-process module run would have reached are **`NOT_RUN`**.
* Nothing else. The run is read-only over the tree except `TemporaryDirectory`
  scratch.

## 5. The reduced units that replaced it

Per §24.2 the heavy unit was not retried at the same size. The observed peak was
already the cap, so a second run could not succeed within the 4 GiB budget.

| reduced unit | observed |
|---|---|
| `test_sigstore_bundle.FrozenPopulation.test_the_frozen_population_reproduces_at_this_tree` | `Ran 1 test`; `FAILED (errors=1)`; `PH_REFUSED_POPULATION_DRIFT` on `evidence/a22/CONTROLS.json` |
| `test_sigstore_bundle.{CommandLine,ControlsRecord,StructuralNoNetwork,ValidatorBehaviour}` | `Ran 30 tests in 1.321s`; `FAILED (failures=1)`; the same drift (`outcome=NOT_RUN`) |
| `test_harden` | `Ran 69 tests in 2.035s`; `FAILED (failures=2, errors=1)`; all three are the same drift |

The three harden reds are `test_the_frozen_record_reproduces_at_head` (error),
`test_the_frozen_scan_reports_growth_at_the_frozen_count` (fail) and
`test_the_producer_is_deterministic_and_matches_the_committed_bytes` (fail).

## 6. Drift found, separate from the OOM

The A22 records were regenerated at `11f6a06f8` (A20 re-bound its pinned
candidate); the A16 inventory and the A11 scan still freeze the previous A22
bytes. Both `evidence/a16/INVENTORY.json` and `evidence/a11/SCAN.json` declare
exactly three A22 members, and all three moved:

| path | frozen/declared SHA-256 | current SHA-256 |
|---|---|---|
| `evidence/a22/CONTROLS.json` | `8c9009cc09e56eb1cba1f8f7894ad955c5886091af33b29422ee2767e3f7cb2a` | `40e0df959e2a08909bcfc5c3411629b6f5c494d507884ab88b957a9b155dbbf2` |
| `evidence/a22/EXPERIMENTS.json` | `253ffce418f6fe675cc2d89a2cce9b1b617711294fbc88de8105943a15d5bafe` | `df72d2e090e76766f6aacc4c2ce0dd9b233305d2929d547b1893e04c4c863ce6` |
| `evidence/a22/RESULTS.json` | `976ecee77d13e5ab11ae78426c0cff3835a5de4bc25d2dcbbc2a035ca768ddde` | `db49003319376aa633aea9898fb9599097ae6f496ec5f6ff661cb547dfba7a1c` |

This is the expected A16/A11 cascade: A11 was not re-frozen and A16 was not
re-frozen in this batch. The drift is not an OOM result and not a defect in the
code under test.

## 7. Claim discipline

No result from the killed process is used. The module-level
`test_sigstore_bundle` result is `PARTIAL` (30 bounded tests run, 1 drift
failure; 12 tests completed before the kill, 1 drift failure) and its
producer/frozen-population remainder is `NOT_RUN` with this incident as the gate
that would produce it. The `test_harden` module completed and is reported in
full (69 run, 3 drift reds). The OOM is a venue (4 GiB cgroup) limitation, not a
code defect: the observed peak equals the cap before any verdict on the killed
test was reached.
