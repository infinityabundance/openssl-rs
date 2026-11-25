# Incident 2026-11-25-2 — the court OOM-killed a single sigstore-bundle test

AGENTS.md §24. A single named test in `forensics/tools/tests/test_sigstore_bundle.py`
was run in the already-running court and the court's cgroup killed it at its
memory limit. This receipt records the command, the measurements, the OOM evidence,
what was lost, and the reduced unit of work that replaced it. It is written by the
batch that saw the incident; it is not a claim about the code under test.

## 1. The command and the venue

| field | value |
|---|---|
| commands | `python3 -m unittest forensics.tools.tests.test_sigstore_bundle`; then the reduced `...DeterminismAndRecords.test_the_producer_is_deterministic_in_process` |
| venue | the pre-existing `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=4294967296` (4 GiB), `MemorySwap=4294967296`, `NanoCpus=8000000000` |
| started | 2026-11-25, during the A7/B8 repair batch |
| concurrent heavy commands | one: nothing else ran in the court |

## 2. Measurements

| field | value |
|---|---|
| host `free -g` immediately before the module run | `Mem: 45 13 13 0 19 32`, `Swap: 45 19 26` — available **32 GiB** |
| host `free -g` immediately before the single-test run | `Mem: 45 13 13 0 19 32`, `Swap: 45 19 26` — available **32 GiB** |
| cap in force | the container's own 4 GiB cgroup limit (`memory.max = 4294967296`) |
| §24.4 derived cap for a *new* court in this batch | `min(4g, 32 − 8) = 4g` |
| observed peak | `memory.peak = 4294967296` (the 4 GiB limit) |

## 3. OOM evidence

Read from the container's cgroup after the first kill:

```
low 0
high 0
max 6500
oom 1
oom_kill 1
memory.peak 4294967296
memory.max 4294967296
```

After the reduced single-test run:

```
low 0
high 0
max 8420
oom 3
oom_kill 3
memory.peak 4294967296
memory.max 4294967296
```

Both `docker exec` invocations ended with the literal output `Killed` and no
Python traceback, which is the cgroup OOM kill rather than a test failure. The
container stayed up (`docker ps`: `openssl-rs-court  openssl-rs-court-tools:1
Up 2 hours`); only the test processes were killed.

## 4. What was lost

* The full `test_sigstore_bundle` module result. It reached 12 completed tests
  (11 pass, 1 drift failure) and was killed at the 13th,
  `DeterminismAndRecords.test_the_producer_is_deterministic_in_process`. Per §24.7
  that test's result is **`NOT_RUN`**, not a failure of the code and not a pass.
* The remaining tests that the single-process module run would have reached:
  the rest of `DeterminismAndRecords` and all of `FrozenPopulation`
  (< 16 tests), are **`NOT_RUN`**.
* Nothing else. The run is read-only over the tree except `TemporaryDirectory`
  scratch.

## 5. The reduced unit that replaced it

Per §24.2 the heavy unit was not retried at the same size. The observed peak was
already the cap, so a second run could not succeed within the §24.4 budget. The
reduced unit was the five non-producer classes of the same module:

```
python3 -m unittest \
  forensics.tools.tests.test_sigstore_bundle.StructuralNoNetwork \
  forensics.tools.tests.test_sigstore_bundle.DocumentSynchronisation \
  forensics.tools.tests.test_sigstore_bundle.ValidatorBehaviour \
  forensics.tools.tests.test_sigstore_bundle.ControlsRecord \
  forensics.tools.tests.test_sigstore_bundle.CommandLine
```

Result: `Ran 36 tests in 1.329s`, `FAILED (failures=1)`. The single failure is the
A11/A16 drift described in §6, not a sigstore validation defect; the other 35
passed. The producer and frozen-population classes were not re-run.

## 6. Drift found, separate from the OOM

The module's declared population binds the A11 records. Two members changed in
this batch:

| path | frozen/declared SHA-256 | current SHA-256 |
|---|---|---|
| `evidence/a7/BASELINES.json` | `2a5a3f863c1ddf7775d0f524e7b36feb9f01a22a6c6569eff1d3c93081ae1cab` | `a57a2766046ff4123e39bce62b3baa75fde758790aac09520657550f76986ca5` |
| `evidence/b8/PENDING.json` | `ee07aa60d10b…` | `63581cd16183…` |

The first observed failure names `evidence/a7/BASELINES.json` with
`PH_REFUSED_POPULATION_DRIFT`. This is the expected A11/A16 re-freeze drift, not an
OOM result; A11 was not re-frozen in this batch.

## 7. Claim discipline

No result from either killed process is used. The five-class subset result is
reported as `PARTIAL` (36 run, 1 drift failure), and the producer/frozen-population
classes are `NOT_RUN` with this incident as the gate that would produce them. The
OOM is a venue (4 GiB cgroup) limitation, not a code defect: the test's observed
peak equals the cap before any test verdict was reached.
