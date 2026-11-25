# Incident 2026-11-25-1 — the court was OOM-killed during a single-process suite run

AGENTS.md §24. A full test discovery was run in the already-running court and the
court was killed at its cgroup limit. This receipt records the command, the
measurements, the OOM evidence, what was lost, and the reduced unit of work that
replaced it. It is written by the batch that saw the incident, for the venue
owner; it is not a claim about the code under test.

## 1. The command and the venue

| field | value |
|---|---|
| command | `python3 -m unittest discover -s forensics/tools/tests` |
| venue | the pre-existing `openssl-rs-court` container, image `openssl-rs-court-tools:1`, `Memory=6442450944` (6 GiB), `MemorySwap=6442450944`, `NanoCpus=8000000000` |
| started | 2026-11-25, during the A11/A16 re-freeze batch |
| concurrent heavy commands | one: nothing else in this batch was running |

## 2. Measurements

| field | value |
|---|---|
| host `free -g` immediately before | `Mem: 45 14 9 0 23 31`, `Swap: 45 17 28` — available **31 GiB** |
| cap in force | the container's own 6 GiB cgroup limit (created by an earlier session, not by this batch) |
| §24.4 derived cap for a *new* court in this batch | `min(4g, 31 − 8) = 4g` |
| observed peak | not measured directly; the cgroup reached its 6 GiB limit, which is what triggered the kill |
| exit | container `ExitCode=137`, `OOMKilled=true` |

## 3. OOM evidence

```
docker inspect --format '{{.Name}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}} mem={{.HostConfig.Memory}}' \
  openssl-rs-court openssl-rs-court-a11a16
/openssl-rs-court oom=true exit=137 mem=6442450944
/openssl-rs-court-a11a16 oom=false exit=137 mem=4294967296
```

Both `openssl-rs-*` containers stopped within the same second; `dmesg` shows the
`docker0` veth teardown for both. During the run `docker exec` also reported
`Error response from daemon: No such exec instance`, i.e. the exec died with the
container. The killed container is the one running the discovery.

## 4. What was lost

* The single-process suite result. Per §24.7 it is **`NOT_RUN`**, not a failure of
  any test and not a pass. No test result from that process is used anywhere.
* Nothing else. The discovery is read-only over the tree; it writes only
  `TemporaryDirectory` scratch and `.frf/` capture artefacts, and no evidence
  record, receipt or source file was being written by it. The batch's own
  records were re-derived and re-verified after the incident (each producer is
  byte-identical across two fresh runs, recorded in the batch report).

## 5. The reduced unit that replaced it

Per §24.2 no further single-process discovery was attempted in this batch, and
per §24.3 the unit was reduced. The court was recreated at the §24.4 cap and the
same test definitions were run in two bounded in-process aggregates plus a
per-module sweep.

| step | command | result |
|---|---|---|
| court recreated | `OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 OPENSSL_RS_COURT_MEM=4g OPENSSL_RS_COURT_MEMSWAP=4g docker/openssl-rs-court.sh up` | running, `mem=4294967296`, `CAP_PERFMON`, `perf version 6.1.192` |
| aggregate 1 | `python3 -m unittest discover -s forensics/tools/tests -p 'test_[a-k]*.py'` | `Ran 1168 tests … OK` |
| aggregate 2 | `python3 -m unittest discover -s forensics/tools/tests -p 'test_[l-z]*.py'` | `Ran 1317 tests … OK` |
| per-module sweep | each of the 54 `forensics/tools/tests/test_*.py` modules alone | all 54 `OK`; sum of per-module counts 2485 |

The two patterns together match every `test_*.py` module, so **every test ran and
passed**, in bounded units, at a 4 GiB cap. What is not established is the
behaviour of the *aggregate single-process* import/run, which is the unit that
was killed; that is reported as `NOT_RUN` in the batch report.

## 6. Venue defect found while recovering (separate from the OOM)

The replacement court was first created without `OPENSSL_RS_COURT_IMAGE`, so it
used the minimal `openssl-rs-court:1` image, which has no `perf`. Two positive
controls then failed for venue reasons only:

* `test_binary_assurance.PositiveControl.test_live_tcb_matches_the_committed_record`
  — `live tcb_digest bfe0ac73… != committed aa8fbaea…`;
* `test_instrument_qualify` — 12 failures.

Recreating the court from `openssl-rs-court-tools:1` (`court_variant=timing-tools`,
`/usr/bin/perf`, `perf version 6.1.192`, `CAP_PERFMON`) makes both pass unchanged:
`Ran 25 tests … OK` and `Ran 16 tests … OK`. The committed TCB records the venue
that had `perf`; a court without it is a different venue, not a code regression.
The launcher's default image remains the venue owner's decision and is recorded
here rather than changed by this batch (`docker/` is out of scope).

## 7. Claim discipline

No result from the killed process is used. The batch report names the four
requested gates, the two aggregates, and the per-module sweep as the evidence,
and records the single-process discovery as `NOT_RUN` with this incident as the
gate that would produce it.
