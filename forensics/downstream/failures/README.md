# Minimized reproductions of candidate-specific downstream failures

This directory holds the **minimized reproducers** Phase 24.8's failure discovery/minimization loop
produces for candidate-specific failures. One subdirectory per failure is written by
`forensics/tools/downstream_failures.py` and is pinned by the corresponding record's `reproducer`
field in `forensics/downstream/failures.json`: the record carries the fixture's recomputed SHA-256,
and the `RT-FAILURE-MINIMIZATION` court re-hashes every fixture from disk and refuses a record whose
fixture is missing or hashes differently.

A fixture is a small, standalone, deterministic C program (`repro.c`) with a `build.sh`, a `run.sh`
and a `README.md` naming the consumer, the first divergent observation, the authority value and the
candidate value. It runs inside the admitted court container with no public network.

## The honest state on this landing

There are **zero** candidate-specific failures to minimize, so there are **no** subdirectories here.
That is the honest measurement, not a failure to minimize and not an omission:

* the build/link atlas reached the authority-applicable level or beyond for every recipe-backed
  family under the candidate, and the runtime atlas's `candidate_below_baseline` is 0;
* every leftover the two atlases record is a **venue/environment limitation** -- a family with no
  admitted recipe, an absent generated `configure`, an absent build dependency, or a program this
  venue admits no local workload for -- and the authority hit the same limitation in the same
  admitted venue, so it is classified `venue-limited` (or `out-of-scope`) rather than counted as a
  candidate defect (the brief's section 44).

The minimizer machinery is not assumed: `downstream_failures.py --self-test` minimizes a synthetic
record into scratch, hashes it, and requires a single-byte tamper to change the hash, and the court's
sensitivity control seeds a record whose minimized fixture is missing and requires it to be caught.

The record that no candidate-specific failure exists is machine-readable: see
`forensics/downstream/failures.json`'s `counts.candidate_specific` (0) and `counts.by_disposition`.
