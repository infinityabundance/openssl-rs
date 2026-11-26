# PFP-2 results at DSO `553e1b8c` — timing, DSO ctgrind, branch audit, differential, rebuild

Date: 2026-11-26. Venue: `openssl-rs-court-tools:1`, container cgroup cap 8 GiB
(the running court; `available` 25 GiB immediately before each command, declared
peak far below half), per-process `RLIMIT_DATA` 4 GiB, one CPU pinned with
`taskset -c 1`, no PMU. One heavy command at a time, `CARGO_BUILD_JOBS=4`;
`memory.events` stayed `oom 0 oom_kill 0` across the timing run and the rebuild.

This file supersedes `RESULTS-83f67826.md` as the arm's current record. The
older file is retained unchanged (Earned Trust article 10); its numbers are not
reused at this digest.

Candidate: `staging` **`c1d25e10d16bc197e03446619a5330842b411c5c`** (the
committed PFP-20 source), whose distribution DSO is
`553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4`
(17,032,672 bytes, build-id `408dafd2f611bb8fa095ed760e7eaafc59ebb39e`).
Authority: `openssl-3.6.4-production`,
sha256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`,
re-confirmed before and after the timing run.

`staging` HEAD `4d4979e26` differs from `c1d25e10d` in exactly one source file,
`src/bn/arith.rs` (the PFP-6 integration); `git diff --name-only c1d25e10d HEAD
-- src` lists that file and nothing else. The frozen DSO was not rebuilt for the
timing run; the bytes are bound by digest checks before and after, and by the
independent rebuild in §5.

| conjunct | record | digest |
|---|---|---|
| timing measurement | `timing-553e1b8c/results.json` | `553e1b8c…` |
| DSO-bound differential | `dso-differential-pfp20/differential-dso-bound.json` | `553e1b8c…` |
| binary branch audit | `ctgrind/pfp20-2026-11-26/branch-audit.md` | `553e1b8c…` |
| ctgrind + mutation control | `ctgrind/PFP-21-DSO.md`, `ctgrind/pfp21-2026-11-26/raw/pfp21-record.json` | `553e1b8c…` |
| independent rebuilds | `repro-553e1b8c/` | `553e1b8c…` |

---

## 1. Timing at the same digest

Instruments invoked unchanged: `courts/phase18/timing/bench_api.c`
(`e1add483…`), `alloc_probe.c` (`76b432fd…`),
`courts/performance-frontier/baseline/analyse_bench_api.py` (`5182354d…`),
`forensics/performance/WORKLOADS.json` (`1d33143a…`). 15 paired repetitions,
balanced pseudo-random order seeded `0x50465030`, one process per subject per
repetition, warm-up excluded, `taskset -c 1`, median of paired ratios,
20,000-resample percentile bootstrap (seed `0x50465030`), Holm–Bonferroni over
the nine-workload family. Analyser: **PASS**; LOADED identity `all_ok` on all 58
rows, every CHECK line matches, cross-verification accepted in both directions
(6 repetitions, both signer orders).

`run_timing.sh` in `timing-553e1b8c/` is a bound copy of the `83f67826` runner.
The harness, analyser, repetition count, seed, ordering, CPU pin, statistic and
bootstrap are unchanged; the diff (`timing-553e1b8c/runner-diff-vs-83f67826.diff`)
changes only the subject digest, the three subject/archive paths, the source
commit, the campaign directory names, the preregistration's `frozen_subject`
string, and `--repo` for the identity document. That last one is needed because
the parent copy refuses a subject whose source tree is not `HEAD:src`; here the
declared commit is one `src` file behind `HEAD`, so the identity document is
taken from a **clean detached worktree at the declared commit**
(`court/tmp/pfp23-src`, `HEAD:src` = `613b4eee…` = `c1d25e10d:src`, working tree
clean). The refusal condition itself is untouched.

| workload | candidate µs | authority µs | paired ratio | CI95 | familywise CI | allocs c/a |
|---|---:|---:|---:|---|---|---:|
| **ecdsa256** | **244.908** | **12.741** | **19.223** | **[19.176, 19.252]** | **[19.175, 19.260]** | 254.2 / 29 |
| dh-ffdhe2048 | 5438.654 | 1192.028 | 4.564 | [4.562, 4.567] | [4.561, 4.571] | 22 / 8 |
| dh-ffdhe3072 | 18443.077 | 3964.792 | 4.665 | [4.647, 4.682] | [4.645, 4.689] | 22 / 8 |
| dh-modp2048 | 5437.634 | 1192.384 | 4.560 | [4.558, 4.563] | [4.549, 4.567] | 22 / 8 |
| dh-synth2048 | 5437.255 | 1193.477 | 4.558 | [4.552, 4.559] | [4.544, 4.562] | 22 / 8 |
| dh-synth3072 | 18432.616 | 3958.031 | 4.657 | [4.654, 4.669] | [4.642, 4.681] | 22 / 8 |
| modexp2048 | 5551.186 | 1198.962 | 4.631 | [4.601, 4.643] | [4.582, 4.643] | 18 / 5 |
| modexp8192 | 362307.611 | 73845.930 | 4.901 | [4.900, 4.911] | [4.897, 4.913] | 18 / 5 |
| rsa2048 | 1843.268 | 350.868 | 5.250 | [5.238, 5.258] | [5.207, 5.262] | 164 / 19 |

`ecdsa256` allocations are 254.2 per signature against 29 (was 254.0 / 29 at
`83f67826`); `T29` stays open.

### Against `19.3228×` — same instrument, different digest, not a trend

At `83f67826` the same instrument read `ecdsa256` 19.3228× [19.2355, 19.3593]
(246.099 / 12.724 µs). At `553e1b8c` it reads **19.2234× [19.1755, 19.2520]**
(244.908 / 12.741 µs), a change of **−0.51%**. In the same run the eight
workloads the P-256 engine does not touch moved by −0.08% to +0.52%
(`dh-ffdhe2048` 4.548 → 4.564, `dh-ffdhe3072` 4.655 → 4.665, `dh-modp2048`
4.545 → 4.560, `dh-synth2048` 4.535 → 4.558, `dh-synth3072` 4.655 → 4.657,
`modexp2048` 4.607 → 4.631, `modexp8192` 4.901 → 4.901, `rsa2048` 5.254 →
5.250), so the venue drifted by a comparable amount between the two campaigns.

This is a **same-instrument comparison across two digests**, not a trend and not
a speedup: it says the two artefacts measure the same to within venue drift on
`ecdsa256` (the only workload the engine changes), and nothing about direction.
No margin was preregistered for that difference; no p-value is computed for a
two-campaign comparison by this protocol.

## 2. ctgrind and the mutation control at the artefact

Record: `ctgrind/PFP-21-DSO.md` (draft), raw `ctgrind/pfp21-2026-11-26/`.
Harness `pfp21_dso_ct.c` source `ef137412…`, binary `3a385537…`; `dlopen` of one
DSO, `LOADED`/`MAPS`/`FOREIGN` checked against `stat`, limb-value taint verified
against each `BIGNUM`'s own export, six populations, fixed fixtures, negative
control 0 errors from 0 contexts.

On candidate A `553e1b8c`: 18 tainted runs, **0 engine-on-path contexts and 0
engine origins**; residue is the pre-existing generic BIGNUM/EC ladder path and
is kernel-independent. `mul-g` 3,596–3,670 errors / 185–236 contexts; `sign`
3,684–3,723 / 248–275; `sign-ex` 24/24; tainted-nonce `sign-ex-k`
33,003–33,017 / 438–450. Sensitivity control C (`83f67826`, pre-PFP-20) reports
**4 engine-on-path contexts per repetition** (12 across three), all
`store_coordinate <- p256_ladder_run::<Mont<_>>`, so the instrument does see the
engine path.

Mutation control, same harness and fixtures, A vs B (`86bc63a6…`, one line
different: `default_kernel_id` `Mont` → `Solinas`): `mul-g` 4,891,699 →
11,375,102 instructions per call (**2.325×**), wall 227.8 → 536.9 µs
(**2.357×**); `sign` 2.176× instructions / 2.249× wall. The admitted kernel is
load-bearing in the shipped bytes.

**Two limits, kept visible.** Memcheck reports conditional jumps/moves on
undefined data; it **cannot distinguish a constant-time cmov from a branch**.
And the nonce generated *inside* `ECDSA_do_sign` has no exported entry point and
**cannot be tainted**; the sign path is covered through `ECDSA_do_sign_ex`
(nonce inverse supplied) and the tainted-`k` path, and that is reported rather
than excluded. Neither instrument is a constant-time proof.

`PFP-21-DSO.md` §7 records the register state **at the time that file was
written** (arm at `83f67826`, timing at this digest `NOT_RUN`). That gap is
closed by this record: the timing exists at `553e1b8c` and `ARMS.json`'s `PFP-2`
arm now names `553e1b8c` with `constant_time_audit.kind`
`CTGRIND_PLUS_BRANCH_AUDIT`. §§1–8 of `PFP-21-DSO.md` are unchanged.

## 3. Binary branch audit

`ctgrind/pfp20-2026-11-26/branch-audit.md` (`b63fc18d…`) at
`--expect-sha256 553e1b8c…`: **exit 0**, 9 of 9 expected targets resolved and
disassembled, 1 through a verified inline mapping
(`mod_exp_core_consttime_from_parts` → `_prepared`), 0 failed. It is a review
aid, not a constant-time proof (`PFP2-AUDIT-NOT-A-PROOF`).

## 4. DSO-bound differential

`dso-differential-pfp20/differential-dso-bound.json` (`d3bfe7b3…`): subject
candidate sha256 `553e1b8c…`, authority `611e511d…`, `result` PASS, identity
proof 8/8 rows `all_ok`. 4,096 `k*G` and 4,096 variable-base `k*P` compared
line-for-line with 0 mismatches; ECDSA cross-verification 256/256 in **both**
directions at seed `0x5046503250485032`.

The record's `record_id` string still carries the label
`PFP2-DSO-DIFFERENTIAL-83f67826` from the parent campaign; its `subjects`,
`cases`, raw outputs and identity proof are all at `553e1b8c`. This is a stale
label, not a stale measurement; it is left unedited rather than rewritten.

## 5. Reproduction (PFP-23)

See `repro-553e1b8c/REPORT.md`. Two independent clean rebuilds from
`c1d25e10d` into different fresh target directories agree byte-for-byte:
archive `b7c22e86…`, DSO `553e1b8c…`. A digest match is not a source-to-binary
refinement claim.

## 6. Residual obligations (none hidden)

1. `T23` — secret ownership does not propagate through the arithmetic; the
   fixed-width transfer window stays open.
2. `T24` — constant-time inversion scratch storage and normalised limb-count
   metadata remain the recorded residual.
3. `T29` — 254.2 allocations per ECDSA signature against 29.
4. `PFP2-WRITEBACK-NORMALISE` — timing branch discharged by PFP-20; the
   length encoding after declassification and its downstream consumers remain
   (`PFP-20-NORMALISE.md`).
5. `PFP2-ADMIT-BE-BYTES` — `ct_ge` admission branch is a required public
   accept/reject decision, not on the ladder path.
6. `PFP2-DIFFERENTIAL-SCOPE` — internal kernels have no exported entry point;
   reached only through `EC_POINT_mul` and ECDSA.
7. `PFP2-AUDIT-NOT-A-PROOF` — the audit is a branch inventory with an inline
   mapping, not a proof.
8. `PFP2-CTGRIND-INSTRUMENT-LIMIT` — memcheck cannot distinguish cmov from
   branch; the library RNG nonce cannot be tainted. DSO-level ctgrind exists at
   this digest (superseding the debug-binary gap).
9. `PFP2-MUTATION-CONTROL-SEPARATE-ARTEFACT` — the control is DSO B
   `86bc63a6`, necessarily a different artefact; B's semantic equivalence is 512
   points at one seed.
10. `PFP2-DIRTY-CANDIDATE` — the DSO bytes are not committed; two independent
    rebuilds from the committed source now bind the digest.
11. `PFP2-NO-PMU` — no PMU or frequency/turbo/SMT/core-isolation control; every
    timing row is `SCOPED_OBSERVATION`.

## 7. What this record does not claim

It does not claim constant time. It does not claim a speedup or regression
against `83f67826`; the two runs are the same instrument at different digests
with venue drift larger than the `ecdsa256` difference. It does not claim the
mutation control was measured on the candidate bytes (it cannot be: a mutation
is a different binary). It does not claim L4/L5.
