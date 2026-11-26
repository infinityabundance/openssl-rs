# PFP-2 results at DSO `83f67826` — timing, DSO-bound differential, branch audit

Date: 2026-11-26. Venue: `openssl-rs-court-tools:1`, cgroup cap 8 GiB,
per-process `RLIMIT_DATA` 4 GiB, one CPU pinned with `taskset -c 1`, no PMU.

This record is the conjunction PFP-19 asks for. All three conjuncts are bound to
the **same** candidate digest:

| conjunct | record | digest |
|---|---|---|
| measurement | `timing-83f67826/results.json` | `454655e3b8ea8055c908c5c271821e0281c4ce0093340eef85195abfffc4b357` |
| differential court | `dso-differential/differential-dso-bound.json` | `d2d64251eab1c6d714d8deb1b1dd009f4aa25ed6fc2d3d9ae5c3e51c46c931ea` |
| binary branch audit | `audit/post-fix-binary-branch-audit-83f67826.md` | `c082c827a933eb5ce45575f929f9a0c45ae9d3345703861e75dc57f968bb96e4` |

Candidate DSO: `court/tmp/pfp2-fix/distribution/libcrypto.so.3`,
sha256 `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f`,
build-id `ef860b61ec716042c749d01e9e7a97884b19de97`.
Authority: `openssl-3.6.4-production`,
sha256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.

The candidate's build-relevant source is the committed staging
`790685a0aa0aba5dc655dee9fd33904f7350cf53` (the PFP-2 fix); current HEAD
`719ef5dbcd` has an identical `src` tree (`git rev-parse HEAD:src` equals
`790685a0aa:src`). The frozen DSO was not rebuilt in these runs, so the digest
is checked before and after execution. The bytes are not committed.

---

## 1. DSO-bound differential court

Instrument: `dso-differential/pfp2_dso_differential.c`
(sha256 `fd67b943889ab710af9f3c246e3119c2f28561dc6a47084ee96f5a5d5f64affc`;
compiled binary sha256
`2ffcf3febb3d4b5f94a3cab13433f5d63996dea2610d7a8cc140317b5ea68693`).
Each process `dlopen(RTLD_NOW | RTLD_LOCAL)`s exactly one `libcrypto.so.3`,
prints `LIB` from `dladdr(BN_new)` and `LOADED realpath/dev/ino/size`, and the
runner compares those fields with `stat(2)` on the expected on-disk DSO and
requires a `/proc/self/maps` entry. All 8 process identities passed.

Population and result:

| case class | cases | comparison | result |
|---|---:|---|---|
| `k*G`, scalar from the fixed seed | 4,096 | serialised uncompressed P-256 point, full line including `k` | 0 mismatches |
| `k*P`, `P = j*G` | 4,096 | serialised uncompressed P-256 point, full line including `j` and `k` | 0 mismatches |
| ECDSA candidate signs, authority verifies | 256 | `ECDSA_do_verify` acceptance | 256/256 |
| ECDSA authority signs, candidate verifies | 256 | `ECDSA_do_verify` acceptance | 256/256 |

Seed `0x5046503250485032`; derivation is splitmix64 over
`(seed ^ domain ^ i*0x9e3779b97f4a7c15)`, with the 32-byte big-endian scalar's
top bit cleared and low bit set, so every scalar is in `[1, 2^255)` below `n`
and non-zero. The four processes derived one identical public key
`04bf5059…15b63` and one identical message sequence. Signature bytes are not
compared because nonces are random; acceptance, key and message sequence are.

Outputs: `raw/mul-g-{candidate,authority}.out`,
`raw/mul-p-{candidate,authority}.out`, `raw/sign-*.out`, `raw/verify-*.out`,
per-case `POINT`/`SIGN`/`VERIFY` lines with the input. Result: **PASS**.

**What this court cannot run.** `p256::mont_reduce_into`,
`p256::wide_mul_x86` and `bn::limbs::normalise` have no exported entry point, so
they were not called directly; they are exercised only through `EC_POINT_mul`
and ECDSA. No source-level test is substituted while calling the court
DSO-bound. This is residual `PFP2-DIFFERENTIAL-SCOPE`.

---

## 2. Timing at the same digest

Tracked instruments, invoked unchanged: `courts/phase18/timing/bench_api.c`
(`e1add483…`), `alloc_probe.c` (`76b432fd…`),
`courts/performance-frontier/baseline/analyse_bench_api.py` (`5182354d…`).
`timing-83f67826/run_timing.sh` is a bound copy of the preregistered protocol
that does **not** rebuild the crate; it pins the frozen DSO and still proves
each mapped file.

15 paired repetitions, balanced pseudo-random order seeded `0x50465030`, one
process per subject per repetition, warm-up excluded, `taskset -c 1`, median of
paired ratios, 20,000-resample percentile bootstrap. Analyser: **PASS**
(LOADED identity `all_ok`, all CHECK lines match, cross-verification accepted
in both directions). `results.json` carries the analyser's fixed `campaign`
label `PFP-0` (the harness schema); the campaign identity is this directory and
`timing-83f67826/preregistration.json`, which say PFP-2.

| workload | candidate µs | authority µs | paired ratio | CI95 | allocs c/a |
|---|---:|---:|---:|---|---|
| **ecdsa256** | **246.099** | **12.724** | **19.323** | **[19.236, 19.359]** | 254.0 / 29 |
| dh-ffdhe2048 | 5419.110 | 1191.539 | 4.548 | [4.546, 4.551] | 22 / 8 |
| dh-ffdhe3072 | 18450.816 | 3964.631 | 4.655 | [4.650, 4.670] | 22 / 8 |
| dh-modp2048 | 5415.623 | 1191.783 | 4.545 | [4.542, 4.550] | 22 / 8 |
| dh-synth2048 | 5418.769 | 1194.670 | 4.535 | [4.532, 4.548] | 22 / 8 |
| dh-synth3072 | 18431.399 | 3963.473 | 4.655 | [4.634, 4.667] | 22 / 8 |
| modexp2048 | 5530.354 | 1200.542 | 4.607 | [4.596, 4.619] | 18 / 5 |
| modexp8192 | 361485.879 | 73763.004 | 4.901 | [4.898, 4.908] | 18 / 5 |
| rsa2048 | 1844.028 | 351.003 | 5.254 | [5.234, 5.263] | 164.6 / 19 |

**Against the recorded pre-fix 18.69×.** The pre-fix campaign (DSO `467527ae`)
recorded `ecdsa256` 18.688× [18.631, 18.750]. At `83f67826` the same harness
reads 19.323× [19.236, 19.359]. The fix did not cost measurable `ecdsa256`
speed. The increase is **not** claimed as a speedup: the eight unaffected
workloads moved down about 3–4% in this run (e.g. `dh-ffdhe2048` 4.710 → 4.548,
`rsa2048` 5.334 → 5.254), which is venue/run drift between the two campaigns,
not an engine change. The honest statement is "at least as fast at this digest";
the preregistered register did not propose a margin for the difference.

Allocations are 254.0 per signature against 29, improved from 273.4 and still
open as `T29`.

---

## 3. Binary branch audit

`courts/phase18/timing/binary_branch_audit.py`
(sha256 `4e61f2ef2eaffed68f73c859dc36557629e3f33eb9f93185b013b8862f095ba0`)
at `--expect-sha256 83f67826…`: **exit 0**. 9 of 9 expected targets resolved
with complete disassembly; 1 resolved through a verified inline mapping
(`mod_exp_core_consttime_from_parts` → its `_prepared` carrier, called by
`BN_mod_exp` with the wrapper's constant `None`). `p256::mont_reduce_into` has
2 conditional jumps, both loop bounds on the public `subtractions` argument;
`p256::wide_mul_x86` has none.

The audit is a review aid: it lists compiler-emitted conditional jumps and
their targets, and a reviewer maps them to the source's secret classification.
It is not a constant-time proof. That limit is residual `PFP2-AUDIT-NOT-A-PROOF`.

---

## 4. Admission decision

`forensics/tools/performance_admission.py check` (unmodified) accepts the
register: `PFP-0-refreeze EXPERIMENT`, `PFP-1 EXPERIMENT`, `PFP-2 CANDIDATE`;
0 refused, exit 0. See `evidence/performance-frontier/admission/ARMS.json`.

The CANDIDATE predicate this record satisfies, quoted from the validator:

> a measurement bound to the candidate digest, a passing differential court at
> that digest, a binary constant-time audit at that digest, a population frozen
> before execution, an empty timing-discharge set, a false
> safety/compatibility declaration and no refused shortcut.

A candidate with a named residual is admissible; a candidate with a hidden one
is not. The residuals are enumerated below and in the claim record.

---

## 5. Residual obligations (none hidden)

1. `PFP2-WRITEBACK-NORMALISE` — `store_coordinate` (`src/ec/smpl.rs:2624`) →
   `limbs::normalise` (`src/bn/limbs.rs:42`) branches on the secret top limb
   (the 4 engine-on-path contexts). It cannot be stored at fixed width without
   breaking the no-trailing-zero-limb `BIGNUM` representation invariant.
   **Update (PFP-20, 2026-11-26):** the timing branch is gone —
   `store_coordinate` now trims with `limbs::normalise_branchless`, and the four
   `store_coordinate` engine-on-path contexts are **0** on DSO `553e1b8c` across
   three repetitions (the `83f67826` before-control stays 4). The representation
   is unchanged; the relocation after declassification and the downstream length
   consumers remain. See `ctgrind/PFP-20-NORMALISE.md`.
2. `PFP2-ADMIT-BE-BYTES` — `P256Scalar::admit_be_bytes` branches on `ct_ge` for
   the required public accept/reject decision; not on the ladder path, and
   removing it would be a correctness bug.
3. `PFP2-DIFFERENTIAL-SCOPE` — internal kernels have no exported entry point;
   they are reached only through `EC_POINT_mul` and ECDSA.
4. `PFP2-AUDIT-NOT-A-PROOF` — the audit is a branch inventory with an inline
   mapping; it is not a constant-time proof and cannot distinguish inlining
   from a source edit with the same instruction stream.
5. `PFP2-CTGRIND-TEST-BINARY` — ctgrind ran the debug test binary, not the DSO.
6. `PFP2-NO-PMU` — no PMU, frequency, turbo, SMT or isolation control; every
   row is `SCOPED_OBSERVATION`.
7. `PFP2-DIRTY-CANDIDATE` — the frozen DSO bytes are not committed; the
   build-relevant source commit and digest are.
8. `PFP2-MUTATION-CONTROL-NOT-AT-DIGEST` — the within-candidate mutation control
   (force the generic kernel) was measured on the pre-fix debug profile, not on
   the released DSO `83f67826`; the release `--test` rebuild hit a recorded
   memory incident. The fast path's load-bearing property is not re-established
   at this digest.
9. `T23`, `T24`, `T29` — unchanged timing obligations; performance evidence does
   not discharge them.

**What would make PFP-2 `DONE` rather than `PARTIAL`:** a DSO-level ctgrind or
equivalent taint run and a mutation control at `83f67826`; removal of the
write-back `normalise` secret-dependent branch with a representation change
justified at the ABI boundary; an explicit decision on `admit_be_bytes`;
committed candidate bytes (or a reproducible rebuild from `790685a0aa` in the
venue); and L4/L5 evidence. None of these is claimed here.
