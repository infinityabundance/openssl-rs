# PFP-6 re-evaluation — the dedicated squaring kernel at the PFP-5 composition

**State: negative for dedicated squaring; the production selection is unchanged
(`window = 5`, `LADDER_SCHEDULE = Sos`, `LADDER_DEDICATED_SQUARING = false`).**
The earlier PFP-6 negative was a per-kernel C transcription; this record measures
whole operations in the crate's release DSO at the composition PFP-5 created.
**CIOS is a separate, material result (16–17 % faster) and is not admitted
here** — it is the obvious next measured decision.

## 1. Why the question changed

PFP-5 replaced the bit-at-a-time ladder with a five-bit window. At width
`64·n` bits the window performs

```
windows            = ceil(64n / 5)
squarings          = 5 · windows
multiplications    = windows          (plus 2^5−2 = 30 table and 1 conversion)
```

so at 2048 bits: **2,050 squarings and 410 multiplications** in the main loop
(83.33 % squarings); at 8192 bits: **8,195 and 1,639** (83.33 %). The old PFP-6
question — "is `mont_sqr_into` faster than reusing the multiply?" — was asked
of an isolated C kernel. The question now is whether putting the dedicated
kernel on the 83 % squaring share improves a whole operation. It does not.

## 2. Source and artefacts

| item | value |
|---|---|
| source commit | `76652a46dcfb388656d964010268685ca032dff1` (`staging`) |
| source state | plus the uncommitted documentation correction to `src/bn/arith.rs` (no code change); `build_relevant_clean = false` |
| `src` tree | `142e4fe9e769ccbc1599be03fb6db68dda8c4f9e`, 887 files, fingerprint `52671fca…1a65` |
| `src/bn/arith.rs` | sha256 `66bd6c4c7f616f7d8101debf34cc2d4915eff225aba0dec4e119eccb5d682e83` |
| toolchain | rustc 1.98.1 (48a229cea), cargo 1.98.1, cc 12.2.0, x86_64-unknown-linux-gnu |
| profile | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4` |
| shell / version script | `efa0fbce…5606` / `75fb6eff…1275` |

| arm | change from A | DSO sha256 | bytes |
|---|---|---|---:|
| **A** | production defaults | `661384603e0b661af384997676d8e88843f2b307b6abf73f56d472b03d888630` | 17,113,432 |
| **A2** | A rebuilt in a fresh target dir | **identical to A** (archive also identical) | 17,113,432 |
| **B** | squarings in `run_mont_ladder_window` use `mont_sqr_into` | `5c0e0d90e9caf95f140fe98d386bab18e27072e78038a0ba3827706b4b900484` | 17,132,608 |
| **C** | `LADDER_SCHEDULE = Cios` | `ca0ae5387d81f42de6dd2207d0794840eb38b8cab1d4015d91d4aa4239569159` | 17,115,256 |
| **D** | C plus B's squaring change | `a24c0aa2e9e09e1335445421c744809585bb680915b16108546f9b5f20ab1197` | 17,134,072 |

A and A2 agree byte for byte. The experimental patches are in `raw/`:
`raw/squaring-difference.diff` (A→B: one call site), `raw/schedule-difference.diff`
(A→C: one const), `raw/cios-dedicated-difference.diff` (A→D: both). The source
fingerprint was re-checked after each build and is identical to the start.
B/C/D are measurement artefacts, not admissions.

## 3. Composition, from the code and from the profile

Callgrind, one operation per workload (`--only`; profiling mode performs three
exponentiations, one CHECK plus warm-up plus timed, so the analyser divides by
three), at DSO A:

| workload | kernel calls/op | squaring role/op | multiply role/op | main-loop squaring share |
|---|---:|---:|---:|---:|
| `modexp2048` | 2,491 | **2,050** | 441 (410 window + 30 table + 1 conversion) | **83.33 %** |
| `modexp8192` | 9,865 | **8,195** | 1,670 (1,639 + 30 + 1) | **83.33 %** |

The squaring role appears as five call arcs of 410/op (2048) and five of
1,639/op (8192); the window-multiply role is a 409/op arc plus a 1/op epilogue
(2048), or 1,638/op plus 1/op (8192). The correspondence is structural, not
assumed: `shift = 5` and `windows = 410` (or 1,639), so `5 · 410` (or
`5 · 1,639`) can only be the per-window squaring loop; the per-window multiply
is one call, which the compiler split into the loop body (409/1,638) and the
last iteration (1). The profile therefore *shows* the `5 · windows` structure.
Per-call inclusive Ir is 30,205 (n = 32) and 454,196 (n = 128).
`mont_mul_sos_into` self cost is 225,476,412 of 232,974,259 (96.78 %) at 2048
and 13,382,418,276 of 13,497,383,967 (99.15 %) at 8192. The totals are within
0.001 % of PFP-5's profile at `842efa27`; the call counts are exact.

## 4. Timing — 15 repetitions, `taskset -c 1`, `--prepared`

Same harness as PFP-5 (`bench_pfp5.c`, sha256 `ac605a5a…36f9c`) and fixtures;
one process per arm per repetition, arm order rotated across the four arms.
The statistic is the median of the 15 paired per-repetition ratios, with a
95 % percentile bootstrap interval (20,000 resamples, seed `0x50465036`).
Ratio < 1 means the first-named arm is faster. The full table is
`timing/raw/timing-summary.json`; this is the compact view.

### 4.1 Dedicated squaring vs SOS (B/A — the multiply role is held at SOS)

| workload | A µs | B µs | B/A | 95 % CI | reading |
|---|---:|---:|---:|---|---|
| `modexp2048` | 2,984.4 | 3,228.5 | **1.0822** | [1.0766, 1.0831] | 8.2 % slower |
| `modexp8192` | 215,900.9 | 216,952.9 | **1.0048** | [1.0026, 1.0051] | 0.5 % slower |
| `rsa2048` | 1,045.9 | 1,169.8 | **1.1174** | [1.1168, 1.1218] | 11.7 % slower |
| `dh-ffdhe2048` | 2,984.6 | 3,230.3 | **1.0825** | [1.0780, 1.0843] | 8.3 % slower |
| `dh-modp2048` | 2,984.6 | 3,233.2 | **1.0834** | [1.0801, 1.0840] | 8.3 % slower |

### 4.2 CIOS vs SOS (C/A — every Montgomery operation, both roles)

| workload | C µs | C/A | 95 % CI | reading |
|---|---:|---:|---|---|
| `modexp2048` | 2,478.3 | **0.8274** | [0.8232, 0.8347] | 17.3 % faster |
| `modexp8192` | 180,883.6 | **0.8379** | [0.8376, 0.8383] | 16.2 % faster |
| `rsa2048` | 873.6 | **0.8356** | [0.8342, 0.8363] | 16.4 % faster |
| `dh-ffdhe2048` | 2,468.4 | **0.8265** | [0.8212, 0.8281] | 17.4 % faster |
| `dh-modp2048` | 2,471.9 | **0.8282** | [0.8246, 0.8304] | 17.2 % faster |

### 4.3 Dedicated squaring vs CIOS (D/C — the multiply role is held at CIOS)

| workload | D µs | D/C | 95 % CI | reading |
|---|---:|---:|---|---|
| `modexp2048` | 3,128.4 | **1.2628** | [1.2574, 1.2677] | 26.3 % slower |
| `modexp8192` | 204,882.7 | **1.1323** | [1.1320, 1.1331] | 13.2 % slower |
| `rsa2048` | 1,132.8 | **1.2963** | [1.2957, 1.2975] | 29.6 % slower |
| `dh-ffdhe2048` | 3,127.5 | **1.2678** | [1.2619, 1.2718] | 26.8 % slower |
| `dh-modp2048` | 3,126.9 | **1.2662** | [1.2614, 1.2689] | 26.6 % slower |

### 4.4 What the ratios say

The direct squaring-role comparisons are **B/A** (SOS multiply fixed) and
**D/C** (CIOS multiply fixed). Dedicated squaring loses both, with intervals
excluding 1 at every width and workload. Derived per-operation ratios (not
independent measurements): `T_CIOS/T_SOS ≈ 0.827` (2048) and `0.838` (8192);
`T_dedicated/T_SOS ≈ 1.10` (2048) and `≈ 1.01` (8192);
`T_dedicated/T_CIOS ≈ 1.32` (2048) and `≈ 1.16` (8192). The ranking for the
squaring role is **CIOS < SOS < dedicated** at this composition.

The `ecdsa256` control moved by at most 1.2 % across arms (130.9–132.3 µs) and
is not on the changed path; its small movement is control noise, not a result.

### 4.5 Against PFP-5's record

The production selection did **not** change, so no new candidate/authority ratio
is claimed and the PFP-5 authority figures were not re-measured in this run.
The absolute A medians reproduce PFP-5's candidate figures:

| workload | PFP-5 candidate µs | new A µs | difference | PFP-5 candidate/authority |
|---|---:|---:|---:|---:|
| `modexp2048` | 2,977.3 | 2,984.4 | +0.24 % | 2.501 |
| `modexp8192` | 215,773.2 | 215,900.9 | +0.06 % | 2.927 |
| `rsa2048` | 1,045.4 | 1,045.9 | +0.05 % | 2.982 |
| `dh-ffdhe2048` | 2,977.9 | 2,984.6 | +0.22 % | 2.500 |

The differences are inside the recorded run-to-run spread; the same selection
produces the same performance. PFP-5's ratios stand. If CIOS were admitted the
candidate would move by the measured `C/A` factor, but it is not admitted here.

## 5. Correctness at the same digest

The PFP-5 ABI transcript harness (`pfp5_diff.c`, unmodified) run against the
authority `611e511d…efd2`:

| arm | transcript lines | vs authority | MX | RSA | DH |
|---|---:|---|---:|---:|---:|
| A | 161 | **IDENTICAL** | 150 | 8 | 2 |
| B | 161 | **IDENTICAL** | 150 | 8 | 2 |
| C | 161 | **IDENTICAL** | 150 | 8 | 2 |
| D | 161 | **IDENTICAL** | 150 | 8 | 2 |

`differential/raw/{authority,a,b,c,d}.txt` and `differential/raw/summary.txt`.
The PFP-6 per-kernel congruence/differential tests also pass in the full suite
(§8), so B/C/D were timed as numerically correct variants, not as experiments
that might be wrong.

## 6. Taint at the re-evaluation source (source-bound)

`bn::arith::tests::ctgrind_secret_exponent_window`, the PFP-5 test unchanged,
with the exponent's limb bytes marked undefined, under valgrind memcheck:

* **0 errors from 0 contexts**; 1 test passed (0.11 s).
* The test binary is a debug build with `CARGO_PROFILE_TEST_DEBUG=0`: the
  debuginfo=2 build aborted with `Allocation failed` under the court's 4 GiB
  `RLIMIT_DATA`, and the smaller unit was used instead. Assertions are
  unchanged (opt-level 0). This is **source-bound, not DSO-bound**, and is not
  a constant-time proof. The DSO-bound result remains PFP-27's at `5e75b694`,
  which is a different digest and is not transferred.

## 7. Branch audit at the new digest

`binary_branch_audit.py` with the PFP-5 targets, `--expect-sha256 66138460…`,
exit 0, both targets resolved uniquely with complete disassembly:

| carrier | bytes | insns | jcc | div | cmov | setcc | jo/jno | loop | calls | cpuid |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `run_mont_ladder` | 5,821 | 1,255 | 100 | **0** | 2 | 18 | 2 | 0 | 70 | **0** |
| `mont_mul_sos_into` | 1,013 | 249 | 19 | **0** | 0 | 10 | 0 | 0 | 5 | **0** |

The counts, addresses and sizes are identical to PFP-5's audit at `842efa27`;
the DSO digest differs because the surrounding link differs. PFP-5's per-site
classification therefore applies to the same emitted functions: the `jcc`s are
public loop/geometry/bounds checks; the `setcc`s are carry/borrow *data* writes
consumed by `adc`/`or`/`mov`/`movzbl`, none reaches a `jcc`; **secret-derived
entries: none**. The audit is a review aid, not a constant-time proof; the
taint run is the independence evidence and is source-bound (§6).

## 8. Repository gates

| check | result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean (`CARGO_PROFILE_DEV_DEBUG=0`) |
| full library suite | **2,491 passed, 0 failed, 54 ignored** (`--test-threads=4`, `CARGO_PROFILE_TEST_DEBUG=0`) |
| unsafe changes | none; the source change is a doc comment. The experimental patches were restored; the three unsafe lints, the `CRYPTO_*` seam and every `#[repr(C)]` layout are untouched |
| `AGENTS.md` | untouched |

## 9. FIOS and almost-Montgomery

**Not evaluated now; the reason is measured, not assumed.**

* **FIOS** is another integrated schedule. The measured lever at this
  composition is already the integrated family: CIOS is **0.827×** the SOS
  operation at 2048 (0.838× at 8192) because it is used for *both* the 83 %
  squaring share and the multiply share. FIOS differs from CIOS in the
  product/reduction interleaving within a limb; its expected delta over CIOS is
  smaller than the CIOS-over-SOS delta measured here, and it would need its own
  `T < m·R`/lazy-representation argument, per-kernel differential and branch
  audit. It is worth evaluating **after** CIOS is admitted, as a CIOS
  alternative; evaluating it first would spend a new boundary on a smaller
  expected effect.
* **Almost-Montgomery** is not a drop-in schedule: it changes the canonicality
  contract (a lazy range with a final correction) and therefore the
  representation/domain that the window's `a·b < m·R` induction and the
  conversion sites rely on. It would need its own bound proof, differential,
  and compatibility/ownership analysis. At this composition the simpler and
  larger measured lever is CIOS, so almost-Montgomery is not on the critical
  path.

Both remain open in `ARMS.json` (`PFP6-FIOS-ALMOST-MONT`).

## 10. What this does not establish

* It is not a frontier result (no PMU) and discharges no timing obligation.
* It does not admit CIOS. The CIOS result is a *measurement* at the new digest;
  the PFP-6 default stays `Sos`. Admitting CIOS is a separate measured decision
  and would require a window-aware CIOS branch audit and a DSO-bound taint at
  its own digest.
* The taint is source-bound; there is no DSO-bound taint at `66138460`.
* The candidate is an uncommitted worktree state; `build_relevant_clean` is
  false. Two clean builds reproduce it, but it is not reproducible from a
  commit.
* A branch audit is not a constant-time proof; absence of a detected
  secret-derived transfer is not a proof of constant-time behaviour.
