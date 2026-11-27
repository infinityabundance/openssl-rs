# PFP-46 receipt — runtime BMI2 dispatch of the CIOS Montgomery kernel

**Decision: IMPLEMENTED, and the performance hypothesis is REFUTED by
measurement.** Step 1 found a 10.5–28.2 % static instruction reduction (>7× the
1.5 % noise band), so the dispatch was built. Step 5 measured **no latency gain**
on any of the five workloads; modexp/RSA are 1.0–1.6 % *slower* and DH is flat.
The gain is smaller than the step-1 prediction (≈1.3×) because the kernel is
bound by its single carry chain, not by instruction count. Correctness, the ABI
transcript and the 30-row DH court all pass; the library gate passes. **This
should not be landed as a performance change** without a different approach
(e.g. a hand-written ADX kernel, which PFP-41 showed is the only route to the
remaining factor).

## 1. Identity

| field | value |
|---|---|
| branch / HEAD | `staging`, `4fcd2cc4c31ddffcaa365b40f5a51052759c7478` |
| `src/bn/arith.rs` before / after | `2d0f42cc…2906e992` / `25a87a8c…cd8e98b` |
| change | `+93 / −1` in `src/bn/arith.rs`; zero other source edits |
| before DSO (clean HEAD) | `033f7fbf925b7451c016c1d1c1a78bfc31895de1ee0ada677fdfe7718837680b` |
| after DSO (dispatch) | `b890760cc44473071840b811c70a8ecc8e6a856fbabd03527582420e741fbc46` |
| rustc / cargo / cc | 1.98.1 / 1.98.1 / Debian 12.2.0-14+deb12u1 |
| CPU | i9-13900K; host `std_detect`: `bmi2=true adx=true avx2=true` |
| court | `openssl-rs-court`, `memory.max=4294967296` (4 GiB), `oom=0 oom_kill=0` |

Build inputs and hashes: `raw/step1/build-inputs-portable.txt`,
`raw/after/build-inputs.txt`. Source diff: `raw/source-difference.diff`.

## 2. The change and the exact unsafe surface

`src/bn/arith.rs`, no intrinsics and no assembly:

* `mont_mul_cios_fixed` (the existing safe CIOS body) is `#[inline(always)]` in
  optimised builds so it inlines into the feature-qualified wrapper;
* `define_bmi2_cios_wrapper!` generates eight monomorphic
  `#[target_feature(enable = "bmi2")] unsafe fn` wrappers (n = 4, 6, 9, 16, 32,
  48, 64, 128). Each wrapper body is **one call to the same safe body**; it
  contains **no unsafe operation**. The `# Safety` doc states the BMI2
  precondition.
* `mont_mul_cios_dispatch` tests `std::is_x86_feature_detected!("bmi2")` and, on
  success, enters one `unsafe { match m.len() { … } }` block that calls the
  wrappers. The portable `match` below it is unchanged and is the fallback on a
  CPU without BMI2 and on non-`x86_64` targets.

**Boundary ID: `BN-CIOS-BMI2-DISPATCH` — `BOUNDARY_COVERED`.**

| unsafe surface | location | count |
|---|---|---:|
| unsafe *operations* (wrapper calls) | one `unsafe { match … }` block, `arith.rs:2177` | 1 block / 8 calls |
| `unsafe fn` declarations | macro `arith.rs:2096`, expansions `arith.rs:2121–2135` | 8 |
| unsafe ops inside a wrapper body | — | **0** |
| unsafe ops on any other call path | — | **0** |

The only new runtime obligation is the BMI2 feature precondition; the single
`is_x86_feature_detected!` test establishes it before the block. The `_` arm is
the safe generic slice kernel and needs no feature. No schedule, table scan,
cleansing buffer or width-selection logic was changed.

**Inlining is profile-dependent, deliberately.** An unoptimised build does not
need the body inlined, and forcing it there copies the body into caller frames;
`tls13_handshake_and_write_fit_a_32_kib_thread_stack` pins a 32 KiB server stack.
The body is therefore `inline(never)` in the test profile. This is a real defect
found and corrected during the gate (§6), not a pre-existing condition.

## 3. Correctness (measured, not inferred)

* In-crate per-width differential (dispatch vs the generic slice kernel), all
  eight admitted widths over the PFP-6 population and an all-ones modulus:
  **pairs = 8190, mismatches = 0**.
* Unspecialised widths and the out-of-range/geometry cases: fallback pairs match;
  `pfp6_geometry_fails_closed` passes.
* CIOS congruence and SOS comparison: `sos = 7890, cios = 7890, sqr = 254`, all
  canonical and congruent; `pfp6_cios_matches_the_reference` exhaustive = 3018,
  sampled = 7890, mismatches = 0.
* C ABI transcript (`courts/performance-frontier/pfp5/pfp5_diff.c`):
  **authority 161 lines; before 161 IDENTICAL; after 161 IDENTICAL** (MX = 150,
  RSA = 8, DH = 2).
* DH preset court (`courts/performance-frontier/pfp8/keygen_matrix.py`):
  **rows = 30, mismatches = 0**, every row `old==new`.

Raw: `differential/raw/diff-*.txt`, `differential/raw/keygen-matrix.*`.

## 4. Branch audit (new instruction selection, re-derived)

`audit_branches.py` over this DSO's disassembly, same structural rules as M-A1:
every `jcc`/`setcc`/`cmovcc` enumerated; a `jcc` with arithmetic flags or a
`cmovcc` with arithmetic flags aborts.

| symbol | jcc | setcc | cmovcc | secret-derived control |
|---|---:|---:|---:|---:|
| `mont_mul_ladder_into` (carrier) | 32 | 52 | 0 | **0** |
| `mont_mul_cios_bmi2_4` | 1 | 9 | 0 | **0** |
| `mont_mul_cios_bmi2_6 / 9 / 16` | 2 each | 5 each | 0 | **0** |
| `mont_mul_cios_bmi2_32 / 48 / 64 / 128` | 6 each | 9 each | 0 | **0** |
| **total** | | | | **175 sites, 0** |

Class-b (`setcc` on add/adc/sub/sbb) flags are consumed only by `adc`/`add`/
`and`/`mov`/store, never by a branch. Two `jcc`s are sourced by `bt` on the
`std_detect` CPUID cache (public, `a-cpuid`); one is the `mont_geometry_ok`
early return sourced by `or`/`xor` over slice lengths/pointers (public,
`a-geom`, allowlisted in `raw/geometry-jcc.txt`). Raw:
`raw/after/branch-audit.out`, `raw/after/branch-classification.tsv`.

**ctgrind.** The active court image has no valgrind; the pinned tools image
`openssl-rs-court-tools:1` (valgrind 3.19.0) was used in a capped one-off
container. Its emulated CPUID reports **`bmi2=0`**, so
`is_x86_feature_detected!` is false there: the taint run exercised the
**portable fallback**, not the `mulx` wrapper. `exponent_taint errors=0
contexts=0`; the negative control fired (`errors=4 contexts=1`). **Dynamic
ctgrind of the actual BMI2 path is `NOT_RUN`**; the mulx encoding is covered by
the structural audit and by the release ABI court, not by a taint instrument.

## 5. Measurement — before / after, paired, same instrument

`bench_pfp5 --prepared` (modexp/RSA) and `bench_pfp8` (DH), one process per arm
per repetition, arm order alternated, `taskset -c 1`, median of paired
after/before ratios. 15 paired repetitions for DH, 5 for modexp/RSA. Final
after DSO `b890760c…`.

| workload | before µs | after µs | ratio | prediction |
|---|---:|---:|---:|---:|
| modexp-2048 | 2409.236 | 2448.448 | **1.0152** | ≈0.77 |
| modexp-8192 | 175008.107 | 177847.628 | **1.0164** | ≈0.77 |
| RSA-2048 | 636.583 | 642.858 | **1.0106** | ≈0.77 |
| DH shared secret ffdhe2048 | 335.601 | 337.349 | **0.9985** | ≈0.77 |
| DH keygen ffdhe2048 | 459.601 | 461.651 | **1.0105** | ≈0.77 |

The step-1 prediction was a ≈1.3× kernel gain (ratio ≈0.77). The measured
ratios are ≈1.00–1.016: **no workload moved, and modexp/RSA are ~1 % slower.**
The 10–28 % instruction reduction does not become cycles. The plausible cause is
that the portable loop is bound by the single `add`/`adc` carry dependency chain
and by the per-multiply out-of-line wrapper call, not by the removed
`mov rax`/`xor` instructions; PFP-41 §11 already warned that instruction counts
are not cycles. The result reproduces on two independent timing sessions and two
after DSOs (`fe8d65d7…` and `b890760c…`). Raw: `timing/raw/`,
`timing/raw/timing-summary.json`.

## 6. Gate — verbatim

All heavy commands ran under `OPENSSL_RS_COURT_MEM=4g
OPENSSL_RS_COURT_MEMSWAP=4g CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0`; no
release `--test` build; `free -g` `available` was 21–27 GiB and `Swap free`
8–12 GiB before each command, so `available ≥ 16` held and the §24.4 cap
`min(4, available − 8) = 4 GiB` was used every time.

```
FMT_RC=0
$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.24s
CLIPPY_RC=0
$ cargo test --lib -- --test-threads=4
test result: ok. 2516 passed; 0 failed; 56 ignored; 0 measured; 0 filtered out; finished in 142.89s
```

Baseline (clean HEAD, same court, same flags): `2516 passed; 0 failed; 56
ignored`. Final: identical. **No test was newly ignored, removed or weakened.**

Intermediate defect (fixed before the final gate): with unconditional
`#[inline(always)]`, `tls13_handshake_and_write_fit_a_32_kib_thread_stack`
overflowed its deliberate 32 KiB thread stack. Clean HEAD passed 2516; the
unfixed change aborted with SIGABRT. The profile-conditional inline (§2) fixed
it and the full suite then passed. This is recorded rather than hidden.

## 7. Unsafe accounting (PFP-46 delta)

| category | count |
|---|---|
| unsafe operations added | **8 calls, in one `unsafe` block** |
| `unsafe fn` declarations added | **8** (monomorphic BMI2 wrappers; bodies have no unsafe op) |
| unsafe operations eliminated | 0 |
| hidden obligations | **0** |
| ABI / symbol / `#[repr(C)]` changes | **0** |

## 8. Residual obligations

| id | state | note |
|---|---|---|
| `PFP46-PERF` | **REFUTED** | Instruction reduction measured; latency gain not realised (modexp/RSA +1 % regression). Do not land as a perf change. |
| `PFP46-CT-BMI2` | **NOT_RUN** | Dynamic ctgrind of the `mulx` path: valgrind 3.19 reports `bmi2=0`, so only the portable fallback was tainted. Structural audit only. |
| `PFP46-TARGETS` | recorded | Per-target evidence does not inherit: only `x86_64` + BMI2 was measured. `aarch64` and non-BMI2 x86-64 run the unchanged portable kernel and were not timed here. |
| `PFP46-DEBUG-INLINE` | recorded | The test profile keeps the body out of line, so the in-crate dispatch differential does not execute the `mulx` encoding; the release disassembly and ABI court do. |
| `PFP46-VENUE` | recorded | Virtualised court, no PMU; timings are `SCOPED_OBSERVATION`; DH per-repetition outliers reported in `timing/raw/`. |

## 9. Evidence index

`BOUNDS.md`, `RECEIPT.md`, `count_per_product.py`, `step1_build.sh`,
`build_after.sh`, `regen_wrappers.sh`, `run_diff.sh`, `run_ctgrind.sh`,
`run_ctgrind_tools.sh`, `audit_branches.py`, `timing/run_timing.sh`,
`timing/analyse_timing.py`, and `raw/`: `step1/` (counts, disassembly, build
inputs), `after/` (build inputs, kernel and wrapper disassembly, branch audit,
feature probe), `geometry-jcc.txt`, `source-difference.diff`;
`differential/raw/`; `ctgrind/`; `timing/raw/`.
