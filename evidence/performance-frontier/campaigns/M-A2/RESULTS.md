# M-A2 — reduced-radix (2^52) deferred-carry arithmetic: results

**Status: experiment; negative result; no admission.** Nothing is integrated
into `src/`, `Cargo.toml`, `build.rs` or `docker/`. The crate exists to decide a
hypothesis by measurement, as the dedicated-squaring refutation requires.

## 1. Identity

| item | value |
|---|---|
| source | `staging` `f9deefd1937e471b291a198b5f355bf2454c7e7b`; `src/` untouched (verified with `git status --porcelain src Cargo.toml build.rs docker`: empty) |
| experiment crate | untracked `courts/performance-frontier/m-a2/`; `Cargo.toml` `d105f7be…63adb`, `src/lib.rs` `be7007d9…08136`, `src/main.rs` `c95479be…db5a1`, `Cargo.lock` `55fdc284…8b74`; standalone workspace root, no dependencies, `#![forbid(unsafe_code)]` |
| toolchain | rustc 1.98.1 (48a229cea), cargo 1.98.1 |
| venue | existing `openssl-rs-court` container, 8 GiB memory / 8 GiB swap cap, `/work` bind mount; host reports `13th Gen Intel(R) Core(TM) i9-13900K`, 30 vCPUs |
| builds | **A**: `cargo build --release` (opt-level 3, `codegen-units=1`, `lto`, `debug=false`) → binary `8534ef77…bf964a`, 584,016 B. **B** (robustness only): the same with `RUSTFLAGS=-C target-cpu=native` → `d1d4d777…59c9a70`, 591,264 B |
| CPU pinning | `taskset -c 2`, one process at a time |

The CIOS reference is a **line-by-line transcription** of the crate's
`mont_mul_cios_into` (`src/bn/arith.rs:1855-1918`), not the crate kernel linked
into this binary: the kernel is `pub(crate)` and cannot be reached from a
standalone crate without exposing internals. A second 64-bit reference uses the
same algorithm over fixed-size arrays. **Absolute numbers do not transfer to the
DSO**; the fixed-array comparison isolates the radix change from slice and
geometry-check overhead, and the transcription is reported alongside.

Commands (run in the court, from `/work/courts/performance-frontier/m-a2`):

```text
cargo build --release
/tmp/ma2-target/release/ma2 check
taskset -c 2 /tmp/ma2-target/release/ma2 bench --reps=501      # ×3
taskset -c 2 /tmp/ma2-native/release/ma2 bench --reps=501      # ×3
valgrind --tool=callgrind ... ma2 perf --width=W --kernel=K --ops=N
```

Raw outputs, including every JSON line quoted below, are in `raw-samples.txt`.

## 2. Correctness before timing

Population per width: random odd moduli with the top 64-bit limb non-zero (two
"extreme" moduli with the top limb all ones, the rest random); operands from
0, 1, m−1, all-ones limbs in both representations, every single-non-zero-limb
value in both representations (all ordered pairs), 10,000 (256-bit) / 2,000
(1024-bit) random pairs per modulus, and 10 forced-reduction pairs per modulus
(`a = 1`, `b = r*R mod m`, `r` in `{0,1,2,3,m−1}`, both orders).

Each case runs four kernels: 52-bit deferred, 52-bit rotate, 64-bit fixed, and
the 64-bit slice transcription. The two prototypes use different `R`, so they
are differenced through `out52 = out64 * (R64 * R52^-1) mod m`; the 64-bit fixed
and transcribed kernels must agree bit for bit; the two 52-bit schedules must
agree bit for bit. The independent oracle is multiply-then-reduce: schoolbook
multiplication followed by binary long division, with `R^-1 = (2^-1)^k mod m`
computed by square-and-multiply — no Montgomery step, no `n0`.

| width | moduli | pairs | oracle checks | mismatches | non-canonical | conversion failures |
|---|---:|---:|---:|---:|---:|---:|
| 256 bits | 6 | 60,924 | 3,510 | **0** | **0** | **0** |
| 1024 bits | 4 | 13,816 | 872 | **0** | **0** | **0** |
| both | — | 74,740 | 4,382 | **0** | **0** | **0** |

Every output was checked `< m` and canonical in its own radix. `cargo test`
(4 tests), `cargo fmt -- --check` and `cargo clippy --all-targets -D warnings`
are clean.

**A mismatch was a STOP, and it fired.** The first run of the broken
implementation reported 666/60,864 mismatches and 667 non-canonical outputs at
256 bits (exit 2). Root cause and fix are recorded in `BOUND.md` §4: the
incumbent's final subtraction uses a base-`2^64` borrow chain, which is not a
valid base-`2^52` digit chain. After the fix both widths are zero. The same
reading shows why 1024 bits had passed the broken kernel: the
conditional-subtraction branch is reached with probability `≈ m/R = 2^-16`
there, so the forced-reduction family was added and is part of the recorded
counts.

## 3. Timing (single Montgomery multiplication, same binary, interleaved)

A/B are measured in the same process, alternating which goes first each
repetition; reported figures are per-operation medians over 501 repetitions of
batches of 2,000 (256-bit) / 200 (1024-bit) operations, and a paired bootstrap
95% interval over the per-repetition ratios (10,000 resamples). Three separate
processes per build; the three-run range is the relevant between-process
uncertainty.

Build A (default release; primary):

| width | pair (A / B) | A ns (median) | B ns (median) | median ratio, 3 runs | representative 95% CI | ratio from per-rep minima |
|---|---|---:|---:|---|---|---:|
| 256 | 52 deferred / 64 fixed | 43.00–43.29 | 12.57–12.80 | 3.442, 3.412, 3.425 | [3.440, 3.443] | 3.452, 3.424, 3.436 |
| 256 | 52 deferred / 64 slice (transcription) | 43.01–43.24 | 32.56–32.74 | 1.328, 1.320, 1.314 | [1.327, 1.328] | 1.327, 1.316, 1.311 |
| 1024 | 52 deferred / 64 fixed | 309.5–323.1 | 226.4–229.2 | 1.402, 1.373, 1.381 | [1.397, 1.407] | 1.376, 1.376, 1.381 |
| 1024 | 52 deferred / 64 slice (transcription) | 310.1–313.9 | 241.8–242.6 | 1.291, 1.279, 1.282 | [1.290, 1.292] | 1.275, 1.267, 1.269 |

Build B (`target-cpu=native`, robustness):

| width | pair (A / B) | median ratio, 3 runs | representative 95% CI |
|---|---|---|---|
| 256 | 52 deferred / 64 fixed | 3.604, 3.514, 3.605 | [3.603, 3.605] |
| 256 | 52 deferred / 64 slice | 1.366, 1.330, 1.373 | [1.365, 1.366] |
| 1024 | 52 deferred / 64 fixed | 1.368, 1.328, 1.326 | [1.363, 1.373] |
| 1024 | 52 deferred / 64 slice | 1.264, 1.246, 1.228 | [1.262, 1.266] |

Secondary attribution probe (the same 52-bit arithmetic with the per-iteration
accumulator shift replaced by a rotating index): 256 bits **31.6 ns** under
native and 36.0 ns in build A, ratio **2.50** (native) / **2.86** (build A) vs
the 64-bit fixed kernel; 1024 bits **358–455 ns**, ratio **1.61–2.03** (one
process instance at the high end). It is faster than the shift version at 256
bits (the shift costs ≈ 12 ns there) and slower at 1024 bits (masked addressing
costs more than the copied coefficients).

**Instruction counts.** `perf stat` reports `<not supported>` for
`instructions` and `cycles` in this venue (no hardware PMU), so **PMU counters
are `NOT_RUN`**. Dynamic instruction counts come from callgrind instead, as
`(Ir(ops) − Ir(0)) / ops`:

| width | 52 deferred | 52 rotate | 64 fixed | 64 slice (transcription) |
|---|---:|---:|---:|---:|
| 256 bits | **584** | 568 | **328** | 642 |
| 1024 bits | **7,441** | 6,682 | **4,754** | 6,476 |

The 52-bit kernel executes 1.78× (256) and 1.56× (1024) the instructions of the
fixed 64-bit kernel, close to the structural 1.5625× limb-product ratio.

## 4. Decision

**The hypothesis is refuted at both widths. Reduced radix loses.**

- 256 bits: **3.41–3.44× slower** than the fixed 64-bit CIOS (3.51–3.61× under
  `target-cpu=native`); **1.31–1.33× slower** than the crate-shaped slice
  transcription. The rotate variant is still 2.5–2.9× slower.
- 1024 bits: **1.37–1.40× slower** than the fixed 64-bit CIOS (1.33–1.37×
  native); **1.28–1.29× slower** than the transcription. The rotate variant is
  slower still (1.61–2.03×).

The result is **regime-dependent in magnitude but not in sign**: the loss is
about 3.4× at 256 bits and about 1.4× at 1024 bits.

Attribution (measured, plus inference where labelled):

1. **Extra limb products are structural.** `(5/4)² = (20/16)² = 1.5625`; the
   measured instruction ratios (1.78× and 1.56×) agree. Nothing about deferring
   carries removes those multiplies.
2. **At 256 bits the loss exceeds the instruction ratio** (3.4× time vs 1.78×
   instructions). The deferred kernel's inner loop is a 16-byte read-modify-write
   accumulator (two `u128` limbs per coefficient) with a store-to-load
   dependency between the product row and the reduction row, and the settling
   shift copies `N` coefficients per iteration. *Inference:* the reduced-radix
   kernel is throughput/store-bound where the 64-bit kernel is latency-bound, and
   at this small width the 64-bit carry chain is short enough that removing it
   buys little. The rotate probe supports the shift part of this: removing the
   shift recovers about a quarter of the time (43 → 36 ns) but is still 2.5× the
   fixed 64-bit kernel.
3. **At 1024 bits the loss narrows** because the 64-bit CIOS is latency-bound on
   a 16-limb serial carry chain, so the independent-product 52-bit loop recovers
   throughput; the 56% extra products and `u128` traffic still dominate the
   balance. The rotate probe is *worse* here (fewer instructions, more time),
   which attributes the 1024-bit cost to addressing and coefficient traffic
   rather than to the settling shift.
4. The settling pass itself is not the dominant term at either width; the extra
   limb products and the wide accumulator are. This matches the
   dedicated-squaring precedent: an operation-count argument (fewer carries) did
   not survive measurement.

> **PFP-57 note (2026-11-27).** Bullets 2 and 3 attribute the loss to the 64-bit
> kernel being "latency-bound" and the reduced-radix kernel being
> "throughput/store-bound". That is one of two unresolved causal hypotheses
> (`PFP-48` is its counterpart); the measured ratios stand, but no bound in
> `M-A3` to `M-A6` may rest on either explanation until hardware performance
> counters exist.

## 5. Consequence and next step

The measured, useful signal is not the radix but the gap between the two 64-bit
references: the fixed-array 2^64 CIOS is 2.6× faster than the crate-shaped slice
transcription at 256 bits (12.6 vs 32.6 ns) and 1.07× at 1024 bits (227 vs
242 ns), at identical arithmetic. That is **M-A1's hypothesis** (compile-time
width specialisation of the incumbent radix), measured here only as a
by-product and not admitted: it must be re-measured in the artefact at the
crate's own build settings before any claim is made. No reduced-radix variant is
recommended for a second attempt; a smaller radix (2^43, 2^32, 2^26) increases
the limb count (and therefore the product count) further, which the measured
trend rejects.

## 6. Caveats

- The 64-bit references are **in this binary**, not in `libcrypto.so.3`;
  absolute numbers do not transfer to the DSO and no performance claim is made
  about the product.
- `perf` hardware events are unavailable in this venue; instruction counts are
  callgrind counts and timing is wall-clock with turbo and host noise present.
  Between-process variation (quoted as ranges) is larger than the within-process
  bootstrap interval. One 52-bit rotate process instance at 1024 bits recorded a
  2.03× ratio where its siblings recorded 1.61×; the direction is unchanged.
  A per-repetition **minimum** estimator is included for this reason.
- No constant-time, branch-audit, sanitizer or Miri claim is made; the
  experiment only constrains arithmetic behaviour on the tested population.
- The accumulator bound is proved in `BOUND.md`; the correctness result is a
  differential over 74,740 cases and 4,382 oracle checks, not a universal
  correctness proof.
