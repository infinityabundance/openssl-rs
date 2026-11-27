# PFP-42 receipt — the window table re-evaluated at the policy width

**Decision: PROCEED.** The bound (`BOUNDS.md`) crosses the campaign's noise floor
at the ffdhe2048 policy geometry and at modexp-8192. A public-geometry window
selector is implemented and measured. Correctness is unchanged at the C ABI
(161/161) and on the 30-row DH preset court (0 mismatches). No workload
regressed.

## 1. Identity

| field | value |
|---|---|
| branch / HEAD | `staging`, `e73999b5d9f71ba6abc8d3ae89fabecea4e4c6c1` |
| `src` tree | `2200c5cee7c24357b814cc950033a32929e71a59` |
| build-relevant dirty path | `src/bn/arith.rs` only |
| `arith.rs` before / after | `92057de3…f9739` / `63df636e…5471df` |
| DSO before (HEAD) | `86a636a35ae95eaf8cf0668eed467e9343ea0a6465e849b169696c6c8acd1876` |
| DSO after (selector) | `a6389c0fec26132685f42fd7fa93abe672f397f66521bb5221c6d72c63ec1460` |
| rustc / cargo / cc | 1.98.1 / 1.98.1 / Debian 12.2.0-14+deb12u1 |
| authority | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3` |
| court | `openssl-rs-court`, `memory.max=4294967296` (4 GiB), `memory.events oom=0 oom_kill=0` |

Build inputs and hashes: `raw/before.env`, `raw/after.env`. Source diff
(`+123/−19`, **zero `unsafe`**): `raw/source-difference.diff`.

## 2. The change

`src/bn/arith.rs`:

* `select_window_bits(width, modulus_limbs)` — public-geometry cost model from
  `BOUNDS.md` §2, `u128` saturating, returns `w ∈ 1..=8`, default `w = 5`.
* the three production dispatch paths that hard-coded `LADDER_WINDOW_BITS` now
  pass `Some(select_window_bits(width, md.len()))`:
  `mod_exp_core_consttime_from_parts_prepared` (unprepared arm),
  `mod_exp_core_consttime_policy` (unprepared arm), and
  `mod_exp_core_consttime_prepared`.
* `mod_exp_core_consttime_width` (test-only generic entry) mirrors production.
* `mod_exp_core_consttime_width_with` keeps the explicit-window test API, so the
  bit-at-a-time reference and every fixed `w` remain reachable.
* one new test, `pfp42_window_selection_follows_public_geometry`; the existing
  window differential was extended to `w = 7, 8` and to the selected width on
  the 1024/2048/3072 large-moduli population.

Selected widths (from `raw/cost-model.txt`):

```
ffdhe2048 policy (4,32) -> 4      modexp-1024 (16,16) -> 5
ffdhe3072 policy (5,48) -> 4      modexp-2048 (32,32) -> 5
P-256 order (4,4)      -> 4      modexp-8192 (128,128) -> 7
PFP-43 2400-bit @2048  -> 6      PFP-43 4096-bit @2048 -> 6
```

`w` depends only on the resolved public ladder width and `md.len()`. No exponent
value and no exponent-normalised length is read (the PFP-43 covering width is
already a declassified length, not a value).

## 3. Correctness (before timing)

### 3.1 In-crate differentials

```
$ cargo test --lib -- --test-threads=4 pfp42_
test bn::arith::tests::pfp42_window_selection_follows_public_geometry ... ok

$ cargo test --lib -- --test-threads=4 pfp5_window
test bn::arith::tests::pfp5_window_matches_the_bit_at_a_time_ladder ... ok
test bn::arith::tests::pfp5_window_matches_on_large_moduli ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; ... finished in 5.91s
```

The small-moduli test now runs `w ∈ {4,5,6,7,8}` against the bit-at-a-time
reference; the large-moduli test runs `w = 5` and the geometry-selected `w`
(1024→5, 2048→5, 3072→6) against the reference over 1024/2048/3072-bit moduli.

### 3.2 C ABI transcript — 161 lines, authority vs before vs after

`courts/performance-frontier/pfp5/pfp5_diff.c` (MX 150 at 256–8192 bits, RSA 8,
DH 2). Full output: `raw/diff-*.txt`.

```
ABI before: 161 lines IDENTICAL to authority
ABI after:  161 lines IDENTICAL to authority
ABI authority lines: 161
ABI MX=150 RSA=8 DH=2
```

The after DSO runs `w = 4` (256-bit), `5` (1024/2048-bit), `6` (3072-bit) and
`7` (8192-bit) through the same MX transcript, so the 8192 geometry is
differentially covered end to end, not only structurally.

### 3.3 DH 30-row preset court

`courts/performance-frontier/pfp8/keygen_matrix.py` over ffdhe2048, ffdhe3072
and modp2048, four key-state combinations and the four out-of-range scalars
(`in_bound_225`, `short_1bit`, `long_modulus_2048`, `long_2400bit`). Full output:
`raw/keygen-matrix.out` (31 lines).

```
OK  ffdhe2048/nid/priv_preset_pub_absent/long_2400bit: rc=1 pub=True errs=[] old==new
OK  ffdhe3072/nid/priv_preset_pub_present/long_2400bit: rc=1 pub=True errs=[] old==new
OK  modp2048/nid/priv_absent_pub_present: rc=1 pub=True errs=[] old==new
...
MATRIX rows=30 mismatches=0
```

Every row is also `old==new`: the after DSO's answers equal the before DSO's
(w = 5) answers, so the selector changed the schedule, not the result.

**No differential mismatch. No STOP condition.**

## 4. Measurement

Instrument: `courts/performance-frontier/pfp8/bench_pfp8.c` for DH (named group,
policy ladder width) and `courts/performance-frontier/pfp5/bench_pfp5.c`
(`--prepared`) for modexp/RSA. One process per arm per repetition, arm order
alternated, `taskset -c 1`, i9-13900K under the court; 15 paired repetitions for
bench_pfp8, 5 for bench_pfp5. Statistic: median of the paired after/before
ratios and the median latency of each arm. Raw: `raw/timing/`,
`raw/timing/timing-summary.json`.

| workload | before µs | after µs | ratio (after/before) | per-rep ratio range |
|---|---:|---:|---:|---|
| DH keygen ffdhe2048 | 461.469 | 455.803 | **0.9883** | 0.4757 – 1.0452 |
| DH shared secret ffdhe2048 | 342.979 | 335.685 | **0.9716** | 0.4395 – 1.4477 |
| DH shared secret ffdhe3072 | 980.114 | 959.144 | **0.9821** | 0.7331 – 0.9986 |
| modexp-2048 | 2410.044 | 2407.075 | 0.9978 | 0.9900 – 1.0061 |
| modexp-8192 | 186344.949 | 175143.142 | **0.9401** | 0.9387 – 0.9416 |
| RSA-2048 | 639.404 | 635.797 | 0.9951 | 0.9920 – 1.0027 |

Reading, on both sides as required:

* **ffdhe2048 shared secret** (−2.8 %) is 97.5 % exponentiation (PFP-8 §1.3), so
  it is the clean signal for the `w = 4` schedule; it matches the model's 3.1 %
  for the exponentiation. **Keygen** (−1.2 %) runs the same exponent but is
  diluted by RNG, group lookup and object construction (≈15 %, PFP-8 §1.2), and
  its per-rep spread is the widest of the DH rows.
* **ffdhe3072 shared secret** (−1.8 %) is above the model's 0.55 %; the model is
  an instruction count and the court has no PMU, so this is not claimed as a
  precise number, only as a non-regression with the predicted direction.
* **modexp-8192** (−6.0 %) is the strongest and tightest result: `w = 7` pays,
  it does **not** hurt the large-exponent path. The model predicted 2.61 %; the
  measured scan is cheaper than the model's conservative 3 Ir/limb.
* **modexp-2048** (0.2 %) and **RSA-2048** (0.5 %) are controls where the
  selector returns `w = 5` (unchanged); their movement is the court's noise
  floor.
* **No workload regressed.** The virtualised venue produces per-repetition
  outliers (e.g. 0.44 and 1.45 on the ffdhe2048 compute), which is why the
  statistic is the median of paired ratios and why this is a
  `SCOPED_OBSERVATION`, not a frontier result.

## 5. Gate — verbatim

All heavy commands ran in `openssl-rs-court` under
`CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0`; no release `--test` build; the
court's cgroup cap was **4 GiB** (`memory.max=4294967296`,
`memory.events oom=0 oom_kill=0`). Explicit `free -g` readings before the heavy
commands: **`available` 24 GiB, `Swap free` 12 GiB**. `available >= 16` holds;
swap free is advisory this session (host editor holds ~23 GiB), so the §24.4
cap `min(4, available − 8) = 4 GiB` was used.

| command | available | swap free | cap | result |
|---|---:|---:|---:|---|
| baseline `cargo build --release --lib` | 24 | 12 | 4 GiB | `Finished … in 50.69s`, DSO `86a636a3…` |
| `cargo test --lib -- … pfp42_` | 24 | 12 | 4 GiB | 1 passed |
| `cargo test --lib -- … pfp5_window` | 24 | 12 | 4 GiB | 2 passed |
| `cargo fmt --all -- --check` | 24 | 12 | 4 GiB | `FMT_RC=0` |
| `cargo clippy --all-targets -- -D warnings` | 24 | 12 | 4 GiB | `CLIPPY_RC=0` |
| `cargo test --lib -- --test-threads=4` | 24 | 12 | 4 GiB | **2,516 passed / 0 failed / 56 ignored** |
| after build (`build_one.sh after`) | 24 | 12 | 4 GiB | DSO `a6389c0f…` |
| ABI transcript + DH matrix | 24 | 12 | 4 GiB | 161/161 identical; `rows=30 mismatches=0` |
| paired timing | 24 | 12 | 4 GiB | §4 |

Verbatim gate lines:

```
FMT_RC=0

$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 28.47s
CLIPPY_RC=0

$ cargo test --lib -- --test-threads=4
test result: ok. 2516 passed; 0 failed; 56 ignored; 0 measured; 0 filtered out; finished in 120.63s
```

Baseline was **2,515 passed / 0 failed / 56 ignored**. The new suite is exactly
baseline + 1 new test. **No test was newly ignored, removed or weakened.**

## 6. Constant-time statement

**No constant-time property changed.** The window width is selected before the
ladder from public geometry only (`bits = 64 · resolved width`, `md.len()`); the
masked full-table scan (`select_window_digit`), the table's `SecretBuf`
cleansing, and the fixed `(w, bits)` schedule are untouched. The selector reads
no exponent limb value and no exponent-normalised length; the PFP-43 covering
width is an already-declassified length, not a new channel. The selected `w` is
fixed for a given group configuration.

**What is not claimed.** No ctgrind and no artefact branch audit was run at this
digest. The existing `ctgrind_secret_exponent_window` still passes in the suite
but pins `Some(5)`, so it does not exercise the selector's `w = 4` at the 4-limb
shape. That artefact-bound evidence is source-bound to the PFP-8 digest and is
`NOT_RUN` here — deferred, never inherited as pass (consistent with PFP-39 §9
and PFP-43 §2.3).

## 7. Unsafe accounting (PFP-42 delta)

| category | count |
|---|---|
| new `unsafe` operators in production code | **0** |
| new `unsafe fn` / safe fn that can cause UB | **0** |
| moved/relocated unsafe assumptions | 0 |
| hidden obligations | **0** |
| ABI/symbol/`#[repr(C)]` changes | **0** |

## 8. Residual obligations

| id | state | note |
|---|---|---|
| `PFP42-CT-AUDIT` | **NOT_RUN** | ctgrind + artefact branch audit at `a6389c0f…` for `w ∈ {4,6,7}`; no constant-time claim made |
| `PFP42-VENUE` | recorded | virtualised court, no PMU; timings are `SCOPED_OBSERVATION`; DH per-rep outliers reported |
| `PFP42-EC-WIDTH` | recorded | the selector also moves the 4-limb (P-256 order) production width from 5 to 4; covered by unit differentials and the full suite, not by a dedicated EC timing row |
| `PFP42-POLICY-3072` | recorded | `w = 4` at (5,48) is predicted only −0.55 % (inside noise); kept because it is the model minimum and measured non-regressing |

## 9. Evidence index

`BOUNDS.md`, `RECEIPT.md`, `model.py`, and `raw/`: `cost-model.txt`,
`source-difference.diff`, `before.env`, `after.env`, `diff-{authority,before,after}.txt`,
`keygen-matrix.{json,txt,out}`, `timing/` (per-rep outputs, `run-meta.env`,
`timing-summary.json`), `build_one.sh`, `run_pfp42_diff.sh`,
`run_pfp42_timing.sh`, `analyse_pfp42.py`.
