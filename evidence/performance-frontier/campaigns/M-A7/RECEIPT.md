# M-A7 receipt — carry-save accumulation (experiment, measured refusal)

**Queue item:** M-A7. **Claim class:** `SCOPED_OBSERVATION` on the court venue;
wall-clock ns/op, no PMU. **This is an experiment, not a candidate.** Nothing is
integrated, no production path is changed.

```yaml
task_id:            M-A7
title:              Carry-save (redundant-accumulator) CIOS, safe Rust
phase:              performance-frontier
stage_branch:       staging (no commit by this agent)
source_identity:
  parent_sha:       450b8352
  result_sha:       none — nothing is committed
  files_added:      src/bn/carry_save.rs (research prototype, 5 unit tests)
                    evidence/performance-frontier/campaigns/M-A7/**
  files_modified:   src/bn/mod.rs (declaration only: `#[allow(dead_code)]
                    pub(crate) mod carry_save;` — crate-internal, no export)
  untouched:        src/bn/arith.rs, Cargo.toml, Cargo.lock, build.rs,
                    docker/, .frf/, docs/PERFORMANCE-FRONTIER-TODO.md
authority_contract: none (measurement + differential only); the compared kernel
                    is the admitted mont_mul_cios_fixed::<N, N+2>
                    (src/bn/arith.rs:2005-2076), transcribed verbatim into the
                    harness
ownership_before:   not applicable (no object, allocator or ownership seam)
ownership_after:    not applicable
mechanisms:         none (measurement arm)
unsafe_ops:
  removed:          0
  retained:         0
  introduced:       0
boundary:           none; the prototype is zero-unsafe safe Rust
obligations:
  discharged:       the accumulator bound (identical CIOS invariant, reused);
                    the redundant-pair exactness argument (carry absorbed then
                    cleared; shift is the base index)
  retained:         constant-time not measured; cleansing is best-effort;
                    correctness is differential over tested inputs, not a proof
  introduced:       none in the product
compatibility_delta: no compatibility claim; correctness evidence is the
                    differential below
safety_checks:      fmt clean; clippy --all-targets -D warnings clean; focused
                    tests 5/5; full library suite 2521 passed / 0 failed /
                    56 ignored (test_sigstore_bundle skipped). Miri/sanitizers/
                    ctgrind NOT_RUN.
graduation:         none — not a conversion batch, no admission
verdict:            REFUSED (measured). 2.54-2.83x slower than CIOS.
residuals:          §7
```

## 1. What was asked and what was found

The hypothesis: keep radix-2^64 limbs and remove the serial `adc` carry chain from
the CIOS accumulation by holding the accumulator as a redundant `(sum, carry)`
pair, then propagate once at the end. The measured outcome:

* **256-bit (4 limbs): 2.54-2.56x slower** than the admitted fixed-width CIOS.
* **1024-bit (16 limbs): 2.70-2.83x slower.**

The hypothesis loses at both campaign widths, by far more than the ~1.5 % noise
band. The pre-registered prediction (BOUNDS.md §4) was parity at 1024 bits and a
loss at 256 bits; the carry chain was already overlapped well enough that
removing it does not pay for the redundant accumulator's extra additions and
memory traffic.

**This is not M-A2.** M-A2 changed the digit width to 52 bits (an extra limb,
56.25 % more limb products, 3.4x loss at 256 bits). M-A7 keeps `n` limbs and
exactly `2n^2` limb products; it changes only when carries are propagated. The
M-A2 refusal is not evidence against this arm, and this refusal is not evidence
against a redundant accumulator on hardware with a wider multiplier array.

## 2. Identity and venue

- One standalone release binary in the court: prototype included by source path
  (`/work/src/bn/carry_save.rs`) and the admitted fixed kernel transcribed
  verbatim; both are timed in the same process, same instrument.
- Build: `cargo build --release` with only the crate's release setting
  (`overflow-checks = true`); default `opt-level=3`. **No release `--test` build.**
- `taskset` to a single core; two runs on different cores (2 and 6); 41 alternating
  rounds each, 300k iterations/round at 4 limbs and 60k at 16 limbs.
- Raw samples: `raw/measurements.txt`; harness: `raw/harness/`.

## 3. The bound, as pre-registered

`BOUNDS.md` contains the full dependency-depth analysis and the pre-registered
numbers. In summary:

| quantity | value (n=4) | value (n=16) |
|---|---:|---:|
| limb products | 32 | 512 |
| CIOS serial carry chain | length n per row, 2n rows | 4 / 32 rows |
| CIOS critical-path adder levels | ~2n | 8 | 32 |
| CIOS throughput floor | ~48 cycles | ~768 cycles |
| measured CIOS gap to floor (M-A1/M-A2 anchors) | ≤4 % | ~15 % |
| **predicted removable fraction** | **≤4 %** | **~15 %** |
| predicted `T_cs/T_cios` | 1.00-1.30 | 0.95-1.05 |
| **refusal permission** | ≤1.5 % band or slower | same |

The redundant design replaces the carry chain with 4-6 independent 128-bit adds
per position (two product rows folded into one pass in the measured prototype),
so its work floor is *higher* than CIOS's. That is the mechanism of the refusal.

Literature is cited in `BOUNDS.md` §6, technique only: Koç/Acar/Kaliski
(CIOS/SOS taxonomy, IEEE Micro 1996), Tenca–Koç (carry-save Montgomery, CHES
1999), Koç (RSA hardware TR-801), Gueron (ePrint 2011/239, two-chain
`mulx`/`adcx`/`adox`), Intel ADX whitepaper. No code is copied or linked.

## 4. Prototype design and location

`src/bn/carry_save.rs`, declared `#[allow(dead_code)] pub(crate) mod carry_save`
in `src/bn/mod.rs` with the same honest allowance PFP-10's `divstep` used. It is
**not test-only** because the standing pattern puts a research prototype beside
the kernel it is compared with, and because the timing harness includes the same
source file (so the measured code is the tested code). Nothing calls it.

- Redundant pair `V = Σ_p (s[p] + c[p])·B^(p-off)`, `B = 2^64`.
- One descending pass per iteration accumulates both `a*b_i` and `u*m`; `u` is
  computable before the pass because the base column depends only on `s[0]`,
  `c[0]`, `a[0]*b_i`.
- No position reads a value written earlier in the same pass (descending order);
  the base column's carry is absorbed into its own `z` and then cleared; the shift
  is the loop index, with the dropped column's carry already in `c[off]`.
- Final single propagation pass, then the admitted kernel's masked conditional
  subtraction, transcribed.
- Constant-time discipline: compile-time loop bounds, no value-dependent branch,
  no secret-derived index, no early exit except public geometry/parity. All
  128-bit sums use `wrapping_*` so the release profile's overflow check (a
  condition on secret limbs) stays out of the loop, as `mul_add_carry` does.
- `impl_cs_width!` instantiates 4 limbs (10 scratch words) and 16 limbs (34).

**Prototype strengthening note.** The first implementation used runtime-offset
indexing and an opaque scratch pointer and measured 3.01x / 3.52x. The dated
refusal is against the *improved* implementation (fixed-index arrays, the two
rows folded into one pass), measured 2.54x / 2.70-2.83x — i.e. the refusal is
conservative in the sense that a harder-working but no-faster variant was
replaced by a faster one before the verdict.

## 5. Measurement table (ns per Montgomery multiplication)

Run A = core 2, Run B = core 6, same binary, same inputs, 41 alternating rounds.

| width | run | CIOS median | carry-save median | **ratio (median)** | CIOS min | CS min | ratio (min) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 4 limbs (256-bit) | A | 13.25 ns | 33.75 ns | **2.546** | 12.97 ns | 33.16 ns | 2.556 |
| 4 limbs (256-bit) | B | 13.44 ns | 34.34 ns | **2.556** | 12.97 ns | 32.98 ns | 2.543 |
| 16 limbs (1024-bit) | A | 187.25 ns | 504.81 ns | **2.696** | 182.00 ns | 495.84 ns | 2.724 |
| 16 limbs (1024-bit) | B | 182.66 ns | 516.38 ns | **2.827** | 180.99 ns | 498.20 ns | 2.753 |

Observations:

- The CIOS anchors agree with the campaign's earlier fixed-width figures
  (~13 ns at 256 bits, ~180 ns at 1024 bits in this venue), so the transcription
  is measuring the same kernel class.
- Between-run medians for the same kernel differ by ≤2.3 %, and minima by <1 %.
  The ratio is 2.54-2.83 across runs and cores; the direction and rough magnitude
  are invariant, and the gap is ~two orders of magnitude above the 1.5 % band.
- The refutation does not depend on the exact ratio: redundant accumulation
  cannot use *fewer* µops than CIOS (it adds state and additions). Even halving
  the redundant-add cost would leave it ≥1.25x slower at 16 limbs.

## 6. Differential results

**STOP condition:** any mismatch. None fired.

| venue | width | canonical pairs | non-canonical pairs | mismatches |
|---|---:|---:|---:|---:|
| crate tests (debug), vs generic CIOS **and** SOS | 4 | 11,140 | 1,132 | **0** |
| crate tests (debug), vs generic CIOS **and** SOS | 16 | 6,627 | 705 | **0** |
| harness (release), vs fixed-width transcription | 4 | 20,000 | — | **0** |
| harness (release), vs fixed-width transcription | 16 | 20,000 | — | **0** |

Total **59,604** pairs, 0 mismatches. Canonical pairs are additionally checked
against the independent SOS reference (schoolbook multiply + REDC); CIOS and SOS
must agree with each other and with the prototype. Corners covered:

- modulus `= 1` (4 limbs): agreement with CIOS; canonical case is zero;
- even modulus: both prototype entry points refuse (`None`), matching the
  caller's admission rule;
- non-canonical operands `m`, `m+1`, `m+2`, `R-1`, all-ones, top-limb-only,
  `m-1`, `m-2`, `m/2`, `0`, `1`, one-limb and top-only;
- the campaign's moduli: P-256 p and order, `B^3+1`, odd all-ones, mixed
  occupancy; at 16 limbs a deterministic mixed 1024-bit modulus, `2^960+1` and a
  nearly-full P-1024-like pattern;
- deterministic pseudo-random sweeps reduced into `[0, m)` (40 values/modulus).

Non-canonical operands are compared against CIOS only: outside `a,b < m` neither
kernel promises canonicality (one conditional subtraction), but they must still
agree, and they do.

## 7. Verdict and residuals

**Verdict: REFUSED (measured negative result).** Carry-save accumulation in safe
Rust does not remove wall-clock from this kernel; it adds it. Cause: the CIOS
carry chain is not the dominant cost at 4 or 16 limbs in this venue (the
throughput floor, not latency, binds), and the redundant accumulator pays 4-6
128-bit additions plus extra memory traffic per position to remove a latency the
out-of-order core was already hiding. This is consistent with PFP-46/PFP-48: the
authority's advantage is the two independent `adcx`/`adox` chains, which is a
codegen organisation, not an accumulation scheme reachable from safe Rust.

No integration is proposed. Had it won, integration would still owe: a branch
audit under the release profile, ctgrind/dudect for secret-dependent flow and
timing, an ABI/export court (none expected: crate-internal), a DSO-level
measurement of the production artefact at the crate's own build settings, and the
`SecretBuf`-backed cleanse path. None of that is run here.

Residuals (stated, not deferred):

1. `PMU_INSTRUCTIONS` / `PMU_CYCLES` — **NOT_RUN**: wall-clock only in this venue.
2. `DSO_TRANSFER` — **NOT_RUN**: both kernels are in the experiment binary;
   absolute ns/op are not claimed for the distribution DSO. The ratio is the
   measured quantity.
3. `CONSTANT_TIME` — **NOT_RUN**: no ctgrind, dudect or generated-code audit. The
   module's fixed loops and mask-only value handling are source-level intent, not
   a timing result (AGENTS §5/§8).
4. `CLEANSE_VOLATILE` — the zero-unsafe prototype clears its scratch and passes it
   through `black_box`; that is best-effort, not an auditable volatile cleanse.
   Integration would use `runtime::secret::SecretBuf` (retained obligation; moot
   for a refusal).
5. `UNIVERSAL_CORRECTNESS` — not claimed; the evidence is a 59,604-pair
   differential, not a proof.
6. `PROCESS_VARIANCE` — one venue, two cores, two runs; medians differ ≤2.3 %.
   The direction is invariant; no claim is made about other microarchitectures.
7. `BOUND_MODEL` — the pre-registered two-pass model predicted parity; the
   measured implementation folds both rows into one pass, which is *stronger*
   than the model, so the refusal is conservative.

## 8. Scope and memory record

**No production path was changed.** `src/bn/arith.rs`, the ladder, the dispatcher,
`Cargo.toml`, `build.rs`, every export, `#[repr(C)]` layout and the allocator seam
are untouched. The only `src/` change outside the new module is its declaration.

Memory protocol per command (all commands in the court):

| command | available before | cap | result |
|---|---:|---:|---|
| `cargo fmt --check` + focused tests | 26 GiB | 4 GiB / 4 GiB swap | pass |
| `cargo test --lib bn::carry_save` | 27 GiB | 4 GiB | 5/5 pass |
| `cargo clippy --all-targets -D warnings` | 27 GiB | 4 GiB | clean |
| `cargo build --release` (harness) + runs | 26 GiB | 4 GiB | pass |
| `cargo test --lib` (BATCH) | 26 GiB | 4 GiB | 2521 pass / 0 fail / 56 ignored / 1 skipped, 118.59 s |

Cap derivation: `min(4g, available - 8g) = 4g` (§24.4 floor 2g). The court was a
pre-existing idle container already capped at 4 GiB; its `memory.events` stayed
`oom=0 oom_kill=0` throughout (checked after the batch). `CARGO_BUILD_JOBS=1`,
`CARGO_PROFILE_TEST_DEBUG=0`, one heavy command at a time, `test_sigstore_bundle`
never run. Swap free was 9 GiB and is advisory this session.
