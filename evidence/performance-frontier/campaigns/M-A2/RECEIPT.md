# M-A2 receipt — reduced-radix deferred-carry arithmetic (experiment)

**Queue item:** `docs/PERFORMANCE-FRONTIER-TODO.md`, M-A2.
**Claim class:** `SCOPED_OBSERVATION` on the court venue; wall-clock + callgrind;
no PMU. **This is an experiment, not a candidate.** Nothing is admitted.

```yaml
task_id:            M-A2
title:              Reduced-radix (2^52) deferred-carry Montgomery experiment
phase:              performance-frontier
stage_branch:       staging (no commit made by this agent)
source_identity:
  parent_sha:       f9deefd1937e471b291a198b5f355bf2454c7e7b
  result_sha:       none — experiment files are untracked; no src/ change
                    Cargo.toml d105f7be…63adb, lib.rs be7007d9…08136,
                    main.rs c95479be…db5a1, Cargo.lock 55fdc284…8b74
authority_contract: none (measurement only); the compared function is
                    mont_mul_cios_into (src/bn/arith.rs:1855-1918), transcribed

ownership_before:   not applicable (no C object, no allocator, no ownership seam)
ownership_after:    not applicable
mechanisms:         none (measurement arm)
unsafe_ops:
  removed:          0
  retained:         0
  introduced:       0
boundary:           none; the experiment crate is #![forbid(unsafe_code)]
obligations:
  discharged:       the radix-2^52 u128 accumulator bound (BOUND.md §2) for
                    256-bit and 1024-bit moduli; the settling-pass carry bound
  retained:         constant-time behaviour is neither measured nor claimed;
                    the differential is over tested inputs, not a universal proof
  introduced:       none in the product; the experiment's final-subtraction
                    obligation is discharged in BOUND.md §4
compatibility_delta: no compatibility claim; correctness evidence is the
                    differential (74,740 pairs) + independent oracle (4,382)
safety_checks:      fmt clean; clippy -D warnings clean; 4 unit tests pass;
                    Miri / sanitizers / branch audit NOT_RUN
graduation:         none — not a conversion batch, no admission
residuals:          see §5
```

## 1. What was asked and what was found

The hypothesis: unsaturated 52-bit limbs let carries be deferred out of the CIOS
inner loops and settled once, removing them from the critical path in safe Rust.
**Measured outcome: the hypothesis loses at both target widths.** 3.41–3.44×
slower than a fixed-array radix-2^64 CIOS at 256 bits and 1.37–1.40× slower at
1024 bits; also slower (1.31–1.33× and 1.28–1.29×) than the crate-shaped
slice transcription. The result is regime-dependent in magnitude, not in sign.
`RESULTS.md` §4 gives the attribution: the structural 56.25% extra limb products,
the `u128` accumulator's read-modify-write traffic and lower throughput at 256
bits, and — at 1024 bits — the same extra products with the 64-bit kernel's long
carry chain partly offsetting them. The settling shift is not dominant.

## 2. Correctness first

| width | pairs | oracle checks | mismatches | non-canonical |
|---|---:|---:|---:|---:|
| 256 bits | 60,924 | 3,510 | 0 | 0 |
| 1024 bits | 13,816 | 872 | 0 | 0 |

The independent oracle is schoolbook multiply + binary long division, with
`R^-1` from `(2^-1)^k`. The prototypes differ in `R` and are differenced through
`out52 = out64 * (R64 * R52^-1) mod m`; the two 52-bit schedules and the two
64-bit kernels agree bit for bit.

**STOP fired on the first implementation**: 666/60,864 mismatches and 667
non-canonical outputs at 256 bits. Root cause: the incumbent's conditional
subtraction borrow chain is base-`2^64`; a base-`2^52` digit chain must mask the
wrapped difference and decide the borrow by comparison. The fix is in
`conditional_subtract` (lib.rs) and `BOUND.md` §4. At 1024 bits the branch is
reached with probability `≈ 2^-16` under random operands, which is why the broken
kernel had passed there; forced-reduction cases were added and the recorded
population exercises the branch at both widths. No mismatch is outstanding.

## 3. Identity and venue

- Court: existing `openssl-rs-court`, 8 GiB / 8 GiB swap cap, one process at a
  time, `taskset -c 2`; host `i9-13900K`, 30 vCPUs. `perf stat` reports
  `<not supported>` for `instructions`/`cycles` (no hardware PMU) → **PMU
  NOT_RUN**; instruction counts are callgrind Ir.
- Build A `cargo build --release`: binary `8534ef77…bf964a` (584,016 B).
  Build B `-C target-cpu=native`: `d1d4d777…59c9a70` (591,264 B). Both prototypes
  are in the same binary; the transcription's absolute numbers do not transfer
  to the DSO.

## 4. Unsafe accounting and scope

| category | content |
|---|---|
| eliminated | none (measurement arm) |
| relocated | none |
| hidden | **0** |
| introduced | **0**; crate is `#![forbid(unsafe_code)]`, no intrinsics, no assembly |
| untouched | `src/`, root `Cargo.toml`, `build.rs`, `docker/`, `AGENTS.md`; no exported symbol or layout changes |

## 5. Residuals (stated, not deferred)

1. `PMU_INSTRUCTIONS` — **NOT_RUN**: hardware events unsupported in this venue.
   Callgrind Ir is the substitute used here.
2. `DSO_TRANSFER` — **NOT_RUN**: references are transcriptions in the experiment
   binary; no claim about the distribution DSO is made or implied.
3. `CONSTANT_TIME` — **NOT_RUN**: no branch audit, ctgrind or dudect run;
   the masked select is transcribed from the incumbent but not re-audited.
4. `PROCESS_VARIANCE` — between-process spread is larger than the within-process
   interval; one rotate instance at 1024 bits recorded 2.03× where siblings
   recorded 1.61×. A per-repetition minimum estimator is recorded alongside the
   median. The direction of the result is invariant across all instances.
5. `UNIVERSAL_CORRECTNESS` — not claimed; the evidence is a differential over
   74,740 cases with 4,382 independent-oracle checks.

## 6. Decision and next step

`DONE` for M-A2 as an **experiment with a recorded negative result**. No
integration. The next arm should be **M-A1** (fixed-width radix-2^64
specialisation): the same arithmetic measured 2.6× faster at 256 bits (12.6 vs
32.6 ns) and 1.07× faster at 1024 bits (227 vs 242 ns) than the crate-shaped
slice kernel in this binary. That is a by-product signal, not an admitted
result — it must be measured in the artefact at the crate's own build settings.
