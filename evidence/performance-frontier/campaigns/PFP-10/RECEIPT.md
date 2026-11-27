# PFP-10 conversion receipt — inversion crossover, nothing integrated

**Decision: DONE by the item's criterion** — the crossover is measured per domain
and size and the conclusion is recorded. **No candidate is integrated**, so the
"clean audit at one digest" conjunct for an integrated winner does not apply.
`ARMS.json` is not updated (no integrated arm, no complete same-digest arm set).

## 1. Identity

| item | value |
|---|---|
| branch / head | `staging`, `b2dbcd1491f16e11101b5d00c761d5fa2590750a` |
| build-relevant working-tree changes | `src/bn/mod.rs` (declare the module, dead-code allowance), `src/ec/p256/fixed_base.rs` (`invert` visibility to `pub(crate)`), new `src/bn/divstep.rs`, new `src/bn/divstep/tests.rs` |
| source fingerprint | `9e764fe9133f15c5b1b21c79b96ec84d2275048bdbe385ea6921e35c8b89f48b` (889 `src/**/*.rs` files) |
| measurement / ctgrind binary | `target/debug/deps/openssl_rs-e1a9da8d91fb8797`, SHA-256 `473a058df52aa58b8328f590dd417082ccee890c9b84108e815a349b28e0dbed` |
| profile | cargo `test`, `opt-level=3`, `debug=0`, `debug-assertions=false`, `CARGO_BUILD_JOBS=1` |
| toolchain | rustc/cargo 1.98.1; valgrind 3.19.0 |
| venue | `openssl-rs-court` container, cgroup 8 GiB / 8 GiB swap, 8 CPUs, `RLIMIT_DATA` 4 GiB, `taskset -c 1` for timing |
| raw samples | `raw-samples.tsv` (225 rows), `results.json`, `analyse_pfp10.py` |

## 2. Authority contract and divergence class

The authority's constant-time inverse is Fermat `x^(m-2) mod m`
(`bn_mod_exp_mont_fixed_top`) for the P-256 order, and the fixed binary extended
GCD (`bn_mod_inverse_no_branch` derived path) for the explicit constant-time
`BN_mod_inverse_consttime`; the variable-time extended Euclidean algorithm is the
fallback. This batch changes **no** deployed path, so there is no behavioural
divergence: all comparisons below are agreed, not substituted. The prototype's
zero behaviour is stated explicitly:

* **zero modulo a prime**: the divstep coefficient is `0` with the all-zeros
  invertibility mask (the gcd is `m`, not one); Fermat computes `0^(m-2) = 0`.
  The P-256 path stores the coefficient for a prime modulus, so it returns `0`,
  matching the Fermat path. This is the same distinction PFP-4 recorded.
* **non-invertible (composite modulus, shared factor)**: mask `0`, companion
  entry point `None`, oracle `None` — matching `mod_inverse_consttime`.
* **even modulus**: refused before any value read (`None`), a property of the
  modulus alone.

## 3. Correctness (before timing)

All counts are from the final source at the fingerprint above.

| population | cases | mismatches |
|---|---:|---:|
| `p256-field`: 1, 2, m−1, m−2, every single-non-zero-limb, top-limb-zero, four non-canonical (m+t), zero, pseudorandom | 2,065 | **0** |
| `p256-order`: same shape | 2,065 | **0** |
| `modp-1024` (RFC 7919 DH1024-160 prime): same shape | 1,053 | **0** |
| `modp-2048` (DH2048-256 prime): same shape | 557 | **0** |
| **total prime-modulus** | **5,740** | **0** |
| composite 256-bit (`p·q`): invertible and non-invertible inputs | 529 | **0** |
| small odd moduli `3..599`, every `0 <= a < m`, vs the extended-Euclidean oracle | > 40,000 invertible pairs (test asserts the count) | **0** |

Each prime case is compared against **two independent oracles**: the Fermat
result (the deployed form for the two P-256 domains, the generic const-time
ladder for the larger sizes) and `limbs::mod_inverse` (variable-time extended
Euclid). Every non-zero case additionally satisfies `a · a⁻¹ ≡ 1 (mod m)`
independently: **5,732 round-trips** (two zero-canonical cases per domain have no
inverse and are excluded from the round-trip count). `fermat_agree` equals
`round_trips` on every domain. A single mismatch is a STOP; none occurred.

The bound is checked separately: `realised_steps_are_within_the_bound` over
widths 4, 5, 8, 16 limbs has worst realised fraction **0.887** of the published
bound (`CONVERGENCE worst_fraction_of_bound=0.8866`).

## 4. Constant-time evidence (prototype, not integrated)

ctgrind technique (`valgrind --tool=memcheck`, `VALGRIND_MAKE_MEM_UNDEFINED` on
the operand) on the binary above:

| case | taint | contexts | error instances | reading |
|---|---|---:|---:|---|
| `ctgrind_control_canary` | 4 limbs, volatile-read/volatile-store branch | **4** | 4 | detector fires (positive control) |
| `ctgrind_secret_mod_inverse_divstep` | order operand (591 divsteps) | **1** | 590 | **one secret-dependent transfer per divstep** |
| `ctgrind_secret_mod_inverse_divstep_1024` | 1024-bit operand (2360 divsteps) | **1** | 2359 | same, scaled to the bound |

The transfer persists after the crate's `black_box` value barriers are applied to
`cond`, `g_odd`, the modular-add correction, the modular-subtract borrow, the
halving mask and the final sign mask. At `opt-level=3` **with debug assertions
on** the same source reports 0 contexts; at release-like codegen it reports one
per step. That is exactly the §21 hazard ("source-level intent is not
constant-time behaviour after optimisation"), and it is a **STOP** for this
candidate: a divstep that makes a secret-derived conditional transfer is not a
constant-time candidate.

The dedicated `CTGRIND_CONTROL=1` path inside the divstep test did **not** add a
context in this build; the standalone `ctgrind_control_canary` was added to
provide a working positive control (4 contexts) and the failed in-test control is
recorded as a limitation, not hidden. The instrument itself is demonstrably
sensitive.

No binary branch audit of a **deployed** object is possible because nothing was
integrated; the audit obligation is therefore `NOT_APPLICABLE (no integration)`,
not "passed".

## 5. Why nothing was integrated

The divstep wins at ≥ ~750 bits (measured; crossover between 521 and 1024) and
against the binary GCD at every measured size. Adoption is blocked:

1. The 256-bit P-256 loci have the branch-free reduced operand but the Fermat
   wins there (1.96–2.04×).
2. The generic ≥ 1024-bit constant-time locus does not guarantee `a < m`, and no
   constant-time general reduction exists; `rem` is variable-time and forbidden
   for a secret operand. The published bound also assumes `0 <= g <= f <= M`.
3. The prototype makes one secret-dependent conditional transfer per step at
   release-like codegen (STOP).

This is a recorded negative with numbers, not a silent omission. Per the W3 rule
there is also no measured consumer that inverts a secret ≥ 1024-bit operand on
the constant-time path.

## 6. Obligations

* **Discharged.** Candidate correctness over 6,269 cases (5,740 prime + 529
  composite) against two oracles plus an independent round-trip; the published
  bound independently validated on the implementation; the crossover measured
  per domain and size with paired intervals.
* **Retained.** The divstep is not constant-time at release-like codegen. No
  constant-time modular reduction for an unreduced operand exists in the crate.
* **Newly introduced.** None in the library: the prototype is safe Rust, adds no
  `unsafe`, and no deployed path calls it.
* **NOT_RUN.** Deployed-DSO timing/`ecdsa256` re-measurement, two-clean-build DSO
  digest agreement, taint and branch audit at a new DSO digest, `ARMS.json`
  update — all **not applicable because nothing was integrated**. They must be run
  if a future batch adopts the divstep.

## 7. Gates

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --all-targets -- -D warnings` | pass |
| full `cargo test --lib -- --test-threads=4` (dev, debuginfo off) | **2,507 passed, 0 failed, 56 ignored** |
| `cargo test --lib -- bn::divstep` (opt-level 3) | 6 passed, 0 failed, 2 ignored |
| ignored `pfp10_large_differential` (opt-level 3) | pass, 0 mismatches |
| ignored `pfp10_bench` (opt-level 3, `taskset -c 1`) | pass, 225 raw rows |

The floor recorded at `a8676158f` was 1,962 library tests; the two ignored rows
added here are the measurement and the large differential, both run explicitly.
No test was removed or newly ignored beyond those two new ignored tests.

## 8. Memory incidents

Recorded in `evidence/incidents/2026-11-27-1/RECEIPT.md`: two `rustc-LLVM out of
memory` aborts inside the 8 GiB court cgroup (an `opt-level=3` full test harness
at `CARGO_BUILD_JOBS=4`, and a dev `--test` build with `debuginfo=2` at
`CARGO_BUILD_JOBS=4`). The reduced units that succeeded: `CARGO_BUILD_JOBS=1`
with `CARGO_PROFILE_TEST_DEBUG=0` (and `DEBUG_ASSERTIONS=false` for the
release-like timing build). `available`/`Swap free` before the heavy commands were
28–31 GiB / 21–25 GiB; the host was never under pressure — the cap was the
container's cgroup.

## 9. Files touched

* `src/bn/divstep.rs` — new safe-Rust prototype (no `unsafe` in library code).
* `src/bn/divstep/tests.rs` — new tests: exhaustive/edge/large differential,
  convergence bound, ctgrind cases and the three-candidate measurement.
* `src/bn/mod.rs` — declare the module with a documented dead-code allowance.
* `src/ec/p256/fixed_base.rs` — `invert` visibility `pub(crate)` only (the test
  measures the deployed field Fermat; no behaviour change).
* `evidence/performance-frontier/campaigns/PFP-10/` — this receipt, `BOUNDS.md`,
  `CROSSOVER.md`, `raw-samples.tsv`, `results.json`, `analyse_pfp10.py`.
* `docs/PERFORMANCE-FRONTIER-TODO.md` — PFP-10 row.
* `evidence/incidents/2026-11-27-1/RECEIPT.md` — the memory incidents.

No `AGENTS.md` was opened, modified, staged, committed or pushed. The campaign
did not commit or push anything.
