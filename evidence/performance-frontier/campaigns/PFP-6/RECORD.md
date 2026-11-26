# PFP-6 record — integrated Montgomery multiply and squaring

**State: PARTIAL.** No commit was made (the task forbids it). Source identity is
`staging` `c1d25e10d16bc197e03446619a5330842b411c5c` plus an uncommitted
`src/bn/arith.rs` worktree change (687 insertions, 39 deletions). The previous
attempt left that file modified and uncommitted; this record resumes it.

## What the uncommitted change was trying to do

Integrate the Montgomery arithmetic in `src/bn/arith.rs`:

* `mont_mul_sos_into` — the existing schoolbook-product + REDC reference,
  factored out and returning `bool`;
* `mont_mul_cios_into` — coarsely integrated operand scanning, `n + 2` limbs;
* `mont_sqr_into` — dedicated Comba squaring from operand symmetry + REDC;
* `MontSchedule` (`Sos` default, `Cios`) and `LADDER_SCHEDULE`;
* `LADDER_DEDICATED_SQUARING = false`;
* `mont_geometry_ok`, replacing the `debug_assert!` pair at the old
  `mont_mul_into` (HEAD lines 1629–1630);
* per-kernel tests under `bn::arith::tests::pfp6_*`.

Nothing is stubbed: there is no `todo!()`/`unimplemented!()` and no remaining
`debug_assert!` in the file. `cargo build --release --lib` succeeds; the
default ladder schedule is still `Sos` and dedicated squaring is still off, so
no production behaviour changes.

## Established

### Build and tests (court `openssl-rs-court-tools:1`, 8 GiB cgroup, RLIMIT_DATA 4 GiB)

* `cargo build --release --lib` — pass (21.2 s, no OOM; `memory.events` all 0).
* `cargo test --lib -- bn` — 156 passed, 0 failed (the extra one-test line is
  the `src/bn/recp.rs` subprocess harness re-invoking the binary).
* `cargo test --lib -- p256` — 19 passed, 0 failed.
* `cargo fmt --all -- --check` — clean.
* `cargo clippy --all-targets -- -D warnings` — clean.
* 4 `pfp6` tests pass. No test was weakened or newly ignored.

### Per-kernel differential (Rust, debug test profile)

Each kernel is checked against the defining congruence `out * R == a * b (mod m)`
and `out < m`, independently, over `pfp6_moduli()` (1, 2, 3, 4, 8 and 16 limbs;
P-256's prime; minimal and maximal top-limb occupancy) and `pfp6_operands()`
(`0`, `1`, `2`, `m-1`, `m-2`, `m/2`, one-limb, top-limb-only, all-ones, and a
24-draw pseudorandom sweep), plus an exhaustive one-limb range for
`m in {3,5,7,9,11,13,15,17,31,33}`:

| kernel | cases | mismatches |
|---|---|---|
| SOS congruence | 7,890 | 0 |
| CIOS congruence | 7,890 | 0 |
| SQR congruence | 254 | 0 |
| CIOS vs SOS (exhaustive) | 3,018 | 0 |
| CIOS vs SOS (sampled) | 7,890 | 0 |
| SQR vs SOS (exhaustive) | 144 | 0 |
| SQR vs SOS (sampled) | 254 | 0 |

The congruence checks make the CIOS/squaring evidence independent rather than
transitive through SOS.

### Preconditions and where they are enforced

| precondition | enforced where |
|---|---|
| `a`, `b`, `out`, `diff` exactly `n = m.len()`; `t` exactly `2n+1` | `mont_geometry_ok` — an unconditional `if`, present in every profile; returns `false` before writing; the allocating wrappers propagate `None` |
| `2n+1` does not overflow | `mont_geometry_ok` / `mont_mul_fallible_with` use `checked_mul`/`checked_add`, fail closed |
| `m` non-empty | `ladder_geometry` returns `None` |
| `m` odd | `ladder_geometry` routes an even `m` to the variable-time path; `mont_n0`'s Newton iteration requires odd |
| `m > 1` | `ladder_geometry` returns `Zero` for `m == 1` |
| non-zero top limb (`m >= B^(n-1)`) | normalised `BIGNUM` limb view |
| `n0 = -m^-1 mod 2^64` | `mont_n0`, only for odd `m` |
| `a * b < m * R` (value bound) | **caller contract, not a runtime check** — a check would branch on secret limbs. Induction base: the ladder zero-extends the base (`< R`) and multiplies by `rr = R^2 mod m < m`; its accumulator starts at `R mod m < m`; every kernel returns canonical. `BN_to_montgomery` passes `R^2 mod m`; `BN_mod_mul_montgomery` requires Montgomery residues |
| canonical `[0, m)` output, no lazy representation | the masked conditional subtraction in `redc_into` and CIOS; argued in the module doc's “Lazy-representation composition” |
| no aliasing of `out`/`t`/`diff` | safe call sites pass distinct `&mut` buffers; `mont_sqr_into(a, a)` passes one `&` twice, which is permitted |

The `T < m·R` bound, the CIOS `T_i < 2m` invariant and the lazy-representation
argument are recorded as arguments in the `src/bn/arith.rs` module
documentation, not as restatements. The old `debug_assert!` pair is gone; the
length contract now fails closed in release.

### Crossover (C transcription, `taskset -c 1`)

Instrument: `bench_mont.c` (standalone C transcription of SOS, CIOS, Comba,
dedicated squaring and schoolbook/Karatsuba products), 15 interleaved
repetitions per width, median of per-repetition means, paired 95% percentile
bootstrap CI (20,000 resamples). Host: i9-13900K, `cc` 12.2.0 `-O2 -g`.
**This measures the C schedules, not the crate's kernels or DSO.**

| bits | CIOS / SOS | dedicated SQR / multiply-for-SQR | Karatsuba / schoolbook |
|---|---|---|---|
| 256 | 0.970 [0.968, 0.973] | 1.133 [1.130, 1.134] | 1.063 [1.061, 1.075] |
| 384 | 0.970 [0.966, 0.973] | 1.112 [1.105, 1.114] | 1.030 [1.016, 1.043] |
| 512 | 0.971 [0.968, 0.975] | 1.119 [1.114, 1.120] | 1.017 [1.002, 1.026] |
| 1024 | 0.937 [0.935, 0.939] | 1.068 [1.065, 1.076] | 1.536 [1.488, 1.543] |
| 2048 | 0.909 [0.906, 0.929] | 1.045 [1.042, 1.056] | 1.377 [1.326, 1.423] |
| 4096 | 0.931 [0.929, 0.937] | 1.048 [1.046, 1.052] | 1.268 [1.231, 1.295] |

* **Schedule:** CIOS beats SOS at every measured width (3–9%), with the CI
  excluding 1 throughout. Comba is slower than SOS at every width
  (1.07–1.19×).
* **Squaring:** the dedicated squaring kernel is *slower* than reusing the
  multiply (1.05–1.13×) at every width, so it stays off
  (`LADDER_DEDICATED_SQUARING = false`) despite being correct.
* **Karatsuba:** there is **no measurable crossover** in 256–4096 bits.
  Karatsuba is slower at every width (1.7% at 512 bits up to 54% at 1024 bits),
  and every CI excludes 1. Schoolbook is the right product; do not add
  Karatsuba for this range. The C transcription's Karatsuba branches on data,
  so it is not proposed for the secret path regardless.
* The Rust kernels are branch-free on secret values at source level: fixed loop
  counts over public `n`, mask selects for the conditional subtraction, and
  `wrapping_*` to keep overflow checks out of the loop. **No binary branch audit
  was run**, so this is a source-level statement, not a constant-time proof.

The measured binary's SHA-256 is recorded in `ARMS.json`; the harness source is
`bench_mont.c` (SHA-256 recorded in the measurement population). The untracked
`bench_mont` build product is reproducible from that source and was not kept.

## What remains (why this is PARTIAL, not DONE)

1. **FIOS and almost-Montgomery were not implemented or compared.** The PFP-6
   item names them; the harness records the omission rather than implying a
   result.
2. **The crossover is a C transcription, not the crate's kernels or DSO.** No
   affected API performance row was re-run at a candidate digest. Selecting
   CIOS (or dedicated squaring) as the default is a separate, measured decision.
3. **The candidate is uncommitted**, so it is not reproducible from a commit.
4. **No binary branch audit at a candidate digest.** The branch-free claim is
   source-level only.
5. The ladder default remains `Sos` and dedicated squaring remains off; the
   reference and every path are retained.
