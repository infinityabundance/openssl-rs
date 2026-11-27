# PFP-6 record — integrated Montgomery multiply and squaring

**State: CIOS ADMITTED (2026-11-27, DSO `6d002db2…`); see `ADMISSION.md`.**
No commit was made (the task forbids it). Source identity is
`staging` `c1d25e10d16bc197e03446619a5330842b411c5c` plus an uncommitted
`src/bn/arith.rs` worktree change (687 insertions, 39 deletions). The previous
attempt left that file modified and uncommitted; this record resumes it.

**Current (2026-11-27):** CIOS is admitted as the constant-time ladder default at
DSO `6d002db2…` (`LADDER_SCHEDULE = Cios`, SOS retained as the reference and
fallback). `ADMISSION.md` carries the per-kernel differential, the 161-line ABI
transcript, the exponent taint plus DSO-bound probe, the CIOS-carrier branch
audit, and the paired timing. FIOS and almost-Montgomery remain open (§9 of
`REEVALUATION.md`); the source change is an uncommitted worktree state.

## Committed-source identity supplement (added 2026-11-26, PFP-27/PFP-28)

The identity statement above is superseded on this point: the `src/bn/arith.rs`
work described here **is committed**. It landed in
`20972901dc5e1d984d1b391ecc9b69d4bd943701` — "PFP-6: integrated Montgomery
schedules compared, with a negative result recorded" (2026-11-26) — and the file
is byte-identical at `staging` `8f771620bba5739fcc830dc23236dd003802c0ec`
(`git diff 20972901d HEAD -- src/bn/arith.rs` is empty; blob `1ea1965`, sha256
`06005795079c9957ba2b35c6816c423b507f427705842284aa9c23d0e0759a1c`).

The artefact measured for PFP-27 is DSO
`5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae`
(source `8f771620b`, `LADDER_SCHEDULE = Sos`), together with the CIOS-default
twin `12023efec3e40444f579c9e88a78653c891448b2ffd2abf9c9c0ee89e0b9f9e8`
(`LADDER_SCHEDULE = Cios`, one line). Records: `ARTEFACT-AUDIT.md` and
`ctgrind/pfp27-2026-11-26/`.

**Not transferred.** The `553e1b8c…` DSO used by the PFP-21/PFP-23 work
deliberately excluded the PFP-6 `src/bn/arith.rs` changes — its build restored
`src/bn/arith.rs` to `c1d25e10d`. Nothing measured on `553e1b8c` (branch audit,
ctgrind, differential, timing) applies to `5e75b694` or `12023efe`, and this
record does not cite it for them. The crossover table below measures C schedule
transcriptions via `bench_mont.c`, not these artefacts, and is marked not
applicable in `ARTEFACT-AUDIT.md` §6.

## Re-evaluation at the PFP-5 composition (2026-11-27)

The PFP-5 five-bit window changed the operation mix to **2,050 squarings and
410 multiplications** at 2048 bits (83.33 % squarings; 8,195/1,639 at 8192).
The dedicated squaring kernel was re-measured in the crate's release DSO at
that mix, with 15 repetitions, `taskset -c 1`, paired ratios and intervals. It
is **slower** than both SOS and CIOS in the squaring role:
`B/A = 1.0822` at 2048 and `1.0048` at 8192; `D/C = 1.2628` and `1.1323`.
`LADDER_DEDICATED_SQUARING` therefore remains **false**. The earlier negative
was a per-kernel C transcription, not a whole-operation measurement at this
mix; the two agree in direction, but the magnitudes do not transfer. CIOS is
**0.8274×** the SOS operation at 2048 (`0.8379×` at 8192) and is the next
measured default decision; it is not enabled in this batch. New default DSO
`66138460…`; A and A2 agree byte for byte. Evidence: `REEVALUATION.md`,
`RECEIPT.md`, `reeval-2026-11-27/`.

## CIOS admission (2026-11-27)

The PFP-6 re-evaluation measured CIOS at **0.8274×** the SOS operation at 2048
bits and **0.8379×** at 8192 (0.8356 RSA, ~0.827 DH) but did not admit it. This
batch admits it: `LADDER_SCHEDULE` selects `MontSchedule::Cios`, and the SOS
reference stays reachable through `mont_mul_fallible` / `MontSchedule::Sos`.

At the admitted digest `6d002db2…` (two clean builds byte-identical; source
`dedb67a5f` + the uncommitted one-constant change):

* **Differential:** CIOS congruence 7,890 / 0 mismatches; CIOS vs SOS exhaustive
  3,018 + sampled 7,890 / 0; SOS 7,890 and squaring 254 / 0. The 161-line ABI
transcript is byte-identical to the 3.6.4 authority for both CIOS and SOS
  (150 MX at 256–8192 bits, 8 RSA CRT/blinding/non-CRT, 2 DH).
* **Gates:** `bn` 159/0; full suite **2,491 passed / 0 failed / 54 ignored**;
  fmt and clippy clean.
* **Taint:** secret-exponent ctgrind **0 errors / 0 contexts**, origins none;
  negative control fires (4 errors / 1 context). DSO-bound base-taint probe
  silent on CIOS and SOS (0 contexts, 3 reps each).
* **Audit (new digest, not inherited):** CIOS carrier `mont_mul_ladder_into`
  `0x58ce60`/`0x36c`: **14 jcc (14 public, 0 secret-derived), 18 setcc (3 public
  geometry, 15 secret carry/borrow flags consumed arithmetically), 0 cmovcc**;
  secret-derived control transfers: none.
* **Timing:** `cand/ref` `modexp2048` **0.8267** [0.8242, 0.8292], `modexp8192`
  **0.8375** [0.8371, 0.8379], `rsa2048` **0.8357**, `dh-ffdhe2048` **0.8272**,
  `dh-modp2048` **0.8276**; `ecdsa256` control 1.0109. `cand/auth` moves to
  2.0690 / 2.4516 / 2.4838 / 2.0709, exactly the PFP-5 ratios times the measured
  factor. The predicted 0.827–0.838 is met.

Evidence: `ADMISSION.md`, `admission-2026-11-27/`.

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

> **Superseded for the CIOS decision (2026-11-27):** the row is DONE for the CIOS
> admission at `6d002db2`. Items 2–5 below are addressed by `ADMISSION.md`; item 1
> (FIOS and almost-Montgomery) remains open, and the candidate is still an
> uncommitted worktree state.

1. **FIOS and almost-Montgomery were not implemented or compared.** The PFP-6
   item names them; the harness records the omission rather than implying a
   result.
2. **The crossover is a C transcription, not the crate's kernels or DSO.**
   **Addressed for the squaring decision (2026-11-27):** the artefact timing in
   `REEVALUATION.md` measures the four DSOs directly and is the evidence for
   keeping dedicated squaring off. The C transcription is marked not applicable
   and is not cited for that decision. What remains open is a DSO-bound
   comparison of *other* schedules (FIOS/almost-Montgomery).
3. **The candidate is uncommitted**, so it is not reproducible from a commit.
   **Still open (2026-11-27).** The re-evaluation built from the worktree state;
   two clean builds reproduce it, but `build_relevant_clean=false`.
4. **No binary branch audit at a candidate digest.** **Addressed at
   `66138460` (2026-11-27):** both targets resolve uniquely; the counts and
   addresses match PFP-5's `842efa27` audit (100/19 jcc, no secret-derived
   transfer). The taint remains source-bound.
5. The ladder default remains `Sos` and dedicated squaring remains off; the
   reference and every path are retained.
