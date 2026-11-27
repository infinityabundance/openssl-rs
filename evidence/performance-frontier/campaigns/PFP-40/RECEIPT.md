# PFP-40 receipt — RSA blinding re-creation

**Decision.** The bound is not small (whole-op ceiling **1.25×** throughput), but it
is dominated by a safety property. **D1 (the fixed-iteration constant-time inverse,
47 % of the refresh wall) is REFUSED**: adopting the authority's early-terminating
Euclid would make the iteration count depend on the secret blinding factor.
**D2 (the re-blinding exponentiation, 53 %) is IMPLEMENTED** as the safe subset
(≈**1.126×** throughput, 0 % latency). The change is in the working tree,
**uncommitted and uncertified**: the mandatory heavy gate could not be run because
host swap fell below the item's 16 GiB floor (§5). This receipt says exactly what
was and was not observed.

## 1. Identity

| item | value |
|---|---|
| branch / HEAD | `staging`, `82a044343351b83b0cf688c63aa4e59ebc61b556` |
| profiled candidate DSO | `c466ee139f2845fbfb09bb5bcdccf0a4a7f18e3cad0c400073422d55eead1d93` (release, clean tree at the HEAD above) |
| authority | OpenSSL 3.6.4, `forensics/authorities/prefix/openssl-3.6.4-production` |
| fixture | `courts/phase18/timing/fixtures/rsa2048.der`, `e = 65537` (17 bits, one 64-bit limb), `n = 2048` bits |
| instruments | callgrind 3.19.0 (`--toggle-collect` inclusive), direct wall probe, PFP-7 timing harness |
| machine | x86-64, no `avx512f`/`avx512ifma`; `taskset -c 1` for timing |

All measurements in §2–§4 are **pre-change** at this HEAD. The source change in §6
was not measured (gate blocked, §5).

## 2. What was measured

Instrument and arithmetic are in [`BOUNDS.md`](BOUNDS.md) §§1–5. Summary:

| quantity | value | method |
|---|---:|---|
| whole refresh (per 32 calls) | **4,626,363 ns** | per-call wall timestamps (index 32 outlier − steady op) |
| refresh instructions | **119,796,714** | callgrind, `--toggle-collect="*create_param_impl*"`, 3 calls |
| — inversion share | **55.19 %** (66.1 M Ir) | callgrind inclusive |
| — exponentiation share | **44.52 %** (53.3 M Ir) | callgrind inclusive |
| — random draw share | **0.23 %** (0.28 M Ir) | callgrind inclusive |
| — allocation/cleansing share | **0.06 %** | callgrind inclusive remainder |
| inversion wall | **2,215,369 ns** | probe, `BN_mod_inverse` on a `BN_FLG_CONSTTIME` modulus |
| exponentiation wall | **2,487,616 ns** | probe, `BN_mod_exp_mont` with a prepared Montgomery context |
| random draw wall | **8,058 ns** | probe, `BN_priv_rand_range_ex` |
| authority refresh instructions | **4,302,513** (27.85× fewer) | callgrind, `--toggle-collect="BN_BLINDING_create_param"` |

**No per-call allocation gap** (≤0.06 %) and **no draw-size gap** (0.17 % wall).
The two real gaps are the inversion algorithm (D1) and the exponentiation width (D2).

**Baseline latency, 15 paired process repetitions** (PFP-7 harness, 205 calls, the
pre-change DSO):

| statistic | candidate | authority | ratio (95 % CI) |
|---|---:|---:|---:|
| latency (min/op) | 515,480 ns | 340,462 ns | **1.5141** [1.5131, 1.5154] |
| blockmed (row statistic) | 751,732 ns | 350,821 ns | **2.1428** [2.1404, 2.1451] |
| sustained mean | 683,887 ns | 349,040 ns | **1.9593** [1.9275, 1.9669] |
| throughput | 1,462 ops/s | 2,865 ops/s | 1.9593 |

The recorded row figure of ≈2.15× is the blockmed statistic; it is reproduced here at
**2.1428×**. Refresh outliers at call indices `0, 32, 64, …, 192` of 5.04–5.15 ms
confirm the schedule.

## 3. The exact difference from the authority

**(D1) Inversion.** Authority `int_bn_mod_inverse`
(`crypto/bn/bn_gcd.c:197`) → `bn_mod_inverse_no_branch` (`:21`), whose outer loop is
`while (!BN_is_zero(B))` (`:82`) — constant-time division, **data-dependent iteration
count**; 2.89 M Ir / 195 µs. Ours
`src/bn/blinding.rs:799-832` → `limbs::mod_inverse_consttime`, a fixed
`2·64·n + 2 = 4,098`-iteration binary EEA (PFP-10 §2); 66.1 M Ir / 2.22 ms.
**Difference: our inverse is the stronger constant-time property, not slack.**

**(D2) Exponentiation.** Authority `BN_BLINDING_create_param`
(`crypto/bn/bn_blind.c:288-294`) → `BN_mod_exp_mont`
(`bn_exp.c:311`) → const-time path (`bn_exp.c:331-335`) →
`bn_mod_exp_mont_fixed_top`, which sizes the ladder from
`bits = p->top * BN_BITS2` (`bn_exp.c:633-637`: whole limbs, deliberately not
`BN_num_bits`, so zero top bits are not revealed). For `e = 65537` that is **one
limb / 64 bits**. Our `src/bn/mont.rs::bn_mod_exp_mont_impl` sized the same
fixed-pattern ladder from `md.len()` (**32 limbs / 2048 bits**), because a generic
`BN_mod_exp_mont` may carry a secret exponent. On the blinding path the exponent is
public, so this is **32× more ladder**. That is the gap.

## 4. What changed, and what was refused

**Refused (D1).** No change to `limbs::mod_inverse_consttime`. The fixed iteration
count is the property that keeps the work independent of the secret factor; the
authority's faster inverse trades it away. Recorded, not silently omitted.

**Implemented (D2), in the working tree, uncommitted:**

* `src/bn/mont.rs`: `LadderWidth { Modulus, Policy {..}, PublicExponent }`.
  `BN_mod_exp_mont` keeps `Modulus`; the DH method keeps `Policy`; a new
  `PublicExponent` arm sets `width = pd.len().max(1)`. `bn_mod_exp_mont_impl` is
  reused (`pub(crate)`, `# Safety` documented) — **no new `unsafe` declaration and
  no new unsafe operation**.
* `src/bn/blinding.rs`: `create_param_impl` selects `PublicExponent` only when the
  effective hook is the crate's own `BN_mod_exp_mont`
  (`core::ptr::fn_addr_eq`), inside the existing `unsafe` block. A method-supplied
  `bn_mod_exp` hook is still called verbatim.
* Tests added: `the_public_exponent_ladder_matches_the_modulus_width_ladder`
  (ladder at 1/2/modulus limbs vs the variable-time oracle and the modulus-width
  ladder) and `the_scheduled_recreation_still_yields_a_cancelling_pair`
  (40 round trips across the 32-call re-creation on the Montgomery branch).

**Properties preserved.** The 32-call schedule is byte-for-byte unchanged
(`BN_BLINDING_COUNTER = 32`); the distribution of `(A^e, A^{-1})` is unchanged
because `A^e` is computed, not altered — `A` is still drawn uniformly by
`BN_priv_rand_range_ex`, `Ai` is still its inverse with the same coprimality retry,
and independence is unchanged. The CRT result check and its fallback, padding and
implicit rejection are untouched (the change is inside the re-creation only).

## 5. Correctness and gates — verbatim, with the block

Memory gate, as required, before each heavy command (`free -g`, GiB):

| command | available | Swap free | outcome |
|---|---:|---:|---|
| `cargo build --release --lib` | 21 | **17** | ran, DSO built |
| callgrind + probe runs | 21 | **17** | ran |
| 15-rep timing | 21 | **17** | ran |
| `cargo check --lib` | 18 | **17** | **pass** (`Finished dev profile … in 10.20s`) |
| `cargo fmt --all -- --check` (final source) | 24–25 | **10–12** | **pass** (`FMT_RC=0`); formatting does not compile |
| `cargo clippy --all-targets -- -D warnings` | 21–25 | **10–14** | **NOT RUN** |
| the two new tests | 21–25 | **10–14** | **NOT RUN** |
| full `cargo test --lib -- --test-threads=4` (baseline 2513/0/56) | 21–25 | **10–14** | **NOT RUN** |
| post-change RSA latency re-measurement | 21–25 | **10–14** | **NOT MEASURED** |

The swap-free column fell to 10–14 GiB (host `zed-editor` holds 23.6 GiB of swap;
the court container itself is `swap.max=0`). The item requires **≥16 GiB swap free
before every heavy command**, so none was started. **Nothing is certified**: the
final source is rust-analyzer-clean (no errors/warnings) and `cargo fmt`-clean, but
it was not rebuilt by `rustc` after the last refactor and no test ran. The
`cargo check` pass was on the pre-test prototype, not the final tree.

**Correctness status: `NOT_RUN` (blocked), not pass.** A future gated run must
execute the two new tests and the full suite, and treat any differential mismatch as
a STOP, before this change is adopted.

## 6. Latency / throughput after

**Not measured.** The pre-change ratios are 1.5141× latency, 2.1428× blockmed,
1.9593× sustained (§2). The predicted effect of D2 alone is ≈1.126× throughput and
1.000× latency (`BOUNDS.md` §5(ii)); the prediction is **not** an observation.

## 7. Constant-time claim

**NO constant-time claim is made**, and none should be inferred.

* The ladder is the existing fixed-pattern kernel; the secret base (the blinding
  factor) still never selects the schedule.
* The loop length now depends on the exponent's **whole-limb length**. On this path
  the exponent is the RSA public exponent, and the authority declassifies exactly
  `p->top` for the same reason. A secret exponent must not select this arm.
* No branch audit of the changed code was run (blocked), so even the source-level
  claim is unverified.

## 8. Obligations

* **Discharged (measured).** Attribution of the refresh into random / inverse /
  allocation / exponentiation; the Amdahl ceiling; the source-level difference from
  the authority; the identification of the safe subset.
* **Retained.** The fixed-iteration constant-time inverse (D1) remains the cost of
  the stronger property; no cheaper constant-time inverse has been established.
* **Newly introduced.** The `PublicExponent` arm assumes the blinding exponent is
  public. That is true of `RSA_setup_blinding` and of the API's purpose, but it is a
  stated assumption, not proven from the generic `BN_BLINDING_create_param` ABI
  contract.
* **NOT_RUN.** clippy, the two new tests, the full library suite, the post-change
  latency/throughput measurement, an ABI differential transcript, and any branch
  audit. All are blocked by the memory floor and must run before adoption.

## 9. Expected gate commands (for the gated run)

```
docker/openssl-rs-court.sh exec sh -c 'cd /work && \
  CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --lib -- bn::mont::tests::the_public_exponent_ladder -- --test-threads=4'
docker/openssl-rs-court.sh exec sh -c 'cd /work && \
  CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --lib -- the_scheduled_recreation_still_yields -- --test-threads=4'
docker/openssl-rs-court.sh exec sh -c 'cd /work && \
  cargo clippy --all-targets -- -D warnings'
docker/openssl-rs-court.sh exec sh -c 'cd /work && \
  CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo test --lib -- --test-threads=4'
```
Expected full-suite count: **2,515 passed / 0 failed / 56 ignored** (baseline 2,513
plus the two new tests). Any other count is a defect to explain.

---

## 10. GATE — 2026-11-27 (supersedes §§5–6 and every status line they state)

### 10.1 Superseded claims (append-only correction)

| earlier claim | superseded status |
|---|---|
| header: “uncommitted and uncertified … gate could not be run” | still **uncommitted**; now **gated**. Final state: **CERTIFIED WITH DEVIATION** (§10.8) |
| §1 “was not measured (gate blocked, §5)” | superseded by §10.5 |
| §5 “Nothing is certified”; “Correctness status: `NOT_RUN` (blocked), not pass.” | superseded: clippy, both new tests, the full suite and the ABI transcript all ran and passed (§10.3) |
| §5 table rows: clippy / two new tests / full suite = `NOT RUN` | superseded by the observed output in §10.3 |
| §5 “post-change RSA latency re-measurement … `NOT MEASURED`”; §6 “**Not measured.**” | superseded by §10.5 |
| §8 `NOT_RUN` list (clippy, the two tests, full suite, post-change timing, ABI transcript) | superseded for those five; the **branch audit remains NOT_RUN** |

The design decision (D1 refused), §7’s constant-time answer (**NO**), and §8’s
retained and newly-introduced obligations are unchanged.

### 10.2 Identity

| item | value |
|---|---|
| source HEAD | `82a044343351b83b0cf688c63aa4e59ebc61b556` (unchanged) |
| dirty build inputs | `M src/bn/blinding.rs`, `M src/bn/mont.rs` |
| `src_fingerprint` (all `src/**/*.rs`) | `1b7587b7e2a3de15b1dfa6c2475f7f38affe9c1c5dbcc6f43e53d3a7ce721bfc` |
| post-change DSO | `86a636a35ae95eaf8cf0668eed467e9343ea0a6465e849b169696c6c8acd1876` |
| pre-change DSO (kept intact) | `c466ee139f2845fbfb09bb5bcdccf0a4a7f18e3cad0c400073422d55eead1d93` |
| authority `libcrypto.so.3` | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| ABI harness `courts/performance-frontier/pfp5/pfp5_diff.c` | `04098db7211b4ee1fe5947c36b2622cd3558e7713efd45aada3232953af2eb63` |
| timing harness `PFP-7/harness/timing.sh` | `c9f20d06903bd3387b33a7ad5a160e6c4f74e497337edcab77cce094a1681598` |

The DSO was built by the PFP-8 recipe (`cargo build --release --lib --offline`,
then the phase-2 shell object and `libcrypto.ld` version script); the timing and
ABI runs used an unmodified copy of the PFP-7 harness whose only change is its
output `DIR`, so no earlier raw output was overwritten.

### 10.3 Memory gate, cap, and verbatim gate output

**Deviation (recorded as required).** `Swap free` was **10 GiB**, below the
brief’s 16 GiB floor (host editor holds ≈23 GiB of swap; the court itself has
`swap.max=0`). `available` was 25–26 GiB ≥ 16, so work proceeded under the
brief’s §24.4 allowance: `cap = min(4, available − 8) = 4 GiB` (2 GiB floor met).
The court container was recreated at that cap (the previous container had been
left at 8 GiB): `memory.max=4294967296`, `memory_swap=4294967296`,
`memory.events oom=0 oom_kill=0`. All heavy commands used
`CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0`; no release `--test` build.

| command (in court) | available | Swap free | cap | observed |
|---|---:|---:|---:|---|
| `cargo check --lib` | 25 | 10 | 4 GiB | pass |
| `cargo fmt --all -- --check` | 25 | 10 | 4 GiB | `FMT_RC=0` |
| `cargo test --lib --no-run` | 25 | 10 | 4 GiB | test target built |
| `cargo test --lib -- --test-threads=4 bn::blinding::tests` | 25 | 10 | 4 GiB | 16 passed |
| `cargo test --lib -- …::the_public_exponent_ladder_matches_the_modulus_width_ladder` | 25 | 10 | 4 GiB | 1 passed |
| `cargo clippy --all-targets -- -D warnings` (first) | 25 | 10 | 4 GiB | **3 lint errors in new test code** (§10.4) |
| `cargo clippy --all-targets -- -D warnings` (after §10.4) | 26 | 10 | 4 GiB | pass, `CLIPPY_RC=0` |
| `cargo fmt --all -- --check` (after §10.4) | 26 | 10 | 4 GiB | `FMT_RC=0` |
| `cargo test --lib -- --test-threads=4` | 26 | 10 | 4 GiB | 2,515 passed / 0 failed / 56 ignored |
| `cargo build --release --lib --offline` | 26 | 10 | 4 GiB | `Finished … in 50.55s` |
| DSO link (`build_dso.sh`) | 26 | 10 | 4 GiB | `86a636a3…` |
| ABI transcript (`pfp5_diff`, authority vs candidate) | 26 | 10 | 4 GiB | 161/161 `IDENTICAL` |
| PFP-7 timing, 15 paired reps | 26 | 10 | 4 GiB | `TIMING_OK` |

Verbatim result lines:

```
$ cargo check --lib
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 11.28s

$ cargo test --lib -- --test-threads=4 bn::blinding::tests
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 2555 filtered out; finished in 0.04s

$ cargo test --lib -- --test-threads=4 the_public_exponent_ladder_matches_the_modulus_width_ladder
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2570 filtered out; finished in 0.07s

$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 28.64s
CLIPPY_RC=0

$ cargo test --lib -- --test-threads=4
test result: ok. 2515 passed; 0 failed; 56 ignored; 0 measured; 0 filtered out; finished in 114.95s

$ pfp5_diff (ABI transcript)
authority_lines=161
candidate_lines=161
result=IDENTICAL
MX=150 RSA=8 DH=2

$ timing.sh (PFP-7, 15 reps)
latency_ns: candidate median=515768.0 authority median=340371.0 ratio=1.5153 ci95=[1.5129,1.5164]
blockmed_ns: candidate median=640966.1 authority median=350966.5 ratio=1.8263 ci95=[1.8237,1.8416]
sustained_mean_ns: candidate median=608429.9 authority median=349114.2 ratio=1.7428 ci95=[1.7154,1.7452]
throughput_ops_per_s candidate=1643.6 authority=2864.4 ratio=1.7428
TIMING_OK
```

The full-suite count is exactly the expected **2,515 / 0 / 56** (baseline 2,513
plus the two new tests). **No test was ignored, removed, or weakened.**

### 10.4 Changes made by the gate

The tree **compiled as found** (`cargo check --lib` passed); no production code
needed a fix. `cargo clippy --all-targets -- -D warnings` found three findings,
all in the new test code, and each was fixed without behavioural change:

1. `src/bn/blinding.rs`: added the per-block `// SAFETY:` comment the
   `undocumented_unsafe_blocks` lint requires above `BN_MONT_CTX_new`, and moved
   the `// SAFETY:` comment for the `round_trip_cancels` call inside the
   `assert!` so it directly precedes its `unsafe` block.
2. `src/bn/mont.rs`: `.expect("the variable-time oracle answers every case")` →
   `let Some(…) = … else { unreachable!(…) };`, matching the identical
   pre-existing pattern in the neighbouring ladder test (`expect_used` is a
   denied lint here).

Both test targets were re-run after these edits (§10.3). The three lint prompts:

```
src/bn/blinding.rs:1468:20: error: unsafe block missing a safety comment
src/bn/blinding.rs:1485:17: error: unsafe block missing a safety comment
src/bn/mont.rs:2128:50: error: used `expect()` on an `Option` value
```

### 10.5 RSA-2048, before and after (same instrument)

PFP-7 harness, 15 paired process repetitions, `--mode priv-nopad`, 205 calls,
`taskset -c 1`, same authority DSO. Candidate is the post-change DSO
`86a636a3…`; the pre-change column is §2 at `c466ee13…`.

| statistic | before (ratio) | after (ratio, 95 % CI) |
|---|---:|---:|
| latency (min/op) | 1.5141 [1.5131, 1.5154] | **1.5153** [1.5129, 1.5164] |
| blockmed (row statistic) | 2.1428 | **1.8263** [1.8237, 1.8416] |
| sustained mean | 1.9593 | **1.7428** [1.7154, 1.7452] |
| throughput | 1.9593 | **1.7428** (1,643.6 vs 2,864.4 ops/s) |

Latency is unchanged (the steady-state op does not refresh). Throughput improves
by **1.9593 / 1.7428 = 1.124×**, consistent with the §6 prediction of ≈1.126×
for D2 alone; the prediction was not substituted for the measurement.

### 10.6 Properties checked against the change

* **32-call refresh schedule**: the post-change candidate’s outlier calls are
  exactly `i = 0, 32, 64, 96, 128, 160, 192` (7 of 205) — the same schedule as
  §2. The 40-round re-creation test passes on the Montgomery branch.
* **Distribution**: `A` is still drawn by `BN_priv_rand_range_ex`, `Ai` is still
  its inverse with the same coprimality retry, and independence is unchanged;
  the diff only replaces the call that raises the fresh factor to `e`. No line
  of the draw, retry, inversion or counter path was edited.
* **CRT result check and fallback, padding, implicit rejection**: untouched
  (the only build inputs changed are `src/bn/blinding.rs` and
  `src/bn/mont.rs`, and neither is on those paths).
* **ABI**: 161/161 lines identical to the authority (`MX=150`, `RSA=8`, `DH=2`),
  including the RSA CRT-blinded, CRT-unblinded and non-CRT rows. **No
  differential mismatch; no STOP condition.**

### 10.7 Constant-time claim

**NO — unchanged.** No branch audit was run in this gate. The ladder kernel is
unmodified; only the public loop bound changed, and the `PublicExponent` arm’s
public-exponent assumption remains a stated, retained obligation (§8), not a
discharged one.

### 10.8 Final state

**CERTIFIED WITH DEVIATION.** Every required gate ran and passed: compile as
found, `fmt` rc 0, both new tests, clippy `-D warnings`, the full library suite
at the exact expected count, the 161/161 ABI transcript, and the post-change
timing. The recorded deviations are: (1) `Swap free` was 10 GiB, below the
brief’s 16 GiB floor, so the §24.4 cap of 4 GiB was used; (2) no constant-time
claim is made and the public-exponent assumption is retained as an open
obligation. The change remains **uncommitted**; committing is the orchestrator’s
step.
