# PFP-11 conversion receipt — per-curve field/reduction/scalar audit, no arm integrated

**Decision: BOUNDED REFUSAL.** All four curves were measured, attributed and
bounded. No fast arm was integrated: P-521 is performance-admissible (field
share 82.65 %, reduction ≈45 %) but the batch's *zero-new-unsafe* and
*exact-group-dispatch* constraints are jointly unsatisfiable on that path
without new unsafe reads or a `repr(C)` change. The other three curves are
non-selected refusals with arithmetic. No source file was modified, so
`ARMS.json` is unchanged and there is no integrated arm to audit. Full text:
`BOUNDS.md`.

## 1. Identity

| item | value |
|---|---|
| branch / head | `staging`, `dcf49b408e49b5197eb0a20035f423fc7f605649` |
| build-relevant working-tree changes | **none** (`git status --porcelain -- src Cargo.toml Cargo.lock build.rs` = 0 lines) |
| source tree | `eb5cf87f7aab4529463cc1eaed0a3b56f2fcc96d` |
| candidate DSO | `dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a` |
| candidate archive | `e3a5652904a8952b756055bcc5e155085b3d5f707bc61d3b517de0eae9d80deb` |
| candidate build id | `ec3c97cfe3a75d5c50ee64836593a2eeaabad8a2` |
| authority | `openssl-3.6.4-production`, DSO `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness | `bench_pfp11.c` source `a92b64f4b3de50e76caba32810daeadf31d888dc82d7a7c3aaa8897db462f835`, binary `8fd79af139a5002e0fa55b86ca005a4f20970a82f76af56a7465e411ba72de62` |
| profile / toolchain | cargo `release --lib` for the DSO, `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`; `cc` Debian 12.2.0; valgrind 3.19.0 |
| venue | `openssl-rs-court` (minimal image, cgroup 4 GiB / 4 GiB swap) for build, timing, differential and gate; `openssl-rs-court-tools` (separate name, same 4 GiB cap) for callgrind only |

Every heavy command's memory: `free -g` read immediately before it, `available`
≥ 16 GiB required. Observed: 23, 23, 23, 23, 24 GiB available; swap free 10-11
GiB (< 16 throughout), so cap = min(4, available − 8) = **4 GiB** on every
command. No command ran above the cap and no OOM occurred. One heavy command
at a time; the tools court was brought down before the gate. No release
`--test` build was made; `cargo test --lib` does not include
`test_sigstore_bundle`.

## 2. What was measured

* **Source audit** (BOUNDS §1): P-384 and P-521 use 6- and 9-limb Montgomery
  CIOS REDC (`bn/arith.rs:2102-2103`) inside `EC_GFP_MONT_METHOD`; X25519 uses
  `Fe64` (2^256−38) with `Fe51` fallback; Ed25519 uses `Fe` (2^25.5) with
  `fe_conv`/`fe_reduce`. The P-256 engine is not used by any of them.
* **Timing**: seven operations, one digest, 15 process-level repetitions,
  `taskset -c 1`, paired against the pinned authority. Ratios (cand/auth):
  P-384 sign 3.260 [3.255, 3.270], verify 2.758 [2.750, 2.768]; P-521 sign
  2.679 [2.674, 2.688], verify 2.381 [2.370, 2.391]; X25519 1.640
  [1.633, 1.647]; Ed25519 sign 3.693 [3.662, 3.695], verify 4.170
  [4.163, 4.190]. Noise floors are in BOUNDS §2; the X25519 authority floor is
  0.31, all others ≤0.033.
* **Differential**: P-384 and P-521 — 48 cases each (order boundaries q−1/q−2,
  zero/low limb occupancy, full-width pseudorandom, digests above the order),
  0 public-key/digest mismatches, 96 cross-verifications each curve (48 in each
  direction) PASS. Ed25519 — 32 cases, public key and signature byte-identical.
  X25519 — 36 pairs, shared secret/failure byte-identical.
* **Attribution**: callgrind on the exact candidate DSO, all seven operations.
  P-521 sign field-multiply subtree 82.65 % (mul 53.58 %, sqr 29.21 %),
  inversion 4.21 %, order inverse 1.96 %, allocation 24.08 %. Derived
  reduction share: 45.5 % of sign, 41.3 % of verify.

## 3. What was implemented or refused

**Nothing was implemented.** Four explicit refusals:

| curve | ceiling (sign / verify) | reduction-only | decision |
|---|---|---|---|
| P-521 | 82.65 % / 74.03 % | 45.5 % / 41.3 % | **highest value; refused on admissibility** |
| P-384 | 78.32 % / 70.54 % | 43.1 % / 38.8 % | not selected; Solinas, not Mersenne; same blocker |
| X25519 | 58.32 % (Fe51 profile) | fused; <10 % | already curve-specific |
| Ed25519 | 75.32 % / 91.02 % | 6.0 % / 7.3 % | already curve-specific; reduction ceiling <10 % |

The P-521 refusal is not a ceiling refusal. The arithmetic says a 1.138× (sign)
or 1.156× (verify) field speedup clears 10 %, and removing half the reduction
work yields 22.7 % / 20.4 %. It was refused because the required exact-group
dispatch cannot be added under "zero new unsafe": `MontCtx`
(`ec/mont.rs:109-135`) carries only the modulus, not `a`, `b`, generator,
order or cofactor; deciding `admits` needs `EcGroup`/`BIGNUM` reads (new unsafe
operations) or a `repr(C)` field (forbidden). A modulus-keyed safe dispatch
would enter for a modified curve with the same `p`, violating the mandatory
fallback test. The unsatisfiability proof and the unblocking design (admission
flag in the opaque `MontCtx`, set at `EC_GROUP_set_generator`) are in BOUNDS §6.

**P-521 reduction is not generic division.** It is fused 9-limb Montgomery
REDC. `BN_nist_mod_521` (`bn/nist.rs:143`) exists but `BN_nist_mod_func` has no
in-crate caller; the admitted build takes the Montgomery arm (`ec/cvt.rs:55-58`).
For `p = 2^521−1`, `n0 = −p^{-1} mod 2^64 = 1`, so a Mersenne REDC would be
shift-plus-carry, not multiplication — the opportunity is real and is the
reason P-521 ranks first.

## 4. Constant-time position

No new carrier exists, so **no new constant-time claim is made**. The
`n0 = 1` shift-REDC argument is an arithmetic property, not a timing result.
The reported ratios are wall-clock medians under `taskset -c 1`; they are not
a constant-time measurement. No branch audit was run on a new carrier because
there is none; the existing carriers are byte-identical to the tested
candidate (no source change), so their previous audits remain bound to that
source identity. A source-level "no secret-dependent branch" statement for any
hypothetical P-521 fold is explicitly **not** claimed.

## 5. Gate

| check | result |
|---|---|
| `cargo fmt --all -- --check` | PASS (rc 0) |
| `cargo clippy --all-targets --offline -- -D warnings` | PASS (rc 0, no warnings) |
| `cargo test --lib --offline -- --test-threads=4` | **2521 passed, 0 failed, 56 ignored** (111.77 s), exact baseline; no newly ignored test |
| `test_sigstore_bundle` | not run (`--lib`; also excluded by campaign rule) |

The gate was run because the receipt must state it even though no source
changed; it confirms the measured candidate is the testable candidate.

## 6. Residual obligations

All are `NOT_RUN` or `PARTIAL`; none is `PASS`:

1. P-521 Mersenne REDC implementation — **REFUSED** (blocker BOUNDS §6).
2. Differential for an implemented fast arm — `NOT_RUN` (no arm); the
   current-implementation differential is `PASS`.
3. Branch audit of a fast carrier — `NOT_RUN` (no carrier).
4. Constant-time/timing evidence for a P-521 fold — `NOT_RUN` (not implemented).
5. X25519 production-path attribution — `PARTIAL` (valgrind masks ADX, profile
   is the `Fe51` fallback; native timing is `Fe64`).
6. Callgrind symbol resolution — `PARTIAL` (no DWARF; one unexplained 10.34 %
   `fe_conv` entry in the X25519 profile is recorded as resolution noise).
7. P-384 Solinas/NIST path — only established as off-path; no engine.
8. Ed25519 multiplication optimisation — not attempted; only the reduction
   ceiling (6-7 %) was bounded.

## 7. Raw evidence

`raw/build-identity.txt`, `raw/artefact-identity.txt`, `raw/timing.json`,
`raw/timing/` (210 per-repetition outputs + `run-meta.env`),
`raw/differential.json`, `raw/diff/` (per-op case transcripts),
`raw/attribution.json`, `raw/callgrind/*.self.txt` and `*.incl.txt`,
`raw/analyse_ceiling.py`. Instrument sources: `bench_pfp11.c`,
`build_candidate.sh`, `run_timing.sh`, `analyse_timing.py`, `run_diff.py`,
`run_callgrind.sh`, `analyse_attribution.py`.
