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

---

# PHASE 2 (2026-11-27) — P-521 Mersenne REDC, integrated

The phase-1 blocker was admissibility, not arithmetic. Phase 2 supplies the
exact-group predicate the phase-1 refusal named, stores its verdict in the
opaque `MontCtx`, and adds the shift-and-add REDC it licenses. **The P-521 fast
arm is now integrated; the phase-1 refusal applies only to phase 1.**

## 8. Identity and scope

| item | value |
|---|---|
| branch / head | `staging`, `56a4c0f7ce020938f51d22eafaa8d7af7c8096dc` |
| build-relevant worktree inputs | 6 (`src/bn/mersenne.rs` new; `bn/mod.rs`, `bn/mont.rs`, `ec/p521.rs` new, `ec/mod.rs`, `ec/lib.rs`) |
| candidate DSO | `d672bf83cab7cf63dc403423993d7f4f8b0cf259c3feeb58ca4198732eabda62` |
| candidate build id | `c4ba12a516364ec10585685bda989c1916c2acac` |
| pristine-HEAD DSO (phase-1 candidate) | `dbf3d0a427ad9a63eb9b724f1434e2b48a3a005242e60e450cf49db922653e3a` — byte-identical to phase 1's recorded candidate |
| authority | `openssl-3.6.4-production`, DSO `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| harness | `bench_pfp11` (`8fd79af1…`), and `bench_p256.c` (`0ff3dc49…`, binary `b8efb1fd…`) for the P-256 control |
| profile | release `--lib`, `CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0` |
| venue | `openssl-rs-court`, cgroup 4 GiB / 4 GiB |

## 9. `MontCtx` layout finding

`MontCtx` (`src/bn/mont.rs`) is **not `#[repr(C)]`**: it is an opaque, Rust-owned
`Box` (`try_boxed`, released by `Box::from_raw`), and `BN_MONT_CTX`'s definition
lives in the uninstalled `bn_local.h`, so there is no external mirror. There is
no `size_of::<MontCtx>()` or field-offset assertion; the only layout consts are
the `AtomicPtr<*mut MontCtx>` size/alignment equalities for the cached-context
slot, which a `bool` field does not change. The struct already documents that
its byte size differs from the authority's C struct and that no consumer sees
it. **Adding `mersenne521: bool` is ABI-neutral.**

## 10. Admission predicate and flag lifecycle

* `ec::p521::admits(group)` is one audited unsafe predicate at the existing C
  ABI boundary, mirroring `p256::fixed_base::admits`. It requires the group's
  `field_mul` to be `ossl_ec_GFp_mont_field_mul`; the raw `field` and `order` to
  equal the tracked P-521 `p` and `n`; `cofactor == 1`; `a`, `b` and the affine
  generator `(Gx,Gy)` (`z_is_one != 0`) to equal the tracked values **in the
  Montgomery domain they are stored in**. Encoding is `x·R mod p = (x<<55)
  folded at 521 bits`, an independent shift-and-fold; a test checks it against
  the group's stored `a`, `b`, `Gx`, `Gy`.
* The flag is cleared at the entry of `EC_GROUP_set_generator` and set only on
  success when `admits` is true. `mont_set` clears it on every modulus
  (re)preparation; `BN_MONT_CTX_copy` copies it (group copy copies every group
  parameter first). The named-curve constructor reaches
  `EC_GROUP_set_generator`, so it is covered; `EC_GROUP_set_curve` installs a
  fresh context whose flag is clear. `ec_precompute_mont_data`'s order-modulus
  context is a different `MontCtx` and is never admitted.
* Tests (`ec::p521::tests`): the named curve is admitted; a modified generator,
  a modified order, a different `b` over the same `p`, a foreign method, and
  P-256 each leave the flag clear, and a field/point operation on each does not
  increment the kernel probe. P-256 has no `MontCtx` at all (plain field
  method), which is the strongest form of untouched.

**Unsafe accounting.** The reduction, its dispatch, and the flag read add
**zero** unsafe operations (safe slice arithmetic and a plain `bool`). The new
unsafe surface is exactly the C-ABI-boundary predicate `admits`, the setter
`set_mersenne521_admission` (which reuses the existing `as_mut_mont` borrow
helper), and a `#[cfg(test)]` flag reader. This is the unblocking design phase 1
named; it is reported, not hidden.

## 11. The dormant fold was not reusable

`bn/nist.rs:143` is `BN_nist_mod_521`, and it is **not a Mersenne fold**: its
body delegates to `BN_nnmod` (generic division), and `BN_nist_mod_func` has no
in-crate caller. Independently checked, it is a correctness shim with division
cost — neither fast nor constant-time. It was therefore not reused; the new
kernel is separate.

## 12. Invariant, fold bound, and shape

With `p = 2^521 − 1`, `B = 2^64`, `R = B^9 = 2^576`, `n0 = −p^{-1} mod B = 1`.
The input contract is the generic path's, `T < p·R` (`BN_mod_mul_montgomery`:
`a,b<p ⇒ T<p²<p·R`; `BN_to_montgomery`: `a<R`, `rr<p`; `BN_from_montgomery`:
routed here only for `T < R < p·R`). Step `i` adds `u·p·B^i = u·2^(521+64i) −
u·B^i`; the `−u·B^i` cancels `t[i]`, so each of the **exactly n = 9** steps is a
zero plus a shift-and-add of `u<<9` at limb `8+i`, with fixed carry propagation.
`k = Σu_iB^i < R`, so `T+k·p < 2p·R` and the residue is `< 2p`; one masked
conditional subtraction yields `[0,p)`. Accumulator bound: `T+k·p <
2^1042+2^1097 < 2^1098`, so the 20-limb scratch cannot overflow and `t[18]=0`.
The fold count is proved by the limb count, not assumed; the stray carry is
folded into the subtraction mask rather than branched on.

## 13. Correctness

* **Kernel differential (safe generic oracle):** 74 edge/random canonical
  operands squared = **5,476** multiply comparisons; **131** non-canonical
  REDC inputs (including `p`, `p+1`, `2^576−1`); 1 maximal-operand case —
  **5,608 comparisons, 0 mismatches**. Edge classes: 0, 1, 2, 3, `p−1`, `p−2`,
  top-limb zero, top-only, full nine-bit top, `p`.
* **Authority differential** (`run_diff.py`, new candidate): P-521 48 cases,
  **0** public-key/digest mismatches, **96** cross-verifications (48 each
  direction) **PASS**. P-384 48/0/96, Ed25519 32/0, X25519 36/0, all PASS.
* **In-crate ECDSA:** 16 P-521 sign/verify rounds, all verify; the fast-arm
  probe confirms the arm was entered.

## 14. Branch audit (static, exact digest)

Full detail: `raw/phase2-audit/classification.md`, `redc.sites.tsv`,
`mont_mul.sites.tsv`. Carrier `redc_p521_in_place`: 6 `jcc` (all public), 19
`setcc` (all carry/borrow, arithmetic consumers), 0 `cmovcc`.
`mont_mul_p521_fallible`: 7 `jcc` (6 public + 1 public-length geometry), 8
`setcc` (all arithmetic consumers), 0 `cmovcc`. **Secret-derived control
transfers: 0. Secret-derived addresses: 0.** Every class-(b) flag is consumed
by `adc`/`add`/`sub`/`or`/`and`/`movzbl`. `ctgrind`/`dudect` on this carrier:
**NOT_RUN**; the result is a static disassembly property, not a timing proof.

## 15. Timing (pair ratio = candidate/authority; `head` = pristine HEAD)

11 paired process repetitions, `taskset -c 1`, one digest, same harness.

| operation | head/auth (this run) | phase-1 head/auth | cand/auth (phase 2) | cand/head | speedup |
|---|---:|---:|---:|---:|---:|
| P-521 ECDSA sign | 2.682 | 2.679 [2.674, 2.688] | **1.857 [1.853, 1.861]** | 0.692 | **1.444×** |
| P-521 ECDSA verify | 2.379 | 2.381 [2.370, 2.391] | **1.741 [1.734, 1.750]** | 0.733 | **1.365×** |
| P-256 ECDSA sign | 12.972 | — (control) | 13.040 [13.000, 13.139] | 1.006 | 0.994 |

The pristine-HEAD arm reproduces phase 1 within noise (2.682 vs 2.679; 2.379
vs 2.381), so the comparison is at the same composition. The P-521-only delta
is `−30.7 %` (sign) and `−26.8 %` (verify) in the authority ratio, i.e. a
`1.444×`/`1.365×` field-path speedup — above the `1.138×` bar and above phase
1's 22.7 %/20.4 % prediction, consistent with removing most rather than half of
the reduction multiplications. A second two-arm run gave sign 1.856
[1.851,1.861] and verify 1.749 [1.739,1.762], consistent. P-256 `cand/head` =
1.006 is within the instrument's noise and is backed by the structural fact
that P-256 has no `MontCtx`; the new kernel is unreachable from its field path.

## 16. Gate (final source)

| check | result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --offline -- -D warnings` | PASS |
| `cargo test --lib --offline -- --test-threads=4` | **2533 passed, 0 failed, 56 ignored** |
| baseline | 2521 passed / 56 ignored; 12 new tests, no newly ignored |
| `test_sigstore_bundle` | not run (`--lib`, campaign rule) |

## 17. Memory

Every heavy command ran in `openssl-rs-court` (cgroup 4 GiB / 4 GiB) with
`CARGO_BUILD_JOBS=1`, `CARGO_PROFILE_TEST_DEBUG=0`, `--test-threads=4`, one
command at a time. Observed `available` 24–28 GiB, swap free 3–9 GiB, so
`cap = min(4, available−8) = 4 GiB` throughout; the running court's cap is
4 GiB. No OOM, no incident.

## 18. Residual obligations

1. `ctgrind`/`dudect` on the Mersenne carrier — **NOT_RUN** (static audit only).
2. Miri/ASan on the new code — **NOT_RUN**; the kernel is safe slice code with
   no unsafe operation.
3. Constant-time claim under optimisation — **NOT_CLAIMED**; the static audit
   establishes only the absence of secret-derived control/address at this
   digest.
4. The one new unsafe predicate is at the C ABI boundary by design; if the
   campaign requires zero new unsafe functions even there, this arm must be
   withdrawn rather than reclassified.

## 19. Phase-2 raw evidence

`raw/phase2-differential.json`, `raw/phase2-diff/`, `raw/phase2-timing.json`,
`raw/phase2-timing-p256.json`, `raw/phase2-three-arm.json`,
`raw/phase2-timing3/{p521,p256}/` (99 per-process outputs) and
`run-meta.env`, `raw/phase2-identity/{build,artefact}-identity.txt`,
`raw/phase2-audit/{cand-*.dis,*.sites.tsv,classification.md,carrier-identity.txt}`.
Instruments: `bench_p256.c`, `phase2_timing.sh`, `phase2_before_timing.sh`,
`phase2_compare.py`, `phase2_audit.py`, `phase2_p256_analyse.py`.
