# PFP-24 — the `ecdsa256` allocation and conversion budget

Status: **PARTIAL.** The allocation sites are enumerated and ranked, the top
three *redundant* ones are removed, the count per signature falls from **253.6
to 232.2** (`−21.4`, `−8.4%`) with the profile recorded at both ends, and no
correctness or constant-time property was traded for it. The row is not `DONE`
because the **latency ratio did not move**: at the same commit, the three
edits change `ecdsa256` from 239.61 µs to 239.93 µs (ratio 18.82× → 18.83×,
overlapping intervals). The 19.22× → 18.83× movement seen against the older
`553e1b8c` record is a change in the **generated code for the selected ladder
schedule** (`src/bn/arith.rs`, PFP-6), not this item's; the control run in §8
separates them. PFP-27 establishes that the production DSO selects SOS
(`LADDER_SCHEDULE = MontSchedule::Sos`), so CIOS does not execute in this
measurement and is **not** the cause of the movement.

Nothing here is a frontier claim and nothing here discharges T23, T24 or T29.

---

## 1. Identity

| role | object | digest |
|---|---|---|
| before (control) | `court/tmp/pfp24-base/distribution/libcrypto.so.3`, built from the clean detached worktree `court/tmp/pfp24-base-src` at `fc2716652735fb829298d7f426141bd8f9936fc8` | `e93776b494c6843107ebcdb90ccf060a9efcf08ec567c437a1169b9d510d2bcb` (17,067,576 B) |
| after (PFP-24) | `court/tmp/pfp24/distribution/libcrypto.so.3`, built from the working tree at the same commit plus the three PFP-24 edits | `5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae` (17,094,080 B) |
| historical | `court/tmp/pfp21/a/distribution/libcrypto.so.3` (the `553e1b8c` record) | `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4` |
| authority | `openssl-3.6.4-production` | `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |

Both candidate builds use the PFP-21/PFP-23 recipe unchanged
(`cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4`, the distribution
shell, `--whole-archive`, `artifacts/phase2/libcrypto.ld`), through
`alloc-profile/build_candidate.sh`. Source fingerprints: before `32c3a0cc…`
(886 files, clean), after `7e8f93e4…` (886 files, dirty in
`src/bn/bignum.rs`, `src/bn/ctx.rs`, `src/runtime/thread.rs`).

**The `after` candidate is fingerprint-bound, not commit-bound.** The three edits
are not committed (this agent does not commit), so its `build-identity.json`
carries `build_relevant_clean=false` with the modified path list. A second clean
build of the same working tree into a fresh `CARGO_TARGET_DIR` reproduced
`5e75b694` and archive `3d082ac3` byte-for-byte, so the bytes are reproducible
from the recorded fingerprint; they are not attributable to a commit.
`PFP2-DIRTY-CANDIDATE` applies.

Venue: `openssl-rs-court-tools:1`, cgroup `memory.max` 8 GiB,
`memory.events` `oom 0`, `oom_kill 0` throughout; `taskset -c 1`;
`CARGO_BUILD_JOBS=4`; `available` 26 GiB before every heavy command, so
`cap = min(8g, 26 − 16) = 8g`. Host `i9-13900K`, kernel 7.3.5-2-cachyos.

## 2. Instrument

Two independent instruments, and they agree:

* **The campaign's row instrument, unchanged**: `courts/phase18/timing/bench_api.c`
  (`e1add483…`) + `courts/phase18/timing/alloc_probe.c` (`76b432fd…`) in
  `--alloc` mode, exactly as `timing-553e1b8c/run_timing.sh` invokes them
  (`alloc-profile/run_alloc_row.sh`, 7 alternating repetitions per subject). This
  is the counter that produced the recorded `254.2`.
* **valgrind DHAT** for attribution: `--tool=dhat --num-callers=40`. DHAT
  attributes every block to a stack; differencing `--sign-ops 50` and
  `--sign-ops 250` yields the per-signature count and bytes at each site over the
  same 200 operations the probe averages (`alloc-profile/parse_dhat.py`).

The workload under DHAT is a **new** harness,
`alloc-profile/ecdsa_alloc_harness.c` (`a2917734…`), because `bench_api.c` must
not be modified: it transcribes `bench_api`'s operand construction exactly
(private scalar seed `0x45434400` top-bit-clear odd; digest seed `0x44494700`
top-bit-clear even; public key derived by `EC_POINT_mul` under test; measured step
`ECDSA_do_sign` + `ECDSA_SIG_free`) and prints the same `LOADED`/`MAPS`/`CHECK`
observables. Its `CHECK ecdsa256 pub=02c5b17d…128f verify=1` is byte-identical to
the recorded timing harness's line, which is what licenses the attribution.

Agreement between the instruments on the same build (per signature):

| subject | alloc_probe (200-op mean, 7 reps) | DHAT (200-op window) |
|---|---:|---:|
| authority `611e511d` | 29.000 | 29.000 |
| candidate before `e93776b4` | 253.6 [253.2, 254.6] | 254.195 |
| candidate after `5e75b694` | 232.2 [231.2, 233.2] | 232.540 |

A short DHAT window (20 operations) reads 3–14 blocks/op away from these
numbers on the candidate and nothing on the authority: the per-signature count is
**value-dependent** — the reductions and multiplications allocate from the
operands' normalised limb lengths, and those lengths change from signature to
signature. The 200-operation window is the smallest window that agrees with the
probe, so that is the one used. This is the same length dependence the records
already carry as the T8/T9 residual; it is not new and this item does not change
it.

## 3. The profile — ranked, one P-256 signature, build `e93776b4`

`254.195 blocks` and `11,136.9 bytes` per `ECDSA_do_sign` + `ECDSA_SIG_free`,
over 91 program points (stacks). Sites are named by the innermost frame that is
the crate's own code; allocator plumbing (`malloc`, `RawVecInner::finish_grow`,
`CRYPTO_malloc`) is stripped from the label. `reached from` is the next frame
out. The counts below the first 26 rows are 35.00 blocks/op over 23 groups.

| # | site | reached from | blocks/op | bytes/op |
|---|---|---|---:|---:|
| 1 | `bn::limbs::divide_fallible` | `bn::limbs::rem_fallible` | 54.32 | 2784.6 |
| 2 | `bn::limbs::mul_fallible` | `BN_mul` | 27.16 | 1714.2 |
| 3 | `runtime::alloc::try_zeroed::<u64>` | `bn::limbs::mod_inverse_consttime` | 12.00 | 392.0 |
| 4 | `BN_new` | `BN_CTX_get` | 11.00 | 352.0 |
| 5 | `bn::bignum::from_bytes` | `BN_bin2bn` | 10.00 | 361.0 |
| 6 | `bn::limbs::reserve_cleansed` | `ossl_ec_scalar_mul_ladder` | 9.00 | 320.0 |
| 7 | `bn::limbs::sub_fallible` | `BN_sub` | 8.08 | 282.6 |
| 8 | `CRYPTO_THREAD_read_lock` | `RAND_get_rand_method` | 8.00 | 352.0 |
| 9 | `bn::limbs::shl_fallible` | `BN_lshift` | 7.12 | 285.0 |
| 10 | `ossl_ec_GFp_simple_point_init` | `ossl_ec_scalar_mul_ladder` | 6.00 | 192.0 |
| 11 | `bn::limbs::mod_inverse_consttime` | `bn::arith::mod_inverse_impl` | 6.00 | 192.0 |
| 12 | `bn::arith::run_mont_ladder` | `mod_exp_core_consttime_from_parts_prepared` | 6.00 | 232.0 |
| 13 | `bn::arith::mont_mul_fallible` | `BN_to_montgomery` | 6.00 | 272.0 |
| 14 | `BN_mod_mul_montgomery` | `ossl_ecdsa_simple_sign_sig` | 6.00 | 192.0 |
| 15 | `bn::arith::mont_mul_fallible` | `BN_mod_mul_montgomery` | 6.00 | 272.0 |
| 16 | `BN_uadd` | `BN_mod_add_quick` | 5.04 | 201.6 |
| 17 | `BN_to_montgomery` | `ossl_ecdsa_simple_sign_sig` | 4.00 | 128.0 |
| 18 | `bn::limbs::sub_fallible` | `BN_usub` | 3.47 | 138.8 |
| 19 | `bn::limbs::sub_fallible` | `BN_add` | 3.00 | 96.0 |
| 20 | `BN_new` | `ossl_ecdsa_simple_sign_sig` | 3.00 | 96.0 |
| 21 | `ossl_ec_GFp_simple_point_init` | `ecdsa_sign_setup` | 3.00 | 96.0 |
| 22 | `bn::limbs::reserve_cleansed` | `bn::limbs::set_bit` | 3.00 | 120.0 |
| 23 | `BN_copy` | `ossl_ec_GFp_simple_point_copy` | 3.00 | 72.0 |
| 24 | `BN_CTX_get` | `ossl_ec_scalar_mul_ladder` | 3.00 | 224.0 |
| 25 | `bn::rand::bnrand` | `bn::rand::bnrand_range` | 3.00 | 96.0 |
| 26 | `bn::arith::mont_mul_fallible` | `bn::arith::run_mont_ladder` | 3.00 | 136.0 |
| | *(23 further groups)* | | 35.00 | 1538.1 |

Grouped by call path (the four groups account for 253.4 of the 254.2; the
residual 0.8 is harness-side and named in `raw-base/profile-e93776b4.json`):

| call path | blocks/op | share |
|---|---:|---:|
| `EC_POINT_mul` → `ossl_ec_scalar_mul_ladder` (ladder pre/step/post, the `z^-1` field inverse, and the nonce draw `BN_priv_rand_range_ex` inside `ladder_pre`) | 177.41 | 69.8% |
| `ossl_ecdsa_simple_sign_sig` (the `s = (m + r·d)·k^-1 mod n` Montgomery chain, `BN_CTX`, `ECDSA_SIG`) | 62.00 | 24.4% |
| `ossl_ec_group_do_inverse_ord` → `BN_mod_exp_mont_consttime` (`k^-1`) | 14.00 | 5.5% |
| other | 0.78 | 0.3% |

Two rows are worth naming precisely because they were the only *gratuitous*
costs found:

* `bn::limbs::divide_fallible` is 34.00 of its 54.32 in a **single** stack
  (`BN_nnmod` inside `ossl_ec_GFp_simple_ladder_post`), i.e. the affine
  conversion reduces ~34 times per signature. Each reduction allocates one
  `a.len()+1`-limb accumulator (`un`) and then **clones** the remainder out of it
  (`limbs.rs:903`). That clone is the T23 transfer window, not a redundancy (§6).
* `CRYPTO_THREAD_read_lock` allocating at all is surprising: it was
  `LockState::note_reader` building the reader table behind `Box<ReaderTable>`,
  and `CRYPTO_THREAD_unlock` freeing it when the last reader left
  (`runtime/thread.rs`). Every acquire/release pair on the RAND, namemap and
  method-store paths therefore paid two allocations, purely to rebuild a table
  that was empty both before and after.

## 4. Which sites are on the secret path

The measured step's secrets are the nonce `k`, its inverse, the private scalar
`d`, and every field element derived from them. Sites that allocate on values
derived from those (and therefore where an optimisation must not introduce a
branch, a length-dependent access or a variable-time free):

| site | why it is secret-bearing | what the count depends on |
|---|---|---|
| `divide_fallible` ← `rem_fallible` ← `BN_nnmod` in `ladder_post`/`ladder_step` | reduces the coordinates of `k·G` | 1 block per call; the *size* is `a.len()+1` limbs, a normalised secret length (the existing T8/T9 residual) |
| `mul_fallible` ← `BN_mul` (field mul/sqr in the ladder) | products of secret coordinates | 1 block; size from the public operand widths |
| `sub_fallible`/`shl_fallible`/`BN_uadd` ← `BN_mod_*_quick` | secret coordinates | 1 block |
| `mod_inverse_consttime` (18 fixed scratch buffers) | `z^-1` of the ladder result | 18 blocks; sizes from the public width `w` |
| `mont_mul_fallible`, `BN_mod_mul_montgomery` | the `s` chain, `k^-1` chain | fixed |
| `reserve_cleansed` ← ladder / `set_bit` | coordinate storage | public widths |
| `from_bytes` ← `BN_bin2bn` ← `bnrand` | the RNG draw for `k` | 1–2 blocks; size from the requested length (public) |

Off the secret path: `BN_new`/`BN_CTX_get` object creation, `point_init`,
`ECDSA_SIG`/`BN_CTX` construction, and the two lock/context-capacity sites
changed here. The digest-side `from_bytes` (`BN_bin2bn` in
`ossl_ecdsa_simple_sign_sig`) is `PUBLIC_DATA`.

## 5. What was removed

Three edits, each a pure capacity/bookkeeping change: no arithmetic, no exported
representation, no `#[repr(C)]` layout, no `CRYPTO_*` seam size/`file`/`line`, no
new `unsafe`, no new branch on a value.

| # | file | mechanism | before → after (blocks/op) |
|---|---|---|---:|
| 1 | `src/runtime/thread.rs` | the reader-hold table is **emptied** instead of freed when the last reader releases (`ReaderTable::clear`); the box and its entries are reused by the next acquisition. The anti-staleness property the free existed for is kept in the stronger form: the table is cleared, so it holds no entry exactly when `readers == 0`, including after a foreign unlock. | 14.00 → 0.00 |
| 2 | `src/bn/bignum.rs` (`from_bytes`) | the big-endian arm materialised a reversed byte vector with no reader other than the accumulation loop. It now indexes `bytes[n-1-i]` instead; `little` is a constant at every call site (both `BN_bin2bn` and `BN_lebin2bn` pass a literal), so it folds away. Same iteration count, same index sequence, same values. | 10.00 → 5.00 |
| 3 | `src/bn/ctx.rs` (`new_ctx`) | the pool slot vector is reserved once for `BN_CTX_POOL_SIZE` (16 — the authority's `crypto/bn/bn_ctx.c:26`) at construction instead of growing by `push` per `BN_CTX_get`. This reproduces the authority's one-allocation first `BN_POOL_ITEM` growth. Capacity only: which slots exist, when an object is created, and every handed-out value are unchanged. | 3.00 → 0.00 (and the two per-`ctx` growth points move to one reservation, already netted in this row) |

An intermediate variant also reserved the `marks` stack. It measured **1
block/op worse** than the pool-only reservation (the reservation replaced a
one-allocation growth with a one-allocation reservation while adding a
fixed cost to every context), so it was reverted; only the pool reservation
stands. That revert is why the recorded candidate is `5e75b694` and an earlier
intermediate build `b4c92ea6` is superseded and unused.

Total: **254.195 → 232.540 blocks/op (−21.66, −8.52%)** and
**11,136.9 → 10,230.2 bytes/op (−8.1%)**; program points 91 → 71. The site
labelling of the untouched `BIGNUM` object allocations moves between builds
(`ossl_ec_GFp_simple_point_init` 9 → 0 while `BN_new` 16 → 25) because inlining
changed; the sum is unchanged, and no allocation was gained or lost there.

**Constant-time / secret-path argument.** The one secret-path edit is #2
(`from_bytes` on the `bnrand` path). It removes one allocation and its free from
a path where both were already unconditional: the loop runs
`bytes.len()` times for every value, the index sequence is the same sequence the
copy performed, and the branch is on `little`, a compile-time constant at every
call site — not on data, not on length. Edits #1 and #3 allocate at fixed sizes
at lock/context creation, before any secret exists. No secret-dependent branch,
no length-dependent access and no variable-time free is introduced. This is an
argument, not a measurement: a ctgrind/branch-audit run at `5e75b694` was **not
run** (§9).

## 6. What was argued necessary (and not removed)

| site | blocks/op | why it stays |
|---|---:|---|
| `divide_fallible` | 54.32 | One accumulator per reduction, and the remainder is **cloned out of it** (`limbs.rs:903`) because the accumulator is a `SecretLimbs` and `SecretBuf` deliberately exposes **no** `into_inner`/`release`: there is no safe way to move an uncleansed allocation out (`runtime/secret.rs`). Removing that clone needs either that API (a new secret-transfer boundary — refused here) or an in-place reduction into a caller-supplied destination (a `BIGNUM`-representation change across `bn/`). Costed, not taken. |
| `mul_fallible` / `sub_fallible` / `shl_fallible` / `BN_uadd` / `BN_copy` / `BN_add` / `mont_mul_fallible` / `BN_mod_mul_montgomery` | 79.88 | Each is the **result** allocation of a `BN_*` operation: the crate computes a fresh `Vec` and swaps it into the destination, where the authority writes in place into a `BN_CTX` pool object. Converting the family to in-place writes is the real lever (~31% of the remaining count) and is a semantics-wide change, not a redundant computation. |
| `mod_inverse_consttime` + its scratch | 18.00 | 18 fixed-width scratch buffers (584 B; the whole `try_zeroed` site family reads 20.00 blocks / 648 B, the other 2.00 being `BN_mod_mul_montgomery`'s), all cleansed by `SecretLimbs::Drop` on every exit path. Removing 16 of the 18 means carving one `SecretLimbs` arena with `split_at_mut` and swapping slice bindings inside a constant-time loop — possible, moderate-risk, and deliberately not done in a batch whose other edits are capacity-only (§10, next site 1). |
| `BN_new` ← `BN_CTX_get` | 11.00 | One `BIGNUM` object per pool slot: the authority allocates 16 at once from a `BN_POOL_ITEM`, this representation allocates one `Box` per slot. Chunking the *objects* changes the pool's representation and its release contract (every slot is currently released with `BN_free`); out of scope for this item. |
| `point_init`, `ecdsa_simple_sign_sig`, `BN_CTX`, `ECDSA_SIG` | 9 + 6 + … | Object construction with the authority's own lifecycle: `X`, `Y`, `Z` per point, a fresh `BN_CTX` per `sign_sig` (the authority does the same), the returned `ECDSA_SIG`. |
| `RAND`/namemap inside `ladder_pre` | ~4 | The nonce draw and the `EVP` fetches it performs. The fetches are per-signature in the authority too; caching them would be a store-lifetime change, not an allocation fix. |

## 7. Secrets-path verdict for the two removed families

The lock-table removal also removes a *timing* signal that was uniform across
inputs (the same two allocations per acquisition for every signature), so it
changes no secret-dependent timing. The `from_bytes` removal is the same: the
allocation count there never depended on the value.

## 8. Re-measurement

### 8.1 Allocations (existing instrument, unchanged)

`alloc-profile/run_alloc_row.sh`, `bench_api --alloc`, 7 alternating repetitions
per subject, median of the per-repetition `allocs_per_op`:

| comparison | before | after | delta |
|---|---:|---:|---:|
| `ecdsa256`, historical `553e1b8c` vs PFP-24 | 253.8 [253.0, 254.2] | 232.6 [232.2, 233.2] | −21.2 (−8.4%) |
| `ecdsa256`, **same commit** control `e93776b4` vs PFP-24 | 253.6 [253.2, 254.6] | 232.2 [231.2, 233.2] | −21.4 (−8.4%) |
| authority | 29.0 | 29.0 | — |

The recorded row value was `254.2` at `553e1b8c` (a single 5-iteration reading);
the 7-repetition median at the same build is 253.8, and across the four runs of
this item it is 253.4–253.8. Against the authority
the per-signature allocation ratio moves **8.74× → 8.01×**; the all-workload
`allocations` block in `timing-5e75b694/results.json` reads 232.80 / 29.00.

### 8.2 Latency (existing instruments, unchanged)

`run_timing.sh` (15 paired repetitions, balanced pseudo-random order seeded
`0x50465030`, `taskset -c 1`, median of paired ratios, 20,000-resample bootstrap,
Holm–Bonferroni over the nine-workload family). Three runs, two of them a
control:

| run | candidate | `ecdsa256` cand µs | auth µs | ratio [CI95] | allocs |
|---|---|---:|---:|---|---:|
| `timing-553e1b8c` (historical, pre-PFP-6) | `553e1b8c` | 244.908 | 12.741 | 19.223 [19.176, 19.252] | 254.2 |
| `timing-baseline-e93776b4` (**control**: same commit, no PFP-24) | `e93776b4` | 239.610 | 12.757 | 18.82 [18.76, 18.83] | 253.0 |
| `timing-5e75b694` (PFP-24) | `5e75b694` | 239.934 | 12.721 | 18.83 [18.81, 18.91] | 232.8 |

**The PFP-24 latency effect is zero within the measurement:** 239.610 → 239.934 µs
(+0.14%), ratio 18.82 → 18.83, and the two intervals overlap. The
`19.22 → 18.83` movement since the historical record is therefore **PFP-6's**
`src/bn/arith.rs` — which is in `fc2716652` and had never been through a timing
run — not this item's. What moved is the generated code for the **selected**
ladder schedule: PFP-27's artefact audit records that the production DSO selects
SOS, so CIOS does not execute there, and CIOS activation is not named as the
cause. No speedup is claimed.

No row regressed beyond the cross-run band, and no row improved beyond it either.
Per-row ratios, control → PFP-24: `dh-ffdhe2048` 4.13 → 4.14, `dh-ffdhe3072`
4.27 → 4.36 (+2.1%), `dh-modp2048` 4.12 → 4.14, `dh-synth2048` 4.12 → 4.14,
`dh-synth3072` 4.27 → 4.34 (+1.6%), `modexp2048` 4.20 → 4.21, `modexp8192`
4.92 → 4.82 (−2.0%), `rsa2048` 4.54 → 4.57. Both directions occur at the same
±2% magnitude, so none of them is attributed to the change; a 2% movement between
two separate runs on this venue is not a win and not a regression.

Correctness in both runs: `check_lines_match_all_repetitions: true` (15/15),
cross-verification accepted in both signer orders, verdict `SCOPED_OBSERVATION`,
`blocked: false`.

### 8.3 Differential

The PFP-22 domain court was re-run unchanged against the PFP-24 candidate:
`dso-differential/pfp24-domain-5e75b694/` (harness source byte-identical to
`pfp22-domain-553e1b8c/pfp22_domain_differential.c`, renamed; only the pinned
candidate digest and the output directory differ). **Nine classes, 16,434 cases
per subject, 32,868 evaluations, 0 mismatches**, identity proof 18/18 rows, and
the base-class historical digests `a9e1068d…` / `bcb22a91…` reproduced — so
`k·G`/`k·P` on the comparable population are unchanged by the three edits. Record:
`dso-differential/pfp24-domain-5e75b694/domain-differential-5e75b694.json` (`PASS`).

## 9. What is not established

* `cargo test --lib -- p256` 19/0 and `cargo test --lib -- bn` 156/0 were run
  **after the three edits as one batch**, not after each edit individually; the
  full library suite is **2472 passed, 0 failed, 54 ignored** (141.9 s,
  `--test-threads=4`). No test was added, removed or ignored by this item.
* Serial (`--test-threads=1`) library run: **NOT_RUN** (BATCH-level gate, not
  re-taken here).
* ctgrind and the binary branch audit at `5e75b694`: **NOT_RUN**. The export is
  a fingerprint-bound dirty-tree candidate, and this item claims no
  constant-time property, only that it introduces none (§5). The recorded
  ctgrind/branch-audit evidence remains bound to `553e1b8c` and is not reused.
* Miri / sanitizers: **NOT_RUN** (no reusable-boundary change; the edits add no
  `unsafe`).
* The claim register and `ARMS` are **not** updated: a same-digest set for a
  claim would need the ctgrind/branch-audit legs at `5e75b694`, which do not
  exist. `timing` + `differential` + `allocations` at one digest is not a claim.
* The 5–14 blocks/op spread between DHAT's short windows and its 200-op window
  is value-dependent allocation sizes (§2). It is reported, not explained away.
* The `+9` `BN_new` / `−9` `point_init` site shift between the two builds is an
  inlining artefact of identical allocations (§5), evidenced by the group totals
  being unchanged except for the three removed families.

## 10. The next three sites to attack

1. **`mod_inverse_consttime`'s 18 scratch buffers → one arena** (18.00 blocks,
   584 bytes per signature, 7.1%). All 18 are fixed-width
   `SecretLimbs::try_zeroed` allocations currently cleansed individually; one
   `SecretLimbs` carved with `split_at_mut` into the same 18 views makes it 1
   allocation and 1 wipe, with no branch, no unsafe and no change to the
   constant-time loop. It is the largest remaining site that is *provably* pure
   overhead, and it is on the secret path, so it needs the full BATCH gate plus a
   ctgrind re-run at the resulting digest.
2. **`BN_new` ← `BN_CTX_get` (11.00 blocks/op).** The authority allocates a
   `BN_POOL_ITEM` of 16 `BIGNUM`s; this pool allocates one `Box` per slot. A
   chunked pool changes the pool's representation and release contract, so it is
   a small ownership batch of its own, not a capacity tweak.
3. **In-place `BN_*` results (~80 blocks/op, 31%).** `mul_fallible`,
   `sub_fallible`, `shl_fallible`, `BN_uadd`, `BN_copy`, `mont_mul_fallible`,
   `BN_mod_mul_montgomery`: every operation writes a fresh `Vec` and swaps it in,
   where the authority writes into a preallocated pool object. This is the item
   that would change the ratio materially, and also the one with the largest
   semantic surface; it needs its own plan and its own differential, and it
   should be measured with the control build of this file as its "before".

The `divide_fallible` clone (54.3, 21%) is *not* on this list because it is
blocked by a deliberate secret-ownership decision (§6), not by effort.

## 11. Reproduce

```
# build the candidate (working tree) and the control (clean worktree at HEAD)
OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
  bash docker/openssl-rs-court.sh exec env CARGO_BUILD_JOBS=4 \
    sh evidence/performance-frontier/campaigns/PFP-2/alloc-profile/build_candidate.sh
PFP24_SRC=/work/court/tmp/pfp24-base-src PFP24_OUT=/work/court/tmp/pfp24-base \
  sh evidence/performance-frontier/campaigns/PFP-2/alloc-profile/build_candidate.sh

# the row, both subjects, 7 alternating repetitions
PFP24_OLD_DSO=/work/court/tmp/pfp24-base/distribution/libcrypto.so.3 \
PFP24_NEW_DSO=/work/court/tmp/pfp24/distribution/libcrypto.so.3 \
  bash evidence/performance-frontier/campaigns/PFP-2/alloc-profile/run_alloc_row.sh

# the profiles
valgrind --tool=dhat --num-callers=40 --dhat-out-file=dhat-50.json \
  <harness> --lib <dso> --sign-ops 50
valgrind --tool=dhat --num-callers=40 --dhat-out-file=dhat-250.json \
  <harness> --lib <dso> --sign-ops 250
python3 evidence/performance-frontier/campaigns/PFP-2/alloc-profile/parse_dhat.py \
  --before dhat-50.json --after dhat-250.json --ops 200

# timing (control and candidate) and the differential
bash evidence/performance-frontier/campaigns/PFP-2/timing-baseline-e93776b4/run_timing.sh
bash evidence/performance-frontier/campaigns/PFP-2/timing-5e75b694/run_timing.sh
bash evidence/performance-frontier/campaigns/PFP-2/dso-differential/pfp24-domain-5e75b694/run_domain.sh
```

Files: `alloc-profile/{ecdsa_alloc_harness.c,parse_dhat.py,show_stacks.py,make_table.py,group_paths.py,build_candidate.sh,run_alloc_row.sh}`
plus `raw/` (historical `553e1b8c`), `raw-base/` (`e93776b4`), `raw-24/` (`5e75b694`).
