# PFP-29 — one whole-path constant-time and correctness checkpoint at one DSO digest

**State: DONE for the exercise-and-report criterion. Every supported
secret-bearing path is exercised at one artefact digest and reported
separately, and no per-path result is assembled into an overall verdict.** The
residuals that keep the checkpoint from being anything more than a
`SCOPED_OBSERVATION` are listed in §7 and are not reclassified.

Per-engine evidence is not a statement about the library. PFP-21 showed that the
P-256 engine is clean at the artefact for a `k*G`/sign population; PFP-27 showed
the SOS kernel is branchless. Neither says what the *other* secret-bearing paths
do. This record exercises ECDSA sign and verify, ECDH, RSA private with and
without CRT, DH (ffdhe2048) and ML-KEM-768 decapsulation in **one population at
one digest**, and reports each path on its own.

---

## 1. Artefact identity and reproducibility

| item | value |
|---|---|
| source commit (`staging`) | `e49d34d8f556a6955996d89e9a07cbda009dd4a2` |
| `src` tree | `8c8deea0835897ee365c3d994686968425935585`, 886 `.rs` files |
| `src` fingerprint | `1946bd861d389061a79c7f4d09b1523e6062712e79006c06145d4f059daae0b4` |
| `src/bn/arith.rs` | `06005795079c9957ba2b35c6816c423b507f427705842284aa9c23d0e0759a1c` |
| `Cargo.lock` | `95e8fd837792b69a69798c3884dfc4000bee28d87c58fd3bf4cd5f597e62c2d9` |
| toolchain | rustc/cargo 1.98.1, cc 12.2.0, `x86_64-unknown-linux-gnu` |
| profile | `cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4` |
| shell / version script | `efa0fbce…5606` / `75fb6eff…1275` |
| **DSO A** | **`5e75b6945907536959c6339eb8acb4c362495dcf4a5a781983c76ac65e2ce5ae`**, 17,094,080 B, build id `73d0772b…2b69` |
| DSO A2 | identical digest, size and build id |

A2 is a second clean build in a fresh `CARGO_TARGET_DIR`, byte-identical to A
(`raw/build-inputs.txt: a2_matches_a yes`). The digest also equals the PFP-27
artefact, independently reproducing it. The source fingerprint is identical
before and after both builds. This is PFP-23's reproducibility discipline
applied to this checkpoint; it is a digest match, not a source-to-binary
refinement claim. The DSO bytes are still not committed (`PFP2-DIRTY-CANDIDATE`).

Venue: court `openssl-rs-court-tools:1`, cgroup cap 8,589,934,592 B (reused).
`available` was 24–25 GiB before every heavy command, so
`cap = min(8 GiB, available − 16 GiB) = 8 GiB` held; one heavy command at a time;
`memory.events` `oom 0`, `oom_kill 0` throughout. No release test-profile build
was attempted.

---

## 2. Per-path taint at the digest

One process per run, one `dlopen`ed candidate DSO, exported entry points only,
`--num-callers=24`, three repetitions per path, fixed fixtures. Attribution is
the campaign's parser (`attrib_pfp29.py`) with five buckets: **engine**
(`src/ec/p256`), **bn** (`src/bn`), **ec** (other `src/ec`), **driver**
(`src/rsa`, `src/dh`, `src/ml_kem`, `src/provider`, `src/evp`), **runtime/std**.
Exported `#[no_mangle]` wrappers (`BN_*`, `EC_*`, `RSA_*`, `DH_*`, `EVP_*`) are
assigned to the module whose code they run.

| path | tainted secret | runs | memcheck errors med [max] | contexts med [max] | engine¹ | bn¹ | ec¹ | driver¹ | runtime¹ | engine-on-path |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `ecdsa-sign` (`sign_ex` + tainted nonce) | `k` before `BN_mod_inverse`/`k*G`, then `kinv` and `d` | 3 | 33,007 [33,032] | 442 [452] | 0 | 446 | 155 | 0 | 452 | **0** |
| `ecdsa-sign-default` (`ECDSA_do_sign`) | `d` only (library RNG nonce is unreachable, see below) | 3 | 3,723 [3,733] | 274 [280] | 0 | 272 | 239 | 0 | 280 | **0** |
| `ecdsa-verify` | **nothing** — public key, signature, digest are all public | 3 | 0 [0] | 0 [0] | 0 | 0 | 0 | 0 | 0 | **0** |
| `ecdh` | `d` | 3 | 3,795 [3,795] | 253 [256] | 0 | 245 | 256 | 0 | 256 | **0** |
| `rsa-crt` (NO_PADDING) | `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp` | 3 | 48,472 [48,515] | 244 [244] | 0 | 241 | 0 | 244 | 244 | **0** |
| `rsa-nocrt` (NO_PADDING) | `d` (key has only `n`, `e`, `d`) | 3 | 37 [37] | 23 [23] | 0 | 23 | 0 | 23 | 23 | **0** |
| `rsa-crt-pkcs1` | as `rsa-crt`; PKCS#1 v1.5 padding check included | 3 | 48,622 [48,623] | 252 [252] | 0 | 244 | 0 | 252 | 252 | **0** |
| `dh` (ffdhe2048) | private exponent (256-bit) | 3 | 277 [277] | 23 [23] | 0 | 21 | 0 | 23 | 23 | **0** |
| `mlkem-decaps` (ML-KEM-768) | 64-byte private-key seed at the `EVP_PKEY_fromdata` boundary | 3 | 2,832 [2,832] | 5 [5] | 0 | 0 | 0 | 5 | 5 | **0** |

¹ contexts with at least one frame from that bucket, max over the three
repetitions. A context can be counted in several buckets; the column is *not* a
partition of the context count.

Negative control (everything defined, every path once): **0 errors from 0
contexts**. Positive sensitivity control on the pre-PFP-20 artefact `83f67826`:
the same harness and `ecdh` mode report **engine_on_path = 4** (218 contexts), so
the instrument still sees the engine path and the zeros above are not a silent
instrument. Errors within a path vary by less than ~0.1%; context counts carry
the instrument's known spread (the largest run-to-run spread is about ±2.3%, on
`ecdsa-sign`).

### Representative origins per path

Read from `attrib/a-<path>-r1.tsv`; these are the path's own residuals, not a
merged number.

* **ECDSA sign (`ex`)** — `limbs::divide_fallible` 104, `BN_nnmod` 32,
  `limbs::mul_fallible` 25, `limbs::sub_fallible` 25, `limbs::mod_inverse` 22,
  `RawVecInner::finish_grow` 22. The fix-top arithmetic and the generic BIGNUM
  surface.
* **ECDSA sign (default)** — `BN_nnmod` 33, `limbs::divide_fallible` 29,
  `limbs::mul_fallible` 21, `BN_add` 18, `BN_sub` 15: the same generic BIGNUM
  stack reached through the ladder.
* **ECDH** — `BN_nnmod` 32, `limbs::divide_fallible` 29, `limbs::mul_fallible`
  22, `BN_mul` 13, `BN_bn2bin` 12.
* **RSA CRT** — the largest residue in the checkpoint: `limbs::divide_fallible`
  33, `limbs::mul_fallible` 32, `BN_sub` 22, `BN_add` 13, plus 42 `memmove`,
  23 `memset`, 16 allocator frames. **Hundreds of contexts in the generic stack;
  reported as such even though the engine is clean.**
* **RSA no-CRT** — only 23 contexts: `memmove` 12, `BN_mod_mul_montgomery` 4,
  `BN_bn2binpad` 3, allocator 4. The constant-time exponentiation contributes
  few memcheck contexts; the serialisation/length steps do.
* **DH** — `BN_cmp` 12, `BN_bn2binpad` 9, `ossl_dh_compute_key` 2. These are the
  authority's own post-exponentiation checks (`z <= 1`, `z == p-1`) and the
  padded serialisation of `z`: branches on the shared secret present in
  `crypto/dh/dh_key.c`, reproduced faithfully rather than introduced by the
  conversion. They are a per-path residual and are not read as anything else.
* **ML-KEM-768 decapsulation** — 5 contexts: `matrix_expand` 2 (inside
  `ossl_ml_kem_genkey`, during the import of the tainted seed), `key::decap` 2
  (the implicit-rejection select region), `ml_kem_pairwise_test` 1 (the import's
  pairwise test). The decapsulation kernel itself is branch-light in memcheck's
  view; memcheck cannot distinguish the mask select from a branch (§7).

**ECDSA verify is explicitly out of scope for taint**: `ECDSA_do_verify` takes a
public key, a published signature and a public digest, so there is no secret to
mark. It is run defined as a behavioural control and covered by the
differential; claiming a taint result for it would be claiming a secret that does
not exist. The library-generated nonce in `ECDSA_do_sign` has no exported entry
point and cannot be marked; the nonce path is covered through `ecdsa-sign`'s
tainted `k` and through the tainted `kinv`/`r` pair, and `ecdsa-sign-default` is
reported with `d` only rather than silently excluding the nonce.

---

## 3. Binary branch audit at the same digest

`courts/phase18/timing/binary_branch_audit.py`, objdump 2.40, bound with
`--expect-sha256 5e75b694…`. Output: `raw/audit-pfp29.md`.

**The tool's default inventory is 8/9 at this digest and exits 1.** It refuses
`mont_mul_into` (`reason=missing`): the PFP-6 `src/bn/arith.rs` refactor left no
out-of-line body for that name. That is recorded, not hidden
(`raw/audit-default.md`, `raw/audit-default.stderr`). The same inlining
discipline used for `mod_exp_core_consttime_from_parts` cannot be applied,
because a mapping must satisfy `resolves_to == symbol + suffix` and
`mont_mul_sos_into` is not a suffixed form of `mont_mul_into`. The PFP-29
inventory therefore **replaces** that entry with the carrier and the selected
kernel:

* `run_mont_ladder` — the carrier into which the ladder multiply is inlined;
* `mont_mul_sos_into` — the SOS kernel `LADDER_SCHEDULE = MontSchedule::Sos`
  selects (PFP-27), audited directly.

**PFP-29 inventory: 29/29 resolved uniquely, 1 through the verified inline
mapping, exit 0** (`raw/audit-pfp29.stderr`). Inventory: `targets-pfp29.json`.

### Coverage by path

| path | audit targets that reach it | not covered by any target |
|---|---|---|
| ECDSA sign | `ossl_ec_scalar_mul_ladder`, `ossl_ec_GFp_simple_ladder_step`, `mod_inverse_consttime`, `run_mont_ladder`, `mont_mul_sos_into`, `mont_mul_fallible`, `mont_reduce_into` (p256), `wide_mul_x86` (p256) | the signer driver `ossl_ecdsa_simple_sign_sig` is not a target |
| ECDSA verify | `ossl_ec_wNAF_mul` (**added by this item**); no `div` in the P-256 kernels reached | `ECDSA_do_verify` / `EC_POINT_mul` dispatch is not a target; all its inputs are public |
| ECDH | the two ladder targets above, the inversion, the Montgomery kernels | `ossl_ecdh_simple_compute_key` driver is not a target |
| RSA private, CRT | `rsa_ossl_mod_exp`, `mod_exp_core_consttime_from_parts` (inline-resolved), the Montgomery kernels | none of the path's arithmetic is outside these |
| RSA private, no-CRT | `rsa_ossl_mod_exp` (the same function; the arm is selected by the key), the mod-exp core, the Montgomery kernels | the raw output serialisation (`BN_bn2binpad`) is an exported `BN_*`, not a target |
| DH (ffdhe2048) | `ossl_dh_compute_key` (**added by this item**), the mod-exp core, the Montgomery kernels | the post-check `BN_cmp` is an exported `BN_*`, not a target |
| ML-KEM-768 decapsulation | `ossl_ml_kem_decap`, `decrypt_cpa`, `encrypt_cpa`, `scalar_inverse_ntt`, `inner_product`, `matrix_mult_transpose_add`, `matrix_expand`, `vector_decode_12`, `vector_encode`, `cbd_2`, `cbd_3`, `gencbd_vector_ntt`, `hash_h`, `hash_g`, `hash_h_pubkey`, `kdf`, `prf` (**all added by this item**) | **`key::decap`** — which contains the implicit-rejection `CRYPTO_memcmp` + `constant_time_eq_int_8` + `constant_time_select_8` — and **`arith::scalar_ntt`** |

**Named audit gap.** `key::decap` and `arith::scalar_ntt` have no out-of-line
symbol without an LLVM `.llvm.<digits>` suffix
(`…6ml_kem3key5decap.llvm.15287269651090981652`,
`…5arith10scalar_ntt.llvm.3800245403269729001`). The resolver accepts only an
exact v0 length-prefixed identifier and therefore cannot name them; extending it
would be an instrument change, which this item does not make. **Consequence: the
branch audit at this digest does not cover the ML-KEM implicit-rejection select,
which is the most security-critical operation in that path.** No claim is made
about it; the ctgrind result (2 contexts in `key::decap`) is control-flow-shaped
and Memcheck cannot distinguish a mask select from a branch.

No path is entirely without a target, but no path is audited end to end either:
the table names each driver and serialisation step that is outside the inventory.

Per-target instruction counts from the audit (jcc / div / cmov / setcc):
`wide_mul_x86` 0/0/0/9, `mont_reduce_into` 2/0/0/2, `mont_mul_sos_into`
19/0/0/10, `run_mont_ladder` 51/0/2/11, `ossl_dh_compute_key` 36/0/1/0,
`ossl_ec_wNAF_mul` 147/**4 div**/34/3 (public-scalar verify core),
`key::ossl_ml_kem_decap` 15/0/1/4, `decrypt_cpa` 37/0/0/6, `encrypt_cpa`
44/0/6/46. A conditional jump listed here is a compiler-emitted transfer whose
condition the reviewer maps to the source's secret classification; this is a
review aid, not a constant-time proof (`PFP2-AUDIT-NOT-A-PROOF`).

---

## 4. Differential at the same artefact

Candidate `5e75b694` vs the 3.6.4 authority `611e511db427…`, one `dlopen`ed DSO
per process, `LOADED`/`MAPS`/`FOREIGN` checked against `stat(2)`.

* **Fixed case**, one per path, exact bytes compared
  (`raw/differential-cand.txt` / `-auth.txt`): ECDSA `r` and `s` (32 B each),
  ECDH shared secret (32 B), RSA-2048 PKCS#1 decryption (256 B),
  DH-ffdhe2048 shared secret (256 B), ML-KEM-768 ciphertext (1,088 B),
  encapsulation secret (32 B) and decapsulation secret (32 B). **8/8 identical.**
* **64-case seeded sweep**, seed `0x5046503239505032`
  (`SWEEP_BASE`, splitmix64 per case), stated case count **64 per path**:
  ECDSA signature, ECDH secret, RSA plaintext, DH secret, KEM ciphertext and
  KEM secret for each case — **384/384 observable rows byte-identical**
  (`raw/sweep-cand.obs` vs `raw/sweep-auth.obs`).
* **Signatures cross-verified both directions:** the authority verifies all 64
  candidate signatures (`VERIFY_SWEEP ok=64 cases=64`) and the candidate verifies
  all 64 authority signatures (`ok=64 cases=64`); the single fixed-case
  signatures are likewise cross-verified both ways.

No mismatch occurred, so no STOP was triggered. A single differing byte would
have aborted the run (`fail` in `run_pfp29.sh`), and the harness never inspects a
secret in the taint runs.

The RSA key is an authority-generated 2048-bit fixture frozen in
`raw/rsa-fixture.txt` (one key; eight components; one PKCS#1 ciphertext). The
sweep's RSA cases build a fixed PKCS#1 block and encrypt it deterministically
with the fixture's public exponent, so both subjects decrypt the *same*
ciphertext. ML-KEM uses the FIPS 203 deterministic keygen seed and a fixed
`ikme`, so the ciphertext is reproducible. DH uses fresh ffdhe2048 keys per case
from the same exponents in both subjects.

---

## 5. Timing rows at the same digest

**Campaign instrument, already at this artefact**
(`evidence/performance-frontier/campaigns/PFP-2/timing-5e75b694/results.json`,
15 paired repetitions, `SCOPED_OBSERVATION`):

| workload | candidate µs | authority µs | ratio [CI95] |
|---|---:|---:|---|
| `ecdsa256` | 239.934 | 12.721 | 18.832 [18.815, 18.913] |
| `dh-ffdhe2048` | 4,933.07 | 1,191.55 | 4.140 [4.136, 4.142] |
| `rsa2048` | 1,605.15 | 351.36 | 4.569 [4.548, 4.589] |
| `modexp2048` | 5,041.21 | 1,197.89 | 4.206 [4.197, 4.214] |
| `modexp8192` | 356,210.89 | 73,896.96 | 4.822 [4.819, 4.827] |

This row set has no ECDH and no KEM workload. The per-path wall rows below fill
that gap **for this checkpoint only**; they are a single-process observation, not
the campaign instrument, and no candidate/authority ratio is claimed from them.

| path (candidate only) | median ns/op | min–max ns/op | notes |
|---|---:|---|---|
| `ecdsa-sign-default` | 250,737 | 7 reps, 20 ops each | the shipped signing path (nonce + `k*G`); consistent with `ecdsa256` 239.9 µs |
| `ecdsa-sign` (`sign_ex`) | 685 | as above | fix-top arithmetic only: a caller-supplied `kinv`/`r` skips the ladder by construction, so this is **not** the signing-cost row |
| `ecdsa-verify` | 601,225 | as above | public-input verify |
| `ecdh` | 226,065 | as above | consistent with PFP-21's 227.8 µs wall for the same ladder |
| `rsa-crt` | 1,723,092 | as above | |
| `rsa-nocrt` | 5,527,860 | as above | |
| `dh` (ffdhe2048) | 5,054,657 | as above | |
| `mlkem-decaps` (ML-KEM-768) | 25,557 | as above | |

No PMU, no frequency/turbo/SMT control: these are `SCOPED_OBSERVATION` rows, not
a frontier result, and the min–max is emitted in `raw/timing.tsv`.

---

## 6. What the checkpoint establishes

At digest `5e75b694`, in the shipped distribution DSO:

1. every supported secret-bearing path — ECDSA sign (both the `sign_ex` and
   default forms), ECDH, RSA private CRT and no-CRT, PKCS#1 v1.5, DH ffdhe2048,
   and ML-KEM-768 decapsulation — was **exercised with its own secret marked and
   its public inputs defined**, three times each, with a zero-error negative
   control and a positive sensitivity control that still sees the engine path;
2. **no path reports a p256 engine context** (`engine_on_path = 0` on all nine
   populations), and the engine's absence is measured, not assumed;
3. the paths are **not equivalent**: the same checkpoint records 5 contexts for
   ML-KEM decapsulation, 23 for DH and RSA no-CRT, 244–252 for RSA CRT, 253 for
   ECDH and 274–452 for ECDSA signing. An engine-local zero would have hidden all
   of that;
4. the candidate is **behaviourally identical** to the authority on 64 seeded
   cases per path (384 observable rows) and on the fixed case, with signatures
   cross-verified both directions 64/64;
5. the branch audit resolves **29/29** targets at the digest with a verified
   inline mapping, and the default 9-target inventory's 8/9 refusal is recorded
   with its cause.

## 7. What it does **not** establish

* **No statistical timing evidence.** There is no dudect run and no
  secret-dependent timing test in this checkpoint; the wall rows are single
  process observations.
* **No proof.** Memcheck reports conditional jumps/moves and uses of undefined
  data; it cannot distinguish a `cmov`/mask select from a branch and cannot see
  secret-dependent arithmetic with no conditional. The binary audit is a review
  aid. `PFP2-AUDIT-NOT-A-PROOF` and the `PFP2-CTGRIND-INSTRUMENT-LIMIT` remain.
* **No independent reproducer.** One campaign produced this evidence. The
  second clean build reproduces the *digest*, not an independent adjudication.
* **Not a whole-path constant-time verdict.** The residual contexts are
  enumerated per path, not explained away: RSA CRT's hundreds of generic-BIGNUM
  contexts, DH's `BN_cmp`/`BN_bn2binpad` on the secret, RSA no-CRT's
  `BN_mod_mul_montgomery`/`BN_bn2binpad`, and ML-KEM's `key::decap` select are
  all reported. Whether each is timing-safe is not decided here.
* **The ML-KEM implicit-rejection select is not branch-audited** (§3). The
  `key::decap` and `arith::scalar_ntt` resolver gap is open.
* **Scope of the populations.** One RSA key fixture; ML-KEM-768 only (512 and
  1024 are present in the build but not exercised here); ffdhe2048 only; P-256
  only; one fixed P-256 scalar per taint run; the nonce inside `ECDSA_do_sign`
  is unreachable at the boundary. The KEM taint marks the seed at the documented
  import boundary, so the import (keygen from the tainted seed and the pairwise
  test) is inside the measured process, and its two `matrix_expand` contexts are
  reported rather than excluded.
* **Serial/library-suite and sanitizer/Miri runs are not part of this item.**
  No `src/` change was made, so nothing is re-validated here beyond the digest
  reproduction and the host modules in §9.

---

## 8. Reproduce

```
# 1. build A and A2 at staging e49d34d8f; digests in raw/build-inputs.txt
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-29/build_dso.sh

# 2. per-path taint, negative + sensitivity controls, timing, fixed-case and
#    64-case differential, cross-verification, recorder
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-29/run_pfp29.sh

# 3. branch audit: default inventory (expects the named refusal) and PFP-29
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-29/run_audit.sh
```

All three take `OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g` and run in
court `openssl-rs-court-tools:1`; nothing runs on the host.

## 9. Files

| file | role |
|---|---|
| `build_dso.sh` | A/A2 build and digest reproduction |
| `pfp29_paths.c` | per-path taint, timing, fixed-case, 64-case sweep, cross-verify |
| `pfp29_fixtures.c` | authority-generated RSA-2048 fixture generator |
| `attrib_pfp29.py` | five-way per-context attribution (parser unchanged from the campaign) |
| `record_pfp29.py` | per-path aggregation into `raw/checkpoint-data.json` |
| `run_pfp29.sh`, `run_audit.sh` | runners with the STOP conditions |
| `targets-pfp29.json` | the 29-target audit inventory |
| `raw/` | build inputs, per-run logs, attribution, timing, differential, audit |
