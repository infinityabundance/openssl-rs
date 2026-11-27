# PFP-4 — the W3 bound that precedes the implementation

**Verdict: STOP the PFP-4 pipeline conversion.** The whole non-`k·G` remainder is
14.2 % of signing wall time; the PFP-4 scalar arithmetic, field-to-order
reduction, `s` expression and export together are **0.45 %**. The dominant cost
is `k·G`, which PFP-3 already owns. The Amdahl ceiling for optimising the entire
non-`k·G` fraction completely is **1.166×**, so the best attainable
`ecdsa256` ratio is **9.07×** against the measured **10.58×** — and the pipeline
arithmetic alone is bounded by **1.005×**. Per the W3 rule, work that cannot move
the number is not performed. The one material component is the order inversion
(≈12.7 % of wall time); it is a self-contained optimisation and is recorded as a
separate, narrowly gated follow-up, not as this conversion.

---

## 1. Identity

| item | value |
|---|---|
| branch / head | `staging`, `0f8904d69` (docs-only commit; `src/` equals `49809764f`) |
| subject DSO | `court/tmp/pfp3-d/distribution/libcrypto.so.3`, SHA-256 `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` |
| authority DSO | `forensics/authorities/prefix/openssl-3.6.4-production/lib/libcrypto.so.3`, SHA-256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2` |
| profile harness | `profile/pfp4_profile.c`, SHA-256 `d867ce842bccb260b1eb24e33a8a78889ea3450b0274b71f7215fe2c966f72bd` |
| wall record | `profile/profile-wall.txt`, SHA-256 `1c4f749f877f7b2a1930d29462e6064740b5ee63b67ed4b23a136104d4018507` |
| callgrind record | `profile/callgrind-sign.out`, SHA-256 `5db5079b48bca0bb4a36cfefebbcc1d5bd4a47e8043f9b72d2942b6ddd4c9161` |

The subject is the **same digest** as the PFP-3 post-fix timing
(`ecdsa256` 10.58× [10.55, 10.62], `evidence/performance-frontier/campaigns/PFP-3/timing-ecbefb7d/`),
so the bound is stated at the digest the 10.58× was measured at. The harness
proves which file it mapped (`dladdr` → realpath, `st_dev`/`st_ino`/`st_size`
against `stat` of the expected path; `IDENTITY dev_ino_match=1 size_match=1`).

## 2. Method

- **Wall time.** A C harness links one `libcrypto.so.3`, fixes a P-256 key
  (`priv` from seed `0x45434400`, digest from seed `0x44494700`) and times each
  operation with `CLOCK_MONOTONIC`: warm-up `iters/4`, then 7 batches of
  `iters = 3000`, median reported. `taskset -c 1`, inside the court container.
- **Attribution.** `valgrind --tool=callgrind` on the same harness `sign` mode
  (525 signatures), `callgrind_annotate --inclusive=yes`, percentage of total
  `Ir`. No hardware PMU is available (`perf stat` reports *no supported events*),
  so instruction attribution is used as the independent axis and is stated as
  such; it is not a time measurement and is not merged with one.

No source was changed. The harness only observes the loaded DSO.

## 3. Measured decomposition (wall, candidate `ecbefb7d`)

| operation | median µs | fraction of `sign` |
|---|---:|---:|
| `ECDSA_do_sign` (whole) | **134.307** | 100 % |
| `EC_POINT_mul(k·G)` (fixed-base arm) | 115.193 | **85.77 %** |
| order inverse `x^(n-2) mod n` (Fermat, public `BN_mod_exp` CONSTTIME) | 19.347 | 14.40 % |
| nonce draw `RAND_priv_bytes`/DRBG chain | 1.245 | 0.93 % |
| `ECDSA_do_sign_ex` with supplied `(kinv, r)` — `s` expression + DER export | 0.550 | 0.41 % |
| affine export + `x mod n` | 0.035 | 0.03 % |
| `BN_nnmod` (field/order reduction) | 0.014 | 0.01 % |

`sign − mul = 19.114 µs` = **14.23 % outside `k·G`**. That remainder is the
nonce draw (1.245), the order inversion (≈17 µs; the public Fermat `BN_mod_exp`
reads 19.35 µs and overstates it slightly because the internal path uses
`bn_mod_exp_mont_fixed_top`), the `s` expression and export (0.550) and setup
overhead. The order inversion is therefore the entire material remainder.

## 4. Instruction attribution (callgrind, `Ir`, inclusive)

| symbol | `Ir` | % of sign |
|---|---:|---:|
| `EC_POINT_mul` / `ossl_ec_wNAF_mul` | 2,514,434,724 | **80.93 %** |
| ├ `fixed_base::table_mul::<Mont<FieldDomain>>` (the comb) | 2,281,607,492 | 73.44 % |
| └ `fixed_base::to_affine` (field inversion) | 228,011,297 | 7.34 % |
| `ossl_ec_group_do_inverse_ord` → `BN_mod_exp_mont_consttime` → `run_mont_ladder` → `mont_mul_sos_into` | 494,302,344 | **15.91 %** |
| `ossl_bn_gen_dsa_nonce_fixed_top` (nonce + DRBG) | 74,168,314 | 2.39 % |
| `ossl_ecdsa_simple_sign_sig − ecdsa_sign_setup` (`s` expression + export) | 14,756,572 | **0.48 %** |

Wall and instruction fractions disagree on the exact share (85.8 % vs 80.9 % for
`k·G`) because the specialised field engine has a different instructions-per-
cycle profile from the generic BIGNUM ladder; both agree on the conclusion
(`k·G` dominates; the `s` expression is below half a percent).

## 5. Amdahl bound

Let `f` be the non-`k·G` fraction and `s = 1/(1−f)` the bound on latency after
optimising `f` completely.

| target | `f` | Amdahl bound | ratio from 10.58× |
|---|---:|---:|---:|
| **entire** non-`k·G` fraction (wall) | 0.1423 | **1.166×** | **9.07×** |
| entire non-`k·G` fraction (instructions) | 0.1907 | 1.236× | 8.56× |
| PFP-4 scalar arithmetic + reduction + `s` + export | 0.0045 | **1.0045×** | **10.53×** |
| order inversion alone (wall, ≈17 µs) | ≈0.127 | 1.145× | 9.24× |
| order inversion alone, realistically halved | ≈0.063 | ≈1.068× | ≈9.91× |

The measured 10.58× does **not** leave room for the pipeline effort: the parts
PFP-4 would rewrite are 0.45 % and cannot move the number; the ceiling for
everything outside `k·G` is 1.166×, and even completely eliminating the single
material component (the inversion) is bounded by 1.145×. This is the PFP-24
lesson applied prospectively — an 8.4 % allocation reduction that did not move
latency — except here the proposed change is an order of magnitude smaller.

## 6. Recommendation

1. **Do not implement the PFP-4 pipeline conversion** (fixed-width scalar type,
   `s`-expression rework, export rework). The bound shows no headroom.
2. **Do not adopt the inversion as part of PFP-4.** A dedicated constant-time
   4-limb Fermat/divstep inverse over `q`, reusing the existing `P256Scalar`
   Montgomery kernel, is the only element with measurable headroom (realistic
   ≈1.07×, ceiling 1.145×). It belongs to a separate task (the campaign already
   lists "a dedicated scalar inversion" under W5) with its own differential,
   taint and branch-audit gates.
3. **`k·G` remains the frontier.** At 85.8 % of signing wall time it is the only
   lever that can materially change `ecdsa256`; that is PFP-3/W5 territory, not
   PFP-4.

A design sketch for what PFP-4 *would* have built is kept in
[`DESIGN.md`](DESIGN.md) so a future session does not have to reconstruct it.
