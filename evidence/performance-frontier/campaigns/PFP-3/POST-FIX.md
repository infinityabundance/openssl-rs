# PFP-3 — post-fix record: branch-free admission at `ecbefb7d`

The pre-fix candidate (`04611380`, commit `289f11187`) carried one
secret-derived conditional transfer: the `ct_ge(k, n)` admission early exit,
`je` at `ossl_ec_wNAF_mul+0x1938`. This record is the repair and the re-run at
the new digest. The historical STOP is preserved in `TAINT-AUDIT.md`,
`RECEIPT.md` and `ctgrind/pfp3-2026-11-27/`; it is not rewritten.

## 1. What changed

`src/ec/p256/fixed_base.rs::try_fixed_base_mul` no longer returns early on the
scalar range. It computes the in-range predicate in constant time and **folds
the mask into the scalar the comb consumes**:

```rust
let out_of_range = ct_ge(&k, &ORDER_MODULUS);      // all-ones iff k >= n
// k_minus_n = k - n as a 256-bit wrapping subtraction (sub_borrow chain)
let mut reduced = [0u64; LIMBS];
select_limbs(&mut reduced, out_of_range, &k_minus_n, &k); // k-n when k >= n
```

A non-negative four-limb scalar is below `2n`, so for `k >= n` the reduced value
is `k - n` (`k mod n`) — exactly the value the ladder multiplies — and for
`k < n` it is `k`. The comb therefore returns the ladder's point for every
input, the decision is exact, and there is no `if`/`match`/`?`/early return on
the mask. The select is arithmetic (`sub_borrow` + `select_limbs`, whose mask
passes the crate's `value_barrier` counterpart); no new `unsafe` was added.

Refusal semantics preserved:

* a modified generator, a modified order, a foreign `EC_GFp_mont_method` and a
  different curve are still refused by `admits` **before** the scalar is
  touched — all four refusal tests pass, probe unchanged;
* a negative or wider-than-four-limb scalar is still refused on public
  metadata (`neg`, `d.len()`), not on a secret value;
* an out-of-range scalar produces the same externally observable result as the
  ladder (`Some(1)`, identical affine point). The new test
  `out_of_range_scalars_match_the_generator_ladder` checks `k = n`, `n+1`, `n+2`
  and `2^256−1` against the variable-base ladder and confirms the comb is
  entered (no early exit). The in-crate 4,096-case fixed-vs-variable
  differential and the four refusal tests are unchanged and pass.

The out-of-range value itself is not multiplied by the comb: it is replaced by
its reduced representative first. The externally observable path (return code
and point) is the ladder's.

## 2. Artefact

| item | value |
|---|---|
| source | `staging` `f8d5c4b33cf751a0dd805fa7cf0d730915e1d073` + uncommitted `src/ec/p256/fixed_base.rs` |
| source fingerprint | `52219f14f2402ffcb2b1ce5abcc843c168b79fb4798b9db66e50b5683c3b0aee` (887 files) |
| distribution DSO | `ecbefb7d4ecd05cb08f5ade57e64ce2cd81de24bcd68b0c236a8640a18559053` (17,123,976 bytes) |
| build-id | `01b4e75402b7c299d8b10c6293d4159f2cd85f9f` |
| archive | `14f76179c517213a35c3c1d69e3dccb722e228f7e12a81efceecb15bdac12bf6` |
| reproducibility | builds `d` and `e` are byte-identical in archive and DSO |

## 3. Constant-time audit (before → after)

| instrument | `04611380` (pre-fix) | `ecbefb7d` (post-fix) |
|---|---|---|
| ctgrind `mul-g-fixed` contexts | 1 / 1 / 1 | **0 / 0 / 0** |
| ctgrind `mul-g-fixed` errors | 1 / 1 / 1 | **0 / 0 / 0** |
| secret-derived conditional transfers | 1 (`je wNAF+0x1938`) | **0** |
| sensitivity control (`83f67826`, engine-on-path) | 4 / rep | **4 / rep (fires)** |
| branch audit `wNAF` jcc | 186 | **183** |
| `test $0x1,%cl` admission-mask jcc | 1 | **0** |
| shared inventory | 31/31, exit 0 | **31/31, exit 0** |

Carrier classification at `ecbefb7d`: `rcb_add` 0 jcc / 0 cmov / 40 setcc
(branch-free carry/borrow masks); `table_mul` 2 public loop jcc / 2 mask setcc;
`to_affine` 2 public jcc (loop + public exponent bit); `build_table` 1 public
jcc; `advance` 1 public jcc; the inlined `ossl_ec_wNAF_mul` 183 jcc / 34 cmov /
5 setcc of the pre-existing general wNAF path, with **no** admission-mask jcc.
The extra aggregated `cmov` is not secret-dependent: the same-digest ctgrind
reports zero contexts on the tainted fixed-base population (memcheck reports a
conditional move on an undefined condition).

## 4. Correctness at the digest

| block | result |
|---|---|
| `cargo test --lib -- p256` | **29 passed, 0 failed** (was 28; +1 out-of-range test) |
| 4,096-case fixed-vs-variable differential | **0 mismatches**, comb entered 4,096 times |
| refusal tests (generator/order/method/curve) | **4/4**, fast arm not entered |
| DSO differential `mul-g` (4,096 `k·G`) | **0 mismatches**, candidate stream == authority `a9e1068d…` |
| DSO differential `mul-p` (4,096 `k·P`) | **0 mismatches**, candidate stream == authority `bcb22a91…` |
| ECDSA cross-verify (256+256) | **512 accepted**, one agreed public key |

Scope: the DSO differential's `scalar_for` population is `[1, 2^255)`, so it
exercises the in-range comb at the artefact level; out-of-range equivalence
(`k = n, n+1, n+2, 2^256−1`) is established in-crate against the variable-base
ladder, on the same `ossl_ec_wNAF_mul` path, not in the DSO court.

## 5. Timing at the digest

| workload | `04611380` | `ecbefb7d` | cost |
|---|---:|---:|---:|
| `ecdsa256` | 10.64× [10.61, 10.67] | **10.58× [10.55, 10.62]** | −0.6 % |
| `ecdh` | 6.79× [4.69, 6.90] | **6.72× [6.67, 6.83]** | −1.0 % |

The branch-free admission costs no measurable amount; the eight unaffected rows
moved by a similar ±1–2 % between runs, so the two-digit difference is not
claimed as a trend (see `timing-ecbefb7d/REPORT.md`).

## 6. Residuals (unchanged, not repaired here)

* `PFP3-P34-COVERAGE` — the PFP-34 coverage-to-path join still names the ladder
  targets for the ecdsa-sign paths.
* `T23/T24/T29` timing residuals are unchanged by PFP-3.
* The timing subject is an uncommitted working tree (campaign rule); the DSO and
  archive digests are pinned and reproduced, but no clean-commit claim is made.

Evidence directories: `ctgrind/pfp3-2026-11-27-postfix/`,
`audit-postfix/`, `dso-differential-postfix/`, `timing-ecbefb7d/`, and
`build/raw/build-inputs-{d,e}.txt`.

## 7. Known consequence of editing `ARMS.json`

`evidence/performance-frontier/admission/ARMS.json` is a frozen member of
`evidence/a11/SCAN.json` and `evidence/a16/INVENTORY.json`. Changing the PFP-3
arm changes that member, so those two freeze verifiers will report population
drift until they are deliberately re-frozen. This is the same known consequence
recorded for the PFP-0 re-freeze; no freeze was silently rewritten here. The
admission validator (`performance_admission.py check`) accepts the register
(1 accepted, 0 refused, exit 0).
