# PFP-20 — the write-back `normalise` declassification boundary

**Status: PARTIAL.** The secret-dependent *branch* is gone and measured gone
(minimal-population ctgrind engine-on-path **4 → 0**, `store_coordinate` **4 → 0**
across three repetitions), the bound is established, the exported representation
is unchanged, and the DSO-bound differential and branch audit pass. What is **not**
done is the literal relocation: the trim still runs on coordinates that are still
secret (before `ladder_post`), so this is branch *elimination* at a named boundary,
not normalisation *after* declassification. §6 states exactly what remains.

Candidate: `staging` `d8be435a6` + PFP-20 (`src/bn/limbs.rs`, `src/ec/smpl.rs`,
`src/ec/mult.rs`, `src/ec/p256/tests.rs`). DSO `553e1b8c…`, built with HEAD's
`src/bn/arith.rs` so the delta from the recorded `83f67826…` candidate is PFP-20
alone; the working tree's unrelated PFP-6 `arith.rs` change was excluded for the
measurement and restored. Full identity: `pfp20-2026-11-26/dso-identity.txt`.

## 1. The mechanism

The admitted P-256 ladder runs entirely inside the fixed-width engine; when it
finishes, `p256_ladder_run` (`src/ec/mult.rs`) wrote four coordinates back:

```
store_coordinate((*r).x, ladder.rx_canonical().as_limbs())
store_coordinate((*r).z, ladder.rz_canonical().as_limbs())
store_coordinate((*s).x, ladder.sx_canonical().as_limbs())
store_coordinate((*s).z, ladder.sz_canonical().as_limbs())
```

`store_coordinate` (`src/ec/smpl.rs`) copied the four limbs into a `BIGNUM`
magnitude and called `limbs::normalise`:

```rust
while v.last() == Some(&0) { v.pop(); }
```

`BIGNUM` is sign-magnitude with **no trailing zero limbs**, so the trip count of
that loop is the number of zero limbs above the highest nonzero one — a function
of the secret coordinate. The value it computes is the represented length
`d.len()`. So the *observable* is the coordinate's limb count; the *mechanism* is
a loop whose iteration count is secret-derived. Removing the branch from the
engine's arithmetic (PFP-2) did not remove this one, because the write-back runs
after the engine and inherits the `BIGNUM` invariant.

## 2. Quantification of the leak

For `v` uniform in `[0, p)` with `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`
(so `2^192 ≤ p < 2^256`), the represented length is `4` unless the value is
below `2^192`:

| event | value | probability |
|---|---|---|
| top limb zero | `v < 2^192` | `2^192 / p = 2^-64 / (1 − 2^-32 + 2^-64 + 2^-160 − 2^-256) ≈ 2^-64 (1 + 2^-32) ≈ 5.421e-20` |
| top two limbs zero | `v < 2^128` | `2^128 / p ≈ 2^-128 ≈ 2.9387e-39` |
| top three limbs zero | `v < 2^64` | `2^64 / p = 2^-192 ≈ 1.5931e-58` |
| all four limbs zero | `v = 0` | `1 / p ≈ 2^-256 ≈ 8.64e-78` |

The length `L` is a deterministic function of the value, so the information an
observer of the length gains is `H(L)`. With `q = P(L ≠ 4) = 2^192/p ≈ 5.421e-20`:

```
H(L) = −q·log2(q) − (1−q)·log2(1−q)
     ≈ q·64 + q/ln 2
     ≈ 5.421e-20 · (64.693)
     ≈ 3.55e-18 bits  ≈  2^-58 bits.
```

**This is negligible, not merely small.** An observer learns essentially nothing
unless the value falls below `2^192`, an event with probability `2^-64`; even
then it learns only which 64-bit prefix the value has. The uniformity model is the
right proxy for the projective coordinates of a scalar multiplication with random
`k` (each is a pseudo-random field element), and for the final affine `x` the
quantity is public anyway (`r = x mod q` is the signature's public output). The
branchless trim below removes the timing channel unconditionally, so the bound is
a statement about the representation, not a residual timing exposure.

## 3. The boundary

A branchless equivalent of `normalise` was added at `src/bn/limbs.rs:63`,
`normalise_branchless`: it forms the retained length with `setne`-style arithmetic
(`(x | x.wrapping_neg()) >> 63`) over the slice's **public** width and installs it
with `Vec::set_len`, so no conditional jump depends on a limb. It is
byte-identical to `normalise` (same retained length, same contents, same
capacity).

The single write-back is now the named boundary:

* `src/ec/smpl.rs:2643` `store_coordinate` — the shared tree/engine write-back,
  documented as the declassification boundary: it converts the fixed-width slot
  or the engine's `Canonical4` into the exported `BIGNUM`, states what an
  observer of the length learns, and carries the §2 arithmetic.
* `src/ec/smpl.rs:2673` `declassify_coordinate` — the engine's typed entry; it
  takes `&Canonical4` so a still-secret engine value cannot be normalised
  anywhere but the boundary.
* `src/ec/mult.rs:696` — `p256_ladder_run` calls `declassify_coordinate` with the
  four `Canonical4`s; the `.as_limbs()` temporaries are gone.

The exported `BIGNUM` is unchanged for every value the engine can write,
including a zero top limb: `the_declassification_boundary_preserves_the_normalised_bignum`
(`src/ec/p256/tests.rs:1097`) compares the boundary's output with
`limbs::normalise` for zero, one/two/three-limb values, a full-width value, a
top-limb-only value, and `u64::MAX`. `the_branchless_trim_matches_the_loop_on_every_four_limb_shape`
(`src/bn/limbs.rs:1903`) checks all 16 zero/nonzero limb patterns.

## 4. Before and after ctgrind

Harness `minimal_mul4` (unchanged): one `EC_POINT_mul`, `taint-value`, the scalar
limb *values* marked undefined. Same container and valgrind for both sides; the
two DSOs differ by PFP-20 only.

| DSO | run | contexts | engine-origin (class B) | engine-on-path | `store_coordinate` |
|---|---|---:|---:|---:|---:|
| before `83f67826` | 1 | 204 | 0 | **4** | **4** |
| before `83f67826` | 2 | 196 | 0 | **4** | **4** |
| before `83f67826` | 3 | 207 | 0 | **4** | **4** |
| after `553e1b8c` | 1 | 200 | 0 | **0** | **0** |
| after `553e1b8c` | 2 | 196 | 0 | **0** | **0** |
| after `553e1b8c` | 3 | 225 | 0 | **0** | **0** |

The total context count varies run to run (the surrounding EC/BN path draws
random values that change which tainted sites execute); the write-back count does
not: `store_coordinate` is **4 before and 0 after** in every repetition, and
engine-origin is 0 both sides. The recorded history (`POST-FIX.md`: 188 contexts,
4 engine-on-path) was produced by an earlier run and is kept unchanged; the
controlled re-run above is the comparison that isolates PFP-20.

Negative control: `minimal_mul4 defined` on the after DSO — `ERROR SUMMARY: 0
errors`, exit 0 (`min-defined.out`).

## 5. Correctness, differential and audit

| check | result |
|---|---|
| `cargo test --lib -- p256` | **19 passed, 0 failed** (18 before + the new boundary test); the 144-case ladder differential (48 × MONT/SOLINAS/ARCH) and the reduction sweeps pass with 0 disagreements |
| `cargo test --lib -- bn` | **156 passed, 0 failed** (includes the new 16-pattern trim test) |
| DSO-bound differential `553e1b8c` | `mul-g` 4,096 / 0 mismatches, `mul-p` 4,096 / 0 mismatches; ECDSA 256 signs + 256 verifies each direction, one agreed public key. Evidence `../dso-differential-pfp20/differential-dso-bound.json` |
| branch audit `553e1b8c` | exit **0**, **9 of 9** targets resolved, 1 through the verified inline mapping (`mod_exp_core_consttime_from_parts`) |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

## 6. What remains (not silent)

1. **The boundary value is still secret.** The write-back runs at the end of the
   ladder and its `BIGNUM`s are consumed by the generic
   `ossl_ec_GFp_simple_ladder_post` before the affine result is public. The trim
   therefore still *encodes* the length of a secret coordinate; it no longer
   *branches* on it. Placing the conversion literally after declassification
   would require a fixed-width `ladder_post` (PFP-3/PFP-4 scale), not a move of
   this call.
2. **Downstream length consumers remain.** `limbs_from_slice` (read side),
   `BN_num_bits`, `BN_is_zero` and `ladder_post` still branch on the represented
   length/value. They are pre-existing and were already in the ctgrind count
   (e.g. 2 `BN_num_bits`, 2 `ladder_post` contexts); they are the variable-length
   representation's consumers, not the write-back normalise.
3. **The surrounding scalar arithmetic is still variable-time on this population**
   (`divide_fallible` ~64, `mul_fallible` ~30, `BN_nnmod`, `BN_add`, …). Those are
   the generic BIGNUM path and the scalar reduction, tracked by PFP-4/PFP-5, not
   by this item.
4. The branch audit is a review aid, not a constant-time proof; this item does not
   change the arm's `CANDIDATE` classification and does not claim the full ECDSA
   operation is constant-time.

## 7. Status rationale

PFP-20's measurable acceptance is met: the write-back branch is gone from the
secret path (ctgrind 4 → 0), the exported representation is asserted byte-identical
including a zero top limb, the boundary is named in source and here, the bound is
established, and ctgrind records the path with and without the change. It is
**not** marked DONE because the normalisation was not *relocated* after
declassification — it was made branchless in place, so the value is still secret
when the length is encoded. The security objective is discharged; the structural
one is not, and §6.1 states what would complete it.
