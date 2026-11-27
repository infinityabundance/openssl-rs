# PFP-3 — admission precondition and refusal tests

`fixed_base::admits(group)` requires **all** of:

* field modulus `p` == the tracked P-256 prime;
* group order `n` == the tracked P-256 order;
* curve `a` == `p - 3` and `b` == the tracked `b`;
* cofactor == 1;
* the method is `ec_method_field_is_plain` **and** its `ladder_step` is
  `ossl_ec_GFp_simple_ladder_step` (a foreign `EC_METHOD` is refused);
* `generator.z_is_one != 0` and its affine `X, Y` equal the tracked `Gx, Gy`.

A caller that is not admitted leaves `try_fixed_base_mul` with `None` and runs
the unchanged Montgomery ladder, preserving its own semantics.

## Tests (all in `src/ec/p256/fixed_base.rs`)

| test | group | admission | fast arm entered | result |
|---|---|---|---|---|
| `a_modified_generator_is_refused` | standard group, generator replaced by `2G` | refused | **no** (probe unchanged) | equals variable-base ladder |
| `a_modified_order_is_refused` | standard group, order `n-1` | refused | **no** | equals variable-base ladder |
| `a_foreign_method_is_refused` | `EC_GROUP_new_curve_GFp(p,a,b)` (Montgomery method) with the standard `G` and `n` | refused on the method predicate alone | **no** | equals variable-base ladder |
| `a_different_curve_is_refused` | `secp256k1` (different curve, its own valid generator) | refused | **no** | equals variable-base ladder |

`refusal_case` asserts the probe count did not move across the candidate's
`EC_POINT_mul(group, r, k, NULL, NULL)`, so the fast arm was not merely
producing the right answer by coincidence — it was not entered. The correctness
comparison is against the variable-base ladder on the **same** group.

The admitted case is exercised by `the_fast_arm_is_reachable` (probe advances by
exactly one and `1·G` equals the generator) and by the 4,096-case differential.

## Exceptional cases PFP-22 pins

`the_complete_formula_pins_the_exceptional_cases` checks, in the admitted
formula: `∞ + G = G`, `G + ∞ = G`, `G + G = 2G`, `G + (-G) = ∞`, and
`2·∞ = ∞`. The 4,096-case differential includes `k = 0` (infinity), `k = 1`
(the generator), `k = n-1`, `k = n-2`, and points where the comb's internal sum
meets a doubling or an inverse (`P + (-P)`), all matching the ladder.
