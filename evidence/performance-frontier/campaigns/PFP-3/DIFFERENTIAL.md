# PFP-3 — correctness differential

All counts below are at the candidate source fingerprint
`ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`.

## 1. DSO level, against the authority (4,096 + 4,096 + ECDSA)

`dso-differential/` (PFP-2 harness reused unchanged, bound to the new DSO
`04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`):

| court | population | mismatches |
|---|---:|---:|
| `mul-g` — fixed-base `k·G` through the comb, serialised point vs authority | 4,096 | **0** |
| `mul-p` — variable-base `k·P`, serialised point vs authority | 4,096 | **0** |
| ECDSA candidate-signs / authority-verifies | 256 | 256 accepted |
| ECDSA authority-signs / candidate-verifies | 256 | 256 accepted |

The four ECDSA processes derive one public key
(`04bf5059…15b63`), and the message sequences agree. Identity: 8/8 process rows
`ok`, each `LOADED` realpath/dev/ino/size matched `stat`. Record:
`dso-differential/differential-dso-bound.json`.

This is the authority check of the table: the `mul-g` candidate and authority
streams are byte-identical over 4,096 scalars.

## 2. In-crate differential (fixed-base arm vs the generic ladder)

`fixed_and_variable_base_agree_over_thousands` (`src/ec/p256/fixed_base.rs`)
runs **4,096** scalar/point combinations through

* the fixed-base arm: `EC_POINT_mul(group, r, k, NULL, NULL)`, and
* the generic variable-base ladder: `EC_POINT_mul(group, r, NULL, G, k)`,

and compares the points with `EC_POINT_cmp`. **0 mismatches.** The population
includes `k = 0, 1, 2, 3, n-1, n-2, 2^64, 2^128, 2^192`, a four-limb value, and
pseudorandom values reduced mod `n`. The test also asserts the fast arm ran for
every one of the 4,096 cases (the probe counter advanced by exactly 4,096), so a
silent fallback cannot make the test pass.

This is also the **fixed-base / variable-base equivalence** result: for every
admitted scalar the two paths return the same point.

### Limit: the DSO arm is not proven load-bearing by a mutation control

The 4,096 `mul-g` comparisons prove the candidate's `EC_POINT_mul(k·G)` agrees
with the authority; they do not by themselves prove the DSO took the *comb* arm
rather than a silent ladder fallback. The in-crate test asserts the fast arm ran
(the probe advanced 4,096 times) in the **test** build, and the runtime
admission conditions hold for the exported group (plain method, tracked
generator, default `Mont` kernel), but a DSO-level mutation control — perturb a
table entry and show `mul-g` mismatches — was **NOT_RUN**. Until it is, the DSO
path is established by construction and by the in-crate probe, not by a mutated
artefact.

## 3. PFP-22 domain classes that apply

The applicable classes — boundaries, exceptional points, and the generator as a
non-special input — are covered by the structured scalar population above and by
`the_complete_formula_pins_the_exceptional_cases` (`∞`, doubling, `G + (-G)`,
`2·∞`). Limb-occupancy classes are a field-engine concern unchanged by this
batch; the PFP-2 `p256` tests still pass (28 passed).

## 4. Gates

| gate | result |
|---|---|
| `cargo test --lib -- p256` | **28 passed, 0 failed** |
| `cargo test --lib -- ec::` | **83 passed, 0 failed, 1 ignored** (pre-existing) |
| `cargo test --lib` (full) | **2,484 passed, 0 failed, 54 ignored** |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean |

(This replaces the observed floor of 1,962 / PFP-2's 2,474 by 10 new tests; no
test was ignored or removed.)
