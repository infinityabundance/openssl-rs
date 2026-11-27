# PFP-3 — fixed-base P-256 multiplication: derivation and the authority check

Date: 2026-11-27. Candidate: `staging` **HEAD `b0ada60ebd72432daaef68d8ee6d7cd5245f7895`**
with the PFP-3 working-tree changes (this campaign does not commit). Source
fingerprint of every `src/**/*.rs` (including the new `src/ec/p256/fixed_base.rs`):
`ca5cc146006b4d771fc4b9a9ffd8109199f25c61ef7de0d9e90160232bd2d46a`.
Distribution DSO `04611380847a708a591a9786734915c4295cc0e164d94025dc937b797ffb15d4`
(17,128,536 bytes, build-id `5a70df9f12a1ada45b0a250fb97019afcb55ebe7`). Authority
`openssl-3.6.4-production`, sha256 `611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2`.

## 1. Where the base point comes from

The base point is **not** a literal in the new code. `src/ec/p256/fixed_base.rs`
reads `Gx` and `Gy` (and `p`, `a`, `b`, `n`) from
`crate::ec::curve_data::_EC_X9_62_PRIME_256V1_DATA`, the generated array whose
module documentation records that every value was **read back from the admitted
authority** and cross-checked member-for-member against the authority's own
`EC_CURVE_DATA` before the file was written. The layout used is the documented
one: 20-byte seed, then eight 32-byte fields `p || a || b || Gx || Gy || order ||
RR_p || RR_n`; the code indexes `Gx` at field 3 and `Gy` at field 4.

## 2. How the table is derived

At **first use** (a `OnceLock`), the code builds the 16-entry comb table

```text
  Q[v] = Σ_{j=0..3} v_j · 2^{64j} · G          v ∈ [0, 16)
```

from the tracked generator by the complete point formulas:
`B_0 = G`, `B_{j+1} = 2^{64} · B_j` (64 complete doublings each), then
`Q[v] = Q[v \ lowbit] + B_{bitindex(lowbit)}` using the complete addition. No
table is transcribed; there is no invented constant. `Q[0]` is the point at
infinity.

`k·G` is then evaluated by Horner's rule over the 64 columns,
`acc ← 2·acc + Q[column_i]`, where `column_i` packs the scalar bits
`{i, i+64, i+128, i+192}`. This is a fixed 64 doublings and 64 additions.

## 3. The authority check

The table is verified against the authority at the DSO level, over **4,096**
scalars, not a sample. `dso-differential/` runs the PFP-2 harness unchanged:
`mul-g` calls the exported `EC_POINT_mul(group, r, k, NULL, NULL)`, which enters
the fixed-base arm on both the candidate and the authority, serialises the
resulting affine point, and compares the two point streams byte for byte.

| case | cases compared | mismatches | candidate output sha256 |
|---|---:|---:|---|
| `mul-g` (fixed-base `k·G`) | 4,096 | **0** | `a9e1068d9c28846fd8beec36d372845723e9f253f3c09602fe93bfb7a23361fd` |
| `mul-p` (variable-base `k·P`) | 4,096 | **0** | `bcb22a91415f5a8593262b56935218f0a21712b2bbedddb2d8824d485af9e23b` |

The `mul-g` stream is identical in the candidate and the authority, so every
derived multiple the table produces is the authority's own multiple. Each
process proves the file it mapped (`LOADED` realpath/dev/ino/size against
`stat`, `LIB` from `dladdr`) before any case runs; the candidate digest is
checked before and after. Record: `dso-differential/differential-dso-bound.json`.
