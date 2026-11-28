# PFP-62 — algebraic multi-block GHASH, measured at four widths per regime

Source identity and full gate: see `../PFP-68/RECEIPT.md`. This receipt covers
the aggregation step only.

## Form

`Y_{i+w} = (Y_i xor X_1)·H^w xor X_2·H^(w-1) xor … xor X_w·H` over `w`
complete blocks, from `H^1..H^w` precomputed once per GCM call. Reduction is
linear over GF(2), so the implementation sums the `w` **full 256-bit products**
in `__m128i` accumulators and applies **one** Alg9 reduction per group, not one
per term. `H` powers are stored pre-twisted (`tw[i] = twist(H^i)`) so the hot
loop never re-twists a key power.

Constant time: `w` is public; `p[width-j]` is selected by the loop index, never
by ciphertext or secret data. No secret-indexed table and no secret branch.

## Width table (`raw/width-table.txt`, final candidate)

| width | 64 B (us) | 16 KiB (us) |
|---|---:|---:|
| 2 | **1.492** | 9.718 |
| 3 | 1.496 | 8.953 |
| 4 | 1.514 | 8.095 |
| 5 | 1.503 | 8.279 |
| 6 | 1.530 | 8.415 |
| 7 | 1.522 | 8.685 |
| 8 | 1.533 | **7.624** |

The regimes differ exactly as anticipated:

* **64 B → w=2** (w=3 statistically tied; 4-8 add `H^2..H^8` power derivation
  that a four-block message cannot repay). Production `bulk_width` already
  selects 2 for `len <= 128`; unchanged.
* **16 KiB → w=8**, 1.27x faster than w=2.

## Did the arithmetic independence deliver?

Yes, but only after PFP-5 removed the serialised AES bottleneck. On the
intermediate tree (reflected GHASH, still one AES block per callback) the same
sweep preferred **w=2** at 16 KiB — w=2 45.75 us vs w=8 48.73 us — because the
AES/CTR cost dominated and the wider group only added power-derivation and loop
cost. After multi-block AES+VAES the same sweep prefers **w=8** (7.63 us vs
9.73 us). So the algebraic form delivered where a generic carry-save arm had
not: the independence was real, but it was hidden behind a larger independent
serial cost.

## Verification

* `ghash_group_matches_serial_chain`: group == serial chain over random
  operands, widths 2..8.
* `gcm_all_widths_match_serial_reference` and
  `gcm_stream_path_matches_serial_reference`: widths 1..8 over the required
  (pt,aad) set and twelve partial/non-multiple-of-16 lengths, including the
  stream path.
* NIST GCM cases 1, 2 and 5 at every width; tamper rejection at every width.
* Cross-library differential identical on all five capability arms
  (`../PFP-68/raw/diff-summary.txt`).
