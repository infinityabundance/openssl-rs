# PFP-42 — re-evaluating the PFP-8 window-table refusal at the new composition

**Item:** re-evaluate the PFP-8 prepared/window-table refusal under the width
policy PFP-5/PFP-8 inherited and PFP-40/PFP-43 changed (PFP-42).

**Claim class:** `SCOPED_OBSERVATION` on the court venue (no hardware PMU; the
wall timings are paired process-level medians, see `RECEIPT.md`).

**Source `S`:** `staging` `e73999b5d9f71ba6abc8d3ae89fabecea4e4c6c1`
(`src` tree `2200c5cee7c24357b814cc950033a32929e71a59`); the only build-relevant
change is `src/bn/arith.rs` (sha256 before `92057de3…f9739`, after
`63df636e…5471df`). Build-relevant tree otherwise clean
(`raw/before.env`, `raw/after.env`).

**Decision: PROCEED.** The bound crosses the campaign's noise floor at the
ffdhe2048 policy geometry and at modexp-8192; a public-geometry selector is
implemented and measured. This is not the PFP-8 conclusion, and §4 states why.

---

## 1. What changed since PFP-8, and why the old refusal does not transfer

PFP-8 (`evidence/performance-frontier/campaigns/PFP-8/BOUND.md` §1.1, §2, §5)
measured the ladder running at the **modulus width**:

* `bits = 64 · md.len() = 2048`, `w = 5`, `windows = 410`, `entries = 32`;
* table build `2^w − 2 = 30` multiplications = **1.19 %** of the exponentiation;
* best prepared window `w = 6` at **2.21 %** faster — below the campaign's 10 %
  refusal threshold. **REFUSE.**

The composition is no longer that. PFP-40/PFP-43 resolve the DH ladder to the
group's declared exponent width, so:

* `ffdhe2048`: 256 bits = 4 limbs × 64, not 2048 bits;
* `ffdhe3072`: 320 bits = 5 limbs × 64, not 3072 bits.

The same 30-multiply `w = 5` table build is now `30 / 344 = 8.72 %` of the
ladder's Montgomery operations, **7.2×** the PFP-8 share. A table that was a
rounding error at 2 492 operations is a material cost at 344. The refusal must
be recomputed, not inherited.

## 2. The model

For a left-to-right fixed window of width `w` over a `bits`-bit exponent, with a
`M`-limb modulus:

```text
windows     = ceil(bits / w)
mont_ops(w) = windows·w          squarings (exactly w per window)
            + windows            main-loop multiplications (one per window)
            + (2^w − 2)          table build (table[0]=R, table[1]=base)
            + 2                  conversions (base fold, final out)
            = windows·(w+1) + 2^w
scan_ir(w)  = windows · 2^w · M · 3        masked full-table scan, 3 Ir/limb-select
cost(w)     = mont_ops(w)·C(M) + scan_ir(w)
```

`C(M)` is the measured per-Montgomery-multiply instruction count at `M` limbs.
The scan coefficient is the campaign's **conservative** upper bound: PFP-8
measured the vectorised scan at 1 013 Ir/window where this model charges
`2^w·M·3 = 3 072`, so the model never understates the table. The production
selector uses exactly this form (`scan = 3`, `saturating` arithmetic,
`src/bn/arith.rs:select_window_bits`).

### 2.1 Coefficients and their provenance

| M (limbs) | C(M) Ir/multiply | provenance |
|---:|---:|---|
| 4 | 333 | **measured** — PFP-41 `raw/instruction-mix.txt`, `n4.full`, fully-unrolled CIOS (32 products) |
| 16 | 4 679 | **measured** — PFP-41, `n16`, 512 products |
| 32 | 21 163 | **measured** — PFP-41, `n32`, 2 048 products (PFP-8's dynamic `mont_mul_ladder_into` call is 21 186, 0.1 % higher) |
| 48 | 47 617 | **inferred** — `k·M²`, `k = 21 163/32² = 20.667` Ir/limb², anchored on the measured n=32 kernel |
| 128 | 338 608 | **inferred** — same quadratic scaling |

The quadratic inference is not a limb-count ratio imposed on unlike kernels: it
is the CIOS schedule's own operation count (`2·M²` limb products per multiply)
with the measured per-product cost of the shipped kernel. It reproduces the
*measured* `n = 4` figure to 0.6 % (331 vs 333), which is why only the `n = 32`
anchor is load-bearing. The `n = 16` point is 13 % cheaper than the quadratic
fill because LLVM unrolls and spills that width; using the quadratic value
overstates scan-relative cost there, which cannot flatter the table.

## 3. The bound: predicted best width per geometry

Measured coefficients, `scan = 3`, over the geometries that exist. The two DH
rows run the ladder at the policy width against a larger modulus; the modexp
rows run it at the modulus width.

| geometry | (ladder limbs, modulus limbs) | `bits` | best `w` | predicted saving vs `w=5` |
|---|---|---:|---:|---:|
| ffdhe2048 policy | (4, 32) | 256 | **4** | **−3.10 %** |
| ffdhe3072 policy | (5, 48) | 320 | **4** | −0.55 % |
| modexp-1024 | (16, 16) | 1024 | 5 | 0.00 % (already best) |
| modexp-2048 | (32, 32) | 2048 | 5 | 0.00 % (already best) |
| modexp-8192 | (128, 128) | 8192 | **7** | **−2.61 %** |

The full `w = 1..=8` sweeps are in `raw/cost-model.txt`. The decision boundaries
are stable: the best width is `4` at (4,32) and (5,48), `5` at (16,16) and
(32,32), and `7` at (128,128) for every scan coefficient 1, 2 or 3. Only
modexp-2048 moves (5 at scan=3, 6 at scan=1–2) and both are inside ±0.83 %.

The two DH rows are the composition PFP-8 did not have:

```text
ffdhe2048 policy, W=256, M=32
  w=4: windows=64  mont_ops=336 (table 14, 4.17%)  total 7,209,072 Ir
  w=5: windows=52  mont_ops=344 (table 30, 8.72%)  total 7,439,816 Ir
  -> w=4 is 3.10% cheaper
```

`w = 4` wins because it removes one main-loop multiplication per ~4 bits while
halving the table and the scan; `w = 6` loses because the 64-entry table and
its scan grow faster than the 9 fewer windows save.

## 4. Old refusal beside the new arithmetic

| | PFP-8 (modulus-width) | PFP-42 (policy-width) |
|---|---|---|
| ladder width | 2048 bits (32 limbs) | 256 bits (4 limbs) |
| `w = 5` mont_ops | 2 492 | 344 |
| table build `2^5 − 2` | 30 | 30 |
| table share | **1.20 %** (measured 1.19 %) | **8.72 %** (7.2×) |
| best other `w` | `w = 6`, **2.21 %** faster | `w = 4`, **3.10 %** faster |
| bar for a change | 10 % refusal threshold | campaign noise **1.2–1.5 %** |
| conclusion | **REFUSE** (2.21 % < 10 %) | **PROCEED** (3.10 % > 1.5 %) |

The change of conclusion is the geometry, not a re-reading of a graph: the
table's share rose 7.2× when the ladder shortened 8×, and the same `w = 4`
schedule now removes more than the campaign's control-noise band.

The model is an instruction-count bound, not a timing result. It decides *which*
width to try; `RECEIPT.md` §4 is the measurement that decides whether it pays.

## 5. Decision

**PROCEED.** Implement a selector that derives `w` from public geometry only
(the resolved ladder width and the modulus limb count) and use it on the
production dispatch paths. The selector is
`src/bn/arith.rs:select_window_bits`; it evaluates the model above and returns
the minimum-cost `w ∈ 1..=8`, with the admitted `w = 5` as the fallback. It
never reads an exponent value or the exponent's own normalised length; the
schedule it selects is fixed for a given `(w, bits)` and therefore for a given
group configuration.

This is the per-geometry selection the item explicitly prefers: modexp-8192 gets
`w = 7` because the model says it pays there, while modexp-2048 stays at `w = 5`
so the large-exponent path is not moved unless it is measured to win.

Deliberate deviations / properties kept:

* the masked full-table scan is unchanged (`select_window_digit`);
* the table still lives in a `SecretBuf` and is cleansed on every exit;
* table dimension and offset arithmetic keep their checked multiplication
  (`entries.checked_shl`, `entries.checked_mul(n)`);
* the bit-at-a-time reference (`window = None`) is untouched and remains the
  differential oracle;
* **zero new `unsafe`** (the diff contains none).

Residual, recorded in `RECEIPT.md`: the artefact-bound ctgrind/branch-audit
evidence is source-bound to the PFP-8 digest; no ctgrind or branch audit was
re-run at this digest, so that obligation is `NOT_RUN`, not inherited as pass.
The source-level property (public-geometry, constant-pattern schedule, no
secret-dependent index) is unchanged.
