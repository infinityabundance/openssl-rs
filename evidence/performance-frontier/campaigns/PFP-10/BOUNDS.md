# PFP-10 — inversion candidates, iteration bounds and cost models

This document states the three candidates the item names, the iteration count each
performs, the derivation of those counts, the per-iteration cost model and the
crossover those models predict. The measurement is in
[`CROSSOVER.md`](CROSSOVER.md); the identity and gates are in
[`RECEIPT.md`](RECEIPT.md).

**No source is integrated.** The division of labour the measurement produced is:

* Fermat wins at the P-256 domains (256 bits) and at 521 bits;
* the divstep wins at 1024 and 2048 bits;
* the fixed-iteration binary GCD loses to the divstep at every measured size.

The reasons no winner was integrated are in `CROSSOVER.md` §5 and `RECEIPT.md`
§5. In short: the winning regime has no admissible locus (the P-256 operand is
branch-free reduced but the Fermat wins there; the generic path does not
guarantee a reduced operand and has no constant-time reduction), and the
prototype shows one secret-dependent conditional transfer per divstep under
release-like codegen — a STOP for a constant-time candidate.

---

## 1. Candidate A — Fermat over the order/field domain (the incumbent)

`x^(m-2) mod m` by square-and-multiply over the **public** compile-time exponent.
The exponent bits are public, so the branch on an exponent bit and the fixed
256-iteration count reveal nothing about the base. Two deployed forms are
measured:

| form | exponent | schedule | kernel |
|---|---|---|---|
| `P256Scalar::invert` (`src/ec/p256.rs`) | `ORDER_MINUS_2` | 256 squarings + one multiply per set bit | `Mont<OrderDomain>` (portable 4×4 schoolbook + REDC) |
| `fixed_base::invert` (`src/ec/p256/fixed_base.rs`) | `P_MINUS_2` | same | `Mont<FieldDomain>` |
| generic ladder (`bn::arith::mod_exp_core_consttime`) | `m-2`, L ≥ 1024 | const-time Montgomery ladder, fixed window | `mont_mul_sos_into` |

Iteration count: **L squarings plus `popcount(m-2)` multiplications**, fixed by a
public constant. For the two 256-bit domains this is 256 + 169 = **425**
`Mont` operations for the order (`ORDER_MINUS_2`) and 256 + 128 = **384** for the
field (`P_MINUS_2`).

Cost model: each operation is an n² schoolbook product plus an n² REDC, so the
whole inversion is **Θ(L·n²) = Θ(L³/4096)** limb-multiplies. At 256 bits that
is ~425 × (16 + 16) ≈ 13,600 64×64 multiplies.

## 2. Candidate B — fixed-iteration binary extended GCD (the incumbent for odd moduli)

`limbs::mod_inverse_consttime_with_mask` (`src/bn/limbs.rs`). It maintains
`u == a·x1 (mod m)`, `v == a·x2 (mod m)` and applies, per iteration, the first
applicable of: halve `u`; halve `v`; replace the larger odd value by `(u-v)/2`.
Every value test is a mask select.

Iteration count: **`2·64·n + 2`**, `n = max(m.len(), a.len())`, a function of the
public limb counts alone. For 4/16/32 limbs: **514 / 2050 / 4098**.

Cost model: each iteration performs two conditional subtractions, two
conditional additions/subtractions modulo `m`, **four** modular halvings
(`x+m` then shift then select) and four select-2s over n limbs. That is the
largest per-iteration constant of the three: measured ~97 ns/iteration at 256
bits, ~257 ns at 1024, ~482 ns at 2048. Total **Θ(L·n) = Θ(L²)** with a large
constant.

## 3. Candidate C — Bernstein–Yang `hddivsteps` (prototype)

`bn::divstep::mod_inverse_divstep_with_mask` (`src/bn/divstep.rs`), safe Rust,
prototype only. State `(delta, f, g, v, r)` with `f == v·a (mod m)` and
`g == r·a (mod m)`; each divstep applies the first applicable of
`(delta+2, f, g/2, v, r/2)` (`g` even or `delta <= 0`) and
`(2-delta, g, (g-f)/2, r, (r-v)/2)` (`g` odd and `delta > 0`), with `delta`
starting at `1/2` and kept scaled by two in an `i64` so every value is an
integer. `f` stays odd, so every division by two is exact.

### 3.1 Iteration bound and its derivation

The loop runs a fixed

```
N(h limbs) = floor((3787 · 64h + 2166) / 1644)
```

steps. For 4/16/32 limbs: **591 / 2360 / 4718**.

Derivation, in the order the bounds literature establishes it:

1. The **original** Bernstein–Yang divstep (`delta` starts at 1) is proved to need
   at most **741** divsteps for 256-bit inputs (ePrint 2019/266, Theorem 11.2);
   `sipa/safegcd-bounds` sharpens this to **724** by convex-hull analysis.
2. Starting `delta` at `1/2` (updated `2±delta`) is algebraically the same
   algorithm; the hull analysis gives the closed form
   `floor((3787·log2 M + 2166)/1644)` divsteps for `M >= 2 301 079`, verified for
   all `M <= 2^4096`. With `log2 M <= 64h` this is the formula above. For 256
   bits it reads 591, which is the "≈590 for a 256-bit modulus" the campaign
   already recorded in the PFP-4 design note.
3. Our domains are 256 ≤ L ≤ 2048 bits with normalized moduli far above the
   floor, so the verified range covers every measured case.
4. The published bound is a **statement about the half-delta recurrence**, not
   about our code. It is validated independently here: `convergence_steps`
   (test-only, early-exit, not constant-time) measures the realised count over
   the differential population. Across widths 4, 5, 8 and 16 limbs the worst
   realised count is **0.887 of the bound**, and every realised count is within
   it. That is a check of this implementation, not a re-proof of the bound.

The task's reference figure of "about 2·64·n + 1" (= 513 at 256 bits) is **too
small**: a random 256-bit population under `delta = 1` needs up to 558 steps, so
513 would produce wrong answers for some inputs. The published bound is used
instead of the heuristic.

### 3.2 Constant-time discipline (source-level)

Fixed step count; every value-dependent decision is an all-ones/all-zeros mask
(`delta` sign, `g`'s low bit, the `>= m` correction, the `|f| == 1` test); no
early exit; no limb-indexed table. Coefficients are kept reduced modulo `m` with
the same modular-halving primitive as the binary GCD, so **there is no final
multiplication by a power of two** in this formulation: the 2-adic scaling is
absorbed by the modular halving at each step, and the closing step is a
fixed-cost modular subtraction selected on the sign of `f`. (The
integer-coefficient formulation does need such a multiply; that variant was not
implemented.) The secret-derived masks are passed through the crate's existing
`black_box` value barrier (the `ct_select2_into` technique).

Source-level intent is **not** the measured result: at release-like codegen
ctgrind reports one secret-dependent conditional transfer per divstep (see
`RECEIPT.md` §4). That is a STOP for the candidate; see `CROSSOVER.md` §5.

### 3.3 Cost model

Each step does one signed subtract, one masked signed add, two arithmetic
shifts, two modular add/subtracts, one modular halving and three selects over
n or n+1 limbs. Measured ~38 ns/step at 256 bits, ~95 ns at 1024, ~189 ns at
2048 — linear in the limb count. Total **Θ(B(L)·n) = Θ(L²)** with a smaller
constant than the binary GCD and a larger constant than a single Montgomery
multiply.

---

## 4. Predicted crossover

| pair | model | prediction |
|---|---|---|
| Fermat vs divstep | Θ(L³/4096) vs Θ(L²) | divstep overtakes Fermat at large L; a cubic/quadratic fit through the 256-bit point (Fermat 11.6 µs, divstep 22.6 µs) puts the crossing near 500–600 bits, with the constant factors pushing the realised crossing later |
| GCD vs divstep | both Θ(L²), divstep's per-step constant ratio measured 0.42–0.46 | divstep should win at every size |
| Fermat vs GCD | Θ(L³) vs Θ(L²) | Fermat wins at small L, GCD overtakes at large L (measured: GCD wins at 2048) |

The measurement (`CROSSOVER.md`) confirms the direction of all three and places
the Fermat/divstep crossing between **521 and 1024 bits** (log-log interpolation
≈ **750 bits**), later than the simple cubic/quadratic model predicts.
