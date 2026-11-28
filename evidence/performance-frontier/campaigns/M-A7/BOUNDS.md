# M-A7 — carry-save accumulation: bound, prediction and refusal permission

**Queue item:** M-A7. **Claim class:** `SCOPED_OBSERVATION` (court venue,
wall-clock; no PMU). **This document is written before the prototype**, as the
task requires, so that the measurement is judged against a stated figure rather
than a post-hoc story.

```yaml
source_identity:
  parent_sha:        450b8352  (branch staging)
  result_sha:        none — nothing is committed by this agent; no production
                     path is changed
authority_contract:  none (measurement + differential only); the compared
                     function is the admitted fixed-width CIOS kernel
                     mont_mul_cios_fixed::<N, N+2> (src/bn/arith.rs:2005-2076)
```

## 0. What this arm is, and what it is not

Carry-save keeps radix 2^64 limbs and changes **only when carries are
propagated**: the running Montgomery accumulator is a redundant `(s, c)` word
pair, each limb product writes into two independent word streams, and a single
propagation pass at the end converts the pair to the ordinary value.

It is **not** M-A2. M-A2 changed the **digit width** to 52 bits, which costs an
extra limb and 56.25 % more limb products and lost 3.41-3.44x at 256 bits. That
refusal is about a wider, under-filled radix. M-A7 keeps `n` limbs and `2n^2`
limb products exactly, so the M-A2 result is **not** evidence against this arm,
and the M-A2 refusal must not be cited against it. The only shared mechanism is
"deferred propagation"; the cost structure is different.

## 1. The loop and its product count (unchanged from CIOS)

For `n` limbs, `B = 2^64`, one CIOS multiplication performs `n` outer iterations.
Each iteration has two rows:

* **product row**: `acc += a * b_i`, `n` limb products;
* **reduction row**: `acc += u * m`, `n` limb products, `u = acc[0] * n0 mod B`.

Total **`2n^2` limb products** (256-bit `n=4`: 32; 1024-bit `n=16`: 512) and
`4n^2` accumulator-word additions. Both the admitted kernel and the prototype
perform exactly these counts; carry-save does not add or remove a product.

## 2. Dependency depth of the admitted CIOS kernel

Each limb-product step is

```text
(carry_out, acc[j]) = acc[j] + a[j]*b_i + carry_in
```

The multiply `a[j]*b_i` is independent of its neighbours, but `carry_in` is the
previous step's `carry_out`, so the additions form a **serial chain of length
`n` per row**. There are `2n` rows (two per iteration), and rows are coupled
forward through the accumulator: iteration `i`'s product step at column `j` reads
`acc[j]` as finalised by iteration `i-1`'s reduction step at column `j+1`.

Two different quantities have to be kept apart:

| quantity | value | n = 4 | n = 16 |
|---|---|---:|---:|
| dependent adder operations along the per-row carry chain | `n` per row, `2n` rows, rows chained | 32 | 512 |
| **critical path in adder levels** | `~2n` (the diagonal of the row/column dependency grid: each node waits for the previous column's carry and for the previous row's shifted reduction) | ~8 | ~32 |
| **work / floor** | `2n^2` multiplies at one per cycle on the multiplier port, plus ~2 adds per product at 4-wide issue (`~1.5` cycles/product) | ~48 cycles | ~768 cycles |

The row-level chain is not the whole story, because out-of-order execution can
overlap the two rows of neighbouring iterations; the honest latency figure is the
**diagonal** path, `~2n` dependent add nodes of ~2 cycles each, i.e. `~4n`
cycles. But the measured kernel is **not** at that latency bound: it sits near the
throughput floor. Anchoring on the campaign's own admitted numbers for the same
fixed-width kernel (M-A1 by-product measurements, quoted in the M-A2 record):

> **PFP-57 note (2026-11-27).** This "sits near the throughput floor" bound rests
> on the throughput explanation, which is a hypothesis, not a finding, and whose
> counterpart is `PFP-48`'s carry-chain conclusion. No bound in `M-A3` to `M-A6`
> may rest on either explanation until hardware performance counters exist.

| width | measured CIOS | throughput floor (model) | gap = removable fraction |
|---|---:|---:|---:|
| 256-bit (`n=4`) | 12.6 ns (~50 cycles @4 GHz) | ~48 cycles (~12 ns) | **≤ 4 %** |
| 1024-bit (`n=16`) | 227 ns (~908 cycles @4 GHz) | ~768 cycles (~192 ns) | **~15 %** |

(Clock normalisation is approximate and is used only to size the bound; the
measurement itself is wall-clock ns/op, not cycles.)

## 3. Dependency depth of a redundant accumulator

The prototype keeps two arrays `s[0..L]`, `c[0..L]`, representing
`V = sum_p (s[p] + c[p]) * B^(p-off)`. A row is accumulated by a *descending*
pass over the positions: at position `p`,

```text
z_p = s[p] + c[p] + lo(product at j=p-off) + hi(product at j=p-off-1)
s'[p] = z_p mod B          c'[p+1] = z_p / B
```

No position reads a value written earlier in the same pass: `s[p]` and `c[p]` are
the previous pass's outputs, the two product words come from independent
multiplies, and `c'[p+1]` is read only by the **next** pass (descending order
makes the read-before-overwrite true even in place). Carry therefore never
threads through a row: the row's `n` position updates are independent.

The remaining depth is the per-position recurrence across passes:

| quantity | CIOS | redundant accumulator |
|---|---|---|
| cross-position carry chain within a row | **yes, length n** | **none** |
| dependent nodes on the critical path | ~2n (diagonal) | ~3n (2n passes + n positions of the `c` recurrence) |
| independent work per pass | 1 carry chain (little ILP) | n+2 positions (full ILP) |
| additions per limb product | 2 (+ carry handling) | 4-6 (`s`, `c`, `lo`, `hi` as 128-bit sums) |
| multiplies per limb product | 1 | 1 (unchanged) |

So carry-save trades a **serial carry chain** for **extra independent
additions**. Its floor is therefore *higher* than CIOS's: roughly
`1.5-2` cycles per position becomes `~2-2.5` cycles per position if 4-wide issue
holds, i.e. the redundant pass must retire ~5-7 µops per position against CIOS's
~3 µops per limb product plus its dependent `adc`.

## 4. Predicted figure

From §2 and §3:

* the fraction of CIOS wall-clock that is *removable* carry latency is at most
  the §2 gap: **≤ 4 % at 256 bits, ~15 % at 1024 bits**;
* carry-save's extra additions raise its own work floor by roughly 50-100 % of
  that gap, so the net prediction is **parity at 1024 bits and a loss at
  256 bits**, with a plausible best case of ~+5 % at 1024 bits and a plausible
  worst case of -25 % at both.

> **PFP-57 note (2026-11-27).** This predicted figure is conditional on the §2
> throughput-floor bound, which is a hypothesis, not a finding; it is recorded
> as a pre-registered hypothesis and may not bound `M-A3` to `M-A6` until
> counters exist.

**Prediction:** `ratio = T_cs / T_cios` in `[0.95, 1.05]` at 1024 bits and
`[1.00, 1.30]` at 256 bits. The arm earns a further measurement only if the
1024-bit ratio is below `1 - 3 %` (twice the campaign's ~1.5 % noise band).

## 5. Refusal permission

This arm is authorised to refuse **with the arithmetic** above. It refuses if:

1. the measured 1024-bit ratio is within the noise band (`|ratio - 1| ≤ 1.5 %`)
   or slower — the removable fraction predicted in §2 does not survive the
   conversion; or
2. the 256-bit ratio is ≥ 1.0 as predicted; or
3. the differential finds any mismatch against CIOS (that is a STOP before any
   performance verdict is read).

A refusal here is a *measured* statement about instruction scheduling on a
4-wide scalar core, not about the idea of redundant accumulation on hardware
with a wider multiplier array.

## 6. Literature cited as technique only

No code is copied, vendored or linked from any of these; they are the source of
the technique and of the comparison methodology.

1. Ç. K. Koç, T. Acar, B. S. Kaliski Jr., *Analyzing and comparing Montgomery
   multiplication algorithms*, IEEE Micro 16(3), 1996 — the CIOS/SOS/FIOS
   taxonomy and the word-level cost model used in §1.
2. A. F. Tenca, Ç. K. Koç, *A scalable architecture for Montgomery
   multiplication*, CHES 1999 — redundant carry-save accumulator with a final
   propagation pass; the `(s, c)` pair and delayed-carry organisation.
3. Ç. K. Koç, *RSA hardware implementation*, RSA Labs TR-801, 1996 — carry-save
   accumulation in the Montgomery inner loop.
4. S. Gueron, *Efficient software implementations of modular exponentiation*,
   ePrint 2011/239 / J. Cryptographic Engineering 2012 — the two-independent-chain
   (`mulx` + `adcx`/`adox`) organisation that the authority uses and that LLVM
   will not emit from this safe-Rust formulation; cited here only to explain why
   instruction count alone (PFP-46/PFP-48) did not move wall-clock.
5. Intel, *New Instructions Supporting Large Integer Arithmetic on Intel
   Architecture Processors* (ADX whitepaper, 2012) — the flag-split rationale.

The M-A7 hypothesis is exactly the software analogue of (2): remove the carry
from the accumulation step and settle it once. Whether that helps a 4-wide
scalar core with a 1/cycle multiplier is the measurement this arm performs.
