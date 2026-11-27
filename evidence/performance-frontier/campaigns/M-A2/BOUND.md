# M-A2 — reduced-radix (2^52) deferred-carry arithmetic: bounds

**Status: experiment. No admission. No `src/` change.**
Source identity: `staging` `f9deefd1937e471b291a198b5f355bf2454c7e7b` plus the
untracked experiment crate `courts/performance-frontier/m-a2/`
(`Cargo.toml` `d105f7be…63adb`, `src/lib.rs` `be7007d9…08136`,
`src/main.rs` `c95479be…db5a1`). The crate is `#![forbid(unsafe_code)]`, has no
dependencies, and is excluded from packaging by the root manifest (`courts/**`).

This file records the arithmetic obligations of the arm — representation, the
extra-limb cost, the accumulator bound and its proof, and the final-subtraction
obligation. An unproven bound would be a refusal; the bound below is proved for
the largest modulus in scope.

## 1. Representation and the extra-limb cost

Radix `B = 2^52`, `N` limbs, `R = B^N`; modulus odd, `m < B^N`, top limb
non-zero; operands `a, b < m` in canonical 52-bit limbs.

| width | `N` | `R = B^N` | spare bits above the modulus | 64-bit limbs |
|---|---:|---|---:|---:|
| 256 bits | 5 | `2^260` | 4 | 4 |
| 1024 bits | 20 | `2^1040` | 16 | 16 |

The 52-bit representation uses 25% more limbs at both widths (5 vs 4, 20 vs 16).
Both CIOS variants execute `2N²` limb products per multiply (product row plus
reduction row, `N` iterations), so the reduced-radix kernel executes
`(N52/N64)² = (5/4)² = (20/16)² = 1.5625` — **56.25% more limb products** than
the radix-2^64 kernel at the same modulus size (50 vs 32 at 256 bits; 800 vs 512
at 1024 bits). On top of that, the deferred variant moves `N` `u128` coefficients
per iteration (`N²` coefficient moves in total) and performs one final `N`-limb
settling pass.

`RESULTS.md` records the measured consequence: the extra work is not recovered
by removing the carry chain.

## 2. Accumulator bound (proof)

`mont_mul_52_deferred` holds `N` `u128` coefficients `acc[0..N]`, deliberately
**not renormalised** inside the loop. Each limb product is at most
`(B-1)² < 2^104`. The obligation is that no coefficient can overflow a `u128`.

Let `B = 2^52`, `P = 2(B-1)² < 2^105`, `S = P/(B-1) < P/2^51`, and let `C_j` be
the bound on `acc[j]` at the start of an iteration. Claim:

```text
    C_j <= (N - j) * P + S          for j = 0 .. N-1
```

**Base case.** All coefficients start at zero.

**Inductive step.** With `0 <= a_j, m_j, b_i, u < B`:

1. After the product row `a*b_i` and the reduction row `u*m` are accumulated,
   `D_j = acc_j + a_j*b_i + u*m_j <= C_j + 2(B-1)² = C_j + P`, hence
   `D_j <= (N - j + 1) * P + S`.
2. The deferred shift divides the represented value by `B` exactly (the low
   coefficient is a multiple of `B` by construction of `u`). It sets
   `C'_0 = D_1 + floor(D_0/B)`, `C'_j = D_{j+1}` for `1 <= j <= N-2`, and
   `C'_{N-1} = 0`.
   - For `j >= 1`: `C'_j = D_{j+1} <= (N - j) * P + S`.
   - For `j = 0`: `floor(D_0/B) <= ((N+1)P + S)/B <= P`, because
     `N + 1 + 1/(B-1) <= 21 < B = 2^52`. Therefore
     `C'_0 <= (N-1)P + S + P = N*P + S`.
   - `C'_{N-1} = 0 <= P + S`.

So every coefficient is below `(N+1)P < 2(N+1)B²` at every point in the loop.
For the largest modulus in scope (`N = 20`):

```text
    2 * 21 * 2^104 = 42 * 2^104 < 2^109.4  <  2^128
```

`N = 5` is smaller (`12 * 2^104 < 2^107.6`). Consequences:

- a `u128` coefficient can hold `2^128 / 2^104 = 2^24 = 16,777,216` maximal
  104-bit limb products; the proven worst case uses fewer than
  `2(N+1) = 42` of them;
- the headroom is at least **18.6 bits** at 1024 bits and 20.4 bits at 256 bits;
- adding both product rows (`< 2^105`) to a coefficient below `2^110` cannot
  overflow, and the settling pass adds a carry below `2^59`.

The induction only needs `N + 1 + 1/(B-1) <= B`, i.e. `N < 2^52`, so the same
bound covers every width down to one limb and up to any practical limb count;
the stated numeric headroom is the 1024-bit and 256-bit cases actually measured.

The value invariant is the ordinary CIOS one: the represented value before the
final subtraction is below `2m` because `a < m`, `b_i < B`, `u < B`, so
`T' = T + a*b_i + u*m < 2m + 2(B-1)m = 2Bm` and `T'/B < 2m`. The bound above is
about the *representation* (which can hold a value below `2B^N` with large
coefficients), not about the value; that is why it must be proved separately.

## 3. Settling-pass and final-carry bounds

After the last iteration the value `T < 2m < 2B^N`. The single settling pass
computes `v = acc[j] + carry`, stores `v & (B-1)` and carries `v >> 52`; with
`acc[j] < 2^110` and `carry < 2^59`, `v < 2^111` and the next carry is below
`2^59`, so no `u128` overflow. The carry out of the top limb is
`floor(T / B^N)`.

For the widths in scope `2m < B^N` (`m < 2^256` and `B^5 = 2^260`;
`m < 2^1024` and `B^20 = 2^1040`), so the final carry is **0** and the `high`
argument of `conditional_subtract` is never 1 here. It is retained for
generality and its use is proved: if `high` were 1, the value would be
`B^N + x`, and the base-`B` borrow chain produces the digits of
`B^N + x - m` (the final borrow of 1 *is* the `B^N` term), which is the same
argument the incumbent uses.

## 4. The final subtraction is radix-specific (found by the differential)

A reduced-radix port **cannot transcribe** the incumbent's final subtraction.
The crate computes `x[j] - m[j] - borrow` with `u64` wrapping, which is a valid
base-`2^64` digit; for base-`2^52` an intermediate underflow stores
`2^64 - d` instead of `2^52 - d` and corrupts the value. The experiment's first
run was stopped by exactly this: **666 of 60,864 pairs mismatched and 667 outputs
were non-canonical at 256 bits** (`exit 2`). The fix masks the wrapped difference
to 52 bits and decides the borrow by `x[j] < m[j] + borrow` (which cannot
overflow); because `2^64 = 0 mod 2^52`, masking recovers the exact base-`2^52`
digit. After the fix both widths are clean (see `RESULTS.md`).

The same run exposed a population defect worth recording: at 1024 bits the
conditional-subtraction path is reached with probability about
`m²/R / (m + m²/R) = m/R = 2^-16` under random operands, so the broken kernel
passed 13,776 random pairs at that width. Forced cases (`a = 1`,
`b = r*R mod m`, `r` in `{0,1,2,3,m-1}`) make `T >= m` reachable at both widths
and are part of the recorded population.

## 5. Scope of these obligations

- Proved: the `u128` accumulator bound for `B = 2^52`, any `N < 2^52`, and the
  concrete 256-bit/1024-bit widths; the settle and final-carry bounds.
- Not claimed: constant-time behaviour (no timing or branch audit is performed
  by this experiment); any statement about the distribution DSO; any statement
  about correctness beyond the tested population.
- No `unsafe`: the crate is `#![forbid(unsafe_code)]`; there is no assembly and
  no intrinsic.
