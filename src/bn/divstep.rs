//! Bernstein–Yang `hddivsteps` modular inversion (PFP-10 prototype, PFP-58
//! admission).
//!
//! PFP-10 measured this candidate against the Fermat inverse
//! ([`crate::ec::p256::P256Scalar::invert`] and
//! [`crate::bn::arith::mod_exp_core_consttime`]) and the fixed-iteration binary
//! GCD ([`crate::bn::limbs::mod_inverse_consttime_with_mask`]) and refused it
//! because of one secret-derived branch per step at release-like codegen. PFP-58
//! removed that transfer, verified the release artifact with ctgrind (firing
//! control included) and a `jcc`/`setcc`/`cmov` audit, and measured it at
//! ~0.38-0.40x the GCD on composite 1024/2048-bit moduli. It is now the
//! odd-modulus inverse used by the RSA blinding refresh
//! ([`crate::bn::blinding`]), but only when the modulus is inside its verified
//! iteration-bound domain (46..=4096 bits); an even or out-of-domain modulus
//! keeps the previous variable-time / fixed-iteration helper. The P-256 loci
//! still use Fermat, which wins there.
//!
//! ## Algorithm
//!
//! Bernstein–Yang divsteps (ePrint 2019/266), in the **half-delta** variant
//! (`hddivsteps`): `delta` starts at `1/2` and is updated `2 - delta` / `2 + delta`
//! rather than `1 - delta` / `1 + delta`. The variant is algebraically the same
//! algorithm with a better worst-case iteration bound; it is not an approximation.
//! The narrow `delta` is kept scaled by two in an `i64`, so every value in the
//! recurrence is an integer.
//!
//! The state is the standard `(delta, f, g, v, r)` tuple with the invariant
//!
//! ```text
//!     f == v * a (mod m)        g == r * a (mod m)
//! ```
//!
//! for the odd modulus `m` and operand `a`, initialised `(1/2, m, a, 0, 1)`. Each
//! divstep applies the first applicable of
//!
//! * `delta <= 0` or `g` even: `(delta + 2, f, g/2, v, r/2)`
//! * `delta > 0` and `g` odd:  `(2 - delta, g, (g - f)/2, r, (r - v)/2)`
//!
//! where the coefficient halving is the modular halving `x/2 mod m` (add `m` when
//! `x` is odd, then shift), exact because `m` is odd. `f` stays odd, so every
//! integer division by two is exact. At termination `g = 0`, `|f| = gcd(a, m)`, and
//! `v = f * a^-1 (mod m)`; when the gcd is one, `v` is `±a^-1`.
//!
//! ## Iteration bound
//!
//! The loop runs a fixed number of steps derived from `m`'s limb count alone:
//!
//! ```text
//!     N = floor((3787 * L + 2166) / 1644),   L = 64 * m.len()
//! ```
//!
//! This is the published `hddivsteps` bound (Wuille's `sipa/safegcd-bounds`),
//! written with `d = L` (the bit width):
//!
//! ```text
//!     N = floor((45907 * d + 26313) / 19929)
//! ```
//!
//! **These are two forms of one bound, not two independent estimates.** The
//! rational functions are not identical — they disagree by one at six
//! non-limb-aligned bit lengths in `[46, 4096]` (`335, 760, 1185, 1979, 2404,
//! 3623`) — but they agree at **every** bit length that is a multiple of 64.
//! This module only ever evaluates the bound at `d = L = 64 * m.len()` (the
//! buffer width), and at `256, 512, 1024, 1536, 2048, 3072, 4096` both forms give
//! `591, 1180, 2360, 3539, 4718, 7077, 9436`. Because `64 * m.len()` is at least
//! the modulus' real bit length, evaluating the limb-aligned form is never
//! smaller than Wuille's bit-length form.
//!
//! ## What kind of evidence, and the exact domain
//!
//! The bound is a **computer-aided analysis, not a machine-checked proof**: the
//! safegcd-bounds computation enumerates reachable `(delta, f, g)` states and
//! fits the iteration count. Its conditions are `0 <= g <= f <= M` with odd `M`,
//! `M >= 2301079` (equivalently `d >= 46` as used here), and `M <= 2^4096`. Too
//! few iterations on an input outside those conditions returns a **wrong**
//! coefficient, so the domain is a **correctness** precondition, not a timing
//! remark.
//!
//! [`modulus_is_in_verified_domain`] is therefore the admission predicate used
//! by the RSA blinding caller ([`crate::bn::blinding`]). A modulus outside it
//! falls back to [`crate::bn::limbs::mod_inverse_consttime`]; no caller receives
//! an inverse computed with an unproven iteration count. The documented range is
//! through 4096 bits, and the differential population exercised here is 256,
//! 1024, 2048 and 3072 bits; the 4096-bit point is checked by the resolved
//! bound assertion and a sampled convergence check, **not** by an exhaustive
//! proof at that width.
//!
//! **A CRT result check is not a substitute for a bound that holds.** A CRT
//! consistency check can only reject a bad inverse *after* it was computed, and
//! the retry would still be computed with the same unproven iteration count; it
//! cannot make a too-small bound safe. The admission predicate is what makes the
//! domain safe, and it is checked before any coefficient is computed.
//!
//! `L` is the *bit width* of the buffer, so the count is a function of public
//! geometry, never of a limb value. For 256 bits this is **591**, for 1024 bits
//! **2360**, for 2048 bits **4718**, for 3072 bits **7077**, for 4096 bits
//! **9436**. The original `delta = 1` variant needs 741/724 for 256 bits
//! (paper/safegcd-bounds), so the half-delta variant is not a cosmetic choice.
//!
//! ## Constant-time discipline
//!
//! * The step count is fixed and public.
//! * Every value-dependent decision is an all-ones/all-zeros mask: the delta sign,
//!   `g`'s low bit, the `>= m` correction and the final `|f| == 1` test. There is
//!   no branch on a limb value, no table index derived from a limb and no early
//!   exit.
//! * `f` and `g` are two's-complement `w`-limb signed values; the branch-free
//!   shift of an even signed numerator is exact, matching the division the
//!   recurrence requires.
//! * The final coefficient is negated by a modular subtraction selected on the
//!   sign of `f`; there is no final multiplication by a power of two because the
//!   coefficients are kept reduced `mod m` at every step (the alternative
//!   integer-coefficient formulation needs such a multiply; this one does not).
//! * Scratch is one [`SecretLimbs`] allocation split into disjoint slices with
//!   `split_at_mut`, so the borrow checker establishes that no region is aliased.
//!   `Drop` volatile-wipes the whole allocation on every exit path. The returned
//!   coefficient is copied out into an ordinary result vector, exactly as the
//!   fixed-iteration binary GCD does.
//!
//! ## Input staging and the blinding factor's length (PFP-74)
//!
//! `mod_inverse_divstep_with_mask` stages the operand with
//! `copy_from_slice(&a[..a.len().min(w)])`, and the destination is zeroed scratch
//! (the same pattern appears in the test-only `convergence_steps`). The copy
//! length is the operand's **normalised limb count**, which for the RSA caller is
//! a function of the secret random blinding draw.
//!
//! This is classified as a **residual leakage channel, not an authorised
//! declassification.** An observer of the copy loop's duration learns at most the
//! number of leading zero *64-bit limbs* of the draw; it learns nothing about the
//! draw's nonzero limbs or bits.
//!
//! The information is bounded and small in the RSA setting. The modulus' top bit
//! is set and the draw is uniform in `[0, m)`, so the top limb is zero with
//! probability at most `2^-64` when the modulus' bit length is a multiple of 64
//! (the common case: a `k`-bit RSA modulus has `k` a multiple of 8, and 2048 bits
//! is 32 limbs). When the bit length is not limb-aligned the top limb can be zero
//! with probability up to about `2^-1`, but that still reveals only the single
//! decision "the leading limb is zero", never a limb value. The timing cost is at
//! most `w` limb copies against a fixed step count of
//! `floor((3787*64*w + 2166)/1644)` (9436 steps at 4096 bits), so it is a bounded
//! additive term independent of the private exponent the blinding protects. A
//! fresh draw is used for every refresh, so the property is not linkable across
//! operations.
//!
//! It is recorded as a residual obligation rather than promoted to a
//! declassification: eliminating it needs a fixed-width, masked staging copy,
//! which is a separate change and would itself have to preserve the branch-free
//! property. **No constant-time claim is made about this channel.**
//!
//! ## Toolchain requalification (PFP-74)
//!
//! `core::hint::black_box` is a **best-effort optimisation barrier, not a
//! constant-time guarantee.** It hides a value from the optimiser *as that
//! toolchain implements it*; a compiler version whose `black_box` lowering,
//! inlining or code-generation heuristics differ can fold the barrier away and
//! re-introduce the secret-dependent branch PFP-58 removed.
//!
//! The PFP-58 release-artifact audit (zero secret-derived `jcc`/`cmov` in the
//! fixed-step loop, with the ctgrind firing control firing in the same run) was
//! performed under:
//!
//! * **`rustc 1.98.1 (48a229cea 2026-09-01)`**, target `x86_64-unknown-linux-gnu`;
//! * release profile `opt-level = 3`, `debug = 0`, `overflow-checks = true`,
//!   `codegen-units = 16`, no LTO;
//! * `valgrind 3.19.0` memcheck (ctgrind technique) and an `objdump`
//!   `jcc`/`setcc`/`cmov` audit of the shipped DSO.
//!
//! **Standing obligation:** any change to the compiler version, target,
//! optimisation level, codegen-units, LTO or `black_box` implementation requires
//! that audit and the ctgrind firing control to be **re-run** before the
//! branch-free claim is reused. Do not claim the barrier survives a compiler
//! upgrade.
//!
//! ## Domain
//!
//! `m` must be **odd** and greater than one; `a` must satisfy `0 <= a < m`. The
//! caller establishes the range (in the P-256 paths a four-limb operand is below
//! `2m` and one masked subtraction reduces it). The function refuses an empty or
//! even modulus, which is a property of the modulus alone. It is safe Rust: a
//! caller that violates the range precondition gets a wrong answer, never
//! undefined behaviour.
//!
//! ## Composite moduli (PFP-58)
//!
//! **Primality is not required for correctness.** The recurrence computes
//! `gcd(a, m)` and the coefficient `v` with `v * a == ±gcd(a, m) (mod m)` for any
//! positive odd `m`; when the gcd is one, `v` is the inverse. The returned mask is
//! the invertibility verdict, so a composite modulus is handled exactly like a
//! prime one: a non-coprime `a` yields an all-zeros mask (and `None` from
//! [`mod_inverse_divstep`]), which is the ordinary "no inverse, retry" answer.
//!
//! The published half-delta iteration bound also assumes only `0 <= g <= f <= M`
//! with odd `M` above its verified floor, not primality. For this entry point
//! `f = m`, `g = a`, so `a < m` is the caller's obligation as before.
//!
//! The caller must therefore establish:
//!
//! * `m` is odd and `m > 1` (an empty/even `m` is refused);
//! * `0 <= a < m` (a wider `a` is silently truncated by the fixed-width buffer);
//! * whether a non-invertible `a` is an error: the mask says so, and the RSA
//!   blinding caller retries the draw, preserving the authority's schedule.

use crate::bn::alloc::try_zeroed as try_zeroed_bn;
use crate::bn::limbs::Limb;
use crate::runtime::secret::SecretLimbs;

// ---------------------------------------------------------------------------
// Masks and small limb helpers
// ---------------------------------------------------------------------------

/// All ones when `x == 0`, all zeros otherwise.
///
/// The value barrier is placed **between** the arithmetic and its use, not on
/// the finished mask: it hides the `x | -x` range from the optimiser so the
/// subtraction cannot be rewritten into a comparison-and-select (which the
/// backend lowered to a conditional branch in the PFP-10 release build).
#[inline(always)]
fn ct_is_zero_mask(x: Limb) -> Limb {
    let non_zero = x | x.wrapping_neg();
    let nz = core::hint::black_box(non_zero >> (Limb::BITS - 1));
    nz.wrapping_sub(1)
}

/// All ones when `x` is odd, all zeros otherwise.
#[inline(always)]
fn ct_odd_mask(x: Limb) -> Limb {
    0u64.wrapping_sub(x & 1)
}

/// All ones when the signed value `delta` is strictly positive.
///
/// Each component is an opaque value when it is combined: the optimiser sees
/// neither that `sign_bit` is `delta < 0` nor that `zero` is `delta == 0`, so
/// it cannot contract `!sign & !zero` into `delta > 0` and emit a branch.
#[inline(always)]
fn ct_positive_mask(delta: i64) -> Limb {
    let bits = delta as u64;
    let sign_bit = core::hint::black_box(bits >> (Limb::BITS - 1));
    let sign = 0u64.wrapping_sub(sign_bit);
    let zero = ct_is_zero_mask(bits);
    !sign & !zero
}

/// Sign extension of the top limb: all ones for a negative value.
#[inline(always)]
fn sign_extend(x: &[Limb]) -> Limb {
    let top = x.last().copied().unwrap_or(0);
    ((top as i64) >> (Limb::BITS - 1)) as u64
}

/// `out = x - y` over `out.len()` limbs, sign-extending both operands into the
/// extra limb.
#[inline(always)]
fn sub_signed_wide(out: &mut [Limb], x: &[Limb], y: &[Limb]) {
    let w = out.len() - 1;
    let (xs, ys) = (sign_extend(x), sign_extend(y));
    let mut borrow: Limb = 0;
    for i in 0..w {
        let (d1, b1) = x[i].overflowing_sub(y[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = Limb::from(b1) | Limb::from(b2);
    }
    let (d1, b1) = xs.overflowing_sub(ys);
    let (d2, _) = d1.overflowing_sub(borrow);
    out[w] = d2;
    let _ = b1;
}

/// Arithmetic `out = out >> 1` over the full (signed) width.
#[inline(always)]
fn shr1_signed_wide(out: &mut [Limb]) {
    let w = out.len();
    for i in 0..w.saturating_sub(1) {
        out[i] = (out[i] >> 1) | (out[i + 1] << (Limb::BITS - 1));
    }
    // The top limb is arithmetic: its sign bit is shifted in.
    out[w - 1] = ((out[w - 1] as i64) >> 1) as u64;
}

/// Logical `out = x >> 1`.
#[inline(always)]
fn shr1_into(out: &mut [Limb], x: &[Limb]) {
    let w = out.len();
    for i in 0..w {
        let high = if i + 1 < w { x[i + 1] } else { 0 };
        out[i] = (x[i] >> 1) | (high << (Limb::BITS - 1));
    }
}

/// Logical `out = (carry_in * 2^w + x) >> 1` over `x.len()` limbs.
#[inline(always)]
fn shr1_with_carry_into(out: &mut [Limb], x: &[Limb], carry_in: Limb) {
    let mut next = carry_in & 1;
    for i in (0..x.len()).rev() {
        out[i] = (x[i] >> 1) | (next << (Limb::BITS - 1));
        next = x[i] & 1;
    }
}

/// `out = a - b` over `out.len()` limbs; returns the all-ones borrow mask.
#[inline(always)]
fn sub_with_borrow(out: &mut [Limb], a: &[Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = ai.overflowing_sub(bi);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *o = d2;
        borrow = Limb::from(b1) | Limb::from(b2);
    }
    0u64.wrapping_sub(borrow)
}

/// `out = (a - b) mod m` for `a, b < m`.
#[inline(always)]
fn sub_mod(out: &mut [Limb], a: &[Limb], b: &[Limb], m: &[Limb]) {
    // Same best-effort value barrier as `add_mod`: the borrow mask is derived from
    // the secret operands, and without the barrier the compiler is free to lower
    // `m[i] & borrow` to a conditional add.
    let borrow = core::hint::black_box(sub_with_borrow(out, a, b));
    // `out` holds `2^w + a - b`; adding `m` under the borrow and dropping the
    // carry gives `a - b + m`, which is in `[0, m)`.
    let mut carry: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let add = m[i] & borrow;
        let (s1, c1) = o.overflowing_add(add);
        let (s2, c2) = s1.overflowing_add(carry);
        *o = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
}

/// `out = (a + b) mod m` for `a, b < m`. `diff` is `out.len()` limbs of scratch.
#[inline(always)]
fn add_mod(out: &mut [Limb], a: &[Limb], b: &[Limb], m: &[Limb], diff: &mut [Limb]) {
    let mut carry: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        *o = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
    // `out - m`; keep it when the sum carried out or did not borrow.
    let borrow_bit = sub_with_borrow(diff, out, m) & 1;
    // The crate's value barrier (`ct_select2_into` uses the same technique): a
    // best-effort optimisation barrier so the compiler does not recognise the
    // all-ones/all-zeros mask and lower the select to a conditional branch. It is
    // not a guarantee about the emitted code or its timing.
    let sum_ge_m =
        core::hint::black_box(0u64.wrapping_sub(carry) | 0u64.wrapping_sub(1 - borrow_bit));
    for (o, d) in out.iter_mut().zip(diff.iter()) {
        *o = (*d & sum_ge_m) | (*o & !sum_ge_m);
    }
}

/// `out = x / 2 mod m` for odd `m` and `x < m`.
///
/// `sum` is `out.len() + 1` limbs, `half` is `out.len()` limbs.
#[inline(always)]
fn halve_mod(out: &mut [Limb], x: &[Limb], m: &[Limb], sum: &mut [Limb], half: &mut [Limb]) {
    let odd = core::hint::black_box(ct_odd_mask(x[0]));
    shr1_into(out, x);
    let mut carry: Limb = 0;
    for i in 0..x.len() {
        let (s1, c1) = x[i].overflowing_add(m[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        sum[i] = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
    sum[x.len()] = carry;
    shr1_with_carry_into(half, &sum[..x.len()], sum[x.len()]);
    for (o, h) in out.iter_mut().zip(half.iter()) {
        *o = (*h & odd) | (*o & !odd);
    }
}

/// `out = select(mask, a, b)`.
#[inline(always)]
fn select_into(out: &mut [Limb], mask: Limb, a: &[Limb], b: &[Limb]) {
    let mask = core::hint::black_box(mask);
    for (i, o) in out.iter_mut().enumerate() {
        *o = (a[i] & mask) | (b[i] & !mask);
    }
}

// ---------------------------------------------------------------------------
// One divstep
// ---------------------------------------------------------------------------

/// The disjoint scratch regions a step needs. Slices into one allocation.
struct Scratch<'a> {
    /// Two signed numerators, signed width plus one limb.
    wide_a: &'a mut [Limb],
    wide_b: &'a mut [Limb],
    /// The next signed `f` and `g`.
    next_f: &'a mut [Limb],
    next_g: &'a mut [Limb],
    /// Four coefficient-width temporaries.
    t0: &'a mut [Limb],
    t1: &'a mut [Limb],
    t2: &'a mut [Limb],
    t3: &'a mut [Limb],
}

/// `out = x + (y & mask)` over the signed width, sign-extending the masked `y`.
#[inline(always)]
fn add_signed_masked_wide(out: &mut [Limb], x: &[Limb], y: &[Limb], mask: Limb) {
    let ws = x.len();
    let mut carry: Limb = 0;
    for i in 0..ws {
        let (s1, c1) = x[i].overflowing_add(y[i] & mask);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
    let (s1, c1) = sign_extend(x).overflowing_add(sign_extend(y) & mask);
    let (s2, c2) = s1.overflowing_add(carry);
    out[ws] = s2;
    let _ = (c1, c2);
}

/// Apply one `hddivstep`. All decisions are masks; no limb value is branched on.
///
/// `f` and `g` are **signed** and therefore one limb wider than the modulus:
/// `m` is close to `2^(64 w)` and does not fit in a signed `w`-limb value. The
/// coefficients `v` and `r` are residues `mod m` and stay `w` limbs wide.
#[inline(always)]
fn divstep(
    f: &mut [Limb],
    g: &mut [Limb],
    v: &mut [Limb],
    r: &mut [Limb],
    delta: &mut i64,
    m: &[Limb],
    s: &mut Scratch<'_>,
) {
    let g_odd = core::hint::black_box(ct_odd_mask(g[0]));
    let cond = core::hint::black_box(ct_positive_mask(*delta) & g_odd);

    // f' = cond ? g : f; g' = (cond ? g - f : g + (g odd ? f : 0)) / 2.
    sub_signed_wide(s.wide_a, g, f);
    add_signed_masked_wide(s.wide_b, g, f, g_odd);
    shr1_signed_wide(s.wide_a);
    shr1_signed_wide(s.wide_b);
    for ((o, &a), &b) in s
        .next_g
        .iter_mut()
        .zip(s.wide_a.iter())
        .zip(s.wide_b.iter())
    {
        *o = (a & cond) | (b & !cond);
    }
    for ((o, &gg), &ff) in s.next_f.iter_mut().zip(g.iter()).zip(f.iter()) {
        *o = (gg & cond) | (ff & !cond);
    }
    f.copy_from_slice(s.next_f);
    g.copy_from_slice(s.next_g);

    // delta' = cond ? 4 - delta : 4 + delta (scaled by two).
    let lowered = 4i64.wrapping_sub(*delta);
    let raised = 4i64.wrapping_add(*delta);
    *delta = (((lowered as u64) & cond) | ((raised as u64) & !cond)) as i64;

    // v' = cond ? r : v; r' = (cond ? r - v : r + (g odd ? v : 0)) / 2 mod m.
    for (o, &vi) in s.t0.iter_mut().zip(v.iter()) {
        *o = vi & g_odd;
    }
    sub_mod(s.t1, r, v, m);
    add_mod(s.t2, r, s.t0, m, s.t3);
    for (o, &b) in s.t1.iter_mut().zip(s.t2.iter()) {
        *o = (*o & cond) | (b & !cond);
    }
    halve_mod(s.t2, s.t1, m, s.wide_a, s.wide_b);
    select_into(s.t0, cond, r, v);
    r.copy_from_slice(s.t2);
    v.copy_from_slice(s.t0);
}

// ---------------------------------------------------------------------------
// Bound
// ---------------------------------------------------------------------------

/// Lowest modulus bit length for which the published `hddivsteps` bound is
/// established.
///
/// The analysis assumes `M >= 2301079` and states the equivalent condition
/// `d >= 46`; a shorter modulus is outside the computer-aided verification and
/// must use the fixed-iteration binary GCD.
pub(crate) const VERIFIED_MIN_MODULUS_BITS: usize = 46;

/// Highest modulus bit length covered by the published computational bound
/// (`M <= 2^4096`).
///
/// A wider modulus would make [`iteration_bound`] return a count at a buffer
/// width the analysis never covered, so the divstep is not admitted there.
pub(crate) const VERIFIED_MAX_MODULUS_BITS: usize = 4096;

/// Whether a modulus of `bit_len` normalised bits is inside the domain where
/// [`iteration_bound`] is the published, computer-aided bound.
///
/// This is the admission predicate the RSA blinding refresh uses. Inside it the
/// fixed-step divstep may compute the inverse; outside it the caller must use
/// [`crate::bn::limbs::mod_inverse_consttime`]. The predicate is on the modulus'
/// bit length, which is public, so it adds no secret-dependent branch.
pub(crate) fn modulus_is_in_verified_domain(bit_len: usize) -> bool {
    (VERIFIED_MIN_MODULUS_BITS..=VERIFIED_MAX_MODULUS_BITS).contains(&bit_len)
}

/// The fixed `hddivsteps` iteration count for a buffer of `limbs` limbs.
///
/// `floor((3787 * 64 * limbs + 2166) / 1644)` — the limb-aligned form of
/// Wuille's published half-delta bound. It is a computer-aided result valid for
/// the domain guarded by [`modulus_is_in_verified_domain`], not a
/// machine-checked proof. `None` only on arithmetic overflow of the public
/// width.
pub(crate) fn iteration_bound(limbs: usize) -> Option<usize> {
    let bits = limbs.checked_mul(Limb::BITS as usize)?;
    let numerator = bits.checked_mul(3787)?.checked_add(2166)?;
    Some(numerator / 1644)
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// `a^-1 mod m` for **odd** `m`, answering the coefficient and an all-ones
/// invertibility mask.
///
/// The coefficient is the fixed width `m.len()` and is **not** trimmed. `0` maps
/// to the coefficient `0` with a zero mask: the mask reports that the gcd is not
/// one (it is `m`), exactly as the fixed-iteration binary GCD does, while the
/// coefficient `0` is what the Fermat path computes for a zero base. A caller
/// whose modulus is prime — the P-256 order — may ignore the mask and store the
/// coefficient; a caller that must report failure uses the mask.
///
/// `a` must satisfy `0 <= a < m`. An empty or even modulus is refused. The
/// modulus need **not** be prime; see the module's "Composite moduli" section.
pub(crate) fn mod_inverse_divstep_with_mask(a: &[Limb], m: &[Limb]) -> Option<(Vec<Limb>, Limb)> {
    if m.is_empty() || m[0] & 1 == 0 {
        return None;
    }
    let w = m.len();
    let steps = iteration_bound(w)?;
    let ws = w.checked_add(1)?;
    let wide = ws.checked_add(1)?;
    // f, g, next_f, next_g (signed width), wide_a, wide_b (signed width + 1),
    // t0..t3 (coefficient width).
    let total = ws
        .checked_mul(4)?
        .checked_add(wide.checked_mul(2)?)?
        .checked_add(w.checked_mul(6)?)?;

    let mut scratch = SecretLimbs::try_zeroed(total)?;
    let whole: &mut [Limb] = &mut scratch;
    let (f, rest) = whole.split_at_mut(ws);
    let (g, rest) = rest.split_at_mut(ws);
    let (v, rest) = rest.split_at_mut(w);
    let (r, rest) = rest.split_at_mut(w);
    let (wide_a, rest) = rest.split_at_mut(wide);
    let (wide_b, rest) = rest.split_at_mut(wide);
    let (next_f, rest) = rest.split_at_mut(ws);
    let (next_g, rest) = rest.split_at_mut(ws);
    let (t0, rest) = rest.split_at_mut(w);
    let (t1, rest) = rest.split_at_mut(w);
    let (t2, rest) = rest.split_at_mut(w);
    let (t3, _rest) = rest.split_at_mut(w);

    f[..w].copy_from_slice(m);
    // PFP-74: `take` is the operand's normalised limb count, so the copy length
    // is a function of the secret draw. This is a bounded residual timing channel
    // (see "Input staging" above), documented rather than hidden; the destination
    // is zeroed scratch, so the omitted limbs are already zero.
    let take = a.len().min(w);
    g[..take].copy_from_slice(&a[..take]);
    r[0] = 1;
    let mut delta: i64 = 1; // 2 * (1/2)

    let mut s = Scratch {
        wide_a,
        wide_b,
        next_f,
        next_g,
        t0,
        t1,
        t2,
        t3,
    };
    for _ in 0..steps {
        divstep(f, g, v, r, &mut delta, m, &mut s);
    }

    // |f| = gcd(a, m); the inverse exists exactly when it is one. f is signed, so
    // its magnitude is `f` or `-f` over the signed width; the magnitude of a
    // gcd is below `m` and its high limbs are zero. The negation is a full
    // multi-limb subtraction, not a per-limb wrap.
    let f_neg = core::hint::black_box(0u64.wrapping_sub(f[ws - 1] >> (Limb::BITS - 1)));
    sub_with_borrow(next_f, &[], f);
    let mut diff = 0u64;
    for (i, (&negated, &value)) in next_f.iter().zip(f.iter()).enumerate() {
        let magnitude = (negated & f_neg) | (value & !f_neg);
        diff |= if i == 0 { magnitude ^ 1 } else { magnitude };
    }
    let invertible = ct_is_zero_mask(diff);

    // v = f * a^-1 (mod m): negate it when f is negative.
    sub_mod(t1, &[], v, m);
    select_into(t3, f_neg, t1, v);

    let mut inverse = try_zeroed_bn(w, 0u64)?;
    inverse.copy_from_slice(t3);
    Some((inverse, invertible))
}

/// `a^-1 mod m` for **odd** `m`, or `None` when no inverse exists.
///
/// This is the fixed-iteration binary GCD's companion entry point: the mask's
/// single branch is the authorised no-inverse declassification. For a prime
/// modulus only the zero operand is non-invertible, and it maps to `0`.
pub(crate) fn mod_inverse_divstep(a: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    let (inverse, invertible) = mod_inverse_divstep_with_mask(a, m)?;
    if invertible == 0 {
        None
    } else {
        Some(inverse)
    }
}

// ---------------------------------------------------------------------------
// Test-only convergence instrument
// ---------------------------------------------------------------------------

/// How many divsteps the recurrence actually needs before `g == 0`.
///
/// Test-only: it exits early on a limb value and therefore is **not**
/// constant-time. It exists to measure the realised step count against
/// [`iteration_bound`] over the differential population.
#[cfg(test)]
pub(crate) fn convergence_steps(a: &[Limb], m: &[Limb], limit: usize) -> Option<usize> {
    if m.is_empty() || m[0] & 1 == 0 {
        return None;
    }
    let w = m.len();
    let ws = w.checked_add(1)?;
    let wide = ws.checked_add(1)?;
    let total = ws
        .checked_mul(4)?
        .checked_add(wide.checked_mul(2)?)?
        .checked_add(w.checked_mul(6)?)?;
    let mut scratch = SecretLimbs::try_zeroed(total)?;
    let whole: &mut [Limb] = &mut scratch;
    let (f, rest) = whole.split_at_mut(ws);
    let (g, rest) = rest.split_at_mut(ws);
    let (v, rest) = rest.split_at_mut(w);
    let (r, rest) = rest.split_at_mut(w);
    let (wide_a, rest) = rest.split_at_mut(wide);
    let (wide_b, rest) = rest.split_at_mut(wide);
    let (next_f, rest) = rest.split_at_mut(ws);
    let (next_g, rest) = rest.split_at_mut(ws);
    let (t0, rest) = rest.split_at_mut(w);
    let (t1, rest) = rest.split_at_mut(w);
    let (t2, rest) = rest.split_at_mut(w);
    let (t3, _rest) = rest.split_at_mut(w);
    f[..w].copy_from_slice(m);
    let take = a.len().min(w);
    g[..take].copy_from_slice(&a[..take]);
    r[0] = 1;
    let mut delta: i64 = 1;
    let mut s = Scratch {
        wide_a,
        wide_b,
        next_f,
        next_g,
        t0,
        t1,
        t2,
        t3,
    };
    for step in 0..limit {
        if g.iter().all(|&limb| limb == 0) {
            return Some(step);
        }
        divstep(f, g, v, r, &mut delta, m, &mut s);
    }
    if g.iter().all(|&limb| limb == 0) {
        Some(limit)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
