//! PFP-59 — the P-384 Solinas fast arm for the Montgomery reduction step.
//!
//! ## What is specialised, and what is not
//!
//! The Montgomery representation is unchanged: `R = 2^384`, the operands stay
//! in the Montgomery domain and the result is `a·b·R^-1 mod p`. What is
//! specialised is the *reduction step*. P-384 is not Mersenne, so the P-521
//! trick (`p ≡ -1 mod B`, `n0 = 1`) does not apply. It is a Solinas prime:
//!
//! ```text
//!   p = 2^384 - 2^128 - 2^96 + 2^32 - 1
//!   c = 2^384 - p = 2^128 + 2^96 - 2^32 + 1        (129 bits)
//!   p + c = 2^384 = R
//! ```
//!
//! The Montgomery word `n0` is also cheap. In radix `B = 2^64`,
//! `p ≡ -(2^32 - 1) (mod B)`, and `(2^32 - 1)·(2^32 + 1) = 2^64 - 1 ≡ -1`, so
//! `p^-1 ≡ -(2^32 + 1)` and `n0 = -p^-1 ≡ 2^32 + 1 (mod B)`. The word step is
//! therefore `u = (t_i << 32) + t_i`: a shift and an add, no multiply.
//!
//! Adding `u·p·B^i` is decomposed with the sparse form of `p`:
//!
//! ```text
//!   u·p·B^i = u·B^(6+i) - u·c·B^i
//!   c = 2^128 + 2^96 - 2^32 + 1
//! ```
//!
//! `u·c` is four limbs built entirely from shifts and adds (`mul_c` below), and
//! `u·B^(6+i)` is a single word placed at a fixed limb. The fold is therefore
//! shifts, additions and subtractions; there is no `u × p[j]` multiply per limb
//! and no division.
//!
//! ## Reduction bound and fold count
//!
//! The kernel is a word REDC with exactly `n = 6` steps. Each step covers one
//! radix-`B` digit of `k = Σ u_i·B^i`; the step count is the public limb count,
//! not a value-dependent fold count. The input contract is the generic path's:
//! `T < p·R`.
//!
//! Under that contract `k < B^6 = R`, so
//!
//! ```text
//!   T + k·p < p·R + R·p = 2·p·R < 2^769
//! ```
//!
//! and the residue `W = (T + k·p)/R` satisfies `W < 2p < 2^385`. The
//! accumulator is therefore at most 769 bits; the fixed `ACC_LIMBS = 13`
//! (832 bits) holds it with room for the carry chain, and `t[12]` (the limb
//! above the six-word result) is `0` or `1`. One masked conditional subtraction
//! closes the result canonically in `[0, p)`. A single fold pass is sufficient;
//! the fixed six steps are what make it so.
//!
//! The callers establish the contract exactly as for the generic kernel:
//! `BN_mod_mul_montgomery` passes two canonical operands (`a·b < p^2 < p·R`),
//! `BN_to_montgomery` passes `rr = R^2 mod p < p` times an `R`-bounded input
//! (`< p·R`), and `BN_from_montgomery` is only routed here for `T < R < p·R`.
//!
//! ## Constant time
//!
//! No branch, index or loop bound depends on a limb value. Every shift is at a
//! fixed limb, every carry/borrow propagation runs over a range fixed by the
//! loop index, and the final conditional subtraction is a full-width mask. `u`
//! is only ever an addend or a multiplicand of the fixed sparse constant `c`; it
//! never selects control flow or an address. The source expresses this; the
//! branch audit of the built carrier is separate evidence and is not inferred
//! from this paragraph.

use crate::bn::alloc::try_zeroed;
use crate::bn::limbs::Limb;
use crate::bn::secret::SecretBuf;

/// Number of 64-bit limbs in `p` (the prime is exactly 384 bits).
pub(crate) const P384_LIMBS: usize = 6;

/// `p = 2^384 - 2^128 - 2^96 + 2^32 - 1` in radix `2^64`, little-endian.
pub(crate) const P384: [Limb; P384_LIMBS] = [
    0x0000_0000_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// `n0 = -p^-1 mod 2^64 = 2^32 + 1`, since `p ≡ -(2^32 - 1) (mod 2^64)`.
pub(crate) const P384_N0: Limb = 0x0000_0001_0000_0001;

/// `c = 2^384 - p` in radix `2^64`: `[0xFFFFFFFF00000001, 0xFFFFFFFF, 1]`.
/// `c = 2^128 + 2^96 - 2^32 + 1`, checked by `the_prime_has_the_solinas_shape`.
#[cfg(test)]
const C_LIMBS: [Limb; 3] = [0xFFFF_FFFF_0000_0001, 0x0000_0000_FFFF_FFFF, 1];

/// Fixed accumulator extent: `2n + 1 = 13` limbs (832 bits) for `2pR < 2^769`.
const ACC_LIMBS: usize = 2 * P384_LIMBS + 1;

/// Whether `m` is exactly the P-384 prime.
///
/// The modulus is public on every reach that enables the fast arm (EC groups).
/// Every limb is read, so the result's timing does not depend on the first
/// differing limb.
pub(crate) fn is_p384(m: &[Limb]) -> bool {
    if m.len() != P384_LIMBS {
        return false;
    }
    let mut diff = 0u64;
    for (&x, &y) in m.iter().zip(P384.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `u·c` as four limbs, from shifts only.
///
/// `c = 2^128 + 2^96 - 2^32 + 1`, so `u·c = u + (u<<96) + (u<<128) - (u<<32)`.
/// The positive terms are assembled first, then the single negative term is
/// subtracted; the final borrow is zero because `c > 0`. Every operation is on
/// the public constant `c`, and `u` is only a value being shifted or added.
fn mul_c(u: Limb) -> [Limb; 4] {
    let lo = u & 0xFFFF_FFFF;
    // u + (u<<96) + (u<<128): limbs of the positive sum.
    let p0 = u;
    let p1 = lo << 32;
    // `u + (u >> 32)` can exceed 64 bits; the carry lands in `p3`.
    let s = (u as u128) + ((u >> 32) as u128);
    let p2 = s as u64;
    let p3 = (s >> 64) as u64;
    // u<<32: limb 0 is the low 32 bits shifted up, limb 1 the high half.
    let s0 = lo << 32;
    let s1 = u >> 32;
    let (w0, b0) = p0.overflowing_sub(s0);
    let (d1, b1) = p1.overflowing_sub(s1);
    let (w1, b2) = d1.overflowing_sub(u64::from(b0));
    let borrow = u64::from(b1) | u64::from(b2);
    let (d2, b3) = p2.overflowing_sub(borrow);
    let (w2, b4) = d2.overflowing_sub(0);
    let (w3, b5) = p3.overflowing_sub(u64::from(b3) | u64::from(b4));
    // `c > 0`, so the four-limb difference is non-negative; `b5` is false.
    debug_assert!(!b5, "u*c must not borrow past four limbs");
    [w0, w1, w2, w3]
}

/// REDC in place on `t[0..]` for `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`.
///
/// The residue is in `t[P384_LIMBS..2·P384_LIMBS]`, canonical, and the low six
/// limbs are zero. Returns `false` only on a short scratch slice, a public
/// length condition; no limb value can change the result or the control flow.
fn redc_p384_in_place(t: &mut [Limb]) -> bool {
    if t.len() < ACC_LIMBS {
        return false;
    }
    // Carries and borrows that leave the fixed ranges are folded here rather
    // than branched on. The bound proves they are zero; keeping them as data
    // keeps the kernel free of a secret-derived transfer even if a range were
    // ever mis-sized.
    let mut stray = 0u64;
    for i in 0..P384_LIMBS {
        // `u = t[i]·n0 mod B = (t[i] << 32) + t[i]`.
        let u = (t[i] << 32).wrapping_add(t[i]);

        // Add `u·B^(6+i)`: one word at a fixed limb, then a fixed-range carry.
        let base = P384_LIMBS + i;
        let (s, c) = t[base].overflowing_add(u);
        t[base] = s;
        let mut carry = u64::from(c);
        for slot in t.iter_mut().take(ACC_LIMBS).skip(base + 1) {
            let (s, c) = slot.overflowing_add(carry);
            *slot = s;
            carry = u64::from(c);
        }
        stray |= carry;

        // Subtract `u·c·B^i`: four limbs at a fixed offset, then a fixed-range
        // borrow. Adding the positive term first keeps the accumulator
        // non-negative, so no borrow can leave the top.
        let w = mul_c(u);
        let (d0, b0) = t[i].overflowing_sub(w[0]);
        t[i] = d0;
        let mut borrow = u64::from(b0);
        for (j, &wj) in w.iter().enumerate().skip(1) {
            let (d, b1) = t[i + j].overflowing_sub(wj);
            let (d, b2) = d.overflowing_sub(borrow);
            t[i + j] = d;
            borrow = u64::from(b1) | u64::from(b2);
        }
        for slot in t.iter_mut().take(ACC_LIMBS).skip(i + w.len()) {
            let (d, b) = slot.overflowing_sub(borrow);
            *slot = d;
            borrow = u64::from(b);
        }
        stray |= borrow;
    }

    // The low six limbs are zero; the residue is `t[6..12]`, below `2p`. The
    // single masked subtraction leaves `[0, p)`. `high` is the possible limb
    // above six (zero by the bound, one at most if the bound were tight) and
    // `borrow` the final borrow of `t[6..12] - p`.
    let high = t[2 * P384_LIMBS] | stray;
    let mut diff = [0u64; P384_LIMBS];
    let mut borrow = 0u64;
    for j in 0..P384_LIMBS {
        let (d1, b1) = t[P384_LIMBS + j].overflowing_sub(P384[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let take = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(take);
    for j in 0..P384_LIMBS {
        let v = t[P384_LIMBS + j];
        t[P384_LIMBS + j] = (v & !mask) | (diff[j] & mask);
    }
    true
}

/// `a·b·R^-1 mod p`, with `a·b < p·R` (the generic kernel's input contract).
///
/// **Retained caller obligation (not enforced by the type).** The width check
/// only establishes `a, b < 2^384 = R`; two such operands give `a·b < 2^768`,
/// which is *wider* than `p·R ≈ 2^767`. The callers keep the product inside the
/// contract: `BN_mod_mul_montgomery` passes two canonical operands
/// (`a, b < p`, so `a·b < p^2 < p·R`), and `BN_to_montgomery` passes
/// `rr = R^2 mod p < p` times an `R`-bounded input. A future caller passing two
/// non-canonical six-limb values would violate the bound and the kernel would
/// not detect it. Enforcement is deliberately not added at run time: a
/// canonicality check on the operands would branch on secret field data.
///
/// Safe Rust throughout: the product and reduction are slice operations with
/// fixed, public extents. Returns `None` when the operands are the wrong width
/// or an allocation fails.
pub(crate) fn mont_mul_p384_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    #[cfg(test)]
    probe::record();
    if a.len() != P384_LIMBS || b.len() != P384_LIMBS {
        return None;
    }
    let mut t = SecretBuf::<Limb>::try_zeroed(ACC_LIMBS)?;
    // Schoolbook product into `t[0..12]`; row `i` writes `i..i+6` and its
    // carry into the untouched limb `i + 6`.
    for i in 0..P384_LIMBS {
        let mut carry: Limb = 0;
        let ai = a[i] as u128;
        for j in 0..P384_LIMBS {
            // Bound: `(2^64-1)^2 + 2·(2^64-1) = 2^128-1`; `wrapping_*` keeps
            // the overflow check out of the secret-bearing loop.
            let v = ai
                .wrapping_mul(b[j] as u128)
                .wrapping_add(t[i + j] as u128)
                .wrapping_add(carry as u128);
            t[i + j] = v as Limb;
            carry = (v >> 64) as Limb;
        }
        t[i + P384_LIMBS] = carry;
    }
    if !redc_p384_in_place(&mut t[..]) {
        return None;
    }
    let mut out = try_zeroed(P384_LIMBS, 0u64)?;
    out.copy_from_slice(&t[P384_LIMBS..2 * P384_LIMBS]);
    Some(out)
}

/// `T·R^-1 mod p` for `T < R = 2^384` (hence `T < p·R`).
///
/// The length check enforces the contract: a value of at most six limbs is
/// below `2^384 = R`, so a wider `T` is refused rather than silently reduced
/// under an unestablished bound.
pub(crate) fn mont_reduce_p384_fallible(a: &[Limb]) -> Option<Vec<Limb>> {
    #[cfg(test)]
    probe::record();
    if a.len() > P384_LIMBS {
        return None;
    }
    let mut t = SecretBuf::<Limb>::try_zeroed(ACC_LIMBS)?;
    t[..a.len()].copy_from_slice(a);
    if !redc_p384_in_place(&mut t[..]) {
        return None;
    }
    let mut out = try_zeroed(P384_LIMBS, 0u64)?;
    out.copy_from_slice(&t[P384_LIMBS..2 * P384_LIMBS]);
    Some(out)
}

/// A test-only count of fast-arm entries, used to prove a refused group never
/// reaches the kernel.
#[cfg(test)]
pub(crate) mod probe {
    use core::cell::Cell;

    thread_local! {
        static TAKEN: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        TAKEN.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn count() -> u64 {
        TAKEN.with(|c| c.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::mont_mul_fallible;

    /// One xorshift step; the test population is deterministic.
    fn next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// A canonical P-384 element (`< p`) from the generator.
    fn canonical(state: &mut u64) -> [Limb; P384_LIMBS] {
        let mut v = [0u64; P384_LIMBS];
        for limb in v.iter_mut() {
            *limb = next(state);
        }
        if u384_ge_p(&v) {
            v = [0u64; P384_LIMBS];
            v[0] = 1;
        }
        v
    }

    /// `v >= p` for a limb slice (test-only; not constant time).
    fn u384_ge_p(v: &[Limb]) -> bool {
        if v.len() != P384_LIMBS {
            return v.len() > P384_LIMBS;
        }
        for i in (0..P384_LIMBS).rev() {
            if v[i] != P384[i] {
                return v[i] > P384[i];
            }
        }
        true
    }

    fn one() -> [Limb; P384_LIMBS] {
        let mut v = [0u64; P384_LIMBS];
        v[0] = 1;
        v
    }

    #[test]
    fn the_prime_has_the_solinas_shape() {
        assert!(is_p384(&P384));
        assert_eq!(P384_N0, 0x0000_0001_0000_0001);
        // `p + c == 2^384` and `c` is the documented three-limb constant.
        let mut sum = [0u64; P384_LIMBS];
        let mut carry = 0u64;
        for i in 0..P384_LIMBS {
            let c = if i < C_LIMBS.len() { C_LIMBS[i] } else { 0 };
            let (s, o1) = P384[i].overflowing_add(c);
            let (s, o2) = s.overflowing_add(carry);
            sum[i] = s;
            carry = u64::from(o1) | u64::from(o2);
        }
        assert_eq!(sum, [0u64; P384_LIMBS], "p + c must be exactly 2^384");
        assert_eq!(carry, 1);
        // `p · n0 ≡ -1 (mod 2^64)`.
        assert_eq!(P384[0].wrapping_mul(P384_N0), u64::MAX);
        assert!(!is_p384(&[u64::MAX; P384_LIMBS]));
        assert!(!is_p384(&[1, 2, 3]));
    }

    /// Every edge class the task names, against the generic SOS kernel.
    #[test]
    fn the_fold_matches_the_generic_reduction_on_the_edge_classes() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut cases: Vec<[Limb; P384_LIMBS]> = Vec::new();
        cases.push([0u64; P384_LIMBS]);
        cases.push(one());
        // Low limb occupancy (PFP-22 classes): 2 and 3.
        let mut two = [0u64; P384_LIMBS];
        two[0] = 2;
        cases.push(two);
        let mut three = [0u64; P384_LIMBS];
        three[0] = 3;
        cases.push(three);
        // `p - 1`, `p - 2`.
        let mut pm1 = P384;
        pm1[0] -= 1;
        cases.push(pm1);
        let mut pm2 = P384;
        pm2[0] -= 2;
        cases.push(pm2);
        // Top limb zero (a value below 2^320), maximal occupancy, and a
        // top-only value.
        let mut low = canonical(&mut state);
        low[5] = 0;
        cases.push(low);
        cases.push([u64::MAX; P384_LIMBS]);
        let mut top_only = [0u64; P384_LIMBS];
        top_only[5] = u64::MAX;
        cases.push(top_only);
        cases.push(P384);
        for _ in 0..64 {
            cases.push(canonical(&mut state));
        }

        let mut checked = 0usize;
        for a in &cases {
            for b in &cases {
                let Some(fast) = mont_mul_p384_fallible(a, b) else {
                    unreachable!("allocation succeeds");
                };
                let Some(oracle) = mont_mul_fallible(a, b, &P384, P384_N0) else {
                    unreachable!("allocation succeeds");
                };
                assert_eq!(fast, oracle, "fast fold disagrees with the generic kernel");
                assert!(
                    fast.len() <= P384_LIMBS && !u384_ge_p(&fast),
                    "the residue is canonical"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, cases.len() * cases.len());
    }

    /// Non-canonical REDC inputs (`T` up to `2^384 - 1`), against the generic
    /// kernel driven through a multiply by one.
    #[test]
    fn the_reduce_matches_the_generic_path_for_non_canonical_inputs() {
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut inputs: Vec<[Limb; P384_LIMBS]> = Vec::new();
        inputs.push([u64::MAX; P384_LIMBS]);
        inputs.push(P384);
        let mut pp1 = P384;
        pp1[0] += 1; // p + 1 <= 2^384 - 1, still six limbs
        inputs.push(pp1);
        for _ in 0..128 {
            let mut v = [0u64; P384_LIMBS];
            for limb in v.iter_mut() {
                *limb = next(&mut state);
            }
            inputs.push(v);
        }
        let one = one();
        for t in &inputs {
            let Some(fast) = mont_reduce_p384_fallible(t) else {
                unreachable!("allocation succeeds");
            };
            let Some(oracle) = mont_mul_fallible(t, &one, &P384, P384_N0) else {
                unreachable!("allocation succeeds");
            };
            assert_eq!(
                fast, oracle,
                "specialized REDC disagrees with the generic path"
            );
        }
    }

    /// `(p-1)^2 ≡ 1 (mod p)`, so the Montgomery residue is `R^-1`.
    #[test]
    fn the_maximum_operands_are_reduced_below_p() {
        let mut max = P384;
        max[0] -= 1;
        let Some(r) = mont_mul_p384_fallible(&max, &max) else {
            unreachable!("allocation succeeds");
        };
        let Some(expect) = mont_reduce_p384_fallible(&one()) else {
            unreachable!("allocation succeeds");
        };
        assert_eq!(r, expect);
    }

    /// A wider operand is refused rather than reduced under an unproven bound.
    #[test]
    fn a_wider_operand_is_refused() {
        assert!(mont_reduce_p384_fallible(&[0u64; P384_LIMBS + 1]).is_none());
        assert!(mont_mul_p384_fallible(&[0u64; P384_LIMBS - 1], &one()).is_none());
    }
}
