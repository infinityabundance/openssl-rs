//! PFP-11 phase 2 — the P-521 Mersenne REDC fast arm.
//!
//! ## Why this is not the generic Montgomery reduction
//!
//! `p = 2^521 - 1` is represented in nine radix-`2^64` limbs, the top holding
//! nine bits, so it is congruent to `-1` modulo `B = 2^64`. The Montgomery
//! constant is therefore `n0 = -p^-1 mod B = 1`, and the REDC step for the word
//! `u = t[i]` adds `u·p·B^i`. Written out,
//!
//! ```text
//!   u·p·B^i = u·(2^521 - 1)·B^i = u·2^(521 + 64i) - u·B^i
//! ```
//!
//! The `-u·B^i` term cancels the accumulator's limb `i` exactly (it holds `u`),
//! so each step is a zero and a shift-and-add of `u << 9` at limb `8 + i`, not a
//! `u × p[j]` multiply per limb. The generic kernel remains the oracle and the
//! fallback; nothing here is reachable unless a caller selects it explicitly.
//!
//! ## Invariant and fold bound
//!
//! The kernel is a *word* REDC with exactly `n = 9` steps — not an iterative
//! fold whose round count depends on the value. Each step places a fixed
//! shift at a fixed limb and runs a fixed-length carry propagation. The input
//! contract is the same as the generic path's: `T < p·R` with `R = 2^576`.
//! Every caller satisfies it — `BN_mod_mul_montgomery` passes `a, b < p`, so
//! `T = a·b < p^2 < p·R`; `BN_to_montgomery` passes `a < R` times `R^2 mod p`;
//! `BN_from_montgomery` is only routed here for `T < R < p·R`.
//!
//! Under that contract `k = Σ u_i·B^i < R`, so `T + k·p < p·R + R·p = 2·p·R`
//! and the residue `(T + k·p)/R` is `< 2p`. One masked conditional subtraction
//! leaves a canonical representative in `[0, p)`. The accumulator is bounded by
//! `T + k·p < 2^1042 + 2^1097 < 2^1098`, which fits the 20-limb scratch with
//! room to spare, so no carry can leave it and `t[18]` (the possible `2p` high
//! limb) is zero.
//!
//! ## Constant time
//!
//! No branch, index or loop bound depends on a limb value. The step count is
//! the public limb count, the carry propagation is a fixed range, and the final
//! conditional subtraction is a full-width mask. `u` is used only as an
//! addend; it never selects control flow or an address.

use crate::bn::alloc::try_zeroed;
use crate::bn::limbs::Limb;
use crate::bn::secret::SecretBuf;

/// Number of 64-bit limbs in `p = 2^521 - 1` (the top limb holds nine bits).
pub(crate) const P521_LIMBS: usize = 9;

/// `p = 2^521 - 1` in radix `2^64`, little-endian.
pub(crate) const P521: [Limb; P521_LIMBS] = [
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    0x1FF,
];

/// `n0 = -p^-1 mod 2^64`. Since `p ≡ -1 (mod 2^64)`, this is one.
pub(crate) const P521_N0: Limb = 1;

/// The scratch accumulator: `2n = 18` product limbs plus one limb for the
/// nine shifted additions and their carries. The bound above caps the value at
/// `2^1098 < 2^(19·64)`, so 20 limbs is a fixed, public extent.
const ACC_LIMBS: usize = 20;

/// Whether `m` is exactly the P-521 prime.
///
/// This is a modulus comparison, and the modulus is public on every reach that
/// enables the fast arm (EC groups). The loop reads every limb so the result's
/// timing does not depend on the first differing limb.
pub(crate) fn is_p521(m: &[Limb]) -> bool {
    if m.len() != P521_LIMBS {
        return false;
    }
    let mut diff = 0u64;
    for (&x, &y) in m.iter().zip(P521.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// REDC in place on `t[0..]` for `p = 2^521 - 1`, `n0 = 1`.
///
/// The residue is in `t[P521_LIMBS..2·P521_LIMBS]`, canonical, and the low nine
/// limbs are zero. Returns `false` only on a short scratch slice, a public
/// length condition; no limb value can change the result or the control flow.
fn redc_p521_in_place(t: &mut [Limb]) -> bool {
    if t.len() < ACC_LIMBS {
        return false;
    }
    // Every shift's outgoing carry is folded here, never branched on. The bound
    // proves it is zero; folding it keeps the kernel free of a secret-derived
    // conditional transfer even in the (unreachable) case it were not.
    let mut stray = 0u64;
    for i in 0..P521_LIMBS {
        // `u = t[i]` because `n0 = 1`. Zeroing the limb is the exact `-u·B^i`
        // cancellation: `t[i]` holds `u`, the lower limbs are already zero, so
        // no borrow propagates.
        let u = t[i];
        t[i] = 0;
        // Add `u·2^(521 + 64i) = (u << 9)·B^(8+i)`.
        let base = 8 + i;
        let w0 = u << 9;
        let w1 = u >> 55;
        let (s, c0) = t[base].overflowing_add(w0);
        t[base] = s;
        let (s, c1) = t[base + 1].overflowing_add(w1);
        let (s, c2) = s.overflowing_add(u64::from(c0));
        t[base + 1] = s;
        let mut carry = u64::from(c1) | u64::from(c2);
        // Fixed-schedule carry propagation to the top of the scratch. The
        // range is public (`base` is the loop index), never a limb value.
        for slot in t.iter_mut().take(ACC_LIMBS).skip(base + 2) {
            let (s, c) = slot.overflowing_add(carry);
            *slot = s;
            carry = u64::from(c);
        }
        stray |= carry;
    }

    // The low nine limbs are zero. The residue is `t[9..18]`, below `2p`; the
    // single masked subtraction leaves `[0, p)`. `high` is the possible limb
    // above nine (zero by the bound) and `borrow` the final borrow of
    // `t[9..18] - p`; keep the difference when `high != 0` or no borrow.
    let high = t[2 * P521_LIMBS] | stray;
    let mut diff = [0u64; P521_LIMBS];
    let mut borrow = 0u64;
    for j in 0..P521_LIMBS {
        let (d1, b1) = t[P521_LIMBS + j].overflowing_sub(P521[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let take = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(take);
    for j in 0..P521_LIMBS {
        let v = t[P521_LIMBS + j];
        t[P521_LIMBS + j] = (v & !mask) | (diff[j] & mask);
    }
    true
}

/// `a·b·R^-1 mod p`, with `a, b < p` (the generic kernel's input contract).
///
/// Safe Rust throughout: the product and reduction are slice operations with
/// fixed, public extents. Returns `None` when the operands are the wrong width
/// or an allocation fails.
pub(crate) fn mont_mul_p521_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    #[cfg(test)]
    probe::record();
    if a.len() != P521_LIMBS || b.len() != P521_LIMBS {
        return None;
    }
    let mut t = SecretBuf::<Limb>::try_zeroed(ACC_LIMBS)?;
    // Schoolbook product into `t[0..18]`; row `i` writes `i..i+9` and its
    // carry into the untouched limb `i + 9`.
    for i in 0..P521_LIMBS {
        let mut carry: Limb = 0;
        let ai = a[i] as u128;
        for j in 0..P521_LIMBS {
            // Bound: `(2^64-1)^2 + 2·(2^64-1) = 2^128-1`; `wrapping_*` keeps
            // the overflow check out of the secret-bearing loop.
            let v = ai
                .wrapping_mul(b[j] as u128)
                .wrapping_add(t[i + j] as u128)
                .wrapping_add(carry as u128);
            t[i + j] = v as Limb;
            carry = (v >> 64) as Limb;
        }
        t[i + P521_LIMBS] = carry;
    }
    if !redc_p521_in_place(&mut t[..]) {
        return None;
    }
    let mut out = try_zeroed(P521_LIMBS, 0u64)?;
    out.copy_from_slice(&t[P521_LIMBS..2 * P521_LIMBS]);
    Some(out)
}

/// `T·R^-1 mod p` for `T < R = 2^576` (hence `T < p·R`).
///
/// This is the specialized counterpart of the generic REDC used by
/// `BN_from_montgomery`. It refuses a `T` wider than nine limbs because then
/// the `< p·R` contract would have to be re-established by the caller.
pub(crate) fn mont_reduce_p521_fallible(a: &[Limb]) -> Option<Vec<Limb>> {
    #[cfg(test)]
    probe::record();
    if a.len() > P521_LIMBS {
        return None;
    }
    let mut t = SecretBuf::<Limb>::try_zeroed(ACC_LIMBS)?;
    t[..a.len()].copy_from_slice(a);
    if !redc_p521_in_place(&mut t[..]) {
        return None;
    }
    let mut out = try_zeroed(P521_LIMBS, 0u64)?;
    out.copy_from_slice(&t[P521_LIMBS..2 * P521_LIMBS]);
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

    /// A canonical P-521 element (`< p`) from the generator.
    fn canonical(state: &mut u64) -> [Limb; P521_LIMBS] {
        let mut v = [0u64; P521_LIMBS];
        for limb in v.iter_mut() {
            *limb = next(state);
        }
        // `p = 2^521 - 1`, so masking the top limb to nine bits yields `<= p`;
        // `p` itself is mapped to zero.
        v[8] &= 0x1FF;
        if v == P521 {
            v = [0u64; P521_LIMBS];
        }
        v
    }

    fn one() -> [Limb; P521_LIMBS] {
        let mut v = [0u64; P521_LIMBS];
        v[0] = 1;
        v
    }

    #[test]
    fn p521_is_the_mersenne_prime() {
        assert!(is_p521(&P521));
        assert_eq!(P521_N0, 1);
        // `p + 1 == 2^521`: the top limb is nine bits and the rest are ones.
        assert_eq!(P521[8], 0x1FF);
        assert!(P521[..8].iter().all(|&l| l == u64::MAX));
        assert!(!is_p521(&[u64::MAX; P521_LIMBS]));
        assert!(!is_p521(&[1, 2, 3]));
    }

    /// Every edge class the task names, against the generic SOS kernel.
    #[test]
    fn the_fold_matches_the_generic_reduction_on_the_edge_classes() {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut cases: Vec<[Limb; P521_LIMBS]> = Vec::new();
        cases.push([0u64; P521_LIMBS]);
        cases.push(one());
        // Low limb occupancy (PFP-22 classes): 2 and 3.
        let mut two = [0u64; P521_LIMBS];
        two[0] = 2;
        cases.push(two);
        let mut three = [0u64; P521_LIMBS];
        three[0] = 3;
        cases.push(three);
        // `p - 1`, `p - 2`.
        let mut pm1 = P521;
        pm1[0] -= 1;
        cases.push(pm1);
        let mut pm2 = P521;
        pm2[0] -= 2;
        cases.push(pm2);
        // Top limb zero (a value below 2^512) and full nine bits.
        let mut low = canonical(&mut state);
        low[8] = 0;
        cases.push(low);
        let mut full = [u64::MAX; P521_LIMBS];
        full[8] = 0x1FF;
        cases.push(full);
        // A top-only value (maximal occupancy is the `full` case above).
        let mut top_only = [0u64; P521_LIMBS];
        top_only[8] = 0x1FF;
        cases.push(top_only);
        cases.push(P521);
        for _ in 0..64 {
            cases.push(canonical(&mut state));
        }

        let mut checked = 0usize;
        for a in &cases {
            for b in &cases {
                let Some(fast) = mont_mul_p521_fallible(a, b) else {
                    unreachable!("allocation succeeds");
                };
                let Some(oracle) = mont_mul_fallible(a, b, &P521, P521_N0) else {
                    unreachable!("allocation succeeds");
                };
                assert_eq!(fast, oracle, "fast fold disagrees with the generic kernel");
                assert!(
                    fast.len() <= P521_LIMBS && fast[8] < 0x200,
                    "the residue is canonical"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, cases.len() * cases.len());
    }

    /// Non-canonical REDC inputs (`T` up to `2^576 - 1`), against the generic
    /// kernel driven through a multiply by one.
    #[test]
    fn the_reduce_matches_the_generic_path_for_non_canonical_inputs() {
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut inputs: Vec<[Limb; P521_LIMBS]> = Vec::new();
        inputs.push([u64::MAX; P521_LIMBS]);
        inputs.push(P521);
        // `p + 1 = 2^521`, still a nine-limb value below `2^576`.
        let mut pp1 = [0u64; P521_LIMBS];
        pp1[8] = 0x200;
        inputs.push(pp1);
        for _ in 0..128 {
            let mut v = [0u64; P521_LIMBS];
            for limb in v.iter_mut() {
                *limb = next(&mut state);
            }
            inputs.push(v);
        }
        let one = one();
        for t in &inputs {
            let Some(fast) = mont_reduce_p521_fallible(t) else {
                unreachable!("allocation succeeds");
            };
            let Some(oracle) = mont_mul_fallible(t, &one, &P521, P521_N0) else {
                unreachable!("allocation succeeds");
            };
            assert_eq!(
                fast, oracle,
                "specialized REDC disagrees with the generic path"
            );
        }
    }

    /// The result is canonical for the maximum operands, which exercise the
    /// widest carry chain.
    #[test]
    fn the_maximum_operands_are_reduced_below_p() {
        let mut max = P521;
        max[0] -= 1; // p - 1
        let Some(r) = mont_mul_p521_fallible(&max, &max) else {
            unreachable!("allocation succeeds");
        };
        // `(p-1)^2 ≡ 1 (mod p)`; in Montgomery form the residue is `R^-1`.
        let Some(expect) = mont_reduce_p521_fallible(&one()) else {
            unreachable!("allocation succeeds");
        };
        assert_eq!(r, expect);
    }
}
