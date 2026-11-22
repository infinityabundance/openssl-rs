//! Fixed-width prime-field scratch for the Montgomery ladder (T29).
//!
//! The authority's ladder step is straight-line C over `BIGNUM`s, and every field
//! operation there allocates a fresh limb vector: `BN_mod_mul` allocates the
//! schoolbook product and then `BN_nnmod` allocates the division accumulator and
//! the remainder, `BN_mod_add_quick`/`BN_mod_sub_quick` allocate their sum or
//! difference, and `BN_mod_lshift*_quick` allocate each shifted form. The T29
//! census attributes the per-signature total to exactly those sites
//! (`limbs::mul_fallible`, the division accumulator and remainder, and
//! `add`/`sub`/`shl_fallible`).
//!
//! [`ScalarLadderWorkspace`] is the fixed-width scratch that removes them. It is
//! allocated **once per scalar multiplication**, at the modulus' public limb
//! count, through the fallible seam. Every buffer is a [`SecretLimbs`], so the
//! whole allocation is volatile-wiped on drop — including the early-return and
//! unwind paths — and the ladder's intermediates stop living in `BN_CTX` scratch
//! that the context does not cleanse (AGENTS §5).
//!
//! The ladder's live state is the workspace. Its four coordinate slots (`r->X`,
//! `r->Z`, `s->X`, `s->Z`) are staged once after `ec_point_ladder_pre`, mutated in
//! place by every step and exchanged by a masked select instead of
//! `BN_consttime_swap`, and written back into the point objects exactly once after
//! the loop. Nothing in the per-bit path allocates, and no loop bound depends on a
//! limb value or on a secret-derived length.
//!
//! ## Width source
//!
//! `n` is `group->field.d.len()`, the modulus' normalised limb count, a public
//! curve parameter. The arrangement follows `bn::arith::mont_mul_into`'s
//! established pattern: an intermediate is exactly as wide as the public modulus,
//! never as wide as a particular value happens to be.
//!
//! ## Which methods it serves
//!
//! Only a field whose operations are the plain `EC_GFp_simple` pair with no
//! encoding. The Montgomery method installs the same `ladder_step` pointer but
//! keeps its coordinates, `group->a` and `group->b` in the Montgomery domain, so
//! plain arithmetic there would compute over the wrong representation; the
//! driver's predicate (`smpl::ec_method_field_is_plain`) refuses it. On this
//! profile that is P-256, which is the T29 workload.
//!
//! ## Allocation failure
//!
//! Each buffer is requested through [`SecretLimbs::try_zeroed`], i.e. the
//! fallible seam; [`ScalarLadderWorkspace::new`] answers `None` when one is
//! refused, and the ladder driver reports that as the step's own failure
//! (`EC_R_LADDER_STEP_FAILURE`) — the same answer the authority's step gives when
//! the `BN_CTX_get` allocations this workspace replaces are refused. No allocation
//! here aborts the process and none panics.
//!
//! ## Constant-time notes
//!
//! Addition, subtraction and doubling are masked selects rather than the
//! authority's `BN_ucmp`/sign comparisons, so they do not branch on an operand
//! value.
//!
//! The reduction has two kernels, selected **once** from the public modulus when
//! the scratch is built (never per operation, never from a value):
//!
//! - a fixed-sequence Solinas fold for P-256, whose modulus shape
//!   `2^256 - 2^224 + 2^192 + 2^96 - 1` turns each fold into shifts, additions and
//!   subtractions with a fixed iteration count, and finishes with masked
//!   subtractions. It contains no division, no loop whose bound depends on a
//!   dividend and no value-dependent add-back;
//! - the authority's Knuth D reduction for every other modulus (P-384, P-521, and
//!   anything else the scratch is built for). That kernel keeps the
//!   quotient-digit estimate `limbs::divide_fallible` runs and is reachable and
//!   tested through those widths.
//!
//! Staging a coordinate reads `src.get(i)` for `i in 0..n`, one residual length
//! test per staged coordinate (the class `stage_fixed_width_exponent` records).
//! Every later read indexes a fixed-width slot whose length is public.

use crate::bn::limbs::Limb;
use crate::runtime::secret::SecretLimbs;

/// The ladder's working slots: the four coordinates the step reads and writes,
/// the loop-invariant inputs, and the authority's `t0`..`t6`.
///
/// Every slot is exactly `n` limbs wide, where `n` is the modulus' limb count.
pub(crate) struct LadderSlots {
    /// `r->X` — staged at entry, replaced by the step's `r->X` output.
    pub(crate) rx: SecretLimbs,
    /// `r->Z` — staged at entry, replaced by the step's `r->Z` output.
    pub(crate) rz: SecretLimbs,
    /// `s->X` — staged at entry, replaced by the step's `s->X` output.
    pub(crate) sx: SecretLimbs,
    /// `s->Z` — staged at entry, replaced by the step's `s->Z` output.
    pub(crate) sz: SecretLimbs,
    /// `p->X` — the affine input point's `X`, staged once per scalar multiplication.
    pub(crate) px: SecretLimbs,
    /// `group->a`, staged once per scalar multiplication.
    pub(crate) ca: SecretLimbs,
    /// `group->b`, staged once per scalar multiplication.
    pub(crate) cb: SecretLimbs,
    /// `t0` — `ecp_smpl.c:1560-1623`.
    pub(crate) t0: SecretLimbs,
    /// `t1`.
    pub(crate) t1: SecretLimbs,
    /// `t2`.
    pub(crate) t2: SecretLimbs,
    /// `t3`.
    pub(crate) t3: SecretLimbs,
    /// `t4`.
    pub(crate) t4: SecretLimbs,
    /// `t5`.
    pub(crate) t5: SecretLimbs,
    /// `t6`.
    pub(crate) t6: SecretLimbs,
}

impl LadderSlots {
    fn try_new(n: usize) -> Option<Self> {
        Some(Self {
            rx: SecretLimbs::try_zeroed(n)?,
            rz: SecretLimbs::try_zeroed(n)?,
            sx: SecretLimbs::try_zeroed(n)?,
            sz: SecretLimbs::try_zeroed(n)?,
            px: SecretLimbs::try_zeroed(n)?,
            ca: SecretLimbs::try_zeroed(n)?,
            cb: SecretLimbs::try_zeroed(n)?,
            t0: SecretLimbs::try_zeroed(n)?,
            t1: SecretLimbs::try_zeroed(n)?,
            t2: SecretLimbs::try_zeroed(n)?,
            t3: SecretLimbs::try_zeroed(n)?,
            t4: SecretLimbs::try_zeroed(n)?,
            t5: SecretLimbs::try_zeroed(n)?,
            t6: SecretLimbs::try_zeroed(n)?,
        })
    }

    /// Exchange the `r` and `s` coordinates when `c` is 1, leave them when it is 0.
    ///
    /// This is `EC_POINT_CSWAP`'s effect on the two X/Z pairs, written as a masked
    /// select over the fixed-width slots instead of `BN_consttime_swap` over the
    /// `BIGNUM` pairs. `c` is a ladder bit; the mask is `0 - c`, and every limb of
    /// both slots is touched whatever the mask, so the work and the addresses do not
    /// depend on it. The slot lengths are the public modulus width.
    pub(crate) fn cswap(&mut self, c: u64) {
        let mask = c.wrapping_neg();
        for (a, b) in [(&mut self.rx, &mut self.sx), (&mut self.rz, &mut self.sz)] {
            swap_masked(a, b, mask);
        }
    }
}

/// Exchange `a` and `b` limb-wise under a full-width `mask` (all-ones exchanges).
fn swap_masked(a: &mut [Limb], b: &mut [Limb], mask: u64) {
    debug_assert_eq!(a.len(), b.len());
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Which reduction kernel this scratch uses.
///
/// Chosen in [`FieldScratch::try_new`] from the modulus slice, i.e. from a public
/// curve parameter, and read only as a dispatch selector thereafter. No code path
/// selects a kernel from a limb value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reduction {
    /// Knuth D, as `limbs::divide_fallible` runs it. The form for every modulus
    /// without a specialised kernel.
    Knuth,
    /// The fixed-sequence Solinas fold for P-256's modulus.
    SolinasP256,
}

/// P-256's modulus, `2^256 - 2^224 + 2^192 + 2^96 - 1`, little-endian limbs.
///
/// The Solinas kernel is valid for exactly this value; [`FieldScratch::try_new`]
/// compares the requested modulus against it and refuses the kernel otherwise. A
/// test pins the constant against `BN_get0_nist_prime_256` and the P-256 group's
/// field.
const P256_MODULUS: [Limb; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// Fold applications before the masked correction. See
/// [`FieldScratch::reduce_solinas_p256`] for how the count follows from the
/// modulus' shape.
const P256_FOLDS: usize = 9;

/// Limbs in the Solinas accumulator: `2n + 1` for P-256's four-limb modulus.
const P256_ACC: usize = 9;

/// Masked subtractions of the modulus after the folds. Two suffice because each
/// fold below the ninth brings the intermediate under `2^257`, and `2^257 < 3p`.
const P256_SUBTRACTIONS: usize = 2;

/// The modulus-width scratch every field operation of one size shares.
///
/// `product` holds a schoolbook product (`2n` limbs), `acc` the reduction
/// accumulator (`2n + 1`), `divisor` the normalised modulus (`n` limbs) and
/// `sum`/`diff` the conditional add/subtract working values (`n + 1` each).
///
/// `reduction` is the kernel chosen from the modulus at construction; `divisor` and
/// `shift` are read by the Knuth kernel only, and stay allocated for every width so
/// one scratch layout serves both kernels.
pub(crate) struct FieldScratch {
    n: usize,
    shift: u32,
    reduction: Reduction,
    divisor: SecretLimbs,
    product: SecretLimbs,
    acc: SecretLimbs,
    sum: SecretLimbs,
    diff: SecretLimbs,
}

impl FieldScratch {
    /// Allocate the scratch at `md`'s public limb count, or `None` when the
    /// allocator refuses one of the buffers.
    ///
    /// The reduction kernel is selected here, once, from `md` itself: a public curve
    /// parameter that no operation can change. Nothing later inspects a limb to
    /// choose a path.
    fn try_new(md: &[Limb]) -> Option<Self> {
        Self::try_new_with(md, reduction_for(md))
    }

    /// [`Self::try_new`] with the kernel supplied by the caller.
    ///
    /// The only non-test caller passes [`reduction_for`]'s answer, so the selection
    /// point stays in one place. The test-only caller forces [`Reduction::Knuth`]
    /// for a P-256 modulus, which is how the fallback stays exercised at that width.
    fn try_new_with(md: &[Limb], reduction: Reduction) -> Option<Self> {
        let n = md.len();
        // A normalised modulus has a non-zero top limb; a zero one would leave the
        // widening shift undefined rather than merely wrong.
        if n == 0 || md[n - 1] == 0 {
            return None;
        }
        let shift = md[n - 1].leading_zeros();
        let two_n = n.checked_mul(2)?;
        let wide = n.checked_add(1)?;
        let mut divisor = SecretLimbs::try_zeroed(n)?;
        let mut carry = 0u64;
        for i in 0..n {
            divisor[i] = (md[i] << shift) | carry;
            carry = if shift == 0 { 0 } else { md[i] >> (64 - shift) };
        }
        // `md` is `n` limbs and `shift` is its top limb's leading-zero count, so
        // `md << shift` still fits `n` limbs.
        debug_assert_eq!(carry, 0);
        Some(Self {
            n,
            shift,
            reduction,
            divisor,
            product: SecretLimbs::try_zeroed(two_n)?,
            acc: SecretLimbs::try_zeroed(two_n.checked_add(1)?)?,
            sum: SecretLimbs::try_zeroed(wide)?,
            diff: SecretLimbs::try_zeroed(wide)?,
        })
    }

    /// The reduction kernel this scratch was built with.
    #[cfg(test)]
    pub(crate) fn reduction(&self) -> Reduction {
        self.reduction
    }

    /// A scratch at the same width with the generic Knuth kernel, for the
    /// differential test that keeps the fallback exercised at P-256's width.
    #[cfg(test)]
    pub(crate) fn try_new_knuth(md: &[Limb]) -> Option<Self> {
        Self::try_new_with(md, Reduction::Knuth)
    }

    /// The public modulus width in limbs.
    pub(crate) fn width(&self) -> usize {
        self.n
    }

    /// `out = a * b mod md`.
    ///
    /// `a` and `b` represent values in `[0, md)`, so each is at most `n` limbs;
    /// `out` is exactly `n` limbs and need not be normalised. `out` must not
    /// alias `a` or `b` — [`Self::mul_assign`] is the in-place form.
    pub(crate) fn mul(&mut self, out: &mut [Limb], a: &[Limb], b: &[Limb], md: &[Limb]) {
        self.product_of(a, b);
        self.reduce(out, md);
    }

    /// `x = x * y mod md`, tolerating `x`'s use as an operand.
    pub(crate) fn mul_assign(&mut self, x: &mut [Limb], y: &[Limb], md: &[Limb]) {
        self.product_of(x, y);
        self.reduce(x, md);
    }

    /// `out = a * a mod md`.
    pub(crate) fn sqr(&mut self, out: &mut [Limb], a: &[Limb], md: &[Limb]) {
        self.product_of(a, a);
        self.reduce(out, md);
    }

    /// `x = x^2 mod md`.
    pub(crate) fn sqr_assign(&mut self, x: &mut [Limb], md: &[Limb]) {
        self.product_of(x, x);
        self.reduce(x, md);
    }

    /// `out = a + b mod md` for operands in `[0, md)`.
    pub(crate) fn add(&mut self, out: &mut [Limb], a: &[Limb], b: &[Limb], md: &[Limb]) {
        self.sum_of(a, b);
        self.conditional_subtract(out, md);
    }

    /// `x = x + y mod md` for operands in `[0, md)`.
    pub(crate) fn add_assign(&mut self, x: &mut [Limb], y: &[Limb], md: &[Limb]) {
        let n = self.n;
        {
            let sum = &mut self.sum;
            let mut carry = 0u64;
            for i in 0..n {
                let s = (x.get(i).copied().unwrap_or(0) as u128)
                    .wrapping_add(y.get(i).copied().unwrap_or(0) as u128)
                    .wrapping_add(carry as u128);
                sum[i] = s as u64;
                carry = (s >> 64) as u64;
            }
            sum[n] = carry;
        }
        self.conditional_subtract(x, md);
    }

    /// `out = a - b mod md` for operands in `[0, md)`.
    pub(crate) fn sub(&mut self, out: &mut [Limb], a: &[Limb], b: &[Limb], md: &[Limb]) {
        let borrow = self.difference_of(a, b);
        self.add_masked_modulus(out, md, borrow.wrapping_neg());
    }

    /// `x = x - y mod md` for operands in `[0, md)`.
    pub(crate) fn sub_assign(&mut self, x: &mut [Limb], y: &[Limb], md: &[Limb]) {
        let borrow = self.difference_of(x, y);
        self.add_masked_modulus(x, md, borrow.wrapping_neg());
    }

    /// `x = y - x mod md` for operands in `[0, md)`.
    ///
    /// The authority writes `BN_mod_sub_quick(t3, t4, t3, field)` in the ladder
    /// step, i.e. the destination is also the subtrahend; the difference is formed
    /// in scratch before the destination is written.
    pub(crate) fn sub_rev_assign(&mut self, x: &mut [Limb], y: &[Limb], md: &[Limb]) {
        let borrow = self.difference_of(y, x);
        self.add_masked_modulus(x, md, borrow.wrapping_neg());
    }

    /// `x = 2 * x mod md`, in place, for `x` in `[0, md)`.
    pub(crate) fn double(&mut self, x: &mut [Limb], md: &[Limb]) {
        let n = self.n;
        {
            let sum = &mut self.sum;
            let mut carry = 0u64;
            for i in 0..n {
                let v = x.get(i).copied().unwrap_or(0);
                sum[i] = (v << 1) | carry;
                carry = v >> 63;
            }
            sum[n] = carry;
        }
        self.conditional_subtract(x, md);
    }

    /// `out = a * 2^k mod md` for `a` in `[0, md)` and a public `k`.
    ///
    /// The authority's `BN_mod_lshift_quick` doubles and subtracts in a
    /// value-dependent batch size; repeated single-bit doubling reaches the same
    /// residue in `[0, md)` with a public loop count.
    pub(crate) fn shift_left(&mut self, out: &mut [Limb], a: &[Limb], k: usize, md: &[Limb]) {
        copy_fixed(out, a);
        for _ in 0..k {
            self.double(out, md);
        }
    }

    /// The schoolbook `a * b` into `self.product`, without trimming or reduction.
    ///
    /// The loop bounds are the public width; a limb index beyond an operand's
    /// normalised length reads zero. The authority's `limbs::mul` skips a zero
    /// multiplier, which is a value-dependent branch that this form does not take.
    ///
    /// The column accumulator is `u128` and its maximum is
    /// `(2^64-1)^2 + 2*(2^64-1) = 2^128 - 1`, so none of the arithmetic can
    /// overflow. `wrapping_*` states that and keeps the profile's debug
    /// overflow-check — a conditional jump whose condition is a product of secret
    /// limbs — out of the ladder, the same reason `bn::arith::mul_add_carry`
    /// wraps in the Montgomery core.
    fn product_of(&mut self, a: &[Limb], b: &[Limb]) {
        let n = self.n;
        debug_assert!(a.len() <= n && b.len() <= n);
        let product = &mut self.product;
        product.fill(0);
        for i in 0..n {
            let x = a.get(i).copied().unwrap_or(0);
            let mut carry = 0u64;
            for j in 0..n {
                let y = b.get(j).copied().unwrap_or(0);
                let t = (x as u128)
                    .wrapping_mul(y as u128)
                    .wrapping_add(product[i + j] as u128)
                    .wrapping_add(carry as u128);
                product[i + j] = t as u64;
                carry = (t >> 64) as u64;
            }
            product[i + n] = carry;
        }
    }

    /// Reduce `self.product` (at most `2n` limbs, zero-padded) modulo `md`.
    ///
    /// The kernel was selected from the modulus when the scratch was built; the
    /// dispatch below reads that stored selector, never a limb.
    fn reduce(&mut self, out: &mut [Limb], md: &[Limb]) {
        let n = self.n;
        debug_assert_eq!(out.len(), n);
        debug_assert_eq!(md.len(), n);
        match self.reduction {
            Reduction::SolinasP256 => self.reduce_solinas_p256(out, md),
            Reduction::Knuth => self.reduce_knuth(out, md),
        }
    }

    /// P-256's fixed-sequence Solinas reduction.
    ///
    /// The modulus satisfies `2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p)`, so a value
    /// `lo + hi·2^256` with `hi` four limbs is congruent to
    /// `lo + hi·(2^224 - 2^192 - 2^96 + 1)`. One application of that identity is a
    /// fold: `lo`, `hi`, `hi·2^224` and the two subtractions `hi·2^192` and `hi·2^96`
    /// combined by additions and subtractions alone. `P256_FOLDS` applications suffice
    /// because `hi·2^224 < 2^480`, so a fold leaves the working value below
    /// `2^256 + 2^{bits(hi)+224}` and therefore shrinks the part above bit 256 by 31
    /// bits: 256, 225, 194, 163, 132, 101, 70, 39, 8, and after the ninth fold the
    /// value is below `2^257`. Two masked subtractions then bring it below `p`,
    /// because `2^257 < 3p` and one subtraction of `p` leaves a value below `2p`.
    ///
    /// **Bounds of each fold.** `hi` is four limbs, so `hi < 2^256`, and the value the
    /// fold forms is non-negative (`lo + hi·(2^224 - 2^192 - 2^96 + 1)` with
    /// `2^224 > 2^192 + 2^96`) and below `2^256 + 2^480 < 2^481`. The fold's lane sums
    /// are therefore bounded: a lane receives at most the five contributions `lo`,
    /// `hi`, `hi·2^224`, `-hi·2^192` and `-hi·2^96`, so with `hi`, `lo < 2^256` each
    /// lane is below `5·2^64` in magnitude. The lanes are carried in `i128` — 63 bits
    /// of headroom — and a single carry pass per fold restores radix `2^64`. Because
    /// the fold's total is non-negative and below `2^481`, that pass produces the
    /// exact digits and the ninth limb stays zero.
    ///
    /// The lane sums make the fold's work independent of the values: no carry chain
    /// runs between contributions, and the only dependency is the nine steps of the
    /// carry pass, which is a public-length loop.
    fn reduce_solinas_p256(&mut self, out: &mut [Limb], md: &[Limb]) {
        let n = self.n;
        debug_assert_eq!(n, 4);
        debug_assert_eq!(md, P256_MODULUS.as_slice());
        let mut acc = [0u64; P256_ACC];
        acc[..2 * n].copy_from_slice(&self.product);

        for _ in 0..P256_FOLDS {
            fold_p256(&mut acc);
        }

        // `acc` is below `2^257`, so at most one of its limbs above the fourth is
        // set; two masked subtractions are complete. The mask is all-ones when the
        // subtraction borrowed, i.e. when `acc < p`, and the value is kept then.
        for _ in 0..P256_SUBTRACTIONS {
            let mut diff = [0u64; 5];
            let mut borrow = 0u64;
            for i in 0..n {
                let (d, b1) = acc[i].overflowing_sub(md[i]);
                let (d, b2) = d.overflowing_sub(borrow);
                diff[i] = d;
                borrow = u64::from(b1) | u64::from(b2);
            }
            let (d, b) = acc[n].overflowing_sub(borrow);
            diff[n] = d;
            let keep_mask = u64::from(b).wrapping_neg();
            for i in 0..=n {
                acc[i] = (acc[i] & keep_mask) | (diff[i] & !keep_mask);
            }
        }

        // The two masked subtractions leave a residue below `p`; `acc[n]` is zero
        // there, which the bound argument above establishes. It is not asserted: the
        // limb is secret-derived, and a debug-profile assertion on it would be a
        // secret-dependent branch.
        out.copy_from_slice(&acc[..n]);
    }

    /// Knuth's Algorithm D with the dividend padded to the public `2n` limbs, so
    /// the quotient-digit count is public. The estimate and the add-back are the
    /// same arithmetic `limbs::divide_fallible` runs; the quotient is not stored,
    /// because no caller reads it.
    fn reduce_knuth(&mut self, out: &mut [Limb], md: &[Limb]) {
        let n = self.n;
        if n < 2 {
            // A one-limb modulus: the whole product is two limbs.
            let d = md[0] as u128;
            debug_assert!(d != 0);
            let v = (self.product[0] as u128) | ((self.product[1] as u128) << 64);
            out[0] = (v % d) as u64;
            return;
        }

        let shift = self.shift;
        let acc = &mut self.acc;
        acc.fill(0);
        if shift == 0 {
            acc[..2 * n].copy_from_slice(&self.product);
        } else {
            let mut carry = 0u64;
            for i in 0..2 * n {
                let v = self.product[i];
                acc[i] = (v << shift) | carry;
                carry = v >> (64 - shift);
            }
            acc[2 * n] = carry;
        }

        let divisor = &self.divisor;
        let vtop = divisor[n - 1] as u128;
        let vnext = divisor[n - 2] as u128;
        for j in (0..=n).rev() {
            // D3: estimate the quotient digit from the top two limbs. The
            // estimate's loop is value-dependent in the same places as
            // `limbs::divide_fallible`'s; the products below are bounded by
            // `2^128 - 1`, so `wrapping_*` keeps the debug overflow-check branch
            // off secret limbs (see `product_of`).
            let top = ((acc[j + n] as u128) << 64) | (acc[j + n - 1] as u128);
            let mut qhat = top / vtop;
            let mut rhat = top % vtop;
            while qhat >= (1u128 << 64)
                || qhat.wrapping_mul(vnext) > ((rhat << 64) | (acc[j + n - 2] as u128))
            {
                qhat -= 1;
                rhat += vtop;
                if rhat >= (1u128 << 64) {
                    break;
                }
            }
            // D4: multiply and subtract.
            let mut borrow = 0i128;
            let mut carry = 0u128;
            for i in 0..n {
                let p = qhat.wrapping_mul(divisor[i] as u128).wrapping_add(carry);
                carry = p >> 64;
                let t = (acc[j + i] as i128)
                    .wrapping_sub((p & 0xffff_ffff_ffff_ffff) as i128)
                    .wrapping_sub(borrow);
                acc[j + i] = (t & 0xffff_ffff_ffff_ffff) as u64;
                borrow = i128::from(t < 0);
            }
            let t = (acc[j + n] as i128)
                .wrapping_sub(carry as i128)
                .wrapping_sub(borrow);
            acc[j + n] = (t & 0xffff_ffff_ffff_ffff) as u64;
            // D5/D6: add back when the estimate borrowed out.
            if t < 0 {
                let mut c = 0u128;
                for i in 0..n {
                    let s = (acc[j + i] as u128)
                        .wrapping_add(divisor[i] as u128)
                        .wrapping_add(c);
                    acc[j + i] = s as u64;
                    c = s >> 64;
                }
                acc[j + n] = (acc[j + n] as u128).wrapping_add(c) as u64;
            }
        }

        // D8: the remainder is the shifted-back low `n` limbs.
        if shift == 0 {
            out.copy_from_slice(&acc[..n]);
        } else {
            for i in 0..n {
                let hi = if i + 1 < n { acc[i + 1] } else { 0 };
                out[i] = (acc[i] >> shift) | (hi << (64 - shift));
            }
        }
    }

    /// `self.sum = a + b` over `n + 1` limbs.
    fn sum_of(&mut self, a: &[Limb], b: &[Limb]) {
        let n = self.n;
        let sum = &mut self.sum;
        let mut carry = 0u64;
        for i in 0..n {
            // At most `2*(2^64-1) + 1 < 2^65`: no overflow, checks suppressed as
            // in `product_of`.
            let s = (a.get(i).copied().unwrap_or(0) as u128)
                .wrapping_add(b.get(i).copied().unwrap_or(0) as u128)
                .wrapping_add(carry as u128);
            sum[i] = s as u64;
            carry = (s >> 64) as u64;
        }
        sum[n] = carry;
    }

    /// `out = self.sum - md` when `self.sum >= md`, else `self.sum`, as a masked
    /// select over `n + 1` limbs.
    ///
    /// The callers only reach this with `self.sum < 2 * md`, so one conditional
    /// subtraction is complete.
    fn conditional_subtract(&mut self, out: &mut [Limb], md: &[Limb]) {
        let n = self.n;
        let sum = &self.sum;
        let diff = &mut self.diff;
        let mut borrow = 0u64;
        for i in 0..n {
            let d = (sum[i] as u128)
                .wrapping_sub(md[i] as u128)
                .wrapping_sub(borrow as u128);
            diff[i] = d as u64;
            borrow = ((d >> 127) & 1) as u64;
        }
        let top = (sum[n] as u128).wrapping_sub(borrow as u128);
        diff[n] = top as u64;
        let underflow = ((top >> 127) & 1) as u64;
        let mask = underflow.wrapping_neg();
        for i in 0..n {
            out[i] = (sum[i] & mask) | (diff[i] & !mask);
        }
    }

    /// `self.diff = a - b` over `n` limbs, answering the final borrow.
    fn difference_of(&mut self, a: &[Limb], b: &[Limb]) -> u64 {
        let n = self.n;
        let diff = &mut self.diff;
        let mut borrow = 0u64;
        for i in 0..n {
            let d = (a.get(i).copied().unwrap_or(0) as u128)
                .wrapping_sub(b.get(i).copied().unwrap_or(0) as u128)
                .wrapping_sub(borrow as u128);
            diff[i] = d as u64;
            borrow = ((d >> 127) & 1) as u64;
        }
        borrow
    }

    /// `out = self.diff + (md & mask)`, propagating the carry across `n` limbs.
    fn add_masked_modulus(&mut self, out: &mut [Limb], md: &[Limb], mask: u64) {
        let n = self.n;
        let diff = &self.diff;
        let mut carry = 0u64;
        for i in 0..n {
            // At most `2*(2^64-1) + 1 < 2^65`: checks suppressed as in `product_of`.
            let s = (diff[i] as u128)
                .wrapping_add((md[i] as u128) & (mask as u128))
                .wrapping_add(carry as u128);
            out[i] = s as u64;
            carry = (s >> 64) as u64;
        }
    }
}

/// The kernel a modulus of this shape gets.
///
/// The only inputs are the modulus' public limb count and limb values. P-256 is the
/// one modulus with a specialised kernel on this profile; every other width and
/// every other value takes the generic Knuth reduction.
fn reduction_for(md: &[Limb]) -> Reduction {
    if md == P256_MODULUS.as_slice() {
        Reduction::SolinasP256
    } else {
        Reduction::Knuth
    }
}

/// One P-256 fold of the nine-limb accumulator, in place.
///
/// Replaces `lo + hi·2^256` by `lo + hi·(2^224 - 2^192 - 2^96 + 1)`, where `lo` is
/// limbs 0..4 and `hi` limbs 4..8. `hi·2^32` is formed once as a five-limb value, so
/// the 224- and 96-bit shifts are whole-limb offsets from it: `hi·2^224` is that
/// value at limb 3, `hi·2^192` is `hi` at limb 3, and `hi·2^96` is that value at
/// limb 1.
///
/// The five contributions are accumulated into `i128` lanes and carried once. A lane
/// receives at most five contributions each below `2^64` in magnitude, so no lane can
/// overflow and no carry chain runs between contributions; the single carry pass is a
/// fixed nine-step loop. Because the fold's total is non-negative and below `2^481`
/// (see [`FieldScratch::reduce_solinas_p256`]), the pass reconstructs its exact radix
/// `2^64` digits and the ninth limb is zero.
#[inline(always)]
fn fold_p256(acc: &mut [Limb; P256_ACC]) {
    let lo = [acc[0], acc[1], acc[2], acc[3]];
    let hi = [acc[4], acc[5], acc[6], acc[7]];
    // `hi · 2^32`, five limbs. The shifts below are offsets from this value.
    let hi32 = [
        hi[0] << 32,
        (hi[1] << 32) | (hi[0] >> 32),
        (hi[2] << 32) | (hi[1] >> 32),
        (hi[3] << 32) | (hi[2] >> 32),
        hi[3] >> 32,
    ];

    let mut lane = [0i128; P256_ACC];
    for i in 0..4 {
        lane[i] = lane[i]
            .wrapping_add(lo[i] as i128)
            .wrapping_add(hi[i] as i128);
    }
    for i in 0..5 {
        lane[3 + i] = lane[3 + i].wrapping_add(hi32[i] as i128);
    }
    for i in 0..4 {
        lane[3 + i] = lane[3 + i].wrapping_sub(hi[i] as i128);
    }
    for i in 0..5 {
        lane[1 + i] = lane[1 + i].wrapping_sub(hi32[i] as i128);
    }

    // One carry pass: `lane[i] + carry` splits into a radix-`2^64` digit and the
    // next lane's carry, with the arithmetic shift supplying the floor division.
    // `wrapping_*` states the lane bound above and keeps the debug profile's
    // overflow check — a conditional jump on secret-derived lanes — out of the fold.
    let mut carry = 0i128;
    for i in 0..P256_ACC {
        let v = lane[i].wrapping_add(carry);
        acc[i] = v as u64;
        carry = v >> 64;
    }
}

/// One scalar multiplication's fixed-width field workspace.
///
/// Created by [`ScalarLadderWorkspace::new`] from public curve parameters and the
/// affine input point, borrowed by the ladder for the whole scalar multiplication
/// (its `rx`/`rz` and `sx`/`sz` slots **are** the ladder's live `r` and `s`
/// coordinates between the initial staging and the single write-back), and dropped
/// (cleansing every buffer) when the scalar multiplication returns.
pub(crate) struct ScalarLadderWorkspace {
    /// The shared product/division/conditional scratch.
    pub(crate) scratch: FieldScratch,
    /// The ladder's coordinate and `t0`..`t6` slots.
    pub(crate) slots: LadderSlots,
}

impl ScalarLadderWorkspace {
    /// Build the workspace at `md`'s public width.
    ///
    /// `md`, `ca`, `cb` and `px` are the field modulus, the curve's `a`, the
    /// curve's `b` and the affine input point's `X`. They are staged once here,
    /// because all four are loop invariant for the scalar multiplication. `None`
    /// means a buffer could not be allocated; the caller reports the ladder step's
    /// ordinary allocation failure.
    pub(crate) fn new(md: &[Limb], ca: &[Limb], cb: &[Limb], px: &[Limb]) -> Option<Self> {
        let n = md.len();
        // A curve constant or input coordinate wider than the modulus is outside
        // the plain-field contract this workspace serves (every caller reduces
        // them first). Answering `None` keeps the caller on a path that can handle
        // it instead of silently truncating a value.
        if ca.len() > n || cb.len() > n || px.len() > n {
            return None;
        }
        let scratch = FieldScratch::try_new(md)?;
        let n = scratch.width();
        let mut slots = LadderSlots::try_new(n)?;
        copy_fixed(&mut slots.ca, ca);
        copy_fixed(&mut slots.cb, cb);
        copy_fixed(&mut slots.px, px);
        Some(Self { scratch, slots })
    }

    /// The public modulus width in limbs.
    pub(crate) fn width(&self) -> usize {
        self.scratch.width()
    }
}

/// Copy `src` into `dst`, zero-extending to `dst`'s public width.
///
/// The copy length is `dst.len()` (public width), not `src.len()`; a limb index
/// beyond `src`'s normalised length reads zero. That presence test is the one
/// length-dependent read in this staging step.
pub(crate) fn copy_fixed(dst: &mut [Limb], src: &[Limb]) {
    debug_assert!(src.len() <= dst.len());
    for (i, slot) in dst.iter_mut().enumerate() {
        *slot = src.get(i).copied().unwrap_or(0);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // test-only failure assertions
mod tests {
    use super::*;
    use crate::bn::limbs;

    fn nist_256() -> &'static [Limb] {
        // SAFETY: a static getter takes no pointers.
        unsafe { &(*crate::bn::primes::BN_get0_nist_prime_256()).d }
    }

    fn nist_384() -> &'static [Limb] {
        // SAFETY: as above.
        unsafe { &(*crate::bn::primes::BN_get0_nist_prime_384()).d }
    }

    fn nist_521() -> &'static [Limb] {
        // SAFETY: as above.
        unsafe { &(*crate::bn::primes::BN_get0_nist_prime_521()).d }
    }

    /// Operand shapes a field element can take, including edges: zero, one, the
    /// modulus minus one, the modulus' top limb alone, and alternating bit
    /// patterns.
    fn operands(md: &[Limb]) -> Vec<Vec<Limb>> {
        let n = md.len();
        let mut v: Vec<Vec<Limb>> = Vec::new();
        v.push(Vec::new());
        v.push(vec![1]);
        v.push(vec![2]);
        let mut minus_one = md.to_vec();
        minus_one[0] -= 1;
        v.push(minus_one);
        let mut top = vec![0u64; n];
        top[n - 1] = md[n - 1];
        v.push(top);
        let mut pattern = vec![0u64; n];
        for (i, slot) in pattern.iter_mut().enumerate() {
            *slot = 0x0123_4567_89ab_cdefu64.wrapping_mul(i as u64 + 1) | 1;
        }
        v.push(pattern);
        let mut high = vec![0u64; n];
        high[n - 1] = 1 << 63;
        v.push(high);
        v
    }

    fn normalised(v: &[Limb]) -> Vec<Limb> {
        let mut v = v.to_vec();
        limbs::normalise(&mut v);
        v
    }

    fn reference_mul(md: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        let product = limbs::mul_fallible(a, b).expect("product allocation");
        limbs::rem_fallible(&product, md).expect("reduction allocation")
    }

    fn one_case(md: &[Limb]) {
        let mut ws = FieldScratch::try_new(md).expect("workspace allocation");
        let n = ws.width();
        let values = operands(md);
        // The `_quick` forms require operands already in `[0, md)`; the product
        // form accepts any value below `2^(64n)`. Reduce a copy for the former so a
        // test shape outside its contract is not read as a defect.
        let reduced: Vec<Vec<Limb>> = values
            .iter()
            .map(|v| limbs::rem_fallible(v, md).expect("operand reduction"))
            .collect();
        let mut out = vec![0u64; n];
        for a in &values {
            for b in &values {
                // Product and reduction.
                ws.mul(&mut out, a, b, md);
                assert_eq!(
                    normalised(&out),
                    normalised(&reference_mul(md, a, b)),
                    "mul mismatch"
                );

                // In-place multiply must agree.
                let mut acc = vec![0u64; n];
                copy_fixed(&mut acc, a);
                ws.mul_assign(&mut acc, b, md);
                assert_eq!(normalised(&acc), normalised(&out), "mul_assign mismatch");
            }
        }
        for a in &reduced {
            for b in &reduced {
                // Modular addition, against the reduced-operand constant form.
                ws.add(&mut out, a, b, md);
                let reference =
                    crate::bn::arith::mod_add_reduced_ct_limbs(a, b, md).expect("add reference");
                assert_eq!(normalised(&out), normalised(&reference), "add mismatch");

                // Modular subtraction, evaluated from its definition.
                ws.sub(&mut out, a, b, md);
                let reference = if limbs::cmp(a, b) != core::cmp::Ordering::Less {
                    limbs::sub_fallible(a, b).expect("sub reference")
                } else {
                    // `a - b mod md == md - (b - a)` because both are reduced and
                    // the difference is below the modulus.
                    let d = limbs::sub_fallible(b, a).expect("sub reference");
                    limbs::sub_fallible(md, &d).expect("sub reference")
                };
                assert_eq!(normalised(&out), normalised(&reference), "sub mismatch");
            }

            // Squaring and doubling.
            ws.sqr(&mut out, a, md);
            assert_eq!(
                normalised(&out),
                normalised(&reference_mul(md, a, a)),
                "sqr mismatch"
            );

            let mut doubled = vec![0u64; n];
            copy_fixed(&mut doubled, a);
            ws.double(&mut doubled, md);
            assert_eq!(
                normalised(&doubled),
                normalised(&reference_mul(md, a, &[2])),
                "double mismatch"
            );

            for k in [1usize, 2, 3] {
                ws.shift_left(&mut out, a, k, md);
                let mut reference = a.clone();
                for _ in 0..k {
                    reference = reference_mul(md, &reference, &[2]);
                }
                assert_eq!(
                    normalised(&out),
                    normalised(&reference),
                    "shift_left mismatch"
                );
            }
        }
    }

    #[test]
    fn the_workspace_arithmetic_matches_the_generic_forms_at_nist_widths() {
        // P-256 (4 limbs), P-384 (6) and P-521 (9, whose top limb is not
        // normalised, so the reduction runs with a non-zero shift).
        one_case(nist_256());
        one_case(nist_384());
        one_case(nist_521());
    }

    /// The P-256 kernel's compile-time modulus is the curve's own, not a copy that
    /// has drifted: `BN_get0_nist_prime_256` and the P-256 group's field are both
    /// compared against the constant the selection predicate reads.
    #[test]
    fn the_p256_kernel_constant_is_the_curves_modulus() {
        use crate::bn::primes::BN_get0_nist_prime_256;
        use crate::ec::curve::EC_GROUP_new_by_curve_name;
        use crate::ec::lib::EC_GROUP_free;
        use crate::runtime::obj::NID_X9_62_prime256v1;

        // SAFETY: the prime getter borrows a static; the group is created and
        // released here.
        unsafe {
            let prime = BN_get0_nist_prime_256();
            assert_eq!(&(*prime).d, P256_MODULUS.as_slice());
            let group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!group.is_null());
            assert_eq!(&(*(*group).field).d, P256_MODULUS.as_slice());
            EC_GROUP_free(group);
        }
    }

    /// The kernel is chosen from the modulus alone: P-256 takes the Solinas fold,
    /// every other width takes Knuth, and a modulus one limb away from P-256 is not
    /// P-256.
    #[test]
    fn the_reduction_kernel_is_selected_from_the_modulus() {
        let solinas = FieldScratch::try_new(nist_256()).expect("P-256 scratch");
        assert_eq!(solinas.reduction(), Reduction::SolinasP256);
        for md in [nist_384(), nist_521()] {
            let scratch = FieldScratch::try_new(md).expect("scratch");
            assert_eq!(scratch.reduction(), Reduction::Knuth);
        }
        let forced = FieldScratch::try_new_knuth(nist_256()).expect("forced scratch");
        assert_eq!(forced.reduction(), Reduction::Knuth);
        let mut near = P256_MODULUS;
        near[0] -= 1;
        assert_eq!(reduction_for(&near), Reduction::Knuth);
    }

    /// Deterministic pseudo-random limbs (xorshift64), so the sweep is reproducible.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> Limb {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn limbs(&mut self, n: usize) -> Vec<Limb> {
            let mut v: Vec<Limb> = (0..n).map(|_| self.next()).collect();
            limbs::normalise(&mut v);
            v
        }

        fn below(&mut self, limit: usize) -> usize {
            (self.next() as usize) % limit
        }
    }

    /// Feed `x` (at most `2n` limbs) through one scratch's reduction.
    fn reduce_with(ws: &mut FieldScratch, x: &[Limb], md: &[Limb]) -> Vec<Limb> {
        let width = ws.product.len();
        assert!(x.len() <= width, "an input wider than the accumulator");
        ws.product.fill(0);
        ws.product[..x.len()].copy_from_slice(x);
        let mut out = vec![0u64; ws.width()];
        ws.reduce(&mut out, md);
        normalised(&out)
    }

    /// Reduce `x` through the crate's `BN_nnmod` entry point.
    ///
    /// This is the reference that is not common-mode with the kernel under test:
    /// `BN_nnmod` runs `limbs::rem_fallible`, i.e. Knuth's Algorithm D, and never
    /// reaches the Solinas fold. Passing a null context is what the C ABI accepts,
    /// because the function has no context use.
    fn bn_nnmod_reference(md: &[Limb], x: &[Limb]) -> Vec<Limb> {
        use crate::bn::arith::BN_nnmod;
        use crate::bn::bignum::BigNum;

        let a = BigNum {
            d: normalised(x),
            neg: 0,
            flags: 0,
        };
        let m = BigNum {
            d: md.to_vec(),
            neg: 0,
            flags: 0,
        };
        let mut r = BigNum {
            d: Vec::new(),
            neg: 0,
            flags: 0,
        };
        // SAFETY: all three objects are live and owned by this call, and `_ctx` is
        // unused by `BN_nnmod`.
        let ok = unsafe { BN_nnmod(&mut r, &a, &m, core::ptr::null_mut()) };
        assert_eq!(ok, 1, "BN_nnmod refused the reference reduction");
        normalised(&r.d)
    }

    /// The Solinas kernel and the generic Knuth kernel must agree with `BN_nnmod`
    /// bit for bit, over the shapes the fold's bounds are argued about and over a
    /// deterministic sweep.
    #[test]
    fn the_solinas_reduction_is_exactly_the_generic_reduction() {
        let md = nist_256();
        let p = P256_MODULUS.to_vec();
        let mut solinas = FieldScratch::try_new(md).expect("P-256 scratch");
        let mut knuth = FieldScratch::try_new_knuth(md).expect("forced Knuth scratch");

        let mut p_minus_1 = p.clone();
        p_minus_1[0] -= 1;
        let p_plus_1 = limbs::add_fallible(&p, &[1]).expect("p + 1");
        let two_p_minus_1 =
            limbs::sub_fallible(&limbs::add_fallible(&p, &p).expect("2p"), &[1]).expect("2p - 1");
        let two_p = limbs::add_fallible(&p, &p).expect("2p");
        let p_sq_minus_1 =
            limbs::sub_fallible(&limbs::mul_fallible(&p, &p).expect("p^2"), &[1]).expect("p^2 - 1");
        let pm1_sq = limbs::mul_fallible(&p_minus_1, &p_minus_1).expect("(p-1)^2");
        let p_times_pm1 = limbs::mul_fallible(&p, &p_minus_1).expect("p(p-1)");

        let mut cases: Vec<Vec<Limb>> = vec![
            Vec::new(),
            vec![0],
            vec![1],
            vec![2],
            limbs::sub_fallible(&p, &[2]).expect("p - 2"),
            p_minus_1,
            p.clone(),
            p_plus_1,
            two_p_minus_1,
            two_p,
            vec![u64::MAX; 4],
            vec![u64::MAX; 8],
            {
                // 2^448: only the top limb of the high half is set.
                let mut v = vec![0u64; 8];
                v[7] = 1;
                v
            },
            {
                let mut v = vec![0u64; 8];
                v[7] = 1 << 63;
                v
            },
            p_sq_minus_1,
            pm1_sq,
            p_times_pm1,
        ];

        // 4 096 values of varying width, plus 2 048 genuine four-by-four limb
        // products: the second family is what the kernel actually sees.
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..4096 {
            let width = rng.below(9);
            cases.push(rng.limbs(width));
        }
        for _ in 0..2048 {
            let a = rng.limbs(4);
            let b = rng.limbs(4);
            cases.push(limbs::mul_fallible(&a, &b).expect("product"));
        }

        let mut checked = 0usize;
        for x in &cases {
            let got = reduce_with(&mut solinas, x, md);
            assert!(
                limbs::cmp(&got, &p) == core::cmp::Ordering::Less,
                "not reduced"
            );
            assert_eq!(got, reduce_with(&mut knuth, x, md), "Knuth disagrees");
            assert_eq!(got, bn_nnmod_reference(md, x), "BN_nnmod disagrees");
            checked += 1;
        }
        assert!(checked >= 4096, "the sweep must cover at least 4096 values");
    }

    /// The T29 claim itself: the workspace is allocated once per scalar
    /// multiplication and no field operation allocates at all.
    #[test]
    fn the_workspace_allocates_once_and_each_operation_allocates_nothing() {
        use crate::runtime::alloc::test_fail::{tally_start, tally_take};

        fn total(sites: &[(&'static core::panic::Location<'static>, usize)]) -> usize {
            sites.iter().map(|&(_, n)| n).sum()
        }

        let md = nist_256();
        let guard = tally_start();
        let mut ws = ScalarLadderWorkspace::new(md, md, md, md).expect("workspace allocation");
        let created = total(&tally_take());
        drop(guard);
        assert_eq!(
            created, 19,
            "one workspace is 5 scratch buffers plus 14 ladder slots"
        );

        let n = ws.width();
        let values = operands(md);
        let mut out = vec![0u64; n];
        let mut x = vec![0u64; n];
        copy_fixed(&mut x, &values[5]);

        let guard = tally_start();
        let scratch = &mut ws.scratch;
        for _ in 0..8 {
            let a = &values[5];
            let b = &values[6];
            scratch.mul(&mut out, a, b, md);
            scratch.mul_assign(&mut x, a, md);
            scratch.sqr(&mut out, a, md);
            scratch.sqr_assign(&mut x, md);
            scratch.add(&mut out, a, b, md);
            scratch.add_assign(&mut x, b, md);
            scratch.sub(&mut out, a, b, md);
            scratch.sub_assign(&mut x, b, md);
            scratch.double(&mut x, md);
            scratch.shift_left(&mut out, a, 3, md);
        }
        let after_ops = total(&tally_take());
        drop(guard);
        assert_eq!(after_ops, 0, "no field operation may allocate");
    }
}
