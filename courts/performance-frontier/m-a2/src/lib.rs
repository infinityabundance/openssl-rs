//! M-A2 — reduced-radix (2^52) deferred-carry Montgomery multiplication.
//!
//! **This is an experiment, not a candidate.** Nothing here is reachable from
//! `src/`; the crate is a standalone workspace root, it has no dependencies, and
//! it is excluded from packaging by the root manifest. It exists to answer one
//! question by measurement: does an unsaturated 52-bit-limb CIOS multiply, whose
//! carries are deferred out of the inner loops and settled once, beat the
//! incumbent radix-2^64 CIOS?
//!
//! The crate is `#![forbid(unsafe_code)]`. The arm's premise is that the
//! comparison is meaningful in safe Rust alone: no `unsafe`, no intrinsics, no
//! assembly. Every routine below is safe Rust over `u64`/`u128`.
//!
//! # Representations
//!
//! * **radix 2^52** — `N` limbs, each `< 2^52`; `R = B^N`, `B = 2^52`;
//!   `N = 5` at 256 bits (`B^5 = 2^260`, 4 spare bits above 256) and `N = 20`
//!   at 1024 bits (`B^20 = 2^1040`, 16 spare bits above 1024). Each limb
//!   product is at most `(B-1)^2 < 2^104`.
//! * **radix 2^64** — `n` limbs, each `< 2^64`; `R = 2^(64n)`; `n = 4` at 256
//!   bits and `n = 16` at 1024 bits.
//!
//! # Extra-limb cost (stated before measuring)
//!
//! For both widths in scope the 52-bit representation uses 25% more limbs
//! (`ceil(bits/52)` vs `bits/64`): 5 vs 4 and 20 vs 16. Because the number of
//! limb products per multiply is quadratic in the limb count, the 52-bit CIOS
//! performs **56.25% more multiply-accumulates** than the 64-bit CIOS at the
//! same modulus size (e.g. 50 vs 32 for 256 bits; 800 vs 512 for 1024 bits,
//! counting both the product row and the reduction row). The hypothesis is that
//! removing the serial carry chain compensates. That is a hypothesis; the
//! measurement decides it, as the dedicated-squaring refutation requires.
//!
//! # Accumulator bound (the proof obligation; an unproven bound is a refusal)
//!
//! In [`mont_mul_52_deferred`] the accumulator is `N` `u128` coefficients,
//! indexed `acc[0..N]`, which are **deliberately not renormalised** inside the
//! loop. We prove that no coefficient can overflow `u128` for the largest
//! modulus in scope (`N = 20`, 1024 bits; `N = 5` for 256 bits is smaller).
//!
//! Write `B = 2^52`, `P = 2(B-1)^2 < 2^105`, `S = P/(B-1) < P/2^51`.
//! Let `C_j` be the bound on `acc[j]` at the start of an iteration. The
//! induction hypothesis is
//!
//! ```text
//!     C_j <= (N - j) * P + S          for j = 0 .. N-1
//! ```
//!
//! Base case: all coefficients start at zero. Inductive step, with
//! `0 <= a_j, m_j, b_i, u < B` and therefore `a_j*b_i < (B-1)^2`,
//! `u*m_j < (B-1)^2`:
//!
//! 1. After both product rows are accumulated, each coefficient is
//!    `D_j = acc_j + a_j*b_i + u*m_j <= C_j + 2(B-1)^2 = C_j + P`,
//!    hence `D_j <= (N - j + 1) * P + S`.
//! 2. The deferred shift sets `C'_0 = D_1 + floor(D_0/B)`,
//!    `C'_j = D_{j+1}` for `1 <= j <= N-2`, and `C'_{N-1} = 0`.
//!    For `j >= 1`: `C'_j = D_{j+1} <= (N - j) * P + S`. For `j = 0`:
//!    `floor(D_0/B) <= ((N+1)P + S)/B <= P` because
//!    `N + 1 + 1/(B-1) <= 21 < B = 2^52`, so
//!    `C'_0 <= (N-1)P + S + P = N*P + S`. The top coefficient is reset to zero,
//!    which satisfies `0 <= P + S`.
//!
//! The maximum coefficient is therefore below `(N+1)*P < 2(N+1)*B^2`. For
//! `N = 20` that is `42 * 2^104 < 2^109.4`; for `N = 5` it is `12 * 2^104 <
//! 2^107.6`. Both are far below `2^128`, so:
//!
//! * a `u128` coefficient can hold `2^128 / 2^104 = 2^24 = 16,777,216`
//!   maximal 104-bit limb products, and the proven worst case uses fewer than
//!   `2(N+1) = 42` of them;
//! * the headroom is at least **18 bits** at 1024 bits and at least 20 bits at
//!   256 bits;
//! * adding the two product rows (`< 2^105`) to a coefficient already below
//!   `2^110` cannot overflow, and the final settling pass adds a carry below
//!   `2^59`.
//!
//! The Montgomery value invariant is the ordinary CIOS one: with `a, b < m`
//! and `m` odd, the pre-reduction accumulator value is below `2m`, so the one
//! masked conditional subtraction leaves a canonical residue in `[0, m)`.
//! Because the coefficients are only an unreduced *representation* of that
//! value, the invariant is about the value, not about each coefficient, which
//! is exactly why the bound above must be proved separately.
//!
//! The 64-bit CIOS needs no such bound: every intermediate is a single `u64`
//! carry produced by `mul_add_carry`, whose own argument is the incumbent's
//! (`(2^64-1)^2 + 2(2^64-1) = 2^128 - 1`).
//!
//! # What is and is not measured here
//!
//! [`mont_mul_64_slice`] is a **line-by-line transcription** of the crate's
//! `mont_mul_cios_into` (`src/bn/arith.rs`, the admitted CIOS carrier) over
//! dynamically sized slices. It is the reference the arm is asked to compare
//! against, but its absolute numbers do not transfer to the DSO: it is in this
//! binary, not in `libcrypto.so.3`, and it is compiled by this crate's profile.
//! [`mont_mul_64_fixed`] is the same algorithm over fixed-size arrays; it
//! isolates the radix effect from slice bounds checks and geometry checks. The
//! primary comparison is 52-bit deferred vs 64-bit fixed (same code shape), with
//! the transcription reported alongside.

#![forbid(unsafe_code)]
// Index-based loops are the arithmetic here: the index is the limb position, and
// several loops write `acc[j]` while reading `acc[j + 1]`. Clippy's iterator
// rewrite would obscure the coefficient structure, so the lint is allowed in
// this experiment crate only (never in the product).
#![allow(clippy::needless_range_loop)]

/// `2^52 - 1`.
pub const MASK52: u64 = (1u64 << 52) - 1;

/// Bits per 52-bit limb.
pub const LIMB52_BITS: u32 = 52;

/// `-m^-1 mod 2^64`, for the radix-2^64 CIOS (`m` odd).
///
/// Newton iteration doubles the number of correct low bits each step; starting
/// from `m` (correct mod 8 for odd `m`) six steps give 192 correct bits, more
/// than the 64 used.
#[inline]
pub fn n0_64(m0: u64) -> u64 {
    let mut inv = m0;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    0u64.wrapping_sub(inv)
}

/// `-m^-1 mod 2^52`, for the radix-2^52 kernels (`m` odd).
///
/// [`n0_64`] already returns `-m^-1`; truncating it to 52 bits leaves
/// `-m^-1 mod 2^52` because `52 < 64`.
#[inline]
pub fn n0_52(m0: u64) -> u64 {
    n0_64(m0) & MASK52
}

/// `a*b + c + d` for 64-bit terms, as a 128-bit value.
///
/// Transcribed from the incumbent (`src/bn/arith.rs`): the maximum is
/// `(2^64-1)^2 + 2(2^64-1) = 2^128 - 1`, so the `wrapping_*` operations state
/// that the wrap cannot occur and keep the profile's overflow check out of the
/// secret-bearing loop.
#[inline(always)]
fn mul_add_carry(a: u64, b: u64, c: u64, d: u64) -> u128 {
    (a as u128)
        .wrapping_mul(b as u128)
        .wrapping_add(c as u128)
        .wrapping_add(d as u128)
}

/// Transcribed barrier: prevents LLVM from lowering the mask select as a
/// branch. Safe `core::hint::black_box`, exactly as the incumbent uses it.
#[inline(always)]
fn value_barrier(a: usize) -> usize {
    core::hint::black_box(a)
}

/// Transcribed `constant_time_select`.
#[inline(always)]
fn constant_time_select(mask: usize, a: usize, b: usize) -> usize {
    (value_barrier(mask) & a) | (value_barrier(!mask) & b)
}

/// One masked conditional subtraction of `m`, given the pre-reduction value
/// `x[0..N]` plus the possible high limb `high` (`0` or `1`).
///
/// **The borrow chain is base-`2^52`, not base-`2^64`.** This is the one place
/// where a reduced-radix port cannot transcribe the incumbent: the crate's
/// `x[j] - m[j] - borrow` wraps in `2^64`, so an intermediate underflow stores
/// `2^64 - d` in the digit while borrowing one from the next limb. That is a
/// valid base-`2^64` digit but not a valid base-`2^52` digit, and it corrupts
/// the value. Here the wrapped difference is masked to the 52-bit digit and the
/// borrow is decided by comparing against `m[j] + borrow` (which cannot
/// overflow, as `m[j] < 2^52`). `2^64 = 0 mod 2^52`, so masking the wrapped
/// subtraction yields exactly the base-`2^52` digit.
///
/// `x + high*B^N < 2m`, so one subtraction suffices. Branchless: `keep` is a
/// value-derived bit and the selection is an AND/OR mask.
#[inline(always)]
fn conditional_subtract<const N: usize>(x: &[u64; N], m: &[u64; N], high: u64) -> [u64; N] {
    let mut diff = [0u64; N];
    let mut borrow = 0u64;
    for j in 0..N {
        let rhs = m[j] + borrow;
        let under = u64::from(x[j] < rhs);
        diff[j] = x[j].wrapping_sub(rhs) & MASK52;
        borrow = under;
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    let mut out = [0u64; N];
    for j in 0..N {
        out[j] = (diff[j] & mask) | (x[j] & !mask);
    }
    out
}

// ---------------------------------------------------------------------------
// Radix 2^52, deferred carries, one settling pass at the end.
// ---------------------------------------------------------------------------

/// Radix-2^52 Montgomery multiply with **all carries deferred** out of the
/// inner loops.
///
/// Inputs and modulus are canonical 52-bit limbs (`< 2^52`), `a, b < m`, `m`
/// odd. `n0` is `-m^-1 mod 2^52` (see [`n0_52`]). `acc` is scratch storage of
/// exactly `N` `u128` coefficients; its contents are ignored on entry.
///
/// The inner loops contain **no carry chain and no mask**: products accumulate
/// independently into `u128` coefficients. Once per iteration the accumulator is
/// divided by `B` exactly — a logical shift of the limb index — and each
/// coefficient is settled only in the single pass after the last iteration.
/// That pass is the "settling pass" whose cost this arm must pay for.
///
/// The accumulator bound is proved in the module documentation; the worst case
/// at 1024 bits is below `2^110`, with 18 bits of headroom in a `u128`.
pub fn mont_mul_52_deferred<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    n0: u64,
    acc: &mut [u128; N],
) -> [u64; N] {
    debug_assert!(N >= 2);
    for slot in acc.iter_mut() {
        *slot = 0;
    }

    for i in 0..N {
        let bi = b[i] as u128;
        // Product row: independent 104-bit products, no serial carry.
        for j in 0..N {
            acc[j] += (a[j] as u128) * bi;
        }

        // `u` depends only on the low 52 bits of the low coefficient.
        let u = ((acc[0] as u64) & MASK52).wrapping_mul(n0) & MASK52;
        let uu = u as u128;
        // Reduction row: again independent products. `acc[0]` becomes exactly
        // divisible by B, which makes the logical divide below exact.
        for j in 0..N {
            acc[j] += (m[j] as u128) * uu;
        }

        // Divide by B: `c_0 = D_1 + D_0/B`, `c_j = D_{j+1}`, `c_{N-1} = 0`.
        // `D_0` is an exact multiple of B by construction of `u`.
        let low = acc[0] >> LIMB52_BITS;
        for j in 0..N - 1 {
            acc[j] = acc[j + 1];
        }
        acc[N - 1] = 0;
        acc[0] += low;
    }

    // The single settling pass: propagate every deferred carry once.
    let mut carry: u128 = 0;
    let mut normalized = [0u64; N];
    for j in 0..N {
        let v = acc[j] + carry;
        normalized[j] = (v & MASK52 as u128) as u64;
        carry = v >> LIMB52_BITS;
    }
    // The represented value is < 2m < 2B^N, so the carry out is 0 or 1.
    debug_assert!(carry <= 1);
    conditional_subtract(&normalized, m, carry as u64)
}

/// The same radix-2^52 arithmetic with the per-iteration accumulator shift
/// replaced by a rotating logical offset.
///
/// The coefficients are identical to [`mont_mul_52_deferred`]; only the
/// bookkeeping differs: no `N`-element copy per iteration, but one extra
/// mask-and-add per coefficient access. It exists to attribute a loss (or a
/// win) between "the radix costs more products" and "the shift costs moves".
/// `L` must be a power of two with `L >= N` (8 for 256 bits, 32 for 1024).
pub fn mont_mul_52_rotate<const N: usize, const L: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    n0: u64,
    acc: &mut [u128; L],
) -> [u64; N] {
    debug_assert!(N >= 2);
    debug_assert!(L.is_power_of_two() && L >= N);
    let idx_mask = L - 1;

    for slot in acc.iter_mut() {
        *slot = 0;
    }
    let mut off = 0usize;
    for i in 0..N {
        let bi = b[i] as u128;
        for j in 0..N {
            let p = (j + off) & idx_mask;
            acc[p] += (a[j] as u128) * bi;
        }
        let low_slot = off & idx_mask;
        let u = ((acc[low_slot] as u64) & MASK52).wrapping_mul(n0) & MASK52;
        let uu = u as u128;
        for j in 0..N {
            let p = (j + off) & idx_mask;
            acc[p] += (m[j] as u128) * uu;
        }
        let low = acc[low_slot] >> LIMB52_BITS;
        off = (off + 1) & idx_mask;
        // New logical N-1 is zero; new logical 0 receives the divided low part.
        acc[(N - 1 + off) & idx_mask] = 0;
        acc[off & idx_mask] += low;
    }

    let mut carry: u128 = 0;
    let mut normalized = [0u64; N];
    for j in 0..N {
        let p = (j + off) & idx_mask;
        let v = acc[p] + carry;
        normalized[j] = (v & MASK52 as u128) as u64;
        carry = v >> LIMB52_BITS;
    }
    debug_assert!(carry <= 1);
    conditional_subtract(&normalized, m, carry as u64)
}

// ---------------------------------------------------------------------------
// Radix 2^64 references.
// ---------------------------------------------------------------------------

/// Fixed-width CIOS at radix 2^64: the incumbent's algorithm over fixed-size
/// arrays, so no slice bounds check participates in the comparison.
///
/// `acc` has at least `N + 2` slots (the incumbent's `n + 2` accumulator).
pub fn mont_mul_64_fixed<const N: usize, const L: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    n0: u64,
    acc: &mut [u64; L],
) -> [u64; N] {
    debug_assert!(L >= N + 2);
    for j in 0..N {
        acc[j] = 0;
    }
    acc[N] = 0;
    acc[N + 1] = 0;

    for i in 0..N {
        let bi = b[i];
        let mut carry = 0u64;
        for j in 0..N {
            let v = mul_add_carry(a[j], bi, acc[j], carry);
            acc[j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (hi, overflow) = acc[N].overflowing_add(carry);
        acc[N] = hi;
        acc[N + 1] = u64::from(overflow);

        let u = acc[0].wrapping_mul(n0);
        let v = mul_add_carry(u, m[0], acc[0], 0);
        let mut carry2 = (v >> 64) as u64;
        for j in 1..N {
            let v = mul_add_carry(u, m[j], acc[j], carry2);
            acc[j - 1] = v as u64;
            carry2 = (v >> 64) as u64;
        }
        let (lo, overflow) = acc[N].overflowing_add(carry2);
        acc[N - 1] = lo;
        acc[N] = acc[N + 1].wrapping_add(u64::from(overflow));
    }

    let high = acc[N];
    let mut borrow = 0u64;
    let mut diff = [0u64; N];
    for j in 0..N {
        let (d1, b1) = acc[j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    let mut out = [0u64; N];
    for j in 0..N {
        out[j] = (diff[j] & mask) | (acc[j] & !mask);
    }
    out
}

/// **Transcription** of the crate's `mont_mul_cios_into`
/// (`src/bn/arith.rs:1855-1918`), over dynamically sized slices exactly as the
/// incumbent is written, including its geometry check.
///
/// This is the reference the arm is asked for, but it is a transcription, not
/// the crate's code linked into this binary: the crate kernel is `pub(crate)`
/// and cannot be reached from a standalone crate without exposing internals.
/// Its absolute numbers therefore do not transfer to the DSO; the *shape* of
/// the algorithm is faithful, and [`mont_mul_64_fixed`] provides the same
/// algorithm without slice overhead for the primary comparison.
///
/// Returns `false` on a geometry violation (the incumbent's fail-closed check).
pub fn mont_mul_64_slice(
    a: &[u64],
    b: &[u64],
    out: &mut [u64],
    m: &[u64],
    n0: u64,
    t: &mut [u64],
    diff: &mut [u64],
) -> bool {
    let n = m.len();
    let Some(t_needed) = n.checked_mul(2).and_then(|w| w.checked_add(1)) else {
        return false;
    };
    if !(a.len() == n && b.len() == n && out.len() == n && diff.len() == n && t.len() == t_needed) {
        return false;
    }
    if n == 0 {
        return true;
    }
    let acc = &mut t[..=n + 1];
    acc.fill(0);

    for &bi in b {
        let mut carry = 0u64;
        for j in 0..n {
            let v = mul_add_carry(a[j], bi, acc[j], carry);
            acc[j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (hi, overflow) = acc[n].overflowing_add(carry);
        acc[n] = hi;
        acc[n + 1] = u64::from(overflow);

        let u = acc[0].wrapping_mul(n0);
        let v = mul_add_carry(u, m[0], acc[0], 0);
        let mut carry = (v >> 64) as u64;
        for j in 1..n {
            let v = mul_add_carry(u, m[j], acc[j], carry);
            acc[j - 1] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (lo, overflow) = acc[n].overflowing_add(carry);
        acc[n - 1] = lo;
        acc[n] = acc[n + 1].wrapping_add(u64::from(overflow));
    }

    let high = acc[n];
    let mut borrow = 0u64;
    for j in 0..n {
        let (d1, b1) = acc[j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    for j in 0..n {
        out[j] = constant_time_select(mask as usize, diff[j] as usize, acc[j] as usize) as u64;
    }
    true
}

// ---------------------------------------------------------------------------
// Independent big-integer oracle: plain multiply, then plain reduction.
// ---------------------------------------------------------------------------

/// Little-endian `u64` limb big integer helpers. Deliberately simple: no
/// Montgomery, no window, no carry tricks. Used only for verification.
pub mod big {
    use core::cmp::Ordering;

    /// Strip leading zero limbs.
    pub fn trim(a: &[u64]) -> &[u64] {
        let mut n = a.len();
        while n > 0 && a[n - 1] == 0 {
            n -= 1;
        }
        &a[..n]
    }

    pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
        let a = trim(a);
        let b = trim(b);
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for i in (0..a.len()).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        Ordering::Equal
    }

    pub fn is_zero(a: &[u64]) -> bool {
        trim(a).is_empty()
    }

    /// `a * b`, schoolbook, exact.
    pub fn mul(a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = vec![0u64; a.len() + b.len()];
        for i in 0..a.len() {
            let mut carry = 0u64;
            for j in 0..b.len() {
                let v = (a[i] as u128) * (b[j] as u128) + out[i + j] as u128 + carry as u128;
                out[i + j] = v as u64;
                carry = (v >> 64) as u64;
            }
            let mut k = i + b.len();
            while carry != 0 {
                let v = out[k] as u128 + carry as u128;
                out[k] = v as u64;
                carry = (v >> 64) as u64;
                k += 1;
            }
        }
        out
    }

    /// `r = 2r + bit (mod m)`, for `r < m`. One conditional subtraction suffices
    /// because `2r + bit < 2m`.
    fn double_add_mod(r: &mut [u64], bit: u64, m: &[u64]) {
        let mut carry = bit;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        let ge = carry == 1 || cmp(r, m) != Ordering::Less;
        if ge {
            let mut borrow = 0u64;
            for j in 0..r.len() {
                let (d1, b1) = r[j].overflowing_sub(m[j]);
                let (d2, b2) = d1.overflowing_sub(borrow);
                r[j] = d2;
                borrow = u64::from(b1) | u64::from(b2);
            }
        }
    }

    /// `x mod m` by binary long division, one bit at a time. Simple on purpose.
    pub fn rem(x: &[u64], m: &[u64]) -> Vec<u64> {
        let mut r = vec![0u64; m.len()];
        for i in (0..x.len() * 64).rev() {
            let bit = (x[i / 64] >> (i % 64)) & 1;
            double_add_mod(&mut r, bit, m);
        }
        r
    }

    /// `x * y mod m`, via [`mul`] and [`rem`] only.
    pub fn modmul(x: &[u64], y: &[u64], m: &[u64]) -> Vec<u64> {
        rem(&mul(x, y), m)
    }

    /// `2^k mod m`.
    pub fn pow2_mod(k: u32, m: &[u64]) -> Vec<u64> {
        let mut r = vec![0u64; m.len()];
        r[0] = 1;
        for _ in 0..k {
            double_add_mod(&mut r, 0, m);
        }
        r
    }

    /// `(m >> 1) + 1`, which is `2^-1 mod m` for odd `m`.
    pub fn inv_of_two(m: &[u64]) -> Vec<u64> {
        let mut out = vec![0u64; m.len()];
        let mut carry = 0u64;
        for i in (0..m.len()).rev() {
            let next = m[i] & 1;
            out[i] = (m[i] >> 1) | (carry << 63);
            carry = next;
        }
        let mut c = 1u64;
        for limb in out.iter_mut() {
            let (v, o) = limb.overflowing_add(c);
            *limb = v;
            c = u64::from(o);
            if c == 0 {
                break;
            }
        }
        out
    }

    /// `base^exp mod m`, square and multiply.
    pub fn pow_mod(base: &[u64], exp: u64, m: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; m.len()];
        result[0] = 1;
        let mut b = base.to_vec();
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = modmul(&result, &b, m);
            }
            e >>= 1;
            if e > 0 {
                b = modmul(&b, &b, m);
            }
        }
        result
    }
}

/// `R^-1 mod m` for `R = 2^k`, computed as `(2^-1)^k mod m` — independent of
/// any Montgomery reduction.
pub fn r_inv(k: u32, m: &[u64]) -> Vec<u64> {
    big::pow_mod(&big::inv_of_two(m), k as u64, m)
}

/// The independent oracle for Montgomery multiplication:
/// `a * b * R^-1 mod m` as `(a*b mod m) * R^-1 mod m`, with only schoolbook
/// multiplication and binary long division.
pub fn mont_oracle(a: &[u64], b: &[u64], m: &[u64], r_inv: &[u64]) -> Vec<u64> {
    let ab = big::modmul(a, b, m);
    big::modmul(&ab, r_inv, m)
}

// ---------------------------------------------------------------------------
// Radix repacking (verification only; never timed).
// ---------------------------------------------------------------------------

/// Repack `src` (limbs of `src_bits` bits) into `dst` (limbs of `dst_bits`
/// bits), little-endian, little-end-first. Bits above `dst.len()*dst_bits` are
/// not representable and are not produced; callers size `dst` from the value's
/// true bit width.
pub fn repack(src: &[u64], src_bits: u32, dst: &mut [u64], dst_bits: u32) {
    let mask: u128 = if dst_bits >= 64 {
        u64::MAX as u128
    } else {
        (1u128 << dst_bits) - 1
    };
    let mut acc: u128 = 0;
    let mut nbits: u32 = 0;
    let mut di = 0usize;
    for &limb in src {
        acc |= (limb as u128) << nbits;
        nbits += src_bits;
        while nbits >= dst_bits && di < dst.len() {
            dst[di] = (acc & mask) as u64;
            acc >>= dst_bits;
            nbits -= dst_bits;
            di += 1;
        }
        if di >= dst.len() {
            break;
        }
    }
    let mut written = di;
    if nbits > 0 && di < dst.len() {
        dst[di] = (acc & mask) as u64;
        written = di + 1;
    }
    for slot in dst.iter_mut().skip(written) {
        *slot = 0;
    }
}

/// Repack into a fixed-size array.
pub fn repack_fixed<const M: usize>(src: &[u64], src_bits: u32, dst_bits: u32) -> [u64; M] {
    let mut out = [0u64; M];
    repack(src, src_bits, &mut out, dst_bits);
    out
}

/// The value of `src` (limbs of `src_bits`) as the shortest little-endian
/// `u64` vector that can hold every bit of the representation.
pub fn value_vec(src: &[u64], src_bits: u32) -> Vec<u64> {
    let bits = (src.len() as u32) * src_bits;
    let words = bits.div_ceil(64) as usize;
    let mut out = vec![0u64; words];
    repack(src, src_bits, &mut out, 64);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n0_is_the_negated_inverse() {
        for &m0 in &[1u64, 3, 5, 0xffff_ffff_ffff_ffff, 0x000f_ffff_ffff_ffff] {
            let inv64 = 0u64.wrapping_sub(n0_64(m0));
            assert_eq!(m0.wrapping_mul(inv64), 1);
            let inv52 = 0u64.wrapping_sub(n0_52(m0)) & MASK52;
            assert_eq!((m0 & MASK52).wrapping_mul(inv52) & MASK52, 1);
        }
    }

    fn check_small<const N: usize, const L: usize>(m: [u64; N], a: [u64; N], b: [u64; N]) {
        // Convert to 64-bit limbs for the oracle (value is tiny, so exact).
        let m64 = value_vec(&m, LIMB52_BITS);
        let a64 = value_vec(&a, LIMB52_BITS);
        let b64 = value_vec(&b, LIMB52_BITS);
        let k = 52 * N as u32;
        let rinv = r_inv(k, &m64);
        let expect = mont_oracle(&a64, &b64, &m64, &rinv);

        let mut acc = [0u128; N];
        let got = mont_mul_52_deferred(&a, &b, &m, n0_52(m[0]), &mut acc);
        assert_eq!(
            big::cmp(&value_vec(&got, LIMB52_BITS), &expect),
            core::cmp::Ordering::Equal
        );

        let mut rot = [0u128; L];
        let got_rot = mont_mul_52_rotate(&a, &b, &m, n0_52(m[0]), &mut rot);
        assert_eq!(got, got_rot);
    }

    #[test]
    fn radix52_matches_the_oracle_on_small_widths() {
        // N = 2, B = 2^52: modulus < 2^104, odd, top limb nonzero.
        // m = 3*B + 1, so every operand below 3*B is a valid input.
        let m = [1u64, 0x0000_0000_0000_0003];
        let cases = [
            ([0, 0], [0, 0]),
            ([1, 0], [1, 0]),
            ([MASK52, 2], [7, 1]),
            ([0x1234_5678_9abc, 0x0001], [0x0fed_cba9_8765, 0x0002]),
            ([MASK52, 2], [MASK52, 2]),
            ([MASK52, 2], [2, 0]),
        ];
        for (a, b) in cases {
            check_small::<2, 2>(m, a, b);
        }
    }

    #[test]
    fn conditional_subtraction_uses_base_2_52_digits() {
        // m = 1 (limb 0 = 1), x = B (value 2^52). The low limb underflows, so
        // the borrow must produce the base-2^52 digit 2^52 - 1, not 2^64 - 1.
        let x = [0u64, 1];
        let m = [1u64, 0];
        assert_eq!(conditional_subtract(&x, &m, 0), [MASK52, 0]);
        // high = 1 represents x + 2^104; with m = B + 1 that is
        // 2^104 + B - (B + 1) = 2^104 - 1, i.e. both digits all ones.
        assert_eq!(conditional_subtract(&x, &[1u64, 1], 1), [MASK52, MASK52]);
    }

    #[test]
    fn radix64_fixed_and_slice_agree() {
        let m = [
            0xffff_ffff_ffff_fffd,
            0x1234_5678_9abc_def1,
            0x0000_0000_0000_0002,
        ];
        let n0 = n0_64(m[0]);
        let cases = [
            ([0u64, 0, 0], [0u64, 0, 0]),
            ([1, 0, 0], [1, 0, 0]),
            ([0xdead_beef, 0x1234, 0x1], [0xfeed_face, 0x4321, 0x1]),
        ];
        for (a, b) in cases {
            let mut acc = [0u64; 5];
            let fixed = mont_mul_64_fixed::<3, 5>(&a, &b, &m, n0, &mut acc);
            let mut out = [0u64; 3];
            let mut t = [0u64; 7];
            let mut diff = [0u64; 3];
            assert!(mont_mul_64_slice(
                &a, &b, &mut out, &m, n0, &mut t, &mut diff
            ));
            assert_eq!(fixed, out);
        }
    }
}
