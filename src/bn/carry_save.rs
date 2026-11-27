//! M-A7 — carry-save (redundant-accumulator) CIOS Montgomery multiplication.
//!
//! This is a **research and measurement prototype**, not a production path. It is
//! not called by any arithmetic code; the module-level `dead_code` allowance in
//! [`crate::bn`] states that honestly and disappears if a crossover ever earns
//! admission. The bound, prediction and refusal permission are in
//! `evidence/performance-frontier/campaigns/M-A7/BOUNDS.md`.
//!
//! ## What it changes, and what it does not
//!
//! Radix, limb count, the CIOS schedule, the number of limb products (`2n^2`) and
//! the final masked conditional subtraction are **unchanged** from
//! [`crate::bn::arith`]'s fixed-width CIOS kernel. The only change is *when*
//! carries are propagated: instead of one `adc` chain threading through every
//! accumulator word of a row, the accumulator is held as a redundant pair
//!
//! ```text
//!     V = sum_p (s[p] + c[p]) * B^(p - off),      B = 2^64
//! ```
//!
//! Both rows of an iteration — the product row `a * b_i` and the reduction row
//! `u * m` — are accumulated in a **single descending pass**. The reduction
//! constant `u` is available before that pass because the base column after the
//! product row depends only on `s[0]`, `c[0]` and `a[0] * b_i`. At position `p`
//! (logical column `j = p - off`):
//!
//! ```text
//!     z_p = s[p] + c[p] + lo_a[j] + hi_a[j-1] + lo_b[j] + hi_b[j-1]
//!     s'[p] = z_p mod B          c'[p+1] = z_p / B
//! ```
//!
//! `s[p]` and `c[p]` are the *previous* pass's outputs, each product word comes
//! from an independent multiply, and `c'[p+1]` is read only by the **next** pass.
//! Descending order guarantees read-before-overwrite in place. Position `off`'s
//! carry is absorbed into `z_off` and then cleared, so the pair stays exact; the
//! shift to the next base is the loop index itself, with the carry out of the
//! dropped column carried in `c[off]`.
//!
//! ## Invariant (inherited from CIOS, not re-derived)
//!
//! The pair represents exactly the value the admitted CIOS kernel's accumulator
//! holds after the same operations in the same order. Reusing its invariant
//! argument: for `n`-limb inputs the accumulator stays below `B^(n+1)` after every
//! iteration, so the `2n + 2` scratch words can never lose a carry, and the same
//! single masked subtraction produces the same residue. For canonical inputs
//! (`a, b < m`) that residue is below `m`; the differential additionally compares
//! non-canonical `n`-limb inputs against CIOS directly.
//!
//! ## Constant-time discipline
//!
//! All loop bounds are compile-time (`N`) or fixed (`N + 2` positions). There is
//! no branch on a limb value, no index derived from a limb, and no early exit.
//! The only early returns are on **public** geometry (scratch too short) and the
//! **public** modulus parity (Montgomery reduction is undefined for an even
//! modulus, mirroring the caller's admission rule). Every 128-bit sum uses
//! `wrapping_*`: the maximum is `6 * (2^64 - 1)`, so no wrap is possible, and the
//! release profile's overflow check — whose condition depends on secret limbs —
//! stays out of the loop, exactly as `mul_add_carry` states in `arith.rs`.
//!
//! ## Zero unsafe
//!
//! The module contains no `unsafe`, no intrinsics and no assembly. Because safe
//! Rust cannot issue the volatile stores an authoritative cleanse requires, the
//! convenience wrappers clear their stack scratch and hand it to
//! [`core::hint::black_box`] so the wipe is not elided; that is *best effort*, and
//! integration would have to pass [`crate::runtime::secret::SecretBuf`] scratch
//! (whose `Drop` performs the audited volatile cleanse) instead. This residual is
//! recorded in the receipt.

#![allow(clippy::needless_range_loop)]

/// Clear a word buffer and keep the writes observable to the optimiser.
///
/// Safe Rust cannot emit volatile stores; `black_box` is the strongest
/// guarantee it offers. The residual (integration must use the audited
/// volatile cleanse through `runtime::secret::SecretBuf`) is recorded in
/// `RECEIPT.md`.
#[inline]
fn zeroize_words(words: &mut [u64]) {
    for w in words.iter_mut() {
        *w = 0;
    }
    core::hint::black_box(words);
}

/// Redundant-accumulator CIOS multiplication over `N` limbs.
///
/// `s` and `c` are caller-provided scratch of at least `L >= 2N + 2` words; the
/// wrappers below supply local buffers. Returns `None` for an even modulus or a
/// scratch length that is too short (both public), writing nothing in that case.
///
/// The returned limbs are `a * b * R^-1 mod m` under the same input bound as the
/// CIOS kernel (`a * b < m * R` for a canonical residue); the bound is not
/// checked at run time because the kernel it replaces does not check it either.
#[inline]
pub(crate) fn mont_mul_cs_core<const N: usize, const L: usize>(
    a: &[u64; N],
    b: &[u64; N],
    m: &[u64; N],
    n0: u64,
    s: &mut [u64; L],
    c: &mut [u64; L],
) -> Option<[u64; N]> {
    if N == 0 || L < 2 * N + 2 {
        return None;
    }
    if m[0] & 1 == 0 {
        // Montgomery reduction needs an odd modulus; the admitted caller rejects
        // an even one before reaching the kernel. Public data.
        return None;
    }
    s.fill(0);
    c.fill(0);

    let mut lo_a = [0u64; N];
    let mut hi_a = [0u64; N];
    let mut lo_b = [0u64; N];
    let mut hi_b = [0u64; N];

    for i in 0..N {
        // Product row words: a * b[i].
        let bi = b[i];
        for j in 0..N {
            let p = (a[j] as u128).wrapping_mul(bi as u128);
            lo_a[j] = p as u64;
            hi_a[j] = (p >> 64) as u64;
        }

        // Reduction constant. The base column after the product row is
        // `s[i] + c[i] + lo_a[0]`; `u = column * n0 mod B` annihilates it.
        let u = s[i]
            .wrapping_add(c[i])
            .wrapping_add(lo_a[0])
            .wrapping_mul(n0);
        for j in 0..N {
            let p = (u as u128).wrapping_mul(m[j] as u128);
            lo_b[j] = p as u64;
            hi_b[j] = (p >> 64) as u64;
        }

        // One descending pass for both rows. No position reads a value written
        // earlier in this pass: `s`/`c` are the previous pass's outputs and the
        // product words are independent multiplies.
        for j in (0..=N + 1).rev() {
            let p = i + j;
            let loa = if j < N { lo_a[j] } else { 0 };
            let hia = if j >= 1 && j <= N { hi_a[j - 1] } else { 0 };
            let lob = if j < N { lo_b[j] } else { 0 };
            let hib = if j >= 1 && j <= N { hi_b[j - 1] } else { 0 };
            let z = (s[p] as u128)
                .wrapping_add(c[p] as u128)
                .wrapping_add(loa as u128)
                .wrapping_add(hia as u128)
                .wrapping_add(lob as u128)
                .wrapping_add(hib as u128);
            s[p] = z as u64;
            c[p + 1] = (z >> 64) as u64;
        }
        // The base column's carry has been absorbed into `z_i` above; leaving it
        // set would double-count it in the represented value.
        c[i] = 0;
    }

    // Single propagation pass. The base is now `N`; the accumulator bound makes
    // the value fit in limbs `0..=N`, so scratch words above `2N` are zero.
    let mut acc = [0u64; N];
    let mut carry = 0u64;
    for j in 0..N {
        let p = N + j;
        let z = (s[p] as u128)
            .wrapping_add(c[p] as u128)
            .wrapping_add(carry as u128);
        acc[j] = z as u64;
        carry = (z >> 64) as u64;
    }
    let z = (s[2 * N] as u128)
        .wrapping_add(c[2 * N] as u128)
        .wrapping_add(carry as u128);
    let high = z as u64;

    Some(conditional_subtract(&acc, high, m))
}

/// The admitted kernel's single masked conditional subtraction, transcribed
/// (mask select, no branch).
#[inline]
fn conditional_subtract<const N: usize>(acc: &[u64; N], high: u64, m: &[u64; N]) -> [u64; N] {
    let mut diff = [0u64; N];
    let mut borrow = 0u64;
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
        out[j] = (acc[j] & !mask) | (diff[j] & mask);
    }
    out
}

macro_rules! impl_cs_width {
    ($name:ident, $n:literal, $len:literal) => {
        /// Carry-save CIOS at a fixed limb count; `$n` limbs, `$len` scratch
        /// words. See [`mont_mul_cs_core`] for the contract.
        #[inline]
        pub(crate) fn $name(
            a: &[u64; $n],
            b: &[u64; $n],
            m: &[u64; $n],
            n0: u64,
        ) -> Option<[u64; $n]> {
            let mut s = [0u64; $len];
            let mut c = [0u64; $len];
            let out = mont_mul_cs_core::<$n, $len>(a, b, m, n0, &mut s, &mut c);
            zeroize_words(&mut s);
            zeroize_words(&mut c);
            out
        }
    };
}

impl_cs_width!(mont_mul_cs_4, 4, 10);
impl_cs_width!(mont_mul_cs_16, 16, 34);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bn::arith::{mont_mul_fallible, mont_mul_fallible_with, MontSchedule};
    use crate::bn::limbs;

    type Kernel<const N: usize> = fn(&[u64; N], &[u64; N], &[u64; N], u64) -> Option<[u64; N]>;

    /// `-m^-1 mod 2^64` for odd `m`, the same Newton recurrence the admitted
    /// kernel uses (`arith::mont_n0`, which is private to that module).
    fn n0_for(m0: u64) -> u64 {
        let mut inv = m0;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        inv.wrapping_neg()
    }

    fn array<const N: usize>(v: &[u64]) -> [u64; N] {
        let mut out = [0u64; N];
        let take = v.len().min(N);
        out[..take].copy_from_slice(&v[..take]);
        out
    }

    fn cios<const N: usize>(a: &[u64; N], b: &[u64; N], m: &[u64; N], n0: u64) -> [u64; N] {
        array::<N>(
            &mont_mul_fallible_with(MontSchedule::Cios, a, b, m, n0)
                .expect("the CIOS reference allocates"),
        )
    }

    /// Deterministic per-modulus operand population: canonical edges, the
    /// campaign's corners and a pseudo-random sweep reduced into `[0, m)`.
    fn population<const N: usize>(m: &[u64; N], m_vec: &[u64]) -> Vec<[u64; N]> {
        let mut values: Vec<[u64; N]> = Vec::new();
        values.push(array::<N>(&[]));
        values.push(array::<N>(&[1, 2, 3]));
        values.push(array::<N>(&[u64::MAX]));
        let mut top_only = [0u64; N];
        top_only[N - 1] = 1;
        values.push(top_only);
        let mut top_full = [0u64; N];
        top_full[N - 1] = u64::MAX;
        values.push(top_full);
        values.push(array::<N>(&limbs::sub(m_vec, &[1])));
        values.push(array::<N>(&limbs::sub(m_vec, &[2])));
        values.push(array::<N>(&limbs::div_rem_small(m_vec, 2).0));
        values.push([u64::MAX; N]);
        values.push(*m);

        let mut state = {
            let mut s = 0x9e37_79b9_7f4a_7c15u64;
            for &l in m.iter() {
                s ^= l;
                s = s.wrapping_mul(0x100_0000_01b3);
            }
            s | 1
        };
        let mut xorshift = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..40 {
            let raw: Vec<u64> = (0..N).map(|_| xorshift()).collect();
            values.push(array::<N>(&limbs::rem(&raw, m_vec)));
        }
        values
    }

    /// Differential at one width. Canonical operands are checked against **both**
    /// CIOS and the independent SOS reference (which must agree with each other);
    /// non-canonical `n`-limb operands are checked against CIOS, since outside
    /// `a, b < m` neither kernel promises canonicality but they must still agree.
    fn run_width<const N: usize>(kernel: Kernel<N>, moduli: &[[u64; N]]) -> (usize, usize, usize) {
        let mut canonical = 0usize;
        let mut noncanonical = 0usize;
        let mut even_refused = 0usize;
        for m in moduli {
            if m[0] & 1 == 0 {
                assert_eq!(
                    kernel(&[0u64; N], &[0u64; N], m, 0),
                    None,
                    "carry-save accepted an even modulus"
                );
                even_refused += 1;
                continue;
            }
            let n0 = n0_for(m[0]);
            let m_vec = m.to_vec();

            let all = population(m, &m_vec);
            let canon: Vec<[u64; N]> = all
                .iter()
                .copied()
                .filter(|v| limbs::cmp(v, m) == core::cmp::Ordering::Less)
                .collect();
            let mut noncanon: Vec<[u64; N]> = all
                .iter()
                .copied()
                .filter(|v| limbs::cmp(v, m) != core::cmp::Ordering::Less)
                .collect();
            noncanon.push(array::<N>(&limbs::add(&m_vec, &[1])));
            noncanon.push(array::<N>(&limbs::add(&m_vec, &[2])));

            for a in &canon {
                for b in &canon {
                    let expected = cios::<N>(a, b, m, n0);
                    let sos = array::<N>(
                        &mont_mul_fallible(a, b, m, n0).expect("the SOS reference allocates"),
                    );
                    assert_eq!(
                        expected, sos,
                        "CIOS and SOS disagree at N={N}: a={a:?} b={b:?} m={m:?}"
                    );
                    let got = kernel(a, b, m, n0).expect("carry-save accepts an odd modulus");
                    assert_eq!(
                        got, expected,
                        "M-A7 mismatch at N={N}: a={a:?} b={b:?} m={m:?}"
                    );
                    canonical += 1;
                }
            }
            for a in &noncanon {
                for b in &canon {
                    let expected = cios::<N>(a, b, m, n0);
                    let got = kernel(a, b, m, n0).expect("carry-save accepts an odd modulus");
                    assert_eq!(
                        got, expected,
                        "M-A7 non-canonical mismatch at N={N}: a={a:?} b={b:?} m={m:?}"
                    );
                    noncanonical += 1;
                }
            }
        }
        (canonical, noncanonical, even_refused)
    }

    fn moduli4() -> Vec<[u64; 4]> {
        vec![
            // P-256 p, little-endian.
            [
                0xffff_ffff_ffff_ffff,
                0x0000_0000_ffff_ffff,
                0,
                0xffff_ffff_0000_0001,
            ],
            // P-256 order n.
            [
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff,
                0xbce6_faad_a717_9e84,
            ],
            // b^3 + 1: minimal top occupancy.
            [1, 0, 0, 1],
            // Odd all-ones.
            [u64::MAX; 4],
            // Mixed occupancy with the top limb set.
            [
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3211,
                0x0f0f_0f0f_0f0f_0f0f,
                0x8000_0000_0000_0001,
            ],
        ]
    }

    fn moduli16() -> Vec<[u64; 16]> {
        // A deterministic odd 1024-bit modulus with mixed occupancy.
        let mut m = [0x9e37_79b9_7f4a_7c15u64; 16];
        let mut state = 0x0123_4567_89ab_cdefu64;
        for (i, limb) in m.iter_mut().enumerate() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *limb = state ^ (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        m[0] |= 1;
        m[15] |= 1 << 63;

        // Minimal top occupancy: m = 2^960 + 1.
        let mut minimal = [0u64; 16];
        minimal[0] = 1;
        minimal[15] = 1;

        // A nearly-full top limb (P-1024-like pattern, odd).
        let mut full = [0u64; 16];
        for (i, limb) in full.iter_mut().enumerate() {
            *limb = match i % 4 {
                0 => 0xffff_ffff_ffff_ffff,
                1 => 0x0000_0000_ffff_ffff,
                2 => 0,
                _ => 0xffff_ffff_0000_0001,
            };
        }

        vec![m, minimal, full]
    }

    #[test]
    fn ma7_matches_cios_and_sos_at_4_limbs() {
        let (cases, edges, even) = run_width::<4>(mont_mul_cs_4, &moduli4());
        assert!(cases > 0 && edges > 0);
        eprintln!(
            "M-A7 4-limb differential: {cases} canonical, {edges} non-canonical, \
             {even} even-modulus refusals, mismatches=0"
        );
    }

    #[test]
    fn ma7_matches_cios_and_sos_at_16_limbs() {
        let (cases, edges, even) = run_width::<16>(mont_mul_cs_16, &moduli16());
        assert!(cases > 0 && edges > 0);
        eprintln!(
            "M-A7 16-limb differential: {cases} canonical, {edges} non-canonical, \
             {even} even-modulus refusals, mismatches=0"
        );
    }

    /// `m = 1`: carry-save must match CIOS on every `n`-limb operand. Only the
    /// canonical case (`a = b = 0`) can be asserted zero: the kernels perform one
    /// conditional subtraction, so a non-canonical operand can leave a congruent
    /// non-zero representative, and *that* agreement is the differential's job.
    #[test]
    fn ma7_modulus_one() {
        let m = [1u64, 0, 0, 0];
        let n0 = n0_for(1);
        for a in [[0u64, 0, 0, 0], [1, 0, 0, 0], [5, 7, 9, 11], [u64::MAX; 4]] {
            for b in [[0u64, 0, 0, 0], [1, 0, 0, 0], [2, 0, 0, 0]] {
                let expected = cios::<4>(&a, &b, &m, n0);
                let got = mont_mul_cs_4(&a, &b, &m, n0).expect("odd modulus");
                assert_eq!(got, expected, "m=1 mismatch: a={a:?} b={b:?}");
                if a == [0, 0, 0, 0] && b == [0, 0, 0, 0] {
                    assert_eq!(got, [0, 0, 0, 0]);
                }
            }
        }
    }

    /// Even moduli are refused by the prototype, matching the caller's admission
    /// rule (Montgomery reduction is undefined for an even modulus).
    #[test]
    fn ma7_rejects_even_modulus() {
        let a = [1u64, 2, 3, 4];
        let b = [5u64, 6, 7, 8];
        for m in [
            [2u64, 0, 0, 0],
            [0, 1, 0, 0],
            [0xffff_ffff_ffff_fffe, 1, 2, 3],
        ] {
            assert_eq!(mont_mul_cs_4(&a, &b, &m, 0), None);
        }
    }

    /// The core must refuse scratch shorter than `2N + 2` rather than index out
    /// of bounds.
    #[test]
    fn ma7_rejects_short_scratch() {
        let a = [1u64, 2, 3, 4];
        let m = [3u64, 0, 0, 0];
        let mut s = [0u64; 8];
        let mut c = [0u64; 8];
        assert_eq!(
            mont_mul_cs_core::<4, 8>(&a, &a, &m, 1, &mut s, &mut c),
            None
        );
    }
}
