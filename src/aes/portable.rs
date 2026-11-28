//! A constant-pattern portable AES for the non-AES-NI arm.
//!
//! The authority's portable arm (`crypto/aes/aes_core.c`) and this crate's earlier
//! transcription both index an S-box table by secret state. That is the
//! table-looking AES a cache-timing observer recovers, and it is what runs on a CPU
//! without the `aes` target feature. This module replaces every such access with a
//! first-party Boolean construction. The shipped arm is the published
//! Boyar–Peralta–Calik 113-gate forward S-box netlist (and its published inverse)
//! evaluated over a fixed-slice state that stays in that representation across all
//! rounds; the round key is the exported schedule converted to the fixed-slice
//! layout per block. No load or branch is selected by a key or message byte.
//!
//! The PFP-63 bitsliced field-exponentiation circuit (`x^254`) and a planar
//! Boyar–Peralta driver are retained as `#[cfg(test)]` measurement baselines; they
//! are not dispatched. The fixed-slice form was selected by measurement in PFP-70
//! (`evidence/performance-frontier/campaigns/PFP-70/`).
//!
//! ## What is preserved
//!
//! `AES_set_encrypt_key`/`AES_set_decrypt_key` export the schedule, so this module
//! reproduces the authority's exact recurrence and round constants. The words it
//! returns are the *logical* big-endian `GETU32` words; `aes.rs` byte-swaps them into
//! the authority's perlasm memory order exactly as before, so the exported bytes are
//! unchanged. The fixed-slice round keys are derived from those exported words
//! inside `encrypt_block`/`decrypt_block`; the exported `AES_KEY` never changes
//! representation.
//!
//! ## Safety
//!
//! This module contains no `unsafe` code; `#![forbid(unsafe_code)]` makes that
//! machine-checked. The pointer and aliasing obligations of the exported ABI stay in
//! `aes.rs`, where they already were.
//!
//! SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use core::ffi::c_int;

use crate::digest::tables::AES_RCON;

/// GF(2^8) multiplication by `x` (the polynomial `0x02`).
///
/// Branch-free: the reduction constant is selected by an all-zero/all-one mask
/// derived arithmetically from the high bit, never by a conditional transfer.
#[inline]
fn xtime(a: u8) -> u8 {
    let reduce = 0u8.wrapping_sub(a >> 7);
    (a << 1) ^ (0x1b & reduce)
}

/// `0x00` when bit `i` is clear, `0xff` when it is set.
#[inline]
fn bit_mask(a: u8, i: u32) -> u8 {
    0u8.wrapping_sub((a >> i) & 1)
}

/// Squaring in GF(2^8) with the AES polynomial `x^8 + x^4 + x^3 + x + 1`.
///
/// Squaring is GF(2)-linear, so it is a fixed XOR network. The masks are the
/// reductions of `x^{2i}` for `i = 0..8`: `x^0, x^2, x^4, x^6, x^8, x^10, x^12,
/// x^14`. No table and no data-dependent index.
#[inline]
fn gf8_square(a: u8) -> u8 {
    const MASKS: [u8; 8] = [0x01, 0x04, 0x10, 0x40, 0x1b, 0x6c, 0xab, 0x9a];
    let mut r = 0u8;
    let mut i = 0u32;
    while i < 8 {
        r ^= MASKS[i as usize] & bit_mask(a, i);
        i += 1;
    }
    r
}

/// Multiplication in GF(2^8) with the AES polynomial, fixed eight-step shift-add.
///
/// The add is masked by the selected multiplier bit rather than branched on, and the
/// reduction uses the same mask. Fixed trip count, no secret-dependent transfer.
#[inline]
fn gf8_mul(a: u8, b: u8) -> u8 {
    let mut r = 0u8;
    let mut aa = a;
    let mut bb = b;
    let mut i = 0;
    while i < 8 {
        r ^= aa & bit_mask(bb, 0);
        aa = xtime(aa);
        bb >>= 1;
        i += 1;
    }
    r
}

/// Multiplicative inverse in GF(2^8): `x^254`, with `0` mapped to `0`.
///
/// `x^254 = (x^127)^2` and `x^{2^{k+1}-1} = (x^{2^k-1})^2 * x`, so six
/// square-multiply steps plus one square reach the inverse without a table.
#[inline]
fn gf8_inv(a: u8) -> u8 {
    let mut t = a;
    let mut i = 0;
    while i < 6 {
        t = gf8_mul(gf8_square(t), a);
        i += 1;
    }
    gf8_square(t)
}

/// The AES affine transformation (including the `0x63` constant).
#[inline]
pub(crate) fn affine(t: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0u32;
    while i < 8 {
        let v = ((t >> i) & 1)
            ^ ((t >> ((i + 4) & 7)) & 1)
            ^ ((t >> ((i + 5) & 7)) & 1)
            ^ ((t >> ((i + 6) & 7)) & 1)
            ^ ((t >> ((i + 7) & 7)) & 1)
            ^ ((0x63u8 >> i) & 1);
        r |= v << i;
        i += 1;
    }
    r
}

/// The inverse affine transformation (no constant; the caller applies `0x63` first).
#[cfg(test)]
#[inline]
fn inv_affine(z: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0u32;
    while i < 8 {
        let v =
            ((z >> ((i + 7) & 7)) & 1) ^ ((z >> ((i + 5) & 7)) & 1) ^ ((z >> ((i + 2) & 7)) & 1);
        r |= v << i;
        i += 1;
    }
    r
}

/// One forward S-box evaluation on a scalar byte (used by the key schedule).
#[inline]
pub(crate) fn sbox_byte(x: u8) -> u8 {
    affine(gf8_inv(x))
}

/// One inverse S-box evaluation on a scalar byte (test reference).
#[cfg(test)]
#[inline]
pub(crate) fn inv_sbox_byte(y: u8) -> u8 {
    gf8_inv(inv_affine(y ^ 0x63))
}

/// One bitslice plane: bit `i` is one bit of state byte `i`.
#[cfg(test)]
type Plane = u16;

/// Every plane bit set, used to XOR a public constant into all sixteen lanes.
#[cfg(test)]
const ALL: Plane = Plane::MAX;

/// Transpose sixteen bytes into eight bit planes.
#[cfg(test)]
#[inline]
fn transpose(state: &[u8; 16]) -> [Plane; 8] {
    let mut p = [0u16; 8];
    let mut i = 0usize;
    while i < 16 {
        let b = state[i];
        let mut k = 0u32;
        while k < 8 {
            p[k as usize] |= ((b as Plane >> k) & 1) << i;
            k += 1;
        }
        i += 1;
    }
    p
}

/// Inverse of [`transpose`].
#[cfg(test)]
#[inline]
fn untranspose(p: &[Plane; 8]) -> [u8; 16] {
    let mut s = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        let mut b = 0u8;
        let mut k = 0u32;
        while k < 8 {
            b |= (((p[k as usize] >> i) & 1) as u8) << k;
            k += 1;
        }
        s[i] = b;
        i += 1;
    }
    s
}

/// Bitsliced `x`-multiplication in GF(2^8).
#[cfg(test)]
#[inline]
fn xtime_planes(a: &[Plane; 8]) -> [Plane; 8] {
    [
        a[7],
        a[0] ^ a[7],
        a[1],
        a[2] ^ a[7],
        a[3] ^ a[7],
        a[4],
        a[5],
        a[6],
    ]
}

/// Bitsliced squaring; the same fixed XOR network as [`gf8_square`].
#[cfg(test)]
#[inline]
fn square_planes(a: &[Plane; 8]) -> [Plane; 8] {
    [
        a[0] ^ a[4] ^ a[6],
        a[4] ^ a[6] ^ a[7],
        a[1] ^ a[5],
        a[4] ^ a[5] ^ a[6] ^ a[7],
        a[2] ^ a[4] ^ a[7],
        a[5] ^ a[6],
        a[3] ^ a[5],
        a[6] ^ a[7],
    ]
}

/// Bitsliced GF(2^8) multiplication, eight fixed steps over the plane vector.
#[cfg(test)]
#[inline]
fn mul_planes(a: &[Plane; 8], b: &[Plane; 8]) -> [Plane; 8] {
    let mut r = [0u16; 8];
    let mut aa = *a;
    let mut k = 0usize;
    while k < 8 {
        let cond = b[k];
        let mut j = 0usize;
        while j < 8 {
            r[j] ^= aa[j] & cond;
            j += 1;
        }
        aa = xtime_planes(&aa);
        k += 1;
    }
    r
}

/// Bitsliced field inverse (`x^254`), the same exponentiation as [`gf8_inv`].
#[cfg(test)]
#[inline]
fn inv_planes(a: &[Plane; 8]) -> [Plane; 8] {
    let mut t = *a;
    let mut i = 0;
    while i < 6 {
        t = mul_planes(&square_planes(&t), a);
        i += 1;
    }
    square_planes(&t)
}

/// Bitsliced forward S-box: `affine(x^254)`.
#[cfg(test)]
#[inline]
fn sbox_planes(a: &[Plane; 8]) -> [Plane; 8] {
    let t = inv_planes(a);
    [
        t[0] ^ t[4] ^ t[5] ^ t[6] ^ t[7] ^ ALL,
        t[1] ^ t[5] ^ t[6] ^ t[7] ^ t[0] ^ ALL,
        t[2] ^ t[6] ^ t[7] ^ t[0] ^ t[1],
        t[3] ^ t[7] ^ t[0] ^ t[1] ^ t[2],
        t[4] ^ t[0] ^ t[1] ^ t[2] ^ t[3],
        t[5] ^ t[1] ^ t[2] ^ t[3] ^ t[4] ^ ALL,
        t[6] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ ALL,
        t[7] ^ t[3] ^ t[4] ^ t[5] ^ t[6],
    ]
}

/// Bitsliced inverse S-box: `(inv_affine(y ^ 0x63))^254`.
#[cfg(test)]
#[inline]
fn inv_sbox_planes(a: &[Plane; 8]) -> [Plane; 8] {
    let z = [
        a[0] ^ ALL,
        a[1] ^ ALL,
        a[2],
        a[3],
        a[4],
        a[5] ^ ALL,
        a[6] ^ ALL,
        a[7],
    ];
    let t = [
        z[7] ^ z[5] ^ z[2],
        z[0] ^ z[6] ^ z[3],
        z[1] ^ z[7] ^ z[4],
        z[2] ^ z[0] ^ z[5],
        z[3] ^ z[1] ^ z[6],
        z[4] ^ z[2] ^ z[7],
        z[5] ^ z[3] ^ z[0],
        z[6] ^ z[4] ^ z[1],
    ];
    inv_planes(&t)
}

// ---------------------------------------------------------------------------
// Boyar–Peralta–Calik 113-gate S-box netlist
// ---------------------------------------------------------------------------
//
// Provenance. The gate list below is the published circuit
// `SLP_AES_113.txt` (Boyar, Peralta and Calik), obtained from
// `http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt` and
// transcribed here from two independent published C/Rust renditions:
//
//   * BearSSL `crypto/aes/../src/symcipher/aes_ct.c`,
//     `br_aes_ct_bitslice_Sbox`, which cites the same netlist and the paper
//     "A new combinational logic minimization technique with applications to
//     cryptology" (https://eprint.iacr.org/2009/191.pdf);
//   * RustCrypto `aes` 0.9.4, `src/backends/fixslice/sbox.rs` (`sub_bytes` and
//     `inv_sub_bytes`), which cites `SLP_AES_113.txt` directly.
//
// The netlist is used verbatim, not reconstructed: 32 AND, 79 XOR and 4 NOT
// operations for the forward circuit as published (the four NOTs are carried
// separately, exactly as both references do). The inverse circuit is the
// published inverse netlist from the same source. Both are checked against
// the authority-derived table over all 256 inputs in this module's tests.
//
// The netlist's `state[0]` is the most-significant bit plane. Our `Plane`
// convention is least-significant first, so the wrappers below reorder at the
// boundary; the netlist body itself keeps the published indexing.

/// The forward circuit body without its four output NOTs, in published
/// indexing (`st[0]` is the high bit plane). Generic over the lane carrier so
/// the same netlist can be measured at wider lane widths; production uses
/// `u16`.
#[inline]
pub(crate) fn bp_sub_bytes<T>(st: &mut [T; 8])
where
    T: Copy + core::ops::BitAnd<Output = T> + core::ops::BitXor<Output = T>,
{
    let u7 = st[0];
    let u6 = st[1];
    let u5 = st[2];
    let u4 = st[3];
    let u3 = st[4];
    let u2 = st[5];
    let u1 = st[6];
    let u0 = st[7];

    let y14 = u3 ^ u5;
    let y13 = u0 ^ u6;
    let y12 = y13 ^ y14;
    let t1 = u4 ^ y12;
    let y15 = t1 ^ u5;
    let t2 = y12 & y15;
    let y6 = y15 ^ u7;
    let y20 = t1 ^ u1;
    let y9 = u0 ^ u3;
    let y11 = y20 ^ y9;
    let t12 = y9 & y11;
    let y7 = u7 ^ y11;
    let y8 = u0 ^ u5;
    let t0 = u1 ^ u2;
    let y10 = y15 ^ t0;
    let y17 = y10 ^ y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let y19 = y10 ^ y8;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let t7 = y13 & y16;
    let y18 = u0 ^ y16;
    let y1 = t0 ^ u7;
    let y4 = y1 ^ u3;
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t18 = t6 ^ t16;
    let t22 = t18 ^ y19;
    let y2 = y1 ^ u0;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t20 = t11 ^ t16;
    let t24 = t20 ^ y18;
    let y5 = y1 ^ u6;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t19 = t9 ^ t14;
    let t23 = t19 ^ y21;
    let y3 = y5 ^ y8;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t17 = t4 ^ y20;
    let t21 = t17 ^ t14;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t31 = t22 ^ t26;
    let t25 = t21 ^ t22;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let z14 = t29 & y2;
    let z5 = t29 & y7;
    let t30 = t23 ^ t24;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t43 = t29 ^ t40;
    let z3 = t43 & y16;
    let tc12 = z3 ^ z5;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z4 = t40 & y1;
    let tc6 = z3 ^ z4;
    let t34 = t23 ^ t33;
    let t37 = t36 ^ t34;
    let t41 = t40 ^ t37;
    let z8 = t41 & y10;
    let z17 = t41 & y8;
    let t44 = t33 ^ t37;
    let z0 = t44 & y15;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z1 = t37 & y6;
    let tc5 = z1 ^ z0;
    let tc11 = tc6 ^ tc5;
    let z11 = t33 & y4;
    let t42 = t29 ^ t33;
    let t45 = t42 ^ t41;
    let z7 = t45 & y17;
    let tc8 = z7 ^ tc6;
    let z16 = t45 & y14;
    let z6 = t42 & y11;
    let tc16 = z6 ^ tc8;
    let z15 = t42 & y9;
    let tc20 = z15 ^ tc16;
    let tc1 = z15 ^ z16;
    let tc2 = z10 ^ tc1;
    let tc21 = tc2 ^ z11;
    let tc3 = z9 ^ tc2;
    let s0 = tc3 ^ tc16;
    let s3 = tc3 ^ tc11;
    let s1 = s3 ^ tc16;
    let tc13 = z13 ^ tc1;
    let z2 = t33 & u7;
    let tc4 = z0 ^ z2;
    let tc7 = z12 ^ tc4;
    let tc9 = z8 ^ tc7;
    let tc10 = tc8 ^ tc9;
    let tc17 = z14 ^ tc10;
    let s5 = tc21 ^ tc17;
    let tc26 = tc17 ^ tc20;
    let s2 = tc26 ^ z17;
    let tc14 = tc4 ^ tc12;
    let tc18 = tc13 ^ tc14;
    let s6 = tc10 ^ tc18;
    let s7 = z12 ^ tc18;
    let s4 = tc14 ^ s3;

    st[0] = s7;
    st[1] = s6;
    st[2] = s5;
    st[3] = s4;
    st[4] = s3;
    st[5] = s2;
    st[6] = s1;
    st[7] = s0;
}

/// The published inverse circuit, in published indexing. It is the true
/// inverse of [`bp_sub_bytes`] (i.e. of the circuit without the four NOTs).
#[inline]
pub(crate) fn bp_inv_sub_bytes<T>(st: &mut [T; 8])
where
    T: Copy + core::ops::BitAnd<Output = T> + core::ops::BitXor<Output = T>,
{
    let u7 = st[0];
    let u6 = st[1];
    let u5 = st[2];
    let u4 = st[3];
    let u3 = st[4];
    let u2 = st[5];
    let u1 = st[6];
    let u0 = st[7];

    let t23 = u0 ^ u3;
    let t8 = u1 ^ t23;
    let m2 = t23 & t8;
    let t4 = u4 ^ t8;
    let t22 = u1 ^ u3;
    let t2 = u0 ^ u1;
    let t1 = u3 ^ u4;
    let t9 = u7 ^ t1;
    let m7 = t22 & t9;
    let t24 = u4 ^ u7;
    let t10 = t2 ^ t24;
    let m14 = t2 & t10;
    let r5 = u6 ^ u7;
    let t3 = t1 ^ r5;
    let t13 = t2 ^ r5;
    let t19 = t22 ^ r5;
    let t17 = u2 ^ t19;
    let t25 = u2 ^ t1;
    let r13 = u1 ^ u6;
    let t20 = t24 ^ r13;
    let m9 = t20 & t17;
    let r17 = u2 ^ u5;
    let t6 = t22 ^ r17;
    let m1 = t13 & t6;
    let y5 = u0 ^ r17;
    let m4 = t19 & y5;
    let m5 = m4 ^ m1;
    let m17 = m5 ^ t24;
    let r18 = u5 ^ u6;
    let t27 = t1 ^ r18;
    let t15 = t10 ^ t27;
    let m11 = t1 & t15;
    let m15 = m14 ^ m11;
    let m21 = m17 ^ m15;
    let m12 = t4 & t27;
    let m13 = m12 ^ m11;
    let t14 = t10 ^ r18;
    let m3 = t14 ^ m1;
    let m16 = m3 ^ m2;
    let m20 = m16 ^ m13;
    let r19 = u2 ^ u4;
    let t16 = r13 ^ r19;
    let t26 = t3 ^ t16;
    let m6 = t3 & t16;
    let m8 = t26 ^ m6;
    let m18 = m8 ^ m7;
    let m22 = m18 ^ m13;
    let m25 = m22 & m20;
    let m26 = m21 ^ m25;
    let m10 = m9 ^ m6;
    let m19 = m10 ^ m15;
    let m23 = m19 ^ t25;
    let m28 = m23 ^ m25;
    let m24 = m22 ^ m23;
    let m30 = m26 & m24;
    let m39 = m23 ^ m30;
    let m48 = m39 & y5;
    let m57 = m39 & t19;
    let m36 = m24 ^ m25;
    let m31 = m20 & m23;
    let m27 = m20 ^ m21;
    let m32 = m27 & m31;
    let m29 = m28 & m27;
    let m37 = m21 ^ m29;
    let m42 = m37 ^ m39;
    let m52 = m42 & t15;
    let m61 = m42 & t1;
    let p0 = m52 ^ m61;
    let p16 = m57 ^ m61;
    let m60 = m37 & t20;
    let m51 = m37 & t17;
    let m33 = m27 ^ m25;
    let m38 = m32 ^ m33;
    let m43 = m37 ^ m38;
    let m49 = m43 & t16;
    let p6 = m49 ^ m60;
    let p13 = m49 ^ m51;
    let m58 = m43 & t3;
    let m50 = m38 & t9;
    let m59 = m38 & t22;
    let p1 = m58 ^ m59;
    let p7 = p0 ^ p1;
    let m34 = m21 & m22;
    let m35 = m24 & m34;
    let m40 = m35 ^ m36;
    let m41 = m38 ^ m40;
    let m45 = m42 ^ m41;
    let m53 = m45 & t27;
    let p8 = m50 ^ m53;
    let p23 = p7 ^ p8;
    let m62 = m45 & t4;
    let p14 = m49 ^ m62;
    let s6 = p14 ^ p23;
    let m54 = m41 & t10;
    let p2 = m54 ^ m62;
    let p22 = p2 ^ p7;
    let s0 = p13 ^ p22;
    let p17 = m58 ^ p2;
    let p15 = m54 ^ m59;
    let m63 = m41 & t2;
    let m44 = m39 ^ m40;
    let m46 = m44 & t6;
    let p5 = m46 ^ m51;
    let p18 = m63 ^ p5;
    let p24 = p5 ^ p7;
    let p12 = m46 ^ m48;
    let s3 = p12 ^ p22;
    let m55 = m44 & t13;
    let p9 = m55 ^ m63;
    let s7 = p9 ^ p16;
    let m47 = m40 & t8;
    let p3 = m47 ^ m50;
    let p19 = p2 ^ p3;
    let s5 = p19 ^ p24;
    let p11 = p0 ^ p3;
    let p26 = p9 ^ p11;
    let m56 = m40 & t23;
    let p4 = m48 ^ m56;
    let p20 = p4 ^ p6;
    let p29 = p15 ^ p20;
    let s1 = p26 ^ p29;
    let p10 = m57 ^ p4;
    let p27 = p10 ^ p18;
    let s4 = p23 ^ p27;
    let p25 = p6 ^ p10;
    let p28 = p11 ^ p25;
    let s2 = p17 ^ p28;

    st[0] = s7;
    st[1] = s6;
    st[2] = s5;
    st[3] = s4;
    st[4] = s3;
    st[5] = s2;
    st[6] = s1;
    st[7] = s0;
}

/// Apply the four NOTs the published forward circuit omits.
#[inline]
pub(crate) fn sub_bytes_nots<T>(st: &mut [T; 8])
where
    T: Copy + core::ops::Not<Output = T>,
{
    st[0] = !st[0];
    st[1] = !st[1];
    st[5] = !st[5];
    st[6] = !st[6];
}

/// Forward S-box over LSB-first planes using the published netlist.
///
/// The netlist's `state[0]` is the bit-0 plane (the `p2 p1 p0` index in the
/// fixed-slice layout), which is the same convention as our `Plane` vector, so
/// no bit-order permutation is needed at this boundary.
#[cfg(test)]
#[inline]
fn sbox_planes_bp(a: &[Plane; 8]) -> [Plane; 8] {
    let mut st = *a;
    bp_sub_bytes(&mut st);
    sub_bytes_nots(&mut st);
    st
}

/// Inverse S-box over LSB-first planes using the published inverse netlist.
///
/// `InvSbox(y) = inv_sub_bytes(sub_bytes_nots(y))`, the exact inverse of the
/// forward wrapper above.
#[cfg(test)]
#[inline]
fn inv_sbox_planes_bp(a: &[Plane; 8]) -> [Plane; 8] {
    let mut st = *a;
    sub_bytes_nots(&mut st);
    bp_inv_sub_bytes(&mut st);
    st
}

// ---------------------------------------------------------------------------
// Planar round driver: state stays in bit planes for the whole block
// ---------------------------------------------------------------------------

/// Rotate the four lanes of every column by `n` positions (`S_n`).
#[cfg(test)]
#[inline]
fn rot4(p: Plane, n: u32) -> Plane {
    match n {
        1 => ((p >> 1) & 0x7777) | ((p & 0x1111) << 3),
        2 => ((p >> 2) & 0x3333) | ((p & 0x3333) << 2),
        _ => ((p << 1) & 0xeeee) | ((p & 0x8888) >> 3),
    }
}

/// `ShiftRows` on lanes (`lane = 4*column + row`).
#[cfg(test)]
#[inline]
fn shift_rows_planes(p: &mut [Plane; 8]) {
    let old = *p;
    let mut k = 0usize;
    while k < 8 {
        let mut w = 0u16;
        let mut i = 0usize;
        while i < 16 {
            let c = i / 4;
            let r = i % 4;
            let src = 4 * ((c + r) % 4) + r;
            w |= ((old[k] >> src) & 1) << i;
            i += 1;
        }
        p[k] = w;
        k += 1;
    }
}

/// `InvShiftRows` on lanes.
#[cfg(test)]
#[inline]
fn inv_shift_rows_planes(p: &mut [Plane; 8]) {
    let old = *p;
    let mut k = 0usize;
    while k < 8 {
        let mut w = 0u16;
        let mut i = 0usize;
        while i < 16 {
            let c = i / 4;
            let r = i % 4;
            let src = 4 * ((c + 4 - r) % 4) + r;
            w |= ((old[k] >> src) & 1) << i;
            i += 1;
        }
        p[k] = w;
        k += 1;
    }
}

#[cfg(test)]
#[inline]
fn add_key_planes(p: &mut [Plane; 8], key: &[Plane; 8]) {
    let mut k = 0usize;
    while k < 8 {
        p[k] ^= key[k];
        k += 1;
    }
}

/// `MixColumns` on planes: circulant, so lane rotations align the columns.
#[cfg(test)]
#[inline]
fn mix_columns_planes(p: &mut [Plane; 8]) {
    let mut s1 = [0u16; 8];
    let mut s2 = [0u16; 8];
    let mut s3 = [0u16; 8];
    let mut t = [0u16; 8];
    let mut q = [0u16; 8];
    let mut k = 0usize;
    while k < 8 {
        s1[k] = rot4(p[k], 1);
        s2[k] = rot4(p[k], 2);
        s3[k] = rot4(p[k], 3);
        t[k] = p[k] ^ s1[k] ^ s2[k] ^ s3[k];
        q[k] = p[k] ^ s1[k];
        k += 1;
    }
    let r = xtime_planes(&q);
    let mut k = 0usize;
    while k < 8 {
        p[k] ^= t[k] ^ r[k];
        k += 1;
    }
}

/// Multiply every lane of the plane vector by the public constant `c`.
#[cfg(test)]
#[inline]
fn mul_const_planes(a: &[Plane; 8], c: u8) -> [Plane; 8] {
    let a2 = xtime_planes(a);
    let a4 = xtime_planes(&a2);
    let a8 = xtime_planes(&a4);
    let m1 = 0u16.wrapping_sub((c & 1) as u16);
    let m2 = 0u16.wrapping_sub(((c >> 1) & 1) as u16);
    let m4 = 0u16.wrapping_sub(((c >> 2) & 1) as u16);
    let m8 = 0u16.wrapping_sub(((c >> 3) & 1) as u16);
    let mut out = [0u16; 8];
    let mut k = 0usize;
    while k < 8 {
        out[k] = (a[k] & m1) ^ (a2[k] & m2) ^ (a4[k] & m4) ^ (a8[k] & m8);
        k += 1;
    }
    out
}

/// `InvMixColumns` on planes. The inverse matrix is circulant, so it is the
/// same rotation trick with the `9/11/13/14` constants.
#[cfg(test)]
#[inline]
fn inv_mix_columns_planes(p: &mut [Plane; 8]) {
    let mut s1 = [0u16; 8];
    let mut s2 = [0u16; 8];
    let mut s3 = [0u16; 8];
    let mut k = 0usize;
    while k < 8 {
        s1[k] = rot4(p[k], 1);
        s2[k] = rot4(p[k], 2);
        s3[k] = rot4(p[k], 3);
        k += 1;
    }
    let m14 = mul_const_planes(p, 14);
    let m11 = mul_const_planes(&s1, 11);
    let m13 = mul_const_planes(&s2, 13);
    let m9 = mul_const_planes(&s3, 9);
    let mut k = 0usize;
    while k < 8 {
        p[k] = m14[k] ^ m11[k] ^ m13[k] ^ m9[k];
        k += 1;
    }
}

/// Transpose one 16-byte round key (authority memory order) into planes.
#[inline]
fn schedule_key_bytes(rk: &[u32; 60], round: usize) -> [u8; 16] {
    let mut k = [0u8; 16];
    let mut c = 0usize;
    while c < 4 {
        let word = rk[4 * round + c].swap_bytes();
        let mut r = 0usize;
        while r < 4 {
            k[4 * c + r] = ((word >> (24 - 8 * r)) & 0xff) as u8;
            r += 1;
        }
        c += 1;
    }
    k
}

/// The planar arm: one transpose at entry and exit, then every round is
/// whole-vector XOR/AND/XOR networks.
#[cfg(test)]
pub(crate) fn encrypt_block_planar(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    let mut keys = [[0u16; 8]; 15];
    let mut r = 0usize;
    while r <= rounds {
        keys[r] = transpose(&schedule_key_bytes(rk, r));
        r += 1;
    }
    let mut s = transpose(state);
    add_key_planes(&mut s, &keys[0]);
    let mut r = 1usize;
    while r < rounds {
        s = sbox_planes_bp(&s);
        shift_rows_planes(&mut s);
        mix_columns_planes(&mut s);
        add_key_planes(&mut s, &keys[r]);
        r += 1;
    }
    s = sbox_planes_bp(&s);
    shift_rows_planes(&mut s);
    add_key_planes(&mut s, &keys[rounds]);
    *state = untranspose(&s);
}

#[cfg(test)]
pub(crate) fn decrypt_block_planar(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    let mut keys = [[0u16; 8]; 15];
    let mut r = 0usize;
    while r <= rounds {
        keys[r] = transpose(&schedule_key_bytes(rk, r));
        r += 1;
    }
    let mut s = transpose(state);
    add_key_planes(&mut s, &keys[0]);
    let mut r = 1usize;
    while r < rounds {
        s = inv_sbox_planes_bp(&s);
        inv_shift_rows_planes(&mut s);
        inv_mix_columns_planes(&mut s);
        add_key_planes(&mut s, &keys[r]);
        r += 1;
    }
    s = inv_sbox_planes_bp(&s);
    inv_shift_rows_planes(&mut s);
    add_key_planes(&mut s, &keys[rounds]);
    *state = untranspose(&s);
}

// ---------------------------------------------------------------------------
// Fixsliced arm (Adomnicai–Peyrin fixed-slice representation, 16-bit word)
// ---------------------------------------------------------------------------
//
// The state is eight 16-bit words in the fixed-slice layout of
// `aes/src/backends/fixslice/{word,sbox,mix_columns,utils}.rs` (RustCrypto
// `aes` 0.9.4, the Rust port of Adomnicai–Peyrin, TCHES 2020/1123). The round
// key words are the exported schedule bitsliced into that layout, derived at
// block time; the exported `AES_KEY` bytes are untouched.

const FIX_ROW_BITS: u32 = 4;
const FIX_HALF_ROW: u32 = FIX_ROW_BITS / 2;
const FIX_QUARTER_ROW: u32 = FIX_ROW_BITS / 4;

#[inline]
fn fix_ror_distance(rows: u32, cols: u32) -> u32 {
    rows * FIX_ROW_BITS + cols * FIX_QUARTER_ROW
}

#[inline]
fn fix_pack_rows(r0: u8, r1: u8, r2: u8, r3: u8) -> u16 {
    (r0 as u16) | ((r1 as u16) << 4) | ((r2 as u16) << 8) | ((r3 as u16) << 12)
}

#[inline]
fn fix_byte_repeat(b: u8) -> u16 {
    (b as u16) * 0x0101
}

#[inline]
fn fix_delta_swap_1(a: &mut u16, shift: u32, mask: u16) {
    let t = (*a ^ (*a >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
fn fix_delta_swap_2(a: &mut u16, b: &mut u16, shift: u32, mask: u16) {
    let t = (*a ^ (*b >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

#[inline]
fn fix_bitslice_swaps(t: &mut [u16; 8]) {
    let [t0, t1, t2, t3, t4, t5, t6, t7] = t;
    let m0 = fix_byte_repeat(0x55);
    fix_delta_swap_2(t1, t0, 1, m0);
    fix_delta_swap_2(t3, t2, 1, m0);
    fix_delta_swap_2(t5, t4, 1, m0);
    fix_delta_swap_2(t7, t6, 1, m0);

    let m1 = fix_byte_repeat(0x33);
    fix_delta_swap_2(t2, t0, 2, m1);
    fix_delta_swap_2(t3, t1, 2, m1);
    fix_delta_swap_2(t6, t4, 2, m1);
    fix_delta_swap_2(t7, t5, 2, m1);

    let m2 = fix_byte_repeat(0x0f);
    fix_delta_swap_2(t4, t0, 4, m2);
    fix_delta_swap_2(t5, t1, 4, m2);
    fix_delta_swap_2(t6, t2, 4, m2);
    fix_delta_swap_2(t7, t3, 4, m2);
}

#[inline]
pub(crate) fn fix_bitslice(input: &[u8; 16]) -> [u16; 8] {
    fn read_reordered(input: &[u8]) -> u16 {
        u16::from(input[0]) | (u16::from(input[2]) << 8)
    }
    let mut t = [
        read_reordered(&input[0x00..]),
        read_reordered(&input[0x04..]),
        read_reordered(&input[0x08..]),
        read_reordered(&input[0x0c..]),
        read_reordered(&input[0x01..]),
        read_reordered(&input[0x05..]),
        read_reordered(&input[0x09..]),
        read_reordered(&input[0x0d..]),
    ];
    fix_bitslice_swaps(&mut t);
    t
}

#[inline]
pub(crate) fn fix_inv_bitslice(input: &[u16; 8]) -> [u8; 16] {
    fn write_reordered(rows: u16, output: &mut [u8]) {
        output[0] = rows as u8;
        output[2] = (rows >> 8) as u8;
    }
    let mut t = *input;
    fix_bitslice_swaps(&mut t);
    let mut out = [0u8; 16];
    write_reordered(t[0], &mut out[0x00..]);
    write_reordered(t[1], &mut out[0x04..]);
    write_reordered(t[2], &mut out[0x08..]);
    write_reordered(t[3], &mut out[0x0c..]);
    write_reordered(t[4], &mut out[0x01..]);
    write_reordered(t[5], &mut out[0x05..]);
    write_reordered(t[6], &mut out[0x09..]);
    write_reordered(t[7], &mut out[0x0d..]);
    out
}

/// `ShiftRows` in the fixed-slice representation.
#[inline]
fn fix_shift_rows_1(state: &mut [u16; 8]) {
    let mut i = 0usize;
    while i < 8 {
        fix_delta_swap_1(
            &mut state[i],
            FIX_HALF_ROW,
            fix_pack_rows(0x0, 0x1, 0x3, 0x2),
        );
        fix_delta_swap_1(
            &mut state[i],
            FIX_QUARTER_ROW,
            fix_pack_rows(0x0, 0x5, 0x0, 0x5),
        );
        i += 1;
    }
}

/// `InvShiftRows` in the fixed-slice representation (`ShiftRows^3`).
#[inline]
fn fix_inv_shift_rows_1(state: &mut [u16; 8]) {
    let mut i = 0usize;
    while i < 8 {
        fix_delta_swap_1(
            &mut state[i],
            FIX_HALF_ROW,
            fix_pack_rows(0x0, 0x2, 0x3, 0x1),
        );
        fix_delta_swap_1(
            &mut state[i],
            FIX_QUARTER_ROW,
            fix_pack_rows(0x0, 0x5, 0x0, 0x5),
        );
        i += 1;
    }
}

/// `MixColumns` for the standard (already ShiftRows'd) fixed-slice state.
#[inline]
fn fix_mix_columns_0(state: &mut [u16; 8]) {
    let a = *state;
    let mut b = [0u16; 8];
    let mut c = [0u16; 8];
    let mut k = 0usize;
    while k < 8 {
        b[k] = a[k].rotate_right(fix_ror_distance(1, 0));
        c[k] = a[k] ^ b[k];
        k += 1;
    }
    let r2 = |x: u16| x.rotate_right(fix_ror_distance(2, 0));
    state[0] = b[0] ^ c[7] ^ r2(c[0]);
    state[1] = b[1] ^ c[0] ^ c[7] ^ r2(c[1]);
    state[2] = b[2] ^ c[1] ^ r2(c[2]);
    state[3] = b[3] ^ c[2] ^ c[7] ^ r2(c[3]);
    state[4] = b[4] ^ c[3] ^ c[7] ^ r2(c[4]);
    state[5] = b[5] ^ c[4] ^ r2(c[5]);
    state[6] = b[6] ^ c[5] ^ r2(c[6]);
    state[7] = b[7] ^ c[6] ^ r2(c[7]);
}

/// `InvMixColumns` for the standard fixed-slice state.
#[inline]
fn fix_inv_mix_columns_0(state: &mut [u16; 8]) {
    let a = *state;
    let mut b = [0u16; 8];
    let mut c = [0u16; 8];
    let mut k = 0usize;
    while k < 8 {
        b[k] = a[k].rotate_right(fix_ror_distance(1, 0));
        c[k] = a[k] ^ b[k];
        k += 1;
    }
    let d = [
        a[0] ^ c[7],
        a[1] ^ c[0] ^ c[7],
        a[2] ^ c[1],
        a[3] ^ c[2] ^ c[7],
        a[4] ^ c[3] ^ c[7],
        a[5] ^ c[4],
        a[6] ^ c[5],
        a[7] ^ c[6],
    ];
    let e0 = c[0] ^ d[6];
    let e1 = c[1] ^ d[6] ^ d[7];
    let e2 = c[2] ^ d[0] ^ d[7];
    let e3 = c[3] ^ d[1] ^ d[6];
    let e4 = c[4] ^ d[2] ^ d[6] ^ d[7];
    let e5 = c[5] ^ d[3] ^ d[7];
    let e6 = c[6] ^ d[4];
    let e7 = c[7] ^ d[5];
    let e = [e0, e1, e2, e3, e4, e5, e6, e7];
    let mut k = 0usize;
    while k < 8 {
        state[k] = d[k] ^ e[k] ^ e[k].rotate_right(fix_ror_distance(2, 0));
        k += 1;
    }
}

#[inline]
fn fix_add_key(state: &mut [u16; 8], key: &[u16; 8]) {
    let mut k = 0usize;
    while k < 8 {
        state[k] ^= key[k];
        k += 1;
    }
}

/// Derive the eight fixed-slice round-key words from the exported schedule.
#[inline]
fn fix_keys(rk: &[u32; 60], rounds: usize) -> [[u16; 8]; 15] {
    let mut keys = [[0u16; 8]; 15];
    let mut r = 0usize;
    while r <= rounds {
        keys[r] = fix_bitslice(&schedule_key_bytes(rk, r));
        r += 1;
    }
    keys
}

pub(crate) fn encrypt_block_fixslice(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    let keys = fix_keys(rk, rounds);
    let mut s = fix_bitslice(state);
    fix_add_key(&mut s, &keys[0]);
    let mut r = 1usize;
    while r < rounds {
        bp_sub_bytes(&mut s);
        sub_bytes_nots(&mut s);
        fix_shift_rows_1(&mut s);
        fix_mix_columns_0(&mut s);
        fix_add_key(&mut s, &keys[r]);
        r += 1;
    }
    bp_sub_bytes(&mut s);
    sub_bytes_nots(&mut s);
    fix_shift_rows_1(&mut s);
    fix_add_key(&mut s, &keys[rounds]);
    *state = fix_inv_bitslice(&s);
}

pub(crate) fn decrypt_block_fixslice(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    let keys = fix_keys(rk, rounds);
    let mut s = fix_bitslice(state);
    fix_add_key(&mut s, &keys[0]);
    let mut r = 1usize;
    while r < rounds {
        sub_bytes_nots(&mut s);
        bp_inv_sub_bytes(&mut s);
        fix_inv_shift_rows_1(&mut s);
        fix_inv_mix_columns_0(&mut s);
        fix_add_key(&mut s, &keys[r]);
        r += 1;
    }
    sub_bytes_nots(&mut s);
    bp_inv_sub_bytes(&mut s);
    fix_inv_shift_rows_1(&mut s);
    fix_add_key(&mut s, &keys[rounds]);
    *state = fix_inv_bitslice(&s);
}

/// The exponentiation arm, retained as the measured baseline.
#[cfg(test)]
pub(crate) fn encrypt_block_exp(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    add_round_key(state, rk, 0);
    let mut round = 1usize;
    while round < rounds {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk, round);
        round += 1;
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk, rounds);
}

#[cfg(test)]
pub(crate) fn decrypt_block_exp(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    add_round_key(state, rk, 0);
    let mut round = 1usize;
    while round < rounds {
        inv_sub_bytes(state);
        inv_shift_rows(state);
        inv_mix_columns(state);
        add_round_key(state, rk, round);
        round += 1;
    }
    inv_sub_bytes(state);
    inv_shift_rows(state);
    add_round_key(state, rk, rounds);
}

/// `SubBytes` over the sixteen-byte state, bitsliced so all bytes share the circuit.
#[cfg(test)]
pub(crate) fn sub_bytes(state: &mut [u8; 16]) {
    let p = transpose(state);
    *state = untranspose(&sbox_planes(&p));
}

/// `InvSubBytes` over the sixteen-byte state.
#[cfg(test)]
pub(crate) fn inv_sub_bytes(state: &mut [u8; 16]) {
    let p = transpose(state);
    *state = untranspose(&inv_sbox_planes(&p));
}

/// `SubWord` on a logical big-endian word.
pub(crate) fn sub_word(w: u32) -> u32 {
    (u32::from(sbox_byte((w >> 24) as u8)) << 24)
        | (u32::from(sbox_byte((w >> 16) as u8)) << 16)
        | (u32::from(sbox_byte((w >> 8) as u8)) << 8)
        | u32::from(sbox_byte(w as u8))
}

/// `RotWord(SubWord(w))` on a logical big-endian word.
pub(crate) fn rot_sub_word(w: u32) -> u32 {
    sub_word(w.rotate_left(8))
}

/// `ShiftRows`, byte-oriented in the crate's column-major state layout.
#[cfg(test)]
pub(crate) fn shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    let mut r = 0usize;
    while r < 4 {
        let mut c = 0usize;
        while c < 4 {
            state[4 * c + r] = old[4 * ((c + r) % 4) + r];
            c += 1;
        }
        r += 1;
    }
}

/// `InvShiftRows`.
#[cfg(test)]
pub(crate) fn inv_shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    let mut r = 0usize;
    while r < 4 {
        let mut c = 0usize;
        while c < 4 {
            state[4 * c + r] = old[4 * ((c + 4 - r) % 4) + r];
            c += 1;
        }
        r += 1;
    }
}

/// `MixColumns`, branch-free and table-free.
#[cfg(test)]
pub(crate) fn mix_columns(state: &mut [u8; 16]) {
    let mut c = 0usize;
    while c < 4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        state[4 * c] = a0 ^ t ^ xtime(a0 ^ a1);
        state[4 * c + 1] = a1 ^ t ^ xtime(a1 ^ a2);
        state[4 * c + 2] = a2 ^ t ^ xtime(a2 ^ a3);
        state[4 * c + 3] = a3 ^ t ^ xtime(a3 ^ a0);
        c += 1;
    }
}

/// `InvMixColumns`, with `9/11/13/14` built from the fixed `2/4/8` chain.
#[cfg(test)]
pub(crate) fn inv_mix_columns(state: &mut [u8; 16]) {
    let mut c = 0usize;
    while c < 4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];

        let a0_2 = xtime(a0);
        let a0_4 = xtime(a0_2);
        let a0_8 = xtime(a0_4);
        let a1_2 = xtime(a1);
        let a1_4 = xtime(a1_2);
        let a1_8 = xtime(a1_4);
        let a2_2 = xtime(a2);
        let a2_4 = xtime(a2_2);
        let a2_8 = xtime(a2_4);
        let a3_2 = xtime(a3);
        let a3_4 = xtime(a3_2);
        let a3_8 = xtime(a3_4);

        state[4 * c] = (a0_8 ^ a0_4 ^ a0_2) ^ (a1_8 ^ a1_2 ^ a1) ^ (a2_8 ^ a2_4 ^ a2) ^ (a3_8 ^ a3);
        state[4 * c + 1] =
            (a0_8 ^ a0) ^ (a1_8 ^ a1_4 ^ a1_2) ^ (a2_8 ^ a2_2 ^ a2) ^ (a3_8 ^ a3_4 ^ a3);
        state[4 * c + 2] =
            (a0_8 ^ a0_4 ^ a0) ^ (a1_8 ^ a1) ^ (a2_8 ^ a2_4 ^ a2_2) ^ (a3_8 ^ a3_2 ^ a3);
        state[4 * c + 3] =
            (a0_8 ^ a0_2 ^ a0) ^ (a1_8 ^ a1_4 ^ a1) ^ (a2_8 ^ a2) ^ (a3_8 ^ a3_4 ^ a3_2);

        c += 1;
    }
}

/// `AddRoundKey` for the stored (byte-swapped) schedule the caller carries.
#[cfg(test)]
#[inline]
pub(crate) fn add_round_key(state: &mut [u8; 16], rk: &[u32; 60], round: usize) {
    let mut c = 0usize;
    while c < 4 {
        let word = rk[4 * round + c].swap_bytes();
        let mut r = 0usize;
        while r < 4 {
            state[4 * c + r] ^= ((word >> (24 - 8 * r)) & 0xff) as u8;
            r += 1;
        }
        c += 1;
    }
}

/// One forward AES block over a stored schedule.
///
/// The selected arm is the fully fixed-slice driver (`encrypt_block_fixslice`);
/// the exponentiation and planar arms are retained for measurement under
/// `#[cfg(test)]` and are not dispatched here.
pub(crate) fn encrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    encrypt_block_fixslice(state, rk, rounds);
}

/// One inverse AES block over a stored decryption schedule.
pub(crate) fn decrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    decrypt_block_fixslice(state, rk, rounds);
}

/// The authority's encryption key expansion, on a caller-supplied key slice.
///
/// Returns the logical `GETU32` words and the round count. The recurrence, the
/// `SubWord`/`RotWord` placement and the round constants are byte-for-byte the
/// authority's, so `aes.rs` can byte-swap the result into the exported `AES_KEY`
/// exactly as it did before this conversion.
pub(crate) fn expand_encrypt_key(key: &[u8], bits: c_int) -> Option<([u32; 60], usize)> {
    let mut rk = [0u32; 60];
    match bits {
        128 => {
            if key.len() != 16 {
                return None;
            }
            rk[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
            rk[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
            rk[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
            rk[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 3];
                rk[off + 4] = rk[off] ^ rot_sub_word(temp) ^ AES_RCON[i];
                rk[off + 5] = rk[off + 1] ^ rk[off + 4];
                rk[off + 6] = rk[off + 2] ^ rk[off + 5];
                rk[off + 7] = rk[off + 3] ^ rk[off + 6];
                i += 1;
                if i == 10 {
                    return Some((rk, 10));
                }
                off += 4;
            }
        }
        192 => {
            if key.len() != 24 {
                return None;
            }
            rk[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
            rk[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
            rk[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
            rk[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);
            rk[4] = u32::from_be_bytes([key[16], key[17], key[18], key[19]]);
            rk[5] = u32::from_be_bytes([key[20], key[21], key[22], key[23]]);
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 5];
                rk[off + 6] = rk[off] ^ rot_sub_word(temp) ^ AES_RCON[i];
                rk[off + 7] = rk[off + 1] ^ rk[off + 6];
                rk[off + 8] = rk[off + 2] ^ rk[off + 7];
                rk[off + 9] = rk[off + 3] ^ rk[off + 8];
                i += 1;
                if i == 8 {
                    return Some((rk, 12));
                }
                rk[off + 10] = rk[off + 4] ^ rk[off + 9];
                rk[off + 11] = rk[off + 5] ^ rk[off + 10];
                off += 6;
            }
        }
        256 => {
            if key.len() != 32 {
                return None;
            }
            rk[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
            rk[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
            rk[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
            rk[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);
            rk[4] = u32::from_be_bytes([key[16], key[17], key[18], key[19]]);
            rk[5] = u32::from_be_bytes([key[20], key[21], key[22], key[23]]);
            rk[6] = u32::from_be_bytes([key[24], key[25], key[26], key[27]]);
            rk[7] = u32::from_be_bytes([key[28], key[29], key[30], key[31]]);
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 7];
                rk[off + 8] = rk[off] ^ rot_sub_word(temp) ^ AES_RCON[i];
                rk[off + 9] = rk[off + 1] ^ rk[off + 8];
                rk[off + 10] = rk[off + 2] ^ rk[off + 9];
                rk[off + 11] = rk[off + 3] ^ rk[off + 10];
                i += 1;
                if i == 7 {
                    return Some((rk, 14));
                }
                let temp = rk[off + 11];
                rk[off + 12] = rk[off + 4] ^ sub_word(temp);
                rk[off + 13] = rk[off + 5] ^ rk[off + 12];
                rk[off + 14] = rk[off + 6] ^ rk[off + 13];
                rk[off + 15] = rk[off + 7] ^ rk[off + 14];
                off += 8;
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::tables::{AES_INV_SBOX, AES_SBOX};

    /// The cheap complete check: all 256 scalar forwards and inverses against the
    /// authority-derived table.
    #[test]
    fn scalar_sbox_is_exhaustively_equal_to_the_reference_table() {
        for x in 0u16..=255 {
            let x = x as u8;
            assert_eq!(sbox_byte(x), AES_SBOX[x as usize], "sbox({x:#04x})");
            assert_eq!(
                inv_sbox_byte(x),
                AES_INV_SBOX[x as usize],
                "inv_sbox({x:#04x})"
            );
        }
    }

    /// The bitsliced carrier must agree with the scalar one on every input, including
    /// all sixteen lanes at once and a mixture that exercises the lane independence.
    #[test]
    fn bitsliced_sbox_is_exhaustively_equal_to_the_scalar_sbox() {
        for x in 0u16..=255 {
            let x = x as u8;
            let mut fwd = [x; 16];
            sub_bytes(&mut fwd);
            for b in fwd {
                assert_eq!(b, sbox_byte(x), "sub_bytes({x:#04x})");
            }
            let mut inv = [x; 16];
            inv_sub_bytes(&mut inv);
            for b in inv {
                assert_eq!(b, inv_sbox_byte(x), "inv_sub_bytes({x:#04x})");
            }
        }

        let mixed: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0xfe, 0xff, 0x80, 0x7f, 0x53, 0xa5, 0x5a, 0x0f, 0xf0, 0x9c,
            0x63, 0x6c,
        ];
        let mut fwd = mixed;
        sub_bytes(&mut fwd);
        for (i, b) in fwd.iter().enumerate() {
            assert_eq!(*b, sbox_byte(mixed[i]));
        }
        let mut inv = mixed;
        inv_sub_bytes(&mut inv);
        for (i, b) in inv.iter().enumerate() {
            assert_eq!(*b, inv_sbox_byte(mixed[i]));
        }
    }

    #[test]
    fn sbox_and_its_inverse_round_trip() {
        for x in 0u16..=255 {
            let x = x as u8;
            assert_eq!(inv_sbox_byte(sbox_byte(x)), x);
            assert_eq!(sbox_byte(inv_sbox_byte(x)), x);
        }
    }

    #[test]
    fn scalar_and_bitsliced_field_inverse_agree() {
        for x in 0u16..=255 {
            let x = x as u8;
            let planes = transpose(&[x; 16]);
            let back = untranspose(&inv_planes(&planes));
            for b in back {
                assert_eq!(b, gf8_inv(x), "inverse({x:#04x})");
            }
        }
    }

    /// Boyar–Peralta–Calik circuit, exhaustive over all 256 inputs, forward
    /// and inverse, against the authority-derived table.
    #[test]
    fn boyar_peralta_sbox_is_exhaustively_equal_to_the_table() {
        for x in 0u16..=255 {
            let x = x as u8;
            let fwd = untranspose(&sbox_planes_bp(&transpose(&[x; 16])));
            let inv = untranspose(&inv_sbox_planes_bp(&transpose(&[x; 16])));
            for b in fwd {
                assert_eq!(b, AES_SBOX[x as usize], "bp sbox({x:#04x})");
            }
            for b in inv {
                assert_eq!(b, AES_INV_SBOX[x as usize], "bp inv_sbox({x:#04x})");
            }
        }
    }

    /// The fixed-slice bit layout must round-trip every 16-byte value.
    #[test]
    fn fixslice_bitslice_round_trips() {
        let mut state = [0u8; 16];
        let mut x = 0x1234_5678_9abc_def0u64;
        for step in 0u32..512 {
            let mut b = step as u64 ^ x;
            for byte in state.iter_mut() {
                *byte = b as u8;
                b = b.rotate_left(7) ^ 0x9e;
            }
            assert_eq!(fix_inv_bitslice(&fix_bitslice(&state)), state);
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
    }

    /// The authority's decrypt transform on stored (byte-swapped) words, used to
    /// build the decryption schedules for the differential block test.
    fn decrypt_schedule_stored(mut rk: [u32; 60], rounds: usize) -> [u32; 60] {
        let mut i = 0usize;
        let mut j = 4 * rounds;
        while i < j {
            for k in 0..4 {
                rk.swap(i + k, j + k);
            }
            i += 4;
            j -= 4;
        }
        let mut off = 0usize;
        for _ in 1..rounds {
            off += 4;
            for jj in 0..4 {
                let tp1 = rk[off + jj];
                let m = tp1 & 0x8080_8080;
                let tp2 = ((tp1 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
                let m = tp2 & 0x8080_8080;
                let tp4 = ((tp2 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
                let m = tp4 & 0x8080_8080;
                let tp8 = ((tp4 & 0x7f7f_7f7f) << 1) ^ ((m.wrapping_sub(m >> 7)) & 0x1b1b_1b1b);
                let tp9 = tp8 ^ tp1;
                let tpb = tp9 ^ tp2;
                let tpd = tp9 ^ tp4;
                let tpe = tp8 ^ tp4 ^ tp2;
                rk[off + jj] = tpe ^ tpd.rotate_left(16) ^ tp9.rotate_left(24) ^ tpb.rotate_left(8);
            }
        }
        rk
    }

    fn stored_schedule(key: &[u8], bits: c_int) -> ([u32; 60], usize) {
        let (mut w, rounds) = match expand_encrypt_key(key, bits) {
            Some(v) => v,
            None => unreachable!("valid key"),
        };
        for word in w.iter_mut().take(4 * (rounds + 1)) {
            *word = word.swap_bytes();
        }
        (w, rounds)
    }

    type Arm = fn(&mut [u8; 16], &[u32; 60], usize);

    /// Every surviving arm must reproduce the table reference for encryption
    /// and decryption over a spread of keys and blocks.
    #[test]
    fn all_arms_match_the_reference_block_for_block() {
        use crate::aes::reference;

        let arms: [(&str, Arm, Arm); 3] = [
            ("exponentiation", encrypt_block_exp, decrypt_block_exp),
            (
                "planar-boyar-peralta",
                encrypt_block_planar,
                decrypt_block_planar,
            ),
            ("fixsliced", encrypt_block_fixslice, decrypt_block_fixslice),
        ];

        let mut key = [0u8; 32];
        let mut block = [0u8; 16];
        let mut seed = 0x0f1e_2d3c_4b5a_6978u64;
        for bits in [128i32, 192, 256] {
            let n = (bits / 8) as usize;
            for _ in 0..32 {
                for b in key[..n].iter_mut() {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    *b = (seed >> 33) as u8;
                }
                let (ek, rounds) = stored_schedule(&key[..n], bits);
                let dk = decrypt_schedule_stored(ek, rounds);
                for _ in 0..8 {
                    for b in block.iter_mut() {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        *b = (seed >> 33) as u8;
                    }
                    let mut want_enc = block;
                    reference::encrypt_block(&mut want_enc, &ek, rounds);
                    let mut want_dec = block;
                    reference::decrypt_block(&mut want_dec, &dk, rounds);
                    for (name, enc, dec) in arms {
                        let mut got = block;
                        enc(&mut got, &ek, rounds);
                        assert_eq!(got, want_enc, "{name} enc bits={bits}");
                        let mut got = block;
                        dec(&mut got, &dk, rounds);
                        assert_eq!(got, want_dec, "{name} dec bits={bits}");
                    }
                }
            }
        }
    }
}
