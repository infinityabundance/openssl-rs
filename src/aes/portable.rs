//! A constant-pattern portable AES for the non-AES-NI arm.
//!
//! The authority's portable arm (`crypto/aes/aes_core.c`) and this crate's earlier
//! transcription both index an S-box table by secret state. That is the
//! table-looking AES a cache-timing observer recovers, and it is what runs on a CPU
//! without the `aes` target feature. This module replaces every such access with a
//! first-party Boolean construction: the S-box is the AES affine map composed with a
//! field inversion computed by fixed-shape GF(2^8) arithmetic (square-and-multiply
//! exponentiation to `x^254`), evaluated bitsliced over all sixteen state bytes. No
//! load or branch is selected by a key or message byte.
//!
//! ## What is preserved
//!
//! `AES_set_encrypt_key`/`AES_set_decrypt_key` export the schedule, so this module
//! reproduces the authority's exact recurrence and round constants. The words it
//! returns are the *logical* big-endian `GETU32` words; `aes.rs` byte-swaps them into
//! the authority's perlasm memory order exactly as before, so the exported bytes are
//! unchanged.
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
type Plane = u16;

/// Every plane bit set, used to XOR a public constant into all sixteen lanes.
const ALL: Plane = Plane::MAX;

/// Transpose sixteen bytes into eight bit planes.
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

/// `SubBytes` over the sixteen-byte state, bitsliced so all bytes share the circuit.
pub(crate) fn sub_bytes(state: &mut [u8; 16]) {
    let p = transpose(state);
    *state = untranspose(&sbox_planes(&p));
}

/// `InvSubBytes` over the sixteen-byte state.
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
pub(crate) fn encrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
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

/// One inverse AES block over a stored decryption schedule.
pub(crate) fn decrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
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
}
