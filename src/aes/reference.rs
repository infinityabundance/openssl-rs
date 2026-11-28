//! Test-only table implementation of AES, kept as the differential reference.
//!
//! This is the pre-conversion transcription: `SubBytes`/`InvSubBytes` and the key
//! schedule's `SubWord` read [`AES_SBOX`]/[`AES_INV_SBOX`] by secret state. It exists
//! only under `#[cfg(test)]` so the portable circuit can be proved equal to the
//! authority-derived table on every input; it is not compiled into any production
//! artefact.
//!
//! SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use core::ffi::c_int;

use crate::digest::tables::{AES_INV_SBOX, AES_RCON, AES_SBOX};

fn get_u32(p: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut r = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

fn add_round_key(state: &mut [u8; 16], rk: &[u32; 60], round: usize) {
    for c in 0..4 {
        let word = rk[4 * round + c].swap_bytes();
        for r in 0..4 {
            state[4 * c + r] ^= ((word >> (24 - 8 * r)) & 0xff) as u8;
        }
    }
}

#[inline(never)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    for r in 0..4 {
        for c in 0..4 {
            state[4 * c + r] = old[4 * ((c + r) % 4) + r];
        }
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    for r in 0..4 {
        for c in 0..4 {
            state[4 * c + r] = old[4 * ((c + 4 - r) % 4) + r];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];
        state[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];
        state[4 * c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        state[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        state[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        state[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

/// The table-based forward block.
pub(crate) fn encrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    add_round_key(state, rk, 0);
    for round in 1..rounds {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk, rounds);
}

/// The table-based inverse block.
pub(crate) fn decrypt_block(state: &mut [u8; 16], rk: &[u32; 60], rounds: usize) {
    add_round_key(state, rk, 0);
    for round in 1..rounds {
        inv_sub_bytes(state);
        inv_shift_rows(state);
        inv_mix_columns(state);
        add_round_key(state, rk, round);
    }
    inv_sub_bytes(state);
    inv_shift_rows(state);
    add_round_key(state, rk, rounds);
}

fn sub_word(w: u32) -> u32 {
    (u32::from(AES_SBOX[(w >> 24) as usize]) << 24)
        | (u32::from(AES_SBOX[((w >> 16) & 0xff) as usize]) << 16)
        | (u32::from(AES_SBOX[((w >> 8) & 0xff) as usize]) << 8)
        | u32::from(AES_SBOX[(w & 0xff) as usize])
}

fn rot_sub_word(w: u32) -> u32 {
    (u32::from(AES_SBOX[((w >> 16) & 0xff) as usize]) << 24)
        | (u32::from(AES_SBOX[((w >> 8) & 0xff) as usize]) << 16)
        | (u32::from(AES_SBOX[(w & 0xff) as usize]) << 8)
        | u32::from(AES_SBOX[(w >> 24) as usize])
}

/// The table-based encryption key expansion, transcribed exactly as it was before the
/// conversion.
pub(crate) fn expand_encrypt_key(key: &[u8], bits: c_int) -> Option<([u32; 60], usize)> {
    let mut rk = [0u32; 60];
    match bits {
        128 => {
            if key.len() != 16 {
                return None;
            }
            rk[0] = get_u32(key, 0);
            rk[1] = get_u32(key, 4);
            rk[2] = get_u32(key, 8);
            rk[3] = get_u32(key, 12);
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
            rk[0] = get_u32(key, 0);
            rk[1] = get_u32(key, 4);
            rk[2] = get_u32(key, 8);
            rk[3] = get_u32(key, 12);
            rk[4] = get_u32(key, 16);
            rk[5] = get_u32(key, 20);
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
            rk[0] = get_u32(key, 0);
            rk[1] = get_u32(key, 4);
            rk[2] = get_u32(key, 8);
            rk[3] = get_u32(key, 12);
            rk[4] = get_u32(key, 16);
            rk[5] = get_u32(key, 20);
            rk[6] = get_u32(key, 24);
            rk[7] = get_u32(key, 28);
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
