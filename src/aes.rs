//! Phase 8.2 — `crypto/aes/`: the portable AES arm and the deprecated mode entry points.
//!
//! The authority's build selects the perlasm arm: `crypto/aes/asm/aes-x86_64.pl`'s object
//! defines `AES_cbc_encrypt`, `AES_decrypt`, `AES_encrypt`, `AES_set_decrypt_key` and
//! `AES_set_encrypt_key` (the plan's §0 measurement), and no `aes_core.o` is linked. This
//! module is the portable arm, and `RT-CIPHER` is what proves it answers the same bytes —
//! a published vector proves *some* correct AES, not this authority's observable function
//! (`docs/PHASE-8-SUBPHASES.md` §3.1, D197).
//!
//! ## The round structure is byte-oriented; the constants are the authority's
//!
//! The authority's portable source computes AES with the four `Te`/`Td` T-tables; the
//! perlasm arm computes the same function with the AES-NI instructions. This module writes
//! the FIPS-197 byte-oriented round — `SubBytes`/`ShiftRows`/`MixColumns`/`AddRoundKey` — and
//! reads the S-box, the inverse S-box and the round constants from
//! [`crate::digest::tables`], where `gen_phase8_tables.py` derives them from
//! `crypto/aes/aes_core.c`'s `Te4`, `Td4` and `rcon`. The *key schedule* is transcribed from
//! the authority's own `AES_set_encrypt_key`/`AES_set_decrypt_key` (the `AES_ASM` branch,
//! which is the one the authority's header layout matches), so the `AES_KEY` a caller keeps
//! across calls is the same object the authority builds.
//!
//! ## `AES_bi_ige_encrypt`'s documented bug is reproduced
//!
//! `crypto/aes/aes_ige.c:169-173` says the function "is supposed to use 2 AES keys, but in
//! fact only one is ever used", kept for backwards compatibility. The `key2` parameter is
//! accepted and ignored, exactly as the authority does; "fixing" it would be a divergence.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::digest::tables::{AES_INV_SBOX, AES_RCON, AES_SBOX};
use crate::modes::wrap::{unwrap128, wrap128};
use crate::modes::{
    CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt, CRYPTO_cfb128_8_encrypt,
    CRYPTO_cfb128_encrypt, CRYPTO_ofb128_encrypt,
};

/// `AES_BLOCK_SIZE` — `include/openssl/aes.h:29`.
pub const AES_BLOCK_SIZE: usize = 16;
/// `AES_ENCRYPT` — `include/openssl/aes.h:34`.
pub const AES_ENCRYPT: c_int = 1;
/// `AES_DECRYPT` — `include/openssl/aes.h:35`.
pub const AES_DECRYPT: c_int = 0;
/// `AES_MAXNR` — `include/openssl/aes.h:37`.
pub const AES_MAXNR: usize = 14;

/// `AES_KEY` — `include/openssl/aes.h:40-46`, with `AES_LONG` undefined in this profile, so
/// `rd_key` is sixty `unsigned int` and then the round count.
#[repr(C)]
pub struct AesKey {
    /// `unsigned int rd_key[4 * (AES_MAXNR + 1)]`.
    pub rd_key: [u32; 4 * (AES_MAXNR + 1)],
    /// `int rounds`.
    pub rounds: c_int,
}

const _: () = {
    assert!(core::mem::offset_of!(AesKey, rounds) == 240);
    assert!(core::mem::size_of::<AesKey>() == 244);
};

/// `GETU32` — `internal/endian.h`, big-endian.
///
/// # Safety
/// `p` readable for four bytes.
unsafe fn get_u32(p: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) }
}

/// `xtime(a)` — multiplication by `x` in `GF(2^8)` with the AES polynomial.
fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

/// Multiplication in `GF(2^8)`, used by the inverse MixColumns.
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

/// `AddRoundKey` — XOR the sixteen state bytes with one round key, big-endian per column.
fn add_round_key(state: &mut [u8; 16], rk: &[u32; 60], round: usize) {
    for c in 0..4 {
        // The stored word is the authority's memory-order representation; the logical word is
        // its byte swap, and the bytes are then the key bytes in order.
        let word = rk[4 * round + c].swap_bytes();
        for r in 0..4 {
            state[4 * c + r] ^= ((word >> (24 - 8 * r)) & 0xff) as u8;
        }
    }
}

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

/// The logical key expansion: the standard `GETU32` words, the authority's round structure.
/// The public entry points byte-swap the result on the way out, because the authority's
/// perlasm key schedule stores each word in memory order and `RT-CIPHER` observes it.
///
/// # Safety
/// `user_key` readable for `bits / 8` bytes and `key` writable, or either NULL.
unsafe fn aes_expand(user_key: *const u8, bits: c_int, key: *mut AesKey) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if user_key.is_null() || key.is_null() {
            return -1;
        }
        if bits != 128 && bits != 192 && bits != 256 {
            return -2;
        }
        let rk = &mut (*key).rd_key;
        (*key).rounds = if bits == 128 {
            10
        } else if bits == 192 {
            12
        } else {
            14
        };

        rk[0] = get_u32(user_key);
        rk[1] = get_u32(user_key.add(4));
        rk[2] = get_u32(user_key.add(8));
        rk[3] = get_u32(user_key.add(12));

        if bits == 128 {
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 3];
                rk[off + 4] = rk[off]
                    ^ ((AES_SBOX[((temp >> 16) & 0xff) as usize] as u32) << 24)
                    ^ ((AES_SBOX[((temp >> 8) & 0xff) as usize] as u32) << 16)
                    ^ ((AES_SBOX[(temp & 0xff) as usize] as u32) << 8)
                    ^ (AES_SBOX[(temp >> 24) as usize] as u32)
                    ^ AES_RCON[i];
                rk[off + 5] = rk[off + 1] ^ rk[off + 4];
                rk[off + 6] = rk[off + 2] ^ rk[off + 5];
                rk[off + 7] = rk[off + 3] ^ rk[off + 6];
                i += 1;
                if i == 10 {
                    return 0;
                }
                off += 4;
            }
        }

        rk[4] = get_u32(user_key.add(16));
        rk[5] = get_u32(user_key.add(20));
        if bits == 192 {
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 5];
                rk[off + 6] = rk[off]
                    ^ ((AES_SBOX[((temp >> 16) & 0xff) as usize] as u32) << 24)
                    ^ ((AES_SBOX[((temp >> 8) & 0xff) as usize] as u32) << 16)
                    ^ ((AES_SBOX[(temp & 0xff) as usize] as u32) << 8)
                    ^ (AES_SBOX[(temp >> 24) as usize] as u32)
                    ^ AES_RCON[i];
                rk[off + 7] = rk[off + 1] ^ rk[off + 6];
                rk[off + 8] = rk[off + 2] ^ rk[off + 7];
                rk[off + 9] = rk[off + 3] ^ rk[off + 8];
                i += 1;
                if i == 8 {
                    return 0;
                }
                rk[off + 10] = rk[off + 4] ^ rk[off + 9];
                rk[off + 11] = rk[off + 5] ^ rk[off + 10];
                off += 6;
            }
        }

        rk[6] = get_u32(user_key.add(24));
        rk[7] = get_u32(user_key.add(28));
        if bits == 256 {
            let mut i = 0usize;
            let mut off = 0usize;
            loop {
                let temp = rk[off + 7];
                rk[off + 8] = rk[off]
                    ^ ((AES_SBOX[((temp >> 16) & 0xff) as usize] as u32) << 24)
                    ^ ((AES_SBOX[((temp >> 8) & 0xff) as usize] as u32) << 16)
                    ^ ((AES_SBOX[(temp & 0xff) as usize] as u32) << 8)
                    ^ (AES_SBOX[(temp >> 24) as usize] as u32)
                    ^ AES_RCON[i];
                rk[off + 9] = rk[off + 1] ^ rk[off + 8];
                rk[off + 10] = rk[off + 2] ^ rk[off + 9];
                rk[off + 11] = rk[off + 3] ^ rk[off + 10];
                i += 1;
                if i == 7 {
                    return 0;
                }
                let temp = rk[off + 11];
                rk[off + 12] = rk[off + 4]
                    ^ ((AES_SBOX[(temp >> 24) as usize] as u32) << 24)
                    ^ ((AES_SBOX[((temp >> 16) & 0xff) as usize] as u32) << 16)
                    ^ ((AES_SBOX[((temp >> 8) & 0xff) as usize] as u32) << 8)
                    ^ (AES_SBOX[(temp & 0xff) as usize] as u32);
                rk[off + 13] = rk[off + 5] ^ rk[off + 12];
                rk[off + 14] = rk[off + 6] ^ rk[off + 13];
                rk[off + 15] = rk[off + 7] ^ rk[off + 14];
                off += 8;
            }
        }
        0
    }
}

/// Byte-swap the live words of a schedule, so the stored bytes match the authority's perlasm
/// `AES_KEY` rather than the C `GETU32` convention. `RT-CIPHER` observes the difference.
///
/// # Safety
/// `key` must be a live schedule whose `rounds` was just set.
unsafe fn bswap_schedule(key: *mut AesKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let rounds = (*key).rounds as usize;
        for i in 0..4 * (rounds + 1) {
            (*key).rd_key[i] = (*key).rd_key[i].swap_bytes();
        }
    }
}

/// `int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)` —
/// `crypto/aes/aes_core.c:3485-3564`, the `AES_ASM` branch (the one whose `AES_KEY` layout is
/// `rd_key[4*(AES_MAXNR+1)]`).
///
/// # Safety
/// `userKey` readable for `bits / 8` bytes and `key` writable, or either NULL (the authority
/// returns -1).
#[no_mangle]
pub unsafe extern "C" fn AES_set_encrypt_key(
    user_key: *const u8,
    bits: c_int,
    key: *mut AesKey,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let rc = aes_expand(user_key, bits, key);
        if rc < 0 {
            return rc;
        }
        bswap_schedule(key);
        0
    }
}

/// `int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)` —
/// `crypto/aes/aes_core.c:3569-3616`.
///
/// # Safety
/// As [`AES_set_encrypt_key`].
#[no_mangle]
pub unsafe extern "C" fn AES_set_decrypt_key(
    user_key: *const u8,
    bits: c_int,
    key: *mut AesKey,
) -> c_int {
    // SAFETY: the caller's contract; `AES_set_encrypt_key` writes only within `key`.
    unsafe {
        let status = aes_expand(user_key, bits, key);
        if status < 0 {
            return status;
        }
        let rk = &mut (*key).rd_key;
        let rounds = (*key).rounds as usize;

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
        bswap_schedule(key);
        0
    }
}

/// `void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)` —
/// FIPS-197 §5.1, the byte-oriented round.
///
/// # Safety
/// `in` readable for sixteen bytes, `out` writable for sixteen, `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn AES_encrypt(input: *const u8, out: *mut u8, key: *const AesKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut state = [0u8; 16];
        ptr::copy_nonoverlapping(input, state.as_mut_ptr(), 16);
        let rk = &(*key).rd_key;
        let rounds = (*key).rounds as usize;

        add_round_key(&mut state, rk, 0);
        for round in 1..rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, rk, round);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, rk, rounds);

        ptr::copy_nonoverlapping(state.as_ptr(), out, 16);
    }
}

/// `void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)` —
/// FIPS-197 §5.3.
///
/// # Safety
/// As [`AES_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_decrypt(input: *const u8, out: *mut u8, key: *const AesKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut state = [0u8; 16];
        ptr::copy_nonoverlapping(input, state.as_mut_ptr(), 16);
        let rk = &(*key).rd_key;
        let rounds = (*key).rounds as usize;

        add_round_key(&mut state, rk, 0);
        for round in 1..rounds {
            inv_sub_bytes(&mut state);
            inv_shift_rows(&mut state);
            inv_mix_columns(&mut state);
            add_round_key(&mut state, rk, round);
        }
        inv_sub_bytes(&mut state);
        inv_shift_rows(&mut state);
        add_round_key(&mut state, rk, rounds);

        ptr::copy_nonoverlapping(state.as_ptr(), out, 16);
    }
}

/// The `block128_f` view of [`AES_encrypt`], for the generic mode functions.
///
/// # Safety
/// The mode function's own contract.
unsafe extern "C" fn aes_encrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the mode functions pass a key schedule they were given.
    unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
}

/// The `block128_f` view of [`AES_decrypt`].
///
/// # Safety
/// The mode function's own contract.
unsafe extern "C" fn aes_decrypt_block(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the mode functions pass a key schedule they were given.
    unsafe { AES_decrypt(input, out, key.cast::<AesKey>()) }
}

/// `const char *AES_options(void)` — `crypto/aes/aes_misc.c:20-28`. The authority's perlasm
/// object answers `aes(partial)` (measured from `libcrypto.so.3`'s strings).
///
/// # Safety
/// None; the returned pointer is a `'static` C string.
#[no_mangle]
pub unsafe extern "C" fn AES_options() -> *const c_char {
    c"aes(partial)".as_ptr()
}

/// `void AES_ecb_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key,
/// const int enc)` — `crypto/aes/aes_ecb.c:24-36`.
///
/// # Safety
/// As [`AES_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_ecb_encrypt(
    input: *const u8,
    out: *mut u8,
    key: *const AesKey,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if enc == AES_ENCRYPT {
            AES_encrypt(input, out, key);
        } else {
            AES_decrypt(input, out, key);
        }
    }
}

/// `void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const
/// AES_KEY *key, unsigned char *ivec, const int enc)` — `crypto/aes/aes_cbc.c:24-34`.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_cbc_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const AesKey,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract; `key` is a live schedule the block function reads.
    unsafe {
        if enc != 0 {
            CRYPTO_cbc128_encrypt(input, out, len, key.cast(), ivec, aes_encrypt_block);
        } else {
            CRYPTO_cbc128_decrypt(input, out, len, key.cast(), ivec, aes_decrypt_block);
        }
    }
}

/// `void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, unsigned char *ivec, int *num, const int enc)` — `crypto/aes/aes_cfb.c:29-36`.
///
/// # Safety
/// As [`CRYPTO_cfb128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_cfb128_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_encrypt(
            input,
            out,
            length,
            key.cast(),
            ivec,
            num,
            enc,
            aes_encrypt_block,
        );
    }
}

/// `void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, unsigned char *ivec, int *num, const int enc)` — `crypto/aes/aes_cfb.c:39-46`.
///
/// `length` is a **bit** count.
///
/// # Safety
/// As [`CRYPTO_cfb128_1_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_cfb1_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_1_encrypt(
            input,
            out,
            length,
            key.cast(),
            ivec,
            num,
            enc,
            aes_encrypt_block,
        );
    }
}

/// `void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, unsigned char *ivec, int *num, const int enc)` — `crypto/aes/aes_cfb.c:48-55`.
///
/// # Safety
/// As [`CRYPTO_cfb128_8_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_cfb8_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_8_encrypt(
            input,
            out,
            length,
            key.cast(),
            ivec,
            num,
            enc,
            aes_encrypt_block,
        );
    }
}

/// `void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, unsigned char *ivec, int *num)` — `crypto/aes/aes_ofb.c:24-31`.
///
/// # Safety
/// As [`CRYPTO_ofb128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_ofb128_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ofb128_encrypt(input, out, length, key.cast(), ivec, num, aes_encrypt_block);
    }
}

/// `void AES_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, unsigned char *ivec, const int enc)` — `crypto/aes/aes_ige.c:48-163`.
///
/// The IV is **two** blocks long. The authority takes a word-oriented fast arm when
/// `in != out` and a buffered arm when `in == out`; both compute the same bytes, and this
/// transcription keeps the two arms so the aliasing behaviour is identical.
///
/// # Safety
/// `in` and `out` readable/writable for `length` bytes (a multiple of sixteen), `ivec`
/// writable for thirty-two, `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn AES_ige_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract; every pointer stays inside the regions it names.
    unsafe {
        if length == 0 {
            return;
        }
        let mut len = length / AES_BLOCK_SIZE;
        let mut input = input;
        let mut out = out;

        if enc == AES_ENCRYPT {
            if input != out {
                let mut ivp: *const u8 = ivec;
                let mut iv2p: *const u8 = ivec.add(AES_BLOCK_SIZE);
                while len != 0 {
                    for n in 0..16 {
                        *out.add(n) = *input.add(n) ^ *ivp.add(n);
                    }
                    AES_encrypt(out, out, key);
                    for n in 0..16 {
                        *out.add(n) ^= *iv2p.add(n);
                    }
                    ivp = out;
                    iv2p = input;
                    len -= 1;
                    input = input.add(16);
                    out = out.add(16);
                }
                ptr::copy(ivp, ivec, 16);
                ptr::copy(iv2p, ivec.add(16), 16);
            } else {
                let mut iv = [0u8; 16];
                let mut iv2 = [0u8; 16];
                ptr::copy_nonoverlapping(ivec, iv.as_mut_ptr(), 16);
                ptr::copy_nonoverlapping(ivec.add(16), iv2.as_mut_ptr(), 16);
                while len != 0 {
                    let mut tmp = [0u8; 16];
                    ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), 16);
                    let mut tmp2 = [0u8; 16];
                    for n in 0..16 {
                        tmp2[n] = tmp[n] ^ iv[n];
                    }
                    AES_encrypt(tmp2.as_ptr(), tmp2.as_mut_ptr(), key);
                    for n in 0..16 {
                        tmp2[n] ^= iv2[n];
                    }
                    ptr::copy_nonoverlapping(tmp2.as_ptr(), out, 16);
                    iv = tmp2;
                    iv2 = tmp;
                    len -= 1;
                    input = input.add(16);
                    out = out.add(16);
                }
                ptr::copy_nonoverlapping(iv.as_ptr(), ivec, 16);
                ptr::copy_nonoverlapping(iv2.as_ptr(), ivec.add(16), 16);
            }
        } else if input != out {
            let mut ivp: *const u8 = ivec;
            let mut iv2p: *const u8 = ivec.add(AES_BLOCK_SIZE);
            while len != 0 {
                let mut tmp = [0u8; 16];
                ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), 16);
                for (n, t) in tmp.iter_mut().enumerate() {
                    *t ^= *iv2p.add(n);
                }
                AES_decrypt(tmp.as_ptr(), out, key);
                for n in 0..16 {
                    *out.add(n) ^= *ivp.add(n);
                }
                ivp = input;
                iv2p = out;
                len -= 1;
                input = input.add(16);
                out = out.add(16);
            }
            ptr::copy(ivp, ivec, 16);
            ptr::copy(iv2p, ivec.add(16), 16);
        } else {
            let mut iv = [0u8; 16];
            let mut iv2 = [0u8; 16];
            ptr::copy_nonoverlapping(ivec, iv.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(ivec.add(16), iv2.as_mut_ptr(), 16);
            while len != 0 {
                let mut tmp = [0u8; 16];
                ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), 16);
                let tmp2 = tmp;
                for (n, x) in iv2.iter().enumerate() {
                    tmp[n] ^= *x;
                }
                AES_decrypt(tmp.as_ptr(), tmp.as_mut_ptr(), key);
                for (n, x) in iv.iter().enumerate() {
                    tmp[n] ^= *x;
                }
                ptr::copy_nonoverlapping(tmp.as_ptr(), out, 16);
                iv = tmp2;
                iv2 = tmp;
                len -= 1;
                input = input.add(16);
                out = out.add(16);
            }
            ptr::copy_nonoverlapping(iv.as_ptr(), ivec, 16);
            ptr::copy_nonoverlapping(iv2.as_ptr(), ivec.add(16), 16);
        }
    }
}

/// `void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length, const
/// AES_KEY *key, const AES_KEY *key2, const unsigned char *ivec, const int enc)` —
/// `crypto/aes/aes_ige.c:180-294`.
///
/// `key2` is accepted and ignored: the authority's documented bug, reproduced deliberately.
///
/// # Safety
/// As [`AES_ige_encrypt`], with `ivec` readable for sixty-four.
#[no_mangle]
pub unsafe extern "C" fn AES_bi_ige_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const AesKey,
    _key2: *const AesKey,
    ivec: *const u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract; `key2` is never read.
    unsafe {
        if enc == AES_ENCRYPT {
            let mut iv = [0u8; 16];
            let mut iv2 = [0u8; 16];
            ptr::copy_nonoverlapping(ivec, iv.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(ivec.add(16), iv2.as_mut_ptr(), 16);
            let mut input = input;
            let mut out = out;
            let mut len = length;
            while len >= 16 {
                for (n, x) in iv.iter().enumerate() {
                    *out.add(n) = *input.add(n) ^ *x;
                }
                AES_encrypt(out, out, key);
                for (n, x) in iv2.iter().enumerate() {
                    *out.add(n) ^= *x;
                }
                iv.copy_from_slice(core::slice::from_raw_parts(out, 16));
                iv2.copy_from_slice(core::slice::from_raw_parts(input, 16));
                len -= 16;
                input = input.add(16);
                out = out.add(16);
            }

            ptr::copy_nonoverlapping(ivec.add(32), iv.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(ivec.add(48), iv2.as_mut_ptr(), 16);
            len = length;
            while len >= 16 {
                out = out.sub(16);
                let mut tmp = [0u8; 16];
                ptr::copy_nonoverlapping(out, tmp.as_mut_ptr(), 16);
                for (n, x) in iv.iter().enumerate() {
                    *out.add(n) ^= *x;
                }
                AES_encrypt(out, out, key);
                for (n, x) in iv2.iter().enumerate() {
                    *out.add(n) ^= *x;
                }
                iv.copy_from_slice(core::slice::from_raw_parts(out, 16));
                iv2 = tmp;
                len -= 16;
            }
        } else {
            let mut iv = [0u8; 16];
            let mut iv2 = [0u8; 16];
            ptr::copy_nonoverlapping(ivec.add(32), iv.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(ivec.add(48), iv2.as_mut_ptr(), 16);
            let mut input = input.add(length);
            let mut out = out.add(length);
            let mut len = length;
            while len >= 16 {
                input = input.sub(16);
                out = out.sub(16);
                let mut tmp = [0u8; 16];
                let mut tmp2 = [0u8; 16];
                ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), 16);
                tmp2.copy_from_slice(&tmp);
                for (n, x) in iv2.iter().enumerate() {
                    tmp[n] ^= *x;
                }
                AES_decrypt(tmp.as_ptr(), out, key);
                for (n, x) in iv.iter().enumerate() {
                    *out.add(n) ^= *x;
                }
                iv = tmp2;
                iv2.copy_from_slice(core::slice::from_raw_parts(out, 16));
                len -= 16;
            }

            ptr::copy_nonoverlapping(ivec, iv.as_mut_ptr(), 16);
            ptr::copy_nonoverlapping(ivec.add(16), iv2.as_mut_ptr(), 16);
            len = length;
            while len >= 16 {
                let mut tmp = [0u8; 16];
                let mut tmp2 = [0u8; 16];
                ptr::copy_nonoverlapping(out, tmp.as_mut_ptr(), 16);
                tmp2.copy_from_slice(&tmp);
                for (n, x) in iv2.iter().enumerate() {
                    tmp[n] ^= *x;
                }
                AES_decrypt(tmp.as_ptr(), out, key);
                for (n, x) in iv.iter().enumerate() {
                    *out.add(n) ^= *x;
                }
                iv = tmp2;
                iv2.copy_from_slice(core::slice::from_raw_parts(out, 16));
                len -= 16;
                input = input.add(16);
                out = out.add(16);
            }
        }
    }
}

/// `int AES_wrap_key(AES_KEY *key, const unsigned char *iv, unsigned char *out, const
/// unsigned char *in, unsigned int inlen)` — `crypto/aes/aes_wrap.c:28-33`, a delegate to
/// `CRYPTO_128_wrap` (8.3's export, whose algorithm lives in [`crate::modes::wrap`]).
///
/// # Safety
/// As [`crate::modes::wrap::wrap128`].
#[no_mangle]
pub unsafe extern "C" fn AES_wrap_key(
    key: *mut AesKey,
    iv: *const u8,
    out: *mut u8,
    input: *const u8,
    inlen: u32,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        wrap128(
            key.cast(),
            iv,
            out,
            input,
            inlen as usize,
            aes_encrypt_block,
        ) as c_int
    }
}

/// `int AES_unwrap_key(AES_KEY *key, const unsigned char *iv, unsigned char *out, const
/// unsigned char *in, unsigned int inlen)` — `crypto/aes/aes_wrap.c:35-41`.
///
/// # Safety
/// As [`crate::modes::wrap::unwrap128`].
#[no_mangle]
pub unsafe extern "C" fn AES_unwrap_key(
    key: *mut AesKey,
    iv: *const u8,
    out: *mut u8,
    input: *const u8,
    inlen: u32,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        unwrap128(
            key.cast(),
            iv,
            out,
            input,
            inlen as usize,
            aes_decrypt_block,
        ) as c_int
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 §C.1 — AES-128 over `00112233445566778899aabbccddeeff`.
    const FIPS_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const FIPS_PT: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn schedule(key: &[u8], bits: c_int) -> AesKey {
        let mut k = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits, &mut k), 0);
        }
        k
    }

    #[test]
    fn fips197_c1_c2_c3() {
        let cases: [(&[u8], c_int, &str); 3] = [
            (&FIPS_KEY, 128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                ],
                192,
                "dda97ca4864cdfe06eaf70a0ec0d7191",
            ),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                256,
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ];
        for (key, bits, want) in cases {
            let k = schedule(key, bits);
            let mut out = [0u8; 16];
            let hex: String;
            // SAFETY: live locals.
            unsafe {
                AES_encrypt(FIPS_PT.as_ptr(), out.as_mut_ptr(), &k);
                hex = out.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(hex, want);
                let mut dec = [0u8; 16];
                let mut dk = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits, &mut dk), 0);
                AES_decrypt(out.as_ptr(), dec.as_mut_ptr(), &dk);
                assert_eq!(dec, FIPS_PT);
            }
        }
    }

    #[test]
    fn wrap_and_unwrap_round_trip() {
        let k = schedule(&FIPS_KEY, 128);
        let kek = [0u8; 16];
        let _ = kek;
        let mut wrapped = [0u8; 24];
        let plain = [0x00u8; 16];
        // The wrap arm uses `AES_encrypt` and the unwrap arm `AES_decrypt`, so the caller keeps
        // the matching schedule for each — exactly the authority's contract.
        let mut dk = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            let n = AES_wrap_key(
                &k as *const AesKey as *mut AesKey,
                ptr::null(),
                wrapped.as_mut_ptr(),
                plain.as_ptr(),
                16,
            );
            assert_eq!(n, 24);
            assert_eq!(AES_set_decrypt_key(FIPS_KEY.as_ptr(), 128, &mut dk), 0);
            let mut unwrapped = [0u8; 16];
            let m = AES_unwrap_key(
                &dk as *const AesKey as *mut AesKey,
                ptr::null(),
                unwrapped.as_mut_ptr(),
                wrapped.as_ptr(),
                24,
            );
            assert_eq!(m, 16);
            assert_eq!(unwrapped, plain);
        }
    }

    /// RFC 5649 §6's two worked examples, exercised through the exported wrappers that
    /// `crypto/modes/wrap128.c` provides and `AES_wrap_key` does not.
    #[test]
    fn rfc5649_wrap_pad_vectors() {
        const KEK: [u8; 24] = [
            0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1,
            0x6e, 0xa1, 0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8,
        ];
        const PT20: [u8; 20] = [
            0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89,
            0x41, 0x15, 0x50, 0x68, 0xf7, 0x38,
        ];
        const PT7: [u8; 7] = [0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69];

        fn hex_of(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }

        let k = schedule(&KEK, 192);
        let mut dk = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(AES_set_decrypt_key(KEK.as_ptr(), 192, &mut dk), 0);

            let mut wrapped = [0u8; 32];
            let n = crate::modes::wrap::CRYPTO_128_wrap_pad(
                &k as *const AesKey as *mut c_void,
                ptr::null(),
                wrapped.as_mut_ptr(),
                PT20.as_ptr(),
                PT20.len(),
                aes_encrypt_block,
            );
            assert_eq!(n, 32);
            assert_eq!(
                hex_of(&wrapped[..n]),
                "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"
            );
            let mut back = [0u8; 20];
            let m = crate::modes::wrap::CRYPTO_128_unwrap_pad(
                &dk as *const AesKey as *mut c_void,
                ptr::null(),
                back.as_mut_ptr(),
                wrapped.as_ptr(),
                n,
                aes_decrypt_block,
            );
            assert_eq!(m, 20);
            assert_eq!(back, PT20);

            let n = crate::modes::wrap::CRYPTO_128_wrap_pad(
                &k as *const AesKey as *mut c_void,
                ptr::null(),
                wrapped.as_mut_ptr(),
                PT7.as_ptr(),
                PT7.len(),
                aes_encrypt_block,
            );
            assert_eq!(n, 16);
            assert_eq!(hex_of(&wrapped[..n]), "afbeb0f07dfbf5419200f2ccb50bb24f");
            let mut back7 = [0u8; 8];
            let m = crate::modes::wrap::CRYPTO_128_unwrap_pad(
                &dk as *const AesKey as *mut c_void,
                ptr::null(),
                back7.as_mut_ptr(),
                wrapped.as_ptr(),
                n,
                aes_decrypt_block,
            );
            assert_eq!(m, 7);
            assert_eq!(back7[..7], PT7);
        }
    }
}
