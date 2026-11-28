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

use crate::digest::tables::AES_RCON;
use crate::modes::wrap::{unwrap128, wrap128};
use crate::modes::{
    CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt, CRYPTO_cfb128_8_encrypt,
    CRYPTO_cfb128_encrypt, CRYPTO_ofb128_encrypt,
};

mod portable;
#[cfg(test)]
mod reference;
#[cfg(test)]
mod research;

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

/// The AES bit in the first `OPENSSL_ia32cap` vector.
///
/// `OPENSSL_ia32cap`'s value is `[vec1][:vec2]`; a vector prefixed with `~` clears the named
/// bits. `AES` is `CPUID.(EAX=1).ECX` bit 25, i.e. bit 25 of the first vector. Only the clear
/// mask is modelled, because that is the form that forces the portable path; the authority's
/// value-set form and its other capability bits are not modelled (`RT-CPU-CAPABILITY`).
#[cfg(target_arch = "x86_64")]
fn ia32cap_aes_cleared(spec: Option<&str>) -> bool {
    let Some(first) = spec.and_then(|s| s.split(':').next()) else {
        return false;
    };
    let Some(mask) = first.strip_prefix('~') else {
        return false;
    };
    let mask = mask.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(mask, 16)
        .map(|m| m & (1u64 << 25) != 0)
        .unwrap_or(false)
}

/// The AES-NI dispatch predicate — the only runtime feature-detection site on this path.
///
/// `BOUNDARY_COVERED`: `is_x86_feature_detected!` is a cached CPUID read with no memory or
/// initialisation obligation; the `#[target_feature(enable = "aes")]` callees execute only
/// SSE2 moves (baseline on x86_64) and AES-NI instructions, so the single `aes` bit is the
/// whole precondition. The result is cached for the process, and `OPENSSL_ia32cap`'s AES clear
/// mask overrides it to force the portable arm.
#[cfg(target_arch = "x86_64")]
fn aes_ni_available() -> bool {
    use std::sync::OnceLock;

    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let spec = std::env::var("OPENSSL_ia32cap").ok();
        if ia32cap_aes_cleared(spec.as_deref()) {
            return false;
        }
        std::is_x86_feature_detected!("aes")
    })
}

/// `SubWord(w)` and `RotWord(SubWord(w))` for the big-endian logical word `w`, via
/// `aeskeygenassist`.
///
/// `w` is a key-schedule word in the `GETU32` convention; the instruction operates on the
/// little-endian lane representation, so the word is byte-swapped in and both results are
/// byte-swapped out. No memory is indexed by `w`.
///
/// # Safety
/// The caller must have established the `aes` target feature.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn ni_subword_pair(w: u32) -> (u32, u32) {
    use core::arch::x86_64::*;

    // SAFETY: the caller establishes `aes`; the only memory touched is the local `lanes`.
    unsafe {
        let wb = w.swap_bytes() as i32;
        // The instruction reads 32-bit words X1 = lane 1 and X3 = lane 3, so the word is placed
        // in both; lane 0 then holds SubWord(w) and lane 1 RotWord(SubWord(w)).
        let x = _mm_set_epi32(wb, 0, wb, 0);
        let t = _mm_aeskeygenassist_si128::<0x00>(x);
        let mut lanes = [0u32; 4];
        _mm_storeu_si128(lanes.as_mut_ptr().cast(), t);
        (lanes[0].swap_bytes(), lanes[1].swap_bytes())
    }
}

/// The portable key expansion: read the caller's key into a local, then let the safe
/// portable module produce the logical `GETU32` words. The public entry points
/// byte-swap the result on the way out, because the authority's perlasm key schedule
/// stores each word in memory order and `RT-CIPHER` observes it.
///
/// # Safety
/// `user_key` readable for `bits / 8` bytes and `key` writable, or either NULL.
unsafe fn aes_expand_portable(user_key: *const u8, bits: c_int, key: *mut AesKey) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if user_key.is_null() || key.is_null() {
            return -1;
        }
        let n: usize = match bits {
            128 => 16,
            192 => 24,
            256 => 32,
            _ => return -2,
        };
        let mut key_bytes = [0u8; 32];
        ptr::copy_nonoverlapping(user_key, key_bytes.as_mut_ptr(), n);
        match portable::expand_encrypt_key(&key_bytes[..n], bits) {
            Some((words, rounds)) => {
                (*key).rd_key = words;
                (*key).rounds = rounds as c_int;
                0
            }
            None => -2,
        }
    }
}

/// The AES-NI key expansion: the same recurrence as [`aes_expand_portable`], with every
/// `SubWord`/`RotWord` taken from `aeskeygenassist` instead of the S-box table.
///
/// The output is the same big-endian logical schedule [`aes_expand_portable`] produces, so
/// [`bswap_schedule`] and the decrypt transform that consume it are unchanged.
///
/// # Safety
/// `user_key` readable for `bits / 8` bytes and `key` writable, or either NULL; the caller must
/// have established the `aes` target feature.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn aes_expand_ni(user_key: *const u8, bits: c_int, key: *mut AesKey) -> c_int {
    // SAFETY: the caller's contract; every read/write is within `user_key`/`key`.
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
                let (_, rot) = ni_subword_pair(rk[off + 3]);
                rk[off + 4] = rk[off] ^ rot ^ AES_RCON[i];
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
                let (_, rot) = ni_subword_pair(rk[off + 5]);
                rk[off + 6] = rk[off] ^ rot ^ AES_RCON[i];
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
                let (_, rot) = ni_subword_pair(rk[off + 7]);
                rk[off + 8] = rk[off] ^ rot ^ AES_RCON[i];
                rk[off + 9] = rk[off + 1] ^ rk[off + 8];
                rk[off + 10] = rk[off + 2] ^ rk[off + 9];
                rk[off + 11] = rk[off + 3] ^ rk[off + 10];
                i += 1;
                if i == 7 {
                    return 0;
                }
                let (sub, _) = ni_subword_pair(rk[off + 11]);
                rk[off + 12] = rk[off + 4] ^ sub;
                rk[off + 13] = rk[off + 5] ^ rk[off + 12];
                rk[off + 14] = rk[off + 6] ^ rk[off + 13];
                rk[off + 15] = rk[off + 7] ^ rk[off + 14];
                off += 8;
            }
        }
        0
    }
}

/// Dispatch the key expansion to the AES-NI arm when it is available, else to the portable
/// table transcription.
///
/// # Safety
/// `user_key` readable for `bits / 8` bytes and `key` writable, or either NULL.
unsafe fn aes_expand(user_key: *const u8, bits: c_int, key: *mut AesKey) -> c_int {
    #[cfg(target_arch = "x86_64")]
    if aes_ni_available() {
        // SAFETY: `aes_ni_available` establishes the `aes` target feature, and the pointer
        // contract is this function's own, unchanged for the callee.
        return unsafe { aes_expand_ni(user_key, bits, key) };
    }

    // SAFETY: the caller's contract, unchanged for the portable transcription.
    unsafe { aes_expand_portable(user_key, bits, key) }
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

/// One AES-128/192/256 block through the AES-NI round instructions.
///
/// The stored schedule is the authority's perlasm memory order, so each round key is one
/// unaligned sixteen-byte load; the round count comes from the schedule, so all three key
/// sizes share this carrier.
///
/// # Safety
/// The caller must have established the `aes` target feature; `in` readable for sixteen bytes,
/// `out` writable for sixteen, `key` a live schedule.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn aes_encrypt_ni(input: *const u8, out: *mut u8, key: *const AesKey) {
    use core::arch::x86_64::*;

    // SAFETY: the caller's contract gives the extents; `rk` is within the live schedule.
    unsafe {
        let rk = (*key).rd_key.as_ptr();
        let rounds = (*key).rounds as usize;
        let mut state = _mm_loadu_si128(input.cast());
        state = _mm_xor_si128(state, _mm_loadu_si128(rk.cast()));
        let mut r = 1usize;
        while r < rounds {
            state = _mm_aesenc_si128(state, _mm_loadu_si128(rk.add(4 * r).cast()));
            r += 1;
        }
        state = _mm_aesenclast_si128(state, _mm_loadu_si128(rk.add(4 * rounds).cast()));
        _mm_storeu_si128(out.cast(), state);
    }
}

/// `void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)` —
/// FIPS-197 §5.1, dispatched to AES-NI when the CPU has it.
///
/// # Safety
/// `in` readable for sixteen bytes, `out` writable for sixteen, `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn AES_encrypt(input: *const u8, out: *mut u8, key: *const AesKey) {
    #[cfg(target_arch = "x86_64")]
    if aes_ni_available() {
        // SAFETY: `aes_ni_available` establishes the `aes` target feature; the pointer contract
        // is this function's own, unchanged for the callee.
        unsafe { aes_encrypt_ni(input, out, key) };
        return;
    }

    // SAFETY: the caller's contract, unchanged for the portable transcription.
    unsafe { aes_encrypt_portable(input, out, key) }
}

/// The portable constant-pattern FIPS-197 §5.1 round, the fallback for CPUs without
/// AES-NI. The state copy is the only pointer work; the round itself is the safe
/// [`portable`] implementation.
///
/// # Safety
/// As [`AES_encrypt`].
unsafe fn aes_encrypt_portable(input: *const u8, out: *mut u8, key: *const AesKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut state = [0u8; 16];
        ptr::copy_nonoverlapping(input, state.as_mut_ptr(), 16);
        portable::encrypt_block(&mut state, &(*key).rd_key, (*key).rounds as usize);
        ptr::copy_nonoverlapping(state.as_ptr(), out, 16);
    }
}

/// One AES-128/192/256 inverse block through the AES-NI round instructions.
///
/// [`AES_set_decrypt_key`] stores the equivalent-inverse-cipher schedule (blocks reversed,
/// inner blocks `InvMixColumns`-transformed), which is exactly the order `aesdec` expects, so
/// this reads the schedule forward from slot 0.
///
/// # Safety
/// The caller must have established the `aes` target feature; `in` readable for sixteen bytes,
/// `out` writable for sixteen, `key` a live decryption schedule.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn aes_decrypt_ni(input: *const u8, out: *mut u8, key: *const AesKey) {
    use core::arch::x86_64::*;

    // SAFETY: the caller's contract gives the extents; `rk` is within the live schedule.
    unsafe {
        let rk = (*key).rd_key.as_ptr();
        let rounds = (*key).rounds as usize;
        let mut state = _mm_loadu_si128(input.cast());
        state = _mm_xor_si128(state, _mm_loadu_si128(rk.cast()));
        let mut r = 1usize;
        while r < rounds {
            state = _mm_aesdec_si128(state, _mm_loadu_si128(rk.add(4 * r).cast()));
            r += 1;
        }
        state = _mm_aesdeclast_si128(state, _mm_loadu_si128(rk.add(4 * rounds).cast()));
        _mm_storeu_si128(out.cast(), state);
    }
}

/// `void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)` —
/// FIPS-197 §5.3, dispatched to AES-NI when the CPU has it.
///
/// # Safety
/// As [`AES_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn AES_decrypt(input: *const u8, out: *mut u8, key: *const AesKey) {
    #[cfg(target_arch = "x86_64")]
    if aes_ni_available() {
        // SAFETY: `aes_ni_available` establishes the `aes` target feature; the pointer contract
        // is this function's own, unchanged for the callee.
        unsafe { aes_decrypt_ni(input, out, key) };
        return;
    }

    // SAFETY: the caller's contract, unchanged for the portable transcription.
    unsafe { aes_decrypt_portable(input, out, key) }
}

/// The portable constant-pattern FIPS-197 §5.3 round, the fallback for CPUs without
/// AES-NI.
///
/// # Safety
/// As [`AES_encrypt`].
unsafe fn aes_decrypt_portable(input: *const u8, out: *mut u8, key: *const AesKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut state = [0u8; 16];
        ptr::copy_nonoverlapping(input, state.as_mut_ptr(), 16);
        portable::decrypt_block(&mut state, &(*key).rd_key, (*key).rounds as usize);
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

                // The portable circuit carrier is checked against the same known-answer
                // vectors directly, not only through the dispatch that takes AES-NI here.
                let mut pout = [0u8; 16];
                aes_encrypt_portable(FIPS_PT.as_ptr(), pout.as_mut_ptr(), &k);
                let phex: String = pout.iter().map(|b| format!("{b:02x}")).collect();
                assert_eq!(phex, want, "portable FIPS encrypt bits={bits}");
                let mut pdec = [0u8; 16];
                aes_decrypt_portable(out.as_ptr(), pdec.as_mut_ptr(), &dk);
                assert_eq!(pdec, FIPS_PT, "portable FIPS decrypt bits={bits}");
            }
        }
    }

    /// The AES-NI expansion and round are the same function as the portable transcription: for
    /// random keys of all three sizes the two schedules are byte-identical, and the two round
    /// carriers agree on random blocks in both directions.
    #[cfg(all(test, target_arch = "x86_64"))]
    #[test]
    fn aes_ni_matches_portable() {
        if !std::is_x86_feature_detected!("aes") {
            return;
        }
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 32) as u8
        };
        for bits in [128u32, 192, 256] {
            let n = (bits / 8) as usize;
            for _ in 0..64 {
                let mut key = [0u8; 32];
                let mut block = [0u8; 16];
                for b in &mut key[..n] {
                    *b = next();
                }
                for b in &mut block {
                    *b = next();
                }

                let mut kp = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                let mut kn = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals; the feature predicate above establishes `aes` for the
                // NI callee, and the pointer extents are live arrays.
                unsafe {
                    assert_eq!(aes_expand_portable(key.as_ptr(), bits as c_int, &mut kp), 0);
                    assert_eq!(aes_expand_ni(key.as_ptr(), bits as c_int, &mut kn), 0);
                }
                assert_eq!(kp.rounds, kn.rounds);
                assert_eq!(kp.rd_key, kn.rd_key, "schedule bits={bits}");

                let mut ek = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals.
                unsafe {
                    assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits as c_int, &mut ek), 0);
                }
                let mut p = [0u8; 16];
                let mut q = [0u8; 16];
                // SAFETY: live locals; feature established above.
                unsafe {
                    aes_encrypt_portable(block.as_ptr(), p.as_mut_ptr(), &ek);
                    aes_encrypt_ni(block.as_ptr(), q.as_mut_ptr(), &ek);
                }
                assert_eq!(p, q, "encrypt bits={bits}");

                let mut dk = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals.
                unsafe {
                    assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits as c_int, &mut dk), 0);
                }
                let mut r = [0u8; 16];
                let mut s = [0u8; 16];
                // SAFETY: live locals; feature established above.
                unsafe {
                    aes_decrypt_portable(p.as_ptr(), r.as_mut_ptr(), &dk);
                    aes_decrypt_ni(p.as_ptr(), s.as_mut_ptr(), &dk);
                }
                assert_eq!(r, s, "decrypt bits={bits}");
                assert_eq!(r, block, "round-trip bits={bits}");
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
            // `out` must be sized for the *padded* plaintext (`padded_len = inlen - 8`), and for
            // the full `inlen` the authority cleanses on every failure path
            // (`crypto/modes/wrap128.c:291,303,317,327`); `unwrap_pad`'s own # Safety contract
            // above says `inlen`. A 20-byte buffer held only the unpadded plaintext and ASan
            // caught `crypto_128_unwrap_raw`'s 24-byte `memmove` (`wrap128.c:112`) overflowing it.
            let mut back = [0u8; 32];
            let m = crate::modes::wrap::CRYPTO_128_unwrap_pad(
                &dk as *const AesKey as *mut c_void,
                ptr::null(),
                back.as_mut_ptr(),
                wrapped.as_ptr(),
                n,
                aes_decrypt_block,
            );
            assert_eq!(m, 20);
            assert_eq!(back[..20], PT20);

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
            // As above: `unwrap_pad` needs `inlen` (16) writable, of which 8 carry the padded
            // plaintext; a bare 8-byte buffer was only enough for the success path's write.
            let mut back7 = [0u8; 16];
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

    /// Deterministic byte stream for the differential key/block population.
    fn next_byte(seed: &mut u64) -> u8 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 32) as u8
    }

    fn must_expand(res: Option<([u32; 60], usize)>) -> ([u32; 60], usize) {
        match res {
            Some(v) => v,
            None => unreachable!("bits is 128, 192 or 256"),
        }
    }

    /// All-zero, all-ones, every single-bit key, then random keys.
    fn keys_for(bits: usize) -> Vec<Vec<u8>> {
        let n = bits / 8;
        let mut keys = Vec::new();
        keys.push(vec![0x00; n]);
        keys.push(vec![0xff; n]);
        for bit in 0..bits {
            let mut k = vec![0u8; n];
            k[bit / 8] = 1 << (bit % 8);
            keys.push(k);
        }
        let mut seed = 0x0f1e_2d3c_4b5a_6978u64 ^ bits as u64;
        for _ in 0..512 {
            let mut k = vec![0u8; n];
            for b in &mut k {
                *b = next_byte(&mut seed);
            }
            keys.push(k);
        }
        keys
    }

    fn bswapped(mut rk: [u32; 60], rounds: usize) -> [u32; 60] {
        for w in rk.iter_mut().take(4 * (rounds + 1)) {
            *w = w.swap_bytes();
        }
        rk
    }

    /// The authority's decrypt-schedule transform on logical words, transcribed here so
    /// the test can derive the expected bytes independently of `AES_set_decrypt_key`.
    fn decrypt_from_logical(mut rk: [u32; 60], rounds: usize) -> [u32; 60] {
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

    /// The circuit expansion is byte-identical to the table transcription for every
    /// key class, both schedules.
    #[test]
    fn portable_schedule_matches_reference_for_all_sizes() {
        for bits in [128usize, 192, 256] {
            for key in keys_for(bits) {
                let p = must_expand(portable::expand_encrypt_key(&key, bits as c_int));
                let r = must_expand(reference::expand_encrypt_key(&key, bits as c_int));
                assert_eq!(p, r, "encrypt schedule bits={bits} key={key:02x?}");

                let expect_dec = bswapped(decrypt_from_logical(r.0, r.1), r.1);

                let mut k = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals; the exported entry may take the AES-NI arm, whose
                // expansion the existing NI/portable test proves equal to the circuit.
                unsafe {
                    assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits as c_int, &mut k), 0);
                }
                assert_eq!(k.rounds, r.1 as c_int);
                assert_eq!(
                    k.rd_key, expect_dec,
                    "decrypt schedule bits={bits} key={key:02x?}"
                );
            }
        }
    }

    /// The exported encryption schedule bytes are unchanged from the reference.
    #[test]
    fn exported_encrypt_schedule_is_byte_identical_to_reference() {
        for bits in [128usize, 192, 256] {
            for key in keys_for(bits) {
                let r = must_expand(reference::expand_encrypt_key(&key, bits as c_int));
                let expect = bswapped(r.0, r.1);
                let mut k = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals.
                unsafe {
                    assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits as c_int, &mut k), 0);
                }
                assert_eq!(k.rounds, r.1 as c_int);
                assert_eq!(k.rd_key, expect, "bits={bits} key={key:02x?}");
            }
        }
    }

    /// Blocks from the portable circuit equal the table reference, and decrypt inverts
    /// encrypt, over the same key population.
    #[test]
    fn portable_block_matches_reference_and_round_trips() {
        let mut seed = 0x1357_9bdf_2468_ace0u64;
        for bits in [128usize, 192, 256] {
            for key in keys_for(bits) {
                let mut ek = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                let mut dk = AesKey {
                    rd_key: [0; 60],
                    rounds: 0,
                };
                // SAFETY: live locals.
                unsafe {
                    assert_eq!(AES_set_encrypt_key(key.as_ptr(), bits as c_int, &mut ek), 0);
                    assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits as c_int, &mut dk), 0);
                }
                for _ in 0..8 {
                    let mut pt = [0u8; 16];
                    for b in &mut pt {
                        *b = next_byte(&mut seed);
                    }
                    let mut got = [0u8; 16];
                    let mut want = pt;
                    // SAFETY: live locals; the reference is the table transcription.
                    unsafe {
                        aes_encrypt_portable(pt.as_ptr(), got.as_mut_ptr(), &ek);
                    }
                    reference::encrypt_block(&mut want, &ek.rd_key, ek.rounds as usize);
                    assert_eq!(got, want, "encrypt bits={bits} key={key:02x?}");

                    let mut back = [0u8; 16];
                    let mut want_dec = got;
                    // SAFETY: live locals.
                    unsafe {
                        aes_decrypt_portable(got.as_ptr(), back.as_mut_ptr(), &dk);
                    }
                    reference::decrypt_block(&mut want_dec, &dk.rd_key, dk.rounds as usize);
                    assert_eq!(back, want_dec, "decrypt bits={bits} key={key:02x?}");
                    assert_eq!(back, pt, "round trip bits={bits} key={key:02x?}");
                }
            }
        }
    }
}
