//! Phase 8.2 — `crypto/seed/`: SEED (KISA, RFC 4269).
//!
//! The authority has no perlasm arm for SEED; `crypto/seed/seed.c` is the implementation, and its
//! `SS[4][256]` S-box rows and sixteen `KC` golden-ratio constants are generated into
//! [`crate::cipher_tables::SEED_SS`]/[`crate::cipher_tables::SEED_KC`]. The twenty-four
//! `KEYSCHEDULE_UPDATE0`/`UPDATE1`/`KEYUPDATE_TEMP` expansions and the sixteen-round `E_SEED`
//! with its `G` function are transcribed.
//!
//! ## The word order is big-endian, and the output words are permuted
//!
//! `char2word`/`word2char` (`seed_local.h:47-54`) are big-endian, but `SEED_encrypt` writes
//! `x3,x4,x1,x2` — not `x1..x4` — to the output (`seed.c:533-536`), and `SEED_decrypt` the
//! same. That permutation is easy to drop because the round structure is symmetric; `RT-CIPHER`
//! observes both directions.
//!
//! ## The four mode wrappers delegate to `modes.h`
//!
//! `seed_cbc.c`, `seed_cfb.c` and `seed_ofb.c` are thin calls into `CRYPTO_cbc128_*`/
//! `CRYPTO_cfb128_encrypt`/`CRYPTO_ofb128_encrypt` with `SEED_encrypt`/`SEED_decrypt` as the
//! block function, so the mode arithmetic is [`crate::modes`]'s and only the block call is this
//! module's.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::cipher_tables::{SEED_KC, SEED_SS};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_encrypt,
    CRYPTO_ofb128_encrypt,
};

/// `SEED_BLOCK_SIZE` — `include/openssl/seed.h:55`.
pub const SEED_BLOCK_SIZE: usize = 16;
/// `SEED_KEY_LENGTH` — `include/openssl/seed.h:56`.
pub const SEED_KEY_LENGTH: usize = 16;

/// `SEED_KEY_SCHEDULE` — `include/openssl/seed.h:66-72`. `SEED_LONG` is undefined in this
/// profile (`AES_LONG` is not defined), so the words are `unsigned int`.
#[repr(C)]
pub struct SeedKeySchedule {
    /// `unsigned int data[32]`.
    pub data: [u32; 32],
}

/// `char2word(c, i)` — `crypto/seed/seed_local.h:47-48`, big-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn char2word(p: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p as u32) << 24)
            | ((*p.add(1) as u32) << 16)
            | ((*p.add(2) as u32) << 8)
            | (*p.add(3) as u32)
    }
}

/// `word2char(l, c)` — `crypto/seed/seed_local.h:50-54`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn word2char(v: u32, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = ((v >> 24) & 0xff) as u8;
        *p.add(1) = ((v >> 16) & 0xff) as u8;
        *p.add(2) = ((v >> 8) & 0xff) as u8;
        *p.add(3) = (v & 0xff) as u8;
    }
}

/// `G_FUNC(v)` — `crypto/seed/seed.c:60-61`, the non-small-footprint `SS` form.
#[inline]
fn g_func(v: u32) -> u32 {
    SEED_SS[0][(v & 0xff) as usize]
        ^ SEED_SS[1][((v >> 8) & 0xff) as usize]
        ^ SEED_SS[2][((v >> 16) & 0xff) as usize]
        ^ SEED_SS[3][((v >> 24) & 0xff) as usize]
}

/// `KEYSCHEDULE_UPDATE0` — `crypto/seed/seed_local.h:56-61`.
#[inline]
fn keyupdate0(x: &mut [u32; 4], kc: u32) -> (u32, u32) {
    let t0 = x[2];
    x[2] = (x[2] << 8) ^ (x[3] >> 24);
    x[3] = (x[3] << 8) ^ (t0 >> 24);
    (
        (x[0].wrapping_add(x[2])).wrapping_sub(kc),
        (x[1].wrapping_add(kc)).wrapping_sub(x[3]),
    )
}

/// `KEYSCHEDULE_UPDATE1` — `crypto/seed/seed_local.h:63-68`.
#[inline]
fn keyupdate1(x: &mut [u32; 4], kc: u32) -> (u32, u32) {
    let t0 = x[0];
    x[0] = (x[0] >> 8) ^ (x[1] << 24);
    x[1] = (x[1] >> 8) ^ (t0 << 24);
    (
        (x[0].wrapping_add(x[2])).wrapping_sub(kc),
        (x[1].wrapping_add(kc)).wrapping_sub(x[3]),
    )
}

/// `E_SEED(T0, T1, X1, X2, X3, X4, rbase)` — `crypto/seed/seed_local.h:98-109`.
#[inline]
fn e_seed(x: &mut [u32; 4], out: &mut [u32; 2], ks: &[u32; 32], rbase: usize) {
    // The macro's X1..X4 are the four words at the caller's chosen order; `x` is that view.
    let mut t0 = x[2] ^ ks[rbase];
    let mut t1 = x[3] ^ ks[rbase + 1];
    t1 ^= t0;
    t1 = g_func(t1);
    t0 = t0.wrapping_add(t1);
    t0 = g_func(t0);
    t1 = t1.wrapping_add(t0);
    t1 = g_func(t1);
    t0 = t0.wrapping_add(t1);
    out[0] = t0;
    out[1] = t1;
}

/// `void SEED_set_key(const unsigned char rawkey[SEED_KEY_LENGTH], SEED_KEY_SCHEDULE *ks)` —
/// `crypto/seed/seed.c:435-492`.
///
/// # Safety
/// `rawkey` readable for sixteen bytes; `ks` writable.
#[no_mangle]
pub unsafe extern "C" fn SEED_set_key(rawkey: *const u8, ks: *mut SeedKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [
            char2word(rawkey),
            char2word(rawkey.add(4)),
            char2word(rawkey.add(8)),
            char2word(rawkey.add(12)),
        ];
        let d = &mut (*ks).data;

        let t0 = x[0].wrapping_add(x[2]).wrapping_sub(SEED_KC[0]);
        let t1 = x[1].wrapping_sub(x[3]).wrapping_add(SEED_KC[0]);
        d[0] = g_func(t0);
        d[1] = g_func(t1);

        let (t0, t1) = keyupdate1(&mut x, SEED_KC[1]);
        d[2] = g_func(t0);
        d[3] = g_func(t1);

        let mut i = 2usize;
        while i < 16 {
            let (t0, t1) = keyupdate0(&mut x, SEED_KC[i]);
            d[i * 2] = g_func(t0);
            d[i * 2 + 1] = g_func(t1);
            let (t0, t1) = keyupdate1(&mut x, SEED_KC[i + 1]);
            d[i * 2 + 2] = g_func(t0);
            d[i * 2 + 3] = g_func(t1);
            i += 2;
        }
    }
}

/// `void SEED_encrypt(const unsigned char s[16], unsigned char d[16],
/// const SEED_KEY_SCHEDULE *ks)` — `crypto/seed/seed.c:494-537`.
///
/// # Safety
/// `s` readable for sixteen bytes; `d` writable for sixteen; `ks` live.
#[no_mangle]
pub unsafe extern "C" fn SEED_encrypt(s: *const u8, d: *mut u8, ks: *const SeedKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [
            char2word(s),
            char2word(s.add(4)),
            char2word(s.add(8)),
            char2word(s.add(12)),
        ];
        let k = &(*ks).data;
        let mut out = [0u32; 2];
        let mut i = 0usize;
        while i < 32 {
            // The macro alternates (X1,X2,X3,X4) and (X3,X4,X1,X2).
            if i.is_multiple_of(4) {
                let mut view = [x[0], x[1], x[2], x[3]];
                e_seed(&mut view, &mut out, k, i);
                x[0] ^= out[0];
                x[1] ^= out[1];
            } else {
                let mut view = [x[2], x[3], x[0], x[1]];
                e_seed(&mut view, &mut out, k, i);
                x[2] ^= out[0];
                x[3] ^= out[1];
            }
            i += 2;
        }
        word2char(x[2], d);
        word2char(x[3], d.add(4));
        word2char(x[0], d.add(8));
        word2char(x[1], d.add(12));
    }
}

/// `void SEED_decrypt(const unsigned char s[16], unsigned char d[16],
/// const SEED_KEY_SCHEDULE *ks)` — `crypto/seed/seed.c:539-582`.
///
/// # Safety
/// As [`SEED_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn SEED_decrypt(s: *const u8, d: *mut u8, ks: *const SeedKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [
            char2word(s),
            char2word(s.add(4)),
            char2word(s.add(8)),
            char2word(s.add(12)),
        ];
        let k = &(*ks).data;
        let mut out = [0u32; 2];
        let mut i = 30usize;
        loop {
            // The decrypt order is 30,28,…,0, alternating the same two views.
            if i % 4 == 2 {
                let mut view = [x[0], x[1], x[2], x[3]];
                e_seed(&mut view, &mut out, k, i);
                x[0] ^= out[0];
                x[1] ^= out[1];
            } else {
                let mut view = [x[2], x[3], x[0], x[1]];
                e_seed(&mut view, &mut out, k, i);
                x[2] ^= out[0];
                x[3] ^= out[1];
            }
            if i == 0 {
                break;
            }
            i -= 2;
        }
        word2char(x[2], d);
        word2char(x[3], d.add(4));
        word2char(x[0], d.add(8));
        word2char(x[1], d.add(12));
    }
}

/// `void SEED_ecb_encrypt(const unsigned char *in, unsigned char *out,
/// const SEED_KEY_SCHEDULE *ks, int enc)` — `crypto/seed/seed_ecb.c:18-25`.
///
/// # Safety
/// `in`/`out` sixteen bytes; `ks` live.
#[no_mangle]
pub unsafe extern "C" fn SEED_ecb_encrypt(
    input: *const u8,
    output: *mut u8,
    ks: *const SeedKeySchedule,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if enc != 0 {
            SEED_encrypt(input, output, ks);
        } else {
            SEED_decrypt(input, output, ks);
        }
    }
}

/// `block128_f` view of [`SEED_encrypt`] — `seed_cbc.c:24-25`'s `(block128_f)SEED_encrypt`.
///
/// # Safety
/// As [`SEED_encrypt`]; `key` is a `SEED_KEY_SCHEDULE *`.
unsafe extern "C" fn seed_block_encrypt(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { SEED_encrypt(input, out, key.cast::<SeedKeySchedule>()) }
}

/// `block128_f` view of [`SEED_decrypt`].
///
/// # Safety
/// As [`SEED_decrypt`]; `key` is a `SEED_KEY_SCHEDULE *`.
unsafe extern "C" fn seed_block_decrypt(input: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { SEED_decrypt(input, out, key.cast::<SeedKeySchedule>()) }
}

const _: Block128F = seed_block_encrypt;

/// `void SEED_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int enc)` —
/// `crypto/seed/seed_cbc.c:19-29`.
///
/// # Safety
/// `in`/`out` `len` bytes; `ks` live; `ivec` sixteen bytes.
#[no_mangle]
pub unsafe extern "C" fn SEED_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    len: usize,
    ks: *const SeedKeySchedule,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if enc != 0 {
            CRYPTO_cbc128_encrypt(
                input,
                output,
                len,
                ks.cast::<c_void>(),
                ivec,
                seed_block_encrypt,
            );
        } else {
            CRYPTO_cbc128_decrypt(
                input,
                output,
                len,
                ks.cast::<c_void>(),
                ivec,
                seed_block_decrypt,
            );
        }
    }
}

/// `void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int *num, int enc)` —
/// `crypto/seed/seed_cfb.c:19-27`.
///
/// # Safety
/// `in`/`out` `len` bytes; `ks` live; `ivec` sixteen bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn SEED_cfb128_encrypt(
    input: *const u8,
    output: *mut u8,
    len: usize,
    ks: *const SeedKeySchedule,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_encrypt(
            input,
            output,
            len,
            ks.cast::<c_void>(),
            ivec,
            num,
            enc,
            seed_block_encrypt,
        );
    }
}

/// `void SEED_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const SEED_KEY_SCHEDULE *ks, unsigned char ivec[16], int *num)` —
/// `crypto/seed/seed_ofb.c:19-26`.
///
/// # Safety
/// `in`/`out` `len` bytes; `ks` live; `ivec` sixteen bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn SEED_ofb128_encrypt(
    input: *const u8,
    output: *mut u8,
    len: usize,
    ks: *const SeedKeySchedule,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ofb128_encrypt(
            input,
            output,
            len,
            ks.cast::<c_void>(),
            ivec,
            num,
            seed_block_encrypt,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // `test/recipes/30-test_evp_data/evpciph_seed.txt`'s `SEED-ECB` vector.
        let key: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut ks = SeedKeySchedule { data: [0; 32] };
        // SAFETY: live locals, sixteen-byte key.
        unsafe { SEED_set_key(key.as_ptr(), &mut ks) };
        let block: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut out = [0u8; 16];
        // SAFETY: live locals.
        unsafe { SEED_ecb_encrypt(block.as_ptr(), out.as_mut_ptr(), &ks, 1) };
        assert_eq!(
            out,
            [
                0x5e, 0xba, 0xc6, 0xe0, 0x05, 0x4e, 0x16, 0x68, 0x19, 0xaf, 0xf1, 0xcc, 0x6d, 0x34,
                0x6c, 0xdb
            ]
        );
        // The recipe block is `Operation = DECRYPT`, so the decryption direction is checked too.
        let mut back = [0u8; 16];
        // SAFETY: live locals.
        unsafe { SEED_ecb_encrypt(out.as_ptr(), back.as_mut_ptr(), &ks, 0) };
        assert_eq!(back, block);
    }
}
