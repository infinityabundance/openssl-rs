//! Phase 8.2 — `crypto/camellia/`: Camellia (NTT, RFC 3713).
//!
//! The authority builds `crypto/camellia/camellia.c` on this profile (`cmll_cbc.c` and the other
//! mode files delegate to `modes.h`), and its four `Camellia_SBOX` rows and twelve `SIGMA`
//! constants are generated into [`crate::cipher_tables::CAMELLIA_SBOX`]/
//! [`crate::cipher_tables::CAMELLIA_SIGMA`]. The `RotLeft128` key-schedule rotations, the
//! six-round `Camellia_Feistel` and the `FL`/`FL⁻¹` layer are transcribed.
//!
//! ## Camellia is the one family here the **default** provider publishes
//!
//! `providers/defltprov.c:276-300` carries the twenty-four `CAMELLIA-{128,192,256}-*` rows, while
//! DES3's rows are at `:302-311` and every other family from D215–D221 is the legacy provider's.
//! The provider half of this slice therefore has a default-provider row to write for Camellia,
//! which is why the provider boundary is a per-row decision rather than one rule.
//!
//! ## Three key lengths, and `grand_rounds` is part of the key object
//!
//! `crypto/camellia/cmll_misc.c:20-28` stores `Camellia_Ekeygen`'s answer in
//! `key->grand_rounds`, which is 3 for 128-bit and 4 otherwise, and `Camellia_encrypt` reads it
//! back. The `CAMELLIA_KEY` layout has the union aligned to eight (`double d`) and `grand_rounds`
//! after the 272-byte table, so `RT-CIPHER` observes the whole 280-byte object.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};

use crate::cipher_tables::{CAMELLIA_SBOX, CAMELLIA_SIGMA};
use crate::modes::{
    Block128F, CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt,
    CRYPTO_cfb128_8_encrypt, CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt, CRYPTO_ofb128_encrypt,
};

/// `CAMELLIA_BLOCK_SIZE` — `include/openssl/camellia.h:27`.
pub const CAMELLIA_BLOCK_SIZE: usize = 16;
/// `CAMELLIA_ENCRYPT` — `include/openssl/camellia.h:31`.
pub const CAMELLIA_ENCRYPT: c_int = 1;
/// `CAMELLIA_DECRYPT` — `include/openssl/camellia.h:32`.
pub const CAMELLIA_DECRYPT: c_int = 0;

/// `CAMELLIA_KEY` — `include/openssl/camellia.h:47-54`. The anonymous union is aligned to eight
/// by its `double d` member, which is what makes `size_of` 280 rather than 276.
#[repr(C, align(8))]
pub struct CamelliaKey {
    /// `KEY_TABLE_TYPE rd_key` — `unsigned int[68]`.
    pub rd_key: [u32; 68],
    /// `int grand_rounds`.
    pub grand_rounds: c_int,
}

const _: () = {
    assert!(core::mem::offset_of!(CamelliaKey, grand_rounds) == 272);
    assert!(core::mem::size_of::<CamelliaKey>() == 280);
};

/// `GETU32(p)` — `camellia.c:56`, big-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn get_u32(p: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p as u32) << 24)
            | ((*p.add(1) as u32) << 16)
            | ((*p.add(2) as u32) << 8)
            | (*p.add(3) as u32)
    }
}

/// `PUTU32(p, v)` — `camellia.c:57`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn put_u32(v: u32, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = ((v >> 24) & 0xff) as u8;
        *p.add(1) = ((v >> 16) & 0xff) as u8;
        *p.add(2) = ((v >> 8) & 0xff) as u8;
        *p.add(3) = (v & 0xff) as u8;
    }
}

/// `RightRotate(x, s)` — `camellia.c:53`.
#[inline]
fn right_rotate(x: u32, s: u32) -> u32 {
    x.rotate_right(s)
}

/// `Camellia_Feistel(_s0, _s1, _s2, _s3, _key)` — `camellia.c:253-272`.
#[inline]
fn feistel(s: &mut [u32; 4], key: &[u32]) {
    let t0 = s[0] ^ key[0];
    let mut t3 = CAMELLIA_SBOX[1][(t0 & 0xff) as usize];
    let t1 = s[1] ^ key[1];
    t3 ^= CAMELLIA_SBOX[3][((t0 >> 8) & 0xff) as usize];
    let mut t2 = CAMELLIA_SBOX[0][(t1 & 0xff) as usize];
    t3 ^= CAMELLIA_SBOX[2][((t0 >> 16) & 0xff) as usize];
    t2 ^= CAMELLIA_SBOX[1][((t1 >> 8) & 0xff) as usize];
    t3 ^= CAMELLIA_SBOX[0][(t0 >> 24) as usize];
    t2 ^= t3;
    t3 = right_rotate(t3, 8);
    t2 ^= CAMELLIA_SBOX[3][((t1 >> 16) & 0xff) as usize];
    s[3] ^= t3;
    t2 ^= CAMELLIA_SBOX[2][(t1 >> 24) as usize];
    s[2] ^= t2;
    s[3] ^= t2;
}

/// `RotLeft128(_s0, _s1, _s2, _s3, _n)` — `camellia.c:279-286`.
#[inline]
fn rot_left128(s: &mut [u32; 4], n: u32) {
    let t0 = s[0] >> (32 - n);
    s[0] = (s[0] << n) | (s[1] >> (32 - n));
    s[1] = (s[1] << n) | (s[2] >> (32 - n));
    s[2] = (s[2] << n) | (s[3] >> (32 - n));
    s[3] = (s[3] << n) | t0;
}

/// `int Camellia_Ekeygen(int keyBitLength, const u8 *rawKey, KEY_TABLE_TYPE k)` —
/// `crypto/camellia/camellia.c:288-403`.
///
/// # Safety
/// `rawKey` readable for `keyBitLength / 8` bytes; `k` writable for sixty-eight words.
unsafe fn ekeygen(key_bit_length: c_int, raw_key: *const u8, k: &mut [u32; 68]) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut s = [
            get_u32(raw_key),
            get_u32(raw_key.add(4)),
            get_u32(raw_key.add(8)),
            get_u32(raw_key.add(12)),
        ];
        k[0] = s[0];
        k[1] = s[1];
        k[2] = s[2];
        k[3] = s[3];

        if key_bit_length != 128 {
            s[0] = get_u32(raw_key.add(16));
            k[8] = s[0];
            s[1] = get_u32(raw_key.add(20));
            k[9] = s[1];
            if key_bit_length == 192 {
                s[2] = !s[0];
                k[10] = s[2];
                s[3] = !s[1];
                k[11] = s[3];
            } else {
                s[2] = get_u32(raw_key.add(24));
                k[10] = s[2];
                s[3] = get_u32(raw_key.add(28));
                k[11] = s[3];
            }
            s[0] ^= k[0];
            s[1] ^= k[1];
            s[2] ^= k[2];
            s[3] ^= k[3];
        }

        feistel(&mut s, &CAMELLIA_SIGMA[0..2]);
        // `Camellia_Feistel(s2, s3, s0, s1, SIGMA + 2)` writes `s0`/`s1` through the macro's
        // `_s2`/`_s3`, so the four words are rotated into the callee's own view and back out.
        {
            let mut v = [s[2], s[3], s[0], s[1]];
            feistel(&mut v, &CAMELLIA_SIGMA[2..4]);
            s[2] = v[0];
            s[3] = v[1];
            s[0] = v[2];
            s[1] = v[3];
        }

        s[0] ^= k[0];
        s[1] ^= k[1];
        s[2] ^= k[2];
        s[3] ^= k[3];
        feistel(&mut s, &CAMELLIA_SIGMA[4..6]);
        {
            let mut v = [s[2], s[3], s[0], s[1]];
            feistel(&mut v, &CAMELLIA_SIGMA[6..8]);
            s[2] = v[0];
            s[3] = v[1];
            s[0] = v[2];
            s[1] = v[3];
        }

        if key_bit_length == 128 {
            k[4] = s[0];
            k[5] = s[1];
            k[6] = s[2];
            k[7] = s[3];
            rot_left128(&mut s, 15);
            k[12] = s[0];
            k[13] = s[1];
            k[14] = s[2];
            k[15] = s[3];
            rot_left128(&mut s, 15);
            k[16] = s[0];
            k[17] = s[1];
            k[18] = s[2];
            k[19] = s[3];
            rot_left128(&mut s, 15);
            k[24] = s[0];
            k[25] = s[1];
            rot_left128(&mut s, 15);
            k[28] = s[0];
            k[29] = s[1];
            k[30] = s[2];
            k[31] = s[3];

            let mut r = [s[1], s[2], s[3], s[0]];
            rot_left128(&mut r, 2);
            k[40] = r[0];
            k[41] = r[1];
            k[42] = r[2];
            k[43] = r[3];
            rot_left128(&mut r, 17);
            k[48] = r[0];
            k[49] = r[1];
            k[50] = r[2];
            k[51] = r[3];

            let mut s = [k[0], k[1], k[2], k[3]];
            rot_left128(&mut s, 15);
            k[8] = s[0];
            k[9] = s[1];
            k[10] = s[2];
            k[11] = s[3];
            rot_left128(&mut s, 30);
            k[20] = s[0];
            k[21] = s[1];
            k[22] = s[2];
            k[23] = s[3];
            rot_left128(&mut s, 15);
            k[26] = s[2];
            k[27] = s[3];
            rot_left128(&mut s, 17);
            k[32] = s[0];
            k[33] = s[1];
            k[34] = s[2];
            k[35] = s[3];
            rot_left128(&mut s, 17);
            k[36] = s[0];
            k[37] = s[1];
            k[38] = s[2];
            k[39] = s[3];
            rot_left128(&mut s, 17);
            k[44] = s[0];
            k[45] = s[1];
            k[46] = s[2];
            k[47] = s[3];
            return 3;
        }

        k[12] = s[0];
        k[13] = s[1];
        k[14] = s[2];
        k[15] = s[3];
        s[0] ^= k[8];
        s[1] ^= k[9];
        s[2] ^= k[10];
        s[3] ^= k[11];
        feistel(&mut s, &CAMELLIA_SIGMA[8..10]);
        {
            let mut v = [s[2], s[3], s[0], s[1]];
            feistel(&mut v, &CAMELLIA_SIGMA[10..12]);
            s[2] = v[0];
            s[3] = v[1];
            s[0] = v[2];
            s[1] = v[3];
        }

        k[4] = s[0];
        k[5] = s[1];
        k[6] = s[2];
        k[7] = s[3];
        rot_left128(&mut s, 30);
        k[20] = s[0];
        k[21] = s[1];
        k[22] = s[2];
        k[23] = s[3];
        rot_left128(&mut s, 30);
        k[40] = s[0];
        k[41] = s[1];
        k[42] = s[2];
        k[43] = s[3];
        let mut r = [s[1], s[2], s[3], s[0]];
        rot_left128(&mut r, 19);
        k[64] = r[0];
        k[65] = r[1];
        k[66] = r[2];
        k[67] = r[3];

        let mut s = [k[8], k[9], k[10], k[11]];
        rot_left128(&mut s, 15);
        k[8] = s[0];
        k[9] = s[1];
        k[10] = s[2];
        k[11] = s[3];
        rot_left128(&mut s, 15);
        k[16] = s[0];
        k[17] = s[1];
        k[18] = s[2];
        k[19] = s[3];
        rot_left128(&mut s, 30);
        k[36] = s[0];
        k[37] = s[1];
        k[38] = s[2];
        k[39] = s[3];
        let mut r = [s[1], s[2], s[3], s[0]];
        rot_left128(&mut r, 2);
        k[52] = r[0];
        k[53] = r[1];
        k[54] = r[2];
        k[55] = r[3];

        let mut s = [k[12], k[13], k[14], k[15]];
        rot_left128(&mut s, 15);
        k[12] = s[0];
        k[13] = s[1];
        k[14] = s[2];
        k[15] = s[3];
        rot_left128(&mut s, 30);
        k[28] = s[0];
        k[29] = s[1];
        k[30] = s[2];
        k[31] = s[3];
        let mut r = [s[1], s[2], s[3], s[0]];
        k[48] = r[0];
        k[49] = r[1];
        k[50] = r[2];
        k[51] = r[3];
        rot_left128(&mut r, 17);
        k[56] = r[0];
        k[57] = r[1];
        k[58] = r[2];
        k[59] = r[3];

        let s = [k[0], k[1], k[2], k[3]];
        let mut r = [s[1], s[2], s[3], s[0]];
        rot_left128(&mut r, 13);
        k[24] = r[0];
        k[25] = r[1];
        k[26] = r[2];
        k[27] = r[3];
        rot_left128(&mut r, 15);
        k[32] = r[0];
        k[33] = r[1];
        k[34] = r[2];
        k[35] = r[3];
        rot_left128(&mut r, 17);
        k[44] = r[0];
        k[45] = r[1];
        k[46] = r[2];
        k[47] = r[3];
        // `RotLeft128(s2, s3, s0, s1, 2)`: the tuple is one word on from `r`'s order
        // `(s1, s2, s3, s0)`, so the limb starts at `r[1]`, not `r[2]`.
        let mut r2 = [r[1], r[2], r[3], r[0]];
        rot_left128(&mut r2, 2);
        k[60] = r2[0];
        k[61] = r2[1];
        k[62] = r2[2];
        k[63] = r2[3];

        4
    }
}

/// `void Camellia_EncryptBlock_Rounds(int grandRounds, const u8 plaintext[],
/// const KEY_TABLE_TYPE keyTable, u8 ciphertext[])` — `crypto/camellia/camellia.c:405-449`.
///
/// # Safety
/// `plaintext`/`ciphertext` sixteen bytes; `key_table` sixty-eight words.
unsafe fn encrypt_block_rounds(
    grand_rounds: c_int,
    plaintext: *const u8,
    key_table: &[u32; 68],
    ciphertext: *mut u8,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut s = [
            get_u32(plaintext) ^ key_table[0],
            get_u32(plaintext.add(4)) ^ key_table[1],
            get_u32(plaintext.add(8)) ^ key_table[2],
            get_u32(plaintext.add(12)) ^ key_table[3],
        ];
        let mut k = 4usize;
        let kend = grand_rounds as usize * 16;
        loop {
            feistel(&mut s, &key_table[k..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k + 2..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            feistel(&mut s, &key_table[k + 4..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k + 6..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            feistel(&mut s, &key_table[k + 8..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k + 10..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            k += 12;
            if k == kend {
                break;
            }
            s[1] ^= (s[0] & key_table[k]).rotate_left(1);
            s[2] ^= s[3] | key_table[k + 3];
            s[0] ^= s[1] | key_table[k + 1];
            s[3] ^= (s[2] & key_table[k + 2]).rotate_left(1);
            k += 4;
        }
        s[2] ^= key_table[k];
        s[3] ^= key_table[k + 1];
        s[0] ^= key_table[k + 2];
        s[1] ^= key_table[k + 3];
        put_u32(s[2], ciphertext);
        put_u32(s[3], ciphertext.add(4));
        put_u32(s[0], ciphertext.add(8));
        put_u32(s[1], ciphertext.add(12));
    }
}

/// `void Camellia_DecryptBlock_Rounds(...)` — `crypto/camellia/camellia.c:458-502`.
///
/// # Safety
/// As [`encrypt_block_rounds`].
unsafe fn decrypt_block_rounds(
    grand_rounds: c_int,
    ciphertext: *const u8,
    key_table: &[u32; 68],
    plaintext: *mut u8,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut k = grand_rounds as usize * 16;
        let mut s = [
            get_u32(ciphertext) ^ key_table[k],
            get_u32(ciphertext.add(4)) ^ key_table[k + 1],
            get_u32(ciphertext.add(8)) ^ key_table[k + 2],
            get_u32(ciphertext.add(12)) ^ key_table[k + 3],
        ];
        loop {
            k -= 12;
            feistel(&mut s, &key_table[k + 10..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k + 8..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            feistel(&mut s, &key_table[k + 6..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k + 4..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            feistel(&mut s, &key_table[k + 2..]);
            {
                let mut v = [s[2], s[3], s[0], s[1]];
                feistel(&mut v, &key_table[k..]);
                s[2] = v[0];
                s[3] = v[1];
                s[0] = v[2];
                s[1] = v[3];
            }
            if k == 4 {
                break;
            }
            k -= 4;
            s[1] ^= (s[0] & key_table[k + 2]).rotate_left(1);
            s[2] ^= s[3] | key_table[k + 1];
            s[0] ^= s[1] | key_table[k + 3];
            s[3] ^= (s[2] & key_table[k]).rotate_left(1);
        }
        k -= 4;
        s[2] ^= key_table[k];
        s[3] ^= key_table[k + 1];
        s[0] ^= key_table[k + 2];
        s[1] ^= key_table[k + 3];
        put_u32(s[2], plaintext);
        put_u32(s[3], plaintext.add(4));
        put_u32(s[0], plaintext.add(8));
        put_u32(s[1], plaintext.add(12));
    }
}

/// `int Camellia_set_key(const unsigned char *userKey, const int bits, CAMELLIA_KEY *key)` —
/// `crypto/camellia/cmll_misc.c:20-29`.
///
/// # Safety
/// `user_key` readable for `bits / 8` bytes; `key` writable.
#[no_mangle]
pub unsafe extern "C" fn Camellia_set_key(
    user_key: *const u8,
    bits: c_int,
    key: *mut CamelliaKey,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if user_key.is_null() || key.is_null() {
            return -1;
        }
        if bits != 128 && bits != 192 && bits != 256 {
            return -2;
        }
        (*key).grand_rounds = ekeygen(bits, user_key, &mut (*key).rd_key);
    }
    0
}

/// `void Camellia_encrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key)`
/// — `crypto/camellia/cmll_misc.c:31-35`.
///
/// # Safety
/// `in`/`out` sixteen bytes; `key` live.
#[no_mangle]
pub unsafe extern "C" fn Camellia_encrypt(in_: *const u8, out: *mut u8, key: *const CamelliaKey) {
    // SAFETY: the caller's contract.
    unsafe {
        encrypt_block_rounds((*key).grand_rounds, in_, &(*key).rd_key, out);
    }
}

/// `void Camellia_decrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key)`
/// — `crypto/camellia/cmll_misc.c:37-41`.
///
/// # Safety
/// As [`Camellia_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn Camellia_decrypt(in_: *const u8, out: *mut u8, key: *const CamelliaKey) {
    // SAFETY: the caller's contract.
    unsafe {
        decrypt_block_rounds((*key).grand_rounds, in_, &(*key).rd_key, out);
    }
}

/// `void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out,
/// const CAMELLIA_KEY *key, const int enc)` — `crypto/camellia/cmll_ecb.c:19-26`.
///
/// # Safety
/// `in`/`out` sixteen bytes; `key` live.
#[no_mangle]
pub unsafe extern "C" fn Camellia_ecb_encrypt(
    in_: *const u8,
    out: *mut u8,
    key: *const CamelliaKey,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if enc == CAMELLIA_ENCRYPT {
            Camellia_encrypt(in_, out, key);
        } else {
            Camellia_decrypt(in_, out, key);
        }
    }
}

/// `block128_f` view of [`Camellia_encrypt`] — `cmll_cbc.c:24-25`'s `(block128_f)Camellia_encrypt`.
///
/// # Safety
/// As [`Camellia_encrypt`]; `key` is a `CAMELLIA_KEY *`.
unsafe extern "C" fn camellia_block_encrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { Camellia_encrypt(in_, out, key.cast::<CamelliaKey>()) }
}

/// `block128_f` view of [`Camellia_decrypt`].
///
/// # Safety
/// As [`Camellia_decrypt`]; `key` is a `CAMELLIA_KEY *`.
unsafe extern "C" fn camellia_block_decrypt(in_: *const u8, out: *mut u8, key: *const c_void) {
    // SAFETY: the caller's contract.
    unsafe { Camellia_decrypt(in_, out, key.cast::<CamelliaKey>()) }
}

const _: Block128F = camellia_block_encrypt;

/// `void Camellia_cbc_encrypt(...)` — `crypto/camellia/cmll_cbc.c:19-30`.
///
/// # Safety
/// `in`/`out` `len` bytes; `key` live; `ivec` sixteen bytes.
#[no_mangle]
pub unsafe extern "C" fn Camellia_cbc_encrypt(
    in_: *const u8,
    out: *mut u8,
    len: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if enc != 0 {
            CRYPTO_cbc128_encrypt(
                in_,
                out,
                len,
                key.cast::<c_void>(),
                ivec,
                camellia_block_encrypt,
            );
        } else {
            CRYPTO_cbc128_decrypt(
                in_,
                out,
                len,
                key.cast::<c_void>(),
                ivec,
                camellia_block_decrypt,
            );
        }
    }
}

/// `void Camellia_cfb128_encrypt(...)` — `crypto/camellia/cmll_cfb.c:25-32`.
///
/// # Safety
/// `in`/`out` `length` bytes; `key` live; `ivec` sixteen bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn Camellia_cfb128_encrypt(
    in_: *const u8,
    out: *mut u8,
    length: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_encrypt(
            in_,
            out,
            length,
            key.cast::<c_void>(),
            ivec,
            num,
            enc,
            camellia_block_encrypt,
        );
    }
}

/// `void Camellia_cfb1_encrypt(...)` — `crypto/camellia/cmll_cfb.c:35-41`. "This expects the
/// input to be packed, MS bit first."
///
/// # Safety
/// As [`Camellia_cfb128_encrypt`]; `length` is a bit count.
#[no_mangle]
pub unsafe extern "C" fn Camellia_cfb1_encrypt(
    in_: *const u8,
    out: *mut u8,
    length: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_1_encrypt(
            in_,
            out,
            length,
            key.cast::<c_void>(),
            ivec,
            num,
            enc,
            camellia_block_encrypt,
        );
    }
}

/// `void Camellia_cfb8_encrypt(...)` — `crypto/camellia/cmll_cfb.c:43-49`.
///
/// # Safety
/// As [`Camellia_cfb128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn Camellia_cfb8_encrypt(
    in_: *const u8,
    out: *mut u8,
    length: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_cfb128_8_encrypt(
            in_,
            out,
            length,
            key.cast::<c_void>(),
            ivec,
            num,
            enc,
            camellia_block_encrypt,
        );
    }
}

/// `void Camellia_ofb128_encrypt(...)` — `crypto/camellia/cmll_ofb.c:24-30`.
///
/// # Safety
/// `in`/`out` `length` bytes; `key` live; `ivec` sixteen bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn Camellia_ofb128_encrypt(
    in_: *const u8,
    out: *mut u8,
    length: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ofb128_encrypt(
            in_,
            out,
            length,
            key.cast::<c_void>(),
            ivec,
            num,
            camellia_block_encrypt,
        );
    }
}

/// `void Camellia_ctr128_encrypt(...)` — `crypto/camellia/cmll_ctr.c:19-29`.
///
/// # Safety
/// `in`/`out` `length` bytes; `key` live; `ivec`/`ecount_buf` sixteen bytes each; `num`
/// readable/writable.
#[no_mangle]
pub unsafe extern "C" fn Camellia_ctr128_encrypt(
    in_: *const u8,
    out: *mut u8,
    length: usize,
    key: *const CamelliaKey,
    ivec: *mut u8,
    ecount_buf: *mut u8,
    num: *mut u32,
) {
    // SAFETY: the caller's contract.
    unsafe {
        CRYPTO_ctr128_encrypt(
            in_,
            out,
            length,
            key.cast::<c_void>(),
            ivec,
            ecount_buf,
            num,
            camellia_block_encrypt,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // `test/recipes/30-test_evp_data/evpciph_camellia.txt`'s first `CAMELLIA-128-ECB` block.
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut ck = CamelliaKey {
            rd_key: [0; 68],
            grand_rounds: 0,
        };
        // SAFETY: live locals.
        unsafe { Camellia_set_key(key.as_ptr(), 128, &mut ck) };
        let block: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut out = [0u8; 16];
        // SAFETY: live locals.
        unsafe { Camellia_ecb_encrypt(block.as_ptr(), out.as_mut_ptr(), &ck, CAMELLIA_ENCRYPT) };
        assert_eq!(
            out,
            [
                0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73, 0x08, 0x57, 0x06, 0x56, 0x48, 0xea,
                0xbe, 0x43
            ]
        );
        let mut back = [0u8; 16];
        // SAFETY: live locals.
        unsafe { Camellia_ecb_encrypt(out.as_ptr(), back.as_mut_ptr(), &ck, CAMELLIA_DECRYPT) };
        assert_eq!(back, block);
        assert_eq!(ck.grand_rounds, 3);
    }

    #[test]
    fn the_192_and_256_recipe_ecb_vectors_match() {
        // `evpciph_camellia.txt`'s first `CAMELLIA-192-ECB` and `CAMELLIA-256-ECB` blocks.
        // The two longer keys exercise the `KB`/`KR` limbs of the schedule.
        let key192: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        let key256: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let block: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cases: [(u32, &[u8], [u8; 16]); 2] = [
            (
                192,
                &key192,
                [
                    0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8, 0x4e, 0xe5, 0xce, 0xe7, 0xd7,
                    0x9b, 0x09, 0xb9,
                ],
            ),
            (
                256,
                &key256,
                [
                    0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c, 0x20, 0xef, 0x7c, 0x91, 0x9e,
                    0x3a, 0x75, 0x09,
                ],
            ),
        ];
        for (bits, key, expected) in cases {
            let mut ck = CamelliaKey {
                rd_key: [0; 68],
                grand_rounds: 0,
            };
            // SAFETY: live locals; the key buffers are long enough for their own `bits`.
            unsafe { Camellia_set_key(key.as_ptr(), bits as c_int, &mut ck) };
            let mut out = [0u8; 16];
            // SAFETY: live locals.
            unsafe {
                Camellia_ecb_encrypt(block.as_ptr(), out.as_mut_ptr(), &ck, CAMELLIA_ENCRYPT)
            };
            assert_eq!(out, expected, "CAMELLIA-{bits}-ECB");
            let mut back = [0u8; 16];
            // SAFETY: live locals.
            unsafe { Camellia_ecb_encrypt(out.as_ptr(), back.as_mut_ptr(), &ck, CAMELLIA_DECRYPT) };
            assert_eq!(back, block, "CAMELLIA-{bits}-ECB round trip");
        }
    }

    #[test]
    fn the_three_key_lengths_set_grand_rounds() {
        for (bits, rounds) in [(128, 3), (192, 4), (256, 4)] {
            let key = [0u8; 32];
            let mut ck = CamelliaKey {
                rd_key: [0; 68],
                grand_rounds: 0,
            };
            // SAFETY: live locals; the key buffer is 32 bytes so every length is readable.
            unsafe { Camellia_set_key(key.as_ptr(), bits, &mut ck) };
            assert_eq!(ck.grand_rounds, rounds);
        }
    }
}
