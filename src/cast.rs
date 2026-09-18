//! Phase 8.2 — `crypto/cast/`: CAST5 (RFC 2144).
//!
//! The authority builds `crypto/cast/c_enc.c`, `c_skey.c` and `c_ecb.c` (the perlasm arm is
//! 32-bit x86 only, `crypto/cast/build.info:5-12`), so this is the arm it links. The eight
//! S-boxes come from [`crate::cipher_tables::CAST_S`], generated from `cast_s.h`; the schedule's
//! `x`/`z` byte-and-word mixing and the twelve-or-sixteen round structure are transcribed from
//! `c_skey.c`/`c_enc.c`.
//!
//! ## The key length selects the round count, and the schedule records it
//!
//! `c_skey.c:47-50` sets `key->short_key = len <= 10`, and `c_enc.c:40-45` omits rounds 12–15
//! when it is set. So the same eight-byte CAST5 key and the same sixteen-byte key differ not
//! only in their schedule but in how many rounds the cipher runs, and `RT-CIPHER` observes
//! both the schedule (including the `short_key` flag, at the end of `CAST_KEY`) and a
//! ciphertext for each key length.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uint};

use crate::cipher_tables::CAST_S;

/// `CAST_BLOCK` — `include/openssl/cast.h:26`.
pub const CAST_BLOCK: usize = 8;
/// `CAST_ENCRYPT` — `include/openssl/cast.h:31`.
pub const CAST_ENCRYPT: c_int = 1;
/// `CAST_DECRYPT` — `include/openssl/cast.h:32`.
pub const CAST_DECRYPT: c_int = 0;

/// `CAST_KEY` — `include/openssl/cast.h:36-39`: `data[32]` and the `short_key` flag. `CAST_LONG`
/// is `unsigned int`.
#[repr(C)]
pub struct CastKey {
    /// `CAST_LONG data[32]`.
    pub data: [c_uint; 32],
    /// `int short_key` — use reduced rounds for a short key.
    pub short_key: c_int,
}

const _: () = {
    assert!(core::mem::offset_of!(CastKey, short_key) == 128);
    assert!(core::mem::size_of::<CastKey>() == 132);
};

const OP_ADD: u8 = 0;
const OP_SUB: u8 = 1;
const OP_XOR: u8 = 2;

/// `ROTL(a, n)` — `crypto/cast/cast_local.h:92`.
#[inline]
fn rotl(a: c_uint, n: c_uint) -> c_uint {
    a.rotate_left(n & 31)
}

#[inline]
fn op(a: c_uint, b: c_uint, o: u8) -> c_uint {
    match o {
        OP_ADD => a.wrapping_add(b),
        OP_SUB => a.wrapping_sub(b),
        _ => a ^ b,
    }
}

/// `E_CAST(n, key, L, R, OP1, OP2, OP3)` — `crypto/cast/cast_local.h:148-158`, the portable arm.
#[inline]
fn e_cast(n: usize, key: &[c_uint; 32], l: &mut c_uint, r: c_uint, o1: u8, o2: u8, o3: u8) {
    let t = rotl(op(key[n * 2], r, o1), key[n * 2 + 1]);
    let a = CAST_S[0][((t >> 8) & 0xff) as usize];
    let b = CAST_S[1][(t & 0xff) as usize];
    let c = CAST_S[2][((t >> 24) & 0xff) as usize];
    let d = CAST_S[3][((t >> 16) & 0xff) as usize];
    *l ^= op(op(op(a, b, o2), c, o3), d, o1);
}

/// `CAST_exp(l, A, a, n)` — `crypto/cast/c_skey.c:20-25`: the word into `A[n/4]` and its four
/// bytes big-endian into `a[n..n+3]`.
#[inline]
fn cast_exp(l: c_uint, big: &mut [c_uint; 4], bytes: &mut [c_uint; 16], n: usize) {
    big[n / 4] = l;
    bytes[n + 3] = l & 0xff;
    bytes[n + 2] = (l >> 8) & 0xff;
    bytes[n + 1] = (l >> 16) & 0xff;
    bytes[n] = (l >> 24) & 0xff;
}

/// `void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data)` —
/// `crypto/cast/c_skey.c:32-123`.
///
/// # Safety
/// `key` writable; `data` readable for `len` bytes.
#[allow(clippy::needless_range_loop)]
#[no_mangle]
pub unsafe extern "C" fn CAST_set_key(key: *mut CastKey, len: c_int, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut x = [0 as c_uint; 16];
        let mut z = [0 as c_uint; 16];
        let mut k = [0 as c_uint; 32];
        let mut big_x = [0 as c_uint; 4];
        let mut big_z = [0 as c_uint; 4];
        let mut len = len;

        if len > 16 {
            len = 16;
        }
        for i in 0..len as usize {
            x[i] = *data.add(i) as c_uint;
        }
        (*key).short_key = c_int::from(len <= 10);

        big_x[0] = (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];
        big_x[1] = (x[4] << 24) | (x[5] << 16) | (x[6] << 8) | x[7];
        big_x[2] = (x[8] << 24) | (x[9] << 16) | (x[10] << 8) | x[11];
        big_x[3] = (x[12] << 24) | (x[13] << 16) | (x[14] << 8) | x[15];

        // Two passes; the authority's `K != k` test runs the body twice, writing k[0..15] then
        // k[16..31].
        for pass in 0..2usize {
            let base = pass * 16;
            let l = big_x[0]
                ^ CAST_S[4][x[13] as usize]
                ^ CAST_S[5][x[15] as usize]
                ^ CAST_S[6][x[12] as usize]
                ^ CAST_S[7][x[14] as usize]
                ^ CAST_S[6][x[8] as usize];
            cast_exp(l, &mut big_z, &mut z, 0);
            let l = big_x[2]
                ^ CAST_S[4][z[0] as usize]
                ^ CAST_S[5][z[2] as usize]
                ^ CAST_S[6][z[1] as usize]
                ^ CAST_S[7][z[3] as usize]
                ^ CAST_S[7][x[10] as usize];
            cast_exp(l, &mut big_z, &mut z, 4);
            let l = big_x[3]
                ^ CAST_S[4][z[7] as usize]
                ^ CAST_S[5][z[6] as usize]
                ^ CAST_S[6][z[5] as usize]
                ^ CAST_S[7][z[4] as usize]
                ^ CAST_S[4][x[9] as usize];
            cast_exp(l, &mut big_z, &mut z, 8);
            let l = big_x[1]
                ^ CAST_S[4][z[10] as usize]
                ^ CAST_S[5][z[9] as usize]
                ^ CAST_S[6][z[11] as usize]
                ^ CAST_S[7][z[8] as usize]
                ^ CAST_S[5][x[11] as usize];
            cast_exp(l, &mut big_z, &mut z, 12);

            k[base] = CAST_S[4][z[8] as usize]
                ^ CAST_S[5][z[9] as usize]
                ^ CAST_S[6][z[7] as usize]
                ^ CAST_S[7][z[6] as usize]
                ^ CAST_S[4][z[2] as usize];
            k[base + 1] = CAST_S[4][z[10] as usize]
                ^ CAST_S[5][z[11] as usize]
                ^ CAST_S[6][z[5] as usize]
                ^ CAST_S[7][z[4] as usize]
                ^ CAST_S[5][z[6] as usize];
            k[base + 2] = CAST_S[4][z[12] as usize]
                ^ CAST_S[5][z[13] as usize]
                ^ CAST_S[6][z[3] as usize]
                ^ CAST_S[7][z[2] as usize]
                ^ CAST_S[6][z[9] as usize];
            k[base + 3] = CAST_S[4][z[14] as usize]
                ^ CAST_S[5][z[15] as usize]
                ^ CAST_S[6][z[1] as usize]
                ^ CAST_S[7][z[0] as usize]
                ^ CAST_S[7][z[12] as usize];

            let l = big_z[2]
                ^ CAST_S[4][z[5] as usize]
                ^ CAST_S[5][z[7] as usize]
                ^ CAST_S[6][z[4] as usize]
                ^ CAST_S[7][z[6] as usize]
                ^ CAST_S[6][z[0] as usize];
            cast_exp(l, &mut big_x, &mut x, 0);
            let l = big_z[0]
                ^ CAST_S[4][x[0] as usize]
                ^ CAST_S[5][x[2] as usize]
                ^ CAST_S[6][x[1] as usize]
                ^ CAST_S[7][x[3] as usize]
                ^ CAST_S[7][z[2] as usize];
            cast_exp(l, &mut big_x, &mut x, 4);
            let l = big_z[1]
                ^ CAST_S[4][x[7] as usize]
                ^ CAST_S[5][x[6] as usize]
                ^ CAST_S[6][x[5] as usize]
                ^ CAST_S[7][x[4] as usize]
                ^ CAST_S[4][z[1] as usize];
            cast_exp(l, &mut big_x, &mut x, 8);
            let l = big_z[3]
                ^ CAST_S[4][x[10] as usize]
                ^ CAST_S[5][x[9] as usize]
                ^ CAST_S[6][x[11] as usize]
                ^ CAST_S[7][x[8] as usize]
                ^ CAST_S[5][z[3] as usize];
            cast_exp(l, &mut big_x, &mut x, 12);

            k[base + 4] = CAST_S[4][x[3] as usize]
                ^ CAST_S[5][x[2] as usize]
                ^ CAST_S[6][x[12] as usize]
                ^ CAST_S[7][x[13] as usize]
                ^ CAST_S[4][x[8] as usize];
            k[base + 5] = CAST_S[4][x[1] as usize]
                ^ CAST_S[5][x[0] as usize]
                ^ CAST_S[6][x[14] as usize]
                ^ CAST_S[7][x[15] as usize]
                ^ CAST_S[5][x[13] as usize];
            k[base + 6] = CAST_S[4][x[7] as usize]
                ^ CAST_S[5][x[6] as usize]
                ^ CAST_S[6][x[8] as usize]
                ^ CAST_S[7][x[9] as usize]
                ^ CAST_S[6][x[3] as usize];
            k[base + 7] = CAST_S[4][x[5] as usize]
                ^ CAST_S[5][x[4] as usize]
                ^ CAST_S[6][x[10] as usize]
                ^ CAST_S[7][x[11] as usize]
                ^ CAST_S[7][x[7] as usize];

            if pass == 1 {
                // The authority's `K != k` test breaks after the second full body; the range
                // ends here, so the state carries over exactly as it does there.
            }

            // The second half of the loop body recomputes z from X, filling k[base+8..11], then x
            // from Z, filling k[base+12..15].
            let l = big_x[0]
                ^ CAST_S[4][x[13] as usize]
                ^ CAST_S[5][x[15] as usize]
                ^ CAST_S[6][x[12] as usize]
                ^ CAST_S[7][x[14] as usize]
                ^ CAST_S[6][x[8] as usize];
            cast_exp(l, &mut big_z, &mut z, 0);
            let l = big_x[2]
                ^ CAST_S[4][z[0] as usize]
                ^ CAST_S[5][z[2] as usize]
                ^ CAST_S[6][z[1] as usize]
                ^ CAST_S[7][z[3] as usize]
                ^ CAST_S[7][x[10] as usize];
            cast_exp(l, &mut big_z, &mut z, 4);
            let l = big_x[3]
                ^ CAST_S[4][z[7] as usize]
                ^ CAST_S[5][z[6] as usize]
                ^ CAST_S[6][z[5] as usize]
                ^ CAST_S[7][z[4] as usize]
                ^ CAST_S[4][x[9] as usize];
            cast_exp(l, &mut big_z, &mut z, 8);
            let l = big_x[1]
                ^ CAST_S[4][z[10] as usize]
                ^ CAST_S[5][z[9] as usize]
                ^ CAST_S[6][z[11] as usize]
                ^ CAST_S[7][z[8] as usize]
                ^ CAST_S[5][x[11] as usize];
            cast_exp(l, &mut big_z, &mut z, 12);

            k[base + 8] = CAST_S[4][z[3] as usize]
                ^ CAST_S[5][z[2] as usize]
                ^ CAST_S[6][z[12] as usize]
                ^ CAST_S[7][z[13] as usize]
                ^ CAST_S[4][z[9] as usize];
            k[base + 9] = CAST_S[4][z[1] as usize]
                ^ CAST_S[5][z[0] as usize]
                ^ CAST_S[6][z[14] as usize]
                ^ CAST_S[7][z[15] as usize]
                ^ CAST_S[5][z[12] as usize];
            k[base + 10] = CAST_S[4][z[7] as usize]
                ^ CAST_S[5][z[6] as usize]
                ^ CAST_S[6][z[8] as usize]
                ^ CAST_S[7][z[9] as usize]
                ^ CAST_S[6][z[2] as usize];
            k[base + 11] = CAST_S[4][z[5] as usize]
                ^ CAST_S[5][z[4] as usize]
                ^ CAST_S[6][z[10] as usize]
                ^ CAST_S[7][z[11] as usize]
                ^ CAST_S[7][z[6] as usize];

            let l = big_z[2]
                ^ CAST_S[4][z[5] as usize]
                ^ CAST_S[5][z[7] as usize]
                ^ CAST_S[6][z[4] as usize]
                ^ CAST_S[7][z[6] as usize]
                ^ CAST_S[6][z[0] as usize];
            cast_exp(l, &mut big_x, &mut x, 0);
            let l = big_z[0]
                ^ CAST_S[4][x[0] as usize]
                ^ CAST_S[5][x[2] as usize]
                ^ CAST_S[6][x[1] as usize]
                ^ CAST_S[7][x[3] as usize]
                ^ CAST_S[7][z[2] as usize];
            cast_exp(l, &mut big_x, &mut x, 4);
            let l = big_z[1]
                ^ CAST_S[4][x[7] as usize]
                ^ CAST_S[5][x[6] as usize]
                ^ CAST_S[6][x[5] as usize]
                ^ CAST_S[7][x[4] as usize]
                ^ CAST_S[4][z[1] as usize];
            cast_exp(l, &mut big_x, &mut x, 8);
            let l = big_z[3]
                ^ CAST_S[4][x[10] as usize]
                ^ CAST_S[5][x[9] as usize]
                ^ CAST_S[6][x[11] as usize]
                ^ CAST_S[7][x[8] as usize]
                ^ CAST_S[5][z[3] as usize];
            cast_exp(l, &mut big_x, &mut x, 12);

            k[base + 12] = CAST_S[4][x[8] as usize]
                ^ CAST_S[5][x[9] as usize]
                ^ CAST_S[6][x[7] as usize]
                ^ CAST_S[7][x[6] as usize]
                ^ CAST_S[4][x[3] as usize];
            k[base + 13] = CAST_S[4][x[10] as usize]
                ^ CAST_S[5][x[11] as usize]
                ^ CAST_S[6][x[5] as usize]
                ^ CAST_S[7][x[4] as usize]
                ^ CAST_S[5][x[7] as usize];
            k[base + 14] = CAST_S[4][x[12] as usize]
                ^ CAST_S[5][x[13] as usize]
                ^ CAST_S[6][x[3] as usize]
                ^ CAST_S[7][x[2] as usize]
                ^ CAST_S[6][x[8] as usize];
            k[base + 15] = CAST_S[4][x[14] as usize]
                ^ CAST_S[5][x[15] as usize]
                ^ CAST_S[6][x[1] as usize]
                ^ CAST_S[7][x[0] as usize]
                ^ CAST_S[7][x[13] as usize];
        }

        for i in 0..16 {
            (*key).data[i * 2] = k[i];
            (*key).data[i * 2 + 1] = (k[i + 16].wrapping_add(16)) & 0x1f;
        }
    }
}

/// `void CAST_encrypt(CAST_LONG *data, const CAST_KEY *key)` — `crypto/cast/c_enc.c:19-49`.
///
/// # Safety
/// `data` two words; `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn CAST_encrypt(data: *mut c_uint, key: *const CastKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let k = &(*key).data;
        let mut l = *data;
        let mut r = *data.add(1);
        e_cast(0, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
        e_cast(1, k, &mut r, l, OP_XOR, OP_SUB, OP_ADD);
        e_cast(2, k, &mut l, r, OP_SUB, OP_ADD, OP_XOR);
        e_cast(3, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        e_cast(4, k, &mut l, r, OP_XOR, OP_SUB, OP_ADD);
        e_cast(5, k, &mut r, l, OP_SUB, OP_ADD, OP_XOR);
        e_cast(6, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
        e_cast(7, k, &mut r, l, OP_XOR, OP_SUB, OP_ADD);
        e_cast(8, k, &mut l, r, OP_SUB, OP_ADD, OP_XOR);
        e_cast(9, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        e_cast(10, k, &mut l, r, OP_XOR, OP_SUB, OP_ADD);
        e_cast(11, k, &mut r, l, OP_SUB, OP_ADD, OP_XOR);
        if (*key).short_key == 0 {
            e_cast(12, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
            e_cast(13, k, &mut r, l, OP_XOR, OP_SUB, OP_ADD);
            e_cast(14, k, &mut l, r, OP_SUB, OP_ADD, OP_XOR);
            e_cast(15, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        }
        *data.add(1) = l;
        *data = r;
    }
}

/// `void CAST_decrypt(CAST_LONG *data, const CAST_KEY *key)` — `crypto/cast/c_enc.c:51-81`.
///
/// # Safety
/// As [`CAST_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CAST_decrypt(data: *mut c_uint, key: *const CastKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let k = &(*key).data;
        let mut l = *data;
        let mut r = *data.add(1);
        if (*key).short_key == 0 {
            e_cast(15, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
            e_cast(14, k, &mut r, l, OP_SUB, OP_ADD, OP_XOR);
            e_cast(13, k, &mut l, r, OP_XOR, OP_SUB, OP_ADD);
            e_cast(12, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        }
        e_cast(11, k, &mut l, r, OP_SUB, OP_ADD, OP_XOR);
        e_cast(10, k, &mut r, l, OP_XOR, OP_SUB, OP_ADD);
        e_cast(9, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
        e_cast(8, k, &mut r, l, OP_SUB, OP_ADD, OP_XOR);
        e_cast(7, k, &mut l, r, OP_XOR, OP_SUB, OP_ADD);
        e_cast(6, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        e_cast(5, k, &mut l, r, OP_SUB, OP_ADD, OP_XOR);
        e_cast(4, k, &mut r, l, OP_XOR, OP_SUB, OP_ADD);
        e_cast(3, k, &mut l, r, OP_ADD, OP_XOR, OP_SUB);
        e_cast(2, k, &mut r, l, OP_SUB, OP_ADD, OP_XOR);
        e_cast(1, k, &mut l, r, OP_XOR, OP_SUB, OP_ADD);
        e_cast(0, k, &mut r, l, OP_ADD, OP_XOR, OP_SUB);
        *data.add(1) = l;
        *data = r;
    }
}

/// `void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAST_KEY *ks,
/// int enc)` — `crypto/cast/c_ecb.c:20-38`.
///
/// # Safety
/// `in`/`out` eight bytes; `ks` live.
#[no_mangle]
pub unsafe extern "C" fn CAST_ecb_encrypt(
    input: *const u8,
    output: *mut u8,
    ks: *const CastKey,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut d = [n2l(input), 0 as c_uint];
        d[1] = n2l(input.add(4));
        if enc != 0 {
            CAST_encrypt(d.as_mut_ptr(), ks);
        } else {
            CAST_decrypt(d.as_mut_ptr(), ks);
        }
        l2n(d[0], output);
        l2n(d[1], output.add(4));
    }
}

/// `n2l(c, l)` — `crypto/cast/cast_local.h:78-81`, big-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn n2l(p: *const u8) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p as c_uint) << 24)
            | ((*p.add(1) as c_uint) << 16)
            | ((*p.add(2) as c_uint) << 8)
            | (*p.add(3) as c_uint)
    }
}

/// `l2n(l, c)` — `crypto/cast/cast_local.h:84-87`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn l2n(v: c_uint, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = ((v >> 24) & 0xff) as u8;
        *p.add(1) = ((v >> 16) & 0xff) as u8;
        *p.add(2) = ((v >> 8) & 0xff) as u8;
        *p.add(3) = (v & 0xff) as u8;
    }
}

/// `n2ln(c, l1, l2, n)` — `crypto/cast/cast_local.h:15-44`.
///
/// # Safety
/// `p` readable for `n` bytes, `1 <= n <= 8`.
unsafe fn n2ln(p: *const u8, n: c_uint) -> (c_uint, c_uint) {
    let mut l1: c_uint = 0;
    let mut l2: c_uint = 0;
    // SAFETY: the loop walks exactly `n` bytes backwards from `p + n`.
    unsafe {
        let mut c = p.add(n as usize);
        let mut k = n;
        while k >= 1 {
            c = c.sub(1);
            let b = *c as c_uint;
            match k {
                8 => l2 = b,
                7 => l2 |= b << 8,
                6 => l2 |= b << 16,
                5 => l2 |= b << 24,
                4 => l1 = b,
                3 => l1 |= b << 8,
                2 => l1 |= b << 16,
                1 => l1 |= b << 24,
                _ => {}
            }
            k -= 1;
        }
    }
    (l1, l2)
}

/// `l2nn(l1, l2, c, n)` — `crypto/cast/cast_local.h:47-75`.
///
/// # Safety
/// `p` writable for `n` bytes, `1 <= n <= 8`.
unsafe fn l2nn(l1: c_uint, l2: c_uint, p: *mut u8, n: c_uint) {
    // SAFETY: the loop writes exactly `n` bytes backwards from `p + n`.
    unsafe {
        let mut c = p.add(n as usize);
        let mut k = n;
        while k >= 1 {
            c = c.sub(1);
            let v = match k {
                8 => l2 & 0xff,
                7 => (l2 >> 8) & 0xff,
                6 => (l2 >> 16) & 0xff,
                5 => (l2 >> 24) & 0xff,
                4 => l1 & 0xff,
                3 => (l1 >> 8) & 0xff,
                2 => (l1 >> 16) & 0xff,
                _ => (l1 >> 24) & 0xff,
            };
            *c = v as u8;
            k -= 1;
        }
    }
}

/// `void CAST_cbc_encrypt(...)` — `crypto/cast/c_enc.c:83-157`.
///
/// # Safety
/// `in`/`out` `length` bytes; `ks` live; `iv` eight bytes (written back).
#[no_mangle]
pub unsafe extern "C" fn CAST_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    ks: *const CastKey,
    iv: *mut u8,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if enc != 0 {
            let mut tout0 = n2l(iv);
            let mut tout1 = n2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = n2l(li) ^ tout0;
                let tin1 = n2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                CAST_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                tout1 = tin[1];
                l2n(tout0, lo);
                l2n(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
            if l != -8 {
                let (p0, p1) = n2ln(li, (l + 8) as c_uint);
                tin[0] = p0 ^ tout0;
                tin[1] = p1 ^ tout1;
                CAST_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                tout1 = tin[1];
                l2n(tout0, lo);
                l2n(tout1, lo.add(4));
            }
            l2n(tout0, iv);
            l2n(tout1, iv.add(4));
        } else {
            let mut xor0 = n2l(iv);
            let mut xor1 = n2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = n2l(li);
                let tin1 = n2l(li.add(4));
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                CAST_decrypt(tin.as_mut_ptr(), ks);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2n(tout0, lo);
                l2n(tout1, lo.add(4));
                lo = lo.add(8);
                xor0 = tin0;
                xor1 = tin1;
                l -= 8;
            }
            if l != -8 {
                let tin0 = n2l(li);
                let tin1 = n2l(li.add(4));
                tin[0] = tin0;
                tin[1] = tin1;
                CAST_decrypt(tin.as_mut_ptr(), ks);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2nn(tout0, tout1, lo, (l + 8) as c_uint);
                xor0 = tin0;
                xor1 = tin1;
            }
            l2n(xor0, iv);
            l2n(xor1, iv.add(4));
        }
    }
}

/// `void CAST_cfb64_encrypt(...)` — `crypto/cast/c_cfb64.c:25-80`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn CAST_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *const CastKey,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [0 as c_uint; 2];
        let mut c: u8;
        if enc != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = n2l(ivec);
                    ti[1] = n2l(ivec.add(4));
                    CAST_encrypt(ti.as_mut_ptr(), schedule);
                    l2n(ti[0], ivec);
                    l2n(ti[1], ivec.add(4));
                }
                c = *input ^ *ivec.add(n);
                *output = c;
                *ivec.add(n) = c;
                input = input.add(1);
                output = output.add(1);
                n = (n + 1) & 0x07;
                l -= 1;
            }
        } else {
            let mut cc: u8;
            while l > 0 {
                if n == 0 {
                    ti[0] = n2l(ivec);
                    ti[1] = n2l(ivec.add(4));
                    CAST_encrypt(ti.as_mut_ptr(), schedule);
                    l2n(ti[0], ivec);
                    l2n(ti[1], ivec.add(4));
                }
                cc = *input;
                c = *ivec.add(n);
                *ivec.add(n) = cc;
                *output = c ^ cc;
                input = input.add(1);
                output = output.add(1);
                n = (n + 1) & 0x07;
                l -= 1;
            }
        }
        *num = n as c_int;
    }
}

/// `void CAST_ofb64_encrypt(...)` — `crypto/cast/c_ofb64.c:24-67`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn CAST_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *const CastKey,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [n2l(ivec), n2l(ivec.add(4))];
        let mut d = [0u8; 8];
        l2n(ti[0], d.as_mut_ptr());
        l2n(ti[1], d.as_mut_ptr().add(4));
        let mut save = 0;
        while l > 0 {
            if n == 0 {
                CAST_encrypt(ti.as_mut_ptr(), schedule);
                l2n(ti[0], d.as_mut_ptr());
                l2n(ti[1], d.as_mut_ptr().add(4));
                save += 1;
            }
            *output = *input ^ d[n];
            input = input.add(1);
            output = output.add(1);
            n = (n + 1) & 0x07;
            l -= 1;
        }
        if save > 0 {
            l2n(ti[0], ivec);
            l2n(ti[1], ivec.add(4));
        }
        *num = n as c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(key: &[u8]) -> CastKey {
        let mut k = CastKey {
            data: [0; 32],
            short_key: 0,
        };
        // SAFETY: live local; `len` bytes readable.
        unsafe { CAST_set_key(&mut k, key.len() as c_int, key.as_ptr()) };
        k
    }

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // `test/recipes/30-test_evp_data/evpciph_cast5.txt`'s first `CAST5-ECB` block:
        // key `0123456712345678234567893456789a`, plaintext `0123456789abcdef`,
        // ciphertext `238b4fe5847e44b2`.
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34, 0x56,
            0x78, 0x9a,
        ];
        let ks = schedule(&key);
        let block = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut out = [0u8; 8];
        // SAFETY: live locals.
        unsafe {
            CAST_ecb_encrypt(
                block.as_ptr(),
                out.as_mut_ptr(),
                &ks as *const CastKey,
                CAST_ENCRYPT,
            )
        };
        assert_eq!(out, [0x23, 0x8b, 0x4f, 0xe5, 0x84, 0x7e, 0x44, 0xb2]);
    }
}
