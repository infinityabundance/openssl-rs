//! Phase 8.2 — `crypto/bf/`: Blowfish, Schneier's 16-round Feistel cipher.
//!
//! The authority has no perlasm arm for Blowfish on this profile, so `crypto/bf/bf_enc.c` and
//! `bf_skey.c` are the implementation. The P array and the four S-boxes are the fractional part
//! of π, and they are generated from `crypto/bf/bf_pi.h` into
//! [`crate::cipher_tables::BF_P`]/[`crate::cipher_tables::BF_S`] rather than typed (D33).
//!
//! ## `BF_set_key` derives the schedule by encrypting with itself
//!
//! `bf_skey.c:22-72` first XORs the P array with the key bytes read cyclically, then repeatedly
//! encrypts the all-zero block, replacing each P word and then each S word with the result. That
//! self-referential derivation is the whole of the key schedule, and `RT-CIPHER` observes the
//! resulting `BF_KEY` as bytes so a wrong π word or a wrong round order is a residual.
//!
//! ## The byte order is big-endian, unlike DES
//!
//! `bf_local.h`'s `n2l`/`l2n` are big-endian, while DES's `c2l`/`l2c` are little-endian; the two
//! are deliberately not shared here.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint};

use crate::cipher_tables::{BF_P, BF_S};

/// `BF_BLOCK` — `include/openssl/blowfish.h:27`.
pub const BF_BLOCK: usize = 8;
/// `BF_ENCRYPT` — `include/openssl/blowfish.h:31`.
pub const BF_ENCRYPT: c_int = 1;
/// `BF_DECRYPT` — `include/openssl/blowfish.h:32`.
pub const BF_DECRYPT: c_int = 0;
/// `BF_ROUNDS` — `include/openssl/blowfish.h:41`.
pub const BF_ROUNDS: usize = 16;

/// `BF_KEY` — `include/openssl/blowfish.h:43-46`: `P[18]` and `S[4 * 256]` of `unsigned int`.
#[repr(C)]
pub struct BfKey {
    /// `BF_LONG P[BF_ROUNDS + 2]`.
    pub p: [c_uint; BF_ROUNDS + 2],
    /// `BF_LONG S[4 * 256]`.
    pub s: [c_uint; 4 * 256],
}

/// `n2l(c, l)` — `crypto/bf/bf_local.h:78-81`, big-endian.
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

/// `l2n(l, c)` — `crypto/bf/bf_local.h:84-87`.
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

/// `n2ln(c, l1, l2, n)` — `crypto/bf/bf_local.h:15-44`, the non-advancing partial reader.
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

/// `l2nn(l1, l2, c, n)` — `crypto/bf/bf_local.h:47-75`.
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

/// `BF_ENC(LL, R, S, P)` — `crypto/bf/bf_local.h:94-96`.
#[inline]
fn bf_enc(ll: &mut c_uint, r: c_uint, s: &[c_uint; 1024], p: c_uint) {
    *ll ^= p;
    *ll ^= (s[((r >> 24) & 0xff) as usize].wrapping_add(s[0x100 + ((r >> 16) & 0xff) as usize])
        ^ s[0x200 + ((r >> 8) & 0xff) as usize])
        .wrapping_add(s[0x300 + (r & 0xff) as usize]);
}

/// `const char *BF_options(void)` — `crypto/bf/bf_ecb.c:26-29`.
///
/// # Safety
/// None; the pointer is a `'static` C string.
#[no_mangle]
pub unsafe extern "C" fn BF_options() -> *const c_char {
    c"blowfish(ptr)".as_ptr()
}

/// `void BF_set_key(BF_KEY *key, int len, const unsigned char *data)` —
/// `crypto/bf/bf_skey.c:22-72`.
///
/// # Safety
/// `key` writable; `data` readable for `len` bytes with `len >= 1`.
#[no_mangle]
pub unsafe extern "C" fn BF_set_key(key: *mut BfKey, len: c_int, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe {
        (*key).p = BF_P;
        (*key).s = BF_S;

        let mut len = len;
        if len > (BF_ROUNDS as c_int + 2) * 4 {
            len = (BF_ROUNDS as c_int + 2) * 4;
        }
        let end = data.add(len as usize);
        let mut d = data;
        for i in 0..BF_ROUNDS + 2 {
            let mut ri = *d as c_uint;
            d = d.add(1);
            if d >= end {
                d = data;
            }
            ri = (ri << 8) | *d as c_uint;
            d = d.add(1);
            if d >= end {
                d = data;
            }
            ri = (ri << 8) | *d as c_uint;
            d = d.add(1);
            if d >= end {
                d = data;
            }
            ri = (ri << 8) | *d as c_uint;
            d = d.add(1);
            if d >= end {
                d = data;
            }
            (*key).p[i] ^= ri;
        }

        let mut block = [0 as c_uint; 2];
        for i in (0..BF_ROUNDS + 2).step_by(2) {
            BF_encrypt(block.as_mut_ptr(), key);
            (*key).p[i] = block[0];
            (*key).p[i + 1] = block[1];
        }
        for i in (0..4 * 256).step_by(2) {
            BF_encrypt(block.as_mut_ptr(), key);
            (*key).s[i] = block[0];
            (*key).s[i + 1] = block[1];
        }
    }
}

/// `void BF_encrypt(BF_LONG *data, const BF_KEY *key)` — `crypto/bf/bf_enc.c:30-67`.
///
/// # Safety
/// `data` holds two words; `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn BF_encrypt(data: *mut c_uint, key: *const BfKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let p = (*key).p.as_ptr();
        let s = &(*key).s;
        let mut l = *data;
        let mut r = *data.add(1);

        l ^= *p;
        bf_enc(&mut r, l, s, *p.add(1));
        bf_enc(&mut l, r, s, *p.add(2));
        bf_enc(&mut r, l, s, *p.add(3));
        bf_enc(&mut l, r, s, *p.add(4));
        bf_enc(&mut r, l, s, *p.add(5));
        bf_enc(&mut l, r, s, *p.add(6));
        bf_enc(&mut r, l, s, *p.add(7));
        bf_enc(&mut l, r, s, *p.add(8));
        bf_enc(&mut r, l, s, *p.add(9));
        bf_enc(&mut l, r, s, *p.add(10));
        bf_enc(&mut r, l, s, *p.add(11));
        bf_enc(&mut l, r, s, *p.add(12));
        bf_enc(&mut r, l, s, *p.add(13));
        bf_enc(&mut l, r, s, *p.add(14));
        bf_enc(&mut r, l, s, *p.add(15));
        bf_enc(&mut l, r, s, *p.add(16));
        r ^= *p.add(BF_ROUNDS + 1);

        *data.add(1) = l;
        *data = r;
    }
}

/// `void BF_decrypt(BF_LONG *data, const BF_KEY *key)` — `crypto/bf/bf_enc.c:69-106`.
///
/// # Safety
/// As [`BF_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn BF_decrypt(data: *mut c_uint, key: *const BfKey) {
    // SAFETY: the caller's contract.
    unsafe {
        let p = (*key).p.as_ptr();
        let s = &(*key).s;
        let mut l = *data;
        let mut r = *data.add(1);

        l ^= *p.add(BF_ROUNDS + 1);
        bf_enc(&mut r, l, s, *p.add(16));
        bf_enc(&mut l, r, s, *p.add(15));
        bf_enc(&mut r, l, s, *p.add(14));
        bf_enc(&mut l, r, s, *p.add(13));
        bf_enc(&mut r, l, s, *p.add(12));
        bf_enc(&mut l, r, s, *p.add(11));
        bf_enc(&mut r, l, s, *p.add(10));
        bf_enc(&mut l, r, s, *p.add(9));
        bf_enc(&mut r, l, s, *p.add(8));
        bf_enc(&mut l, r, s, *p.add(7));
        bf_enc(&mut r, l, s, *p.add(6));
        bf_enc(&mut l, r, s, *p.add(5));
        bf_enc(&mut r, l, s, *p.add(4));
        bf_enc(&mut l, r, s, *p.add(3));
        bf_enc(&mut r, l, s, *p.add(2));
        bf_enc(&mut l, r, s, *p.add(1));
        r ^= *p;

        *data.add(1) = l;
        *data = r;
    }
}

/// `void BF_ecb_encrypt(const unsigned char *in, unsigned char *out, const BF_KEY *key,
/// int encrypt)` — `crypto/bf/bf_ecb.c:31-49`.
///
/// # Safety
/// `in`/`out` eight bytes; `key` live.
#[no_mangle]
pub unsafe extern "C" fn BF_ecb_encrypt(
    input: *const u8,
    output: *mut u8,
    key: *const BfKey,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut d = [n2l(input), 0 as c_uint];
        d[1] = n2l(input.add(4));
        if encrypt != 0 {
            BF_encrypt(d.as_mut_ptr(), key);
        } else {
            BF_decrypt(d.as_mut_ptr(), key);
        }
        l2n(d[0], output);
        l2n(d[1], output.add(4));
    }
}

/// `void BF_cbc_encrypt(...)` — `crypto/bf/bf_enc.c:108-181`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes (written back).
#[no_mangle]
pub unsafe extern "C" fn BF_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *const BfKey,
    ivec: *mut u8,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if encrypt != 0 {
            let mut tout0 = n2l(ivec);
            let mut tout1 = n2l(ivec.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = n2l(li) ^ tout0;
                let tin1 = n2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                BF_encrypt(tin.as_mut_ptr(), schedule);
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
                BF_encrypt(tin.as_mut_ptr(), schedule);
                tout0 = tin[0];
                tout1 = tin[1];
                l2n(tout0, lo);
                l2n(tout1, lo.add(4));
            }
            l2n(tout0, ivec);
            l2n(tout1, ivec.add(4));
        } else {
            let mut xor0 = n2l(ivec);
            let mut xor1 = n2l(ivec.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = n2l(li);
                let tin1 = n2l(li.add(4));
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                BF_decrypt(tin.as_mut_ptr(), schedule);
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
                BF_decrypt(tin.as_mut_ptr(), schedule);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2nn(tout0, tout1, lo, (l + 8) as c_uint);
                xor0 = tin0;
                xor1 = tin1;
            }
            l2n(xor0, ivec);
            l2n(xor1, ivec.add(4));
        }
    }
}

/// `void BF_cfb64_encrypt(...)` — `crypto/bf/bf_cfb64.c:25-80`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn BF_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *const BfKey,
    ivec: *mut u8,
    num: *mut c_int,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [0 as c_uint; 2];
        let mut c: u8;
        if encrypt != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = n2l(ivec);
                    ti[1] = n2l(ivec.add(4));
                    BF_encrypt(ti.as_mut_ptr(), schedule);
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
                    BF_encrypt(ti.as_mut_ptr(), schedule);
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

/// `void BF_ofb64_encrypt(...)` — `crypto/bf/bf_ofb64.c:24-67`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn BF_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *const BfKey,
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
                BF_encrypt(ti.as_mut_ptr(), schedule);
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

    #[test]
    fn the_options_string_is_the_measured_one() {
        // SAFETY: the returned pointer is a static C string.
        let s = unsafe { BF_options() };
        // SAFETY: `s` points at that static NUL-terminated C string.
        let text = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes();
        assert_eq!(text, b"blowfish(ptr)");
    }

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // `test/recipes/30-test_evp_data/evpciph_bf.txt`'s `BF-ECB` first block: key
        // `000102…0f`, plaintext `0f0e0c0d0b0a0908`, ciphertext `079590e001062668`.
        let mut key = BfKey {
            p: [0; 18],
            s: [0; 1024],
        };
        let k: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        // SAFETY: live local, non-empty key.
        unsafe { BF_set_key(&mut key, 16, k.as_ptr()) };
        let block = [0x0fu8, 0x0e, 0x0c, 0x0d, 0x0b, 0x0a, 0x09, 0x08];
        let mut out = [0u8; 8];
        // SAFETY: live locals.
        unsafe {
            BF_ecb_encrypt(
                block.as_ptr(),
                out.as_mut_ptr(),
                &key as *const BfKey,
                BF_ENCRYPT,
            )
        };
        assert_eq!(out, [0x07, 0x95, 0x90, 0xe0, 0x01, 0x06, 0x26, 0x68]);
    }
}
