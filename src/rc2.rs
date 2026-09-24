//! Phase 8.2 — `crypto/rc2/`: RC2, Rivest's variable-key block cipher.
//!
//! The authority's build has no perlasm arm for RC2, so `crypto/rc2/rc2_skey.c` and `rc2_cbc.c`
//! are the implementation, and `RT-CIPHER` proves this transcription is *that* function. The
//! `PITABLE` expansion table is generated (`crate::cipher_tables::RC2_KEY_TABLE`) from
//! `rc2_skey.c`, and the structure around it — the 128-byte key expansion, the effective-key-bits
//! reduction, the three passes of sixteen 16-bit rounds with their `MIX` — is transcribed.
//!
//! ## The effective-key-bits parameter is an observable, not a knob
//!
//! `RC2_set_key`'s fourth argument is the BSAFE-style effective key length in bits, and it is
//! *not* `len * 8`: `rc2_skey.c:59-103` uses it to choose the reduction's start index and mask.
//! The `RC2-40-CBC`/`RC2-64-CBC` spellings set it to 40 and 64, which is why `CT-CIPHER` drives
//! them through `RC2_set_key` directly rather than assuming the default.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uint, c_ulong};

use crate::cipher_tables::RC2_KEY_TABLE;

/// `RC2_BLOCK` — `include/openssl/rc2.h:26`.
pub const RC2_BLOCK: usize = 8;
/// `RC2_KEY_LENGTH` — `include/openssl/rc2.h:27`.
pub const RC2_KEY_LENGTH: usize = 16;
/// `RC2_ENCRYPT` — `include/openssl/rc2.h:32`.
pub const RC2_ENCRYPT: c_int = 1;
/// `RC2_DECRYPT` — `include/openssl/rc2.h:33`.
pub const RC2_DECRYPT: c_int = 0;

/// `RC2_KEY` — `include/openssl/rc2.h:35-37`: `RC2_INT data[64]`, where `RC2_INT` is
/// `unsigned int`.
#[repr(C)]
pub struct Rc2Key {
    /// `RC2_INT data[64]`.
    pub data: [c_uint; 64],
}

/// `c2l(c, l)` — `crypto/rc2/rc2_local.h:11-14`; `l` is `unsigned long`.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn c2l(p: *const u8) -> c_ulong {
    // SAFETY: the caller's contract.
    unsafe {
        (*p as c_ulong)
            | ((*p.add(1) as c_ulong) << 8)
            | ((*p.add(2) as c_ulong) << 16)
            | ((*p.add(3) as c_ulong) << 24)
    }
}

/// `l2c(l, c)` — `crypto/rc2/rc2_local.h:50-53`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn l2c(v: c_ulong, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = (v & 0xff) as u8;
        *p.add(1) = ((v >> 8) & 0xff) as u8;
        *p.add(2) = ((v >> 16) & 0xff) as u8;
        *p.add(3) = ((v >> 24) & 0xff) as u8;
    }
}

/// `c2ln(c, l1, l2, n)` — `crypto/rc2/rc2_local.h:18-47`.
///
/// # Safety
/// `p` readable for `n` bytes, `1 <= n <= 8`.
unsafe fn c2ln(p: *const u8, n: c_uint) -> (c_ulong, c_ulong) {
    let mut l1: c_ulong = 0;
    let mut l2: c_ulong = 0;
    // SAFETY: the loop walks exactly `n` bytes backwards from `p + n`.
    unsafe {
        let mut c = p.add(n as usize);
        let mut k = n;
        while k >= 1 {
            c = c.sub(1);
            let b = *c as c_ulong;
            match k {
                8 => l2 = b << 24,
                7 => l2 |= b << 16,
                6 => l2 |= b << 8,
                5 => l2 |= b,
                4 => l1 = b << 24,
                3 => l1 |= b << 16,
                2 => l1 |= b << 8,
                1 => l1 |= b,
                _ => {}
            }
            k -= 1;
        }
    }
    (l1, l2)
}

/// `l2cn(l1, l2, c, n)` — `crypto/rc2/rc2_local.h:57-84`.
///
/// # Safety
/// `p` writable for `n` bytes, `1 <= n <= 8`.
unsafe fn l2cn(l1: c_ulong, l2: c_ulong, p: *mut u8, n: c_uint) {
    // SAFETY: the loop writes exactly `n` bytes backwards from `p + n`.
    unsafe {
        let mut c = p.add(n as usize);
        let mut k = n;
        while k >= 1 {
            c = c.sub(1);
            let v = match k {
                8 => (l2 >> 24) & 0xff,
                7 => (l2 >> 16) & 0xff,
                6 => (l2 >> 8) & 0xff,
                5 => l2 & 0xff,
                4 => (l1 >> 24) & 0xff,
                3 => (l1 >> 16) & 0xff,
                2 => (l1 >> 8) & 0xff,
                _ => l1 & 0xff,
            };
            *c = v as u8;
            k -= 1;
        }
    }
}

/// `void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits)` —
/// `crypto/rc2/rc2_skey.c:59-104`.
///
/// # Safety
/// `key` writable; `data` readable for `len` bytes with `len >= 1` (a zero length reads
/// `data[-1]` in the authority too).
// The two index loops below mirror `rc2_skey.c`'s own byte-index arithmetic (the lookback into
// `k[j]` and the reduction's `k[i + j]`), which an iterator rewrite would obscure.
#[allow(clippy::needless_range_loop)]
#[no_mangle]
pub unsafe extern "C" fn RC2_set_key(key: *mut Rc2Key, len: c_int, data: *const u8, bits: c_int) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut len = len;
        let mut bits = bits;
        if len > 128 {
            len = 128;
        }
        if bits <= 0 {
            bits = 1024;
        }
        if bits > 1024 {
            bits = 1024;
        }
        // The expansion works on the same 128 bytes the schedule is stored in, low byte first.
        let mut k = [0u8; 128];
        let src = core::slice::from_raw_parts(data, len as usize);
        k[..len as usize].copy_from_slice(src);
        let mut d: c_uint = k[len as usize - 1] as c_uint;
        let mut j = 0usize;
        for i in len as usize..128 {
            d = RC2_KEY_TABLE[((k[j] as u32 + d) & 0xff) as usize] as c_uint;
            k[i] = d as u8;
            j += 1;
        }

        // Reduce the key to `bits` effective bits, BSAFE-style.
        j = ((bits + 7) >> 3) as usize;
        let mut i = 128usize - j;
        let c: c_uint = 0xff >> ((-bits) & 0x07);
        d = RC2_KEY_TABLE[(k[i] as u32 & c) as usize] as c_uint;
        k[i] = d as u8;
        while i > 0 {
            i -= 1;
            d = RC2_KEY_TABLE[(k[i + j] as u32 ^ d) as usize] as c_uint;
            k[i] = d as u8;
        }

        // Copy the bytes into the 64 sixteen-bit words, high byte first.
        let ki = (*key).data.as_mut_ptr().add(63);
        for idx in (1..128).step_by(2).rev() {
            let word = ((k[idx] as c_uint) << 8) | (k[idx - 1] as c_uint);
            *ki.sub((127 - idx) / 2) = word & 0xffff;
        }
    }
}

/// `void RC2_encrypt(unsigned long *d, RC2_KEY *key)` — `crypto/rc2/rc2_cbc.c:94-136`.
///
/// # Safety
/// `d` holds two `unsigned long`s; `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn RC2_encrypt(d: *mut c_ulong, key: *mut Rc2Key) {
    // SAFETY: the caller's contract.
    unsafe {
        let l = *d;
        let mut x0 = (l & 0xffff) as c_uint;
        let mut x1 = ((l >> 16) & 0xffff) as c_uint;
        let l = *d.add(1);
        let mut x2 = (l & 0xffff) as c_uint;
        let mut x3 = ((l >> 16) & 0xffff) as c_uint;

        let mut n = 3;
        let mut i = 5;
        let data = &(*key).data;
        let mut p0 = 0usize;

        loop {
            let mut t = (x0 + (x1 & !x3) + (x2 & x3) + data[p0]) & 0xffff;
            p0 += 1;
            x0 = ((t << 1) | (t >> 15)) & 0xffff;
            t = (x1 + (x2 & !x0) + (x3 & x0) + data[p0]) & 0xffff;
            p0 += 1;
            x1 = ((t << 2) | (t >> 14)) & 0xffff;
            t = (x2 + (x3 & !x1) + (x0 & x1) + data[p0]) & 0xffff;
            p0 += 1;
            x2 = ((t << 3) | (t >> 13)) & 0xffff;
            t = (x3 + (x0 & !x2) + (x1 & x2) + data[p0]) & 0xffff;
            p0 += 1;
            x3 = ((t << 5) | (t >> 11)) & 0xffff;

            i -= 1;
            if i == 0 {
                n -= 1;
                if n == 0 {
                    break;
                }
                i = if n == 2 { 6 } else { 5 };
                x0 = (x0 + data[(x3 & 0x3f) as usize]) & 0xffff;
                x1 = (x1 + data[(x0 & 0x3f) as usize]) & 0xffff;
                x2 = (x2 + data[(x1 & 0x3f) as usize]) & 0xffff;
                x3 = (x3 + data[(x2 & 0x3f) as usize]) & 0xffff;
            }
        }

        *d = (x0 & 0xffff) as c_ulong | ((x1 & 0xffff) as c_ulong) << 16;
        *d.add(1) = (x2 & 0xffff) as c_ulong | ((x3 & 0xffff) as c_ulong) << 16;
    }
}

/// `void RC2_decrypt(unsigned long *d, RC2_KEY *key)` — `crypto/rc2/rc2_cbc.c:138-181`.
///
/// # Safety
/// As [`RC2_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn RC2_decrypt(d: *mut c_ulong, key: *mut Rc2Key) {
    // SAFETY: the caller's contract.
    unsafe {
        let l = *d;
        let mut x0 = (l & 0xffff) as c_uint;
        let mut x1 = ((l >> 16) & 0xffff) as c_uint;
        let l = *d.add(1);
        let mut x2 = (l & 0xffff) as c_uint;
        let mut x3 = ((l >> 16) & 0xffff) as c_uint;

        let mut n = 3;
        let mut i = 5;
        let data = &(*key).data;
        // `isize` because the authority's `p0` is decremented past the array start on the last
        // group; a `usize` would underflow and panic where the C pointer simply moves.
        let mut p0: isize = 63;

        loop {
            let mut t = ((x3 << 11) | (x3 >> 5)) & 0xffff;
            x3 = (t
                .wrapping_sub(x0 & !x2)
                .wrapping_sub(x1 & x2)
                .wrapping_sub(data[p0 as usize]))
                & 0xffff;
            p0 -= 1;
            t = ((x2 << 13) | (x2 >> 3)) & 0xffff;
            x2 = (t
                .wrapping_sub(x3 & !x1)
                .wrapping_sub(x0 & x1)
                .wrapping_sub(data[p0 as usize]))
                & 0xffff;
            p0 -= 1;
            t = ((x1 << 14) | (x1 >> 2)) & 0xffff;
            x1 = (t
                .wrapping_sub(x2 & !x0)
                .wrapping_sub(x3 & x0)
                .wrapping_sub(data[p0 as usize]))
                & 0xffff;
            p0 -= 1;
            t = ((x0 << 15) | (x0 >> 1)) & 0xffff;
            x0 = (t
                .wrapping_sub(x1 & !x3)
                .wrapping_sub(x2 & x3)
                .wrapping_sub(data[p0 as usize]))
                & 0xffff;
            p0 -= 1;

            i -= 1;
            if i == 0 {
                n -= 1;
                if n == 0 {
                    break;
                }
                i = if n == 2 { 6 } else { 5 };
                x3 = x3.wrapping_sub(data[(x2 & 0x3f) as usize]) & 0xffff;
                x2 = x2.wrapping_sub(data[(x1 & 0x3f) as usize]) & 0xffff;
                x1 = x1.wrapping_sub(data[(x0 & 0x3f) as usize]) & 0xffff;
                x0 = x0.wrapping_sub(data[(x3 & 0x3f) as usize]) & 0xffff;
            }
        }

        *d = (x0 & 0xffff) as c_ulong | ((x1 & 0xffff) as c_ulong) << 16;
        *d.add(1) = (x2 & 0xffff) as c_ulong | ((x3 & 0xffff) as c_ulong) << 16;
    }
}

/// `void RC2_ecb_encrypt(const unsigned char *in, unsigned char *out, RC2_KEY *key, int encrypt)`
/// — `crypto/rc2/rc2_ecb.c:28-46`.
///
/// # Safety
/// `in`/`out` eight bytes; `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn RC2_ecb_encrypt(
    input: *const u8,
    output: *mut u8,
    key: *mut Rc2Key,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut d = [c2l(input), 0 as c_ulong];
        d[1] = c2l(input.add(4));
        if encrypt != 0 {
            RC2_encrypt(d.as_mut_ptr(), key);
        } else {
            RC2_decrypt(d.as_mut_ptr(), key);
        }
        l2c(d[0], output);
        l2c(d[1], output.add(4));
    }
}

/// `void RC2_cbc_encrypt(...)` — `crypto/rc2/rc2_cbc.c:19-92`.
///
/// # Safety
/// `in`/`out` `length` bytes; `ks` a live schedule; `iv` eight bytes (written back).
#[no_mangle]
pub unsafe extern "C" fn RC2_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    ks: *mut Rc2Key,
    iv: *mut u8,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_ulong; 2];
        if encrypt != 0 {
            let mut tout0 = c2l(iv);
            let mut tout1 = c2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = c2l(li) ^ tout0;
                let tin1 = c2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                RC2_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                l2c(tout0, lo);
                tout1 = tin[1];
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
            if l != -8 {
                let (p0, p1) = c2ln(li, (l + 8) as c_uint);
                tin[0] = p0 ^ tout0;
                tin[1] = p1 ^ tout1;
                RC2_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                l2c(tout0, lo);
                tout1 = tin[1];
                l2c(tout1, lo.add(4));
            }
            l2c(tout0, iv);
            l2c(tout1, iv.add(4));
        } else {
            let mut xor0 = c2l(iv);
            let mut xor1 = c2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = c2l(li);
                let tin1 = c2l(li.add(4));
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                RC2_decrypt(tin.as_mut_ptr(), ks);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2c(tout0, lo);
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                xor0 = tin0;
                xor1 = tin1;
                l -= 8;
            }
            if l != -8 {
                let tin0 = c2l(li);
                let tin1 = c2l(li.add(4));
                tin[0] = tin0;
                tin[1] = tin1;
                RC2_decrypt(tin.as_mut_ptr(), ks);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2cn(tout0, tout1, lo, (l + 8) as c_uint);
                xor0 = tin0;
                xor1 = tin1;
            }
            l2c(xor0, iv);
            l2c(xor1, iv.add(4));
        }
    }
}

/// `void RC2_cfb64_encrypt(...)` — `crypto/rc2/rc2cfb64.c:25-80`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` a live schedule; `ivec` eight bytes; `num`
/// readable/writable.
#[no_mangle]
pub unsafe extern "C" fn RC2_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut Rc2Key,
    ivec: *mut u8,
    num: *mut c_int,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [0 as c_ulong; 2];
        let mut c: u8;
        if encrypt != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = c2l(ivec);
                    ti[1] = c2l(ivec.add(4));
                    RC2_encrypt(ti.as_mut_ptr(), schedule);
                    l2c(ti[0], ivec);
                    l2c(ti[1], ivec.add(4));
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
                    ti[0] = c2l(ivec);
                    ti[1] = c2l(ivec.add(4));
                    RC2_encrypt(ti.as_mut_ptr(), schedule);
                    l2c(ti[0], ivec);
                    l2c(ti[1], ivec.add(4));
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

/// `void RC2_ofb64_encrypt(...)` — `crypto/rc2/rc2ofb64.c:24-67`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` a live schedule; `ivec` eight bytes; `num`
/// readable/writable.
#[no_mangle]
pub unsafe extern "C" fn RC2_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut Rc2Key,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [c2l(ivec), c2l(ivec.add(4))];
        let mut d = [0u8; 8];
        l2c(ti[0], d.as_mut_ptr());
        l2c(ti[1], d.as_mut_ptr().add(4));
        let mut save = 0;
        while l > 0 {
            if n == 0 {
                RC2_encrypt(ti.as_mut_ptr(), schedule);
                l2c(ti[0], d.as_mut_ptr());
                l2c(ti[1], d.as_mut_ptr().add(4));
                save += 1;
            }
            *output = *input ^ d[n];
            input = input.add(1);
            output = output.add(1);
            n = (n + 1) & 0x07;
            l -= 1;
        }
        if save > 0 {
            l2c(ti[0], ivec);
            l2c(ti[1], ivec.add(4));
        }
        *num = n as c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(key: &[u8], bits: c_int) -> Rc2Key {
        let mut k = Rc2Key { data: [0; 64] };
        // SAFETY: live local, non-empty key.
        unsafe { RC2_set_key(&mut k, key.len() as c_int, key.as_ptr(), bits) };
        k
    }

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // `test/recipes/30-test_evp_data/evpciph_rc2.txt`: `RC2-ECB`, an **eight-byte** key
        // `0000000000000000`, plaintext `0001020304050607`, ciphertext `a4085a9f3e710563`. The
        // recipe says these were generated by the deprecated cipher code to pin provider
        // equivalence, so this is the authority's own value rather than a published standard one.
        // The key length matters to the schedule even though the effective bits are 128.
        let key = [0u8; 8];
        let ks = schedule(&key, 128);
        let block = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let mut out = [0u8; 8];
        // SAFETY: live locals.
        unsafe {
            RC2_ecb_encrypt(
                block.as_ptr(),
                out.as_mut_ptr(),
                &ks as *const Rc2Key as *mut Rc2Key,
                1,
            )
        };
        assert_eq!(out, [0xa4, 0x08, 0x5a, 0x9f, 0x3e, 0x71, 0x05, 0x63]);
    }
}
