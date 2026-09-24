//! Phase 8.2 — `crypto/idea/`: IDEA (Lai–Massey).
//!
//! The authority has no perlasm arm for IDEA; `crypto/idea/i_skey.c`, `i_cbc.c` and the mode
//! files are the implementation. There is **no table** to generate — the multiplicative inverse
//! is computed at key-schedule time by `inverse` (`i_skey.c:91-118`) — so this module is pure
//! structure, and `RT-CIPHER` observes the whole 54-word schedule as bytes.
//!
//! ## The keystream is `unsigned long`, not 32-bit
//!
//! `i_cbc.c:96-128`'s `IDEA_encrypt` declares `x1`…`x4`, `t0`, `t1`, `ul` as `unsigned long`,
//! and `idea_mul` multiplies two of them into a `unsigned long` before reducing modulo `2^16 +
//! 1`. On this profile that is 64-bit arithmetic, so the transcription uses `u64` throughout:
//! the intermediate values exceed 16 bits and are masked only where the authority masks them.
//! The `ul == 0` arm is `-(int)a - b + 1` computed in C's implicit `unsigned long`, which is
//! reproduced exactly.
//!
//! ## The negative-`num` poison arm is IDEA's own
//!
//! `i_cfb64.c:36-39` and `i_ofb64.c:38-41` set `*num = -1` and return when the incoming `*num`
//! is negative — the one mode pair in this stratum that does, which `RT-CIPHER` observes.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_ulong};

/// `IDEA_BLOCK` — `include/openssl/idea.h:26`.
pub const IDEA_BLOCK: usize = 8;
/// `IDEA_KEY_LENGTH` — `include/openssl/idea.h:27`.
pub const IDEA_KEY_LENGTH: usize = 16;
/// `IDEA_ENCRYPT` — `include/openssl/idea.h:33`.
pub const IDEA_ENCRYPT: c_int = 1;
/// `IDEA_DECRYPT` — `include/openssl/idea.h:34`.
pub const IDEA_DECRYPT: c_int = 0;

/// `IDEA_KEY_SCHEDULE` — `include/openssl/idea.h:36-38`: `IDEA_INT data[9][6]` — fifty-four
/// words, of which the cipher reads fifty-two.
#[repr(C)]
pub struct IdeaKeySchedule {
    /// `IDEA_INT data[9][6]`.
    pub data: [[u32; 6]; 9],
}

/// The flattened view the schedule is written through: fifty-four words.
impl IdeaKeySchedule {
    fn words_mut(&mut self) -> &mut [u32; 54] {
        // SAFETY: `[[u32; 6]; 9]` is fifty-four contiguous `u32`s and `repr(C)` fixes the layout.
        unsafe { &mut *self.data.as_mut_ptr().cast::<[u32; 54]>() }
    }

    fn words(&self) -> &[u32; 54] {
        // SAFETY: as `words_mut`.
        unsafe { &*self.data.as_ptr().cast::<[u32; 54]>() }
    }
}

/// `n2s(c, l)` — `crypto/idea/idea_local.h:99-100`, big-endian sixteen bits.
///
/// # Safety
/// `p` readable for two bytes.
#[inline]
unsafe fn n2s(p: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { ((*p as u32) << 8) | (*p.add(1) as u32) }
}

/// `n2l(c, l)` — `crypto/idea/idea_local.h:83-86`, big-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn n2l(p: *const u8) -> c_ulong {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p as c_ulong) << 24)
            | ((*p.add(1) as c_ulong) << 16)
            | ((*p.add(2) as c_ulong) << 8)
            | (*p.add(3) as c_ulong)
    }
}

/// `l2n(l, c)` — `crypto/idea/idea_local.h:89-92`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn l2n(v: c_ulong, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = ((v >> 24) & 0xff) as u8;
        *p.add(1) = ((v >> 16) & 0xff) as u8;
        *p.add(2) = ((v >> 8) & 0xff) as u8;
        *p.add(3) = (v & 0xff) as u8;
    }
}

/// `n2ln(c, l1, l2, n)` — `crypto/idea/idea_local.h:20-49`.
///
/// # Safety
/// `p` readable for `n` bytes, `1 <= n <= 8`.
unsafe fn n2ln(p: *const u8, n: u32) -> (c_ulong, c_ulong) {
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

/// `l2nn(l1, l2, c, n)` — `crypto/idea/idea_local.h:52-80`.
///
/// # Safety
/// `p` writable for `n` bytes, `1 <= n <= 8`.
unsafe fn l2nn(l1: c_ulong, l2: c_ulong, p: *mut u8, n: u32) {
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

/// `idea_mul(r, a, b, ul)` — `crypto/idea/idea_local.h:10-17`.
#[inline]
fn idea_mul(a: u64, b: u64) -> u64 {
    let ul = a.wrapping_mul(b);
    if ul != 0 {
        let mut r = (ul & 0xffff).wrapping_sub(ul >> 16);
        r = r.wrapping_sub(r >> 16);
        r
    } else {
        // `(-(int)a - b + 1)`: `-(int)a` is an `int`, `b` is `unsigned long`, so the C
        // subtraction is done in `unsigned long`.
        ((-(a as i32)) as i64 as u64)
            .wrapping_sub(b)
            .wrapping_add(1)
    }
}

/// `const char *IDEA_options(void)` — `crypto/idea/i_ecb.c:21-24`.
///
/// # Safety
/// None; the pointer is a `'static` C string.
#[no_mangle]
pub unsafe extern "C" fn IDEA_options() -> *const c_char {
    c"idea(int)".as_ptr()
}

/// `inverse(xin)` — `crypto/idea/i_skey.c:91-118`, the multiplicative inverse modulo `2^16 + 1`.
fn inverse(xin: u32) -> u32 {
    if xin == 0 {
        return 0;
    }
    let mut n1: i64 = 0x10001;
    let mut n2: i64 = xin as i64;
    let mut b2: i64 = 1;
    let mut b1: i64 = 0;
    loop {
        let r = n1 % n2;
        let q = (n1 - r) / n2;
        if r == 0 {
            if b2 < 0 {
                b2 += 0x10001;
            }
            break;
        }
        n1 = n2;
        n2 = r;
        let t = b2;
        b2 = b1 - q * b2;
        b1 = t;
    }
    b2 as u32
}

/// `void IDEA_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks)` —
/// `crypto/idea/i_skey.c:21-59`.
///
/// # Safety
/// `key` readable for sixteen bytes; `ks` writable.
// The index loop mirrors `i_skey.c`'s `kt[i] = n2s(key)` and `key` advances by two each step.
#[allow(clippy::needless_range_loop)]
#[no_mangle]
pub unsafe extern "C" fn IDEA_set_encrypt_key(key: *const u8, ks: *mut IdeaKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let kt = (*ks).words_mut();
        for i in 0..8 {
            kt[i] = n2s(key.add(2 * i));
        }

        let mut kt_idx = 8usize;
        for i in 0..6 {
            let kf = i * 8;
            let r2 = kt[kf + 1];
            let mut r1 = kt[kf + 2];
            kt[kt_idx] = ((r2 << 9) | (r1 >> 7)) & 0xffff;
            kt_idx += 1;
            let mut r0 = kt[kf + 3];
            kt[kt_idx] = ((r1 << 9) | (r0 >> 7)) & 0xffff;
            kt_idx += 1;
            r1 = kt[kf + 4];
            kt[kt_idx] = ((r0 << 9) | (r1 >> 7)) & 0xffff;
            kt_idx += 1;
            r0 = kt[kf + 5];
            kt[kt_idx] = ((r1 << 9) | (r0 >> 7)) & 0xffff;
            kt_idx += 1;
            r1 = kt[kf + 6];
            kt[kt_idx] = ((r0 << 9) | (r1 >> 7)) & 0xffff;
            kt_idx += 1;
            r0 = kt[kf + 7];
            kt[kt_idx] = ((r1 << 9) | (r0 >> 7)) & 0xffff;
            kt_idx += 1;
            let r1 = kt[kf];
            if i >= 5 {
                break;
            }
            kt[kt_idx] = ((r0 << 9) | (r1 >> 7)) & 0xffff;
            kt_idx += 1;
            kt[kt_idx] = ((r1 << 9) | (r2 >> 7)) & 0xffff;
            kt_idx += 1;
        }
    }
}

/// `void IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)` —
/// `crypto/idea/i_skey.c:61-88`.
///
/// # Safety
/// `ek` a live encryption schedule; `dk` writable.
#[no_mangle]
pub unsafe extern "C" fn IDEA_set_decrypt_key(ek: *mut IdeaKeySchedule, dk: *mut IdeaKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let src = (*ek).words();
        let tp = (*dk).words_mut();
        let mut tp_idx = 0usize;
        let mut fp = 48isize;
        for r in 0..9 {
            tp[tp_idx] = inverse(src[fp as usize]);
            tp_idx += 1;
            tp[tp_idx] = (0x10000u32.wrapping_sub(src[(fp + 2) as usize])) & 0xffff;
            tp_idx += 1;
            tp[tp_idx] = (0x10000u32.wrapping_sub(src[(fp + 1) as usize])) & 0xffff;
            tp_idx += 1;
            tp[tp_idx] = inverse(src[(fp + 3) as usize]);
            tp_idx += 1;
            if r == 8 {
                break;
            }
            fp -= 6;
            tp[tp_idx] = src[(fp + 4) as usize];
            tp_idx += 1;
            tp[tp_idx] = src[(fp + 5) as usize];
            tp_idx += 1;
        }

        tp.swap(1, 2);
        tp.swap(49, 50);
    }
}

/// The round's working pair, so `E_IDEA`'s in-place swap reads the same as the authority's.
struct IdeaState {
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
}

/// `E_IDEA(num)` — `crypto/idea/idea_local.h:102-122`.
#[inline]
fn e_idea(s: &mut IdeaState, p: &mut usize, k: &[u32; 54]) {
    s.x1 &= 0xffff;
    s.x1 = idea_mul(s.x1, k[*p] as u64);
    *p += 1;
    s.x2 = s.x2.wrapping_add(k[*p] as u64);
    *p += 1;
    s.x3 = s.x3.wrapping_add(k[*p] as u64);
    *p += 1;
    s.x4 &= 0xffff;
    s.x4 = idea_mul(s.x4, k[*p] as u64);
    *p += 1;
    let mut t0 = (s.x1 ^ s.x3) & 0xffff;
    t0 = idea_mul(t0, k[*p] as u64);
    *p += 1;
    let mut t1 = (t0.wrapping_add(s.x2 ^ s.x4)) & 0xffff;
    t1 = idea_mul(t1, k[*p] as u64);
    *p += 1;
    t0 = t0.wrapping_add(t1);
    s.x1 ^= t1;
    s.x4 ^= t0;
    let ul = s.x2 ^ t0;
    s.x2 = s.x3 ^ t1;
    s.x3 = ul;
}

/// `void IDEA_encrypt(unsigned long *d, IDEA_KEY_SCHEDULE *key)` —
/// `crypto/idea/i_cbc.c:96-129`.
///
/// # Safety
/// `d` holds two `unsigned long`s; `key` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn IDEA_encrypt(d: *mut c_ulong, key: *mut IdeaKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let x2 = *d;
        let mut s = IdeaState {
            x1: x2 >> 16,
            x2,
            x4: *d.add(1),
            x3: *d.add(1) >> 16,
        };
        let k = (*key).words();
        let mut p = 0usize;
        for _ in 0..8 {
            e_idea(&mut s, &mut p, k);
        }
        s.x1 &= 0xffff;
        s.x1 = idea_mul(s.x1, k[p] as u64);
        p += 1;
        let t0 = s.x3.wrapping_add(k[p] as u64);
        p += 1;
        let t1 = s.x2.wrapping_add(k[p] as u64);
        p += 1;
        s.x4 &= 0xffff;
        s.x4 = idea_mul(s.x4, k[p] as u64);

        *d = (t0 & 0xffff) | ((s.x1 & 0xffff) << 16);
        *d.add(1) = (s.x4 & 0xffff) | ((t1 & 0xffff) << 16);
    }
}

/// `void IDEA_ecb_encrypt(const unsigned char *in, unsigned char *out,
/// IDEA_KEY_SCHEDULE *ks)` — `crypto/idea/i_ecb.c:26-41`.
///
/// # Safety
/// `in`/`out` eight bytes; `ks` a live encryption schedule.
#[no_mangle]
pub unsafe extern "C" fn IDEA_ecb_encrypt(
    input: *const u8,
    output: *mut u8,
    ks: *mut IdeaKeySchedule,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut d = [n2l(input), 0 as c_ulong];
        d[1] = n2l(input.add(4));
        IDEA_encrypt(d.as_mut_ptr(), ks);
        l2n(d[0], output);
        l2n(d[1], output.add(4));
    }
}

/// `void IDEA_cbc_encrypt(...)` — `crypto/idea/i_cbc.c:20-94`.
///
/// # Safety
/// `in`/`out` `length` bytes; `ks` live; `iv` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn IDEA_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    ks: *mut IdeaKeySchedule,
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
            let mut tout0 = n2l(iv);
            let mut tout1 = n2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = n2l(li) ^ tout0;
                let tin1 = n2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                IDEA_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                l2n(tout0, lo);
                tout1 = tin[1];
                l2n(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
            if l != -8 {
                let (p0, p1) = n2ln(li, (l + 8) as u32);
                tin[0] = p0 ^ tout0;
                tin[1] = p1 ^ tout1;
                IDEA_encrypt(tin.as_mut_ptr(), ks);
                tout0 = tin[0];
                l2n(tout0, lo);
                tout1 = tin[1];
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
                IDEA_encrypt(tin.as_mut_ptr(), ks);
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
                IDEA_encrypt(tin.as_mut_ptr(), ks);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2nn(tout0, tout1, lo, (l + 8) as u32);
                xor0 = tin0;
                xor1 = tin1;
            }
            l2n(xor0, iv);
            l2n(xor1, iv.add(4));
        }
    }
}

/// `void IDEA_cfb64_encrypt(...)` — `crypto/idea/i_cfb64.c:26-87`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn IDEA_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut IdeaKeySchedule,
    ivec: *mut u8,
    num: *mut c_int,
    encrypt: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = *num;
        if n < 0 {
            *num = -1;
            return;
        }
        n &= 0x07;
        let mut l = length;
        let mut ti = [0 as c_ulong; 2];
        let mut c: u8;
        if encrypt != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = n2l(ivec);
                    ti[1] = n2l(ivec.add(4));
                    IDEA_encrypt(ti.as_mut_ptr(), schedule);
                    l2n(ti[0], ivec);
                    l2n(ti[1], ivec.add(4));
                }
                c = *input ^ *ivec.add(n as usize);
                *output = c;
                *ivec.add(n as usize) = c;
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
                    IDEA_encrypt(ti.as_mut_ptr(), schedule);
                    l2n(ti[0], ivec);
                    l2n(ti[1], ivec.add(4));
                }
                cc = *input;
                c = *ivec.add(n as usize);
                *ivec.add(n as usize) = cc;
                *output = c ^ cc;
                input = input.add(1);
                output = output.add(1);
                n = (n + 1) & 0x07;
                l -= 1;
            }
        }
        *num = n;
    }
}

/// `void IDEA_ofb64_encrypt(...)` — `crypto/idea/i_ofb64.c:25-74`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn IDEA_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut IdeaKeySchedule,
    ivec: *mut u8,
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = *num;
        if n < 0 {
            *num = -1;
            return;
        }
        n &= 0x07;
        let mut l = length;
        let mut ti = [n2l(ivec), n2l(ivec.add(4))];
        let mut d = [0u8; 8];
        l2n(ti[0], d.as_mut_ptr());
        l2n(ti[1], d.as_mut_ptr().add(4));
        let mut save = 0;
        while l > 0 {
            if n == 0 {
                IDEA_encrypt(ti.as_mut_ptr(), schedule);
                l2n(ti[0], d.as_mut_ptr());
                l2n(ti[1], d.as_mut_ptr().add(4));
                save += 1;
            }
            *output = *input ^ d[n as usize];
            input = input.add(1);
            output = output.add(1);
            n = (n + 1) & 0x07;
            l -= 1;
        }
        if save > 0 {
            l2n(ti[0], ivec);
            l2n(ti[1], ivec.add(4));
        }
        *num = n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_schedule(key: &[u8; 16]) -> IdeaKeySchedule {
        let mut ks = IdeaKeySchedule { data: [[0; 6]; 9] };
        // SAFETY: live local, sixteen-byte key.
        unsafe { IDEA_set_encrypt_key(key.as_ptr(), &mut ks) };
        ks
    }

    #[test]
    fn the_recipe_ecb_vector_matches() {
        // The classic IDEA vector: key `00010002000300040005000600070008`, plaintext
        // `0000000100020003`, ciphertext `11fbed2b01986de5`.
        let key: [u8; 16] = [
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
            0x00, 0x08,
        ];
        let mut ks = enc_schedule(&key);
        let block: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        let mut out = [0u8; 8];
        // SAFETY: live locals.
        unsafe {
            IDEA_ecb_encrypt(
                block.as_ptr(),
                out.as_mut_ptr(),
                &mut ks as *mut IdeaKeySchedule,
            )
        };
        assert_eq!(out, [0x11, 0xfb, 0xed, 0x2b, 0x01, 0x98, 0x6d, 0xe5]);
    }
}
