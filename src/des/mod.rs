//! Phase 8.2 — `crypto/des/`: DES, the modes built on it, and the two key helpers.
//!
//! The authority's build does **not** select a perlasm arm for DES on this profile:
//! `crypto/des/build.info` only substitutes `$DESASM_x86` (`des-586.S`) for the 32-bit
//! x86 asm_arch, and this profile's asm_arch is `x86_64`, so `$DESASM` stays
//! `des_enc.c fcrypt_b.c` — the portable C arm. What `RT-CIPHER` proves is therefore that
//! this transcription is *this* implementation's observable function, not merely some
//! correct DES; the tables are read from [`crate::cipher_tables`], which
//! `gen_phase8_cipher_tables.py` derives from `spr.h`, `set_key.c` and `fcrypt.c`.
//!
//! ## `DES_cblock` is an array typedef, and its const is in a comment
//!
//! `include/openssl/des.h:35-36` declares `typedef unsigned char DES_cblock[8];` and
//! `typedef /* const */ unsigned char const_DES_cblock[8];` — the `const` is **inside a
//! comment**, so `const_DES_cblock *` is a non-const `unsigned char (*)[8]`. The exported
//! parameters are therefore `*mut [u8; 8]` here, which is the authority's actual type and
//! the one `prototype_court.py`'s type plane canonicalises against (D215 fixed that plane,
//! which could not read an array typedef at all and reported correct declarations as
//! `type_unmapped`).
//!
//! ## `DES_set_key`'s precedence is reproduced
//!
//! `crypto/des/set_key.c:682-692`: `DES_set_key` returns `-2` for a weak key even when the
//! parity was also wrong, because the weak-key test overwrites the `-1`. That precedence is
//! the authority's observable contract and is reproduced rather than "fixed".
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint};

use crate::cipher_tables::{
    DES_CON_SALT, DES_COV_2CHAR, DES_ODD_PARITY, DES_SHIFTS2, DES_SKB, DES_SPTRANS, DES_WEAK_KEYS,
};
use crate::rand::rand_lib::RAND_priv_bytes;

/// `DES_ENCRYPT` — `include/openssl/des.h:55`.
pub const DES_ENCRYPT: c_int = 1;
/// `DES_DECRYPT` — `include/openssl/des.h:56`.
pub const DES_DECRYPT: c_int = 0;
/// `DES_KEY_SZ` — `include/openssl/des.h:52`.
pub const DES_KEY_SZ: usize = 8;

/// One `DES_ks` entry — `include/openssl/des.h:42-50`: the union of an eight-byte
/// `DES_cblock` and two `DES_LONG`s (`unsigned int` here).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DesKs {
    /// `DES_LONG deslong[2]`.
    pub deslong: [c_uint; 2],
}

/// `DES_key_schedule` — `include/openssl/des.h:42-50`: sixteen `DES_ks`, one per round.
#[repr(C)]
pub struct DesKeySchedule {
    /// `struct DES_ks ks[16]`.
    pub ks: [DesKs; 16],
}

const _: () = {
    assert!(core::mem::size_of::<DesKeySchedule>() == 128);
};

/// `PERM_OP(a, b, t, n, m)` — `crypto/des/des_local.h:216-218`.
#[inline]
fn perm_op(a: &mut c_uint, b: &mut c_uint, n: u32, m: c_uint) {
    let t = ((*a >> n) ^ *b) & m;
    *b ^= t;
    *a ^= t << n;
}

/// `IP(l, r)` — `crypto/des/des_local.h:220-228`.
#[inline]
fn ip(mut l: c_uint, mut r: c_uint) -> (c_uint, c_uint) {
    perm_op(&mut r, &mut l, 4, 0x0f0f_0f0f);
    perm_op(&mut l, &mut r, 16, 0x0000_ffff);
    perm_op(&mut r, &mut l, 2, 0x3333_3333);
    perm_op(&mut l, &mut r, 8, 0x00ff_00ff);
    perm_op(&mut r, &mut l, 1, 0x5555_5555);
    (l, r)
}

/// `FP(l, r)` — `crypto/des/des_local.h:230-238`.
#[inline]
fn fp(mut l: c_uint, mut r: c_uint) -> (c_uint, c_uint) {
    perm_op(&mut l, &mut r, 1, 0x5555_5555);
    perm_op(&mut r, &mut l, 8, 0x00ff_00ff);
    perm_op(&mut l, &mut r, 2, 0x3333_3333);
    perm_op(&mut r, &mut l, 16, 0x0000_ffff);
    perm_op(&mut l, &mut r, 4, 0x0f0f_0f0f);
    (l, r)
}

/// `D_ENCRYPT(LL, R, S)` — `crypto/des/des_local.h:171-176`, the non-`DES_FCRYPT` arm.
#[inline]
fn d_encrypt(ll: &mut c_uint, r: c_uint, s: *const c_uint, idx: usize) {
    // SAFETY: `s` points at the schedule's thirty-two words and `idx + 1 < 32`.
    let (u, t) = unsafe { (r ^ *s.add(idx), r ^ *s.add(idx + 1)) };
    let t = t.rotate_right(4);
    *ll ^= DES_SPTRANS[0][((u >> 2) & 0x3f) as usize]
        ^ DES_SPTRANS[2][((u >> 10) & 0x3f) as usize]
        ^ DES_SPTRANS[4][((u >> 18) & 0x3f) as usize]
        ^ DES_SPTRANS[6][((u >> 26) & 0x3f) as usize]
        ^ DES_SPTRANS[1][((t >> 2) & 0x3f) as usize]
        ^ DES_SPTRANS[3][((t >> 10) & 0x3f) as usize]
        ^ DES_SPTRANS[5][((t >> 18) & 0x3f) as usize]
        ^ DES_SPTRANS[7][((t >> 26) & 0x3f) as usize];
}

/// `D_ENCRYPT` under `DES_FCRYPT` — `des_local.h:142-157`, which folds the `Eswap` masks into
/// the expansion rather than reading them from the schedule.
#[inline]
fn d_encrypt_fc(ll: &mut c_uint, r: c_uint, s: *const c_uint, idx: usize, e0: c_uint, e1: c_uint) {
    let t0 = r ^ (r >> 16);
    let mut u = t0 & e0;
    let mut t = t0 & e1;
    let tmp_u = u << 16;
    let tmp_t = t << 16;
    // SAFETY: `s` points at the schedule's thirty-two words and `idx + 1 < 32`.
    unsafe {
        u ^= r ^ *s.add(idx);
        u ^= tmp_u;
        t ^= r ^ *s.add(idx + 1);
        t ^= tmp_t;
    }
    let t = t.rotate_right(4);
    *ll ^= DES_SPTRANS[0][((u >> 2) & 0x3f) as usize]
        ^ DES_SPTRANS[2][((u >> 10) & 0x3f) as usize]
        ^ DES_SPTRANS[4][((u >> 18) & 0x3f) as usize]
        ^ DES_SPTRANS[6][((u >> 26) & 0x3f) as usize]
        ^ DES_SPTRANS[1][((t >> 2) & 0x3f) as usize]
        ^ DES_SPTRANS[3][((t >> 10) & 0x3f) as usize]
        ^ DES_SPTRANS[5][((t >> 18) & 0x3f) as usize]
        ^ DES_SPTRANS[7][((t >> 26) & 0x3f) as usize];
}

/// `c2l(c, l)` — `des_local.h:29-32`, little-endian.
///
/// # Safety
/// `p` readable for four bytes.
#[inline]
unsafe fn c2l(p: *const u8) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        (*p as c_uint)
            | ((*p.add(1) as c_uint) << 8)
            | ((*p.add(2) as c_uint) << 16)
            | ((*p.add(3) as c_uint) << 24)
    }
}

/// `l2c(l, c)` — `des_local.h:66-69`.
///
/// # Safety
/// `p` writable for four bytes.
#[inline]
unsafe fn l2c(v: c_uint, p: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        *p = (v & 0xff) as u8;
        *p.add(1) = ((v >> 8) & 0xff) as u8;
        *p.add(2) = ((v >> 16) & 0xff) as u8;
        *p.add(3) = ((v >> 24) & 0xff) as u8;
    }
}

/// `c2ln(c, l1, l2, n)` — `des_local.h:35-64`, the non-advancing partial reader.
///
/// # Safety
/// `p` readable for `n` bytes, `1 <= n <= 8`.
unsafe fn c2ln(p: *const u8, n: c_uint) -> (c_uint, c_uint) {
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

/// `l2cn(l1, l2, c, n)` — `des_local.h:72-100`.
///
/// # Safety
/// `p` writable for `n` bytes, `1 <= n <= 8`.
unsafe fn l2cn(l1: c_uint, l2: c_uint, p: *mut u8, n: c_uint) {
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

/// `const char *DES_options(void)` — `crypto/des/ecb_enc.c:20-33`. `sizeof(DES_LONG)` is four
/// and `sizeof(long)` is eight on this profile, so the answer is `des(int)`.
///
/// # Safety
/// None; the pointer is a `'static` C string.
#[no_mangle]
pub unsafe extern "C" fn DES_options() -> *const c_char {
    c"des(int)".as_ptr()
}

/// `int DES_random_key(DES_cblock *ret)` — `crypto/des/rand_key.c:19-27`.
///
/// The one `des.h` export whose body is the random layer rather than the cipher, and the
/// only one `crypto/des/` holds whose callee is not this stratum's: it draws eight bytes
/// with `RAND_priv_bytes` and **rejects a weak key**, looping until the draw is not one of
/// the sixteen weak or semi-weak keys, then fixes the parity. A failed draw is a `0` answer
/// with `ret` holding whatever the call left; the loop's `while` is the authority's own
/// refusal path and is why a caller never sees a weak key here.
///
/// # Safety
/// `ret` writable for eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_random_key(ret: *mut [u8; 8]) -> c_int {
    // SAFETY: the caller's contract; `ret` is eight writable bytes.
    unsafe {
        loop {
            if RAND_priv_bytes(ret.cast::<c_uchar>(), 8) != 1 {
                return 0;
            }
            if DES_is_weak_key(ret) == 0 {
                break;
            }
        }
        DES_set_odd_parity(ret);
        1
    }
}

/// `void DES_set_odd_parity(DES_cblock *key)` — `crypto/des/set_key.c:59-65`.
///
/// # Safety
/// `key` writable for eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_set_odd_parity(key: *mut [u8; 8]) {
    // SAFETY: the caller's contract.
    unsafe {
        for i in 0..DES_KEY_SZ {
            (*key)[i] = DES_ODD_PARITY[(*key)[i] as usize];
        }
    }
}

/// `int DES_check_key_parity(const_DES_cblock *key)` — `crypto/des/set_key.c:71-84`. Answers
/// 1 when every byte has odd parity, 0 otherwise.
///
/// # Safety
/// `key` readable for eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_check_key_parity(key: *mut [u8; 8]) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut res: u8 = 0xff;
        for i in 0..DES_KEY_SZ {
            let mut b = (*key)[i];
            b ^= b >> 4;
            b ^= b >> 2;
            b ^= b >> 1;
            res &= (b & 1 == 1) as u8;
        }
        (res & 1) as c_int
    }
}

/// `int DES_is_weak_key(const_DES_cblock *key)` — `crypto/des/set_key.c:119-129`.
///
/// # Safety
/// `key` readable for eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_is_weak_key(key: *mut [u8; 8]) -> c_int {
    // SAFETY: the caller's contract; the table is sixteen eight-byte keys.
    let k = unsafe { &*key };
    let mut res = 0u8;
    for w in DES_WEAK_KEYS.iter() {
        let mut diff = 0u8;
        for i in 0..8 {
            diff |= k[i] ^ w[i];
        }
        res |= (diff == 0) as u8;
    }
    (res & 1) as c_int
}

/// `void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule)` —
/// `crypto/des/set_key.c:709-766`.
///
/// # Safety
/// `key` readable for eight bytes; `schedule` writable for 128.
#[no_mangle]
pub unsafe extern "C" fn DES_set_key_unchecked(key: *mut [u8; 8], schedule: *mut DesKeySchedule) {
    // SAFETY: the caller's contract.
    unsafe {
        let input = (*key).as_ptr();
        let (mut c, mut d) = (c2l(input), c2l(input.add(4)));
        let mut t: c_uint;

        perm_op(&mut d, &mut c, 4, 0x0f0f_0f0f);
        // HPERM_OP(c, t, -2, 0xcccc0000) and HPERM_OP(d, t, -2, 0xcccc0000).
        t = ((c << 18) ^ c) & 0xcccc_0000;
        c = c ^ t ^ (t >> 18);
        t = ((d << 18) ^ d) & 0xcccc_0000;
        d = d ^ t ^ (t >> 18);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);
        perm_op(&mut c, &mut d, 8, 0x00ff_00ff);
        perm_op(&mut d, &mut c, 1, 0x5555_5555);
        d = ((d & 0x0000_00ff) << 16)
            | (d & 0x0000_ff00)
            | ((d & 0x00ff_0000) >> 16)
            | ((c & 0xf000_0000) >> 4);
        c &= 0x0fff_ffff;

        let k = (*schedule).ks.as_mut_ptr() as *mut c_uint;
        for (i, &shift) in DES_SHIFTS2.iter().enumerate() {
            if shift != 0 {
                c = (c >> 2) | (c << 26);
                d = (d >> 2) | (d << 26);
            } else {
                c = (c >> 1) | (c << 27);
                d = (d >> 1) | (d << 27);
            }
            c &= 0x0fff_ffff;
            d &= 0x0fff_ffff;
            let s = DES_SKB[0][(c & 0x3f) as usize]
                | DES_SKB[1][(((c >> 6) & 0x03) | ((c >> 7) & 0x3c)) as usize]
                | DES_SKB[2][(((c >> 13) & 0x0f) | ((c >> 14) & 0x30)) as usize]
                | DES_SKB[3]
                    [(((c >> 20) & 0x01) | ((c >> 21) & 0x06) | ((c >> 22) & 0x38)) as usize];
            let t2 = DES_SKB[4][(d & 0x3f) as usize]
                | DES_SKB[5][(((d >> 7) & 0x03) | ((d >> 8) & 0x3c)) as usize]
                | DES_SKB[6][((d >> 15) & 0x3f) as usize]
                | DES_SKB[7][(((d >> 21) & 0x0f) | ((d >> 22) & 0x30)) as usize];

            // table contained 0213 4657
            let w0 = ((t2 << 16) | (s & 0x0000_ffff)).rotate_right(30);
            let w1 = ((s >> 16) | (t2 & 0xffff_0000)).rotate_right(26);
            *k.add(2 * i) = w0;
            *k.add(2 * i + 1) = w1;
        }
    }
}

/// `int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule)` —
/// `crypto/des/set_key.c:699-707`.
///
/// # Safety
/// As [`DES_set_key_unchecked`].
#[no_mangle]
pub unsafe extern "C" fn DES_set_key_checked(
    key: *mut [u8; 8],
    schedule: *mut DesKeySchedule,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if DES_check_key_parity(key) == 0 {
            return -1;
        }
        if DES_is_weak_key(key) != 0 {
            return -2;
        }
        DES_set_key_unchecked(key, schedule);
    }
    0
}

/// `int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule)` —
/// `crypto/des/set_key.c:682-692`. Sets the schedule even when it returns non-zero, and the
/// weak-key verdict overwrites a parity failure, which is the authority's precedence.
///
/// # Safety
/// As [`DES_set_key_unchecked`].
#[no_mangle]
pub unsafe extern "C" fn DES_set_key(key: *mut [u8; 8], schedule: *mut DesKeySchedule) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ret = 0;
        if DES_check_key_parity(key) == 0 {
            ret = -1;
        }
        if DES_is_weak_key(key) != 0 {
            ret = -2;
        }
        DES_set_key_unchecked(key, schedule);
        ret
    }
}

/// `int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule)` —
/// `crypto/des/set_key.c:768-771`.
///
/// # Safety
/// As [`DES_set_key_unchecked`].
#[no_mangle]
pub unsafe extern "C" fn DES_key_sched(key: *mut [u8; 8], schedule: *mut DesKeySchedule) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { DES_set_key(key, schedule) }
}

/// `void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc)` —
/// `crypto/des/des_enc.c:20-89`.
///
/// # Safety
/// `data` holds two words; `ks` a live schedule.
#[no_mangle]
pub unsafe extern "C" fn DES_encrypt1(data: *mut c_uint, ks: *mut DesKeySchedule, enc: c_int) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut r = *data;
        let mut l = *data.add(1);
        let (nr, nl) = ip(r, l);
        r = nr;
        l = nl;
        r = r.rotate_right(29);
        l = l.rotate_right(29);
        let s = (*ks).ks.as_mut_ptr() as *const c_uint;

        if enc != 0 {
            for i in 0..16usize {
                if i % 2 == 0 {
                    d_encrypt(&mut l, r, s, 2 * i);
                } else {
                    d_encrypt(&mut r, l, s, 2 * i);
                }
            }
        } else {
            for i in 0..16usize {
                if i % 2 == 0 {
                    d_encrypt(&mut l, r, s, 30 - 2 * i);
                } else {
                    d_encrypt(&mut r, l, s, 30 - 2 * i);
                }
            }
        }
        l = l.rotate_right(3);
        r = r.rotate_right(3);
        let (nr, nl) = fp(r, l);
        r = nr;
        l = nl;
        *data = l;
        *data.add(1) = r;
    }
}

/// `void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc)` —
/// `crypto/des/des_enc.c:91-153`, the IP/FP-less core 3DES uses.
///
/// # Safety
/// As [`DES_encrypt1`].
#[no_mangle]
pub unsafe extern "C" fn DES_encrypt2(data: *mut c_uint, ks: *mut DesKeySchedule, enc: c_int) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut r = *data;
        let mut l = *data.add(1);
        r = r.rotate_right(29);
        l = l.rotate_right(29);
        let s = (*ks).ks.as_mut_ptr() as *const c_uint;

        if enc != 0 {
            for i in 0..16usize {
                if i % 2 == 0 {
                    d_encrypt(&mut l, r, s, 2 * i);
                } else {
                    d_encrypt(&mut r, l, s, 2 * i);
                }
            }
        } else {
            for i in 0..16usize {
                if i % 2 == 0 {
                    d_encrypt(&mut l, r, s, 30 - 2 * i);
                } else {
                    d_encrypt(&mut r, l, s, 30 - 2 * i);
                }
            }
        }
        *data = l.rotate_right(3);
        *data.add(1) = r.rotate_right(3);
    }
}

/// `void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
/// DES_key_schedule *ks3)` — `crypto/des/des_enc.c:155-173`.
///
/// # Safety
/// As [`DES_encrypt1`]; all three schedules live.
#[no_mangle]
pub unsafe extern "C" fn DES_encrypt3(
    data: *mut c_uint,
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut l = *data;
        let mut r = *data.add(1);
        let (nl, nr) = ip(l, r);
        l = nl;
        r = nr;
        *data = l;
        *data.add(1) = r;
        DES_encrypt2(data, ks1, DES_ENCRYPT);
        DES_encrypt2(data, ks2, DES_DECRYPT);
        DES_encrypt2(data, ks3, DES_ENCRYPT);
        l = *data;
        r = *data.add(1);
        let (nr, nl) = fp(r, l);
        r = nr;
        l = nl;
        *data = l;
        *data.add(1) = r;
    }
}

/// `void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2,
/// DES_key_schedule *ks3)` — `crypto/des/des_enc.c:175-193`.
///
/// # Safety
/// As [`DES_encrypt3`].
#[no_mangle]
pub unsafe extern "C" fn DES_decrypt3(
    data: *mut c_uint,
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut l = *data;
        let mut r = *data.add(1);
        let (nl, nr) = ip(l, r);
        l = nl;
        r = nr;
        *data = l;
        *data.add(1) = r;
        DES_encrypt2(data, ks3, DES_DECRYPT);
        DES_encrypt2(data, ks2, DES_ENCRYPT);
        DES_encrypt2(data, ks1, DES_DECRYPT);
        l = *data;
        r = *data.add(1);
        let (nr, nl) = fp(r, l);
        r = nr;
        l = nl;
        *data = l;
        *data.add(1) = r;
    }
}

/// `void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output,
/// DES_key_schedule *ks, int enc)` — `crypto/des/ecb_enc.c:35-53`.
///
/// # Safety
/// `input`/`output` eight bytes; `ks` live.
#[no_mangle]
pub unsafe extern "C" fn DES_ecb_encrypt(
    input: *mut [u8; 8],
    output: *mut [u8; 8],
    ks: *mut DesKeySchedule,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ll = [c2l((*input).as_ptr()), 0];
        ll[1] = c2l((*input).as_ptr().add(4));
        DES_encrypt1(ll.as_mut_ptr(), ks, enc);
        let out = (*output).as_mut_ptr();
        l2c(ll[0], out);
        l2c(ll[1], out.add(4));
    }
}

/// `void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1,
/// DES_key_schedule *ks2, DES_key_schedule *ks3, int enc)` — `crypto/des/ecb3_enc.c:18-39`.
///
/// # Safety
/// As [`DES_ecb_encrypt`], with three live schedules.
#[no_mangle]
pub unsafe extern "C" fn DES_ecb3_encrypt(
    input: *mut [u8; 8],
    output: *mut [u8; 8],
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut ll = [c2l((*input).as_ptr()), 0];
        ll[1] = c2l((*input).as_ptr().add(4));
        if enc != 0 {
            DES_encrypt3(ll.as_mut_ptr(), ks1, ks2, ks3);
        } else {
            DES_decrypt3(ll.as_mut_ptr(), ks1, ks2, ks3);
        }
        let out = (*output).as_mut_ptr();
        l2c(ll[0], out);
        l2c(ll[1], out.add(4));
    }
}

/// `DES_ncbc_encrypt` / `DES_cbc_encrypt` — `crypto/des/ncbc_enc.c`, the two spellings
/// differing only in `CBC_ENC_C__DONT_UPDATE_IV`.
///
/// # Safety
/// `input`/`output` `length` bytes; `schedule` live; `ivec` eight bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn ncbc(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
    update_iv: bool,
) {
    // SAFETY: the caller's contract, plus the schedule and IV being live.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if enc != 0 {
            let mut tout0 = c2l(iv);
            let mut tout1 = c2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = c2l(li) ^ tout0;
                let tin1 = c2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
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
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
                tout0 = tin[0];
                l2c(tout0, lo);
                tout1 = tin[1];
                l2c(tout1, lo.add(4));
            }
            if update_iv {
                l2c(tout0, iv);
                l2c(tout1, iv.add(4));
            }
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
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_DECRYPT);
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
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_DECRYPT);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2cn(tout0, tout1, lo, (l + 8) as c_uint);
                if update_iv {
                    xor0 = tin0;
                    xor1 = tin1;
                }
            }
            if update_iv {
                l2c(xor0, iv);
                l2c(xor1, iv.add(4));
            }
        }
    }
}

/// `void DES_cbc_encrypt(const unsigned char *input, unsigned char *output, long length,
/// DES_key_schedule *schedule, DES_cblock *ivec, int enc)` — `crypto/des/cbc_enc.c`, which is
/// `ncbc_enc.c` under `CBC_ENC_C__DONT_UPDATE_IV`: **the IV is not written back**.
///
/// # Safety
/// `input`/`output` `length` bytes; `schedule` live; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe { ncbc(input, output, length, schedule, ivec, enc, false) }
}

/// `void DES_ncbc_encrypt(...)` — `crypto/des/des_enc.c`, `ncbc_enc.c` with the IV written
/// back.
///
/// # Safety
/// As [`DES_cbc_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn DES_ncbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe { ncbc(input, output, length, schedule, ivec, enc, true) }
}

/// `void DES_ede3_cbc_encrypt(...)` — `crypto/des/des_enc.c:202-305`.
///
/// # Safety
/// `input`/`output` `length` bytes; three live schedules; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_ede3_cbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if enc != 0 {
            let mut tout0 = c2l(iv);
            let mut tout1 = c2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = c2l(li) ^ tout0;
                let tin1 = c2l(li.add(4)) ^ tout1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                DES_encrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
                tout0 = tin[0];
                tout1 = tin[1];
                l2c(tout0, lo);
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
            if l != -8 {
                let (p0, p1) = c2ln(li, (l + 8) as c_uint);
                tin[0] = p0 ^ tout0;
                tin[1] = p1 ^ tout1;
                DES_encrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
                tout0 = tin[0];
                tout1 = tin[1];
                l2c(tout0, lo);
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
                let t0 = tin0;
                let t1 = tin1;
                tin[0] = tin0;
                tin[1] = tin1;
                DES_decrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2c(tout0, lo);
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                xor0 = t0;
                xor1 = t1;
                l -= 8;
            }
            if l != -8 {
                let tin0 = c2l(li);
                let tin1 = c2l(li.add(4));
                let t0 = tin0;
                let t1 = tin1;
                tin[0] = tin0;
                tin[1] = tin1;
                DES_decrypt3(tin.as_mut_ptr(), ks1, ks2, ks3);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                l2cn(tout0, tout1, lo, (l + 8) as c_uint);
                xor0 = t0;
                xor1 = t1;
            }
            l2c(xor0, iv);
            l2c(xor1, iv.add(4));
        }
    }
}

/// `void DES_pcbc_encrypt(...)` — `crypto/des/pcbc_enc.c:18-72`.
///
/// # Safety
/// `input`/`output` `length` bytes; `schedule` live; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_pcbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if enc != 0 {
            let mut xor0 = c2l(iv);
            let mut xor1 = c2l(iv.add(4));
            while l > 0 {
                let (sin0, sin1) = if l >= 8 {
                    (c2l(li), c2l(li.add(4)))
                } else {
                    c2ln(li, l as c_uint)
                };
                li = li.add(if l >= 8 { 8 } else { l as usize });
                tin[0] = sin0 ^ xor0;
                tin[1] = sin1 ^ xor1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
                let tout0 = tin[0];
                let tout1 = tin[1];
                xor0 = sin0 ^ tout0;
                xor1 = sin1 ^ tout1;
                l2c(tout0, lo);
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
        } else {
            let mut xor0 = c2l(iv);
            let mut xor1 = c2l(iv.add(4));
            while l > 0 {
                let sin0 = c2l(li);
                let sin1 = c2l(li.add(4));
                li = li.add(8);
                tin[0] = sin0;
                tin[1] = sin1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_DECRYPT);
                let tout0 = tin[0] ^ xor0;
                let tout1 = tin[1] ^ xor1;
                if l >= 8 {
                    l2c(tout0, lo);
                    l2c(tout1, lo.add(4));
                } else {
                    l2cn(tout0, tout1, lo, l as c_uint);
                }
                lo = lo.add(8);
                xor0 = tout0 ^ sin0;
                xor1 = tout1 ^ sin1;
                l -= 8;
            }
        }
    }
}

/// `void DES_xcbc_encrypt(...)` — `crypto/des/xcbc_enc.c:20-109`.
///
/// # Safety
/// `input`/`output` `length` bytes; `schedule` live; the three eight-byte blocks readable.
#[no_mangle]
pub unsafe extern "C" fn DES_xcbc_encrypt(
    input: *const u8,
    output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    inw: *mut [u8; 8],
    outw: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let in_w0 = c2l((*inw).as_ptr());
        let in_w1 = c2l((*inw).as_ptr().add(4));
        let out_w0 = c2l((*outw).as_ptr());
        let out_w1 = c2l((*outw).as_ptr().add(4));
        let iv = (*ivec).as_mut_ptr();
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        if enc != 0 {
            let mut tout0 = c2l(iv);
            let mut tout1 = c2l(iv.add(4));
            l -= 8;
            while l >= 0 {
                let tin0 = c2l(li) ^ tout0 ^ in_w0;
                let tin1 = c2l(li.add(4)) ^ tout1 ^ in_w1;
                li = li.add(8);
                tin[0] = tin0;
                tin[1] = tin1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
                tout0 = tin[0] ^ out_w0;
                l2c(tout0, lo);
                tout1 = tin[1] ^ out_w1;
                l2c(tout1, lo.add(4));
                lo = lo.add(8);
                l -= 8;
            }
            if l != -8 {
                let (p0, p1) = c2ln(li, (l + 8) as c_uint);
                tin[0] = p0 ^ tout0 ^ in_w0;
                tin[1] = p1 ^ tout1 ^ in_w1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
                tout0 = tin[0] ^ out_w0;
                l2c(tout0, lo);
                tout1 = tin[1] ^ out_w1;
                l2c(tout1, lo.add(4));
            }
            l2c(tout0, iv);
            l2c(tout1, iv.add(4));
        } else {
            let mut xor0 = c2l(iv);
            let mut xor1 = c2l(iv.add(4));
            l -= 8;
            while l > 0 {
                let tin0 = c2l(li);
                let tin1 = c2l(li.add(4));
                li = li.add(8);
                tin[0] = tin0 ^ out_w0;
                tin[1] = tin1 ^ out_w1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_DECRYPT);
                let tout0 = tin[0] ^ xor0 ^ in_w0;
                let tout1 = tin[1] ^ xor1 ^ in_w1;
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
                tin[0] = tin0 ^ out_w0;
                tin[1] = tin1 ^ out_w1;
                DES_encrypt1(tin.as_mut_ptr(), schedule, DES_DECRYPT);
                let tout0 = tin[0] ^ xor0 ^ in_w0;
                let tout1 = tin[1] ^ xor1 ^ in_w1;
                l2cn(tout0, tout1, lo, (l + 8) as c_uint);
                xor0 = tin0;
                xor1 = tin1;
            }
            l2c(xor0, iv);
            l2c(xor1, iv.add(4));
        }
    }
}

/// `void DES_cfb64_encrypt(...)` — `crypto/des/cfb64enc.c:24-79`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn DES_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [0 as c_uint; 2];
        let mut c: u8;
        if enc != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = c2l(iv);
                    ti[1] = c2l(iv.add(4));
                    DES_encrypt1(ti.as_mut_ptr(), schedule, DES_ENCRYPT);
                    l2c(ti[0], iv);
                    l2c(ti[1], iv.add(4));
                }
                c = *input ^ *iv.add(n);
                *output = c;
                *iv.add(n) = c;
                input = input.add(1);
                output = output.add(1);
                n = (n + 1) & 0x07;
                l -= 1;
            }
        } else {
            let mut cc: u8;
            while l > 0 {
                if n == 0 {
                    ti[0] = c2l(iv);
                    ti[1] = c2l(iv.add(4));
                    DES_encrypt1(ti.as_mut_ptr(), schedule, DES_ENCRYPT);
                    l2c(ti[0], iv);
                    l2c(ti[1], iv.add(4));
                }
                cc = *input;
                c = *iv.add(n);
                *iv.add(n) = cc;
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

/// `void DES_ede3_cfb64_encrypt(...)` — `crypto/des/cfb64ede.c:24-84`.
///
/// # Safety
/// As [`DES_cfb64_encrypt`], with three live schedules.
#[no_mangle]
pub unsafe extern "C" fn DES_ede3_cfb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    num: *mut c_int,
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [0 as c_uint; 2];
        let mut c: u8;
        if enc != 0 {
            while l > 0 {
                if n == 0 {
                    ti[0] = c2l(iv);
                    ti[1] = c2l(iv.add(4));
                    DES_encrypt3(ti.as_mut_ptr(), ks1, ks2, ks3);
                    l2c(ti[0], iv);
                    l2c(ti[1], iv.add(4));
                }
                c = *input ^ *iv.add(n);
                *output = c;
                *iv.add(n) = c;
                input = input.add(1);
                output = output.add(1);
                n = (n + 1) & 0x07;
                l -= 1;
            }
        } else {
            let mut cc: u8;
            while l > 0 {
                if n == 0 {
                    ti[0] = c2l(iv);
                    ti[1] = c2l(iv.add(4));
                    DES_encrypt3(ti.as_mut_ptr(), ks1, ks2, ks3);
                    l2c(ti[0], iv);
                    l2c(ti[1], iv.add(4));
                }
                cc = *input;
                c = *iv.add(n);
                *iv.add(n) = cc;
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

/// `void DES_ede3_cfb_encrypt(...)` — `crypto/des/cfb64ede.c:91-195`, the CFB-r variant "compatible
/// with the single key CFB-r for DES".
///
/// # Safety
/// `in`/`out` `length` bytes; three live schedules; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_ede3_cfb_encrypt(
    input: *const u8,
    output: *mut u8,
    numbits: c_int,
    length: c_long,
    ks1: *mut DesKeySchedule,
    ks2: *mut DesKeySchedule,
    ks3: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut l = length as u64;
        let num = numbits as u32;
        if num > 64 {
            return;
        }
        let n = num.div_ceil(8) as usize;
        let iv = (*ivec).as_mut_ptr();
        let mut v0 = c2l(iv);
        let mut v1 = c2l(iv.add(4));
        let mut li = input;
        let mut lo = output;
        let mut ovec = [0u8; 16];
        while l >= n as u64 {
            l -= n as u64;
            let mut ti = [v0, v1];
            DES_encrypt3(ti.as_mut_ptr(), ks1, ks2, ks3);
            let (mut d0, mut d1) = c2ln(li, n as c_uint);
            li = li.add(n);
            if enc != 0 {
                d0 ^= ti[0];
                d1 ^= ti[1];
                l2cn(d0, d1, lo, n as c_uint);
                lo = lo.add(n);
                if num == 32 {
                    v0 = v1;
                    v1 = d0;
                } else if num == 64 {
                    v0 = d0;
                    v1 = d1;
                } else {
                    l2c(v0, ovec.as_mut_ptr());
                    l2c(v1, ovec.as_mut_ptr().add(4));
                    l2c(d0, ovec.as_mut_ptr().add(8));
                    l2c(d1, ovec.as_mut_ptr().add(12));
                    let shift = (num / 8) as usize;
                    let len = 8 + usize::from(!num.is_multiple_of(8));
                    ovec.copy_within(shift..shift + len, 0);
                    if !num.is_multiple_of(8) {
                        for i in 0..8 {
                            ovec[i] = (ovec[i] << (num % 8)) | (ovec[i + 1] >> (8 - num % 8));
                        }
                    }
                    v0 = c2l(ovec.as_ptr());
                    v1 = c2l(ovec.as_ptr().add(4));
                }
            } else {
                if num == 32 {
                    v0 = v1;
                    v1 = d0;
                } else if num == 64 {
                    v0 = d0;
                    v1 = d1;
                } else {
                    l2c(v0, ovec.as_mut_ptr());
                    l2c(v1, ovec.as_mut_ptr().add(4));
                    l2c(d0, ovec.as_mut_ptr().add(8));
                    l2c(d1, ovec.as_mut_ptr().add(12));
                    let shift = (num / 8) as usize;
                    let len = 8 + usize::from(!num.is_multiple_of(8));
                    ovec.copy_within(shift..shift + len, 0);
                    if !num.is_multiple_of(8) {
                        for i in 0..8 {
                            ovec[i] = (ovec[i] << (num % 8)) | (ovec[i + 1] >> (8 - num % 8));
                        }
                    }
                    v0 = c2l(ovec.as_ptr());
                    v1 = c2l(ovec.as_ptr().add(4));
                }
                d0 ^= ti[0];
                d1 ^= ti[1];
                l2cn(d0, d1, lo, n as c_uint);
                lo = lo.add(n);
            }
        }
        l2c(v0, iv);
        l2c(v1, iv.add(4));
    }
}

/// `void DES_ofb_encrypt(const unsigned char *in, unsigned char *out, int numbits,
/// long length, DES_key_schedule *schedule, DES_cblock *ivec)` —
/// `crypto/des/ofb_enc.c:24-88`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_ofb_encrypt(
    input: *const u8,
    output: *mut u8,
    numbits: c_int,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
) {
    // SAFETY: the caller's contract.
    unsafe {
        let num = numbits as u32;
        if num > 64 {
            return;
        }
        let n = num.div_ceil(8) as usize;
        let (mask0, mask1) = if num > 32 {
            (
                0xffff_ffffu32,
                if num >= 64 {
                    0xffff_ffffu32
                } else {
                    (1u32 << (num - 32)) - 1
                },
            )
        } else {
            (
                if num == 32 {
                    0xffff_ffffu32
                } else {
                    (1u32 << num) - 1
                },
                0,
            )
        };
        let iv = (*ivec).as_mut_ptr();
        let mut v0 = c2l(iv);
        let mut v1 = c2l(iv.add(4));
        let mut li = input;
        let mut lo = output;
        let mut l = length;
        while l > 0 {
            let mut ti = [v0, v1];
            DES_encrypt1(ti.as_mut_ptr(), schedule, DES_ENCRYPT);
            let vv0 = ti[0];
            let vv1 = ti[1];
            let (d0, d1) = c2ln(li, n as c_uint);
            li = li.add(n);
            let d0 = (d0 ^ vv0) & mask0;
            let d1 = (d1 ^ vv1) & mask1;
            l2cn(d0, d1, lo, n as c_uint);
            lo = lo.add(n);
            if num == 32 {
                v0 = v1;
                v1 = vv0;
            } else if num == 64 {
                v0 = vv0;
                v1 = vv1;
            } else if num > 32 {
                v0 = (v1 >> (num - 32)) | (vv0 << (64 - num));
                v1 = (vv0 >> (num - 32)) | (vv1 << (64 - num));
            } else {
                v0 = (v0 >> num) | (v1 << (32 - num));
                v1 = (v1 >> num) | (vv0 << (32 - num));
            }
            l -= 1;
        }
        l2c(v0, iv);
        l2c(v1, iv.add(4));
    }
}

/// `void DES_ofb64_encrypt(...)` — `crypto/des/ofb64enc.c:23-66`.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes; `num` readable/writable.
#[no_mangle]
pub unsafe extern "C" fn DES_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [c2l(iv), c2l(iv.add(4))];
        let mut d = [0u8; 8];
        l2c(ti[0], d.as_mut_ptr());
        l2c(ti[1], d.as_mut_ptr().add(4));
        let mut save = 0;
        while l > 0 {
            if n == 0 {
                DES_encrypt1(ti.as_mut_ptr(), schedule, DES_ENCRYPT);
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
            l2c(ti[0], iv);
            l2c(ti[1], iv.add(4));
        }
        *num = n as c_int;
    }
}

/// `void DES_ede3_ofb64_encrypt(...)` — `crypto/des/ofb64ede.c:23-68`.
///
/// # Safety
/// As [`DES_ofb64_encrypt`], with three live schedules.
#[no_mangle]
pub unsafe extern "C" fn DES_ede3_ofb64_encrypt(
    mut input: *const u8,
    mut output: *mut u8,
    length: c_long,
    k1: *mut DesKeySchedule,
    k2: *mut DesKeySchedule,
    k3: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    num: *mut c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let iv = (*ivec).as_mut_ptr();
        let mut n = (*num & 0x07) as usize;
        let mut l = length;
        let mut ti = [c2l(iv), c2l(iv.add(4))];
        let mut d = [0u8; 8];
        l2c(ti[0], d.as_mut_ptr());
        l2c(ti[1], d.as_mut_ptr().add(4));
        let mut save = 0;
        while l > 0 {
            if n == 0 {
                DES_encrypt3(ti.as_mut_ptr(), k1, k2, k3);
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
            l2c(ti[0], iv);
            l2c(ti[1], iv.add(4));
        }
        *num = n as c_int;
    }
}

/// `void DES_cfb_encrypt(...)` — `crypto/des/cfb_enc.c:30-153`, the CFB-r variant. Only the
/// little-endian `sh[4]` path is compiled on this profile, which is what the `#ifdef L_ENDIAN`
/// branch reproduces.
///
/// # Safety
/// `in`/`out` `length` bytes; `schedule` live; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_cfb_encrypt(
    input: *const u8,
    output: *mut u8,
    numbits: c_int,
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
    enc: c_int,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let num = numbits / 8;
        let n = (numbits + 7) / 8;
        let rem = numbits % 8;
        if numbits <= 0 || numbits > 64 {
            return;
        }
        let n = n as usize;
        let iv = (*ivec).as_mut_ptr();
        let mut v0 = c2l(iv);
        let mut v1 = c2l(iv.add(4));
        let mut li = input;
        let mut lo = output;
        let mut l = length as u64;
        while l >= n as u64 {
            l -= n as u64;
            let mut ti = [v0, v1];
            DES_encrypt1(ti.as_mut_ptr(), schedule, DES_ENCRYPT);
            let (mut d0, mut d1) = c2ln(li, n as c_uint);
            li = li.add(n);
            if enc != 0 {
                d0 ^= ti[0];
                d1 ^= ti[1];
                l2cn(d0, d1, lo, n as c_uint);
                lo = lo.add(n);
                if numbits == 32 {
                    v0 = v1;
                    v1 = d0;
                } else if numbits == 64 {
                    v0 = d0;
                    v1 = d1;
                } else {
                    let mut sh = [v0, v1, d0, d1];
                    let ovec = sh.as_mut_ptr() as *mut u8;
                    if rem == 0 {
                        core::ptr::copy(ovec.add(num as usize), ovec, 8);
                    } else {
                        for i in 0..8 {
                            *ovec.add(i) = (*ovec.add(i + num as usize) << rem)
                                | (*ovec.add(i + num as usize + 1) >> (8 - rem));
                        }
                    }
                    v0 = sh[0];
                    v1 = sh[1];
                }
            } else {
                if numbits == 32 {
                    v0 = v1;
                    v1 = d0;
                } else if numbits == 64 {
                    v0 = d0;
                    v1 = d1;
                } else {
                    let mut sh = [v0, v1, d0, d1];
                    let ovec = sh.as_mut_ptr() as *mut u8;
                    if rem == 0 {
                        core::ptr::copy(ovec.add(num as usize), ovec, 8);
                    } else {
                        for i in 0..8 {
                            *ovec.add(i) = (*ovec.add(i + num as usize) << rem)
                                | (*ovec.add(i + num as usize + 1) >> (8 - rem));
                        }
                    }
                    v0 = sh[0];
                    v1 = sh[1];
                }
                d0 ^= ti[0];
                d1 ^= ti[1];
                l2cn(d0, d1, lo, n as c_uint);
                lo = lo.add(n);
            }
        }
        l2c(v0, iv);
        l2c(v1, iv.add(4));
    }
}

/// `DES_LONG DES_cbc_cksum(const unsigned char *in, DES_cblock *output, long length,
/// DES_key_schedule *schedule, const_DES_cblock *ivec)` — `crypto/des/cbc_cksm.c:18-59`.
///
/// # Safety
/// `in` `length` bytes; `output` eight bytes or NULL; `schedule` live; `ivec` eight bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_cbc_cksum(
    input: *const u8,
    output: *mut [u8; 8],
    length: c_long,
    schedule: *mut DesKeySchedule,
    ivec: *mut [u8; 8],
) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        let src = (*ivec).as_ptr();
        let mut tout0 = c2l(src);
        let mut tout1 = c2l(src.add(4));
        let mut li = input;
        let mut l = length;
        let mut tin = [0 as c_uint; 2];
        while l > 0 {
            let (tin0, tin1) = if l >= 8 {
                (c2l(li), c2l(li.add(4)))
            } else {
                c2ln(li, l as c_uint)
            };
            li = li.add(if l >= 8 { 8 } else { l as usize });
            tin[0] = tin0 ^ tout0;
            tin[1] = tin1 ^ tout1;
            DES_encrypt1(tin.as_mut_ptr(), schedule, DES_ENCRYPT);
            tout0 = tin[0];
            tout1 = tin[1];
            l -= 8;
        }
        if !output.is_null() {
            let out = (*output).as_mut_ptr();
            l2c(tout0, out);
            l2c(tout1, out.add(4));
        }
        // Match the MIT Kerberos mit_des_cbc_cksum return value.
        ((tout1 >> 24) & 0x0000_00ff)
            | ((tout1 >> 8) & 0x0000_ff00)
            | ((tout1 << 8) & 0x00ff_0000)
            | ((tout1 << 24) & 0xff00_0000)
    }
}

/// `DES_LONG DES_quad_cksum(const unsigned char *input, DES_cblock output[], long length,
/// int out_count, DES_cblock *seed)` — `crypto/des/qud_cksm.c:34-81`.
///
/// # Safety
/// `input` `length` bytes; `output` `2 * out_count` words writable (or NULL); `seed` eight
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_quad_cksum(
    input: *const u8,
    output: *mut [u8; 8],
    length: c_long,
    out_count: c_int,
    seed: *mut [u8; 8],
) -> c_uint {
    const NOISE: c_uint = 83_653_421;
    // SAFETY: the caller's contract.
    unsafe {
        let count = out_count.max(1);
        let mut lp: *mut u8 = if output.is_null() {
            core::ptr::null_mut()
        } else {
            (*output).as_mut_ptr()
        };
        let s = (*seed).as_ptr();
        let mut z0 = (*s as c_uint)
            | ((*s.add(1) as c_uint) << 8)
            | ((*s.add(2) as c_uint) << 16)
            | ((*s.add(3) as c_uint) << 24);
        let mut z1 = (*s.add(4) as c_uint)
            | ((*s.add(5) as c_uint) << 8)
            | ((*s.add(6) as c_uint) << 16)
            | ((*s.add(7) as c_uint) << 24);
        for _i in 0..4.min(count) {
            let mut cp = input;
            let mut l = length;
            while l > 0 {
                let mut t0;
                if l > 1 {
                    t0 = *cp as c_uint;
                    t0 |= (*cp.add(1) as c_uint) << 8;
                    cp = cp.add(2);
                    l -= 1;
                } else {
                    t0 = *cp as c_uint;
                    cp = cp.add(1);
                }
                l -= 1;
                t0 = t0.wrapping_add(z0);
                let t1 = z1;
                z0 = (t0.wrapping_mul(t0).wrapping_add(t1.wrapping_mul(t1))) % 0x7fff_ffff;
                z1 = (t0.wrapping_mul(t1.wrapping_add(NOISE))) % 0x7fff_ffff;
            }
            if !lp.is_null() {
                l2c(z0, lp);
                l2c(z1, lp.add(4));
                lp = lp.add(8);
            }
        }
        z0
    }
}

/// `void DES_string_to_key(const char *str, DES_cblock *key)` —
/// `crypto/des/str2key.c:19-47`.
///
/// # Safety
/// `str` a NUL-terminated C string; `key` eight bytes writable.
#[no_mangle]
pub unsafe extern "C" fn DES_string_to_key(str_: *const c_char, key: *mut [u8; 8]) {
    // SAFETY: the caller's contract.
    unsafe {
        let bytes = core::ffi::CStr::from_ptr(str_).to_bytes();
        let mut k = [0u8; 8];
        for (i, &j0) in bytes.iter().enumerate() {
            let mut j = j0;
            if (i % 16) < 8 {
                k[i % 8] ^= j << 1;
            } else {
                j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f);
                j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33);
                j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55);
                k[7 - (i % 8)] ^= j;
            }
        }
        *key = k;
        DES_set_odd_parity(key);
        let mut ks = DesKeySchedule {
            ks: [DesKs { deslong: [0; 2] }; 16],
        };
        DES_set_key_unchecked(key, &mut ks);
        let n = bytes.len().min(c_int::MAX as usize) as c_long;
        DES_cbc_cksum(str_.cast::<u8>(), key, n, &mut ks, key);
        // `crypto/des/str2key.c:46` fixes the parity again after the checksum overwrote it.
        DES_set_odd_parity(key);
    }
}

/// `void DES_string_to_2keys(const char *str, DES_cblock *key1, DES_cblock *key2)` —
/// `crypto/des/str2key.c:49-89`.
///
/// # Safety
/// `str` a NUL-terminated C string; `key1`/`key2` eight bytes each writable.
#[no_mangle]
pub unsafe extern "C" fn DES_string_to_2keys(
    str_: *const c_char,
    key1: *mut [u8; 8],
    key2: *mut [u8; 8],
) {
    // SAFETY: the caller's contract.
    unsafe {
        let bytes = core::ffi::CStr::from_ptr(str_).to_bytes();
        let mut k1 = [0u8; 8];
        let mut k2 = [0u8; 8];
        for (i, &j0) in bytes.iter().enumerate() {
            let mut j = j0;
            if (i % 32) < 16 {
                if (i % 16) < 8 {
                    k1[i % 8] ^= j << 1;
                } else {
                    k2[i % 8] ^= j << 1;
                }
            } else {
                j = ((j << 4) & 0xf0) | ((j >> 4) & 0x0f);
                j = ((j << 2) & 0xcc) | ((j >> 2) & 0x33);
                j = ((j << 1) & 0xaa) | ((j >> 1) & 0x55);
                if (i % 16) < 8 {
                    k1[7 - (i % 8)] ^= j;
                } else {
                    k2[7 - (i % 8)] ^= j;
                }
            }
        }
        if bytes.len() <= 8 {
            k2 = k1;
        }
        *key1 = k1;
        *key2 = k2;
        DES_set_odd_parity(key1);
        DES_set_odd_parity(key2);
        let mut ks = DesKeySchedule {
            ks: [DesKs { deslong: [0; 2] }; 16],
        };
        let n = bytes.len().min(c_int::MAX as usize) as c_long;
        DES_set_key_unchecked(key1, &mut ks);
        DES_cbc_cksum(str_.cast::<u8>(), key1, n, &mut ks, key1);
        DES_set_key_unchecked(key2, &mut ks);
        DES_cbc_cksum(str_.cast::<u8>(), key2, n, &mut ks, key2);
        DES_set_odd_parity(key1);
        DES_set_odd_parity(key2);
    }
}

/// `void fcrypt_body(DES_LONG *out, DES_key_schedule *ks, DES_LONG Eswap0,
/// DES_LONG Eswap1)` — `crypto/des/fcrypt_b.c:31-78`.
///
/// # Safety
/// `out` two words; `ks` live.
unsafe fn fcrypt_body(out: *mut c_uint, ks: *mut DesKeySchedule, e0: c_uint, e1: c_uint) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut l: c_uint = 0;
        let mut r: c_uint = 0;
        let s = (*ks).ks.as_mut_ptr() as *const c_uint;
        for _ in 0..25 {
            for i in 0..16usize {
                if i % 2 == 0 {
                    d_encrypt_fc(&mut l, r, s, 2 * i, e0, e1);
                } else {
                    d_encrypt_fc(&mut r, l, s, 2 * i, e0, e1);
                }
            }
            core::mem::swap(&mut l, &mut r);
        }
        l = l.rotate_right(3);
        r = r.rotate_right(3);
        perm_op(&mut l, &mut r, 1, 0x5555_5555);
        perm_op(&mut r, &mut l, 8, 0x00ff_00ff);
        perm_op(&mut l, &mut r, 2, 0x3333_3333);
        perm_op(&mut r, &mut l, 16, 0x0000_ffff);
        perm_op(&mut l, &mut r, 4, 0x0f0f_0f0f);
        *out = r;
        *out.add(1) = l;
    }
}

/// `char *DES_fcrypt(const char *buf, const char *salt, char *ret)` —
/// `crypto/des/fcrypt.c:94-152`.
///
/// # Safety
/// `buf`/`salt` NUL-terminated; `ret` writable for at least 14 bytes.
#[no_mangle]
pub unsafe extern "C" fn DES_fcrypt(
    buf: *const c_char,
    salt: *const c_char,
    ret: *mut c_char,
) -> *mut c_char {
    // SAFETY: the caller's contract.
    unsafe {
        let x0 = *salt as u8 as c_int;
        if x0 == 0 || x0 as usize >= DES_CON_SALT.len() {
            return core::ptr::null_mut();
        }
        *ret = *salt;
        let e0 = (DES_CON_SALT[x0 as usize] as c_uint) << 2;
        let x1 = *salt.add(1) as u8 as c_int;
        if x1 == 0 || x1 as usize >= DES_CON_SALT.len() {
            return core::ptr::null_mut();
        }
        *ret.add(1) = *salt.add(1);
        let e1 = (DES_CON_SALT[x1 as usize] as c_uint) << 6;

        let mut key = [0u8; 8];
        let mut p = buf;
        let mut i = 0;
        while i < 8 {
            let c = *p;
            if c == 0 {
                break;
            }
            key[i] = (c as u8) << 1;
            p = p.add(1);
            i += 1;
        }
        let mut ks = DesKeySchedule {
            ks: [DesKs { deslong: [0; 2] }; 16],
        };
        DES_set_key_unchecked(core::ptr::addr_of_mut!(key), &mut ks);
        let mut out = [0 as c_uint; 2];
        fcrypt_body(out.as_mut_ptr(), &mut ks, e0, e1);

        let mut bb = [0u8; 9];
        l2c(out[0], bb.as_mut_ptr());
        l2c(out[1], bb.as_mut_ptr().add(4));
        let mut y = 0usize;
        let mut u: u8 = 0x80;
        for idx in 2usize..13 {
            let mut c = 0u8;
            for _ in 0..6 {
                c <<= 1;
                if bb[y] & u != 0 {
                    c |= 1;
                }
                u >>= 1;
                if u == 0 {
                    y += 1;
                    u = 0x80;
                }
            }
            *ret.add(idx) = DES_COV_2CHAR[c as usize] as c_char;
        }
        *ret.add(13) = 0;
        ret
    }
}

/// A process-global buffer for [`DES_crypt`], exactly as `crypto/des/fcrypt.c:63` keeps one.
static mut DES_CRYPT_BUFF: [c_char; 14] = [0; 14];

/// `char *DES_crypt(const char *buf, const char *salt)` — `crypto/des/fcrypt.c:61-92`, the
/// non-EBCDIC arm.
///
/// # Safety
/// `buf`/`salt` NUL-terminated C strings. The returned pointer is to a shared static buffer,
/// as in the authority.
#[no_mangle]
pub unsafe extern "C" fn DES_crypt(buf: *const c_char, salt: *const c_char) -> *mut c_char {
    // SAFETY: the caller's contract; the buffer is a private static.
    unsafe {
        DES_fcrypt(
            buf,
            salt,
            core::ptr::addr_of_mut!(DES_CRYPT_BUFF).cast::<c_char>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_random_key_observes_the_properties_and_never_the_draw() {
        // `crypto/des/rand_key.c:19-27`. The value is random on both sides of the differential
        // court, so this test asserts what a caller relies on rather than the bytes: the loop
        // rejects weak keys, and the parity fix follows it.
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        // SAFETY: two live eight-byte buffers.
        unsafe {
            assert_eq!(DES_random_key(core::ptr::addr_of_mut!(a)), 1);
            assert_eq!(DES_random_key(core::ptr::addr_of_mut!(b)), 1);
        }
        // The loop's exit condition: the draw is not one of the sixteen weak keys.
        // SAFETY: `a` is a live eight-byte buffer.
        let weak = unsafe { DES_is_weak_key(core::ptr::addr_of_mut!(a)) };
        assert_eq!(weak, 0);
        // The parity fix after it.
        // SAFETY: `a` is a live eight-byte buffer.
        let parity = unsafe { DES_check_key_parity(core::ptr::addr_of_mut!(a)) };
        assert_eq!(parity, 1);
        for byte in a {
            assert_eq!(byte.count_ones() % 2, 1, "every byte is odd-parity");
        }
        // Two draws differ with probability 1 - 2^-64; a transcription that answered a constant
        // would fail here, and no arm compares the values themselves.
        assert_ne!(a, b);
        // The key is one `DES_set_key` accepts, which is the loop's whole purpose.
        let mut ks = DesKeySchedule {
            ks: [DesKs { deslong: [0; 2] }; 16],
        };
        // SAFETY: `a` and `ks` are live locals.
        let set = unsafe { DES_set_key(core::ptr::addr_of_mut!(a), &mut ks) };
        assert_eq!(set, 0);
    }

    fn schedule_from(key: &[u8; 8]) -> DesKeySchedule {
        let mut ks = DesKeySchedule {
            ks: [DesKs { deslong: [0; 2] }; 16],
        };
        let mut k = *key;
        // SAFETY: live locals, eight-byte key.
        unsafe { DES_set_key_unchecked(core::ptr::addr_of_mut!(k), &mut ks) };
        ks
    }

    #[test]
    fn the_fips_vector_round_trips() {
        // FIPS 46-3: key `133457799BBCDFF1`, block `0123456789ABCDEF` -> `85E813540F0AB405`.
        let key = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        let ks = schedule_from(&key);
        let mut block = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let mut out = [0u8; 8];
        // SAFETY: live locals.
        unsafe {
            DES_ecb_encrypt(
                core::ptr::addr_of_mut!(block),
                core::ptr::addr_of_mut!(out),
                core::ptr::addr_of!(ks) as *mut DesKeySchedule,
                DES_ENCRYPT,
            );
        }
        assert_eq!(out, [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]);
    }

    #[test]
    fn the_options_string_is_the_measured_one() {
        // SAFETY: the returned pointer is a static C string.
        let s = unsafe { DES_options() };
        // SAFETY: `s` points at that static NUL-terminated C string.
        let text = unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes();
        assert_eq!(text, b"des(int)");
    }

    #[test]
    fn weak_and_parity_helpers_agree_with_the_tables() {
        let mut weak = [0x01u8; 8];
        // SAFETY: live local, eight bytes.
        unsafe { assert_eq!(DES_is_weak_key(core::ptr::addr_of_mut!(weak)), 1) };
        let mut good = [0x13u8, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
        // SAFETY: live local, eight bytes.
        unsafe { assert_eq!(DES_check_key_parity(core::ptr::addr_of_mut!(good)), 1) };
        weak[0] = 0x00;
        // SAFETY: live local.
        unsafe { DES_set_odd_parity(core::ptr::addr_of_mut!(weak)) };
        assert_eq!(weak[0], 0x01);
    }
}
