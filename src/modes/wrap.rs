//! Phase 8.2 — the RFC 3394 key-wrap algorithm, as an internal shared by the 8.2 cipher
//! arms and 8.3's exported `CRYPTO_128_*` family.
//!
//! `AES_wrap_key`/`AES_unwrap_key` (`crypto/aes/aes_wrap.c`) are 8.2's and each is a
//! one-line delegate to `CRYPTO_128_wrap`/`CRYPTO_128_unwrap` (`crypto/modes/wrap128.c`).
//! Those two exports are the **key-wrap family**, which the plan puts in 8.3, so the
//! algorithm lives here as [`pub(crate)`] functions that 8.3's exported wrappers will call,
//! and the AES arms call now. Writing the algorithm twice — once private for AES and once
//! public for 8.3 — would be the second implementation of a symbol this stratum exports once,
//! which is the reason the MDC2 inversion was rejected (D197).
//!
//! RFC 3394 §2.2.1/§2.2.2 and the `wrap128.c` transcription: the default initial value
//! `A6A6A6A6A6A6A6A6`, the two `memmove`s an in-place caller needs, and the `t` counter's
//! three high bytes that only move once `t > 0xff`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_void;
use core::ptr;

use crate::modes::Block128F;
use crate::runtime::mem::{CRYPTO_memcmp, OPENSSL_cleanse};

/// `default_iv` — `crypto/modes/wrap128.c:22-24`.
const DEFAULT_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];

/// `CRYPTO128_WRAP_MAX` — `crypto/modes/wrap128.c:32`.
const CRYPTO128_WRAP_MAX: usize = 1 << 31;

/// `size_t CRYPTO_128_wrap(void *key, const unsigned char *iv, unsigned char *out, const
/// unsigned char *in, size_t inlen, block128_f block)` — `crypto/modes/wrap128.c:46-75`.
///
/// # Safety
/// `out` writable for `inlen + 8` bytes, `in` readable for `inlen`, `iv` NULL or readable for
/// eight, and `block` as its own contract requires.
pub(crate) unsafe fn wrap128(
    key: *mut c_void,
    iv: *const u8,
    out: *mut u8,
    input: *const u8,
    inlen: usize,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if (inlen & 0x7) != 0 || !(16..=CRYPTO128_WRAP_MAX).contains(&inlen) {
            return 0;
        }
        ptr::copy(input, out.add(8), inlen);

        let mut a = [0u8; 8];
        if iv.is_null() {
            a.copy_from_slice(&DEFAULT_IV);
        } else {
            ptr::copy_nonoverlapping(iv, a.as_mut_ptr(), 8);
        }

        let mut t: u64 = 1;
        for _ in 0..6 {
            let mut r = out.add(8);
            let mut i = 0;
            while i < inlen {
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&a);
                ptr::copy_nonoverlapping(r, b.as_mut_ptr().add(8), 8);
                block(b.as_ptr(), b.as_mut_ptr(), key);
                a.copy_from_slice(&b[..8]);
                a[7] ^= (t & 0xff) as u8;
                if t > 0xff {
                    a[6] ^= ((t >> 8) & 0xff) as u8;
                    a[5] ^= ((t >> 16) & 0xff) as u8;
                    a[4] ^= ((t >> 24) & 0xff) as u8;
                }
                ptr::copy_nonoverlapping(b.as_ptr().add(8), r, 8);
                i += 8;
                t += 1;
                r = r.add(8);
            }
        }
        ptr::copy_nonoverlapping(a.as_ptr(), out, 8);
        inlen + 8
    }
}

/// `crypto_128_unwrap_raw` — `crypto/modes/wrap128.c:92-129`.
///
/// # Safety
/// `out` writable for `inlen - 8`, `in` readable for `inlen`, `iv` writable for eight.
unsafe fn unwrap_raw(
    key: *mut c_void,
    iv: *mut u8,
    out: *mut u8,
    input: *const u8,
    inlen: usize,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let inlen = inlen - 8;
        if (inlen & 0x7) != 0 || !(16..=CRYPTO128_WRAP_MAX).contains(&inlen) {
            return 0;
        }
        let mut a = [0u8; 8];
        ptr::copy_nonoverlapping(input, a.as_mut_ptr(), 8);
        ptr::copy(input.add(8), out, inlen);

        let mut t: u64 = 6 * (inlen as u64 >> 3);
        for _ in 0..6 {
            let mut r = out.add(inlen - 8);
            let mut i = 0;
            while i < inlen {
                a[7] ^= (t & 0xff) as u8;
                if t > 0xff {
                    a[6] ^= ((t >> 8) & 0xff) as u8;
                    a[5] ^= ((t >> 16) & 0xff) as u8;
                    a[4] ^= ((t >> 24) & 0xff) as u8;
                }
                let mut b = [0u8; 16];
                b[..8].copy_from_slice(&a);
                ptr::copy_nonoverlapping(r, b.as_mut_ptr().add(8), 8);
                block(b.as_ptr(), b.as_mut_ptr(), key);
                a.copy_from_slice(&b[..8]);
                ptr::copy_nonoverlapping(b.as_ptr().add(8), r, 8);
                i += 8;
                t -= 1;
                r = r.sub(8);
            }
        }
        ptr::copy_nonoverlapping(a.as_ptr(), iv, 8);
        inlen
    }
}

/// `size_t CRYPTO_128_unwrap(void *key, const unsigned char *iv, unsigned char *out, const
/// unsigned char *in, size_t inlen, block128_f block)` — `crypto/modes/wrap128.c:143-161`.
///
/// # Safety
/// As [`wrap128`], with `out` writable for `inlen - 8`.
pub(crate) unsafe fn unwrap128(
    key: *mut c_void,
    iv: *const u8,
    out: *mut u8,
    input: *const u8,
    inlen: usize,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract, plus the comparison and cleanse below.
    unsafe {
        let mut got_iv = [0u8; 8];
        let ret = unwrap_raw(key, got_iv.as_mut_ptr(), out, input, inlen, block);
        if ret == 0 {
            return 0;
        }
        let expected = if iv.is_null() {
            DEFAULT_IV.as_ptr()
        } else {
            iv
        };
        if CRYPTO_memcmp(got_iv.as_ptr().cast(), expected.cast(), 8) != 0 {
            OPENSSL_cleanse(out.cast(), ret);
            return 0;
        }
        ret
    }
}
