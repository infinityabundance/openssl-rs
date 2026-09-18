//! Phase 8.2 — `crypto/modes/`'s non-AEAD mode helpers, `modes.h`'s `CRYPTO_*`.
//!
//! `docs/PHASE-8-SUBPHASES.md`'s 8.2 row owns "`modes.h`'s `CRYPTO_*` helpers", and the
//! plan's 8.3 row owns "the remaining `CRYPTO_*` mode functions" — the AEAD constructions.
//! This module is the **non-AEAD half in full**:
//!
//! * CBC (`CRYPTO_cbc128_encrypt`/`_decrypt`), the mode AES's own `AES_cbc_encrypt` is
//!   written over;
//! * the feedback modes CFB-128 (`CRYPTO_cfb128_encrypt`), CFB-8 (`CRYPTO_cfb128_8_encrypt`)
//!   and CFB-1 (`CRYPTO_cfb128_1_encrypt`), whose `length` is a **bit** count and whose bit
//!   packing is MSB-first;
//! * OFB (`CRYPTO_ofb128_encrypt`);
//! * CTR, both the general counter (`CRYPTO_ctr128_encrypt`) and the 32-bit-counter
//!   fast path (`CRYPTO_ctr128_encrypt_ctr32`) that re-uses the block cipher's own
//!   counter routine;
//! * the two ciphertext-stealing families, RFC 2040-style (`CRYPTO_cts128_*`) and the
//!   NIST proposal (`CRYPTO_nistcts128_*`), each with its block-taking and cbc-taking
//!   spelling.
//!
//! ## What is here, and what is deliberately 8.3's
//!
//! The **AEAD** constructions in the same header are *not* here: GCM (`CRYPTO_gcm128_*`),
//! CCM (`CRYPTO_ccm128_*`), OCB (`CRYPTO_ocb128_*`), XTS (`CRYPTO_xts128_encrypt`) and the
//! key-wrap family (`CRYPTO_128_{wrap,unwrap,wrap_pad,unwrap_pad}`). They are the
//! authenticated constructions, the plan separates them into 8.3, and D-plan's ordering is
//! by dependency: this module is what a probe can drive with an ordinary `block128_f`, and
//! the AEAD family needs the GHASH/CMAC/OCB arithmetic 8.3 lands.
//!
//! ## `block128_f` and the two planes
//!
//! Every function here is generic over a caller-supplied `block128_f` (or `cbc128_f`/
//! `ctr128_f`), so it is *not* a cipher: it is the transform that a cipher's own ECB entry
//! point is fed to. That is why the differential court can exercise it on both sides with a
//! probe-local block function before any cipher has landed, and why the construction vectors
//! arrive with AES in the next commit: a mode with no named block cipher has no published
//! vector, and the committed AES-mode values in
//! `test/recipes/30-test_evp_data/evpciph_aes_common.txt` are the standard's statement of
//! the same transforms.
//!
//! ## The transcription is structural, and the authority's own arithmetical devices are kept
//!
//! The authority's fast arms (the `size_t_aX` block copies, `ctr128_inc_aligned`'s
//! word-at-a-time carry) are *endian and alignment optimisations of a byte sequence*; this
//! module reads and writes bytes, which is the same value on this profile's little-endian
//! host. What is **not** simplified away is every observable side effect: the IV write-back
//! (the authority writes the advanced IV through the caller's pointer), the `num` round
//! trip, the `*num = -1` poison arm in `CRYPTO_ofb128_encrypt`/`CRYPTO_cfb128_encrypt`, and
//! the partial-final-block arm of CBC encryption that fills the tail from the IV rather than
//! from the input.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint, c_void};
use core::ptr;

pub mod ccm;
pub mod gcm;
pub mod wrap;
pub mod xts;

/// `block128_f` — `include/openssl/modes.h:25-26`: one block cipher call, `in` and `out` each
/// sixteen bytes, `key` the caller's key schedule.
pub type Block128F = unsafe extern "C" fn(input: *const u8, out: *mut u8, key: *const c_void);

/// `cbc128_f` — `include/openssl/modes.h:28-30`: a whole CBC run, used by the CTS wrappers.
pub type Cbc128F = unsafe extern "C" fn(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
);

/// `ctr128_f` — `include/openssl/modes.h:36-38`: `blocks` counter blocks from a 32-bit
/// counter, with the counter *not* advanced by the callee.
pub type Ctr128F = unsafe extern "C" fn(
    input: *const u8,
    out: *mut u8,
    blocks: usize,
    key: *const c_void,
    ivec: *const u8,
);

/// `ccm128_f` — `include/openssl/modes.h:40-43`: `blocks` CCM blocks from the 64-bit counter,
/// updating the CBC-MAC in `cmac` as it goes. The counter is advanced by the callee through the
/// `ctr64_add` in [`ccm::CRYPTO_ccm128_encrypt_ccm64`].
pub type Ccm128F = unsafe extern "C" fn(
    inp: *const u8,
    out: *mut u8,
    blocks: usize,
    key: *const c_void,
    ivec: *const u8,
    cmac: *mut u8,
);

/// `ctr128_inc` — `crypto/modes/ctr128.c:28-38`: increment a 128-bit big-endian counter.
fn ctr128_inc(counter: *mut u8) {
    // SAFETY: the caller passes a live sixteen-byte counter; every access is within it.
    unsafe {
        let mut n: u32 = 16;
        let mut c: u32 = 1;
        loop {
            n -= 1;
            c += *counter.add(n as usize) as u32;
            *counter.add(n as usize) = c as u8;
            c >>= 8;
            if n == 0 {
                break;
            }
        }
    }
}

/// `ctr96_inc` — `crypto/modes/ctr128.c:190-199`: increment the upper ninety-six bits.
fn ctr96_inc(counter: *mut u8) {
    // SAFETY: the caller passes a live sixteen-byte counter.
    unsafe {
        let mut n: u32 = 12;
        let mut c: u32 = 1;
        loop {
            n -= 1;
            c += *counter.add(n as usize) as u32;
            *counter.add(n as usize) = c as u8;
            c >>= 8;
            if n == 0 {
                break;
            }
        }
    }
}

/// `GETU32` — `internal/endian.h`, big-endian, used for the 32-bit CTR word.
///
/// # Safety
/// `p` must be readable for four bytes.
unsafe fn get_u32_be(p: *const u8) -> u32 {
    // SAFETY: the caller's contract.
    unsafe { u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]) }
}

/// `PUTU32` — `internal/endian.h`, big-endian.
///
/// # Safety
/// `p` must be writable for four bytes.
unsafe fn put_u32_be(p: *mut u8, value: u32) {
    // SAFETY: the caller's contract.
    unsafe {
        let bytes = value.to_be_bytes();
        *p = bytes[0];
        *p.add(1) = bytes[1];
        *p.add(2) = bytes[2];
        *p.add(3) = bytes[3];
    }
}

/// `void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cbc128.c:29-73`.
///
/// # Safety
/// `in` readable for `len` bytes (or aliasing `out`), `out` writable for `len`, `ivec`
/// writable for 16, and `block` a function the caller may call with `out` as both buffers.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cbc128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) {
    // SAFETY: the caller's contract; `iv` and `out` always point into the regions named
    // there, and `block` reads and writes sixteen bytes at the pointers it is given.
    unsafe {
        let mut len = len;
        let mut input = input;
        let mut out = out;
        let mut iv = ivec;
        if len == 0 {
            return;
        }

        while len >= 16 {
            for n in 0..16 {
                *out.add(n) = *input.add(n) ^ *iv.add(n);
            }
            block(out, out, key);
            iv = out;
            len -= 16;
            input = input.add(16);
            out = out.add(16);
        }

        // The authority's tail: bytes past `len` are the IV's, not the input's, so the
        // final block is the IV padded by the last partial plaintext block.
        while len != 0 {
            let mut n = 0;
            while n < 16 && n < len {
                *out.add(n) = *input.add(n) ^ *iv.add(n);
                n += 1;
            }
            while n < 16 {
                *out.add(n) = *iv.add(n);
                n += 1;
            }
            block(out, out, key);
            iv = out;
            if len <= 16 {
                break;
            }
            len -= 16;
            input = input.add(16);
            out = out.add(16);
        }

        if ivec != iv {
            ptr::copy_nonoverlapping(iv, ivec, 16);
        }
    }
}

/// `void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cbc128.c:75-168`.
///
/// The in-place and out-of-place arms differ in *where* the ciphertext is kept before it is
/// overwritten, which is exactly the distinction the differential court observes.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cbc128_decrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut len = len;
        let mut input = input;
        let mut out = out;
        if len == 0 {
            return;
        }

        if input != out {
            let mut iv: *const u8 = ivec;
            while len >= 16 {
                block(input, out, key);
                for n in 0..16 {
                    *out.add(n) ^= *iv.add(n);
                }
                iv = input;
                len -= 16;
                input = input.add(16);
                out = out.add(16);
            }
            if !core::ptr::eq(ivec as *const u8, iv) {
                ptr::copy_nonoverlapping(iv, ivec, 16);
            }
        } else {
            let mut tmp = [0u8; 16];
            while len >= 16 {
                block(input, tmp.as_mut_ptr(), key);
                for (n, t) in tmp.iter().enumerate() {
                    let c = *input.add(n);
                    *out.add(n) = *t ^ *ivec.add(n);
                    *ivec.add(n) = c;
                }
                len -= 16;
                input = input.add(16);
                out = out.add(16);
            }
        }

        while len != 0 {
            let mut tmp = [0u8; 16];
            block(input, tmp.as_mut_ptr(), key);
            let mut n = 0;
            while n < 16 && n < len {
                let c = *input.add(n);
                *out.add(n) = tmp[n] ^ *ivec.add(n);
                *ivec.add(n) = c;
                n += 1;
            }
            if len <= 16 {
                while n < 16 {
                    *ivec.add(n) = *input.add(n);
                    n += 1;
                }
                break;
            }
            len -= 16;
            input = input.add(16);
            out = out.add(16);
        }
    }
}

/// `void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], int *num, block128_f block)` —
/// `crypto/modes/ofb128.c:25-83`.
///
/// # Safety
/// `in` readable for `len`, `out` writable for `len`, `ivec` writable for 16, `num`
/// writable, and `block` as for [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ofb128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    num: *mut c_int,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if *num < 0 {
            // There is no error return, so the authority poisons the count instead.
            *num = -1;
            return;
        }
        let mut n = *num as u32;
        let mut l: usize = 0;

        while n != 0 && l < len {
            *out.add(l) = *input.add(l) ^ *ivec.add(n as usize);
            l += 1;
            n = (n + 1) % 16;
        }
        while l + 16 <= len {
            block(ivec, ivec, key);
            let mut i = 0;
            while i < 16 {
                *out.add(l + i) = *input.add(l + i) ^ *ivec.add(i);
                i += 1;
            }
            l += 16;
            n = 0;
        }
        if l < len {
            block(ivec, ivec, key);
            while l < len {
                *out.add(l) = *input.add(l) ^ *ivec.add(n as usize);
                l += 1;
                n += 1;
            }
        }
        *num = n as c_int;
    }
}

/// `void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], int *num, int enc, block128_f block)` —
/// `crypto/modes/cfb128.c:29-133`.
///
/// # Safety
/// As [`CRYPTO_ofb128_encrypt`]; `enc` selects encryption (non-zero) or decryption.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    num: *mut c_int,
    enc: c_int,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if *num < 0 {
            *num = -1;
            return;
        }
        let mut n = *num as u32;
        let mut l: usize = 0;

        if enc != 0 {
            while n != 0 && l < len {
                let c = *input.add(l);
                *ivec.add(n as usize) ^= c;
                *out.add(l) = *ivec.add(n as usize);
                l += 1;
                n = (n + 1) % 16;
            }
            while l + 16 <= len {
                block(ivec, ivec, key);
                let mut i = 0;
                while i < 16 {
                    let c = *input.add(l + i);
                    *ivec.add(i) ^= c;
                    *out.add(l + i) = *ivec.add(i);
                    i += 1;
                }
                l += 16;
                n = 0;
            }
            if l < len {
                block(ivec, ivec, key);
                while l < len {
                    let c = *input.add(l);
                    *ivec.add(n as usize) ^= c;
                    *out.add(l) = *ivec.add(n as usize);
                    l += 1;
                    n += 1;
                }
            }
            *num = n as c_int;
        } else {
            while n != 0 && l < len {
                let c = *input.add(l);
                *out.add(l) = *ivec.add(n as usize) ^ c;
                *ivec.add(n as usize) = c;
                l += 1;
                n = (n + 1) % 16;
            }
            while l + 16 <= len {
                block(ivec, ivec, key);
                let mut i = 0;
                while i < 16 {
                    let c = *input.add(l + i);
                    *out.add(l + i) = *ivec.add(i) ^ c;
                    *ivec.add(i) = c;
                    i += 1;
                }
                l += 16;
                n = 0;
            }
            if l < len {
                block(ivec, ivec, key);
                while l < len {
                    let c = *input.add(l);
                    *out.add(l) = *ivec.add(n as usize) ^ c;
                    *ivec.add(n as usize) = c;
                    l += 1;
                    n += 1;
                }
            }
            *num = n as c_int;
        }
    }
}

/// `cfbr_encrypt_block` — `crypto/modes/cfb128.c:139-168`: one CFB run over `nbits` bits,
/// MSB-first, packing the shifted IV back.
///
/// # Safety
/// `in` readable for `nbits` bits (rounded up), `out` writable for the same, `ivec`
/// writable for 16, `block` as for [`CRYPTO_cbc128_encrypt`].
unsafe fn cfbr_encrypt_block(
    input: *const u8,
    out: *mut u8,
    nbits: c_int,
    key: *const c_void,
    ivec: *mut u8,
    enc: c_int,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        if nbits <= 0 || nbits > 128 {
            return;
        }
        // `ovec[16..32]` holds the new IV candidate and `ovec[..16]` the old IV, exactly as the
        // authority's doubled buffer does: the shift reads one byte past the written region,
        // which is why the authority's buffer is `16 * 2 + 1`.
        let mut ovec = [0u8; 16 * 2 + 1];
        ptr::copy_nonoverlapping(ivec, ovec.as_mut_ptr(), 16);
        block(ivec, ivec, key);
        let num = (nbits as usize).div_ceil(8);
        if enc != 0 {
            for n in 0..num {
                let v = *input.add(n) ^ *ivec.add(n);
                ovec[16 + n] = v;
                *out.add(n) = v;
            }
        } else {
            for n in 0..num {
                let v = *input.add(n) ^ *ivec.add(n);
                ovec[16 + n] = *input.add(n);
                *out.add(n) = v;
            }
        }
        let rem = (nbits % 8) as u32;
        let num = (nbits / 8) as usize;
        if rem == 0 {
            ptr::copy_nonoverlapping(ovec.as_ptr().add(num), ivec, 16);
        } else {
            for n in 0..16 {
                *ivec.add(n) = (ovec[n + num] << rem) | (ovec[n + num + 1] >> (8 - rem));
            }
        }
    }
}

/// `void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out, size_t bits,
/// const void *key, unsigned char ivec[16], int *num, int enc, block128_f block)` —
/// `crypto/modes/cfb128.c:171-184`.
///
/// **`bits`, not `length`.** The parameter is a bit count and the input is packed MSB-first;
/// a caller that passes a byte count silently encrypts a prefix, which is the trap this
/// function's probe observation pins.
///
/// # Safety
/// `in` readable for `ceil(bits/8)` bytes, `out` writable for the same, `ivec` writable for
/// 16, and `block` as for [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_1_encrypt(
    input: *const u8,
    out: *mut u8,
    bits: usize,
    key: *const c_void,
    ivec: *mut u8,
    _num: *mut c_int,
    enc: c_int,
    block: Block128F,
) {
    // SAFETY: the caller's contract; `c`/`d` are locals and `cfbr_encrypt_block` writes one
    // byte at `d`.
    unsafe {
        let mut c = [0u8; 1];
        let mut d = [0u8; 1];
        for n in 0..bits {
            c[0] = if (*input.add(n / 8) & (1u8 << (7 - n % 8))) != 0 {
                0x80
            } else {
                0
            };
            cfbr_encrypt_block(c.as_ptr(), d.as_mut_ptr(), 1, key, ivec, enc, block);
            let keep = *out.add(n / 8) & !(1u8 << (7 - n % 8));
            *out.add(n / 8) = keep | ((d[0] & 0x80) >> (n % 8));
        }
    }
}

/// `void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out, size_t length,
/// const void *key, unsigned char ivec[16], int *num, int enc, block128_f block)` —
/// `crypto/modes/cfb128.c:186-195`.
///
/// # Safety
/// As [`CRYPTO_cfb128_1_encrypt`], with `length` in bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cfb128_8_encrypt(
    input: *const u8,
    out: *mut u8,
    length: usize,
    key: *const c_void,
    ivec: *mut u8,
    _num: *mut c_int,
    enc: c_int,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        for n in 0..length {
            cfbr_encrypt_block(input.add(n), out.add(n), 8, key, ivec, enc, block);
        }
    }
}

/// `void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int *num,
/// block128_f block)` — `crypto/modes/ctr128.c:72-131`.
///
/// # Safety
/// `in` readable for `len`, `out` writable for `len`, `ivec` and `ecount_buf` writable for
/// 16, `num` writable, and `block` as for [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ctr128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    ecount_buf: *mut u8,
    num: *mut c_uint,
    block: Block128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut n = *num;
        let mut l: usize = 0;

        while n != 0 && l < len {
            *out.add(l) = *input.add(l) ^ *ecount_buf.add(n as usize);
            l += 1;
            n = (n + 1) % 16;
        }
        while l + 16 <= len {
            block(ivec, ecount_buf, key);
            ctr128_inc(ivec);
            for i in 0..16 {
                *out.add(l + i) = *input.add(l + i) ^ *ecount_buf.add(i);
            }
            l += 16;
            n = 0;
        }
        if l < len {
            block(ivec, ecount_buf, key);
            ctr128_inc(ivec);
            while l < len {
                *out.add(l) = *input.add(l) ^ *ecount_buf.add(n as usize);
                l += 1;
                n += 1;
            }
        }
        *num = n;
    }
}

/// `void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int *num,
/// ctr128_f ctr)` — `crypto/modes/ctr128.c:201-260`.
///
/// # Safety
/// As [`CRYPTO_ctr128_encrypt`], with `ctr` the block cipher's 32-bit-counter routine.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ctr128_encrypt_ctr32(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    ecount_buf: *mut u8,
    num: *mut c_uint,
    ctr: Ctr128F,
) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut len = len;
        let mut n = *num;
        let mut input = input;
        let mut out = out;

        while n != 0 && len != 0 {
            *out = *input ^ *ecount_buf.add(n as usize);
            out = out.add(1);
            input = input.add(1);
            len -= 1;
            n = (n + 1) % 16;
        }

        let mut ctr32 = get_u32_be(ivec.add(12));
        while len >= 16 {
            let mut blocks = len / 16;
            if core::mem::size_of::<usize>() > core::mem::size_of::<u32>()
                && blocks > (1usize << 28)
            {
                blocks = 1usize << 28;
            }
            let add = blocks as u32;
            ctr32 = ctr32.wrapping_add(add);
            if ctr32 < add {
                blocks -= ctr32 as usize;
                ctr32 = 0;
            }
            ctr(input, out, blocks, key, ivec);
            put_u32_be(ivec.add(12), ctr32);
            if ctr32 == 0 {
                ctr96_inc(ivec);
            }
            let consumed = blocks * 16;
            len -= consumed;
            out = out.add(consumed);
            input = input.add(consumed);
        }
        if len != 0 {
            ptr::write_bytes(ecount_buf, 0, 16);
            ctr(ecount_buf, ecount_buf, 1, key, ivec);
            ctr32 = ctr32.wrapping_add(1);
            put_u32_be(ivec.add(12), ctr32);
            if ctr32 == 0 {
                ctr96_inc(ivec);
            }
            while len != 0 {
                *out.add(n as usize) = *input.add(n as usize) ^ *ecount_buf.add(n as usize);
                n += 1;
                len -= 1;
            }
        }
        *num = n;
    }
}

/// `size_t CRYPTO_cts128_encrypt_block(const unsigned char *in, unsigned char *out, size_t
/// len, const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cts128.c:35-61`.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cts128_encrypt_block(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len <= 16 {
            return 0;
        }
        let mut residue = len % 16;
        if residue == 0 {
            residue = 16;
        }
        let len = len - residue;

        CRYPTO_cbc128_encrypt(input, out, len, key, ivec, block);

        let input = input.add(len);
        let out = out.add(len);

        for n in 0..residue {
            *ivec.add(n) ^= *input.add(n);
        }
        block(ivec, ivec, key);
        ptr::copy_nonoverlapping(out.sub(16), out, residue);
        ptr::copy_nonoverlapping(ivec, out.sub(16), 16);

        len + residue
    }
}

/// `size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
/// size_t len, const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cts128.c:63-91`.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_nistcts128_encrypt_block(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len < 16 {
            return 0;
        }
        let residue = len % 16;
        let len = len - residue;

        CRYPTO_cbc128_encrypt(input, out, len, key, ivec, block);
        if residue == 0 {
            return len;
        }

        let input = input.add(len);
        let out = out.add(len);

        for n in 0..residue {
            *ivec.add(n) ^= *input.add(n);
        }
        block(ivec, ivec, key);
        ptr::copy_nonoverlapping(ivec, out.sub(16).add(residue), 16);

        len + residue
    }
}

/// `size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], cbc128_f cbc)` — `crypto/modes/cts128.c:93-125`.
///
/// # Safety
/// `in` readable for `len`, `out` writable for `len`, `ivec` writable for 16, and `cbc` a
/// CBC routine the caller may call with a local buffer.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cts128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    cbc_fn: Cbc128F,
) -> usize {
    // SAFETY: the caller's contract; `tmp` is a local sixteen-byte buffer and `cbc_fn` reads and
    // writes exactly the bytes it is told to.
    unsafe {
        if len <= 16 {
            return 0;
        }
        let mut residue = len % 16;
        if residue == 0 {
            residue = 16;
        }
        let len = len - residue;

        cbc_fn(input, out, len, key, ivec, 1);

        let input = input.add(len);
        let out = out.add(len);

        let mut tmp = [0u8; 16];
        ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), residue);
        ptr::copy_nonoverlapping(out.sub(16), out, residue);
        cbc_fn(tmp.as_ptr(), out.sub(16), 16, key, ivec, 1);

        len + residue
    }
}

/// `size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], cbc128_f cbc)` — `crypto/modes/cts128.c:127-151`.
///
/// # Safety
/// As [`CRYPTO_cts128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_nistcts128_encrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    cbc_fn: Cbc128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len < 16 {
            return 0;
        }
        let residue = len % 16;
        let len = len - residue;

        cbc_fn(input, out, len, key, ivec, 1);
        if residue == 0 {
            return len;
        }
        let input = input.add(len);
        let out = out.add(len);

        let mut tmp = [0u8; 16];
        ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), residue);
        cbc_fn(tmp.as_ptr(), out.sub(16).add(residue), 16, key, ivec, 1);

        len + residue
    }
}

/// `size_t CRYPTO_cts128_decrypt_block(const unsigned char *in, unsigned char *out, size_t
/// len, const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cts128.c:153-192`.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cts128_decrypt_block(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len <= 16 {
            return 0;
        }
        let mut residue = len % 16;
        if residue == 0 {
            residue = 16;
        }
        let len = len - 16 - residue;

        let mut input = input;
        let mut out = out;
        if len != 0 {
            CRYPTO_cbc128_decrypt(input, out, len, key, ivec, block);
            input = input.add(len);
            out = out.add(len);
        }

        let mut tmp = [0u8; 32];
        block(input, tmp.as_mut_ptr().add(16), key);
        ptr::copy_nonoverlapping(tmp.as_ptr().add(16), tmp.as_mut_ptr(), 16);
        ptr::copy_nonoverlapping(input.add(16), tmp.as_mut_ptr(), residue);
        block(tmp.as_ptr(), tmp.as_mut_ptr(), key);

        let mut n = 0;
        while n < 16 {
            let c = *input.add(n);
            *out.add(n) = tmp[n] ^ *ivec.add(n);
            *ivec.add(n) = c;
            n += 1;
        }
        residue += 16;
        while n < residue {
            *out.add(n) = tmp[n] ^ *input.add(n);
            n += 1;
        }

        16 + len + residue
    }
}

/// `size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
/// size_t len, const void *key, unsigned char ivec[16], block128_f block)` —
/// `crypto/modes/cts128.c:194-242`.
///
/// # Safety
/// As [`CRYPTO_cbc128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_nistcts128_decrypt_block(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    block: Block128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len < 16 {
            return 0;
        }
        let residue = len % 16;
        if residue == 0 {
            CRYPTO_cbc128_decrypt(input, out, len, key, ivec, block);
            return len;
        }
        let len = len - 16 - residue;

        let mut input = input;
        let mut out = out;
        if len != 0 {
            CRYPTO_cbc128_decrypt(input, out, len, key, ivec, block);
            input = input.add(len);
            out = out.add(len);
        }

        let mut tmp = [0u8; 32];
        block(input.add(residue), tmp.as_mut_ptr().add(16), key);
        ptr::copy_nonoverlapping(tmp.as_ptr().add(16), tmp.as_mut_ptr(), 16);
        ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), residue);
        block(tmp.as_ptr(), tmp.as_mut_ptr(), key);

        let mut n = 0;
        while n < 16 {
            let c = *input.add(n);
            *out.add(n) = tmp[n] ^ *ivec.add(n);
            *ivec.add(n) = *input.add(n + residue);
            tmp[n] = c;
            n += 1;
        }
        let finish = residue + 16;
        while n < finish {
            *out.add(n) = tmp[n] ^ tmp[n - 16];
            n += 1;
        }

        // The authority's `for (residue += 16; ...)` leaves `residue` thirty here.
        16 + len + residue + 16
    }
}

/// `size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], cbc128_f cbc)` — `crypto/modes/cts128.c:244-283`.
///
/// # Safety
/// As [`CRYPTO_cts128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_cts128_decrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    cbc_fn: Cbc128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len <= 16 {
            return 0;
        }
        let mut residue = len % 16;
        if residue == 0 {
            residue = 16;
        }
        let len = len - 16 - residue;

        let mut input = input;
        let mut out = out;
        if len != 0 {
            cbc_fn(input, out, len, key, ivec, 0);
            input = input.add(len);
            out = out.add(len);
        }

        let mut tmp = [0u8; 32];
        // This places `in[16..]` at `&tmp[16]` and the decrypted block at `&tmp[0]`.
        cbc_fn(
            input,
            tmp.as_mut_ptr(),
            16,
            key,
            tmp.as_mut_ptr().add(16),
            0,
        );

        ptr::copy_nonoverlapping(input.add(16), tmp.as_mut_ptr(), residue);
        cbc_fn(tmp.as_ptr(), tmp.as_mut_ptr(), 32, key, ivec, 0);
        ptr::copy_nonoverlapping(tmp.as_ptr(), out, 16 + residue);

        16 + len + residue
    }
}

/// `size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out, size_t len,
/// const void *key, unsigned char ivec[16], cbc128_f cbc)` — `crypto/modes/cts128.c:285-330`.
///
/// # Safety
/// As [`CRYPTO_cts128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_nistcts128_decrypt(
    input: *const u8,
    out: *mut u8,
    len: usize,
    key: *const c_void,
    ivec: *mut u8,
    cbc_fn: Cbc128F,
) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        if len < 16 {
            return 0;
        }
        let residue = len % 16;
        if residue == 0 {
            cbc_fn(input, out, len, key, ivec, 0);
            return len;
        }
        let len = len - 16 - residue;

        let mut input = input;
        let mut out = out;
        if len != 0 {
            cbc_fn(input, out, len, key, ivec, 0);
            input = input.add(len);
            out = out.add(len);
        }

        let mut tmp = [0u8; 32];
        cbc_fn(
            input.add(residue),
            tmp.as_mut_ptr(),
            16,
            key,
            tmp.as_mut_ptr().add(16),
            0,
        );
        ptr::copy_nonoverlapping(input, tmp.as_mut_ptr(), residue);
        cbc_fn(tmp.as_ptr(), tmp.as_mut_ptr(), 32, key, ivec, 0);
        ptr::copy_nonoverlapping(tmp.as_ptr(), out, 16 + residue);

        16 + len + residue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe-local "block cipher": XOR the sixteen-byte block with a byte that depends on
    /// the position, so the mode functions are exercised without any cipher having landed.
    /// It is its own inverse, which is what CBC decryption needs from a block function.
    unsafe extern "C" fn toy_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the mode functions guarantee sixteen readable bytes at `input`, sixteen
        // writable at `out`, and one readable at `key`.
        unsafe {
            let k = *(key.cast::<u8>());
            for i in 0..16 {
                *out.add(i) = (*input.add(i)) ^ k.wrapping_add(i as u8);
            }
        }
    }

    #[test]
    fn cbc_round_trips_through_its_inverse() {
        let key = 0x3bu8;
        let mut iv = [0u8; 16];
        for (i, b) in iv.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plain: Vec<u8> = (0..40u8).collect();
        // CBC writes a whole final block for a partial input, so the caller's buffer must
        // have room for it; that is the authority's own contract and the reason the probe
        // observes the trailing bytes.
        let mut cipher = vec![0u8; plain.len() + 16];
        let mut iv_enc = iv;
        // SAFETY: the pointers are live locals.
        unsafe {
            CRYPTO_cbc128_encrypt(
                plain.as_ptr(),
                cipher.as_mut_ptr(),
                plain.len(),
                (&key as *const u8).cast(),
                iv_enc.as_mut_ptr(),
                toy_block,
            );
            let mut dec = vec![0u8; plain.len()];
            let mut iv_dec = iv;
            CRYPTO_cbc128_decrypt(
                cipher.as_ptr(),
                dec.as_mut_ptr(),
                plain.len(),
                (&key as *const u8).cast(),
                iv_dec.as_mut_ptr(),
                toy_block,
            );
            assert_eq!(dec, plain);
        }
    }

    #[test]
    fn cfb1_takes_a_bit_count() {
        let key = 0x11u8;
        let mut iv = [0u8; 16];
        // One byte of input is eight bits; passing `1` must touch the top bit of one byte.
        let input = [0b1010_1010u8];
        let mut out = [0u8; 1];
        // SAFETY: live locals.
        unsafe {
            CRYPTO_cfb128_1_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                1,
                (&key as *const u8).cast(),
                iv.as_mut_ptr(),
                ptr::null_mut(),
                1,
                toy_block,
            );
        }
        // The low seven bits are untouched when only one bit is processed.
        assert_eq!(out[0] & 0x7f, 0);
    }
}
