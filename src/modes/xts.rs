//! Phase 8.3 — XTS (`crypto/modes/xts128.c`), the one `CRYPTO_xts128_encrypt` export.
//!
//! XTS is a tweakable narrow-block mode with **ciphertext stealing**, and the two rules the plan
//! names are exactly what is transcribed:
//!
//! * the tweak is the IV encrypted under the second key, and it is advanced between blocks by
//!   multiplication by `x` in `GF(2^128)` — `0x87` is XORed in when the top bit was set, which is
//!   the little-endian branch of `IS_LITTLE_ENDIAN`. That branch is the one this profile's build
//!   compiles (x86-64); the big-endian arm is the identical arithmetic on the byte string and is
//!   dead here, so the crate implements the little-endian form and this note records that.
//! * ciphertext stealing on a final partial block: encryption replaces the tail of the output
//!   with the stolen prefix of the previous ciphertext block and re-encrypts the mixed block into
//!   `out - 16`; decryption steals in the opposite direction and writes the last full block and
//!   the recovered tail separately.
//!
//! The context is **caller-supplied and caller-populated**: the public header only
//! forward-declares `XTS128_CONTEXT`, and the four fields (`key1`, `key2`, `block1`, `block2`) are
//! set by the caller before the call. The struct here is `#[repr(C)]` and field-for-field the
//! authority's, because the caller writes it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::modes::Block128F;

/// `xts128_context` — `include/crypto/modes.h:148-151`. Field-for-field the authority's, because
/// the caller fills it in before calling [`CRYPTO_xts128_encrypt`].
#[repr(C)]
pub struct XtsCtx {
    /// `void *key1` — the data-unit cipher's key schedule.
    key1: *mut c_void,
    /// `void *key2` — the tweak cipher's key schedule.
    key2: *mut c_void,
    /// `block128_f block1` — the data-unit cipher (encrypt direction for both operations).
    block1: Option<Block128F>,
    /// `block128_f block2` — the tweak cipher.
    block2: Option<Block128F>,
}

/// The little-endian doubling, `IS_LITTLE_ENDIAN`'s arm of `crypto/modes/xts128.c:71-77`: the
/// two host-order 64-bit words are shifted left and the `0x87` reduction is applied when the high
/// word's top bit was set.
fn double_tweak(t: &mut [u8; 16]) {
    let mut w0 = read_le_u64(&t[0..8]);
    let mut w1 = read_le_u64(&t[8..16]);
    let res = if (w1 >> 63) & 1 == 1 { 0x87u64 } else { 0 };
    let carry = w0 >> 63;
    w0 = (w0 << 1) ^ res;
    w1 = (w1 << 1) | carry;
    t[0..8].copy_from_slice(&w0.to_le_bytes());
    t[8..16].copy_from_slice(&w1.to_le_bytes());
}

fn read_le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// `int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx, const unsigned char iv[16], const
/// unsigned char *inp, unsigned char *out, size_t len, int enc)` —
/// `crypto/modes/xts128.c:23-161`.
///
/// # Safety
/// `ctx` points at a caller-populated context whose four fields are live, `iv` is readable for
/// sixteen bytes, and `inp`/`out` are as the caller's contract requires for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_xts128_encrypt(
    ctx: *const XtsCtx,
    iv: *const u8,
    inp: *const u8,
    out: *mut u8,
    len: usize,
    enc: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut len = len;
        if len < 16 {
            return -1;
        }

        let block1 = (*ctx).block1;
        let block2 = (*ctx).block2;
        let key1 = (*ctx).key1.cast_const();
        let key2 = (*ctx).key2.cast_const();

        let mut tweak = [0u8; 16];
        ptr::copy_nonoverlapping(iv, tweak.as_mut_ptr(), 16);
        if let Some(f) = block2 {
            f(tweak.as_ptr(), tweak.as_mut_ptr(), key2);
        }

        let mut inp = inp;
        let mut out = out;
        if enc == 0 && !len.is_multiple_of(16) {
            len -= 16;
        }

        let mut scratch = [0u8; 16];
        while len >= 16 {
            scratch.copy_from_slice(core::slice::from_raw_parts(inp, 16));
            xor16(&mut scratch, &tweak);
            if let Some(f) = block1 {
                f(scratch.as_ptr(), scratch.as_mut_ptr(), key1);
            }
            xor16(&mut scratch, &tweak);
            ptr::copy_nonoverlapping(scratch.as_ptr(), out, 16);

            inp = inp.add(16);
            out = out.add(16);
            len -= 16;
            if len == 0 {
                return 0;
            }
            double_tweak(&mut tweak);
        }

        if enc != 0 {
            /* Ciphertext stealing forward: the tail of the output is the stolen prefix of the
             * previous ciphertext, and the mixed block is written back over it. */
            let mut i = 0usize;
            while i < len {
                let c = *inp.add(i);
                *out.add(i) = scratch[i];
                scratch[i] = c;
                i += 1;
            }
            xor16(&mut scratch, &tweak);
            if let Some(f) = block1 {
                f(scratch.as_ptr(), scratch.as_mut_ptr(), key1);
            }
            xor16(&mut scratch, &tweak);
            ptr::copy_nonoverlapping(scratch.as_ptr(), out.sub(16), 16);
        } else {
            /* Ciphertext stealing backward: decrypt the last full block under the doubled tweak,
             * recover the tail, then decrypt the stolen block under the current tweak. */
            let mut tweak1 = tweak;
            double_tweak(&mut tweak1);
            scratch.copy_from_slice(core::slice::from_raw_parts(inp, 16));
            xor16(&mut scratch, &tweak1);
            if let Some(f) = block1 {
                f(scratch.as_ptr(), scratch.as_mut_ptr(), key1);
            }
            xor16(&mut scratch, &tweak1);

            let mut i = 0usize;
            while i < len {
                let c = *inp.add(16 + i);
                *out.add(16 + i) = scratch[i];
                scratch[i] = c;
                i += 1;
            }
            xor16(&mut scratch, &tweak);
            if let Some(f) = block1 {
                f(scratch.as_ptr(), scratch.as_mut_ptr(), key1);
            }
            xor16(&mut scratch, &tweak);
            ptr::copy_nonoverlapping(scratch.as_ptr(), out, 16);
        }

        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key, AesKey};

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

    fn schedule_dec(key: &[u8], bits: c_int) -> AesKey {
        let mut k = AesKey {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(AES_set_decrypt_key(key.as_ptr(), bits, &mut k), 0);
        }
        k
    }

    // SAFETY: forwards its arguments to `AES_encrypt`.
    unsafe extern "C" fn aes_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the caller's contract.
        unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
    }

    // SAFETY: forwards its arguments to `AES_decrypt`.
    unsafe extern "C" fn aes_dec_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the caller's contract.
        unsafe { AES_decrypt(input, out, key.cast::<AesKey>()) }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
            .collect()
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// IEEE Std 1619-2007 vector (`evpciph_aes_common.txt:1081`): two full blocks, so the tweak is
    /// doubled once and no stealing happens.
    #[test]
    fn xts_ieee_two_blocks() {
        let key = unhex("1111111111111111111111111111111122222222222222222222222222222222");
        let iv = unhex("33333333330000000000000000000000");
        let pt = unhex("4444444444444444444444444444444444444444444444444444444444444444");
        let want = "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0";
        // SAFETY: live locals and live schedules.
        unsafe {
            let k1 = schedule(&key[..16], 128);
            let k2 = schedule(&key[16..], 128);
            let dk1 = schedule_dec(&key[..16], 128);
            let ctx = XtsCtx {
                key1: (&k1 as *const AesKey).cast_mut().cast(),
                key2: (&k2 as *const AesKey).cast_mut().cast(),
                block1: Some(aes_block),
                block2: Some(aes_block),
            };
            let mut ct = vec![0u8; pt.len()];
            assert_eq!(
                CRYPTO_xts128_encrypt(&ctx, iv.as_ptr(), pt.as_ptr(), ct.as_mut_ptr(), pt.len(), 1),
                0
            );
            assert_eq!(hex_of(&ct), want);
            // The other direction is the caller's job: `block1` becomes the data cipher's
            // *decrypt* function (`crypto/evp/e_aes.c:303`), while `block2` stays encrypt.
            let dctx = XtsCtx {
                key1: (&dk1 as *const AesKey).cast_mut().cast(),
                key2: (&k2 as *const AesKey).cast_mut().cast(),
                block1: Some(aes_dec_block),
                block2: Some(aes_block),
            };
            let mut back = vec![0u8; pt.len()];
            assert_eq!(
                CRYPTO_xts128_encrypt(
                    &dctx,
                    iv.as_ptr(),
                    ct.as_ptr(),
                    back.as_mut_ptr(),
                    ct.len(),
                    0
                ),
                0
            );
            assert_eq!(hex_of(&back), hex_of(&pt));
        }
    }

    /// IEEE Std 1619-2007 vector (`evpciph_aes_common.txt`): one full block plus one byte, so
    /// both stealing arms are taken.
    #[test]
    fn xts_ieee_ciphertext_stealing() {
        let key = unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
        let iv = unhex("9a785634120000000000000000000000");
        let pt = unhex("000102030405060708090a0b0c0d0e0f10");
        let want = "6c1625db4671522d3d7599601de7ca09ed";
        // SAFETY: live locals and live schedules.
        unsafe {
            let k1 = schedule(&key[..16], 128);
            let k2 = schedule(&key[16..], 128);
            let dk1 = schedule_dec(&key[..16], 128);
            let ctx = XtsCtx {
                key1: (&k1 as *const AesKey).cast_mut().cast(),
                key2: (&k2 as *const AesKey).cast_mut().cast(),
                block1: Some(aes_block),
                block2: Some(aes_block),
            };
            let mut ct = vec![0u8; pt.len()];
            assert_eq!(
                CRYPTO_xts128_encrypt(&ctx, iv.as_ptr(), pt.as_ptr(), ct.as_mut_ptr(), pt.len(), 1),
                0
            );
            assert_eq!(hex_of(&ct), want);
            let dctx = XtsCtx {
                key1: (&dk1 as *const AesKey).cast_mut().cast(),
                key2: (&k2 as *const AesKey).cast_mut().cast(),
                block1: Some(aes_dec_block),
                block2: Some(aes_block),
            };
            let mut back = vec![0u8; pt.len()];
            assert_eq!(
                CRYPTO_xts128_encrypt(
                    &dctx,
                    iv.as_ptr(),
                    ct.as_ptr(),
                    back.as_mut_ptr(),
                    ct.len(),
                    0
                ),
                0
            );
            assert_eq!(hex_of(&back), hex_of(&pt));
        }
    }

    /// A data unit shorter than one block is refused with `-1` and writes nothing.
    #[test]
    fn xts_short_data_unit_is_refused() {
        let key = unhex("1111111111111111111111111111111122222222222222222222222222222222");
        let iv = unhex("33333333330000000000000000000000");
        let pt = [1u8; 15];
        // SAFETY: live locals and live schedules.
        unsafe {
            let k1 = schedule(&key[..16], 128);
            let k2 = schedule(&key[16..], 128);
            let ctx = XtsCtx {
                key1: (&k1 as *const AesKey).cast_mut().cast(),
                key2: (&k2 as *const AesKey).cast_mut().cast(),
                block1: Some(aes_block),
                block2: Some(aes_block),
            };
            let mut out = [0u8; 15];
            assert_eq!(
                CRYPTO_xts128_encrypt(&ctx, iv.as_ptr(), pt.as_ptr(), out.as_mut_ptr(), 15, 1),
                -1
            );
        }
    }
}
