//! Phase 8.3 — CCM (`crypto/modes/ccm128.c`), the eight `CRYPTO_ccm128_*` exports.
//!
//! ## What is transcribed
//!
//! CCM is not a dispatch shell the way GCM is: `ccm128.c` computes everything itself and its only
//! caller-supplied acceleration is the `ccm128_f` stream that `_encrypt_ccm64`/`_decrypt_ccm64`
//! use for their full blocks. So the whole file is transcribed, including the two static counter
//! helpers, which keep the authority's names (`ctr64_inc`, `ctr64_add`) so that
//! `prerequisite_gate.py` sees the unit's internal surface wired.
//!
//! The substance is the observable state machine, and the trap the plan names is the first line
//! of it: **the message length is fixed before the AAD**. `CRYPTO_ccm128_setiv` stores `mlen`
//! into the last `L+1` octets of the B0 block, and `CRYPTO_ccm128_encrypt`/`_decrypt` refuse with
//! `-1` unless the length they reconstruct from those octets equals `len`. There is no way to
//! stream a message of unknown length: a caller that calls `setiv` with one length and `encrypt`
//! with another gets the refusal, not a truncated result. That is why the probe drives each
//! message through a fresh `init`/`setiv`/`aad`/`encrypt` sequence and observes both the refusal
//! and the accept.
//!
//! Other exact behaviours kept:
//!
//! * `init`'s B0 flags: `((L-1)&7) | (((M-2)/2)&7)<<3`, with `M` the tag length in octets — so
//!   `M` must be even and in `[4,16]`, and `L` in `[2,8]` gives a nonce of `15-L` octets;
//! * the three AAD length encodings (`< 0xff00` two octets, `>= 2^32` ten octets, else six);
//! * `aad` is a no-op for `alen == 0` and does **not** set the Adata flag in that case;
//! * the `blocks` accounting is asymmetric on purpose: `encrypt` adds
//!   `((len+15)>>3)|1` and refuses past `2^61` with `-2`, while `decrypt` never touches
//!   `blocks` at all. That is the authority's, and the tuple court can see it (a decrypt after
//!   an encrypt does not move the counter);
//! * `tag`'s answer is `M` only when `len == M`, and `0` otherwise — the caller compares.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint, c_void};
use core::ptr;

use crate::modes::{Block128F, Ccm128F};

/// `ccm128_context` — `include/crypto/modes.h:159-167`. The layout is this crate's, because the
/// type is opaque to every caller: the public header only forward-declares it.
#[repr(C)]
pub struct CcmCtx {
    /// `nonce` — the B0 block, built by `init`/`setiv`/`aad`.
    nonce: [u8; 16],
    /// `cmac` — the CBC-MAC accumulator.
    cmac: [u8; 16],
    /// `blocks` — the authority's 61-bit block budget.
    blocks: u64,
    /// `block` — the caller's block cipher.
    block: Option<Block128F>,
    /// `key` — the caller's key schedule.
    key: *mut c_void,
}

impl CcmCtx {
    /// Re-point `key` at a caller's schedule.
    ///
    /// The one writer outside this module is the provider's CCM `dupctx`
    /// (`cipher_aes_ccm.c:54`): a shallow copy of a `PROV_AES_CCM_CTX` carries the *original's*
    /// key pointer, and the authority repairs it to the copy's own `AES_KEY` before returning.
    /// The field stays private so that repair is the only way in.
    pub(crate) fn repoint_key(&mut self, key: *mut c_void) {
        self.key = key;
    }
}

/// `static void ctr64_inc(unsigned char *counter)` — `crypto/modes/ccm128.c:121-135`: increment
/// the low sixty-four bits of the sixteen-byte `nonce`.
///
/// # Safety
/// `counter` points to a live sixteen-byte block.
unsafe fn ctr64_inc(counter: *mut u8) {
    // SAFETY: the caller passes a live sixteen-byte counter; the index stays within it.
    unsafe {
        let mut n: usize = 8;
        loop {
            n -= 1;
            let c = counter.add(8).add(n).read().wrapping_add(1);
            counter.add(8).add(n).write(c);
            if c != 0 {
                return;
            }
            if n == 0 {
                return;
            }
        }
    }
}

/// `static void ctr64_add(unsigned char *counter, size_t inc)` — `crypto/modes/ccm128.c:296-308`.
///
/// # Safety
/// `counter` points to a live sixteen-byte block.
unsafe fn ctr64_add(counter: *mut u8, inc: usize) {
    // SAFETY: the caller passes a live sixteen-byte counter; the index stays within it.
    unsafe {
        let mut n: usize = 8;
        let mut val: usize = 0;
        let mut inc = inc;
        loop {
            n -= 1;
            val += counter.add(8).add(n).read() as usize + (inc & 0xff);
            counter.add(8).add(n).write(val as u8);
            val >>= 8;
            inc >>= 8;
            if n == 0 || (inc == 0 && val == 0) {
                return;
            }
        }
    }
}

/// The block call, as a small helper so the four bodies read like the authority's.
///
/// # Safety
/// `ctx` is live; `input` and `out` are the block function's own contract.
unsafe fn block_call(ctx: *mut CcmCtx, input: *const u8, out: *mut u8) {
    // SAFETY: the caller's contract.
    unsafe {
        if let Some(f) = (*ctx).block {
            f(input, out, (*ctx).key);
        }
    }
}

/// `void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned int M, unsigned int L, void *key,
/// block128_f block)` — `crypto/modes/ccm128.c:26-35`.
///
/// # Safety
/// `ctx` is a live, writable context; `block`/`key` are the caller's cipher and schedule.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_init(
    ctx: *mut CcmCtx,
    m: c_uint,
    l: c_uint,
    key: *mut c_void,
    block: Block128F,
) {
    // SAFETY: the caller's contract; the whole struct is this crate's own layout.
    unsafe {
        (*ctx).nonce = [0u8; 16];
        (*ctx).nonce[0] =
            (l.wrapping_sub(1) & 7) as u8 | (((m.wrapping_sub(2) / 2) & 7) as u8) << 3;
        (*ctx).blocks = 0;
        (*ctx).block = Some(block);
        (*ctx).key = key;
    }
}

/// `int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce, size_t nlen,
/// size_t mlen)` — `crypto/modes/ccm128.c:40-65`.
///
/// # Safety
/// `ctx` is live and `nonce` readable for `nlen` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_setiv(
    ctx: *mut CcmCtx,
    nonce: *const u8,
    nlen: usize,
    mlen: usize,
) -> c_int {
    // SAFETY: the caller's contract, plus the length check below.
    unsafe {
        let l: usize = ((*ctx).nonce[0] & 7) as usize;

        if nlen < (14 - l) {
            return -1; /* nonce is too short */
        }

        if core::mem::size_of::<usize>() == 8 && l >= 3 {
            (*ctx).nonce[8] = (mlen >> 56) as u8;
            (*ctx).nonce[9] = (mlen >> 48) as u8;
            (*ctx).nonce[10] = (mlen >> 40) as u8;
            (*ctx).nonce[11] = (mlen >> 32) as u8;
        } else {
            for i in 8..16 {
                (*ctx).nonce[i] = 0;
            }
        }

        (*ctx).nonce[12] = (mlen >> 24) as u8;
        (*ctx).nonce[13] = (mlen >> 16) as u8;
        (*ctx).nonce[14] = (mlen >> 8) as u8;
        (*ctx).nonce[15] = mlen as u8;

        (*ctx).nonce[0] &= !0x40; /* clear Adata flag */
        ptr::copy_nonoverlapping(nonce, (*ctx).nonce.as_mut_ptr().add(1), 14 - l);

        0
    }
}

/// `void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const unsigned char *aad, size_t alen)` —
/// `crypto/modes/ccm128.c:68-113`.
///
/// # Safety
/// `ctx` is live and `aad` readable for `alen` bytes (or NULL when `alen == 0`).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_aad(ctx: *mut CcmCtx, aad: *const u8, alen: usize) {
    // SAFETY: the caller's contract.
    unsafe {
        if alen == 0 {
            return;
        }

        (*ctx).nonce[0] |= 0x40; /* set Adata flag */
        block_call(ctx, (*ctx).nonce.as_ptr(), (*ctx).cmac.as_mut_ptr());
        (*ctx).blocks = (*ctx).blocks.wrapping_add(1);

        let mut i: usize;
        if alen < (0x10000 - 0x100) {
            (*ctx).cmac[0] ^= (alen >> 8) as u8;
            (*ctx).cmac[1] ^= alen as u8;
            i = 2;
        } else if core::mem::size_of::<usize>() == 8 && alen >= (1usize << 32) {
            (*ctx).cmac[0] ^= 0xFF;
            (*ctx).cmac[1] ^= 0xFF;
            (*ctx).cmac[2] ^= (alen >> 56) as u8;
            (*ctx).cmac[3] ^= (alen >> 48) as u8;
            (*ctx).cmac[4] ^= (alen >> 40) as u8;
            (*ctx).cmac[5] ^= (alen >> 32) as u8;
            (*ctx).cmac[6] ^= (alen >> 24) as u8;
            (*ctx).cmac[7] ^= (alen >> 16) as u8;
            (*ctx).cmac[8] ^= (alen >> 8) as u8;
            (*ctx).cmac[9] ^= alen as u8;
            i = 10;
        } else {
            (*ctx).cmac[0] ^= 0xFF;
            (*ctx).cmac[1] ^= 0xFE;
            (*ctx).cmac[2] ^= (alen >> 24) as u8;
            (*ctx).cmac[3] ^= (alen >> 16) as u8;
            (*ctx).cmac[4] ^= (alen >> 8) as u8;
            (*ctx).cmac[5] ^= alen as u8;
            i = 6;
        }

        let mut p = aad;
        let mut remaining = alen;
        loop {
            while i < 16 && remaining != 0 {
                (*ctx).cmac[i] ^= *p;
                i += 1;
                p = p.add(1);
                remaining -= 1;
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
            (*ctx).blocks = (*ctx).blocks.wrapping_add(1);
            i = 0;
            if remaining == 0 {
                break;
            }
        }
    }
}

/// The shared prologue of the four message bodies: clear the Adata flag path, reconstruct the
/// length, and answer the refusal codes. `stats` selects whether `encrypt`'s `blocks` accounting
/// runs (the authority adds it in the two encrypt bodies and not in the two decrypt bodies).
///
/// # Safety
/// `ctx` is live.
unsafe fn ccm_start(ctx: *mut CcmCtx, len: usize, stats: bool) -> Result<(u8, usize), c_int> {
    // SAFETY: the caller's contract.
    unsafe {
        let flags0 = (*ctx).nonce[0];
        if flags0 & 0x40 == 0 {
            block_call(ctx, (*ctx).nonce.as_ptr(), (*ctx).cmac.as_mut_ptr());
            if stats {
                (*ctx).blocks = (*ctx).blocks.wrapping_add(1);
            }
        }

        let l: usize = (flags0 & 7) as usize;
        (*ctx).nonce[0] = l as u8;

        let mut n: usize = 0;
        let mut i = 15 - l;
        while i < 15 {
            n |= (*ctx).nonce[i] as usize;
            (*ctx).nonce[i] = 0;
            n <<= 8;
            i += 1;
        }
        n |= (*ctx).nonce[15] as usize; /* reconstructed length */
        (*ctx).nonce[15] = 1;

        if n != len {
            return Err(-1); /* length mismatch */
        }

        if stats {
            (*ctx).blocks = (*ctx)
                .blocks
                .wrapping_add((((len as u64).wrapping_add(15)) >> 3) | 1);
            if (*ctx).blocks > (1u64 << 61) {
                return Err(-2); /* too much data */
            }
        }

        Ok((flags0, l))
    }
}

/// The shared epilogue: zero the counter field, fold the final counter block into the MAC, and
/// restore the flags byte.
///
/// # Safety
/// `ctx` is live and `flags0`/`l` came from [`ccm_start`].
unsafe fn ccm_finish(ctx: *mut CcmCtx, flags0: u8, l: usize, scratch: &mut [u8; 16]) {
    // SAFETY: the caller's contract.
    unsafe {
        for i in (15 - l)..16 {
            (*ctx).nonce[i] = 0;
        }
        block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
        for (i, s) in scratch.iter().enumerate() {
            (*ctx).cmac[i] ^= *s;
        }
        (*ctx).nonce[0] = flags0;
    }
}

/// `int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const unsigned char *inp, unsigned char *out,
/// size_t len)` — `crypto/modes/ccm128.c:137-219`.
///
/// # Safety
/// `ctx` is live and `inp`/`out` as the caller's contract requires for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_encrypt(
    ctx: *mut CcmCtx,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let (flags0, l) = match ccm_start(ctx, len, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut inp = inp;
        let mut out = out;
        let mut len = len;
        let mut scratch = [0u8; 16];

        while len >= 16 {
            for i in 0..16 {
                (*ctx).cmac[i] ^= *inp.add(i);
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            ctr64_inc((*ctx).nonce.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate() {
                *out.add(i) = *s ^ *inp.add(i);
            }
            inp = inp.add(16);
            out = out.add(16);
            len -= 16;
        }

        if len != 0 {
            for i in 0..len {
                (*ctx).cmac[i] ^= *inp.add(i);
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate().take(len) {
                *out.add(i) = *s ^ *inp.add(i);
            }
        }

        ccm_finish(ctx, flags0, l, &mut scratch);

        0
    }
}

/// `int CRYPTO_ccm128_decrypt(...)` — `crypto/modes/ccm128.c:221-294`.
///
/// # Safety
/// As [`CRYPTO_ccm128_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_decrypt(
    ctx: *mut CcmCtx,
    inp: *const u8,
    out: *mut u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let (flags0, l) = match ccm_start(ctx, len, false) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut inp = inp;
        let mut out = out;
        let mut len = len;
        let mut scratch = [0u8; 16];

        while len >= 16 {
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            ctr64_inc((*ctx).nonce.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate() {
                let c = *s ^ *inp.add(i);
                *out.add(i) = c;
                (*ctx).cmac[i] ^= c;
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
            inp = inp.add(16);
            out = out.add(16);
            len -= 16;
        }

        if len != 0 {
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate().take(len) {
                let c = *s ^ *inp.add(i);
                *out.add(i) = c;
                (*ctx).cmac[i] ^= c;
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
        }

        ccm_finish(ctx, flags0, l, &mut scratch);

        0
    }
}

/// `int CRYPTO_ccm128_encrypt_ccm64(...)` — `crypto/modes/ccm128.c:310-372`. The bulk blocks go
/// through the caller's `ccm128_f`; the remainder and the MAC epilogue are the ordinary path.
///
/// # Safety
/// As [`CRYPTO_ccm128_encrypt`]; `stream` is the caller's own CCM stream.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_encrypt_ccm64(
    ctx: *mut CcmCtx,
    inp: *const u8,
    out: *mut u8,
    len: usize,
    stream: Ccm128F,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let (flags0, l) = match ccm_start(ctx, len, true) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut inp = inp;
        let mut out = out;
        let mut len = len;
        let mut scratch = [0u8; 16];

        let nb = len / 16;
        if nb != 0 {
            stream(
                inp,
                out,
                nb,
                (*ctx).key,
                (*ctx).nonce.as_ptr(),
                (*ctx).cmac.as_mut_ptr(),
            );
            let nbytes = nb * 16;
            inp = inp.add(nbytes);
            out = out.add(nbytes);
            len -= nbytes;
            if len != 0 {
                ctr64_add((*ctx).nonce.as_mut_ptr(), nb);
            }
        }

        if len != 0 {
            for i in 0..len {
                (*ctx).cmac[i] ^= *inp.add(i);
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate().take(len) {
                *out.add(i) = *s ^ *inp.add(i);
            }
        }

        ccm_finish(ctx, flags0, l, &mut scratch);

        0
    }
}

/// `int CRYPTO_ccm128_decrypt_ccm64(...)` — `crypto/modes/ccm128.c:374-430`.
///
/// # Safety
/// As [`CRYPTO_ccm128_decrypt`]; `stream` is the caller's own CCM stream.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_decrypt_ccm64(
    ctx: *mut CcmCtx,
    inp: *const u8,
    out: *mut u8,
    len: usize,
    stream: Ccm128F,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let (flags0, l) = match ccm_start(ctx, len, false) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut inp = inp;
        let mut out = out;
        let mut len = len;
        let mut scratch = [0u8; 16];

        let nb = len / 16;
        if nb != 0 {
            stream(
                inp,
                out,
                nb,
                (*ctx).key,
                (*ctx).nonce.as_ptr(),
                (*ctx).cmac.as_mut_ptr(),
            );
            let nbytes = nb * 16;
            inp = inp.add(nbytes);
            out = out.add(nbytes);
            len -= nbytes;
            if len != 0 {
                ctr64_add((*ctx).nonce.as_mut_ptr(), nb);
            }
        }

        if len != 0 {
            block_call(ctx, (*ctx).nonce.as_ptr(), scratch.as_mut_ptr());
            for (i, s) in scratch.iter().enumerate().take(len) {
                let c = *s ^ *inp.add(i);
                *out.add(i) = c;
                (*ctx).cmac[i] ^= c;
            }
            block_call(ctx, (*ctx).cmac.as_ptr(), (*ctx).cmac.as_mut_ptr());
        }

        ccm_finish(ctx, flags0, l, &mut scratch);

        0
    }
}

/// `size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len)` —
/// `crypto/modes/ccm128.c:432-442`.
///
/// # Safety
/// `ctx` is live and `tag` writable for `min(len, 16)` bytes.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_ccm128_tag(ctx: *mut CcmCtx, tag: *mut u8, len: usize) -> usize {
    // SAFETY: the caller's contract.
    unsafe {
        let mut m: usize = (((*ctx).nonce[0] >> 3) & 7) as usize; /* the M parameter */
        m *= 2;
        m += 2;
        if len != m {
            return 0;
        }
        ptr::copy_nonoverlapping((*ctx).cmac.as_ptr(), tag, m);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{AES_encrypt, AES_set_encrypt_key, AesKey};

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

    // SAFETY: forwards its arguments to `AES_encrypt`.
    unsafe extern "C" fn aes_block(input: *const u8, out: *mut u8, key: *const c_void) {
        // SAFETY: the caller's contract.
        unsafe { AES_encrypt(input, out, key.cast::<AesKey>()) }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0))
            .collect()
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// NIST SP 800-38C CAVS (`evpciph_aes_ccm_cavs.txt:573`): a 7-octet nonce (so `L = 8`), a
    /// 4-octet tag, no AAD, and a 24-octet message.
    #[test]
    fn ccm_cavs_message() {
        let key = unhex("19ebfde2d5468ba0a3031bde629b11fd");
        let nonce = unhex("5a8aa485c316e9");
        let pt = unhex("3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22");
        let want_ct = unhex("a90e8ea44085ced791b2fdb7fd44b5cf0bd7d27718029bb7");
        let want_tag = unhex("03e1fa6b");
        // SAFETY: live locals and a live schedule.
        unsafe {
            let k = schedule(&key, 128);
            let mut ctx = core::mem::zeroed::<CcmCtx>();
            CRYPTO_ccm128_init(
                &mut ctx,
                4,
                8,
                (&k as *const AesKey).cast_mut().cast(),
                aes_block,
            );
            assert_eq!(
                CRYPTO_ccm128_setiv(&mut ctx, nonce.as_ptr(), nonce.len(), pt.len()),
                0
            );
            let mut ct = vec![0u8; pt.len()];
            assert_eq!(
                CRYPTO_ccm128_encrypt(&mut ctx, pt.as_ptr(), ct.as_mut_ptr(), pt.len()),
                0
            );
            assert_eq!(hex_of(&ct), hex_of(&want_ct));
            let mut tag = [0u8; 4];
            assert_eq!(CRYPTO_ccm128_tag(&mut ctx, tag.as_mut_ptr(), 4), 4);
            assert_eq!(hex_of(&tag), hex_of(&want_tag));
        }
    }

    /// NIST SP 800-38C CAVS (`evpciph_aes_ccm_cavs.txt:1133`): AAD only, empty message.
    #[test]
    fn ccm_cavs_aad_only() {
        let key = unhex("90929a4b0ac65b350ad1591611fe4829");
        let nonce = unhex("5a8aa485c316e9");
        let aad = unhex("3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22ec22b1a268f88e2c");
        let want_tag = unhex("782e4318");
        // SAFETY: live locals and a live schedule.
        unsafe {
            let k = schedule(&key, 128);
            let mut ctx = core::mem::zeroed::<CcmCtx>();
            CRYPTO_ccm128_init(
                &mut ctx,
                4,
                8,
                (&k as *const AesKey).cast_mut().cast(),
                aes_block,
            );
            assert_eq!(
                CRYPTO_ccm128_setiv(&mut ctx, nonce.as_ptr(), nonce.len(), 0),
                0
            );
            CRYPTO_ccm128_aad(&mut ctx, aad.as_ptr(), aad.len());
            assert_eq!(
                CRYPTO_ccm128_encrypt(&mut ctx, ptr::null(), ptr::null_mut(), 0),
                0
            );
            let mut tag = [0u8; 4];
            assert_eq!(CRYPTO_ccm128_tag(&mut ctx, tag.as_mut_ptr(), 4), 4);
            assert_eq!(hex_of(&tag), hex_of(&want_tag));
        }
    }

    /// The plan's trap, and the quirk it exposes: the message length is fixed before the AAD, so
    /// a body whose `len` disagrees with `setiv`'s `mlen` is refused with `-1`. The refusal
    /// returns *without restoring* `B0`'s flags byte — `CRYPTO_ccm128_encrypt` sets
    /// `nonce.c[0] = L` before the check — so a subsequent `tag` reads `M` from the cleared bits
    /// as `2` and answers `0` rather than a tag. That is the authority's own behaviour
    /// (bug-compatible), not a divergence, and `RT-CIPHER` observes it directly.
    #[test]
    fn ccm_length_mismatch_is_refused() {
        let key = unhex("19ebfde2d5468ba0a3031bde629b11fd");
        let nonce = unhex("5a8aa485c316e9");
        let pt = [1u8; 16];
        // SAFETY: live locals and a live schedule.
        unsafe {
            let k = schedule(&key, 128);
            let mut ctx = core::mem::zeroed::<CcmCtx>();
            CRYPTO_ccm128_init(
                &mut ctx,
                4,
                8,
                (&k as *const AesKey).cast_mut().cast(),
                aes_block,
            );
            assert_eq!(
                CRYPTO_ccm128_setiv(&mut ctx, nonce.as_ptr(), nonce.len(), 16),
                0
            );
            let mut out = [0u8; 16];
            assert_eq!(
                CRYPTO_ccm128_encrypt(&mut ctx, pt.as_ptr(), out.as_mut_ptr(), 15),
                -1
            );
            assert_eq!(CRYPTO_ccm128_tag(&mut ctx, out.as_mut_ptr(), 4), 0);
        }
    }

    /// A round trip: decrypting the ciphertext with the tag recomputed recovers the plaintext.
    #[test]
    fn ccm_decrypt_round_trip() {
        let key = unhex("19ebfde2d5468ba0a3031bde629b11fd");
        let nonce = unhex("5a8aa485c316e9");
        let pt = unhex("3796cf51b8726652a4204733b8fbb047cf00fb91a9837e22");
        let ct = unhex("a90e8ea44085ced791b2fdb7fd44b5cf0bd7d27718029bb7");
        // SAFETY: live locals and a live schedule.
        unsafe {
            let k = schedule(&key, 128);
            let mut ctx = core::mem::zeroed::<CcmCtx>();
            CRYPTO_ccm128_init(
                &mut ctx,
                4,
                8,
                (&k as *const AesKey).cast_mut().cast(),
                aes_block,
            );
            assert_eq!(
                CRYPTO_ccm128_setiv(&mut ctx, nonce.as_ptr(), nonce.len(), ct.len()),
                0
            );
            let mut back = vec![0u8; ct.len()];
            assert_eq!(
                CRYPTO_ccm128_decrypt(&mut ctx, ct.as_ptr(), back.as_mut_ptr(), ct.len()),
                0
            );
            assert_eq!(hex_of(&back), hex_of(&pt));
            let mut tag = [0u8; 4];
            assert_eq!(CRYPTO_ccm128_tag(&mut ctx, tag.as_mut_ptr(), 4), 4);
            assert_eq!(hex_of(&tag), "03e1fa6b");
        }
    }
}
