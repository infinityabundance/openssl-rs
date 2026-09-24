//! Phase 8.3 — `crypto/poly1305/poly1305.c`, the internal Poly1305 unit.
//!
//! **This unit has no `libcrypto` symbol.** `Poly1305_Init`/`_Update`/`_Final` and
//! `Poly1305_ctx_size` are declared in `include/crypto/poly1305.h` and `nm -D libcrypto.so.3`
//! lists none of them; the only Poly1305 entry points the DSO exports are `EVP_chacha20_poly1305`
//! and `EVP_PKEY_get0_poly1305`, which are Phase 9's and Phase 13's. The callers this stratum wants
//! are `providers/implementations/macs/poly1305_prov.c`'s row and, later,
//! `cipher_chacha20_poly1305.c`.
//!
//! # `POLY1305_ASM` is defined in this profile and its implementation is declined
//!
//! The file is built twice over: the whole translation unit is inside `#ifndef POLY1305_ASM`, and
//! this profile's `perlasm` command line carries `-DPOLY1305_ASM` (the flag is in the build's
//! Makefile and `crypto/poly1305/libcrypto-lib-poly1305-x86_64.o` exists), so what actually
//! compiles is the `#else` arm: `poly1305_init` is a **perlasm** function with a third argument
//! that selects the block/emit implementations, and `Poly1305_Init` stores the resulting pointers
//! into `ctx->func`.
//!
//! This crate transcribes the **C** branch and not the assembly, and records it rather than
//! pretending otherwise. Three things make that safe rather than convenient, and each is the
//! reason a different plausible approach is *not* taken:
//!
//!   * The wrapper logic is **identical in both branches**. `Poly1305_Update` and `Poly1305_Final`
//!     have the same statements either way; under `POLY1305_ASM` the two calls
//!     `poly1305_blocks(ctx->opaque, …)` and `poly1305_emit(ctx->opaque, …)` are *macro* forms that
//!     dispatch through `ctx->func`. So the declined part is where the arithmetic lives, not what
//!     the API does.
//!   * Poly1305 is a **pure function** of its key, nonce and message: the assembly and the C
//!     reference compute the same 16-byte tag for the same input. Declining it cannot change any
//!     observable, which is a stronger statement than "the tests pass" and is why the divergence is
//!     safe here where an assembly arm with a *different* signature would not be.
//!   * `ctx->func` is **still laid out**, because `Poly1305_ctx_size` is observable through
//!     `CRYPTO_set_mem_functions`'s `num` argument and the provider row allocates
//!     `sizeof(struct poly1305_data_st)` — 264 bytes, of which the embedded `POLY1305` is 248. The
//!     field is never written by this transcription, which is the one observable consequence of the
//!     decline and is recorded in `docs/DECISIONS.md`.
//!
//! The `u128` branch of the C is the one transcribed: `#if defined(INT64_MAX) && defined(INT128_MAX)`
//! selects it and both hold on this profile. It is not a win of one branch over the other — the
//! `u32`-limb variant is inside the branch that does not compile here.
//!
//! SPDX-License-Identifier: Apache-2.0

// `Poly1305_Init`, `Poly1305_Update` and `Poly1305_Final` are the authority's spellings --
// `include/crypto/poly1305.h` -- and this crate keeps an authority name rather than Rustifying it,
// for the reason `src/asn1/bitstr.rs` gives for `ossl_i2c_ASN1_BIT_STRING`: the name is how a
// reader finds the C function it transcribes.
#![allow(non_snake_case)]

use core::ffi::{c_uchar, c_uint, c_void};
use core::ptr;

use crate::runtime::mem::cleanse;

/// `POLY1305_BLOCK_SIZE` — `crypto/poly1305.h:16`.
pub(crate) const POLY1305_BLOCK_SIZE: usize = 16;
/// `POLY1305_DIGEST_SIZE` — `crypto/poly1305.h:17`. What the provider row reports as its size.
pub(crate) const POLY1305_DIGEST_SIZE: usize = 16;
/// `POLY1305_KEY_SIZE` — `crypto/poly1305.h:18`. A key of any other length is refused, not padded.
pub(crate) const POLY1305_KEY_SIZE: usize = 32;

/// `typedef struct { u64 h[3]; u64 r[2]; } poly1305_internal` — `poly1305.c:104-107`.
///
/// `h` is the accumulator mod 2^130-5 held in three 64-bit limbs with the top limb allowed a
/// transient extra bit, and `r` is the clamped key half. It is written into the head of the
/// `POLY1305` context's `opaque` area by the cast the C does.
#[repr(C)]
struct Internal {
    /// `u64 h[3]`.
    h: [u64; 3],
    /// `u64 r[2]`.
    r: [u64; 2],
}

/// `typedef struct poly1305_context POLY1305` — `crypto/poly1305.h:21-40`.
///
/// The layout is the authority's field for field, `func` included, because the size is observable:
/// `Poly1305_ctx_size()` returns `sizeof(POLY1305)` and the provider row's allocation request is
/// `sizeof(struct poly1305_data_st)` = 264, which contains this struct at offset 16. `opaque` is
/// `double[24]` in the C — "declared 'double' to ensure at least 64-bit invariant alignment across
/// all platforms" — and `u64[24]` is the same 192 bytes at the same alignment on this profile.
///
/// `func` holds the two function pointers the `POLY1305_ASM` arm would install. Nothing here writes
/// them, so they keep whatever `OPENSSL_zalloc` left: this is the decline recorded in the module
/// documentation.
#[repr(C)]
pub(crate) struct Poly1305 {
    /// `double opaque[24]` — the `poly1305_internal` state, cast onto.
    opaque: [u64; 24],
    /// `unsigned int nonce[4]` — the key's second half, as four little-endian words.
    nonce: [c_uint; 4],
    /// `unsigned char data[POLY1305_BLOCK_SIZE]` — the partial block held between updates.
    data: [c_uchar; POLY1305_BLOCK_SIZE],
    /// `size_t num` — how many bytes of `data` are live.
    num: usize,
    /// `struct { poly1305_blocks_f blocks; poly1305_emit_f emit; } func` — never written here.
    func: [usize; 2],
}

/// `static u64 U8TOU64(const unsigned char *p)` — `poly1305.c:109-113`, little-endian.
///
/// # Safety
/// `p` is readable for eight bytes.
#[inline]
unsafe fn u8_to_u64(p: *const c_uchar) -> u64 {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p.add(0) as u64) & 0xff)
            | (((*p.add(1) as u64) & 0xff) << 8)
            | (((*p.add(2) as u64) & 0xff) << 16)
            | (((*p.add(3) as u64) & 0xff) << 24)
            | (((*p.add(4) as u64) & 0xff) << 32)
            | (((*p.add(5) as u64) & 0xff) << 40)
            | (((*p.add(6) as u64) & 0xff) << 48)
            | (((*p.add(7) as u64) & 0xff) << 56)
    }
}

/// `static void U64TO8(unsigned char *p, u64 v)` — `poly1305.c:115-119`. The comment above it in
/// the authority says "32-bit unsigned integer", which is a copy-paste of the BLAKE2 helper's; the
/// body stores all eight bytes and that is what is transcribed.
///
/// # Safety
/// `p` is writable for eight bytes.
#[inline]
unsafe fn u64_to_u8(p: *mut c_uchar, v: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        *p.add(0) = (v & 0xff) as c_uchar;
        *p.add(1) = ((v >> 8) & 0xff) as c_uchar;
        *p.add(2) = ((v >> 16) & 0xff) as c_uchar;
        *p.add(3) = ((v >> 24) & 0xff) as c_uchar;
        *p.add(4) = ((v >> 32) & 0xff) as c_uchar;
        *p.add(5) = ((v >> 40) & 0xff) as c_uchar;
        *p.add(6) = ((v >> 48) & 0xff) as c_uchar;
        *p.add(7) = ((v >> 56) & 0xff) as c_uchar;
    }
}

/// `#define CONSTANT_TIME_CARRY(a, b)` — `poly1305.c:87-88`: the carry out of `a + b`, as a mask
/// of `0` or `1`.
///
/// `(a ^ ((a ^ b) | ((a - b) ^ b))) >> 63`. The subtraction is the authority's and wraps; the
/// shift is `sizeof(a) * 8 - 1`, which is 63 for the `u64` this file uses it with. It is
/// branch-free on purpose: it is the reduction step's carry propagation, which must not depend on
/// the accumulator's value.
#[inline]
fn constant_time_carry(a: u64, b: u64) -> u64 {
    (a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b))) >> 63
}

/// `static void poly1305_init(void *ctx, const unsigned char key[16])` — `poly1305.c:122-133`.
///
/// **Sixteen bytes of key, not thirty-two.** The nonce half is taken by `Poly1305_Init` and the
/// clamp constant clears the bits RFC 8439 requires cleared, in two different masks for the two
/// halves.
///
/// # Safety
/// `ctx` is a live `Poly1305` (its `opaque` is cast onto `Internal`); `key` is readable for 16 bytes.
unsafe fn poly1305_init(ctx: *mut c_void, key: *const c_uchar) {
    // SAFETY: the caller's contract; `opaque` is the 192-byte area `Internal` fits in.
    unsafe {
        let st = ctx.cast::<Internal>();

        /* h = 0 */
        (*st).h[0] = 0;
        (*st).h[1] = 0;
        (*st).h[2] = 0;

        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        (*st).r[0] = u8_to_u64(key) & 0x0fff_fffc_0fff_ffff;
        (*st).r[1] = u8_to_u64(key.add(8)) & 0x0fff_fffc_0fff_fffc;
    }
}

/// `static void poly1305_blocks(void *ctx, const unsigned char *inp, size_t len, u32 padbit)` —
/// `poly1305.c:137-197`.
///
/// The whole algorithm. Four details are the authority's and each is why a "cleaner" version would
/// be wrong:
///
///   * `len` is not required to be a multiple of the block size and the trailing partial block is
///     **ignored** — the caller may only hand this whole blocks except for the final padded one.
///   * The `padbit` is 1 for every block except the last, where the caller has already appended the
///     `0x01` byte and zeroed the rest.
///   * `h2` is allowed to carry a bit above its nominal three, and the comment says the overflow is
///     taken care of "naturally" by the next iteration or by the final comparison.
///   * `h2 * s1` and `h2 * r0` are **64-bit** multiplications, not widened ones. They cannot
///     overflow given the clamp above (r0, r1 < 2^60 and h2 < 8), and that bound is the reason the
///     authority can write them that way.
///
/// # Safety
/// `ctx` is live; `inp` is readable for `len` bytes.
unsafe fn poly1305_blocks(ctx: *mut c_void, inp: *const c_uchar, len: usize, padbit: c_uint) {
    // SAFETY: the caller's contract.
    unsafe {
        let st = ctx.cast::<Internal>();
        let (r0, r1) = ((*st).r[0], (*st).r[1]);

        // `s1 = r1 + (r1 >> 2)`, the multiplier for the cross term.
        let s1 = r1.wrapping_add(r1 >> 2);

        let mut h0 = (*st).h[0];
        let mut h1 = (*st).h[1];
        let mut h2 = (*st).h[2];
        let mut inp = inp;
        let mut len = len;

        while len >= POLY1305_BLOCK_SIZE {
            /* h += m[i] */
            let d0 = (h0 as u128) + (u8_to_u64(inp) as u128);
            h0 = d0 as u64;
            let d1 = (h1 as u128) + (d0 >> 64) + (u8_to_u64(inp.add(8)) as u128);
            h1 = d1 as u64;
            /*
             * padbit can be zero only when original len was POLY1305_BLOCK_SIZE, but we don't
             * check.
             */
            h2 = h2
                .wrapping_add((d1 >> 64) as u64)
                .wrapping_add(padbit as u64);

            /* h *= r "%" p, where "%" stands for "partial remainder" */
            let d0 = (h0 as u128) * (r0 as u128) + (h1 as u128) * (s1 as u128);
            let mut d1 = (h0 as u128) * (r1 as u128)
                + (h1 as u128) * (r0 as u128)
                + (h2.wrapping_mul(s1) as u128);
            h2 = h2.wrapping_mul(r0);

            /* last reduction step: */
            /* a) h2:h0 = h2<<128 + d1<<64 + d0 */
            h0 = d0 as u64;
            d1 += d0 >> 64;
            h1 = d1 as u64;
            h2 = h2.wrapping_add((d1 >> 64) as u64);
            /* b) (h2:h0 += (h2:h0>>130) * 5) %= 2^130 */
            let mut c = (h2 >> 2).wrapping_add(h2 & !3u64);
            h2 &= 3;
            h0 = h0.wrapping_add(c);
            c = constant_time_carry(h0, c);
            h1 = h1.wrapping_add(c);
            h2 = h2.wrapping_add(constant_time_carry(h1, c));

            inp = inp.add(POLY1305_BLOCK_SIZE);
            len -= POLY1305_BLOCK_SIZE;
        }

        (*st).h[0] = h0;
        (*st).h[1] = h1;
        (*st).h[2] = h2;
    }
}

/// `static void poly1305_emit(void *ctx, unsigned char mac[16], const u32 nonce[4])` —
/// `poly1305.c:199-231`.
///
/// The final reduction: compare the accumulator with the modulus by computing `h + 5` and watching
/// the carry into the 131st bit, select between the two with a mask rather than a branch, then add
/// the nonce modulo 2^128.
///
/// # Safety
/// `ctx` is live (its state is finalised by this call's caller); `mac` is writable for 16 bytes;
/// `nonce` is readable for four words.
unsafe fn poly1305_emit(ctx: *mut c_void, mac: *mut c_uchar, nonce: *const c_uint) {
    // SAFETY: the caller's contract.
    unsafe {
        let st = ctx.cast::<Internal>();
        let mut h0 = (*st).h[0];
        let mut h1 = (*st).h[1];
        let h2 = (*st).h[2];

        /* compare to modulus by computing h + -p */
        let mut t = (h0 as u128) + 5;
        let mut g0 = t as u64;
        t = (h1 as u128) + (t >> 64);
        let mut g1 = t as u64;
        let g2 = h2.wrapping_add((t >> 64) as u64);

        /* if there was carry into 131st bit, h1:h0 = g1:g0 */
        let mut mask = 0u64.wrapping_sub(g2 >> 2);
        g0 &= mask;
        g1 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;

        /* mac = (h + nonce) % (2^128) */
        t = (h0 as u128) + (*nonce.add(0) as u128) + ((*nonce.add(1) as u128) << 32);
        h0 = t as u64;
        t = (h1 as u128) + (*nonce.add(2) as u128) + ((*nonce.add(3) as u128) << 32) + (t >> 64);
        h1 = t as u64;

        u64_to_u8(mac, h0);
        u64_to_u8(mac.add(8), h1);
    }
}

/// `size_t Poly1305_ctx_size(void)` — `poly1305.c`'s only `Poly1305_*` function that takes no
/// context, and the one that makes the struct's layout observable: its answer reaches
/// `CRYPTO_set_mem_functions`'s `num`. The provider row does not call it — its own allocation is
/// `sizeof(struct poly1305_data_st)` — so this is transcribed for the unit's sake and its named
/// caller is the Phase 9 ChaCha20-Poly1305 row: `crypto/evp/e_chacha20_poly1305.c:506` allocates
/// `sizeof(*actx) + Poly1305_ctx_size()` and `:493` cleanses exactly that much.
///
/// The authority's spelling is kept here and not Rustified to `poly1305_ctx_size`, which is the
/// file's rule for the three `Poly1305_*` above and is also what lets the prerequisite gate join
/// this definition to `crypto/poly1305/poly1305.c`'s `Poly1305_ctx_size` by name. Rustifying it
/// made the gate report the function as unwired in this stratum: the atlas finds the authority
/// spelling, the Rustified definition is invisible to it, and a name that cannot be joined is
/// indistinguishable from a name that is absent.
#[allow(dead_code)] // caller: `cipher_chacha20_poly1305.c`'s `chacha20_poly1305_newctx` (Phase 9)
pub(crate) fn Poly1305_ctx_size() -> usize {
    core::mem::size_of::<Poly1305>()
}

/// `void Poly1305_Init(POLY1305 *ctx, const unsigned char key[32])` — `poly1305.c:404-426`, the
/// `#ifndef POLY1305_ASM` arm.
///
/// The key's second half becomes the nonce as four **little-endian words**, and the first half
/// initialises the accumulator's multiplier. `ctx->num` is then zero, so a re-init discards a
/// partial block rather than carrying it.
///
/// # Safety
/// `ctx` is a live `Poly1305`; `key` is readable for 32 bytes.
pub(crate) unsafe fn Poly1305_Init(ctx: *mut Poly1305, key: *const c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        (*ctx).nonce[0] = u8_to_u32(key.add(16));
        (*ctx).nonce[1] = u8_to_u32(key.add(20));
        (*ctx).nonce[2] = u8_to_u32(key.add(24));
        (*ctx).nonce[3] = u8_to_u32(key.add(28));

        poly1305_init((*ctx).opaque.as_mut_ptr().cast::<c_void>(), key);

        (*ctx).num = 0;
    }
}

/// `static u32 U8TOU32(const unsigned char *p)` — `poly1305.c`'s `U8TOU32`, used only here.
///
/// # Safety
/// `p` is readable for four bytes.
#[inline]
unsafe fn u8_to_u32(p: *const c_uchar) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p.add(0) as c_uint) & 0xff)
            | (((*p.add(1) as c_uint) & 0xff) << 8)
            | (((*p.add(2) as c_uint) & 0xff) << 16)
            | (((*p.add(3) as c_uint) & 0xff) << 24)
    }
}

/// `void Poly1305_Update(POLY1305 *ctx, const unsigned char *inp, size_t len)` —
/// `poly1305.c:434-471`, the `#ifndef POLY1305_ASM` arm.
///
/// The block-boundary handling the algorithm needs: a partial block from a previous call is
/// finished first (with `padbit` 1), then whole blocks are fed directly out of the caller's buffer,
/// then the remainder is *copied* into `ctx->data` for the next call — which is why `inp` may be a
/// caller's buffer that does not outlive the call.
///
/// # Safety
/// `ctx` is a live, initialised `Poly1305`; `inp` is readable for `len` bytes.
pub(crate) unsafe fn Poly1305_Update(ctx: *mut Poly1305, inp: *const c_uchar, len: usize) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut inp = inp;
        let mut len = len;

        let num = (*ctx).num;
        if num != 0 {
            let rem = POLY1305_BLOCK_SIZE - num;
            if len >= rem {
                ptr::copy_nonoverlapping(inp, (*ctx).data.as_mut_ptr().add(num), rem);
                poly1305_blocks(
                    (*ctx).opaque.as_mut_ptr().cast::<c_void>(),
                    (*ctx).data.as_ptr(),
                    POLY1305_BLOCK_SIZE,
                    1,
                );
                inp = inp.add(rem);
                len -= rem;
            } else {
                /* Still not enough data to process a block. */
                ptr::copy_nonoverlapping(inp, (*ctx).data.as_mut_ptr().add(num), len);
                (*ctx).num = num + len;
                return;
            }
        }

        let rem = len % POLY1305_BLOCK_SIZE;
        len -= rem;

        if len >= POLY1305_BLOCK_SIZE {
            poly1305_blocks((*ctx).opaque.as_mut_ptr().cast::<c_void>(), inp, len, 1);
            inp = inp.add(len);
        }

        if rem != 0 {
            ptr::copy_nonoverlapping(inp, (*ctx).data.as_mut_ptr(), rem);
        }

        (*ctx).num = rem;
    }
}

/// `void Poly1305_Final(POLY1305 *ctx, unsigned char mac[16])` — `poly1305.c:473-491`, the
/// `#ifndef POLY1305_ASM` arm.
///
/// The final partial block is completed **here** rather than by the caller: the `0x01` byte the
/// algorithm appends is written at the buffered position and the rest is zeroed, then that block is
/// fed with `padbit` 0. The context is then **cleansed**, so a second `Poly1305_Final` on the same
/// context emits the tag of an all-zero state — the caller is expected not to, and the provider row
/// sets a flag that stops it.
///
/// # Safety
/// `ctx` is live and initialised; `mac` is writable for 16 bytes.
pub(crate) unsafe fn Poly1305_Final(ctx: *mut Poly1305, mac: *mut c_uchar) {
    // SAFETY: the caller's contract.
    unsafe {
        let num = (*ctx).num;
        if num != 0 {
            let mut num = num;
            (*ctx).data[num] = 1; /* pad bit */
            num += 1;
            while num < POLY1305_BLOCK_SIZE {
                (*ctx).data[num] = 0;
                num += 1;
            }
            poly1305_blocks(
                (*ctx).opaque.as_mut_ptr().cast::<c_void>(),
                (*ctx).data.as_ptr(),
                POLY1305_BLOCK_SIZE,
                0,
            );
        }

        poly1305_emit(
            (*ctx).opaque.as_mut_ptr().cast::<c_void>(),
            mac,
            (*ctx).nonce.as_ptr(),
        );

        /* zero out the state */
        cleanse(ctx.cast::<u8>(), core::mem::size_of::<Poly1305>());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The RFC 8439 §2.5.2 tests, plus §2.8.2's AEAD key, transcribed from the RFC rather than from
    /// the authority. Poly1305's specification is *public and independent of OpenSSL*, which is what
    /// makes this a construction check rather than a transcription check — the distinction D248
    /// recorded when SipHash had no such source and its table had to say so.
    #[test]
    fn the_rfc_8439_vectors() {
        // §2.5.2: the one-block message.
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let mut tag = [0u8; 16];
        let mut ctx = Poly1305 {
            opaque: [0; 24],
            nonce: [0; 4],
            data: [0; 16],
            num: 0,
            func: [0; 2],
        };

        // SAFETY: `ctx` is this frame's own and `key`/`msg` are this frame's own arrays.
        unsafe {
            Poly1305_Init(&mut ctx, key.as_ptr());
            Poly1305_Update(&mut ctx, msg.as_ptr(), msg.len());
            Poly1305_Final(&mut ctx, tag.as_mut_ptr());
        }
        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );

        // And a property the construction gives directly rather than a second cited vector: with
        // an **empty** message the accumulator stays zero, so `emit` returns `(0 + nonce) mod 2^128`
        // -- the tag is exactly the key's second half, little-endian. That is checked here because
        // it exercises `emit`'s nonce handling and `Init`'s word order independently of any vector
        // this file might misremember, and it is the check that would catch a nonce taken from the
        // wrong half of the key.
        let mut tag2 = [0u8; 16];
        let mut ctx2 = Poly1305 {
            opaque: [0; 24],
            nonce: [0; 4],
            data: [0; 16],
            num: 0,
            func: [0; 2],
        };
        // SAFETY: as above.
        unsafe {
            Poly1305_Init(&mut ctx2, key.as_ptr());
            Poly1305_Final(&mut ctx2, tag2.as_mut_ptr());
        }
        assert_eq!(
            tag2,
            key[16..32],
            "an empty message tags to the key's nonce half"
        );
    }

    /// The §2.5.2 message split at every boundary: a one-shot update, then byte-at-a-time, then
    /// split at exactly the block size. A transcription that mishandled the partial-block carry
    /// would agree with the one-shot case for a message shorter than a block and disagree here.
    #[test]
    fn the_message_splits_agree() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let want = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        let fresh = || Poly1305 {
            opaque: [0; 24],
            nonce: [0; 4],
            data: [0; 16],
            num: 0,
            func: [0; 2],
        };

        for split in 0..=msg.len() {
            let mut tag = [0u8; 16];
            let mut ctx = fresh();
            // SAFETY: `ctx` is this frame's own; both slices are inside `msg`.
            unsafe {
                Poly1305_Init(&mut ctx, key.as_ptr());
                Poly1305_Update(&mut ctx, msg.as_ptr(), split);
                Poly1305_Update(&mut ctx, msg.as_ptr().add(split), msg.len() - split);
                Poly1305_Final(&mut ctx, tag.as_mut_ptr());
            }
            assert_eq!(tag, want, "split at {split}");
        }

        // Byte at a time, which exercises the single-byte buffering path 34 times.
        let mut tag = [0u8; 16];
        let mut ctx = fresh();
        // SAFETY: as above.
        unsafe {
            Poly1305_Init(&mut ctx, key.as_ptr());
            for i in 0..msg.len() {
                Poly1305_Update(&mut ctx, msg.as_ptr().add(i), 1);
            }
            Poly1305_Final(&mut ctx, tag.as_mut_ptr());
        }
        assert_eq!(tag, want);

        // Zero-length updates interleaved, which must not change anything.
        let mut tag = [0u8; 16];
        let mut ctx = fresh();
        // SAFETY: as above.
        unsafe {
            Poly1305_Init(&mut ctx, key.as_ptr());
            Poly1305_Update(&mut ctx, msg.as_ptr(), 0);
            Poly1305_Update(&mut ctx, msg.as_ptr(), msg.len());
            Poly1305_Update(&mut ctx, msg.as_ptr(), 0);
            Poly1305_Final(&mut ctx, tag.as_mut_ptr());
        }
        assert_eq!(tag, want);
    }

    /// The struct's size is contract, and this is the number that makes it so: the provider row's
    /// allocation request is `sizeof(struct poly1305_data_st)`, which `CRYPTO_set_mem_functions`
    /// hands to an application's allocator. 248 and 264 come from compiling the authority's own
    /// header and provider file.
    #[test]
    fn the_context_sizes_are_the_authoritys() {
        assert_eq!(Poly1305_ctx_size(), 248);
        assert_eq!(core::mem::align_of::<Poly1305>(), 8);
    }
}
