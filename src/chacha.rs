//! Phase 8.3 — `crypto/chacha/chacha_enc.c`, the ChaCha20 primitive.
//!
//! **This unit is not compiled in the admitted profile, and `ChaCha20_ctr32` is perlasm.**
//! `crypto/chacha/build.info` starts `$CHACHAASM=chacha_enc.c` under `IF[{- !$disabled{asm} -}]`
//! and then replaces it with the arch-specific list: on x86-64 that is `chacha-x86_64.s` **alone**,
//! and `$CHACHADEF` — the variable that carries `INCLUDE_C_CHACHA20` — is assigned only for
//! `riscv64` (`$CHACHADEF_riscv64=INCLUDE_C_CHACHA20`). So this build has
//! `libcrypto-lib-chacha-x86_64.o` and **no** `libcrypto-lib-chacha_enc.o` at all. The consequence
//! is visible in the crate's own atlases: `forensics/atlas/internal-symbols.json` gives
//! `ChaCha20_ctr32` the translation unit `crypto/chacha/chacha-x86_64.c`, and
//! `translation_units_without_a_source_file` lists it beside `crypto/aes/aes-x86_64.c` and
//! `crypto/rc4/rc4-x86_64.c`.
//!
//! That makes this a **decline of a different kind from D258's**, and the difference is the reason it
//! gets its own paragraph rather than being folded in. For Poly1305 the C file *is* a translation
//! unit and only `poly1305_init` comes from perlasm; the transcription there is of the branch that
//! actually compiles, and the decline is the assembly. Here there is **no compiled C branch to
//! transcribe**: the file defines `ChaCha20_ctr32_c` only under `INCLUDE_C_CHACHA20`, and under
//! `#else` it defines `ChaCha20_ctr32` — the two spellings are the *same body* behind one
//! `#ifdef`, so the file is the specification of the function and not an implementation of it.
//!
//! Three properties make the transcription honest rather than convenient, and each is the reason a
//! different plausible alternative is *not* taken:
//!
//!   * **The file is the authority's own reference implementation of the same function.** It is
//!     "Adapted from the public domain code by D. Bernstein from SUPERCOP", and `chacha-x86_64.pl`
//!     computes the same keystream: the assembly is an optimisation of this body, which is exactly
//!     what the `#ifdef` asserts by naming both spellings of one function.
//!   * **`ChaCha20_ctr32` is a pure function** of its key, counter and input. It has no state, no
//!     allocation and no error path — it cannot fail — so where the arithmetic lives cannot change
//!     any observable. That is a stronger statement than "the tags match", and it is what makes the
//!     decline safe here.
//!   * **Its only observable is bytes.** The caller's buffer is the whole output; there is no
//!     context whose layout could differ and no error queue to leave alone. The Poly1305 decline had
//!     one consequence to record (`ctx->func` stays unwritten, and the *size* is observable through
//!     `CRYPTO_set_mem_functions`); this one has none.
//!
//! **The endianness branch is not declined, because both of its arms are the same bytes.**
//! `chacha20_core` writes the output words with a fast path `output->u[i] = …` under
//! `IS_LITTLE_ENDIAN` and `U32TO8_LITTLE(output->c + 4 * i, …)` otherwise. `U32TO8_LITTLE` is
//! little-endian *by construction*, so the two arms agree byte for byte on every host; this
//! transcription writes `u32::to_le_bytes` unconditionally, which is the same function on this
//! profile and the correct one everywhere. The same holds for `CHACHA_U8TOU32`, whose shifts are
//! little-endian in the header's own text.
//!
//! SPDX-License-Identifier: Apache-2.0

// `ChaCha20_ctr32` is `include/crypto/chacha.h`'s spelling and this file keeps it, for the reason
// `src/mac/poly1305.rs` and `src/asn1/bitstr.rs` give: the name is how the prerequisite gate joins a
// definition to the authority's translation unit, and a name the tooling cannot join is
// indistinguishable from a name that is absent (D259).
#![allow(non_snake_case)]

use core::ffi::{c_uchar, c_uint};

/// `CHACHA_KEY_SIZE` — `include/crypto/chacha.h:43`.
pub(crate) const CHACHA_KEY_SIZE: usize = 32;

/// `CHACHA_CTR_SIZE` — `include/crypto/chacha.h:44`. The *counter block*'s width: thirty-two bits of
/// block counter followed by a twelve-byte nonce, which is `rfc7539`'s layout and **not** the
/// original draft's eight-byte nonce.
pub(crate) const CHACHA_CTR_SIZE: usize = 16;

/// `CHACHA_BLK_SIZE` — `include/crypto/chacha.h:45`.
pub(crate) const CHACHA_BLK_SIZE: usize = 64;

/// `CHACHA_U8TOU32(p)` — `include/crypto/chacha.h:38-39`, little-endian by the shifts themselves.
///
/// `unsafe` because it dereferences the caller's pointer: a safe wrapper doing unsafe reads is how a
/// soundness hole gets introduced, and the crate's rule is that the `unsafe` keyword is where the
/// obligation is.
///
/// # Safety
/// `p` is readable for four bytes.
#[inline]
unsafe fn chacha_u8tou32(p: *const c_uchar) -> c_uint {
    // SAFETY: the caller's contract.
    unsafe {
        ((*p as c_uint) & 0xff)
            | (((*p.add(1) as c_uint) & 0xff) << 8)
            | (((*p.add(2) as c_uint) & 0xff) << 16)
            | (((*p.add(3) as c_uint) & 0xff) << 24)
    }
}

/// `CHACHA_U8TOU32` for a slice, which is how the row's `initkey`/`initiv` spell the same macro over
/// a key or an IV it already holds.
///
/// # Safety
/// `p` is readable for `p.len()` bytes.
#[inline]
pub(crate) unsafe fn u8tou32(p: &[c_uchar]) -> c_uint {
    // SAFETY: the caller's contract; `len >= 4` is the caller's precondition.
    unsafe { chacha_u8tou32(p.as_ptr()) }
}

/// A local index-erased `ROTATE`. The authority's macro is `((v) << (n)) | ((v) >> (32 - (n)))`,
/// which is `rotate_left` exactly; the `#if` group above it substitutes a `roriw`/`rori` inline-asm
/// spelling for riscv, which is not this profile's.
#[inline]
fn rotl(v: c_uint, n: u32) -> c_uint {
    v.rotate_left(n)
}

/// `QUARTERROUND(a, b, c, d)` — `chacha_enc.c:51-55`, the macro the core is built from.
///
/// The four indexes are passed rather than the operands so that the transcription keeps the
/// authority's `x[a] += x[b]` shape: the additions **wrap**, and the rotations are 16, 12, 8 and 7
/// in that order. A transcription that reordered them, or that used 32-bit saturating arithmetic,
/// would still produce a plausible-looking keystream.
#[inline]
fn quarterround(x: &mut [c_uint; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = rotl(x[b] ^ x[c], 7);
}

/// `static void chacha20_core(chacha_buf *output, const u32 input[16])` — `chacha_enc.c:58-84`.
///
/// Ten double rounds of four column quarter-rounds then four diagonal ones, then the final addition
/// of the input state — the whole of ChaCha20. `output` is written as sixty-four little-endian bytes,
/// which is what the authority's `IS_LITTLE_ENDIAN` fast path and its `U32TO8_LITTLE` fallback both
/// produce.
fn chacha20_core(output: &mut [c_uchar; CHACHA_BLK_SIZE], input: &[c_uint; 16]) {
    let mut x = *input;
    let mut i = 20;

    while i > 0 {
        quarterround(&mut x, 0, 4, 8, 12);
        quarterround(&mut x, 1, 5, 9, 13);
        quarterround(&mut x, 2, 6, 10, 14);
        quarterround(&mut x, 3, 7, 11, 15);
        quarterround(&mut x, 0, 5, 10, 15);
        quarterround(&mut x, 1, 6, 11, 12);
        quarterround(&mut x, 2, 7, 8, 13);
        quarterround(&mut x, 3, 4, 9, 14);
        i -= 2;
    }

    for (j, word) in x.iter().enumerate() {
        let v = word.wrapping_add(input[j]);
        output[4 * j..4 * j + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// `void ChaCha20_ctr32(unsigned char *out, const unsigned char *inp, size_t len,
/// const unsigned int key[8], const unsigned int counter[4])` — `chacha_enc.c:90-154`.
///
/// **The key and counter arrive as thirty-two-bit elements in host byte order, not as byte
/// vectors.** The header says why: `CHACHA_U8TOU32` "is so trivial that it's reckoned the macro is
/// sufficient", so there is no key-setup call and the caller collects the bytes itself. The row's
/// `chacha20_initkey`/`chacha20_initiv` are those callers.
///
/// The four sigma words are `"expand 32-byte k"` read as four **little-endian** words, and they are
/// written here as the four ASCII literals rather than as four hex constants, so the spelling and
/// the construction are both visible.
///
/// **The counter is thirty-two bits wide and this function advances only `input[12]`.** Its own
/// comment is explicit that the subroutine is "nonce-agnostic" and that a wider counter is the
/// caller's job: `chacha20_cipher` in `cipher_chacha20_hw.c` is that caller, and it carries into
/// `counter[1]` when `input[12]` wraps. So `len` is not permitted to make the counter wrap inside
/// one call, and the row never does.
///
/// **`out` may equal `inp`.** The XOR is byte-by-byte in the authority and is written here as
/// `inp[i] ^ buf[i]` read from the *old* value before the store, so in-place operation is exact.
///
/// # Safety
/// `out` is writable for `len` bytes; `inp` is readable for `len` bytes and may equal `out`; `key`
/// is readable for eight `unsigned int`s; `counter` for four.
pub(crate) unsafe fn ChaCha20_ctr32(
    out: *mut c_uchar,
    inp: *const c_uchar,
    len: usize,
    key: *const c_uint,
    counter: *const c_uint,
) {
    let mut input = [0 as c_uint; 16];
    let mut buf = [0 as c_uchar; CHACHA_BLK_SIZE];

    /* sigma constant "expand 32-byte k" in little-endian encoding */
    input[0] = c_uint::from_le_bytes(*b"expa");
    input[1] = c_uint::from_le_bytes(*b"nd 3");
    input[2] = c_uint::from_le_bytes(*b"2-by");
    input[3] = c_uint::from_le_bytes(*b"te k");

    // SAFETY: the caller's contract; `key` is readable for eight words and `counter` for four.
    unsafe {
        for i in 0..8 {
            input[4 + i] = *key.add(i);
        }
        for i in 0..4 {
            input[12 + i] = *counter.add(i);
        }
    }

    let mut len = len;
    let mut inp = inp;
    let mut out = out;

    while len > 0 {
        let todo = core::cmp::min(len, CHACHA_BLK_SIZE);

        chacha20_core(&mut buf, &input);

        // The authority's literal `for (i = 0; i < todo; i++) out[i] = inp[i] ^ buf.c[i];`, kept in
        // the form it is written rather than rewritten as a `zip` -- the same call this crate makes
        // wherever the loop *is* the transcription. The index is also what makes the in-place case
        // obviously exact: `inp[i]` is read before `out[i]` is written.
        #[allow(clippy::needless_range_loop)]
        for i in 0..todo {
            // SAFETY: `todo <= len` and both buffers are the caller's for `len` bytes.
            unsafe {
                *out.add(i) = *inp.add(i) ^ buf[i];
            }
        }
        // SAFETY: as above, for `todo`.
        unsafe {
            out = out.add(todo);
            inp = inp.add(todo);
        }
        len -= todo;

        /*
         * Advance the 32-bit counter. The authority's comment is the contract: this limited width
         * "doesn't prevent caller from implementing wider counter. It would simply take two calls
         * split on counter overflow".
         */
        input[12] = input[12].wrapping_add(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// `RFC 7539` §2.4.2's key and nonce, as four and one little-endian words. The vector corpus is
    /// `test/recipes/30-test_evp_data/evpciph_chacha.txt`, whose title says where the vectors come
    /// from — "Chacha20 test vectors from RFC7539" — so the expected bytes below are the standard's
    /// and not this implementation's.
    fn words(bytes: &[u8]) -> [c_uint; 8] {
        let mut w = [0 as c_uint; 8];
        for (i, slot) in w.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
        }
        w
    }

    fn ctr(bytes: &[u8]) -> [c_uint; 4] {
        let mut w = [0 as c_uint; 4];
        for (i, slot) in w.iter_mut().enumerate() {
            *slot = u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
        }
        w
    }

    /// A.1 Test Vector 1: an all-zero key and an all-zero counter, sixty-four zero bytes in, and
    /// the standard's first keystream block out.
    #[test]
    fn cha20_block_with_an_all_zero_state_is_rfc7539s_first_one() {
        let key = words(&[0u8; 32]);
        let counter = ctr(&[0u8; 16]);
        let inp = [0u8; 64];
        let mut out = [0u8; 64];

        // SAFETY: every buffer is a live local of the length passed.
        unsafe {
            ChaCha20_ctr32(
                out.as_mut_ptr(),
                inp.as_ptr(),
                64,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }

        let want: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(out, want);
    }

    /// A.1 Test Vector 2: the counter word is `counter[0]`, so a leading `01` in the IV block is a
    /// counter of one and not a nonce byte. A transcription that treated the sixteen bytes as a
    /// nonce would answer vector 1's keystream again.
    #[test]
    fn the_first_counter_word_is_the_block_counter() {
        let key = words(&[0u8; 32]);
        let mut iv = [0u8; 16];
        iv[0] = 1;
        let counter = ctr(&iv);
        let inp = [0u8; 64];
        let mut out = [0u8; 64];

        // SAFETY: as above.
        unsafe {
            ChaCha20_ctr32(
                out.as_mut_ptr(),
                inp.as_ptr(),
                64,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }

        let want: [u8; 64] = [
            0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a, 0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d,
            0x08, 0x0d, 0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69, 0x12, 0xc6, 0x53, 0x3e,
            0x32, 0xee, 0x7a, 0xed, 0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43, 0xd5, 0x71,
            0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5, 0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
            0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
        ];
        assert_eq!(out, want);
    }

    /// **The multi-block arm, which is where a per-call bug lives.** A message longer than one block
    /// crosses the counter, and the *last* block may be partial — the one place the byte-at-a-time
    /// XOR runs at a length that is not 64. Two properties are asserted, and neither is a vector:
    /// that three hand-stepped single-block calls reproduce one 129-byte call, and that the call is
    /// its own inverse. A vector cannot supply either, and a per-call counter bug breaks the first.
    #[test]
    fn a_multi_block_message_crosses_the_counter_and_a_partial_tail() {
        let key = words(&[
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ]);
        let mut iv = [0u8; 16];
        iv[0] = 0x2a;
        iv[15] = 0x02;
        let counter = ctr(&iv);

        // One counter word, but 129 bytes: two full blocks and one byte, so the third block's
        // counter is 0x2a + 2 = 0x2c and only its first byte is used.
        let inp = [0u8; 129];
        let mut out = [0u8; 129];
        // SAFETY: every buffer is a live local of the length passed.
        unsafe {
            ChaCha20_ctr32(
                out.as_mut_ptr(),
                inp.as_ptr(),
                129,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }

        // The separate-block form must agree: three calls, the counter stepped by hand.
        let mut split = [0u8; 129];
        for (i, step) in [(0usize, 0x2au32), (64, 0x2bu32), (128, 0x2cu32)] {
            let mut c = iv;
            c[0..4].copy_from_slice(&step.to_le_bytes());
            let cc = ctr(&c);
            let n = core::cmp::min(129 - i, 64);
            // SAFETY: `split` is writable from `i` for `n` bytes.
            unsafe {
                ChaCha20_ctr32(
                    split.as_mut_ptr().add(i),
                    inp.as_ptr(),
                    n,
                    key.as_ptr(),
                    cc.as_ptr(),
                );
            }
        }
        assert_eq!(out, split);

        // And the round trip: the same call on the ciphertext returns the plaintext.
        let mut back = [0u8; 129];
        // SAFETY: as above.
        unsafe {
            ChaCha20_ctr32(
                back.as_mut_ptr(),
                out.as_ptr(),
                129,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }
        assert_eq!(back, inp);
    }

    /// **In-place operation is exact.** `cipher_chacha20_hw.c`'s fast path passes the caller's
    /// buffers straight through, and the authority's XOR reads `inp[i]` before writing `out[i]` —
    /// which is what makes `out == inp` work. A transcription that vectorised the XOR in the wrong
    /// order would corrupt a caller that encrypts in place.
    #[test]
    fn encrypting_in_place_agrees_with_encrypting_apart() {
        let key = words(&[0x11u8; 32]);
        let mut iv = [0u8; 16];
        for (i, b) in iv.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let counter = ctr(&iv);

        let mut msg = [0u8; 100];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        let mut apart = [0u8; 100];
        // SAFETY: both buffers are live locals of the length passed.
        unsafe {
            ChaCha20_ctr32(
                apart.as_mut_ptr(),
                msg.as_ptr(),
                100,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }

        // SAFETY: `inp` and `out` are the same live local, which the contract allows.
        unsafe {
            ChaCha20_ctr32(
                msg.as_mut_ptr(),
                msg.as_ptr(),
                100,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }
        assert_eq!(msg, apart);
    }

    /// A zero-length call must not touch the buffers or advance anything. The authority's loop body
    /// is skipped entirely when `len == 0`, so this is a property of the `while`, not of a guard.
    #[test]
    fn a_zero_length_call_is_a_no_op() {
        let key = words(&[0u8; 32]);
        let counter = ctr(&[0u8; 16]);
        let mut out = [0xAAu8; 8];
        // SAFETY: a zero-length call reads and writes nothing.
        unsafe {
            ChaCha20_ctr32(
                out.as_mut_ptr(),
                core::ptr::null(),
                0,
                key.as_ptr(),
                counter.as_ptr(),
            );
        }
        assert_eq!(out, [0xAAu8; 8]);
    }

    /// The header's four constants, and the macro the row's `initkey` uses.
    #[test]
    fn the_chacha_constants_are_the_headers() {
        assert_eq!(CHACHA_KEY_SIZE, 32);
        assert_eq!(CHACHA_CTR_SIZE, 16);
        assert_eq!(CHACHA_BLK_SIZE, 64);

        // SAFETY: the slice is a live local of exactly four bytes.
        let b = [0x01u8, 0x02, 0x03, 0x04];
        // SAFETY: the slice is a live local of exactly the four bytes the macro reads.
        unsafe {
            assert_eq!(u8tou32(&b), 0x0403_0201);
        }
    }
}
