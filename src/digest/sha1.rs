//! Phase 8.1a — `crypto/sha/`: SHA-1.
//!
//! Transcribed from `crypto/sha/sha1dgst.c` and `crypto/sha/sha_local.h`, over
//! [`crate::digest::md32`]. The authority's own header carries the whole function: the
//! compression is eighty rounds of `BODY_00_15`..`BODY_60_79` macros selected by round
//! group, and its message expansion is `Xupdate(a, ix, ia, ib, ic, id)`, which is
//! `a = ia ^ ib ^ ic ^ id; ix = a = ROTATE(a, 1)` — the standard recurrence, written as a
//! macro so it can be interleaved with the rounds.
//!
//! ## The two arms the authority carries, and why the loop is the one used here
//!
//! `sha_local.h` compiles the fully unrolled arm unless `OPENSSL_SMALL_FOOTPRINT` is set, and
//! **it also carries a loop arm of the same function** guarded by that flag: the same eighty
//! rounds, the same four round functions, the same four constants and the same
//! `X[(i + k) & 15]` schedule, with a `BODY_*` macro per round group. This module writes the
//! loop form, and the expansion it uses is the unrolled arm's own `Xupdate` recurrence
//! applied to a sixteen-word ring. The two are the same arithmetic — the project's own
//! configure flag is what selects between them in C — and `RT-DIGEST` is what proves the
//! choice: a published vector would show the crate computes *a* SHA-1, and the differential
//! court shows it computes *this* one.
//!
//! ## `SHA_CTX` has no `md_len`, and that is the whole difference from the SHA-2 contexts
//!
//! `SHA1_Final` writes five words and there is no truncated variant of SHA-1 in the header,
//! so the context is `h0..h4`, `Nl`, `Nh`, `data[16]`, `num` — five words where
//! `SHA256_CTX` has eight plus a length selector. Its `HASH_MAKE_STRING` is therefore
//! unconditional, and `src/digest/sha2.rs`'s is a switch.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::digest::md32::{self, load_word, Md32, MD32_CBLOCK};

/// `SHA_CTX` — `include/openssl/sha.h:41-48`.
#[repr(C)]
pub struct ShaCtx {
    /// `SHA_LONG h0` — the first chaining word.
    pub h0: u32,
    /// `SHA_LONG h1`.
    pub h1: u32,
    /// `SHA_LONG h2`.
    pub h2: u32,
    /// `SHA_LONG h3`.
    pub h3: u32,
    /// `SHA_LONG h4`.
    pub h4: u32,
    /// `SHA_LONG Nl` — the low word of the bit length.
    pub nl: u32,
    /// `SHA_LONG Nh` — the high word.
    pub nh: u32,
    /// `SHA_LONG data[SHA_LBLOCK]` — the staging buffer.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(ShaCtx, h0) == 0);
    assert!(core::mem::offset_of!(ShaCtx, nl) == 20);
    assert!(core::mem::offset_of!(ShaCtx, data) == 28);
    assert!(core::mem::offset_of!(ShaCtx, num) == 92);
    assert!(core::mem::size_of::<ShaCtx>() == 96);
};

/// `K_00_19` … `K_60_79` — `crypto/sha/sha_local.h:70-73`.
const K: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

/// `F_00_19(b,c,d)` — `((c ^ d) & b) ^ d`, Wei Dai's simplification.
#[inline]
fn f_00_19(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}
/// `F_20_39(b,c,d)` — `b ^ c ^ d`.
#[inline]
fn f_20_39(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
/// `F_40_59(b,c,d)` — `(b & c) | ((b | c) & d)`.
#[inline]
fn f_40_59(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | ((b | c) & d)
}

/// `F_60_79` is `F_20_39`.
#[inline]
fn f_60_79(b: u32, c: u32, d: u32) -> u32 {
    f_20_39(b, c, d)
}

/// `F_00_19` … `F_60_79` by round group.
const ROUND: [fn(u32, u32, u32) -> u32; 4] = [f_00_19, f_20_39, f_40_59, f_60_79];

/// `sha1_block_data_order` — `crypto/sha/sha_local.h:127-350`, in its loop form.
fn sha1_block(ctx: &mut ShaCtx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * MD32_CBLOCK` readable bytes.
            *word = unsafe { load_word(data.add(i * 4), false) };
        }
        let mut a = ctx.h0;
        let mut b = ctx.h1;
        let mut c = ctx.h2;
        let mut d = ctx.h3;
        let mut e = ctx.h4;
        for i in 0..80 {
            // `Xupdate`'s recurrence, interleaved with the round that consumes it: the
            // authority writes it inside `BODY_16_19`..`BODY_60_79`, which computes the
            // ring slot and then reads it in the same step. Expanding the whole ring in a
            // separate pass first would overwrite `x[0..16]` — the words rounds 0..15
            // read — with the words rounds 64..79 read.
            if i >= 16 {
                x[i & 15] = (x[(i + 13) & 15] ^ x[(i + 8) & 15] ^ x[(i + 2) & 15] ^ x[i & 15])
                    .rotate_left(1);
            }
            let temp = a
                .rotate_left(5)
                .wrapping_add(ROUND[i / 20](b, c, d))
                .wrapping_add(e)
                .wrapping_add(K[i / 20])
                .wrapping_add(x[i & 15]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        ctx.h0 = ctx.h0.wrapping_add(a);
        ctx.h1 = ctx.h1.wrapping_add(b);
        ctx.h2 = ctx.h2.wrapping_add(c);
        ctx.h3 = ctx.h3.wrapping_add(d);
        ctx.h4 = ctx.h4.wrapping_add(e);

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(MD32_CBLOCK) };
        num -= 1;
    }
}

impl Md32 for ShaCtx {
    const LITTLE_ENDIAN: bool = false;

    fn nl_nh(&self) -> (u32, u32) {
        (self.nl, self.nh)
    }

    fn set_nl_nh(&mut self, nl: u32, nh: u32) {
        self.nl = nl;
        self.nh = nh;
    }

    fn num(&self) -> u32 {
        self.num
    }

    fn set_num(&mut self, num: u32) {
        self.num = num;
    }

    fn data_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr().cast::<u8>()
    }

    unsafe fn block(&mut self, data: *const u8, num: usize) {
        sha1_block(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `HASH_MAKE_STRING` — `crypto/sha/sha_local.h:21-37`: five big-endian words.
        // SAFETY: the caller guaranteed twenty writable bytes at `md`.
        unsafe {
            md32::store_word(md, self.h0, false);
            md32::store_word(md.add(4), self.h1, false);
            md32::store_word(md.add(8), self.h2, false);
            md32::store_word(md.add(12), self.h3, false);
            md32::store_word(md.add(16), self.h4, false);
        }
        1
    }
}

/// `int SHA1_Init(SHA_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<ShaCtx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn SHA1_Init(c: *mut ShaCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<ShaCtx>());
        (*c).h0 = 0x6745_2301;
        (*c).h1 = 0xefcd_ab89;
        (*c).h2 = 0x98ba_dcfe;
        (*c).h3 = 0x1032_5476;
        (*c).h4 = 0xc3d2_e1f0;
    }
    1
}

/// `int SHA1_Update(SHA_CTX *c, const void *data, size_t len)`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA1_Update(c: *mut ShaCtx, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data.cast::<u8>(), len) }
}

/// `int SHA1_Final(unsigned char *md, SHA_CTX *c)`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 20 bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA1_Final(md: *mut u8, c: *mut ShaCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void SHA1_Transform(SHA_CTX *c, const unsigned char *data)`.
///
/// # Safety
/// `c` must be a live context; `data` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn SHA1_Transform(c: *mut ShaCtx, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, data) };
}

/// `int ossl_sha1_ctrl(SHA_CTX *sha1, int cmd, int mslen, void *ms)` —
/// `crypto/sha/sha1dgst.c:28-85`, declared in `include/crypto/sha.h:20`.
///
/// This is `SHA1_CTRL`, the SSLv3 master-secret arm: it hashes the master secret with `pad_1`
/// (0x36), finalises to the intermediate digest, reinitialises, and hashes the master secret
/// with `pad_2` (0x5c) and the intermediate — so a later `SHA1_Final` answers the RFC 6101
/// §5.6.8 value. Its callers are the provider's `sha1_set_ctx_params` and Phase 13's legacy
/// `EVP_MD` ctrl, which is why it is `pub(crate)` internal and carries the authority's name.
///
/// It is not `#[no_mangle]`: the authority declares it in an uninstalled header
/// (`include/crypto/sha.h`) and it is not in the exported symbol set.
///
/// # Safety
/// `sha1` must be a live initialised context and `ms` readable for `mslen` bytes when `mslen`
/// is 48; a NULL `sha1` answers 0 without being dereferenced, as the authority's guard does.
// The provider's `sha1_set_ctx_params` and Phase 13's `legacy_sha.c` are the two callers the
// authority has; the provider half lands in this same commit, and the legacy one is Phase 13's.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_sha1_ctrl(
    sha1: *mut ShaCtx,
    cmd: c_int,
    mslen: c_int,
    ms: *mut c_void,
) -> c_int {
    /// `SHA_DIGEST_LENGTH` — `include/openssl/sha.h:28`.
    const SHA_DIGEST_LENGTH: usize = 20;
    /// `EVP_CTRL_SSL3_MASTER_SECRET` — `include/openssl/evp.h:1221`.
    const EVP_CTRL_SSL3_MASTER_SECRET: c_int = 0x1d;
    /// The authority's `unsigned char padtmp[40]` — `2 * SHA_DIGEST_LENGTH`, because the arm
    /// pads the master secret with a full digest's worth of bytes on each side of the outer hash.
    const PAD_LENGTH: usize = 40;

    let mut padtmp = [0u8; PAD_LENGTH];
    let mut sha1tmp = [0u8; SHA_DIGEST_LENGTH];

    if cmd != EVP_CTRL_SSL3_MASTER_SECRET {
        return -2;
    }
    if sha1.is_null() {
        return 0;
    }
    if mslen != 48 {
        return 0;
    }

    // SAFETY: `sha1` is live and `ms` is readable for `mslen == 48` bytes per the caller.
    if unsafe { SHA1_Update(sha1, ms.cast_const(), mslen as usize) } <= 0 {
        return 0;
    }

    padtmp.fill(0x36);
    // SAFETY: `sha1` is live and `padtmp` is a live local of forty bytes.
    if unsafe { SHA1_Update(sha1, padtmp.as_ptr().cast(), PAD_LENGTH) } == 0 {
        return 0;
    }
    // SAFETY: `sha1` is live and `sha1tmp` is a live local of the digest length.
    if unsafe { SHA1_Final(sha1tmp.as_mut_ptr(), sha1) } == 0 {
        return 0;
    }
    // SAFETY: `sha1` is live.
    if unsafe { SHA1_Init(sha1) } == 0 {
        return 0;
    }

    // SAFETY: as the first update above.
    if unsafe { SHA1_Update(sha1, ms.cast_const(), mslen as usize) } <= 0 {
        return 0;
    }

    padtmp.fill(0x5c);
    // SAFETY: `sha1` is live and `padtmp` is a live local of forty bytes.
    if unsafe { SHA1_Update(sha1, padtmp.as_ptr().cast(), PAD_LENGTH) } == 0 {
        return 0;
    }
    // SAFETY: `sha1` is live and `sha1tmp` is a live local of the digest length.
    if unsafe { SHA1_Update(sha1, sha1tmp.as_ptr().cast(), SHA_DIGEST_LENGTH) } == 0 {
        return 0;
    }

    // `OPENSSL_cleanse(sha1tmp, sizeof(sha1tmp))`.
    // SAFETY: `sha1tmp` is a live local of the digest length.
    unsafe { ptr::write_bytes(sha1tmp.as_mut_ptr(), 0, SHA_DIGEST_LENGTH) };

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4's SHA-1 examples and the alphabet vector.
    const VECTORS: [(&[u8], &str); 4] = [
        (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = ShaCtx {
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            nl: 0,
            nh: 0,
            data: [0; 16],
            num: 0,
        };
        let mut out = [0u8; 20];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(SHA1_Init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(SHA1_Update(&mut c, data.as_ptr().cast(), at), 1);
                    assert_eq!(
                        SHA1_Update(&mut c, data.as_ptr().add(at).cast(), data.len() - at),
                        1
                    );
                }
                None => assert_eq!(SHA1_Update(&mut c, data.as_ptr().cast(), data.len()), 1),
            }
            assert_eq!(SHA1_Final(out.as_mut_ptr(), &mut c), 1);
        }
        hex(&out)
    }

    #[test]
    fn the_authoritys_vectors() {
        for (input, want) in VECTORS {
            assert_eq!(digest(input, None), want, "{input:?}");
        }
    }

    #[test]
    fn a_split_update_answers_the_same_as_one_call() {
        for (input, want) in VECTORS {
            for at in 0..=input.len() {
                assert_eq!(digest(input, Some(at)), want, "{input:?} split at {at}");
            }
        }
    }

    #[test]
    fn the_padding_arms_are_where_the_length_field_moves() {
        let mut data = [0u8; 128];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i & 0xff) as u8;
        }
        for len in [54usize, 55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let msg = &data[..len];
            assert_eq!(digest(msg, None).len(), 40);
            assert_eq!(digest(msg, None), digest(msg, Some(len / 2)));
        }
    }
}
