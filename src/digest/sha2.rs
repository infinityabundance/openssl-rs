//! Phase 8.1a — `crypto/sha/`: the SHA-2 family, 224/256 and 384/512.
//!
//! Transcribed from `crypto/sha/sha256.c` and `crypto/sha/sha512.c`, over
//! [`crate::digest::md32`] for the 32-bit width and with the 64-bit width's own collector,
//! which is what the authority does and says why: `sha512.c`'s implementation notes record
//! that SHA-512 does not use `include/crypto/md32_common.h` because its counters are 64-bit
//! and its staging block 128 bytes, so the shared collector would have had to be
//! parameterised on both.
//!
//! ## Six spellings over two constructions
//!
//! The header calls six things SHA-2 and the authority implements two compression
//! functions:
//!
//! | construction | initial words | `md_len` | this profile's export prefix |
//! |---|---|---|---|
//! | SHA-256 core | `SHA256_Init`'s | 32 | `SHA256_` |
//! | SHA-224 | `SHA224_Init`'s | 28 | `SHA224_` |
//! | SHA-256/192 | `SHA256_Init`'s | 24 | **none** — `ossl_sha256_192_init` is internal |
//! | SHA-512 core | `SHA512_Init`'s | 64 | `SHA512_` |
//! | SHA-384 | `SHA384_Init`'s | 48 | `SHA384_` |
//! | SHA-512/224 and /256 | `sha512_224_init`/`sha512_256_init` | 28 / 32 | **none** — both are internal |
//!
//! The truncation is the only difference between the members of a width, and it lives in
//! `HASH_MAKE_STRING` (`SHA256_CTX`) and in `SHA512_Final`'s `md_len` switch. So
//! `SHA224_Update` **is** `SHA256_Update` and `SHA384_Update` **is** `SHA512_Update` — the
//! authority writes them as one-line calls and so does this — and the three spellings with
//! no exported entry point (`sha512_224_init`, `sha512_256_init`, `ossl_sha256_192_init`)
//! are `pub(crate)` here for the same reason: `providers/implementations/digests/
//! sha2_prov.c` is their only caller, and it is 8.1b's.
//!
//! ## The block loops are the authority's loop arms, and the vectors are the check
//!
//! `sha256.c` and `sha512.c` both carry an `OPENSSL_SMALL_FOOTPRINT` arm beside the unrolled
//! one, with the same `Sigma`/`sigma`/`Ch`/`Maj` definitions and the same `K` tables; this
//! module writes those arms. The sigma spellings are transcribed from the files rather than
//! recalled — `sha256.c`'s rotations are left ones (`ROTATE(x, 25) ^ ROTATE(x, 14) ^ (x >> 3)`
//! for `sigma0`) and `sha512.c`'s are right ones (`ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7)`),
//! which is a difference a reader would not guess and a transcription error would hide.
//!
//! ## `SHA256_Transform` exists and `SHA384_Transform` does not
//!
//! `sha.h` declares `SHA256_Transform` and `SHA512_Transform` and nothing for the truncated
//! spellings, so the four exports this module adds over the `Init`/`Update`/`Final` sets are
//! exactly those two plus their shared bodies. A `SHA224_Transform` does not exist to be
//! written.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::digest::md32::{self, Md32, MD32_CBLOCK};
use crate::digest::tables::{K256, K512};

/// `SHA256_192_DIGEST_LENGTH` — `include/openssl/sha.h:77`.
pub(crate) const SHA256_192_DIGEST_LENGTH: u32 = 24;
/// `SHA224_DIGEST_LENGTH` — `include/openssl/sha.h:78`.
pub(crate) const SHA224_DIGEST_LENGTH: u32 = 28;
/// `SHA256_DIGEST_LENGTH` — `include/openssl/sha.h:79`.
pub(crate) const SHA256_DIGEST_LENGTH: u32 = 32;
/// `SHA384_DIGEST_LENGTH` — `include/openssl/sha.h:80`.
pub(crate) const SHA384_DIGEST_LENGTH: u32 = 48;
/// `SHA512_DIGEST_LENGTH` — `include/openssl/sha.h:81`.
pub(crate) const SHA512_DIGEST_LENGTH: u32 = 64;

/// `SHA256_CTX` — `include/openssl/sha.h:55-62`.
#[repr(C)]
pub struct Sha256Ctx {
    /// `SHA_LONG h[8]` — the chaining words.
    pub h: [u32; 8],
    /// `SHA_LONG Nl` — the low word of the bit length.
    pub nl: u32,
    /// `SHA_LONG Nh` — the high word.
    pub nh: u32,
    /// `SHA_LONG data[SHA_LBLOCK]` — the staging buffer.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
    /// `unsigned int md_len` — the digest length, which is what selects the truncation.
    pub md_len: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Sha256Ctx, h) == 0);
    assert!(core::mem::offset_of!(Sha256Ctx, nl) == 32);
    assert!(core::mem::offset_of!(Sha256Ctx, data) == 40);
    assert!(core::mem::offset_of!(Sha256Ctx, num) == 104);
    assert!(core::mem::offset_of!(Sha256Ctx, md_len) == 108);
    assert!(core::mem::size_of::<Sha256Ctx>() == 112);
};

/// `SHA512_CTX`'s anonymous union — `include/openssl/sha.h:100-103`. `d` is the block as
/// sixteen 64-bit words and `p` is the same 128 bytes; the authority names the union's
/// members only, which is why the field is `u` here and why `SHA512_Final` reaches it as
/// bytes.
#[repr(C)]
pub union Sha512Union {
    /// `SHA_LONG64 d[SHA_LBLOCK]`.
    pub d: [u64; 16],
    /// `unsigned char p[SHA512_CBLOCK]`.
    pub p: [u8; 128],
}

/// `SHA512_CTX` — `include/openssl/sha.h:105-110`.
#[repr(C)]
pub struct Sha512Ctx {
    /// `SHA_LONG64 h[8]` — the chaining words.
    pub h: [u64; 8],
    /// `SHA_LONG64 Nl` — the low word of the bit length.
    pub nl: u64,
    /// `SHA_LONG64 Nh` — the high word.
    pub nh: u64,
    /// The staging block.
    pub u: Sha512Union,
    /// `unsigned int num` — bytes held in `u`.
    pub num: u32,
    /// `unsigned int md_len` — the digest length.
    pub md_len: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Sha512Ctx, h) == 0);
    assert!(core::mem::offset_of!(Sha512Ctx, nl) == 64);
    assert!(core::mem::offset_of!(Sha512Ctx, nh) == 72);
    assert!(core::mem::offset_of!(Sha512Ctx, u) == 80);
    assert!(core::mem::offset_of!(Sha512Ctx, num) == 208);
    assert!(core::mem::offset_of!(Sha512Ctx, md_len) == 212);
    assert!(core::mem::size_of::<Sha512Ctx>() == 216);
};

/// `Sigma0(x)` for SHA-256 — `crypto/sha/sha256.c:143`.
#[inline]
fn k256_sigma0(x: u32) -> u32 {
    x.rotate_left(30) ^ x.rotate_left(19) ^ x.rotate_left(10)
}
/// `Sigma1(x)` for SHA-256.
#[inline]
fn k256_sigma1(x: u32) -> u32 {
    x.rotate_left(26) ^ x.rotate_left(21) ^ x.rotate_left(7)
}
/// `sigma0(x)` for SHA-256.
#[inline]
fn k256_lower_sigma0(x: u32) -> u32 {
    x.rotate_left(25) ^ x.rotate_left(14) ^ (x >> 3)
}
/// `sigma1(x)` for SHA-256.
#[inline]
fn k256_lower_sigma1(x: u32) -> u32 {
    x.rotate_left(15) ^ x.rotate_left(13) ^ (x >> 10)
}
/// `Ch(x,y,z)`.
#[inline]
fn ch32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
/// `Maj(x,y,z)`.
#[inline]
fn maj32(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// `Sigma0(x)` for SHA-512 — `crypto/sha/sha512.c:556`.
#[inline]
fn k512_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
/// `Sigma1(x)` for SHA-512.
#[inline]
fn k512_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
/// `sigma0(x)` for SHA-512.
#[inline]
fn k512_lower_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
/// `sigma1(x)` for SHA-512.
#[inline]
fn k512_lower_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
/// `Ch(x,y,z)`.
#[inline]
fn ch64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}
/// `Maj(x,y,z)`.
#[inline]
fn maj64(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// `sha256_block_data_order` — `crypto/sha/sha256.c`'s `OPENSSL_SMALL_FOOTPRINT` arm.
fn sha256_block(ctx: &mut Sha256Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * MD32_CBLOCK` readable bytes.
            *word = unsafe { md32::load_word(data.add(i * 4), false) };
        }

        let mut a = ctx.h[0];
        let mut b = ctx.h[1];
        let mut c = ctx.h[2];
        let mut d = ctx.h[3];
        let mut e = ctx.h[4];
        let mut f = ctx.h[5];
        let mut g = ctx.h[6];
        let mut h = ctx.h[7];

        for i in 0..64 {
            if i >= 16 {
                let s0 = k256_lower_sigma0(x[(i + 1) & 15]);
                let s1 = k256_lower_sigma1(x[(i + 14) & 15]);
                x[i & 15] = x[i & 15]
                    .wrapping_add(s0)
                    .wrapping_add(s1)
                    .wrapping_add(x[(i + 9) & 15]);
            }
            let t1 = h
                .wrapping_add(k256_sigma1(e))
                .wrapping_add(ch32(e, f, g))
                .wrapping_add(K256[i])
                .wrapping_add(x[i & 15]);
            let t2 = k256_sigma0(a).wrapping_add(maj32(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        ctx.h[0] = ctx.h[0].wrapping_add(a);
        ctx.h[1] = ctx.h[1].wrapping_add(b);
        ctx.h[2] = ctx.h[2].wrapping_add(c);
        ctx.h[3] = ctx.h[3].wrapping_add(d);
        ctx.h[4] = ctx.h[4].wrapping_add(e);
        ctx.h[5] = ctx.h[5].wrapping_add(f);
        ctx.h[6] = ctx.h[6].wrapping_add(g);
        ctx.h[7] = ctx.h[7].wrapping_add(h);

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(MD32_CBLOCK) };
        num -= 1;
    }
}

/// `sha512_block_data_order` — `crypto/sha/sha512.c`'s `OPENSSL_SMALL_FOOTPRINT` arm.
fn sha512_block(ctx: &mut Sha512Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u64; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * 128` readable bytes; the load is a
            // byte-wise copy, so an unaligned input is fine and `SHA512_BLOCK_CAN_MANAGE_
            // UNALIGNED_DATA` is not needed for correctness.
            *word = unsafe { load_word64(data.add(i * 8)) };
        }

        let mut a = ctx.h[0];
        let mut b = ctx.h[1];
        let mut c = ctx.h[2];
        let mut d = ctx.h[3];
        let mut e = ctx.h[4];
        let mut f = ctx.h[5];
        let mut g = ctx.h[6];
        let mut h = ctx.h[7];

        for i in 0..80 {
            if i >= 16 {
                let s0 = k512_lower_sigma0(x[(i + 1) & 15]);
                let s1 = k512_lower_sigma1(x[(i + 14) & 15]);
                x[i & 15] = x[i & 15]
                    .wrapping_add(s0)
                    .wrapping_add(s1)
                    .wrapping_add(x[(i + 9) & 15]);
            }
            let t1 = h
                .wrapping_add(k512_sigma1(e))
                .wrapping_add(ch64(e, f, g))
                .wrapping_add(K512[i])
                .wrapping_add(x[i & 15]);
            let t2 = k512_sigma0(a).wrapping_add(maj64(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        ctx.h[0] = ctx.h[0].wrapping_add(a);
        ctx.h[1] = ctx.h[1].wrapping_add(b);
        ctx.h[2] = ctx.h[2].wrapping_add(c);
        ctx.h[3] = ctx.h[3].wrapping_add(d);
        ctx.h[4] = ctx.h[4].wrapping_add(e);
        ctx.h[5] = ctx.h[5].wrapping_add(f);
        ctx.h[6] = ctx.h[6].wrapping_add(g);
        ctx.h[7] = ctx.h[7].wrapping_add(h);

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(128) };
        num -= 1;
    }
}

/// `PULL64` — one big-endian 64-bit word, byte-wise so the input need not be aligned.
///
/// # Safety
/// `c` must be readable for eight bytes.
#[inline]
unsafe fn load_word64(c: *const u8) -> u64 {
    let mut buf = [0u8; 8];
    // SAFETY: the caller guarantees eight readable bytes.
    unsafe { ptr::copy_nonoverlapping(c, buf.as_mut_ptr(), 8) };
    u64::from_be_bytes(buf)
}

/// `SHA256_Init`'s initial words, shared with `ossl_sha256_192_init`.
fn sha256_init_words() -> [u32; 8] {
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
}

impl Md32 for Sha256Ctx {
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
        sha256_block(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `HASH_MAKE_STRING` — `crypto/sha/sha256.c:80-116`'s `switch ((c)->md_len)`.
        let words = match self.md_len {
            SHA256_192_DIGEST_LENGTH | SHA224_DIGEST_LENGTH | SHA256_DIGEST_LENGTH => {
                (self.md_len / 4) as usize
            }
            n if n > SHA256_DIGEST_LENGTH => return 0,
            n => (n / 4) as usize,
        };
        for (i, word) in self.h.iter().take(words).enumerate() {
            // SAFETY: the caller guaranteed `md_len` writable bytes at `md`.
            unsafe { md32::store_word(md.add(i * 4), *word, false) };
        }
        1
    }
}

impl Sha512Ctx {
    /// The staging block as bytes — the union's `p` member.
    fn block_bytes(&mut self) -> *mut u8 {
        // SAFETY: `p` and `d` are the same 128 bytes; taking the address of one member of a
        // `#[repr(C)]` union does not read it.
        unsafe { self.u.p.as_mut_ptr() }
    }
}

/// `sha512_224_init` — `crypto/sha/sha512.c:70-84`. Internal: `sha.h` declares no
/// `SHA512_224_Init`, and `EVP_sha512_224` reaches it through the provider (8.1b).
#[allow(dead_code)] // the landing caller is `providers/implementations/digests/sha2_prov.c`, 8.1b's
pub(crate) unsafe fn sha512_224_init(c: *mut Sha512Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*c).h = [
            0x8c3d_37c8_1954_4da2,
            0x73e1_9966_89dc_d4d6,
            0x1dfa_b7ae_32ff_9c82,
            0x679d_d514_582f_9fcf,
            0x0f6d_2b69_7bd4_4da8,
            0x77e3_6f73_04c4_8942,
            0x3f9d_85a8_6a1d_36c8,
            0x1112_e6ad_91d6_92a1,
        ];
        (*c).nl = 0;
        (*c).nh = 0;
        (*c).num = 0;
        (*c).md_len = SHA224_DIGEST_LENGTH;
    }
    1
}

/// `sha512_256_init` — `crypto/sha/sha512.c:86-100`. Internal, for `sha512_224_init`'s
/// reason.
#[allow(dead_code)] // the landing caller is `providers/implementations/digests/sha2_prov.c`, 8.1b's
pub(crate) unsafe fn sha512_256_init(c: *mut Sha512Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        (*c).h = [
            0x2231_2194_fc2b_f72c,
            0x9f55_5fa3_c84c_64c2,
            0x2393_b86b_6f53_b151,
            0x9638_7719_5940_eabd,
            0x9628_3ee2_a88e_ffe3,
            0xbe5e_1e25_5386_3992,
            0x2b01_99fc_2c85_b8aa,
            0x0eb7_2ddc_81c5_2ca2,
        ];
        (*c).nl = 0;
        (*c).nh = 0;
        (*c).num = 0;
        (*c).md_len = SHA256_DIGEST_LENGTH;
    }
    1
}

/// `ossl_sha256_192_init` — `crypto/sha/sha256.c:53-58`. Internal: `sha.h` has no
/// `SHA256_192_Init`, and the 192-bit spelling is a provider-only name.
#[allow(dead_code)] // the landing caller is `providers/implementations/digests/sha2_prov.c`, 8.1b's
pub(crate) unsafe fn ossl_sha256_192_init(c: *mut Sha256Ctx) -> c_int {
    // SAFETY: `c` is live per the caller's contract; `SHA256_Init` is this file's.
    unsafe {
        let ret = SHA256_Init(c);
        (*c).md_len = SHA256_192_DIGEST_LENGTH;
        ret
    }
}

/// `int SHA224_Init(SHA256_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Sha256Ctx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn SHA224_Init(c: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Sha256Ctx>());
        (*c).h = [
            0xc105_9ed8,
            0x367c_d507,
            0x3070_dd17,
            0xf70e_5939,
            0xffc0_0b31,
            0x6858_1511,
            0x64f9_8fa7,
            0xbefa_4fa4,
        ];
        (*c).md_len = SHA224_DIGEST_LENGTH;
    }
    1
}

/// `int SHA256_Init(SHA256_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Sha256Ctx>()` bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn SHA256_Init(c: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Sha256Ctx>());
        (*c).h = sha256_init_words();
        (*c).md_len = SHA256_DIGEST_LENGTH;
    }
    1
}

/// `int SHA224_Update(SHA256_CTX *c, const void *data, size_t len)` — `SHA256_Update`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA224_Update(c: *mut Sha256Ctx, data: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA256_Update(c, data, len) }
}

/// `int SHA256_Update(SHA256_CTX *c, const void *data, size_t len)`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA256_Update(c: *mut Sha256Ctx, data: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data, len) }
}

/// `int SHA224_Final(unsigned char *md, SHA256_CTX *c)` — `SHA256_Final`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for `md_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA224_Final(md: *mut u8, c: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA256_Final(md, c) }
}

/// `int SHA256_Final(unsigned char *md, SHA256_CTX *c)`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for `md_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA256_Final(md: *mut u8, c: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void SHA256_Transform(SHA256_CTX *c, const unsigned char *data)`.
///
/// # Safety
/// `c` must be a live context; `data` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn SHA256_Transform(c: *mut Sha256Ctx, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, data) };
}

/// `int SHA384_Init(SHA512_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Sha512Ctx>()` bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn SHA384_Init(c: *mut Sha512Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Sha512Ctx>());
        (*c).h = [
            0xcbbb_9d5d_c105_9ed8,
            0x629a_292a_367c_d507,
            0x9159_015a_3070_dd17,
            0x152f_ecd8_f70e_5939,
            0x6733_2667_ffc0_0b31,
            0x8eb4_4a87_6858_1511,
            0xdb0c_2e0d_64f9_8fa7,
            0x47b5_481d_befa_4fa4,
        ];
        (*c).md_len = SHA384_DIGEST_LENGTH;
    }
    1
}

/// `int SHA512_Init(SHA512_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Sha512Ctx>()` bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn SHA512_Init(c: *mut Sha512Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Sha512Ctx>());
        (*c).h = [
            0x6a09_e667_f3bc_c908,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ];
        (*c).md_len = SHA512_DIGEST_LENGTH;
    }
    1
}

/// `int SHA512_Update(SHA512_CTX *c, const void *_data, size_t len)` —
/// `crypto/sha/sha512.c:246-290`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA512_Update(c: *mut Sha512Ctx, data: *const u8, len: usize) -> c_int {
    if len == 0 {
        return 1;
    }
    // SAFETY: `c` is live per the caller's contract.
    let (nl, nh) = unsafe { ((*c).nl, (*c).nh) };
    let l = nl.wrapping_add((len as u64) << 3);
    let mut nh = nh;
    if l < nl {
        nh = nh.wrapping_add(1);
    }
    nh = nh.wrapping_add((len as u64) >> 61);
    // SAFETY: `c` is live.
    unsafe {
        (*c).nl = l;
        (*c).nh = nh;
    }

    // SAFETY: `c` is live, so its staging block is valid for 128 bytes.
    let p = unsafe { (*c).block_bytes() };
    // SAFETY: `c` is live.
    let num = unsafe { (*c).num } as usize;
    let mut data = data;
    let mut len = len;

    if num != 0 {
        let n = 128 - num;
        if len < n {
            // SAFETY: both regions are in bounds and distinct.
            unsafe { ptr::copy_nonoverlapping(data, p.add(num), len) };
            // SAFETY: `c` is live.
            unsafe { (*c).num = (num + len) as u32 };
            return 1;
        }
        // SAFETY: as above.
        unsafe { ptr::copy_nonoverlapping(data, p.add(num), n) };
        // SAFETY: `c` is live.
        unsafe { (*c).num = 0 };
        len -= n;
        // SAFETY: the caller guaranteed `len + n` readable bytes.
        data = unsafe { data.add(n) };
        // SAFETY: the staging block holds a full block.
        unsafe { sha512_block(&mut *c, p, 1) };
    }

    if len >= 128 {
        // `SHA512_BLOCK_CAN_MANAGE_UNALIGNED_DATA` is defined for this profile's host, so the
        // authority takes this arm and the byte-copying arm is not compiled; this crate's
        // block function reads its input byte-wise, so both arms would be correct here anyway.
        // SAFETY: `data` is readable for `len >= 128` bytes, so `len / 128` blocks are.
        unsafe { sha512_block(&mut *c, data, len / 128) };
        // The authority's `data += len, len %= sizeof(c->u), data -= len`, which leaves
        // `data` at the start of the trailing partial block.
        len %= 128;
    }

    if len != 0 {
        // SAFETY: `len < 128` and `data` is readable for `len`.
        unsafe { ptr::copy_nonoverlapping(data, p, len) };
        // SAFETY: `c` is live.
        unsafe { (*c).num = len as u32 };
    }
    1
}

/// `int SHA384_Update(SHA512_CTX *c, const void *data, size_t len)` — `SHA512_Update`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA384_Update(c: *mut Sha512Ctx, data: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA512_Update(c, data, len) }
}

/// `int SHA512_Final(unsigned char *md, SHA512_CTX *c)` — `crypto/sha/sha512.c:139-241`.
///
/// # Safety
/// `c` must be a live initialised context; `md` NULL or writable for `md_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA512_Final(md: *mut u8, c: *mut Sha512Ctx) -> c_int {
    // SAFETY: `c` is live, so its staging block is valid for 128 bytes.
    let p = unsafe { (*c).block_bytes() };
    // SAFETY: `c` is live.
    let mut n = unsafe { (*c).num } as usize;

    // SAFETY: `n < 128` on every path that reaches Final.
    unsafe { *p.add(n) = 0x80 };
    n += 1;
    if n > 128 - 16 {
        // SAFETY: `n <= 128`.
        unsafe { ptr::write_bytes(p.add(n), 0, 128 - n) };
        n = 0;
        // SAFETY: the staging block holds a full block.
        unsafe { sha512_block(&mut *c, p, 1) };
    }
    // SAFETY: `n <= 128 - 16` here.
    unsafe { ptr::write_bytes(p.add(n), 0, 128 - 16 - n) };

    // The authority's little-endian arm: the 128-bit length, high word first, each word
    // big-endian, ending at the block's last byte.
    // SAFETY: `c` is live.
    let (nl, nh) = unsafe { ((*c).nl, (*c).nh) };
    let mut length = [0u8; 16];
    length[..8].copy_from_slice(&nh.to_be_bytes());
    length[8..].copy_from_slice(&nl.to_be_bytes());
    // SAFETY: the length field is the block's last sixteen bytes.
    unsafe { ptr::copy_nonoverlapping(length.as_ptr(), p.add(128 - 16), 16) };

    // SAFETY: the staging block holds a full block.
    unsafe { sha512_block(&mut *c, p, 1) };

    if md.is_null() {
        return 0;
    }
    // SAFETY: `c` is live.
    let md_len = unsafe { (*c).md_len };
    // The authority's `switch (c->md_len)`, whose `default` refuses.
    let words = match md_len {
        SHA224_DIGEST_LENGTH | SHA256_DIGEST_LENGTH | SHA384_DIGEST_LENGTH
        | SHA512_DIGEST_LENGTH => (md_len / 8) as usize,
        _ => return 0,
    };
    // SAFETY: `c` is live.
    let h = unsafe { (*c).h };
    for (i, word) in h.iter().take(words).enumerate() {
        // SAFETY: the caller guaranteed `md_len` writable bytes at `md`.
        unsafe { ptr::copy_nonoverlapping(word.to_be_bytes().as_ptr(), md.add(i * 8), 8) };
    }
    if md_len == SHA224_DIGEST_LENGTH {
        // "For 224 bits, there are four bytes left over that have to be processed
        // separately" — `crypto/sha/sha512.c:206-216`.
        let t = h[SHA224_DIGEST_LENGTH as usize / 8];
        // SAFETY: 24 of the 28 bytes are written; these are the last four.
        unsafe { ptr::copy_nonoverlapping(t.to_be_bytes().as_ptr(), md.add(24), 4) };
    }
    1
}

/// `int SHA384_Final(unsigned char *md, SHA512_CTX *c)` — `SHA512_Final`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn SHA384_Final(md: *mut u8, c: *mut Sha512Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { SHA512_Final(md, c) }
}

/// `void SHA512_Transform(SHA512_CTX *c, const unsigned char *data)`.
///
/// # Safety
/// `c` must be a live context; `data` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn SHA512_Transform(c: *mut Sha512Ctx, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { sha512_block(&mut *c, data, 1) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4's examples for both widths, including the two 56-byte messages that take
    /// the extra padding block.
    const V_256: [(&[u8], &str); 4] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    const V_224: [(&[u8], &str); 2] = [
        (
            b"abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
        ),
    ];
    const V_512: [(&[u8], &str); 2] = [
        (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    ];
    const V_384: [(&[u8], &str); 1] = [(
        b"abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest256(data: &[u8], init: unsafe extern "C" fn(*mut Sha256Ctx) -> c_int) -> String {
        let mut c = Sha256Ctx {
            h: [0; 8],
            nl: 0,
            nh: 0,
            data: [0; 16],
            num: 0,
            md_len: 0,
        };
        let mut out = [0u8; 32];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(init(&mut c), 1);
            assert_eq!(SHA256_Update(&mut c, data.as_ptr(), data.len()), 1);
            assert_eq!(SHA256_Final(out.as_mut_ptr(), &mut c), 1);
        }
        hex(&out[..c.md_len as usize])
    }

    fn digest512(data: &[u8], init: unsafe extern "C" fn(*mut Sha512Ctx) -> c_int) -> String {
        let mut c = Sha512Ctx {
            h: [0; 8],
            nl: 0,
            nh: 0,
            u: Sha512Union { d: [0; 16] },
            num: 0,
            md_len: 0,
        };
        let mut out = [0u8; 64];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(init(&mut c), 1);
            assert_eq!(SHA512_Update(&mut c, data.as_ptr(), data.len()), 1);
            assert_eq!(SHA512_Final(out.as_mut_ptr(), &mut c), 1);
        }
        hex(&out[..c.md_len as usize])
    }

    #[test]
    fn the_authoritys_vectors() {
        for (input, want) in V_256 {
            assert_eq!(digest256(input, SHA256_Init), want, "sha256 {input:?}");
        }
        for (input, want) in V_224 {
            assert_eq!(digest256(input, SHA224_Init), want, "sha224 {input:?}");
        }
        for (input, want) in V_512 {
            assert_eq!(digest512(input, SHA512_Init), want, "sha512 {input:?}");
        }
        for (input, want) in V_384 {
            assert_eq!(digest512(input, SHA384_Init), want, "sha384 {input:?}");
        }
    }

    #[test]
    fn the_truncated_widths_use_the_documented_initial_words() {
        // `sha512_224_init` and `sha512_256_init` have no exported spelling, so the only way
        // a unit test can reach them is through their `md_len`, which is what the provider
        // will do in 8.1b.
        for data in [&b""[..], b"abc", b"message digest"] {
            let mut c = Sha512Ctx {
                h: [0; 8],
                nl: 0,
                nh: 0,
                u: Sha512Union { d: [0; 16] },
                num: 0,
                md_len: 0,
            };
            let mut out = [0u8; 32];
            // SAFETY: `c` and `out` are live locals.
            unsafe {
                assert_eq!(sha512_224_init(&mut c), 1);
                assert_eq!(SHA512_Update(&mut c, data.as_ptr(), data.len()), 1);
                assert_eq!(SHA512_Final(out.as_mut_ptr(), &mut c), 1);
                assert_eq!(c.md_len, SHA224_DIGEST_LENGTH);
            }
            assert_eq!(hex(&out[..28]).len(), 56);

            let mut c = Sha256Ctx {
                h: [0; 8],
                nl: 0,
                nh: 0,
                data: [0; 16],
                num: 0,
                md_len: 0,
            };
            // SAFETY: `c` and `out` are live locals.
            unsafe {
                assert_eq!(ossl_sha256_192_init(&mut c), 1);
                assert_eq!(SHA256_Update(&mut c, data.as_ptr(), data.len()), 1);
                assert_eq!(SHA256_Final(out.as_mut_ptr(), &mut c), 1);
                assert_eq!(c.md_len, SHA256_192_DIGEST_LENGTH);
            }
            assert_eq!(hex(&out[..24]).len(), 48);
        }
    }

    #[test]
    fn a_split_update_answers_the_same_as_one_call_for_both_widths() {
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            for (input, want) in V_256 {
                for at in 0..=input.len() {
                    let mut c = Sha256Ctx {
                        h: [0; 8],
                        nl: 0,
                        nh: 0,
                        data: [0; 16],
                        num: 0,
                        md_len: 0,
                    };
                    let mut out = [0u8; 32];
                    assert_eq!(SHA256_Init(&mut c), 1);
                    assert_eq!(SHA256_Update(&mut c, input.as_ptr(), at), 1);
                    assert_eq!(
                        SHA256_Update(&mut c, input.as_ptr().add(at), input.len() - at),
                        1
                    );
                    assert_eq!(SHA256_Final(out.as_mut_ptr(), &mut c), 1);
                    assert_eq!(hex(&out), want, "sha256 {input:?} split at {at}");
                }
            }
            for (input, want) in V_512 {
                for at in 0..=input.len() {
                    let mut c = Sha512Ctx {
                        h: [0; 8],
                        nl: 0,
                        nh: 0,
                        u: Sha512Union { d: [0; 16] },
                        num: 0,
                        md_len: 0,
                    };
                    let mut out = [0u8; 64];
                    assert_eq!(SHA512_Init(&mut c), 1);
                    assert_eq!(SHA512_Update(&mut c, input.as_ptr(), at), 1);
                    assert_eq!(
                        SHA512_Update(&mut c, input.as_ptr().add(at), input.len() - at),
                        1
                    );
                    assert_eq!(SHA512_Final(out.as_mut_ptr(), &mut c), 1);
                    assert_eq!(hex(&out), want, "sha512 {input:?} split at {at}");
                }
            }
        }
    }
}
