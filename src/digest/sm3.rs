//! Phase 8.1b — `crypto/sm3/`: SM3.
//!
//! SM3 is the OSCCA (GB/T 32905-2016) digest and is self-contained in the same way as the
//! SHA-2 family: `crypto/sm3/sm3.c` supplies `ossl_sm3_init` and the compression
//! `ossl_sm3_block_data_order`, and `crypto/sm3/sm3_local.h` includes the collector
//! `include/crypto/md32_common.h` with `DATA_ORDER_IS_BIG_ENDIAN`, so `ossl_sm3_update` and
//! `ossl_sm3_final` are the shared machine over a 64-byte block and a 32-byte digest.
//!
//! ## Why this is provider work with no export
//!
//! `include/openssl/sha.h` declares nothing for SM3 and there is no `sm3.h` in the installed
//! headers; the authority's entry points are `ossl_`-prefixed and local, exactly as D197 read.
//! The provider row (`sm3_prov.c`'s `ossl_sm3_functions`, published from `defltprov.c:145`) is
//! therefore the only surface, and `EVP_sm3` — Phase 7's — reaches this construction through it.
//! Nothing here carries `#[no_mangle]`.
//!
//! ## The unrolled authority and this loop
//!
//! `sm3.c` is an unrolled transcription of the specification: 64 `R1`/`R2` invocations that rotate
//! the eight register names and expand the message schedule one word ahead of the round that
//! consumes it. This module writes the same `RND`, `EXPAND`, `P0`/`P1`, `FF`/`GG` and `T_j`
//! arithmetic as a loop over a 68-word schedule. The values are the specification's, and
//! `RT-DIGEST` is what proves the loop form computes *this* construction's bytes rather than
//! merely *a* correct SM3.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::digest::md32::{self, Md32, MD32_CBLOCK};

/// `SM3_DIGEST_LENGTH` — `include/internal/sm3.h:21`.
pub(crate) const SM3_DIGEST_LENGTH: usize = 32;
/// `SM3_CBLOCK` — `include/internal/sm3.h:27`.
pub(crate) const SM3_CBLOCK: usize = 64;

/// `SM3_CTX` — `include/internal/sm3.h:30-36`. Eight chaining words, the two length words, the
/// 64-byte staging buffer and `num`; the collector's `HASH_*` macros are what read them.
#[repr(C)]
pub struct Sm3Ctx {
    /// `SM3_WORD A` … `H` — the chaining state.
    pub a: u32,
    /// `SM3_WORD B`.
    pub b: u32,
    /// `SM3_WORD C`.
    pub c: u32,
    /// `SM3_WORD D`.
    pub d: u32,
    /// `SM3_WORD E`.
    pub e: u32,
    /// `SM3_WORD F`.
    pub f: u32,
    /// `SM3_WORD G`.
    pub g: u32,
    /// `SM3_WORD H`.
    pub h: u32,
    /// `SM3_WORD Nl` — the low word of the bit length.
    pub nl: u32,
    /// `SM3_WORD Nh` — the high word.
    pub nh: u32,
    /// `SM3_WORD data[SM3_LBLOCK]` — the staging buffer.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Sm3Ctx, a) == 0);
    assert!(core::mem::offset_of!(Sm3Ctx, nl) == 32);
    assert!(core::mem::offset_of!(Sm3Ctx, data) == 40);
    assert!(core::mem::offset_of!(Sm3Ctx, num) == 104);
    assert!(core::mem::size_of::<Sm3Ctx>() == 108);
};

/// `SM3_A` … `SM3_H` — `crypto/sm3/sm3_local.h:124-131`.
const IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

/// `P0(X)` — `X ^ ROTATE(X, 9) ^ ROTATE(X, 17)`.
#[inline]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}
/// `P1(X)` — `X ^ ROTATE(X, 15) ^ ROTATE(X, 23)`.
#[inline]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}
/// `FF0(X,Y,Z)` — `X ^ Y ^ Z`.
#[inline]
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
/// `GG0(X,Y,Z)` is `FF0`.
#[inline]
fn gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
/// `FF1(X,Y,Z)` — `(X & Y) | ((X | Y) & Z)`.
#[inline]
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((x | y) & z)
}
/// `GG1(X,Y,Z)` — `Z ^ (X & (Y ^ Z))`.
#[inline]
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

/// `ossl_sm3_init` — `crypto/sm3/sm3.c:15-27`.
///
/// # Safety
/// `c` must be writable for `size_of::<Sm3Ctx>()` bytes.
pub(crate) unsafe fn ossl_sm3_init(c: *mut Sm3Ctx) -> c_int {
    // SAFETY: `c` is writable per the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Sm3Ctx>());
        (*c).a = IV[0];
        (*c).b = IV[1];
        (*c).c = IV[2];
        (*c).d = IV[3];
        (*c).e = IV[4];
        (*c).f = IV[5];
        (*c).g = IV[6];
        (*c).h = IV[7];
    }
    1
}

/// `ossl_sm3_block_data_order` — `crypto/sm3/sm3.c:29-195`, in loop form over the 68-word
/// schedule. The feed-forward is the authority's `ctx->A ^= A` (an XOR, not an add). The
/// authority's name is kept because `prerequisite_gate.py` joins the internal function a
/// transcribed unit owes to the name that unit gives it.
fn ossl_sm3_block_data_order(ctx: &mut Sm3Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut w = [0u32; 68];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            // SAFETY: the caller guaranteed `num * SM3_CBLOCK` readable bytes.
            *word = unsafe { md32::load_word(data.add(i * 4), false) };
        }
        // `EXPAND(W0, W7, W13, W3, W10)` — `sm3_local.h:102-103`.
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }

        let mut a = ctx.a;
        let mut b = ctx.b;
        let mut c = ctx.c;
        let mut d = ctx.d;
        let mut e = ctx.e;
        let mut f = ctx.f;
        let mut g = ctx.g;
        let mut h = ctx.h;

        for j in 0..64 {
            // `TJ` — `0x79CC4519` rotated left by `j` for rounds 0..15, `0x7A879D8A` for 16..63;
            // the authority writes the rotation mod 32 as literal constants.
            let tj = if j < 16 {
                0x79cc_4519u32
            } else {
                0x7a87_9d8au32
            }
            .rotate_left((j % 32) as u32);
            // `Wj` in the authority's `RND` call is `Wi ^ W[i+4]`.
            let wj = w[j] ^ w[j + 4];

            let a12 = a.rotate_left(12);
            let a12_sm = a12.wrapping_add(e).wrapping_add(tj);
            let ss1 = a12_sm.rotate_left(7);
            let (ff, gg) = if j < 16 {
                (ff0(a, b, c), gg0(e, f, g))
            } else {
                (ff1(a, b, c), gg1(e, f, g))
            };
            let tt1 = ff.wrapping_add(d).wrapping_add(ss1 ^ a12).wrapping_add(wj);
            let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);

            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = p0(tt2);
        }

        ctx.a ^= a;
        ctx.b ^= b;
        ctx.c ^= c;
        ctx.d ^= d;
        ctx.e ^= e;
        ctx.f ^= f;
        ctx.g ^= g;
        ctx.h ^= h;

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(MD32_CBLOCK) };
        num -= 1;
    }
}

impl Md32 for Sm3Ctx {
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
        ossl_sm3_block_data_order(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `HASH_MAKE_STRING` — `crypto/sm3/sm3_local.h:24-43`: eight big-endian words.
        let words = [
            self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h,
        ];
        for (i, word) in words.iter().enumerate() {
            // SAFETY: the caller guaranteed `SM3_DIGEST_LENGTH` writable bytes at `md`.
            unsafe { md32::store_word(md.add(i * 4), *word, false) };
        }
        1
    }
}

/// `int ossl_sm3_update(SM3_CTX *c, const void *data, size_t len)` — the collector's
/// `HASH_UPDATE`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
pub(crate) unsafe fn ossl_sm3_update(c: *mut Sm3Ctx, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data.cast::<u8>(), len) }
}

/// `int ossl_sm3_final(unsigned char *md, SM3_CTX *c)` — the collector's `HASH_FINAL`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 32 bytes.
pub(crate) unsafe fn ossl_sm3_final(md: *mut u8, c: *mut Sm3Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void ossl_sm3_transform(SM3_CTX *c, const unsigned char *data)` — the collector's
/// `HASH_TRANSFORM`, declared at `sm3_local.h:70` but not exported.
///
/// # Safety
/// `c` must be a live context; `data` readable for one block.
#[allow(dead_code)] // the provider needs no Transform; the authority declares it for symmetry
pub(crate) unsafe fn ossl_sm3_transform(c: *mut Sm3Ctx, data: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, data) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32905-2016 and the SM3 examples circulated with it.
    const VECTORS: [(&[u8], &str); 2] = [
        (
            b"abc",
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        ),
        (
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = Sm3Ctx {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            f: 0,
            g: 0,
            h: 0,
            nl: 0,
            nh: 0,
            data: [0; 16],
            num: 0,
        };
        let mut out = [0u8; SM3_DIGEST_LENGTH];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(ossl_sm3_init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(ossl_sm3_update(&mut c, data.as_ptr().cast(), at), 1);
                    assert_eq!(
                        ossl_sm3_update(&mut c, data.as_ptr().add(at).cast(), data.len() - at),
                        1
                    );
                }
                None => assert_eq!(ossl_sm3_update(&mut c, data.as_ptr().cast(), data.len()), 1),
            }
            assert_eq!(ossl_sm3_final(out.as_mut_ptr(), &mut c), 1);
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
        let mut data = [0u8; 200];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i * 5 + 11) as u8;
        }
        for len in [0usize, 1, 55, 56, 63, 64, 65, 128, 200] {
            let msg = &data[..len];
            assert_eq!(digest(msg, None), digest(msg, Some(len / 2)), "len {len}");
        }
    }
}
