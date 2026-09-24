//! Phase 8.1a — `crypto/md4/`: MD4, RFC 1186.
//!
//! Transcribed from `crypto/md4/md4_dgst.c` (the compression function) and
//! `crypto/md4/md4_one.c` (the one-shot) over [`crate::digest::md32`]. MD4 and MD5 share a
//! context layout and a collector, so the module's shape is `src/digest/md5.rs`'s and the
//! three differences are the whole of this file:
//!
//! * **Three rounds, not four, and no message-schedule round.** MD4's third round uses the
//!   message words in the sequence `0, 8, 4, 12, 2, 10, 6, 14, …`, which is why it has one
//!   layer of round constants and MD5 has three.
//! * **The round functions are the RFC's own** — `(x & y) | (~x & z)`,
//!   `(x & y) | (x & z) | (y & z)` and `x ^ y ^ z` — and not Wei Dai's simplified spellings,
//!   because `md4_local.h` does not carry those. They are not interchangeable with MD5's:
//!   MD4's `F` is the "choose" function and MD5's is the differently-grouped form of it,
//!   and the two agree only for `F`, which is exactly the kind of near-miss a transcription
//!   can make silently.
//! * **Round 1's constant is zero.** The authority writes it as a literal `0` in the
//!   invocation, which is why the generated table has three bands: open zeros, then
//!   `0x5a827999`, then `0x6ed9eba1`.
//!
//! The message word, rotation and constant of every one of the forty-eight invocations come
//! from [`crate::digest::tables`], derived by `gen_phase8_tables.py` from those invocation
//! lines; the register cycle is MD5's (`A, D, C, B`).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::digest::md32::{self, load_word, Md32, MD32_CBLOCK};
use crate::digest::tables::{MD4_K, MD4_ROT, MD4_WORD};

/// `MD4_CTX` — `include/openssl/md4.h:39-45`. The same field order as `MD5_CTX`, which the
/// authority's own headers make explicit by giving the two the same members in the same
/// order.
#[repr(C)]
pub struct Md4Ctx {
    /// `MD4_LONG A` — the first of the four chaining words.
    pub a: u32,
    /// `MD4_LONG B`.
    pub b: u32,
    /// `MD4_LONG C`.
    pub c: u32,
    /// `MD4_LONG D`.
    pub d: u32,
    /// `MD4_LONG Nl` — the low word of the bit length.
    pub nl: u32,
    /// `MD4_LONG Nh` — the high word.
    pub nh: u32,
    /// `MD4_LONG data[MD4_LBLOCK]` — the staging buffer, written as bytes.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Md4Ctx, a) == 0);
    assert!(core::mem::offset_of!(Md4Ctx, nl) == 16);
    assert!(core::mem::offset_of!(Md4Ctx, data) == 24);
    assert!(core::mem::offset_of!(Md4Ctx, num) == 88);
    assert!(core::mem::size_of::<Md4Ctx>() == 92);
};

/// `F(x,y,z)` — `crypto/md4/md4_local.h`: `(x & y) | (~x & z)`.
#[inline]
fn f_round(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
/// `G(x,y,z)` — `(x & y) | (x & z) | (y & z)`.
#[inline]
fn g_round(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
/// `H(x,y,z)` — `x ^ y ^ z`.
#[inline]
fn h_round(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// `R0(A,B,C,D)`, `R0(D,A,B,C)`, … — MD5's cycle, which MD4's invocations use as well.
const DESTINATION: [usize; 4] = [0, 3, 2, 1];

/// `F`, `G`, `H` by round.
const ROUND: [fn(u32, u32, u32) -> u32; 3] = [f_round, g_round, h_round];

/// `void md4_block_data_order(MD4_CTX *c, const void *data_, size_t num)` —
/// `crypto/md4/md4_dgst.c:41-130`, the `HASH_BLOCK_DATA_ORDER` the collector's `HASH_UPDATE`
/// calls. The Rust shape takes `&mut Md4Ctx` where the authority takes `MD4_CTX *`, because the
/// context's methods are the only way the collector reaches it; the name is the authority's so
/// that `prerequisite_gate.py`'s `unwired_function_in_the_current_stratum` sees it wired.
fn md4_block_data_order(ctx: &mut Md4Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * MD32_CBLOCK` readable bytes.
            *word = unsafe { load_word(data.add(i * 4), true) };
        }

        let mut v = [ctx.a, ctx.b, ctx.c, ctx.d];
        for i in 0..48 {
            let dst = DESTINATION[i % 4];
            let b = v[(dst + 1) % 4];
            let c = v[(dst + 2) % 4];
            let d = v[(dst + 3) % 4];
            // `R0/R1/R2` in `crypto/md4/md4_local.h` end at the rotate: unlike MD5's
            // `ROUND`, which adds `b` back afterwards, MD4's macro is
            // `a = ROTATE(a + k + t + F(b,c,d), s)` and nothing more.
            let mixed = v[dst]
                .wrapping_add(ROUND[i / 16](b, c, d))
                .wrapping_add(x[MD4_WORD[i]])
                .wrapping_add(MD4_K[i]);
            v[dst] = mixed.rotate_left(MD4_ROT[i]);
        }
        ctx.a = ctx.a.wrapping_add(v[0]);
        ctx.b = ctx.b.wrapping_add(v[1]);
        ctx.c = ctx.c.wrapping_add(v[2]);
        ctx.d = ctx.d.wrapping_add(v[3]);

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(MD32_CBLOCK) };
        num -= 1;
    }
}

impl Md32 for Md4Ctx {
    const LITTLE_ENDIAN: bool = true;

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
        md4_block_data_order(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `HASH_MAKE_STRING` — `crypto/md4/md4_local.h`: four little-endian words.
        // SAFETY: the caller guaranteed sixteen writable bytes at `md`.
        unsafe {
            md32::store_word(md, self.a, true);
            md32::store_word(md.add(4), self.b, true);
            md32::store_word(md.add(8), self.c, true);
            md32::store_word(md.add(12), self.d, true);
        }
        1
    }
}

/// `int MD4_Init(MD4_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Md4Ctx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn MD4_Init(c: *mut Md4Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Md4Ctx>());
        (*c).a = 0x6745_2301;
        (*c).b = 0xefcd_ab89;
        (*c).c = 0x98ba_dcfe;
        (*c).d = 0x1032_5476;
    }
    1
}

/// `int MD4_Update(MD4_CTX *c, const void *data, size_t len)`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn MD4_Update(c: *mut Md4Ctx, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data.cast::<u8>(), len) }
}

/// `int MD4_Final(unsigned char *md, MD4_CTX *c)`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn MD4_Final(md: *mut u8, c: *mut Md4Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void MD4_Transform(MD4_CTX *c, const unsigned char *b)`.
///
/// # Safety
/// `c` must be a live context; `b` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn MD4_Transform(c: *mut Md4Ctx, b: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, b) };
}

/// `unsigned char *MD4(const unsigned char *d, size_t n, unsigned char *md)` —
/// `crypto/md4/md4_one.c`.
///
/// # Safety
/// `d` readable for `n` bytes; `md` NULL or writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn MD4(d: *const u8, n: usize, md: *mut u8) -> *mut u8 {
    static mut STATIC_MD: [u8; 16] = [0; 16];
    // SAFETY: the address of a `static mut` in this file, as in `MD5`.
    let md = if md.is_null() {
        ptr::addr_of_mut!(STATIC_MD).cast::<u8>()
    } else {
        md
    };
    let mut c = Md4Ctx {
        a: 0,
        b: 0,
        c: 0,
        d: 0,
        nl: 0,
        nh: 0,
        data: [0; 16],
        num: 0,
    };
    // SAFETY: `c` is a live local.
    unsafe {
        if MD4_Init(ptr::addr_of_mut!(c)) == 0 {
            return ptr::null_mut();
        }
        MD4_Update(ptr::addr_of_mut!(c), d.cast(), n);
        MD4_Final(md, ptr::addr_of_mut!(c));
        ptr::write_bytes(
            ptr::addr_of_mut!(c).cast::<u8>(),
            0,
            core::mem::size_of::<Md4Ctx>(),
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1186's own vectors, and RFC 1320's two extra.
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = Md4Ctx {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            nl: 0,
            nh: 0,
            data: [0; 16],
            num: 0,
        };
        let mut out = [0u8; 16];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(MD4_Init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(MD4_Update(&mut c, data.as_ptr().cast(), at), 1);
                    assert_eq!(
                        MD4_Update(&mut c, data.as_ptr().add(at).cast(), data.len() - at),
                        1
                    );
                }
                None => assert_eq!(MD4_Update(&mut c, data.as_ptr().cast(), data.len()), 1),
            }
            assert_eq!(MD4_Final(out.as_mut_ptr(), &mut c), 1);
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
            assert_eq!(digest(msg, None), digest(msg, Some(len / 2)));
        }
    }
}
