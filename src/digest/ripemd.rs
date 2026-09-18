//! Phase 8.1a — `crypto/ripemd/`: RIPEMD-160.
//!
//! Transcribed from `crypto/ripemd/rmd_dgst.c` (the compression function),
//! `crypto/ripemd/rmd_one.c` (the one-shot), `crypto/ripemd/rmd_local.h` (the round
//! functions, the initial words and the register macro) and `crypto/ripemd/rmdconst.h` (the
//! four message-order tables and the two key schedules), over [`crate::digest::md32`].
//!
//! ## Two lines of sixteen steps, not two halves of one
//!
//! RIPEMD-160's distinctive structure is that the message block is compressed **twice**, by
//! two independent lines that share the initial state and nothing else:
//!
//! * the *left* line runs `F1, F2, F3, F4, F5` over `WL`/`SL` with `KL`;
//! * the *right* line runs `F5, F4, F3, F2, F1` over `WR`/`SR` with `KR`;
//! * and the two are combined word by word at the end, each output word taking one word from
//!   each line plus one of the *initial* words.
//!
//! `rmd_dgst.c` expresses that by saving the left line's five registers, reloading the
//! context, running the right line, and then writing the five combined values — and the
//! order of those five assignments is not the order of the state words, because the first
//! one is a temporary that the last reuses. This module reproduces the combine as five named
//! expressions rather than as a loop, because the reuse of the temporary is load-bearing: a
//! transcription that computed `A` first would clobber the value `E` needs.
//!
//! ## `RIPEMD160_Transform` is the collector's, and its `num` behaviour is the collector's
//!
//! The authority's `HASH_TRANSFORM` compresses one block and leaves `num`, `Nl` and `Nh`
//! alone, so a `Transform` in the middle of a message is not an `Update`. That is the
//! collector's contract (Phase 8.1a's `src/digest/md32.rs`) and this module adds nothing to
//! it.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::digest::md32::{self, load_word, Md32, MD32_CBLOCK};
use crate::digest::tables::{RIPEMD160_INIT, RMD_KL, RMD_KR, RMD_SL, RMD_SR, RMD_WL, RMD_WR};

/// `RIPEMD160_CTX` — `include/openssl/ripemd.h:37-43`.
#[repr(C)]
pub struct Ripemd160Ctx {
    /// `RIPEMD160_LONG A` — the first of the five chaining words.
    pub a: u32,
    /// `RIPEMD160_LONG B`.
    pub b: u32,
    /// `RIPEMD160_LONG C`.
    pub c: u32,
    /// `RIPEMD160_LONG D`.
    pub d: u32,
    /// `RIPEMD160_LONG E`.
    pub e: u32,
    /// `RIPEMD160_LONG Nl` — the low word of the bit length.
    pub nl: u32,
    /// `RIPEMD160_LONG Nh` — the high word.
    pub nh: u32,
    /// `RIPEMD160_LONG data[RIPEMD160_LBLOCK]` — the staging buffer.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Ripemd160Ctx, a) == 0);
    assert!(core::mem::offset_of!(Ripemd160Ctx, nl) == 20);
    assert!(core::mem::offset_of!(Ripemd160Ctx, data) == 28);
    assert!(core::mem::offset_of!(Ripemd160Ctx, num) == 92);
    assert!(core::mem::size_of::<Ripemd160Ctx>() == 96);
};

/// `F1(x,y,z)` — `crypto/ripemd/rmd_local.h:56`: `x ^ y ^ z`.
#[inline]
fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
/// `F2(x,y,z)` — `((y ^ z) & x) ^ z`.
#[inline]
fn f2(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}
/// `F3(x,y,z)` — `(~y | x) ^ z`.
#[inline]
fn f3(x: u32, y: u32, z: u32) -> u32 {
    (!y | x) ^ z
}
/// `F4(x,y,z)` — `((x ^ y) & z) ^ y`.
#[inline]
fn f4(x: u32, y: u32, z: u32) -> u32 {
    ((x ^ y) & z) ^ y
}
/// `F5(x,y,z)` — `(~z | y) ^ x`.
#[inline]
fn f5(x: u32, y: u32, z: u32) -> u32 {
    (!z | y) ^ x
}

/// `RIP1(A,B,C,D,E)`, `RIP1(E,A,B,C,D)`, … — the left line's five-step register cycle.
const LEFT_CYCLE: [usize; 5] = [0, 4, 3, 2, 1];
/// The right line's, which is the same cycle: `RIP5(A,B,C,D,E)` … `RIP5(B,C,D,E,A)`.
const RIGHT_CYCLE: [usize; 5] = [0, 4, 3, 2, 1];
/// The left line's five round functions, by step group.
const LEFT_ROUND: [fn(u32, u32, u32) -> u32; 5] = [f1, f2, f3, f4, f5];
/// The right line's five, which are the left line's in reverse order.
const RIGHT_ROUND: [fn(u32, u32, u32) -> u32; 5] = [f5, f4, f3, f2, f1];

/// One step of either line: `a += F(b,c,d) + X(w) + K; a = ROTATE(a,s) + e; c = ROTATE(c,10)`.
#[inline]
fn step(
    v: &mut [u32; 5],
    dst: usize,
    round: fn(u32, u32, u32) -> u32,
    x: &[u32; 16],
    w: usize,
    s: u32,
    k: u32,
) {
    let b = v[(dst + 1) % 5];
    let c = v[(dst + 2) % 5];
    let d = v[(dst + 3) % 5];
    let e = v[(dst + 4) % 5];
    let a = v[dst]
        .wrapping_add(round(b, c, d))
        .wrapping_add(x[w])
        .wrapping_add(k);
    v[dst] = a.rotate_left(s).wrapping_add(e);
    let c_index = (dst + 2) % 5;
    v[c_index] = v[c_index].rotate_left(10);
}

/// `ripemd160_block_data_order` — `crypto/ripemd/rmd_dgst.c:41-260`.
fn ripemd160_block(ctx: &mut Ripemd160Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * MD32_CBLOCK` readable bytes.
            *word = unsafe { load_word(data.add(i * 4), true) };
        }

        // The left line, from the context's state.
        let mut left = [ctx.a, ctx.b, ctx.c, ctx.d, ctx.e];
        for i in 0..80 {
            step(
                &mut left,
                LEFT_CYCLE[i % 5],
                LEFT_ROUND[i / 16],
                &x,
                RMD_WL[i],
                RMD_SL[i],
                RMD_KL[i / 16],
            );
        }

        // The right line, from the *same* initial state.
        let mut right = [ctx.a, ctx.b, ctx.c, ctx.d, ctx.e];
        for i in 0..80 {
            step(
                &mut right,
                RIGHT_CYCLE[i % 5],
                RIGHT_ROUND[i / 16],
                &x,
                RMD_WR[i],
                RMD_SR[i],
                RMD_KR[i / 16],
            );
        }

        // `rmd_dgst.c:236-241`, whose five assignments are not in state order and whose first
        // value is the temporary the last one reuses.
        let (a_l, b_l, c_l, d_l, e_l) = (left[0], left[1], left[2], left[3], left[4]);
        let (a_r, b_r, c_r, d_r, e_r) = (right[0], right[1], right[2], right[3], right[4]);
        let t = ctx.b.wrapping_add(c_l).wrapping_add(d_r);
        ctx.b = ctx.c.wrapping_add(d_l).wrapping_add(e_r);
        ctx.c = ctx.d.wrapping_add(e_l).wrapping_add(a_r);
        ctx.d = ctx.e.wrapping_add(a_l).wrapping_add(b_r);
        ctx.e = ctx.a.wrapping_add(b_l).wrapping_add(c_r);
        ctx.a = t;

        // SAFETY: `num >= 1`, so advancing one block stays inside the caller's region.
        data = unsafe { data.add(MD32_CBLOCK) };
        num -= 1;
    }
}

impl Md32 for Ripemd160Ctx {
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
        ripemd160_block(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `crypto/ripemd/rmd_local.h`'s `HASH_MAKE_STRING`: five little-endian words.
        // SAFETY: the caller guaranteed twenty writable bytes at `md`.
        unsafe {
            md32::store_word(md, self.a, true);
            md32::store_word(md.add(4), self.b, true);
            md32::store_word(md.add(8), self.c, true);
            md32::store_word(md.add(12), self.d, true);
            md32::store_word(md.add(16), self.e, true);
        }
        1
    }
}

/// `int RIPEMD160_Init(RIPEMD160_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<Ripemd160Ctx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160_Init(c: *mut Ripemd160Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Ripemd160Ctx>());
        (*c).a = RIPEMD160_INIT[0];
        (*c).b = RIPEMD160_INIT[1];
        (*c).c = RIPEMD160_INIT[2];
        (*c).d = RIPEMD160_INIT[3];
        (*c).e = RIPEMD160_INIT[4];
    }
    1
}

/// `int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data, size_t len)`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160_Update(
    c: *mut Ripemd160Ctx,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data, len) }
}

/// `int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c)`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 20 bytes.
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160_Final(md: *mut u8, c: *mut Ripemd160Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void RIPEMD160_Transform(RIPEMD160_CTX *c, const unsigned char *b)`.
///
/// # Safety
/// `c` must be a live context; `b` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160_Transform(c: *mut Ripemd160Ctx, b: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, b) };
}

/// `unsigned char *RIPEMD160(const unsigned char *d, size_t n, unsigned char *md)` —
/// `crypto/ripemd/rmd_one.c`.
///
/// # Safety
/// `d` readable for `n` bytes; `md` NULL or writable for 20 bytes.
#[no_mangle]
pub unsafe extern "C" fn RIPEMD160(d: *const u8, n: usize, md: *mut u8) -> *mut u8 {
    static mut STATIC_MD: [u8; 20] = [0; 20];
    // SAFETY: the address of a `static mut` in this file, as in `MD5`.
    let md = if md.is_null() {
        ptr::addr_of_mut!(STATIC_MD).cast::<u8>()
    } else {
        md
    };
    let mut c = Ripemd160Ctx {
        a: 0,
        b: 0,
        c: 0,
        d: 0,
        e: 0,
        nl: 0,
        nh: 0,
        data: [0; 16],
        num: 0,
    };
    // SAFETY: `c` is a live local.
    unsafe {
        if RIPEMD160_Init(ptr::addr_of_mut!(c)) == 0 {
            return ptr::null_mut();
        }
        RIPEMD160_Update(ptr::addr_of_mut!(c), d, n);
        RIPEMD160_Final(md, ptr::addr_of_mut!(c));
        ptr::write_bytes(
            ptr::addr_of_mut!(c).cast::<u8>(),
            0,
            core::mem::size_of::<Ripemd160Ctx>(),
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RIPEMD-160's published vectors, including the 56-byte message that is exactly the
    /// length where the padding takes the extra block.
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (
            b"message digest",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "b0e20b6e3116640286ed3a87a5713079b21f5189",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = Ripemd160Ctx {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            nl: 0,
            nh: 0,
            data: [0; 16],
            num: 0,
        };
        let mut out = [0u8; 20];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(RIPEMD160_Init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(RIPEMD160_Update(&mut c, data.as_ptr(), at), 1);
                    assert_eq!(
                        RIPEMD160_Update(&mut c, data.as_ptr().add(at), data.len() - at),
                        1
                    );
                }
                None => assert_eq!(RIPEMD160_Update(&mut c, data.as_ptr(), data.len()), 1),
            }
            assert_eq!(RIPEMD160_Final(out.as_mut_ptr(), &mut c), 1);
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
