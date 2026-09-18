//! Phase 8.1a — `crypto/md5/`: MD5, and the shortest of the six collector users.
//!
//! RFC 1321's construction, transcribed from `crypto/md5/md5_dgst.c` (the compression
//! function) and `crypto/md5/md5_one.c` (the one-shot) over [`crate::digest::md32`], which
//! is `include/crypto/md32_common.h`.
//!
//! ## The round table is the authority's own invocation order
//!
//! `md5_dgst.c` writes sixty-four invocations of four macros, each naming four registers and
//! a message word. The register roles *rotate*: `R0(A,B,C,D,...)` is followed by
//! `R0(D,A,B,C,...)`, so the register a round writes cycles `A, D, C, B` and the compression
//! is a function of that cycle rather than of any remembered index formula. This module
//! reproduces the cycle (`DESTINATION[i % 4]`) and reads the message word, the rotation and
//! the constant from [`crate::digest::tables`], where `gen_phase8_tables.py` derived them
//! from those same invocation lines. A transcription that recalled the standard `g` formulas
//! instead would agree on every vector and differ on a mistaken recollection; this one
//! cannot, because the numbers are read rather than remembered.
//!
//! ## The layout is the authority's, and it is asserted
//!
//! `MD5_CTX` is public and passed by pointer — a caller allocates it from the installed
//! header — so the collector writes bytes into `data` and reads `Nl`/`Nh`/`num` by name. A
//! layout that drifted would put `MD5_Final`'s length field in the wrong bytes, so the
//! offsets are pinned below rather than assumed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::digest::md32::{self, load_word, Md32, MD32_CBLOCK};
use crate::digest::tables::{MD5_K, MD5_ROT, MD5_WORD};

/// `MD5_CTX` — `include/openssl/md5.h:39-45`.
#[repr(C)]
pub struct Md5Ctx {
    /// `MD5_LONG A` — the first of the four chaining words.
    pub a: u32,
    /// `MD5_LONG B`.
    pub b: u32,
    /// `MD5_LONG C`.
    pub c: u32,
    /// `MD5_LONG D`.
    pub d: u32,
    /// `MD5_LONG Nl` — the low word of the bit length.
    pub nl: u32,
    /// `MD5_LONG Nh` — the high word.
    pub nh: u32,
    /// `MD5_LONG data[MD5_LBLOCK]` — the staging buffer, written as bytes.
    pub data: [u32; 16],
    /// `unsigned int num` — bytes held in `data`.
    pub num: u32,
}

const _: () = {
    assert!(core::mem::offset_of!(Md5Ctx, a) == 0);
    assert!(core::mem::offset_of!(Md5Ctx, nl) == 16);
    assert!(core::mem::offset_of!(Md5Ctx, data) == 24);
    assert!(core::mem::offset_of!(Md5Ctx, num) == 88);
    assert!(core::mem::size_of::<Md5Ctx>() == 92);
};

/// `F(b,c,d)` — `crypto/md5/md5_local.h:48`, Wei Dai's simplification.
#[inline]
fn f_round(b: u32, c: u32, d: u32) -> u32 {
    ((c ^ d) & b) ^ d
}
/// `G(b,c,d)`.
#[inline]
fn g_round(b: u32, c: u32, d: u32) -> u32 {
    ((b ^ c) & d) ^ c
}
/// `H(b,c,d)`.
#[inline]
fn h_round(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}
/// `I(b,c,d)`.
#[inline]
fn i_round(b: u32, c: u32, d: u32) -> u32 {
    (!d | b) ^ c
}

/// `R0(A,B,C,D)`, `R0(D,A,B,C)`, … — which register each of the four invocations in a cycle
/// writes. `A`, `D`, `C`, `B` in the authority's own order.
const DESTINATION: [usize; 4] = [0, 3, 2, 1];

/// `F`, `G`, `H`, `I` by round.
const ROUND: [fn(u32, u32, u32) -> u32; 4] = [f_round, g_round, h_round, i_round];

/// `md5_block_data_order` — `crypto/md5/md5_dgst.c:41-140`.
///
/// The authority interleaves each message load with the round that consumes it; the loads
/// are hoisted here into the sixteen words they produce, which is the same value because no
/// round writes to them.
fn md5_block(ctx: &mut Md5Ctx, mut data: *const u8, mut num: usize) {
    while num > 0 {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // SAFETY: the caller guaranteed `num * MD32_CBLOCK` readable bytes, so each of
            // the sixteen four-byte words is in bounds.
            *word = unsafe { load_word(data.add(i * 4), true) };
        }

        let mut v = [ctx.a, ctx.b, ctx.c, ctx.d];
        for i in 0..64 {
            let dst = DESTINATION[i % 4];
            let b = v[(dst + 1) % 4];
            let c = v[(dst + 2) % 4];
            let d = v[(dst + 3) % 4];
            let mixed = v[dst]
                .wrapping_add(ROUND[i / 16](b, c, d))
                .wrapping_add(x[MD5_WORD[i]])
                .wrapping_add(MD5_K[i]);
            v[dst] = mixed.rotate_left(MD5_ROT[i]).wrapping_add(b);
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

impl Md32 for Md5Ctx {
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
        md5_block(self, data, num);
    }

    unsafe fn make_string(&self, md: *mut u8) -> c_int {
        // `HASH_MAKE_STRING` — `crypto/md5/md5_local.h:39-47`: four little-endian words.
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

/// `int MD5_Init(MD5_CTX *c)`.
///
/// `memset(c, 0, sizeof(*c))` and then the four `INIT_DATA_*` words: the zeroing is not
/// decoration, because `HASH_UPDATE`'s first call reads `num`.
///
/// # Safety
/// `c` must be writable for `size_of::<Md5Ctx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn MD5_Init(c: *mut Md5Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<Md5Ctx>());
        (*c).a = 0x6745_2301;
        (*c).b = 0xefcd_ab89;
        (*c).c = 0x98ba_dcfe;
        (*c).d = 0x1032_5476;
    }
    1
}

/// `int MD5_Update(MD5_CTX *c, const void *data, size_t len)`.
///
/// # Safety
/// `c` must be a live initialised context; `data` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn MD5_Update(c: *mut Md5Ctx, data: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::update(c, data, len) }
}

/// `int MD5_Final(unsigned char *md, MD5_CTX *c)`.
///
/// # Safety
/// `c` must be a live initialised context; `md` writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn MD5_Final(md: *mut u8, c: *mut Md5Ctx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { md32::finalize(md, c) }
}

/// `void MD5_Transform(MD5_CTX *c, const unsigned char *b)`.
///
/// # Safety
/// `c` must be a live context; `b` readable for one block.
#[no_mangle]
pub unsafe extern "C" fn MD5_Transform(c: *mut Md5Ctx, b: *const u8) {
    // SAFETY: the caller's contract.
    unsafe { md32::transform(c, b) };
}

/// `unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)` —
/// `crypto/md5/md5_one.c:26-56`.
///
/// The digest is written to `md`, or to the file's `static unsigned char m[16]` when `md` is
/// NULL — a static, so two calls without an explicit buffer overwrite each other's answer,
/// which is the authority's behaviour and not a defect to improve on.
///
/// # Safety
/// `d` readable for `n` bytes; `md` NULL or writable for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn MD5(d: *const u8, n: usize, md: *mut u8) -> *mut u8 {
    static mut STATIC_MD: [u8; 16] = [0; 16];
    // SAFETY: the address of a `static mut` in this file; the authority's is the same single
    // object, and no probe can call this concurrently in a way the authority allows.
    let md = if md.is_null() {
        ptr::addr_of_mut!(STATIC_MD).cast::<u8>()
    } else {
        md
    };
    let mut c = Md5Ctx {
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
        if MD5_Init(ptr::addr_of_mut!(c)) == 0 {
            return ptr::null_mut();
        }
        MD5_Update(ptr::addr_of_mut!(c), d, n);
        MD5_Final(md, ptr::addr_of_mut!(c));
        // `OPENSSL_cleanse(&c, sizeof(c))` — the context is a local, and the cleanse is what
        // stops a stack copy holding the last block.
        ptr::write_bytes(
            ptr::addr_of_mut!(c).cast::<u8>(),
            0,
            core::mem::size_of::<Md5Ctx>(),
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1321's own vectors. `RT-DIGEST` is the differential instrument; these are the
    /// cheap first line, and they are the vectors the authority's own `README` names.
    const VECTORS: [(&[u8], &str); 7] = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], split: Option<usize>) -> String {
        let mut c = Md5Ctx {
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
            assert_eq!(MD5_Init(&mut c), 1);
            match split {
                Some(at) => {
                    assert_eq!(MD5_Update(&mut c, data.as_ptr(), at), 1);
                    assert_eq!(
                        MD5_Update(&mut c, data.as_ptr().add(at), data.len() - at),
                        1
                    );
                }
                None => assert_eq!(MD5_Update(&mut c, data.as_ptr(), data.len()), 1),
            }
            assert_eq!(MD5_Final(out.as_mut_ptr(), &mut c), 1);
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
        // 55 bytes leaves room for the `0x80` and the eight-byte length; 56 does not, and
        // takes the extra block. Both are in the authority's `HASH_FINAL` as the
        // `n > HASH_CBLOCK - 8` arm, so a transcription that dropped the arm diverges here
        // and nowhere else.
        let mut data = [0u8; 128];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i & 0xff) as u8;
        }
        for len in [54usize, 55, 56, 57, 63, 64, 65, 119, 120, 128] {
            let msg = &data[..len];
            assert_eq!(digest(msg, None).len(), 32);
            assert_eq!(digest(msg, None), digest(msg, Some(len / 2)));
        }
    }

    #[test]
    fn a_zero_length_update_does_not_move_the_length() {
        let mut c = Md5Ctx {
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
            assert_eq!(MD5_Init(&mut c), 1);
            assert_eq!(MD5_Update(&mut c, ptr::null(), 0), 1);
            assert_eq!((c.nl, c.nh, c.num), (0, 0, 0));
        }
    }
}
