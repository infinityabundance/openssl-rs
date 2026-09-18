//! Phase 8.1a — `crypto/whrlpool/`: Whirlpool.
//!
//! Transcribed from `crypto/whrlpool/wp_dgst.c` (the collector, the bit-oriented update and
//! the finalisation) and `crypto/whrlpool/wp_block.c` (the block function), with the two
//! hundred and fifty-six table entries and the ten round constants derived by
//! `forensics/tools/gen_phase8_tables.py` into [`crate::digest::tables`].
//!
//! ## It is not a `md32` construction, and the reason is the bit counter
//!
//! `WHIRLPOOL_Update` takes **bytes** and `WHIRLPOOL_BitUpdate` takes **bits**, and the
//! latter is the primitive: `Update` chunks its input and calls `BitUpdate` with `bytes * 8`.
//! The counter is a 256-bit integer in `bitlen[4]`, so there is no `Nl`/`Nh` pair and no place
//! in `include/crypto/md32_common.h` for it. This module therefore carries its own collector,
//! which is `wp_dgst.c`'s.
//!
//! ## The table's byte shift, made explicit
//!
//! `wp_block.c`'s `C0`..`C7` macros do not index seven tables: they read *one* table at seven
//! one-byte shifts, through an unaligned `u64` view of a row that the source's own `LL` macro
//! duplicates for exactly that purpose. The source calls this its "endian-neutral
//! representation". On this profile's little-endian host, `Ck(K, i)` is the table entry
//! indexed by byte `k` of word `i`, rotated right by `8k`; that identity is what
//! [`ck`] reproduces, and it is the source's device written out rather than an assumption
//! about the host, because a rotate is the same operation on either endianness.
//!
//! ## The block function is the authority's small-footprint arm
//!
//! `wp_block.c` carries two arms of `whirlpool_block`, and `OPENSSL_SMALL_FOOTPRINT` selects
//! the shorter one — which *is* the arm written here, because it is the same permutation over
//! the same table and is the one a reader can check against the source line for line. The
//! unrolled arm exists for speed, which is Phase 19's business (`docs/RELEASE_GATES.md`).
//!
//! ## `WHIRLPOOL_Update`'s chunking is observable
//!
//! Its chunk size is `((size_t)1) << (sizeof(size_t) * 8 - 4)` — `1 << 60` on this profile —
//! and each chunk goes through `WHIRLPOOL_BitUpdate` with `chunk * 8` bits. The number is not
//! a performance detail: it decides how many times the bit-oriented path is entered, and
//! therefore whether `bitlen[0]`'s overflow arm and the `inpgap == 0 && bitrem == 0` fast path
//! agree with a single call over the same bytes. `RT-DIGEST` drives a message that is a
//! multiple of the block size, which is where the two paths meet.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::digest::tables::{WP_RC, WP_TABLE};

/// `WHIRLPOOL_BBLOCK` — `include/openssl/whrlpool.h:31`. The block size **in bits**.
const WHIRLPOOL_BBLOCK: usize = 512;
/// `WHIRLPOOL_COUNTER` — `include/openssl/whrlpool.h:32`. The counter's width in bytes.
const WHIRLPOOL_COUNTER: usize = 256 / 8;
/// `WHIRLPOOL_DIGEST_LENGTH` — `include/openssl/whrlpool.h:26`. Sixty-four bytes.
pub(crate) const WHIRLPOOL_DIGEST_LENGTH: usize = 512 / 8;

/// `WHIRLPOOL_CTX` — `include/openssl/whrlpool.h:34-42`.
///
/// `H` is the authority's `union { unsigned char c[64]; double q[8]; }`. It is written as the
/// byte array alone here because the construction **only ever reads it as bytes** — the block
/// function's `S` and `K` are byte-wise XORs of `H` and the input, and `WHIRLPOOL_Final`
/// copies `H.c` — and because the layout is identical either way: the `double` member's
/// eight-byte alignment is what puts `bitlen` at offset 136, and `size_t`'s alignment does the
/// same. The offsets below are the assertion of that.
#[repr(C)]
pub struct WhirlpoolCtx {
    /// The `union { c[64]; q[8]; }` state, as its `c` member.
    pub h: [u8; 64],
    /// `unsigned char data[WHIRLPOOL_BBLOCK / 8]` — the staging block.
    pub data: [u8; WHIRLPOOL_BBLOCK / 8],
    /// `unsigned int bitoff` — the bit offset into `data`.
    pub bitoff: u32,
    /// `size_t bitlen[WHIRLPOOL_COUNTER / sizeof(size_t)]` — the 256-bit bit count.
    pub bitlen: [usize; WHIRLPOOL_COUNTER / core::mem::size_of::<usize>()],
}

const _: () = {
    assert!(core::mem::offset_of!(WhirlpoolCtx, h) == 0);
    assert!(core::mem::offset_of!(WhirlpoolCtx, data) == 64);
    assert!(core::mem::offset_of!(WhirlpoolCtx, bitoff) == 128);
    assert!(core::mem::offset_of!(WhirlpoolCtx, bitlen) == 136);
    assert!(core::mem::size_of::<WhirlpoolCtx>() == 168);
};

/// `Ck(K, i)` — the table entry selected by byte `k` of word `i`, rotated right by `8k`.
///
/// See the module doc for why this is the `Cx.c + k` unaligned read.
#[inline]
fn ck(k: usize, i: usize, word: &[u8; 64]) -> u64 {
    WP_TABLE[word[i * 8 + k] as usize].rotate_right(8 * k as u32)
}

/// `whirlpool_block` — `crypto/whrlpool/wp_block.c:496`, its `OPENSSL_SMALL_FOOTPRINT` arm.
fn whirlpool_block(ctx: &mut WhirlpoolCtx, mut p: *const u8, mut n: usize) {
    while n > 0 {
        let mut s = [0u8; 64];
        let mut k = [0u8; 64];
        for i in 0..64 {
            // SAFETY: the caller guaranteed `n` readable blocks, so `p` is readable for 64
            // bytes on every iteration.
            let input = unsafe { *p.add(i) };
            s[i] = ctx.h[i] ^ input;
            k[i] = ctx.h[i];
        }

        for round in 0..10 {
            let mut l = [0u64; 8];
            for i in 0..8 {
                let mut v = if i == 0 { WP_RC[round] } else { 0 };
                for kk in 0..8 {
                    v ^= ck(kk, (i + 8 - kk) % 8, &k);
                }
                l[i] = v;
            }
            for i in 0..8 {
                k[i * 8..i * 8 + 8].copy_from_slice(&l[i].to_le_bytes());
            }
            for i in 0..8 {
                for kk in 0..8 {
                    l[i] ^= ck(kk, (i + 8 - kk) % 8, &s);
                }
            }
            for i in 0..8 {
                s[i * 8..i * 8 + 8].copy_from_slice(&l[i].to_le_bytes());
            }
        }

        for i in 0..64 {
            // SAFETY: as above.
            let input = unsafe { *p.add(i) };
            ctx.h[i] ^= s[i] ^ input;
        }

        // SAFETY: `n >= 1`, so advancing one block stays inside the caller's region.
        p = unsafe { p.add(64) };
        n -= 1;
    }
}

/// `int WHIRLPOOL_Init(WHIRLPOOL_CTX *c)`.
///
/// # Safety
/// `c` must be writable for `size_of::<WhirlpoolCtx>()` bytes, or NULL, in which case the
/// authority dereferences it and this does too.
#[no_mangle]
pub unsafe extern "C" fn WHIRLPOOL_Init(c: *mut WhirlpoolCtx) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<WhirlpoolCtx>()) };
    1
}

/// `int WHIRLPOOL_Update(WHIRLPOOL_CTX *c, const void *inp, size_t bytes)` —
/// `crypto/whrlpool/wp_dgst.c:68-86`.
///
/// # Safety
/// `c` must be a live initialised context; `inp` readable for `bytes` bytes.
#[no_mangle]
pub unsafe extern "C" fn WHIRLPOOL_Update(
    c: *mut WhirlpoolCtx,
    inp: *const u8,
    bytes: usize,
) -> c_int {
    /// `((size_t)1) << (sizeof(size_t) * 8 - 4)` — the authority's chunk, `1 << 60` here.
    const CHUNK: usize = 1usize << (core::mem::size_of::<usize>() * 8 - 4);

    let mut inp = inp;
    let mut bytes = bytes;
    while bytes >= CHUNK {
        // SAFETY: the caller's contract, and the chunk is within the readable region.
        unsafe { WHIRLPOOL_BitUpdate(c, inp, CHUNK * 8) };
        bytes -= CHUNK;
        // SAFETY: `CHUNK <= bytes` before the subtraction.
        inp = unsafe { inp.add(CHUNK) };
    }
    if bytes != 0 {
        // SAFETY: `bytes < CHUNK` and `inp` is readable for `bytes`.
        unsafe { WHIRLPOOL_BitUpdate(c, inp, bytes * 8) };
    }
    1
}

/// `void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c, const void *inp, size_t bits)` —
/// `crypto/whrlpool/wp_dgst.c:88-215`.
///
/// The `goto reconsider` in the authority's bit-oriented arm is a labelled `continue` here:
/// after the `bitrem == inpgap` case consumes a partial byte and aligns the stream, the
/// byte-oriented fast path becomes reachable again and the source re-tests it.
///
/// `inp[0] << inpgap | inp[1] >> (8 - inpgap)` is computed in 32 bits rather than in `u8`,
/// because C's integer promotion makes `inp[1] >> 8` zero where a `u8` shift is undefined;
/// `inpgap` is zero exactly when the stream is byte-aligned, which is the case the
/// byte-oriented arm above has already taken, so the shift reaches 8 only from the fallback.
///
/// # Safety
/// `c` must be a live initialised context; `inp` readable for the bytes `bits` touches.
#[no_mangle]
pub unsafe extern "C" fn WHIRLPOOL_BitUpdate(c: *mut WhirlpoolCtx, inp: *const u8, bits: usize) {
    let mut inp = inp;
    let mut bits = bits;
    // SAFETY: `c` is live.
    let mut bitoff = unsafe { (*c).bitoff } as usize;
    let mut bitrem = bitoff % 8;
    let mut inpgap = (8 - (bits % 8)) & 7;

    // The 256-bit counter's carry. `bitlen[0] += bits` and then a ripple through the rest,
    // which is what "natural size of CPU register" buys the authority.
    // SAFETY: `c` is live.
    unsafe {
        (*c).bitlen[0] = (*c).bitlen[0].wrapping_add(bits);
    }
    // SAFETY: `c` is live.
    if unsafe { (*c).bitlen[0] } < bits {
        let mut n = 1usize;
        loop {
            // SAFETY: `c` is live and `n < 4` — the counter is four `size_t`s.
            unsafe {
                (*c).bitlen[n] = (*c).bitlen[n].wrapping_add(1);
            }
            // SAFETY: as above.
            if unsafe { (*c).bitlen[n] } != 0 {
                break;
            }
            n += 1;
            if n >= WHIRLPOOL_COUNTER / core::mem::size_of::<usize>() {
                break;
            }
        }
    }

    'reconsider: loop {
        if inpgap == 0 && bitrem == 0 {
            // The byte-oriented arm: whole blocks go straight to the block function, and a
            // partial one is staged.
            while bits != 0 {
                // SAFETY: `c` is live.
                let c_data = unsafe { (*c).data.as_mut_ptr() };
                let blocks = bits / WHIRLPOOL_BBLOCK;
                if bitoff == 0 && blocks != 0 {
                    // SAFETY: `c` is live; `inp` is readable for `blocks` blocks.
                    unsafe { whirlpool_block(&mut *c, inp, blocks) };
                    // SAFETY: as above.
                    inp = unsafe { inp.add(blocks * WHIRLPOOL_BBLOCK / 8) };
                    bits %= WHIRLPOOL_BBLOCK;
                } else {
                    let byteoff = bitoff / 8;
                    bitrem = WHIRLPOOL_BBLOCK - bitoff;
                    if bits >= bitrem {
                        bits -= bitrem;
                        bitrem /= 8;
                        // SAFETY: the staging block is 64 bytes and `byteoff + bitrem <= 64`.
                        unsafe { ptr::copy_nonoverlapping(inp, c_data.add(byteoff), bitrem) };
                        // SAFETY: `inp` is readable for at least `bitrem` bytes here.
                        inp = unsafe { inp.add(bitrem) };
                        // SAFETY: `c` is live and the staging block holds a full block.
                        unsafe { whirlpool_block(&mut *c, c_data, 1) };
                        bitoff = 0;
                    } else {
                        // SAFETY: the staging block is 64 bytes and `byteoff + bits/8 <= 64`.
                        unsafe {
                            ptr::copy_nonoverlapping(inp, c_data.add(byteoff), bits / 8);
                        };
                        bitoff += bits;
                        bits = 0;
                    }
                    // SAFETY: `c` is live.
                    unsafe { (*c).bitoff = bitoff as u32 };
                }
            }
            break;
        } else {
            while bits != 0 {
                let byteoff = bitoff / 8;
                // SAFETY: `c` is live.
                let c_data = unsafe { (*c).data.as_mut_ptr() };
                if bitrem == inpgap {
                    // SAFETY: the byte is within the staging block and `inp` is readable for
                    // the byte this arm consumes.
                    unsafe {
                        *c_data.add(byteoff) |= *inp & (0xffu8 >> inpgap);
                    }
                    inpgap = 8 - inpgap;
                    bitoff += inpgap;
                    bitrem = 0;
                    bits -= inpgap;
                    inpgap = 0;
                    // SAFETY: `inp` is readable for the byte just consumed.
                    inp = unsafe { inp.add(1) };
                    if bitoff == WHIRLPOOL_BBLOCK {
                        // SAFETY: `c` is live and the staging block holds a full block.
                        unsafe { whirlpool_block(&mut *c, c_data, 1) };
                        bitoff = 0;
                    }
                    // SAFETY: `c` is live.
                    unsafe { (*c).bitoff = bitoff as u32 };
                    continue 'reconsider;
                } else if bits > 8 {
                    // SAFETY: `bits > 8`, so `inp[1]` is readable.
                    let mut b = unsafe {
                        ((*inp as u32) << inpgap) | ((*inp.add(1) as u32) >> (8 - inpgap))
                    };
                    b &= 0xff;
                    if bitrem != 0 {
                        // SAFETY: the byte is within the staging block.
                        unsafe {
                            *c_data.add(byteoff) |= (b >> bitrem) as u8;
                        }
                    } else {
                        // SAFETY: as above.
                        unsafe {
                            *c_data.add(byteoff) = b as u8;
                        }
                    }
                    bitoff += 8;
                    bits -= 8;
                    // SAFETY: `inp` is readable for the byte just consumed.
                    inp = unsafe { inp.add(1) };
                    let mut byteoff = byteoff + 1;
                    if bitoff >= WHIRLPOOL_BBLOCK {
                        // SAFETY: `c` is live and the staging block holds a full block.
                        unsafe { whirlpool_block(&mut *c, c_data, 1) };
                        byteoff = 0;
                        bitoff %= WHIRLPOOL_BBLOCK;
                    }
                    if bitrem != 0 {
                        // SAFETY: the byte is within the staging block.
                        unsafe {
                            *c_data.add(byteoff) = (b << (8 - bitrem)) as u8;
                        }
                    }
                } else {
                    // SAFETY: `inp` is readable for the byte this arm consumes.
                    let mut b = unsafe { (*inp as u32) << inpgap };
                    b &= 0xff;
                    let mut byteoff = byteoff;
                    if bitrem != 0 {
                        // SAFETY: the byte is within the staging block.
                        unsafe {
                            *c_data.add(byteoff) |= (b >> bitrem) as u8;
                        }
                        byteoff += 1;
                    } else {
                        // SAFETY: as above.
                        unsafe {
                            *c_data.add(byteoff) = b as u8;
                        }
                        byteoff += 1;
                    }
                    bitoff += bits;
                    if bitoff == WHIRLPOOL_BBLOCK {
                        // SAFETY: `c` is live and the staging block holds a full block.
                        unsafe { whirlpool_block(&mut *c, c_data, 1) };
                        byteoff = 0;
                        bitoff %= WHIRLPOOL_BBLOCK;
                    }
                    if bitrem != 0 {
                        // SAFETY: the byte is within the staging block.
                        unsafe {
                            *c_data.add(byteoff) = (b << (8 - bitrem)) as u8;
                        }
                    }
                    bits = 0;
                }
                // SAFETY: `c` is live.
                unsafe { (*c).bitoff = bitoff as u32 };
            }
            break;
        }
    }
}

/// `int WHIRLPOOL_Final(unsigned char *md, WHIRLPOOL_CTX *c)` —
/// `crypto/whrlpool/wp_dgst.c:217-256`.
///
/// # Safety
/// `c` must be a live initialised context; `md` NULL or writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn WHIRLPOOL_Final(md: *mut u8, c: *mut WhirlpoolCtx) -> c_int {
    // SAFETY: `c` is live.
    let mut bitoff = unsafe { (*c).bitoff } as usize;
    let mut byteoff = bitoff / 8;
    bitoff %= 8;
    // SAFETY: the byte is within the staging block.
    unsafe {
        let data = (*c).data.as_mut_ptr();
        if bitoff != 0 {
            *data.add(byteoff) |= 0x80u8 >> bitoff;
        } else {
            *data.add(byteoff) = 0x80;
        }
    }
    byteoff += 1;

    // `WHIRLPOOL_BBLOCK / 8 - WHIRLPOOL_COUNTER` is 32: the staging block reserves its last
    // thirty-two bytes for the counter.
    const COUNTER_AT: usize = WHIRLPOOL_BBLOCK / 8 - WHIRLPOOL_COUNTER;
    // SAFETY: `c` is live.
    let data = unsafe { (*c).data.as_mut_ptr() };
    if byteoff > COUNTER_AT {
        if byteoff < WHIRLPOOL_BBLOCK / 8 {
            // SAFETY: `byteoff < 64`, so the range is inside the staging block.
            unsafe { ptr::write_bytes(data.add(byteoff), 0, WHIRLPOOL_BBLOCK / 8 - byteoff) };
        }
        // SAFETY: `c` is live and the staging block holds a full block.
        unsafe { whirlpool_block(&mut *c, data, 1) };
        byteoff = 0;
    }
    if byteoff < COUNTER_AT {
        // SAFETY: `byteoff < 32`, so the range is inside the staging block.
        unsafe { ptr::write_bytes(data.add(byteoff), 0, COUNTER_AT - byteoff) };
    }

    // "smash 256-bit c->bitlen in big-endian order": the authority walks the counter
    // little-endian *within* each `size_t` and writes the words from the block's last byte
    // backwards.
    let mut p = unsafe { data.add(WHIRLPOOL_BBLOCK / 8 - 1) };
    for i in 0..WHIRLPOOL_COUNTER / core::mem::size_of::<usize>() {
        // SAFETY: `c` is live.
        let mut v = unsafe { (*c).bitlen[i] };
        for _ in 0..core::mem::size_of::<usize>() {
            // SAFETY: `p` starts at the block's last byte and walks down 32 bytes.
            unsafe {
                *p = (v & 0xff) as u8;
                p = p.sub(1);
            }
            v >>= 8;
        }
    }

    // SAFETY: `c` is live and the staging block holds a full block.
    unsafe { whirlpool_block(&mut *c, data, 1) };

    if md.is_null() {
        return 0;
    }
    // SAFETY: the caller guaranteed sixty-four writable bytes at `md`.
    unsafe { ptr::copy_nonoverlapping((*c).h.as_ptr(), md, WHIRLPOOL_DIGEST_LENGTH) };
    // `OPENSSL_cleanse(c, sizeof(*c))`.
    // SAFETY: `c` is live.
    unsafe { ptr::write_bytes(c.cast::<u8>(), 0, core::mem::size_of::<WhirlpoolCtx>()) };
    1
}

/// `unsigned char *WHIRLPOOL(const void *inp, size_t bytes, unsigned char *md)` —
/// `crypto/whrlpool/wp_dgst.c:253-266`.
///
/// # Safety
/// `inp` readable for `bytes` bytes; `md` NULL or writable for 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn WHIRLPOOL(inp: *const u8, bytes: usize, md: *mut u8) -> *mut u8 {
    static mut STATIC_MD: [u8; WHIRLPOOL_DIGEST_LENGTH] = [0; WHIRLPOOL_DIGEST_LENGTH];
    // SAFETY: the address of a `static mut` in this file, as in `MD5`.
    let md = if md.is_null() {
        ptr::addr_of_mut!(STATIC_MD).cast::<u8>()
    } else {
        md
    };
    let mut ctx = WhirlpoolCtx {
        h: [0; 64],
        data: [0; 64],
        bitoff: 0,
        bitlen: [0; 4],
    };
    // SAFETY: `ctx` is a live local.
    unsafe {
        WHIRLPOOL_Init(ptr::addr_of_mut!(ctx));
        WHIRLPOOL_Update(ptr::addr_of_mut!(ctx), inp, bytes);
        WHIRLPOOL_Final(md, ptr::addr_of_mut!(ctx));
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NESSIE submission's own vectors.
    const VECTORS: [(&[u8], &str); 5] = [
        (
            b"",
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        ),
        (
            b"a",
            "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
        ),
        (
            b"abc",
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
        ),
        (
            b"message digest",
            "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b",
        ),
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn digest(data: &[u8], bits: Option<usize>) -> String {
        let mut ctx = WhirlpoolCtx {
            h: [0; 64],
            data: [0; 64],
            bitoff: 0,
            bitlen: [0; 4],
        };
        let mut out = [0u8; 64];
        // SAFETY: every pointer below is a live local of this test.
        unsafe {
            assert_eq!(WHIRLPOOL_Init(&mut ctx), 1);
            match bits {
                Some(b) => WHIRLPOOL_BitUpdate(&mut ctx, data.as_ptr(), b),
                None => {
                    assert_eq!(WHIRLPOOL_Update(&mut ctx, data.as_ptr(), data.len()), 1);
                }
            }
            assert_eq!(WHIRLPOOL_Final(out.as_mut_ptr(), &mut ctx), 1);
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
    fn a_bit_update_of_the_same_bytes_answers_the_same() {
        // The byte-oriented arm is only reachable through `BitUpdate` with a whole number of
        // bytes; this drives the same bytes through both spellings.
        for (input, want) in VECTORS {
            assert_eq!(digest(input, Some(input.len() * 8)), want, "{input:?}");
        }
    }

    #[test]
    fn the_padding_arms_are_where_the_counter_field_moves() {
        let mut data = [0u8; 128];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i & 0xff) as u8;
        }
        // 31 and 32 bytes are the two sides of `byteoff > 64 - 32`; 63 and 64 are the two
        // sides of the block boundary.
        for len in [31usize, 32, 33, 63, 64, 65, 96, 127, 128] {
            let msg = &data[..len];
            let one = digest(msg, None);
            assert_eq!(one.len(), 128);
            assert_eq!(one, digest(msg, Some(len * 8)));
        }
    }
}
