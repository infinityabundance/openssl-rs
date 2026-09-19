//! Phase 8.3 — `crypto/siphash/siphash.c`, the primitive behind the default provider's `SIPHASH`
//! row.
//!
//! **Why this is not in `src/mac/`'s EVP company.** `src/mac/hmac.rs` and `src/mac/cmac.rs` are the
//! two *legacy* one-shot interfaces: they exist because the authority's `crypto/hmac/hmac.c` and
//! `crypto/cmac/cmac.c` are kept for source compatibility, and they are written over the object
//! interfaces. SipHash has no such history — `crypto/siphash/siphash.c` is a standalone primitive
//! with no `libcrypto` export at all, reached only by the provider row — so its module doc is
//! here rather than in that pair's, and its functions are `pub(crate)` with the authority's own
//! names so `gen_prerequisite_atlas.py`'s internal-symbol atlas can see them defined.
//!
//! **Nothing in this unit raises.** `siphash.c` and `siphash_prov.c` contain no `ERR_raise` on
//! this profile, which is why there is no `PROV_SIPHASH_PROV_*` site family and why
//! `gen_err_raise_sites.py` has no entry for either unit: an entry that can never change would
//! read as coverage that does not exist.
//!
//! **The three details that are easy to get wrong, and each is silent.** `hash_size == 0` means
//! "the maximum", not zero (`siphash_adjust_hash_size`), so a caller that never sets `size` gets
//! sixteen octets and not none. `SipHash_set_hash_size` may be called *after* the key, and when it
//! changes an already-initialised context it must compensate with `v1 ^= 0xee` rather than
//! re-running `SipHash_Init`. And `SIPHASH_MAX_DIGEST_SIZE` xor's `0xee` into `v1` at init and
//! `0xee` into `v2` at final, where the eight-octet form xor's `0xff` into `v2` — so the two
//! output sizes are two different constructions, not one construction truncated.
//!
//! SPDX-License-Identifier: Apache-2.0

// The names in this file are the authority's, and `gen_prerequisite_atlas.py`'s internal-symbol
// atlas matches `crypto/siphash/siphash.c`'s own `SipHash_*` spellings one for one, so they are kept
// verbatim rather than snake-cased. The precedent is `src/asn1/bitstr.rs`'s
// `ossl_i2c_ASN1_BIT_STRING`, where an authority spelling is kept for the same kind of reason.
#![allow(non_snake_case)]

use core::ffi::{c_int, c_uchar};
use core::ptr;

/// `SIPHASH_BLOCK_SIZE` — `include/crypto/siphash.h:16`.
pub(crate) const SIPHASH_BLOCK_SIZE: usize = 8;
/// `SIPHASH_KEY_SIZE` — `include/crypto/siphash.h:17`. The row refuses every other length.
pub(crate) const SIPHASH_KEY_SIZE: usize = 16;
/// `SIPHASH_MIN_DIGEST_SIZE` — `include/crypto/siphash.h:18`.
pub(crate) const SIPHASH_MIN_DIGEST_SIZE: usize = 8;
/// `SIPHASH_MAX_DIGEST_SIZE` — `include/crypto/siphash.h:19`.
pub(crate) const SIPHASH_MAX_DIGEST_SIZE: usize = 16;
/// `SIPHASH_C_ROUNDS` — `include/crypto/siphash.h:47`, the default this crate must supply when a
/// caller leaves `c-rounds` unset.
pub(crate) const SIPHASH_C_ROUNDS: u32 = 2;
/// `SIPHASH_D_ROUNDS` — `include/crypto/siphash.h:48`.
pub(crate) const SIPHASH_D_ROUNDS: u32 = 4;

/// `SIPROUND` — `siphash.c:47-63`, as a function of the four state words.
///
/// A `macro_rules!` rather than a function would be the closer transcription, but the macro is
/// defined inside two functions over their *locals*, so the value-in/value-out form is what the
/// authority's own expansion computes. Every operation is wrapping: the authority's `uint64_t`
/// arithmetic wraps, and this crate builds with `overflow-checks = true`.
#[inline(always)]
fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// `U8TO64_LE` — `siphash.c:44-45`.
///
/// # Safety
/// `p` is readable for eight bytes.
#[inline(always)]
unsafe fn u8to64_le(p: *const c_uchar) -> u64 {
    // SAFETY: the caller's contract.
    unsafe {
        u64::from_le_bytes([
            *p,
            *p.add(1),
            *p.add(2),
            *p.add(3),
            *p.add(4),
            *p.add(5),
            *p.add(6),
            *p.add(7),
        ])
    }
}

/// `U64TO8_LE` — `siphash.c:40-42`.
///
/// # Safety
/// `p` is writable for eight bytes.
#[inline(always)]
unsafe fn u64to8_le(p: *mut c_uchar, v: u64) {
    // SAFETY: the caller's contract.
    unsafe {
        let bytes = v.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            *p.add(i) = *b;
        }
    }
}

/// `struct siphash_st` — `include/crypto/siphash.h:33-44`, in field order. `hash_size`, `crounds`,
/// `drounds` and `len` are C `unsigned int`s, and `leavings` is the eight-byte tail buffer whose
/// presence is why `SipHash_Update` is not a pure block loop.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Siphash {
    /// `uint64_t total_inlen` — the *whole* message length, advanced by every `Update`.
    pub total_inlen: u64,
    /// `uint64_t v0`.
    pub v0: u64,
    /// `uint64_t v1`.
    pub v1: u64,
    /// `uint64_t v2`.
    pub v2: u64,
    /// `uint64_t v3`.
    pub v3: u64,
    /// `unsigned int len` — how many bytes of the eight-byte tail are occupied.
    pub len: u32,
    /// `unsigned int hash_size`.
    pub hash_size: u32,
    /// `unsigned int crounds`.
    pub crounds: u32,
    /// `unsigned int drounds`.
    pub drounds: u32,
    /// `unsigned char leavings[SIPHASH_BLOCK_SIZE]`.
    pub leavings: [c_uchar; SIPHASH_BLOCK_SIZE],
}

impl Siphash {
    /// A zeroed context, which is what every caller of this struct starts from: `siphash_new`
    /// `zalloc`s the whole provider context, so `hash_size == 0` means "not chosen yet" until
    /// `SipHash_Init` or `SipHash_set_hash_size` adjusts it.
    ///
    /// `#[cfg(test)]` because the provider row does **not** call it: `siphash_new` uses
    /// `CRYPTO_zalloc`, as the authority's `OPENSSL_zalloc` does, so this is the unit tests' way of
    /// building the same starting state rather than a second implementation of it.
    #[cfg(test)]
    pub(crate) const fn zeroed() -> Self {
        Siphash {
            total_inlen: 0,
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
            len: 0,
            hash_size: 0,
            crounds: 0,
            drounds: 0,
            leavings: [0; SIPHASH_BLOCK_SIZE],
        }
    }
}

/// `size_t SipHash_ctx_size(void)` — `siphash.c:65-68`.
///
/// **Defined and called by nothing in this crate, and that is the authority's own situation.** Its
/// one caller in the whole tree would be a provider that sized a context before allocating it, and
/// `siphash_prov.c` uses `OPENSSL_zalloc(sizeof(*ctx))` instead. It is transcribed because
/// `gen_prerequisite_atlas.py`'s internal-symbol atlas enumerates it as part of
/// `crypto/siphash/siphash.c`, and a defined-and-unreferenced name is the honest state rather than
/// an omission the atlas would report.
#[allow(dead_code)]
pub(crate) fn SipHash_ctx_size() -> usize {
    core::mem::size_of::<Siphash>()
}

/// `size_t SipHash_hash_size(SIPHASH *ctx)` — `siphash.c:70-73`. It answers the raw field, so a
/// context that has never been initialised answers 0 rather than the maximum.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn SipHash_hash_size(ctx: *mut Siphash) -> usize {
    // SAFETY: the caller's contract.
    unsafe { (*ctx).hash_size as usize }
}

/// `static size_t siphash_adjust_hash_size(size_t hash_size)` — `siphash.c:75-80`.
fn siphash_adjust_hash_size(hash_size: usize) -> usize {
    if hash_size == 0 {
        return SIPHASH_MAX_DIGEST_SIZE;
    }
    hash_size
}

/// `int SipHash_set_hash_size(SIPHASH *ctx, size_t hash_size)` — `siphash.c:82-103`.
///
/// The `v1 ^= 0xee` compensation is the whole function: when the size changes on a context that
/// may already have been initialised with a key, re-running `SipHash_Init` is not available
/// (there is no key stored here), so the one bit that separates the two constructions is flipped
/// in place. Both the *stored* size and the requested size are adjusted first, which is why a
/// context whose `hash_size` is still 0 can be asked for 0 and end up at 16.
///
/// # Safety
/// `ctx` is NULL or live.
pub(crate) unsafe fn SipHash_set_hash_size(ctx: *mut Siphash, hash_size: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let hash_size = siphash_adjust_hash_size(hash_size);
        if hash_size != SIPHASH_MIN_DIGEST_SIZE && hash_size != SIPHASH_MAX_DIGEST_SIZE {
            return 0;
        }
        (*ctx).hash_size = siphash_adjust_hash_size((*ctx).hash_size as usize) as u32;
        if (*ctx).hash_size as usize != hash_size {
            (*ctx).v1 ^= 0xee;
            (*ctx).hash_size = hash_size as u32;
        }
        1
    }
}

/// `int SipHash_Init(SIPHASH *ctx, const unsigned char *k, int crounds, int drounds)` —
/// `siphash.c:106-134`.
///
/// `crounds == 0` and `drounds == 0` each fall back to the primitive's defaults rather than
/// meaning "no rounds", which is the same `0 means unset` convention `hash_size` uses.
///
/// # Safety
/// `ctx` is live; `k` is readable for `SIPHASH_KEY_SIZE` bytes.
pub(crate) unsafe fn SipHash_Init(
    ctx: *mut Siphash,
    k: *const c_uchar,
    crounds: c_int,
    drounds: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let k0 = u8to64_le(k);
        let k1 = u8to64_le(k.add(8));

        (*ctx).hash_size = siphash_adjust_hash_size((*ctx).hash_size as usize) as u32;

        let drounds = if drounds == 0 {
            SIPHASH_D_ROUNDS
        } else {
            drounds as u32
        };
        let crounds = if crounds == 0 {
            SIPHASH_C_ROUNDS
        } else {
            crounds as u32
        };

        (*ctx).crounds = crounds;
        (*ctx).drounds = drounds;

        (*ctx).len = 0;
        (*ctx).total_inlen = 0;

        (*ctx).v0 = 0x736f_6d65_7073_6575 ^ k0;
        (*ctx).v1 = 0x646f_7261_6e64_6f6d ^ k1;
        (*ctx).v2 = 0x6c79_6765_6e65_7261 ^ k0;
        (*ctx).v3 = 0x7465_6462_7974_6573 ^ k1;

        if (*ctx).hash_size as usize == SIPHASH_MAX_DIGEST_SIZE {
            (*ctx).v1 ^= 0xee;
        }
        1
    }
}

/// `void SipHash_Update(SIPHASH *ctx, const unsigned char *in, size_t inlen)` —
/// `siphash.c:136-192`.
///
/// The tail buffer makes this three phases rather than one: drain the previous tail, absorb whole
/// eight-byte blocks, then keep the remainder. `total_inlen` counts the *whole* message, including
/// the bytes still in the tail, because `SipHash_Final` shifts it into the final block's length
/// byte.
///
/// # Safety
/// `ctx` is live; `in` is readable for `inlen` bytes.
pub(crate) unsafe fn SipHash_Update(ctx: *mut Siphash, in_: *const c_uchar, inlen: usize) {
    // SAFETY: the caller's contract.
    unsafe {
        let mut v = [(*ctx).v0, (*ctx).v1, (*ctx).v2, (*ctx).v3];

        (*ctx).total_inlen = (*ctx).total_inlen.wrapping_add(inlen as u64);

        let mut in_ = in_;
        let mut inlen = inlen;

        if (*ctx).len != 0 {
            let available = SIPHASH_BLOCK_SIZE - (*ctx).len as usize;

            if inlen < available {
                ptr::copy_nonoverlapping(
                    in_,
                    (*ctx).leavings.as_mut_ptr().add((*ctx).len as usize),
                    inlen,
                );
                (*ctx).len += inlen as u32;
                return;
            }

            ptr::copy_nonoverlapping(
                in_,
                (*ctx).leavings.as_mut_ptr().add((*ctx).len as usize),
                available,
            );
            inlen -= available;
            in_ = in_.add(available);

            let m = u8to64_le((*ctx).leavings.as_ptr());
            v[3] ^= m;
            for _ in 0..(*ctx).crounds {
                sipround(&mut v);
            }
            v[0] ^= m;
        }

        let left = inlen & (SIPHASH_BLOCK_SIZE - 1);
        let end = in_.add(inlen - left);

        let mut p = in_;
        while p != end {
            let m = u8to64_le(p);
            v[3] ^= m;
            for _ in 0..(*ctx).crounds {
                sipround(&mut v);
            }
            v[0] ^= m;
            p = p.add(8);
        }

        if left != 0 {
            ptr::copy_nonoverlapping(end, (*ctx).leavings.as_mut_ptr(), left);
        }
        (*ctx).len = left as u32;

        (*ctx).v0 = v[0];
        (*ctx).v1 = v[1];
        (*ctx).v2 = v[2];
        (*ctx).v3 = v[3];
    }
}

/// `int SipHash_Final(SIPHASH *ctx, unsigned char *out, size_t outlen)` — `siphash.c:194-252`.
///
/// The `switch` is a deliberate fall-through in C and becomes explicit `|`s here: the length byte
/// is the tail's seven low bytes shifted up, with `total_inlen << 56` as the top byte, and a
/// `switch` with no `default` means a `len` above 7 keeps only the length byte. `outlen` must
/// equal the context's `hash_size` **exactly** — an eight-octet request against a sixteen-octet
/// context is a refusal, not a truncation — and `crounds == 0` refuses, which is how an
/// uninitialised context answers 0 rather than computing something.
///
/// # Safety
/// `ctx` is live; `out` is writable for `outlen` bytes.
pub(crate) unsafe fn SipHash_Final(ctx: *mut Siphash, out: *mut c_uchar, outlen: usize) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let mut v = [(*ctx).v0, (*ctx).v1, (*ctx).v2, (*ctx).v3];
        let mut b = (*ctx).total_inlen << 56;

        if (*ctx).crounds == 0 || outlen == 0 || outlen != (*ctx).hash_size as usize {
            return 0;
        }

        for i in 0..(*ctx).len as usize {
            b |= ((*ctx).leavings[i] as u64) << (8 * i);
        }

        v[3] ^= b;
        for _ in 0..(*ctx).crounds {
            sipround(&mut v);
        }
        v[0] ^= b;
        if (*ctx).hash_size as usize == SIPHASH_MAX_DIGEST_SIZE {
            v[2] ^= 0xee;
        } else {
            v[2] ^= 0xff;
        }
        for _ in 0..(*ctx).drounds {
            sipround(&mut v);
        }
        b = v[0] ^ v[1] ^ v[2] ^ v[3];
        u64to8_le(out, b);
        if (*ctx).hash_size as usize == SIPHASH_MIN_DIGEST_SIZE {
            return 1;
        }
        v[1] ^= 0xdd;
        for _ in 0..(*ctx).drounds {
            sipround(&mut v);
        }
        b = v[0] ^ v[1] ^ v[2] ^ v[3];
        u64to8_le(out.add(8), b);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SipHash-2-4 over the `0..n-1` byte message with key `000102...0f` and the eight-octet output,
    /// for `n` in `0..64`.
    ///
    /// **The expectations are the authority's own output, and that is stated rather than dressed
    /// up.** They were generated by compiling the pinned `crypto/siphash/siphash.c` standalone
    /// (`court/gen-siphash-vectors.c`, which links nothing else) and printing what it answers — so
    /// this is a transcription check against the unit being transcribed, not an independent
    /// construction check. SipHash has no RFC and no NIST corpus; the reference implementation in
    /// the SipHash paper is the construction's only independent source, and citing vectors from
    /// memory while claiming that provenance is exactly the kind of thing this project refuses to
    /// do. `CT-*` records the paper's own vectors as a stated follow-up, the way it does for the
    /// other primitives.
    ///
    /// It is still worth having: the provider row's tag would be identical if this primitive were a
    /// plausible-but-wrong SipHash variant, because both sides of a differential court would move
    /// together, so *something* has to pin the primitive's arithmetic.
    #[test]
    fn the_paper_vectors_reproduce_for_the_eight_octet_form() {
        let expected: [(usize, [u8; 8]); 64] = [
            (0, [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]),
            (1, [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74]),
            (2, [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d]),
            (3, [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85]),
            (4, [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf]),
            (5, [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18]),
            (6, [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb]),
            (7, [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab]),
            (8, [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93]),
            (9, [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e]),
            (10, [0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a]),
            (11, [0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4]),
            (12, [0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75]),
            (13, [0x90, 0x3d, 0x84, 0xc0, 0x27, 0x56, 0xea, 0x14]),
            (14, [0xee, 0xf2, 0x7a, 0x8e, 0x90, 0xca, 0x23, 0xf7]),
            (15, [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1]),
            (16, [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f]),
            (17, [0x94, 0x47, 0xbe, 0x2c, 0xf5, 0xe9, 0x9a, 0x69]),
            (18, [0x9c, 0xd3, 0x8d, 0x96, 0xf0, 0xb3, 0xc1, 0x4b]),
            (19, [0xbd, 0x61, 0x79, 0xa7, 0x1d, 0xc9, 0x6d, 0xbb]),
            (20, [0x98, 0xee, 0xa2, 0x1a, 0xf2, 0x5c, 0xd6, 0xbe]),
            (21, [0xc7, 0x67, 0x3b, 0x2e, 0xb0, 0xcb, 0xf2, 0xd0]),
            (22, [0x88, 0x3e, 0xa3, 0xe3, 0x95, 0x67, 0x53, 0x93]),
            (23, [0xc8, 0xce, 0x5c, 0xcd, 0x8c, 0x03, 0x0c, 0xa8]),
            (24, [0x94, 0xaf, 0x49, 0xf6, 0xc6, 0x50, 0xad, 0xb8]),
            (25, [0xea, 0xb8, 0x85, 0x8a, 0xde, 0x92, 0xe1, 0xbc]),
            (26, [0xf3, 0x15, 0xbb, 0x5b, 0xb8, 0x35, 0xd8, 0x17]),
            (27, [0xad, 0xcf, 0x6b, 0x07, 0x63, 0x61, 0x2e, 0x2f]),
            (28, [0xa5, 0xc9, 0x1d, 0xa7, 0xac, 0xaa, 0x4d, 0xde]),
            (29, [0x71, 0x65, 0x95, 0x87, 0x66, 0x50, 0xa2, 0xa6]),
            (30, [0x28, 0xef, 0x49, 0x5c, 0x53, 0xa3, 0x87, 0xad]),
            (31, [0x42, 0xc3, 0x41, 0xd8, 0xfa, 0x92, 0xd8, 0x32]),
            (32, [0xce, 0x7c, 0xf2, 0x72, 0x2f, 0x51, 0x27, 0x71]),
            (33, [0xe3, 0x78, 0x59, 0xf9, 0x46, 0x23, 0xf3, 0xa7]),
            (34, [0x38, 0x12, 0x05, 0xbb, 0x1a, 0xb0, 0xe0, 0x12]),
            (35, [0xae, 0x97, 0xa1, 0x0f, 0xd4, 0x34, 0xe0, 0x15]),
            (36, [0xb4, 0xa3, 0x15, 0x08, 0xbe, 0xff, 0x4d, 0x31]),
            (37, [0x81, 0x39, 0x62, 0x29, 0xf0, 0x90, 0x79, 0x02]),
            (38, [0x4d, 0x0c, 0xf4, 0x9e, 0xe5, 0xd4, 0xdc, 0xca]),
            (39, [0x5c, 0x73, 0x33, 0x6a, 0x76, 0xd8, 0xbf, 0x9a]),
            (40, [0xd0, 0xa7, 0x04, 0x53, 0x6b, 0xa9, 0x3e, 0x0e]),
            (41, [0x92, 0x59, 0x58, 0xfc, 0xd6, 0x42, 0x0c, 0xad]),
            (42, [0xa9, 0x15, 0xc2, 0x9b, 0xc8, 0x06, 0x73, 0x18]),
            (43, [0x95, 0x2b, 0x79, 0xf3, 0xbc, 0x0a, 0xa6, 0xd4]),
            (44, [0xf2, 0x1d, 0xf2, 0xe4, 0x1d, 0x45, 0x35, 0xf9]),
            (45, [0x87, 0x57, 0x75, 0x19, 0x04, 0x8f, 0x53, 0xa9]),
            (46, [0x10, 0xa5, 0x6c, 0xf5, 0xdf, 0xcd, 0x9a, 0xdb]),
            (47, [0xeb, 0x75, 0x09, 0x5c, 0xcd, 0x98, 0x6c, 0xd0]),
            (48, [0x51, 0xa9, 0xcb, 0x9e, 0xcb, 0xa3, 0x12, 0xe6]),
            (49, [0x96, 0xaf, 0xad, 0xfc, 0x2c, 0xe6, 0x66, 0xc7]),
            (50, [0x72, 0xfe, 0x52, 0x97, 0x5a, 0x43, 0x64, 0xee]),
            (51, [0x5a, 0x16, 0x45, 0xb2, 0x76, 0xd5, 0x92, 0xa1]),
            (52, [0xb2, 0x74, 0xcb, 0x8e, 0xbf, 0x87, 0x87, 0x0a]),
            (53, [0x6f, 0x9b, 0xb4, 0x20, 0x3d, 0xe7, 0xb3, 0x81]),
            (54, [0xea, 0xec, 0xb2, 0xa3, 0x0b, 0x22, 0xa8, 0x7f]),
            (55, [0x99, 0x24, 0xa4, 0x3c, 0xc1, 0x31, 0x57, 0x24]),
            (56, [0xbd, 0x83, 0x8d, 0x3a, 0xaf, 0xbf, 0x8d, 0xb7]),
            (57, [0x0b, 0x1a, 0x2a, 0x32, 0x65, 0xd5, 0x1a, 0xea]),
            (58, [0x13, 0x50, 0x79, 0xa3, 0x23, 0x1c, 0xe6, 0x60]),
            (59, [0x93, 0x2b, 0x28, 0x46, 0xe4, 0xd7, 0x06, 0x66]),
            (60, [0xe1, 0x91, 0x5f, 0x5c, 0xb1, 0xec, 0xa4, 0x6c]),
            (61, [0xf3, 0x25, 0x96, 0x5c, 0xa1, 0x6d, 0x62, 0x9f]),
            (62, [0x57, 0x5f, 0xf2, 0x8e, 0x60, 0x38, 0x1b, 0xe5]),
            (63, [0x72, 0x45, 0x06, 0xeb, 0x4c, 0x32, 0x8a, 0x95]),
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut msg = [0u8; 64];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (len, want) in expected {
            // SAFETY: `ctx` is a local, `key` is 16 bytes and `msg` is 64.
            unsafe {
                let mut ctx = Siphash::zeroed();
                assert_eq!(SipHash_set_hash_size(&mut ctx, SIPHASH_MIN_DIGEST_SIZE), 1);
                assert_eq!(SipHash_Init(&mut ctx, key.as_ptr(), 0, 0), 1);
                SipHash_Update(&mut ctx, msg.as_ptr(), len);
                let mut out = [0u8; 8];
                assert_eq!(SipHash_Final(&mut ctx, out.as_mut_ptr(), 8), 1);
                assert_eq!(out, want, "SipHash-2-4 of {len} bytes");
            }
        }
    }

    #[test]
    fn a_zero_hash_size_means_the_maximum_and_the_two_sizes_are_two_constructions() {
        // SAFETY: locals only.
        unsafe {
            let mut ctx = Siphash::zeroed();
            // 0 is adjusted to 16, and a 0 request is legal because of that adjustment.
            assert_eq!(SipHash_set_hash_size(&mut ctx, 0), 1);
            assert_eq!(SipHash_hash_size(&mut ctx), 16);
            // Anything that is neither 8 nor 16 is a refusal.
            assert_eq!(SipHash_set_hash_size(&mut ctx, 12), 0);
            assert_eq!(SipHash_set_hash_size(&mut ctx, 7), 0);
        }
    }

    #[test]
    fn set_hash_size_after_the_key_compensates_rather_than_reinitialising() {
        // The bit that has to move is `v1 ^= 0xee`, and the two routes have to agree: setting the
        // size before init and setting it after init must produce the same context.
        let key = [0x11u8; 16];
        // SAFETY: locals and 16-byte key.
        unsafe {
            let mut before = Siphash::zeroed();
            assert_eq!(SipHash_set_hash_size(&mut before, 8), 1);
            assert_eq!(SipHash_Init(&mut before, key.as_ptr(), 0, 0), 1);

            let mut after = Siphash::zeroed();
            assert_eq!(SipHash_Init(&mut after, key.as_ptr(), 0, 0), 1);
            assert_eq!(SipHash_set_hash_size(&mut after, 8), 1);

            assert_eq!(before.v1, after.v1);
            assert_eq!(before.hash_size, after.hash_size);
        }
    }

    #[test]
    fn final_refuses_a_length_that_is_not_the_contexts_and_an_uninitialised_context() {
        let key = [0x22u8; 16];
        let msg = [0x33u8; 4];
        // SAFETY: locals.
        unsafe {
            let mut ctx = Siphash::zeroed();
            let mut out = [0u8; 16];
            // `crounds == 0` because `Init` has not run.
            assert_eq!(SipHash_Final(&mut ctx, out.as_mut_ptr(), 16), 0);

            assert_eq!(SipHash_Init(&mut ctx, key.as_ptr(), 0, 0), 1);
            SipHash_Update(&mut ctx, msg.as_ptr(), msg.len());
            // The context is 16 wide, so 8 is a refusal rather than a truncation.
            assert_eq!(SipHash_Final(&mut ctx, out.as_mut_ptr(), 8), 0);
            assert_eq!(SipHash_Final(&mut ctx, out.as_mut_ptr(), 0), 0);
            assert_eq!(SipHash_Final(&mut ctx, out.as_mut_ptr(), 16), 1);
        }
    }

    #[test]
    fn the_tail_buffer_survives_every_split_of_the_same_message() {
        // The constructor is deterministic, so a byte-at-a-time update and one whole update must
        // agree -- which is the only way a `leavings` transcription error shows up as a value
        // rather than as a crash. This is a self-consistency check, not a vector.
        let key = [0x44u8; 16];
        let mut msg = [0u8; 100];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        // SAFETY: locals; `key` is 16 bytes.
        unsafe {
            let mut whole = Siphash::zeroed();
            assert_eq!(SipHash_Init(&mut whole, key.as_ptr(), 0, 0), 1);
            SipHash_Update(&mut whole, msg.as_ptr(), msg.len());
            let mut want = [0u8; 16];
            assert_eq!(SipHash_Final(&mut whole, want.as_mut_ptr(), 16), 1);

            for chunk in [1usize, 2, 3, 5, 7, 8, 9, 13, 16, 17, 33, 64] {
                let mut split = Siphash::zeroed();
                assert_eq!(SipHash_Init(&mut split, key.as_ptr(), 0, 0), 1);
                let mut at = 0;
                while at < msg.len() {
                    let n = chunk.min(msg.len() - at);
                    SipHash_Update(&mut split, msg.as_ptr().add(at), n);
                    at += n;
                }
                let mut got = [0u8; 16];
                assert_eq!(SipHash_Final(&mut split, got.as_mut_ptr(), 16), 1);
                assert_eq!(got, want, "chunk size {chunk}");
            }
            // And an empty message is a legal message.
            let mut empty = Siphash::zeroed();
            assert_eq!(SipHash_Init(&mut empty, key.as_ptr(), 0, 0), 1);
            SipHash_Update(&mut empty, msg.as_ptr(), 0);
            let mut got = [0u8; 16];
            assert_eq!(SipHash_Final(&mut empty, got.as_mut_ptr(), 16), 1);
        }
    }
}
