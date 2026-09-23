//! `crypto/ml_kem/ml_kem.c` — the arithmetic, hash, sampling and CPA layer.
//!
//! This file is `ml_kem.c:33-1590`: the bit helpers, the four SHA3/SHAKE entry points
//! (`single_keccak`, `prf`, `hash_h`/`hash_h_pubkey`, `hash_g`, `kdf`), `sample_scalar`,
//! the Barrett reduction pair, the NTT and its inverse, the byte encode/decode family
//! (`scalar_encode`, `scalar_encode_1`, `scalar_decode`, `scalar_decode_12`,
//! `scalar_decode_decompress_add`), `compress`/`decompress` and their scalar/vector wrappers,
//! the inner product and the two matrix products, `matrix_expand`, the two CBD samplers and
//! their vector drivers, and `encrypt_cpa`/`decrypt_cpa`.
//!
//! ## `CONSTTIME_SECRET`/`CONSTTIME_DECLASSIFY` are recorded, not written
//!
//! On this profile neither `OPENSSL_CONSTANT_TIME_VALIDATION` nor the valgrind arm it selects is
//! compiled (`ml_kem.c:150-172`), so both macros expand to nothing and the thirteen call sites
//! below are the whole of their observable behaviour: none. They are recorded with their
//! coordinates in [`CONSTTIME_SITES`] rather than written as no-op calls, because a no-op call
//! would suggest the crate tracks secret memory when it does not.
//!
//! ## All arithmetic wraps
//!
//! The crate builds with `overflow-checks = true`, where the authority's C promotes to `int` and
//! relies on modular wraparound at the `uint16_t` store. Every subtraction and addition here is
//! `wrapping_*` so the two agree bit for bit in a debug build.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};
use core::ptr;

use crate::evp::digest::{
    EVP_DigestFinalXOF, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestSqueeze, EVP_DigestUpdate,
    EVP_MD_CTX_get0_md, EVP_MD_xof, EvpMdCtx,
};

use super::tables::{KINVERSE_NTT_ROOTS, KMOD_ROOTS, KNTT_ROOTS};
use super::{
    MlKemKey, Scalar, BARRETT_SHIFT, INVERSE_DEGREE, KBARRETT_MULTIPLIER, KHALFPRIME,
    ML_KEM_DEGREE, ML_KEM_PKHASH_BYTES, ML_KEM_PRIME, ML_KEM_RANDOM_BYTES, ML_KEM_SEED_BYTES,
    ML_KEM_SHARED_SECRET_BYTES, SCALAR_SAMPLING_BUFSIZE,
};

/// The thirteen `CONSTTIME_SECRET`/`CONSTTIME_DECLASSIFY` call sites, with their coordinates.
///
/// `ml_kem.c:150` selects the valgrind arm only under `OPENSSL_CONSTANT_TIME_VALIDATION`; on this
/// profile the `#else` arm (`:169-170`) is the one compiled, where both macros are empty. The
/// sites are listed so a reader can see what the profile loses, and so a later
/// constant-time-validation build knows exactly which lines to re-enable.
pub(crate) const CONSTTIME_SITES: [(&str, c_int); 13] = [
    ("genkey", 1746),
    ("genkey", 1757),
    ("ossl_ml_kem_genkey", 2264),
    ("ossl_ml_kem_genkey", 2272),
    ("ossl_ml_kem_genkey", 2284),
    ("ossl_ml_kem_genkey", 2285),
    ("ossl_ml_kem_encap_seed", 2315),
    ("ossl_ml_kem_encap_seed", 2342),
    ("ossl_ml_kem_encap_seed", 2343),
    ("ossl_ml_kem_encap_seed", 2344),
    ("ossl_ml_kem_decap", 2403),
    ("ossl_ml_kem_decap", 2429),
    ("ossl_ml_kem_decap", 2430),
];

/// `bit0(b)` — `ml_kem.c:34`, `((b) & 1)`.
#[inline]
pub(crate) fn bit0(b: u8) -> u8 {
    b & 1
}

/// `bitn(n, b)` — `ml_kem.c:35`, `(((b) >> n) & 1)`.
#[inline]
pub(crate) fn bitn(n: u32, b: u8) -> u8 {
    (b >> n) & 1
}

/// `constish_time_non_zero(b)` — `ml_kem.c:70`, `(0u - (b))`.
///
/// The `#if 0` arm above it (`:68`) is not compiled, so this is the whole of the macro. Its
/// argument is always 0 or 1, and the answer is the all-ones/all-zeros mask.
#[inline]
pub(crate) fn constish_time_non_zero(b: u16) -> u16 {
    0u16.wrapping_sub(b)
}

/// `OPENSSL_store_u64_le(out, v)` — `<openssl/byteorder.h>`, little-endian, returns `out + 8`.
///
/// # Safety
/// `out` must be writable for eight bytes.
#[inline]
unsafe fn store_u64_le(out: *mut u8, v: u64) -> *mut u8 {
    let bytes = v.to_le_bytes();
    // SAFETY: `out` is writable for eight bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, 8) };
    // SAFETY: the pointer arithmetic stays within the object `out` names.
    unsafe { out.add(8) }
}

/// `OPENSSL_load_u64_le(&accum, in)` — `<openssl/byteorder.h>`, returns `in + 8`.
///
/// The authority's macro returns the advanced pointer, so the byte-at-a-time arm is the one
/// written: the accumulator is filled in place and the advanced pointer handed back.
///
/// # Safety
/// `in` must be readable for eight bytes.
#[inline]
unsafe fn load_u64_le(in_: *const u8, accum: &mut u64) -> *const u8 {
    let mut bytes = [0u8; 8];
    // SAFETY: `in_` is readable for eight bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(in_, bytes.as_mut_ptr(), 8) };
    *accum = u64::from_le_bytes(bytes);
    // SAFETY: the pointer arithmetic stays within the object `in_` names.
    unsafe { in_.add(8) }
}

/// `single_keccak(...)` — `ml_kem.c:670-681`.
///
/// # Safety
/// `mdctx` must be an initialised digest context and `out` writable for `outlen` bytes.
pub(crate) unsafe fn single_keccak(
    out: *mut u8,
    outlen: usize,
    in_: *const u8,
    inlen: usize,
    mdctx: *mut EvpMdCtx,
) -> c_int {
    let mut sz: c_uint = outlen as c_uint;

    // SAFETY: the arguments are forwarded under this function's contract.
    unsafe {
        if EVP_DigestUpdate(mdctx, in_.cast(), inlen) == 0 {
            return 0;
        }
        if EVP_MD_xof(EVP_MD_CTX_get0_md(mdctx)) != 0 {
            return EVP_DigestFinalXOF(mdctx, out, outlen);
        }
        if EVP_DigestFinal_ex(mdctx, out, &mut sz) != 0 && sz as usize == outlen {
            1
        } else {
            0
        }
    }
}

/// `prf(out, len, in, mdctx, key)` — `ml_kem.c:687-692`, FIPS 203 equation (4.3).
///
/// # Safety
/// `key` must be live with a fetched `shake256_md`.
pub(crate) unsafe fn prf(
    out: *mut u8,
    len: usize,
    in_: *const u8,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if EVP_DigestInit_ex(mdctx, (*key).shake256_md, ptr::null_mut()) == 0 {
            return 0;
        }
        single_keccak(out, len, in_, ML_KEM_RANDOM_BYTES + 1, mdctx)
    }
}

/// `hash_h(out, in, len, mdctx, key)` — `ml_kem.c:698-703`, FIPS 203 equation (4.4), SHA3-256.
///
/// # Safety
/// `key` must be live with a fetched `sha3_256_md`.
pub(crate) unsafe fn hash_h(
    out: *mut u8,
    in_: *const u8,
    len: usize,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if EVP_DigestInit_ex(mdctx, (*key).sha3_256_md, ptr::null_mut()) == 0 {
            return 0;
        }
        single_keccak(out, ML_KEM_PKHASH_BYTES, in_, len, mdctx)
    }
}

/// `hash_h_pubkey(pkhash, mdctx, key)` — `ml_kem.c:706-729`, the incremental form.
///
/// # Safety
/// `key` must be live with a populated `t`/`rho`.
pub(crate) unsafe fn hash_h_pubkey(
    pkhash: *mut u8,
    mdctx: *mut EvpMdCtx,
    key: *mut MlKemKey,
) -> c_int {
    let mut sz: c_uint = 0;
    // SAFETY: `key` is live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let rank = (*vinfo).rank;
        let mut t = (*key).t;

        let mut buf = [0u8; 3 * ML_KEM_DEGREE / 2];

        if EVP_DigestInit_ex(mdctx, (*key).sha3_256_md, ptr::null_mut()) == 0 {
            return 0;
        }

        loop {
            scalar_encode(buf.as_mut_ptr(), t, 12);
            if EVP_DigestUpdate(mdctx, buf.as_ptr().cast(), buf.len()) == 0 {
                return 0;
            }
            t = t.add(1);
            if !(t < (*key).t.add(rank as usize)) {
                break;
            }
        }

        if EVP_DigestUpdate(mdctx, (*key).rho.cast(), ML_KEM_RANDOM_BYTES) == 0 {
            return 0;
        }
        if EVP_DigestFinal_ex(mdctx, pkhash, &mut sz) != 0 && sz == ML_KEM_PKHASH_BYTES as c_uint {
            1
        } else {
            0
        }
    }
}

/// `hash_g(out, in, len, mdctx, key)` — `ml_kem.c:736-741`, FIPS 203 equation (4.5), SHA3-512.
///
/// # Safety
/// `key` must be live with a fetched `sha3_512_md`.
pub(crate) unsafe fn hash_g(
    out: *mut u8,
    in_: *const u8,
    len: usize,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if EVP_DigestInit_ex(mdctx, (*key).sha3_512_md, ptr::null_mut()) == 0 {
            return 0;
        }
        single_keccak(out, ML_KEM_SEED_BYTES, in_, len, mdctx)
    }
}

/// `kdf(out, z, ctext, len, mdctx, key)` — `ml_kem.c:749-758`, FIPS 203 equation (4.4), `J`.
///
/// # Safety
/// `key` must be live with a fetched `shake256_md`.
pub(crate) unsafe fn kdf(
    out: *mut u8,
    z: *const u8,
    ctext: *const u8,
    len: usize,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        if EVP_DigestInit_ex(mdctx, (*key).shake256_md, ptr::null_mut()) == 0 {
            return 0;
        }
        if EVP_DigestUpdate(mdctx, z.cast(), ML_KEM_RANDOM_BYTES) == 0 {
            return 0;
        }
        if EVP_DigestUpdate(mdctx, ctext.cast(), len) == 0 {
            return 0;
        }
        EVP_DigestFinalXOF(mdctx, out, ML_KEM_SHARED_SECRET_BYTES)
    }
}

/// `sample_scalar(out, mdctx)` — `ml_kem.c:766-793`, FIPS 203 Algorithm 7 steps 3-17.
///
/// # Safety
/// `out` must be a live scalar and `mdctx` a live SHAKE128 context mid-squeeze.
pub(crate) unsafe fn sample_scalar(out: *mut Scalar, mdctx: *mut EvpMdCtx) -> c_int {
    // SAFETY: `out` is live per the contract, and the index is bounded by the loop conditions.
    unsafe {
        let c = &mut (*out).c;
        let mut buf = [0u8; SCALAR_SAMPLING_BUFSIZE];
        let mut curr = 0usize;

        loop {
            if EVP_DigestSqueeze(mdctx, buf.as_mut_ptr(), SCALAR_SAMPLING_BUFSIZE) == 0 {
                return 0;
            }
            let mut i = 0usize;
            loop {
                let b1 = buf[i];
                let b2 = buf[i + 1];
                let b3 = buf[i + 2];
                i += 3;

                if curr >= ML_KEM_DEGREE {
                    break;
                }
                let d = (((b2 & 0x0f) as u16) << 8) + b1 as u16;
                if d < ML_KEM_PRIME as u16 {
                    c[curr] = d;
                    curr += 1;
                }
                if curr >= ML_KEM_DEGREE {
                    break;
                }
                let d = ((b3 as u16) << 4) + ((b2 >> 4) as u16);
                if d < ML_KEM_PRIME as u16 {
                    c[curr] = d;
                    curr += 1;
                }
                if i >= SCALAR_SAMPLING_BUFSIZE {
                    break;
                }
            }
            if curr >= ML_KEM_DEGREE {
                break;
            }
        }
        1
    }
}

/// `reduce_once(x)` — `ml_kem.c:802-808`, reduces `0 <= x < 2*kPrime`.
#[inline]
pub(crate) fn reduce_once(x: u16) -> u16 {
    let subtracted = x.wrapping_sub(ML_KEM_PRIME as u16);
    let mask = constish_time_non_zero(subtracted >> 15);
    (mask & x) | (!mask & subtracted)
}

/// `reduce(x)` — `ml_kem.c:816-823`, Barrett reduction, `x < kPrime + 2 * kPrime^2`.
#[inline]
pub(crate) fn reduce(x: u32) -> u16 {
    let product = (x as u64).wrapping_mul(KBARRETT_MULTIPLIER);
    let quotient = (product >> BARRETT_SHIFT) as u32;
    let remainder = x.wrapping_sub(quotient.wrapping_mul(ML_KEM_PRIME));
    reduce_once(remainder as u16)
}

/// `scalar_mult_const(s, a)` — `ml_kem.c:826-834`.
///
/// # Safety
/// `s` must be a live scalar.
pub(crate) unsafe fn scalar_mult_const(s: *mut Scalar, a: u16) {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let c = &mut (*s).c;
        for x in c.iter_mut() {
            *x = reduce((*x as u32).wrapping_mul(a as u32));
        }
    }
}

/// `scalar_ntt(s)` — `ml_kem.c:845-867`, FIPS 203 Algorithm 9.
///
/// # Safety
/// `s` must be a live scalar.
pub(crate) unsafe fn scalar_ntt(s: *mut Scalar) {
    // SAFETY: `s` is live per the contract; every index is bounded by `offset < ML_KEM_DEGREE`.
    unsafe {
        let c = &mut (*s).c;
        let mut roots = 0usize;
        let mut offset = ML_KEM_DEGREE / 2;

        loop {
            let mut curr = 0usize;
            let mut peer;
            loop {
                let pause = curr + offset;
                // `*++roots` — the pre-increment skips index 0.
                roots += 1;
                let zeta = KNTT_ROOTS[roots] as u32;
                peer = pause;
                loop {
                    let even = c[curr];
                    let odd = reduce((c[peer] as u32).wrapping_mul(zeta));
                    c[peer] = reduce_once(even.wrapping_sub(odd).wrapping_add(ML_KEM_PRIME as u16));
                    c[curr] = reduce_once(odd.wrapping_add(even));
                    peer += 1;
                    curr += 1;
                    if curr >= pause {
                        break;
                    }
                }
                curr = peer;
                if curr >= ML_KEM_DEGREE {
                    break;
                }
            }
            offset >>= 1;
            if offset < 2 {
                break;
            }
        }
    }
}

/// `scalar_inverse_ntt(s)` — `ml_kem.c:877-900`, FIPS 203 Algorithm 10.
///
/// # Safety
/// `s` must be a live scalar.
pub(crate) unsafe fn scalar_inverse_ntt(s: *mut Scalar) {
    // SAFETY: `s` is live per the contract, and `offset` doubles to at most `ML_KEM_DEGREE`.
    unsafe {
        let c = &mut (*s).c;
        let mut roots = 0usize;
        let mut offset = 2usize;

        loop {
            let mut curr = 0usize;
            let mut peer;
            loop {
                let pause = curr + offset;
                roots += 1;
                let zeta = KINVERSE_NTT_ROOTS[roots] as u32;
                peer = pause;
                loop {
                    let even = c[curr];
                    let odd = c[peer];
                    c[peer] = reduce(
                        zeta.wrapping_mul(
                            (even as u32)
                                .wrapping_sub(odd as u32)
                                .wrapping_add(ML_KEM_PRIME),
                        ),
                    );
                    c[curr] = reduce_once(odd.wrapping_add(even));
                    peer += 1;
                    curr += 1;
                    if curr >= pause {
                        break;
                    }
                }
                curr = peer;
                if curr >= ML_KEM_DEGREE {
                    break;
                }
            }
            offset <<= 1;
            if offset >= ML_KEM_DEGREE {
                break;
            }
        }
        scalar_mult_const(s, INVERSE_DEGREE);
    }
}

/// `scalar_add(lhs, rhs)` — `ml_kem.c:903-909`.
///
/// # Safety
/// Both scalars must be live.
pub(crate) unsafe fn scalar_add(lhs: *mut Scalar, rhs: *const Scalar) {
    // SAFETY: both are live per the contract.
    unsafe {
        let l = &mut (*lhs).c;
        let r = &(*rhs).c;
        for (x, y) in l.iter_mut().zip(r.iter()) {
            *x = reduce_once(x.wrapping_add(*y));
        }
    }
}

/// `scalar_sub(lhs, rhs)` — `ml_kem.c:912-918`.
///
/// # Safety
/// Both scalars must be live.
pub(crate) unsafe fn scalar_sub(lhs: *mut Scalar, rhs: *const Scalar) {
    // SAFETY: both are live per the contract.
    unsafe {
        let l = &mut (*lhs).c;
        let r = &(*rhs).c;
        for (x, y) in l.iter_mut().zip(r.iter()) {
            *x = reduce_once(x.wrapping_sub(*y).wrapping_add(ML_KEM_PRIME as u16));
        }
    }
}

/// `scalar_mult(out, lhs, rhs)` — `ml_kem.c:931-946`, the NTT-state product.
///
/// # Safety
/// The three scalars must be live and `out` must not overlap the inputs.
pub(crate) unsafe fn scalar_mult(out: *mut Scalar, lhs: *const Scalar, rhs: *const Scalar) {
    // SAFETY: all three are live and disjoint per the contract.
    unsafe {
        let o = &mut (*out).c;
        let l = &(*lhs).c;
        let r = &(*rhs).c;
        let mut i = 0usize;
        let mut roots = 0usize;
        while i < ML_KEM_DEGREE {
            let l0 = l[i] as u32;
            let r0 = r[i] as u32;
            let l1 = l[i + 1] as u32;
            let r1 = r[i + 1] as u32;
            let zetapow = KMOD_ROOTS[roots] as u32;
            roots += 1;

            o[i] = reduce(
                l0.wrapping_mul(r0)
                    .wrapping_add((reduce(l1.wrapping_mul(r1)) as u32).wrapping_mul(zetapow)),
            );
            o[i + 1] = reduce(l0.wrapping_mul(r1).wrapping_add(l1.wrapping_mul(r0)));
            i += 2;
        }
    }
}

/// `scalar_mult_add(out, lhs, rhs)` — `ml_kem.c:949-966`, as above, added to `out`.
///
/// # Safety
/// The three scalars must be live and `out` must not overlap the inputs.
pub(crate) unsafe fn scalar_mult_add(out: *mut Scalar, lhs: *const Scalar, rhs: *const Scalar) {
    // SAFETY: all three are live and disjoint per the contract.
    unsafe {
        let o = &mut (*out).c;
        let l = &(*lhs).c;
        let r = &(*rhs).c;
        let mut i = 0usize;
        let mut roots = 0usize;
        while i < ML_KEM_DEGREE {
            let l0 = l[i] as u32;
            let r0 = r[i] as u32;
            let l1 = l[i + 1] as u32;
            let r1 = r[i + 1] as u32;
            let zetapow = KMOD_ROOTS[roots] as u32;
            roots += 1;

            o[i] = reduce(
                (o[i] as u32)
                    .wrapping_add(l0.wrapping_mul(r0))
                    .wrapping_add((reduce(l1.wrapping_mul(r1)) as u32).wrapping_mul(zetapow)),
            );
            o[i + 1] = reduce(
                (o[i + 1] as u32)
                    .wrapping_add(l0.wrapping_mul(r1))
                    .wrapping_add(l1.wrapping_mul(r0)),
            );
            i += 2;
        }
    }
}

/// `scalar_encode(out, s, bits)` — `ml_kem.c:972-993`, FIPS 203 Algorithm 5.
///
/// # Safety
/// `out` must be writable for `DEGREE / 8 * bits` bytes.
pub(crate) unsafe fn scalar_encode(out: *mut u8, s: *const Scalar, bits: c_int) {
    // SAFETY: `out` is writable and `s` live per the contract.
    unsafe {
        let c = &(*s).c;
        let bits = bits as u32;
        let mut p = out;
        let mut accum: u64 = 0;
        let mut used: u32 = 0;

        for e in c.iter() {
            let element = *e as u64;
            if used + bits < 64 {
                accum |= element << used;
                used += bits;
            } else if used + bits > 64 {
                p = store_u64_le(p, accum | (element << used));
                accum = element >> (64 - used);
                used = (used + bits) - 64;
            } else {
                p = store_u64_le(p, accum | (element << used));
                accum = 0;
                used = 0;
            }
        }
    }
}

/// `scalar_encode_1(out, s)` — `ml_kem.c:998-1010`, `bits == 1` specialised.
///
/// # Safety
/// `out` must be writable for `DEGREE / 8` bytes.
pub(crate) unsafe fn scalar_encode_1(out: *mut u8, s: *const Scalar) {
    // SAFETY: `out` is writable and `s` live per the contract.
    unsafe {
        let c = &(*s).c;
        let mut p = out;
        for i in (0..ML_KEM_DEGREE).step_by(8) {
            let mut out_byte: u8 = 0;
            for j in 0..8 {
                out_byte |= bit0(c[i + j] as u8) << j;
            }
            *p = out_byte;
            p = p.add(1);
        }
    }
}

/// `scalar_decode(out, in, bits)` — `ml_kem.c:1020-1063`, FIPS 203 Algorithm 6 for `2 <= d < 12`.
///
/// # Safety
/// `in` must be readable for `DEGREE / 8 * bits` bytes.
pub(crate) unsafe fn scalar_decode(out: *mut Scalar, in_: *const u8, bits: c_int) {
    // SAFETY: `in_` is readable and `out` live per the contract.
    unsafe {
        let c = &mut (*out).c;
        let bits = bits as u32;
        let mut p = in_;
        let mut accum: u64 = 0;
        let mut accum_bits: u32 = 0;
        let mut todo: u32 = bits;
        let bitmask: u16 = ((1u16) << bits) - 1;
        let mut mask: u16 = bitmask;
        let mut element: u16 = 0;
        let mut curr = 0usize;

        loop {
            if accum_bits == 0 {
                p = load_u64_le(p, &mut accum);
                accum_bits = 64;
            }
            if todo == bits && accum_bits >= bits {
                c[curr] = (accum as u16) & mask;
                curr += 1;
                accum >>= bits;
                accum_bits -= bits;
            } else if accum_bits >= todo {
                c[curr] = element | (((accum as u16) & mask) << (bits - todo));
                curr += 1;
                accum >>= todo;
                accum_bits -= todo;
                element = 0;
                todo = bits;
                mask = bitmask;
            } else {
                element = (accum as u16) & mask;
                todo -= accum_bits;
                mask = bitmask >> accum_bits;
                accum_bits = 0;
            }
            if curr >= ML_KEM_DEGREE {
                break;
            }
        }
    }
}

/// `scalar_decode_12(out, in)` — `ml_kem.c:1065-1081`, `bits == 12` specialised.
///
/// # Safety
/// `in` must be readable for `3 * DEGREE / 2` bytes.
pub(crate) unsafe fn scalar_decode_12(out: *mut Scalar, in_: *const u8) -> c_int {
    // SAFETY: `in_` is readable and `out` live per the contract.
    unsafe {
        let c = &mut (*out).c;
        let mut p = in_;
        for i in 0..ML_KEM_DEGREE / 2 {
            let b1 = *p;
            let b2 = *p.add(1);
            let b3 = *p.add(2);
            p = p.add(3);
            c[2 * i] = (b1 as u16) | (((b2 & 0x0f) as u16) << 8);
            let out_of_range1 = c[2 * i] >= ML_KEM_PRIME as u16;
            c[2 * i + 1] = ((b2 >> 4) as u16) | ((b3 as u16) << 4);
            let out_of_range2 = c[2 * i + 1] >= ML_KEM_PRIME as u16;

            if out_of_range1 | out_of_range2 {
                return 0;
            }
        }
        1
    }
}

/// `scalar_decode_decompress_add(out, in)` — `ml_kem.c:1095-1128`, `bits == 1` combined.
///
/// # Safety
/// `in` must be readable for `DEGREE / 8` bytes.
pub(crate) unsafe fn scalar_decode_decompress_add(out: *mut Scalar, in_: *const u8) {
    /// `half_q_plus_1` — `ml_kem.c:1098`, `(ML_KEM_PRIME >> 1) + 1`.
    const HALF_Q_PLUS_1: u16 = ((ML_KEM_PRIME >> 1) + 1) as u16;

    // SAFETY: `in_` is readable and `out` live per the contract.
    unsafe {
        let c = &mut (*out).c;
        let mut p = in_;
        // Unrolled to process each byte in one iteration: the authority's outer loop advances the
        // coefficient pointer eight times per byte, so it runs `DEGREE / 8` times, not `DEGREE`.
        let mut i = 0usize;
        while i < ML_KEM_DEGREE {
            let mut b = *p;
            p = p.add(1);
            for _ in 0..8 {
                let mask = constish_time_non_zero(bit0(b) as u16);
                c[i] = reduce_once(c[i].wrapping_add(mask & HALF_Q_PLUS_1));
                b >>= 1;
                i += 1;
            }
        }
    }
}

/// `compress(x, bits)` — `ml_kem.c:1140-1156`, FIPS 203 equation (4.7).
pub(crate) fn compress(x: u16, bits: c_int) -> u16 {
    use crate::runtime::constant_time::constant_time_lt_u32;

    let shifted = (x as u32) << bits;
    let product = (shifted as u64).wrapping_mul(KBARRETT_MULTIPLIER);
    let quotient = (product >> BARRETT_SHIFT) as u32;
    let remainder = shifted.wrapping_sub(quotient.wrapping_mul(ML_KEM_PRIME));

    let mut quotient = quotient;
    quotient = quotient.wrapping_add(1 & constant_time_lt_u32(KHALFPRIME as u32, remainder));
    quotient = quotient
        .wrapping_add(1 & constant_time_lt_u32(ML_KEM_PRIME + KHALFPRIME as u32, remainder));
    (quotient & ((1u32 << bits) - 1)) as u16
}

/// `decompress(x, bits)` — `ml_kem.c:1165-1181`, FIPS 203 equation (4.8).
pub(crate) fn decompress(x: u16, bits: c_int) -> u16 {
    let product = (x as u32).wrapping_mul(ML_KEM_PRIME);
    let power = 1u32 << bits;
    let remainder = product & (power - 1);
    let lower = product >> bits;
    (lower + (remainder >> (bits - 1))) as u16
}

/// `scalar_compress(s, bits)` — `ml_kem.c:1187-1193`.
///
/// # Safety
/// `s` must be a live scalar.
pub(crate) unsafe fn scalar_compress(s: *mut Scalar, bits: c_int) {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let c = &mut (*s).c;
        for x in c.iter_mut() {
            *x = compress(*x, bits);
        }
    }
}

/// `scalar_decompress(s, bits)` — `ml_kem.c:1199-1205`.
///
/// # Safety
/// `s` must be a live scalar.
pub(crate) unsafe fn scalar_decompress(s: *mut Scalar, bits: c_int) {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let c = &mut (*s).c;
        for x in c.iter_mut() {
            *x = decompress(*x, bits);
        }
    }
}

/// `vector_add(lhs, rhs, rank)` — `ml_kem.c:1208-1213`.
///
/// # Safety
/// `rank >= 1` and both vectors must be live for `rank` scalars.
pub(crate) unsafe fn vector_add(lhs: *mut Scalar, rhs: *const Scalar, rank: c_int) {
    let mut l = lhs;
    let mut r = rhs;
    let mut n = rank;
    loop {
        // SAFETY: both vectors are live for `rank` scalars per the contract.
        unsafe { scalar_add(l, r) };
        // SAFETY: the pointers stay within their own objects per the contract.
        unsafe {
            l = l.add(1);
            r = r.add(1);
        }
        n -= 1;
        if n <= 0 {
            break;
        }
    }
}

/// `vector_encode(out, a, bits, rank)` — `ml_kem.c:1220-1226`.
///
/// # Safety
/// `out` must be writable for `rank * DEGREE / 8 * bits` bytes.
pub(crate) unsafe fn vector_encode(out: *mut u8, a: *const Scalar, bits: c_int, rank: c_int) {
    let stride = (bits as usize) * ML_KEM_DEGREE / 8;
    let mut p = out;
    let mut s = a;
    let mut n = rank;
    while n > 0 {
        // SAFETY: `p` is writable and `s` live per the contract.
        unsafe { scalar_encode(p, s, bits) };
        // SAFETY: the pointers stay within their own objects per the contract.
        unsafe {
            p = p.add(stride);
            s = s.add(1);
        }
        n -= 1;
    }
}

/// `vector_decode_decompress_ntt(out, in, bits, rank)` — `ml_kem.c:1237-1247`.
///
/// # Safety
/// `in` must be readable for `rank * DEGREE / 8 * bits` bytes.
pub(crate) unsafe fn vector_decode_decompress_ntt(
    out: *mut Scalar,
    in_: *const u8,
    bits: c_int,
    rank: c_int,
) {
    let stride = (bits as usize) * ML_KEM_DEGREE / 8;
    let mut p = in_;
    let mut o = out;
    let mut n = rank;
    while n > 0 {
        // SAFETY: `p` is readable and `o` live per the contract.
        unsafe {
            scalar_decode(o, p, bits);
            scalar_decompress(o, bits);
            scalar_ntt(o);
        }
        // SAFETY: the pointers stay within their own objects per the contract.
        unsafe {
            p = p.add(stride);
            o = o.add(1);
        }
        n -= 1;
    }
}

/// `vector_decode_12(out, in, rank)` — `ml_kem.c:1250-1258`.
///
/// # Safety
/// `in` must be readable for `rank * 3 * DEGREE / 2` bytes.
pub(crate) unsafe fn vector_decode_12(out: *mut Scalar, in_: *const u8, rank: c_int) -> c_int {
    let stride = 3 * ML_KEM_DEGREE / 2;
    let mut p = in_;
    let mut o = out;
    let mut n = rank;
    while n > 0 {
        // SAFETY: `p` is readable and `o` live per the contract.
        unsafe {
            if scalar_decode_12(o, p) == 0 {
                return 0;
            }
        }
        // SAFETY: the pointers stay within their own objects per the contract.
        unsafe {
            p = p.add(stride);
            o = o.add(1);
        }
        n -= 1;
    }
    1
}

/// `vector_compress(a, bits, rank)` — `ml_kem.c:1261-1266`.
///
/// # Safety
/// `rank >= 1` and `a` must be live for `rank` scalars.
pub(crate) unsafe fn vector_compress(a: *mut Scalar, bits: c_int, rank: c_int) {
    let mut s = a;
    let mut n = rank;
    loop {
        // SAFETY: `s` is live per the contract.
        unsafe { scalar_compress(s, bits) };
        // SAFETY: the pointer stays within its own object per the contract.
        unsafe {
            s = s.add(1);
        }
        n -= 1;
        if n <= 0 {
            break;
        }
    }
}

/// `inner_product(out, lhs, rhs, rank)` — `ml_kem.c:1269-1275`.
///
/// # Safety
/// The output must not overlap the inputs, and all must be live for `rank` scalars.
pub(crate) unsafe fn inner_product(
    out: *mut Scalar,
    lhs: *const Scalar,
    rhs: *const Scalar,
    rank: c_int,
) {
    // SAFETY: all three are live and disjoint per the contract.
    unsafe {
        scalar_mult(out, lhs, rhs);
        let mut l = lhs.add(1);
        let mut r = rhs.add(1);
        let mut n = rank - 1;
        while n > 0 {
            scalar_mult_add(out, l, r);
            l = l.add(1);
            r = r.add(1);
            n -= 1;
        }
    }
}

/// `matrix_mult_intt(out, m, a, rank)` — `ml_kem.c:1281-1293`, result inverse-NTT'd.
///
/// # Safety
/// The output must not overlap the inputs, and all must be live for `rank * rank`/`rank` scalars.
pub(crate) unsafe fn matrix_mult_intt(
    out: *mut Scalar,
    m: *const Scalar,
    a: *const Scalar,
    rank: c_int,
) {
    // SAFETY: all three are live and disjoint per the contract.
    unsafe {
        let mut o = out;
        let mut mc = m;
        let mut i = rank;
        while i > 0 {
            i -= 1;
            let mut ar = a;
            scalar_mult(o, mc, ar);
            mc = mc.add(1);
            let mut j = rank - 1;
            while j > 0 {
                ar = ar.add(1);
                scalar_mult_add(o, mc, ar);
                mc = mc.add(1);
                j -= 1;
            }
            scalar_inverse_ntt(o);
            o = o.add(1);
        }
    }
}

/// `matrix_mult_transpose_add(out, m, a, rank)` — `ml_kem.c:1296-1307`.
///
/// # Safety
/// The output must not overlap the inputs, and all must be live for `rank * rank`/`rank` scalars.
pub(crate) unsafe fn matrix_mult_transpose_add(
    out: *mut Scalar,
    m: *const Scalar,
    a: *const Scalar,
    rank: c_int,
) {
    // SAFETY: all three are live and disjoint per the contract.
    unsafe {
        let mut o = out;
        let mut mc = m;
        let mut i = rank;
        while i > 0 {
            i -= 1;
            let mut ar = a;
            let mut mr = mc;
            mc = mc.add(1);
            scalar_mult_add(o, mr, ar);
            let mut j = rank;
            while j > 1 {
                j -= 1;
                ar = ar.add(1);
                mr = mr.add(rank as usize);
                scalar_mult_add(o, mr, ar);
            }
            o = o.add(1);
        }
    }
}

/// `matrix_expand(mdctx, key)` — `ml_kem.c:1316-1341`, FIPS 203 Algorithm 7's `A` expansion.
///
/// # Safety
/// `key` must be live with a populated `rho` and allocated `m`.
pub(crate) unsafe fn matrix_expand(mdctx: *mut EvpMdCtx, key: *mut MlKemKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    unsafe {
        let mut out = (*key).m;
        let mut input = [0u8; ML_KEM_RANDOM_BYTES + 2];
        let rank = (*(*key).vinfo).rank;
        let shake128_md = (*key).shake128_md;

        ptr::copy_nonoverlapping((*key).rho, input.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
        for i in 0..rank {
            for j in 0..rank {
                input[ML_KEM_RANDOM_BYTES] = i as u8;
                input[ML_KEM_RANDOM_BYTES + 1] = j as u8;
                if EVP_DigestInit_ex(mdctx, shake128_md, ptr::null_mut()) == 0
                    || EVP_DigestUpdate(mdctx, input.as_ptr().cast(), input.len()) == 0
                    || sample_scalar(out, mdctx) == 0
                {
                    return 0;
                }
                out = out.add(1);
            }
        }
        1
    }
}

/// `CBD_FUNC` — `ml_kem.c:123-124`, `int (*)(scalar *, uint8_t[ML_KEM_RANDOM_BYTES + 1], ...)`.
pub(crate) type CbdFunc = unsafe fn(*mut Scalar, *mut u8, *mut EvpMdCtx, *const MlKemKey) -> c_int;

/// `cbd_2(out, in, mdctx, key)` — `ml_kem.c:1351-1387`, FIPS 203 Algorithm 7 with `eta == 2`.
///
/// # Safety
/// `key` must be live with a fetched `shake256_md`.
pub(crate) unsafe fn cbd_2(
    out: *mut Scalar,
    in_: *mut u8,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `out` and `key` are live per the contract.
    unsafe {
        let c = &mut (*out).c;
        let mut randbuf = [0u8; 4 * ML_KEM_DEGREE / 8];

        if prf(randbuf.as_mut_ptr(), randbuf.len(), in_, mdctx, key) == 0 {
            crate::runtime::mem::OPENSSL_cleanse(randbuf.as_mut_ptr().cast(), randbuf.len());
            return 0;
        }

        let mut curr = 0usize;
        let mut r = 0usize;
        loop {
            let b = randbuf[r];
            r += 1;

            let mut value: u16 = (bit0(b) as u16) + (bitn(1, b) as u16);
            value = value.wrapping_sub((bitn(2, b) as u16).wrapping_add(bitn(3, b) as u16));
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            let mut value: u16 = (bitn(4, b) as u16) + (bitn(5, b) as u16);
            value = value.wrapping_sub((bitn(6, b) as u16).wrapping_add(bitn(7, b) as u16));
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            if curr >= ML_KEM_DEGREE {
                break;
            }
        }

        crate::runtime::mem::OPENSSL_cleanse(randbuf.as_mut_ptr().cast(), randbuf.len());
        1
    }
}

/// `cbd_3(out, in, mdctx, key)` — `ml_kem.c:1395-1443`, FIPS 203 Algorithm 7 with `eta == 3`.
///
/// # Safety
/// `key` must be live with a fetched `shake256_md`.
pub(crate) unsafe fn cbd_3(
    out: *mut Scalar,
    in_: *mut u8,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: `out` and `key` are live per the contract.
    unsafe {
        let c = &mut (*out).c;
        let mut randbuf = [0u8; 6 * ML_KEM_DEGREE / 8];

        if prf(randbuf.as_mut_ptr(), randbuf.len(), in_, mdctx, key) == 0 {
            crate::runtime::mem::OPENSSL_cleanse(randbuf.as_mut_ptr().cast(), randbuf.len());
            return 0;
        }

        let mut curr = 0usize;
        let mut r = 0usize;
        loop {
            let b1 = randbuf[r];
            let b2 = randbuf[r + 1];
            let b3 = randbuf[r + 2];
            r += 3;

            let mut value: u16 = (bit0(b1) as u16) + (bitn(1, b1) as u16) + (bitn(2, b1) as u16);
            value = value.wrapping_sub(
                (bitn(3, b1) as u16)
                    .wrapping_add(bitn(4, b1) as u16)
                    .wrapping_add(bitn(5, b1) as u16),
            );
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            let mut value: u16 = (bitn(6, b1) as u16) + (bitn(7, b1) as u16) + (bit0(b2) as u16);
            value = value.wrapping_sub(
                (bitn(1, b2) as u16)
                    .wrapping_add(bitn(2, b2) as u16)
                    .wrapping_add(bitn(3, b2) as u16),
            );
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            let mut value: u16 = (bitn(4, b2) as u16) + (bitn(5, b2) as u16) + (bitn(6, b2) as u16);
            value = value.wrapping_sub(
                (bitn(7, b2) as u16)
                    .wrapping_add(bit0(b3) as u16)
                    .wrapping_add(bitn(1, b3) as u16),
            );
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            let mut value: u16 = (bitn(2, b3) as u16) + (bitn(3, b3) as u16) + (bitn(4, b3) as u16);
            value = value.wrapping_sub(
                (bitn(5, b3) as u16)
                    .wrapping_add(bitn(6, b3) as u16)
                    .wrapping_add(bitn(7, b3) as u16),
            );
            let mask = constish_time_non_zero(value >> 15);
            c[curr] = value.wrapping_add((ML_KEM_PRIME as u16) & mask);
            curr += 1;

            if curr >= ML_KEM_DEGREE {
                break;
            }
        }

        crate::runtime::mem::OPENSSL_cleanse(randbuf.as_mut_ptr().cast(), randbuf.len());
        1
    }
}

/// `gencbd_vector(out, cbd, counter, seed, rank, mdctx, key)` — `ml_kem.c:1449-1467`.
///
/// # Safety
/// `out` must be live for `rank` scalars.
pub(crate) unsafe fn gencbd_vector(
    out: *mut Scalar,
    cbd: CbdFunc,
    counter: *mut u8,
    seed: *const u8,
    rank: c_int,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: all arguments are live per the contract.
    unsafe {
        let mut input = [0u8; ML_KEM_RANDOM_BYTES + 1];
        let mut ret = 0;
        let mut o = out;
        let mut n = rank;

        ptr::copy_nonoverlapping(seed, input.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
        loop {
            input[ML_KEM_RANDOM_BYTES] = *counter;
            *counter = counter.read().wrapping_add(1);
            if cbd(o, input.as_mut_ptr(), mdctx, key) == 0 {
                break;
            }
            o = o.add(1);
            n -= 1;
            if n <= 0 {
                ret = 1;
                break;
            }
        }

        crate::runtime::mem::OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len());
        ret
    }
}

/// `gencbd_vector_ntt(out, cbd, counter, seed, rank, mdctx, key)` — `ml_kem.c:1472-1491`.
///
/// # Safety
/// `out` must be live for `rank` scalars.
pub(crate) unsafe fn gencbd_vector_ntt(
    out: *mut Scalar,
    cbd: CbdFunc,
    counter: *mut u8,
    seed: *const u8,
    rank: c_int,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: all arguments are live per the contract.
    unsafe {
        let mut input = [0u8; ML_KEM_RANDOM_BYTES + 1];
        let mut ret = 0;
        let mut o = out;
        let mut n = rank;

        ptr::copy_nonoverlapping(seed, input.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
        loop {
            input[ML_KEM_RANDOM_BYTES] = *counter;
            *counter = counter.read().wrapping_add(1);
            if cbd(o, input.as_mut_ptr(), mdctx, key) == 0 {
                break;
            }
            scalar_ntt(o);
            o = o.add(1);
            n -= 1;
            if n <= 0 {
                ret = 1;
                break;
            }
        }

        crate::runtime::mem::OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len());
        ret
    }
}

/// `CBD1(evp_type)` — `ml_kem.c:1494`, `cbd_3` for ML-KEM-512 and `cbd_2` otherwise.
#[inline]
pub(crate) fn cbd1(evp_type: c_int) -> CbdFunc {
    if evp_type == super::EVP_PKEY_ML_KEM_512 {
        cbd_3
    } else {
        cbd_2
    }
}

/// `encrypt_cpa(out, message, r, tmp, mdctx, key)` — `ml_kem.c:1512-1564`, FIPS 203 Algorithm 14.
///
/// # Safety
/// `tmp` must be live for `2 * rank` scalars and `key` must be a populated public key.
pub(crate) unsafe fn encrypt_cpa(
    out: *mut u8,
    message: *const u8,
    r: *const u8,
    tmp: *mut Scalar,
    mdctx: *mut EvpMdCtx,
    key: *const MlKemKey,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let cbd_1 = cbd1((*vinfo).evp_type);
        let rank = (*vinfo).rank;
        // We can use tmp[0..rank-1] as storage for |y|, then |e1|, ...
        let y = tmp;
        let e1 = tmp;
        let e2 = tmp;
        // We can use tmp[rank]..tmp[2*rank - 1] for |u|
        let u = tmp.add(rank as usize);
        let mut v = Scalar::ZERO;
        let mut input = [0u8; ML_KEM_RANDOM_BYTES + 1];
        let mut counter: u8 = 0;
        let du = (*vinfo).du;
        let dv = (*vinfo).dv;
        let mut ret = 0;

        // FIPS 203 "y" vector
        if gencbd_vector_ntt(y, cbd_1, &mut counter, r, rank, mdctx, key) == 0 {
            crate::runtime::mem::OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len());
            crate::runtime::mem::OPENSSL_cleanse(
                (&raw mut v).cast(),
                core::mem::size_of::<Scalar>(),
            );
            return 0;
        }
        // FIPS 203 "v" scalar
        inner_product(&mut v, (*key).t, y, rank);
        scalar_inverse_ntt(&mut v);
        // FIPS 203 "u" vector
        matrix_mult_intt(u, (*key).m, y, rank);

        // All done with |y|, now free to reuse tmp[0] for FIPS 203 |e1|
        let ok = gencbd_vector(e1, cbd_2, &mut counter, r, rank, mdctx, key);
        if ok != 0 {
            vector_add(u, e1, rank);
            vector_compress(u, du, rank);
            vector_encode(out, u, du, rank);

            // All done with |e1|, now free to reuse tmp[0] for FIPS 203 |e2|
            ptr::copy_nonoverlapping(r, input.as_mut_ptr(), ML_KEM_RANDOM_BYTES);
            input[ML_KEM_RANDOM_BYTES] = counter;
            if cbd_2(e2, input.as_mut_ptr(), mdctx, key) != 0 {
                scalar_add(&mut v, e2);

                // Combine message with |v|
                scalar_decode_decompress_add(&mut v, message);
                scalar_compress(&mut v, dv);
                scalar_encode(out.add((*vinfo).u_vector_bytes), &v, dv);
                ret = 1;
            }
        }
        crate::runtime::mem::OPENSSL_cleanse(input.as_mut_ptr().cast(), input.len());
        crate::runtime::mem::OPENSSL_cleanse((&raw mut v).cast(), core::mem::size_of::<Scalar>());
        ret
    }
}

/// `decrypt_cpa(out, ctext, u, key)` — `ml_kem.c:1569-1590`, FIPS 203 Algorithm 15.
///
/// # Safety
/// `u` must be live for `rank` scalars.
pub(crate) unsafe fn decrypt_cpa(
    out: *mut u8,
    ctext: *const u8,
    u: *mut Scalar,
    key: *const MlKemKey,
) {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let vinfo = (*key).vinfo;
        let rank = (*vinfo).rank;
        let du = (*vinfo).du;
        let dv = (*vinfo).dv;
        let mut v = Scalar::ZERO;
        let mut mask = Scalar::ZERO;

        vector_decode_decompress_ntt(u, ctext, du, rank);
        scalar_decode(&mut v, ctext.add((*vinfo).u_vector_bytes), dv);
        scalar_decompress(&mut v, dv);
        inner_product(&mut mask, (*key).s, u, rank);
        scalar_inverse_ntt(&mut mask);
        scalar_sub(&mut v, &mask);
        scalar_compress(&mut v, 1);
        scalar_encode_1(out, &v);

        crate::runtime::mem::OPENSSL_cleanse((&raw mut v).cast(), core::mem::size_of::<Scalar>());
        crate::runtime::mem::OPENSSL_cleanse(
            (&raw mut mask).cast(),
            core::mem::size_of::<Scalar>(),
        );
    }
}
