//! `crypto/ml_dsa/ml_dsa_sample.c` — the rejection samplers.
//!
//! This file is the whole of `ml_dsa_sample.c`: `RejNTTPoly` (FIPS 204 Algorithm 30) and its
//! `CoeffFromThreeBytes`, `RejBoundedPoly` (Algorithm 31) and its two `CoeffFromHalfByte` arms,
//! `ExpandA` (Algorithm 32), `ExpandS` (Algorithm 33), `ExpandMask` (Algorithm 34) and
//! `SampleInBall` (Algorithm 29).
//!
//! ## The two block sizes are read from the header's formula, not typed
//!
//! `SHAKE128_BLOCKSIZE`/`SHAKE256_BLOCKSIZE` are `SHA3_BLOCKSIZE(128)`/`(256)`, i.e. `200 - 2 * n / 8`
//! = 168 and 136. `rej_ntt_poly` requires 168 to be a multiple of 3, which the file's own `#error`
//! asserts; the const expression here keeps that arithmetic visible.
//!
//! ## `value_barrier_32` is the crate's `black_box`
//!
//! `coeff_from_nibble_4`/`_2` guard their range tests with `value_barrier_32(...)` so the compiler
//! cannot turn the branch into a value select. The crate's spelling for that barrier is
//! [`core::hint::black_box`], the same substitution `src/ec/curve448.rs` records (D371's sibling).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::evp::digest::{EVP_DigestSqueeze, EvpMd, EvpMdCtx};
use crate::runtime::mem::OPENSSL_cleanse;

use super::encoders::ossl_ml_dsa_poly_decode_expand_mask;
use super::hash::shake_xof;
use super::poly::{poly_zero, Matrix, Poly, Vector};
use super::{
    mod_sub, ML_DSA_ETA_4, ML_DSA_GAMMA1_TWO_POWER_19, ML_DSA_NUM_POLY_COEFFICIENTS,
    ML_DSA_PRIV_SEED_BYTES, ML_DSA_Q, ML_DSA_RHO_BYTES,
};

/// `SHAKE128_BLOCKSIZE` — `ml_dsa_sample.c:19`, `SHA3_BLOCKSIZE(128)`, `200 - 2 * 128 / 8`.
pub(crate) const SHAKE128_BLOCKSIZE: usize = 200 - 2 * (128 / 8);
/// `SHAKE256_BLOCKSIZE` — `ml_dsa_sample.c:20`, `SHA3_BLOCKSIZE(256)`, `200 - 2 * 256 / 8`.
pub(crate) const SHAKE256_BLOCKSIZE: usize = 200 - 2 * (256 / 8);

/// `MOD5(n)` — `ml_dsa_sample.c:27`, a constant-time `n % 5` for `n` in `0..16`.
///
/// `0xFFFF / 5 = 0x3333`; `2` is added to over-estimate `1/5` and the result is divided by
/// `0xFFFF + 1`, which is the header's own comment (`:23-26`).
#[inline(always)]
fn mod5(n: u32) -> u32 {
    n.wrapping_sub(5u32.wrapping_mul((0x3335u32.wrapping_mul(n)) >> 16))
}

/// `COEFF_FROM_NIBBLE_FUNC` — `ml_dsa_sample.c:33`, `int (*)(uint32_t nibble, uint32_t *out)`.
type CoeffFromNibbleFn = fn(u32, &mut u32) -> c_int;

/// `coeff_from_three_bytes(s, out)` — `ml_dsa_sample.c:49-54`, FIPS 204 Algorithm 14.
///
/// Not constant time: it generates the public matrix `A`. Returns 1 when the coefficient is `< q`.
#[inline]
fn coeff_from_three_bytes(s: &[u8], out: &mut u32) -> c_int {
    // Zero out the top bit of the 3rd byte to get a value in the range 0..2^23-1.
    *out = (s[0] as u32) | ((s[1] as u32) << 8) | (((s[2] as u32) & 0x7f) << 16);
    (*out < ML_DSA_Q) as c_int
}

/// `coeff_from_nibble_4(nibble, out)` — `ml_dsa_sample.c:66-77`, `CoeffFromHalfByte` with `eta = 4`.
///
/// The range is `(q-4)..0..4` — the FIPS 204 `-4..4` with `q` added to the negatives, as the file's
/// comment says (`:59-60`).
#[inline]
fn coeff_from_nibble_4(nibble: u32, out: &mut u32) -> c_int {
    // Not constant time, but the value is either chosen or thrown away, so nothing leaks.
    if core::hint::black_box(nibble < 9) {
        *out = mod_sub(4, nibble);
        return 1;
    }
    0
}

/// `coeff_from_nibble_2(nibble, out)` — `ml_dsa_sample.c:89-96`, `CoeffFromHalfByte` with `eta = 2`.
#[inline]
fn coeff_from_nibble_2(nibble: u32, out: &mut u32) -> c_int {
    if core::hint::black_box(nibble < 15) {
        *out = mod_sub(2, mod5(nibble));
        return 1;
    }
    0
}

/// `rej_ntt_poly(g_ctx, md, seed, seed_len, out)` — `ml_dsa_sample.c:117-140`, FIPS 204 Algorithm 30.
///
/// A whole 168-byte block is squeezed at a time rather than three bytes, because the block size is
/// divisible by 3. The `|out|` coefficients are in `0..q-1`, which is what the NTT requires.
///
/// # Safety
/// `g_ctx` must be a live digest context, `md` a fetched SHAKE128, `seed` readable for `seed_len`
/// bytes and `out` one initialised polynomial.
pub(crate) unsafe fn rej_ntt_poly(
    g_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    seed: *const u8,
    seed_len: usize,
    out: &mut Poly,
) -> c_int {
    let mut j = 0usize;
    let mut blocks = [0u8; SHAKE128_BLOCKSIZE];

    // SAFETY: the arguments are live per the contract.
    if unsafe { shake_xof(g_ctx, md, seed, seed_len, blocks.as_mut_ptr(), blocks.len()) } == 0 {
        return 0;
    }

    loop {
        let mut b = 0usize;
        while b < blocks.len() {
            let mut coeff = 0u32;
            if coeff_from_three_bytes(&blocks[b..], &mut coeff) != 0 {
                out.coeff[j] = coeff;
                j += 1;
                if j >= ML_DSA_NUM_POLY_COEFFICIENTS {
                    return 1; /* finished */
                }
            }
            b += 3;
        }
        // SAFETY: `g_ctx` is live and `blocks` is a live 168-byte buffer.
        if unsafe { EVP_DigestSqueeze(g_ctx, blocks.as_mut_ptr(), blocks.len()) } == 0 {
            return 0;
        }
    }
}

/// `rej_bounded_poly(h_ctx, md, coef_from_nibble, seed, seed_len, out)` — `ml_dsa_sample.c:159-194`,
/// FIPS 204 Algorithm 31.
///
/// # Safety
/// `h_ctx` must be a live digest context, `md` a fetched SHAKE256, `seed` readable for `seed_len`
/// bytes and `out` one initialised polynomial.
pub(crate) unsafe fn rej_bounded_poly(
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    coef_from_nibble: CoeffFromNibbleFn,
    seed: *const u8,
    seed_len: usize,
    out: &mut Poly,
) -> c_int {
    let mut j = 0usize;
    let mut blocks = [0u8; SHAKE256_BLOCKSIZE];

    // SAFETY: the arguments are live per the contract.
    if unsafe { shake_xof(h_ctx, md, seed, seed_len, blocks.as_mut_ptr(), blocks.len()) } == 0 {
        // SAFETY: `blocks` is a live local of exactly its length.
        unsafe { OPENSSL_cleanse(blocks.as_mut_ptr().cast(), blocks.len()) };
        return 0;
    }

    let ret = 'outer: loop {
        for &byte in blocks.iter() {
            let z0 = (byte & 0x0F) as u32; /* lower nibble */
            let z1 = (byte >> 4) as u32; /* high nibble */

            let mut coeff = 0u32;
            if coef_from_nibble(z0, &mut coeff) != 0 {
                out.coeff[j] = coeff;
                j += 1;
                if j >= ML_DSA_NUM_POLY_COEFFICIENTS {
                    break 'outer 1;
                }
            }
            let mut coeff = 0u32;
            if coef_from_nibble(z1, &mut coeff) != 0 {
                out.coeff[j] = coeff;
                j += 1;
                if j >= ML_DSA_NUM_POLY_COEFFICIENTS {
                    break 'outer 1;
                }
            }
        }
        // SAFETY: `h_ctx` is live and `blocks` is a live 136-byte buffer.
        if unsafe { EVP_DigestSqueeze(h_ctx, blocks.as_mut_ptr(), blocks.len()) } == 0 {
            break 'outer 0;
        }
    };

    // SAFETY: `blocks` is a live local of exactly its length.
    unsafe { OPENSSL_cleanse(blocks.as_mut_ptr().cast(), blocks.len()) };
    ret
}

/// `ossl_ml_dsa_matrix_expand_A(g_ctx, md, rho, out)` — `ml_dsa_sample.c:209-239`, FIPS 204
/// Algorithm 32.
///
/// The seed for matrix element `(i, j)` is `rho || j || i`, and the two seeds and the sampling
/// buffers are **not** cleansed: per FIPS 204 section 3.6.3 `A` is easily computed from the public
/// key and needs no protection, which the file's own comment states (`:217-222`).
///
/// # Safety
/// `g_ctx` must be a live digest context, `md` a fetched SHAKE128, `rho` readable for
/// `ML_DSA_RHO_BYTES` bytes, and `out` must name a `k` by `l` block of polynomials.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_dsa_matrix_expand_A`)
pub(crate) unsafe fn ossl_ml_dsa_matrix_expand_A(
    g_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    rho: *const u8,
    out: &mut Matrix,
) -> c_int {
    let mut derived_seed = [0u8; ML_DSA_RHO_BYTES + 2];

    // SAFETY: `rho` is readable for `ML_DSA_RHO_BYTES` bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(rho, derived_seed.as_mut_ptr(), ML_DSA_RHO_BYTES) };

    let base = out.m_poly;
    let mut idx = 0usize;
    for i in 0..out.k {
        for j in 0..out.l {
            derived_seed[ML_DSA_RHO_BYTES + 1] = i as u8;
            derived_seed[ML_DSA_RHO_BYTES] = j as u8;
            // SAFETY: `base` names `k * l` polynomials per the contract, and `idx < k * l`.
            if unsafe {
                rej_ntt_poly(
                    g_ctx,
                    md,
                    derived_seed.as_ptr(),
                    derived_seed.len(),
                    &mut *base.add(idx),
                )
            } == 0
            {
                return 0;
            }
            idx += 1;
        }
    }
    1
}

/// `ossl_ml_dsa_vector_expand_S(h_ctx, md, eta, seed, s1, s2)` — `ml_dsa_sample.c:259-295`, FIPS 204
/// Algorithm 33.
///
/// Each polynomial uses `seed || counter`, the counter starting at 0 and incrementing one byte at a
/// time; the FIPS 204 range `-eta..eta` is again kept as `(q-eta)..eta`.
///
/// # Safety
/// `s1` must name `l` polynomials, `s2` must name `k` polynomials, `seed` must be readable for
/// `ML_DSA_PRIV_SEED_BYTES` bytes, and `h_ctx`/`md` must be live.
#[allow(non_snake_case)] // the authority's own spelling (`ossl_ml_dsa_vector_expand_S`)
pub(crate) unsafe fn ossl_ml_dsa_vector_expand_S(
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    eta: c_int,
    seed: *const u8,
    s1: &mut Vector,
    s2: &mut Vector,
) -> c_int {
    let l = s1.num_poly;
    let k = s2.num_poly;
    let mut derived_seed = [0u8; ML_DSA_PRIV_SEED_BYTES + 2];
    let coef_from_nibble_fn: CoeffFromNibbleFn = if eta == ML_DSA_ETA_4 {
        coeff_from_nibble_4
    } else {
        coeff_from_nibble_2
    };

    // SAFETY: `seed` is readable for `ML_DSA_PRIV_SEED_BYTES` bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(seed, derived_seed.as_mut_ptr(), ML_DSA_PRIV_SEED_BYTES) };
    derived_seed[ML_DSA_PRIV_SEED_BYTES] = 0;
    derived_seed[ML_DSA_PRIV_SEED_BYTES + 1] = 0;

    for i in 0..l {
        // SAFETY: `s1.poly` names `l` polynomials per the contract, and `i < l`.
        let ok = unsafe {
            rej_bounded_poly(
                h_ctx,
                md,
                coef_from_nibble_fn,
                derived_seed.as_ptr(),
                derived_seed.len(),
                &mut *s1.poly.add(i),
            )
        };
        if ok == 0 {
            // SAFETY: `derived_seed` is a live local of exactly its length.
            unsafe { OPENSSL_cleanse(derived_seed.as_mut_ptr().cast(), derived_seed.len()) };
            return 0;
        }
        derived_seed[ML_DSA_PRIV_SEED_BYTES] = derived_seed[ML_DSA_PRIV_SEED_BYTES].wrapping_add(1);
    }
    for i in 0..k {
        // SAFETY: `s2.poly` names `k` polynomials per the contract, and `i < k`.
        let ok = unsafe {
            rej_bounded_poly(
                h_ctx,
                md,
                coef_from_nibble_fn,
                derived_seed.as_ptr(),
                derived_seed.len(),
                &mut *s2.poly.add(i),
            )
        };
        if ok == 0 {
            // SAFETY: `derived_seed` is a live local of exactly its length.
            unsafe { OPENSSL_cleanse(derived_seed.as_mut_ptr().cast(), derived_seed.len()) };
            return 0;
        }
        derived_seed[ML_DSA_PRIV_SEED_BYTES] = derived_seed[ML_DSA_PRIV_SEED_BYTES].wrapping_add(1);
    }

    // SAFETY: `derived_seed` is a live local of exactly its length.
    unsafe { OPENSSL_cleanse(derived_seed.as_mut_ptr().cast(), derived_seed.len()) };
    1
}

/// `ossl_ml_dsa_poly_expand_mask(out, seed, seed_len, gamma1, h_ctx, md)` — `ml_dsa_sample.c:298-309`,
/// FIPS 204 Algorithm 34 steps 4 and 5.
///
/// `gamma1` is `2^19` (44 bytes per entry) for ML-DSA-65/87 and `2^17` (18 bytes) for ML-DSA-44, so
/// `32 * 20` bytes is the buffer bound.
///
/// # Safety
/// `out` must name one initialised polynomial, `seed` readable for `seed_len` bytes, and
/// `h_ctx`/`md` live.
pub(crate) unsafe fn ossl_ml_dsa_poly_expand_mask(
    out: &mut Poly,
    seed: *const u8,
    seed_len: usize,
    gamma1: u32,
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
) -> c_int {
    let mut buf = [0u8; 32 * 20];
    let buf_len = 32
        * if gamma1 == ML_DSA_GAMMA1_TWO_POWER_19 {
            20
        } else {
            18
        };

    // SAFETY: `h_ctx`/`md` are live and `buf` is writable for `buf_len <= 640` bytes per the
    // contract; `out` names one initialised polynomial.
    let ret = unsafe {
        shake_xof(h_ctx, md, seed, seed_len, buf.as_mut_ptr(), buf_len) != 0
            && ossl_ml_dsa_poly_decode_expand_mask(out, buf.as_ptr(), buf_len, gamma1) != 0
    };

    // SAFETY: `buf` is a live local of exactly its length.
    unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) };
    ret as c_int
}

/// `ossl_ml_dsa_poly_sample_in_ball(out_c, seed, seed_len, h_ctx, md, tau)` — `ml_dsa_sample.c:325-380`,
/// FIPS 204 Algorithm 29.
///
/// Durstenfeld's Fisher-Yates shuffle over the last `tau` positions. The coefficients are kept
/// positive (`q-1`, `0` or `1`), and the function is **not** constant time, as its own comment says
/// (`:316`).
///
/// # Safety
/// `out_c` must name one initialised polynomial, `seed` readable for `seed_len` bytes, and
/// `h_ctx`/`md` live.
pub(crate) unsafe fn ossl_ml_dsa_poly_sample_in_ball(
    out_c: &mut Poly,
    seed: *const u8,
    seed_len: c_int,
    h_ctx: *mut EvpMdCtx,
    md: *const EvpMd,
    tau: u32,
) -> c_int {
    let mut block = [0u8; SHAKE256_BLOCKSIZE];
    let mut offset = 8usize;

    // SAFETY: `h_ctx`/`md` are live, `seed` is readable for `seed_len` bytes and `block` is a live
    // 136-byte buffer per the contract.
    if unsafe {
        shake_xof(
            h_ctx,
            md,
            seed,
            seed_len as usize,
            block.as_mut_ptr(),
            block.len(),
        )
    } == 0
    {
        // SAFETY: `block` is a live local of exactly its length.
        unsafe { OPENSSL_cleanse(block.as_mut_ptr().cast(), block.len()) };
        return 0;
    }

    // Grab the first 64 bits -- since tau < 64, each bit gives a +1 or -1 value.
    let mut signs = u64::from_le_bytes([
        block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
    ]);

    poly_zero(out_c);

    /* Loop tau times */
    for end in (ML_DSA_NUM_POLY_COEFFICIENTS - tau as usize)..ML_DSA_NUM_POLY_COEFFICIENTS {
        let index = loop {
            if offset == block.len() {
                // SAFETY: `h_ctx` is live and `block` is a live 136-byte buffer.
                if unsafe { EVP_DigestSqueeze(h_ctx, block.as_mut_ptr(), block.len()) } == 0 {
                    // SAFETY: `block` is a live local of exactly its length.
                    unsafe { OPENSSL_cleanse(block.as_mut_ptr().cast(), block.len()) };
                    return 0;
                }
                offset = 0;
            }
            let candidate = block[offset] as usize;
            offset += 1;
            if candidate <= end {
                break candidate;
            }
        };

        // In-place swap: move the coefficient about to be replaced to the end so no value that has
        // already been written is lost.
        out_c.coeff[end] = out_c.coeff[index];
        out_c.coeff[index] = mod_sub(1, 2 * ((signs & 1) as u32));
        signs >>= 1;
    }

    // SAFETY: `block` is a live local of exactly its length.
    unsafe { OPENSSL_cleanse(block.as_mut_ptr().cast(), block.len()) };
    1
}
