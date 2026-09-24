//! `crypto/ml_dsa/ml_dsa_sign.c` — the FIPS 204 signing and verification core.
//!
//! This file is the whole of `ml_dsa_sign.c:1-500`: the message-representative accumulator
//! (`ossl_ml_dsa_mu_init`/`_update`/`_finalize`), the two static algorithm bodies
//! (`ml_dsa_sign_internal`, FIPS 204 Algorithm 7, and `ml_dsa_verify_internal`, Algorithm 8), the
//! `static signature_init` that points an [`MlDsaSig`] at preallocated blocks, and the
//! `ossl_ml_dsa_sign`/`ossl_ml_dsa_verify` entry points the signature provider row calls.
//!
//! ## The unit raises three times, all `PROV_R_BAD_LENGTH` and all with no data
//!
//! `ossl_ml_dsa_mu_finalize` (`:135`), `ml_dsa_sign_internal` (`:181`) and `ml_dsa_verify_internal`
//! (`:344`) each guard a `mu` length with `ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH)`. The
//! authority spells these `ERR_raise`, not `ERR_raise_data`, so they carry no message: the crate's
//! data-less [`raise_site`] is the match, at the census's own coordinates
//! `err_sites::ML_DSA_SIGN_135`, `_181` and `_344`.
//!
//! ## Each internal takes one allocation and recovers its vectors by pointer arithmetic
//!
//! `ml_dsa_sign_internal` and `ml_dsa_verify_internal` both `OPENSSL_malloc` a single block and
//! place `c_ntt`, the `a_ntt` matrix, the signature's `z`/`hint` and their own temporaries — sign's
//! five `k`-long and three `l`-long vectors, verify's two extra `k`-long ones — inside it by
//! advancing a `POLY *`. That arithmetic is reproduced as written, exactly as `src/ml_dsa/poly.rs`'s
//! `Vector`/`Matrix` shape requires.
//!
//! ## Four vector operations are in place, which the crate's helpers cannot spell
//!
//! `ml_dsa_sign.c` aliases a `VECTOR *` onto a second name — `r0` onto `w1`, and `w_approx` and `w1`
//! onto `az_ntt` — and then calls `vector_low_bits(r0, gamma2, r0)`,
//! `vector_sub(&az_ntt, &ct1_ntt, w_approx)`, `vector_mult_scalar(&ct1_ntt, c_ntt, &ct1_ntt)` and
//! `vector_use_hint(&sig.hint, w_approx, gamma2, w1)` with the output aliasing an input. The
//! crate's `vector_*` helpers take `&Vector`/`&mut Vector` and document that `out` must not alias,
//! so those four calls are expanded here one polynomial at a time with a `Poly` copy as the input,
//! which is what the C's own element-at-a-time loop does.
//!
//! ## Three `ml_dsa_*.h` inlines this unit includes are written here
//!
//! `poly_sample_in_ball_ntt` (`ml_dsa_poly.h:73-81`), `vector_expand_mask`
//! (`ml_dsa_vector.h:155-174`) and `matrix_expand_A` (`ml_dsa_matrix.h:39-44`) are the three
//! `static ossl_inline` bodies this file reaches that `src/ml_dsa/poly.rs` does not carry, so each
//! is transcribed here beside its only caller rather than referenced; each names the `sample.rs`
//! function it forwards to.
//!
//! ## The signing path is randomised, and the randomness is the caller's
//!
//! `ossl_ml_dsa_sign` takes the 32-byte `rnd` the provider row drew and passes it through to
//! `ml_dsa_sign_internal`'s first `shake_xof_3`. This file calls no `RAND_*` entry point.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::evp::digest::{
    EVP_DigestInit_ex2, EVP_DigestSqueeze, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EvpMdCtx,
};
use crate::runtime::constant_time::{constant_time_ge_u32, constant_time_lt_u32};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::{CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};

use super::encoders::{ossl_ml_dsa_sig_decode, ossl_ml_dsa_sig_encode, ossl_ml_dsa_w1_encode};
use super::hash::{shake_xof_2, shake_xof_3};
use super::key::{ossl_ml_dsa_key_get_priv, ossl_ml_dsa_key_get_pub};
use super::ntt::ossl_ml_dsa_poly_ntt_mult;
use super::poly::{
    matrix_expand_A, matrix_init, matrix_mult_vector, poly_low_bits, poly_sample_in_ball_ntt,
    poly_sub, poly_use_hint, vector_add, vector_copy, vector_count_ones, vector_expand_mask,
    vector_high_bits, vector_make_hint, vector_max, vector_max_signed, vector_mult_scalar,
    vector_ntt, vector_ntt_inverse, vector_scale_power2_round_ntt, vector_sub, Poly, Vector,
};
use super::{
    MlDsaKey, MlDsaSig, ML_DSA_GAMMA2_Q_MINUS1_DIV88, ML_DSA_K_BYTES,
    ML_DSA_MAX_CONTEXT_STRING_LEN, ML_DSA_MU_BYTES, ML_DSA_RHO_PRIME_BYTES, ML_DSA_TR_BYTES,
};

extern "C" {
    /// `int memcmp(const void *, const void *, size_t)` — the authority's own comparison, reached at
    /// `ml_dsa_sign.c:403`.
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
}

/// `ML_DSA_MAX_LAMBDA` — `ml_dsa_sign.c:23`, the collision strength of ML-DSA-87 in bits.
const ML_DSA_MAX_LAMBDA: usize = 256;

/// The unit's own `__FILE__`, for the allocator's debug arguments.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ml_dsa/ml_dsa_sign.c".as_ptr();

/// `ml_dsa_sign_internal`'s `OPENSSL_malloc(alloc_len)`, `ml_dsa_sign.c:192`.
const LINE_SIGN_ALLOC: c_int = 192;
/// `ml_dsa_sign_internal`'s `OPENSSL_clear_free(alloc, alloc_len)`, `ml_dsa_sign.c:298`.
const LINE_SIGN_CLEAR_FREE: c_int = 298;
/// `ml_dsa_verify_internal`'s `OPENSSL_malloc(...)`, `ml_dsa_sign.c:350`.
const LINE_VERIFY_ALLOC: c_int = 350;
/// `ml_dsa_verify_internal`'s `OPENSSL_free(alloc)`, `ml_dsa_sign.c:405`.
const LINE_VERIFY_FREE: c_int = 405;

/// `signature_init(sig, hint, k, z, l, c_tilde, c_tilde_len)` — `ml_dsa_sign.c:38-46`.
///
/// Points an [`MlDsaSig`] at preallocated blocks; the signature owns none of them, exactly as the
/// authority's comment says.
fn signature_init(
    sig: &mut MlDsaSig,
    hint: *mut Poly,
    k: u32,
    z: *mut Poly,
    l: u32,
    c_tilde: *mut u8,
    c_tilde_len: usize,
) {
    sig.z = Vector::init(z, l as usize);
    sig.hint = Vector::init(hint, k as usize);
    sig.c_tilde = c_tilde;
    sig.c_tilde_len = c_tilde_len;
}

/// `ossl_ml_dsa_mu_init(key, encode, ctx, ctx_len)` — `ml_dsa_sign.c:69-109`.
///
/// Begins `H(tr || M')` and answers the live digest context, or NULL on any failure. `M'` is
/// `00 || ctx_len || ctx` only when `encode` is set, and the message follows in
/// [`ossl_ml_dsa_mu_update`].
///
/// # Safety
/// `key` must be a live key with a populated `tr` and `shake256_md`, and `ctx` must be readable for
/// `ctx_len` bytes when `encode` is nonzero.
pub(crate) unsafe fn ossl_ml_dsa_mu_init(
    key: *const MlDsaKey,
    encode: c_int,
    ctx: *const u8,
    ctx_len: usize,
) -> *mut EvpMdCtx {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        if key.is_null() {
            return ptr::null_mut();
        }
        let md_ctx = EVP_MD_CTX_new();
        if md_ctx.is_null() {
            return ptr::null_mut();
        }
        'err: {
            // H(.. pk (= key->tr)
            if EVP_DigestInit_ex2(md_ctx, (*key).shake256_md, ptr::null()) == 0 {
                break 'err;
            }
            if EVP_DigestUpdate(md_ctx, (*key).tr.as_ptr().cast(), ML_DSA_TR_BYTES) == 0 {
                break 'err;
            }
            // M' = 00 || IntegerToBytes(|ctx|, 1) || ctx, when `encode` is set.
            if encode != 0 {
                if ctx_len > ML_DSA_MAX_CONTEXT_STRING_LEN {
                    break 'err;
                }
                let mut itb = [0u8; 2];
                itb[0] = 0;
                itb[1] = ctx_len as u8;
                if EVP_DigestUpdate(md_ctx, itb.as_ptr().cast(), 2) == 0 {
                    break 'err;
                }
                if EVP_DigestUpdate(md_ctx, ctx.cast(), ctx_len) == 0 {
                    break 'err;
                }
                // .. msg) follows in the update and finalize functions.
            }
            return md_ctx;
        }
        EVP_MD_CTX_free(md_ctx);
        ptr::null_mut()
    }
}

/// `ossl_ml_dsa_mu_update(md_ctx, msg, msg_len)` — `ml_dsa_sign.c:119-122`.
///
/// # Safety
/// `md_ctx` must be live and initialised; `msg` readable for `msg_len` bytes.
pub(crate) unsafe fn ossl_ml_dsa_mu_update(
    md_ctx: *mut EvpMdCtx,
    msg: *const u8,
    msg_len: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe { EVP_DigestUpdate(md_ctx, msg.cast(), msg_len) }
}

/// `ossl_ml_dsa_mu_finalize(md_ctx, mu, mu_len)` — `ml_dsa_sign.c:132-139`.
///
/// # Safety
/// `md_ctx` must be live and initialised; `mu` writable for `mu_len` bytes.
pub(crate) unsafe fn ossl_ml_dsa_mu_finalize(
    md_ctx: *mut EvpMdCtx,
    mu: *mut u8,
    mu_len: usize,
) -> c_int {
    if mu_len != ML_DSA_MU_BYTES {
        // `!ossl_assert(mu_len == ML_DSA_MU_BYTES)`, which is this comparison under `NDEBUG`.
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ML_DSA_SIGN_135) };
        return 0;
    }
    // SAFETY: forwarded under this function's contract.
    unsafe { EVP_DigestSqueeze(md_ctx, mu, mu_len) }
}

/// `ml_dsa_sign_internal(priv, mu, mu_len, rnd, rnd_len, out_sig)` — `ml_dsa_sign.c:155-302`,
/// FIPS 204 Algorithm 7.
///
/// # Safety
/// `priv` must be a live private key with allocated `s1`/`s2`/`t0`; `mu` readable for `mu_len`
/// bytes; `rnd` readable for `rnd_len` bytes; and `out_sig` writable for `priv->params->sig_len`.
unsafe fn ml_dsa_sign_internal(
    priv_: *const MlDsaKey,
    mu: *const u8,
    mu_len: usize,
    rnd: *const u8,
    rnd_len: usize,
    out_sig: *mut u8,
) -> c_int {
    let mut ret = 0;
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let params = (*priv_).params;
        let k = (*params).k as u32;
        let l = (*params).l as u32;
        let gamma1 = (*params).gamma1 as u32;
        let gamma2 = (*params).gamma2 as u32;
        let num_polys_sig_k = 2 * k as usize;
        let num_polys_k = 5 * k as usize;
        let num_polys_l = 3 * l as usize;
        let num_polys_k_by_l = k as usize * l as usize;
        let mut rho_prime = [0u8; ML_DSA_RHO_PRIME_BYTES];
        let mut c_tilde = [0u8; ML_DSA_MAX_LAMBDA / 4];
        let c_tilde_len = ((*params).bit_strength >> 2) as usize;

        if mu_len != ML_DSA_MU_BYTES {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::ML_DSA_SIGN_181);
            return 0;
        }

        // One blob for most of the variable-size temporaries (every `POLY` is 1K).
        let w1_encoded_len = (k as usize)
            * if gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV88 {
                192
            } else {
                128
            };
        let alloc_len = w1_encoded_len
            + core::mem::size_of::<Poly>()
                * (1 + num_polys_k + num_polys_l + num_polys_k_by_l + num_polys_sig_k);
        let alloc = CRYPTO_malloc(alloc_len, FILE, LINE_SIGN_ALLOC).cast::<u8>();
        if alloc.is_null() {
            return 0;
        }
        let md_ctx = EVP_MD_CTX_new();

        // Point every temporary at its slice of the blob.
        let w1_encoded = alloc;
        let mut p: *mut Poly = w1_encoded.add(w1_encoded_len).cast();
        let c_ntt = p;
        p = p.add(1);
        let mut a_ntt = matrix_init(p, k as usize, l as usize);
        p = p.add(num_polys_k_by_l);
        let mut s2_ntt = Vector::init(p, k as usize);
        let mut t0_ntt = Vector::init(s2_ntt.poly.add(k as usize), k as usize);
        let mut w = Vector::init(t0_ntt.poly.add(k as usize), k as usize);
        let mut w1 = Vector::init(w.poly.add(k as usize), k as usize);
        let mut cs2 = Vector::init(w1.poly.add(k as usize), k as usize);
        p = p.add(num_polys_k);
        let mut s1_ntt = Vector::init(p, l as usize);
        let mut y = Vector::init(p.add(l as usize), l as usize);
        let mut cs1 = Vector::init(p.add(2 * l as usize), l as usize);
        p = p.add(num_polys_l);
        let mut sig = MlDsaSig {
            z: Vector::empty(),
            hint: Vector::empty(),
            c_tilde: ptr::null_mut(),
            c_tilde_len: 0,
        };
        signature_init(
            &mut sig,
            p,
            k,
            p.add(k as usize),
            l,
            c_tilde.as_mut_ptr(),
            c_tilde_len,
        );

        'err: {
            if md_ctx.is_null() {
                break 'err;
            }
            if matrix_expand_A(
                md_ctx,
                (*priv_).shake128_md,
                (*priv_).rho.as_ptr(),
                &mut a_ntt,
            ) == 0
            {
                break 'err;
            }

            // rho_prime = H(K || rnd || mu).
            if shake_xof_3(
                md_ctx,
                (*priv_).shake256_md,
                (*priv_).k.as_ptr(),
                ML_DSA_K_BYTES,
                rnd,
                rnd_len,
                mu,
                mu_len,
                rho_prime.as_mut_ptr(),
                rho_prime.len(),
            ) == 0
            {
                break 'err;
            }

            vector_copy(&mut s1_ntt, &(*priv_).s1);
            vector_ntt(&mut s1_ntt);
            vector_copy(&mut s2_ntt, &(*priv_).s2);
            vector_ntt(&mut s2_ntt);
            vector_copy(&mut t0_ntt, &(*priv_).t0);
            vector_ntt(&mut t0_ntt);

            // kappa must not exceed 2^16, but the chance of reaching even 1000 iterations is
            // vanishingly small.
            let mut kappa = 0usize;
            loop {
                let kappa_used = kappa as u32;
                kappa = kappa.wrapping_add(l as usize);

                // y_ntt is `cs1`.
                vector_expand_mask(
                    &mut y,
                    rho_prime.as_ptr(),
                    rho_prime.len(),
                    kappa_used,
                    gamma1,
                    md_ctx,
                    (*priv_).shake256_md,
                );
                vector_copy(&mut cs1, &y);
                vector_ntt(&mut cs1);

                matrix_mult_vector(&a_ntt, &cs1, &mut w);
                vector_ntt_inverse(&mut w);

                vector_high_bits(&w, gamma2, &mut w1);
                ossl_ml_dsa_w1_encode(&w1, gamma2, w1_encoded, w1_encoded_len);

                if shake_xof_2(
                    md_ctx,
                    (*priv_).shake256_md,
                    mu,
                    mu_len,
                    w1_encoded,
                    w1_encoded_len,
                    c_tilde.as_mut_ptr(),
                    c_tilde_len,
                ) == 0
                {
                    break;
                }

                if poly_sample_in_ball_ntt(
                    c_ntt,
                    c_tilde.as_ptr(),
                    c_tilde_len as c_int,
                    md_ctx,
                    (*priv_).shake256_md,
                    (*params).tau as u32,
                ) == 0
                {
                    break;
                }

                vector_mult_scalar(&s1_ntt, &*c_ntt, &mut cs1);
                vector_ntt_inverse(&mut cs1);
                vector_mult_scalar(&s2_ntt, &*c_ntt, &mut cs2);
                vector_ntt_inverse(&mut cs2);

                vector_add(&y, &cs1, &mut sig.z);

                // r0 = lowbits(w - cs2) into `w1`. `vector_low_bits(r0, gamma2, r0)` is in place,
                // which `&Vector`/`&mut Vector` cannot spell, so it is expanded one polynomial at a
                // time with a `Poly` copy as the input.
                vector_sub(&w, &cs2, &mut w1);
                for i in 0..w1.num_poly {
                    // SAFETY: `w1.poly + i` names one initialised polynomial.
                    let src = *w1.poly.add(i);
                    poly_low_bits(&src, gamma2, &mut *w1.poly.add(i));
                }

                // Leaking that the signature is rejected is fine: the next attempt is
                // indistinguishable from an independent one.
                let z_max = vector_max(&sig.z);
                let r0_max = vector_max_signed(&w1);
                if core::hint::black_box(
                    constant_time_ge_u32(z_max, gamma1.wrapping_sub((*params).beta as u32))
                        | constant_time_ge_u32(r0_max, gamma2.wrapping_sub((*params).beta as u32)),
                ) != 0
                {
                    continue;
                }

                // ct0 is `w1`; the same reasoning applies to the leak as above.
                vector_mult_scalar(&t0_ntt, &*c_ntt, &mut w1);
                vector_ntt_inverse(&mut w1);
                vector_make_hint(&w1, &cs2, &w, gamma2, &mut sig.hint);

                let ct0_max = vector_max(&w1);
                let h_ones = vector_count_ones(&sig.hint) as u32;
                if core::hint::black_box(
                    constant_time_ge_u32(ct0_max, gamma2)
                        | constant_time_lt_u32((*params).omega as u32, h_ones),
                ) != 0
                {
                    continue;
                }
                ret = ossl_ml_dsa_sig_encode(&sig, params, out_sig);
                break;
            }
        }

        EVP_MD_CTX_free(md_ctx);
        CRYPTO_clear_free(alloc.cast(), alloc_len, FILE, LINE_SIGN_CLEAR_FREE);
        OPENSSL_cleanse(rho_prime.as_mut_ptr().cast(), rho_prime.len());
        OPENSSL_cleanse(c_tilde.as_mut_ptr().cast(), c_tilde.len());
        ret
    }
}

/// `ml_dsa_verify_internal(pub, mu, mu_len, sig_enc, sig_enc_len)` — `ml_dsa_sign.c:317-408`,
/// FIPS 204 Algorithm 8.
///
/// # Safety
/// `pub_` must be a live public key with an allocated `t1`; `mu` readable for `mu_len` bytes; and
/// `sig_enc` readable for `sig_enc_len` bytes.
unsafe fn ml_dsa_verify_internal(
    pub_: *const MlDsaKey,
    mu: *const u8,
    mu_len: usize,
    sig_enc: *const u8,
    sig_enc_len: usize,
) -> c_int {
    let mut ret = 0;
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let params = (*pub_).params;
        let k = (*params).k as u32;
        let l = (*params).l as u32;
        let gamma2 = (*params).gamma2 as u32;

        let num_polys_sig = k as usize + l as usize;
        let num_polys_k = 2 * k as usize;
        // The authority's `1 * l`; clippy's `identity_op` refuses the literal spelling.
        #[allow(clippy::identity_op)]
        let num_polys_l = 1 * l as usize;
        let num_polys_k_by_l = k as usize * l as usize;
        let mut c_tilde = [0u8; ML_DSA_MAX_LAMBDA / 4];
        let mut c_tilde_sig = [0u8; ML_DSA_MAX_LAMBDA / 4];
        let c_tilde_len = ((*params).bit_strength >> 2) as usize;

        if mu_len != ML_DSA_MU_BYTES {
            // SAFETY: a compile-time-constant site.
            raise_site(&err_sites::ML_DSA_SIGN_344);
            return 0;
        }

        // One blob for every temporary `POLY`.
        let w1_encoded_len = (k as usize)
            * if gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV88 {
                192
            } else {
                128
            };
        let alloc = CRYPTO_malloc(
            w1_encoded_len
                + core::mem::size_of::<Poly>()
                    * (1 + num_polys_k + num_polys_l + num_polys_k_by_l + num_polys_sig),
            FILE,
            LINE_VERIFY_ALLOC,
        )
        .cast::<u8>();
        if alloc.is_null() {
            return 0;
        }
        let md_ctx = EVP_MD_CTX_new();

        // Point every temporary at its slice of the blob.
        let w1_encoded = alloc;
        let mut p: *mut Poly = w1_encoded.add(w1_encoded_len).cast();
        let c_ntt = p;
        p = p.add(1);
        let mut a_ntt = matrix_init(p, k as usize, l as usize);
        p = p.add(num_polys_k_by_l);
        let mut sig = MlDsaSig {
            z: Vector::empty(),
            hint: Vector::empty(),
            c_tilde: ptr::null_mut(),
            c_tilde_len: 0,
        };
        signature_init(
            &mut sig,
            p,
            k,
            p.add(k as usize),
            l,
            c_tilde_sig.as_mut_ptr(),
            c_tilde_len,
        );
        p = p.add(num_polys_sig);
        let mut az_ntt = Vector::init(p, k as usize);
        let mut ct1_ntt = Vector::init(p.add(k as usize), k as usize);

        'err: {
            if md_ctx.is_null() {
                break 'err;
            }
            if ossl_ml_dsa_sig_decode(&mut sig, sig_enc, sig_enc_len, params) == 0
                || matrix_expand_A(
                    md_ctx,
                    (*pub_).shake128_md,
                    (*pub_).rho.as_ptr(),
                    &mut a_ntt,
                ) == 0
            {
                break 'err;
            }

            // c_ntt = NTT(SampleInBall(c_tilde)).
            if poly_sample_in_ball_ntt(
                c_ntt,
                c_tilde_sig.as_ptr(),
                c_tilde_len as c_int,
                md_ctx,
                (*pub_).shake256_md,
                (*params).tau as u32,
            ) == 0
            {
                break 'err;
            }

            // ct1_ntt = NTT(c) * NTT(t1 * 2^d). `vector_mult_scalar(&ct1_ntt, c_ntt, &ct1_ntt)` is
            // in place, so it is expanded one polynomial at a time with a `Poly` copy.
            vector_scale_power2_round_ntt(&(*pub_).t1, &mut ct1_ntt);
            for i in 0..ct1_ntt.num_poly {
                // SAFETY: `ct1_ntt.poly + i` names one initialised polynomial and `c_ntt` one.
                let lhs = *ct1_ntt.poly.add(i);
                ossl_ml_dsa_poly_ntt_mult(&lhs, &*c_ntt, &mut *ct1_ntt.poly.add(i));
            }

            // Compute z_max early in order to reuse sig.z.
            let z_max = vector_max(&sig.z);

            // w_approx = NTT_inverse(A * NTT(z) - ct1_ntt), with w_approx aliased onto az_ntt.
            vector_ntt(&mut sig.z);
            matrix_mult_vector(&a_ntt, &sig.z, &mut az_ntt);
            for i in 0..az_ntt.num_poly {
                // SAFETY: `az_ntt.poly + i` and `ct1_ntt.poly + i` each name one polynomial; the
                // subtraction is element-wise and `lhs`/`rhs` are copies.
                let lhs = *az_ntt.poly.add(i);
                let rhs = *ct1_ntt.poly.add(i);
                poly_sub(&lhs, &rhs, &mut *az_ntt.poly.add(i));
            }
            vector_ntt_inverse(&mut az_ntt);

            // w1_encoded, with `w1` aliased onto `w_approx` (`az_ntt`) as well.
            for i in 0..az_ntt.num_poly {
                // SAFETY: `az_ntt.poly + i` names one polynomial and `sig.hint.poly + i` another,
                // in a distinct allocation; `r` is a copy.
                let r = *az_ntt.poly.add(i);
                poly_use_hint(&*sig.hint.poly.add(i), &r, gamma2, &mut *az_ntt.poly.add(i));
            }
            ossl_ml_dsa_w1_encode(&az_ntt, gamma2, w1_encoded, w1_encoded_len);

            if shake_xof_3(
                md_ctx,
                (*pub_).shake256_md,
                mu,
                mu_len,
                w1_encoded,
                w1_encoded_len,
                ptr::null(),
                0,
                c_tilde.as_mut_ptr(),
                c_tilde_len,
            ) == 0
            {
                break 'err;
            }

            ret = c_int::from(
                z_max < (*params).gamma1.wrapping_sub((*params).beta) as u32
                    && memcmp(c_tilde.as_ptr().cast(), sig.c_tilde.cast(), c_tilde_len) == 0,
            );
        }

        CRYPTO_free(alloc.cast(), FILE, LINE_VERIFY_FREE);
        EVP_MD_CTX_free(md_ctx);
        ret
    }
}

/// `ossl_ml_dsa_sign(priv, msg_is_mu, msg, msg_len, context, context_len, rand, rand_len, encode,
/// sig, sig_len, sig_size)` — `ml_dsa_sign.c:415-460`, FIPS 204 Algorithm 2.
///
/// # Safety
/// `priv` must be a live private key; `msg` readable for `msg_len`, `context` for `context_len` and
/// `rand` for `rand_len` bytes; `sig` writable for `sig_size` bytes; and `sig_len` null or writable.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_ml_dsa_sign(
    priv_: *const MlDsaKey,
    msg_is_mu: c_int,
    msg: *const u8,
    msg_len: usize,
    context: *const u8,
    context_len: usize,
    rand: *const u8,
    rand_len: usize,
    encode: c_int,
    sig: *mut u8,
    sig_len: *mut usize,
    sig_size: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut mu = [0u8; ML_DSA_MU_BYTES];
        let mut mu_ptr: *const u8 = mu.as_ptr();
        let mut mu_len = mu.len();
        let mut md_ctx: *mut EvpMdCtx = ptr::null_mut();
        let mut ret = 0;

        if ossl_ml_dsa_key_get_priv(priv_).is_null() {
            return 0;
        }

        if !sig_len.is_null() {
            *sig_len = (*(*priv_).params).sig_len;
        }

        if sig.is_null() {
            return if !sig_len.is_null() { 1 } else { 0 };
        }

        if sig_size < (*(*priv_).params).sig_len {
            return 0;
        }

        if msg_is_mu != 0 {
            mu_ptr = msg;
            mu_len = msg_len;
        } else {
            md_ctx = ossl_ml_dsa_mu_init(priv_, encode, context, context_len);
            if md_ctx.is_null() {
                return 0;
            }
        }

        'err: {
            if msg_is_mu == 0 {
                if ossl_ml_dsa_mu_update(md_ctx, msg, msg_len) == 0 {
                    break 'err;
                }
                if ossl_ml_dsa_mu_finalize(md_ctx, mu.as_mut_ptr(), mu_len) == 0 {
                    break 'err;
                }
            }
            ret = ml_dsa_sign_internal(priv_, mu_ptr, mu_len, rand, rand_len, sig);
        }

        EVP_MD_CTX_free(md_ctx);
        OPENSSL_cleanse(mu.as_mut_ptr().cast(), mu.len());
        ret
    }
}

/// `ossl_ml_dsa_verify(pub, msg_is_mu, msg, msg_len, context, context_len, encode, sig, sig_len)` —
/// `ml_dsa_sign.c:466-500`, FIPS 204 Algorithm 3.
///
/// # Safety
/// `pub_` must be a live public key; `msg` readable for `msg_len`, `context` for `context_len` and
/// `sig` for `sig_len` bytes.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_ml_dsa_verify(
    pub_: *const MlDsaKey,
    msg_is_mu: c_int,
    msg: *const u8,
    msg_len: usize,
    context: *const u8,
    context_len: usize,
    encode: c_int,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    // SAFETY: the arguments are live per the contract.
    unsafe {
        let mut mu = [0u8; ML_DSA_MU_BYTES];
        let mut mu_ptr: *const u8 = mu.as_ptr();
        let mut mu_len = mu.len();
        let mut md_ctx: *mut EvpMdCtx = ptr::null_mut();
        let mut ret = 0;

        if ossl_ml_dsa_key_get_pub(pub_).is_null() {
            return 0;
        }

        if msg_is_mu != 0 {
            mu_ptr = msg;
            mu_len = msg_len;
        } else {
            md_ctx = ossl_ml_dsa_mu_init(pub_, encode, context, context_len);
            if md_ctx.is_null() {
                return 0;
            }
        }

        'err: {
            if msg_is_mu == 0 {
                if ossl_ml_dsa_mu_update(md_ctx, msg, msg_len) == 0 {
                    break 'err;
                }
                if ossl_ml_dsa_mu_finalize(md_ctx, mu.as_mut_ptr(), mu_len) == 0 {
                    break 'err;
                }
            }
            ret = ml_dsa_verify_internal(pub_, mu_ptr, mu_len, sig, sig_len);
        }

        EVP_MD_CTX_free(md_ctx);
        OPENSSL_cleanse(mu.as_mut_ptr().cast(), mu.len());
        ret
    }
}
