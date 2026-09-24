//! `crypto/ml_dsa/ml_dsa_ntt.c` — the number-theoretic transform and Montgomery multiplication.
//!
//! This file is the whole of `ml_dsa_ntt.c`: the 256 zeta table (generated, in [`super::tables`]),
//! `reduce_montgomery`, the pointwise multiply `ossl_ml_dsa_poly_ntt_mult`, the forward transform
//! `ossl_ml_dsa_poly_ntt` and the inverse `ossl_ml_dsa_poly_ntt_inverse`.
//!
//! `ossl_ml_dsa_matrix_mult_vector` — `ml_dsa_matrix.c:24-41` — is here rather than in a module of
//! its own because the authority's `ml_dsa_matrix.c` is a single twenty-five-line function that
//! exists only to drive `ossl_ml_dsa_poly_ntt_mult` over a matrix, and the header's inline
//! `matrix_mult_vector` is its only caller.
//!
//! ## The transform is transcribed from the file, not from FIPS 204
//!
//! The authority's forward transform indexes the table as `zetas_montgomery[step + i]` and its
//! inverse as `ML_DSA_Q - zetas_montgomery[step + (step - 1 - i)]`; both are reproduced exactly,
//! including the inverse's final multiplication by `ML_DSA_DEGREE_INV_MONTGOMERY`. The 256 table
//! entries are the generated ones (D33), so no zeta is typed here.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::runtime::mem::OPENSSL_cleanse;

use super::poly::{matrix_as_slice, poly_add, Matrix, Poly, Vector};
use super::tables::ZETAS_MONTGOMERY;
use super::{
    mod_sub, reduce_once, ML_DSA_DEGREE_INV_MONTGOMERY, ML_DSA_NUM_POLY_COEFFICIENTS, ML_DSA_Q,
    ML_DSA_Q_NEG_INV,
};

/// `reduce_montgomery(a)` — `ml_dsa_ntt.c:93-100`.
///
/// `a` is a product of two Montgomery-form values, in the range `0..(2^32)*q`. The body is the
/// file's own: `t = (uint32_t)a * ML_DSA_Q_NEG_INV`, `b = a + t * ML_DSA_Q`, `c = b >> 32`, then
/// one `reduce_once`.
#[inline(always)]
pub(crate) fn reduce_montgomery(a: u64) -> u32 {
    let t = (a as u32).wrapping_mul(ML_DSA_Q_NEG_INV);
    let b = a.wrapping_add((t as u64).wrapping_mul(ML_DSA_Q as u64));
    let c = (b >> 32) as u32;
    reduce_once(c)
}

/// `ossl_ml_dsa_poly_ntt_mult(lhs, rhs, out)` — `ml_dsa_ntt.c:111-117`, FIPS 204 Algorithm 45
/// with the Montgomery multiply the file substitutes.
pub(crate) fn ossl_ml_dsa_poly_ntt_mult(lhs: &Poly, rhs: &Poly, out: &mut Poly) {
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        out.coeff[i] = reduce_montgomery((lhs.coeff[i] as u64) * (rhs.coeff[i] as u64));
    }
}

/// `ossl_ml_dsa_poly_ntt(p)` — `ml_dsa_ntt.c:128-152`, FIPS 204 Algorithm 41, in place.
pub(crate) fn ossl_ml_dsa_poly_ntt(p: &mut Poly) {
    let mut offset = ML_DSA_NUM_POLY_COEFFICIENTS;
    let mut step = 1usize;
    while step < ML_DSA_NUM_POLY_COEFFICIENTS {
        let mut k = 0usize;
        offset >>= 1;
        for i in 0..step {
            let z_step_root = ZETAS_MONTGOMERY[step + i];
            for j in k..k + offset {
                let w_even = p.coeff[j];
                let t_odd = reduce_montgomery((z_step_root as u64) * (p.coeff[j + offset] as u64));
                p.coeff[j] = reduce_once(w_even.wrapping_add(t_odd));
                p.coeff[j + offset] = mod_sub(w_even, t_odd);
            }
            k += 2 * offset;
        }
        step <<= 1;
    }
}

/// `ossl_ml_dsa_poly_ntt_inverse(p)` — `ml_dsa_ntt.c:161-193`, FIPS 204 Algorithm 42, in place.
pub(crate) fn ossl_ml_dsa_poly_ntt_inverse(p: &mut Poly) {
    let mut step = ML_DSA_NUM_POLY_COEFFICIENTS;
    let mut offset = 1usize;
    while offset < ML_DSA_NUM_POLY_COEFFICIENTS {
        step >>= 1;
        let mut k = 0usize;
        for i in 0..step {
            let step_root = ML_DSA_Q.wrapping_sub(ZETAS_MONTGOMERY[step + (step - 1 - i)]);
            for j in k..k + offset {
                let even = p.coeff[j];
                let odd = p.coeff[j + offset];
                p.coeff[j] = reduce_once(odd.wrapping_add(even));
                p.coeff[j + offset] = reduce_montgomery(
                    (step_root as u64) * (ML_DSA_Q.wrapping_add(even).wrapping_sub(odd) as u64),
                );
            }
            k += 2 * offset;
        }
        offset <<= 1;
    }
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        p.coeff[i] = reduce_montgomery((p.coeff[i] as u64) * (ML_DSA_DEGREE_INV_MONTGOMERY as u64));
    }
}

/// `ossl_ml_dsa_matrix_mult_vector(a, s, t)` — `ml_dsa_matrix.c:24-41`, `t = a * s`.
///
/// `a` is `k * l` polynomials in NTT form, `s` a `1 * l` vector and `t` the `1 * k` result. The
/// local `product` is declared once and cleared at the end, as the C's
/// `OPENSSL_cleanse(&product, sizeof(product))` does.
///
/// # Safety
/// `a` must name `a.k * a.l` polynomials, `s` must name `a.l` polynomials and `t` must name `a.k`
/// polynomials, all initialised; `t` must not alias `s`.
pub(crate) unsafe fn ossl_ml_dsa_matrix_mult_vector(a: &Matrix, s: &Vector, t: &mut Vector) {
    // SAFETY: the contract says `t` names `a.k` polynomials.
    t.zero();

    // SAFETY: the contract says `a` names `k * l` polynomials and `s` names `a.l` of them.
    let poly = unsafe { matrix_as_slice(a) };
    // SAFETY: the contract says `s` names `a.l` polynomials.
    let sv = unsafe { s.as_slice() };
    // SAFETY: the contract says `t` names `a.k` polynomials; this is the only borrow of `t`.
    let tv = unsafe { t.as_mut_slice() };

    let mut product = Poly {
        coeff: [0u32; ML_DSA_NUM_POLY_COEFFICIENTS],
    };

    let mut idx = 0usize;
    // The C walks `i < a->k` over `t->poly[i]` and `j < a->l` over `s->poly[j]`; the two slices are
    // `a.k` and `a.l` long by the contract, so the iterators are the same walk.
    for ti in tv.iter_mut().take(a.k) {
        for sj in sv.iter().take(a.l) {
            ossl_ml_dsa_poly_ntt_mult(&poly[idx], sj, &mut product);
            // `poly_add(&product, &t->poly[i], &t->poly[i])` accumulates in place; a copy expresses
            // the same thing because `Poly` is `Copy` and the coefficients are plain values.
            let operand = *ti;
            let mut acc = operand;
            poly_add(&product, &operand, &mut acc);
            *ti = acc;
            idx += 1;
        }
    }

    // `OPENSSL_cleanse(&product, sizeof(product))` — the product is a polynomial of key material.
    // SAFETY: `product` is a live local of exactly that size.
    unsafe {
        OPENSSL_cleanse(
            core::ptr::from_mut(&mut product).cast(),
            core::mem::size_of::<Poly>(),
        )
    };
}
