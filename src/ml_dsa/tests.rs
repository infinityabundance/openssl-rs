//! Unit evidence for [`crate::ml_dsa`]'s arithmetic core.
//!
//! The eight `crypto/ml_dsa/*.c` units define no export of their own — the six provider rows live in
//! `ml_dsa_kmgmt.c.in` and `ml_dsa_sig.c.in` — so before those units land this module's evidence is
//! here, exactly as `crypto/slh_dsa/`'s and `crypto/ml_kem/`'s was before their provider units
//! (D398, D401). These tests are **self-consistency and definition checks**, not independent
//! cryptographic correctness: each asserts a property re-derived from FIPS 204 or from the C body
//! in 64-bit arithmetic the transcription does not use, so a transcription error in the 32-bit
//! constant-time path is visible rather than shared. The independent correctness plane is the
//! FIPS 204 / ACVP known-answer court that lands with the provider units.
//!
//! SPDX-License-Identifier: Apache-2.0

use super::encoders::{ossl_ml_dsa_pk_decode, ossl_ml_dsa_pk_encode};
use super::key::{
    ossl_ml_dsa_generate_key, ossl_ml_dsa_key_free, ossl_ml_dsa_key_get_priv,
    ossl_ml_dsa_key_get_pub, ossl_ml_dsa_key_get_pub_len, ossl_ml_dsa_key_get_sig_len,
    ossl_ml_dsa_key_new, ossl_ml_dsa_key_pairwise_check,
};
use super::key_compress::{
    ossl_ml_dsa_key_compress_decompose, ossl_ml_dsa_key_compress_high_bits,
    ossl_ml_dsa_key_compress_low_bits, ossl_ml_dsa_key_compress_power2_round,
};
use super::ntt::{ossl_ml_dsa_poly_ntt, ossl_ml_dsa_poly_ntt_inverse};
use super::poly::Poly;
use super::sign::{ossl_ml_dsa_sign, ossl_ml_dsa_verify};
use super::{
    mod_sub, reduce_once, EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65, EVP_PKEY_ML_DSA_87,
    ML_DSA_44_PUB_LEN, ML_DSA_D_BITS, ML_DSA_GAMMA2_Q_MINUS1_DIV32, ML_DSA_GAMMA2_Q_MINUS1_DIV88,
    ML_DSA_NUM_POLY_COEFFICIENTS, ML_DSA_Q, ML_DSA_Q_MINUS1_DIV2,
};

/// `2^32 mod q` — the Montgomery multiplier's image, `ml_dsa_local.h`'s `R` in `mod q`.
const MONTGOMERY_R: u64 = 4193792;

/// `reduce_once(x) = x < q ? x : x - q`, for every `x` in the input range `0 .. 2q`.
#[test]
fn reduce_once_is_the_definition() {
    for x in (0..2 * ML_DSA_Q).step_by(2017) {
        let want = if x < ML_DSA_Q { x } else { x - ML_DSA_Q };
        assert_eq!(reduce_once(x), want, "x={x}");
    }
}

/// `mod_sub(a, b) = (a - b) mod q` for every sampled `a`,`b`, computed in `u64` and `% q`.
#[test]
fn mod_sub_is_the_positive_difference() {
    for a in (0..ML_DSA_Q).step_by(4099) {
        for b in (0..ML_DSA_Q).step_by(7919) {
            let want = ((a as u64 + ML_DSA_Q as u64 - b as u64) % ML_DSA_Q as u64) as u32;
            assert_eq!(mod_sub(a, b), want, "a={a} b={b}");
        }
    }
}

/// `Power2Round` reconstructs `r = r1 * 2^13 + r0 (mod q)` and keeps `r0` in `(0, 4096] ∪ (q-4095, q)`.
#[test]
fn power2_round_reconstructs_and_bounds_r0() {
    for r in (0..ML_DSA_Q).step_by(1013) {
        let (r1, r0) = ossl_ml_dsa_key_compress_power2_round(r);
        let reconstructed = (r1 as u64 * (1 << ML_DSA_D_BITS) + r0 as u64) % ML_DSA_Q as u64;
        assert_eq!(reconstructed, r as u64, "r={r}");
        assert!(
            r0 <= 4096 || r0 >= ML_DSA_Q - 4095,
            "r0={r0} out of range for r={r}"
        );
    }
}

/// `Decompose` reconstructs `r = r1 * (2 * gamma2) + r0 (mod q)` with `|r0| <= gamma2`, and
/// `LowBits` answers the same `r0` `HighBits` decomposes around, for both parameter sets' `gamma2`.
#[test]
fn decompose_reconstructs_and_bounds_r0() {
    for gamma2 in [ML_DSA_GAMMA2_Q_MINUS1_DIV32, ML_DSA_GAMMA2_Q_MINUS1_DIV88] {
        for r in (0..ML_DSA_Q).step_by(997) {
            let (r1, r0) = ossl_ml_dsa_key_compress_decompose(r, gamma2);
            let reconstructed =
                ((r1 as i64) * 2 * (gamma2 as i64) + r0 as i64).rem_euclid(ML_DSA_Q as i64) as u64;
            assert_eq!(reconstructed, r as u64, "gamma2={gamma2} r={r}");
            assert!(
                (r0 as i64).abs() <= gamma2 as i64,
                "r0={r0} out of range for gamma2={gamma2} r={r}"
            );
            assert_eq!(ossl_ml_dsa_key_compress_low_bits(r, gamma2), r0);
            assert_eq!(ossl_ml_dsa_key_compress_high_bits(r, gamma2), r1);
            // The `(q-1)/2` boundary is `Decompose`'s own adjustment; assert the sign convention.
            assert!(r0 as i64 <= ML_DSA_Q_MINUS1_DIV2 as i64);
        }
    }
}

/// `intt(ntt(x)) = x * 2^32 mod q`, the exact scale the Montgomery-form table and the inverse's
/// `inverse_degree_montgomery` multiply leave behind. Measured against the C body: with `R = 2^32`
/// the forward transform is scale-free, the inverse ends in `* (256^-1 * R)`, so the composition
/// carries one factor of `R` — which is what the NTT-domain product's `* R^-1` cancels.
#[test]
fn ntt_then_inverse_scales_by_the_montgomery_r() {
    let mut x = Poly {
        coeff: [0u32; ML_DSA_NUM_POLY_COEFFICIENTS],
    };
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        x.coeff[i] = ((i as u64 * 12345 + 7) % ML_DSA_Q as u64) as u32;
    }
    let orig = x;

    ossl_ml_dsa_poly_ntt(&mut x);
    // A pure forward transform must not leave every coefficient equal to the input (otherwise the
    // scale check below would be vacuous on a constant).
    assert_ne!(x.coeff, orig.coeff);

    ossl_ml_dsa_poly_ntt_inverse(&mut x);
    for i in 0..ML_DSA_NUM_POLY_COEFFICIENTS {
        let want = ((orig.coeff[i] as u64 * MONTGOMERY_R) % ML_DSA_Q as u64) as u32;
        assert_eq!(x.coeff[i], want, "coeff {i}");
    }
}

/// A freshly generated key of every parameter set satisfies its own pairwise consistency test.
///
/// `ossl_ml_dsa_key_pairwise_check` signs and verifies internally, so this one call drives
/// `keygen_internal`, `ExpandA`, `ExpandS`, both NTTs, both encoders and the whole signature path.
#[test]
fn a_generated_key_passes_its_pairwise_check() {
    for evp_type in [EVP_PKEY_ML_DSA_44, EVP_PKEY_ML_DSA_65, EVP_PKEY_ML_DSA_87] {
        // SAFETY: the key is created by `ossl_ml_dsa_key_new` and freed below; every other call is
        // under that function's own contract.
        unsafe {
            let key = ossl_ml_dsa_key_new(core::ptr::null_mut(), core::ptr::null(), evp_type);
            assert!(!key.is_null(), "key_new({evp_type})");
            assert_eq!(ossl_ml_dsa_generate_key(key), 1, "generate_key({evp_type})");
            assert_eq!(
                ossl_ml_dsa_key_pairwise_check(key),
                1,
                "pairwise_check({evp_type})"
            );
            assert!(!ossl_ml_dsa_key_get_pub(key).is_null());
            assert!(!ossl_ml_dsa_key_get_priv(key).is_null());
            assert_ne!(ossl_ml_dsa_key_get_sig_len(key), 0);
            ossl_ml_dsa_key_free(key);
        }
    }
}

/// A signature over a message verifies, and a single flipped signature bit does not.
#[test]
fn a_signature_verifies_and_a_tampered_one_does_not() {
    let msg = b"openssl-rs ML-DSA self-consistency";
    // A fixed `rnd` makes the randomised signing path deterministic for the test.
    let rnd = [0x5au8; 32];

    // SAFETY: the key is created and freed here; the buffers are live for the lengths passed.
    unsafe {
        let key = ossl_ml_dsa_key_new(core::ptr::null_mut(), core::ptr::null(), EVP_PKEY_ML_DSA_44);
        assert_eq!(ossl_ml_dsa_generate_key(key), 1);

        let sig_len = ossl_ml_dsa_key_get_sig_len(key);
        let mut sig = vec![0u8; sig_len];
        let mut out_len = 0usize;

        assert_eq!(
            ossl_ml_dsa_sign(
                key,
                0,
                msg.as_ptr(),
                msg.len(),
                core::ptr::null(),
                0,
                rnd.as_ptr(),
                rnd.len(),
                1,
                sig.as_mut_ptr(),
                &mut out_len,
                sig_len,
            ),
            1
        );
        assert_eq!(out_len, sig_len);

        assert_eq!(
            ossl_ml_dsa_verify(
                key,
                0,
                msg.as_ptr(),
                msg.len(),
                core::ptr::null(),
                0,
                1,
                sig.as_ptr(),
                out_len,
            ),
            1
        );

        sig[0] ^= 1;
        assert_eq!(
            ossl_ml_dsa_verify(
                key,
                0,
                msg.as_ptr(),
                msg.len(),
                core::ptr::null(),
                0,
                1,
                sig.as_ptr(),
                out_len,
            ),
            0
        );

        ossl_ml_dsa_key_free(key);
    }
}

/// `pk_encode` then `pk_decode` into a second key reproduces the encoded public key byte for byte.
#[test]
fn the_public_key_encoding_round_trips() {
    // SAFETY: both keys are created and freed here, and the byte slice stays live across the call.
    unsafe {
        let key = ossl_ml_dsa_key_new(core::ptr::null_mut(), core::ptr::null(), EVP_PKEY_ML_DSA_44);
        assert_eq!(ossl_ml_dsa_generate_key(key), 1);
        assert_eq!(ossl_ml_dsa_pk_encode(key), 1);

        let pk = ossl_ml_dsa_key_get_pub(key);
        let pk_len = ossl_ml_dsa_key_get_pub_len(key);
        assert_eq!(pk_len, ML_DSA_44_PUB_LEN);
        let bytes = core::slice::from_raw_parts(pk, pk_len).to_vec();

        let other =
            ossl_ml_dsa_key_new(core::ptr::null_mut(), core::ptr::null(), EVP_PKEY_ML_DSA_44);
        assert_eq!(ossl_ml_dsa_pk_decode(other, bytes.as_ptr(), bytes.len()), 1);
        let pk2 = ossl_ml_dsa_key_get_pub(other);
        let pk2_len = ossl_ml_dsa_key_get_pub_len(other);
        assert_eq!(core::slice::from_raw_parts(pk2, pk2_len), &bytes[..]);

        ossl_ml_dsa_key_free(key);
        ossl_ml_dsa_key_free(other);
    }
}
