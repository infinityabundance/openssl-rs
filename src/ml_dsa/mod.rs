//! Phase 8 — `crypto/ml_dsa/`: the ML-DSA (FIPS 204) core the six keymgmt and signature rows are
//! built on.
//!
//! This module is the crate's transcription of the `crypto/ml_dsa/*.c` translation units the
//! ML-DSA provider rows are built on — `ml_dsa_params.c`, `ml_dsa_ntt.c`, `ml_dsa_key_compress.c`,
//! `ml_dsa_sample.c`, `ml_dsa_encoders.c`, `ml_dsa_key.c`, `ml_dsa_sign.c` and `ml_dsa_matrix.c` —
//! transcribed whole per D327's rule, together with the five headers whose static inlines every
//! unit includes (`ml_dsa_local.h`, `ml_dsa_poly.h`, `ml_dsa_vector.h`, `ml_dsa_hash.h` and
//! `include/crypto/ml_dsa.h`). The one header-declared structure, [`MlDsaKey`], is modelled
//! field-for-field, as are [`Poly`], [`Vector`], [`Matrix`], [`MlDsaParams`] and [`MlDsaSig`].
//!
//! ## The 256 table lines are generated, not transcribed
//!
//! `zetas_montgomery` is 256 `uint32_t` literals — the Montgomery-form 256th roots of unity the
//! forward and inverse NTT both read. It lives in [`tables`], re-derived by
//! `forensics/tools/gen_ml_dsa_tables.py` from the definition comment the file carries and checked
//! entry for entry against the authority's literals. Nothing here types them.
//!
//! ## The shared header inlines are free functions over [`Poly`]/[`Vector`]/[`Matrix`]
//!
//! `ml_dsa_poly.h`, `ml_dsa_vector.h` and `ml_dsa_matrix.h` are `static ossl_inline` bodies, so
//! they are not part of the exported surface and have no owning phase of their own: they belong to
//! the units that include them. They are [`poly`]'s, transcribed whole so the call graph the
//! authority's own compiler sees is the one below.
//!
//! ## All arithmetic wraps
//!
//! The crate builds with `overflow-checks = true`, where the authority's C promotes to `int`/`int32_t`
//! and relies on two's-complement wraparound. Every addition and subtraction here is `wrapping_*`
//! so the two agree bit for bit in a debug build.
//!
//! ## No provider row is published by this module
//!
//! The six rows live in `providers/implementations/keymgmt/ml_dsa_kmgmt.c.in` and
//! `providers/implementations/signature/ml_dsa_sig.c.in`, which are separate units, exactly as
//! `crypto/slh_dsa/` and `crypto/ml_kem/` were before their provider units landed. The allow below
//! is a statement about *when* this module is reached, not a claim that any function is unused.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

pub(crate) mod encoders;
pub(crate) mod hash;
pub(crate) mod key;
pub(crate) mod key_compress;
pub(crate) mod ntt;
pub(crate) mod poly;
pub(crate) mod sample;
pub(crate) mod sign;
pub(crate) mod tables;

#[cfg(test)]
mod tests;

use core::ffi::{c_char, c_int, c_void};

use crate::evp::digest::EvpMd;
use crate::runtime::obj::{NID_ML_DSA_44, NID_ML_DSA_65, NID_ML_DSA_87};

// `Matrix` and `Poly` are re-exported for the units that follow (`sample.rs`, `encoders.rs`,
// `key.rs`, `sign.rs`); `Vector` is used by `MlDsaKey` below already.
#[allow(unused_imports)]
pub(crate) use self::poly::{Matrix, Poly, Vector};

/// `ML_DSA_MAX_CONTEXT_STRING_LEN` — `include/crypto/ml_dsa.h:20`.
pub(crate) const ML_DSA_MAX_CONTEXT_STRING_LEN: usize = 255;
/// `ML_DSA_SEED_BYTES` — `include/crypto/ml_dsa.h:21`, the `(rho, K)` keygen seed pair.
pub(crate) const ML_DSA_SEED_BYTES: usize = 32;
/// `ML_DSA_ENTROPY_LEN` — `include/crypto/ml_dsa.h:23`.
pub(crate) const ML_DSA_ENTROPY_LEN: usize = 32;
/// `ML_DSA_MU_BYTES` — `include/crypto/ml_dsa.h:25`, the size of the message representative.
pub(crate) const ML_DSA_MU_BYTES: usize = 64;

/// `ML_DSA_44_PRIV_LEN` — `include/crypto/ml_dsa.h:28`, FIPS 204 Table 2.
pub(crate) const ML_DSA_44_PRIV_LEN: usize = 2560;
/// `ML_DSA_44_PUB_LEN` — `include/crypto/ml_dsa.h:29`.
pub(crate) const ML_DSA_44_PUB_LEN: usize = 1312;
/// `ML_DSA_44_SIG_LEN` — `include/crypto/ml_dsa.h:30`.
pub(crate) const ML_DSA_44_SIG_LEN: usize = 2420;

/// `ML_DSA_65_PRIV_LEN` — `include/crypto/ml_dsa.h:33`.
pub(crate) const ML_DSA_65_PRIV_LEN: usize = 4032;
/// `ML_DSA_65_PUB_LEN` — `include/crypto/ml_dsa.h:34`.
pub(crate) const ML_DSA_65_PUB_LEN: usize = 1952;
/// `ML_DSA_65_SIG_LEN` — `include/crypto/ml_dsa.h:35`.
pub(crate) const ML_DSA_65_SIG_LEN: usize = 3309;

/// `ML_DSA_87_PRIV_LEN` — `include/crypto/ml_dsa.h:38`.
pub(crate) const ML_DSA_87_PRIV_LEN: usize = 4896;
/// `ML_DSA_87_PUB_LEN` — `include/crypto/ml_dsa.h:39`.
pub(crate) const ML_DSA_87_PUB_LEN: usize = 2592;
/// `ML_DSA_87_SIG_LEN` — `include/crypto/ml_dsa.h:40`.
pub(crate) const ML_DSA_87_SIG_LEN: usize = 4627;

/// `MAX_ML_DSA_PRIV_LEN` — `include/crypto/ml_dsa.h:43`, the 87 parameter set's private-key size.
pub(crate) const MAX_ML_DSA_PRIV_LEN: usize = ML_DSA_87_PRIV_LEN;
/// `MAX_ML_DSA_PUB_LEN` — `include/crypto/ml_dsa.h:44`.
pub(crate) const MAX_ML_DSA_PUB_LEN: usize = ML_DSA_87_PUB_LEN;
/// `MAX_ML_DSA_SIG_LEN` — `include/crypto/ml_dsa.h:45`.
pub(crate) const MAX_ML_DSA_SIG_LEN: usize = ML_DSA_87_SIG_LEN;

/// `ML_DSA_KEY_PREFER_SEED` — `include/crypto/ml_dsa.h:47`.
pub(crate) const ML_DSA_KEY_PREFER_SEED: c_int = 1 << 0;
/// `ML_DSA_KEY_RETAIN_SEED` — `include/crypto/ml_dsa.h:48`.
pub(crate) const ML_DSA_KEY_RETAIN_SEED: c_int = 1 << 1;
/// `ML_DSA_KEY_PROV_FLAGS_DEFAULT` — `include/crypto/ml_dsa.h:50-51`.
pub(crate) const ML_DSA_KEY_PROV_FLAGS_DEFAULT: c_int =
    ML_DSA_KEY_PREFER_SEED | ML_DSA_KEY_RETAIN_SEED;

/// `ML_DSA_Q` — `ml_dsa_local.h:18`, `2^23 - 2^13 + 1`.
pub(crate) const ML_DSA_Q: u32 = 8380417;
/// `ML_DSA_Q_MINUS1_DIV2` — `ml_dsa_local.h:19`, `(ML_DSA_Q - 1) / 2`.
pub(crate) const ML_DSA_Q_MINUS1_DIV2: u32 = (ML_DSA_Q - 1) / 2;
/// `ML_DSA_Q_BITS` — `ml_dsa_local.h:21`.
pub(crate) const ML_DSA_Q_BITS: u32 = 23;
/// `ML_DSA_Q_INV` — `ml_dsa_local.h:22`, `q^-1` satisfies `q^-1 * q = 1 mod 2^32`.
pub(crate) const ML_DSA_Q_INV: u32 = 58728449;
/// `ML_DSA_Q_NEG_INV` — `ml_dsa_local.h:23`, the negation of `q`'s inverse modulo `2^32`.
pub(crate) const ML_DSA_Q_NEG_INV: u32 = 4236238847;
/// `ML_DSA_DEGREE_INV_MONTGOMERY` — `ml_dsa_local.h:24`, `256^-1 mod q` in Montgomery form.
pub(crate) const ML_DSA_DEGREE_INV_MONTGOMERY: u32 = 41978;
/// `ML_DSA_D_BITS` — `ml_dsa_local.h:26`, the bits dropped from the public vector `t`.
pub(crate) const ML_DSA_D_BITS: u32 = 13;
/// `ML_DSA_NUM_POLY_COEFFICIENTS` — `ml_dsa_local.h:27`, degrees of the quotient polynomial.
pub(crate) const ML_DSA_NUM_POLY_COEFFICIENTS: usize = 256;
/// `ML_DSA_RHO_BYTES` — `ml_dsa_local.h:28`, the public random seed.
pub(crate) const ML_DSA_RHO_BYTES: usize = 32;
/// `ML_DSA_PRIV_SEED_BYTES` — `ml_dsa_local.h:29`, the private random seed `rho'`.
pub(crate) const ML_DSA_PRIV_SEED_BYTES: usize = 64;
/// `ML_DSA_K_BYTES` — `ml_dsa_local.h:30`, the private random seed for signing.
pub(crate) const ML_DSA_K_BYTES: usize = 32;
/// `ML_DSA_TR_BYTES` — `ml_dsa_local.h:31`, the size of the hash of the public key.
pub(crate) const ML_DSA_TR_BYTES: usize = 64;
/// `ML_DSA_RHO_PRIME_BYTES` — `ml_dsa_local.h:32`, the private random seed size.
pub(crate) const ML_DSA_RHO_PRIME_BYTES: usize = 64;

/// `ML_DSA_ETA_4` — `ml_dsa_local.h:42`.
pub(crate) const ML_DSA_ETA_4: c_int = 4;
/// `ML_DSA_ETA_2` — `ml_dsa_local.h:43`.
pub(crate) const ML_DSA_ETA_2: c_int = 2;
/// `ML_DSA_GAMMA1_TWO_POWER_19` — `ml_dsa_local.h:48`.
pub(crate) const ML_DSA_GAMMA1_TWO_POWER_19: u32 = 1 << 19;
/// `ML_DSA_GAMMA1_TWO_POWER_17` — `ml_dsa_local.h:49`.
pub(crate) const ML_DSA_GAMMA1_TWO_POWER_17: u32 = 1 << 17;
/// `ML_DSA_GAMMA2_Q_MINUS1_DIV32` — `ml_dsa_local.h:54`, `(ML_DSA_Q - 1) / 32`.
pub(crate) const ML_DSA_GAMMA2_Q_MINUS1_DIV32: u32 = (ML_DSA_Q - 1) / 32;
/// `ML_DSA_GAMMA2_Q_MINUS1_DIV88` — `ml_dsa_local.h:55`, `(ML_DSA_Q - 1) / 88`.
pub(crate) const ML_DSA_GAMMA2_Q_MINUS1_DIV88: u32 = (ML_DSA_Q - 1) / 88;

/// `EVP_PKEY_ML_DSA_44` — `include/openssl/evp.h:86`, `NID_ML_DSA_44`.
pub(crate) const EVP_PKEY_ML_DSA_44: c_int = NID_ML_DSA_44;
/// `EVP_PKEY_ML_DSA_65` — `include/openssl/evp.h:87`, `NID_ML_DSA_65`.
pub(crate) const EVP_PKEY_ML_DSA_65: c_int = NID_ML_DSA_65;
/// `EVP_PKEY_ML_DSA_87` — `include/openssl/evp.h:88`, `NID_ML_DSA_87`.
pub(crate) const EVP_PKEY_ML_DSA_87: c_int = NID_ML_DSA_87;

/// `reduce_once(x)` — `ml_dsa_local.h:111-114`, `x < q ? x : x - q` in constant time.
#[inline(always)]
pub(crate) fn reduce_once(x: u32) -> u32 {
    crate::runtime::constant_time::constant_time_select_u32(
        crate::runtime::constant_time::constant_time_lt_u32(x, ML_DSA_Q),
        x,
        x.wrapping_sub(ML_DSA_Q),
    )
}

/// `mod_sub(a, b)` — `ml_dsa_local.h:127-130`, the positive value of `(a - b) mod q`.
#[inline(always)]
pub(crate) fn mod_sub(a: u32, b: u32) -> u32 {
    reduce_once(ML_DSA_Q.wrapping_add(a).wrapping_sub(b))
}

/// `abs_signed(x)` — `ml_dsa_local.h:136-139`, `is_positive(x) ? x : -x` in constant time.
#[inline(always)]
pub(crate) fn abs_signed(x: u32) -> u32 {
    crate::runtime::constant_time::constant_time_select_u32(
        crate::runtime::constant_time::constant_time_lt_u32(x, 0x80000000),
        x,
        0u32.wrapping_sub(x),
    )
}

/// `abs_mod_prime(x)` — `ml_dsa_local.h:145-149`, `x > (q - 1) / 2 ? q - x : x`.
#[inline(always)]
pub(crate) fn abs_mod_prime(x: u32) -> u32 {
    crate::runtime::constant_time::constant_time_select_u32(
        crate::runtime::constant_time::constant_time_lt_u32(ML_DSA_Q_MINUS1_DIV2, x),
        ML_DSA_Q.wrapping_sub(x),
        x,
    )
}

/// `maximum(x, y)` — `ml_dsa_local.h:155-158`, `x < y ? y : x` in constant time.
#[inline(always)]
pub(crate) fn maximum(x: u32, y: u32) -> u32 {
    crate::runtime::constant_time::constant_time_select(
        crate::runtime::constant_time::constant_time_lt_s(x as usize, y as usize),
        y as usize,
        x as usize,
    ) as u32
}

/// `struct ml_dsa_params_st` — `include/crypto/ml_dsa.h:57-72`, the FIPS 204 parameter set.
///
/// The fields shared by all three parameter sets (`q`, `d`, the degree) are deliberately omitted
/// by the header, exactly as its own comment says (`:54-56`).
#[repr(C)]
pub(crate) struct MlDsaParams {
    /// `const char *alg` — the provider algorithm name.
    pub(crate) alg: *const c_char,
    /// `int evp_type` — the `EVP_PKEY_ML_DSA_*` type.
    pub(crate) evp_type: c_int,
    /// `int tau` — the number of `±1`s in the challenge polynomial `c`.
    pub(crate) tau: c_int,
    /// `int bit_strength` — the collision strength `lambda`.
    pub(crate) bit_strength: c_int,
    /// `int gamma1` — the coefficient range of `y`.
    pub(crate) gamma1: c_int,
    /// `int gamma2` — the low-order rounding range.
    pub(crate) gamma2: c_int,
    /// `size_t k` — the row count of `A`.
    pub(crate) k: usize,
    /// `size_t l` — the column count of `A`.
    pub(crate) l: usize,
    /// `int eta` — the private-key coefficient range.
    pub(crate) eta: c_int,
    /// `int beta` — `tau * eta`.
    pub(crate) beta: c_int,
    /// `int omega` — the number of `1`s in the hint `h`.
    pub(crate) omega: c_int,
    /// `int security_category` — the NIST security category.
    pub(crate) security_category: c_int,
    /// `size_t sk_len` — the private-key size.
    pub(crate) sk_len: usize,
    /// `size_t pk_len` — the public-key size.
    pub(crate) pk_len: usize,
    /// `size_t sig_len` — the signature size.
    pub(crate) sig_len: usize,
}

// SAFETY: `MlDsaParams` is a table of plain data plus one `const char *` that points at a `'static`
// C string literal; it is only ever shared, never mutated.
unsafe impl Sync for MlDsaParams {}

/// `ml_dsa_params[]` — `ml_dsa_params.c:44-91`, the three FIPS 204 parameter sets in file order.
static ML_DSA_PARAMS: [MlDsaParams; 3] = [
    MlDsaParams {
        alg: c"ML-DSA-44".as_ptr(),
        evp_type: EVP_PKEY_ML_DSA_44,
        tau: 39,
        bit_strength: 128,
        gamma1: ML_DSA_GAMMA1_TWO_POWER_17 as c_int,
        gamma2: ML_DSA_GAMMA2_Q_MINUS1_DIV88 as c_int,
        k: 4,
        l: 4,
        eta: ML_DSA_ETA_2,
        beta: 78,
        omega: 80,
        security_category: 2,
        sk_len: ML_DSA_44_PRIV_LEN,
        pk_len: ML_DSA_44_PUB_LEN,
        sig_len: ML_DSA_44_SIG_LEN,
    },
    MlDsaParams {
        alg: c"ML-DSA-65".as_ptr(),
        evp_type: EVP_PKEY_ML_DSA_65,
        tau: 49,
        bit_strength: 192,
        gamma1: ML_DSA_GAMMA1_TWO_POWER_19 as c_int,
        gamma2: ML_DSA_GAMMA2_Q_MINUS1_DIV32 as c_int,
        k: 6,
        l: 5,
        eta: ML_DSA_ETA_4,
        beta: 196,
        omega: 55,
        security_category: 3,
        sk_len: ML_DSA_65_PRIV_LEN,
        pk_len: ML_DSA_65_PUB_LEN,
        sig_len: ML_DSA_65_SIG_LEN,
    },
    MlDsaParams {
        alg: c"ML-DSA-87".as_ptr(),
        evp_type: EVP_PKEY_ML_DSA_87,
        tau: 60,
        bit_strength: 256,
        gamma1: ML_DSA_GAMMA1_TWO_POWER_19 as c_int,
        gamma2: ML_DSA_GAMMA2_Q_MINUS1_DIV32 as c_int,
        k: 8,
        l: 7,
        eta: ML_DSA_ETA_2,
        beta: 120,
        omega: 75,
        security_category: 5,
        sk_len: ML_DSA_87_PRIV_LEN,
        pk_len: ML_DSA_87_PUB_LEN,
        sig_len: ML_DSA_87_SIG_LEN,
    },
];

/// `ossl_ml_dsa_params_get(evp_type)` — `ml_dsa_params.c:96-105`, a linear scan over the table.
pub(crate) fn ossl_ml_dsa_params_get(evp_type: c_int) -> *const MlDsaParams {
    for p in ML_DSA_PARAMS.iter() {
        if p.evp_type == evp_type {
            return p;
        }
    }
    core::ptr::null()
}

/// `struct ml_dsa_key_st` — `ml_dsa_key.h:15-56`.
///
/// `s1`'s polynomial block is allocated with space for `s2` and `t0` after it (`:55`), so the three
/// vectors share one allocation and only `s1.poly` is freed; the field order and the block sizes
/// are the header's.
#[repr(C)]
pub(crate) struct MlDsaKey {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `const ML_DSA_PARAMS *params`.
    pub(crate) params: *const MlDsaParams,
    /// `EVP_MD *shake128_md`.
    pub(crate) shake128_md: *mut EvpMd,
    /// `EVP_MD *shake256_md`.
    pub(crate) shake256_md: *mut EvpMd,
    /// `uint8_t rho[ML_DSA_RHO_BYTES]` — the public random seed.
    pub(crate) rho: [u8; ML_DSA_RHO_BYTES],
    /// `uint8_t tr[ML_DSA_TR_BYTES]` — the pre-cached public-key hash.
    pub(crate) tr: [u8; ML_DSA_TR_BYTES],
    /// `uint8_t K[ML_DSA_K_BYTES]` — the private random seed for signing.
    pub(crate) k: [u8; ML_DSA_K_BYTES],
    /// `uint8_t *pub_encoding` — the encoded public key, or NULL.
    pub(crate) pub_encoding: *mut u8,
    /// `uint8_t *priv_encoding` — the encoded private key, or NULL.
    pub(crate) priv_encoding: *mut u8,
    /// `uint8_t *seed` — the `(rho, K)` seed, or NULL.
    pub(crate) seed: *mut u8,
    /// `int prov_flags` — the `ML_DSA_KEY_*` flags.
    pub(crate) prov_flags: c_int,
    /// `VECTOR t1` — the top 10 bits of `t`; `t1.poly` is allocated.
    pub(crate) t1: Vector,
    /// `VECTOR t0` — the 13 low bits of `t`; points into `s1`'s block.
    pub(crate) t0: Vector,
    /// `VECTOR s2` — the `K`-rank secret with short coefficients; points into `s1`'s block.
    pub(crate) s2: Vector,
    /// `VECTOR s1` — the `L`-rank secret; owns the block `t0` and `s2` also point into.
    pub(crate) s1: Vector,
}

/// `struct ml_dsa_sig_st` — `ml_dsa_sign.h:10-15`.
#[repr(C)]
pub(crate) struct MlDsaSig {
    /// `VECTOR z` — the masked response.
    pub(crate) z: Vector,
    /// `VECTOR hint` — the hint vector.
    pub(crate) hint: Vector,
    /// `uint8_t *c_tilde` — the challenge hash; allocated.
    pub(crate) c_tilde: *mut u8,
    /// `size_t c_tilde_len`.
    pub(crate) c_tilde_len: usize,
}
