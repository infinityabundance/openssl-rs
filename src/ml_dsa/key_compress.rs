//! `crypto/ml_dsa/ml_dsa_key_compress.c` — the key-compression, rounding and hint functions.
//!
//! This file is the whole of `ml_dsa_key_compress.c`: `Power2Round` (FIPS 204 Algorithm 35),
//! `HighBits` (Algorithm 37), `Decompose` (Algorithm 36), `LowBits` (Algorithm 38), `MakeHint`
//! (Algorithm 39) and `UseHint` (Algorithm 40). The two `Decompose` spellings the header declares
//! twice (`ml_dsa_local.h:81-84`, an obvious duplication in the authority's own header) are one
//! function here, because a C translation unit cannot have two definitions of the same name.
//!
//! ## The rounding keeps `r0` positive, and that is the file's own choice
//!
//! `ossl_ml_dsa_key_compress_power2_round` documents (`:18-27`) that it is "more complex than the
//! FIPS 204 spec" because it keeps `r0` positive by adding `q` and re-reducing. That choice is
//! transcribed rather than simplified: the branches that read `r0`'s sign downstream
//! (`use_hint`'s `r0 > 0`, the decompose adjustment) depend on it.
//!
//! ## The constant-time helpers are the crate's `constant_time_*`
//!
//! `constant_time_lt` and `constant_time_select_int` are the authority's; here they are
//! [`crate::runtime::constant_time::constant_time_lt_s`] and
//! [`crate::runtime::constant_time::constant_time_select_int`].
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::runtime::constant_time::{constant_time_lt_s, constant_time_select_int};

use super::{
    mod_sub, reduce_once, ML_DSA_D_BITS, ML_DSA_GAMMA2_Q_MINUS1_DIV32, ML_DSA_Q,
    ML_DSA_Q_MINUS1_DIV2,
};

/// `ossl_ml_dsa_key_compress_power2_round(r, r1, r0)` — `ml_dsa_key_compress.c:34-51`.
///
/// Returns `(r1, r0)`: the top 10 bits (range `0..1023`) and the remainder, whose effective range
/// is 13 bits and which is kept positive, as the file's comment says.
#[inline]
pub(crate) fn ossl_ml_dsa_key_compress_power2_round(r: u32) -> (u32, u32) {
    let mut r1 = r >> ML_DSA_D_BITS;
    let mut r0 = r - (r1 << ML_DSA_D_BITS);

    let r0_adjusted = mod_sub(r0, 1 << ML_DSA_D_BITS);
    let r1_adjusted = r1.wrapping_add(1);

    // Mask is set iff `r0 > 2^(D_BITS - 1)`.
    let mask = constant_time_lt_s(1usize << (ML_DSA_D_BITS - 1), r0 as usize);
    // `r0 = mask ? r0_adjusted : r0` and `r1 = mask ? r1_adjusted : r1`.
    r0 = constant_time_select_int(mask as u32, r0_adjusted as i32, r0 as i32) as u32;
    r1 = constant_time_select_int(mask as u32, r1_adjusted as i32, r1 as i32) as u32;

    (r1, r0)
}

/// `ossl_ml_dsa_key_compress_high_bits(r, gamma2)` — `ml_dsa_key_compress.c:62-75`.
///
/// FIPS 204 Algorithm 37. The two multipliers `1025`/`11275` and shifts are the file's own
/// integer approximations of the `round`/`floor` formulas.
pub(crate) fn ossl_ml_dsa_key_compress_high_bits(r: u32, gamma2: u32) -> u32 {
    let mut r1: i32 = ((r + 127) >> 7) as i32;

    if gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32 {
        r1 = (r1 * 1025 + (1 << 21)) >> 22;
        r1 &= 15; /* mod 16 */
        r1 as u32
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;
        r1 ^= ((43 - r1) >> 31) & r1;
        r1 as u32
    }
}

/// `ossl_ml_dsa_key_compress_decompose(r, gamma2, r1, r0)` — `ml_dsa_key_compress.c:86-93`.
///
/// Returns `(r1, r0)` with `r == r1 * (2 * gamma2) + r0 mod q`.
pub(crate) fn ossl_ml_dsa_key_compress_decompose(r: u32, gamma2: u32) -> (u32, i32) {
    let r1 = ossl_ml_dsa_key_compress_high_bits(r, gamma2);

    let mut r0: i32 = r as i32 - (r1 as i32) * 2 * (gamma2 as i32);
    r0 -= (((ML_DSA_Q_MINUS1_DIV2 as i32) - r0) >> 31) & (ML_DSA_Q as i32);
    (r1, r0)
}

/// `ossl_ml_dsa_key_compress_low_bits(r, gamma2)` — `ml_dsa_key_compress.c:104-111`.
///
/// FIPS 204 Algorithm 38.
pub(crate) fn ossl_ml_dsa_key_compress_low_bits(r: u32, gamma2: u32) -> i32 {
    let (_, r0) = ossl_ml_dsa_key_compress_decompose(r, gamma2);
    r0
}

/// `ossl_ml_dsa_key_compress_make_hint(ct0, cs2, gamma2, w)` — `ml_dsa_key_compress.c:133-141`.
///
/// FIPS 204 Algorithm 39, specialised to the three arguments the caller has (the file's comment
/// `:118-124` explains the saving) and reduced to one bit of result.
pub(crate) fn ossl_ml_dsa_key_compress_make_hint(ct0: u32, cs2: u32, gamma2: u32, w: u32) -> i32 {
    let r_plus_z = mod_sub(w, cs2);
    let r = reduce_once(r_plus_z.wrapping_add(ct0));

    (ossl_ml_dsa_key_compress_high_bits(r, gamma2)
        != ossl_ml_dsa_key_compress_high_bits(r_plus_z, gamma2)) as i32
}

/// `ossl_ml_dsa_key_compress_use_hint(hint, r, gamma2)` — `ml_dsa_key_compress.c:154-175`.
///
/// FIPS 204 Algorithm 40. The file notes it is **not** constant time (`:146`), and the branches on
/// `r0`'s sign and on `r1 == 43`/`r1 == 0` are transcribed rather than masked.
pub(crate) fn ossl_ml_dsa_key_compress_use_hint(hint: u32, r: u32, gamma2: u32) -> u32 {
    let (r1, r0) = ossl_ml_dsa_key_compress_decompose(r, gamma2);

    if hint == 0 {
        return r1;
    }

    if gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32 {
        /* m = 16, thus |mod m| in the spec turns into |& 15| */
        if r0 > 0 {
            (r1 + 1) & 15
        } else {
            r1.wrapping_sub(1) & 15
        }
    } else {
        /* m = 44 if gamma2 = ((q - 1) / 88) */
        if r0 > 0 {
            if r1 == 43 {
                0
            } else {
                r1 + 1
            }
        } else if r1 == 0 {
            43
        } else {
            r1 - 1
        }
    }
}
