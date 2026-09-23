//! Phase 8 — `crypto/rsa/rsa_sp800_56b_check.c`: the SP800-56B RSA key validators.
//!
//! Four hundred and forty-seven source lines and ten functions, and **this module was created in
//! D391 because the reachability measurement changed rather than because the plan did**. D326
//! landed three of these ten — [`ossl_rsa_check_public_exponent`], [`ossl_rsa_check_pminusq_diff`]
//! and [`ossl_rsa_get_lcm`] — inside `src/rsa/sp800.rs` (whose dominant unit is
//! `rsa_sp800_56b_gen.c`), and gave its reason at the top of that module: the generate path reaches
//! exactly those three, the other seven are reached only from `ossl_rsa_sp800_56b_check_keypair` and
//! the provider's public-key validation, and giving the unit its own module would have made seven
//! **unbuilt** internals countable to `forensics/tools/prerequisite_gate.py`, which is a finding
//! rather than a landing.
//!
//! **`rsa_kmgmt.c` reaches all seven**, so the measurement inverts: the seven are no longer dead
//! code, the unit can be transcribed whole (D327's rule), and the three helpers are **moved here**
//! rather than left behind. The three move because the unit↔module map in
//! `forensics/atlas/transcription-edges.json` is *measured* — "the unit is the dominant authority
//! translation unit among the symbols the module defines" — so leaving ten check-unit functions
//! beside five gen-unit ones would have handed `src/rsa/sp800.rs` to the check unit and left
//! `rsa_sp800_56b_gen.c` with no module at all, which would have made the generator's own
//! internals uncountable. One unit, one module, and `src/rsa/sp800.rs` keeps its.
//!
//! ## The `#ifdef FIPS_MODULE` arms are not this profile's and are named at each site
//!
//! `check_public`'s `ossl_rsa_sp800_56b_validate_strength` arm (`:304`), its
//! `BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME`-only status test (`:341`), and
//! `ossl_rsa_check_public_exponent`'s `[17..256]` bit-length window (`:228-233`) are all inside the
//! module guard. The `#else` arms below are the whole function here, exactly as
//! `src/dh/check.rs`'s `DH_check_params` records for its own twin.
//!
//! ## `BN_CTX_get` failures are checked once, at the last temporary
//!
//! Five of these functions take several `BN_CTX_get` results and test only the **last** for NULL,
//! because `BN_CTX_get` is all-or-nothing within a started frame: the authority's `if (gcd != NULL)`
//! is the frame's own answer. A transcription that tested each separately would change nothing
//! observable and would differ from the text; a transcription that tested none would leak the
//! `ret = 0` the authority writes for a failed frame.
//!
//! ## `ossl_rsa_check_crt_components`' "all NULL is OK" arm
//!
//! It returns **1** when every one of `dmp1`, `dmq1` and `iqmp` is NULL — a key with no CRT
//! parameters is valid, and the check is that they are all present or all absent. The partial case
//! is a refusal, and it is the only place in the unit where an unset field is a *pass*.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::{
    BN_cmp, BN_div, BN_gcd, BN_lshift, BN_mod_mul, BN_mul, BN_rshift, BN_sub, BN_sub_word,
};
use crate::bn::bignum::{
    BN_clear, BN_copy, BN_free, BN_is_odd, BN_is_one, BN_is_zero, BN_new, BN_num_bits,
    BN_set_flags, BN_set_negative, BN_value_one, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::primes::{
    ossl_bn_get0_small_factors, ossl_bn_miller_rabin_is_prime, BN_check_prime,
};
use crate::bn::rsa_fips186_4::ossl_bn_inv_sqrt_2;
use crate::rsa::sp800::ossl_rsa_sp800_56b_validate_strength;
use crate::rsa::Rsa;
use crate::runtime::err::err_sites::{
    RSA_SP800_56B_CHECK_294, RSA_SP800_56B_CHECK_309, RSA_SP800_56B_CHECK_314,
    RSA_SP800_56B_CHECK_329, RSA_SP800_56B_CHECK_340, RSA_SP800_56B_CHECK_385,
    RSA_SP800_56B_CHECK_396, RSA_SP800_56B_CHECK_403, RSA_SP800_56B_CHECK_408,
    RSA_SP800_56B_CHECK_413, RSA_SP800_56B_CHECK_427, RSA_SP800_56B_CHECK_440,
};
use crate::runtime::err::raise_site;

/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`.
#[allow(dead_code)] // read only by the five `ossl_rsa_check_*` helpers reached through `ossl_rsa_sp800_56b_check_keypair`
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `OPENSSL_RSA_MAX_MODULUS_BITS` — `include/openssl/rsa.h:76`. Restated for the reason every
/// numeric constant in this crate is: `src/rsa/ossl.rs` keeps its own copy beside its user.
const OPENSSL_RSA_MAX_MODULUS_BITS: c_int = 16384;

/// `RSA_MIN_MODULUS_BITS` — `include/openssl/rsa.h:75`.
const RSA_MIN_MODULUS_BITS: c_int = 512;

/// `BN_PRIMETEST_COMPOSITE_WITH_FACTOR` — `include/crypto/bn.h:103`.
const BN_PRIMETEST_COMPOSITE_WITH_FACTOR: c_int = 1;
/// `BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME` — `include/crypto/bn.h:104`.
const BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME: c_int = 2;

/// `int ossl_rsa_check_crt_components(const RSA *rsa, BN_CTX *ctx)` —
/// `rsa_sp800_56b_check.c:24-78`.
///
/// # Safety
/// `rsa` is live with readable `p`, `q`, `dmp1`, `dmq1`, `iqmp` and `e`; `ctx` is a live `BN_CTX`.
// Reached only from `ossl_rsa_sp800_56b_check_keypair` below, whose only caller in the whole
// authority is `rsa_chk.c`'s `#ifdef FIPS_MODULE` arm, so this profile never calls it.
#[allow(dead_code)]
#[allow(unused_assignments)] // the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
pub(crate) unsafe fn ossl_rsa_check_crt_components(rsa: *const Rsa, ctx: *mut BnCtx) -> c_int {
    let mut ret: c_int = 0;
    let mut r: *mut BigNum = ptr::null_mut();
    let mut p1: *mut BigNum = ptr::null_mut();
    let mut q1: *mut BigNum = ptr::null_mut();

    // SAFETY: `rsa` is live per the contract.
    unsafe {
        /* check if only some of the crt components are set */
        if (*rsa).dmp1.is_null() || (*rsa).dmq1.is_null() || (*rsa).iqmp.is_null() {
            if !(*rsa).dmp1.is_null() || !(*rsa).dmq1.is_null() || !(*rsa).iqmp.is_null() {
                return 0;
            }
            return 1; /* return ok if all components are NULL */
        }

        BN_CTX_start(ctx);
        r = BN_CTX_get(ctx);
        p1 = BN_CTX_get(ctx);
        q1 = BN_CTX_get(ctx);
        if !q1.is_null() {
            BN_set_flags(r, BN_FLG_CONSTTIME);
            BN_set_flags(p1, BN_FLG_CONSTTIME);
            BN_set_flags(q1, BN_FLG_CONSTTIME);
            ret = 1;
        } else {
            ret = 0;
        }
        ret = c_int::from(
            ret != 0
                /* p1 = p -1 */
                && !BN_copy(p1, (*rsa).p).is_null()
                && BN_sub_word(p1, 1) != 0
                /* q1 = q - 1 */
                && !BN_copy(q1, (*rsa).q).is_null()
                && BN_sub_word(q1, 1) != 0
                /* (a) 1 < dP < (p - 1). */
                && BN_cmp((*rsa).dmp1, BN_value_one()) > 0
                && BN_cmp((*rsa).dmp1, p1) < 0
                /* (b) 1 < dQ < (q - 1). */
                && BN_cmp((*rsa).dmq1, BN_value_one()) > 0
                && BN_cmp((*rsa).dmq1, q1) < 0
                /* (c) 1 < qInv < p */
                && BN_cmp((*rsa).iqmp, BN_value_one()) > 0
                && BN_cmp((*rsa).iqmp, (*rsa).p) < 0
                /* (d) 1 = (dP . e) mod (p - 1)*/
                && BN_mod_mul(r, (*rsa).dmp1, (*rsa).e, p1, ctx) != 0
                && BN_is_one(r) != 0
                /* (e) 1 = (dQ . e) mod (q - 1) */
                && BN_mod_mul(r, (*rsa).dmq1, (*rsa).e, q1, ctx) != 0
                && BN_is_one(r) != 0
                /* (f) 1 = (qInv . q) mod p */
                && BN_mod_mul(r, (*rsa).iqmp, (*rsa).q, (*rsa).p, ctx) != 0
                && BN_is_one(r) != 0,
        );
        BN_clear(r);
        BN_clear(p1);
        BN_clear(q1);
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_check_prime_factor_range(const BIGNUM *p, int nbits, BN_CTX *ctx)` —
/// `rsa_sp800_56b_check.c:88-127`.
///
/// # Safety
/// `p` is live; `ctx` is a live `BN_CTX`.
#[allow(unused_assignments)]
// the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
#[allow(dead_code)] // reached only from `ossl_rsa_check_prime_factor` below
pub(crate) unsafe fn ossl_rsa_check_prime_factor_range(
    p: *const BigNum,
    mut nbits: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int = 0;
    let mut low: *mut BigNum = ptr::null_mut();

    nbits >>= 1;
    // SAFETY: `ossl_bn_inv_sqrt_2` answers shared static storage; `p` is live.
    let shift: c_int = unsafe { nbits - BN_num_bits(ossl_bn_inv_sqrt_2()) };

    /* Upper bound check */
    // SAFETY: `p` is live.
    if unsafe { BN_num_bits(p) } != nbits {
        return 0;
    }

    // SAFETY: `ctx` is live and `p` is live per the contract.
    unsafe {
        BN_CTX_start(ctx);
        low = BN_CTX_get(ctx);
        if low.is_null() {
            BN_CTX_end(ctx);
            return ret;
        }

        /* set low = (√2)(2^(nbits/2 - 1) */
        if BN_copy(low, ossl_bn_inv_sqrt_2()).is_null() {
            BN_CTX_end(ctx);
            return ret;
        }

        if shift >= 0 {
            /*
             * We don't have all the bits. ossl_bn_inv_sqrt_2 contains a rounded up
             * value, so there is a very low probability that we'll reject a valid
             * value.
             */
            if BN_lshift(low, low, shift) == 0 {
                BN_CTX_end(ctx);
                return ret;
            }
        } else if BN_rshift(low, low, -shift) == 0 {
            BN_CTX_end(ctx);
            return ret;
        }
        if BN_cmp(p, low) <= 0 {
            BN_CTX_end(ctx);
            return ret;
        }
        ret = 1;
        /* The authority's `err:` label. */
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_check_prime_factor(BIGNUM *p, BIGNUM *e, int nbits, BN_CTX *ctx)` —
/// `rsa_sp800_56b_check.c:136-167`.
///
/// # Safety
/// `p` and `e` are live; `ctx` is a live `BN_CTX`.
#[allow(unused_assignments)]
// the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
#[allow(dead_code)] // reached only from `ossl_rsa_sp800_56b_check_keypair` below
pub(crate) unsafe fn ossl_rsa_check_prime_factor(
    p: *mut BigNum,
    e: *mut BigNum,
    nbits: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int = 0;
    let mut p1: *mut BigNum = ptr::null_mut();
    let mut gcd: *mut BigNum = ptr::null_mut();

    // SAFETY: `p` is live and `ctx` is alive per the contract.
    unsafe {
        /* (Steps 5 a-b) prime test */
        if BN_check_prime(p, ctx, ptr::null_mut()) != 1
            /* (Step 5c) (√2)(2^(nbits/2 - 1) <= p <= 2^(nbits/2 - 1) */
            || ossl_rsa_check_prime_factor_range(p, nbits, ctx) != 1
        {
            return 0;
        }

        BN_CTX_start(ctx);
        p1 = BN_CTX_get(ctx);
        gcd = BN_CTX_get(ctx);
        if !gcd.is_null() {
            BN_set_flags(p1, BN_FLG_CONSTTIME);
            BN_set_flags(gcd, BN_FLG_CONSTTIME);
            ret = 1;
        } else {
            ret = 0;
        }
        ret = c_int::from(
            ret != 0
                /* (Step 5d) GCD(p-1, e) = 1 */
                && !BN_copy(p1, p).is_null()
                && BN_sub_word(p1, 1) != 0
                && BN_gcd(gcd, p1, e, ctx) != 0
                && BN_is_one(gcd) != 0,
        );

        BN_clear(p1);
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_check_private_exponent(const RSA *rsa, int nbits, BN_CTX *ctx)` —
/// `rsa_sp800_56b_check.c:175-220`.
///
/// # Safety
/// `rsa` is live with readable `d`, `p`, `q` and `e`; `ctx` is a live `BN_CTX`.
#[allow(unused_assignments)]
// the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
#[allow(dead_code)] // reached only from `ossl_rsa_sp800_56b_check_keypair` below
pub(crate) unsafe fn ossl_rsa_check_private_exponent(
    rsa: *const Rsa,
    nbits: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int;
    let mut r: *mut BigNum = ptr::null_mut();
    let mut p1: *mut BigNum = ptr::null_mut();
    let mut q1: *mut BigNum = ptr::null_mut();
    let mut lcm: *mut BigNum = ptr::null_mut();
    let mut p1q1: *mut BigNum = ptr::null_mut();
    let mut gcd: *mut BigNum = ptr::null_mut();

    // SAFETY: `rsa` is live per the contract.
    unsafe {
        /* (Step 6a) 2^(nbits/2) < d */
        if BN_num_bits((*rsa).d) <= (nbits >> 1) {
            return 0;
        }

        BN_CTX_start(ctx);
        r = BN_CTX_get(ctx);
        p1 = BN_CTX_get(ctx);
        q1 = BN_CTX_get(ctx);
        lcm = BN_CTX_get(ctx);
        p1q1 = BN_CTX_get(ctx);
        gcd = BN_CTX_get(ctx);
        if !gcd.is_null() {
            BN_set_flags(r, BN_FLG_CONSTTIME);
            BN_set_flags(p1, BN_FLG_CONSTTIME);
            BN_set_flags(q1, BN_FLG_CONSTTIME);
            BN_set_flags(lcm, BN_FLG_CONSTTIME);
            BN_set_flags(p1q1, BN_FLG_CONSTTIME);
            BN_set_flags(gcd, BN_FLG_CONSTTIME);
            ret = 1;
        } else {
            ret = 0;
        }
        ret = c_int::from(
            ret != 0
                /* LCM(p - 1, q - 1) */
                && ossl_rsa_get_lcm(ctx, (*rsa).p, (*rsa).q, lcm, gcd, p1, q1, p1q1) == 1
                /* (Step 6a) d < LCM(p - 1, q - 1) */
                && BN_cmp((*rsa).d, lcm) < 0
                /* (Step 6b) 1 = (e . d) mod LCM(p - 1, q - 1) */
                && BN_mod_mul(r, (*rsa).e, (*rsa).d, lcm, ctx) != 0
                && BN_is_one(r) != 0,
        );

        BN_clear(r);
        BN_clear(p1);
        BN_clear(q1);
        BN_clear(lcm);
        BN_clear(gcd);
        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_rsa_check_public_exponent(const BIGNUM *e)` —
/// `crypto/rsa/rsa_sp800_56b_check.c:226-237`.
///
/// The profile's `#else` arm: "Allow small exponents larger than 1 for legacy
/// purposes". The FIPS arm's `[17..256]` bit-length window is not this build's, and
/// neither is the bound it would place on `rsa_multiprime_keygen`'s `e`.
///
/// # Safety
///
/// `e` must be NULL or a live `BIGNUM`.
pub(crate) unsafe fn ossl_rsa_check_public_exponent(e: *const BigNum) -> c_int {
    // SAFETY: `e` is NULL or live per this function's `# Safety` section, and
    // `BN_is_odd`/`BN_cmp`/`BN_value_one` accept those.
    unsafe { c_int::from(BN_is_odd(e) != 0 && BN_cmp(e, BN_value_one()) > 0) }
}

/// `int ossl_rsa_check_pminusq_diff(BIGNUM *diff, const BIGNUM *p, const BIGNUM *q,`
/// `int nbits)` — `crypto/rsa/rsa_sp800_56b_check.c:243-258`.
///
/// `|p - q| > 2^(nbits/2 - 100)`, with `-1` for "the subtraction failed" and `0` for
/// "not far enough apart". The `BN_set_negative(diff, 0)` is the absolute value, and
/// the `BN_sub_word(diff, 1)` before the width test makes the comparison strict:
/// `num_bits(p - q - 1) > bitlen` is the authority's spelling of
/// `p - q > 2^bitlen`.
///
/// # Safety
///
/// `diff` must be live and writable; `p` and `q` must be live.
pub(crate) unsafe fn ossl_rsa_check_pminusq_diff(
    diff: *mut BigNum,
    p: *const BigNum,
    q: *const BigNum,
    nbits: c_int,
) -> c_int {
    let bitlen = (nbits >> 1) - 100;

    // SAFETY: `diff`, `p` and `q` are live per this function's `# Safety` section.
    unsafe {
        if BN_sub(diff, p, q) == 0 {
            return -1;
        }
        BN_set_negative(diff, 0);
        if BN_is_zero(diff) != 0 {
            return 0;
        }
        if BN_sub_word(diff, 1) == 0 {
            return -1;
        }
        c_int::from(BN_num_bits(diff) > bitlen)
    }
}

/// `int ossl_rsa_get_lcm(BN_CTX *ctx, const BIGNUM *p, const BIGNUM *q, BIGNUM *lcm,`
/// `BIGNUM *gcd, BIGNUM *p1, BIGNUM *q1, BIGNUM *p1q1)` —
/// `crypto/rsa/rsa_sp800_56b_check.c:266-275`.
///
/// `LCM(p-1, q-1)` as `(p-1)(q-1) / gcd(p-1, q-1)`. The caller owns every temporary
/// and must have marked them `BN_FLG_CONSTTIME`; this function only consumes them.
///
/// # Safety
///
/// Every pointer is live; `ctx` is a live `BN_CTX`.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
pub(crate) unsafe fn ossl_rsa_get_lcm(
    ctx: *mut BnCtx,
    p: *const BigNum,
    q: *const BigNum,
    lcm: *mut BigNum,
    gcd: *mut BigNum,
    p1: *mut BigNum,
    q1: *mut BigNum,
    p1q1: *mut BigNum,
) -> c_int {
    // SAFETY: every pointer is live per this function's `# Safety` section.
    unsafe {
        c_int::from(
            BN_sub(p1, p, BN_value_one()) != 0 /* p-1 */
                && BN_sub(q1, q, BN_value_one()) != 0 /* q-1 */
                && BN_mul(p1q1, p1, q1, ctx) != 0 /* (p-1)(q-1) */
                && BN_gcd(gcd, p1, q1, ctx) != 0
                && BN_div(lcm, ptr::null_mut(), p1q1, gcd, ctx) != 0,
        )
    }
}

/// `int ossl_rsa_sp800_56b_check_public(const RSA *rsa)` — `rsa_sp800_56b_check.c:282-350`.
///
/// # Safety
/// `rsa` is live with readable `n`, `e` and `libctx`.
#[allow(unused_assignments)] // the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
pub(crate) unsafe fn ossl_rsa_sp800_56b_check_public(rsa: *const Rsa) -> c_int {
    let mut ret: c_int = 0;
    let mut status: c_int = 0;
    let nbits: c_int;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut gcd: *mut BigNum = ptr::null_mut();

    // SAFETY: `rsa` is live per the contract.
    unsafe {
        if (*rsa).n.is_null() || (*rsa).e.is_null() {
            return 0;
        }

        nbits = BN_num_bits((*rsa).n);
        if nbits > OPENSSL_RSA_MAX_MODULUS_BITS {
            raise_site(&RSA_SP800_56B_CHECK_294);
            return 0;
        }

        /* `#ifdef FIPS_MODULE`'s `ossl_rsa_sp800_56b_validate_strength` arm (`:304`) is not this
         * profile's. */

        if BN_is_odd((*rsa).n) == 0 {
            raise_site(&RSA_SP800_56B_CHECK_309);
            return 0;
        }
        /* (Steps b-c): 2^16 < e < 2^256, n and e must be odd */
        if ossl_rsa_check_public_exponent((*rsa).e) == 0 {
            raise_site(&RSA_SP800_56B_CHECK_314);
            return 0;
        }

        ctx = BN_CTX_new_ex((*rsa).libctx);
        gcd = BN_new();
        if ctx.is_null() || gcd.is_null() {
            BN_free(gcd);
            BN_CTX_free(ctx);
            return ret;
        }

        /* (Steps d-f):
         * The modulus is composite, but not a power of a prime.
         * The modulus has no factors smaller than 752.
         */
        if BN_gcd(gcd, (*rsa).n, ossl_bn_get0_small_factors(), ctx) == 0 || BN_is_one(gcd) == 0 {
            raise_site(&RSA_SP800_56B_CHECK_329);
            ret = 0;
            BN_free(gcd);
            BN_CTX_free(ctx);
            return ret;
        }

        /* Highest number of MR rounds from FIPS 186-5 Section B.3 Table B.1 */
        ret = ossl_bn_miller_rabin_is_prime((*rsa).n, 5, ctx, ptr::null_mut(), 1, &mut status);
        /* `#ifdef FIPS_MODULE`'s `status != BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME` test is the
         * module arm's; this profile's carries the `RSA_MIN_MODULUS_BITS` escape. */
        if ret != 1
            || (status != BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME
                && (nbits >= RSA_MIN_MODULUS_BITS || status != BN_PRIMETEST_COMPOSITE_WITH_FACTOR))
        {
            raise_site(&RSA_SP800_56B_CHECK_340);
            ret = 0;
            /* The authority's `err:` label. */
            BN_free(gcd);
            BN_CTX_free(ctx);
            return ret;
        }

        ret = 1;
        /* The authority's `err:` label. */
        BN_free(gcd);
        BN_CTX_free(ctx);
    }
    ret
}

/// `int ossl_rsa_sp800_56b_check_private(const RSA *rsa)` — `rsa_sp800_56b_check.c:355-360`.
///
/// # Safety
/// `rsa` is live with readable `d`, `n`.
pub(crate) unsafe fn ossl_rsa_sp800_56b_check_private(rsa: *const Rsa) -> c_int {
    // SAFETY: `rsa` is live per the contract.
    unsafe {
        if (*rsa).d.is_null() || (*rsa).n.is_null() {
            return 0;
        }
        c_int::from(BN_cmp((*rsa).d, BN_value_one()) >= 0 && BN_cmp((*rsa).d, (*rsa).n) < 0)
    }
}

/// `int ossl_rsa_sp800_56b_check_keypair(const RSA *rsa, const BIGNUM *efixed,`
/// `int strength, int nbits)` — `rsa_sp800_56b_check.c:373-447`.
///
/// # Safety
/// `rsa` is live with readable `p`, `q`, `e`, `d`, `n` and `libctx`; `efixed` is NULL or live.
#[allow(unused_assignments)]
// the authority's temporaries are declared NULL at the top of the block and assigned after `BN_CTX_start`
#[allow(dead_code)] // its only caller in the whole authority is `rsa_chk.c:250`, inside `#ifdef FIPS_MODULE`
pub(crate) unsafe fn ossl_rsa_sp800_56b_check_keypair(
    rsa: *const Rsa,
    efixed: *const BigNum,
    strength: c_int,
    nbits: c_int,
) -> c_int {
    let mut ret: c_int = 0;
    let mut ctx: *mut BnCtx = ptr::null_mut();
    let mut r: *mut BigNum = ptr::null_mut();

    // SAFETY: `rsa` is live per the contract.
    unsafe {
        if (*rsa).p.is_null()
            || (*rsa).q.is_null()
            || (*rsa).e.is_null()
            || (*rsa).d.is_null()
            || (*rsa).n.is_null()
        {
            raise_site(&RSA_SP800_56B_CHECK_385);
            return 0;
        }
        /* (Step 1): Check Ranges */
        if ossl_rsa_sp800_56b_validate_strength(nbits, strength) == 0 {
            return 0;
        }

        /* If the exponent is known */
        if !efixed.is_null() {
            /* (2): Check fixed exponent matches public exponent. */
            if BN_cmp(efixed, (*rsa).e) != 0 {
                raise_site(&RSA_SP800_56B_CHECK_396);
                return 0;
            }
        }
        /* (Step 1.c): e is odd integer 65537 <= e < 2^256 */
        if ossl_rsa_check_public_exponent((*rsa).e) == 0 {
            /* exponent out of range */
            raise_site(&RSA_SP800_56B_CHECK_403);
            return 0;
        }
        /* (Step 3.b): check the modulus */
        if nbits != BN_num_bits((*rsa).n) {
            raise_site(&RSA_SP800_56B_CHECK_408);
            return 0;
        }
        /* (Step 3.c): check that the modulus length is a positive even integer */
        if nbits <= 0 || (nbits & 0x1) != 0 {
            raise_site(&RSA_SP800_56B_CHECK_413);
            return 0;
        }

        ctx = BN_CTX_new_ex((*rsa).libctx);
        if ctx.is_null() {
            return 0;
        }

        BN_CTX_start(ctx);
        r = BN_CTX_get(ctx);
        if r.is_null() || BN_mul(r, (*rsa).p, (*rsa).q, ctx) == 0 {
            /* The authority's `err:` label. */
            BN_clear(r);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }
        /* (Step 4.c): Check n = pq */
        if BN_cmp((*rsa).n, r) != 0 {
            raise_site(&RSA_SP800_56B_CHECK_427);
            /* The authority's `err:` label. */
            BN_clear(r);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ret;
        }

        /* (Step 5): check prime factors p & q */
        ret = c_int::from(
            ossl_rsa_check_prime_factor((*rsa).p, (*rsa).e, nbits, ctx) != 0
                && ossl_rsa_check_prime_factor((*rsa).q, (*rsa).e, nbits, ctx) != 0
                && ossl_rsa_check_pminusq_diff(r, (*rsa).p, (*rsa).q, nbits) > 0
                /* (Step 6): Check the private exponent d */
                && ossl_rsa_check_private_exponent(rsa, nbits, ctx) != 0
                /* 6.4.1.2.3 (Step 7): Check the CRT components */
                && ossl_rsa_check_crt_components(rsa, ctx) != 0,
        );
        if ret != 1 {
            raise_site(&RSA_SP800_56B_CHECK_440);
        }

        /* The authority's `err:` label. */
        BN_clear(r);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ret
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_is_one, BN_set_word};

    /// **The profile's public-exponent rule is the legacy arm**: an odd exponent
    /// greater than 1 is accepted, and everything else — even values, 1, 0 — is not.
    /// The FIPS arm's bit-length window is a different function, and a test that
    /// asserted it here would be asserting a branch this build does not compile.
    #[test]
    fn the_public_exponent_check_is_the_legacy_arm() {
        // SAFETY: each `e` is a fresh object this test owns and `BN_set_word` writes a
        // live one.
        unsafe {
            for (word, want) in [
                (65537u64, 1),
                (3, 1),
                (17, 1),
                (1, 0),
                (0, 0),
                (2, 0),
                (4, 0),
            ] {
                let e = BN_new();
                assert!(!e.is_null());
                assert_eq!(BN_set_word(e, word), 1);
                assert_eq!(
                    ossl_rsa_check_public_exponent(e),
                    want,
                    "ossl_rsa_check_public_exponent({word})"
                );
                BN_free(e);
            }
        }
    }

    /// **`|p - q| > 2^(nbits/2 - 100)` and its three answers.** A 1023-bit `p` against
    /// `q = 3` is far enough apart at 2048 bits; equal factors answer `0`, and a pair
    /// one apart also answers `0` because the `BN_sub_word(diff, 1)` makes the test
    /// strict.
    #[test]
    fn the_pminusq_check_measures_the_gap() {
        // SAFETY: every pointer is a fresh object this test owns.
        unsafe {
            let p = BN_new();
            let q = BN_new();
            let diff = BN_new();
            assert!(!p.is_null() && !q.is_null() && !diff.is_null());

            assert_eq!(crate::bn::bignum::BN_set_bit(p, 1023), 1);
            assert_eq!(BN_set_word(q, 3), 1);
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p, q, 2048), 1);

            /* `p == q`: zero difference. */
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p, p, 2048), 0);

            /* One apart: `diff - 1 == 0`, so the width test is not satisfied. */
            let q2 = BN_new();
            assert!(!q2.is_null());
            assert_eq!(BN_set_word(q2, 4), 1);
            let p2 = BN_new();
            assert!(!p2.is_null());
            assert_eq!(BN_set_word(p2, 5), 1);
            assert_eq!(ossl_rsa_check_pminusq_diff(diff, p2, q2, 2048), 0);

            BN_free(p);
            BN_free(q);
            BN_free(q2);
            BN_free(p2);
            BN_free(diff);
        }
    }

    /// **The lcm helper is `LCM(p-1, q-1)`, not `(p-1)(q-1)`.** With `p = 61` and
    /// `q = 53` the factors are 60 and 52, whose gcd is 4, so the lcm is 780 — and the
    /// product identity `(p-1)(q-1) = gcd * lcm` is the independent statement that does
    /// not restate the two `BN_div` arguments.
    #[test]
    fn the_lcm_helper_is_the_least_common_multiple() {
        // SAFETY: every pointer is a fresh object this test owns or a live pool slot.
        unsafe {
            let ctx = BN_CTX_new_ex(core::ptr::null_mut());
            assert!(!ctx.is_null());
            BN_CTX_start(ctx);
            let p = BN_new();
            let q = BN_new();
            assert!(!p.is_null() && !q.is_null());
            assert_eq!(BN_set_word(p, 61), 1);
            assert_eq!(BN_set_word(q, 53), 1);

            let (p1, q1, lcm, p1q1, gcd) = (
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
                BN_CTX_get(ctx),
            );
            assert!(!gcd.is_null());
            assert_eq!(ossl_rsa_get_lcm(ctx, p, q, lcm, gcd, p1, q1, p1q1), 1);

            let want = BN_new();
            assert!(!want.is_null());
            assert_eq!(BN_set_word(want, 780), 1);
            assert_eq!(BN_cmp(lcm, want), 0);

            /* `(p-1)(q-1) == gcd * lcm`. */
            let prod = BN_new();
            assert!(!prod.is_null());
            assert_eq!(BN_mul(prod, gcd, lcm, ctx), 1);
            assert_eq!(BN_cmp(prod, p1q1), 0);
            assert_eq!(BN_is_one(gcd), 0);

            BN_free(want);
            BN_free(prod);
            BN_free(p);
            BN_free(q);
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }
    }
}
