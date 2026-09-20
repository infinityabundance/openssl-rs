//! Phase 8 — `crypto/ffc/ffc_params_validate.c`: FFC domain-parameter validation.
//!
//! This unit calls the *same* generator the generation path uses, because the authority's
//! validation is the generation run backwards: `ossl_ffc_params_FIPS186_4_gen_verify` takes a
//! `mode` and computes the same `V(j)` chain, comparing each result against the parameters the
//! caller supplied. That is why `ffc_params_generate.c` is the larger half and why the
//! validator here is two small wrappers plus the generator's `g`-only arm.
//!
//! ## The entry point the DH key path reaches
//!
//! `ossl_ffc_params_simple_validate` is what `crypto/dh/dh_key.c:353` calls before generating a
//! private key from a caller-supplied `q`: it validates `p` and `g` structurally and
//! **deliberately does not validate `q`'s primality or the seed chain**, because those inputs
//! may not be available. Its three load-bearing decisions are transcribed rather than
//! summarised:
//!
//! * The params are **copied first** and the copy is what is validated, with `flags` forced to
//!   `VALIDATE_G` (only) and `gindex` forced to `FFC_UNVERIFIABLE_GINDEX`. So a caller's own
//!   `VALIDATE_PQ` bit, seed and counter do not reach the p/q chain, and the canonical-`g` arm
//!   cannot fire even when the caller set a `gindex`.
//! * `res == NULL` is replaced by a local, so the `FFC_ERROR_NOT_SUITABLE_GENERATOR` test
//!   always has somewhere to read from.
//! * A failure that carries the not-suitable-generator bit raises
//!   **`DH_R_NOT_SUITABLE_GENERATOR`** from `ERR_LIB_DH` — the FFC unit raising a DH-library
//!   reason, which is what `include/internal/ffc.h`'s own header comment ("Uses Error codes
//!   from DH") says it does and why `crypto/ffc/` has no error library of its own. The reason's
//!   coordinate is generated, not typed: `FFC_PARAMS_VALIDATE_125`.
//!
//! `ossl_ffc_params_full_validate` is the non-FIPS arm: with a seed present it delegates to the
//! FIPS 186-4 or 186-2 validator according to `VALIDATE_LEGACY`, and without one it runs the
//! simple check and then `BN_check_prime` on `q` and `p`, raising the **DSA** prime reasons.
//!
//! ## The `#ifdef FIPS_MODULE` arms, recorded rather than silently dropped
//!
//! Both entry points carry FIPS-only arms, and `full_validate` is *entirely* FIPS-only above
//! the `#else`. Neither is this profile's, so neither is compiled into the bodies above; the
//! FIPS spellings are named here because a reader of the authority's file will find them:
//! `simple_validate` would lose its 186-2 branch (the `VALIDATE_LEGACY` test is inside
//! `#ifndef FIPS_MODULE`), and `full_validate` would become a one-line call to
//! `ossl_ffc_params_FIPS186_4_validate`.

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_num_bits, BN_value_one, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex, BnCtx, BnGencb};
use crate::bn::mont::{BN_mod_exp_mont, MontCtx};
use crate::bn::primes::BN_check_prime;
use crate::runtime::err::err_sites::{
    FFC_PARAMS_VALIDATE_125, FFC_PARAMS_VALIDATE_172, FFC_PARAMS_VALIDATE_178,
};
use crate::runtime::err::raise_site;

use super::params::{ossl_ffc_params_cleanup, ossl_ffc_params_copy};
use super::params_generate::{
    ossl_ffc_params_FIPS186_2_gen_verify, ossl_ffc_params_FIPS186_4_gen_verify,
};
use super::{
    FfcParams, FFC_CHECK_INVALID_PQ, FFC_ERROR_NOT_SUITABLE_GENERATOR, FFC_PARAM_FLAG_VALIDATE_G,
    FFC_PARAM_FLAG_VALIDATE_LEGACY, FFC_PARAM_MODE_VERIFY, FFC_PARAM_RET_STATUS_FAILED,
    FFC_UNVERIFIABLE_GINDEX,
};

/// `int ossl_ffc_params_validate_unverifiable_g(BN_CTX *ctx, BN_MONT_CTX *mont,`
/// `const BIGNUM *p, const BIGNUM *q, const BIGNUM *g, BIGNUM *tmp, int *ret)` —
/// `crypto/ffc/ffc_params_validate.c:23-50`.
///
/// FIPS 186-4 A.2.2's unverifiable partial validation of the generator: **`2 <= g <= p - 1`**
/// and **`g^q mod p == 1`**. Both failures set `FFC_ERROR_NOT_SUITABLE_GENERATOR` — the same bit
/// for two different causes, which is why `ossl_ffc_params_simple_validate` can report only "not
/// suitable" rather than which test failed.
///
/// Both `*ret` writes are `|=` rather than `=`, so a caller that pre-seeded the word keeps what
/// it had. Nothing this slice lands pre-seeds it; the authority's own callers pass the `res` that
/// `ossl_ffc_params_FIPS186_4_gen_verify` zeroed at entry.
///
/// The range test is the authority's own spelling of `2 <= g <= p - 1`: `BN_cmp(g, 1) <= 0`
/// rejects 1 *and every negative value*, and `BN_cmp(g, p) >= 0` rejects `p` and above.
///
/// # Safety
///
/// `ctx` and `mont` must be live and `mont` must have been set for `p`; `p`, `q` and `g` must
/// be live; `tmp` must be a live scratch `BIGNUM`; `ret` must be writable.
pub(crate) unsafe fn ossl_ffc_params_validate_unverifiable_g(
    ctx: *mut BnCtx,
    mont: *mut MontCtx,
    p: *const BigNum,
    q: *const BigNum,
    g: *const BigNum,
    tmp: *mut BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: every pointer is live per this function's `# Safety` section.
    unsafe {
        /*
         * A.2.2 Step (1) AND
         * A.2.4 Step (2)
         * Verify that 2 <= g <= (p - 1)
         */
        if BN_cmp(g, BN_value_one()) <= 0 || BN_cmp(g, p) >= 0 {
            *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
            return 0;
        }

        /*
         * A.2.2 Step (2) AND
         * A.2.4 Step (3)
         * Check g^q mod p = 1
         */
        if BN_mod_exp_mont(tmp, g, q, p, ctx, mont) == 0 {
            return 0;
        }
        if BN_cmp(tmp, BN_value_one()) != 0 {
            *ret |= FFC_ERROR_NOT_SUITABLE_GENERATOR;
            return 0;
        }
    }
    1
}

/// `int ossl_ffc_params_FIPS186_4_validate(OSSL_LIB_CTX *libctx, const FFC_PARAMS *params,`
/// `int type, int *res, BN_GENCB *cb)` — `crypto/ffc/ffc_params_validate.c:52-67`.
///
/// `L` and `N` are **not** parameters here: they are read off the object, `L = BN_num_bits(p)`
/// and `N = BN_num_bits(q)`, which is why this entry point takes fewer arguments than the
/// generator it calls. The `params->p == NULL || params->q == NULL` refusal answers
/// `FFC_PARAM_RET_STATUS_FAILED` **without touching `*res`** — the opposite of the 186-2 twin
/// below, and the difference is observable from a caller that pre-set `res`.
///
/// # Safety
///
/// `params` must be live and its `p`/`q` slots NULL or live; `res` must be writable; `cb` must
/// be NULL or a live `BN_GENCB`.
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_4_validate(
    libctx: *mut core::ffi::c_void,
    params: *const FfcParams,
    type_: c_int,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `params` is live per this function's `# Safety` section.
    unsafe {
        if params.is_null() || (*params).p.is_null() || (*params).q.is_null() {
            return FFC_PARAM_RET_STATUS_FAILED;
        }

        /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
        let l = BN_num_bits((*params).p) as usize;
        let n = BN_num_bits((*params).q) as usize;
        /* The authority casts the `const FFC_PARAMS *` to `FFC_PARAMS *` here, because the
         * generating mode writes `p`, `q` and `g` back through it. In verify mode nothing is
         * written, and the cast is the authority's own. */
        ossl_ffc_params_FIPS186_4_gen_verify(
            libctx,
            params.cast_mut(),
            FFC_PARAM_MODE_VERIFY,
            type_,
            l,
            n,
            res,
            cb,
        )
    }
}

/// `int ossl_ffc_params_FIPS186_2_validate(OSSL_LIB_CTX *libctx, const FFC_PARAMS *params,`
/// `int type, int *res, BN_GENCB *cb)` — `crypto/ffc/ffc_params_validate.c:70-87`.
///
/// "This may be used in FIPS mode to validate deprecated FIPS-186-2 Params." The one
/// behavioural difference from the 186-4 twin is the refusal: **this one sets
/// `FFC_CHECK_INVALID_PQ` before answering failed**, and it tests `params == NULL` first, so a
/// NULL object is also `INVALID_PQ` rather than a general failure.
///
/// # Safety
///
/// As [`ossl_ffc_params_FIPS186_4_validate`]; `res` must be writable (not NULL).
#[allow(non_snake_case)] // the authority's name, kept verbatim
pub(crate) unsafe fn ossl_ffc_params_FIPS186_2_validate(
    libctx: *mut core::ffi::c_void,
    params: *const FfcParams,
    type_: c_int,
    res: *mut c_int,
    cb: *mut BnGencb,
) -> c_int {
    // SAFETY: `params` is live per this function's `# Safety` section.
    unsafe {
        if params.is_null() || (*params).p.is_null() || (*params).q.is_null() {
            *res = FFC_CHECK_INVALID_PQ;
            return FFC_PARAM_RET_STATUS_FAILED;
        }

        /* A.1.1.3 Step (1..2) : L = len(p), N = len(q) */
        let l = BN_num_bits((*params).p) as usize;
        let n = BN_num_bits((*params).q) as usize;
        ossl_ffc_params_FIPS186_2_gen_verify(
            libctx,
            params.cast_mut(),
            FFC_PARAM_MODE_VERIFY,
            type_,
            l,
            n,
            res,
            cb,
        )
    }
}

/// `int ossl_ffc_params_simple_validate(OSSL_LIB_CTX *libctx, const FFC_PARAMS *params,`
/// `int paramstype, int *res)` — `crypto/ffc/ffc_params_validate.c:95-132`.
///
/// "This does a simple check of L and N and partial g. It makes no attempt to do a full
/// validation of p, q or g since these require extra parameters such as the digest and seed,
/// which may not be available for this test."
///
/// The four steps:
///
/// 1. `params == NULL` answers **0**, not a `RET_STATUS`: this function's answer is a boolean,
///    not the tri-state the generator below it returns.
/// 2. A local `tmpres` stands in for a NULL `res`.
/// 3. The object is **copied** and the copy is rewritten: `flags = FFC_PARAM_FLAG_VALIDATE_G`
///    (so `VALIDATE_PQ` and `VALIDATE_LEGACY` are cleared and the `p`/`q` chain is not checked)
///    and `gindex = FFC_UNVERIFIABLE_GINDEX` (so the canonical-`g` arm cannot fire). The seed has
///    been carried over by the copy, which is what lets the generator's seed-length check still
///    see it.
/// 4. The answer is `ret != FAILED`, so the generator's third answer
///    (`FFC_PARAM_RET_STATUS_UNVERIFIABLE_G`, 2) is a **success** here — which is the point of
///    the partial check.
///
/// The 186-2 arm is tested against the **caller's** flags, not the copy's — the copy's
/// `VALIDATE_LEGACY` was just cleared, so reading it there would make the arm unreachable.
///
/// # Safety
///
/// `params` must be live and its slots NULL or live; `res` must be NULL or writable.
pub(crate) unsafe fn ossl_ffc_params_simple_validate(
    libctx: *mut core::ffi::c_void,
    params: *const FfcParams,
    paramstype: c_int,
    res: *mut c_int,
) -> c_int {
    let mut tmpres: c_int = 0;
    /* `FFC_PARAMS tmpparams = { 0 };` — zero, not `ossl_ffc_params_init`'s three settings.
     * Nothing observable turns on the difference: the copy overwrites every field, and its own
     * failure path re-initialises the destination. The authority spells it `{ 0 }`. */
    let mut tmpparams = core::mem::MaybeUninit::<FfcParams>::zeroed();

    if params.is_null() {
        return 0;
    }

    let res_ptr = if res.is_null() { &raw mut tmpres } else { res };

    // SAFETY: `params` is live and `tmpparams` is a local, zeroed destination this call owns.
    unsafe {
        if ossl_ffc_params_copy(tmpparams.as_mut_ptr(), params) == 0 {
            return 0;
        }
        let tmp = tmpparams.as_mut_ptr();
        (*tmp).flags = FFC_PARAM_FLAG_VALIDATE_G;
        (*tmp).gindex = FFC_UNVERIFIABLE_GINDEX;

        let ret = if ((*params).flags & FFC_PARAM_FLAG_VALIDATE_LEGACY) != 0 {
            ossl_ffc_params_FIPS186_2_validate(libctx, tmp, paramstype, res_ptr, ptr::null_mut())
        } else {
            ossl_ffc_params_FIPS186_4_validate(libctx, tmp, paramstype, res_ptr, ptr::null_mut())
        };

        if ret == FFC_PARAM_RET_STATUS_FAILED && (*res_ptr & FFC_ERROR_NOT_SUITABLE_GENERATOR) != 0
        {
            raise_site(&FFC_PARAMS_VALIDATE_125);
        }

        ossl_ffc_params_cleanup(tmp);

        c_int::from(ret != FFC_PARAM_RET_STATUS_FAILED)
    }
}

/// `int ossl_ffc_params_full_validate(OSSL_LIB_CTX *libctx, const FFC_PARAMS *params,`
/// `int paramstype, int *res)` — `crypto/ffc/ffc_params_validate.c:139-187`.
///
/// "If possible (or always in FIPS_MODULE) do full FIPS 186-4 validation. Otherwise do simple
/// check but in addition also check the primality of the p and q."
///
/// Three arms on this profile:
///
/// * **A NULL object is normalised first**, and unlike [`ossl_ffc_params_simple_validate`] the
///   `res` substitution happens after the NULL test, so a NULL `params` answers 0 with `res`
///   untouched.
/// * **A seed is present**: delegate to the 186-2 validator when `VALIDATE_LEGACY` is set and to
///   the 186-4 one otherwise. The answer is the generator's tri-state, passed straight out.
/// * **No seed**: run the simple check, then test `q` and `p` for primality with a fresh
///   `BN_CTX`. Each failure raises the **DSA** reason (`DSA_R_Q_NOT_PRIME` at `:172`,
///   `DSA_R_P_NOT_PRIME` at `:178`) even for a DH parameter set — the DSA library's reasons are
///   what the authority's FFC validator raises here, and `crypto/ffc/` has no reasons of its
///   own. The `p` test is guarded by `ret != 0`, so a non-prime `q` skips it entirely. A
///   `BN_CTX_new_ex` failure answers 0 **without** running either test.
///
/// # Safety
///
/// `params` must be live and its slots NULL or live; `res` must be NULL or writable.
pub(crate) unsafe fn ossl_ffc_params_full_validate(
    libctx: *mut core::ffi::c_void,
    params: *const FfcParams,
    paramstype: c_int,
    res: *mut c_int,
) -> c_int {
    let mut tmpres: c_int = 0;

    if params.is_null() {
        return 0;
    }

    let res_ptr = if res.is_null() { &raw mut tmpres } else { res };

    // SAFETY: `params` is live and `res_ptr` is a local or the caller's writable pointer.
    unsafe {
        if !(*params).seed.is_null() {
            if ((*params).flags & FFC_PARAM_FLAG_VALIDATE_LEGACY) != 0 {
                return ossl_ffc_params_FIPS186_2_validate(
                    libctx,
                    params,
                    paramstype,
                    res_ptr,
                    ptr::null_mut(),
                );
            }
            return ossl_ffc_params_FIPS186_4_validate(
                libctx,
                params,
                paramstype,
                res_ptr,
                ptr::null_mut(),
            );
        }

        let mut ret = ossl_ffc_params_simple_validate(libctx, params, paramstype, res_ptr);
        if ret != 0 {
            let ctx: *mut BnCtx = BN_CTX_new_ex(libctx);
            if ctx.is_null() {
                return 0;
            }
            if BN_check_prime((*params).q, ctx, ptr::null_mut()) != 1 {
                raise_site(&FFC_PARAMS_VALIDATE_172);
                ret = 0;
            }
            if ret != 0 && BN_check_prime((*params).p, ctx, ptr::null_mut()) != 1 {
                raise_site(&FFC_PARAMS_VALIDATE_178);
                ret = 0;
            }
            BN_CTX_free(ctx);
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::arith::{BN_add_word, BN_lshift, BN_lshift1};
    use crate::bn::bignum::{BN_bin2bn, BN_dup, BN_free, BN_new, BN_set_word};
    use crate::bn::ctx::{BN_CTX_end, BN_CTX_get, BN_CTX_start};
    use crate::bn::mont::{BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set};
    use crate::ffc::params::{
        ossl_ffc_params_cleanup, ossl_ffc_params_init, ossl_ffc_params_set0_pqg,
        ossl_ffc_params_set_flags, ossl_ffc_params_set_seed, ossl_ffc_params_set_validate_params,
        ossl_ffc_set_digest,
    };
    use crate::ffc::params_generate::ossl_ffc_params_FIPS186_4_generate;
    use crate::ffc::{
        FFC_CHECK_BAD_LN_PAIR, FFC_CHECK_INVALID_G, FFC_CHECK_INVALID_PQ,
        FFC_CHECK_INVALID_Q_VALUE, FFC_CHECK_INVALID_SEED_SIZE, FFC_CHECK_Q_MISMATCH,
        FFC_CHECK_Q_NOT_PRIME, FFC_PARAM_FLAG_VALIDATE_LEGACY, FFC_PARAM_FLAG_VALIDATE_PQ,
        FFC_PARAM_RET_STATUS_SUCCESS, FFC_PARAM_RET_STATUS_UNVERIFIABLE_G, FFC_PARAM_TYPE_DH,
        FFC_PARAM_TYPE_DSA,
    };

    /// A fresh params object, released on drop. Every test here owns its objects, which is what
    /// makes the `# Safety` sections in the module above satisfiable at all.
    struct Params(FfcParams);

    impl Params {
        fn new() -> Self {
            let mut p = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `p` is live and writable; `ossl_ffc_params_init` writes every byte.
            let inner = unsafe {
                ossl_ffc_params_init(p.as_mut_ptr());
                p.assume_init()
            };
            Params(inner)
        }

        fn as_mut(&mut self) -> *mut FfcParams {
            &raw mut self.0
        }

        fn as_ref(&self) -> *const FfcParams {
            &raw const self.0
        }
    }

    impl Drop for Params {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { ossl_ffc_params_cleanup(&raw mut self.0) };
        }
    }

    /*
     * `test/ffc_internal_test.c`'s own parameter sets. They are the authority's known-good
     * groups, which is what makes the validation answers below assertions about the *primes*
     * rather than about this crate agreeing with itself.
     */

    /// `dsa_2048_224_sha224_p` — `test/ffc_internal_test.c:33-56`.
    const P_2048_224_SHA224: [u8; 256] = [
        0x93, 0x57, 0x93, 0x62, 0x1b, 0x9a, 0x10, 0x9b, 0xc1, 0x56, 0x0f, 0x24, 0x71, 0x76, 0x4e,
        0xd3, 0xed, 0x78, 0x78, 0x7a, 0xbf, 0x89, 0x71, 0x67, 0x8e, 0x03, 0xd8, 0x5b, 0xcd, 0x22,
        0x8f, 0x70, 0x74, 0xff, 0x22, 0x05, 0x07, 0x0c, 0x4c, 0x60, 0xed, 0x41, 0xe1, 0x9e, 0x9c,
        0xaa, 0x3e, 0x19, 0x5c, 0x3d, 0x80, 0x58, 0xb2, 0x7f, 0x5f, 0x89, 0xec, 0xb5, 0x19, 0xdb,
        0x06, 0x11, 0xe9, 0x78, 0x5c, 0xf9, 0xa0, 0x9e, 0x70, 0x62, 0x14, 0x7b, 0xda, 0x92, 0xbf,
        0xb2, 0x6b, 0x01, 0x6f, 0xb8, 0x68, 0x9c, 0x89, 0x36, 0x89, 0x72, 0x79, 0x49, 0x93, 0x3d,
        0x14, 0xb2, 0x2d, 0xbb, 0xf0, 0xdf, 0x94, 0x45, 0x0b, 0x5f, 0xf1, 0x75, 0x37, 0xeb, 0x49,
        0xb9, 0x2d, 0xce, 0xb7, 0xf4, 0x95, 0x77, 0xc2, 0xe9, 0x39, 0x1c, 0x4e, 0x0c, 0x40, 0x62,
        0x33, 0x0a, 0xe6, 0x29, 0x6f, 0xba, 0xef, 0x02, 0xdd, 0x0d, 0xe4, 0x04, 0x01, 0x70, 0x40,
        0xb9, 0xc9, 0x7e, 0x2f, 0x10, 0x37, 0xe9, 0xde, 0xb0, 0xf6, 0xeb, 0x71, 0x7f, 0x9c, 0x35,
        0x16, 0xf3, 0x0d, 0xc4, 0xe8, 0x02, 0x37, 0x6c, 0xdd, 0xb3, 0x8d, 0x2d, 0x1e, 0x28, 0x13,
        0x22, 0x89, 0x40, 0xe5, 0xfa, 0x16, 0x67, 0xd6, 0xda, 0x12, 0xa2, 0x38, 0x83, 0x25, 0xcc,
        0x26, 0xc1, 0x27, 0x74, 0xfe, 0xf6, 0x7a, 0xb6, 0xa1, 0xe4, 0xe8, 0xdf, 0x5d, 0xd2, 0x9c,
        0x2f, 0xec, 0xea, 0x08, 0xca, 0x48, 0xdb, 0x18, 0x4b, 0x12, 0xee, 0x16, 0x9b, 0xa6, 0x00,
        0xa0, 0x18, 0x98, 0x7d, 0xce, 0x6c, 0x6d, 0xf8, 0xfc, 0x95, 0x51, 0x1b, 0x0a, 0x40, 0xb6,
        0xfc, 0xe5, 0xe2, 0xb0, 0x26, 0x53, 0x4c, 0xd7, 0xfe, 0xaa, 0x6d, 0xbc, 0xdd, 0xc0, 0x61,
        0x65, 0xe4, 0x89, 0x44, 0x18, 0x6f, 0xd5, 0x39, 0xcf, 0x75, 0x6d, 0x29, 0xcc, 0xf8, 0x40,
        0xab,
    ];
    /// `dsa_2048_224_sha224_q` — `test/ffc_internal_test.c:57-61`.
    const Q_2048_224_SHA224: [u8; 28] = [
        0xf2, 0x5e, 0x4e, 0x9a, 0x15, 0xa8, 0x13, 0xdf, 0xa3, 0x17, 0x90, 0xc6, 0xd6, 0x5e, 0xb1,
        0xfb, 0x31, 0xf8, 0xb5, 0xb1, 0x4b, 0xa7, 0x6d, 0xde, 0x57, 0x76, 0x6f, 0x11,
    ];
    /// `dsa_2048_224_sha224_seed` — `test/ffc_internal_test.c:62-66`.
    const SEED_2048_224_SHA224: [u8; 28] = [
        0xd2, 0xb1, 0x36, 0xd8, 0x5b, 0x8e, 0xa4, 0xb2, 0x6a, 0xab, 0x4e, 0x85, 0x8b, 0x49, 0xf9,
        0xdd, 0xe6, 0xa1, 0xcd, 0xad, 0x49, 0x52, 0xe9, 0xb3, 0x36, 0x17, 0x06, 0xcf,
    ];
    /// `dsa_2048_224_sha224_bad_seed` — `test/ffc_internal_test.c:67-71`: the last byte is `d0`
    /// rather than `cf`.
    const BAD_SEED_2048_224_SHA224: [u8; 28] = [
        0xd2, 0xb1, 0x36, 0xd8, 0x5b, 0x8e, 0xa4, 0xb2, 0x6a, 0xab, 0x4e, 0x85, 0x8b, 0x49, 0xf9,
        0xdd, 0xe6, 0xa1, 0xcd, 0xad, 0x49, 0x52, 0xe9, 0xb3, 0x36, 0x17, 0x06, 0xd0,
    ];
    /// `dsa_2048_224_sha224_counter` — `test/ffc_internal_test.c:72`.
    const COUNTER_2048_224_SHA224: c_int = 2878;

    /// `dsa_2048_224_sha256_p` — `test/ffc_internal_test.c:120-143`.
    const P_2048_224_SHA256: [u8; 256] = [
        0xe9, 0x13, 0xbc, 0xf2, 0x14, 0x5d, 0xf9, 0x79, 0xd6, 0x6d, 0xf5, 0xc5, 0xbe, 0x7b, 0x6f,
        0x90, 0x63, 0xd0, 0xfd, 0xee, 0x4f, 0xc4, 0x65, 0x83, 0xbf, 0xec, 0xc3, 0x2c, 0x5d, 0x30,
        0xc8, 0xa4, 0x3b, 0x2f, 0x3b, 0x29, 0x43, 0x69, 0xfb, 0x6e, 0xa9, 0xa4, 0x07, 0x6c, 0xcd,
        0xb0, 0xd2, 0xd9, 0xd3, 0xe6, 0xf4, 0x87, 0x16, 0xb7, 0xe5, 0x06, 0xb9, 0xba, 0xd6, 0x87,
        0xbc, 0x01, 0x9e, 0xba, 0xc2, 0xcf, 0x39, 0xb6, 0xec, 0xdc, 0x75, 0x07, 0xc1, 0x39, 0x2d,
        0x6a, 0x95, 0x31, 0x97, 0xda, 0x54, 0x20, 0x29, 0xe0, 0x1b, 0xf9, 0x74, 0x65, 0xaa, 0xc1,
        0x47, 0xd3, 0x9e, 0xb4, 0x3c, 0x1d, 0xe0, 0xdc, 0x2d, 0x21, 0xab, 0x12, 0x3b, 0xa5, 0x51,
        0x1e, 0xc6, 0xbc, 0x6b, 0x4c, 0x22, 0xd1, 0x7c, 0xc6, 0xce, 0xcb, 0x8c, 0x1d, 0x1f, 0xce,
        0x1c, 0xe2, 0x75, 0x49, 0x6d, 0x2c, 0xee, 0x7f, 0x5f, 0xb8, 0x74, 0x42, 0x5c, 0x96, 0x77,
        0x13, 0xff, 0x80, 0xf3, 0x05, 0xc7, 0xfe, 0x08, 0x3b, 0x25, 0x36, 0x46, 0xa2, 0xc4, 0x26,
        0xb4, 0xb0, 0x3b, 0xd5, 0xb2, 0x4c, 0x13, 0x29, 0x0e, 0x47, 0x31, 0x66, 0x7d, 0x78, 0x57,
        0xe6, 0xc2, 0xb5, 0x9f, 0x46, 0x17, 0xbc, 0xa9, 0x9a, 0x49, 0x1c, 0x0f, 0x45, 0xe0, 0x88,
        0x97, 0xa1, 0x30, 0x7c, 0x42, 0xb7, 0x2c, 0x0a, 0xce, 0xb3, 0xa5, 0x7a, 0x61, 0x8e, 0xab,
        0x44, 0xc1, 0xdc, 0x70, 0xe5, 0xda, 0x78, 0x2a, 0xb4, 0xe6, 0x3c, 0xa0, 0x58, 0xda, 0x62,
        0x0a, 0xb2, 0xa9, 0x3d, 0xaa, 0x49, 0x7e, 0x7f, 0x9a, 0x19, 0x67, 0xee, 0xd6, 0xe3, 0x67,
        0x13, 0xe8, 0x6f, 0x79, 0x50, 0x76, 0xfc, 0xb3, 0x9d, 0x7e, 0x9e, 0x3e, 0x6e, 0x47, 0xb1,
        0x11, 0x5e, 0xc8, 0x83, 0x3a, 0x3c, 0xfc, 0x82, 0x5c, 0x9d, 0x34, 0x65, 0x73, 0xb4, 0x56,
        0xd5,
    ];
    /// `dsa_2048_224_sha256_q` — `test/ffc_internal_test.c:144-148`.
    const Q_2048_224_SHA256: [u8; 28] = [
        0xb0, 0xdf, 0xa1, 0x7b, 0xa4, 0x77, 0x64, 0x0e, 0xb9, 0x28, 0xbb, 0xbc, 0xd4, 0x60, 0x02,
        0xaf, 0x21, 0x8c, 0xb0, 0x69, 0x0f, 0x8a, 0x7b, 0xc6, 0x80, 0xcb, 0x0a, 0x45,
    ];
    /// `dsa_2048_224_sha256_g` — `test/ffc_internal_test.c:149-172`.
    const G_2048_224_SHA256: [u8; 256] = [
        0x11, 0x7c, 0x5f, 0xf6, 0x99, 0x44, 0x67, 0x5b, 0x69, 0xa3, 0x83, 0xef, 0xb5, 0x85, 0xa2,
        0x19, 0x35, 0x18, 0x2a, 0xf2, 0x58, 0xf4, 0xc9, 0x58, 0x9e, 0xb9, 0xe8, 0x91, 0x17, 0x2f,
        0xb0, 0x60, 0x85, 0x95, 0xa6, 0x62, 0x36, 0xd0, 0xff, 0x94, 0xb9, 0xa6, 0x50, 0xad, 0xa6,
        0xf6, 0x04, 0x28, 0xc2, 0xc9, 0xb9, 0x75, 0xf3, 0x66, 0xb4, 0xeb, 0xf6, 0xd5, 0x06, 0x13,
        0x01, 0x64, 0x82, 0xa9, 0xf1, 0xd5, 0x41, 0xdc, 0xf2, 0x08, 0xfc, 0x2f, 0xc4, 0xa1, 0x21,
        0xee, 0x7d, 0xbc, 0xda, 0x5a, 0xa4, 0xa2, 0xb9, 0x68, 0x87, 0x36, 0xba, 0x53, 0x9e, 0x14,
        0x4e, 0x76, 0x5c, 0xba, 0x79, 0x3d, 0x0f, 0xe5, 0x99, 0x1c, 0x27, 0xfc, 0xaf, 0x10, 0x63,
        0x87, 0x68, 0x0e, 0x3e, 0x6e, 0xaa, 0xf3, 0xdf, 0x76, 0x7e, 0x02, 0x9a, 0x41, 0x96, 0xa1,
        0x6c, 0xbb, 0x67, 0xee, 0x0c, 0xad, 0x72, 0x65, 0xf1, 0x70, 0xb0, 0x39, 0x9b, 0x54, 0x5f,
        0xd7, 0x6c, 0xc5, 0x9a, 0x90, 0x53, 0x18, 0xde, 0x5e, 0x62, 0x89, 0xb9, 0x2f, 0x66, 0x59,
        0x3a, 0x3d, 0x10, 0xeb, 0xa5, 0x99, 0xf6, 0x21, 0x7d, 0xf2, 0x7b, 0x42, 0x15, 0x1c, 0x55,
        0x79, 0x15, 0xaa, 0xa4, 0x17, 0x2e, 0x48, 0xc3, 0xa8, 0x36, 0xf5, 0x1a, 0x97, 0xce, 0xbd,
        0x72, 0xef, 0x1d, 0x50, 0x5b, 0xb1, 0x60, 0x0a, 0x5c, 0x0b, 0xa6, 0x21, 0x38, 0x28, 0x4e,
        0x89, 0x33, 0x1d, 0xb5, 0x7e, 0x5c, 0xf1, 0x6b, 0x2c, 0xbd, 0xad, 0x84, 0xb2, 0x8e, 0x96,
        0xe2, 0x30, 0xe7, 0x54, 0xb8, 0xc9, 0x70, 0xcb, 0x10, 0x30, 0x63, 0x90, 0xf4, 0x45, 0x64,
        0x93, 0x09, 0x38, 0x6a, 0x47, 0x58, 0x31, 0x04, 0x1a, 0x18, 0x04, 0x1a, 0xe0, 0xd7, 0x0b,
        0x3c, 0xbe, 0x2a, 0x9c, 0xec, 0xcc, 0x0d, 0x0c, 0xed, 0xde, 0x54, 0xbc, 0xe6, 0x93, 0x59,
        0xfc,
    ];

    fn bin(bytes: &[u8]) -> *mut BigNum {
        // SAFETY: `bytes` is readable for its length; the destination is NULL, so
        // `BN_bin2bn` allocates.
        unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len() as c_int, ptr::null_mut()) }
    }

    /// `test/ffc_internal_test.c`'s `ffc_params_validate_pq_test`, in the crate's terms: the
    /// authority's known-good 2048/224 pair validates with its own seed and counter, and three
    /// wrong inputs each refuse with a **different, named** reason.
    #[test]
    fn a_known_good_pair_validates_and_three_wrong_inputs_refuse_distinctly() {
        let mut p = Params::new();
        // SAFETY: the object is live and owned by this test.
        unsafe {
            let bp = bin(&P_2048_224_SHA224);
            let bq = bin(&Q_2048_224_SHA224);
            assert!(!bp.is_null() && !bq.is_null());

            /* No p: the validator answers FAILED without touching res. */
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), bq, ptr::null_mut());
            ossl_ffc_params_set_flags(p.as_mut(), FFC_PARAM_FLAG_VALIDATE_PQ);
            ossl_ffc_set_digest(p.as_mut(), c"SHA224".as_ptr(), ptr::null());
            let mut res: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res, -1, "a missing p leaves res untouched");

            /* The valid case: the seed chain reproduces p at the recorded counter. */
            ossl_ffc_params_set0_pqg(p.as_mut(), bp, ptr::null_mut(), ptr::null_mut());
            ossl_ffc_params_set_validate_params(
                p.as_mut(),
                SEED_2048_224_SHA224.as_ptr(),
                SEED_2048_224_SHA224.len(),
                COUNTER_2048_224_SHA224,
            );
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            assert_eq!(res, 0);

            /* A wrong counter: the chain finds a p, but not this one. */
            ossl_ffc_params_set_validate_params(
                p.as_mut(),
                SEED_2048_224_SHA224.as_ptr(),
                SEED_2048_224_SHA224.len(),
                1,
            );
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_ne!(res, 0);

            /* A seed one byte short: `seedlen * 8 < N`, refused before any arithmetic. */
            ossl_ffc_params_set_validate_params(
                p.as_mut(),
                SEED_2048_224_SHA224.as_ptr(),
                SEED_2048_224_SHA224.len() - 1,
                COUNTER_2048_224_SHA224,
            );
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res, FFC_CHECK_INVALID_SEED_SIZE);

            /* The seed with its last byte changed: it does not produce a prime q. */
            ossl_ffc_params_set_validate_params(
                p.as_mut(),
                BAD_SEED_2048_224_SHA224.as_ptr(),
                BAD_SEED_2048_224_SHA224.len(),
                COUNTER_2048_224_SHA224,
            );
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res, FFC_CHECK_Q_NOT_PRIME);
        }
    }

    /// The L/N pair test is **type-dependent**, and the DH refusal happens before any arithmetic
    /// on `q`: a 3072/256 pair is a valid DSA pair on this profile
    /// (`L >= 3072 && N >= 256`) and is not in the DH table (which is `1024/160` and
    /// `2048/224|256`), so the same object answers `FFC_CHECK_BAD_LN_PAIR` as DH and gets past
    /// the pair test as DSA.
    ///
    /// The object is built synthetically — `p = 2^3071`, `q = 2^255` — because the branch under
    /// test reads only `BN_num_bits` of the two. That is the claim: the DH refusal is the *width*
    /// test and nothing else.
    #[test]
    fn the_ln_pair_test_is_type_dependent() {
        let mut p = Params::new();
        let seed = [0x11u8; 32];
        // SAFETY: the object is live and owned by this test.
        unsafe {
            let bp = BN_new();
            let bq = BN_new();
            assert!(BN_lshift(bp, BN_value_one(), 3071) != 0);
            assert!(BN_lshift(bq, BN_value_one(), 255) != 0);
            assert_eq!(BN_num_bits(bp), 3072);
            assert_eq!(BN_num_bits(bq), 256);

            ossl_ffc_params_set0_pqg(p.as_mut(), bp, bq, ptr::null_mut());
            ossl_ffc_params_set_flags(p.as_mut(), FFC_PARAM_FLAG_VALIDATE_PQ);
            ossl_ffc_set_digest(p.as_mut(), c"SHA-256".as_ptr(), ptr::null());
            ossl_ffc_params_set_validate_params(p.as_mut(), seed.as_ptr(), seed.len(), 1);

            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res, FFC_CHECK_BAD_LN_PAIR, "3072/256 is not a DH pair");

            /* The same object as DSA gets past the pair test; the refusal is a later one. */
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_ne!(res, FFC_CHECK_BAD_LN_PAIR);
            assert!(
                res == FFC_CHECK_Q_MISMATCH || res == FFC_CHECK_Q_NOT_PRIME,
                "the seed chain fails on the supplied q, one way or the other; got {res:#x}"
            );
        }
    }

    /// `simple_validate` is a **boolean** over a *rewritten copy*. The group is the authority's
    /// `dsa_2048_224_sha256` triple, whose `g` is that subgroup's own generator, so the
    /// accepting case is an assertion about the authority's numbers.
    ///
    /// The rewritten copy is what the `VALIDATE_LEGACY` arm shows from the other side: the copy's
    /// `VALIDATE_LEGACY` is cleared, so the flag can only be read from the *caller's* object —
    /// setting it there switches the validator and the same group is still accepted.
    #[test]
    fn simple_validate_is_a_boolean_over_a_rewritten_copy() {
        let mut p = Params::new();
        // SAFETY: the object is live and owned by this test.
        unsafe {
            /* A NULL object answers 0 without a validator ever running. */
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    ptr::null(),
                    FFC_PARAM_TYPE_DSA,
                    ptr::null_mut(),
                ),
                0
            );

            /* The authority's own group, `g` unset: the copy's forced VALIDATE_G makes the
             * missing g the refusal, whatever the caller's flags say. */
            let bp = bin(&P_2048_224_SHA256);
            let bq = bin(&Q_2048_224_SHA256);
            ossl_ffc_params_set0_pqg(p.as_mut(), bp, bq, ptr::null_mut());
            ossl_ffc_params_set_flags(p.as_mut(), 0);
            ossl_ffc_set_digest(p.as_mut(), c"SHA256".as_ptr(), ptr::null());
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                0
            );
            assert_eq!(res, FFC_CHECK_INVALID_G);

            /* With the authority's own generator the partial check accepts. */
            let bg = bin(&G_2048_224_SHA256);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), ptr::null_mut(), bg);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                1
            );
            assert_eq!(res, 0, "the generator is verifiable, so no error bit");

            /* `g + 1` is in range and no longer of order q. */
            let bg_plus = BN_dup(bg);
            assert!(BN_add_word(bg_plus, 1) != 0);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), ptr::null_mut(), bg_plus);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            /* `g = 1` is the first of the two range refusals. */
            let one = BN_new();
            assert!(BN_set_word(one, 1) != 0);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), ptr::null_mut(), one);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            /* `g = p` is the second. */
            let bp2 = BN_dup((*p.as_ref()).p);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), ptr::null_mut(), bp2);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            /* Restore a real g, then set the caller's VALIDATE_LEGACY: the 186-2 validator is
             * selected from the caller's flags, and it accepts the same group. */
            let bg = bin(&G_2048_224_SHA256);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), ptr::null_mut(), bg);
            ossl_ffc_params_set_flags(p.as_mut(), FFC_PARAM_FLAG_VALIDATE_LEGACY);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res,
                ),
                1,
                "the legacy flag switches the validator and the group is still accepted"
            );

            /* `res == NULL` is replaced by a local, so this must not fault. */
            let _ = ossl_ffc_params_simple_validate(
                ptr::null_mut(),
                p.as_ref(),
                FFC_PARAM_TYPE_DSA,
                ptr::null_mut(),
            );
        }
    }

    /// The 186-2 and 186-4 entry points' **distinct refusals**: the 186-2 one writes
    /// `FFC_CHECK_INVALID_PQ` into `res`, the 186-4 one leaves it alone. That difference is the
    /// whole of the observable contract of their NULL arms.
    #[test]
    fn the_two_validate_entry_points_refuse_differently() {
        let mut p = Params::new();
        // SAFETY: the object is live and owned by this test.
        unsafe {
            let mut res_4: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    ptr::null(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_4,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res_4, -1, "the 186-4 refusal does not write res");

            let mut res_2: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_validate(
                    ptr::null_mut(),
                    ptr::null(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_2,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res_2, FFC_CHECK_INVALID_PQ, "the 186-2 refusal writes res");

            /* The same for a live object with no p, and two objects with p but no q. */
            let mut res_4: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_4_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_4,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res_4, -1);

            let bp = bin(&[23u8]);
            ossl_ffc_params_set0_pqg(p.as_mut(), bp, ptr::null_mut(), ptr::null_mut());
            let mut res_2: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_2,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res_2, FFC_CHECK_INVALID_PQ);

            let bq = bin(&[11u8]);
            ossl_ffc_params_set0_pqg(p.as_mut(), ptr::null_mut(), bq, ptr::null_mut());
            let mut res_2: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_2,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(
                res_2, FFC_CHECK_INVALID_Q_VALUE,
                "with both p and q set the 186-2 verifier reaches the digest choice, and \
                 N = 4 has no default digest"
            );

            /* Name the digest and the next refusal is the one behind it: `L = 5 < 512`. */
            ossl_ffc_set_digest(p.as_mut(), c"SHA-1".as_ptr(), ptr::null());
            let mut res_2: c_int = -1;
            assert_eq!(
                ossl_ffc_params_FIPS186_2_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_2,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_FAILED
            );
            assert_eq!(res_2, FFC_CHECK_BAD_LN_PAIR);
        }
    }

    /// `full_validate`'s arms, and the one that carries the primality tests.
    ///
    /// The construction is the interesting part. A *generated* 2048/256 DH group is a genuine
    /// FIPS 186-4 group, so `simple_validate` accepts it; clearing the seed then makes
    /// `full_validate` take the no-seed arm, where both `BN_check_prime` answers must be 1 — an
    /// assertion that the arm ran and both primes held.
    ///
    /// A second object carries the same `p` and `g` with **`q` doubled**, which isolates the
    /// *refusing* `q` test. `p` is an odd prime and `q` an odd prime, so `e = (p - 1) / q` is
    /// even and `2q` divides `p - 1`; `g^(2q) = (g^q)^2 = 1`, so the `g` check still passes; `N`
    /// becomes 257, still a valid **DSA** pair (`L >= 2048 && N >= 224`), so the only thing left
    /// for the validator to notice is that `2q` is even. The `p` test is then skipped, which is
    /// the `ret != 0` guard.
    #[test]
    fn full_validate_branches_on_the_seed_and_runs_both_prime_tests() {
        let mut p = Params::new();
        let mut doubled = Params::new();
        let mut res: c_int = -1;
        // SAFETY: both objects are live and owned by this test.
        unsafe {
            assert_eq!(
                ossl_ffc_params_full_validate(
                    ptr::null_mut(),
                    ptr::null(),
                    FFC_PARAM_TYPE_DH,
                    ptr::null_mut(),
                ),
                0
            );
            assert_eq!(
                ossl_ffc_params_full_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res,
                ),
                0,
                "an empty object fails the simple check, so no prime test runs"
            );

            assert_eq!(
                ossl_ffc_params_FIPS186_4_generate(
                    ptr::null_mut(),
                    p.as_mut(),
                    FFC_PARAM_TYPE_DH,
                    2048,
                    256,
                    &raw mut res,
                    ptr::null_mut(),
                ),
                FFC_PARAM_RET_STATUS_SUCCESS
            );
            /* The generated object carries its seed and the default `VALIDATE_PQG` flags, so
             * this is the *delegating* arm and the answer is the tri-state: the p/q chain is
             * validated and `g` is only partially verifiable, because generation left `gindex`
             * at `FFC_UNVERIFIABLE_GINDEX`. */
            let mut res_del: c_int = 0;
            assert_eq!(
                ossl_ffc_params_full_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_del,
                ),
                FFC_PARAM_RET_STATUS_UNVERIFIABLE_G
            );

            /* Now double q. `2q` is composite (even) and still divides `p - 1`. */
            let doubled_p = BN_dup((*p.as_ref()).p);
            let doubled_q = BN_dup((*p.as_ref()).q);
            let doubled_g = BN_dup((*p.as_ref()).g);
            assert!(BN_lshift1(doubled_q, doubled_q) != 0);
            assert_eq!(BN_num_bits(doubled_q), 257);
            ossl_ffc_params_set0_pqg(doubled.as_mut(), doubled_p, doubled_q, doubled_g);
            ossl_ffc_set_digest(doubled.as_mut(), c"SHA-256".as_ptr(), ptr::null());
            assert!((*doubled.as_ref()).seed.is_null());

            /* `simple_validate` alone still accepts: the g check sees (g^q)^2 == 1. */
            let mut res_simple: c_int = 0;
            assert_eq!(
                ossl_ffc_params_simple_validate(
                    ptr::null_mut(),
                    doubled.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res_simple,
                ),
                1
            );

            /* `full_validate` refuses, on the primality of q. */
            let mut res_q: c_int = 0;
            assert_eq!(
                ossl_ffc_params_full_validate(
                    ptr::null_mut(),
                    doubled.as_ref(),
                    FFC_PARAM_TYPE_DSA,
                    &raw mut res_q,
                ),
                0,
                "2q is composite, so the q test refuses and the p test is skipped"
            );

            /* Clear the first object's seed and take the no-seed arm on a genuine group: both
             * primality tests run and both must answer 1. */
            assert_eq!(ossl_ffc_params_set_seed(p.as_mut(), ptr::null(), 0), 1);
            assert!((*p.as_ref()).seed.is_null());
            ossl_ffc_set_digest(p.as_mut(), c"SHA-256".as_ptr(), ptr::null());
            let mut res_noseed: c_int = 0;
            assert_eq!(
                ossl_ffc_params_full_validate(
                    ptr::null_mut(),
                    p.as_ref(),
                    FFC_PARAM_TYPE_DH,
                    &raw mut res_noseed,
                ),
                1,
                "the generated p and q are prime, so both BN_check_prime calls answered 1"
            );
        }
    }

    /// `ossl_ffc_params_validate_unverifiable_g`'s two refusals and its success, on a group
    /// whose arithmetic is checkable by hand: `p = 23`, `q = 11`, and `2^11 = 2048 = 89 * 23 + 1`,
    /// so `g = 2` is a genuine element of order 11 in `Z_23^*`.
    ///
    /// `g = 1` and `g = 23` are the two range refusals; `g = 5` is in range and
    /// `5^11 = 48828125 = 2122961 * 23 + 22`, so it is the order refusal. The two causes share
    /// one error bit, which is exactly what this test records.
    #[test]
    fn the_unverifiable_g_check_is_range_then_order() {
        let bp = bin(&[23u8]);
        let bq = bin(&[11u8]);
        let bg = bin(&[2u8]);
        // SAFETY: every pointer below is one of this test's own objects.
        unsafe {
            let ctx = BN_CTX_new_ex(ptr::null_mut());
            assert!(!ctx.is_null());
            BN_CTX_start(ctx);
            let tmp = BN_CTX_get(ctx);
            assert!(!tmp.is_null());

            let mont = BN_MONT_CTX_new();
            assert!(!mont.is_null());
            assert_eq!(BN_MONT_CTX_set(mont, bp, ctx), 1);

            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_validate_unverifiable_g(ctx, mont, bp, bq, bg, tmp, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            let one = bin(&[1u8]);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_validate_unverifiable_g(ctx, mont, bp, bq, one, tmp, &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_validate_unverifiable_g(ctx, mont, bp, bq, bp, tmp, &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            let five = bin(&[5u8]);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_params_validate_unverifiable_g(ctx, mont, bp, bq, five, tmp, &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_NOT_SUITABLE_GENERATOR);

            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            BN_MONT_CTX_free(mont);
            BN_free(one);
            BN_free(five);
            BN_free(bp);
            BN_free(bq);
            BN_free(bg);
        }
    }
}
