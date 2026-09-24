//! Phase 8 — `crypto/ffc/ffc_key_validate.c`: FFC public- and private-key validation.
//!
//! Three functions, and the first is the whole of the other two: SP800-56A r3 §5.6.2.3.1's
//! partial public-key check (`2 <= pub <= p - 1`) is `ossl_ffc_validate_public_key_partial`, the
//! full check adds `pub^q mod p == 1`, and the private-key check is a range test against the
//! caller's own upper bound.
//!
//! The DH callers are `crypto/dh/dh_check.c:287` (`DH_check_pub_key`'s full check), `:297`
//! (`DH_check_pub_key_partial`, which the provider's `dh_public_check`-style paths use) and
//! `:342` (`DH_check_priv_key`). None of them is in this slice — `dh_check.c` is later in 8.5 —
//! but the unit is whole here because a half-transcribed validation file is precisely the shape
//! the gate turns into findings.
//!
//! ## The answer shapes differ, and that is the contract
//!
//! * `ossl_ffc_validate_public_key_partial` and `ossl_ffc_validate_public_key` answer **1 with
//!   `*ret` set** for a NULL parameter — the check "succeeded" in the sense that it ran and
//!   reported, and it is the caller's job to read `*ret`. Both also set `*ret = 0` as their
//!   *first* act, so `ret` must be a valid pointer on every path including the NULL one.
//! * `ossl_ffc_validate_private_key` answers **0 with `*ret` set** for a NULL parameter, and
//!   `goto err` for its range failures — so "the check ran and the value is bad" and "I could
//!   not run the check" are distinguished by the return, not by `*ret`.
//!
//! ## A 2^N upper bound is a supported caller
//!
//! `ossl_ffc_validate_private_key`'s header comment says the upper bound "is normally
//! `params->q` but can be `2^N` for approved safe prime groups": for a group whose `q` is
//! `(p - 1) / 2`, a private key in `[1, q)` is *not* what `ossl_ffc_generate_private_key`
//! produces when the caller asked for `N < qbits` — it produces `[1, 2^N)`. The two are used
//! together by `dh_key.c`'s two arms, which is why this file's function takes the bound rather
//! than reading it off the params.

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::{BN_cmp, BN_mod_exp, BN_sub_word};
use crate::bn::bignum::{BN_copy, BN_is_one, BN_set_word, BN_value_one, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};

use super::{
    FfcParams, FFC_ERROR_PASSED_NULL_PARAM, FFC_ERROR_PRIVKEY_TOO_LARGE,
    FFC_ERROR_PRIVKEY_TOO_SMALL, FFC_ERROR_PUBKEY_INVALID, FFC_ERROR_PUBKEY_TOO_LARGE,
    FFC_ERROR_PUBKEY_TOO_SMALL,
};

/// `int ossl_ffc_validate_public_key_partial(const FFC_PARAMS *params,`
/// `const BIGNUM *pub_key, int *ret)` — `crypto/ffc/ffc_key_validate.c:19-57`.
///
/// "See SP800-56Ar3 Section 5.6.2.3.1 : FFC Partial public key validation. To only be used with
/// ephemeral FFC public keys generated using the approved safe-prime groups. (Checks that the
/// public key is in the range `[2, p - 1]`". The closing bracket is the authority's.
///
/// The context is created with **`BN_CTX_new_ex(NULL)`** — a NULL library context, not the
/// caller's — because a range check needs no provider.
///
/// The two comparisons are one-sided on purpose: `BN_cmp(pub, 1) <= 0` catches 0, 1 and every
/// negative value, and `BN_cmp(pub, p - 1) >= 0` catches `p - 1` and above. So `p - 1` is
/// **too large**, not "the largest valid": the valid range is `[2, p - 2]`.
///
/// # Safety
///
/// `params` must be NULL or live with a NULL-or-live `p`; `pub_key` must be NULL or live; `ret`
/// must be writable and **not NULL** — the authority writes it before its first test.
pub(crate) unsafe fn ossl_ffc_validate_public_key_partial(
    params: *const FfcParams,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    let mut ok: c_int = 0;
    let ctx: *mut BnCtx;

    // SAFETY: `ret` is writable per this function's `# Safety` section.
    unsafe {
        *ret = 0;
        if params.is_null() || pub_key.is_null() || (*params).p.is_null() {
            *ret = FFC_ERROR_PASSED_NULL_PARAM;
            return 1;
        }

        ctx = BN_CTX_new_ex(ptr::null_mut());
        if ctx.is_null() {
            return ok;
        }

        BN_CTX_start(ctx);
        let tmp = BN_CTX_get(ctx);
        /* Step(1): Verify pub_key >= 2 */
        if tmp.is_null() || BN_set_word(tmp, 1) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }
        if BN_cmp(pub_key, tmp) <= 0 {
            *ret |= FFC_ERROR_PUBKEY_TOO_SMALL;
        }
        /* Step(1): Verify pub_key <=  p-2 */
        if BN_copy(tmp, (*params).p).is_null() || BN_sub_word(tmp, 1) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }
        if BN_cmp(pub_key, tmp) >= 0 {
            *ret |= FFC_ERROR_PUBKEY_TOO_LARGE;
        }
        ok = 1;

        /* The authority's `err:` label. */
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ok
}

/// `int ossl_ffc_validate_public_key(const FFC_PARAMS *params, const BIGNUM *pub_key,`
/// `int *ret)` — `crypto/ffc/ffc_key_validate.c:62-94`.
///
/// "See SP800-56Ar3 Section 5.6.2.3.1 : FFC Full public key validation." The partial check
/// first, and then `pub^q mod p == 1` **only when the range check reported no problem and `q` is
/// set** — so a public key that is out of range is never exponentiated, and a group with no `q`
/// (a caller-built DH group) is accepted on the range alone. The exponentiation is `BN_mod_exp`,
/// not a Montgomery form: there is no modulus precomputation to reuse here.
///
/// The non-one result sets `FFC_ERROR_PUBKEY_INVALID` and the return is still 1 — the answer to
/// "did the check run" is yes.
///
/// # Safety
///
/// `params` must be NULL or live with NULL-or-live `p` and `q`; `pub_key` must be NULL or live;
/// `ret` must be writable and not NULL.
pub(crate) unsafe fn ossl_ffc_validate_public_key(
    params: *const FfcParams,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    let mut ok: c_int = 0;
    let ctx: *mut BnCtx;

    // SAFETY: `params`, `pub_key` and `ret` are as the partial check's contract requires.
    unsafe {
        if ossl_ffc_validate_public_key_partial(params, pub_key, ret) == 0 {
            return 0;
        }

        if *ret == 0 && !(*params).q.is_null() {
            ctx = BN_CTX_new_ex(ptr::null_mut());
            if ctx.is_null() {
                return ok;
            }
            BN_CTX_start(ctx);
            let tmp = BN_CTX_get(ctx);

            /* Check pub_key^q == 1 mod p */
            if tmp.is_null() || BN_mod_exp(tmp, pub_key, (*params).q, (*params).p, ctx) == 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ok;
            }
            if BN_is_one(tmp) == 0 {
                *ret |= FFC_ERROR_PUBKEY_INVALID;
            }

            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
        }

        ok = 1;
    }
    ok
}

/// `int ossl_ffc_validate_private_key(const BIGNUM *upper, const BIGNUM *priv, int *ret)` —
/// `crypto/ffc/ffc_key_validate.c:102-124`.
///
/// "See SP800-56Ar3 Section 5.6.2.1.2: Owner assurance of Private key validity. Verifies
/// priv_key is in the range `[1..upper-1]`. The passed in value of upper is normally
/// `params->q` but can be `2^N` for approved safe prime groups. Note: This assumes that the
/// domain parameters are valid."
///
/// Every failure is a `goto err` with the return left 0: a NULL argument sets
/// `FFC_ERROR_PASSED_NULL_PARAM`, a value below 1 sets `FFC_ERROR_PRIVKEY_TOO_SMALL` and a value
/// at or above `upper` sets `FFC_ERROR_PRIVKEY_TOO_LARGE`, and **the first failure returns
/// immediately** rather than accumulating bits — so the word carries at most one of the three.
///
/// # Safety
///
/// `upper` and `priv` must each be NULL or live; `ret` must be writable and not NULL.
pub(crate) unsafe fn ossl_ffc_validate_private_key(
    upper: *const BigNum,
    priv_: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    let mut ok: c_int = 0;

    // SAFETY: `upper` and `priv_` are NULL or live and `ret` is writable per this function's
    // `# Safety` section.
    unsafe {
        *ret = 0;

        if priv_.is_null() || upper.is_null() {
            *ret = FFC_ERROR_PASSED_NULL_PARAM;
            return ok;
        }
        if BN_cmp(priv_, BN_value_one()) < 0 {
            *ret |= FFC_ERROR_PRIVKEY_TOO_SMALL;
            return ok;
        }
        if BN_cmp(priv_, upper) >= 0 {
            *ret |= FFC_ERROR_PRIVKEY_TOO_LARGE;
            return ok;
        }
        ok = 1;
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::bignum::{BN_free, BN_new, BN_set_negative};

    /// `p = 23`, `q = 11`, `g = 2` — a **safe prime** with a hand-checkable subgroup:
    /// `2^11 = 2048 = 89 * 23 + 1`, so 2 generates the order-11 subgroup of `Z_23^*`, and
    /// `21 = p - 2` is `-2`, whose 11th power is `-1 != 1`. That makes every answer below
    /// arithmetic rather than convention.
    struct Tiny {
        params: FfcParams,
    }

    impl Tiny {
        fn new() -> Self {
            let mut params = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `params` is live and writable; each object is this test's own and its
            // ownership passes to the params.
            let params = unsafe {
                crate::ffc::params::ossl_ffc_params_init(params.as_mut_ptr());
                let p = BN_new();
                let q = BN_new();
                let g = BN_new();
                assert!(BN_set_word(p, 23) != 0);
                assert!(BN_set_word(q, 11) != 0);
                assert!(BN_set_word(g, 2) != 0);
                let mut params = params.assume_init();
                crate::ffc::params::ossl_ffc_params_set0_pqg(&raw mut params, p, q, g);
                params
            };
            Tiny { params }
        }

        fn as_ref(&self) -> *const FfcParams {
            &raw const self.params
        }
    }

    impl Drop for Tiny {
        fn drop(&mut self) {
            // SAFETY: `self.params` is live and this test owns it.
            unsafe { crate::ffc::params::ossl_ffc_params_cleanup(&raw mut self.params) };
        }
    }

    fn word(v: u64) -> *mut BigNum {
        // SAFETY: `BN_new` answers NULL or a fresh object.
        unsafe {
            let b = BN_new();
            assert!(!b.is_null());
            assert!(BN_set_word(b, v) != 0);
            b
        }
    }

    /// The partial check's two range refusals, its acceptances, and the three NULL arms that
    /// answer **1 with `*ret` set**.
    #[test]
    fn the_partial_public_check_reports_through_ret_and_answers_one() {
        let tiny = Tiny::new();
        // SAFETY: every pointer below is this test's own and `ret` is a local.
        unsafe {
            let mut res: c_int = -1;

            /* The three NULL arms answer 1 and set PASSED_NULL_PARAM. */
            assert_eq!(
                ossl_ffc_validate_public_key_partial(ptr::null(), ptr::null(), &raw mut res),
                1
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            let two = word(2);
            assert_eq!(
                ossl_ffc_validate_public_key_partial(tiny.as_ref(), ptr::null(), &raw mut res),
                1
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            let empty = core::mem::MaybeUninit::<FfcParams>::zeroed();
            let empty = empty.assume_init();
            assert_eq!(
                ossl_ffc_validate_public_key_partial(&raw const empty, two, &raw mut res),
                1
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            /* 0 and 1 are too small; so is a negative value. */
            let zero = word(0);
            let one = word(1);
            let minus = word(1);
            BN_set_negative(minus, 1);
            for small in [zero, one, minus] {
                let mut res: c_int = 0;
                assert_eq!(
                    ossl_ffc_validate_public_key_partial(tiny.as_ref(), small, &raw mut res),
                    1
                );
                assert_eq!(res, FFC_ERROR_PUBKEY_TOO_SMALL);
            }

            /* 2 is the smallest accepted value. */
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key_partial(tiny.as_ref(), two, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            /* 22 = p - 1 is too large, and so is 23 = p. */
            let pm1 = word(22);
            let p = word(23);
            for large in [pm1, p] {
                let mut res: c_int = 0;
                assert_eq!(
                    ossl_ffc_validate_public_key_partial(tiny.as_ref(), large, &raw mut res),
                    1
                );
                assert_eq!(res, FFC_ERROR_PUBKEY_TOO_LARGE);
            }

            /* 21 = p - 2 is the largest accepted value. */
            let pm2 = word(21);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key_partial(tiny.as_ref(), pm2, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            for b in [two, zero, one, minus, pm1, p, pm2] {
                BN_free(b);
            }
        }
    }

    /// The full check adds `pub^q mod p == 1`, and it is reached **only** when the range check
    /// reported no problem. On the tiny group `2^11 == 1` and `21^11 == -1`, so the two answers
    /// are the arithmetic.
    #[test]
    fn the_full_public_check_adds_the_order_test() {
        let tiny = Tiny::new();
        // SAFETY: every pointer below is this test's own.
        unsafe {
            /* 2 is in range and of order 11. */
            let two = word(2);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key(tiny.as_ref(), two, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            /* 3 is a square mod 23 (7^2 = 49 = 3), so 3^11 == 1 as well. */
            let three = word(3);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key(tiny.as_ref(), three, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            /* 21 = -2 is in range and 21^11 = -1: in range, wrong order. */
            let pm2 = word(21);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key(tiny.as_ref(), pm2, &raw mut res),
                1
            );
            assert_eq!(res, FFC_ERROR_PUBKEY_INVALID);

            /* And an out-of-range value is *not* exponentiated: the answer is the range bit
             * alone, never range|invalid. */
            let one = word(1);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key(tiny.as_ref(), one, &raw mut res),
                1
            );
            assert_eq!(res, FFC_ERROR_PUBKEY_TOO_SMALL);

            /* A group with no q is accepted on the range alone. */
            let noq = core::mem::MaybeUninit::<FfcParams>::zeroed();
            let mut noq = noq.assume_init();
            crate::ffc::params::ossl_ffc_params_init(&raw mut noq);
            let p = word(23);
            let g = word(2);
            crate::ffc::params::ossl_ffc_params_set0_pqg(&raw mut noq, p, ptr::null_mut(), g);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_public_key(&raw const noq, pm2, &raw mut res),
                1
            );
            assert_eq!(res, 0, "no q means no order test");
            crate::ffc::params::ossl_ffc_params_cleanup(&raw mut noq);

            for b in [two, three, pm2, one] {
                BN_free(b);
            }
        }
    }

    /// The private check: the range is `[1, upper)`, every failure answers **0**, and the three
    /// causes are distinguishable by `*ret` because the first failure returns immediately.
    #[test]
    fn the_private_check_answers_zero_and_one_cause_at_a_time() {
        let upper = word(11);
        // SAFETY: every pointer below is this test's own.
        unsafe {
            let mut res: c_int = -1;

            /* A NULL bound or value answers 0 with PASSED_NULL_PARAM. */
            assert_eq!(
                ossl_ffc_validate_private_key(ptr::null(), ptr::null(), &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            let one = word(1);
            assert_eq!(
                ossl_ffc_validate_private_key(upper, ptr::null(), &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            assert_eq!(
                ossl_ffc_validate_private_key(ptr::null(), one, &raw mut res),
                0
            );
            assert_eq!(res, FFC_ERROR_PASSED_NULL_PARAM);

            /* 0 and a negative value are too small. */
            let zero = word(0);
            let minus = word(1);
            BN_set_negative(minus, 1);
            for small in [zero, minus] {
                let mut res: c_int = 0;
                assert_eq!(ossl_ffc_validate_private_key(upper, small, &raw mut res), 0);
                assert_eq!(res, FFC_ERROR_PRIVKEY_TOO_SMALL);
            }

            /* 1 is the smallest accepted value; the bound itself is too large. */
            let mut res: c_int = 0;
            assert_eq!(ossl_ffc_validate_private_key(upper, one, &raw mut res), 1);
            assert_eq!(res, 0);

            let bound = word(11);
            let mut res: c_int = 0;
            assert_eq!(ossl_ffc_validate_private_key(upper, bound, &raw mut res), 0);
            assert_eq!(res, FFC_ERROR_PRIVKEY_TOO_LARGE);

            /* `upper - 1` is the largest accepted value. */
            let ten = word(10);
            let mut res: c_int = 0;
            assert_eq!(ossl_ffc_validate_private_key(upper, ten, &raw mut res), 1);
            assert_eq!(res, 0);

            /* `2^N` is a supported bound, and the same value can be in range under one and
             * out of range under the other. */
            let two_pow_4 = word(16);
            let fifteen = word(15);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_private_key(two_pow_4, fifteen, &raw mut res),
                1
            );
            assert_eq!(res, 0);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_private_key(two_pow_4, bound, &raw mut res),
                1
            );
            assert_eq!(
                res, 0,
                "11 is in range under 2^4 even though it is not under q = 11"
            );

            for b in [upper, one, zero, minus, bound, ten, two_pow_4, fifteen] {
                BN_free(b);
            }
        }
    }
}
