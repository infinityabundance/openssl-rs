//! Phase 8 — `crypto/ffc/ffc_key_generate.c`: FFC private-key generation.
//!
//! One function, sixty lines, and it is the last link of the chain Phase 8.4's blocker ran
//! through: `crypto/dh/dh_key.c:320` and `:361` both call it, and its first callee is
//! `BN_priv_rand_range_ex` — which is why no key type's `generate_key` could land before the
//! random layer did (D286).
//!
//! ## The shape of the algorithm, and the one step that is not an obvious rejection loop
//!
//! SP800-56A r3 §5.6.1.1.4 ("key pair generation by testing candidates") generates a private key
//! in `[1, min(2^N - 1, q - 1)]`. The authority's transcription is worth reading twice because
//! its *comparison* is one step tighter than that interval suggests:
//!
//! * `c = random[0 .. 2^N - 1]`, then `priv = c + 1`, so `priv` is in `[1, 2^N]` — note the
//!   inclusive upper end, which the next step trims.
//! * `M = min(2^N, q)` and the loop repeats **while `priv >= M`**, so the accepted interval is
//!   `[1, M - 1]`. With `M = 2^N` that is `[1, 2^N - 1]`; with `M = q` it is `[1, q - 1]`.
//!   The comment above the loop says "loop if c > M - 2 (i.e. c + 1 >= M)", which is the same
//!   test on `c`.
//! * **The `N == 0` default is `params->keylength` when the group carries one, and `2 * s`
//!   otherwise.** `keylength` is the RFC 7919 private-key length of a named group
//!   (`ffc_dh.c`'s table), so a caller that asks for "the group's own length" gets 225 for
//!   ffdhe2048 rather than the 224 that `2 * s` would give — a difference of one bit that the
//!   authority's own `test/ffc_internal_test.c:650` asserts (`BN_num_bits(priv) <= 225`).
//!
//! ## The two refusals, and which one is not a `goto`
//!
//! The authority declares `two_powN = NULL` at the top and releases it on both exits, so `s == 0`
//! is `goto err` with a NULL release and `N < 2 * s || N > qbits` is a bare `return 0`. Neither
//! path has allocated anything, so the two are indistinguishable from outside; the first is
//! transcribed as the plain refusal it behaves as, and the second is the plain refusal it is,
//! with a comment at each site saying which arm of the authority's code it is.
//!
//! ## What the `q` of a named group is, because it sets the width of `N`
//!
//! For the FFDHE and MODP families `q` is `(p - 1) / 2` — a *2047*-bit number for ffdhe2048, not
//! the 224 or 256 bits a reader might assume from the group's name. `crypto/bn/bn_dh.c`defines
//! the constants that way and `ffc_dh.c`'s table points at them, so `N = BN_num_bits(q)` there is
//! 2047 and the interval `2s <= N <= qbits` is wide. The test below builds exactly that shape
//! from the authority's own 2048-bit prime, and the shape is load-bearing: with a 224-bit `q` the
//! only `N` a caller could pass is 224.

use core::ffi::c_int;

use crate::bn::arith::{BN_add_word, BN_cmp, BN_lshift};
use crate::bn::bignum::{BN_free, BN_new, BN_num_bits, BN_value_one, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::rand::BN_priv_rand_range_ex;

use super::FfcParams;

/// `int ossl_ffc_generate_private_key(BN_CTX *ctx, const FFC_PARAMS *params, int N, int s,`
/// `BIGNUM *priv)` — `crypto/ffc/ffc_key_generate.c:22-60`.
///
/// `ctx` "must be set up with a libctx (for fips mode)" — this crate's `BN_CTX` carries the
/// library context, and `BN_priv_rand_range_ex` reads it through `ossl_bn_get_libctx`.
///
/// `N` is the maximum bit length of the generated private key and `s` the security strength.
/// Both zero-sentinels are handled here rather than by the caller: `s == 0` is a hard refusal and
/// `N == 0` means "the group's own length, or twice the strength".
///
/// # Safety
///
/// `ctx` must be a live `BN_CTX`; `params` must be live with a live `q`; `priv` must be a live,
/// writable `BIGNUM`.
pub(crate) unsafe fn ossl_ffc_generate_private_key(
    ctx: *mut BnCtx,
    params: *const FfcParams,
    mut n: c_int,
    s: c_int,
    priv_: *mut BigNum,
) -> c_int {
    let mut ret: c_int = 0;
    // SAFETY: `params` is live and its `q` is live per this function's `# Safety` section. The
    // authority reads `qbits` before its first test, so a NULL `q` is a caller error there too.
    let qbits = unsafe { BN_num_bits((*params).q) };

    /* Deal with the edge cases where the value of N and/or s is not set */
    if s == 0 {
        /* The authority's `goto err` here releases a `two_powN` that is still NULL. */
        return 0;
    }
    if n == 0 {
        // SAFETY: `params` is live.
        n = unsafe {
            if (*params).keylength != 0 {
                (*params).keylength
            } else {
                2 * s
            }
        };
    }

    /* Step (2) : check range of N */
    if n < 2 * s || n > qbits {
        return 0;
    }

    // SAFETY: `BN_new` answers NULL or a fresh `BIGNUM`.
    let two_pow_n = unsafe { BN_new() };
    /* 2^N */
    // SAFETY: `two_pow_n` is NULL or live; `BN_value_one` is static storage this call only reads.
    if two_pow_n.is_null() || unsafe { BN_lshift(two_pow_n, BN_value_one(), n) } == 0 {
        // SAFETY: NULL or live, and `BN_free` accepts NULL.
        unsafe { BN_free(two_pow_n) };
        return ret;
    }

    /* Step (5) : M = min(2 ^ N, q) */
    // SAFETY: `two_pow_n` is live and `params->q` is live.
    let m = unsafe {
        if BN_cmp(two_pow_n, (*params).q) > 0 {
            (*params).q
        } else {
            two_pow_n
        }
    };

    loop {
        /* Steps (3, 4 & 7) :  c + 1 = 1 + random[0..2^N - 1] */
        // SAFETY: `priv_` is live and writable, `two_pow_n` is live, `ctx` is live.
        if unsafe { BN_priv_rand_range_ex(priv_, two_pow_n, 0, ctx) } == 0
            // SAFETY: `priv_` is live and writable.
            || unsafe { BN_add_word(priv_, 1) } == 0
        {
            break;
        }
        /* Step (6) : loop if c > M - 2 (i.e. c + 1 >= M) */
        // SAFETY: `priv_` is live and `m` is `two_pow_n` or `params->q`, both live.
        if unsafe { BN_cmp(priv_, m) } < 0 {
            ret = 1;
            break;
        }
    }

    /* The authority's `err:` label. */
    // SAFETY: `two_pow_n` is NULL or live and `BN_free` accepts NULL.
    unsafe { BN_free(two_pow_n) };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ptr;

    use crate::bn::arith::{BN_rshift1, BN_sub_word};
    use crate::bn::bignum::{BN_bin2bn, BN_dup, BN_set_word};
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
    use crate::ffc::key_validate::ossl_ffc_validate_private_key;
    use crate::ffc::params::{
        ossl_ffc_params_cleanup, ossl_ffc_params_init, ossl_ffc_params_set0_pqg,
    };

    /// A live `FFC_PARAMS` carrying a *safe-prime-shaped* group: the authority's own 2048-bit
    /// DSA prime with `q = (p - 1) / 2`, which is how `crypto/bn/bn_dh.c` defines the FFDHE and
    /// MODP families' `q`. That shape is what gives `N` room — `qbits` is 2047, not 224 — so the
    /// interval the authority's own test walks is reachable.
    ///
    /// The group is built from `test/ffc_internal_test.c`'s own prime rather than from a NID.
    /// That is a choice about *this test's* input, not about the crate: since D332 the
    /// named-group table is landed and `crate::dh::group_params::DH_new_by_nid` builds the
    /// same shape from a NID. The authority's own prime is kept here because the interval the
    /// test walks is the one `test/ffc_internal_test.c:650` asserts over *that* group.
    struct Group {
        params: FfcParams,
    }

    /// `dsa_2048_224_sha224_p` — `test/ffc_internal_test.c:33-56`.
    const P: [u8; 256] = [
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

    impl Group {
        fn new() -> Self {
            let mut params = core::mem::MaybeUninit::<FfcParams>::uninit();
            // SAFETY: `params` is live and writable; the initialiser writes every byte; each
            // `BIGNUM` is this test's own and its ownership passes to the params object.
            let params = unsafe {
                ossl_ffc_params_init(params.as_mut_ptr());
                let p = BN_bin2bn(P.as_ptr(), P.len() as c_int, ptr::null_mut());
                assert!(!p.is_null());
                let q = BN_dup(p);
                assert!(BN_sub_word(q, 1) != 0);
                assert!(BN_rshift1(q, q) != 0);
                let g = BN_new();
                assert!(BN_set_word(g, 2) != 0);
                let mut params = params.assume_init();
                ossl_ffc_params_set0_pqg(&raw mut params, p, q, g);
                params
            };
            Group { params }
        }

        fn as_ref(&self) -> *const FfcParams {
            &raw const self.params
        }

        fn as_mut(&mut self) -> *mut FfcParams {
            &raw mut self.params
        }
    }

    impl Drop for Group {
        fn drop(&mut self) {
            // SAFETY: `self.params` is a live object this test owns.
            unsafe { ossl_ffc_params_cleanup(&raw mut self.params) };
        }
    }

    /// `test/ffc_internal_test.c`'s `ffc_private_gen_test`, in the crate's terms: four refusals
    /// and four acceptances, and **every acceptance is checked by property** — the bit width and
    /// `ossl_ffc_validate_private_key`'s range answer. The output is random, so no value is
    /// asserted and none could be.
    #[test]
    fn private_key_generation_refuses_four_ways_and_always_lands_in_range() {
        let mut group = Group::new();
        // SAFETY: the group is live and owned by this test; every `BIGNUM` below is this test's.
        unsafe {
            let ctx = BN_CTX_new_ex(ptr::null_mut());
            assert!(!ctx.is_null());
            let priv_ = BN_new();
            assert!(!priv_.is_null());

            let qbits = BN_num_bits((*group.as_ref()).q);
            assert_eq!(qbits, 2047, "a safe-prime group's q is (p-1)/2");

            /* `N < 2 * s` with s = 112. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), 220, 112, priv_),
                0
            );
            /* `N > qbits`. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits + 1, 112, priv_),
                0
            );
            /* `s` must always be set. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits, 0, priv_),
                0
            );
            /* A negative `N` is also `N < 2 * s`. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), -1, 112, priv_),
                0
            );

            /* Accepted: `N == qbits`, the widest the group allows. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits, 112, priv_),
                1
            );
            assert!(BN_num_bits(priv_) <= qbits);
            assert!(BN_num_bits(priv_) >= 1);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_private_key((*group.as_ref()).q, priv_, &raw mut res),
                1
            );
            assert_eq!(res, 0);

            /* Accepted: `N = qbits / 2`, still `>= 2s`, and at most that wide. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits / 2, 112, priv_),
                1
            );
            assert!(BN_num_bits(priv_) <= qbits / 2);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_private_key((*group.as_ref()).q, priv_, &raw mut res),
                1
            );

            /* `N == 0` with no `keylength`: `2 * s` = 224. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), 0, 112, priv_),
                1
            );
            assert!(BN_num_bits(priv_) <= 224);
            let mut res: c_int = 0;
            assert_eq!(
                ossl_ffc_validate_private_key((*group.as_ref()).q, priv_, &raw mut res),
                1
            );

            /* `N == 0` with a `keylength`: it wins over `2 * s`, which is the ffdhe2048 case
             * where 225 > 224. */
            (*group.as_mut()).keylength = 275;
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), 0, 112, priv_),
                1
            );
            assert!(BN_num_bits(priv_) <= 275);
            /* But `keylength` still has to satisfy the range check: below `2s` it refuses. */
            (*group.as_mut()).keylength = 200;
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), 0, 112, priv_),
                0
            );
            /* And above `qbits` it refuses too. */
            (*group.as_mut()).keylength = qbits + 1;
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), 0, 112, priv_),
                0
            );
            (*group.as_mut()).keylength = 0;

            /* The accepted key is `>= 1`: subtracting one can reach zero and the *next*
             * generation is fresh, so the property is that every draw is in `[1, q)`. */
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits, 112, priv_),
                1
            );
            assert!(BN_sub_word(priv_, 1) != 0);
            assert_eq!(
                ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits, 112, priv_),
                1
            );
            assert!(BN_num_bits(priv_) >= 1);

            BN_free(priv_);
            BN_CTX_free(ctx);
        }
    }

    /// The bound is `2^N` when `2^N < q` and `q` when it is not, and the difference is
    /// observable: with `N` where `2^N <= q` the drawn key is **strictly less than `2^N`**, so
    /// no key can have more than `N` bits. That is the property a transcription that compared
    /// against `q` alone would break, and it is measured over eight independent draws because
    /// one draw could satisfy the weaker bound by luck.
    #[test]
    fn the_bound_is_twos_power_n_when_q_is_wider() {
        let group = Group::new();
        // SAFETY: the group and the context are this test's own objects.
        unsafe {
            let ctx = BN_CTX_new_ex(ptr::null_mut());
            assert!(!ctx.is_null());
            let priv_ = BN_new();
            assert!(!priv_.is_null());

            for n in [224, 256, 512, 1024] {
                for _ in 0..2 {
                    assert_eq!(
                        ossl_ffc_generate_private_key(ctx, group.as_ref(), n, 112, priv_),
                        1
                    );
                    assert!(BN_num_bits(priv_) <= n);
                    assert!(BN_num_bits(priv_) >= 1);
                }
            }

            /* `N == qbits` is the other arm: the bound is `q` itself, and a draw is still
             * strictly below it. */
            let qbits = BN_num_bits((*group.as_ref()).q);
            for _ in 0..2 {
                assert_eq!(
                    ossl_ffc_generate_private_key(ctx, group.as_ref(), qbits, 112, priv_),
                    1
                );
                assert!(BN_cmp(priv_, (*group.as_ref()).q) < 0);
            }

            BN_free(priv_);
            BN_CTX_free(ctx);
        }
    }
}
