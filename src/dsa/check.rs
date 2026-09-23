//! Phase 8 — `crypto/dsa/dsa_check.c`: the DSA parameter, public-key and private-key validators.
//!
//! One hundred and thirty-three source lines, six functions and one static. The five internals are
//! the provider's and the ameth's; `src/provider/dsa_kmgmt.rs` reaches all five of them, which is
//! what makes this unit landable rather than dead code (D391). Every name it calls is in the crate:
//! `ossl_ffc_params_simple_validate`/`_full_validate` (`src/ffc/params_validate.rs`),
//! `ossl_ffc_validate_public_key`/`_partial`/`_private_key` (`src/ffc/key_validate.rs`) and
//! `ossl_dsa_generate_public_key` (`src/dsa/key.rs`).
//!
//! ## `ret` is an out-parameter and the first thing every entry point does is write it
//!
//! `dsa_precheck_params` stamps `FFC_CHECK_INVALID_PQ` into the caller's `*ret` on each of its three
//! refusals; `ossl_dsa_check_priv_key` writes `*ret = 0` **before** its precheck, while
//! `ossl_dsa_check_pub_key` and `_partial` do not -- they only reach the FFC validator, which
//! writes `*ret` itself. The asymmetry is the authority's and is observable: a caller that passes
//! a `ret` it pre-loaded sees a different value after `pub_key` succeeds and after `priv_key`
//! succeeds.
//!
//! ## `ossl_dsa_check_pub_key`'s `&& *ret == 0`
//!
//! The validator's answer alone is not the answer: the function returns
//! `ossl_ffc_validate_public_key(...) && *ret == 0`, so a *passing* structural test whose `ret`
//! the validator set nonzero is still a refusal. `_partial` is the same shape. That is what keeps
//! "the FFC call said ok" and "the check's own ledger says ok" from being conflated.
//!
//! ## `ossl_dsa_check_pairwise` has the `goto err` the others do not
//!
//! It allocates a `BN_CTX` and a `BIGNUM`, so it has an `err:` label; a failed allocation returns
//! **0**, the same answer as a mismatched public key, and that is the authority's own conflation.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_free, BN_new, BN_num_bits, BigNum};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex, BnCtx};
use crate::dsa::key::ossl_dsa_generate_public_key;
use crate::dsa::{Dsa, OPENSSL_DSA_MAX_MODULUS_BITS};
use crate::ffc::key_validate::{
    ossl_ffc_validate_private_key, ossl_ffc_validate_public_key,
    ossl_ffc_validate_public_key_partial,
};
use crate::ffc::params_validate::{ossl_ffc_params_full_validate, ossl_ffc_params_simple_validate};
use crate::ffc::{FFC_CHECK_INVALID_PQ, FFC_PARAM_TYPE_DSA};
use crate::runtime::err::err_sites::{DSA_CHECK_25, DSA_CHECK_31, DSA_CHECK_37};
use crate::runtime::err::raise_site;

/// `OSSL_KEYMGMT_VALIDATE_QUICK_CHECK` — `include/openssl/core_dispatch.h:387`. Restated for the
/// reason every numeric constant in this crate is: the header's macro set is not re-exported.
const OSSL_KEYMGMT_VALIDATE_QUICK_CHECK: c_int = 1;

/// `static int dsa_precheck_params(const DSA *dsa, int *ret)` — `dsa_check.c:21-41`.
///
/// # Safety
/// `dsa` and `ret` are live, as [`ossl_dsa_check_params`] requires.
unsafe fn dsa_precheck_params(dsa: *const Dsa, ret: *mut c_int) -> c_int {
    // SAFETY: `dsa` and `ret` are live per the contract.
    unsafe {
        if (*dsa).params.p.is_null() || (*dsa).params.q.is_null() {
            raise_site(&DSA_CHECK_25);
            *ret = FFC_CHECK_INVALID_PQ;
            return 0;
        }

        if BN_num_bits((*dsa).params.p) > OPENSSL_DSA_MAX_MODULUS_BITS {
            raise_site(&DSA_CHECK_31);
            *ret = FFC_CHECK_INVALID_PQ;
            return 0;
        }

        if BN_num_bits((*dsa).params.q) >= BN_num_bits((*dsa).params.p) {
            raise_site(&DSA_CHECK_37);
            *ret = FFC_CHECK_INVALID_PQ;
            return 0;
        }
    }
    1
}

/// `int ossl_dsa_check_params(const DSA *dsa, int checktype, int *ret)` — `dsa_check.c:43-58`.
///
/// # Safety
/// `dsa` is live with a readable `params` and `libctx`; `ret` is writable.
pub(crate) unsafe fn ossl_dsa_check_params(
    dsa: *const Dsa,
    checktype: c_int,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract is `dsa_precheck_params`'s.
    if unsafe { dsa_precheck_params(dsa, ret) } == 0 {
        return 0;
    }

    // SAFETY: `dsa` is live past the precheck.
    unsafe {
        if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
            return ossl_ffc_params_simple_validate(
                (*dsa).libctx,
                &raw const (*dsa).params,
                FFC_PARAM_TYPE_DSA,
                ret,
            );
        }
        /*
         * Do full FFC domain params validation according to FIPS-186-4
         *  - always in FIPS_MODULE
         *  - only if possible (i.e., seed is set) in default provider
         */
        ossl_ffc_params_full_validate(
            (*dsa).libctx,
            &raw const (*dsa).params,
            FFC_PARAM_TYPE_DSA,
            ret,
        )
    }
}

/// `int ossl_dsa_check_pub_key(const DSA *dsa, const BIGNUM *pub_key, int *ret)` —
/// `dsa_check.c:60-71`.
///
/// # Safety
/// As [`ossl_dsa_check_params`]; `pub_key` is NULL or live.
pub(crate) unsafe fn ossl_dsa_check_pub_key(
    dsa: *const Dsa,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract is `dsa_precheck_params`'s.
    if unsafe { dsa_precheck_params(dsa, ret) } == 0 {
        return 0;
    }

    // SAFETY: `dsa` is live past the precheck; `pub_key` and `ret` are the caller's.
    unsafe {
        c_int::from(
            ossl_ffc_validate_public_key(&raw const (*dsa).params, pub_key, ret) != 0 && *ret == 0,
        )
    }
}

/// `int ossl_dsa_check_pub_key_partial(const DSA *dsa, const BIGNUM *pub_key, int *ret)` —
/// `dsa_check.c:73-86`.
///
/// **No caller anywhere in the authority, which is why it carries `dead_code`.**
/// `grep -rn ossl_dsa_check_pub_key_partial` over the pinned tree answers the definition and the
/// declaration in `include/crypto/dsa.h` and nothing else: the DH half's partial public-key check
/// is `crypto/dh/dh_check.c`'s own `ossl_dh_check_pub_key_partial`, and the DSA wrapper's stated
/// purpose — "To only be used with ephemeral FFC public keys generated using the approved
/// safe-prime groups" — has no DSA caller because DSA has no safe-prime group. It is transcribed
/// because it is `dsa_check.c`'s own text and D327's rule is that a unit is transcribed whole.
///
/// # Safety
/// As [`ossl_dsa_check_pub_key`].
#[allow(dead_code)] // declared by `crypto/dsa.h` and called by nothing in the authority
pub(crate) unsafe fn ossl_dsa_check_pub_key_partial(
    dsa: *const Dsa,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: the caller's contract is `dsa_precheck_params`'s.
    if unsafe { dsa_precheck_params(dsa, ret) } == 0 {
        return 0;
    }

    // SAFETY: `dsa` is live past the precheck; `pub_key` and `ret` are the caller's.
    unsafe {
        c_int::from(
            ossl_ffc_validate_public_key_partial(&raw const (*dsa).params, pub_key, ret) != 0
                && *ret == 0,
        )
    }
}

/// `int ossl_dsa_check_priv_key(const DSA *dsa, const BIGNUM *priv_key, int *ret)` —
/// `dsa_check.c:88-96`.
///
/// # Safety
/// As [`ossl_dsa_check_pub_key`], with `priv_key` for `pub_key`.
pub(crate) unsafe fn ossl_dsa_check_priv_key(
    dsa: *const Dsa,
    priv_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: `ret` is writable per the contract.
    unsafe { *ret = 0 };

    // SAFETY: the caller's contract is `dsa_precheck_params`'s.
    if unsafe { dsa_precheck_params(dsa, ret) } == 0 {
        return 0;
    }

    // SAFETY: `dsa` is live past the precheck; `priv_key` and `ret` are the caller's.
    unsafe { ossl_ffc_validate_private_key((*dsa).params.q, priv_key, ret) }
}

/// `int ossl_dsa_check_pairwise(const DSA *dsa)` — `dsa_check.c:98-133`.
///
/// # Safety
/// `dsa` is live with readable `params`, `priv_key`, `pub_key` and `libctx`.
#[allow(unused_assignments)] // the authority's `BN_CTX *ctx = NULL` is dead: every path that reaches the `err:` label assigns it first
pub(crate) unsafe fn ossl_dsa_check_pairwise(dsa: *const Dsa) -> c_int {
    let mut ret: c_int = 0;
    let mut ctx: *mut BnCtx = core::ptr::null_mut();
    let mut pub_key: *mut BigNum = core::ptr::null_mut();

    // SAFETY: `dsa` is live; `ret` is this call's own.
    if unsafe { dsa_precheck_params(dsa, &mut ret) } == 0 {
        return 0;
    }

    // SAFETY: `dsa` is live.
    unsafe {
        if (*dsa).params.g.is_null() || (*dsa).priv_key.is_null() || (*dsa).pub_key.is_null() {
            return 0;
        }
    }

    'err: {
        // SAFETY: `dsa` is live per the contract; every pointer below is this call's own.
        unsafe {
            ctx = BN_CTX_new_ex((*dsa).libctx);
            if ctx.is_null() {
                break 'err;
            }
            pub_key = BN_new();
            if pub_key.is_null() {
                break 'err;
            }

            /* recalculate the public key = (g ^ priv) mod p */
            if ossl_dsa_generate_public_key(ctx, dsa, (*dsa).priv_key, pub_key) == 0 {
                break 'err;
            }
            /* check it matches the existing public_key */
            ret = c_int::from(BN_cmp(pub_key, (*dsa).pub_key) == 0);
        }
    }
    /* The authority's `err:` label. */
    // SAFETY: both are this call's own allocations, NULL or live.
    unsafe {
        BN_free(pub_key);
        BN_CTX_free(ctx);
    }
    ret
}
