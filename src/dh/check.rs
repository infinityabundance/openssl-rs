//! Phase 8 — `crypto/dh/dh_check.c`: the parameter and public-key validators.
//!
//! Six exports (`DH_check_params_ex`, `DH_check_params`, `DH_check_ex`, `DH_check`, and the
//! public-key pair) and three internals (`ossl_dh_check_pub_key_partial`,
//! `ossl_dh_check_priv_key`, `ossl_dh_check_pairwise`), in authority order. The internals are the
//! provider's and the ameth's; the two `_check_pub_key` entry points are the ones the object's own
//! `ossl_dh_buf2key` reaches.
//!
//! ## `DH_get_nid`, which D331 wrote as its field read and which is now a call
//!
//! `DH_check` (`:158`) and `ossl_dh_check_priv_key` (`:336`) both branch on
//! `DH_get_nid((DH *)dh) != NID_undef`, and that function is
//! `crypto/dh/dh_group_params.c:94-100` — the named-group unit D329/D330 left as a
//! separable data transcription. D331 wrote each branch as the `params.nid` read it
//! reduces to, with the argument that the field had no writer in the crate; that unit
//! is landed ([`crate::dh::group_params`]) and both sites are the real calls.
//!
//! **The two arms are now reachable and are not the same arm.** `DH_check`'s answers 1
//! immediately — a group the table names has been validated by construction, so no
//! primality work happens at all. `ossl_dh_check_priv_key`'s arm is the one that reads
//! `dh->length`: for a named group whose length is set it caps `two_powN` at `2^length`
//! before `ossl_ffc_validate_private_key` runs, and for a group whose length is 0 it
//! does nothing at all. `RT-DH` drives both.
//!
//! The `#ifdef FIPS_MODULE` twin of `DH_check_params` (`:49-68`) — which *is* the
//! named-group check plus `ossl_ffc_params_FIPS186_4_validate` — is not compiled on this
//! profile, so it is not transcribed; the `#else` arm below is the whole function here.
//! *(The `#else` arm has no `DH_get_nid` call at all: the named-group shortcut is the
//! FIPS arm's, and the crate's `DH_check_params` is the authority's `#else` arm. The
//! module's earlier note said "both begin with it", which was the FIPS twin's shape.)*
//!
//! ## Ordering, where the authority's is load-bearing
//!
//! * `DH_check` runs `DH_check_params` **before** it creates a `BN_CTX`, and returns its answer
//!   directly, so the four cheap structural flags are reported by the callee's `|=` and the
//!   primality work happens only when the caller set `VALIDATE_PQ`-style flags — no, it runs
//!   unconditionally here, which is why the function refines `*ret` rather than replacing it.
//! * `DH_check_ex` raises one reason **per set bit, in fixed order**, so a parameter set that is
//!   both not-prime and has an unsuitable generator leaves two queue records and the first is the
//!   generator's. That order is the contract and is transcribed bit for bit.
//! * `ossl_dh_check_priv_key` returns 1 **without** running the FFC range test when the object has
//!   only a `p`: the `goto end` in that arm is what makes the "reasonable range" check the whole
//!   answer rather than a preliminary one.
//! * `ossl_dh_check_pairwise` starts a self-test record before it allocates anything, and its
//!   `err:` label ends the record with whatever `ret` holds — so a failure anywhere reports 0 to
//!   the self-test callback rather than leaving the record open.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::bn::arith::{BN_cmp, BN_div, BN_lshift, BN_mod_exp, BN_rshift1, BN_sub_word, BN_ucmp};
use crate::bn::bignum::{
    BN_copy, BN_free, BN_is_negative, BN_is_odd, BN_is_one, BN_is_zero, BN_new, BN_num_bits,
    BN_value_one, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start};
use crate::bn::primes::BN_check_prime;
use crate::ffc::key_validate::{
    ossl_ffc_validate_private_key, ossl_ffc_validate_public_key,
    ossl_ffc_validate_public_key_partial,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_undef;
use crate::selftest::{
    OSSL_SELF_TEST_free, OSSL_SELF_TEST_get_callback, OSSL_SELF_TEST_new, OSSL_SELF_TEST_onbegin,
    OSSL_SELF_TEST_onend, OsslCallback,
};

use super::group_params::DH_get_nid;
use super::key::ossl_dh_generate_public_key;
use super::{
    Dh, DH_CHECK_INVALID_J_VALUE, DH_CHECK_INVALID_Q_VALUE, DH_CHECK_PUBKEY_INVALID,
    DH_CHECK_PUBKEY_TOO_LARGE, DH_CHECK_PUBKEY_TOO_SMALL, DH_CHECK_P_NOT_PRIME,
    DH_CHECK_P_NOT_SAFE_PRIME, DH_CHECK_Q_NOT_PRIME, DH_MIN_MODULUS_BITS, DH_MODULUS_TOO_LARGE,
    DH_MODULUS_TOO_SMALL, DH_NOT_SUITABLE_GENERATOR, DH_UNABLE_TO_CHECK_GENERATOR,
    OPENSSL_DH_CHECK_MAX_MODULUS_BITS, OPENSSL_DH_MAX_MODULUS_BITS,
};

/// `OSSL_SELF_TEST_TYPE_PCT` — `include/openssl/self_test.h:32`.
const OSSL_SELF_TEST_TYPE_PCT: &core::ffi::CStr = c"Conditional_PCT";
/// `OSSL_SELF_TEST_DESC_PCT_DH` — `include/openssl/self_test.h:54`.
const OSSL_SELF_TEST_DESC_PCT_DH: &core::ffi::CStr = c"DH";

/// `int DH_check_params_ex(const DH *dh)` — `dh_check.c:29-46`.
///
/// The four structural flags, each raising its own reason. **It answers the return value of
/// `DH_check_params`, not "the flags were zero"**, so an allocation failure inside the callee is
/// 0 with no reason raised.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_check_params_ex(dh: *const Dh) -> c_int {
    let mut errflags: c_int = 0;

    // SAFETY: `dh` is live and `errflags` is a writable local.
    if unsafe { DH_check_params(dh, &raw mut errflags) } == 0 {
        return 0;
    }

    // SAFETY: each site is a compile-time constant.
    unsafe {
        if (errflags & DH_CHECK_P_NOT_PRIME) != 0 {
            raise_site(&err_sites::DH_CHECK_37);
        }
        if (errflags & DH_NOT_SUITABLE_GENERATOR) != 0 {
            raise_site(&err_sites::DH_CHECK_39);
        }
        if (errflags & DH_MODULUS_TOO_SMALL) != 0 {
            raise_site(&err_sites::DH_CHECK_41);
        }
        if (errflags & DH_MODULUS_TOO_LARGE) != 0 {
            raise_site(&err_sites::DH_CHECK_43);
        }
    }

    c_int::from(errflags == 0)
}

/// `int DH_check_params(const DH *dh, int *ret)` — `dh_check.c:70-113`, the `#else` arm.
///
/// The cheap structural checks: `p` odd, `1 < g < p - 1`, and the modulus bounds. A NULL `p` or
/// `g` reports both `NOT_SUITABLE_GENERATOR` and `CHECK_P_NOT_PRIME` through `*ret` and answers 1
/// rather than dereferencing either.
///
/// # Safety
///
/// `dh` is a live object; `ret` is writable.
#[no_mangle]
pub unsafe extern "C" fn DH_check_params(dh: *const Dh, ret: *mut c_int) -> c_int {
    let mut ok: c_int = 0;

    // SAFETY: `ret` is writable per the contract.
    unsafe {
        *ret = 0;
        /*
         * A DH with no modulus or generator cannot be checked. Report
         * the failure via |*ret| rather than dereferencing NULL below.
         */
        if (*dh).params.p.is_null() || (*dh).params.g.is_null() {
            *ret = DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME;
            return 1;
        }
    }

    // SAFETY: `dh` is live per the contract; `params.p` is non-NULL as established above.
    let ctx = unsafe { BN_CTX_new_ex((*dh).libctx) };
    if ctx.is_null() {
        return ok;
    }

    // SAFETY: `ctx` is live and is this call's own; `dh` is live.
    unsafe {
        BN_CTX_start(ctx);
        let tmp = BN_CTX_get(ctx);
        if tmp.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }

        if BN_is_odd((*dh).params.p) == 0 {
            *ret |= DH_CHECK_P_NOT_PRIME;
        }
        if BN_is_negative((*dh).params.g) != 0
            || BN_is_zero((*dh).params.g) != 0
            || BN_is_one((*dh).params.g) != 0
        {
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        }
        if BN_copy(tmp, (*dh).params.p).is_null() || BN_sub_word(tmp, 1) == 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }
        if BN_cmp((*dh).params.g, tmp) >= 0 {
            *ret |= DH_NOT_SUITABLE_GENERATOR;
        }
        if BN_num_bits((*dh).params.p) < DH_MIN_MODULUS_BITS {
            *ret |= DH_MODULUS_TOO_SMALL;
        }
        if BN_num_bits((*dh).params.p) > OPENSSL_DH_MAX_MODULUS_BITS {
            *ret |= DH_MODULUS_TOO_LARGE;
        }

        ok = 1;

        /* The authority's `err:` label. */
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ok
}

/// `int DH_check_ex(const DH *dh)` — `dh_check.c:120-147`.
///
/// One reason per set bit, in the authority's fixed order. `DH_UNABLE_TO_CHECK_GENERATOR` is the
/// one bit whose reason the flag names; `DH_check` never sets it on this profile, and it is
/// transcribed because the authority's list has it.
///
/// # Safety
///
/// `dh` is a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_check_ex(dh: *const Dh) -> c_int {
    let mut errflags: c_int = 0;

    // SAFETY: `dh` is live and `errflags` is a writable local.
    if unsafe { DH_check(dh, &raw mut errflags) } == 0 {
        return 0;
    }

    // SAFETY: each site is a compile-time constant.
    unsafe {
        if (errflags & DH_NOT_SUITABLE_GENERATOR) != 0 {
            raise_site(&err_sites::DH_CHECK_128);
        }
        if (errflags & DH_CHECK_Q_NOT_PRIME) != 0 {
            raise_site(&err_sites::DH_CHECK_130);
        }
        if (errflags & DH_CHECK_INVALID_Q_VALUE) != 0 {
            raise_site(&err_sites::DH_CHECK_132);
        }
        if (errflags & DH_CHECK_INVALID_J_VALUE) != 0 {
            raise_site(&err_sites::DH_CHECK_134);
        }
        if (errflags & DH_UNABLE_TO_CHECK_GENERATOR) != 0 {
            raise_site(&err_sites::DH_CHECK_136);
        }
        if (errflags & DH_CHECK_P_NOT_PRIME) != 0 {
            raise_site(&err_sites::DH_CHECK_138);
        }
        if (errflags & DH_CHECK_P_NOT_SAFE_PRIME) != 0 {
            raise_site(&err_sites::DH_CHECK_140);
        }
        if (errflags & DH_MODULUS_TOO_SMALL) != 0 {
            raise_site(&err_sites::DH_CHECK_142);
        }
        if (errflags & DH_MODULUS_TOO_LARGE) != 0 {
            raise_site(&err_sites::DH_CHECK_144);
        }
    }

    c_int::from(errflags == 0)
}

/// `int DH_check(const DH *dh, int *ret)` — `dh_check.c:150-242`, the `#else` arm.
///
/// "According to documentation - this only checks the params." A group that names a known
/// `nid` is accepted immediately; above `OPENSSL_DH_CHECK_MAX_MODULUS_BITS` the function raises,
/// sets two bits and answers 0 without running an exponentiation; otherwise `DH_check_params`
/// runs first and the subgroup checks refine `*ret` rather than replacing it.
///
/// # Safety
///
/// `dh` is a live object; `ret` is writable.
#[no_mangle]
pub unsafe extern "C" fn DH_check(dh: *const Dh, ret: *mut c_int) -> c_int {
    let mut ok: c_int = 0;
    let mut q_good: c_int = 0;

    // SAFETY: `ret` is writable per the contract.
    unsafe {
        *ret = 0;
        /* A DH with no modulus or generator cannot be checked. */
        if (*dh).params.p.is_null() || (*dh).params.g.is_null() {
            *ret = DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME;
            return 1;
        }
    }

    /* The authority's `DH_get_nid((DH *)dh)`: a group the table names is valid by
     * construction, so no primality work runs for one. */
    // SAFETY: `dh` is live per the contract.
    let nid = unsafe { DH_get_nid(dh) };
    if nid != NID_undef {
        return 1;
    }

    // SAFETY: `dh` is live per the contract.
    unsafe {
        /* Don't do any checks at all with an excessively large modulus */
        if BN_num_bits((*dh).params.p) > OPENSSL_DH_CHECK_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_CHECK_171);
            *ret = DH_MODULUS_TOO_LARGE | DH_CHECK_P_NOT_PRIME;
            return 0;
        }
    }

    // SAFETY: `dh` is live and `ret` is the caller's writable pointer.
    if unsafe { DH_check_params(dh, ret) } == 0 {
        return 0;
    }

    // SAFETY: `dh` is live per the contract.
    let ctx = unsafe { BN_CTX_new_ex((*dh).libctx) };
    if ctx.is_null() {
        return ok;
    }

    // SAFETY: `ctx` is live and is this call's own; `dh` is live and its `p`/`g` are non-NULL.
    unsafe {
        BN_CTX_start(ctx);
        let t1 = BN_CTX_get(ctx);
        let t2 = BN_CTX_get(ctx);
        if t2.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }

        if !(*dh).params.q.is_null() {
            if BN_ucmp((*dh).params.p, (*dh).params.q) > 0 {
                q_good = 1;
            } else {
                *ret |= DH_CHECK_INVALID_Q_VALUE;
            }
        }

        if q_good != 0 {
            if BN_cmp((*dh).params.g, BN_value_one()) <= 0
                || BN_cmp((*dh).params.g, (*dh).params.p) >= 0
            {
                *ret |= DH_NOT_SUITABLE_GENERATOR;
            } else {
                /* Check g^q == 1 mod p */
                if BN_mod_exp(t1, (*dh).params.g, (*dh).params.q, (*dh).params.p, ctx) == 0 {
                    BN_CTX_end(ctx);
                    BN_CTX_free(ctx);
                    return ok;
                }
                if BN_is_one(t1) == 0 {
                    *ret |= DH_NOT_SUITABLE_GENERATOR;
                }
            }
            let r = BN_check_prime((*dh).params.q, ctx, ptr::null_mut());
            if r < 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ok;
            }
            if r == 0 {
                *ret |= DH_CHECK_Q_NOT_PRIME;
            }
            /* Check p == 1 mod q  i.e. q divides p - 1 */
            if BN_div(t1, t2, (*dh).params.p, (*dh).params.q, ctx) == 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ok;
            }
            if BN_is_one(t2) == 0 {
                *ret |= DH_CHECK_INVALID_Q_VALUE;
            }
            if !(*dh).params.j.is_null() && BN_cmp((*dh).params.j, t1) != 0 {
                *ret |= DH_CHECK_INVALID_J_VALUE;
            }
        }

        let r = BN_check_prime((*dh).params.p, ctx, ptr::null_mut());
        if r < 0 {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            return ok;
        }
        if r == 0 {
            *ret |= DH_CHECK_P_NOT_PRIME;
        } else if (*dh).params.q.is_null() {
            if BN_rshift1(t1, (*dh).params.p) == 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ok;
            }
            let r = BN_check_prime(t1, ctx, ptr::null_mut());
            if r < 0 {
                BN_CTX_end(ctx);
                BN_CTX_free(ctx);
                return ok;
            }
            if r == 0 {
                *ret |= DH_CHECK_P_NOT_SAFE_PRIME;
            }
        }
        ok = 1;

        /* The authority's `err:` label. */
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    ok
}

/// `int DH_check_pub_key_ex(const DH *dh, const BIGNUM *pub_key)` — `dh_check.c:244-259`.
///
/// # Safety
///
/// `dh` is a live object; `pub_key` is a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn DH_check_pub_key_ex(dh: *const Dh, pub_key: *const BigNum) -> c_int {
    let mut errflags: c_int = 0;

    // SAFETY: `dh` and `pub_key` are live and `errflags` is a writable local.
    if unsafe { DH_check_pub_key(dh, pub_key, &raw mut errflags) } == 0 {
        return 0;
    }

    // SAFETY: each site is a compile-time constant.
    unsafe {
        if (errflags & DH_CHECK_PUBKEY_TOO_SMALL) != 0 {
            raise_site(&err_sites::DH_CHECK_252);
        }
        if (errflags & DH_CHECK_PUBKEY_TOO_LARGE) != 0 {
            raise_site(&err_sites::DH_CHECK_254);
        }
        if (errflags & DH_CHECK_PUBKEY_INVALID) != 0 {
            raise_site(&err_sites::DH_CHECK_256);
        }
    }

    c_int::from(errflags == 0)
}

/// `int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *ret)` — `dh_check.c:264-288`.
///
/// "See SP800-56Ar3 Section 5.6.2.3.1 : FFC Full public key validation." A NULL `p` reports
/// `DH_CHECK_PUBKEY_INVALID` through `*ret` and answers 1; an excessively large modulus raises and
/// answers 0; `q > p` reports two bits and answers 1; everything else is the FFC full check, whose
/// own answer is passed through.
///
/// # Safety
///
/// `dh` is a live object; `pub_key` is a live `BIGNUM`; `ret` is writable.
#[no_mangle]
pub unsafe extern "C" fn DH_check_pub_key(
    dh: *const Dh,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: `ret` is writable per the contract.
    unsafe {
        *ret = 0;
        /*
         * Without a modulus we cannot check anything; signal failure via
         * |*ret| rather than crashing in BN_num_bits below.
         */
        if (*dh).params.p.is_null() {
            *ret = DH_CHECK_PUBKEY_INVALID;
            return 1;
        }
        /* Don't do any checks at all with an excessively large modulus */
        if BN_num_bits((*dh).params.p) > OPENSSL_DH_CHECK_MAX_MODULUS_BITS {
            raise_site(&err_sites::DH_CHECK_277);
            *ret = DH_MODULUS_TOO_LARGE | DH_CHECK_PUBKEY_INVALID;
            return 0;
        }

        if !(*dh).params.q.is_null() && BN_ucmp((*dh).params.p, (*dh).params.q) < 0 {
            *ret |= DH_CHECK_INVALID_Q_VALUE | DH_CHECK_PUBKEY_INVALID;
            return 1;
        }

        ossl_ffc_validate_public_key(ptr::addr_of!((*dh).params), pub_key, ret)
    }
}

/// `int ossl_dh_check_pub_key_partial(const DH *dh, const BIGNUM *pub_key, int *ret)` —
/// `dh_check.c:295-299`. Internal.
///
/// The FFC range check plus "the range check reported nothing", written as the `&&` it is. This is
/// the check `ossl_dh_buf2key` reaches, and the reason a peer key of `1` or `p - 1` is refused on
/// import.
///
/// # Safety
///
/// `dh` is a live object; `pub_key` is a live `BIGNUM`; `ret` is writable.
pub(crate) unsafe fn ossl_dh_check_pub_key_partial(
    dh: *const Dh,
    pub_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    // SAFETY: `dh` is live and `ret` is writable per the contract.
    unsafe {
        c_int::from(
            ossl_ffc_validate_public_key_partial(ptr::addr_of!((*dh).params), pub_key, ret) != 0
                && *ret == 0,
        )
    }
}

/// `int ossl_dh_check_priv_key(const DH *dh, const BIGNUM *priv_key, int *ret)` —
/// `dh_check.c:301-349`. Internal.
///
/// Two regimes: with a `q` the upper bound is the subgroup order (or `2^length` when that is
/// smaller and the object names a group), and the FFC range test runs; with only a `p` the check
/// is the authority's "reasonable range" rule and the function returns before the FFC test.
///
/// The `#ifndef FIPS_MODULE` arm that reads `dh->length` is this profile's, and its two-exit shape
/// — `goto end` after setting `ok` — is preserved.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider keymgmt and the ameth**
/// (`dh_kmgmt.c:413`), both beyond this slice.
///
/// # Safety
///
/// `dh` is a live object; `priv_key` is a live `BIGNUM`; `ret` is writable.
#[allow(dead_code)] // read by the provider keymgmt and the ameth, which are later slices
pub(crate) unsafe fn ossl_dh_check_priv_key(
    dh: *const Dh,
    priv_key: *const BigNum,
    ret: *mut c_int,
) -> c_int {
    let mut ok: c_int = 0;

    // SAFETY: `ret` is writable per the contract.
    unsafe { *ret = 0 };

    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let two_pow_n = unsafe { BN_new() };
    if two_pow_n.is_null() {
        return 0;
    }

    // SAFETY: `dh` and `priv_key` are live per the contract.
    let mut upper = unsafe {
        if !(*dh).params.q.is_null() {
            (*dh).params.q
        } else if !(*dh).params.p.is_null() {
            /*
             * We do not have q so we just check the key is within some
             * reasonable range, or the number of bits is equal to dh->length.
             */
            let mut length = (*dh).length;
            if length == 0 {
                length = BN_num_bits((*dh).params.p) - 1;
                if BN_num_bits(priv_key) <= length && BN_num_bits(priv_key) > 1 {
                    ok = 1;
                }
            } else if BN_num_bits(priv_key) == length {
                ok = 1;
            }
            BN_free(two_pow_n);
            return ok;
        } else {
            BN_free(two_pow_n);
            return 0;
        }
    };

    // SAFETY: `dh` is live, `priv_key` is live, `upper` is `params.q` (live), and `two_pow_n` is
    // this call's own.
    unsafe {
        /* Is it from an approved Safe prime group ?*/
        if DH_get_nid(dh) != NID_undef && (*dh).length != 0 {
            if BN_lshift(two_pow_n, BN_value_one(), (*dh).length) == 0 {
                BN_free(two_pow_n);
                return ok;
            }
            if BN_cmp(two_pow_n, (*dh).params.q) < 0 {
                upper = two_pow_n;
            }
        }
        if ossl_ffc_validate_private_key(upper, priv_key, ret) == 0 {
            BN_free(two_pow_n);
            return ok;
        }
        ok = 1;
        BN_free(two_pow_n);
    }
    ok
}

/// `int ossl_dh_check_pairwise(const DH *dh, int return_on_null_numbers)` — `dh_check.c:355-410`.
/// Internal.
///
/// "FFC pairwise check from SP800-56A R3. Section 5.6.2.1.4 Owner Assurance of Pair-wise
/// Consistency". The public key is recomputed from the stored private key and compared with the
/// stored one. The `#ifdef FIPS_MODULE` corrupt-a-byte block is not compiled on this profile.
///
/// The early return answers **`return_on_null_numbers`**, so a caller that wants "no key material
/// is not a failure" passes 1 — that is the whole reason the parameter exists.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the provider keymgmt** (`dh_kmgmt.c:447`,
/// `:799`), beyond this slice.
///
/// # Safety
///
/// `dh` is a live object.
#[allow(dead_code)] // read by the provider keymgmt, which is a later slice
pub(crate) unsafe fn ossl_dh_check_pairwise(dh: *const Dh, return_on_null_numbers: c_int) -> c_int {
    let mut ret: c_int = 0;

    // SAFETY: `dh` is live per the contract.
    unsafe {
        if (*dh).params.p.is_null()
            || (*dh).params.g.is_null()
            || (*dh).priv_key.is_null()
            || (*dh).pub_key.is_null()
        {
            return return_on_null_numbers;
        }
    }

    let mut stcb: Option<OsslCallback> = None;
    let mut stcbarg: *mut c_void = ptr::null_mut();
    // SAFETY: `stcb` and `stcbarg` are writable locals; the library context is the object's.
    unsafe {
        OSSL_SELF_TEST_get_callback((*dh).libctx, &raw mut stcb, &raw mut stcbarg);
    }
    // `OSSL_SELF_TEST_new` is a safe function in this crate: it allocates and stores the pair.
    let st = OSSL_SELF_TEST_new(stcb, stcbarg);
    if st.is_null() {
        return ret;
    }
    // SAFETY: `st` is live and the two strings are static.
    unsafe {
        OSSL_SELF_TEST_onbegin(
            st,
            OSSL_SELF_TEST_TYPE_PCT.as_ptr(),
            OSSL_SELF_TEST_DESC_PCT_DH.as_ptr(),
        );
    }

    // SAFETY: `dh` is live per the contract.
    let ctx = unsafe { BN_CTX_new_ex((*dh).libctx) };
    if ctx.is_null() {
        // SAFETY: `st` is live and `ret` is 0.
        unsafe { OSSL_SELF_TEST_onend(st, ret) };
        // SAFETY: `st` is this call's own.
        unsafe { OSSL_SELF_TEST_free(st) };
        return ret;
    }
    // SAFETY: `BN_new` allocates without touching a caller pointer.
    let pub_key = unsafe { BN_new() };
    if pub_key.is_null() {
        // SAFETY: each pointer is live and is this call's own.
        unsafe {
            BN_CTX_free(ctx);
            OSSL_SELF_TEST_onend(st, ret);
            OSSL_SELF_TEST_free(st);
        }
        return ret;
    }

    // SAFETY: `ctx`, `dh` and the object's own private key are live; `pub_key` is this call's own.
    if unsafe { ossl_dh_generate_public_key(ctx, dh, (*dh).priv_key, pub_key) } != 0 {
        /* the `#ifdef FIPS_MODULE` corrupt-a-byte block is not compiled on this profile */
        // SAFETY: `pub_key` is live and `(*dh).pub_key` is the stored one.
        ret = c_int::from(unsafe { BN_cmp(pub_key, (*dh).pub_key) } == 0);
    }

    /* The authority's `err:` label. */
    // SAFETY: each pointer is live and is this call's own.
    unsafe {
        BN_free(pub_key);
        BN_CTX_free(ctx);
        OSSL_SELF_TEST_onend(st, ret);
        OSSL_SELF_TEST_free(st);
    }
    ret
}
