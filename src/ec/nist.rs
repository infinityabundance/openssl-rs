//! `crypto/ec/ecp_nist.c` — the NIST-prime fast-reduction `EC_METHOD`, Phase 8.7.
//!
//! Four `ossl_ec_GFp_nist_*` internals and the export `EC_GFp_nist_method`. Its field columns
//! multiply and reduce through `group->field_mod_func`, which is one of `BN_nist_mod_192`..`_521`.
//!
//! The `ERR_raise` sites are named `err_sites::ECP_NIST_<line>` after the generator's stem for
//! `crypto/ec/ecp_nist.c`; those constants are owed with the rest of this tranche's stem set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::{BN_mul, BN_sqr, BN_ucmp};
use crate::bn::bignum::BigNum;
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::nist::{
    BN_nist_mod_192, BN_nist_mod_224, BN_nist_mod_256, BN_nist_mod_384, BN_nist_mod_521,
};
use crate::bn::primes::{
    BN_get0_nist_prime_192, BN_get0_nist_prime_224, BN_get0_nist_prime_256, BN_get0_nist_prime_384,
    BN_get0_nist_prime_521,
};
use crate::ec::ecdh_ossl::ossl_ecdh_simple_compute_key;
use crate::ec::ecdsa_ossl::{
    ossl_ecdsa_simple_sign_setup, ossl_ecdsa_simple_sign_sig, ossl_ecdsa_simple_verify_sig,
};
use crate::ec::key::{
    ossl_ec_key_simple_check_key, ossl_ec_key_simple_generate_key,
    ossl_ec_key_simple_generate_public_key, ossl_ec_key_simple_oct2priv,
    ossl_ec_key_simple_priv2oct,
};
use crate::ec::lib::ossl_ec_group_simple_order_bits;
use crate::ec::smpl::{
    ossl_ec_GFp_simple_add, ossl_ec_GFp_simple_blind_coordinates, ossl_ec_GFp_simple_cmp,
    ossl_ec_GFp_simple_dbl, ossl_ec_GFp_simple_field_inv,
    ossl_ec_GFp_simple_group_check_discriminant, ossl_ec_GFp_simple_group_clear_finish,
    ossl_ec_GFp_simple_group_copy, ossl_ec_GFp_simple_group_finish,
    ossl_ec_GFp_simple_group_get_curve, ossl_ec_GFp_simple_group_get_degree,
    ossl_ec_GFp_simple_group_init, ossl_ec_GFp_simple_group_set_curve, ossl_ec_GFp_simple_invert,
    ossl_ec_GFp_simple_is_at_infinity, ossl_ec_GFp_simple_is_on_curve,
    ossl_ec_GFp_simple_ladder_post, ossl_ec_GFp_simple_ladder_pre, ossl_ec_GFp_simple_ladder_step,
    ossl_ec_GFp_simple_make_affine, ossl_ec_GFp_simple_point_clear_finish,
    ossl_ec_GFp_simple_point_copy, ossl_ec_GFp_simple_point_finish,
    ossl_ec_GFp_simple_point_get_affine_coordinates, ossl_ec_GFp_simple_point_init,
    ossl_ec_GFp_simple_point_set_affine_coordinates, ossl_ec_GFp_simple_point_set_to_infinity,
    ossl_ec_GFp_simple_points_make_affine,
};
use crate::ec::{
    EcComputeKeyFn, EcFieldModFn, EcFieldMulFn, EcFieldSqrFn, EcGroup, EcGroupCheckDiscriminantFn,
    EcGroupCopyFn, EcGroupFinishFn, EcGroupGetCurveFn, EcGroupInitFn, EcGroupQueryFn,
    EcGroupSetCurveFn, EcKeyCheckFn, EcKeyInitFn, EcKeySignSetupFn, EcKeySignSigFn,
    EcKeyVerifySigFn, EcLadderFn, EcMethod, EcOct2PrivFn, EcPointAddFn, EcPointCmpFn,
    EcPointCopyFn, EcPointDblFn, EcPointFinishFn, EcPointGetAffineFn, EcPointInitFn,
    EcPointIsAtInfinityFn, EcPointIsOnCurveFn, EcPointSetAffineFn, EcPointSetToInfinityFn,
    EcPointUnaryFn, EcPointsMakeAffineFn, EcPriv2OctFn, EC_FLAGS_DEFAULT_OCT,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_X9_62_prime_field;

/// `static const EC_METHOD` — `crypto/ec/ecp_nist.c:25-80`.
static EC_GFP_NIST_METHOD: EcMethod = EcMethod {
    flags: EC_FLAGS_DEFAULT_OCT,
    field_type: NID_X9_62_prime_field,
    group_init: Some(ossl_ec_GFp_simple_group_init as EcGroupInitFn),
    group_finish: Some(ossl_ec_GFp_simple_group_finish as EcGroupFinishFn),
    group_clear_finish: Some(ossl_ec_GFp_simple_group_clear_finish as EcGroupFinishFn),
    group_copy: Some(ossl_ec_GFp_nist_group_copy as EcGroupCopyFn),
    group_set_curve: Some(ossl_ec_GFp_nist_group_set_curve as EcGroupSetCurveFn),
    group_get_curve: Some(ossl_ec_GFp_simple_group_get_curve as EcGroupGetCurveFn),
    group_get_degree: Some(ossl_ec_GFp_simple_group_get_degree as EcGroupQueryFn),
    group_order_bits: Some(ossl_ec_group_simple_order_bits as EcGroupQueryFn),
    group_check_discriminant: Some(
        ossl_ec_GFp_simple_group_check_discriminant as EcGroupCheckDiscriminantFn,
    ),
    point_init: Some(ossl_ec_GFp_simple_point_init as EcPointInitFn),
    point_finish: Some(ossl_ec_GFp_simple_point_finish as EcPointFinishFn),
    point_clear_finish: Some(ossl_ec_GFp_simple_point_clear_finish as EcPointFinishFn),
    point_copy: Some(ossl_ec_GFp_simple_point_copy as EcPointCopyFn),
    point_set_to_infinity: Some(ossl_ec_GFp_simple_point_set_to_infinity as EcPointSetToInfinityFn),
    point_set_affine_coordinates: Some(
        ossl_ec_GFp_simple_point_set_affine_coordinates as EcPointSetAffineFn,
    ),
    point_get_affine_coordinates: Some(
        ossl_ec_GFp_simple_point_get_affine_coordinates as EcPointGetAffineFn,
    ),
    point_set_compressed_coordinates: None,
    point2oct: None,
    oct2point: None,
    add: Some(ossl_ec_GFp_simple_add as EcPointAddFn),
    dbl: Some(ossl_ec_GFp_simple_dbl as EcPointDblFn),
    invert: Some(ossl_ec_GFp_simple_invert as EcPointUnaryFn),
    is_at_infinity: Some(ossl_ec_GFp_simple_is_at_infinity as EcPointIsAtInfinityFn),
    is_on_curve: Some(ossl_ec_GFp_simple_is_on_curve as EcPointIsOnCurveFn),
    point_cmp: Some(ossl_ec_GFp_simple_cmp as EcPointCmpFn),
    make_affine: Some(ossl_ec_GFp_simple_make_affine as EcPointUnaryFn),
    points_make_affine: Some(ossl_ec_GFp_simple_points_make_affine as EcPointsMakeAffineFn),
    mul: None,
    precompute_mult: None,
    have_precompute_mult: None,
    field_mul: Some(ossl_ec_GFp_nist_field_mul as EcFieldMulFn),
    field_sqr: Some(ossl_ec_GFp_nist_field_sqr as EcFieldSqrFn),
    field_div: None,
    field_inv: Some(ossl_ec_GFp_simple_field_inv as EcFieldSqrFn),
    field_encode: None,
    field_decode: None,
    field_set_to_one: None,
    priv2oct: Some(ossl_ec_key_simple_priv2oct as EcPriv2OctFn),
    oct2priv: Some(ossl_ec_key_simple_oct2priv as EcOct2PrivFn),
    set_private: None,
    keygen: Some(ossl_ec_key_simple_generate_key as EcKeyInitFn),
    keycheck: Some(ossl_ec_key_simple_check_key as EcKeyCheckFn),
    keygenpub: Some(ossl_ec_key_simple_generate_public_key as EcKeyInitFn),
    keycopy: None,
    keyfinish: None,
    ecdh_compute_key: Some(ossl_ecdh_simple_compute_key as EcComputeKeyFn),
    ecdsa_sign_setup: Some(ossl_ecdsa_simple_sign_setup as EcKeySignSetupFn),
    ecdsa_sign_sig: Some(ossl_ecdsa_simple_sign_sig as EcKeySignSigFn),
    ecdsa_verify_sig: Some(ossl_ecdsa_simple_verify_sig as EcKeyVerifySigFn),
    field_inverse_mod_ord: None,
    blind_coordinates: Some(ossl_ec_GFp_simple_blind_coordinates as EcPointUnaryFn),
    ladder_pre: Some(ossl_ec_GFp_simple_ladder_pre as EcLadderFn),
    ladder_step: Some(ossl_ec_GFp_simple_ladder_step as EcLadderFn),
    ladder_post: Some(ossl_ec_GFp_simple_ladder_post as EcLadderFn),
    group_full_init: None,
};

/// `const EC_METHOD *EC_GFp_nist_method(void)` — `crypto/ec/ecp_nist.c:23-83`.
#[no_mangle]
pub extern "C" fn EC_GFp_nist_method() -> *const EcMethod {
    &EC_GFP_NIST_METHOD
}

/// `int ossl_ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src)` —
/// `crypto/ec/ecp_nist.c:85-90`.
///
/// # Safety
///
/// As [`ossl_ec_GFp_simple_group_copy`]'s contract; `src`'s `field_mod_func` is copied to `dest`.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_nist_group_copy(
    dest: *mut EcGroup,
    src: *const EcGroup,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*dest).field_mod_func = (*src).field_mod_func;
        ossl_ec_GFp_simple_group_copy(dest, src)
    }
}

/// `int ossl_ec_GFp_nist_group_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_nist.c:92-126`.
///
/// # Safety
///
/// `group` is live; `p`, `a`, `b` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_nist_group_set_curve(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);

        let f: EcFieldModFn = if BN_ucmp(BN_get0_nist_prime_192(), p) == 0 {
            BN_nist_mod_192
        } else if BN_ucmp(BN_get0_nist_prime_224(), p) == 0 {
            BN_nist_mod_224
        } else if BN_ucmp(BN_get0_nist_prime_256(), p) == 0 {
            BN_nist_mod_256
        } else if BN_ucmp(BN_get0_nist_prime_384(), p) == 0 {
            BN_nist_mod_384
        } else if BN_ucmp(BN_get0_nist_prime_521(), p) == 0 {
            BN_nist_mod_521
        } else {
            raise_site(&err_sites::ECP_NIST_116);
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        };
        (*group).field_mod_func = Some(f);

        ret = ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_nist_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_nist.c:128-151`.
///
/// # Safety
///
/// `group`, `r`, `a`, `b` are non-NULL live values, and `group->field_mod_func` is set.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_nist_field_mul(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut ctx_new: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if group.is_null() || r.is_null() || a.is_null() || b.is_null() {
                raise_site(&err_sites::ECP_NIST_135);
                break 'err;
            }
            if ctx.is_null() {
                ctx_new = BN_CTX_new_ex((*group).libctx);
                ctx = ctx_new;
                if ctx.is_null() {
                    break 'err;
                }
            }

            if BN_mul(r, a, b, ctx) == 0 {
                break 'err;
            }
            let f = match (*group).field_mod_func {
                Some(f) => f,
                None => break 'err,
            };
            if f(r, r, (*group).field, ctx) == 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_free(ctx_new);
    }
    ret
}

/// `int ossl_ec_GFp_nist_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_nist.c:153-176`.
///
/// # Safety
///
/// `group`, `r`, `a` are non-NULL live values, and `group->field_mod_func` is set.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_nist_field_sqr(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut ctx_new: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            if group.is_null() || r.is_null() || a.is_null() {
                raise_site(&err_sites::ECP_NIST_160);
                break 'err;
            }
            if ctx.is_null() {
                ctx_new = BN_CTX_new_ex((*group).libctx);
                ctx = ctx_new;
                if ctx.is_null() {
                    break 'err;
                }
            }

            if BN_sqr(r, a, ctx) == 0 {
                break 'err;
            }
            let f = match (*group).field_mod_func {
                Some(f) => f,
                None => break 'err,
            };
            if f(r, r, (*group).field, ctx) == 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_free(ctx_new);
    }
    ret
}
