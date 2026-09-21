//! `crypto/ec/ecp_mont.c` — the Montgomery-representation prime-field `EC_METHOD`, Phase 8.7.
//!
//! Eleven `ossl_ec_GFp_mont_*` internals and the export `EC_GFp_mont_method`. The table's
//! non-field columns are `ecp_smpl.c`'s and `ec_lib.c`'s (and the eleven key/ecdh/ecdsa columns),
//! which is why [`crate::ec::smpl`] and this file land in one commit.
//!
//! The `ERR_raise` sites are named `err_sites::ECP_MONT_<line>` after the generator's stem for
//! `crypto/ec/ecp_mont.c`; `gen_err_raise_sites.py`'s `COVERED_FILES` does not list this unit
//! yet, so those constants are owed with the rest of this tranche's stem set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::BN_sub;
use crate::bn::bignum::{
    BN_clear_free, BN_copy, BN_dup, BN_free, BN_is_zero, BN_new, BN_set_word, BN_value_one, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_secure_new_ex, BN_CTX_start, BnCtx,
};
use crate::bn::mont::{
    BN_MONT_CTX_copy, BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set, BN_from_montgomery,
    BN_mod_exp_mont, BN_mod_mul_montgomery, BN_to_montgomery, MontCtx,
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
    ossl_ec_GFp_simple_dbl, ossl_ec_GFp_simple_group_check_discriminant,
    ossl_ec_GFp_simple_group_clear_finish, ossl_ec_GFp_simple_group_copy,
    ossl_ec_GFp_simple_group_finish, ossl_ec_GFp_simple_group_get_curve,
    ossl_ec_GFp_simple_group_get_degree, ossl_ec_GFp_simple_group_init,
    ossl_ec_GFp_simple_group_set_curve, ossl_ec_GFp_simple_invert,
    ossl_ec_GFp_simple_is_at_infinity, ossl_ec_GFp_simple_is_on_curve,
    ossl_ec_GFp_simple_ladder_post, ossl_ec_GFp_simple_ladder_pre, ossl_ec_GFp_simple_ladder_step,
    ossl_ec_GFp_simple_make_affine, ossl_ec_GFp_simple_point_clear_finish,
    ossl_ec_GFp_simple_point_copy, ossl_ec_GFp_simple_point_finish,
    ossl_ec_GFp_simple_point_get_affine_coordinates, ossl_ec_GFp_simple_point_init,
    ossl_ec_GFp_simple_point_set_affine_coordinates, ossl_ec_GFp_simple_point_set_to_infinity,
    ossl_ec_GFp_simple_points_make_affine,
};
use crate::ec::{
    EcComputeKeyFn, EcFieldMulFn, EcFieldSetToOneFn, EcFieldSqrFn, EcGroup,
    EcGroupCheckDiscriminantFn, EcGroupCopyFn, EcGroupFinishFn, EcGroupGetCurveFn, EcGroupInitFn,
    EcGroupQueryFn, EcGroupSetCurveFn, EcKeyCheckFn, EcKeyInitFn, EcKeySignSetupFn, EcKeySignSigFn,
    EcKeyVerifySigFn, EcLadderFn, EcMethod, EcOct2PrivFn, EcPointAddFn, EcPointCmpFn,
    EcPointCopyFn, EcPointDblFn, EcPointFinishFn, EcPointGetAffineFn, EcPointInitFn,
    EcPointIsAtInfinityFn, EcPointIsOnCurveFn, EcPointSetAffineFn, EcPointSetToInfinityFn,
    EcPointUnaryFn, EcPointsMakeAffineFn, EcPriv2OctFn, EC_FLAGS_DEFAULT_OCT,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_X9_62_prime_field;

/// `static const EC_METHOD` — `crypto/ec/ecp_mont.c:23-78`.
///
/// As [`crate::ec::smpl`]'s table, with the five field columns `ecp_mont.c` supplies and the
/// eleven key/ecdh/ecdsa columns D335 measured.
static EC_GFP_MONT_METHOD: EcMethod = EcMethod {
    flags: EC_FLAGS_DEFAULT_OCT,
    field_type: NID_X9_62_prime_field,
    group_init: Some(ossl_ec_GFp_mont_group_init as EcGroupInitFn),
    group_finish: Some(ossl_ec_GFp_mont_group_finish as EcGroupFinishFn),
    group_clear_finish: Some(ossl_ec_GFp_mont_group_clear_finish as EcGroupFinishFn),
    group_copy: Some(ossl_ec_GFp_mont_group_copy as EcGroupCopyFn),
    group_set_curve: Some(ossl_ec_GFp_mont_group_set_curve as EcGroupSetCurveFn),
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
    field_mul: Some(ossl_ec_GFp_mont_field_mul as EcFieldMulFn),
    field_sqr: Some(ossl_ec_GFp_mont_field_sqr as EcFieldSqrFn),
    field_div: None,
    field_inv: Some(ossl_ec_GFp_mont_field_inv as EcFieldSqrFn),
    field_encode: Some(ossl_ec_GFp_mont_field_encode as EcFieldSqrFn),
    field_decode: Some(ossl_ec_GFp_mont_field_decode as EcFieldSqrFn),
    field_set_to_one: Some(ossl_ec_GFp_mont_field_set_to_one as EcFieldSetToOneFn),
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

/// `const EC_METHOD *EC_GFp_mont_method(void)` — `crypto/ec/ecp_mont.c:21-81`.
#[no_mangle]
pub extern "C" fn EC_GFp_mont_method() -> *const EcMethod {
    &EC_GFP_MONT_METHOD
}

/// `int ossl_ec_GFp_mont_group_init(EC_GROUP *group)` — `crypto/ec/ecp_mont.c:83-91`.
///
/// # Safety
///
/// As [`ossl_ec_GFp_simple_group_init`]'s contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_group_init(group: *mut EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ok = ossl_ec_GFp_simple_group_init(group);
        (*group).field_data1 = ptr::null_mut();
        (*group).field_data2 = ptr::null_mut();
        ok
    }
}

/// `void ossl_ec_GFp_mont_group_finish(EC_GROUP *group)` — `crypto/ec/ecp_mont.c:93-100`.
///
/// # Safety
///
/// `group` is live and its `field_data1`/`field_data2` are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_group_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_MONT_CTX_free((*group).field_data1.cast::<MontCtx>());
        (*group).field_data1 = ptr::null_mut();
        BN_free((*group).field_data2.cast::<BigNum>());
        (*group).field_data2 = ptr::null_mut();
        ossl_ec_GFp_simple_group_finish(group);
    }
}

/// `void ossl_ec_GFp_mont_group_clear_finish(EC_GROUP *group)` — `crypto/ec/ecp_mont.c:102-109`.
///
/// # Safety
///
/// As [`ossl_ec_GFp_mont_group_finish`].
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_group_clear_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_MONT_CTX_free((*group).field_data1.cast::<MontCtx>());
        (*group).field_data1 = ptr::null_mut();
        BN_clear_free((*group).field_data2.cast::<BigNum>());
        (*group).field_data2 = ptr::null_mut();
        ossl_ec_GFp_simple_group_clear_finish(group);
    }
}

/// `int ossl_ec_GFp_mont_group_copy(EC_GROUP *dest, const EC_GROUP *src)` —
/// `crypto/ec/ecp_mont.c:111-140`.
///
/// # Safety
///
/// `dest` and `src` are live groups with their own field data.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_group_copy(
    dest: *mut EcGroup,
    src: *const EcGroup,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_MONT_CTX_free((*dest).field_data1.cast::<MontCtx>());
        (*dest).field_data1 = ptr::null_mut();
        BN_clear_free((*dest).field_data2.cast::<BigNum>());
        (*dest).field_data2 = ptr::null_mut();

        if ossl_ec_GFp_simple_group_copy(dest, src) == 0 {
            return 0;
        }

        'err: {
            if !(*src).field_data1.is_null() {
                (*dest).field_data1 = BN_MONT_CTX_new().cast();
                if (*dest).field_data1.is_null() {
                    return 0;
                }
                if BN_MONT_CTX_copy(
                    (*dest).field_data1.cast::<MontCtx>(),
                    (*src).field_data1.cast::<MontCtx>(),
                )
                .is_null()
                {
                    break 'err;
                }
            }
            if !(*src).field_data2.is_null() {
                (*dest).field_data2 = BN_dup((*src).field_data2.cast::<BigNum>()).cast();
                if (*dest).field_data2.is_null() {
                    break 'err;
                }
            }

            return 1;
        }

        BN_MONT_CTX_free((*dest).field_data1.cast::<MontCtx>());
        (*dest).field_data1 = ptr::null_mut();
        0
    }
}

/// `int ossl_ec_GFp_mont_group_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:142-194`.
///
/// # Safety
///
/// `group` is live; `p`, `a`, `b` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_group_set_curve(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut mont: *mut MontCtx;
    let mut one: *mut BigNum = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_MONT_CTX_free((*group).field_data1.cast::<MontCtx>());
        (*group).field_data1 = ptr::null_mut();
        BN_free((*group).field_data2.cast::<BigNum>());
        (*group).field_data2 = ptr::null_mut();

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        'err: {
            mont = BN_MONT_CTX_new();
            if mont.is_null() {
                break 'err;
            }
            if BN_MONT_CTX_set(mont, p, ctx) == 0 {
                raise_site(&err_sites::ECP_MONT_166);
                break 'err;
            }
            one = BN_new();
            if one.is_null() {
                break 'err;
            }
            if BN_to_montgomery(one, BN_value_one(), mont, ctx) == 0 {
                break 'err;
            }

            (*group).field_data1 = mont.cast();
            mont = ptr::null_mut();
            (*group).field_data2 = one.cast();
            one = ptr::null_mut();

            ret = ossl_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

            if ret == 0 {
                BN_MONT_CTX_free((*group).field_data1.cast::<MontCtx>());
                (*group).field_data1 = ptr::null_mut();
                BN_free((*group).field_data2.cast::<BigNum>());
                (*group).field_data2 = ptr::null_mut();
            }
        }

        BN_free(one);
        BN_CTX_free(new_ctx);
        BN_MONT_CTX_free(mont);
    }
    ret
}

/// `int ossl_ec_GFp_mont_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:196-205`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_mul(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data1.is_null() {
            raise_site(&err_sites::ECP_MONT_200);
            return 0;
        }

        BN_mod_mul_montgomery(r, a, b, (*group).field_data1.cast::<MontCtx>(), ctx)
    }
}

/// `int ossl_ec_GFp_mont_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:207-216`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_sqr(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data1.is_null() {
            raise_site(&err_sites::ECP_MONT_211);
            return 0;
        }

        BN_mod_mul_montgomery(r, a, a, (*group).field_data1.cast::<MontCtx>(), ctx)
    }
}

/// `int ossl_ec_GFp_mont_field_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:223-265`.
///
/// # Safety
///
/// `group` is live with `field_data1` set; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_inv(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data1.is_null() {
            return 0;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_secure_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let e = BN_CTX_get(ctx);
        if e.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            /* Inverse in constant time with Fermats Little Theorem */
            if BN_set_word(e, 2) == 0 {
                break 'err;
            }
            if BN_sub(e, (*group).field, e) == 0 {
                break 'err;
            }
            /*-
             * Exponent e is public.
             * No need for scatter-gather or BN_FLG_CONSTTIME.
             */
            if BN_mod_exp_mont(
                r,
                a,
                e,
                (*group).field,
                ctx,
                (*group).field_data1.cast::<MontCtx>(),
            ) == 0
            {
                break 'err;
            }

            /* throw an error on zero */
            if BN_is_zero(r) != 0 {
                raise_site(&err_sites::ECP_MONT_255);
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_mont_field_encode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:267-276`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_encode(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data1.is_null() {
            raise_site(&err_sites::ECP_MONT_271);
            return 0;
        }

        BN_to_montgomery(r, a, (*group).field_data1.cast::<MontCtx>(), ctx)
    }
}

/// `int ossl_ec_GFp_mont_field_decode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_mont.c:278-287`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_decode(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data1.is_null() {
            raise_site(&err_sites::ECP_MONT_282);
            return 0;
        }

        BN_from_montgomery(r, a, (*group).field_data1.cast::<MontCtx>(), ctx)
    }
}

/// `int ossl_ec_GFp_mont_field_set_to_one(const EC_GROUP *group, BIGNUM *r, BN_CTX *ctx)` —
/// `crypto/ec/ecp_mont.c:289-300`.
///
/// # Safety
///
/// `group` is live; `r` is live; `ctx` is unused.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_mont_field_set_to_one(
    group: *const EcGroup,
    r: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let _ = ctx;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*group).field_data2.is_null() {
            raise_site(&err_sites::ECP_MONT_293);
            return 0;
        }

        if BN_copy(r, (*group).field_data2.cast::<BigNum>()).is_null() {
            return 0;
        }
        1
    }
}
