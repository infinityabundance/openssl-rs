//! `crypto/ec/ecp_smpl.c` — the generic prime-field `EC_METHOD`, Phase 8.7.
//!
//! Thirty-two `ossl_ec_GFp_simple_*` internals and the one export `EC_GFp_simple_method`. The
//! table's non-field columns name `ec_lib.c`'s `ossl_ec_group_simple_order_bits` and the eleven
//! `ec_key.c`/`ecdh_ossl.c`/`ecdsa_ossl.c` columns D335 measured, so this unit lands in the same
//! commit as those; the crate is allowed not to compile between the staging branch's sessions.
//!
//! The `ERR_raise` sites this unit reaches are named `err_sites::ECP_SMPL_<line>` after the
//! generator's stem for `crypto/ec/ecp_smpl.c`. `forensics/tools/gen_err_raise_sites.py`'s
//! `COVERED_FILES` does not list this unit yet, so those constants do not exist in
//! `src/runtime/err_sites.rs`; adding the row and regenerating is owed by the commit that lands
//! this module, and the reference here is the coordinate rather than a value.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::{
    BN_add, BN_add_word, BN_cmp, BN_lshift, BN_mod_add, BN_mod_add_quick, BN_mod_inverse,
    BN_mod_lshift1_quick, BN_mod_lshift_quick, BN_mod_mul, BN_mod_sqr, BN_mod_sub_quick,
    BN_mul_word, BN_nnmod, BN_rshift1, BN_ucmp, BN_usub,
};
use crate::bn::bignum::{
    BN_clear_free, BN_copy, BN_free, BN_is_odd, BN_is_one, BN_is_zero, BN_new, BN_num_bits,
    BN_set_negative, BN_set_word, BN_value_one, BN_zero_ex, BigNum,
};
use crate::bn::ctx::{
    BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_secure_new_ex, BN_CTX_start, BnCtx,
};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::ec::ecdh_ossl::ossl_ecdh_simple_compute_key;
use crate::ec::ecdsa_ossl::{
    ossl_ecdsa_simple_sign_setup, ossl_ecdsa_simple_sign_sig, ossl_ecdsa_simple_verify_sig,
};
use crate::ec::key::{
    ossl_ec_key_simple_check_key, ossl_ec_key_simple_generate_key,
    ossl_ec_key_simple_generate_public_key, ossl_ec_key_simple_oct2priv,
    ossl_ec_key_simple_priv2oct,
};
use crate::ec::lib::{
    ossl_ec_group_simple_order_bits, EC_POINT_copy, EC_POINT_dbl, EC_POINT_get_affine_coordinates,
    EC_POINT_invert, EC_POINT_is_at_infinity, EC_POINT_set_Jprojective_coordinates_GFp,
    EC_POINT_set_affine_coordinates, EC_POINT_set_to_infinity,
};
use crate::ec::{
    EcComputeKeyFn, EcFieldMulFn, EcFieldSqrFn, EcGroup, EcGroupCheckDiscriminantFn, EcGroupCopyFn,
    EcGroupFinishFn, EcGroupGetCurveFn, EcGroupInitFn, EcGroupQueryFn, EcGroupSetCurveFn,
    EcKeyCheckFn, EcKeyInitFn, EcKeySignSetupFn, EcKeySignSigFn, EcKeyVerifySigFn, EcLadderFn,
    EcMethod, EcOct2PrivFn, EcPoint, EcPointAddFn, EcPointCmpFn, EcPointCopyFn, EcPointDblFn,
    EcPointFinishFn, EcPointGetAffineFn, EcPointInitFn, EcPointIsAtInfinityFn, EcPointIsOnCurveFn,
    EcPointSetAffineFn, EcPointSetToInfinityFn, EcPointUnaryFn, EcPointsMakeAffineFn, EcPriv2OctFn,
    EC_FLAGS_DEFAULT_OCT,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc_array};
use crate::runtime::obj::NID_X9_62_prime_field;

/// The translation-unit coordinate the two `OPENSSL_malloc_array`/`OPENSSL_free` pairs in
/// `ossl_ec_GFp_simple_points_make_affine` are attributed to, as the allocator reports them.
const FILE: &core::ffi::CStr = c"crypto/ec/ecp_smpl.c";

/// `static const EC_METHOD` — `crypto/ec/ecp_smpl.c:24-79`.
///
/// The table `EC_GFp_simple_method` hands out. Every pointer is `Some` except the eleven the
/// authority leaves NULL (`mul`, `precompute_mult`, `have_precompute_mult`, `field_div`,
/// `field_encode`, `field_decode`, `field_set_to_one`, `set_private`, `keycopy`, `keyfinish`,
/// `field_inverse_mod_ord`), and the eleven columns it names from other units are the cycle
/// D335 measured rather than a transcription gap.
static EC_GFP_SIMPLE_METHOD: EcMethod = EcMethod {
    flags: EC_FLAGS_DEFAULT_OCT,
    field_type: NID_X9_62_prime_field,
    group_init: Some(ossl_ec_GFp_simple_group_init as EcGroupInitFn),
    group_finish: Some(ossl_ec_GFp_simple_group_finish as EcGroupFinishFn),
    group_clear_finish: Some(ossl_ec_GFp_simple_group_clear_finish as EcGroupFinishFn),
    group_copy: Some(ossl_ec_GFp_simple_group_copy as EcGroupCopyFn),
    group_set_curve: Some(ossl_ec_GFp_simple_group_set_curve as EcGroupSetCurveFn),
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
    field_mul: Some(ossl_ec_GFp_simple_field_mul as EcFieldMulFn),
    field_sqr: Some(ossl_ec_GFp_simple_field_sqr as EcFieldSqrFn),
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

/// `const EC_METHOD *EC_GFp_simple_method(void)` — `crypto/ec/ecp_smpl.c:22-82`.
///
/// The table's *address* is the answer, so two calls compare equal.
#[no_mangle]
pub extern "C" fn EC_GFp_simple_method() -> *const EcMethod {
    &EC_GFP_SIMPLE_METHOD
}

/// `int ossl_ec_GFp_simple_group_init(EC_GROUP *group)` — `crypto/ec/ecp_smpl.c:98-111`.
///
/// # Safety
///
/// `group` is a live object whose `field`, `a` and `b` are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_init(group: *mut EcGroup) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*group).field = BN_new();
        (*group).a = BN_new();
        (*group).b = BN_new();
        if (*group).field.is_null() || (*group).a.is_null() || (*group).b.is_null() {
            BN_free((*group).field);
            BN_free((*group).a);
            BN_free((*group).b);
            return 0;
        }
        (*group).a_is_minus3 = 0;
    }
    1
}

/// `void ossl_ec_GFp_simple_group_finish(EC_GROUP *group)` — `crypto/ec/ecp_smpl.c:113-118`.
///
/// # Safety
///
/// `group` is live and its three field elements are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_free((*group).field);
        BN_free((*group).a);
        BN_free((*group).b);
    }
}

/// `void ossl_ec_GFp_simple_group_clear_finish(EC_GROUP *group)` — `crypto/ec/ecp_smpl.c:120-125`.
///
/// # Safety
///
/// As [`ossl_ec_GFp_simple_group_finish`].
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_clear_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*group).field);
        BN_clear_free((*group).a);
        BN_clear_free((*group).b);
    }
}

/// `int ossl_ec_GFp_simple_group_copy(EC_GROUP *dest, const EC_GROUP *src)` —
/// `crypto/ec/ecp_smpl.c:127-139`.
///
/// # Safety
///
/// `dest` and `src` are live groups with their own field elements.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_copy(
    dest: *mut EcGroup,
    src: *const EcGroup,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if BN_copy((*dest).field, (*src).field).is_null() {
            return 0;
        }
        if BN_copy((*dest).a, (*src).a).is_null() {
            return 0;
        }
        if BN_copy((*dest).b, (*src).b).is_null() {
            return 0;
        }
        (*dest).a_is_minus3 = (*src).a_is_minus3;
    }
    1
}

/// `int ossl_ec_GFp_simple_group_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:141-198`.
///
/// # Safety
///
/// `group` is live and its `libctx` is the context the temporary context is made in; `p`, `a`,
/// `b` are live; `ctx` is null or a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_set_curve(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let tmp_a: *mut BigNum;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* p must be a prime > 3 */
        if BN_num_bits(p) <= 2 || BN_is_odd(p) == 0 {
            raise_site(&err_sites::ECP_SMPL_151);
            return 0;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        tmp_a = BN_CTX_get(ctx);
        if tmp_a.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            /* group->field */
            if BN_copy((*group).field, p).is_null() {
                break 'err;
            }
            BN_set_negative((*group).field, 0);

            /* group->a */
            if BN_nnmod(tmp_a, a, p, ctx) == 0 {
                break 'err;
            }
            let meth = (*group).meth;
            if let Some(field_encode) = (*meth).field_encode {
                if field_encode(group, (*group).a, tmp_a, ctx) == 0 {
                    break 'err;
                }
            } else if BN_copy((*group).a, tmp_a).is_null() {
                break 'err;
            }

            /* group->b */
            if BN_nnmod((*group).b, b, p, ctx) == 0 {
                break 'err;
            }
            if let Some(field_encode) = (*meth).field_encode {
                if field_encode(group, (*group).b, (*group).b, ctx) == 0 {
                    break 'err;
                }
            }

            /* group->a_is_minus3 */
            if BN_add_word(tmp_a, 3) == 0 {
                break 'err;
            }
            (*group).a_is_minus3 = c_int::from(BN_cmp(tmp_a, (*group).field) == 0);

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_group_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
/// BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:200-243`.
///
/// # Safety
///
/// `group` is live; `p`, `a`, `b` are null or writable; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_get_curve(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !p.is_null() && BN_copy(p, (*group).field).is_null() {
            return 0;
        }

        if !a.is_null() || !b.is_null() {
            let meth = (*group).meth;
            if (*meth).field_decode.is_some() {
                if ctx.is_null() {
                    new_ctx = BN_CTX_new_ex((*group).libctx);
                    ctx = new_ctx;
                    if ctx.is_null() {
                        return 0;
                    }
                }
                'err: {
                    if !a.is_null()
                        && (*meth)
                            .field_decode
                            .map_or(1, |f| f(group, a, (*group).a, ctx))
                            == 0
                    {
                        break 'err;
                    }
                    if !b.is_null()
                        && (*meth)
                            .field_decode
                            .map_or(1, |f| f(group, b, (*group).b, ctx))
                            == 0
                    {
                        break 'err;
                    }
                    ret = 1;
                }
            } else {
                if !a.is_null() && BN_copy(a, (*group).a).is_null() {
                    BN_CTX_free(new_ctx);
                    return ret;
                }
                if !b.is_null() && BN_copy(b, (*group).b).is_null() {
                    BN_CTX_free(new_ctx);
                    return ret;
                }
                ret = 1;
            }
        } else {
            ret = 1;
        }

        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_group_get_degree(const EC_GROUP *group)` —
/// `crypto/ec/ecp_smpl.c:245-248`.
///
/// # Safety
///
/// `group` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_get_degree(
    group: *const EcGroup,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_num_bits((*group).field) }
}

/// `int ossl_ec_GFp_simple_group_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:250-320`.
///
/// # Safety
///
/// `group` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_group_check_discriminant(
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    let p = unsafe { (*group).field };
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                raise_site(&err_sites::ECP_SMPL_261);
                return ret;
            }
        }
        BN_CTX_start(ctx);
        let a = BN_CTX_get(ctx);
        let b = BN_CTX_get(ctx);
        let tmp_1 = BN_CTX_get(ctx);
        let tmp_2 = BN_CTX_get(ctx);
        let order = BN_CTX_get(ctx);
        if order.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let meth = (*group).meth;
            if (*meth).field_decode.is_some() {
                if (*meth)
                    .field_decode
                    .map_or(1, |f| f(group, a, (*group).a, ctx))
                    == 0
                {
                    break 'err;
                }
                if (*meth)
                    .field_decode
                    .map_or(1, |f| f(group, b, (*group).b, ctx))
                    == 0
                {
                    break 'err;
                }
            } else {
                if BN_copy(a, (*group).a).is_null() {
                    break 'err;
                }
                if BN_copy(b, (*group).b).is_null() {
                    break 'err;
                }
            }

            /*-
             * check the discriminant:
             * y^2 = x^3 + a*x + b is an elliptic curve <=> 4*a^3 + 27*b^2 != 0 (mod p)
             * 0 =< a, b < p
             */
            if BN_is_zero(a) != 0 {
                if BN_is_zero(b) != 0 {
                    break 'err;
                }
            } else if BN_is_zero(b) == 0 {
                if BN_mod_sqr(tmp_1, a, p, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_mul(tmp_2, tmp_1, a, p, ctx) == 0 {
                    break 'err;
                }
                if BN_lshift(tmp_1, tmp_2, 2) == 0 {
                    break 'err;
                }
                /* tmp_1 = 4*a^3 */

                if BN_mod_sqr(tmp_2, b, p, ctx) == 0 {
                    break 'err;
                }
                if BN_mul_word(tmp_2, 27) == 0 {
                    break 'err;
                }
                /* tmp_2 = 27*b^2 */

                if BN_mod_add(a, tmp_1, tmp_2, p, ctx) == 0 {
                    break 'err;
                }
                if BN_is_zero(a) != 0 {
                    break 'err;
                }
            }
            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_point_init(EC_POINT *point)` — `crypto/ec/ecp_smpl.c:322-336`.
///
/// # Safety
///
/// `point` is a live object whose `x`, `y` and `z` are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_init(point: *mut EcPoint) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*point).x = BN_new();
        (*point).y = BN_new();
        (*point).z = BN_new();
        (*point).z_is_one = 0;

        if (*point).x.is_null() || (*point).y.is_null() || (*point).z.is_null() {
            BN_free((*point).x);
            BN_free((*point).y);
            BN_free((*point).z);
            return 0;
        }
    }
    1
}

/// `void ossl_ec_GFp_simple_point_finish(EC_POINT *point)` — `crypto/ec/ecp_smpl.c:338-343`.
///
/// # Safety
///
/// `point` is live and its three coordinates are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_finish(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_free((*point).x);
        BN_free((*point).y);
        BN_free((*point).z);
    }
}

/// `void ossl_ec_GFp_simple_point_clear_finish(EC_POINT *point)` —
/// `crypto/ec/ecp_smpl.c:345-351`.
///
/// # Safety
///
/// As [`ossl_ec_GFp_simple_point_finish`].
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_clear_finish(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*point).x);
        BN_clear_free((*point).y);
        BN_clear_free((*point).z);
        (*point).z_is_one = 0;
    }
}

/// `int ossl_ec_GFp_simple_point_copy(EC_POINT *dest, const EC_POINT *src)` —
/// `crypto/ec/ecp_smpl.c:353-365`.
///
/// # Safety
///
/// `dest` and `src` are live points with their own coordinates.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_copy(
    dest: *mut EcPoint,
    src: *const EcPoint,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if BN_copy((*dest).x, (*src).x).is_null() {
            return 0;
        }
        if BN_copy((*dest).y, (*src).y).is_null() {
            return 0;
        }
        if BN_copy((*dest).z, (*src).z).is_null() {
            return 0;
        }
        (*dest).z_is_one = (*src).z_is_one;
        (*dest).curve_name = (*src).curve_name;
    }
    1
}

/// `int ossl_ec_GFp_simple_point_set_to_infinity(const EC_GROUP *group, EC_POINT *point)` —
/// `crypto/ec/ecp_smpl.c:367-373`.
///
/// # Safety
///
/// `point` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_set_to_infinity(
    group: *const EcGroup,
    point: *mut EcPoint,
) -> c_int {
    let _ = group;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*point).z_is_one = 0;
        BN_zero_ex((*point).z);
    }
    1
}

/// `int ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:375-432`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x`, `y`, `z` are null or live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_set_Jprojective_coordinates_GFp(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    z: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
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

        'err: {
            let meth = (*group).meth;
            if !x.is_null() {
                if BN_nnmod((*point).x, x, (*group).field, ctx) == 0 {
                    break 'err;
                }
                if let Some(field_encode) = (*meth).field_encode {
                    if field_encode(group, (*point).x, (*point).x, ctx) == 0 {
                        break 'err;
                    }
                }
            }

            if !y.is_null() {
                if BN_nnmod((*point).y, y, (*group).field, ctx) == 0 {
                    break 'err;
                }
                if let Some(field_encode) = (*meth).field_encode {
                    if field_encode(group, (*point).y, (*point).y, ctx) == 0 {
                        break 'err;
                    }
                }
            }

            if !z.is_null() {
                if BN_nnmod((*point).z, z, (*group).field, ctx) == 0 {
                    break 'err;
                }
                let z_is_one = BN_is_one((*point).z);
                if let Some(field_encode) = (*meth).field_encode {
                    if z_is_one != 0 && (*meth).field_set_to_one.is_some() {
                        if (*meth)
                            .field_set_to_one
                            .map_or(1, |f| f(group, (*point).z, ctx))
                            == 0
                        {
                            break 'err;
                        }
                    } else if field_encode(group, (*point).z, (*point).z, ctx) == 0 {
                        break 'err;
                    }
                }
                (*point).z_is_one = z_is_one;
            }

            ret = 1;
        }

        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
/// const EC_POINT *point, BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:434-481`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x`, `y`, `z` are null or writable; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_get_Jprojective_coordinates_GFp(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    z: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let meth = (*group).meth;
        if (*meth).field_decode.is_some() {
            if ctx.is_null() {
                new_ctx = BN_CTX_new_ex((*group).libctx);
                ctx = new_ctx;
                if ctx.is_null() {
                    return 0;
                }
            }

            'err: {
                if !x.is_null()
                    && (*meth)
                        .field_decode
                        .map_or(1, |f| f(group, x, (*point).x, ctx))
                        == 0
                {
                    break 'err;
                }
                if !y.is_null()
                    && (*meth)
                        .field_decode
                        .map_or(1, |f| f(group, y, (*point).y, ctx))
                        == 0
                {
                    break 'err;
                }
                if !z.is_null()
                    && (*meth)
                        .field_decode
                        .map_or(1, |f| f(group, z, (*point).z, ctx))
                        == 0
                {
                    break 'err;
                }
                ret = 1;
            }
        } else {
            'err: {
                if !x.is_null() && BN_copy(x, (*point).x).is_null() {
                    break 'err;
                }
                if !y.is_null() && BN_copy(y, (*point).y).is_null() {
                    break 'err;
                }
                if !z.is_null() && BN_copy(z, (*point).z).is_null() {
                    break 'err;
                }
                ret = 1;
            }
        }

        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:483-498`.
///
/// # Safety
///
/// As [`EC_POINT_set_Jprojective_coordinates_GFp`]'s own contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_set_affine_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if x.is_null() || y.is_null() {
            /* unlike for projective coordinates, we do not tolerate this */
            raise_site(&err_sites::ECP_SMPL_492);
            return 0;
        }

        EC_POINT_set_Jprojective_coordinates_GFp(group, point, x, y, BN_value_one(), ctx)
    }
}

/// `int ossl_ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *group,
/// const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:500-610`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x`, `y` are null or writable; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point_get_affine_coordinates(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, point) != 0 {
            raise_site(&err_sites::ECP_SMPL_511);
            return 0;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let z = BN_CTX_get(ctx);
        let z_1 = BN_CTX_get(ctx);
        let z_2 = BN_CTX_get(ctx);
        let z_3 = BN_CTX_get(ctx);
        if z_3.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let meth = (*group).meth;
            /* transform  (X, Y, Z)  into  (x, y) := (X/Z^2, Y/Z^3) */

            let z_: *const BigNum = if (*meth).field_decode.is_some() {
                if (*meth)
                    .field_decode
                    .map_or(1, |f| f(group, z, (*point).z, ctx))
                    == 0
                {
                    break 'err;
                }
                z
            } else {
                (*point).z
            };

            if BN_is_one(z_) != 0 {
                if (*meth).field_decode.is_some() {
                    if !x.is_null()
                        && (*meth)
                            .field_decode
                            .map_or(1, |f| f(group, x, (*point).x, ctx))
                            == 0
                    {
                        break 'err;
                    }
                    if !y.is_null()
                        && (*meth)
                            .field_decode
                            .map_or(1, |f| f(group, y, (*point).y, ctx))
                            == 0
                    {
                        break 'err;
                    }
                } else {
                    if !x.is_null() && BN_copy(x, (*point).x).is_null() {
                        break 'err;
                    }
                    if !y.is_null() && BN_copy(y, (*point).y).is_null() {
                        break 'err;
                    }
                }
            } else {
                let field_inv = match (*meth).field_inv {
                    Some(f) => f,
                    None => break 'err,
                };
                let field_sqr = match (*meth).field_sqr {
                    Some(f) => f,
                    None => break 'err,
                };
                let field_mul = match (*meth).field_mul {
                    Some(f) => f,
                    None => break 'err,
                };

                if field_inv(group, z_1, z_, ctx) == 0 {
                    raise_site(&err_sites::ECP_SMPL_561);
                    break 'err;
                }

                if (*meth).field_encode.is_none() {
                    /* field_sqr works on standard representation */
                    if field_sqr(group, z_2, z_1, ctx) == 0 {
                        break 'err;
                    }
                } else if BN_mod_sqr(z_2, z_1, (*group).field, ctx) == 0 {
                    break 'err;
                }

                if !x.is_null() {
                    /*
                     * in the Montgomery case, field_mul will cancel out Montgomery
                     * factor in X:
                     */
                    if field_mul(group, x, (*point).x, z_2, ctx) == 0 {
                        break 'err;
                    }
                }

                if !y.is_null() {
                    if (*meth).field_encode.is_none() {
                        /* field_mul works on standard representation */
                        if field_mul(group, z_3, z_2, z_1, ctx) == 0 {
                            break 'err;
                        }
                    } else if BN_mod_mul(z_3, z_2, z_1, (*group).field, ctx) == 0 {
                        break 'err;
                    }

                    /*
                     * in the Montgomery case, field_mul will cancel out Montgomery
                     * factor in Y:
                     */
                    if field_mul(group, y, (*point).y, z_3, ctx) == 0 {
                        break 'err;
                    }
                }
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
/// const EC_POINT *b, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:612-795`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live points that may alias; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_add(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if a == b {
            return EC_POINT_dbl(group, r, a, ctx);
        }
        if EC_POINT_is_at_infinity(group, a) != 0 {
            return EC_POINT_copy(r, b);
        }
        if EC_POINT_is_at_infinity(group, b) != 0 {
            return EC_POINT_copy(r, a);
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;
        let p = (*group).field;

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let n0 = BN_CTX_get(ctx);
        let n1 = BN_CTX_get(ctx);
        let n2 = BN_CTX_get(ctx);
        let n3 = BN_CTX_get(ctx);
        let n4 = BN_CTX_get(ctx);
        let n5 = BN_CTX_get(ctx);
        let n6 = BN_CTX_get(ctx);
        if n6.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'end: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'end,
            };
            let _ = (field_mul, field_sqr);

            /*
             * Note that in this function we must not read components of 'a' or 'b'
             * once we have written the corresponding components of 'r'. ('r' might
             * be one of 'a' or 'b'.)
             */

            /* n1, n2 */
            if (*b).z_is_one != 0 {
                if BN_copy(n1, (*a).x).is_null() {
                    break 'end;
                }
                if BN_copy(n2, (*a).y).is_null() {
                    break 'end;
                }
                /* n1 = X_a */
                /* n2 = Y_a */
            } else {
                if field_sqr(group, n0, (*b).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, n1, (*a).x, n0, ctx) == 0 {
                    break 'end;
                }
                /* n1 = X_a * Z_b^2 */

                if field_mul(group, n0, n0, (*b).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, n2, (*a).y, n0, ctx) == 0 {
                    break 'end;
                }
                /* n2 = Y_a * Z_b^3 */
            }

            /* n3, n4 */
            if (*a).z_is_one != 0 {
                if BN_copy(n3, (*b).x).is_null() {
                    break 'end;
                }
                if BN_copy(n4, (*b).y).is_null() {
                    break 'end;
                }
                /* n3 = X_b */
                /* n4 = Y_b */
            } else {
                if field_sqr(group, n0, (*a).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, n3, (*b).x, n0, ctx) == 0 {
                    break 'end;
                }
                /* n3 = X_b * Z_a^2 */

                if field_mul(group, n0, n0, (*a).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, n4, (*b).y, n0, ctx) == 0 {
                    break 'end;
                }
                /* n4 = Y_b * Z_a^3 */
            }

            /* n5, n6 */
            if BN_mod_sub_quick(n5, n1, n3, p) == 0 {
                break 'end;
            }
            if BN_mod_sub_quick(n6, n2, n4, p) == 0 {
                break 'end;
            }
            /* n5 = n1 - n3 */
            /* n6 = n2 - n4 */

            if BN_is_zero(n5) != 0 {
                if BN_is_zero(n6) != 0 {
                    /* a is the same point as b */
                    BN_CTX_end(ctx);
                    ret = EC_POINT_dbl(group, r, a, ctx);
                    ctx = ptr::null_mut();
                    break 'end;
                } else {
                    /* a is the inverse of b */
                    BN_zero_ex((*r).z);
                    (*r).z_is_one = 0;
                    ret = 1;
                    break 'end;
                }
            }

            /* 'n7', 'n8' */
            if BN_mod_add_quick(n1, n1, n3, p) == 0 {
                break 'end;
            }
            if BN_mod_add_quick(n2, n2, n4, p) == 0 {
                break 'end;
            }
            /* 'n7' = n1 + n3 */
            /* 'n8' = n2 + n4 */

            /* Z_r */
            if (*a).z_is_one != 0 && (*b).z_is_one != 0 {
                if BN_copy((*r).z, n5).is_null() {
                    break 'end;
                }
            } else {
                if (*a).z_is_one != 0 {
                    if BN_copy(n0, (*b).z).is_null() {
                        break 'end;
                    }
                } else if (*b).z_is_one != 0 {
                    if BN_copy(n0, (*a).z).is_null() {
                        break 'end;
                    }
                } else if field_mul(group, n0, (*a).z, (*b).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, (*r).z, n0, n5, ctx) == 0 {
                    break 'end;
                }
            }
            (*r).z_is_one = 0;
            /* Z_r = Z_a * Z_b * n5 */

            /* X_r */
            if field_sqr(group, n0, n6, ctx) == 0 {
                break 'end;
            }
            if field_sqr(group, n4, n5, ctx) == 0 {
                break 'end;
            }
            if field_mul(group, n3, n1, n4, ctx) == 0 {
                break 'end;
            }
            if BN_mod_sub_quick((*r).x, n0, n3, p) == 0 {
                break 'end;
            }
            /* X_r = n6^2 - n5^2 * 'n7' */

            /* 'n9' */
            if BN_mod_lshift1_quick(n0, (*r).x, p) == 0 {
                break 'end;
            }
            if BN_mod_sub_quick(n0, n3, n0, p) == 0 {
                break 'end;
            }
            /* n9 = n5^2 * 'n7' - 2 * X_r */

            /* Y_r */
            if field_mul(group, n0, n0, n6, ctx) == 0 {
                break 'end;
            }
            if field_mul(group, n5, n4, n5, ctx) == 0 {
                break 'end; /* now n5 is n5^3 */
            }
            if field_mul(group, n1, n2, n5, ctx) == 0 {
                break 'end;
            }
            if BN_mod_sub_quick(n0, n0, n1, p) == 0 {
                break 'end;
            }
            if BN_is_odd(n0) != 0 && BN_add(n0, n0, p) == 0 {
                break 'end;
            }
            /* now  0 <= n0 < 2*p,  and n0 is even */
            if BN_rshift1((*r).y, n0) == 0 {
                break 'end;
            }
            /* Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 */

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:797-937`.
///
/// # Safety
///
/// `group` is live; `r` and `a` are live points that may alias; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_dbl(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, a) != 0 {
            BN_zero_ex((*r).z);
            (*r).z_is_one = 0;
            return 1;
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;
        let p = (*group).field;

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let n0 = BN_CTX_get(ctx);
        let n1 = BN_CTX_get(ctx);
        let n2 = BN_CTX_get(ctx);
        let n3 = BN_CTX_get(ctx);
        if n3.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'err,
            };

            /*
             * Note that in this function we must not read components of 'a' once we
             * have written the corresponding components of 'r'. ('r' might the same
             * as 'a'.)
             */

            /* n1 */
            if (*a).z_is_one != 0 {
                if field_sqr(group, n0, (*a).x, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_lshift1_quick(n1, n0, p) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n0, n0, n1, p) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n1, n0, (*group).a, p) == 0 {
                    break 'err;
                }
                /* n1 = 3 * X_a^2 + a_curve */
            } else if (*group).a_is_minus3 != 0 {
                if field_sqr(group, n1, (*a).z, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n0, (*a).x, n1, p) == 0 {
                    break 'err;
                }
                if BN_mod_sub_quick(n2, (*a).x, n1, p) == 0 {
                    break 'err;
                }
                if field_mul(group, n1, n0, n2, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_lshift1_quick(n0, n1, p) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n1, n0, n1, p) == 0 {
                    break 'err;
                }
                /*-
                 * n1 = 3 * (X_a + Z_a^2) * (X_a - Z_a^2)
                 *    = 3 * X_a^2 - 3 * Z_a^4
                 */
            } else {
                if field_sqr(group, n0, (*a).x, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_lshift1_quick(n1, n0, p) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n0, n0, n1, p) == 0 {
                    break 'err;
                }
                if field_sqr(group, n1, (*a).z, ctx) == 0 {
                    break 'err;
                }
                if field_sqr(group, n1, n1, ctx) == 0 {
                    break 'err;
                }
                if field_mul(group, n1, n1, (*group).a, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(n1, n1, n0, p) == 0 {
                    break 'err;
                }
                /* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
            }

            /* Z_r */
            if (*a).z_is_one != 0 {
                if BN_copy(n0, (*a).y).is_null() {
                    break 'err;
                }
            } else if field_mul(group, n0, (*a).y, (*a).z, ctx) == 0 {
                break 'err;
            }
            if BN_mod_lshift1_quick((*r).z, n0, p) == 0 {
                break 'err;
            }
            (*r).z_is_one = 0;
            /* Z_r = 2 * Y_a * Z_a */

            /* n2 */
            if field_sqr(group, n3, (*a).y, ctx) == 0 {
                break 'err;
            }
            if field_mul(group, n2, (*a).x, n3, ctx) == 0 {
                break 'err;
            }
            if BN_mod_lshift_quick(n2, n2, 2, p) == 0 {
                break 'err;
            }
            /* n2 = 4 * X_a * Y_a^2 */

            /* X_r */
            if BN_mod_lshift1_quick(n0, n2, p) == 0 {
                break 'err;
            }
            if field_sqr(group, (*r).x, n1, ctx) == 0 {
                break 'err;
            }
            if BN_mod_sub_quick((*r).x, (*r).x, n0, p) == 0 {
                break 'err;
            }
            /* X_r = n1^2 - 2 * n2 */

            /* n3 */
            if field_sqr(group, n0, n3, ctx) == 0 {
                break 'err;
            }
            if BN_mod_lshift_quick(n3, n0, 3, p) == 0 {
                break 'err;
            }
            /* n3 = 8 * Y_a^4 */

            /* Y_r */
            if BN_mod_sub_quick(n0, n2, (*r).x, p) == 0 {
                break 'err;
            }
            if field_mul(group, n0, n1, n0, ctx) == 0 {
                break 'err;
            }
            if BN_mod_sub_quick((*r).y, n0, n3, p) == 0 {
                break 'err;
            }
            /* Y_r = n1 * (n2 - X_r) - n3 */

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_invert(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:939-947`.
///
/// # Safety
///
/// `group` is live; `point` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_invert(
    group: *const EcGroup,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, point) != 0 || BN_is_zero((*point).y) != 0 {
            /* point is its own inverse */
            return 1;
        }

        let _ = ctx;
        BN_usub((*point).y, (*group).field, (*point).y)
    }
}

/// `int ossl_ec_GFp_simple_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)` —
/// `crypto/ec/ecp_smpl.c:949-953`.
///
/// # Safety
///
/// `point` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_is_at_infinity(
    group: *const EcGroup,
    point: *const EcPoint,
) -> c_int {
    let _ = group;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_is_zero((*point).z) }
}

/// `int ossl_ec_GFp_simple_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
/// BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:955-1056`.
///
/// # Safety
///
/// `group` is live; `point` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_is_on_curve(
    group: *const EcGroup,
    point: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret: c_int = -1;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, point) != 0 {
            return 1;
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;
        let p = (*group).field;

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return -1;
            }
        }

        BN_CTX_start(ctx);
        let rh = BN_CTX_get(ctx);
        let tmp = BN_CTX_get(ctx);
        let z4 = BN_CTX_get(ctx);
        let z6 = BN_CTX_get(ctx);
        if z6.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'err,
            };

            /*-
             * We have a curve defined by a Weierstrass equation
             *      y^2 = x^3 + a*x + b.
             * The point to consider is given in Jacobian projective coordinates
             * where  (X, Y, Z)  represents  (x, y) = (X/Z^2, Y/Z^3).
             * Substituting this and multiplying by  Z^6  transforms the above equation into
             *      Y^2 = X^3 + a*X*Z^4 + b*Z^6.
             * To test this, we add up the right-hand side in 'rh'.
             */

            /* rh := X^2 */
            if field_sqr(group, rh, (*point).x, ctx) == 0 {
                break 'err;
            }

            if (*point).z_is_one == 0 {
                if field_sqr(group, tmp, (*point).z, ctx) == 0 {
                    break 'err;
                }
                if field_sqr(group, z4, tmp, ctx) == 0 {
                    break 'err;
                }
                if field_mul(group, z6, z4, tmp, ctx) == 0 {
                    break 'err;
                }

                /* rh := (rh + a*Z^4)*X */
                if (*group).a_is_minus3 != 0 {
                    if BN_mod_lshift1_quick(tmp, z4, p) == 0 {
                        break 'err;
                    }
                    if BN_mod_add_quick(tmp, tmp, z4, p) == 0 {
                        break 'err;
                    }
                    if BN_mod_sub_quick(rh, rh, tmp, p) == 0 {
                        break 'err;
                    }
                    if field_mul(group, rh, rh, (*point).x, ctx) == 0 {
                        break 'err;
                    }
                } else {
                    if field_mul(group, tmp, z4, (*group).a, ctx) == 0 {
                        break 'err;
                    }
                    if BN_mod_add_quick(rh, rh, tmp, p) == 0 {
                        break 'err;
                    }
                    if field_mul(group, rh, rh, (*point).x, ctx) == 0 {
                        break 'err;
                    }
                }

                /* rh := rh + b*Z^6 */
                if field_mul(group, tmp, (*group).b, z6, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(rh, rh, tmp, p) == 0 {
                    break 'err;
                }
            } else {
                /* point->Z_is_one */

                /* rh := (rh + a)*X */
                if BN_mod_add_quick(rh, rh, (*group).a, p) == 0 {
                    break 'err;
                }
                if field_mul(group, rh, rh, (*point).x, ctx) == 0 {
                    break 'err;
                }
                /* rh := rh + b */
                if BN_mod_add_quick(rh, rh, (*group).b, p) == 0 {
                    break 'err;
                }
            }

            /* 'lh' := Y^2 */
            if field_sqr(group, tmp, (*point).y, ctx) == 0 {
                break 'err;
            }

            ret = c_int::from(BN_ucmp(tmp, rh) == 0);
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
/// BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1058-1164`.
///
/// # Safety
///
/// `group` is live; `a` and `b` are live points; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_cmp(
    group: *const EcGroup,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    /*-
     * return values:
     *  -1   error
     *   0   equal (in affine coordinates)
     *   1   not equal
     */
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret: c_int = -1;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, a) != 0 {
            return if EC_POINT_is_at_infinity(group, b) != 0 {
                0
            } else {
                1
            };
        }

        if EC_POINT_is_at_infinity(group, b) != 0 {
            return 1;
        }

        if (*a).z_is_one != 0 && (*b).z_is_one != 0 {
            return if BN_cmp((*a).x, (*b).x) == 0 && BN_cmp((*a).y, (*b).y) == 0 {
                0
            } else {
                1
            };
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return -1;
            }
        }

        BN_CTX_start(ctx);
        let tmp1 = BN_CTX_get(ctx);
        let tmp2 = BN_CTX_get(ctx);
        let za23 = BN_CTX_get(ctx);
        let zb23 = BN_CTX_get(ctx);
        if zb23.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'end: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'end,
            };

            /*-
             * We have to decide whether
             *     (X_a/Z_a^2, Y_a/Z_a^3) = (X_b/Z_b^2, Y_b/Z_b^3),
             * or equivalently, whether
             *     (X_a*Z_b^2, Y_a*Z_b^3) = (X_b*Z_a^2, Y_b*Z_a^3).
             */

            let mut tmp1_: *const BigNum;
            let mut tmp2_: *const BigNum;
            if (*b).z_is_one == 0 {
                if field_sqr(group, zb23, (*b).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, tmp1, (*a).x, zb23, ctx) == 0 {
                    break 'end;
                }
                tmp1_ = tmp1;
            } else {
                tmp1_ = (*a).x;
            }
            if (*a).z_is_one == 0 {
                if field_sqr(group, za23, (*a).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, tmp2, (*b).x, za23, ctx) == 0 {
                    break 'end;
                }
                tmp2_ = tmp2;
            } else {
                tmp2_ = (*b).x;
            }

            /* compare  X_a*Z_b^2  with  X_b*Z_a^2 */
            if BN_cmp(tmp1_, tmp2_) != 0 {
                ret = 1; /* points differ */
                break 'end;
            }

            if (*b).z_is_one == 0 {
                if field_mul(group, zb23, zb23, (*b).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, tmp1, (*a).y, zb23, ctx) == 0 {
                    break 'end;
                }
                /* tmp1_ = tmp1 */
            } else {
                tmp1_ = (*a).y;
            }
            if (*a).z_is_one == 0 {
                if field_mul(group, za23, za23, (*a).z, ctx) == 0 {
                    break 'end;
                }
                if field_mul(group, tmp2, (*b).y, za23, ctx) == 0 {
                    break 'end;
                }
                /* tmp2_ = tmp2 */
            } else {
                tmp2_ = (*b).y;
            }

            /* compare  Y_a*Z_b^3  with  Y_b*Z_a^3 */
            if BN_cmp(tmp1_, tmp2_) != 0 {
                ret = 1; /* points differ */
                break 'end;
            }

            /* points are equal */
            ret = 0;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:1166-1203`.
///
/// # Safety
///
/// `group` is live; `point` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_make_affine(
    group: *const EcGroup,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*point).z_is_one != 0 || EC_POINT_is_at_infinity(group, point) != 0 {
            return 1;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        if y.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            if EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 0 {
                break 'err;
            }
            if EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 0 {
                break 'err;
            }
            if (*point).z_is_one == 0 {
                raise_site(&err_sites::ECP_SMPL_1193);
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_points_make_affine(const EC_GROUP *group, size_t num,
/// EC_POINT *points[], BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1205-1360`.
///
/// # Safety
///
/// `group` is live; `points` is an array of `num` live points; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_points_make_affine(
    group: *const EcGroup,
    num: usize,
    points: *mut *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let prod_z: *mut *mut BigNum;
    let mut ret = 0;
    let mut ctx = ctx;
    let mut i: usize;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if num == 0 {
            return 1;
        }

        let meth = (*group).meth;

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex((*group).libctx);
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let tmp = BN_CTX_get(ctx);
        let tmp_z = BN_CTX_get(ctx);
        if tmp_z.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            prod_z = CRYPTO_malloc_array(
                num,
                core::mem::size_of::<*mut BigNum>(),
                FILE.as_ptr(),
                1229,
            )
            .cast::<*mut BigNum>();
            if prod_z.is_null() {
                break 'err;
            }
            i = 0;
            while i < num {
                *prod_z.add(i) = BN_new();
                if (*prod_z.add(i)).is_null() {
                    break 'err;
                }
                i += 1;
            }

            /*
             * Set each prod_Z[i] to the product of points[0]->Z .. points[i]->Z,
             * skipping any zero-valued inputs (pretend that they're 1).
             */

            if BN_is_zero((**points).z) == 0 {
                if BN_copy(*prod_z, (**points).z).is_null() {
                    break 'err;
                }
            } else if (*meth).field_set_to_one.is_some() {
                if (*meth)
                    .field_set_to_one
                    .map_or(1, |f| f(group, *prod_z, ctx))
                    == 0
                {
                    break 'err;
                }
            } else if BN_set_word(*prod_z, 1) == 0 {
                break 'err;
            }

            i = 1;
            while i < num {
                if BN_is_zero((**points.add(i)).z) == 0 {
                    let field_mul = match (*meth).field_mul {
                        Some(f) => f,
                        None => break 'err,
                    };
                    if field_mul(
                        group,
                        *prod_z.add(i),
                        *prod_z.add(i - 1),
                        (**points.add(i)).z,
                        ctx,
                    ) == 0
                    {
                        break 'err;
                    }
                } else if BN_copy(*prod_z.add(i), *prod_z.add(i - 1)).is_null() {
                    break 'err;
                }
                i += 1;
            }

            /*
             * Now use a single explicit inversion to replace every non-zero
             * points[i]->Z by its inverse.
             */

            let field_inv = match (*meth).field_inv {
                Some(f) => f,
                None => break 'err,
            };
            if field_inv(group, tmp, *prod_z.add(num - 1), ctx) == 0 {
                raise_site(&err_sites::ECP_SMPL_1273);
                break 'err;
            }
            if (*meth).field_encode.is_some() {
                /*
                 * In the Montgomery case, we just turned R*H (representing H) into
                 * 1/(R*H), but we need R*(1/H) (representing 1/H); i.e. we need to
                 * multiply by the Montgomery factor twice.
                 */
                let Some(field_encode) = (*meth).field_encode else {
                    break 'err;
                };
                if field_encode(group, tmp, tmp, ctx) == 0 {
                    break 'err;
                }
                if field_encode(group, tmp, tmp, ctx) == 0 {
                    break 'err;
                }
            }

            i = num - 1;
            while i > 0 {
                /*
                 * Loop invariant: tmp is the product of the inverses of points[0]->Z
                 * .. points[i]->Z (zero-valued inputs skipped).
                 */
                if BN_is_zero((**points.add(i)).z) == 0 {
                    let field_mul = match (*meth).field_mul {
                        Some(f) => f,
                        None => break 'err,
                    };
                    /*
                     * Set tmp_Z to the inverse of points[i]->Z (as product of Z
                     * inverses 0 .. i, Z values 0 .. i - 1).
                     */
                    if field_mul(group, tmp_z, *prod_z.add(i - 1), tmp, ctx) == 0 {
                        break 'err;
                    }
                    /*
                     * Update tmp to satisfy the loop invariant for i - 1.
                     */
                    if field_mul(group, tmp, tmp, (**points.add(i)).z, ctx) == 0 {
                        break 'err;
                    }
                    /* Replace points[i]->Z by its inverse. */
                    if BN_copy((**points.add(i)).z, tmp_z).is_null() {
                        break 'err;
                    }
                }
                i -= 1;
            }

            if BN_is_zero((**points).z) == 0 {
                /* Replace points[0]->Z by its inverse. */
                if BN_copy((**points).z, tmp).is_null() {
                    break 'err;
                }
            }

            /* Finally, fix up the X and Y coordinates for all points. */

            i = 0;
            while i < num {
                let p = *points.add(i);

                if BN_is_zero((*p).z) == 0 {
                    let field_mul = match (*meth).field_mul {
                        Some(f) => f,
                        None => break 'err,
                    };
                    let field_sqr = match (*meth).field_sqr {
                        Some(f) => f,
                        None => break 'err,
                    };
                    /* turn  (X, Y, 1/Z)  into  (X/Z^2, Y/Z^3, 1) */

                    if field_sqr(group, tmp, (*p).z, ctx) == 0 {
                        break 'err;
                    }
                    if field_mul(group, (*p).x, (*p).x, tmp, ctx) == 0 {
                        break 'err;
                    }

                    if field_mul(group, tmp, tmp, (*p).z, ctx) == 0 {
                        break 'err;
                    }
                    if field_mul(group, (*p).y, (*p).y, tmp, ctx) == 0 {
                        break 'err;
                    }

                    if (*meth).field_set_to_one.is_some() {
                        if (*meth)
                            .field_set_to_one
                            .map_or(1, |f| f(group, (*p).z, ctx))
                            == 0
                        {
                            break 'err;
                        }
                    } else if BN_set_word((*p).z, 1) == 0 {
                        break 'err;
                    }
                    (*p).z_is_one = 1;
                }
                i += 1;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
        if !prod_z.is_null() {
            i = 0;
            while i < num {
                if (*prod_z.add(i)).is_null() {
                    break;
                }
                BN_clear_free(*prod_z.add(i));
                i += 1;
            }
            CRYPTO_free(prod_z.cast(), FILE.as_ptr(), 1357);
        }
    }
    ret
}

/// `int ossl_ec_GFp_simple_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1362-1366`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live `BIGNUM`s; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_field_mul(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_mod_mul(r, a, b, (*group).field, ctx) }
}

/// `int ossl_ec_GFp_simple_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1368-1372`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_field_sqr(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_mod_sqr(r, a, (*group).field, ctx) }
}

/// `int ossl_ec_GFp_simple_field_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1380-1418`.
///
/// # Safety
///
/// `group` is live with a secure context's `libctx`; `r` and `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_field_inv(
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
            loop {
                if BN_priv_rand_range_ex(e, (*group).field, 0, ctx) == 0 {
                    break 'err;
                }
                if BN_is_zero(e) == 0 {
                    break;
                }
            }

            let field_mul = match (*(*group).meth).field_mul {
                Some(f) => f,
                None => break 'err,
            };

            /* r := a * e */
            if field_mul(group, r, a, e, ctx) == 0 {
                break 'err;
            }
            /* r := 1/(a * e) */
            if BN_mod_inverse(r, r, (*group).field, ctx).is_null() {
                raise_site(&err_sites::ECP_SMPL_1405);
                break 'err;
            }
            /* r := e/(a * e) = 1/a */
            if field_mul(group, r, r, e, ctx) == 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_blind_coordinates(const EC_GROUP *group, EC_POINT *p, BN_CTX *ctx)` —
/// `crypto/ec/ecp_smpl.c:1427-1473`.
///
/// # Safety
///
/// `group` is live; `p` is live; `ctx` is a live context (the authority dereferences it).
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_blind_coordinates(
    group: *const EcGroup,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_CTX_start(ctx);
        let lambda = BN_CTX_get(ctx);
        let temp = BN_CTX_get(ctx);
        if temp.is_null() {
            raise_site(&err_sites::ECP_SMPL_1438);
            BN_CTX_end(ctx);
            return ret;
        }

        'end: {
            /*-
             * Make sure lambda is not zero.
             * If the RNG fails, we cannot blind but nevertheless want
             * code to continue smoothly and not clobber the error stack.
             */
            loop {
                ERR_set_mark();
                ret = BN_priv_rand_range_ex(lambda, (*group).field, 0, ctx);
                ERR_pop_to_mark();
                if ret == 0 {
                    ret = 1;
                    break 'end;
                }
                if BN_is_zero(lambda) == 0 {
                    break;
                }
            }

            let _meth = (*group).meth;
            let meth = (*group).meth;
            let field_mul = match (*meth).field_mul {
                Some(f) => f,
                None => break 'end,
            };
            let field_sqr = match (*meth).field_sqr {
                Some(f) => f,
                None => break 'end,
            };

            /* if field_encode defined convert between representations */
            if let Some(field_encode) = (*meth).field_encode {
                if field_encode(group, lambda, lambda, ctx) == 0
                    || field_mul(group, (*p).z, (*p).z, lambda, ctx) == 0
                    || field_sqr(group, temp, lambda, ctx) == 0
                    || field_mul(group, (*p).x, (*p).x, temp, ctx) == 0
                    || field_mul(group, temp, temp, lambda, ctx) == 0
                    || field_mul(group, (*p).y, (*p).y, temp, ctx) == 0
                {
                    break 'end;
                }
            } else if field_mul(group, (*p).z, (*p).z, lambda, ctx) == 0
                || field_sqr(group, temp, lambda, ctx) == 0
                || field_mul(group, (*p).x, (*p).x, temp, ctx) == 0
                || field_mul(group, temp, temp, lambda, ctx) == 0
                || field_mul(group, (*p).y, (*p).y, temp, ctx) == 0
            {
                break 'end;
            }

            (*p).z_is_one = 0;
            ret = 1;
        }

        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_ladder_pre(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1490-1545`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_ladder_pre(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let t1 = (*s).z;
        let t2 = (*r).z;
        let t3 = (*s).x;
        let t4 = (*r).x;
        let t5 = (*s).y;

        let meth = (*group).meth;
        let field_sqr = (*meth).field_sqr;
        let field_mul = (*meth).field_mul;

        let ok = {
            let field_sqr = match field_sqr {
                Some(f) => f,
                None => return 0,
            };
            let field_mul = match field_mul {
                Some(f) => f,
                None => return 0,
            };

            (*p).z_is_one != 0 /* r := 2p */
                && field_sqr(group, t3, (*p).x, ctx) != 0
                && BN_mod_sub_quick(t4, t3, (*group).a, (*group).field) != 0
                && field_sqr(group, t4, t4, ctx) != 0
                && field_mul(group, t5, (*p).x, (*group).b, ctx) != 0
                && BN_mod_lshift_quick(t5, t5, 3, (*group).field) != 0
                /* r->X coord output */
                && BN_mod_sub_quick((*r).x, t4, t5, (*group).field) != 0
                && BN_mod_add_quick(t1, t3, (*group).a, (*group).field) != 0
                && field_mul(group, t2, (*p).x, t1, ctx) != 0
                && BN_mod_add_quick(t2, (*group).b, t2, (*group).field) != 0
                /* r->Z coord output */
                && BN_mod_lshift_quick((*r).z, t2, 2, (*group).field) != 0
        };
        if !ok {
            return 0;
        }

        /* make sure lambda (r->Y here for storage) is not zero */
        loop {
            if BN_priv_rand_range_ex((*r).y, (*group).field, 0, ctx) == 0 {
                return 0;
            }
            if BN_is_zero((*r).y) == 0 {
                break;
            }
        }

        /* make sure lambda (s->Z here for storage) is not zero */
        loop {
            if BN_priv_rand_range_ex((*s).z, (*group).field, 0, ctx) == 0 {
                return 0;
            }
            if BN_is_zero((*s).z) == 0 {
                break;
            }
        }

        /* if field_encode defined convert between representations */
        if let Some(field_encode) = (*meth).field_encode {
            if field_encode(group, (*r).y, (*r).y, ctx) == 0
                || field_encode(group, (*s).z, (*s).z, ctx) == 0
            {
                return 0;
            }
        }

        let field_mul = match (*meth).field_mul {
            Some(f) => f,
            None => return 0,
        };

        /* blind r and s independently */
        if field_mul(group, (*r).z, (*r).z, (*r).y, ctx) == 0
            || field_mul(group, (*r).x, (*r).x, (*r).y, ctx) == 0
            || field_mul(group, (*s).x, (*p).x, (*s).z, ctx) == 0
        /* s := p */
        {
            return 0;
        }

        (*r).z_is_one = 0;
        (*s).z_is_one = 0;

        1
    }
}

/// `int ossl_ec_GFp_simple_ladder_step(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1560-1623`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_ladder_step(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_CTX_start(ctx);
        let t0 = BN_CTX_get(ctx);
        let t1 = BN_CTX_get(ctx);
        let t2 = BN_CTX_get(ctx);
        let t3 = BN_CTX_get(ctx);
        let t4 = BN_CTX_get(ctx);
        let t5 = BN_CTX_get(ctx);
        let t6 = BN_CTX_get(ctx);

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;

        'err: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'err,
            };

            if t6.is_null()
                || field_mul(group, t6, (*r).x, (*s).x, ctx) == 0
                || field_mul(group, t0, (*r).z, (*s).z, ctx) == 0
                || field_mul(group, t4, (*r).x, (*s).z, ctx) == 0
                || field_mul(group, t3, (*r).z, (*s).x, ctx) == 0
                || field_mul(group, t5, (*group).a, t0, ctx) == 0
                || BN_mod_add_quick(t5, t6, t5, (*group).field) == 0
                || BN_mod_add_quick(t6, t3, t4, (*group).field) == 0
                || field_mul(group, t5, t6, t5, ctx) == 0
                || field_sqr(group, t0, t0, ctx) == 0
                || BN_mod_lshift_quick(t2, (*group).b, 2, (*group).field) == 0
                || field_mul(group, t0, t2, t0, ctx) == 0
                || BN_mod_lshift1_quick(t5, t5, (*group).field) == 0
                || BN_mod_sub_quick(t3, t4, t3, (*group).field) == 0
                /* s->Z coord output */
                || field_sqr(group, (*s).z, t3, ctx) == 0
                || field_mul(group, t4, (*s).z, (*p).x, ctx) == 0
                || BN_mod_add_quick(t0, t0, t5, (*group).field) == 0
                /* s->X coord output */
                || BN_mod_sub_quick((*s).x, t0, t4, (*group).field) == 0
                || field_sqr(group, t4, (*r).x, ctx) == 0
                || field_sqr(group, t5, (*r).z, ctx) == 0
                || field_mul(group, t6, t5, (*group).a, ctx) == 0
                || BN_mod_add_quick(t1, (*r).x, (*r).z, (*group).field) == 0
                || field_sqr(group, t1, t1, ctx) == 0
                || BN_mod_sub_quick(t1, t1, t4, (*group).field) == 0
                || BN_mod_sub_quick(t1, t1, t5, (*group).field) == 0
                || BN_mod_sub_quick(t3, t4, t6, (*group).field) == 0
                || field_sqr(group, t3, t3, ctx) == 0
                || field_mul(group, t0, t5, t1, ctx) == 0
                || field_mul(group, t0, t2, t0, ctx) == 0
                /* r->X coord output */
                || BN_mod_sub_quick((*r).x, t3, t0, (*group).field) == 0
                || BN_mod_add_quick(t3, t4, t6, (*group).field) == 0
                || field_sqr(group, t4, t5, ctx) == 0
                || field_mul(group, t4, t4, t2, ctx) == 0
                || field_mul(group, t1, t1, t3, ctx) == 0
                || BN_mod_lshift1_quick(t1, t1, (*group).field) == 0
                /* r->Z coord output */
                || BN_mod_add_quick((*r).z, t4, t1, (*group).field) == 0
            {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
    }
    ret
}

/// `int ossl_ec_GFp_simple_ladder_post(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ecp_smpl.c:1648-1720`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_ladder_post(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if BN_is_zero((*r).z) != 0 {
            return EC_POINT_set_to_infinity(group, r);
        }

        if BN_is_zero((*s).z) != 0 {
            if EC_POINT_copy(r, p) == 0 || EC_POINT_invert(group, r, ctx) == 0 {
                return 0;
            }
            return 1;
        }

        BN_CTX_start(ctx);
        let t0 = BN_CTX_get(ctx);
        let t1 = BN_CTX_get(ctx);
        let t2 = BN_CTX_get(ctx);
        let t3 = BN_CTX_get(ctx);
        let t4 = BN_CTX_get(ctx);
        let t5 = BN_CTX_get(ctx);
        let t6 = BN_CTX_get(ctx);

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;

        'err: {
            let (field_mul, field_sqr) = match (field_mul, field_sqr) {
                (Some(m), Some(s)) => (m, s),
                _ => break 'err,
            };
            let field_inv = match (*meth).field_inv {
                Some(f) => f,
                None => break 'err,
            };

            if t6.is_null()
                || BN_mod_lshift1_quick(t4, (*p).y, (*group).field) == 0
                || field_mul(group, t6, (*r).x, t4, ctx) == 0
                || field_mul(group, t6, (*s).z, t6, ctx) == 0
                || field_mul(group, t5, (*r).z, t6, ctx) == 0
                || BN_mod_lshift1_quick(t1, (*group).b, (*group).field) == 0
                || field_mul(group, t1, (*s).z, t1, ctx) == 0
                || field_sqr(group, t3, (*r).z, ctx) == 0
                || field_mul(group, t2, t3, t1, ctx) == 0
                || field_mul(group, t6, (*r).z, (*group).a, ctx) == 0
                || field_mul(group, t1, (*p).x, (*r).x, ctx) == 0
                || BN_mod_add_quick(t1, t1, t6, (*group).field) == 0
                || field_mul(group, t1, (*s).z, t1, ctx) == 0
                || field_mul(group, t0, (*p).x, (*r).z, ctx) == 0
                || BN_mod_add_quick(t6, (*r).x, t0, (*group).field) == 0
                || field_mul(group, t6, t6, t1, ctx) == 0
                || BN_mod_add_quick(t6, t6, t2, (*group).field) == 0
                || BN_mod_sub_quick(t0, t0, (*r).x, (*group).field) == 0
                || field_sqr(group, t0, t0, ctx) == 0
                || field_mul(group, t0, t0, (*s).x, ctx) == 0
                || BN_mod_sub_quick(t0, t6, t0, (*group).field) == 0
                || field_mul(group, t1, (*s).z, t4, ctx) == 0
                || field_mul(group, t1, t3, t1, ctx) == 0
                || ((*meth).field_decode.is_some()
                    && (*meth).field_decode.map_or(1, |f| f(group, t1, t1, ctx)) == 0)
                || field_inv(group, t1, t1, ctx) == 0
                || ((*meth).field_encode.is_some()
                    && (*meth).field_encode.map_or(1, |f| f(group, t1, t1, ctx)) == 0)
                || field_mul(group, (*r).x, t5, t1, ctx) == 0
                || field_mul(group, (*r).y, t0, t1, ctx) == 0
            {
                break 'err;
            }

            if (*meth).field_set_to_one.is_some() {
                if (*meth)
                    .field_set_to_one
                    .map_or(1, |f| f(group, (*r).z, ctx))
                    == 0
                {
                    break 'err;
                }
            } else if BN_set_word((*r).z, 1) == 0 {
                break 'err;
            }

            (*r).z_is_one = 1;
            ret = 1;
        }

        BN_CTX_end(ctx);
    }
    ret
}
