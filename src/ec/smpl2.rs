//! `crypto/ec/ec2_smpl.c` and `crypto/ec/ec2_oct.c` — the binary-field `EC_METHOD` and its octet
//! conversion, Phase 8.7.
//!
//! Twenty-six `ossl_ec_GF2m_simple_*` internals plus the five file statics (`ec_GF2m_simple_*`),
//! and the export `EC_GF2m_simple_method`. `ec2_oct.c`'s three internals live here too: the plan's
//! §2c names one module for both units. The four `BN_GF2m_mod_{sqrt,solve_quad}_arr` callees are
//! Phase 5's and Phase 9's ledger (§3's deferral rows).
//!
//! The `ERR_raise` sites are named `err_sites::EC2_SMPL_<line>` and `err_sites::EC2_OCT_<line>`;
//! neither is in `gen_err_raise_sites.py`'s `COVERED_FILES` yet.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::bn::arith::{BN_cmp, BN_ucmp};
use crate::bn::bignum::{
    bn_wexpand, BN_bin2bn, BN_bn2bin, BN_clear_free, BN_copy, BN_free, BN_is_odd, BN_is_zero,
    BN_new, BN_num_bits, BN_set_negative, BN_value_one, BN_zero_ex, BigNum,
};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new, BN_CTX_start, BnCtx};
use crate::bn::gf2m::{
    BN_GF2m_add, BN_GF2m_mod_arr, BN_GF2m_mod_div, BN_GF2m_mod_inv, BN_GF2m_mod_mul_arr,
    BN_GF2m_mod_solve_quad_arr, BN_GF2m_mod_sqr_arr, BN_GF2m_mod_sqrt_arr, BN_GF2m_poly2arr,
};
use crate::bn::intern::bn_set_all_zero;
use crate::bn::rand::{BN_priv_rand_ex, BN_RAND_BOTTOM_ANY, BN_RAND_TOP_ANY};
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
    ossl_ec_group_simple_order_bits, EC_GROUP_get_degree, EC_POINT_add, EC_POINT_copy,
    EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_invert, EC_POINT_is_at_infinity,
    EC_POINT_new, EC_POINT_set_affine_coordinates, EC_POINT_set_to_infinity,
};
use crate::ec::mult::{ossl_ec_scalar_mul_ladder, ossl_ec_wNAF_mul};
use crate::ec::{
    EcComputeKeyFn, EcFieldMulFn, EcFieldSqrFn, EcGroup, EcGroupCheckDiscriminantFn, EcGroupCopyFn,
    EcGroupFinishFn, EcGroupGetCurveFn, EcGroupInitFn, EcGroupQueryFn, EcGroupSetCurveFn,
    EcKeyCheckFn, EcKeyInitFn, EcKeySignSetupFn, EcKeySignSigFn, EcKeyVerifySigFn, EcLadderFn,
    EcMethod, EcOct2PointFn, EcOct2PrivFn, EcPoint, EcPoint2OctFn, EcPointAddFn, EcPointCmpFn,
    EcPointCopyFn, EcPointDblFn, EcPointFinishFn, EcPointGetAffineFn, EcPointInitFn,
    EcPointIsAtInfinityFn, EcPointIsOnCurveFn, EcPointMulFn, EcPointSetAffineFn,
    EcPointSetCompressedFn, EcPointSetToInfinityFn, EcPointUnaryFn, EcPointsMakeAffineFn,
    EcPriv2OctFn, PointConversionForm, EC_FLAGS_DEFAULT_OCT, POINT_CONVERSION_COMPRESSED,
    POINT_CONVERSION_HYBRID, POINT_CONVERSION_UNCOMPRESSED,
};
use crate::runtime::err::err_reasons::BN_R_NO_SOLUTION;
use crate::runtime::err::err_sites;
use crate::runtime::err::{
    peek_last_lib, peek_last_reason, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::obj::NID_X9_62_characteristic_two_field;

/// `ERR_LIB_BN` — `include/openssl/err.h`, the library the two `BN_R_NO_SOLUTION`/`BN_R_NOT_A_SQUARE`
/// dispatches test against.
const ERR_LIB_BN: c_int = 3;

/// `BN_BITS2` — `crypto/bn/bn_local.h:93`, the 64-bit profile's limb width. Used only to size
/// `bn_wexpand` calls exactly as `ec2_smpl.c` sizes them.
const BN_BITS2: c_int = 64;

/// `int ossl_ec_GF2m_simple_group_init(EC_GROUP *group)` — `crypto/ec/ec2_smpl.c:28-41`.
///
/// # Safety
///
/// As [`crate::ec::smpl::ossl_ec_GFp_simple_group_init`]'s contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_init(group: *mut EcGroup) -> c_int {
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
    }
    1
}

/// `void ossl_ec_GF2m_simple_group_finish(EC_GROUP *group)` — `crypto/ec/ec2_smpl.c:47-52`.
///
/// # Safety
///
/// `group` is live and its three field elements are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_free((*group).field);
        BN_free((*group).a);
        BN_free((*group).b);
    }
}

/// `void ossl_ec_GF2m_simple_group_clear_finish(EC_GROUP *group)` — `crypto/ec/ec2_smpl.c:58-69`.
///
/// # Safety
///
/// As [`ossl_ec_GF2m_simple_group_finish`].
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_clear_finish(group: *mut EcGroup) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*group).field);
        BN_clear_free((*group).a);
        BN_clear_free((*group).b);
        (*group).poly = [0, 0, 0, 0, 0, -1];
    }
}

/// `int ossl_ec_GF2m_simple_group_copy(EC_GROUP *dest, const EC_GROUP *src)` —
/// `crypto/ec/ec2_smpl.c:75-96`.
///
/// # Safety
///
/// `dest` and `src` are live groups with their own field elements.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_copy(
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
        (*dest).poly = (*src).poly;
        if bn_wexpand((*dest).a, ((*dest).poly[0] + BN_BITS2 - 1) / BN_BITS2).is_null() {
            return 0;
        }
        if bn_wexpand((*dest).b, ((*dest).poly[0] + BN_BITS2 - 1) / BN_BITS2).is_null() {
            return 0;
        }
        bn_set_all_zero((*dest).a);
        bn_set_all_zero((*dest).b);
    }
    1
}

/// `int ossl_ec_GF2m_simple_group_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:99-133`.
///
/// # Safety
///
/// `group` is live; `p`, `a`, `b` are live; `ctx` is unused.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_set_curve(
    group: *mut EcGroup,
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let _ = ctx;
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        'err: {
            /* group->field */
            if BN_copy((*group).field, p).is_null() {
                break 'err;
            }
            let i = BN_GF2m_poly2arr((*group).field, (*group).poly.as_mut_ptr(), 6) - 1;
            if i != 5 && i != 3 {
                raise_site(&err_sites::EC2_SMPL_110);
                break 'err;
            }

            /* group->a */
            if BN_GF2m_mod_arr((*group).a, a, (*group).poly.as_ptr()) == 0 {
                break 'err;
            }
            if bn_wexpand((*group).a, ((*group).poly[0] + BN_BITS2 - 1) / BN_BITS2).is_null() {
                break 'err;
            }
            bn_set_all_zero((*group).a);

            /* group->b */
            if BN_GF2m_mod_arr((*group).b, b, (*group).poly.as_ptr()) == 0 {
                break 'err;
            }
            if bn_wexpand((*group).b, ((*group).poly[0] + BN_BITS2 - 1) / BN_BITS2).is_null() {
                break 'err;
            }
            bn_set_all_zero((*group).b);

            ret = 1;
        }
    }
    ret
}

/// `int ossl_ec_GF2m_simple_group_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
/// BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:139-163`.
///
/// # Safety
///
/// `group` is live; `p`, `a`, `b` are null or writable.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_get_curve(
    group: *const EcGroup,
    p: *mut BigNum,
    a: *mut BigNum,
    b: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let _ = ctx;
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if !p.is_null() && BN_copy(p, (*group).field).is_null() {
            return 0;
        }

        'err: {
            if !a.is_null() && BN_copy(a, (*group).a).is_null() {
                break 'err;
            }

            if !b.is_null() && BN_copy(b, (*group).b).is_null() {
                break 'err;
            }

            ret = 1;
        }
    }
    ret
}

/// `int ossl_ec_GF2m_simple_group_get_degree(const EC_GROUP *group)` —
/// `crypto/ec/ec2_smpl.c:169-172`.
///
/// # Safety
///
/// `group` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_get_degree(
    group: *const EcGroup,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_num_bits((*group).field) - 1 }
}

/// `int ossl_ec_GF2m_simple_group_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)` —
/// `crypto/ec/ec2_smpl.c:178-217`.
///
/// # Safety
///
/// `group` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_group_check_discriminant(
    group: *const EcGroup,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                raise_site(&err_sites::EC2_SMPL_189);
                return ret;
            }
        }
        BN_CTX_start(ctx);
        let b = BN_CTX_get(ctx);
        if b.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            if BN_GF2m_mod_arr(b, (*group).b, (*group).poly.as_ptr()) == 0 {
                break 'err;
            }

            /*
             * check the discriminant: y^2 + x*y = x^3 + a*x^2 + b is an elliptic
             * curve <=> b != 0 (mod p)
             */
            if BN_is_zero(b) != 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GF2m_simple_point_init(EC_POINT *point)` — `crypto/ec/ec2_smpl.c:220-233`.
///
/// # Safety
///
/// As [`crate::ec::smpl::ossl_ec_GFp_simple_point_init`]'s contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_init(point: *mut EcPoint) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        (*point).x = BN_new();
        (*point).y = BN_new();
        (*point).z = BN_new();

        if (*point).x.is_null() || (*point).y.is_null() || (*point).z.is_null() {
            BN_free((*point).x);
            BN_free((*point).y);
            BN_free((*point).z);
            return 0;
        }
    }
    1
}

/// `void ossl_ec_GF2m_simple_point_finish(EC_POINT *point)` — `crypto/ec/ec2_smpl.c:236-241`.
///
/// # Safety
///
/// `point` is live and its coordinates are NULL or owned by it.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_finish(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_free((*point).x);
        BN_free((*point).y);
        BN_free((*point).z);
    }
}

/// `void ossl_ec_GF2m_simple_point_clear_finish(EC_POINT *point)` — `crypto/ec/ec2_smpl.c:244-250`.
///
/// # Safety
///
/// As [`ossl_ec_GF2m_simple_point_finish`].
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_clear_finish(point: *mut EcPoint) {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        BN_clear_free((*point).x);
        BN_clear_free((*point).y);
        BN_clear_free((*point).z);
        (*point).z_is_one = 0;
    }
}

/// `int ossl_ec_GF2m_simple_point_copy(EC_POINT *dest, const EC_POINT *src)` —
/// `crypto/ec/ec2_smpl.c:256-268`.
///
/// # Safety
///
/// As [`crate::ec::smpl::ossl_ec_GFp_simple_point_copy`]'s contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_copy(
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

/// `int ossl_ec_GF2m_simple_point_set_to_infinity(const EC_GROUP *group, EC_POINT *point)` —
/// `crypto/ec/ec2_smpl.c:274-280`.
///
/// # Safety
///
/// `point` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_set_to_infinity(
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

/// `int ossl_ec_GF2m_simple_point_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:286-312`.
///
/// # Safety
///
/// `point` is live; `x` and `y` are live; `group` and `ctx` are unused.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_set_affine_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let _ = (group, ctx);
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if x.is_null() || y.is_null() {
            raise_site(&err_sites::EC2_SMPL_294);
            return 0;
        }

        'err: {
            if BN_copy((*point).x, x).is_null() {
                break 'err;
            }
            BN_set_negative((*point).x, 0);
            if BN_copy((*point).y, y).is_null() {
                break 'err;
            }
            BN_set_negative((*point).y, 0);
            if BN_copy((*point).z, BN_value_one()).is_null() {
                break 'err;
            }
            BN_set_negative((*point).z, 0);
            (*point).z_is_one = 1;
            ret = 1;
        }
    }
    ret
}

/// `int ossl_ec_GF2m_simple_point_get_affine_coordinates(const EC_GROUP *group,
/// const EC_POINT *point, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:318-348`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x`, `y` are null or writable.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point_get_affine_coordinates(
    group: *const EcGroup,
    point: *const EcPoint,
    x: *mut BigNum,
    y: *mut BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let _ = ctx;
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, point) != 0 {
            raise_site(&err_sites::EC2_SMPL_326);
            return 0;
        }

        if BN_cmp((*point).z, BN_value_one()) != 0 {
            raise_site(&err_sites::EC2_SMPL_331);
            return 0;
        }

        'err: {
            if !x.is_null() {
                if BN_copy(x, (*point).x).is_null() {
                    break 'err;
                }
                BN_set_negative(x, 0);
            }
            if !y.is_null() {
                if BN_copy(y, (*point).y).is_null() {
                    break 'err;
                }
                BN_set_negative(y, 0);
            }
            ret = 1;
        }
    }
    ret
}

/// `int ossl_ec_GF2m_simple_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
/// const EC_POINT *b, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:354-469`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live points that may alias; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_add(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, a) != 0 {
            if EC_POINT_copy(r, b) == 0 {
                return 0;
            }
            return 1;
        }

        if EC_POINT_is_at_infinity(group, b) != 0 {
            if EC_POINT_copy(r, a) == 0 {
                return 0;
            }
            return 1;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let x0 = BN_CTX_get(ctx);
        let y0 = BN_CTX_get(ctx);
        let x1 = BN_CTX_get(ctx);
        let y1 = BN_CTX_get(ctx);
        let x2 = BN_CTX_get(ctx);
        let y2 = BN_CTX_get(ctx);
        let s = BN_CTX_get(ctx);
        let t = BN_CTX_get(ctx);
        if t.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let meth = (*group).meth;
            let field_div = match (*meth).field_div {
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

            if (*a).z_is_one != 0 {
                if BN_copy(x0, (*a).x).is_null() {
                    break 'err;
                }
                if BN_copy(y0, (*a).y).is_null() {
                    break 'err;
                }
            } else if EC_POINT_get_affine_coordinates(group, a, x0, y0, ctx) == 0 {
                break 'err;
            }
            if (*b).z_is_one != 0 {
                if BN_copy(x1, (*b).x).is_null() {
                    break 'err;
                }
                if BN_copy(y1, (*b).y).is_null() {
                    break 'err;
                }
            } else if EC_POINT_get_affine_coordinates(group, b, x1, y1, ctx) == 0 {
                break 'err;
            }

            if BN_ucmp(x0, x1) != 0 {
                if BN_GF2m_add(t, x0, x1) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(s, y0, y1) == 0 {
                    break 'err;
                }
                if field_div(group, s, s, t, ctx) == 0 {
                    break 'err;
                }
                if field_sqr(group, x2, s, ctx) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(x2, x2, (*group).a) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(x2, x2, s) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(x2, x2, t) == 0 {
                    break 'err;
                }
            } else {
                if BN_ucmp(y0, y1) != 0 || BN_is_zero(x1) != 0 {
                    if EC_POINT_set_to_infinity(group, r) == 0 {
                        break 'err;
                    }
                    ret = 1;
                    break 'err;
                }
                if field_div(group, s, y1, x1, ctx) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(s, s, x1) == 0 {
                    break 'err;
                }

                if field_sqr(group, x2, s, ctx) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(x2, x2, s) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(x2, x2, (*group).a) == 0 {
                    break 'err;
                }
            }

            if BN_GF2m_add(y2, x1, x2) == 0 {
                break 'err;
            }
            if field_mul(group, y2, y2, s, ctx) == 0 {
                break 'err;
            }
            if BN_GF2m_add(y2, y2, x2) == 0 {
                break 'err;
            }
            if BN_GF2m_add(y2, y2, y1) == 0 {
                break 'err;
            }

            if EC_POINT_set_affine_coordinates(group, r, x2, y2, ctx) == 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GF2m_simple_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:475-479`.
///
/// # Safety
///
/// As [`ossl_ec_GF2m_simple_add`]'s contract.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_dbl(
    group: *const EcGroup,
    r: *mut EcPoint,
    a: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { ossl_ec_GF2m_simple_add(group, r, a, a, ctx) }
}

/// `int ossl_ec_GF2m_simple_invert(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ec2_smpl.c:481-492`.
///
/// # Safety
///
/// `group` is live; `point` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_invert(
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

        match (*(*group).meth).make_affine {
            Some(make_affine) => {
                if make_affine(group, point, ctx) == 0 {
                    return 0;
                }
            }
            None => return 0,
        }
        BN_GF2m_add((*point).y, (*point).x, (*point).y)
    }
}

/// `int ossl_ec_GF2m_simple_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)` —
/// `crypto/ec/ec2_smpl.c:495-499`.
///
/// # Safety
///
/// `point` is live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_is_at_infinity(
    group: *const EcGroup,
    point: *const EcPoint,
) -> c_int {
    let _ = group;
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_is_zero((*point).z) }
}

/// `int ossl_ec_GF2m_simple_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:506-570`.
///
/// # Safety
///
/// `group` is live; `point` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_is_on_curve(
    group: *const EcGroup,
    point: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int = -1;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if EC_POINT_is_at_infinity(group, point) != 0 {
            return 1;
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;

        /* only support affine coordinates */
        if (*point).z_is_one == 0 {
            return -1;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                return -1;
            }
        }

        BN_CTX_start(ctx);
        let y2 = BN_CTX_get(ctx);
        let lh = BN_CTX_get(ctx);
        if lh.is_null() {
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
             *      y^2 + x*y = x^3 + a*x^2 + b.
             *  <=> x^3 + a*x^2 + x*y + b + y^2 = 0
             *  <=> ((x + a) * x + y) * x + b + y^2 = 0
             */
            if BN_GF2m_add(lh, (*point).x, (*group).a) == 0 {
                break 'err;
            }
            if field_mul(group, lh, lh, (*point).x, ctx) == 0 {
                break 'err;
            }
            if BN_GF2m_add(lh, lh, (*point).y) == 0 {
                break 'err;
            }
            if field_mul(group, lh, lh, (*point).x, ctx) == 0 {
                break 'err;
            }
            if BN_GF2m_add(lh, lh, (*group).b) == 0 {
                break 'err;
            }
            if field_sqr(group, y2, (*point).y, ctx) == 0 {
                break 'err;
            }
            if BN_GF2m_add(lh, lh, y2) == 0 {
                break 'err;
            }
            ret = BN_is_zero(lh);
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GF2m_simple_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:579-627`.
///
/// # Safety
///
/// `group` is live; `a` and `b` are live points; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_cmp(
    group: *const EcGroup,
    a: *const EcPoint,
    b: *const EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret: c_int = -1;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
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

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                return -1;
            }
        }

        BN_CTX_start(ctx);
        let ax = BN_CTX_get(ctx);
        let ay = BN_CTX_get(ctx);
        let bx = BN_CTX_get(ctx);
        let by = BN_CTX_get(ctx);
        if by.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            if EC_POINT_get_affine_coordinates(group, a, ax, ay, ctx) == 0 {
                break 'err;
            }
            if EC_POINT_get_affine_coordinates(group, b, bx, by, ctx) == 0 {
                break 'err;
            }
            ret = if BN_cmp(ax, bx) == 0 && BN_cmp(ay, by) == 0 {
                0
            } else {
                1
            };
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GF2m_simple_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)` —
/// `crypto/ec/ec2_smpl.c:630-674`.
///
/// # Safety
///
/// `group` is live; `point` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_make_affine(
    group: *const EcGroup,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if (*point).z_is_one != 0 || EC_POINT_is_at_infinity(group, point) != 0 {
            return 1;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
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
            if BN_copy((*point).x, x).is_null() {
                break 'err;
            }
            if BN_copy((*point).y, y).is_null() {
                break 'err;
            }
            if crate::bn::bignum::BN_set_word((*point).z, 1) == 0 {
                break 'err;
            }
            (*point).z_is_one = 1;

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `int ossl_ec_GF2m_simple_points_make_affine(const EC_GROUP *group, size_t num,
/// EC_POINT *points[], BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:679-690`.
///
/// # Safety
///
/// `group` is live; `points` is an array of `num` live points; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_points_make_affine(
    group: *const EcGroup,
    num: usize,
    points: *mut *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        for i in 0..num {
            let f = match (*(*group).meth).make_affine {
                Some(f) => f,
                None => return 0,
            };
            if f(group, *points.add(i), ctx) == 0 {
                return 0;
            }
        }
    }
    1
}

/// `int ossl_ec_GF2m_simple_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:693-697`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_field_mul(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_GF2m_mod_mul_arr(r, a, b, (*group).poly.as_ptr(), ctx) }
}

/// `int ossl_ec_GF2m_simple_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:700-704`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_field_sqr(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_GF2m_mod_sqr_arr(r, a, (*group).poly.as_ptr(), ctx) }
}

/// `int ossl_ec_GF2m_simple_field_div(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *b, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:707-711`.
///
/// # Safety
///
/// `group` is live; `r`, `a`, `b` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_field_div(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { BN_GF2m_mod_div(r, a, b, (*group).field, ctx) }
}

/// `static int ec_GF2m_simple_ladder_pre(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:719-764`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
unsafe extern "C" fn ec_GF2m_simple_ladder_pre(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /* if p is not affine, something is wrong */
        if (*p).z_is_one == 0 {
            return 0;
        }

        let meth = (*group).meth;

        /* s blinding: make sure lambda (s->Z here) is not zero */
        loop {
            if BN_priv_rand_ex(
                (*s).z,
                BN_num_bits((*group).field) - 1,
                BN_RAND_TOP_ANY,
                BN_RAND_BOTTOM_ANY,
                0,
                ctx,
            ) == 0
            {
                raise_site(&err_sites::EC2_SMPL_731);
                return 0;
            }
            if BN_is_zero((*s).z) == 0 {
                break;
            }
        }

        let field_mul = match (*meth).field_mul {
            Some(f) => f,
            None => return 0,
        };

        /* if field_encode defined convert between representations */
        if (*meth).field_encode.is_some() {
            let Some(field_encode) = (*meth).field_encode else {
                return 0;
            };
            if field_encode(group, (*s).z, (*s).z, ctx) == 0 {
                return 0;
            }
        }
        if field_mul(group, (*s).x, (*p).x, (*s).z, ctx) == 0 {
            return 0;
        }

        /* r blinding: make sure lambda (r->Y here for storage) is not zero */
        loop {
            if BN_priv_rand_ex(
                (*r).y,
                BN_num_bits((*group).field) - 1,
                BN_RAND_TOP_ANY,
                BN_RAND_BOTTOM_ANY,
                0,
                ctx,
            ) == 0
            {
                raise_site(&err_sites::EC2_SMPL_746);
                return 0;
            }
            if BN_is_zero((*r).y) == 0 {
                break;
            }
        }

        let field_sqr = match (*meth).field_sqr {
            Some(f) => f,
            None => return 0,
        };

        if let Some(field_encode) = (*meth).field_encode {
            if field_encode(group, (*r).y, (*r).y, ctx) == 0 {
                return 0;
            }
        }

        if field_sqr(group, (*r).z, (*p).x, ctx) == 0
            || field_sqr(group, (*r).x, (*r).z, ctx) == 0
            || BN_GF2m_add((*r).x, (*r).x, (*group).b) == 0
            || field_mul(group, (*r).z, (*r).z, (*r).y, ctx) == 0
            || field_mul(group, (*r).x, (*r).x, (*r).y, ctx) == 0
        {
            return 0;
        }

        (*s).z_is_one = 0;
        (*r).z_is_one = 0;

        1
    }
}

/// `static int ec_GF2m_simple_ladder_step(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:771-792`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
unsafe extern "C" fn ec_GF2m_simple_ladder_step(
    group: *const EcGroup,
    r: *mut EcPoint,
    s: *mut EcPoint,
    p: *mut EcPoint,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let meth = (*group).meth;
        let field_mul = match (*meth).field_mul {
            Some(f) => f,
            None => return 0,
        };
        let field_sqr = match (*meth).field_sqr {
            Some(f) => f,
            None => return 0,
        };

        if field_mul(group, (*r).y, (*r).z, (*s).x, ctx) == 0
            || field_mul(group, (*s).x, (*r).x, (*s).z, ctx) == 0
            || field_sqr(group, (*s).y, (*r).z, ctx) == 0
            || field_sqr(group, (*r).z, (*r).x, ctx) == 0
            || BN_GF2m_add((*s).z, (*r).y, (*s).x) == 0
            || field_sqr(group, (*s).z, (*s).z, ctx) == 0
            || field_mul(group, (*s).x, (*r).y, (*s).x, ctx) == 0
            || field_mul(group, (*r).y, (*s).z, (*p).x, ctx) == 0
            || BN_GF2m_add((*s).x, (*s).x, (*r).y) == 0
            || field_sqr(group, (*r).y, (*r).z, ctx) == 0
            || field_mul(group, (*r).z, (*r).z, (*s).y, ctx) == 0
            || field_sqr(group, (*s).y, (*s).y, ctx) == 0
            || field_mul(group, (*s).y, (*s).y, (*group).b, ctx) == 0
            || BN_GF2m_add((*r).x, (*r).y, (*s).y) == 0
        {
            return 0;
        }

        1
    }
}

/// `static int ec_GF2m_simple_ladder_post(const EC_GROUP *group, EC_POINT *r, EC_POINT *s,
/// EC_POINT *p, BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:800-860`.
///
/// # Safety
///
/// `group` is live; `r`, `s`, `p` are live points; `ctx` is a live context.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
unsafe extern "C" fn ec_GF2m_simple_ladder_post(
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
                raise_site(&err_sites::EC2_SMPL_813);
                return 0;
            }
            return 1;
        }

        BN_CTX_start(ctx);
        let t0 = BN_CTX_get(ctx);
        let t1 = BN_CTX_get(ctx);
        let t2 = BN_CTX_get(ctx);
        if t2.is_null() {
            raise_site(&err_sites::EC2_SMPL_824);
            BN_CTX_end(ctx);
            return ret;
        }

        let meth = (*group).meth;
        let field_mul = (*meth).field_mul;
        let field_sqr = (*meth).field_sqr;
        let field_inv = (*meth).field_inv;

        'err: {
            let (field_mul, field_sqr, field_inv) = match (field_mul, field_sqr, field_inv) {
                (Some(m), Some(q), Some(i)) => (m, q, i),
                _ => break 'err,
            };

            if field_mul(group, t0, (*r).z, (*s).z, ctx) == 0
                || field_mul(group, t1, (*p).x, (*r).z, ctx) == 0
                || BN_GF2m_add(t1, (*r).x, t1) == 0
                || field_mul(group, t2, (*p).x, (*s).z, ctx) == 0
                || field_mul(group, (*r).z, (*r).x, t2, ctx) == 0
                || BN_GF2m_add(t2, t2, (*s).x) == 0
                || field_mul(group, t1, t1, t2, ctx) == 0
                || field_sqr(group, t2, (*p).x, ctx) == 0
                || BN_GF2m_add(t2, (*p).y, t2) == 0
                || field_mul(group, t2, t2, t0, ctx) == 0
                || BN_GF2m_add(t1, t2, t1) == 0
                || field_mul(group, t2, (*p).x, t0, ctx) == 0
                || field_inv(group, t2, t2, ctx) == 0
                || field_mul(group, t1, t1, t2, ctx) == 0
                || field_mul(group, (*r).x, (*r).z, t2, ctx) == 0
                || BN_GF2m_add(t2, (*p).x, (*r).x) == 0
                || field_mul(group, t2, t2, t1, ctx) == 0
                || BN_GF2m_add((*r).y, (*p).y, t2) == 0
                || crate::bn::bignum::BN_set_word((*r).z, 1) == 0
            {
                break 'err;
            }

            (*r).z_is_one = 1;

            /* GF(2^m) field elements should always have BIGNUM::neg = 0 */
            BN_set_negative((*r).x, 0);
            BN_set_negative((*r).y, 0);

            ret = 1;
        }

        BN_CTX_end(ctx);
    }
    ret
}

/// `static int ec_GF2m_simple_points_mul(const EC_GROUP *group, EC_POINT *r,
/// const BIGNUM *scalar, size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:862-916`.
///
/// # Safety
///
/// `group` is live; `r` is live; `scalar`, `points`, `scalars` follow the authority's contract;
/// `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
unsafe extern "C" fn ec_GF2m_simple_points_mul(
    group: *const EcGroup,
    r: *mut EcPoint,
    scalar: *const BigNum,
    num: usize,
    points: *mut *const EcPoint,
    scalars: *mut *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        /*-
         * We limit use of the ladder only to the following cases:
         * - r := scalar * G
         *   Fixed point mul: scalar != NULL && num == 0;
         * - r := scalars[0] * points[0]
         *   Variable point mul: scalar == NULL && num == 1;
         * - r := scalar * G + scalars[0] * points[0]
         *   used, e.g., in ECDSA verification: scalar != NULL && num == 1
         *
         * In any other case (num > 1) we use the default wNAF implementation.
         *
         * We also let the default implementation handle degenerate cases like group
         * order or cofactor set to 0.
         */
        if num > 1 || BN_is_zero((*group).order) != 0 || BN_is_zero((*group).cofactor) != 0 {
            return ossl_ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);
        }

        if !scalar.is_null() && num == 0 {
            /* Fixed point multiplication */
            return ossl_ec_scalar_mul_ladder(group, r, scalar, ptr::null(), ctx);
        }

        if scalar.is_null() && num == 1 {
            /* Variable point multiplication */
            return ossl_ec_scalar_mul_ladder(group, r, *scalars, *points, ctx);
        }

        /*-
         * Double point multiplication:
         *  r := scalar * G + scalars[0] * points[0]
         */

        let t = EC_POINT_new(group);
        if t.is_null() {
            raise_site(&err_sites::EC2_SMPL_902);
            return 0;
        }

        'err: {
            if ossl_ec_scalar_mul_ladder(group, t, scalar, ptr::null(), ctx) == 0
                || ossl_ec_scalar_mul_ladder(group, r, *scalars, *points, ctx) == 0
                || EC_POINT_add(group, r, t, r, ctx) == 0
            {
                break 'err;
            }

            ret = 1;
        }

        EC_POINT_free(t);
    }
    ret
}

/// `static int ec_GF2m_simple_field_inv(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
/// BN_CTX *ctx)` — `crypto/ec/ec2_smpl.c:923-931`.
///
/// # Safety
///
/// `group` is live; `r`, `a` are live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
unsafe extern "C" fn ec_GF2m_simple_field_inv(
    group: *const EcGroup,
    r: *mut BigNum,
    a: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let ret = BN_GF2m_mod_inv(r, a, (*group).field, ctx);
        if ret == 0 {
            raise_site(&err_sites::EC2_SMPL_929);
        }
        ret
    }
}

/// `static const EC_METHOD` — `crypto/ec/ec2_smpl.c:935-992`.
static EC_GF2M_SIMPLE_METHOD: EcMethod = EcMethod {
    flags: EC_FLAGS_DEFAULT_OCT,
    field_type: NID_X9_62_characteristic_two_field,
    group_init: Some(ossl_ec_GF2m_simple_group_init as EcGroupInitFn),
    group_finish: Some(ossl_ec_GF2m_simple_group_finish as EcGroupFinishFn),
    group_clear_finish: Some(ossl_ec_GF2m_simple_group_clear_finish as EcGroupFinishFn),
    group_copy: Some(ossl_ec_GF2m_simple_group_copy as EcGroupCopyFn),
    group_set_curve: Some(ossl_ec_GF2m_simple_group_set_curve as EcGroupSetCurveFn),
    group_get_curve: Some(ossl_ec_GF2m_simple_group_get_curve as EcGroupGetCurveFn),
    group_get_degree: Some(ossl_ec_GF2m_simple_group_get_degree as EcGroupQueryFn),
    group_order_bits: Some(ossl_ec_group_simple_order_bits as EcGroupQueryFn),
    group_check_discriminant: Some(
        ossl_ec_GF2m_simple_group_check_discriminant as EcGroupCheckDiscriminantFn,
    ),
    point_init: Some(ossl_ec_GF2m_simple_point_init as EcPointInitFn),
    point_finish: Some(ossl_ec_GF2m_simple_point_finish as EcPointFinishFn),
    point_clear_finish: Some(ossl_ec_GF2m_simple_point_clear_finish as EcPointFinishFn),
    point_copy: Some(ossl_ec_GF2m_simple_point_copy as EcPointCopyFn),
    point_set_to_infinity: Some(
        ossl_ec_GF2m_simple_point_set_to_infinity as EcPointSetToInfinityFn,
    ),
    point_set_affine_coordinates: Some(
        ossl_ec_GF2m_simple_point_set_affine_coordinates as EcPointSetAffineFn,
    ),
    point_get_affine_coordinates: Some(
        ossl_ec_GF2m_simple_point_get_affine_coordinates as EcPointGetAffineFn,
    ),
    point_set_compressed_coordinates: Some(
        ossl_ec_GF2m_simple_set_compressed_coordinates as EcPointSetCompressedFn,
    ),
    point2oct: Some(ossl_ec_GF2m_simple_point2oct as EcPoint2OctFn),
    oct2point: Some(ossl_ec_GF2m_simple_oct2point as EcOct2PointFn),
    add: Some(ossl_ec_GF2m_simple_add as EcPointAddFn),
    dbl: Some(ossl_ec_GF2m_simple_dbl as EcPointDblFn),
    invert: Some(ossl_ec_GF2m_simple_invert as EcPointUnaryFn),
    is_at_infinity: Some(ossl_ec_GF2m_simple_is_at_infinity as EcPointIsAtInfinityFn),
    is_on_curve: Some(ossl_ec_GF2m_simple_is_on_curve as EcPointIsOnCurveFn),
    point_cmp: Some(ossl_ec_GF2m_simple_cmp as EcPointCmpFn),
    make_affine: Some(ossl_ec_GF2m_simple_make_affine as EcPointUnaryFn),
    points_make_affine: Some(ossl_ec_GF2m_simple_points_make_affine as EcPointsMakeAffineFn),
    mul: Some(ec_GF2m_simple_points_mul as EcPointMulFn),
    precompute_mult: None,
    have_precompute_mult: None,
    field_mul: Some(ossl_ec_GF2m_simple_field_mul as EcFieldMulFn),
    field_sqr: Some(ossl_ec_GF2m_simple_field_sqr as EcFieldSqrFn),
    field_div: Some(ossl_ec_GF2m_simple_field_div as EcFieldMulFn),
    field_inv: Some(ec_GF2m_simple_field_inv as EcFieldSqrFn),
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
    blind_coordinates: None,
    ladder_pre: Some(ec_GF2m_simple_ladder_pre as EcLadderFn),
    ladder_step: Some(ec_GF2m_simple_ladder_step as EcLadderFn),
    ladder_post: Some(ec_GF2m_simple_ladder_post as EcLadderFn),
    group_full_init: None,
};

/// `const EC_METHOD *EC_GF2m_simple_method(void)` — `crypto/ec/ec2_smpl.c:933-995`.
#[no_mangle]
pub extern "C" fn EC_GF2m_simple_method() -> *const EcMethod {
    &EC_GF2M_SIMPLE_METHOD
}

/// `int ossl_ec_GF2m_simple_set_compressed_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x_, int y_bit, BN_CTX *ctx)` — `crypto/ec/ec2_oct.c:39-118`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x_` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_set_compressed_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x_: *const BigNum,
    y_bit: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        let y_bit = c_int::from(y_bit != 0);

        BN_CTX_start(ctx);
        let tmp = BN_CTX_get(ctx);
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        let z = BN_CTX_get(ctx);
        if z.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let meth = (*group).meth;

            if BN_GF2m_mod_arr(x, x_, (*group).poly.as_ptr()) == 0 {
                break 'err;
            }
            if BN_is_zero(x) != 0 {
                if BN_GF2m_mod_sqrt_arr(y, (*group).b, (*group).poly.as_ptr(), ctx) == 0 {
                    break 'err;
                }
            } else {
                let field_sqr = match (*meth).field_sqr {
                    Some(f) => f,
                    None => break 'err,
                };
                let field_div = match (*meth).field_div {
                    Some(f) => f,
                    None => break 'err,
                };
                let field_mul = match (*meth).field_mul {
                    Some(f) => f,
                    None => break 'err,
                };
                if field_sqr(group, tmp, x, ctx) == 0 {
                    break 'err;
                }
                if field_div(group, tmp, (*group).b, tmp, ctx) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(tmp, (*group).a, tmp) == 0 {
                    break 'err;
                }
                if BN_GF2m_add(tmp, x, tmp) == 0 {
                    break 'err;
                }
                ERR_set_mark();
                if BN_GF2m_mod_solve_quad_arr(z, tmp, (*group).poly.as_ptr(), ctx) == 0 {
                    let lib = peek_last_lib();
                    let reason = peek_last_reason();
                    if lib == ERR_LIB_BN as core::ffi::c_ulong
                        && reason == BN_R_NO_SOLUTION as core::ffi::c_ulong
                    {
                        ERR_pop_to_mark();
                        raise_site(&err_sites::EC2_OCT_88);
                    } else {
                        ERR_clear_last_mark();
                        raise_site(&err_sites::EC2_OCT_93);
                    }
                    break 'err;
                }
                ERR_clear_last_mark();
                let z0 = c_int::from(BN_is_odd(z) != 0);
                if field_mul(group, y, x, z, ctx) == 0 {
                    break 'err;
                }
                if z0 != y_bit && BN_GF2m_add(y, y, x) == 0 {
                    break 'err;
                }
            }

            if EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 0 {
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_end(ctx);
        BN_CTX_free(new_ctx);
    }
    ret
}

/// `size_t ossl_ec_GF2m_simple_point2oct(const EC_GROUP *group, const EC_POINT *point,
/// point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx)` —
/// `crypto/ec/ec2_oct.c:125-248`.
///
/// # Safety
///
/// `group` is live; `point` is live; `buf` is null or writable for `len` bytes; `ctx` is null or
/// live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_point2oct(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    buf: *mut c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> usize {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut used_ctx = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if form != POINT_CONVERSION_COMPRESSED
            && form != POINT_CONVERSION_UNCOMPRESSED
            && form != POINT_CONVERSION_HYBRID
        {
            raise_site(&err_sites::EC2_OCT_141);
            return 0;
        }

        if EC_POINT_is_at_infinity(group, point) != 0 {
            /* encodes to a single 0 octet */
            if !buf.is_null() {
                if len < 1 {
                    raise_site(&err_sites::EC2_OCT_149);
                    return 0;
                }
                *buf = 0;
            }
            return 1;
        }

        /* ret := required output buffer length */
        let field_len = ((EC_GROUP_get_degree(group) + 7) / 8) as usize;
        let ret = if form == POINT_CONVERSION_COMPRESSED {
            1 + field_len
        } else {
            1 + 2 * field_len
        };

        let ok = 'err: {
            /* if 'buf' is NULL, just return required length */
            if !buf.is_null() {
                if len < ret {
                    raise_site(&err_sites::EC2_OCT_164);
                    break 'err false;
                }

                if ctx.is_null() {
                    new_ctx = BN_CTX_new();
                    ctx = new_ctx;
                    if ctx.is_null() {
                        return 0;
                    }
                }

                BN_CTX_start(ctx);
                used_ctx = 1;
                let x = BN_CTX_get(ctx);
                let y = BN_CTX_get(ctx);
                let yxi = BN_CTX_get(ctx);
                if yxi.is_null() {
                    break 'err false;
                }

                if EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 0 {
                    break 'err false;
                }

                *buf = form as c_uchar;
                if form != POINT_CONVERSION_UNCOMPRESSED && BN_is_zero(x) == 0 {
                    let field_div = match (*(*group).meth).field_div {
                        Some(f) => f,
                        None => break 'err false,
                    };
                    if field_div(group, yxi, y, x, ctx) == 0 {
                        break 'err false;
                    }
                    if BN_is_odd(yxi) != 0 {
                        *buf += 1;
                    }
                }

                let mut i: usize = 1;

                let mut skip = field_len - ((BN_num_bits(x) + 7) / 8) as usize;
                if skip > field_len {
                    raise_site(&err_sites::EC2_OCT_199);
                    break 'err false;
                }
                while skip > 0 {
                    *buf.add(i) = 0;
                    i += 1;
                    skip -= 1;
                }
                skip = BN_bn2bin(x, buf.add(i)) as usize;
                i += skip;
                if i != 1 + field_len {
                    raise_site(&err_sites::EC2_OCT_209);
                    break 'err false;
                }

                if form == POINT_CONVERSION_UNCOMPRESSED || form == POINT_CONVERSION_HYBRID {
                    skip = field_len - ((BN_num_bits(y) + 7) / 8) as usize;
                    if skip > field_len {
                        raise_site(&err_sites::EC2_OCT_217);
                        break 'err false;
                    }
                    while skip > 0 {
                        *buf.add(i) = 0;
                        i += 1;
                        skip -= 1;
                    }
                    skip = BN_bn2bin(y, buf.add(i)) as usize;
                    i += skip;
                }

                if i != ret {
                    raise_site(&err_sites::EC2_OCT_229);
                    break 'err false;
                }
            }

            true
        };

        if used_ctx != 0 {
            BN_CTX_end(ctx);
        }
        BN_CTX_free(new_ctx);
        if ok {
            ret
        } else {
            0
        }
    }
}

/// `int ossl_ec_GF2m_simple_oct2point(const EC_GROUP *group, EC_POINT *point,
/// const unsigned char *buf, size_t len, BN_CTX *ctx)` — `crypto/ec/ec2_oct.c:254-385`.
///
/// # Safety
///
/// `group` is live; `point` is live; `buf` is readable for `len` bytes; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GF2m_simple_oct2point(
    group: *const EcGroup,
    point: *mut EcPoint,
    buf: *const c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if len == 0 {
            raise_site(&err_sites::EC2_OCT_268);
            return 0;
        }

        /*
         * The first octet is the point conversion octet PC, see X9.62, page 4
         * and section 4.4.2.  It must be:
         *     0x00          for the point at infinity
         *     0x02 or 0x03  for compressed form
         *     0x04          for uncompressed form
         *     0x06 or 0x07  for hybrid form.
         * For compressed or hybrid forms, we store the last bit of buf[0] as
         * y_bit and clear it from buf[0] so as to obtain a POINT_CONVERSION_*.
         * We error if buf[0] contains any but the above values.
         */
        let y_bit = (*buf & 1) as c_int;
        let form: c_int = (*buf & !1u32 as c_uchar) as c_int;

        if form != 0
            && form != POINT_CONVERSION_COMPRESSED
            && form != POINT_CONVERSION_UNCOMPRESSED
            && form != POINT_CONVERSION_HYBRID
        {
            raise_site(&err_sites::EC2_OCT_289);
            return 0;
        }
        if (form == 0 || form == POINT_CONVERSION_UNCOMPRESSED) && y_bit != 0 {
            raise_site(&err_sites::EC2_OCT_293);
            return 0;
        }

        /* The point at infinity is represented by a single zero octet. */
        if form == 0 {
            if len != 1 {
                raise_site(&err_sites::EC2_OCT_300);
                return 0;
            }

            return EC_POINT_set_to_infinity(group, point);
        }

        let m = EC_GROUP_get_degree(group);
        let field_len = (m + 7) / 8;
        let enc_len = if form == POINT_CONVERSION_COMPRESSED {
            1 + field_len
        } else {
            1 + 2 * field_len
        };

        if len != enc_len as usize {
            raise_site(&err_sites::EC2_OCT_312);
            return 0;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                return 0;
            }
        }

        BN_CTX_start(ctx);
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        let yxi = BN_CTX_get(ctx);
        if yxi.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            if BN_bin2bn(buf.add(1), field_len, x).is_null() {
                break 'err;
            }
            if BN_num_bits(x) > m {
                raise_site(&err_sites::EC2_OCT_334);
                break 'err;
            }

            if form == POINT_CONVERSION_COMPRESSED {
                if crate::ec::oct::EC_POINT_set_compressed_coordinates(group, point, x, y_bit, ctx)
                    == 0
                {
                    break 'err;
                }
            } else {
                if BN_bin2bn(buf.add(1 + field_len as usize), field_len, y).is_null() {
                    break 'err;
                }
                if BN_num_bits(y) > m {
                    raise_site(&err_sites::EC2_OCT_345);
                    break 'err;
                }
                if form == POINT_CONVERSION_HYBRID {
                    /*
                     * Check that the form in the encoding was set correctly
                     * according to X9.62 4.4.2.a, 4(c), see also first paragraph
                     * of X9.62, 4.4.1.b.
                     */
                    if BN_is_zero(x) != 0 {
                        if y_bit != 0 {
                            raise_site(&err_sites::EC2_OCT_356);
                            break 'err;
                        }
                    } else {
                        let field_div = match (*(*group).meth).field_div {
                            Some(f) => f,
                            None => break 'err,
                        };
                        if field_div(group, yxi, y, x, ctx) == 0 {
                            break 'err;
                        }
                        if y_bit != BN_is_odd(yxi) {
                            raise_site(&err_sites::EC2_OCT_363);
                            break 'err;
                        }
                    }
                }

                /*
                 * EC_POINT_set_affine_coordinates is responsible for checking that
                 * the point is on the curve.
                 */
                if EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 0 {
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
