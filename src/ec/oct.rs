//! `crypto/ec/ecp_oct.c` and `crypto/ec/ec_oct.c` — the octet conversion layer, Phase 8.7.
//!
//! `ecp_oct.c` supplies the three prime-field internals (`ossl_ec_GFp_simple_oct2point`,
//! `_point2oct`, `_set_compressed_coordinates`); `ec_oct.c` supplies the six exports that
//! dispatch to them or to the group table. Both units land in `src/ec/oct.rs` because the plan's
//! §2b names one module for each and the exports are the entry points the internals back.
//!
//! The `ERR_raise` sites are named after each unit's generator stem — `err_sites::ECP_OCT_<line>`
//! and `err_sites::EC_OCT_<line>` — neither of which is in `gen_err_raise_sites.py`'s
//! `COVERED_FILES` yet.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::bn::arith::{
    BN_mod_add_quick, BN_mod_lshift1_quick, BN_mod_mul, BN_mod_sqr, BN_mod_sqrt, BN_mod_sub_quick,
    BN_nnmod, BN_ucmp, BN_usub,
};
use crate::bn::bignum::{BN_bin2bn, BN_bn2bin, BN_is_odd, BN_is_zero, BN_num_bits, BigNum};
use crate::bn::ctx::{BN_CTX_end, BN_CTX_free, BN_CTX_get, BN_CTX_new_ex, BN_CTX_start, BnCtx};
use crate::bn::kron::BN_kronecker;
use crate::ec::lib::{
    EC_POINT_get_affine_coordinates, EC_POINT_is_at_infinity, EC_POINT_set_affine_coordinates,
    EC_POINT_set_to_infinity,
};
use crate::ec::smpl2::{
    ossl_ec_GF2m_simple_oct2point, ossl_ec_GF2m_simple_point2oct,
    ossl_ec_GF2m_simple_set_compressed_coordinates,
};
use crate::ec::{
    ec_point_is_compat, EcGroup, EcPoint, PointConversionForm, EC_FLAGS_DEFAULT_OCT,
    POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_HYBRID, POINT_CONVERSION_UNCOMPRESSED,
};
use crate::runtime::err::err_reasons::BN_R_NOT_A_SQUARE;
use crate::runtime::err::err_sites;
use crate::runtime::err::{
    peek_last_lib, peek_last_reason, raise_site, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::NID_X9_62_prime_field;

/// `ERR_LIB_BN` — `include/openssl/err.h`, the library `EC_R_INVALID_COMPRESSED_POINT`'s raise
/// site tests against.
const ERR_LIB_BN: c_int = 3;

/// The `crypto/ec/ec_oct.c` translation unit, for the one allocation pair attributed to it.
const FILE_EC_OCT: &core::ffi::CStr = c"crypto/ec/ec_oct.c";

/// `int ossl_ec_GFp_simple_set_compressed_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x_, int y_bit, BN_CTX *ctx)` — `crypto/ec/ecp_oct.c:22-157`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x_` is live; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_set_compressed_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x_: *const BigNum,
    y_bit: c_int,
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

        let y_bit = c_int::from(y_bit != 0);

        BN_CTX_start(ctx);
        let tmp1 = BN_CTX_get(ctx);
        let tmp2 = BN_CTX_get(ctx);
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        if y.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            let meth = (*group).meth;

            /*-
             * Recover y.  We have a Weierstrass equation
             *     y^2 = x^3 + a*x + b,
             * so  y  is one of the square roots of  x^3 + a*x + b.
             */

            /* tmp1 := x^3 */
            if BN_nnmod(x, x_, (*group).field, ctx) == 0 {
                break 'err;
            }
            if (*meth).field_decode.is_none() {
                /* field_{sqr,mul} work on standard representation */
                let field_sqr = match (*meth).field_sqr {
                    Some(f) => f,
                    None => break 'err,
                };
                let field_mul = match (*meth).field_mul {
                    Some(f) => f,
                    None => break 'err,
                };
                if field_sqr(group, tmp2, x_, ctx) == 0 {
                    break 'err;
                }
                if field_mul(group, tmp1, tmp2, x_, ctx) == 0 {
                    break 'err;
                }
            } else {
                if BN_mod_sqr(tmp2, x_, (*group).field, ctx) == 0 {
                    break 'err;
                }
                if BN_mod_mul(tmp1, tmp2, x_, (*group).field, ctx) == 0 {
                    break 'err;
                }
            }

            /* tmp1 := tmp1 + a*x */
            if (*group).a_is_minus3 != 0 {
                if BN_mod_lshift1_quick(tmp2, x, (*group).field) == 0 {
                    break 'err;
                }
                if BN_mod_add_quick(tmp2, tmp2, x, (*group).field) == 0 {
                    break 'err;
                }
                if BN_mod_sub_quick(tmp1, tmp1, tmp2, (*group).field) == 0 {
                    break 'err;
                }
            } else {
                if (*meth).field_decode.is_some() {
                    if (*meth)
                        .field_decode
                        .map_or(1, |f| f(group, tmp2, (*group).a, ctx))
                        == 0
                    {
                        break 'err;
                    }
                    if BN_mod_mul(tmp2, tmp2, x, (*group).field, ctx) == 0 {
                        break 'err;
                    }
                } else {
                    /* field_mul works on standard representation */
                    let field_mul = match (*meth).field_mul {
                        Some(f) => f,
                        None => break 'err,
                    };
                    if field_mul(group, tmp2, (*group).a, x, ctx) == 0 {
                        break 'err;
                    }
                }

                if BN_mod_add_quick(tmp1, tmp1, tmp2, (*group).field) == 0 {
                    break 'err;
                }
            }

            /* tmp1 := tmp1 + b */
            if (*meth).field_decode.is_some() {
                if (*meth)
                    .field_decode
                    .map_or(1, |f| f(group, tmp2, (*group).b, ctx))
                    == 0
                {
                    break 'err;
                }
                if BN_mod_add_quick(tmp1, tmp1, tmp2, (*group).field) == 0 {
                    break 'err;
                }
            } else if BN_mod_add_quick(tmp1, tmp1, (*group).b, (*group).field) == 0 {
                break 'err;
            }

            ERR_set_mark();
            if BN_mod_sqrt(y, tmp1, (*group).field, ctx).is_null() {
                let lib = peek_last_lib();
                let reason = peek_last_reason();
                if lib == ERR_LIB_BN as core::ffi::c_ulong
                    && reason == BN_R_NOT_A_SQUARE as core::ffi::c_ulong
                {
                    ERR_pop_to_mark();
                    raise_site(&err_sites::ECP_OCT_112);
                } else {
                    ERR_clear_last_mark();
                    raise_site(&err_sites::ECP_OCT_117);
                }
                break 'err;
            }
            ERR_clear_last_mark();

            if y_bit != BN_is_odd(y) {
                if BN_is_zero(y) != 0 {
                    let kron = BN_kronecker(x, (*group).field, ctx);
                    if kron == -2 {
                        break 'err;
                    }

                    if kron == 1 {
                        raise_site(&err_sites::ECP_OCT_132);
                    } else {
                        /*
                         * BN_mod_sqrt() should have caught this error (not a square)
                         */
                        raise_site(&err_sites::ECP_OCT_137);
                    }
                    break 'err;
                }
                if BN_usub(y, (*group).field, y) == 0 {
                    break 'err;
                }
            }
            if y_bit != BN_is_odd(y) {
                raise_site(&err_sites::ECP_OCT_144);
                break 'err;
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

/// `size_t ossl_ec_GFp_simple_point2oct(const EC_GROUP *group, const EC_POINT *point,
/// point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx)` —
/// `crypto/ec/ecp_oct.c:159-271`.
///
/// # Safety
///
/// `group` is live; `point` is live; `buf` is null or writable for `len` bytes; `ctx` is null or
/// live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_point2oct(
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
            raise_site(&err_sites::ECP_OCT_172);
            return 0;
        }

        if EC_POINT_is_at_infinity(group, point) != 0 {
            /* encodes to a single 0 octet */
            if !buf.is_null() {
                if len < 1 {
                    raise_site(&err_sites::ECP_OCT_180);
                    return 0;
                }
                *buf = 0;
            }
            return 1;
        }

        /* ret := required output buffer length */
        let field_len = ((BN_num_bits((*group).field) + 7) / 8) as usize;
        let ret = if form == POINT_CONVERSION_COMPRESSED {
            1 + field_len
        } else {
            1 + 2 * field_len
        };

        let ok = 'err: {
            /* if 'buf' is NULL, just return required length */
            if !buf.is_null() {
                if len < ret {
                    raise_site(&err_sites::ECP_OCT_195);
                    break 'err false;
                }

                if ctx.is_null() {
                    new_ctx = BN_CTX_new_ex((*group).libctx);
                    ctx = new_ctx;
                    if ctx.is_null() {
                        return 0;
                    }
                }

                BN_CTX_start(ctx);
                used_ctx = 1;
                let x = BN_CTX_get(ctx);
                let y = BN_CTX_get(ctx);
                if y.is_null() {
                    break 'err false;
                }

                if EC_POINT_get_affine_coordinates(group, point, x, y, ctx) == 0 {
                    break 'err false;
                }

                if (form == POINT_CONVERSION_COMPRESSED || form == POINT_CONVERSION_HYBRID)
                    && BN_is_odd(y) != 0
                {
                    *buf = (form + 1) as c_uchar;
                } else {
                    *buf = form as c_uchar;
                }

                let mut i: usize = 1;

                let mut skip = field_len - ((BN_num_bits(x) + 7) / 8) as usize;
                if skip > field_len {
                    raise_site(&err_sites::ECP_OCT_226);
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
                    raise_site(&err_sites::ECP_OCT_236);
                    break 'err false;
                }

                if form == POINT_CONVERSION_UNCOMPRESSED || form == POINT_CONVERSION_HYBRID {
                    skip = field_len - ((BN_num_bits(y) + 7) / 8) as usize;
                    if skip > field_len {
                        raise_site(&err_sites::ECP_OCT_244);
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
                    raise_site(&err_sites::ECP_OCT_256);
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

/// `int ossl_ec_GFp_simple_oct2point(const EC_GROUP *group, EC_POINT *point,
/// const unsigned char *buf, size_t len, BN_CTX *ctx)` — `crypto/ec/ecp_oct.c:273-369`.
///
/// # Safety
///
/// `group` is live; `point` is live; `buf` is readable for `len` bytes; `ctx` is null or live.
#[allow(non_snake_case)] // the authority's own symbol name; ABI-PROTOTYPE resolves it by this exact spelling
pub(crate) unsafe extern "C" fn ossl_ec_GFp_simple_oct2point(
    group: *const EcGroup,
    point: *mut EcPoint,
    buf: *const c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ret = 0;
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if len == 0 {
            raise_site(&err_sites::ECP_OCT_285);
            return 0;
        }
        let mut form: c_int = *buf as c_int;
        let y_bit = form & 1;
        form &= !1u32 as c_int;
        if form != 0
            && form != POINT_CONVERSION_COMPRESSED
            && form != POINT_CONVERSION_UNCOMPRESSED
            && form != POINT_CONVERSION_HYBRID
        {
            raise_site(&err_sites::ECP_OCT_294);
            return 0;
        }
        if (form == 0 || form == POINT_CONVERSION_UNCOMPRESSED) && y_bit != 0 {
            raise_site(&err_sites::ECP_OCT_298);
            return 0;
        }

        if form == 0 {
            if len != 1 {
                raise_site(&err_sites::ECP_OCT_304);
                return 0;
            }

            return EC_POINT_set_to_infinity(group, point);
        }

        let field_len = (BN_num_bits((*group).field) + 7) / 8;
        let enc_len = if form == POINT_CONVERSION_COMPRESSED {
            1 + field_len
        } else {
            1 + 2 * field_len
        };

        if len != enc_len as usize {
            raise_site(&err_sites::ECP_OCT_315);
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
        let x = BN_CTX_get(ctx);
        let y = BN_CTX_get(ctx);
        if y.is_null() {
            BN_CTX_end(ctx);
            BN_CTX_free(new_ctx);
            return ret;
        }

        'err: {
            if BN_bin2bn(buf.add(1), field_len, x).is_null() {
                break 'err;
            }
            if BN_ucmp(x, (*group).field) >= 0 {
                raise_site(&err_sites::ECP_OCT_334);
                break 'err;
            }

            if form == POINT_CONVERSION_COMPRESSED {
                let f = match (*(*group).meth).point_set_compressed_coordinates {
                    Some(f) => f,
                    None => break 'err,
                };
                if f(group, point, x, y_bit, ctx) == 0 {
                    break 'err;
                }
            } else {
                if BN_bin2bn(buf.add(1 + field_len as usize), field_len, y).is_null() {
                    break 'err;
                }
                if BN_ucmp(y, (*group).field) >= 0 {
                    raise_site(&err_sites::ECP_OCT_345);
                    break 'err;
                }
                if form == POINT_CONVERSION_HYBRID && y_bit != BN_is_odd(y) {
                    raise_site(&err_sites::ECP_OCT_350);
                    break 'err;
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

/// `int EC_POINT_set_compressed_coordinates(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, int y_bit, BN_CTX *ctx)` — `crypto/ec/ec_oct.c:24-53`.
///
/// # Safety
///
/// `group` is live; `point` is live; `x` is live; `ctx` is null or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y_bit: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let meth = (*group).meth;
        if (*meth).point_set_compressed_coordinates.is_none()
            && ((*meth).flags & EC_FLAGS_DEFAULT_OCT) == 0
        {
            raise_site(&err_sites::EC_OCT_29);
            return 0;
        }
        if !ec_point_is_compat(point, group) {
            raise_site(&err_sites::EC_OCT_33);
            return 0;
        }
        if ((*meth).flags & EC_FLAGS_DEFAULT_OCT) != 0 {
            if (*meth).field_type == NID_X9_62_prime_field {
                return ossl_ec_GFp_simple_set_compressed_coordinates(group, point, x, y_bit, ctx);
            }
            return ossl_ec_GF2m_simple_set_compressed_coordinates(group, point, x, y_bit, ctx);
        }
        match (*meth).point_set_compressed_coordinates {
            Some(point_set_compressed_coordinates) => {
                point_set_compressed_coordinates(group, point, x, y_bit, ctx)
            }
            None => 0,
        }
    }
}

/// `int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, int y_bit, BN_CTX *ctx)` — `crypto/ec/ec_oct.c:56-61`.
///
/// # Safety
///
/// As [`EC_POINT_set_compressed_coordinates`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates_GFp(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y_bit: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { EC_POINT_set_compressed_coordinates(group, point, x, y_bit, ctx) }
}

/// `int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *point,
/// const BIGNUM *x, int y_bit, BN_CTX *ctx)` — `crypto/ec/ec_oct.c:64-69`.
///
/// # Safety
///
/// As [`EC_POINT_set_compressed_coordinates`]'s contract.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_set_compressed_coordinates_GF2m(
    group: *const EcGroup,
    point: *mut EcPoint,
    x: *const BigNum,
    y_bit: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe { EC_POINT_set_compressed_coordinates(group, point, x, y_bit, ctx) }
}

/// `size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *point,
/// point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx)` —
/// `crypto/ec/ec_oct.c:73-107`.
///
/// # Safety
///
/// `group` is live; `point` is null or live; `buf` is null or writable for `len` bytes; `ctx` is
/// null or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_point2oct(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    buf: *mut c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if point.is_null() {
            raise_site(&err_sites::EC_OCT_78);
            return 0;
        }
        let meth = (*group).meth;
        if (*meth).point2oct.is_none() && ((*meth).flags & EC_FLAGS_DEFAULT_OCT) == 0 {
            raise_site(&err_sites::EC_OCT_83);
            return 0;
        }
        if !ec_point_is_compat(point, group) {
            raise_site(&err_sites::EC_OCT_87);
            return 0;
        }
        if ((*meth).flags & EC_FLAGS_DEFAULT_OCT) != 0 {
            if (*meth).field_type == NID_X9_62_prime_field {
                return ossl_ec_GFp_simple_point2oct(group, point, form, buf, len, ctx);
            }
            return ossl_ec_GF2m_simple_point2oct(group, point, form, buf, len, ctx);
        }

        let Some(f) = (*meth).point2oct else {
            return 0;
        };
        f(group, point, form, buf, len, ctx)
    }
}

/// `int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point, const unsigned char *buf,
/// size_t len, BN_CTX *ctx)` — `crypto/ec/ec_oct.c:109-135`.
///
/// # Safety
///
/// `group` is live; `point` is live; `buf` is readable for `len` bytes; `ctx` is null or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_oct2point(
    group: *const EcGroup,
    point: *mut EcPoint,
    buf: *const c_uchar,
    len: usize,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let meth = (*group).meth;
        if (*meth).oct2point.is_none() && ((*meth).flags & EC_FLAGS_DEFAULT_OCT) == 0 {
            raise_site(&err_sites::EC_OCT_114);
            return 0;
        }
        if !ec_point_is_compat(point, group) {
            raise_site(&err_sites::EC_OCT_118);
            return 0;
        }
        if ((*meth).flags & EC_FLAGS_DEFAULT_OCT) != 0 {
            if (*meth).field_type == NID_X9_62_prime_field {
                return ossl_ec_GFp_simple_oct2point(group, point, buf, len, ctx);
            }
            return ossl_ec_GF2m_simple_oct2point(group, point, buf, len, ctx);
        }
        match (*meth).oct2point {
            Some(oct2point) => oct2point(group, point, buf, len, ctx),
            None => 0,
        }
    }
}

/// `size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point,
/// point_conversion_form_t form, unsigned char **pbuf, BN_CTX *ctx)` —
/// `crypto/ec/ec_oct.c:137-156`.
///
/// # Safety
///
/// `group` is live; `point` is live; `pbuf` is a writable slot; `ctx` is null or live.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_point2buf(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    pbuf: *mut *mut c_uchar,
    ctx: *mut BnCtx,
) -> usize {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut len = EC_POINT_point2oct(group, point, form, ptr::null_mut(), 0, ptr::null_mut());
        if len == 0 {
            return 0;
        }
        let buf = CRYPTO_malloc(len, FILE_EC_OCT.as_ptr(), 147).cast::<c_uchar>();
        if buf.is_null() {
            return 0;
        }
        len = EC_POINT_point2oct(group, point, form, buf, len, ctx);
        if len == 0 {
            CRYPTO_free(buf.cast(), FILE_EC_OCT.as_ptr(), 151);
            return 0;
        }
        *pbuf = buf;
        len
    }
}
