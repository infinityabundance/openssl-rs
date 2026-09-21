//! `crypto/ec/ec_check.c` — the curve and point validity checks, Phase 8.7.
//!
//! Two exports, `EC_GROUP_check_named_curve` and `EC_GROUP_check`, both wrappers over the group
//! and point accessors `ec_lib.c` supplies — which is why they land in the step that first gives
//! them their callees rather than with [`crate::ec::smpl`]. `EC_GROUP_check`'s `#ifdef FIPS_MODULE`
//! arm is not this profile's; the `#else` arm is transcribed whole.
//!
//! The `ERR_raise` sites are named `err_sites::EC_CHECK_<line>` after the generator's stem for
//! `crypto/ec/ec_check.c`; those constants are owed with the rest of this tranche's stem set.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::bn::bignum::BN_is_zero;
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BN_CTX_new_ex, BnCtx};
use crate::ec::curve::{ossl_ec_curve_nid_from_params, EC_curve_nid2nist};
use crate::ec::lib::{
    EC_GROUP_check_discriminant, EC_GROUP_get0_order, EC_POINT_free, EC_POINT_is_at_infinity,
    EC_POINT_is_on_curve, EC_POINT_mul, EC_POINT_new,
};
use crate::ec::{EcGroup, EcPoint, EC_FLAGS_CUSTOM_CURVE};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_undef;

/// `int EC_GROUP_check_named_curve(const EC_GROUP *group, int nist_only, BN_CTX *ctx)` —
/// `crypto/ec/ec_check.c:19-44`.
///
/// # Safety
///
/// `group` is null or live; `ctx` is null or a live context; the answer is a NID or `NID_undef`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_check_named_curve(
    group: *const EcGroup,
    nist_only: c_int,
    ctx: *mut BnCtx,
) -> c_int {
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() {
            raise_site(&err_sites::EC_CHECK_26);
            return NID_undef;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new_ex(ptr::null_mut());
            ctx = new_ctx;
            if ctx.is_null() {
                raise_site(&err_sites::EC_CHECK_33);
                return NID_undef;
            }
        }

        let f: unsafe extern "C" fn(*const EcGroup, *mut BnCtx) -> c_int =
            ossl_ec_curve_nid_from_params;
        let mut nid = f(group, ctx);
        let nid2nist: unsafe extern "C" fn(c_int) -> *const c_char = EC_curve_nid2nist;
        if nid > 0 && nist_only != 0 && nid2nist(nid).is_null() {
            nid = NID_undef;
        }

        BN_CTX_free(new_ctx);
        nid
    }
}

/// `int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx)` — `crypto/ec/ec_check.c:46-117`.
///
/// # Safety
///
/// `group` is null or live; `ctx` is null or a live context.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_check(group: *const EcGroup, ctx: *mut BnCtx) -> c_int {
    let mut ret = 0;
    let mut new_ctx: *mut BnCtx = ptr::null_mut();
    let mut point: *mut EcPoint = ptr::null_mut();
    let mut ctx = ctx;

    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        if group.is_null() || (*group).meth.is_null() {
            raise_site(&err_sites::EC_CHECK_61);
            return 0;
        }

        /* Custom curves assumed to be correct */
        if ((*(*group).meth).flags & EC_FLAGS_CUSTOM_CURVE) != 0 {
            return 1;
        }

        if ctx.is_null() {
            new_ctx = BN_CTX_new();
            ctx = new_ctx;
            if ctx.is_null() {
                raise_site(&err_sites::EC_CHECK_72);
                return ret;
            }
        }

        'err: {
            /* check the discriminant */
            if EC_GROUP_check_discriminant(group, ctx) == 0 {
                raise_site(&err_sites::EC_CHECK_79);
                break 'err;
            }

            /* check the generator */
            if (*group).generator.is_null() {
                raise_site(&err_sites::EC_CHECK_85);
                break 'err;
            }
            if EC_POINT_is_on_curve(group, (*group).generator, ctx) <= 0 {
                raise_site(&err_sites::EC_CHECK_89);
                break 'err;
            }

            /* check the order of the generator */
            point = EC_POINT_new(group);
            if point.is_null() {
                break 'err;
            }
            let order = EC_GROUP_get0_order(group);
            if order.is_null() {
                break 'err;
            }
            if BN_is_zero(order) != 0 {
                raise_site(&err_sites::EC_CHECK_100);
                break 'err;
            }

            if EC_POINT_mul(group, point, order, ptr::null(), ptr::null(), ctx) == 0 {
                break 'err;
            }
            if EC_POINT_is_at_infinity(group, point) == 0 {
                raise_site(&err_sites::EC_CHECK_107);
                break 'err;
            }

            ret = 1;
        }

        BN_CTX_free(new_ctx);
        EC_POINT_free(point);
    }
    ret
}
