//! `crypto/ec/ec_cvt.c` — the two curve constructors, Phase 8.7.
//!
//! Eighty-nine lines and exactly two exports, neither of which defines an internal:
//! `EC_GROUP_new_curve_GFp` and `EC_GROUP_new_curve_GF2m`. Each picks an `EC_METHOD`, builds a
//! group through `ossl_ec_group_new_ex` and then calls `EC_GROUP_set_curve` — so the unit is the
//! *only* caller that chooses a field method by hand rather than by reading `curve_list[]`'s
//! fourth column, and it is what `ec_group_new_from_data` falls back to for every row whose
//! method column is NULL.
//!
//! ## The prime-field method is chosen at compile time on this profile
//!
//! The authority writes
//!
//! ```text
//! #if defined(OPENSSL_BN_ASM_MONT)
//!     meth = EC_GFp_mont_method();
//! #else
//!     if (BN_nist_mod_func(p))
//!         meth = EC_GFp_nist_method();
//!     else
//!         meth = EC_GFp_mont_method();
//! #endif
//! ```
//!
//! and the admitted build record defines **`OPENSSL_BN_ASM_MONT`**
//! (`forensics/authorities/captures/openssl-3.6.3-historical/make.log`), so the first arm is the
//! one that compiles and `BN_nist_mod_func` is not called here at all. The transcription is the
//! first arm, and the second is named rather than transcribed: writing both as one Rust `if`
//! would be a behaviour the authority does not have on this profile. `EC_GFp_nist_method` is
//! still reachable, but only through `curve_list[]`, whose method column is `ec_curve.c`'s
//! business rather than this unit's.
//!
//! ## The binary-field arm is compiled
//!
//! `#ifndef OPENSSL_NO_EC2M` holds on this profile — `ec2_smpl.c` and `ec2_oct.c` land as
//! [`crate::ec::smpl2`] — so `EC_GROUP_new_curve_GF2m` is a real export here and not a
//! compiled-out name.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::bn::bignum::BigNum;
use crate::bn::ctx::{ossl_bn_get_libctx, BnCtx};
use crate::ec::lib::{ossl_ec_group_new_ex, EC_GROUP_free, EC_GROUP_set_curve};
use crate::ec::mont::EC_GFp_mont_method;
use crate::ec::smpl2::EC_GF2m_simple_method;
use crate::ec::{EcGroup, EcMethod};

/// `EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_cvt.c:21-67`.
///
/// `p`, `a` and `b` are left in the caller's `BN_CTX`; the group copies them through
/// `EC_GROUP_set_curve`. A group whose curve is rejected is freed before NULL is answered, so
/// the caller owns nothing on the failure path.
///
/// The method is `EC_GFp_mont_method()` **unconditionally** on this profile: the authority's
/// `#if defined(OPENSSL_BN_ASM_MONT)` arm is the one the admitted build compiles, and its
/// `BN_nist_mod_func(p)` arm is named in the module documentation rather than written here.
/// `ossl_bn_get_libctx(ctx)` is the group's `libctx`, so a caller's `BN_CTX` carries the
/// library context the new group is made in and a NULL `ctx` means the default context.
///
/// # Safety
///
/// `p`, `a` and `b` are live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_curve_GFp(
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> *mut EcGroup {
    unsafe {
        // SAFETY: this function's own contract.
        let meth: *const EcMethod = EC_GFp_mont_method();

        let ret = ossl_ec_group_new_ex(ossl_bn_get_libctx(ctx), core::ptr::null(), meth);
        if ret.is_null() {
            return core::ptr::null_mut();
        }

        if EC_GROUP_set_curve(ret, p, a, b, ctx) == 0 {
            EC_GROUP_free(ret);
            return core::ptr::null_mut();
        }

        ret
    }
}

/// `EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b,
/// BN_CTX *ctx)` — `crypto/ec/ec_cvt.c:70-88`.
///
/// The binary-field twin, inside `#ifndef OPENSSL_NO_EC2M` and compiled on this profile. Its
/// method is `EC_GF2m_simple_method()` and its `libctx` is the caller's `ctx` exactly as the
/// prime-field arm's is.
///
/// # Safety
///
/// `p`, `a` and `b` are live `BIGNUM`s; `ctx` is NULL or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_GROUP_new_curve_GF2m(
    p: *const BigNum,
    a: *const BigNum,
    b: *const BigNum,
    ctx: *mut BnCtx,
) -> *mut EcGroup {
    unsafe {
        // SAFETY: this function's own contract.
        let meth: *const EcMethod = EC_GF2m_simple_method();

        let ret = ossl_ec_group_new_ex(ossl_bn_get_libctx(ctx), core::ptr::null(), meth);
        if ret.is_null() {
            return core::ptr::null_mut();
        }

        if EC_GROUP_set_curve(ret, p, a, b, ctx) == 0 {
            EC_GROUP_free(ret);
            return core::ptr::null_mut();
        }

        ret
    }
}
