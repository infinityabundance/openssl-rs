//! `crypto/ec/ec_deprecated.c` — the two `EC_POINT`/`BIGNUM` codecs, Phase 8.7.
//!
//! The unit is seventy-six lines and its whole body — two exports and no internals — sits inside
//! one `#ifndef OPENSSL_NO_DEPRECATED_3_0` block (`ec_deprecated.c:20-75`). That guard is the
//! authority's own policy statement about *callers* (`OPENSSL_SUPPRESS_DEPRECATED` is defined for
//! the implementation at `:14`) and not a build condition: the two names are declared in `ec.h`
//! and are in the admitted profile's export set, which is why the ledger carries both and why
//! they land here rather than being withheld.
//!
//! `EC_POINT_point2bn` is `EC_POINT_point2buf`'s answer handed to `BN_bin2bn`; it refuses an
//! encoding wider than `INT_MAX` because the third argument of `BN_bin2bn` is an `int`, and the
//! authority's own comment (`ec_local.h`) is why the octet buffer is freed on the
//! `BN_bin2bn` failure path as well as the success one. `EC_POINT_bn2point` is the inverse:
//! `BN_num_bytes` (the header's own `(BN_num_bits(a) + 7) / 8` macro, written out here because a
//! macro has no symbol), `BN_bn2binpad` into a fresh buffer, then `EC_POINT_oct2point`. Its one
//! boundary case is a zero-byte `bn`, which is widened to a one-byte buffer rather than passed
//! as a zero-length read.
//!
//! ## The whole unit lands, and both directions are courted
//!
//! These are the other two names `docs/DECISIONS.md` D344 measured as same-stratum work. Every
//! callee is in — `EC_POINT_point2buf`, `EC_POINT_oct2point`, `EC_POINT_new`,
//! `EC_POINT_clear_free`, `BN_bin2bn`, `BN_bn2binpad` — so nothing waits on another stratum.
//! `RT-EC`'s arms drive a hex round trip through `EC_POINT_point2hex`/`EC_POINT_hex2point` and a
//! BN round trip through the pair here, both over the crate's own generated group, and observe
//! only widths, return codes and the recovered point's coordinates compared by value.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;

use crate::bn::bignum::{BN_bin2bn, BN_bn2binpad, BN_num_bits, BigNum};
use crate::bn::ctx::BnCtx;
use crate::ec::lib::{EC_POINT_clear_free, EC_POINT_new};
use crate::ec::oct::{EC_POINT_oct2point, EC_POINT_point2buf};
use crate::ec::{EcGroup, EcPoint, PointConversionForm};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};

/// The translation unit the four allocation pairs below are attributed to, with the admitted
/// build record's `../../src/openssl-3.6.4/` prefix `ec_deprecated.c`'s compiled `__FILE__` carries.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/ec/ec_deprecated.c".as_ptr();

/// `int`'s maximum, the bound the authority puts on the encoding `BN_bin2bn` accepts. Written as
/// `i32::MAX` rather than an `INT_MAX` constant because the authority's build defines it to
/// exactly this on every target this crate admits.
const INT_MAX: usize = i32::MAX as usize;

/// `BN_num_bytes(a)` — `include/openssl/bn.h`'s macro `((BN_num_bits(a) + 7) / 8)`.
///
/// A macro has no symbol to call, so the expression is written out. `BN_num_bits` is the
/// authority's own and is already in the crate.
///
/// # Safety
///
/// `a` is null or live.
unsafe fn bn_num_bytes(a: *const BigNum) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { (BN_num_bits(a) + 7) / 8 }
}

/// `BIGNUM *EC_POINT_point2bn(const EC_GROUP *group, const EC_POINT *point,`
/// `point_conversion_form_t form, BIGNUM *ret, BN_CTX *ctx)` — `crypto/ec/ec_deprecated.c:21-39`.
///
/// `ret` is written in place when non-NULL and allocated when NULL, the `BN_bin2bn` contract.
///
/// # Safety
///
/// `group` and `point` are live and compatible; `ret` is null or a live `BIGNUM`; `ctx` is null
/// or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_point2bn(
    group: *const EcGroup,
    point: *const EcPoint,
    form: PointConversionForm,
    ret: *mut BigNum,
    ctx: *mut BnCtx,
) -> *mut BigNum {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut buf: *mut c_uchar = ptr::null_mut();
        let buf_len = EC_POINT_point2buf(group, point, form, &mut buf, ctx);

        if buf_len == 0 || buf_len > INT_MAX {
            return ptr::null_mut();
        }

        // `ret = BN_bin2bn(buf, (int)buf_len, ret)`, line 34.
        let ret = BN_bin2bn(buf, buf_len as c_int, ret);

        // `OPENSSL_free(buf)`, line 36.
        CRYPTO_free(buf.cast(), FILE, 36);

        ret
    }
}

/// `EC_POINT *EC_POINT_bn2point(const EC_GROUP *group, const BIGNUM *bn, EC_POINT *point,`
/// `BN_CTX *ctx)` — `crypto/ec/ec_deprecated.c:41-75`.
///
/// A NULL `point` allocates one; the answer is NULL on every failure, and a point this call
/// allocated is cleared while the caller's own is left alone.
///
/// # Safety
///
/// `group` is live; `bn` is live; `point` is null or live and compatible with `group`; `ctx` is
/// null or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn EC_POINT_bn2point(
    group: *const EcGroup,
    bn: *const BigNum,
    point: *mut EcPoint,
    ctx: *mut BnCtx,
) -> *mut EcPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer used here.
    unsafe {
        let mut buf_len = bn_num_bytes(bn);
        if buf_len == 0 {
            buf_len = 1;
        }

        // `buf = OPENSSL_malloc(buf_len)`, line 50.
        let buf = CRYPTO_malloc(buf_len as usize, FILE, 50).cast::<c_uchar>();
        if buf.is_null() {
            return ptr::null_mut();
        }

        if BN_bn2binpad(bn, buf, buf_len) < 0 {
            // `OPENSSL_free(buf)`, line 54.
            CRYPTO_free(buf.cast(), FILE, 54);
            return ptr::null_mut();
        }

        let ret: *mut EcPoint;
        if point.is_null() {
            ret = EC_POINT_new(group);
            if ret.is_null() {
                // `OPENSSL_free(buf)`, line 60.
                CRYPTO_free(buf.cast(), FILE, 60);
                return ptr::null_mut();
            }
        } else {
            ret = point;
        }

        if EC_POINT_oct2point(group, ret, buf, buf_len as usize, ctx) == 0 {
            if ret != point {
                // SAFETY: `ret` is this frame's own allocation, never the caller's point.
                EC_POINT_clear_free(ret);
            }
            // `OPENSSL_free(buf)`, line 69.
            CRYPTO_free(buf.cast(), FILE, 69);
            return ptr::null_mut();
        }

        // `OPENSSL_free(buf)`, line 73.
        CRYPTO_free(buf.cast(), FILE, 73);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bn::arith::BN_cmp;
    use crate::bn::bignum::{BN_free, BN_new, BN_set_word};
    use crate::ec::curve::EC_GROUP_new_by_curve_name;
    use crate::ec::lib::{
        EC_GROUP_free, EC_GROUP_get0_generator, EC_POINT_cmp, EC_POINT_copy, EC_POINT_free,
        EC_POINT_new,
    };
    use crate::runtime::obj::NID_X9_62_prime256v1;

    /// `EC_POINT_point2bn` and `EC_POINT_bn2point` are an inverse pair, and the `BIGNUM` is the
    /// uncompressed encoding as an integer — so its byte width equals the octet length.
    #[test]
    fn the_bn_codec_round_trips() {
        // SAFETY: every pointer below is this test's own live object.
        unsafe {
            let g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            assert!(!g.is_null());
            let p = EC_POINT_new(g);
            assert_eq!(EC_POINT_copy(p, EC_GROUP_get0_generator(g)), 1);

            let bn = EC_POINT_point2bn(
                g,
                p,
                crate::ec::POINT_CONVERSION_UNCOMPRESSED,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            assert!(!bn.is_null());

            let back = EC_POINT_bn2point(g, bn, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(!back.is_null());
            assert_eq!(EC_POINT_cmp(g, p, back, core::ptr::null_mut()), 0);

            // A caller-supplied `BIGNUM` is written in place and answered back.
            let reuse = BN_new();
            assert_eq!(
                EC_POINT_point2bn(
                    g,
                    p,
                    crate::ec::POINT_CONVERSION_UNCOMPRESSED,
                    reuse,
                    core::ptr::null_mut(),
                ),
                reuse
            );
            assert_eq!(BN_cmp(reuse, bn), 0);

            // A zero `BIGNUM` is widened to one octet, which is the point at infinity; a single
            // non-zero octet carries the `y_bit` an uncompressed form must not.
            let zero = BN_new();
            let one = BN_new();
            assert_eq!(BN_set_word(zero, 0), 1);
            assert_eq!(BN_set_word(one, 1), 1);
            let inf = EC_POINT_bn2point(g, zero, core::ptr::null_mut(), core::ptr::null_mut());
            assert!(!inf.is_null());
            assert_eq!(crate::ec::lib::EC_POINT_is_at_infinity(g, inf), 1);
            assert!(
                EC_POINT_bn2point(g, one, core::ptr::null_mut(), core::ptr::null_mut()).is_null()
            );

            EC_POINT_free(inf);
            BN_free(one);
            BN_free(zero);
            BN_free(reuse);
            EC_POINT_free(back);
            BN_free(bn);
            EC_POINT_free(p);
            EC_GROUP_free(g);
        }
    }
}
