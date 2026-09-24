//! `crypto/sm2/sm2_key.c` — SM2's private-key range check, Phase 8.10.
//!
//! Fifty-two lines, one function. It is landed because the `SM2` provider key management row
//! (`providers/implementations/keymgmt/ec_kmgmt.c`'s `sm2_validate`, `:902`) calls it, and because
//! the rest of the SM2 object surface the row needs was already landed: `src/ec/curve_data.rs`
//! carries the `NID_sm2` curve row, `src/ec/mult.rs` and `src/ec/smpl.rs` the arithmetic its
//! `EC_GROUP` uses, and `src/ec/ameth.rs`'s `ossl_sm2_asn1_meth` the legacy method. It is an
//! authority *internal* — `crypto/sm2.h` declares it and is not installed — so it is a `pub(crate)`
//! function rather than a `#[no_mangle]` export.
//!
//! SM2's private scalar is in `[1, n-1)`, which is a **strictly narrower** range than the DSA/ECDSA
//! `[1, n-1]` the sibling checks accept; the two are different enough that the authority gives SM2
//! its own function, and that difference is the reason the row exists.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::bn::arith::{BN_cmp, BN_sub_word};
use crate::bn::bignum::{BN_dup, BN_free, BN_value_one, BigNum};
use crate::ec::key::{EC_KEY_get0_group, EC_KEY_get0_private_key};
use crate::ec::lib::EC_GROUP_get0_order;
use crate::ec::EcKey;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;

/// `int ossl_sm2_key_private_check(const EC_KEY *eckey)` — `crypto/sm2/sm2_key.c:22-52`.
///
/// The two raises carry the `sm2err.h` reasons the unit's own translation unit raises: the
/// `ERR_LIB_SM2`/`ERR_R_PASSED_NULL_PARAMETER` coordinate (`SM2_KEY_33`) and the
/// `ERR_LIB_SM2`/`SM2_R_INVALID_PRIVATE_KEY` one (`SM2_KEY_43`).
///
/// # Safety
/// `eckey` is NULL or a live key.
#[allow(unused_assignments)] // the authority initialises `max` to NULL and assigns it on every path that reads it
pub(crate) unsafe fn ossl_sm2_key_private_check(eckey: *const EcKey) -> c_int {
    let mut ret: c_int = 0;
    let mut max: *mut BigNum = ptr::null_mut();

    if eckey.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SM2_KEY_33) };
        return 0;
    }

    // SAFETY: `eckey` is non-NULL past the guard.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    if group.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SM2_KEY_33) };
        return 0;
    }
    // SAFETY: `eckey` and `group` are live.
    let priv_key = unsafe { EC_KEY_get0_private_key(eckey) };
    if priv_key.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SM2_KEY_33) };
        return 0;
    }
    // SAFETY: `group` is live.
    let order = unsafe { EC_GROUP_get0_order(group) };
    if order.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::SM2_KEY_33) };
        return 0;
    }

    // SAFETY: `order` is live; `max` is this call's own BIGNUM.
    unsafe {
        /* range of SM2 private key is [1, n-1) */
        max = BN_dup(order);
        if !max.is_null() && BN_sub_word(max, 1) != 0 {
            // SAFETY: `priv_key` and `max` are live.
            if BN_cmp(priv_key, BN_value_one()) < 0 || BN_cmp(priv_key, max) >= 0 {
                // SAFETY: a compile-time-constant site.
                raise_site(&err_sites::SM2_KEY_43);
            } else {
                ret = 1;
            }
        }
        BN_free(max);
    }
    ret
}
