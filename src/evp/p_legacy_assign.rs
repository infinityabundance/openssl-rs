//! `crypto/evp/p_legacy.c` — the six legacy `set1`/`get0`/`get1` entry points plus the two
//! `_int` readers they share.
//!
//! ## This module is named for the unit and not for the ledger row it belongs to
//!
//! The crate's ledger already has a `src/evp/p_legacy.rs` row, and it is **not** this unit: that
//! row groups thirteen *open* symbols by prefix — `EVP_BytesToKey` and the password prompt
//! helpers from `crypto/evp/evp_key.c`, `EVP_SignFinal`/`EVP_VerifyFinal` from `p_sign.c`/
//! `p_verify.c`, `EVP_OpenInit`/`EVP_SealInit` from `p_open.c`/`p_seal.c` — over five authority
//! units that share a module because they were *withheld* together. This file is the opposite:
//! one authority **unit**, transcribed, and the atlas maps a module to the dominant authority
//! translation unit among the symbols it defines. Naming it `p_legacy_assign.rs` keeps the unit's
//! own basename (`p_legacy.c`), names the operation the six exports perform so a reader can tell
//! it apart from the row above, and does not claim the withheld thirteen.
//!
//! ## What it is, and what it withholds
//!
//! Six exports — `EVP_PKEY_set1_RSA`, `EVP_PKEY_get0_RSA`, `EVP_PKEY_get1_RSA`,
//! `EVP_PKEY_set1_EC_KEY`, `EVP_PKEY_get0_EC_KEY`, `EVP_PKEY_get1_EC_KEY` — and the two
//! `crypto/evp.h`-declared internals `evp_pkey_get0_RSA_int` and `evp_pkey_get0_EC_KEY_int` they
//! are written over. Every one of them is a `up_ref` plus `EVP_PKEY_assign`, or a type test plus
//! `evp_pkey_get_legacy`, both of which `crypto/evp/p_lib.c`'s half of 8.8 lands.
//!
//! `EVP_PKEY_set1_DH`, `EVP_PKEY_set1_DSA`, `EVP_PKEY_get0_DH`, `EVP_PKEY_get1_DH`,
//! `EVP_PKEY_get0_DSA` and `EVP_PKEY_get1_DSA` are **not** here. The authority defines them in
//! `p_lib.c`, not `p_legacy.c`, and each is transcribed in its own unit's module
//! ([`crate::evp::pkey`]) for that reason.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::EcKey;
use crate::evp::pkey::{evp_pkey_get_legacy, EVP_PKEY_assign, EVP_PKEY_get_base_id, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_EC, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS};
use crate::rsa::object::{RSA_free, RSA_up_ref};
use crate::rsa::Rsa;
use crate::runtime::err::{err_sites, raise_site};

/// `int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key)` — `crypto/evp/p_legacy.c:25`.
///
/// A reference is taken before the assignment and released if the assignment fails, so the
/// caller's own reference is never consumed by a refusal.
///
/// # Safety
/// `pkey` must be live; `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_RSA(pkey: *mut EvpPkey, key: *mut Rsa) -> c_int {
    // SAFETY: `key` is live per the contract.
    if unsafe { RSA_up_ref(key) } == 0 {
        return 0;
    }

    // SAFETY: `pkey` and `key` are live.
    let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_RSA, key.cast()) };

    if ret == 0 {
        // SAFETY: `key` is live; the reference taken above is released.
        unsafe { RSA_free(key) };
    }

    ret
}

/// `RSA *evp_pkey_get0_RSA_int(const EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:40`.
///
/// The two RSA types are both accepted: `EVP_PKEY_RSA` and the PSS spelling name the same key
/// object, and the authority tests for both.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn evp_pkey_get0_RSA_int(pkey: *const EvpPkey) -> *mut Rsa {
    // SAFETY: `pkey` is live per the contract.
    let t = unsafe { (*pkey).type_ };
    if t != EVP_PKEY_RSA && t != EVP_PKEY_RSA_PSS {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LEGACY_43) };
        return core::ptr::null_mut();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<Rsa>()
}

/// `const RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:49`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_RSA(pkey: *const EvpPkey) -> *const Rsa {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get0_RSA_int(pkey) }
}

/// `RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:54`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_RSA(pkey: *mut EvpPkey) -> *mut Rsa {
    // SAFETY: `pkey` is live per the contract.
    let ret = unsafe { evp_pkey_get0_RSA_int(pkey) };

    // SAFETY: `ret` is non-NULL and therefore a live `RSA` per the accessor's contract.
    if !ret.is_null() && unsafe { RSA_up_ref(ret) } == 0 {
        return core::ptr::null_mut();
    }

    ret
}

/// `int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key)` — `crypto/evp/p_legacy.c:65`.
///
/// The EC half refuses with a plain `0` where the RSA half's failure is `EVP_PKEY_assign`'s own
/// answer; the two spellings are the authority's.
///
/// # Safety
/// `pkey` must be live; `key` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_set1_EC_KEY(pkey: *mut EvpPkey, key: *mut EcKey) -> c_int {
    // SAFETY: `key` is live per the contract.
    if unsafe { EC_KEY_up_ref(key) } == 0 {
        return 0;
    }
    // SAFETY: `pkey` and `key` are live.
    if unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, key.cast()) } == 0 {
        // SAFETY: `key` is live; the reference taken above is released.
        unsafe { EC_KEY_free(key) };
        return 0;
    }
    1
}

/// `EC_KEY *evp_pkey_get0_EC_KEY_int(const EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:76`.
///
/// The test is on the **base** id, not the raw type, so an SM2 key — whose base id is
/// `EVP_PKEY_EC` — is accepted exactly as the authority accepts it.
///
/// # Safety
/// `pkey` must be live.
#[allow(non_snake_case)] // the authority's own internal name
pub(crate) unsafe fn evp_pkey_get0_EC_KEY_int(pkey: *const EvpPkey) -> *mut EcKey {
    // SAFETY: `pkey` is live per the contract.
    if unsafe { EVP_PKEY_get_base_id(pkey) } != EVP_PKEY_EC {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::P_LEGACY_79) };
        return core::ptr::null_mut();
    }
    // SAFETY: `pkey` is live, cast to the mutable form the accessor takes.
    unsafe { evp_pkey_get_legacy(pkey as *mut EvpPkey) }.cast::<EcKey>()
}

/// `const EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:85`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get0_EC_KEY(pkey: *const EvpPkey) -> *const EcKey {
    // SAFETY: `pkey` is live per the contract.
    unsafe { evp_pkey_get0_EC_KEY_int(pkey) }
}

/// `EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey)` — `crypto/evp/p_legacy.c:90`.
///
/// # Safety
/// `pkey` must be live.
#[no_mangle]
pub unsafe extern "C" fn EVP_PKEY_get1_EC_KEY(pkey: *mut EvpPkey) -> *mut EcKey {
    // SAFETY: `pkey` is live per the contract.
    let ret = unsafe { evp_pkey_get0_EC_KEY_int(pkey) };

    // SAFETY: `ret` is non-NULL and therefore a live `EC_KEY` per the accessor's contract.
    if !ret.is_null() && unsafe { EC_KEY_up_ref(ret) } == 0 {
        return core::ptr::null_mut();
    }
    ret
}
