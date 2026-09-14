//! Phase 5 — `BN_nist_mod_*`: reduction modulo the five NIST primes.
//!
//! ## What these functions actually are
//!
//! The authority's bodies are heavily unrolled carry chains, and the first line of
//! each one is `field = &ossl_bignum_nist_p_192; /* just to make sure */` — the
//! caller's `field` argument is **overwritten** before it is used, and the small and
//! negative cases are dispatched straight to `BN_nnmod` against that same static
//! prime. The unrolled path exists to make the same reduction fast, not to make it
//! different.
//!
//! So the observable contract is one sentence: the result is the non-negative
//! remainder of `a` modulo that specific prime, whatever `field` the caller passed.
//! Implementing it as `BN_nnmod` against the same generated constant is therefore
//! exact rather than approximate, and it is the version that cannot silently disagree
//! with its authority when a carry chain is mistranscribed.
//!
//! ## `BN_nist_mod_func`
//!
//! It selects by **value**, not by identity: the authority compares `BN_ucmp` against
//! each static prime, so any `BIGNUM` equal to one of them selects that reducer, and
//! anything else — including a different prime of the same size — selects nothing and
//! returns `NULL`.

use core::ffi::c_int;

use crate::bn::arith::BN_nnmod;
use crate::bn::bignum::{as_ref, parts, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::Limb;
use crate::bn::primes::{
    BN_get0_nist_prime_192, BN_get0_nist_prime_224, BN_get0_nist_prime_256, BN_get0_nist_prime_384,
    BN_get0_nist_prime_521,
};
use crate::ffi::guard_ffi;

/// The signature the authority gives `BN_nist_mod_func`'s result.
pub(crate) type NistReduce =
    unsafe extern "C" fn(*mut BigNum, *const BigNum, *const BigNum, *mut BnCtx) -> c_int;

/// Whether `pd` (a magnitude) is the value of `prime`.
///
/// # Safety
///
/// `prime` must be a live `BIGNUM`, which the static getters guarantee.
unsafe fn is_value(pd: &[Limb], prime: *const BigNum) -> bool {
    // SAFETY: the caller guarantees `prime` is live.
    parts(unsafe { as_ref(prime) }).0 == pd
}

/// The one body all five reducers share.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` must be null or live;
/// `prime` must be a live static `BIGNUM`; `ctx` is unused.
unsafe fn reduce(r: *mut BigNum, a: *const BigNum, prime: *const BigNum, ctx: *mut BnCtx) -> c_int {
    // SAFETY: `BN_nnmod`'s contract is this function's contract.
    unsafe { BN_nnmod(r, a, prime, ctx) }
}

/// `int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *field, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `field` must each be
/// null or live; `ctx` is unused. `field` is accepted and ignored, as the authority
/// ignores it.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_192(
    r: *mut BigNum,
    a: *const BigNum,
    _field: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the getter takes no pointers; `reduce`'s contract is this
        // function's.
        unsafe { reduce(r, a, BN_get0_nist_prime_192(), ctx) }
    })
}

/// `int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *field, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_nist_mod_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_224(
    r: *mut BigNum,
    a: *const BigNum,
    _field: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as above.
        unsafe { reduce(r, a, BN_get0_nist_prime_224(), ctx) }
    })
}

/// `int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_nist_mod_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_256(
    r: *mut BigNum,
    a: *const BigNum,
    _field: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as above.
        unsafe { reduce(r, a, BN_get0_nist_prime_256(), ctx) }
    })
}

/// `int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *field, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_nist_mod_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_384(
    r: *mut BigNum,
    a: *const BigNum,
    _field: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as above.
        unsafe { reduce(r, a, BN_get0_nist_prime_384(), ctx) }
    })
}

/// `int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *field, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_nist_mod_192`.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_521(
    r: *mut BigNum,
    a: *const BigNum,
    _field: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as above.
        unsafe { reduce(r, a, BN_get0_nist_prime_521(), ctx) }
    })
}

/// `int (*BN_nist_mod_func(const BIGNUM *p))(BIGNUM *, const BIGNUM *,`
/// `const BIGNUM *, BN_CTX *)`
///
/// `None` — a null function pointer to the caller — when `p` is not one of the five.
///
/// # Safety
///
/// `p` must be null or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_nist_mod_func(p: *const BigNum) -> Option<NistReduce> {
    guard_ffi(None, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (pd, _) = parts(unsafe { as_ref(p) });
        // SAFETY: every getter takes no pointers, and `is_value`'s contract is that
        // its second argument is live, which a static getter's result is.
        unsafe {
            if is_value(&pd, BN_get0_nist_prime_192()) {
                return Some(BN_nist_mod_192);
            }
            if is_value(&pd, BN_get0_nist_prime_224()) {
                return Some(BN_nist_mod_224);
            }
            if is_value(&pd, BN_get0_nist_prime_256()) {
                return Some(BN_nist_mod_256);
            }
            if is_value(&pd, BN_get0_nist_prime_384()) {
                return Some(BN_nist_mod_384);
            }
            if is_value(&pd, BN_get0_nist_prime_521()) {
                return Some(BN_nist_mod_521);
            }
        }
        None
    })
}
