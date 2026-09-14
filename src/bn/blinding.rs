//! Phase 5 — `BN_BLINDING`, the blinding context RSA uses to keep a private
//! exponentiation from being a timing oracle.
//!
//! The type is opaque, so the representation is ours; what is reproduced is the
//! observable state machine, and it has three parts worth naming:
//!
//! * **`counter == -1` means "fresh, never used"**, and that is not the same as
//!   `counter == 0`: a fresh context is not updated before its first use, and
//!   `BN_BLINDING_convert_ex` is where the distinction is spent.
//! * **The lock and the owning thread are part of the object.** `BN_BLINDING_lock`
//!   takes the internal write lock and `BN_BLINDING_is_current_thread` compares the
//!   recorded `CRYPTO_THREAD_ID` with the caller's, so a caller can use both to
//!   decide whether this context is its own.
//! * **A null modulus is not a crash.** `BN_BLINDING_new` stores a duplicate of the
//!   modulus and a `BN_dup(NULL)` is NULL, so a null modulus takes the error path and
//!   returns NULL — the authority's `bn_check_top` is a debug-only assertion, so in
//!   the shipped build that is the behaviour a caller sees.
//!
//! The use counter and the exponent are deliberately **not** fields here. Their only
//! readers are the four Phase 9 functions below, and a field nothing can read is not
//! state this stratum maintains — it arrives with the code that reads it, which is
//! also the only way to keep `counter == -1` meaning "fresh" rather than just being
//! another integer.
//!
//! ## What is not here
//!
//! `BN_BLINDING_create_param`, `BN_BLINDING_update`, `BN_BLINDING_convert` and
//! `BN_BLINDING_convert_ex` are Phase 9's: `update` re-creates the blinding factor
//! through `create_param` once `counter` reaches `BN_BLINDING_COUNTER`, and
//! `create_param` draws that factor with `BN_rand_range`. The re-creation is
//! reachable for any context whose exponent was set, so none of the four can be
//! reproduced faithfully without the RAND stratum. The ledger records the hand-off
//! and the seal states the count.

use core::ffi::{c_int, c_ulong};

use crate::bn::arith::BN_mod_mul;
use crate::bn::bignum::{BN_dup, BN_free, BigNum};
use crate::bn::ctx::BnCtx;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BN_BLIND_172, BN_BLIND_41};
use crate::runtime::err::raise_site;
use crate::runtime::thread::{
    CRYPTO_THREAD_compare_id, CRYPTO_THREAD_get_current_id, CRYPTO_THREAD_lock_free,
    CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock, CryptoRwlock,
    CryptoThreadId,
};

/// The authority's `BN_BLINDING`.
pub struct Blinding {
    /// `A` — the blinding factor.
    a: *mut BigNum,
    /// `Ai` — its inverse, which is what `BN_BLINDING_invert_ex` multiplies by.
    ai: *mut BigNum,
    /// `e` — the exponent the factor was derived with, when the caller set one.
    e: *mut BigNum,
    /// `mod` — the modulus, owned because the authority duplicates it too.
    mod_: *mut BigNum,
    /// `tid` — the thread that created or last claimed this context.
    tid: CryptoThreadId,
    /// `flags` — `BN_BLINDING_NO_UPDATE` and `BN_BLINDING_NO_RECREATE` live here.
    flags: c_ulong,
    /// `lock` — the context's own lock.
    lock: *mut CryptoRwlock,
}

/// Read a `*mut Blinding` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `Blinding`.
unsafe fn as_mut_blinding<'a>(p: *mut Blinding) -> Option<&'a mut Blinding> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// Read a `*const Blinding` as a shared reference.
///
/// # Safety
///
/// `p` must be null or point to a live `Blinding`.
unsafe fn as_ref_blinding<'a>(p: *const Blinding) -> Option<&'a Blinding> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live.
        Some(unsafe { &*p })
    }
}

/// `BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod)`
///
/// # Safety
///
/// `a` and `ai` must each be null or live; `m` must be null or a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_new(
    a: *const BigNum,
    ai: *const BigNum,
    m: *mut BigNum,
) -> *mut Blinding {
    guard_ffi(core::ptr::null_mut(), || {
        let fresh = Box::into_raw(Box::new(Blinding {
            a: core::ptr::null_mut(),
            ai: core::ptr::null_mut(),
            e: core::ptr::null_mut(),
            mod_: core::ptr::null_mut(),
            tid: 0,
            flags: 0,
            lock: core::ptr::null_mut(),
        }));

        // SAFETY: the lock constructor takes no pointers, so this call needs no
        // `unsafe`.
        let lock = CRYPTO_THREAD_lock_new();
        // SAFETY: as above.
        unsafe { (*fresh).lock = lock };
        if lock.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_BLIND_41) };
            // SAFETY: `fresh` is the object this call allocated.
            drop(unsafe { Box::from_raw(fresh) });
            return core::ptr::null_mut();
        }

        // SAFETY: `fresh` is live and uniquely owned.
        unsafe { BN_BLINDING_set_current_thread(fresh) };

        if !a.is_null() {
            // SAFETY: `a` is live per this function's contract.
            let dup = unsafe { BN_dup(a) };
            // SAFETY: as above.
            unsafe { (*fresh).a = dup };
            if dup.is_null() {
                // SAFETY: `fresh` is the object this call allocated.
                unsafe { BN_BLINDING_free(fresh) };
                return core::ptr::null_mut();
            }
        }
        if !ai.is_null() {
            // SAFETY: `ai` is live per this function's contract.
            let dup = unsafe { BN_dup(ai) };
            // SAFETY: as above.
            unsafe { (*fresh).ai = dup };
            if dup.is_null() {
                // SAFETY: `fresh` is the object this call allocated.
                unsafe { BN_BLINDING_free(fresh) };
                return core::ptr::null_mut();
            }
        }
        // The modulus is duplicated unconditionally, so a null one fails here —
        // which is what the authority's `BN_dup(NULL)` does in the shipped build.
        // SAFETY: `m` is null or live per this function's contract.
        let mdup = unsafe { BN_dup(m) };
        // SAFETY: `fresh` is live and uniquely owned.
        unsafe { (*fresh).mod_ = mdup };
        if mdup.is_null() {
            // SAFETY: `fresh` is the object this call allocated.
            unsafe { BN_BLINDING_free(fresh) };
            return core::ptr::null_mut();
        }
        fresh
    })
}

/// `void BN_BLINDING_free(BN_BLINDING *b)`
///
/// A null pointer is a no-op.
///
/// # Safety
///
/// `b` must be null or a pointer returned by `BN_BLINDING_new`, and not already
/// freed.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_free(b: *mut Blinding) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let Some(b) = (unsafe { as_mut_blinding(b) }) else {
            return;
        };
        // SAFETY: every member is null or a live object this context owns, and each
        // `BN_free` accepts null.
        unsafe {
            BN_free(b.a);
            BN_free(b.ai);
            BN_free(b.e);
            BN_free(b.mod_);
            CRYPTO_THREAD_lock_free(b.lock);
        }
        // SAFETY: the caller's contract is exactly that `b` came from
        // `BN_BLINDING_new` and has not been freed.
        drop(unsafe { Box::from_raw(b as *mut Blinding) });
    });
}

/// `int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)`
///
/// # Safety
///
/// `n` must be a live, uniquely-owned `BIGNUM`; `b` must be null or a live
/// `BN_BLINDING`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_invert(
    n: *mut BigNum,
    b: *mut Blinding,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: `BN_BLINDING_invert_ex`'s contract is this function's contract.
    unsafe { BN_BLINDING_invert_ex(n, core::ptr::null(), b, ctx) }
}

/// `int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b,`
/// `BN_CTX *ctx)`
///
/// A null `r` means "use the context's own inverse", and a context that has none is
/// the `NOT_INITIALIZED` failure.
///
/// # Safety
///
/// `n` must be a live, uniquely-owned `BIGNUM`; `r` must be null or live; `b` must be
/// null or a live `BN_BLINDING`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_invert_ex(
    n: *mut BigNum,
    r: *const BigNum,
    b: *mut Blinding,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let bc = unsafe { as_ref_blinding(b) };
        let Some(bc) = bc else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_BLIND_172) };
            return 0;
        };
        let factor = if r.is_null() { bc.ai } else { r.cast_mut() };
        if factor.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_BLIND_172) };
            return 0;
        }
        // SAFETY: `BN_mod_mul`'s contract is this function's contract.
        unsafe { BN_mod_mul(n, n, factor, bc.mod_, ctx) }
    })
}

/// `int BN_BLINDING_is_current_thread(BN_BLINDING *b)`
///
/// # Safety
///
/// `b` must be null or a live `BN_BLINDING`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_is_current_thread(b: *mut Blinding) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let Some(bc) = (unsafe { as_ref_blinding(b) }) else {
            return 0;
        };
        CRYPTO_THREAD_compare_id(CRYPTO_THREAD_get_current_id(), bc.tid)
    })
}

/// `void BN_BLINDING_set_current_thread(BN_BLINDING *b)`
///
/// # Safety
///
/// `b` must be null or a live, uniquely-owned `BN_BLINDING`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_set_current_thread(b: *mut Blinding) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(bc) = unsafe { as_mut_blinding(b) } {
            bc.tid = CRYPTO_THREAD_get_current_id();
        }
    });
}

/// `int BN_BLINDING_lock(BN_BLINDING *b)`
///
/// # Safety
///
/// `b` must be null or a live `BN_BLINDING` whose lock is live.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_lock(b: *mut Blinding) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let Some(bc) = (unsafe { as_ref_blinding(b) }) else {
            return 0;
        };
        // SAFETY: the lock is created with the context and freed only with it.
        unsafe { CRYPTO_THREAD_write_lock(bc.lock) }
    })
}

/// `int BN_BLINDING_unlock(BN_BLINDING *b)`
///
/// # Safety
///
/// As `BN_BLINDING_lock`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_unlock(b: *mut Blinding) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let Some(bc) = (unsafe { as_ref_blinding(b) }) else {
            return 0;
        };
        // SAFETY: as above.
        unsafe { CRYPTO_THREAD_unlock(bc.lock) }
    })
}

/// `unsigned long BN_BLINDING_get_flags(const BN_BLINDING *b)`
///
/// # Safety
///
/// `b` must be null or a live `BN_BLINDING`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_get_flags(b: *const Blinding) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref_blinding(b) } {
            Some(bc) => bc.flags,
            None => 0,
        }
    })
}

/// `void BN_BLINDING_set_flags(BN_BLINDING *b, unsigned long flags)`
///
/// # Safety
///
/// `b` must be null or a live, uniquely-owned `BN_BLINDING`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_set_flags(b: *mut Blinding, flags: c_ulong) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(bc) = unsafe { as_mut_blinding(b) } {
            bc.flags = flags;
        }
    });
}
