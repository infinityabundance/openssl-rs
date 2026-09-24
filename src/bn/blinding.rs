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
//! ## The four functions Phase 9 owed, and the three fields they read
//!
//! `BN_BLINDING_create_param`, `BN_BLINDING_update`, `BN_BLINDING_convert` and
//! `BN_BLINDING_convert_ex` complete the file. `update` re-creates the blinding
//! factor through `create_param` once `counter` reaches `BN_BLINDING_COUNTER`
//! (`32`), and `create_param` draws that factor with `BN_priv_rand_range_ex`; that
//! is why the family could not be reproduced before the RAND stratum landed.
//!
//! Three fields arrived with them, and each is read by exactly one of the four:
//! `counter` (the `-1`/`0`/`32` state machine), `m_ctx` (the Montgomery context
//! `create_param`'s caller may hand in) and `bn_mod_exp` (the exponentiation
//! function pointer of the same call).
//!
//! `BN_BLINDING_new` also grew one line of its own body that had been left out:
//! the authority copies `BN_FLG_CONSTTIME` from the caller's modulus onto its own
//! duplicate (`bn_blind.c:62-63`), and that flag is what `int_bn_mod_inverse`
//! below branches on.

use core::ffi::{c_int, c_ulong};

use crate::bn::arith::{BN_mod_exp, BN_mod_mul};
use crate::bn::bignum::{
    as_mut, as_ref, parts, store, BN_copy, BN_dup, BN_free, BN_get_flags, BN_new, BN_set_flags,
    BigNum,
};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs;
use crate::bn::mont::{BN_mod_mul_montgomery, BN_to_montgomery, MontCtx};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BN_BLIND_138, BN_BLIND_172, BN_BLIND_283, BN_BLIND_41, BN_BLIND_96,
};
use crate::runtime::err::raise_site;
use crate::runtime::thread::{
    CRYPTO_THREAD_compare_id, CRYPTO_THREAD_get_current_id, CRYPTO_THREAD_lock_free,
    CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock, CryptoRwlock,
    CryptoThreadId,
};

/// `BN_BLINDING_COUNTER` — `crypto/bn/bn_blind.c:14`. The use count at which
/// `BN_BLINDING_update` re-creates the factor.
const BN_BLINDING_COUNTER: c_int = 32;
/// `BN_BLINDING_NO_UPDATE` — `include/openssl/bn.h:421`.
const BN_BLINDING_NO_UPDATE: c_ulong = 0x0000_0001;
/// `BN_BLINDING_NO_RECREATE` — `include/openssl/bn.h:422`.
const BN_BLINDING_NO_RECREATE: c_ulong = 0x0000_0002;
/// `BN_FLG_CONSTTIME` — `include/openssl/bn.h:67`.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// The authority's `bn_mod_exp` member: `int (*)(BIGNUM *r, const BIGNUM *a,
/// const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)`, the sixth
/// parameter of `BN_BLINDING_create_param` (`include/openssl/bn.h:440-446`).
/// `BN_mod_exp_mont` has exactly this signature.
pub type BnModExp = Option<
    unsafe extern "C" fn(
        *mut BigNum,
        *const BigNum,
        *const BigNum,
        *const BigNum,
        *mut BnCtx,
        *mut MontCtx,
    ) -> c_int,
>;

/// The authority's `BN_BLINDING`.
///
/// The field names follow `struct bn_blinding_st` (`crypto/bn/bn_local.h`) so the
/// structure stays reviewable against its origin, even though no caller can see it.
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
    /// `counter` — the use count. `-1` is "fresh, never used", which is *not*
    /// `0`: a fresh context is not updated before its first use.
    counter: c_int,
    /// `flags` — `BN_BLINDING_NO_UPDATE` and `BN_BLINDING_NO_RECREATE` live here.
    flags: c_ulong,
    /// `m_ctx` — the Montgomery context the factor was derived in, when the caller
    /// passed one to `BN_BLINDING_create_param`. It is the caller's object, not
    /// this context's, so it is not freed here; it selects the Montgomery spelling
    /// of the three multiplications `update`, `convert_ex` and `invert_ex` make.
    m_ctx: *mut MontCtx,
    /// `bn_mod_exp` — the exponentiation `create_param` uses when both this and
    /// `m_ctx` are set, and `BN_mod_exp` otherwise.
    bn_mod_exp: BnModExp,
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
            counter: -1,
            flags: 0,
            m_ctx: core::ptr::null_mut(),
            bn_mod_exp: None,
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
        // `bn_blind.c:62-63`: the caller's consttime request is carried onto the
        // duplicate, and it is what selects the branch-free inversion in
        // `BN_BLINDING_create_param` below.
        // SAFETY: `m` is null or live per this function's contract, and `mdup` is
        // live; both take null-or-live.
        unsafe {
            if BN_get_flags(m, BN_FLG_CONSTTIME) != 0 {
                BN_set_flags(mdup, BN_FLG_CONSTTIME);
            }
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
/// The `m_ctx` branch multiplies through the context's Montgomery form, which is the
/// only shape in which `BN_BLINDING_create_param` can have left `A`/`Ai` when the
/// caller passed a Montgomery context. The authority's body writes that branch with
/// `bn_mul_mont_fixed_top` plus a hand-rolled `dmax`/`top` fix-up and a closing
/// `bn_correct_top_consttime`; here it is `BN_mod_mul_montgomery`, whose *value* is
/// the same and which normalises the top itself. The fix-up is representation only —
/// it exists so the multiply takes the constant-time path — so nothing a caller can
/// observe differs. See the module note.
///
/// # Safety
///
/// `n` must be a live, uniquely-owned `BIGNUM`; `r` must be null or live; `b` must be
/// null or a live `BN_BLINDING`; `ctx` must be null or a live `BN_CTX`.
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
        if !bc.m_ctx.is_null() {
            // SAFETY: `n` and `factor` are live per this function's contract and the
            // Montgomery context belongs to the caller; `BN_mod_mul_montgomery` has
            // exactly that contract.
            return unsafe { BN_mod_mul_montgomery(n, n, factor, bc.m_ctx, ctx) };
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

/// `int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)` —
/// `crypto/bn/bn_blind.c:91-124`.
///
/// Three arms, and the order they are written in is the contract:
///
/// * `counter == -1` becomes `0` first, so a **fresh** context is not updated
///   before its first use (this is the whole reason `-1` and `0` are distinct).
/// * the counter is then pre-incremented; reaching `BN_BLINDING_COUNTER` with an
///   exponent set and `NO_RECREATE` clear **re-creates** the factor through
///   [`BN_BLINDING_create_param`], drawing a new one.
/// * otherwise, unless `NO_UPDATE` is set, the factor and its inverse are squared.
///   Note that the `else` is reached when the counter does reach `32` but the
///   re-creation is suppressed, so a `NO_RECREATE` context squares instead — the
///   authority's own shape, kept.
///
/// The trailing `if (b->counter == BN_BLINDING_COUNTER) b->counter = 0;` is on the
/// `err` path as well as the success path, and it is written here the same way:
/// a failed re-creation still wraps the counter.
///
/// A null `b` is a null dereference in the authority (`b->A`). This crate refuses
/// it at the site's own `NOT_INITIALIZED`, which is a graceful extension rather
/// than a claim about the crash — the same convention `src/bn/rand.rs` records for
/// a null range.
///
/// # Safety
///
/// `b` must be null or a live, uniquely-owned `BN_BLINDING`; `ctx` must be null or a
/// live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_update(b: *mut Blinding, ctx: *mut BnCtx) -> c_int {
    guard_ffi(0, || {
        if b.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_BLIND_96) };
            return 0;
        }
        // SAFETY: `b` is non-null and live per this function's `# Safety` section;
        // the body below reads and writes its fields through this pointer only.
        let bp = b;
        // SAFETY: as above; every read is of a null-or-live member or a plain scalar.
        unsafe {
            if (*bp).a.is_null() || (*bp).ai.is_null() {
                raise_site(&BN_BLIND_96);
                return 0;
            }

            if (*bp).counter == -1 {
                (*bp).counter = 0;
            }

            (*bp).counter += 1;
            let mut ok = true;
            if (*bp).counter == BN_BLINDING_COUNTER
                && !(*bp).e.is_null()
                && ((*bp).flags & BN_BLINDING_NO_RECREATE) == 0
            {
                // The authority's `BN_BLINDING_create_param(b, NULL, NULL, ctx,
                // NULL, NULL)`: the exponent and modulus stay this context's own.
                if BN_BLINDING_create_param(
                    bp,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    ctx,
                    None,
                    core::ptr::null_mut(),
                )
                .is_null()
                {
                    ok = false;
                }
            } else if ((*bp).flags & BN_BLINDING_NO_UPDATE) == 0 {
                if !(*bp).m_ctx.is_null() {
                    ok = BN_mod_mul_montgomery((*bp).ai, (*bp).ai, (*bp).ai, (*bp).m_ctx, ctx) != 0
                        && BN_mod_mul_montgomery((*bp).a, (*bp).a, (*bp).a, (*bp).m_ctx, ctx) != 0;
                } else {
                    ok = BN_mod_mul((*bp).ai, (*bp).ai, (*bp).ai, (*bp).mod_, ctx) != 0
                        && BN_mod_mul((*bp).a, (*bp).a, (*bp).a, (*bp).mod_, ctx) != 0;
                }
            }

            if (*bp).counter == BN_BLINDING_COUNTER {
                (*bp).counter = 0;
            }
            c_int::from(ok)
        }
    })
}

/// `int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx)` —
/// `crypto/bn/bn_blind.c:126-129`.
///
/// # Safety
///
/// As [`BN_BLINDING_convert_ex`], with no `r`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_convert(
    n: *mut BigNum,
    b: *mut Blinding,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: `BN_BLINDING_convert_ex`'s contract is this function's contract.
    unsafe { BN_BLINDING_convert_ex(n, core::ptr::null_mut(), b, ctx) }
}

/// `int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *ctx)`
/// — `crypto/bn/bn_blind.c:131-157`.
///
/// The `counter == -1` test here is what spends the fresh/used distinction: a
/// never-used context multiplies by `A` with **no** update, and every later call
/// updates first through [`BN_BLINDING_update`]. A non-null `r` is a copy of the
/// inverse that was current *after* that update, which is what makes
/// `convert_ex`/`invert_ex(n, r, ...)` an identity.
///
/// # Safety
///
/// `n` must be a live, uniquely-owned `BIGNUM`; `r` must be null or a live,
/// uniquely-owned `BIGNUM`; `b` must be null or a live `BN_BLINDING`; `ctx` must be
/// null or a live `BN_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_convert_ex(
    n: *mut BigNum,
    r: *mut BigNum,
    b: *mut Blinding,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        if b.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_BLIND_138) };
            return 0;
        }
        // SAFETY: `b` is non-null and live per this function's `# Safety` section.
        let bp = b;
        // SAFETY: as above; every read is of a null-or-live member or a plain scalar.
        unsafe {
            if (*bp).a.is_null() || (*bp).ai.is_null() {
                raise_site(&BN_BLIND_138);
                return 0;
            }

            if (*bp).counter == -1 {
                // Fresh blinding, doesn't need updating.
                (*bp).counter = 0;
            } else if BN_BLINDING_update(bp, ctx) == 0 {
                return 0;
            }

            if !r.is_null() && BN_copy(r, (*bp).ai).is_null() {
                return 0;
            }

            if !(*bp).m_ctx.is_null() {
                BN_mod_mul_montgomery(n, n, (*bp).a, (*bp).m_ctx, ctx)
            } else {
                BN_mod_mul(n, n, (*bp).a, (*bp).mod_, ctx)
            }
        }
    })
}

/// The observable half of `int_bn_mod_inverse` (`crypto/bn/bn_gcd.c:197`), the
/// internal `BN_BLINDING_create_param` calls **instead of** the public
/// `BN_mod_inverse`.
///
/// Two differences from [`crate::bn::arith::BN_mod_inverse`] are why the internal is
/// named here rather than the wrapper being used:
///
/// * **it raises nothing.** The wrapper raises `BN_R_NO_INVERSE` when no inverse
///   exists, and `create_param` calls the internal precisely so that a retry is
///   silent. A caller draining the error queue would see the wrapper's raise on
///   every non-coprime draw.
/// * its `int *pnoinv` out-parameter separates "no inverse" (`1`, the retry) from
///   "the computation failed" (`0`).
///
/// Answers `true` for `pnoinv == 1`: the modulus is `0` or `\u00b11`
/// (`BN_abs_is_word(n, 1) || BN_is_zero(n)`, the authority's first test), or the value
/// shares a factor with it. `pnoinv == 0` with a NULL return is the authority's
/// temporary-pool exhaustion, which has no counterpart here — this crate's
/// temporaries are `Vec`s, whose allocation failure aborts rather than answering
/// null — so the retry loop has one reachable reason to continue instead of two.
/// That is a recorded divergence, not a silent one.
///
/// The consttime branch (`bn_mod_inverse_no_branch`, `crypto/bn/bn_gcd.c:215`) is
/// not a separate branch here: both authority branches compute the same residue, and
/// what the flag buys there is constant *time*, which no value-level observation can
/// see. `BN_FLG_CONSTTIME` is still carried onto the modulus by `BN_BLINDING_new`,
/// because that is the flag's only reader in this file.
///
/// # Safety
///
/// `dst` must be a live, uniquely-owned `BIGNUM`; `a` and `n` must each be null or
/// live.
unsafe fn int_bn_mod_inverse(dst: *mut BigNum, a: *const BigNum, n: *const BigNum) -> bool {
    // SAFETY: null-or-live per this function's `# Safety` section.
    let (x, y) = unsafe { (as_ref(a), as_ref(n)) };
    let (ad, _) = parts(x);
    let (nd, _) = parts(y);
    if nd.is_empty() || (nd.len() == 1 && nd[0] == 1) {
        return true;
    }
    match limbs::mod_inverse(&ad, &nd) {
        Some(inv) => {
            // SAFETY: `dst` is live per this function's `# Safety` section.
            unsafe { store(as_mut(dst), inv, false) };
            false
        }
        None => true,
    }
}

/// `BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b, const BIGNUM *e,`
/// `BIGNUM *m, BN_CTX *ctx, int (*bn_mod_exp)(...), BN_MONT_CTX *m_ctx)` —
/// `crypto/bn/bn_blind.c:231-310`.
///
/// The `retry_counter` loop is the authority's: a draw whose value is not coprime
/// with the modulus is retried, up to `33` draws (`retry_counter--` compares before
/// it decrements, so the value `0` is tested on the thirty-third pass), and then
/// `BN_R_TOO_MANY_ITERATIONS` is raised. The draw itself is
/// `BN_priv_rand_range_ex(A, mod, 0, ctx)`, so this is the function that needed the
/// RAND stratum.
///
/// Two things a caller can observe about the object it gets back:
///
/// * When `b` is NULL the context is new, and every failure **frees it and answers
///   NULL** — `m == NULL` fails inside `BN_BLINDING_new`'s `BN_dup`, and a NULL `e`
///   fails the `ret->e == NULL` test. Neither raises anything, so an empty error
///   queue is the observable.
/// * When `b` is non-NULL the context is the caller's and every failure answers
///   **`b` itself**, partly initialised, with nothing freed. That asymmetry is the
///   authority's `err: if (b == NULL) {...}` and is kept.
///
/// # Safety
///
/// `b` must be null or a live, uniquely-owned `BN_BLINDING`; `e` must be null or
/// live; `m` must be null or live and must outlive the returned context when `b` is
/// null (the context duplicates it, so in practice it must merely be valid for this
/// call); `ctx` must be null or a live `BN_CTX`; `bn_mod_exp`, when non-null, must be
/// a function with the authority's `bn_mod_exp` signature that is safe to call with
/// the arguments below; `m_ctx` must be null or a live Montgomery context that
/// outlives the returned context.
#[no_mangle]
pub unsafe extern "C" fn BN_BLINDING_create_param(
    b: *mut Blinding,
    e: *const BigNum,
    m: *mut BigNum,
    ctx: *mut BnCtx,
    bn_mod_exp: BnModExp,
    m_ctx: *mut MontCtx,
) -> *mut Blinding {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `BN_BLINDING_new`'s contract is this function's; its `m` argument
        // is null-or-live here too.
        let mut ret: *mut Blinding = if b.is_null() {
            // SAFETY: `m` is live and the two nulls are what this arm passes.
            unsafe { BN_BLINDING_new(core::ptr::null(), core::ptr::null(), m) }
        } else {
            b
        };
        if ret.is_null() {
            return core::ptr::null_mut();
        }

        let ok = (|| -> bool {
            // SAFETY: `ret` is non-null and live, either from `BN_BLINDING_new`
            // above or from the caller; every access below is a read or write of one
            // of its members, each of which is null-or-live.
            unsafe {
                if (*ret).a.is_null() {
                    (*ret).a = BN_new();
                }
                if (*ret).a.is_null() {
                    return false;
                }
                if (*ret).ai.is_null() {
                    (*ret).ai = BN_new();
                }
                if (*ret).ai.is_null() {
                    return false;
                }

                if !e.is_null() {
                    BN_free((*ret).e);
                    (*ret).e = BN_dup(e);
                }
                if (*ret).e.is_null() {
                    return false;
                }

                if bn_mod_exp.is_some() {
                    (*ret).bn_mod_exp = bn_mod_exp;
                }
                if !m_ctx.is_null() {
                    (*ret).m_ctx = m_ctx;
                }

                let mut retry_counter: c_int = 32;
                loop {
                    if BN_priv_rand_range_ex((*ret).a, (*ret).mod_, 0, ctx) == 0 {
                        return false;
                    }
                    if !int_bn_mod_inverse((*ret).ai, (*ret).a, (*ret).mod_) {
                        break;
                    }
                    // The authority's `if (!rv) goto err;`: `pnoinv == 0` with a
                    // NULL return. See `int_bn_mod_inverse` above — reachable there
                    // and not here.
                    if retry_counter == 0 {
                        raise_site(&BN_BLIND_283);
                        return false;
                    }
                    retry_counter -= 1;
                }

                let used_mont_exp = match (*ret).bn_mod_exp {
                    // SAFETY: the pointer was installed by this function from the
                    // caller's argument, whose contract says it is safe to call with
                    // these arguments, and `m_ctx` is the caller's live context.
                    Some(f) if !(*ret).m_ctx.is_null() => {
                        if f((*ret).a, (*ret).a, (*ret).e, (*ret).mod_, ctx, (*ret).m_ctx) == 0 {
                            return false;
                        }
                        true
                    }
                    _ => false,
                };
                if !used_mont_exp && BN_mod_exp((*ret).a, (*ret).a, (*ret).e, (*ret).mod_, ctx) == 0
                {
                    return false;
                }

                if !(*ret).m_ctx.is_null()
                    && (BN_to_montgomery((*ret).ai, (*ret).ai, (*ret).m_ctx, ctx) == 0
                        || BN_to_montgomery((*ret).a, (*ret).a, (*ret).m_ctx, ctx) == 0)
                {
                    return false;
                }
                true
            }
        })();

        if !ok && b.is_null() {
            // SAFETY: `ret` is the object `BN_BLINDING_new` returned and nothing
            // else refers to it; `b` was null, so the authority frees it here.
            unsafe { BN_BLINDING_free(ret) };
            ret = core::ptr::null_mut();
        }
        ret
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::{BN_cmp, BN_sub_word};
    use crate::bn::bignum::{BN_hex2bn, BN_is_one};
    use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
    use crate::bn::mont::{BN_MONT_CTX_free, BN_MONT_CTX_new, BN_MONT_CTX_set};
    use crate::runtime::err::{err_sites, ERR_clear_error, ERR_peek_error};

    /// The packed code `ERR_peek_error` reports for a recorded site.
    fn packed(site: &err_sites::ErrSite) -> c_ulong {
        (((site.lib as c_ulong) & 0xff) << 23) | ((site.reason as c_ulong) & 0x7f_ffff)
    }

    /// The secp256k1 field prime: 256 bits, odd, and **prime**, so a random value in
    /// `[0, m)` is coprime with it and `create_param`'s retry loop never spins. That
    /// makes the arms below cheap and their identities sharp.
    const MODULUS: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

    /// Build a `BIGNUM` from a hex string.
    fn hex(s: &str) -> *mut BigNum {
        let c = crate::bn::bignum::dup_cstring(s);
        let mut p: *mut BigNum = core::ptr::null_mut();
        // SAFETY: `p` is this frame's slot and `c` is NUL-terminated and live.
        unsafe {
            assert!(BN_hex2bn(&mut p, c) > 0);
            crate::runtime::mem::CRYPTO_free(c.cast(), core::ptr::null(), 0);
        }
        p
    }

    /// A context the caller has to set up is refused with `NOT_INITIALIZED` at
    /// `BN_BLINDING_update`'s own coordinate rather than updated.
    #[test]
    fn update_on_a_context_without_a_factor_is_not_initialized() {
        let m = hex("010001"); // 65537, a plausible RSA modulus *shape*
                               // SAFETY: `m` is live; `BN_BLINDING_new` admits null `A`/`Ai`.
        let b = unsafe { BN_BLINDING_new(core::ptr::null(), core::ptr::null(), m) };
        assert!(!b.is_null());

        ERR_clear_error();
        // SAFETY: `b` is live and `ctx` is null, which the entry point admits.
        assert_eq!(unsafe { BN_BLINDING_update(b, core::ptr::null_mut()) }, 0);
        assert_eq!(ERR_peek_error(), packed(&BN_BLIND_96));

        ERR_clear_error();
        let n = hex("03");
        // SAFETY: `n` and `b` are live.
        assert_eq!(
            // SAFETY: `n` and `b` are live.
            unsafe { BN_BLINDING_convert(n, b, core::ptr::null_mut()) },
            0
        );
        assert_eq!(ERR_peek_error(), packed(&BN_BLIND_138));
        assert_eq!(
            // SAFETY: as above, with a null `r`.
            unsafe { BN_BLINDING_convert_ex(n, core::ptr::null_mut(), b, core::ptr::null_mut()) },
            0
        );
        assert_eq!(ERR_peek_error(), packed(&BN_BLIND_138));

        // SAFETY: both were allocated in this test.
        unsafe {
            BN_free(n);
            BN_BLINDING_free(b);
            BN_free(m);
        }
    }

    /// `create_param` with a null `b` and a null exponent answers NULL **without
    /// raising**: the authority's `ret->e == NULL` test is not an error site.
    #[test]
    fn create_param_without_an_exponent_answers_null_quietly() {
        let m = hex("010001");
        ERR_clear_error();
        // SAFETY: `m` is live; `b` is null on purpose and `e`/`ctx`/`m_ctx` are null.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                core::ptr::null(),
                m,
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(b.is_null());
        assert_eq!(ERR_peek_error(), 0, "no site is reached");
        // SAFETY: `m` was allocated in this test.
        unsafe { BN_free(m) };
    }

    /// A null modulus fails inside `BN_BLINDING_new`'s `BN_dup` and answers NULL
    /// with an empty queue.
    #[test]
    fn create_param_without_a_modulus_answers_null_quietly() {
        let e = hex("03");
        ERR_clear_error();
        // SAFETY: `e` is live; the modulus is null on purpose.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(b.is_null());
        assert_eq!(ERR_peek_error(), 0);
        // SAFETY: `e` was allocated in this test.
        unsafe { BN_free(e) };
    }

    /// A modulus of `1` has no inverse for any value, so the retry loop runs to its
    /// end and raises `BN_R_TOO_MANY_ITERATIONS` — the one arm that observes the
    /// thirty-three-draw ceiling without a value.
    #[test]
    fn a_modulus_of_one_exhausts_the_retry_loop() {
        let e = hex("03");
        let one = hex("01");
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { crate::bn::ctx::BN_CTX_new() };
        ERR_clear_error();
        // SAFETY: every argument is live.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                one,
                ctx,
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(b.is_null());
        assert_eq!(ERR_peek_error(), packed(&BN_BLIND_283));
        // SAFETY: all three were allocated in this test.
        unsafe {
            crate::bn::ctx::BN_CTX_free(ctx);
            BN_free(one);
            BN_free(e);
        }
    }

    /// `65537^-1 mod (p - 1)`, for the modulus and public exponent above. An RSA
    /// private exponent is congruent to this, and it is what makes the blinding
    /// cancel: `A = a^e` and `Ai = a^-1`, so `A^d * Ai = a^(e*d-1) = a^0 = 1` in the
    /// multiplicative group of the prime `p`. The test asserts `e * d mod (p - 1) == 1`
    /// before it relies on the constant, so a typo here fails rather than passing
    /// silently.
    const PRIVATE_EXPONENT: &str =
        "e8b4174be8b4174be8b4174be8b4174be8b4174be8b4174be8b4174afffffc87";

    /// The blinding's round trip, in the shape a caller uses it: `convert` multiplies
    /// by `A = a^e`, the caller exponentiates by `d`, and `invert` multiplies by
    /// `Ai = a^-1`, so the composition is `n^d * a^(e*d-1) == n^d`.
    ///
    /// Nothing here is a statement about this run's randomness: `A` and `Ai` differ
    /// every run, and the *equality with `n^d`* holds for every draw. The same
    /// identity is then checked after an explicit `BN_BLINDING_update` (which squares
    /// the factor), under `BN_BLINDING_NO_UPDATE`, and through a Montgomery context.
    #[test]
    fn the_blinding_round_trip_cancels_after_the_private_exponentiation() {
        let m = hex(MODULUS);
        let e = hex("010001");
        let d = hex(PRIVATE_EXPONENT);
        let n = hex("123456789abcdef0fedcba9876543210");
        let keep = hex("123456789abcdef0fedcba9876543210");
        let expect = hex("00");
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };

        // The constant is checked before it is relied on: `e * d mod (p - 1) == 1`.
        // SAFETY: `BN_new` takes no pointers.
        let one_less = unsafe { BN_new() };
        // SAFETY: `BN_new` takes no pointers.
        let prod = unsafe { BN_new() };
        // SAFETY: `one_less`, `m` and `prod` are live.
        unsafe {
            assert_eq!(BN_copy(one_less, m), one_less);
            assert_eq!(BN_sub_word(one_less, 1), 1);
            assert_eq!(BN_mod_mul(prod, e, d, one_less, ctx), 1);
            assert_eq!(BN_is_one(prod), 1, "e*d == 1 mod (p-1)");
        }

        // SAFETY: `e`, `m` and `ctx` are live.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                m,
                ctx,
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(!b.is_null(), "the modulus is odd and large enough");

        // `keep^d`, the answer the round trip has to reproduce.
        // SAFETY: all three are live.
        assert_eq!(unsafe { BN_mod_exp(expect, keep, d, m, ctx) }, 1);
        assert_ne!(
            // SAFETY: `expect` is live.
            unsafe { BN_is_one(expect) },
            1,
            "the expectation is not the trivial one"
        );

        // Round 0 takes the `counter == -1` arm; round 1 takes the update arm. `n` is
        // reset to `keep` each round so the expected answer does not compound.
        for round in 0..2 {
            // SAFETY: `BN_new` takes no pointers.
            let r = unsafe { BN_new() };
            // SAFETY: all of `n`, `r`, `b` and `ctx` are live.
            unsafe {
                assert_eq!(BN_copy(n, keep), n);
                assert_eq!(BN_BLINDING_convert_ex(n, r, b, ctx), 1, "round {round}");
                assert_ne!(BN_cmp(n, keep), 0, "the factor moved the value");
                assert_eq!(BN_mod_exp(n, n, d, m, ctx), 1);
                assert_eq!(BN_BLINDING_invert_ex(n, r, b, ctx), 1, "round {round}");
                assert_eq!(
                    BN_cmp(n, expect),
                    0,
                    "round {round}: the blinding cancelled"
                );
                BN_free(r);
            }
        }

        // `BN_BLINDING_update` squares the factor on its own; the identity survives.
        // SAFETY: all four are live.
        unsafe {
            assert_eq!(BN_copy(n, keep), n);
            assert_eq!(BN_BLINDING_update(b, ctx), 1);
            assert_eq!(BN_BLINDING_convert(n, b, ctx), 1);
            assert_ne!(BN_cmp(n, keep), 0);
            assert_eq!(BN_mod_exp(n, n, d, m, ctx), 1);
            assert_eq!(BN_BLINDING_invert(n, b, ctx), 1);
            assert_eq!(BN_cmp(n, expect), 0);
        }

        // `BN_BLINDING_NO_UPDATE` stops the squaring: the inverse read back after the
        // update is the one from before it.
        // SAFETY: all four are live.
        unsafe {
            BN_BLINDING_set_flags(b, BN_BLINDING_NO_UPDATE);
            let before = BN_new();
            let after = BN_new();
            assert_eq!(BN_BLINDING_convert_ex(n, before, b, ctx), 1);
            assert_eq!(BN_BLINDING_update(b, ctx), 1);
            assert_eq!(BN_BLINDING_convert_ex(n, after, b, ctx), 1);
            assert_eq!(BN_cmp(before, after), 0, "NO_UPDATE: the factor is fixed");
            BN_free(before);
            BN_free(after);
            BN_BLINDING_set_flags(b, 0);
        }

        // A Montgomery context takes the other multiplier spelling and is the same
        // identity. `BN_MONT_CTX_set` on the odd modulus succeeds.
        // SAFETY: `BN_MONT_CTX_new` takes no pointers.
        let mont = unsafe { BN_MONT_CTX_new() };
        // SAFETY: `mont` and `m` are live.
        assert_eq!(unsafe { BN_MONT_CTX_set(mont, m, ctx) }, 1);
        // SAFETY: every argument is live; `m` is the modulus the context duplicates.
        let bm = unsafe { BN_BLINDING_create_param(core::ptr::null_mut(), e, m, ctx, None, mont) };
        assert!(!bm.is_null());
        // SAFETY: `n` and `keep` are live, and `n` is reset to `keep` first.
        unsafe {
            assert_eq!(BN_copy(n, keep), n);
            assert_eq!(BN_BLINDING_convert(n, bm, ctx), 1);
            assert_ne!(BN_cmp(n, keep), 0);
            assert_eq!(BN_mod_exp(n, n, d, m, ctx), 1);
            assert_eq!(BN_BLINDING_invert(n, bm, ctx), 1);
            assert_eq!(BN_cmp(n, expect), 0, "the Montgomery path cancels too");
        }

        // SAFETY: everything allocated here, and `mont` belongs to this test.
        unsafe {
            BN_BLINDING_free(bm);
            BN_MONT_CTX_free(mont);
            BN_BLINDING_free(b);
            BN_free(prod);
            BN_free(one_less);
            BN_free(expect);
            BN_free(keep);
            BN_free(n);
            BN_free(d);
            BN_free(e);
            BN_free(m);
            BN_CTX_free(ctx);
        }
    }

    /// With an exponent of **one**, `A` is the drawn value itself, so `A * Ai == 1`
    /// and `convert` followed by `invert` is the identity with no exponentiation in
    /// between. That is the narrowest form of the property, and it is here because it
    /// needs no `d`: it pins the pair, not the design.
    #[test]
    fn an_exponent_of_one_makes_convert_and_invert_a_pair() {
        let m = hex(MODULUS);
        let e = hex("01");
        let n = hex("deadbeefcafebabe");
        let keep = hex("deadbeefcafebabe");
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        // SAFETY: every argument is live.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                m,
                ctx,
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(!b.is_null());
        for round in 0..3 {
            // SAFETY: all four are live.
            unsafe {
                assert_eq!(BN_copy(n, keep), n);
                assert_eq!(BN_BLINDING_convert(n, b, ctx), 1, "round {round}");
                assert_ne!(BN_cmp(n, keep), 0, "round {round}");
                assert_eq!(BN_BLINDING_invert(n, b, ctx), 1, "round {round}");
                assert_eq!(BN_cmp(n, keep), 0, "round {round}: A * Ai == 1");
            }
        }
        // SAFETY: both were allocated in this test.
        unsafe {
            BN_BLINDING_free(b);
            BN_CTX_free(ctx);
            BN_free(keep);
            BN_free(n);
            BN_free(e);
            BN_free(m);
        }
    }

    /// A fresh context has `counter == -1`, so its **first** `convert` does not
    /// update: the inverse it hands back is `A^-1`, and a second `convert` hands back
    /// a different one. Observed as an inequality between two probabilistic values,
    /// which is a property of the state machine rather than of either draw.
    #[test]
    fn the_first_convert_does_not_update_the_counter() {
        let m = hex(MODULUS);
        let e = hex("010001");
        let n = hex("deadbeef");
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { crate::bn::ctx::BN_CTX_new() };
        // SAFETY: every argument is live; `m` is the odd modulus above.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                m,
                ctx,
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(!b.is_null());
        // SAFETY: `b` is live, which is how the counter is read back.
        assert_eq!(unsafe { (*b).counter }, -1, "a fresh context is -1, not 0");

        // SAFETY: all of `n`, `b` and `ctx` are live.
        unsafe {
            let first = BN_new();
            let second = BN_new();
            assert_eq!(BN_BLINDING_convert_ex(n, first, b, ctx), 1);
            assert_eq!((*b).counter, 0, "the first convert spends -1 -> 0");
            assert_eq!(BN_BLINDING_convert_ex(n, second, b, ctx), 1);
            assert_ne!(BN_cmp(first, second), 0, "the second one updated first");
            BN_free(first);
            BN_free(second);
            BN_BLINDING_free(b);
            BN_CTX_free(ctx);
            BN_free(n);
            BN_free(e);
            BN_free(m);
        }
    }

    /// An exponent of **zero** pins `A` to one — `a^0 mod m` is `1` — while `Ai` stays
    /// the inverse of the *drawn* value. So `convert` is the identity here and the
    /// value does not move at all. That is the arm that shows `create_param`
    /// exponentiates `A` and leaves `Ai` alone, which is exactly the asymmetry an RSA
    /// caller cancels with its private exponent.
    #[test]
    fn an_exponent_of_zero_pins_the_factor_to_one() {
        let m = hex(MODULUS);
        let e = hex("00");
        let n = hex("abcdef0123456789");
        let keep = hex("abcdef0123456789");
        // SAFETY: `BN_CTX_new` takes no pointers.
        let ctx = unsafe { BN_CTX_new() };
        // SAFETY: every argument is live; `e` is zero on purpose.
        let b = unsafe {
            BN_BLINDING_create_param(
                core::ptr::null_mut(),
                e,
                m,
                ctx,
                None,
                core::ptr::null_mut(),
            )
        };
        assert!(!b.is_null());
        // SAFETY: all four are live.
        unsafe {
            assert_eq!(BN_BLINDING_convert(n, b, ctx), 1);
            assert_eq!(BN_cmp(n, keep), 0, "A^0 == 1, so convert is the identity");
            BN_BLINDING_free(b);
            BN_CTX_free(ctx);
            BN_free(keep);
            BN_free(n);
            BN_free(e);
            BN_free(m);
        }
    }

    /// `BN_BLINDING_is_current_thread` and the flags read back through the two
    /// accessors, on a context this test made.
    #[test]
    fn the_accessors_see_the_context_this_call_built() {
        let m = hex("010001");
        // SAFETY: `m` is live; `A`/`Ai` may be null.
        let b = unsafe { BN_BLINDING_new(core::ptr::null(), core::ptr::null(), m) };
        assert!(!b.is_null());
        // SAFETY: `b` is live.
        unsafe {
            assert_eq!(BN_BLINDING_is_current_thread(b), 1);
            BN_BLINDING_set_flags(b, BN_BLINDING_NO_UPDATE | BN_BLINDING_NO_RECREATE);
            assert_eq!(
                BN_BLINDING_get_flags(b),
                BN_BLINDING_NO_UPDATE | BN_BLINDING_NO_RECREATE
            );
            assert_eq!(BN_BLINDING_lock(b), 1);
            assert_eq!(BN_BLINDING_unlock(b), 1);
            BN_BLINDING_free(b);
            BN_free(m);
        }
    }

    /// A `BN_BLINDING_new` with no modulus is NULL: the duplicate is unconditional.
    #[test]
    fn a_null_modulus_has_no_context() {
        // SAFETY: every argument is null on purpose; the authority's `BN_dup(NULL)`
        // path is the one under test.
        let b =
            unsafe { BN_BLINDING_new(core::ptr::null(), core::ptr::null(), core::ptr::null_mut()) };
        assert!(b.is_null());
        assert_eq!(ERR_peek_error(), 0, "the failure raises nothing");
    }

    /// The consttime flag on the caller's modulus is carried onto the duplicate,
    /// which is the flag `int_bn_mod_inverse`'s authority branch reads.
    #[test]
    fn the_consttime_flag_is_carried_onto_the_duplicate() {
        let m = hex("010001");
        // SAFETY: `m` is live and the flag is a plain value.
        unsafe { BN_set_flags(m, BN_FLG_CONSTTIME) };
        // SAFETY: `m` is live.
        let b = unsafe { BN_BLINDING_new(core::ptr::null(), core::ptr::null(), m) };
        assert!(!b.is_null());
        // SAFETY: `b` is live.
        unsafe {
            assert_ne!((*b).mod_, m, "the duplicate is a different object");
            assert_ne!(BN_get_flags((*b).mod_, BN_FLG_CONSTTIME), 0);
            BN_BLINDING_free(b);
            BN_free(m);
        }
    }
}
