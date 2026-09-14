//! Phase 5 — the `BN_*` arithmetic entry points.
//!
//! Over the sign-magnitude representation in `bignum.rs` and the limb primitives in
//! `limbs.rs`. Every entry point here follows the same discipline: it reads its raw
//! pointer arguments in **exactly one** `unsafe` block whose comment states the
//! invariant, and the rest of the body works with `Option<&BigNum>` and owned
//! vectors.
//!
//! ## Sign rules, stated because they are contract
//!
//! * `BN_add`, `BN_sub`, `BN_mul` and `BN_sqr` produce the algebraic result and
//!   never leave `neg` set on a zero result.
//! * `BN_div` truncates the quotient toward zero and gives the remainder the sign
//!   of the dividend, so `a == b*q + r` holds for every sign combination. That is
//!   the property the differential court checks, because it is the property a caller
//!   can rely on without reading this implementation.
//! * `BN_mod` inherits `BN_div`'s remainder. `BN_nnmod` is the non-negative one, and
//!   the `BN_mod_*` family is defined through it, so their results lie in `[0, m)`.
//! * `BN_lshift`/`BN_rshift` shift the **magnitude** and preserve the sign, so
//!   `-5 >> 1` is `-2`: this truncates toward zero, not toward minus infinity.
//!
//! ## Aliasing
//!
//! Every function accepts `r` aliasing `a` or `b`, which the authority allows and its
//! own code relies on. Each therefore computes into a local magnitude and assigns at
//! the end rather than writing through `r` as it goes.

use core::ffi::{c_int, c_ulong};

use crate::bn::bignum::{as_mut, as_ref, new_owned, parts, store, BN_copy, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BN_ADD_142, BN_DIV_217, BN_EXP_1324, BN_GCD_532, BN_MOD_194, BN_MOD_22, BN_MOD_307,
    BN_SQRT_352, BN_SQRT_43,
};
use crate::runtime::err::raise_site;

/// The truncated quotient and remainder magnitudes of `a / b`.
///
/// Signs are applied by the callers, because the sign rules differ per operation
/// and keeping them at the call site is what makes them reviewable. `None` for a
/// zero divisor, which the authority reports through the error queue and a zero
/// return.
fn div_rem_mag(a: &[Limb], b: &[Limb]) -> Option<(Vec<Limb>, Vec<Limb>)> {
    if b.is_empty() {
        None
    } else {
        Some(limbs::div_rem(a, b))
    }
}

/// `int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be
/// null or live.
#[no_mangle]
pub unsafe extern "C" fn BN_add(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: all three pointers are null-or-live per this function's `# Safety`
        // section, and this is the only place any of them is read.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, an) = parts(x);
        let (bd, bn) = parts(y);
        let (mag, neg) = if an == bn {
            (limbs::add(&ad, &bd), an)
        } else {
            match limbs::cmp(&ad, &bd) {
                core::cmp::Ordering::Equal => (Vec::new(), false),
                core::cmp::Ordering::Greater => (limbs::sub(&ad, &bd), an),
                core::cmp::Ordering::Less => (limbs::sub(&bd, &ad), bn),
            }
        };
        c_int::from(store(dst, mag, neg))
    })
}

/// `int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// As `BN_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_sub(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, an) = parts(x);
        let (bd, bn) = parts(y);
        let (mag, neg) = if an != bn {
            (limbs::add(&ad, &bd), an)
        } else {
            match limbs::cmp(&ad, &bd) {
                core::cmp::Ordering::Equal => (Vec::new(), false),
                core::cmp::Ordering::Greater => (limbs::sub(&ad, &bd), an),
                core::cmp::Ordering::Less => (limbs::sub(&bd, &ad), !bn),
            }
        };
        c_int::from(store(dst, mag, neg))
    })
}

/// `int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)` — magnitudes added,
/// signs ignored.
///
/// # Safety
///
/// As `BN_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_uadd(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        c_int::from(store(dst, limbs::add(&ad, &bd), false))
    })
}

/// `int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)` — magnitudes
/// subtracted.
///
/// The authority reports an error only when `a` has **fewer limbs** than `b`
/// (`bn_add.c`: `if (dif < 0) ERR_raise(..., BN_R_ARG2_LT_ARG3)`). At equal width it
/// subtracts and lets the final borrow escape, so a smaller `a` yields
/// `a - b mod 2^(64*len)` rather than a failure. `BN_add(3)` calls that case
/// undefined, but a precompiled caller sees the wrapped value, so it is reproduced
/// here instead of being "fixed" into a failure the authority never reports.
///
/// # Safety
///
/// As `BN_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_usub(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        if ad.len() < bd.len() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_ADD_142) };
            return 0;
        }
        c_int::from(store(dst, limbs::sub(&ad, &bd), false))
    })
}

/// `int BN_add_word(BIGNUM *a, BN_ULONG w)`
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_add_word(a: *mut BigNum, w: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let dst = match unsafe { as_mut(a) } {
            Some(d) => d,
            None => return 0,
        };
        let (mag, neg) = if w == 0 {
            (dst.d.clone(), dst.neg != 0)
        } else if dst.neg != 0 {
            let sub = limbs::from_u64(w as Limb);
            if limbs::cmp(&dst.d, &sub) == core::cmp::Ordering::Less {
                (limbs::sub(&sub, &dst.d), false)
            } else {
                (limbs::sub(&dst.d, &sub), true)
            }
        } else {
            (limbs::add_word(&dst.d, w as Limb), false)
        };
        c_int::from(store(Some(dst), mag, neg))
    })
}

/// `int BN_sub_word(BIGNUM *a, BN_ULONG w)`
///
/// # Safety
///
/// As `BN_add_word`.
#[no_mangle]
pub unsafe extern "C" fn BN_sub_word(a: *mut BigNum, w: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let dst = match unsafe { as_mut(a) } {
            Some(d) => d,
            None => return 0,
        };
        let (mag, neg) = if w == 0 {
            (dst.d.clone(), dst.neg != 0)
        } else if dst.neg != 0 {
            (limbs::add_word(&dst.d, w as Limb), true)
        } else {
            match limbs::sub_word(&dst.d, w as Limb) {
                Some(d) => (d, false),
                None => (limbs::sub(&limbs::from_u64(w as Limb), &dst.d), true),
            }
        };
        c_int::from(store(Some(dst), mag, neg))
    })
}

/// `int BN_mul_word(BIGNUM *a, BN_ULONG w)`
///
/// # Safety
///
/// As `BN_add_word`.
#[no_mangle]
pub unsafe extern "C" fn BN_mul_word(a: *mut BigNum, w: c_ulong) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let dst = match unsafe { as_mut(a) } {
            Some(d) => d,
            None => return 0,
        };
        let neg = dst.neg != 0;
        let mag = limbs::mul_word(&dst.d, w as Limb);
        c_int::from(store(Some(dst), mag, neg))
    })
}

/// `int BN_div_word(BIGNUM *a, BN_ULONG w)` — divides in place and answers the
/// remainder, or `(BN_ULONG)-1` for a zero divisor.
///
/// # Safety
///
/// As `BN_add_word`.
#[no_mangle]
pub unsafe extern "C" fn BN_div_word(a: *mut BigNum, w: c_ulong) -> c_ulong {
    guard_ffi(c_ulong::MAX, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let dst = match unsafe { as_mut(a) } {
            Some(d) => d,
            None => return c_ulong::MAX,
        };
        if w == 0 {
            return c_ulong::MAX;
        }
        let (q, r) = limbs::div_rem_small(&dst.d, w as Limb);
        let neg = dst.neg != 0;
        store(Some(dst), q, neg);
        r as c_ulong
    })
}

/// `BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)`
///
/// # Safety
///
/// `a` must be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_word(a: *const BigNum, w: c_ulong) -> c_ulong {
    guard_ffi(c_ulong::MAX, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let src = match unsafe { as_ref(a) } {
            Some(s) => s,
            None => return c_ulong::MAX,
        };
        if w == 0 {
            return c_ulong::MAX;
        }
        limbs::div_rem_small(&src.d, w as Limb).1 as c_ulong
    })
}

/// `int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// `ctx` is accepted and unused: it exists for the authority's temporary pool, and a
/// caller passing `NULL` is legal here where the authority requires a context for
/// large operands. Accepting more than the authority does cannot break a working
/// caller, but it is not parity and the ledger records it.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mul(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, an) = parts(x);
        let (bd, bn) = parts(y);
        c_int::from(store(dst, limbs::mul(&ad, &bd), an != bn))
    })
}

/// `int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_mul`.
#[no_mangle]
pub unsafe extern "C" fn BN_sqr(r: *mut BigNum, a: *const BigNum, _ctx: *mut BnCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut(r), as_ref(a)) };
        let (ad, _) = parts(x);
        // A square is never negative, whatever the operand's sign.
        c_int::from(store(dst, limbs::mul(&ad, &ad), false))
    })
}

/// `int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// Either output may be null. A zero divisor fails, returns `0` and raises
/// `BN_R_DIV_BY_ZERO` at the authority's own coordinate in `BN_div`, which is
/// observable through `ERR_peek_error_all`.
///
/// # Safety
///
/// `dv` and `rem` must each be null or a live, uniquely-owned `BIGNUM`; `a` and `b`
/// must each be null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_div(
    dv: *mut BigNum,
    rem: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (q_out, r_out, x, y) = unsafe { (as_mut(dv), as_mut(rem), as_ref(a), as_ref(b)) };
        let (ad, an) = parts(x);
        let (bd, bn) = parts(y);
        let (q, r) = match div_rem_mag(&ad, &bd) {
            Some(qr) => qr,
            None => {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_DIV_217) };
                return 0;
            }
        };
        // The quotient is negative exactly when the signs differ, and the remainder
        // takes the dividend's sign. The remainder is stored first so that a caller
        // passing the same object for both slots sees the remainder, which is the
        // authority's order too.
        let mut ok = true;
        if let Some(dst) = r_out {
            ok &= store(Some(dst), r, an);
        }
        if let Some(dst) = q_out {
            ok &= store(Some(dst), q, an != bn);
        }
        c_int::from(ok)
    })
}

/// `int BN_nnmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)`
///
/// The non-negative remainder, which the rest of the `mod` family is defined
/// through. `BN_mod` is deliberately **not** exported: the authority declares it as
/// a macro over `BN_div`, so a library that exported it would be reachable through
/// `dlsym` where the authority is not — an observable ABI difference in the wrong
/// direction.
///
/// # Safety
///
/// As `BN_div`.
#[no_mangle]
pub unsafe extern "C" fn BN_nnmod(
    r: *mut BigNum,
    a: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(m)) };
        let (ad, an) = parts(x);
        let (md, _) = parts(y);
        if core::ptr::eq(r.cast_const(), m) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_MOD_22) };
            return 0;
        }
        if md.is_empty() {
            // The authority reaches this through `BN_mod` -> `BN_div`, so the
            // coordinate is `BN_div`'s, not a `BN_nnmod` one.
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_DIV_217) };
            return 0;
        }
        let (_, mut rem) = limbs::div_rem(&ad, &md);
        // A remainder that came out negative is made non-negative by adding the
        // modulus, which is the definition of `nnmod` rather than a fix-up.
        if an && !rem.is_empty() {
            rem = limbs::sub(&md, &rem);
        }
        c_int::from(store(dst, rem, false))
    })
}

/// `int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)`
///
/// The authority defines this as `BN_add(r, a, b)` followed by `BN_nnmod(r, r, m)`:
/// the sum keeps its true sign and is reduced once, at the end. Reducing the
/// operands first is the obvious shortcut and is only equivalent when both are
/// already in `[0, m)` — it differs by exactly the modulus whenever an operand is
/// negative, which is a difference the differential court sees immediately.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `b` and `m` must each
/// be null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_add(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_add` and `BN_nnmod` have this function's contract.
        unsafe {
            if BN_add(r, a, b) == 0 {
                return 0;
            }
            BN_nnmod(r, r.cast_const(), m, ctx)
        }
    })
}

/// `int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)`
///
/// As `BN_mod_add`: the difference keeps its sign and the reduction happens last.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sub(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_sub` and `BN_nnmod` have this function's contract.
        unsafe {
            if BN_sub(r, a, b) == 0 {
                return 0;
            }
            BN_nnmod(r, r.cast_const(), m, ctx)
        }
    })
}

/// `int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)`
///
/// The product, then one reduction — so a negative operand contributes its sign to
/// the product rather than being reduced away first.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_mul(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_mul` and `BN_nnmod` have this function's contract.
        unsafe {
            if BN_mul(r, a, b, ctx) == 0 {
                return 0;
            }
            BN_nnmod(r, r.cast_const(), m, ctx)
        }
    })
}

/// `int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sqr(
    r: *mut BigNum,
    a: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    // SAFETY: `BN_mod_mul`'s contract covers this function's arguments.
    unsafe { BN_mod_mul(r, a, a, m, ctx) }
}

/// `BN_mod_lshift_quick`'s loop, written the way the authority writes it.
///
/// It requires `a` already in `[0, |m|)`, doubles the value one window at a time and
/// subtracts `m` once the result has caught up with it. It is deliberately *not*
/// `BN_mod_lshift`: that one reduces first, and this one reports
/// `BN_R_INPUT_NOT_REDUCED` when handed a value outside the precondition, which is a
/// different observable outcome rather than a slower path to the same one.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `m` must each be
/// null or live.
unsafe fn mod_lshift_quick_impl(
    r: *mut BigNum,
    a: *const BigNum,
    mut n: c_int,
    m: *const BigNum,
) -> c_int {
    if r != a.cast_mut() {
        // SAFETY: `BN_copy`'s contract is this function's contract.
        if unsafe { BN_copy(r, a) }.is_null() {
            return 0;
        }
    }
    while n > 0 {
        // SAFETY: `r` and `m` are null-or-live per this function's contract.
        let (rv, mv) = unsafe {
            let (rd, md) = (as_ref(r), as_ref(m));
            (parts(rd).0, parts(md).0)
        };
        let mut max_shift = limbs::bit_len(&mv) as c_int - limbs::bit_len(&rv) as c_int;
        if max_shift < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_MOD_307) };
            return 0;
        }
        if max_shift > n {
            max_shift = n;
        }
        let shifted = if max_shift > 0 {
            // SAFETY: `BN_lshift`'s contract is this function's contract.
            unsafe { BN_lshift(r, r.cast_const(), max_shift) }
        } else {
            // SAFETY: `BN_lshift1`'s contract is this function's contract.
            unsafe { BN_lshift1(r, r.cast_const()) }
        };
        if shifted == 0 {
            return 0;
        }
        n -= if max_shift > 0 { max_shift } else { 1 };
        // SAFETY: `r` and `m` are null-or-live per this function's contract.
        let (rv2, mv2) = unsafe {
            let (rd, md) = (as_ref(r), as_ref(m));
            (parts(rd).0, parts(md).0)
        };
        if limbs::cmp(&rv2, &mv2) != core::cmp::Ordering::Less {
            // SAFETY: `BN_sub`'s contract is this function's contract.
            if unsafe { BN_sub(r, r.cast_const(), m) } == 0 {
                return 0;
            }
        }
    }
    1
}

/// `int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)`
///
/// The `_quick` variants require operands already reduced and in `[0, m)`, and the
/// authority implements them as their own small algorithms rather than as calls to
/// the general ones — for an operand outside the precondition the two disagree, so
/// sharing the implementation would be a divergence, not a simplification.
///
/// # Safety
///
/// As `BN_mod_add`, minus the context.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_add_quick(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_uadd`'s and `BN_usub`'s contracts are this function's.
        unsafe {
            if BN_uadd(r, a, b) == 0 {
                return 0;
            }
            let (rd, md) = (as_ref(r), as_ref(m));
            let (rv, mv) = (parts(rd).0, parts(md).0);
            if limbs::cmp(&rv, &mv) == core::cmp::Ordering::Less {
                1
            } else {
                BN_usub(r, r.cast_const(), m)
            }
        }
    })
}

/// `int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)`
///
/// # Safety
///
/// As `BN_mod_sub`, minus the context.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sub_quick(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_sub`'s and `BN_add`'s contracts are this function's.
        unsafe {
            if core::ptr::eq(r.cast_const(), m) {
                // SAFETY: the site is a compile-time constant.
                raise_site(&BN_MOD_194);
                return 0;
            }
            if BN_sub(r, a, b) == 0 {
                return 0;
            }
            if as_ref(r).is_some_and(|v| v.neg != 0) {
                BN_add(r, r.cast_const(), m)
            } else {
                1
            }
        }
    })
}

/// `int BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)`
///
/// Writes to `r` and returns `r`, or allocates and returns the new object when `r`
/// is null; `NULL` when no inverse exists.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_inverse(
    r: *mut BigNum,
    a: *const BigNum,
    n: *const BigNum,
    _ctx: *mut BnCtx,
) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(n)) };
        let (ad, _) = parts(x);
        let (nd, _) = parts(y);
        let inv = match limbs::mod_inverse(&ad, &nd) {
            Some(v) => v,
            None => {
                // The authority's `BN_mod_inverse` raises this itself, after its
                // internal helper reports the failure through a flag.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GCD_532) };
                return core::ptr::null_mut();
            }
        };
        match dst {
            None => new_owned(inv, 0),
            Some(dst) => {
                if store(Some(dst), inv, false) {
                    r
                } else {
                    core::ptr::null_mut()
                }
            }
        }
    })
}

/// `int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` must be null or live.
#[no_mangle]
pub unsafe extern "C" fn BN_lshift(r: *mut BigNum, a: *const BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut(r), as_ref(a)) };
        let (ad, an) = parts(x);
        c_int::from(store(dst, limbs::shl(&ad, n as usize), an))
    })
}

/// `int BN_lshift1(BIGNUM *r, const BIGNUM *a)`
///
/// # Safety
///
/// As `BN_lshift`.
#[no_mangle]
pub unsafe extern "C" fn BN_lshift1(r: *mut BigNum, a: *const BigNum) -> c_int {
    // SAFETY: `BN_lshift`'s contract covers this function's arguments.
    unsafe { BN_lshift(r, a, 1) }
}

/// `int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)`
///
/// # Safety
///
/// As `BN_lshift`.
#[no_mangle]
pub unsafe extern "C" fn BN_rshift(r: *mut BigNum, a: *const BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut(r), as_ref(a)) };
        let (ad, an) = parts(x);
        c_int::from(store(dst, limbs::shr(&ad, n as usize), an))
    })
}

/// `int BN_rshift1(BIGNUM *r, const BIGNUM *a)`
///
/// # Safety
///
/// As `BN_lshift`.
#[no_mangle]
pub unsafe extern "C" fn BN_rshift1(r: *mut BigNum, a: *const BigNum) -> c_int {
    // SAFETY: `BN_rshift`'s contract covers this function's arguments.
    unsafe { BN_rshift(r, a, 1) }
}

/// `int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx)`
///
/// Reduces first and then shifts, which is how the authority defines it.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift(
    r: *mut BigNum,
    a: *const BigNum,
    n: c_int,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_nnmod` and `mod_lshift_quick_impl` have this function's
        // contract, and `r` aliasing `a` is exactly what the helper expects.
        unsafe {
            if BN_nnmod(r, a, m, ctx) == 0 {
                return 0;
            }
            mod_lshift_quick_impl(r, r.cast_const(), n, m)
        }
    })
}

/// `int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift1(
    r: *mut BigNum,
    a: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_lshift1` and `BN_nnmod` have this function's contract.
        unsafe {
            if BN_lshift1(r, a) == 0 {
                return 0;
            }
            BN_nnmod(r, r.cast_const(), m, ctx)
        }
    })
}

/// `int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)`
///
/// # Safety
///
/// As `BN_mod_lshift`, minus the context.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift_quick(
    r: *mut BigNum,
    a: *const BigNum,
    n: c_int,
    m: *const BigNum,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `mod_lshift_quick_impl`'s contract is this function's contract.
        unsafe { mod_lshift_quick_impl(r, a, n, m) }
    })
}

/// `int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)`
///
/// # Safety
///
/// As `BN_mod_lshift`, minus the context.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_lshift1_quick(
    r: *mut BigNum,
    a: *const BigNum,
    m: *const BigNum,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_lshift1`, `BN_sub` and the magnitude reads below all have this
        // function's contract.
        unsafe {
            if BN_lshift1(r, a) == 0 {
                return 0;
            }
            let (rd, md) = (as_ref(r), as_ref(m));
            let (rv, mv) = (parts(rd).0, parts(md).0);
            if limbs::cmp(&rv, &mv) == core::cmp::Ordering::Less {
                1
            } else {
                BN_sub(r, r.cast_const(), m)
            }
        }
    })
}

/// `int BN_mask_bits(BIGNUM *a, int n)` — truncate to the low `n` bits in place.
///
/// # Safety
///
/// `a` must be null or a live, uniquely-owned `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_mask_bits(a: *mut BigNum, n: c_int) -> c_int {
    guard_ffi(0, || {
        if n < 0 {
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let dst = match unsafe { as_mut(a) } {
            Some(d) => d,
            None => return 0,
        };
        // The authority's `ossl_bn_mask_bits_fixed_top` answers 0 when the requested
        // width starts at or past the value's own top limb, so masking to a width the
        // value does not have is *reported* rather than accepted as a no-op. The check
        // also bounds the mask below: without it a huge `n` would try to allocate
        // `n / 64` limbs.
        if (n as usize) / 64 >= dst.d.len() {
            return 0;
        }
        // A mask of `2^n - 1`.
        let mask = limbs::sub(&limbs::shl(&[1u64], n as usize), &[1u64]);
        let masked = limbs::and(&dst.d, &mask);
        let neg = dst.neg != 0;
        c_int::from(store(Some(dst), masked, neg))
    })
}

/// `int BN_cmp(const BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// `a` and `b` must each be null or point to a live `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_cmp(a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (x, y) = unsafe { (as_ref(a), as_ref(b)) };
        let (ad, an) = parts(x);
        let (bd, bn) = parts(y);
        // The authority orders by sign first (`a->neg != b->neg`) and only then by
        // magnitude, reversing the magnitude order when both are negative. Reversing
        // the mixed-sign answer as well — the obvious way to write "reversed for
        // negatives" — is wrong for exactly the case where `a` is negative and `b` is
        // not, and that case is in the court.
        match (an, bn) {
            (false, true) => 1,
            (true, false) => -1,
            (true, true) => match limbs::cmp(&ad, &bd) {
                core::cmp::Ordering::Less => 1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => -1,
            },
            (false, false) => match limbs::cmp(&ad, &bd) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            },
        }
    })
}

/// `int BN_ucmp(const BIGNUM *a, const BIGNUM *b)` — magnitudes compared.
///
/// # Safety
///
/// As `BN_cmp`.
#[no_mangle]
pub unsafe extern "C" fn BN_ucmp(a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (x, y) = unsafe { (as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        match limbs::cmp(&ad, &bd) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    })
}

/// `int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
///
/// Square-and-multiply over the exponent's bits, which is what makes the cost
/// depend on the exponent's bit length rather than its value.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_exp(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(p)) };
        // The authority's ladder is driven by `BN_num_bits`/`BN_is_bit_set`, which read
        // the exponent's *magnitude*, so a negative exponent is not rejected: it
        // computes `a^|p|`. `BN_exp` is explicit about that in `bn_exp.c` — there is no
        // sign test anywhere in it.
        let (pd, _) = parts(y);
        let (ad, _) = parts(x);
        let mut acc: Vec<Limb> = vec![1];
        let mut base = ad;
        for i in 0..limbs::bit_len(&pd) {
            if limbs::bit(&pd, i) {
                acc = limbs::mul(&acc, &base);
            }
            if i + 1 < limbs::bit_len(&pd) {
                base = limbs::mul(&base, &base);
            }
        }
        let _ = ctx;
        c_int::from(store(dst, acc, false))
    })
}

/// `int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)`
///
/// Square-and-multiply with a reduction at every step. The authority dispatches to a
/// Montgomery path for an odd modulus and a reciprocal-based one otherwise; this is
/// the plain one, which is correct for every modulus and makes no speed claim.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y, z) = unsafe { (as_mut(r), as_ref(a), as_ref(p), as_ref(m)) };
        let (ad, _) = parts(x);
        let (pd, _) = parts(y);
        let (md, _) = parts(z);
        match mod_exp_core(&ad, &pd, &md) {
            Some(v) => c_int::from(store(dst, v, false)),
            None => {
                // A zero modulus reaches `BN_div` inside the authority's ladder, so
                // the coordinate is `BN_div`'s.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_DIV_217) };
                0
            }
        }
    })
}

/// The shared modular-exponentiation ladder: `a^|p| mod m`.
///
/// The exponent's sign is ignored because the authority's ladder is driven by
/// `BN_is_bit_set`, which reads the magnitude: a negative exponent is not rejected
/// there, it computes `a^|p|`. That is a surprising behaviour to preserve, and the
/// differential court is what keeps it honest rather than guessed.
///
/// `None` for a zero modulus; the caller reports that at the coordinate the
/// authority's own ladder would.
fn mod_exp_core(ad: &[Limb], pd: &[Limb], md: &[Limb]) -> Option<Vec<Limb>> {
    if md.is_empty() {
        return None;
    }
    // `x**0 mod 1` and `x**0 mod -1` are zero, and every other zero exponent gives
    // one — the authority states this rule explicitly, and the naive loop gets the
    // `|m| == 1` case wrong by answering one.
    if limbs::bit_len(pd) == 0 {
        return Some(if md.len() == 1 && md[0] == 1 {
            Vec::new()
        } else {
            vec![1]
        });
    }
    let mut acc: Vec<Limb> = vec![1];
    let mut base = limbs::rem(ad, md);
    let bits = limbs::bit_len(pd);
    for i in 0..bits {
        if limbs::bit(pd, i) {
            acc = limbs::rem(&limbs::mul(&acc, &base), md);
        }
        if i + 1 < bits {
            base = limbs::rem(&limbs::mul(&base, &base), md);
        }
    }
    Some(acc)
}

/// `int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx)`
///
/// The authority implements this as its own function rather than as an alias of
/// `BN_mod_exp`, and it rejects `r == m`, which the Montgomery paths do not. The
/// arithmetic below it is the same ladder, so only the guard is duplicated here.
///
/// # Safety
///
/// As `BN_mod_add`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_simple(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        if core::ptr::eq(r.cast_const(), m) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP_1324) };
            return 0;
        }
        // SAFETY: `BN_mod_exp`'s contract covers this function's arguments.
        unsafe { BN_mod_exp(r, a, p, m, ctx) }
    })
}

/// `int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// The result is non-negative, which is the authority's behaviour and why the sign
/// bits are ignored.
///
/// # Safety
///
/// As `BN_add`, plus `ctx` which is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_gcd(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(r), as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        c_int::from(store(dst, limbs::gcd(&ad, &bd), false))
    })
}

/// `int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// # Safety
///
/// `a` and `b` must each be null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_are_coprime(
    a: *const BigNum,
    b: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (x, y) = unsafe { (as_ref(a), as_ref(b)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        c_int::from(limbs::are_coprime(&ad, &bd))
    })
}

/// `BIGNUM *BN_mod_sqrt(BIGNUM *in, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)`
/// — a square root of `a` modulo the prime `p`, by Tonelli–Shanks.
///
/// `NULL` when `a` is not a quadratic residue, with `BN_R_NOT_A_SQUARE` raised where
/// the authority's own verification step raises it; `BN_R_P_IS_NOT_PRIME` when `p` is
/// even and not two, which the authority rejects before doing any work at all.
///
/// # Safety
///
/// `in` must be null or a live, uniquely-owned `BIGNUM`; `a` and `p` must each be
/// null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_sqrt(
    inp: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    _ctx: *mut BnCtx,
) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y) = unsafe { (as_mut(inp), as_ref(a), as_ref(p)) };
        let (ad, an) = parts(x);
        let (pd, _) = parts(y);

        // `p` must be an odd prime. The authority rejects an even `p` — and `|p| == 1` —
        // before it does any work, with `p == 2` the single even value it handles; the
        // rejection is observable, so it is reproduced rather than folded into the
        // general non-residue answer.
        if pd.is_empty() || limbs::is_even(&pd) || (pd.len() == 1 && pd[0] == 1) {
            if pd.len() == 1 && pd[0] == 2 {
                // The only even prime: the root is `a`'s low bit.
                return finish_sqrt(dst, inp, limbs::rem(&ad, &pd));
            }
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_SQRT_43) };
            return core::ptr::null_mut();
        }

        let a_mod = if an {
            let r = limbs::rem(&ad, &pd);
            if r.is_empty() {
                r
            } else {
                limbs::sub(&pd, &r)
            }
        } else {
            limbs::rem(&ad, &pd)
        };

        // Euler's criterion: a non-residue has no root, and saying so is the
        // difference between a correct answer and a plausible one. The coordinate is
        // the authority's verification step, which is where a prime modulus with a
        // non-residue input is actually rejected there.
        let exp = limbs::shr(&limbs::sub(&pd, &[1u64]), 1);
        let legendre = mod_exp_mag(&a_mod, &exp, &pd);
        if legendre != vec![1u64] {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_SQRT_352) };
            return core::ptr::null_mut();
        }

        // Write p - 1 = q * 2^s with q odd.
        let one = limbs::sub(&pd, &[1u64]);
        let mut q = one.clone();
        let mut s = 0usize;
        while limbs::is_even(&q) {
            q = limbs::shr(&q, 1);
            s += 1;
        }
        // Find a quadratic non-residue z, which must exist for a prime p > 2.
        let mut z: Vec<Limb> = vec![2];
        while mod_exp_mag(&z, &exp, &pd) != limbs::sub(&pd, &[1u64]) {
            z = limbs::add(&z, &[1u64]);
            if limbs::cmp(&z, &pd) != core::cmp::Ordering::Less {
                return core::ptr::null_mut();
            }
        }
        let mut m = s;
        let mut c = mod_exp_mag(&z, &q, &pd);
        let mut t = mod_exp_mag(&a_mod, &q, &pd);
        let mut r = mod_exp_mag(&a_mod, &limbs::shr(&limbs::add(&q, &[1u64]), 1), &pd);

        while t != vec![1u64] {
            // Least i in (0, m) with t^(2^i) == 1.
            let mut i = 0usize;
            let mut t2 = t.clone();
            while t2 != vec![1u64] {
                t2 = limbs::rem(&limbs::mul(&t2, &t2), &pd);
                i += 1;
                if i == m {
                    return core::ptr::null_mut();
                }
            }
            if i == 0 {
                break;
            }
            let mut b = c.clone();
            for _ in 0..(m - i - 1) {
                b = limbs::rem(&limbs::mul(&b, &b), &pd);
            }
            m = i;
            c = limbs::rem(&limbs::mul(&b, &b), &pd);
            t = limbs::rem(&limbs::mul(&t, &c), &pd);
            r = limbs::rem(&limbs::mul(&r, &b), &pd);
        }
        finish_sqrt(dst, inp, r)
    })
}

/// `a^e mod m` on magnitudes.
fn mod_exp_mag(a: &[Limb], e: &[Limb], m: &[Limb]) -> Vec<Limb> {
    let mut acc: Vec<Limb> = vec![1];
    let mut base = limbs::rem(a, m);
    let bits = limbs::bit_len(e);
    for i in 0..bits {
        if limbs::bit(e, i) {
            acc = limbs::rem(&limbs::mul(&acc, &base), m);
        }
        if i + 1 < bits {
            base = limbs::rem(&limbs::mul(&base, &base), m);
        }
    }
    acc
}

/// Store a computed square root into `dst`, allocating when `dst` is null — the
/// shared tail of `BN_mod_sqrt`'s several exits.
fn finish_sqrt(dst: Option<&mut BigNum>, inp: *mut BigNum, value: Vec<Limb>) -> *mut BigNum {
    match dst {
        None => new_owned(value, 0),
        Some(dst) => {
            if store(Some(dst), value, false) {
                inp
            } else {
                core::ptr::null_mut()
            }
        }
    }
}
