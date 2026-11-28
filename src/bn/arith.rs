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
//! Each entry point reads its operands through shared references whose last use
//! precedes the write, then borrows the output once at the store. No `&mut` and `&`
//! to the same object are ever live together, so a supported aliased call is not UB.
//!
//! The supported output aliases are the authority's documented or source-visible
//! ones. `r` may alias `a` or `b` for `BN_add`, `BN_sub`, `BN_uadd`, `BN_usub`,
//! `BN_mul` and `BN_gcd`; `r` may alias `a` for `BN_sqr`, `BN_nnmod`, `BN_lshift`,
//! `BN_rshift` and `BN_mod_inverse`; `r` may alias `a` or `p` for `BN_exp` and
//! `BN_mod_exp`; and `in` may alias `a` for `BN_mod_sqrt`. `BN_nnmod` rejects
//! `r == m`, as the authority's `bn_mod.c:21-24` does. `BN_mod_inverse`'s manual
//! calls `r == n` an error, but the authority's `int_bn_mod_inverse` copies `n`
//! before writing the result, so this implementation defines that case too.
//! `BN_mod_exp`'s `r == m` and `BN_mod_sqrt`'s `in == p` are likewise defined here
//! but are not authority-guaranteed.
//!
//! ## Montgomery multiplication: the bound argument
//!
//! The kernels ([`mont_mul_sos_into`], [`mont_mul_cios_into`], [`mont_sqr_into`])
//! compute `a * b * R^-1 mod m` for `n = m.len()` limbs, radix `B = 2^64`,
//! `R = B^n`, and an odd modulus `m` with a non-zero top limb (so
//! `B^(n-1) <= m < R`). The `T < m * R` bound is established here, not assumed
//! from the arithmetic:
//!
//! * The caller supplies `a, b < m`. The constant-time ladder establishes this
//!   **inductively**: every schedule returns a canonical residue in `[0, m)`, so
//!   the next multiply's operands satisfy the same bound. The base case is
//!   explicit: `run_mont_ladder` zero-extends the base to `n` limbs (`< R`) and
//!   multiplies by `rr = R^2 mod m < m`, so the first product is `< R * m` and
//!   the result is canonical; its accumulator starts as `R mod m < m`, and the
//!   final multiply uses the constant `1`. `BN_to_montgomery` passes
//!   `R^2 mod m` as one operand; `BN_mod_mul_montgomery`'s C contract is that
//!   both operands are already Montgomery residues (`< m`).
//! * Therefore `T = a * b < m^2 <= m * R`, which is REDC's exact precondition.
//!   In particular `T < B^(2n)`, so the product and every reduction
//!   intermediate fit the `2n + 1` accumulator without a carry escaping the top
//!   limb: adding `q_i * m * B^i` keeps the value below
//!   `m * R + (R - 1) * m = (2R - 1) * m < 2 * B^(2n)`.
//! * REDC returns `S = (T + q*m) / R` with `0 <= S < 2m`, so one masked
//!   conditional subtraction (a final borrow, never a branch on secret values)
//!   leaves the canonical representative in `[0, m)`.
//!
//! **Lazy-representation composition.** The schedules deliberately do *not* use
//! a lazy representation: every result is canonical before it is returned, which
//! is exactly what lets the ladder compose multiplications with no extra
//! correction. A kernel returning a merely `[0, 2m)` residue would not be
//! composable: feeding two such operands back in gives `T < 4m^2`, and
//! `4m^2 < m*R` requires `4m < R`, false for a modulus with a full top limb. Such
//! a kernel would have to finish the conditional subtraction (or be given a
//! wider reduction bound) before its output could be an input here. No schedule
//! below relaxes the bound, and none may without that argument.
//!
//! The width preconditions (`a`, `b`, `out`, `diff` exactly `n` limbs, `t`
//! exactly `2n + 1`) are checked in release by [`mont_geometry_ok`]; a mismatch
//! fails closed and writes nothing. Those lengths are public geometry, so the
//! check is not a branch on secret values.
//!
//! Only the *length* preconditions are runtime-checked. The *value* bound
//! (`a * b < m * R`) is a caller contract, not a runtime test: establishing
//! `a < m` inside the kernel would read secret limbs and branch on them, which
//! §5 forbids. It is instead established by construction — every kernel returns
//! a canonical `[0, m)` residue, `BN_to_montgomery` passes `R^2 mod m` as the
//! wide operand, and `BN_mod_mul_montgomery` requires Montgomery residues — so
//! the induction above is discharged at the callers, not by an assertion.

use core::ffi::{c_int, c_ulong};

use crate::bn::bignum::{
    as_mut, as_ref, magnitude, new_owned, new_owned_consttime, parts, parts_borrowed,
    parts_fallible, store, store_consttime, BN_copy, BN_get_flags, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;
use crate::runtime::constant_time::{constant_time_eq_s, constant_time_lt_s, constant_time_select};
use crate::runtime::err::err_sites::{
    BN_ADD_142, BN_DIV_217, BN_EXP_1324, BN_GCD_532, BN_MOD_194, BN_MOD_22, BN_MOD_307,
    BN_SQRT_352, BN_SQRT_43,
};
use crate::runtime::err::raise_site;
use crate::runtime::secret::{SecretBuf, SecretLimbs, SecretRef};

/// `int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` and `b` must each be
/// null or live.
#[no_mangle]
pub unsafe extern "C" fn BN_add(r: *mut BigNum, a: *const BigNum, b: *const BigNum) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, an) = parts_borrowed(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, bn) = parts_borrowed(y);
        let built = (|| -> Option<(Vec<Limb>, bool)> {
            if an == bn {
                Some((limbs::add_fallible(ad, bd)?, an))
            } else {
                match limbs::cmp(ad, bd) {
                    core::cmp::Ordering::Equal => Some((Vec::new(), false)),
                    core::cmp::Ordering::Greater => Some((limbs::sub_fallible(ad, bd)?, an)),
                    core::cmp::Ordering::Less => Some((limbs::sub_fallible(bd, ad)?, bn)),
                }
            }
        })();
        let Some((mag, neg)) = built else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, neg))
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
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, an) = parts_borrowed(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, bn) = parts_borrowed(y);
        let built = (|| -> Option<(Vec<Limb>, bool)> {
            if an != bn {
                Some((limbs::add_fallible(ad, bd)?, an))
            } else {
                match limbs::cmp(ad, bd) {
                    core::cmp::Ordering::Equal => Some((Vec::new(), false)),
                    core::cmp::Ordering::Greater => Some((limbs::sub_fallible(ad, bd)?, an)),
                    core::cmp::Ordering::Less => Some((limbs::sub_fallible(bd, ad)?, !bn)),
                }
            }
        })();
        let Some((mag, neg)) = built else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, neg))
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
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, _) = parts_borrowed(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, _) = parts_borrowed(y);
        let Some(mag) = limbs::add_fallible(ad, bd) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, false))
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
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, _) = parts_borrowed(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, _) = parts_borrowed(y);
        if ad.len() < bd.len() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_ADD_142) };
            return 0;
        }
        let Some(mag) = limbs::sub_fallible(ad, bd) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, false))
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
        let built = (|| -> Option<(Vec<Limb>, bool)> {
            if w == 0 {
                Some((crate::bn::alloc::try_clone_slice(&dst.d)?, dst.neg != 0))
            } else if dst.neg != 0 {
                let sub = limbs::from_u64_fallible(w as Limb)?;
                if limbs::cmp(&dst.d, &sub) == core::cmp::Ordering::Less {
                    Some((limbs::sub_fallible(&sub, &dst.d)?, false))
                } else {
                    Some((limbs::sub_fallible(&dst.d, &sub)?, true))
                }
            } else {
                Some((limbs::add_word_fallible(&dst.d, w as Limb)?, false))
            }
        })();
        let Some((mag, neg)) = built else {
            return 0;
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
        let built = (|| -> Option<(Vec<Limb>, bool)> {
            if w == 0 {
                Some((crate::bn::alloc::try_clone_slice(&dst.d)?, dst.neg != 0))
            } else if dst.neg != 0 {
                Some((limbs::add_word_fallible(&dst.d, w as Limb)?, true))
            } else {
                match limbs::sub_word_fallible(&dst.d, w as Limb) {
                    Some(d) => Some((d, false)),
                    None => Some((
                        limbs::sub_fallible(&limbs::from_u64_fallible(w as Limb)?, &dst.d)?,
                        true,
                    )),
                }
            }
        })();
        let Some((mag, neg)) = built else {
            return 0;
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
        let Some(mag) = limbs::mul_word_fallible(&dst.d, w as Limb) else {
            return 0;
        };
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
        let Some((q, r)) = limbs::div_rem_small_fallible(&dst.d, w as Limb) else {
            return c_ulong::MAX;
        };
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
        match limbs::div_rem_small_fallible(&src.d, w as Limb) {
            Some((_, r)) => r as c_ulong,
            None => c_ulong::MAX,
        }
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
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, an) = parts_borrowed(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, bn) = parts_borrowed(y);
        let Some(mag) = limbs::mul_fallible(ad, bd) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, an != bn))
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section; its
        // shared borrow ends at the limb operation, before the output is borrowed.
        let x = unsafe { as_ref(a) };
        let (ad, _) = parts_borrowed(x);
        let Some(mag) = limbs::mul_fallible(ad, ad) else {
            return 0;
        };
        // A square is never negative, whatever the operand's sign.
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared read above has ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, false))
    })
}

/// `int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// Either output may be null. A zero divisor fails, returns `0` and raises
/// `BN_R_DIV_BY_ZERO` at the authority's own coordinate in `BN_div`, which is
/// observable through `ERR_peek_error_all`.
///
/// **Dispatch.** A caller that stamps `BN_FLG_CONSTTIME` on `a` or `b` — the
/// authority's own signal, and what `ossl_rsa_check_private_exponent` and
/// `ossl_rsa_multiprime_derive` already do to their secret operands — gets the
/// fixed-pattern binary division in [`limbs::div_rem_ct_fallible`]. Every other
/// caller keeps the variable-time Knuth division it had, which is the authority's
/// behaviour for an unflagged operand. The dispatch itself is a branch on a
/// public flag, not on a secret value.
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
        // SAFETY: null-or-live per this function's `# Safety` section. The inputs are
        // read through shared references whose uses end before either output is
        // borrowed, so `a`/`b` may alias each other or either output.
        let (ad, an) = {
            // SAFETY: `a` is null-or-live per this function's `# Safety` section.
            let x = unsafe { as_ref(a) };
            parts_borrowed(x)
        };
        let (bd, bn) = {
            // SAFETY: `b` is null-or-live per this function's `# Safety` section.
            let y = unsafe { as_ref(b) };
            parts_borrowed(y)
        };
        if bd.is_empty() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_DIV_217) };
            return 0;
        }
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section, and the flags are plain values.
        let consttime =
            unsafe { BN_get_flags(a, BN_FLG_CONSTTIME) | BN_get_flags(b, BN_FLG_CONSTTIME) } != 0;
        // A zero divisor raises `BN_R_DIV_BY_ZERO` above; an allocation failure
        // here is only the ordinary failure answer and raises nothing.
        let divided = if consttime {
            limbs::div_rem_ct_fallible(ad, bd)
        } else {
            limbs::div_rem_fallible(ad, bd)
        };
        let Some((q, r)) = divided else {
            return 0;
        };
        // The quotient is negative exactly when the signs differ, and the remainder
        // takes the dividend's sign. Each output is borrowed and released in turn, so
        // two `&mut` are never alive at once when a caller passes the same object for
        // both slots. The remainder is stored first and the quotient last, so that
        // aliased case ends with the quotient.
        let mut ok = true;
        // SAFETY: `rem` is null-or-live per this function's `# Safety` section.
        let rem_out = unsafe { as_mut(rem) };
        if let Some(dst) = rem_out {
            ok &= store(Some(dst), r, an);
        }
        // SAFETY: `dv` is null-or-live per this function's `# Safety` section.
        let dv_out = unsafe { as_mut(dv) };
        if let Some(dst) = dv_out {
            ok &= store(Some(dst), q, an != bn);
        }
        c_int::from(ok)
    })
}

/// `int BN_nnmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)`
///
/// The non-negative remainder, which the rest of the `mod` family is defined
/// `BN_mod` is deliberately **not** exported: the authority declares it as
/// a macro over `BN_div`, so a library that exported it would be reachable through
/// `dlsym` where the authority is not — an observable ABI difference in the wrong
/// direction.
///
/// **No `BN_FLG_CONSTTIME` dispatch, deliberately, and measured.** The RSA CRT
/// sites T28 is about call `BN_div`'s remainder slot directly (the authority's
/// `BN_mod` macro), so the dispatch lives there. Routing this function's reduction
/// through the fixed-pattern division as well was implemented and then withdrawn:
/// the EC ladder stamps `BN_FLG_CONSTTIME` on every point coordinate, so the flag
/// propagates into the field arithmetic and the generic binary division was used
/// for the ladder's reductions. Measured on candidate `HEAD` with the same
/// harness: `ecdsa256` 1 722 µs / 136.4x the authority **with** the dispatch here
/// and 632 µs / 50.1x **without** it, every other workload unchanged and the six
/// cross-implementation checks identical. A field reduction needs a
/// constant-pattern *field* reduction (the sibling of `T27`), not a
/// bit-at-a-time long division; the flag is therefore honoured in [`BN_div`] and
/// not here, and the mod family's secret-operand timing is recorded as open in
/// T28 rather than paid for with a 2.7x signing cost.
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
        // SAFETY: `a` and `m` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its limb operation, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, an) = parts_borrowed(x);
        // SAFETY: as above for `m`.
        let y = unsafe { as_ref(m) };
        let (md, _) = parts_borrowed(y);
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
        // A remainder-only call: the quotient has no reader here (it can derive from
        // a secret dividend, which is why an earlier version adopted it in a
        // `SecretBuf` and discarded it), and the T29 census showed that allocation was
        // one of the per-reduction costs paid on every field multiplication. The loop
        // does not build it at all.
        let Some(mut rem) = limbs::rem_fallible(ad, md) else {
            return 0;
        };
        // A remainder that came out negative is made non-negative by adding the
        // modulus, which is the definition of `nnmod` rather than a fix-up.
        if an && !rem.is_empty() {
            let Some(v) = limbs::sub_fallible(md, &rem) else {
                return 0;
            };
            rem = v;
        }
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, rem, false))
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

/// The arithmetic behind [`mod_add_reduced_ct`], on limb slices, so it can be
/// tested without a `BIGNUM` and without unsafe pointer handling.
///
/// Preconditions: `ad` and `bd` are each shorter than or equal to `md`, and both
/// represent values in `[0, md)`. The result is a fresh vector shorter than or
/// equal to `md`.
pub(crate) fn mod_add_reduced_ct_limbs(ad: &[Limb], bd: &[Limb], md: &[Limb]) -> Option<Vec<Limb>> {
    let n = md.len();
    if n == 0 || ad.len() > n || bd.len() > n {
        return None;
    }

    let mut sum = crate::runtime::alloc::try_zeroed(n + 1, 0u64)?;
    let mut carry = 0u64;
    for (i, slot) in sum.iter_mut().enumerate().take(n) {
        // `overflowing_add` rather than `u128` sums: the debug profile's overflow
        // check is a conditional jump whose condition is derived from the operands'
        // values, which is exactly the branch this function exists to keep off a
        // secret-derived addend.
        let (low, carry_a) = ad.get(i).copied().unwrap_or(0).overflowing_add(carry);
        let (value, carry_b) = low.overflowing_add(bd.get(i).copied().unwrap_or(0));
        *slot = value;
        carry = u64::from(carry_a) | u64::from(carry_b);
    }
    sum[n] = carry;

    let mut reduced = crate::runtime::secret::SecretBuf::<u64>::try_zeroed(n + 1)?;
    let mut borrow = 0u64;
    for i in 0..n {
        let d = (sum[i] as u128)
            .wrapping_sub(md[i] as u128)
            .wrapping_sub(borrow as u128);
        reduced[i] = d as u64;
        borrow = ((d >> 127) & 1) as u64;
    }
    let top = (sum[n] as u128).wrapping_sub(borrow as u128);
    reduced[n] = top as u64;
    let underflow = ((top >> 127) & 1) as u64;

    // `underflow == 1` means `a + b < md`, so the unreduced sum is the answer.
    let mask = underflow.wrapping_neg();
    for i in 0..=n {
        sum[i] = (sum[i] & mask) | (reduced[i] & !mask);
    }

    // Both selected candidates are below `md`, so the limb at index `n` is zero
    // whichever one the mask picked: a sum below `md` has no carry into it, and a
    // sum at or above `md` is below `2*md < 2^(64n+1)`, hence its difference with
    // `md` cannot need that limb. Dropping it is a fixed length change, not a
    // value test, and it keeps the result within the public width the store
    // scans.
    sum.truncate(n);
    Some(sum)
}

/// `r = (a + b) mod m` for operands already reduced in `[0, m)`, in a constant
/// pattern over the public width `m.len()`.
///
/// This exists because the generic `BN_mod_add` reduces with `BN_nnmod`, whose
/// work follows the operands' values. The callers that need this one know their
/// operands are reduced; there is deliberately **no** value-dependent dispatch
/// here, because deciding whether an operand is reduced would itself compare
/// secrets.
///
/// The sum is formed over a fixed `n + 1` limbs; the conditional subtraction is
/// a masked select over the same width, with no trimming by value. A refused
/// allocation answers `false` without touching `r`; so do a null `r` and an
/// operand wider than the modulus, the latter two being caller-contract violations
/// rather than runtime outcomes.
///
/// The result is stored through [`store_consttime`], so its recorded limb length
/// remains value-dependent in the way every constant-time store in this crate is
/// (the T8 residual). What the fixed pattern removes is the branch on the addends' values
/// — including the reduction a generic add would run over the secret-derived sum — not the
/// normalised-length residual the representation imposes on every result.
///
/// # Precondition (arithmetic, not memory safety)
///
/// `a` and `b` are each in `[0, m)`. That is the caller's obligation, because
/// testing it here would compare secrets. The one wired caller,
/// `ossl_ecdsa_simple_sign_sig`'s `s = s + m`, establishes it by reducing the
/// digest into `[0, q)` first (the digest is `PUBLIC_DATA`, so the reduction's
/// control flow is public) and by taking `s` from a Montgomery product that is
/// already reduced. An operand outside the range is not a soundness problem: the
/// result is simply not the reduced sum.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `b` and `m` must each
/// be null or live. `r` may alias `a` or `b`: every shared read of the operands
/// ends before `r` is borrowed for the store, which is the aliasing the signing
/// path uses for its in-place add.
pub(crate) unsafe fn mod_add_reduced_ct(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    m: *const BigNum,
) -> bool {
    // SAFETY: `a`, `b` and `m` are null-or-live per this function's `# Safety`
    // section. The three shared reads end at the limb operation below, before `r`
    // is borrowed for the store, so an `r` aliasing `a` or `b` is never borrowed
    // twice.
    let (ad, bd, md) = unsafe {
        (
            magnitude(as_ref(a)),
            magnitude(as_ref(b)),
            magnitude(as_ref(m)),
        )
    };
    let width = md.len();
    if width == 0 {
        return false;
    }
    let Some(sum) = mod_add_reduced_ct_limbs(ad, bd, md) else {
        return false;
    };
    // SAFETY: `r` is null-or-live per this function's `# Safety` section, and every
    // shared borrow above has ended.
    store_consttime(unsafe { as_mut(r) }, sum, false, width)
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
            (magnitude(rd), magnitude(md))
        };
        let mut max_shift = limbs::bit_len(mv) as c_int - limbs::bit_len(rv) as c_int;
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
            (magnitude(rd), magnitude(md))
        };
        if limbs::cmp(rv2, mv2) != core::cmp::Ordering::Less {
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
            let (rv, mv) = (magnitude(rd), magnitude(md));
            if limbs::cmp(rv, mv) == core::cmp::Ordering::Less {
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

/// Shared body of [`BN_mod_inverse`] and [`BN_mod_inverse_consttime`].
///
/// `request_consttime` is the caller's classification: the public entry point sets
/// it from `BN_FLG_CONSTTIME` on `a` or `n` (the authority's own dispatch, its
/// `int_bn_mod_inverse`), while an internal caller that knows its operands are
/// secret sets it directly. `strict_consttime` makes a domain refusal a failure
/// rather than a fallback: the explicit constant-time entry point refuses an even
/// or zero modulus instead of silently taking the variable-time path.
///
/// Both paths raise `BN_R_NO_INVERSE` on failure, so the reason code a caller can
/// observe is the same for either.
///
/// # Safety
///
/// As `BN_mod_add`: `r` is null or live and uniquely owned, and `a` and `n` are
/// null or live.
unsafe fn mod_inverse_impl(
    r: *mut BigNum,
    a: *const BigNum,
    n: *const BigNum,
    request_consttime: bool,
    strict_consttime: bool,
) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: `a` and `n` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its `parts` call, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return core::ptr::null_mut();
        };
        // SAFETY: as above for `n`.
        let y = unsafe { as_ref(n) };
        let Some((nd, _)) = parts_fallible(y) else {
            return core::ptr::null_mut();
        };

        // The constant-time binary EEA's domain is a non-zero odd modulus. The
        // parity and emptiness of the modulus are public geometry, not a secret
        // value, so this dispatch is not a secret-dependent branch.
        let eligible = !nd.is_empty() && !limbs::is_even(&nd);
        if request_consttime && strict_consttime && !eligible {
            // Enforced precondition, not an assumption: the explicit entry point
            // is only for callers that can prove an odd modulus. No reachable
            // caller supplies an even one; failing closed here keeps a future
            // caller from silently getting the variable-time algorithm.
            return core::ptr::null_mut();
        }
        let consttime = request_consttime && eligible;
        let inv = if consttime {
            limbs::mod_inverse_consttime(&ad, &nd)
        } else {
            limbs::mod_inverse(&ad, &nd)
        };
        let inv = match inv {
            Some(v) => v,
            None => {
                // The authority's `BN_mod_inverse` raises this itself, after its
                // internal helper reports the failure through a flag.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_GCD_532) };
                return core::ptr::null_mut();
            }
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        match unsafe { as_mut(r) } {
            // A constant-time result is trimmed and tested with a mask; the
            // variable-time result keeps the authority's normalising copy.
            None if consttime => new_owned_consttime(inv, 0, nd.len()),
            None => crate::bn::bignum::try_new_owned(inv, 0).unwrap_or(core::ptr::null_mut()),
            Some(dst) => {
                let stored = if consttime {
                    // The modulus limb count is the public width the inverse was
                    // produced at; the trim costs exactly that many limbs.
                    store_consttime(Some(dst), inv, false, nd.len())
                } else {
                    store(Some(dst), inv, false)
                };
                if stored {
                    r
                } else {
                    core::ptr::null_mut()
                }
            }
        }
    })
}

/// `int BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)`
///
/// Writes to `r` and returns `r`, or allocates and returns the new object when `r`
/// is null; `NULL` when no inverse exists.
///
/// **Dispatch.** A caller that stamps `BN_FLG_CONSTTIME` on `a` or `n` — the
/// authority's own signal, and what `dsa_sign_setup` does to its blinding factor
/// — gets the fixed-iteration binary extended GCD when the modulus is odd. Every
/// other caller, and every even-modulus caller, keeps the variable-time
/// extended Euclidean path. This is the public, compatibility-preserving
/// dispatch; internal callers that know their operands secret and their modulus
/// odd use [`BN_mod_inverse_consttime`] instead.
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
    // SAFETY: `a` and `n` are null-or-live per this function's `# Safety`
    // section; `BN_get_flags` accepts null (no flags).
    let consttime =
        unsafe { BN_get_flags(a, BN_FLG_CONSTTIME) | BN_get_flags(n, BN_FLG_CONSTTIME) } != 0;
    // SAFETY: this function's contract is `mod_inverse_impl`'s contract, and a
    // non-strict request preserves the public fallback for an even modulus.
    unsafe { mod_inverse_impl(r, a, n, consttime, false) }
}

/// Crate-internal constant-time inversion, for callers whose operands are secret
/// and whose modulus is proved odd.
///
/// The returned value and its error semantics are `BN_mod_inverse`'s; the only
/// difference is that an even or zero modulus is **refused** (answers `NULL`
/// without raising) rather than falling back to the variable-time algorithm. That
/// is deliberate: a caller that has classified its operands as secret must not be
/// able to reach a value-dependent algorithm by supplying a modulus outside the
/// constant-time domain.
///
/// # Safety
///
/// As `BN_mod_add`.
#[allow(non_snake_case)] // the crate's BN entry points keep the authority's spelling
pub(crate) unsafe fn BN_mod_inverse_consttime(
    r: *mut BigNum,
    a: *const BigNum,
    n: *const BigNum,
) -> *mut BigNum {
    // SAFETY: this function's contract is `mod_inverse_impl`'s contract.
    unsafe { mod_inverse_impl(r, a, n, true, true) }
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section; the
        // borrowed view ends before the output is borrowed.
        let x = unsafe { as_ref(a) };
        let ad = magnitude(x);
        let an = x.is_some_and(|v| v.neg != 0);
        let Some(mag) = limbs::shl_fallible(ad, n as usize) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared read above has ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, an))
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section; the
        // borrowed view ends before the output is borrowed.
        let x = unsafe { as_ref(a) };
        let ad = magnitude(x);
        let an = x.is_some_and(|v| v.neg != 0);
        let Some(mag) = limbs::shr_fallible(ad, n as usize) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared read above has ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, mag, an))
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
            let (rv, mv) = (magnitude(rd), magnitude(md));
            if limbs::cmp(rv, mv) == core::cmp::Ordering::Less {
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
        let Some(pow) = limbs::shl_fallible(&[1u64], n as usize) else {
            return 0;
        };
        let Some(mask) = limbs::sub_fallible(&pow, &[1u64]) else {
            return 0;
        };
        let Some(masked) = limbs::and_fallible(&dst.d, &mask) else {
            return 0;
        };
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
        let (ad, bd) = (magnitude(x), magnitude(y));
        let (an, bn) = (x.is_some_and(|v| v.neg != 0), y.is_some_and(|v| v.neg != 0));
        // The authority orders by sign first (`a->neg != b->neg`) and only then by
        // magnitude, reversing the magnitude order when both are negative. Reversing
        // the mixed-sign answer as well — the obvious way to write "reversed for
        // negatives" — is wrong for exactly the case where `a` is negative and `b` is
        // not, and that case is in the court.
        match (an, bn) {
            (false, true) => 1,
            (true, false) => -1,
            (true, true) => match limbs::cmp(ad, bd) {
                core::cmp::Ordering::Less => 1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => -1,
            },
            (false, false) => match limbs::cmp(ad, bd) {
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
        let (ad, bd) = (magnitude(x), magnitude(y));
        match limbs::cmp(ad, bd) {
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
        // SAFETY: `p` is null-or-live per this function's `# Safety` section; its
        // shared borrow ends at `parts`, before the output is borrowed.
        let y = unsafe { as_ref(p) };
        // The authority's ladder is driven by `BN_num_bits`/`BN_is_bit_set`, which read
        // the exponent's *magnitude*, so a negative exponent is not rejected: it
        // computes `a^|p|`. `BN_exp` is explicit about that in `bn_exp.c` — there is no
        // sign test anywhere in it.
        let Some((pd, _)) = parts_fallible(y) else {
            return 0;
        };
        // SAFETY: as above for `a`.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        let Some(mut acc) = crate::bn::alloc::try_zeroed(1, 1u64) else {
            return 0;
        };
        let mut base = ad;
        for i in 0..limbs::bit_len(&pd) {
            if limbs::bit(&pd, i) {
                let Some(v) = limbs::mul_fallible(&acc, &base) else {
                    return 0;
                };
                acc = v;
            }
            if i + 1 < limbs::bit_len(&pd) {
                let Some(v) = limbs::mul_fallible(&base, &base) else {
                    return 0;
                };
                base = v;
            }
        }
        let _ = ctx;
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, acc, false))
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
        // SAFETY: `a`, `p` and `m` are null-or-live per this function's `# Safety`
        // section. The base and modulus are copied; the exponent is borrowed only
        // across the staging copy / ladder, and that borrow ends before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: as above for `p`.
        let y = unsafe { as_ref(p) };
        // The exponent's magnitude is secret on the constant-time path. It is not
        // cloned at its own length: `magnitude` borrows the caller's storage and
        // the constant-time branch stages it directly into a buffer sized by the
        // public modulus width. See `mod_exp_core_consttime_from_parts`.
        let pd = magnitude(y);
        // SAFETY: as above for `m`.
        let z = unsafe { as_ref(m) };
        let Some((md, _)) = parts_fallible(z) else {
            return 0;
        };
        // SAFETY: `a`, `p` and `m` are null-or-live per this function's
        // `# Safety` section; `BN_get_flags` treats null as no flags. The
        // authority tests all three operands, and a marked base is how
        // `dsa_sign_setup`'s Fermat inversion asks for the fixed-pattern path.
        let consttime = unsafe {
            BN_get_flags(a, BN_FLG_CONSTTIME)
                | BN_get_flags(p, BN_FLG_CONSTTIME)
                | BN_get_flags(m, BN_FLG_CONSTTIME)
        } != 0;
        // The dispatch is explicit: a caller that stamped the base, exponent or
        // modulus with `BN_FLG_CONSTTIME` gets the fixed-pattern ladder; every
        // other caller keeps the variable-time ladder it had. An even modulus has
        // no Montgomery form, so it stays on the variable-time path here — the two
        // Montgomery entry points refuse that modulus before they get this far.
        let result = if consttime && !limbs::is_even(&md) {
            // The public width is the modulus' limb count. The exponent in every
            // constant-time reachable caller is bounded by that modulus (DH's
            // private exponent is < p, RSA's is < n, EC's is < the group order),
            // so the ladder's geometry is fixed from public data alone.
            //
            // `from_parts` stages the borrowed exponent into a buffer whose
            // allocation is that public width before running the ladder. A wider
            // exponent is refused inside, never truncated; an allocation failure
            // is the ordinary failure answer.
            match mod_exp_core_consttime_from_parts(&ad, pd, &md, md.len()) {
                Some(v) => Some(v),
                None => return 0,
            }
        } else {
            mod_exp_core(&ad, pd, &md)
        };
        match result {
            Some(v) => {
                // SAFETY: `r` is null-or-live per this function's `# Safety` section;
                // the shared reads above have ended.
                let dst = unsafe { as_mut(r) };
                // A consttime result may be a function of the secret exponent, so
                // it is stored without a value-dependent trim branch.
                let stored = if consttime {
                    store_consttime(dst, v, false, md.len())
                } else {
                    store(dst, v, false)
                };
                c_int::from(stored)
            }
            None => {
                // The only `None` here is the variable-time ladder's zero modulus;
                // that reaches `BN_div` inside the authority's ladder, so the
                // coordinate is `BN_div`'s.
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BN_DIV_217) };
                0
            }
        }
    })
}

/// Test-only observation of the exponentiation schedule each entry point selects.
///
/// The production code calls this nowhere; `#[cfg(test)]` removes it from every
/// non-test build. A thread-local record keeps parallel tests independent, and
/// the values are iteration counts (`64 * width` for the fixed-pattern ladder,
/// `bit_len(exponent)` for the variable-time core), never wall-clock times.
#[cfg(test)]
pub(crate) mod ladder_probe {
    use core::cell::RefCell;

    thread_local! {
        static LADDER_BITS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static VARTIME_BITS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    /// Start a fresh observation on this thread.
    pub(crate) fn reset() {
        LADDER_BITS.with(|v| v.borrow_mut().clear());
        VARTIME_BITS.with(|v| v.borrow_mut().clear());
    }

    pub(crate) fn record_ladder(bits: usize) {
        LADDER_BITS.with(|v| v.borrow_mut().push(bits));
    }

    pub(crate) fn record_vartime(bits: usize) {
        VARTIME_BITS.with(|v| v.borrow_mut().push(bits));
    }

    /// Every fixed-pattern ladder executed on this thread since [`reset`].
    pub(crate) fn ladder_bits() -> Vec<usize> {
        LADDER_BITS.with(|v| v.borrow().clone())
    }

    /// Every variable-time core execution on this thread since [`reset`].
    pub(crate) fn vartime_bits() -> Vec<usize> {
        VARTIME_BITS.with(|v| v.borrow().clone())
    }
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
pub(crate) fn mod_exp_core(ad: &[Limb], pd: &[Limb], md: &[Limb]) -> Option<Vec<Limb>> {
    if md.is_empty() {
        return None;
    }
    #[cfg(test)]
    ladder_probe::record_vartime(limbs::bit_len(pd));
    // `x**0 mod 1` and `x**0 mod -1` are zero, and every other zero exponent gives
    // one — the authority states this rule explicitly, and the naive loop gets the
    // `|m| == 1` case wrong by answering one.
    if limbs::bit_len(pd) == 0 {
        return Some(if md.len() == 1 && md[0] == 1 {
            Vec::new()
        } else {
            crate::bn::alloc::try_zeroed(1, 1u64)?
        });
    }
    // This ladder is the variable-time one, but it still runs on DH's private
    // exponent when the caller did not stamp the constant-time flag, so its
    // allocations are fallible and propagate instead of aborting.
    let mut acc: Vec<Limb> = crate::bn::alloc::try_zeroed(1, 1u64)?;
    let mut base = limbs::rem_fallible(ad, md)?;
    let bits = limbs::bit_len(pd);
    for i in 0..bits {
        if limbs::bit(pd, i) {
            let prod = limbs::mul_fallible(&acc, &base)?;
            acc = limbs::rem_fallible(&prod, md)?;
        }
        if i + 1 < bits {
            let sq = limbs::mul_fallible(&base, &base)?;
            base = limbs::rem_fallible(&sq, md)?;
        }
    }
    Some(acc)
}

/// `-m^-1 mod 2^64` for an odd `m`, by Newton's iteration.
///
/// Only the modulus is an input, and the modulus is public on every path that
/// reaches the constant-time ladder, so this precomputation is deliberately
/// variable-time.
fn mont_n0(m0: Limb) -> Limb {
    // For odd `m0`, `m0 * m0 == 1 (mod 8)`, so `inv = m0` is correct in three
    // bits and each iteration doubles the correct width (3 * 2^6 = 192 bits).
    let mut inv = m0;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// Copy `v` into a zero-padded vector of exactly `n` limbs, or `None` when the
/// allocation fails.
pub(crate) fn pad_to(v: &[Limb], n: usize) -> Option<Vec<Limb>> {
    let mut out = crate::bn::alloc::try_zeroed(n, 0u64)?;
    let take = v.len().min(n);
    out[..take].copy_from_slice(&v[..take]);
    Some(out)
}

/// Copy `v` into exactly `n` limbs of a [`SecretLimbs`] buffer.
///
/// This is the protected counterpart of [`pad_to`] for the constant-time ladder's
/// base: the destination is allocated as secret-bearing storage *first*, so a
/// secret value is never staged in an ordinary `Vec` whose release would leave the
/// contents behind. Used with a [`SecretBuf`] remainder (see
/// [`mod_exp_core_consttime_staged`]) and with the caller's base limbs.
fn pad_secret(v: &[Limb], n: usize) -> Option<SecretLimbs> {
    let mut out = SecretBuf::try_zeroed(n)?;
    let take = v.len().min(n);
    out[..take].copy_from_slice(&v[..take]);
    Some(out)
}

/// A zeroed limb vector of exactly `n` limbs, or `None` if the allocator refuses.
///
/// The ladder's scratch is allocated once, through `try_reserve_exact`, so an
/// allocation failure becomes the entry points' ordinary `None`/0 answer instead
/// of `handle_alloc_error`'s process abort. The pre-ladder reductions use the
/// fallible [`limbs::rem_fallible`]/[`limbs::mul_fallible`] family. What remains
/// infallible on the way in is the C-ABI argument copies in
/// [`crate::bn::bignum::parts`], plus the [`limbs::rem`]/[`limbs::mul`] wrappers
/// that the variable-time public path still calls; that residual keeps
/// `OBL-BN-ALLOCATOR` open.
fn try_zeroed_limbs(n: usize) -> Option<Vec<Limb>> {
    crate::bn::alloc::try_zeroed(n, 0u64)
}

/// Stage the exponent at exactly `width` limbs with a **fixed-width, masked**
/// extension, **once**, before the ladder.
///
/// The destination is written `width` times — the loop bound is the public
/// width, never `pd.len()` — so the copy's work and the staged buffer's
/// allocation are fixed by public geometry. A destination limb whose source is
/// absent is written as zero: the presence test is an all-ones/all-zeros mask
/// (`constant_time_lt_s(i, n)`), not a select of the limb's value.
///
/// After this copy every exponent read inside the ladder is an indexed load from
/// a buffer whose length is the public `width`; no iteration consults the
/// exponent's normalised length.
///
/// **Residual, stated rather than hidden.** The source binds `pd`'s usable
/// extent to the exponent's own (secret) normalised length, so `pd.get(i)` must
/// test `i < pd.len()` to avoid an out-of-bounds read; ctgrind reports that one
/// bounds test under length taint. It is irreducible at this generic ABI: the
/// caller's `BIGNUM` stores only `len` limbs, so a public-width read would either
/// index out of bounds or read uninitialised spare storage. What is removed here
/// is the *work* dependence — the duplicate secret-sized clone, the `min()`
/// length check and the length-sized memmove are gone; only a single presence
/// test remains, and the destination extent is public.
///
/// Returns the number of destination limbs written so a test can prove the copy
/// length is the public width even when two inputs differ in length.
fn stage_fixed_width_exponent(pd: &[Limb], width: usize) -> Option<(SecretLimbs, usize)> {
    let mut view = SecretBuf::try_zeroed(width)?;
    let n = pd.len();
    let mut written = 0usize;
    for (i, dst) in view.iter_mut().enumerate() {
        // All-ones exactly when limb `i` is present. The mask is a value, not a
        // branch on the limb, and the destination index is public.
        let present = constant_time_lt_s(i, n) as Limb;
        let limb = pd.get(i).copied().unwrap_or(0);
        *dst = limb & present;
        written += 1;
    }
    Some((view, written))
}

/// [`stage_fixed_width_exponent`], discarding the work count.
fn fixed_width_exponent(pd: &[Limb], width: usize) -> Option<SecretLimbs> {
    stage_fixed_width_exponent(pd, width).map(|(view, _)| view)
}

/// The schedule an integrated Montgomery multiply uses.
///
/// Both schedules compute the same function, `a * b * R^-1 mod m`, and are
/// differentially verified against each other bit for bit. `Sos` is the
/// reference; `Cios` is the admitted ladder default, selected through the named
/// constant [`LADDER_SCHEDULE`] so a schedule change stays an explicit, measured
/// decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MontSchedule {
    /// Reference: separated operand scanning (SOS) — the full schoolbook
    /// product into `2n + 1` limbs, then a word-wise REDC pass.
    Sos,
    /// Coarsely integrated operand scanning (CIOS): each product row is reduced
    /// as it is produced, so only `n + 2` limbs of accumulator are needed and
    /// the product's low half is never stored.
    ///
    /// The admitted ladder default ([`LADDER_SCHEDULE`]); also constructible by
    /// a caller through [`mont_mul_fallible_with`] and by the PFP-6 differential
    /// court.
    Cios,
}

/// The schedule the constant-time ladder uses.
///
/// `Cios` is the admitted default: at the PFP-5 five-bit-window composition it
/// measured 0.8274× the SOS operation at 2048 bits and 0.8379× at 8192 bits, and
/// the CIOS carrier was branch-audited at its own digests (PFP-6
/// `evidence/performance-frontier/campaigns/PFP-6/ADMISSION.md`). `Sos` remains
/// the reference kernel, selected through [`mont_mul_fallible`] /
/// [`MontSchedule::Sos`] for the differential court and available as the
/// fallback. Switching this constant is the whole schedule change; the window,
/// the squaring path and the conversions are untouched.
const LADDER_SCHEDULE: MontSchedule = MontSchedule::Cios;

/// Whether the ladder uses the dedicated squaring kernel.
///
/// The kernel is differentially verified against the reference. Adopting it
/// changes the ladder's default arithmetic and is therefore off until the
/// affected performance rows are re-run at the same digest.
const LADDER_DEDICATED_SQUARING: bool = false;

/// The fixed window width of the constant-time exponentiation ladder, or `None`
/// for the bit-at-a-time reference.
///
/// The window is a constant-pattern schedule: the number of windows is
/// `ceil(64 * width / w)` (public geometry), every window performs exactly `w`
/// squarings, and the digit is selected from a `2^w`-entry table with a full
/// masked scan — never an index. The exponent's value therefore changes only
/// which table row is masked in, never the control flow or the addresses.
///
/// `Some(5)` is the admitted PFP-5 default and the fallback for a degenerate
/// geometry; the production paths derive `w` from public geometry with
/// [`select_window_bits`] (PFP-42). `None` keeps the bit-at-a-time reference,
/// which the differential court runs against the windowed path on every case.
const LADDER_WINDOW_BITS: Option<u32> = Some(5);

/// Select the fixed-window width from **public geometry only**.
///
/// `width` is the ladder's resolved limb width — the staged exponent buffer's
/// length, so `bits = 64 * width` — and `modulus_limbs` is `md.len()`. Both are
/// public: the width is the caller's declared bound (or the PFP-43 covering
/// width, itself a declassified *length*), and the modulus limb count is
/// public. No exponent value and no exponent-normalised length enters this
/// choice; the selected `w` is therefore fixed for a given group configuration
/// and the mask-scan schedule it drives stays constant-pattern.
///
/// Evaluates the PFP-42 integer cost model
/// (`evidence/performance-frontier/campaigns/PFP-42/BOUNDS.md`):
///
/// ```text
/// cost(w) = [ceil(bits/w)·(w+1) + 2^w]·C(M) + windows·2^w·M·3
/// ```
///
/// The first term is main-loop squarings, main-loop multiplies, the table build
/// and the conversions; the second is the campaign's conservative upper bound
/// of three instructions per limb-select for the full masked scan (the measured
/// scan is cheaper, so the model never understates the table). `C(M)` is the
/// measured per-Montgomery-multiply cost, modelled as `21163·M²/1024`:
/// anchored on the measured `n = 32` CIOS figure (21,163 instructions) and
/// matching the measured `n = 4` figure (333) to 0.6 %. The scaling is exact in
/// `M²` for the CIOS schedule, so only the `n = 32` anchor is load-bearing.
///
/// The arithmetic is `u128` and saturating; an overflowing score loses to a
/// finite one, and a degenerate geometry keeps [`LADDER_WINDOW_BITS`]. The
/// returned width is in `1..=8`.
fn select_window_bits(width: usize, modulus_limbs: usize) -> u32 {
    const MAX_W: u32 = 8;
    let default = LADDER_WINDOW_BITS.unwrap_or(5);
    let bits = width.saturating_mul(64);
    if bits == 0 || modulus_limbs == 0 {
        return default;
    }
    let m = modulus_limbs as u128;
    let score = |w: u32| -> u128 {
        let wu = w as usize;
        let windows = bits.div_ceil(wu);
        let mont_ops = windows
            .saturating_mul(wu.saturating_add(1))
            .saturating_add(1usize << wu);
        let mult = (mont_ops as u128)
            .saturating_mul(21_163)
            .saturating_mul(m)
            .saturating_mul(m);
        let scan = (windows as u128)
            .saturating_mul(1u128 << wu)
            .saturating_mul(m)
            .saturating_mul(3 * 1024);
        mult.saturating_add(scan)
    };
    let mut best_w = default;
    let mut best = score(best_w);
    for w in 1..=MAX_W {
        let s = score(w);
        if s < best {
            best = s;
            best_w = w;
        }
    }
    best_w
}

/// `a * b + c + d` for 64-bit terms, as a 128-bit value.
///
/// The maximum is `(2^64-1)^2 + 2*(2^64-1) = 2^128 - 1`, so the arithmetic
/// cannot overflow. `wrapping_*` states that and keeps the profile's overflow
/// check — a conditional jump on the product's high bits — out of the
/// secret-bearing Montgomery loop. The check is never taken, but its *condition*
/// depends on secret limbs, which is exactly what ctgrind reports and what
/// §5 forbids after optimisation.
#[inline(always)]
fn mul_add_carry(a: u64, b: u64, c: u64, d: u64) -> u128 {
    (a as u128)
        .wrapping_mul(b as u128)
        .wrapping_add(c as u128)
        .wrapping_add(d as u128)
}

/// Add a 128-bit term into a private 192-bit accumulator.
///
/// One column of a Comba product has at most `n + 1` terms, each below `2^128`,
/// so it is below `(n + 1) * 2^128 < 2^192` for every `usize` limb count
/// `n < 2^64`. Three limbs therefore hold it without loss. `wrapping_*` keeps
/// the profile's overflow check out of the secret-bearing loop; the bound above
/// shows the wrap cannot occur.
#[inline(always)]
fn wide_add(acc: &mut [Limb; 3], v: u128) {
    let (s0, c0) = acc[0].overflowing_add(v as Limb);
    let (s1, c1) = acc[1].overflowing_add((v >> 64) as Limb);
    let (s1, c2) = s1.overflowing_add(u64::from(c0));
    acc[0] = s0;
    acc[1] = s1;
    acc[2] = acc[2]
        .wrapping_add(u64::from(c1))
        .wrapping_add(u64::from(c2));
}

/// Check the shared length geometry of every integrated kernel.
///
/// `a`, `b`, `out` and `diff` must be exactly `n = m.len()` limbs and `t`
/// exactly `2n + 1`. These are public lengths, so this branch is not a branch on
/// a secret value. It fails closed in release: a mismatch returns `false` and the
/// kernel writes nothing.
///
/// This replaces the `debug_assert!` pair that guarded the reference. In a
/// release build those assertions vanished, so an oversized `a` or `b` was
/// silently truncated to `n` limbs (a wrong product with no diagnostic) and an
/// undersized buffer indexed out of bounds (a panic, not a memory-safety bug,
/// but not a defined failure either). Widths now fail closed in every profile.
fn mont_geometry_ok(
    a: &[Limb],
    b: &[Limb],
    out: &[Limb],
    diff: &[Limb],
    m: &[Limb],
    t: &[Limb],
) -> bool {
    let n = m.len();
    let Some(t_needed) = n.checked_mul(2).and_then(|w| w.checked_add(1)) else {
        return false;
    };
    a.len() == n && b.len() == n && out.len() == n && diff.len() == n && t.len() == t_needed
}

/// REDC in place on `t[0..=2n]`: add `u * m * B^i` so limb `i` becomes zero, for
/// every `i`, then write the canonical residue into `out`.
///
/// The carry runs through a fixed range; the total value is below `2 * B^(2n)`,
/// so it never leaves `t`. The caller has checked the geometry and that
/// `a * b < m * R` (see the module-level bound argument).
fn redc_into(t: &mut [Limb], m: &[Limb], n0: Limb, out: &mut [Limb], diff: &mut [Limb]) {
    let n = m.len();
    for i in 0..n {
        let u = t[i].wrapping_mul(n0);
        let mut carry = 0u64;
        for j in 0..n {
            let v = mul_add_carry(u, m[j], t[i + j], carry);
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let mut c = carry;
        for limb in t[(i + n)..=(2 * n)].iter_mut() {
            let (s, overflow) = limb.overflowing_add(c);
            *limb = s;
            c = u64::from(overflow);
        }
    }

    // One masked conditional subtraction: the REDC value is in `[0, 2m)`. `high`
    // is the possible bit above `n` limbs; `borrow` is the final borrow of
    // `t[n..2n] - m`. Keep `t` only when `high == 0 && borrow == 1`.
    let high = t[2 * n];
    let mut borrow = 0u64;
    for j in 0..n {
        let (d1, b1) = t[n + j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = (high ^ 1) & borrow;
    let keep_mask = 0u64.wrapping_sub(keep);
    for (j, slot) in out.iter_mut().enumerate() {
        *slot =
            constant_time_select(keep_mask as usize, t[n + j] as usize, diff[j] as usize) as Limb;
    }
}

/// Reference Montgomery multiplication (SOS): full schoolbook product, then
/// word-wise REDC. Fixed loop counts (no value-dependent skip or normalise), and
/// the conditional subtraction is a mask select rather than a branch.
///
/// Returns `false` if the caller's geometry violates the length contract, in
/// which case nothing is written.
fn mont_mul_sos_into(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    if !mont_geometry_ok(a, b, out, diff, m, t) {
        return false;
    }
    let n = m.len();
    t.fill(0);

    // Schoolbook product into t[0..2n]. `t[i + n]` is untouched when row `i`
    // runs, so the carry may be stored directly.
    for i in 0..n {
        let mut carry = 0u64;
        for j in 0..n {
            let v = mul_add_carry(a[i], b[j], t[i + j], carry);
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        t[i + n] = carry;
    }

    redc_into(t, m, n0, out, diff);
    true
}

/// CIOS Montgomery multiplication: each product row is reduced as it is
/// produced. The accumulator is `n + 2` limbs (`t[0..=n+1]`), so the product's
/// low half is discarded as it is annihilated rather than stored.
///
/// **Invariant argument.** Let `T_i < 2m` be the accumulator at the start of
/// iteration `i` (initially `T_0 = 0`). The product step gives
/// `T' = T_i + a*b_i < 2m + m(B-1) = m(B+1)` because `a < m` and
/// `b_i <= B-1`; so `T' < B^n(B+1) < 2B^(n+1)`, which fits the `n + 2` limbs and
/// leaves `acc[n+1]` a single carry bit. The reduction step adds
/// `u*m <= (B-1)m`, so `T' + u*m < m(B+1) + m(B-1) = 2Bm`; dividing by `B`
/// gives `T_{i+1} < 2m`, re-establishing the invariant. After `n` iterations
/// `T_n < 2m`, so the single masked subtraction leaves `[0, m)`.
///
/// The final subtraction is a mask select. All loop counts are fixed by the
/// public `n`, and there is no branch on a limb's value.
fn mont_mul_cios_into(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    if !mont_geometry_ok(a, b, out, diff, m, t) {
        return false;
    }
    let n = m.len();
    if n == 0 {
        return true;
    }
    let acc = &mut t[..=n + 1];
    acc.fill(0);

    for &bi in b {
        // acc += a * b[i]
        let mut carry = 0u64;
        for j in 0..n {
            let v = mul_add_carry(a[j], bi, acc[j], carry);
            acc[j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (hi, overflow) = acc[n].overflowing_add(carry);
        acc[n] = hi;
        acc[n + 1] = u64::from(overflow);

        // acc += u * m, with `u` chosen so the low limb becomes zero. The low
        // limb of `u * m[0] + acc[0]` is zero by construction, so it is dropped.
        let u = acc[0].wrapping_mul(n0);
        let v = mul_add_carry(u, m[0], acc[0], 0);
        let mut carry = (v >> 64) as u64;
        for j in 1..n {
            let v = mul_add_carry(u, m[j], acc[j], carry);
            acc[j - 1] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (lo, overflow) = acc[n].overflowing_add(carry);
        acc[n - 1] = lo;
        acc[n] = acc[n + 1].wrapping_add(u64::from(overflow));
    }

    // acc[0..n] is the result before the single conditional subtraction; acc[n]
    // is the possible high bit. Subtract when the value is at least `m`:
    // `high != 0`, or the `n`-limb difference did not borrow.
    let high = acc[n];
    let mut borrow = 0u64;
    for j in 0..n {
        let (d1, b1) = acc[j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    for j in 0..n {
        out[j] = constant_time_select(mask as usize, diff[j] as usize, acc[j] as usize) as Limb;
    }
    true
}

/// CIOS Montgomery multiplication specialised to a compile-time limb count.
///
/// The body is [`mont_mul_cios_into`] with the runtime `n` replaced by the const
/// parameter `N`, so every loop bound, array extent and index is a compile-time
/// constant and the compiler can unroll the fixed trip counts and drop the
/// bounds checks it cannot prove for a runtime length. `a`, `b`, `out`, `m` and
/// `diff` are exactly `N` limbs; the accumulator is the first `ACC` limbs of `t`,
/// with `ACC == N + 2` at every call site (the CIOS accumulator size). `ACC` is a
/// second const parameter only because `N + 2` is not a stable const-generic
/// expression.
///
/// **The accumulator bound is inherited, not re-derived.** The product row, the
/// reduction row and the masked final subtraction are the same operations in the
/// same order as [`mont_mul_cios_into`], and the accumulator is the same `N + 2`
/// limbs, so the `T_i < 2m` invariant argument there applies verbatim with
/// `n := N`. No schedule, window, squaring or conversion step is changed.
///
/// Returns `false` on any geometry mismatch (a public length check), writing
/// nothing.
#[inline]
fn mont_mul_cios_fixed<const N: usize, const ACC: usize>(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    if N == 0 || ACC < N + 2 || t.len() < ACC {
        return false;
    }
    let (Ok(a), Ok(b), Ok(m)) = (
        <&[Limb; N]>::try_from(a),
        <&[Limb; N]>::try_from(b),
        <&[Limb; N]>::try_from(m),
    ) else {
        return false;
    };
    let (Ok(out), Ok(diff), Ok(acc)) = (
        <&mut [Limb; N]>::try_from(out),
        <&mut [Limb; N]>::try_from(diff),
        <&mut [Limb; ACC]>::try_from(&mut t[..ACC]),
    ) else {
        return false;
    };

    acc.fill(0);

    for &bi in b {
        // acc += a * b[i]
        let mut carry = 0u64;
        for j in 0..N {
            let v = mul_add_carry(a[j], bi, acc[j], carry);
            acc[j] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (hi, overflow) = acc[N].overflowing_add(carry);
        acc[N] = hi;
        acc[N + 1] = u64::from(overflow);

        // acc += u * m, with `u` chosen so the low limb becomes zero. The low
        // limb of `u * m[0] + acc[0]` is zero by construction, so it is dropped.
        let u = acc[0].wrapping_mul(n0);
        let v = mul_add_carry(u, m[0], acc[0], 0);
        let mut carry = (v >> 64) as u64;
        for j in 1..N {
            let v = mul_add_carry(u, m[j], acc[j], carry);
            acc[j - 1] = v as u64;
            carry = (v >> 64) as u64;
        }
        let (lo, overflow) = acc[N].overflowing_add(carry);
        acc[N - 1] = lo;
        acc[N] = acc[N + 1].wrapping_add(u64::from(overflow));
    }

    // The same single masked conditional subtraction as the generic kernel.
    let high = acc[N];
    let mut borrow = 0u64;
    for j in 0..N {
        let (d1, b1) = acc[j].overflowing_sub(m[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let keep = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(keep);
    for j in 0..N {
        out[j] = constant_time_select(mask as usize, diff[j] as usize, acc[j] as usize) as Limb;
    }
    true
}

/// Dispatch a CIOS multiply to the compile-time-width kernel when the modulus'
/// limb count is one of the specialised widths, and to the generic slice kernel
/// for everything else.
///
/// The choice is on the **public** limb count, exactly as [`mont_geometry_ok`]
/// is. The generic [`mont_mul_cios_into`] is retained unchanged as both the
/// differential reference (`mont_mul_fallible_with`) and the fallback, so a
/// width that is not listed here keeps the previous code exactly. The widths are
/// the RSA/DH limb counts (16, 32, 48, 64, 128) and the two EC order widths that
/// the ladder reaches (4 for P-256, 6 for P-384, 9 for P-521).
fn mont_mul_cios_dispatch(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    if !mont_geometry_ok(a, b, out, diff, m, t) {
        return false;
    }
    match m.len() {
        4 => mont_mul_cios_fixed::<4, 6>(a, b, out, m, n0, t, diff),
        6 => mont_mul_cios_fixed::<6, 8>(a, b, out, m, n0, t, diff),
        9 => mont_mul_cios_fixed::<9, 11>(a, b, out, m, n0, t, diff),
        16 => mont_mul_cios_fixed::<16, 18>(a, b, out, m, n0, t, diff),
        32 => mont_mul_cios_fixed::<32, 34>(a, b, out, m, n0, t, diff),
        48 => mont_mul_cios_fixed::<48, 50>(a, b, out, m, n0, t, diff),
        64 => mont_mul_cios_fixed::<64, 66>(a, b, out, m, n0, t, diff),
        128 => mont_mul_cios_fixed::<128, 130>(a, b, out, m, n0, t, diff),
        _ => mont_mul_cios_into(a, b, out, m, n0, t, diff),
    }
}

/// Dedicated squaring: a Comba product from the operand's symmetry (each
/// unordered pair `i < j` contributes twice, the diagonal once), then the same
/// REDC pass as the reference.
///
/// This halves the number of limb multiplications relative to the reference's
/// `a * a`. The accumulator proof is in [`wide_add`]; the REDC bound is the same
/// as the reference (`a * a < m * R` because `a < m`). Returns `false` on a
/// geometry violation or if a carry survived the product's top column, which
/// cannot happen for `n`-limb operands and is reported rather than ignored.
fn mont_sqr_into(
    a: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    if !mont_geometry_ok(a, a, out, diff, m, t) {
        return false;
    }
    let n = m.len();
    t.fill(0);

    let mut acc = [0u64; 3];
    for (k, slot) in t.iter_mut().enumerate().take(n.saturating_mul(2)) {
        if k & 1 == 0 {
            let i = k / 2;
            if i < n {
                let v = (a[i] as u128) * (a[i] as u128);
                wide_add(&mut acc, v);
            }
        }
        if k >= 1 {
            // `j = k - i` and `i < j < n` for this (public) index range.
            let lo = k.saturating_sub(n - 1);
            let hi = (k - 1) / 2;
            for i in lo..=hi {
                let j = k - i;
                let v = (a[i] as u128) * (a[j] as u128);
                wide_add(&mut acc, v);
                wide_add(&mut acc, v);
            }
        }
        *slot = acc[0];
        acc[0] = acc[1];
        acc[1] = acc[2];
        acc[2] = 0;
    }
    // A product of two `n`-limb values is below `B^(2n)`, so after the `2n`
    // columns are emitted no carry survives. The check is structural (the value
    // is zero for every input), and a survivor is reported rather than dropped.
    if acc != [0, 0, 0] {
        return false;
    }

    redc_into(t, m, n0, out, diff);
    true
}

/// The ladder's multiply, using [`LADDER_SCHEDULE`].
///
/// Keeping the schedule out of the parameter list keeps the call site's argument
/// count at the reference's and makes the selected default one named constant.
fn mont_mul_ladder_into(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    match LADDER_SCHEDULE {
        MontSchedule::Sos => mont_mul_sos_into(a, b, out, m, n0, t, diff),
        MontSchedule::Cios => mont_mul_cios_dispatch(a, b, out, m, n0, t, diff),
    }
}

/// Reference Montgomery multiplication, kept as the named SOS path used by
/// [`mont_mul_fallible`]. See [`mont_mul_sos_into`]; returns `false` on a
/// geometry violation.
fn mont_mul_into(
    a: &[Limb],
    b: &[Limb],
    out: &mut [Limb],
    m: &[Limb],
    n0: Limb,
    t: &mut [Limb],
    diff: &mut [Limb],
) -> bool {
    mont_mul_sos_into(a, b, out, m, n0, t, diff)
}

/// Allocating wrapper over [`mont_mul_into`], for one-shot conversions outside the
/// ladder. `out` is returned as a plain vector because the caller adopts it into
/// a [`SecretBuf`]; the intermediate product and REDC storage can be secret when
/// the inputs are, so they are cleansed on every exit.
///
/// The input bound is `a * b < m * R` (see the module-level argument), which holds
/// for `a, b < m` or, as `BN_to_montgomery` uses, for `a < R` with `b = R^2 mod m`.
/// The result is then below `2m` and the single masked subtraction finishes it.
/// A geometry violation returns `None` rather than truncating.
pub(crate) fn mont_mul_fallible(a: &[Limb], b: &[Limb], m: &[Limb], n0: Limb) -> Option<Vec<Limb>> {
    mont_mul_fallible_with(MontSchedule::Sos, a, b, m, n0)
}

/// [`mont_mul_fallible`] with an explicit schedule, for the PFP-6 differential
/// and for a caller that has measured the schedule at its own widths.
pub(crate) fn mont_mul_fallible_with(
    schedule: MontSchedule,
    a: &[Limb],
    b: &[Limb],
    m: &[Limb],
    n0: Limb,
) -> Option<Vec<Limb>> {
    let n = m.len();
    let mut out = try_zeroed_limbs(n)?;
    let mut t = SecretBuf::try_zeroed(n.checked_mul(2)?.checked_add(1)?)?;
    let mut diff = SecretBuf::try_zeroed(n)?;
    if !match schedule {
        MontSchedule::Sos => mont_mul_sos_into(a, b, &mut out, m, n0, &mut t, &mut diff),
        MontSchedule::Cios => mont_mul_cios_into(a, b, &mut out, m, n0, &mut t, &mut diff),
    } {
        return None;
    }
    Some(out)
}

/// Allocating wrapper over [`mont_sqr_into`] for tests and for a caller that has
/// measured the dedicated squaring kernel at its own widths.
#[cfg(test)]
pub(crate) fn mont_sqr_fallible(a: &[Limb], m: &[Limb], n0: Limb) -> Option<Vec<Limb>> {
    let n = m.len();
    let mut out = try_zeroed_limbs(n)?;
    let mut t = SecretBuf::try_zeroed(n.checked_mul(2)?.checked_add(1)?)?;
    let mut diff = SecretBuf::try_zeroed(n)?;
    if !mont_sqr_into(a, &mut out, m, n0, &mut t, &mut diff) {
        return None;
    }
    Some(out)
}

/// Constant-pattern exponentiation `a^|p| mod m` for a secret exponent.
///
/// ## Design and why it has no secret-dependent branch
///
/// A fixed-width ladder: the loop runs exactly `64 * width` times, where `width`
/// is a **public** limb count supplied by the caller — the modulus' limb count for
/// the C entry points, or an explicitly declared width for a caller whose exponent
/// is legitimately wider than its modulus. It never uses the exponent's normalised
/// `len()` as the geometry: the exponent is only read through its bits. There is
/// no early exit, no skip, and no `bit_len` query. The exponent is zero-extended
/// once to a buffer of that public width, and each iteration reads a bit from it as
/// `(limb >> bit) & 1` and turns it into an all-ones/all-zeros mask; every iteration
/// computes both the multiply and the square and blends the multiply into the
/// accumulator with an in-place mask select. There is no secret index: a table
/// would be indexed by a secret, whereas this ladder selects between two
/// register-shaped candidates.
///
/// The reduction is Montgomery REDC ([`mont_mul`]) because it has a fixed loop
/// count, unlike [`limbs::rem`]. `R`, `R^2` and `n0` derive from the modulus;
/// their size is public, but their contents are not automatically public (RSA
/// CRT precomputation runs on secret primes), so `R` and `R^2` are kept in
/// [`SecretBuf`] and are still computed with variable-time helpers. The base is
/// folded into Montgomery form once, without a division: a base of at most `n`
/// limbs is below `R = 2^(64n)`, so `base * R^2 < R * m` satisfies REDC's
/// precondition and the fixed-loop [`mont_mul_into`] performs the reduction.
/// Its secrecy is per caller (DH's generator and RSA's message are public; an EC
/// field element, notably `ecdsa_sign_setup`'s nonce through
/// `ec_field_inverse_mod_ord`, is secret), so the fold is unconditional and
/// fixed-pattern. Only a base wider than `n` limbs — outside every EC caller's
/// domain — keeps the variable-time [`limbs::rem_fallible`], and that width is
/// public geometry.
///
/// Every intermediate is `n = m.len()` limbs wide, so no allocation size or
/// limb count depends on a secret bit. All ladder scratch is allocated once, before
/// the first iteration, and reused; an allocation failure returns `None` rather
/// than aborting. The returned vector is `n` limbs wide (not trimmed); a
/// constant-time caller stores it through [`store_consttime`], which trims with a
/// fixed-pass mask instead of a value-dependent branch.
///
/// ## When it is used
///
/// Only for an odd modulus: Montgomery form does not exist otherwise, and both
/// `BN_mod_exp_mont` and `BN_mod_exp_mont_consttime` refuse an even modulus
/// before reaching here. The dispatch is in `BN_mod_exp_mont` (the exponent or
/// modulus carries `BN_FLG_CONSTTIME`), in `BN_mod_exp_mont_consttime` (always),
/// and in `BN_mod_exp` (constant-time flag and odd modulus). The variable-time
/// [`mod_exp_core`] is retained for inputs proven public by their callers.
/// Test-only convenience wrapper: the default public width is the modulus' limb
/// count. The C entry points stage the borrowed exponent through
/// [`mod_exp_core_consttime_from_parts`] so the public width is stated at each
/// call site; the staging copy is the only transfer and it is public-width.
#[cfg(test)]
pub(crate) fn mod_exp_core_consttime(ad: &[Limb], pd: &[Limb], md: &[Limb]) -> Option<Vec<Limb>> {
    mod_exp_core_consttime_width(ad, pd, md, md.len())
}

/// What the ladder should do for an exponent/modulus pair.
///
/// The decision reads the modulus' limb count (public), the caller's
/// `declared_limbs` (public) and the exponent's normalised limb count. That last
/// read is an **admission decision** — an exponent wider than the public width is
/// refused, not truncated — and the limbs are then staged into a buffer whose
/// allocation and write count are fixed by the public terms alone. The ctgrind
/// `modexp_len` control taints it so this admission read is reported rather than
/// hidden.
enum LadderGeometry {
    /// `x mod 1 == 0` for every exponent; no ladder is needed.
    Zero,
    /// No Montgomery form for an even modulus: the variable-time path answers.
    VariableTime,
    /// Run the fixed-pattern ladder with this public limb width.
    Fixed(usize),
}

fn ladder_geometry(pd: &[Limb], md: &[Limb], declared_limbs: usize) -> Option<LadderGeometry> {
    if md.is_empty() {
        return None;
    }
    // `x mod 1` is zero for every exponent, and Montgomery form needs an odd
    // modulus greater than one. Modulus limbs are public, so this test is not a
    // leak.
    if md.len() == 1 && md[0] == 1 {
        return Some(LadderGeometry::Zero);
    }
    if limbs::is_even(md) {
        return Some(LadderGeometry::VariableTime);
    }
    // Both terms are public: the caller's declared width and the modulus' limb
    // count. The exponent's length is not consulted beyond the refusal below.
    let width = declared_limbs.max(md.len()).max(1);
    if pd.len() > width {
        return None;
    }
    Some(LadderGeometry::Fixed(width))
}

/// Constant-pattern exponentiation with an explicit **public** limb width.
///
/// `declared_limbs` is the width the caller's public contract fixes: the modulus'
/// limb count for the C entry points, or a larger declared value when a caller's
/// exponent may legitimately exceed its modulus. The loop count is
/// `64 * width` with `width = max(declared_limbs, md.len(), 1)`, both terms public.
/// The exponent's own normalised length never enters that expression.
///
/// An exponent wider than `width` is **refused** (`None`), not truncated and not
/// used to widen the ladder: widening on the exponent's length is exactly the
/// secret-metadata dependence this function exists to remove. Every reachable DH,
/// RSA CRT and EC caller keeps the exponent inside the modulus/order, so this
/// refusal is a contract check for an out-of-contract C caller, recorded as a
/// compatibility deviation rather than hidden.
#[cfg(test)]
pub(crate) fn mod_exp_core_consttime_width(
    ad: &[Limb],
    pd: &[Limb],
    md: &[Limb],
    declared_limbs: usize,
) -> Option<Vec<Limb>> {
    match ladder_geometry(pd, md, declared_limbs)? {
        LadderGeometry::Zero => Some(Vec::new()),
        // No Montgomery form. The two Montgomery entry points refuse this case
        // before dispatch; keeping a total answer here prevents an accidental
        // even modulus from producing a wrong result.
        LadderGeometry::VariableTime => mod_exp_core(ad, pd, md),
        LadderGeometry::Fixed(width) => {
            let exponent = fixed_width_exponent(pd, width)?;
            let window = Some(select_window_bits(width, md.len()));
            mod_exp_core_consttime_staged(ad, &exponent, md, width, window)
        }
    }
}

/// The [`mod_exp_core_consttime_width`] dispatch with an explicit window choice,
/// so the differential court can run the bit-at-a-time reference (`None`) and the
/// windowed schedules (`Some(4..=6)`) over the same population.
#[cfg(test)]
pub(crate) fn mod_exp_core_consttime_width_with(
    ad: &[Limb],
    pd: &[Limb],
    md: &[Limb],
    declared_limbs: usize,
    window: Option<u32>,
) -> Option<Vec<Limb>> {
    match ladder_geometry(pd, md, declared_limbs)? {
        LadderGeometry::Zero => Some(Vec::new()),
        LadderGeometry::VariableTime => mod_exp_core(ad, pd, md),
        LadderGeometry::Fixed(width) => {
            let exponent = fixed_width_exponent(pd, width)?;
            mod_exp_core_consttime_staged(ad, &exponent, md, width, window)
        }
    }
}

/// The precomputed parameters of one Montgomery domain, borrowed from a
/// prepared context.
///
/// The owner (`MontCtx`) establishes that every field belongs to the same
/// modulus and that the modulus matches the exponentiation's operand before a
/// value of this type is built. `rr` and `one` are exactly `md.len()` limbs.
pub(crate) struct PreparedMontParams<'a> {
    /// `-m^-1 mod 2^64`, the REDC word.
    pub(crate) n0: Limb,
    /// `R^2 mod m`.
    pub(crate) rr: &'a [Limb],
    /// `R mod m`, the Montgomery form of one.
    pub(crate) one: &'a [Limb],
}

/// Constant-pattern exponentiation for the C entry points, staging the exponent
/// directly from the caller's borrowed magnitude.
///
/// This is the representation-level fix for the destructor-timing finding. The
/// protected buffer is built at the **public** width before any secret limb is
/// copied into it, so its allocation — and therefore the extent its `Drop`
/// cleanse touches — is fixed by public geometry. `pd` is the caller's own limb
/// storage, not a length-sized clone: the staging copy is the only transfer, and
/// the temporary it produces is public-width. The borrow ends when this function
/// returns, so a caller may alias the output with the exponent afterwards.
pub(crate) fn mod_exp_core_consttime_from_parts(
    ad: &[Limb],
    pd: &[Limb],
    md: &[Limb],
    declared_limbs: usize,
) -> Option<Vec<Limb>> {
    mod_exp_core_consttime_from_parts_prepared(ad, pd, md, declared_limbs, None)
}

/// Constant-pattern exponentiation with optional precomputed Montgomery
/// parameters.
///
/// `prepared` is `Some` only when the caller holds a prepared context whose
/// modulus and representation were checked against `md`; the ladder then reuses
/// `R`, `R^2` and `n0` instead of deriving them from the modulus again. A
/// `None` keeps the recomputation, so an unprepared caller has exactly the
/// previous behaviour. The ladder's work, iteration count and memory access
/// pattern are otherwise identical in both arms.
pub(crate) fn mod_exp_core_consttime_from_parts_prepared(
    ad: &[Limb],
    pd: &[Limb],
    md: &[Limb],
    declared_limbs: usize,
    prepared: Option<&PreparedMontParams<'_>>,
) -> Option<Vec<Limb>> {
    match ladder_geometry(pd, md, declared_limbs)? {
        LadderGeometry::Zero => Some(Vec::new()),
        // No Montgomery form. The prepared parameters cannot be used here; the
        // two Montgomery entry points refuse this case before dispatch.
        LadderGeometry::VariableTime => mod_exp_core(ad, pd, md),
        LadderGeometry::Fixed(width) => {
            // The protected buffer: its allocation is the declared public width,
            // so its capacity cannot encode the exponent's normalised length.
            let exponent = fixed_width_exponent(pd, width)?;
            let window = Some(select_window_bits(width, md.len()));
            match prepared {
                Some(params) => mod_exp_core_consttime_prepared(ad, &exponent, md, width, params),
                None => mod_exp_core_consttime_staged(ad, &exponent, md, width, window),
            }
        }
    }
}

/// The ladder with `R^2`, `R` and `n0` recomputed from the modulus.
///
/// `exponent.len() == width`, and `width` is public. Splitting this from
/// [`mod_exp_core_consttime_width`] is what lets the C entry points stage the
/// exponent before the `64 * width` loop begins.
fn mod_exp_core_consttime_staged(
    ad: &[Limb],
    exponent: &SecretLimbs,
    md: &[Limb],
    width: usize,
    window: Option<u32>,
) -> Option<Vec<Limb>> {
    let n = md.len();
    let n0 = mont_n0(md[0]);
    // `R` and `R^2` derive from the modulus. Their limb count is public, but the
    // modulus contents are not automatically public: RSA CRT precomputation runs
    // on the secret primes (T6). They are computed from `n` (the public limb
    // count) by fixed-pattern doubling — `R = 2^(64n)`, `R^2 = 2^(128n)` — so no
    // division or value-dependent loop touches the modulus contents. `R` is then
    // one Montgomery multiply away (`R^2 * R^-1`), so only one conversion exists.
    let ri = n.checked_mul(64)?;
    let rr = SecretBuf::from_vec(limbs::pow2_mod_consttime(ri.checked_mul(2)?, md)?);
    let mut one_plain = try_zeroed_limbs(n)?;
    one_plain[0] = 1;
    let one_mont = SecretBuf::from_vec(mont_mul_fallible(&rr, &one_plain, md, n0)?);
    run_mont_ladder(ad, exponent, md, width, n0, &rr, one_mont, window)
}

/// Resolve the constant-time ladder width for **one** exponentiation, once.
///
/// `policy_limbs` is the key object's declared public bound (`0` = none),
/// `modulus_limbs` the modulus' public limb count, and `exponent_limbs` the
/// exponent's **normalised limb count**, captured once at ingestion by the key
/// object (PFP-39) — a length, not its value.
///
/// The formula is
///
/// ```text
/// (policy_limbs == 0 ? modulus_limbs : min(policy_limbs, modulus_limbs)).max(exponent_limbs)
/// ```
///
/// It reproduces the PFP-8 policy exactly whenever the exponent fits the policy
/// (`exponent_limbs <= policy_limbs <= modulus_limbs` gives `policy_limbs`, so
/// the in-policy schedule is computationally unchanged), keeps the clamp that a
/// policy wider than the modulus cannot exceed it, and otherwise **widens to
/// cover an out-of-policy key** so the answer is `g^x mod p` rather than a
/// refusal. The width is a length: it is declassified once here (PFP-43), never
/// a limb value.
pub(crate) fn resolve_ladder_width(
    policy_limbs: usize,
    modulus_limbs: usize,
    exponent_limbs: usize,
) -> usize {
    let base = if policy_limbs == 0 {
        modulus_limbs
    } else {
        policy_limbs.min(modulus_limbs)
    };
    base.max(exponent_limbs)
}

/// Constant-pattern exponentiation at an **explicitly resolved** ladder width.
///
/// `resolved_width` is produced once per operation by [`resolve_ladder_width`]
/// at the C entry point in `bn::mont`, from the key object's declared public
/// bound and the exponent's normalised limb count, which the key object captured
/// once at ingestion (PFP-39). This function never derives a width from `pd`; it
/// only stages the exponent into a buffer of
/// `resolved_width` limbs — allocation and write count fixed by that width — and
/// runs the ladder for `64 * resolved_width` iterations. No iteration consults
/// the exponent's value or its normalised length.
///
/// The width is therefore a **length declassification** (PFP-43): it reflects
/// how many limbs the private key occupies, never what they contain. For a
/// conforming key (`pd.len() <= policy <= md.len()`) the width is exactly the
/// policy, so the PFP-8 in-policy schedule is unchanged. A caller-supplied key
/// wider than the policy — and, for a 2048-bit modulus, wider than the modulus
/// itself — widens the ladder to cover it; the result is never truncated. The
/// threat model and residual channel are recorded in
/// `evidence/performance-frontier/campaigns/PFP-43/BOUNDS.md`.
///
/// `resolved_width == 0` is the "no resolved width" sentinel and delegates to
/// the modulus-width entry point, exactly as the former `policy_limbs == 0` arm
/// did. [`resolve_ladder_width`] never returns 0 for a non-empty modulus.
///
/// `pd.len() > resolved_width` is a caller contract violation; it is refused
/// rather than truncated. The resolver makes it unreachable on every in-crate
/// path, so it is a defensive check, not this function's width decision.
pub(crate) fn mod_exp_core_consttime_policy(
    ad: &[Limb],
    pd: &[Limb],
    md: &[Limb],
    resolved_width: usize,
    prepared: Option<&PreparedMontParams<'_>>,
) -> Option<Vec<Limb>> {
    if resolved_width == 0 {
        // No resolved width: exactly the modulus-width entry point.
        return mod_exp_core_consttime_from_parts_prepared(ad, pd, md, md.len(), prepared);
    }
    // The same degenerate-modulus answers as `ladder_geometry`, whose comments
    // give the reasons: `x mod 1` is zero, and an even modulus has no
    // Montgomery form.
    if md.is_empty() {
        return None;
    }
    if md.len() == 1 && md[0] == 1 {
        return Some(Vec::new());
    }
    if limbs::is_even(md) {
        return mod_exp_core(ad, pd, md);
    }
    if pd.len() > resolved_width {
        return None;
    }
    let exponent = fixed_width_exponent(pd, resolved_width)?;
    match prepared {
        Some(params) => mod_exp_core_consttime_prepared(ad, &exponent, md, resolved_width, params),
        None => {
            let window = Some(select_window_bits(resolved_width, md.len()));
            mod_exp_core_consttime_staged(ad, &exponent, md, resolved_width, window)
        }
    }
}

/// The ladder reusing a prepared domain's `R`, `R^2` and `n0`.
///
/// The caller has checked that the prepared parameters belong to `md`; the only
/// per-call work on the modulus is the base reduction and the conversions the
/// ladder already performs. `acc` starts as a private copy of the prepared
/// `R mod m`, because the ladder mutates its accumulator.
fn mod_exp_core_consttime_prepared(
    ad: &[Limb],
    exponent: &SecretLimbs,
    md: &[Limb],
    width: usize,
    params: &PreparedMontParams<'_>,
) -> Option<Vec<Limb>> {
    let acc = pad_secret(params.one, md.len())?;
    let window = Some(select_window_bits(width, md.len()));
    run_mont_ladder(ad, exponent, md, width, params.n0, params.rr, acc, window)
}

/// The fixed-pattern Montgomery ladder, given its precomputed parameters.
///
/// `exponent.len() == width`, `width` is public, `rr` is `R^2 mod m` and `acc`
/// is a fresh buffer holding `R mod m`. Everything else is derived here.
#[allow(clippy::too_many_arguments)]
fn run_mont_ladder(
    ad: &[Limb],
    exponent: &SecretLimbs,
    md: &[Limb],
    width: usize,
    n0: Limb,
    rr: &[Limb],
    mut acc: SecretLimbs,
    window: Option<u32>,
) -> Option<Vec<Limb>> {
    let n = md.len();
    // Read the staged exponent through the borrowed secret view: a signature can
    // say "this is secret" without borrowing the owner and without implying any
    // ownership or cleansing claim.
    let exponent = SecretRef::new(exponent);
    let bits = width.checked_mul(64)?;
    #[cfg(test)]
    ladder_probe::record_ladder(bits);
    let t_len = n.checked_mul(2)?.checked_add(1)?;

    // Base reduction. The EC reaches this with a secret base: the nonce through
    // `ec_field_inverse_mod_ord` (`ecdsa_sign_setup`) and a field element through
    // `ossl_ec_GFp_mont_field_inv`. A division here would be variable-time and
    // leak the base, so it is folded into Montgomery form directly instead.
    // Zero-extended to `n` limbs the base is below `R = 2^(64n)`, and `rr < m`,
    // so `base * rr < R * m` is exactly REDC's precondition: the fixed-loop
    // `mont_mul_into` answers `base * R mod m` — the Montgomery form of
    // `base mod m` — with no division.
    //
    // Precondition relied on: `ad.len() <= n` (a public limb count), so
    // `base < R`. Both EC callers satisfy it (the nonce is below the order, a
    // field element below the field). A C caller passing a base of more than
    // `n` limbs — `base >= R`, which the authority's `BN_mod_exp_mont_consttime`
    // accepts — keeps the variable-time reduction; that input is outside the EC
    // secret domain, and the width dispatch is on public geometry.
    // The base is secret on the EC reach, so it is copied straight into protected
    // storage. In the wide case the remainder is adopted as soon as it is produced
    // (no fallible step intervenes), so the plain vector `rem_fallible` returns never
    // becomes an uncleansed temporary; `pad_secret` then writes it into a second
    // `SecretBuf` rather than taking a slice of the adopted one through an ordinary
    // `Vec` (T23).
    let base_plain = if ad.len() <= n {
        pad_secret(ad, n)?
    } else {
        let rem = SecretBuf::from_vec(limbs::rem_fallible(ad, md)?);
        pad_secret(&rem, n)?
    };
    // `base * R^2 * R^-1 == base * R`: convert into the Montgomery domain.
    let mut base = SecretBuf::from_vec(mont_mul_fallible(&base_plain, rr, md, n0)?);

    // One allocation per buffer, before the first iteration. An allocation failure
    // is the entry points' ordinary failure answer, not an abort.
    let mut product = try_zeroed_limbs(n)?;
    let mut squared = SecretBuf::try_zeroed(n)?;
    let mut t = SecretBuf::try_zeroed(t_len)?;
    let mut diff = SecretBuf::try_zeroed(n)?;
    let mut one = try_zeroed_limbs(n)?;
    one[0] = 1;

    // The fixed-window schedule, when admitted, replaces only the multiplication
    // half of the bit-at-a-time loop; the squarings, the base and accumulator
    // bound arguments, and the conversion out of Montgomery form are unchanged.
    // `None` runs the reference below.
    if let Some(w) = window {
        run_mont_ladder_window(
            &exponent,
            md,
            bits,
            n0,
            &base,
            &one,
            &mut acc,
            &mut product[..],
            &mut squared,
            &mut t,
            &mut diff,
            w,
        )?;
        return Some(product);
    }

    for i in 0..bits {
        // The index is public: `i >> 6 < width`, the exponent buffer's length.
        let bit = (exponent[i >> 6] >> (i & 63)) & 1;
        let mask = 0u64.wrapping_sub(bit);
        if !mont_mul_ladder_into(&acc, &base, &mut product, md, n0, &mut t, &mut diff) {
            return None;
        }
        for (slot, &taken) in acc.iter_mut().zip(product.iter()) {
            *slot = constant_time_select(mask as usize, taken as usize, *slot as usize) as Limb;
        }
        // Squared on the last iteration too: the pattern must not depend on the
        // exponent's value or on which iteration is last.
        let squared_ok = if LADDER_DEDICATED_SQUARING {
            mont_sqr_into(&base, &mut squared, md, n0, &mut t, &mut diff)
        } else {
            mont_mul_into(&base, &base, &mut squared, md, n0, &mut t, &mut diff)
        };
        if !squared_ok {
            return None;
        }
        core::mem::swap(&mut base, &mut squared);
    }

    if !mont_mul_ladder_into(&acc, &one, &mut product, md, n0, &mut t, &mut diff) {
        return None;
    }

    // The exponent and every secret-derived intermediate live in `SecretBuf`, so
    // the normal return, an early `?` return and an unwind all cleanse them in
    // `Drop` before the blocks are freed. `product` is the result and is returned;
    // the destination `store_consttime` moves that same allocation into the
    // caller's `BIGNUM`, whose release cleanses it, so it is not a disposable
    // intermediate. The two `one` buffers hold the public constant 1 and are
    // deliberately ordinary.
    Some(product)
}

/// The fixed-window constant-time exponentiation body.
///
/// Consumes the same precomputed parameters as [`run_mont_ladder`] and writes the
/// plain (non-Montgomery) result into `product`. `acc` and `scratch` alternate as
/// the running Montgomery residue and its destination, so the borrows are derived
/// from the owners rather than reasserted as raw slices.
///
/// ## Why the schedule is constant-time
///
/// * `entries = 2^w` and `windows = ceil(bits / w)` depend only on public geometry
///   (`w` is selected from public geometry by [`select_window_bits`] and fixed
///   for the call; `bits = 64 * width`).
/// * Every window performs exactly `w` squarings and one multiplication, including
///   the last window and including leading-zero windows.
/// * The digit is built from the staged exponent with shifts and masks — value
///   operations, no branch on a secret and no secret-dependent index.
/// * [`select_window_digit`] scans all `entries` rows and combines them under an
///   all-ones/all-zeros mask from `constant_time_eq_s`, so the *addresses* read
///   are public and only the value depends on the secret digit.
///
/// The table holds secret powers of the base and lives in a [`SecretBuf`]; it is
/// cleansed on every exit. The base, accumulator and conversion bounds are the
/// ones established for the bit-at-a-time ladder (module documentation): every
/// table entry is canonical in `[0, m)`, so each multiply's `a * b < m * R`
/// precondition still holds inductively.
#[allow(clippy::too_many_arguments)]
fn run_mont_ladder_window(
    exponent: &SecretRef<'_, Limb>,
    md: &[Limb],
    bits: usize,
    n0: Limb,
    base: &[Limb],
    one: &[Limb],
    acc: &mut SecretLimbs,
    product: &mut [Limb],
    scratch: &mut SecretLimbs,
    t: &mut SecretLimbs,
    diff: &mut SecretLimbs,
    w: u32,
) -> Option<()> {
    let n = md.len();
    let shift = usize::try_from(w).ok()?;
    // Fail closed on a degenerate window rather than index a one-entry table.
    let entries = 1usize.checked_shl(w)?;
    if shift < 1 || entries < 2 {
        return None;
    }
    let table_len = entries.checked_mul(n)?;
    let mut table = SecretBuf::try_zeroed(table_len)?;
    let mut selected = SecretBuf::try_zeroed(n)?;

    // table[0] = R mod m (the Montgomery one, `acc` on entry), table[1] = base,
    // and table[i] = table[i-1] * base. The loop bound is public geometry.
    table[..n].copy_from_slice(&acc[..n]);
    table[n..2 * n].copy_from_slice(base);
    for i in 2..entries {
        // Split the owner so the previous row is read while this row is written;
        // both slices are disjoint ranges of the same allocation.
        let (done, rest) = table.split_at_mut(i * n);
        let prev = &done[(i - 1) * n..i * n];
        let dst = &mut rest[..n];
        if !mont_mul_ladder_into(prev, base, dst, md, n0, &mut t[..], &mut diff[..]) {
            return None;
        }
    }

    let windows = bits.checked_add(shift - 1)?.checked_div(shift)?;
    acc.copy_from_slice(&table[..n]);

    for hi in (0..windows).rev() {
        // `window_start` and every bit position below are public: `hi`, `shift`,
        // `bits` and the exponent buffer's length are public geometry.
        let window_start = hi.checked_mul(shift)?;
        let mut digit = 0u64;
        for k in 0..shift {
            let bitpos = window_start.checked_add(k)?;
            let bit = if bitpos < bits {
                (exponent[bitpos >> 6] >> (bitpos & 63)) & 1
            } else {
                0
            };
            digit |= bit << k;
        }
        for _ in 0..shift {
            if !mont_mul_ladder_into(
                &acc[..],
                &acc[..],
                &mut scratch[..],
                md,
                n0,
                &mut t[..],
                &mut diff[..],
            ) {
                return None;
            }
            core::mem::swap(acc, scratch);
        }
        select_window_digit(&table[..], n, entries, digit, &mut selected[..]);
        if !mont_mul_ladder_into(
            &acc[..],
            &selected[..],
            &mut scratch[..],
            md,
            n0,
            &mut t[..],
            &mut diff[..],
        ) {
            return None;
        }
        core::mem::swap(acc, scratch);
    }

    // Convert out of Montgomery form: `acc * 1 * R^-1`.
    if !mont_mul_ladder_into(&acc[..], one, product, md, n0, &mut t[..], &mut diff[..]) {
        return None;
    }
    Some(())
}

/// `out = table[digit]` by a full masked scan of every row.
///
/// `j` and every limb index are loop counters over public table geometry; the only
/// secret input is `digit`, and it enters solely through the mask. `out` is
/// zeroed first so the OR accumulation is exact.
///
/// **The source shape is not the constant-time evidence.** Reading public
/// addresses and combining them with bitwise AND/OR is the intent, but this
/// project has observed the optimiser lower a comparison-derived mask or a
/// masked select into a branch (PFP-2's REDC borrow, PFP-31's ML-KEM rejection
/// mask). What was established for `digit` is artefact-level: at DSO
/// `842efa27` (rustc 1.98.1, x86-64, release) the binary branch audit found no
/// secret-derived transfer in `run_mont_ladder`, and ctgrind with the secret
/// exponent tainted reported 0 contexts. A source, toolchain or target change
/// invalidates that result and requires the audit to be re-run.
fn select_window_digit(table: &[Limb], n: usize, entries: usize, digit: u64, out: &mut [Limb]) {
    for slot in out.iter_mut() {
        *slot = 0;
    }
    for j in 0..entries {
        let mask = constant_time_eq_s(digit as usize, j) as Limb;
        let row = &table[j * n..j * n + n];
        for (slot, &v) in out.iter_mut().zip(row.iter()) {
            *slot |= v & mask;
        }
    }
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
        // SAFETY: `a` and `b` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its `parts` call, before `r` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, _) = parts(x);
        // SAFETY: as above for `b`.
        let y = unsafe { as_ref(b) };
        let (bd, _) = parts(y);
        // SAFETY: `r` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended, so an aliased `r` is not borrowed twice.
        c_int::from(store(unsafe { as_mut(r) }, limbs::gcd(&ad, &bd), false))
    })
}

/// `int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)`
///
/// # Safety
///
/// `a` and `b` must each be null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_are_coprime(
    a: *mut BigNum,
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
        // SAFETY: `a` and `p` are null-or-live per this function's `# Safety`
        // section. Each shared borrow ends at its `parts` call, before `inp` is
        // borrowed for the store.
        let x = unsafe { as_ref(a) };
        let (ad, an) = parts(x);
        // SAFETY: as above for `p`.
        let y = unsafe { as_ref(p) };
        let (pd, _) = parts(y);

        // `p` must be an odd prime. The authority rejects an even `p` — and `|p| == 1` —
        // before it does any work, with `p == 2` the single even value it handles; the
        // rejection is observable, so it is reproduced rather than folded into the
        // general non-residue answer.
        if pd.is_empty() || limbs::is_even(&pd) || (pd.len() == 1 && pd[0] == 1) {
            if pd.len() == 1 && pd[0] == 2 {
                // The only even prime: the root is `a`'s low bit.
                // SAFETY: `inp` is null-or-live per this function's `# Safety`
                // section; the shared reads above have ended.
                return finish_sqrt(unsafe { as_mut(inp) }, inp, limbs::rem(&ad, &pd));
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
        // SAFETY: `inp` is null-or-live per this function's `# Safety` section; the
        // shared reads above have ended.
        finish_sqrt(unsafe { as_mut(inp) }, inp, r)
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

#[cfg(test)]
mod tests {
    #[test]
    fn mod_add_reduced_ct_handles_carry_and_the_conditional_subtract() {
        // (a, b, m, expected) with every operand already reduced mod `m`.
        type Case<'a> = (&'a [u64], &'a [u64], &'a [u64], &'a [u64]);
        let cases: &[Case<'_>] = &[
            (&[3], &[4], &[5], &[2]),
            (&[4], &[4], &[5], &[3]),
            (&[0], &[0], &[5], &[0]),
            (&[2], &[2], &[4], &[0]), // sum equals the modulus
            (&[1], &[0], &[5], &[1]), // trivial identity
            (
                &[u64::MAX],
                &[u64::MAX],
                &[1, 1],
                &[u64::MAX - 2], // 2*(2^64-1) mod (2^64+1)
            ),
        ];

        for (a, b, m, want) in cases {
            let produced = mod_add_reduced_ct_limbs(a, b, m);
            assert!(produced.is_some(), "a small allocation must succeed");
            let Some(mut got) = produced else {
                return;
            };
            while got.last() == Some(&0) {
                got.pop();
            }
            let mut want_v = want.to_vec();
            while want_v.last() == Some(&0) {
                want_v.pop();
            }
            assert_eq!(
                &got[..],
                &want_v[..],
                "a={a:?} b={b:?} m={m:?} produced {got:?}"
            );
        }
    }

    #[test]
    fn mod_add_reduced_ct_refuses_when_an_operand_is_wider_than_the_modulus() {
        assert!(mod_add_reduced_ct_limbs(&[1, 2, 3], &[1], &[5, 6]).is_none());
        assert!(mod_add_reduced_ct_limbs(&[1], &[1], &[]).is_none());
    }

    /// One differential case for the wired signing sequence: reduce each operand
    /// into `[0, q)`, run [`mod_add_reduced_ct`], and compare with the generic
    /// `BN_mod_add` on the *unreduced* operands, which is what the signing path ran
    /// before the wiring. The two in-place forms are checked too, because the
    /// signing path writes `s` in place.
    fn assert_wired_add_matches_generic(
        a: *const BigNum,
        b: *const BigNum,
        q: *mut BigNum,
        label: &str,
    ) {
        // SAFETY: every object is created and released here; `a`, `b` and `q` are
        // live for the call because the calling test owns them.
        unsafe {
            let a_red = BN_new();
            let b_red = BN_new();
            let got = BN_new();
            let want = BN_new();
            assert!(!a_red.is_null() && !b_red.is_null());
            assert!(!got.is_null() && !want.is_null());
            assert_eq!(BN_nnmod(a_red, a, q, core::ptr::null_mut()), 1, "{label}");
            assert_eq!(BN_nnmod(b_red, b, q, core::ptr::null_mut()), 1, "{label}");
            assert!(BN_ucmp(a_red, q) < 0, "{label}: first reduction is below q");
            assert!(
                BN_ucmp(b_red, q) < 0,
                "{label}: second reduction is below q"
            );

            assert!(mod_add_reduced_ct(got, a_red, b_red, q), "{label}");
            assert_eq!(
                BN_mod_add(want, a, b, q, core::ptr::null_mut()),
                1,
                "{label}: the generic form accepts the operands"
            );
            assert_eq!(
                BN_ucmp(got, want),
                0,
                "{label}: the wired add disagrees with BN_mod_add"
            );
            assert!(BN_ucmp(got, q) < 0, "{label}: the result is below q");

            let in_place_a = copy_of(a_red);
            assert!(
                mod_add_reduced_ct(in_place_a, in_place_a, b_red, q),
                "{label}"
            );
            assert_same(in_place_a, want, "{label}: in-place r == a");
            let in_place_b = copy_of(b_red);
            assert!(
                mod_add_reduced_ct(in_place_b, a_red, in_place_b, q),
                "{label}"
            );
            assert_same(in_place_b, want, "{label}: in-place r == b");

            BN_free(a_red);
            BN_free(b_red);
            BN_free(got);
            BN_free(want);
            BN_free(in_place_a);
            BN_free(in_place_b);
        }
    }

    /// splitmix64, so the pseudo-random sweep is deterministic and needs no
    /// external dependency.
    fn next_limb(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// The wired sequence — reduce into `[0, q)`, then the fixed-pattern add — must
    /// agree exactly with the generic `BN_mod_add` on the unreduced operands, for
    /// the operand shapes the signing path can be handed, and every result must be
    /// below the order.
    ///
    /// Shapes sit at and around the order: `0`, `1`, `q-2`, `q-1`, `q`, `q+1`,
    /// `2q-1`, `2^256` (one bit longer than the 256-bit order), `q + 2^256`, and
    /// five- and six-limb values (wider than the order's four limbs). The sweep
    /// then covers 256 deterministic pseudo-random pairs of widths `0..=6` limbs.
    #[test]
    fn mod_add_reduced_ct_matches_bn_mod_add_over_boundary_shapes() {
        // P-256's order, big-endian:
        // FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551.
        const Q: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];

        // SAFETY: every object is created, used and released in this function.
        unsafe {
            let q = BN_bin2bn(Q.as_ptr(), Q.len() as c_int, core::ptr::null_mut());
            assert!(!q.is_null());

            let zero = word(0);
            let one = word(1);
            let two = word(2);
            let q_minus_1 = BN_new();
            let q_minus_2 = BN_new();
            let q_plus_1 = BN_new();
            let twice_q_minus_1 = BN_new();
            assert!(!q_minus_1.is_null() && !q_minus_2.is_null());
            assert!(!q_plus_1.is_null() && !twice_q_minus_1.is_null());
            assert_eq!(BN_sub(q_minus_1, q, one), 1);
            assert_eq!(BN_sub(q_minus_2, q, two), 1);
            assert_eq!(BN_add(q_plus_1, q, one), 1);
            assert_eq!(BN_add(twice_q_minus_1, q, q_minus_1), 1);

            let bit_256 = new_owned(vec![0, 0, 0, 0, 1], 0);
            let q_plus_bit_256 = BN_new();
            assert!(!q_plus_bit_256.is_null());
            assert_eq!(BN_add(q_plus_bit_256, q, bit_256), 1);
            let five_limbs = new_owned(vec![0x0123_4567_89ab_cdef, 0, 0, 0, 0x00ff_00ff], 0);
            let six_limbs = new_owned(vec![1, 2, 3, 4, 5, 6], 0);

            let shapes = [
                zero,
                one,
                q_minus_2,
                q_minus_1,
                q,
                q_plus_1,
                twice_q_minus_1,
                bit_256,
                q_plus_bit_256,
                five_limbs,
                six_limbs,
            ];
            for (ai, &a) in shapes.iter().enumerate() {
                for (bi, &b) in shapes.iter().enumerate() {
                    assert_wired_add_matches_generic(a, b, q, &format!("shapes {ai}/{bi}"));
                }
            }

            let mut state: u64 = 0x1234_5678_9abc_def0;
            for case in 0..256usize {
                let alen = (next_limb(&mut state) % 7) as usize;
                let blen = (next_limb(&mut state) % 7) as usize;
                let al: Vec<Limb> = (0..alen).map(|_| next_limb(&mut state)).collect();
                let bl: Vec<Limb> = (0..blen).map(|_| next_limb(&mut state)).collect();
                let a = new_owned(al, 0);
                let b = new_owned(bl, 0);
                assert_wired_add_matches_generic(a, b, q, &format!("sweep {case}"));
                BN_free(a);
                BN_free(b);
            }

            // `q` is one of the shapes, so this releases every object exactly once.
            for shape in shapes {
                BN_free(shape);
            }
        }
    }

    use super::*;
    use crate::bn::bignum::{
        BN_bin2bn, BN_copy, BN_free, BN_get_word, BN_new, BN_set_flags, BN_set_word,
    };

    /// A `BIGNUM` holding a machine word.
    fn word(w: c_ulong) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let b = unsafe { BN_new() };
        // SAFETY: `b` is live.
        assert_eq!(unsafe { BN_set_word(b, w) }, 1);
        b
    }

    /// Copy an object so an aliased-output call does not destroy the input used by
    /// the distinct-output reference computation.
    fn copy_of(src: *const BigNum) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let dst = unsafe { BN_new() };
        // SAFETY: `dst` is live and `src` is live for the duration of the call.
        assert!(!unsafe { BN_copy(dst, src) }.is_null());
        dst
    }

    /// Compare an aliased output with the distinct-output reference.
    fn assert_same(aliased: *const BigNum, reference: *const BigNum, what: &str) {
        // SAFETY: both objects are live.
        assert_eq!(unsafe { BN_ucmp(aliased, reference) }, 0, "{what}");
    }

    /// T23: the ladder's base preparation writes a secret remainder into protected
    /// storage instead of an ordinary `Vec` temporary.
    ///
    /// A base wider than the modulus takes the remainder arm of
    /// [`mod_exp_core_consttime_staged`]. The remainder is adopted as a
    /// [`SecretBuf`] the moment it exists and padded directly into a second
    /// protected buffer, so when the padding operation's owner goes out of scope
    /// its storage is zeroised before release. The drop probe reads the live
    /// allocation from inside `Drop`, after the wipe and before the free.
    #[test]
    fn a_secret_base_remainder_is_padded_into_cleansed_storage() {
        use crate::bn::secret::drop_probe;

        let md = vec![
            0xffff_ffff_ffff_ffc5u64,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
        ];
        let ad = vec![
            0x0123_4567_89ab_cdefu64,
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
            0x0fed_cba9_8765_4321,
        ];
        let n = md.len();
        assert!(ad.len() > n, "the base must take the remainder arm");

        let rem = SecretBuf::from_vec(match limbs::rem_fallible(&ad, &md) {
            Some(rem) => rem,
            None => unreachable!("the remainder allocation succeeds"),
        });
        assert!(
            rem.iter().any(|&limb| limb != 0),
            "the test needs a non-zero secret remainder"
        );
        let padded = match pad_secret(&rem, n) {
            Some(padded) => padded,
            None => unreachable!("the protected padding allocation succeeds"),
        };
        assert_eq!(&padded[..], &rem[..n], "the remainder is padded unchanged");

        let ptr = padded.as_ptr();
        drop_probe::arm(ptr);
        drop(padded);

        let observed = match drop_probe::take() {
            Some(observed) => observed,
            None => unreachable!("Drop observed the armed allocation"),
        };
        assert_eq!(observed.ptr, ptr as usize, "Drop observed the padded base");
        assert_eq!(
            observed.nonzero_bytes, 0,
            "the padded secret base was released uncleansed"
        );
    }

    /// One object used for both `BN_div` outputs must stay defined: the two output
    /// borrows are taken in turn rather than simultaneously, and the remainder is
    /// stored first so the quotient is what remains in the shared object.
    #[test]
    fn div_accepts_one_object_for_both_outputs() {
        // SAFETY: `BN_new` has no preconditions.
        let a = unsafe { BN_new() };
        // SAFETY: as above.
        let b = unsafe { BN_new() };
        // SAFETY: as above.
        let out = unsafe { BN_new() };
        assert!(!a.is_null() && !b.is_null() && !out.is_null());
        // SAFETY: the three objects are live and this test owns them.
        unsafe {
            assert_eq!(BN_set_word(a, 17), 1);
            assert_eq!(BN_set_word(b, 5), 1);
            assert_eq!(BN_div(out, out, a, b, core::ptr::null_mut()), 1);
            assert_eq!(BN_get_word(out), 3, "the quotient is stored last");
            BN_free(a);
            BN_free(b);
            BN_free(out);
        }
    }

    /// T28: a `BN_div` whose operands carry `BN_FLG_CONSTTIME` takes the
    /// fixed-pattern division.
    ///
    /// The dispatch is asserted through the entry counter, because two correct
    /// divisions of the same operands produce the same answer and value comparison
    /// alone cannot distinguish the arms. The values are then checked twice: against
    /// the variable-time arm, and against the division identity `q*b + r == a`,
    /// `r < b`, which does not restate either implementation.
    #[test]
    fn div_honours_the_consttime_flag() {
        type Case = (Vec<Limb>, Vec<Limb>);
        let cases: &[Case] = &[
            (vec![u64::MAX, u64::MAX], vec![0, 1]),
            (vec![1, 0x8000_0000_0000_0000], vec![u64::MAX]),
            (vec![1], vec![u64::MAX, u64::MAX]),
            (
                vec![0x0123_4567_89ab_cdef, 0x1122_3344_5566_7788, 0x99aa_bbcc],
                vec![0x0fed_cba9_8765_4321, 0x0000_0000_0000_0001],
            ),
            (vec![3], vec![3]),
            (vec![4], vec![3]),
        ];
        let entries = crate::bn::limbs::ct_div_entries;

        for (ad, bd) in cases {
            // SAFETY: every `new_owned` below answers a fresh live object, and each
            // object is freed exactly once before the iteration ends.
            unsafe {
                let a = new_owned(ad.clone(), 0);
                let flagged = new_owned(bd.clone(), 0);
                let plain = new_owned(bd.clone(), 0);
                BN_set_flags(flagged, BN_FLG_CONSTTIME);
                let q_ct = BN_new();
                let r_ct = BN_new();
                let q_vt = BN_new();
                let r_vt = BN_new();
                let prod = BN_new();
                let sum = BN_new();
                assert!(
                    !a.is_null()
                        && !flagged.is_null()
                        && !plain.is_null()
                        && !q_ct.is_null()
                        && !r_ct.is_null()
                        && !q_vt.is_null()
                        && !r_vt.is_null()
                        && !prod.is_null()
                        && !sum.is_null()
                );

                let before = entries();
                assert_eq!(BN_div(q_ct, r_ct, a, flagged, core::ptr::null_mut()), 1);
                assert!(
                    entries() > before,
                    "a flagged divisor must reach the constant-pattern division"
                );

                let before = entries();
                assert_eq!(BN_div(q_vt, r_vt, a, plain, core::ptr::null_mut()), 1);
                assert_eq!(
                    entries(),
                    before,
                    "an unflagged call must keep the variable-time division"
                );

                assert_eq!(BN_ucmp(q_ct, q_vt), 0, "quotient differs: {ad:?}/{bd:?}");
                assert_eq!(BN_ucmp(r_ct, r_vt), 0, "remainder differs: {ad:?}/{bd:?}");
                assert_eq!(BN_mul(prod, q_ct, plain, core::ptr::null_mut()), 1);
                assert_eq!(BN_add(sum, prod, r_ct), 1);
                assert_eq!(BN_ucmp(sum, a), 0, "q*b+r != a for {ad:?}/{bd:?}");
                assert_eq!(BN_ucmp(r_ct, plain), -1, "r >= b for {ad:?}/{bd:?}");

                // The flag on the dividend is the dispatch's other arm.
                let flagged_a = new_owned(ad.clone(), 0);
                BN_set_flags(flagged_a, BN_FLG_CONSTTIME);
                let before = entries();
                assert_eq!(
                    BN_div(q_ct, r_ct, flagged_a, plain, core::ptr::null_mut()),
                    1
                );
                assert!(
                    entries() > before,
                    "a flagged dividend must reach the constant-pattern division"
                );
                assert_eq!(BN_ucmp(q_ct, q_vt), 0);

                for p in [
                    a, flagged, plain, flagged_a, q_ct, r_ct, q_vt, r_vt, prod, sum,
                ] {
                    BN_free(p);
                }
            }
        }
    }

    /// The M18-D1 regression control for this file (B13). Every entry point that
    /// formed `as_mut(r)` and `as_ref(input)` in one tuple computes a
    /// distinct-output reference and then the same call with the output aliasing a
    /// supported input. Before the repair those calls created overlapping borrows.
    ///
    /// The alias set is the one stated in this file's `Aliasing` section: the
    /// authority's documented/source-visible cases, plus the implementation-defined
    /// `BN_mod_exp r == m` and `BN_mod_sqrt in == p`, pinned so a future edit cannot
    /// silently change them.
    #[test]
    fn aliased_outputs_match_the_distinct_form() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        let a = word(17);
        let b = word(5);
        let m = word(11);
        let p = word(4);
        let base = word(3);
        let sqrt_a = word(2);
        let sqrt_p = word(7);

        // SAFETY: every object above is live; each call satisfies its `# Safety`
        // section, and each aliased object is live and uniquely owned by this test.
        unsafe {
            // BN_add, BN_sub, BN_uadd and BN_usub: r == a and r == b.
            let two_input: [(
                unsafe extern "C" fn(*mut BigNum, *const BigNum, *const BigNum) -> c_int,
                &str,
            ); 4] = [
                (BN_add, "add"),
                (BN_sub, "sub"),
                (BN_uadd, "uadd"),
                (BN_usub, "usub"),
            ];
            for (f, name) in two_input {
                let reference = BN_new();
                assert_eq!(f(reference, a, b), 1);
                for alias_first in [true, false] {
                    let x = if alias_first { copy_of(a) } else { copy_of(b) };
                    assert_eq!(
                        if alias_first { f(x, x, b) } else { f(x, a, x) },
                        1,
                        "{name}: aliased call failed"
                    );
                    assert_same(x, reference, name);
                    BN_free(x);
                }
                BN_free(reference);
            }

            // BN_mul takes an unused context: r == a and r == b.
            let product = BN_new();
            assert_eq!(BN_mul(product, a, b, NULL), 1);
            for alias_first in [true, false] {
                let x = if alias_first { copy_of(a) } else { copy_of(b) };
                assert_eq!(
                    if alias_first {
                        BN_mul(x, x, b, NULL)
                    } else {
                        BN_mul(x, a, x, NULL)
                    },
                    1
                );
                assert_same(x, product, "mul");
                BN_free(x);
            }
            BN_free(product);

            // BN_sqr: r == a.
            let square = BN_new();
            assert_eq!(BN_sqr(square, a, NULL), 1);
            let alias_square = copy_of(a);
            assert_eq!(BN_sqr(alias_square, alias_square, NULL), 1);
            assert_same(alias_square, square, "sqr");
            BN_free(alias_square);
            BN_free(square);

            // BN_nnmod: r == a; r == m is the authority's rejection case.
            let reduced = BN_new();
            assert_eq!(BN_nnmod(reduced, a, m, NULL), 1);
            let alias_reduced = copy_of(a);
            assert_eq!(BN_nnmod(alias_reduced, alias_reduced, m, NULL), 1);
            assert_same(alias_reduced, reduced, "nnmod r == a");
            BN_free(alias_reduced);
            let alias_modulus = copy_of(m);
            assert_eq!(
                BN_nnmod(alias_modulus, a, alias_modulus, NULL),
                0,
                "nnmod rejects r == m"
            );
            BN_free(alias_modulus);
            BN_free(reduced);

            // BN_mod_inverse: r == a and r == n (defined here; see the module doc).
            let inverse = BN_mod_inverse(core::ptr::null_mut(), a, m, NULL);
            assert!(!inverse.is_null());
            let alias_inverse_a = copy_of(a);
            assert_eq!(
                BN_mod_inverse(alias_inverse_a, alias_inverse_a, m, NULL),
                alias_inverse_a
            );
            assert_same(alias_inverse_a, inverse, "mod_inverse r == a");
            BN_free(alias_inverse_a);
            let alias_inverse_n = copy_of(m);
            assert_eq!(
                BN_mod_inverse(alias_inverse_n, a, alias_inverse_n, NULL),
                alias_inverse_n
            );
            assert_same(alias_inverse_n, inverse, "mod_inverse r == n");
            BN_free(alias_inverse_n);
            BN_free(inverse);

            // BN_lshift and BN_rshift: r == a.
            let shifted = BN_new();
            assert_eq!(BN_lshift(shifted, a, 2), 1);
            let alias_lshift = copy_of(a);
            assert_eq!(BN_lshift(alias_lshift, alias_lshift, 2), 1);
            assert_same(alias_lshift, shifted, "lshift");
            BN_free(alias_lshift);
            BN_free(shifted);

            let shifted = BN_new();
            assert_eq!(BN_rshift(shifted, a, 2), 1);
            let alias_rshift = copy_of(a);
            assert_eq!(BN_rshift(alias_rshift, alias_rshift, 2), 1);
            assert_same(alias_rshift, shifted, "rshift");
            BN_free(alias_rshift);
            BN_free(shifted);

            // BN_exp: r == a and r == p.
            let power = BN_new();
            assert_eq!(BN_exp(power, base, p, NULL), 1);
            let alias_exp_a = copy_of(base);
            assert_eq!(BN_exp(alias_exp_a, alias_exp_a, p, NULL), 1);
            assert_same(alias_exp_a, power, "exp r == a");
            BN_free(alias_exp_a);
            let alias_exp_p = copy_of(p);
            assert_eq!(BN_exp(alias_exp_p, base, alias_exp_p, NULL), 1);
            assert_same(alias_exp_p, power, "exp r == p");
            BN_free(alias_exp_p);
            BN_free(power);

            // BN_mod_exp: r == a, r == p, and (implementation-defined) r == m.
            let residue = BN_new();
            assert_eq!(BN_mod_exp(residue, base, p, m, NULL), 1);
            let alias_modexp_a = copy_of(base);
            assert_eq!(BN_mod_exp(alias_modexp_a, alias_modexp_a, p, m, NULL), 1);
            assert_same(alias_modexp_a, residue, "mod_exp r == a");
            BN_free(alias_modexp_a);
            let alias_modexp_p = copy_of(p);
            assert_eq!(BN_mod_exp(alias_modexp_p, base, alias_modexp_p, m, NULL), 1);
            assert_same(alias_modexp_p, residue, "mod_exp r == p");
            BN_free(alias_modexp_p);
            let alias_modexp_m = copy_of(m);
            assert_eq!(BN_mod_exp(alias_modexp_m, base, p, alias_modexp_m, NULL), 1);
            assert_same(alias_modexp_m, residue, "mod_exp r == m");
            BN_free(alias_modexp_m);
            BN_free(residue);

            // BN_gcd: r == a and r == b.
            let gcd = BN_new();
            assert_eq!(BN_gcd(gcd, a, b, NULL), 1);
            for alias_first in [true, false] {
                let x = if alias_first { copy_of(a) } else { copy_of(b) };
                assert_eq!(
                    if alias_first {
                        BN_gcd(x, x, b, NULL)
                    } else {
                        BN_gcd(x, a, x, NULL)
                    },
                    1
                );
                assert_same(x, gcd, "gcd");
                BN_free(x);
            }
            BN_free(gcd);

            // BN_mod_sqrt: in == a and (implementation-defined) in == p.
            let root = BN_mod_sqrt(core::ptr::null_mut(), sqrt_a, sqrt_p, NULL);
            assert!(!root.is_null(), "2 is a quadratic residue modulo 7");
            let alias_sqrt_a = copy_of(sqrt_a);
            assert_eq!(
                BN_mod_sqrt(alias_sqrt_a, alias_sqrt_a, sqrt_p, NULL),
                alias_sqrt_a
            );
            assert_same(alias_sqrt_a, root, "mod_sqrt in == a");
            BN_free(alias_sqrt_a);
            let alias_sqrt_p = copy_of(sqrt_p);
            assert_eq!(
                BN_mod_sqrt(alias_sqrt_p, sqrt_a, alias_sqrt_p, NULL),
                alias_sqrt_p
            );
            assert_same(alias_sqrt_p, root, "mod_sqrt in == p");
            BN_free(alias_sqrt_p);
            BN_free(root);

            for x in [a, b, m, p, base, sqrt_a, sqrt_p] {
                BN_free(x);
            }
        }
    }

    /// The constant-pattern ladder must be a value-for-value substitution for the
    /// variable-time ladder on every shape it accepts: exponent zero and modulus
    /// one (the special cases), one-limb and multi-limb moduli and exponents, an
    /// even modulus (where the constant-time function falls back and must still
    /// agree), and bases at and above the modulus. An exponent wider than the
    /// public modulus width is the one shape it *refuses*, and that refusal is
    /// asserted here rather than allowed to become a truncation.
    #[test]
    fn the_constant_time_ladder_matches_the_variable_time_ladder() {
        let moduli: Vec<Vec<Limb>> = vec![
            vec![1],
            vec![2],
            vec![3],
            vec![0xffff_ffff_ffff_ffff],
            vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211],
        ];
        let exponents: Vec<Vec<Limb>> = vec![
            Vec::new(),
            vec![1],
            vec![2],
            vec![0xffff_ffff_ffff_ffff],
            vec![0x8000_0000_0000_0001, 0x0000_0000_0000_0002],
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            seed
        };
        let bases: Vec<Vec<Limb>> = vec![
            Vec::new(),
            vec![1],
            vec![2],
            vec![next()],
            vec![next(), next()],
            vec![0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff],
        ];
        for m in &moduli {
            let constant_time = !m.is_empty() && !(m.len() == 1 && m[0] == 1) && !limbs::is_even(m);
            for e in &exponents {
                for a in &bases {
                    let expected = mod_exp_core(a, e, m);
                    let got = mod_exp_core_consttime(a, e, m);
                    if constant_time && e.len() > m.len().max(1) {
                        assert!(
                            got.is_none(),
                            "an exponent wider than the public width is refused, not truncated: \
                             a={a:?} e={e:?} m={m:?}"
                        );
                        continue;
                    }
                    assert!(
                        expected.is_some() && got.is_some(),
                        "a nonzero modulus always answers"
                    );
                    if let (Some(expected), Some(mut got)) = (expected, got) {
                        limbs::normalise(&mut got);
                        assert_eq!(got, expected, "a={a:?} e={e:?} m={m:?}");
                    }
                }
            }
        }
    }

    /// A deterministic odd modulus of exactly `bits` bits (a non-zero top limb),
    /// the Montgomery admission shape.
    fn pfp5_modulus(bits: usize, seed: u64) -> Vec<u64> {
        let n = bits / 64;
        let mut state = seed | 1;
        let mut m: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
        m[0] |= 1;
        m[n - 1] |= 1u64 << 63;
        m
    }

    /// The exponent classes the differential requires: zero, one, two, a small
    /// one-limb value, a full-width pseudorandom value and all-ones.
    fn pfp5_exponents(bits: usize) -> Vec<Vec<u64>> {
        let n = bits / 64;
        let mut state = 0xa5a5_5a5a_1234_5678u64 ^ bits as u64;
        let rand: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
        vec![
            Vec::new(),
            vec![1],
            vec![2],
            vec![0x0123_4567_89ab_cdef],
            rand,
            vec![u64::MAX; n],
        ]
    }

    /// The base classes: `0`, `1`, `2`, `m-1` and a pseudorandom residue.
    fn pfp5_bases(m: &[u64]) -> Vec<Vec<u64>> {
        let n = m.len();
        let mut state = 0x5eed_0000_0000_0000u64 ^ (n as u64);
        let raw: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
        let Some(r) = limbs::rem_fallible(&raw, m) else {
            unreachable!("a remainder succeeds")
        };
        vec![
            pfp6_pad(&[], n),
            pfp6_pad(&[1], n),
            pfp6_pad(&[2], n),
            limbs::sub(m, &[1]),
            pfp6_pad(&r, n),
        ]
    }

    fn pfp5_answer(a: &[u64], e: &[u64], m: &[u64], window: Option<u32>) -> Option<Vec<u64>> {
        mod_exp_core_consttime_width_with(a, e, m, m.len(), window).map(|mut v| {
            limbs::normalise(&mut v);
            v
        })
    }

    /// PFP8-WIDTH-POLICY: the policy-width ladder must answer exactly what the
    /// modulus-width ladder answers, for every policy from zero limbs to one
    /// beyond the modulus. Policies narrower than the exponent exercise the
    /// documented fallback; a policy larger than the modulus is clamped.
    #[test]
    fn policy_width_matches_the_modulus_width_ladder() {
        let mut cases = 0usize;
        for m in pfp6_moduli() {
            if m.len() > 4 || limbs::is_even(&m) {
                continue;
            }
            let bits = m.len() * 64;
            for e in pfp5_exponents(bits) {
                for a in pfp6_operands(&m) {
                    let reference = pfp5_answer(&a, &e, &m, Some(5));
                    for policy in 0..=m.len() + 1 {
                        let width = resolve_ladder_width(policy, m.len(), e.len());
                        let got =
                            mod_exp_core_consttime_policy(&a, &e, &m, width, None).map(|mut v| {
                                limbs::normalise(&mut v);
                                v
                            });
                        assert_eq!(
                            got, reference,
                            "policy {policy} disagrees with the modulus width: \
                             a={a:?} e={e:?} m={m:?}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert!(cases >= 1000, "the population is not degenerate: {cases}");
    }

    /// PFP-43 **supersedes** `policy_width_never_truncates_and_refuses_wider_than_the_modulus`.
    ///
    /// The former contract refused an exponent wider than the policy fallback
    /// (`md.len()`), which made `DH_generate_key` answer 0 for a caller-supplied
    /// 2400-bit key against a 2048-bit modulus while the authority returned
    /// `g^x mod p`. The width is now **resolved to cover the exponent** (once, at
    /// the C entry point) and the ladder is never truncated. The two obligations
    /// the old test carried are kept: the in-policy path is exactly the policy,
    /// and a widened path equals the independent ladders.
    #[test]
    fn policy_width_widens_to_cover_the_exponent_and_never_truncates() {
        let m = pfp5_modulus(256, 0x5eed_1234);
        let a = pfp6_pad(&[2], m.len());
        // In-policy: `width == policy` exactly, and the answer is the reference.
        let e = pfp6_pad(&[0xdead_beef, 0xfeed_face, 1, 7], m.len());
        let reference = pfp5_answer(&a, &e, &m, Some(5));
        let mut in_policy_cases = 0usize;
        for policy in 1..=m.len() {
            if e.len() > policy {
                continue;
            }
            let width = resolve_ladder_width(policy, m.len(), e.len());
            assert_eq!(width, policy, "an in-policy width must be the policy");
            let got = mod_exp_core_consttime_policy(&a, &e, &m, width, None).map(|mut v| {
                limbs::normalise(&mut v);
                v
            });
            assert_eq!(
                got, reference,
                "policy {policy} disagrees with the modulus width"
            );
            in_policy_cases += 1;
        }
        assert!(in_policy_cases >= 1);

        // Out of policy *and* wider than the modulus: accepted at a covering width.
        let wide = pfp6_pad(&[1, 2, 3, 4, 5], m.len() + 1);
        assert!(wide.len() > m.len());
        let width = resolve_ladder_width(4, m.len(), wide.len());
        assert_eq!(width, wide.len());
        let Some(mut expected) = mod_exp_core_consttime_width(&a, &wide, &m, wide.len()) else {
            unreachable!("the declared-width ladder answers a covering width")
        };
        limbs::normalise(&mut expected);
        let got = mod_exp_core_consttime_policy(&a, &wide, &m, width, None).map(|mut v| {
            limbs::normalise(&mut v);
            v
        });
        assert_eq!(
            got,
            Some(expected),
            "an exponent wider than the modulus is not refused"
        );

        // The high limbs are used, not dropped: the same base with the top limb
        // removed answers a different value.
        let truncation = mod_exp_core_consttime_policy(
            &a,
            &wide[..m.len()],
            &m,
            resolve_ladder_width(4, m.len(), m.len()),
            None,
        )
        .map(|mut v| {
            limbs::normalise(&mut v);
            v
        });
        assert_ne!(got, truncation, "the exponent must not be truncated");

        // A width that does not cover the exponent is a contract violation and is
        // refused, never silently used to truncate.
        assert!(mod_exp_core_consttime_policy(&a, &wide, &m, m.len(), None).is_none());
    }

    /// The ffdhe2048 prime (`OSSL_BIGNUM_FFDHE2048_P_BYTES`, big-endian) as limbs.
    fn pfp43_ffdhe2048_p() -> Vec<Limb> {
        let bytes = crate::bn::dh_data::OSSL_BIGNUM_FFDHE2048_P_BYTES;
        let mut limbs = vec![0 as Limb; bytes.len().div_ceil(8)];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 8] |= (byte as Limb) << (8 * (i % 8));
        }
        limbs
    }

    /// PFP-43: a 2400-bit exponent against the 2048-bit ffdhe2048 modulus answers
    /// the same value as two independent in-crate ladders and as the authority's
    /// `pow(g, x, p)`. The exponent is `"ab" * 300`; the expected residue below
    /// was computed independently with
    /// `python3 -c 'pow(2, int("ab"*300,16), int(<ffdhe2048 p>,16))'` and is
    /// stored little-endian, lowest limb first.
    #[test]
    fn pfp43_widened_ladder_matches_independent_paths_and_the_authority_constant() {
        let m = pfp43_ffdhe2048_p();
        assert_eq!(m.len(), 32, "ffdhe2048 is 2048 bits");
        let a: Vec<Limb> = vec![2];
        // 2400 bits of 0xab: 37 full limbs then a half limb, 38 limbs total.
        let mut e: Vec<Limb> = vec![0xabab_abab_abab_abab; 37];
        e.push(0xabab_abab);
        assert_eq!(e.len(), 38);
        // ffdhe2048's declared key length is 225 bits => 4 limbs.
        let width = resolve_ladder_width(4, m.len(), e.len());
        assert_eq!(width, 38);

        let Some(mut got) = mod_exp_core_consttime_policy(&a, &e, &m, width, None) else {
            unreachable!("the widened ladder answers")
        };
        limbs::normalise(&mut got);

        // Independent in-crate path 1: the variable-time ladder.
        let Some(mut oracle) = mod_exp_core(&a, &e, &m) else {
            unreachable!("a nonzero modulus answers")
        };
        limbs::normalise(&mut oracle);
        assert_eq!(got, oracle, "widened policy path != variable-time oracle");

        // Independent in-crate path 2: the declared-width ladder.
        let Some(mut declared) = mod_exp_core_consttime_width(&a, &e, &m, e.len()) else {
            unreachable!("the declared-width ladder answers a covering width")
        };
        limbs::normalise(&mut declared);
        assert_eq!(
            got, declared,
            "widened policy path != declared-width ladder"
        );

        // `pow(2, int("ab"*300, 16), ffdhe2048_p)`, little-endian limbs.
        let expected: [Limb; 32] = [
            0x9f26_3779_fc85_e662,
            0xffdb_90ba_1c1e_9ace,
            0x2bec_f1d3_1e28_26d8,
            0xc07b_1e9c_1861_6b3e,
            0xce2b_0219_b363_cfbc,
            0x80af_ad5b_5928_41cc,
            0xc931_8ee7_48c5_424c,
            0x4ae5_eafd_5344_0a04,
            0x3eed_d858_4f16_a7ec,
            0x6c8c_79db_dcfd_be01,
            0xcab1_0f1a_8ff7_c6da,
            0x46f7_c29d_7ba3_b97d,
            0x6750_07b0_4bc6_e6e0,
            0x0115_6989_0282_d1a2,
            0x5138_d0b3_f3cb_0ea5,
            0x1ccd_cbf7_28d4_5a4b,
            0x0309_84a1_c594_ae8c,
            0x3ce3_c451_2d9b_79ab,
            0x79e7_31eb_cb50_c329,
            0x8491_630f_1862_0a30,
            0xf8e8_4632_8414_f28e,
            0xe197_a27b_bcc2_4421,
            0xc571_b227_5230_2a57,
            0x0143_563a_5a1e_340d,
            0x8118_6734_76ac_c736,
            0x05b6_1837_6b88_5a6f,
            0xd665_bc6f_388f_85e6,
            0x2b38_2123_f40d_282f,
            0x9db2_10df_d045_e713,
            0xe576_f648_4550_a310,
            0xcc8f_8e84_77e0_3b11,
            0x55ed_b9a4_c08f_e9e7,
        ];
        assert_eq!(got, expected, "widened path != pow(g, x, p)");
    }

    /// PFP-43 size boundaries: an exponent of exactly `64 * md.len()` bits, one
    /// bit wider, and a 4096-bit exponent against the 2048-bit modulus all answer
    /// what the variable-time ladder answers; none is refused.
    #[test]
    fn pfp43_widened_ladder_covers_the_size_boundaries() {
        let m = pfp43_ffdhe2048_p();
        let a: Vec<Limb> = vec![2];
        let mut exact = vec![0 as Limb; 32];
        exact[0] = 1;
        exact[31] = 0x8000_0000_0000_0000;
        let mut plus_one = vec![0 as Limb; 33];
        plus_one[0] = 1;
        plus_one[32] = 1;
        let wide4096 = vec![Limb::MAX; 64];
        for (name, e) in [
            ("2048 bits == 64 * md.len()", exact),
            ("2049 bits (+1)", plus_one),
            ("4096 bits", wide4096),
        ] {
            let width = resolve_ladder_width(4, m.len(), e.len());
            assert!(width >= e.len(), "{name}: width must cover the exponent");
            let Some(mut got) = mod_exp_core_consttime_policy(&a, &e, &m, width, None) else {
                unreachable!("{name}: the widened ladder answers")
            };
            limbs::normalise(&mut got);
            let Some(mut oracle) = mod_exp_core(&a, &e, &m) else {
                unreachable!("{name}: a nonzero modulus answers")
            };
            limbs::normalise(&mut oracle);
            assert_eq!(
                got, oracle,
                "{name} disagrees with the variable-time ladder"
            );
        }
    }

    /// PFP-5: the fixed-window ladder must be value-for-value identical to the
    /// bit-at-a-time reference and to the variable-time oracle, for every window
    /// width, over edge and pseudorandom bases and exponents.
    ///
    /// Scope: moduli up to 256 bits here; the larger widths are in
    /// `pfp5_window_matches_on_large_moduli` and, at 8192 bits, in the
    /// authority-bound DSO differential (a debug-profile 8192-bit ladder costs
    /// minutes per case, so it is not in the routine suite).
    #[test]
    fn pfp5_window_matches_the_bit_at_a_time_ladder() {
        let mut cases = 0usize;
        for m in pfp6_moduli() {
            if m.len() > 4 || limbs::is_even(&m) {
                continue;
            }
            let bits = m.len() * 64;
            for e in pfp5_exponents(bits) {
                for a in pfp6_operands(&m) {
                    let oracle = mod_exp_core(&a, &e, &m).map(|mut v| {
                        limbs::normalise(&mut v);
                        v
                    });
                    let reference = pfp5_answer(&a, &e, &m, None);
                    assert_eq!(
                        reference, oracle,
                        "reference disagrees with oracle: a={a:?} e={e:?} m={m:?}"
                    );
                    for w in [Some(4u32), Some(5), Some(6), Some(7), Some(8)] {
                        let got = pfp5_answer(&a, &e, &m, w);
                        assert_eq!(
                            got, reference,
                            "window {w:?} disagrees with the bit-at-a-time ladder: a={a:?} e={e:?} m={m:?}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert!(
            cases >= 1000,
            "the population is unexpectedly small: {cases}"
        );
        eprintln!("pfp5 window-vs-reference comparisons: {cases} (moduli <= 256 bits)");
    }

    /// PFP-5 large-moduli differential: 1024, 2048 and 3072 bit odd moduli, full
    /// width and edge exponents, against the bit-at-a-time ladder. Every window
    /// digit and every window boundary is exercised. A single mismatch fails.
    #[test]
    fn pfp5_window_matches_on_large_moduli() {
        let mut cases = 0usize;
        for (bits, seed, keep) in [
            (
                1024usize,
                0x1024_0000_0000_0001u64,
                &[0usize, 1, 2, 3, 4, 5][..],
            ),
            (2048, 0x2048_0000_0000_0001, &[0usize, 3, 4, 5][..]),
            (3072, 0x3072_0000_0000_0001, &[1usize, 4, 5][..]),
        ] {
            let m = pfp5_modulus(bits, seed);
            let all = pfp5_exponents(bits);
            let bs = pfp5_bases(&m);
            for &idx in keep {
                let e = &all[idx];
                for a in &bs {
                    let reference = pfp5_answer(a, e, &m, None);
                    let got = pfp5_answer(a, e, &m, Some(5));
                    assert_eq!(
                        got, reference,
                        "window disagrees at {bits} bits: a={a:?} e={e:?}"
                    );
                    // PFP-42: the geometry-selected width must also match. At the
                    // modulus-width entry point `width = m.len()`, so the selector
                    // sees `(m.len(), m.len())`; 3072 bits selects w=6 here.
                    let selected = select_window_bits(m.len(), m.len());
                    let got_selected = pfp5_answer(a, e, &m, Some(selected));
                    assert_eq!(
                        got_selected, reference,
                        "selected w={selected} disagrees at {bits} bits: a={a:?} e={e:?}"
                    );
                    cases += 1;
                }
            }
        }
        assert!(
            cases >= 60,
            "the large-moduli population is unexpectedly small: {cases}"
        );
        assert!(
            cases >= 40,
            "the large-moduli population is unexpectedly small: {cases}"
        );
        eprintln!("pfp5 large-moduli window-vs-reference comparisons: {cases}");
    }

    /// PFP-42: the window selector is a function of **public geometry only**, and
    /// its chosen widths reproduce the campaign's cost-model minima.
    ///
    /// The two DH-policy rows are the composition this item re-evaluates: the
    /// ladder runs at the group's RFC 7919 key width (256 bits = 4 limbs for
    /// ffdhe2048, 320 bits = 5 limbs for ffdhe3072) against a 32/48-limb modulus,
    /// which is why a 16-entry table is no longer negligible there. The three
    /// modexp rows run the ladder at the modulus width. The out-of-policy rows are
    /// the PFP-43 covering widths: a *length* declassification, never a value.
    #[test]
    fn pfp42_window_selection_follows_public_geometry() {
        for (width, modulus, expected) in [
            (4usize, 32usize, 4u32), // ffdhe2048 policy: 256-bit ladder, 2048-bit modulus
            (5, 48, 4),              // ffdhe3072 policy: 320-bit ladder, 3072-bit modulus
            (16, 16, 5),             // modexp-1024
            (32, 32, 5),             // modexp-2048
            (128, 128, 7),           // modexp-8192
        ] {
            assert_eq!(
                select_window_bits(width, modulus),
                expected,
                "geometry width_limbs={width} modulus_limbs={modulus}"
            );
        }
        // PFP-43 out-of-policy covering widths (2400-bit and 4096-bit exponents
        // against a 2048-bit modulus) are public *lengths* and select w=6.
        assert_eq!(select_window_bits(38, 32), 6);
        assert_eq!(select_window_bits(64, 32), 6);
        // A degenerate geometry keeps the admitted default rather than indexing a
        // zero-width schedule.
        assert_eq!(select_window_bits(0, 32), LADDER_WINDOW_BITS.unwrap_or(5));
        assert_eq!(select_window_bits(4, 0), LADDER_WINDOW_BITS.unwrap_or(5));
    }

    /// ctgrind taint case for the secret-base reduction.
    ///
    /// This is the arithmetic of `ec_field_inverse_mod_ord`, which
    /// `ecdsa_sign_setup` reaches with the secret nonce: the P-256 order is the
    /// modulus and `order - 2` the public Fermat exponent, with a
    /// signing-sized value as the base. The base's limbs are marked undefined
    /// with valgrind's client request, so memcheck reports any conditional jump
    /// or secret-derived address inside the fixed-pattern ladder and its
    /// initial base fold. Without valgrind the request is a harmless no-op, so
    /// the same test also runs in the ordinary suite.
    ///
    /// Coverage: the ladder core and the base fold. Not covered: the C-ABI
    /// `parts()` copy, the `ec_field_inverse_mod_ord` wrapper, `BN_CTX`
    /// allocation, and the public exponent's own timing.
    ///
    /// Gate: `valgrind --tool=memcheck --error-exitcode=99 <test-bin> --exact
    /// bn::arith::tests::ctgrind_secret_base_fold_and_ladder --nocapture`.
    /// `CTGRIND_CONTROL=1` adds a deliberate branch on a marked limb, which
    /// memcheck must report (negative control).
    #[test]
    fn ctgrind_secret_base_fold_and_ladder() {
        let order = vec![
            0xf3b9_cac2_fc63_2551u64,
            0xbce6_faad_a717_9e84,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_0000_0000,
        ];
        let mut exponent = order.clone();
        exponent[0] -= 2; // order - 2, public

        let mut base = vec![
            0x0123_4567_89ab_cdefu64,
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
            0x0fed_cba9_8765_4321,
        ];

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: `base` is a live, uniquely borrowed buffer and the
            // client-request sequence only marks its bytes' definedness.
            unsafe {
                valgrind_make_mem_undefined(base.as_mut_ptr().cast::<u8>(), base.len() * 8);
            }
            if std::env::var_os("CTGRIND_CONTROL").is_some() {
                // Negative control: memcheck must flag this branch on a
                // marked limb.
                let mut acc = 0u64;
                for &limb in &base {
                    if limb & 1 == 1 {
                        acc = acc.wrapping_add(1);
                    }
                }
                core::hint::black_box(acc);
            }
        }

        let Some(staged) = pad_to(&exponent, order.len()).map(SecretBuf::from_vec) else {
            unreachable!("the exponent fits the public width")
        };
        let out = mod_exp_core_consttime_from_parts(&base, &staged, &order, order.len());
        // Only the `Option` discriminant is inspected: the value itself is
        // secret-derived and must never be branched on.
        assert!(out.is_some(), "a nonzero modulus always answers");
    }

    /// `BN_mod_inverse`'s constant-time dispatch keeps the authority's documented
    /// aliases, and the explicit entry point refuses an even modulus instead of
    /// silently taking the variable-time path.
    #[test]
    fn the_consttime_inverse_supports_aliases_and_refuses_even_moduli() {
        let a = vec![0x0123_4567_89ab_cdefu64, 0x0f0f_0f0f_0f0f_0f0fu64];
        let m = vec![0xffff_ffff_ffff_ffc5u64, 0xffff_ffff_ffff_ffff];
        let even = vec![0xffff_ffff_ffff_ffc4u64, 0xffff_ffff_ffff_ffff];
        // SAFETY: every object is a fresh object this test owns.
        unsafe {
            let reference = BN_new();
            // `d` is little-endian: `d[0]` is the low limb.
            let mk = |d: &[u64]| {
                let dst = BN_new();
                assert_eq!(BN_set_word(dst, d[1]), 1);
                assert_eq!(BN_lshift(dst, dst, 64), 1);
                let lo = BN_new();
                assert_eq!(BN_set_word(lo, d[0]), 1);
                assert_eq!(BN_add(dst, dst, lo), 1);
                BN_free(lo);
                dst
            };
            let ma = mk(&a);
            let mm = mk(&m);
            let me = mk(&even);

            assert_eq!(
                BN_mod_inverse(reference, ma, mm, core::ptr::null_mut()),
                reference
            );

            let alias_a = mk(&a);
            BN_set_flags(alias_a, BN_FLG_CONSTTIME);
            assert_eq!(
                BN_mod_inverse(alias_a, alias_a, mm, core::ptr::null_mut()),
                alias_a
            );
            assert_same(alias_a, reference, "consttime mod_inverse r == a");

            let alias_n = mk(&m);
            BN_set_flags(alias_n, BN_FLG_CONSTTIME);
            assert_eq!(
                BN_mod_inverse(alias_n, ma, alias_n, core::ptr::null_mut()),
                alias_n
            );
            assert_same(alias_n, reference, "consttime mod_inverse r == n");

            // The explicit entry point is for odd moduli only and fails closed.
            let refused = BN_new();
            assert!(
                BN_mod_inverse_consttime(refused, ma, me).is_null(),
                "an even modulus is outside the constant-time domain"
            );

            BN_free(refused);
            BN_free(alias_a);
            BN_free(alias_n);
            BN_free(ma);
            BN_free(mm);
            BN_free(me);
            BN_free(reference);
        }
    }

    /// ctgrind case for the secret inversion path.
    ///
    /// An odd RSA-shaped composite modulus is used, with a secret base marked
    /// undefined through valgrind's client request. The algorithm's loop count is
    /// fixed by limb counts and every value test is a mask select, so memcheck must
    /// report no conditional jump inside `mod_inverse_consttime_with_mask`. The
    /// returned coefficient and gcd mask are marked **defined** before the
    /// assertions, so the case covers the algorithm, not the caller's authorised
    /// no-inverse decision. `CTGRIND_CONTROL=1` branches on a marked limb as the
    /// negative control.
    #[test]
    fn ctgrind_secret_mod_inverse() {
        // Two 128-bit odd factors; their product is an odd 256-bit composite, the
        // shape of an RSA modulus.
        let p = vec![0xffff_ffff_ffff_ff61u64, 0xffff_ffff_ffff_ffff];
        let q = vec![0xffff_ffff_ffff_ff53u64, 0xffff_ffff_ffff_ffff];
        let m = limbs::mul(&p, &q);
        let mut a = vec![
            0x0123_4567_89ab_cdefu64,
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
            0x0fed_cba9_8765_4321,
        ];
        while limbs::gcd(&a, &m) != vec![1u64] {
            a[0] = a[0].wrapping_add(2);
        }
        let a_plain = a.clone();

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: `a` is a live, uniquely borrowed buffer and the
            // client-request sequence only marks its bytes' definedness.
            unsafe {
                valgrind_make_mem_undefined(a.as_mut_ptr().cast::<u8>(), a.len() * 8);
            }
            if std::env::var_os("CTGRIND_CONTROL").is_some() {
                // Negative control: memcheck must flag this branch on a marked
                // limb.
                let mut acc = 0u64;
                for &limb in &a {
                    if limb & 1 == 1 {
                        acc = acc.wrapping_add(1);
                    }
                }
                core::hint::black_box(acc);
            }
        }

        let Some((mut inverse, mut invertible)) = limbs::mod_inverse_consttime_with_mask(&a, &m)
        else {
            unreachable!("the test modulus is odd")
        };
        #[cfg(target_arch = "x86_64")]
        {
            // Declassify only for the assertions below.
            // SAFETY: both are live, uniquely borrowed locals.
            unsafe {
                valgrind_make_mem_defined(inverse.as_mut_ptr().cast::<u8>(), inverse.len() * 8);
                valgrind_make_mem_defined((&mut invertible as *mut u64).cast::<u8>(), 8);
            }
        }
        assert_ne!(invertible, 0, "the test value is coprime with the modulus");
        assert_eq!(
            limbs::rem(&limbs::mul(&a_plain, &inverse), &m),
            vec![1u64],
            "a * a^-1 == 1"
        );
    }

    /// PFP-5 ctgrind case for the **fixed-window** ladder: the exponent is secret
    /// and every value derived from it — the window digit, the scanned table row,
    /// the accumulator — is secret too.
    ///
    /// Only the exponent's limb bytes are marked undefined; its length stays
    /// defined, so the documented staging bounds test is not part of this case.
    /// Memcheck must report no conditional jump and no secret-derived address
    /// inside `run_mont_ladder_window` or `select_window_digit`.
    ///
    /// Gate: `valgrind --tool=memcheck --error-exitcode=99 <test-bin> --exact
    /// bn::arith::tests::ctgrind_secret_exponent_window --nocapture`.
    /// `CTGRIND_CONTROL=1` branches on a marked exponent limb (negative control).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ctgrind_secret_exponent_window() {
        let mut m = vec![
            0xffff_ffff_ffff_ff61u64,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3211,
            0x9e37_79b9_7f4a_7c15,
        ];
        m[0] |= 1;
        let a = vec![0x0f0f_0f0f_0f0f_0f0f, 0, 0, 0];
        let e_defined = vec![
            0x1234_5678_9abc_def1u64,
            0xfedc_ba98_7654_3210,
            0x0f0f_0f0f_0f0f_0f0f,
            0x7fff_ffff_ffff_ffff,
        ];
        let expected = mod_exp_core_consttime_width_with(&a, &e_defined, &m, m.len(), Some(5));
        assert!(expected.is_some());

        let mut e = e_defined.clone();
        // SAFETY: `e` is a live, uniquely borrowed buffer and the client request
        // only marks its bytes' definedness.
        unsafe {
            valgrind_make_mem_undefined(e.as_mut_ptr().cast::<u8>(), e.len() * 8);
        }
        if std::env::var_os("CTGRIND_CONTROL").is_some() {
            // Negative control: memcheck must flag this branch on a marked limb.
            let mut acc = 0u64;
            for &limb in &e {
                if limb & 1 == 1 {
                    acc = acc.wrapping_add(1);
                }
            }
            core::hint::black_box(acc);
        }

        let mut got = mod_exp_core_consttime_width_with(&a, &e, &m, m.len(), Some(5));
        if let Some(v) = got.as_mut() {
            // Declassify only for the assertion below.
            // SAFETY: `v` is a live, uniquely borrowed local.
            unsafe {
                valgrind_make_mem_defined(v.as_mut_ptr().cast::<u8>(), v.len() * 8);
            }
        }
        assert_eq!(got, expected);
    }

    /// PFP8-WIDTH-POLICY ctgrind case: the **shortened** schedule. The modulus is
    /// eight limbs and the policy four, so the ladder runs 256 iterations rather
    /// than 512. The exponent's limb bytes are marked undefined and its length
    /// stays defined, so the documented staging bounds test is not part of this
    /// case. Memcheck must report no conditional jump and no secret-derived
    /// address: the iteration count and every table index are the public policy,
    /// and only limb values depend on the exponent.
    ///
    /// Gate: `valgrind --tool=memcheck --error-exitcode=99 <test-bin> --exact
    /// bn::arith::tests::ctgrind_secret_exponent_policy_width --nocapture`.
    /// `CTGRIND_POLICY_CONTROL=1` branches on a marked exponent limb (negative
    /// control).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ctgrind_secret_exponent_policy_width() {
        let mut m = vec![
            0xffff_ffff_ffff_ff61u64,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3211,
            0x9e37_79b9_7f4a_7c15,
            0x1111_2222_3333_4445,
            0x5555_6666_7777_8889,
            0x9999_aaaa_bbbb_cccd,
            0xdddd_eeee_ffff_0001,
        ];
        m[0] |= 1;
        let a = vec![0x0f0f_0f0f_0f0f_0f0f, 0, 0, 0, 0, 0, 0, 0];
        let e_defined = vec![
            0x1234_5678_9abc_def1u64,
            0xfedc_ba98_7654_3210,
            0x0f0f_0f0f_0f0f_0f0f,
            0x7fff_ffff_ffff_ffff,
        ];
        let expected = mod_exp_core_consttime_policy(&a, &e_defined, &m, 4, None);
        assert!(expected.is_some());

        let mut e = e_defined.clone();
        // SAFETY: `e` is a live, uniquely borrowed buffer and the client request
        // only marks its bytes' definedness.
        unsafe {
            valgrind_make_mem_undefined(e.as_mut_ptr().cast::<u8>(), e.len() * 8);
        }
        if std::env::var_os("CTGRIND_POLICY_CONTROL").is_some() {
            // Negative control: memcheck must flag this branch on a marked limb.
            let mut acc = 0u64;
            for &limb in &e {
                if limb & 1 == 1 {
                    acc = acc.wrapping_add(1);
                }
            }
            core::hint::black_box(acc);
        }

        let mut got = mod_exp_core_consttime_policy(&a, &e, &m, 4, None);
        if let Some(v) = got.as_mut() {
            // Declassify only for the assertion below.
            // SAFETY: `v` is a live, uniquely borrowed local.
            unsafe {
                valgrind_make_mem_defined(v.as_mut_ptr().cast::<u8>(), v.len() * 8);
            }
        }
        assert_eq!(got, expected);
    }

    /// `VALGRIND_MAKE_MEM_UNDEFINED` as the amd64 client request.
    ///
    /// The instruction sequence is `valgrind.h`'s
    /// `__SPECIAL_INSTRUCTION_PREAMBLE` followed by `xchgq rbx, rbx`; valgrind
    /// replaces it during translation and reads the request word and arguments
    /// from the array `rax` points at. Outside valgrind it is a few harmless
    /// register rotations.
    #[cfg(target_arch = "x86_64")]
    unsafe fn valgrind_make_mem_undefined(addr: *mut u8, len: usize) {
        let args: [usize; 6] = [0x4D43_0001, addr as usize, len, 0, 0, 0];
        let _result: usize;
        // SAFETY: the sequence is the documented valgrind client-request
        // pattern; `args` lives for the duration of the asm and is only read.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") args.as_ptr(),
                inout("rdx") 0usize => _result,
                out("rdi") _,
                options(nostack),
            );
        }
    }

    /// `VALGRIND_MAKE_MEM_DEFINED`, the counterpart used to declassify a result
    /// after the algorithm has run (request code `0x4D43_0002`).
    #[cfg(target_arch = "x86_64")]
    unsafe fn valgrind_make_mem_defined(addr: *mut u8, len: usize) {
        let args: [usize; 6] = [0x4D43_0002, addr as usize, len, 0, 0, 0];
        let _result: usize;
        // SAFETY: the sequence is the documented valgrind client-request
        // pattern; `args` lives for the duration of the asm and is only read.
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") args.as_ptr(),
                inout("rdx") 0usize => _result,
                out("rdi") _,
                options(nostack),
            );
        }
    }

    /// A declared width is a *public* lower bound on the ladder. The width variant
    /// agrees with the variable-time ladder whenever the declaration covers the
    /// exponent, and refuses (never truncates) when it does not.
    #[test]
    fn a_declared_width_either_covers_the_exponent_or_refuses() {
        let m = vec![0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3211];
        let a = vec![0xdead_beef_0bad_f00du64, 0x0f0f_0f0f_0f0f_0f0fu64];
        let exponents: Vec<Vec<Limb>> = vec![
            Vec::new(),
            vec![1],
            vec![0x8000_0000_0000_0001],
            vec![0x8000_0000_0000_0001, 0x0000_0000_0000_0003],
            // Wider than the widest declaration below *and* the modulus: the
            // only case that must refuse.
            vec![1, 0, 0, 0, 1],
        ];
        for e in &exponents {
            let Some(expected) = mod_exp_core(&a, e, &m) else {
                unreachable!("a nonzero modulus answers")
            };
            for declared in 1..=4 {
                let got = mod_exp_core_consttime_width(&a, e, &m, declared);
                if e.len() > declared.max(m.len()) {
                    assert!(
                        got.is_none(),
                        "declared={declared} < e.len()={} must refuse",
                        e.len()
                    );
                    continue;
                }
                let Some(mut got) = got else {
                    unreachable!("a covered exponent answers")
                };
                limbs::normalise(&mut got);
                assert_eq!(got, expected, "e={e:?} declared={declared}");
            }
        }
    }

    /// T3: the protected exponent buffer's capacity is fixed by the declared
    /// **public** width, not by the input's normalised length. Two exponents of
    /// different lengths, staged under one width, must have identical capacity.
    ///
    /// This would fail if the buffer were built by adopting the input (a clone
    /// has capacity == its length, so the two would report 2 and 4): the
    /// destructor's cleanse extent would then encode the secret length.
    #[test]
    fn exponent_buffer_capacity_follows_the_public_width() {
        let width = 4;
        let short = vec![0x0123_4567_89ab_cdefu64, 0xfeed_face_dead_beefu64];
        let long = vec![
            0x0123_4567_89ab_cdefu64,
            0xfeed_face_dead_beefu64,
            0x0f0f_0f0f_0f0f_0f0fu64,
            0xdead_beef_dead_beefu64,
        ];
        assert_ne!(short.len(), long.len(), "the inputs must differ in length");

        let Some(short_view) = fixed_width_exponent(&short, width) else {
            unreachable!("a four-limb allocation succeeds")
        };
        let Some(long_view) = fixed_width_exponent(&long, width) else {
            unreachable!("a four-limb allocation succeeds")
        };

        assert_eq!(short_view.len(), width);
        assert_eq!(long_view.len(), width);
        assert_eq!(
            short_view.capacity(),
            long_view.capacity(),
            "capacity must come from the public width, not the input length"
        );
        assert_eq!(short_view.capacity(), width);
        // The secret limbs are still staged in the low positions.
        assert_eq!(&short_view[..short.len()], &short[..]);
        assert_eq!(&long_view[..], &long[..]);
    }

    /// T9 mutation control: the staging copy must write exactly the public
    /// width, whatever the input's normalised length. Two exponents of different
    /// lengths under one width must report the same write count (`width`).
    ///
    /// This is the fixture the batch asks for: a copy whose length follows the
    /// input length — `for i in 0..pd.len().min(width)`, or the old
    /// `min`+`copy_from_slice` body — makes the counts differ (2 and 4, or 0),
    /// so the test fails rather than silently reporting a public width it did not
    /// use.
    #[test]
    fn the_staging_copy_writes_the_public_width_not_the_input_length() {
        let width = 4;
        let short = vec![0x0123_4567_89ab_cdefu64, 0xfeed_face_dead_beefu64];
        let long = vec![
            0x0123_4567_89ab_cdefu64,
            0xfeed_face_dead_beefu64,
            0x0f0f_0f0f_0f0f_0f0fu64,
            0xdead_beef_dead_beefu64,
        ];
        assert_ne!(short.len(), long.len(), "the inputs must differ in length");

        let Some((short_view, short_written)) = stage_fixed_width_exponent(&short, width) else {
            unreachable!("a four-limb allocation succeeds")
        };
        let Some((long_view, long_written)) = stage_fixed_width_exponent(&long, width) else {
            unreachable!("a four-limb allocation succeeds")
        };

        assert_eq!(short_view.len(), width);
        assert_eq!(long_view.len(), width);
        assert_eq!(
            short_written, long_written,
            "the copy length must not follow the input length"
        );
        assert_eq!(short_written, width, "the copy must write the public width");
        // Absent limbs are zero, present limbs are staged unchanged.
        assert_eq!(&short_view[short.len()..], &[0u64; 2]);
        assert_eq!(&short_view[..short.len()], &short[..]);
        assert_eq!(&long_view[..], &long[..]);
    }

    /// Allocation failure is a return value on this path, not an abort: an
    /// impossible reservation answers `None`, which the entry points turn into
    /// their ordinary failure.
    #[test]
    fn try_zeroed_limbs_reports_an_impossible_size() {
        assert!(try_zeroed_limbs(usize::MAX / 2).is_none());
        let Some(v) = try_zeroed_limbs(3) else {
            unreachable!("a small allocation succeeds")
        };
        assert_eq!(v, vec![0, 0, 0]);
    }

    /// Fail every fallible allocation in the constant-pattern ladder in turn
    /// through the test allocation seam. Each failure must surface as `None`, and
    /// the ladder must succeed once the budget exceeds the number of seam-visible
    /// allocations.
    ///
    /// The seam intercepts `crate::bn::alloc`'s reservations only. It does not
    /// prove that no allocation exists elsewhere on the path (the C-ABI argument
    /// copies in `parts` are infallible `Vec::clone`s), and it does not model the
    /// allocator's own failure modes.
    #[test]
    fn a_failed_allocation_in_the_constant_time_ladder_returns_none() {
        let a = vec![0x0123_4567_89ab_cdefu64, 0x0f0f_0f0f_0f0f_0f0f];
        let e = vec![0x8000_0000_0000_0001u64, 0x0000_0000_0000_0002];
        let m = vec![0xffff_ffff_ffff_ffc5u64, 0x0123_4567_89ab_cdef];
        assert!(!limbs::is_even(&m));

        let Some(mut expected) = mod_exp_core(&a, &e, &m) else {
            unreachable!("a nonzero modulus answers")
        };
        limbs::normalise(&mut expected);

        let Some(mut baseline) = mod_exp_core_consttime(&a, &e, &m) else {
            unreachable!("the ladder answers")
        };
        limbs::normalise(&mut baseline);
        assert_eq!(baseline, expected);

        let mut intercepted = None;
        for successes in 0..64 {
            let _guard = crate::bn::alloc::test_fail::fail_after(successes);
            if mod_exp_core_consttime(&a, &e, &m).is_some() {
                intercepted = Some(successes);
                break;
            }
        }
        let allocations = match intercepted {
            Some(n) => n,
            None => unreachable!("the ladder must eventually stop failing"),
        };
        assert!(
            allocations > 0,
            "the seam must intercept at least one allocation"
        );
    }

    /// The C entry point turns a failed ladder allocation into its ordinary `0`
    /// return rather than aborting. The seam fails the first reservation, which
    /// is the fixed-width exponent buffer allocated before the ladder.
    #[test]
    fn a_failed_allocation_at_the_montgomery_entry_point_returns_zero() {
        let a = word(3);
        let p = word(5);
        let m = word(7);
        let r = word(0);
        {
            let _guard = crate::bn::alloc::test_fail::fail_after(0);
            assert_eq!(
                unsafe {
                    // SAFETY: every object is live and uniquely owned by this test.
                    crate::bn::mont::BN_mod_exp_mont_consttime(
                        r,
                        a,
                        p,
                        m,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                    )
                },
                0,
                "allocation failure must be reported, not abort"
            );
        }
        assert_eq!(
            unsafe {
                // SAFETY: as above; the seam is disarmed and the same call now succeeds.
                crate::bn::mont::BN_mod_exp_mont_consttime(
                    r,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            1
        );
        // SAFETY: the objects are live and owned here.
        unsafe {
            BN_free(a);
            BN_free(p);
            BN_free(m);
            BN_free(r);
        }
    }

    /// Sweep **every** seam-visible allocation on the constant-time modular
    /// exponentiation path: each failure must be the entry point's documented `0`,
    /// and the operation must succeed once the budget exceeds the path's
    /// allocation count.
    #[test]
    fn every_allocation_failure_in_constant_time_modexp_returns_zero() {
        let a = word(3);
        let p = word(0x8000_0000_0000_0001);
        let m = word(0xffff_ffff_ffff_ffc5);
        let r = word(0);
        let allocations = crate::bn::alloc::test_fail::sweep_sites(|| unsafe {
            // SAFETY: every object is live and uniquely owned by this test.
            crate::bn::mont::BN_mod_exp_mont_consttime(
                r,
                a,
                p,
                m,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ) == 1
        });
        assert!(
            allocations > 0,
            "the seam must see the ladder's allocations"
        );
        eprintln!("T22 sites: modexp={allocations}");
        // The seam is disarmed; the same call still succeeds.
        assert_eq!(
            // SAFETY: the BIGNUM objects are live and exclusively owned here,
            // and the allocation seam has been disarmed.
            unsafe {
                crate::bn::mont::BN_mod_exp_mont_consttime(
                    r,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            },
            1
        );
        // SAFETY: the objects are live and owned here.
        unsafe {
            BN_free(a);
            BN_free(p);
            BN_free(m);
            BN_free(r);
        }
    }

    /// Sweep every seam-visible allocation in the fixed-iteration constant-time
    /// inversion: each failure must answer `NULL` rather than aborting.
    #[test]
    fn every_allocation_failure_in_the_consttime_inverse_returns_null() {
        let a = word(0x0123_4567_89ab_cdef);
        let n = word(0xffff_ffff_ffff_ffc5);
        let r = word(0);
        let allocations = crate::bn::alloc::test_fail::sweep_sites(|| unsafe {
            // SAFETY: every object is live and uniquely owned by this test.
            !BN_mod_inverse_consttime(r, a, n).is_null()
        });
        assert!(allocations > 0, "the seam must see the inverse's scratch");
        eprintln!("T22 sites: consttime_inverse={allocations}");
        assert_eq!(
            // SAFETY: the BIGNUM objects are live and exclusively owned here,
            // and the allocation seam has been disarmed.
            unsafe { BN_mod_inverse_consttime(r, a, n) },
            r,
            "the same call succeeds once the seam is disarmed"
        );
        // SAFETY: the objects are live and owned here.
        unsafe {
            BN_free(a);
            BN_free(n);
            BN_free(r);
        }
    }

    // ------------------------------------------------------------------
    // PFP-6: independent differential courts for the Montgomery schedules.
    //
    // The reference is the SOS schedule (`mont_mul_fallible`). CIOS and the
    // dedicated squaring kernel must agree with it bit for bit. These are
    // comparisons *between kernels*; the REDC congruence itself is checked
    // against `limbs::{mul, rem}` in `bn::mont::etp4_verification`.
    // ------------------------------------------------------------------

    fn pfp6_xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn pfp6_pad(v: &[u64], n: usize) -> Vec<u64> {
        let mut out = vec![0u64; n];
        let take = v.len().min(n);
        out[..take].copy_from_slice(&v[..take]);
        out
    }

    /// Odd moduli with a non-zero top limb, the Montgomery admission shape,
    /// spanning one to eight limbs and including P-256's prime.
    fn pfp6_moduli() -> Vec<Vec<u64>> {
        vec![
            vec![3],
            vec![0xffff_ffff_ffff_ffff],
            vec![0x8000_0000_0000_0001],
            vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211],
            // b^3 + 1: minimal top-limb occupancy.
            vec![1, 0, 0, 1],
            vec![u64::MAX; 4],
            // P-256 p = 2^256 - 2^224 + 2^192 + 2^96 - 1, little-endian.
            vec![
                0xffff_ffff_ffff_ffff,
                0x0000_0000_ffff_ffff,
                0,
                0xffff_ffff_0000_0001,
            ],
            // Eight limbs (512 bits), mixed occupancy.
            vec![
                0xffff_ffff_ffff_fffd,
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3211,
                0x0f0f_0f0f_0f0f_0f0f,
                0xdead_beef_dead_beef,
                0x1111_2222_3333_4445,
                0xaaaa_bbbb_cccc_dddd,
                0x9999_8888_7777_6667,
            ],
            // Sixteen limbs (1024 bits), mixed occupancy.
            vec![
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3211,
                0x0f0f_0f0f_0f0f_0f0f,
                0xdead_beef_dead_beef,
                0x1111_2222_3333_4445,
                0xaaaa_bbbb_cccc_dddd,
                0x9999_8888_7777_6667,
                0x1357_9bdf_2468_ace1,
                0xffff_ffff_ffff_ffff,
                0x8000_0000_0000_0000,
                0x7fff_ffff_ffff_ffff,
                0x0f0f_0f0f_0f0f_0f0f,
                0xf0f0_f0f0_f0f0_f0f0,
                0xdead_c0de_dead_c0de,
                0x0123_4567_89ab_cdef,
                0x8000_0000_0000_0001,
            ],
        ]
    }

    /// Edge and adversarial operands below the modulus: `0`, `1`, `m-1`,
    /// `m-2`, `m/2`, a one-limb value (minimal occupancy), a top-limb-only
    /// value, all-ones where it is below `m`, and a deterministic pseudo-random
    /// sweep reduced into `[0, m)`.
    fn pfp6_operands(m: &[u64]) -> Vec<Vec<u64>> {
        let n = m.len();
        let mut values: Vec<Vec<u64>> = Vec::new();
        let mut push = |v: Vec<u64>| {
            let p = pfp6_pad(&v, n);
            if limbs::cmp(&p, m) == core::cmp::Ordering::Less && !values.contains(&p) {
                values.push(p);
            }
        };
        push(Vec::new());
        push(vec![1]);
        push(vec![2]);
        push(limbs::sub(m, &[1]));
        push(limbs::sub(m, &[2]));
        push(limbs::div_rem_small(m, 2).0);
        push(vec![u64::MAX]);
        let mut top_only = vec![0u64; n];
        top_only[n - 1] = 1;
        push(top_only);
        push(vec![u64::MAX; n]);
        let mut state = {
            let mut s = 0x9e37_79b9_7f4a_7c15u64;
            for &l in m {
                s ^= l;
                s = s.wrapping_mul(0x100_0000_01b3);
            }
            s | 1
        };
        for _ in 0..24 {
            let raw: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
            let Some(reduced) = limbs::rem_fallible(&raw, m) else {
                unreachable!("a remainder succeeds")
            };
            push(reduced);
        }
        values
    }

    /// The defining Montgomery congruence for one kernel result:
    /// `out * R == a * b (mod m)` and `out < m`.
    fn pfp6_assert_congruent(out: &[u64], a: &[u64], b: &[u64], m: &[u64], kernel: &str) {
        assert_eq!(
            limbs::cmp(out, m),
            core::cmp::Ordering::Less,
            "{kernel} output is not canonical for m={m:?}, a={a:?}, b={b:?}"
        );
        let mut scaled = vec![0u64; m.len()];
        scaled.extend_from_slice(out); // out * R
        let product = limbs::mul(a, b);
        let mut lhs = limbs::rem(&scaled, m);
        let mut rhs = limbs::rem(&product, m);
        limbs::normalise(&mut lhs);
        limbs::normalise(&mut rhs);
        assert_eq!(
            lhs, rhs,
            "{kernel}: out * R != a * b (mod m) for m={m:?}, a={a:?}, b={b:?}"
        );
    }

    /// Every kernel is checked against the *defining congruence*, not only against
    /// the SOS reference: `out * R == a * b (mod m)` and `out < m`. SOS, CIOS and
    /// the dedicated squaring kernel therefore each have independent evidence; the
    /// `*_matches_the_reference` tests below add the bit-for-bit cross-check.
    #[test]
    fn pfp6_each_kernel_satisfies_the_congruence() {
        let mut sos_cases = 0usize;
        let mut cios_cases = 0usize;
        let mut sqr_cases = 0usize;
        for m in pfp6_moduli() {
            let n0 = mont_n0(m[0]);
            let values = pfp6_operands(&m);
            for a in &values {
                for b in &values {
                    let Some(sos) = mont_mul_fallible(a, b, &m, n0) else {
                        unreachable!("allocation succeeds")
                    };
                    pfp6_assert_congruent(&sos, a, b, &m, "SOS");
                    sos_cases += 1;
                    let Some(cios) = mont_mul_fallible_with(MontSchedule::Cios, a, b, &m, n0)
                    else {
                        unreachable!("allocation succeeds")
                    };
                    pfp6_assert_congruent(&cios, a, b, &m, "CIOS");
                    cios_cases += 1;
                }
            }
            for a in &values {
                let Some(sqr) = mont_sqr_fallible(a, &m, n0) else {
                    unreachable!("allocation succeeds")
                };
                pfp6_assert_congruent(&sqr, a, a, &m, "SQR");
                sqr_cases += 1;
            }
        }
        eprintln!(
            "PFP-6 kernel congruence: sos={sos_cases} cios={cios_cases} sqr={sqr_cases} mismatches=0"
        );
        assert!(sos_cases > 0 && cios_cases == sos_cases && sqr_cases > 0);
    }

    /// CIOS must equal the SOS reference over an exhaustive one-limb range and
    /// the sampled edge/adversarial populations at 64 to 1024 bits.
    #[test]
    fn pfp6_cios_matches_the_reference() {
        let mut exhaustive = 0usize;
        for m in [3u64, 5, 7, 9, 11, 13, 15, 17, 31, 33] {
            let n0 = mont_n0(m);
            for a in 0..m {
                for b in 0..m {
                    let Some(sos) = mont_mul_fallible(&[a], &[b], &[m], n0) else {
                        unreachable!("a one-limb allocation succeeds")
                    };
                    let Some(cios) =
                        mont_mul_fallible_with(MontSchedule::Cios, &[a], &[b], &[m], n0)
                    else {
                        unreachable!("a one-limb allocation succeeds")
                    };
                    assert_eq!(cios, sos, "CIOS != SOS at m={m}, a={a}, b={b}");
                    exhaustive += 1;
                }
            }
        }

        let mut sampled = 0usize;
        for m in pfp6_moduli() {
            assert!(m[0] & 1 == 1 && m.last().copied().unwrap_or(0) != 0);
            let n0 = mont_n0(m[0]);
            let values = pfp6_operands(&m);
            assert!(values.len() >= 3, "population too small for {m:?}");
            for a in &values {
                for b in &values {
                    let Some(sos) = mont_mul_fallible(a, b, &m, n0) else {
                        unreachable!("allocation succeeds")
                    };
                    let Some(cios) = mont_mul_fallible_with(MontSchedule::Cios, a, b, &m, n0)
                    else {
                        unreachable!("allocation succeeds")
                    };
                    assert_eq!(cios, sos, "CIOS != SOS at m={m:?}, a={a:?}, b={b:?}");
                    sampled += 1;
                }
            }
        }
        eprintln!(
            "PFP-6 CIOS differential: exhaustive={exhaustive} sampled={sampled} mismatches=0"
        );
        assert!(exhaustive > 0 && sampled > 0);
    }

    /// The dedicated squaring kernel must equal `a * a` through the reference.
    #[test]
    fn pfp6_dedicated_squaring_matches_the_reference() {
        let mut exhaustive = 0usize;
        for m in [3u64, 5, 7, 9, 11, 13, 15, 17, 31, 33] {
            let n0 = mont_n0(m);
            for a in 0..m {
                let Some(reference) = mont_mul_fallible(&[a], &[a], &[m], n0) else {
                    unreachable!("allocation succeeds")
                };
                let Some(squared) = mont_sqr_fallible(&[a], &[m], n0) else {
                    unreachable!("allocation succeeds")
                };
                assert_eq!(squared, reference, "SQR != SOS at m={m}, a={a}");
                exhaustive += 1;
            }
        }

        let mut sampled = 0usize;
        for m in pfp6_moduli() {
            let n0 = mont_n0(m[0]);
            for a in pfp6_operands(&m) {
                let Some(reference) = mont_mul_fallible(&a, &a, &m, n0) else {
                    unreachable!("allocation succeeds")
                };
                let Some(squared) = mont_sqr_fallible(&a, &m, n0) else {
                    unreachable!("allocation succeeds")
                };
                assert_eq!(squared, reference, "SQR != SOS at m={m:?}, a={a:?}");
                sampled += 1;
            }
        }
        eprintln!(
            "PFP-6 squaring differential: exhaustive={exhaustive} sampled={sampled} mismatches=0"
        );
        assert!(exhaustive > 0 && sampled > 0);
    }

    /// The width contract is an unconditional check, not a `debug_assert!`: an
    /// oversized operand is refused instead of truncated, an undersized
    /// accumulator is refused, and a refused call writes nothing. The refusal is
    /// an ordinary `if ... { return false }`, so it is compiled into every
    /// profile; this test exercises that behaviour.
    #[test]
    fn pfp6_geometry_fails_closed() {
        let m = [3u64];
        let n0 = mont_n0(3);
        let mut out = [0u64; 1];
        let mut t = [0u64; 3];
        let mut diff = [0u64; 1];

        assert!(!mont_mul_sos_into(
            &[1, 9],
            &[1],
            &mut out,
            &m,
            n0,
            &mut t,
            &mut diff
        ));
        assert!(!mont_mul_cios_into(
            &[1, 9],
            &[1],
            &mut out,
            &m,
            n0,
            &mut t,
            &mut diff
        ));
        assert!(!mont_sqr_into(&[1, 9], &mut out, &m, n0, &mut t, &mut diff));
        assert_eq!(out, [0], "a refused call must write nothing");

        let mut short_t = [0u64; 2];
        assert!(!mont_mul_sos_into(
            &[1],
            &[1],
            &mut out,
            &m,
            n0,
            &mut short_t,
            &mut diff
        ));
        assert!(!mont_mul_cios_into(
            &[1],
            &[1],
            &mut out,
            &m,
            n0,
            &mut short_t,
            &mut diff
        ));

        assert!(
            mont_mul_fallible_with(MontSchedule::Cios, &[1, 9], &[1], &m, n0).is_none(),
            "the allocating wrapper must propagate the refusal, not truncate"
        );

        assert!(mont_mul_cios_into(
            &[1],
            &[1],
            &mut out,
            &m,
            n0,
            &mut t,
            &mut diff
        ));
    }

    // ------------------------------------------------------------------
    // M-A1: per-width differential of the compile-time CIOS kernels against
    // the generic slice kernel. The generic kernel is the reference; a
    // mismatch at any width is a STOP.
    // ------------------------------------------------------------------

    /// An odd `n`-limb modulus with a non-zero top limb. `kind` selects the
    /// pseudorandom shape or the all-ones modulus (`R - 1`), so the population
    /// includes a maximal top limb and a maximally dense modulus.
    fn ma1_modulus(n: usize, kind: u64) -> Vec<u64> {
        if kind == 0 {
            return vec![u64::MAX; n];
        }
        let mut state = kind | 1;
        let mut m: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
        m[0] |= 1;
        m[n - 1] |= 1 << 63;
        m
    }

    /// The PFP-6 operand population, specialised to a given width: `0`, `1`,
    /// `m-1`, `m-2`, a one-limb value, every single-non-zero-limb value (all
    /// positions for `n <= 16`, a boundary/midpoint sample otherwise), the
    /// all-ones vector where it is below `m`, and a deterministic random sweep
    /// reduced into `[0, m)`.
    fn ma1_operands(m: &[u64]) -> Vec<Vec<u64>> {
        let n = m.len();
        let mut values: Vec<Vec<u64>> = Vec::new();
        let mut push = |v: Vec<u64>| {
            let p = pfp6_pad(&v, n);
            if limbs::cmp(&p, m) == core::cmp::Ordering::Less && !values.contains(&p) {
                values.push(p);
            }
        };
        push(Vec::new());
        push(vec![1]);
        push(limbs::sub(m, &[1]));
        push(limbs::sub(m, &[2]));
        push(vec![u64::MAX]);
        push(vec![u64::MAX; n]);
        let positions: Vec<usize> = if n <= 16 {
            (0..n).collect()
        } else {
            vec![0, 1, n / 2, n - 2, n - 1]
        };
        for &pos in &positions {
            let mut v = vec![0u64; n];
            v[pos] = 1;
            push(v);
            if pos == n - 1 {
                let mut top = vec![0u64; n];
                top[pos] = 1 << 63;
                push(top);
            }
        }
        let mut state = {
            let mut s = 0x9e37_79b9_7f4a_7c15u64;
            for &l in m {
                s ^= l;
                s = s.wrapping_mul(0x100_0000_01b3);
            }
            s | 1
        };
        let random = if n >= 64 { 4 } else { 12 };
        for _ in 0..random {
            let raw: Vec<u64> = (0..n).map(|_| pfp6_xorshift(&mut state)).collect();
            let Some(reduced) = limbs::rem_fallible(&raw, m) else {
                unreachable!("a remainder succeeds")
            };
            push(reduced);
        }
        values
    }

    fn ma1_specialised_widths() -> [usize; 8] {
        [4, 6, 9, 16, 32, 48, 64, 128]
    }

    /// Run one multiply through the dispatch boundary and through the generic
    /// slice kernel, assert bit equality, and check the defining congruence.
    fn ma1_check_pair(m: &[u64], a: &[u64], b: &[u64], n0: u64) -> bool {
        let n = m.len();
        let Some(generic) = mont_mul_fallible_with(MontSchedule::Cios, a, b, m, n0) else {
            unreachable!("allocation succeeds")
        };
        let mut out = vec![0u64; n];
        let mut t = vec![0u64; n * 2 + 1];
        let mut diff = vec![0u64; n];
        assert!(
            mont_mul_cios_dispatch(a, b, &mut out, m, n0, &mut t, &mut diff),
            "dispatch refused the geometry"
        );
        assert_eq!(
            out, generic,
            "specialised != generic at n={n}, m={m:?}, a={a:?}, b={b:?}"
        );
        pfp6_assert_congruent(&out, a, b, m, "M-A1 fixed");
        true
    }

    /// Every specialised width must equal the generic slice kernel over the
    /// PFP-6 population, at two modulus shapes. One mismatch stops the test.
    #[test]
    fn ma1_specialised_widths_match_the_generic_kernel() {
        let mut total = 0usize;
        for n in ma1_specialised_widths() {
            let mut cases = 0usize;
            for kind in [0x0123_4567_89ab_cdefu64, 0] {
                let m = ma1_modulus(n, kind);
                assert!(m[0] & 1 == 1 && m[n - 1] != 0);
                let n0 = mont_n0(m[0]);
                let values = ma1_operands(&m);
                for a in &values {
                    for b in &values {
                        assert!(ma1_check_pair(&m, a, b, n0));
                        cases += 1;
                    }
                }
            }
            eprintln!("M-A1 width n={n}: pairs={cases} mismatches=0");
            assert!(cases > 0);
            total += cases;
        }
        eprintln!("M-A1 specialised differential: pairs={total} mismatches=0");
    }

    /// Widths outside the specialised set must fall back to the generic slice
    /// kernel and still agree with it (the fallback is the reference itself, so
    /// this checks the dispatch boundary, not a second implementation).
    #[test]
    fn ma1_unspecialised_widths_use_the_generic_kernel() {
        let mut cases = 0usize;
        for n in [1, 2, 3, 5, 7, 8, 13, 17, 33] {
            let m = ma1_modulus(n, 0xdead_beef_0bad_f00du64);
            let n0 = mont_n0(m[0]);
            let values = ma1_operands(&m);
            for a in &values {
                for b in &values {
                    assert!(ma1_check_pair(&m, a, b, n0));
                    cases += 1;
                }
            }
        }
        eprintln!("M-A1 fallback widths: pairs={cases} mismatches=0");
        assert!(cases > 0);
    }
}

// ---------------------------------------------------------------------------
// Kani proof harnesses for the 4-limb CIOS Montgomery multiply (PFP-53).
//
// Compiled only under Kani (`--cfg kani`); a normal `cargo build` or
// `cargo test` never sees this module, so the `kani` crate is not a build
// dependency of the ordinary build. These reach the private
// `mont_mul_cios_fixed::<4, 6>` kernel, so they live inside the crate rather
// than in `tests/kani_proofs.rs`, which can only see the public surface. Run:
//
//     cargo kani --harness cios4_equiv_full_width
//
// The harness is a bounded model check, not an exhaustive proof: it quantifies
// over the 4-limb symbolic operands with fixed, compile-time loop bounds, and
// the oracle is an independent multi-precision computation that shares no code
// path with the kernel.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod kani_proofs {
    use core::cmp::Ordering;

    /// Compare two little-endian 4-limb values, most-significant limb first.
    fn cmp4(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return if a[i] > b[i] {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
        }
        Ordering::Equal
    }

    /// 512-bit schoolbook product `a * b` into 8 little-endian limbs.
    fn mul4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let v = (a[i] as u128) * (b[j] as u128) + (out[i + j] as u128) + carry;
                out[i + j] = v as u64;
                carry = v >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    /// `m << s` for `s < 256`, as 8 little-endian limbs.
    fn shl4(m: &[u64; 4], s: usize) -> [u64; 8] {
        let mut out = [0u64; 8];
        let word = s / 64;
        let bit = s % 64;
        for j in 0..4 {
            let dst = word + j;
            out[dst] |= m[j] << bit;
            if bit != 0 {
                out[dst + 1] |= m[j] >> (64 - bit);
            }
        }
        out
    }

    /// Compare two little-endian 8-limb values, most-significant limb first.
    fn cmp8(a: &[u64; 8], b: &[u64; 8]) -> Ordering {
        for i in (0..8).rev() {
            if a[i] != b[i] {
                return if a[i] > b[i] {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
        }
        Ordering::Equal
    }

    /// `a - b` for 8 limbs, assuming `a >= b`.
    fn sub8(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut out = [0u64; 8];
        let mut borrow = 0u64;
        for i in 0..8 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = u64::from(b1) | u64::from(b2);
        }
        out
    }

    /// `t mod m` for a 512-bit `t` and a 256-bit odd `m` (top limb non-zero),
    /// by binary long division with a fixed 256-iteration loop (no data-
    /// dependent trip count). Both values this harness reduces are `< m * 2^256`,
    /// so their quotient by `m` is `< 2^256` and 256 iterations suffice.
    fn reduce_512(t: &[u64; 8], m: &[u64; 4]) -> [u64; 4] {
        let mut acc = *t;
        for i in (0..256).rev() {
            let cand = shl4(m, i);
            if cmp8(&acc, &cand) != Ordering::Less {
                acc = sub8(&acc, &cand);
            }
        }
        [acc[0], acc[1], acc[2], acc[3]]
    }

    /// `-m0^-1 mod 2^64`, independent of `super::mont_n0` so the harness's n0
    /// does not come from the implementation under test. The formula is the
    /// standard Newton iteration; the code is not shared.
    fn n0_of(m0: u64) -> u64 {
        let mut inv = m0;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        inv.wrapping_neg()
    }

    /// The 4-limb CIOS kernel equals `(a * b * 2^-256) mod m`, for arbitrary
    /// 4-limb `a`, `b` and odd modulus `m` with `2^192 <= m < 2^256` (non-zero
    /// top limb) and `a, b < m`. The postcondition is checked inverse-free: the
    /// oracle asserts `0 <= r < m` and `r * 2^256 ≡ a * b (mod m)`, both
    /// computed from limb vectors with the helpers above (no crate helper is
    /// called for the oracle).
    #[kani::proof]
    #[kani::unwind(256)]
    fn cios4_equiv_full_width() {
        let a: [u64; 4] = kani::any();
        let b: [u64; 4] = kani::any();
        let m: [u64; 4] = kani::any();

        kani::assume(m[0] & 1 == 1); // odd modulus
        kani::assume(m[3] != 0); // non-zero top limb: 2^192 <= m < 2^256
        kani::assume(cmp4(&a, &m) == Ordering::Less); // a < m
        kani::assume(cmp4(&b, &m) == Ordering::Less); // b < m

        let n0 = n0_of(m[0]);

        let mut out = [0u64; 4];
        let mut t = [0u64; 6];
        let mut diff = [0u64; 4];
        let ok = super::mont_mul_cios_fixed::<4, 6>(&a, &b, &mut out, &m, n0, &mut t, &mut diff);
        assert!(
            ok,
            "the width contract must accept a well-formed 4-limb call"
        );

        // Independent oracle, inverse-free: r * 2^256 ≡ a * b (mod m), r < m.
        let prod = mul4(&a, &b);
        let prod_mod = reduce_512(&prod, &m);
        let r_r = [0u64, 0, 0, 0, out[0], out[1], out[2], out[3]]; // out * 2^256
        let r_r_mod = reduce_512(&r_r, &m);

        assert!(cmp4(&out, &m) == Ordering::Less, "range: 0 <= r < m");
        assert_eq!(r_r_mod, prod_mod, "r * 2^256 ≡ a * b (mod m)");
    }
}
