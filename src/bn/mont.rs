//! Phase 5 — `BN_MONT_CTX` and the Montgomery arithmetic built on it.
//!
//! `BN_MONT_CTX` is opaque to a consumer: `types.h` forward-declares it and the
//! definition lives in `crypto/bn/bn_local.h`, which is not installed. The
//! representation here is therefore ours, and what is reproduced is the arithmetic
//! the type exists to make fast.
//!
//! ## What is observable, and why the internal form is not a free choice
//!
//! Montgomery conversion is a bijection onto the residues, so `BN_to_montgomery`'s
//! **result** is observable even though the context is opaque: a caller may convert,
//! store the value, and convert back. The authority picks `R = 2^ri` with
//! `ri = ceil(bits(m) / 64) * 64` (`bn_mont.c`, the `MONT_WORD` path this profile
//! compiles), and the two conversions are exactly `a * R mod m` and
//! `a * R^-1 mod m`. A different `R` would be just as correct arithmetically and
//! would disagree with every caller that persisted an intermediate.
//!
//! ## Failure behaviour that is contract
//!
//! * `BN_MONT_CTX_set` on a zero modulus returns 0 and raises nothing.
//! * On a non-zero **even** modulus it returns 0 and raises `BN_R_NO_INVERSE`,
//!   because the authority reaches the failure through `BN_mod_inverse` and that
//!   raise is observable. It is an artefact of the implementation route, and it is
//!   reproduced rather than tidied away.
//! * The exponentiation entry points here require an **odd** modulus and raise
//!   `BN_R_CALLED_WITH_EVEN_MODULUS` at the authority's own coordinate otherwise —
//!   a different answer from `BN_mod_exp`'s, which dispatches to a reciprocal path
//!   when the modulus is even.

use core::ffi::{c_int, c_ulong};

use crate::bn::arith::mod_exp_core;
use crate::bn::bignum::{as_mut, as_ref, parts, store, BigNum};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BN_EXP2_35, BN_EXP_1187, BN_EXP_1195, BN_EXP_327, BN_EXP_622, BN_GCD_532,
};
use crate::runtime::err::raise_site;
use crate::runtime::thread::CryptoRwlock;

/// `BN_FLG_CONSTTIME`, as the authority's `bn.h` defines it.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// The authority's `BN_MONT_CTX`.
///
/// The field names follow `crypto/bn/bn_local.h` so the structure stays reviewable
/// against its origin, even though no caller can see it.
pub struct MontCtx {
    /// `RR` — `R^2 mod N`, which is what makes conversion a single multiply.
    rr: Vec<Limb>,
    /// `N` — the modulus.
    n: Vec<Limb>,
    /// `Ni` — the authority's word-based path leaves this empty, and so do we.
    ni: Vec<Limb>,
    /// `n0` — `-N^-1 mod 2^64`, in the low word.
    n0: [Limb; 2],
    /// `ri` — the bit width of `R`.
    ri: c_int,
    /// `flags` — carried so a copied context reads back the same value.
    flags: c_int,
}

/// Read a `*mut MontCtx` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `MontCtx`.
unsafe fn as_mut_mont<'a>(p: *mut MontCtx) -> Option<&'a mut MontCtx> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// Read a `*const MontCtx` as a shared reference.
///
/// # Safety
///
/// `p` must be null or point to a live `MontCtx`.
unsafe fn as_ref_mont<'a>(p: *const MontCtx) -> Option<&'a MontCtx> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live.
        Some(unsafe { &*p })
    }
}

/// A fresh, unset context.
fn new_mont() -> *mut MontCtx {
    Box::into_raw(Box::new(MontCtx {
        rr: Vec::new(),
        n: Vec::new(),
        ni: Vec::new(),
        n0: [0, 0],
        ri: 0,
        flags: 0,
    }))
}

/// `-n^-1 mod 2^64`, the word the authority keeps in `n0[0]`.
///
/// Newton's iteration doubles the number of correct low bits each round, so six
/// rounds from a one-bit seed are exact. `n` must be odd; an even modulus is refused
/// before this is reached, which is also when the word does not exist.
fn inverse_word(n: Limb) -> Limb {
    let mut inv: Limb = 1;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// Whether the modulus is zero or even — the pair the Montgomery path refuses.
fn refuses(md: &[Limb]) -> bool {
    md.is_empty() || limbs::is_even(md)
}

/// The Montgomery context for an odd modulus, or `false` when there is none.
///
/// The even case is the caller's to report, because the authority reports it from
/// inside `BN_mod_inverse` rather than here.
fn mont_set(mont: &mut MontCtx, m: &[Limb]) -> bool {
    if refuses(m) {
        return false;
    }
    mont.n = m.to_vec();
    // `ri = ceil(bits / 64) * 64`, the authority's own rounding.
    mont.ri = (limbs::bit_len(m).div_ceil(64) * 64) as c_int;
    mont.n0 = [inverse_word(m[0]), 0];
    mont.ni = Vec::new();
    mont.flags = 0;
    mont.rr = limbs::rem(&limbs::shl(&[1u64], (2 * mont.ri) as usize), m);
    true
}

/// Montgomery reduction: `(r * R^-1) mod n`, for `0 <= r < n * R`.
///
/// The classic word algorithm — add `m * n` until `R` divides the accumulator, then
/// shift. The result is below `2n`, so one conditional subtraction finishes it, which
/// is exactly what the authority's `bn_from_montgomery_word` does.
fn mont_reduce(r: &[Limb], n: &[Limb], n0: Limb) -> Vec<Limb> {
    let nl = n.len();
    if nl == 0 {
        return Vec::new();
    }
    let mut t: Vec<Limb> = r.to_vec();
    t.resize(2 * nl + 2, 0);
    for i in 0..nl {
        let m = t[i].wrapping_mul(n0);
        let mut carry: Limb = 0;
        for j in 0..nl {
            let prod = (m as u128) * (n[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = prod as Limb;
            carry = (prod >> 64) as Limb;
        }
        let mut k = i + nl;
        while carry != 0 && k < t.len() {
            let s = (t[k] as u128) + (carry as u128);
            t[k] = s as Limb;
            carry = (s >> 64) as Limb;
            k += 1;
        }
    }
    let mut out: Vec<Limb> = t[nl..].to_vec();
    limbs::normalise(&mut out);
    if !out.is_empty() && limbs::cmp(&out, n) != core::cmp::Ordering::Less {
        out = limbs::sub(&out, n);
    }
    out
}

/// `BN_MONT_CTX *BN_MONT_CTX_new(void)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_new() -> *mut MontCtx {
    guard_ffi(core::ptr::null_mut(), new_mont)
}

/// `void BN_MONT_CTX_free(BN_MONT_CTX *mont)`
///
/// A null pointer is a no-op.
///
/// # Safety
///
/// `mont` must be null or a pointer returned by `BN_MONT_CTX_new`,
/// `BN_MONT_CTX_copy` or `BN_MONT_CTX_set_locked`, and not already freed.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_free(mont: *mut MontCtx) {
    guard_ffi((), || {
        if !mont.is_null() {
            // SAFETY: the caller's contract is exactly that `mont` came from one of
            // those constructors and has not been freed.
            drop(unsafe { Box::from_raw(mont) });
        }
    });
}

/// `int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)`
///
/// # Safety
///
/// `mont` must be null or a live, uniquely-owned `BN_MONT_CTX`; `mod` must be null or
/// live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_set(
    mont: *mut MontCtx,
    m: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x) = unsafe { (as_mut_mont(mont), as_ref(m)) };
        let (md, _) = parts(x);
        let Some(dst) = dst else {
            return 0;
        };
        // A zero modulus is refused quietly; an even one through the inverse the
        // authority cannot form, and that raise is observable.
        if md.is_empty() {
            return 0;
        }
        if !mont_set(dst, &md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_GCD_532) };
            return 0;
        }
        1
    })
}

/// `BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)`
///
/// # Safety
///
/// `to` must be null or a live, uniquely-owned `BN_MONT_CTX`; `from` must be null or
/// live.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_copy(to: *mut MontCtx, from: *mut MontCtx) -> *mut MontCtx {
    guard_ffi(core::ptr::null_mut(), || {
        // The authority returns `to` untouched when the two are the same object, and
        // a caller can observe that by identity.
        if to == from {
            return to;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, src) = unsafe { (as_mut_mont(to), as_ref_mont(from)) };
        let (Some(dst), Some(src)) = (dst, src) else {
            return core::ptr::null_mut();
        };
        dst.rr = src.rr.clone();
        dst.n = src.n.clone();
        dst.ni = src.ni.clone();
        dst.n0 = src.n0;
        dst.ri = src.ri;
        dst.flags = src.flags;
        to
    })
}

/// `BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,`
/// `const BIGNUM *mod, BN_CTX *ctx)`
///
/// The double-checked pattern the authority uses, under the caller's lock: a context
/// that is already there is returned as it is, so a caller that keeps the result in a
/// shared slot pays for the setup once.
///
/// # Safety
///
/// `pmont` must point to a writable `*mut MontCtx` slot; `lock` must be null or a
/// live `CRYPTO_RWLOCK`; `mod` must be null or live; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_set_locked(
    pmont: *mut *mut MontCtx,
    lock: *mut CryptoRwlock,
    m: *const BigNum,
    ctx: *mut BnCtx,
) -> *mut MontCtx {
    guard_ffi(core::ptr::null_mut(), || {
        if pmont.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: the caller guarantees `pmont` is a writable slot.
        if !unsafe { *pmont }.is_null() {
            // SAFETY: as above, and the slot's value is a live context the caller
            // owns.
            return unsafe { *pmont };
        }
        if !lock.is_null() {
            // SAFETY: the caller guarantees `lock` is live; the status the authority
            // ignores is ignored here too.
            unsafe { crate::runtime::thread::CRYPTO_THREAD_write_lock(lock) };
        }
        // SAFETY: the slot is still writable, and the re-read under the lock is the
        // second half of the double check.
        let mut out = unsafe { *pmont };
        if out.is_null() {
            // SAFETY: `BN_MONT_CTX_new` takes no pointers; `BN_MONT_CTX_set` and
            // `BN_MONT_CTX_free` have `m`'s and the fresh context's contracts, both
            // of which this function's caller guarantees.
            unsafe {
                let fresh = BN_MONT_CTX_new();
                if BN_MONT_CTX_set(fresh, m, ctx) == 1 {
                    *pmont = fresh;
                    out = fresh;
                } else {
                    BN_MONT_CTX_free(fresh);
                }
            }
        }
        if !lock.is_null() {
            // SAFETY: as above.
            unsafe { crate::runtime::thread::CRYPTO_THREAD_unlock(lock) };
        }
        out
    })
}

/// `int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a` must be null or live;
/// `mont` must be null or a live `BN_MONT_CTX`; `ctx` is unused.
#[no_mangle]
pub unsafe extern "C" fn BN_to_montgomery(
    r: *mut BigNum,
    a: *const BigNum,
    mont: *mut MontCtx,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, mc) = unsafe { (as_mut(r), as_ref(a), as_ref_mont(mont)) };
        let (ad, _) = parts(x);
        let Some(mc) = mc else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        // `a * RR`, reduced: the authority reaches this through
        // `BN_mod_mul_montgomery(r, a, &mont->RR, mont, ctx)`.
        let prod = limbs::mul(&ad, &mc.rr);
        c_int::from(store(dst, mont_reduce(&prod, &mc.n, mc.n0[0]), false))
    })
}

/// `int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,`
/// `BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_to_montgomery`.
#[no_mangle]
pub unsafe extern "C" fn BN_from_montgomery(
    r: *mut BigNum,
    a: *const BigNum,
    mont: *mut MontCtx,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, mc) = unsafe { (as_mut(r), as_ref(a), as_ref_mont(mont)) };
        let (ad, _) = parts(x);
        let Some(mc) = mc else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        c_int::from(store(dst, mont_reduce(&ad, &mc.n, mc.n0[0]), false))
    })
}

/// `int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `BN_MONT_CTX *mont, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_to_montgomery`, with `b` null or live.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_mul_montgomery(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    mont: *mut MontCtx,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y, mc) = unsafe { (as_mut(r), as_ref(a), as_ref(b), as_ref_mont(mont)) };
        let (ad, _) = parts(x);
        let (bd, _) = parts(y);
        let Some(mc) = mc else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        let prod = limbs::mul(&ad, &bd);
        c_int::from(store(dst, mont_reduce(&prod, &mc.n, mc.n0[0]), false))
    })
}

/// `int BN_get_flags(const BIGNUM *b, int n)` read for `BN_FLG_CONSTTIME`.
///
/// # Safety
///
/// `b` must be null or a live `BIGNUM`.
unsafe fn gets_consttime(b: *const BigNum) -> bool {
    // SAFETY: the caller guarantees `b` is null or live, which is `BN_get_flags`'s
    // own contract.
    unsafe { crate::bn::bignum::BN_get_flags(b, BN_FLG_CONSTTIME) != 0 }
}

/// `int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)`
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `a`, `p` and `m` must each be
/// null or live; `ctx` is unused. `in_mont` is an optimisation the authority may
/// precompute; this implementation is exact without one and does not read it.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    _in_mont: *mut MontCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y, z) = unsafe { (as_mut(r), as_ref(a), as_ref(p), as_ref(m)) };
        let (ad, _) = parts(x);
        let (pd, _) = parts(y);
        let (md, _) = parts(z);
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP_327) };
            return 0;
        }
        match mod_exp_core(&ad, &pd, &md) {
            Some(v) => c_int::from(store(dst, v, false)),
            None => 0,
        }
    })
}

/// `int BN_mod_exp_mont_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)`
///
/// The even-modulus refusal is raised at `bn_mod_exp_mont_fixed_top`'s coordinate,
/// which is the function the authority's public entry point forwards to.
///
/// # Safety
///
/// As `BN_mod_exp_mont`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont_consttime(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    _in_mont: *mut MontCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (dst, x, y, z) = unsafe { (as_mut(r), as_ref(a), as_ref(p), as_ref(m)) };
        let (ad, _) = parts(x);
        let (pd, _) = parts(y);
        let (md, _) = parts(z);
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP_622) };
            return 0;
        }
        match mod_exp_core(&ad, &pd, &md) {
            Some(v) => c_int::from(store(dst, v, false)),
            None => 0,
        }
    })
}

/// `int BN_mod_exp_mont_consttime_x2(...)` — two independent exponentiations sharing
/// one context.
///
/// The argument list is the authority's; an ABI signature is not this project's to
/// shorten, which is why the lint is silenced rather than the signature changed.
///
/// # Safety
///
/// Each `BIGNUM` pointer must be null or live, and `r1`/`r2` uniquely owned where
/// they are outputs. The two `BN_MONT_CTX` pointers and the context are unused.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn BN_mod_exp_mont_consttime_x2(
    r1: *mut BigNum,
    a1: *const BigNum,
    p1: *const BigNum,
    m1: *const BigNum,
    mont1: *mut MontCtx,
    r2: *mut BigNum,
    a2: *const BigNum,
    p2: *const BigNum,
    m2: *const BigNum,
    mont2: *mut MontCtx,
    ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `BN_mod_exp_mont_consttime`'s contract covers the first half.
        if unsafe { BN_mod_exp_mont_consttime(r1, a1, p1, m1, ctx, mont1) } == 0 {
            return 0;
        }
        // SAFETY: as above, for the second half.
        unsafe { BN_mod_exp_mont_consttime(r2, a2, p2, m2, ctx, mont2) }
    })
}

/// `int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,`
/// `const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)`
///
/// A constant-time exponent or modulus is refused here — this entry point has no
/// constant-time path — and so is an even modulus, at that function's own
/// coordinates.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; `p` and `m` must each be null
/// or live; `ctx` and `in_mont` are unused.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont_word(
    r: *mut BigNum,
    a: c_ulong,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    _in_mont: *mut MontCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (y, z) = unsafe { (as_ref(p), as_ref(m)) };
        let (pd, _) = parts(y);
        let (md, _) = parts(z);
        // SAFETY: the null checks are `BN_get_flags`'s own contract, and the sites
        // are compile-time constants.
        unsafe {
            if gets_consttime(p) || gets_consttime(m) {
                raise_site(&BN_EXP_1187);
                return 0;
            }
            if refuses(&md) {
                raise_site(&BN_EXP_1195);
                return 0;
            }
        }
        let base = limbs::rem(&limbs::from_u64(a), &md);
        match mod_exp_core(&base, &pd, &md) {
            // SAFETY: null-or-live per this function's `# Safety` section.
            Some(v) => c_int::from(store(unsafe { as_mut(r) }, v, false)),
            None => 0,
        }
    })
}

/// `int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,`
/// `const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m, BN_CTX *ctx,`
/// `BN_MONT_CTX *m_ctx)` — `(a1^p1 * a2^p2) mod m`.
///
/// # Safety
///
/// `r` must be null or a live, uniquely-owned `BIGNUM`; every input must be null or
/// live; `ctx` and `m_ctx` are unused.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn BN_mod_exp2_mont(
    r: *mut BigNum,
    a1: *const BigNum,
    p1: *const BigNum,
    a2: *const BigNum,
    p2: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    _m_ctx: *mut MontCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (x, y, z) = unsafe { (as_ref(a1), as_ref(p1), as_ref(m)) };
        let (a1d, _) = parts(x);
        let (p1d, _) = parts(y);
        let (md, _) = parts(z);
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP2_35) };
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (u, v) = unsafe { (as_ref(a2), as_ref(p2)) };
        let (a2d, _) = parts(u);
        let (p2d, _) = parts(v);
        let (Some(first), Some(second)) =
            (mod_exp_core(&a1d, &p1d, &md), mod_exp_core(&a2d, &p2d, &md))
        else {
            return 0;
        };
        let product = limbs::rem(&limbs::mul(&first, &second), &md);
        // SAFETY: null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(r) }, product, false))
    })
}
