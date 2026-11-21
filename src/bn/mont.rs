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
//!
//! ## Ownership classification (final classification batch)
//!
//! **Deliberately Rust-owned internal representation; no allocator-seam interior site.**
//! `MontCtx` is opaque to callers and its storage is a Rust [`Box`] over `Vec<Limb>`
//! fields, created in [`new_mont`] and released by [`BN_MONT_CTX_free`]'s `Box::from_raw`.
//! There is no `CRYPTO_zalloc`/`CRYPTO_free` (or other seam allocation) in this file; the
//! only `CRYPTO_THREAD_*` calls are the caller's read/write lock in
//! [`BN_MONT_CTX_set_locked`], not an allocation. The consequence is stated rather than
//! hidden: an installed `CRYPTO_set_mem_functions` hook does not observe these objects'
//! allocations or releases. That is the recorded compatibility residual P1 in
//! `PROGRESS.md` (the Rust representation's byte size differs from the authority's C
//! struct, so allocating it at `size_of::<MontCtx>()` would violate §6's exact-size hook
//! parity); it is retained, not claimed discharged.

use core::ffi::{c_int, c_ulong};

use crate::bn::arith::{
    mod_exp_core, mod_exp_core_consttime_from_parts, mont_mul_fallible, pad_to,
};
use crate::bn::bignum::{
    as_mut, as_ref, magnitude, parts, parts_fallible, store, store_consttime, BigNum,
};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::bn::secret::SecretBuf;
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
    crate::bn::alloc::try_boxed(MontCtx {
        rr: Vec::new(),
        n: Vec::new(),
        ni: Vec::new(),
        n0: [0, 0],
        ri: 0,
        flags: 0,
    })
    .unwrap_or(core::ptr::null_mut())
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
    // `ri = ceil(bits / 64) * 64`, the authority's own rounding. For a normalised
    // modulus that is exactly `64 * m.len()`: its top limb is non-zero, so the
    // bit length lies in `((len-1)*64, len*64]` and the ceiling is `len`. Computing
    // it from the public limb count rather than `limbs::bit_len` is what keeps a
    // secret CRT modulus' top-limb leading zeros out of a branch.
    let Some(ri) = m.len().checked_mul(64) else {
        return false;
    };
    // `RR = R^2 mod m` with `R = 2^ri`. Fixed-pattern doubling from public
    // geometry; the contents of a secret modulus never select a branch, an index
    // or a loop bound (T6).
    let Some(rr) = ri
        .checked_mul(2)
        .and_then(|bits| limbs::pow2_mod_consttime(bits, m))
    else {
        return false;
    };
    let Some(n) = crate::bn::alloc::try_clone_slice(m) else {
        return false;
    };
    mont.n = n;
    mont.ri = ri as c_int;
    mont.n0 = [inverse_word(m[0]), 0];
    mont.ni = Vec::new();
    mont.flags = 0;
    mont.rr = rr;
    true
}

/// Montgomery reduction: `(r * R^-1) mod n`, for `0 <= r < n * R`.
///
/// The classic word algorithm — add `m * n` until `R` divides the accumulator, then
/// shift. The result is below `2n`, so one conditional subtraction finishes it, which
/// is exactly what the authority's `bn_from_montgomery_word` does.
///
/// Every loop is bounded by the public limb count `n.len()`, the carry runs over a
/// fixed range, and the final subtraction is a mask select. The CRT moduli reach
/// this through `BN_from_montgomery`/`BN_to_montgomery`, so the accumulation and
/// the reduction must not branch on the modulus' limbs (T6).
fn mont_reduce(r: &[Limb], n: &[Limb], n0: Limb) -> Option<Vec<Limb>> {
    let nl = n.len();
    if nl == 0 {
        return Some(Vec::new());
    }
    // One allocation for the accumulator, sized by the public limb count, and two
    // for the conditional-subtraction scratch; all three are fallible so a caller
    // on a secret path can report the failure rather than abort. The accumulator and
    // the subtraction scratch derive from the operands, which are secret on the RSA
    // CRT reach (`BN_to_montgomery`/`BN_from_montgomery`/`BN_mod_mul_montgomery`),
    // so they are `SecretBuf`s; the returned `out` is moved into the caller's
    // `BIGNUM`, whose release cleanses it.
    let t_len = nl.checked_mul(2)?.checked_add(2)?;
    let mut t = SecretBuf::try_zeroed(t_len)?;
    let take = r.len().min(t_len);
    t[..take].copy_from_slice(&r[..take]);
    for i in 0..nl {
        let m = t[i].wrapping_mul(n0);
        let mut carry: Limb = 0;
        for j in 0..nl {
            // The bound is `(2^64-1)^2 + 2*(2^64-1) = 2^128-1`; `wrapping_*`
            // keeps the profile's overflow check — a conditional jump on the high
            // bits of a modulus-derived product — out of the loop.
            let prod = (m as u128)
                .wrapping_mul(n[j] as u128)
                .wrapping_add(t[i + j] as u128)
                .wrapping_add(carry as u128);
            t[i + j] = prod as Limb;
            carry = (prod >> 64) as Limb;
        }
        // Carry through a fixed range instead of `while carry != 0`: the total
        // value is below `2 * B^(2n)`, so it never leaves `t`.
        let mut c = carry;
        for limb in t[(i + nl)..=(2 * nl)].iter_mut() {
            let (s, overflow) = limb.overflowing_add(c);
            *limb = s;
            c = u64::from(overflow);
        }
    }
    // One masked conditional subtraction; `high` is the limb above the result's
    // `nl` limbs and `borrow` the final borrow of `t[nl..2nl] - n`. Keep the
    // difference when the value is at least `n`: `high != 0` or no borrow.
    let high = t[2 * nl];
    let mut diff = SecretBuf::try_zeroed(nl)?;
    let mut borrow = 0u64;
    for j in 0..nl {
        let (d1, b1) = t[nl + j].overflowing_sub(n[j]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[j] = d2;
        borrow = u64::from(b1) | u64::from(b2);
    }
    let take = high | (borrow ^ 1);
    let mask = 0u64.wrapping_sub(take);
    let mut out = crate::bn::alloc::try_zeroed(nl, 0u64)?;
    for j in 0..nl {
        out[j] = (t[nl + j] & !mask) | (diff[j] & mask);
    }
    Some(out)
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
/// `mont` must be null or a live `BN_MONT_CTX`; `m` must be null or live; `ctx` is
/// unused. The context and the modulus are distinct object types (`MontCtx` and
/// `BigNum`), so aliasing them is not a supported input.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_set(
    mont: *mut MontCtx,
    m: *const BigNum,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `m` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(m) };
        let (md, _) = parts(x);
        // SAFETY: `mont` is null-or-live per this function's `# Safety` section.
        let Some(dst) = (unsafe { as_mut_mont(mont) }) else {
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
/// live. When `to == from` the function returns `to` before forming any borrow, so
/// the `&mut` on `to` and the `&` on `from` below always refer to distinct objects.
#[no_mangle]
pub unsafe extern "C" fn BN_MONT_CTX_copy(to: *mut MontCtx, from: *mut MontCtx) -> *mut MontCtx {
    guard_ffi(core::ptr::null_mut(), || {
        // The authority returns `to` untouched when the two are the same object, and
        // a caller can observe that by identity. This check also makes the borrows
        // below non-overlapping by construction.
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
/// `r` must be null or a live `BIGNUM`; `a` must be null or live; `mont` must be
/// null or a live `BN_MONT_CTX`; `ctx` is unused. `r` may alias `a`; the operand is
/// copied before `r` is borrowed. `mont` is a distinct object type and cannot alias
/// either `BIGNUM`.
#[no_mangle]
pub unsafe extern "C" fn BN_to_montgomery(
    r: *mut BigNum,
    a: *const BigNum,
    mont: *mut MontCtx,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `a` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: `mont` is null-or-live per this function's `# Safety` section.
        let Some(mc) = (unsafe { as_ref_mont(mont) }) else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        // `a * RR`, reduced: the authority reaches this through
        // `BN_mod_mul_montgomery(r, a, &mont->RR, mont, ctx)`. For `a < R` the
        // product is below `m * R`, so REDC's fixed-pattern form applies directly;
        // a wider operand — outside every crate caller — keeps the general
        // reduction. The dispatch is on the public limb count.
        let value = if ad.len() <= mc.n.len() {
            let Some(padded) = pad_to(&ad, mc.n.len()) else {
                return 0;
            };
            let Some(v) = mont_mul_fallible(&padded, &mc.rr, &mc.n, mc.n0[0]) else {
                return 0;
            };
            v
        } else {
            let Some(prod) = limbs::mul_fallible(&ad, &mc.rr) else {
                return 0;
            };
            match mont_reduce(&prod, &mc.n, mc.n0[0]) {
                Some(v) => v,
                None => return 0,
            }
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(r) }, value, false))
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: `mont` is null-or-live per this function's `# Safety` section.
        let Some(mc) = (unsafe { as_ref_mont(mont) }) else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        let Some(value) = mont_reduce(&ad, &mc.n, mc.n0[0]) else {
            return 0;
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(r) }, value, false))
    })
}

/// `int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,`
/// `BN_MONT_CTX *mont, BN_CTX *ctx)`
///
/// # Safety
///
/// As `BN_to_montgomery`, with `b` null or live. `r` may alias `a` or `b`; both
/// operands are copied before `r` is borrowed.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_mul_montgomery(
    r: *mut BigNum,
    a: *const BigNum,
    b: *const BigNum,
    mont: *mut MontCtx,
    _ctx: *mut BnCtx,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `a` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: `b` is null-or-live per this function's `# Safety` section.
        let y = unsafe { as_ref(b) };
        let Some((bd, _)) = parts_fallible(y) else {
            return 0;
        };
        // SAFETY: `mont` is null-or-live per this function's `# Safety` section.
        let Some(mc) = (unsafe { as_ref_mont(mont) }) else {
            return 0;
        };
        if mc.n.is_empty() {
            return 0;
        }
        // Both operands are below the modulus by this function's contract, so
        // REDC's `a * b < m * R` bound holds and the fixed-pattern product-plus-
        // reduction can serve directly. An operand wider than the modulus is
        // outside every crate caller (blinding, ECDSA and the RSA CRT path all
        // pass reduced values) and keeps the general reduction; the dispatch is
        // on the public limb count, never on a value.
        let value = if ad.len() <= mc.n.len() && bd.len() <= mc.n.len() {
            let Some(pa) = pad_to(&ad, mc.n.len()) else {
                return 0;
            };
            let Some(pb) = pad_to(&bd, mc.n.len()) else {
                return 0;
            };
            let Some(v) = mont_mul_fallible(&pa, &pb, &mc.n, mc.n0[0]) else {
                return 0;
            };
            v
        } else {
            let Some(prod) = limbs::mul_fallible(&ad, &bd) else {
                return 0;
            };
            match mont_reduce(&prod, &mc.n, mc.n0[0]) {
                Some(v) => v,
                None => return 0,
            }
        };
        // SAFETY: `r` is null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(r) }, value, false))
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
/// `r` must be null or a live `BIGNUM`; `a`, `p` and `m` must each be null or live;
/// `ctx` is unused. `r` may alias any of `a`, `p` and `m`; all three are copied
/// before `r` is borrowed. `in_mont` is an optimisation the authority may precompute;
/// this implementation is exact without one and does not read it.
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: `p` is null-or-live per this function's `# Safety` section.
        let y = unsafe { as_ref(p) };
        // Secret on the constant-time path. Borrowed, not cloned: the staging
        // copy below is the only transfer and it is public-width.
        let pd = magnitude(y);
        // SAFETY: `m` is null-or-live per this function's `# Safety` section.
        let z = unsafe { as_ref(m) };
        let Some((md, _)) = parts_fallible(z) else {
            return 0;
        };
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP_327) };
            return 0;
        }
        // SAFETY: `a`, `p` and `m` are null-or-live per this function's
        // `# Safety` section, which is `BN_get_flags`'s contract.
        //
        // The authority tests all three operands (`bn_exp.c:331-335`): a marked
        // base is what routes `dsa_sign_setup`'s `k` through the fixed-pattern
        // ladder in `dsa_mod_inverse_fermat`. Omitting `a` left the secret-base
        // Fermat inversion on the variable-time path.
        let consttime = unsafe { gets_consttime(a) || gets_consttime(p) || gets_consttime(m) };
        let result = if consttime {
            // The authority's `BN_mod_exp` dispatches on the same flags. The
            // modulus is odd here (the refusal above), so the Montgomery-form
            // ladder is available. Its width is the modulus' limb count — a
            // public parameter — never the exponent's normalised length.
            mod_exp_core_consttime_from_parts(&ad, pd, &md, md.len())
        } else {
            mod_exp_core(&ad, pd, &md)
        };
        match result {
            Some(v) => {
                // SAFETY: `r` is null-or-live per this function's `# Safety` section.
                let dst = unsafe { as_mut(r) };
                // The consttime path may carry a secret-derived result, so it is
                // stored without a value-dependent trim branch.
                c_int::from(if consttime {
                    store_consttime(dst, v, false, md.len())
                } else {
                    store(dst, v, false)
                })
            }
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
        // SAFETY: `a` is null-or-live per this function's `# Safety` section.
        let x = unsafe { as_ref(a) };
        let Some((ad, _)) = parts_fallible(x) else {
            return 0;
        };
        // SAFETY: `p` is null-or-live per this function's `# Safety` section.
        let y = unsafe { as_ref(p) };
        // This entry point is always constant-time, so the exponent is secret.
        // It is borrowed, not cloned; the ladder stages it at the public modulus
        // width, so the only copy's extent is public geometry.
        let pd = magnitude(y);
        // SAFETY: `m` is null-or-live per this function's `# Safety` section.
        let z = unsafe { as_ref(m) };
        let Some((md, _)) = parts_fallible(z) else {
            return 0;
        };
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP_622) };
            return 0;
        }
        // This entry point's name is the promise: always the fixed-pattern ladder.
        // The modulus is odd (refused above), so Montgomery form exists. The
        // loop width is the modulus' limb count, a public parameter.
        match mod_exp_core_consttime_from_parts(&ad, pd, &md, md.len()) {
            // SAFETY: `r` is null-or-live per this function's `# Safety` section;
            // the result may derive from a secret exponent, so it is stored
            // without a value-dependent trim branch.
            Some(v) => c_int::from(store_consttime(unsafe { as_mut(r) }, v, false, md.len())),
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
/// `r` must be null or a live `BIGNUM`; `p` and `m` must each be null or live; `ctx`
/// and `in_mont` are unused. `r` may alias `p` or `m`; both are read before `r` is
/// borrowed.
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
        let Some((pd, _)) = parts_fallible(y) else {
            return 0;
        };
        let Some((md, _)) = parts_fallible(z) else {
            return 0;
        };
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
        let Some(word) = limbs::from_u64_fallible(a) else {
            return 0;
        };
        let Some(base) = limbs::rem_fallible(&word, &md) else {
            return 0;
        };
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
/// `r` must be null or a live `BIGNUM`; every input must be null or live; `ctx` and
/// `m_ctx` are unused. `r` may alias any input; all five are read before `r` is
/// borrowed.
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
        let Some((a1d, _)) = parts_fallible(x) else {
            return 0;
        };
        let Some((p1d, _)) = parts_fallible(y) else {
            return 0;
        };
        let Some((md, _)) = parts_fallible(z) else {
            return 0;
        };
        if refuses(&md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_EXP2_35) };
            return 0;
        }
        // SAFETY: null-or-live per this function's `# Safety` section.
        let (u, v) = unsafe { (as_ref(a2), as_ref(p2)) };
        let Some((a2d, _)) = parts_fallible(u) else {
            return 0;
        };
        let Some((p2d, _)) = parts_fallible(v) else {
            return 0;
        };
        let (Some(first), Some(second)) =
            (mod_exp_core(&a1d, &p1d, &md), mod_exp_core(&a2d, &p2d, &md))
        else {
            return 0;
        };
        let Some(prod) = limbs::mul_fallible(&first, &second) else {
            return 0;
        };
        let Some(product) = limbs::rem_fallible(&prod, &md) else {
            return 0;
        };
        // SAFETY: null-or-live per this function's `# Safety` section.
        c_int::from(store(unsafe { as_mut(r) }, product, false))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::arith::{BN_mod_exp, BN_ucmp};
    use crate::bn::bignum::{new_owned, BN_copy, BN_free, BN_new, BN_set_flags, BN_set_word};

    /// A `BIGNUM` holding a machine word.
    fn word(w: c_ulong) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let b = unsafe { BN_new() };
        // SAFETY: `b` is live.
        assert_eq!(unsafe { BN_set_word(b, w) }, 1);
        b
    }

    /// Copy an object so an aliased-output case does not destroy the input used by
    /// the distinct-output reference computation.
    fn copy_of(src: *const BigNum) -> *mut BigNum {
        // SAFETY: `BN_new` takes no pointers.
        let dst = unsafe { BN_new() };
        // SAFETY: `dst` is live and `src` is live for the duration of the call.
        assert!(!unsafe { BN_copy(dst, src) }.is_null());
        dst
    }

    /// The M18-D1 regression control for this file: every entry point that writes
    /// `r` while reading `a`/`b`/`p`/`m` accepts `r` aliasing any of them. The
    /// aliased result is compared with the distinct-output computation. Before the
    /// repair, `as_mut(r)` and `as_ref(input)` were formed in one tuple, so these
    /// calls were undefined behaviour.
    #[test]
    fn aliased_outputs_match_the_distinct_form() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: `BN_MONT_CTX_new` takes no pointers.
        let mont = unsafe { BN_MONT_CTX_new() };
        let m = word(31);
        let a = word(3);
        let b = word(7);
        let p = word(5);
        // SAFETY: every object is live and the context is unused.
        assert_eq!(unsafe { BN_MONT_CTX_set(mont, m, NULL) }, 1);

        // BN_to_montgomery: r == a.
        // SAFETY: `BN_new` takes no pointers.
        let mont_a = unsafe { BN_new() };
        // SAFETY: every pointer is live.
        assert_eq!(unsafe { BN_to_montgomery(mont_a, a, mont, NULL) }, 1);
        let alias = copy_of(a);
        // SAFETY: every pointer is live and `alias` is both input and output.
        assert_eq!(unsafe { BN_to_montgomery(alias, alias, mont, NULL) }, 1);
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(alias, mont_a) }, 0, "to_montgomery alias");

        // BN_from_montgomery: r == a.
        // SAFETY: `BN_new` takes no pointers.
        let back = unsafe { BN_new() };
        // SAFETY: every pointer is live.
        assert_eq!(unsafe { BN_from_montgomery(back, mont_a, mont, NULL) }, 1);
        let alias_back = copy_of(mont_a);
        // SAFETY: every pointer is live and `alias_back` is both input and output.
        assert_eq!(
            // SAFETY: every pointer is live.
            unsafe { BN_from_montgomery(alias_back, alias_back, mont, NULL) },
            1
        );
        assert_eq!(
            // SAFETY: both are live.
            unsafe { BN_ucmp(alias_back, back) },
            0,
            "from_montgomery alias"
        );
        // SAFETY: both are live; the round trip restores the base.
        assert_eq!(unsafe { BN_ucmp(back, a) }, 0, "round trip");

        // BN_mod_mul_montgomery: r == a and r == b.
        // SAFETY: `BN_new` takes no pointers.
        let product = unsafe { BN_new() };
        // SAFETY: every pointer is live.
        assert_eq!(
            // SAFETY: every pointer is live.
            unsafe { BN_mod_mul_montgomery(product, a, b, mont, NULL) },
            1
        );
        for alias_first in [true, false] {
            let x = if alias_first { copy_of(a) } else { copy_of(b) };
            // SAFETY: every pointer is live; the copied operand is also the output.
            assert_eq!(
                // SAFETY: every pointer is live.
                unsafe {
                    if alias_first {
                        BN_mod_mul_montgomery(x, x, b, mont, NULL)
                    } else {
                        BN_mod_mul_montgomery(x, a, x, mont, NULL)
                    }
                },
                1
            );
            assert_eq!(
                // SAFETY: both are live.
                unsafe { BN_ucmp(x, product) },
                0,
                "mod_mul_montgomery alias"
            );
        }

        // BN_mod_exp_mont: r == a, r == p, and r == m.
        // SAFETY: `BN_new` takes no pointers.
        let power = unsafe { BN_new() };
        // SAFETY: every pointer is live and `in_mont` is unused.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont(power, a, p, m, NULL, core::ptr::null_mut()) },
            1
        );
        // r == a.
        let alias_a = copy_of(a);
        // SAFETY: every pointer is live; `alias_a` is both base and output.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont(alias_a, alias_a, p, m, NULL, core::ptr::null_mut()) },
            1
        );
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(alias_a, power) }, 0, "mod_exp_mont r == a");
        // r == p.
        let alias_p = copy_of(p);
        // SAFETY: every pointer is live; `alias_p` is both exponent and output.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont(alias_p, a, alias_p, m, NULL, core::ptr::null_mut()) },
            1
        );
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(alias_p, power) }, 0, "mod_exp_mont r == p");
        // r == m.
        let alias_m = copy_of(m);
        // SAFETY: every pointer is live; `alias_m` is both modulus and output.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont(alias_m, a, p, alias_m, NULL, core::ptr::null_mut()) },
            1
        );
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(alias_m, power) }, 0, "mod_exp_mont r == m");

        // BN_mod_exp_mont_consttime: r == a.
        let ct = copy_of(a);
        // SAFETY: every pointer is live; `ct` is both input and output.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont_consttime(ct, ct, p, m, NULL, core::ptr::null_mut()) },
            1
        );
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(ct, power) }, 0, "consttime alias");

        // BN_mod_exp_mont_word: r == m (the shape was already read-first, and this
        // pins it).
        let word_out = copy_of(m);
        // SAFETY: every pointer is live; `word_out` is both the modulus and output.
        assert_eq!(
            // SAFETY: every pointer is live and `in_mont` is unused.
            unsafe { BN_mod_exp_mont_word(word_out, 3, p, word_out, NULL, core::ptr::null_mut()) },
            1
        );
        // SAFETY: both are live.
        assert_eq!(unsafe { BN_ucmp(word_out, power) }, 0, "mont_word alias");
    }

    /// `BN_mod_exp_mont` dispatches on `BN_FLG_CONSTTIME`: the flagged call must
    /// take the fixed-pattern ladder and still answer the same value as the
    /// unflagged call, which keeps the variable-time ladder.
    #[test]
    fn a_consttime_flagged_exponent_agrees_with_the_unflagged_form() {
        let a = word(5);
        let m = word(497);
        let p = word(117);
        // SAFETY: every object is live and owned by this test.
        unsafe {
            let reference = BN_new();
            assert_eq!(
                BN_mod_exp_mont(
                    reference,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                1
            );
            BN_set_flags(p, BN_FLG_CONSTTIME);
            let flagged = BN_new();
            assert_eq!(
                BN_mod_exp_mont(
                    flagged,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                1
            );
            assert_eq!(BN_ucmp(flagged, reference), 0, "flagged dispatch");
            BN_free(flagged);
            BN_free(reference);
            BN_free(a);
            BN_free(m);
            BN_free(p);
        }
    }

    /// An exponent wider than the public modulus limb count is refused on the
    /// constant-time path — it is neither widened on its own (secret) length nor
    /// truncated — while the variable-time path keeps answering it.
    #[test]
    fn an_exponent_wider_than_the_public_width_is_refused_not_truncated() {
        // SAFETY: every object here is allocated by this test and live.
        unsafe {
            let a = word(3);
            let m = word(7);
            let p = new_owned(vec![1, 1], 0);
            let ct = BN_new();
            let vt = BN_new();
            assert_eq!(
                BN_mod_exp_mont_consttime(
                    ct,
                    a,
                    p,
                    m,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                0
            );
            assert_eq!(BN_mod_exp(vt, a, p, m, core::ptr::null_mut()), 1);
            for b in [ct, vt, a, m, p] {
                BN_free(b);
            }
        }
    }
}
