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
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::bn::arith::{
    mod_exp_core, mod_exp_core_consttime_from_parts_prepared, mod_exp_core_consttime_policy,
    mont_mul_fallible, pad_to, resolve_ladder_width, PreparedMontParams,
};
use crate::bn::bignum::{
    as_mut, as_ref, magnitude, parts_fallible, store, store_consttime, BigNum,
};
use crate::bn::ctx::BnCtx;
use crate::bn::limbs::{self, Limb};
use crate::bn::secret::SecretBuf;
use crate::ffi::guard_ffi;
use crate::runtime::err::err_reasons::BN_R_INVALID_RANGE;
use crate::runtime::err::err_sites::{
    BN_EXP2_35, BN_EXP_1187, BN_EXP_1195, BN_EXP_327, BN_EXP_622, BN_GCD_532,
};
use crate::runtime::err::{raise_site, raise_with};
use crate::runtime::secret::SecretLimbs;
use crate::runtime::thread::CryptoRwlock;

/// `BN_FLG_CONSTTIME`, as the authority's `bn.h` defines it.
const BN_FLG_CONSTTIME: c_int = 0x04;

/// `ERR_LIB_BN` — `include/openssl/err.h.in`.
const ERR_LIB_BN: c_int = 3;

/// The radix a prepared domain is expressed in. The authority's word-based path
/// (`MONT_WORD`) is radix 2^64, so the value is both the authority's and this
/// implementation's; the observable `BN_to_montgomery` result fixes it.
const MONT_RADIX_BITS: u32 = 64;

/// The reduction kernel a prepared domain was built for.
///
/// PFP-1 has one portable REDC kernel. The identity is still recorded and
/// checked on use so a future backend cannot be paired with parameters from a
/// different one; a mismatch is refused rather than silently reinterpreted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MontBackend {
    /// Schoolbook product plus word-wise REDC ([`crate::bn::arith::mont_mul_fallible`]).
    PortableRedc,
    /// Never constructed in a release build; it exists so the refusal test can
    /// prove a context from another kernel is rejected.
    #[cfg(test)]
    TestMismatch,
}

/// The authority's `BN_MONT_CTX`, and the crate's prepared Montgomery domain.
///
/// The field names follow `crypto/bn/bn_local.h` so the structure stays reviewable
/// against its origin, even though no caller can see it. Every field below the
/// authority's `flags` binds one prepared domain to a single modulus:
///
/// * `n` — the modulus, as secret storage because RSA CRT prepares on the secret
///   primes (T6);
/// * `rr` — `R^2 mod N`;
/// * `one` — `R mod N`, the Montgomery form of one;
/// * `ri` — the radix width, `64 * N.len()`;
/// * `radix_bits` and `backend` — the representation and kernel identity;
/// * `n0` — `-N^-1 mod 2^64`.
///
/// A prepared context is immutable after [`mont_set`]. `Drop` therefore cleanses
/// the modulus, both derived residues and the `n0` word on every exit, including
/// an early return and an unwind in the owning object's lifecycle.
pub struct MontCtx {
    /// `RR` — `R^2 mod N`, which is what makes conversion a single multiply.
    rr: SecretLimbs,
    /// `N` — the modulus.
    n: SecretLimbs,
    /// `R mod N` — the prepared Montgomery form of one.
    one: SecretLimbs,
    /// `Ni` — the authority's word-based path leaves this empty, and so does the crate.
    ni: Vec<Limb>,
    /// `n0` — `-N^-1 mod 2^64`, in the low word.
    n0: [Limb; 2],
    /// `ri` — the bit width of `R`.
    ri: c_int,
    /// `flags` — carried so a copied context reads back the same value.
    flags: c_int,
    /// The radix the residues are expressed in.
    radix_bits: u32,
    /// The reduction kernel the residues were prepared for.
    backend: MontBackend,
    /// Admission for the P-521 Mersenne REDC fast arm. It is cleared by every
    /// modulus (re)preparation and by `BN_MONT_CTX_copy`'s copy of this field,
    /// and can only be set by the EC group's exact-identity predicate at the
    /// point the generator and curve are established. A plain `bool` here has
    /// no ABI consequence: `MontCtx` is an opaque, Rust-owned `Box`, not
    /// `#[repr(C)]`, and no consumer sees its layout.
    mersenne521: bool,
}

// The cached-context slot is a caller-owned `*mut MontCtx` in the ABI structs
// (`DH`, `DSA`, `RSA`, `RSA_PRIME_INFO`). `BN_MONT_CTX_set_locked` reads and
// publishes it through an `AtomicPtr` view of that same slot. That view is only
// sound when it has exactly the slot's size and alignment; a target where an
// atomic pointer is larger or more aligned must fail to compile rather than
// silently reinterpret the slot.
const _: () =
    assert!(core::mem::size_of::<AtomicPtr<MontCtx>>() == core::mem::size_of::<*mut MontCtx>());
const _: () =
    assert!(core::mem::align_of::<AtomicPtr<MontCtx>>() == core::mem::align_of::<*mut MontCtx>());

/// Volatile-wipe the modulus-derived `n0` word in place.
///
/// `n0` is `-N^-1 mod 2^64`, so on the RSA CRT reach it is derived from a secret
/// prime. It is a scalar in the context rather than a [`SecretBuf`], so the two
/// places that overwrite it — preparation and copy — and the context's own
/// destructor must wipe it explicitly.
fn cleanse_n0(n0: &mut [Limb; 2]) {
    let bytes = core::mem::size_of_val(n0);
    // SAFETY: `n0` is a live, uniquely borrowed array of `bytes` writable bytes;
    // `cleanse` only stores zeros through it.
    unsafe { crate::runtime::mem::cleanse(n0.as_mut_ptr().cast::<u8>(), bytes) };
}

impl Drop for MontCtx {
    fn drop(&mut self) {
        // The `SecretBuf` fields cleanse themselves; `n0` is a scalar field and
        // needs its own wipe. This runs on every release, including one reached
        // through `Box::from_raw` in `BN_MONT_CTX_free`.
        cleanse_n0(&mut self.n0);
    }
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
        rr: SecretBuf::from_vec(Vec::new()),
        n: SecretBuf::from_vec(Vec::new()),
        one: SecretBuf::from_vec(Vec::new()),
        ni: Vec::new(),
        n0: [0, 0],
        ri: 0,
        flags: 0,
        radix_bits: 0,
        backend: MontBackend::PortableRedc,
        mersenne521: false,
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
///
/// **Ordering of the preparation.** Every check that can refuse on public
/// geometry — the zero/even test, the `c_int` radix range and the doubling of
/// `R`'s bit length — runs before the first secret-bearing allocation, so a
/// refusal costs no secret lifetime. The modulus is normalised by the `BigNum`
/// representation the only caller reads (`normalise` trims the magnitude), and
/// `MONT_RADIX_BITS` is a constant; neither needs a value-dependent check.
///
/// **Adoption at production.** Each value that derives from the modulus is moved
/// into [`SecretBuf`] at the statement that produces it. An ordinary `Vec` never
/// holds a modulus-derived intermediate across a later fallible step, so an
/// allocation failure cannot release one uncleansed.
fn mont_set(mont: &mut MontCtx, m: &[Limb]) -> bool {
    if refuses(m) {
        return false;
    }
    // Public geometry first. `ri = ceil(bits / 64) * 64`; for a normalised modulus
    // that is exactly `64 * m.len()`: its top limb is non-zero, so the bit length
    // lies in `((len-1)*64, len*64]` and the ceiling is `len`. Computing it from
    // the public limb count rather than `limbs::bit_len` keeps a secret CRT
    // modulus' top-limb leading zeros out of a branch.
    let Some(ri_bits) = m.len().checked_mul(64) else {
        return false;
    };
    let Ok(ri) = c_int::try_from(ri_bits) else {
        return false;
    };
    let Some(rr_bits) = ri_bits.checked_mul(2) else {
        return false;
    };
    // `RR = R^2 mod m` with `R = 2^ri`. Fixed-pattern doubling from public
    // geometry; the contents of a secret modulus never select a branch, an index
    // or a loop bound (T6). The returned vector is adopted at the call that
    // produces it, so no ordinary `Vec` owns it beyond the producing statement.
    let Some(rr) = limbs::pow2_mod_consttime(rr_bits, m).map(SecretBuf::from_vec) else {
        return false;
    };
    // Test-only: a test cannot hold a pointer to this function's local owner, so a
    // pending request arms the drop probe on `R^2 mod N`, the first secret-derived
    // buffer. A later allocation failure then drops this buffer on the failure
    // path, and the probe reports, from inside `Drop`, that the release cleansed.
    #[cfg(test)]
    if crate::bn::secret::drop_probe::take_request() {
        crate::bn::secret::drop_probe::arm(rr.as_ptr());
    }
    // The modulus is cloned directly into secret storage. `try_clone_slice` would
    // leave an ordinary modulus copy that a later failure releases intact.
    let Some(n) = clone_secret(m) else {
        return false;
    };
    let n0 = inverse_word(m[0]);
    // `R mod m` is one Montgomery multiply from the other prepared values:
    // `R^2 * 1 * R^-1`. The one is a public constant; the result derives from the
    // modulus and is adopted at production, before any further fallible step.
    let Some(mut one_plain) = crate::bn::alloc::try_zeroed(m.len(), 0u64) else {
        return false;
    };
    one_plain[0] = 1;
    let Some(one) = mont_mul_fallible(&rr, &one_plain, m, n0).map(SecretBuf::from_vec) else {
        return false;
    };
    // Commit only after every fallible step has succeeded, so a failure leaves the
    // destination exactly as it was. The replaced `n0` is wiped before the new
    // value overwrites it.
    cleanse_n0(&mut mont.n0);
    mont.n = n;
    mont.ri = ri;
    mont.n0 = [n0, 0];
    mont.ni = Vec::new();
    mont.flags = 0;
    mont.radix_bits = MONT_RADIX_BITS;
    mont.backend = MontBackend::PortableRedc;
    // A new modulus invalidates any prior admission; only the EC group's
    // exact-identity predicate may re-establish it.
    mont.mersenne521 = false;
    mont.rr = rr;
    mont.one = one;
    true
}

/// Copy a limb slice into fresh secret storage, or `None` on allocation failure.
fn clone_secret(v: &[Limb]) -> Option<SecretLimbs> {
    let mut out = SecretBuf::try_zeroed(v.len())?;
    out.copy_from_slice(v);
    Some(out)
}

/// The prepared parameters, borrowed from a validated context.
impl MontCtx {
    fn prepared(&self) -> PreparedMontParams<'_> {
        PreparedMontParams {
            n0: self.n0[0],
            rr: &self.rr[..],
            one: &self.one[..],
        }
    }
}

/// Record `admitted` on the `MontCtx` behind `mont`.
///
/// # Safety
///
/// `mont` must be null or a live, uniquely-owned `MontCtx` — the group's
/// `field_data1`, which the caller's group contract owns.
pub(crate) unsafe fn set_mersenne521_admission(mont: *mut MontCtx, admitted: bool) {
    // SAFETY: the caller's contract.
    if let Some(mc) = unsafe { as_mut_mont(mont) } {
        mc.mersenne521 = admitted;
    }
}

/// The test-only read side of the admission flag.
///
/// # Safety
///
/// `mont` must be null or a live `MontCtx`.
#[cfg(test)]
pub(crate) unsafe fn mersenne521_admission(mont: *const MontCtx) -> bool {
    // SAFETY: the caller's contract.
    unsafe { as_ref_mont(mont) }.is_some_and(|mc| mc.mersenne521)
}

/// Whether the prepared domain is admitted **and** still holds exactly the
/// P-521 modulus with `n0 = 1`. The flag is set only by the EC predicate, so
/// this is defence in depth; the modulus compare keeps a stale or mis-set flag
/// from reaching the specialized kernel.
fn mersenne521_active(mc: &MontCtx) -> bool {
    mc.mersenne521
        && mc.n0[0] == crate::bn::mersenne::P521_N0
        && crate::bn::mersenne::is_p521(&mc.n)
}

/// Whether `mc` is a prepared domain for exactly `md`.
///
/// The structural half compares public geometry — limb width, radix, reduction
/// kernel, the declared radix width and the prepared buffers' extents — and can
/// refuse early without reading any modulus limb, because those values are
/// public. The content half compares the whole modulus with a full-width
/// accumulation and a single equality test; there is no per-limb early exit, so
/// the loop's control flow depends only on the public width.
///
/// **Classification of the comparison's control flow.** It reveals only whether
/// two stored copies of the same modulus agree, and on the legitimate path they
/// always agree. The modulus is not being checked against attacker-chosen data:
/// it is the operand already supplied by the caller and the copy this context
/// was prepared from. A disagreement means the caller handed a stale context,
/// which is a correctness fault, not secret information.
fn context_matches(mc: &MontCtx, md: &[Limb]) -> bool {
    let width = md.len();
    if width == 0 {
        return false;
    }
    let Some(expected_ri) = width.checked_mul(64) else {
        return false;
    };
    let Ok(expected_ri) = c_int::try_from(expected_ri) else {
        return false;
    };
    // Public structure. A context that was never prepared, was prepared for a
    // different width/radix/backend, or lost a derived buffer is refused here.
    if mc.radix_bits != MONT_RADIX_BITS
        || mc.backend != MontBackend::PortableRedc
        || mc.ri != expected_ri
        || mc.n.len() != width
        || mc.rr.len() != width
        || mc.one.len() != width
    {
        return false;
    }
    // Contents. The loop bound is the public width and the accumulator is read
    // in full on every call; only the final comparison consults the result. The
    // two buffers have the same checked length, so `zip` visits the whole width.
    let mut diff = 0u64;
    for (stored, operand) in mc.n.iter().zip(md.iter()) {
        diff |= stored ^ operand;
    }
    // `n0` is derived from `md[0]`, so a context whose modulus matches but whose
    // prepared word does not is still inconsistent. `inverse_word` is a fixed
    // six-round iteration with no data-dependent branch.
    diff |= mc.n0[0] ^ inverse_word(md[0]);
    diff == 0
}

/// Refuse a supplied context whose prepared domain does not match the operand.
///
/// The authority does not validate `in_mont`; a stale context silently produces
/// a wrong answer, which programme §11 lists as a refused shortcut. This raise
/// is therefore a recorded correctness/safety divergence with **no authority
/// coordinate**: `raise_with` at line 0 names the authority file the context
/// belongs to and makes the absence of a real site explicit rather than
/// inventing one.
fn refuse_context() {
    // SAFETY: the file pointer is a static NUL-terminated C string.
    unsafe {
        raise_with(
            ERR_LIB_BN,
            BN_R_INVALID_RANGE,
            c"crypto/bn/bn_mont.c".as_ptr(),
            0,
        )
    };
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
        // The magnitude is borrowed, not copied into an ordinary `Vec`: the modulus
        // is secret on the RSA CRT reach, and `mont_set` is the single transfer
        // point into protected storage. A plain `parts` clone would be an ordinary
        // temporary that a later failure released uncleansed.
        let md = magnitude(x);
        // SAFETY: `mont` is null-or-live per this function's `# Safety` section.
        let Some(dst) = (unsafe { as_mut_mont(mont) }) else {
            return 0;
        };
        // A zero modulus is refused quietly; an even one through the inverse the
        // authority cannot form, and that raise is observable.
        if md.is_empty() {
            return 0;
        }
        if !mont_set(dst, md) {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BN_GCD_532) };
            return 0;
        }
        1
    })
}

/// `BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)`
///
/// A copy allocates its own modulus, `R^2`, `R mod N` and `Ni`; an allocation
/// failure returns NULL and leaves `to` unchanged. The authority's copy cannot
/// fail on allocation because it aborts instead; returning the ordinary failure
/// answer is the crate's recorded memory-safety improvement.
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
        // Allocate every buffer before assigning any, so a failure leaves `dst`
        // exactly as it was rather than half-copied.
        let Some(rr) = clone_secret(&src.rr) else {
            return core::ptr::null_mut();
        };
        let Some(n) = clone_secret(&src.n) else {
            return core::ptr::null_mut();
        };
        let Some(one) = clone_secret(&src.one) else {
            return core::ptr::null_mut();
        };
        let Some(ni) = crate::bn::alloc::try_clone_slice(&src.ni) else {
            return core::ptr::null_mut();
        };
        dst.rr = rr;
        dst.n = n;
        dst.one = one;
        dst.ni = ni;
        // The replaced word is modulus-derived; wipe it before the copy of `src`'s
        // value overwrites it.
        cleanse_n0(&mut dst.n0);
        dst.n0 = src.n0;
        dst.ri = src.ri;
        dst.flags = src.flags;
        dst.radix_bits = src.radix_bits;
        dst.backend = src.backend;
        // The source's admission travels with the copy: `ossl_ec_GFp_mont_group_copy`
        // copies the curve, generator, order and cofactor first, so an admitted
        // source is an admitted destination and a refused one stays refused.
        dst.mersenne521 = src.mersenne521;
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
/// ## Publication and ownership rule
///
/// The slot is read and written through an [`AtomicPtr`] view of the caller's
/// `*mut MontCtx` storage. The fast path is an `Acquire` load; the publication is a
/// `Release` store performed while the write lock is held. A reader that observes a
/// non-null pointer therefore also observes the fully initialised [`MontCtx`] it
/// names, and the null-to-context transition has exactly one writer, so every
/// waiting caller receives the same immutable context.
///
/// This function **never frees or replaces a published context**. The context is
/// owned by the enclosing object (`DH`, `DSA`, `RSA` or `RSA_PRIME_INFO`) and is
/// released once by that object's `finish` hook. The reader's obligation is the
/// same lifetime precondition as the authority's: the enclosing object must outlive
/// every operation that uses the returned pointer and must not be freed or have its
/// method changed concurrently. Those transitions perform non-atomic writes to the
/// slot, which is sound only under that exclusive-access precondition; the atomic
/// publication removes the data race between the fast-path read and the
/// null-to-context store, and does not extend the context's lifetime.
///
/// # Safety
///
/// `pmont` must point to a writable `*mut MontCtx` slot that is suitably aligned and
/// remains valid for the duration of the call and of the returned pointer's use;
/// no non-atomic access to it may run concurrently with this call (`lock` is what
/// excludes them). `lock` must be null or a live `CRYPTO_RWLOCK`; `mod` must be null
/// or live; `ctx` is unused. A null `lock` leaves concurrent initialisation to the
/// caller's own exclusion: the atomic slot access is still race-free, but two
/// callers without exclusion may each create a context.
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
        // SAFETY: the caller guarantees `pmont` is a writable slot of a pointer's
        // size and alignment, and that non-atomic accesses to it are excluded by
        // the lock or by the caller's own exclusive access. The const assertions
        // above make the size/alignment equivalence a compile-time property of the
        // ABI slot, and the slot remains live for the duration of the borrow.
        let slot = unsafe { AtomicPtr::<MontCtx>::from_ptr(pmont) };
        let cached = slot.load(Ordering::Acquire);
        if !cached.is_null() {
            return cached;
        }
        if !lock.is_null() {
            // SAFETY: the caller guarantees `lock` is live; the status the authority
            // ignores is ignored here too.
            unsafe { crate::runtime::thread::CRYPTO_THREAD_write_lock(lock) };
        }
        // Second half of the double check. Holding the write lock makes this the
        // only null-to-context writer, so every waiter observes the same pointer.
        let mut out = slot.load(Ordering::Acquire);
        if out.is_null() {
            // SAFETY: `BN_MONT_CTX_new` takes no pointers; `BN_MONT_CTX_set` and
            // `BN_MONT_CTX_free` have `m`'s and the fresh context's contracts, both
            // of which this function's caller guarantees.
            unsafe {
                let fresh = BN_MONT_CTX_new();
                if BN_MONT_CTX_set(fresh, m, ctx) == 1 {
                    // Release: the initialised, immutable context is visible to the
                    // acquiring fast path before the pointer naming it.
                    slot.store(fresh, Ordering::Release);
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
            let fast = mersenne521_active(mc);
            let reduced = if fast {
                crate::bn::mersenne::mont_mul_p521_fallible(&padded, &mc.rr)
            } else {
                mont_mul_fallible(&padded, &mc.rr, &mc.n, mc.n0[0])
            };
            let Some(v) = reduced else {
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
        // The specialized REDC is valid for `T < p·R = p·2^576`; a nine-limb
        // input is below `2^576 < p·R`. Anything wider keeps the general path.
        let reduced = if mersenne521_active(mc) && ad.len() <= crate::bn::mersenne::P521_LIMBS {
            crate::bn::mersenne::mont_reduce_p521_fallible(&ad)
        } else {
            mont_reduce(&ad, &mc.n, mc.n0[0])
        };
        let Some(value) = reduced else {
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
            let fast = mersenne521_active(mc);
            let reduced = if fast {
                crate::bn::mersenne::mont_mul_p521_fallible(&pa, &pb)
            } else {
                mont_mul_fallible(&pa, &pb, &mc.n, mc.n0[0])
            };
            let Some(v) = reduced else {
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
/// A non-NULL `in_mont` is validated against `m` before use. The Montgomery
/// dispatch reuses its prepared `R`, `R^2` and `n0` when the constant-time flag
/// selects that ladder; a context for any other modulus, width, radix or backend
/// is refused with `BN_R_INVALID_RANGE` instead of producing a wrong answer.
///
/// # Safety
///
/// `r` must be null or a live `BIGNUM`; `a`, `p` and `m` must each be null or live;
/// `ctx` is unused. `r` may alias any of `a`, `p` and `m`; all three are copied
/// before `r` is borrowed. `in_mont` must be null or a live `BN_MONT_CTX`.
#[no_mangle]
pub unsafe extern "C" fn BN_mod_exp_mont(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    _ctx: *mut BnCtx,
    in_mont: *mut MontCtx,
) -> c_int {
    // SAFETY: the caller's contract, forwarded unchanged.
    unsafe { bn_mod_exp_mont_impl(r, a, p, m, in_mont, LadderWidth::Modulus) }
}

/// `BN_mod_exp_mont` with the constant-time ladder bounded by a **public policy
/// width**, in 64-bit limbs.
///
/// Only the DH method table uses this. `dh->length` (or, when that is unset, the
/// named group's RFC 7919 key length) is the maximum private-key length the
/// group declares, so a conforming exponent is `ceil(length / 64)` limbs wide
/// and the ladder need not run at the modulus width. The bound is public
/// configuration; the result is bit-for-bit the modulus-width ladder's. `0`
/// means "no declared bound" and is exactly [`BN_mod_exp_mont`].
///
/// **A caller-supplied exponent wider than the policy is not refused.** The
/// operand slices are in hand at this entry point, so the resolved ladder width
/// is bound once here (PFP-43): `max(policy, stored_exponent_limbs)` when the
/// exponent fits the modulus, and the stored count when it does not. The
/// exponent's normalised limb count is captured once at ingestion (PFP-39) and
/// passed in as `stored_exponent_limbs`; this entry point does not re-read `p`'s
/// length to choose the width. The value is a declassified length, never the
/// exponent's content; the in-policy path
/// (`stored_exponent_limbs <= policy`) is computationally identical to the former
/// policy ladder.
///
/// # Safety
///
/// As [`BN_mod_exp_mont`].
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn bn_mod_exp_mont_policy(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    in_mont: *mut MontCtx,
    policy_limbs: usize,
    stored_exponent_limbs: usize,
) -> c_int {
    // SAFETY: forwarded under this function's contract.
    unsafe {
        bn_mod_exp_mont_impl(
            r,
            a,
            p,
            m,
            in_mont,
            LadderWidth::Policy {
                policy_limbs,
                stored_exponent_limbs,
            },
        )
    }
}

/// How [`bn_mod_exp_mont_impl`] fixes the constant-time ladder's length.
///
/// The length is always a **public** limb count; the variants differ only in where
/// that public bound comes from. None reads the exponent's value, and the
/// fixed-pattern kernel is identical in every arm.
pub(crate) enum LadderWidth {
    /// The modulus' limb count — the C entry points' default. The exponent's
    /// normalised length never enters the loop bound, so a secret exponent leaks
    /// nothing through the schedule.
    Modulus,
    /// A public policy width from the key object (the DH method), widened to cover
    /// a stored out-of-policy exponent.
    Policy {
        policy_limbs: usize,
        stored_exponent_limbs: usize,
    },
    /// The exponent's own normalised limb count. Admissible only for an exponent
    /// whose **length is public**.
    ///
    /// The RSA blinding refresh is the only selector: it raises the fresh factor
    /// `A` to the public exponent `e` (`crypto/bn/bn_blind.c:288-294`), so `e`'s
    /// length is not a secret and the fixed-pattern ladder may use it as its
    /// public width instead of the modulus' width. The authority's
    /// `bn_mod_exp_mont_fixed_top` sizes the same ladder from
    /// `p->top * BN_BITS2` — the exponent's **whole-limb** length, kept that way
    /// deliberately so the top bits of the last limb are not revealed
    /// (`crypto/bn/bn_exp.c:633-637`) — which is exactly `pd.len()` limbs here.
    /// For RSA's `e = 65537` that is one limb (64 bits) against the 32-limb
    /// (2048-bit) modulus width this crate otherwise runs, a 32x shorter
    /// schedule.
    ///
    /// The kernel is the same constant-pattern Montgomery ladder as the
    /// [`Modulus`](LadderWidth::Modulus) arm; only the loop bound changes. Every
    /// secret-dependent decision remains a mask over the accumulator, and the
    /// base (the blinding factor) is never branched on. **No constant-time claim
    /// is made about the exponent**: its length is observable by construction
    /// and is public on this path. A secret exponent must not select this arm.
    PublicExponent,
}

/// [`BN_mod_exp_mont`]'s body with an explicit public ladder-width policy.
///
/// The `Policy` arm is consulted only on the constant-time path, exactly as
/// `BN_FLG_CONSTTIME` is; the variable-time path is unchanged. Its
/// `stored_exponent_limbs` is the exponent's normalised limb count, captured once
/// by the key object at ingestion (PFP-39), and is used to resolve the ladder width
/// instead of reading `p`'s length per operation.
///
/// # Safety
///
/// As [`BN_mod_exp_mont`]: `r` is null or a live `BIGNUM`; `a`, `p` and `m` are each
/// null or live; `r` may alias any of them; `in_mont` is null or a live
/// `BN_MONT_CTX`.
pub(crate) unsafe fn bn_mod_exp_mont_impl(
    r: *mut BigNum,
    a: *const BigNum,
    p: *const BigNum,
    m: *const BigNum,
    in_mont: *mut MontCtx,
    width: LadderWidth,
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
        // A supplied context is validated before dispatch. Present-but-stale is
        // refused, never silently ignored: the authority would use it and return
        // a wrong answer.
        //
        // SAFETY: `in_mont` is null-or-live per this function's `# Safety` section.
        let prepared = match unsafe { as_ref_mont(in_mont) } {
            None => None,
            Some(mc) => {
                if !context_matches(mc, &md) {
                    refuse_context();
                    return 0;
                }
                Some(mc.prepared())
            }
        };
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
            // ladder is available. The loop width is always a **public** limb
            // count, but the arms take it from different public sources:
            // * `Modulus` (the C entry points) uses the modulus' limb count and
            //   never reads the exponent's normalised length;
            // * `Policy` (the DH method) uses a declared public bound, widened to
            //   cover the exponent count captured at ingestion (PFP-43, PFP-39),
            //   and only *refuses* an exponent wider than the resolved width;
            // * `PublicExponent` (the RSA blinding refresh) uses the exponent's own
            //   normalised limb count because that length is public on this path —
            //   the authority's `bn_mod_exp_mont_fixed_top` uses `p->top * BN_BITS2`
            //   for the same reason (`bn_exp.c:633-637`). This is the only arm that
            //   derives the loop width from the exponent, and only the blinding
            //   refresh selects it. See [`LadderWidth::PublicExponent`] and
            //   [`mod_exp_core_consttime_policy`].
            match width {
                LadderWidth::Policy {
                    policy_limbs,
                    stored_exponent_limbs,
                } => {
                    let width = resolve_ladder_width(policy_limbs, md.len(), stored_exponent_limbs);
                    mod_exp_core_consttime_policy(&ad, pd, &md, width, prepared.as_ref())
                }
                LadderWidth::Modulus => mod_exp_core_consttime_from_parts_prepared(
                    &ad,
                    pd,
                    &md,
                    md.len(),
                    prepared.as_ref(),
                ),
                // The exponent's length is public on this arm (see
                // [`LadderWidth::PublicExponent`]), so it may set the ladder
                // width. `max(1)` keeps a zero exponent's staged buffer non-empty;
                // the policy core handles the degenerate moduli and the
                // out-of-width refusal.
                LadderWidth::PublicExponent => {
                    let width = pd.len().max(1);
                    mod_exp_core_consttime_policy(&ad, pd, &md, width, prepared.as_ref())
                }
            }
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
/// which is the function the authority's public entry point forwards to. A non-NULL
/// `in_mont` is validated against `m` and its prepared parameters are reused; a
/// stale context is refused rather than used.
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
    in_mont: *mut MontCtx,
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
        // Validate the supplied context once, before the ladder. A context for a
        // different modulus, width, radix or backend is an error, not a reason
        // to recompute: silently ignoring it would hide a caller's stale cache.
        //
        // SAFETY: `in_mont` is null-or-live per this function's `# Safety` section.
        let prepared = match unsafe { as_ref_mont(in_mont) } {
            None => None,
            Some(mc) => {
                if !context_matches(mc, &md) {
                    refuse_context();
                    return 0;
                }
                Some(mc.prepared())
            }
        };
        // This entry point's name is the promise: always the fixed-pattern ladder.
        // The modulus is odd (refused above), so Montgomery form exists. The
        // loop width is the modulus' limb count, a public parameter.
        match mod_exp_core_consttime_from_parts_prepared(&ad, pd, &md, md.len(), prepared.as_ref())
        {
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
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error};

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

    /// The deliberately broken comparator the negative control borrows: it answers
    /// the same on defined inputs, but its per-limb early exit reveals the first
    /// differing position. It exists only so a tainted run can show that the
    /// instrument sees such a comparator; the production `context_matches` never
    /// takes that shape.
    fn context_matches_early_exit(mc: &MontCtx, md: &[Limb]) -> bool {
        let width = md.len();
        if width == 0 {
            return false;
        }
        let Some(expected_ri) = width.checked_mul(64) else {
            return false;
        };
        let Ok(expected_ri) = c_int::try_from(expected_ri) else {
            return false;
        };
        if mc.radix_bits != MONT_RADIX_BITS
            || mc.backend != MontBackend::PortableRedc
            || mc.ri != expected_ri
            || mc.n.len() != width
            || mc.rr.len() != width
            || mc.one.len() != width
        {
            return false;
        }
        for (stored, operand) in mc.n.iter().zip(md.iter()) {
            if stored != operand {
                return false;
            }
        }
        mc.n0[0] == inverse_word(md[0])
    }

    /// `VALGRIND_MAKE_MEM_UNDEFINED` as the amd64 client request.
    ///
    /// Same sequence as the helpers in `bn::arith`, `rsa::ossl` and
    /// `ec::ecdsa_ossl`: `valgrind.h`'s preamble and an `xchg rbx, rbx`, which
    /// valgrind replaces during translation. Outside valgrind it is a few harmless
    /// register rotations, so the same test runs in the ordinary suite.
    #[cfg(target_arch = "x86_64")]
    unsafe fn valgrind_make_mem_undefined(addr: *mut u8, len: usize) {
        let args: [usize; 6] = [0x4D43_0001, addr as usize, len, 0, 0, 0];
        let _result: usize;
        // SAFETY: the sequence is the documented valgrind client-request pattern;
        // `args` lives for the duration of the asm and is only read.
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

    /// `VALGRIND_MAKE_MEM_DEFINED`, used to declassify only the authorised
    /// equality decision so the test's own assertion is not a second tainted
    /// branch.
    #[cfg(target_arch = "x86_64")]
    unsafe fn valgrind_make_mem_defined(addr: *mut u8, len: usize) {
        let args: [usize; 6] = [0x4D43_0002, addr as usize, len, 0, 0, 0];
        let _result: usize;
        // SAFETY: as `valgrind_make_mem_undefined`.
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

    /// `context_matches` is exercised directly, with no context insertion or
    /// exponentiation around it: an equal operand is accepted and a one-bit
    /// difference is refused. The broken early-exit comparator answers the same on
    /// these defined inputs, which is why the tainted run below is what
    /// distinguishes the two shapes.
    #[test]
    fn context_matches_compares_the_whole_modulus_and_refuses_a_difference() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object is created, used and released inside this test.
        unsafe {
            let m = new_owned(vec![0xffff_ffff_ffff_ffc5, 0xffff_ffff_ffff_ffff], 0);
            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
            let mc = &*mont;
            let equal = (*m).d.clone();
            assert!(context_matches(mc, &equal));
            let mut unequal = equal.clone();
            unequal[0] ^= 1;
            assert!(!context_matches(mc, &unequal));

            // The negative control is semantically equivalent on defined data; the
            // difference is only its per-limb early exit.
            assert!(context_matches_early_exit(mc, &equal));
            assert!(!context_matches_early_exit(mc, &unequal));

            BN_MONT_CTX_free(mont);
            BN_free(m);
        }
    }

    /// ctgrind case for the declassification boundary in `context_matches`.
    ///
    /// The stored modulus is defined; the operand's limbs are marked undefined.
    /// The production comparison reads the whole width into one accumulation, so
    /// the only tainted decision is the final equality test — the authorised
    /// declassification point. The equal and unequal calls exercise both outcomes
    /// of that decision. `CTGRIND_CONTROL=1` additionally runs the deliberately
    /// broken early-exit comparator on tainted data; memcheck must report its
    /// per-limb branch, which is what shows the instrument can see a comparator of
    /// that shape.
    ///
    /// Gate: `valgrind --tool=memcheck --error-exitcode=99 <test-bin> --exact
    /// bn::mont::tests::ctgrind_context_matches_declassifies_at_the_equality_decision
    /// --test-threads=1 --nocapture`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn ctgrind_context_matches_declassifies_at_the_equality_decision() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object and buffer is this test's own, and each client
        // request only marks the definedness of live storage.
        unsafe {
            let m = new_owned(vec![0xffff_ffff_ffff_ffc5, 0xffff_ffff_ffff_ffff], 0);
            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
            let mc = &*mont;

            let mut equal = (*m).d.clone();
            valgrind_make_mem_undefined(equal.as_mut_ptr().cast::<u8>(), equal.len() * 8);
            let mut eq = context_matches(mc, &equal);
            valgrind_make_mem_defined((&mut eq as *mut bool).cast::<u8>(), 1);
            assert!(eq, "equal tainted operands must declassify to true");

            let mut unequal = equal.clone();
            unequal[0] ^= 1;
            let mut ne = context_matches(mc, &unequal);
            valgrind_make_mem_defined((&mut ne as *mut bool).cast::<u8>(), 1);
            assert!(!ne, "a tainted difference must declassify to false");

            if std::env::var_os("CTGRIND_CONTROL").is_some() {
                let mut tainted = (*m).d.clone();
                valgrind_make_mem_undefined(tainted.as_mut_ptr().cast::<u8>(), tainted.len() * 8);
                let mut control = context_matches_early_exit(mc, &tainted);
                valgrind_make_mem_defined((&mut control as *mut bool).cast::<u8>(), 1);
                assert!(control);
            }

            BN_MONT_CTX_free(mont);
            BN_free(m);
        }
    }

    /// Every allocation failure after the first secret-derived buffer exists
    /// releases that buffer cleansed.
    ///
    /// The seam records the allocation sites a successful preparation reaches;
    /// the test then fails each site in turn. `mont_set` arms the drop probe on
    /// `R^2 mod N`, the first secret-derived buffer, when the test requests it; a
    /// later allocation failure drops that buffer and the probe reads its still-live
    /// allocation from inside `Drop`. The assertions are only made for sites that
    /// reached the probe, and at least one must, because sites before `R^2 mod N`
    /// exists have no earlier secret buffer to observe. A return-code-only check
    /// would not see an uncleansed release.
    #[test]
    fn an_allocation_failure_during_preparation_cleanses_the_derived_values() {
        use crate::bn::alloc::test_fail;
        use crate::bn::secret::drop_probe;

        const NULL: *mut BnCtx = core::ptr::null_mut();
        let m = new_owned(vec![0xffff_ffff_ffff_ffc5, 0xffff_ffff_ffff_ffff], 0);

        let sites = test_fail::sites_reached(|| {
            // SAFETY: each object is created, used and released in this closure.
            unsafe {
                let mont = BN_MONT_CTX_new();
                let ok = BN_MONT_CTX_set(mont, m, NULL);
                BN_MONT_CTX_free(mont);
                ok == 1
            }
        });
        assert!(!sites.is_empty(), "the preparation must reach the seam");

        let mut observed = 0usize;
        for site in &sites {
            drop_probe::request();
            let guard = test_fail::fail_at_site(site);
            // SAFETY: each object is created, used and released in this block.
            let result = unsafe {
                let mont = BN_MONT_CTX_new();
                let ok = BN_MONT_CTX_set(mont, m, NULL);
                BN_MONT_CTX_free(mont);
                ok
            };
            drop(guard);
            // A site before the first secret buffer leaves the request pending;
            // clear it so it cannot arm a later, unrelated allocation.
            drop_probe::take_request();
            if let Some(observed_drop) = drop_probe::take() {
                observed += 1;
                assert!(
                    observed_drop.nonzero_before > 0,
                    "the derived buffer must hold live data before the failure"
                );
                assert_eq!(
                    observed_drop.nonzero_bytes, 0,
                    "the derived buffer was released uncleansed at {site}"
                );
                assert_eq!(result, 0, "the injected failure must be reported at {site}");
            }
            // The address may be reused by a later buffer; disarm so its drop
            // cannot be mistaken for this observation.
            drop_probe::arm(core::ptr::null());
        }
        assert!(
            observed > 0,
            "no allocation-failure site exercised the earlier secret buffer"
        );

        ERR_clear_error();
        // SAFETY: `m` is this test's own object.
        unsafe { BN_free(m) };
    }

    /// Concurrent publication, concurrent failure, replacement after publication
    /// and the owner-sequenced release.
    ///
    /// The test runs real threads (no test-only serialisation), so it can detect a
    /// fast-path read that observes a partially published context, a second
    /// context created for the same slot, or a replacement of a published pointer.
    /// It **cannot** detect a concurrent free of the context while a reader holds
    /// it: that is outside the documented lifetime precondition, so the test frees
    /// only after every reader has joined. It also cannot detect a compiler or CPU
    /// reordering that the abstract `Acquire`/`Release` pair permits; it observes
    /// the abstract machine, not arbitrary optimisation.
    #[test]
    fn the_locked_publication_is_atomic_and_publishes_once() {
        use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new};
        use std::sync::atomic::{AtomicPtr, Ordering};
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 4;
        const ROUNDS: usize = 25;

        struct SendLock(*mut CryptoRwlock);
        // SAFETY: the lock is a process-owned synchronisation object; the test
        // shares it only through `Arc` and every use is inside the lock API.
        unsafe impl Send for SendLock {}
        // SAFETY: as above.
        unsafe impl Sync for SendLock {}

        struct SendNum(*mut BigNum);
        // SAFETY: the modulus is read-only after construction, and the test keeps
        // every thread's use on one raw pointer it owns.
        unsafe impl Send for SendNum {}
        // SAFETY: as above.
        unsafe impl Sync for SendNum {}

        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: the lock and both moduli are this test's own objects.
        let lock = Arc::new(SendLock(CRYPTO_THREAD_lock_new()));
        assert!(!lock.0.is_null());
        let odd = Arc::new(SendNum(new_owned(
            vec![0xffff_ffff_ffff_ffc5, 0xffff_ffff_ffff_ffff],
            0,
        )));
        let even = Arc::new(SendNum(new_owned(
            vec![0xffff_ffff_ffff_ffc4, 0xffff_ffff_ffff_ffff],
            0,
        )));

        // Phase 1: concurrent initialisation. Every caller must receive the one
        // context published under the lock.
        let slot = Arc::new(AtomicPtr::<MontCtx>::new(core::ptr::null_mut()));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let slot = Arc::clone(&slot);
            let lock = Arc::clone(&lock);
            let odd = Arc::clone(&odd);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let pmont = Arc::as_ptr(&slot).cast_mut().cast::<*mut MontCtx>();
                barrier.wait();
                let mut seen = Vec::with_capacity(ROUNDS);
                for _ in 0..ROUNDS {
                    // SAFETY: the slot is the shared atomic this test owns, the
                    // lock is live, and the modulus is read-only for the run.
                    let got = unsafe {
                        BN_MONT_CTX_set_locked(pmont, lock.0, odd.0, core::ptr::null_mut())
                    };
                    seen.push(got as usize);
                }
                seen
            }));
        }
        let mut published: Option<usize> = None;
        for handle in handles {
            let Ok(seen) = handle.join() else {
                unreachable!("initialisation worker panicked");
            };
            for got in seen {
                match published {
                    None => published = Some(got),
                    Some(first) => assert_eq!(first, got, "publication must be a single context"),
                }
            }
        }
        let Some(published) = published else {
            unreachable!("at least one caller ran");
        };
        assert_ne!(published, 0, "a successful publication must be non-null");
        assert_eq!(slot.load(Ordering::Acquire) as usize, published);

        // Phase 2: concurrent failure. Failure leaves the slot null, and every
        // caller reports null rather than publishing a half-built context.
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        let fresh_slot = Arc::new(AtomicPtr::<MontCtx>::new(core::ptr::null_mut()));
        for _ in 0..THREADS {
            let slot = Arc::clone(&fresh_slot);
            let lock = Arc::clone(&lock);
            let even = Arc::clone(&even);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let pmont = Arc::as_ptr(&slot).cast_mut().cast::<*mut MontCtx>();
                barrier.wait();
                for _ in 0..ROUNDS {
                    // SAFETY: as in phase 1; the modulus is even, so preparation
                    // refuses it and the entry point reports null.
                    let got = unsafe {
                        BN_MONT_CTX_set_locked(pmont, lock.0, even.0, core::ptr::null_mut())
                    };
                    assert!(got.is_null(), "an even modulus must not publish a context");
                }
            }));
        }
        for handle in handles {
            assert!(handle.join().is_ok(), "failure worker panicked");
        }
        assert!(fresh_slot.load(Ordering::Acquire).is_null());
        // SAFETY: the error queue is this thread's; the workers' refusals are
        // discarded the same way the authority's callers discard them.
        ERR_clear_error();

        // Phase 3: replacement. A published context is returned unchanged by every
        // concurrent caller and is never freed by this function.
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        let keep = published;
        for _ in 0..THREADS {
            let slot = Arc::clone(&slot);
            let lock = Arc::clone(&lock);
            let odd = Arc::clone(&odd);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let pmont = Arc::as_ptr(&slot).cast_mut().cast::<*mut MontCtx>();
                barrier.wait();
                for _ in 0..ROUNDS {
                    // SAFETY: as in phase 1.
                    let got = unsafe {
                        BN_MONT_CTX_set_locked(pmont, lock.0, odd.0, core::ptr::null_mut())
                    };
                    assert_eq!(
                        got as usize, keep,
                        "a published context must not be replaced"
                    );
                }
            }));
        }
        for handle in handles {
            assert!(handle.join().is_ok(), "replacement worker panicked");
        }

        // Phase 4: destruction after every reader has joined, which is the only
        // lifetime the ownership rule permits. A fresh cycle proves the slot can be
        // republished after the owner releases it; the address may differ, so the
        // republished pointer is checked for non-null rather than identity.
        for _ in 0..ROUNDS {
            // SAFETY: no reader remains, and the slot names the context this test
            // owns.
            let cached = slot.load(Ordering::Acquire);
            assert!(!cached.is_null());
            // SAFETY: `cached` was published by this test and is freed exactly once.
            unsafe {
                BN_MONT_CTX_free(cached);
                slot.store(core::ptr::null_mut(), Ordering::Release);
                let again = BN_MONT_CTX_set_locked(
                    Arc::as_ptr(&slot).cast_mut().cast::<*mut MontCtx>(),
                    lock.0,
                    odd.0,
                    NULL,
                );
                assert!(!again.is_null());
            }
        }
        // Release the final cycle's context.
        // SAFETY: as above.
        unsafe {
            BN_MONT_CTX_free(slot.load(Ordering::Acquire));
            slot.store(core::ptr::null_mut(), Ordering::Release);
        }

        // SAFETY: the remaining contexts and the lock are this test's own, and no
        // thread is running.
        unsafe {
            for n in [odd.0, even.0] {
                BN_free(n);
            }
            let lock_ptr = lock.0;
            drop(lock);
            CRYPTO_THREAD_lock_free(lock_ptr);
        }
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

    /// A deterministic pseudo-random limb generator for the sweep.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// Moduli whose shapes exercise one limb, an exact limb boundary, a
    /// secret-shaped two-limb prime and full four-limb storage. Every value is
    /// odd and greater than one, which is the Montgomery domain's admission
    /// condition.
    fn adversarial_moduli() -> Vec<Vec<Limb>> {
        vec![
            vec![0xffff_ffff_ffff_fffd],
            vec![0xffff_ffff_ffff_ffff],
            vec![1, 1],
            vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211],
            vec![0xffff_ffff_ffff_ffff; 4],
        ]
    }

    /// Exponent shapes at a modulus' public width: zero, one, all-ones and a
    /// full-width top bit, followed by a pseudorandom sweep.
    fn adversarial_exponents(width: usize) -> Vec<Vec<Limb>> {
        let mut out = vec![
            vec![0u64; width],
            {
                let mut e = vec![0u64; width];
                e[0] = 1;
                e
            },
            vec![u64::MAX; width],
            {
                let mut e = vec![0u64; width];
                e[width - 1] = 1 << 63;
                e
            },
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ width as u64;
        for _ in 0..4 {
            let mut e: Vec<Limb> = (0..width).map(|_| xorshift(&mut state)).collect();
            e[width - 1] |= 1 << 63;
            out.push(e);
        }
        out
    }

    /// Base shapes: zero, one, two and the widest value the public width admits.
    fn adversarial_bases(width: usize) -> Vec<Vec<Limb>> {
        vec![vec![0u64], vec![1u64], vec![2u64], vec![u64::MAX; width]]
    }

    /// PFP-1's correctness differential: over an adversarial operand population,
    /// a prepared context answers exactly what the unprepared ladder and the
    /// variable-time core answer, for both Montgomery entry points.
    #[test]
    fn a_prepared_domain_matches_the_unprepared_ladder_over_adversarial_operands() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        let mut cases = 0usize;
        for m_limbs in adversarial_moduli() {
            let width = m_limbs.len();
            // SAFETY: every object is created, used and released inside this test.
            unsafe {
                let m = new_owned(m_limbs.clone(), 0);
                BN_set_flags(m, BN_FLG_CONSTTIME);
                let mont = BN_MONT_CTX_new();
                assert!(!mont.is_null());
                assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
                for e_limbs in adversarial_exponents(width) {
                    let e = new_owned(e_limbs.clone(), 0);
                    for a_limbs in adversarial_bases(width) {
                        let a = new_owned(a_limbs.clone(), 0);
                        let Some(expected_limbs) = mod_exp_core(&a_limbs, &e_limbs, &m_limbs)
                        else {
                            unreachable!("the variable-time oracle answers every case");
                        };
                        let expected = new_owned(expected_limbs, 0);
                        for consttime_only in [false, true] {
                            let unprepared = BN_new();
                            let prepared = BN_new();
                            let ok_unprepared = if consttime_only {
                                BN_mod_exp_mont_consttime(
                                    unprepared,
                                    a,
                                    e,
                                    m,
                                    NULL,
                                    core::ptr::null_mut(),
                                )
                            } else {
                                BN_mod_exp_mont(unprepared, a, e, m, NULL, core::ptr::null_mut())
                            };
                            let ok_prepared = if consttime_only {
                                BN_mod_exp_mont_consttime(prepared, a, e, m, NULL, mont)
                            } else {
                                BN_mod_exp_mont(prepared, a, e, m, NULL, mont)
                            };
                            assert_eq!(ok_unprepared, 1, "unprepared m={m_limbs:?}");
                            assert_eq!(ok_prepared, 1, "prepared m={m_limbs:?}");
                            assert_eq!(BN_ucmp(prepared, unprepared), 0, "prepared vs unprepared");
                            assert_eq!(BN_ucmp(prepared, expected), 0, "prepared vs oracle");
                            cases += 1;
                            BN_free(unprepared);
                            BN_free(prepared);
                        }
                        BN_free(expected);
                        BN_free(a);
                    }
                    BN_free(e);
                }
                BN_MONT_CTX_free(mont);
                BN_free(m);
            }
        }
        assert!(
            cases >= 100,
            "the population must be exercised, got {cases}"
        );
    }

    /// PFP-40: the blinding entry point's exponent-width ladder is the same
    /// function as the modulus-width ladder with a different loop bound. Over
    /// adversarial moduli and public exponents of several widths, both answer
    /// the variable-time oracle exactly. The width is a public exponent length on
    /// this path; the secret base never selects the schedule.
    #[test]
    fn the_public_exponent_ladder_matches_the_modulus_width_ladder() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        let mut cases = 0usize;
        for m_limbs in adversarial_moduli() {
            let m_width = m_limbs.len();
            // SAFETY: every object is created, used and released inside this test.
            unsafe {
                let m = new_owned(m_limbs.clone(), 0);
                BN_set_flags(m, BN_FLG_CONSTTIME);
                let mont = BN_MONT_CTX_new();
                assert!(!mont.is_null());
                assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
                for e_width in [1usize, 2, m_width] {
                    if e_width > m_width {
                        continue;
                    }
                    for e_limbs in adversarial_exponents(e_width) {
                        let e = new_owned(e_limbs.clone(), 0);
                        for a_limbs in adversarial_bases(m_width) {
                            let a = new_owned(a_limbs.clone(), 0);
                            let Some(expected_limbs) = mod_exp_core(&a_limbs, &e_limbs, &m_limbs)
                            else {
                                unreachable!("the variable-time oracle answers every case");
                            };
                            let expected = new_owned(expected_limbs, 0);
                            let narrow = BN_new();
                            let wide = BN_new();
                            assert_eq!(
                                bn_mod_exp_mont_impl(
                                    narrow,
                                    a,
                                    e,
                                    m,
                                    mont,
                                    LadderWidth::PublicExponent,
                                ),
                                1,
                                "public-exponent ladder m={m_limbs:?} e_width={e_width}"
                            );
                            assert_eq!(BN_mod_exp_mont(wide, a, e, m, NULL, mont), 1);
                            assert_eq!(BN_ucmp(narrow, wide), 0, "narrow vs modulus width");
                            assert_eq!(BN_ucmp(narrow, expected), 0, "narrow vs oracle");
                            cases += 1;
                            BN_free(narrow);
                            BN_free(wide);
                            BN_free(expected);
                            BN_free(a);
                        }
                        BN_free(e);
                    }
                }
                BN_MONT_CTX_free(mont);
                BN_free(m);
            }
        }
        assert!(
            cases >= 100,
            "the population must be exercised, got {cases}"
        );
    }

    /// The packed code `ERR_peek_error` reports for the local refusal site.
    fn refusal_packed() -> c_ulong {
        ((ERR_LIB_BN as c_ulong) << 23) | (BN_R_INVALID_RANGE as c_ulong & 0x7f_ffff)
    }

    /// A supplied context whose modulus differs — at the same width and at a
    /// different width — is refused, and the refusal is observable on the error
    /// queue rather than a silent recomputation.
    #[test]
    fn a_context_for_another_modulus_is_refused() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object is created, used and released inside this test.
        unsafe {
            let a = word(3);
            let p = word(5);
            let m = word(0xffff_ffff_ffff_fffd);
            let other_same_width = word(0xffff_ffff_ffff_fffb);
            let other_narrow = word(0xffff_fff9);
            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, other_same_width, NULL), 1);
            let r = BN_new();

            for wrong in [m, other_narrow] {
                ERR_clear_error();
                assert_eq!(
                    BN_mod_exp_mont_consttime(r, a, p, wrong, NULL, mont),
                    0,
                    "a context for another modulus must be refused"
                );
                assert_eq!(ERR_peek_error(), refusal_packed());
            }

            // `BN_mod_exp_mont` validates a supplied context even when its
            // dispatch would not use Montgomery form.
            ERR_clear_error();
            assert_eq!(BN_mod_exp_mont(r, a, p, m, NULL, mont), 0);
            assert_eq!(ERR_peek_error(), refusal_packed());

            for b in [r, m, a, p, other_same_width, other_narrow] {
                BN_free(b);
            }
            BN_MONT_CTX_free(mont);
        }
    }

    /// A context whose recorded radix or reduction-kernel identity differs is
    /// refused before any modulus limb is read.
    #[test]
    fn a_context_for_another_representation_is_refused() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object is created, used and released inside this test.
        unsafe {
            let a = word(3);
            let p = word(5);
            let m = word(0xffff_ffff_ffff_fffd);
            let r = BN_new();

            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
            (*mont).radix_bits = 32;
            ERR_clear_error();
            assert_eq!(BN_mod_exp_mont_consttime(r, a, p, m, NULL, mont), 0);
            assert_eq!(ERR_peek_error(), refusal_packed());
            BN_MONT_CTX_free(mont);

            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
            (*mont).backend = MontBackend::TestMismatch;
            ERR_clear_error();
            assert_eq!(BN_mod_exp_mont_consttime(r, a, p, m, NULL, mont), 0);
            assert_eq!(ERR_peek_error(), refusal_packed());
            BN_MONT_CTX_free(mont);

            // A fresh, never-prepared context is not a prepared domain.
            let unset = BN_MONT_CTX_new();
            ERR_clear_error();
            assert_eq!(BN_mod_exp_mont_consttime(r, a, p, m, NULL, unset), 0);
            assert_eq!(ERR_peek_error(), refusal_packed());
            BN_MONT_CTX_free(unset);

            for b in [r, m, a, p] {
                BN_free(b);
            }
        }
    }

    /// Reuse is load-bearing: the prepared path reaches fewer fallible-allocation
    /// sites than the unprepared path for the same operation (the mutation-control
    /// direction).
    #[test]
    fn a_prepared_domain_removes_the_precomputation_allocations() {
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object is created, used and released inside this test.
        unsafe {
            let m = new_owned(vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211], 0);
            let a = new_owned(vec![0xdead_beef_0bad_f00d, 1], 0);
            let p = new_owned(vec![0x0123_4567_89ab_cdef, 0x7edc_ba98_7654_3211], 0);
            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);
            let r = BN_new();

            let unprepared = {
                let _count = crate::bn::alloc::test_fail::count_start();
                assert_eq!(
                    BN_mod_exp_mont_consttime(r, a, p, m, NULL, core::ptr::null_mut()),
                    1
                );
                crate::bn::alloc::test_fail::counted()
            };
            let prepared = {
                let _count = crate::bn::alloc::test_fail::count_start();
                assert_eq!(BN_mod_exp_mont_consttime(r, a, p, m, NULL, mont), 1);
                crate::bn::alloc::test_fail::counted()
            };
            assert!(
                prepared < unprepared,
                "reuse must remove allocations: prepared={prepared} unprepared={unprepared}"
            );

            for b in [r, a, p, m] {
                BN_free(b);
            }
            BN_MONT_CTX_free(mont);
        }
    }

    /// The prepared modulus is secret-owned: releasing the context cleanses it,
    /// and a copied context is an independent, equally usable domain.
    #[test]
    fn a_prepared_domain_is_cleansed_on_release_and_survives_a_copy() {
        use crate::bn::secret::drop_probe;
        const NULL: *mut BnCtx = core::ptr::null_mut();
        // SAFETY: every object is created, used and released inside this test.
        unsafe {
            let m = new_owned(vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211], 0);
            let a = word(3);
            let p = word(5);
            let mont = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_set(mont, m, NULL), 1);

            let copy = BN_MONT_CTX_new();
            assert_eq!(BN_MONT_CTX_copy(copy, mont), copy);
            let with_copy = BN_new();
            let with_original = BN_new();
            assert_eq!(BN_mod_exp_mont_consttime(with_copy, a, p, m, NULL, copy), 1);
            assert_eq!(
                BN_mod_exp_mont_consttime(with_original, a, p, m, NULL, mont),
                1
            );
            assert_eq!(BN_ucmp(with_copy, with_original), 0);

            // The copy's modulus is a separately allocated, cleansed buffer.
            let ptr = (*copy).n.as_ptr();
            drop_probe::arm(ptr);
            BN_MONT_CTX_free(copy);
            let Some(observed) = drop_probe::take() else {
                unreachable!("the modulus Drop must be observed");
            };
            assert!(
                observed.nonzero_before > 0,
                "the modulus must hold live data"
            );
            assert_eq!(observed.nonzero_bytes, 0, "the modulus must be cleansed");

            for b in [with_copy, with_original, a, p, m] {
                BN_free(b);
            }
            BN_MONT_CTX_free(mont);
        }
    }
}

// ----------------------------------------------------------------------
// ETP-4: bounded verification of the fixed-width REDC kernels.
//
// This module is compiled only under `cfg(test)`. It exercises the two
// production REDC implementations directly:
//
//   * `mont_mul_fallible` (schoolbook product + REDC; the kernel behind
//     `BN_to_montgomery`, `BN_mod_mul_montgomery`, `BN_MONT_CTX_set` and the
//     constant-time ladder), whose contract is `a, b < m`;
//   * `mont_reduce` (the general reduction behind `BN_from_montgomery` and the
//     wide-operand branches), whose contract is `r < m * R`.
//
// The oracle is an independent path through `limbs::{mul, rem}` — the
// variable-time bignum reference — never REDC itself. Correctness is checked
// as the defining congruence `out * R == input (mod m)` plus the canonical
// bound `out < m`. That is exactly the property REDC must establish; it does
// not assume a particular quotient or intermediate.
//
// Exhaustive domain: every one-limb modulus in `ETP4_EXHAUSTIVE_MODULI` with
// every ordered pair of residues, i.e. the *whole* residue range for those
// moduli. Sampled domain: the boundary moduli at one and two limbs, with the
// declared populations enumerated in the methods below.
// ----------------------------------------------------------------------

#[cfg(test)]
mod etp4_verification {
    use super::*;
    use crate::bn::arith::mont_mul_fallible;
    use crate::bn::limbs;

    /// Deterministic pseudo-random limb source for the sampled populations.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn seed_from(limbs: &[Limb]) -> u64 {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for &l in limbs {
            state ^= l;
            state = state.wrapping_mul(0x100_0000_01b3);
        }
        state | 1
    }

    /// A little-endian limb vector padded to `n` limbs.
    fn pad(value: &[Limb], n: usize) -> Vec<Limb> {
        let mut out = vec![0u64; n];
        let take = value.len().min(n);
        out[..take].copy_from_slice(&value[..take]);
        out
    }

    /// `v * R` with `R = B^n`, as a limb vector.
    fn times_r(v: &[Limb], n: usize) -> Vec<Limb> {
        let mut out = vec![0u64; n];
        out.extend_from_slice(v);
        out
    }

    /// The canonical bound plus the defining congruence, for one REDC output.
    fn assert_reduced(out: &[Limb], m: &[Limb], input: &[Limb], context: &str) {
        assert_eq!(
            limbs::cmp(out, m),
            core::cmp::Ordering::Less,
            "{context}: output is not canonical (out={out:?} m={m:?})"
        );
        let lhs = limbs::rem(&times_r(out, m.len()), m);
        let rhs = limbs::rem(input, m);
        assert_eq!(
            limbs::cmp(&lhs, &rhs),
            core::cmp::Ordering::Equal,
            "{context}: out * R != input (mod m); out={out:?} input={input:?} m={m:?}"
        );
    }

    /// One-limb moduli whose *whole* residue square is enumerated.
    const ETP4_EXHAUSTIVE_MODULI: [u64; 16] = [
        3, 5, 7, 9, 11, 13, 15, 17, 31, 33, 63, 65, 127, 129, 255, 257,
    ];

    /// One-limb boundary moduli: top bit set, top bit clear, near-maximum and
    /// mixed patterns, all odd.
    const ETP4_ONE_LIMB_BOUNDARY: [u64; 7] = [
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0001,
        0x8000_0000_0000_0003,
        0xffff_0000_0000_0001,
        0xffff_ffff_ffff_fffd,
        0x1234_5678_9abc_def1,
        0xffff_ffff_ffff_ffff,
    ];

    /// Two-limb boundary moduli: padded one-limb, limb boundary, top bit clear,
    /// top bit set, near-maximum, mixed and all-ones. All odd.
    fn etp4_two_limb_moduli() -> Vec<Vec<Limb>> {
        // Every modulus is normalised (non-zero top limb), odd and greater than
        // one, which is the representation invariant the bignum reference and the
        // Montgomery domain both require.
        vec![
            vec![1, 1],
            vec![0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff],
            vec![0x8000_0000_0000_0001, 0x8000_0000_0000_0000],
            vec![0xffff_ffff_ffff_fffd, 0xffff_ffff_ffff_ffff],
            vec![0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3211],
            vec![0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff],
        ]
    }

    /// A one-limb operand population: the declared boundary values followed by
    /// a deterministic pseudo-random sweep reduced into `[0, m)`.
    fn one_limb_population(m: u64) -> Vec<u64> {
        let mut values = vec![0, 1, 2, m - 1, m - 2, m >> 1];
        let mut state = seed_from(&[m]);
        for _ in 0..26 {
            values.push(xorshift(&mut state) % m);
        }
        values
    }

    /// Exhaustive one-limb Montgomery multiplication: every ordered pair of
    /// residues for every modulus in `ETP4_EXHAUSTIVE_MODULI`.
    #[test]
    fn etp4_mont_mul_one_limb_exhaustive() {
        let mut cases = 0usize;
        for &m in &ETP4_EXHAUSTIVE_MODULI {
            assert!(m > 1 && m & 1 == 1, "admission: m must be odd and > 1");
            let n0 = inverse_word(m);
            let modulus = [m];
            for a in 0..m {
                for b in 0..m {
                    let Some(out) = mont_mul_fallible(&[a], &[b], &modulus, n0) else {
                        unreachable!("a one-limb allocation succeeds")
                    };
                    assert_eq!(out.len(), 1, "one-limb result width");
                    assert_reduced(
                        &out,
                        &modulus,
                        &limbs::mul(&[a], &[b]),
                        "mont_mul exhaustive",
                    );
                    // The same congruence over u128, independent of `limbs`.
                    let lhs = ((out[0] as u128) << 64) % (m as u128);
                    let rhs = ((a as u128) * (b as u128)) % (m as u128);
                    assert_eq!(lhs, rhs, "mont_mul exhaustive u128 congruence");
                    cases += 1;
                }
            }
        }
        std::eprintln!("ETP4 mont_mul one-limb exhaustive: cases={cases}");
        assert_eq!(cases, 175_056, "the declared exhaustive domain changed");
    }

    /// Sampled one-limb Montgomery multiplication over the boundary moduli.
    #[test]
    fn etp4_mont_mul_one_limb_boundary() {
        let mut cases = 0usize;
        for &m in &ETP4_ONE_LIMB_BOUNDARY {
            assert!(m & 1 == 1);
            let n0 = inverse_word(m);
            let modulus = [m];
            let values = one_limb_population(m);
            assert_eq!(values.len(), 32);
            for &a in &values {
                for &b in &values {
                    let Some(out) = mont_mul_fallible(&[a], &[b], &modulus, n0) else {
                        unreachable!("a one-limb allocation succeeds")
                    };
                    assert_reduced(&out, &modulus, &limbs::mul(&[a], &[b]), "mont_mul boundary");
                    let lhs = ((out[0] as u128) << 64) % (m as u128);
                    let rhs = ((a as u128) * (b as u128)) % (m as u128);
                    assert_eq!(lhs, rhs);
                    cases += 1;
                }
            }
        }
        std::eprintln!("ETP4 mont_mul one-limb boundary: cases={cases}");
        assert_eq!(cases, 7 * 32 * 32);
    }

    /// One-limb `mont_reduce` population, including non-canonical inputs `m`
    /// and `m + 1`, the top of the admitted range (`m * R - 1`), and operands
    /// spanning the final conditional subtraction.
    fn one_limb_reduce_population(m: u64) -> Vec<Vec<Limb>> {
        let r_minus_1 = u64::MAX;
        let m_times_r_minus_1 = (m as u128) * (1u128 << 64) - 1;
        // `m + 1` is one limb unless the modulus is the largest one-limb value,
        // in which case it is `R` and needs a second limb.
        let m_plus_1 = if m == u64::MAX {
            vec![0, 1]
        } else {
            vec![m + 1]
        };
        let mut values: Vec<Vec<Limb>> = vec![
            vec![0],
            vec![1],
            vec![2],
            vec![m - 1],
            vec![m],
            m_plus_1,
            vec![r_minus_1, 0],
            vec![0, 1],
            vec![1, 1],
            vec![m - 1, 1],
            vec![m_times_r_minus_1 as u64, (m_times_r_minus_1 >> 64) as u64],
        ];
        let mut state = seed_from(&[m, 0x5eed]);
        let highs = [0u64, 1, 2, m - 2, m - 1];
        for &high in &highs {
            let low = xorshift(&mut state);
            values.push(vec![low, high]);
        }
        for _ in 0..15 {
            let low = xorshift(&mut state);
            let high = xorshift(&mut state) % m;
            values.push(vec![low, high]);
        }
        values
    }

    /// Sampled one-limb general reduction over the full admitted input range.
    #[test]
    fn etp4_mont_reduce_one_limb() {
        let mut cases = 0usize;
        let moduli: Vec<u64> = ETP4_EXHAUSTIVE_MODULI
            .iter()
            .chain(ETP4_ONE_LIMB_BOUNDARY.iter())
            .copied()
            .collect();
        for &m in &moduli {
            let n0 = inverse_word(m);
            let modulus = [m];
            for input in one_limb_reduce_population(m) {
                // The declared precondition is `input < m * R`.
                let value = (input.first().copied().unwrap_or(0) as u128)
                    + ((input.get(1).copied().unwrap_or(0) as u128) << 64);
                assert!(value < (m as u128) * (1u128 << 64));
                let Some(out) = mont_reduce(&input, &modulus, n0) else {
                    unreachable!("a one-limb allocation succeeds")
                };
                assert_reduced(&out, &modulus, &input, "mont_reduce one-limb");
                cases += 1;
            }
        }
        std::eprintln!("ETP4 mont_reduce one-limb: cases={cases}");
        assert_eq!(cases, moduli.len() * 31);
    }

    /// Two-limb operand population, every value reduced into `[0, m)`.
    fn two_limb_population(m: &[Limb]) -> Vec<Vec<Limb>> {
        let mut values = vec![
            vec![0, 0],
            vec![1, 0],
            vec![2, 0],
            pad(&limbs::sub(m, &[1]), 2),
            pad(&limbs::sub(m, &[2]), 2),
            pad(&limbs::div_rem_small(m, 2).0, 2),
        ];
        let mut state = seed_from(m);
        for _ in 0..16 {
            let raw = vec![xorshift(&mut state), xorshift(&mut state)];
            let Some(reduced) = limbs::rem_fallible(&raw, m) else {
                unreachable!("a two-limb remainder succeeds")
            };
            values.push(pad(&reduced, 2));
        }
        values
    }

    /// Sampled two-limb Montgomery multiplication.
    #[test]
    fn etp4_mont_mul_two_limb() {
        let mut cases = 0usize;
        for modulus in etp4_two_limb_moduli() {
            assert_eq!(modulus.len(), 2);
            assert!(modulus[0] & 1 == 1, "admission: m must be odd");
            let n0 = inverse_word(modulus[0]);
            let values = two_limb_population(&modulus);
            assert_eq!(values.len(), 22);
            for a in &values {
                for b in &values {
                    assert_eq!(limbs::cmp(a, &modulus), core::cmp::Ordering::Less);
                    assert_eq!(limbs::cmp(b, &modulus), core::cmp::Ordering::Less);
                    let Some(out) = mont_mul_fallible(a, b, &modulus, n0) else {
                        unreachable!("a two-limb allocation succeeds")
                    };
                    let product = limbs::mul(a, b);
                    assert_reduced(&out, &modulus, &product, "mont_mul two-limb");
                    cases += 1;
                }
            }
        }
        std::eprintln!("ETP4 mont_mul two-limb: cases={cases}");
        assert_eq!(cases, 6 * 22 * 22);
    }

    /// Two-limb reduction population over the admitted range `r < m * R`.
    fn two_limb_reduce_population(m: &[Limb]) -> Vec<Vec<Limb>> {
        let m_minus_1 = limbs::sub(m, &[1]);
        let mut values: Vec<Vec<Limb>> = vec![
            vec![0, 0, 0, 0],
            vec![1, 0, 0, 0],
            vec![2, 0, 0, 0],
            pad(&m_minus_1, 4),
            pad(m, 4),
            vec![u64::MAX, u64::MAX, 0, 0],
            vec![0, 0, 1, 0],
            vec![1, 0, 1, 0],
        ];
        // `m * R - 1`
        let mut top = vec![u64::MAX, u64::MAX];
        top.extend_from_slice(&m_minus_1);
        values.push(top);
        let mut state = seed_from(&[m[0], m[1], 0xbeef]);
        for _ in 0..20 {
            let raw_high = vec![xorshift(&mut state), xorshift(&mut state)];
            let Some(high) = limbs::rem_fallible(&raw_high, m) else {
                unreachable!("a two-limb remainder succeeds")
            };
            let mut r = vec![xorshift(&mut state), xorshift(&mut state)];
            r.extend_from_slice(&pad(&high, 2));
            values.push(r);
        }
        values
    }

    /// Sampled two-limb general reduction.
    #[test]
    fn etp4_mont_reduce_two_limb() {
        let mut cases = 0usize;
        for modulus in etp4_two_limb_moduli() {
            let n0 = inverse_word(modulus[0]);
            for input in two_limb_reduce_population(&modulus) {
                assert_eq!(input.len(), 4);
                let Some(out) = mont_reduce(&input, &modulus, n0) else {
                    unreachable!("a two-limb allocation succeeds")
                };
                assert_reduced(&out, &modulus, &input, "mont_reduce two-limb");
                cases += 1;
            }
        }
        std::eprintln!("ETP4 mont_reduce two-limb: cases={cases}");
        assert_eq!(cases, 6 * 29);
    }
}
