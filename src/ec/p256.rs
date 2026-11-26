//! Fixed-width P-256 field engine (PFP-2).
//!
//! The programme's §3.2 asks for three **distinct** representation types:
//! [`P256Field`] (residues modulo the field prime `p`), [`P256Scalar`] (residues
//! modulo the group order `q`) and [`P256Projective`] (a projective point over
//! `p`). Four limbs in common does not make them interchangeable, so no
//! conversion exists between the field and the order, and the projective type is
//! built only from the field type.
//!
//! ## The interface
//!
//! [`FieldKernel`] exposes `mul`, `sqr`, `add`, `sub`, `reduce`, `select`/`cswap`,
//! `from_limbs` and `to_limbs`. Three kernels implement it for the field:
//!
//! | kernel | representation | multiply | reduction |
//! |---|---|---|---|
//! | [`Mont`] | Montgomery, `R = 2^256` | schoolbook | REDC |
//! | [`Solinas`] | ordinary canonical | schoolbook | nine-fold Solinas |
//! | [`Arch`] | ordinary canonical | `mulx`/`adcx` (x86-64), `u128` (AArch64) | nine-fold Solinas |
//!
//! [`P256Scalar`] uses [`Mont`] over the order domain; the order has no Solinas
//! shape, and inventing one would be a second unproved reduction. The field and
//! order kernels are the same trait implementation instantiated over different
//! [`Domain`]s, so the interface is one interface, not two.
//!
//! ## Invariants
//!
//! * **Canonical representation.** Every stored value is the kernel's encoding of
//!   a residue in `[0, p)` (or `[0, q)`); every operation returns such a value.
//!   `to_limbs` is the only observation, and it yields the ordinary canonical
//!   residue, which is `< p` (`< q`).
//! * **Secret ownership.** [`SecretLimbs4`] is the only storage. Its `Drop`
//!   performs the crate's volatile cleanse over all 32 bytes on normal return,
//!   early return and unwind. [`SecretWords`] guards every wide intermediate the
//!   same way. The engine allocates nothing: every value is a fixed `[u64; 4]`
//!   and every operation is stack-resident.
//! * **No value-dependent control flow.** Add, subtract, compare, select and
//!   conditional subtraction are masks. Borrows and carries are read from the
//!   high half of a 128-bit operation rather than from a comparison, and the
//!   select masks pass an optimisation barrier, so the release optimiser has no
//!   predicate on a secret limb that it can lower to a conditional branch (this
//!   is measured by ctgrind and the binary branch audit, not assumed). The
//!   Solinas fold's iteration count is a
//!   constant, its carry pass is a fixed nine-step loop, and its final correction
//!   is two masked subtractions. The Montgomery reduction's loops are fixed
//!   counts and its final subtraction is a mask. No `debug_assert!` is used as a
//!   safety argument; every bound is stated in prose beside the code.
//! * **Fallible allocation.** There is none to do: the engine has no allocator
//!   call, so it cannot abort and cannot fail. The surrounding `BIGNUM`
//!   conversion points keep their existing fallible allocation.
//!
//! ## Kernel selection
//!
//! [`select_field_kernel`] chooses once per scalar multiplication from public
//! data only. The modulus identity is fixed by this engine (P-256), and the CPU
//! capability bits are the authority's `nistz256` predicate; no value is ever
//! read. The measured comparison selects [`Mont`] as the default on the admitted
//! venue, where it beat both [`Solinas`] and [`Arch`] on `mul`, `sqr`, `reduce`
//! and the end-to-end ladder. [`Arch`] is admissible only after [`Arch::new`] has
//! verified BMI2 and ADX, so the intrinsic call's target-feature precondition is
//! established by construction; it is measured but not selected, because a
//! selection that publishes a measured regression would violate the programme's
//! §11 admission rule. Evidence does not inherit across targets: changing the
//! policy for another target requires that target's own measurement.
//!
//! **Recorded divergence.** The authority masks its capability words by the
//! `OPENSSL_ia32cap` environment variable in `OPENSSL_cpuid_setup`. This crate
//! reads the same CPUID bits directly and does not model that mask; the
//! divergence is recorded by `RT-CPU-CAPABILITY` and is not introduced here. On
//! a masked host the two sides may therefore select different arms, which is a
//! selection difference, not an arithmetic one.
//!
//! ## Bounds, per kernel
//!
//! P-256's prime is `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`, so
//! `2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)`. Write a 512-bit product as
//! `lo + hi·2^256` with `lo, hi < 2^256`. One fold replaces it by
//! `lo + hi·(2^224 - 2^192 - 2^96 + 1)`, which is non-negative because
//! `2^224 > 2^192 + 2^96`, and below `2^256 + 2^480 < 2^481`. A fold's lane
//! receives at most five 64-bit contributions (`lo`, `hi`, `hi·2^224`,
//! `-hi·2^192`, `-hi·2^96`), so each `i128` lane is below `5·2^64` in magnitude
//! and the running prefix below `2^70`: neither overflows the 127-bit signed
//! workspace. Because the total is non-negative and below `2^481`, the single
//! nine-step carry pass reconstructs its exact radix-`2^64` digits and the ninth
//! limb stays zero. Each application shrinks the part above bit 256 by 32 bits;
//! after nine folds the value is below `2^257`, and `2^257 < 3p` because
//! `p > 2^255`, so two masked subtractions of `p` leave it below `p`.
//!
//! For Montgomery, `a, b < p` makes the schoolbook product `< p^2 < R·p`, so
//! REDC's result `(a·b + u·p)/R` is below `2p` and one masked subtraction is
//! complete. The conversion `x·R^2 mod p` for `x < R` is likewise below `2p`.
//! The trait-level `reduce` accepts any 512-bit value, whose REDC result is
//! below `2^256 + p < 2^257 < 3p`, so it performs two masked subtractions. Each
//! REDC inner term is `u·m[j] + t + carry ≤ (2^64-1)^2 + 2(2^64-1) = 2^128-1`,
//! which the `u128` accumulator holds exactly; the carry-out of the propagation
//! loop is bounded by the 9-limb accumulator's spare top limb.
//!
//! The architecture kernel uses the same Solinas reduction, so only its multiply
//! needs a bound. On x86-64 `multiply` composes a 64×64→128 product with two
//! `addcarry` chains; the column total is the ordinary schoolbook sum, which is
//! below `2^512`, and the high word `hi + c1 + c2` cannot overflow because that
//! total is below `2^128` for each column. On AArch64 the `u128` product is the
//! same arithmetic the portable path uses, lowered by the compiler to `mul` and
//! `umulh`.
//!
//! ## What this module is not
//!
//! A performance result never discharges a timing obligation. The engine's
//! constant-time structure is argued here and audited by ctgrind and the binary
//! branch audit at the receipt's digest; neither instrument proves constant
//! constant time, and this module claims neither a frontier result nor `SAFE_COMPATIBLE`.

// The §3.2 interface is complete, but the production ladder consumes only the
// field kernel and the ladder state. The scalar, projective and ABI conversion
// points are exercised by this module's tests and are the interface PFP-3 and
// PFP-4 consume; allowing dead-code here is a statement about consumers, not a
// licence to leave unused internals.
#![allow(dead_code)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::bn::limbs::Limb;
use crate::runtime::mem::cleanse;

const LIMBS: usize = 4;

/// P-256's field prime `2^256 - 2^224 + 2^192 + 2^96 - 1`, little-endian limbs.
pub(crate) const FIELD_MODULUS: [Limb; LIMBS] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256's group order, little-endian limbs.
pub(crate) const ORDER_MODULUS: [Limb; LIMBS] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// `-p^-1 mod 2^64`. `p[0]` is all ones, whose inverse is itself, so the
/// negated inverse is one.
const FIELD_N0: Limb = 1;

/// `-q^-1 mod 2^64`, checked by `the_modular_constants_are_consistent`.
const ORDER_N0: Limb = 0xCCD1_C8AA_EE00_BC4F;

/// `R^2 mod p` for `R = 2^256`.
const FIELD_R2: [Limb; LIMBS] = [
    0x0000_0000_0000_0003,
    0xFFFF_FFFB_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFE,
    0x0000_0004_FFFF_FFFD,
];

/// `R^2 mod q` for `R = 2^256`.
const ORDER_R2: [Limb; LIMBS] = [
    0x8324_4C95_BE79_EEA2,
    0x4699_799C_49BD_6FA6,
    0x2845_B239_2B6B_EC59,
    0x66E1_2D94_F3D9_5620,
];

/// Folds before the final correction. The bound argument in the module header
/// shows nine leave the value below `2^257`.
const FOLDS: usize = 9;

/// Masked subtractions of the modulus after the folds. Two suffice because
/// `2^257 < 3p`.
const SUBTRACTIONS: usize = 2;

// ---------------------------------------------------------------------------
// Secret storage
// ---------------------------------------------------------------------------

/// Four secret limbs with a volatile wipe on drop.
///
/// This is the only storage the engine uses. `Drop` runs on the normal path, an
/// early return and an unwind, so the wipe is a property of the type rather than
/// of a function that must remember it.
pub(crate) struct SecretLimbs4([Limb; LIMBS]);

impl SecretLimbs4 {
    const fn zero() -> Self {
        Self([0; LIMBS])
    }

    fn new(limbs: [Limb; LIMBS]) -> Self {
        Self(limbs)
    }

    fn limbs(&self) -> &[Limb; LIMBS] {
        &self.0
    }

    fn limbs_mut(&mut self) -> &mut [Limb; LIMBS] {
        &mut self.0
    }

    fn copy_from(&mut self, other: &Self) {
        self.0.copy_from_slice(&other.0);
    }
}

impl Drop for SecretLimbs4 {
    fn drop(&mut self) {
        // Test-only observation. The limbs are read only when the caller armed the
        // probe, which no ctgrind case does: the instrumentation must never add a
        // secret-dependent branch to the path it is auditing. Inside the armed
        // case both reductions are branchless (a `setne`-style sum and an OR fold),
        // so even the dedicated cleansing test does not branch on a limb.
        #[cfg(test)]
        let armed = drop_probe::armed();
        #[cfg(test)]
        let nonzero_before = if armed {
            self.0.iter().map(|&v| usize::from(v != 0)).sum::<usize>()
        } else {
            0
        };
        // SAFETY: `self.0` is a live array of four `u64`, i.e. 32 writable bytes
        // for the duration of `Drop`, and `drop` has exclusive access to it.
        unsafe { cleanse(self.0.as_mut_ptr().cast::<u8>(), LIMBS * 8) }
        #[cfg(test)]
        if armed {
            drop_probe::record(
                32,
                nonzero_before,
                self.0.iter().fold(0u64, |acc, &v| acc | v) == 0,
            );
        }
    }
}

/// A fixed run of secret words with a volatile wipe on drop.
///
/// Used for the schoolbook product, the Solinas accumulator, the REDC
/// accumulator and the masked-subtraction difference. The wipe makes every
/// intermediate a short-lived owner rather than an unnamed stack temporary.
struct SecretWords<const N: usize>([Limb; N]);

impl<const N: usize> SecretWords<N> {
    const fn zero() -> Self {
        Self([0; N])
    }

    fn words(&self) -> &[Limb; N] {
        &self.0
    }

    fn words_mut(&mut self) -> &mut [Limb; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretWords<N> {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live array of `N` `u64`, i.e. `N * 8` writable
        // bytes for the duration of `Drop`, and `drop` has exclusive access.
        unsafe { cleanse(self.0.as_mut_ptr().cast::<u8>(), N * 8) }
    }
}

/// The Solinas fold's signed lane accumulator, wiped on drop.
struct SecretLanes([i128; FOLDS]);

impl SecretLanes {
    const fn zero() -> Self {
        Self([0; FOLDS])
    }
}

impl Drop for SecretLanes {
    fn drop(&mut self) {
        // SAFETY: the array is live for `FOLDS * 16` writable bytes during
        // `Drop`, and `drop` has exclusive access.
        unsafe { cleanse(self.0.as_mut_ptr().cast::<u8>(), FOLDS * 16) }
    }
}

/// Ordinary canonical limbs leaving the engine.
///
/// A distinct owner so the caller cannot accidentally pass a residue to a
/// routine expecting a different domain, and so the copy is cleansed on drop.
pub(crate) struct Canonical4([Limb; LIMBS]);

impl Canonical4 {
    fn zero() -> Self {
        Self([0; LIMBS])
    }

    pub(crate) fn as_limbs(&self) -> &[Limb] {
        &self.0
    }

    fn limbs_mut(&mut self) -> &mut [Limb; LIMBS] {
        &mut self.0
    }

    fn be_bytes(&self) -> [u8; 32] {
        limbs_to_be(&self.0)
    }
}

impl Drop for Canonical4 {
    fn drop(&mut self) {
        // SAFETY: the array is live for 32 writable bytes during `Drop`.
        unsafe { cleanse(self.0.as_mut_ptr().cast::<u8>(), LIMBS * 8) }
    }
}

/// A 32-byte big-endian export of a scalar or field element.
pub(crate) struct Canonical32([u8; 32]);

impl Canonical32 {
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Canonical32 {
    fn drop(&mut self) {
        // SAFETY: the array is live for 32 writable bytes during `Drop`.
        unsafe { cleanse(self.0.as_mut_ptr(), 32) }
    }
}

/// Test-only observation of [`SecretLimbs4`]'s wipe.
#[cfg(test)]
pub(crate) mod drop_probe {
    use core::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static RECORDED: Cell<Option<(usize, usize, bool)>> = const { Cell::new(None) };
    }

    pub(crate) fn arm() {
        ARMED.with(|a| a.set(true));
        RECORDED.with(|r| r.set(None));
    }

    pub(crate) fn armed() -> bool {
        ARMED.with(|a| a.get())
    }

    pub(crate) fn take() -> Option<(usize, usize, bool)> {
        ARMED.with(|a| a.set(false));
        RECORDED.with(|r| r.take())
    }

    pub(super) fn record(len: usize, nonzero_before: usize, zero_after: bool) {
        if ARMED.with(|a| a.get()) {
            RECORDED.with(|r| r.set(Some((len, nonzero_before, zero_after))));
        }
    }
}

// ---------------------------------------------------------------------------
// Domains and the kernel interface
// ---------------------------------------------------------------------------

/// A fixed-width odd modulus the engine can encode.
pub(crate) trait Domain: 'static {
    /// The modulus, little-endian limbs.
    const MODULUS: [Limb; LIMBS];
    /// `-MODULUS^-1 mod 2^64`.
    const N0: Limb;
    /// `R^2 mod MODULUS`, `R = 2^256`.
    const R2: [Limb; LIMBS];
    /// A stable name for diagnostics and tests.
    const LABEL: &'static str;
}

/// The field domain, modulo P-256's prime.
pub(crate) struct FieldDomain;

impl Domain for FieldDomain {
    const MODULUS: [Limb; LIMBS] = FIELD_MODULUS;
    const N0: Limb = FIELD_N0;
    const R2: [Limb; LIMBS] = FIELD_R2;
    const LABEL: &'static str = "p256-field";
}

/// The order domain, modulo P-256's group order.
pub(crate) struct OrderDomain;

impl Domain for OrderDomain {
    const MODULUS: [Limb; LIMBS] = ORDER_MODULUS;
    const N0: Limb = ORDER_N0;
    const R2: [Limb; LIMBS] = ORDER_R2;
    const LABEL: &'static str = "p256-order";
}

/// The one interface the three field kernels implement.
///
/// Every method writes its answer to `out`, which the caller borrows exclusively;
/// the implementations compute into local guards first, so `out` may hold a
/// previous value and the operation is not an alias hazard.
///
// `from_limbs` is the name the programme's §3.2 interface specifies; the kernel
// value is the dispatch token, so the method takes `&self` like its siblings.
#[allow(clippy::wrong_self_convention)]
pub(crate) trait FieldKernel<D: Domain>: 'static {
    /// The kernel's identity, for selection, tests and receipts.
    const ID: KernelId;

    /// Encode arbitrary ordinary limbs (a value below `2^256`, not necessarily
    /// below the modulus) into the kernel representation.
    fn from_limbs(&self, out: &mut [Limb; LIMBS], ordinary: &[Limb; LIMBS]);

    /// Decode a kernel representation into the ordinary canonical residue.
    fn to_limbs(&self, out: &mut [Limb; LIMBS], repr: &[Limb; LIMBS]);

    fn mul(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]);
    fn sqr(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS]);
    fn add(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]);
    fn sub(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]);

    /// The kernel's reduction of an arbitrary 512-bit value. Its output is the
    /// representation of `wide mod MODULUS`, except that Montgomery's reduction
    /// necessarily also multiplies by `R^-1`; each implementation documents the
    /// exact contract, and [`Mont::mul`] composes with it consistently.
    fn reduce(&self, out: &mut [Limb; LIMBS], wide: &[Limb; 8]);

    /// `out = a` when `mask` is all ones, `b` when it is zero.
    fn select(&self, out: &mut [Limb; LIMBS], mask: Limb, a: &[Limb; LIMBS], b: &[Limb; LIMBS]);

    /// Exchange `a` and `b` when `mask` is all ones, leave them when zero.
    fn cswap(&self, mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]);
}

/// A kernel identity. Selection returns one of these; it is never derived from a
/// limb value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelId {
    Mont,
    Solinas,
    Arch,
}

// ---------------------------------------------------------------------------
// Masked primitives
// ---------------------------------------------------------------------------

/// `a - b - borrow`, returning the difference and the 0/1 borrow out.
///
/// The borrow is read from the high half of a 128-bit difference, never from a
/// comparison. A comparison produces an `i1` predicate, and the optimiser is
/// free to lower a predicate on a secret limb to a conditional jump (this is
/// exactly what it did to `mont_reduce_into` at release); a value read from the
/// high half of a subtraction has no predicate to branch on. `borrow` must be
/// zero or one.
#[inline(always)]
fn sub_borrow(a: Limb, b: Limb, borrow: Limb) -> (Limb, Limb) {
    let t = (a as u128)
        .wrapping_sub(b as u128)
        .wrapping_sub(borrow as u128);
    (t as Limb, ((t >> 64) as Limb) & 1)
}

/// `a + b + carry`, returning the sum and the 0/1 carry out.
///
/// As [`sub_borrow`]: the carry is the high half of a 128-bit sum, not a
/// comparison result, so no secret-dependent predicate reaches control flow.
/// `carry` must be zero or one.
#[inline(always)]
fn add_carry(a: Limb, b: Limb, carry: Limb) -> (Limb, Limb) {
    let t = (a as u128)
        .wrapping_add(b as u128)
        .wrapping_add(carry as u128);
    (t as Limb, ((t >> 64) as Limb) & 1)
}

/// An optimisation barrier for a secret-derived mask.
///
/// This is the crate's counterpart of `constant_time.h`'s `value_barrier_*`
/// (see `ec::curve448`): the optimiser is otherwise free to prove the mask is
/// `0`/`!0` and if-convert the masked select into a conditional branch on the
/// secret limb, which is exactly what it did to the reduction at release. The
/// barrier is best-effort, not a guarantee; ctgrind and the binary branch audit
/// measure whether it held at the recorded digest.
#[inline(always)]
fn mask_barrier(mask: Limb) -> Limb {
    core::hint::black_box(mask)
}

/// All ones when `a >= b`, zero otherwise, with no branch.
#[inline(always)]
fn ct_ge(a: &[Limb; LIMBS], b: &[Limb; LIMBS]) -> Limb {
    let mut borrow = 0u64;
    for i in 0..LIMBS {
        let (_, b) = sub_borrow(a[i], b[i], borrow);
        borrow = b;
    }
    borrow.wrapping_sub(1)
}

/// All ones when every limb is zero, zero otherwise, with no branch.
#[inline(always)]
fn ct_is_zero(a: &[Limb; LIMBS]) -> Limb {
    let x = a[0] | a[1] | a[2] | a[3];
    ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// `out = a` when `mask` is all ones, `b` when zero.
#[inline(always)]
fn select_limbs(out: &mut [Limb; LIMBS], mask: Limb, a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
    let mask = mask_barrier(mask);
    for i in 0..LIMBS {
        out[i] = b[i] ^ ((a[i] ^ b[i]) & mask);
    }
}

/// Exchange `a` and `b` when `mask` is all ones.
#[inline(always)]
fn cswap_limbs(mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]) {
    let mask = mask_barrier(mask);
    for i in 0..LIMBS {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// `out = a + b - modulus` when `a + b >= modulus`, else `a + b`, for `a, b <
/// modulus`. `a + b < 2·modulus`, so one conditional subtraction is complete.
///
/// The sum is formed in `out` with the fifth limb held in a local, and the
/// conditional subtraction is a masked in-place subtract. No temporary buffer is
/// allocated on the stack, so there is nothing beyond `out` to cleanse here.
#[inline(always)]
fn add_canonical(out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS], m: &[Limb; LIMBS]) {
    let mut carry = 0u64;
    for i in 0..LIMBS {
        // At most `2*(2^64-1) + 1 < 2^65`: no overflow, checks suppressed as
        // the crate's other secret-bearing arithmetic does.
        let (v, c) = add_carry(a[i], b[i], carry);
        out[i] = v;
        carry = c;
    }

    let mut borrow = 0u64;
    for i in 0..LIMBS {
        let (_, b) = sub_borrow(out[i], m[i], borrow);
        borrow = b;
    }
    // `a + b < 2m`, so when the sum has a fifth limb its low four limbs are
    // below `m`; the final borrow is then one and the sum is the answer.
    let (_, top_borrow) = sub_borrow(carry, 0, borrow);
    let subtract = mask_barrier(top_borrow.wrapping_sub(1));
    let mut c = 0u64;
    for i in 0..LIMBS {
        let (d, ci) = sub_borrow(out[i], m[i] & subtract, c);
        out[i] = d;
        c = ci;
    }
    // `carry - c` is zero by the `a + b < 2m` bound; the answer is `out`.
}

/// `out = a - b + modulus` when `a < b`, else `a - b`, for `a, b < modulus`.
#[inline(always)]
fn sub_canonical(out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS], m: &[Limb; LIMBS]) {
    let mut borrow = 0u64;
    for i in 0..LIMBS {
        let (d, b) = sub_borrow(a[i], b[i], borrow);
        out[i] = d;
        borrow = b;
    }
    let mask = mask_barrier(borrow.wrapping_neg());
    let mut c = 0u64;
    for i in 0..LIMBS {
        let (d, ci) = add_carry(out[i], m[i] & mask, c);
        out[i] = d;
        c = ci;
    }
}

// ---------------------------------------------------------------------------
// Wide products and reductions
// ---------------------------------------------------------------------------

/// `t[0..8] = a · b`, with `t[8] = 0`; `t` is the caller's guarded accumulator.
///
/// The column accumulator is `u128` and its maximum is
/// `(2^64-1)^2 + 2(2^64-1) = 2^128-1`, so none of the arithmetic can overflow;
/// `wrapping_*` keeps the debug profile's overflow check — a conditional jump on
/// secret limbs — out of the multiply.
#[inline(always)]
fn wide_mul_into(t: &mut [Limb; 9], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
    t.fill(0);
    for i in 0..LIMBS {
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let v = (a[i] as u128)
                .wrapping_mul(b[j] as u128)
                .wrapping_add(t[i + j] as u128)
                .wrapping_add(carry as u128);
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        t[i + LIMBS] = carry;
    }
}

/// One P-256 fold of the nine-limb accumulator, in place.
///
/// Replaces `lo + hi·2^256` by `lo + hi·(2^224 - 2^192 - 2^96 + 1)`. `hi·2^32`
/// is formed once as a five-limb value, making the 224- and 96-bit shifts
/// whole-limb offsets from it. The bound argument is in the module header.
#[inline(always)]
fn fold(acc: &mut [Limb; 9], lane: &mut [i128; FOLDS]) {
    let lo = [acc[0], acc[1], acc[2], acc[3]];
    let hi = [acc[4], acc[5], acc[6], acc[7]];
    let hi32 = [
        hi[0] << 32,
        (hi[1] << 32) | (hi[0] >> 32),
        (hi[2] << 32) | (hi[1] >> 32),
        (hi[3] << 32) | (hi[2] >> 32),
        hi[3] >> 32,
    ];

    lane.fill(0);
    for i in 0..LIMBS {
        lane[i] = lane[i]
            .wrapping_add(lo[i] as i128)
            .wrapping_add(hi[i] as i128);
    }
    for i in 0..5 {
        lane[3 + i] = lane[3 + i].wrapping_add(hi32[i] as i128);
    }
    for i in 0..LIMBS {
        lane[3 + i] = lane[3 + i].wrapping_sub(hi[i] as i128);
    }
    for i in 0..5 {
        lane[1 + i] = lane[1 + i].wrapping_sub(hi32[i] as i128);
    }

    // One carry pass. The arithmetic shift supplies the floor division, and
    // `wrapping_*` keeps the debug overflow check off secret-derived lanes.
    let mut carry = 0i128;
    for i in 0..9 {
        let v = lane[i].wrapping_add(carry);
        acc[i] = v as u64;
        carry = v >> 64;
    }
}

/// Two masked subtractions of P-256's prime over the low five limbs, in place.
#[inline(always)]
fn correct_solinas(acc: &mut [Limb; 9]) {
    for _ in 0..SUBTRACTIONS {
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (_, b) = sub_borrow(acc[i], FIELD_MODULUS[i], borrow);
            borrow = b;
        }
        let (_, b) = sub_borrow(acc[4], 0, borrow);
        // All ones when the subtraction did not borrow, i.e. `acc >= p`.
        let subtract = mask_barrier(b.wrapping_sub(1));
        let mut c = 0u64;
        for i in 0..LIMBS {
            let (d, ci) = sub_borrow(acc[i], FIELD_MODULUS[i] & subtract, c);
            acc[i] = d;
            c = ci;
        }
        let (d, _) = sub_borrow(acc[4], 0, c);
        acc[4] = d;
    }
}

/// `acc = wide mod p` by the fixed-sequence Solinas fold, in place.
///
/// `acc[0..8]` holds the input and `acc[8]` is zero on entry.
#[inline(always)]
fn solinas_reduce_into(out: &mut [Limb; LIMBS], acc: &mut [Limb; 9], lanes: &mut SecretLanes) {
    for _ in 0..FOLDS {
        fold(acc, &mut lanes.0);
    }
    correct_solinas(acc);
    out.copy_from_slice(&acc[..LIMBS]);
}

/// Montgomery reduction in place over the guarded accumulator, with
/// `subtractions` masked corrections.
///
/// `subtractions = 1` is complete for a value below `R·m` (the product of two
/// reduced residues, or `x·R^2` with `x < R`): the result is below `2m`.
/// `subtractions = 2` is complete for any 512-bit value: the result is below
/// `2^256 + m < 2^257 < 3m`.
fn mont_reduce_into(
    out: &mut [Limb; LIMBS],
    t: &mut [Limb; 9],
    m: &[Limb; LIMBS],
    n0: Limb,
    subtractions: usize,
) {
    for i in 0..LIMBS {
        let u = t[i].wrapping_mul(n0);
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let v = (u as u128)
                .wrapping_mul(m[j] as u128)
                .wrapping_add(t[i + j] as u128)
                .wrapping_add(carry as u128);
            t[i + j] = v as u64;
            carry = (v >> 64) as u64;
        }
        // Fixed-width carry propagation; no early exit on a secret carry.
        for slot in t[(i + LIMBS)..].iter_mut() {
            let (s, c) = add_carry(*slot, carry, 0);
            *slot = s;
            carry = c;
        }
    }

    for _ in 0..subtractions {
        let mut borrow = 0u64;
        for i in 0..LIMBS {
            let (_, b) = sub_borrow(t[LIMBS + i], m[i], borrow);
            borrow = b;
        }
        let (_, b) = sub_borrow(t[2 * LIMBS], 0, borrow);
        // All ones when the whole value did not borrow, i.e. `t >= m`.
        let subtract = mask_barrier(b.wrapping_sub(1));
        let mut c = 0u64;
        for i in 0..LIMBS {
            let (d, ci) = sub_borrow(t[LIMBS + i], m[i] & subtract, c);
            t[LIMBS + i] = d;
            c = ci;
        }
        let (d, _) = sub_borrow(t[2 * LIMBS], 0, c);
        t[2 * LIMBS] = d;
    }

    out.copy_from_slice(&t[LIMBS..(2 * LIMBS)]);
}

// ---------------------------------------------------------------------------
// The kernels
// ---------------------------------------------------------------------------

/// Unrolled four-limb Montgomery arithmetic with `R = 2^256`.
///
/// This matches the authority's representation, so a domain conversion is one
/// Montgomery multiply rather than a division.
pub(crate) struct Mont<D: Domain> {
    _domain: PhantomData<D>,
}

impl<D: Domain> Default for Mont<D> {
    fn default() -> Self {
        Self {
            _domain: PhantomData,
        }
    }
}

impl<D: Domain> Mont<D> {
    /// One guarded nine-limb accumulator per operation; the masked correction is
    /// in place, so this is the only temporary that needs cleansing.
    #[inline(always)]
    fn mont_mul(out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        wide_mul_into(&mut acc.0, a, b);
        mont_reduce_into(out, &mut acc.0, &D::MODULUS, D::N0, 1);
    }
}

impl<D: Domain> FieldKernel<D> for Mont<D> {
    const ID: KernelId = KernelId::Mont;

    fn from_limbs(&self, out: &mut [Limb; LIMBS], ordinary: &[Limb; LIMBS]) {
        // `x < R` and `R^2 < m`, so the product is below `R·m` and one masked
        // subtraction is complete.
        let mut acc = SecretWords::<9>::zero();
        wide_mul_into(&mut acc.0, ordinary, &D::R2);
        mont_reduce_into(out, &mut acc.0, &D::MODULUS, D::N0, 1);
    }

    fn to_limbs(&self, out: &mut [Limb; LIMBS], repr: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..LIMBS].copy_from_slice(repr);
        mont_reduce_into(out, &mut acc.0, &D::MODULUS, D::N0, 1);
    }

    fn mul(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        Self::mont_mul(out, a, b);
    }

    fn sqr(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS]) {
        // The full product rather than a symmetry-expanded square: it is exact for
        // every input, including a long run of identical limbs, and PFP-2 does not
        // claim a dedicated squaring (PFP-6 compares those schedules).
        let mut acc = SecretWords::<9>::zero();
        wide_mul_into(&mut acc.0, a, a);
        mont_reduce_into(out, &mut acc.0, &D::MODULUS, D::N0, 1);
    }

    fn add(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        // Montgomery encoding is linear, so the modular sum of two encodings is
        // the encoding of the modular sum.
        add_canonical(out, a, b, &D::MODULUS);
    }

    fn sub(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        sub_canonical(out, a, b, &D::MODULUS);
    }

    fn reduce(&self, out: &mut [Limb; LIMBS], wide: &[Limb; 8]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..8].copy_from_slice(wide);
        mont_reduce_into(out, &mut acc.0, &D::MODULUS, D::N0, 2);
    }

    fn select(&self, out: &mut [Limb; LIMBS], mask: Limb, a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        select_limbs(out, mask, a, b);
    }

    fn cswap(&self, mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]) {
        cswap_limbs(mask, a, b);
    }
}

/// Fixed-sequence Solinas reduction from `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
///
/// The representation is the ordinary canonical residue, so `from_limbs` and
/// `to_limbs` reduce or copy; there is no domain conversion in either direction.
pub(crate) struct Solinas;

impl FieldKernel<FieldDomain> for Solinas {
    const ID: KernelId = KernelId::Solinas;

    fn from_limbs(&self, out: &mut [Limb; LIMBS], ordinary: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..LIMBS].copy_from_slice(ordinary);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn to_limbs(&self, out: &mut [Limb; LIMBS], repr: &[Limb; LIMBS]) {
        out.copy_from_slice(repr);
    }

    fn mul(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        wide_mul_into(&mut acc.0, a, b);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn sqr(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        wide_mul_into(&mut acc.0, a, a);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn add(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        add_canonical(out, a, b, &FIELD_MODULUS);
    }

    fn sub(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        sub_canonical(out, a, b, &FIELD_MODULUS);
    }

    fn reduce(&self, out: &mut [Limb; LIMBS], wide: &[Limb; 8]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..8].copy_from_slice(wide);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn select(&self, out: &mut [Limb; LIMBS], mask: Limb, a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        select_limbs(out, mask, a, b);
    }

    fn cswap(&self, mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]) {
        cswap_limbs(mask, a, b);
    }
}

// ---------------------------------------------------------------------------
// The architecture kernel
// ---------------------------------------------------------------------------

/// The architecture kernel's capability proof.
///
/// It exists only when the target's multiply primitives are usable, so no safe
/// constructor can produce an [`Arch`] on a target where calling the intrinsic
/// would be undefined behaviour.
#[derive(Clone, Copy)]
struct ArchProof(());

impl ArchProof {
    fn new() -> Option<Self> {
        arch_supported().then_some(Self(()))
    }
}

/// Whether the architecture multiply is available on this target and CPU.
fn arch_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if !std::is_x86_feature_detected!("bmi2") || !std::is_x86_feature_detected!("adx") {
            return false;
        }
        // The authority's `nistz256` predicate is
        // `OPENSSL_ia32cap_P[2] & 0x80100 == 0x80100`: BMI2 (bit 8) and ADX
        // (bit 19) of `CPUID.(EAX=7,ECX=0).EBX`. This crate reads those bits
        // directly; the `OPENSSL_ia32cap` environment mask is not modelled
        // (recorded divergence `RT-CPU-CAPABILITY`).
        core::arch::x86_64::__cpuid_count(7, 0).ebx & 0x8_0100 == 0x8_0100
    }
    #[cfg(target_arch = "aarch64")]
    {
        // `u128` multiplication lowers to `mul`/`umulh`, which are baseline
        // AArch64 and always available.
        true
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Architecture-tuned multiply: `mulx`/`adcx` on x86-64, `u128` on AArch64.
///
/// The reduction is the same fixed-sequence Solinas fold as [`Solinas`], so the
/// measured difference between the two kernels is the multiply alone.
pub(crate) struct Arch {
    _proof: ArchProof,
}

impl Arch {
    /// Construct the kernel if this CPU can execute its multiply.
    pub(crate) fn new() -> Option<Self> {
        ArchProof::new().map(|_proof| Self { _proof })
    }

    #[inline(always)]
    fn wide_mul_into(&self, out: &mut [Limb; 9], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: `self` can only be constructed by `Arch::new`, which called
            // `ArchProof::new`; that returned `Some` only after `arch_supported`
            // verified BMI2 and ADX on this CPU. `wide_mul_x86` has exactly those
            // two target features, so the call cannot execute an unsupported
            // instruction. The pointer arguments are two live four-limb arrays
            // and one live nine-limb accumulator owned by this call.
            unsafe { wide_mul_x86(a, b, out) };
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            // `u128` multiplication lowers to `mul`/`umulh` on AArch64, which is
            // the architecture primitive this arm claims.
            wide_mul_into(out, a, b);
        }
    }
}

impl FieldKernel<FieldDomain> for Arch {
    const ID: KernelId = KernelId::Arch;

    fn from_limbs(&self, out: &mut [Limb; LIMBS], ordinary: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..LIMBS].copy_from_slice(ordinary);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn to_limbs(&self, out: &mut [Limb; LIMBS], repr: &[Limb; LIMBS]) {
        out.copy_from_slice(repr);
    }

    fn mul(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        self.wide_mul_into(&mut acc.0, a, b);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn sqr(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS]) {
        let mut acc = SecretWords::<9>::zero();
        self.wide_mul_into(&mut acc.0, a, a);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn add(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        add_canonical(out, a, b, &FIELD_MODULUS);
    }

    fn sub(&self, out: &mut [Limb; LIMBS], a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        sub_canonical(out, a, b, &FIELD_MODULUS);
    }

    fn reduce(&self, out: &mut [Limb; LIMBS], wide: &[Limb; 8]) {
        let mut acc = SecretWords::<9>::zero();
        acc.0[..8].copy_from_slice(wide);
        let mut lanes = SecretLanes::zero();
        solinas_reduce_into(out, &mut acc.0, &mut lanes);
    }

    fn select(&self, out: &mut [Limb; LIMBS], mask: Limb, a: &[Limb; LIMBS], b: &[Limb; LIMBS]) {
        select_limbs(out, mask, a, b);
    }

    fn cswap(&self, mask: Limb, a: &mut [Limb; LIMBS], b: &mut [Limb; LIMBS]) {
        cswap_limbs(mask, a, b);
    }
}

/// `a · b` with `mulx` and two `addcarry` chains.
///
/// Each column is `hi:lo = a[i]·b[j]`; adding `t[i+j]` and the previous carry
/// produces a new low word and two carry bits into `hi`. The column sum is the
/// ordinary schoolbook term, which is below `2^128`, so `hi + c1 + c2` cannot
/// overflow and the final carry of those two adds is zero by that bound.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX; this function has both as target features
/// and the caller ([`Arch`]) establishes them at construction.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "bmi2,adx")]
unsafe fn wide_mul_x86(a: &[Limb; LIMBS], b: &[Limb; LIMBS], out: &mut [Limb; 9]) {
    use core::arch::x86_64::{_addcarry_u64, _mulx_u64};

    out.fill(0);
    for i in 0..LIMBS {
        let mut carry = 0u64;
        for j in 0..LIMBS {
            let mut hi = 0u64;
            let lo = _mulx_u64(a[i], b[j], &mut hi);
            let mut lo1 = 0u64;
            let c1 = _addcarry_u64(0, lo, out[i + j], &mut lo1);
            let mut lo2 = 0u64;
            let c2 = _addcarry_u64(0, lo1, carry, &mut lo2);
            out[i + j] = lo2;
            let mut hi1 = 0u64;
            let _ = _addcarry_u64(0, hi, c1 as u64, &mut hi1);
            let mut hi2 = 0u64;
            let _ = _addcarry_u64(0, hi1, c2 as u64, &mut hi2);
            carry = hi2;
        }
        out[i + LIMBS] = carry;
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The kernel selected once for this process.
pub(crate) enum SelectedFieldKernel {
    #[allow(dead_code)] // measured and available; selected only on a non-arch target
    Mont(Mont<FieldDomain>),
    Solinas(Solinas),
    Arch(Arch),
}

/// Select the field kernel from public data.
///
/// The modulus is fixed by this engine's construction (P-256). The default is
/// [`Mont`]: the PFP-2 measurement (`evidence/performance-frontier/campaigns/PFP-2/`)
/// found it the fastest of the three admissible kernels on the admitted venue for
/// `mul`, `sqr`, `reduce` and the end-to-end ladder, so selecting another would
/// publish a measured regression. [`Arch`] remains admissible only when
/// [`Arch::new`] has verified BMI2 and ADX — that predicate is the kernel's
/// construction precondition, never a value — and is retained as a measured arm.
/// [`Solinas`] is the portable arm with the same evidence. The answer is cached in
/// an atomic, so selection happens once per process and never per operation.
pub(crate) fn select_field_kernel() -> SelectedFieldKernel {
    #[cfg(test)]
    if let Some(id) = test_force::forced() {
        return match id {
            KernelId::Mont => SelectedFieldKernel::Mont(Mont::default()),
            KernelId::Solinas => SelectedFieldKernel::Solinas(Solinas),
            KernelId::Arch => match Arch::new() {
                Some(k) => SelectedFieldKernel::Arch(k),
                None => SelectedFieldKernel::Solinas(Solinas),
            },
        };
    }
    match default_kernel_id() {
        KernelId::Arch => match Arch::new() {
            Some(k) => SelectedFieldKernel::Arch(k),
            None => SelectedFieldKernel::Solinas(Solinas),
        },
        KernelId::Mont => SelectedFieldKernel::Mont(Mont::default()),
        KernelId::Solinas => SelectedFieldKernel::Solinas(Solinas),
    }
}

/// The process-wide default, computed once.
///
/// The measured result, not an architectural preference, decides this. ARCH was
/// slower than MONT on every measured operation and on the ladder, so the
/// capability-gated arm is not the default; its admission check stays where it
/// belongs, in [`Arch::new`].
fn default_kernel_id() -> KernelId {
    static SELECTED: AtomicU8 = AtomicU8::new(u8::MAX);
    let cached = SELECTED.load(Ordering::Relaxed);
    if cached != u8::MAX {
        return kernel_from_u8(cached);
    }
    let id = KernelId::Mont;
    SELECTED.store(kernel_to_u8(id), Ordering::Relaxed);
    id
}

fn kernel_to_u8(id: KernelId) -> u8 {
    match id {
        KernelId::Mont => 0,
        KernelId::Solinas => 1,
        KernelId::Arch => 2,
    }
}

fn kernel_from_u8(v: u8) -> KernelId {
    match v {
        0 => KernelId::Mont,
        2 => KernelId::Arch,
        _ => KernelId::Solinas,
    }
}

/// Test-only kernel override.
///
/// Compiled out of every non-test build. Tests that force a kernel are the only
/// users; the production selector reads CPUID and the modulus identity.
#[cfg(test)]
pub(crate) mod test_force {
    use core::cell::Cell;

    use super::KernelId;

    thread_local! {
        static FORCED: Cell<Option<KernelId>> = const { Cell::new(None) };
    }

    pub(crate) fn set(id: Option<KernelId>) {
        FORCED.with(|f| f.set(id));
    }

    pub(crate) fn forced() -> Option<KernelId> {
        FORCED.with(|f| f.get())
    }

    /// Restore the default when dropped, including during an unwind.
    pub(crate) struct Guard;

    impl Guard {
        pub(crate) fn new(id: KernelId) -> Self {
            set(Some(id));
            Self
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            set(None);
        }
    }
}

// ---------------------------------------------------------------------------
// Representation types
// ---------------------------------------------------------------------------

/// A residue modulo P-256's field prime, in kernel representation.
///
/// The type parameter is the kernel, so two kernels' values are also distinct
/// types; the ordinary residue is [`P256Field::to_canonical`]'s answer and is
/// always below `p`.
pub(crate) struct P256Field<K> {
    limbs: SecretLimbs4,
    _kernel: PhantomData<K>,
}

impl<K> P256Field<K> {
    /// The additive identity. Zero has the same encoding in every kernel.
    pub(crate) fn zero() -> Self {
        Self {
            limbs: SecretLimbs4::zero(),
            _kernel: PhantomData,
        }
    }

    /// A copy of another element of the same domain and kernel.
    pub(crate) fn copy_from(&mut self, other: &Self) {
        self.limbs.copy_from(&other.limbs);
    }

    /// All ones when this is zero, zero otherwise.
    pub(crate) fn is_zero_mask(&self) -> Limb {
        ct_is_zero(self.limbs.limbs())
    }

    fn limbs(&self) -> &[Limb; LIMBS] {
        self.limbs.limbs()
    }

    fn limbs_mut(&mut self) -> &mut [Limb; LIMBS] {
        self.limbs.limbs_mut()
    }
}

impl<K: FieldKernel<FieldDomain>> P256Field<K> {
    /// Encode arbitrary ordinary limbs (a value below `2^256`) as a residue.
    pub(crate) fn from_canonical(kernel: &K, ordinary: &[Limb; LIMBS]) -> Self {
        let mut out = SecretLimbs4::zero();
        kernel.from_limbs(out.limbs_mut(), ordinary);
        Self {
            limbs: out,
            _kernel: PhantomData,
        }
    }

    /// Parse a 32-byte big-endian encoding, reducing modulo `p`.
    pub(crate) fn from_be_bytes(kernel: &K, bytes: &[u8; 32]) -> Self {
        let ordinary = limbs_from_be(bytes);
        Self::from_canonical(kernel, &ordinary)
    }

    /// The ordinary canonical residue.
    pub(crate) fn to_canonical(&self, kernel: &K) -> Canonical4 {
        let mut out = Canonical4::zero();
        kernel.to_limbs(out.limbs_mut(), self.limbs());
        out
    }

    /// The 32-byte big-endian encoding of the ordinary residue.
    pub(crate) fn to_be_bytes(&self, kernel: &K) -> Canonical32 {
        Canonical32::new(self.to_canonical(kernel).be_bytes())
    }

    /// `self = a · b`, with `self` as the destination.
    pub(crate) fn mul_into(&mut self, kernel: &K, a: &Self, b: &Self) {
        kernel.mul(self.limbs_mut(), a.limbs(), b.limbs());
    }

    pub(crate) fn mul_assign(&mut self, kernel: &K, rhs: &Self) {
        let mut out = SecretLimbs4::zero();
        kernel.mul(out.limbs_mut(), self.limbs(), rhs.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = a²`, with `self` as the destination.
    pub(crate) fn sqr_into(&mut self, kernel: &K, a: &Self) {
        kernel.sqr(self.limbs_mut(), a.limbs());
    }

    pub(crate) fn sqr_assign(&mut self, kernel: &K) {
        let mut out = SecretLimbs4::zero();
        kernel.sqr(out.limbs_mut(), self.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = a + b`, with `self` as the destination.
    pub(crate) fn add_into(&mut self, kernel: &K, a: &Self, b: &Self) {
        kernel.add(self.limbs_mut(), a.limbs(), b.limbs());
    }

    pub(crate) fn add_assign(&mut self, kernel: &K, rhs: &Self) {
        let mut out = SecretLimbs4::zero();
        kernel.add(out.limbs_mut(), self.limbs(), rhs.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = a - b`, with `self` as the destination.
    pub(crate) fn sub_into(&mut self, kernel: &K, a: &Self, b: &Self) {
        kernel.sub(self.limbs_mut(), a.limbs(), b.limbs());
    }

    pub(crate) fn sub_assign(&mut self, kernel: &K, rhs: &Self) {
        let mut out = SecretLimbs4::zero();
        kernel.sub(out.limbs_mut(), self.limbs(), rhs.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = rhs - self`.
    pub(crate) fn sub_rev_assign(&mut self, kernel: &K, rhs: &Self) {
        let mut out = SecretLimbs4::zero();
        kernel.sub(out.limbs_mut(), rhs.limbs(), self.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = 2·self`, as `self + self`.
    pub(crate) fn double_assign(&mut self, kernel: &K) {
        let mut out = SecretLimbs4::zero();
        kernel.add(out.limbs_mut(), self.limbs(), self.limbs());
        self.limbs.copy_from(&out);
    }

    /// `self = a·2^k` for a public `k`, by repeated doubling.
    pub(crate) fn shift_left_assign(&mut self, kernel: &K, k: usize) {
        for _ in 0..k {
            self.double_assign(kernel);
        }
    }

    /// `out = a` when `mask` is all ones, `b` when zero.
    pub(crate) fn select(kernel: &K, mask: Limb, a: &Self, b: &Self, out: &mut Self) {
        kernel.select(out.limbs_mut(), mask, a.limbs(), b.limbs());
    }

    /// Exchange `a` and `b` when `mask` is all ones.
    pub(crate) fn cswap(kernel: &K, mask: Limb, a: &mut Self, b: &mut Self) {
        let (a_limbs, b_limbs) = (a.limbs_mut(), b.limbs_mut());
        kernel.cswap(mask, a_limbs, b_limbs);
    }

    /// Reduce an arbitrary 512-bit value with the kernel's reduction.
    pub(crate) fn reduce_wide(kernel: &K, wide: &[Limb; 8]) -> Self {
        let mut out = SecretLimbs4::zero();
        kernel.reduce(out.limbs_mut(), wide);
        Self {
            limbs: out,
            _kernel: PhantomData,
        }
    }
}

/// A residue modulo P-256's group order, in Montgomery representation.
///
/// Distinct from [`P256Field`]: there is no conversion between the two, and the
/// canonicality invariant is against `q`, not `p`.
pub(crate) struct P256Scalar {
    limbs: SecretLimbs4,
}

impl P256Scalar {
    const KERNEL: Mont<OrderDomain> = Mont {
        _domain: PhantomData,
    };

    /// The additive identity.
    pub(crate) fn zero() -> Self {
        Self {
            limbs: SecretLimbs4::zero(),
        }
    }

    /// Reduce arbitrary ordinary limbs modulo `q`.
    pub(crate) fn from_canonical_reduced(ordinary: &[Limb; LIMBS]) -> Self {
        let mut out = SecretLimbs4::zero();
        Self::KERNEL.from_limbs(out.limbs_mut(), ordinary);
        Self { limbs: out }
    }

    /// Admit a 32-byte big-endian scalar, refusing a value that is not below
    /// `q` (the secret-scalar domain check).
    pub(crate) fn admit_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let ordinary = limbs_from_be(bytes);
        if ct_ge(&ordinary, &ORDER_MODULUS) != 0 {
            return None;
        }
        Some(Self::from_canonical_reduced(&ordinary))
    }

    /// The ordinary canonical residue.
    pub(crate) fn to_canonical(&self) -> Canonical4 {
        let mut out = Canonical4::zero();
        Self::KERNEL.to_limbs(out.limbs_mut(), self.limbs());
        out
    }

    /// The 32-byte big-endian encoding of the ordinary residue.
    pub(crate) fn to_be_bytes(&self) -> Canonical32 {
        Canonical32::new(self.to_canonical().be_bytes())
    }

    pub(crate) fn mul(&self, rhs: &Self, out: &mut Self) {
        Self::KERNEL.mul(out.limbs.limbs_mut(), self.limbs(), rhs.limbs());
    }

    pub(crate) fn add(&self, rhs: &Self, out: &mut Self) {
        Self::KERNEL.add(out.limbs.limbs_mut(), self.limbs(), rhs.limbs());
    }

    pub(crate) fn sub(&self, rhs: &Self, out: &mut Self) {
        Self::KERNEL.sub(out.limbs.limbs_mut(), self.limbs(), rhs.limbs());
    }

    pub(crate) fn select(mask: Limb, a: &Self, b: &Self, out: &mut Self) {
        Self::KERNEL.select(out.limbs.limbs_mut(), mask, a.limbs(), b.limbs());
    }

    pub(crate) fn cswap(mask: Limb, a: &mut Self, b: &mut Self) {
        let (a_limbs, b_limbs) = (a.limbs.limbs_mut(), b.limbs.limbs_mut());
        Self::KERNEL.cswap(mask, a_limbs, b_limbs);
    }

    /// Reduce and encode an arbitrary 512-bit value.
    pub(crate) fn reduce_wide(wide: &[Limb; 8]) -> Self {
        let mut out = SecretLimbs4::zero();
        Self::KERNEL.reduce(out.limbs_mut(), wide);
        Self { limbs: out }
    }

    pub(crate) fn is_zero_mask(&self) -> Limb {
        ct_is_zero(self.limbs())
    }

    fn limbs(&self) -> &[Limb; LIMBS] {
        self.limbs.limbs()
    }
}

/// A projective P-256 point over the field domain.
pub(crate) struct P256Projective<K> {
    pub(crate) x: P256Field<K>,
    pub(crate) y: P256Field<K>,
    pub(crate) z: P256Field<K>,
}

impl<K> P256Projective<K> {
    pub(crate) fn new(x: P256Field<K>, y: P256Field<K>, z: P256Field<K>) -> Self {
        Self { x, y, z }
    }

    /// The point at infinity, represented as `(0, 1, 0)`.
    pub(crate) fn infinity(kernel: &K) -> Self
    where
        K: FieldKernel<FieldDomain>,
    {
        let mut one = [0u64; LIMBS];
        one[0] = 1;
        Self {
            x: P256Field::zero(),
            y: P256Field::from_canonical(kernel, &one),
            z: P256Field::zero(),
        }
    }
}

// ---------------------------------------------------------------------------
// The ladder dataflow
// ---------------------------------------------------------------------------

/// The authority's plain-ladder step over the fixed-width engine.
///
/// The body is `crypto/ec/ecp_smpl.c:1560-1623` translated operation for
/// operation onto [`P256Field`]: the same thirteen multiplications, seven
/// squarings, six modular additions, six modular subtractions and three
/// doublings, over the same operand pairs. The storage is the fixed-width
/// engine, so no field operation crosses into `BIGNUM` and none allocates.
pub(crate) struct P256Ladder<K> {
    kernel: K,
    rx: P256Field<K>,
    rz: P256Field<K>,
    sx: P256Field<K>,
    sz: P256Field<K>,
    px: P256Field<K>,
    ca: P256Field<K>,
    cb: P256Field<K>,
    t0: P256Field<K>,
    t1: P256Field<K>,
    t2: P256Field<K>,
    t3: P256Field<K>,
    t4: P256Field<K>,
    t5: P256Field<K>,
    t6: P256Field<K>,
}

impl<K: FieldKernel<FieldDomain>> P256Ladder<K> {
    /// Build the workspace. `a`, `b` and `px` are the curve's `a`, the curve's
    /// `b` and the affine input point's `X`, each ordinary canonical limbs
    /// (already reduced by the caller).
    pub(crate) fn new(kernel: K, a: &[Limb; LIMBS], b: &[Limb; LIMBS], px: &[Limb; LIMBS]) -> Self {
        let ca = P256Field::from_canonical(&kernel, a);
        let cb = P256Field::from_canonical(&kernel, b);
        let px = P256Field::from_canonical(&kernel, px);
        Self {
            kernel,
            rx: P256Field::zero(),
            rz: P256Field::zero(),
            sx: P256Field::zero(),
            sz: P256Field::zero(),
            px,
            ca,
            cb,
            t0: P256Field::zero(),
            t1: P256Field::zero(),
            t2: P256Field::zero(),
            t3: P256Field::zero(),
            t4: P256Field::zero(),
            t5: P256Field::zero(),
            t6: P256Field::zero(),
        }
    }

    /// Stage the four live coordinates.
    pub(crate) fn load(
        &mut self,
        rx: &[Limb; LIMBS],
        rz: &[Limb; LIMBS],
        sx: &[Limb; LIMBS],
        sz: &[Limb; LIMBS],
    ) {
        self.rx = P256Field::from_canonical(&self.kernel, rx);
        self.rz = P256Field::from_canonical(&self.kernel, rz);
        self.sx = P256Field::from_canonical(&self.kernel, sx);
        self.sz = P256Field::from_canonical(&self.kernel, sz);
    }

    pub(crate) fn rx_canonical(&self) -> Canonical4 {
        self.rx.to_canonical(&self.kernel)
    }

    pub(crate) fn rz_canonical(&self) -> Canonical4 {
        self.rz.to_canonical(&self.kernel)
    }

    pub(crate) fn sx_canonical(&self) -> Canonical4 {
        self.sx.to_canonical(&self.kernel)
    }

    pub(crate) fn sz_canonical(&self) -> Canonical4 {
        self.sz.to_canonical(&self.kernel)
    }

    /// Exchange the `r` and `s` X/Z pairs when `bit` is one.
    ///
    /// `bit` is a ladder bit (zero or one); the full-width mask is formed here so
    /// no caller has to remember to widen it.
    pub(crate) fn cswap(&mut self, bit: Limb) {
        let mask = bit.wrapping_neg();
        P256Field::cswap(&self.kernel, mask, &mut self.rx, &mut self.sx);
        P256Field::cswap(&self.kernel, mask, &mut self.rz, &mut self.sz);
    }

    /// One ladder step.
    pub(crate) fn step(&mut self) {
        let Self {
            kernel: k,
            rx,
            rz,
            sx,
            sz,
            px,
            ca,
            cb,
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        } = self;
        let k = &*k;

        t6.mul_into(k, rx, sx);
        t0.mul_into(k, rz, sz);
        t4.mul_into(k, rx, sz);
        t3.mul_into(k, rz, sx);
        t5.mul_into(k, ca, t0);
        t5.add_assign(k, t6);
        t6.add_into(k, t3, t4);
        t5.mul_assign(k, t6);
        t0.sqr_assign(k);
        t2.copy_from(cb);
        t2.shift_left_assign(k, 2);
        t0.mul_assign(k, t2);
        t5.double_assign(k);
        t3.sub_rev_assign(k, t4);
        sz.sqr_into(k, t3);
        t4.mul_into(k, sz, px);
        t0.add_assign(k, t5);
        sx.sub_into(k, t0, t4);
        t4.sqr_into(k, rx);
        t5.sqr_into(k, rz);
        t6.mul_into(k, t5, ca);
        t1.add_into(k, rx, rz);
        t1.sqr_assign(k);
        t1.sub_assign(k, t4);
        t1.sub_assign(k, t5);
        t3.sub_into(k, t4, t6);
        t3.sqr_assign(k);
        t0.mul_into(k, t5, t1);
        t0.mul_assign(k, t2);
        rx.sub_into(k, t3, t0);
        t3.add_into(k, t4, t6);
        t4.sqr_into(k, t5);
        t4.mul_assign(k, t2);
        t1.mul_assign(k, t3);
        t1.double_assign(k);
        rz.add_into(k, t4, t1);
    }
}

/// Split a `BIGNUM` magnitude into four canonical limbs, refusing a value wider
/// than the public width.
pub(crate) fn limbs_from_slice(src: &[Limb]) -> Option<[Limb; LIMBS]> {
    if src.len() > LIMBS {
        return None;
    }
    let mut out = [0u64; LIMBS];
    out[..src.len()].copy_from_slice(src);
    Some(out)
}

fn limbs_from_be(bytes: &[u8; 32]) -> [Limb; LIMBS] {
    let mut out = [0u64; LIMBS];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = 32 - 8 * (i + 1);
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[start..start + 8]);
        *slot = u64::from_be_bytes(word);
    }
    out
}

fn limbs_to_be(limbs: &[Limb; LIMBS]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used)] // test-only failure assertions
#[allow(clippy::unwrap_used)] // test-only reference arithmetic
mod tests;
