//! Phase 5 — the limb arithmetic under `BIGNUM`.
//!
//! Pure integer arithmetic on little-endian `u64` limbs. No FFI, no OpenSSL
//! types: the arithmetic is the part that must be *provably* right, and keeping it
//! separable is what lets the unit tests below exercise it without an authority, a
//! court or a `BIGNUM`.
//!
//! ## Representation
//!
//! A value is a `Vec<u64>`, least significant limb first, with **no trailing zero
//! limbs**, so zero is the empty slice. Every function here preserves that
//! invariant; `normalise` establishes it after any operation that can violate it.
//!
//! `BIGNUM` is opaque to callers of the authority (`include/openssl/bn.h` declares
//! `typedef struct bignum_st BIGNUM;` and defines nothing), so this representation
//! is ours. It is not part of the ABI, and the ABI layout court does not constrain
//! it — that court's 158 types contain no `BN` type, which was checked rather than
//! assumed.
//!
//! ## Overflow
//!
//! The release profile enables `overflow-checks`, on the grounds that courts must
//! be able to reason about overflow. Arithmetic that is *expected* to wrap says so
//! with `wrapping_*`, so a genuine overflow is still a panic rather than a silent
//! wrong answer.
//!
//! ## Provenance
//!
//! The algorithms are the standard published ones — schoolbook multiplication,
//! Knuth's Algorithm D for division (`TAOCP` volume 2, 4.3.1), the binary GCD, the
//! extended Euclidean algorithm, and Newton's method for the integer square root —
//! implemented from their descriptions rather than transliterated from the
//! authority's C.

/// A limb. 64-bit because the crate has one build profile, `x86_64-linux`.
pub(crate) type Limb = u64;

use crate::runtime::secret::SecretLimbs;

/// Drop trailing zero limbs, restoring the "no leading zeros" invariant.
pub(crate) fn normalise(v: &mut Vec<Limb>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

/// Zero every limb of `d`'s allocation, not merely its current length.
///
/// This is the representation's analogue of the authority's
/// `OPENSSL_cleanse(a->d, sizeof(*a->d) * a->dmax)` in `BN_clear` and
/// `OPENSSL_clear_free(a->d, a->dmax * sizeof(*a->d))` in `BN_clear_free`: `capacity()`
/// is the allocated limb extent, whereas `len()` is only the normalised top. The spare
/// capacity can still hold limbs from a larger earlier value, because `Vec::clear`,
/// `truncate` and `normalise` discard the length without writing the storage.
/// Volatile writes plus the fence are what stop the optimiser eliding the wipe.
///
/// The loop mirrors `runtime::mem::cleanse` element-wise rather than asking it to wipe
/// `capacity() * size_of::<Limb>()` bytes, so no size multiplication has to be trusted
/// not to overflow (§3).
pub(crate) fn cleanse_storage(d: &mut Vec<Limb>) {
    let p = d.as_mut_ptr();
    for i in 0..d.capacity() {
        // SAFETY: `i < capacity`, so `p.add(i)` lies inside the allocation `d` owns.
        // `Limb` is `Copy` with no destructor, so zeroing spare (still uninitialised)
        // capacity is sound and does not change the length or drop anything.
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Release a limb allocation whose storage has already been cleansed.
///
/// The only release path used by the growth helpers below: the old block is wiped
/// while the vector still owns it, then handed here. In a test that armed
/// [`realloc_probe`] on this allocation, the observer reads the block just before
/// the `Vec` releases it.
pub(crate) fn release_cleansed(storage: Vec<Limb>) {
    #[cfg(test)]
    realloc_probe::observe(&storage);
    drop(storage);
}

/// Ensure `v` can hold at least `words` limbs without letting `Vec`'s own
/// reallocation path release an uncleansed block.
///
/// `Vec::try_reserve`/`try_reserve_exact` may move the allocation and free the old
/// block as part of the request, before any caller can cleanse it. This helper
/// instead allocates a separate block, copies the live limbs, cleanses the complete
/// old allocation while it is still owned, and only then swaps and releases it. On
/// success `v`'s length and contents are unchanged; on refusal `v` is untouched.
pub(crate) fn reserve_cleansed(v: &mut Vec<Limb>, words: usize) -> bool {
    if v.capacity() >= words {
        return true;
    }
    let Some(mut fresh) = crate::bn::alloc::try_zeroed(words, 0u64) else {
        return false;
    };
    let len = v.len();
    fresh[..len].copy_from_slice(v);
    fresh.truncate(len);
    cleanse_storage(v);
    release_cleansed(core::mem::replace(v, fresh));
    true
}

/// Grow `v` to `new_len` limbs through a fresh allocation, cleansing the old block
/// before it is released.
///
/// Returns `false` — leaving `v` unchanged — when the separate allocation is
/// refused. The in-capacity case is an ordinary `resize`, which cannot release
/// anything.
pub(crate) fn grow_cleansed(v: &mut Vec<Limb>, new_len: usize) -> bool {
    if new_len <= v.len() {
        return true;
    }
    if !reserve_cleansed(v, new_len) {
        return false;
    }
    v.resize(new_len, 0);
    true
}

/// Test-only deallocation observer for the growth helpers.
///
/// Records what an armed allocation still contained immediately before
/// [`release_cleansed`] handed it to the allocator. This is the point the old
/// implementation could not observe: it reserved in place, so the old block was
/// already gone. Compiled out of every non-test build.
#[cfg(test)]
pub(crate) mod realloc_probe {
    use core::cell::Cell;

    use super::Limb;

    /// What the observer saw on the armed allocation.
    pub(crate) struct Observation {
        pub(crate) ptr: usize,
        /// The allocation's capacity.
        pub(crate) capacity: usize,
        /// Non-zero limbs across the whole allocation (expected `0`).
        pub(crate) nonzero_limbs: usize,
    }

    thread_local! {
        static TARGET: Cell<usize> = const { Cell::new(0) };
        static SEEN: Cell<Option<Observation>> = const { Cell::new(None) };
    }

    /// Arm the observer on the allocation at `ptr`.
    pub(crate) fn arm(ptr: *const Limb) {
        TARGET.with(|t| t.set(ptr as usize));
        SEEN.with(|s| s.set(None));
    }

    /// Take the recorded observation, if the armed allocation was released.
    pub(crate) fn take() -> Option<Observation> {
        SEEN.with(|s| s.take())
    }

    pub(super) fn observe(v: &Vec<Limb>) {
        let addr = v.as_ptr() as usize;
        if TARGET.with(|t| t.get()) != addr {
            return;
        }
        // The armed test initialises every capacity slot, and the growth path
        // cleanses the whole allocation before calling here, so every slot read
        // below is initialised. Reading an unarmed allocation never happens.
        let mut nonzero_limbs = 0usize;
        for i in 0..v.capacity() {
            // SAFETY: `i < capacity` covers the live allocation `v` still owns;
            // the observer runs before the field is released.
            if unsafe { core::ptr::read_volatile(v.as_ptr().add(i)) } != 0 {
                nonzero_limbs += 1;
            }
        }
        SEEN.with(|s| {
            s.set(Some(Observation {
                ptr: addr,
                capacity: v.capacity(),
                nonzero_limbs,
            }))
        });
    }
}

/// Drop trailing zero limbs without branching on a limb value.
///
/// The trim is the same operation as [`normalise`], but the significant length is
/// computed in one **fixed** pass over `width` limbs with [`constant_time_select`]
/// masks and then installed with `set_len`. There is no early exit, no
/// `while last() == 0` loop and no comparison of a limb in control position, so a
/// secret-bearing result does not acquire a data-dependent branch merely by being
/// stored.
///
/// `width` is the **public** limb width the caller produced the magnitude at (the
/// modulus/operand limb count for every constant-time caller). The scan always
/// costs exactly `width` iterations, whatever the magnitude's normalised length,
/// so the pass does not become a length oracle. A shorter vector — only a
/// variable-time fallback result that already arrived trimmed — is zero-extended
/// to `width` first; the extension is empty on every fixed-pattern path.
///
/// The resulting `Vec` length still depends on the value — that is inherent in
/// this crate's normalised `BIGNUM` representation, which cannot express a fixed
/// top (see `bignum.rs`'s `BN_FLG_FIXED_TOP` note). What this function removes is
/// the branch and the length-proportional work, not the length: the length
/// remains observable to a caller that asks for it.
///
/// [`constant_time_select`]: crate::runtime::constant_time::constant_time_select
pub(crate) fn normalise_consttime(v: &mut Vec<Limb>, width: usize) -> Option<usize> {
    use crate::runtime::constant_time::{constant_time_is_zero_s, constant_time_select};

    debug_assert!(
        v.len() <= width,
        "a constant-time magnitude cannot be wider than its declared public width"
    );
    if v.len() < width && !grow_cleansed(v, width) {
        // The separate zero-extension allocation was refused. `v` is unchanged, so
        // the caller still owns its secret contents and must cleanse them.
        return None;
    }
    let mut keep: usize = 0;
    let mut trimming: usize = usize::MAX;
    for i in (0..width).rev() {
        // Indexing by the public `width`, never by the magnitude's normalised
        // length, is what bounds this pass to public geometry.
        #[cfg(test)]
        trim_probe::record_iteration();
        let limb = v[i];
        // All-ones when the limb is non-zero. The first one found (scanning from
        // the most significant limb) fixes `keep`; every lower limb leaves it
        // alone because `trimming` is then all-zeros.
        let nonzero = !constant_time_is_zero_s(limb as usize);
        let take = trimming & nonzero;
        #[cfg(test)]
        trim_probe::record_select();
        keep = constant_time_select(take, i + 1, keep);
        trimming &= !nonzero;
    }
    // SAFETY: `keep <= width == v.len()`, and every element below `keep` is
    // initialised because `keep` is either zero or the index after a limb that
    // was read in this pass. `Limb` is `Copy` with no destructor, so shrinking
    // the length drops nothing.
    unsafe { v.set_len(keep) };
    Some(keep)
}

/// Test-only observation seam for [`normalise_consttime`].
///
/// Records how many limbs the fixed-pattern scan visited and how many masked
/// selects it performed, so a test can assert that two magnitudes with the same
/// **public** width and different normalised lengths produce the identical
/// pattern. Compiled out of every non-test build; recording is a no-op unless a
/// test armed the probe on this thread.
#[cfg(test)]
pub(crate) mod trim_probe {
    use core::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static ITERATIONS: Cell<usize> = const { Cell::new(0) };
        static SELECTS: Cell<usize> = const { Cell::new(0) };
    }

    /// Start a fresh observation on this thread.
    pub(crate) fn arm() {
        ARMED.with(|a| a.set(true));
        ITERATIONS.with(|c| c.set(0));
        SELECTS.with(|c| c.set(0));
    }

    /// Stop observing and answer `(limbs scanned, masked selects)`.
    pub(crate) fn disarm() -> (usize, usize) {
        ARMED.with(|a| a.set(false));
        (ITERATIONS.with(Cell::get), SELECTS.with(Cell::get))
    }

    pub(super) fn record_iteration() {
        if ARMED.with(Cell::get) {
            ITERATIONS.with(|c| c.set(c.get() + 1));
        }
    }

    pub(super) fn record_select() {
        if ARMED.with(Cell::get) {
            SELECTS.with(|c| c.set(c.get() + 1));
        }
    }
}

/// True when the value is zero.
pub(crate) fn is_zero(v: &[Limb]) -> bool {
    v.iter().all(|&l| l == 0)
}

/// `a` against `b`, ignoring trailing zeros so `[5, 0]` equals `[5]`.
pub(crate) fn cmp(a: &[Limb], b: &[Limb]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let (mut a, mut b) = (a, b);
    while let Some(&0) = a.last() {
        a = &a[..a.len() - 1];
    }
    while let Some(&0) = b.last() {
        b = &b[..b.len() - 1];
    }
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for i in (0..a.len()).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// The number of significant bits, or `0` for zero.
pub(crate) fn bit_len(v: &[Limb]) -> usize {
    match v.iter().rposition(|&l| l != 0) {
        None => 0,
        Some(i) => i * 64 + (64 - v[i].leading_zeros() as usize),
    }
}

/// [`bit_len`] without a branch or a value-dependent loop bound.
///
/// Every limb is visited in order and contributes its width under an all-ones
/// mask only while it is the most significant non-zero limb. `leading_zeros` on
/// zero answers 64, so a zero limb contributes nothing. The iteration count is
/// the slice's length, which is the value's normalised limb count — public for
/// the CRT moduli (16 limbs each at RSA-2048).
pub(crate) fn bit_len_consttime(v: &[Limb]) -> usize {
    let mut top = 0usize;
    for (i, &l) in v.iter().enumerate() {
        // All-ones when `l != 0`: `l | -l` has its top bit set exactly then.
        let nonzero = ((l | l.wrapping_neg()) >> 63) as usize;
        let mask = 0usize.wrapping_sub(nonzero);
        let width = i.wrapping_mul(64).wrapping_add(bit_len_word_consttime(l));
        top = (top & !mask) | (width & mask);
    }
    top
}

/// The significant bit count of one limb, without a data-dependent branch or a
/// conditional move on its value.
///
/// `leading_zeros` lowers to `bsr` plus a conditional move, which memcheck
/// reports as a secret-dependent move. The six halving steps below ask "is any
/// bit at or above `2^k` set" with a mask, and shift by a literal constant;
/// neither a branch nor a shift-amount check reads the limb.
#[inline(always)]
fn bit_len_word_consttime(w: Limb) -> usize {
    let mut x = w;
    let mut n = 0usize;
    // Six fixed comparisons against literal shifts. A variable shift would emit
    // Rust's shift-amount check — a conditional jump on a tainted count — so the
    // shifts are literals and the choice is a mask select.
    macro_rules! step {
        ($k:expr) => {{
            let hi = x >> $k;
            let mask = 0u64.wrapping_sub((hi | hi.wrapping_neg()) >> 63);
            n = n.wrapping_add(($k as usize) & (mask as usize));
            x = (x & !mask) | (hi & mask);
        }};
    }
    step!(32);
    step!(16);
    step!(8);
    step!(4);
    step!(2);
    step!(1);
    // After all six steps `x` is 1 for a non-zero limb and 0 for zero, which is
    // the one bit the floor did not count.
    n.wrapping_add(x as usize)
}

/// The number of significant bits in a single limb, or `0` for zero.
pub(crate) fn bit_len_word(w: Limb) -> usize {
    if w == 0 {
        0
    } else {
        64 - w.leading_zeros() as usize
    }
}

/// `2^bits mod m` for a non-empty odd `m`, in fixed time.
///
/// Both buffers are exactly `m.len()` limbs and every iteration does the same
/// work, so no allocation size, loop bound, branch or index depends on a limb
/// value. `bits` is public: its callers derive it from the modulus' limb count
/// (`ri = 64 * m.len()`, so `2 * ri = 128 * m.len()`), not from its contents.
///
/// The representative stays below `m`: doubling gives `2r < 2m`, and one masked
/// conditional subtraction finishes each step. `carry` is 0 or 1 because
/// `2r < 2 * 2^(64n)`. `take` is the "value >= m" decision: a carry out of the
/// top limb, or no borrow from `r - m`.
pub(crate) fn pow2_mod_consttime(bits: usize, m: &[Limb]) -> Option<Vec<Limb>> {
    let n = m.len();
    if n == 0 {
        return None;
    }
    let mut r = crate::bn::alloc::try_zeroed(n, 0u64)?;
    // The conditional-subtraction scratch derives from the modulus' contents. For
    // RSA CRT the modulus is a secret prime, so the scratch is secret-bearing and
    // must not be released intact; `r` is the result and is adopted by the caller.
    let mut diff = crate::bn::secret::SecretBuf::try_zeroed(n)?;
    r[0] = 1;
    for _ in 0..bits {
        let mut carry = 0u64;
        for slot in r.iter_mut() {
            let v = (*slot as u128).wrapping_mul(2).wrapping_add(carry as u128);
            *slot = v as Limb;
            carry = (v >> 64) as Limb;
        }
        let mut borrow = 0u64;
        for ((slot, &rv), &mv) in diff.iter_mut().zip(r.iter()).zip(m.iter()) {
            let (d1, b1) = rv.overflowing_sub(mv);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *slot = d2;
            borrow = u64::from(b1) | u64::from(b2);
        }
        let take = carry | (borrow ^ 1);
        let mask = 0u64.wrapping_sub(take);
        for (slot, &d) in r.iter_mut().zip(diff.iter()) {
            *slot = (*slot & !mask) | (d & mask);
        }
    }
    Some(r)
}

/// Whether bit `n` is set. Bits above the value are zero.
pub(crate) fn bit(v: &[Limb], n: usize) -> bool {
    match v.get(n / 64) {
        Some(&l) => (l >> (n % 64)) & 1 == 1,
        None => false,
    }
}

/// Set bit `n` in place, growing the vector as needed; `false` when that growth
/// cannot be allocated.
pub(crate) fn set_bit(v: &mut Vec<Limb>, n: usize) -> bool {
    let (limb, off) = (n / 64, n % 64);
    if v.len() <= limb {
        // The value may be secret: growth must not let `Vec` free the old block
        // before it can be cleansed.
        if !grow_cleansed(v, limb + 1) {
            return false;
        }
    }
    v[limb] |= 1 << off;
    true
}

/// Clear bit `n` in place, normalising afterwards.
pub(crate) fn clear_bit(v: &mut Vec<Limb>, n: usize) {
    let (limb, off) = (n / 64, n % 64);
    if v.len() > limb {
        v[limb] &= !(1 << off);
        normalise(v);
    }
}

/// `a + b`.
///
/// Infallible wrapper for the variable-time public path; the secret-bearing entry
/// points call [`add_fallible`] so an allocation failure is their ordinary error
/// answer rather than an abort.
#[allow(clippy::expect_used)]
pub(crate) fn add(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    add_fallible(a, b).expect("limbs::add: allocation failed")
}

/// `a + b`, or `None` when the result cannot be allocated.
pub(crate) fn add_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    let n = a.len().max(b.len());
    let len = n.checked_add(1)?;
    let mut out = crate::bn::alloc::try_zeroed(len, 0u64)?;
    let mut carry = 0u64;
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        let s =
            (*a.get(i).unwrap_or(&0) as u128) + (*b.get(i).unwrap_or(&0) as u128) + (carry as u128);
        *slot = s as u64;
        carry = (s >> 64) as u64;
    }
    out[n] = carry;
    normalise(&mut out);
    Some(out)
}

/// `a - b`, which requires `a >= b`. The public entry points check before calling.
///
/// Infallible wrapper for the variable-time public path; [`sub_fallible`] is the
/// form the secret-bearing entry points use.
#[allow(clippy::expect_used)]
pub(crate) fn sub(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    sub_fallible(a, b).expect("limbs::sub: allocation failed")
}

/// `a - b`, or `None` when the result cannot be allocated.
pub(crate) fn sub_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    let mut out = crate::bn::alloc::try_zeroed(a.len(), 0u64)?;
    let mut borrow = 0i128;
    for (i, &limb) in a.iter().enumerate() {
        let d = (limb as i128) - (*b.get(i).unwrap_or(&0) as i128) - borrow;
        out[i] = (d & 0xffff_ffff_ffff_ffff) as u64;
        borrow = i128::from(d < 0);
    }
    normalise(&mut out);
    Some(out)
}

/// `a + w` for a single limb.
///
/// Test-only convenience wrapper; the entry points use [`add_word_fallible`].
#[cfg(test)]
pub(crate) fn add_word(a: &[Limb], w: Limb) -> Vec<Limb> {
    add(a, &[w])
}

/// `a + w`, or `None` when the result cannot be allocated.
pub(crate) fn add_word_fallible(a: &[Limb], w: Limb) -> Option<Vec<Limb>> {
    add_fallible(a, &[w])
}

/// `a - w` for a single limb, or `None` when that would go negative.
///
/// Test-only convenience wrapper; the entry points use [`sub_word_fallible`].
#[cfg(test)]
pub(crate) fn sub_word(a: &[Limb], w: Limb) -> Option<Vec<Limb>> {
    sub_word_fallible(a, w)
}

/// `a - w`, or `None` when that would go negative or the result cannot be
/// allocated.
pub(crate) fn sub_word_fallible(a: &[Limb], w: Limb) -> Option<Vec<Limb>> {
    if cmp(a, &[w]) == core::cmp::Ordering::Less {
        return None;
    }
    sub_fallible(a, &[w])
}

/// `a * b`.
///
/// Infallible wrapper for the variable-time public path. Allocation failure is a
/// panic here, which the C ABI boundary reports as an ordinary failure; the
/// constant-time path calls [`mul_fallible`] instead.
#[allow(clippy::expect_used)]
pub(crate) fn mul(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    mul_fallible(a, b).expect("limbs::mul: allocation failed")
}

/// `a * b`, or `None` when the product cannot be allocated.
///
/// Schoolbook. Intermediates are `u128` and each column accumulator holds at most
/// `2^128-1`, so nothing here can overflow. The output length is computed with
/// `checked_add` before it is used as an allocation size.
pub(crate) fn mul_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    if a.is_empty() || b.is_empty() {
        return Some(Vec::new());
    }
    let len = a.len().checked_add(b.len())?;
    let mut out = crate::bn::alloc::try_zeroed(len, 0u64)?;
    for (i, &x) in a.iter().enumerate() {
        if x == 0 {
            continue;
        }
        let mut carry = 0u64;
        for (j, &y) in b.iter().enumerate() {
            let t = (x as u128) * (y as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        let mut k = i + b.len();
        while carry != 0 {
            let t = (out[k] as u128) + (carry as u128);
            out[k] = t as u64;
            carry = (t >> 64) as u64;
            k += 1;
        }
    }
    normalise(&mut out);
    Some(out)
}

/// `a * w` for a single limb.
///
/// Test-only convenience wrapper; the entry points use [`mul_word_fallible`].
#[cfg(test)]
pub(crate) fn mul_word(a: &[Limb], w: Limb) -> Vec<Limb> {
    mul(a, &[w])
}

/// `a * w`, or `None` when the product cannot be allocated.
pub(crate) fn mul_word_fallible(a: &[Limb], w: Limb) -> Option<Vec<Limb>> {
    mul_fallible(a, &[w])
}

/// `a << bits`.
///
/// Infallible wrapper for the variable-time public path; the constant-time path
/// uses [`shl_fallible`].
#[allow(clippy::expect_used)]
pub(crate) fn shl(a: &[Limb], bits: usize) -> Vec<Limb> {
    shl_fallible(a, bits).expect("limbs::shl: allocation failed")
}

/// `a << bits`, or `None` when the result cannot be allocated.
pub(crate) fn shl_fallible(a: &[Limb], bits: usize) -> Option<Vec<Limb>> {
    if a.is_empty() {
        return Some(Vec::new());
    }
    let (whole, part) = (bits / 64, bits % 64);
    if part == 0 {
        let len = whole.checked_add(a.len())?;
        let mut out = crate::bn::alloc::try_zeroed(len, 0u64)?;
        out[whole..].copy_from_slice(a);
        normalise(&mut out);
        return Some(out);
    }
    let len = whole.checked_add(a.len())?.checked_add(1)?;
    let mut out = crate::bn::alloc::try_zeroed(len, 0u64)?;
    let mut carry = 0u64;
    for (k, &l) in a.iter().enumerate() {
        out[whole + k] = (l << part) | carry;
        carry = l >> (64 - part);
    }
    out[whole + a.len()] = carry;
    normalise(&mut out);
    Some(out)
}

/// `a >> bits` — a floor division by a power of two on the magnitude.
///
/// Infallible wrapper for the variable-time public path; the constant-time path
/// uses [`shr_fallible`].
#[allow(clippy::expect_used)]
pub(crate) fn shr(a: &[Limb], bits: usize) -> Vec<Limb> {
    shr_fallible(a, bits).expect("limbs::shr: allocation failed")
}

/// `a >> bits`, or `None` when the result cannot be allocated.
pub(crate) fn shr_fallible(a: &[Limb], bits: usize) -> Option<Vec<Limb>> {
    let (whole, part) = (bits / 64, bits % 64);
    if whole >= a.len() {
        return Some(Vec::new());
    }
    let src = &a[whole..];
    if part == 0 {
        let mut out = crate::bn::alloc::try_clone_slice(src)?;
        normalise(&mut out);
        return Some(out);
    }
    let mut out = crate::bn::alloc::try_zeroed(src.len(), 0u64)?;
    for i in 0..src.len() {
        let hi = if i + 1 < src.len() { src[i + 1] } else { 0 };
        out[i] = (src[i] >> part) | (hi << (64 - part));
    }
    normalise(&mut out);
    Some(out)
}

/// `a & b`, limbwise.
///
/// Test-only convenience wrapper; the entry points use [`and_fallible`].
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn and(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    and_fallible(a, b).expect("limbs::and: allocation failed")
}

/// `a & b`, limbwise, or `None` when the result cannot be allocated.
pub(crate) fn and_fallible(a: &[Limb], b: &[Limb]) -> Option<Vec<Limb>> {
    let n = a.len().min(b.len());
    let mut out = crate::bn::alloc::try_zeroed(n, 0u64)?;
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = a[i] & b[i];
    }
    normalise(&mut out);
    Some(out)
}

/// The low limb, or zero.
pub(crate) fn low_u64(v: &[Limb]) -> u64 {
    v.first().copied().unwrap_or(0)
}

/// A single limb as a value.
#[allow(clippy::expect_used)]
pub(crate) fn from_u64(w: u64) -> Vec<Limb> {
    from_u64_fallible(w).expect("limbs::from_u64: allocation failed")
}

/// A single limb as a value, or `None` when the one-element allocation fails.
pub(crate) fn from_u64_fallible(w: u64) -> Option<Vec<Limb>> {
    if w == 0 {
        Some(Vec::new())
    } else {
        crate::bn::alloc::try_zeroed(1, w)
    }
}

/// Divide by a single limb, returning `(quotient, remainder)`.
///
/// The caller must not pass zero. Infallible wrapper for the variable-time
/// public path; the constant-time path uses [`div_rem_small_fallible`].
#[allow(clippy::expect_used)]
pub(crate) fn div_rem_small(a: &[Limb], d: Limb) -> (Vec<Limb>, Limb) {
    div_rem_small_fallible(a, d).expect("limbs::div_rem_small: allocation failed")
}

/// Divide by a single limb, or `None` when the quotient cannot be allocated.
pub(crate) fn div_rem_small_fallible(a: &[Limb], d: Limb) -> Option<(Vec<Limb>, Limb)> {
    let mut out = crate::bn::alloc::try_zeroed(a.len(), 0u64)?;
    let mut rem = 0u128;
    for i in (0..a.len()).rev() {
        let cur = (rem << 64) | (a[i] as u128);
        out[i] = (cur / (d as u128)) as u64;
        rem = cur % (d as u128);
    }
    normalise(&mut out);
    Some((out, rem as u64))
}

/// `a mod m`, for a non-zero `m`.
///
/// Infallible wrapper for the variable-time public path; the constant-time path
/// uses [`rem_fallible`].
#[allow(clippy::expect_used)]
pub(crate) fn rem(a: &[Limb], m: &[Limb]) -> Vec<Limb> {
    rem_fallible(a, m).expect("limbs::rem: allocation failed")
}

/// `a mod m`, for a non-zero `m`, or `None` when the reduction cannot be
/// allocated.
pub(crate) fn rem_fallible(a: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    if m.len() == 1 {
        let (q, r) = div_rem_small_fallible(a, m[0])?;
        // The quotient has no reader here and derives from the (possibly secret)
        // dividend. Adopting it immediately makes its release cleanse the block;
        // no fallible step runs between the return and this adoption.
        drop(crate::bn::secret::SecretBuf::from_vec(q));
        return from_u64_fallible(r);
    }
    let (q, r) = div_rem_fallible(a, m)?;
    // As above: under the T23 chains the dividend is secret, and this quotient is
    // an intermediate the remainder-only caller never observes.
    drop(crate::bn::secret::SecretBuf::from_vec(q));
    Some(r)
}

/// `(a, b) -> (quotient, remainder)`. `b` must be non-zero.
///
/// Knuth's Algorithm D: textbook long division generalised to machine words. The
/// implementation is deliberately literal, including `D1`'s normalisation shift,
/// because the classic failure of this algorithm is a quotient-digit estimate that
/// is occasionally too large, and the add-back in `D6` is what makes the estimate
/// safe rather than approximate.
/// Infallible wrapper for the variable-time public path; the constant-time path
/// uses [`div_rem_fallible`].
#[allow(clippy::expect_used)]
pub(crate) fn div_rem(a: &[Limb], b: &[Limb]) -> (Vec<Limb>, Vec<Limb>) {
    div_rem_fallible(a, b).expect("limbs::div_rem: allocation failed")
}

/// `(a, b) -> (quotient, remainder)`, or `None` when an intermediate cannot be
/// allocated. `b` must be non-zero.
pub(crate) fn div_rem_fallible(a: &[Limb], b: &[Limb]) -> Option<(Vec<Limb>, Vec<Limb>)> {
    assert!(!b.is_empty(), "division by zero");
    if cmp(a, b) == core::cmp::Ordering::Less {
        return Some((Vec::new(), crate::bn::alloc::try_clone_slice(a)?));
    }
    if b.len() == 1 {
        let (q, r) = div_rem_small_fallible(a, b[0])?;
        return Some((q, from_u64_fallible(r)?));
    }

    // D1: normalise so the divisor's top limb has its high bit set.
    let shift = b[b.len() - 1].leading_zeros() as usize;
    // The shifted dividend, divisor and accumulator all derive from the operands.
    // On the T23 chains at least one operand is secret (an EC nonce's coordinate,
    // an RSA CRT prime), so these scratch buffers are secret-bearing and are
    // cleansed on every exit rather than released intact.
    let u = crate::bn::secret::SecretBuf::from_vec(if shift == 0 {
        crate::bn::alloc::try_clone_slice(a)?
    } else {
        shl_fallible(a, shift)?
    });
    let v = crate::bn::secret::SecretBuf::from_vec(if shift == 0 {
        crate::bn::alloc::try_clone_slice(b)?
    } else {
        shl_fallible(b, shift)?
    });
    let n = v.len();
    let m = u.len() - n;
    let mut un = crate::bn::secret::SecretBuf::try_zeroed(u.len().checked_add(1)?)?;
    un[..u.len()].copy_from_slice(&u);
    let mut q = crate::bn::alloc::try_zeroed(m.checked_add(1)?, 0u64)?;
    let vtop = v[n - 1] as u128;
    let vnext = v[n - 2] as u128;

    for j in (0..=m).rev() {
        // D3: estimate the quotient digit from the top two limbs.
        let top = ((un[j + n] as u128) << 64) | (un[j + n - 1] as u128);
        let mut qhat = top / vtop;
        let mut rhat = top % vtop;
        while qhat >= (1u128 << 64) || qhat * vnext > ((rhat << 64) | (un[j + n - 2] as u128)) {
            qhat -= 1;
            rhat += vtop;
            if rhat >= (1u128 << 64) {
                break;
            }
        }
        // D4: multiply and subtract.
        let mut borrow = 0i128;
        let mut carry = 0u128;
        for i in 0..n {
            let p = qhat * (v[i] as u128) + carry;
            carry = p >> 64;
            let t = (un[j + i] as i128) - ((p & 0xffff_ffff_ffff_ffff) as i128) - borrow;
            un[j + i] = (t & 0xffff_ffff_ffff_ffff) as u64;
            borrow = i128::from(t < 0);
        }
        let t = (un[j + n] as i128) - (carry as i128) - borrow;
        un[j + n] = (t & 0xffff_ffff_ffff_ffff) as u64;
        // D5/D6: add back when the estimate borrowed out.
        if t < 0 {
            qhat -= 1;
            let mut c = 0u128;
            for i in 0..n {
                let s = (un[j + i] as u128) + (v[i] as u128) + c;
                un[j + i] = s as u64;
                c = s >> 64;
            }
            un[j + n] = (un[j + n] as u128).wrapping_add(c) as u64;
        }
        q[j] = qhat as u64;
    }

    // D8: the remainder is the shifted-back low limbs.
    let mut r = crate::bn::alloc::try_clone_slice(&un[..n])?;
    if shift != 0 {
        r = shr_fallible(&r, shift)?;
    }
    normalise(&mut r);
    normalise(&mut q);
    Some((q, r))
}

/// Greatest common divisor, by the binary method.
pub(crate) fn gcd(a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    normalise(&mut x);
    normalise(&mut y);
    if x.is_empty() {
        return y;
    }
    if y.is_empty() {
        return x;
    }
    let shift = (x[0] | y[0]).trailing_zeros() as usize;
    x = shr(&x, x[0].trailing_zeros() as usize);
    y = shr(&y, y[0].trailing_zeros() as usize);
    loop {
        if cmp(&x, &y) == core::cmp::Ordering::Greater {
            core::mem::swap(&mut x, &mut y);
        }
        y = sub(&y, &x);
        if y.is_empty() {
            break;
        }
        y = shr(&y, y[0].trailing_zeros() as usize);
    }
    shl(&x, shift)
}

/// `a^-1 mod m`, or `None` when no inverse exists.
///
/// The extended Euclidean algorithm iterating on remainders. The coefficient is
/// reduced modulo `m` at every step; without that it grows like the product of the
/// quotients and the operation becomes quadratic in the wrong variable.
pub(crate) fn mod_inverse(a: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    // There is no inverse modulo zero, and the question cannot be expressed as a
    // remainder: `rem` would assert. Answering `None` here rather than letting the
    // assertion fire is what keeps a misuse of the public entry point a reported
    // failure instead of a panic crossing the ABI boundary.
    if m.is_empty() {
        return None;
    }
    if m.len() == 1 && m[0] == 1 {
        return Some(Vec::new());
    }
    let a = rem(a, m);
    if a.is_empty() {
        return None;
    }
    let (mut r0, mut r1) = (m.to_vec(), a);
    let (mut t0, mut t1) = (Vec::<Limb>::new(), vec![1u64]);
    while !r1.is_empty() {
        let (q, r2) = div_rem(&r0, &r1);
        let prod_mod = rem(&mul(&q, &t1), m);
        let t2 = if cmp(&t0, &prod_mod) != core::cmp::Ordering::Less {
            sub(&t0, &prod_mod)
        } else {
            sub(m, &sub(&prod_mod, &t0))
        };
        r0 = r1;
        r1 = r2;
        t0 = t1;
        t1 = t2;
    }
    if !(r0.len() == 1 && r0[0] == 1) {
        return None;
    }
    Some(rem(&t0, m))
}

// ---------------------------------------------------------------------------------------------
// Fixed-iteration binary extended GCD for secret operands
// ---------------------------------------------------------------------------------------------
//
// [`mod_inverse_consttime_with_mask`] implements the binary extended Euclidean
// algorithm with a loop count fixed by the *limb counts* of its operands. Every
// branch on an operand value is replaced by an all-ones/all-zeros mask and a
// select, and the coefficient is kept reduced modulo `m` so its width never
// depends on the value. It is a different function from the variable-time
// [`mod_inverse`] above: this one must never be described as the ordinary
// extended Euclidean algorithm, whose quotient sequence is data-dependent.
//
// **Domain.** The modulus must be non-zero and **odd**. Oddness is what makes the
// coefficient update `(x + m) / 2` the correct modular halving; an even modulus is
// refused rather than computed wrongly (the caller keeps the variable-time path,
// which handles that domain). The modulus' limb count and the operand's limb count
// are treated as public geometry: they size the iteration count and the buffers,
// never a value. The operand may be wider than the modulus (for example
// `(p - 1)^-1 mod e` in RSA key generation), in which case the wider limb count is
// the public width.

/// All-ones when `x == 0`, all-zeros otherwise.
#[inline(always)]
fn ct_mask_is_zero(x: Limb) -> Limb {
    // `x | -x` has the high bit set exactly when `x != 0`; subtracting one from
    // that bit gives the mask. No comparison is in control position.
    let non_zero = x | x.wrapping_neg();
    (non_zero >> (Limb::BITS - 1)).wrapping_sub(1)
}

/// `out = a - b` at the width of `out`, answering an all-ones borrow mask when
/// `a < b`. Missing limbs of either operand are zero.
#[inline(always)]
fn ct_sub_into(out: &mut [Limb], a: &[Limb], b: &[Limb]) -> Limb {
    let mut borrow: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = ai.overflowing_sub(bi);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *o = d2;
        borrow = Limb::from(b1) | Limb::from(b2);
    }
    0u64.wrapping_sub(borrow)
}

/// `out = a + b` at the width of `out`; a carry out of the last limb is stored in
/// `out` only when the caller supplies a wider `out` than its operands (as
/// [`ct_halve_mod_into`] does with `m.len() + 1` limbs).
#[inline(always)]
fn ct_add_into(out: &mut [Limb], a: &[Limb], b: &[Limb]) {
    let mut carry: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        let (s1, c1) = ai.overflowing_add(bi);
        let (s2, c2) = s1.overflowing_add(carry);
        *o = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
}

/// `out = a >> 1`, with `carry_in` shifted into the most significant bit.
#[inline(always)]
fn ct_shr1_into(out: &mut [Limb], a: &[Limb], carry_in: Limb) {
    let mut next = carry_in & 1;
    for (i, o) in out.iter_mut().enumerate().rev() {
        let v = a.get(i).copied().unwrap_or(0);
        *o = (v >> 1) | (next << (Limb::BITS - 1));
        next = v & 1;
    }
}

/// `out = select(m2, a2, select(m1, a1, base))`, which is how one of four
/// mutually exclusive candidates is chosen without aliasing an input slice.
#[inline(always)]
fn ct_select2_into(out: &mut [Limb], m1: Limb, a1: &[Limb], m2: Limb, a2: &[Limb], base: &[Limb]) {
    // The authority's `value_barrier_bn` on the two secret masks: a best-effort
    // optimisation barrier that keeps the nested selects from being recognised and
    // lowered to branches. It is not a guarantee about the emitted code or its
    // timing (see `runtime::constant_time`'s module note).
    let m1 = core::hint::black_box(m1);
    let m2 = core::hint::black_box(m2);
    for (i, o) in out.iter_mut().enumerate() {
        let bv = base.get(i).copied().unwrap_or(0);
        let av1 = a1.get(i).copied().unwrap_or(0);
        let v1 = (m1 & av1) | (!m1 & bv);
        let av2 = a2.get(i).copied().unwrap_or(0);
        *o = (m2 & av2) | (!m2 & v1);
    }
}

/// `out = (a - b) mod m`, for `a, b < m` and odd `m`. `tmp` is `m.len()` limbs of
/// scratch.
#[inline(always)]
fn ct_sub_mod_into(out: &mut [Limb], a: &[Limb], b: &[Limb], m: &[Limb], tmp: &mut [Limb]) {
    let borrow = ct_sub_into(tmp, a, b);
    // When the subtraction borrowed, `tmp` holds `2^w + a - b`; adding `m` and
    // discarding the carry out of the width gives `a - b + m`, which is in
    // `[0, m)`. `borrow` is all-ones exactly in that case.
    let mut carry: Limb = 0;
    for (i, o) in out.iter_mut().enumerate() {
        let add = m.get(i).copied().unwrap_or(0) & borrow;
        let (s1, c1) = tmp.get(i).copied().unwrap_or(0).overflowing_add(add);
        let (s2, c2) = s1.overflowing_add(carry);
        *o = s2;
        carry = Limb::from(c1) | Limb::from(c2);
    }
}

/// `out = x / 2 mod m` for odd `m` and `x < m`: `x >> 1` when `x` is even and
/// `(x + m) >> 1` when it is odd. `sum` is `m.len() + 1` limbs and `half` is
/// `m.len()` limbs of scratch.
#[inline(always)]
fn ct_halve_mod_into(
    out: &mut [Limb],
    x: &[Limb],
    m: &[Limb],
    sum: &mut [Limb],
    half: &mut [Limb],
) {
    // `value_barrier_bn` on a mask derived from a secret limb's low bit; the same
    // best-effort barrier, and the same non-guarantee, as in `ct_select2_into`.
    let odd = core::hint::black_box(0u64.wrapping_sub(x.first().copied().unwrap_or(0) & 1));
    ct_shr1_into(out, x, 0);
    ct_add_into(sum, x, m);
    // `sum` has `m.len() + 1` limbs, so `sum[m.len()]` is `x + m`'s carry bit.
    ct_shr1_into(half, &sum[..m.len()], sum[m.len()]);
    // Select in place: `out` already holds the even candidate, `half` the odd one.
    for (i, o) in out.iter_mut().enumerate() {
        let odd_value = half.get(i).copied().unwrap_or(0);
        *o = (odd & odd_value) | (!odd & *o);
    }
}

/// Constant-time `a^-1 mod m` for **odd** `m`, answering the coefficient and an
/// all-ones invertibility mask.
///
/// The loop runs exactly `2 * 64 * max(a.len(), m.len()) + 2` times, a function of
/// the public limb counts alone. It maintains
///
/// ```text
///     u == a * x1 (mod m)        v == a * x2 (mod m)
/// ```
///
/// starting from `(u, v, x1, x2) = (a, m, 1, 0)` and applying, per iteration, the
/// first applicable of: halve `u`; halve `v`; subtract the smaller odd value from
/// the larger and halve; until `u == 0`. Then `v == gcd(a, m)` and `x2` is
/// `a^-1 * gcd(a, m) mod m`; the mask is all-ones exactly when that gcd is one.
/// A zero `u` only occurs once `v` is already the gcd, so the remaining fixed
/// iterations are harmless (they halve `u` and `x1` only).
///
/// ## Storage and width
///
/// Every scratch buffer is a [`SecretLimbs`] (the crate's heap secret-owner
/// policy), allocated once before the loop through the fallible seam. `Drop`
/// volatile-wipes each allocation on every exit path — the normal return, an
/// early `?` allocation failure and an unwind — so no intermediate is released
/// intact. The returned coefficient is the one allocation that crosses the
/// boundary: it is copied out, after the loop, into the ordinary (result-transfer)
/// vector the caller stores, exactly as the ladder transfers its product.
///
/// Two widths occur. `m.len()` sizes the coefficient buffers (`x1 x2 nx1 nx2 dtmp
/// h1 h2 haux` and `sum = m.len() + 1`), because the coefficients are kept reduced
/// modulo `m`. `wide = max(m.len(), a.len())` sizes `u v nu nv cu cv diff_uv
/// diff_vu`, because the operand may be wider than the modulus. `a` is
/// zero-extended into `u` at `wide` limbs, so no buffer is sized by a limb
/// **value**. The widths are the operands' normalised limb counts: the modulus'
/// length is public on every constant-time caller (field, group order, RSA
/// modulus, or a prime of the requested key size), and the operand's length is
/// the length metadata a normalised `BIGNUM` already exposes through
/// `BN_num_bits` (the recorded T8 residual), not a new value-dependent branch.
/// Removing it would require a public-width parameter at the C ABI (an API/ABI
/// change) or a constant-time reduction of an arbitrarily wide secret operand
/// (not implemented; the variable-time `rem` would leak). It is therefore
/// recorded, not reclassified.
///
/// Answers `None` for an empty or even modulus: that is a domain refusal, visible
/// from the modulus alone, not a value-dependent branch on `a`.
pub(crate) fn mod_inverse_consttime_with_mask(a: &[Limb], m: &[Limb]) -> Option<(Vec<Limb>, Limb)> {
    if m.is_empty() || is_even(m) {
        return None;
    }
    let w = m.len();
    let wide = w.max(a.len());
    let bits = wide.checked_mul(Limb::BITS as usize)?;
    let iterations = bits.checked_mul(2)?.checked_add(2)?;

    // All scratch is allocated once, before the fixed-iteration loop, through the
    // fallible seam: an allocation failure is the entry point's ordinary error
    // answer, not `handle_alloc_error`. Each buffer is owned by `SecretLimbs`, so
    // its `Drop` cleanses it on the normal return, an early `?` and an unwind.
    let mut u = SecretLimbs::try_zeroed(wide)?;
    u[..a.len()].copy_from_slice(a);
    let mut v = SecretLimbs::try_zeroed(wide)?;
    v[..w].copy_from_slice(m);
    let mut x1 = SecretLimbs::try_zeroed(w)?;
    x1[0] = 1;
    let mut x2 = SecretLimbs::try_zeroed(w)?;

    let mut nu = SecretLimbs::try_zeroed(wide)?;
    let mut nv = SecretLimbs::try_zeroed(wide)?;
    let mut cu = SecretLimbs::try_zeroed(wide)?;
    let mut cv = SecretLimbs::try_zeroed(wide)?;
    let mut diff_uv = SecretLimbs::try_zeroed(wide)?;
    let mut diff_vu = SecretLimbs::try_zeroed(wide)?;

    let mut nx1 = SecretLimbs::try_zeroed(w)?;
    let mut nx2 = SecretLimbs::try_zeroed(w)?;
    let mut dtmp = SecretLimbs::try_zeroed(w)?;
    let mut h1 = SecretLimbs::try_zeroed(w)?;
    let mut h2 = SecretLimbs::try_zeroed(w)?;
    let mut haux = SecretLimbs::try_zeroed(w)?;
    let mut sum = SecretLimbs::try_zeroed(w.checked_add(1)?)?;

    // Test-only hook: the scratch is local to this function, so a test cannot hold
    // a pointer to it. A caller asks the probe to arm `sum` (which holds the
    // non-zero `x + m` after the loop) and then reads what `Drop` observed. `sum`
    // is never swapped, so the armed address stays the same allocation.
    #[cfg(test)]
    if crate::bn::secret::drop_probe::take_request() {
        crate::bn::secret::drop_probe::arm(sum.as_ptr());
    }

    for _ in 0..iterations {
        let u_odd = 0u64.wrapping_sub(u[0] & 1);
        let v_odd = 0u64.wrapping_sub(v[0] & 1);
        let u_even = !u_odd;
        let borrow_uv = ct_sub_into(&mut diff_uv, &u, &v);
        let u_ge_v = !borrow_uv;
        ct_sub_into(&mut diff_vu, &v, &u);

        // Exactly one of the four cases is selected; `c1`/`c3` are disjoint and
        // so are `c2`/`c4`.
        let c1 = u_even;
        let c2 = u_odd & !v_odd;
        let both_odd = u_odd & v_odd;
        let c3 = both_odd & u_ge_v;
        let c4 = both_odd & borrow_uv;

        ct_shr1_into(&mut cu, &u, 0);
        ct_shr1_into(&mut cv, &diff_uv, 0);
        ct_select2_into(&mut nu, c1, &cu, c3, &cv, &u);

        ct_shr1_into(&mut cu, &v, 0);
        ct_shr1_into(&mut cv, &diff_vu, 0);
        ct_select2_into(&mut nv, c2, &cu, c4, &cv, &v);

        ct_halve_mod_into(&mut h1, &x1, m, &mut sum, &mut haux);
        ct_sub_mod_into(&mut dtmp, &x1, &x2, m, &mut haux);
        ct_halve_mod_into(&mut h2, &dtmp, m, &mut sum, &mut haux);
        ct_select2_into(&mut nx1, c1, &h1, c3, &h2, &x1);

        ct_halve_mod_into(&mut h1, &x2, m, &mut sum, &mut haux);
        ct_sub_mod_into(&mut dtmp, &x2, &x1, m, &mut haux);
        ct_halve_mod_into(&mut h2, &dtmp, m, &mut sum, &mut haux);
        ct_select2_into(&mut nx2, c2, &h1, c4, &h2, &x2);

        core::mem::swap(&mut u, &mut nu);
        core::mem::swap(&mut v, &mut nv);
        core::mem::swap(&mut x1, &mut nx1);
        core::mem::swap(&mut x2, &mut nx2);
    }

    // `v == 1` iff the inverse exists. The comparison is mask arithmetic; the
    // returned mask is the declassification value the caller decides on.
    let mut diff = v[0] ^ 1;
    for &limb in &v[1..] {
        diff |= limb;
    }
    // The coefficient is the result-transfer allocation: it is copied out of the
    // cleansed `x2` into the ordinary vector the caller stores (and whose `BIGNUM`
    // release cleanses), so no secret intermediate is returned alive.
    let mut inverse = crate::bn::alloc::try_zeroed(w, 0u64)?;
    inverse.copy_from_slice(&x2);
    Some((inverse, ct_mask_is_zero(diff)))
}

/// Constant-time `a^-1 mod m` for odd `m`, or `None` when no inverse exists.
///
/// The returned vector is the fixed width `m.len()`: it is **not** trimmed, so a
/// caller storing it must use a branch-free store (`store_consttime` in
/// `bn::bignum`) rather than `normalise`. The single branch on the invertibility
/// mask below is the authorised declassification point for the error result; the
/// algorithm itself never branches on a value.
///
pub(crate) fn mod_inverse_consttime(a: &[Limb], m: &[Limb]) -> Option<Vec<Limb>> {
    let (inverse, invertible) = mod_inverse_consttime_with_mask(a, m)?;
    if invertible == 0 {
        None
    } else {
        Some(inverse)
    }
}

/// Whether `a` is even.
pub(crate) fn is_even(a: &[Limb]) -> bool {
    a.first().map(|&l| l & 1 == 0).unwrap_or(true)
}

/// Whether `a` and `b` are coprime.
pub(crate) fn are_coprime(a: &[Limb], b: &[Limb]) -> bool {
    let g = gcd(a, b);
    g.len() == 1 && g[0] == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(h: &str) -> Vec<Limb> {
        let mut out: Vec<Limb> = Vec::new();
        for c in h.chars() {
            let Some(d) = c.to_digit(16) else {
                unreachable!("the tests pass hex digits")
            };
            let mut carry = d as u64;
            for limb in out.iter_mut() {
                let t = ((*limb as u128) << 4) | (carry as u128);
                *limb = t as u64;
                carry = (t >> 64) as u64;
            }
            if carry != 0 {
                out.push(carry);
            }
        }
        normalise(&mut out);
        out
    }

    fn to_hex(v: &[Limb]) -> String {
        if v.is_empty() {
            return "0".to_string();
        }
        let mut s = format!("{:x}", v[v.len() - 1]);
        for l in v[..v.len() - 1].iter().rev() {
            s.push_str(&format!("{l:016x}"));
        }
        s
    }

    #[test]
    fn hex_helpers_round_trip_the_limb_boundary() {
        for h in [
            "1",
            "ffffffffffffffff",
            "10000000000000000",
            "deadbeefcafebabe0123456789abcdef",
        ] {
            assert_eq!(to_hex(&from_hex(h)), h);
        }
        assert!(from_hex("0").is_empty());
        assert_eq!(to_hex(&from_hex("0")), "0");
    }

    #[test]
    fn add_carries_across_the_limb_boundary() {
        assert_eq!(add(&[u64::MAX], &[1]), vec![0, 1]);
        assert_eq!(add(&[u64::MAX], &[u64::MAX]), vec![u64::MAX - 1, 1]);
        assert_eq!(add(&[1, 2], &[]), vec![1, 2]);
    }

    #[test]
    fn sub_borrows_and_normalises() {
        assert_eq!(sub(&[0, 1], &[1]), vec![u64::MAX]);
        assert_eq!(sub(&[5], &[5]), Vec::<Limb>::new());
        assert_eq!(sub_word(&[5], 6), None);
        assert_eq!(sub_word(&[5], 5), Some(Vec::new()));
    }

    #[test]
    fn mul_matches_known_products() {
        let m = u64::MAX;
        assert_eq!(to_hex(&mul(&[m], &[m])), "fffffffffffffffe0000000000000001");
        // Ground truth from an independent bignum, not from arithmetic done in
        // this test author's head: the first version of this expectation was
        // wrong and the implementation was right.
        assert_eq!(
            to_hex(&mul(
                &from_hex("123456789abcdef"),
                &from_hex("fedcba987654321")
            )),
            "121fa00ad77d7422236d88fe5618cf"
        );
        assert!(mul(&Vec::new(), &[7]).is_empty());
    }

    #[test]
    fn div_rem_satisfies_its_definition_on_awkward_shapes() {
        // q*b + r == a with r < b, over operands that exercise the D3 estimate and
        // the D6 add-back.
        let cases = [
            ("ffffffffffffffffffffffffffffffff", "10000000000000000"),
            ("80000000000000000000000000000001", "ffffffffffffffff"),
            ("ffffffffffffffff0000000000000001", "fffffffffffffffe"),
            ("1", "ffffffffffffffffffffffffffffffff"),
            ("10000000000000000000000000000000000000000", "3"),
            (
                "ffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffff",
            ),
        ];
        for (a, b) in cases {
            let (av, bv) = (from_hex(a), from_hex(b));
            let (q, r) = div_rem(&av, &bv);
            assert_eq!(cmp(&r, &bv), core::cmp::Ordering::Less, "r < b for {a}/{b}");
            assert_eq!(
                to_hex(&add(&mul(&q, &bv), &r)),
                a.trim_start_matches('0'),
                "q*b+r == a for {a}/{b}"
            );
        }
        let (q, r) = div_rem(&from_hex("1000000000000000000000000"), &from_hex("1000"));
        assert_eq!(to_hex(&q), "1000000000000000000000");
        assert!(r.is_empty());
    }

    #[test]
    fn shifts_cross_limb_boundaries() {
        assert_eq!(shl(&[1], 63), vec![1u64 << 63]);
        assert_eq!(shl(&[1], 64), vec![0, 1]);
        assert_eq!(shl(&[1], 65), vec![0, 2]);
        assert_eq!(shr(&[0, 1], 64), vec![1]);
        assert_eq!(shr(&[1], 1), Vec::<Limb>::new());
        let v = from_hex("123456789abcdef0fedcba9876543210");
        for bits in [0usize, 1, 63, 64, 65, 127, 128] {
            assert_eq!(shr(&shl(&v, bits), bits), v, "round trip at {bits}");
        }
    }

    #[test]
    fn bit_and_word_helpers_agree_with_the_values() {
        let a = from_hex("ff00ff00ff00ff00");
        let b = from_hex("0f0f0f0f0f0f0f0f");
        assert_eq!(to_hex(&and(&a, &b)), "f000f000f000f00");
        let mut v = from_hex("0");
        set_bit(&mut v, 130);
        assert!(bit(&v, 130) && bit_len(&v) == 131);
        clear_bit(&mut v, 130);
        assert!(v.is_empty());
        assert_eq!(bit_len_word(0), 0);
        assert_eq!(bit_len_word(1), 1);
        assert_eq!(bit_len_word(u64::MAX), 64);
        assert_eq!(add_word(&[u64::MAX], 1), vec![0, 1]);
        assert_eq!(mul_word(&[3], 5), vec![15]);
    }

    #[test]
    fn gcd_inverse_and_coprimality_agree_with_small_arithmetic() {
        assert_eq!(gcd(&[12], &[18]), vec![6]);
        assert_eq!(gcd(&Vec::new(), &[5]), vec![5]);
        assert_eq!(gcd(&[270], &[192]), vec![6]);
        assert_eq!(mod_inverse(&[3], &[11]), Some(vec![4]));
        assert_eq!(mod_inverse(&[6], &[9]), None);
        assert!(are_coprime(&[3], &[11]));
        assert!(!are_coprime(&[6], &[9]));
    }

    #[test]
    fn mod_inverse_satisfies_its_definition() {
        // 2^81 + 5, coprime with the operand below. The first version of this test
        // used a modulus sharing the factor 147 with the operand and therefore
        // asserted an inverse that correctly does not exist.
        let m = from_hex("200000000000000000005");
        let a = from_hex("123456789abcdef123456789abcdef12345");
        let Some(inv) = mod_inverse(&a, &m) else {
            unreachable!("coprime operands have an inverse")
        };
        assert_eq!(rem(&mul(&a, &inv), &m), vec![1u64], "a * a^-1 == 1 mod m");
    }

    #[test]
    fn fixed_iteration_inverse_matches_the_variable_time_result() {
        let moduli = vec![
            Vec::<Limb>::new(),
            vec![1],
            vec![2],
            vec![3],
            vec![9],
            vec![11],
            vec![15],
            vec![35],
            vec![3233], // 61 * 53, an odd composite RSA-sized shape
            from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc5"),
        ];
        let values = vec![
            Vec::<Limb>::new(),
            vec![1],
            vec![2],
            vec![3],
            vec![6],
            vec![7],
            vec![9],
            vec![10],
            vec![11],
            vec![15],
            vec![20],
            vec![61],
            from_hex("123456789abcdef123456789abcdef12345"),
        ];
        for m in &moduli {
            for a in &values {
                let variable = mod_inverse(a, m);
                let constant = mod_inverse_consttime(a, m);
                if m.is_empty() || is_even(m) {
                    assert!(
                        constant.is_none(),
                        "the constant-time path refuses an even or zero modulus: a={a:?} m={m:?}"
                    );
                    continue;
                }
                match (variable, constant) {
                    (Some(mut want), Some(mut got)) => {
                        normalise(&mut want);
                        normalise(&mut got);
                        assert_eq!(got, want, "a={a:?} m={m:?}");
                        // Modulo one every residue is zero; the established
                        // answer is zero and `a * 0 == 0`, not one.
                        if !(m.len() == 1 && m[0] == 1) {
                            assert_eq!(rem(&mul(a, &got), m), vec![1u64], "a * a^-1 == 1");
                        }
                    }
                    (None, None) => {}
                    (want, got) => {
                        unreachable!("disagreement: a={a:?} m={m:?} want={want:?} got={got:?}")
                    }
                }
            }
        }
    }

    #[test]
    fn fixed_iteration_inverse_covers_the_edge_domains() {
        // Zero modulus: no inverse, and no panic.
        assert_eq!(mod_inverse_consttime(&[3], &[]), None);
        // Modulus one keeps this crate's established answer (zero), which the
        // authority-compatible public wrapper has always produced here.
        assert_eq!(
            mod_inverse_consttime(&[7], &[1]).map(|mut v| {
                normalise(&mut v);
                v
            }),
            Some(Vec::new())
        );
        // Zero is not invertible modulo any modulus greater than one.
        assert_eq!(mod_inverse_consttime(&[], &[7]), None);
        // A value congruent to zero is not invertible either.
        assert_eq!(mod_inverse_consttime(&[14], &[7]), None);
        // A value at or above the modulus is reduced by the algorithm itself.
        let Some(inv) = mod_inverse_consttime(&[20], &[7]) else {
            unreachable!("6 is coprime with 7")
        };
        assert_eq!(rem(&mul(&[20], &inv), &[7]), vec![1u64]);
        // Even moduli are outside the binary EEA's domain and are refused.
        assert_eq!(mod_inverse_consttime(&[3], &[8]), None);
        // Odd composite modulus: both an invertible and a non-invertible value.
        assert!(mod_inverse_consttime(&[7], &[15]).is_some());
        assert_eq!(mod_inverse_consttime(&[6], &[15]), None);
        // The smallest even modulus and a composite with a repeated factor.
        assert_eq!(mod_inverse_consttime(&[1], &[2]), None);
        assert_eq!(mod_inverse_consttime(&[6], &[9]), None);
        // An operand wider than a small odd modulus: RSA key generation's
        // `(p - 1)^-1 mod e` shape.
        let wide = from_hex("deadbeefcafebabe0123456789abcdefdeadbeef");
        let Some(inv) = mod_inverse_consttime(&wide, &[65537]) else {
            unreachable!("the test value is coprime with 65537")
        };
        assert_eq!(rem(&mul(&wide, &inv), &[65537]), vec![1u64]);
    }

    #[test]
    fn fixed_iteration_inverse_agrees_on_random_shapes() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            seed
        };
        for case in 0..256 {
            let m_len = 1 + (next() as usize % 8);
            let mut m: Vec<Limb> = (0..m_len).map(|_| next()).collect();
            m[0] |= 1; // odd domain
            let top = m.len() - 1;
            m[top] |= 1; // a non-zero top limb, so `m.len()` is the width
            let a_len = 1 + (next() as usize % (m_len + 2));
            let a: Vec<Limb> = (0..a_len).map(|_| next()).collect();

            let mut variable = mod_inverse(&a, &m);
            let mut constant = mod_inverse_consttime(&a, &m);
            if let Some(v) = variable.as_mut() {
                normalise(v);
            }
            if let Some(v) = constant.as_mut() {
                normalise(v);
            }
            assert_eq!(constant, variable, "case {case}: a={a:?} m={m:?}");
            if let Some(inv) = variable {
                if !(m.len() == 1 && m[0] == 1) {
                    assert_eq!(rem(&mul(&a, &inv), &m), vec![1u64], "case {case}");
                }
            }
        }
    }

    /// T24: the inversion's scratch is owned by [`SecretLimbs`], so `Drop`
    /// volatile-wipes every buffer before release, including the early-`?` and
    /// unwind paths.
    ///
    /// The buffers are local, so the test asks the inversion (test-only hook) to
    /// arm the drop probe on `sum`, which holds `x + m` — non-zero for an odd
    /// modulus — and then asserts the probe observed non-zero contents *before*
    /// the wipe and **zero** non-zero bytes after it. Removing the `SecretLimbs`
    /// ownership fails the test either with no observation or with surviving
    /// bytes.
    #[test]
    fn constant_time_inverse_scratch_is_cleansed_on_release() {
        use crate::bn::secret::drop_probe;

        let m = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc5");
        let a = from_hex("123456789abcdef123456789abcdef12345");

        drop_probe::request();
        let result = mod_inverse_consttime_with_mask(&a, &m);
        assert!(result.is_some(), "the operand is invertible");

        let observed = match drop_probe::take() {
            Some(observed) => observed,
            None => unreachable!("the inversion armed and released its scratch"),
        };
        assert!(
            observed.nonzero_before > 0,
            "the armed scratch holds non-zero secret-derived data before the wipe"
        );
        assert_eq!(
            observed.nonzero_bytes, 0,
            "the inversion scratch was released uncleansed"
        );
    }

    #[test]
    fn the_branchless_normalise_is_the_same_function() {
        let mut seed = 0x0123_4567_89ab_cdefu64;
        for len in 0..12 {
            for _ in 0..32 {
                let mut v: Vec<Limb> = (0..len)
                    .map(|_| {
                        seed = seed
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        // Mostly zeros, so several leading limbs are trimmed.
                        if seed & 3 == 0 {
                            seed
                        } else {
                            0
                        }
                    })
                    .collect();
                let mut expected = v.clone();
                normalise(&mut expected);
                let Some(keep) = normalise_consttime(&mut v, len) else {
                    unreachable!("the zero-extension allocation succeeds")
                };
                assert_eq!(v, expected, "len={len}");
                assert_eq!(keep, expected.len(), "len={len}");
            }
        }
    }

    /// T8: two results with the same declared public width but different bit
    /// lengths must trim in exactly the same pattern.
    ///
    /// The first magnitude's top limb is zero, so its normalised length is one;
    /// the second is full width; the third arrives already trimmed, which is the
    /// variable-time fallback shape and must still be scanned at the declared
    /// width. An implementation that scanned `v.len()` or used [`normalise`]
    /// would report a different iteration count for at least one case — this is
    /// the regression the probe exists to catch.
    #[test]
    fn the_consttime_trim_scans_the_public_width_not_the_result_length() {
        let width = 4usize;
        let mut cases = [
            vec![0x8000_0000_0000_0000u64, 0, 0, 0],
            vec![0x1234, 0x5678, 0x9abc, 0x8000_0000_0000_0000],
            vec![7u64],
        ];
        let mut keeps = Vec::new();
        for (case, v) in cases.iter_mut().enumerate() {
            trim_probe::arm();
            let Some(keep) = normalise_consttime(v, width) else {
                unreachable!("the zero-extension allocation succeeds")
            };
            let (iterations, selects) = trim_probe::disarm();
            assert_eq!(
                iterations, width,
                "case {case}: the scan must visit every public limb"
            );
            assert_eq!(
                selects, width,
                "case {case}: one masked select per public limb"
            );
            assert_eq!(
                v.len(),
                keep,
                "case {case}: the trim reports what it installed"
            );
            keeps.push(keep);
        }
        assert_eq!(keeps[0], 1, "the first result is one limb long");
        assert_eq!(keeps[1], width, "the second result is full width");
        assert_ne!(keeps[0], keeps[1], "the two results have different lengths");
    }

    #[test]
    fn compare_treats_trailing_zeros_as_insignificant() {
        assert_eq!(cmp(&[5, 0, 0], &[5]), core::cmp::Ordering::Equal);
        assert_eq!(cmp(&[], &[0]), core::cmp::Ordering::Equal);
        assert_eq!(cmp(&[0, 1], &[u64::MAX]), core::cmp::Ordering::Greater);
    }

    #[test]
    fn rem_and_small_division_agree() {
        let a = from_hex("123456789abcdef0123456789abcdef");
        let (q, r) = div_rem_small(&a, 1000);
        assert_eq!(add(&mul(&q, &[1000]), &from_u64(r)), a);
        assert_eq!(rem(&a, &[1000]), from_u64(r));
    }

    /// The constant-time scans agree with the variable-time ones on every limb
    /// pattern that can occur in a magnitude, including zero and top-bit-set
    /// limbs.
    #[test]
    fn the_constant_time_bit_lengths_agree_with_the_variable_time_ones() {
        let words = [
            0u64,
            1,
            2,
            3,
            u64::MAX,
            0x8000_0000_0000_0000,
            0x0000_0001_0000_0000,
            0x00ff_0000_0000_00ff,
        ];
        for &w in &words {
            assert_eq!(bit_len_word_consttime(w), bit_len_word(w), "word={w:#x}");
            assert_eq!(bit_len_consttime(&[w]), bit_len(&[w]), "word={w:#x}");
        }
        let v = [0u64, 0, 0x0123_4567_89ab_cdef, 0, 0xfedc_ba98_7654_3210];
        assert_eq!(bit_len_consttime(&v), bit_len(&v));
        assert_eq!(bit_len_consttime(&[]), 0);
        assert_eq!(bit_len_consttime(&[0, 0, 0]), 0);
    }

    /// `2^bits mod m` agrees with the variable-time shift-and-remainder it
    /// replaced, for the shapes the Montgomery contexts use.
    #[test]
    fn pow2_mod_consttime_agrees_with_rem() {
        let m = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3211];
        for bits in [0usize, 1, 63, 64, 65, 127, 128, 256] {
            let expected = if bits == 0 {
                vec![1u64]
            } else {
                rem(&shl(&[1u64], bits), &m)
            };
            let mut got = pow2_mod_consttime(bits, &m).unwrap_or_default();
            normalise(&mut got);
            assert_eq!(got, expected, "bits={bits}");
        }
    }
}
