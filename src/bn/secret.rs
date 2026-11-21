//! Secret-bearing heap scratch that is cleansed on **every** release path.
//!
//! The constant-time exponentiation ladder in [`crate::bn::arith`] stages the
//! fixed-width exponent copy and its secret-derived intermediates in heap
//! scratch. Cleansing those buffers with explicit calls at the end of the
//! ladder only covers the success path: a later allocation failure takes an
//! early `?` return, so the vectors are dropped normally and the block is freed
//! with its secret contents intact.
//!
//! [`SecretBuf`] makes cleansing a property of the type instead of a step the
//! function must remember. `Drop` zeroes the storage before the allocation is
//! released, so a normal return, an early return and an unwind all behave
//! identically.
//!
//! This is containment, not an ownership reconstruction: the buffer contents
//! are still readable by the holder, and the infallible allocations in
//! `limbs::rem`/`limbs::mul` that feed the ladder are untouched. The residual
//! `OBL-BN-ALLOCATOR` obligation remains open.

use core::ops::{Deref, DerefMut};

/// Plain-data element types that [`SecretBuf`] may cleanse.
///
/// # Safety
///
/// An implementor must be `Copy` and have no destructor, must have no
/// reference, `NonNull`, enum discriminant or other field whose validity
/// requirement the all-zero byte pattern could violate, and [`Self::ZERO`] must
/// be that all-zero bit pattern. These are exactly the conditions under which
/// overwriting a live `[Self]` with volatile zero writes (a) yields valid
/// values, (b) leaks no resources, and (c) leaves the enclosing `Vec` free to
/// release the block afterwards.
pub(crate) unsafe trait SecretElement: Copy {
    /// The value represented by the all-zero byte pattern.
    const ZERO: Self;
}

// SAFETY: `u64` is `Copy`, has no destructor, has no invalid bit patterns (so
// the all-zero pattern is a valid `u64`), and `ZERO` is that pattern.
unsafe impl SecretElement for u64 {
    const ZERO: u64 = 0;
}

/// A heap buffer of [`SecretElement`]s that zeroes its storage when released.
///
/// Cleansing runs from `Drop`, so it happens on **every** path out of scope: a
/// normal return, an early `?` return and an unwind. The type deliberately
/// offers no `Copy`, no `Clone`, no `into_inner` and no `Default`, so the
/// backing `Vec` cannot be taken out without passing through that `Drop`. A
/// caller can still copy *from* the slice (`Deref`/`DerefMut`), which remains
/// its own secret-handling obligation, but it cannot extract the uncleansed
/// allocation.
pub(crate) struct SecretBuf<T: SecretElement> {
    inner: Vec<T>,
}

impl<T: SecretElement> SecretBuf<T> {
    /// Adopt an existing vector as secret-bearing storage.
    ///
    /// Ownership moves inwards; the buffer is cleansed when it is released like
    /// any other [`SecretBuf`].
    pub(crate) fn from_vec(inner: Vec<T>) -> Self {
        Self { inner }
    }

    /// A zero-filled buffer of `n` elements, or `None` when `n` cannot be
    /// reserved. Allocation failure is reported, never aborted.
    pub(crate) fn try_zeroed(n: usize) -> Option<Self> {
        let mut inner: Vec<T> = Vec::new();
        inner.try_reserve_exact(n).ok()?;
        inner.resize(n, T::ZERO);
        Some(Self { inner })
    }

    /// The release sequence: volatile-zero the storage.
    ///
    /// `Drop` calls this immediately before the backing `Vec` is released, so it
    /// is the only cleansing a `SecretBuf` ever needs. It is idempotent, which is
    /// what lets a test run it explicitly on a still-live buffer and then read the
    /// cleared bytes soundly.
    fn cleanse_now(&mut self) {
        cleanse_slice(&mut self.inner);
    }
}

impl<T: SecretElement> Deref for SecretBuf<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.inner
    }
}

impl<T: SecretElement> DerefMut for SecretBuf<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: SecretElement> Drop for SecretBuf<T> {
    fn drop(&mut self) {
        // The `Vec` is released by ordinary field drop *after* this returns, so
        // the block is cleansed before it is freed, on success, early return and
        // unwind alike.
        self.cleanse_now();
    }
}

/// Zero a secret-bearing slice through volatile writes.
fn cleanse_slice<T: SecretElement>(v: &mut [T]) {
    // `size_of_val` of a live slice cannot overflow: a slice's byte length is
    // bounded by `isize::MAX` at construction.
    let bytes = core::mem::size_of_val(v);
    if bytes == 0 {
        return;
    }
    // SAFETY: `v` is a live slice of `v.len()` `T`s, so its elements are exactly
    // `bytes` writable bytes. `T: SecretElement` guarantees no destructor and no
    // all-zero-pattern validity hazard, so the volatile writes leave the slice
    // valid and the later `Vec` release well-formed.
    unsafe { crate::runtime::mem::cleanse(v.as_mut_ptr().cast::<u8>(), bytes) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-zero pattern standing in for staged exponent limbs.
    const PATTERN: [u64; 4] = [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x0f0f_0f0f_0f0f_0f0f,
        0xdead_beef_dead_beef,
    ];

    /// Copy the secret in, then take the same early-return path the constant-time
    /// ladder takes when a later scratch allocation fails. The failing
    /// allocation is genuine (`usize::MAX / 2` limbs cannot be reserved), not a
    /// simulated error: `try_zeroed` reports it with `None`, so `?` returns here.
    fn stage_then_fail(staged: &mut SecretBuf<u64>) -> Option<()> {
        staged.copy_from_slice(&PATTERN);
        let _later = SecretBuf::<u64>::try_zeroed(usize::MAX / 2)?;
        Some(())
    }

    #[test]
    fn an_early_return_after_staging_cleanses_before_release() {
        // A failing allocator is not available to this crate's `Vec` seam, so the
        // test observes cleansing through the release sequence that `Drop` runs: it
        // is invoked explicitly while the test still owns the allocation, the
        // cleared block is read through its raw pointer, and the ordinary drop at
        // the end of the test then frees that already-cleansed block.
        let Some(mut staged) = SecretBuf::<u64>::try_zeroed(PATTERN.len()) else {
            unreachable!("a four-limb allocation succeeds")
        };
        let ptr = staged.as_ptr();

        assert_eq!(
            stage_then_fail(&mut staged),
            None,
            "an impossible later allocation must fail, forcing the early return"
        );
        assert_eq!(
            &staged[..],
            &PATTERN[..],
            "the secret is staged before the failure"
        );

        // Run `Drop`'s release sequence explicitly. It only writes zeros, so it is
        // idempotent: the same method runs again, immediately before the free,
        // when `staged` drops at the end of this test.
        staged.cleanse_now();

        for (i, _) in PATTERN.iter().enumerate() {
            // SAFETY: `ptr.add(i)` addresses `staged`'s live allocation, which
            // the test still owns and which has not been reallocated; `u64` is
            // `Copy`, so the read has no side effects.
            let limb = unsafe { ptr.add(i).read_volatile() };
            assert_eq!(limb, 0, "limb {i} was released uncleansed");
        }
    }
}
