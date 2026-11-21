//! Secret-bearing heap scratch that is cleansed on **every** release path.
//!
//! The storage policy — this heap form, the fixed-size stack form, the limb alias
//! and the borrowed view — is documented in [`crate::runtime::secret`]. This
//! module keeps the heap owner's implementation and its mutation controls.
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
//! Cleansing covers the **whole allocation**, not just the initialised prefix.
//! A `Vec` adopted through [`SecretBuf::from_vec`] may have been grown and then
//! shrunk, leaving earlier secret limbs in its spare capacity; `len()` does not
//! describe them, but they are still part of the block that is released.
//!
//! Whole-allocation cleansing is chosen over forcing `capacity == len` because
//! `from_vec` must adopt whatever vector its caller already produced: shrinking
//! to exact capacity can reallocate and would copy the secret through a second,
//! uncleansed temporary (leaving the old block behind), and it can fail. The
//! capacity is therefore read at release time, and every byte the vector owns is
//! zeroed before the release.
//!
//! This is containment, not an ownership reconstruction: the buffer contents
//! are still readable by the holder. The constant-time ladder's arithmetic and
//! scratch allocations now use the fallible helpers in [`crate::bn::alloc`], but
//! the copies made by [`crate::bn::bignum::parts`] on every entry-point argument
//! are still infallible `Vec` clones, so the residual `OBL-BN-ALLOCATOR`
//! obligation remains open.

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

// SAFETY: `u8` is `Copy`, has no destructor, has no invalid bit patterns (so the
// all-zero pattern is a valid `u8`), and `ZERO` is that pattern. This is what lets
// byte-sized secret staging use `SecretBuf<u8>` instead of a local `Vec` guard.
unsafe impl SecretElement for u8 {
    const ZERO: u8 = 0;
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
    /// any other [`SecretBuf`]. The adopted vector may carry spare capacity: the
    /// visible secret is `[..len()]`, but `Drop` zeroes every byte the vector's
    /// allocation owns, so nothing still in the buffer survives the release.
    pub(crate) fn from_vec(inner: Vec<T>) -> Self {
        Self { inner }
    }

    /// A zero-filled buffer of `n` elements, or `None` when `n` cannot be
    /// reserved. Allocation failure is reported, never aborted.
    ///
    /// `#[track_caller]` keeps the allocation-failure seam's site identity at the
    /// caller (for example each scratch buffer in the constant-time inversion)
    /// instead of collapsing every `SecretBuf` request onto this line.
    #[track_caller]
    pub(crate) fn try_zeroed(n: usize) -> Option<Self> {
        crate::bn::alloc::try_zeroed(n, T::ZERO).map(Self::from_vec)
    }

    /// The release sequence: volatile-zero the whole allocation.
    ///
    /// `Drop` calls this immediately before the backing `Vec` is released, so it
    /// is the only cleansing a `SecretBuf` ever needs. It is idempotent, which is
    /// what lets a test run it explicitly on a still-live buffer and then read the
    /// cleared bytes soundly.
    fn cleanse_now(&mut self) {
        cleanse_allocation(&mut self.inner);
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
        // Test-only: count the non-zero bytes first, so the observation says both
        // that the buffer held live secret data and that the wipe removed it.
        // Compiled out of every non-test build.
        #[cfg(test)]
        let nonzero_before = self.observe_before_for_test();
        // The `Vec` is released by ordinary field drop *after* this returns, so
        // the block is cleansed before it is freed, on success, early return and
        // unwind alike.
        self.cleanse_now();
        // Test-only: read the allocation now, while it is still live and before
        // the field drop releases it, so a test can prove that automatic
        // destruction cleansed. Compiled out of every non-test build.
        #[cfg(test)]
        self.observe_release_for_test(nonzero_before);
    }
}

/// Test-only observation seam for [`SecretBuf`]'s `Drop`.
///
/// A test-only global allocator would observe the real release, but installing
/// one `#[global_allocator]` would apply to the whole library test binary and
/// change allocation behaviour for every unrelated test. This seam instead
/// observes the last state of the armed allocation from inside `Drop`, after
/// cleansing and before the backing `Vec` is released — the strongest point that
/// is still a live, soundly readable allocation.
#[cfg(test)]
pub(crate) mod drop_probe {
    use core::cell::Cell;

    /// What `Drop` saw on an armed allocation.
    pub(crate) struct Observation {
        pub(crate) ptr: usize,
        /// Non-zero bytes immediately **before** the wipe.
        pub(crate) nonzero_before: usize,
        /// Non-zero bytes immediately **after** the wipe (expected `0`).
        pub(crate) nonzero_bytes: usize,
    }

    thread_local! {
        /// Address a test has armed, or 0 for none.
        static TARGET: Cell<usize> = const { Cell::new(0) };
        /// What the last armed `Drop` recorded on this thread.
        static SEEN: Cell<Option<Observation>> = const { Cell::new(None) };
        /// A one-shot request for a code path that owns its scratch privately to
        /// arm the probe on its next buffer.
        static REQUEST: Cell<bool> = const { Cell::new(false) };
    }

    /// Ask a cooperating code path to arm the probe on the scratch it is about to
    /// create and release. Used by call sites whose buffers are local, so a test
    /// cannot hold the pointer itself.
    pub(crate) fn request() {
        REQUEST.with(|r| r.set(true));
    }

    /// Consume a pending [`request`].
    pub(crate) fn take_request() -> bool {
        REQUEST.with(|r| r.replace(false))
    }

    pub(crate) fn arm(ptr: *const u64) {
        TARGET.with(|t| t.set(ptr as usize));
        SEEN.with(|s| s.set(None));
    }

    pub(super) fn is_armed(ptr: usize) -> bool {
        TARGET.with(|t| t.get() == ptr)
    }

    pub(super) fn record(ptr: usize, nonzero_before: usize, nonzero_bytes: usize) {
        SEEN.with(|s| {
            s.set(Some(Observation {
                ptr,
                nonzero_before,
                nonzero_bytes,
            }))
        });
    }

    pub(crate) fn take() -> Option<Observation> {
        SEEN.with(|s| s.take())
    }
}

#[cfg(test)]
impl<T: SecretElement> SecretBuf<T> {
    /// The allocation's element capacity: the extent `Drop` cleanses.
    ///
    /// Exposed only under `cfg(test)` so a test can assert that capacity is
    /// fixed by public geometry rather than by the input's normalised length.
    pub(crate) fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Count non-zero bytes *before* `Drop`'s cleanse. Runs only when the
    /// allocation was armed by a test on this thread.
    fn observe_before_for_test(&self) -> usize {
        if !drop_probe::is_armed(self.inner.as_ptr() as usize) {
            return 0;
        }
        self.nonzero_bytes()
    }

    /// Read the storage after `Drop`'s cleanse and record whether any byte
    /// survived. Runs only when the allocation was armed by a test on this
    /// thread, so unrelated `SecretBuf` drops are ignored.
    fn observe_release_for_test(&self, nonzero_before: usize) {
        let addr = self.inner.as_ptr() as usize;
        if !drop_probe::is_armed(addr) {
            return;
        }
        drop_probe::record(addr, nonzero_before, self.nonzero_bytes());
    }

    /// Count the non-zero bytes across the allocation the vector owns.
    ///
    /// # Safety-relevant precondition
    ///
    /// The caller reads every byte of the allocation, so every one of them must
    /// be initialised. The probe is only armed by tests that stage (or stage then
    /// shrink, after initialising all capacity slots) the buffer, which is the
    /// same precondition the release observation already relied on.
    fn nonzero_bytes(&self) -> usize {
        let Some(bytes) = self.inner.capacity().checked_mul(core::mem::size_of::<T>()) else {
            return 0;
        };
        let base = self.inner.as_ptr().cast::<u8>();
        let mut nonzero = 0usize;
        for i in 0..bytes {
            // SAFETY: `i < bytes` covers the allocation, so `base.add(i)` lies
            // inside `self.inner`'s live allocation. The block is still owned and
            // readable here (this runs inside `Drop`, before the field release);
            // the volatile read has no side effects and cannot be optimised away.
            if unsafe { base.add(i).read_volatile() } != 0 {
                nonzero += 1;
            }
        }
        nonzero
    }
}

/// Zero a secret-bearing allocation through volatile writes.
///
/// # Storage invariant
///
/// Every byte a [`SecretBuf`] can still expose at release time lies inside its
/// vector's live allocation: the range
/// `[as_mut_ptr(), as_mut_ptr() + capacity * size_of::<T>())`. That range is
/// exactly what the `Vec` owns and releases, so cleansing it is complete for the
/// buffer — and, unlike cleansing `[..len()]`, it also covers spare capacity
/// that was populated before a shrink. Bytes left in a block that an earlier
/// reallocation already released are outside any destructor's reach; the
/// invariant is scoped to the allocation the buffer still owns.
///
/// The writes are stores, never loads, so a spare slot that is not currently
/// initialised is initialised by the cleanse rather than read as if it were.
fn cleanse_allocation<T: SecretElement>(v: &mut Vec<T>) {
    // A `Vec`'s capacity can never make this product overflow (`capacity * size`
    // is bounded by `isize::MAX`), but the checked form keeps the arithmetic
    // obligation explicit instead of relying on that invariant.
    let Some(bytes) = v.capacity().checked_mul(core::mem::size_of::<T>()) else {
        return;
    };
    if bytes == 0 {
        return;
    }
    // SAFETY: `v.capacity()` slots are allocated from `v.as_mut_ptr()`, so
    // `bytes` writable bytes lie inside the allocation `v` owns. `T:
    // SecretElement` guarantees no destructor and no all-zero-pattern validity
    // hazard, so overwriting the slot bytes with zero leaves the `Vec`
    // well-formed and its later release valid. `cleanse` only stores.
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

    /// A staged buffer and its allocation address, with the drop probe armed.
    fn armed_staged() -> (SecretBuf<u64>, *const u64) {
        let mut buf = match SecretBuf::<u64>::try_zeroed(PATTERN.len()) {
            Some(buf) => buf,
            None => unreachable!("a four-limb allocation succeeds"),
        };
        buf.copy_from_slice(&PATTERN);
        let ptr = buf.as_ptr();
        drop_probe::arm(ptr);
        (buf, ptr)
    }

    /// The armed allocation must have been observed by `Drop` and released with
    /// no non-zero byte left — over the whole allocation, spare capacity
    /// included. Removing the `Drop` body therefore fails the test twice over:
    /// no observation is recorded at all.
    fn assert_released_cleansed(ptr: *const u64) {
        let obs = match drop_probe::take() {
            Some(obs) => obs,
            None => unreachable!("Drop did not observe the armed allocation"),
        };
        assert_eq!(
            obs.ptr, ptr as usize,
            "Drop observed a different allocation"
        );
        assert_eq!(
            obs.nonzero_bytes, 0,
            "automatic destruction released uncleansed storage"
        );
    }

    /// Normal return: the parameter is dropped at the end of the function.
    fn drop_on_normal_return(_buf: SecretBuf<u64>) {}

    /// Early `?` return: the parameter is dropped on the way out.
    fn drop_on_early_return(_buf: SecretBuf<u64>) -> Option<()> {
        let _later = SecretBuf::<u64>::try_zeroed(usize::MAX / 2)?;
        Some(())
    }

    /// Unwind: the parameter is dropped while the panic propagates. The panic
    /// is the point of the test, so the lint that forbids panics in production
    /// code is explicitly waived for this helper.
    #[allow(clippy::panic)]
    fn drop_on_unwind(_buf: SecretBuf<u64>) {
        panic!("unwind after staging the secret");
    }

    /// Spare capacity can retain earlier secret material: stage eight patterned
    /// limbs, cut the logical length back to four, and adopt the vector. Only a
    /// cleanse of the whole allocation reaches the four spare slots.
    #[test]
    fn automatic_drop_cleanses_spare_capacity() {
        // Grow from empty so the backing vector really is over-allocated, then
        // shrink only the logical length.
        let mut backing = Vec::new();
        backing.extend_from_slice(&PATTERN);
        backing.extend_from_slice(&PATTERN);
        let capacity = backing.capacity();
        // Initialise every capacity slot, so the probe's whole-allocation read
        // is of initialised bytes even if the allocator rounded the growth up.
        backing.resize(capacity, PATTERN[0]);
        backing.truncate(PATTERN.len());
        assert!(
            capacity > backing.len(),
            "the test requires spare capacity: {capacity} slots for {} limbs",
            backing.len()
        );
        let ptr = backing.as_ptr();
        let buf = SecretBuf::from_vec(backing);
        drop_probe::arm(ptr);
        drop(buf);
        assert_released_cleansed(ptr);
    }

    #[test]
    fn automatic_drop_cleanses_on_normal_return() {
        let (buf, ptr) = armed_staged();
        drop_on_normal_return(buf);
        assert_released_cleansed(ptr);
    }

    #[test]
    fn automatic_drop_cleanses_on_early_return() {
        let (buf, ptr) = armed_staged();
        assert_eq!(
            drop_on_early_return(buf),
            None,
            "the impossible later allocation must fail"
        );
        assert_released_cleansed(ptr);
    }

    #[test]
    fn automatic_drop_cleanses_on_unwind() {
        let (buf, ptr) = armed_staged();
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop_on_unwind(buf)));
        assert!(outcome.is_err(), "the helper must unwind");
        assert_released_cleansed(ptr);
    }
}
