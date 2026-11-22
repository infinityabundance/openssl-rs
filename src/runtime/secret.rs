//! The crate's single policy for **Rust-owned** secret-bearing storage.
//!
//! Secret material may live in exactly one of two Rust storage forms, plus a
//! non-owning borrowed view:
//!
//! | form | storage | width | release |
//! |------|---------|-------|---------|
//! | [`SecretArray<N>`] | stack, fixed at compile time | `N` | volatile wipe of all `N` bytes in `Drop` |
//! | [`SecretBuf<T>`] | heap (`Vec<T>`) | public initialised prefix, `len()` (see [`SecretLimbs`]) | volatile wipe of the **whole allocation**, capacity included, in `Drop` |
//! | [`SecretRef<'a, T>`] | borrow only | caller's slice | none — it owns nothing |
//!
//! ## Guarantees shared by both owners
//!
//! * Cleansing is a property of the type, not a step a function must remember.
//!   `Drop` runs on the normal return, on an early `?` return and during an
//!   unwind, so every exit path wipes.
//! * No `Copy`, no `Clone`, no `into_inner`, no `Default`-from-secret bytes:
//!   there is no safe way to move the uncleansed allocation out. `Deref` /
//!   `DerefMut` / the slice and pointer accessors are **borrows**, which remain
//!   the caller's own secret-handling obligation.
//! * The wipe is the crate's volatile-store primitive
//!   ([`crate::runtime::mem::cleanse`]); the compiler may not elide it.
//! * `SecretBuf` records the allocation extent, not `len()`: an adopted vector
//!   may carry spare capacity holding earlier secret elements, and `Drop`
//!   wipes that too. Neither type exposes a value after release.
//!
//! ## Scope — what this policy does **not** cover
//!
//! These are deliberately not instances of the two Rust storage forms:
//!
//! * **Allocator-seam owners** ([`crate::runtime::owned_buf::OwnedBuf`],
//!   `crate::ec::ecdh_ossl::OwnedSecretBuf`, `crate::ec::kmeth::OwnedSecret`,
//!   `crate::provider::ec_kem::OwnedSecret`, `crate::runtime::buffer::OwnedData`).
//!   They must reproduce `CRYPTO_*` allocation and cleanup events at the
//!   authority's exact size/`file`/`line`, and some are owned by C or a
//!   provider. Replacing them with a Rust `Vec` would change that seam, so they
//!   keep their own documented release contracts.
//! * **Raw FFI-touched or C-owned buffers** in boundary code, and the secure
//!   heap ([`crate::runtime::secure`]), which has its own cleanse-before-release
//!   semantics.
//! * **Ad-hoc `cleanse` calls** on storage that is not a Rust owner above
//!   (short-lived landing buffers, C struct fields, mmap arenas). They are
//!   observed as a separate mechanism in the T10 inventory, not silently
//!   absorbed into this module.
//!
//! Do not wrap an unsafe guarantee in a safe-looking name here: both owners
//! own their storage outright. [`SecretRef`] explicitly guarantees nothing
//! about the memory it borrows — it is a classification marker, not an owner.

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
        crate::runtime::alloc::try_zeroed(n, T::ZERO).map(Self::from_vec)
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
        // Only the initialised slice is readable before the wipe: spare capacity
        // may still be uninitialised, and reading it would be undefined.
        self.nonzero_bytes_initialised()
    }

    /// Read the storage after `Drop`'s cleanse and record whether any byte
    /// survived. Runs only when the allocation was armed by a test on this
    /// thread, so unrelated `SecretBuf` drops are ignored.
    fn observe_release_for_test(&self, nonzero_before: usize) {
        let addr = self.inner.as_ptr() as usize;
        if !drop_probe::is_armed(addr) {
            return;
        }
        drop_probe::record(addr, nonzero_before, self.nonzero_bytes_after_cleanse());
    }

    /// Count the non-zero bytes across the initialised slice, `[..len()]`.
    ///
    /// This is the read used **before** the wipe. Every byte of the slice is
    /// initialised by construction, whereas spare capacity may not be; the
    /// whole-capacity read is reserved for after the wipe has written zeros.
    fn nonzero_bytes_initialised(&self) -> usize {
        let Some(bytes) = self.inner.len().checked_mul(core::mem::size_of::<T>()) else {
            return 0;
        };
        let base = self.inner.as_ptr().cast::<u8>();
        let mut nonzero = 0usize;
        for i in 0..bytes {
            // SAFETY: `i < len * size_of`, which covers only the initialised
            // slice of the live allocation.
            if unsafe { base.add(i).read_volatile() } != 0 {
                nonzero += 1;
            }
        }
        nonzero
    }

    /// Count the non-zero bytes across the whole allocation the vector owns.
    ///
    /// Only called after `cleanse_now` has written zeros to every capacity slot,
    /// so the full-capacity read is of initialised bytes even when spare capacity
    /// was never written by the caller.
    fn nonzero_bytes_after_cleanse(&self) -> usize {
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

/// Heap storage whose elements are BN limbs (`u64`).
///
/// A naming alias, not a second abstraction: the width is the public
/// initialised prefix, and the allocation is cleansed as described on
/// [`SecretBuf`].
pub(crate) type SecretLimbs = SecretBuf<u64>;

/// A borrowed, read-only view of secret data.
///
/// This type owns nothing and cleanses nothing; it only marks that the bytes it
/// borrows are secret, so a function signature can say so without borrowing the
/// owner itself. It cannot extend the borrow beyond `'a`, and it offers no
/// accessor that could release or remove the storage.
pub(crate) struct SecretRef<'a, T> {
    inner: &'a [T],
}

impl<'a, T> SecretRef<'a, T> {
    pub(crate) fn new(inner: &'a [T]) -> Self {
        Self { inner }
    }
}

impl<T> Deref for SecretRef<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.inner
    }
}

/// A fixed-size stack scratch buffer that wipes itself when it goes out of scope.
///
/// Use this for bounded temporaries (digest pads, TLS premaster secrets, HPKE key
/// schedule scratch). Use [`SecretBuf`] when the width is a run-time value.
///
/// [`crate::runtime::mem::cleanse`] writes through volatile pointers and a compiler
/// fence, so the wipe survives optimisation. The type exists for functions with many
/// early returns: the secret is wiped on every one of them, not only the success
/// path. It deliberately exposes no accessor that could observe the contents after
/// `Drop`.
pub(crate) struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    /// A zero-initialised scratch buffer.
    pub(crate) fn new() -> Self {
        Self([0u8; N])
    }

    /// The buffer's read pointer.
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// The buffer's write pointer.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// The buffer as a slice; callers pass the initialised prefix.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The buffer as a mutable slice.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Fill the whole buffer with `byte` — the SSLv3 `pad_1`/`pad_2` arms fill their pad
    /// temporary with a constant before hashing it.
    pub(crate) fn fill(&mut self, byte: u8) {
        self.0.fill(byte);
    }
}

impl<const N: usize> Deref for SecretArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> DerefMut for SecretArray<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Default for SecretArray<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        #[cfg(test)]
        let nonzero_before = self.0.iter().filter(|&&b| b != 0).count();
        // SAFETY: the array is live for `N` writable bytes for the duration of `Drop`.
        unsafe { crate::runtime::mem::cleanse(self.0.as_mut_ptr(), N) }
        // A test-only observation of the wipe for callers whose secret temporaries must be
        // cleansed on their early-failure returns (for example `ossl_sha1_ctrl`). It reads
        // this owner's still-live storage inside `Drop`, never freed stack, and release
        // builds carry none of it.
        #[cfg(test)]
        cleanse_hooks::record(N, nonzero_before, self.0.iter().all(|&b| b == 0));
    }
}

/// Test-only observation of [`SecretArray`]'s wipe.
///
/// A caller cannot inspect a scratch buffer after it has gone out of scope without reading
/// freed stack. This records what the wipe did from inside `Drop`, while the storage is still
/// live: how many bytes it covered, how many were non-zero beforehand, and that every byte read
/// zero afterwards. It is thread-local, so tests using it need no global lock.
#[cfg(test)]
pub(crate) mod cleanse_hooks {
    use core::cell::RefCell;

    /// One `SecretArray::drop`, described without exposing the bytes themselves.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Event {
        /// `N` — the length the wipe covered.
        pub len: usize,
        /// Bytes that were non-zero immediately before the wipe.
        pub nonzero_before: usize,
        /// Whether every byte read zero immediately after the wipe.
        pub zero_after: bool,
    }

    thread_local! {
        static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    /// Forget every wipe recorded on this thread.
    pub(crate) fn reset() {
        EVENTS.with(|events| events.borrow_mut().clear());
    }

    /// Every wipe recorded on this thread since the last [`reset`].
    pub(crate) fn events() -> Vec<Event> {
        EVENTS.with(|events| events.borrow().clone())
    }

    pub(super) fn record(len: usize, nonzero_before: usize, zero_after: bool) {
        EVENTS.with(|events| {
            events.borrow_mut().push(Event {
                len,
                nonzero_before,
                zero_after,
            });
        });
    }
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

    // ------------------------------------------------------------------
    // ETP-4: whole-allocation cleansing over an enumerated domain.
    //
    // The tests above establish the exit paths for a buffer whose logical
    // length equals the staged pattern. The harness below enumerates the
    // capacity/initialised boundary instead: every byte of the allocation,
    // spare capacity included, is initialised to a non-zero pattern before
    // release, so a wipe that stops at `len()` leaves observable non-zero
    // bytes behind. Each case is an independent allocation observed from
    // inside `Drop` by the drop probe, which is the last point at which the
    // block is live.
    // ------------------------------------------------------------------

    /// Lengths spanning empty, sub-word, word-boundary and multi-word shapes.
    const ETP4_LENGTHS: [usize; 12] = [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 64, 65];

    /// Spare-capacity margins applied to every length.
    const ETP4_SPARE: [usize; 3] = [1, 3, 8];

    /// A vector whose capacity equals its length, every element non-zero.
    fn etp4_exact_backing(len: usize) -> Vec<u64> {
        let mut v: Vec<u64> = (0..len).map(|i| PATTERN[i % PATTERN.len()]).collect();
        v.shrink_to_fit();
        assert_eq!(
            v.capacity(),
            v.len(),
            "exact-fit construction must leave no spare capacity"
        );
        v
    }

    /// A vector with at least `extra` spare slots, with **all** capacity slots
    /// initialised to a non-zero element before the logical length is cut back.
    fn etp4_spare_backing(len: usize, extra: usize) -> Vec<u64> {
        let mut v: Vec<u64> = Vec::with_capacity(len + extra);
        v.extend((0..len).map(|i| PATTERN[i % PATTERN.len()]));
        let capacity = v.capacity();
        assert!(capacity >= len + extra, "reserve must satisfy the request");
        // Initialise every capacity slot, then restore the logical length. The
        // spare bytes remain initialised, so reading them is defined and the
        // pre-wipe state genuinely holds secret-shaped data.
        v.resize(capacity, PATTERN[0]);
        v.truncate(len);
        assert!(capacity > len, "the case must carry spare capacity");
        v
    }

    /// Count non-zero bytes in the spare capacity `[len..capacity]`.
    ///
    /// Every capacity slot was initialised by the constructor above, so the
    /// volatile byte read covers initialised storage.
    fn etp4_spare_nonzero(v: &[u64], len: usize, capacity: usize) -> usize {
        assert!(capacity >= v.len(), "capacity covers the logical length");
        let start = len * core::mem::size_of::<u64>();
        let end = capacity * core::mem::size_of::<u64>();
        let base = v.as_ptr().cast::<u8>();
        let mut nonzero = 0usize;
        for i in start..end {
            // SAFETY: `i` lies in `[len, capacity)` bytes of the live allocation
            // and every byte there was initialised by `resize`.
            if unsafe { base.add(i).read_volatile() } != 0 {
                nonzero += 1;
            }
        }
        nonzero
    }

    /// Arm the probe, release the buffer, and require that `Drop` observed the
    /// whole allocation as zero, with the expected non-zero state beforehand.
    fn etp4_assert_cleansed(buf: SecretBuf<u64>, ptr: *const u64, nonzero_before: usize) {
        drop_probe::arm(ptr);
        drop(buf);
        let Some(obs) = drop_probe::take() else {
            unreachable!("Drop did not observe the armed allocation")
        };
        assert_eq!(
            obs.ptr, ptr as usize,
            "Drop observed a different allocation"
        );
        assert_eq!(
            obs.nonzero_before, nonzero_before,
            "the secret-shaped pre-state was not staged as expected"
        );
        assert_eq!(
            obs.nonzero_bytes, 0,
            "automatic destruction left non-zero bytes in the allocation"
        );
    }

    /// Exhaust the declared domain: every length in [`ETP4_LENGTHS`] at the
    /// exact-fit boundary and with each spare margin in [`ETP4_SPARE`]. The
    /// zero-length cases include both the empty allocation (capacity zero) and
    /// an allocation whose whole capacity is spare.
    #[test]
    fn etp4_whole_allocation_cleanse_domain() {
        let mut exact_cases = 0usize;
        let mut spare_cases = 0usize;
        let mut observed_bytes = 0usize;
        for &len in &ETP4_LENGTHS {
            let v = etp4_exact_backing(len);
            let ptr = v.as_ptr();
            let before = len * core::mem::size_of::<u64>();
            etp4_assert_cleansed(SecretBuf::from_vec(v), ptr, before);
            exact_cases += 1;
            observed_bytes += len * core::mem::size_of::<u64>();
        }
        for &len in &ETP4_LENGTHS {
            for &extra in &ETP4_SPARE {
                let v = etp4_spare_backing(len, extra);
                let capacity = v.capacity();
                let spare_nonzero = etp4_spare_nonzero(&v, len, capacity);
                assert!(
                    spare_nonzero > 0,
                    "len={len} capacity={capacity}: spare capacity was not staged"
                );
                let ptr = v.as_ptr();
                let before = len * core::mem::size_of::<u64>();
                etp4_assert_cleansed(SecretBuf::from_vec(v), ptr, before);
                spare_cases += 1;
                observed_bytes += capacity * core::mem::size_of::<u64>();
            }
        }
        let cases = exact_cases + spare_cases;
        std::eprintln!(
            "ETP4 cleanse: cases={cases} exact={exact_cases} spare={spare_cases} observed_bytes={observed_bytes}"
        );
        assert_eq!(cases, ETP4_LENGTHS.len() * (1 + ETP4_SPARE.len()));
    }

    /// A buffer with a staged non-zero prefix **and** staged spare capacity.
    fn etp4_armed_with_spare(len: usize, extra: usize) -> (SecretBuf<u64>, *const u64, usize) {
        let v = etp4_spare_backing(len, extra);
        let capacity = v.capacity();
        assert!(etp4_spare_nonzero(&v, len, capacity) > 0);
        let ptr = v.as_ptr();
        let before = len * core::mem::size_of::<u64>();
        drop_probe::arm(ptr);
        (SecretBuf::from_vec(v), ptr, before)
    }

    /// Spare capacity is covered on every exit path the module exposes.
    #[test]
    fn etp4_spare_capacity_cleansed_on_every_exit_path() {
        let mut cases = 0usize;
        for &len in &ETP4_LENGTHS {
            let (buf, ptr, before) = etp4_armed_with_spare(len, 8);
            drop_on_normal_return(buf);
            let Some(obs) = drop_probe::take() else {
                unreachable!("normal return skipped Drop")
            };
            assert_eq!(obs.ptr, ptr as usize);
            assert_eq!(obs.nonzero_before, before);
            assert_eq!(obs.nonzero_bytes, 0, "normal return left spare bytes");
            cases += 1;

            let (buf, ptr, before) = etp4_armed_with_spare(len, 8);
            assert_eq!(drop_on_early_return(buf), None);
            let Some(obs) = drop_probe::take() else {
                unreachable!("early return skipped Drop")
            };
            assert_eq!(obs.ptr, ptr as usize);
            assert_eq!(obs.nonzero_before, before);
            assert_eq!(obs.nonzero_bytes, 0, "early return left spare bytes");
            cases += 1;

            let (buf, ptr, before) = etp4_armed_with_spare(len, 8);
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop_on_unwind(buf)));
            assert!(outcome.is_err(), "the helper must unwind");
            let Some(obs) = drop_probe::take() else {
                unreachable!("unwind skipped Drop")
            };
            assert_eq!(obs.ptr, ptr as usize);
            assert_eq!(obs.nonzero_before, before);
            assert_eq!(obs.nonzero_bytes, 0, "unwind left spare bytes");
            cases += 1;
        }
        std::eprintln!("ETP4 cleanse exit paths: cases={cases}");
        assert_eq!(cases, ETP4_LENGTHS.len() * 3);
    }

    /// Capacity growth is established deterministically: the allocation gains
    /// spare slots beyond the initialised length, and those slots can be staged
    /// with non-zero bytes before destruction.
    ///
    /// The buffer's address is deliberately **not** asserted to change.
    /// `Vec::reserve` is permitted to grow the allocation in place, so a
    /// pointer-inequality requirement would encode one allocator's placement
    /// decision rather than the property under test. The relocation witness is
    /// `etp4_reallocated_buffer_cleanses_whole_allocation`, which obtains a
    /// distinct allocation by construction instead.
    #[test]
    fn etp4_capacity_growth_initialises_spare_capacity() {
        let mut v: Vec<u64> = Vec::new();
        v.extend_from_slice(&PATTERN);
        let initial_capacity = v.capacity();
        // `reserve` guarantees `capacity >= len + additional`, so requesting
        // `initial_capacity + 64` forces growth whatever the allocator reserved
        // initially. Growth therefore follows from the documented postcondition,
        // not from an assumption about allocation geometry.
        v.reserve(initial_capacity + 64);
        let capacity = v.capacity();
        assert!(
            capacity > initial_capacity,
            "growth must increase capacity: {initial_capacity} -> {capacity}"
        );
        assert!(capacity > v.len(), "growth must leave spare capacity");
        v.resize(capacity, PATTERN[1]);
        v.truncate(PATTERN.len());
        let staged = etp4_spare_nonzero(&v, PATTERN.len(), capacity);
        assert!(
            staged > 0,
            "the grown allocation's spare capacity was not initialised non-zero"
        );
        std::eprintln!(
            "ETP4 capacity growth: initial={initial_capacity} capacity={capacity} staged={staged}"
        );
    }

    /// A buffer whose payload was moved into a fresh, larger allocation has its
    /// whole final allocation cleansed, including spare capacity.
    ///
    /// The relocation is obtained **deterministically**: a distinct, larger
    /// allocation is constructed and the payload is moved into it, rather than
    /// assuming that `Vec::reserve` relocates. That assumption is not a `Vec`
    /// guarantee — growth may happen in place — so it was removed together with
    /// an `assert_ne!` on `as_ptr()` that had encoded allocator placement instead
    /// of the cleansing property. Do not reintroduce a pointer-inequality
    /// requirement here.
    #[test]
    fn etp4_reallocated_buffer_cleanses_whole_allocation() {
        let source: Vec<u64> = PATTERN.to_vec();
        // The destination is a second allocation while `source` is still live, so
        // it is a distinct block regardless of how the allocator places it.
        let mut v: Vec<u64> = Vec::with_capacity(source.len() + 64);
        v.extend_from_slice(&source);
        let capacity = v.capacity();
        assert!(
            capacity > v.len(),
            "the grown buffer must carry spare capacity"
        );
        v.resize(capacity, PATTERN[1]);
        v.truncate(source.len());
        assert!(
            etp4_spare_nonzero(&v, source.len(), capacity) > 0,
            "spare capacity was not staged before adoption"
        );
        let ptr = v.as_ptr();
        let before = source.len() * core::mem::size_of::<u64>();
        etp4_assert_cleansed(SecretBuf::from_vec(v), ptr, before);
        std::eprintln!("ETP4 cleanse relocated: cases=1 capacity={capacity}");
    }
}
