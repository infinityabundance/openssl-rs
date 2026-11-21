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

pub(crate) use crate::bn::secret::SecretBuf;

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
