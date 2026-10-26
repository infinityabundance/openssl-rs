//! The BIO stratum's owned-handle seam.
//!
//! Every BIO method's private-data context (`b->ptr`), the core BIO handle and the core BIO
//! globals block are `#[repr(C)]` blocks this crate allocates for itself. Historically each was
//! hand-managed: a `create`/constructor ran a `CRYPTO_zalloc`/`CRYPTO_malloc` and every `destroy`
//! or `*_free` walked the block by hand and called `CRYPTO_free` at its own call site.
//!
//! This module is the one seam that turns that ownership into a type. [`OwnedCtx`] allocates a
//! block through the crate's allocator seam at `size_of::<T>()` and its `Drop` is the block's
//! single release, so a caller-installed `CRYPTO_set_mem_functions` hook observes the allocation,
//! its size and its release exactly as it observes the authority's -- a Rust `Box` would hide all
//! three. [`CtxDestroy::destroy_body`] is the authority's `*_free` body *minus* the block release,
//! so the member releases the authority performs there (a duplicate string, a member buffer) stay
//! the authority's own calls, relocated to the context's `Drop`.
//!
//! Ownership is expressed *above* the seam: a constructor hands the block out with
//! [`OwnedCtx::into_raw`] (the C caller's context pointer), and a `destroy`/`*_free` reclaims it
//! with [`OwnedCtx::from_raw`] so `Drop` runs the authority's own free body before the block
//! release. The `#[repr(C)]` layouts, the stable addresses the C ABI hands out, the exported
//! symbols and their return/error semantics are unchanged.
//!
//! ## Two states, so a destructor cannot run too early
//!
//! [`OwnedCtx`]'s `Drop` runs `destroy_body`, which reads members the block must already hold. A
//! safe constructor that hands out *uninitialised* storage as an [`OwnedCtx`] would let a safe
//! caller drop it and make `destroy_body` read uninitialised bytes -- UB through a safe interface.
//! So allocation and validity are split: [`RawCtx`] owns storage that is **not yet** a valid `T`
//! and its `Drop` releases the block alone, and [`RawCtx::assume_init`] is the one validated
//! transition to [`OwnedCtx`], whose `Drop` may run `destroy_body`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc, SEAM_MALLOC_ALIGN};
use crate::runtime::mem_coords::SeamFile;

/// Test-only observation of which owner's `Drop` ran, for the OB-3 model
/// correspondence tests. Thread-local so concurrent tests cannot see each other's
/// drops. It is compiled out of every non-test build.
#[cfg(test)]
mod drop_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Call {
        Raw,
        Owned,
    }

    thread_local! {
        pub(super) static LAST: Cell<Option<Call>> = const { Cell::new(None) };
    }
}

/// The authority's `*_free` body for one `#[repr(C)]` context, without the block release
/// [`OwnedCtx`]'s `Drop` performs. One impl per context type, so the owner runs the right
/// destructor from `Drop` without a `CRYPTO_free` written at any call site.
///
/// `FILE`/`LINE_ALLOC`/`LINE_FREE` are the authority's own allocation-tracking coordinates, kept
/// distinct so a caller-installed `CRYPTO_set_mem_functions` hook observes the release at the same
/// site the authority releases it (the `bf_*` filters allocate and free at `NULL`/`0`, while
/// `ossl_core_bio.c` records its own `__FILE__` and the two lines it names).
///
/// # Safety
///
/// An implementer takes on both halves of this contract, because the owner ([`OwnedCtx`]) runs the
/// implementer's body through a safe interface:
///
/// (a) **destructor** — [`destroy_body`](CtxDestroy::destroy_body) runs the authority's `*_free`
///     member body **exactly once**, releasing exactly the members the object owns (every releaser
///     it calls must accept the not-yet-set NULL/zero state of a partially built object), and it
///     **never** releases the enclosing block, which [`OwnedCtx`]'s `Drop` releases alone; and
/// (b) **zero-validity** — an all-zero block of `Self` is a valid `Self`, and `destroy_body` and
///     every operation the owner performs on it are sound for that value. This is the obligation
///     the safe [`OwnedCtx::zalloc`] leans on: it validates an authority `CRYPTO_zalloc` block with
///     no caller assertion, so `Self` must be a type whose zeroed state the authority's own
///     constructor leaves; and
/// (c) **coordinate lifetime** — [`FILE`](CtxDestroy::FILE) is NULL or points at a NUL-terminated
///     C string with static storage that remains valid for the entire program, because a
///     caller-installed `CRYPTO_set_mem_functions` hook may read it during any release.
///     [`SeamFile::from_static_ptr`] relies on this and cannot establish it; and
/// (d) **no alignment obligation** — an implementor whose `align_of::<Self>()` exceeds
///     [`SEAM_MALLOC_ALIGN`] is *refused* by the safe constructors (they answer `None`, the
///     allocation-refusal arm), so no implementor can be handed a misaligned `NonNull<Self>`
///     through safe code. This is a fact about the constructors, not a new obligation: an
///     over-aligned `Self` simply cannot be built by [`OwnedCtx`]/[`RawCtx`].
///
/// Breaking (a) lets safe Rust double-release or release the enclosing block; breaking (b) runs
/// `destroy_body` on a value that is not a valid `Self`; breaking (c) lets an allocator hook read a
/// dangling file string during release. Each is undefined behaviour reachable without `unsafe` at
/// the call site.
pub(crate) unsafe trait CtxDestroy: Sized {
    /// `__FILE__` for this context's `CRYPTO_*` calls, or NULL where the authority passes none.
    ///
    /// An implementer must ensure this is NULL or a NUL-terminated string with static storage
    /// that remains valid for the lifetime of every owner made from it. The owner converts it
    /// once through [`SeamFile::from_static_ptr`], so the obligation stays at the unsafe trait
    /// boundary rather than on a safe caller.
    const FILE: *const c_char = ptr::null();
    /// `__LINE__` for the context's allocation.
    const LINE_ALLOC: c_int = 0;
    /// `__LINE__` for the context's block release.
    const LINE_FREE: c_int = 0;

    /// The authority's `*_free` body, without the block release [`OwnedCtx`]'s `Drop` performs.
    ///
    /// # Safety
    /// `ptr` is a live context this crate allocated and has not released.
    unsafe fn destroy_body(ptr: *mut Self);
}

/// An owned `#[repr(C)]` context block.
///
/// The block keeps the authority's layout and its stable address (the C ABI hands it out and takes
/// it back), but its *ownership* is this type: it is allocated on the crate's allocator seam and
/// `Drop` is its single release.
pub(crate) struct OwnedCtx<T: CtxDestroy> {
    ptr: NonNull<T>,
    /// The authority's `__FILE__` for this block's release.
    file: SeamFile,
    /// The authority's `__LINE__` for this block's release.
    line: c_int,
}

impl<T: CtxDestroy> OwnedCtx<T> {
    /// Allocate a fresh, zeroed block of `T`'s size through the installed allocator, or `None`
    /// when it answers NULL -- the authority's refused `CRYPTO_zalloc`.
    ///
    /// A zeroed block is the authority's own constructed state for every context this constructor
    /// is used for (each is one the authority builds with `OPENSSL_zalloc`), so `destroy_body` is
    /// written against it and the block may be validated immediately.
    pub(crate) fn zalloc() -> Option<OwnedCtx<T>> {
        // SAFETY: `T: CtxDestroy` carries implementer obligation (b) — an all-zero block is a valid
        // `T` for which `destroy_body` is sound — so the zeroed storage is a valid `T`.
        Some(unsafe { RawCtx::<T>::zalloc()?.assume_init() })
    }

    /// Allocate a fresh, zeroed block at the caller's allocation coordinates, for release at a
    /// distinct site (`alloc_file`/`alloc_line` and `release_file`/`release_line` are the
    /// authority's own `CRYPTO_zalloc` and `CRYPTO_free` sites).
    pub(crate) fn zalloc_at(
        alloc_file: SeamFile,
        alloc_line: c_int,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<OwnedCtx<T>> {
        // SAFETY: as `zalloc` -- the allocator zeroes the block, and implementer obligation (b)
        // makes that a valid `T`.
        Some(unsafe {
            RawCtx::<T>::zalloc_at(alloc_file, alloc_line, release_file, release_line)?
                .assume_init()
        })
    }

    /// The stable address the C ABI hands out and takes back.
    pub(crate) fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the C caller's context pointer.
    pub(crate) fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim a block a previous `into_raw` handed to the C caller, for release by `Drop`.
    ///
    /// # Safety
    /// `ptr` is NULL or a live block a previous `into_raw` gave up and `Drop` has not released.
    pub(crate) unsafe fn from_raw(ptr: *mut T) -> Option<OwnedCtx<T>> {
        // SAFETY: the caller establishes this function's contract; `T: CtxDestroy`
        // establishes that `T::FILE` is NULL or static, NUL-terminated storage.
        unsafe { Self::from_raw_at(ptr, SeamFile::from_static_ptr(T::FILE), T::LINE_FREE) }
    }

    /// Reclaim a block handed to the C caller, releasing it at the given authority site.
    ///
    /// # Safety
    /// `ptr` is NULL or a live block a previous `into_raw` gave up and `Drop` has not released,
    /// and it is aligned for `T`. A non-NULL misaligned pointer answering `None` is the
    /// allocation-refusal arm: the block is not adopted (and therefore not released here), so a
    /// caller that violates the alignment precondition loses the block instead of obtaining UB.
    pub(crate) unsafe fn from_raw_at(
        ptr: *mut T,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<OwnedCtx<T>> {
        NonNull::new(ptr)
            .filter(|ptr| {
                ptr.as_ptr()
                    .addr()
                    .is_multiple_of(core::mem::align_of::<T>())
            })
            .map(|ptr| OwnedCtx {
                ptr,
                file: release_file,
                line: release_line,
            })
    }

    /// Re-point the block release at another authority site (a failed push releases at a different
    /// line than the record's stored path).
    pub(crate) fn set_release_line(&mut self, line: c_int) {
        self.line = line;
    }
}

impl<T: CtxDestroy> Drop for OwnedCtx<T> {
    /// The context destructor: the authority's `*_free` body ([`CtxDestroy::destroy_body`])
    /// followed by the block's release, through the same allocator seam the block was allocated on.
    fn drop(&mut self) {
        #[cfg(test)]
        drop_probe::LAST.with(|last| last.set(Some(drop_probe::Call::Owned)));
        // SAFETY: `self.ptr` is the block this handle allocated (or `from_raw` reclaimed) and this
        // is its single release; `Drop` runs once, and `destroy_body` is the authority's own
        // `*_free` body, which releases the owned members and never the enclosing block.
        unsafe { T::destroy_body(self.ptr.as_ptr()) };
        // Recorded after the member releases and before the block's own release, so the probe
        // observes the block release in the order the authority performs the two steps.
        #[cfg(test)]
        crate::runtime::release_probe::record(
            crate::runtime::release_probe::Arm::Plain,
            self.ptr.as_ptr().cast::<c_void>(),
            self.file.as_ptr(),
            self.line,
        );
        // SAFETY: `self.ptr` is the block this handle owns and `destroy_body` has not released; the
        // stored coordinates are the authority's release site for it.
        unsafe {
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                self.file.as_ptr(),
                self.line,
            );
        }
    }
}

/// Allocated storage for a context that is **not yet** a valid `T`.
///
/// [`OwnedCtx`]'s `Drop` runs `T::destroy_body`, which reads the members the destructor needs.
/// That is only sound once the storage holds a fully initialised `T`, so a constructor that hands
/// out raw storage must not be an [`OwnedCtx`]. [`RawCtx`] is the type for that window: it owns the
/// block, never forms a reference to `T` (it holds `NonNull<MaybeUninit<T>>`), and its `Drop`
/// releases the **block alone** -- it never runs `T::destroy_body`.
///
/// The window closes with [`RawCtx::assume_init`], the one validated transition to [`OwnedCtx`].
pub(crate) struct RawCtx<T: CtxDestroy> {
    ptr: NonNull<MaybeUninit<T>>,
    /// The authority's `__FILE__` for this block's release.
    file: SeamFile,
    /// The authority's `__LINE__` for this block's release.
    line: c_int,
}

impl<T: CtxDestroy> RawCtx<T> {
    /// Allocate a fresh, **uninitialised** block of `T`'s size through the installed allocator, or
    /// `None` when it answers NULL -- the authority's `CRYPTO_malloc` for the blocks it does not
    /// zero (`ossl_core_bio.c`'s handle and `linebuffer.c`'s context).
    pub(crate) fn malloc() -> Option<RawCtx<T>> {
        // SAFETY: `T: CtxDestroy` establishes that `T::FILE` is NULL or static,
        // NUL-terminated storage.
        let file = unsafe { SeamFile::from_static_ptr(T::FILE) };
        Self::malloc_at(file, T::LINE_ALLOC, file, T::LINE_FREE)
    }

    /// Allocate a fresh, **uninitialised** block at the caller's allocation and release
    /// coordinates (`CRYPTO_malloc`'s `file`/`line` and the later `CRYPTO_free`'s).
    pub(crate) fn malloc_at(
        alloc_file: SeamFile,
        alloc_line: c_int,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<RawCtx<T>> {
        // The seam guarantees pointer alignment (see `SEAM_MALLOC_ALIGN`); a type above that
        // bound is refused before the allocator is asked, exactly as a refused allocation. The
        // check is a compile-time constant per monomorphisation, so no current implementor pays
        // for it, and no path can produce a misaligned `NonNull<T>` through this safe constructor.
        if core::mem::align_of::<T>() > SEAM_MALLOC_ALIGN {
            return None;
        }
        // `CRYPTO_malloc` is a safe function: it answers NULL or a fresh, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(core::mem::size_of::<T>(), alloc_file.as_ptr(), alloc_line)
        }
        .cast::<MaybeUninit<T>>();
        NonNull::new(raw).map(|ptr| RawCtx {
            ptr,
            file: release_file,
            line: release_line,
        })
    }

    /// Allocate a fresh, zeroed block of `T`'s size through the installed allocator, or `None` when
    /// it answers NULL -- the authority's `CRYPTO_zalloc`. The bytes are zero but the block is a
    /// `RawCtx`: zeroing is not, by itself, a valid `T` for every context, so the caller still
    /// validates it with [`RawCtx::assume_init`].
    pub(crate) fn zalloc() -> Option<RawCtx<T>> {
        // SAFETY: `T: CtxDestroy` establishes that `T::FILE` is NULL or static,
        // NUL-terminated storage.
        let file = unsafe { SeamFile::from_static_ptr(T::FILE) };
        Self::zalloc_at(file, T::LINE_ALLOC, file, T::LINE_FREE)
    }

    /// Allocate a fresh, zeroed block at the caller's allocation and release coordinates
    /// (`CRYPTO_zalloc`'s `file`/`line` and the later `CRYPTO_free`'s).
    pub(crate) fn zalloc_at(
        alloc_file: SeamFile,
        alloc_line: c_int,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<RawCtx<T>> {
        // As `malloc_at`: the seam's aligned bound is enforced here, so the zeroed block is only
        // adopted when `NonNull<T>` is actually aligned for `T`.
        if core::mem::align_of::<T>() > SEAM_MALLOC_ALIGN {
            return None;
        }
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_zalloc(core::mem::size_of::<T>(), alloc_file.as_ptr(), alloc_line)
        }
        .cast::<MaybeUninit<T>>();
        NonNull::new(raw).map(|ptr| RawCtx {
            ptr,
            file: release_file,
            line: release_line,
        })
    }

    /// The stable address the caller initialises `T`'s fields through.
    pub(crate) fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr().cast::<T>()
    }

    /// Re-point the block-only release at another authority site (a constructor failure releases at
    /// a different line than the object's stored path).
    pub(crate) fn set_release_line(&mut self, line: c_int) {
        self.line = line;
    }

    /// Give up ownership of the uninitialised block to the C caller's context pointer.
    pub(crate) fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr().cast::<T>();
        core::mem::forget(self);
        p
    }

    /// The validated transition: the storage now holds a fully initialised, valid `T`.
    ///
    /// # Safety
    /// The storage holds a valid, fully initialised `T` -- every field [`CtxDestroy::destroy_body`]
    /// reads has been written, so the block is a valid `T` and its members satisfy the destructor's
    /// invariants -- and no other owner will release it: the returned handle's `Drop` is the block's
    /// single release.
    pub(crate) unsafe fn assume_init(self) -> OwnedCtx<T> {
        let ptr = self.ptr.cast::<T>();
        let file = self.file;
        let line = self.line;
        core::mem::forget(self);
        OwnedCtx { ptr, file, line }
    }
}

impl<T: CtxDestroy> Drop for RawCtx<T> {
    /// Releases the **block alone**: `T` is not (yet) a valid value, so its destructor body must not
    /// run. Same allocator, size and `T::FILE`/`T::LINE_FREE` as [`OwnedCtx`]'s block release.
    fn drop(&mut self) {
        #[cfg(test)]
        drop_probe::LAST.with(|last| last.set(Some(drop_probe::Call::Raw)));
        #[cfg(test)]
        crate::runtime::release_probe::record(
            crate::runtime::release_probe::Arm::Plain,
            self.ptr.as_ptr().cast::<c_void>(),
            self.file.as_ptr(),
            self.line,
        );
        // SAFETY: `self.ptr` is the block this handle allocated and has not handed out; this is its
        // single release, and the authority's own bare `CRYPTO_free` is the whole release.
        unsafe {
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                self.file.as_ptr(),
                self.line,
            )
        };
    }
}

/// An owned seam block that is not one of the `#[repr(C)]` contexts -- a member buffer the
/// authority owns and releases with a plain `CRYPTO_free`.
///
/// It stays a `CRYPTO_*`-seam block released by `Drop` at the authority's own (NULL, 0) site, so a
/// caller-installed `CRYPTO_set_mem_functions` hook observes it. It is adopted with [`Self::take`]
/// from the `#[repr(C)]` member that still holds the raw pointer.
pub(crate) struct OwnedBlock {
    ptr: *mut c_void,
}

impl OwnedBlock {
    /// Adopt a block the seam answered, or `None` for NULL.
    ///
    /// # Safety
    /// `ptr` is NULL or a block the crate's allocator seam produced, is owned by the caller, and
    /// will not be freed or handed to any other owner -- this handle's `Drop` is its single
    /// release.
    pub(crate) unsafe fn take(ptr: *mut c_void) -> Option<OwnedBlock> {
        if ptr.is_null() {
            None
        } else {
            Some(OwnedBlock { ptr })
        }
    }
}

impl Drop for OwnedBlock {
    fn drop(&mut self) {
        #[cfg(test)]
        crate::runtime::release_probe::record(
            crate::runtime::release_probe::Arm::Plain,
            self.ptr,
            ptr::null(),
            0,
        );
        // SAFETY: `self.ptr` is a block this seam allocated and has not handed out; its single
        // release is the authority's own plain `CRYPTO_free`.
        unsafe { CRYPTO_free(self.ptr, ptr::null(), 0) };
    }
}

#[cfg(test)]
mod release_family_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::runtime::release_probe::{self, Arm};

    /// D1-style drift guard: this family's release is the plain `CRYPTO_free` at the
    /// seam's inert `(NULL, 0)` coordinate.
    #[test]
    fn release_is_plain_at_the_null_coordinates() {
        release_probe::clear();
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(8, ptr::null(), 0)
        };
        assert!(!raw.is_null());
        // SAFETY: `raw` is the fresh seam block this test owns.
        // SAFETY: `raw` is the fresh block this test owns and has not released.
        let block = unsafe { OwnedBlock::take(raw) }.expect("a non-NULL block is owned");
        drop(block);
        let call = release_probe::take().expect("the release was recorded");
        assert_eq!(call.arm, Arm::Plain);
        assert!(call.file.is_null());
        assert_eq!(call.line, 0);
    }
}

// -------------------------------------------------------------------------------------------
// Adversarial partial-initialisation tests (`stage/p25/adv-tests`, §2 / §16)
// -------------------------------------------------------------------------------------------
//
// `RawCtx::drop` must release the block alone and never run `T::destroy_body` on storage that is
// not yet a valid `T`. These tests observe that with a test-only `CtxDestroy` whose `destroy_body`
// records that it ran, and a negative control that proves the recording is live.
#[cfg(test)]
mod adv_partial_init_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Records that a `destroy_body` ran, so a test can assert it did NOT.
    static DESTROY_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// The three tests below observe the shared `DESTROY_CALLS` counter, so they must not run
    /// concurrently with each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// A test-only context whose destructor records its own call and releases nothing: it holds a
    /// plain integer, so an all-zero block is a valid value and the destructor is sound on it.
    #[repr(C)]
    struct ProbeCtx {
        marker: usize,
    }

    // SAFETY: (a) `destroy_body` releases exactly the members the object owns -- none, since
    // `ProbeCtx` holds only an integer -- and never the enclosing block; it only records its call.
    // (b) an all-zero `ProbeCtx` is a valid value for which `destroy_body` is sound.
    unsafe impl CtxDestroy for ProbeCtx {
        unsafe fn destroy_body(_ptr: *mut ProbeCtx) {
            DESTROY_CALLS.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn destroys() -> usize {
        DESTROY_CALLS.load(Ordering::SeqCst)
    }

    /// Dropping a `RawCtx` releases the block alone: the destructor must not run on storage that
    /// was never validated with `assume_init`.
    #[test]
    fn rawctx_drop_does_not_run_destroy_body() {
        let _guard = TEST_LOCK.lock().unwrap();
        let before = destroys();
        {
            let raw = RawCtx::<ProbeCtx>::zalloc();
            assert!(raw.is_some(), "a zeroed block must be allocatable");
            // `raw` drops here: the block is released, the destructor must not run.
        }
        assert_eq!(
            destroys(),
            before,
            "RawCtx::drop must not run the context destructor on uninitialised storage"
        );
    }

    /// Dropping a validated `OwnedCtx` does run the destructor exactly once.
    #[test]
    fn owned_ctx_drop_runs_destroy_body_once() {
        let _guard = TEST_LOCK.lock().unwrap();
        let before = destroys();
        {
            let owned = OwnedCtx::<ProbeCtx>::zalloc();
            assert!(owned.is_some());
        }
        assert_eq!(destroys(), before + 1);
    }

    /// Negative control (§16): prove the `DESTROY_CALLS` instrument is live. A handle reclaimed
    /// from the raw block WITHOUT `assume_init` (test-only) drops as an `OwnedCtx`, so `Drop` does
    /// invoke the destructor on storage that was never validated -- the exact defect the first test
    /// guards against. If the instrument could not observe this, the first test's assertion would
    /// be vacuous.
    #[test]
    fn canary_destroy_instrument_is_live() {
        let _guard = TEST_LOCK.lock().unwrap();
        let before = destroys();
        let raw = RawCtx::<ProbeCtx>::zalloc();
        assert!(raw.is_some());
        let p = match raw {
            Some(r) => r.into_raw(),
            None => ptr::null_mut(),
        };
        assert!(!p.is_null());
        // SAFETY: `p` is the live block `raw` gave up. The canary deliberately reclaims it as an
        // `OwnedCtx` without `assume_init`, so `Drop` runs the destructor on unvalidated storage;
        // `ProbeCtx::destroy_body` is sound on any bit pattern, so this cannot cause UB.
        let canary = unsafe { OwnedCtx::<ProbeCtx>::from_raw(p) };
        drop(canary);
        assert_eq!(
            destroys(),
            before + 1,
            "the instrument must observe a destroy_body call (negative control)"
        );
    }

    /// A test-only context whose alignment the allocator seam cannot guarantee. It is a valid
    /// `CtxDestroy` implementor (its destructor reads nothing), so it is exactly the shape the
    /// old constructors would have handed a misaligned `NonNull<T>` through safe code.
    #[repr(C, align(64))]
    struct OverAlignedCtx {
        marker: usize,
    }

    // SAFETY: (a) `destroy_body` releases nothing and never the enclosing block; (b) an all-zero
    // `OverAlignedCtx` is a valid value; (c) `FILE` is the default NULL coordinate; (d) the
    // over-alignment is refused by the constructors, so it never reaches an owner.
    unsafe impl CtxDestroy for OverAlignedCtx {
        unsafe fn destroy_body(_ptr: *mut OverAlignedCtx) {}
    }

    /// The alignment defect ADV-R3: a conforming implementor with a 64-byte alignment used to be
    /// handed a `CRYPTO_malloc` block (pointer-aligned only) as a `NonNull<Self>`. Every safe
    /// constructor now answers the allocation-refusal arm instead, so the type is never adopted.
    #[test]
    fn over_aligned_ctx_is_refused_not_adopted() {
        assert!(
            core::mem::align_of::<OverAlignedCtx>() > SEAM_MALLOC_ALIGN,
            "the test type must exceed the seam's guarantee for the assertion to mean anything"
        );
        assert!(RawCtx::<OverAlignedCtx>::malloc().is_none());
        assert!(RawCtx::<OverAlignedCtx>::zalloc().is_none());
        assert!(OwnedCtx::<OverAlignedCtx>::zalloc().is_none());
        assert!(OwnedCtx::<OverAlignedCtx>::zalloc_at(
            SeamFile::new(c"test/over-aligned"),
            1,
            SeamFile::new(c"test/over-aligned"),
            2,
        )
        .is_none());
    }

    /// Negative control for the bound itself: a type the seam *can* align is still adopted, and
    /// the address it returns is aligned for it. A constructor that refused everything would make
    /// the previous test vacuous.
    #[test]
    fn seam_aligned_ctx_is_adopted_and_aligned() {
        let _guard = TEST_LOCK.lock().unwrap();
        let owned = OwnedCtx::<ProbeCtx>::zalloc().expect("a pointer-aligned context allocates");
        assert_eq!(
            (owned.as_ptr() as usize) % core::mem::align_of::<ProbeCtx>(),
            0,
            "the adopted address is aligned for the context"
        );
    }

    /// `OwnedBlock::take(NULL)` is `None`; a non-NULL block is owned and released by `Drop`.
    #[test]
    fn owned_block_take_null_is_none() {
        // SAFETY: NULL is a valid input; `take` adopts nothing.
        assert!(unsafe { OwnedBlock::take(ptr::null_mut()) }.is_none());
        let p = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(16, ptr::null(), 0)
        };
        assert!(!p.is_null());
        // SAFETY: `p` is a fresh block this frame owns; the handle is its single release.
        assert!(unsafe { OwnedBlock::take(p) }.is_some());
    }
}

// The exhaustive ownership-transition model and the production correspondence tests. Test-only:
// nothing here is compiled into the library, and it never changes the production rules.
#[cfg(test)]
#[path = "owned_ctx_model.rs"]
mod release_model_tests;

// -------------------------------------------------------------------------------------------
// RUNTIME_ALLOC_OWNERSHIP site tests: allocation refusal, partial initialisation and
// exactly-once release, asserted by address.
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod alloc_own_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::runtime::mem::free_probe;
    use crate::runtime::release_probe::{self, Arm};
    use core::cell::RefCell;

    thread_local! {
        /// The member addresses `MemberCtx::destroy_body` released on this thread.
        static MEMBER_RELEASES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    fn member_releases() -> Vec<usize> {
        MEMBER_RELEASES.with(|r| r.borrow().clone())
    }

    /// A context with one owned member block: the shape `destroy_body` must release exactly once,
    /// and the only shape a partially initialised owner must *not* release.
    ///
    /// It deliberately has no C layout: it is a test-only type that never crosses the C ABI, so
    /// the owner's layout is Rust's.
    struct MemberCtx {
        member: *mut c_void,
    }

    // SAFETY: (a) `destroy_body` releases exactly the one member this value owns (NULL-tolerant)
    // and never the enclosing block, which `OwnedCtx`'s `Drop` releases alone; it is reached once
    // per owner. (b) an all-zero `MemberCtx` (member NULL) is a valid value for which the body is
    // sound. (c) `FILE` is the default NULL coordinate, which has no lifetime obligation.
    unsafe impl CtxDestroy for MemberCtx {
        unsafe fn destroy_body(ptr: *mut MemberCtx) {
            // SAFETY: `ptr` is a live context per the trait contract.
            let member = unsafe { (*ptr).member };
            if member.is_null() {
                return;
            }
            MEMBER_RELEASES.with(|r| r.borrow_mut().push(member as usize));
            // The block is still owned by `OwnedCtx` at this point: its `Drop` calls this body
            // first and releases the block afterwards. Observing no release yet proves the order.
            assert!(
                release_probe::take().is_none(),
                "a member must be released before the enclosing block"
            );
            // SAFETY: `member` is the block this context owns and has not released.
            unsafe { CRYPTO_free(member, ptr::null(), 0) };
        }
    }

    /// A validated owner releases its member and its block exactly once each, by address, and the
    /// member goes first. The exactly-once claim is checked at the **allocator seam** (which sees
    /// frees performed by callees too), not only at the owner's own probe: a `destroy_body` that
    /// also released the enclosing block would make the block's seam count 2.
    #[test]
    fn alloc_own_ctx_releases_member_and_block_once_each_by_address() {
        release_probe::clear();
        free_probe::reset();
        MEMBER_RELEASES.with(|r| r.borrow_mut().clear());
        let member = unsafe {
            // SAFETY: `file` is NULL, which `CRYPTO_malloc` accepts.
            CRYPTO_malloc(16, ptr::null(), 0)
        };
        assert!(!member.is_null(), "the member block allocates");
        let block_addr;
        {
            let owned = OwnedCtx::<MemberCtx>::zalloc().expect("a zeroed context allocates");
            block_addr = owned.as_ptr() as usize;
            // SAFETY: `owned` is live and uniquely owned; the member is a fresh block this test
            // transfers to it.
            unsafe { (*owned.as_ptr()).member = member };
        }
        assert_eq!(
            member_releases(),
            vec![member as usize],
            "the member released once"
        );
        let call = release_probe::take().expect("the block release was recorded");
        assert_eq!(call.arm, Arm::Plain);
        assert_eq!(
            call.ptr as usize, block_addr,
            "the block release names its address"
        );
        assert!(
            release_probe::take().is_none(),
            "the block release happens once"
        );
        // The member was freed by `destroy_body` (a callee), the block by the owner's `Drop`.
        assert_eq!(
            free_probe::count(member),
            1,
            "the seam saw exactly one release of the member"
        );
        assert_eq!(
            free_probe::count(block_addr as *const c_void),
            1,
            "the seam saw exactly one release of the block"
        );
        assert_eq!(
            free_probe::events(),
            vec![member as usize, block_addr],
            "member then block, each exactly once"
        );
    }

    /// Instrument liveness (§16): the seam counter distinguishes one release at an address from
    /// two. This is the negative control for the exactly-once assertions above -- if `count`
    /// could not see a second record, those assertions would be vacuous.
    #[test]
    fn free_probe_counts_a_second_release_at_the_same_address() {
        free_probe::reset();
        // An address-shaped value; `record` only stores the number and never dereferences it.
        let p = 0x1000 as *mut c_void;
        free_probe::record(p);
        assert_eq!(free_probe::count(p), 1);
        free_probe::record(p);
        assert_eq!(free_probe::count(p), 2, "a second release is visible");
    }

    /// Storage that was never validated (`RawCtx`) releases the block alone: the member it still
    /// points at is not a resource the owner acquired, so nothing else is released.
    #[test]
    fn alloc_own_rawctx_partial_init_releases_the_block_alone() {
        release_probe::clear();
        MEMBER_RELEASES.with(|r| r.borrow_mut().clear());
        let member = unsafe {
            // SAFETY: `file` is NULL, which `CRYPTO_malloc` accepts.
            CRYPTO_malloc(16, ptr::null(), 0)
        };
        assert!(!member.is_null());
        let raw = RawCtx::<MemberCtx>::zalloc().expect("a zeroed block allocates");
        let block_addr = raw.as_ptr() as usize;
        // SAFETY: `raw` is live storage for a `MemberCtx` whose fields the caller initialises;
        // `member` is a fresh block.
        unsafe { (*raw.as_ptr()).member = member };
        drop(raw);
        assert!(
            member_releases().is_empty(),
            "unvalidated storage must not run the destructor body"
        );
        let call = release_probe::take().expect("the block release was recorded");
        assert_eq!(
            call.ptr as usize, block_addr,
            "the only release is the block"
        );
        assert!(release_probe::take().is_none());
        // SAFETY: the test still owns the member block it allocated above.
        unsafe { CRYPTO_free(member, ptr::null(), 0) };
    }

    /// A refused allocation answers `None` and creates nothing to release; the seam's NULL is not
    /// adopted as a block.
    #[test]
    fn alloc_own_refused_allocation_answers_none_and_releases_nothing() {
        release_probe::clear();
        let refused = unsafe {
            // SAFETY: `file` is NULL, which `CRYPTO_malloc` accepts. The libc allocator refuses a
            // request larger than `PTRDIFF_MAX`, which is the seam's own allocation-refusal arm.
            CRYPTO_malloc(usize::MAX, ptr::null(), 0)
        };
        assert!(refused.is_null(), "the seam refuses an impossible request");
        // SAFETY: NULL is the documented "nothing to adopt" input.
        assert!(unsafe { OwnedBlock::take(refused) }.is_none());
        assert!(
            release_probe::take().is_none(),
            "a refused allocation creates no block to release"
        );
    }

    /// The same two facts for the byte-block owner, whose release is the seam's `(NULL, 0)`
    /// coordinate: one release, naming the address the owner was handed.
    #[test]
    fn alloc_own_block_release_is_exactly_once_at_the_allocated_address() {
        release_probe::clear();
        let raw = unsafe {
            // SAFETY: `file` is NULL, which `CRYPTO_malloc` accepts.
            CRYPTO_malloc(8, ptr::null(), 0)
        };
        assert!(!raw.is_null());
        // SAFETY: `raw` is the fresh block this test owns and has not released.
        let block = unsafe { OwnedBlock::take(raw) }.expect("a non-NULL block is owned");
        drop(block);
        let call = release_probe::take().expect("the release was recorded");
        assert_eq!(call.arm, Arm::Plain);
        assert_eq!(
            call.ptr as usize, raw as usize,
            "released at its own address"
        );
        assert!(call.file.is_null() && call.line == 0);
        assert!(release_probe::take().is_none(), "released exactly once");
    }
}
