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

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
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
///     [`SeamFile::from_static_ptr`] relies on this and cannot establish it.
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
    /// `ptr` is NULL or a live block a previous `into_raw` gave up and `Drop` has not released.
    pub(crate) unsafe fn from_raw_at(
        ptr: *mut T,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<OwnedCtx<T>> {
        NonNull::new(ptr).map(|ptr| OwnedCtx {
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
        // `*_free` body.
        unsafe {
            T::destroy_body(self.ptr.as_ptr());
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
        // `CRYPTO_malloc` is a safe function: it answers NULL or a fresh, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = CRYPTO_malloc(core::mem::size_of::<T>(), alloc_file.as_ptr(), alloc_line)
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
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = CRYPTO_zalloc(core::mem::size_of::<T>(), alloc_file.as_ptr(), alloc_line)
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
        // SAFETY: `self.ptr` is a block this seam allocated and has not handed out; its single
        // release is the authority's own plain `CRYPTO_free`.
        unsafe { CRYPTO_free(self.ptr, ptr::null(), 0) };
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

    /// `OwnedBlock::take(NULL)` is `None`; a non-NULL block is owned and released by `Drop`.
    #[test]
    fn owned_block_take_null_is_none() {
        // SAFETY: NULL is a valid input; `take` adopts nothing.
        assert!(unsafe { OwnedBlock::take(ptr::null_mut()) }.is_none());
        let p = CRYPTO_malloc(16, ptr::null(), 0);
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
