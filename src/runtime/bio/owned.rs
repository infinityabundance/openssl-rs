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

/// The authority's `*_free` body for one `#[repr(C)]` context, without the block release
/// [`OwnedCtx`]'s `Drop` performs. One impl per context type, so the owner runs the right
/// destructor from `Drop` without a `CRYPTO_free` written at any call site.
///
/// `FILE`/`LINE_ALLOC`/`LINE_FREE` are the authority's own allocation-tracking coordinates, kept
/// distinct so a caller-installed `CRYPTO_set_mem_functions` hook observes the release at the same
/// site the authority releases it (the `bf_*` filters allocate and free at `NULL`/`0`, while
/// `ossl_core_bio.c` records its own `__FILE__` and the two lines it names).
pub(crate) trait CtxDestroy: Sized {
    /// `__FILE__` for this context's `CRYPTO_*` calls, or NULL where the authority passes none.
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
}

impl<T: CtxDestroy> OwnedCtx<T> {
    /// Allocate a fresh, zeroed block of `T`'s size through the installed allocator, or `None`
    /// when it answers NULL -- the authority's refused `CRYPTO_zalloc`.
    ///
    /// A zeroed block is the authority's own constructed state for every context this constructor
    /// is used for (each is one the authority builds with `OPENSSL_zalloc`), so `destroy_body` is
    /// written against it and the block may be validated immediately.
    pub(crate) fn zalloc() -> Option<OwnedCtx<T>> {
        // SAFETY: for every context this constructor is used for, the all-zero block is the
        // authority's own constructed `T` (the authority builds it with `OPENSSL_zalloc`), and
        // `destroy_body` is written to release exactly that state, so the storage holds a valid `T`
        // whose members satisfy the destructor's invariants.
        Some(unsafe { RawCtx::<T>::zalloc()?.assume_init() })
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
        NonNull::new(ptr).map(|ptr| OwnedCtx { ptr })
    }
}

impl<T: CtxDestroy> Drop for OwnedCtx<T> {
    /// The context destructor: the authority's `*_free` body ([`CtxDestroy::destroy_body`])
    /// followed by the block's release, through the same allocator seam the block was allocated on.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle allocated (or `from_raw` reclaimed) and this
        // is its single release; `Drop` runs once, and `destroy_body` is the authority's own
        // `*_free` body.
        unsafe {
            T::destroy_body(self.ptr.as_ptr());
            CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), T::FILE, T::LINE_FREE);
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
}

impl<T: CtxDestroy> RawCtx<T> {
    /// Allocate a fresh, **uninitialised** block of `T`'s size through the installed allocator, or
    /// `None` when it answers NULL -- the authority's `CRYPTO_malloc` for the blocks it does not
    /// zero (`ossl_core_bio.c`'s handle and `linebuffer.c`'s context).
    pub(crate) fn malloc() -> Option<RawCtx<T>> {
        // `CRYPTO_malloc` is a safe function: it answers NULL or a fresh, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = CRYPTO_malloc(core::mem::size_of::<T>(), T::FILE, T::LINE_ALLOC)
            .cast::<MaybeUninit<T>>();
        NonNull::new(raw).map(|ptr| RawCtx { ptr })
    }

    /// Allocate a fresh, zeroed block of `T`'s size through the installed allocator, or `None` when
    /// it answers NULL -- the authority's `CRYPTO_zalloc`. The bytes are zero but the block is a
    /// `RawCtx`: zeroing is not, by itself, a valid `T` for every context, so the caller still
    /// validates it with [`RawCtx::assume_init`].
    pub(crate) fn zalloc() -> Option<RawCtx<T>> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<T>()` bytes, which is exactly `T`'s layout.
        let raw = CRYPTO_zalloc(core::mem::size_of::<T>(), T::FILE, T::LINE_ALLOC)
            .cast::<MaybeUninit<T>>();
        NonNull::new(raw).map(|ptr| RawCtx { ptr })
    }

    /// The stable address the caller initialises `T`'s fields through.
    pub(crate) fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr().cast::<T>()
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
        core::mem::forget(self);
        OwnedCtx { ptr }
    }
}

impl<T: CtxDestroy> Drop for RawCtx<T> {
    /// Releases the **block alone**: `T` is not (yet) a valid value, so its destructor body must not
    /// run. Same allocator, size and `T::FILE`/`T::LINE_FREE` as [`OwnedCtx`]'s block release.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block this handle allocated and has not handed out; this is its
        // single release, and the authority's own bare `CRYPTO_free` is the whole release.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), T::FILE, T::LINE_FREE) };
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
