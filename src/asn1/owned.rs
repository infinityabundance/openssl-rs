//! Owned seam blocks for the ASN.1 template machinery.
//!
//! The `d2i`/`i2d` codec and the primitive encoders allocate a handful of
//! *transient* blocks -- the `SET OF` sort scratch, the joined error string, the
//! growing OID digit heap, the two opaque context objects -- and release each by
//! hand on its tail path and (for some) an error path. [`OwnedBlock`] gives every
//! such block a single owning handle whose `Drop` is the only release, so the tail
//! free and the error-path frees become one `Drop` rather than a hand-written walk.
//!
//! The blocks stay `CRYPTO_*` allocations at the authority's exact sizes and
//! through the authority's own `__FILE__`/`__LINE__`, so a caller-installed
//! `CRYPTO_set_mem_functions` hook observes each allocation and its size exactly as
//! it observes the authority's. Ownership is expressed *above* the seam; the seam
//! stays the raw boundary, and the one dereference the handle performs -- the
//! release in its `Drop` -- is its documented `unsafe` boundary.
//!
//! This is not the `Collected` constructed-string buffer of [`crate::asn1::d2i`]:
//! that one grows through `CRYPTO_realloc` and hands its block to an `ASN1_STRING`,
//! so it carries its own handle in the module that owns that lifecycle.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};

/// An owned `CRYPTO_*` block.
///
/// The block keeps the authority's size and the authority's `__FILE__`/`__LINE__`
/// (both observable to an installed hook), but its *ownership* is this type: the
/// two constructors allocate through the crate's allocator seam and [`Drop`] is the
/// block's single release. A C caller receives the block's stable address through
/// [`into_raw`](OwnedBlock::into_raw) and hands it back to be reclaimed by
/// [`from_raw`](OwnedBlock::from_raw), whose `Drop` releases it.
pub(crate) struct OwnedBlock<T> {
    ptr: ptr::NonNull<T>,
    file: *const c_char,
    line: c_int,
}

impl<T> OwnedBlock<T> {
    /// Allocate `count` blocks of `T` through the installed allocator's *malloc*
    /// arm, or `None` when it answers NULL.
    ///
    /// `count` items of `T` is `count * size_of::<T>()` bytes, which is the size the
    /// authority asks for. The product is `checked_mul`-guarded: an overflow is the
    /// module's failure outcome (`None`, the same arm as a refused allocation), so a
    /// wrapped, too-small request never reaches the allocator. No block is allocated
    /// on that path, so nothing is leaked, and when the product does not overflow the
    /// request is byte-for-byte the authority's own size.
    pub(crate) fn malloc(count: usize, file: *const c_char, line: c_int) -> Option<OwnedBlock<T>> {
        let size = count.checked_mul(core::mem::size_of::<T>())?;
        let raw = CRYPTO_malloc(size, file, line).cast::<T>();
        ptr::NonNull::new(raw).map(|ptr| OwnedBlock { ptr, file, line })
    }

    /// Allocate `count` *zeroed* blocks of `T` through the installed allocator's
    /// *zalloc* arm, or `None` when it answers NULL.
    ///
    /// As [`malloc`](OwnedBlock::malloc), the byte count is `checked_mul`-guarded so
    /// an overflow answers the module's failure outcome without ever asking the
    /// allocator for a wrapped size.
    pub(crate) fn zalloc(count: usize, file: *const c_char, line: c_int) -> Option<OwnedBlock<T>> {
        let size = count.checked_mul(core::mem::size_of::<T>())?;
        let raw = CRYPTO_zalloc(size, file, line).cast::<T>();
        ptr::NonNull::new(raw).map(|ptr| OwnedBlock { ptr, file, line })
    }

    /// Reclaim a block a previous [`into_raw`](OwnedBlock::into_raw) handed to a C
    /// caller, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live block of `T` from the crate's allocator that a
    /// previous `into_raw` gave up and `Drop` has not released; `file`/`line` are
    /// the values that block's allocation recorded.
    pub(crate) unsafe fn from_raw(
        ptr: *mut T,
        file: *const c_char,
        line: c_int,
    ) -> Option<OwnedBlock<T>> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedBlock { ptr, file, line })
    }

    /// The block's stable address, for the raw C calls the codec makes.
    pub(crate) fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Re-point the release diagnostic at the authority's other site for this
    /// block, preserving the allocation file. The line is metadata only: no
    /// extent or ownership invariant depends on it.
    pub(crate) fn set_release_line(&mut self, line: c_int) {
        self.line = line;
    }

    /// Give up ownership of the block to the C caller's pointer.
    pub(crate) fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl<T> Drop for OwnedBlock<T> {
    /// Release the block through the same allocator seam it was allocated on.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the exclusively owned block this handle allocated
        // (`malloc`/`zalloc`, or reclaimed by `from_raw`) and has not released; the
        // stored release coordinates, which `set_release_line` may update, are the
        // authority's release site for this block; `Drop` runs once, so this is its
        // single release.
        unsafe { CRYPTO_free(self.ptr.as_ptr().cast::<c_void>(), self.file, self.line) };
    }
}
