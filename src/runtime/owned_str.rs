//! Shared ownership for a crate-allocator C string.
//!
//! This is the one owner for the `S-P` duplicate group: an allocator-seam
//! `char *` whose release is the authority's plain
//! `CRYPTO_free(ptr, file, line)`. All ten members store the same
//! `{ptr, file, line}` coordinates; the construction sites differ only in which
//! seam call produced the block (`CRYPTO_malloc`, `CRYPTO_strdup`,
//! `CRYPTO_strndup`, or an authority helper that allocates through one of them).
//!
//! The block stays a raw allocation through the crate's allocator seam: a Rust
//! `String`/`CString` would hide both the allocation and its release from a
//! caller-installed `CRYPTO_set_mem_functions` hook. Only *ownership* is this
//! type. The constructors allocate or adopt the block and `Drop` performs its
//! single release, at the exact authority coordinates the caller supplies.
//!
//! The pointer is a bare `*mut c_char`, not a [`core::ptr::NonNull`]: every
//! member's authority path can observe a NULL `CRYPTO_strdup` refusal, and a
//! NULL block is the authority's own no-op `free(NULL)`. [`OwnedStr::adopt`]
//! answers `None` for it; [`OwnedStr::adopt_nullable`] keeps it as an empty
//! handle whose `Drop` is that no-op release.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::mem_coords::SeamFile;

/// Test-only observation of the release `Drop` selected, for the `OwnedStr`
/// model-correspondence tests. Thread-local so concurrent tests cannot perturb
/// each other.
#[cfg(test)]
mod drop_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Call {
        /// `Drop` was asked to release a NULL handle (the authority's `free(NULL)`).
        pub(super) null: bool,
    }

    thread_local! {
        pub(super) static LAST: Cell<Option<Call>> = const { Cell::new(None) };
    }
}

/// An owned NUL-terminated (or, before its consumer fills it, writable) C
/// string allocated through the crate's `CRYPTO_*` allocator seam.
pub(crate) struct OwnedStr {
    ptr: *mut c_char,
    file: SeamFile,
    line: c_int,
}

impl OwnedStr {
    /// `CRYPTO_malloc(len, alloc_file, alloc_line)` for a block whose `Drop`
    /// releases at `release_file`/`release_line`, or `None` when the allocator
    /// answers NULL.
    ///
    /// The two coordinate pairs stay separate so a caller-installed
    /// `CRYPTO_set_mem_functions` hook observes each at the authority's own
    /// site. The bytes are uninitialised; a consumer that reads the block as a
    /// C string must write the terminator first.
    pub(crate) fn new(
        len: usize,
        alloc_file: SeamFile,
        alloc_line: c_int,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<Self> {
        let raw = CRYPTO_malloc(len, alloc_file.as_ptr(), alloc_line).cast::<c_char>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            file: release_file,
            line: release_line,
        })
    }

    /// `CRYPTO_zalloc(len, alloc_file, alloc_line)` for a zeroed block whose
    /// `Drop` releases at `release_file`/`release_line`, or `None` when the
    /// allocator answers NULL.
    ///
    /// As [`Self::new`], the two coordinate pairs stay separate so a
    /// caller-installed `CRYPTO_set_mem_functions` hook observes each at the
    /// authority's own site. The bytes are an all-zero initialised block of
    /// `len` bytes; a consumer that reads it as a C string still needs the
    /// zeroed first byte to be its terminator.
    pub(crate) fn new_zeroed(
        len: usize,
        alloc_file: SeamFile,
        alloc_line: c_int,
        release_file: SeamFile,
        release_line: c_int,
    ) -> Option<Self> {
        let raw = CRYPTO_zalloc(len, alloc_file.as_ptr(), alloc_line).cast::<c_char>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            file: release_file,
            line: release_line,
        })
    }

    /// Adopt a block a helper or a field returned, or `None` for NULL -- the
    /// authority's own no-op `free(NULL)`.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish:
    ///
    /// * **provenance** -- the block is a live allocation from this crate's
    ///   `CRYPTO_*` allocator seam (`CRYPTO_malloc`/`CRYPTO_strdup`/
    ///   `CRYPTO_strndup`, or an authority helper that allocates through one of
    ///   them), not a pointer into a Rust `String`/`Vec` or an unrelated
    ///   allocator;
    /// * **allocation identity and extent** -- `ptr` is the base of the whole
    ///   block, not an interior pointer or a sub-range;
    /// * **alignment** -- it is aligned for `c_char` and for the seam's own
    ///   release;
    /// * **initialization** -- if any consumer reads the block as a C string,
    ///   it is NUL-terminated within the allocation; `Drop` itself never reads
    ///   the bytes;
    /// * **exclusive ownership** -- no other owner will release the block; this
    ///   handle's `Drop` is its single release;
    /// * **exact release** -- `file`/`line` name the authority's own plain
    ///   `CRYPTO_free` site for this block. `SeamFile` establishes that the file
    ///   coordinate names static storage.
    pub(crate) unsafe fn adopt(ptr: *mut c_char, file: SeamFile, line: c_int) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, file, line })
        }
    }

    /// Adopt a block while keeping NULL as the authority's empty string, so
    /// `Drop` performs the authority's no-op `free(NULL)`.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish the same conditions as
    /// [`Self::adopt`]: seam provenance, whole-block identity and extent,
    /// alignment, NUL-termination for any string consumer, exclusive ownership,
    /// and the exact plain `CRYPTO_free` release site.
    pub(crate) unsafe fn adopt_nullable(ptr: *mut c_char, file: SeamFile, line: c_int) -> Self {
        Self { ptr, file, line }
    }

    /// Re-point the release diagnostic at the authority's other site for this
    /// string, preserving the release file. The line is metadata only: no
    /// extent, ownership or initialization invariant depends on it.
    pub(crate) fn set_release_line(&mut self, line: c_int) {
        self.line = line;
    }

    /// The start of the string. Writable, because crate constructors fill a
    /// freshly allocated block through this handle.
    pub(crate) fn as_ptr(&self) -> *mut c_char {
        self.ptr
    }

    /// Give up ownership of the block to a consumer that takes it over.
    pub(crate) fn into_raw(self) -> *mut c_char {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedStr {
    /// The block's single release, through the same seam the authority uses.
    fn drop(&mut self) {
        #[cfg(test)]
        drop_probe::LAST.with(|last| {
            last.set(Some(drop_probe::Call {
                null: self.ptr.is_null(),
            }))
        });
        // SAFETY: `self.ptr` is the block this handle owns and has not released
        // (or NULL, which `CRYPTO_free` accepts as its no-op); the coordinates
        // are the authority's own release site.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file.as_ptr(), self.line) };
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedStr;
    use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
    use crate::runtime::mem_coords::SeamFile;
    use core::ffi::CStr;
    use core::ptr;

    const FILE: &CStr = c"test/owned_str.rs";

    #[test]
    fn new_allocates_a_writable_block_of_the_requested_size() {
        let owned = OwnedStr::new(6, SeamFile::new(FILE), 11, SeamFile::new(FILE), 12);
        assert!(owned.is_some(), "a 6-byte block must be allocatable");
        let Some(owned) = owned else { return };
        // SAFETY: `owned` exclusively owns the 6-byte block and `as_ptr` is its
        // writable start.
        unsafe {
            ptr::write_bytes(owned.as_ptr(), 0x5a, 6);
        }
        for i in 0..6 {
            // SAFETY: `i` is within the requested 6-byte extent.
            assert_eq!(unsafe { *owned.as_ptr().add(i) }, 0x5a);
        }
    }

    #[test]
    fn set_release_line_keeps_the_file_and_changes_only_the_line() {
        let mut owned = OwnedStr::new(4, SeamFile::new(FILE), 21, SeamFile::new(FILE), 22);
        assert!(owned.is_some(), "a 4-byte block must be allocatable");
        let Some(ref mut owned) = owned else { return };
        assert_eq!(owned.file.as_ptr(), FILE.as_ptr());
        assert_eq!(owned.line, 22);
        owned.set_release_line(23);
        assert_eq!(
            owned.file.as_ptr(),
            FILE.as_ptr(),
            "the release file must be preserved"
        );
        assert_eq!(owned.line, 23);
    }

    #[test]
    fn new_zeroed_allocates_a_zeroed_writable_block() {
        let owned = OwnedStr::new_zeroed(8, SeamFile::new(FILE), 24, SeamFile::new(FILE), 25);
        assert!(
            owned.is_some(),
            "an 8-byte zeroed block must be allocatable"
        );
        let Some(owned) = owned else { return };
        for i in 0..8 {
            // SAFETY: `i` is within the requested 8-byte extent.
            assert_eq!(unsafe { *owned.as_ptr().add(i) }, 0);
        }
        // SAFETY: the block is writable for the requested 8 bytes.
        unsafe { ptr::write_bytes(owned.as_ptr(), 0x5a, 8) };
        for i in 0..8 {
            // SAFETY: `i` is within the requested 8-byte extent.
            assert_eq!(unsafe { *owned.as_ptr().add(i) }, 0x5a);
        }
    }

    #[test]
    fn adopt_keeps_the_nul_terminated_contents() {
        // SAFETY: the literal is NUL-terminated and the seam answers a fresh
        // block owned by this frame.
        let raw = unsafe { CRYPTO_strdup(c"owned-str".as_ptr(), FILE.as_ptr(), 13) };
        // SAFETY: `raw` is NULL or the fresh seam block just allocated; no other
        // owner will release it.
        let owned = unsafe { OwnedStr::adopt(raw, SeamFile::new(FILE), 14) };
        assert!(owned.is_some(), "a successful strdup must be adopted");
        let Some(owned) = owned else { return };
        // SAFETY: the adopted block is NUL-terminated by `CRYPTO_strdup`.
        assert_eq!(unsafe { CStr::from_ptr(owned.as_ptr()) }, c"owned-str");
    }

    #[test]
    fn adopt_null_is_none() {
        // SAFETY: NULL is explicitly permitted by the adoption contract.
        let owned = unsafe { OwnedStr::adopt(ptr::null_mut(), SeamFile::new(FILE), 15) };
        assert!(owned.is_none());
    }

    #[test]
    fn null_handle_drop_is_the_noop_release() {
        // SAFETY: NULL is explicitly permitted by the nullable adoption contract.
        let owned = unsafe { OwnedStr::adopt_nullable(ptr::null_mut(), SeamFile::new(FILE), 16) };
        assert!(owned.as_ptr().is_null());
        drop(owned);
    }

    #[test]
    fn into_raw_suppresses_release() {
        // SAFETY: the literal is NUL-terminated and the seam answers a fresh
        // block owned by this frame.
        let raw = unsafe { CRYPTO_strdup(c"transfer".as_ptr(), FILE.as_ptr(), 17) };
        // SAFETY: `raw` is NULL or the fresh seam block just allocated; no other
        // owner will release it.
        let owned = unsafe { OwnedStr::adopt(raw, SeamFile::new(FILE), 18) };
        assert!(owned.is_some(), "a successful strdup must be adopted");
        let Some(owned) = owned else { return };
        let raw = owned.into_raw();
        assert!(!raw.is_null());
        // SAFETY: `raw` is the whole block allocated above and is released here
        // exactly once; no `OwnedStr` still owns it.
        unsafe { CRYPTO_free(raw.cast(), FILE.as_ptr(), 18) };
    }
}

// The exhaustive ownership-transition model and the production correspondence
// tests. Test-only: nothing here is compiled into the library.
#[cfg(test)]
#[path = "owned_str_model.rs"]
mod release_model_tests;
