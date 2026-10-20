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
//! ## `OwnedStr` vs [`OwnedCStr`]
//!
//! [`OwnedStr`] is the **general** byte/string owner. Its [`OwnedStr::new`] and
//! [`OwnedStr::new_zeroed`] constructors deliberately do not establish a NUL
//! terminator (a zero-length or unterminated writable block is legitimate for a
//! consumer that tracks its own length or fills the terminator itself). It is
//! therefore **not** a proof that a block is readable as a C string.
//!
//! [`OwnedCStr`] is the narrower **proof type**: exclusively owned,
//! seam-allocated, and NUL-terminated. Every safe-visible constructor is an
//! operation that establishes termination (`CRYPTO_strdup`/`CRYPTO_strndup`, or
//! an explicitly contracted adoption), so a consumer such as an object's C-string
//! member may rely on the invariant without re-checking it. The two types must
//! not be conflated: installing an `OwnedStr` where a C string is required would
//! silence exactly the obligation `OwnedCStr` exists to carry.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void, CStr};

use crate::runtime::mem::{
    CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_strndup, CRYPTO_zalloc,
};
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
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(len, alloc_file.as_ptr(), alloc_line)
        }
        .cast::<c_char>();
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
        let raw = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_zalloc(len, alloc_file.as_ptr(), alloc_line)
        }
        .cast::<c_char>();
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

    /// `CRYPTO_strdup(s, file, line)` as an owned block whose `Drop` releases at the
    /// same coordinates, or `None` when the allocator answers NULL.
    ///
    /// # Safety
    ///
    /// `s` is NULL or a NUL-terminated C string. The block is fresh, so no other
    /// owner will release it.
    pub(crate) unsafe fn dup(s: *const c_char, file: SeamFile, line: c_int) -> Option<Self> {
        // SAFETY: `s` is NUL-terminated per the contract and the seam answers NULL
        // or a fresh block this call owns; `file` is a static coordinate.
        let raw = unsafe { CRYPTO_strdup(s, file.as_ptr(), line) };
        // SAFETY: `raw` is NULL or the fresh seam block just allocated; no other
        // owner will release it.
        unsafe { Self::adopt(raw, file, line) }
    }

    /// `CRYPTO_strndup(s, max, file, line)` as an owned block whose `Drop` releases
    /// at the same coordinates, or `None` when the allocator answers NULL.
    ///
    /// # Safety
    ///
    /// `s` is NULL or readable for `max` bytes with a NUL terminator at or before
    /// `max`; the copy this constructor returns is always NUL-terminated.
    pub(crate) unsafe fn strndup(
        s: *const c_char,
        max: usize,
        file: SeamFile,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `s` is readable for `max` bytes per the contract and the seam
        // answers NULL or a fresh block this call owns.
        let raw = unsafe { CRYPTO_strndup(s, max, file.as_ptr(), line) };
        // SAFETY: `raw` is NULL or the fresh seam block just allocated; no other
        // owner will release it.
        unsafe { Self::adopt(raw, file, line) }
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

/// An owned, seam-allocated, **NUL-terminated** C string.
///
/// This is a proof type, distinct from the general byte/string owner
/// [`OwnedStr`]. Constructing one (other than through the explicitly unsafe
/// adoption route) goes through `CRYPTO_strdup`/`CRYPTO_strndup`, whose contract
/// establishes that the block ends in a NUL byte. The type holds a **non-NULL**
/// pointer: a refused allocation is `None`, never an empty handle.
///
/// Unlike [`OwnedStr`], whose `new`/`new_zeroed` constructors may produce an
/// unterminated or zero-length block, `OwnedCStr` carries the termination
/// invariant to every consumer. There is deliberately **no safe conversion from
/// `OwnedStr`**: `OwnedStr` does not record the allocation extent, so termination
/// cannot be validated from it without already assuming the answer. A caller that
/// genuinely has a foreign unterminated block must use the explicitly `unsafe`
/// adoption route (or write the terminator itself before adopting).
///
/// The release is unchanged from [`OwnedStr`]: the block's single plain
/// `CRYPTO_free` at the coordinates the constructor was given.
pub(crate) struct OwnedCStr {
    inner: OwnedStr,
}

impl OwnedCStr {
    /// `CRYPTO_strdup(s, file, line)` as a NUL-terminated owned block whose
    /// `Drop` releases at the same coordinates, or `None` when the allocator
    /// answers NULL.
    ///
    /// # Safety
    ///
    /// `s` is NULL or a NUL-terminated C string. The operation itself establishes
    /// the copy's terminator; the caller's obligation is only the readability of
    /// `s`.
    pub(crate) unsafe fn dup(s: *const c_char, file: SeamFile, line: c_int) -> Option<Self> {
        // SAFETY: `s` is NULL or NUL-terminated per the contract; `OwnedStr::dup`
        // performs the seam's own `CRYPTO_strdup` call at these coordinates.
        let inner = unsafe { OwnedStr::dup(s, file, line) }?;
        Some(Self { inner })
    }

    /// `CRYPTO_strndup(s, max, file, line)` as a NUL-terminated owned block whose
    /// `Drop` releases at the same coordinates, or `None` when the allocator
    /// answers NULL.
    ///
    /// `CRYPTO_strndup` copies at most `max` bytes and always appends the
    /// terminator, so the result is readable as a C string even when `s` has no
    /// NUL at or before `max`.
    ///
    /// # Safety
    ///
    /// `s` is NULL or readable for `max` bytes.
    pub(crate) unsafe fn strndup(
        s: *const c_char,
        max: usize,
        file: SeamFile,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `s` is readable for `max` bytes per the contract; the seam's
        // own `CRYPTO_strndup` call and its coordinates are unchanged.
        let inner = unsafe { OwnedStr::strndup(s, max, file, line) }?;
        Some(Self { inner })
    }

    /// Adopt a foreign seam block of `len` bytes total whose final byte is the
    /// terminator, for a genuine transfer where the caller (not this module)
    /// allocated the block.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish everything [`OwnedStr::adopt`]
    /// requires, plus termination:
    ///
    /// * **provenance** -- a live allocation from this crate's `CRYPTO_*` seam;
    /// * **identity and extent** -- `ptr` is the base of the **whole** block;
    /// * **alignment** -- valid for `c_char` and the seam's release;
    /// * **initialization and termination** -- `len` is the block's extent in
    ///   bytes, `len > 0`, and `ptr[len - 1]` (and therefore the first NUL at or
    ///   before it) terminates the readable string;
    /// * **exclusive ownership** -- no other owner will release it; this handle's
    ///   `Drop` is its single release at `file`/`line`.
    ///
    /// A NULL `ptr` answers `None` (the authority's empty state); a non-NULL
    /// `ptr` always becomes the owner, so a failed conversion cannot leak.
    #[allow(dead_code)] // Contracted foreign-transfer route; no in-tree caller needs it yet.
    pub(crate) unsafe fn adopt(
        ptr: *mut c_char,
        len: usize,
        file: SeamFile,
        line: c_int,
    ) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        // The contract proves the extent and the terminator; these checks make a
        // violating caller fail loudly in debug/test builds rather than install an
        // unterminated member.
        debug_assert!(len > 0, "a non-NULL C string includes its terminator");
        // SAFETY: `ptr` is readable for `len` bytes and `len > 0` per the contract.
        let last = unsafe { *ptr.add(len - 1) };
        debug_assert_eq!(last, 0, "block is not NUL-terminated");
        // SAFETY: `ptr` is non-NULL and the caller establishes the `OwnedStr::adopt`
        // preconditions above; ownership is transferred once.
        let inner = unsafe { OwnedStr::adopt(ptr, file, line) }?;
        Some(Self { inner })
    }

    /// The start of the string. Always non-NULL and NUL-terminated for the life of
    /// the handle.
    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.inner.as_ptr()
    }

    /// Borrow the contents as a `CStr`; the borrow cannot outlive this owner.
    pub(crate) fn as_c_str(&self) -> &CStr {
        // SAFETY: `as_ptr` is non-NULL and NUL-terminated by the type's constructors,
        // and the borrow is tied to `&self`.
        unsafe { CStr::from_ptr(self.as_ptr()) }
    }

    /// Give up ownership of the block to a consumer that takes it over.
    pub(crate) fn into_raw(self) -> *mut c_char {
        self.inner.into_raw()
    }
}

impl AsRef<CStr> for OwnedCStr {
    fn as_ref(&self) -> &CStr {
        self.as_c_str()
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
