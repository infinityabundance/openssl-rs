//! Shared ownership for a crate-allocator byte block.
//!
//! This is the one owner for the `B-R1a` duplicate group: a `CRYPTO_malloc` block
//! whose release is either the authority's plain `CRYPTO_free(ptr, file, line)`
//! or its cleansing `CRYPTO_clear_free(ptr, num, file, line)`.
//!
//! The block stays a raw allocation through the crate's allocator seam: a Rust
//! `Box`/`Vec` would hide both the allocation and its release from a
//! caller-installed `CRYPTO_set_mem_functions` hook. Only *ownership* is this
//! type. The constructors allocate or adopt the block and `Drop` performs its
//! single release, at the exact authority coordinates the caller supplies.
//!
//! The release representation is private: safe callers cannot construct a
//! cleansing release with a length larger than the block they allocated. The
//! safe allocating constructors always set `num` to the allocation length; the
//! only constructor that accepts a distinct `num` is `unsafe` and carries the
//! `num <= len` obligation.
//!
//! A NULL pointer is a valid, empty buffer: the adoption constructors answer
//! `None` for it, and `Drop` accepts a NULL block, matching the authority's own
//! no-op `free(NULL)`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};

use crate::runtime::mem::{
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_zalloc,
};

/// An owned block allocated through the crate's `CRYPTO_*` allocator seam.
pub(crate) struct OwnedBuf {
    ptr: *mut c_uchar,
    release: Release,
}

/// How the authority releases a buffer [`OwnedBuf`] owns.
///
/// Private to this module so safe code cannot manufacture a cleansing release
/// whose `num` exceeds the allocated extent.
enum Release {
    /// The authority's plain `CRYPTO_free(ptr, file, line)`.
    Plain { file: *const c_char, line: c_int },
    /// The authority's cleansing `CRYPTO_clear_free(ptr, num, file, line)`, which
    /// zeroes `num` bytes before releasing the block.
    Cleansed {
        num: usize,
        file: *const c_char,
        line: c_int,
    },
}

impl OwnedBuf {
    /// `CRYPTO_malloc(len, file, line)` for a plainly released block, or `None`
    /// when the allocator answers NULL.
    pub(crate) fn new(len: usize, file: *const c_char, line: c_int) -> Option<Self> {
        Self::alloc_plain(len, file, line, file, line)
    }

    /// `CRYPTO_malloc(len, alloc_file, alloc_line)` for a plainly released block
    /// whose `Drop` records `release_file`/`release_line`, or `None` when the
    /// allocator answers NULL.
    ///
    /// The two coordinate pairs stay separate so a caller-installed
    /// `CRYPTO_set_mem_functions` hook observes each at the authority's own site.
    pub(crate) fn new_plain_released(
        len: usize,
        alloc_file: *const c_char,
        alloc_line: c_int,
        release_file: *const c_char,
        release_line: c_int,
    ) -> Option<Self> {
        Self::alloc_plain(len, alloc_file, alloc_line, release_file, release_line)
    }

    /// `CRYPTO_zalloc(len, file, line)` for a plainly released block, or `None`
    /// when the allocator answers NULL.
    pub(crate) fn new_zeroed(len: usize, file: *const c_char, line: c_int) -> Option<Self> {
        let raw = CRYPTO_zalloc(len, file, line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::Plain { file, line },
        })
    }

    /// `CRYPTO_malloc(len, file, line)` for a block whose `Drop` cleanses exactly
    /// its allocation length, or `None` when the allocator answers NULL.
    pub(crate) fn new_cleansed(len: usize, file: *const c_char, line: c_int) -> Option<Self> {
        Self::alloc_cleansed(len, len, file, line, line)
    }

    /// `CRYPTO_malloc(len, file, alloc_line)` for a block whose `Drop` cleanses
    /// exactly its allocation length at `file`/`release_line`, or `None` when the
    /// allocator answers NULL.
    pub(crate) fn new_cleansed_at(
        len: usize,
        file: *const c_char,
        alloc_line: c_int,
        release_line: c_int,
    ) -> Option<Self> {
        if alloc_line == release_line {
            Self::new_cleansed(len, file, alloc_line)
        } else {
            Self::alloc_cleansed(len, len, file, alloc_line, release_line)
        }
    }

    /// `CRYPTO_zalloc(len, file, line)` for a block whose `Drop` cleanses exactly
    /// its allocation length, or `None` when the allocator answers NULL.
    pub(crate) fn new_zeroed_cleansed(
        len: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        Self::new_zeroed_cleansed_at(len, file, line, line)
    }

    /// `CRYPTO_zalloc(len, file, alloc_line)` for a block whose `Drop` cleanses
    /// exactly its allocation length at `file`/`release_line`, or `None` when the
    /// allocator answers NULL.
    pub(crate) fn new_zeroed_cleansed_at(
        len: usize,
        file: *const c_char,
        alloc_line: c_int,
        release_line: c_int,
    ) -> Option<Self> {
        let raw = CRYPTO_zalloc(len, file, alloc_line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::Cleansed {
                num: len,
                file,
                line: release_line,
            },
        })
    }

    /// `CRYPTO_malloc(len, file, alloc_line)` for a block whose `Drop` cleanses
    /// `num` bytes at `file`/`release_line`, or `None` when the allocator answers
    /// NULL.
    ///
    /// # Safety
    ///
    /// `num <= len`. `len` is the allocation extent; `num` is the number of bytes
    /// the cleansing write will cover. Passing `num > len` would make
    /// `CRYPTO_clear_free` write outside the block.
    pub(crate) unsafe fn new_cleansed_num(
        len: usize,
        num: usize,
        file: *const c_char,
        alloc_line: c_int,
        release_line: c_int,
    ) -> Option<Self> {
        debug_assert!(
            num <= len,
            "the cleansing length must not exceed the allocation"
        );
        Self::alloc_cleansed(len, num, file, alloc_line, release_line)
    }

    /// `CRYPTO_strdup(str_, file, line)`, or `None` when the helper answers NULL.
    ///
    /// # Safety
    ///
    /// `str_` is NULL or points at a NUL-terminated C string.
    pub(crate) unsafe fn new_strdup(
        str_: *const c_char,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `str_` is NULL or NUL-terminated per this function's contract.
        let raw = unsafe { CRYPTO_strdup(str_, file, line) }.cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::Plain { file, line },
        })
    }

    /// Adopt a plainly released block, or `None` for NULL.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish:
    ///
    /// * **provenance** — the block came from the `CRYPTO_*` seam (not `Box`, `Vec`,
    ///   `malloc`, or a foreign allocator), so `CRYPTO_free` is its valid release;
    /// * **allocation identity and extent** — `ptr` is the whole block's base, not a
    ///   sub-range or an interior pointer, and the extent is the allocation the
    ///   seam made;
    /// * **alignment** — it is aligned for the allocator's own release;
    /// * **initialization** — any bytes read before release were initialized for
    ///   their use; a plain release performs no reads;
    /// * **exclusive ownership** — no other owner will release the block; this
    ///   handle's `Drop` is its single release;
    /// * **exact release** — `file`/`line` name the authority's own plain
    ///   `CRYPTO_free` site for this block.
    pub(crate) unsafe fn adopt_plain(
        ptr: *mut c_uchar,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                release: Release::Plain { file, line },
            })
        }
    }

    /// Adopt a secret block released cleansing over `num` bytes, or `None` for
    /// NULL.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish:
    ///
    /// * **provenance** — the block came from the `CRYPTO_*` seam (not `Box`, `Vec`,
    ///   `malloc`, or a foreign allocator), so `CRYPTO_clear_free` is its valid
    ///   release;
    /// * **allocation identity and extent** — `ptr` is the whole block's base, not a
    ///   sub-range or an interior pointer, and `num <= allocated extent`;
    /// * **alignment** — it is aligned for the allocator's own release;
    /// * **initialization** — the `num` bytes the cleansing write touches are
    ///   inside the allocation; `CRYPTO_clear_free` performs no read that depends
    ///   on their values;
    /// * **exclusive ownership** — no other owner will release the block; this
    ///   handle's `Drop` is its single release;
    /// * **exact release** — `file`/`line` name the authority's own cleansing
    ///   `CRYPTO_clear_free` site for this block.
    pub(crate) unsafe fn adopt_cleansed(
        ptr: *mut c_uchar,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                release: Release::Cleansed { num, file, line },
            })
        }
    }

    /// The writable start of the block.
    pub(crate) fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Give up ownership of the block to a consumer that takes it over.
    pub(crate) fn into_raw(self) -> *mut c_uchar {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }

    fn alloc_plain(
        len: usize,
        alloc_file: *const c_char,
        alloc_line: c_int,
        release_file: *const c_char,
        release_line: c_int,
    ) -> Option<Self> {
        let raw = CRYPTO_malloc(len, alloc_file, alloc_line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::Plain {
                file: release_file,
                line: release_line,
            },
        })
    }

    fn alloc_cleansed(
        len: usize,
        num: usize,
        file: *const c_char,
        alloc_line: c_int,
        release_line: c_int,
    ) -> Option<Self> {
        let raw = CRYPTO_malloc(len, file, alloc_line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::Cleansed {
                num,
                file,
                line: release_line,
            },
        })
    }
}

impl Drop for OwnedBuf {
    /// The block's single release, through the same seam the authority uses.
    fn drop(&mut self) {
        match self.release {
            Release::Plain { file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not
                // released; the authority's `CRYPTO_free` accepts NULL.
                unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), file, line) };
            }
            Release::Cleansed { num, file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not
                // released; `num` was set to the allocation length by a safe
                // constructor or established by `adopt_cleansed`'s contract, so it
                // is readable for `num` bytes. `CRYPTO_clear_free` zeroes then
                // releases it and accepts NULL.
                unsafe { CRYPTO_clear_free(self.ptr.cast::<c_void>(), num, file, line) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedBuf;
    use core::ffi::c_char;
    use core::ptr;

    const FILE: *const c_char = c"test/owned_buf.rs".as_ptr();

    #[test]
    fn new_allocates_and_plain_releases() {
        let buf = OwnedBuf::new(16, FILE, 11);
        assert!(buf.is_some(), "a 16-byte block must be allocatable");
        let Some(buf) = buf else { return };
        assert!(!buf.as_ptr().is_null());
        drop(buf);
    }

    #[test]
    fn new_zeroed_allocates() {
        let buf = OwnedBuf::new_zeroed(16, FILE, 12);
        assert!(buf.is_some(), "a 16-byte block must be allocatable");
        let Some(buf) = buf else { return };
        // SAFETY: `as_ptr` is the block's writable start, 16 bytes long.
        assert_eq!(unsafe { *buf.as_ptr() }, 0);
    }

    #[test]
    fn new_cleansed_uses_the_allocation_length() {
        let buf = OwnedBuf::new_cleansed(8, FILE, 15);
        assert!(buf.is_some(), "an 8-byte block must be allocatable");
        let Some(buf) = buf else { return };
        // SAFETY: the block is 8 bytes and exclusively owned by `buf`; the
        // constructor fixed the cleansing length to that same 8 bytes.
        unsafe { core::ptr::write_bytes(buf.as_ptr(), 0xab, 8) };
        drop(buf);
    }

    #[test]
    fn adopt_null_is_none_for_both_releases() {
        // SAFETY: NULL is explicitly permitted by the adoption contract.
        let plain = unsafe { OwnedBuf::adopt_plain(ptr::null_mut(), FILE, 13) };
        assert!(plain.is_none());
        // SAFETY: NULL is explicitly permitted by the adoption contract.
        let cleansed = unsafe { OwnedBuf::adopt_cleansed(ptr::null_mut(), 0, FILE, 14) };
        assert!(cleansed.is_none());
    }

    #[test]
    fn into_raw_suppresses_release() {
        let buf = OwnedBuf::new(4, FILE, 17);
        assert!(buf.is_some(), "a 4-byte block must be allocatable");
        let Some(buf) = buf else { return };
        let raw = buf.into_raw();
        assert!(!raw.is_null());
        // SAFETY: `raw` is the whole block allocated above and is released here
        // exactly once; no `OwnedBuf` still owns it.
        unsafe { crate::runtime::mem::CRYPTO_free(raw.cast(), FILE, 17) };
    }
}
