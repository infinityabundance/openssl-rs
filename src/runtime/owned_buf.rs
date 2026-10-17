//! Shared ownership for a crate-allocator byte block.
//!
//! This is the one owner for the `B-R1a`/`B-R1b`/`B-R3` duplicate groups: an
//! allocator-seam block whose release is the authority's plain
//! `CRYPTO_free(ptr, file, line)`, its cleansing `CRYPTO_clear_free(ptr, num,
//! file, line)`, or its secure-heap `CRYPTO_secure_clear_free(ptr, num, file,
//! line)`.
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
    CRYPTO_clear_free, CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup, CRYPTO_strndup, CRYPTO_zalloc,
};
use crate::runtime::secure::{
    CRYPTO_secure_clear_free, CRYPTO_secure_malloc, CRYPTO_secure_zalloc,
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
    /// The authority's conditional release: cleansing over `num` bytes when `clear`, plain
    /// `CRYPTO_free` otherwise. `clear` is fixed at construction (the fields are private and no
    /// method changes it), so the release kind a handle was adopted with cannot drift.
    Conditional {
        num: usize,
        clear: bool,
        file: *const c_char,
        line: c_int,
    },
    /// The authority's secure-heap cleansing
    /// `CRYPTO_secure_clear_free(ptr, num, file, line)`, which zeroes the whole
    /// usable allocation and releases it through the secure allocator.
    SecureCleansed {
        num: usize,
        file: *const c_char,
        line: c_int,
    },
}

/// Test-only observation of the conditional release arm. Thread-local so a concurrent test in
/// another module cannot perturb the value and vice versa.
#[cfg(test)]
mod conditional_probe {
    use core::cell::Cell;

    thread_local! {
        pub(super) static LAST: Cell<Option<(bool, usize)>> = const { Cell::new(None) };
    }
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
        Self::alloc_cleansed(len, len, file, line, file, line)
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
            Self::alloc_cleansed(len, len, file, alloc_line, file, release_line)
        }
    }

    /// `CRYPTO_malloc(len, alloc_file, alloc_line)` for a block whose `Drop`
    /// cleanses exactly its allocation length at `release_file`/`release_line`,
    /// or `None` when the allocator answers NULL.
    ///
    /// `B-R1b`'s cleansing wrapper records constant release coordinates that
    /// differ from the allocation site, so the two pairs stay separate.
    pub(crate) fn new_cleansed_released(
        len: usize,
        alloc_file: *const c_char,
        alloc_line: c_int,
        release_file: *const c_char,
        release_line: c_int,
    ) -> Option<Self> {
        Self::alloc_cleansed(len, len, alloc_file, alloc_line, release_file, release_line)
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

    /// `CRYPTO_secure_malloc(len, file, line)` for a block whose `Drop` releases
    /// through the authority's secure-heap cleansing
    /// `CRYPTO_secure_clear_free(ptr, len, file, line)`, or `None` when the
    /// allocator answers NULL.
    ///
    /// When the secure heap is not initialised the secure allocator falls back to
    /// the plain seam, exactly as the authority does;
    /// `CRYPTO_secure_clear_free` routes both provenances correctly.
    pub(crate) fn new_secure_cleansed(
        len: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `file` is NULL or a NUL-terminated C string at every call site.
        let raw = unsafe { CRYPTO_secure_malloc(len, file, line) }.cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::SecureCleansed {
                num: len,
                file,
                line,
            },
        })
    }

    /// `CRYPTO_secure_zalloc(len, file, line)` for a block whose `Drop` releases
    /// through the authority's secure-heap cleansing
    /// `CRYPTO_secure_clear_free(ptr, len, file, line)`, or `None` when the
    /// allocator answers NULL.
    pub(crate) fn new_secure_zalloc_cleansed(
        len: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `file` is NULL or a NUL-terminated C string at every call site.
        let raw = unsafe { CRYPTO_secure_zalloc(len, file, line) }.cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(Self {
            ptr: raw,
            release: Release::SecureCleansed {
                num: len,
                file,
                line,
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
        Self::alloc_cleansed(len, num, file, alloc_line, file, release_line)
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

    /// `CRYPTO_strndup(str_, max, file, line)`: a NUL-terminated copy of at most
    /// `max` bytes, or `None` when the helper answers NULL.
    ///
    /// # Safety
    ///
    /// `str_` is NULL or readable for `max` bytes; a non-NULL `str_` need not be
    /// NUL-terminated within `max`.
    pub(crate) unsafe fn new_strndup(
        str_: *const c_char,
        max: usize,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        // SAFETY: `str_` is NULL or readable for `max` bytes per this function's
        // contract.
        let raw = unsafe { CRYPTO_strndup(str_, max, file, line) }.cast::<c_uchar>();
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
    /// * **provenance** — the block came from the plain `CRYPTO_*` seam (not `Box`,
    ///   `Vec`, `malloc`, a foreign allocator, or the secure heap), so `CRYPTO_free` is
    ///   its valid release. A secure-heap pointer is **excluded**: releasing it
    ///   through `CRYPTO_free` is undefined behaviour, not a fallback;
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

    /// Adopt a block whose authority release is conditional: cleansing over `num` bytes when
    /// `clear`, plain `CRYPTO_free` otherwise. `clear` is fixed at construction and never
    /// mutated. Answer `None` for NULL.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish the same conditions as
    /// [`Self::adopt_cleansed`]: plain `CRYPTO_*` seam provenance (a secure-heap pointer is
    /// excluded), whole-block identity and extent with `num <= allocated extent`, alignment,
    /// initialization, exclusive ownership, and the exact `file`/`line` at which the authority
    /// releases this block. `clear` must be the authority's own decision for this block and must
    /// not change afterwards; the returned handle never mutates it.
    pub(crate) unsafe fn adopt_conditional(
        ptr: *mut c_uchar,
        num: usize,
        clear: bool,
        file: *const c_char,
        line: c_int,
    ) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                release: Release::Conditional {
                    num,
                    clear,
                    file,
                    line,
                },
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
    /// * **provenance** — the block came from the plain `CRYPTO_*` seam (not `Box`,
    ///   `Vec`, `malloc`, a foreign allocator, or the secure heap), so
    ///   `CRYPTO_clear_free` is its valid release. A secure-heap pointer is
    ///   **excluded**: this arm performs a plain release after cleansing and does not
    ///   carry the secure allocator's provenance;
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

    /// Adopt a plainly released block, treating NULL as the authority's empty
    /// buffer. `Drop` then calls `CRYPTO_free(NULL, ...)`, the authority's no-op.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish the same conditions as
    /// [`Self::adopt_plain`]: provenance from the `CRYPTO_*` seam, whole-block
    /// identity and extent, alignment, initialization for any reads, exclusive
    /// ownership, and the exact plain `CRYPTO_free` release site. A secure-heap
    /// pointer is excluded here for the same reason as in [`Self::adopt_plain`].
    pub(crate) unsafe fn adopt_plain_nullable(
        ptr: *mut c_uchar,
        file: *const c_char,
        line: c_int,
    ) -> Self {
        Self {
            ptr,
            release: Release::Plain { file, line },
        }
    }

    /// Adopt a secret block released cleansing over `num` bytes, treating NULL as
    /// the authority's empty buffer. `Drop` then calls
    /// `CRYPTO_clear_free(NULL, ...)`, the authority's no-op.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish the same conditions as
    /// [`Self::adopt_cleansed`]: provenance from the `CRYPTO_*` seam, whole-block
    /// identity and extent with `num <= allocated extent`, alignment, exclusive
    /// ownership, and the exact cleansing `CRYPTO_clear_free` release site. A
    /// secure-heap pointer is excluded here for the same reason as in
    /// [`Self::adopt_cleansed`].
    pub(crate) unsafe fn adopt_cleansed_nullable(
        ptr: *mut c_uchar,
        num: usize,
        file: *const c_char,
        line: c_int,
    ) -> Self {
        Self {
            ptr,
            release: Release::Cleansed { num, file, line },
        }
    }

    /// Adopt a secure-heap block released cleansing over `num` bytes, or `None`
    /// for NULL.
    ///
    /// # Safety
    ///
    /// For a non-NULL `ptr` the caller must establish:
    ///
    /// * **provenance** — the block is either (a) a live allocation from this
    ///   module's secure heap, or (b) the exact plain-fallback block
    ///   `CRYPTO_secure_malloc`/`CRYPTO_secure_zalloc` returned while the secure heap
    ///   was uninitialised. `CRYPTO_secure_clear_free` is the release for both. An
    ///   independently allocated plain `CRYPTO_malloc` block is **excluded** — the
    ///   reverse of the exclusion in `adopt_plain`/`adopt_cleansed`; a plain block
    ///   reaches this arm only through the secure allocator's own fallback;
    /// * **allocation identity and extent** — `ptr` is the whole block's base, not a
    ///   sub-range or an interior pointer, and `num <= allocated extent` (for the
    ///   fallback case, that plain allocation's extent);
    /// * **alignment** — it is aligned for the secure allocator's own release;
    /// * **initialization** — the `num` bytes the caller reasons about are inside
    ///   the allocation; the secure release cleanses the whole usable chunk and does
    ///   not read those bytes for a decision;
    /// * **exclusive ownership** — no other owner will release the block; this
    ///   handle's `Drop` is its single release;
    /// * **exact release** — `file`/`line` name the authority's own secure cleansing
    ///   `CRYPTO_secure_clear_free` site for this block.
    pub(crate) unsafe fn adopt_secure_cleansed(
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
                release: Release::SecureCleansed { num, file, line },
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
            release: Release::Cleansed {
                num,
                file: release_file,
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
            Release::Conditional {
                num,
                clear,
                file,
                line,
            } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released. `num`
                // was established by `adopt_conditional`'s contract as at most the allocated
                // extent, so the cleansing write is in bounds. `clear` was fixed at construction,
                // so this handle's release kind cannot have changed; both releases accept NULL.
                #[cfg(test)]
                conditional_probe::LAST.with(|last| last.set(Some((clear, num))));
                // SAFETY: both releases accept the block this handle owns; the preceding comment
                // establishes its provenance, extent and single-release obligation.
                unsafe {
                    if clear {
                        CRYPTO_clear_free(self.ptr.cast::<c_void>(), num, file, line);
                    } else {
                        CRYPTO_free(self.ptr.cast::<c_void>(), file, line);
                    }
                }
            }
            Release::SecureCleansed { num, file, line } => {
                // SAFETY: `self.ptr` is the whole block a secure constructor allocated or
                // `adopt_secure_cleansed` established as secure-allocator provenance
                // (including that allocator's documented plain fallback); this handle has
                // not released it. `CRYPTO_secure_clear_free` cleanses
                // the whole usable secure chunk, routes its documented plain fallback,
                // and accepts NULL.
                unsafe { CRYPTO_secure_clear_free(self.ptr.cast::<c_void>(), num, file, line) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::conditional_probe;
    use super::OwnedBuf;
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::runtime::secure::{
        test_arena_bytes, test_offset_of, CRYPTO_secure_actual_size, CRYPTO_secure_malloc_done,
        CRYPTO_secure_malloc_init, CRYPTO_secure_used,
    };
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
    fn adopt_secure_null_is_none() {
        // SAFETY: NULL is explicitly permitted by the adoption contract; no secure
        // heap needs to be initialised for it.
        let adopted = unsafe { OwnedBuf::adopt_secure_cleansed(ptr::null_mut(), 0, FILE, 23) };
        assert!(adopted.is_none());
    }

    #[test]
    fn secure_cleansed_block_releases_through_the_secure_allocator() {
        let _guard = crate::test_support::lock_global_state();
        let _ = CRYPTO_secure_malloc_done();
        let init = CRYPTO_secure_malloc_init(1 << 20, 16);
        assert!(
            init == 1 || init == 2,
            "the secure heap must initialise for this test (init returned {init})"
        );
        let buf = OwnedBuf::new_secure_cleansed(64, FILE, 24);
        assert!(
            buf.is_some(),
            "a 64-byte allocation from an initialised secure heap must succeed"
        );
        let Some(buf) = buf else { return };
        let ptr = buf.as_ptr().cast::<core::ffi::c_void>();
        let size = CRYPTO_secure_actual_size(ptr);
        assert!(size >= 64, "actual size {size} covers the request");
        let offset = test_offset_of(ptr);
        assert!(offset.is_some(), "the allocation must be inside the arena");
        let Some(offset) = offset else { return };
        assert!(
            test_arena_bytes(offset, size).iter().all(|&b| b == 0),
            "a fresh secure allocation starts zeroed"
        );
        // SAFETY: `buf` exclusively owns the whole `size`-byte usable chunk.
        unsafe { core::ptr::write_bytes(buf.as_ptr(), 0xab, size) };
        assert!(
            test_arena_bytes(offset, size).iter().all(|&b| b == 0xab),
            "the nonzero pattern must be observable before release"
        );
        drop(buf);
        let released = test_arena_bytes(offset, size);
        assert_eq!(released.len(), size, "the released chunk stays readable");
        assert!(
            released.iter().all(|&b| b == 0),
            "the secure release must cleanse the whole usable chunk"
        );
        assert_eq!(CRYPTO_secure_used(), 0);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn secure_cleansed_zero_length_block_is_a_cleansed_minimum_chunk() {
        let _guard = crate::test_support::lock_global_state();
        let _ = CRYPTO_secure_malloc_done();
        let init = CRYPTO_secure_malloc_init(1 << 20, 16);
        assert!(
            init == 1 || init == 2,
            "the secure heap must initialise for this test (init returned {init})"
        );
        let buf = OwnedBuf::new_secure_cleansed(0, FILE, 25);
        assert!(
            buf.is_some(),
            "a zero-length request from an initialised secure heap still allocates"
        );
        let Some(buf) = buf else { return };
        let ptr = buf.as_ptr().cast::<core::ffi::c_void>();
        let size = CRYPTO_secure_actual_size(ptr);
        assert_eq!(size, 16, "a zero-length request gets the minimum chunk");
        let offset = test_offset_of(ptr);
        assert!(offset.is_some(), "the allocation must be inside the arena");
        let Some(offset) = offset else { return };
        // SAFETY: `buf` exclusively owns the whole `size`-byte usable chunk.
        unsafe { core::ptr::write_bytes(buf.as_ptr(), 0x5a, size) };
        assert!(test_arena_bytes(offset, size).iter().all(|&b| b == 0x5a));
        drop(buf);
        let released = test_arena_bytes(offset, size);
        assert_eq!(released.len(), size);
        assert!(
            released.iter().all(|&b| b == 0),
            "the secure release cleanses even when the stored num is zero"
        );
        assert_eq!(CRYPTO_secure_used(), 0);
        assert_eq!(CRYPTO_secure_malloc_done(), 1);
    }

    #[test]
    fn conditional_release_selects_the_mode_and_keeps_the_length() {
        // The constructor must carry the authority's decision and its cleansing length through to
        // `Drop`: `clear = true` selects `CRYPTO_clear_free` over exactly `num` bytes, while
        // `clear = false` selects the plain `CRYPTO_free`.
        fn observed_release(clear: bool) -> Option<(bool, usize)> {
            // SAFETY: the block is a fresh 8-byte allocation from this crate's seam, owned by this
            // frame and released exactly once by `buf`.
            let buf = unsafe {
                OwnedBuf::adopt_conditional(CRYPTO_malloc(8, FILE, 18).cast(), 8, clear, FILE, 19)
            }?;
            conditional_probe::LAST.with(|last| last.set(None));
            drop(buf);
            conditional_probe::LAST.with(core::cell::Cell::take)
        }

        assert_eq!(
            observed_release(true),
            Some((true, 8)),
            "clear = true must take the cleansing release over the stored length"
        );
        assert_eq!(
            observed_release(false),
            Some((false, 8)),
            "clear = false must take the plain release"
        );
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
