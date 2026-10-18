//! Allocator-seam diagnostic coordinates.
//!
//! [`SeamFile`] is the only file coordinate a safe constructor accepts when the
//! owner stores the pointer for later use at `Drop`. It is built from a
//! `&'static CStr` -- a C-string literal (`c"..."`) or a module constant with
//! static storage -- so a safe caller cannot hand an owner a pointer into a
//! temporary allocation that dies before the owner's release. A genuinely
//! dynamic `*const c_char` is not expressible through these safe constructors:
//! an owner that must accept one needs an explicitly audited
//! `unsafe fn ..._dynamic` route whose `# Safety` contract requires the pointer
//! to remain valid for at least as long as the owner and every allocator-hook
//! use of it during release.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, CStr};

/// A `CRYPTO_*` `file` coordinate whose storage outlives every owner made from
/// it.
#[derive(Clone, Copy)]
pub(crate) struct SeamFile(*const c_char);

impl SeamFile {
    /// The authority's NULL coordinate (`CRYPTO_free(..., NULL, ...)`).
    pub(crate) const NULL: SeamFile = SeamFile(core::ptr::null());

    /// A coordinate backed by static storage: a C-string literal or a `'static`
    /// constant.
    pub(crate) const fn new(file: &'static CStr) -> SeamFile {
        SeamFile(file.as_ptr())
    }

    /// A coordinate the caller proves names static storage.
    ///
    /// # Safety
    ///
    /// `file` is NULL or points at a NUL-terminated byte string that remains
    /// valid for the entire lifetime of every owner that stores this coordinate
    /// and for every allocator-hook read of it during release. This is the
    /// narrow route for an unsafe trait's associated coordinate (for example
    /// [`crate::runtime::bio::owned::CtxDestroy::FILE`]); safe callers use
    /// [`Self::new`] with a `&'static CStr` instead.
    pub(crate) const unsafe fn from_static_ptr(file: *const c_char) -> SeamFile {
        SeamFile(file)
    }

    /// The raw pointer the allocator seam records.
    pub(crate) const fn as_ptr(self) -> *const c_char {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::SeamFile;
    use core::ffi::CStr;

    #[test]
    fn new_preserves_the_static_pointer() {
        const FILE: &CStr = c"test/mem_coords.rs";
        assert_eq!(SeamFile::new(FILE).as_ptr(), FILE.as_ptr());
    }

    #[test]
    fn null_coordinate_is_null() {
        assert!(SeamFile::NULL.as_ptr().is_null());
    }

    #[test]
    fn from_static_ptr_preserves_the_static_pointer() {
        // A `static` C string, unlike a temporary `CStr`, is valid for the whole
        // program. `SeamFile::new` requires `&'static CStr`, so constructing one
        // from a non-`'static` temporary is a compile-time rejection, not a
        // runtime check.
        static FILE: &CStr = c"test/mem_coords_static.rs";
        // SAFETY: `FILE` is static storage and NUL-terminated for the program.
        let seam = unsafe { SeamFile::from_static_ptr(FILE.as_ptr()) };
        assert_eq!(seam.as_ptr(), FILE.as_ptr());
    }
}
