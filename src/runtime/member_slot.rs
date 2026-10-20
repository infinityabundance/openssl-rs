//! The shared validated handle over an object-owned C-string member buffer.
//!
//! Many `#[repr(C)]` objects model an owned C string as a `char *` field whose
//! setter, reader and destructor live in different functions and modules. The
//! field must keep the authority's exact type and offset, so it cannot *be* a Rust
//! owner; this module supplies the transient **borrow** that is the only sanctioned
//! way to move the member's ownership in and out.
//!
//! ## The member-buffer invariant (stated once)
//!
//! The field is, at every observation, either NULL or a single NUL-terminated block
//! produced by the crate's `CRYPTO_strdup`/`CRYPTO_strndup` seam and owned by the
//! enclosing object.
//! That object is the block's only owner: the block is released **exactly once**, by
//! the object destructor (through [`CStrSlot::clear`]) or by the next
//! `clear`/`store` that replaces it. Nothing else frees or aliases it, and the empty
//! state is NULL (not a zero-length block).
//!
//! ## The token
//!
//! [`CStrSlot::clear`] releases the incumbent and returns an [`EmptyCStrSlot`], a
//! non-`Copy` proof that the field is now NULL. [`EmptyCStrSlot::store`] consumes
//! that token when it transfers an [`OwnedCStr`] into the object, so a second store
//! on the same cleared slot, and storing over an incumbent, are both inexpressible
//! through the safe interface. A caller that drops the token without storing has
//! simply left the field NULL, which is the authority's own empty state.
//!
//! `store` takes [`OwnedCStr`], not the general [`crate::runtime::owned_str::OwnedStr`]:
//! only the former proves that the block is NUL-terminated, which is what the
//! member-buffer invariant promises every subsequent reader. An `OwnedStr` produced
//! by `new`/`new_zeroed` cannot be installed from safe code, so safe code cannot
//! falsify the invariant. A genuinely foreign block is transferred through the
//! explicitly `unsafe` [`EmptyCStrSlot::store_raw`] route (or adopted as an
//! `OwnedCStr` first).
//!
//! `unsafe` appears only at the proof boundaries: [`CStrSlot::of`] (the field obeys
//! the invariant), [`CStrSlot::assume_empty`] (the field is NULL without a preceding
//! `clear`, for a freshly zeroed object), and [`EmptyCStrSlot::store_raw`] (an
//! externally allocated block is transferred). `clear` and `store` are safe: the
//! borrow, the [`SeamFile`] coordinate and the [`OwnedCStr`] establish their
//! preconditions. The persisted `file` coordinate of `clear` is a [`SeamFile`] (a
//! `&'static CStr`), exactly as `OwnedBuf`'s release coordinate is, so a safe caller
//! cannot hand the later allocator hook a pointer into a temporary allocation.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::runtime::mem::CRYPTO_free;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_str::OwnedCStr;

/// A validated handle over one object-owned C-string member field.
///
/// The handle borrows only the field, never the enclosing object, so call sites keep
/// their existing `PropqSlot::of(&mut enclosing)` shape through a module-local thin
/// wrapper that borrows the whole object and hands this type the private field.
pub(crate) struct CStrSlot<'a> {
    /// Borrow of the object's member field; its value obeys the invariant for `'a`.
    slot: &'a mut *mut c_char,
}

impl<'a> CStrSlot<'a> {
    /// Derive the handle from a member field.
    ///
    /// # Safety
    ///
    /// `slot` is the member field of a live object and is borrowed mutably for `'a`;
    /// its current value obeys the member-buffer invariant (NULL, or one
    /// NUL-terminated seam block that object owns exclusively). No other code frees,
    /// aliases or writes the field for `'a`.
    pub(crate) unsafe fn of(slot: &'a mut *mut c_char) -> CStrSlot<'a> {
        CStrSlot { slot }
    }

    /// Release any incumbent through the authority's own `CRYPTO_free` site, leaving
    /// the field NULL, and answer the token that a subsequent store consumes.
    ///
    /// NULL is a no-op for `CRYPTO_free`, so an unconditional `clear` reproduces both
    /// the authority's `if (p) { free(p); p = NULL; }` and its unguarded
    /// `OPENSSL_free(p)`.
    pub(crate) fn clear(&mut self, file: SeamFile, line: c_int) -> EmptyCStrSlot<'_> {
        let old = core::mem::replace(&mut *self.slot, ptr::null_mut());
        // SAFETY: by the member-buffer invariant the incumbent is NULL or the
        // object's own single seam block, so this is that block's one release;
        // `CRYPTO_free` ignores NULL. `SeamFile` guarantees the coordinate's storage
        // outlives any later allocator-hook read.
        unsafe { CRYPTO_free(old.cast(), file.as_ptr(), line) };
        EmptyCStrSlot {
            slot: &mut *self.slot,
        }
    }

    /// Assert that the field is already NULL and answer the store token without
    /// releasing anything.
    ///
    /// This is the fresh-zeroed-object arm: the authority allocates the enclosing
    /// object with `CRYPTO_zalloc`, so the member is empty and the authority performs
    /// no release at the store site. It keeps the allocator transcript exact where a
    /// `clear` would add a `free(NULL)` call (observationally inert, but not the
    /// authority's own sequence).
    ///
    /// # Safety
    ///
    /// The field is currently NULL and the caller holds exclusive access to it for
    /// `'a`.
    pub(crate) unsafe fn assume_empty(self) -> EmptyCStrSlot<'a> {
        EmptyCStrSlot { slot: self.slot }
    }
}

/// Proof that a member field is empty (NULL), borrowed from its object.
///
/// The type is not `Copy`/`Clone` and is only constructible through
/// [`CStrSlot::clear`] or [`CStrSlot::assume_empty`], so the safe interface permits
/// exactly one store per cleared slot.
pub(crate) struct EmptyCStrSlot<'a> {
    slot: &'a mut *mut c_char,
}

impl EmptyCStrSlot<'_> {
    /// Transfer an owned, **NUL-terminated** block into the enclosing object: the
    /// object becomes its only owner and its destructor is the block's single release.
    ///
    /// The parameter is [`OwnedCStr`], the proof type for a seam block that ends in a
    /// NUL byte. The general `OwnedStr` cannot be passed here from safe code, so safe
    /// code cannot install an unterminated (or zero-length) block and falsify the
    /// member-buffer invariant.
    pub(crate) fn store(self, owned: OwnedCStr) {
        // `into_raw` suppresses `OwnedCStr`'s `Drop`, so ownership moves to the object
        // rather than being released here.
        *self.slot = owned.into_raw();
    }

    /// Transfer an **externally allocated** block whose ownership this caller already
    /// holds, for a genuine foreign transfer (an authority helper that allocated the
    /// block, or an item layer handing it over). Prefer [`Self::store`] whenever the
    /// caller allocated the block itself.
    ///
    /// # Safety
    ///
    /// `adopted` is NULL or a block that satisfies §1 of `AGENTS.md`:
    ///
    /// * **provenance** — produced by this crate's `CRYPTO_*` allocator seam, not a
    ///   Rust allocator or an unrelated one;
    /// * **identity and extent** — the base of the whole block, not an interior
    ///   pointer or a sub-range;
    /// * **alignment** — valid for `c_char` and for the seam's release;
    /// * **initialization** — the block is NUL-terminated within the allocation, so
    ///   the member-buffer invariant is restored immediately;
    /// * **exclusive ownership** — no other owner will release it; the enclosing
    ///   object's destructor is its single release.
    ///
    /// This is the **only** route by which safe code's type-level termination proof
    /// can be bypassed. It is therefore explicitly `unsafe`: a non-terminated block
    /// is permitted here only under the caller's own contract, never silently through
    /// a weakened safe signature. Prefer [`Self::store`], or adopt the block as an
    /// [`OwnedCStr`] first, whenever the caller owns it.
    ///
    /// The release coordinates are the enclosing object's destructor, not the
    /// caller's; this method persists no coordinate of its own.
    #[allow(dead_code)] // Audited foreign-transfer route; no in-tree caller needs it yet.
    pub(crate) unsafe fn store_raw(self, adopted: *mut c_char) {
        *self.slot = adopted;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::runtime::mem_coords::SeamFile;
    use core::ffi::CStr;

    /// Static storage, so `SeamFile::new` (which demands `&'static CStr`) accepts it.
    const FILE: &CStr = c"test/member_slot.rs";

    /// Install the Rust-backed allocator shim first under Miri, where the default
    /// libc allocator is a foreign function Miri cannot execute.
    fn install_miri_shim() {
        #[cfg(miri)]
        crate::runtime::miri_tcb::install();
    }

    fn dup(s: &CStr) -> OwnedCStr {
        // SAFETY: the literal is NUL-terminated.
        unsafe { OwnedCStr::dup(s.as_ptr(), SeamFile::new(FILE), 1) }.unwrap()
    }

    #[test]
    fn store_transfers_the_block_and_clear_releases_it() {
        install_miri_shim();
        let mut field: *mut c_char = ptr::null_mut();
        {
            // SAFETY: `field` is this test's own local member and initially NULL.
            let mut slot = unsafe { CStrSlot::of(&mut field) };
            let empty = slot.clear(SeamFile::new(FILE), 2);
            empty.store(dup(c"alpha"));
        }

        assert!(!field.is_null());
        // SAFETY: the stored block is NUL-terminated.
        assert_eq!(unsafe { CStr::from_ptr(field) }, c"alpha");

        // A second clear releases the stored block exactly once and leaves NULL.
        {
            // SAFETY: `field` is this test's own local member and is non-NULL (the
            // stored block), which the handle's invariant permits.
            let mut slot = unsafe { CStrSlot::of(&mut field) };
            // Dropping the token without storing is the authority's empty state.
            let _empty = slot.clear(SeamFile::new(FILE), 3);
        }
        assert!(field.is_null());
    }

    /// Runtime witness of the token's single-use shape: [`EmptyCStrSlot::store`] takes
    /// `self` by value and the token is not `Copy`/`Clone`, so the second
    /// `empty.store(...)` in this test would be a compile error. The test exercises the
    /// only safe path -- clear (or `assume_empty`), then exactly one store.
    #[test]
    fn empty_token_is_consumed_by_store() {
        install_miri_shim();
        let mut field: *mut c_char = ptr::null_mut();
        // SAFETY: `field` is this test's own local member and is NULL.
        let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
        empty.store(dup(c"once"));
        assert!(!field.is_null());
        // SAFETY: the stored block is NUL-terminated.
        assert_eq!(unsafe { CStr::from_ptr(field) }, c"once");
        // SAFETY: `field` holds the stored block.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 9);
        assert!(field.is_null());
    }

    #[test]
    fn assume_empty_stores_without_clearing() {
        install_miri_shim();
        let mut field: *mut c_char = ptr::null_mut();
        // SAFETY: `field` is this test's own local member and is NULL.
        let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
        empty.store(dup(c"beta"));
        assert!(!field.is_null());
        // SAFETY: the stored block is NUL-terminated.
        assert_eq!(unsafe { CStr::from_ptr(field) }, c"beta");

        // SAFETY: `field` is this test's own local member and holds the stored block.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 4);
        assert!(field.is_null());
    }

    #[test]
    fn clear_of_null_is_a_noop_and_yields_an_empty_token() {
        install_miri_shim();
        let mut field: *mut c_char = ptr::null_mut();
        {
            // SAFETY: `field` is this test's own local member and is NULL.
            let mut slot = unsafe { CStrSlot::of(&mut field) };
            let empty = slot.clear(SeamFile::new(FILE), 5);
            empty.store(dup(c"gamma"));
        }
        assert!(!field.is_null());
        {
            // SAFETY: `field` is this test's own local member and holds the stored block.
            let mut slot = unsafe { CStrSlot::of(&mut field) };
            slot.clear(SeamFile::new(FILE), 6);
        }
        assert!(field.is_null());
    }

    /// Regression (GAP 1): safe code cannot install a non-terminated member.
    ///
    /// The enforcement is **type-level**, not a runtime check: [`EmptyCStrSlot::store`]
    /// takes [`OwnedCStr`] by value, and `OwnedCStr`'s only safe-visible construction
    /// operations (`CRYPTO_strdup`/`CRYPTO_strndup`) establish the terminator. The
    /// general `OwnedStr` (`new`/`new_zeroed`, possibly unterminated or zero-length)
    /// is a different type, and there is deliberately no `From<OwnedStr>` conversion,
    /// so `empty.store(owned_str)` is a compile error rather than a silent weakening.
    /// The function-item coercion below is the compile-time witness of that signature;
    /// the runtime half checks that the blocks reachable through this signature really
    /// are terminated.
    #[test]
    fn store_requires_the_terminated_proof_type() {
        install_miri_shim();
        // Compile-time witness: `store`'s parameter is exactly `OwnedCStr`. Passing an
        // `OwnedStr` (e.g. `OwnedStr::new_zeroed(0, ..)`) here does not type-check.
        fn store_proof<'a>(slot: EmptyCStrSlot<'a>, owned: OwnedCStr) {
            slot.store(owned);
        }

        // `dup` and `strndup` both end in the NUL the type promises, including the
        // truncated copy whose source has no NUL within `max`.
        let mut field: *mut c_char = ptr::null_mut();
        // SAFETY: `field` is this test's own local member and is NULL.
        let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
        // SAFETY: the literal is NUL-terminated; `strndup` copies the terminator itself.
        let truncated =
            unsafe { OwnedCStr::strndup(c"abcdef".as_ptr(), 3, SeamFile::new(FILE), 10) }
                .expect("a short strndup must succeed");
        assert_eq!(truncated.as_c_str(), c"abc");
        // SAFETY: the copy owns at least `3` copied bytes plus its terminator.
        let last = unsafe { *truncated.as_ptr().add(3) };
        assert_eq!(last, 0, "the copy ends in its own terminator");
        store_proof(empty, truncated);
        // SAFETY: every constructor reachable through the proof type terminates.
        assert_eq!(unsafe { CStr::from_ptr(field) }, c"abc");
        // SAFETY: `field` holds the stored block.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 11);
        assert!(field.is_null());
    }

    /// Regression (GAP 3): `clear` accepts only a `SeamFile`, so its persisted
    /// coordinate cannot point into a temporary allocation. The compile-time witness
    /// fixes the parameter type; `SeamFile::new` itself demands a `&'static CStr`.
    #[test]
    fn clear_takes_a_static_seam_coordinate() {
        install_miri_shim();
        // Compile-time witness of `clear`'s parameter type. A `*const c_char` (or any
        // non-static pointer) does not type-check here.
        fn clear_with_static_coordinate<'s, 'b>(
            slot: &'b mut CStrSlot<'s>,
            file: SeamFile,
            line: c_int,
        ) -> EmptyCStrSlot<'b> {
            slot.clear(file, line)
        }

        let mut field: *mut c_char = ptr::null_mut();
        // SAFETY: `field` is this test's own local member and is NULL.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        // `FILE` is a `const &'static CStr`; a pointer into a temporary `CString`
        // cannot be turned into a `SeamFile` by any safe constructor.
        let _empty = clear_with_static_coordinate(&mut slot, SeamFile::new(FILE), 12);
    }

    #[test]
    fn store_raw_transfers_an_externally_allocated_block() {
        install_miri_shim();
        // SAFETY: the literal is NUL-terminated and the seam answers a fresh block.
        let raw =
            unsafe { crate::runtime::mem::CRYPTO_strdup(c"delta".as_ptr(), FILE.as_ptr(), 7) };
        assert!(!raw.is_null());
        let mut field: *mut c_char = ptr::null_mut();
        // SAFETY: `field` is NULL; `raw` is the fresh seam block this frame owns.
        let empty = unsafe { CStrSlot::of(&mut field).assume_empty() };
        // SAFETY: `raw` is NULL or a fresh exclusive seam block; the object's
        // destructor (the `clear` below) is its single release.
        unsafe { empty.store_raw(raw) };
        assert_eq!(field, raw);
        // SAFETY: `field` is this test's own local member and holds the transferred block.
        let mut slot = unsafe { CStrSlot::of(&mut field) };
        slot.clear(SeamFile::new(FILE), 8);
        assert!(field.is_null());
    }
}
