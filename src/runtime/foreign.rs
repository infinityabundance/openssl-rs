//! Ownership of a foreign object a frame created with a `*_new`.
//!
//! The two `ssl/statem` modules previously carried byte-identical copies of this
//! abstraction. They are the same owner with the same destructor contract (the
//! object's own `*_free`, exactly once), so the type lives here and both modules
//! import it. This is deliberately **not** [`crate::runtime::bio::owned::OwnedCtx`]:
//! that owner allocates and releases a `CRYPTO_zalloc` block through the allocator
//! seam and runs a `CtxDestroy` body, whereas this one wraps an object some other
//! constructor produced and delegates its complete release to that object's own
//! `*_free`. Neither the allocator coordinate nor the zero-validity claim transfers.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr::NonNull;

/// A foreign object this frame created (a `*_new`) whose single release is the
/// object's own `*_free`.
///
/// # Safety
///
/// An implementer takes on the contract because [`OwnedCtx`]'s `Drop` runs the
/// implementer's body through a safe interface:
///
/// * **release** — `free_on_drop(ptr)` runs the object's own `*_free` — the
///   **complete** release of the object its matching `*_new` created — **exactly
///   once**, for a live object this frame owns one reference to. It must be the
///   `*_free` matching that `*_new`, and it is the object's single release: the
///   frame never calls the free by hand.
///
/// There is **no** zero-validity claim: the handle wraps a `*_new` answer, not a
/// `CRYPTO_zalloc` block, so no all-zero value is relied on as a valid `Self`.
pub(crate) unsafe trait FreeOnDrop: Sized {
    /// The authority's own `*_free` for this object.
    ///
    /// # Safety
    /// `ptr` is a live object of this type, owned here and not yet released.
    unsafe fn free_on_drop(ptr: *mut Self);
}

/// An owned foreign object: a `*_new` this frame called whose `Drop` runs the
/// object's own `*_free`. The object keeps its layout and its stable address; only
/// its *ownership* is this handle, so the constructor's refusal and every early
/// return release what they built instead of calling the free function by hand.
pub(crate) struct OwnedCtx<T: FreeOnDrop> {
    ptr: NonNull<T>,
}

impl<T: FreeOnDrop> OwnedCtx<T> {
    /// Own a `*_new` answer, or `None` when it answered NULL.
    ///
    /// # Safety
    ///
    /// `ptr` is either NULL, or the answer of the `*_new` whose matching `*_free` is
    /// `T::free_on_drop`; in the latter case:
    ///
    /// * **provenance** — it came from that constructor on this crate's allocator
    ///   seam, not from a sub-pointer, an interior pointer, or another allocator;
    /// * **identity and extent** — it addresses the whole allocation the constructor
    ///   returned, of at least `size_of::<T>()` bytes and aligned for `T`;
    /// * **initialization** — it is a live, fully constructed object valid for the
    ///   release `T::free_on_drop` performs; the handle claims no zero-validity, so
    ///   an all-zero block is not accepted merely because it is zeroed;
    /// * **exclusive ownership** — no other handle, field, or frame will release it:
    ///   this handle's `Drop`, or the `into_raw` transfer it makes, is the object's
    ///   single release.
    pub(crate) unsafe fn new(ptr: *mut T) -> Option<OwnedCtx<T>> {
        NonNull::new(ptr).map(|ptr| OwnedCtx { ptr })
    }

    /// The object's stable address, for the raw calls the frame makes over it.
    pub(crate) fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Hand the object to a stable slot (the authority's field assignment), giving up
    /// ownership so the slot's own release is the only one.
    pub(crate) fn into_raw(self) -> *mut T {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl<T: FreeOnDrop> Drop for OwnedCtx<T> {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a live object this frame created and has not
        // released; `Drop` runs once, so `free_on_drop` is its single release.
        unsafe { T::free_on_drop(self.ptr.as_ptr()) }
    }
}

/// `EVP_MD_CTX_free` is the `EVP_MD_CTX` block's own release.
// SAFETY: release holds: `free_on_drop` runs `EVP_MD_CTX_free`, the `*_free` matching
// `EVP_MD_CTX_new`, exactly once on a live `EVP_MD_CTX` this frame owns; it is the
// object's single release. No zero-validity claim: the handle wraps a constructor answer.
unsafe impl FreeOnDrop for crate::evp::digest::EvpMdCtx {
    /// # Safety
    /// `ptr` is a live `EVP_MD_CTX` this frame owns and has not released.
    unsafe fn free_on_drop(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the contract and `EVP_MD_CTX_free` is its release.
        unsafe { crate::evp::digest::EVP_MD_CTX_free(ptr) }
    }
}

/// `EVP_CIPHER_CTX_free` is the `EVP_CIPHER_CTX` block's own release.
// SAFETY: release holds: `free_on_drop` runs `EVP_CIPHER_CTX_free`, the `*_free` matching
// `EVP_CIPHER_CTX_new`, exactly once on a live `EVP_CIPHER_CTX` this frame owns; it is the
// object's single release. No zero-validity claim: the handle wraps a constructor answer.
unsafe impl FreeOnDrop for crate::evp::cipher_ctx::EvpCipherCtx {
    /// # Safety
    /// `ptr` is a live `EVP_CIPHER_CTX` this frame owns and has not released.
    unsafe fn free_on_drop(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the contract and `EVP_CIPHER_CTX_free` is its release.
        unsafe { crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ptr) }
    }
}

/// `EVP_PKEY_free` is the `EVP_PKEY` block's own release.
// SAFETY: release holds: `free_on_drop` runs `EVP_PKEY_free`, the `*_free` matching
// `EVP_PKEY_new`, exactly once on a live `EVP_PKEY` this frame owns; it is the object's
// single release. No zero-validity claim: the handle wraps a constructor answer.
unsafe impl FreeOnDrop for crate::evp::pkey::EvpPkey {
    /// # Safety
    /// `ptr` is a live `EVP_PKEY` this frame owns and has not released.
    unsafe fn free_on_drop(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the contract and `EVP_PKEY_free` is its release.
        unsafe { crate::evp::pkey::EVP_PKEY_free(ptr) }
    }
}

/// `SSL_SESSION_free` is the `SSL_SESSION` block's own release.
// SAFETY: release holds: `free_on_drop` runs `SSL_SESSION_free`, the `*_free` matching the
// `SSL_SESSION` constructor, exactly once on a live session this frame owns; it is the
// object's single release. No zero-validity claim: the handle wraps a constructor answer.
unsafe impl FreeOnDrop for crate::ssl::ssl_lib::SslSession {
    /// # Safety
    /// `ptr` is a live `SSL_SESSION` this frame owns and has not released.
    unsafe fn free_on_drop(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the contract and `SSL_SESSION_free` is its release.
        unsafe { crate::ssl::ssl_sess::SSL_SESSION_free(ptr) }
    }
}

/// `HMAC_CTX_free` is the `HMAC_CTX` block's own release.
// SAFETY: release holds: `free_on_drop` runs `HMAC_CTX_free`, the `*_free` matching the
// `HMAC_CTX` constructor, exactly once on a live context this frame owns; it is the
// object's single release. No zero-validity claim: the handle wraps a constructor answer.
unsafe impl FreeOnDrop for crate::mac::hmac::HmacCtx {
    /// # Safety
    /// `ptr` is a live `HMAC_CTX` this frame owns and has not released.
    unsafe fn free_on_drop(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the contract and `HMAC_CTX_free` is its release.
        unsafe { crate::mac::hmac::HMAC_CTX_free(ptr) }
    }
}
