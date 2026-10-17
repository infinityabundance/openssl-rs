//! The reference-count protocol shared by the crate's `CRYPTO_REF_COUNT` gates.
//!
//! The authority's `include/internal/refcount.h` moves `CRYPTO_REF_COUNT` with relaxed
//! fetch-add and release fetch-sub operations and does not distinguish "the count reached
//! zero" from "the object is being torn down". That is sufficient for well-behaved C
//! reference counting, but `SSL_free`, `SSL_CTX_free`, `SSL_SESSION_free` and
//! `X509_STORE_free` all invoke application callbacks from inside the destructor body,
//! after the count reached zero. A callback can re-enter the same `*_free`; with the
//! authority's protocol the re-entrant call observes zero (or a negative count), mistakes
//! itself for the last reference and runs the destructor a second time.
//!
//! This module reserves the otherwise impossible count [`REF_DESTROYING`] (`i32::MIN`)
//! and lets the last releaser claim it with a compare-and-swap before running the body.
//! A re-entrant `*_free` observes the sentinel and returns without teardown, and
//! `*_up_ref` refuses to resurrect a zero or destroying object. The sentinel lives in the
//! existing atomic count, so no field, `#[repr(C)]` layout or exported signature changes.
//!
//! ## Divergence from the authority (§17)
//!
//! The authority's over-free is undefined behaviour (`REF_ASSERT_ISNT(i < 0)` is compiled
//! out under `NDEBUG`) and its `CRYPTO_UP_REF` on a zero count increments to one and then
//! reports failure. This protocol deliberately does not reproduce the UB: a `*_free` that
//! observes zero or [`REF_DESTROYING`] while the object's storage is still live is a
//! defined no-op, and `*_up_ref` reports failure without changing the count. On a live
//! object with a positive count both operations preserve the authority's observable
//! answer and ordering.

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

/// The reserved count that marks an object whose destructor body is running.
///
/// A legitimate reference count is always positive, so `i32::MIN` can never collide with
/// a live count. It is stored in the object's existing `AtomicI32` and keeps the C layout
/// (same size and alignment as the authority's `int`).
pub(crate) const REF_DESTROYING: i32 = i32::MIN;

/// The result of releasing one reference with [`down_ref`].
pub(crate) enum DownRef {
    /// The caller released a non-final reference; the object still has at least one owner.
    Remaining,
    /// The caller won the last reference (the count moved `1 -> REF_DESTROYING`) and is the
    /// only caller permitted to run the destructor body.
    Last,
    /// The count already reached zero, or another caller is destroying the object. The call
    /// is a defined no-op: no destructor body may run.
    Retired,
}

/// `CRYPTO_DOWN_REF` with a destroying state: release one reference.
///
/// The down-ref is a release operation, exactly as the authority's `fetch_sub(1, Release)`.
/// The caller that claims the last reference does so with an `AcqRel`
/// compare-and-swap, which supplies both the release of its own reference and the acquire
/// ordering the authority obtains from `fence(Acquire)` when the count reaches zero.
pub(crate) fn down_ref(refs: &AtomicI32) -> DownRef {
    loop {
        let n = refs.load(Ordering::Acquire);
        // A zero or negative count means the object is already retired; `REF_DESTROYING`
        // is the explicit state installed by the last reference. Neither may be released
        // again.
        if n == REF_DESTROYING || n <= 0 {
            return DownRef::Retired;
        }
        if n == 1 {
            match refs.compare_exchange(1, REF_DESTROYING, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return DownRef::Last,
                // Another thread changed the count between the load and the swap; re-read
                // and retry so the racing reference is accounted for.
                Err(_) => continue,
            }
        }
        match refs.compare_exchange(n, n - 1, Ordering::Release, Ordering::Acquire) {
            Ok(_) => return DownRef::Remaining,
            Err(_) => continue,
        }
    }
}

/// `CRYPTO_UP_REF` that refuses a zero, negative or destroying count.
///
/// A live object always has a positive count, for which this returns the authority's
/// answer (`1`, because the new count is greater than one) and uses the authority's
/// relaxed ordering. Zero and [`REF_DESTROYING`] are never incremented: the call reports
/// failure (`0`) without resurrecting an object that is being, or has been, retired.
pub(crate) fn up_ref(refs: &AtomicI32) -> c_int {
    loop {
        let n = refs.load(Ordering::Relaxed);
        if n == REF_DESTROYING || n <= 0 {
            return 0;
        }
        match refs.compare_exchange(n, n + 1, Ordering::Relaxed, Ordering::Relaxed) {
            // `compare_exchange` answers the *previous* value. A positive `n` makes the new
            // count greater than one, which is the authority's `1` answer.
            Ok(_) => return 1,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_destroying_never_matches_a_live_count() {
        let live = AtomicI32::new(1);
        assert_ne!(live.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn down_ref_claims_last_reference_then_retires() {
        let refs = AtomicI32::new(2);
        assert!(matches!(down_ref(&refs), DownRef::Remaining));
        assert!(matches!(down_ref(&refs), DownRef::Last));
        assert_eq!(refs.load(Ordering::Relaxed), REF_DESTROYING);
        // A re-entrant release must not produce a second destructor.
        assert!(matches!(down_ref(&refs), DownRef::Retired));
        assert_eq!(refs.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn up_ref_refuses_zero_and_destroying() {
        let zero = AtomicI32::new(0);
        assert_eq!(up_ref(&zero), 0);
        assert_eq!(zero.load(Ordering::Relaxed), 0);

        let destroying = AtomicI32::new(REF_DESTROYING);
        assert_eq!(up_ref(&destroying), 0);
        assert_eq!(destroying.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn up_ref_preserves_positive_count_answer() {
        let refs = AtomicI32::new(1);
        assert_eq!(up_ref(&refs), 1);
        assert_eq!(refs.load(Ordering::Relaxed), 2);
        assert_eq!(up_ref(&refs), 1);
        assert_eq!(refs.load(Ordering::Relaxed), 3);
    }
}
