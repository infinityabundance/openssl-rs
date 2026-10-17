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
//! An over-free in the authority drives the count negative (the atomic arithmetic itself is
//! defined two's-complement, but the `REF_ASSERT_ISNT(i < 0)` diagnostic is compiled out
//! under `NDEBUG`), and the resulting second teardown is undefined behaviour. Its
//! `CRYPTO_UP_REF` on a zero count increments to one and then reports failure. This
//! protocol deliberately does not reproduce either defect: a `*_free` that
//! observes zero or [`REF_DESTROYING`] while the object's storage is still live is a
//! defined no-op, and `*_up_ref` reports failure without changing the count. At
//! `i32::MAX` the authority's atomic `CRYPTO_UP_REF` wraps the signed count to `i32::MIN`
//! and leaves it there: C11 defines signed atomic fetch-add as two's-complement
//! wraparound, so the atomic profile's result is defined rather than UB, and the public
//! wrapper reports failure because the new value is not greater than one. This
//! implementation uses a checked add: it reports the same public failure (`0`) but leaves
//! the count unchanged instead of wrapping it into this module's destroying sentinel or a
//! negative live count. On a live object with a positive count both operations preserve
//! the authority's observable answer and ordering.

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
        // A live count at `i32::MAX` cannot be incremented by this crate: the authority's
        // C11/GNU atomic path wraps it to `i32::MIN` (defined two's-complement behaviour,
        // C11 7.17.7.5), and its non-atomic fallback's `n + 1` may overflow (undefined
        // behaviour in C). Here a wrap would fabricate the destroying sentinel, so the
        // checked add refuses without modifying the count, matching the zero and destroying
        // answers.
        let Some(next) = n.checked_add(1) else {
            return 0;
        };
        match refs.compare_exchange(n, next, Ordering::Relaxed, Ordering::Relaxed) {
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;
    use std::thread;

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
    fn up_ref_refuses_overflow_without_changing_count() {
        let refs = AtomicI32::new(i32::MAX);
        assert_eq!(up_ref(&refs), 0);
        assert_eq!(refs.load(Ordering::Relaxed), i32::MAX);
    }

    #[test]
    fn up_ref_preserves_positive_count_answer() {
        let refs = AtomicI32::new(1);
        assert_eq!(up_ref(&refs), 1);
        assert_eq!(refs.load(Ordering::Relaxed), 2);
        assert_eq!(up_ref(&refs), 1);
        assert_eq!(refs.load(Ordering::Relaxed), 3);
    }

    /// Every holder that acquired a reference releases it exactly once. With `THREADS`
    /// holders racing on the last release, exactly one observes `Last` and the rest observe
    /// `Remaining`; a later release must observe `Retired`, never a second `Last`.
    ///
    /// This is protocol-level evidence: the object is live, and the count holds `THREADS`
    /// references, but the test does not require a distinct per-thread token before each
    /// `down_ref`. It is not evidence that an arbitrary caller conforms to the C contract.
    #[test]
    fn many_threads_last_release_is_unique() {
        const THREADS: usize = 8;

        let refs = AtomicI32::new(THREADS as i32);
        let barrier = Barrier::new(THREADS);
        let last = AtomicUsize::new(0);
        let remaining = AtomicUsize::new(0);
        let retired = AtomicUsize::new(0);

        thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    barrier.wait();
                    match down_ref(&refs) {
                        DownRef::Last => {
                            last.fetch_add(1, Ordering::Relaxed);
                        }
                        DownRef::Remaining => {
                            remaining.fetch_add(1, Ordering::Relaxed);
                        }
                        DownRef::Retired => {
                            retired.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });

        assert_eq!(
            last.load(Ordering::Acquire),
            1,
            "exactly one caller may claim the last reference"
        );
        assert_eq!(
            remaining.load(Ordering::Acquire),
            THREADS - 1,
            "every other holder releases a non-final reference"
        );
        assert_eq!(
            retired.load(Ordering::Acquire),
            0,
            "no holder may observe a retired object"
        );
        assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
        assert!(matches!(down_ref(&refs), DownRef::Retired));
        assert_eq!(refs.load(Ordering::Relaxed), REF_DESTROYING);
    }

    /// One base reference is held for the whole test. Each worker repeatedly acquires and
    /// releases its own reference; because the base reference is never released until every
    /// worker has joined, no worker may observe `Retired` or a refused increment, and the
    /// base release is the unique `Last`.
    ///
    /// This is protocol-level evidence: a worker calls `up_ref` without previously holding a
    /// reference of its own (the authority permits incrementing any live, non-retiring
    /// object). It is not conforming-caller evidence.
    #[test]
    fn concurrent_increments_and_decrements_conserve_ownership() {
        const THREADS: usize = 8;
        const ITERATIONS: usize = 1_000;

        let refs = AtomicI32::new(1);
        let barrier = Barrier::new(THREADS);

        thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    barrier.wait();
                    for _ in 0..ITERATIONS {
                        assert_eq!(
                            up_ref(&refs),
                            1,
                            "increment with a live base reference must succeed"
                        );
                        assert!(
                            matches!(down_ref(&refs), DownRef::Remaining),
                            "a worker holding the base reference must not retire the object"
                        );
                    }
                });
            }
        });

        assert!(matches!(down_ref(&refs), DownRef::Last));
        assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
        assert!(matches!(down_ref(&refs), DownRef::Retired));
    }

    /// A release racing an increment must end in one of two consistent states: either the
    /// release claimed the object (and the increment is refused), or the increment won (and
    /// the release is non-final). No interleaving may resurrect an object whose last
    /// reference already claimed the sentinel.
    ///
    /// This is a protocol-level sampler, not conforming-caller evidence: it does not require
    /// a thread to hold a reference before `up_ref`, and it does not require both branches to
    /// occur in any run. It requires whichever outcome occurs to satisfy its invariant.
    #[test]
    fn up_ref_racing_last_release_never_resurrects() {
        const ROUNDS: usize = 2_000;

        let mut last_rounds = 0usize;
        let mut increment_rounds = 0usize;

        for _ in 0..ROUNDS {
            let refs = AtomicI32::new(1);
            let barrier = Barrier::new(2);
            // `0` = `Remaining`, `1` = `Last`, `2` = `Retired`; `-1` is "not recorded".
            let down_code = AtomicI32::new(-1);
            let up_result = AtomicI32::new(-1);

            thread::scope(|scope| {
                scope.spawn(|| {
                    barrier.wait();
                    let code = match down_ref(&refs) {
                        DownRef::Remaining => 0,
                        DownRef::Last => 1,
                        DownRef::Retired => 2,
                    };
                    down_code.store(code, Ordering::Release);
                });
                scope.spawn(|| {
                    barrier.wait();
                    up_result.store(up_ref(&refs), Ordering::Release);
                });
            });

            let down_code = down_code.load(Ordering::Acquire);
            let up_result = up_result.load(Ordering::Acquire);

            assert!(
                up_result == 0 || up_result == 1,
                "up_ref must answer exactly 0 or 1"
            );
            assert_ne!(
                down_code, 2,
                "a release starting from one reference cannot observe a retired object"
            );
            if down_code == 1 {
                // The release claimed the sentinel. The increment must be refused, and no
                // later increment may resurrect the object.
                assert_eq!(up_result, 0, "a winning release must refuse the increment");
                assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                assert_eq!(
                    up_ref(&refs),
                    0,
                    "a destroying object must not be resurrected"
                );
                assert!(matches!(down_ref(&refs), DownRef::Retired));
                last_rounds += 1;
            } else {
                // The increment landed first, so the release was non-final and the
                // increment's reference is the one that remains. Releasing it is then the
                // unique `Last`.
                assert_eq!(down_code, 0);
                assert_eq!(up_result, 1, "a non-final release means the increment won");
                assert!(matches!(down_ref(&refs), DownRef::Last));
                assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                assert!(matches!(down_ref(&refs), DownRef::Retired));
                increment_rounds += 1;
            }
        }

        assert_eq!(
            last_rounds + increment_rounds,
            ROUNDS,
            "every round must end in one of the two consistent outcomes"
        );
    }

    /// Both outcome classes are reachable on a live object: a successful increment and a
    /// non-final release, then the unique final release, the sentinel, a refused increment
    /// and a no-op release. Deterministic, so it does not depend on scheduling.
    #[test]
    fn up_ref_down_ref_outcome_classes_are_reachable() {
        let refs = AtomicI32::new(1);

        assert_eq!(up_ref(&refs), 1);
        assert_eq!(refs.load(Ordering::Relaxed), 2);
        assert!(matches!(down_ref(&refs), DownRef::Remaining));
        assert_eq!(refs.load(Ordering::Relaxed), 1);
        assert!(matches!(down_ref(&refs), DownRef::Last));
        assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
        assert_eq!(up_ref(&refs), 0);
        assert!(matches!(down_ref(&refs), DownRef::Retired));
    }
}
