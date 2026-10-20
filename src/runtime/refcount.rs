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

/// The atomic operations the protocol below relies on.
///
/// This is a crate-private seam so the `cfg(loom)` harness can run the *same*
/// protocol over modelled atomics. Every product and ordinary-test build has
/// exactly one implementor, [`core::sync::atomic::AtomicI32`], and the generic
/// instantiation compiles to the same load/compare-exchange calls as a direct
/// call would. It is test instrumentation, not an extension point.
pub(crate) trait RefAtomic {
    /// Atomically read the count with `order`.
    fn load_ref(&self, order: Ordering) -> i32;

    /// Atomically replace `current` with `new` when the count still equals
    /// `current`, answering the observed value.
    fn compare_exchange_ref(
        &self,
        current: i32,
        new: i32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<i32, i32>;
}

impl RefAtomic for AtomicI32 {
    fn load_ref(&self, order: Ordering) -> i32 {
        self.load(order)
    }

    fn compare_exchange_ref(
        &self,
        current: i32,
        new: i32,
        success: Ordering,
        failure: Ordering,
    ) -> Result<i32, i32> {
        self.compare_exchange(current, new, success, failure)
    }
}

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
///
/// # Safety
///
/// The caller must own exactly one reference to the object whose count `refs` is, and must
/// establish all of the following:
///
/// - the object's storage (and therefore `refs`) is live, and remains live until this call
///   returns;
/// - no other caller releases this same reference (each reference is released exactly once);
/// - if the result is [`DownRef::Last`], this caller is the unique destructor runner: it may
///   run the destructor body exactly once and must not use the object afterwards, except
///   that the storage stays readable until the body has finished and is released.
///
/// `DownRef::Retired` covers a re-entrant release of an already-retired object; it is not a
/// licence to call this function on an object the caller does not own.
pub(crate) unsafe fn down_ref<A: RefAtomic>(refs: &A) -> DownRef {
    loop {
        let n = refs.load_ref(Ordering::Acquire);
        // A zero or negative count means the object is already retired; `REF_DESTROYING`
        // is the explicit state installed by the last reference. Neither may be released
        // again.
        if n == REF_DESTROYING || n <= 0 {
            return DownRef::Retired;
        }
        if n == 1 {
            match refs.compare_exchange_ref(1, REF_DESTROYING, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return DownRef::Last,
                // Another thread changed the count between the load and the swap; re-read
                // and retry so the racing reference is accounted for.
                Err(_) => continue,
            }
        }
        match refs.compare_exchange_ref(n, n - 1, Ordering::Release, Ordering::Acquire) {
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
///
/// # Safety
///
/// The caller must establish all of the following:
///
/// - a published positive count exists: the object's constructor has published a count of
///   at least one, and that publication is visible to this call (a count still being
///   initialised, or one already retired, is not a live object);
/// - the caller holds a reference, or acts on behalf of an owner whose reference will not
///   be released for the duration of the call (as `SSL_dup` does for its caller);
/// - the object's storage (and therefore `refs`) is live for the duration of the call.
///
/// On success the caller owns exactly one new reference and is responsible for releasing it
/// exactly once through [`down_ref`] or the object's `*_free` path. On refusal the caller
/// acquires nothing, so it owes no release.
pub(crate) unsafe fn up_ref<A: RefAtomic>(refs: &A) -> c_int {
    loop {
        let n = refs.load_ref(Ordering::Relaxed);
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
        match refs.compare_exchange_ref(n, next, Ordering::Relaxed, Ordering::Relaxed) {
            // `compare_exchange` answers the *previous* value. A positive `n` makes the new
            // count greater than one, which is the authority's `1` answer.
            Ok(_) => return 1,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod family_reentrancy_tests {
    //! Re-entrancy evidence for the families whose destructor bodies invoke
    //! application/provider callbacks. Each callback re-enters the same `*_free` from the
    //! ex-data teardown; the shared destroying sentinel must make that a defined no-op.

    use core::ffi::{c_int, c_long, c_void};
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::dh::object::{DH_free, DH_new, DH_set_ex_data};
    use crate::dh::Dh;
    use crate::dsa::object::{DSA_free, DSA_new, DSA_set_ex_data};
    use crate::dsa::Dsa;
    use crate::ec::key::{EC_KEY_free, EC_KEY_new};
    use crate::ec::lib::EC_KEY_set_ex_data;
    use crate::ec::EcKey;
    use crate::evp::pkey::EvpPkey;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_ex_data};
    use crate::rsa::object::{RSA_free, RSA_new, RSA_set_ex_data};
    use crate::rsa::Rsa;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{
        BIO_free, BIO_new, BIO_set_callback_ex, BIO_set_ex_data, Bio, BioCallbackExFn, BIO_CB_FREE,
    };
    use crate::runtime::ex_data::{
        CRYPTO_get_ex_new_index, CryptoExData, CRYPTO_EX_INDEX_BIO, CRYPTO_EX_INDEX_DH,
        CRYPTO_EX_INDEX_DSA, CRYPTO_EX_INDEX_EC_KEY, CRYPTO_EX_INDEX_EVP_PKEY, CRYPTO_EX_INDEX_RSA,
    };

    type FreeCb = unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *mut CryptoExData,
        c_int,
        c_long,
        *mut c_void,
    );

    macro_rules! reentry_test {
        ($name:ident, $target:ident, $calls:ident, $cb:ident, $class:expr, $new:path, $set:path,
         $free:path, $ty:ty) => {
            static $target: AtomicUsize = AtomicUsize::new(0);
            static $calls: AtomicUsize = AtomicUsize::new(0);

            unsafe extern "C" fn $cb(
                parent: *mut c_void,
                _ptr: *mut c_void,
                _ad: *mut CryptoExData,
                _idx: c_int,
                _argl: c_long,
                _argp: *mut c_void,
            ) {
                let target = $target.load(Ordering::SeqCst) as *mut $ty;
                if !target.is_null() && parent.cast::<$ty>() == target {
                    $calls.fetch_add(1, Ordering::SeqCst);
                    // SAFETY: the target is the object whose ex-data is being torn down and
                    // whose block is still allocated here.
                    unsafe { $free(target) };
                }
            }

            #[test]
            fn $name() {
                let idx = CRYPTO_get_ex_new_index(
                    $class,
                    0,
                    ptr::null_mut(),
                    None,
                    None,
                    Some($cb as FreeCb),
                );
                assert!(idx >= 1, "an ex-data index must be available");
                // SAFETY: constructors and setters take live objects; `free` owns the only
                // reference.
                unsafe {
                    let p = $new();
                    assert!(!p.is_null());
                    assert_eq!($set(p, idx, ptr::dangling_mut::<c_void>()), 1);
                    $target.store(p as usize, Ordering::SeqCst);
                    $calls.store(0, Ordering::SeqCst);
                    $free(p);
                }
                $target.store(0, Ordering::SeqCst);
                assert_eq!(
                    $calls.load(Ordering::SeqCst),
                    1,
                    "the callback ran exactly once"
                );
            }
        };
    }

    reentry_test!(
        dh_reentry_is_a_noop,
        DH_TARGET,
        DH_CALLS,
        dh_free_cb,
        CRYPTO_EX_INDEX_DH,
        DH_new,
        DH_set_ex_data,
        DH_free,
        Dh
    );
    reentry_test!(
        dsa_reentry_is_a_noop,
        DSA_TARGET,
        DSA_CALLS,
        dsa_free_cb,
        CRYPTO_EX_INDEX_DSA,
        DSA_new,
        DSA_set_ex_data,
        DSA_free,
        Dsa
    );
    reentry_test!(
        rsa_reentry_is_a_noop,
        RSA_TARGET,
        RSA_CALLS,
        rsa_free_cb,
        CRYPTO_EX_INDEX_RSA,
        RSA_new,
        RSA_set_ex_data,
        RSA_free,
        Rsa
    );
    reentry_test!(
        ec_key_reentry_is_a_noop,
        EC_TARGET,
        EC_CALLS,
        ec_free_cb,
        CRYPTO_EX_INDEX_EC_KEY,
        EC_KEY_new,
        EC_KEY_set_ex_data,
        EC_KEY_free,
        EcKey
    );
    reentry_test!(
        evp_pkey_reentry_is_a_noop,
        PKEY_TARGET,
        PKEY_CALLS,
        pkey_free_cb,
        CRYPTO_EX_INDEX_EVP_PKEY,
        EVP_PKEY_new,
        EVP_PKEY_set_ex_data,
        EVP_PKEY_free,
        EvpPkey
    );

    static BIO_TARGET: AtomicUsize = AtomicUsize::new(0);
    static BIO_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn bio_free_cb(
        parent: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        _idx: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) {
        let target = BIO_TARGET.load(Ordering::SeqCst) as *mut Bio;
        if !target.is_null() && parent.cast::<Bio>() == target {
            BIO_CALLS.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the target is the BIO whose ex-data is being torn down and whose block
            // is still allocated here.
            let _ = unsafe { BIO_free(target) };
        }
    }

    #[test]
    fn bio_reentry_is_a_noop() {
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_BIO,
            0,
            ptr::null_mut(),
            None,
            None,
            Some(bio_free_cb as FreeCb),
        );
        assert!(idx >= 1);
        // SAFETY: `BIO_s_mem` is a static method table and `BIO_new` takes a reference to it.
        unsafe {
            let b = BIO_new(BIO_s_mem());
            assert!(!b.is_null());
            assert_eq!(BIO_set_ex_data(b, idx, ptr::dangling_mut::<c_void>()), 1);
            BIO_TARGET.store(b as usize, Ordering::SeqCst);
            BIO_CALLS.store(0, Ordering::SeqCst);
            assert_eq!(BIO_free(b), 1);
        }
        BIO_TARGET.store(0, Ordering::SeqCst);
        assert_eq!(BIO_CALLS.load(Ordering::SeqCst), 1);
    }

    static BIO_CB_TARGET: AtomicUsize = AtomicUsize::new(0);
    static BIO_CB_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// The modern BIO callback sees `BIO_CB_FREE` with the count already claimed by the
    /// destroying sentinel. Re-entering `BIO_free` from it must be a defined no-op.
    unsafe extern "C" fn bio_free_callback(
        bio: *mut Bio,
        oper: c_int,
        _argp: *const core::ffi::c_char,
        _len: usize,
        _argi: c_int,
        _argl: c_long,
        _ret: c_int,
        _processed: *mut usize,
    ) -> c_long {
        let target = BIO_CB_TARGET.load(Ordering::SeqCst) as *mut Bio;
        if oper == BIO_CB_FREE && !target.is_null() && bio == target {
            BIO_CB_CALLS.fetch_add(1, Ordering::SeqCst);
            // SAFETY: `bio` is the BIO whose free callback is running; the block is still
            // allocated here.
            let _ = unsafe { BIO_free(bio) };
        }
        1
    }

    #[test]
    fn bio_free_callback_reentry_is_a_noop() {
        // SAFETY: `BIO_s_mem` is a static method table and this test owns the BIO.
        unsafe {
            let b = BIO_new(BIO_s_mem());
            assert!(!b.is_null());
            let cb: BioCallbackExFn = bio_free_callback;
            BIO_set_callback_ex(b, Some(cb));
            BIO_CB_TARGET.store(b as usize, Ordering::SeqCst);
            BIO_CB_CALLS.store(0, Ordering::SeqCst);
            assert_eq!(BIO_free(b), 1);
            BIO_CB_TARGET.store(0, Ordering::SeqCst);
            assert_eq!(BIO_CB_CALLS.load(Ordering::SeqCst), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;
    use std::thread;

    // SAFETY (every `up_ref`/`down_ref` call in this module): each test owns the
    // `AtomicI32` it passes, the storage outlives every call, the count is initialised
    // to the number of references the test models, and every modelled reference is
    // released exactly once. These are protocol-level tests, not conforming-C-caller
    // evidence.

    #[test]
    fn ref_destroying_never_matches_a_live_count() {
        let live = AtomicI32::new(1);
        assert_ne!(live.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn down_ref_claims_last_reference_then_retires() {
        let refs = AtomicI32::new(2);
        // SAFETY: the test owns both modelled references and releases each once; the
        // storage outlives all three calls (the last is the defined re-entrant no-op).
        unsafe {
            assert!(matches!(down_ref(&refs), DownRef::Remaining));
            assert!(matches!(down_ref(&refs), DownRef::Last));
            assert_eq!(refs.load(Ordering::Relaxed), REF_DESTROYING);
            // A re-entrant release must not produce a second destructor.
            assert!(matches!(down_ref(&refs), DownRef::Retired));
        }
        assert_eq!(refs.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn up_ref_refuses_zero_and_destroying() {
        let zero = AtomicI32::new(0);
        // SAFETY: the storage is live for both calls. The zero and destroying counts
        // model refusals: no reference is acquired and no release is owed.
        unsafe {
            assert_eq!(up_ref(&zero), 0);
        }
        assert_eq!(zero.load(Ordering::Relaxed), 0);

        let destroying = AtomicI32::new(REF_DESTROYING);
        // SAFETY: as above; a destroying count is live storage but not a live object.
        unsafe {
            assert_eq!(up_ref(&destroying), 0);
        }
        assert_eq!(destroying.load(Ordering::Relaxed), REF_DESTROYING);
    }

    #[test]
    fn up_ref_refuses_overflow_without_changing_count() {
        let refs = AtomicI32::new(i32::MAX);
        // SAFETY: the test owns the one live reference; the refused increment acquires
        // nothing, so no release is owed.
        unsafe {
            assert_eq!(up_ref(&refs), 0);
        }
        assert_eq!(refs.load(Ordering::Relaxed), i32::MAX);
    }

    #[test]
    fn up_ref_preserves_positive_count_answer() {
        let refs = AtomicI32::new(1);
        // SAFETY: the test owns the base reference and then the two acquired references;
        // the storage outlives both calls.
        unsafe {
            assert_eq!(up_ref(&refs), 1);
        }
        assert_eq!(refs.load(Ordering::Relaxed), 2);
        // SAFETY: the caller acts for the base owner and acquires a second reference.
        unsafe {
            assert_eq!(up_ref(&refs), 1);
        }
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
                    // SAFETY: this thread owns exactly one of the `THREADS` modelled
                    // references, and the scoped thread keeps `refs` live across the call.
                    let outcome = unsafe { down_ref(&refs) };
                    match outcome {
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
        // SAFETY: a thread still owns no reference now, but the storage is live; this
        // models a re-entrant release, which must observe `Retired`.
        unsafe {
            assert!(matches!(down_ref(&refs), DownRef::Retired));
        }
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
                        // SAFETY: the base reference is held for the whole test, so a
                        // live owner exists; the worker releases only the reference it
                        // just acquired. The scope keeps `refs` live.
                        let took = unsafe { up_ref(&refs) };
                        assert_eq!(took, 1, "increment with a live base reference must succeed");
                        // SAFETY: the worker releases only the reference it just acquired,
                        // while the base reference keeps the object live.
                        let outcome = unsafe { down_ref(&refs) };
                        assert!(
                            matches!(outcome, DownRef::Remaining),
                            "a worker holding the base reference must not retire the object"
                        );
                    }
                });
            }
        });

        // SAFETY: the test owns the base reference; releasing it is the unique final
        // release, and the follow-up models a re-entrant no-op on live storage.
        unsafe {
            assert!(matches!(down_ref(&refs), DownRef::Last));
            assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
            assert!(matches!(down_ref(&refs), DownRef::Retired));
        }
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
                    // SAFETY: this thread owns the single reference released here; the
                    // scoped thread keeps `refs` live across the call.
                    let code = match unsafe { down_ref(&refs) } {
                        DownRef::Remaining => 0,
                        DownRef::Last => 1,
                        DownRef::Retired => 2,
                    };
                    down_code.store(code, Ordering::Release);
                });
                scope.spawn(|| {
                    barrier.wait();
                    // SAFETY: the release racing this increment models an existing owner
                    // (the initial reference); the increment, if granted, is the one this
                    // thread owns. The scope keeps `refs` live.
                    let took = unsafe { up_ref(&refs) };
                    up_result.store(took, Ordering::Release);
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
                // SAFETY: the storage is live and holds the destroying sentinel; a
                // refused increment acquires nothing and the release is a no-op.
                unsafe {
                    assert_eq!(
                        up_ref(&refs),
                        0,
                        "a destroying object must not be resurrected"
                    );
                    assert!(matches!(down_ref(&refs), DownRef::Retired));
                }
                last_rounds += 1;
            } else {
                // The increment landed first, so the release was non-final and the
                // increment's reference is the one that remains. Releasing it is then the
                // unique `Last`.
                assert_eq!(down_code, 0);
                assert_eq!(up_result, 1, "a non-final release means the increment won");
                // SAFETY: the increment won, so this thread owns the surviving reference;
                // the follow-up models a re-entrant no-op on live storage.
                unsafe {
                    assert!(matches!(down_ref(&refs), DownRef::Last));
                    assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                    assert!(matches!(down_ref(&refs), DownRef::Retired));
                }
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

        // SAFETY: the test owns the base reference; each successful increment is owned
        // and released exactly once, and the storage outlives every call.
        unsafe {
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
}

/// Loom model checking of the *real* protocol over modelled atomics.
///
/// Run with `RUSTFLAGS="--cfg loom" cargo test --lib runtime::refcount::loom_tests`.
/// The module is absent from ordinary builds, and the crate's other tests keep using
/// `core::sync::atomic::AtomicI32` through the same generic functions.
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use loom::sync::atomic::AtomicI32;
    use loom::sync::Arc;
    use loom::thread;

    impl RefAtomic for AtomicI32 {
        fn load_ref(&self, order: Ordering) -> i32 {
            self.load(order)
        }

        fn compare_exchange_ref(
            &self,
            current: i32,
            new: i32,
            success: Ordering,
            failure: Ordering,
        ) -> Result<i32, i32> {
            self.compare_exchange(current, new, success, failure)
        }
    }

    fn code(outcome: DownRef) -> i32 {
        match outcome {
            DownRef::Remaining => 0,
            DownRef::Last => 1,
            DownRef::Retired => 2,
        }
    }

    /// A base reference held across two workers that each acquire and release one
    /// reference: the base release is the unique `Last`, and no worker may retire
    /// the object while the base reference is held.
    #[test]
    fn loom_base_reference_yields_one_last() {
        loom::model(|| {
            let refs = Arc::new(AtomicI32::new(1));
            let mut workers = Vec::new();
            for _ in 0..2 {
                let refs = refs.clone();
                workers.push(thread::spawn(move || {
                    // SAFETY: the test owns this reference and the base reference keeps
                    // the object live for the duration of both calls.
                    assert_eq!(unsafe { up_ref(&*refs) }, 1);
                    // SAFETY: only the reference just acquired is released here.
                    assert!(matches!(unsafe { down_ref(&*refs) }, DownRef::Remaining));
                }));
            }
            for worker in workers {
                assert!(worker.join().is_ok());
            }
            // SAFETY: the test owns the remaining base reference; the final release
            // claims the sentinel and the extra call models a re-entrant free.
            unsafe {
                assert!(matches!(down_ref(&*refs), DownRef::Last));
                assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                assert!(matches!(down_ref(&*refs), DownRef::Retired));
            }
        });
    }

    /// The release of a single reference races an increment. Either the release wins
    /// (and the increment is refused) or the increment wins (and the release is
    /// non-final). No execution may resurrect the object after the sentinel is set.
    #[test]
    fn loom_last_release_race_never_resurrects() {
        loom::model(|| {
            let refs = Arc::new(AtomicI32::new(1));
            let release = {
                let refs = refs.clone();
                // SAFETY: this thread owns the single initial reference.
                thread::spawn(move || code(unsafe { down_ref(&*refs) }))
            };
            let increment = {
                let refs = refs.clone();
                // SAFETY: the increment acts while the initial owner exists; if it
                // succeeds it acquires the reference this thread then releases below.
                thread::spawn(move || unsafe { up_ref(&*refs) })
            };
            let down_code = release.join().unwrap_or(-1);
            let up_result = increment.join().unwrap_or(-1);

            assert_ne!(down_code, 2, "the release cannot observe a retired object");
            assert!(
                up_result == 0 || up_result == 1,
                "up_ref must answer exactly 0 or 1"
            );
            if down_code == 1 {
                assert_eq!(up_result, 0, "a winning release must refuse the increment");
                assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                // SAFETY: the storage is live but the object is destroying; both calls
                // are defined no-ops under the protocol.
                unsafe {
                    assert_eq!(up_ref(&*refs), 0);
                    assert!(matches!(down_ref(&*refs), DownRef::Retired));
                }
            } else {
                assert_eq!(down_code, 0, "the release must be non-final");
                assert_eq!(up_result, 1, "a non-final release means the increment won");
                // SAFETY: the increment's reference is the surviving one; releasing it
                // is the unique final release, and the extra call models re-entrancy.
                unsafe {
                    assert!(matches!(down_ref(&*refs), DownRef::Last));
                    assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
                    assert!(matches!(down_ref(&*refs), DownRef::Retired));
                }
            }
        });
    }

    /// The sentinel absorbs a second release of the same count: exactly one `Last`
    /// and one `Retired`, never two destructor runners.
    #[test]
    fn loom_sentinel_absorbs_a_second_release() {
        loom::model(|| {
            let refs = Arc::new(AtomicI32::new(1));
            let first = {
                let refs = refs.clone();
                // SAFETY: the count models a reference held by this caller.
                thread::spawn(move || code(unsafe { down_ref(&*refs) }))
            };
            let second = {
                let refs = refs.clone();
                // SAFETY: the storage stays live; the call models a re-entrant free.
                thread::spawn(move || code(unsafe { down_ref(&*refs) }))
            };
            let mut codes = [first.join().unwrap_or(-1), second.join().unwrap_or(-1)];
            codes.sort_unstable();
            assert_eq!(codes, [1, 2], "one Last and one Retired, never two Lasts");
            assert_eq!(refs.load(Ordering::Acquire), REF_DESTROYING);
        });
    }

    /// `i32::MAX` is refused without changing the count and without wrapping into
    /// the destroying sentinel.
    #[test]
    fn loom_up_ref_refuses_i32_max() {
        loom::model(|| {
            let refs = AtomicI32::new(i32::MAX);
            // SAFETY: the storage is live; a refused increment acquires nothing.
            unsafe {
                assert_eq!(up_ref(&refs), 0);
            }
            assert_eq!(refs.load(Ordering::Relaxed), i32::MAX);
        });
    }
}

/// Exhaustive, bounded interleaving model of the refcount protocol.
///
/// This mirrors [`up_ref`] and [`down_ref`] over plain integers and enumerates every
/// interleaving of their atomic micro-steps with a deterministic step scheduler. It is
/// a model of the algorithm, not a proof about the compiled code; the `loom_tests`
/// module runs the same algorithm over modelled atomics. The three mutants are
/// negative controls: each is selected through the same harness and must make it
/// report a violation.
#[cfg(test)]
mod exhaustive_model_tests {
    use super::REF_DESTROYING;
    use std::collections::BTreeMap;

    /// A bounded run; caps livelock exploration and is reported if reached.
    const MAX_STEPS: usize = 128;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Proto {
        Real,
        /// (a) Read-modify-write without a compare-and-swap: lost updates.
        NonAtomicRmw,
        /// (b) `n + 1` without the zero/sentinel guard: resurrection and wrap.
        UncheckedUp,
        /// (c) Free on any zero/negative instead of claiming the sentinel.
        ZeroFree,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Up,
        DownOwned,
        DownReentrant,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Phase {
        Load,
        Commit,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Violation {
        MultipleLast,
        LastWithOutstandingRefs,
        Resurrection,
        UpProducedNonPositive,
        NegativeLiveCount,
        ReentrantDownClaimedLast,
        ReentrantDownReleasedReference,
        OwnedDownObservedRetired,
        OutstandingUnderflow,
        LastCountMismatch,
        FinalCountMismatch,
        ConservationMismatch,
        OutstandingAtEnd,
        StuckState,
        StepBoundExceeded,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DownResult {
        Remaining,
        Last,
    }

    const UP_THEN_DOWN: &[Op] = &[Op::Up, Op::DownOwned];
    const DOWN_OWNED: &[Op] = &[Op::DownOwned];
    const DOWN_REENTRANT: &[Op] = &[Op::DownReentrant];
    const UP_ONLY: &[Op] = &[Op::Up];

    #[derive(Clone, Debug)]
    struct Actor {
        program: &'static [Op],
        pc: usize,
        phase: Phase,
        loaded: i32,
        loaded_retired: bool,
        held: bool,
        done: bool,
        eligible_after_last: bool,
        eligible_after_others_done: bool,
    }

    fn actor(
        program: &'static [Op],
        held: bool,
        eligible_after_last: bool,
        eligible_after_others_done: bool,
    ) -> Actor {
        Actor {
            program,
            pc: 0,
            phase: Phase::Load,
            loaded: 0,
            loaded_retired: false,
            held,
            done: false,
            eligible_after_last,
            eligible_after_others_done,
        }
    }

    struct Scenario {
        name: &'static str,
        initial: i32,
        actors: Vec<Actor>,
        expect_lasts: u32,
        expect_final_count: i32,
    }

    fn scenarios() -> Vec<Scenario> {
        vec![
            Scenario {
                name: "base-plus-two-workers",
                initial: 1,
                actors: vec![
                    actor(UP_THEN_DOWN, false, false, false),
                    actor(UP_THEN_DOWN, false, false, false),
                    actor(DOWN_OWNED, true, false, true),
                ],
                expect_lasts: 1,
                expect_final_count: REF_DESTROYING,
            },
            Scenario {
                name: "last-release-race",
                initial: 1,
                actors: vec![
                    actor(DOWN_OWNED, true, false, false),
                    actor(UP_THEN_DOWN, false, false, false),
                ],
                expect_lasts: 1,
                expect_final_count: REF_DESTROYING,
            },
            Scenario {
                name: "reentrant-double-down",
                initial: 1,
                actors: vec![
                    actor(DOWN_OWNED, true, false, false),
                    actor(DOWN_REENTRANT, false, true, false),
                ],
                expect_lasts: 1,
                expect_final_count: REF_DESTROYING,
            },
            Scenario {
                name: "i32-max-refusal",
                initial: i32::MAX,
                actors: vec![actor(UP_ONLY, false, false, false)],
                expect_lasts: 0,
                expect_final_count: i32::MAX,
            },
        ]
    }

    #[derive(Clone, Debug)]
    struct Sim {
        count: i32,
        outstanding: i32,
        lasts: u32,
        ups: u32,
        downs: u32,
        sentinel_installed: bool,
        steps: usize,
        violations: BTreeMap<Violation, usize>,
    }

    #[derive(Default)]
    struct Report {
        executions: usize,
        violations: BTreeMap<Violation, usize>,
    }

    impl Report {
        fn count(&self, violation: Violation) -> usize {
            *self.violations.get(&violation).unwrap_or(&0)
        }
    }

    fn record(sim: &mut Sim, violation: Violation) {
        *sim.violations.entry(violation).or_insert(0) += 1;
    }

    fn merge(report: &mut Report, sim: &Sim) {
        for (violation, count) in &sim.violations {
            *report.violations.entry(*violation).or_insert(0) += count;
        }
    }

    fn advance(actor: &mut Actor) {
        actor.pc += 1;
        actor.phase = Phase::Load;
        actor.loaded = 0;
        actor.loaded_retired = false;
        if actor.pc >= actor.program.len() {
            actor.done = true;
        }
    }

    fn check_count(sim: &mut Sim) {
        if sim.count < 0 && sim.count != REF_DESTROYING {
            record(sim, Violation::NegativeLiveCount);
        }
    }

    fn complete_up(sim: &mut Sim, actor: &mut Actor) {
        sim.ups += 1;
        sim.outstanding += 1;
        actor.held = true;
        if actor.loaded_retired || sim.sentinel_installed {
            record(sim, Violation::Resurrection);
        }
        if sim.count <= 0 {
            record(sim, Violation::UpProducedNonPositive);
        }
        check_count(sim);
    }

    fn complete_down(sim: &mut Sim, actor: &mut Actor, result: DownResult, reentrant: bool) {
        if reentrant {
            match result {
                DownResult::Last => record(sim, Violation::ReentrantDownClaimedLast),
                DownResult::Remaining => record(sim, Violation::ReentrantDownReleasedReference),
            }
        } else {
            sim.downs += 1;
            actor.held = false;
            sim.outstanding -= 1;
            if sim.outstanding < 0 {
                record(sim, Violation::OutstandingUnderflow);
            }
        }
        if result == DownResult::Last {
            sim.lasts += 1;
            if sim.lasts > 1 {
                record(sim, Violation::MultipleLast);
            }
            if !reentrant && sim.outstanding != 0 {
                record(sim, Violation::LastWithOutstandingRefs);
            }
        }
        check_count(sim);
    }

    /// Apply a write for an atomic protocol only when the observed count is still
    /// `expected`; the non-atomic mutant writes unconditionally.
    fn apply_write(sim: &mut Sim, proto: Proto, expected: i32, next: i32) -> bool {
        if proto == Proto::NonAtomicRmw || sim.count == expected {
            sim.count = next;
            true
        } else {
            false
        }
    }

    fn run_step(actor: &mut Actor, sim: &mut Sim, proto: Proto) {
        sim.steps += 1;
        let op = actor.program[actor.pc];
        match op {
            Op::Up => match actor.phase {
                Phase::Load => {
                    let n = sim.count;
                    let retired = n == REF_DESTROYING || n <= 0;
                    let refuse =
                        proto != Proto::UncheckedUp && (retired || n.checked_add(1).is_none());
                    if refuse {
                        advance(actor);
                    } else {
                        actor.loaded = n;
                        actor.loaded_retired = retired;
                        actor.phase = Phase::Commit;
                    }
                }
                Phase::Commit => {
                    let n = actor.loaded;
                    let next = n.wrapping_add(1);
                    if !apply_write(sim, proto, n, next) {
                        actor.phase = Phase::Load;
                        return;
                    }
                    complete_up(sim, actor);
                    advance(actor);
                }
            },
            Op::DownOwned | Op::DownReentrant => {
                let reentrant = op == Op::DownReentrant;
                if !reentrant && !actor.held {
                    advance(actor);
                    return;
                }
                match actor.phase {
                    Phase::Load => {
                        let n = sim.count;
                        if proto == Proto::ZeroFree && (n == REF_DESTROYING || n <= 0) {
                            // The mutant frees on any zero/negative count instead of
                            // requiring the sentinel claim.
                            complete_down(sim, actor, DownResult::Last, reentrant);
                            advance(actor);
                            return;
                        }
                        if n == REF_DESTROYING || n <= 0 {
                            if reentrant {
                                advance(actor);
                            } else {
                                record(sim, Violation::OwnedDownObservedRetired);
                                advance(actor);
                            }
                            return;
                        }
                        actor.loaded = n;
                        actor.phase = Phase::Commit;
                    }
                    Phase::Commit => {
                        let n = actor.loaded;
                        if proto == Proto::ZeroFree {
                            let next = n - 1;
                            if sim.count != n {
                                actor.phase = Phase::Load;
                                return;
                            }
                            sim.count = next;
                            let result = if next <= 0 {
                                DownResult::Last
                            } else {
                                DownResult::Remaining
                            };
                            complete_down(sim, actor, result, reentrant);
                            advance(actor);
                            return;
                        }
                        let (next, result) = if n == 1 {
                            (REF_DESTROYING, DownResult::Last)
                        } else {
                            (n - 1, DownResult::Remaining)
                        };
                        if !apply_write(sim, proto, n, next) {
                            actor.phase = Phase::Load;
                            return;
                        }
                        if result == DownResult::Last {
                            sim.sentinel_installed = true;
                        }
                        complete_down(sim, actor, result, reentrant);
                        advance(actor);
                    }
                }
            }
        }
    }

    fn eligible(index: usize, actors: &[Actor], sim: &Sim) -> bool {
        let actor = &actors[index];
        if actor.done {
            return false;
        }
        if actor.eligible_after_last && sim.lasts == 0 {
            return false;
        }
        if actor.eligible_after_others_done
            && actors
                .iter()
                .enumerate()
                .any(|(other_index, other)| other_index != index && !other.done)
        {
            return false;
        }
        true
    }

    fn walk(sim: Sim, actors: Vec<Actor>, scenario: &Scenario, proto: Proto, report: &mut Report) {
        if actors.iter().all(|actor| actor.done) {
            let mut sim = sim;
            finalize(&mut sim, scenario);
            merge(report, &sim);
            report.executions += 1;
            return;
        }
        if sim.steps >= MAX_STEPS {
            let mut sim = sim;
            record(&mut sim, Violation::StepBoundExceeded);
            merge(report, &sim);
            return;
        }
        let mut ran_any = false;
        for index in 0..actors.len() {
            if !eligible(index, &actors, &sim) {
                continue;
            }
            ran_any = true;
            let mut next_sim = sim.clone();
            let mut next_actors = actors.clone();
            run_step(&mut next_actors[index], &mut next_sim, proto);
            walk(next_sim, next_actors, scenario, proto, report);
        }
        if !ran_any {
            *report.violations.entry(Violation::StuckState).or_insert(0) += 1;
        }
    }

    fn finalize(sim: &mut Sim, scenario: &Scenario) {
        if sim.lasts != scenario.expect_lasts {
            record(sim, Violation::LastCountMismatch);
        }
        if sim.count != scenario.expect_final_count {
            record(sim, Violation::FinalCountMismatch);
        }
        if sim.outstanding != 0 {
            record(sim, Violation::OutstandingAtEnd);
        }
        // Every modelled reference is either released, still live, or retired with
        // the whole object. The count and the operation log must agree.
        let live = if sim.count == REF_DESTROYING {
            0i64
        } else {
            i64::from(sim.count)
        };
        if i64::from(scenario.initial) + i64::from(sim.ups) - i64::from(sim.downs) != live {
            record(sim, Violation::ConservationMismatch);
        }
    }

    fn explore(scenario: &Scenario, proto: Proto) -> Report {
        let outstanding = scenario.actors.iter().filter(|actor| actor.held).count() as i32;
        let sim = Sim {
            count: scenario.initial,
            outstanding,
            lasts: 0,
            ups: 0,
            downs: 0,
            sentinel_installed: false,
            steps: 0,
            violations: BTreeMap::new(),
        };
        let mut report = Report::default();
        walk(sim, scenario.actors.clone(), scenario, proto, &mut report);
        report
    }

    #[test]
    fn exhaustive_real_protocol_has_no_violations() {
        for scenario in scenarios() {
            let report = explore(&scenario, Proto::Real);
            assert!(
                report.executions > 0,
                "{}: the scheduler explored no execution",
                scenario.name
            );
            assert!(
                report.violations.is_empty(),
                "{}: the real protocol violated {:?} over {} executions",
                scenario.name,
                report.violations,
                report.executions
            );
        }
    }

    #[test]
    fn exhaustive_scheduler_explores_racing_interleavings() {
        let report = explore(&scenarios()[0], Proto::Real);
        assert_eq!(
            report.executions, 226,
            "the three-actor scenario must enumerate all 226 interleavings, explored {}",
            report.executions
        );
    }

    #[test]
    fn mutant_non_atomic_rmw_is_detected() {
        let report = explore(&scenarios()[0], Proto::NonAtomicRmw);
        assert!(
            report.count(Violation::LastWithOutstandingRefs) > 0,
            "lost updates must let a release claim Last while a reference is outstanding: {:?}",
            report.violations
        );
    }

    #[test]
    fn mutant_unchecked_up_is_detected() {
        let report = explore(&scenarios()[1], Proto::UncheckedUp);
        assert!(
            report.count(Violation::Resurrection) > 0,
            "an unguarded increment must resurrect the sentinel: {:?}",
            report.violations
        );
    }

    #[test]
    fn mutant_zero_free_is_detected() {
        let report = explore(&scenarios()[2], Proto::ZeroFree);
        assert!(
            report.count(Violation::MultipleLast) > 0,
            "freeing on zero must produce a second destructor claim: {:?}",
            report.violations
        );
    }
}
