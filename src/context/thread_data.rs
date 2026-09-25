//! Phase 6.6e — the per-context thread slot, and the two thread-count accessors.
//!
//! Three authority files meet here:
//!
//! * `crypto/thread/internal.c` — `ossl_threads_ctx_new` / `ossl_threads_ctx_free`,
//!   the object `context_init` stores in slot 19 and `context_deinit_objs`
//!   releases;
//! * `crypto/thread/api.c` — `OSSL_get_max_threads` / `OSSL_set_max_threads`,
//!   which are two locks and a field read;
//! * `include/internal/thread.h` — `OSSL_LIB_CTX_THREADS`, whose four members are
//!   reproduced exactly: two counters, a mutex and a condition variable.
//!
//! ## Why the two exports look trivial, and what makes them not
//!
//! `OSSL_get_max_threads(ctx)` reads a `uint64_t` out of a per-context structure.
//! Everything interesting about it is in the *plural*: the value is per
//! **context**, not per process, so `OSSL_set_max_threads(ctx_a, n)` must not
//! move `OSSL_get_max_threads(ctx_b)`; the accessor resolves a NULL context
//! through the library context's default chain, so it answers for whatever
//! context this thread is defaulting to at the moment it is called; and both
//! functions answer `0` — not a stored value, and `set` also answers `0` — when
//! the slot is missing, which is what the authority does when it cannot read the
//! context at all. `RT-THREADDATA` observes all three, and `RT-LIBCTX` observes
//! the slot's existence in the index table.
//!
//! ## The condition variable
//!
//! `ossl_threads_ctx_new` creates `cond_finished`; for three subphases nothing
//! waited on it, and D396 is where the thread pool that does became reachable.
//! It is created and released here because the authority creates and releases it
//! here, and `ossl_threads_ctx_new` **fails** if either primitive cannot be
//! allocated -- which is why the constructor's failure path is real rather than
//! decorative.
//!
//! ## The pool, which is the rest of `crypto/thread/internal.c`
//!
//! D396 lands `ossl_get_avail_threads` and `ossl_crypto_thread_start` / `_join` /
//! `_clean` beside the constructor, because they are the same translation unit and
//! because they are the only readers of the four members above. The thread object
//! itself and its native layer are `src/runtime/thread.rs`'s (that is
//! `crypto/thread/arch.c` and `crypto/thread/arch/thread_posix.c`).
//!
//! Two properties of the authority's pool are load-bearing and are transcribed
//! rather than simplified away. **The slot is counted before the spawn and
//! uncounted if the spawn fails**, so `active_threads` is the number of live
//! workers and not the number of successful spawns. And **the wait for a free
//! slot is on `cond_finished`**, which `ossl_crypto_thread_join` signals under the
//! same lock -- which is why `join` must decrement before it signals, or the
//! woken starter would find the slot still taken.

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_THREAD_INDEX};
use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    ossl_crypto_condvar_free, ossl_crypto_condvar_new, ossl_crypto_condvar_signal,
    ossl_crypto_condvar_wait, ossl_crypto_mutex_free, ossl_crypto_mutex_lock,
    ossl_crypto_mutex_new, ossl_crypto_mutex_unlock, CryptoCondvar, CryptoMutex,
};
use crate::runtime::thread_arch::{
    ossl_crypto_thread_native_clean, ossl_crypto_thread_native_join,
    ossl_crypto_thread_native_start, CryptoThread, CryptoThreadRetval, CryptoThreadRoutine,
};

/// The authority's translation unit. `OPENSSL_zalloc(sizeof(*t))` is at
/// `crypto/thread/internal.c:129` and `OPENSSL_free(t)` at 156.
const FILE: *const core::ffi::c_char = c"../../src/openssl-3.6.4/crypto/thread/internal.c".as_ptr();
const LINE_ZALLOC: c_int = 129;
const LINE_FREE: c_int = 156;

/// `struct openssl_threads_st`, from `include/internal/thread.h`.
///
/// `max_threads` and `active_threads` are plain counters rather than atomics
/// because the authority writes them under `lock`, and every read here is under
/// the same lock. Making them atomic would be a divergence in the observable
/// requirements on the caller, not an improvement: a caller that reads the field
/// without the lock gets a torn value in the authority and would get a clean one
/// here.
#[repr(C)]
pub(crate) struct OsslLibCtxThreads {
    /// `uint64_t max_threads` — `0` until a caller sets it, which is what
    /// `OSSL_get_max_threads` answers for a fresh context.
    pub(crate) max_threads: u64,
    /// `uint64_t active_threads` — raised by the pool before a spawn and lowered
    /// when a worker is joined.
    pub(crate) active_threads: u64,
    /// `CRYPTO_MUTEX *lock`.
    pub(crate) lock: *mut CryptoMutex,
    /// `CRYPTO_CONDVAR *cond_finished`.
    pub(crate) cond_finished: *mut CryptoCondvar,
}

/// `void *ossl_threads_ctx_new(OSSL_LIB_CTX *ctx)`
///
/// The `ctx` argument is accepted and unused, exactly as in the authority's body:
/// the structure holds no reference back to its context. It is kept in the
/// signature because the caller passes it and a future worker-spawn path will
/// need it.
///
/// Returns NULL when either primitive cannot be allocated, having released
/// whatever it did allocate — the authority's `goto fail`.
pub(crate) fn ossl_threads_ctx_new(_ctx: *mut c_void) -> *mut OsslLibCtxThreads {
    let raw = CRYPTO_zalloc(core::mem::size_of::<OsslLibCtxThreads>(), FILE, LINE_ZALLOC)
        .cast::<OsslLibCtxThreads>();
    if raw.is_null() {
        return ptr::null_mut();
    }
    let mut lock = ossl_crypto_mutex_new();
    let mut cond = ossl_crypto_condvar_new();
    if lock.is_null() || cond.is_null() {
        // SAFETY: `lock` and `cond` came from the two constructors just above
        // and are released exactly once; each accepts a NULL target.
        unsafe {
            ossl_crypto_mutex_free(&raw mut lock);
            ossl_crypto_condvar_free(&raw mut cond);
        }
        // SAFETY: `raw` came from `CRYPTO_zalloc` above, was never published, and
        // nothing else holds it.
        unsafe { CRYPTO_free(raw.cast::<c_void>(), FILE, LINE_FREE) };
        return ptr::null_mut();
    }
    // SAFETY: `raw` is a live zeroed block of exactly this struct's size that no
    // other thread can observe yet, and these are its only writes.
    unsafe {
        (*raw).lock = lock;
        (*raw).cond_finished = cond;
    }
    raw
}

/// `void ossl_threads_ctx_free(void *vdata)` — accepts NULL, as the authority does.
///
/// # Safety
/// `t` must be NULL or a live value returned by [`ossl_threads_ctx_new`], and no
/// thread may be waiting on its condition variable.
pub(crate) unsafe fn ossl_threads_ctx_free(t: *mut OsslLibCtxThreads) {
    if t.is_null() {
        return;
    }
    // SAFETY: `t` is live per the caller's contract. Both frees are of pointers
    // this object owns, each released exactly once, and both accept NULL so a
    // half-constructed object is safe to pass here.
    unsafe {
        ossl_crypto_mutex_free(ptr::addr_of_mut!((*t).lock));
        ossl_crypto_condvar_free(ptr::addr_of_mut!((*t).cond_finished));
    }
    // SAFETY: as above; the block came from `CRYPTO_zalloc` in the constructor and
    // is freed exactly once.
    unsafe { CRYPTO_free(t.cast::<c_void>(), FILE, LINE_FREE) };
}

/// `OSSL_LIB_CTX_GET_THREADS(ctx)` — the authority's macro, which is
/// `ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_THREAD_INDEX)` with a stray trailing
/// semicolon in the header.
pub(crate) fn threads_of(ctx: *mut c_void) -> *mut OsslLibCtxThreads {
    lib_ctx_get_data(ctx, OSSL_LIB_CTX_THREAD_INDEX).cast::<OsslLibCtxThreads>()
}

/// `uint64_t OSSL_get_max_threads(OSSL_LIB_CTX *ctx)`
///
/// Answers `0` when the context cannot be resolved or the slot is missing, which
/// is what the authority's `fail:` label does. A NULL context resolves through
/// the default chain, so this answers for whatever this thread defaults to.
///
/// # Safety
/// `ctx` must be NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_get_max_threads(ctx: *mut c_void) -> u64 {
    guard_ffi(0, || {
        let tdata = threads_of(ctx);
        if tdata.is_null() {
            return 0;
        }
        // SAFETY: `tdata` is a live thread slot, so its mutex is live.
        unsafe { ossl_crypto_mutex_lock((*tdata).lock) };
        // SAFETY: the read is under the lock the authority writes under.
        let ret = unsafe { (*tdata).max_threads };
        // SAFETY: as above; the same mutex is released.
        unsafe { ossl_crypto_mutex_unlock((*tdata).lock) };
        ret
    })
}

/// `int OSSL_set_max_threads(OSSL_LIB_CTX *ctx, uint64_t max_threads)`
///
/// Answers 1 on success and 0 when the context cannot be resolved or the slot is
/// missing. The value is stored verbatim: the authority does not range-check it,
/// so `UINT64_MAX` is a legal thing to set and to read back.
///
/// # Safety
/// `ctx` must be NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn OSSL_set_max_threads(ctx: *mut c_void, max_threads: u64) -> c_int {
    guard_ffi(0, || {
        let tdata = threads_of(ctx);
        if tdata.is_null() {
            return 0;
        }
        // SAFETY: `tdata` is a live thread slot, so its mutex is live.
        unsafe { ossl_crypto_mutex_lock((*tdata).lock) };
        // SAFETY: the write is under the lock the reads use.
        unsafe { (*tdata).max_threads = max_threads };
        // SAFETY: as above; the same mutex is released.
        unsafe { ossl_crypto_mutex_unlock((*tdata).lock) };
        1
    })
}

// ---------------------------------------------------------------------------
// The pool: `crypto/thread/internal.c`'s remaining four functions
//
// Their only caller in the authority is `kdfs/argon2.c.in`'s `fill_mem_blocks_mt`
// (`argon2.c.in:594`), and **that caller is now landed**: `src/provider/kdf.rs`'s
// `fill_mem_blocks_mt` is the first thing in the crate to reach this pool, so the
// `allow` each of these five used to carry is gone and the module note in
// `src/runtime/thread_arch.rs` no longer applies. `src/context/thread_data.rs`'s own
// tests still spawn, join and clean real workers, which is what first exercised the
// condition variable.
// ---------------------------------------------------------------------------

/// `static ossl_inline uint64_t _ossl_get_avail_threads(OSSL_LIB_CTX_THREADS *tdata)` —
/// `crypto/thread/internal.c:19-23`. Assumes `tdata->lock` is taken.
///
/// `wrapping_sub`, not `-`: the authority's subtraction is modular and `max_threads` is
/// caller-settable, so a value below `active_threads` is reachable rather than
/// theoretical, and a debug-build panic would be a divergence from an answer the
/// authority does give.
fn avail_threads_locked(tdata: *mut OsslLibCtxThreads) -> u64 {
    // SAFETY: the caller holds `tdata->lock`, which is what makes the two reads
    // one consistent pair.
    unsafe { (*tdata).max_threads.wrapping_sub((*tdata).active_threads) }
}

/// `uint64_t ossl_get_avail_threads(OSSL_LIB_CTX *ctx)` —
/// `crypto/thread/internal.c:25-38`. Answers `0` when the slot is missing.
///
/// `kdf_argon2_derive` is the reader: it refuses `threads > ossl_get_avail_threads(ctx)`.
///
/// # Safety
/// `ctx` must be NULL or a live library context.
pub(crate) unsafe fn ossl_get_avail_threads(ctx: *mut c_void) -> u64 {
    let tdata = threads_of(ctx);
    if tdata.is_null() {
        return 0;
    }
    // SAFETY: `tdata` is a live thread slot, so its mutex is live.
    unsafe { ossl_crypto_mutex_lock((*tdata).lock) };
    let retval = avail_threads_locked(tdata);
    // SAFETY: as above; the same mutex is released.
    unsafe { ossl_crypto_mutex_unlock((*tdata).lock) };
    retval
}

/// `void *ossl_crypto_thread_start(OSSL_LIB_CTX *ctx, CRYPTO_THREAD_ROUTINE start,
/// void *data)` — `crypto/thread/internal.c:40-71`.
///
/// The slot is claimed **before** the spawn: `active_threads` is raised under the
/// lock, the lock is dropped, and only then is the OS thread created. A spawn that
/// fails hands the slot back, so a starter never observes more active workers than
/// `max_threads`. The authority's redundant second `tdata == NULL` test (after the
/// lock is taken, where the first one already answered) is elided; nothing in
/// `threads_of` can change it.
///
/// # Safety
/// `ctx` must be NULL or a live library context; `start` must be safe to run on
/// another thread with `data`, and `data` must outlive that thread.
pub(crate) unsafe fn ossl_crypto_thread_start(
    ctx: *mut c_void,
    start: Option<CryptoThreadRoutine>,
    data: *mut c_void,
) -> *mut c_void {
    let tdata = threads_of(ctx);
    if tdata.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `tdata` is a live slot, so its mutex and condition variable are
    // live, and every read and write below is under `tdata->lock`.
    unsafe {
        ossl_crypto_mutex_lock((*tdata).lock);
        if (*tdata).max_threads == 0 {
            ossl_crypto_mutex_unlock((*tdata).lock);
            return ptr::null_mut();
        }

        while avail_threads_locked(tdata) == 0 {
            ossl_crypto_condvar_wait((*tdata).cond_finished, (*tdata).lock);
        }
        (*tdata).active_threads += 1;
        ossl_crypto_mutex_unlock((*tdata).lock);

        let thread = ossl_crypto_thread_native_start(start, data, 1);
        if thread.is_null() {
            ossl_crypto_mutex_lock((*tdata).lock);
            (*tdata).active_threads -= 1;
            ossl_crypto_mutex_unlock((*tdata).lock);
            return ptr::null_mut();
        }
        (*thread).ctx = ctx;
        thread.cast()
    }
}

/// `int ossl_crypto_thread_join(void *vhandle, CRYPTO_THREAD_RETVAL *retval)` —
/// `crypto/thread/internal.c:73-93`.
///
/// The slot is released **before** `cond_finished` is signalled, and under the same
/// lock: a starter woken by the signal must find the slot already free.
///
/// # Safety
/// `vhandle` must be NULL or a live value returned by [`ossl_crypto_thread_start`];
/// `retval` must be NULL or writable.
pub(crate) unsafe fn ossl_crypto_thread_join(
    vhandle: *mut c_void,
    retval: *mut CryptoThreadRetval,
) -> c_int {
    if vhandle.is_null() {
        return 0;
    }

    // SAFETY: `vhandle` is a live thread per the contract, so its `ctx` is the one
    // the starter was given and `threads_of` resolves the same slot again.
    let tdata = unsafe { threads_of((*vhandle.cast::<CryptoThread>()).ctx) };
    if tdata.is_null() {
        return 0;
    }

    // SAFETY: `vhandle` is the live thread the caller was handed, and `tdata` is a
    // live slot.
    unsafe {
        if ossl_crypto_thread_native_join(vhandle.cast::<CryptoThread>(), retval) == 0 {
            return 0;
        }
        ossl_crypto_mutex_lock((*tdata).lock);
        (*tdata).active_threads -= 1;
        ossl_crypto_condvar_signal((*tdata).cond_finished);
        ossl_crypto_mutex_unlock((*tdata).lock);
    }
    1
}

/// `int ossl_crypto_thread_clean(void *vhandle)` —
/// `crypto/thread/internal.c:95-100`. A one-line forward, as in the authority.
///
/// # Safety
/// `vhandle` must be NULL or a live thread that has been joined.
pub(crate) unsafe fn ossl_crypto_thread_clean(vhandle: *mut c_void) -> c_int {
    // SAFETY: `vhandle` is NULL or a live thread per the contract, and the callee
    // accepts NULL.
    unsafe { ossl_crypto_thread_native_clean(vhandle.cast::<CryptoThread>()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new, OSSL_LIB_CTX_set0_default};
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// The shared state the pool tests' workers take. A `struct` rather than a
    /// bare atomic so the routine has a `void *` to take, as a real caller does.
    struct Work {
        counter: AtomicU32,
        /// Set by `the_pool_starts_joins_and_cleans_workers` to let its workers
        /// return. They wait on it because `native_clean` admits a thread that has
        /// reached `FINISHED` even when nothing joined it, so a worker released the
        /// moment it starts could finish before the joiner calls `clean` and answer
        /// 1 where that test asks for 0. The gate makes "started and unfinished" a
        /// state the test stands in rather than races for.
        release: AtomicBool,
    }

    /// Returns its own ordinal plus one, so the joiner's `retval` is checkable.
    ///
    /// Waits on `release` first, so a caller that starts this routine and has not
    /// released it is holding a thread that is running and unjoined -- which is the
    /// state `the_pool_starts_joins_and_cleans_workers` needs to observe.
    unsafe extern "C" fn worker(data: *mut c_void) -> CryptoThreadRetval {
        // SAFETY: `data` is the `Work` the caller passed and outlives every join.
        let work = unsafe { &*data.cast::<Work>() };
        while !work.release.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        work.counter.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// The value is per **context**: setting it on one must not move another's,
    /// and the default context is one of the contexts.
    #[test]
    fn max_threads_is_per_context() {
        let a = OSSL_LIB_CTX_new();
        let b = OSSL_LIB_CTX_new();
        assert!(!a.is_null() && !b.is_null());
        // SAFETY: both contexts are live and the NULL calls resolve to the
        // default context.
        unsafe {
            assert_eq!(OSSL_get_max_threads(a), 0);
            assert_eq!(OSSL_get_max_threads(b), 0);

            assert_eq!(OSSL_set_max_threads(a, 7), 1);
            assert_eq!(OSSL_get_max_threads(a), 7);
            assert_eq!(OSSL_get_max_threads(b), 0);

            assert_eq!(OSSL_set_max_threads(b, u64::MAX), 1);
            assert_eq!(OSSL_get_max_threads(b), u64::MAX);
            assert_eq!(OSSL_get_max_threads(a), 7);

            assert_eq!(OSSL_set_max_threads(a, 0), 1);
            assert_eq!(OSSL_get_max_threads(a), 0);

            OSSL_LIB_CTX_free(b);
            OSSL_LIB_CTX_free(a);
        }
    }

    /// A NULL context is whatever this thread defaults to, so installing a
    /// default changes the answer.
    #[test]
    fn a_null_context_follows_the_thread_default() {
        let a = OSSL_LIB_CTX_new();
        assert!(!a.is_null());
        // SAFETY: `a` is live; the default chain is the subject of the test.
        unsafe {
            assert_eq!(OSSL_set_max_threads(a, 11), 1);
            assert_ne!(OSSL_get_max_threads(core::ptr::null_mut()), 11);
            let previous = OSSL_LIB_CTX_set0_default(a);
            assert_eq!(OSSL_get_max_threads(core::ptr::null_mut()), 11);
            // Restore, so this test leaves no thread-local default behind for
            // another test to observe.
            OSSL_LIB_CTX_set0_default(previous);
            assert_ne!(OSSL_get_max_threads(core::ptr::null_mut()), 11);
            OSSL_LIB_CTX_free(a);
        }
    }

    /// The pool end to end: four workers, each raising a shared counter and
    /// returning its own ordinal plus one, joined and cleaned.
    ///
    /// This is the **first** exercise of the condition variable at all -- the
    /// four `ossl_crypto_condvar_*` functions carried `#[allow(dead_code)]`
    /// labelled "unreachable until the thread pool ..." until D396 -- so it is
    /// also the test that would have caught the lost-wakeup window in `wait` that
    /// D396 closed: with it, a worker that finished before its joiner reached the
    /// wait left the joiner blocked for ever and this test would hang rather than
    /// fail.
    ///
    /// The workers are held at `Work::release` until every `clean` that expects a
    /// refusal has run. `native_clean` admits a thread that has reached `FINISHED`
    /// whether or not anything joined it, so a worker released at once could finish
    /// first and make the refusal assertion race the scheduler; the gate removes
    /// that race instead of loosening the assertion.
    #[test]
    fn the_pool_starts_joins_and_cleans_workers() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        let work = Work {
            counter: AtomicU32::new(0),
            release: AtomicBool::new(false),
        };
        let wid = core::ptr::addr_of!(work).cast_mut().cast::<c_void>();

        // SAFETY: the context and the work item are live for the whole test, and
        // the workers touch only the atomic inside `work`.
        unsafe {
            assert_eq!(OSSL_set_max_threads(ctx, 8), 1);
            assert_eq!(ossl_get_avail_threads(ctx), 8);

            let mut handles = [core::ptr::null_mut::<c_void>(); 4];
            for h in handles.iter_mut() {
                *h = ossl_crypto_thread_start(ctx, Some(worker), wid);
                assert!(!h.is_null());
                // Running and unjoined, so not cleanable: `native_clean` refuses a
                // state with neither `FINISHED` nor `JOINED`, and `Work::release`
                // holds each worker before it returns, so neither is set.
                assert_eq!(ossl_crypto_thread_clean(*h), 0);
            }
            assert_eq!(ossl_get_avail_threads(ctx), 4);

            // Every refusal has been observed; let the four workers return. Each
            // join then waits for `FINISHED` and sets `JOINED`, which is what makes
            // the `clean` below answer 1.
            work.release.store(true, Ordering::Release);

            for h in handles.iter() {
                let mut retval: CryptoThreadRetval = 0;
                assert_eq!(ossl_crypto_thread_join(*h, &mut retval), 1);
                assert!((1..=4).contains(&retval), "retval {retval} is out of range");
                assert_eq!(ossl_crypto_thread_clean(*h), 1);
            }

            assert_eq!(work.counter.load(Ordering::Acquire), 4);
            // Every slot came back: `join` releases it before it signals.
            assert_eq!(ossl_get_avail_threads(ctx), 8);
            assert_eq!(OSSL_get_max_threads(ctx), 8);
            OSSL_LIB_CTX_free(ctx);
        }
    }

    /// A context whose `max_threads` is still `0` refuses every start, and a NULL
    /// context with no default slot answers `0` available rather than faulting.
    #[test]
    fn a_zero_max_threads_refuses_a_start() {
        let ctx = OSSL_LIB_CTX_new();
        assert!(!ctx.is_null());
        let work = Work {
            counter: AtomicU32::new(0),
            release: AtomicBool::new(false),
        };
        let wid = core::ptr::addr_of!(work).cast_mut().cast::<c_void>();

        // SAFETY: the context and the work item are live; no worker is started.
        unsafe {
            assert_eq!(OSSL_get_max_threads(ctx), 0);
            assert!(ossl_crypto_thread_start(ctx, Some(worker), wid).is_null());
            assert_eq!(work.counter.load(Ordering::Acquire), 0);
            OSSL_LIB_CTX_free(ctx);
        }
    }
}
