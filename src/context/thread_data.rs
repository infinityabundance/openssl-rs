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
//! `ossl_threads_ctx_new` creates `cond_finished` and nothing in this stratum
//! waits on it: it is the condition the thread pool signals when a worker
//! finishes, and the pool is not a Phase 6 subsystem. It is created and released
//! here because the authority creates and releases it here, and
//! `ossl_threads_ctx_new` **fails** if either primitive cannot be allocated —
//! which is why the constructor's failure path is real rather than decorative.

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::context::{lib_ctx_get_data, OSSL_LIB_CTX_THREAD_INDEX};
use crate::ffi::guard_ffi;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    ossl_crypto_condvar_free, ossl_crypto_condvar_new, ossl_crypto_mutex_free,
    ossl_crypto_mutex_lock, ossl_crypto_mutex_new, ossl_crypto_mutex_unlock, CryptoCondvar,
    CryptoMutex,
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
    max_threads: u64,
    /// `uint64_t active_threads` — written by the pool, which is why this
    /// stratum never observes it.
    active_threads: u64,
    /// `CRYPTO_MUTEX *lock`.
    lock: *mut CryptoMutex,
    /// `CRYPTO_CONDVAR *cond_finished`.
    cond_finished: *mut CryptoCondvar,
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
fn threads_of(ctx: *mut c_void) -> *mut OsslLibCtxThreads {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new, OSSL_LIB_CTX_set0_default};

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
}
