//! Phase 3 core runtime — thread and atomic primitives (`CRYPTO_THREAD_*`,
//! `CRYPTO_atomic_*`).
//!
//! OpenSSL's C callers observe these functions directly: the locks serialise
//! their own callbacks, the once guards their own initialisation, the local
//! storage carries their own per-thread data, and the atomics read and write
//! memory *they* own. So this module reproduces the observable contract — the
//! success values, the null behaviour, the destructor semantics and the memory
//! orderings — rather than merely offering a Rust-flavoured equivalent.
//!
//! ## Signatures and platform types
//!
//! Taken from the authority's installed `crypto.h`, not from memory. On the
//! admitted `linux-x86_64` profile (`e_os2.h`/`crypto.h`):
//!
//! ```text
//! CRYPTO_RWLOCK        typedef void
//! CRYPTO_ONCE          typedef pthread_once_t   == int          (glibc)
//! CRYPTO_THREAD_LOCAL  typedef pthread_key_t    == unsigned int (glibc)
//! CRYPTO_THREAD_ID     typedef pthread_t        == unsigned long(glibc)
//! ```
//!
//! Those platform bindings are asserted by the C compiler on the authority side
//! and mirrored here as [`CryptoOnce`], [`CryptoThreadLocal`] and
//! [`CryptoThreadId`]. The once and the local storage are implemented on the
//! *same* pthread primitives the authority uses, so `CRYPTO_ONCE_STATIC_INIT`
//! (`PTHREAD_ONCE_INIT`, `0`) and the pthread shuffling of caller-owned key
//! storage are byte-compatible by construction: there is no private encoding
//! that a caller's zero-initialised static could disagree with.
//!
//! ## The read/write lock
//!
//! `CRYPTO_RWLOCK` is opaque (`typedef void`), so its representation is ours.
//! It is implemented here as a genuine reader/writer lock built from
//! `std::sync::Mutex` + `std::sync::Condvar`: readers share, writers exclude
//! both readers and other writers.
//!
//! `std::sync::RwLock` cannot be used directly, despite being the obvious
//! native choice. The C API unlocks *by handle* — `CRYPTO_THREAD_unlock(lock)`
//! receives only the opaque pointer, with no RAII guard and no per-thread
//! bookkeeping — whereas `RwLock` releases exclusively by dropping a guard
//! borrowed from the lock. There is no way to recover the guard from the raw
//! pointer without inventing a side table. A `Mutex` + `Condvar` lock keeps the
//! handle-as-identity property the C API requires while staying in `std`.
//!
//! ### Where this may fail, and the authority's own "may fail" language
//!
//! The authority's `crypto.h` marks the read and write acquire calls `__owur`
//! and documents that they "may fail". Its pthread implementation can indeed
//! return 0:
//!
//! * `pthread_rwlock_wrlock` returns `EDEADLK` when the calling thread already
//!   holds the write lock (glibc's recursive-write detection);
//! * `pthread_rwlock_rdlock` likewise reports `EDEADLK` for a read request made
//!   while the same thread holds the write lock;
//! * `pthread_rwlock_unlock` returns non-zero when the lock is not held.
//!
//! This implementation reproduces all three as a `0` return: recursive write and
//! write-then-read are detected via the writer's thread identity, and unlocking
//! an unheld lock returns 0. It is *more* deterministic than the authority —
//! glibc's `EDEADLK` behaviour depends on the rwlock's configured kind, and the
//! authority's read path can, on other configurations, deadlock instead of
//! failing. That is a documented divergence in the failure *mode*, not in the
//! success path; a caller that acquires correctly sees identical behaviour.
//!
//! Fairness is deliberately unspecified, as it is in POSIX. A stream of readers
//! can delay a waiting writer; the authority's default glibc rwlock (prefer
//! reader) behaves the same way.
//!
//! ## Atomics and the lock argument
//!
//! Each `CRYPTO_atomic_*` takes a caller-owned `int`/`uint64_t` and an optional
//! `CRYPTO_RWLOCK *`. The authority's source takes the *hardware* path first
//! whenever the compiler reports the operation lock-free, and only falls back to
//! the lock otherwise. On `x86_64`, `__atomic_is_lock_free` is true for 4- and
//! 8-byte types, so the lock is **ignored entirely** — even when it is non-NULL.
//! This was confirmed by probing the authority: with the lock held for writing,
//! `CRYPTO_atomic_add`, `CRYPTO_atomic_add64` and `CRYPTO_atomic_load_int` all
//! still returned 1 and completed (see `court/scratch/probe_atomic_lock.c`).
//! The implementation below therefore always uses `core::sync::atomic` with the
//! authority's orderings, and treats the lock parameter as accepted-and-ignored
//! *exactly as the authority does* — following the advertised "use the lock when
//! non-NULL" description would itself have been the divergence.
//!
//! The orderings are the authority's: `AcqRel` for the read-modify-write
//! operations, `Acquire` for loads, `Release` for stores.

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

use crate::ffi::guard_ffi;
use crate::runtime::bio::sys::{self, Timespec, Timeval};

// ---------------------------------------------------------------------------
// pthread bindings
//
// These are the same platform primitives the authority uses. They are declared
// directly, like `malloc`/`free` in `mem.rs`, so no dependency is added.
// ---------------------------------------------------------------------------

extern "C" {
    fn pthread_once(once: *mut c_int, init: extern "C" fn()) -> c_int;
    fn pthread_key_create(
        key: *mut c_uint,
        destructor: Option<extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn pthread_key_delete(key: c_uint) -> c_int;
    fn pthread_getspecific(key: c_uint) -> *mut c_void;
    fn pthread_setspecific(key: c_uint, value: *const c_void) -> c_int;
    fn pthread_self() -> c_ulong;
    fn pthread_equal(a: c_ulong, b: c_ulong) -> c_int;
}

/// Opaque handle matching the C `CRYPTO_RWLOCK *` (`typedef void CRYPTO_RWLOCK`).
#[repr(C)]
pub struct CryptoRwlock {
    _private: [u8; 0],
}

/// `pthread_once_t`-shaped `CRYPTO_ONCE`. On glibc this is `int`, so
/// `CRYPTO_ONCE_STATIC_INIT` is the zero-initialised value the C caller already
/// has.
pub type CryptoOnce = c_int;

/// `pthread_key_t`-shaped `CRYPTO_THREAD_LOCAL` (`unsigned int` on glibc).
pub type CryptoThreadLocal = c_uint;

/// `pthread_t`-shaped `CRYPTO_THREAD_ID` (`unsigned long` on glibc/x86_64).
pub type CryptoThreadId = c_ulong;

// ---------------------------------------------------------------------------
// Reader/writer lock internals
// ---------------------------------------------------------------------------

/// The protected state. `writer_id` records *which* thread holds the write lock
/// so that `CRYPTO_THREAD_unlock` can tell a write unlock from a read unlock and
/// so that recursive write acquisition can fail rather than deadlock.
struct LockState {
    writer: bool,
    writer_id: Option<CryptoThreadId>,
    readers: usize,
}

struct RwlockInner {
    state: Mutex<LockState>,
    cond: Condvar,
}

/// # Safety
/// `lock` must be non-NULL and point to a live `RwlockInner` produced by
/// [`CRYPTO_THREAD_lock_new`] and not yet freed.
unsafe fn rwlock_inner<'a>(lock: *mut CryptoRwlock) -> &'a RwlockInner {
    // SAFETY: `CRYPTO_THREAD_lock_new` boxes an `RwlockInner` and casts it to
    // `*mut CryptoRwlock`; the caller guarantees the pointer is live and
    // non-NULL. The returned reference's lifetime is the caller's contract for
    // the duration of one C call.
    unsafe { &*lock.cast::<RwlockInner>() }
}

/// Locks the inner mutex, recovering from poisoning.
///
/// The authority has no notion of a poisoned lock: a thread that dies while
/// holding one of its locks leaves the lock simply locked. Recovering the guard
/// here reproduces that (the state itself is only mutated in short,
/// non-panicking critical sections).
fn lock_state(inner: &RwlockInner) -> MutexGuard<'_, LockState> {
    match inner.state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Blocks until signalled, recovering from poisoning as [`lock_state`] does.
fn wait_state<'a>(
    inner: &'a RwlockInner,
    state: MutexGuard<'a, LockState>,
) -> MutexGuard<'a, LockState> {
    match inner.cond.wait(state) {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The calling thread's identity, from the same primitive the authority uses.
fn current_id() -> CryptoThreadId {
    // SAFETY: `pthread_self` takes no arguments and always succeeds.
    unsafe { pthread_self() }
}

// ---------------------------------------------------------------------------
// Locks
// ---------------------------------------------------------------------------

/// `CRYPTO_RWLOCK *CRYPTO_THREAD_lock_new(void)`
///
/// Returns NULL when allocation fails. The authority deliberately sets no error
/// here ("to avoid recursion blowup" in its own comment), so neither does this.
#[no_mangle]
pub extern "C" fn CRYPTO_THREAD_lock_new() -> *mut CryptoRwlock {
    guard_ffi(core::ptr::null_mut(), || {
        let inner = RwlockInner {
            state: Mutex::new(LockState {
                writer: false,
                writer_id: None,
                readers: 0,
            }),
            cond: Condvar::new(),
        };
        Box::into_raw(Box::new(inner)).cast::<CryptoRwlock>()
    })
}

/// `int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock)`
///
/// Returns 1 on success, 0 if this thread already holds the write lock (the
/// authority's `EDEADLK` case) or if `lock` is NULL.
///
/// # Safety
/// `lock` must be NULL or a live lock returned by [`CRYPTO_THREAD_lock_new`] and
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_read_lock(lock: *mut CryptoRwlock) -> c_int {
    guard_ffi(0, || {
        if lock.is_null() {
            return 0;
        }
        // SAFETY: `lock` is a live, unfreed lock per the caller's contract.
        let inner = unsafe { rwlock_inner(lock) };
        let me = current_id();
        let mut state = lock_state(inner);
        loop {
            if !state.writer {
                state.readers += 1;
                return 1;
            }
            if state.writer_id == Some(me) {
                // A read request while this thread holds the write lock is the
                // authority's EDEADLK path, surfaced as 0.
                return 0;
            }
            state = wait_state(inner, state);
        }
    })
}

/// `int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock)`
///
/// Returns 1 on success, 0 if this thread already holds the write lock (the
/// authority's `EDEADLK` case) or if `lock` is NULL.
///
/// # Safety
/// `lock` must be NULL or a live lock returned by [`CRYPTO_THREAD_lock_new`] and
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_write_lock(lock: *mut CryptoRwlock) -> c_int {
    guard_ffi(0, || {
        if lock.is_null() {
            return 0;
        }
        // SAFETY: as `CRYPTO_THREAD_read_lock`.
        let inner = unsafe { rwlock_inner(lock) };
        let me = current_id();
        let mut state = lock_state(inner);
        while state.writer || state.readers > 0 {
            if state.writer_id == Some(me) {
                return 0;
            }
            state = wait_state(inner, state);
        }
        state.writer = true;
        state.writer_id = Some(me);
        1
    })
}

/// `int CRYPTO_THREAD_unlock(CRYPTO_RWLOCK *lock)`
///
/// Releases whichever kind of lock this thread holds — the C API does not say
/// which — and returns 1 on success. Returns 0 when the lock is not held by this
/// thread (the authority's `EPERM` case) or when `lock` is NULL.
///
/// # Safety
/// `lock` must be NULL or a live lock returned by [`CRYPTO_THREAD_lock_new`] and
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_unlock(lock: *mut CryptoRwlock) -> c_int {
    guard_ffi(0, || {
        if lock.is_null() {
            return 0;
        }
        // SAFETY: as `CRYPTO_THREAD_read_lock`.
        let inner = unsafe { rwlock_inner(lock) };
        let me = current_id();
        let mut state = lock_state(inner);
        if state.writer {
            if state.writer_id == Some(me) {
                state.writer = false;
                state.writer_id = None;
                inner.cond.notify_all();
                return 1;
            }
            // Held by another thread.
            return 0;
        }
        if state.readers > 0 {
            state.readers -= 1;
            inner.cond.notify_all();
            return 1;
        }
        0
    })
}

/// `void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock)`
///
/// NULL is a no-op, matching the authority. Freeing a lock that is held or
/// waited upon is a caller defect in both implementations; the authority's
/// `pthread_rwlock_destroy` shares the same hazard.
///
/// # Safety
/// `lock` must be NULL or a live lock returned by [`CRYPTO_THREAD_lock_new`],
/// and must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_lock_free(lock: *mut CryptoRwlock) {
    guard_ffi((), || {
        if lock.is_null() {
            return;
        }
        // SAFETY: `lock` came from `Box::into_raw` in `CRYPTO_THREAD_lock_new`
        // and is not used again by the caller.
        drop(unsafe { Box::from_raw(lock.cast::<RwlockInner>()) });
    })
}

// ---------------------------------------------------------------------------
// Once
// ---------------------------------------------------------------------------

/// `int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void))`
///
/// A real once, shared across threads, implemented on `pthread_once` — the exact
/// primitive the authority calls. `once` is caller-owned storage whose initial
/// value must be `CRYPTO_ONCE_STATIC_INIT` (`PTHREAD_ONCE_INIT`, `0`); the
/// pthread library shuffles it into whatever state it needs, so no private
/// encoding is imposed on the caller's static.
///
/// Returns 1 on success and 0 if `once` is NULL, if `init` is NULL, or if
/// `pthread_once` fails. The authority would crash on a NULL `init`; returning 0
/// is a deliberate, safe divergence from a caller contract violation.
///
/// # Safety
/// `once` must be NULL or valid, writable, suitably aligned storage for a
/// `CRYPTO_ONCE` (initially `CRYPTO_ONCE_STATIC_INIT`). `init`, when non-NULL,
/// must be a valid function pointer that is safe to call from any thread.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_run_once(
    once: *mut CryptoOnce,
    init: Option<extern "C" fn()>,
) -> c_int {
    guard_ffi(0, || {
        if once.is_null() {
            return 0;
        }
        let Some(init) = init else {
            return 0;
        };
        // SAFETY: `once` is valid storage per the caller's contract and `init` is
        // non-NULL, which is exactly what `pthread_once` requires.
        if unsafe { pthread_once(once, init) } == 0 {
            1
        } else {
            0
        }
    })
}

// ---------------------------------------------------------------------------
// Thread-local storage
// ---------------------------------------------------------------------------

/// `int CRYPTO_THREAD_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))`
///
/// Creates the per-thread key and registers `cleanup` as its destructor, which
/// the pthread library invokes with the thread's non-NULL value when that thread
/// exits (repeatedly, up to `PTHREAD_DESTRUCTOR_ITERATIONS`, unless the
/// destructor clears the value). Returns 1 on success, 0 on failure or NULL
/// `key`.
///
/// The authority runs its global thread-event initialisation **first**, through
/// `ossl_init_thread()`, and refuses the caller's key when that fails. That call
/// was named here as a later phase until 6.6e-ii landed; it is now made, and the
/// order matters: a key created before the event machinery exists would be usable
/// by a caller who then registered a handler against a thread-local list that had
/// nowhere to go.
///
/// # Safety
/// `key` must be NULL or valid, writable storage for a `CRYPTO_THREAD_LOCAL`.
/// `cleanup`, when non-NULL, must be a valid function pointer.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_init_local(
    key: *mut CryptoThreadLocal,
    cleanup: Option<extern "C" fn(*mut c_void)>,
) -> c_int {
    guard_ffi(0, || {
        if key.is_null() {
            return 0;
        }
        if crate::runtime::thread_events::ossl_init_thread() == 0 {
            return 0;
        }
        // SAFETY: `key` is valid storage per the caller's contract.
        unsafe { thread_key_create(key, cleanup) }
    })
}

/// The body of `CRYPTO_THREAD_init_local` without the event-machinery preamble, which the
/// event machinery itself needs: `ossl_init_thread_once` creates the *destructor* key, and
/// that creation must not re-enter `ossl_init_thread`.
///
/// The authority has this as a separate function, `ossl_thread_init_local`, for exactly that
/// reason. This crate had folded it in; the fold stays and this is the seam.
///
/// # Safety
/// As [`CRYPTO_THREAD_init_local`], minus the initialisation requirement.
pub(crate) unsafe fn thread_key_create(
    key: *mut CryptoThreadLocal,
    cleanup: Option<extern "C" fn(*mut c_void)>,
) -> c_int {
    if key.is_null() {
        return 0;
    }
    // SAFETY: `key` is valid storage per the caller's contract.
    if unsafe { pthread_key_create(key, cleanup) } == 0 {
        1
    } else {
        0
    }
}

/// The body of `CRYPTO_THREAD_cleanup_local`, for the same reason as [`thread_key_create`]:
/// `ossl_cleanup_thread` releases the destructor key, and going through the exported function
/// would be guard-wrapped and re-entrant in a way the authority's call is not.
///
/// # Safety
/// `key` must be NULL or a live key from [`thread_key_create`].
pub(crate) unsafe fn thread_key_free(key: *mut CryptoThreadLocal) -> c_int {
    if key.is_null() {
        return 0;
    }
    // SAFETY: `key` points to a live key per the caller's contract.
    if unsafe { pthread_key_delete(*key) } == 0 {
        1
    } else {
        0
    }
}

/// `void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key)`
///
/// Returns this thread's value, or NULL.
///
/// # Safety
/// `key` must be NULL or point to a key created by [`CRYPTO_THREAD_init_local`]
/// and not yet deleted.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_get_local(key: *mut CryptoThreadLocal) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        if key.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `key` points to a live key per the caller's contract.
        unsafe { pthread_getspecific(*key) }
    })
}

/// `int CRYPTO_THREAD_set_local(CRYPTO_THREAD_LOCAL *key, void *val)`
///
/// Returns 1 on success, 0 on failure or NULL `key`.
///
/// # Safety
/// `key` must be NULL or point to a key created by [`CRYPTO_THREAD_init_local`]
/// and not yet deleted. `val` is stored verbatim and is the caller's to manage
/// (or for the destructor to release).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_set_local(
    key: *mut CryptoThreadLocal,
    val: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        if key.is_null() {
            return 0;
        }
        // SAFETY: `key` points to a live key per the caller's contract.
        if unsafe { pthread_setspecific(*key, val) } == 0 {
            1
        } else {
            0
        }
    })
}

/// `int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key)`
///
/// Deletes the key. Matching POSIX and the authority, deleting a key does **not**
/// run destructors for values already set in other threads; that is why the
/// authority's own `OPENSSL_cleanup` calls `OPENSSL_thread_stop` first.
///
/// # Safety
/// `key` must be NULL or point to a key created by [`CRYPTO_THREAD_init_local`]
/// that has not already been deleted.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_THREAD_cleanup_local(key: *mut CryptoThreadLocal) -> c_int {
    guard_ffi(0, || {
        if key.is_null() {
            return 0;
        }
        // SAFETY: `key` points to a live key per the caller's contract.
        unsafe { thread_key_free(key) }
    })
}

// ---------------------------------------------------------------------------
// Thread identity
// ---------------------------------------------------------------------------

/// `CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void)`
///
/// The value is a `pthread_t`, exactly as in the authority, so callers may pass
/// it to other pthread APIs on this platform.
#[no_mangle]
pub extern "C" fn CRYPTO_THREAD_get_current_id() -> CryptoThreadId {
    guard_ffi(0, current_id)
}

/// `int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b)`
///
/// Non-zero when the two ids refer to the same thread, zero otherwise — the
/// authority's `pthread_equal` result.
#[no_mangle]
pub extern "C" fn CRYPTO_THREAD_compare_id(a: CryptoThreadId, b: CryptoThreadId) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `pthread_equal` takes two ids by value and never fails.
        unsafe { pthread_equal(a, b) }
    })
}

// ---------------------------------------------------------------------------
// Atomics
//
// Every one of these takes the same optional lock as the authority. On x86_64
// the authority's lock-free branch is taken unconditionally for 4- and 8-byte
// types, so the lock is accepted and ignored — the probed, observable behaviour.
// ---------------------------------------------------------------------------

/// `int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock)`
///
/// `*ret` receives the **resulting** value, not the previous one — measured by
/// `courts/phase3/rt_thread_probe.c` (`v = 10`, `amount = 5` yields `*ret == 15`).
/// Returns 1.
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `int` storage.
/// The authority dereferences both without a NULL check, so a NULL is a fault
/// boundary rather than a documented failure (see the module note).
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_add(
    val: *mut c_int,
    amount: c_int,
    ret: *mut c_int,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `val`/`ret` are valid, aligned, non-NULL per the contract. The
        // 4-byte operation is lock-free on this profile, so the authority's
        // hardware path is taken and the lock is unused.
        unsafe {
            let old = AtomicI32::from_ptr(val).fetch_add(amount, Ordering::AcqRel);
            *ret = old.wrapping_add(amount);
        }
        1
    })
}

/// `int CRYPTO_atomic_add64(uint64_t *val, uint64_t op, uint64_t *ret, CRYPTO_RWLOCK *lock)`
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_add64(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add`; 8-byte operations are lock-free here.
        unsafe {
            let old = AtomicU64::from_ptr(val).fetch_add(op, Ordering::AcqRel);
            *ret = old.wrapping_add(op);
        }
        1
    })
}

/// `int CRYPTO_atomic_and(uint64_t *val, uint64_t op, uint64_t *ret, CRYPTO_RWLOCK *lock)`
///
/// `*ret` receives the **resulting** value: with `val == 0xFF` and `op == 0x30`
/// the probe observes `*ret == 0x30`, not `0xFF`. Writing the pre-operation value
/// here is a plausible-looking mistake that the reference measurement rules out.
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_and(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add64`.
        unsafe {
            // The authority's lock-free branch is `__atomic_fetch_and(...)`, whose
            // result is the pre-operation value; what it writes through `ret` is
            // the resulting value, which the probe pins down (`0xFF & 0x30`).
            let old = AtomicU64::from_ptr(val).fetch_and(op, Ordering::AcqRel);
            *ret = old & op;
        }
        1
    })
}

/// `int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret, CRYPTO_RWLOCK *lock)`
///
/// `*ret` receives the **resulting** value (`val == 0` with `op == 0xF0` yields
/// `*ret == 0xF0`), which is what the authority's lock-free branch computes.
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_or(
    val: *mut u64,
    op: u64,
    ret: *mut u64,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add64`.
        unsafe {
            let old = AtomicU64::from_ptr(val).fetch_or(op, Ordering::AcqRel);
            *ret = old | op;
        }
        1
    })
}

/// `int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock)`
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_load(
    val: *mut u64,
    ret: *mut u64,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add64`. The authority loads with `Acquire`.
        unsafe {
            *ret = AtomicU64::from_ptr(val).load(Ordering::Acquire);
        }
        1
    })
}

/// `int CRYPTO_atomic_store(uint64_t *dst, uint64_t val, CRYPTO_RWLOCK *lock)`
///
/// # Safety
/// `dst` must be non-NULL, valid and aligned for `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_store(
    dst: *mut u64,
    val: u64,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add64`. The authority stores with `Release`.
        unsafe {
            AtomicU64::from_ptr(dst).store(val, Ordering::Release);
        }
        1
    })
}

/// `int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock)`
///
/// # Safety
/// `val` and `ret` must be non-NULL, valid, aligned pointers to `int`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_atomic_load_int(
    val: *mut c_int,
    ret: *mut c_int,
    _lock: *mut CryptoRwlock,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: as `CRYPTO_atomic_add`. The authority loads with `Acquire`.
        unsafe {
            *ret = AtomicI32::from_ptr(val).load(Ordering::Acquire);
        }
        1
    })
}

#[cfg(test)]
// Test-side `unsafe` blocks are direct calls to the API under test, with pointers
// to values the test owns and whose validity it just established; the invariant is
// the same in each case, so it is stated once here rather than five times. Product
// code keeps the crate-wide denial.
#[allow(clippy::undocumented_unsafe_blocks)]
mod tests {
    // `unwrap_used` is denied for product code; in tests a failing unwrap is the
    // desired loud failure. `unwrap_or`/`unwrap_or_else`, used below, are not
    // panicking and need no allowance.
    use super::*;
    use core::sync::atomic::AtomicUsize;

    // -------- once ---------------------------------------------------------

    /// Stand-in for `CRYPTO_ONCE_STATIC_INIT` (`PTHREAD_ONCE_INIT` == 0).
    static ONCE: AtomicI32 = AtomicI32::new(0);
    static ONCE_RUNS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn once_body() {
        ONCE_RUNS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn run_once_executes_the_callback_exactly_once_across_threads() {
        ONCE.store(0, Ordering::SeqCst);
        ONCE_RUNS.store(0, Ordering::SeqCst);

        let mut handles = Vec::new();
        for _ in 0..16 {
            handles.push(std::thread::spawn(|| {
                // SAFETY: `ONCE.as_ptr()` is valid, aligned storage for a
                // `CRYPTO_ONCE`; `once_body` is a valid `extern "C"` callback.
                let r = unsafe { CRYPTO_THREAD_run_once(ONCE.as_ptr(), Some(once_body)) };
                assert_eq!(r, 1);
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        assert_eq!(
            ONCE_RUNS.load(Ordering::SeqCst),
            1,
            "the once callback must run exactly once"
        );
    }

    /// Separate storage so this test cannot race the once test's `ONCE`.
    static ONCE_NULL: AtomicI32 = AtomicI32::new(0);

    #[test]
    fn run_once_rejects_null_arguments() {
        // SAFETY: NULL is explicitly accepted by the contract as a failure value.
        let r = unsafe { CRYPTO_THREAD_run_once(core::ptr::null_mut(), Some(once_body)) };
        assert_eq!(r, 0);
        // SAFETY: valid storage with a NULL init pointer.
        let r = unsafe { CRYPTO_THREAD_run_once(ONCE_NULL.as_ptr(), None) };
        assert_eq!(r, 0);
    }

    // -------- rwlock -------------------------------------------------------

    /// Transfers a raw lock pointer to/from worker threads. Test-only: the
    /// pointer is a live lock for the duration of the test, so sharing it is
    /// sound, but raw pointers are not `Send` by default.
    struct SendLock(*mut CryptoRwlock);
    // SAFETY: the pointer outlives every use (the test frees it after joining).
    unsafe impl Send for SendLock {}
    // SAFETY: as above; all accesses go through the lock's own synchronisation.
    unsafe impl Sync for SendLock {}

    static RW_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn rwlock_write_lock_serialises_threads() {
        RW_COUNT.store(0, Ordering::SeqCst);
        let lock = CRYPTO_THREAD_lock_new();
        assert!(!lock.is_null(), "lock allocation must succeed");
        let shared = std::sync::Arc::new(SendLock(lock));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let shared = std::sync::Arc::clone(&shared);
            handles.push(std::thread::spawn(move || {
                for _ in 0..2000 {
                    // SAFETY: `shared.0` is a live lock owned by the test.
                    assert_eq!(unsafe { CRYPTO_THREAD_write_lock(shared.0) }, 1);
                    RW_COUNT.fetch_add(1, Ordering::SeqCst);
                    // SAFETY: the preceding write lock is held by this thread.
                    assert_eq!(unsafe { CRYPTO_THREAD_unlock(shared.0) }, 1);
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        assert_eq!(RW_COUNT.load(Ordering::SeqCst), 8 * 2000);

        // SAFETY: every user has joined and the lock is not held.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }

    #[test]
    fn rwlock_readers_and_unlock_on_a_read_lock() {
        let lock = CRYPTO_THREAD_lock_new();
        assert!(!lock.is_null());
        let shared = std::sync::Arc::new(SendLock(lock));

        // SAFETY: `lock` is live and unheld.
        assert_eq!(unsafe { CRYPTO_THREAD_read_lock(lock) }, 1);

        // A second reader on another thread must not block: readers share.
        let shared2 = std::sync::Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            // SAFETY: shared, live lock.
            let ok = unsafe { CRYPTO_THREAD_read_lock(shared2.0) };
            // SAFETY: this worker holds the read lock it just acquired.
            let un = unsafe { CRYPTO_THREAD_unlock(shared2.0) };
            (ok, un)
        });

        // SAFETY: this thread holds a read lock.
        assert_eq!(unsafe { CRYPTO_THREAD_unlock(lock) }, 1);
        assert_eq!(handle.join().unwrap_or((0, 0)), (1, 1));

        // Unlocking an unheld lock fails, as in the authority (EPERM path).
        // SAFETY: `lock` is live and unheld.
        assert_eq!(unsafe { CRYPTO_THREAD_unlock(lock) }, 0);

        // SAFETY: no user remains.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }

    #[test]
    fn rwlock_recursive_write_is_reported_not_deadlocked() {
        let lock = CRYPTO_THREAD_lock_new();
        assert!(!lock.is_null());

        // SAFETY: `lock` is live and unheld.
        assert_eq!(unsafe { CRYPTO_THREAD_write_lock(lock) }, 1);
        // The authority's glibc rwlock returns EDEADLK here; we return 0.
        // SAFETY: the same thread already holds the write lock.
        assert_eq!(unsafe { CRYPTO_THREAD_write_lock(lock) }, 0);
        // A read while holding write is also the EDEADLK case.
        // SAFETY: as above.
        assert_eq!(unsafe { CRYPTO_THREAD_read_lock(lock) }, 0);
        // SAFETY: this thread holds the write lock.
        assert_eq!(unsafe { CRYPTO_THREAD_unlock(lock) }, 1);

        // SAFETY: no user remains.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
        // NULL is a no-op.
        // SAFETY: NULL is explicitly allowed.
        unsafe { CRYPTO_THREAD_lock_free(core::ptr::null_mut()) };
    }

    // -------- thread identity ---------------------------------------------

    #[test]
    fn thread_ids_agree_within_a_thread_and_differ_across_threads() {
        let main_id = CRYPTO_THREAD_get_current_id();
        assert_eq!(CRYPTO_THREAD_compare_id(main_id, main_id), 1);

        let handle = std::thread::spawn(move || {
            CRYPTO_THREAD_compare_id(main_id, CRYPTO_THREAD_get_current_id())
        });
        assert_eq!(
            handle.join().unwrap_or(1),
            0,
            "a worker thread must not compare equal to the test thread"
        );
    }

    // -------- thread-local storage ----------------------------------------

    static KEY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static DTOR_RUNS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn tls_destructor(_value: *mut c_void) {
        // Clearing the value stops the pthread library from re-invoking the
        // destructor up to PTHREAD_DESTRUCTOR_ITERATIONS times.
        // SAFETY: `KEY` holds a live key created by the test.
        unsafe { CRYPTO_THREAD_set_local(KEY.as_ptr(), core::ptr::null_mut()) };
        DTOR_RUNS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn thread_local_is_per_thread_and_runs_its_destructor() {
        DTOR_RUNS.store(0, Ordering::SeqCst);

        // SAFETY: `KEY.as_ptr()` is valid, aligned storage for a thread-local
        // key; the destructor is a valid `extern "C"` function.
        let r = unsafe { CRYPTO_THREAD_init_local(KEY.as_ptr(), Some(tls_destructor)) };
        assert_eq!(r, 1, "key creation must succeed");

        const MAIN_VALUE: usize = 0x1234;
        // SAFETY: the key was created above.
        assert_eq!(
            unsafe { CRYPTO_THREAD_set_local(KEY.as_ptr(), MAIN_VALUE as *mut c_void) },
            1
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { CRYPTO_THREAD_get_local(KEY.as_ptr()) } as usize,
            MAIN_VALUE
        );

        let handle = std::thread::spawn(|| {
            // A different thread starts with no value for this key.
            // SAFETY: the key is live for the test's duration.
            let before = unsafe { CRYPTO_THREAD_get_local(KEY.as_ptr()) };
            assert!(before.is_null(), "thread-local storage is per thread");
            // SAFETY: as above.
            assert_eq!(
                unsafe { CRYPTO_THREAD_set_local(KEY.as_ptr(), 0x5678 as *mut c_void) },
                1
            );
            // SAFETY: as above.
            assert_eq!(
                unsafe { CRYPTO_THREAD_get_local(KEY.as_ptr()) } as usize,
                0x5678
            );
            // Returning runs this thread's key destructor.
        });
        let _ = handle.join();
        assert_eq!(
            DTOR_RUNS.load(Ordering::SeqCst),
            1,
            "the registered destructor must run exactly once on thread exit"
        );

        // The test thread's value is untouched by the worker's exit.
        // SAFETY: the key is live.
        assert_eq!(
            unsafe { CRYPTO_THREAD_get_local(KEY.as_ptr()) } as usize,
            MAIN_VALUE
        );

        // SAFETY: the key will not be used again.
        assert_eq!(unsafe { CRYPTO_THREAD_cleanup_local(KEY.as_ptr()) }, 1);
    }

    // -------- atomics ------------------------------------------------------

    static A64: AtomicU64 = AtomicU64::new(100);

    #[test]
    fn atomic_add64_is_visible_across_threads() {
        A64.store(100, Ordering::SeqCst);
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(std::thread::spawn(|| {
                for _ in 0..1000 {
                    let mut ret: u64 = 0;
                    // SAFETY: `A64.as_ptr()` is valid, aligned `u64` storage and
                    // `ret` is a valid local.
                    let r = unsafe {
                        CRYPTO_atomic_add64(A64.as_ptr(), 1, &mut ret, core::ptr::null_mut())
                    };
                    assert_eq!(r, 1);
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
        assert_eq!(A64.load(Ordering::SeqCst), 100 + 8 * 1000);
    }

    #[test]
    fn atomics_ignore_a_supplied_lock_like_the_authority() {
        let lock = CRYPTO_THREAD_lock_new();
        assert!(!lock.is_null());
        // Hold the lock for writing. The authority still takes the lock-free
        // path, so every call below must succeed and complete.
        // SAFETY: `lock` is live and unheld.
        assert_eq!(unsafe { CRYPTO_THREAD_write_lock(lock) }, 1);

        let mut v: u64 = 0;
        let mut ret: u64 = 0;
        // SAFETY: `v`/`ret` are valid, aligned `u64` storage.
        let r = unsafe { CRYPTO_atomic_or(&mut v, 0xF0, &mut ret, lock) };
        assert_eq!((r, v, ret), (1, 0xF0, 0xF0));

        // SAFETY: as above.
        let r = unsafe { CRYPTO_atomic_and(&mut v, 0x30, &mut ret, lock) };
        assert_eq!((r, v, ret), (1, 0x30, 0x30));

        // SAFETY: as above.
        let r = unsafe { CRYPTO_atomic_store(&mut v, 0xAB, lock) };
        assert_eq!((r, v), (1, 0xAB));

        // SAFETY: as above.
        let r = unsafe { CRYPTO_atomic_load(&mut v, &mut ret, lock) };
        assert_eq!((r, ret), (1, 0xAB));

        let mut vi: c_int = 5;
        let mut ri: c_int = 0;
        // SAFETY: `vi`/`ri` are valid, aligned `int` storage.
        let r = unsafe { CRYPTO_atomic_add(&mut vi, -2, &mut ri, lock) };
        assert_eq!((r, vi, ri), (1, 3, 3));

        // SAFETY: as above.
        let r = unsafe { CRYPTO_atomic_load_int(&mut vi, &mut ri, lock) };
        assert_eq!((r, ri), (1, 3));

        // SAFETY: this thread holds the write lock.
        assert_eq!(unsafe { CRYPTO_THREAD_unlock(lock) }, 1);
        // SAFETY: no user remains.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }
}

// ---------------------------------------------------------------------------
// The thread pool's primitives
//
// `crypto/threads_pthread.c` provides `ossl_crypto_mutex_*` and
// `ossl_crypto_condvar_*` over `pthread_mutex_t`/`pthread_cond_t`, and
// `crypto/thread/internal.c` builds the per-context thread slot out of them.
// They are internal: `internal/thread_arch.h` declares the types as opaque
// typedefs, so no consumer can name them, and their contract is the ordinary
// mutual-exclusion and signalling contract rather than an OpenSSL-specific one.
//
// Two design points are worth stating, because both are places a shim is
// usually wrong.
//
// **The mutex is not recursive, and a second lock by the same thread must
// block.** The authority's `pthread_mutex_t` is `PTHREAD_MUTEX_DEFAULT`, which
// deadlocks on re-lock; `std::sync::Mutex` would instead return an error on
// lock or panic on unlock, so this cannot be a thin wrapper over it. The
// implementation below parks until the flag is clear, which deadlocks exactly
// as `PTHREAD_MUTEX_DEFAULT` does.
//
// **A condition variable is paired with one mutex, and the pairing is made
// explicit.** The authority's C API creates the two independently
// (`ossl_crypto_condvar_new` takes no mutex) and pairs them at each `wait`, on
// the promise that release-and-wait is atomic. Rust's `Condvar::wait` requires
// the guard of the mutex it is waiting on, so the pairing is bound on the first
// `wait` and kept. Every use in the authority pairs one condvar with one mutex
// for its lifetime -- `OSSL_LIB_CTX_THREADS` is `lock`+`cond_finished`, the
// thread queue is `alloc_lock`+`alloc_signal`, `prior_lock`+`prior_signal` -- so
// binding it makes an invariant the authority relies on explicit, and a
// mismatched pair is reported rather than becoming a lost wakeup.
// ---------------------------------------------------------------------------

/// `struct crypto_mutex_st`, opaque in `internal/thread_arch.h`.
pub struct CryptoMutex {
    /// `true` while a thread holds it. This is the parking mutex *and* the flag,
    /// so releasing it and waiting on a condition variable is one atomic step.
    held: Mutex<bool>,
    /// Signalled when the flag is cleared, to wake a thread waiting in
    /// [`ossl_crypto_mutex_lock`]. Distinct from a [`CryptoCondvar`]'s own
    /// condvar even when the two share `held`, because the two wait for
    /// different things.
    released: Condvar,
}

/// `struct crypto_condvar_st`, opaque in `internal/thread_arch.h`.
pub struct CryptoCondvar {
    /// The mutex this condition variable was first waited on with. NULL until
    /// then; one condvar is used with one mutex for its whole life.
    bound: AtomicPtr<CryptoMutex>,
    cond: Condvar,
}

/// `CRYPTO_MUTEX *ossl_crypto_mutex_new(void)` — NULL when allocation fails.
pub(crate) fn ossl_crypto_mutex_new() -> *mut CryptoMutex {
    let m = CryptoMutex {
        held: Mutex::new(false),
        released: Condvar::new(),
    };
    Box::into_raw(Box::new(m))
}

/// `void ossl_crypto_mutex_lock(CRYPTO_MUTEX *mutex)`
///
/// # Safety
/// `mutex` must be non-NULL and live, and not already held by this thread (the
/// authority's non-recursive mutex deadlocks on that, and so does this).
unsafe fn mutex_held(m: *mut CryptoMutex) -> &'static Mutex<bool> {
    // SAFETY: `mutex` is a live object produced by `ossl_crypto_mutex_new` per
    // the caller's contract; the returned reference borrows one of its fields
    // for the duration of one C call.
    unsafe { &(*m).held }
}

pub(crate) unsafe fn ossl_crypto_mutex_lock(m: *mut CryptoMutex) {
    if m.is_null() {
        return;
    }
    // SAFETY: `m` is live per the caller's contract.
    let held = unsafe { mutex_held(m) };
    let mut flag = lock_state_poisoned(held);
    while *flag {
        // SAFETY: `m` is live per the caller's contract.
        flag = match unsafe { &(*m).released }.wait(flag) {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
    }
    *flag = true;
}

/// Locks, recovering from poisoning, as the rwlock helpers above do.
fn lock_state_poisoned(held: &Mutex<bool>) -> MutexGuard<'_, bool> {
    match held.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// `int ossl_crypto_mutex_try_lock(CRYPTO_MUTEX *mutex)` — 1 on success.
///
/// # Safety
/// `mutex` must be non-NULL and live.
#[allow(dead_code)] // unreachable until the thread pool tries one
pub(crate) unsafe fn ossl_crypto_mutex_try_lock(m: *mut CryptoMutex) -> c_int {
    if m.is_null() {
        return 0;
    }
    // SAFETY: `m` is live per the caller's contract.
    let mut flag = lock_state_poisoned(unsafe { mutex_held(m) });
    if *flag {
        return 0;
    }
    *flag = true;
    1
}

/// `void ossl_crypto_mutex_unlock(CRYPTO_MUTEX *mutex)`
///
/// # Safety
/// `mutex` must be non-NULL, live, and held by this thread.
pub(crate) unsafe fn ossl_crypto_mutex_unlock(m: *mut CryptoMutex) {
    if m.is_null() {
        return;
    }
    // SAFETY: `m` is live per the caller's contract.
    let mut flag = lock_state_poisoned(unsafe { mutex_held(m) });
    *flag = false;
    drop(flag);
    // SAFETY: `m` is live per the caller's contract.
    unsafe { &(*m).released }.notify_one();
}

/// `void ossl_crypto_mutex_free(CRYPTO_MUTEX **mutex)` — frees and NULLs.
///
/// # Safety
/// `mutex` must be NULL or a live `*mut *mut CryptoMutex` whose target came
/// from [`ossl_crypto_mutex_new`] and is not held.
pub(crate) unsafe fn ossl_crypto_mutex_free(m: *mut *mut CryptoMutex) {
    if m.is_null() {
        return;
    }
    // SAFETY: `m` is a live caller pointer per the contract.
    let obj = unsafe { *m };
    if !obj.is_null() {
        // SAFETY: the pointer came from `Box::into_raw` in
        // `ossl_crypto_mutex_new` and is freed exactly once here.
        drop(unsafe { Box::from_raw(obj) });
        // SAFETY: as above; the caller's slot is NULLed, which is what the
        // authority's `CRYPTO_MUTEX **` signature is for.
        unsafe { *m = core::ptr::null_mut() };
    }
}

/// `CRYPTO_CONDVAR *ossl_crypto_condvar_new(void)` — NULL when allocation fails.
pub(crate) fn ossl_crypto_condvar_new() -> *mut CryptoCondvar {
    let cv = CryptoCondvar {
        bound: AtomicPtr::new(core::ptr::null_mut()),
        cond: Condvar::new(),
    };
    Box::into_raw(Box::new(cv))
}

/// `void ossl_crypto_condvar_wait(CRYPTO_CONDVAR *cv, CRYPTO_MUTEX *mutex)`
///
/// Releases `mutex`, waits for a signal, and re-acquires it — the release and
/// the wait are one step with respect to the flag, because both use the mutex's
/// own parking mutex.
///
/// # Safety
/// `cv` and `mutex` must be live, and `mutex` must be held by this thread. A
/// `cv` already bound to a different mutex is a caller error: the authority's
/// `pthread_cond_wait` has no defined answer for it either, and this reports it
/// by returning without waiting rather than by becoming a lost wakeup.
#[allow(dead_code)] // unreachable until the thread pool waits on one
pub(crate) unsafe fn ossl_crypto_condvar_wait(cv: *mut CryptoCondvar, m: *mut CryptoMutex) {
    if cv.is_null() || m.is_null() {
        return;
    }
    // SAFETY: `cv` is live per the caller's contract.
    let bound = unsafe { &(*cv).bound };
    // Bind on first use, and accept only this mutex afterwards.
    let existing = bound.load(Ordering::Acquire);
    if existing.is_null() {
        let _ = bound.compare_exchange(
            core::ptr::null_mut(),
            m,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    } else if existing != m {
        return;
    }
    // SAFETY: `m` is live and held by this thread per the caller's contract.
    let held = unsafe { mutex_held(m) };
    let mut flag = lock_state_poisoned(held);
    if !*flag {
        // The caller did not hold it. `pthread_cond_wait` is undefined there too,
        // so this returns rather than waiting on a mutex it does not own.
        return;
    }
    *flag = false;
    drop(flag);
    // Wake one `ossl_crypto_mutex_lock` waiter, now that the flag is clear.
    // SAFETY: `m` is live.
    unsafe { &(*m).released }.notify_one();
    // Re-acquire before waiting, so that a signaller -- which every caller in
    // the authority is, under this mutex -- cannot slip between the release
    // above and the wait below. The wait then releases it atomically.
    // SAFETY: `m` is live.
    let g = lock_state_poisoned(unsafe { mutex_held(m) });
    // SAFETY: `cv` is live; the guard belongs to this mutex, which is what makes
    // release-and-wait one step.
    let mut g = match unsafe { &(*cv).cond }.wait(g) {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    // The wait returns with the mutex re-locked: restore the flag so the next
    // `unlock` releases it rather than corrupting the state.
    *g = true;
}

/// `void ossl_crypto_condvar_signal(CRYPTO_CONDVAR *cv)` — wakes one waiter.
///
/// # Safety
/// `cv` must be NULL or live.
#[allow(dead_code)] // unreachable until the thread pool signals one
pub(crate) unsafe fn ossl_crypto_condvar_signal(cv: *mut CryptoCondvar) {
    if cv.is_null() {
        return;
    }
    // SAFETY: `cv` is live per the caller's contract.
    unsafe { &(*cv).cond }.notify_one();
}

/// `void ossl_crypto_condvar_broadcast(CRYPTO_CONDVAR *cv)` — wakes all waiters.
///
/// # Safety
/// `cv` must be NULL or live.
#[allow(dead_code)] // unreachable until the thread pool broadcasts to them
pub(crate) unsafe fn ossl_crypto_condvar_broadcast(cv: *mut CryptoCondvar) {
    if cv.is_null() {
        return;
    }
    // SAFETY: `cv` is live per the caller's contract.
    unsafe { &(*cv).cond }.notify_all();
}

/// `void ossl_crypto_condvar_free(CRYPTO_CONDVAR **cv)` — frees and NULLs.
///
/// # Safety
/// `cv` must be NULL or a live `*mut *mut CryptoCondvar` whose target came from
/// [`ossl_crypto_condvar_new`] and has no waiters.
pub(crate) unsafe fn ossl_crypto_condvar_free(cv: *mut *mut CryptoCondvar) {
    if cv.is_null() {
        return;
    }
    // SAFETY: `cv` is a live caller pointer per the contract.
    let obj = unsafe { *cv };
    if !obj.is_null() {
        // SAFETY: the pointer came from `Box::into_raw` in
        // `ossl_crypto_condvar_new` and is freed exactly once here.
        drop(unsafe { Box::from_raw(obj) });
        // SAFETY: as above; the caller's slot is NULLed.
        unsafe { *cv = core::ptr::null_mut() };
    }
}

// ---------------------------------------------------------------------------
// The thread-count surface, and sleeping
// ---------------------------------------------------------------------------

/// `OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL`, from `openssl/thread.h`.
const OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL: u32 = 1 << 0;
/// `OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN`, from `openssl/thread.h`.
const OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN: u32 = 1 << 1;

/// `uint32_t OSSL_get_thread_support_flags(void)`
///
/// A compile-time constant of the build, not a runtime query:
/// `crypto/thread/api.c` ORs a flag in for each of `OPENSSL_NO_THREAD_POOL` and
/// `OPENSSL_NO_DEFAULT_THREAD_POOL` that is **not** defined. Neither is defined
/// in the pinned profile — `crypto/thread/arch.c` is built and the option list
/// contains no `no-thread-pool` — so the answer is `3`.
///
/// The two flags decide what `OSSL_get_max_threads`/`OSSL_set_max_threads` mean
/// for their caller, and those two are **not** implemented here: they read and
/// write the thread-tracking ex-data slot of an `OSSL_LIB_CTX`
/// (`OSSL_LIB_CTX_GET_THREADS(ctx)` → `ossl_lib_ctx_get_data(ctx,
/// OSSL_LIB_CTX_THREAD_INDEX)`), so they are Phase 6's obligation and are
/// recorded as a hand-off in `forensics/phase3-obligations.json` with that
/// dependency named.
#[no_mangle]
pub extern "C" fn OSSL_get_thread_support_flags() -> u32 {
    OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL | OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN
}

/// `void OSSL_sleep(uint64_t millis)`
///
/// Sleeps for at least `millis` milliseconds and returns. The authority's body
/// recomputes the remaining time after every sleep and loops until the clock has
/// passed the deadline, so a sleep interrupted by a signal is *continued* rather
/// than abandoned — which is observable, and is why this is not a bare
/// `nanosleep` call.
///
/// The clock is `gettimeofday`, because that is what `ossl_time_now` uses on this
/// platform (`crypto/time.c`'s non-Windows arm), and `OSSL_TIME` is microseconds.
/// Using a monotonic clock here would be tidier and would answer differently if
/// the wall clock steps backwards mid-sleep.
///
/// The `USE_SLEEP_SECS` outer loop in the authority is for platforms without
/// `nanosleep`; the admitted profile has it, so only the `nanosleep` arm is
/// present, and a literal for the other arm would be an unmeasured claim.
// The authority's spelling, which `ABI-PROTOTYPE` resolves by name; renaming it
// to `ossl_sleep` would make the export disappear.
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn OSSL_sleep(millis: u64) {
    let now = time_now_nanos();
    let finish = now.wrapping_add(millis.wrapping_mul(1_000_000));
    let mut left = millis;
    loop {
        sleep_millis(left);
        let now = time_now_nanos();
        if now >= finish {
            return;
        }
        left = finish.wrapping_sub(now) / 1_000_000;
    }
}

/// `ossl_time_now()` — nanoseconds since the epoch, or zero if `gettimeofday`
/// fails, which is the authority's `ossl_time_zero()` fallback.
///
/// The unit is **nanoseconds**, not microseconds: `OSSL_TIME` counts
/// `OSSL_TIME_SECOND == 1_000_000_000` ticks per second, and `crypto/time.c`'s
/// non-Windows arm multiplies the `struct timeval` by `OSSL_TIME_US` (1000) to
/// get there. Reading `OSSL_TIME` as microseconds made `ossl_ms2time` look like
/// `ms * 1000`, which is the mistake this comment exists to stop being repeated:
/// the first version of the test above asserted a microsecond bound against a
/// nanosecond value and failed by a factor of a thousand.
fn time_now_nanos() -> u64 {
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid, aligned `Timeval` and the timezone argument is
    // documented as ignored and may be NULL.
    let r = unsafe { sys::gettimeofday(&mut tv, core::ptr::null_mut()) };
    if r < 0 {
        return 0;
    }
    if tv.tv_sec <= 0 {
        return if tv.tv_usec <= 0 {
            0
        } else {
            (tv.tv_usec as u64) * 1000
        };
    }
    ((tv.tv_sec as u64) * 1_000_000 + tv.tv_usec as u64) * 1000
}

/// `ossl_sleep_millis` — `nanosleep` for the whole number of milliseconds.
fn sleep_millis(millis: u64) {
    let ts = Timespec {
        tv_sec: (millis / 1000) as c_long,
        tv_nsec: ((millis % 1000) * 1_000_000) as c_long,
    };
    // SAFETY: `ts` is a valid, aligned `Timespec` and the remainder argument is
    // documented as optional.
    unsafe { nanosleep(&ts, core::ptr::null_mut()) };
}

unsafe extern "C" {
    /// `int nanosleep(const struct timespec *req, struct timespec *rem)`, from
    /// `<time.h>`.
    fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int;
}

/// `int openssl_get_fork_id(void)` — `crypto/threads_pthread.c:1238-1241`.
///
/// The whole body is `return getpid();`; the `FIPS_MODULE` arm beside it is not built on this
/// profile. It exists because a `fork(2)` hands the child a copy of its parent's DRBG state:
/// `drbg.c` records this value at every (re)seed and compares it before generating, so a child
/// that inherits a seeded DRBG reseeds rather than repeating its parent's output. A value that was
/// not the process's would make that comparison answer "no fork" forever, which is a false
/// negative in a security-relevant path rather than a cosmetic error.
///
/// Internal: `include/internal/cryptlib.h` declares it and `libcrypto.num` does not, so it carries
/// no export.
#[allow(dead_code)] // the landing caller is `src/provider/rand.rs`'s `ProvDrbg` reseed check
pub(crate) fn openssl_get_fork_id() -> c_int {
    // SAFETY: `getpid` takes no arguments, dereferences none, and cannot fail per POSIX.
    unsafe { sys::getpid() }
}

#[cfg(test)]
mod sleep_tests {
    use super::*;

    #[test]
    fn the_support_flags_are_the_profiles_three() {
        assert_eq!(OSSL_get_thread_support_flags(), 3);
    }

    #[test]
    fn a_zero_sleep_returns_immediately_and_a_small_one_actually_waits() {
        let start = time_now_nanos();
        OSSL_sleep(0);
        assert!(time_now_nanos().wrapping_sub(start) < 1_000_000);

        let start = time_now_nanos();
        OSSL_sleep(20);
        let elapsed = time_now_nanos().wrapping_sub(start);
        // At least the requested time -- the loop cannot return early -- and not
        // wildly more: `nanosleep` for 20ms does not overshoot by an order of
        // magnitude on an unloaded machine. The units are nanoseconds.
        assert!(elapsed >= 20_000_000, "elapsed {elapsed}ns");
        assert!(elapsed < 2_000_000_000, "elapsed {elapsed}ns");
    }
}

#[cfg(test)]
mod fork_id_tests {
    //! `openssl_get_fork_id` is one line, and this is the test that says which line.
    //!
    //! The function's whole contract is "the process's id", and `drbg.c`'s fork check is a
    //! comparison of two of its answers. A transcription that returned a constant would satisfy
    //! every caller in a single process and defeat the check in exactly the case it exists for, so
    //! the assertion is against the platform rather than against a recorded value.

    use super::*;

    #[test]
    fn the_fork_id_is_this_process_id() {
        let id = openssl_get_fork_id();
        assert!(id > 0, "a pid is positive, got {id}");
        // SAFETY: `getpid` takes no arguments and cannot fail per POSIX.
        let real = unsafe { sys::getpid() };
        assert_eq!(
            id, real,
            "openssl_get_fork_id() is getpid(), not a copy of it"
        );
    }
}
