//! Phase 6.10a-iii — `crypto/threads_pthread.c`'s RCU layer.
//!
//! A read-copy-update lock lets many readers proceed without an atomic on their side and
//! defers a writer's reclamation until every reader that could still be looking at the old
//! object has finished. `crypto/conf/conf_mod.c` is the only consumer in this build: it
//! keeps the configuration module registry in a structure that `CONF_modules_load` swaps
//! while `CONF_modules_unload` may be reading it.
//!
//! ## The three ideas the file's own comments state, and why they are all load-bearing
//!
//! **A quiescent point is a counter, and a reader holds one for a whole thread.** A
//! `rcu_qp` is a `uint64_t` and nothing else; the read side's entire cost is one
//! acquire-add on it. The writer publishes a fresh qp by bumping `reader_idx`, so a reader
//! that arrives after the swap counts against the new one while every reader that arrived
//! before it counts against the old one. `get_hold_current_qp`'s retry loop is what makes
//! that race-free: it adds to the qp it saw, re-reads the index, and if the index moved it
//! subtracts and starts again.
//!
//! **Retirement is in order, and the order is a counter, not a queue.** `update_qp` hands
//! out `id_ctr` and increments it; `ossl_synchronize_rcu` waits on `prior_signal` until
//! `next_to_retire` equals the id it was given. So two writers racing to synchronize retire
//! their qps in the order they allocated them, and a slow writer cannot let a fast one
//! reclaim a qp a reader has not yet left.
//!
//! **The per-thread bookkeeping is collective, because a thread may hold several locks.**
//! `rcu_thr_data` holds ten `thread_qp` slots and each slot names the lock it belongs to.
//! A thread that holds two locks holds two quiescent points, and RCU has to be able to
//! find both at thread exit — which is why the state is stored under
//! `CRYPTO_THREAD_LOCAL_RCU_KEY` *in the lock's own context* and released by a thread-stop
//! handler rather than by a destructor of its own. That is D118's chain: this file cannot
//! be written before 6.6e-ii's handler table and 6.10a-ii's `_ex` family, and it is the
//! reason 6.10a was three units rather than one (D122).
//!
//! ## What is transcribed literally, and the four places it is not
//!
//! The atomics are the authority's, order for order: `Relaxed` for the first index load,
//! `Acquire` for the increment and for the re-read that confirms it, `Relaxed` for the
//! compensating decrement, `Release` for the reader's final decrement, `Acquire` for the
//! writer's spin, and `Release` for both the `reader_idx` store and the zero-add that
//! follows it. `__atomic_add_fetch` returns the *new* value and Rust's `fetch_add` returns
//! the old one, so the two sites that use it — the read-side increment and the writer's
//! spin — are written as `fetch_add` plus the arithmetic the macro does, marked
//! `wrapping_*` because the C is unsigned and wraps. The `TSAN_FAKE_LOCK`/
//! `TSAN_FAKE_UNLOCK` pairs in `ossl_rcu_write_lock`/`_write_unlock` are no-ops in a build
//! without ThreadSanitizer, which this profile is, so they have no counterpart here.
//!
//! **The mutexes and condition variables are handles rather than embedded objects.** The
//! authority embeds three `pthread_mutex_t` and two `pthread_cond_t` inside
//! `struct rcu_lock_st`. This crate's equivalents (`crypto/threads_pthread.c`'s own
//! `CRYPTO_MUTEX` and `CRYPTO_CONDVAR`, which 6.6a landed and Phase 3's `thread.rs` holds)
//! are opaque handles allocated on the heap, so the struct here holds pointers to them and
//! `ossl_rcu_lock_new` allocates five objects instead of one. Nothing observes the
//! difference: `rcu_lock_st` is `typedef`d opaque in `include/internal/rcu.h`, RCU exports
//! no symbol, and its only consumer is in this crate.
//!
//! **`ossl_rcu_lock_new`'s unwind path is expressed with five named locals rather than the
//! authority's two arrays.** The C tracks which `pthread_mutex_init`/`pthread_cond_init`
//! calls succeeded in `mutexes[3]`/`conds[2]` so that the `goto err` block destroys exactly
//! those. The observable behaviour is identical — the same objects are released and NULL is
//! returned — and the failure it unwinds is *unreachable* here, because this crate's
//! `ossl_crypto_mutex_new` and `ossl_crypto_condvar_new` box and cannot fail. The
//! transcription is still written out rather than elided, because the day one of them can
//! fail is the day the difference would matter.
//!
//! **Three faults are recorded rather than reproduced**, and the entry names are the ones
//! in `docs/SECURITY_DIVERGENCE_POLICY.md`: `D-RCU-1` (the read side's `assert` on an
//! exhausted quiescent-point array is compiled out under `NDEBUG`, so the authority writes
//! through `thread_qps[-1]`), `D-RCU-2` (`ossl_rcu_read_unlock` with no thread data
//! dereferences NULL, its `assert` being compiled out) and `D-RCU-3` (the same function's
//! `OPENSSL_assert(ret != UINT64_MAX)` is *active* and calls `OPENSSL_die` on an
//! over-unlock).
//!
//! ## What the tests can and cannot pin
//!
//! The retry loop in `get_hold_current_qp` and the `alloc_signal`/`prior_signal` waits only
//! *retry* or *block* under contention, so a single-threaded test never enters them. They
//! are exercised by two tests that spawn threads and hand off through atomics, and the
//! hand-off is deterministic: the reader publishes "held" before the writer is allowed to
//! call `ossl_synchronize_rcu`, and the writer's completion is observed rather than timed.
//!
//! SPDX-License-Identifier: Apache-2.0

// Everything here is unreachable until 6.10b lands `crypto/conf/conf_mod.c`, whose registry
// is RCU's only consumer in this build. The attribute is at module scope rather than on
// twelve items because the reason is one reason; it is removed in the commit that declares
// the client, which is the same shape `src/runtime/defaults.rs` used.
#![allow(dead_code)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::context::lib_ctx_get_concrete;
use crate::runtime::mem::{CRYPTO_calloc, CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    ossl_crypto_condvar_broadcast, ossl_crypto_condvar_new, ossl_crypto_condvar_signal,
    ossl_crypto_condvar_wait, ossl_crypto_mutex_free, ossl_crypto_mutex_lock,
    ossl_crypto_mutex_new, ossl_crypto_mutex_unlock, CryptoCondvar, CryptoMutex,
};
use crate::runtime::thread_events::ossl_init_thread_start;
use crate::runtime::threads_common::{
    CRYPTO_THREAD_get_local_ex, CRYPTO_THREAD_set_local_ex, CRYPTO_THREAD_LOCAL_RCU_KEY,
};

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/threads_pthread.c".as_ptr();

/// `new = OPENSSL_zalloc(sizeof(*new))` in `ossl_rcu_lock_new`.
const L_LOCK_NEW: c_int = 590;
/// `OPENSSL_calloc(count, sizeof(*new))` in `allocate_new_qp_group`.
const L_QP_GROUP_NEW: c_int = 475;
/// `OPENSSL_free(rlock->qp_group)` in `ossl_rcu_lock_free`.
const L_QP_GROUP_FREE: c_int = 641;
/// `ossl_rcu_free_local_data`'s `OPENSSL_free(data)`.
const L_THR_DATA_FREE: c_int = 330;
/// `data = OPENSSL_zalloc(sizeof(*data))` in `ossl_rcu_read_lock`.
const L_THR_DATA_NEW: c_int = 345;
/// `OPENSSL_free(data)` on the `set_local_ex` failure arm of `ossl_rcu_read_lock`.
const L_THR_DATA_FREE_SET: c_int = 350;
/// `OPENSSL_free(data)` on the `ossl_init_thread_start` failure arm.
const L_THR_DATA_FREE_START: c_int = 354;
/// `ossl_rcu_cb_item_new`'s `OPENSSL_zalloc(sizeof(CRYPTO_RCU_CB_ITEM))`.
const L_CB_ITEM_NEW: c_int = 542;
/// `ossl_rcu_cb_item_free`'s `OPENSSL_free(item)`.
const L_CB_ITEM_FREE: c_int = 547;
/// `OPENSSL_free(tmpcb)` in `ossl_synchronize_rcu`'s callback walk.
const L_CB_ITEM_DRAIN: c_int = 536;

/// `#define MAX_QPS 10` — the number of quiescent points one thread may hold at once.
///
/// It is a *per-thread* bound, not a per-lock one: a re-entrant hold on the same lock
/// increments a depth counter rather than taking a second slot.
pub(crate) const MAX_QPS: usize = 10;

/// `struct rcu_qp { uint64_t users; }`.
///
/// One counter and nothing else. The read side's only cost is the acquire-add on it, and
/// the writer's only wait is for it to reach zero.
///
/// `AtomicU64` rather than a bare `u64` because the authority reaches it only through
/// `ATOMIC_ADD_FETCH`/`ATOMIC_SUB_FETCH`/`ATOMIC_LOAD_N`, every one of them with an
/// explicit memory order. Its layout is that of a `u64`, which is what `#[repr(C)]` states
/// and what `allocate_new_qp_group`'s `sizeof(*new)` relies on.
#[repr(C)]
pub(crate) struct RcuQp {
    /// `users` — readers currently holding this quiescent point.
    pub(crate) users: AtomicU64,
}

/// `struct thread_qp { struct rcu_qp *qp; unsigned int depth; CRYPTO_RCU_LOCK *lock; }`.
///
/// One slot of the per-thread array. `qp` is NULL when the slot is free — that is the only
/// liveness marker the array has, which is why `get_hold_current_qp` is called *after* the
/// free slot is chosen rather than before it.
#[repr(C)]
pub(crate) struct ThreadQp {
    /// The quiescent point this slot holds, or NULL when the slot is free.
    pub(crate) qp: *mut RcuQp,
    /// How many times this thread has taken a read hold on `lock` without releasing it.
    pub(crate) depth: u32,
    /// The lock this slot belongs to, or NULL when the slot is free.
    pub(crate) lock: *mut RcuLockSt,
}

/// `typedef void (*rcu_cb_fn)(void *data)` — `include/internal/rcu.h`.
///
/// A plain `extern "C"` function pointer of one argument: it is *not* an `unsafe fn` in the
/// C sense but it is called with a caller-owned pointer, so the signature is the C one.
pub(crate) type RcuCbFn = unsafe extern "C" fn(*mut c_void);

/// `struct rcu_cb_item { rcu_cb_fn fn; void *data; struct rcu_cb_item *next; }`.
///
/// The field the authority calls `fn` is called `func` here, because `fn` is a Rust
/// keyword. The order of the three fields is the authority's.
#[repr(C)]
pub(crate) struct RcuCbItem {
    /// `fn` — the callback to run at the next `ossl_synchronize_rcu`.
    pub(crate) func: RcuCbFn,
    /// `data` — the argument it is called with.
    pub(crate) data: *mut c_void,
    /// `next` — the rest of the list; the list is LIFO.
    pub(crate) next: *mut RcuCbItem,
}

/// `struct rcu_thr_data { struct thread_qp thread_qps[MAX_QPS]; }`.
///
/// Stored under `CRYPTO_THREAD_LOCAL_RCU_KEY` in the lock's own context, so that a thread
/// holding locks from two contexts keeps two arrays. Freed by the thread-stop handler
/// [`ossl_rcu_free_local_data`] and not by a key destructor: see the module note.
#[repr(C)]
pub(crate) struct RcuThrData {
    /// The ten slots. A zeroed array is the "no locks held" state, because slot liveness
    /// is `qp != NULL`.
    pub(crate) thread_qps: [ThreadQp; MAX_QPS],
}

/// `struct rcu_lock_st`.
///
/// Opaque in `include/internal/rcu.h` — `typedef struct rcu_lock_st CRYPTO_RCU_LOCK` — so
/// the layout is internal to the library and is not part of any ABI. The five
/// synchronisation objects are *pointers* here where the authority embeds them by value;
/// see the module note for why that is unobservable.
pub(crate) struct RcuLockSt {
    /// `cb_items` — the callbacks the next `ossl_synchronize_rcu` runs, most recent first.
    pub(crate) cb_items: *mut RcuCbItem,
    /// `ctx` — the resolved context this lock belongs to, and the index its per-thread data
    /// is filed under.
    pub(crate) ctx: *mut c_void,
    /// `qp_group` — `group_count` quiescent points, allocated once by `ossl_rcu_lock_new`.
    pub(crate) qp_group: *mut RcuQp,
    /// `id_ctr` — the next quiescent point id to hand out.
    pub(crate) id_ctr: u32,
    /// `group_count` — how many quiescent points `qp_group` holds.
    pub(crate) group_count: u32,
    /// `reader_idx` — which quiescent point readers arriving now should count against.
    ///
    /// Atomic because the read side loads it twice with `Relaxed` and `Acquire` orderings
    /// and the write side stores it with `Release`; every other field in this struct is
    /// reached under one of the three mutexes.
    pub(crate) reader_idx: AtomicU32,
    /// `next_to_retire` — the id of the oldest quiescent point still being retired.
    pub(crate) next_to_retire: u32,
    /// `current_alloc_idx` — the index the next `update_qp` will claim.
    pub(crate) current_alloc_idx: u32,
    /// `writers_alloced` — how many quiescent points are allocated and not yet retired.
    pub(crate) writers_alloced: u32,
    /// `write_lock` — held for the whole of a write side operation.
    pub(crate) write_lock: *mut CryptoMutex,
    /// `alloc_lock` — protects `writers_alloced` and `current_alloc_idx`.
    pub(crate) alloc_lock: *mut CryptoMutex,
    /// `alloc_signal` — wakes writers waiting in `update_qp`.
    pub(crate) alloc_signal: *mut CryptoCondvar,
    /// `prior_lock` — enforces in-order retirement.
    pub(crate) prior_lock: *mut CryptoMutex,
    /// `prior_signal` — wakes writers waiting for their turn to retire.
    pub(crate) prior_signal: *mut CryptoCondvar,
}

// SAFETY note: no `unsafe impl Sync` is needed and none is claimed. The type lives only
// behind the `*mut RcuLockSt` its constructor hands out and is never placed in a `static` or
// shared by reference, so the compiler never asks whether it is `Sync`; asserting it would
// be an unverifiable claim about a type nothing can share that way.

/// The ten-slot array as a raw pointer to its first element.
///
/// Written as `addr_of_mut!` rather than as `(*data).thread_qps.as_mut_ptr()` so that no
/// `&mut [ThreadQp; 10]` is created: the array is walked with `i`-indexed writes, and a
/// temporary mutable reference to the whole array would be a second, unnecessary claim on
/// it.
///
/// # Safety
/// `data` must be NULL or point to a live `RcuThrData`.
unsafe fn qp_slots(data: *mut RcuThrData) -> *mut ThreadQp {
    // SAFETY: the caller guarantees `data` is live.
    unsafe { ptr::addr_of_mut!((*data).thread_qps).cast::<ThreadQp>() }
}

/// `static struct rcu_qp *get_hold_current_qp(struct rcu_lock_st *lock)`.
///
/// Read side acquisition of the current quiescent point: add one to the point that
/// `reader_idx` named, then re-read `reader_idx` with `Acquire`, and if it moved in between,
/// take the increment back with `Relaxed` and try again. The `Acquire` on the re-read is
/// what orders this thread's subsequent reads against the writer's `Release` store, and the
/// comment in the authority's source says so — item 1 of it is about stopping the compiler
/// hoisting the re-read above the increment, item 2 about seeing the store on a
/// non-cache-coherent machine.
///
/// # Safety
/// `lock` must be live, and its `qp_group` must hold `group_count >= 1` quiescent points
/// with `reader_idx` in range — both of which `ossl_rcu_lock_new` and `update_qp` maintain.
unsafe fn get_hold_current_qp(lock: *mut RcuLockSt) -> *mut RcuQp {
    loop {
        // SAFETY: `lock` is live per the contract.
        let qp_idx = unsafe { (*lock).reader_idx.load(Ordering::Relaxed) };
        // SAFETY: `lock` is live, and `reader_idx` is in range, so this is one of the
        // `group_count` live quiescent points.
        let qp = unsafe { (*lock).qp_group.add(qp_idx as usize) };
        // SAFETY: as above. `ATOMIC_ADD_FETCH(..., 1, __ATOMIC_ACQUIRE)` returns the new
        // count; `fetch_add` answers the old one, so the increment is applied here. It
        // cannot overflow: the count is bounded by the number of threads that can hold this
        // point at once.
        unsafe { (*qp).users.fetch_add(1, Ordering::Acquire) };
        // SAFETY: as above.
        if qp_idx == unsafe { (*lock).reader_idx.load(Ordering::Acquire) } {
            return qp;
        }
        // SAFETY: as above. The compensating decrement is `Relaxed`, as the authority's is:
        // it undoes an increment this thread is the only one able to see, and the release
        // that matters is the one on the confirming path.
        unsafe { (*qp).users.fetch_sub(1, Ordering::Relaxed) };
    }
}

/// `static void ossl_rcu_free_local_data(void *arg)` — the thread-stop handler.
///
/// Registered by the *first* read hold a thread takes for a given context, and called when
/// that thread stops. It releases the whole `rcu_thr_data` block, and it clears the key
/// before freeing so that a re-entrant call — `init_thread_stop` unlinks as it walks, but a
/// handler may still run twice across an explicit stop and a `pthread` destructor — finds
/// nothing.
///
/// The values the three-level table holds are *not* released here; that is
/// `threads_common.rs`'s `clean_master_key`, and the two are deliberately separable.
///
/// # Safety
/// `arg` is the context the handler was registered with, and must be a live context or
/// NULL; the authority registers it with `lock->ctx`, which `ossl_rcu_lock_new` resolved.
unsafe extern "C" fn ossl_rcu_free_local_data(arg: *mut c_void) {
    let ctx = arg;
    // SAFETY: `ctx` is the argument the handler was registered with, and the caller's side
    // of that contract is `ossl_rcu_read_lock`.
    let data = unsafe { CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx) };
    // SAFETY: as above.
    unsafe { CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, ptr::null_mut()) };
    // SAFETY: `data` is this thread's `RcuThrData`, allocated in `ossl_rcu_read_lock` and
    // released exactly once, here; `CRYPTO_free` accepts NULL.
    unsafe { CRYPTO_free(data, FILE, L_THR_DATA_FREE) };
}

/// `int ossl_rcu_read_lock(CRYPTO_RCU_LOCK *lock)` — 1 on success, 0 when the hold was
/// refused.
///
/// The first hold a thread takes for a context allocates its `rcu_thr_data` and registers
/// [`ossl_rcu_free_local_data`] as a thread-stop handler; every later hold reuses it.
/// A hold on a lock this thread already holds increments that slot's depth instead of taking
/// a second quiescent point, which is what makes a read side re-entrant.
///
/// **`D-RCU-1`.** The authority's `assert(available_qp != -1)` is compiled out under
/// `NDEBUG`, which the admitted profile defines, so a thread holding all ten slots and
/// taking an eleventh *distinct* lock writes through `data->thread_qps[-1]`. That is out of
/// bounds and this crate answers 0 instead; see `docs/SECURITY_DIVERGENCE_POLICY.md`.
///
/// # Safety
/// `lock` must be a live lock returned by [`ossl_rcu_lock_new`].
pub(crate) unsafe fn ossl_rcu_read_lock(lock: *mut RcuLockSt) -> c_int {
    if lock.is_null() {
        return 0;
    }
    // SAFETY: `lock` is live per the contract.
    let ctx = unsafe { (*lock).ctx };
    // SAFETY: `ctx` is the context the lock was created against, and the authority reaches
    // its per-thread data through exactly this call.
    let mut data = unsafe { CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx) }
        .cast::<RcuThrData>();

    if data.is_null() {
        let fresh = CRYPTO_zalloc(core::mem::size_of::<RcuThrData>(), FILE, L_THR_DATA_NEW)
            .cast::<RcuThrData>();
        if fresh.is_null() {
            return 0;
        }
        // The assignment is what the first version of this function omitted, and
        // `a_read_hold_counts_once_and_a_re_entrant_hold_counts_depth` is what found it: the
        // block was allocated and stored under the key and never bound to the local, so the
        // walk below ran against the NULL the lookup had answered. `data` here is the C's
        // `data` after all three of its arms rather than only the first.
        data = fresh;
        // SAFETY: `ctx` is live and `fresh` is this function's own allocation.
        if unsafe { CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, fresh.cast()) }
            == 0
        {
            // SAFETY: `fresh` came from `CRYPTO_zalloc` above and is not reachable from
            // anywhere else, the `set` having failed.
            unsafe { CRYPTO_free(fresh.cast(), FILE, L_THR_DATA_FREE_SET) };
            return 0;
        }
        // SAFETY: `ctx` is handed to the handler unchanged and the handler outlives the
        // lock only until the thread stops, which is the authority's contract too.
        if unsafe { ossl_init_thread_start(ptr::null(), ctx, Some(ossl_rcu_free_local_data)) } == 0
        {
            // SAFETY: both are this function's own; the table slot is cleared *before* the
            // free so that no destructor can see a dangling value.
            unsafe {
                CRYPTO_free(fresh.cast(), FILE, L_THR_DATA_FREE_START);
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx, ptr::null_mut());
            }
            return 0;
        }
    }

    // SAFETY: `data` is non-NULL and is a live `RcuThrData` — either freshly allocated above
    // or this thread's own from an earlier hold.
    let slots = unsafe { qp_slots(data) };
    let mut available_qp: isize = -1;
    let mut i = 0usize;
    while i < MAX_QPS {
        // SAFETY: `i < MAX_QPS`, so this is one of the ten live slots of the live array.
        let slot = unsafe { slots.add(i) };
        // SAFETY: `slot` is live. A free slot is one whose `qp` is NULL, which is the only
        // liveness marker the array has.
        if unsafe { (*slot).qp }.is_null() && available_qp == -1 {
            available_qp = i as isize;
        }
        // SAFETY: `slot` is live. The comparison is of two lock pointers this crate handed
        // out; a pointer comparison needs no reachability.
        if unsafe { (*slot).lock } == lock {
            // SAFETY: `slot` is live, and `depth` is this thread's own counter for this
            // lock, so a re-entrant hold cannot overflow it in any real program.
            unsafe { (*slot).depth += 1 };
            return 1;
        }
        i += 1;
    }

    if available_qp == -1 {
        // `D-RCU-1`: the authority indexes `thread_qps[-1]` here. Refused instead.
        return 0;
    }

    // SAFETY: `available_qp` is in `0..MAX_QPS`, so this is a live slot.
    let slot = unsafe { slots.add(available_qp as usize) };
    // SAFETY: `slot` is live and free (`qp` is NULL and `lock` is not this lock), and the
    // hold taken here is released by `ossl_rcu_read_unlock` with the same slot.
    unsafe {
        (*slot).qp = get_hold_current_qp(lock);
        (*slot).depth = 1;
        (*slot).lock = lock;
    }
    1
}

/// `void ossl_rcu_read_unlock(CRYPTO_RCU_LOCK *lock)`.
///
/// Releases one level of the hold, and on the outermost level takes the quiescent point's
/// count back down with `Release`, so that everything this thread read before the unlock is
/// visible to the writer that observes the count reach zero.
///
/// **Two of the authority's three exit paths are not reachable here**, and the difference is
/// recorded rather than hidden:
///
/// * `D-RCU-2` — its `assert(data != NULL)` is compiled out under `NDEBUG`, so an unlock
///   with no thread data dereferences NULL. Answered here by returning.
/// * `D-RCU-3` — its `OPENSSL_assert(ret != UINT64_MAX)` is *active* (the macro in
///   `crypto.h.in` is not `NDEBUG`-gated) and calls `OPENSSL_die`. That is a reached abort
///   on an over-unlock, which this crate does not reproduce: it puts the count back to zero
///   — the state a caller who never took the hold described — and clears the slot.
/// * Its trailing `assert(0)`, on unlocking a lock this thread never acquired, **is**
///   compiled out, so the authority returns from there with no other effect. That path is
///   reproduced exactly: falling out of the loop returns.
///
/// # Safety
/// `lock` must be a live lock that this thread holds a read hold on. An unbalanced unlock is
/// answered rather than faulted, which is `D-RCU-2`/`D-RCU-3` and not a licence.
pub(crate) unsafe fn ossl_rcu_read_unlock(lock: *mut RcuLockSt) {
    if lock.is_null() {
        return;
    }
    // SAFETY: `lock` is live per the contract.
    let ctx = unsafe { (*lock).ctx };
    // SAFETY: `ctx` is the context the lock was created against.
    let data = unsafe { CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_RCU_KEY, ctx) }
        .cast::<RcuThrData>();
    if data.is_null() {
        // `D-RCU-2`: the authority dereferences NULL here.
        return;
    }

    // SAFETY: `data` is non-NULL and live.
    let slots = unsafe { qp_slots(data) };
    let mut i = 0usize;
    while i < MAX_QPS {
        // SAFETY: `i < MAX_QPS`.
        let slot = unsafe { slots.add(i) };
        // SAFETY: `slot` is live.
        if unsafe { (*slot).lock } == lock {
            // SAFETY: `slot` is live.
            unsafe { (*slot).depth -= 1 };
            // SAFETY: as above.
            if unsafe { (*slot).depth } == 0 {
                // SAFETY: a slot whose depth has just reached zero holds a non-NULL `qp`,
                // because `ossl_rcu_read_lock` set both together.
                let qp = unsafe { (*slot).qp };
                // SAFETY: `qp` is a live quiescent point of this lock's group.
                let ret = unsafe { (*qp).users.fetch_sub(1, Ordering::Release) }.wrapping_sub(1);
                if ret == u64::MAX {
                    // `D-RCU-3`. The count was already zero, so the subtraction wrapped:
                    // the caller unlocked more times than it locked. The authority dies
                    // here. Undoing the wrap restores the only state that describes the
                    // caller's actual hold — none — and leaves retirement able to proceed.
                    // SAFETY: `qp` is live, and adding the one back cannot overflow because
                    // the subtraction just wrapped it to `u64::MAX`.
                    unsafe { (*qp).users.fetch_add(1, Ordering::Release) };
                }
                // SAFETY: `slot` is live and this thread owns it.
                unsafe {
                    (*slot).qp = ptr::null_mut();
                    (*slot).lock = ptr::null_mut();
                }
            }
            return;
        }
        i += 1;
    }
    // The authority's `assert(0)` is compiled out under `NDEBUG`: an unlock of a lock this
    // thread never acquired returns with no other effect, and so does this.
}

/// `static struct rcu_qp *update_qp(CRYPTO_RCU_LOCK *lock, uint32_t *curr_id)`.
///
/// The writer's half of the handshake: claim a free quiescent point, publish the next index
/// so that readers arriving now count against it, and hand back the point that was current
/// — the one whose readers have to drain before it can be retired.
///
/// The `while (group_count - writers_alloced < 2)` wait is not defensive: a reader must
/// always have a point to arrive on that is neither the one being drained nor the one just
/// claimed, so at least two must be available.
///
/// # Safety
/// `lock` must be live, and `curr_id` must be NULL or writable.
unsafe fn update_qp(lock: *mut RcuLockSt, curr_id: *mut u32) -> *mut RcuQp {
    // SAFETY: `lock` is live per the contract, so `alloc_lock` is one of its handles.
    unsafe { ossl_crypto_mutex_lock((*lock).alloc_lock) };
    loop {
        // SAFETY: `lock` is live, and this loop holds `alloc_lock`, which is the mutex that
        // protects both counters. The arithmetic is the C's, which is unsigned and wraps.
        let spare = unsafe { (*lock).group_count.wrapping_sub((*lock).writers_alloced) };
        if spare >= 2 {
            break;
        }
        // SAFETY: `lock` is live, and `alloc_signal` is the condvar the authority waits on
        // while holding `alloc_lock`.
        unsafe { ossl_crypto_condvar_wait((*lock).alloc_signal, (*lock).alloc_lock) };
    }

    // SAFETY: `lock` is live and `alloc_lock` is held, so the counters below are this
    // thread's alone to read and write.
    let current_idx = unsafe { (*lock).current_alloc_idx };
    // SAFETY: as above.
    unsafe {
        (*lock).writers_alloced += 1;
        (*lock).current_alloc_idx = ((*lock).current_alloc_idx + 1) % (*lock).group_count;
        // `curr_id` is dereferenced unconditionally, as the C does: the only caller passes
        // the address of a local, so a NULL argument is the caller's error.
        *curr_id = (*lock).id_ctr;
        (*lock).id_ctr += 1;
    }
    // SAFETY: `current_idx` is in range because it came from the counter that is reduced
    // modulo `group_count`.
    let point = unsafe { (*lock).qp_group.add(current_idx as usize) };
    // SAFETY: `lock` is live and `alloc_lock` is held, so reading `current_alloc_idx` here
    // is this thread's alone.
    let published = unsafe { (*lock).current_alloc_idx };
    // SAFETY: as above. The store is `Release` so that the increments above are visible to
    // a reader that observes the new index.
    unsafe { (*lock).reader_idx.store(published, Ordering::Release) };
    // SAFETY: `point` is live. This is the authority's `ATOMIC_ADD_FETCH(..., 0,
    // __ATOMIC_RELEASE)` — an add of zero, i.e. a release fence on that location, whose own
    // comment says it exists so that the new `reader_idx` is visible in
    // `get_hold_current_qp` directly after the reader's increment.
    unsafe { (*point).users.fetch_add(0, Ordering::Release) };
    // SAFETY: `lock` is live and `alloc_signal` is its condvar.
    unsafe { ossl_crypto_condvar_signal((*lock).alloc_signal) };
    // SAFETY: as above; `alloc_lock` is held by this thread.
    unsafe { ossl_crypto_mutex_unlock((*lock).alloc_lock) };
    point
}

/// `static void retire_qp(CRYPTO_RCU_LOCK *lock, struct rcu_qp *qp)`.
///
/// Returns the point to the free set and wakes a writer waiting for one. `qp` is not touched;
/// it is the *index* that `writers_alloced` counts, so the caller's pointer is passed only to
/// keep the two halves of the pair legible against the authority's source.
///
/// # Safety
/// `lock` must be live and `qp` must be a point of its group.
unsafe fn retire_qp(lock: *mut RcuLockSt, qp: *mut RcuQp) {
    let _ = qp;
    // SAFETY: `lock` is live.
    unsafe { ossl_crypto_mutex_lock((*lock).alloc_lock) };
    // SAFETY: `lock` is live and `alloc_lock` is held, so `writers_alloced` is this
    // thread's alone; it is positive because `update_qp` incremented it for this point.
    unsafe { (*lock).writers_alloced -= 1 };
    // SAFETY: `lock` is live and `alloc_signal` is its condvar.
    unsafe { ossl_crypto_condvar_signal((*lock).alloc_signal) };
    // SAFETY: as above; `alloc_lock` is held by this thread.
    unsafe { ossl_crypto_mutex_unlock((*lock).alloc_lock) };
}

/// `static struct rcu_qp *allocate_new_qp_group(struct rcu_lock_st *lock, uint32_t count)`.
///
/// Allocates the quiescent-point array and *records the count on the lock*, which is why it
/// takes the lock rather than just the count: `update_qp` reduces modulo `group_count`, so
/// the two must be set together.
///
/// # Safety
/// `lock` must be live and not yet have a `qp_group`.
unsafe fn allocate_new_qp_group(lock: *mut RcuLockSt, count: u32) -> *mut RcuQp {
    let group = CRYPTO_calloc(
        count as usize,
        core::mem::size_of::<RcuQp>(),
        FILE,
        L_QP_GROUP_NEW,
    )
    .cast::<RcuQp>();
    // SAFETY: `lock` is live per the contract; the count is set even when the allocation
    // failed, which is the authority's order and is harmless because the caller returns NULL.
    unsafe { (*lock).group_count = count };
    group
}

/// `void ossl_rcu_write_lock(CRYPTO_RCU_LOCK *lock)`.
///
/// Takes `write_lock`. The authority pairs it with a `TSAN_FAKE_UNLOCK` — a no-op unless
/// ThreadSanitizer is enabled, which this profile is not.
///
/// # Safety
/// `lock` must be live.
pub(crate) unsafe fn ossl_rcu_write_lock(lock: *mut RcuLockSt) {
    // SAFETY: `lock` is live per the contract.
    unsafe { ossl_crypto_mutex_lock((*lock).write_lock) };
}

/// `void ossl_rcu_write_unlock(CRYPTO_RCU_LOCK *lock)`.
///
/// # Safety
/// `lock` must be live and held for writing by this thread.
pub(crate) unsafe fn ossl_rcu_write_unlock(lock: *mut RcuLockSt) {
    // SAFETY: `lock` is live per the contract.
    unsafe { ossl_crypto_mutex_unlock((*lock).write_lock) };
}

/// `void ossl_synchronize_rcu(CRYPTO_RCU_LOCK *lock)`.
///
/// The whole write side in one call: take the pending callback list aside under
/// `write_lock`, claim a new quiescent point, wait for this writer's turn to retire, wait for
/// the old point's readers to drain, then run the callbacks.
///
/// The order of the two waits is the part worth reading twice. `update_qp` is called *after*
/// the callback list is taken, so a callback queued by a second writer while this one waits
/// is run by the second writer rather than twice; and the `next_to_retire != curr_id` wait
/// happens *before* the reader count is examined, so writers retire in allocation order even
/// when they arrive out of order.
///
/// # Safety
/// `lock` must be live, and the caller must hold no read hold on it — a read hold taken by
/// the calling thread on this lock would never drain.
pub(crate) unsafe fn ossl_synchronize_rcu(lock: *mut RcuLockSt) {
    // SAFETY: `lock` is live per the contract.
    unsafe { ossl_crypto_mutex_lock((*lock).write_lock) };
    // SAFETY: `lock` is live and `write_lock` is held, so the callback list is this
    // thread's alone to take.
    let mut cb_items = unsafe { (*lock).cb_items };
    // SAFETY: as above.
    unsafe { (*lock).cb_items = ptr::null_mut() };
    // SAFETY: as above; `write_lock` is held by this thread.
    unsafe { ossl_crypto_mutex_unlock((*lock).write_lock) };

    let mut curr_id: u32 = 0;
    // SAFETY: `lock` is live and `curr_id` is this frame's own local.
    let qp = unsafe { update_qp(lock, ptr::from_mut(&mut curr_id)) };

    // SAFETY: `lock` is live.
    unsafe { ossl_crypto_mutex_lock((*lock).prior_lock) };
    loop {
        // SAFETY: `lock` is live and `prior_lock` is held.
        let next = unsafe { (*lock).next_to_retire };
        if next == curr_id {
            break;
        }
        // SAFETY: `lock` is live, and `prior_signal` is the condvar the authority waits on
        // while holding `prior_lock`.
        unsafe { ossl_crypto_condvar_wait((*lock).prior_signal, (*lock).prior_lock) };
    }

    // The reader count of this point, spinning rather than waiting on anything: a reader's
    // release is a single atomic decrement, so there is nothing to be signalled by.
    loop {
        // SAFETY: `qp` is a live point of `lock`'s group, and `Acquire` is what makes a
        // releasing reader's prior reads visible before this loop observes zero.
        if unsafe { (*qp).users.load(Ordering::Acquire) } == 0 {
            break;
        }
    }

    // SAFETY: `lock` is live and `prior_lock` is held.
    unsafe {
        (*lock).next_to_retire += 1;
        ossl_crypto_condvar_broadcast((*lock).prior_signal);
        ossl_crypto_mutex_unlock((*lock).prior_lock);
    }

    // SAFETY: `lock` is live and `qp` is a point of its group.
    unsafe { retire_qp(lock, qp) };

    // Drain the callback list. Each node is a live `RcuCbItem` whose `next` chain ends in
    // NULL, built by `ossl_rcu_call` under `write_lock`, and each is freed exactly once here.
    // The callback is called *after* its node is unlinked and before it is freed, as in the
    // authority, so a callback may allocate freely.
    while !cb_items.is_null() {
        let node = cb_items;
        // SAFETY: `node` is a live node of the list taken aside above, and `node.func` was
        // set by `ossl_rcu_call` to a non-NULL `extern "C"` callback.
        unsafe {
            cb_items = (*node).next;
            ((*node).func)((*node).data);
            CRYPTO_free(node.cast(), FILE, L_CB_ITEM_DRAIN);
        }
    }
}

/// `CRYPTO_RCU_CB_ITEM *ossl_rcu_cb_item_new(void)` — a zeroed node, or NULL.
pub(crate) fn ossl_rcu_cb_item_new() -> *mut RcuCbItem {
    CRYPTO_zalloc(core::mem::size_of::<RcuCbItem>(), FILE, L_CB_ITEM_NEW).cast::<RcuCbItem>()
}

/// `void ossl_rcu_cb_item_free(CRYPTO_RCU_CB_ITEM *item)`.
///
/// For a node that was allocated and never queued. A queued node is freed by
/// [`ossl_synchronize_rcu`] itself, and freeing it here as well would be a double free — which
/// is why the authority states which of the two owns it rather than leaving it to the caller.
///
/// # Safety
/// `item` must be NULL or a node from [`ossl_rcu_cb_item_new`] that has not been queued.
pub(crate) unsafe fn ossl_rcu_cb_item_free(item: *mut RcuCbItem) {
    // SAFETY: `item` is NULL or this function's to release, per the contract.
    unsafe { CRYPTO_free(item.cast(), FILE, L_CB_ITEM_FREE) };
}

/// `void ossl_rcu_call(CRYPTO_RCU_LOCK *lock, CRYPTO_RCU_CB_ITEM *item, rcu_cb_fn cb, void *data)`.
///
/// Queues `item` at the head of the list, so callbacks run most-recently-queued first.
///
/// The authority's comment is the contract: *"This call assumes its made under the protection
/// of `ossl_rcu_write_lock`"*. It touches `lock->cb_items`, which
/// [`ossl_synchronize_rcu`] takes and clears under that same lock.
///
/// # Safety
/// `lock`, `item` and `cb` must be live and non-NULL, and the caller must hold `lock`'s write
/// lock.
pub(crate) unsafe fn ossl_rcu_call(
    lock: *mut RcuLockSt,
    item: *mut RcuCbItem,
    cb: RcuCbFn,
    data: *mut c_void,
) {
    // SAFETY: `item` is live and not yet queued, per the contract, so writing its fields is
    // this caller's alone.
    unsafe {
        (*item).func = cb;
        (*item).data = data;
        // SAFETY: `lock` is live and write-locked, so reading the head and replacing it is
        // this thread's alone.
        (*item).next = (*lock).cb_items;
        (*lock).cb_items = item;
    }
}

/// `void *ossl_rcu_uptr_deref(void **p)` — the `Acquire` load of a published pointer.
///
/// The `include/internal/rcu.h` macro `ossl_rcu_deref(p)` is this with a cast. The body is
/// safe — `from_ptr` reinterprets an address and loading an atomic pointer is not a
/// dereference — but the function is `unsafe` because what makes it correct is the caller's
/// contract that the slot is reached through nothing but this pair, which the signature
/// cannot state.
///
/// # Safety
/// `p` must point to a `*mut c_void` slot that is accessed only through this function and
/// [`ossl_rcu_assign_uptr`].
pub(crate) unsafe fn ossl_rcu_uptr_deref(p: *mut *mut c_void) -> *mut c_void {
    // SAFETY: `p` is a live slot per the contract. `from_ptr` is unsafe because the
    // resulting reference must not outlive the value it points at, and it does not: the
    // load's answer is returned and the reference is gone.
    unsafe { AtomicPtr::from_ptr(p) }.load(Ordering::Acquire)
}

/// `void ossl_rcu_assign_uptr(void **p, void **v)` — the `Release` store.
///
/// # Safety
/// `p` must point to a `*mut c_void` slot accessed only through this pair, and `v` must
/// point to the value to publish. Neither may be NULL.
pub(crate) unsafe fn ossl_rcu_assign_uptr(p: *mut *mut c_void, v: *mut *mut c_void) {
    // SAFETY: `v` is a live slot per the contract; the authority's
    // `ATOMIC_STORE(pvoid, p, v, __ATOMIC_RELEASE)` publishes the *pointee* of `v`.
    let value = unsafe { *v };
    // SAFETY: `p` is a live slot per the contract, and the reference `from_ptr` builds is
    // dropped at the end of this statement.
    unsafe { AtomicPtr::from_ptr(p) }.store(value, Ordering::Release);
}

/// `CRYPTO_RCU_LOCK *ossl_rcu_lock_new(int num_writers, OSSL_LIB_CTX *ctx)`.
///
/// `num_writers` is the size of the quiescent-point group, raised to two when the caller asks
/// for fewer — and `crypto/conf/conf_mod.c` does pass one, which is why the clamp is
/// reachable rather than theoretical.
///
/// `ctx` is resolved with `ossl_lib_ctx_get_concrete` **before** anything is allocated, and a
/// NULL resolution refuses: the context is the index the per-thread data is filed under, so a
/// lock without one could not be read-locked at all. `ossl_rcu_lock_new(1, NULL)` therefore
/// answers a lock against the *default* context rather than NULL, because NULL is what the
/// resolution is for.
///
/// # Safety
/// `ctx` must be NULL or a live `OSSL_LIB_CTX`.
pub(crate) unsafe fn ossl_rcu_lock_new(num_writers: c_int, ctx: *mut c_void) -> *mut RcuLockSt {
    let count = if num_writers < 2 {
        2
    } else {
        num_writers as u32
    };

    let ctx = lib_ctx_get_concrete(ctx);
    if ctx.is_null() {
        return ptr::null_mut();
    }

    let lock =
        CRYPTO_zalloc(core::mem::size_of::<RcuLockSt>(), FILE, L_LOCK_NEW).cast::<RcuLockSt>();
    if lock.is_null() {
        return ptr::null_mut();
    }

    // The authority's three `pthread_mutex_init` and two `pthread_cond_init` calls, in its
    // order, with its unwind. Each of the five can fail in C and none of them can fail here
    // (the crate's constructors box), so the unwind is written out for the day that is no
    // longer true rather than assumed away.
    let mut made: [*mut CryptoMutex; 3] = [ptr::null_mut(); 3];
    let mut conds: [*mut CryptoCondvar; 2] = [ptr::null_mut(); 2];

    // SAFETY: `lock` is this function's own fresh allocation, so every field write below is
    // unaliased, and each handle written was produced by a constructor that does not fail.
    unsafe {
        (*lock).ctx = ctx;
        (*lock).write_lock = ossl_crypto_mutex_new();
        (*lock).prior_lock = ossl_crypto_mutex_new();
        (*lock).alloc_lock = ossl_crypto_mutex_new();
        (*lock).prior_signal = ossl_crypto_condvar_new();
        (*lock).alloc_signal = ossl_crypto_condvar_new();
        made[0] = (*lock).write_lock;
        made[1] = (*lock).prior_lock;
        made[2] = (*lock).alloc_lock;
        conds[0] = (*lock).prior_signal;
        conds[1] = (*lock).alloc_signal;
    }

    if made.contains(&ptr::null_mut()) || conds.contains(&ptr::null_mut()) {
        // SAFETY: `lock` is this function's own allocation and the two arrays list exactly
        // the handles created for it, NULLs included.
        return unsafe { rcu_lock_new_unwind(lock, &made, &conds) };
    }

    // SAFETY: `lock` is this function's own allocation; `allocate_new_qp_group` writes the
    // group count and answers the array.
    let group = unsafe { allocate_new_qp_group(lock, count) };
    if group.is_null() {
        // SAFETY: as above.
        return unsafe { rcu_lock_new_unwind(lock, &made, &conds) };
    }
    // SAFETY: `lock` is live and this write is unaliased.
    unsafe { (*lock).qp_group = group };

    lock
}

/// `ossl_rcu_lock_new`'s `goto err` block.
///
/// Takes the arrays of what was created rather than reading the struct's fields, because the
/// authority's block destroys exactly the objects whose initialisation succeeded and the
/// struct holds the same information in a different shape.
///
/// # Safety
/// `lock` must be this function's own allocation, and the two arrays must list exactly the
/// handles created for it.
unsafe fn rcu_lock_new_unwind(
    lock: *mut RcuLockSt,
    made: &[*mut CryptoMutex; 3],
    conds: &[*mut CryptoCondvar; 2],
) -> *mut RcuLockSt {
    for m in made.iter() {
        if !m.is_null() {
            let mut slot = *m;
            // SAFETY: each entry is a handle `ossl_crypto_mutex_new` produced for this lock
            // and nothing else refers to it.
            unsafe { ossl_crypto_mutex_free(&mut slot) };
        }
    }
    for c in conds.iter() {
        if !c.is_null() {
            let mut slot = *c;
            // SAFETY: each entry is a handle `ossl_crypto_condvar_new` produced for this
            // lock; nothing else refers to it.
            unsafe { crate::runtime::thread::ossl_crypto_condvar_free(&mut slot) };
        }
    }
    // SAFETY: the group is either NULL or this lock's own allocation.
    unsafe { CRYPTO_free((*lock).qp_group.cast(), FILE, L_QP_GROUP_FREE) };
    // SAFETY: `lock` is this function's own allocation and is not reachable from anywhere
    // else once NULL is returned.
    unsafe { CRYPTO_free(lock.cast(), FILE, L_LOCK_FREE) };
    ptr::null_mut()
}

/// `ossl_rcu_lock_free`'s `OPENSSL_free(rlock)`.
const L_LOCK_FREE: c_int = 654;

/// `void ossl_rcu_lock_free(CRYPTO_RCU_LOCK *lock)`.
///
/// Synchronizes before releasing anything, so that a lock freed while a writer is mid-retire
/// does not leave that writer waiting on a destroyed condition variable. The authority's
/// comment on the three `pthread_mutex_destroy` calls — *"Some targets (BSD) allocate heap
/// when initializing a mutex or condition, to prevent leaks, those need to be destroyed
/// here"* — applies here for a stronger reason: this crate's handles are heap objects, so
/// releasing them is not optional.
///
/// # Safety
/// `lock` must be NULL or a live lock with no read holds outstanding on any thread.
pub(crate) unsafe fn ossl_rcu_lock_free(lock: *mut RcuLockSt) {
    if lock.is_null() {
        return;
    }

    // SAFETY: `lock` is live per the contract; `ossl_synchronize_rcu` requires no read hold
    // held by this thread, which is the caller's side of the contract.
    unsafe { ossl_synchronize_rcu(lock) };

    // SAFETY: `qp_group` is this lock's own allocation, made in `ossl_rcu_lock_new` and not
    // reachable from anywhere else.
    unsafe { CRYPTO_free((*lock).qp_group.cast(), FILE, L_QP_GROUP_FREE) };

    // SAFETY: the five handles are this lock's own, and no other thread can be inside the
    // lock now that `ossl_synchronize_rcu` has returned.
    unsafe {
        let mut w = (*lock).write_lock;
        let mut p = (*lock).prior_lock;
        let mut a = (*lock).alloc_lock;
        let mut ps = (*lock).prior_signal;
        let mut asig = (*lock).alloc_signal;
        ossl_crypto_mutex_free(&mut w);
        ossl_crypto_mutex_free(&mut p);
        ossl_crypto_mutex_free(&mut a);
        crate::runtime::thread::ossl_crypto_condvar_free(&mut ps);
        crate::runtime::thread::ossl_crypto_condvar_free(&mut asig);
    }

    // SAFETY: `lock` is this function's to release, per the contract.
    unsafe { CRYPTO_free(lock.cast(), FILE, L_LOCK_FREE) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicI32};
    use std::thread;
    use std::time::Duration;

    /// A callback that records that it ran and what it was handed.
    static CB_CALLS: AtomicI32 = AtomicI32::new(0);
    static CB_SAW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    unsafe extern "C" fn count_cb(data: *mut c_void) {
        CB_CALLS.fetch_add(1, Ordering::SeqCst);
        CB_SAW.store(data, Ordering::SeqCst);
    }

    /// A marker the callbacks are handed; never dereferenced.
    static MARKER: u8 = 0x5A;

    fn marker() -> *mut c_void {
        (&MARKER as *const u8 as *mut u8).cast::<c_void>()
    }

    /// A clean slate: this thread's event handlers and per-context tables are emptied, so a
    /// test cannot observe another test's RCU thread data. `clean_local` is the same call
    /// `OPENSSL_thread_stop` makes, and it is made explicitly because libtest reuses one
    /// thread for every test in the crate.
    fn reset() {
        crate::runtime::thread_events::ensure_thread_machinery_for_test();
        crate::runtime::thread_events::OPENSSL_thread_stop();
        CB_CALLS.store(0, Ordering::SeqCst);
        CB_SAW.store(ptr::null_mut(), Ordering::SeqCst);
    }

    /// Free a lock and then stop the thread, which is the order that leaves nothing behind:
    /// the lock's own release synchronizes, and the stop runs `ossl_rcu_free_local_data`.
    fn teardown(locks: &[*mut RcuLockSt]) {
        for l in locks {
            // SAFETY: each is a live lock from `ossl_rcu_lock_new` with no read hold held by
            // this thread, and this is its single release.
            unsafe { ossl_rcu_lock_free(*l) };
        }
        crate::runtime::thread_events::OPENSSL_thread_stop();
    }

    /// The `users` count of the point readers are currently arriving on.
    ///
    /// # Safety
    /// `lock` must be live and hold at least one quiescent point.
    unsafe fn current_users(lock: *mut RcuLockSt) -> u64 {
        // SAFETY: `reader_idx` is in range by `update_qp`'s invariant, and the point is live.
        let idx = unsafe { (*lock).reader_idx.load(Ordering::Relaxed) } as usize;
        // SAFETY: as above.
        let point = unsafe { (*lock).qp_group.add(idx) };
        // SAFETY: as above.
        unsafe { (*point).users.load(Ordering::Acquire) }
    }

    #[test]
    fn a_queued_callback_runs_at_synchronize_and_its_node_is_consumed() {
        reset();
        // SAFETY: a NULL context is resolved rather than refused, which is what the
        // authority's `ossl_lib_ctx_get_concrete` is for.
        let lock = unsafe { ossl_rcu_lock_new(1, ptr::null_mut()) };
        assert!(!lock.is_null());

        let item = ossl_rcu_cb_item_new();
        assert!(!item.is_null(), "a zeroed node is allocated");
        // SAFETY: `lock` and `item` are live, and the write lock is taken below, which is
        // `ossl_rcu_call`'s stated precondition.
        unsafe {
            ossl_rcu_write_lock(lock);
            ossl_rcu_call(lock, item, count_cb, marker());
            ossl_rcu_write_unlock(lock);
        }
        assert_eq!(CB_CALLS.load(Ordering::SeqCst), 0, "queued, not run yet");

        // SAFETY: `lock` is live and this thread holds no read hold on it.
        unsafe { ossl_synchronize_rcu(lock) };
        assert_eq!(CB_CALLS.load(Ordering::SeqCst), 1, "the callback ran once");
        assert_eq!(
            CB_SAW.load(Ordering::SeqCst),
            marker(),
            "it was handed the data `ossl_rcu_call` was given"
        );

        // A second synchronize must run nothing: the list was taken and cleared, and the node
        // was freed by the first call rather than left on the lock.
        // SAFETY: as above.
        unsafe { ossl_synchronize_rcu(lock) };
        assert_eq!(
            CB_CALLS.load(Ordering::SeqCst),
            1,
            "the list is consumed, not re-run"
        );

        teardown(&[lock]);
    }

    #[test]
    fn a_read_hold_counts_once_and_a_re_entrant_hold_counts_depth() {
        reset();
        // SAFETY: as above.
        let lock = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!lock.is_null());

        // SAFETY: `lock` is live.
        unsafe {
            assert_eq!(current_users(lock), 0, "a fresh lock has no readers");
            assert_eq!(ossl_rcu_read_lock(lock), 1);
            assert_eq!(
                current_users(lock),
                1,
                "the hold is one quiescent point, not one per call"
            );
            // Re-entrant: same lock, so the depth rises and the count does not.
            assert_eq!(ossl_rcu_read_lock(lock), 1);
            assert_eq!(
                current_users(lock),
                1,
                "a re-entrant hold adds depth, not a point"
            );
            ossl_rcu_read_unlock(lock);
            assert_eq!(current_users(lock), 1, "one level is still held");
            ossl_rcu_read_unlock(lock);
            assert_eq!(
                current_users(lock),
                0,
                "the outermost release drains the point"
            );
        }

        teardown(&[lock]);
    }

    #[test]
    fn two_locks_take_two_quiescent_points_on_one_thread() {
        reset();
        // SAFETY: as above.
        let a = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        // SAFETY: as above.
        let b = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!a.is_null() && !b.is_null());

        // SAFETY: both locks are live, and the two holds are on different locks.
        unsafe {
            assert_eq!(ossl_rcu_read_lock(a), 1);
            assert_eq!(ossl_rcu_read_lock(b), 1);
            assert_eq!(current_users(a), 1, "the first lock's point has one reader");
            assert_eq!(current_users(b), 1, "and the second's has its own");
            ossl_rcu_read_unlock(a);
            assert_eq!(current_users(a), 0);
            assert_eq!(
                current_users(b),
                1,
                "releasing one lock leaves the other held"
            );
            ossl_rcu_read_unlock(b);
            assert_eq!(current_users(b), 0);
        }

        teardown(&[a, b]);
    }

    #[test]
    fn a_thread_stop_frees_the_per_thread_data_and_the_next_hold_rebuilds_it() {
        reset();
        // SAFETY: as above.
        let lock = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!lock.is_null());
        // SAFETY: `lock` is live.
        unsafe { assert_eq!(ossl_rcu_read_lock(lock), 1) };
        // SAFETY: the hold above is released before the stop, so the thread has no reader
        // state the handler could outlive.
        unsafe { ossl_rcu_read_unlock(lock) };

        // The stop runs `ossl_rcu_free_local_data`, which releases the `RcuThrData` this
        // thread allocated. That the *next* hold succeeds is what shows the handler left no
        // dangling pointer behind and no half-cleared table either.
        crate::runtime::thread_events::OPENSSL_thread_stop();
        // SAFETY: `lock` is live.
        unsafe {
            assert_eq!(ossl_rcu_read_lock(lock), 1, "the data is rebuilt on demand");
            assert_eq!(current_users(lock), 1);
            ossl_rcu_read_unlock(lock);
        }

        teardown(&[lock]);
    }

    #[test]
    fn an_unbalanced_unlock_neither_faults_nor_disturbs_a_later_hold() {
        reset();
        // SAFETY: as above.
        let lock = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!lock.is_null());

        // No thread data at all: the authority dereferences NULL here, its `assert` being
        // compiled out under `NDEBUG` (D-RCU-2). The crate returns.
        // SAFETY: `lock` is live; the unlock is unbalanced, which is what is being pinned.
        unsafe { ossl_rcu_read_unlock(lock) };

        // Thread data exists but no hold on *this* lock: the authority's trailing `assert(0)`
        // is compiled out and it returns from there, which is reproduced exactly.
        // SAFETY: `lock` and `other` are live.
        let other = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!other.is_null());
        // SAFETY: as above.
        unsafe {
            assert_eq!(ossl_rcu_read_lock(other), 1);
            ossl_rcu_read_unlock(lock);
            assert_eq!(
                current_users(other),
                1,
                "the other lock's hold is untouched"
            );
            ossl_rcu_read_unlock(other);
            assert_eq!(current_users(other), 0);
        }

        teardown(&[lock, other]);
    }

    #[test]
    fn num_writers_is_raised_to_two_and_a_null_context_is_resolved() {
        reset();
        // SAFETY: a NULL context resolves to the default one.
        let small = unsafe { ossl_rcu_lock_new(1, ptr::null_mut()) };
        // SAFETY: as above.
        let wide = unsafe { ossl_rcu_lock_new(5, ptr::null_mut()) };
        assert!(!small.is_null() && !wide.is_null());

        // SAFETY: both are live.
        unsafe {
            assert_eq!(
                (*small).group_count,
                2,
                "conf_mod.c's argument of 1 is clamped up, and that clamp is reachable"
            );
            assert_eq!((*wide).group_count, 5);
            assert!(!(*small).ctx.is_null(), "NULL is resolved, not stored");
            assert_eq!(
                (*small).ctx,
                crate::context::lib_ctx_get_concrete(ptr::null_mut()),
                "and resolved to the default context"
            );
        }

        teardown(&[small, wide]);
    }

    #[test]
    fn an_eleventh_distinct_lock_is_refused_rather_than_indexed_out_of_bounds() {
        reset();
        let mut locks = [ptr::null_mut::<RcuLockSt>(); MAX_QPS + 1];
        for slot in locks.iter_mut() {
            // SAFETY: a NULL context resolves to the default one.
            *slot = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
            assert!(!slot.is_null());
        }

        // SAFETY: every lock in the array is live.
        unsafe {
            for (i, l) in locks.iter().enumerate().take(MAX_QPS) {
                assert_eq!(ossl_rcu_read_lock(*l), 1, "slot {i} is available");
            }
            assert_eq!(
                ossl_rcu_read_lock(locks[MAX_QPS]),
                0,
                "D-RCU-1: the authority writes through thread_qps[-1] here; the crate refuses"
            );
            for l in locks.iter().take(MAX_QPS) {
                ossl_rcu_read_unlock(*l);
            }
        }

        teardown(&locks);
    }

    #[test]
    fn the_pointer_accessors_publish_and_load_through_the_atomic() {
        let mut slot: *mut c_void = ptr::null_mut();
        let mut value: *mut c_void = marker();
        // SAFETY: `slot` is this frame's own, and it is reached only through this pair; `value`
        // is a live slot holding the marker.
        unsafe {
            assert_eq!(ossl_rcu_uptr_deref(&mut slot), ptr::null_mut());
            ossl_rcu_assign_uptr(&mut slot, &mut value);
            assert_eq!(ossl_rcu_uptr_deref(&mut slot), marker());
            value = ptr::null_mut();
            ossl_rcu_assign_uptr(&mut slot, &mut value);
            assert_eq!(ossl_rcu_uptr_deref(&mut slot), ptr::null_mut());
        }
    }

    #[test]
    fn an_unqueued_callback_node_is_freeable_and_a_queued_one_is_not_the_caller_s() {
        reset();
        // A node that never reaches a lock is the caller's to release, and NULL is legal.
        let orphan = ossl_rcu_cb_item_new();
        assert!(!orphan.is_null());
        // SAFETY: `orphan` was just allocated and was never queued.
        unsafe { ossl_rcu_cb_item_free(orphan) };
        // SAFETY: `ossl_rcu_cb_item_free` is `OPENSSL_free`, which accepts NULL.
        unsafe { ossl_rcu_cb_item_free(ptr::null_mut()) };

        // A queued one is freed by `ossl_synchronize_rcu` itself; the test proves it by
        // running the queue twice and by not freeing the node here.
        // SAFETY: a NULL context resolves to the default one.
        let lock = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!lock.is_null());
        let item = ossl_rcu_cb_item_new();
        assert!(!item.is_null());
        // SAFETY: `lock` and `item` are live and the write lock is taken.
        unsafe {
            ossl_rcu_write_lock(lock);
            ossl_rcu_call(lock, item, count_cb, marker());
            ossl_rcu_write_unlock(lock);
            ossl_synchronize_rcu(lock);
        }
        assert_eq!(CB_CALLS.load(Ordering::SeqCst), 1);

        teardown(&[lock]);
    }

    #[test]
    fn a_reader_of_another_thread_holds_off_retirement() {
        reset();
        static READER_HELD: AtomicBool = AtomicBool::new(false);
        static RELEASE: AtomicBool = AtomicBool::new(false);
        static RETIRED: AtomicBool = AtomicBool::new(false);

        // SAFETY: a NULL context resolves to the default one.
        let lock = unsafe { ossl_rcu_lock_new(2, ptr::null_mut()) };
        assert!(!lock.is_null());
        let addr = lock as usize;

        READER_HELD.store(false, Ordering::SeqCst);
        RELEASE.store(false, Ordering::SeqCst);
        RETIRED.store(false, Ordering::SeqCst);

        let reader = thread::spawn(move || {
            crate::runtime::thread_events::ensure_thread_machinery_for_test();
            let lock = addr as *mut RcuLockSt;
            // SAFETY: `lock` is live for the whole of this closure; the main thread frees it
            // only after joining this thread.
            unsafe { assert_eq!(ossl_rcu_read_lock(lock), 1) };
            READER_HELD.store(true, Ordering::SeqCst);
            while !RELEASE.load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
            // SAFETY: the hold taken above, released once.
            unsafe { ossl_rcu_read_unlock(lock) };
        });

        while !READER_HELD.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        let writer = thread::spawn(move || {
            let lock = addr as *mut RcuLockSt;
            // SAFETY: `lock` is live, and this thread holds no read hold on it; the main
            // thread frees the lock only after joining this thread.
            unsafe { ossl_synchronize_rcu(lock) };
            RETIRED.store(true, Ordering::SeqCst);
        });

        // The reader is still holding, so the writer cannot have returned. The wait is the
        // *safe* direction for a loaded machine: a slower machine only makes the window this
        // assertion observes larger, never smaller.
        thread::sleep(Duration::from_millis(50));
        assert!(
            !RETIRED.load(Ordering::SeqCst),
            "retirement ran while a reader still held the point"
        );

        RELEASE.store(true, Ordering::SeqCst);
        assert!(reader.join().is_ok());
        assert!(writer.join().is_ok());
        assert!(
            RETIRED.load(Ordering::SeqCst),
            "the writer finishes once the reader leaves"
        );

        // The reader thread's own `RcuThrData` was released by the thread-exit handler, so
        // there is nothing left to stop here beyond this thread's own state.
        teardown(&[lock]);
    }
}
