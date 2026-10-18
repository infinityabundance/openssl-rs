//! Phase 8.4 — `crypto/thread/arch.c` and `crypto/thread/arch/thread_posix.c`: the
//! `CRYPTO_THREAD` object and the native layer on it.
//!
//! This is where [`crate::runtime::thread`]'s mutex and condition variable meet a real
//! OS thread. `ossl_crypto_thread_native_start` builds the object, `..._spawn` creates
//! the thread and the object's state machine is what `..._join` and `..._clean`
//! implement; `crate::context::thread_data`'s pool is the caller.
//!
//! ## Why this is its own module
//!
//! `crypto/thread/` is a directory in the authority: the primitives this crate had
//! already landed live in `arch/thread_posix.c` (and are `src/runtime/thread.rs`'s),
//! and the object plus its life-cycle is `arch.c`. Keeping the second beside the first
//! made every item here read as dead to the *library* build while the only caller of
//! the pool -- `kdfs/argon2.c.in`'s `fill_mem_blocks_mt` -- was untranscribed, so the
//! module carried one `allow(dead_code)` with that reason instead of twenty-nine
//! per-item ones.
//!
//! **That reason is discharged.** `src/provider/kdf.rs`'s `fill_mem_blocks_mt` landed
//! as `crypto/thread/internal.c`'s first in-crate caller of the pool, so the module
//! `allow` is gone and every item below is reachable from `argon2` through
//! `crate::context::thread_data` -- with the test module still the thing that spawns
//! four workers, joins them, reads their return values and cleans them.
//!
//! ## The three things this layer has to get right
//!
//! **`FINISHED` is set before the retval is published and the broadcast follows both.**
//! A joiner wakes on the broadcast and reads the retval, so the order inside the thunk
//! is the reason the thunk takes the `statelock` at all rather than reading the
//! condition variable alone.
//!
//! **`JOINED` is set in the *error* half on a failed join.** `CRYPTO_THREAD_SET_ERROR`
//! shifts by 16, and the failure path clears `JOIN_AWAIT` so a concurrent joiner retries
//! rather than blocking for ever. Both are transcribed; neither is reachable from
//! argon2, and both are what makes the state word's two halves mean what they say.
//!
//! **`pthread_attr_t` is a 56-byte, 8-aligned local.** The authority names the type;
//! here it is an opaque buffer of the size and alignment glibc gives it
//! (`union { char __size[56]; long __align; }`), because only one of its members is ever
//! touched and that is reached through this module's own `pthread_attr_*` bindings. A
//! wrong size would corrupt the stack, and the ABI court is what would catch a port.
//!
//! **What the module-level `allow` still covers.** `argon2` reaches
//! `ossl_crypto_thread_native_start`/`_join`/`_clean` and their `pthread_*` bindings, but
//! not every arm of the state word: `JOINED` set in the *error* half, the `JOIN_AWAIT`
//! retry and the `pthread_attr_*` shims are unreachable from any in-crate caller by
//! construction, and they are transcribed because the authority's own code is.
#![allow(dead_code)] // not every state-word arm and portability shim has a caller; see the note below

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;

use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    ossl_crypto_condvar_broadcast, ossl_crypto_condvar_free, ossl_crypto_condvar_new,
    ossl_crypto_condvar_signal, ossl_crypto_condvar_wait, ossl_crypto_mutex_free,
    ossl_crypto_mutex_lock, ossl_crypto_mutex_new, ossl_crypto_mutex_unlock, CryptoCondvar,
    CryptoMutex,
};

extern "C" {
    fn pthread_create(
        thread: *mut c_ulong,
        attr: *const c_void,
        start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> c_int;
    fn pthread_join(thread: c_ulong, retval: *mut *mut c_void) -> c_int;
    fn pthread_exit(retval: *mut c_void) -> !;
    fn pthread_attr_init(attr: *mut c_void) -> c_int;
    fn pthread_attr_destroy(attr: *mut c_void) -> c_int;
    fn pthread_attr_setdetachstate(attr: *mut c_void, state: c_int) -> c_int;
    fn pthread_self() -> c_ulong;
    fn pthread_equal(a: c_ulong, b: c_ulong) -> c_int;
}

/// `__FILE__` for `crypto/thread/arch.c`'s two allocation records.
const FILE_ARCH: *const c_char = c"../../src/openssl-3.6.4/crypto/thread/arch.c".as_ptr();
/// `arch.c`'s `OPENSSL_zalloc(sizeof(*handle))`.
const LINE_ARCH_ZALLOC: c_int = 21;
/// `arch.c`'s `OPENSSL_free(handle)`.
const LINE_ARCH_FREE: c_int = 43;
/// `__FILE__` for `crypto/thread/arch/thread_posix.c`'s two allocation records.
const FILE_POSIX: *const c_char =
    c"../../src/openssl-3.6.4/crypto/thread/arch/thread_posix.c".as_ptr();
/// `thread_posix.c`'s `OPENSSL_zalloc(sizeof(*handle))` in `native_spawn`.
const LINE_POSIX_ZALLOC: c_int = 41;
/// `thread_posix.c`'s `OPENSSL_free(handle)` in `native_spawn`'s failure path.
const LINE_POSIX_FREE: c_int = 59;

/// `PTHREAD_CREATE_DETACHED` — `pthread.h` on the admitted glibc profile.
const PTHREAD_CREATE_DETACHED: c_int = 1;

/// `CRYPTO_THREAD_RETVAL` — `include/internal/thread_arch.h:56`, `uint32_t`.
pub(crate) type CryptoThreadRetval = u32;

/// `CRYPTO_THREAD_ROUTINE` — `include/internal/thread_arch.h:57`. `Option` is the
/// FFI-safe spelling of the authority's possibly-NULL function pointer, and
/// [`ossl_crypto_thread_native_start`] is where the NULL is refused.
pub(crate) type CryptoThreadRoutine = unsafe extern "C" fn(*mut c_void) -> CryptoThreadRetval;

/// `CRYPTO_THREAD_NO_STATE` — `include/internal/thread_arch.h:62`. The authority defines
/// it and no arm writes it; transcribed so the four are readable as a set.
const CRYPTO_THREAD_NO_STATE: u32 = 0;
/// `CRYPTO_THREAD_FINISHED` — `include/internal/thread_arch.h:63`.
const CRYPTO_THREAD_FINISHED: u32 = 1 << 0;
/// `CRYPTO_THREAD_JOIN_AWAIT` — `include/internal/thread_arch.h:64`.
const CRYPTO_THREAD_JOIN_AWAIT: u32 = 1 << 1;
/// `CRYPTO_THREAD_JOINED` — `include/internal/thread_arch.h:65`.
const CRYPTO_THREAD_JOINED: u32 = 1 << 2;

/// `struct crypto_thread_st` — `include/internal/thread_arch.h:70-82`, member for member.
///
/// `CRYPTO_THREAD` is internal (`include/internal/thread_arch.h`, not installed), so its
/// layout is not itself observable -- but the state word is, through the two wait loops'
/// exit conditions, and the member set is what makes `native_join`'s concurrent-join path
/// mean anything. Transcribing the members is cheaper than reasoning about which of them
/// could be dropped.
#[repr(C)]
pub(crate) struct CryptoThread {
    /// `uint32_t state` — the four flags, with the two error copies at `<< 16`. Read and
    /// written only under `statelock`, which is why it is a plain word rather than an
    /// atomic: the authority's `CRYPTO_THREAD_GET_STATE` in the wait loops is inside the
    /// lock too, so a caller that read it without one would get a torn value in the
    /// authority as well.
    state: u32,
    /// `void *data` — the routine's argument, owned by the caller.
    data: *mut c_void,
    /// `CRYPTO_THREAD_ROUTINE routine`.
    routine: Option<CryptoThreadRoutine>,
    /// `CRYPTO_THREAD_RETVAL retval` — what the routine returned.
    retval: CryptoThreadRetval,
    /// `void *handle` — the `pthread_t` this layer allocated, or NULL.
    handle: *mut c_ulong,
    /// `CRYPTO_MUTEX *lock` — created and destroyed by this layer and free for the pool to
    /// use. Nothing this profile compiles takes it.
    lock: *mut CryptoMutex,
    /// `CRYPTO_MUTEX *statelock` — guards `state` and `retval`.
    statelock: *mut CryptoMutex,
    /// `CRYPTO_CONDVAR *condvar` — broadcast when the routine finishes, signalled when the
    /// join state moves.
    condvar: *mut CryptoCondvar,
    /// `unsigned long thread_id` — the authority's member; no arm this profile compiles
    /// writes it.
    thread_id: c_ulong,
    /// `int joinable` — 1 when the spawner will join.
    joinable: c_int,
    /// `OSSL_LIB_CTX *ctx` — set by the pool's `ossl_crypto_thread_start` and read by
    /// `ossl_crypto_thread_join` to find the same slot again.
    pub(crate) ctx: *mut c_void,
}

/// The object's destructor body, without the block release [`OwnedCtx`]'s `Drop` performs:
/// `native_clean`'s four member releases (`arch.c:113-144`).
///
/// Every member is NULL on the zeroed block `ossl_crypto_thread_native_start` allocates, and each
/// release is NULL-safe, so the body is written against the state the constructor's own failure
/// paths leave behind: the mutex/condvar members it did not get to set read NULL, and the
/// `pthread_t` block is released by [`OwnedThreadHandle`].
// SAFETY: (a) `destroy_body` is the authority's `native_clean` member body, releasing exactly this
// object's own mutex, state lock, condvar and `pthread_t` block once (each releaser accepts the
// unset NULL) and never the enclosing block, which `OwnedCtx` releases; (b) `CryptoThread` is a
// `#[repr(C)]` record of integers, raw pointers and `Option<fn>`, so an all-zero block is a valid
// `CryptoThread` the body is sound on.
unsafe impl CtxDestroy for CryptoThread {
    const FILE: *const c_char = FILE_ARCH;
    const LINE_ALLOC: c_int = LINE_ARCH_ZALLOC;
    const LINE_FREE: c_int = LINE_ARCH_FREE;

    unsafe fn destroy_body(ptr: *mut CryptoThread) {
        // SAFETY: `ptr` is a live object this unit allocated per the trait contract; the three
        // mutex/condvar members and the `pthread_t` block are each NULL or this unit's own.
        unsafe {
            ossl_crypto_mutex_free(ptr::addr_of_mut!((*ptr).lock));
            ossl_crypto_mutex_free(ptr::addr_of_mut!((*ptr).statelock));
            ossl_crypto_condvar_free(ptr::addr_of_mut!((*ptr).condvar));
            drop(OwnedThreadHandle::from_raw((*ptr).handle));
        }
    }
}

/// The separate `pthread_t` block `native_spawn` allocates (`thread_posix.c:41`) and `native_clean`
/// releases. It is a block apart from the [`CryptoThread`] object, so it has its own owner: the
/// object's `handle` member holds it between the spawn and the clean.
///
/// The block stays a `CRYPTO_zalloc` at the authority's own `file`/`line` (`FILE_POSIX`,
/// `LINE_POSIX_ZALLOC`) and is released at the authority's own failure-path coordinates
/// (`FILE_POSIX`, `LINE_POSIX_FREE`), so a caller-installed `CRYPTO_set_mem_functions` hook
/// observes both ends; only its *ownership* is this type.
struct OwnedThreadHandle {
    ptr: ptr::NonNull<c_ulong>,
}

impl OwnedThreadHandle {
    /// `CRYPTO_zalloc(sizeof(*handle), FILE_POSIX, LINE_POSIX_ZALLOC)`, or `None` when the
    /// allocator answers NULL.
    fn zalloc() -> Option<OwnedThreadHandle> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<c_ulong>()` bytes, which is exactly the `pthread_t` slot's layout.
        let raw = CRYPTO_zalloc(
            core::mem::size_of::<c_ulong>(),
            FILE_POSIX,
            LINE_POSIX_ZALLOC,
        )
        .cast::<c_ulong>();
        ptr::NonNull::new(raw).map(|ptr| OwnedThreadHandle { ptr })
    }

    /// The `pthread_t` slot `pthread_create`/`pthread_join` read and write.
    fn as_ptr(&self) -> *mut c_ulong {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the object that stores it in its `handle` member.
    fn into_raw(self) -> *mut c_ulong {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }

    /// Reclaim the block an object's `handle` member still holds, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or the block [`Self::zalloc`] produced and [`Self::into_raw`] gave the object;
    /// this handle's `Drop` is its single release.
    unsafe fn from_raw(ptr: *mut c_ulong) -> Option<OwnedThreadHandle> {
        ptr::NonNull::new(ptr).map(|ptr| OwnedThreadHandle { ptr })
    }
}

impl Drop for OwnedThreadHandle {
    /// The block's single release, through the same seam and the authority's own site.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `zalloc` allocated and has not handed out; its single
        // release is the authority's own plain `CRYPTO_free`.
        unsafe {
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                FILE_POSIX,
                LINE_POSIX_FREE,
            )
        };
    }
}

/// `static void *thread_start_thunk(void *vthread)` —
/// `crypto/thread/arch/thread_posix.c:18-33`.
///
/// The routine's return value is recorded **before** `FINISHED` is set and before the
/// broadcast, so a joiner that wakes on the broadcast always reads it: that order is the
/// reason the thunk takes the `statelock` at all rather than relying on the condition
/// variable alone.
extern "C" fn thread_start_thunk(vthread: *mut c_void) -> *mut c_void {
    let thread = vthread.cast::<CryptoThread>();

    // SAFETY: `vthread` is the `CRYPTO_THREAD` `pthread_create` was handed, and it
    // outlives this call because `native_clean` frees it only after `FINISHED` and
    // `JOINED`. The routine is non-NULL: `ossl_crypto_thread_native_start` refused a NULL
    // one before spawning this thread.
    unsafe {
        if let Some(routine) = (*thread).routine {
            let ret = routine((*thread).data);
            ossl_crypto_mutex_lock((*thread).statelock);
            (*thread).state |= CRYPTO_THREAD_FINISHED;
            (*thread).retval = ret;
            ossl_crypto_condvar_broadcast((*thread).condvar);
            ossl_crypto_mutex_unlock((*thread).statelock);
        }
    }

    ptr::null_mut()
}

/// `int ossl_crypto_thread_native_spawn(CRYPTO_THREAD *thread)` —
/// `crypto/thread/arch/thread_posix.c:35-61`.
///
/// # Safety
/// `thread` must be a live object whose `joinable`, `routine`, `condvar` and `statelock`
/// members are already set, and it must stay alive until the routine finishes.
unsafe fn ossl_crypto_thread_native_spawn(thread: *mut CryptoThread) -> c_int {
    // SAFETY: the caller's contract covers `thread` and every member read below.
    unsafe {
        // `pthread_t` is heap-allocated rather than stored inline: the authority allocates
        // it (`:41`) and `native_clean` frees `handle->handle` (`:238` of that file's own
        // numbering).
        let Some(handle) = OwnedThreadHandle::zalloc() else {
            (*thread).handle = ptr::null_mut();
            return 0;
        };

        // 56 bytes, 8-aligned: glibc's `pthread_attr_t`. Only `setdetachstate` touches it,
        // and only when the spawner will not join.
        let mut attr = [0u64; 7];
        pthread_attr_init(attr.as_mut_ptr().cast());
        if (*thread).joinable == 0 {
            pthread_attr_setdetachstate(attr.as_mut_ptr().cast(), PTHREAD_CREATE_DETACHED);
        }
        let ret = pthread_create(
            handle.as_ptr(),
            attr.as_ptr().cast(),
            thread_start_thunk,
            thread.cast(),
        );
        pthread_attr_destroy(attr.as_mut_ptr().cast());

        if ret != 0 {
            (*thread).handle = ptr::null_mut();
            // `handle` drops here, releasing the block exactly as the authority's own
            // `OPENSSL_free(handle)` does on this path.
            return 0;
        }

        (*thread).handle = handle.into_raw();
        1
    }
}

/// `int ossl_crypto_thread_native_perform_join(CRYPTO_THREAD *thread,
/// CRYPTO_THREAD_RETVAL *retval)` — `crypto/thread/arch/thread_posix.c:63-83`.
///
/// `retval` is **accepted and ignored**, exactly as in the authority's body: the thunk
/// already stored the routine's return value on the object, and this function's own
/// `thread_retval` is `pthread_join`'s answer, which the authority checks only for NULL
/// because a non-NULL one means the thread was cancelled.
///
/// # Safety
/// `thread` must be live, spawned joinable, and not already joined.
unsafe fn ossl_crypto_thread_native_perform_join(
    thread: *mut CryptoThread,
    _retval: *mut CryptoThreadRetval,
) -> c_int {
    if thread.is_null() {
        return 0;
    }
    // SAFETY: `thread` is live per the caller's contract.
    let handle = unsafe { (*thread).handle };
    if handle.is_null() {
        return 0;
    }

    let mut thread_retval: *mut c_void = ptr::null_mut();
    // SAFETY: `handle` is the `pthread_t` `native_spawn` allocated and has not been joined,
    // so `pthread_join` writes exactly one value into `thread_retval`.
    if unsafe { pthread_join(*handle, &mut thread_retval) } != 0 {
        return 0;
    }

    // A non-NULL return value means the thread was cancelled.
    c_int::from(thread_retval.is_null())
}

/// `int ossl_crypto_thread_native_exit(void)` — `crypto/thread/arch/thread_posix.c:85-89`.
/// Terminates the **calling** thread, so it never returns; the authority's trailing
/// `return 1` is unreachable and is recorded here rather than written as dead code.
///
/// # Safety
/// Ends the calling thread immediately, running no destructors for it.
unsafe fn ossl_crypto_thread_native_exit() -> c_int {
    // SAFETY: `pthread_exit` takes the calling thread's return value, NULL here.
    unsafe { pthread_exit(ptr::null_mut()) }
}

/// `int ossl_crypto_thread_native_is_self(CRYPTO_THREAD *thread)` —
/// `crypto/thread/arch/thread_posix.c:91-94`.
///
/// # Safety
/// `thread` must be live and spawned.
unsafe fn ossl_crypto_thread_native_is_self(thread: *mut CryptoThread) -> c_int {
    // SAFETY: `thread` is live and spawned per the contract, so `handle` is set.
    unsafe { pthread_equal(*(*thread).handle, pthread_self()) }
}

/// `CRYPTO_THREAD *ossl_crypto_thread_native_start(CRYPTO_THREAD_ROUTINE routine, void
/// *data, int joinable)` — `crypto/thread/arch.c:17-47`.
///
/// Returns NULL for a NULL routine, for a failed allocation, or when the spawn fails; in
/// the last two cases it releases whatever it did allocate. The object is zeroed first,
/// which is what makes the failure path's three frees NULL-safe.
///
/// # Safety
/// `routine` must be a function safe to run on another thread with `data`.
pub(crate) unsafe fn ossl_crypto_thread_native_start(
    routine: Option<CryptoThreadRoutine>,
    data: *mut c_void,
    joinable: c_int,
) -> *mut CryptoThread {
    let Some(routine) = routine else {
        return ptr::null_mut();
    };

    // `CRYPTO_zalloc(sizeof(*handle), FILE_ARCH, LINE_ARCH_ZALLOC)`: a zeroed block is this
    // object's own constructed state (every member is NULL or a plain word), which is the state
    // [`CtxDestroy::destroy_body`] is written against, so it may be validated immediately.
    let Some(handle) = OwnedCtx::<CryptoThread>::zalloc() else {
        return ptr::null_mut();
    };
    let ret = handle.as_ptr();

    // SAFETY: `ret` is this call's own zeroed allocation and no other thread can
    // observe it yet, so these are its only writes.
    unsafe {
        (*ret).lock = ossl_crypto_mutex_new();
        if (*ret).lock.is_null() {
            return ptr::null_mut();
        }
        (*ret).statelock = ossl_crypto_mutex_new();
        if (*ret).statelock.is_null() {
            return ptr::null_mut();
        }
        (*ret).condvar = ossl_crypto_condvar_new();
        if (*ret).condvar.is_null() {
            return ptr::null_mut();
        }

        (*ret).data = data;
        (*ret).routine = Some(routine);
        (*ret).joinable = joinable;

        if ossl_crypto_thread_native_spawn(ret) == 1 {
            return handle.into_raw();
        }
    }
    // `handle` drops here, running the authority's own `err:`-path release: the members it did
    // set, the `pthread_t` block (NULL when `native_spawn` failed) and the object's block.
    ptr::null_mut()
}

/// `CRYPTO_THREAD_GET_STATE(THREAD, FLAG)` — `include/internal/thread_arch.h:67`, the
/// read half of the state word.
///
/// Written as a function rather than inlined at each use so the two wait loops read as
/// "until the state says so" and so a lint that looks for a loop variable mutated in the
/// body does not have to be silenced: the mutation is on the **other** thread, under this
/// same lock.
///
/// # Safety
/// The caller must hold `thread`'s `statelock`.
unsafe fn thread_state(thread: *mut CryptoThread) -> u32 {
    // SAFETY: the caller holds `statelock` per the contract, which is the lock the thunk
    // writes the word under.
    unsafe { (*thread).state }
}

/// `int ossl_crypto_thread_native_join(CRYPTO_THREAD *thread, CRYPTO_THREAD_RETVAL
/// *retval)` — `crypto/thread/arch.c:49-111`.
///
/// The three states matter and each is transcribed: a thread already `FINISHED` is waited
/// for, a thread already `JOINED` answers immediately from the stored `retval`, and a
/// thread another caller is joining (`JOIN_AWAIT`) is **waited on rather than joined**,
/// because `pthread_join` may be called only once. The failure path leaves `JOINED` in the
/// **error half** of the state word and clears `JOIN_AWAIT`, so a concurrent joiner
/// retries rather than blocking for ever.
///
/// # Safety
/// `thread` must be live and spawned joinable; `retval` must be NULL or writable.
pub(crate) unsafe fn ossl_crypto_thread_native_join(
    thread: *mut CryptoThread,
    retval: *mut CryptoThreadRetval,
) -> c_int {
    if thread.is_null() {
        return 0;
    }

    // SAFETY: `thread` is live per the caller's contract, so this is its own mutex and
    // condition variable. Every read of `state` is inside the same block, because the
    // thunk writes it under this same lock.
    unsafe {
        let statelock = (*thread).statelock;
        let condvar = (*thread).condvar;
        ossl_crypto_mutex_lock(statelock);

        let req_state_mask = CRYPTO_THREAD_FINISHED | CRYPTO_THREAD_JOINED;
        while thread_state(thread) & req_state_mask == 0 {
            ossl_crypto_condvar_wait(condvar, statelock);
        }

        if thread_state(thread) & CRYPTO_THREAD_JOINED == 0 {
            // Await concurrent join completion, if any.
            loop {
                if thread_state(thread) & CRYPTO_THREAD_JOIN_AWAIT == 0 {
                    break;
                }
                if thread_state(thread) & CRYPTO_THREAD_JOINED == 0 {
                    ossl_crypto_condvar_wait(condvar, statelock);
                }
                if thread_state(thread) & CRYPTO_THREAD_JOINED != 0 {
                    break;
                }
            }

            if thread_state(thread) & CRYPTO_THREAD_JOINED == 0 {
                (*thread).state |= CRYPTO_THREAD_JOIN_AWAIT;
                ossl_crypto_mutex_unlock(statelock);

                if ossl_crypto_thread_native_perform_join(thread, retval) == 0 {
                    ossl_crypto_mutex_lock(statelock);
                    (*thread).state |= CRYPTO_THREAD_JOINED << 16;
                    (*thread).state &= !CRYPTO_THREAD_JOIN_AWAIT;
                    ossl_crypto_condvar_signal(condvar);
                    ossl_crypto_mutex_unlock(statelock);
                    return 0;
                }

                ossl_crypto_mutex_lock(statelock);
            }
        }

        (*thread).state &= !(CRYPTO_THREAD_JOINED << 16);
        (*thread).state |= CRYPTO_THREAD_JOINED;
        // Signalled even when no actual join was performed: several callers can be waiting
        // for the `JOIN_AWAIT -> JOINED` transition, and signalling only on completion
        // would wake one of them.
        ossl_crypto_condvar_signal(condvar);
        ossl_crypto_mutex_unlock(statelock);

        if !retval.is_null() {
            *retval = (*thread).retval;
        }
    }
    1
}

/// `int ossl_crypto_thread_native_clean(CRYPTO_THREAD *handle)` —
/// `crypto/thread/arch.c:113-144`.
///
/// Refuses a thread whose state has **neither** `FINISHED` nor `JOINED` set -- the guard
/// against freeing an object a *running* routine still owns. A thread that has finished is
/// cleanable whether or not anything joined it, because the authority's test is
/// `state & (FINISHED | JOINED) == 0` and not an equality against both flags. Returns 1
/// only when it actually freed.
///
/// # Safety
/// `handle` must be NULL or a live value returned by
/// [`ossl_crypto_thread_native_start`], with no waiter on its condition variable.
pub(crate) unsafe fn ossl_crypto_thread_native_clean(handle: *mut CryptoThread) -> c_int {
    if handle.is_null() {
        return 0;
    }

    // SAFETY: `handle` is live per the caller's contract.
    unsafe {
        let req_state_mask = CRYPTO_THREAD_FINISHED | CRYPTO_THREAD_JOINED;
        ossl_crypto_mutex_lock((*handle).statelock);
        let cleanable = thread_state(handle) & req_state_mask != 0;
        ossl_crypto_mutex_unlock((*handle).statelock);
        if !cleanable {
            return 0;
        }

        // The state check above is the authority's own cleanable guard; it passed, so the object
        // is reclaimed for release by `Drop`, whose [`CtxDestroy::destroy_body`] is the
        // authority's own `native_clean` body -- the three member releases and the `pthread_t`
        // block, each NULL-safe because `FINISHED` may have been reached through the
        // already-joined path -- followed by the object's single block release.
        // SAFETY: `handle` is the live object `ossl_crypto_thread_native_start` returned and no
        // owner has released it.
        drop(OwnedCtx::<CryptoThread>::from_raw(handle));
    }
    1
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(CryptoThread => zero_state_sweep_crypto_thread);
