//! Phase 6.6e-ii — `crypto/initthread.c`: the per-thread event-handler table.
//!
//! The library needs to be told when a thread that has used it stops, so that per-thread
//! state it handed out can be released. `ossl_init_thread_start(index, arg, handfn)`
//! registers such a handler; the handler runs when the thread exits, or earlier if
//! [`OPENSSL_thread_stop`] is called explicitly.
//!
//! ## Two structures, and why both are needed
//!
//! The handlers live in a **thread-local singly linked list**, reached through one
//! `CRYPTO_THREAD_LOCAL` key. That is the list `init_thread_stop` walks.
//!
//! A **global register** holds every thread's list-head pointer, so that a handler can be
//! *deregistered* before its owner disappears: `ossl_init_thread_deregister(prov)` is what
//! `ossl_provider_free` calls, and without the global register a thread that still held a
//! handler referring to the freed provider would call it at exit. That is the whole reason
//! the register exists, and it is why the two are written together.
//!
//! ## The list is LIFO, so handlers run in reverse registration order
//!
//! `ossl_init_thread_start` pushes at the head, and `init_thread_stop` walks from the head.
//! That is observable and is pinned by the court rather than left to the reader.
//!
//! `init_thread_stop`'s walk **unlinks as it goes**, which has a consequence worth stating:
//! a handler that registers another handler during its own run does not have the new one
//! called by the same stop, because the walk holds a cursor and the new node is behind it.
//!
//! ## `arg` filters, and the one caller that uses it for something other than a context
//!
//! `init_thread_stop(arg, hands)` calls only the handlers whose `arg` matches, and
//! `ossl_ctx_thread_stop(ctx)` is the caller that passes one — it stops the handlers
//! registered *for that context*. Note that the filter is on `hand->arg` and **not** on
//! `hand->index`: `index` is the deregistration key (`ossl_init_thread_start`'s first
//! parameter, which every caller in this build passes as the owning object), and the two are
//! different fields with different purposes. A reader who conflated them would deregister by
//! context.
//!
//! ## `destructor_key` is a union in C and two fields here
//!
//! `crypto/initthread.c` declares
//!
//! ```c
//! static union { long sane; CRYPTO_THREAD_LOCAL value; } destructor_key = { -1 };
//! ```
//!
//! and reads `destructor_key.sane != -1` as "the key has been created". The union is a
//! packing trick: writing the four-byte `value` leaves the eight-byte `sane` reading
//! `0xFFFFFFFF_<key>`, which is not `-1`, so the guard flips as a side effect of the write
//! it guards. It is reproduced here as **two named fields with the same sentinel and the
//! same two transition points**, because that is what the guard's answer is: unset until
//! `ossl_init_thread_once` has created the key, set afterwards, and unset again by
//! `ossl_cleanup_thread`. The one reading where the union's overlap could differ is a key
//! whose value is `0xFFFFFFFF` *and* whose high half was never written — the guard would
//! then answer "unset" after the key existed — and that is unreachable, because the profile's
//! `pthread_key_t` values are small integers.
//!
//! `ossl_cleanup_thread` resetting the sentinel is not decoration: it is what makes the
//! shim refuse to touch a key after `OPENSSL_cleanup`, and it is why `OPENSSL_thread_stop`
//! and `ossl_ctx_thread_stop` both guard on it.
//!
//! ## The FIPS branches are not written, and are not missing
//!
//! Every `#ifdef FIPS_MODULE` in this file belongs to a build this profile is not: the
//! per-context `CRYPTO_THREAD_LOCAL_TEVENT_KEY`, `ossl_thread_register_fips`,
//! `ossl_arg_thread_stop`, and the second copy of `ossl_ctx_thread_stop` that calls it. In
//! this build there is **one** thread-local key and one `init_thread_stop`, and the
//! `ossl_*_local_ex` family has no counterpart here. That is a build fact from
//! `configdata.pm` and not a simplification.
//!
//! ## Allocation coordinates
//!
//! `file` and `line` are the authority's own, from `crypto/initthread.c`, for the reason
//! every other module records them: Phase 3's memory-debug court reads them back.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicPtr, Ordering};

use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_get_local, CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new,
    CRYPTO_THREAD_run_once, CRYPTO_THREAD_set_local, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock, CryptoThreadLocal,
};

/// The authority's translation unit, so a failing allocation records its coordinates.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/initthread.c".as_ptr();

/// `typedef void (*OSSL_thread_stop_handler_fn)(void *arg)` — `openssl/crypto.h`.
///
/// Unnamed parameters, for the reason `ProviderInitFn` states: `ABI-PROTOTYPE` reads a
/// function pointer's *types*, and a named argument is not one.
pub(crate) type ThreadStopHandlerFn = unsafe extern "C" fn(*mut c_void);

/// `typedef struct thread_event_handler_st THREAD_EVENT_HANDLER` — `crypto/initthread.c`.
///
/// The order is the authority's, and it is load-bearing for `index`: the field exists only
/// in the non-FIPS build, which is this one.
#[repr(C)]
pub(crate) struct ThreadEventHandler {
    /// The deregistration key, passed by the registering caller. Not the context.
    pub(crate) index: *const c_void,
    /// The argument the handler is called with, and the field `init_thread_stop` filters on.
    pub(crate) arg: *mut c_void,
    /// The handler itself.
    pub(crate) handfn: Option<ThreadStopHandlerFn>,
    /// The next handler in this thread's list, or NULL.
    pub(crate) next: *mut ThreadEventHandler,
}

/// `GLOBAL_TEVENT_REGISTER` — `crypto/initthread.c`.
///
/// `skhands` is a stack of **`THREAD_EVENT_HANDLER **`** — pointers to each thread's
/// list-head variable — so that deregistration can rewrite a list another thread owns. The
/// authority types it `DEFINE_SPECIAL_STACK_OF`; this crate's `OpenSslStack` is untyped and
/// stores `*const c_void`, which is the same thing once the elements are cast.
#[repr(C)]
pub(crate) struct GlobalTeventRegister {
    /// The stack of per-thread list heads.
    pub(crate) skhands: *mut OpenSslStack,
    /// Guards `skhands`.
    pub(crate) lock: *mut CryptoRwlock,
}

/// The creation coordinates, gathered so the whole set can be compared at once.
mod lines {
    #![allow(dead_code)] // the failure arms are unreachable without an allocation failure
    use core::ffi::c_int;

    /// `create_global_tevent_register`'s `OPENSSL_zalloc`.
    pub(super) const L_GTR_NEW: c_int = 61;
    /// `create_global_tevent_register`'s `OPENSSL_free(glob_tevent_reg)`.
    pub(super) const L_GTR_ERR: c_int = 70;
    /// `manage_thread_local`'s `OPENSSL_zalloc(sizeof(*hands))`.
    pub(super) const L_HANDS_ALLOC: c_int = 153;
    /// `manage_thread_local`'s two error-arm frees, in the authority's order.
    pub(super) const L_HANDS_SET_ERR: c_int = 157;
    /// `manage_thread_local`'s `OPENSSL_free(hands)` after a failed push.
    pub(super) const L_HANDS_PUSH_ERR: c_int = 163;
    /// `init_thread_destructor`'s `OPENSSL_free(hands)`.
    pub(super) const L_DESTRUCTOR_FREE: c_int = 246;
    /// `ossl_ctx_thread_stop`'s `OPENSSL_free(hands)`.
    pub(super) const L_CTX_STOP_FREE: c_int = 362;
    /// `init_thread_stop`'s `OPENSSL_free(tmp)`.
    pub(super) const L_STOP_FREE_HAND: c_int = 402;
    /// `ossl_init_thread_start`'s `OPENSSL_malloc(sizeof(*hand))`.
    pub(super) const L_HAND_NEW: c_int = 442;
    /// `init_thread_deregister`'s `OPENSSL_free(tmp)`.
    pub(super) const L_DEREG_FREE_HAND: c_int = 491;
    /// `init_thread_deregister`'s `OPENSSL_free(hands)` on the `all` path.
    pub(super) const L_DEREG_FREE_HANDS: c_int = 498;
}

// ---------------------------------------------------------------------------
// `destructor_key`: the key that reaches this thread's handler list
// ---------------------------------------------------------------------------

/// `destructor_key.sane` — the sentinel. `-1` means the key has not been created.
///
/// See the module note on why this is a field and not half of a union.
static DESTRUCTOR_SANE: AtomicI64 = AtomicI64::new(-1);
/// `destructor_key.value` — the thread-local key.
///
/// A `UnsafeCell` rather than an atomic, because `CRYPTO_THREAD_init_local` hands the
/// *address* to `pthread_key_create`, which writes it, and the two accessors hand the same
/// address to the pthread specific get/set. The address must therefore be stable and the
/// storage `CryptoThreadLocal`-shaped; the concurrency is the key's own, and pthread
/// guarantees it.
struct KeyCell(core::cell::UnsafeCell<CryptoThreadLocal>);

// SAFETY: the cell holds a `pthread_key_t` written exactly once, by `ossl_init_thread_once`
// under a run-once, and read afterwards only by the pthread key APIs themselves, which are
// thread-safe. Nothing here reads or writes it outside those paths.
unsafe impl Sync for KeyCell {}

static DESTRUCTOR_VALUE: KeyCell = KeyCell(core::cell::UnsafeCell::new(0));
/// `static CRYPTO_ONCE ossl_init_thread_runonce = CRYPTO_ONCE_STATIC_INIT`.
///
/// An `AtomicI32` rather than a bare `static`, because `pthread_once` **writes through** the
/// pointer it is given: a `static CryptoOnce = 0` lands in read-only storage and the write
/// faults. This is the crate's pattern for every `CRYPTO_ONCE` (`context/mod.rs`'s
/// `DEFAULT_CONTEXT_INIT` is the same shape), and it is not merely defensive — the first
/// version of this file used a bare static and `OSSL_LIB_CTX_new()` segfaulted.
static INIT_THREAD_RUNONCE: AtomicI32 = AtomicI32::new(0);

/// `static int destructor_key_sane(void)` — the authority's `destructor_key.sane != -1`.
fn destructor_key_sane() -> bool {
    DESTRUCTOR_SANE.load(Ordering::Acquire) != -1
}

/// The key, as a pointer, for the two accessors. Only meaningful when [`destructor_key_sane`].
fn destructor_key_ptr() -> *mut CryptoThreadLocal {
    DESTRUCTOR_VALUE.0.get()
}

/// A **test-only** re-arm of the machinery, for the one case a process cannot have: the
/// library has been cleaned up and a later test in the same process needs a live handler
/// table.
///
/// After `OPENSSL_cleanup` the library is dead by contract — `OPENSSL_init_crypto` refuses
/// from then on, and `ossl_cleanup_thread` releases the key, frees the global register and
/// resets the sentinel, so `ossl_init_thread_start` answers 0. That is correct behaviour and
/// it is what a consumer observes; what it makes impossible is a *unit test*, because libtest
/// runs every test in the crate in one process and cannot promise that the cleanup test runs
/// last.
///
/// So the tests re-arm: both run-onces are reset, the sentinel goes back to `-1`, and
/// `ossl_init_thread` is called once more. That creates a **second** pthread key and leaks the
/// first, which is harmless, unreachable in the product, and the price of testing this
/// machinery in a crate whose own cleanup test is irreversible.
#[cfg(test)]
pub(crate) fn rearm_for_test() {
    TEVENT_REGISTER_RUNONCE.store(0, Ordering::Release);
    INIT_THREAD_RUNONCE.store(0, Ordering::Release);
    DESTRUCTOR_SANE.store(-1, Ordering::Release);
    GLOB_TEVENT_REG.store(ptr::null_mut(), Ordering::Release);
    assert_eq!(
        ossl_init_thread(),
        1,
        "the machinery must re-arm for a test"
    );
    // **The thread's own local has to be cleared, and that is why this function is not just
    // four stores.** `ossl_cleanup_thread` frees every list head but cannot clear the thread
    // locals that pointed at them -- it presumes the threads are gone, which is true in the
    // product and false here. Worse, `pthread_key_create` after a `pthread_key_delete`
    // routinely hands back the **same key number**, and glibc's per-thread value array for that
    // number is not cleared by the delete, so the new key can read the old, freed head. The
    // two tests that ran after the cleanup test observed exactly that: a dangling head was
    // taken as this thread's live list, and the registration was answered 0. Clearing the local
    // under the new key makes the re-arm total.
    // SAFETY: the key was just created by `ossl_init_thread`, and NULL is a legal value.
    let _ = unsafe {
        crate::runtime::thread::CRYPTO_THREAD_set_local(destructor_key_ptr(), ptr::null_mut())
    };
}

// ---------------------------------------------------------------------------
// The global register
// ---------------------------------------------------------------------------

/// `static GLOBAL_TEVENT_REGISTER *glob_tevent_reg = NULL`.
///
/// A `static mut` in the authority, an atomic pointer here. `init_thread_deregister(NULL, 1)`
/// writes NULL to it, which is the one place it is cleared without the register's own lock.
static GLOB_TEVENT_REG: AtomicPtr<GlobalTeventRegister> = AtomicPtr::new(ptr::null_mut());

/// `static CRYPTO_ONCE tevent_register_runonce = CRYPTO_ONCE_STATIC_INIT`.
///
/// An `AtomicI32` for the reason `INIT_THREAD_RUNONCE` states: `pthread_once` writes through
/// its argument.
static TEVENT_REGISTER_RUNONCE: AtomicI32 = AtomicI32::new(0);

/// `DEFINE_RUN_ONCE_STATIC(create_global_tevent_register)`.
///
/// The three allocations are made **before** either is checked, and the failure arm releases
/// both whatever the order, which is why the two `sk`/`lock` frees are unconditional there.
extern "C" fn create_global_tevent_register() {
    // `CRYPTO_zalloc` is a SAFE function in this crate (D113), so this is unguarded.
    let gtr = CRYPTO_zalloc(
        core::mem::size_of::<GlobalTeventRegister>(),
        FILE,
        lines::L_GTR_NEW,
    )
    .cast::<GlobalTeventRegister>();
    if gtr.is_null() {
        return;
    }
    // SAFETY: `gtr` is a fresh, owned block, so both field writes are to owned storage.
    unsafe {
        (*gtr).skhands = OPENSSL_sk_new_null();
        (*gtr).lock = CRYPTO_THREAD_lock_new();
        if (*gtr).skhands.is_null() || (*gtr).lock.is_null() {
            OPENSSL_sk_free((*gtr).skhands);
            CRYPTO_THREAD_lock_free((*gtr).lock);
            CRYPTO_free(gtr.cast::<c_void>(), FILE, lines::L_GTR_ERR);
            return;
        }
    }
    GLOB_TEVENT_REG.store(gtr, Ordering::Release);
}

/// `static GLOBAL_TEVENT_REGISTER *get_global_tevent_register(void)`.
fn get_global_tevent_register() -> *mut GlobalTeventRegister {
    // SAFETY: `create_global_tevent_register` is a valid `extern "C"` initialiser with no
    // parameters, which is what the run-once requires; the `once` pointer is this module's own
    // storage.
    if unsafe {
        CRYPTO_THREAD_run_once(
            TEVENT_REGISTER_RUNONCE.as_ptr(),
            Some(create_global_tevent_register),
        )
    } == 0
    {
        return ptr::null_mut();
    }
    GLOB_TEVENT_REG.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// The thread-local list head
// ---------------------------------------------------------------------------

/// `static THREAD_EVENT_HANDLER **get_thread_event_handler(OSSL_LIB_CTX *ctx)`.
///
/// `ctx` is accepted and unused in this build: the FIPS build keys the list on the context
/// as well as the thread, and the non-FIPS build does not.
fn get_thread_event_handler(_ctx: *mut c_void) -> *mut *mut ThreadEventHandler {
    if !destructor_key_sane() {
        return ptr::null_mut();
    }
    // SAFETY: the key is live per the guard above, which is the same contract the authority's
    // `CRYPTO_THREAD_get_local` call has.
    unsafe { CRYPTO_THREAD_get_local(destructor_key_ptr()).cast::<*mut ThreadEventHandler>() }
}

/// `static int set_thread_event_handler(OSSL_LIB_CTX *ctx, THREAD_EVENT_HANDLER **hands)`.
fn set_thread_event_handler(_ctx: *mut c_void, hands: *mut *mut ThreadEventHandler) -> c_int {
    if !destructor_key_sane() {
        return 0;
    }
    // SAFETY: as `get_thread_event_handler`.
    unsafe { CRYPTO_THREAD_set_local(destructor_key_ptr(), hands.cast::<c_void>()) }
}

/// `static THREAD_EVENT_HANDLER **manage_thread_local(OSSL_LIB_CTX *ctx, int alloc, int keep)`.
///
/// Three callers, three behaviours, and the two flags are the whole of it:
///
/// * `alloc = 1, keep = 0` — allocate the head if absent, and register it in the global
///   register, so `init_thread_deregister` can reach it.
/// * `alloc = 0, keep = 1` — fetch without allocating and without clearing.
/// * `alloc = 0, keep = 0` — clear the thread's local and answer what it held.
///
/// The register push can fail, and the authority then clears the thread local again and
/// releases the head: a thread whose list is not in the register can never be deregistered,
/// so the failure is made total rather than partial.
fn manage_thread_local(ctx: *mut c_void, alloc: bool, keep: bool) -> *mut *mut ThreadEventHandler {
    let mut hands = get_thread_event_handler(ctx);

    if alloc {
        if hands.is_null() {
            // SAFETY: a fresh zeroed block of exactly this type.
            hands = CRYPTO_zalloc(
                core::mem::size_of::<*mut ThreadEventHandler>(),
                FILE,
                lines::L_HANDS_ALLOC,
            )
            .cast::<*mut ThreadEventHandler>();
            if hands.is_null() {
                return ptr::null_mut();
            }
            if set_thread_event_handler(ctx, hands) == 0 {
                // SAFETY: `hands` is this function's own allocation.
                unsafe { CRYPTO_free(hands.cast::<c_void>(), FILE, lines::L_HANDS_SET_ERR) };
                return ptr::null_mut();
            }
            if !init_thread_push_handlers(hands) {
                set_thread_event_handler(ctx, ptr::null_mut());
                // SAFETY: `hands` is this function's own allocation, and the failed push left
                // the register untouched, so nothing else holds it.
                unsafe { CRYPTO_free(hands.cast::<c_void>(), FILE, lines::L_HANDS_PUSH_ERR) };
                return ptr::null_mut();
            }
        }
    } else if !keep {
        set_thread_event_handler(ctx, ptr::null_mut());
    }

    hands
}

/// `static ossl_inline THREAD_EVENT_HANDLER **clear_thread_local(OSSL_LIB_CTX *ctx)`.
fn clear_thread_local(ctx: *mut c_void) -> *mut *mut ThreadEventHandler {
    manage_thread_local(ctx, false, false)
}

/// `static ossl_inline THREAD_EVENT_HANDLER **alloc_thread_local(OSSL_LIB_CTX *ctx)`.
fn alloc_thread_local(ctx: *mut c_void) -> *mut *mut ThreadEventHandler {
    manage_thread_local(ctx, true, false)
}

// ---------------------------------------------------------------------------
// The register's two operations
// ---------------------------------------------------------------------------

/// `static int init_thread_push_handlers(THREAD_EVENT_HANDLER **hands)`.
///
/// The element is the **address of the list head**, not the head itself: deregistration has
/// to be able to rewrite another thread's head.
fn init_thread_push_handlers(hands: *mut *mut ThreadEventHandler) -> bool {
    let gtr = get_global_tevent_register();
    if gtr.is_null() {
        return false;
    }
    // SAFETY: `gtr` is live and non-NULL, so its lock and stack are live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*gtr).lock) == 0 {
            return false;
        }
        let ret = OPENSSL_sk_push((*gtr).skhands, hands.cast::<c_void>()) != 0;
        CRYPTO_THREAD_unlock((*gtr).lock);
        ret
    }
}

/// `static void init_thread_remove_handlers(THREAD_EVENT_HANDLER **handsin)`.
///
/// A linear search for the exact head pointer, and the **first** match wins. A head pushed
/// twice would leave the second entry behind, which is the authority's behaviour and cannot
/// happen because `manage_thread_local` pushes only on a fresh allocation.
fn init_thread_remove_handlers(handsin: *mut *mut ThreadEventHandler) {
    let gtr = get_global_tevent_register();
    if gtr.is_null() {
        return;
    }
    // SAFETY: `gtr` is live and non-NULL, so its lock and stack are live.
    unsafe {
        if CRYPTO_THREAD_write_lock((*gtr).lock) == 0 {
            return;
        }
        let n = OPENSSL_sk_num((*gtr).skhands);
        let mut i = 0;
        while i < n {
            let hands = OPENSSL_sk_value((*gtr).skhands, i).cast::<*mut ThreadEventHandler>();
            if hands == handsin {
                OPENSSL_sk_delete((*gtr).skhands, i);
                CRYPTO_THREAD_unlock((*gtr).lock);
                return;
            }
            i += 1;
        }
        CRYPTO_THREAD_unlock((*gtr).lock);
    }
}

// ---------------------------------------------------------------------------
// `ossl_init_thread` and the destructor
// ---------------------------------------------------------------------------

/// `DEFINE_RUN_ONCE_STATIC(ossl_init_thread_once)` — create the key, once.
extern "C" fn ossl_init_thread_once() {
    // SAFETY: `ossl_thread_init_local` creates the key; `init_thread_destructor` is a valid
    // `extern "C"` cleanup for it. The key's storage is the atomic's address, which outlives
    // the key.
    let ok = unsafe { ossl_thread_init_local(destructor_key_ptr(), Some(init_thread_destructor)) };
    if ok == 0 {
        return;
    }
    // The sentinel flips here, and only here, on the success path. The authority achieves
    // the same by writing the union's `value` field and reading `sane`.
    // SAFETY: the run-once means this is the only reader, and `thread_key_create` has just
    // written the key through the same pointer.
    let key = unsafe { *destructor_key_ptr() };
    DESTRUCTOR_SANE.store(i64::from(key), Ordering::Release);
}

/// `int ossl_init_thread(void)`.
///
/// Answers 0 only when the run-once did not succeed, which is a key-creation failure. It is
/// called from `CRYPTO_THREAD_init_local` before the caller's own key is created, so a
/// failure here refuses the caller's key too — which is why the crate's `CRYPTO_THREAD_init_local`
/// carries the marker for this call.
pub(crate) fn ossl_init_thread() -> c_int {
    // SAFETY: `ossl_init_thread_once` is a valid `extern "C"` initialiser with no parameters,
    // which is what the run-once requires; the `once` pointer is this module's own storage.
    if unsafe { CRYPTO_THREAD_run_once(INIT_THREAD_RUNONCE.as_ptr(), Some(ossl_init_thread_once)) }
        == 0
    {
        return 0;
    }
    1
}

/// `int ossl_thread_init_local(CRYPTO_THREAD_LOCAL *key, void (*cleanup)(void *))`.
///
/// The authority has this as a separate function over `pthread_key_create`; this crate had
/// folded it into [`crate::runtime::thread::CRYPTO_THREAD_init_local`]. The fold stays, and
/// this is the seam the fold calls *through* so that `CRYPTO_THREAD_init_local` can run
/// `ossl_init_thread` first without recursing into itself.
///
/// # Safety
/// `key` must be NULL or valid, writable storage; `cleanup` a valid destructor or NULL.
pub(crate) unsafe fn ossl_thread_init_local(
    key: *mut CryptoThreadLocal,
    cleanup: Option<extern "C" fn(*mut c_void)>,
) -> c_int {
    // SAFETY: the caller's contract is this function's contract.
    unsafe { crate::runtime::thread::thread_key_create(key, cleanup) }
}

/// `static void init_thread_destructor(void *hands)`.
///
/// The thread-exit path: stop this thread's handlers, drop its head from the register, and
/// release the head. It is reached from the pthread key destructor, so it runs on a thread
/// that is going away and must not allocate.
extern "C" fn init_thread_destructor(hands: *mut c_void) {
    let heads = hands.cast::<*mut ThreadEventHandler>();
    // SAFETY: `heads` is the value the key held, which is a head this module allocated.
    unsafe {
        init_thread_stop(ptr::null_mut(), heads);
        init_thread_remove_handlers(heads);
        CRYPTO_free(heads.cast::<c_void>(), FILE, lines::L_DESTRUCTOR_FREE);
    }
}

/// `void ossl_cleanup_thread(void)`.
///
/// Called from `OPENSSL_cleanup`. It deregisters **every** handler and drops the register
/// itself, then releases the key and resets the sentinel — so after this the shim refuses to
/// touch the key at all, which is what `OPENSSL_thread_stop`'s and `ossl_ctx_thread_stop`'s
/// guards observe.
pub(crate) fn ossl_cleanup_thread() {
    let gtr = get_global_tevent_register();
    if !gtr.is_null() {
        // SAFETY: `gtr` is live. `all = 1` frees it, so nothing else may use it afterwards.
        unsafe { init_thread_deregister(ptr::null_mut(), true, gtr) };
    }
    // SAFETY: the key is live if the sentinel says so; the call is harmless otherwise because
    // it is guarded here rather than inside.
    if destructor_key_sane() {
        // SAFETY: the key was created by `ossl_init_thread_once` and has not been released.
        unsafe { crate::runtime::thread::thread_key_free(destructor_key_ptr()) };
    }
    DESTRUCTOR_SANE.store(-1, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Registration and deregistration
// ---------------------------------------------------------------------------

/// `int ossl_init_thread_start(const void *index, void *arg, OSSL_thread_stop_handler_fn handfn)`.
///
/// Pushes at the **head**, so handlers run in reverse registration order. `index` is stored
/// only for deregistration; `arg` is what the handler is called with and what
/// `init_thread_stop` filters on.
///
/// The list head is allocated on first use for this thread, which is also what puts the head
/// into the global register — so a handler registered from a thread is always reachable by
/// `ossl_init_thread_deregister` afterwards.
///
/// # Safety
/// `index` is an opaque deregistration key (NULL is legal and is what RCU passes); `arg` is
/// handed to `handfn` unchanged.
pub(crate) unsafe fn ossl_init_thread_start(
    index: *const c_void,
    arg: *mut c_void,
    handfn: Option<ThreadStopHandlerFn>,
) -> c_int {
    // `ctx` is NULL in this build: the non-FIPS list is per thread and not per context.
    // SAFETY: `alloc_thread_local` takes a context it ignores here.
    let hands = alloc_thread_local(ptr::null_mut());
    if hands.is_null() {
        return 0;
    }

    // SAFETY: a fresh block of exactly this type.
    let hand = CRYPTO_malloc(
        core::mem::size_of::<ThreadEventHandler>(),
        FILE,
        lines::L_HAND_NEW,
    )
    .cast::<ThreadEventHandler>();
    if hand.is_null() {
        return 0;
    }
    // SAFETY: `hands` is live (it was just allocated and registered), so `*hands` is a live
    // head slot; `hand` is this function's own allocation.
    unsafe {
        (*hand).handfn = handfn;
        (*hand).arg = arg;
        (*hand).index = index;
        (*hand).next = *hands;
        *hands = hand;
    }
    1
}

/// `int ossl_init_thread_deregister(void *index)`.
///
/// Removes every handler whose `index` matches, across **all** threads, and answers 0 when
/// the register could not be taken or a thread's head is NULL.
///
/// This is the function `ossl_provider_free` calls unconditionally, and the authority's
/// comment there is why it is unconditional: *"We deregister thread handling whether or not
/// the provider was initialized. If init was attempted but was not successful then the
/// provider may still have registered a thread handler."* A provider that failed to
/// initialise can therefore still have a registered handler, and skipping this call would
/// leave a dangling one that runs at thread exit.
///
/// # Safety
/// `index` is an opaque key previously passed to `ossl_init_thread_start`.
pub(crate) fn ossl_init_thread_deregister(index: *const c_void) -> c_int {
    let gtr = get_global_tevent_register();
    if gtr.is_null() {
        return 0;
    }
    // SAFETY: `gtr` is live and non-NULL.
    unsafe { init_thread_deregister(index, false, gtr) }
}

/// `static int init_thread_deregister(void *index, int all)`.
///
/// `all` is the `ossl_cleanup_thread` path: every handler in every list is removed, each
/// list head is released, and then the register's own lock and stack and the register are
/// released. It **does not clear the thread locals that point at those heads**, which is the
/// authority's behaviour: the threads are presumed gone by then.
///
/// # Safety
/// `gtr` must be live and non-NULL. When `all` is true it is released, so the caller must not
/// use it afterwards.
unsafe fn init_thread_deregister(
    index: *const c_void,
    all: bool,
    gtr: *mut GlobalTeventRegister,
) -> c_int {
    // SAFETY: `gtr` is live per this function's contract.
    unsafe {
        if !all {
            if CRYPTO_THREAD_write_lock((*gtr).lock) == 0 {
                return 0;
            }
        } else {
            // The authority assigns NULL to the global before walking, so a handler that
            // somehow calls back into `get_global_tevent_register` creates a fresh register
            // rather than re-entering one that is being torn down.
            GLOB_TEVENT_REG.store(ptr::null_mut(), Ordering::Release);
        }

        let n = OPENSSL_sk_num((*gtr).skhands);
        let mut i = 0;
        while i < n {
            let hands = OPENSSL_sk_value((*gtr).skhands, i).cast::<*mut ThreadEventHandler>();
            if hands.is_null() {
                // The authority bails out of the whole loop here, having already decided not
                // to unlock on the `all` path.
                if !all {
                    CRYPTO_THREAD_unlock((*gtr).lock);
                }
                return 0;
            }
            let mut curr = *hands;
            let mut prev: *mut ThreadEventHandler = ptr::null_mut();
            while !curr.is_null() {
                let matches = all || (*curr).index == index;
                if matches {
                    if !prev.is_null() {
                        (*prev).next = (*curr).next;
                    } else {
                        *hands = (*curr).next;
                    }
                    let tmp = curr;
                    curr = (*curr).next;
                    CRYPTO_free(tmp.cast::<c_void>(), FILE, lines::L_DEREG_FREE_HAND);
                    continue;
                }
                prev = curr;
                curr = (*curr).next;
            }
            if all {
                CRYPTO_free(hands.cast::<c_void>(), FILE, lines::L_DEREG_FREE_HANDS);
            }
            i += 1;
        }

        if all {
            CRYPTO_THREAD_lock_free((*gtr).lock);
            OPENSSL_sk_free((*gtr).skhands);
            CRYPTO_free(gtr.cast::<c_void>(), FILE, lines::L_GTR_ERR);
        } else {
            CRYPTO_THREAD_unlock((*gtr).lock);
        }
    }
    1
}

// ---------------------------------------------------------------------------
// The stop paths
// ---------------------------------------------------------------------------

/// `static void init_thread_stop(void *arg, THREAD_EVENT_HANDLER **hands)`.
///
/// Walks the list from the head, calling each handler whose `arg` matches and **unlinking it
/// as it goes**, and it holds the global register's write lock for the whole walk — so a
/// handler may not register another handler on the same list without deadlocking, and a
/// handler registered during the walk is behind the cursor and is not called by this stop.
///
/// A NULL `hands` is "this thread has no list", which is the common case and is not an error.
///
/// # Safety
/// `hands` must be NULL or a live head this module allocated.
unsafe fn init_thread_stop(arg: *mut c_void, hands: *mut *mut ThreadEventHandler) {
    if hands.is_null() {
        return;
    }
    let gtr = get_global_tevent_register();
    if gtr.is_null() {
        return;
    }
    // SAFETY: `gtr` is live and non-NULL.
    unsafe {
        if CRYPTO_THREAD_write_lock((*gtr).lock) == 0 {
            return;
        }

        let mut curr = *hands;
        let mut prev: *mut ThreadEventHandler = ptr::null_mut();
        while !curr.is_null() {
            if !arg.is_null() && (*curr).arg != arg {
                prev = curr;
                curr = (*curr).next;
                continue;
            }
            if let Some(f) = (*curr).handfn {
                // SAFETY: `f` is the handler the registering caller supplied, and `arg` is
                // the argument it was registered with. `init_thread_stop`'s own contract is
                // that the handler tolerates being called here.
                f((*curr).arg);
            }
            if prev.is_null() {
                *hands = (*curr).next;
            } else {
                (*prev).next = (*curr).next;
            }
            let tmp = curr;
            curr = (*curr).next;
            CRYPTO_free(tmp.cast::<c_void>(), FILE, lines::L_STOP_FREE_HAND);
        }
        CRYPTO_THREAD_unlock((*gtr).lock);
    }
}

/// `void ossl_ctx_thread_stop(OSSL_LIB_CTX *ctx)`.
///
/// Stops every handler registered for `ctx` and clears this thread's local, so the remaining
/// handlers (for other contexts) stay registered. Unlike `OPENSSL_thread_stop` it does **not**
/// remove the head from the global register, because the thread is still alive and may
/// register more.
///
/// # Safety
/// `ctx` must be NULL or live. NULL stops the handlers registered with a NULL argument, which
/// is what RCU's `ossl_init_thread_start(NULL, ctx, …)` is *not* — RCU's own handler is for
/// its lock's context.
pub(crate) unsafe fn ossl_ctx_thread_stop(ctx: *mut c_void) {
    if !destructor_key_sane() {
        return;
    }
    // SAFETY: the list is this thread's, per the guard.
    let hands = clear_thread_local(ctx);
    // SAFETY: `hands` is NULL or a live head.
    unsafe {
        init_thread_stop(ctx, hands);
        if !hands.is_null() {
            CRYPTO_free(hands.cast::<c_void>(), FILE, lines::L_CTX_STOP_FREE);
        }
    }
}

/// `void OPENSSL_thread_stop_ex(OSSL_LIB_CTX *ctx)`.
///
/// The concrete-context resolution is the authority's, and this crate's
/// [`crate::context::lib_ctx_get_concrete`] is the function. It resolves a thread-default
/// context to the object it stands for, so a caller that passed the default stops the
/// handlers registered against the real one.
///
/// # Safety
/// `ctx` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OPENSSL_thread_stop_ex(ctx: *mut c_void) {
    crate::ffi::guard_ffi((), || {
        let concrete = crate::context::lib_ctx_get_concrete(ctx);
        // SAFETY: `concrete` is NULL or live, which is `ossl_ctx_thread_stop`'s contract.
        unsafe { ossl_ctx_thread_stop(concrete) };
    })
}

/// `void OPENSSL_thread_stop(void)`.
///
/// The whole-thread stop: take this thread's list out of the local, run every handler on it,
/// remove the head from the global register and free the head. After it, this thread has no
/// handlers and no list — so a second call is safe and runs nothing, and a later
/// `ossl_init_thread_start` on the same thread allocates a fresh head and re-registers it.
///
/// ## The last statement is `CRYPTO_THREAD_clean_local()`, and it is not decoration
///
/// `crypto/initthread.c` ends this function with `CRYPTO_THREAD_clean_local()`, which drops
/// **every per-context thread-local table this thread holds** — the `_ex` family's tables from
/// `crypto/threads_common.c`, keyed by libctx. Without it, a thread that stops still holds
/// those tables until `pthread`'s key destructor runs, and for a thread whose key was created
/// and then deleted and re-created (the same slot number, an uncleared value — see
/// [`rearm_for_test`]) the destructor is exactly the wrong place to rely on.
///
/// This call was **absent** until the prerequisite gate's first run reported it: the crate
/// defined the function (under the name [`crate::runtime::threads_common::clean_local`], which
/// the gate's own atlases are what connected to `CRYPTO_THREAD_clean_local`) and never called
/// it from the one place the authority does. That is the class the gate exists for -- a
/// dependency the crate has *not noticed* it needs, invisible to any scan of the crate alone.
#[no_mangle]
pub extern "C" fn OPENSSL_thread_stop() {
    crate::ffi::guard_ffi((), || {
        if !destructor_key_sane() {
            return;
        }
        // SAFETY: `clear_thread_local` answers this thread's head, NULL or live.
        unsafe {
            let hands = clear_thread_local(ptr::null_mut());
            init_thread_stop(ptr::null_mut(), hands);
            init_thread_remove_handlers(hands);
            if !hands.is_null() {
                CRYPTO_free(hands.cast::<c_void>(), FILE, lines::L_DESTRUCTOR_FREE);
            }
        }
        crate::runtime::threads_common::clean_local();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handler that counts its calls and records the argument it saw.
    static CALLS: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
    static LAST_ARG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FIRST_SAW: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

    /// A marker the handlers are registered with and compared against, never dereferenced.
    static ARG_A: u8 = 0xA1;
    static ARG_B: u8 = 0xB2;

    unsafe extern "C" fn count_handler(arg: *mut c_void) {
        let n = CALLS.fetch_add(1, Ordering::SeqCst);
        LAST_ARG.store(arg, Ordering::SeqCst);
        if n == 0 {
            FIRST_SAW.store(1, Ordering::SeqCst);
        }
    }

    fn reset() {
        // The machinery must be live before a handler can be registered, and that is the
        // authority's precondition rather than a test convenience: `CRYPTO_THREAD_init_local`
        // runs `ossl_init_thread()` before it creates any key, so by the time a caller holds a
        // thread-local of its own the event machinery exists. A caller that skipped that is
        // answered 0 by `ossl_init_thread_start` -- which is what these tests observed before
        // this line existed, and what they would observe again if it were removed.
        //
        // `rearm_for_test` is needed because one test in this crate calls `OPENSSL_cleanup`,
        // which is irreversible by contract; see its own doc.
        if !destructor_key_sane() {
            rearm_for_test();
        }
        assert_eq!(ossl_init_thread(), 1);
        CALLS.store(0, Ordering::SeqCst);
        LAST_ARG.store(ptr::null_mut(), Ordering::SeqCst);
        FIRST_SAW.store(0, Ordering::SeqCst);
    }

    fn arg_a() -> *mut c_void {
        (&ARG_A as *const u8 as *mut u8).cast::<c_void>()
    }
    fn arg_b() -> *mut c_void {
        (&ARG_B as *const u8 as *mut u8).cast::<c_void>()
    }

    /// The list is LIFO, so the *most recently* registered handler runs first, and every one
    /// of them runs exactly once with the argument it was registered with.
    #[test]
    fn handlers_run_once_each_in_reverse_registration_order() {
        reset();
        // SAFETY: the handler and its argument are this module's own.
        unsafe {
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_a(), Some(count_handler)),
                1
            );
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_b(), Some(count_handler)),
                1
            );
        }
        OPENSSL_thread_stop();
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        // The LIFO order means the last *called* was the first registered.
        assert_eq!(LAST_ARG.load(Ordering::SeqCst), arg_a());
        assert_eq!(FIRST_SAW.load(Ordering::SeqCst), 1);
    }

    /// A second stop on the same thread is safe and runs nothing, because the handler list
    /// was unlinked and the head released by the first.
    #[test]
    fn a_second_stop_is_a_no_op() {
        reset();
        // SAFETY: as above.
        unsafe { ossl_init_thread_start(ptr::null(), arg_a(), Some(count_handler)) };
        OPENSSL_thread_stop();
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        OPENSSL_thread_stop();
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "the list is gone");
    }

    /// `ossl_ctx_thread_stop` filters on the handler's `arg`: only the handlers registered for
    /// that context run, and the rest stay linked.
    ///
    /// **It then releases the list head anyway, so the survivors are unreachable.** That is the
    /// authority's shape and not an accident of this transcription: `clear_thread_local` clears
    /// the thread local and hands back the head, `init_thread_stop(ctx, head)` runs the matching
    /// handlers, and `OPENSSL_free(head)` releases the head block while nodes for *other*
    /// contexts are still linked to it. The consequence is observable and pinned below: a
    /// whole-thread stop afterwards runs **nothing**, because this thread no longer has a list to
    /// walk, and the remaining nodes are leaked. Recorded as `D-TEVENT-CTX-STOP-LEAK-1` in
    /// `docs/SECURITY_DIVERGENCE_POLICY.md`, which is where a defined but defective upstream
    /// behaviour is recorded rather than quietly "fixed".
    #[test]
    fn the_context_stop_filters_on_the_argument() {
        reset();
        // SAFETY: the handlers and arguments are this module's own.
        unsafe {
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_a(), Some(count_handler)),
                1
            );
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_b(), Some(count_handler)),
                1
            );
            ossl_ctx_thread_stop(arg_a());
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 1, "only the A handler");
        assert_eq!(LAST_ARG.load(Ordering::SeqCst), arg_a());
        OPENSSL_thread_stop();
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "the surviving handler is unreachable: its list head was released"
        );
    }

    /// Deregistration by `index` removes the named handler from every thread's list, and a
    /// handler registered with NULL `index` is not matched by a non-NULL one.
    #[test]
    fn deregistration_matches_on_the_index() {
        reset();
        let key: u8 = 7;
        let other: u8 = 9;
        let key_ptr = (&key as *const u8).cast::<c_void>();
        let other_ptr = (&other as *const u8).cast::<c_void>();
        // SAFETY: both keys are this module's own `'static` markers.
        unsafe {
            assert_eq!(
                ossl_init_thread_start(key_ptr, arg_a(), Some(count_handler)),
                1
            );
            assert_eq!(
                ossl_init_thread_start(other_ptr, arg_b(), Some(count_handler)),
                1
            );
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_a(), Some(count_handler)),
                1
            );
            assert_eq!(ossl_init_thread_deregister(key_ptr), 1);
        }
        OPENSSL_thread_stop();
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            2,
            "the keyed handler was removed and the NULL-index one was not"
        );
    }

    /// A handler that tries to register another handler from inside a stop is **refused**, and
    /// that refusal is a recorded safety divergence rather than a reproduction.
    ///
    /// The walk holds the global register's write lock across the handler call, so a nested
    /// registration re-enters `init_thread_push_handlers` and asks for the same lock. On the
    /// authority's pthread rwlock that is a **deadlock** — `pthread_rwlock_wrlock` on a lock the
    /// same thread already holds for writing does not return — and a deadlock inside thread
    /// teardown is exactly the class of fault this project records instead of recreating
    /// (`docs/SECURITY_DIVERGENCE_POLICY.md`, `D-TEVENT-REENTRANT-1`). This crate's lock refuses
    /// a same-thread write acquisition with 0, so the nested registration fails cleanly and the
    /// handler is answered 0.
    ///
    /// The certain half is asserted: the nested handler is not called by this stop, because the
    /// walk would not have reached it anyway — it unlinks as it goes, and a node pushed at the
    /// head during the walk is behind the cursor.
    #[test]
    fn a_handler_registered_during_a_stop_is_refused() {
        static NESTED_RESULT: core::sync::atomic::AtomicI32 =
            core::sync::atomic::AtomicI32::new(-1);
        unsafe extern "C" fn reregister(_arg: *mut c_void) {
            CALLS.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the handler and argument are this module's own.
            let r = unsafe { ossl_init_thread_start(ptr::null(), arg_b(), Some(count_handler)) };
            NESTED_RESULT.store(r, Ordering::SeqCst);
        }
        reset();
        NESTED_RESULT.store(-1, Ordering::SeqCst);
        // SAFETY: as above.
        unsafe { ossl_init_thread_start(ptr::null(), arg_a(), Some(reregister)) };
        OPENSSL_thread_stop();
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "only the outer handler ran"
        );
        // `LAST_ARG` is `count_handler`'s record, and `count_handler` never ran: the nested
        // registration that would have installed it was refused. So NULL is the *evidence* of
        // the refusal, not a missing assertion.
        assert_eq!(
            LAST_ARG.load(Ordering::SeqCst),
            ptr::null_mut(),
            "the nested handler was never installed"
        );
        assert_eq!(
            NESTED_RESULT.load(Ordering::SeqCst),
            0,
            "the nested registration is refused rather than deadlocking"
        );
    }

    /// `OPENSSL_thread_stop` runs `CRYPTO_THREAD_clean_local()`, so the per-context thread-local
    /// tables this thread holds are gone afterwards.
    ///
    /// The call is the *last* statement of `crypto/initthread.c`'s function and it is easy to
    /// miss, because the function is in a different translation unit from the family it
    /// cleans — which is exactly how this crate came to define `clean_local` and never call it.
    /// The prerequisite gate reported that (`docs/DECISIONS.md` D123); this test is what keeps it
    /// from happening again, because it is the *observable* consequence rather than the call.
    #[test]
    fn a_thread_stop_drops_the_per_context_thread_locals() {
        use crate::runtime::threads_common::{
            CRYPTO_THREAD_get_local_ex, CRYPTO_THREAD_set_local_ex,
            CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
        };
        reset();
        // SAFETY: the table calls below take a live context pointer and a marker that is this
        // test's own static, never dereferenced.
        unsafe {
            clean_local_for_the_test();
            let ctx = crate::context::OSSL_LIB_CTX_new();
            assert!(!ctx.is_null());
            assert_eq!(
                CRYPTO_THREAD_set_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY, ctx, arg_a()),
                1
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY, ctx),
                arg_a(),
                "the value is there before the stop"
            );

            // A handler must be registered for the stop to reach its last statement at all:
            // the whole body is behind `destructor_key.sane != -1`.
            assert_eq!(
                ossl_init_thread_start(ptr::null(), arg_b(), Some(count_handler)),
                1
            );
            OPENSSL_thread_stop();

            assert_eq!(
                CALLS.load(Ordering::SeqCst),
                1,
                "the stop ran, so it reached its last statement"
            );
            assert_eq!(
                CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY, ctx),
                ptr::null_mut(),
                "CRYPTO_THREAD_clean_local() dropped every per-context table, so this is gone"
            );
            crate::context::OSSL_LIB_CTX_free(ctx);
        }
    }

    /// `crate::runtime::threads_common::clean_local()`, named once for the test above so that
    /// the test states the call it is about rather than an inline path.
    fn clean_local_for_the_test() {
        crate::runtime::threads_common::clean_local();
    }
}
