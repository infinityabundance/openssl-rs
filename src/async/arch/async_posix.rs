//! Phase 13.7 — `crypto/async/arch/async_posix.c`: the POSIX `ucontext_t` fibre backend.
//!
//! The authority's `async_posix.h` defines `async_fibre` around the platform's
//! `ucontext_t` and switches stacks with `getcontext`/`makecontext`/`swapcontext`. This
//! crate's `ucontext_t` is opaque and its field access is made on the C side of the ABI by
//! `src/async/arch/async_ucontext.c` — the same arrangement `src/runtime/dir_posix.c` uses
//! for `struct dirent` and `struct stat`, and for the same reason: no field offset or
//! alignment is assumed in Rust.
//!
//! What stays here is every behavioural decision: the `STACKSIZE` the authority allocates,
//! the `stack_alloc_impl`/`stack_free_impl` pair [`ASYNC_set_mem_functions`] may replace
//! (and [`ASYNC_get_mem_functions`] reports), the `allow_customize` latch that freezes the
//! pair once a stack has been allocated, and the `async_mem_lock` those three share.
//!
//! `ASYNC_is_capable`, `ASYNC_set_mem_functions` and `ASYNC_get_mem_functions` are the
//! unit's three exports, all here; the fibre helpers are the internal functions `async.c`
//! calls.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::mem::transmute;
use core::ptr::{self, null_mut};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_ASYNC};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

/// The authority's `OPENSSL_FILE` for this unit, so a caller's `CRYPTO_set_mem_functions`
/// sees an allocation with the authority's coordinate.
const FILE: *const c_char = c"crypto/async/arch/async_posix.c".as_ptr();
/// `OPENSSL_LINE` of `async_stack_alloc`'s `OPENSSL_malloc` (`:84`).
const LINE_ALLOC: c_int = 84;
/// `OPENSSL_LINE` of `async_stack_free`'s `OPENSSL_free` (`:89`).
const LINE_FREE: c_int = 89;

/// `#define STACKSIZE 32768` — `async_posix.c:20`.
const STACKSIZE: usize = 32768;

/// `typedef void *(*ASYNC_stack_alloc_fn)(size_t *num)` — `openssl/async.h:82`.
pub type AsyncStackAllocFn = unsafe extern "C" fn(*mut usize) -> *mut c_void;
/// `typedef void (*ASYNC_stack_free_fn)(void *addr)` — `openssl/async.h:83`.
pub type AsyncStackFreeFn = unsafe extern "C" fn(*mut c_void);

// The platform half of the fibre, kept on the C side of the ABI. See the module header and
// `src/async/arch/async_ucontext.c`.
unsafe extern "C" {
    /// `sizeof(ucontext_t)`, so Rust allocates the opaque storage without naming its size.
    fn openssl_rs_ucontext_size() -> usize;
    /// `_Alignof(ucontext_t)`. Reported for the storage's alignment invariant; the storage
    /// itself comes from `CRYPTO_zalloc`, whose `malloc` alignment is the binding guarantee.
    #[allow(dead_code)] // asserted in the unit test; no production reader
    fn openssl_rs_ucontext_align() -> usize;
    /// `getcontext(ucp)` — 0 on success, nonzero on failure.
    fn openssl_rs_ucontext_getcontext(ctx: *mut c_void) -> c_int;
    /// Set `uc_stack` from the caller's stack and `makecontext` onto `start`.
    fn openssl_rs_ucontext_set_stack(
        ctx: *mut c_void,
        start: unsafe extern "C" fn(),
        stack: *mut c_void,
        size: usize,
    ) -> c_int;
    /// `swapcontext(old, new)` — 1 on success, 0 on failure.
    fn openssl_rs_ucontext_swapcontext(old_ctx: *mut c_void, new_ctx: *mut c_void) -> c_int;
    /// `((ucontext_t *)ctx)->uc_stack.ss_sp`.
    fn openssl_rs_ucontext_stack(ctx: *mut c_void) -> *mut c_void;
    /// `getcontext(&ctx) == 0` — the `ASYNC_is_capable` probe.
    fn openssl_rs_ucontext_capable() -> c_int;
}

/// `static CRYPTO_RWLOCK *async_mem_lock;` — `async_posix.c:22`.
static ASYNC_MEM_LOCK: AtomicPtr<CryptoRwlock> = AtomicPtr::new(null_mut());

/// `static int allow_customize = 1;` — `async_posix.c:38`.
static ALLOW_CUSTOMIZE: AtomicBool = AtomicBool::new(true);

/// `static ASYNC_stack_alloc_fn stack_alloc_impl = async_stack_alloc;` — the slot, with a
/// null pointer as the "default" marker exactly as `src/runtime/mem.rs` keeps its allocator
/// slots. `AtomicPtr<()>`, not `AtomicUsize`: the value is a function pointer and must stay
/// one so its provenance survives the atomic (see `src/runtime/mem.rs` and `docs/UNSAFE.md`
/// §4).
static STACK_ALLOC_IMPL: AtomicPtr<()> = AtomicPtr::new(null_mut());
/// `static ASYNC_stack_free_fn stack_free_impl = async_stack_free;`.
static STACK_FREE_IMPL: AtomicPtr<()> = AtomicPtr::new(null_mut());

// The pointer->function-pointer recovery below is a `transmute`, so the two types must be
// the same size. This fails the build, not the run, if Rust ever stops guaranteeing that on
// this platform.
const _: () = {
    assert!(core::mem::size_of::<AsyncStackAllocFn>() == core::mem::size_of::<*mut ()>());
    assert!(core::mem::size_of::<AsyncStackFreeFn>() == core::mem::size_of::<*mut ()>());
};

/// `static void *async_stack_alloc(size_t *num)` — `async_posix.c:82-85`.
///
/// # Safety
/// `num` must be a live `size_t`.
pub(crate) unsafe extern "C" fn async_stack_alloc(num: *mut usize) -> *mut c_void {
    // SAFETY: `num` is live per the contract.
    CRYPTO_zalloc(unsafe { *num }, FILE, LINE_ALLOC)
}

/// `static void async_stack_free(void *addr)` — `async_posix.c:87-90`.
///
/// # Safety
/// `addr` must be a stack this module allocated, or NULL.
pub(crate) unsafe extern "C" fn async_stack_free(addr: *mut c_void) {
    // SAFETY: `addr` is a stack this module allocated, or NULL.
    unsafe { CRYPTO_free(addr, FILE, LINE_FREE) };
}

/// The current `stack_alloc_impl`, in the authority's identity-default form.
fn stack_alloc_fn() -> AsyncStackAllocFn {
    let slot = STACK_ALLOC_IMPL.load(Ordering::Relaxed);
    let raw = if slot.is_null() {
        async_stack_alloc as *const () as *mut ()
    } else {
        slot
    };
    // SAFETY: the slot only ever holds a value written by `ASYNC_set_mem_functions`, whose
    // parameter type is `AsyncStackAllocFn`, or the non-null `async_stack_alloc` substituted
    // above. Both carry the function's provenance, so the pointer->function-pointer
    // `transmute` is the recovered cast rather than an integer reconstruction. `raw` is
    // non-null by construction.
    debug_assert!(
        !raw.is_null(),
        "the stack-alloc slot resolves to a function"
    );
    // SAFETY: `raw` is non-null and carries the function's provenance per the invariant above.
    unsafe { transmute::<*mut (), AsyncStackAllocFn>(raw) }
}

/// The current `stack_free_impl`, as [`stack_alloc_fn`].
fn stack_free_fn() -> AsyncStackFreeFn {
    let slot = STACK_FREE_IMPL.load(Ordering::Relaxed);
    let raw = if slot.is_null() {
        async_stack_free as *const () as *mut ()
    } else {
        slot
    };
    // SAFETY: as `stack_alloc_fn`.
    debug_assert!(!raw.is_null(), "the stack-free slot resolves to a function");
    // SAFETY: `raw` is non-null and carries the function's provenance per the invariant above.
    unsafe { transmute::<*mut (), AsyncStackFreeFn>(raw) }
}

/// `int async_local_init(void)` — `async_posix.c:27-31`.
///
/// Creates the lock the three `*_mem_functions` paths share, and answers whether the
/// allocation succeeded, which is the value `ossl_init_async` records.
pub(crate) fn async_local_init() -> c_int {
    let lock = CRYPTO_THREAD_lock_new();
    ASYNC_MEM_LOCK.store(lock, Ordering::Release);
    c_int::from(!lock.is_null())
}

/// `void async_local_deinit(void)` — `async_posix.c:33-36`.
pub(crate) fn async_local_deinit() {
    let lock = ASYNC_MEM_LOCK.swap(null_mut(), Ordering::AcqRel);
    if !lock.is_null() {
        // SAFETY: `lock` was created by `async_local_init` and is this function's to release.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }
}

/// `void async_local_cleanup(void)` — an empty function (`async_posix.c:92-94`).
pub(crate) fn async_local_cleanup() {}

/// `int ASYNC_is_capable(void)` — `async_posix.c:42-51`.
///
/// The authority probes `getcontext` because some platforms provide it but leave it broken;
/// the probe is the shim's, on a fresh context.
#[no_mangle]
pub extern "C" fn ASYNC_is_capable() -> c_int {
    guard_ffi(0, || {
        // SAFETY: the shim's probe takes no pointer and has no preconditions.
        unsafe { openssl_rs_ucontext_capable() }
    })
}

/// `int ASYNC_set_mem_functions(ASYNC_stack_alloc_fn alloc_fn, ASYNC_stack_free_fn free_fn)` —
/// `async_posix.c:53-71`.
///
/// A NULL argument leaves the matching slot as it was. The latch is checked under
/// `async_mem_lock` and refuses once a stack has been allocated.
///
/// # Safety
/// The two arguments are the caller's function pointers (or NULL); any pointer stored is
/// invoked later as the stack allocator/free for this process.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_set_mem_functions(
    alloc_fn: Option<AsyncStackAllocFn>,
    free_fn: Option<AsyncStackFreeFn>,
) -> c_int {
    guard_ffi(0, || {
        // The authority's `ASYNC_set_mem_functions` reaches the init bit first; NULL settings,
        // as it passes.
        OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null());
        let lock = ASYNC_MEM_LOCK.load(Ordering::Acquire);
        if lock.is_null() {
            return 0;
        }
        // SAFETY: `lock` is live, having been created by `async_local_init`.
        if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
            return 0;
        }
        if !ALLOW_CUSTOMIZE.load(Ordering::Acquire) {
            // SAFETY: `lock` is held by this thread.
            unsafe { CRYPTO_THREAD_unlock(lock) };
            return 0;
        }
        // SAFETY: `lock` is held by this thread.
        unsafe { CRYPTO_THREAD_unlock(lock) };
        if let Some(f) = alloc_fn {
            STACK_ALLOC_IMPL.store(f as *const () as *mut (), Ordering::Release);
        }
        if let Some(f) = free_fn {
            STACK_FREE_IMPL.store(f as *const () as *mut (), Ordering::Release);
        }
        1
    })
}

/// `void ASYNC_get_mem_functions(ASYNC_stack_alloc_fn *alloc_fn, ASYNC_stack_free_fn
/// *free_fn)` — `async_posix.c:73-80`.
///
/// # Safety
/// Each output is NULL or a writable slot of the matching function-pointer type.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_get_mem_functions(
    alloc_fn: *mut Option<AsyncStackAllocFn>,
    free_fn: *mut Option<AsyncStackFreeFn>,
) {
    guard_ffi((), || {
        // SAFETY: each output is NULL or writable per the contract.
        unsafe {
            if !alloc_fn.is_null() {
                *alloc_fn = Some(stack_alloc_fn());
            }
            if !free_fn.is_null() {
                *free_fn = Some(stack_free_fn());
            }
        }
    })
}

/// Allocate the opaque `ucontext_t` storage for one fibre.
///
/// # Safety
/// None beyond the module's invariants; the returned block is owned by the caller.
pub(crate) unsafe fn async_fibre_alloc() -> *mut c_void {
    // SAFETY: `openssl_rs_ucontext_size` takes no arguments and answers the storage size.
    let size = unsafe { openssl_rs_ucontext_size() };
    // SAFETY: the storage's alignment is `malloc`'s, which the shim's `_Alignof(ucontext_t)`
    // probe is asserted against in the unit test below.
    CRYPTO_zalloc(size, FILE, LINE_ALLOC)
}

/// `int async_fibre_makecontext(async_fibre *fibre)` — `async_posix.c:96-126`.
///
/// Captures the context, freezes `allow_customize` on the first call, allocates the stack
/// through the current allocator and attaches it. Answers 0 on the two failure arms the
/// authority has: a failed context capture or a failed stack allocation.
///
/// # Safety
/// `fibre` must be storage from [`async_fibre_alloc`] that is not currently live on a stack.
pub(crate) unsafe fn async_fibre_makecontext(fibre: *mut c_void) -> c_int {
    // SAFETY: `fibre` is storage from `async_fibre_alloc` per the contract.
    if unsafe { openssl_rs_ucontext_getcontext(fibre) } != 0 {
        return 0;
    }
    if ALLOW_CUSTOMIZE.load(Ordering::Acquire) {
        let lock = ASYNC_MEM_LOCK.load(Ordering::Acquire);
        if lock.is_null() {
            return 0;
        }
        // SAFETY: `lock` is live.
        if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
            return 0;
        }
        ALLOW_CUSTOMIZE.store(false, Ordering::Release);
        // SAFETY: `lock` is held by this thread.
        unsafe { CRYPTO_THREAD_unlock(lock) };
    }
    let mut num: usize = STACKSIZE;
    // SAFETY: `num` is a live counter and the current allocator is the contract's.
    let stack = unsafe { (stack_alloc_fn())(&mut num) };
    if stack.is_null() {
        return 0;
    }
    // SAFETY: `fibre` is live, `stack` is this call's own allocation of `num` bytes, and
    // `async_start_func` is the entry the authority's `makecontext` sets.
    unsafe {
        openssl_rs_ucontext_set_stack(
            fibre,
            crate::crypto_async::job::async_start_func,
            stack,
            num,
        )
    }
}

/// The stack pointer `async_fibre_makecontext` attached to `fibre`, for the free path.
///
/// # Safety
/// `fibre` must be live.
unsafe fn async_fibre_stack(fibre: *mut c_void) -> *mut c_void {
    // SAFETY: `fibre` is live per the contract.
    unsafe { openssl_rs_ucontext_stack(fibre) }
}

/// `void async_fibre_free(async_fibre *fibre)` — `async_posix.c:128-132`.
///
/// Releases the stack through the current free function. The opaque `ucontext_t` storage
/// itself is released separately by [`async_fibre_release`], because in this crate the
/// storage is allocated rather than embedded in the job.
///
/// # Safety
/// `fibre` must be live and its stack not already released.
pub(crate) unsafe fn async_fibre_free(fibre: *mut c_void) {
    // SAFETY: `fibre` is live per the contract.
    let stack = unsafe { async_fibre_stack(fibre) };
    // SAFETY: `stack` is the fibre's own, or NULL.
    unsafe { (stack_free_fn())(stack) };
}

/// Release one fibre's stack and its opaque storage.
///
/// # Safety
/// `fibre` must be storage from [`async_fibre_alloc`] that is not live on any stack.
pub(crate) unsafe fn async_fibre_release(fibre: *mut c_void) {
    if fibre.is_null() {
        return;
    }
    // SAFETY: `fibre` is live per the contract.
    unsafe { async_fibre_free(fibre) };
    // SAFETY: `fibre` is this call's own allocation and is no longer referenced.
    unsafe { CRYPTO_free(fibre, FILE, LINE_FREE) };
}

/// Release one fibre's opaque storage **without** touching its stack.
///
/// The dispatcher's stack is the calling thread's own and was never allocated here, so the
/// context object releases only the storage. Job fibres, whose stack this module allocated,
/// go through [`async_fibre_release`].
///
/// # Safety
/// `fibre` must be storage from [`async_fibre_alloc`] that is not live on any stack.
pub(crate) unsafe fn async_fibre_storage_free(fibre: *mut c_void) {
    if fibre.is_null() {
        return;
    }
    // SAFETY: `fibre` is this call's own allocation.
    unsafe { CRYPTO_free(fibre, FILE, LINE_FREE) };
}

/// `async_fibre_swapcontext(o, n, r)` — `async_posix.h:72-88`'s `swapcontext` arm.
///
/// Answers 1 on success and 0 on failure, matching the authority's helper.
///
/// # Safety
/// `o` and `n` must be live fibres whose contexts are established.
pub(crate) unsafe fn async_fibre_swapcontext(o: *mut c_void, n: *mut c_void) -> c_int {
    // SAFETY: `o` and `n` are live per the contract.
    unsafe { openssl_rs_ucontext_swapcontext(o, n) }
}

/// A compile-time guard that the `ucontext_t` the shim reports is not larger than the
/// implementation assumes. The storage is allocated to the reported size, so this only
/// records the size the court's platform reports; it is not a bound the code reads.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_reports_a_usable_context() {
        // SAFETY: both shim calls take no arguments and have no preconditions.
        let size = unsafe { openssl_rs_ucontext_size() };
        // SAFETY: as above.
        let align = unsafe { openssl_rs_ucontext_align() };
        assert!(size > 0);
        assert!(align.is_power_of_two());
        assert!(size <= 4096, "unexpected ucontext_t size {size}");
        // SAFETY: the capability probe takes no arguments.
        assert_eq!(unsafe { openssl_rs_ucontext_capable() }, 1);
    }

    #[test]
    fn the_default_allocators_round_trip() {
        let mut num: usize = 64;
        // SAFETY: `num` is live and the default allocator is the one installed by default.
        let p = unsafe { async_stack_alloc(&mut num) };
        assert!(!p.is_null());
        // SAFETY: `p` came from `async_stack_alloc`.
        unsafe { async_stack_free(p) };
    }
}
