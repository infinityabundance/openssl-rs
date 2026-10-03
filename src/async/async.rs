//! Phase 13.7 — `crypto/async/async.c`: the job, the pool and the `ASYNC_*` entry points.
//!
//! An `ASYNC_JOB` is a fibre: a stack with a saved context, created by
//! [`crate::crypto_async::arch::async_posix`]'s `async_fibre_makecontext`, entered by
//! [`async_start_func`] and switched to and from by `async_fibre_swapcontext`. A job runs until
//! its function returns (the fibre reports `ASYNC_JOB_STOPPING` and the caller sees
//! `ASYNC_FINISH`) or calls [`ASYNC_pause_job`] (the fibre reports `ASYNC_JOB_PAUSING` and the
//! caller sees `ASYNC_PAUSE`). Jobs are pooled per thread, under two of the
//! `CRYPTO_THREAD_LOCAL` keys `src/runtime/threads_common.rs` already declares:
//! `CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY` and `CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY`.
//!
//! ## The pool and the thread-local state
//!
//! `async_ctx_new` registers `async_delete_thread_state` through `ossl_init_thread_start`, so
//! the pool and the fibre context are released when the thread stops, exactly as the authority
//! arranges. Every `ASYNC_*` entry point reaches `OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, NULL)`
//! first; that bit is enabled by this subphase in `src/runtime/init.rs`.
//!
//! ## The two documented differences from the C layout
//!
//! * The fibre's `ucontext_t` is allocated rather than embedded, because Rust cannot name the
//!   platform's type. The two allocations are made and released together, so the lifetime is
//!   the authority's.
//! * `async_fibre_swapcontext` uses the `swapcontext` arm of `arch/async_posix.h` for every
//!   switch. The authority selects between that and a `setjmp`/`longjmp` arm by
//!   `USE_SWAPCONTEXT`; the observable fibre transitions are the same, and the C shim is the
//!   platform half of the chosen arm.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, null_mut};

use crate::context::{lib_ctx_get_concrete, OSSL_LIB_CTX_set0_default};
use crate::crypto_async::arch::async_posix::{
    async_fibre_alloc, async_fibre_makecontext, async_fibre_release, async_fibre_storage_free,
    async_fibre_swapcontext,
};
use crate::crypto_async::async_wait::{async_wait_ctx_reset_counts, AsyncWaitCtx};
use crate::ffi::guard_ffi;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::init::{OPENSSL_init_crypto, OPENSSL_INIT_ASYNC};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_pop, OPENSSL_sk_push, OpenSslStack,
};
use crate::runtime::thread_events::ossl_init_thread_start;
use crate::runtime::threads_common::{
    CRYPTO_THREAD_get_local_ex, CRYPTO_THREAD_set_local_ex, CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
    CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY, CRYPTO_THREAD_NO_CONTEXT,
};

/// The authority's `OPENSSL_FILE` for this unit.
const FILE: *const c_char = c"crypto/async/async.c".as_ptr();
/// `async_ctx_new`'s `OPENSSL_malloc(sizeof(*nctx))` (`:40`).
const LINE_CTX: c_int = 40;
/// `async_ctx_new`'s failure free and `async_ctx_free`'s `OPENSSL_free(ctx)` (`:53`, `:74`).
const LINE_CTX_FREE: c_int = 74;
/// `async_job_new`'s `OPENSSL_zalloc(sizeof(*job))` (`:83`).
const LINE_JOB_NEW: c_int = 83;
/// `async_job_free`'s `OPENSSL_free(job->funcargs)` (`:95`).
const LINE_JOB_FREEARGS: c_int = 95;
/// `async_job_free`'s `OPENSSL_free(job)` (`:97`).
const LINE_JOB_FREE: c_int = 97;
/// `ASYNC_start_job`'s `OPENSSL_malloc(size)` (`:260`).
const LINE_JOB_ARGS: c_int = 260;
/// `ASYNC_init_thread`'s `OPENSSL_zalloc(sizeof(*pool))` (`:361`).
const LINE_POOL: c_int = 361;
/// `ASYNC_init_thread`'s failure free and `async_delete_thread_state`'s (`:368`, `:401`, `:413`).
const LINE_POOL_FREE: c_int = 401;

/// `#define ASYNC_JOB_RUNNING 0` — `async.c:26`.
const ASYNC_JOB_RUNNING: c_int = 0;
/// `#define ASYNC_JOB_PAUSING 1` — `async.c:27`.
const ASYNC_JOB_PAUSING: c_int = 1;
/// `#define ASYNC_JOB_PAUSED 2` — `async.c:28`.
const ASYNC_JOB_PAUSED: c_int = 2;
/// `#define ASYNC_JOB_STOPPING 3` — `async.c:29`.
const ASYNC_JOB_STOPPING: c_int = 3;

/// `#define ASYNC_ERR 0` — `openssl/async.h:41`.
pub const ASYNC_ERR: c_int = 0;
/// `#define ASYNC_NO_JOBS 1` — `openssl/async.h:42`.
pub const ASYNC_NO_JOBS: c_int = 1;
/// `#define ASYNC_PAUSE 2` — `openssl/async.h:43`.
pub const ASYNC_PAUSE: c_int = 2;
/// `#define ASYNC_FINISH 3` — `openssl/async.h:44`.
pub const ASYNC_FINISH: c_int = 3;

/// `struct async_job_st` — `crypto/async/async_local.h:39-47`.
///
/// Public because the exported `ASYNC_start_job`/`ASYNC_get_current_job` signatures name it;
/// its fields are the module's own.
#[repr(C)]
pub struct AsyncJob {
    /// The fibre's opaque `ucontext_t` storage.
    pub(crate) fibre: *mut c_void,
    /// The job function.
    pub(crate) func: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    /// The copied argument block.
    pub(crate) funcargs: *mut c_void,
    /// The job function's return value.
    pub(crate) ret: c_int,
    /// One of `ASYNC_JOB_{RUNNING,PAUSING,PAUSED,STOPPING}`.
    pub(crate) status: c_int,
    /// The wait context the caller passed to `ASYNC_start_job`.
    pub(crate) waitctx: *mut AsyncWaitCtx,
    /// The default library context to restore when the job resumes.
    pub(crate) libctx: *mut c_void,
}

/// `struct async_ctx_st` — `crypto/async/async_local.h:33-37`.
#[repr(C)]
pub(crate) struct AsyncCtx {
    /// The dispatcher's fibre (the calling thread's own context).
    pub(crate) dispatcher: *mut c_void,
    /// The job currently running on this thread, or NULL.
    pub(crate) currjob: *mut AsyncJob,
    /// `ASYNC_block_pause`'s nesting depth.
    pub(crate) blocked: c_uint,
}

/// `struct async_pool_st` — `crypto/async/async_local.h:70-74`.
#[repr(C)]
pub(crate) struct AsyncPool {
    /// The idle jobs, as an untyped `STACK_OF(ASYNC_JOB)`.
    pub(crate) jobs: *mut OpenSslStack,
    /// The number of jobs created.
    pub(crate) curr_size: usize,
    /// The configured maximum, or 0 for unbounded.
    pub(crate) max_size: usize,
}

/// `static async_ctx *async_ctx_new(void)` — `async.c:33-56`.
///
/// # Safety
/// None beyond the module's invariants; the result is owned by the caller if non-NULL.
unsafe fn async_ctx_new() -> *mut AsyncCtx {
    // SAFETY: the handler is a valid `extern "C"` function of the required shape.
    if unsafe { ossl_init_thread_start(ptr::null(), null_mut(), Some(async_delete_thread_state)) }
        == 0
    {
        return null_mut();
    }

    let nctx = CRYPTO_malloc(size_of::<AsyncCtx>(), FILE, LINE_CTX).cast::<AsyncCtx>();
    if nctx.is_null() {
        return null_mut();
    }
    // `async_fibre_init_dispatcher(&nctx->dispatcher)` is a no-op on this platform, but the
    // dispatcher storage still has to exist because `swapcontext` writes the calling thread's
    // context into it on the first switch.
    // SAFETY: no preconditions; the returned block is this call's own.
    let dispatcher = unsafe { async_fibre_alloc() };
    if dispatcher.is_null() {
        // SAFETY: `nctx` is this call's own allocation.
        unsafe { CRYPTO_free(nctx.cast::<c_void>(), FILE, LINE_CTX_FREE) };
        return null_mut();
    }
    // SAFETY: `nctx` and `dispatcher` are this call's own allocations.
    unsafe {
        (*nctx).dispatcher = dispatcher;
        (*nctx).currjob = null_mut();
        (*nctx).blocked = 0;
    }
    // SAFETY: `nctx` is live and this is its own thread's key.
    if unsafe {
        CRYPTO_THREAD_set_local_ex(
            CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
            CRYPTO_THREAD_NO_CONTEXT,
            nctx.cast::<c_void>(),
        )
    } == 0
    {
        // SAFETY: both blocks are this call's own.
        unsafe {
            async_fibre_storage_free(dispatcher);
            CRYPTO_free(nctx.cast::<c_void>(), FILE, LINE_CTX_FREE);
        }
        return null_mut();
    }
    nctx
}

/// `async_ctx *async_get_ctx(void)` — `async.c:58-62`.
///
/// # Safety
/// None; answers NULL when this thread has no context.
pub(crate) unsafe fn async_get_ctx() -> *mut AsyncCtx {
    // SAFETY: the key is the crate's own and the sentinel is the authority's.
    unsafe {
        CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY, CRYPTO_THREAD_NO_CONTEXT)
    }
    .cast::<AsyncCtx>()
}

/// `static int async_ctx_free(void)` — `async.c:64-77`.
///
/// # Safety
/// None; answers 0 only when the thread-local store fails.
unsafe fn async_ctx_free() -> c_int {
    // SAFETY: no preconditions.
    let ctx = unsafe { async_get_ctx() };
    // SAFETY: the key is the crate's own.
    if unsafe {
        CRYPTO_THREAD_set_local_ex(
            CRYPTO_THREAD_LOCAL_ASYNC_CTX_KEY,
            CRYPTO_THREAD_NO_CONTEXT,
            null_mut(),
        )
    } == 0
    {
        return 0;
    }
    if !ctx.is_null() {
        // SAFETY: `ctx` is this thread's own context; the dispatcher's stack is the caller's
        // and is not released, only the opaque storage.
        unsafe {
            async_fibre_storage_free((*ctx).dispatcher);
            CRYPTO_free(ctx.cast::<c_void>(), FILE, LINE_CTX_FREE);
        }
    }
    1
}

/// `static ASYNC_JOB *async_job_new(void)` — `async.c:79-90`.
///
/// # Safety
/// None; the result is owned by the caller if non-NULL.
unsafe fn async_job_new() -> *mut AsyncJob {
    let job = CRYPTO_zalloc(size_of::<AsyncJob>(), FILE, LINE_JOB_NEW).cast::<AsyncJob>();
    if job.is_null() {
        return null_mut();
    }
    // SAFETY: no preconditions; the returned block is this call's own.
    let fibre = unsafe { async_fibre_alloc() };
    if fibre.is_null() {
        // SAFETY: `job` is this call's own allocation.
        unsafe { CRYPTO_free(job.cast::<c_void>(), FILE, LINE_JOB_FREE) };
        return null_mut();
    }
    // SAFETY: `job` and `fibre` are this call's own.
    unsafe {
        (*job).fibre = fibre;
        (*job).status = ASYNC_JOB_RUNNING;
    }
    job
}

/// `static void async_job_free(ASYNC_JOB *job)` — `async.c:92-99`.
///
/// # Safety
/// `job` must be NULL or a job not currently on a stack.
unsafe fn async_job_free(job: *mut AsyncJob) {
    if job.is_null() {
        return;
    }
    // SAFETY: `job` is live per the contract, and its two buffers are its own.
    unsafe {
        CRYPTO_free((*job).funcargs, FILE, LINE_JOB_FREEARGS);
        async_fibre_release((*job).fibre);
        CRYPTO_free(job.cast::<c_void>(), FILE, LINE_JOB_FREE);
    }
}

/// `static ASYNC_JOB *async_get_pool_job(void)` — `async.c:101-135`.
///
/// # Safety
/// None beyond the module's invariants.
unsafe fn async_get_pool_job() -> *mut AsyncJob {
    // SAFETY: the key is the crate's own.
    let mut pool = unsafe {
        CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY, CRYPTO_THREAD_NO_CONTEXT)
    }
    .cast::<AsyncPool>();
    if pool.is_null() {
        // SAFETY: two sizes and no pointer.
        if unsafe { ASYNC_init_thread(0, 0) } == 0 {
            return null_mut();
        }
        // SAFETY: the key is the crate's own.
        pool = unsafe {
            CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY, CRYPTO_THREAD_NO_CONTEXT)
        }
        .cast::<AsyncPool>();
    }

    // SAFETY: `pool` is live (the authority dereferences it unconditionally here too).
    let job = unsafe { OPENSSL_sk_pop((*pool).jobs) }.cast::<AsyncJob>();
    if !job.is_null() {
        return job;
    }
    // SAFETY: `pool` is live.
    if unsafe { (*pool).max_size != 0 && (*pool).curr_size >= (*pool).max_size } {
        return null_mut();
    }
    // SAFETY: no preconditions; the returned job is this call's own.
    let fresh = unsafe { async_job_new() };
    if !fresh.is_null() {
        // SAFETY: `fresh` is this call's own job.
        if unsafe { async_fibre_makecontext((*fresh).fibre) } == 0 {
            // SAFETY: `fresh` is this call's own and has no stack.
            unsafe { async_job_free(fresh) };
            return null_mut();
        }
        // SAFETY: `pool` is live and this call owns `fresh`.
        unsafe { (*pool).curr_size += 1 };
    }
    fresh
}

/// `static void async_release_job(ASYNC_JOB *job)` — `async.c:137-150`.
///
/// # Safety
/// `job` must be live and not currently on a stack.
unsafe fn async_release_job(job: *mut AsyncJob) {
    // SAFETY: the key is the crate's own.
    let pool = unsafe {
        CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY, CRYPTO_THREAD_NO_CONTEXT)
    }
    .cast::<AsyncPool>();
    if pool.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYNC_144) };
        return;
    }
    // SAFETY: `job` is live per the contract and `pool` is this thread's.
    unsafe {
        CRYPTO_free((*job).funcargs, FILE, LINE_JOB_FREEARGS);
        (*job).funcargs = null_mut();
        OPENSSL_sk_push((*pool).jobs, job.cast::<c_void>());
    }
}

/// `void async_start_func(void)` — `async.c:152-177`.
///
/// The `makecontext` entry every fibre begins at. It runs one job to completion, reports
/// `ASYNC_JOB_STOPPING` and yields to the dispatcher; the loop is the authority's, because a
/// released job's fibre can be re-entered for the next job.
///
/// # Safety
/// Only ever invoked by `swapcontext` on a fibre's own stack.
pub(crate) unsafe extern "C" fn async_start_func() {
    // SAFETY: no preconditions.
    let ctx = unsafe { async_get_ctx() };
    if ctx.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::ASYNC_158) };
        return;
    }
    loop {
        // SAFETY: `ctx` is live and the dispatcher only switches here with `currjob` set.
        let job = unsafe { (*ctx).currjob };
        // SAFETY: `job` is live.
        let (func, funcargs) = unsafe { ((*job).func, (*job).funcargs) };
        let ret = match func {
            // SAFETY: `func` is the job function the caller passed.
            Some(f) => unsafe { f(funcargs) },
            None => 0,
        };
        // SAFETY: `job` is live.
        unsafe {
            (*job).ret = ret;
            (*job).status = ASYNC_JOB_STOPPING;
        }
        // SAFETY: `job`/`ctx` are live and their fibres are established.
        if unsafe { async_fibre_swapcontext((*job).fibre, (*ctx).dispatcher) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYNC_174) };
        }
    }
}

/// The authority's `err:` label of [`ASYNC_start_job`] — `async.c:286-290` — as the shared
/// release path its three `goto err`s take.
///
/// # Safety
/// `ctx` must be live with a non-NULL `currjob`; `job` is the caller's slot.
unsafe fn async_start_job_err(ctx: *mut AsyncCtx, job: *mut *mut AsyncJob) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        async_release_job((*ctx).currjob);
        (*ctx).currjob = null_mut();
        *job = null_mut();
    }
    ASYNC_ERR
}

/// `int ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *ctx, int *ret, int (*func)(void *),
/// void *args, size_t size)` — `crypto/async/async.c:179-291`.
///
/// # Safety
/// `job` and `ret` are writable; `wctx` is NULL or a live wait context; `func`/`args` are the
/// job's; `size` matches `args`.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_start_job(
    job: *mut *mut AsyncJob,
    wctx: *mut AsyncWaitCtx,
    ret: *mut c_int,
    func: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    args: *mut c_void,
    size: usize,
) -> c_int {
    guard_ffi(ASYNC_ERR, || {
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return ASYNC_ERR;
        }
        // SAFETY: no preconditions.
        let mut ctx = unsafe { async_get_ctx() };
        if ctx.is_null() {
            // SAFETY: no preconditions; the context is owned here on success.
            ctx = unsafe { async_ctx_new() };
        }
        if ctx.is_null() {
            return ASYNC_ERR;
        }
        // SAFETY: `job` is the caller's slot per the contract.
        if unsafe { !(*job).is_null() } {
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).currjob = *job };
        }

        loop {
            // SAFETY: `ctx` is live.
            let currjob = unsafe { (*ctx).currjob };
            if !currjob.is_null() {
                // SAFETY: `currjob` is a live job.
                let status = unsafe { (*currjob).status };
                if status == ASYNC_JOB_STOPPING {
                    // SAFETY: every pointer is live per the contract.
                    unsafe {
                        *ret = (*currjob).ret;
                        (*currjob).waitctx = null_mut();
                        async_release_job(currjob);
                        (*ctx).currjob = null_mut();
                        *job = null_mut();
                    }
                    return ASYNC_FINISH;
                }
                if status == ASYNC_JOB_PAUSING {
                    // SAFETY: `job` and `currjob` are live.
                    unsafe {
                        *job = currjob;
                        (*currjob).status = ASYNC_JOB_PAUSED;
                        (*ctx).currjob = null_mut();
                    }
                    return ASYNC_PAUSE;
                }
                if status == ASYNC_JOB_PAUSED {
                    // SAFETY: `job` is the caller's slot.
                    if unsafe { (*job).is_null() } {
                        return ASYNC_ERR;
                    }
                    // SAFETY: `ctx` and `job` are live.
                    unsafe { (*ctx).currjob = *job };
                    // Restore the default libctx to what it was when the fibre last ran.
                    // SAFETY: `currjob` is live; the stored context is NULL or a live default.
                    let libctx = unsafe { OSSL_LIB_CTX_set0_default((*currjob).libctx) };
                    if libctx.is_null() {
                        // SAFETY: a compile-time-constant site.
                        unsafe { raise_site(&err_sites::ASYNC_227) };
                        // SAFETY: `ctx` is live with a non-NULL `currjob` and `job` is the
                        // caller's slot.
                        return unsafe { async_start_job_err(ctx, job) };
                    }
                    // SAFETY: `ctx`/`currjob` are live and their fibres are established.
                    let ok =
                        unsafe { async_fibre_swapcontext((*ctx).dispatcher, (*currjob).fibre) };
                    if ok == 0 {
                        // SAFETY: `currjob` is live.
                        unsafe {
                            (*currjob).libctx = OSSL_LIB_CTX_set0_default(libctx);
                            raise_site(&err_sites::ASYNC_234);
                        }
                        // SAFETY: `ctx` is live with a non-NULL `currjob`.
                        return unsafe { async_start_job_err(ctx, job) };
                    }
                    // SAFETY: `currjob` is live.
                    unsafe { (*currjob).libctx = OSSL_LIB_CTX_set0_default(libctx) };
                    continue;
                }
                // Should not happen.
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::ASYNC_247) };
                // SAFETY: `ctx` is live with a non-NULL `currjob`.
                return unsafe { async_start_job_err(ctx, job) };
            }

            // Start a new job.
            // SAFETY: no preconditions; the returned job is this thread's own.
            let fresh = unsafe { async_get_pool_job() };
            // SAFETY: `ctx` is live.
            unsafe { (*ctx).currjob = fresh };
            if fresh.is_null() {
                return ASYNC_NO_JOBS;
            }
            if !args.is_null() && size > 0 {
                let funcargs = CRYPTO_malloc(size, FILE, LINE_JOB_ARGS);
                // SAFETY: `fresh` is this call's own job.
                unsafe { (*fresh).funcargs = funcargs };
                if funcargs.is_null() {
                    // SAFETY: `fresh` and `ctx` are live.
                    unsafe {
                        async_release_job(fresh);
                        (*ctx).currjob = null_mut();
                    }
                    return ASYNC_ERR;
                }
                // SAFETY: `args` is `size` bytes per the contract and `funcargs` is a fresh
                // block of `size`; the two do not overlap.
                unsafe { ptr::copy_nonoverlapping(args.cast::<u8>(), funcargs.cast::<u8>(), size) };
            } else {
                // SAFETY: `fresh` is live.
                unsafe { (*fresh).funcargs = null_mut() };
            }
            // SAFETY: `fresh` is live.
            unsafe {
                (*fresh).func = func;
                (*fresh).waitctx = wctx;
            }
            // SAFETY: `lib_ctx_get_concrete` reads the thread default and takes NULL.
            let libctx = lib_ctx_get_concrete(ptr::null_mut());
            // SAFETY: `ctx`/`fresh` are live and the fibres are established.
            let ok = unsafe { async_fibre_swapcontext((*ctx).dispatcher, (*fresh).fibre) };
            if ok == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::ASYNC_276) };
                // SAFETY: `ctx` is live with a non-NULL `currjob`.
                return unsafe { async_start_job_err(ctx, job) };
            }
            // SAFETY: `fresh` is live.
            unsafe { (*fresh).libctx = OSSL_LIB_CTX_set0_default(libctx) };
        }
    })
}

/// `int ASYNC_pause_job(void)` — `crypto/async/async.c:293-320`.
///
/// Outside a job, or while pausing is blocked, the call is a success with no switch, which is
/// the authority's "deliberately not started within a job" arm.
///
/// # Safety
/// None; safe to call from any thread, in or out of a job.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_pause_job() -> c_int {
    guard_ffi(0, || {
        // SAFETY: no preconditions.
        let ctx = unsafe { async_get_ctx() };
        if ctx.is_null() {
            return 1;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).currjob }.is_null() || unsafe { (*ctx).blocked } != 0 {
            return 1;
        }
        // SAFETY: `ctx` is live and `currjob` is non-NULL.
        let job = unsafe { (*ctx).currjob };
        // SAFETY: `job` is live.
        unsafe { (*job).status = ASYNC_JOB_PAUSING };
        // SAFETY: `job` and `ctx` are live and their fibres are established.
        if unsafe { async_fibre_swapcontext((*job).fibre, (*ctx).dispatcher) } == 0 {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYNC_313) };
            return 0;
        }
        // Reset the counts of added and deleted fds.
        // SAFETY: `job` is live; the wait context is NULL or the caller's.
        unsafe { async_wait_ctx_reset_counts((*job).waitctx) };
        1
    })
}

/// `static void async_empty_pool(async_pool *pool)` — `async.c:322-333`.
///
/// # Safety
/// `pool` must be NULL or live.
unsafe fn async_empty_pool(pool: *mut AsyncPool) {
    if pool.is_null() {
        return;
    }
    // SAFETY: `pool` is live per the contract.
    if unsafe { (*pool).jobs }.is_null() {
        return;
    }
    loop {
        // SAFETY: `pool` is live and its stack is live.
        let job = unsafe { OPENSSL_sk_pop((*pool).jobs) }.cast::<AsyncJob>();
        // SAFETY: `job` is NULL or the pool's own.
        unsafe { async_job_free(job) };
        if job.is_null() {
            break;
        }
    }
}

/// `int async_init(void)` — `crypto/async.h`, the internal function `ossl_init_async` calls.
pub(crate) fn async_init() -> c_int {
    crate::crypto_async::arch::async_posix::async_local_init()
}

/// `void async_deinit(void)` — the internal function `OPENSSL_cleanup` calls.
pub(crate) fn async_deinit() {
    crate::crypto_async::arch::async_posix::async_local_deinit()
}

/// `int ASYNC_init_thread(size_t max_size, size_t init_size)` — `async.c:345-403`.
///
/// # Safety
/// None; the pool is per-thread state.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_init_thread(max_size: usize, init_size: usize) -> c_int {
    guard_ffi(0, || {
        if init_size > max_size || max_size > c_int::MAX as usize {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYNC_351) };
            return 0;
        }
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return 0;
        }
        // SAFETY: the handler is a valid `extern "C"` function of the required shape.
        if unsafe {
            ossl_init_thread_start(ptr::null(), null_mut(), Some(async_delete_thread_state))
        } == 0
        {
            return 0;
        }
        let pool = CRYPTO_zalloc(size_of::<AsyncPool>(), FILE, LINE_POOL).cast::<AsyncPool>();
        if pool.is_null() {
            return 0;
        }
        // SAFETY: `pool` is fresh storage and `init_size` was checked against `INT_MAX`.
        unsafe {
            (*pool).jobs = OPENSSL_sk_new_reserve(None, init_size as c_int);
        }
        // SAFETY: `pool` is live.
        if unsafe { (*pool).jobs }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYNC_367) };
            // SAFETY: `pool` is this call's own allocation.
            unsafe { CRYPTO_free(pool.cast::<c_void>(), FILE, LINE_POOL_FREE) };
            return 0;
        }
        // SAFETY: `pool` is live.
        unsafe { (*pool).max_size = max_size };
        let mut curr_size = 0usize;
        let mut remaining = init_size;
        while remaining > 0 {
            remaining -= 1;
            // SAFETY: no preconditions; the job is owned here on success.
            let job = unsafe { async_job_new() };
            // SAFETY: `job` is NULL or this call's own.
            if job.is_null() || unsafe { async_fibre_makecontext((*job).fibre) } == 0 {
                // SAFETY: `job` is NULL or this call's own; the borrow of `*job` above ended.
                unsafe { async_job_free(job) };
                break;
            }
            // SAFETY: `job`/`pool` are live and the reserved stack cannot fail to push.
            unsafe {
                (*job).funcargs = null_mut();
                OPENSSL_sk_push((*pool).jobs, job.cast::<c_void>());
            }
            curr_size += 1;
        }
        // SAFETY: `pool` is live.
        unsafe { (*pool).curr_size = curr_size };
        // SAFETY: the key is the crate's own.
        if unsafe {
            CRYPTO_THREAD_set_local_ex(
                CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY,
                CRYPTO_THREAD_NO_CONTEXT,
                pool.cast::<c_void>(),
            )
        } == 0
        {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::ASYNC_393) };
            // SAFETY: `pool` is this call's own.
            unsafe {
                async_empty_pool(pool);
                OPENSSL_sk_free((*pool).jobs);
                CRYPTO_free(pool.cast::<c_void>(), FILE, LINE_POOL_FREE);
            }
            return 0;
        }
        1
    })
}

/// `static void async_delete_thread_state(void *arg)` — `async.c:405-419`.
///
/// Declared safe because that is the signature `ossl_init_thread_start` takes
/// (`ThreadStopHandlerFn`); the handler's own unsafe work is in the block below.
extern "C" fn async_delete_thread_state(_arg: *mut c_void) {
    // SAFETY: the key is the crate's own.
    let pool = unsafe {
        CRYPTO_THREAD_get_local_ex(CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY, CRYPTO_THREAD_NO_CONTEXT)
    }
    .cast::<AsyncPool>();
    if !pool.is_null() {
        // SAFETY: `pool` is this thread's own and no other thread holds it.
        unsafe {
            async_empty_pool(pool);
            OPENSSL_sk_free((*pool).jobs);
            CRYPTO_free(pool.cast::<c_void>(), FILE, LINE_POOL_FREE);
            CRYPTO_THREAD_set_local_ex(
                CRYPTO_THREAD_LOCAL_ASYNC_POOL_KEY,
                CRYPTO_THREAD_NO_CONTEXT,
                null_mut(),
            );
        }
    }
    crate::crypto_async::arch::async_posix::async_local_cleanup();
    // SAFETY: this thread's context is this thread's to release.
    unsafe { async_ctx_free() };
}

/// `void ASYNC_cleanup_thread(void)` — `crypto/async/async.c:421-427`.
///
/// # Safety
/// None; releases this thread's pool and context.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_cleanup_thread() {
    guard_ffi((), || {
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return;
        }
        async_delete_thread_state(null_mut());
    })
}

/// `ASYNC_JOB *ASYNC_get_current_job(void)` — `crypto/async/async.c:429-441`.
///
/// # Safety
/// None; answers NULL outside a job.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_get_current_job() -> *mut AsyncJob {
    guard_ffi(null_mut(), || {
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return null_mut();
        }
        // SAFETY: no preconditions.
        let ctx = unsafe { async_get_ctx() };
        if ctx.is_null() {
            return null_mut();
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).currjob }
    })
}

/// `ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job)` — `crypto/async/async.c:443-446`.
///
/// # Safety
/// `job` must be live; the authority dereferences it without a NULL test.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_get_wait_ctx(job: *mut AsyncJob) -> *mut AsyncWaitCtx {
    guard_ffi(null_mut(), || {
        // SAFETY: `job` is live per the contract.
        unsafe { (*job).waitctx }
    })
}

/// `void ASYNC_block_pause(void)` — `crypto/async/async.c:448-463`.
///
/// # Safety
/// None; a no-op outside a job.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_block_pause() {
    guard_ffi((), || {
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return;
        }
        // SAFETY: no preconditions.
        let ctx = unsafe { async_get_ctx() };
        if ctx.is_null() {
            return;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).currjob }.is_null() {
            return;
        }
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).blocked += 1 };
    })
}

/// `void ASYNC_unblock_pause(void)` — `crypto/async/async.c:465-481`.
///
/// # Safety
/// None; a no-op outside a job or when the depth is already zero.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_unblock_pause() {
    guard_ffi((), || {
        // SAFETY: NULL settings, as the authority passes.
        if OPENSSL_init_crypto(OPENSSL_INIT_ASYNC, ptr::null()) == 0 {
            return;
        }
        // SAFETY: no preconditions.
        let ctx = unsafe { async_get_ctx() };
        if ctx.is_null() {
            return;
        }
        // SAFETY: `ctx` is live.
        if unsafe { (*ctx).currjob }.is_null() {
            return;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            if (*ctx).blocked > 0 {
                (*ctx).blocked -= 1;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_async::async_wait::{ASYNC_WAIT_CTX_free, ASYNC_WAIT_CTX_new};
    use core::sync::atomic::{AtomicI32, Ordering};

    /// The step counter a job mutation is observed through.
    static STEPS: AtomicI32 = AtomicI32::new(0);

    /// A job that increments [`STEPS`], pauses once, and on resume increments it again and
    /// returns `*arg + 100`. The copy `ASYNC_start_job` makes is what makes the pointer valid on
    /// the fibre's stack.
    unsafe extern "C" fn pausing_job(arg: *mut c_void) -> c_int {
        STEPS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: called on a fibre set up by this module.
        unsafe { ASYNC_pause_job() };
        STEPS.fetch_add(10, Ordering::SeqCst);
        // SAFETY: `arg` is the copied argument block, a live `c_int`.
        unsafe { *(arg.cast::<c_int>()) + 100 }
    }

    /// The start/pause/resume/finish sequence, and the current-job and wait-context accessors
    /// around it.
    #[test]
    fn a_job_pauses_and_resumes_once() {
        // The async entry points reach `OPENSSL_init_crypto`, which is process-global; the
        // crate-wide lock keeps this from racing the init/cleanup tests.
        let _guard = crate::test_support::lock_global_state();
        STEPS.store(0, Ordering::SeqCst);
        let arg: c_int = 7;
        let wctx = ASYNC_WAIT_CTX_new();
        assert!(!wctx.is_null());
        let mut job: *mut AsyncJob = null_mut();
        let mut ret: c_int = -1;
        // SAFETY: every pointer is this test's own.
        let r1 = unsafe {
            ASYNC_start_job(
                &raw mut job,
                wctx,
                &raw mut ret,
                Some(pausing_job),
                (&raw const arg).cast::<c_void>().cast_mut(),
                core::mem::size_of::<c_int>(),
            )
        };
        assert_eq!(r1, ASYNC_PAUSE);
        assert!(!job.is_null());
        assert_eq!(STEPS.load(Ordering::SeqCst), 1);
        // SAFETY: `job` is live until the finish below; the authority reads `waitctx` the same way.
        assert_eq!(unsafe { ASYNC_get_wait_ctx(job) }, wctx);
        // SAFETY: no preconditions; outside a job this is NULL.
        assert!(unsafe { ASYNC_get_current_job() }.is_null());
        // SAFETY: `job` is the handle the first call wrote back.
        let r2 = unsafe {
            ASYNC_start_job(
                &raw mut job,
                wctx,
                &raw mut ret,
                Some(pausing_job),
                null_mut(),
                0,
            )
        };
        assert_eq!(r2, ASYNC_FINISH);
        assert!(job.is_null());
        assert_eq!(ret, 107);
        assert_eq!(STEPS.load(Ordering::SeqCst), 11);
        // SAFETY: `wctx` is this test's own and the job is finished.
        unsafe { ASYNC_WAIT_CTX_free(wctx) };
    }

    /// `ASYNC_pause_job` outside a job is a success with no switch, and the block/unblock pair
    /// is a no-op there.
    #[test]
    fn pause_outside_a_job_is_a_no_op_success() {
        // `ASYNC_block_pause`/`_unblock_pause` reach `OPENSSL_init_crypto`, so this shares the
        // crate-wide global-state lock.
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        assert_eq!(unsafe { ASYNC_pause_job() }, 1);
        // SAFETY: no preconditions.
        unsafe { ASYNC_block_pause() };
        // SAFETY: no preconditions.
        unsafe { ASYNC_unblock_pause() };
    }
}
