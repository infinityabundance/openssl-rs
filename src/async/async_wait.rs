//! Phase 13.7 — `crypto/async/async_wait.c`: the `ASYNC_WAIT_CTX` object.
//!
//! An `ASYNC_WAIT_CTX` is the state an asynchronous engine carries across an `ASYNC_pause_job`
//! boundary: a list of watched file descriptors with per-fd custom data and a cleanup
//! callback, a count of descriptors added and deleted since the last resume, an optional
//! `ASYNC_callback_fn` the engine installs, and an integer status. Every one of the unit's
//! eleven exports is here, each one a direct transcription of its authority arm.
//!
//! `OSSL_ASYNC_FD` is `int` on every platform this profile admits (the `_WIN32` `HANDLE` arm
//! is not built), so [`OsslAsyncFd`] is [`core::ffi::c_int`].
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

use crate::ffi::guard_ffi;
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::mem_coords::SeamFile;

/// The authority's `OPENSSL_FILE` for this unit.
const FILE: *const c_char = c"crypto/async/async_wait.c".as_ptr();
const FILE_SEAM: SeamFile = SeamFile::new(c"crypto/async/async_wait.c");
/// `ASYNC_WAIT_CTX_new`'s `OPENSSL_zalloc` (`:17`).
const LINE_NEW: c_int = 17;
/// `ASYNC_WAIT_CTX_free`'s `OPENSSL_free(curr)` (`:37`).
const LINE_FREE_LOOKUP: c_int = 37;
/// `ASYNC_WAIT_CTX_free`'s `OPENSSL_free(ctx)` (`:41`).
const LINE_FREE_CTX: c_int = 41;
/// `ASYNC_WAIT_CTX_set_wait_fd`'s `OPENSSL_zalloc` (`:51`).
const LINE_LOOKUP: c_int = 51;
/// `ASYNC_WAIT_CTX_clear_fd`'s `OPENSSL_free(curr)` (`:164`).
const LINE_FREE_CLEARED: c_int = 164;
/// `async_wait_ctx_reset_counts`'s `OPENSSL_free(curr)` (`:234`).
const LINE_FREE_RESET: c_int = 234;

/// `#define OSSL_ASYNC_FD int` — `openssl/async.h:28`.
pub type OsslAsyncFd = c_int;

/// `typedef int (*ASYNC_callback_fn)(void *arg)` — `openssl/async.h:39`.
pub type AsyncCallbackFn = unsafe extern "C" fn(*mut c_void) -> c_int;

/// `struct fd_lookup_st` — `crypto/async/async_local.h:49-57`.
#[repr(C)]
struct FdLookup {
    /// The caller's lookup key.
    key: *const c_void,
    /// The watched descriptor.
    fd: OsslAsyncFd,
    /// The caller's per-fd data.
    custom_data: *mut c_void,
    /// The caller's cleanup callback, run from `ASYNC_WAIT_CTX_free` for a live entry.
    cleanup:
        Option<unsafe extern "C" fn(*mut AsyncWaitCtx, *const c_void, OsslAsyncFd, *mut c_void)>,
    /// Set by `ASYNC_WAIT_CTX_set_wait_fd`, cleared when the counts are reset.
    add: c_int,
    /// Set by `ASYNC_WAIT_CTX_clear_fd`'s deletion arm, cleared when the counts are reset.
    del: c_int,
    /// The next entry in the list.
    next: *mut FdLookup,
}

/// `struct async_wait_ctx_st` — `crypto/async/async_local.h:59-66`.
#[repr(C)]
pub struct AsyncWaitCtx {
    /// The watched-descriptor list.
    fds: *mut FdLookup,
    /// Descriptors added since the last resume.
    numadd: usize,
    /// Descriptors deleted since the last resume.
    numdel: usize,
    /// The engine's callback, or NULL.
    callback: Option<AsyncCallbackFn>,
    /// The callback's argument.
    callback_arg: *mut c_void,
    /// The engine's status word.
    status: c_int,
}

// ---------------------------------------------------------------------------------------------
// Ownership of the `ASYNC_WAIT_CTX` object and its `fd_lookup_st` nodes
// ---------------------------------------------------------------------------------------------

/// The authority's `ASYNC_WAIT_CTX_free` body (`crypto/async/async_wait.c:20-42`), without the
/// block release [`OwnedCtx`]'s `Drop` performs: the cleanup callbacks of every live entry and the
/// release of every node.
// SAFETY: (a) holds: `destroy_body` is the authority's `ASYNC_WAIT_CTX_free` body minus the block
// -- it runs every live entry's cleanup callback and releases every node, each the authority's own,
// and never the enclosing block. (b) holds: an all-zero context has a NULL `fds` list, so the body
// is the authority's own all-empty teardown -- what the safe `OwnedCtx::zalloc_at` leans on.
unsafe impl CtxDestroy for AsyncWaitCtx {
    unsafe fn destroy_body(ptr: *mut AsyncWaitCtx) {
        // SAFETY: `ptr` is a live object per the trait contract; `fds` is NULL or this file's own
        // list of nodes.
        let mut curr = unsafe { (*ptr).fds };
        while !curr.is_null() {
            // SAFETY: `curr` is a live node.
            let (del, cleanup, key, fd, custom_data, next) = unsafe {
                (
                    (*curr).del,
                    (*curr).cleanup,
                    (*curr).key,
                    (*curr).fd,
                    (*curr).custom_data,
                    (*curr).next,
                )
            };
            if del == 0 {
                if let Some(f) = cleanup {
                    // SAFETY: `f` is the caller's cleanup callback and `ptr` is the object it was
                    // installed against; every argument is the entry's own.
                    unsafe { f(ptr, key, fd, custom_data) };
                }
            }
            // SAFETY: `curr` is this function's own node and `next` was read before the release.
            drop(unsafe { OwnedFdLookup::adopt(curr, FILE, LINE_FREE_LOOKUP) });
            curr = next;
        }
    }
}

/// An owned `struct fd_lookup_st` node.
struct OwnedFdLookup {
    ptr: *mut FdLookup,
    file: *const c_char,
    line: c_int,
}

impl OwnedFdLookup {
    /// `CRYPTO_zalloc(size_of::<FdLookup>(), file, line)`, or `None` when it answers NULL.
    fn new_zeroed(file: *const c_char, line: c_int) -> Option<OwnedFdLookup> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh, zeroed, writable block of
        // `size_of::<FdLookup>()` bytes, which is exactly the node's layout.
        let raw = CRYPTO_zalloc(core::mem::size_of::<FdLookup>(), file, line).cast::<FdLookup>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedFdLookup {
            ptr: raw,
            file,
            line,
        })
    }

    /// Take up a live node still linked into a context's list, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is a live node this file allocated that no other owner will release.
    unsafe fn adopt(ptr: *mut FdLookup, file: *const c_char, line: c_int) -> OwnedFdLookup {
        OwnedFdLookup { ptr, file, line }
    }

    /// The node's address, for the context field it is stored in.
    fn as_ptr(&self) -> *mut FdLookup {
        self.ptr
    }

    /// Give up ownership of the node to the context's list.
    fn into_raw(self) -> *mut FdLookup {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedFdLookup {
    /// The node's single release, through the same seam.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a block this handle owns and has not released; the authority's own
        // `CRYPTO_free` accepts NULL.
        unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), self.file, self.line) };
    }
}

/// `ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void)` — `crypto/async/async_wait.c:15-18`.
#[no_mangle]
pub extern "C" fn ASYNC_WAIT_CTX_new() -> *mut AsyncWaitCtx {
    guard_ffi(null_mut(), || {
        OwnedCtx::<AsyncWaitCtx>::zalloc_at(FILE_SEAM, LINE_NEW, FILE_SEAM, LINE_NEW)
            .map_or_else(null_mut, |ctx| ctx.into_raw())
    })
}

/// `void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx)` — `crypto/async/async_wait.c:20-42`.
///
/// # Safety
/// `ctx` must be NULL or an object from [`ASYNC_WAIT_CTX_new`] not already released.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_free(ctx: *mut AsyncWaitCtx) {
    guard_ffi((), || {
        // SAFETY: `ctx` is NULL or a live object this file allocated per the contract; `Drop` runs
        // the authority's own free body and this is its single block release.
        drop(unsafe { OwnedCtx::<AsyncWaitCtx>::from_raw_at(ctx, FILE_SEAM, LINE_FREE_CTX) });
    })
}

/// `int ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD fd,
/// void *custom_data, void (*cleanup)(ASYNC_WAIT_CTX *, const void *, OSSL_ASYNC_FD, void *))`
/// — `crypto/async/async_wait.c:44-63`.
///
/// # Safety
/// `ctx` must be live; `key`/`custom_data`/`cleanup` are the caller's.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_wait_fd(
    ctx: *mut AsyncWaitCtx,
    key: *const c_void,
    fd: OsslAsyncFd,
    custom_data: *mut c_void,
    cleanup: Option<
        unsafe extern "C" fn(*mut AsyncWaitCtx, *const c_void, OsslAsyncFd, *mut c_void),
    >,
) -> c_int {
    guard_ffi(0, || {
        let Some(fdlookup) = OwnedFdLookup::new_zeroed(FILE, LINE_LOOKUP) else {
            return 0;
        };
        // SAFETY: `fdlookup` is this call's own fresh node and `ctx` is live per the contract.
        unsafe {
            let node = fdlookup.as_ptr();
            (*node).key = key;
            (*node).fd = fd;
            (*node).custom_data = custom_data;
            (*node).cleanup = cleanup;
            (*node).add = 1;
            (*node).next = (*ctx).fds;
            (*ctx).fds = fdlookup.into_raw();
            (*ctx).numadd += 1;
        }
        1
    })
}

/// `int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD *fd,
/// void **custom_data)` — `crypto/async/async_wait.c:65-85`.
///
/// # Safety
/// `ctx` must be live; `fd`/`custom_data` are writable.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_fd(
    ctx: *mut AsyncWaitCtx,
    key: *const c_void,
    fd: *mut OsslAsyncFd,
    custom_data: *mut *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        let mut curr = unsafe { (*ctx).fds };
        while !curr.is_null() {
            // SAFETY: `curr` is a live node.
            let (del, ckey, cfd, data, next) = unsafe {
                (
                    (*curr).del,
                    (*curr).key,
                    (*curr).fd,
                    (*curr).custom_data,
                    (*curr).next,
                )
            };
            if del == 0 && ckey == key {
                // SAFETY: `fd` and `custom_data` are writable per the contract.
                unsafe {
                    *fd = cfd;
                    *custom_data = data;
                }
                return 1;
            }
            curr = next;
        }
        0
    })
}

/// `int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd, size_t *numfds)` —
/// `crypto/async/async_wait.c:87-108`.
///
/// # Safety
/// `ctx` must be live; `numfds` writable; `fd` NULL or a buffer with room for every live entry.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_all_fds(
    ctx: *mut AsyncWaitCtx,
    fd: *mut OsslAsyncFd,
    numfds: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        let mut curr = unsafe { (*ctx).fds };
        // SAFETY: `numfds` is writable per the contract.
        unsafe { *numfds = 0 };
        let mut cursor = fd;
        while !curr.is_null() {
            // SAFETY: `curr` is a live node.
            let (del, cfd, next) = unsafe { ((*curr).del, (*curr).fd, (*curr).next) };
            if del == 0 {
                if !cursor.is_null() {
                    // SAFETY: `cursor` is inside the caller's buffer per the contract.
                    unsafe {
                        *cursor = cfd;
                        cursor = cursor.add(1);
                    }
                }
                // SAFETY: `numfds` is writable per the contract.
                unsafe { *numfds += 1 };
            }
            curr = next;
        }
        1
    })
}

/// `int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd, size_t
/// *numaddfds, OSSL_ASYNC_FD *delfd, size_t *numdelfds)` — `crypto/async/async_wait.c:110-137`.
///
/// # Safety
/// `ctx` must be live; `numaddfds`/`numdelfds` writable; `addfd`/`delfd` NULL or buffers with
/// room for every changed entry.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_changed_fds(
    ctx: *mut AsyncWaitCtx,
    addfd: *mut OsslAsyncFd,
    numaddfds: *mut usize,
    delfd: *mut OsslAsyncFd,
    numdelfds: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live and the two counts are writable per the contract.
        unsafe {
            *numaddfds = (*ctx).numadd;
            *numdelfds = (*ctx).numdel;
        }
        if addfd.is_null() && delfd.is_null() {
            return 1;
        }
        // SAFETY: `ctx` is live per the contract.
        let mut curr = unsafe { (*ctx).fds };
        let mut add_cursor = addfd;
        let mut del_cursor = delfd;
        while !curr.is_null() {
            // SAFETY: `curr` is a live node.
            let (del, add, cfd, next) =
                unsafe { ((*curr).del, (*curr).add, (*curr).fd, (*curr).next) };
            // An entry marked both added and deleted is ignored, as the authority ignores it.
            if del != 0 && add == 0 && !del_cursor.is_null() {
                // SAFETY: `del_cursor` is inside the caller's buffer per the contract.
                unsafe {
                    *del_cursor = cfd;
                    del_cursor = del_cursor.add(1);
                }
            }
            if add != 0 && del == 0 && !add_cursor.is_null() {
                // SAFETY: `add_cursor` is inside the caller's buffer per the contract.
                unsafe {
                    *add_cursor = cfd;
                    add_cursor = add_cursor.add(1);
                }
            }
            curr = next;
        }
        1
    })
}

/// `int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key)` —
/// `crypto/async/async_wait.c:139-182`.
///
/// # Safety
/// `ctx` must be live; `key` is the caller's.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_clear_fd(
    ctx: *mut AsyncWaitCtx,
    key: *const c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        let mut curr = unsafe { (*ctx).fds };
        let mut prev: *mut FdLookup = null_mut();
        while !curr.is_null() {
            // SAFETY: `curr` is a live node.
            let (del, add, ckey, next) =
                unsafe { ((*curr).del, (*curr).add, (*curr).key, (*curr).next) };
            if del == 1 {
                prev = curr;
                curr = next;
                continue;
            }
            if ckey == key {
                if add == 1 {
                    // The entry was only added, so it is unlinked and released.
                    // SAFETY: `ctx` is live and `curr`/`prev` are in its list.
                    unsafe {
                        if (*ctx).fds == curr {
                            (*ctx).fds = next;
                        } else {
                            (*prev).next = next;
                        }
                        drop(OwnedFdLookup::adopt(curr, FILE, LINE_FREE_CLEARED));
                        (*ctx).numadd -= 1;
                    }
                    return 1;
                }
                // Marked deleted; the caller is responsible for its own cleanup.
                // SAFETY: `curr` is live and `ctx` is live.
                unsafe {
                    (*curr).del = 1;
                    (*ctx).numdel += 1;
                }
                return 1;
            }
            prev = curr;
            curr = next;
        }
        0
    })
}

/// `int ASYNC_WAIT_CTX_set_callback(ASYNC_WAIT_CTX *ctx, ASYNC_callback_fn callback, void
/// *callback_arg)` — `crypto/async/async_wait.c:184-194`.
///
/// # Safety
/// `ctx` must be live; the callback and its argument are the caller's.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_callback(
    ctx: *mut AsyncWaitCtx,
    callback: Option<AsyncCallbackFn>,
    callback_arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live per the contract.
        unsafe {
            (*ctx).callback = callback;
            (*ctx).callback_arg = callback_arg;
        }
        1
    })
}

/// `int ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx, ASYNC_callback_fn *callback, void
/// **callback_arg)` — `crypto/async/async_wait.c:196-206`.
///
/// # Safety
/// `ctx` must be live; `callback`/`callback_arg` writable.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_callback(
    ctx: *mut AsyncWaitCtx,
    callback: *mut Option<AsyncCallbackFn>,
    callback_arg: *mut *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        if unsafe { (*ctx).callback }.is_none() {
            return 0;
        }
        // SAFETY: `ctx` is live and the outputs are writable per the contract.
        unsafe {
            *callback = (*ctx).callback;
            *callback_arg = (*ctx).callback_arg;
        }
        1
    })
}

/// `int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status)` —
/// `crypto/async/async_wait.c:208-212`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_set_status(ctx: *mut AsyncWaitCtx, status: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).status = status };
        1
    })
}

/// `int ASYNC_WAIT_CTX_get_status(ASYNC_WAIT_CTX *ctx)` — `crypto/async/async_wait.c:214-217`.
///
/// # Safety
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn ASYNC_WAIT_CTX_get_status(ctx: *mut AsyncWaitCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).status }
    })
}

/// `void async_wait_ctx_reset_counts(ASYNC_WAIT_CTX *ctx)` — `crypto/async/async_wait.c:219-247`.
///
/// Called from `ASYNC_pause_job` when a job resumes: clears the two counts, clears every
/// entry's `add` flag and unlinks (and releases) every entry marked `del`.
///
/// # Safety
/// `ctx` must be live.
pub(crate) unsafe fn async_wait_ctx_reset_counts(ctx: *mut AsyncWaitCtx) {
    // SAFETY: `ctx` is live per the contract; `ASYNC_pause_job` guards against the NULL the
    // authority would dereference here by only calling it on a job that has a wait context.
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).numadd = 0;
        (*ctx).numdel = 0;
    }
    let mut prev: *mut FdLookup = null_mut();
    // SAFETY: `ctx` is live per the contract.
    let mut curr = unsafe { (*ctx).fds };
    while !curr.is_null() {
        // SAFETY: `curr` is a live node.
        let (del, add, next) = unsafe { ((*curr).del, (*curr).add, (*curr).next) };
        if del != 0 {
            // SAFETY: `curr`/`prev` are in `ctx`'s list, so the unlink is well formed, and
            // `next` was read before the release.
            unsafe {
                if prev.is_null() {
                    (*ctx).fds = next;
                } else {
                    (*prev).next = next;
                }
                drop(OwnedFdLookup::adopt(curr, FILE, LINE_FREE_RESET));
            }
            curr = next;
            continue;
        }
        if add != 0 {
            // SAFETY: `curr` is a live node.
            unsafe { (*curr).add = 0 };
        }
        prev = curr;
        curr = next;
    }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(AsyncWaitCtx => zero_state_sweep_async_wait_ctx);
