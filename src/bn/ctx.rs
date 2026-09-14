//! Phase 5 — `BN_CTX`, the temporary pool, and the `BN_GENCB` callback object.
//!
//! Both types are opaque to callers of the authority, so the representation is
//! ours. What is reproduced is the *discipline*, because that is what callers
//! depend on:
//!
//! * `BN_CTX_get` hands out a cleared object and reuses pool slots rather than
//!   allocating, which is the whole reason the type exists.
//! * `BN_CTX_start`/`BN_CTX_end` bracket a stack of borrows, and `BN_CTX_end`
//!   returns every temporary taken since the matching `start`. Nesting works, and
//!   an unbalanced `end` restores the innermost mark rather than corrupting the
//!   pool.
//! * `BN_GENCB` carries a callback and its argument, and `BN_GENCB_call` invokes it
//!   with the two operation words the authority passes.

use core::ffi::{c_int, c_void};

use crate::bn::bignum::{BN_free, BN_new, BigNum};
use crate::ffi::guard_ffi;

/// The authority's `BN_CTX`.
#[repr(C)]
pub struct BnCtx {
    /// Objects owned by the context and reused across borrow depths.
    pool: Vec<*mut BigNum>,
    /// How many pool slots are currently lent out.
    used: usize,
    /// `used` at each live `BN_CTX_start`, innermost last.
    marks: Vec<usize>,
    /// A `BIGNUM` reserved for Montgomery state, which the authority keeps in the
    /// context rather than in the pool.
    mont: *mut BigNum,
}

/// Read a `*mut BnCtx` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `BnCtx`.
pub(crate) unsafe fn as_mut_ctx<'a>(p: *mut BnCtx) -> Option<&'a mut BnCtx> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// A fresh context.
fn new_ctx() -> *mut BnCtx {
    Box::into_raw(Box::new(BnCtx {
        pool: Vec::new(),
        used: 0,
        marks: Vec::new(),
        mont: core::ptr::null_mut(),
    }))
}

/// `BN_CTX *BN_CTX_new(void)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_new() -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), new_ctx)
}

/// `BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq)`
///
/// The library context and property query select a provider for the operations the
/// context performs. Those belong to Phase 6, so this creates a context that uses
/// this implementation directly. Recorded as
/// `OBL-BN-CTX-LIBCTX-SELECTION` rather than claimed as parity.
///
/// # Safety
///
/// `libctx` and `propq` are accepted and unused; a caller may pass null for either.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_new_ex(_libctx: *mut c_void, _propq: *const i8) -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), new_ctx)
}

/// `BN_CTX *BN_CTX_secure_new(void)`
///
/// The authority allocates this context's temporaries from the secure heap;
/// `CRYPTO_secure_malloc` exists in Phase 3, but routing each temporary through it
/// is part of the allocator-integration obligation
/// (`OBL-BN-ALLOCATOR`), so this returns a context with the same behaviour and the
/// difference is recorded rather than hidden.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_secure_new() -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), new_ctx)
}

/// `BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *libctx, const char *propq)`
///
/// # Safety
///
/// As `BN_CTX_new_ex`.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_secure_new_ex(
    _libctx: *mut c_void,
    _propq: *const i8,
) -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), new_ctx)
}

/// `void BN_CTX_free(BN_CTX *c)`
///
/// A null pointer is a no-op.
///
/// # Safety
///
/// `c` must be null or a context this library allocated and has not freed.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_free(c: *mut BnCtx) {
    guard_ffi((), || {
        if c.is_null() {
            return;
        }
        // SAFETY: by this function's `# Safety` section `c` came from
        // `Box::into_raw` here and is not yet freed; the only read of the pointer.
        let ctx = unsafe { Box::from_raw(c) };
        for p in ctx.pool.iter() {
            // SAFETY: every pool entry was produced by `BN_new` and has not been
            // freed, so dropping it here is exactly what is owed.
            unsafe { BN_free(*p) };
        }
        if !ctx.mont.is_null() {
            // SAFETY: as above — the Montgomery slot is a `BN_new` object.
            unsafe { BN_free(ctx.mont) };
        }
    });
}

/// `void BN_CTX_start(BN_CTX *ctx)`
///
/// # Safety
///
/// `ctx` must be null or a live, uniquely-owned context.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_start(ctx: *mut BnCtx) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(c) = unsafe { as_mut_ctx(ctx) } {
            c.marks.push(c.used);
        }
    });
}

/// `void BN_CTX_end(BN_CTX *ctx)`
///
/// Gives every temporary taken since the matching `BN_CTX_start` back to the pool.
///
/// # Safety
///
/// As `BN_CTX_start`.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_end(ctx: *mut BnCtx) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(c) = unsafe { as_mut_ctx(ctx) } {
            if let Some(mark) = c.marks.pop() {
                c.used = mark;
            }
        }
    });
}

/// `BIGNUM *BN_CTX_get(BN_CTX *ctx)`
///
/// Hands out a **cleared** temporary, reusing a pool slot when one is free, which is
/// what the authority does and what callers rely on.
///
/// # Safety
///
/// As `BN_CTX_start`.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_get(ctx: *mut BnCtx) -> *mut BigNum {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let c = match unsafe { as_mut_ctx(ctx) } {
            Some(c) => c,
            None => return core::ptr::null_mut(),
        };
        let p = if c.used < c.pool.len() {
            c.pool[c.used]
        } else {
            // SAFETY: `BN_new` allocates without touching any caller pointer.
            let fresh = unsafe { BN_new() };
            if fresh.is_null() {
                return core::ptr::null_mut();
            }
            c.pool.push(fresh);
            fresh
        };
        c.used += 1;
        // SAFETY: `p` is a live object this context owns.
        unsafe { crate::bn::bignum::BN_clear(p) };
        p
    })
}

/// The authority's `BN_GENCB`: a callback for the prime-generation loops.
#[repr(C)]
pub struct BnGencb {
    /// The modern callback, `int (*)(int event, int n, BN_GENCB *cb)`.
    cb: Option<unsafe extern "C" fn(c_int, c_int, *mut BnGencb) -> c_int>,
    /// The deprecated callback, `int (*)(int event, int n, void *arg)`.
    cb_old: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int>,
    /// The caller's argument.
    arg: *mut c_void,
}

/// Read a `*mut BnGencb` as a mutable reference.
///
/// # Safety
///
/// `p` must be null or point to a live, uniquely-owned `BnGencb`.
pub(crate) unsafe fn as_mut_gencb<'a>(p: *mut BnGencb) -> Option<&'a mut BnGencb> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live and
        // uniquely owned.
        Some(unsafe { &mut *p })
    }
}

/// `BN_GENCB *BN_GENCB_new(void)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_new() -> *mut BnGencb {
    guard_ffi(core::ptr::null_mut(), || {
        Box::into_raw(Box::new(BnGencb {
            cb: None,
            cb_old: None,
            arg: core::ptr::null_mut(),
        }))
    })
}

/// `void BN_GENCB_free(BN_GENCB *cb)`
///
/// # Safety
///
/// `cb` must be null or an object this library allocated and has not freed.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_free(cb: *mut BnGencb) {
    guard_ffi((), || {
        if cb.is_null() {
            return;
        }
        // SAFETY: by this function's `# Safety` section `cb` came from
        // `Box::into_raw` here and is not yet freed.
        drop(unsafe { Box::from_raw(cb) });
    });
}

/// `void BN_GENCB_set(BN_GENCB *gencb, int (*cb)(int, int, BN_GENCB *), void *arg)`
///
/// # Safety
///
/// `gencb` must be null or a live, uniquely-owned `BnGencb`; `arg` is the caller's
/// and is only ever handed back to `callback`.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_set(
    gencb: *mut BnGencb,
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut BnGencb) -> c_int>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(c) = unsafe { as_mut_gencb(gencb) } {
            c.cb = callback;
            c.cb_old = None;
            c.arg = arg;
        }
    });
}

/// `void BN_GENCB_set_old(BN_GENCB *gencb, void (*cb)(int, int, void *), void *arg)`
///
/// # Safety
///
/// As `BN_GENCB_set`.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_set_old(
    gencb: *mut BnGencb,
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(c) = unsafe { as_mut_gencb(gencb) } {
            c.cb = None;
            c.cb_old = callback;
            c.arg = arg;
        }
    });
}

/// `int BN_GENCB_call(BN_GENCB *cb, int a, int b)`
///
/// Answers `1` when there is no callback to consult, which is what the authority
/// does and what lets the generation loops run without one.
///
/// # Safety
///
/// `cb` must be null or a live `BnGencb`, and the callback it carries must be safe
/// to call with the arguments this function passes.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_call(cb: *mut BnGencb, a: c_int, b: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        let c = match unsafe { as_ref_gencb(cb) } {
            Some(c) => c,
            None => return 1,
        };
        match (c.cb, c.cb_old) {
            // SAFETY: the caller guarantees the stored callback is safe to call
            // with these arguments, and `cb` is live.
            (Some(f), _) => unsafe { f(a, b, cb) },
            // SAFETY: as above, with the deprecated signature.
            (None, Some(f)) => unsafe { f(a, b, c.arg) },
            (None, None) => 1,
        }
    })
}

/// `void *BN_GENCB_get_arg(BN_GENCB *cb)`
///
/// # Safety
///
/// `cb` must be null or a live `BnGencb`.
#[no_mangle]
pub unsafe extern "C" fn BN_GENCB_get_arg(cb: *mut BnGencb) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        match unsafe { as_ref_gencb(cb) } {
            Some(c) => c.arg,
            None => core::ptr::null_mut(),
        }
    })
}

/// Read a `*const BnGencb` as a shared reference.
///
/// # Safety
///
/// `p` must be null or point to a live `BnGencb`.
unsafe fn as_ref_gencb<'a>(p: *const BnGencb) -> Option<&'a BnGencb> {
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller's contract is exactly that a non-null `p` is live.
        Some(unsafe { &*p })
    }
}

/// `void BN_set_params(int m, int e, int i, int f)` — a deprecated tuning knob the
/// authority ignores entirely. It returns **void**, which the atlas's declaration
/// for it settles; an earlier version of this function returned `int` and would
/// have been wrong at every call site.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_set_params(_m: c_int, _e: c_int, _i: c_int, _f: c_int) {
    guard_ffi((), || {});
}

/// `int BN_get_params(int i)` — as `BN_set_params`; the authority answers `0`.
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_get_params(_i: c_int) -> c_int {
    guard_ffi(0, || 0)
}
