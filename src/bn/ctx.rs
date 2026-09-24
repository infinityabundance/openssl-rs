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
    /// The library context the authority's `struct bignum_ctx` carries (`bn_ctx.c:77`),
    /// stored by `BN_CTX_new_ex` and read back by
    /// [`ossl_bn_get_libctx`].
    ///
    /// It is *stored and read*, which is the half D-`OBL-BN-CTX-LIBCTX-SELECTION` did
    /// not have: the remaining half of that obligation is using it to select a provider
    /// for the context's operations, which is Phase 6's.
    libctx: *mut c_void,
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

/// A fresh context carrying `libctx`, the way the authority's `BN_CTX_new_ex` does.
fn new_ctx(libctx: *mut c_void) -> *mut BnCtx {
    Box::into_raw(Box::new(BnCtx {
        pool: Vec::new(),
        used: 0,
        marks: Vec::new(),
        mont: core::ptr::null_mut(),
        libctx,
    }))
}

/// `OSSL_LIB_CTX *ossl_bn_get_libctx(BN_CTX *ctx)` — `crypto/bn/bn_ctx.c:243`, declared
/// in `include/crypto/bn.h`.
///
/// A null context answers null, which is the authority's own first line. It is what lets
/// `bnrand` hand the context's library context to `RAND_bytes_ex`.
///
/// # Safety
///
/// `ctx` must be null or a live `BN_CTX` this library allocated.
#[allow(dead_code)] // the landing caller is `bnrand` (`src/bn/rand.rs`)
pub(crate) unsafe fn ossl_bn_get_libctx(ctx: *mut BnCtx) -> *mut c_void {
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's contract is that a non-null `ctx` is live.
    unsafe { (*ctx).libctx }
}

/// `BN_CTX *BN_CTX_new(void)`
///
/// # Safety
///
/// Takes no pointers.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_new() -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), || new_ctx(core::ptr::null_mut()))
}

/// `BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *libctx)`
///
/// The authority stores `libctx` in the context (`bn_ctx.c:131`) and reads it back with
/// `ossl_bn_get_libctx`, which is what `bnrand` passes to `RAND_bytes_ex`. That is
/// reproduced here. The *selection* half of the obligation -- using the context to pick
/// a provider for the context's operations -- belongs to Phase 6 and is recorded as
/// `OBL-BN-CTX-LIBCTX-SELECTION` rather than claimed as parity.
///
/// The signature is the authority's: **one** parameter. An earlier version of this
/// declaration carried a second `propq` argument the authority does not have, and the
/// prototype court caught it (`forensics/atlas/prototype-court.json`, D65) -- an extra
/// unused parameter is harmless at the call site on this ABI, which is exactly why
/// only a prototype comparison finds it.
///
/// # Safety
///
/// `libctx` must be null or a live `OSSL_LIB_CTX`, and must outlive the returned
/// context the way it does in the authority.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_new_ex(libctx: *mut c_void) -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), || new_ctx(libctx))
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
    guard_ffi(core::ptr::null_mut(), || new_ctx(core::ptr::null_mut()))
}

/// `BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *libctx)`
///
/// As `BN_CTX_new_ex`, and with the same one-parameter signature the authority
/// declares rather than the two-parameter one an earlier version carried.
///
/// # Safety
///
/// As `BN_CTX_new_ex`.
#[no_mangle]
pub unsafe extern "C" fn BN_CTX_secure_new_ex(libctx: *mut c_void) -> *mut BnCtx {
    guard_ffi(core::ptr::null_mut(), || new_ctx(libctx))
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
///
/// Opaque in the installed headers, so this layout is ours, but the *discriminator*
/// is the authority's and is observable. `struct bn_gencb_st` carries a `ver` word
/// -- 0 for a freshly allocated object, 1 after `BN_GENCB_set_old`, 2 after
/// `BN_GENCB_set` -- and `BN_GENCB_call` branches on it rather than on which
/// function pointer happens to be set. That distinction is the whole of
/// `gencb.call_without_callback`: a *fresh* object answers `0`, while an object whose
/// old-style registration carried a NULL callback answers `1`, and a candidate that
/// models only "is a callback present" cannot tell those apart.
#[repr(C)]
pub struct BnGencb {
    /// `ver`: 0 unset, 1 old-style, 2 new-style.
    ver: core::ffi::c_uint,
    /// The modern callback, `int (*)(int event, int n, BN_GENCB *cb)` (the union's
    /// `cb_2`, live when `ver == 2`).
    cb: Option<unsafe extern "C" fn(c_int, c_int, *mut BnGencb) -> c_int>,
    /// The deprecated callback, `void (*)(int event, int n, void *arg)` (the
    /// union's `cb_1`, live when `ver == 1`).
    cb_old: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
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
            ver: 0,
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
            c.ver = 2;
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
    callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: null-or-live per this function's `# Safety` section.
        if let Some(c) = unsafe { as_mut_gencb(gencb) } {
            c.ver = 1;
            c.cb = None;
            c.cb_old = callback;
            c.arg = arg;
        }
    });
}

/// `int BN_GENCB_call(BN_GENCB *cb, int a, int b)`
///
/// The answer is the authority's own branch on `ver`, not a convenience:
///
/// * NULL `cb` answers `1` -- "no callback means continue".
/// * `ver == 1` (old-style) answers `1`, whether or not a callback is installed;
///   the callback returns void and is invoked for its side effect only.
/// * `ver == 2` (new-style) answers whatever the callback returns.
/// * anything else -- a freshly allocated object, whose `ver` is `0` -- answers
///   `0`. That is what stops a generation loop rather than continuing it.
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
        match c.ver {
            1 => {
                if let Some(f) = c.cb_old {
                    // The deprecated callback returns void; the authority ignores
                    // its result and answers 1.
                    // SAFETY: the caller guarantees the stored callback is safe to
                    // call with these arguments.
                    unsafe { f(a, b, c.arg) };
                }
                1
            }
            2 => match c.cb {
                // SAFETY: as above, with the modern signature.
                Some(f) => unsafe { f(a, b, cb) },
                // The authority calls `cb->cb.cb_2` with no NULL check, so a
                // `BN_GENCB_set(cb, NULL, arg)` makes `BN_GENCB_call` call through
                // a null pointer. Recorded as a safety divergence and not
                // reproduced (docs/SECURITY_DIVERGENCE_POLICY.md); `0` is the
                // answer for "no callback was recognised".
                None => 0,
            },
            // `ver == 0`: freshly allocated, no callback registered at all.
            _ => 0,
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
