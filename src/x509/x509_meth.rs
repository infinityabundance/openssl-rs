//! Phase 11.1 — `crypto/x509/x509_meth.c`: the `X509_LOOKUP_METHOD` object. **This slice lands
//! all twenty of its functions**, where Phase 10.14.2 withheld them whole.
//!
//! `crypto/x509/x509_meth.c` is 157 lines and publishes the `X509_LOOKUP_meth_new`/`_free` pair
//! and the nine setters/getters that fill the `X509_LOOKUP_METHOD` vtable (`new_item`, `free`,
//! `init`, `shutdown`, `ctrl`, `get_by_subject`, `get_by_issuer_serial`, `get_by_fingerprint`,
//! `get_by_alias`).
//!
//! ## Why 10.14.2 withheld them, and why the blocker is gone
//!
//! The unit's one blocker was the `X509_LOOKUP`/`X509_LOOKUP_METHOD` object pair: the method
//! struct is declared in `crypto/x509/x509_local.h` and its `ctrl` and `get_by_*` members are
//! typed by `X509_LOOKUP_ctrl_fn` and the four `X509_LOOKUP_get_by_*_fn` typedefs, whose first
//! parameter is `X509_LOOKUP *`, and the crate had neither type nor layout. Phase 11.1's
//! `x509_lu.rs` now defines both — [`X509LookupMethod`] (the 96-byte vtable) and `X509Lookup` —
//! together with the five typedefs, so every function here is transcribed rather than withheld.
//!
//! `crypto/x509/x509_meth.c` raises nothing, so it is deliberately **not** listed in
//! `gen_err_raise_sites.py`'s covered set and declares no raise coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::mem::size_of;
use core::ptr::NonNull;

use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::x509::x509_lu::{
    X509Lookup, X509LookupMethod, X509_LOOKUP_ctrl_fn, X509_LOOKUP_get_by_alias_fn,
    X509_LOOKUP_get_by_fingerprint_fn, X509_LOOKUP_get_by_issuer_serial_fn,
    X509_LOOKUP_get_by_subject_fn,
};

/// The `OPENSSL_FILE` string for this unit's `OPENSSL_zalloc`/`OPENSSL_strdup`/`OPENSSL_free`
/// expansions.
const FILE: &CStr = c"crypto/x509/x509_meth.c";
/// `X509_LOOKUP_meth_new`'s `OPENSSL_zalloc(sizeof(X509_LOOKUP_METHOD))` (`:22`).
const LINE_ZALLOC_METH: c_int = 22;
/// `X509_LOOKUP_meth_new`'s `OPENSSL_strdup(name)` (`:25`).
const LINE_STRDUP_METH: c_int = 25;
/// `X509_LOOKUP_meth_new`'s error-path `OPENSSL_free(method)` (`:33`).
const LINE_FREE_METH_NEW: c_int = 33;
/// `X509_LOOKUP_meth_free`'s `OPENSSL_free(method->name)` (`:40`).
const LINE_FREE_METH_NAME: c_int = 40;
/// `X509_LOOKUP_meth_free`'s `OPENSSL_free(method)` (`:41`).
const LINE_FREE_METH: c_int = 41;

// ---------------------------------------------------------------------------------------------
// Ownership of the method block
// ---------------------------------------------------------------------------------------------

/// An owned `X509_LOOKUP_METHOD` block still under construction.
///
/// `X509_LOOKUP_meth_new` allocates the block zeroed and fills its `name`; until the block is handed
/// to the caller its release is the block alone -- the authority's own error-path
/// `OPENSSL_free(method)` at `:33` -- so the full destructor (`X509_LOOKUP_meth_free`) over a `name`
/// that may not be set must not run. [`Self::finish`] hands the block to the caller on success.
///
/// Every member of the block is a raw pointer or an optional `extern "C"` callback
/// ([`crate::x509::x509_lu::X509LookupMethod`]), for which an all-zero block is a valid value, so the
/// zeroed block *is* a valid instance from its first byte.
struct RawMethod {
    ptr: NonNull<X509LookupMethod>,
}

impl RawMethod {
    /// `CRYPTO_zalloc(sizeof(X509_LOOKUP_METHOD), FILE, 22)`, or `None` when it answers NULL.
    fn new() -> Option<RawMethod> {
        // `CRYPTO_zalloc` is a safe function: it answers NULL or a fresh zeroed block of
        // `size_of::<X509LookupMethod>()` bytes, which is exactly `X509_LOOKUP_METHOD`'s layout.
        let raw = CRYPTO_zalloc(
            size_of::<X509LookupMethod>(),
            FILE.as_ptr(),
            LINE_ZALLOC_METH,
        )
        .cast::<X509LookupMethod>();
        NonNull::new(raw).map(|ptr| RawMethod { ptr })
    }

    /// The writable start of the block.
    fn as_ptr(&self) -> *mut X509LookupMethod {
        self.ptr.as_ptr()
    }

    /// Give up ownership of the block to the caller.
    fn finish(self) -> *mut X509LookupMethod {
        let p = self.ptr.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for RawMethod {
    /// The authority's `X509_LOOKUP_meth_new` error-path release (`:33`): the block alone.
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the block `new` allocated and has not been handed out; its single
        // release is the authority's own plain `CRYPTO_free` at the `err:` path.
        unsafe {
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_METH_NEW,
            )
        };
    }
}

/// An owned `X509_LOOKUP_METHOD` the C ABI hands back.
///
/// `X509_LOOKUP_meth_free` releases the method's `name` and the method; [`Self::from_raw`] reclaims a
/// block a previous [`RawMethod::finish`] handed to a C caller, so both releases are its `Drop`.
struct OwnedMethod {
    ptr: NonNull<X509LookupMethod>,
}

impl OwnedMethod {
    /// Reclaim a method the C ABI hands back, for release by `Drop`.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a live `X509_LOOKUP_METHOD` this file allocated through the `CRYPTO_*` seam
    /// that no other owner will release; its `name` is NULL or this file's own `CRYPTO_strdup`
    /// block. `Drop` performs both releases, at the authority's own sites.
    unsafe fn from_raw(ptr: *mut X509LookupMethod) -> Option<OwnedMethod> {
        NonNull::new(ptr).map(|ptr| OwnedMethod { ptr })
    }
}

impl Drop for OwnedMethod {
    /// The method's release (`X509_LOOKUP_meth_free`): its `name` (`:40`) then the block (`:41`).
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is the live method `from_raw` reclaimed and `Drop` runs once; `name`
        // is NULL (a `CRYPTO_free` no-op) or the block this file's `new` strdup'd, and both releases
        // are the authority's own.
        unsafe {
            CRYPTO_free(
                (*self.ptr.as_ptr()).name.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_METH_NAME,
            );
            CRYPTO_free(
                self.ptr.as_ptr().cast::<c_void>(),
                FILE.as_ptr(),
                LINE_FREE_METH,
            );
        }
    }
}

/// `X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name)` — `crypto/x509/x509_meth.c:20-35`.
///
/// A zeroed method whose `name` is a copy of `name`. A failed allocation or a NULL `name` (whose
/// `OPENSSL_strdup` answers NULL) frees the object and answers NULL.
///
/// # Safety
///
/// `name` must be NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_new(name: *const c_char) -> *mut X509LookupMethod {
    let Some(method) = RawMethod::new() else {
        return core::ptr::null_mut();
    };
    // SAFETY: `name` is NULL or NUL-terminated per the contract; the allocator takes the file/line
    // for its mdbg record only.
    let dup = unsafe { CRYPTO_strdup(name, FILE.as_ptr(), LINE_STRDUP_METH) };
    // SAFETY: `method` is this call's own fresh zeroed block, live and writable.
    unsafe { (*method.as_ptr()).name = dup };
    if dup.is_null() {
        // `method`'s `Drop` performs the authority's error-path release (`:33`).
        return core::ptr::null_mut();
    }
    method.finish()
}

/// `void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method)` —
/// `crypto/x509/x509_meth.c:37-42`.
///
/// Releases the method's name and the method. A NULL `method` is a no-op.
///
/// # Safety
///
/// `method` must be NULL or a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_free(method: *mut X509LookupMethod) {
    // SAFETY: `method` is NULL or a live `X509_LOOKUP_METHOD` this file allocated whose ownership no
    // other holder retains (the C contract); `OwnedMethod`'s `Drop` is its release.
    drop(unsafe { OwnedMethod::from_raw(method) });
}

/// `int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method, int (*new_item)(X509_LOOKUP
/// *ctx))` — `crypto/x509/x509_meth.c:44-49`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`; `new_item` is the callback contract's.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_new_item(
    method: *mut X509LookupMethod,
    new_item: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).new_item = new_item };
    1
}

/// `int (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_meth.c:51-54`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_new_item(
    method: *const X509LookupMethod,
) -> Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int> {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).new_item }
}

/// `int X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method, void (*free_fn)(X509_LOOKUP *ctx))`
/// — `crypto/x509/x509_meth.c:56-62`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_free(
    method: *mut X509LookupMethod,
    free_fn: Option<unsafe extern "C" fn(ctx: *mut X509Lookup)>,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).free = free_fn };
    1
}

/// `void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_meth.c:64-67`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_free(
    method: *const X509LookupMethod,
) -> Option<unsafe extern "C" fn(ctx: *mut X509Lookup)> {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).free }
}

/// `int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method, int (*init)(X509_LOOKUP *ctx))` —
/// `crypto/x509/x509_meth.c:69-74`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_init(
    method: *mut X509LookupMethod,
    init: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).init = init };
    1
}

/// `int (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_meth.c:76-79`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_init(
    method: *const X509LookupMethod,
) -> Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int> {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).init }
}

/// `int X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method, int (*shutdown)(X509_LOOKUP
/// *ctx))` — `crypto/x509/x509_meth.c:81-87`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_shutdown(
    method: *mut X509LookupMethod,
    shutdown: Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int>,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).shutdown = shutdown };
    1
}

/// `int (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD *method))(X509_LOOKUP *ctx)` —
/// `crypto/x509/x509_meth.c:89-92`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_shutdown(
    method: *const X509LookupMethod,
) -> Option<unsafe extern "C" fn(ctx: *mut X509Lookup) -> c_int> {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).shutdown }
}

/// `int X509_LOOKUP_meth_set_ctrl(X509_LOOKUP_METHOD *method, X509_LOOKUP_ctrl_fn ctrl)` —
/// `crypto/x509/x509_meth.c:94-100`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_ctrl(
    method: *mut X509LookupMethod,
    ctrl: X509_LOOKUP_ctrl_fn,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).ctrl = ctrl };
    1
}

/// `X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD *method)` —
/// `crypto/x509/x509_meth.c:102-105`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_ctrl(
    method: *const X509LookupMethod,
) -> X509_LOOKUP_ctrl_fn {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).ctrl }
}

/// `int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
/// X509_LOOKUP_get_by_subject_fn fn)` — `crypto/x509/x509_meth.c:107-112`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_subject(
    method: *mut X509LookupMethod,
    get_by_subject: X509_LOOKUP_get_by_subject_fn,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).get_by_subject = get_by_subject };
    1
}

/// `X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(const X509_LOOKUP_METHOD
/// *method)` — `crypto/x509/x509_meth.c:114-118`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_subject(
    method: *const X509LookupMethod,
) -> X509_LOOKUP_get_by_subject_fn {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).get_by_subject }
}

/// `int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD *method,
/// X509_LOOKUP_get_by_issuer_serial_fn fn)` — `crypto/x509/x509_meth.c:120-125`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_issuer_serial(
    method: *mut X509LookupMethod,
    get_by_issuer_serial: X509_LOOKUP_get_by_issuer_serial_fn,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).get_by_issuer_serial = get_by_issuer_serial };
    1
}

/// `X509_LOOKUP_get_by_issuer_serial_fn X509_LOOKUP_meth_get_get_by_issuer_serial(const
/// X509_LOOKUP_METHOD *method)` — `crypto/x509/x509_meth.c:127-131`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_issuer_serial(
    method: *const X509LookupMethod,
) -> X509_LOOKUP_get_by_issuer_serial_fn {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).get_by_issuer_serial }
}

/// `int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method,
/// X509_LOOKUP_get_by_fingerprint_fn fn)` — `crypto/x509/x509_meth.c:133-138`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_fingerprint(
    method: *mut X509LookupMethod,
    get_by_fingerprint: X509_LOOKUP_get_by_fingerprint_fn,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).get_by_fingerprint = get_by_fingerprint };
    1
}

/// `X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(const
/// X509_LOOKUP_METHOD *method)` — `crypto/x509/x509_meth.c:140-144`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_fingerprint(
    method: *const X509LookupMethod,
) -> X509_LOOKUP_get_by_fingerprint_fn {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).get_by_fingerprint }
}

/// `int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD *method,
/// X509_LOOKUP_get_by_alias_fn fn)` — `crypto/x509/x509_meth.c:146-151`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_set_get_by_alias(
    method: *mut X509LookupMethod,
    get_by_alias: X509_LOOKUP_get_by_alias_fn,
) -> c_int {
    // SAFETY: `method` is live and writable per the contract.
    unsafe { (*method).get_by_alias = get_by_alias };
    1
}

/// `X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(const X509_LOOKUP_METHOD
/// *method)` — `crypto/x509/x509_meth.c:153-157`.
///
/// # Safety
///
/// `method` must be a live `X509_LOOKUP_METHOD`.
#[no_mangle]
pub unsafe extern "C" fn X509_LOOKUP_meth_get_get_by_alias(
    method: *const X509LookupMethod,
) -> X509_LOOKUP_get_by_alias_fn {
    // SAFETY: `method` is live per the contract.
    unsafe { (*method).get_by_alias }
}
