//! Phase 3 core runtime — `ex_data`, the per-object extension-data interface.
//!
//! OpenSSL lets an application attach an arbitrary number of
//! `(index, void *)` slots to objects it does not own — an `X509`, an `SSL`,
//! a `BIO`, an application-defined class — and register three callbacks per
//! slot (`new`, `dup`, `free`) that the library invokes at the right points in
//! the object's lifetime. The indices are process-global and allocated per
//! *class*; the slots themselves live in a `CRYPTO_EX_DATA` structure that the
//! **caller owns and zero-initialises**.
//!
//! ## Why the layout is part of the contract
//!
//! Unlike the `ERR` queue or the `OPENSSL_STACK`, `CRYPTO_EX_DATA` is a public
//! struct: callers embed it by value in their own objects and zero it with
//! `memset`. Its layout is therefore ABI, not an implementation detail. The
//! authority's installed `crypto.h` declares it as
//!
//! ```c
//! struct crypto_ex_data_st {
//!     OSSL_LIB_CTX *ctx;
//!     STACK_OF(void) *sk;
//! };
//! ```
//!
//! (Some older OpenSSL releases named these fields `sk`/`dummy`; the installed
//! 3.6.4 header is the source of truth and carries `ctx`/`sk`, which is what
//! [`CryptoExData`] reproduces.) Because the second member is a real
//! `STACK_OF(void)`, this module stores the slots in the crate's own
//! [`crate::runtime::stack`] implementation rather than a private `Vec`: a
//! caller that reaches for the `sk_void_*` macros on `ad->sk` must observe a
//! genuine OpenSSL stack, exactly as it would against the authority.
//!
//! ## Index model (probed against the authority)
//!
//! Each class owns a *sentinel-carrying* list of callbacks. The first
//! registration leaves a `NULL` sentinel at position 0 and places the real
//! callback at position 1, and `CRYPTO_get_ex_new_index` returns that position
//! — so the first index a caller sees is **1**, not 0. Slot 0 of an
//! `ad->sk` is therefore never used by a registered callback, though
//! `CRYPTO_set_ex_data(ad, 0, …)` is still legal and observable.
//!
//! `CRYPTO_free_ex_index` does **not** renumber: it overwrites the callback
//! with no-op "dummy" functions, so indices stay stable and are never reused.
//! That is reproduced here with real no-op callback pointers rather than a
//! "removed" flag, because the observable difference (`CRYPTO_alloc_ex_data`
//! on a freed index still reports success) is real.
//!
//! ## Deliberate safe divergences
//!
//! The authority dereferences several caller pointers without a NULL check and
//! will segfault. `docs/UNSAFE.md` §5 forbids reproducing undefined behaviour
//! merely because an observed run did something, so this module returns the
//! documented failure value instead:
//!
//! * a NULL `CRYPTO_EX_DATA *` yields the failure value rather than a fault;
//! * `CRYPTO_alloc_ex_data` with an index outside the registered range (or
//!   negative) returns 0, where the authority reads through a NULL callback;
//! * `CRYPTO_LH_doall`-style callbacks are not re-entered while a Rust
//!   reference to the table is live (see `lhash.rs`).
//!
//! The `ctx` member selects a per-`OSSL_LIB_CTX` registry in the authority.
//! There is no `OSSL_LIB_CTX` yet in this crate, so a single process-global
//! registry is used for every context; `ctx` is stored verbatim and copied by
//! `dup` so that callers observing the field still see the authority's value.
//!
//! ## Signatures
//!
//! Taken from the authority's installed `crypto.h`, not from memory. The class
//! constants are `CRYPTO_EX_INDEX_*` and terminate at
//! `CRYPTO_EX_INDEX__COUNT == 18`.

use core::ffi::{c_int, c_long, c_void};
use std::sync::Mutex;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{ErrSite, EX_DATA_37, EX_DATA_474, EX_DATA_481, EX_DATA_487};
use crate::runtime::err::raise_site;
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_set,
    OPENSSL_sk_value, OpenSslStack,
};

/// `CRYPTO_EX_INDEX__COUNT` from the authority's `crypto.h`.
const CLASS_COUNT: usize = 18;

// The class indices, exactly as `crypto.h` defines them. They are C macros and
// therefore not exported symbols; reproducing the values is what lets a caller
// that branches on them keep working. Measured from the authority's own header.

/// `CRYPTO_EX_INDEX_SSL`.
pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
/// `CRYPTO_EX_INDEX_SSL_CTX`.
pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
/// `CRYPTO_EX_INDEX_SSL_SESSION`.
pub const CRYPTO_EX_INDEX_SSL_SESSION: c_int = 2;
/// `CRYPTO_EX_INDEX_X509`.
pub const CRYPTO_EX_INDEX_X509: c_int = 3;
/// `CRYPTO_EX_INDEX_X509_STORE`.
pub const CRYPTO_EX_INDEX_X509_STORE: c_int = 4;
/// `CRYPTO_EX_INDEX_X509_STORE_CTX`.
pub const CRYPTO_EX_INDEX_X509_STORE_CTX: c_int = 5;
/// `CRYPTO_EX_INDEX_DH`.
pub const CRYPTO_EX_INDEX_DH: c_int = 6;
/// `CRYPTO_EX_INDEX_DSA`.
pub const CRYPTO_EX_INDEX_DSA: c_int = 7;
/// `CRYPTO_EX_INDEX_EC_KEY`.
pub const CRYPTO_EX_INDEX_EC_KEY: c_int = 8;
/// `CRYPTO_EX_INDEX_RSA`.
pub const CRYPTO_EX_INDEX_RSA: c_int = 9;
/// `CRYPTO_EX_INDEX_ENGINE`.
pub const CRYPTO_EX_INDEX_ENGINE: c_int = 10;
/// `CRYPTO_EX_INDEX_UI`.
pub const CRYPTO_EX_INDEX_UI: c_int = 11;
/// `CRYPTO_EX_INDEX_BIO`.
pub const CRYPTO_EX_INDEX_BIO: c_int = 12;
/// `CRYPTO_EX_INDEX_APP`.
pub const CRYPTO_EX_INDEX_APP: c_int = 13;
/// `CRYPTO_EX_INDEX_UI_METHOD`.
pub const CRYPTO_EX_INDEX_UI_METHOD: c_int = 14;
/// `CRYPTO_EX_INDEX_RAND_DRBG` (also spelled `CRYPTO_EX_INDEX_DRBG`).
pub const CRYPTO_EX_INDEX_RAND_DRBG: c_int = 15;
/// `CRYPTO_EX_INDEX_OSSL_LIB_CTX`.
pub const CRYPTO_EX_INDEX_OSSL_LIB_CTX: c_int = 16;
/// `CRYPTO_EX_INDEX_EVP_PKEY`.
pub const CRYPTO_EX_INDEX_EVP_PKEY: c_int = 17;
/// `CRYPTO_EX_INDEX__COUNT`.
pub const CRYPTO_EX_INDEX__COUNT: c_int = CLASS_COUNT as c_int;

/// The layout-compatible representation of C's `CRYPTO_EX_DATA`.
///
/// The struct is public and caller-allocated, so its field order and size are
/// ABI. See the module documentation for the header this reproduces.
#[repr(C)]
pub struct CryptoExData {
    /// `OSSL_LIB_CTX *ctx` — stored and copied verbatim; not otherwise used
    /// yet because this crate has no `OSSL_LIB_CTX`.
    pub ctx: *mut c_void,
    /// `STACK_OF(void) *sk` — one slot per registered index, allocated lazily
    /// by [`CRYPTO_set_ex_data`].
    pub sk: *mut OpenSslStack,
}

/// `void (*)(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl,
/// void *argp)` — `CRYPTO_EX_new`.
type NewFunc =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut CryptoExData, c_int, c_long, *mut c_void);

/// `CRYPTO_EX_free` has the same shape as [`NewFunc`].
type FreeFunc = NewFunc;

/// `int (*)(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void **from_d,
/// int idx, long argl, void *argp)` — `CRYPTO_EX_dup`.
type DupFunc = unsafe extern "C" fn(
    *mut CryptoExData,
    *const CryptoExData,
    *mut *mut c_void,
    c_int,
    c_long,
    *mut c_void,
) -> c_int;

/// A registered callback triple plus its `(argl, argp)` payload.
///
/// `argp` is stored as a `usize` rather than a raw pointer so the registry is
/// `Send`; it is converted back to `*mut c_void` at the call site.
#[derive(Clone, Copy)]
struct Callback {
    new_func: Option<NewFunc>,
    dup_func: Option<DupFunc>,
    free_func: Option<FreeFunc>,
    argl: c_long,
    argp: usize,
}

/// The per-class callback registries.
///
/// Element 0 of every non-empty class list is the `None` sentinel that the
/// authority materialises as a `NULL` stack entry; registered callbacks start
/// at position 1. A never-used class is an empty `Vec`.
struct Registry {
    classes: [Vec<Option<Callback>>; CLASS_COUNT],
}

impl Registry {
    const fn new() -> Self {
        Self {
            classes: [const { Vec::new() }; CLASS_COUNT],
        }
    }
}

/// The process-global registry. The authority guards its equivalent with a
/// read/write lock; callbacks are always invoked with the lock released so a
/// callback may call back into this interface.
static REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());

/// Run `f` with the registry locked, recovering the guard if a previous panic
/// poisoned the mutex rather than propagating the poison.
fn with_registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut guard)
}

/// Report a failure on the thread-local `ERR` queue at the authority site this
/// code path reconstructs.
///
/// The three debug strings (file, line, function) and the `(lib, reason)` pair
/// all come from the generated table, so a caller reading them back through
/// `ERR_get_error_all` sees the authority's values rather than a placeholder.
///
/// The authority has two further raise sites in
/// `ossl_crypto_get_ex_new_index_ex` (`crypto/ex_data.c:175` and `:191`) that
/// fire only when an allocation fails. This crate's registry grows through
/// `Vec`, whose failure mode is an abort rather than a NULL, so those two sites
/// have no reachable counterpart here; they remain registered obligations in
/// `forensics/atlas/err-raise-sites.json`.
fn raise(site: &ErrSite) {
    // SAFETY: the site is a compile-time constant whose pointers are static.
    unsafe { raise_site(site) };
}

/// `0 <= class_index < CRYPTO_EX_INDEX__COUNT`.
fn valid_class(class_index: c_int) -> bool {
    class_index >= 0 && class_index < CLASS_COUNT as c_int
}

/// The no-op callback installed by `CRYPTO_free_ex_index`.
unsafe extern "C" fn dummy_new(
    _parent: *mut c_void,
    _ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
}

/// The no-op callback installed by `CRYPTO_free_ex_index`.
unsafe extern "C" fn dummy_free(
    _parent: *mut c_void,
    _ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
}

/// The no-op "dup" installed by `CRYPTO_free_ex_index`; it reports success so
/// a `dup` over a freed index still copies the slot.
unsafe extern "C" fn dummy_dup(
    _to: *mut CryptoExData,
    _from: *const CryptoExData,
    _from_d: *mut *mut c_void,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) -> c_int {
    1
}

/// `int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
/// CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)`
///
/// Allocates the next index for `class_index`. Indices are 1-based and never
/// reused; the first registration for any class returns 1. A class outside
/// `0..CRYPTO_EX_INDEX__COUNT` raises `ERR_R_PASSED_INVALID_ARGUMENT` and
/// returns -1.
#[no_mangle]
pub extern "C" fn CRYPTO_get_ex_new_index(
    class_index: c_int,
    argl: c_long,
    argp: *mut c_void,
    new_func: Option<NewFunc>,
    dup_func: Option<DupFunc>,
    free_func: Option<FreeFunc>,
) -> c_int {
    guard_ffi(-1, || {
        if !valid_class(class_index) {
            raise(&EX_DATA_37);
            return -1;
        }
        with_registry(|reg| {
            let classes = &mut reg.classes[class_index as usize];
            if classes.is_empty() {
                classes.push(None);
            }
            classes.push(Some(Callback {
                new_func,
                dup_func,
                free_func,
                argl,
                argp: argp as usize,
            }));
            (classes.len() - 1) as c_int
        })
    })
}

/// `int CRYPTO_free_ex_index(int class_index, int idx)`
///
/// Retires the callback at `idx` by overwriting it with no-op callbacks; the
/// index itself is not freed and will not be reused. Returns 1 when a
/// registered callback was retired, 0 for an out-of-range or sentinel index,
/// and 0 with an `ERR` for an invalid class.
#[no_mangle]
pub extern "C" fn CRYPTO_free_ex_index(class_index: c_int, idx: c_int) -> c_int {
    guard_ffi(0, || {
        if !valid_class(class_index) {
            raise(&EX_DATA_37);
            return 0;
        }
        with_registry(|reg| {
            let classes = &mut reg.classes[class_index as usize];
            if idx <= 0 || (idx as usize) >= classes.len() {
                return 0;
            }
            let slot = &mut classes[idx as usize];
            if slot.is_none() {
                return 0;
            }
            *slot = Some(Callback {
                new_func: Some(dummy_new),
                dup_func: Some(dummy_dup),
                free_func: Some(dummy_free),
                argl: 0,
                argp: 0,
            });
            1
        })
    })
}

/// `int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val)`
///
/// Creates the slot stack on first use, pads it with NULLs up to `idx`, and
/// stores `val`. Returns 1 on success; 0 with an `ERR` when the stack cannot
/// be grown or the index cannot be stored.
///
/// # Safety
/// `ad` must be NULL or point to a writable, properly aligned `CRYPTO_EX_DATA`
/// that is either zeroed or was initialised by this interface.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_set_ex_data(
    ad: *mut CryptoExData,
    idx: c_int,
    val: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        if ad.is_null() {
            return 0;
        }
        // SAFETY: `ad` is non-NULL and, per the caller's contract, points to a
        // writable `CRYPTO_EX_DATA`.
        let mut sk = unsafe { (*ad).sk };
        if sk.is_null() {
            sk = OPENSSL_sk_new_null();
            if sk.is_null() {
                raise(&EX_DATA_474);
                return 0;
            }
            // SAFETY: `ad` is writable; the freshly created stack is owned by
            // this slot until `free_ex_data` or another `set`.
            unsafe { (*ad).sk = sk };
        }
        loop {
            // SAFETY: `sk` is a live stack created by `OPENSSL_sk_new_null`.
            let n = unsafe { OPENSSL_sk_num(sk) };
            if n > idx {
                break;
            }
            // SAFETY: `sk` is live; a NULL data slot is a valid padding value.
            let pushed = unsafe { OPENSSL_sk_push(sk, core::ptr::null()) };
            if pushed == 0 {
                raise(&EX_DATA_481);
                return 0;
            }
        }
        // SAFETY: `sk` is live and `idx` is within range after padding.
        let stored = unsafe { OPENSSL_sk_set(sk, idx, val) };
        if !core::ptr::eq(stored, val.cast_const()) {
            raise(&EX_DATA_487);
            return 0;
        }
        1
    })
}

/// `void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx)`
///
/// Returns the stored pointer, or NULL when `ad` is NULL, the slot stack has
/// not been created, or `idx` is out of range.
///
/// # Safety
/// `ad` must be NULL or point to an initialised `CRYPTO_EX_DATA`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_get_ex_data(ad: *const CryptoExData, idx: c_int) -> *mut c_void {
    guard_ffi(core::ptr::null_mut(), || {
        if ad.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `ad` is non-NULL and initialised per the caller's contract.
        let sk = unsafe { (*ad).sk };
        if sk.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `sk` is a live stack; `OPENSSL_sk_value` NULLs out-of-range
        // and negative indices itself.
        unsafe { OPENSSL_sk_value(sk, idx) }
    })
}

/// Snapshot the callbacks of `class_index` under the registry lock.
fn snapshot(class_index: c_int) -> Vec<Option<Callback>> {
    with_registry(|reg| reg.classes[class_index as usize].clone())
}

/// `int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)`
///
/// Resets `ad` to empty and invokes each registered `new_func` in ascending
/// index order with `(obj, current_value, ad, idx, argl, argp)`. Returns 1 for
/// any valid class (even one with no callbacks); 0 with an `ERR` for an
/// invalid class.
///
/// # Safety
/// `ad` must be NULL or point to a writable `CRYPTO_EX_DATA`; `obj` is passed
/// through to the callbacks and is not dereferenced here.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_new_ex_data(
    class_index: c_int,
    obj: *mut c_void,
    ad: *mut CryptoExData,
) -> c_int {
    guard_ffi(0, || {
        if !valid_class(class_index) {
            raise(&EX_DATA_37);
            return 0;
        }
        if ad.is_null() {
            return 0;
        }
        let cbs = snapshot(class_index);
        // SAFETY: `ad` is non-NULL and writable. The authority discards any
        // pre-existing slot stack here rather than freeing it; that leak is
        // reproduced for observability, since a caller could still hold the
        // old `ad->sk` pointer.
        unsafe {
            (*ad).ctx = core::ptr::null_mut();
            (*ad).sk = core::ptr::null_mut();
        }
        for (pos, cb) in cbs.iter().enumerate() {
            if let Some(cb) = cb {
                if let Some(f) = cb.new_func {
                    // SAFETY: `ad` is initialised and `pos` is a valid index.
                    let ptr = unsafe { CRYPTO_get_ex_data(ad, pos as c_int) };
                    // SAFETY: `f` is the caller's registered constructor.
                    unsafe { f(obj, ptr, ad, pos as c_int, cb.argl, cb.argp as *mut c_void) };
                }
            }
        }
        1
    })
}

/// `void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)`
///
/// Invokes each registered `free_func` in ascending index order with
/// `(obj, current_value, ad, idx, argl, argp)`, then releases the slot stack
/// and zeroes `ad` (both `ctx` and `sk`). An invalid class raises an `ERR` but
/// still performs the release, exactly as the authority does.
///
/// # Safety
/// `ad` must be NULL or point to an initialised `CRYPTO_EX_DATA`; `obj` is
/// passed through to the callbacks.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_free_ex_data(
    class_index: c_int,
    obj: *mut c_void,
    ad: *mut CryptoExData,
) {
    guard_ffi((), || {
        if ad.is_null() {
            return;
        }
        let valid = valid_class(class_index);
        if !valid {
            raise(&EX_DATA_37);
        }
        let cbs = if valid {
            snapshot(class_index)
        } else {
            Vec::new()
        };
        for (pos, cb) in cbs.iter().enumerate() {
            if let Some(cb) = cb {
                if let Some(f) = cb.free_func {
                    // SAFETY: `ad` is initialised; the authority reads the
                    // live slot value at callback time.
                    let ptr = unsafe { CRYPTO_get_ex_data(ad, pos as c_int) };
                    // SAFETY: `f` is the caller's registered destructor.
                    unsafe { f(obj, ptr, ad, pos as c_int, cb.argl, cb.argp as *mut c_void) };
                }
            }
        }
        // SAFETY: `ad` is non-NULL and writable.
        let sk = unsafe { (*ad).sk };
        if !sk.is_null() {
            // SAFETY: `sk` is the stack owned by `ad`; it is not used again
            // after `ad` is zeroed below.
            unsafe { OPENSSL_sk_free(sk) };
        }
        // SAFETY: `ad` is writable and its contents are dead.
        unsafe {
            (*ad).sk = core::ptr::null_mut();
            (*ad).ctx = core::ptr::null_mut();
        }
    })
}

/// `int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
/// const CRYPTO_EX_DATA *from)`
///
/// Copies `from`'s context pointer and slots into `to`, invoking each
/// registered `dup_func` in ascending index order with a pointer to the value
/// being copied. The loop covers the sentinel position 0 as well as the
/// registered indices, so slots 0..=count are copied. Returns 1 on success
/// (including the trivial cases) and 0 on an allocation failure, an invalid
/// class, or when the class has no registry at all.
///
/// # Safety
/// `to` and `from` must be NULL or point to initialised `CRYPTO_EX_DATA`
/// values; `to` must be writable and distinct from `from`.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_dup_ex_data(
    class_index: c_int,
    to: *mut CryptoExData,
    from: *const CryptoExData,
) -> c_int {
    guard_ffi(0, || {
        if to.is_null() || from.is_null() {
            return 0;
        }
        // SAFETY: both pointers are non-NULL and initialised.
        unsafe { (*to).ctx = (*from).ctx };
        // SAFETY: `from` is initialised.
        let from_sk = unsafe { (*from).sk };
        if from_sk.is_null() {
            return 1;
        }
        if !valid_class(class_index) {
            raise(&EX_DATA_37);
            return 0;
        }
        let cbs = snapshot(class_index);
        if cbs.is_empty() {
            // No registry exists for this class. The authority computes
            // `sk_num(NULL) == -1` and returns 0 here.
            return 0;
        }
        // SAFETY: `from_sk` is a live stack.
        let slots = unsafe { OPENSSL_sk_num(from_sk) };
        let count = core::cmp::min(cbs.len() as c_int, slots);
        if count <= 0 {
            return 1;
        }
        for pos in 0..count {
            // SAFETY: `from` is initialised and `pos` is in range.
            let mut value = unsafe { CRYPTO_get_ex_data(from, pos) };
            if let Some(Some(cb)) = cbs.get(pos as usize) {
                if let Some(f) = cb.dup_func {
                    // SAFETY: `f` is the caller's registered dup callback; it
                    // may replace the value through `&mut value`.
                    let rc =
                        unsafe { f(to, from, &mut value, pos, cb.argl, cb.argp as *mut c_void) };
                    if rc == 0 {
                        return 0;
                    }
                }
            }
            // SAFETY: `to` is initialised and writable; the authority stores
            // the value (including NULL) unconditionally.
            if unsafe { CRYPTO_set_ex_data(to, pos, value) } == 0 {
                return 0;
            }
        }
        1
    })
}

/// `int CRYPTO_alloc_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad,
/// int idx)`
///
/// Invokes the `new_func` registered at `idx` for an empty slot. Returns 1
/// when the slot already has a value (the callback is not invoked), 1 after a
/// successful callback, and 0 when no constructor is registered or the index
/// is out of range. An out-of-range index returns 0 here rather than faulting
/// (see the module note); the callback receives a NULL `ptr`.
///
/// # Safety
/// `ad` must be NULL or point to an initialised, writable `CRYPTO_EX_DATA`;
/// `obj` is passed through to the callback.
#[no_mangle]
pub unsafe extern "C" fn CRYPTO_alloc_ex_data(
    class_index: c_int,
    obj: *mut c_void,
    ad: *mut CryptoExData,
    idx: c_int,
) -> c_int {
    guard_ffi(0, || {
        if ad.is_null() {
            return 0;
        }
        // SAFETY: `ad` is initialised.
        if !unsafe { CRYPTO_get_ex_data(ad, idx) }.is_null() {
            return 1;
        }
        if !valid_class(class_index) {
            raise(&EX_DATA_37);
            return 0;
        }
        let cb = with_registry(|reg| {
            let classes = &reg.classes[class_index as usize];
            if idx < 0 || (idx as usize) >= classes.len() {
                None
            } else {
                classes[idx as usize]
            }
        });
        match cb.and_then(|cb| cb.new_func.map(|f| (f, cb))) {
            None => 0,
            Some((f, cb)) => {
                // SAFETY: `f` is the caller's registered constructor, invoked
                // with the `(argl, argp)` values that were registered alongside
                // it. `ptr` is NULL here, which is what the authority passes from
                // `CRYPTO_alloc_ex_data`.
                unsafe {
                    f(
                        obj,
                        core::ptr::null_mut(),
                        ad,
                        idx,
                        cb.argl,
                        cb.argp as *mut c_void,
                    )
                };
                1
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::runtime::err::ERR_get_error;
    use std::cell::RefCell;

    thread_local! {
        static LOG: RefCell<Vec<(u8, c_int, c_long)>> = const { RefCell::new(Vec::new()) };
    }

    fn record(kind: u8, idx: c_int, argl: c_long) {
        LOG.with(|l| l.borrow_mut().push((kind, idx, argl)));
    }

    extern "C" fn log_new(
        _parent: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        idx: c_int,
        argl: c_long,
        _argp: *mut c_void,
    ) {
        record(b'N', idx, argl);
    }

    extern "C" fn log_free(
        _parent: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        idx: c_int,
        argl: c_long,
        _argp: *mut c_void,
    ) {
        record(b'F', idx, argl);
    }

    extern "C" fn log_dup(
        _to: *mut CryptoExData,
        _from: *const CryptoExData,
        from_d: *mut *mut c_void,
        idx: c_int,
        argl: c_long,
        _argp: *mut c_void,
    ) -> c_int {
        record(b'D', idx, argl);
        // Exercise the value pointer the way a real callback would.
        if !from_d.is_null() {
            // SAFETY: `from_d` is a valid out-parameter supplied by dup.
            let _ = unsafe { *from_d };
        }
        1
    }

    fn zeroed() -> CryptoExData {
        CryptoExData {
            ctx: core::ptr::null_mut(),
            sk: core::ptr::null_mut(),
        }
    }

    #[test]
    fn indices_are_monotonic_and_per_class() {
        // Exclusive classes keep this test independent of the others.
        let a = CRYPTO_get_ex_new_index(3, 1, core::ptr::null_mut(), None, None, None);
        let b = CRYPTO_get_ex_new_index(3, 2, core::ptr::null_mut(), None, None, None);
        assert!(a >= 1, "first index must be 1-based, got {a}");
        assert_eq!(b, a + 1, "indices increment by one");
        let other = CRYPTO_get_ex_new_index(4, 3, core::ptr::null_mut(), None, None, None);
        assert!(other >= 1);
        assert_eq!(
            CRYPTO_get_ex_new_index(-1, 0, core::ptr::null_mut(), None, None, None),
            -1
        );
        assert_eq!(
            CRYPTO_get_ex_new_index(
                CLASS_COUNT as c_int,
                0,
                core::ptr::null_mut(),
                None,
                None,
                None
            ),
            -1
        );
        let _ = ERR_get_error();
    }

    #[test]
    fn set_get_and_out_of_range() {
        let mut ad = zeroed();
        // SAFETY: `ad` is a live, zeroed structure, so every read below is valid;
        // out-of-range and NULL indices are explicitly handled by the API.
        unsafe {
            assert!(CRYPTO_get_ex_data(&ad, 0).is_null());
            assert_eq!(CRYPTO_set_ex_data(&mut ad, 2, 0x1234 as *mut c_void), 1);
            assert_eq!(CRYPTO_get_ex_data(&ad, 2), 0x1234 as *mut c_void);
            assert!(CRYPTO_get_ex_data(&ad, 1).is_null());
            assert!(CRYPTO_get_ex_data(&ad, -1).is_null());
            assert!(CRYPTO_get_ex_data(&ad, 99).is_null());
            assert!(CRYPTO_get_ex_data(core::ptr::null(), 0).is_null());
        }
        // SAFETY: passing a NULL `ad` is explicitly handled and returns 0.
        assert_eq!(
            unsafe {
                // SAFETY: a NULL `ad` is rejected before any pointer is used.
                CRYPTO_set_ex_data(core::ptr::null_mut(), 0, core::ptr::null_mut())
            },
            0
        );
        // SAFETY: `ad` owns a stack from the `set` above.
        unsafe { CRYPTO_free_ex_data(5, core::ptr::null_mut(), &mut ad) };
        assert!(ad.sk.is_null());
        assert!(ad.ctx.is_null());
    }

    #[test]
    fn callbacks_run_in_registration_order_with_their_args() {
        let ad_sk = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_APP,
            11,
            core::ptr::null_mut(),
            Some(log_new),
            Some(log_dup),
            Some(log_free),
        );
        let i2 = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_APP,
            22,
            core::ptr::null_mut(),
            Some(log_new),
            Some(log_dup),
            Some(log_free),
        );
        assert_eq!(i2, ad_sk + 1);
        LOG.with(|l| l.borrow_mut().clear());
        let mut ad = zeroed();
        // SAFETY: `ad` is live and zeroed; a NULL parent is accepted.
        unsafe {
            assert_eq!(
                CRYPTO_new_ex_data(CRYPTO_EX_INDEX_APP, core::ptr::null_mut(), &mut ad),
                1
            );
        }
        LOG.with(|l| {
            let log = l.borrow();
            assert_eq!(log.len(), 2, "both registered constructors run");
            assert_eq!(log[0], (b'N', ad_sk, 11));
            assert_eq!(log[1], (b'N', i2, 22));
        });

        // MEASURED (`courts/phase3/rt_exdata_probe.c`): `CRYPTO_new_ex_data`
        // performs the callback but does NOT allocate the slot stack, and
        // `CRYPTO_dup_ex_data` returns 1 WITHOUT invoking any dup callback when
        // the source has no stack. Both are easy to get plausibly wrong.
        assert!(
            ad.sk.is_null(),
            "new_ex_data must not allocate the slot stack"
        );
        LOG.with(|l| l.borrow_mut().clear());
        let mut to = zeroed();
        // SAFETY: both structures are live and distinct; `ad` has no stack.
        unsafe {
            assert_eq!(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &mut to, &ad), 1);
        }
        LOG.with(|l| assert!(l.borrow().is_empty(), "no dup without a source stack"));

        // Populating a slot is what allocates the stack. Now a duplicate must run
        // every registered dup callback, in index order, with its own `argl`.
        // SAFETY: `ad` is live.
        unsafe {
            assert_eq!(CRYPTO_set_ex_data(&mut ad, ad_sk, 0x1234 as *mut c_void), 1);
            assert_eq!(CRYPTO_set_ex_data(&mut ad, i2, 0x5678 as *mut c_void), 1);
        }
        LOG.with(|l| l.borrow_mut().clear());
        // SAFETY: `to` is live and distinct from `ad`.
        unsafe {
            assert_eq!(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_APP, &mut to, &ad), 1);
        }
        LOG.with(|l| {
            let log = l.borrow();
            assert_eq!(log[0], (b'D', ad_sk, 11));
            assert_eq!(log[1], (b'D', i2, 22));
        });

        LOG.with(|l| l.borrow_mut().clear());
        // SAFETY: both are live; free releases the stacks inside them.
        unsafe {
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, core::ptr::null_mut(), &mut ad);
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, core::ptr::null_mut(), &mut to);
        }
        LOG.with(|l| {
            let log = l.borrow();
            assert_eq!(log[0], (b'F', ad_sk, 11));
            assert_eq!(log[1], (b'F', i2, 22));
            assert_eq!(log[2], (b'F', ad_sk, 11));
            assert_eq!(log[3], (b'F', i2, 22));
        });
    }

    #[test]
    fn dup_copies_ctx_and_slot_zero() {
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_DH,
            7,
            core::ptr::null_mut(),
            None,
            None,
            None,
        );
        assert!(idx >= 1);
        let mut from = zeroed();
        from.ctx = 0xC7 as *mut c_void;
        // SAFETY: `from` is live.
        unsafe {
            assert_eq!(CRYPTO_set_ex_data(&mut from, 0, 0xA0 as *mut c_void), 1);
        }
        let mut to = zeroed();
        // SAFETY: `to` and `from` are live and distinct.
        unsafe {
            assert_eq!(CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DH, &mut to, &from), 1);
        }
        assert_eq!(to.ctx, 0xC7 as *mut c_void);
        // SAFETY: `to` is a live structure whose slot 0 was just populated.
        assert_eq!(unsafe { CRYPTO_get_ex_data(&to, 0) }, 0xA0 as *mut c_void);
        // SAFETY: both own stacks.
        unsafe {
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, core::ptr::null_mut(), &mut from);
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, core::ptr::null_mut(), &mut to);
        }
    }

    #[test]
    fn alloc_invokes_new_for_empty_slot_and_is_idempotent() {
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_EC_KEY,
            5,
            core::ptr::null_mut(),
            Some(log_new),
            None,
            None,
        );
        assert!(idx >= 1);
        let mut ad = zeroed();
        // SAFETY: `ad` is live.
        unsafe {
            assert_eq!(
                CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad),
                1
            );
        }
        LOG.with(|l| l.borrow_mut().clear());
        // SAFETY: `ad` is live.
        let r = unsafe {
            CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad, idx)
        };
        assert_eq!(r, 1);
        LOG.with(|l| assert_eq!(l.borrow().as_slice(), &[(b'N', idx, 5)]));
        // Now store a value and confirm the callback is skipped.
        // SAFETY: `ad` is live.
        unsafe {
            assert_eq!(CRYPTO_set_ex_data(&mut ad, idx, 0x55 as *mut c_void), 1);
        }
        LOG.with(|l| l.borrow_mut().clear());
        // SAFETY: `ad` is live.
        let r = unsafe {
            CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad, idx)
        };
        assert_eq!(r, 1);
        LOG.with(|l| assert!(l.borrow().is_empty()));
        // Out-of-range and negative indices return 0 (documented divergence).
        // SAFETY: `ad` is live.
        unsafe {
            assert_eq!(
                CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad, 999),
                0
            );
            assert_eq!(
                CRYPTO_alloc_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad, -1),
                0
            );
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EC_KEY, core::ptr::null_mut(), &mut ad);
        }
    }

    #[test]
    fn free_ex_index_retires_without_renumbering() {
        let first = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_RSA,
            1,
            core::ptr::null_mut(),
            Some(log_new),
            None,
            Some(log_free),
        );
        let second = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_RSA,
            2,
            core::ptr::null_mut(),
            Some(log_new),
            None,
            Some(log_free),
        );
        assert_eq!(second, first + 1);
        assert_eq!(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, first), 1);
        assert_eq!(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, 0), 0);
        assert_eq!(CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, 999), 0);
        assert_eq!(CRYPTO_free_ex_index(-1, 0), 0);
        let _ = ERR_get_error();
        let third = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_RSA,
            3,
            core::ptr::null_mut(),
            Some(log_new),
            None,
            Some(log_free),
        );
        assert_eq!(third, second + 1, "retired indices are not reused");
        LOG.with(|l| l.borrow_mut().clear());
        let mut ad = zeroed();
        // SAFETY: `ad` is live.
        unsafe {
            assert_eq!(
                CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, core::ptr::null_mut(), &mut ad),
                1
            );
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, core::ptr::null_mut(), &mut ad);
        }
        LOG.with(|l| {
            let log = l.borrow();
            // The retired index `first` must not appear.
            assert!(log.iter().all(|e| e.1 != first));
            assert_eq!(log[0], (b'N', second, 2));
            assert_eq!(log[1], (b'N', third, 3));
        });
    }

    #[test]
    fn invalid_class_is_rejected() {
        let mut ad = zeroed();
        // SAFETY: `ad` is live; the class check precedes any use of it.
        unsafe {
            assert_eq!(CRYPTO_new_ex_data(-1, core::ptr::null_mut(), &mut ad), 0);
            assert_eq!(
                CRYPTO_new_ex_data(CLASS_COUNT as c_int, core::ptr::null_mut(), &mut ad),
                0
            );
        }
        // MEASURED: with a source that has no slot stack, `CRYPTO_dup_ex_data`
        // returns 1 *before* it looks at the class at all. Class validation only
        // happens once there is something to copy, so the zeroed case must NOT be
        // read as "the invalid class was accepted".
        // SAFETY: both arguments refer to the same live, stackless structure.
        assert_eq!(unsafe { CRYPTO_dup_ex_data(-1, &mut ad, &ad) }, 1);

        // With a populated source the invalid class IS rejected, and an error is
        // raised (both measured with `courts/phase3/rt_exdata_probe.c`).
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_APP,
            5,
            core::ptr::null_mut(),
            None,
            None,
            None,
        );
        let mut src = zeroed();
        // SAFETY: `src` is live.
        unsafe {
            assert_eq!(CRYPTO_set_ex_data(&mut src, idx, 0x9 as *mut c_void), 1);
        }
        let mut to = zeroed();
        crate::runtime::err::ERR_clear_error();
        // SAFETY: `src` and `to` are live and distinct.
        assert_eq!(unsafe { CRYPTO_dup_ex_data(-1, &mut to, &src) }, 0);
        assert_ne!(
            crate::runtime::err::ERR_peek_error(),
            0,
            "an invalid class with a populated source must raise"
        );
        crate::runtime::err::ERR_clear_error();
        // SAFETY: `src` owns a stack; freeing it is the caller's job.
        unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_APP, core::ptr::null_mut(), &mut src) };
        let _ = ERR_get_error();
    }
}
