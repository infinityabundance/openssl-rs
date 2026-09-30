//! `crypto/store/store_register.c` — the legacy `OSSL_STORE_LOADER` object and its registry.
//! Phase 10 (10.5).
//!
//! The unit is 302 lines and sixteen exports. Twelve are the deprecated `OSSL_STORE_LOADER_*`
//! object (`new`, two accessors, and the ten setter functions); four are the scheme registry
//! (`OSSL_STORE_register_loader`, `OSSL_STORE_unregister_loader`, `OSSL_STORE_do_all_loaders`
//! and the engine accessor's sibling count below). The four unexported workers
//! (`ossl_store_register_loader_int`, `ossl_store_get0_loader_int`,
//! `ossl_store_unregister_loader_int` and `ossl_store_destroy_loaders_int`) land with them.
//!
//! # The registry's container, and the one observable difference from the authority's
//!
//! The authority keys a process-global `LHASH_OF(OSSL_STORE_LOADER)` by scheme, under a
//! `CRYPTO_RWLOCK` created by a `RUN_ONCE`. This transcription keeps the lock and the
//! once, and keeps the **set semantics** the public API promises — insert-or-replace,
//! retrieve by `strcmp`, delete by `strcmp` — but uses the crate's own `OpenSslStack` for
//! storage rather than a re-implemented LHASH. `OSSL_STORE_do_all_loaders` therefore walks
//! the loaders in insertion order where the authority walks them in the hash's bucket
//! order. **The order is not part of the observable contract** — `store.h:362-367` gives
//! the callback no ordering guarantee, and the authority's own order depends on
//! `OPENSSL_LH_strhash` — so `RT-STORE`'s `do_all` observations are keyed per scheme
//! rather than by position. A caller that observed the order would see a difference; none
//! can through the declared interface.
//!
//! **A duplicate insert leaks the replaced loader in the authority too.** `lh_..._insert`
//! returns the old value and `ossl_store_register_loader_int` ignores it; the replacement
//! below likewise drops the old pointer without freeing it, which is faithful rather than
//! tidy.
//!
//! # The local `err_sites` declaration
//!
//! `crypto/store/store_register.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`,
//! so its ten raise coordinates are declared here under the generator's own naming, the way
//! `src/pkcs12/p12_npas.rs` and `src/provider/encode_key2any.rs` declare theirs, and move
//! into `src/runtime/err_sites.rs` when that generator's file list next carries this unit.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use crate::runtime::ctype::{ossl_isalpha, ossl_isdigit};
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::mem::CRYPTO_zalloc;
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_set, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CRYPTO_THREAD_run_once, CRYPTO_THREAD_unlock,
    CRYPTO_THREAD_write_lock, CryptoRwlock,
};

use super::{
    OsslStoreAttachFn, OsslStoreCloseFn, OsslStoreCtrlFn, OsslStoreEofFn, OsslStoreErrorFn,
    OsslStoreExpectFn, OsslStoreFindFn, OsslStoreLoadFn, OsslStoreLoader, OsslStoreOpenExFn,
    OsslStoreOpenFn,
};

/// `ERR_LIB_OSSL_STORE` — `include/openssl/err.h:158`.
const ERR_LIB_OSSL_STORE: c_int = 44;
/// `OSSL_STORE_R_INVALID_SCHEME` — `include/openssl/storeerr.h:29`.
const OSSL_STORE_R_INVALID_SCHEME: c_int = 106;
/// `OSSL_STORE_R_LOADER_INCOMPLETE` — `include/openssl/storeerr.h:33`.
const OSSL_STORE_R_LOADER_INCOMPLETE: c_int = 116;
/// `OSSL_STORE_R_UNREGISTERED_SCHEME` — `include/openssl/storeerr.h:42`.
const OSSL_STORE_R_UNREGISTERED_SCHEME: c_int = 105;
/// `ERR_R_CRYPTO_LIB` — `err.h:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_INTERNAL_ERROR` — `err.h:356`, `259 | ERR_R_FATAL`.
const ERR_R_INTERNAL_ERROR: c_int = 786691;

/// One `store_register.c` raise coordinate. `line` and `func` are the authority file's own.
const fn register_site(line: c_int, func: &'static CStr, reason: c_int) -> err_sites::ErrSite {
    err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/store/store_register.c",
        line,
        func,
        lib: ERR_LIB_OSSL_STORE,
        reason,
        dynamic_reason: false,
    }
}

/// `OSSL_STORE_LOADER_new` at `store_register.c:42`.
const STORE_REGISTER_42: err_sites::ErrSite =
    register_site(42, c"OSSL_STORE_LOADER_new", OSSL_STORE_R_INVALID_SCHEME);
/// `ossl_store_register_loader_int` at `store_register.c:178`.
const STORE_REGISTER_178: err_sites::ErrSite = register_site(
    178,
    c"ossl_store_register_loader_int",
    OSSL_STORE_R_INVALID_SCHEME,
);
/// `ossl_store_register_loader_int` at `store_register.c:186`.
const STORE_REGISTER_186: err_sites::ErrSite = register_site(
    186,
    c"ossl_store_register_loader_int",
    OSSL_STORE_R_LOADER_INCOMPLETE,
);
/// `ossl_store_register_loader_int` at `store_register.c:192`.
const STORE_REGISTER_192: err_sites::ErrSite =
    register_site(192, c"ossl_store_register_loader_int", ERR_R_CRYPTO_LIB);
/// `ossl_store_get0_loader_int` at `store_register.c:226`.
const STORE_REGISTER_226: err_sites::ErrSite =
    register_site(226, c"ossl_store_get0_loader_int", ERR_R_CRYPTO_LIB);
/// `ossl_store_get0_loader_int` at `store_register.c:233`.
const STORE_REGISTER_233: err_sites::ErrSite =
    register_site(233, c"ossl_store_get0_loader_int", ERR_R_INTERNAL_ERROR);
/// `ossl_store_get0_loader_int` at `store_register.c:237`.
const STORE_REGISTER_237: err_sites::ErrSite = register_site(
    237,
    c"ossl_store_get0_loader_int",
    OSSL_STORE_R_UNREGISTERED_SCHEME,
);
/// `ossl_store_unregister_loader_int` at `store_register.c:258`.
const STORE_REGISTER_258: err_sites::ErrSite =
    register_site(258, c"ossl_store_unregister_loader_int", ERR_R_CRYPTO_LIB);
/// `ossl_store_unregister_loader_int` at `store_register.c:265`.
const STORE_REGISTER_265: err_sites::ErrSite = register_site(
    265,
    c"ossl_store_unregister_loader_int",
    ERR_R_INTERNAL_ERROR,
);
/// `ossl_store_unregister_loader_int` at `store_register.c:269`.
const STORE_REGISTER_269: err_sites::ErrSite = register_site(
    269,
    c"ossl_store_unregister_loader_int",
    OSSL_STORE_R_UNREGISTERED_SCHEME,
);

// ---------------------------------------------------------------------------
// The process-global registry
// ---------------------------------------------------------------------------

/// `static CRYPTO_ONCE registry_init = CRYPTO_ONCE_STATIC_INIT` — `store_register.c:19`.
static REGISTRY_ONCE: AtomicI32 = AtomicI32::new(0);
/// `static CRYPTO_RWLOCK *registry_lock` — `store_register.c:18`.
static REGISTRY_LOCK: AtomicPtr<CryptoRwlock> = AtomicPtr::new(ptr::null_mut());
/// `static LHASH_OF(OSSL_STORE_LOADER) *loader_register = NULL` — `store_register.c:150`.
///
/// The container this transcription substitutes for the authority's LHASH; see the module
/// doc for the one observable difference (do-all order).
static LOADER_REGISTER: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `DEFINE_RUN_ONCE_STATIC(do_registry_init)` — `store_register.c:21-25`.
///
/// Creates the registry lock. The authority's answer is `registry_lock != NULL`; because the
/// crate's `CRYPTO_THREAD_run_once` takes a `void` initialiser, the success test is made by
/// [`ensure_registry`] against the published pointer, which is the same predicate.
extern "C" fn do_registry_init() {
    // `CRYPTO_THREAD_lock_new` is a SAFE function in this crate, and `CRYPTO_THREAD_run_once`
    // calls this exactly once; the store is the publication.
    REGISTRY_LOCK.store(CRYPTO_THREAD_lock_new(), Ordering::Release);
}

/// `RUN_ONCE(&registry_init, do_registry_init)` — the authority's three callers' guard.
///
/// Answers true when the lock exists, which is `RUN_ONCE`'s int answer in the authority.
fn ensure_registry() -> bool {
    // SAFETY: `REGISTRY_ONCE` is this module's own `CRYPTO_ONCE` storage, and
    // `do_registry_init` is a valid `extern "C"` initialiser with no parameters.
    if unsafe { CRYPTO_THREAD_run_once(REGISTRY_ONCE.as_ptr(), Some(do_registry_init)) } == 0 {
        return false;
    }
    !REGISTRY_LOCK.load(Ordering::Acquire).is_null()
}

/// `static int ossl_store_register_init(void)` — `store_register.c:151-158`.
///
/// Creates the loader stack lazily. Called only under the registry lock, so no atomic
/// publish beyond the store itself is needed.
fn ossl_store_register_init() -> bool {
    if !LOADER_REGISTER.load(Ordering::Acquire).is_null() {
        return true;
    }
    let stack = OPENSSL_sk_new_null();
    if stack.is_null() {
        return false;
    }
    LOADER_REGISTER.store(stack, Ordering::Release);
    true
}

/// The loader whose `scheme` equals `scheme`, or NULL.
///
/// # Safety
/// `scheme` must be NUL-terminated. Each stored loader's own `scheme` is NUL-terminated
/// because only [`OSSL_STORE_LOADER_new`] or `store_meth.c`'s constructor can have made it,
/// and both reject NULL.
unsafe fn find_loader(scheme: *const c_char) -> *mut OsslStoreLoader {
    let stack = LOADER_REGISTER.load(Ordering::Acquire);
    if stack.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `stack` is the live register per the load above.
    let n = unsafe { OPENSSL_sk_num(stack) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i < n`, so the value is one of the register's own loader pointers.
        let loader = unsafe { OPENSSL_sk_value(stack, i) }.cast::<OsslStoreLoader>();
        // SAFETY: both `scheme` and the loader's own scheme are NUL-terminated.
        if !loader.is_null() && unsafe { schemes_equal((*loader).scheme, scheme) } {
            return loader;
        }
        i += 1;
    }
    ptr::null_mut()
}

/// `strcmp(a, b) == 0`, for two scheme strings.
///
/// # Safety
/// Both pointers must be NUL-terminated.
unsafe fn schemes_equal(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return a == b;
    }
    let mut i = 0usize;
    loop {
        // SAFETY: both are NUL-terminated per the contract, so neither read leaves the string.
        let (ca, cb) = unsafe { (*a.add(i), *b.add(i)) };
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// The `OSSL_STORE_LOADER` object — `store_register.c:31-132`
// ---------------------------------------------------------------------------

/// `OSSL_STORE_LOADER *OSSL_STORE_LOADER_new(ENGINE *e, const char *scheme)` —
/// `store_register.c:31-52`.
///
/// A zeroed object with the legacy `engine` and the **borrowed** `scheme`; the object's
/// `prov` stays NULL, which is what makes `OSSL_STORE_LOADER_free` take the legacy path.
/// A NULL scheme is refused with `OSSL_STORE_R_INVALID_SCHEME` rather than accepted, because
/// the scheme is what the registry keys on and a NULL one would fail later with a mystery.
///
/// # Safety
/// `scheme`, when non-NULL, must remain valid for the loader's whole lifetime: it is not
/// copied.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_new(
    e: *mut c_void,
    scheme: *const c_char,
) -> *mut OsslStoreLoader {
    if scheme.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_42) };
        return ptr::null_mut();
    }

    // SAFETY: the constructor asks only for a zeroed block of the object's size.
    let res = CRYPTO_zalloc(core::mem::size_of::<OsslStoreLoader>(), ptr::null(), 0)
        .cast::<OsslStoreLoader>();
    if res.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `res` is a fresh, uniquely-owned block.
    unsafe {
        (*res).engine = e;
        (*res).scheme = scheme;
    }
    res
}

/// `const ENGINE *OSSL_STORE_LOADER_get0_engine(const OSSL_STORE_LOADER *loader)` —
/// `store_register.c:54-57`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_engine(
    loader: *const OsslStoreLoader,
) -> *const c_void {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).engine }
}

/// `const char *OSSL_STORE_LOADER_get0_scheme(const OSSL_STORE_LOADER *loader)` —
/// `store_register.c:59-62`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_get0_scheme(
    loader: *const OsslStoreLoader,
) -> *const c_char {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).scheme }
}

/// `int OSSL_STORE_LOADER_set_open(OSSL_STORE_LOADER *loader, OSSL_STORE_open_fn f)` —
/// `store_register.c:64-69`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_open(
    loader: *mut OsslStoreLoader,
    open_function: Option<OsslStoreOpenFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).open = open_function };
    1
}

/// `int OSSL_STORE_LOADER_set_open_ex(OSSL_STORE_LOADER *loader, OSSL_STORE_open_ex_fn f)` —
/// `store_register.c:71-76`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_open_ex(
    loader: *mut OsslStoreLoader,
    open_ex_function: Option<OsslStoreOpenExFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).open_ex = open_ex_function };
    1
}

/// `int OSSL_STORE_LOADER_set_attach(OSSL_STORE_LOADER *loader, OSSL_STORE_attach_fn f)` —
/// `store_register.c:78-83`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_attach(
    loader: *mut OsslStoreLoader,
    attach_function: Option<OsslStoreAttachFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).attach = attach_function };
    1
}

/// `int OSSL_STORE_LOADER_set_ctrl(OSSL_STORE_LOADER *loader, OSSL_STORE_ctrl_fn f)` —
/// `store_register.c:85-90`.
///
/// The function pointer is the authority's `OSSL_STORE_ctrl_fn` shape, [`StoreCtrlFn`].
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_ctrl(
    loader: *mut OsslStoreLoader,
    ctrl_function: Option<OsslStoreCtrlFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).ctrl = ctrl_function };
    1
}

/// `int OSSL_STORE_LOADER_set_expect(OSSL_STORE_LOADER *loader, OSSL_STORE_expect_fn f)` —
/// `store_register.c:92-97`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_expect(
    loader: *mut OsslStoreLoader,
    expect_function: Option<OsslStoreExpectFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).expect = expect_function };
    1
}

/// `int OSSL_STORE_LOADER_set_find(OSSL_STORE_LOADER *loader, OSSL_STORE_find_fn f)` —
/// `store_register.c:99-104`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_find(
    loader: *mut OsslStoreLoader,
    find_function: Option<OsslStoreFindFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).find = find_function };
    1
}

/// `int OSSL_STORE_LOADER_set_load(OSSL_STORE_LOADER *loader, OSSL_STORE_load_fn f)` —
/// `store_register.c:106-111`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_load(
    loader: *mut OsslStoreLoader,
    load_function: Option<OsslStoreLoadFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).load = load_function };
    1
}

/// `int OSSL_STORE_LOADER_set_eof(OSSL_STORE_LOADER *loader, OSSL_STORE_eof_fn f)` —
/// `store_register.c:113-118`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_eof(
    loader: *mut OsslStoreLoader,
    eof_function: Option<OsslStoreEofFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).eof = eof_function };
    1
}

/// `int OSSL_STORE_LOADER_set_error(OSSL_STORE_LOADER *loader, OSSL_STORE_error_fn f)` —
/// `store_register.c:120-125`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_error(
    loader: *mut OsslStoreLoader,
    error_function: Option<OsslStoreErrorFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).error = error_function };
    1
}

/// `int OSSL_STORE_LOADER_set_close(OSSL_STORE_LOADER *loader, OSSL_STORE_close_fn f)` —
/// `store_register.c:127-132`.
///
/// # Safety
/// `loader` must be live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_LOADER_set_close(
    loader: *mut OsslStoreLoader,
    close_function: Option<OsslStoreCloseFn>,
) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { (*loader).closefn = close_function };
    1
}

// ---------------------------------------------------------------------------
// Registration — `store_register.c:160-279`
// ---------------------------------------------------------------------------

/// `int ossl_store_register_loader_int(OSSL_STORE_LOADER *loader)` —
/// `store_register.c:160-206`.
///
/// Validates the scheme against RFC 3986's grammar, requires the five non-optional legacy
/// callbacks, then inserts under the registry lock. The insert's answer is 1 when the
/// loader was stored (fresh or replacing an existing scheme) or when the container reported
/// no error — for the crate's stack that is simply "the insert happened".
///
/// # Safety
/// `loader` must be a live loader whose `scheme` is non-NULL and NUL-terminated.
unsafe fn ossl_store_register_loader_int(loader: *mut OsslStoreLoader) -> c_int {
    // SAFETY: `loader` is live per the contract.
    let scheme = unsafe { (*loader).scheme };
    let mut ok = 0;

    // SAFETY: `scheme` is non-NULL and NUL-terminated; the walk stays inside it.
    let syntax_ok = unsafe {
        let mut p = scheme;
        if ossl_isalpha(c_int::from(*p)) {
            while *p != 0
                && (ossl_isalpha(c_int::from(*p))
                    || ossl_isdigit(c_int::from(*p))
                    || matches!(*p as u8, b'+' | b'-' | b'.'))
            {
                p = p.add(1);
            }
        }
        *p == 0
    };
    if !syntax_ok {
        // The authority formats `scheme=%s` from the loader's own scheme.
        let mut msg = [0 as c_char; 512];
        // SAFETY: `msg` is a live writable buffer of its own length and `scheme` is
        // NUL-terminated.
        unsafe {
            crate::runtime::bio::print::BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"scheme=%s".as_ptr(),
                scheme,
            );
        }
        // SAFETY: `msg` is a NUL-terminated stack buffer and `scheme` is NUL-terminated.
        unsafe { raise_site_data(&STORE_REGISTER_178, msg.as_ptr()) };
        return 0;
    }

    // SAFETY: `loader` is live; the five callbacks are read to test for absence.
    let complete = unsafe {
        (*loader).open.is_some()
            && (*loader).load.is_some()
            && (*loader).eof.is_some()
            && (*loader).error.is_some()
            && (*loader).closefn.is_some()
    };
    if !complete {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_186) };
        return 0;
    }

    if !ensure_registry() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_192) };
        return 0;
    }
    // SAFETY: the lock exists per `ensure_registry`.
    let lock = REGISTRY_LOCK.load(Ordering::Acquire);
    // SAFETY: `lock` is the live registry lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return 0;
    }

    if ossl_store_register_init() {
        // SAFETY: `scheme` is NUL-terminated and the register is live.
        let existing = unsafe { find_loader(scheme) };
        let stack = LOADER_REGISTER.load(Ordering::Acquire);
        if !existing.is_null() {
            // Replace in place, as `lh_insert` does; the replaced loader is not freed (the
            // authority leaks it too -- see the module doc).
            // SAFETY: `stack` is live and `existing` is one of its own values.
            unsafe {
                let n = OPENSSL_sk_num(stack);
                let mut i = 0;
                while i < n {
                    if OPENSSL_sk_value(stack, i) == existing.cast::<c_void>() {
                        OPENSSL_sk_set(stack, i, loader.cast::<c_void>());
                        ok = 1;
                        break;
                    }
                    i += 1;
                }
            }
        } else {
            // SAFETY: `stack` is live and `loader` is this call's own.
            ok = c_int::from(unsafe { OPENSSL_sk_push(stack, loader.cast::<c_void>()) } != 0);
        }
    }

    // SAFETY: `lock` is the live registry lock, taken above.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    ok
}

/// `int OSSL_STORE_register_loader(OSSL_STORE_LOADER *loader)` —
/// `store_register.c:207-210`.
///
/// # Safety
/// `loader` must be a live loader built by `OSSL_STORE_LOADER_new` or `store_meth.c`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_register_loader(loader: *mut OsslStoreLoader) -> c_int {
    // SAFETY: `loader` is live per the contract.
    unsafe { ossl_store_register_loader_int(loader) }
}

/// `const OSSL_STORE_LOADER *ossl_store_get0_loader_int(const char *scheme)` —
/// `store_register.c:212-243`.
///
/// Takes the **write** lock even though it only reads, as the authority does.
///
/// # Safety
/// `scheme` must be NUL-terminated.
pub(crate) unsafe fn ossl_store_get0_loader_int(scheme: *const c_char) -> *const OsslStoreLoader {
    if !ensure_registry() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_226) };
        return ptr::null();
    }
    // SAFETY: the lock exists per `ensure_registry`.
    let lock = REGISTRY_LOCK.load(Ordering::Acquire);
    // SAFETY: `lock` is the live registry lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return ptr::null();
    }

    let mut loader: *mut OsslStoreLoader = ptr::null_mut();
    if !ossl_store_register_init() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_233) };
    } else {
        // SAFETY: `scheme` is NUL-terminated and the register is live.
        loader = unsafe { find_loader(scheme) };
        if loader.is_null() {
            let mut msg = [0 as c_char; 512];
            // SAFETY: `msg` is a live writable buffer of its own length and `scheme` is
            // NUL-terminated.
            unsafe {
                crate::runtime::bio::print::BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"scheme=%s".as_ptr(),
                    scheme,
                );
            }
            // SAFETY: `msg` is a NUL-terminated stack buffer.
            unsafe { raise_site_data(&STORE_REGISTER_237, msg.as_ptr()) };
        }
    }

    // SAFETY: `lock` is the live registry lock, taken above.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    loader
}

/// `OSSL_STORE_LOADER *ossl_store_unregister_loader_int(const char *scheme)` —
/// `store_register.c:245-275`.
///
/// # Safety
/// `scheme` must be NUL-terminated.
pub(crate) unsafe fn ossl_store_unregister_loader_int(
    scheme: *const c_char,
) -> *mut OsslStoreLoader {
    if !ensure_registry() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_258) };
        return ptr::null_mut();
    }
    // SAFETY: the lock exists per `ensure_registry`.
    let lock = REGISTRY_LOCK.load(Ordering::Acquire);
    // SAFETY: `lock` is the live registry lock.
    if unsafe { CRYPTO_THREAD_write_lock(lock) } == 0 {
        return ptr::null_mut();
    }

    let mut loader: *mut OsslStoreLoader = ptr::null_mut();
    if !ossl_store_register_init() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&STORE_REGISTER_265) };
    } else {
        // SAFETY: `scheme` is NUL-terminated and the register is live.
        let found = unsafe { find_loader(scheme) };
        if found.is_null() {
            let mut msg = [0 as c_char; 512];
            // SAFETY: `msg` is a live writable buffer of its own length and `scheme` is
            // NUL-terminated.
            unsafe {
                crate::runtime::bio::print::BIO_snprintf(
                    msg.as_mut_ptr(),
                    msg.len(),
                    c"scheme=%s".as_ptr(),
                    scheme,
                );
            }
            // SAFETY: `msg` is a NUL-terminated stack buffer.
            unsafe { raise_site_data(&STORE_REGISTER_269, msg.as_ptr()) };
        } else {
            // SAFETY: the register is live and `found` is one of its own values.
            unsafe {
                let stack = LOADER_REGISTER.load(Ordering::Acquire);
                let n = OPENSSL_sk_num(stack);
                let mut i = 0;
                while i < n {
                    if OPENSSL_sk_value(stack, i) == found.cast::<c_void>() {
                        OPENSSL_sk_delete(stack, i);
                        break;
                    }
                    i += 1;
                }
            }
            loader = found;
        }
    }

    // SAFETY: `lock` is the live registry lock, taken above.
    unsafe { CRYPTO_THREAD_unlock(lock) };

    loader
}

/// `OSSL_STORE_LOADER *OSSL_STORE_unregister_loader(const char *scheme)` —
/// `store_register.c:276-279`.
///
/// # Safety
/// `scheme` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_unregister_loader(
    scheme: *const c_char,
) -> *mut OsslStoreLoader {
    // SAFETY: `scheme` is NUL-terminated per the contract.
    unsafe { ossl_store_unregister_loader_int(scheme) }
}

/// `void ossl_store_destroy_loaders_int(void)` — `store_register.c:281-287`.
///
/// Releases the registry and its lock. Nothing in this crate calls it yet: the authority
/// reaches it from `OPENSSL_cleanup`'s store teardown, which this crate's cleanup chain does
/// not carry. It is transcribed so the registry's destructor exists beside its constructor.
#[allow(dead_code)] // reached by the cleanup chain a later stratum lands
pub(crate) fn ossl_store_destroy_loaders_int() {
    let stack = LOADER_REGISTER.swap(ptr::null_mut(), Ordering::AcqRel);
    if !stack.is_null() {
        // SAFETY: `stack` is the register this module created and nobody else freed.
        unsafe { OPENSSL_sk_free(stack) };
    }
    let lock = REGISTRY_LOCK.swap(ptr::null_mut(), Ordering::AcqRel);
    if !lock.is_null() {
        // SAFETY: `lock` is the registry lock this module created and nobody else freed.
        unsafe { CRYPTO_THREAD_lock_free(lock) };
    }
}

/// `int OSSL_STORE_do_all_loaders(void (*do_function)(const OSSL_STORE_LOADER *loader,
/// void *do_arg), void *do_arg)` — `store_register.c:294-302`.
///
/// # Safety
/// `do_function`, when non-NULL, must be a valid callback that tolerates every loader;
/// `do_arg` is opaque to this module.
#[no_mangle]
pub unsafe extern "C" fn OSSL_STORE_do_all_loaders(
    do_function: Option<unsafe extern "C" fn(*const OsslStoreLoader, *mut c_void)>,
    do_arg: *mut c_void,
) -> c_int {
    if ossl_store_register_init() {
        let stack = LOADER_REGISTER.load(Ordering::Acquire);
        if let Some(f) = do_function {
            // SAFETY: `stack` is the live register; each value is one of its loaders, and `f`
            // is the caller's callback.
            unsafe {
                let n = OPENSSL_sk_num(stack);
                let mut i = 0;
                while i < n {
                    f(OPENSSL_sk_value(stack, i).cast::<OsslStoreLoader>(), do_arg);
                    i += 1;
                }
            }
        }
    }
    1
}
