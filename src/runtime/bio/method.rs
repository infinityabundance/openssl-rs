//! Phase 4 — the method-table API.
//!
//! A `BIO_METHOD` is the vtable a BIO dispatches through, and `BIO_meth_new` is
//! how an application (or a provider) supplies its own. The public accessors and
//! mutators are therefore a compatibility surface in their own right: a
//! third-party BIO implementation is written against exactly these functions.
//!
//! ## The two read/write forms, and why both exist
//!
//! OpenSSL 3 widened `read`/`write` from `int` to `size_t` byte counts but kept
//! the old signatures working. Internally there is **one** dispatch slot
//! (`bread`/`bwrite`, the modern form) and one legacy slot (`bread_old` /
//! `bwrite_old`); `BIO_meth_set_read` stores the legacy function and installs a
//! conversion shim into the dispatch slot, while `BIO_meth_set_read_ex` stores
//! the modern function directly and clears the legacy slot. The getters are
//! asymmetric by design:
//!
//! * `BIO_meth_get_read` returns the **legacy** pointer, which is NULL if only
//!   the `_ex` setter was used;
//! * `BIO_meth_get_read_ex` returns the **dispatch** pointer, which is non-NULL
//!   after either setter.
//!
//! Reproducing that asymmetry matters because a caller can (and the RT-BIO probe
//! does) set one form and read both.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};

use super::{
    Bio, BioCallbackCtrlFn, BioCreateFn, BioCtrlFn, BioDestroyFn, BioGetsFn, BioMethod, BioPutsFn,
    BioReadExFn, BioReadFn, BioRecvmmsgFn, BioSendmmsgFn, BioWriteExFn, BioWriteFn,
};

/// `__FILE__` for this unit's allocator calls — the source-tree `crypto/bio/bio_meth.c`.
const FILE: *const c_char = c"../../src/openssl-3.6.4/crypto/bio/bio_meth.c".as_ptr();
/// `BIO_meth_new`'s `OPENSSL_zalloc(sizeof(BIO_METHOD))` — `bio_meth.c:39`.
const LINE_ZALLOC: c_int = 39;
/// `BIO_meth_new`'s `OPENSSL_strdup(name)` — `bio_meth.c:42`.
const LINE_STRDUP: c_int = 42;
/// `BIO_meth_new`'s failure `OPENSSL_free(biom)` — `bio_meth.c:43`.
const LINE_FREE_REFUSED: c_int = 43;
/// `BIO_meth_free`'s `OPENSSL_free(biom->name)` — `bio_meth.c:53`.
const LINE_FREE_NAME: c_int = 53;
/// `BIO_meth_free`'s `OPENSSL_free(biom)` — `bio_meth.c:54`.
const LINE_FREE_TABLE: c_int = 54;

/// `BIO_METHOD`'s owned-context contract.
///
/// The authority allocates the table with `OPENSSL_zalloc`, installs a `CRYPTO_strdup` name, and
/// releases the name and then the table in `BIO_meth_free` (`bio_meth.c:37-56`).
///
/// # Safety
/// Zero is the authority's constructed state: `type_` is a `c_int`, `name` is a raw pointer, and
/// every dispatch slot is `None` in an all-zero block, so the zeroed storage is a valid
/// `BioMethod`. `destroy_body` releases exactly the one member `BIO_meth_free` releases — the
/// duplicate name — at that function's own coordinates, and never the enclosing table.
// SAFETY: zero is a valid `BioMethod` (all fields are integers, raw pointers, or `Option<fn>`,
// whose zero is `None`), and `destroy_body` frees only the `CRYPTO_strdup` name at :53, leaving
// the table to `OwnedCtx::Drop` at :54.
unsafe impl CtxDestroy for BioMethod {
    const FILE: *const c_char = FILE;
    const LINE_ALLOC: c_int = LINE_ZALLOC;
    const LINE_FREE: c_int = LINE_FREE_TABLE;

    /// `BIO_meth_free`'s `OPENSSL_free(biom->name)` (`bio_meth.c:53`), without the block release.
    ///
    /// # Safety
    /// `ptr` is a live method table this crate allocated and has not released (the trait
    /// contract).
    unsafe fn destroy_body(ptr: *mut Self) {
        // SAFETY: `ptr` is live per the trait contract; `name` is NULL or the single duplicate
        // this crate installed, and the seam treats a NULL release as a no-op.
        unsafe {
            CRYPTO_free(
                (*ptr).name.cast_mut().cast::<c_void>(),
                FILE,
                LINE_FREE_NAME,
            )
        };
    }
}

/// The legacy write adapter the authority installs for `BIO_meth_set_write`.
///
/// # Safety
/// `bio` must be a live BIO whose method has a non-NULL `bwrite_old`.
pub(crate) unsafe extern "C" fn bwrite_conv(
    bio: *mut Bio,
    data: *const c_char,
    datal: usize,
    written: *mut usize,
) -> c_int {
    let datal = if datal as c_long > c_int::MAX as c_long {
        c_int::MAX as usize
    } else {
        datal
    };
    // SAFETY: the caller's contract is that a BIO dispatched through this shim
    // has a legacy write installed.
    let old = match unsafe { bio.as_ref() }.and_then(|b| unsafe { b.method.as_ref() }) {
        Some(m) => m.bwrite_old,
        None => None,
    };
    let Some(old) = old else {
        return 0;
    };
    // SAFETY: `bio` is live; `data` is valid for `datal` bytes.
    let ret = unsafe { old(bio, data, datal as c_int) };
    if ret <= 0 {
        if !written.is_null() {
            // SAFETY: `written` is the caller's out-parameter.
            unsafe { *written = 0 };
        }
        return ret;
    }
    if !written.is_null() {
        // SAFETY: as above.
        unsafe { *written = ret as usize };
    }
    1
}

/// The legacy read adapter the authority installs for `BIO_meth_set_read`.
///
/// # Safety
/// `bio` must be a live BIO whose method has a non-NULL `bread_old`.
pub(crate) unsafe extern "C" fn bread_conv(
    bio: *mut Bio,
    data: *mut c_char,
    datal: usize,
    readbytes: *mut usize,
) -> c_int {
    let datal = if datal as c_long > c_int::MAX as c_long {
        c_int::MAX as usize
    } else {
        datal
    };
    // SAFETY: as for the write shim.
    let old = match unsafe { bio.as_ref() }.and_then(|b| unsafe { b.method.as_ref() }) {
        Some(m) => m.bread_old,
        None => None,
    };
    let Some(old) = old else {
        return 0;
    };
    // SAFETY: `bio` is live; `data` is valid for `datal` bytes.
    let ret = unsafe { old(bio, data, datal as c_int) };
    if ret <= 0 {
        if !readbytes.is_null() {
            // SAFETY: `readbytes` is the caller's out-parameter.
            unsafe { *readbytes = 0 };
        }
        return ret;
    }
    if !readbytes.is_null() {
        // SAFETY: as above.
        unsafe { *readbytes = ret as usize };
    }
    1
}

/// `BIO_METHOD *BIO_meth_new(int type, const char *name)`
///
/// The name is **copied** through the `CRYPTO_strdup` seam, so `BIO_meth_free` owns it. A NULL
/// `name` is a failure: the authority still allocates and releases the table around the refused
/// duplicate, so a caller-installed `CRYPTO_set_mem_functions` hook observes that sequence.
///
/// # Safety
/// `name` must be NULL or point at a NUL-terminated C string that stays valid
/// for the duration of the call; it is copied with `CRYPTO_strdup` before returning.
/// The returned table must be released with `BIO_meth_free`, and must outlive
/// every BIO created against it.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut BioMethod {
    guard_ffi(ptr::null_mut(), || {
        // The authority allocates before duplicating (`bio_meth.c:39`), and a refused allocation
        // answers NULL without raising.
        let Some(table) = OwnedCtx::<BioMethod>::zalloc() else {
            return ptr::null_mut();
        };
        // SAFETY: `name` is NULL or a NUL-terminated C string per this function's contract.
        let copied = unsafe { CRYPTO_strdup(name, FILE, LINE_STRDUP) };
        if copied.is_null() {
            // The authority's failure arm releases the table at :43 (its `name` is still NULL, so
            // only the block is released). `Drop` would release at :54, so release here at the
            // authority's coordinate and give up the handle.
            let table_ptr = table.as_ptr();
            core::mem::forget(table);
            // SAFETY: `table_ptr` is the block just allocated and forgotten; this is its single
            // release.
            unsafe { CRYPTO_free(table_ptr.cast::<c_void>(), FILE, LINE_FREE_REFUSED) };
            return ptr::null_mut();
        }
        let table_ptr = table.as_ptr();
        // SAFETY: `table_ptr` is the live zeroed table this call owns exclusively; `copied` is a
        // fresh `CRYPTO_strdup` block whose ownership moves into the table.
        unsafe {
            (*table_ptr).name = copied;
            (*table_ptr).type_ = type_;
        }
        table.into_raw()
    })
}

/// `void BIO_meth_free(BIO_METHOD *biom)`
///
/// # Safety
/// `biom` must be NULL or a table returned by `BIO_meth_new` that no live BIO still references;
/// it is reclaimed here through the crate's allocator seam, releasing its copied `name` (at
/// `bio_meth.c:53`) and then the table (at :54) in the authority's order.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_free(biom: *mut BioMethod) {
    guard_ffi((), || {
        // SAFETY: `biom` is NULL or a live table `BIO_meth_new` handed out with `into_raw` and
        // `Drop` has not released; `Drop` is its single release.
        drop(unsafe { OwnedCtx::<BioMethod>::from_raw(biom) });
    })
}

/// `int BIO_meth_set_write(BIO_METHOD *biom, int (*write)(BIO *, const char *, int))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_write(biom: *mut BioMethod, f: Option<BioWriteFn>) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bwrite_old = f;
        m.bwrite = Some(bwrite_conv);
        1
    })
}

/// `int BIO_meth_set_write_ex(BIO_METHOD *biom, int (*bwrite)(BIO *, const char *, size_t, size_t *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_write_ex(
    biom: *mut BioMethod,
    f: Option<BioWriteExFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bwrite_old = None;
        m.bwrite = f;
        1
    })
}

/// `int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_read(biom: *mut BioMethod, f: Option<BioReadFn>) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bread_old = f;
        m.bread = Some(bread_conv);
        1
    })
}

/// `int BIO_meth_set_read_ex(BIO_METHOD *biom, int (*bread)(BIO *, char *, size_t, size_t *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_read_ex(
    biom: *mut BioMethod,
    f: Option<BioReadExFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bread_old = None;
        m.bread = f;
        1
    })
}

/// `int BIO_meth_set_puts(BIO_METHOD *biom, int (*puts)(BIO *, const char *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_puts(biom: *mut BioMethod, f: Option<BioPutsFn>) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bputs = f;
        1
    })
}

/// `int BIO_meth_set_gets(BIO_METHOD *biom, int (*gets)(BIO *, char *, int))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_gets(biom: *mut BioMethod, f: Option<BioGetsFn>) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bgets = f;
        1
    })
}

/// `int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_ctrl(biom: *mut BioMethod, f: Option<BioCtrlFn>) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.ctrl = f;
        1
    })
}

/// `int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_create(
    biom: *mut BioMethod,
    f: Option<BioCreateFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.create = f;
        1
    })
}

/// `int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_destroy(
    biom: *mut BioMethod,
    f: Option<BioDestroyFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.destroy = f;
        1
    })
}

/// `int BIO_meth_set_callback_ctrl(BIO_METHOD *biom, long (*callback_ctrl)(BIO *, int, BIO_info_cb *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_callback_ctrl(
    biom: *mut BioMethod,
    f: Option<BioCallbackCtrlFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.callback_ctrl = f;
        1
    })
}

/// `int BIO_meth_set_sendmmsg(BIO_METHOD *biom, int (*f)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_sendmmsg(
    biom: *mut BioMethod,
    f: Option<BioSendmmsgFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.sendmmsg = f;
        1
    })
}

/// `int BIO_meth_set_recvmmsg(BIO_METHOD *biom, int (*f)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *))`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`] that this call has
/// exclusive access to; `f`, when non-NULL, must be a valid function pointer of
/// the documented signature that remains callable while the table is installed.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_recvmmsg(
    biom: *mut BioMethod,
    f: Option<BioRecvmmsgFn>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `biom` is NULL or a live method table with no other live borrow.
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.recvmmsg = f;
        1
    })
}

/// `int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int)`
///
/// Returns the **legacy** pointer, which is NULL when only `_ex` was set.
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_write(biom: *const BioMethod) -> Option<BioWriteFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bwrite_old))
}

/// `int (*BIO_meth_get_write_ex(const BIO_METHOD *biom))(BIO *, const char *, size_t, size_t *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_write_ex(biom: *const BioMethod) -> Option<BioWriteExFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bwrite))
}

/// `int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_read(biom: *const BioMethod) -> Option<BioReadFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bread_old))
}

/// `int (*BIO_meth_get_read_ex(const BIO_METHOD *biom))(BIO *, char *, size_t, size_t *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_read_ex(biom: *const BioMethod) -> Option<BioReadExFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bread))
}

/// `int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_puts(biom: *const BioMethod) -> Option<BioPutsFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bputs))
}

/// `int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_gets(biom: *const BioMethod) -> Option<BioGetsFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bgets))
}

/// `long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_ctrl(biom: *const BioMethod) -> Option<BioCtrlFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.ctrl))
}

/// `int (*BIO_meth_get_create(const BIO_METHOD *biom))(BIO *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_create(biom: *const BioMethod) -> Option<BioCreateFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.create))
}

/// `int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_destroy(biom: *const BioMethod) -> Option<BioDestroyFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.destroy))
}

/// `long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))(BIO *, int, BIO_info_cb *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_callback_ctrl(
    biom: *const BioMethod,
) -> Option<BioCallbackCtrlFn> {
    guard_ffi(None, || {
        // SAFETY: `biom` is NULL or a live method table; the shared borrow is
        // confined to this expression.
        unsafe { biom.as_ref() }.and_then(|m| m.callback_ctrl)
    })
}

/// `int (*BIO_meth_get_sendmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_sendmmsg(biom: *const BioMethod) -> Option<BioSendmmsgFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.sendmmsg))
}

/// `int (*BIO_meth_get_recvmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)`
///
/// # Safety
/// `biom` must be NULL or point at a live [`BioMethod`]; the returned function
/// pointer is callable only while that table remains alive and unmodified.
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_recvmmsg(biom: *const BioMethod) -> Option<BioRecvmmsgFn> {
    // SAFETY: `biom` is NULL or a live method table; the shared borrow is
    // confined to this expression.
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.recvmmsg))
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(BioMethod => zero_state_sweep_bio_method);
