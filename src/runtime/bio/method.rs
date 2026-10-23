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

use core::ffi::{c_char, c_int, c_void};
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

/// The type-correct slot pairing for the two read/write callback families.
///
/// A legacy callback (`Option<BioWriteFn>`, `int (*)(BIO *, const char *, int)`) is only
/// reachable through the modern dispatch slot (`int (*)(BIO *, const char *, size_t,
/// size_t *)`). "Legacy slot populated implies the dispatch slot is the conversion shim" is
/// therefore an invariant of the table, not a convention: it is installed and read here, as a
/// pair, so no caller of these safe methods can create a mismatched signature/state pairing.
/// The C setters remain `unsafe` only because they take a raw table pointer.
impl BioMethod {
    /// `BIO_meth_set_write`: store the legacy callback and install [`bwrite_conv`] in the
    /// dispatch slot. The authority installs the shim even for a NULL callback
    /// (`bio_meth.c:67-73`), so that is preserved exactly.
    fn install_legacy_write(&mut self, f: Option<BioWriteFn>) {
        self.bwrite_old = f;
        self.bwrite = Some(bwrite_conv);
    }

    /// `BIO_meth_set_write_ex`: store the modern callback directly and clear the legacy slot.
    fn install_modern_write(&mut self, f: Option<BioWriteExFn>) {
        self.bwrite_old = None;
        self.bwrite = f;
    }

    /// `BIO_meth_set_read`: the read-side counterpart of [`Self::install_legacy_write`].
    fn install_legacy_read(&mut self, f: Option<BioReadFn>) {
        self.bread_old = f;
        self.bread = Some(bread_conv);
    }

    /// `BIO_meth_set_read_ex`: the read-side counterpart of [`Self::install_modern_write`].
    fn install_modern_read(&mut self, f: Option<BioReadExFn>) {
        self.bread_old = None;
        self.bread = f;
    }

    /// The legacy write callback, which is NULL when only the modern setter was used.
    fn legacy_write(&self) -> Option<BioWriteFn> {
        self.bwrite_old
    }

    /// The write dispatch slot: non-NULL after either setter.
    fn dispatch_write(&self) -> Option<BioWriteExFn> {
        self.bwrite
    }

    /// The legacy read callback, which is NULL when only the modern setter was used.
    fn legacy_read(&self) -> Option<BioReadFn> {
        self.bread_old
    }

    /// The read dispatch slot: non-NULL after either setter.
    fn dispatch_read(&self) -> Option<BioReadExFn> {
        self.bread
    }

    /// Give a zeroed table its owning name and type in one step. The caller transfers the
    /// `CRYPTO_strdup` name with this call; a table is never published half-initialised.
    fn initialise(&mut self, type_: c_int, name: *const c_char) {
        self.type_ = type_;
        self.name = name;
    }
}

/// The legacy write adapter the authority installs for `BIO_meth_set_write`.
///
/// The callback is **copied out** of the table before it is invoked: it may re-enter the BIO
/// API and mutate this table (AGENTS §21.3), so no borrow of the BIO or the table is held
/// across the call.
///
/// # Safety
/// `bio` must be a live BIO whose method table is live for the duration of the call.
pub(crate) unsafe extern "C" fn bwrite_conv(
    bio: *mut Bio,
    data: *const c_char,
    datal: usize,
    written: *mut usize,
) -> c_int {
    let datal = if datal > c_int::MAX as usize {
        c_int::MAX as usize
    } else {
        datal
    };
    // SAFETY: `bio` is live and its table is live per the contract; both borrows end at this
    // statement, so the callback below sees no outstanding reference.
    let old = unsafe { bio.as_ref() }
        .and_then(|b| unsafe { b.method() })
        .and_then(BioMethod::legacy_write);
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
/// As for [`bwrite_conv`], the callback is copied out before it runs and may re-enter this API.
///
/// # Safety
/// `bio` must be a live BIO whose method table is live for the duration of the call.
pub(crate) unsafe extern "C" fn bread_conv(
    bio: *mut Bio,
    data: *mut c_char,
    datal: usize,
    readbytes: *mut usize,
) -> c_int {
    let datal = if datal > c_int::MAX as usize {
        c_int::MAX as usize
    } else {
        datal
    };
    // SAFETY: as for the write shim: both borrows end before the callback runs.
    let old = unsafe { bio.as_ref() }
        .and_then(|b| unsafe { b.method() })
        .and_then(BioMethod::legacy_read);
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
        // fresh `CRYPTO_strdup` block whose ownership moves into the table, and the safe method
        // writes both fields before the table is published by `into_raw`.
        unsafe { (*table_ptr).initialise(type_, copied) };
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
        m.install_legacy_write(f);
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
        m.install_modern_write(f);
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
        m.install_legacy_read(f);
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
        m.install_modern_read(f);
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
    guard_ffi(None, || {
        // SAFETY: `biom` is NULL or a live method table; the shared borrow is confined to this
        // expression.
        unsafe { biom.as_ref() }.and_then(BioMethod::legacy_write)
    })
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
    guard_ffi(None, || {
        // SAFETY: `biom` is NULL or a live method table; the shared borrow is confined to this
        // expression.
        unsafe { biom.as_ref() }.and_then(BioMethod::dispatch_write)
    })
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
    guard_ffi(None, || {
        // SAFETY: `biom` is NULL or a live method table; the shared borrow is confined to this
        // expression.
        unsafe { biom.as_ref() }.and_then(BioMethod::legacy_read)
    })
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
    guard_ffi(None, || {
        // SAFETY: `biom` is NULL or a live method table; the shared borrow is confined to this
        // expression.
        unsafe { biom.as_ref() }.and_then(BioMethod::dispatch_read)
    })
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use core::sync::atomic::{AtomicI32, Ordering};

    use super::*;
    use crate::runtime::bio::{BIO_free, BIO_new, BIO_write, Bio};

    static SEEN_WRITE: AtomicI32 = AtomicI32::new(-1);
    static SEEN_READ: AtomicI32 = AtomicI32::new(-1);
    static MODERN_SEEN: AtomicI32 = AtomicI32::new(-1);
    static REPLACED_SEEN: AtomicI32 = AtomicI32::new(-1);
    static SHARED_SEEN: AtomicI32 = AtomicI32::new(-1);
    static DESTROYED: AtomicI32 = AtomicI32::new(0);
    static DESTROY_TYPE: AtomicI32 = AtomicI32::new(-1);
    static REENTERED: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn record_write(_b: *mut Bio, _data: *const c_char, len: c_int) -> c_int {
        SEEN_WRITE.store(len, Ordering::SeqCst);
        len
    }

    unsafe extern "C" fn record_read(_b: *mut Bio, _data: *mut c_char, len: c_int) -> c_int {
        SEEN_READ.store(len, Ordering::SeqCst);
        len
    }

    unsafe extern "C" fn replaced_write(_b: *mut Bio, _data: *const c_char, len: c_int) -> c_int {
        REPLACED_SEEN.store(len, Ordering::SeqCst);
        len
    }

    unsafe extern "C" fn shared_write(_b: *mut Bio, _data: *const c_char, len: c_int) -> c_int {
        SHARED_SEEN.store(len, Ordering::SeqCst);
        len
    }

    unsafe extern "C" fn modern_write(
        _b: *mut Bio,
        _data: *const c_char,
        len: usize,
        written: *mut usize,
    ) -> c_int {
        MODERN_SEEN.store(len as c_int, Ordering::SeqCst);
        if !written.is_null() {
            // SAFETY: `written` is the caller's non-NULL out-parameter.
            unsafe { *written = len };
        }
        1
    }

    /// Records that it ran while the table was still live, and which table it was.
    unsafe extern "C" fn destroy_record(b: *mut Bio) -> c_int {
        // SAFETY: the destroy contract hands a live BIO whose method table is still live.
        unsafe {
            let m = (*b).method;
            assert!(
                !m.is_null(),
                "a BIO with a method must keep it until destroy"
            );
            DESTROY_TYPE.store((*m).type_, Ordering::SeqCst);
        }
        DESTROYED.fetch_add(1, Ordering::SeqCst);
        1
    }

    unsafe extern "C" fn puts_noop(_b: *mut Bio, _s: *const c_char) -> c_int {
        1
    }

    /// Re-enters the table API from inside a dispatch callback, mutating the table while the
    /// adapter is on the stack. Legal because the adapter copies the callback out first.
    unsafe extern "C" fn reentrant_write(b: *mut Bio, _data: *const c_char, len: c_int) -> c_int {
        // SAFETY: the callback receives a live BIO and a live method table.
        unsafe {
            let m = (*b).method;
            assert!(BIO_meth_get_write_ex(m).is_some());
            assert_eq!(BIO_meth_set_puts(m.cast_mut(), Some(puts_noop)), 1);
        }
        REENTERED.fetch_add(1, Ordering::SeqCst);
        len
    }

    fn method_with(write: Option<BioWriteFn>, read: Option<BioReadFn>) -> BioMethod {
        BioMethod {
            type_: 0,
            name: core::ptr::null(),
            bwrite: None,
            bwrite_old: write,
            bread: None,
            bread_old: read,
            bputs: None,
            bgets: None,
            ctrl: None,
            create: None,
            destroy: None,
            callback_ctrl: None,
            sendmmsg: None,
            recvmmsg: None,
        }
    }

    #[test]
    fn legacy_adapters_clamp_size_max_to_int_max() {
        let method = method_with(Some(record_write), Some(record_read));
        // SAFETY: every field of `Bio` admits the all-zero value (raw pointers,
        // integers and an `AtomicI32`); the method pointer is then set.
        let mut bio: Bio = unsafe { core::mem::zeroed() };
        bio.method = &method;

        let mut written = 0usize;
        // SAFETY: `bio` points at the table above and the shim reads only its
        // method; the sink never dereferences `data`.
        let ret = unsafe { bwrite_conv(&mut bio, b"x".as_ptr().cast(), usize::MAX, &mut written) };
        assert_eq!(ret, 1);
        assert_eq!(SEEN_WRITE.load(Ordering::SeqCst), c_int::MAX);
        assert_eq!(written, c_int::MAX as usize);

        let mut readbytes = 0usize;
        let mut byte = 0 as c_char;
        // SAFETY: as above; the read sink records the length without writing.
        let ret = unsafe { bread_conv(&mut bio, &mut byte, usize::MAX, &mut readbytes) };
        assert_eq!(ret, 1);
        assert_eq!(SEEN_READ.load(Ordering::SeqCst), c_int::MAX);
        assert_eq!(readbytes, c_int::MAX as usize);
    }

    #[test]
    fn legacy_method_installs_the_conversion_shim() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the table is created and released in this frame.
        unsafe {
            let table = BIO_meth_new(0x1234, c"legacy".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_write(table, Some(record_write)), 1);
            assert_eq!(BIO_meth_set_read(table, Some(record_read)), 1);
            // The legacy pointer is what was installed; the dispatch slot is the shim.
            assert!(BIO_meth_get_write(table).is_some());
            assert_eq!(
                BIO_meth_get_write_ex(table).map(|f| f as usize),
                Some(bwrite_conv as *const () as usize)
            );
            assert!(BIO_meth_get_read(table).is_some());
            assert_eq!(
                BIO_meth_get_read_ex(table).map(|f| f as usize),
                Some(bread_conv as *const () as usize)
            );
            // A modern setter clears the legacy slot and stores the callback directly.
            assert_eq!(BIO_meth_set_write_ex(table, Some(modern_write)), 1);
            assert!(BIO_meth_get_write(table).is_none());
            assert_eq!(
                BIO_meth_get_write_ex(table).map(|f| f as usize),
                Some(modern_write as *const () as usize)
            );
            BIO_meth_free(table);
        }
    }

    #[test]
    fn a_modern_method_round_trips_through_its_dispatch_slot() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the table is created and released in this frame; `bio` is stack-owned.
        unsafe {
            let table = BIO_meth_new(0, c"modern".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_write_ex(table, Some(modern_write)), 1);
            let mut bio: Bio = core::mem::zeroed();
            bio.method = table;
            let Some(slot) = (*table).dispatch_write() else {
                panic!("the modern setter must populate the dispatch slot");
            };
            let mut written = 0usize;
            let ret = slot(&mut bio, b"abcd".as_ptr().cast(), 4, &mut written);
            assert_eq!(ret, 1);
            assert_eq!(written, 4);
            assert_eq!(MODERN_SEEN.load(Ordering::SeqCst), 4);
            BIO_meth_free(table);
        }
    }

    #[test]
    fn replacing_a_callback_on_a_live_bio_takes_effect() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let table = BIO_meth_new(0, c"replace".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_write(table, Some(record_write)), 1);
            let bio = BIO_new(table);
            assert!(!bio.is_null());
            assert_eq!(BIO_write(bio, b"a".as_ptr().cast(), 1), 1);
            assert_eq!(SEEN_WRITE.load(Ordering::SeqCst), 1);
            // The table outlives the BIO, so replacing the slot is legal and the next dispatch
            // must observe the new callback.
            assert_eq!(BIO_meth_set_write(table, Some(replaced_write)), 1);
            assert_eq!(BIO_write(bio, b"abc".as_ptr().cast(), 3), 3);
            assert_eq!(REPLACED_SEEN.load(Ordering::SeqCst), 3);
            BIO_free(bio);
            BIO_meth_free(table);
        }
    }

    #[test]
    fn two_bios_sharing_one_table_both_dispatch() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let table = BIO_meth_new(0, c"shared".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_write(table, Some(shared_write)), 1);
            let first = BIO_new(table);
            let second = BIO_new(table);
            assert!(!first.is_null() && !second.is_null());
            assert_eq!(BIO_write(first, b"x".as_ptr().cast(), 1), 1);
            assert_eq!(SHARED_SEEN.load(Ordering::SeqCst), 1);
            assert_eq!(BIO_write(second, b"xyz".as_ptr().cast(), 3), 3);
            assert_eq!(SHARED_SEEN.load(Ordering::SeqCst), 3);
            BIO_free(first);
            BIO_free(second);
            BIO_meth_free(table);
        }
    }

    #[test]
    fn a_destroyed_bio_runs_destroy_while_the_table_is_still_live() {
        let _g = crate::test_support::lock_global_state();
        DESTROYED.store(0, Ordering::SeqCst);
        DESTROY_TYPE.store(-1, Ordering::SeqCst);
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let table = BIO_meth_new(0x1234, c"owned".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_destroy(table, Some(destroy_record)), 1);
            let bio = BIO_new(table);
            assert!(!bio.is_null());
            // The BIO is torn down first: `destroy` must observe a live table.
            BIO_free(bio);
            assert_eq!(DESTROYED.load(Ordering::SeqCst), 1);
            assert_eq!(DESTROY_TYPE.load(Ordering::SeqCst), 0x1234);
            // Releasing the table afterwards calls into nothing: no BIO references it.
            BIO_meth_free(table);
            assert_eq!(DESTROYED.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn a_reentrant_callback_needs_no_outstanding_borrow() {
        let _g = crate::test_support::lock_global_state();
        REENTERED.store(0, Ordering::SeqCst);
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let table = BIO_meth_new(0, c"reentrant".as_ptr());
            assert!(!table.is_null());
            assert_eq!(BIO_meth_set_write(table, Some(reentrant_write)), 1);
            let bio = BIO_new(table);
            assert!(!bio.is_null());
            assert_eq!(BIO_write(bio, b"ab".as_ptr().cast(), 2), 2);
            assert_eq!(REENTERED.load(Ordering::SeqCst), 1);
            assert!(
                (*table).bputs.is_some(),
                "the re-entrant mutation took effect after the adapter's borrow ended"
            );
            BIO_free(bio);
            BIO_meth_free(table);
        }
    }
}
