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

use core::ffi::{c_char, c_int, c_long};

use crate::ffi::guard_ffi;

use super::{
    Bio, BioCallbackCtrlFn, BioCreateFn, BioCtrlFn, BioDestroyFn, BioGetsFn, BioInfoCb, BioMethod,
    BioPutsFn, BioReadExFn, BioReadFn, BioRecvmmsgFn, BioSendmmsgFn, BioWriteExFn, BioWriteFn,
};

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
/// The name is **copied**, so `BIO_meth_free` owns it. A NULL `name` is a
/// failure (the authority's `OPENSSL_strdup(NULL)` returns NULL).
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_new(type_: c_int, name: *const c_char) -> *mut BioMethod {
    guard_ffi(core::ptr::null_mut(), || {
        if name.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `name` is a NUL-terminated C string.
        let copied = unsafe { super::sys::strdup(name) };
        if copied.is_null() {
            return core::ptr::null_mut();
        }
        Box::into_raw(Box::new(BioMethod {
            name: copied,
            ..BioMethod::new(type_, core::ptr::null())
        }))
    })
}

/// `void BIO_meth_free(BIO_METHOD *biom)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_free(biom: *mut BioMethod) {
    guard_ffi((), || {
        if biom.is_null() {
            return;
        }
        // SAFETY: `biom` was allocated by `BIO_meth_new`; its `name` was copied
        // by `strdup` and is owned here.
        let boxed = unsafe { Box::from_raw(biom) };
        if !boxed.name.is_null() {
            // SAFETY: `name` came from `strdup`.
            unsafe { super::sys::free(boxed.name.cast_mut().cast()) };
        }
    })
}

/// `int BIO_meth_set_write(BIO_METHOD *biom, int (*write)(BIO *, const char *, int))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_write(biom: *mut BioMethod, f: Option<BioWriteFn>) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bwrite_old = f;
        m.bwrite = Some(bwrite_conv);
        1
    })
}

/// `int BIO_meth_set_write_ex(BIO_METHOD *biom, int (*bwrite)(BIO *, const char *, size_t, size_t *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_write_ex(
    biom: *mut BioMethod,
    f: Option<BioWriteExFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bwrite_old = None;
        m.bwrite = f;
        1
    })
}

/// `int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_read(biom: *mut BioMethod, f: Option<BioReadFn>) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bread_old = f;
        m.bread = Some(bread_conv);
        1
    })
}

/// `int BIO_meth_set_read_ex(BIO_METHOD *biom, int (*bread)(BIO *, char *, size_t, size_t *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_read_ex(
    biom: *mut BioMethod,
    f: Option<BioReadExFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bread_old = None;
        m.bread = f;
        1
    })
}

/// `int BIO_meth_set_puts(BIO_METHOD *biom, int (*puts)(BIO *, const char *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_puts(biom: *mut BioMethod, f: Option<BioPutsFn>) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bputs = f;
        1
    })
}

/// `int BIO_meth_set_gets(BIO_METHOD *biom, int (*gets)(BIO *, char *, int))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_gets(biom: *mut BioMethod, f: Option<BioGetsFn>) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.bgets = f;
        1
    })
}

/// `int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_ctrl(biom: *mut BioMethod, f: Option<BioCtrlFn>) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.ctrl = f;
        1
    })
}

/// `int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_create(
    biom: *mut BioMethod,
    f: Option<BioCreateFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.create = f;
        1
    })
}

/// `int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_destroy(
    biom: *mut BioMethod,
    f: Option<BioDestroyFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.destroy = f;
        1
    })
}

/// `int BIO_meth_set_callback_ctrl(BIO_METHOD *biom, long (*callback_ctrl)(BIO *, int, BIO_info_cb *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_callback_ctrl(
    biom: *mut BioMethod,
    f: Option<BioCallbackCtrlFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.callback_ctrl = f;
        1
    })
}

/// `int BIO_meth_set_sendmmsg(BIO_METHOD *biom, int (*f)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_sendmmsg(
    biom: *mut BioMethod,
    f: Option<BioSendmmsgFn>,
) -> c_int {
    guard_ffi(0, || {
        let Some(m) = (unsafe { biom.as_mut() }) else {
            return 0;
        };
        m.sendmmsg = f;
        1
    })
}

/// `int BIO_meth_set_recvmmsg(BIO_METHOD *biom, int (*f)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *))`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_set_recvmmsg(
    biom: *mut BioMethod,
    f: Option<BioRecvmmsgFn>,
) -> c_int {
    guard_ffi(0, || {
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
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_write(biom: *const BioMethod) -> Option<BioWriteFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bwrite_old))
}

/// `int (*BIO_meth_get_write_ex(const BIO_METHOD *biom))(BIO *, const char *, size_t, size_t *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_write_ex(biom: *const BioMethod) -> Option<BioWriteExFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bwrite))
}

/// `int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_read(biom: *const BioMethod) -> Option<BioReadFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bread_old))
}

/// `int (*BIO_meth_get_read_ex(const BIO_METHOD *biom))(BIO *, char *, size_t, size_t *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_read_ex(biom: *const BioMethod) -> Option<BioReadExFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bread))
}

/// `int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_puts(biom: *const BioMethod) -> Option<BioPutsFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bputs))
}

/// `int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_gets(biom: *const BioMethod) -> Option<BioGetsFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.bgets))
}

/// `long (*BIO_meth_get_ctrl(const BIO_METHOD *biom))(BIO *, int, long, void *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_ctrl(biom: *const BioMethod) -> Option<BioCtrlFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.ctrl))
}

/// `int (*BIO_meth_get_create(const BIO_METHOD *biom))(BIO *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_create(biom: *const BioMethod) -> Option<BioCreateFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.create))
}

/// `int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_destroy(biom: *const BioMethod) -> Option<BioDestroyFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.destroy))
}

/// `long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))(BIO *, int, BIO_info_cb *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_callback_ctrl(
    biom: *const BioMethod,
) -> Option<BioCallbackCtrlFn> {
    guard_ffi(None, || {
        unsafe { biom.as_ref() }.and_then(|m| m.callback_ctrl)
    })
}

/// `int (*BIO_meth_get_sendmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_sendmmsg(biom: *const BioMethod) -> Option<BioSendmmsgFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.sendmmsg))
}

/// `int (*BIO_meth_get_recvmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)`
#[no_mangle]
pub unsafe extern "C" fn BIO_meth_get_recvmmsg(biom: *const BioMethod) -> Option<BioRecvmmsgFn> {
    guard_ffi(None, || unsafe { biom.as_ref() }.and_then(|m| m.recvmmsg))
}
