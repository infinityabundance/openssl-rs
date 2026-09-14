//! Phase 4 — the null sink (`BIO_s_null`).
//!
//! A source/sink that discards writes, reports EOF reads and — importantly —
//! *does not chain*: its writes report the byte count they were given, so a
//! caller that measures throughput through it sees the input size. The control
//! table is small but not uniform: `BIO_CTRL_RESET`, `EOF`, `SET`, `SET_CLOSE`,
//! `FLUSH` and `DUP` report 1 while `GET_CLOSE`, `INFO`, `GET`, `PENDING` and
//! `WPENDING` report 0, and everything else also reports 0.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET, BIO_CTRL_SET_CLOSE,
    BIO_CTRL_WPENDING, BIO_TYPE_NULL,
};

/// The authority's method name for the null sink.
const NULL_NAME: &[u8] = b"NULL\0";

/// The compiled-in method table returned by `BIO_s_null`.
static NULL_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_NULL,
    name: NULL_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(null_write),
    bread: Some(bread_conv),
    bread_old: Some(null_read),
    bputs: Some(null_puts),
    bgets: Some(null_gets),
    ctrl: Some(null_ctrl),
    create: None,
    destroy: None,
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_null(void)`
///
/// The method has no `create`, so `BIO_new` sets `init = 1` on the object and
/// the sink is usable immediately.
#[no_mangle]
pub extern "C" fn BIO_s_null() -> *const BioMethod {
    guard_ffi(ptr::null(), || &NULL_METHOD)
}

/// `static int null_read(BIO *b, char *out, int outl)`
///
/// # Safety
/// `b` is a live BIO; neither `out` nor `outl` is used.
unsafe extern "C" fn null_read(_b: *mut Bio, _out: *mut c_char, _outl: c_int) -> c_int {
    0
}

/// `static int null_write(BIO *b, const char *in, int inl)`
///
/// Reports `inl` unchanged, so the caller observes the sink accepting everything.
///
/// # Safety
/// `b` is a live BIO; `in_` is unused.
unsafe extern "C" fn null_write(_b: *mut Bio, _in: *const c_char, inl: c_int) -> c_int {
    inl
}

/// `static long null_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` is a live BIO; `arg` is unused by every command this method accepts.
unsafe extern "C" fn null_ctrl(
    _b: *mut Bio,
    cmd: c_int,
    _num: c_long,
    _arg: *mut c_void,
) -> c_long {
    match cmd {
        BIO_CTRL_RESET | BIO_CTRL_EOF | BIO_CTRL_SET | BIO_CTRL_SET_CLOSE | BIO_CTRL_FLUSH
        | BIO_CTRL_DUP => 1,
        _ => {
            let _ = (
                BIO_CTRL_GET_CLOSE,
                BIO_CTRL_INFO,
                BIO_CTRL_GET,
                BIO_CTRL_PENDING,
                BIO_CTRL_WPENDING,
            );
            0
        }
    }
}

/// `static int null_gets(BIO *bp, char *buf, int size)`
///
/// # Safety
/// `bp` is a live BIO; `buf` and `size` are unused.
unsafe extern "C" fn null_gets(_bp: *mut Bio, _buf: *mut c_char, _size: c_int) -> c_int {
    0
}

/// `static int null_puts(BIO *bp, const char *str)`
///
/// Returns the string's length (or 0 for NULL), matching the authority's
/// `strlen` with an `INT_MAX` guard.
///
/// # Safety
/// `bp` is a live BIO; `str_` is NULL or NUL-terminated.
unsafe extern "C" fn null_puts(_bp: *mut Bio, str_: *const c_char) -> c_int {
    if str_.is_null() {
        return 0;
    }
    // SAFETY: `str_` is NUL-terminated per the method contract.
    let n = unsafe { super::sys::strlen(str_) };
    if n > c_int::MAX as usize {
        return -1;
    }
    n as c_int
}
