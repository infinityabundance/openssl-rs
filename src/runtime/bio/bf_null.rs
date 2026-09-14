//! Phase 4 — the null filter (`BIO_f_null`).
//!
//! Unlike `BIO_s_null`, this is a *filter*: it forwards every operation to
//! `next_bio` and exists so a caller can insert a no-op node into a chain (for
//! example to keep a `BIO_push`/`BIO_pop` pairing balanced). Because it forwards,
//! the retry flags it exposes are the downstream BIO's, copied up after each
//! transfer — which is why `BIO_clear_retry_flags` precedes `BIO_copy_next_retry`
//! rather than the other way round.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;

use super::method::{bread_conv, bwrite_conv};
use super::{
    Bio, BioInfoCb, BioMethod, BIO_CTRL_DUP, BIO_C_DO_STATE_MACHINE, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_TYPE_NULL_FILTER,
};

/// The authority's method name for the null filter.
const NULLF_NAME: &[u8] = b"NULL filter\0";

/// The compiled-in method table returned by `BIO_f_null`.
static NULLF_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_NULL_FILTER,
    name: NULLF_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(nullf_write),
    bread: Some(bread_conv),
    bread_old: Some(nullf_read),
    bputs: Some(nullf_puts),
    bgets: Some(nullf_gets),
    ctrl: Some(nullf_ctrl),
    create: None,
    destroy: None,
    callback_ctrl: Some(nullf_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_null(void)`
#[no_mangle]
pub extern "C" fn BIO_f_null() -> *const BioMethod {
    guard_ffi(ptr::null(), || &NULLF_METHOD)
}

/// `static int nullf_read(BIO *b, char *out, int outl)`
///
/// # Safety
/// `b` must be a live filter BIO; `out` must be valid for `outl` bytes.
unsafe extern "C" fn nullf_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    if out.is_null() {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is a live BIO in the chain.
    let ret = unsafe { super::BIO_read(next, out.cast(), outl) };
    // SAFETY: `b` is live.
    unsafe {
        super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        super::BIO_copy_next_retry(b);
    }
    ret
}

/// `static int nullf_write(BIO *b, const char *in, int inl)`
///
/// # Safety
/// `b` must be a live filter BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn nullf_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    if in_.is_null() || inl <= 0 {
        return 0;
    }
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is a live BIO in the chain.
    let ret = unsafe { super::BIO_write(next, in_.cast(), inl) };
    // SAFETY: `b` is live.
    unsafe {
        super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        super::BIO_copy_next_retry(b);
    }
    ret
}

/// `static long nullf_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live filter BIO; `arg` must be as the command requires.
unsafe extern "C" fn nullf_ctrl(b: *mut Bio, cmd: c_int, num: c_long, arg: *mut c_void) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    match cmd {
        BIO_C_DO_STATE_MACHINE => {
            // SAFETY: `b` and `next` are live.
            unsafe {
                super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
            }
            // SAFETY: `next` is live.
            let ret = unsafe { super::BIO_ctrl(next, cmd, num, arg) };
            // SAFETY: `b` is live.
            unsafe { super::BIO_copy_next_retry(b) };
            ret
        }
        // A filter must not duplicate the *downstream* BIO's private state into
        // itself, so the authority refuses `DUP` here rather than forwarding it.
        BIO_CTRL_DUP => 0,
        _ => {
            // SAFETY: `next` is live.
            unsafe { super::BIO_ctrl(next, cmd, num, arg) }
        }
    }
}

/// `static long nullf_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)`
///
/// # Safety
/// `b` must be a live filter BIO.
unsafe extern "C" fn nullf_callback_ctrl(b: *mut Bio, cmd: c_int, fp: *mut BioInfoCb) -> c_long {
    // SAFETY: `b` is live.
    let next = unsafe { (*b).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live.
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// `static int nullf_gets(BIO *bp, char *buf, int size)`
///
/// # Safety
/// `bp` must be a live filter BIO; `buf` must be valid for `size` bytes.
unsafe extern "C" fn nullf_gets(bp: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    // SAFETY: `bp` is live.
    let next = unsafe { (*bp).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live; `buf` is valid for `size` bytes.
    unsafe { super::BIO_gets(next, buf, size) }
}

/// `static int nullf_puts(BIO *bp, const char *str)`
///
/// # Safety
/// `bp` must be a live filter BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn nullf_puts(bp: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `bp` is live.
    let next = unsafe { (*bp).next_bio };
    if next.is_null() {
        return 0;
    }
    // SAFETY: `next` is live; `str_` is NUL-terminated.
    unsafe { super::BIO_puts(next, str_) }
}
