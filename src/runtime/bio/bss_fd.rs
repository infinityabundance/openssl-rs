//! Phase 4 — the file-descriptor BIO (`BIO_s_fd`, `BIO_new_fd`).
//!
//! The descriptor BIO is the layer where the retry protocol becomes visible:
//! `fd_read` and `fd_write` clear the retry flags, and on a non-positive result
//! consult `BIO_fd_should_retry` — which reads `errno` — to decide whether to set
//! the retry-read or retry-write flag. Unlike the socket BIO, `EINTR` counts as
//! retryable here, because a blocking `read(2)` on a pipe can be interrupted.
//!
//! Three details are easy to get wrong and are all observable:
//!
//! * `clear_sys_error()` is `errno = 0` on this platform, and it runs **before**
//!   the syscall, so an operation that succeeds or reaches EOF leaves `errno` at
//!   zero rather than holding a stale value;
//! * `fd_read` sets `BIO_FLAGS_IN_EOF` when the read returns exactly 0, which is
//!   what makes `BIO_ctrl(BIO_CTRL_EOF)` answer 1 afterwards;
//! * `fd_gets` reads **one byte at a time** through `fd_read`, so a partial
//!   `read(2)` still yields a complete line as far as the buffer allows, and a
//!   non-blocking descriptor can return a short line with a retry flag set.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;

use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{
    Bio, BioMethod, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE, BIO_CTRL_INFO,
    BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET_CLOSE, BIO_CTRL_WPENDING, BIO_C_FILE_SEEK,
    BIO_C_FILE_TELL, BIO_C_GET_FD, BIO_C_SET_FD, BIO_FLAGS_IN_EOF, BIO_FLAGS_READ, BIO_FLAGS_RWS,
    BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_UPLINK_INTERNAL, BIO_FLAGS_WRITE, BIO_TYPE_FD,
};

/// The method name the authority reports for a descriptor BIO.
const FD_NAME: &[u8] = b"file descriptor\0";

/// A compiled-in method table. `BIO_s_fd()` returns its address.
static FD_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_FD,
    name: FD_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(fd_write),
    bread: Some(bread_conv),
    bread_old: Some(fd_read),
    bputs: Some(fd_puts),
    bgets: Some(fd_gets),
    ctrl: Some(fd_ctrl),
    create: Some(fd_new),
    destroy: Some(fd_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_fd(void)`
#[no_mangle]
pub extern "C" fn BIO_s_fd() -> *const BioMethod {
    guard_ffi(ptr::null(), || &FD_METHOD)
}

/// `BIO *BIO_new_fd(int fd, int close_flag)`
#[no_mangle]
pub extern "C" fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_s_fd` returns a static method table.
        let ret = unsafe { super::BIO_new(BIO_s_fd()) };
        if ret.is_null() {
            return ptr::null_mut();
        }
        // `BIO_set_fd(b, fd, c)` is `BIO_int_ctrl(b, BIO_C_SET_FD, c, fd)`.
        // SAFETY: `ret` is a fresh descriptor BIO; `BIO_int_ctrl` passes the
        // `int` by address as the control requires.
        unsafe { super::BIO_int_ctrl(ret, BIO_C_SET_FD, close_flag as c_long, fd) };
        ret
    })
}

/// `fd_new`
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn fd_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 0;
        (*bi).num = -1;
        (*bi).ptr = ptr::null_mut();
        (*bi).flags = BIO_FLAGS_UPLINK_INTERNAL;
    }
    1
}

/// `fd_free` — closes the descriptor when `shutdown` and `init` are set.
///
/// # Safety
/// `a` must be NULL or a live BIO.
unsafe extern "C" fn fd_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live.
    if unsafe { (*a).shutdown != 0 } {
        // SAFETY: as above.
        let (init, num) = unsafe { ((*a).init, (*a).num) };
        if init != 0 {
            // SAFETY: `num` is a descriptor this BIO owns.
            unsafe { sys::close(num) };
        }
        // SAFETY: as above.
        unsafe {
            (*a).init = 0;
            (*a).flags = BIO_FLAGS_UPLINK_INTERNAL;
        }
    }
    1
}

/// `fd_read`
///
/// # Safety
/// `b` must be a live descriptor BIO and `out` writable for `outl` bytes or NULL.
unsafe extern "C" fn fd_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    let mut ret = 0;
    if !out.is_null() {
        // `clear_sys_error()`.
        // SAFETY: `errno` is thread-local.
        unsafe { sys::set_errno(0) };
        // SAFETY: `b` is live; `out` is writable for `outl` bytes.
        let num = unsafe { (*b).num };
        // SAFETY: the descriptor and buffer follow this method's contract; `out` is writable for `outl`.
        ret = unsafe { sys::read(num, out.cast(), outl as usize) as c_int };
        // `BIO_clear_retry_flags(b)`.
        // SAFETY: `b` is live.
        unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
        if ret <= 0 {
            if super::retry::BIO_fd_should_retry(ret) != 0 {
                // `BIO_set_retry_read(b)`.
                // SAFETY: `b` is live.
                unsafe { super::BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) };
            } else if ret == 0 {
                // SAFETY: `b` is live.
                unsafe { (*b).flags |= BIO_FLAGS_IN_EOF };
            }
        }
    }
    ret
}

/// `fd_write`
///
/// # Safety
/// `b` must be a live descriptor BIO and `in_` readable for `inl` bytes.
unsafe extern "C" fn fd_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    // `clear_sys_error()`.
    // SAFETY: `errno` is thread-local.
    unsafe { sys::set_errno(0) };
    // SAFETY: `b` is live; `in_` is readable for `inl` bytes.
    let num = unsafe { (*b).num };
    // SAFETY: the descriptor and buffer follow this method's contract; `in_` is readable for `inl`.
    let ret = unsafe { sys::write(num, in_.cast(), inl as usize) as c_int };
    // SAFETY: `b` is live.
    unsafe { super::BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
    if ret <= 0 && super::retry::BIO_fd_should_retry(ret) != 0 {
        // `BIO_set_retry_write(b)`.
        // SAFETY: `b` is live.
        unsafe { super::BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
    }
    ret
}

/// `fd_ctrl`
///
/// # Safety
/// `b` must be a live descriptor BIO and `ptr` must match the control's contract.
unsafe extern "C" fn fd_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr_: *mut c_void) -> c_long {
    let mut ret: c_long = 1;
    // SAFETY: `b` is live.
    let fd = unsafe { (*b).num };

    match cmd {
        BIO_CTRL_RESET | BIO_C_FILE_SEEK => {
            // `BIO_CTRL_RESET` zeroes the offset before falling through, so both
            // commands seek absolutely.
            let off = if cmd == BIO_CTRL_RESET { 0 } else { num };
            // SAFETY: `fd` is a descriptor this BIO owns.
            ret = unsafe { sys::lseek(fd, off, sys::SEEK_SET) as c_long };
        }
        BIO_C_FILE_TELL | BIO_CTRL_INFO => {
            // SAFETY: as above.
            ret = unsafe { sys::lseek(fd, 0, sys::SEEK_CUR) as c_long };
        }
        BIO_C_SET_FD => {
            // SAFETY: `b` is live.
            unsafe { fd_free(b) };
            // SAFETY: the control's contract says `ptr_` is an `int *`.
            let newfd = unsafe { *(ptr_ as *const c_int) };
            // SAFETY: `b` is live.
            unsafe {
                (*b).num = newfd;
                (*b).shutdown = num as c_int;
                (*b).init = 1;
            }
        }
        BIO_C_GET_FD => {
            // SAFETY: `b` is live.
            if unsafe { (*b).init } != 0 {
                if !ptr_.is_null() {
                    // SAFETY: the control's contract says `ptr_` is an `int *`.
                    unsafe { *(ptr_ as *mut c_int) = fd };
                }
                ret = fd as c_long;
            } else {
                ret = -1;
            }
        }
        BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).shutdown as c_long };
        }
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` is live.
            unsafe { (*b).shutdown = num as c_int };
        }
        BIO_CTRL_PENDING | BIO_CTRL_WPENDING => {
            ret = 0;
        }
        BIO_CTRL_DUP | BIO_CTRL_FLUSH => {
            ret = 1;
        }
        BIO_CTRL_EOF => {
            // SAFETY: `b` is live.
            ret = c_long::from(unsafe { (*b).flags } & BIO_FLAGS_IN_EOF != 0);
        }
        _ => {
            ret = 0;
        }
    }
    ret
}

/// `fd_puts`
///
/// # Safety
/// `bp` must be a live descriptor BIO and `s` NUL-terminated.
unsafe extern "C" fn fd_puts(bp: *mut Bio, s: *const c_char) -> c_int {
    if s.is_null() {
        // The authority calls `strlen`, which faults; total by policy.
        return -1;
    }
    // SAFETY: `s` is NUL-terminated.
    let n = unsafe { sys::strlen(s) };
    if n > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp` is live and `s` is readable for `n` bytes.
    unsafe { fd_write(bp, s, n as c_int) }
}

/// `fd_gets` — one byte per `fd_read`, stopping at a newline, at `size - 1`
/// bytes, or at the first non-positive read.
///
/// # Safety
/// `bp` must be a live descriptor BIO and `buf` writable for `size` bytes.
unsafe extern "C" fn fd_gets(bp: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    if buf.is_null() || size <= 0 {
        // The authority's `end = buf + size - 1` underflows for size 0; total by
        // policy.
        return 0;
    }
    let mut ptr = buf;
    // SAFETY: `size > 0` was checked, so `size - 1` is inside the caller's buffer.
    let end = unsafe { buf.add((size - 1) as usize) };
    while ptr < end {
        // SAFETY: `ptr` is writable and inside `buf`.
        let r = unsafe { fd_read(bp, ptr, 1) };
        if r <= 0 {
            break;
        }
        // SAFETY: `fd_read` wrote one byte.
        let c = unsafe { *ptr } as u8;
        // SAFETY: `ptr` is at most `end`, which is inside the caller's buffer.
        ptr = unsafe { ptr.add(1) };
        if c == b'\n' {
            break;
        }
    }
    // SAFETY: `ptr` is within `buf` (at most `end`).
    unsafe { *ptr = 0 };
    // SAFETY: `buf` is NUL-terminated now.
    let first = unsafe { *buf };
    if first != 0 {
        // SAFETY: as above.
        return unsafe { sys::strlen(buf) as c_int };
    }
    0
}
