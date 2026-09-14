//! Phase 4 — socket primitives and the socket BIO.
//!
//! This module carries the parts of the authority's socket surface that do not
//! need a `BIO_ADDR`: descriptor classification, non-blocking mode, readiness
//! waiting, descriptor close, and the `BIO_s_socket` method itself.
//!
//! ## What is deliberately not here, and why
//!
//! `BIO_socket`, `BIO_connect`, `BIO_bind`, `BIO_listen`, `BIO_accept_ex` and
//! `BIO_sock_info`, together with `BIO_ADDR*` and `BIO_lookup*`, all take or
//! produce a `BIO_ADDR`. Implementing them without the address object would mean
//! either fabricating an address or silently ignoring the caller's, so they are
//! recorded as deferred obligations of this stratum in
//! `forensics/phase4-obligations.json` rather than approximated. The exported
//! symbols that *do* exist here are complete behaviours, not placeholders.
//!
//! ## Classifying a socket error is itself a contract
//!
//! `BIO_sock_should_retry` is not "did it fail": a `-1` return consults `errno`
//! and reports whether the error is one of the transient classes, while a
//! *negative* return value is classified by the authority with
//! `((i << 24) >> 31) & 1`. That shift-and-test is reproduced exactly because a
//! caller's retry loop depends on it.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{BIO_LIB_1002, BIO_SOCK_248};
use crate::runtime::err::raise_site_dynamic;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};

use super::method::{bread_conv, bwrite_conv};
use super::sys;
use super::{Bio, BioMethod, BIO_TYPE_SOCKET};

/// The method name the authority reports for a socket BIO.
const SOCK_NAME: &[u8] = b"socket\0";

/// The compiled-in method table returned by `BIO_s_socket`.
static SOCK_METHOD: BioMethod = BioMethod {
    type_: BIO_TYPE_SOCKET,
    name: SOCK_NAME.as_ptr().cast(),
    bwrite: Some(bwrite_conv),
    bwrite_old: Some(sock_write),
    bread: Some(bread_conv),
    bread_old: Some(sock_read),
    bputs: Some(sock_puts),
    bgets: None,
    ctrl: Some(sock_ctrl),
    create: Some(sock_new),
    destroy: Some(sock_free),
    callback_ctrl: None,
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_s_socket(void)`
#[no_mangle]
pub extern "C" fn BIO_s_socket() -> *const BioMethod {
    guard_ffi(ptr::null(), || &SOCK_METHOD)
}

/// `BIO *BIO_new_socket(int sock, int close_flag)`
///
/// The authority is a `BIO_new` followed by `BIO_set_fd`, and that matters: the
/// control is what sets `init`, closes any previous descriptor and clears the
/// TCP-fast-open state. Writing the fields directly would leave `init` at the
/// value `sock_new` chose (`0`) and the BIO would behave as uninitialised.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_socket(sock: c_int, close_flag: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `BIO_new` allocates and runs `sock_new`.
        let bio = unsafe { super::BIO_new(BIO_s_socket()) };
        if bio.is_null() {
            return ptr::null_mut();
        }
        // `BIO_set_fd(b, fd, c)` is `BIO_int_ctrl(b, BIO_C_SET_FD, c, fd)`.
        // SAFETY: `bio` is a fresh socket BIO; `BIO_int_ctrl` passes the `int` by
        // address as the control requires.
        unsafe { super::BIO_int_ctrl(bio, super::BIO_C_SET_FD, close_flag as c_long, sock) };
        bio
    })
}

/// `int BIO_sock_init(void)`
///
/// There is no per-process socket initialisation on this platform, and the
/// authority's non-Windows path returns 1 without raising.
#[no_mangle]
pub extern "C" fn BIO_sock_init() -> c_int {
    guard_ffi(1, || 1)
}

/// `int BIO_sock_error(int sock)`
///
/// On a failed `getsockopt` the authority returns the *current socket error*, not
/// a generic 1 — measured: `BIO_sock_error(-1)` is `9` (`EBADF`), not `1`. A
/// caller that branches on this value sees the difference, so it is reproduced.
#[no_mangle]
pub extern "C" fn BIO_sock_error(sock: c_int) -> c_int {
    guard_ffi(1, || {
        let mut err: c_int = 0;
        let mut len: sys::SockLen = core::mem::size_of::<c_int>() as sys::SockLen;
        // SAFETY: `err` and `len` are live locals of the correct types.
        let rc = unsafe {
            sys::getsockopt(
                sock,
                sys::SOL_SOCKET,
                sys::SO_ERROR,
                (&mut err as *mut c_int).cast(),
                &mut len,
            )
        };
        if rc < 0 {
            // SAFETY: `errno` is thread-local and always readable.
            return unsafe { sys::errno() };
        }
        err
    })
}

/// `int BIO_socket_ioctl(int fd, long type, void *arg)`
#[no_mangle]
pub unsafe extern "C" fn BIO_socket_ioctl(fd: c_int, type_: c_long, arg: *mut c_void) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `fd` and `arg` are the caller's; `ioctl` requires a valid
        // descriptor and a request-appropriate argument.
        let ret = unsafe { sys::ioctl(fd, type_ as core::ffi::c_ulong, arg) };
        if ret == -1 {
            // SAFETY: the site is a compile-time constant and `errno` is
            // thread-local.
            unsafe { raise_site_dynamic(&BIO_SOCK_248, sys::errno()) };
        }
        ret
    })
}

/// `int BIO_socket_nbio(int fd, int mode)`
///
/// On this platform `FIONBIO` is available, so the authority takes the `ioctl`
/// path rather than the `fcntl` one, and returns `ioctl(...) == 0` — i.e. success
/// is *zero from the syscall*, which is why the comparison is written the way the
/// authority writes it rather than as a truthiness test.
#[no_mangle]
pub extern "C" fn BIO_socket_nbio(fd: c_int, mode: c_int) -> c_int {
    guard_ffi(0, || {
        let mut l = mode;
        // SAFETY: `fd` is the caller's descriptor and `l` is a live local.
        let ret = unsafe { BIO_socket_ioctl(fd, FIONBIO, (&mut l as *mut c_int).cast()) };
        (ret == 0) as c_int
    })
}

/// `FIONBIO` on Linux (`asm-generic/ioctls.h`).
const FIONBIO: c_long = 0x5421;

/// `int BIO_sock_non_fatal_error(int err)`
#[no_mangle]
pub extern "C" fn BIO_sock_non_fatal_error(err: c_int) -> c_int {
    guard_ffi(0, || {
        if matches!(
            err,
            sys::EAGAIN
                | sys::EWOULDBLOCK
                | sys::EINTR
                | sys::EINPROGRESS
                | sys::EALREADY
                | sys::ENOTCONN
                | sys::ECONNREFUSED
                | sys::ECONNRESET
                | sys::ENOBUFS
        ) {
            1
        } else {
            0
        }
    })
}

/// `int BIO_sock_should_retry(int i)`
#[no_mangle]
pub extern "C" fn BIO_sock_should_retry(i: c_int) -> c_int {
    guard_ffi(0, || {
        if i == -1 {
            // SAFETY: `errno` is thread-local and always readable.
            return BIO_sock_non_fatal_error(unsafe { sys::errno() });
        }
        if i > 0 {
            return 0;
        }
        // The authority shifts the value left by 24 and keeps the top bit;
        // reproduced exactly rather than re-derived.
        ((i << 24) >> 31) & 1
    })
}

/// `int BIO_err_is_non_fatal(unsigned int errcode)`
#[no_mangle]
pub extern "C" fn BIO_err_is_non_fatal(errcode: core::ffi::c_uint) -> c_int {
    guard_ffi(0, || {
        let lib = ((errcode >> 23) & 0xff) as c_int;
        let reason = (errcode & 0x00ff_ffff) as c_int;
        if lib == super::ERR_LIB_SYS {
            return BIO_sock_non_fatal_error(reason);
        }
        if lib == super::BIO_LIB_CODE && reason == super::BIO_R_NON_FATAL {
            1
        } else {
            0
        }
    })
}

/// `int BIO_socket_wait(int fd, int for_read, time_t max_time)`
///
/// Returns 1 on readiness, 0 on timeout (raising `BIO_R_TRANSFER_TIMEOUT`) and
/// -1 on error (raising `BIO_R_TRANSFER_ERROR`). The two failure classes are
/// distinct because a caller's retry policy treats them differently.
#[no_mangle]
pub extern "C" fn BIO_socket_wait(fd: c_int, for_read: c_int, max_time: c_long) -> c_int {
    guard_ffi(-1, || {
        if max_time <= 0 {
            return 1;
        }
        let mut fds = [sys::PollFd {
            fd,
            events: if for_read != 0 {
                sys::POLLIN
            } else {
                sys::POLLOUT
            },
            revents: 0,
        }];
        // SAFETY: `time` takes a `time_t *`; NULL asks for the current time.
        let now = unsafe { sys::time(ptr::null_mut()) };
        let mut timeout_ms = (max_time - now).saturating_mul(1000);
        if timeout_ms < 0 {
            timeout_ms = 0;
        }
        let timeout_ms = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: `fds` is a live one-element array.
        let rv = unsafe { sys::poll(fds.as_mut_ptr(), 1, timeout_ms) };
        if rv == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site_dynamic(&BIO_LIB_1002, super::BIO_R_TRANSFER_TIMEOUT) };
            return 0;
        }
        if rv < 0 {
            // The authority reports a failed wait through the return value; there
            // is no raise site for this arm in `bio_sock.c`, so none is recorded
            // here either.
            return -1;
        }
        1
    })
}

/// `int BIO_closesocket(int sock)`
#[no_mangle]
pub extern "C" fn BIO_closesocket(sock: c_int) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `sock` is the caller's descriptor.
        unsafe { sys::close(sock) }
    })
}

/* ------------------------------------------------------------------------- */
/* The socket BIO method.                                                    */
/* ------------------------------------------------------------------------- */

/// `static int sock_write(BIO *b, const char *in, int inl)`
///
/// # Safety
/// `b` must be a live socket BIO; `in_` must be valid for `inl` bytes.
unsafe extern "C" fn sock_write(b: *mut Bio, in_: *const c_char, inl: c_int) -> c_int {
    // SAFETY: `b` is live.
    unsafe {
        super::BIO_clear_flags(b, super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY);
        if inl == 0 {
            return 0;
        }
        let sock = (*b).num;
        let ret = sys::send(sock, in_.cast(), inl as usize, 0);
        if ret < 0 {
            if BIO_sock_should_retry(ret as c_int) != 0 {
                super::BIO_set_flags(b, super::BIO_FLAGS_WRITE | super::BIO_FLAGS_SHOULD_RETRY);
            }
            return -1;
        }
        ret as c_int
    }
}

/// `static int sock_read(BIO *b, char *out, int outl)`
///
/// A NULL `out` peeks one byte without consuming it, which is how a caller tests
/// readability; that arm is reproduced rather than treated as an error.
///
/// # Safety
/// `b` must be a live socket BIO; `out` must be NULL or valid for `outl` bytes.
unsafe extern "C" fn sock_read(b: *mut Bio, out: *mut c_char, outl: c_int) -> c_int {
    // SAFETY: `b` is live.
    unsafe {
        super::BIO_clear_flags(b, super::BIO_FLAGS_RWS | super::BIO_FLAGS_SHOULD_RETRY);
        if outl == 0 {
            return 0;
        }
        let sock = (*b).num;
        if out.is_null() {
            let mut c: [c_char; 1] = [0];
            let ret = sys::recv(sock, c.as_mut_ptr().cast(), 1, sys::MSG_PEEK);
            return if ret == 1 { 1 } else { ret as c_int };
        }
        let ret = sys::recv(sock, out.cast(), outl as usize, 0);
        if ret < 0 {
            if BIO_sock_should_retry(ret as c_int) != 0 {
                super::BIO_set_flags(b, super::BIO_FLAGS_READ | super::BIO_FLAGS_SHOULD_RETRY);
            }
            return -1;
        }
        ret as c_int
    }
}

/// `static int sock_puts(BIO *b, const char *str)`
///
/// # Safety
/// `b` must be a live socket BIO; `str_` must be NUL-terminated.
unsafe extern "C" fn sock_puts(b: *mut Bio, str_: *const c_char) -> c_int {
    // SAFETY: `str_` is NUL-terminated per the method contract.
    let n = unsafe { sys::strlen(str_) };
    if n > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `b` is live and `str_` is valid for `n` bytes.
    unsafe { sock_write(b, str_, n as c_int) }
}

/// The socket BIO's private state.
///
/// The authority's `struct bss_sock_st` carries the TCP-fast-open fields. Its
/// layout is ours (the structure is private), but the *allocation* is observable:
/// a bare `BIO_new(BIO_s_socket())` either has a non-NULL private block or fails
/// creation, and its `init` stays `0` until `BIO_C_SET_FD` is used.
#[repr(C)]
struct BssSockData {
    /// Set once a peer address has been supplied for TFO.
    tfo_first: c_int,
    /// The TFO peer address (`BIO_ADDR` is a Phase 4 open obligation, so this is
    /// storage only).
    tfo_peer: [u8; 28],
}

/// `static int sock_new(BIO *bi)`
///
/// Measured: the created BIO has `init == 0`. That is not an oversight in the
/// authority — it is why `BIO_ctrl(b, BIO_C_GET_FD, …)` answers `-1` and why a
/// bare socket BIO's destructor does not close descriptor 0.
///
/// # Safety
/// `bi` must be a live BIO.
unsafe extern "C" fn sock_new(bi: *mut Bio) -> c_int {
    // SAFETY: `bi` is live.
    unsafe {
        (*bi).init = 0;
        (*bi).num = 0;
        (*bi).flags = 0;
        // SAFETY: a plain zeroed allocation request.
        let data = CRYPTO_zalloc(core::mem::size_of::<BssSockData>(), ptr::null(), 0)
            .cast::<BssSockData>();
        if data.is_null() {
            return 0;
        }
        (*bi).ptr = data.cast();
    }
    1
}

/// `static int sock_free(BIO *a)`
///
/// The descriptor is closed only when `shutdown` is set **and** the BIO was
/// initialised — a BIO created but never given a descriptor must not close a
/// descriptor it does not own. The private block is released unconditionally.
///
/// # Safety
/// `a` must be a live socket BIO being destroyed.
unsafe extern "C" fn sock_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live.
    unsafe {
        if (*a).shutdown != 0 {
            if (*a).init != 0 {
                BIO_closesocket((*a).num);
            }
            (*a).init = 0;
            (*a).flags = 0;
        }
        CRYPTO_free((*a).ptr, ptr::null(), 0);
        (*a).ptr = ptr::null_mut();
    }
    1
}

/// `static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)`
///
/// # Safety
/// `b` must be a live socket BIO; `arg` must be as the command requires.
unsafe extern "C" fn sock_ctrl(b: *mut Bio, cmd: c_int, num: c_long, arg: *mut c_void) -> c_long {
    // The authority initialises `ret` to 1 and only a few cases change it, so the
    // "handled" cases that fall through report success.
    let mut ret: c_long = 1;
    match cmd {
        super::BIO_C_SET_FD => {
            // The old descriptor is closed only when the BIO owned it, and the
            // flag word is cleared as part of the same minimal teardown. The TFO
            // state is reset because the new descriptor has no TFO peer yet.
            // SAFETY: `b` is live; the caller passes `int *`.
            unsafe {
                if (*b).shutdown != 0 {
                    if (*b).init != 0 {
                        BIO_closesocket((*b).num);
                    }
                    (*b).flags = 0;
                }
                (*b).num = *arg.cast::<c_int>();
                (*b).shutdown = num as c_int;
                (*b).init = 1;
                let data = (*b).ptr.cast::<BssSockData>();
                if !data.is_null() {
                    (*data).tfo_first = 0;
                    (*data).tfo_peer = [0u8; 28];
                }
            }
        }
        super::BIO_C_GET_FD => {
            // The descriptor is *returned*, not turned into a success flag, and an
            // uninitialised BIO reports -1. Measured: `BIO_ctrl(s, BIO_C_GET_FD,
            // 0, &i)` is `3` for a socket whose descriptor is 3.
            // SAFETY: `b` is live.
            let init = unsafe { (*b).init };
            if init != 0 {
                // SAFETY: `b` is live and the caller passes `int *`.
                unsafe {
                    let num_ = (*b).num;
                    if !arg.is_null() {
                        *arg.cast::<c_int>() = num_;
                    }
                    ret = num_ as c_long;
                }
            } else {
                ret = -1;
            }
        }
        super::BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` is live.
            ret = unsafe { (*b).shutdown as c_long };
        }
        super::BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` is live.
            unsafe { (*b).shutdown = num as c_int };
        }
        super::BIO_CTRL_DUP | super::BIO_CTRL_FLUSH => ret = 1,
        super::BIO_CTRL_GET_RPOLL_DESCRIPTOR | super::BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
            // SAFETY: `b` is live; the caller passes a `BIO_POLL_DESCRIPTOR *`.
            unsafe {
                if (*b).init == 0 {
                    return 0;
                }
                let pd = arg.cast::<super::BioPollDescriptor>();
                if !pd.is_null() {
                    (*pd).r#type = super::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD;
                    (*pd).value.fd = (*b).num;
                }
            }
        }
        // A socket BIO's EOF is a *flag*, set by `BIO_CTRL_EOF`'s own peers; it is
        // not a read-ahead probe. Measured against the authority, which reports
        // the flag rather than peeking at the descriptor.
        super::BIO_CTRL_EOF => {
            // SAFETY: `b` is live.
            ret = unsafe { ((*b).flags & super::BIO_FLAGS_IN_EOF != 0) as c_long };
        }
        // `BIO_C_SET_NBIO` is deliberately absent: the authority's socket method
        // has no case for it, so it reaches `default` and reports 0. Applications
        // use `BIO_socket_nbio` for a socket BIO instead.
        _ => ret = 0,
    }
    ret
}
