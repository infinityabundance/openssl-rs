//! Phase 4 — the BIO dispatch layer.
//!
//! Everything in this module is a *dispatch* concern rather than a method
//! concern: argument checking, the callback protocol, the `init` gate, the
//! `num_read`/`num_write` accounting, error raising, and the translation between
//! the byte-counting entry points (`BIO_read`, `BIO_write`) and the
//! success-flag entry points (`BIO_read_ex`, `BIO_write_ex`).
//!
//! ## The two contracts are not the same
//!
//! `BIO_read` returns a **byte count** (or a negative failure class), while
//! `BIO_read_ex` returns **1 or 0**. The authority is explicit about this and the
//! distinction is load-bearing: code that treats `BIO_read_ex`'s result as a
//! length silently reads zero bytes. Both are reproduced exactly, and the
//! `RT-BIO` probe measures both on the same object so the relationship is
//! observed rather than assumed.
//!
//! ## Failure classes are observable
//!
//! The dispatch layer distinguishes `-1` (ordinary/uninitialised failure), `-2`
//! (unsupported method) and `0`, and raises a different `ERR` for each. A caller
//! that branches on the return value, or reads the error queue, sees the
//! difference, so the classes are part of the contract rather than an internal
//! detail. The `ERR` coordinates come from
//! `crate::runtime::err::err_sites`, generated from the pinned authority source
//! by `forensics/tools/gen_err_raise_sites.py`.
//!
//! ## The callback protocol
//!
//! Every entry point calls the BIO's callback **before** the method and again
//! with `BIO_CB_RETURN` after it, and a non-positive pre-call result vetoes the
//! operation. Both the modern (`BIO_set_callback_ex`) and the deprecated
//! (`BIO_set_callback`) forms are supported, with the argument translation the
//! authority performs between them.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::err::err_sites::{
    BIO_LIB_1002, BIO_LIB_1022, BIO_LIB_1064, BIO_LIB_1071, BIO_LIB_267, BIO_LIB_271, BIO_LIB_279,
    BIO_LIB_294, BIO_LIB_340, BIO_LIB_348, BIO_LIB_399, BIO_LIB_405, BIO_LIB_424, BIO_LIB_446,
    BIO_LIB_452, BIO_LIB_471, BIO_LIB_500, BIO_LIB_504, BIO_LIB_515, BIO_LIB_533, BIO_LIB_549,
    BIO_LIB_553, BIO_LIB_558, BIO_LIB_569, BIO_LIB_601, BIO_LIB_605, BIO_LIB_611, BIO_LIB_615,
    BIO_LIB_663, BIO_LIB_690, BIO_LIB_813,
};
use crate::runtime::err::{raise_site, raise_site_dynamic};

use super::{
    Bio, BioInfoCb, BioMsg, BIO_CB_CTRL, BIO_CB_GETS, BIO_CB_PUTS, BIO_CB_READ, BIO_CB_RECVMMSG,
    BIO_CB_RETURN, BIO_CB_SENDMMSG, BIO_CB_WRITE, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT,
    BIO_CTRL_DGRAM_GET_SEND_TIMEOUT, BIO_CTRL_EOF, BIO_CTRL_GET_RPOLL_DESCRIPTOR,
    BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_PENDING, BIO_CTRL_POP, BIO_CTRL_PUSH,
    BIO_CTRL_WPENDING, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_TYPE_MASK,
};

/// `BIO_CB_READ`, `BIO_CB_WRITE` and `BIO_CB_GETS` are the operations whose
/// length argument reaches a *legacy* callback through `argi`; see
/// `HAS_LEN_OPER` in the authority.
fn has_len_oper(oper: c_int) -> bool {
    oper == BIO_CB_READ || oper == BIO_CB_WRITE || oper == BIO_CB_GETS
}

/// `int INT_MAX` on this target.
const INT_MAX: c_long = c_int::MAX as c_long;

/// The authority's `bio_call_callback`.
///
/// Modern callbacks receive every argument; legacy callbacks receive the
/// translated set and, on the return leg of a read/write/gets, exchange a byte
/// count for a success flag. The translation is reproduced because a legacy
/// callback is a public (if deprecated) interface and its observable arguments
/// are part of the compatibility contract.
///
/// # Safety
/// `b` must be a live BIO; `argp` and `processed` must be valid for the
/// operation being performed, per the callback contract.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn bio_call_callback(
    bio: *mut Bio,
    oper: c_int,
    argp: *const c_char,
    len: usize,
    argi: c_int,
    argl: c_long,
    inret: c_long,
    processed: *mut usize,
) -> c_long {
    // SAFETY: `bio` is a live BIO per the caller's contract.
    let Some(b) = (unsafe { bio.as_ref() }) else {
        return inret;
    };
    if let Some(cb) = b.callback_ex {
        // SAFETY: the callback was installed through `BIO_set_callback_ex` for
        // this object; the arguments are the documented ones.
        return unsafe { cb(bio, oper, argp, len, argi, argl, inret as c_int, processed) };
    }
    let Some(cb) = b.callback else {
        return inret;
    };
    let bareoper = oper & !BIO_CB_RETURN;
    let mut argi = argi;
    let mut inret = inret;
    if has_len_oper(bareoper) {
        if len as c_long > INT_MAX {
            return -1;
        }
        argi = len as c_int;
    }
    if inret > 0 && (oper & BIO_CB_RETURN) != 0 && bareoper != BIO_CB_CTRL {
        // SAFETY: `processed` is a valid out-parameter on this leg, per the
        // callback contract.
        if unsafe { *processed } as c_long > INT_MAX {
            return -1;
        }
        // SAFETY: as above.
        inret = unsafe { *processed } as c_long;
    }
    // SAFETY: the legacy callback was installed through `BIO_set_callback`.
    let mut ret = unsafe { cb(bio, oper, argp, argi, argl, inret) };
    if ret > 0 && (oper & BIO_CB_RETURN) != 0 && bareoper != BIO_CB_CTRL {
        // SAFETY: `processed` is a valid out-parameter on this leg.
        unsafe { *processed = ret as usize };
        ret = 1;
    }
    ret
}

/// Whether the BIO has either callback form installed (`HAS_CALLBACK`).
///
/// # Safety
/// `bio` must be NULL or a live BIO.
unsafe fn has_callback(bio: *mut Bio) -> bool {
    match unsafe { bio.as_ref() } {
        Some(b) => b.callback_ex.is_some() || b.callback.is_some(),
        None => false,
    }
}

/// `static int bio_read_intern(BIO *b, void *data, size_t dlen, size_t *readbytes)`
///
/// # Safety
/// `bio` must be NULL or a live BIO; `data` must be valid for `dlen` bytes when
/// `dlen` is non-zero; `readbytes` must point at a writable `size_t`.
unsafe fn bio_read_intern(
    bio: *mut Bio,
    data: *mut c_void,
    dlen: usize,
    readbytes: *mut usize,
) -> c_int {
    if bio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_267) };
        return -1;
    }
    // SAFETY: `bio` is non-NULL and live.
    let b = unsafe { &mut *bio };
    let Some(m) = (unsafe { b.method.as_ref() }) else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_271) };
        return -2;
    };
    let Some(bread) = m.bread else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_271) };
        return -2;
    };
    if unsafe { has_callback(bio) } {
        // SAFETY: the callback contract for `BIO_CB_READ` allows `processed` to
        // be NULL, which is what the pre-call passes.
        let ret = unsafe {
            bio_call_callback(
                bio,
                BIO_CB_READ,
                data.cast(),
                dlen,
                0,
                0,
                1,
                ptr::null_mut(),
            )
        };
        if ret <= 0 {
            return ret as c_int;
        }
    }
    if b.init == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_279) };
        return -1;
    }
    // SAFETY: the method's read contract is to fill at most `dlen` bytes at
    // `data` and report how many through `readbytes`.
    let mut ret = unsafe { bread(bio, data.cast(), dlen, readbytes) };
    if ret > 0 {
        // SAFETY: `readbytes` is a writable out-parameter owned by this call.
        b.num_read += unsafe { *readbytes } as u64;
    }
    if unsafe { has_callback(bio) } {
        // SAFETY: on the return leg `processed` receives the byte count.
        ret = unsafe {
            bio_call_callback(
                bio,
                BIO_CB_READ | BIO_CB_RETURN,
                data.cast(),
                dlen,
                0,
                0,
                ret as c_long,
                readbytes,
            )
        } as c_int;
    }
    if ret > 0 && unsafe { *readbytes } > dlen {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_294) };
        return -1;
    }
    ret
}

/// `int BIO_read(BIO *b, void *data, int dlen)`
///
/// Returns the number of bytes read, or a negative failure class. A negative
/// `dlen` is `0`, not an error.
#[no_mangle]
pub unsafe extern "C" fn BIO_read(bio: *mut Bio, data: *mut c_void, dlen: c_int) -> c_int {
    guard_ffi(0, || {
        if dlen < 0 {
            return 0;
        }
        let mut readbytes: usize = 0;
        // SAFETY: `bio` is NULL or live; `data` is valid for `dlen` bytes.
        let mut ret = unsafe { bio_read_intern(bio, data, dlen as usize, &mut readbytes) };
        if ret > 0 {
            ret = readbytes as c_int;
        }
        ret
    })
}

/// `int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes)`
///
/// Returns **1** on success (with `*readbytes` set) and 0 on failure — the
/// success-flag form, not a byte count.
#[no_mangle]
pub unsafe extern "C" fn BIO_read_ex(
    bio: *mut Bio,
    data: *mut c_void,
    dlen: usize,
    readbytes: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the out-parameter contract is the
        // method's.
        (unsafe { bio_read_intern(bio, data, dlen, readbytes) } > 0) as c_int
    })
}

/// `static int bio_write_intern(BIO *b, const void *data, size_t dlen, size_t *written)`
///
/// A NULL `b` is not an error here: it means "zero bytes written", which is why
/// this helper returns 0 rather than raising. The authority comments on it.
///
/// # Safety
/// `bio` must be NULL or a live BIO; `data` must be valid for `dlen` bytes when
/// `dlen` is non-zero.
unsafe fn bio_write_intern(
    bio: *mut Bio,
    data: *const c_void,
    dlen: usize,
    written: *mut usize,
) -> c_int {
    if !written.is_null() {
        // SAFETY: `written` is non-NULL and writable per the caller's contract.
        unsafe { *written = 0 };
    }
    if bio.is_null() {
        return 0;
    }
    // SAFETY: `bio` is non-NULL and live.
    let b = unsafe { &mut *bio };
    let Some(bwrite) = (unsafe { b.method.as_ref() }).and_then(|m| m.bwrite) else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_340) };
        return -2;
    };
    if unsafe { has_callback(bio) } {
        // SAFETY: the callback contract for `BIO_CB_WRITE` allows `processed` to
        // be NULL on the pre-call.
        let ret = unsafe {
            bio_call_callback(
                bio,
                BIO_CB_WRITE,
                data.cast(),
                dlen,
                0,
                0,
                1,
                ptr::null_mut(),
            )
        };
        if ret <= 0 {
            return ret as c_int;
        }
    }
    if b.init == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&BIO_LIB_348) };
        return -1;
    }
    let mut local_written: usize = 0;
    // SAFETY: the method's write contract is to consume at most `dlen` bytes from
    // `data` and report how many through `local_written`.
    let mut ret = unsafe { bwrite(bio, data.cast(), dlen, &mut local_written) };
    if ret > 0 {
        b.num_write += local_written as u64;
    }
    if unsafe { has_callback(bio) } {
        // SAFETY: on the return leg `processed` receives the byte count.
        ret = unsafe {
            bio_call_callback(
                bio,
                BIO_CB_WRITE | BIO_CB_RETURN,
                data.cast(),
                dlen,
                0,
                0,
                ret as c_long,
                &mut local_written,
            )
        } as c_int;
    }
    if !written.is_null() {
        // SAFETY: `written` is non-NULL and writable.
        unsafe { *written = local_written };
    }
    ret
}

/// `int BIO_write(BIO *b, const void *data, int dlen)`
///
/// A non-positive `dlen` is `0` — including zero, which never reaches the method.
#[no_mangle]
pub unsafe extern "C" fn BIO_write(bio: *mut Bio, data: *const c_void, dlen: c_int) -> c_int {
    guard_ffi(0, || {
        if dlen <= 0 {
            return 0;
        }
        let mut written: usize = 0;
        // SAFETY: `bio` is NULL or live; `data` is valid for `dlen` bytes.
        let mut ret = unsafe { bio_write_intern(bio, data, dlen as usize, &mut written) };
        if ret > 0 {
            ret = written as c_int;
        }
        ret
    })
}

/// `int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written)`
///
/// Returns 1 on success. A NULL `b` combined with `dlen == 0` is *success*, and
/// the order of the two tests is deliberate: `*written` must still be zeroed even
/// when `b` is NULL.
#[no_mangle]
pub unsafe extern "C" fn BIO_write_ex(
    bio: *mut Bio,
    data: *const c_void,
    dlen: usize,
    written: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the out-parameter contract is the
        // method's.
        let ret = unsafe { bio_write_intern(bio, data, dlen, written) };
        (ret > 0 || (!bio.is_null() && dlen == 0)) as c_int
    })
}

/// `int BIO_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg,
/// uint64_t flags, size_t *msgs_processed)`
#[no_mangle]
pub unsafe extern "C" fn BIO_sendmmsg(
    bio: *mut Bio,
    msg: *mut BioMsg,
    stride: usize,
    num_msg: usize,
    flags: u64,
    msgs_processed: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `msgs_processed` is a caller-supplied out-parameter; the
        // authority writes it unconditionally on the early exits.
        if !msgs_processed.is_null() {
            unsafe { *msgs_processed = 0 };
        } else {
            return 0;
        }
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_399) };
            return 0;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(m) = (unsafe { b.method.as_ref() }) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_405) };
            return 0;
        };
        let Some(send) = m.sendmmsg else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_405) };
            return 0;
        };
        let mut args = super::BioMmsgCbArgs {
            msg,
            stride,
            num_msg,
            flags,
            msgs_processed,
        };
        if unsafe { has_callback(bio) } {
            // SAFETY: the message-array callback contract passes `args` as the
            // opaque `argp`.
            let ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_SENDMMSG,
                    (&mut args as *mut super::BioMmsgCbArgs).cast(),
                    0,
                    0,
                    0,
                    1,
                    ptr::null_mut(),
                )
            };
            if ret <= 0 {
                return 0;
            }
        }
        if b.init == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_424) };
            return 0;
        }
        // SAFETY: the method's mmsg contract is to process at most `num_msg`
        // entries and report how many through `msgs_processed`.
        let mut ret = unsafe { send(bio, msg, stride, num_msg, flags, msgs_processed) };
        if unsafe { has_callback(bio) } {
            // SAFETY: on the return leg `processed` is an in/out byte count; the
            // mmsg callback uses the message count in `ret` instead.
            ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_SENDMMSG | BIO_CB_RETURN,
                    (&mut args as *mut super::BioMmsgCbArgs).cast(),
                    0,
                    0,
                    0,
                    ret as c_long,
                    msgs_processed,
                )
            } as c_int;
        }
        (ret > 0) as c_int
    })
}

/// `int BIO_recvmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg,
/// uint64_t flags, size_t *msgs_processed)`
#[no_mangle]
pub unsafe extern "C" fn BIO_recvmmsg(
    bio: *mut Bio,
    msg: *mut BioMsg,
    stride: usize,
    num_msg: usize,
    flags: u64,
    msgs_processed: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `msgs_processed` is a caller-supplied out-parameter.
        if !msgs_processed.is_null() {
            unsafe { *msgs_processed = 0 };
        } else {
            return 0;
        }
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_446) };
            return 0;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(recv) = (unsafe { b.method.as_ref() }).and_then(|m| m.recvmmsg) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_452) };
            return 0;
        };
        let mut args = super::BioMmsgCbArgs {
            msg,
            stride,
            num_msg,
            flags,
            msgs_processed,
        };
        if unsafe { has_callback(bio) } {
            // SAFETY: as for `BIO_sendmmsg`.
            let ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_RECVMMSG,
                    (&mut args as *mut super::BioMmsgCbArgs).cast(),
                    0,
                    0,
                    0,
                    1,
                    ptr::null_mut(),
                )
            };
            if ret <= 0 {
                return 0;
            }
        }
        if b.init == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_471) };
            return 0;
        }
        // SAFETY: the method's mmsg contract, as for `BIO_sendmmsg`.
        let mut ret = unsafe { recv(bio, msg, stride, num_msg, flags, msgs_processed) };
        if unsafe { has_callback(bio) } {
            // SAFETY: as for `BIO_sendmmsg`.
            ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_RECVMMSG | BIO_CB_RETURN,
                    (&mut args as *mut super::BioMmsgCbArgs).cast(),
                    0,
                    0,
                    0,
                    ret as c_long,
                    msgs_processed,
                )
            } as c_int;
        }
        (ret > 0) as c_int
    })
}

/// `int BIO_puts(BIO *b, const char *buf)`
///
/// Returns the number of bytes written (not a flag) so that `BIO_puts` and
/// `BIO_write` are interchangeable at a call site.
#[no_mangle]
pub unsafe extern "C" fn BIO_puts(bio: *mut Bio, buf: *const c_char) -> c_int {
    guard_ffi(-1, || {
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_500) };
            return -1;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(bputs) = (unsafe { b.method.as_ref() }).and_then(|m| m.bputs) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_504) };
            return -2;
        };
        if unsafe { has_callback(bio) } {
            // SAFETY: `BIO_CB_PUTS` carries no processed byte count.
            let ret =
                unsafe { bio_call_callback(bio, BIO_CB_PUTS, buf, 0, 0, 0, 1, ptr::null_mut()) };
            if ret <= 0 {
                return ret as c_int;
            }
        }
        if b.init == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_515) };
            return -1;
        }
        // SAFETY: the method writes the NUL-terminated string at `buf`.
        let mut ret = unsafe { bputs(bio, buf) };
        let mut written: usize = 0;
        if ret > 0 {
            b.num_write += ret as u64;
            written = ret as usize;
            ret = 1;
        }
        if unsafe { has_callback(bio) } {
            // SAFETY: the return leg receives the byte count through `written`.
            ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_PUTS | BIO_CB_RETURN,
                    buf,
                    0,
                    0,
                    0,
                    ret as c_long,
                    &mut written,
                )
            } as c_int;
        }
        if ret > 0 {
            if written as c_long > INT_MAX {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&BIO_LIB_533) };
                return -1;
            }
            return written as c_int;
        }
        ret
    })
}

/// `int BIO_gets(BIO *b, char *buf, int size)`
#[no_mangle]
pub unsafe extern "C" fn BIO_gets(bio: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    guard_ffi(-1, || {
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_549) };
            return -1;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(bgets) = (unsafe { b.method.as_ref() }).and_then(|m| m.bgets) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_553) };
            return -2;
        };
        if size < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_558) };
            return -1;
        }
        if unsafe { has_callback(bio) } {
            // SAFETY: `BIO_CB_GETS` carries the buffer length in `len`.
            let ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_GETS,
                    buf,
                    size as usize,
                    0,
                    0,
                    1,
                    ptr::null_mut(),
                )
            };
            if ret <= 0 {
                return ret as c_int;
            }
        }
        if b.init == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_569) };
            return -1;
        }
        // SAFETY: the method fills at most `size` bytes at `buf`.
        let mut ret = unsafe { bgets(bio, buf, size) };
        let mut readbytes: usize = 0;
        if ret > 0 {
            readbytes = ret as usize;
            ret = 1;
        }
        if unsafe { has_callback(bio) } {
            // SAFETY: the return leg receives the byte count through `readbytes`.
            ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_GETS | BIO_CB_RETURN,
                    buf,
                    size as usize,
                    0,
                    0,
                    ret as c_long,
                    &mut readbytes,
                )
            } as c_int;
        }
        if ret > 0 {
            if readbytes > size as usize {
                return -1;
            }
            return readbytes as c_int;
        }
        ret
    })
}

/// `int BIO_get_line(BIO *bio, char *buf, int size)`
///
/// Reads one byte at a time until `\n` or the buffer is full, so it works over
/// any BIO — including one whose method has no `gets`. On EOF it returns the
/// bytes accumulated so far rather than the negative class, which is what makes
/// it usable as a line reader.
#[no_mangle]
pub unsafe extern "C" fn BIO_get_line(bio: *mut Bio, buf: *mut c_char, size: c_int) -> c_int {
    guard_ffi(-1, || {
        if buf.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_601) };
            return -1;
        }
        if size <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_605) };
            return -1;
        }
        // SAFETY: `buf` is non-NULL and `size > 0`, so the first byte is writable.
        unsafe { *buf = 0 };
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_611) };
            return -1;
        }
        // SAFETY: `bio` is non-NULL and live.
        if unsafe { (*bio).init } == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_615) };
            return -1;
        }
        let mut ret: c_int = 0;
        let mut ptr = buf;
        let mut remaining = size;
        while {
            remaining -= 1;
            remaining > 0
        } {
            // SAFETY: `ptr` addresses the caller's buffer, which holds at least
            // `remaining + 1` writable bytes by the loop invariant.
            ret = unsafe { BIO_read(bio, ptr.cast(), 1) };
            if ret <= 0 {
                break;
            }
            // SAFETY: `ptr` is within the caller's buffer.
            let c = unsafe { *ptr };
            ptr = unsafe { ptr.add(1) };
            if c == b'\n' as c_char {
                break;
            }
        }
        // SAFETY: `ptr` addresses the terminating byte position within `buf`.
        unsafe { *ptr = 0 };
        if ret > 0 {
            return (ptr as usize - buf as usize) as c_int;
        }
        // SAFETY: `BIO_eof` is `BIO_ctrl(bio, BIO_CTRL_EOF, 0, NULL)`.
        let eof = unsafe { BIO_ctrl(bio, BIO_CTRL_EOF, 0, ptr::null_mut()) };
        if eof != 0 {
            (ptr as usize - buf as usize) as c_int
        } else {
            ret
        }
    })
}

/// `long BIO_int_ctrl(BIO *b, int cmd, long larg, int iarg)`
///
/// Passes the `int` argument by address, which is how file-descriptor and
/// buffer-size controls receive it.
#[no_mangle]
pub unsafe extern "C" fn BIO_int_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    larg: c_long,
    iarg: c_int,
) -> c_long {
    guard_ffi(-1, || {
        let mut i = iarg;
        // SAFETY: `i` is a live local; `BIO_ctrl` may read it through `parg`.
        unsafe { BIO_ctrl(bio, cmd, larg, (&mut i as *mut c_int).cast()) }
    })
}

/// `void *BIO_ptr_ctrl(BIO *b, int cmd, long larg)`
///
/// Returns the pointer the control produced, or NULL when the control reported
/// failure.
#[no_mangle]
pub unsafe extern "C" fn BIO_ptr_ctrl(bio: *mut Bio, cmd: c_int, larg: c_long) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let mut p: *mut c_void = ptr::null_mut();
        // SAFETY: `p` is a live local; `BIO_ctrl` may write it through `parg`.
        if unsafe { BIO_ctrl(bio, cmd, larg, (&mut p as *mut *mut c_void).cast()) } <= 0 {
            ptr::null_mut()
        } else {
            p
        }
    })
}

/// `long BIO_ctrl(BIO *b, int cmd, long larg, void *parg)`
///
/// A NULL BIO is `-1`; a method without a `ctrl` is `-2` with an `ERR`. Those
/// differ from each other and from a control that legitimately returns 0, so the
/// classes are reproduced rather than collapsed.
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    guard_ffi(-1, || {
        if bio.is_null() {
            return -1;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(ctrl) = (unsafe { b.method.as_ref() }).and_then(|m| m.ctrl) else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_663) };
            return -2;
        };
        if unsafe { has_callback(bio) } {
            // SAFETY: `BIO_CB_CTRL` passes the control argument and the command
            // in `argi`.
            let ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_CTRL,
                    parg.cast(),
                    0,
                    cmd,
                    larg,
                    1,
                    ptr::null_mut(),
                )
            };
            if ret <= 0 {
                return ret;
            }
        }
        // SAFETY: the method's control contract; `parg` is as the command says.
        let ret = unsafe { ctrl(bio, cmd, larg, parg) };
        if unsafe { has_callback(bio) } {
            // SAFETY: the return leg, as above.
            return unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_CTRL | BIO_CB_RETURN,
                    parg.cast(),
                    0,
                    cmd,
                    larg,
                    ret,
                    ptr::null_mut(),
                )
            };
        }
        ret
    })
}

/// `long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp)`
///
/// Only `BIO_CTRL_SET_CALLBACK` is meaningful; every other command is reported
/// as unsupported, matching the authority's guard.
#[no_mangle]
pub unsafe extern "C" fn BIO_callback_ctrl(
    bio: *mut Bio,
    cmd: c_int,
    fp: *mut BioInfoCb,
) -> c_long {
    guard_ffi(-2, || {
        if bio.is_null() {
            return -2;
        }
        // SAFETY: `bio` is non-NULL and live.
        let b = unsafe { &mut *bio };
        let Some(callback_ctrl) = (unsafe { b.method.as_ref() }).and_then(|m| m.callback_ctrl)
        else {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_690) };
            return -2;
        };
        if cmd != super::BIO_CTRL_SET_CALLBACK {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_690) };
            return -2;
        }
        if unsafe { has_callback(bio) } {
            // SAFETY: the control callback receives the address of the function
            // pointer, as the authority passes it.
            let ret = unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_CTRL,
                    (&fp as *const *mut BioInfoCb).cast(),
                    0,
                    cmd,
                    0,
                    1,
                    ptr::null_mut(),
                )
            };
            if ret <= 0 {
                return ret;
            }
        }
        // SAFETY: the method's callback-control contract.
        let ret = unsafe { callback_ctrl(bio, cmd, fp) };
        if unsafe { has_callback(bio) } {
            // SAFETY: the return leg, as above.
            return unsafe {
                bio_call_callback(
                    bio,
                    BIO_CB_CTRL | BIO_CB_RETURN,
                    (&fp as *const *mut BioInfoCb).cast(),
                    0,
                    cmd,
                    0,
                    ret,
                    ptr::null_mut(),
                )
            };
        }
        ret
    })
}

/// `size_t BIO_ctrl_pending(BIO *bio)`
///
/// Clamps a negative control result to zero, which is why a caller cannot use it
/// to detect "unsupported": that information lives in the return type of
/// [`BIO_ctrl`], not here.
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_pending(bio: *mut Bio) -> usize {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; `BIO_CTRL_PENDING` takes no argument.
        let ret = unsafe { BIO_ctrl(bio, BIO_CTRL_PENDING, 0, ptr::null_mut()) };
        if ret < 0 {
            0
        } else {
            ret as usize
        }
    })
}

/// `size_t BIO_ctrl_wpending(BIO *bio)`
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_wpending(bio: *mut Bio) -> usize {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; `BIO_CTRL_WPENDING` takes no argument.
        let ret = unsafe { BIO_ctrl(bio, BIO_CTRL_WPENDING, 0, ptr::null_mut()) };
        if ret < 0 {
            0
        } else {
            ret as usize
        }
    })
}

/// `size_t BIO_ctrl_get_write_guarantee(BIO *b)`
///
/// The BIO-pair and datagram-pair controls report how much can be written without
/// blocking; the value is clamped at zero for the same reason as `pending`.
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_get_write_guarantee(bio: *mut Bio) -> usize {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live.
        let ret = unsafe { BIO_ctrl(bio, super::BIO_CTRL_GET_WRITE_GUARANTEE, 0, ptr::null_mut()) };
        if ret < 0 {
            0
        } else {
            ret as usize
        }
    })
}

/// `size_t BIO_ctrl_get_read_request(BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_get_read_request(bio: *mut Bio) -> usize {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live.
        let ret = unsafe { BIO_ctrl(bio, super::BIO_CTRL_GET_READ_REQUEST, 0, ptr::null_mut()) };
        if ret < 0 {
            0
        } else {
            ret as usize
        }
    })
}

/// `int BIO_ctrl_reset_read_request(BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_ctrl_reset_read_request(bio: *mut Bio) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live.
        unsafe { BIO_ctrl(bio, super::BIO_CTRL_RESET_READ_REQUEST, 0, ptr::null_mut()) as c_int }
    })
}

/// `int BIO_nread0(BIO *bio, char **buf)`
#[no_mangle]
pub unsafe extern "C" fn BIO_nread0(bio: *mut Bio, buf: *mut *mut c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; `BIO_C_NREAD0` writes `*buf`.
        unsafe { BIO_ctrl(bio, super::BIO_C_NREAD0, 0, buf.cast()) as c_int }
    })
}

/// `int BIO_nread(BIO *bio, char **buf, int num)`
#[no_mangle]
pub unsafe extern "C" fn BIO_nread(bio: *mut Bio, buf: *mut *mut c_char, num: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the control may write `*buf`.
        unsafe { BIO_ctrl(bio, super::BIO_C_NREAD, num as c_long, buf.cast()) as c_int }
    })
}

/// `int BIO_nwrite0(BIO *bio, char **buf)`
#[no_mangle]
pub unsafe extern "C" fn BIO_nwrite0(bio: *mut Bio, buf: *mut *mut c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; `BIO_C_NWRITE0` writes `*buf`.
        unsafe { BIO_ctrl(bio, super::BIO_C_NWRITE0, 0, buf.cast()) as c_int }
    })
}

/// `int BIO_nwrite(BIO *bio, char **buf, int num)`
#[no_mangle]
pub unsafe extern "C" fn BIO_nwrite(bio: *mut Bio, buf: *mut *mut c_char, num: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the control may write `*buf`.
        unsafe { BIO_ctrl(bio, super::BIO_C_NWRITE, num as c_long, buf.cast()) as c_int }
    })
}

/// `int BIO_get_rpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_rpoll_descriptor(
    bio: *mut Bio,
    desc: *mut super::BioPollDescriptor,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the control fills `desc`.
        unsafe { BIO_ctrl(bio, BIO_CTRL_GET_RPOLL_DESCRIPTOR, 0, desc.cast()) as c_int }
    })
}

/// `int BIO_get_wpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_wpoll_descriptor(
    bio: *mut Bio,
    desc: *mut super::BioPollDescriptor,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `bio` is NULL or live; the control fills `desc`.
        unsafe { BIO_ctrl(bio, BIO_CTRL_GET_WPOLL_DESCRIPTOR, 0, desc.cast()) as c_int }
    })
}

/// `int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds)`
///
/// Returns 1 immediately when `max_time` is 0 (no timeout). Otherwise it waits on
/// the BIO's descriptor when it has one, and otherwise naps, reporting `-1`/`0`
/// with an `ERR` for error and timeout respectively.
#[no_mangle]
pub unsafe extern "C" fn BIO_wait(bio: *mut Bio, max_time: c_long, nap_milliseconds: u32) -> c_int {
    guard_ffi(-1, || {
        let rv = unsafe { bio_wait(bio, max_time, nap_milliseconds) };
        if rv <= 0 {
            // The authority raises one of two constants depending on whether the
            // wait timed out or failed; both are recorded as dynamic sites
            // because the choice is made at run time.
            let reason = if rv == 0 {
                super::BIO_R_TRANSFER_TIMEOUT
            } else {
                super::BIO_R_TRANSFER_ERROR
            };
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site_dynamic(&BIO_LIB_1002, reason) };
        }
        rv
    })
}

/// The authority's `static int bio_wait`.
///
/// # Safety
/// `bio` must be NULL or a live BIO.
unsafe fn bio_wait(bio: *mut Bio, max_time: c_long, nap_milliseconds: u32) -> c_int {
    if max_time == 0 {
        return 1;
    }
    let mut fd: c_int = 0;
    // `BIO_get_fd(b, &fd)` walks the chain looking for a BIO with a descriptor.
    // SAFETY: `fd` is a live local that the control may write.
    if unsafe { BIO_ctrl(bio, super::BIO_C_GET_FD, 0, (&mut fd as *mut c_int).cast()) } > 0 {
        // SAFETY: `BIO_should_read` is a flag test on a live BIO.
        let for_read = unsafe { super::BIO_test_flags(bio, super::BIO_FLAGS_READ) };
        // SAFETY: `fd` is a descriptor obtained from this BIO.
        let ret = unsafe { super::bss_sock::BIO_socket_wait(fd, for_read, max_time) };
        if ret != -1 {
            return ret;
        }
    }
    // SAFETY: `time` takes a `time_t *`; passing NULL asks for the current time.
    let now = unsafe { super::sys::time(ptr::null_mut()) };
    let sec_diff = max_time.saturating_sub(now);
    if sec_diff < 0 {
        return 0;
    }
    let mut nap = nap_milliseconds;
    if sec_diff == 0 {
        if nap > 1000 {
            nap = 1000;
        }
    } else if (sec_diff as u64) * 1000 < nap as u64 {
        nap = (sec_diff as u64 * 1000) as u32;
    }
    // SAFETY: `usleep` is a plain libc call.
    unsafe { super::sys::usleep(nap) };
    1
}

/// `int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds)`
///
/// `timeout == 0` means "blocking, no retry loop"; a negative `timeout` means
/// "one attempt only". The two cases differ in whether `BIO_set_nbio` is applied
/// and whether `bio_wait` is entered, so they are distinguished explicitly.
#[no_mangle]
pub unsafe extern "C" fn BIO_do_connect_retry(
    bio: *mut Bio,
    timeout: c_int,
    nap_milliseconds: c_int,
) -> c_int {
    guard_ffi(-1, || {
        let blocking = timeout <= 0;
        // SAFETY: `time` takes a `time_t *`; NULL asks for the current time.
        let max_time = if timeout > 0 {
            (unsafe { super::sys::time(ptr::null_mut()) }) + timeout as c_long
        } else {
            0
        };
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_site(&BIO_LIB_1022) };
            return -1;
        }
        let nap = if nap_milliseconds < 0 {
            100
        } else {
            nap_milliseconds
        };
        // `BIO_set_nbio(bio, !blocking)` is `BIO_ctrl(bio, BIO_C_SET_NBIO, ...)`.
        // SAFETY: `bio` is non-NULL and live.
        unsafe {
            BIO_ctrl(
                bio,
                super::BIO_C_SET_NBIO,
                (!blocking) as c_long,
                ptr::null_mut(),
            )
        };
        loop {
            // SAFETY: mark/peek/pop are the ERR queue's own interfaces.
            unsafe { crate::runtime::err::ERR_set_mark() };
            // `BIO_do_connect(bio)` is `BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, NULL)`.
            // SAFETY: `bio` is live.
            let mut rv = unsafe { BIO_ctrl(bio, super::BIO_C_DO_STATE_MACHINE, 0, ptr::null_mut()) }
                as c_int;
            if rv <= 0 {
                // SAFETY: the ERR queue is thread-local and initialised here.
                let err = unsafe { crate::runtime::err::ERR_peek_last_error() };
                let reason = (err & 0x00ff_ffff) as c_int;
                // SAFETY: `BIO_should_retry` is a flag test.
                let mut do_retry =
                    unsafe { super::BIO_test_flags(bio, BIO_FLAGS_SHOULD_RETRY) } != 0;
                let lib = ((err >> 23) & 0xff) as c_int;
                if lib == super::BIO_LIB_CODE {
                    // `ERR_R_SYS_LIB` and the two connect-error reasons are the
                    // retryable classes; the authority resets the BIO before
                    // retrying so a half-open socket can be reused.
                    if reason == super::ERR_R_SYS_LIB
                        || reason == super::BIO_R_CONNECT_ERROR
                        || reason == super::BIO_R_NBIO_CONNECT_ERROR
                    {
                        // SAFETY: `BIO_reset` is a control on a live BIO.
                        unsafe { BIO_ctrl(bio, super::BIO_CTRL_RESET, 0, ptr::null_mut()) };
                        do_retry = true;
                    }
                }
                if timeout >= 0 && do_retry {
                    // SAFETY: the mark was set above on this thread.
                    unsafe { crate::runtime::err::ERR_pop_to_mark() };
                    // SAFETY: `bio` is live.
                    rv = unsafe { bio_wait(bio, max_time, nap as u32) };
                    if rv > 0 {
                        continue;
                    }
                    let reason = if rv == 0 {
                        super::BIO_R_CONNECT_TIMEOUT
                    } else {
                        super::BIO_R_CONNECT_ERROR
                    };
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site_dynamic(&BIO_LIB_1064, reason) };
                    return rv;
                }
                // SAFETY: the mark was set above on this thread.
                unsafe { crate::runtime::err::ERR_clear_last_mark() };
                rv = -1;
                if err == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&BIO_LIB_1071) };
                }
                return rv;
            }
            // SAFETY: the mark was set above on this thread.
            unsafe { crate::runtime::err::ERR_clear_last_mark() };
            return rv;
        }
    })
}

/// `int BIO_find_type` is in `mod.rs`; these are the remaining libcrypto-lib
/// helpers that live beside the dispatch layer rather than in a method module.
/// They are re-exported here so the module boundary matches the authority's
/// `bio_lib.c` split.
pub use super::{BIO_find_type, BIO_pop, BIO_push};
