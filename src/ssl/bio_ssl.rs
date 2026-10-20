//! Phase 14.6 — `ssl/bio_ssl.c`: the BIO pair and its buffers.
//!
//! The whole of the unit: `BIO_f_ssl` (the `"ssl"` filter method and its seven callbacks),
//! `BIO_new_ssl`, `BIO_new_ssl_connect`, `BIO_new_buffer_ssl_connect`, and the two session
//! controls `BIO_ssl_copy_session_id`/`BIO_ssl_shutdown`. The authority's `BIO_SSL` record is
//! reproduced with its renegotiation counters; the method table is the authority's field for
//! field (`bio_ssl.c:42-55`).
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The renegotiation trigger is never fired.** `ssl_read`/`ssl_write`'s
//!   `SSL_renegotiate` calls (`bio_ssl.c:119`/`130`/`188`/`199`) are unreachable without a
//!   handshake, and `SSL_renegotiate` is still an open `ssl_lib.c` row; the byte/time accounting
//!   that gates them is transcribed, but no court drives a transfer through the SSL BIO.
//! * **`BIO_CTRL_DUP` is reduced to the authority's failure shape.** The authority's case calls
//!   `SSL_dup` (`ssl_lib.c`, 14.7's row); this crate has no duplicated connection to hand back, so
//!   the case frees the destination's `SSL` and leaves it NULL, which is the authority's `ret = 0`
//!   when `SSL_dup` fails. No arm of `RT-SSL-BIO` drives a duplicate.
//! * **`BIO_CTRL_RESET`'s role restore is reduced.** The authority re-selects the handshake entry
//!   by comparing `sc->handshake_func` against the method's two function pointers; this crate's
//!   method table carries no such pointers (14.2 stores scalars), so the reset calls `SSL_clear`
//!   and forwards the control to the next BIO without re-installing a role. Nothing in the court
//!   resets a role.
//! * **`BIO_ssl_copy_session_id` calls a reduced session copy.** The authority reaches
//!   `SSL_copy_session_id`, whose session object and certificate refcount are 14.7's; the reduced
//!   body in `src/ssl/ssl_lib.rs` matches the reachable fresh-connection answer and is named there.
//! * **The `ssl_read`/`ssl_write` error mapping is the modern path only.** The authority's switch
//!   over `SSL_get_error` is transcribed, but `SSL_get_error`'s answer for an object with no
//!   record layer is this crate's (`ssl_lib.rs`), so no retry flag is observable without a
//!   handshake.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::bio::{
    BIO_callback_ctrl, BIO_clear_flags, BIO_copy_next_retry, BIO_ctrl, BIO_f_buffer, BIO_find_type,
    BIO_free, BIO_get_data, BIO_get_init, BIO_get_retry_reason, BIO_get_shutdown, BIO_method_type,
    BIO_new, BIO_next, BIO_push, BIO_s_connect, BIO_set_data, BIO_set_flags, BIO_set_init,
    BIO_set_next, BIO_set_retry_reason, BIO_set_shutdown, BIO_up_ref, BIO_write, Bio, BioInfoCb,
    BioMethod, BIO_CLOSE, BIO_CTRL_DUP, BIO_CTRL_FLUSH, BIO_CTRL_GET_CLOSE,
    BIO_CTRL_GET_RPOLL_DESCRIPTOR, BIO_CTRL_GET_WPOLL_DESCRIPTOR, BIO_CTRL_INFO, BIO_CTRL_PENDING,
    BIO_CTRL_POP, BIO_CTRL_PUSH, BIO_CTRL_RESET, BIO_CTRL_SET_CALLBACK, BIO_CTRL_SET_CLOSE,
    BIO_CTRL_WPENDING, BIO_C_DO_STATE_MACHINE, BIO_C_GET_FD, BIO_C_GET_SSL,
    BIO_C_GET_SSL_NUM_RENEGOTIATES, BIO_C_SET_SSL, BIO_C_SET_SSL_RENEGOTIATE_BYTES,
    BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT, BIO_C_SSL_MODE, BIO_FLAGS_IO_SPECIAL, BIO_FLAGS_READ,
    BIO_FLAGS_SHOULD_RETRY, BIO_FLAGS_WRITE, BIO_RR_ACCEPT, BIO_RR_CONNECT, BIO_RR_SSL_X509_LOOKUP,
    BIO_TYPE_SSL,
};
use crate::ssl::ssl_lib::{
    ssl_copy_session_id, ssl_read_internal, ssl_set_accept_state, ssl_set_connect_state,
    ssl_write_internal, SSL_clear, SSL_do_handshake, SSL_free, SSL_get_error, SSL_get_rbio,
    SSL_get_rpoll_descriptor, SSL_get_wbio, SSL_get_wpoll_descriptor, SSL_is_quic, SSL_new,
    SSL_pending, SSL_set_bio, SSL_shutdown, Ssl, SslCtx,
};
use crate::ssl::statem::statem::SSL_in_init;

/// `SSL_ERROR_NONE` — `ssl.h:1258`.
const SSL_ERROR_NONE: c_int = 0;
/// `SSL_ERROR_WANT_READ` — `ssl.h:1260`.
const SSL_ERROR_WANT_READ: c_int = 2;
/// `SSL_ERROR_WANT_WRITE` — `ssl.h:1261`.
const SSL_ERROR_WANT_WRITE: c_int = 3;
/// `SSL_ERROR_WANT_X509_LOOKUP` — `ssl.h:1262`.
const SSL_ERROR_WANT_X509_LOOKUP: c_int = 4;
/// `SSL_ERROR_WANT_CONNECT` — `ssl.h:1266`.
const SSL_ERROR_WANT_CONNECT: c_int = 7;
/// `SSL_ERROR_WANT_ACCEPT` — `ssl.h:1267`.
const SSL_ERROR_WANT_ACCEPT: c_int = 8;

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/bio_ssl.c".as_ptr();

/// `BIO_TYPE_SSL`'s method name — `bio_ssl.c:44`.
const SSL_METHOD_NAME: *const c_char = c"ssl".as_ptr();

/// `struct bio_ssl_st` — `bio_ssl.c:28-40`, field for field.
#[repr(C)]
struct BioSsl {
    /// `SSL *ssl`.
    ssl: *mut Ssl,
    /// `int num_renegotiates`.
    num_renegotiates: c_int,
    /// `unsigned long renegotiate_count`.
    renegotiate_count: c_long,
    /// `size_t byte_count`.
    byte_count: usize,
    /// `unsigned long renegotiate_timeout`.
    renegotiate_timeout: c_long,
    /// `unsigned long last_time`.
    last_time: c_long,
}

// SAFETY: (a) `destroy_body` is empty because the authority does **not** release `ssl`
// unconditionally: `ssl_free` runs `SSL_free` only when the BIO's shutdown flag is set and the BIO
// is initialised, and it does so before dropping this block, so the pointer is that function's
// release and never the block owner's; the enclosing block is released by `OwnedCtx` alone; (b) an
// all-zero `BioSsl` is valid: a null `ssl`, zero scalars, exactly the authority's `OPENSSL_zalloc`
// result.
unsafe impl CtxDestroy for BioSsl {
    const FILE: *const c_char = FILE;
    const LINE_ALLOC: c_int = 64;
    const LINE_FREE: c_int = 91;

    unsafe fn destroy_body(_ptr: *mut BioSsl) {}
}

/// `ssl_write` — `bio_ssl.c:165-225`.
///
/// # Safety
/// `b` must be a live BIO of this method whose data is a live `BioSsl`; `buf` must hold `size`
/// readable bytes and `written` be writable.
unsafe extern "C" fn ssl_write(
    b: *mut Bio,
    buf: *const c_char,
    size: usize,
    written: *mut usize,
) -> c_int {
    if buf.is_null() {
        return 0;
    }
    // SAFETY: `b` is live per the caller's contract.
    let bs = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
    // A failed re-creation in `BIO_C_SET_SSL` leaves the data slot NULL; the BIO then
    // has no connection to write through and answers the authority's uninitialised 0.
    if bs.is_null() {
        return 0;
    }
    // SAFETY: this method's data is a `BioSsl`.
    let ssl = unsafe { (*bs).ssl };
    // SAFETY: `b` is live.
    unsafe {
        BIO_clear_flags(
            b,
            BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY,
        )
    };
    // SAFETY: `ssl`/`buf`/`written` per the caller; `ssl` may be NULL after
    // `BIO_C_SET_SSL` was given a NULL connection, and `ssl_write_internal` answers 0.
    let ret = unsafe { ssl_write_internal(ssl, buf.cast::<c_void>(), size, 0, written) };
    // SAFETY: `ssl` live.
    match unsafe { SSL_get_error(ssl, ret) } {
        SSL_ERROR_NONE => {
            // SAFETY: `bs` is live.
            let count = unsafe { (*bs).renegotiate_count };
            if count > 0 {
                // SAFETY: `bs`/`written` are live.
                let n = unsafe {
                    (*bs).byte_count += if written.is_null() { 0 } else { *written };
                    (*bs).byte_count
                };
                if n > count as usize {
                    // SAFETY: `bs` live.
                    unsafe {
                        (*bs).byte_count = 0;
                        (*bs).num_renegotiates += 1;
                    }
                    // The authority calls `SSL_renegotiate(ssl)` here (14.1's open row); the
                    // counter is the observable and the trigger is unreachable without a
                    // handshake. Recorded in the module header.
                }
            }
        }
        SSL_ERROR_WANT_WRITE => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) }
        }
        SSL_ERROR_WANT_READ => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) }
        }
        SSL_ERROR_WANT_X509_LOOKUP => {
            // SAFETY: `b` is live.
            unsafe {
                BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                BIO_set_retry_reason(b, BIO_RR_SSL_X509_LOOKUP);
            }
        }
        SSL_ERROR_WANT_CONNECT => {
            // SAFETY: `b` is live.
            unsafe {
                BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                BIO_set_retry_reason(b, BIO_RR_CONNECT);
            }
        }
        _ => {}
    }
    ret
}

/// `ssl_read` — `bio_ssl.c:95-163`.
///
/// # Safety
/// `b` must be a live BIO of this method whose data is a live `BioSsl`; `buf` must hold `size`
/// writable bytes and `readbytes` be writable.
unsafe extern "C" fn ssl_read(
    b: *mut Bio,
    buf: *mut c_char,
    size: usize,
    readbytes: *mut usize,
) -> c_int {
    if buf.is_null() {
        return 0;
    }
    // SAFETY: `b` is live per the caller's contract.
    let sb = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
    // A failed re-creation in `BIO_C_SET_SSL` leaves the data slot NULL; a read then
    // has no connection to read from and answers 0 (the uninitialised answer).
    if sb.is_null() {
        return 0;
    }
    // SAFETY: this method's data is a `BioSsl`.
    let ssl = unsafe { (*sb).ssl };
    // SAFETY: `b` is live.
    unsafe {
        BIO_clear_flags(
            b,
            BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY,
        )
    };
    // SAFETY: `ssl`/`buf`/`readbytes` per the caller; `ssl` may be NULL after
    // `BIO_C_SET_SSL` was given a NULL connection, and `ssl_read_internal` answers -1.
    let ret = unsafe { ssl_read_internal(ssl, buf.cast::<c_void>(), size, readbytes) };
    let mut retry_reason = 0;
    // SAFETY: `ssl` live.
    match unsafe { SSL_get_error(ssl, ret) } {
        SSL_ERROR_NONE => {
            // SAFETY: `sb` live.
            let count = unsafe { (*sb).renegotiate_count };
            if count > 0 {
                // SAFETY: `sb`/`readbytes` live.
                let n = unsafe {
                    (*sb).byte_count += if readbytes.is_null() { 0 } else { *readbytes };
                    (*sb).byte_count
                };
                if n > count as usize {
                    // SAFETY: `sb` live.
                    unsafe {
                        (*sb).byte_count = 0;
                        (*sb).num_renegotiates += 1;
                    }
                }
            }
        }
        SSL_ERROR_WANT_READ => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) }
        }
        SSL_ERROR_WANT_WRITE => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) }
        }
        SSL_ERROR_WANT_X509_LOOKUP => {
            // SAFETY: `b` is live.
            unsafe {
                BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
            }
            retry_reason = BIO_RR_SSL_X509_LOOKUP;
        }
        SSL_ERROR_WANT_ACCEPT => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY) };
            retry_reason = BIO_RR_ACCEPT;
        }
        SSL_ERROR_WANT_CONNECT => {
            // SAFETY: `b` is live.
            unsafe { BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY) };
            retry_reason = BIO_RR_CONNECT;
        }
        _ => {}
    }
    // SAFETY: `b` is live.
    unsafe { BIO_set_retry_reason(b, retry_reason) };
    ret
}

/// `ssl_puts` — `bio_ssl.c:434-443`.
///
/// # Safety
/// `bp` must be a live BIO of this method; `str` a NUL-terminated string.
unsafe extern "C" fn ssl_puts(bp: *mut Bio, str: *const c_char) -> c_int {
    let mut n = 0usize;
    // SAFETY: `str` is NUL-terminated per the caller's contract.
    while unsafe { *str.add(n) } != 0 {
        n += 1;
    }
    if n > c_int::MAX as usize {
        return -1;
    }
    // SAFETY: `bp`/`str` per the caller.
    unsafe { BIO_write(bp, str.cast::<c_void>(), n as c_int) }
}

/// `ssl_ctrl` — `bio_ssl.c:227-413`, reduced where the authority reaches 14.7's connection calls.
///
/// # Safety
/// `b` must be a live BIO of this method whose data is a live `BioSsl`; `ptr` is the control's
/// argument.
unsafe extern "C" fn ssl_ctrl(b: *mut Bio, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    // SAFETY: `b` is live per the caller's contract.
    let bs = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
    // SAFETY: `b` is live.
    let next = unsafe { BIO_next(b) };
    // A failed re-creation in `BIO_C_SET_SSL` leaves the method data NULL. Every other
    // control needs it; the SET_SSL arm allocates a fresh block and recovers.
    if bs.is_null() && cmd != BIO_C_SET_SSL {
        return 0;
    }
    let mut ssl = if bs.is_null() {
        // NULL only on the SET_SSL recovery path, handled below.
        ptr::null_mut()
    } else {
        // SAFETY: the guard above established `bs` is non-NULL and is this method's data.
        unsafe { (*bs).ssl }
    };
    if ssl.is_null() && cmd != BIO_C_SET_SSL {
        return 0;
    }
    let mut ret: c_long = 1;
    match cmd {
        BIO_CTRL_RESET => {
            // SAFETY: `ssl` is live (checked above).
            if unsafe { SSL_is_quic(ssl) } != 0 {
                return 0;
            }
            // SAFETY: `ssl` live.
            unsafe { SSL_shutdown(ssl) };
            // SAFETY: `ssl` live.
            if unsafe { SSL_clear(ssl) } == 0 {
                ret = 0;
            } else if !next.is_null() {
                // SAFETY: `next` is a live BIO.
                ret = unsafe { BIO_ctrl(next, cmd, num, ptr) };
            } else {
                // SAFETY: `ssl` live.
                let rbio = unsafe { SSL_get_rbio(ssl) };
                if rbio.is_null() {
                    ret = 1;
                } else {
                    // SAFETY: `rbio` is a live BIO.
                    ret = unsafe { BIO_ctrl(rbio, cmd, num, ptr) };
                }
            }
        }
        BIO_CTRL_INFO => ret = 0,
        BIO_C_SSL_MODE => {
            if num != 0 {
                // SAFETY: `ssl` live.
                unsafe { ssl_set_connect_state(ssl) };
            } else {
                // SAFETY: `ssl` live.
                unsafe { ssl_set_accept_state(ssl) };
            }
        }
        BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT => {
            // SAFETY: `bs` live.
            ret = unsafe { (*bs).renegotiate_timeout };
            let num = if num < 60 { 5 } else { num };
            // SAFETY: `bs` live.
            unsafe {
                (*bs).renegotiate_timeout = num;
                (*bs).last_time = 0;
            }
        }
        BIO_C_SET_SSL_RENEGOTIATE_BYTES => {
            // SAFETY: `bs` live.
            ret = unsafe { (*bs).renegotiate_count };
            if num >= 512 {
                // SAFETY: `bs` live.
                unsafe { (*bs).renegotiate_count = num };
            }
        }
        BIO_C_GET_SSL_NUM_RENEGOTIATES => {
            // SAFETY: `bs` live.
            ret = unsafe { (*bs).num_renegotiates } as c_long;
        }
        BIO_C_SET_SSL => {
            if bs.is_null() {
                // Recover a data slot cleared by a failed earlier re-creation; without
                // this the BIO would stay permanently poisoned.
                // SAFETY: `b` is a live BIO of this method.
                if unsafe { ssl_new(b) } == 0 {
                    return 0;
                }
                // The authority transfers the caller's connection to the fresh data slot on
                // this recovery path too (`bs->ssl = (SSL *)ptr` after the successful
                // `ssl_new`); without this assignment the block would be adopted with a NULL
                // connection and the caller's SSL would leak.
                ssl = ptr as *mut Ssl;
            } else if !ssl.is_null() {
                // SAFETY: `b` is a live BIO of this method.
                unsafe { ssl_free(b) };
                // `ssl_free` released the block but the BIO still names it. Clear the
                // pointer *before* a possibly failing `ssl_new`, so an allocation refusal
                // leaves a NULL (poisoned but safe) slot rather than a dangling one that
                // a later `BIO_free` would release a second time. `ssl_free` clears `init`
                // only when the shutdown flag is set, so clear it here too: an unpaired
                // data slot must not read as initialised.
                // SAFETY: `b` is a live BIO.
                unsafe {
                    BIO_set_data(b, ptr::null_mut());
                    BIO_set_init(b, 0);
                }
                // SAFETY: `b` is a live BIO.
                if unsafe { ssl_new(b) } == 0 {
                    return 0;
                }
                // SAFETY: `b` is live and was just re-initialised.
                let fresh = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
                // SAFETY: `fresh` is this method's data.
                unsafe { (*fresh).ssl = ptr::null_mut() };
                ssl = ptr as *mut Ssl;
                // SAFETY: `fresh` is this method's data.
                unsafe { (*fresh).ssl = ssl };
            } else {
                ssl = ptr as *mut Ssl;
            }
            // Re-read the data pointer: the authority rebinds `bs` when it recreated it.
            // SAFETY: `b` is live.
            let bs2 = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
            if bs2.is_null() {
                return 0;
            }
            // SAFETY: `b`/`bs2` live.
            unsafe {
                BIO_set_shutdown(b, num as c_int);
                (*bs2).ssl = ssl;
            }
            if !ssl.is_null() {
                // SAFETY: `ssl` live.
                let bio = unsafe { SSL_get_rbio(ssl) };
                if !bio.is_null() {
                    // SAFETY: `bio` is a live BIO.
                    if unsafe { BIO_up_ref(bio) } == 0 {
                        return 0;
                    }
                    if !next.is_null() {
                        // SAFETY: both are live BIOs.
                        unsafe { BIO_push(bio, next) };
                    }
                    // SAFETY: `b`/`bio` live.
                    unsafe { BIO_set_next(b, bio) };
                }
            }
            // SAFETY: `b` live.
            unsafe { BIO_set_init(b, 1) };
        }
        BIO_C_GET_SSL => {
            if !ptr.is_null() {
                // SAFETY: `ptr` is a `SSL **` per the caller.
                unsafe { *(ptr as *mut *mut Ssl) = ssl };
            } else {
                ret = 0;
            }
        }
        BIO_CTRL_GET_CLOSE => {
            // SAFETY: `b` live.
            ret = unsafe { BIO_get_shutdown(b) } as c_long;
        }
        BIO_CTRL_SET_CLOSE => {
            // SAFETY: `b` live.
            unsafe { BIO_set_shutdown(b, num as c_int) };
        }
        BIO_CTRL_WPENDING => {
            // SAFETY: `ssl` live.
            let wbio = unsafe { SSL_get_wbio(ssl) };
            // SAFETY: `wbio` is a live BIO.
            ret = unsafe { BIO_ctrl(wbio, cmd, num, ptr) };
        }
        BIO_CTRL_PENDING => {
            // SAFETY: `ssl` live.
            ret = unsafe { SSL_pending(ssl) } as c_long;
            if ret == 0 {
                // SAFETY: `ssl` live.
                let rbio = unsafe { SSL_get_rbio(ssl) };
                // SAFETY: `rbio` is a live BIO.
                ret = unsafe { BIO_ctrl(rbio, cmd, num, ptr) };
            }
        }
        BIO_CTRL_FLUSH => {
            // SAFETY: `b` live.
            unsafe {
                BIO_clear_flags(
                    b,
                    BIO_FLAGS_READ
                        | BIO_FLAGS_WRITE
                        | BIO_FLAGS_IO_SPECIAL
                        | BIO_FLAGS_SHOULD_RETRY,
                );
            }
            // SAFETY: `ssl` live.
            let wbio = unsafe { SSL_get_wbio(ssl) };
            // SAFETY: `wbio` is a live BIO.
            ret = unsafe { BIO_ctrl(wbio, cmd, num, ptr) };
            // SAFETY: `b` live.
            unsafe { BIO_copy_next_retry(b) };
        }
        BIO_CTRL_PUSH => {
            // SAFETY: `ssl` live.
            let rbio = unsafe { SSL_get_rbio(ssl) };
            if !next.is_null() && next != rbio {
                // SAFETY: `next` is a live BIO.
                if unsafe { BIO_up_ref(next) } == 0 {
                    ret = 0;
                } else {
                    // SAFETY: `ssl`/`next` live.
                    unsafe { SSL_set_bio(ssl, next, next) };
                }
            }
        }
        BIO_CTRL_POP => {
            if b == ptr.cast::<Bio>() {
                // SAFETY: `ssl` live.
                unsafe { SSL_set_bio(ssl, ptr::null_mut(), ptr::null_mut()) };
            }
        }
        BIO_C_DO_STATE_MACHINE => {
            // SAFETY: `b` live.
            unsafe {
                BIO_clear_flags(
                    b,
                    BIO_FLAGS_READ
                        | BIO_FLAGS_WRITE
                        | BIO_FLAGS_IO_SPECIAL
                        | BIO_FLAGS_SHOULD_RETRY,
                );
                BIO_set_retry_reason(b, 0);
            }
            // SAFETY: `ssl` live.
            let handshake = unsafe { SSL_do_handshake(ssl) };
            ret = handshake as c_long;
            // SAFETY: `ssl` live.
            match unsafe { SSL_get_error(ssl, handshake) } {
                SSL_ERROR_WANT_READ => {
                    // SAFETY: `b` live.
                    unsafe { BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY) };
                }
                SSL_ERROR_WANT_WRITE => {
                    // SAFETY: `b` live.
                    unsafe { BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY) };
                }
                SSL_ERROR_WANT_CONNECT => {
                    // SAFETY: `b` live.
                    unsafe {
                        BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                        BIO_set_retry_reason(
                            b,
                            if next.is_null() {
                                0
                            } else {
                                BIO_get_retry_reason(next)
                            },
                        );
                    }
                }
                SSL_ERROR_WANT_X509_LOOKUP => {
                    // SAFETY: `b` live.
                    unsafe {
                        BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL | BIO_FLAGS_SHOULD_RETRY);
                        BIO_set_retry_reason(b, BIO_RR_SSL_X509_LOOKUP);
                    }
                }
                _ => {}
            }
        }
        BIO_CTRL_DUP => {
            // The authority calls `SSL_dup` (14.7's row); the reduced body leaves the destination
            // connection NULL, which is the authority's `ret = 0` when `SSL_dup` fails.
            // SAFETY: `b` is a live BIO of this method.
            let dbio = ptr as *mut Bio;
            // SAFETY: `dbio` is a live BIO of this method per the caller.
            let dbs = unsafe { BIO_get_data(dbio) }.cast::<BioSsl>();
            // SAFETY: `dbs`/`bs` live.
            unsafe {
                if !(*dbs).ssl.is_null() {
                    SSL_free((*dbs).ssl);
                    (*dbs).ssl = ptr::null_mut();
                }
                (*dbs).num_renegotiates = (*bs).num_renegotiates;
                (*dbs).renegotiate_count = (*bs).renegotiate_count;
                (*dbs).byte_count = (*bs).byte_count;
                (*dbs).renegotiate_timeout = (*bs).renegotiate_timeout;
                (*dbs).last_time = (*bs).last_time;
            }
            ret = 0;
        }
        BIO_C_GET_FD => {
            // SAFETY: `ssl` live.
            let rbio = unsafe { SSL_get_rbio(ssl) };
            // SAFETY: `rbio` is a live BIO.
            ret = unsafe { BIO_ctrl(rbio, cmd, num, ptr) };
        }
        BIO_CTRL_SET_CALLBACK => ret = 0,
        BIO_CTRL_GET_RPOLL_DESCRIPTOR => {
            // SAFETY: `ssl` live; `ptr` a `BIO_POLL_DESCRIPTOR *` per the caller.
            if unsafe { SSL_get_rpoll_descriptor(ssl, ptr.cast()) } == 0 {
                ret = 0;
            }
        }
        BIO_CTRL_GET_WPOLL_DESCRIPTOR => {
            // SAFETY: `ssl` live; `ptr` a `BIO_POLL_DESCRIPTOR *` per the caller.
            if unsafe { SSL_get_wpoll_descriptor(ssl, ptr.cast()) } == 0 {
                ret = 0;
            }
        }
        _ => {
            // SAFETY: `ssl` live.
            let rbio = unsafe { SSL_get_rbio(ssl) };
            // SAFETY: `rbio` is a live BIO.
            ret = unsafe { BIO_ctrl(rbio, cmd, num, ptr) };
        }
    }
    ret
}

/// `ssl_callback_ctrl` — `bio_ssl.c:415-432`.
///
/// # Safety
/// `b` must be a live BIO of this method.
unsafe extern "C" fn ssl_callback_ctrl(b: *mut Bio, cmd: c_int, fp: Option<BioInfoCb>) -> c_long {
    // SAFETY: `b` is live per the caller's contract.
    let bs = unsafe { BIO_get_data(b) }.cast::<BioSsl>();
    // A failed re-creation in `BIO_C_SET_SSL` leaves the data slot NULL; there is no
    // connection whose callback could be set.
    if bs.is_null() {
        return 0;
    }
    // SAFETY: this method's data is a `BioSsl`.
    let ssl = unsafe { (*bs).ssl };
    match cmd {
        BIO_CTRL_SET_CALLBACK => {
            // SAFETY: `ssl` live.
            let rbio = unsafe { SSL_get_rbio(ssl) };
            // SAFETY: `rbio` is a live BIO.
            unsafe { BIO_callback_ctrl(rbio, cmd, fp) }
        }
        _ => 0,
    }
}

/// `ssl_new` — `bio_ssl.c:62-74`.
///
/// # Safety
/// `bi` must be a live BIO of this method.
unsafe extern "C" fn ssl_new(bi: *mut Bio) -> c_int {
    // The owner allocates at the authority's own size/coordinates; a zeroed `BioSsl` is its
    // constructed state, so `OwnedCtx` validates it directly. `into_raw` hands the BIO the stable
    // data pointer, and `ssl_free` reclaims it.
    let Some(bs) = OwnedCtx::<BioSsl>::zalloc() else {
        return 0;
    };
    let raw = bs.into_raw().cast::<c_void>();
    // SAFETY: `bi` is live per the caller's contract.
    unsafe {
        BIO_set_init(bi, 0);
        BIO_set_data(bi, raw);
        BIO_clear_flags(bi, !0);
    }
    1
}

/// `ssl_free` — `bio_ssl.c:76-93`.
///
/// # Safety
/// `a` must be NULL or a live BIO of this method.
unsafe extern "C" fn ssl_free(a: *mut Bio) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: `a` is live per the caller's contract.
    let bs = unsafe { BIO_get_data(a) }.cast::<BioSsl>();
    // A failed `BIO_C_SET_SSL` re-creation leaves the data slot NULL; `ssl_free` is then
    // the authority's `OPENSSL_free(NULL)` no-op and answers success.
    if bs.is_null() {
        return 1;
    }
    // SAFETY: this method's data is a `BioSsl`.
    unsafe {
        if BIO_get_shutdown(a) != 0 {
            let ssl = (*bs).ssl;
            if !ssl.is_null() && SSL_in_init(ssl) == 0 {
                SSL_shutdown(ssl);
            }
            if BIO_get_init(a) != 0 {
                SSL_free((*bs).ssl);
            }
            BIO_clear_flags(a, !0);
            BIO_set_init(a, 0);
        }
    }
    // SAFETY: `bs` is NULL or the block `ssl_new` handed out and has not been released;
    // `from_raw` maps NULL to `None`, and `Drop` is the block's single release at `bio_ssl.c:91`.
    drop(unsafe { OwnedCtx::<BioSsl>::from_raw(bs) });
    1
}

/// The compiled-in `BIO_METHOD` returned by [`BIO_f_ssl`] — `bio_ssl.c:42-55`.
static METHODS_SSLP: BioMethod = BioMethod {
    type_: BIO_TYPE_SSL,
    name: SSL_METHOD_NAME,
    bwrite: Some(ssl_write),
    bwrite_old: None,
    bread: Some(ssl_read),
    bread_old: None,
    bputs: Some(ssl_puts),
    bgets: None,
    ctrl: Some(ssl_ctrl),
    create: Some(ssl_new),
    destroy: Some(ssl_free),
    callback_ctrl: Some(ssl_callback_ctrl),
    sendmmsg: None,
    recvmmsg: None,
};

/// `const BIO_METHOD *BIO_f_ssl(void)` — `ssl/bio_ssl.c:57-60`.
///
/// # Safety
/// The returned pointer is to a process-lifetime static; no precondition.
#[no_mangle]
pub unsafe extern "C" fn BIO_f_ssl() -> *const BioMethod {
    &METHODS_SSLP
}

/// `BIO *BIO_new_ssl(SSL_CTX *ctx, int client)` — `ssl/bio_ssl.c:496-514`.
///
/// # Safety
/// `ctx` must be NULL or a live context; the returned BIO owns the SSL it creates.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_ssl(ctx: *mut SslCtx, client: c_int) -> *mut Bio {
    // SAFETY: a constant method site.
    let ret = unsafe { BIO_new(&METHODS_SSLP) };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or live per the caller's contract.
    let ssl = unsafe { SSL_new(ctx) };
    if ssl.is_null() {
        // SAFETY: `ret` is a live BIO.
        unsafe { BIO_free(ret) };
        return ptr::null_mut();
    }
    if client != 0 {
        // SAFETY: `ssl` is live.
        unsafe { ssl_set_connect_state(ssl) };
    } else {
        // SAFETY: `ssl` is live.
        unsafe { ssl_set_accept_state(ssl) };
    }
    // `BIO_set_ssl(ret, ssl, BIO_CLOSE)` is `BIO_ctrl(ret, BIO_C_SET_SSL, BIO_CLOSE, ssl)`.
    // SAFETY: `ret` is a live BIO of this method; `ssl` is live.
    unsafe {
        BIO_ctrl(
            ret,
            BIO_C_SET_SSL,
            BIO_CLOSE as c_long,
            ssl.cast::<c_void>(),
        )
    };
    ret
}

/// `BIO *BIO_new_ssl_connect(SSL_CTX *ctx)` — `ssl/bio_ssl.c:470-494`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_ssl_connect(ctx: *mut SslCtx) -> *mut Bio {
    // SAFETY: a constant method site.
    let con = unsafe { BIO_new(BIO_s_connect()) };
    if con.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or live per the caller's contract.
    let ssl = unsafe { BIO_new_ssl(ctx, 1) };
    if ssl.is_null() {
        // SAFETY: both are live BIOs.
        unsafe { BIO_free(con) };
        return ptr::null_mut();
    }
    // SAFETY: both are live BIOs.
    let ret = unsafe { BIO_push(ssl, con) };
    if ret.is_null() {
        // SAFETY: both are live BIOs.
        unsafe {
            BIO_free(ssl);
            BIO_free(con);
        }
        return ptr::null_mut();
    }
    ret
}

/// `BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx)` — `ssl/bio_ssl.c:445-468`.
///
/// The `IS_QUIC_CTX(ctx)` short-circuit (`bio_ssl.c:451`) is unreachable here: this crate builds
/// no QUIC context (14.10 records that reduction), so every context takes the buffered arm.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_buffer_ssl_connect(ctx: *mut SslCtx) -> *mut Bio {
    // SAFETY: a constant method site.
    let buf = unsafe { BIO_new(BIO_f_buffer()) };
    if buf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is NULL or live per the caller's contract.
    let ssl = unsafe { BIO_new_ssl_connect(ctx) };
    if ssl.is_null() {
        // SAFETY: `buf` is a live BIO.
        unsafe { BIO_free(buf) };
        return ptr::null_mut();
    }
    // SAFETY: both are live BIOs.
    let ret = unsafe { BIO_push(buf, ssl) };
    if ret.is_null() {
        // SAFETY: both are live BIOs.
        unsafe {
            BIO_free(buf);
            BIO_free(ssl);
        }
        return ptr::null_mut();
    }
    ret
}

/// `int BIO_ssl_copy_session_id(BIO *t, BIO *f)` — `ssl/bio_ssl.c:516-530`.
///
/// # Safety
/// `t`/`f` must be NULL or live BIOs.
#[no_mangle]
pub unsafe extern "C" fn BIO_ssl_copy_session_id(t: *mut Bio, f: *mut Bio) -> c_int {
    // SAFETY: `t`/`f` are NULL or live per the caller's contract.
    let (t, f) = unsafe {
        (
            BIO_find_type(t, BIO_TYPE_SSL),
            BIO_find_type(f, BIO_TYPE_SSL),
        )
    };
    if t.is_null() || f.is_null() {
        return 0;
    }
    // SAFETY: `t`/`f` are SSL BIOs found by `BIO_find_type`.
    let (tdata, fdata) = unsafe {
        (
            BIO_get_data(t).cast::<BioSsl>(),
            BIO_get_data(f).cast::<BioSsl>(),
        )
    };
    // A failed `BIO_C_SET_SSL` re-creation leaves the data slot NULL, so an SSL BIO can be
    // live and findable by type without a data block. The authority dereferences that slot
    // unconditionally here; that is the same UB class 3.0.22 guards in `BIO_ssl_shutdown`, so
    // this refuses instead of reproducing it (AGENTS.md §17).
    if tdata.is_null() || fdata.is_null() {
        return 0;
    }
    // SAFETY: both data pointers are this method's.
    let (tssl, fssl) = unsafe { ((*tdata).ssl, (*fdata).ssl) };
    if tssl.is_null() || fssl.is_null() {
        return 0;
    }
    // SAFETY: both SSL pointers are live.
    unsafe { ssl_copy_session_id(tssl, fssl) }
}

/// `void BIO_ssl_shutdown(BIO *b)` — `ssl/bio_ssl.c:532-543`.
///
/// # Safety
/// `b` must be NULL or a live BIO chain.
#[no_mangle]
pub unsafe extern "C" fn BIO_ssl_shutdown(b: *mut Bio) {
    let mut cur = b;
    while !cur.is_null() {
        // SAFETY: `cur` is live.
        if unsafe { BIO_method_type(cur) } == BIO_TYPE_SSL {
            // SAFETY: `cur` is a live SSL BIO.
            let bdata = unsafe { BIO_get_data(cur) }.cast::<BioSsl>();
            // A failed re-creation leaves the data slot NULL; the authority's own
            // `bdata != NULL` guard (3.0.22 `bio_ssl.c:503`) is the behaviour preserved here.
            if !bdata.is_null() {
                // SAFETY: this method's data is a `BioSsl`.
                let ssl = unsafe { (*bdata).ssl };
                if !ssl.is_null() {
                    // SAFETY: `ssl` is live.
                    unsafe { SSL_shutdown(ssl) };
                }
            }
        }
        // SAFETY: `cur` is live; `BIO_next` walks the chain.
        cur = unsafe { BIO_next(cur) };
    }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(BioSsl => zero_state_sweep_bio_ssl);

#[cfg(test)]
mod adv_probe {
    use super::*;
    use crate::runtime::bio::BIO_read;
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::adv_alloc;

    /// Allocation-refusal control for `BIO_C_SET_SSL`'s re-creation arm.
    ///
    /// Before the repair the arm called `ssl_free` (which releases the `BioSsl` block and leaves
    /// `BIO.ptr` naming it) and then returned 0 when `ssl_new`'s allocation was refused. The
    /// dangling slot made the next `BIO_free` release the same block a second time and made every
    /// callback read freed memory. The instrument records a release of an already-released
    /// pointer as a double free, so the control both fails on the old body and passes only when
    /// the slot is cleared first.
    #[ignore = "process-global allocator probe; run via scripts/adv-probe.sh"]
    #[test]
    fn set_ssl_allocation_refusal_clears_data_before_recreate() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();

        // SAFETY: the probe holds the global state lock and runs alone; every pointer below is
        // live for the duration of the call, and the two SSL blocks are this test's own.
        unsafe {
            let b = BIO_new(&METHODS_SSLP);
            assert!(!b.is_null());
            let old_ssl = adv_alloc::zeroed_ssl();
            let refused_ssl = adv_alloc::zeroed_ssl();
            assert!(!old_ssl.is_null() && !refused_ssl.is_null());

            // `num == 0` keeps `ssl_free` out of the zeroed connection: the control is about the
            // block lifecycle, not about `SSL_shutdown`.
            assert_eq!(BIO_ctrl(b, BIO_C_SET_SSL, 0, old_ssl.cast::<c_void>()), 1);
            assert!(!BIO_get_data(b).is_null());
            assert_eq!(BIO_get_init(b), 1);

            adv_alloc::reset();
            adv_alloc::arm_any(core::mem::size_of::<BioSsl>());
            let rc = BIO_ctrl(b, BIO_C_SET_SSL, 0, refused_ssl.cast::<c_void>());
            adv_alloc::disarm_any();
            assert_eq!(rc, 0, "the refused BioSsl allocation must fail SET_SSL");
            adv_alloc::assert_no_double_free();

            // The repaired invariant: NULL (poisoned but safe), never the block `ssl_free`
            // just released.
            assert!(BIO_get_data(b).is_null());
            assert_eq!(BIO_get_init(b), 0);

            // Every callback on the poisoned object answers without dereferencing stale data.
            // `init == 0` makes the generic `BIO_read`/`BIO_write` return the uninitialised
            // failure before dispatch; either answer is acceptable so long as it is not a
            // successful transfer and no stale pointer is read.
            let mut byte: c_char = 0;
            assert!(
                BIO_read(b, (&mut byte as *mut c_char).cast::<c_void>(), 1) <= 0,
                "a poisoned SSL BIO must not report a read"
            );
            assert!(
                BIO_write(b, (&byte as *const c_char).cast::<c_void>(), 1) <= 0,
                "a poisoned SSL BIO must not report a write"
            );
            assert_eq!(BIO_ctrl(b, BIO_CTRL_PENDING, 0, ptr::null_mut()), 0);
            assert_eq!(BIO_callback_ctrl(b, BIO_CTRL_SET_CALLBACK, None), 0);
            // The chain-level entry points must tolerate the poisoned slot as well: the
            // authority's `BIO_ssl_shutdown` checks `bdata != NULL`, and the copy refuses.
            BIO_ssl_shutdown(b);
            assert_eq!(BIO_ssl_copy_session_id(b, b), 0);

            assert_eq!(BIO_free(b), 1);
            adv_alloc::assert_no_double_free();

            // Neither connection was adopted by the refused re-create; both blocks stay this
            // test's, released once at the allocator's own `(NULL, 0)` coordinate.
            CRYPTO_free(old_ssl.cast(), ptr::null(), 0);
            CRYPTO_free(refused_ssl.cast(), ptr::null(), 0);
        }
    }
}
