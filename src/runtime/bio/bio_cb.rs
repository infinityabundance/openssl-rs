//! Phase 4 — `BIO_debug_callback` and `BIO_debug_callback_ex`.
//!
//! These two functions are the reference implementation of the BIO callback
//! protocol: a caller can pass `BIO_debug_callback` to `BIO_set_callback` and
//! every BIO operation then writes a line describing itself. They are exported,
//! they are the documented way to observe the callback protocol, and their
//! *output text* is therefore part of the observable contract — a probe that
//! installs one and captures the destination BIO compares it byte for byte.
//!
//! ## Two quirks that are contract, not accident
//!
//! `BIO_debug_callback` (the deprecated wrapper) forwards a **coerced** return
//! value to the `_ex` form — `ret > 0 ? 1 : (int)ret` — and then **discards**
//! whatever `_ex` returns, answering with its own original `ret`. So the wrapper
//! can never report the `"recvmmsg processed"` rewrite that `_ex` performs.
//!
//! `BIO_debug_callback_ex` rewrites its own return only in the two `sendmmsg`/
//! `recvmmsg` completion arms, where it answers `(long)len` rather than `ret`.
//! Every other operation answers `ret` unchanged, even though it also *printed*
//! a different number.
//!
//! ## Destination selection
//!
//! The formatted text goes to `(BIO *)bio->cb_arg` when that is non-NULL and to
//! `stderr` otherwise. `cb_arg` is typed `char *` in the header and cast to
//! `BIO *` here, exactly as the authority casts it; a caller who sets a
//! non-BIO argument gets the authority's behaviour (a write into whatever the
//! pointer addresses), and the probe therefore always sets a BIO.

use core::ffi::{c_char, c_int, c_long};

use crate::ffi::guard_ffi;

use super::print::BIO_snprintf;
use super::sys;
use super::{
    Bio, BIO_CB_CTRL, BIO_CB_FREE, BIO_CB_GETS, BIO_CB_PUTS, BIO_CB_READ, BIO_CB_RECVMMSG,
    BIO_CB_RETURN, BIO_CB_SENDMMSG, BIO_CB_WRITE, BIO_TYPE_DESCRIPTOR,
};

/// The authority's stack buffer size (`char buf[256]` in `bio_cb.c`).
const BUF_LEN: usize = 256;

/// Write `text` to the callback-argument BIO, or to `stderr` when there is none.
///
/// # Safety
/// `bio` must be a live `BIO`. When `cb_arg` is non-NULL the authority treats it
/// as a `BIO *` and writes to it, so a caller that set a non-BIO argument must
/// accept the authority's behaviour.
unsafe fn emit(bio: *mut Bio, text: *const c_char) {
    // SAFETY: `bio` is live.
    let arg = unsafe { (*bio).cb_arg };
    if arg.is_null() {
        // SAFETY: `stderr` is the C library's standard error stream.
        unsafe {
            sys::fputs(text, sys::stderr);
        }
    } else {
        // SAFETY: the authority casts `cb_arg` to `BIO *` and writes to it; the
        // length is the NUL-terminated text length.
        unsafe {
            let len = sys::strlen(text);
            super::BIO_write(arg.cast(), text.cast(), len as c_int);
        }
    }
}

/// `long BIO_debug_callback_ex(BIO *bio, int oper, const char *argp, size_t len,
/// int argi, long argl, int ret, size_t *processed)`
///
/// # Safety
/// `bio` must be a live `BIO`; `argp` must be whatever the operation's callbacks
/// specify for `oper`; `processed` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn BIO_debug_callback_ex(
    bio: *mut Bio,
    cmd: c_int,
    argp: *const c_char,
    len: usize,
    argi: c_int,
    _argl: c_long,
    ret: c_int,
    processed: *mut usize,
) -> c_long {
    guard_ffi(0, || {
        if bio.is_null() {
            // The authority dereferences `bio->method` in every arm and faults;
            // total by policy (docs/SECURITY_DIVERGENCE_POLICY.md).
            return 0;
        }
        let mut ret_ = ret as c_long;
        let mut l: usize = 0;
        if !processed.is_null() {
            // SAFETY: the caller's contract says `processed` is writable.
            l = unsafe { *processed };
        }

        let mut buf = [0 as c_char; BUF_LEN];
        let mut left = {
            // SAFETY: `buf` is writable for `BUF_LEN` bytes; the format and its
            // single `%p` argument are correct for a C variadic call.
            unsafe {
                BIO_snprintf(
                    buf.as_mut_ptr(),
                    BUF_LEN,
                    c"BIO[%p]: ".as_ptr(),
                    bio.cast::<core::ffi::c_void>(),
                )
            }
        };
        if left < 0 {
            left = 0;
        }
        let mut p = buf.as_mut_ptr();
        // SAFETY: `left` came from `BIO_snprintf` and is > 0 and < BUF_LEN for
        // this format, so advancing `p` stays inside `buf`.
        p = unsafe { p.add(left as usize) };
        left = BUF_LEN as c_int - left;

        // SAFETY: the method pointer of a live BIO is a live method table.
        let name = unsafe { (*(*bio).method).name };
        // SAFETY: as above.
        let mtype = unsafe { (*(*bio).method).type_ };
        // SAFETY: the `num` field is a plain `int` member of a live BIO.
        let num = unsafe { (*bio).num };

        match cmd {
            BIO_CB_FREE => {
                // SAFETY: `p` points inside `buf` with `left` bytes available;
                // `name` is a NUL-terminated method name.
                unsafe { BIO_snprintf(p, left as usize, c"Free - %s\n".as_ptr(), name) };
            }
            BIO_CB_READ => {
                if mtype & BIO_TYPE_DESCRIPTOR != 0 {
                    // SAFETY: as above, with the `fd=%d` suffix.
                    unsafe {
                        BIO_snprintf(
                            p,
                            left as usize,
                            c"read(%d,%zu) - %s fd=%d\n".as_ptr(),
                            num,
                            len,
                            name,
                            num,
                        )
                    };
                } else {
                    // SAFETY: as above.
                    unsafe {
                        BIO_snprintf(
                            p,
                            left as usize,
                            c"read(%d,%zu) - %s\n".as_ptr(),
                            num,
                            len,
                            name,
                        )
                    };
                }
            }
            BIO_CB_WRITE => {
                if mtype & BIO_TYPE_DESCRIPTOR != 0 {
                    // SAFETY: as above.
                    unsafe {
                        BIO_snprintf(
                            p,
                            left as usize,
                            c"write(%d,%zu) - %s fd=%d\n".as_ptr(),
                            num,
                            len,
                            name,
                            num,
                        )
                    };
                } else {
                    // SAFETY: as above.
                    unsafe {
                        BIO_snprintf(
                            p,
                            left as usize,
                            c"write(%d,%zu) - %s\n".as_ptr(),
                            num,
                            len,
                            name,
                        )
                    };
                }
            }
            BIO_CB_PUTS => {
                // SAFETY: as above.
                unsafe { BIO_snprintf(p, left as usize, c"puts() - %s\n".as_ptr(), name) };
            }
            BIO_CB_GETS => {
                // SAFETY: as above.
                unsafe { BIO_snprintf(p, left as usize, c"gets(%zu) - %s\n".as_ptr(), len, name) };
            }
            BIO_CB_CTRL => {
                // SAFETY: as above.
                unsafe { BIO_snprintf(p, left as usize, c"ctrl(%d) - %s\n".as_ptr(), argi, name) };
            }
            BIO_CB_RECVMMSG => {
                // SAFETY: for this operation the callback contract says `argp` is
                // a `BIO_MMSG_CB_ARGS *`.
                let args = argp.cast::<super::BioMmsgCbArgs>();
                // SAFETY: as just stated.
                let num_msg = unsafe { (*args).num_msg };
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"recvmmsg(%zu) - %s".as_ptr(),
                        num_msg,
                        name,
                    )
                };
            }
            BIO_CB_SENDMMSG => {
                // SAFETY: as for `recvmmsg`.
                let args = argp.cast::<super::BioMmsgCbArgs>();
                // SAFETY: as just stated.
                let num_msg = unsafe { (*args).num_msg };
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"sendmmsg(%zu) - %s".as_ptr(),
                        num_msg,
                        name,
                    )
                };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_READ) => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"read return %d processed: %zu\n".as_ptr(),
                        ret,
                        l,
                    )
                };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_WRITE) => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"write return %d processed: %zu\n".as_ptr(),
                        ret,
                        l,
                    )
                };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_GETS) => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"gets return %d processed: %zu\n".as_ptr(),
                        ret,
                        l,
                    )
                };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_PUTS) => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"puts return %d processed: %zu\n".as_ptr(),
                        ret,
                        l,
                    )
                };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_CTRL) => {
                // SAFETY: as above.
                unsafe { BIO_snprintf(p, left as usize, c"ctrl return %d\n".as_ptr(), ret) };
            }
            c if c == (BIO_CB_RETURN | BIO_CB_RECVMMSG) => {
                // SAFETY: as above. Note the authority answers `len`, not `ret`.
                unsafe {
                    BIO_snprintf(p, left as usize, c"recvmmsg processed: %zu\n".as_ptr(), len)
                };
                ret_ = len as c_long;
            }
            c if c == (BIO_CB_RETURN | BIO_CB_SENDMMSG) => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(p, left as usize, c"sendmmsg processed: %zu\n".as_ptr(), len)
                };
                ret_ = len as c_long;
            }
            _ => {
                // SAFETY: as above.
                unsafe {
                    BIO_snprintf(
                        p,
                        left as usize,
                        c"bio callback - unknown type (%d)\n".as_ptr(),
                        cmd,
                    )
                };
            }
        }

        // SAFETY: `buf` was NUL-terminated by the second `BIO_snprintf`.
        unsafe { emit(bio, buf.as_ptr()) };
        ret_
    })
}

/// `long BIO_debug_callback(BIO *bio, int cmd, const char *argp, int argi,
/// long argl, long ret)`
///
/// The deprecated wrapper. It coerces `ret` for the `_ex` call
/// (`ret > 0 ? 1 : (int)ret`), passes `argi` in both the `len` and `argi`
/// positions, and returns its **own** `ret` — so it never reports the
/// `sendmmsg`/`recvmmsg` rewrite.
///
/// # Safety
/// As [`BIO_debug_callback_ex`]: `bio` must be live and `argp` must match `cmd`.
#[no_mangle]
pub unsafe extern "C" fn BIO_debug_callback(
    bio: *mut Bio,
    cmd: c_int,
    argp: *const c_char,
    argi: c_int,
    argl: c_long,
    ret: c_long,
) -> c_long {
    guard_ffi(0, || {
        let mut processed: usize = 0;
        if ret > 0 {
            processed = ret as usize;
        }
        let coerced: c_int = if ret > 0 { 1 } else { ret as c_int };
        // SAFETY: `bio` and `argp` follow `BIO_debug_callback_ex`'s contract.
        unsafe {
            BIO_debug_callback_ex(
                bio,
                cmd,
                argp,
                argi as usize,
                argi,
                argl,
                coerced,
                &mut processed,
            );
        }
        ret
    })
}
