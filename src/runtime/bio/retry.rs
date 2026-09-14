//! Phase 4 — the descriptor error classifiers.
//!
//! Three exported predicates decide whether a failed descriptor operation is
//! *transient* and therefore worth retrying: `BIO_fd_should_retry`,
//! `BIO_fd_non_fatal_error` and `BIO_dgram_non_fatal_error`. They are small, and
//! it is tempting to treat them as trivia, but their membership sets differ from
//! `BIO_sock_should_retry`'s and a caller's retry loop branches on exactly that
//! difference. Each switch arm below is conditional on the macro existing in the
//! authority's Linux build (`crypto/bio/bss_fd.c`, `crypto/bio/bss_dgram.c`), so
//! the *set* is part of the contract and not merely the concept.

use core::ffi::c_int;

use crate::ffi::guard_ffi;

use super::sys;

/// The retryable-`errno` set both classifiers share.
///
/// The authority writes one `switch` per function, conditioned on which macros
/// its platform defines; on Linux the two lists differ only in `ENOTCONN`, which
/// only the file-descriptor classifier accepts.
const fn shared_non_fatal(err: c_int) -> bool {
    matches!(
        err,
        sys::EWOULDBLOCK |  // == EAGAIN on Linux; the authority guards the duplicate
        sys::EINTR        |
        sys::EPROTO       |
        sys::EINPROGRESS  |
        sys::EALREADY
    )
}

/// `int BIO_fd_non_fatal_error(int err)`
///
/// The file-descriptor classifier. Unlike the datagram one it also accepts
/// `ENOTCONN`, because a `write(2)` on an unconnected stream socket reports it.
/// `EAGAIN` and `EWOULDBLOCK` are the same value here, and the authority's
/// `#if EWOULDBLOCK != EAGAIN` guard compiles the duplicate arm out.
#[no_mangle]
pub extern "C" fn BIO_fd_non_fatal_error(err: c_int) -> c_int {
    guard_ffi(0, || {
        c_int::from(shared_non_fatal(err) || err == sys::ENOTCONN)
    })
}

/// `int BIO_fd_should_retry(int i)`
///
/// Only a `0` or `-1` return reports a retryable *error*; any other value —
/// including a negative count other than `-1` — is not consulted against
/// `errno` at all and answers 0. The authority reads the *result* of the call,
/// not a descriptor, so this reproduces the check exactly.
#[no_mangle]
pub extern "C" fn BIO_fd_should_retry(i: c_int) -> c_int {
    guard_ffi(0, || {
        if i != 0 && i != -1 {
            return 0;
        }
        // SAFETY: `errno` is thread-local and always readable.
        BIO_fd_non_fatal_error(unsafe { sys::errno() })
    })
}

/// `int BIO_dgram_non_fatal_error(int err)`
///
/// The datagram classifier. `ENOTCONN` is deliberately **not** in its set, so
/// `BIO_fd_non_fatal_error(ENOTCONN)` is 1 while
/// `BIO_dgram_non_fatal_error(ENOTCONN)` is 0. That asymmetry is measured, not
/// inferred, and is the reason the two functions cannot share one predicate.
#[no_mangle]
pub extern "C" fn BIO_dgram_non_fatal_error(err: c_int) -> c_int {
    guard_ffi(0, || c_int::from(shared_non_fatal(err)))
}
