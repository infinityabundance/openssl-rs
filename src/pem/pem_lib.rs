//! Phase 5 — `crypto/pem/pem_lib.c`'s two header formatters.
//!
//! `PEM_proc_type` and `PEM_dek_info` are the only two exports of the PEM stratum
//! that need nothing beyond `BIO_snprintf`, and they are the two that *append* rather
//! than write: each starts at `buf + strlen(buf)` and leaves whatever was already
//! there alone. `PEM_ASN1_write_bio_internal` assembles a header by calling them in
//! sequence — first the `Proc-Type`, then the `DEK-Info` — and that accumulation is
//! the observable part of them.
//!
//! ## The one place the authority writes outside the buffer, and this one does not
//!
//! `PEM_BUFSIZE` is the only length either function has to work with; the caller is
//! not asked for one, so the contract is "a `PEM_BUFSIZE`-byte buffer". The authority
//! computes the remaining space as an `int` and converts it to `size_t` at each call,
//! so a negative remainder becomes enormous. It does not test for that, and two paths
//! reach it:
//!
//! * `PEM_proc_type`'s `BIO_snprintf(p, PEM_BUFSIZE - (p - buf), …)`, when the
//!   caller's existing prefix is already longer than `PEM_BUFSIZE`;
//! * `PEM_dek_info`'s per-byte `%02X`, which returns `2` whether or not two bytes
//!   were written. With exactly one byte left it writes the NUL alone and leaves `j`
//!   at `-1`; the next iteration then calls `BIO_snprintf(p, (size_t)-1, …)` and
//!   writes the encoding of every remaining byte past the end of the buffer.
//!
//! The candidate clamps the length to zero and stops the loop when no room is left.
//! Everything inside the buffer is identical — the truncated NULs land in the same
//! places — so the divergence is only in the region the authority writes illegally.
//! It is recorded as `D-PEM-1` and no compatibility claim covers that region.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::str::OPENSSL_strnlen;

/// `PEM_BUFSIZE` — `pem.h`'s header buffer length.
pub(crate) const PEM_BUFSIZE: c_int = 1024;
/// `PEM_TYPE_ENCRYPTED` — `pem.h`.
pub(crate) const PEM_TYPE_ENCRYPTED: c_int = 10;
/// `PEM_TYPE_MIC_ONLY` — `pem.h`.
pub(crate) const PEM_TYPE_MIC_ONLY: c_int = 20;
/// `PEM_TYPE_MIC_CLEAR` — `pem.h`.
pub(crate) const PEM_TYPE_MIC_CLEAR: c_int = 30;

/// `void PEM_proc_type(char *buf, int type)`
///
/// Appends `Proc-Type: 4,<name>\n` at the end of what `buf` already holds. Only
/// `ENCRYPTED`, `MIC-CLEAR` and `MIC-ONLY` are named; every other value — including
/// `pem.h`'s `PEM_TYPE_CLEAR`, which has no arm of its own — appends `BAD-TYPE`.
///
/// # Safety
///
/// `buf` must point at a NUL-terminated string in a writable region of at least
/// `PEM_BUFSIZE` bytes, or be null, in which case the authority dereferences it and
/// this does too.
#[no_mangle]
pub unsafe extern "C" fn PEM_proc_type(buf: *mut c_char, type_: c_int) {
    let str_ = match type_ {
        PEM_TYPE_ENCRYPTED => c"ENCRYPTED".as_ptr(),
        PEM_TYPE_MIC_CLEAR => c"MIC-CLEAR".as_ptr(),
        PEM_TYPE_MIC_ONLY => c"MIC-ONLY".as_ptr(),
        _ => c"BAD-TYPE".as_ptr(),
    };
    // SAFETY: the caller's contract makes `buf` a NUL-terminated string.
    let used = unsafe { OPENSSL_strnlen(buf, usize::MAX) } as c_int;
    // The authority subtracts as an `int` and converts at the call; the clamp is the
    // divergence D-PEM-1 describes.
    let room = (PEM_BUFSIZE - used).max(0) as usize;
    // SAFETY: `buf + used` is inside the caller's `PEM_BUFSIZE`-byte region when the
    // caller honoured the contract, `room` is what is left of it, and the format and
    // argument match. The cursor arithmetic is wrapping because `used` can exceed
    // `PEM_BUFSIZE` for a caller that did not; see D-PEM-1.
    unsafe {
        BIO_snprintf(
            buf.wrapping_add(used as usize),
            room,
            c"Proc-Type: 4,%s\n".as_ptr(),
            str_,
        )
    };
}

/// `void PEM_dek_info(char *buf, const char *type, int len, const char *str)`
///
/// Appends `DEK-Info: <type>,` and then `len` bytes of `str` as uppercase hex, then a
/// newline — but only if more than one byte of room remains for it, which is the
/// authority's `if (j > 1)`. A `BIO_snprintf` that answers zero or less abandons the
/// whole thing without further writes.
///
/// # Safety
///
/// `buf` as [`PEM_proc_type`]; `type` must be a NUL-terminated string; `str` must be
/// readable for `len` bytes, and `len` non-negative.
#[no_mangle]
pub unsafe extern "C" fn PEM_dek_info(
    buf: *mut c_char,
    type_: *const c_char,
    len: c_int,
    str_: *const c_char,
) {
    // SAFETY: the caller's contract makes `buf` a NUL-terminated string.
    let used = unsafe { OPENSSL_strnlen(buf, usize::MAX) } as c_int;
    let mut p = used as usize;
    let mut j = PEM_BUFSIZE - used;
    // SAFETY: the caller's contract; `type_` is NUL-terminated.
    let n = unsafe {
        BIO_snprintf(
            buf.wrapping_add(p),
            j.max(0) as usize,
            c"DEK-Info: %s,".as_ptr(),
            type_,
        )
    };
    if n <= 0 {
        return;
    }
    j -= n;
    p += n as usize;
    let mut i = 0;
    while i < len {
        // The authority reaches this call with a negative `j` and a `size_t` that is
        // therefore enormous; see D-PEM-1. Stopping here is what keeps the write
        // inside the caller's buffer.
        if j <= 0 {
            return;
        }
        // SAFETY: `str_` is readable for `len` bytes and `i < len`.
        let byte = c_int::from(unsafe { *str_.add(i as usize) } as u8);
        // SAFETY: `p` is inside the buffer and `j` bytes of room remain. Wrapping
        // again: the authority advances past the end here and this does not write
        // there, but the cursor value has to stay representable.
        let n = unsafe { BIO_snprintf(buf.wrapping_add(p), j as usize, c"%02X".as_ptr(), byte) };
        if n <= 0 {
            return;
        }
        j -= n;
        p += n as usize;
        i += 1;
    }
    if j > 1 {
        // SAFETY: `j > 1` means `buf + p` has at least two writable bytes, and the
        // two-byte static is NUL-terminated.
        unsafe { copy_two(buf.wrapping_add(p), c"\n".as_ptr()) };
    }
}

/// `strcpy(dst, "\n")` — the two bytes, `\n` and the terminator.
///
/// # Safety
///
/// `dst` must be writable for two bytes.
unsafe fn copy_two(dst: *mut c_char, src: *const c_char) {
    // SAFETY: the caller's contract.
    unsafe {
        *dst = *src;
        *dst.add(1) = *src.add(1);
    }
}
