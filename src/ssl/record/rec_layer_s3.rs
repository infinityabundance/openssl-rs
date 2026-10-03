//! Phase 14.4 — `ssl/record/rec_layer_s3.c`: the default read-buffer accessors and the record-state
//! string readers.
//!
//! The authority's record layer proper — `RECORD_LAYER_*`, the read/write record methods, the
//! `rlayer` structure — is not the measured surface the plan gives this subphase (section 3.4):
//! the observable is the two length accessors, the two state-string readers, and `SSL_poll`.
//!
//! ## What landed
//!
//! * `SSL_CTX_set_default_read_buffer_len` — stores the context-wide default.
//! * `SSL_set_default_read_buffer_len` — stores the connection-wide default (`ssl_default_read_buf_len`
//!   is not publicly readable, so the court records the call rather than the stored value; the
//!   authority exposes no getter either).
//! * `SSL_rstate_string`/`SSL_rstate_string_long` — the `tls_get_state` mapping over the connection's
//!   `rlayer.rstate`, which a fresh connection sets to `SSL_ST_READ_HEADER` (`"RH"`/`"read header"`).
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The record-read method is not modelled; `rlayer.rstate` is a scalar field.** The authority
//!   installs a `tls_common.c` read method on the connection (`RECORD_LAYER_reset`, `rec_layer_s3.c:72`)
//!   and reaches its `tls_get_state` through `rl->rrlmethod`; this crate keeps the state value the
//!   switch reads (`rstate`) and the switch's mapping, but not the method object. No public API changes
//!   `rstate` outside a handshake, so the value is `SSL_ST_READ_HEADER` throughout this slice, and the
//!   `rrlmethod == NULL` guard that would answer `"unknown"` (`rec_layer_s3.c:228-229`) is unreachable.
//! * **The setter's stored value has no public reader on either side.** The authority's
//!   `SSL_CTX_set_default_read_buffer_len` and `SSL_set_default_read_buffer_len` write fields that only
//!   the record layer allocator reads; the court drives the calls but cannot compare the stored length,
//!   and records that rather than inventing a reader. The context setter is not driven with NULL: the
//!   authority dereferences it there, and only the connection setter's NULL arm (a no-op) is driven.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::ssl::ssl_lib::{Ssl, SslCtx};

/// `SSL_ST_READ_HEADER` — `ssl.h:1113`.
const SSL_ST_READ_HEADER: c_int = 0xF0;
/// `SSL_ST_READ_BODY` — `ssl.h:1114`.
const SSL_ST_READ_BODY: c_int = 0xF1;

/// `void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len)` —
/// `ssl/record/rec_layer_s3.c:206-209`.
///
/// # Safety
/// `ctx` must be NULL or point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_read_buffer_len(ctx: *mut SslCtx, len: usize) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is non-NULL and live per the caller's contract.
    unsafe { (*ctx).default_read_buf_len = len };
}

/// `void SSL_set_default_read_buffer_len(SSL *s, size_t len)` — `ssl/record/rec_layer_s3.c:211-218`.
///
/// The authority's guard is `sc == NULL || IS_QUIC(s)`; this crate never produces a QUIC object, so
/// the NULL test is the whole guard.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_default_read_buffer_len(s: *mut Ssl, len: usize) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { (*s).rlayer_default_read_buf_len = len };
}

/// `const char *SSL_rstate_string_long(const SSL *s)` — `ssl/record/rec_layer_s3.c:220-234`.
///
/// The `tls_get_state` long names (`tls_common.c:2080-2092`) for the connection's read state.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_rstate_string_long(s: *const Ssl) -> *const c_char {
    if s.is_null() {
        return ptr::null();
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    match unsafe { (*s).rstate } {
        SSL_ST_READ_HEADER => c"read header".as_ptr(),
        SSL_ST_READ_BODY => c"read body".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}

/// `const char *SSL_rstate_string(const SSL *s)` — `ssl/record/rec_layer_s3.c:236-250`.
///
/// The `tls_get_state` short names (`tls_common.c:2080-2092`).
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_rstate_string(s: *const Ssl) -> *const c_char {
    if s.is_null() {
        return ptr::null();
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    match unsafe { (*s).rstate } {
        SSL_ST_READ_HEADER => c"RH".as_ptr(),
        SSL_ST_READ_BODY => c"RB".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}
