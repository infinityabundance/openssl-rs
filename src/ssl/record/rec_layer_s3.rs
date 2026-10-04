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

use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::{BIO_ctrl, BIO_CTRL_FLUSH};
use crate::ssl::ssl_lib::{Ssl, SslCtx};

/// `TLS1_VERSION` — `ssl3.h`.
const TLS1_VERSION: c_int = 0x0301;
/// `TLS1_2_VERSION` — `ssl3.h`.
const TLS1_2_VERSION: c_int = 0x0303;
/// `TLS1_3_VERSION` — `ssl3.h`.
const TLS1_3_VERSION: c_int = 0x0304;
/// `TLS_ST_CW_CLNT_HELLO` — `ssl.h:1135`.
const TLS_ST_CW_CLNT_HELLO: c_int = 13;
/// `SSL_HRR_NONE` — `ssl_local.h`.
const SSL_HRR_NONE: c_int = 0;
/// `SSL3_RT_HEADER_LENGTH` — `ssl3.h` (5).
const SSL3_RT_HEADER_LENGTH: usize = 5;

/// `int ssl3_write_bytes(SSL *ssl, uint8_t type, const void *buf_, size_t len, size_t *written)` —
/// `ssl/record/rec_layer_s3.c:273-489`, reduced to the plaintext, single-record, no-retry arm.
///
/// The record version rule is `rec_layer_s3.c:395-405`: a TLS1.3 connection writes TLS1.2 records,
/// but an initial `ClientHello` (`TLS_ST_CW_CLNT_HELLO`, not a renegotiation, no HelloRetryRequest)
/// is versioned TLS1.0 for the middlebox-compatibility reason the authority's comment names. The
/// record header is the five-byte `type || version || length` of `tls_write_records_default`
/// (`ssl/record/methods/tls_common.c:1759-1896`); the buffering BIO, the write pipeline and the
/// encryption path are not modelled (recorded in `src/ssl/mod.rs`).
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write; `buf` must be readable
/// for `len` bytes.
pub(crate) unsafe fn ssl3_write_bytes(s: *mut Ssl, type_: u8, buf: *const u8, len: usize) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    let (version, hand_state, renegotiate, hrr) = unsafe {
        (
            (*s).version,
            (*s).hand_state,
            (*s).renegotiate,
            (*s).hello_retry_request,
        )
    };

    let mut recversion: c_int = if version == TLS1_3_VERSION {
        TLS1_2_VERSION
    } else {
        version
    };
    if hand_state == TLS_ST_CW_CLNT_HELLO
        && renegotiate == 0
        && version > TLS1_VERSION
        && hrr == SSL_HRR_NONE
    {
        recversion = TLS1_VERSION;
    }

    let mut hdr = [0u8; SSL3_RT_HEADER_LENGTH];
    hdr[0] = type_;
    hdr[1] = (recversion >> 8) as u8;
    hdr[2] = recversion as u8;
    hdr[3] = (len >> 8) as u8;
    hdr[4] = len as u8;

    // SAFETY: `s` is live; `wbio` is the caller's BIO.
    unsafe {
        if BIO_write(
            (*s).wbio,
            hdr.as_ptr().cast(),
            SSL3_RT_HEADER_LENGTH as c_int,
        ) <= 0
        {
            return -1;
        }
        if len != 0 && BIO_write((*s).wbio, buf.cast(), len as c_int) <= 0 {
            return -1;
        }
        // `ssl3_do_write` returns through `statem_flush`; a memory BIO needs no flush, but the
        // authority's `BIO_flush` on the write path is performed so a flush-requiring BIO is served.
        BIO_ctrl((*s).wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut());
    }
    1
}

/// `RECORD_LAYER_write_pending(const RECORD_LAYER *rl)` — `ssl/record/rec_layer_s3.c:114-117`.
///
/// The authority's macro reads `rl->wpend_tot`, the pending write's byte count; a fresh connection
/// has written nothing, so it is 0.
///
/// # Safety
/// `s` must point to a live connection.
pub(crate) unsafe fn record_layer_write_pending(s: *const Ssl) -> usize {
    // SAFETY: `s` is live per the caller's contract.
    unsafe { (*s).wpend_tot }
}

/// `RECORD_LAYER_read_pending(const RECORD_LAYER *rl)` — `ssl/record/rec_layer_s3.c:101-105`.
///
/// The authority reaches the read method's `unprocessed_read_pending`; this crate models no
/// record-read method, and a fresh connection has no read-ahead data, so it answers 0 (recorded in
/// `src/ssl/mod.rs`).
///
/// # Safety
/// `s` must point to a live connection.
pub(crate) unsafe fn record_layer_read_pending(_s: *const Ssl) -> c_int {
    0
}

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
