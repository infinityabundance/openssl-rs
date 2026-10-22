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

use core::ffi::{c_char, c_int, CStr};
use core::ptr;

use crate::runtime::bio::iolib::{BIO_read, BIO_write};
use crate::runtime::bio::{
    BIO_ctrl, BIO_CTRL_FLUSH, BIO_FLAGS_IN_EOF, BIO_FLAGS_READ, BIO_FLAGS_WRITE,
};
use crate::runtime::err::err_reasons::{
    SSL_R_INVALID_ALERT, SSL_R_NO_RENEGOTIATION, SSL_R_PACKET_LENGTH_TOO_LONG,
    SSL_R_TOO_MANY_WARN_ALERTS, SSL_R_UNEXPECTED_EOF_WHILE_READING, SSL_R_UNKNOWN_ALERT_TYPE,
};
use crate::runtime::err::{openssl_rs_err_set_error, ERR_new, ERR_set_debug};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::ssl::ssl_ciph_table::SSL_OP_IGNORE_UNEXPECTED_EOF;
use crate::ssl::ssl_lib::{Ssl, SslCtx};
use crate::ssl::statem::statem::ossl_statem_fatal;

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

/// `SSL3_RT_MAX_PLAIN_LENGTH` — `ssl3.h` (16384): the largest plaintext a single TLS record may
/// carry, and the fragment size `tls_write_records_default` (`ssl/record/methods/tls_common.c`)
/// splits a larger `SSL_write` into.
const SSL3_RT_MAX_PLAIN_LENGTH: usize = 16384;

/// The record scratch bound: a plaintext fragment plus the TLS1.3 inner content-type byte, the
/// AEAD tag and the five-byte record header (`SSL3_RT_MAX_ENCRYPTED_LENGTH`).
const SSL3_RT_MAX_ENCRYPTED_LENGTH: usize = 17000;

/// The allocator-seam coordinate of the authority's write-buffer allocation
/// (`p = OPENSSL_malloc(len)`, `ssl/record/ssl3_buffer.c:124`). The reduced record layer keeps no
/// `SSL3_BUFFER`, so the record scratch is allocated at that site for the duration of a write.
const WRITE_BUF_FILE: &CStr = c"ssl/record/ssl3_buffer.c";
const WRITE_BUF_LINE: c_int = 124;

// --- record types (`include/openssl/ssl3.h`) ---------------------------------
/// `SSL3_RT_ALERT` — `ssl3.h` (21).
const SSL3_RT_ALERT: u8 = 21;

// --- alert levels and descriptions (`include/openssl/ssl3.h`, `tls1.h`, `ssl_local.h`)
/// `SSL3_AL_WARNING` — `ssl3.h:252`.
const SSL3_AL_WARNING: c_int = 1;
/// `SSL3_AL_FATAL` — `ssl3.h:253`.
const SSL3_AL_FATAL: c_int = 2;
/// `SSL_AD_CLOSE_NOTIFY` (`SSL3_AD_CLOSE_NOTIFY`) — `ssl3.h:255`.
const SSL_AD_CLOSE_NOTIFY: c_int = 0;
/// `SSL_AD_UNEXPECTED_MESSAGE` (`SSL3_AD_UNEXPECTED_MESSAGE`) — `ssl3.h:256`.
const SSL_AD_UNEXPECTED_MESSAGE: c_int = 10;
/// `SSL_AD_HANDSHAKE_FAILURE` (`SSL3_AD_HANDSHAKE_FAILURE`) — `ssl3.h:259`.
const SSL_AD_HANDSHAKE_FAILURE: c_int = 40;
/// `SSL_AD_ILLEGAL_PARAMETER` (`SSL3_AD_ILLEGAL_PARAMETER`) — `ssl3.h:266`.
const SSL_AD_ILLEGAL_PARAMETER: c_int = 47;
/// `SSL_AD_RECORD_OVERFLOW` (`TLS1_AD_RECORD_OVERFLOW`) — `ssl3.h:261`.
const SSL_AD_RECORD_OVERFLOW: c_int = 22;
/// `SSL_AD_DECODE_ERROR` (`TLS1_AD_DECODE_ERROR`) — `tls1.h:61`.
const SSL_AD_DECODE_ERROR: c_int = 50;
/// `SSL_AD_USER_CANCELLED` (`TLS1_AD_USER_CANCELLED`) — `tls1.h:68`.
const SSL_AD_USER_CANCELLED: c_int = 90;
/// `SSL_AD_NO_RENEGOTIATION` (`TLS1_AD_NO_RENEGOTIATION`) — `tls1.h:69`.
const SSL_AD_NO_RENEGOTIATION: c_int = 100;
/// `SSL_AD_NO_ALERT` — `ssl_local.h:63` ("we don't want to send an alert").
const SSL_AD_NO_ALERT: c_int = -1;
/// `SSL_AD_REASON_OFFSET` — `ssl.h:1159` (the offset that turns an alert description into the
/// `SSL_R_...` reason code `ERR_vset_error` carries).
const SSL_AD_REASON_OFFSET: c_int = 1000;
/// `MAX_WARN_ALERT_COUNT` — `ssl/record/record_local.h:17`.
const MAX_WARN_ALERT_COUNT: c_int = 5;

// --- connection state reads --------------------------------------------------
/// `SSL_RECEIVED_SHUTDOWN` — `ssl.h:217`.
const SSL_RECEIVED_SHUTDOWN: c_int = 2;
/// `SSL_NOTHING` — `ssl.h:932`.
const SSL_NOTHING: c_int = 1;
/// `SSL_READING` — `ssl.h:934`.
const SSL_READING: c_int = 3;
/// `SSL_WRITING` — `ssl.h:933`.
const SSL_WRITING: c_int = 2;
/// `ERR_LIB_SSL` — `err.h:121`.
const ERR_LIB_SSL: c_int = 20;

/// `int ssl3_write_bytes(SSL *ssl, uint8_t type, const void *buf_, size_t len, size_t *written)` —
/// `ssl/record/rec_layer_s3.c:273-489`, reduced to the plaintext, no-retry arm.
///
/// A request larger than one record is fragmented into `SSL3_RT_MAX_PLAIN_LENGTH`-byte records,
/// exactly as the authority's `tls_write_records_default` does (`ssl/record/methods/tls_common.c`):
/// the record version rule is `rec_layer_s3.c:395-405` — a TLS1.3 connection writes TLS1.2
/// records, but an initial `ClientHello` (`TLS_ST_CW_CLNT_HELLO`, not a renegotiation, no
/// HelloRetryRequest) is versioned TLS1.0 for the middlebox-compatibility reason the authority's
/// comment names. Each fragment is one five-byte `type || version || length` header plus its body
/// (`ssl3_write_one_record`).
///
/// A zero-length request writes no record at all: the authority reaches its `tot == len` arm
/// (`rec_layer_s3.c:356-358`) and returns success with `*written = 0`, so no five-byte header is
/// emitted for it. This also keeps a legal `SSL_write(s, NULL, 0)` from passing a NULL source to
/// the record encoders.
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write; `buf` must be readable
/// for `len` bytes (`buf` is never dereferenced when `len == 0`).
pub(crate) unsafe fn ssl3_write_bytes(s: *mut Ssl, type_: u8, buf: *const u8, len: usize) -> c_int {
    if len == 0 {
        return 1;
    }
    // The encrypted record paths need a record-sized scratch block. It is heap-allocated through
    // the crate's allocator seam at the authority's own write-buffer site so no record-sized frame
    // lands on the caller's thread stack (a 32 KiB accept thread, radsecproxy's, previously
    // overflowed here). The handle's single release is its `Drop` on every return below.
    // SAFETY: `s` is live per this function's contract.
    let scratch = if unsafe { write_needs_scratch(s) } {
        match OwnedBuf::new(
            SSL3_RT_MAX_ENCRYPTED_LENGTH,
            SeamFile::new(WRITE_BUF_FILE),
            WRITE_BUF_LINE,
        ) {
            Some(block) => Some(block),
            // The authority's `ssl3_setup_write_buffer` failure: this function's documented
            // failure value.
            None => return -1,
        }
    } else {
        None
    };
    let rec = match scratch.as_ref() {
        Some(block) => block.as_ptr(),
        None => ptr::null_mut(),
    };
    let mut off = 0usize;
    loop {
        let remaining = len - off;
        let chunk = if remaining > SSL3_RT_MAX_PLAIN_LENGTH {
            SSL3_RT_MAX_PLAIN_LENGTH
        } else {
            remaining
        };
        // `buf.add(0)` on a NULL `buf` would be UB, so only advance when a fragment has been sent.
        let p = if off == 0 {
            buf
        } else {
            // SAFETY: `off < len`, so `off` is in bounds of the caller's `len` readable bytes.
            unsafe { buf.add(off) }
        };
        // SAFETY: `s`/`p` are per this function's contract, with `chunk` readable bytes at `p`;
        // `rec` is the scratch block above when an encrypted path needs it, NULL otherwise.
        if unsafe { ssl3_write_one_record(s, type_, p, chunk, rec) } <= 0 {
            return -1;
        }
        off += chunk;
        if off >= len {
            break;
        }
    }
    1
}

/// Whether [`ssl3_write_one_record`] will take an encrypted path and therefore need the record
/// scratch block (`tls13_enc`/`tls1_enc`, selected by the installed version and cipher state).
///
/// # Safety
/// `s` must be a live connection.
unsafe fn write_needs_scratch(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the contract.
    let (version, active) = unsafe { ((*s).version, (*s).enc_active) };
    active != 0 && (version == TLS1_3_VERSION || version == TLS1_2_VERSION)
}

/// Write `len` bytes from `p` to the connection's write BIO, resuming a short `BIO_write`.
///
/// The authority's `ssl3_write_bytes` keeps `rlayer.wpend_tot` and re-enters the write method when
/// the BIO accepts only part of a record (`rec_layer_s3.c:459-488`); this reduced form loops until
/// every byte is accepted, so a short `write(2)` cannot silently truncate a record. An `EAGAIN`
/// still surfaces as -1 with `BIO_FLAGS_WRITE` (the pending-write resumption is a recorded
/// boundary).
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write; `p` must be readable for
/// `len` bytes.
unsafe fn ssl3_write_all(s: *mut Ssl, p: *const u8, len: usize) -> c_int {
    let mut off = 0usize;
    while off < len {
        // SAFETY: `s` is live; `p.add(off)` is `len - off` readable bytes; `wbio` is the caller's.
        let n = unsafe { BIO_write((*s).wbio, p.add(off).cast(), (len - off) as c_int) };
        if n <= 0 {
            // The authority's `ossl_tls_handle_rlayer_return` sets `rwstate = SSL_WRITING` on a
            // retryable record write (`rec_layer_s3.c:491-498`), which `SSL_get_error` turns into
            // `SSL_ERROR_WANT_WRITE`.
            // SAFETY: `s` is live; `wbio` is its write BIO.
            let wbio = unsafe { (*s).wbio };
            // SAFETY: `wbio` is non-NULL here, so its flags word is readable.
            if !wbio.is_null() && unsafe { (*wbio).flags } & BIO_FLAGS_WRITE != 0 {
                // SAFETY: `s` is live.
                unsafe { (*s).rwstate = SSL_WRITING };
            }
            return -1;
        }
        off += n as usize;
    }
    1
}

/// Write exactly one record of at most `SSL3_RT_MAX_PLAIN_LENGTH` plaintext bytes.
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write; `buf` must be readable
/// for `len` bytes and `len` must not exceed [`SSL3_RT_MAX_PLAIN_LENGTH`]; `rec` must be NULL or
/// writable for [`SSL3_RT_MAX_ENCRYPTED_LENGTH`] bytes.
unsafe fn ssl3_write_one_record(
    s: *mut Ssl,
    type_: u8,
    buf: *const u8,
    len: usize,
    rec: *mut u8,
) -> c_int {
    // The record encoders size their output from `len`; both the encoded scratch block and the
    // two-byte record-length field are bounded by the plaintext fragment limit. The only caller
    // ([`ssl3_write_bytes`]) fragments at this length, so this is a defensive refusal, not a
    // reachable path.
    if len > SSL3_RT_MAX_PLAIN_LENGTH {
        return -1;
    }
    // SAFETY: `s` is live per the caller's contract.
    let (version, hand_state, renegotiate, hrr) = unsafe {
        (
            (*s).version,
            (*s).hand_state,
            (*s).renegotiate,
            (*s).hello_retry_request,
        )
    };

    // Phase 17.2c: once the TLS 1.3 write key is installed every record is AEAD-protected
    // (`tls13_enc`, `ssl/record/methods/tls13_meth.c`).
    // SAFETY: `s` is live per the caller's contract.
    if version == TLS1_3_VERSION && unsafe { (*s).enc_active } != 0 {
        if rec.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; `rec` is the caller's record scratch; `buf` is `len` readable.
        let n = unsafe { crate::ssl::tls13_enc::tls13_encrypt_record(s, type_, buf, len, rec) };
        if n < 0 {
            return -1;
        }
        // SAFETY: `s` is live; `wbio` is the caller's BIO.
        unsafe {
            if ssl3_write_all(s, rec, n as usize) <= 0 {
                return -1;
            }
            BIO_ctrl((*s).wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut());
        }
        return 1;
    }

    // Phase 17: a TLS1.2 AEAD record (`tls1_enc`, `ssl/t1_enc.c`). The header, explicit nonce and
    // tag are built by the TLS1.2 record method, so no generic header follows.
    // SAFETY: `s` is live per the caller's contract.
    if version == TLS1_2_VERSION && unsafe { (*s).enc_active } != 0 {
        if rec.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; `rec` is the caller's record scratch; `buf` is `len` readable.
        let n = unsafe { crate::ssl::t1_enc::tls12_encrypt_record(s, type_, buf, len, rec) };
        if n < 0 {
            return -1;
        }
        // SAFETY: `s` is live; `wbio` is the caller's BIO.
        unsafe {
            if ssl3_write_all(s, rec, n as usize) <= 0 {
                return -1;
            }
            BIO_ctrl((*s).wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut());
        }
        return 1;
    }

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
        if ssl3_write_all(s, hdr.as_ptr(), SSL3_RT_HEADER_LENGTH) <= 0 {
            return -1;
        }
        if len != 0 && ssl3_write_all(s, buf, len) <= 0 {
            return -1;
        }
        // `ssl3_do_write` returns through `statem_flush`; a memory BIO needs no flush, but the
        // authority's `BIO_flush` on the write path is performed so a flush-requiring BIO is served.
        BIO_ctrl((*s).wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut());
    }
    1
}

/// `int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf, size_t len,` —
/// `ssl/record/rec_layer_s3.c:612-...`, reduced to the record-read arm the handshake and
/// application readers need.
///
/// It reads one record with [`ssl3_read_one_record`] and, when that record is an alert, decodes it
/// exactly as the authority's alert block does (`rec_layer_s3.c:864-944`): a `close_notify` sets
/// `SSL_RECEIVED_SHUTDOWN` and ends the read, a fatal alert (any non-`user_cancelled` TLS 1.3
/// alert) records `s3.fatal_alert` and queues `SSL_AD_REASON_OFFSET + alert_descr`, `user_cancelled`
/// and the TLS1.2 warnings are ignored, and `no_renegotiation` or an unknown type is fatal.
///
/// The return follows the authority's `ssl3_read_internal`: a positive body length, `0` for a
/// terminal record whose connection state and error queue are already set, or `-1` for a retry
/// (which leaves `rwstate = SSL_READING`, `rec_layer_s3.c:497`).
///
/// # Safety
/// `s` must be a live connection whose read BIO is the caller's to read; `buf` must be writable for
/// `cap` bytes; `rectype` must be writable.
pub(crate) unsafe fn ssl3_read_bytes(
    s: *mut Ssl,
    rectype: *mut u8,
    buf: *mut u8,
    cap: usize,
) -> c_int {
    // SAFETY: `s` is live per the caller's contract; every read/write below is to it.
    unsafe {
        loop {
            let mut rec_ty = 0u8;
            // SAFETY: `s` is live; `buf`/`cap` are the caller's; `rec_ty` is writable.
            let n = ssl3_read_one_record(s, &mut rec_ty, buf, cap);
            if n <= 0 {
                return n;
            }
            if rec_ty != SSL3_RT_ALERT {
                *rectype = rec_ty;
                return n;
            }
            // `rec_layer_s3.c:864-944`.
            match ssl3_read_bytes_alert(s, buf, n) {
                AlertOutcome::Terminal => return 0,
                AlertOutcome::Fatal => return -1,
                AlertOutcome::Ignored => continue,
            }
        }
    }
}

/// The authority's received-alert verdict (`ssl3_read_bytes`, `ssl/record/rec_layer_s3.c:864-944`).
enum AlertOutcome {
    /// A record that ends the read with 0 (`close_notify`, a fatal alert).
    Terminal,
    /// A record that ends the read with -1 after `SSLfatal` (invalid, too many warnings,
    /// `no_renegotiation`, an unknown type).
    Fatal,
    /// `user_cancelled` or a TLS1.2 warning: the authority's `goto start` reads again.
    Ignored,
}

/// Decode one received alert (`ssl3_read_bytes`, `ssl/record/rec_layer_s3.c:864-944`).
///
/// # Safety
/// `s` is a live connection; `buf` holds `len` alert bytes.
unsafe fn ssl3_read_bytes_alert(s: *mut Ssl, buf: *const u8, len: c_int) -> AlertOutcome {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if len != 2 {
            // `rec_layer_s3.c:868-874`: `PACKET_remaining(&alert) != 0` after the level and the
            // description, so any packet other than exactly two bytes is an invalid alert.
            ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_INVALID_ALERT);
            return AlertOutcome::Fatal;
        }
        let alert_level = c_int::from(*buf);
        let alert_descr = c_int::from(*buf.add(1));
        let is_tls13 = (*s).version == TLS1_3_VERSION;

        // `rec_layer_s3.c:891-903`: a TLS1.2 warning (or a TLS1.3 `user_cancelled`) is counted;
        // `MAX_WARN_ALERT_COUNT` consecutive warnings are fatal.
        if (!is_tls13 && alert_level == SSL3_AL_WARNING)
            || (is_tls13 && alert_descr == SSL_AD_USER_CANCELLED)
        {
            (*s).warn_alert = alert_descr;
            (*s).alert_count += 1;
            if (*s).alert_count == MAX_WARN_ALERT_COUNT {
                ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_TOO_MANY_WARN_ALERTS);
                return AlertOutcome::Fatal;
            }
        }

        if is_tls13 && alert_descr == SSL_AD_USER_CANCELLED {
            // `rec_layer_s3.c:909-910`: the one ignorable TLS1.3 warning.
            return AlertOutcome::Ignored;
        } else if alert_descr == SSL_AD_CLOSE_NOTIFY && (is_tls13 || alert_level == SSL3_AL_WARNING)
        {
            // `rec_layer_s3.c:911-914`.
            (*s).shutdown |= SSL_RECEIVED_SHUTDOWN;
            (*s).rwstate = SSL_NOTHING;
            return AlertOutcome::Terminal;
        } else if alert_level == SSL3_AL_FATAL || is_tls13 {
            // `rec_layer_s3.c:915-925`: a fatal alert (any non-`close_notify`/`user_cancelled`
            // TLS1.3 alert) records the description and queues `SSL_AD_REASON_OFFSET + descr`.
            (*s).rwstate = SSL_NOTHING;
            (*s).fatal_alert = alert_descr;
            raise_alert_received(s, alert_descr);
            (*s).shutdown |= SSL_RECEIVED_SHUTDOWN;
            return AlertOutcome::Terminal;
        } else if alert_descr == SSL_AD_NO_RENEGOTIATION {
            // `rec_layer_s3.c:926-936`.
            ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_RENEGOTIATION);
            return AlertOutcome::Fatal;
        } else if alert_level == SSL3_AL_WARNING {
            // `rec_layer_s3.c:937-939`: any other TLS1.2 warning is ignored.
            return AlertOutcome::Ignored;
        }
        // `rec_layer_s3.c:942-943`.
        ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_UNKNOWN_ALERT_TYPE);
        AlertOutcome::Fatal
    }
}

/// `SSLfatal_data(s, SSL_AD_NO_ALERT, SSL_AD_REASON_OFFSET + alert_descr, "SSL alert number %d",`
/// `alert_descr)` — `ssl/record/rec_layer_s3.c:916-925`.
///
/// The error is raised at the alert block's own coordinate (`rec_layer_s3.c:918`) with the alert
/// number as `ERR` data, then the state machine's fatal transition runs with `SSL_AD_NO_ALERT`, so
/// no alert is echoed to the peer.
///
/// # Safety
/// `s` is a live connection.
unsafe fn raise_alert_received(s: *mut Ssl, alert_descr: c_int) {
    let _ = s;
    ERR_new();
    // SAFETY: the file/function strings are static; the coordinate is the authority's.
    unsafe {
        ERR_set_debug(
            c"ssl/record/rec_layer_s3.c".as_ptr(),
            918,
            c"ssl3_read_bytes".as_ptr(),
        )
    };
    let msg = format!("SSL alert number {alert_descr}\0");
    // SAFETY: `msg` is NUL-terminated; the callee copies the data.
    unsafe {
        openssl_rs_err_set_error(
            ERR_LIB_SSL,
            SSL_AD_REASON_OFFSET + alert_descr,
            msg.as_ptr().cast(),
        )
    };
    // SAFETY: `s` is live; this is `SSLfatal`'s state transition with `SSL_AD_NO_ALERT`.
    unsafe { crate::ssl::statem::statem::ossl_statem_send_fatal(s, SSL_AD_NO_ALERT) };
}

/// The `ossl_tls_handle_rlayer_return` verdict for a short or failed record read
/// (`ssl/record/rec_layer_s3.c:491-553`).
///
/// A zero-length read (or a BIO already flagged `BIO_FLAGS_IN_EOF`) with
/// `SSL_OP_IGNORE_UNEXPECTED_EOF` set is a clean EOF: the connection records a received shutdown
/// and the alert description `close_notify`, so `SSL_get_error` answers `SSL_ERROR_ZERO_RETURN`
/// (`rec_layer_s3.c:512-514`). Without the option it raises `SSL_R_UNEXPECTED_EOF_WHILE_READING`
/// and makes the connection fatal. A read the BIO flagged retryable leaves `rwstate = SSL_READING`
/// and answers -1, the arm `SSL_get_error` turns into `SSL_ERROR_WANT_READ`. Any other failure
/// answers -1 with no error queued, which `SSL_get_error` reports as `SSL_ERROR_SYSCALL`.
///
/// # Safety
/// `s` is a live connection.
unsafe fn ssl3_read_bytes_rlayer_return(s: *mut Ssl, got: c_int) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        let flags = if (*s).rbio.is_null() {
            0
        } else {
            (*(*s).rbio).flags
        };
        if got == 0 || flags & BIO_FLAGS_IN_EOF != 0 {
            // `rec_layer_s3.c:501-524`: `rwstate = SSL_NOTHING` first, then the EOF arm. With
            // `SSL_OP_IGNORE_UNEXPECTED_EOF` the EOF is graceful — record the shutdown and the
            // `close_notify` description so the read terminates with 0 and `SSL_get_error`
            // answers `SSL_ERROR_ZERO_RETURN` (`ssl_lib.c:4929-4930`).
            (*s).rwstate = SSL_NOTHING;
            if (*s).options & SSL_OP_IGNORE_UNEXPECTED_EOF != 0 {
                (*s).shutdown |= SSL_RECEIVED_SHUTDOWN;
                (*s).warn_alert = SSL_AD_CLOSE_NOTIFY;
                return 0;
            }
            ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_UNEXPECTED_EOF_WHILE_READING);
            return 0;
        }
        if flags & BIO_FLAGS_READ != 0 {
            // `rec_layer_s3.c:496-498`.
            (*s).rwstate = SSL_READING;
            return -1;
        }
        // `rec_layer_s3.c:499-500`: `rwstate = SSL_NOTHING`, no alert; `SSL_ERROR_SYSCALL`.
        (*s).rwstate = SSL_NOTHING;
        -1
    }
}

/// Read one `type || version || length` record and report its body length, the inner reader of
/// [`ssl3_read_bytes`].
///
/// The authority's read pipeline runs the record method's `read_record` and the message layer above
/// it; this reduced form reads one header and its body from `rbio`, **resuming a short
/// `BIO_read` across calls** the way the authority's `RECORD_LAYER` retains `rlayer.rrec`
/// (`rec_layer_s3.c:161-...`). A non-blocking socket BIO returns fewer bytes than requested
/// whenever the peer's record is split across TCP segments; reading into a fresh local each call
/// would drop the partial and desynchronise the stream, which is what the authority avoids. The
/// buffering BIO, the read-ahead queue and the `SSL3_RT_MAX_PLAIN_LENGTH` fragmentation are still
/// not modelled (recorded in `src/ssl/mod.rs`).
///
/// # Safety
/// `s` must be a live connection whose read BIO is the caller's to read; `buf` must be writable for
/// `cap` bytes; `rectype` must be writable.
unsafe fn ssl3_read_one_record(s: *mut Ssl, rectype: *mut u8, buf: *mut u8, cap: usize) -> c_int {
    // Accumulate the five-byte header, resuming after a short read.
    // SAFETY: `s` is live per the caller's contract.
    while unsafe { (*s).rec_hdr_len } < SSL3_RT_HEADER_LENGTH {
        // SAFETY: `s` is live.
        let off = unsafe { (*s).rec_hdr_len };
        let want = SSL3_RT_HEADER_LENGTH - off;
        // SAFETY: `s` is live; `rec_hdr[off..]` is `want` writable bytes; `rbio` is the caller's.
        let got = unsafe {
            BIO_read(
                (*s).rbio,
                (*s).rec_hdr.as_mut_ptr().add(off).cast(),
                want as c_int,
            )
        };
        if got <= 0 {
            // SAFETY: `s` is live; the partial header stays in `rec_hdr` for the next call.
            return unsafe { ssl3_read_bytes_rlayer_return(s, got) };
        }
        // SAFETY: `got` is a positive count no larger than `want`.
        unsafe { (*s).rec_hdr_len = off + got as usize };
    }
    // SAFETY: the header is complete (five valid bytes).
    let hdr = unsafe { (*s).rec_hdr };
    let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;

    // SAFETY: `s` is live per the caller's contract.
    if len > unsafe { (*s).rec_body.len() } {
        // `rec_layer_s3.c:669-672`: a length that does not fit the record buffer is a fatal
        // record overflow. The header bytes have already been consumed, so a silent -1 would
        // desynchronise the stream on the peer's body bytes; poison instead. Reset the
        // accumulator so a retry cannot re-enter the arm.
        // SAFETY: `s` is live; this is the authority's `RLAYERfatal`.
        unsafe {
            (*s).rec_hdr_len = 0;
            ossl_statem_fatal(s, SSL_AD_RECORD_OVERFLOW, SSL_R_PACKET_LENGTH_TOO_LONG);
        }
        return -1;
    }
    // Accumulate the body, resuming after a short read.
    // SAFETY: `s` is live per the caller's contract.
    while unsafe { (*s).rec_body_len } < len {
        // SAFETY: `s` is live.
        let off = unsafe { (*s).rec_body_len };
        let want = len - off;
        // SAFETY: `s` is live; `rec_body[off..]` is `want` writable bytes; `rbio` is the caller's.
        let got = unsafe {
            BIO_read(
                (*s).rbio,
                (*s).rec_body.as_mut_ptr().add(off).cast(),
                want as c_int,
            )
        };
        if got <= 0 {
            // SAFETY: `s` is live; the partial body stays in `rec_body` for the next call.
            return unsafe { ssl3_read_bytes_rlayer_return(s, got) };
        }
        // SAFETY: `got` is a positive count no larger than `want`.
        unsafe { (*s).rec_body_len = off + got as usize };
    }

    // The record is complete; reset the accumulator before processing it.
    // SAFETY: `s` is live.
    unsafe {
        (*s).rec_hdr_len = 0;
        (*s).rec_body_len = 0;
    }

    // Phase 17.2c: once the TLS 1.3 read key is installed the record is AEAD-protected
    // (`tls13_dec`, `ssl/record/methods/tls13_meth.c`).
    // SAFETY: `s` is live per the caller's contract.
    if unsafe { (*s).dec_active } != 0 {
        // Phase 17: a TLS1.2 AEAD record (`tls1_enc`, `ssl/t1_enc.c`) decrypts whenever the read
        // key is installed; unlike TLS1.3 the outer type is the real content type.
        // SAFETY: `s` is live; `rec_body` holds `len` bytes; `rectype` is writable.
        if unsafe { (*s).version } == TLS1_2_VERSION {
            // SAFETY: `s` is live; `rec_body` holds `len` bytes; `buf`/`rectype` are the caller's.
            return unsafe {
                crate::ssl::t1_enc::tls12_decrypt_record(
                    s,
                    &hdr,
                    (*s).rec_body.as_ptr(),
                    len,
                    buf,
                    cap,
                    rectype,
                ) as c_int
            };
        }
        // `SSL3_RT_APPLICATION_DATA` (23) is the outer type of every TLS 1.3 protected record; a
        // middlebox-compatibility `ChangeCipherSpec` (20) or a plaintext alert is *not* protected
        // and is read straight through (`tls13_dec`, `ssl/record/methods/tls13_meth.c`).
        if hdr[0] != SSL3_RT_APPLICATION_DATA {
            if len > cap {
                return -1;
            }
            if len != 0 {
                // SAFETY: `buf` is `cap >= len` writable bytes; `rec_body` holds `len` bytes.
                unsafe { ptr::copy_nonoverlapping((*s).rec_body.as_ptr(), buf, len) };
            }
            // SAFETY: `rectype` is writable per the contract.
            unsafe { *rectype = hdr[0] };
            return len as c_int;
        }
        // SAFETY: `s` is live; `rec_body` holds `len` bytes; `rectype` is writable.
        return unsafe {
            crate::ssl::tls13_enc::tls13_decrypt_record(
                s,
                &hdr,
                (*s).rec_body.as_ptr(),
                len,
                buf,
                cap,
                rectype,
            ) as c_int
        };
    }

    if len > cap {
        return -1;
    }
    if len != 0 {
        // SAFETY: `buf` is `cap >= len` writable bytes; `rec_body` holds `len` bytes.
        unsafe { ptr::copy_nonoverlapping((*s).rec_body.as_ptr(), buf, len) };
    }
    // SAFETY: `rectype` is writable per the contract.
    unsafe { *rectype = hdr[0] };
    len as c_int
}

/// Read the next TLS 1.3 handshake message into `buf`, returning its length (including the
/// four-byte handshake header) or `-1` when the peer BIO is empty or the stream is malformed.
///
/// The authority's message layer (`tls_get_message_header`/`tls_get_message_body`,
/// `ssl/statem/statem_lib.c`) reads from a buffer filled by `ssl3_read_bytes`, which may carry
/// several handshake messages (its server flight is flushed as one record, `statem_flush`,
/// `ssl/statem/statem.c:945`) and may interleave a middlebox-compatibility `ChangeCipherSpec`
/// record (type 20). This reduced reader buffers the decrypted record content on the connection
/// (`rd_msg_buf`) and hands the driver one message per call, skipping bare `ChangeCipherSpec`
/// records.
///
/// # Safety
/// `s` must be a live connection; `buf` must be writable for `cap` bytes.
pub(crate) unsafe fn tls13_next_handshake_message(s: *mut Ssl, buf: *mut u8, cap: usize) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        // Deliver the next buffered message, if one remains.
        if (*s).rd_msg_off + 4 <= (*s).rd_msg_len {
            let p = (*s).rd_msg_off;
            let blen = (((*s).rd_msg_buf[p + 1] as usize) << 16)
                | (((*s).rd_msg_buf[p + 2] as usize) << 8)
                | ((*s).rd_msg_buf[p + 3] as usize);
            let msg_len = 4 + blen;
            if p + msg_len <= (*s).rd_msg_len && msg_len <= cap {
                core::ptr::copy_nonoverlapping((*s).rd_msg_buf.as_ptr().add(p), buf, msg_len);
                (*s).rd_msg_off = p + msg_len;
                return msg_len as c_int;
            }
            return -1;
        }

        // Read one record. `SSL3_RT_CHANGE_CIPHER_SPEC` (20) records are interleaved by middleware
        // compatibility and skipped; any other non-handshake record is not part of the flight.
        loop {
            let mut rt = 0u8;
            let n = ssl3_read_bytes(
                s,
                &mut rt,
                (*s).rd_msg_buf.as_mut_ptr(),
                (*s).rd_msg_buf.len(),
            );
            if n <= 0 {
                return -1;
            }
            (*s).rd_msg_len = n as usize;
            (*s).rd_msg_off = 0;
            match rt {
                22 => break,    // SSL3_RT_HANDSHAKE
                20 => continue, // SSL3_RT_CHANGE_CIPHER_SPEC
                _ => {
                    // The record was fully consumed from the BIO and discarded. Clear the
                    // buffered-message state before reporting the wait: leaving `rd_msg_len`
                    // pointing at this non-handshake record would let the next call parse its
                    // body as a handshake header (a record type confusion).
                    (*s).rd_msg_len = 0;
                    (*s).rd_msg_off = 0;
                    return -1;
                }
            }
        }

        if (*s).rd_msg_len < 4 {
            return -1;
        }
        let blen = (((*s).rd_msg_buf[1] as usize) << 16)
            | (((*s).rd_msg_buf[2] as usize) << 8)
            | ((*s).rd_msg_buf[3] as usize);
        let msg_len = 4 + blen;
        if msg_len > (*s).rd_msg_len || msg_len > cap {
            return -1;
        }
        core::ptr::copy_nonoverlapping((*s).rd_msg_buf.as_ptr(), buf, msg_len);
        (*s).rd_msg_off = msg_len;
        msg_len as c_int
    }
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

/// `SSL3_RT_APPLICATION_DATA` — `ssl3.h` (23): the outer type of every TLS 1.3 protected record.
const SSL3_RT_APPLICATION_DATA: u8 = 23;
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

#[cfg(test)]
mod boundary_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::runtime::bio::bss_mem::BIO_s_mem;
    use crate::runtime::bio::{BIO_ctrl_pending, BIO_free, BIO_new, BIO_write};
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::adv_alloc::zeroed_ssl;
    use crate::ssl::statem::statem::ossl_statem_in_error;

    /// Build a frame-owned zeroed connection over a fresh memory BIO carrying `bytes`. The
    /// caller releases the BIO and the block.
    ///
    /// # Safety
    /// The returned pointers are exclusively owned by the caller; `bytes` is only read here.
    unsafe fn connection_with_read_bytes(
        bytes: &[u8],
    ) -> (*mut Ssl, *mut crate::runtime::bio::Bio) {
        // SAFETY: `zeroed_ssl` answers NULL or a live zeroed connection this frame owns.
        let s = unsafe { zeroed_ssl() };
        assert!(!s.is_null(), "the zeroed connection block must allocate");
        // SAFETY: no preconditions.
        let bio = unsafe { BIO_new(BIO_s_mem()) };
        assert!(!bio.is_null(), "the memory BIO must allocate");
        // SAFETY: `bio` is live; `bytes` is readable for its length; `s` is live.
        unsafe {
            if !bytes.is_empty() {
                assert_eq!(
                    BIO_write(bio, bytes.as_ptr().cast(), bytes.len() as c_int),
                    bytes.len() as c_int,
                    "the fixture record must be queued in full"
                );
            }
            (*s).rbio = bio;
            (*s).version = TLS1_2_VERSION;
        }
        (s, bio)
    }

    /// The authority requires an alert packet to be exactly two bytes
    /// (`PACKET_remaining(&alert) != 0`). A three-byte warning/close_notify must be an invalid
    /// alert, not a graceful shutdown.
    #[test]
    fn an_over_long_alert_is_invalid_not_close_notify() {
        // `SSL3_RT_ALERT` (21), TLS1.2 record version, length 3, `warning || close_notify || 0`.
        let record = [21u8, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00];
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record);
            let mut rt = 0u8;
            let mut buf = [0u8; 16];
            let n = ssl3_read_bytes(s, &mut rt, buf.as_mut_ptr(), buf.len());
            assert_eq!(n, -1, "a non-two-byte alert is fatal");
            assert_ne!(ossl_statem_in_error(s), 0, "the connection is poisoned");
            assert_eq!(
                (*s).shutdown & SSL_RECEIVED_SHUTDOWN,
                0,
                "not a clean shutdown"
            );
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A non-handshake record read by the reduced TLS1.3 message reader is consumed and
    /// discarded. Its body must not be reparsed as a handshake message on the next call.
    #[test]
    fn a_discarded_non_handshake_record_is_not_reparsed_as_handshake() {
        // Application data whose body would satisfy the handshake framing (`22 || 0 || 0 || 1`),
        // followed by a real handshake record with the indistinguishable prefix and a different
        // final byte.
        let app_data = [23u8, 0x03, 0x03, 0x00, 0x05, 22, 0x00, 0x00, 0x01, 0xAA];
        let handshake = [22u8, 0x03, 0x03, 0x00, 0x05, 22, 0x00, 0x00, 0x01, 0xBB];
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&app_data);
            assert_eq!(
                BIO_write(bio, handshake.as_ptr().cast(), handshake.len() as c_int),
                handshake.len() as c_int
            );
            let mut out = [0u8; 16];
            let first = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert!(
                first <= 0,
                "application data is not part of the handshake flight"
            );
            let second = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert_eq!(second, 5, "the next handshake record is delivered");
            assert_eq!(
                out[4], 0xBB,
                "the discarded application-data body was not reparsed as handshake"
            );
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// `SSL_write(s, NULL, 0)` is a legal empty write. The authority's `tot == len` arm writes no
    /// record; it must not pass the NULL source to the TLS1.3 encoder either.
    #[test]
    fn a_zero_length_write_emits_no_record_and_never_dereferences_null() {
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let s = zeroed_ssl();
            assert!(!s.is_null(), "the zeroed connection block must allocate");
            let bio = BIO_new(BIO_s_mem());
            assert!(!bio.is_null(), "the memory BIO must allocate");
            (*s).version = TLS1_3_VERSION;
            (*s).enc_active = 1;
            // Reach the TLS1.3 encoder body once the zero-length guard is absent: a valid IV
            // length is required before it copies the (NULL) plaintext.
            (*s).cipher_iv_len = 12;
            (*s).cipher_tag_len = 16;
            (*s).wbio = bio;
            let r = ssl3_write_bytes(s, 23, ptr::null(), 0);
            assert_eq!(r, 1, "the authority's empty-write arm succeeds");
            assert_eq!(BIO_ctrl_pending(bio), 0, "no record bytes are queued");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }
}
