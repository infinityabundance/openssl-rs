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

use crate::runtime::bio::iolib::{BIO_read, BIO_write};
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

    // Phase 17.2c: once the TLS 1.3 write key is installed every record is AEAD-protected
    // (`tls13_enc`, `ssl/record/methods/tls13_meth.c`).
    // SAFETY: `s` is live per the caller's contract.
    if version == TLS1_3_VERSION && unsafe { (*s).enc_active } != 0 {
        let mut rec = [0u8; 17000];
        // SAFETY: `s` is live; `rec` is the record buffer; `buf` is `len` readable.
        let n = unsafe {
            crate::ssl::tls13_enc::tls13_encrypt_record(s, type_, buf, len, rec.as_mut_ptr())
        };
        if n < 0 {
            return -1;
        }
        // SAFETY: `s` is live; `wbio` is the caller's BIO.
        unsafe {
            if BIO_write((*s).wbio, rec.as_ptr().cast(), n as c_int) <= 0 {
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

/// `int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf, size_t len,` —
/// `ssl/record/rec_layer_s3.c:612-...`, reduced to the plaintext, single-record, no-retry arm the
/// server's first read needs.
///
/// The authority's read pipeline runs the record method's `read_record` and the message layer above
/// it; this reduced form reads one `type || version || length` header and its body from `rbio` and
/// reports the body length, which is the ClientHello handshake message. The buffering BIO, the
/// read-ahead queue, the encryption path and the `SSL3_RT_MAX_PLAIN_LENGTH` fragmentation are not
/// modelled (recorded in `src/ssl/mod.rs`).
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
    // Phase 17.2c: once the TLS 1.3 read key is installed the record is AEAD-protected
    // (`tls13_dec`, `ssl/record/methods/tls13_meth.c`).
    // SAFETY: `s` is live per the caller's contract.
    if unsafe { (*s).dec_active } != 0 {
        let mut hdr = [0u8; SSL3_RT_HEADER_LENGTH];
        // SAFETY: `s` is live; `hdr` is 5 writable bytes and `rbio` is the caller's.
        let got = unsafe {
            BIO_read(
                (*s).rbio,
                hdr.as_mut_ptr().cast(),
                SSL3_RT_HEADER_LENGTH as c_int,
            )
        };
        if got != SSL3_RT_HEADER_LENGTH as c_int {
            return -1;
        }
        let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
        // `SSL3_RT_APPLICATION_DATA` (23) is the outer type of every TLS 1.3 protected record; a
        // middlebox-compatibility `ChangeCipherSpec` (20) or a plaintext alert is *not* protected
        // and is read straight through (`tls13_dec`, `ssl/record/methods/tls13_meth.c`).
        if hdr[0] != SSL3_RT_APPLICATION_DATA {
            if len > cap {
                return -1;
            }
            if len != 0 {
                // SAFETY: `buf` is `cap >= len` writable bytes and `rbio` is the caller's.
                let n = unsafe { BIO_read((*s).rbio, buf.cast(), len as c_int) };
                if n != len as c_int {
                    return -1;
                }
            }
            // SAFETY: `rectype` is writable per the contract.
            unsafe { *rectype = hdr[0] };
            return len as c_int;
        }
        let mut ct = [0u8; 17000];
        if len > ct.len() {
            return -1;
        }
        if len != 0 {
            // SAFETY: `ct` is `len` writable bytes and `rbio` is the caller's.
            let n = unsafe { BIO_read((*s).rbio, ct.as_mut_ptr().cast(), len as c_int) };
            if n != len as c_int {
                return -1;
            }
        }
        // SAFETY: `s` is live; the buffers are this frame's; `rectype` is writable.
        return unsafe {
            crate::ssl::tls13_enc::tls13_decrypt_record(
                s,
                &hdr,
                ct.as_ptr(),
                len,
                buf,
                cap,
                rectype,
            ) as c_int
        };
    }

    let mut hdr = [0u8; SSL3_RT_HEADER_LENGTH];
    // SAFETY: `s` is live; `hdr` is 5 writable bytes and `rbio` is the caller's.
    let got = unsafe {
        BIO_read(
            (*s).rbio,
            hdr.as_mut_ptr().cast(),
            SSL3_RT_HEADER_LENGTH as c_int,
        )
    };
    if got != SSL3_RT_HEADER_LENGTH as c_int {
        return -1;
    }
    let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
    if len > cap {
        return -1;
    }
    if len != 0 {
        // SAFETY: `buf` is `cap >= len` writable bytes and `rbio` is the caller's.
        let n = unsafe { BIO_read((*s).rbio, buf.cast(), len as c_int) };
        if n != len as c_int {
            return -1;
        }
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
                _ => return -1,
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
