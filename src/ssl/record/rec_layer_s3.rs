//! The reduced `ssl/record/rec_layer_s3.c`: the record read/write path, the TLS 1.3 handshake
//! assembly reader, the `rlayer` accessors and the exported `SSL_*` state readers.
//!
//! ## The reconstruction
//!
//! The file is split into a small, contracted connection boundary and a safe interior. Every
//! entry point acquires the connection as a `&mut Ssl` exactly once; the record accumulation,
//! framing, alert decisions and retry classification above that reference are ordinary safe
//! Rust. The remaining `unsafe` operations are the seam items documented in the boundary section
//! below: the caller's output region ([`OutBuf`]), the record write scratch ([`Scratch`]), the
//! BIO transport calls and the AEAD sinks.
//!
//! The read outcome is a discriminated [`ReadStatus`], not a `c_int`: "complete", "would block",
//! "fatal", "clean EOF", "unexpected EOF" and "transport failure" are separate variants, and
//! only `Complete` carries record bytes. The previous `c_int` form returned `0` both for a
//! completed zero-length record and for end of stream, which made a completed empty record
//! indistinguishable from a retry at the layer above; that confusion is now unrepresentable.
//!
//! ## Record layer scope
//!
//! The authority's record layer proper — `RECORD_LAYER_*`, the method objects, read-ahead and
//! pipelining — is not modelled here (recorded in `src/ssl/mod.rs`). The observable surface this
//! file owns is the read/write path the handshake and application readers call, plus the two
//! length accessors and the two state-string readers.
//!
//! ## Recorded divergences
//!
//! * **The record-read method is not modelled; `rlayer.rstate` is a scalar field.** The authority
//!   installs a read method on the connection (`RECORD_LAYER_reset`, `rec_layer_s3.c:72`) and
//!   reaches its `tls_get_state` through `rl->rrlmethod`; this crate keeps the state value the
//!   switch reads (`rstate`) and the switch's mapping, but not the method object. `rstate` stays
//!   `SSL_ST_READ_HEADER`, so the `rrlmethod == NULL` guard (`rec_layer_s3.c:228-229`) is
//!   unreachable.
//! * **The setter's stored value has no public reader on either side.** The authority's
//!   `SSL_CTX_set_default_read_buffer_len` and `SSL_set_default_read_buffer_len` write fields that
//!   only the record layer allocator reads; the court drives the calls but cannot compare the
//!   stored length, and records that rather than inventing a reader.
//! * **A zero-length record reports its content type.** The authority assigns `*recvd_type`
//!   before its `len == 0` arm; the previous reduced reader answered 0 without writing
//!   `*rectype`. The reconstructed path follows the authority (the return value stays 0).
//! * **Buffered records are not pipelined.** `read_record` decodes one record per call; the
//!   authority's `read_ahead`/`max_pipelines` batching is not modelled.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};
use core::ptr;

use crate::runtime::bio::iolib::{BIO_read, BIO_write};
use crate::runtime::bio::{
    BIO_ctrl, Bio, BIO_CTRL_FLUSH, BIO_FLAGS_IN_EOF, BIO_FLAGS_READ, BIO_FLAGS_WRITE,
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
use crate::ssl::statem::statem::{ossl_statem_fatal, ossl_statem_send_fatal};

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

// =============================================================================
// The `Ssl` <-> record-layer boundary
// =============================================================================
//
// This file is the whole of the reduced record layer. It touches the connection
// in exactly two directions, and both are confined to this section:
//
// * **into `Ssl`** — the read accumulators (`rec_hdr`, `rec_hdr_len`, `rec_body`,
//   `rec_body_len`), the handshake assembly buffer (`rd_msg_buf`, `rd_msg_len`,
//   `rd_msg_off`), the protocol/cipher state that selects a record path
//   (`version`, `enc_active`, `dec_active`, `hand_state`, `renegotiate`,
//   `hello_retry_request`, `cipher_iv_len`, `cipher_tag_len`), the transport and
//   error state (`rbio`, `wbio`, `rwstate`, `options`, `shutdown`, `warn_alert`,
//   `alert_count`, `fatal_alert`, `wpend_tot`, `rstate`), and the two read-buffer
//   settings.
// * **back out of `Ssl`** — exactly the entry points below: `ssl3_write_bytes`,
//   `ssl3_read_bytes`, `tls13_next_handshake_message`,
//   `record_layer_write_pending`, `record_layer_read_pending` and the four
//   exported `SSL_*` accessors.
//
// The connection is reached through a `&mut Ssl` acquired once per entry point
// (the callers are the C ABI, whose contract is that the pointer is a live,
// exclusively borrowed connection). Everything above that reference is safe
// Rust; the remaining `unsafe` operations are the small, individually contracted
// seam listed here:
//
// * [`OutBuf`] — the caller's writable region with a written-length ledger, so a
//   slice is only ever published over bytes this read wrote.
// * [`Sink`] — where a record body goes: the caller's region, or a *checked
//   index* into the connection's own assembly tail.
// * [`Scratch`] — the one owner of the record write scratch; its `Drop` is the
//   only release on every return path.
// * [`Scratch::region`], `OutBuf::from_raw` — the two typed-slice constructions
//   over memory that is promised writable but not initialised.
// * `BIO_read`/`BIO_write`/`BIO_ctrl` and the AEAD sinks — the transport and
//   cipher seams.
// * `fatal`, `send_fatal` — the one state-machine transition each.
//
// ## Record buffer ownership
//
// `rec_hdr`, `rec_body` and `rd_msg_buf` are inline fields of `Ssl`: the `Ssl`
// block is their single owner and their lifecycle is the connection's lifecycle.
// Nothing in this file allocates, replaces or frees them, so "released exactly
// once" is the `Ssl` release (`SSL_free`), outside this file. The only heap
// resource here is the write scratch, owned by [`Scratch`] for the whole write.
//
// The accumulator lengths (`rec_hdr_len`, `rec_body_len`, `rd_msg_len`,
// `rd_msg_off`) are re-validated against their buffers on every use, so a
// corrupted or stale length is a refusal, never an out-of-range slice.

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
/// for `len` bytes (`buf` is never dereferenced when `len == 0`). No application-controlled BIO
/// callback invoked below may re-enter this connection.
pub(crate) unsafe fn ssl3_write_bytes(s: *mut Ssl, type_: u8, buf: *const u8, len: usize) -> c_int {
    if len == 0 {
        return 1;
    }
    // SAFETY: `s` is live and exclusively borrowed per the contract.
    let s = unsafe { &mut *s };
    // The plaintext is a C input region, validated once here; every fragment below is a checked
    // sub-slice of this single borrow, so no fragment pointer can leave the caller's range.
    // SAFETY: `buf` is readable for `len` bytes per the contract and `len != 0`.
    let src: &[u8] = unsafe { core::slice::from_raw_parts(buf, len) };
    let needs_scratch = write_needs_scratch(s);
    // The encrypted record paths need a record-sized scratch block. It is heap-allocated through
    // the crate's allocator seam at the authority's own write-buffer site so no record-sized frame
    // lands on the caller's thread stack (a 32 KiB accept thread, radsecproxy's, previously
    // overflowed here). `Scratch` is the block's only owner, so its `Drop` releases it exactly
    // once on every return below, including the encoder and BIO failure paths.
    let mut scratch = match needs_scratch {
        true => match Scratch::allocate() {
            Some(block) => Some(block),
            // The authority's `ssl3_setup_write_buffer` failure.
            None => return -1,
        },
        false => None,
    };
    let mut off = 0usize;
    while off < src.len() {
        // `off < src.len()`, so the remainder is non-empty and in bounds.
        let Some(remaining) = src.get(off..) else {
            return -1;
        };
        let chunk = remaining.len().min(SSL3_RT_MAX_PLAIN_LENGTH);
        let Some(fragment) = remaining.get(..chunk) else {
            return -1;
        };
        // A fresh writable region over the same owned block for this fragment. The encoder writes
        // it and reports how many bytes; only that prefix is ever read back.
        let rec = scratch.as_mut().map(Scratch::region);
        if ssl3_write_one_record(s, type_, fragment, rec) <= 0 {
            return -1;
        }
        let Some(next) = off.checked_add(chunk) else {
            return -1;
        };
        off = next;
    }
    1
}

/// Whether [`ssl3_write_one_record`] will take an encrypted path and therefore need the record
/// scratch block (`tls13_enc`/`tls1_enc`, selected by the installed version and cipher state).
fn write_needs_scratch(s: &Ssl) -> bool {
    s.enc_active != 0 && (s.version == TLS1_3_VERSION || s.version == TLS1_2_VERSION)
}

/// The record encoders' scratch block: one owner, one release.
///
/// The block is allocated through the crate's allocator seam at the authority's write-buffer site
/// and released by the [`OwnedBuf`] field's `Drop` on every return path of
/// [`ssl3_write_bytes`]. The newtype adds no ownership; it exists so the release can be observed
/// by address in the boundary tests.
struct Scratch(OwnedBuf);

impl Scratch {
    /// The authority's write-buffer allocation (`p = OPENSSL_malloc(len)`,
    /// `ssl/record/ssl3_buffer.c:124`), sized for the largest encrypted record.
    fn allocate() -> Option<Self> {
        OwnedBuf::new(
            SSL3_RT_MAX_ENCRYPTED_LENGTH,
            SeamFile::new(WRITE_BUF_FILE),
            WRITE_BUF_LINE,
        )
        .map(Self)
    }

    /// The whole allocation as an [`OutBuf`]: writable, not promised initialised, and never read
    /// before the encoder reports how many bytes it wrote.
    fn region(&mut self) -> OutBuf {
        // SAFETY: `OwnedBuf::new` allocated exactly `SSL3_RT_MAX_ENCRYPTED_LENGTH` bytes through
        // the seam and this handle exclusively owns them for its lifetime; no other reference
        // aliases the block.
        unsafe { OutBuf::from_raw(self.0.as_ptr(), SSL3_RT_MAX_ENCRYPTED_LENGTH) }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        #[cfg(test)]
        scratch_probe::record(self.0.as_ptr());
        // The `OwnedBuf` field's own `Drop` performs the single release.
    }
}

/// Test-only observation of the scratch release, by address. Thread-local so a concurrent test in
/// another thread cannot perturb it.
#[cfg(test)]
mod scratch_probe {
    use core::cell::RefCell;

    thread_local! {
        pub(super) static RELEASED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(ptr: *mut u8) {
        RELEASED.with(|released| released.borrow_mut().push(ptr as usize));
    }

    pub(super) fn take() -> Vec<usize> {
        RELEASED.with(|released| core::mem::take(&mut *released.borrow_mut()))
    }
}

/// Write `p` to the connection's write BIO, resuming a short `BIO_write`.
///
/// The authority's `ssl3_write_bytes` keeps `rlayer.wpend_tot` and re-enters the write method when
/// the BIO accepts only part of a record (`rec_layer_s3.c:459-488`); this reduced form loops until
/// every byte is accepted, so a short `write(2)` cannot silently truncate a record. An `EAGAIN`
/// still surfaces as -1 with `BIO_FLAGS_WRITE` (the pending-write resumption is a recorded
/// boundary).
///
/// The connection invariant this private function relies on is the entry point's: ``s`'s `wbio`
/// is NULL or a live BIO that the caller owns. No application-controlled BIO callback invoked
/// below may re-enter this connection.
fn ssl3_write_all(s: &mut Ssl, p: &[u8]) -> c_int {
    if p.is_empty() {
        return 1;
    }
    let mut off = 0usize;
    while off < p.len() {
        // `off < p.len()`, so the remainder is non-empty and in bounds.
        let Some(remaining) = p.get(off..) else {
            return -1;
        };
        // `BIO_write` takes an `int`; cap the offered length rather than truncating the cast.
        let offered = remaining.len().min(c_int::MAX as usize);
        let Ok(offered_i32) = c_int::try_from(offered) else {
            return -1;
        };
        let wbio = s.wbio;
        // SAFETY: `wbio` is NULL or a live BIO, both accepted by `BIO_write`; `remaining` is
        // `offered` readable bytes.
        let got = unsafe { BIO_write(wbio, remaining.as_ptr().cast(), offered_i32) };
        if got <= 0 {
            // The authority's `ossl_tls_handle_rlayer_return` sets `rwstate = SSL_WRITING` on a
            // retryable record write (`rec_layer_s3.c:491-498`), which `SSL_get_error` turns into
            // `SSL_ERROR_WANT_WRITE`.
            if bio_flags(wbio) & BIO_FLAGS_WRITE != 0 {
                s.rwstate = SSL_WRITING;
            }
            return -1;
        }
        // A BIO that claims to have accepted more than it was offered violates `BIO_write`'s
        // contract; advancing by that count would walk `off` past the slice and silently truncate.
        let Ok(written) = usize::try_from(got) else {
            s.rwstate = SSL_NOTHING;
            return -1;
        };
        if written > offered {
            s.rwstate = SSL_NOTHING;
            return -1;
        }
        let Some(next) = off.checked_add(written) else {
            return -1;
        };
        off = next;
    }
    1
}

/// Write exactly one record of at most `SSL3_RT_MAX_PLAIN_LENGTH` plaintext bytes.
///
/// The connection invariant is the entry point's: `s.wbio` is NULL or a live BIO that the caller
/// owns, and no application-controlled BIO callback invoked below may re-enter this connection.
/// `input` is at most [`SSL3_RT_MAX_PLAIN_LENGTH`] bytes; `rec` is the write scratch's whole
/// region when the active cipher state selects an encrypted path.
fn ssl3_write_one_record(s: &mut Ssl, type_: u8, input: &[u8], rec: Option<OutBuf>) -> c_int {
    // The record encoders size their output from `input.len()`; both the encoded scratch block and
    // the two-byte record-length field are bounded by the plaintext fragment limit. The only
    // caller ([`ssl3_write_bytes`]) fragments at this length, so this is a defensive refusal.
    if input.len() > SSL3_RT_MAX_PLAIN_LENGTH {
        return -1;
    }
    let (version, hand_state, renegotiate, hrr, enc_active) = (
        s.version,
        s.hand_state,
        s.renegotiate,
        s.hello_retry_request,
        s.enc_active,
    );

    // Phase 17.2c: once the TLS 1.3 write key is installed every record is AEAD-protected
    // (`tls13_enc`, `ssl/record/methods/tls13_meth.c`).
    if version == TLS1_3_VERSION && enc_active != 0 {
        let Some(mut rec) = rec else {
            return -1;
        };
        // SAFETY: `s` is live; `rec` is the whole scratch allocation; `input` is
        // `input.len()` readable bytes.
        let n = unsafe {
            crate::ssl::tls13_enc::tls13_encrypt_record(
                s as *mut Ssl,
                type_,
                input.as_ptr(),
                input.len(),
                rec.ptr(),
            )
        };
        // The encoder may not write past the region it was given; record the prefix it reports.
        let Ok(n) = usize::try_from(n) else {
            return -1;
        };
        if rec.set_written(n).is_none() {
            return -1;
        }
        if ssl3_write_all(s, rec.written()) <= 0 {
            return -1;
        }
        send_flush(s);
        return 1;
    }

    // Phase 17: a TLS1.2 AEAD record (`tls1_enc`, `ssl/t1_enc.c`). The header, explicit nonce and
    // tag are built by the TLS1.2 record method, so no generic header follows.
    if version == TLS1_2_VERSION && enc_active != 0 {
        let Some(mut rec) = rec else {
            return -1;
        };
        // SAFETY: `s` is live; `rec` is the whole scratch allocation; `input` is
        // `input.len()` readable bytes.
        let n = unsafe {
            crate::ssl::t1_enc::tls12_encrypt_record(
                s as *mut Ssl,
                type_,
                input.as_ptr(),
                input.len(),
                rec.ptr(),
            )
        };
        // SAFETY: as in the TLS1.3 arm.
        let Ok(n) = usize::try_from(n) else {
            return -1;
        };
        if rec.set_written(n).is_none() {
            return -1;
        }
        if ssl3_write_all(s, rec.written()) <= 0 {
            return -1;
        }
        send_flush(s);
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

    // `input.len() <= SSL3_RT_MAX_PLAIN_LENGTH` was checked above, so both the two-byte length
    // field and the 16-bit version field are represented exactly.
    let hdr: [u8; SSL3_RT_HEADER_LENGTH] = [
        type_,
        (recversion >> 8) as u8,
        recversion as u8,
        (input.len() >> 8) as u8,
        input.len() as u8,
    ];

    if ssl3_write_all(s, &hdr) <= 0 {
        return -1;
    }
    if !input.is_empty() && ssl3_write_all(s, input) <= 0 {
        return -1;
    }
    // `ssl3_do_write` returns through `statem_flush`; a memory BIO needs no flush, but the
    // authority's `BIO_flush` on the write path is performed so a flush-requiring BIO is served.
    send_flush(s);
    1
}

/// `BIO_flush` on the connection's write BIO (`statem_flush`, `ssl/statem/statem.c:945`).
fn send_flush(s: &Ssl) {
    let wbio = s.wbio;
    // SAFETY: `wbio` is NULL or a live BIO and `BIO_ctrl` accepts NULL.
    unsafe { BIO_ctrl(wbio, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
}

/// The flag word of a (possibly NULL) BIO.
fn bio_flags(bio: *mut Bio) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: `bio` is non-NULL; the caller established it is a live BIO.
    unsafe { (*bio).flags }
}

/// The handshake message length declared by `bytes`' four-byte header (header plus body), or
/// `None` when the header is not buffered yet or the declared length overflows `usize`.
fn framed_message_len(bytes: &[u8]) -> Option<usize> {
    let header = bytes.get(..4)?;
    let body = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    4usize.checked_add(body)
}

/// The record accumulator's new length after `got` bytes were added at `off`.
///
/// `None` (and therefore a refusal) when the count exceeds the space the read was offered or when
/// the resulting length would leave the accumulator's `cap`-byte extent.
fn accumulated(off: usize, got: c_int, offered: usize, cap: usize) -> Option<usize> {
    let got = usize::try_from(got).ok()?;
    if got > offered {
        return None;
    }
    off.checked_add(got).filter(|n| *n <= cap)
}

/// A writable output region for one record read, with a ledger of what was written.
///
/// The construction is the boundary proof: the caller guarantees that `ptr` is valid for writes
/// of `cap` bytes for as long as the handle is used, and may be dangling when `cap == 0` (it is
/// never dereferenced then). The methods are then safe and enforce the remaining rule: only the
/// bytes this read actually wrote can ever be published as a `&[u8]`, so an unwritten or
/// uninitialised byte can never be read.
struct OutBuf {
    ptr: *mut u8,
    cap: usize,
    written: usize,
}

impl OutBuf {
    /// # Safety
    /// `ptr` must be valid for writes of `cap` bytes for the whole time this handle (or a
    /// reference derived from it) is used, and `ptr` may be dangling only when `cap == 0`. The
    /// region must not overlap any memory read through another borrow while this handle is live.
    unsafe fn from_raw(ptr: *mut u8, cap: usize) -> Self {
        Self {
            ptr,
            cap,
            written: 0,
        }
    }

    fn cap(&self) -> usize {
        self.cap
    }

    fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Writes `src` and records it as the output, or refuses when it does not fit.
    fn write(&mut self, src: &[u8]) -> Option<usize> {
        if src.len() > self.cap {
            return None;
        }
        if !src.is_empty() {
            // SAFETY: `from_raw` promises `ptr` writable for `cap >= src.len()` bytes, and the
            // constructor's overlap precondition excludes the source region.
            unsafe { ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, src.len()) };
        }
        self.written = src.len();
        Some(src.len())
    }

    /// Records that a callee wrote `n` bytes into the region (the AEAD sink), refusing a count
    /// beyond the region.
    fn set_written(&mut self, n: usize) -> Option<usize> {
        if n > self.cap {
            return None;
        }
        self.written = n;
        Some(n)
    }

    /// The bytes written so far. Empty when nothing was written, so no slice is ever formed over
    /// a possibly-dangling or uninitialised region.
    fn written(&self) -> &[u8] {
        if self.written == 0 {
            return &[];
        }
        // SAFETY: both setters enforce `written <= cap`, and exactly those bytes were written by
        // `write` or reported by the AEAD sink; `written != 0` implies `cap != 0` and therefore a
        // valid non-NULL `ptr`.
        unsafe { core::slice::from_raw_parts(self.ptr, self.written) }
    }
}

/// The outcome of one record read.
///
/// This replaces the bare `c_int` the reduced reader used to return, where `0` meant both "a
/// complete zero-length record" and "end of stream", and `-1` meant retry, a fatal alert, a
/// record overflow and a transport failure. Only [`ReadStatus::Complete`] carries a length, so no
/// other outcome can be consumed as record bytes; and a partial read is `WouldBlock`, never a
/// completed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadStatus {
    /// A complete record was delivered; `len` bytes are the initialised output.
    Complete { record_type: u8, len: usize },
    /// The transport has no data now: a retry with the partial accumulator retained
    /// (`rwstate = SSL_READING`). The C ABI answer is -1.
    WouldBlock,
    /// Fatal, poisoned, with the error queued. The C ABI answer is -1.
    Fatal,
    /// Clean end of stream (`close_notify`, or an unexpected EOF ignored under
    /// `SSL_OP_IGNORE_UNEXPECTED_EOF`). The C ABI answer is 0.
    Eof,
    /// Unexpected EOF: poisoned with the error queued, but the authority answers 0.
    FatalEof,
    /// Transport failure with no alert queued. The C ABI answer is -1.
    Failed,
}

/// A fully accumulated record header.
struct RecordHead {
    hdr: [u8; SSL3_RT_HEADER_LENGTH],
    /// The body extent declared by the header, checked against `rec_body`.
    body_len: usize,
}

/// Where [`read_record`] delivers a record body.
enum Sink<'a> {
    /// A caller-supplied output region, disjoint from the connection by the entry point's
    /// contract.
    External(&'a mut OutBuf),
    /// The unused tail of the connection's handshake assembly buffer, starting at `used`
    /// (`used <= rd_msg_buf.len()`). Described by an index, never by a pointer, so no raw alias
    /// into `Ssl` outlives the record read.
    AssemblyTail { used: usize },
}

impl Sink<'_> {
    /// The (writable pointer, capacity) pair for an AEAD sink.
    ///
    /// # Safety
    /// `sp` is a live connection and `used` (if any) is at most `rd_msg_buf.len()`; the returned
    /// region is not written through any other reference while the callee uses it.
    unsafe fn slot(&mut self, sp: *mut Ssl) -> Result<(*mut u8, usize), ReadStatus> {
        match self {
            Sink::External(out) => Ok((out.ptr(), out.cap())),
            Sink::AssemblyTail { used } => {
                // SAFETY: `sp` is live; `used <= rd_msg_buf.len()` by the assembly loop.
                let tail = unsafe { (*sp).rd_msg_buf.get_mut(*used..) };
                match tail {
                    Some(tail) => Ok((tail.as_mut_ptr(), tail.len())),
                    None => Err(ReadStatus::Failed),
                }
            }
        }
    }

    /// Records a length written by a callee. The caller has already checked it against the
    /// capacity returned by [`Sink::slot`].
    fn record_written(&mut self, n: usize) -> Option<usize> {
        match self {
            Sink::External(out) => out.set_written(n),
            // The output is the connection's own buffer; the length is returned to the caller,
            // which knows the offset.
            Sink::AssemblyTail { .. } => Some(n),
        }
    }
}

/// The record layer's one fatal transition (`SSLfatal`).
fn fatal(s: &mut Ssl, alert: c_int, reason: c_int) {
    // SAFETY: `s` is a live connection, established by the `&mut Ssl`; the callee does not retain
    // the pointer and no application callback runs.
    unsafe { ossl_statem_fatal(s as *mut Ssl, alert, reason) };
}

/// The fatal transition with no alert echoed to the peer (`SSL_AD_NO_ALERT`).
fn send_fatal(s: &mut Ssl, alert: c_int) {
    // SAFETY: as for [`fatal`]: `s` is live and no application callback runs.
    unsafe { ossl_statem_send_fatal(s as *mut Ssl, alert) };
}

/// The flag word of the connection's read BIO, or 0 when it is unset.
fn rbio_flags(s: &Ssl) -> c_int {
    bio_flags(s.rbio)
}

/// Accumulate one record's header and body from the read BIO.
///
/// The partial-read state is `rec_hdr_len`/`rec_body_len`, whose only writer is this function.
/// Both bounds are re-established from the checked `get_mut` on every iteration, so a short read
/// can only ever resume at a valid offset and a subtraction can never leave the buffer.
fn accumulate(s: &mut Ssl) -> Result<RecordHead, ReadStatus> {
    loop {
        let off = s.rec_hdr_len;
        let Some(dst) = s.rec_hdr.get_mut(off..) else {
            return Err(ReadStatus::Failed);
        };
        if dst.is_empty() {
            break;
        }
        let offered = dst.len();
        let Ok(offered_i32) = c_int::try_from(offered) else {
            return Err(ReadStatus::Failed);
        };
        let ptr = dst.as_mut_ptr();
        // The field borrow ends here; the raw pointer keeps its provenance.
        let rbio = s.rbio;
        // SAFETY: `rbio` is the connection's read BIO (NULL or live, both accepted by
        // `BIO_read`); `ptr` is `offered` writable bytes of `rec_hdr`.
        let got = unsafe { BIO_read(rbio, ptr.cast(), offered_i32) };
        if got <= 0 {
            return Err(transport_status(s, got));
        }
        let Some(next) = accumulated(off, got, offered, SSL3_RT_HEADER_LENGTH) else {
            // A BIO that reports more than it was offered violates `BIO_read`'s contract; the
            // accumulator must not leave `rec_hdr`.
            s.rwstate = SSL_NOTHING;
            return Err(ReadStatus::Failed);
        };
        s.rec_hdr_len = next;
    }

    // The header is complete: all five bytes were written by the reads above.
    let hdr = s.rec_hdr;
    let body_len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
    if body_len > s.rec_body.len() {
        // `rec_layer_s3.c:669-672`: a length that does not fit the record buffer is a fatal
        // record overflow. The header bytes have already been consumed, so a silent -1 would
        // desynchronise the stream on the peer's body bytes; poison instead. Reset the
        // accumulator so a retry cannot re-enter the arm.
        s.rec_hdr_len = 0;
        fatal(s, SSL_AD_RECORD_OVERFLOW, SSL_R_PACKET_LENGTH_TOO_LONG);
        return Err(ReadStatus::Fatal);
    }
    if s.rec_body_len > body_len {
        // A body longer than this header declares is a broken accumulator invariant, not a
        // completion: refuse rather than deliver a prefix of the wrong record.
        return Err(ReadStatus::Failed);
    }

    loop {
        let off = s.rec_body_len;
        if off >= body_len {
            break;
        }
        // `[off..body_len]` is exactly the unwritten remainder, inside `rec_body`.
        let Some(dst) = s.rec_body.get_mut(off..body_len) else {
            return Err(ReadStatus::Failed);
        };
        let offered = dst.len();
        let Ok(offered_i32) = c_int::try_from(offered) else {
            return Err(ReadStatus::Failed);
        };
        let ptr = dst.as_mut_ptr();
        let rbio = s.rbio;
        // SAFETY: as for the header: `ptr` is `offered` writable bytes of `rec_body`, bounded by
        // the declared length.
        let got = unsafe { BIO_read(rbio, ptr.cast(), offered_i32) };
        if got <= 0 {
            return Err(transport_status(s, got));
        }
        let Some(next) = accumulated(off, got, offered, body_len) else {
            // As for the header: a count beyond the offered space cannot be folded into the
            // accumulator, and the body length is the bound every later stage relies on.
            s.rwstate = SSL_NOTHING;
            return Err(ReadStatus::Failed);
        };
        s.rec_body_len = next;
    }

    // The record is complete; release the accumulator before the caller reads the body.
    s.rec_hdr_len = 0;
    s.rec_body_len = 0;
    Ok(RecordHead { hdr, body_len })
}

/// The `ossl_tls_handle_rlayer_return` verdict for a short or failed record read
/// (`ssl/record/rec_layer_s3.c:491-553`).
///
/// A zero-length read (or a BIO already flagged `BIO_FLAGS_IN_EOF`) with
/// `SSL_OP_IGNORE_UNEXPECTED_EOF` set is a clean EOF: the connection records a received shutdown
/// and the alert description `close_notify`, so `SSL_get_error` answers `SSL_ERROR_ZERO_RETURN`
/// (`rec_layer_s3.c:512-514`). Without the option it raises `SSL_R_UNEXPECTED_EOF_WHILE_READING`
/// and makes the connection fatal. A read the BIO flagged retryable is `WouldBlock`: `rwstate`
/// stays `SSL_READING` and the partial accumulator is retained. Any other failure is `Failed`
/// with no error queued, which `SSL_get_error` reports as `SSL_ERROR_SYSCALL`.
fn transport_status(s: &mut Ssl, got: c_int) -> ReadStatus {
    let flags = rbio_flags(s);
    if got == 0 || flags & BIO_FLAGS_IN_EOF != 0 {
        // `rec_layer_s3.c:501-524`: `rwstate = SSL_NOTHING` first, then the EOF arm.
        s.rwstate = SSL_NOTHING;
        if s.options & SSL_OP_IGNORE_UNEXPECTED_EOF != 0 {
            s.shutdown |= SSL_RECEIVED_SHUTDOWN;
            s.warn_alert = SSL_AD_CLOSE_NOTIFY;
            return ReadStatus::Eof;
        }
        fatal(s, SSL_AD_DECODE_ERROR, SSL_R_UNEXPECTED_EOF_WHILE_READING);
        return ReadStatus::FatalEof;
    }
    if flags & BIO_FLAGS_READ != 0 {
        // `rec_layer_s3.c:496-498`.
        s.rwstate = SSL_READING;
        return ReadStatus::WouldBlock;
    }
    // `rec_layer_s3.c:499-500`: `rwstate = SSL_NOTHING`, no alert; `SSL_ERROR_SYSCALL`.
    s.rwstate = SSL_NOTHING;
    ReadStatus::Failed
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

/// Decode one received alert from its length and first two bytes.
fn decode_alert(s: &mut Ssl, alert_len: usize, alert: [u8; 2]) -> AlertOutcome {
    if alert_len != 2 {
        // `rec_layer_s3.c:868-874`: `PACKET_remaining(&alert) != 0` after the level and the
        // description, so any packet other than exactly two bytes is an invalid alert.
        fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_INVALID_ALERT);
        return AlertOutcome::Fatal;
    }
    let alert_level = c_int::from(alert[0]);
    let alert_descr = c_int::from(alert[1]);
    let is_tls13 = s.version == TLS1_3_VERSION;

    // `rec_layer_s3.c:891-903`: a TLS1.2 warning (or a TLS1.3 `user_cancelled`) is counted;
    // `MAX_WARN_ALERT_COUNT` consecutive warnings are fatal.
    if (!is_tls13 && alert_level == SSL3_AL_WARNING)
        || (is_tls13 && alert_descr == SSL_AD_USER_CANCELLED)
    {
        s.warn_alert = alert_descr;
        s.alert_count += 1;
        if s.alert_count == MAX_WARN_ALERT_COUNT {
            fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_TOO_MANY_WARN_ALERTS);
            return AlertOutcome::Fatal;
        }
    }

    if is_tls13 && alert_descr == SSL_AD_USER_CANCELLED {
        // `rec_layer_s3.c:909-910`: the one ignorable TLS1.3 warning.
        AlertOutcome::Ignored
    } else if alert_descr == SSL_AD_CLOSE_NOTIFY && (is_tls13 || alert_level == SSL3_AL_WARNING) {
        // `rec_layer_s3.c:911-914`.
        s.shutdown |= SSL_RECEIVED_SHUTDOWN;
        s.rwstate = SSL_NOTHING;
        AlertOutcome::Terminal
    } else if alert_level == SSL3_AL_FATAL || is_tls13 {
        // `rec_layer_s3.c:915-925`: a fatal alert (any non-`close_notify`/`user_cancelled`
        // TLS1.3 alert) records the description and queues `SSL_AD_REASON_OFFSET + descr`.
        s.rwstate = SSL_NOTHING;
        s.fatal_alert = alert_descr;
        raise_alert_received(s, alert_descr);
        s.shutdown |= SSL_RECEIVED_SHUTDOWN;
        AlertOutcome::Terminal
    } else if alert_descr == SSL_AD_NO_RENEGOTIATION {
        // `rec_layer_s3.c:926-936`.
        fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_RENEGOTIATION);
        AlertOutcome::Fatal
    } else if alert_level == SSL3_AL_WARNING {
        // `rec_layer_s3.c:937-939`: any other TLS1.2 warning is ignored.
        AlertOutcome::Ignored
    } else {
        // `rec_layer_s3.c:942-943`.
        fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_UNKNOWN_ALERT_TYPE);
        AlertOutcome::Fatal
    }
}

/// `SSLfatal_data(s, SSL_AD_NO_ALERT, SSL_AD_REASON_OFFSET + alert_descr, "SSL alert number %d",`
/// `alert_descr)` — `ssl/record/rec_layer_s3.c:916-925`.
///
/// The error is raised at the alert block's own coordinate (`rec_layer_s3.c:918`) with the alert
/// number as `ERR` data, then the state machine's fatal transition runs with `SSL_AD_NO_ALERT`, so
/// no alert is echoed to the peer.
fn raise_alert_received(s: &mut Ssl, alert_descr: c_int) {
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
    send_fatal(s, SSL_AD_NO_ALERT);
}

/// Deliver one accumulated record body to the sink.
fn deliver(s: &mut Ssl, head: &RecordHead, sink: &mut Sink<'_>) -> Result<(u8, usize), ReadStatus> {
    if s.dec_active != 0 {
        // Phase 17: a TLS1.2 AEAD record (`tls1_enc`, `ssl/t1_enc.c`) decrypts whenever the read
        // key is installed; unlike TLS1.3 the outer type is the real content type.
        if s.version == TLS1_2_VERSION {
            return decrypt(s, head, sink, Aead::Tls12);
        }
        // `SSL3_RT_APPLICATION_DATA` (23) is the outer type of every TLS 1.3 protected record; a
        // middlebox-compatibility `ChangeCipherSpec` (20) or a plaintext alert is *not* protected
        // and is read straight through (`tls13_dec`, `ssl/record/methods/tls13_meth.c`).
        if head.hdr[0] != SSL3_RT_APPLICATION_DATA {
            return Ok((head.hdr[0], write_plain(s, head, sink)?));
        }
        return decrypt(s, head, sink, Aead::Tls13);
    }

    Ok((head.hdr[0], write_plain(s, head, sink)?))
}

/// Publish an authenticated/plaintext record body to the sink.
fn write_plain(s: &mut Ssl, head: &RecordHead, sink: &mut Sink<'_>) -> Result<usize, ReadStatus> {
    // `head.body_len <= rec_body.len()` was checked by `accumulate`, and every byte of the extent
    // was written by the reads that completed it.
    let src = &s.rec_body[..head.body_len];
    match sink {
        Sink::External(out) => out.write(src).ok_or(ReadStatus::Failed),
        Sink::AssemblyTail { used } => {
            // `rec_body` and `rd_msg_buf` are distinct fields, so both borrows can be live.
            let Some(dst) = s
                .rd_msg_buf
                .get_mut(*used..)
                .and_then(|tail| tail.get_mut(..src.len()))
            else {
                return Err(ReadStatus::Failed);
            };
            dst.copy_from_slice(src);
            Ok(src.len())
        }
    }
}

/// Which AEAD sink reads the record.
#[derive(Clone, Copy)]
enum Aead {
    Tls12,
    Tls13,
}

/// Decrypt one AEAD-protected record into the sink.
fn decrypt(
    s: &mut Ssl,
    head: &RecordHead,
    sink: &mut Sink<'_>,
    aead: Aead,
) -> Result<(u8, usize), ReadStatus> {
    let sp: *mut Ssl = s;
    // SAFETY: `sp` is live and `head.body_len <= rec_body.len()`, so the view is a checked
    // initialised extent of the connection's own buffer.
    let body = unsafe { (*sp).rec_body.as_ptr() };
    // SAFETY: `sp` is live and `head.body_len <= rec_body.len()`; the sink's destination is
    // disjoint from the ciphertext by the `Sink` invariants.
    let (out_ptr, out_cap) = unsafe { sink.slot(sp) }?;
    let mut record_type = 0u8;
    // SAFETY: `sp` is live; `body` is `head.body_len` initialised bytes; `out_ptr` is writable
    // for `out_cap` bytes; `record_type` is a local out-parameter. The callee reads the
    // ciphertext and writes the plaintext region, which does not alias it.
    let n = unsafe {
        match aead {
            Aead::Tls12 => crate::ssl::t1_enc::tls12_decrypt_record(
                sp,
                &head.hdr,
                body,
                head.body_len,
                out_ptr,
                out_cap,
                &mut record_type,
            ),
            Aead::Tls13 => crate::ssl::tls13_enc::tls13_decrypt_record(
                sp,
                &head.hdr,
                body,
                head.body_len,
                out_ptr,
                out_cap,
                &mut record_type,
            ),
        }
    };
    // The sink refuses a count beyond the capacity it was given; the caller's output can never
    // be published as a longer prefix.
    let Ok(n) = usize::try_from(n) else {
        return Err(ReadStatus::Failed);
    };
    if n > out_cap {
        return Err(ReadStatus::Failed);
    }
    if sink.record_written(n).is_none() {
        return Err(ReadStatus::Failed);
    }
    Ok((record_type, n))
}

/// Copy an alert's first two bytes out of the sink and decode it.
fn decode_alert_at(s: &mut Ssl, sink: &Sink<'_>, len: usize) -> AlertOutcome {
    let take = len.min(2);
    let mut alert = [0u8; 2];
    let mut alert_len = len;
    match sink {
        Sink::External(out) => {
            let written = out.written();
            let n = take.min(written.len());
            alert[..n].copy_from_slice(&written[..n]);
            if n != take {
                alert_len = 0;
            }
        }
        Sink::AssemblyTail { used } => {
            let Some(bytes) = s.rd_msg_buf.get(*used..).and_then(|tail| tail.get(..take)) else {
                // The reader wrote `len` bytes at `used`; this is unreachable unless the
                // assembly invariant was violated, and an alert of the wrong length is invalid.
                alert_len = 0;
                return decode_alert(s, alert_len, alert);
            };
            alert[..take].copy_from_slice(bytes);
        }
    }
    decode_alert(s, alert_len, alert)
}

/// Read one record (repeating over ignored alerts) and deliver its body.
///
/// The destination is either the caller's region (`Sink::External`, disjoint from `s` by the
/// entry point's contract) or a checked tail offset in `s`'s own assembly buffer.
fn read_record(s: &mut Ssl, sink: &mut Sink<'_>) -> ReadStatus {
    loop {
        let head = match accumulate(s) {
            Ok(head) => head,
            Err(status) => return status,
        };
        let (record_type, len) = match deliver(s, &head, sink) {
            Ok(delivered) => delivered,
            Err(status) => return status,
        };
        if record_type != SSL3_RT_ALERT {
            return ReadStatus::Complete { record_type, len };
        }
        match decode_alert_at(s, sink, len) {
            AlertOutcome::Terminal => return ReadStatus::Eof,
            AlertOutcome::Fatal => return ReadStatus::Fatal,
            AlertOutcome::Ignored => continue,
        }
    }
}

/// `int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf, size_t len,` —
/// `ssl/record/rec_layer_s3.c:612-...`, reduced to the record-read arm the handshake and
/// application readers need.
///
/// It reads one record with [`read_record`] and, when that record is an alert, decodes it exactly
/// as the authority's alert block does (`rec_layer_s3.c:864-944`): a `close_notify` sets
/// `SSL_RECEIVED_SHUTDOWN` and ends the read, a fatal alert (any non-`user_cancelled` TLS 1.3
/// alert) records `s3.fatal_alert` and queues `SSL_AD_REASON_OFFSET + alert_descr`, `user_cancelled`
/// and the TLS1.2 warnings are ignored, and `no_renegotiation` or an unknown type is fatal.
///
/// The return follows the authority's `ssl3_read_internal`: a positive body length, `0` for a
/// terminal record whose connection state and error queue are already set, or `-1` for a retry
/// (which leaves `rwstate = SSL_READING`, `rec_layer_s3.c:497`).
///
/// Unlike the previous form, a zero-length record now also reports its content type, as the
/// authority does (`recvd_type` is assigned before its `len == 0` arm), while still answering 0.
///
/// # Safety
/// `s` must be a live connection whose read BIO is the caller's to read; `rectype` must be
/// writable. `buf` must be non-NULL and writable for `cap` bytes when `cap != 0`; **it need not be
/// initialised**, and this function never reads it before writing it. On a positive return exactly
/// the first `n` bytes of `buf` have been written and form the whole published output. `buf` must
/// not overlap the connection's record buffers (`rec_hdr`, `rec_body`, `rd_msg_buf`). No
/// application-controlled BIO callback invoked below may re-enter this connection.
pub(crate) unsafe fn ssl3_read_bytes(
    s: *mut Ssl,
    rectype: *mut u8,
    buf: *mut u8,
    cap: usize,
) -> c_int {
    // SAFETY: `s` is live and exclusively borrowed per the contract.
    let s = unsafe { &mut *s };
    // No typed slice is built over the whole caller capacity: the region may be uninitialised and
    // only the written prefix is ever published, by `OutBuf`.
    // SAFETY: `buf` is writable for `cap` when `cap != 0`, may be uninitialised, and does not
    // overlap the connection's buffers per the contract.
    let mut out = unsafe { OutBuf::from_raw(buf, cap) };
    let mut sink = Sink::External(&mut out);
    let status = read_record(s, &mut sink);
    match status {
        ReadStatus::Complete { record_type, len } => {
            let Ok(len) = c_int::try_from(len) else {
                return -1;
            };
            // SAFETY: `rectype` is writable per the contract.
            unsafe { *rectype = record_type };
            len
        }
        ReadStatus::WouldBlock | ReadStatus::Fatal | ReadStatus::Failed => -1,
        ReadStatus::Eof | ReadStatus::FatalEof => 0,
    }
}

/// The buffered TLS 1.3 handshake state for one step of [`tls13_next_handshake_message`].
enum AssemblyStep {
    /// A complete framed message occupies `off..off + len` of `rd_msg_buf`.
    Deliver { off: usize, len: usize },
    /// Not yet a whole message: read the next record into the unused tail starting at `used`.
    NeedMore { used: usize },
    /// The buffered state is unusable or a message can never fit; refuse.
    Refuse,
}

/// `MAX_EMPTY_RECORDS` — `ssl/record/methods/tls_common.c`: the number of consecutive empty
/// records the authority tolerates before failing the read. A completed empty record is a
/// completed record, not a retry; it must not stop the assembly loop.
const MAX_EMPTY_RECORDS: usize = 32;

/// Decide what the assembly buffer can do next.
///
/// Both lengths are normalised here: every index below is derived from them, so a stale or
/// corrupted accumulator is a refusal, never an out-of-range slice.
fn assembly_step(s: &mut Ssl) -> AssemblyStep {
    if s.rd_msg_len > s.rd_msg_buf.len() || s.rd_msg_off > s.rd_msg_len {
        s.rd_msg_len = 0;
        s.rd_msg_off = 0;
        return AssemblyStep::Refuse;
    }
    let off = s.rd_msg_off;
    let mut deliver = None;
    let mut overflow = false;
    {
        let buffered = &s.rd_msg_buf[..s.rd_msg_len];
        // `off <= rd_msg_len`, so the tail is in bounds; keep the checked form anyway.
        if let Some(rest) = buffered.get(off..) {
            if let Some(msg_len) = framed_message_len(rest) {
                match buffered.len().checked_sub(off) {
                    Some(remaining) if msg_len <= remaining => deliver = Some(msg_len),
                    // A message that can never fit the assembly buffer is refused rather than
                    // accumulated forever.
                    _ if msg_len > s.rd_msg_buf.len() => overflow = true,
                    _ => {}
                }
            }
        }
    }
    if let Some(len) = deliver {
        return AssemblyStep::Deliver { off, len };
    }
    if overflow {
        s.rd_msg_len = 0;
        s.rd_msg_off = 0;
        return AssemblyStep::Refuse;
    }

    // Make room by discarding the consumed prefix. This is an overlapping move, so it is
    // `copy_within` rather than a raw copy; the message's own bytes stay contiguous.
    if s.rd_msg_len == s.rd_msg_buf.len() {
        let consumed = s.rd_msg_off;
        if consumed == 0 {
            return AssemblyStep::Refuse;
        }
        let Some(remaining) = s.rd_msg_len.checked_sub(consumed) else {
            return AssemblyStep::Refuse;
        };
        s.rd_msg_buf.copy_within(consumed..s.rd_msg_len, 0);
        s.rd_msg_len = remaining;
        s.rd_msg_off = 0;
    }
    AssemblyStep::NeedMore { used: s.rd_msg_len }
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
/// records and completed zero-length handshake records, as the authority's
/// `MAX_EMPTY_RECORDS` loop does.
///
/// # Safety
/// `s` must be a live connection. `buf` must be non-NULL and writable for `cap` bytes when
/// `cap != 0`; **it need not be initialised**, and this function never reads it. `buf` must not
/// overlap the connection's assembly buffer (`rd_msg_buf`) or record buffers, whose bytes are the
/// source of the copy. On a positive return exactly the first `n` bytes are written. No
/// application-controlled BIO callback invoked below may re-enter this connection.
pub(crate) unsafe fn tls13_next_handshake_message(s: *mut Ssl, buf: *mut u8, cap: usize) -> c_int {
    // SAFETY: `s` is live and exclusively borrowed per the contract.
    let s = unsafe { &mut *s };
    // SAFETY: as for `ssl3_read_bytes`: the caller's region is writable and disjoint from `Ssl`.
    let mut out = unsafe { OutBuf::from_raw(buf, cap) };
    let mut empty_records = 0usize;
    loop {
        match assembly_step(s) {
            AssemblyStep::Deliver { off, len } => {
                if len > cap {
                    // The buffered message is not consumed, so a retry with enough room works.
                    return -1;
                }
                // The message is a checked prefix of the connection's own buffer.
                let Some(written) = out.write(&s.rd_msg_buf[off..off + len]) else {
                    return -1;
                };
                debug_assert_eq!(written, len);
                let Some(next) = off.checked_add(len) else {
                    return -1;
                };
                s.rd_msg_off = next;
                let Ok(len) = c_int::try_from(len) else {
                    return -1;
                };
                return len;
            }
            AssemblyStep::NeedMore { used } => {
                let mut sink = Sink::AssemblyTail { used };
                let (record_type, len) = match read_record(s, &mut sink) {
                    ReadStatus::Complete { record_type, len } => (record_type, len),
                    // Every non-complete outcome keeps this function's -1 contract. A completed
                    // empty record is `Complete`, so it is no longer mistaken for a retry.
                    _ => return -1,
                };
                let Some(end) = used.checked_add(len) else {
                    return -1;
                };
                if end > s.rd_msg_buf.len() {
                    return -1;
                }
                match record_type {
                    22 => {
                        // SSL3_RT_HANDSHAKE: append and re-parse the framing at the top.
                        if len == 0 {
                            empty_records += 1;
                            if empty_records > MAX_EMPTY_RECORDS {
                                return -1;
                            }
                        } else {
                            empty_records = 0;
                        }
                        s.rd_msg_len = end;
                    }
                    20 => {} // SSL3_RT_CHANGE_CIPHER_SPEC: consumed and skipped.
                    _ => {
                        // The record was fully consumed from the BIO and discarded. Clear the
                        // buffered-message state before reporting the wait: leaving `rd_msg_len`
                        // pointing at this non-handshake record would let the next call parse its
                        // body as a handshake header (a record type confusion).
                        s.rd_msg_len = 0;
                        s.rd_msg_off = 0;
                        return -1;
                    }
                }
            }
            AssemblyStep::Refuse => return -1,
        }
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
    use crate::runtime::bio::method::{BIO_meth_free, BIO_meth_new, BIO_meth_set_write};
    use crate::runtime::bio::{BIO_ctrl_pending, BIO_free, BIO_new, BIO_write, Bio};
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::adv_alloc::zeroed_ssl;
    use crate::ssl::statem::statem::ossl_statem_in_error;
    use core::mem::MaybeUninit;

    /// A TLS1.2-versioned record: `type || 0x0303 || length || body`.
    fn record(type_: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![type_, 0x03, 0x03, (body.len() >> 8) as u8, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

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

    /// A handshake message split across two records is accumulated by the message layer and
    /// delivered once, with the same bytes as the unfragmented message.
    #[test]
    fn a_fragmented_handshake_message_is_reassembled() {
        // `ServerHello` type (2) with a one-byte body; split 3/2 across two records.
        let msg = [2u8, 0x00, 0x00, 0x01, 0xBB];
        let first = record(22, &msg[..3]);
        let second = record(22, &msg[3..]);
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&first);
            assert_eq!(
                BIO_write(bio, second.as_ptr().cast(), second.len() as c_int),
                second.len() as c_int
            );
            let mut out = [0u8; 16];
            let n = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert_eq!(n, 5, "the two record fragments form one message");
            assert_eq!(&out[..5], &msg, "the reassembled bytes are exact");
            assert_eq!((*s).rd_msg_len, 5);
            assert_eq!((*s).rd_msg_off, 5);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// Two complete messages in one record are handed out in order; the pending offset advances
    /// by exactly each message's framed length.
    #[test]
    fn two_messages_in_one_record_are_delivered_in_order() {
        let first = [2u8, 0x00, 0x00, 0x01, 0xAA];
        let second = [4u8, 0x00, 0x00, 0x02, 0xCC, 0xDD];
        let mut body = first.to_vec();
        body.extend_from_slice(&second);
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(22, &body));
            let mut out = [0u8; 16];
            assert_eq!(
                tls13_next_handshake_message(s, out.as_mut_ptr(), out.len()),
                5
            );
            assert_eq!(&out[..5], &first);
            assert_eq!((*s).rd_msg_off, 5);
            assert_eq!(
                tls13_next_handshake_message(s, out.as_mut_ptr(), out.len()),
                6
            );
            assert_eq!(&out[..6], &second);
            assert_eq!((*s).rd_msg_off, 11);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A record whose length field exceeds the record buffer is a fatal record overflow: -1, the
    /// connection is poisoned, and the header accumulator is reset.
    #[test]
    fn a_record_length_beyond_the_buffer_is_a_record_overflow() {
        // 0x4269 = 17001 > the 17000-byte record body buffer.
        let record = [23u8, 0x03, 0x03, 0x42, 0x69];
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record);
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(n, -1);
            assert_ne!(ossl_statem_in_error(s), 0, "the connection is poisoned");
            assert_eq!((*s).rec_hdr_len, 0, "the accumulator cannot be re-entered");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A zero-length record is legal and delivers zero bytes without poisoning the connection.
    #[test]
    fn a_zero_length_record_delivers_zero_bytes() {
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(23, &[]));
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(n, 0);
            assert_eq!(ossl_statem_in_error(s), 0);
            assert_eq!((*s).rec_hdr_len, 0);
            assert_eq!((*s).rec_body_len, 0);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A maximum-size plaintext record (16384 bytes) is delivered byte for byte.
    #[test]
    fn a_maximum_size_record_is_delivered() {
        let body: Vec<u8> = (0..SSL3_RT_MAX_PLAIN_LENGTH)
            .map(|i| (i % 251) as u8)
            .collect();
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(23, &body));
            let mut out = vec![0u8; SSL3_RT_MAX_PLAIN_LENGTH];
            let mut rt = 0u8;
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(n, SSL3_RT_MAX_PLAIN_LENGTH as c_int);
            assert_eq!(rt, 23);
            assert_eq!(out, body);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A partial header is retained across the short read and resumed on the next call; the body
    /// then arrives intact. `SSL_OP_IGNORE_UNEXPECTED_EOF` makes the interim EOF graceful, which is
    /// the only way a non-blocking stream can pause mid-record.
    #[test]
    fn a_partial_read_then_a_second_read_resumes_the_header() {
        let full = record(23, b"hello");
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&full[..2]);
            (*s).options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            let first = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(first, -1, "a short header is a retryable read");
            assert_eq!((*s).rwstate, SSL_READING);
            assert_eq!((*s).rec_hdr_len, 2, "the partial header is retained");
            assert_eq!(
                BIO_write(bio, full[2..].as_ptr().cast(), (full.len() - 2) as c_int),
                (full.len() - 2) as c_int
            );
            let second = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(second, 5);
            assert_eq!(&out[..5], b"hello");
            assert_eq!((*s).rec_hdr_len, 0);
            assert_eq!((*s).rec_body_len, 0);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A handshake message larger than the caller's output is refused with -1 and writes nothing
    /// past the declared capacity. The backing array is deliberately larger than `cap` so the
    /// sensitivity control can observe an over-write without corrupting the frame.
    #[test]
    fn a_handshake_message_larger_than_the_output_is_refused() {
        let body = [2u8, 0x00, 0x00, 0x01, 0xBB];
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(22, &body));
            let mut backing = [0u8; 64];
            let n = tls13_next_handshake_message(s, backing.as_mut_ptr(), 2);
            assert_eq!(n, -1, "a message that does not fit the output is refused");
            assert_eq!(&backing[..], &[0u8; 64], "nothing is written past `cap`");
            assert_eq!((*s).rd_msg_off, 0, "the buffered message is not consumed");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A write BIO that claims to have accepted more bytes than it was offered violates the BIO
    /// contract; the record writer must refuse rather than advance past the buffer.
    unsafe extern "C" fn overreporting_write(
        _bio: *mut Bio,
        _data: *const c_char,
        len: c_int,
    ) -> c_int {
        len.saturating_add(1)
    }

    #[test]
    fn a_write_bio_that_overreports_is_refused() {
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let s = zeroed_ssl();
            assert!(!s.is_null());
            let method = BIO_meth_new(0, c"overreporting".as_ptr());
            assert!(!method.is_null());
            assert_eq!(BIO_meth_set_write(method, Some(overreporting_write)), 1);
            let bio = BIO_new(method);
            assert!(!bio.is_null());
            (*s).wbio = bio;
            let plain = [7u8; 16];
            let r = ssl3_write_bytes(s, 23, plain.as_ptr(), plain.len());
            assert_eq!(r, -1, "an over-reporting BIO is refused");
            assert_eq!((*s).rwstate, SSL_NOTHING);
            BIO_free(bio);
            BIO_meth_free(method);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A deterministic sweep of malformed record streams: the reader must answer a bounded
    /// result and never panic, whatever the header length and type bytes say.
    #[test]
    fn a_seeded_malformed_record_stream_never_panics() {
        let mut seed = 0x1234_5678u32;
        for _ in 0..64 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let body_len = (seed % 96) as usize;
            let mut bytes = Vec::with_capacity(5 + body_len);
            for _ in 0..5 + body_len {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                bytes.push((seed >> 24) as u8);
            }
            // SAFETY: the connection and BIO are exclusive frame-owned objects.
            unsafe {
                let (s, bio) = connection_with_read_bytes(&bytes);
                let mut out = [0u8; 32];
                let mut rt = 0u8;
                let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
                assert!(
                    n >= -1 && n <= out.len() as c_int,
                    "a malformed stream must answer in range, got {n}"
                );
                BIO_free(bio);
                CRYPTO_free(s.cast(), ptr::null(), 0);
            }
        }
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

    /// The caller promises only *writable* memory, never initialised `u8` values. Both output
    /// entry points must therefore write before they read: the buffer is a `MaybeUninit` region
    /// and only the returned prefix is ever inspected.
    #[test]
    fn rec_layer_uninitialised_output_is_not_read_before_written() {
        let msg = [2u8, 0x00, 0x00, 0x01, 0xBB];
        // SAFETY: the connection and BIO are exclusive frame-owned objects; the output buffers
        // are exclusively this frame's and are initialised only by the record layer.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(22, &msg));
            let mut out = vec![MaybeUninit::<u8>::uninit(); 16];
            let n = tls13_next_handshake_message(s, out.as_mut_ptr().cast(), out.len());
            assert_eq!(n, 5, "the framed message length is reported");
            // SAFETY: a positive return means the first `n` bytes were written by the reader.
            let written = core::slice::from_raw_parts(out.as_ptr().cast::<u8>(), n as usize);
            assert_eq!(written, &msg, "only the written prefix is published");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);

            // The record-layer entry point has the same contract.
            let body = b"plaintext";
            let (s, bio) = connection_with_read_bytes(&record(23, body));
            let mut out = vec![MaybeUninit::<u8>::uninit(); 16];
            let mut rt = 0u8;
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr().cast(), out.len());
            assert_eq!(n as usize, body.len());
            assert_eq!(rt, 23);
            // SAFETY: a positive return means the first `n` bytes were written by the reader.
            let written = core::slice::from_raw_parts(out.as_ptr().cast::<u8>(), n as usize);
            assert_eq!(written, body);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A short read writes nothing and retains the partial header; the resumed read publishes
    /// exactly the record body and leaves every byte beyond it untouched.
    #[test]
    fn rec_layer_short_read_publishes_only_the_written_prefix() {
        let full = record(23, b"hello");
        // SAFETY: the connection and BIO are exclusive frame-owned objects; `out` is a local
        // sentinel-filled buffer whose bytes past the written prefix must stay unchanged.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&full[..2]);
            (*s).options |= SSL_OP_IGNORE_UNEXPECTED_EOF;
            let mut rt = 0u8;
            let mut out = [0xCDu8; 16];
            let first = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(first, -1, "a short header is a retryable read");
            assert_eq!((*s).rec_hdr_len, 2, "the partial header is retained");
            assert_eq!(out, [0xCDu8; 16], "a short read writes no output");
            assert_eq!(
                BIO_write(bio, full[2..].as_ptr().cast(), (full.len() - 2) as c_int),
                (full.len() - 2) as c_int
            );
            let second = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(second, 5, "the resumed read delivers the body");
            assert_eq!(&out[..5], b"hello");
            assert_eq!(
                &out[5..],
                &[0xCDu8; 11],
                "only the written prefix is published"
            );
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A handshake message split across three records, with middlebox-compatibility
    /// `ChangeCipherSpec` records and completed empty handshake records interleaved, is
    /// reassembled into one message. The empty records are the `MAX_EMPTY_RECORDS` case: a
    /// completed zero-length record must not stop the assembly loop.
    #[test]
    fn rec_layer_fragmented_handshake_message_reassembles() {
        // `ServerHello` type (2) with a four-byte body: 2 + 3 + 3 bytes across three records.
        let msg = [2u8, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
        let empty = record(22, &[]);
        let first = record(22, &msg[..2]);
        let ccs = record(20, &[0x01]);
        let second = record(22, &msg[2..5]);
        let third = record(22, &msg[5..]);
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&empty);
            for fragment in [&first, &ccs, &empty, &second, &third] {
                assert_eq!(
                    BIO_write(bio, fragment.as_ptr().cast(), fragment.len() as c_int),
                    fragment.len() as c_int
                );
            }
            let mut out = [0u8; 16];
            let n = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert_eq!(n, 8, "the fragments form one message");
            assert_eq!(&out[..8], &msg, "the reassembled bytes are exact");
            assert_eq!((*s).rd_msg_off, 8, "the whole message is consumed");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A refused output reservation must not consume the buffered message: the state is
    /// left reusable so a retry with enough room delivers the same bytes.
    ///
    /// This boundary allocates nothing of its own (the caller supplies the output and the
    /// connection's assembly buffer is inline), and the crate's allocator-customisation latch
    /// is one-way, so a genuine `CRYPTO_malloc` failure cannot be injected here. The refusal
    /// seam exercised below is the only allocation-like reservation on the converted path; the
    /// allocation-failure requirement is recorded as **not injectable**, not as passing.
    #[test]
    fn rec_layer_refusal_leaves_state_unchanged() {
        let msg = [2u8, 0x00, 0x00, 0x01, 0xBB];
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&record(22, &msg));
            let mut out = [0u8; 16];
            let refused = tls13_next_handshake_message(s, out.as_mut_ptr(), 2);
            assert_eq!(refused, -1, "a message that does not fit is refused");
            assert_eq!((*s).rd_msg_off, 0, "the buffered message is not consumed");
            assert_eq!((*s).rd_msg_len, 5, "the record stays assembled for a retry");
            assert_eq!(out, [0u8; 16], "the refusal writes nothing");
            let retried = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert_eq!(retried, 5, "the retry delivers the same message");
            assert_eq!(&out[..5], &msg);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A record body split across two `BIO_read`s is delivered exactly once: the first call
    /// retains the partial body and reports a retry, the second resumes at the retained offset
    /// and completes the record, and no later call can deliver it again.
    #[test]
    fn rec_layer_partial_body_then_remainder_completes_once() {
        let full = record(23, b"hello");
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            // Five header bytes plus two of the five body bytes.
            let (s, bio) = connection_with_read_bytes(&full[..7]);
            let mut rt = 0u8;
            let mut out = [0xCDu8; 16];
            let first = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(first, -1, "a short body is a retry");
            assert_eq!((*s).rwstate, SSL_READING, "the retry is WANT_READ");
            assert_eq!((*s).rec_body_len, 2, "the partial body is retained");
            assert_eq!(out, [0xCDu8; 16], "a retry publishes nothing");
            assert_eq!(
                BIO_write(bio, full[7..].as_ptr().cast(), (full.len() - 7) as c_int),
                (full.len() - 7) as c_int
            );
            let second = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(second, 5, "the resumed read completes the record once");
            assert_eq!(rt, 23);
            assert_eq!(&out[..5], b"hello");
            assert_eq!((*s).rec_body_len, 0, "the accumulator is released");
            let third = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(third, -1, "the record is not delivered a second time");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// An unterminated record is never delivered as a complete one: when the transport reports
    /// end of stream with part of the body buffered, the read ends with 0 (the authority's
    /// unexpected-EOF arm), the connection is poisoned, nothing is published, and the partial
    /// body stays partial.
    #[test]
    fn rec_layer_unterminated_record_is_not_delivered_as_complete() {
        let full = record(23, b"hello");
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&full[..7]);
            // The next read reports EOF instead of a retry (the memory BIO's `num` is -1).
            (*bio).flags |= BIO_FLAGS_IN_EOF;
            let mut rt = 0u8;
            let mut out = [0xCDu8; 16];
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(n, 0, "an unexpected EOF ends the read with 0");
            assert_ne!(ossl_statem_in_error(s), 0, "the connection is poisoned");
            assert_eq!(out, [0xCDu8; 16], "no partial record is published");
            assert_eq!((*s).rec_body_len, 2, "the partial body is retained");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A record whose declared length exceeds the body buffer is refused as a record overflow
    /// without reading past the header: the peer's body bytes stay in the BIO, and no part of
    /// them reaches `rec_body` or the caller's buffer.
    #[test]
    fn rec_layer_over_long_record_is_refused_without_consuming_its_body() {
        // 0x4269 = 17001 > the 17000-byte record body buffer, followed by eight body bytes.
        let mut bytes = vec![23u8, 0x03, 0x03, 0x42, 0x69];
        bytes.extend_from_slice(&[0xAAu8; 8]);
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&bytes);
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            let n = ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len());
            assert_eq!(n, -1, "an over-long record is fatal");
            assert_ne!(ossl_statem_in_error(s), 0, "the connection is poisoned");
            assert_eq!(
                BIO_ctrl_pending(bio),
                8,
                "the body was not read past the header"
            );
            assert_eq!((*s).rec_body_len, 0, "no body bytes were accumulated");
            assert_eq!(out, [0u8; 16], "nothing was published");
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// A completed zero-length handshake record is a *completion*, not a retry: the assembly
    /// reader consumes it and delivers the following message in the same call, as the
    /// authority's `MAX_EMPTY_RECORDS` loop does. This is the retry/completion distinction the
    /// reconstructed status makes structural; the pre-fix reader answered 0 for both an empty
    /// record and end of stream, and the assembly reader turned every `n <= 0` into -1.
    #[test]
    fn rec_layer_empty_record_before_a_message_is_not_a_retry() {
        let msg = [2u8, 0x00, 0x00, 0x01, 0xBB];
        let mut bytes = record(22, &[]);
        bytes.extend_from_slice(&record(22, &msg));
        // SAFETY: the connection and BIO are exclusive frame-owned objects.
        unsafe {
            let (s, bio) = connection_with_read_bytes(&bytes);
            let mut out = [0u8; 16];
            let n = tls13_next_handshake_message(s, out.as_mut_ptr(), out.len());
            assert_eq!(n, 5, "the empty record is skipped, not reported as a retry");
            assert_eq!(&out[..5], &msg);
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
    }

    /// The connection's record buffers have exactly one owner (the `Ssl` block): no read failure
    /// path frees, replaces or moves them, so their addresses and extents are identical before
    /// and after the failure, and the connection block itself is released once at the end.
    /// The only heap resource this layer owns is the write scratch, whose single release is
    /// observed by address and must happen exactly once.
    #[test]
    fn rec_layer_failure_paths_release_record_buffers_once() {
        // SAFETY: every object is created and released in this frame.
        unsafe {
            // Failure path 1: record overflow.
            let (s, bio) = connection_with_read_bytes(&[]);
            let hdr_base = (*s).rec_hdr.as_ptr();
            let body_base = (*s).rec_body.as_ptr();
            let msg_base = (*s).rd_msg_buf.as_ptr();
            let hdr_len = (*s).rec_hdr.len();
            let body_len = (*s).rec_body.len();
            let msg_len = (*s).rd_msg_buf.len();
            let overflow = [23u8, 0x03, 0x03, 0x42, 0x69];
            assert_eq!(
                BIO_write(bio, overflow.as_ptr().cast(), overflow.len() as c_int),
                overflow.len() as c_int
            );
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            assert_eq!(ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len()), -1);
            assert_eq!((*s).rec_hdr.as_ptr(), hdr_base, "header address unchanged");
            assert_eq!((*s).rec_body.as_ptr(), body_base, "body address unchanged");
            assert_eq!(
                (*s).rd_msg_buf.as_ptr(),
                msg_base,
                "assembly address unchanged"
            );
            assert_eq!((*s).rec_hdr.len(), hdr_len);
            assert_eq!((*s).rec_body.len(), body_len);
            assert_eq!((*s).rd_msg_buf.len(), msg_len);
            // The single release of the record buffers is the connection block's own release.
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);

            // Failure path 2: an invalid alert. Same owner, same address identity.
            let alert = [21u8, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x00];
            let (s, bio) = connection_with_read_bytes(&alert);
            let hdr_base = (*s).rec_hdr.as_ptr();
            let body_base = (*s).rec_body.as_ptr();
            let msg_base = (*s).rd_msg_buf.as_ptr();
            let mut rt = 0u8;
            let mut out = [0u8; 16];
            assert_eq!(ssl3_read_bytes(s, &mut rt, out.as_mut_ptr(), out.len()), -1);
            assert_eq!((*s).rec_hdr.as_ptr(), hdr_base, "header address unchanged");
            assert_eq!((*s).rec_body.as_ptr(), body_base, "body address unchanged");
            assert_eq!(
                (*s).rd_msg_buf.as_ptr(),
                msg_base,
                "assembly address unchanged"
            );
            BIO_free(bio);
            CRYPTO_free(s.cast(), ptr::null(), 0);

            // The write scratch: one owner, one release, at its own address.
            scratch_probe::take();
            let block = Scratch::allocate().expect("the scratch block must allocate");
            let scratch_addr = block.0.as_ptr() as usize;
            drop(block);
            assert_eq!(
                scratch_probe::take(),
                vec![scratch_addr],
                "the scratch is released exactly once, at its allocation address"
            );
        }
    }

    /// Negative control (`#[cfg(test)]` only): the pre-fix reader returned a bare `c_int` in
    /// which `0` meant *both* "a completed zero-length record" and "end of stream"; the
    /// assembly layer's `n <= 0` rule then reported a completion as a retry. The control models
    /// both rules and fails if the pre-fix rule does not expose the confusion.
    #[test]
    fn rec_layer_canary_pre_fix_retry_is_confused_with_completion() {
        // Pre-fix: one integer for every outcome, so completion is `n > 0`.
        fn pre_fix_is_retry(n: c_int) -> bool {
            n <= 0
        }
        // Post-fix: only an explicit would-block is a retry.
        fn post_fix_is_retry(status: ReadStatus) -> bool {
            matches!(status, ReadStatus::WouldBlock)
        }
        let empty_record: c_int = 0;
        let pre = pre_fix_is_retry(empty_record);
        assert!(
            pre,
            "the pre-fix rule treats a completed empty record as a retry (the defect)"
        );
        let complete = ReadStatus::Complete {
            record_type: 22,
            len: 0,
        };
        assert!(
            !post_fix_is_retry(complete),
            "the reconstructed status keeps completion distinct"
        );
        assert!(post_fix_is_retry(ReadStatus::WouldBlock));
        std::println!(
            "rec_layer canary: pre-fix c_int {empty_record} -> retry={pre}; post-fix \
             Complete{{len:0}} -> retry={}",
            post_fix_is_retry(complete)
        );
    }

    /// Negative control (`#[cfg(test)]` only): the pre-fix rule published a typed slice of the
    /// whole caller capacity over memory that is only promised writable, so its published
    /// length could exceed the initialised prefix. The control models both rules against a
    /// shadow initialised-length and fails if the pre-fix rule does not expose an uninitialised
    /// byte.
    #[test]
    fn rec_layer_canary_pre_fix_output_slice_exceeds_written_prefix() {
        // Pre-fix: `from_raw_parts_mut(buf, cap)` -> published length `cap`.
        fn pre_fix_published(cap: usize, _written: usize) -> usize {
            cap
        }
        // Post-fix: only the written prefix is exposed.
        fn post_fix_published(cap: usize, written: usize) -> usize {
            written.min(cap)
        }
        let (cap, written) = (16usize, 0usize);
        let pre = pre_fix_published(cap, written);
        let first_uninitialised = (0..pre).find(|i| *i >= written);
        assert_eq!(
            first_uninitialised,
            Some(0),
            "the pre-fix slice exposes the unwritten byte (the defect)"
        );
        assert_eq!(
            post_fix_published(cap, written),
            0,
            "the converted path exposes no byte before it is written"
        );
        std::println!(
            "rec_layer canary: pre-fix published {pre} bytes of which {written} were initialised \
             (first uninitialised index {first_uninitialised:?}); post-fix publishes {} byte(s)",
            post_fix_published(cap, written)
        );
    }
}
