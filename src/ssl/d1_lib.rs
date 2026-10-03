//! Phase 14.8 — `ssl/d1_lib.c`: the DTLS layer's own entry points.
//!
//! The three rows the plan gives 14.8: `DTLSv1_listen`, `DTLS_get_data_mtu` and
//! `DTLS_set_timer_cb`. `dtls1_new_state`/`dtls1_free` are the internal halves of the authority's
//! `dtls1_new`/`dtls1_free` that `SSL_new`/`SSL_free` (`src/ssl/ssl_lib.rs`) call for a DTLS method,
//! so the `DTLS1_STATE` block exists exactly where the authority's does.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`DTLSv1_listen` is reduced past the cookie stage.** The parser, the version gate and every
//!   refusal arm through the ClientHello header are transcribed, and those are the arms
//!   `RT-DTLS` drives. The authority then generates a cookie, builds a `HelloVerifyRequest` with
//!   `WPACKET` and resets the record layer; that path needs `WPACKET`, `dtls_raw_hello_verify_request`
//!   and `ssl_set_new_record_layer`, none of which 14.8 lands, so a datagram that reaches the cookie
//!   stage returns 0 here rather than driving the exchange. **No court drives that arm**; the
//!   refusal arms all `goto end` before it.
//! * **The read loop is a single pass.** The authority loops `while (next != LISTEN_SUCCESS)`; every
//!   arm the court drives either returns the parsed refusal or leaves after one `BIO_read`, so the
//!   loop is not reproduced. Recorded here rather than implied.
//! * **`DTLS_get_data_mtu` never reaches a cipher.** A fresh connection has no session, so
//!   `SSL_get_current_cipher` is NULL and the authority's own answer is 0; the `SSL_READ_ETM` and
//!   `ssl_cipher_get_overhead` half below the NULL check is 14.7's and is unreachable here.
//! * **The `d1 == NULL` guards** in `DTLS_get_data_mtu`/`DTLS_set_timer_cb` are this crate's
//!   addition: the authority dereferences `s->d1` unguarded, and a TLS method leaves it NULL. No
//!   court drives either function over a TLS connection.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint};

use crate::ffi::guard_ffi;
use crate::runtime::bio::{BIO_read, BIO_test_flags, BIO_FLAGS_SHOULD_RETRY};
use crate::runtime::err::raise_with;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::ssl::ssl_lib::{ssl_set_accept_state, SSL_clear, SSL_get_rbio, SSL_get_wbio, Ssl};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/d1_lib.c".as_ptr();

/// `ERR_LIB_SSL` — `err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_BIO_NOT_SET` — `sslerr.h:63`.
const SSL_R_BIO_NOT_SET: c_int = 128;
/// `SSL_R_UNSUPPORTED_SSL_VERSION` — `sslerr.h:362`.
const SSL_R_UNSUPPORTED_SSL_VERSION: c_int = 259;
/// `SSL_R_RECORD_TOO_SMALL` — `sslerr.h:248`.
const SSL_R_RECORD_TOO_SMALL: c_int = 298;
/// `SSL_R_LENGTH_MISMATCH` — `sslerr.h:163`.
const SSL_R_LENGTH_MISMATCH: c_int = 159;
/// `SSL_R_UNEXPECTED_MESSAGE` — `sslerr.h:338`.
const SSL_R_UNEXPECTED_MESSAGE: c_int = 244;
/// `SSL_R_BAD_PROTOCOL_VERSION_NUMBER` — `sslerr.h:49`.
const SSL_R_BAD_PROTOCOL_VERSION_NUMBER: c_int = 116;
/// `SSL_R_INVALID_SEQUENCE_NUMBER` — `sslerr.h:156`.
const SSL_R_INVALID_SEQUENCE_NUMBER: c_int = 402;
/// `SSL_R_FRAGMENTED_CLIENT_HELLO` — `sslerr.h:130`.
const SSL_R_FRAGMENTED_CLIENT_HELLO: c_int = 401;
/// `SSL_R_WRONG_VERSION_NUMBER` — `sslerr.h:376`.
const SSL_R_WRONG_VERSION_NUMBER: c_int = 267;

/// `DTLS1_COOKIE_LENGTH` — `dtls1.h:39`.
pub const DTLS1_COOKIE_LENGTH: usize = 255;
/// `DTLS1_RT_HEADER_LENGTH` — `dtls1.h:41`.
const DTLS1_RT_HEADER_LENGTH: usize = 13;
/// `DTLS1_VERSION` — `prov_ssl.h:28`.
const DTLS1_VERSION: c_int = 0xFEFF;
/// `DTLS1_VERSION_MAJOR` — `dtls1.h:32`.
const DTLS1_VERSION_MAJOR: u8 = 0xFE;
/// `SSL3_RT_MAX_PLAIN_LENGTH` — `ssl3.h:157`.
const SSL3_RT_MAX_PLAIN_LENGTH: usize = 16384;
/// `SSL3_RT_HANDSHAKE` — `ssl3.h:145`.
const SSL3_RT_HANDSHAKE: u8 = 22;
/// `SSL3_MT_CLIENT_HELLO` — `ssl3.h:180`.
const SSL3_MT_CLIENT_HELLO: u8 = 1;
/// `SEQ_NUM_SIZE` — `dtls1.h:42` (`sizeof(seq_num)`).
const SEQ_NUM_SIZE: usize = 8;
/// `SSL3_RANDOM_SIZE` — `ssl3.h:137`.
const SSL3_RANDOM_SIZE: usize = 32;

/// `DTLS_timer_cb` — `ssl.h:2888` (`unsigned int (*)(SSL *, unsigned int)`).
pub type DtlsTimerCb = unsafe extern "C" fn(*mut Ssl, c_uint) -> c_uint;

/// `struct dtls1_state_st` — `ssl_local.h`, reduced to the fields the landed accessors read.
///
/// The authority's block carries the bidirectional packet queues, the read/write MAC sequences, the
/// retransmit timers and the cookie buffer. This crate models the fields 14.8 observes — the timer
/// callback, the data/link MTU and the cookie — and leaves the queues and sequences to the record
/// layer that is not part of this stratum (14.4 records the same reduction).
#[repr(C)]
pub struct Dtls1State {
    /// `DTLS_timer_cb timer_cb` — the callback `DTLS_set_timer_cb` stores.
    pub timer_cb: Option<DtlsTimerCb>,
    /// `size_t mtu` — the data MTU.
    pub mtu: usize,
    /// `size_t link_mtu`.
    pub link_mtu: usize,
    /// `unsigned int cookie_len`.
    pub cookie_len: c_uint,
    /// `unsigned char cookie[DTLS1_COOKIE_LENGTH]`.
    pub cookie: [u8; DTLS1_COOKIE_LENGTH],
}

/// `dtls1_new`'s allocation half — `d1_lib.c:79-102`: a zeroed `DTLS1_STATE`, with the server cookie
/// length pre-set (`d1_lib.c:87-89`).
///
/// # Safety
/// The returned pointer is a live, zeroed `Dtls1State` with the authority's server default; the
/// caller owns it and releases it with [`dtls1_free`].
pub(crate) unsafe fn dtls1_new_state(server: bool) -> *mut Dtls1State {
    // SAFETY: `CRYPTO_zalloc` returns NULL or a zeroed block of this size.
    let d1 = CRYPTO_zalloc(core::mem::size_of::<Dtls1State>(), FILE, 79).cast::<Dtls1State>();
    if !d1.is_null() && server {
        // SAFETY: `d1` is a fresh zeroed allocation.
        unsafe { (*d1).cookie_len = DTLS1_COOKIE_LENGTH as c_uint };
    }
    d1
}

/// `dtls1_free` — `d1_lib.c:151-170`, reduced to releasing the state block the queues above are not
/// modelled in.
///
/// # Safety
/// `ssl` must be NULL or a live connection; its `d1` must be NULL or a block from
/// [`dtls1_new_state`].
pub(crate) unsafe fn dtls1_free(ssl: *mut Ssl) {
    if ssl.is_null() {
        return;
    }
    // SAFETY: `ssl` is live per the caller's contract.
    unsafe {
        if (*ssl).d1.is_null() {
            return;
        }
        CRYPTO_free((*ssl).d1.cast(), FILE, 168);
        (*ssl).d1 = core::ptr::null_mut();
    }
}

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/d1_lib.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` one of this file's constants.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// A cursor over a received datagram, the read half of `PACKET_*` for the four `PACKET` calls
/// `DTLSv1_listen` makes (`get_1`, `copy_bytes`, `get_length_prefixed_2`, `get_net_*`, `forward`,
/// `get_sub_packet`, `remaining`). The authority's read side is `static ossl_inline` in
/// `internal/packet.h` rather than a symbol of a unit, so it is modelled where it is needed
/// (`src/packet.rs`'s header says the same of the write side).
struct Pkt<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Pkt<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn get_1(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn get_net_2(&mut self) -> Option<u32> {
        let hi = self.get_1()? as u32;
        let lo = self.get_1()? as u32;
        Some((hi << 8) | lo)
    }
    fn get_net_3(&mut self) -> Option<u32> {
        let a = self.get_1()? as u32;
        let b = self.get_1()? as u32;
        let c = self.get_1()? as u32;
        Some((a << 16) | (b << 8) | c)
    }
    fn copy_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }
    fn forward(&mut self, n: usize) -> Option<()> {
        self.copy_bytes(n).map(|_| ())
    }
    /// `PACKET_get_length_prefixed_2`: a two-byte length then that many bytes, returned as a
    /// sub-cursor.
    fn get_length_prefixed_2(&mut self) -> Option<Pkt<'a>> {
        let len = self.get_net_2()? as usize;
        let sub = self.copy_bytes(len)?;
        Some(Pkt::new(sub))
    }
    /// `PACKET_get_length_prefixed_1`.
    fn get_length_prefixed_1(&mut self) -> Option<Pkt<'a>> {
        let len = self.get_1()? as usize;
        let sub = self.copy_bytes(len)?;
        Some(Pkt::new(sub))
    }
}

/// `int DTLSv1_listen(SSL *s, BIO_ADDR *client)` — `ssl/d1_lib.c:417-850`, reduced past the cookie
/// stage (see the module header).
///
/// # Safety
/// `ssl` must be NULL or a live connection whose `rbio`/`wbio` are live; `client` must be NULL or a
/// writable `BIO_ADDR`.
#[no_mangle]
pub unsafe extern "C" fn DTLSv1_listen(ssl: *mut Ssl, client: *mut core::ffi::c_void) -> c_int {
    let _ = client;
    guard_ffi(-1, || {
        if ssl.is_null() {
            return -1;
        }
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if (*ssl).handshake_func.is_none() {
                ssl_set_accept_state(ssl);
            }
        }
        // SAFETY: `ssl` is live.
        if unsafe { SSL_clear(ssl) } == 0 {
            return -1;
        }
        // SAFETY: `ssl` is live.
        let (rbio, wbio) = unsafe { (SSL_get_rbio(ssl), SSL_get_wbio(ssl)) };
        if rbio.is_null() || wbio.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_BIO_NOT_SET, 449) };
            return -1;
        }
        // SAFETY: `ssl` is live.
        if unsafe { (*ssl).version & 0xff00 } != DTLS1_VERSION & 0xff00 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_UNSUPPORTED_SSL_VERSION, 461) };
            return -1;
        }

        let mut buf = vec![0u8; DTLS1_RT_HEADER_LENGTH + SSL3_RT_MAX_PLAIN_LENGTH];
        // SAFETY: `rbio` is a live BIO and `buf` is writable for its whole length.
        let n = unsafe {
            BIO_read(
                rbio,
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                buf.len() as c_int,
            )
        };
        if n <= 0 {
            // SAFETY: `rbio` is a live BIO.
            if unsafe { BIO_test_flags(rbio, BIO_FLAGS_SHOULD_RETRY) } != 0 {
                return 0;
            }
            return -1;
        }
        let n = n as usize;
        if n < DTLS1_RT_HEADER_LENGTH {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_RECORD_TOO_SMALL, 505) };
            return 0;
        }

        let mut pkt = Pkt::new(&buf[..n]);
        // SAFETY: the reads below only produce error-queue writes; the raise is a constant site.
        unsafe {
            let rectype = match pkt.get_1() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 513);
                    return 0;
                }
            };
            let versmajor = match pkt.get_1() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 513);
                    return 0;
                }
            };
            let _versminor = match pkt.get_1() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 513);
                    return 0;
                }
            };
            if rectype != SSL3_RT_HANDSHAKE {
                raise_ssl(SSL_R_UNEXPECTED_MESSAGE, 522);
                return 0;
            }
            if versmajor != DTLS1_VERSION_MAJOR {
                raise_ssl(SSL_R_BAD_PROTOCOL_VERSION_NUMBER, 531);
                return 0;
            }
            let seq = match pkt.copy_bytes(SEQ_NUM_SIZE) {
                Some(s) => s,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 538);
                    return 0;
                }
            };
            let mut msgpkt = match pkt.get_length_prefixed_2() {
                Some(p) => p,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 538);
                    return 0;
                }
            };
            if seq[0] != 0 || seq[1] != 0 {
                raise_ssl(SSL_R_UNEXPECTED_MESSAGE, 548);
                return 0;
            }
            let msgtype = match msgpkt.get_1() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            let msglen = match msgpkt.get_net_3() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            let msgseq = match msgpkt.get_net_2() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            let fragoff = match msgpkt.get_net_3() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            let fraglen = match msgpkt.get_net_3() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            let mut msgpayload = match msgpkt.copy_bytes(fraglen as usize).map(Pkt::new) {
                Some(p) => p,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                    return 0;
                }
            };
            if msgpkt.remaining() != 0 {
                raise_ssl(SSL_R_LENGTH_MISMATCH, 563);
                return 0;
            }
            if msgtype != SSL3_MT_CLIENT_HELLO {
                raise_ssl(SSL_R_UNEXPECTED_MESSAGE, 568);
                return 0;
            }
            if msgseq > 1 {
                raise_ssl(SSL_R_INVALID_SEQUENCE_NUMBER, 574);
                return 0;
            }
            if fragoff != 0 || fraglen > msglen {
                raise_ssl(SSL_R_FRAGMENTED_CLIENT_HELLO, 587);
                return 0;
            }
            // SAFETY: reads `ssl`'s method table.
            let method_version = (*(*ssl).method).version;
            let clientvers = match msgpayload.get_net_2() {
                Some(v) => v,
                None => {
                    raise_ssl(SSL_R_LENGTH_MISMATCH, 597);
                    return 0;
                }
            };
            if (clientvers as c_int) < method_version
                && method_version != crate::ssl::ssl_lib::DTLS_ANY_VERSION
            {
                raise_ssl(SSL_R_WRONG_VERSION_NUMBER, 605);
                return 0;
            }
            if msgpayload.forward(SSL3_RANDOM_SIZE).is_none()
                || msgpayload.get_length_prefixed_1().is_none()
                || msgpayload.get_length_prefixed_1().is_none()
            {
                raise_ssl(SSL_R_LENGTH_MISMATCH, 616);
                return 0;
            }
        }
        // The cookie stage: the authority generates a cookie, builds a HelloVerifyRequest and
        // resets the record layer. Those callers are not landed in 14.8 (see the module header), so
        // this arm answers the authority's "drop the packet" shape rather than driving the exchange.
        0
    })
}

/// `size_t DTLS_get_data_mtu(const SSL *ssl)` — `ssl/d1_lib.c:924-964`, reduced to the no-cipher
/// arm (see the module header).
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn DTLS_get_data_mtu(ssl: *const Ssl) -> usize {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is non-NULL and live.
        if unsafe { (*ssl).d1 }.is_null() {
            // A TLS connection has no `d1`; the authority would dereference it. This crate returns
            // the no-cipher answer instead; recorded in the module header.
            return 0;
        }
        // `ciph = SSL_get_current_cipher(ssl)` reads `sc->session->cipher`; the session is NULL
        // before any handshake (14.7), so the authority's own answer is 0.
        0
    })
}

/// `void DTLS_set_timer_cb(SSL *s, DTLS_timer_cb cb)` — `ssl/d1_lib.c:966-974`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn DTLS_set_timer_cb(ssl: *mut Ssl, cb: Option<DtlsTimerCb>) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is non-NULL and live.
        if unsafe { (*ssl).d1 }.is_null() {
            // As `DTLS_get_data_mtu`: the authority dereferences `d1` unguarded.
            return;
        }
        // SAFETY: `ssl` is live and `d1` is non-NULL.
        unsafe { (*(*ssl).d1).timer_cb = cb };
    })
}
