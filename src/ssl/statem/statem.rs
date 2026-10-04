//! Phase 14.5b — `ssl/statem/statem.c`: the handshake-state machine, its bookkeeping and its
//! fresh-connection driver.
//!
//! 14.5 landed the four state *readers* (`SSL_get_state`, `SSL_in_before`, `SSL_in_init`,
//! `SSL_is_init_finished`) over three scalar words. This slice (14.5b) lands the state machine's
//! **control surface and driver**: the `ossl_statem_*` bookkeeping functions the handshake entry
//! points call (`clear`, `set_in_init`, `set_in_handshake`, `set_renegotiate`, `send_fatal`/
//! `fatal`, `in_error`, `check_finish_init`, `skip_early_data`, `set_hello_verify_done`,
//! `statem_flush`, the three `*_allowed` predicates) and the role drivers `ossl_statem_connect`/
//! `ossl_statem_accept` that `SSL_set_connect_state`/`SSL_set_accept_state` install as the
//! connection's `handshake_func`.
//!
//! ## What is landed, and where the engine stops
//!
//! The authority's `state_machine` (`statem.c:355-532`) drives the message-flow states
//! (`MSG_FLOW_UNINITED` -> `WRITING` <-> `READING` -> `FINISHED`), each step calling the
//! client/server transition and message handlers in `statem_clnt.c`/`statem_srvr.c` through the
//! extension units (`extensions*.c`) and the record layer's read/write path (`rec_layer_s3.c`).
//! Those handlers construct and parse every TLS message and run the key schedule; **none of them
//! is landed**, and neither is the record layer's record protection. So the state machine cannot
//! emit a first flight, and this slice's [`state_machine`] is the authority's driver **up to that
//! boundary**: it reproduces the `MSG_FLOW_ERROR` refusal, the `in_handshake` re-entry counter,
//! the fresh-connection `SSL_clear`, the role assignment and the TLS version-family gate, and then
//! reproduces *the observable state a fresh connection is left in* once the authority's own first
//! read finds the peer BIO empty:
//!
//! * a **client** (writing its ClientHello is unlanded, but the authority reaches
//!   `TLS_ST_CW_CLNT_HELLO` before it reads) is left at `hand_state = TLS_ST_CW_CLNT_HELLO`,
//!   `statem_state = MSG_FLOW_READING`, `rwstate = SSL_READING`;
//! * a **server** (reading a ClientHello that is not there) is left at
//!   `hand_state = TLS_ST_BEFORE`, `statem_state = MSG_FLOW_READING`, `rwstate = SSL_READING`.
//!
//! Those are the values the admitted authority reports for the same call over an empty peer BIO
//! (measured: `SSL_connect` -> -1, `SSL_get_state` 13, `SSL_want` 3; `SSL_accept` -> -1,
//! `SSL_get_state` 0, `SSL_want` 3), so the state readers, `SSL_want` and the return value agree.
//! The divergence is the flight itself: the authority writes a ClientHello (and a server would
//! process one), and this slice writes nothing. That is recorded, not hidden, and no court reads a
//! flight's bytes.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The message layer is unlanded, so no flight is emitted.** `tls_setup_handshake`
//!   (`statem_lib.c`), `ssl_init_wbio_buffer` (`s3_lib.c`) and every `construct_message`/
//!   `process_message` handler (`statem_clnt.c`/`statem_srvr.c`), plus the extension units and the
//!   record layer's `ssl3_read_bytes`/`ssl3_write_bytes` protection path, are what would build and
//!   parse the messages. The reduced driver does not call them, so a fresh connection's peer BIO
//!   never receives a ClientHello. The handlers are named in `src/ssl/mod.rs` as the remaining work.
//! * **`ossl_statem_send_fatal` does not send an alert.** The authority calls `ssl3_send_alert`
//!   when `rlayer.wrlmethod != NULL`; this crate does not model the record-write method, so the
//!   alert is skipped and only the `MSG_FLOW_ERROR` transition is performed.
//! * **Only the fresh state is reachable.** With the message layer unlanded the flow never leaves
//!   `MSG_FLOW_READING` for a connection whose peer BIO is empty; the `FINISHED`, `OK` and
//!   post-handshake states are unreachable, exactly as the authority's are for that connection.
//! * **`statem_flush`'s `rwstate` restore is the authority's; the BIO it flushes need not exist.**
//!   A fresh connection that never got a flight has no buffering BIO, so the authority's
//!   `BIO_flush` is only reached once the engine runs; the transcribed body is the authority's.

use core::ffi::c_int;

use crate::runtime::bio::iolib::BIO_ctrl;
use crate::ssl::ssl_lib::{raise_statem, Ssl};

/// `TLS_ST_BEFORE` — `ssl.h:1066`, the first `OSSL_HANDSHAKE_STATE`; "no handshake has been
/// initiated yet".
pub const TLS_ST_BEFORE: c_int = 0;
/// `TLS_ST_OK` — `ssl.h:1067`, "a handshake has been successfully completed".
pub const TLS_ST_OK: c_int = 1;
/// `TLS_ST_CW_CLNT_HELLO` — `ssl.h:1078`, the client's post-ClientHello state.
const TLS_ST_CW_CLNT_HELLO: c_int = 13;
/// `TLS_ST_CR_SRVR_HELLO` — `ssl.h:1067`, the client's read-the-ServerHello state (17.2a).
const TLS_ST_CR_SRVR_HELLO: c_int = 3;
/// `TLS_ST_SR_CLNT_HELLO` — `ssl.h:1087`, the server's post-ClientHello-read state.
const TLS_ST_SR_CLNT_HELLO: c_int = 22;
/// `TLS_ST_SW_SRVR_HELLO` — `ssl.h` (24), the server's write-the-ServerHello state (17.2b).
const TLS_ST_SW_SRVR_HELLO: c_int = 24;
/// `TLS_ST_SW_ENCRYPTED_EXTENSIONS` — `ssl.h` (41), the state after the ServerHello (17.2b).
const TLS_ST_SW_ENCRYPTED_EXTENSIONS: c_int = 41;
/// `TLS_ST_SW_HELLO_REQ` — `ssl.h:1086`, the renegotiation request state.
const TLS_ST_SW_HELLO_REQ: c_int = 21;
/// `TLS_ST_SW_FINISHED` — `ssl.h:1105`, the `ossl_statem_export_allowed` exclusion.
const TLS_ST_SW_FINISHED: c_int = 40;
/// `TLS_ST_EARLY_DATA` — `ssl.h:1116`, the `ossl_statem_skip_early_data` predicate.
const TLS_ST_EARLY_DATA: c_int = 50;
/// `TLS_ST_PENDING_EARLY_DATA_END` — `ssl.h:1117`.
const TLS_ST_PENDING_EARLY_DATA_END: c_int = 51;

/// `MSG_FLOW_UNINITED` — `internal/statem.h:53`, "no handshake in progress".
const MSG_FLOW_UNINITED: c_int = 0;
/// `MSG_FLOW_ERROR` — `internal/statem.h:55`, "a permanent error with this connection".
const MSG_FLOW_ERROR: c_int = 1;
/// `MSG_FLOW_READING` — `internal/statem.h:57`.
const MSG_FLOW_READING: c_int = 2;
/// `MSG_FLOW_FINISHED` — `internal/statem.h:61`.
const MSG_FLOW_FINISHED: c_int = 4;

/// `SSL3_VERSION_MAJOR` — `ssl3.h:193`, the record-family major byte the gate compares.
const SSL3_VERSION_MAJOR: c_int = 3;
/// `SSL_AD_NO_ALERT` — `ssl3.h:328`, "we don't want to send an alert".
const SSL_AD_NO_ALERT: c_int = 0;

/// `SSL_NOTHING` — `ssl.h:932` (the `rwstate` idle value).
const SSL_NOTHING: c_int = 1;
/// `SSL_READING` — `ssl.h:934`.
const SSL_READING: c_int = 3;
/// `SSL_WRITING` — `ssl.h:933`.
const SSL_WRITING: c_int = 2;
/// `BIO_CTRL_FLUSH` — `bio.h:101`.
const BIO_CTRL_FLUSH: c_int = 11;

/// `SSL_EARLY_DATA_REJECTED` — `ssl.h:1989`.
const SSL_EARLY_DATA_REJECTED: c_int = 1;
/// `SSL_EARLY_DATA_ACCEPTED` — `ssl.h:1990`.
const SSL_EARLY_DATA_ACCEPTED: c_int = 2;
/// `SSL_EARLY_DATA_NOT_SENT` — `ssl.h:1988`.
const SSL_EARLY_DATA_NOT_SENT: c_int = 0;
/// `SSL_EARLY_DATA_WRITE_RETRY` — `ssl_local.h:594`.
const SSL_EARLY_DATA_WRITE_RETRY: c_int = 3;
/// `SSL_EARLY_DATA_FINISHED_WRITING` — `ssl_local.h:598`.
const SSL_EARLY_DATA_FINISHED_WRITING: c_int = 7;
/// `SSL_EARLY_DATA_FINISHED_READING` — `ssl_local.h:603`.
const SSL_EARLY_DATA_FINISHED_READING: c_int = 12;
/// `SSL_EARLY_DATA_WRITING` — `ssl_local.h:595`.
const SSL_EARLY_DATA_WRITING: c_int = 4;

/// `SSL_HRR_COMPLETE` — `ssl_local.h:1536`.
const SSL_HRR_COMPLETE: c_int = 2;

/// `TLS1_FLAGS_STATELESS` — `tls1.h:263`, set by `SSL_stateless` around `SSL_accept`.
const TLS1_FLAGS_STATELESS: u64 = 0x0002_0000;

/// `OSSL_HANDSHAKE_STATE SSL_get_state(const SSL *ssl)` — `ssl/statem/statem.c:74-82`.
///
/// # Safety
/// `ssl` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_state(ssl: *const Ssl) -> c_int {
    if ssl.is_null() {
        return TLS_ST_BEFORE;
    }
    // SAFETY: `ssl` is non-NULL and live per the caller's contract.
    unsafe { (*ssl).hand_state }
}

/// `int SSL_in_init(const SSL *s)` — `ssl/statem/statem.c:84-92`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_in_init(s: *const Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { (*s).in_init }
}

/// `int SSL_is_init_finished(const SSL *s)` — `ssl/statem/statem.c:94-102`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_init_finished(s: *const Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (in_init, hand_state) = unsafe { ((*s).in_init, (*s).hand_state) };
    c_int::from(in_init == 0 && hand_state == TLS_ST_OK)
}

/// `int SSL_in_before(const SSL *s)` — `ssl/statem/statem.c:104-120`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_in_before(s: *const Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (hand_state, statem_state) = unsafe { ((*s).hand_state, (*s).statem_state) };
    c_int::from(hand_state == TLS_ST_BEFORE && statem_state == MSG_FLOW_UNINITED)
}

/// `OSSL_HANDSHAKE_STATE ossl_statem_get_state(SSL_CONNECTION *s)` — `ssl/statem/statem.c:122-125`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
pub unsafe fn ossl_statem_get_state(s: *const Ssl) -> c_int {
    if s.is_null() {
        return TLS_ST_BEFORE;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { (*s).hand_state }
}

/// `void ossl_statem_clear(SSL_CONNECTION *s)` — `ssl/statem/statem.c:130-136`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_clear(s: *mut Ssl) {
    // SAFETY: `s` is live per the caller's contract; every write is to it.
    unsafe {
        (*s).statem_state = MSG_FLOW_UNINITED;
        (*s).hand_state = TLS_ST_BEFORE;
        ossl_statem_set_in_init(s, 1);
        (*s).statem_no_cert_verify = 0;
    }
}

/// `void ossl_statem_set_renegotiate(SSL_CONNECTION *s)` — `ssl/statem/statem.c:141-145`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_set_renegotiate(s: *mut Ssl) {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        ossl_statem_set_in_init(s, 1);
        (*s).statem_request_state = TLS_ST_SW_HELLO_REQ;
    }
}

/// `void ossl_statem_send_fatal(SSL_CONNECTION *s, int al)` — `ssl/statem/statem.c:147-156`,
/// reduced to the state transition.
///
/// The authority calls `ssl3_send_alert(s, SSL3_AL_FATAL, al)` when a record-write method is
/// installed; this crate models no record method, so the alert is skipped (recorded in the module
/// header).
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_send_fatal(s: *mut Ssl, _al: c_int) {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if (*s).in_init != 0 && (*s).statem_state == MSG_FLOW_ERROR {
            return;
        }
        ossl_statem_set_in_init(s, 1);
        (*s).statem_state = MSG_FLOW_ERROR;
    }
}

/// `void ossl_statem_fatal(SSL_CONNECTION *s, int al, int reason, const char *fmt, ...)` —
/// `ssl/statem/statem.c:164-174`, reduced to the `ERR_raise` plus [`ossl_statem_send_fatal`].
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_fatal(s: *mut Ssl, al: c_int, reason: c_int) {
    // SAFETY: a constant statem.c coordinate.
    unsafe { raise_statem(reason, c"ssl/statem/statem.c".as_ptr(), 170) };
    // SAFETY: `s` is live per the caller's contract.
    unsafe { ossl_statem_send_fatal(s, al) };
}

/// `int ossl_statem_in_error(const SSL_CONNECTION *s)` — `ssl/statem/statem.c:195-201`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_in_error(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    c_int::from(unsafe { (*s).statem_state } == MSG_FLOW_ERROR)
}

/// `void ossl_statem_set_in_init(SSL_CONNECTION *s, int init)` — `ssl/statem/statem.c:203-208`,
/// reduced past the record method's own `set_in_init`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_set_in_init(s: *mut Ssl, init: c_int) {
    // SAFETY: `s` is live per the caller's contract.
    unsafe { (*s).in_init = init };
}

/// `int ossl_statem_get_in_handshake(SSL_CONNECTION *s)` — `ssl/statem/statem.c:210-213`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_get_in_handshake(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe { (*s).statem_in_handshake }
}

/// `void ossl_statem_set_in_handshake(SSL_CONNECTION *s, int inhand)` — `ssl/statem/statem.c:215-221`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_set_in_handshake(s: *mut Ssl, inhand: c_int) {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if inhand != 0 {
            (*s).statem_in_handshake += 1;
        } else {
            (*s).statem_in_handshake -= 1;
        }
    }
}

/// `int ossl_statem_skip_early_data(SSL_CONNECTION *s)` — `ssl/statem/statem.c:224-235`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_skip_early_data(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if (*s).ext_early_data != SSL_EARLY_DATA_REJECTED {
            return 0;
        }
        if (*s).server == 0
            || (*s).hand_state != TLS_ST_EARLY_DATA
            || (*s).hello_retry_request == SSL_HRR_COMPLETE
        {
            return 0;
        }
    }
    1
}

/// `int ossl_statem_check_finish_init(SSL_CONNECTION *s, int sending)` — `ssl/statem/statem.c:245-277`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_check_finish_init(s: *mut Ssl, sending: c_int) -> c_int {
    // SAFETY: `s` is live per the caller's contract; every read/write is to it.
    unsafe {
        if sending == -1 {
            if (*s).hand_state == TLS_ST_PENDING_EARLY_DATA_END
                || (*s).hand_state == TLS_ST_EARLY_DATA
            {
                ossl_statem_set_in_init(s, 1);
                if (*s).early_data_state == SSL_EARLY_DATA_WRITE_RETRY {
                    (*s).early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;
                }
            }
        } else if (*s).server == 0 {
            if (sending != 0
                && ((*s).hand_state == TLS_ST_PENDING_EARLY_DATA_END
                    || (*s).hand_state == TLS_ST_EARLY_DATA)
                && (*s).early_data_state != SSL_EARLY_DATA_WRITING)
                || (sending == 0 && (*s).hand_state == TLS_ST_EARLY_DATA)
            {
                ossl_statem_set_in_init(s, 1);
                if sending != 0 && (*s).early_data_state == SSL_EARLY_DATA_WRITE_RETRY {
                    (*s).early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;
                }
            }
        } else if (*s).early_data_state == SSL_EARLY_DATA_FINISHED_READING
            && (*s).hand_state == TLS_ST_EARLY_DATA
        {
            ossl_statem_set_in_init(s, 1);
        }
    }
    1
}

/// `void ossl_statem_set_hello_verify_done(SSL_CONNECTION *s)` — `ssl/statem/statem.c:279-291`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_set_hello_verify_done(s: *mut Ssl) {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        (*s).statem_state = MSG_FLOW_UNINITED;
        ossl_statem_set_in_init(s, 1);
        (*s).hand_state = TLS_ST_SR_CLNT_HELLO;
    }
}

/// `int ossl_statem_connect(SSL *s)` — `ssl/statem/statem.c:293-301`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
pub unsafe extern "C" fn ossl_statem_connect(s: *mut Ssl) -> c_int {
    if s.is_null() {
        return -1;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { state_machine(s, false) }
}

/// `int ossl_statem_accept(SSL *s)` — `ssl/statem/statem.c:303-311`.
///
/// # Safety
/// `s` must be NULL or point to a live connection.
pub unsafe extern "C" fn ossl_statem_accept(s: *mut Ssl) -> c_int {
    if s.is_null() {
        return -1;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe { state_machine(s, true) }
}

/// `static int state_machine(SSL_CONNECTION *s, int server)` — `ssl/statem/statem.c:355-532`,
/// reduced at the message-construction boundary.
///
/// The authority's driver, its message-flow states and its read/write sub-state machines are
/// reproduced as far as the unlanded message layer permits (see the module header): the
/// `MSG_FLOW_ERROR` refusal, the `in_handshake` counter, the fresh-connection `SSL_clear`, the role
/// assignment and the version-family gate run, and then the connection is left in the exact state
/// the authority's first read reaches for an empty peer BIO.
///
/// # Safety
/// `s` must point to a live connection.
unsafe fn state_machine(s: *mut Ssl, server: bool) -> c_int {
    // SAFETY: `s` is live per the caller's contract; every read/write below is to it.
    unsafe {
        if (*s).statem_state == MSG_FLOW_ERROR {
            /* Shouldn't have been called if we're already in the error state */
            return -1;
        }

        // `statem.c:370-371`: `ERR_clear_error(); clear_sys_error();`. The crate models no system
        // error word, so only the queue is cleared (recorded in the module header).
        crate::runtime::err::ERR_clear_error();

        (*s).statem_in_handshake += 1;

        // `statem.c:376-383`: clear a connection that is not yet initialised, unless `SSL_stateless`
        // already did. The authority calls the public `SSL_clear`; this crate's is the reduced guard
        // that reports the authority's answer for a fresh connection.
        let needs_clear = ((*s).in_init == 0 || SSL_in_before(s) != 0)
            && ((*s).s3_flags & TLS1_FLAGS_STATELESS) == 0;
        if needs_clear {
            // SAFETY: `s` is live; `SSL_clear` reports 0 only for a NULL method.
            if crate::ssl::ssl_lib::SSL_clear(s) == 0 {
                (*s).statem_in_handshake -= 1;
                return -1;
            }
        }

        // `statem.c:396-401`: initialise the message flow, then assign the role the caller asked
        // for (`statem.c:403`).
        if (*s).statem_state == MSG_FLOW_UNINITED || (*s).statem_state == MSG_FLOW_FINISHED {
            if (*s).statem_state == MSG_FLOW_UNINITED {
                (*s).hand_state = TLS_ST_BEFORE;
                (*s).statem_request_state = TLS_ST_BEFORE;
            }
            (*s).server = c_int::from(server);

            // `statem.c:415-425`: the TLS/DTLS family gate. Every object this crate builds is TLS,
            // so the DTLS half is unreachable (recorded in the module header).
            if (*s).version >> 8 != SSL3_VERSION_MAJOR {
                ossl_statem_send_fatal(s, SSL_AD_NO_ALERT);
                (*s).statem_in_handshake -= 1;
                return -1;
            }
        }

        // The authority allocates `init_buf`, pushes the write-buffering BIO, calls
        // `tls_setup_handshake` and constructs its first flight. 17.2a lands the client's first
        // flight across that boundary -- `ossl_statem_client_write_transition`'s
        // `TLS_ST_BEFORE -> TLS_ST_CW_CLNT_HELLO`, then `tls_construct_client_hello` over the reduced
        // record write -- so the peer BIO receives a real ClientHello. 17.2b lands the server's
        // first flight: the server reads the ClientHello record over the reduced plaintext record
        // read, `tls_process_client_hello` chooses the version/cipher/group, and
        // `tls_construct_server_hello` writes a ServerHello. The server then waits for the next
        // flight, which the client's unlanded read path cannot produce.
        if !server && (*s).hand_state == TLS_ST_BEFORE {
            (*s).hand_state = TLS_ST_CW_CLNT_HELLO;
        }
        if !server && (*s).hand_state == TLS_ST_CW_CLNT_HELLO {
            // SAFETY: `s` is live; the write BIO is the caller's to write.
            if crate::ssl::statem::statem_clnt::write_client_hello(s) <= 0 {
                ossl_statem_send_fatal(s, SSL_AD_NO_ALERT);
                (*s).statem_in_handshake -= 1;
                return -1;
            }
            // The read transition that consumes the server's `ServerHello` would move the state to
            // `TLS_ST_CR_SRVR_HELLO`; the crate advances it here so a second `SSL_connect` does not
            // rebuild the flight (the authority leaves it at `TLS_ST_CW_CLNT_HELLO` until the read
            // transition runs, a recorded transient difference).
            (*s).hand_state = TLS_ST_CR_SRVR_HELLO;
        }

        // The server's first flight (17.2b). A fresh server at `TLS_ST_BEFORE` reads one plaintext
        // handshake record; when the ClientHello arrives it processes it and writes the ServerHello.
        // An empty read BIO leaves the server waiting, exactly as the authority's first read does.
        if server && (*s).hand_state == TLS_ST_BEFORE {
            let mut buf = [0u8; 4096];
            let mut rectype = 0u8;
            // SAFETY: `s` is live; `buf` is 4096 writable bytes.
            let n = crate::ssl::record::rec_layer_s3::ssl3_read_bytes(
                s,
                &mut rectype,
                buf.as_mut_ptr(),
                buf.len(),
            );
            if n <= 0 {
                (*s).statem_state = MSG_FLOW_READING;
                (*s).rwstate = SSL_READING;
                (*s).statem_in_handshake -= 1;
                return -1;
            }
            // SAFETY: `s` is live; `buf[..n]` is the handshake message.
            if crate::ssl::statem::statem_srvr::tls_process_client_hello(s, &buf[..n as usize]) == 0
            {
                ossl_statem_send_fatal(s, SSL_AD_NO_ALERT);
                (*s).statem_in_handshake -= 1;
                return -1;
            }
            (*s).hand_state = TLS_ST_SW_SRVR_HELLO;
            // SAFETY: `s` is live; the write BIO is the caller's to write.
            if crate::ssl::statem::statem_srvr::write_server_hello(s) <= 0 {
                ossl_statem_send_fatal(s, SSL_AD_NO_ALERT);
                (*s).statem_in_handshake -= 1;
                return -1;
            }
            (*s).hand_state = TLS_ST_SW_ENCRYPTED_EXTENSIONS;
        }

        (*s).statem_state = MSG_FLOW_READING;
        (*s).rwstate = SSL_READING;
        (*s).statem_in_handshake -= 1;
        -1
    }
}

/// `int statem_flush(SSL_CONNECTION *s)` — `ssl/statem/statem.c:945-954`.
///
/// # Safety
/// `s` must point to a live connection whose write BIO is the caller's to flush.
pub unsafe fn statem_flush(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        (*s).rwstate = SSL_WRITING;
        // `BIO_flush(b)` is `BIO_ctrl(b, BIO_CTRL_FLUSH, 0, NULL)` (`BIO_CTRL_FLUSH` = 11).
        if BIO_ctrl((*s).wbio, BIO_CTRL_FLUSH, 0, core::ptr::null_mut()) <= 0 {
            return 0;
        }
        (*s).rwstate = SSL_NOTHING;
    }
    1
}

/// `int ossl_statem_app_data_allowed(SSL_CONNECTION *s)` — `ssl/statem/statem.c:964-992`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_app_data_allowed(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if (*s).statem_state == MSG_FLOW_UNINITED {
            return 0;
        }
        if (*s).s3_in_read_app_data == 0 || (*s).s3_total_renegotiations == 0 {
            return 0;
        }
        if (*s).server != 0 {
            if (*s).hand_state == TLS_ST_BEFORE || (*s).hand_state == TLS_ST_SR_CLNT_HELLO {
                return 1;
            }
        } else if (*s).hand_state == TLS_ST_CW_CLNT_HELLO {
            return 1;
        }
    }
    0
}

/// `int ossl_statem_export_allowed(SSL_CONNECTION *s)` — `ssl/statem/statem.c:998-1002`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_export_allowed(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        c_int::from(
            (*s).s3_previous_server_finished_len != 0 && (*s).hand_state != TLS_ST_SW_FINISHED,
        )
    }
}

/// `int ossl_statem_export_early_allowed(SSL_CONNECTION *s)` — `ssl/statem/statem.c:1008-1017`.
///
/// # Safety
/// `s` must point to a live connection.
pub unsafe fn ossl_statem_export_early_allowed(s: *const Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        c_int::from(
            (*s).ext_early_data == SSL_EARLY_DATA_ACCEPTED
                || ((*s).server == 0 && (*s).ext_early_data != SSL_EARLY_DATA_NOT_SENT),
        )
    }
}
