//! Phase 16.5 — `ssl/statem/statem_clnt.c`: the client half of the TLS message
//! layer, reduced at the message-construction boundary.
//!
//! Phase 14.5b landed the state machine's control surface and driver
//! ([`crate::ssl::statem::statem`]) but not the client message construction and
//! parsing, so no flight was built or parsed on the client side. 16.5 lands the
//! **transition surface** this file owns: `ossl_statem_client_read_transition`
//! (the parser's decision that a given message type can follow the current hand
//! state) and `ossl_statem_client_write_transition` (the constructor's decision
//! what message to build next), for both TLS1.2 and TLS1.3, plus
//! `ossl_statem_client_max_message_size` and the three predicates the transitions
//! read.
//!
//! ## What is landed, and where the unit stops
//!
//! Every read/write transition arm that reads only the connection's own state is
//! transcribed. The transition surface is exactly what
//! [`crate::ssl::statem::statem`]'s driver would call next; its return values are
//! the authority's. The **message bodies** the transitions select —
//! `tls_construct_client_hello`, `tls_process_server_hello` and their 36 siblings
//! — are not landed: they build and parse bytes through the record layer
//! (`ssl3_write_bytes`/`ssl3_read_bytes`), the extension units
//! (`extensions_clnt.c`) and the key schedule (`t1_enc.c`/`tls13_enc.c`), none of
//! which is landed. So the dispatch stops at the transition and the body selection
//! is the boundary, recorded rather than fabricated. See
//! `docs/PHASE-16-SUBPHASES.md` §3.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The message bodies are the boundary.** No `tls_construct_*`/`tls_process_*`
//!   body is transcribed; the transitions name the states, not the bytes.
//! * **The DTLS arms are unreachable.** Every object this crate builds is a TLS
//!   method, so `SSL_CONNECTION_IS_DTLS` is false at every reachable entry; the
//!   two DTLS transitions fall through to the authority's error arm.
//! * **The timestamp writes are omitted.** `s->ts_msg_read = ossl_time_now()` and
//!   its write sibling set a `CLOCK_MONOTONIC` word. No court reads it, the record
//!   is not reproducible across runs, and the authority's `ossl_time_now` is
//!   `crypto/time.c`'s unit, so the assignment is not performed.
//! * **The post-handshake-auth digest restore is skipped.** The TLS1.3 read
//!   transition's PHA arm calls `tls13_restore_handshake_digest_for_pha`, which is
//!   `tls13_enc.c`'s; the state change it guards is performed and the restore is
//!   recorded as the boundary.
//! * **The `session_secret_cb`/ticket arm is reduced.** The TLS1.2 read
//!   transition's `s->ext.session_secret_cb != NULL && s->session->ext.tick != NULL`
//!   arm reads the session ticket, which is 14.7's; a fresh connection has neither,
//!   so the arm's condition is false and the reduction is unobservable there.
//!
//! SPDX-License-Identifier: Apache-2.0

// The transition functions mirror the authority's `switch`/nested-`if` shape arm for arm;
// collapsing an arm into a match guard would obscure the correspondence.
#![allow(clippy::collapsible_match)]

use core::ffi::c_int;

use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::statem::statem::ossl_statem_fatal;

// --- hand states (`include/openssl/ssl.h`) -----------------------------------
const TLS_ST_BEFORE: c_int = 0;
const TLS_ST_OK: c_int = 1;
const TLS_ST_CR_SRVR_HELLO: c_int = 3;
const TLS_ST_CR_CERT: c_int = 4;
const TLS_ST_CR_COMP_CERT: c_int = 5;
const TLS_ST_CR_CERT_STATUS: c_int = 6;
const TLS_ST_CR_KEY_EXCH: c_int = 7;
const TLS_ST_CR_CERT_REQ: c_int = 8;
const TLS_ST_CR_SRVR_DONE: c_int = 9;
const TLS_ST_CR_SESSION_TICKET: c_int = 10;
const TLS_ST_CR_CHANGE: c_int = 11;
const TLS_ST_CR_FINISHED: c_int = 12;
const TLS_ST_CW_CLNT_HELLO: c_int = 13;
const TLS_ST_CW_CERT: c_int = 14;
const TLS_ST_CW_COMP_CERT: c_int = 15;
const TLS_ST_CW_KEY_EXCH: c_int = 16;
const TLS_ST_CW_CERT_VRFY: c_int = 17;
const TLS_ST_CW_CHANGE: c_int = 18;
const TLS_ST_CW_FINISHED: c_int = 20;
const TLS_ST_CW_NEXT_PROTO: c_int = 19;
const TLS_ST_CR_ENCRYPTED_EXTENSIONS: c_int = 42;
const TLS_ST_CR_CERT_VRFY: c_int = 43;
const TLS_ST_CR_HELLO_REQ: c_int = 45;
const TLS_ST_CW_KEY_UPDATE: c_int = 47;
const TLS_ST_CR_KEY_UPDATE: c_int = 49;
const TLS_ST_EARLY_DATA: c_int = 50;
const TLS_ST_PENDING_EARLY_DATA_END: c_int = 51;
const TLS_ST_CW_END_OF_EARLY_DATA: c_int = 52;

// --- message types (`include/openssl/ssl3.h`) --------------------------------
const SSL3_MT_HELLO_REQUEST: c_int = 0;
const SSL3_MT_SERVER_HELLO: c_int = 2;
const SSL3_MT_NEWSESSION_TICKET: c_int = 4;
const SSL3_MT_ENCRYPTED_EXTENSIONS: c_int = 8;
const SSL3_MT_CERTIFICATE: c_int = 11;
const SSL3_MT_SERVER_KEY_EXCHANGE: c_int = 12;
const SSL3_MT_CERTIFICATE_REQUEST: c_int = 13;
const SSL3_MT_SERVER_DONE: c_int = 14;
const SSL3_MT_CERTIFICATE_VERIFY: c_int = 15;
const SSL3_MT_FINISHED: c_int = 20;
const SSL3_MT_CERTIFICATE_STATUS: c_int = 22;
const SSL3_MT_KEY_UPDATE: c_int = 24;
const SSL3_MT_COMPRESSED_CERTIFICATE: c_int = 25;
const SSL3_MT_CHANGE_CIPHER_SPEC: c_int = 0x0101;

// --- alerts / reasons --------------------------------------------------------
const SSL_AD_INTERNAL_ERROR: c_int = 80;
const SSL_AD_UNEXPECTED_MESSAGE: c_int = 10;
const ERR_R_INTERNAL_ERROR: c_int = 1 | (2 << 18) | (1 << 18);
const SSL_R_UNEXPECTED_MESSAGE: c_int = 245;

// --- connection flags --------------------------------------------------------
const SSL3_VERSION: c_int = 0x0300;
const TLS1_3_VERSION: c_int = 0x0304;
const DTLS1_VERSION_MAJOR: c_int = 0xFE;
const SSL_PHA_REQUESTED: c_int = 4;
const SSL_KEY_UPDATE_NONE: c_int = -1;
const SSL_HRR_NONE: c_int = 0;
const SSL_HRR_PENDING: c_int = 1;
const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 1 << 20;
const SSL_SENT_SHUTDOWN: c_int = 1;
const TLS1_FLAGS_SKIP_CERT_VERIFY: u64 = 0x0010;
const SSL_PSK: u64 = 8 | 16;

// --- transition return codes (`include/internal/statem.h`) --------------------
const WRITE_TRAN_ERROR: c_int = 0;
const WRITE_TRAN_CONTINUE: c_int = 1;
const WRITE_TRAN_FINISHED: c_int = 2;

// --- message length caps (`ssl/statem/statem_local.h`) -----------------------
const SERVER_HELLO_MAX_LENGTH: usize = 65607;
const CERTIFICATE_VERIFY_MAX_LENGTH: usize = 65539;
const SERVER_KEY_EXCH_MAX_LENGTH: usize = 102400;
const SERVER_HELLO_DONE_MAX_LENGTH: usize = 0;
const CCS_MAX_LENGTH: usize = 1;
const SESSION_TICKET_MAX_LENGTH_TLS13: usize = 131338;
const SESSION_TICKET_MAX_LENGTH_TLS12: usize = 65541;
const FINISHED_MAX_LENGTH: usize = 64;
const ENCRYPTED_EXTENSIONS_MAX_LENGTH: usize = 20000;
const KEY_UPDATE_MAX_LENGTH: usize = 1;
const SSL3_RT_MAX_PLAIN_LENGTH: usize = 16384;

#[inline]
fn is_tls13(s: *const Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe { (*s).version == TLS1_3_VERSION }
}

#[inline]
fn is_dtls(s: *const Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe { (*s).version >> 8 == DTLS1_VERSION_MAJOR }
}

/// `static ossl_inline int cert_req_allowed(SSL_CONNECTION *s)` — `statem_clnt.c:56-65`.
fn cert_req_allowed(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        let c = (*s).pending_cipher;
        if c.is_null() {
            return true;
        }
        let auth = (*c).algorithm_auth as u64;
        if ((*s).version > SSL3_VERSION && (auth & t::SSL_aNULL) != 0)
            || (auth & (t::SSL_aSRP | t::SSL_aPSK)) != 0
        {
            return false;
        }
    }
    true
}

/// `static int key_exchange_expected(SSL_CONNECTION *s)` — `statem_clnt.c:74-87`.
fn key_exchange_expected(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        let c = (*s).pending_cipher;
        if c.is_null() {
            return false;
        }
        let k = (*c).algorithm_mkey as u64;
        (k & (t::SSL_kDHE | t::SSL_kECDHE | t::SSL_kDHEPSK | t::SSL_kECDHEPSK | t::SSL_kSRP)) != 0
    }
}

/// `static int do_compressed_cert(SSL_CONNECTION *sc)` — `statem_clnt.c:428-433`.
fn do_compressed_cert(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe { (*s).ext_client_cert_type == 1 && (*s).ext_compress_certificate_from_peer_0 != 0 }
}

/// `static int ossl_statem_client13_read_transition(SSL_CONNECTION *s, int mt)` —
/// `statem_clnt.c:98-220`.
fn client13_read_transition(s: *mut Ssl, mt: c_int) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        match (*s).hand_state {
            TLS_ST_CW_CLNT_HELLO => {
                if mt == SSL3_MT_SERVER_HELLO {
                    (*s).hand_state = TLS_ST_CR_SRVR_HELLO;
                    return true;
                }
            }
            TLS_ST_CR_SRVR_HELLO => {
                if mt == SSL3_MT_ENCRYPTED_EXTENSIONS {
                    (*s).hand_state = TLS_ST_CR_ENCRYPTED_EXTENSIONS;
                    return true;
                }
            }
            TLS_ST_CR_ENCRYPTED_EXTENSIONS => {
                if (*s).hit != 0 {
                    if mt == SSL3_MT_FINISHED {
                        (*s).hand_state = TLS_ST_CR_FINISHED;
                        return true;
                    }
                } else {
                    if mt == SSL3_MT_CERTIFICATE_REQUEST {
                        (*s).hand_state = TLS_ST_CR_CERT_REQ;
                        return true;
                    }
                    if mt == SSL3_MT_CERTIFICATE {
                        (*s).hand_state = TLS_ST_CR_CERT;
                        return true;
                    }
                    if mt == SSL3_MT_COMPRESSED_CERTIFICATE
                        && (*s).ext_compress_certificate_sent != 0
                    {
                        (*s).hand_state = TLS_ST_CR_COMP_CERT;
                        return true;
                    }
                }
            }
            TLS_ST_CR_CERT_REQ => {
                if mt == SSL3_MT_CERTIFICATE {
                    (*s).hand_state = TLS_ST_CR_CERT;
                    return true;
                }
                if mt == SSL3_MT_COMPRESSED_CERTIFICATE && (*s).ext_compress_certificate_sent != 0 {
                    (*s).hand_state = TLS_ST_CR_COMP_CERT;
                    return true;
                }
            }
            TLS_ST_CR_CERT | TLS_ST_CR_COMP_CERT => {
                if mt == SSL3_MT_CERTIFICATE_VERIFY {
                    (*s).hand_state = TLS_ST_CR_CERT_VRFY;
                    return true;
                }
            }
            TLS_ST_CR_CERT_VRFY => {
                if mt == SSL3_MT_FINISHED {
                    (*s).hand_state = TLS_ST_CR_FINISHED;
                    return true;
                }
            }
            TLS_ST_OK => {
                if mt == SSL3_MT_NEWSESSION_TICKET {
                    (*s).hand_state = TLS_ST_CR_SESSION_TICKET;
                    return true;
                }
                if mt == SSL3_MT_KEY_UPDATE {
                    (*s).hand_state = TLS_ST_CR_KEY_UPDATE;
                    return true;
                }
                if mt == SSL3_MT_CERTIFICATE_REQUEST && (*s).post_handshake_auth == 1 {
                    (*s).post_handshake_auth = SSL_PHA_REQUESTED;
                    // `tls13_restore_handshake_digest_for_pha` is `tls13_enc.c`'s and is
                    // the boundary (module header).
                    (*s).hand_state = TLS_ST_CR_CERT_REQ;
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// `int ossl_statem_client_read_transition(SSL_CONNECTION *s, int mt)` —
/// `statem_clnt.c:231-426`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_client_read_transition(s: *mut Ssl, mt: c_int) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if is_tls13(s) {
            return c_int::from(client13_read_transition(s, mt));
        }

        let ske_expected;
        match (*s).hand_state {
            TLS_ST_CW_CLNT_HELLO => {
                if mt == SSL3_MT_SERVER_HELLO {
                    (*s).hand_state = TLS_ST_CR_SRVR_HELLO;
                    return 1;
                }
            }
            TLS_ST_EARLY_DATA => {
                if mt == SSL3_MT_SERVER_HELLO {
                    (*s).hand_state = TLS_ST_CR_SRVR_HELLO;
                    return 1;
                }
            }
            TLS_ST_CR_SRVR_HELLO => {
                if (*s).hit != 0 {
                    if (*s).ext_ticket_expected != 0 {
                        if mt == SSL3_MT_NEWSESSION_TICKET {
                            (*s).hand_state = TLS_ST_CR_SESSION_TICKET;
                            return 1;
                        }
                    } else if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                        (*s).hand_state = TLS_ST_CR_CHANGE;
                        return 1;
                    }
                } else {
                    let c = (*s).pending_cipher;
                    let auth = if c.is_null() {
                        0
                    } else {
                        (*c).algorithm_auth as u64
                    };
                    if (auth & (t::SSL_aNULL | t::SSL_aSRP | t::SSL_aPSK)) == 0 {
                        if mt == SSL3_MT_CERTIFICATE {
                            (*s).hand_state = TLS_ST_CR_CERT;
                            return 1;
                        }
                    } else {
                        ske_expected = key_exchange_expected(s);
                        if ske_expected
                            || ((if c.is_null() {
                                0
                            } else {
                                (*c).algorithm_mkey as u64
                            } & SSL_PSK)
                                != 0
                                && mt == SSL3_MT_SERVER_KEY_EXCHANGE)
                        {
                            if mt == SSL3_MT_SERVER_KEY_EXCHANGE {
                                (*s).hand_state = TLS_ST_CR_KEY_EXCH;
                                return 1;
                            }
                        } else if mt == SSL3_MT_CERTIFICATE_REQUEST && cert_req_allowed(s) {
                            (*s).hand_state = TLS_ST_CR_CERT_REQ;
                            return 1;
                        } else if mt == SSL3_MT_SERVER_DONE {
                            (*s).hand_state = TLS_ST_CR_SRVR_DONE;
                            return 1;
                        }
                    }
                }
            }
            TLS_ST_CR_CERT | TLS_ST_CR_COMP_CERT | TLS_ST_CR_CERT_STATUS => {
                if mt == SSL3_MT_CERTIFICATE_STATUS && (*s).ext_status_expected != 0 {
                    (*s).hand_state = TLS_ST_CR_CERT_STATUS;
                    return 1;
                }
                ske_expected = key_exchange_expected(s);
                let c = (*s).pending_cipher;
                if ske_expected
                    || ((if c.is_null() {
                        0
                    } else {
                        (*c).algorithm_mkey as u64
                    } & SSL_PSK)
                        != 0
                        && mt == SSL3_MT_SERVER_KEY_EXCHANGE)
                {
                    if mt == SSL3_MT_SERVER_KEY_EXCHANGE {
                        (*s).hand_state = TLS_ST_CR_KEY_EXCH;
                        return 1;
                    }
                    return 0;
                }
                if mt == SSL3_MT_CERTIFICATE_REQUEST {
                    if cert_req_allowed(s) {
                        (*s).hand_state = TLS_ST_CR_CERT_REQ;
                        return 1;
                    }
                    return 0;
                }
                if mt == SSL3_MT_SERVER_DONE {
                    (*s).hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
            TLS_ST_CR_KEY_EXCH => {
                if mt == SSL3_MT_CERTIFICATE_REQUEST {
                    if cert_req_allowed(s) {
                        (*s).hand_state = TLS_ST_CR_CERT_REQ;
                        return 1;
                    }
                    return 0;
                }
                if mt == SSL3_MT_SERVER_DONE {
                    (*s).hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
            TLS_ST_CR_CERT_REQ => {
                if mt == SSL3_MT_SERVER_DONE {
                    (*s).hand_state = TLS_ST_CR_SRVR_DONE;
                    return 1;
                }
            }
            TLS_ST_CW_FINISHED => {
                if (*s).ext_ticket_expected != 0 {
                    if mt == SSL3_MT_NEWSESSION_TICKET {
                        (*s).hand_state = TLS_ST_CR_SESSION_TICKET;
                        return 1;
                    }
                } else if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                    (*s).hand_state = TLS_ST_CR_CHANGE;
                    return 1;
                }
            }
            TLS_ST_CR_SESSION_TICKET => {
                if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                    (*s).hand_state = TLS_ST_CR_CHANGE;
                    return 1;
                }
            }
            TLS_ST_CR_CHANGE => {
                if mt == SSL3_MT_FINISHED {
                    (*s).hand_state = TLS_ST_CR_FINISHED;
                    return 1;
                }
            }
            TLS_ST_OK => {
                if mt == SSL3_MT_HELLO_REQUEST {
                    (*s).hand_state = TLS_ST_CR_HELLO_REQ;
                    return 1;
                }
            }
            _ => {}
        }

        if is_dtls(s) && mt == SSL3_MT_CHANGE_CIPHER_SPEC {
            // The DTLS out-of-order-CCS drop path; unreachable here (module header).
            (*s).statem_state = 2; // MSG_FLOW_READING
            return 0;
        }
        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
        0
    }
}

/// `static WRITE_TRAN ossl_statem_client13_write_transition(SSL_CONNECTION *s)` —
/// `statem_clnt.c:440-536`.
fn client13_write_transition(s: *mut Ssl) -> c_int {
    // SAFETY: the caller passes a live connection.
    unsafe {
        match (*s).hand_state {
            TLS_ST_CR_CERT_REQ => {
                if (*s).post_handshake_auth == SSL_PHA_REQUESTED {
                    (*s).hand_state = if do_compressed_cert(s) {
                        TLS_ST_CW_COMP_CERT
                    } else {
                        TLS_ST_CW_CERT
                    };
                    return WRITE_TRAN_CONTINUE;
                }
                if ((*s).shutdown & SSL_SENT_SHUTDOWN) == 0 {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return WRITE_TRAN_ERROR;
                }
                (*s).hand_state = TLS_ST_OK;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CR_FINISHED => {
                if (*s).early_data_state == 3 // SSL_EARLY_DATA_WRITE_RETRY
                    || (*s).early_data_state == 7
                // SSL_EARLY_DATA_FINISHED_WRITING
                {
                    (*s).hand_state = TLS_ST_PENDING_EARLY_DATA_END;
                } else if ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
                    && (*s).hello_retry_request == SSL_HRR_NONE
                {
                    (*s).hand_state = TLS_ST_CW_CHANGE;
                } else if (*s).s3_tmp_cert_req == 0 {
                    (*s).hand_state = TLS_ST_CW_FINISHED;
                } else if do_compressed_cert(s) {
                    (*s).hand_state = TLS_ST_CW_COMP_CERT;
                } else {
                    (*s).hand_state = TLS_ST_CW_CERT;
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_PENDING_EARLY_DATA_END => {
                if (*s).ext_early_data == 2 {
                    // SSL_EARLY_DATA_ACCEPTED
                    (*s).hand_state = TLS_ST_CW_END_OF_EARLY_DATA;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = client13_cert_or_finished(s);
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_END_OF_EARLY_DATA | TLS_ST_CW_CHANGE => {
                (*s).hand_state = client13_cert_or_finished(s);
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_COMP_CERT | TLS_ST_CW_CERT => {
                (*s).hand_state = if (*s).s3_tmp_cert_req == 1 {
                    TLS_ST_CW_CERT_VRFY
                } else {
                    TLS_ST_CW_FINISHED
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_CERT_VRFY => {
                (*s).hand_state = TLS_ST_CW_FINISHED;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CR_KEY_UPDATE
            | TLS_ST_CW_KEY_UPDATE
            | TLS_ST_CR_SESSION_TICKET
            | TLS_ST_CW_FINISHED => {
                (*s).hand_state = TLS_ST_OK;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_OK => {
                if (*s).key_update != SSL_KEY_UPDATE_NONE {
                    (*s).hand_state = TLS_ST_CW_KEY_UPDATE;
                    return WRITE_TRAN_CONTINUE;
                }
                WRITE_TRAN_FINISHED
            }
            _ => {
                ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                WRITE_TRAN_ERROR
            }
        }
    }
}

/// The `cert_req == 0 ? FINISHED : (compressed ? COMP_CERT : CERT)` step shared by
/// the TLS1.3 write transition's `PENDING_EARLY_DATA_END`/`CW_CHANGE` arms
/// (`statem_clnt.c:500-507`).
fn client13_cert_or_finished(s: *mut Ssl) -> c_int {
    // SAFETY: the caller passes a live connection.
    unsafe {
        if (*s).s3_tmp_cert_req == 0 {
            TLS_ST_CW_FINISHED
        } else if do_compressed_cert(s) {
            TLS_ST_CW_COMP_CERT
        } else {
            TLS_ST_CW_CERT
        }
    }
}

/// `WRITE_TRAN ossl_statem_client_write_transition(SSL_CONNECTION *s)` —
/// `statem_clnt.c:542-708`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_client_write_transition(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if is_tls13(s) {
            return client13_write_transition(s);
        }
        match (*s).hand_state {
            TLS_ST_OK => {
                if (*s).renegotiate == 0 {
                    return WRITE_TRAN_FINISHED;
                }
                (*s).hand_state = TLS_ST_CW_CLNT_HELLO;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_BEFORE => {
                (*s).hand_state = TLS_ST_CW_CLNT_HELLO;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_CLNT_HELLO => {
                if (*s).early_data_state == 2
                // SSL_EARLY_DATA_CONNECTING
                {
                    (*s).hand_state = if ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0 {
                        TLS_ST_CW_CHANGE
                    } else {
                        TLS_ST_EARLY_DATA
                    };
                    return WRITE_TRAN_CONTINUE;
                }
                WRITE_TRAN_FINISHED
            }
            TLS_ST_CR_SRVR_HELLO => {
                (*s).hand_state = if ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
                    && (*s).early_data_state != 7
                {
                    TLS_ST_CW_CHANGE
                } else {
                    TLS_ST_CW_CLNT_HELLO
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_EARLY_DATA => WRITE_TRAN_FINISHED,
            TLS_ST_CR_SRVR_DONE => {
                (*s).hand_state = if (*s).s3_tmp_cert_req != 0 {
                    TLS_ST_CW_CERT
                } else {
                    TLS_ST_CW_KEY_EXCH
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_CERT => {
                (*s).hand_state = TLS_ST_CW_KEY_EXCH;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_KEY_EXCH => {
                (*s).hand_state = if (*s).s3_tmp_cert_req == 1 {
                    TLS_ST_CW_CERT_VRFY
                } else {
                    TLS_ST_CW_CHANGE
                };
                if ((*s).s3_flags & TLS1_FLAGS_SKIP_CERT_VERIFY) != 0 {
                    (*s).hand_state = TLS_ST_CW_CHANGE;
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_CERT_VRFY => {
                (*s).hand_state = TLS_ST_CW_CHANGE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_CHANGE => {
                if (*s).hello_retry_request == SSL_HRR_PENDING {
                    (*s).hand_state = TLS_ST_CW_CLNT_HELLO;
                } else if (*s).early_data_state == 2 {
                    (*s).hand_state = TLS_ST_EARLY_DATA;
                } else {
                    (*s).hand_state = if (*s).s3_npn_seen != 0 {
                        TLS_ST_CW_NEXT_PROTO
                    } else {
                        TLS_ST_CW_FINISHED
                    };
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_NEXT_PROTO => {
                (*s).hand_state = TLS_ST_CW_FINISHED;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CW_FINISHED => {
                if (*s).hit != 0 {
                    (*s).hand_state = TLS_ST_OK;
                    WRITE_TRAN_CONTINUE
                } else {
                    WRITE_TRAN_FINISHED
                }
            }
            TLS_ST_CR_FINISHED => {
                (*s).hand_state = if (*s).hit != 0 {
                    TLS_ST_CW_CHANGE
                } else {
                    TLS_ST_OK
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_CR_HELLO_REQ => {
                if crate::ssl::s3_lib::ssl3_renegotiate_check(s, 1) != 0 {
                    // `tls_setup_handshake` (`statem_lib.c`) is the boundary (module header).
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return WRITE_TRAN_ERROR;
                }
                (*s).hand_state = TLS_ST_OK;
                WRITE_TRAN_CONTINUE
            }
            _ => {
                ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                WRITE_TRAN_ERROR
            }
        }
    }
}

/// `size_t ossl_statem_client_max_message_size(SSL_CONNECTION *s)` —
/// `statem_clnt.c:1029-1086`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_client_max_message_size(s: *mut Ssl) -> usize {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        match (*s).hand_state {
            TLS_ST_CR_SRVR_HELLO => SERVER_HELLO_MAX_LENGTH,
            TLS_ST_CR_COMP_CERT | TLS_ST_CR_CERT | TLS_ST_CR_CERT_REQ => (*s).max_cert_list,
            TLS_ST_CR_CERT_VRFY => CERTIFICATE_VERIFY_MAX_LENGTH,
            TLS_ST_CR_CERT_STATUS => SSL3_RT_MAX_PLAIN_LENGTH,
            TLS_ST_CR_KEY_EXCH => SERVER_KEY_EXCH_MAX_LENGTH,
            TLS_ST_CR_SRVR_DONE => SERVER_HELLO_DONE_MAX_LENGTH,
            TLS_ST_CR_CHANGE => {
                if (*s).version == 0x0100 {
                    3
                } else {
                    CCS_MAX_LENGTH
                }
            }
            TLS_ST_CR_SESSION_TICKET => {
                if is_tls13(s) {
                    SESSION_TICKET_MAX_LENGTH_TLS13
                } else {
                    SESSION_TICKET_MAX_LENGTH_TLS12
                }
            }
            TLS_ST_CR_FINISHED => FINISHED_MAX_LENGTH,
            TLS_ST_CR_ENCRYPTED_EXTENSIONS => ENCRYPTED_EXTENSIONS_MAX_LENGTH,
            TLS_ST_CR_KEY_UPDATE => KEY_UPDATE_MAX_LENGTH,
            _ => 0,
        }
    }
}
