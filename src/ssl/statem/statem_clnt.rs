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

use crate::packet::{
    WPACKET_close, WPACKET_get_length, WPACKET_put_bytes_u16, WPACKET_put_bytes_u8,
    WPACKET_start_sub_packet_len__, Wpacket,
};
use crate::rand::rand_lib::RAND_bytes;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_lib::{SSL_get_ciphers, Ssl};
use crate::ssl::statem::extensions_clnt::tls_construct_extensions;
use crate::ssl::statem::statem::ossl_statem_fatal;
use crate::ssl::t1_lib::{ssl_cipher_disabled, ssl_set_client_disabled};

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

// ---------------------------------------------------------------------------------------------
// Phase 17.2a — the client's initial flight: `tls_construct_client_hello` (statem_clnt.c:1176-1361)
// and the two write-path helpers it is driven through.
// ---------------------------------------------------------------------------------------------

/// `TLS1_2_VERSION` — `ssl3.h` (the legacy ClientHello version for TLS1.3).
const TLS1_2_VERSION: c_int = 0x0303;
/// `SSL3_MT_CLIENT_HELLO` — `ssl3.h`.
const SSL3_MT_CLIENT_HELLO: u8 = 1;
/// `SSL_SECOP_CIPHER_SUPPORTED` — `ssl.h:2724`.
const SSL_SECOP_CIPHER_SUPPORTED: c_int = 6;
/// `SSL3_RANDOM_SIZE` — `ssl3.h` (32).
const SSL3_RANDOM_SIZE: usize = 32;
/// `SSL3_RT_HANDSHAKE` — `ssl3.h` (22).
const SSL3_RT_HANDSHAKE: u8 = 22;

/// `int ssl3_set_handshake_header(SSL_CONNECTION *s, WPACKET *pkt, int htype)` —
/// `ssl/s3_lib.c:3789-3800`.
///
/// # Safety
/// `pkt` must be a live packet.
pub(crate) unsafe fn ssl3_set_handshake_header(pkt: *mut Wpacket, htype: u8) -> c_int {
    // SAFETY: `pkt` is live. `WPACKET_start_sub_packet_u24` is `start_sub_packet_len__(pkt, 3)`.
    unsafe {
        if WPACKET_put_bytes_u8(pkt, htype) == 0 || WPACKET_start_sub_packet_len__(pkt, 3) == 0 {
            return 0;
        }
    }
    1
}

/// `int tls_close_construct_packet(SSL_CONNECTION *s, WPACKET *pkt, int htype)` —
/// `ssl/statem/statem_lib.c:126-138`, returning the message length through `msglen`.
///
/// # Safety
/// `pkt` must be a live packet and `msglen` writable.
pub(crate) unsafe fn tls_close_construct_packet(pkt: *mut Wpacket, msglen: *mut usize) -> c_int {
    // SAFETY: `pkt`/`msglen` are live per the contract.
    unsafe {
        if WPACKET_close(pkt) == 0 || WPACKET_get_length(pkt, msglen) == 0 {
            return 0;
        }
    }
    1
}

/// `int ssl_cipher_list_to_bytes(SSL_CONNECTION *s, STACK_OF(SSL_CIPHER) *sk, WPACKET *pkt)` —
/// `ssl/statem/statem_clnt.c:4160-4247`, reduced to the client's own offered list.
///
/// The disabled-cipher filter, the sanity check that the maximum offered version has a cipher, and
/// the version gate are the authority's; the empty-renegotiation SCSV arm and the
/// `OPENSSL_MAX_TLS1_2_CIPHER_LENGTH` chop are not taken (a named boundary in 17.2a).
///
/// # Safety
/// `s` must be a live connection; `pkt` must be a live packet.
unsafe fn ssl_cipher_list_to_bytes(
    s: *mut Ssl,
    sk: *mut crate::runtime::stack::OpenSslStack,
    pkt: *mut Wpacket,
) -> c_int {
    // SAFETY: `s` is live; `ssl_set_client_disabled` reads/writes its masks.
    if unsafe { ssl_set_client_disabled(s) } == 0 {
        return 0;
    }
    if sk.is_null() {
        return 0;
    }

    let mut totlen = 0u32;
    let mut maxverok = 0;
    // SAFETY: `sk` is a live stack of `const SSL_CIPHER *`.
    let n = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..n {
        // SAFETY: `i` is in range; the row is a table `SSL_CIPHER`.
        let c = unsafe { OPENSSL_sk_value(sk, i) as *const SslCipher };
        if c.is_null() {
            continue;
        }
        // SAFETY: `s`/`c` are live; the filter is the authority's own.
        if unsafe { ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED, 0) } != 0 {
            continue;
        }
        // SAFETY: `c` is a table row.
        let (min_tls, max_tls, id) = unsafe { ((*c).min_tls, (*c).max_tls, (*c).id) };
        // `ssl3_put_cipher_by_char` writes the 16-bit wire id (`ssl/s3_lib.c`).
        // SAFETY: `pkt` is live.
        if unsafe { crate::packet::WPACKET_put_bytes_u16(pkt, id as u16) } == 0 {
            return 0;
        }
        if maxverok == 0 {
            // `ssl_version_cmp(s, maxproto, s->s3.tmp.max_ver) >= 0 && min <= max_ver`.
            // SAFETY: `s` is live.
            let max_ver = unsafe { (*s).max_ver };
            if max_tls >= max_ver && min_tls <= max_ver {
                maxverok = 1;
            }
        }
        totlen += 2;
    }

    if totlen == 0 || maxverok == 0 {
        return 0;
    }
    1
}

/// `CON_FUNC_RETURN tls_construct_client_hello(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `ssl/statem/statem_clnt.c:1176-1361`.
///
/// The handshake header is written by the caller (`ssl3_set_handshake_header`), as in the
/// authority's `state_machine`. The session object (`ssl_get_new_session`) is 14.7's and unlanded;
/// this slice fills `client_random` and the middlebox-compatibility session id directly from
/// `RAND_bytes`, which is the reachable fresh-connection arm, and records the reduction.
///
/// # Safety
/// `s` must be a live connection; `pkt` must be a live packet.
pub(crate) unsafe fn tls_construct_client_hello(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // `ssl_set_client_hello_version`: for a TLS1.3-capable connection the legacy version is 1.2.
    // SAFETY: `s` is live.
    unsafe { (*s).client_version = TLS1_2_VERSION };

    // `ssl_fill_hello_random` (`ssl/statem/statem_lib.c`): the fresh-connection arm is RAND.
    // SAFETY: `s` is live; `client_random` is a 32-byte array.
    if unsafe { RAND_bytes((*s).client_random.as_mut_ptr(), SSL3_RANDOM_SIZE as c_int) } <= 0 {
        return 0;
    }

    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, (*s).client_version as u16) == 0
            || crate::packet::WPACKET_memcpy(
                pkt,
                (*s).client_random.as_ptr().cast(),
                SSL3_RANDOM_SIZE,
            ) == 0
        {
            return 0;
        }
    }

    // Session ID. `ssl_get_new_session` is 14.7's and unlanded; the reachable arm for a TLS1.3
    // connection with `SSL_OP_ENABLE_MIDDLEBOX_COMPAT` is `s->tmp_session_id`, 32 random bytes.
    let mut sess_id = [0u8; SSL3_RANDOM_SIZE];
    // SAFETY: `s` is live; the condition is the authority's (`statem_clnt.c:1271-1286`).
    let sess_id_len = unsafe {
        if ((*s).new_session != 0 || (*s).version == TLS1_3_VERSION)
            && (*s).version == TLS1_3_VERSION
            && ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
        {
            if RAND_bytes(sess_id.as_mut_ptr(), SSL3_RANDOM_SIZE as c_int) <= 0 {
                return 0;
            }
            SSL3_RANDOM_SIZE
        } else {
            0
        }
    };

    // SAFETY: `pkt` is live. `WPACKET_start_sub_packet_u8` is `start_sub_packet_len__(pkt, 1)`.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, 1) == 0
            || (sess_id_len != 0
                && crate::packet::WPACKET_memcpy(pkt, sess_id.as_ptr().cast(), sess_id_len) == 0)
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    // Ciphers (`statem_clnt.c:1312-1326`): `WPACKET_start_sub_packet_u16` around the list.
    // SAFETY: `pkt` is live; `SSL_get_ciphers(s)` is the connection's own stack.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, 2) == 0 {
            return 0;
        }
        let ciphers = SSL_get_ciphers(s);
        if ssl_cipher_list_to_bytes(s, ciphers, pkt) == 0 {
            return 0;
        }
        if WPACKET_close(pkt) == 0 {
            return 0;
        }
    }

    // Compression (`statem_clnt.c:1328-1352`): compression is off by default, so only NULL (0).
    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, 1) == 0
            || WPACKET_put_bytes_u8(pkt, 0) == 0
            || WPACKET_close(pkt) == 0
        {
            return 0;
        }
    }

    // Extensions (`statem_clnt.c:1354-1358`).
    // SAFETY: `s`/`pkt` are live.
    if unsafe { tls_construct_extensions(s, pkt) } == 0 {
        return 0;
    }
    1
}

/// Write the client's initial handshake flight: build the ClientHello into `buf`, frame it as one
/// plaintext handshake record and write it to the connection's write BIO.
///
/// This is the reduced transcription of `statem.c:857-905`'s construct-and-send arm for
/// `TLS_ST_CW_CLNT_HELLO` -- `ssl_set_handshake_header` + `tls_construct_client_hello` +
/// `ssl_close_construct_packet` + `ssl3_do_write` -- with `s->init_buf` replaced by the caller's
/// buffer and the buffering BIO omitted (both recorded in the module header).
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write.
pub(crate) unsafe fn write_client_hello(s: *mut Ssl) -> c_int {
    let mut buf = [0u8; 4096];
    // SAFETY: a zeroed `WPACKET` is a valid starting state for `WPACKET_init_static_len`.
    let mut pkt: Wpacket = unsafe { core::mem::zeroed() };
    let mut msglen: usize = 0;

    // SAFETY: `pkt`/`buf` are live locals; the buffer outlives the packet.
    unsafe {
        if crate::packet::WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0) == 0 {
            return 0;
        }
        if ssl3_set_handshake_header(&mut pkt, SSL3_MT_CLIENT_HELLO) == 0
            || tls_construct_client_hello(s, &mut pkt) == 0
            || tls_close_construct_packet(&mut pkt, &mut msglen) == 0
            || crate::packet::WPACKET_finish(&mut pkt) == 0
        {
            crate::packet::WPACKET_cleanup(&mut pkt);
            return 0;
        }
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(
            s,
            SSL3_RT_HANDSHAKE,
            buf.as_ptr(),
            msglen,
        )
    }
}
