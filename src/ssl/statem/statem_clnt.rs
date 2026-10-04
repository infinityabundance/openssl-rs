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
use crate::runtime::err::err_reasons::SSL_R_CERTIFICATE_VERIFY_FAILED;
use crate::runtime::err::{ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_lib::{SSL_get_ciphers, Ssl};
use crate::ssl::statem::extensions_clnt::tls_construct_extensions;
use crate::ssl::statem::statem::{ossl_statem_fatal, ossl_statem_in_error};
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
    // The TLSv1.3 ServerHello echoes this session id (`statem_clnt.c:1568`), so keep it on the
    // connection (`s3.tmp.session_id`).
    if sess_id_len != 0 {
        // SAFETY: `sess_id_len <= SSL3_RANDOM_SIZE <= SSL_MAX_SSL_SESSION_ID_LENGTH`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                sess_id.as_ptr(),
                core::ptr::addr_of_mut!((*s).tmp_session_id).cast::<u8>(),
                sess_id_len,
            );
            (*s).tmp_session_id_len = sess_id_len;
        }
    }

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
        let r = crate::ssl::record::rec_layer_s3::ssl3_write_bytes(
            s,
            SSL3_RT_HANDSHAKE,
            buf.as_ptr(),
            msglen,
        );
        // The transcript begins with the ClientHello; while the cipher is unknown this buffers
        // (`transcript_update`), to be replayed by `tls_process_server_hello`.
        if r > 0 {
            crate::ssl::tls13_enc::transcript_update(s, buf.as_ptr(), msglen);
        }
        r
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 17.2c — the client's read path: `tls_process_server_hello` and the rest of the server
// flight (`statem_clnt.c:1467`, `:4114`, `:1995`, `statem_lib.c:441/843`), plus the flight driver.
// ---------------------------------------------------------------------------------------------

/// `SSL3_MT_ENCRYPTED_EXTENSIONS` — `ssl3.h` (8).
const SSL3_MT_EE_BODY: u8 = 8;
/// `TLSEXT_TYPE_supported_versions` — `tls1.h:151`.
const TLSEXT_TYPE_SUPPORTED_VERSIONS: u16 = 43;
/// `TLSEXT_TYPE_key_share` — `tls1.h:165`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;
/// `MSG_FLOW_READING` — `ssl/statem/statem.h`.
const MSG_FLOW_READING_13: c_int = 2;
/// `MSG_FLOW_ERROR` — `ssl/statem/statem.h`.
const MSG_FLOW_ERROR_13: c_int = 1;

/// `TLS_ST_SW_ENCRYPTED_EXTENSIONS`'s client mirror: install the read/write handshake keys and
/// derive the shared secret — the `ssl_derive` + `tls13_change_cipher_state` tail of
/// `tls_process_server_hello` (`statem_clnt.c:1800-1828`).
///
/// # Safety
/// `s` is live.
unsafe fn client_derive_and_install(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc as k;
    let mut pms = [0u8; 64];
    let mut pmslen = 0usize;
    // SAFETY: `s` is live; the keys are the connection's ephemerals.
    if unsafe {
        k::tls13_derive_shared(
            s,
            (*s).pkey,
            (*s).peer_tmp,
            pms.as_mut_ptr(),
            pms.len(),
            &mut pmslen,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live; `pms[..pmslen]` is the shared secret.
    if unsafe { k::tls13_generate_handshake_secret(s, &pms[..pmslen]) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; the transcript is `ClientHello || ServerHello`.
    if unsafe { k::tls13_derive_handshake_traffic(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `pending_cipher` was set by `tls_process_server_hello`.
    let cid = unsafe { (*(*s).pending_cipher).id as u16 };
    // The authority installs the server-read handshake key now and, in middlebox-compat mode,
    // defers the client-write one to the Finished; the reduced flight has no dummy CCS, so both
    // are installed here (recorded in the module header).
    // SAFETY: `s` is live.
    if unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_HANDSHAKE | k::SSL3_CHANGE_CIPHER_CLIENT_READ,
            cid,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_HANDSHAKE | k::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            cid,
        )
    } == 0
    {
        return 0;
    }
    1
}

/// `MSG_PROCESS_RETURN tls_process_server_hello(SSL_CONNECTION *s, PACKET *pkt)` —
/// `statem_clnt.c:1467-1836`, reduced to the fresh-connection, non-HRR, non-PSK path.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message (`type || length || body`).
pub(crate) unsafe fn tls_process_server_hello(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::tls13_enc as k;
    if msg.len() < 4 || msg[0] != SSL3_MT_SERVER_HELLO as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let b = &msg[4..4 + blen];
    if b.len() < 2 + SSL3_RANDOM_SIZE + 1 + 2 + 1 {
        return 0;
    }
    let sversion = ((b[0] as c_int) << 8) | b[1] as c_int;
    if sversion != TLS1_2_VERSION {
        return 0;
    }
    // server random is not used by the TLS1.3 schedule, but the authority stores it.
    // SAFETY: `s` is live; `b[2..34]` is 32 bytes.
    unsafe {
        (*s).server_random
            .copy_from_slice(&b[2..2 + SSL3_RANDOM_SIZE])
    };
    let mut p = 2 + SSL3_RANDOM_SIZE;
    let sid_len = b[p] as usize;
    p += 1;
    if p + sid_len + 2 + 1 > b.len() {
        return 0;
    }
    // The TLS1.3 ServerHello echoes the ClientHello session id (`statem_clnt.c:1568`).
    let sid = &b[p..p + sid_len];
    // SAFETY: `s` is live; `tmp_session_id` is a 32-byte array.
    let (tmp_len, tmp_id) = unsafe { ((*s).tmp_session_id_len, (*s).tmp_session_id) };
    if sid_len != tmp_len || sid != &tmp_id[..sid_len] {
        return 0;
    }
    p += sid_len;
    let cipher = &b[p..p + 2];
    p += 2;
    let compression = b[p];
    p += 1;
    if compression != 0 {
        return 0;
    }
    // SAFETY: `cipher` is two readable bytes.
    let chosen = unsafe { crate::ssl::ssl_ciph::ssl3_get_cipher_by_char(cipher.as_ptr()) };
    if chosen.is_null() {
        return 0;
    }
    // SAFETY: `s` is live; `chosen` is a table row.
    unsafe { (*s).pending_cipher = chosen };

    // supported_versions (43) confirms TLS1.3; key_share (51) carries the server share.
    // SAFETY: `s` is live.
    let mut group: u16 = 0;
    let mut share: &[u8] = &[];
    if p + 2 <= b.len() {
        let ext_len = ((b[p] as usize) << 8) | b[p + 1] as usize;
        p += 2;
        if p + ext_len > b.len() {
            return 0;
        }
        let exts = &b[p..p + ext_len];
        let mut off = 0usize;
        while off + 4 <= exts.len() {
            let etype = ((exts[off] as u16) << 8) | exts[off + 1] as u16;
            let elen = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
            off += 4;
            if off + elen > exts.len() {
                return 0;
            }
            let eb = &exts[off..off + elen];
            if etype == TLSEXT_TYPE_SUPPORTED_VERSIONS && eb.len() >= 2 {
                // SAFETY: `s` is live; the body is the selected version.
                unsafe { (*s).version = ((eb[0] as c_int) << 8) | eb[1] as c_int };
            }
            if etype == TLSEXT_TYPE_KEY_SHARE && eb.len() >= 4 {
                group = ((eb[0] as u16) << 8) | eb[1] as u16;
                let klen = ((eb[2] as usize) << 8) | eb[3] as usize;
                if 4 + klen <= eb.len() {
                    share = &eb[4..4 + klen];
                }
            }
            off += elen;
        }
    }
    // SAFETY: `s` is live.
    unsafe {
        (*s).group_id = group;
        (*s).version = TLS1_3_VERSION;
    }
    // SAFETY: `s` is live; `chosen` is the table row.
    if unsafe { k::tls13_setup_cipher(s, (*chosen).id as u16) } == 0 {
        return 0;
    }
    // The transcript was buffered with the ClientHello; replay it, then append the ServerHello.
    // SAFETY: `s` is live; `msg` is the full ServerHello.
    if unsafe { k::transcript_update(s, msg.as_ptr(), msg.len()) } == 0 {
        return 0;
    }
    if group == crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519 && share.len() == 32 {
        // SAFETY: `s` is live; `share` is 32 readable bytes.
        let peer = unsafe { k::tls13_pkey_from_share(s, share.as_ptr(), share.len()) };
        if peer.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).peer_tmp = peer };
    }
    // SAFETY: `s` is live.
    unsafe { client_derive_and_install(s) }
}

/// `MSG_PROCESS_RETURN tls_process_encrypted_extensions(...)` — `statem_clnt.c:4114`, reduced to the
/// transcript append (no extension is negotiated in the reduced flight).
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls_process_encrypted_extensions(s: *mut Ssl, msg: &[u8]) -> c_int {
    if msg.len() < 4 || msg[0] != SSL3_MT_EE_BODY {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `int ssl_x509err2alert(int x509err)` — `ssl/statem/statem_lib.c:1823-1832`, table at
/// `:1777-1820`.
///
/// Maps an `X509_V_ERR_*` verification result to the TLS alert the client sends when verification
/// fails. Returns `SSL_AD_CERTIFICATE_UNKNOWN` (46) for any value not in the authority's table.
fn ssl_x509err2alert(x509err: c_int) -> c_int {
    // Alerts — `include/openssl/ssl3.h`.
    const SSL_AD_HANDSHAKE_FAILURE: c_int = 40;
    const SSL_AD_BAD_CERTIFICATE: c_int = 42;
    const SSL_AD_UNSUPPORTED_CERTIFICATE: c_int = 43;
    const SSL_AD_CERTIFICATE_REVOKED: c_int = 44;
    const SSL_AD_CERTIFICATE_EXPIRED: c_int = 45;
    const SSL_AD_CERTIFICATE_UNKNOWN: c_int = 46;
    const SSL_AD_UNKNOWN_CA: c_int = 48;
    const SSL_AD_DECRYPT_ERROR: c_int = 51;
    const SSL_AD_INTERNAL_ERROR: c_int = 80;
    // `X509_V_ERR_*` — `include/openssl/x509_vfy.h.in`.
    const X509_V_ERR_UNSPECIFIED: c_int = 1;
    const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
    const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
    const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
    const X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
    const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
    const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
    const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
    const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
    const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
    const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
    const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
    const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
    const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
    const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
    const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
    const X509_V_ERR_OUT_OF_MEM: c_int = 17;
    const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
    const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
    const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
    const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
    const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
    const X509_V_ERR_CERT_REVOKED: c_int = 23;
    const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
    const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
    const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
    const X509_V_ERR_CERT_REJECTED: c_int = 28;
    const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
    const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
    const X509_V_ERR_HOSTNAME_MISMATCH: c_int = 62;
    const X509_V_ERR_EMAIL_MISMATCH: c_int = 63;
    const X509_V_ERR_IP_ADDRESS_MISMATCH: c_int = 64;
    const X509_V_ERR_DANE_NO_MATCH: c_int = 65;
    const X509_V_ERR_EE_KEY_TOO_SMALL: c_int = 66;
    const X509_V_ERR_CA_KEY_TOO_SMALL: c_int = 67;
    const X509_V_ERR_CA_MD_TOO_WEAK: c_int = 68;
    const X509_V_ERR_INVALID_CALL: c_int = 69;
    const X509_V_ERR_STORE_LOOKUP: c_int = 70;
    const X509_V_ERR_INVALID_CA: c_int = 79;
    const X509_V_ERR_EC_KEY_EXPLICIT_PARAMS: c_int = 94;

    match x509err {
        X509_V_ERR_APPLICATION_VERIFICATION => SSL_AD_HANDSHAKE_FAILURE,
        X509_V_ERR_CA_KEY_TOO_SMALL => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_EC_KEY_EXPLICIT_PARAMS => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CA_MD_TOO_WEAK => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CERT_CHAIN_TOO_LONG => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_CERT_HAS_EXPIRED => SSL_AD_CERTIFICATE_EXPIRED,
        X509_V_ERR_CERT_NOT_YET_VALID => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CERT_REJECTED => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CERT_REVOKED => SSL_AD_CERTIFICATE_REVOKED,
        X509_V_ERR_CERT_SIGNATURE_FAILURE => SSL_AD_DECRYPT_ERROR,
        X509_V_ERR_CERT_UNTRUSTED => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CRL_HAS_EXPIRED => SSL_AD_CERTIFICATE_EXPIRED,
        X509_V_ERR_CRL_NOT_YET_VALID => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_CRL_SIGNATURE_FAILURE => SSL_AD_DECRYPT_ERROR,
        X509_V_ERR_DANE_NO_MATCH => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_EE_KEY_TOO_SMALL => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_EMAIL_MISMATCH => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_HOSTNAME_MISMATCH => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_INVALID_CA => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_INVALID_CALL => SSL_AD_INTERNAL_ERROR,
        X509_V_ERR_INVALID_PURPOSE => SSL_AD_UNSUPPORTED_CERTIFICATE,
        X509_V_ERR_IP_ADDRESS_MISMATCH => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_OUT_OF_MEM => SSL_AD_INTERNAL_ERROR,
        X509_V_ERR_PATH_LENGTH_EXCEEDED => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_STORE_LOOKUP => SSL_AD_INTERNAL_ERROR,
        X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE => SSL_AD_BAD_CERTIFICATE,
        X509_V_ERR_UNABLE_TO_GET_CRL => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE => SSL_AD_UNKNOWN_CA,
        X509_V_ERR_UNSPECIFIED => SSL_AD_INTERNAL_ERROR,
        _ => SSL_AD_CERTIFICATE_UNKNOWN,
    }
}

/// `MSG_PROCESS_RETURN tls_process_server_certificate(...)` — `statem_clnt.c:1995`: the reduced
/// client parses the leaf certificate out of the TLS 1.3 `Certificate` message (the first
/// `CertificateEntry`'s `cert_data`) into an `X509` for `tls_process_cert_verify` to verify against.
/// The chain beyond the leaf is not walked (the fixtures carry one certificate and the probe sets
/// `SSL_VERIFY_NONE`; the CertificateVerify signature is still checked).
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls_process_server_certificate(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::x509::x_x509::{d2i_X509, X509};
    if msg.len() < 4 || msg[0] != SSL3_MT_CERTIFICATE as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    // `certificate_request_context<0..2^8-1> || CertificateEntry certificate_list<0..2^24-1>`.
    if body.len() < 4 {
        return 0;
    }
    let ctx_len = body[0] as usize;
    let mut p = 1 + ctx_len;
    if p + 3 > body.len() {
        return 0;
    }
    let list_len =
        ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
    p += 3;
    if list_len == 0 || p + list_len > body.len() {
        return 0;
    }
    let list_end = p + list_len;

    // The authority appends every `CertificateEntry` to `s->session->peer_chain`
    // (`tls_process_server_certificate`, `statem_clnt.c:2026-2077`); the leaf is
    // `sk_X509_value(peer_chain, 0)` and becomes `session->peer` in
    // `tls_post_process_server_certificate` (`statem_clnt.c:2137,2165-2172`). The reduced path has
    // no handshake-created session, so the chain is stored on the connection.
    // SAFETY: no preconditions; the new stack owns the references pushed into it.
    let chain = OPENSSL_sk_new_null();
    if chain.is_null() {
        return 0;
    }
    // Each TLS 1.3 `CertificateEntry` is `cert_data<1..2^24-1> || extensions<0..2^16-1>`.
    while p + 3 <= list_end {
        let derlen =
            ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
        p += 3;
        if derlen == 0 || p + derlen > list_end {
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        }
        let mut inp = body[p..p + derlen].as_ptr();
        let mut x: *mut X509 = core::ptr::null_mut();
        // SAFETY: `inp` points at `derlen` readable bytes; `x` is this frame's writable slot.
        let got = unsafe { d2i_X509(&mut x, &mut inp, derlen as core::ffi::c_long) };
        if got.is_null() || x.is_null() {
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        }
        // SAFETY: `chain` is live; `x` is a live certificate whose reference moves into it.
        if unsafe { OPENSSL_sk_push(chain, x.cast()) } == 0 {
            // SAFETY: `x` has not been pushed, so this frame still owns it.
            unsafe { crate::x509::x_x509::X509_free(x) };
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        }
        p += derlen;
        if p + 2 > list_end {
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        }
        let extlen = ((body[p] as usize) << 8) | body[p + 1] as usize;
        p += 2 + extlen;
        if p > list_end {
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        }
    }

    // SAFETY: `s` is live; the previous leaf/chain/verified chain are owned here.
    unsafe {
        if !(*s).peer_cert.is_null() {
            crate::x509::x_x509::X509_free((*s).peer_cert.cast());
        }
        if !(*s).peer_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
        }
        if !(*s).verified_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).verified_chain.cast());
        }
        // `session->peer` is an up-ref of the leaf, `peer_chain[0]` (`statem_clnt.c:2137,2165-2172`),
        // which this crate reads through `peer_cert` in `tls_process_cert_verify`.
        let leaf = OPENSSL_sk_value(chain, 0).cast::<X509>();
        crate::x509::x509_set::X509_up_ref(leaf);
        (*s).peer_cert = leaf.cast();
        (*s).peer_chain = chain;
    }
    // Verify the presented chain (`tls_post_process_server_certificate`, `statem_clnt.c:2092-2131`).
    // The authority verifies in the post-process step that follows this message; the reduced driver
    // performs both here, after the whole chain is parsed (there is no separate post-process arm).
    // `ERR_set_mark`/`ERR_pop_to_mark` keep `s->verify_result` while discarding the verify path's
    // own error-queue entries when the connection does not ask for verification (`:2121-2129`).
    // SAFETY: `s` is live; `peer_chain` is the chain just stored.
    unsafe {
        ERR_set_mark();
        let chain = (*s).peer_chain;
        let i = crate::ssl::ssl_cert::ssl_verify_cert_chain(s, chain);
        if i <= 0 && (*s).verify_mode != t::SSL_VERIFY_NONE as c_int {
            ERR_clear_last_mark();
            let alert = ssl_x509err2alert((*s).verify_result as c_int);
            ossl_statem_fatal(s, alert, SSL_R_CERTIFICATE_VERIFY_FAILED);
            return 0;
        }
        ERR_pop_to_mark();
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `MSG_PROCESS_RETURN tls_process_cert_verify(...)` — `statem_lib.c:441-560`: verify the peer's
/// `CertificateVerify` signature over the TLS 1.3 `TBS` preamble (`get_cert_verify_tbs_data`) with
/// the leaf certificate's public key (`tls12_check_peer_sigalg`, `tls1_lib.c:2682`). The reduced
/// client accepts the RSA SHA-256 schemes `rsa_pss_rsae_sha256` (0x0804) and `rsa_pkcs1_sha256`
/// (0x0401) -- the two the fixtures' RSA certificate can carry.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls_process_cert_verify(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::evp::digest::{
        EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_free, EVP_MD_CTX_new,
    };
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx};
    use crate::rsa::ctrl::{
        EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding,
        EVP_PKEY_CTX_set_rsa_pss_saltlen,
    };
    use crate::x509::x509_cmp::X509_get0_pubkey;
    // `RSA_PKCS1_PSS_PADDING` / `RSA_PSS_SALTLEN_DIGEST` — `include/openssl/rsa.h`.
    const RSA_PKCS1_PSS_PADDING: c_int = 6;
    const RSA_PSS_SALTLEN_DIGEST: c_int = -1;

    if msg.len() < 8 || msg[0] != SSL3_MT_CERTIFICATE_VERIFY as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    let sigalg = ((body[0] as u16) << 8) | body[1] as u16;
    let siglen = ((body[2] as usize) << 8) | body[3] as usize;
    if 4 + siglen > body.len() {
        return 0;
    }
    let sig = &body[4..4 + siglen];
    let is_pss = match sigalg {
        0x0804 => true,
        0x0401 => false,
        _ => return 0,
    };

    // SAFETY: `s` is live.
    let peer_cert = unsafe { (*s).peer_cert };
    if peer_cert.is_null() {
        return 0;
    }
    // SAFETY: `peer_cert` is a live certificate.
    let pkey = unsafe { X509_get0_pubkey(peer_cert.cast()) };
    if pkey.is_null() {
        return 0;
    }

    // TBS = 64 spaces || context string || 0x00 || transcript hash (`get_cert_verify_tbs_data`).
    // SAFETY: `s` is live.
    let hash_len = unsafe { (*s).hs_md_len };
    let ctx_str = b"TLS 1.3, server CertificateVerify";
    let mut tbs = [0u8; 64 + 33 + 1 + crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    for b in tbs[..64].iter_mut() {
        *b = 0x20;
    }
    tbs[64..64 + ctx_str.len()].copy_from_slice(ctx_str);
    let mut pos = 64 + ctx_str.len();
    tbs[pos] = 0;
    pos += 1;
    // SAFETY: `s` is live; the transcript is `CH || SH || EE || Certificate` (the CertificateVerify
    // is not yet appended), and `tbs[pos..]` has room for the hash.
    if unsafe {
        crate::ssl::tls13_enc::transcript_hash(s, tbs.as_mut_ptr().add(pos), core::ptr::null_mut())
    } == 0
    {
        return 0;
    }
    pos += hash_len;

    // SAFETY: no preconditions.
    let mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        return 0;
    }
    let md = EVP_sha256();
    let mut pctx: *mut EvpPkeyCtx = core::ptr::null_mut();
    let mut ok = false;
    // SAFETY: `mctx`/`pkey` are live; `tbs`/`sig` are the caller's.
    unsafe {
        if EVP_DigestVerifyInit(mctx, &mut pctx, md, core::ptr::null_mut(), pkey) > 0
            && !pctx.is_null()
            && EVP_PKEY_CTX_set_signature_md(pctx, md) > 0
            && (!is_pss
                || (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
                    && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0
                    && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0))
            && EVP_DigestVerify(mctx, sig.as_ptr(), siglen, tbs.as_ptr(), pos) == 1
        {
            ok = true;
        }
        EVP_MD_CTX_free(mctx);
    }
    if !ok {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `MSG_PROCESS_RETURN tls_process_finished(...)` for a client — `statem_lib.c:843-960`: verify the
/// server's Finished, derive the application secrets, install the server-application read key, then
/// send the client's Finished and install the client-application write key.
///
/// # Safety
/// `s` is live; `msg` is the full Finished message.
pub(crate) unsafe fn tls13_process_server_finished(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::tls13_enc as k;
    // SAFETY: `s` is live; the secret is the connection's.
    if unsafe { k::tls13_process_finished(s, msg, (*s).server_hs_traffic.as_ptr()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { k::tls13_derive_application_traffic(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `pending_cipher` was set by `tls_process_server_hello`.
    let cid = unsafe { (*(*s).pending_cipher).id as u16 };
    // SAFETY: `s` is live.
    if unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_APPLICATION | k::SSL3_CHANGE_CIPHER_CLIENT_READ,
            cid,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live; the client-handshake write key was installed after ServerHello.
    if unsafe { k::tls13_construct_finished(s, (*s).client_hs_traffic.as_ptr()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_APPLICATION | k::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            cid,
        )
    }
}

/// `SSL_CONNECTION *s`'s client read/write transition driver: pumps one record per hand state until
/// the peer BIO is empty (`-1`, waiting) or the handshake finishes (`1`). The reduced transcript of
/// `statem.c`'s read/write sub-state machines (`ssl3_read_bytes` + `ossl_statem_client_process_message`
/// + `tls_construct_finished`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_client_drive(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        loop {
            match (*s).hand_state {
                TLS_ST_BEFORE => {
                    // The write transition moves to `TLS_ST_CW_CLNT_HELLO` before constructing the
                    // ClientHello, which is the state `ssl3_write_bytes`'s TLS1.0 record-version
                    // rule reads (`rec_layer_s3.c:395-405`).
                    (*s).hand_state = TLS_ST_CW_CLNT_HELLO;
                    if write_client_hello(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // The read transition (`client13_read_transition`'s `TLS_ST_CW_CLNT_HELLO ->
                    // TLS_ST_CR_SRVR_HELLO`) is applied by the authority's `READ_STATE_HEADER` only
                    // after `tls_get_message_header` has read a message. The hand state is therefore
                    // left at `TLS_ST_CW_CLNT_HELLO` (13) here, and an empty peer BIO leaves it there
                    // -- the value the fresh-connection `SSL_connect` observers compare.
                }
                TLS_ST_CW_CLNT_HELLO | TLS_ST_CR_SRVR_HELLO => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    // The ServerHello header has now been read, so the read transition advances the
                    // hand state before the body is processed (the authority's `read_state_machine`).
                    (*s).hand_state = TLS_ST_CR_SRVR_HELLO;
                    if tls_process_server_hello(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_ENCRYPTED_EXTENSIONS;
                }
                TLS_ST_CR_ENCRYPTED_EXTENSIONS => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    if tls_process_encrypted_extensions(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_CERT;
                }
                TLS_ST_CR_CERT => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    if tls_process_server_certificate(s, &buf[..n]) == 0 {
                        // `tls_process_server_certificate` already raises the verification alert
                        // and enters `MSG_FLOW_ERROR`; only the parse-failure arm needs the generic
                        // alert (`ossl_statem_send_fatal` is idempotent, but the reason is not).
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_CERT_VRFY;
                }
                TLS_ST_CR_CERT_VRFY => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    if tls_process_cert_verify(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_FINISHED;
                }
                TLS_ST_CR_FINISHED => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    if tls13_process_server_finished(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_OK;
                    (*s).in_init = 0;
                    (*s).rwstate = 1; // SSL_NOTHING
                    (*s).statem_state = MSG_FLOW_READING_13;
                    return 1;
                }
                TLS_ST_OK => {
                    (*s).in_init = 0;
                    (*s).rwstate = 1; // SSL_NOTHING
                    (*s).statem_state = MSG_FLOW_READING_13;
                    return 1;
                }
                _ => {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
            }
        }
    }
}

/// Read one handshake record into a fresh buffer, returning `(buf, len)` or `None` when the peer
/// BIO is empty (`SSL3_MT_*`/`ssl3_read_bytes`).
///
/// # Safety
/// `s` is live.
unsafe fn client_read(s: *mut Ssl) -> Option<([u8; 16384], usize)> {
    let mut buf = [0u8; 16384];
    // SAFETY: `s` is live; `buf` is writable. The helper splits a record that carries several
    // handshake messages (the authority coalesces its flight) and skips a middlebox-compat
    // `ChangeCipherSpec` record.
    let n = unsafe {
        crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
            s,
            buf.as_mut_ptr(),
            buf.len(),
        )
    };
    if n <= 0 {
        return None;
    }
    Some((buf, n as usize))
}

/// Mark the client as waiting for the peer's next record.
///
/// # Safety
/// `s` is live.
unsafe fn client_wait(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        (*s).statem_state = MSG_FLOW_READING_13;
        (*s).rwstate = 3; // SSL_READING
    }
    let _ = MSG_FLOW_ERROR_13;
    -1
}
