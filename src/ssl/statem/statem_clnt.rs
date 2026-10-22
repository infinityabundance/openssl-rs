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
use crate::runtime::foreign::OwnedCtx;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_lib::{SSL_get_ciphers, Ssl};
use crate::ssl::statem::extensions_clnt::tls_construct_extensions;
use crate::ssl::statem::statem::{ossl_statem_fatal, ossl_statem_in_error};
use crate::ssl::statem::statem_srvr::SliceCursor;
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
/// `SSL_AD_DECRYPT_ERROR` — `ssl3.h` (51).
const SSL_AD_DECRYPT_ERROR: c_int = 51;
/// `SSL_AD_ILLEGAL_PARAMETER` — `ssl3.h` (47).
const SSL_AD_ILLEGAL_PARAMETER: c_int = 47;
const ERR_R_INTERNAL_ERROR: c_int = 259 | (2 << 18) | (1 << 18);
const SSL_R_UNEXPECTED_MESSAGE: c_int = 244;
/// `SSL3_MT_CLIENT_KEY_EXCHANGE` — `ssl3.h` (16).
const SSL3_MT_CLIENT_KEY_EXCHANGE: c_int = 16;
/// `SSL_R_BAD_SIGNATURE` — `sslerr.h:148`.
const SSL_R_BAD_SIGNATURE: c_int = 148;
/// `SSL_R_BAD_KEY_SHARE` — `sslerr.h:43` (108). The previous 384 is
/// `SSL_R_INVALID_COMMAND`'s neighbour in the authority's table and was never this reason.
const SSL_R_BAD_KEY_SHARE: c_int = 108;
/// `SSL_R_SSL3_SESSION_ID_TOO_LONG` — `sslerr.h:300`.
const SSL_R_SSL3_SESSION_ID_TOO_LONG: c_int = 300;
/// `SSL_R_WRONG_CURVE` — `sslerr.h:378`.
const SSL_R_WRONG_CURVE: c_int = 378;
/// `SSL_R_WRONG_SIGNATURE_TYPE` — `sslerr.h:370`.
const SSL_R_WRONG_SIGNATURE_TYPE: c_int = 370;

// --- connection flags --------------------------------------------------------
const SSL3_VERSION: c_int = 0x0300;
const TLS1_3_VERSION: c_int = 0x0304;
const DTLS1_VERSION_MAJOR: c_int = 0xFE;
const SSL_PHA_REQUESTED: c_int = 4;
/// `SSL_PHA_EXT_SENT` — `ssl_local.h:372`.
const SSL_PHA_EXT_SENT: c_int = 1;
const SSL_KEY_UPDATE_NONE: c_int = -1;
const SSL_HRR_NONE: c_int = 0;
const SSL_HRR_PENDING: c_int = 1;
const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 1 << 20;
const SSL_SENT_SHUTDOWN: c_int = 1;
/// `SSL_RECEIVED_SHUTDOWN` — `ssl.h:217` (set by a received `close_notify`, `rec_layer_s3.c:913`).
const SSL_RECEIVED_SHUTDOWN: c_int = 2;
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

// ---------------------------------------------------------------------------------------------
// Ownership reclaimed from the hand-written releases in this file
// ---------------------------------------------------------------------------------------------

// The shared [`OwnedBuf`] owns a `CRYPTO_*` block this frame allocated (or a `get1` out-pointer
// it took back), so its single release is `Drop`'s `CRYPTO_free` at the authority's own
// `(file, line)` and no call site writes a `CRYPTO_free` by hand.

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
/// authority's `state_machine`. The session object is created by `tls12_process_server_hello` once
/// the version is known (a pre-loaded resumable session is kept); this function fills
/// `client_random`, the session id from the loaded session, and the middlebox-compatibility random
/// id for a TLS1.3-capable connection.
///
/// # Safety
/// `s` must be a live connection; `pkt` must be a live packet.
pub(crate) unsafe fn tls_construct_client_hello(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // `ssl_set_client_hello_version` (`statem_lib.c:2586-2623`): install the connection's maximum
    // supported version (which the session-id / middlebox logic reads), then the legacy version
    // (`TLS1.2` for a TLS1.3-capable connection).
    let mut ver_min: c_int = 0;
    let mut ver_max: c_int = 0;
    // SAFETY: `s` is live; the out-pointers are live locals.
    if unsafe {
        crate::ssl::statem::statem_lib::ssl_get_min_max_version(
            s,
            &mut ver_min,
            &mut ver_max,
            core::ptr::null_mut(),
        )
    } != 0
    {
        return 0;
    }
    let client_version = if ver_max > TLS1_2_VERSION {
        TLS1_2_VERSION
    } else {
        ver_max
    };
    // SAFETY: `s` is live.
    unsafe {
        (*s).version = ver_max;
        (*s).client_version = client_version;
    }

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

    // The fresh handshake session is created once the ServerHello fixes the version (TLS1.2),
    // in `tls12_process_server_hello`; a pre-loaded (resumed) session is kept. TLS1.3 keeps its
    // end-of-handshake `tls13_client_create_session` arm.
    //
    // Session ID (`statem_clnt.c:1270-1300`): an empty id on a fresh handshake, a random one for
    // TLS1.3 middlebox compatibility, or the session's own id when resuming.
    let mut sess_id = [0u8; SSL3_RANDOM_SIZE];
    // SAFETY: `s` is live; the condition is the authority's.
    let sess_id_len = unsafe {
        if (*s).new_session != 0 || (*s).version == TLS1_3_VERSION {
            if (*s).version == TLS1_3_VERSION
                && ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
            {
                if RAND_bytes(sess_id.as_mut_ptr(), SSL3_RANDOM_SIZE as c_int) <= 0 {
                    return 0;
                }
                SSL3_RANDOM_SIZE
            } else {
                0
            }
        } else if (*s).version != TLS1_3_VERSION && !(*s).session.is_null() {
            let sl = (*(*s).session).session_id_length.min(SSL3_RANDOM_SIZE);
            if sl > 0 {
                core::ptr::copy_nonoverlapping(
                    (*(*s).session).session_id.as_ptr(),
                    sess_id.as_mut_ptr(),
                    sl,
                );
            }
            sl
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
    // The packet buffer is heap-allocated through the crate's allocator seam: a 4 KiB frame on
    // every ClientHello, on top of the record and handshake read frames, is what pushed a 32 KiB
    // accept/connect thread over its guard page.
    let Some(buf_block) = OwnedBuf::new(4096, SeamFile::NULL, 0) else {
        return 0;
    };
    let buf = buf_block.as_ptr();
    // SAFETY: a zeroed `WPACKET` is a valid starting state for `WPACKET_init_static_len`.
    let mut pkt: Wpacket = unsafe { core::mem::zeroed() };
    let mut msglen: usize = 0;

    // SAFETY: `pkt`/`buf` are live locals; the buffer outlives the packet.
    unsafe {
        if crate::packet::WPACKET_init_static_len(&mut pkt, buf, 4096, 0) == 0 {
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
        let r =
            crate::ssl::record::rec_layer_s3::ssl3_write_bytes(s, SSL3_RT_HANDSHAKE, buf, msglen);
        // The transcript begins with the ClientHello; while the cipher is unknown this buffers
        // (`transcript_update`), to be replayed by `tls_process_server_hello`.
        if r > 0 {
            crate::ssl::tls13_enc::transcript_update(s, buf, msglen);
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
/// `TLSEXT_TYPE_session_ticket` — `tls1.h` (35).
const TLSEXT_TYPE_SESSION_TICKET: u16 = 35;
/// `TLSEXT_TYPE_status_request` — `tls1.h:88`.
const TLSEXT_TYPE_STATUS_REQUEST: u16 = 5;
/// `SSL_AD_UNSUPPORTED_EXTENSION` — `ssl.h:1236`.
const SSL_AD_UNSUPPORTED_EXTENSION: c_int = 110;
/// `SSL_AD_DECODE_ERROR` — `ssl3.h` (50).
const SSL_AD_DECODE_ERROR: c_int = 50;
/// `SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE` — `tls1.h:77` (113).
const SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE: c_int = 113;
/// `SSL_R_BAD_EXTENSION` — `sslerr.h`.
const SSL_R_BAD_EXTENSION: c_int = 110;
/// `TLSEXT_TYPE_key_share` — `tls1.h:165`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;
/// `TLSEXT_TYPE_pre_shared_key` — `tls1.h:163`.
const TLSEXT_TYPE_PRE_SHARED_KEY: u16 = 41;
/// `TLSEXT_TYPE_application_layer_protocol_negotiation` — `tls1.h:116`.
const TLSEXT_TYPE_ALPN: u16 = 16;
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
    let mut pms = crate::runtime::mem::CleansedScratch::<64>::new();
    let mut pmslen = 0usize;
    // SAFETY: `s` is live; the keys are the connection's ephemerals.
    if unsafe {
        k::tls13_derive_shared(
            s,
            (*s).pkey,
            (*s).peer_tmp,
            pms.as_mut_ptr(),
            64,
            &mut pmslen,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live; `pms[..pmslen]` is the shared secret.
    if unsafe { k::tls13_generate_handshake_secret(s, &pms.as_slice()[..pmslen]) } == 0 {
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

/// The fixed part of a ServerHello that both version parsers read identically:
/// `legacy_version(2) || random(32) || session_id(1+n) || cipher_suite(2) ||
/// compression_method(1)` and the unconsumed remainder (the extension block).
struct ServerHelloLayout<'a> {
    version: u16,
    random: &'a [u8],
    session_id: &'a [u8],
    cipher: &'a [u8],
    compression: u8,
    rest: &'a [u8],
}

/// Read the handshake header and the fixed ServerHello prefix.
///
/// `None` is exactly the set of inputs the previous offset arithmetic refused: a short header, a
/// handshake length that runs past `msg`, a body shorter than version+random+session-id+
/// cipher+compression, or a version/session-id/cipher field crossing the body's end. Trailing
/// bytes after the declared handshake length are ignored, as before.
fn read_server_hello_layout<'a>(msg: &'a [u8], expected_type: u8) -> Option<ServerHelloLayout<'a>> {
    let mut msg_cur = SliceCursor::new(msg);
    if msg_cur.take_u8()? != expected_type {
        return None;
    }
    let blen = ((msg_cur.take_u8()? as usize) << 16)
        | ((msg_cur.take_u8()? as usize) << 8)
        | msg_cur.take_u8()? as usize;
    let body = msg_cur.take(blen)?;
    let mut cur = SliceCursor::new(body);
    let version = cur.take_u16()?;
    let random = cur.take(SSL3_RANDOM_SIZE)?;
    let sid_len = cur.take_u8()? as usize;
    let session_id = cur.take(sid_len)?;
    let cipher = cur.take(2)?;
    let compression = cur.take_u8()?;
    Some(ServerHelloLayout {
        version,
        random,
        session_id,
        cipher,
        compression,
        rest: &body[cur.pos()..],
    })
}

/// `Extension extensions<0..2^16-1>` at the end of a ServerHello body.
enum ServerHelloExtensionBlock<'a> {
    /// Fewer than two bytes remain: the previous `p + 2 <= b.len()` guard read this as "no
    /// extension block" and accepted the message.
    Absent,
    Present(&'a [u8]),
}

/// Read the extension vector. `None` is a declared extent that runs past `rest`.
fn read_extension_block(rest: &[u8]) -> Option<ServerHelloExtensionBlock<'_>> {
    if rest.len() < 2 {
        return Some(ServerHelloExtensionBlock::Absent);
    }
    let mut cur = SliceCursor::new(rest);
    let len = cur.take_u16()? as usize;
    let exts = cur.take(len)?;
    Some(ServerHelloExtensionBlock::Present(exts))
}

/// Walk an `Extension extensions<2>` vector in order.
///
/// `None` means one extension's declared body crosses the block's end; the caller turns that into
/// the authority's error. A trailing 1..=3 bytes are ignored, matching the previous
/// `off + 4 <= exts.len()` loop.
fn walk_server_hello_extensions<'a, F>(exts: &'a [u8], mut visit: F) -> Option<()>
where
    F: FnMut(u16, &'a [u8]),
{
    let mut walk = SliceCursor::new(exts);
    while walk.remaining() >= 4 {
        let etype = walk.take_u16()?;
        let elen = walk.take_u16()? as usize;
        let eb = walk.take(elen)?;
        visit(etype, eb);
    }
    Some(())
}

/// `supported_versions` in a ServerHello: the selected `ProtocolVersion` (`extensions_clnt.c`).
///
/// A body shorter than two bytes is ignored (the previous `eb.len() >= 2` guard).
fn read_supported_versions(eb: &[u8]) -> Option<u16> {
    let mut cur = SliceCursor::new(eb);
    cur.take_u16()
}

/// `key_share` in a ServerHello: `group(2) || key_exchange<2..2^16-1>`.
///
/// `None` is a body shorter than four bytes or a key extent crossing the body; the previous
/// reader ignored both and kept the previously seen share.
fn read_key_share(eb: &[u8]) -> Option<(u16, &[u8])> {
    let mut cur = SliceCursor::new(eb);
    let group = cur.take_u16()?;
    let klen = cur.take_u16()? as usize;
    Some((group, cur.take(klen)?))
}

/// `pre_shared_key` in a ServerHello: `selected_identity(2)` (`tls_parse_stoc_psk`).
fn read_pre_shared_key(eb: &[u8]) -> Option<u16> {
    let mut cur = SliceCursor::new(eb);
    cur.take_u16()
}

/// The `key_share` selection a ServerHello carries (zero/empty when absent or unusable).
struct ServerHelloKeyShare<'a> {
    group: u16,
    share: &'a [u8],
}

/// Read the TLS1.3 ServerHello extensions the reduced client consumes.
///
/// `supported_versions` and `pre_shared_key` are read for shape but their values are not applied:
/// the reduced client marks TLS1.3 by the extension's presence (`process_server_hello_dispatch`),
/// always installs `TLS1_3_VERSION`, and offers no PSK (`extensions_clnt.rs`, recorded boundary).
/// A duplicate extension keeps the last value, as the previous in-order walk did.
fn read_tls13_server_hello_extensions(exts: &[u8]) -> Option<ServerHelloKeyShare<'_>> {
    let mut chosen = ServerHelloKeyShare {
        group: 0,
        share: &[],
    };
    walk_server_hello_extensions(exts, |etype, eb| match etype {
        TLSEXT_TYPE_SUPPORTED_VERSIONS => {
            let _selected = read_supported_versions(eb);
        }
        TLSEXT_TYPE_KEY_SHARE => {
            if let Some((group, share)) = read_key_share(eb) {
                chosen.group = group;
                chosen.share = share;
            }
        }
        TLSEXT_TYPE_PRE_SHARED_KEY => {
            let _selected_identity = read_pre_shared_key(eb);
        }
        _ => {}
    })?;
    Some(chosen)
}

/// The dispatch decision used by [`process_server_hello_dispatch`].
///
/// `Ok(true)` means a `supported_versions` extension (type 43) is present. `Ok(false)` means it is
/// absent; a declared extension vector that runs past the body is also treated as absent here,
/// because the previous dispatcher fell through to the legacy arm on that input. `Err(())` is a
/// framing or in-block extension overrun, which the previous dispatcher refused.
fn server_hello_selects_tls13(msg: &[u8]) -> Result<bool, ()> {
    let sh = read_server_hello_layout(msg, SSL3_MT_SERVER_HELLO as u8).ok_or(())?;
    let mut has_supported_versions = false;
    match read_extension_block(sh.rest) {
        Some(ServerHelloExtensionBlock::Present(exts)) => {
            walk_server_hello_extensions(exts, |etype, _| {
                if etype == TLSEXT_TYPE_SUPPORTED_VERSIONS {
                    has_supported_versions = true;
                }
            })
            .ok_or(())?;
        }
        Some(ServerHelloExtensionBlock::Absent) | None => {}
    }
    Ok(has_supported_versions)
}

/// `MSG_PROCESS_RETURN tls_process_server_hello(SSL_CONNECTION *s, PACKET *pkt)` —
/// `statem_clnt.c:1467-1836`, reduced to the fresh-connection, non-HRR, non-PSK path.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message (`type || length || body`).
pub(crate) unsafe fn tls_process_server_hello(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::tls13_enc as k;
    let Some(sh) = read_server_hello_layout(msg, SSL3_MT_SERVER_HELLO as u8) else {
        return 0;
    };
    if sh.version != TLS1_2_VERSION as u16 {
        return 0;
    }
    // server random is not used by the TLS1.3 schedule, but the authority stores it.
    // SAFETY: `s` is live; the layout fixed `random` at exactly `SSL3_RANDOM_SIZE` bytes.
    unsafe { (*s).server_random.copy_from_slice(sh.random) };
    // The authority bounds the echoed id before using it (`statem_clnt.c:1519-1524`);
    // `tmp_session_id` is `SSL_MAX_SSL_SESSION_ID_LENGTH` bytes.
    if sh.session_id.len() > crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_SSL3_SESSION_ID_TOO_LONG) };
        return 0;
    }
    // The TLS1.3 ServerHello echoes the ClientHello session id (`statem_clnt.c:1568`).
    // SAFETY: `s` is live; `tmp_session_id` is a 32-byte array.
    let (tmp_len, tmp_id) = unsafe { ((*s).tmp_session_id_len, (*s).tmp_session_id) };
    if sh.session_id.len() != tmp_len || sh.session_id != &tmp_id[..sh.session_id.len()] {
        return 0;
    }
    if sh.compression != 0 {
        return 0;
    }
    // SAFETY: `sh.cipher` is exactly two readable bytes by construction.
    let chosen = unsafe { crate::ssl::ssl_ciph::ssl3_get_cipher_by_char(sh.cipher.as_ptr()) };
    if chosen.is_null() {
        return 0;
    }
    // SAFETY: `s` is live; `chosen` is a table row.
    unsafe { (*s).pending_cipher = chosen };

    // supported_versions (43) confirms TLS1.3; key_share (51) carries the server share.
    let ServerHelloKeyShare { group, share } = match read_extension_block(sh.rest) {
        Some(ServerHelloExtensionBlock::Present(exts)) => {
            let Some(chosen_share) = read_tls13_server_hello_extensions(exts) else {
                return 0;
            };
            chosen_share
        }
        Some(ServerHelloExtensionBlock::Absent) => ServerHelloKeyShare {
            group: 0,
            share: &[],
        },
        None => return 0,
    };
    // SAFETY: `s` is live.
    unsafe {
        (*s).group_id = group;
        (*s).version = TLS1_3_VERSION;
        // `tls_setup_handshake` installs the negotiated-version method (`statem_lib.c:2292`),
        // which `SSL_CONNECTION_IS_TLS13` reads.
        (*s).method = crate::ssl::methods::tls13_method(false);
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

/// Read one three-byte big-endian length (`u24`) through the bounds-checked cursor.
fn take_u24(cur: &mut SliceCursor<'_>) -> Option<usize> {
    let hi = cur.take_u8()? as usize;
    let mid = cur.take_u8()? as usize;
    let lo = cur.take_u8()? as usize;
    Some((hi << 16) | (mid << 8) | lo)
}

/// `tls_parse_stoc_alpn` (`extensions_clnt.c:1665`): the body is
/// `protocol_name_list<2..2^16-1> = list_len(2) || proto_len(1) || proto`.
///
/// The authority rejects an empty list, a declared list extent past the extension, and a list
/// whose one entry does not span the list. `None` is that rejection; the caller answers the
/// authority's `SSL_AD_DECODE_ERROR` path.
fn read_alpn_selected(eb: &[u8]) -> Option<&[u8]> {
    let mut cur = SliceCursor::new(eb);
    let list_len = cur.take_u16()? as usize;
    let plen = cur.take_u8()? as usize;
    let list_end = list_len.checked_add(2)?;
    if list_len == 0 || list_end > eb.len() || list_end != plen.checked_add(3)? {
        return None;
    }
    cur.take(plen)
}

/// `MSG_PROCESS_RETURN tls_process_encrypted_extensions(...)` — `statem_clnt.c:4114-4140`: parse the
/// `Extension extensions<0..2^16-1>` block (the negotiated ALPN, `tls_parse_stoc_alpn`,
/// `extensions_clnt.c:1665`) and append the message to the transcript.
///
/// The reduced client ignores the remaining `EncryptedExtensions` extensions
/// (`supported_groups`, `early_data`, `max_fragment_length` and the rest), exactly as before:
/// only ALPN has a reader on this path.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls_process_encrypted_extensions(s: *mut Ssl, msg: &[u8]) -> c_int {
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_EE_BODY) {
        return 0;
    }
    // The reduced reader never consulted `msg[1..4]`; keep ignoring the declared handshake length
    // and parse every byte after it as the body.
    if frame.take(3).is_none() {
        return 0;
    }
    let rest = frame.remaining();
    let Some(body) = frame.take(rest) else {
        return 0;
    };
    let mut body_cur = SliceCursor::new(body);
    let exts = match body_cur.take_u16() {
        Some(ext_len) => {
            let Some(exts) = body_cur.take(ext_len as usize) else {
                return 0;
            };
            exts
        }
        // A body too short for the block length carries no extensions; that was accepted before.
        None => &[],
    };
    let mut walk = SliceCursor::new(exts);
    while walk.remaining() >= 4 {
        let Some(etype) = walk.take_u16() else {
            return 0;
        };
        let Some(elen) = walk.take_u16() else {
            return 0;
        };
        let Some(eb) = walk.take(elen as usize) else {
            return 0;
        };
        if etype == TLSEXT_TYPE_ALPN {
            let Some(proto) = read_alpn_selected(eb) else {
                return 0;
            };
            // SAFETY: `s` is live; `proto` borrows the message and holds `proto.len()` bytes.
            unsafe {
                use crate::runtime::mem::CRYPTO_memdup;
                let mut slot = (*s).s3_alpn_selected_slot();
                slot.clear(core::ptr::null(), 0);
                let dup = CRYPTO_memdup(proto.as_ptr().cast(), proto.len(), core::ptr::null(), 0)
                    .cast::<u8>();
                if dup.is_null() {
                    return 0;
                }
                slot.store(dup, proto.len());
            }
        }
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `MSG_PROCESS_RETURN tls_process_certificate_request(...)` — `statem_clnt.c:2601-2720`, reduced to
/// the TLS1.3 arm: read the `certificate_request_context<0..2^8-1>` and the
/// `Extension extensions<2>` block and record that a client certificate is wanted
/// (`s->s3.tmp.cert_req = 1`, `statem_clnt.c:2710`). The requested schemes are saved exactly as
/// the server saves the ClientHello's list (`tls1_save_sigalgs`, `statem_clnt.c:2686`), because the
/// certificate constructors check that the scheme they choose was offered; a request that omits
/// the extension falls back to this client's own advertised list (`tls_choose_sigalg`,
/// `t1_lib.c:4685-4713`). The request context is kept for the client Certificate/CertificateVerify
/// echo.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls_process_certificate_request(s: *mut Ssl, msg: &[u8]) -> c_int {
    // `SSL_AD_DECODE_ERROR` — `ssl3.h` (50); `SSL_R_LENGTH_MISMATCH` — `sslerr.h:163`.
    const SSL_AD_DECODE_ERROR: c_int = 50;
    const SSL_R_LENGTH_MISMATCH: c_int = 159;
    // `SSL_R_BAD_LENGTH` — `sslerr.h` (271); `tls1_process_sigalgs`' failure alert.
    const SSL_R_BAD_LENGTH: c_int = 271;
    // `SSL_R_BAD_EXTENSION` — `sslerr.h` (110); what `tls_parse_ctos_sig_algs` raises.
    const SSL_R_BAD_EXTENSION: c_int = 110;
    /// `TLSEXT_TYPE_signature_algorithms` — `tls1.h:145`.
    const TLSEXT_TYPE_SIG_ALGS: u16 = 13;
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_CERTIFICATE_REQUEST as u8) {
        return 0;
    }
    let Some(blen) = take_u24(&mut frame) else {
        return 0;
    };
    let Some(body) = frame.take(blen) else {
        return 0;
    };
    let mut cur = SliceCursor::new(body);
    // `CertificateRequest { certificate_request_context<0..2^8-1>; Extension extensions<2>; }`.
    let Some(ctx_len) = cur.take_u8() else {
        return 0;
    };
    let ctx_len = ctx_len as usize;
    let ctx = match cur.take(ctx_len) {
        Some(ctx) => ctx,
        None => {
            // SAFETY: `s` is live.
            unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
            return 0;
        }
    };
    let Some(ext_len) = cur.take_u16() else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    };
    let ext_len = ext_len as usize;
    if cur.remaining() != ext_len {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    }
    let Some(_extensions) = cur.take(ext_len) else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    };
    // `tls_parse_all_extensions(..., SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)`: the one extension this
    // client acts on is `signature_algorithms`. Its body is saved for the certificate
    // constructors' scheme check; a malformed vector is refused before the incumbent list is
    // touched (`tls1_save_u16` parses first), and a request that omits the extension leaves the
    // client on its own advertised default list.
    let extensions = _extensions;
    let mut sigalgs_seen = false;
    let mut walk = SliceCursor::new(extensions);
    while walk.remaining() >= 4 {
        let (Some(ty), Some(len)) = (walk.take_u16(), walk.take_u16()) else {
            break;
        };
        let Some(eb) = walk.take(len as usize) else {
            // The extension body runs past the block: the authority's reader refuses it.
            // SAFETY: `s` is live.
            unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH) };
            return 0;
        };
        if ty == TLSEXT_TYPE_SIG_ALGS {
            if eb.len() >= 2 && eb[0] == 0 && eb[1] == 0 {
                // An empty vector is legal for a CertificateRequest (`PACKET_memdup` answers
                // NULL for zero bytes), and the result is the same as an absent extension:
                // the client stays on its defaults.
            } else {
                // SAFETY: `s` is live; `eb` is the extension body.
                if unsafe { crate::ssl::t1_lib::tls1_save_peer_sigalgs(s, eb) } == 0 {
                    // SAFETY: `s` is live.
                    unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                    return 0;
                }
                sigalgs_seen = true;
            }
        }
    }
    if walk.remaining() != 0 {
        // 1-3 trailing bytes cannot frame another extension.
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH) };
        return 0;
    }
    if !sigalgs_seen {
        // No `signature_algorithms`: the authority uses its defaults — for the client, the list
        // it advertised (`tls1_get_legacy_sigalg` + `tls12_get_psigalgs(s, 1, ...)`,
        // `t1_lib.c:4685-4713`; the NULL-`peer_sigalgs` arm of `tls1_set_shared_sigalgs`).
        // SAFETY: `s` is live; the list is a `'static` array.
        if unsafe {
            crate::ssl::t1_lib::tls1_save_peer_sigalgs_default(
                s,
                &crate::ssl::statem::extensions_clnt::CLIENT_SIGALGS,
            )
        } == 0
        {
            // SAFETY: `s` is live.
            unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_LENGTH) };
            return 0;
        }
    }
    // The request context is copied into `pha_context` (`tls_process_certificate_request`,
    // `statem_clnt.c:2637`); the reduced client stores it in `tmp_session_id`-like storage is not
    // available, so the empty (in-handshake) context is the only one the reduced driver reaches.
    if ctx_len != 0 {
        // Post-handshake auth context: recorded and handled by the PHA driver.
        // SAFETY: `s` is live; its `pha_context` member obeys the member-buffer invariant.
        unsafe {
            let mut slot = (*s).pha_context_slot();
            slot.clear(core::ptr::null(), 0);
            let dup = crate::runtime::mem::CRYPTO_memdup(
                ctx.as_ptr().cast(),
                ctx_len,
                core::ptr::null(),
                0,
            )
            .cast::<u8>();
            if dup.is_null() {
                return 0;
            }
            slot.store(dup, ctx_len);
        }
    }
    // SAFETY: `s` is live.
    unsafe { (*s).s3_tmp_cert_req = 1 };
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}
/// `:1777-1820`.
///
/// Maps an `X509_V_ERR_*` verification result to the TLS alert the client sends when verification
/// fails. Returns `SSL_AD_CERTIFICATE_UNKNOWN` (46) for any value not in the authority's table.
pub(crate) fn ssl_x509err2alert(x509err: c_int) -> c_int {
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

/// One TLS1.3 `CertificateEntry` — `cert_data<1..2^24-1> || extensions<0..2^16-1>` — framed
/// through the bounds-checked cursor. The returned slices borrow the certificate list; DER decoding
/// of `cert_data` remains with the caller's existing `d2i_X509` boundary.
///
/// `None` is the authority's rejection: a zero-length `cert_data`, or a declared extent past the
/// end of the list. The caller frees the chain built so far.
fn read_tls13_certificate_entry<'a>(cur: &mut SliceCursor<'a>) -> Option<(&'a [u8], &'a [u8])> {
    let der_len = take_u24(cur)?;
    let der = cur.take(der_len)?;
    if der_len == 0 {
        return None;
    }
    let ext_len = cur.take_u16()? as usize;
    let extensions = cur.take(ext_len)?;
    Some((der, extensions))
}

/// `MSG_PROCESS_RETURN tls_process_server_certificate(...)` — `statem_clnt.c:1995`, generalized to
/// also serve the server's `tls_process_client_certificate` (`statem_srvr.c:3805-4002`). The reduced
/// path parses each TLS 1.3 `CertificateEntry`'s `cert_data` into an `X509`; the leaf becomes
/// `peer_cert`/`peer_chain[0]`. For the server an empty `certificate_list` is legal unless
/// `SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT` is set, in which case it is
/// `SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE` (`statem_srvr.c:3906-3918`).
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls13_process_peer_certificate(
    s: *mut Ssl,
    msg: &[u8],
    is_server: bool,
) -> c_int {
    use crate::x509::x_x509::{d2i_X509, X509};
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_CERTIFICATE as u8) {
        return 0;
    }
    let Some(blen) = take_u24(&mut frame) else {
        return 0;
    };
    let Some(body) = frame.take(blen) else {
        return 0;
    };
    // `certificate_request_context<0..2^8-1> || certificate_list<0..2^24-1>`.
    let mut cur = SliceCursor::new(body);
    let Some(ctx_len) = cur.take_u8() else {
        return 0;
    };
    let Some(_ctx) = cur.take(ctx_len as usize) else {
        return 0;
    };
    let Some(list_len) = take_u24(&mut cur) else {
        return 0;
    };
    let Some(cert_list) = cur.take(list_len) else {
        return 0;
    };
    if list_len == 0 {
        if !is_server {
            // A server always sends a certificate; an empty list is a protocol violation here.
            return 0;
        }
        // `SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE` only when the server requires one
        // (`statem_srvr.c:3913-3918`). `SSL_AD_CERTIFICATE_REQUIRED` = 116.
        const SSL_AD_CERTIFICATE_REQUIRED: c_int = 116;
        const SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE: c_int = 205;
        // SAFETY: `s` is live.
        unsafe {
            if ((*s).verify_mode & (t::SSL_VERIFY_PEER as c_int)) != 0
                && ((*s).verify_mode & (t::SSL_VERIFY_FAIL_IF_NO_PEER_CERT as c_int)) != 0
            {
                ossl_statem_fatal(
                    s,
                    SSL_AD_CERTIFICATE_REQUIRED,
                    SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE,
                );
                return 0;
            }
        }
        // SAFETY: `s` is live; the previous peer leaf/chain are owned here and are cleared so
        // `SSL_get_peer_certificate` answers NULL for a client that sent no certificate.
        unsafe {
            if !(*s).peer_cert.is_null() {
                crate::x509::x_x509::X509_free((*s).peer_cert.cast());
                (*s).peer_cert = core::ptr::null_mut();
            }
            if !(*s).peer_chain.is_null() {
                crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
                (*s).peer_chain = core::ptr::null_mut();
            }
        }
        // SAFETY: `s` is live; `msg` is the full message.
        return unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) };
    }
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
    let mut list = SliceCursor::new(cert_list);
    while list.remaining() >= 3 {
        let Some((der, _extensions)) = read_tls13_certificate_entry(&mut list) else {
            // SAFETY: `chain` is a live stack of the certs pushed so far.
            unsafe { crate::x509::t_x509::OSSL_STACK_OF_X509_free(chain) };
            return 0;
        };
        let mut inp = der.as_ptr();
        let mut x: *mut X509 = core::ptr::null_mut();
        // SAFETY: `inp` points at `der.len()` readable bytes; `x` is this frame's writable slot.
        let got = unsafe { d2i_X509(&mut x, &mut inp, der.len() as core::ffi::c_long) };
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
    }

    // SAFETY: `s` is live; the previous leaf/chain/verified chain are owned here.
    unsafe {
        if !(*s).peer_cert.is_null() {
            crate::x509::x_x509::X509_free((*s).peer_cert.cast());
            (*s).peer_cert = core::ptr::null_mut();
        }
        if !(*s).peer_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
            (*s).peer_chain = core::ptr::null_mut();
        }
        if !(*s).verified_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).verified_chain.cast());
            // `ssl_verify_cert_chain` frees and replaces `verified_chain` unconditionally; leaving
            // the freed pointer here would double-free on a second certificate exchange (the
            // post-handshake-authentication round trip).
            (*s).verified_chain = core::ptr::null_mut();
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
        if i <= 0 && (is_server || (*s).verify_mode != t::SSL_VERIFY_NONE as c_int) {
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
pub(crate) unsafe fn tls_process_cert_verify(s: *mut Ssl, msg: &[u8], is_server: bool) -> c_int {
    use crate::evp::digest::{EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_new};
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
    // `tls1_lookup_sigalg` (`t1_lib.c:2367-2432`): the scheme names its key type and digest. An
    // ECDSA scheme carries the curve it may be used with and takes no RSA padding.
    let (is_pss, md) = match sigalg {
        0x0804 => (true, crate::evp::legacy_sha::EVP_sha256()),
        0x0401 => (false, crate::evp::legacy_sha::EVP_sha256()),
        0x0403 => (false, crate::evp::legacy_sha::EVP_sha256()),
        0x0503 => (false, crate::evp::legacy_sha::EVP_sha384()),
        0x0603 => (false, crate::evp::legacy_sha::EVP_sha512()),
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
    // `tls12_check_peer_sigalg` (`t1_lib.c:2690-2770`): the scheme must be consistent with the
    // peer's key. An EC key signs only under the scheme whose curve column names its own curve
    // (`SSL_R_WRONG_CURVE`); an RSA key only under a PSS scheme or PKCS1-SHA256. Without this a
    // P-384 key's signature could be labelled with the P-256 scheme (or an ECDSA signature with
    // an RSA label) and still verify, because the TBS does not bind the scheme id.
    // SAFETY: `pkey` is live.
    let base_id = unsafe { crate::evp::pkey::EVP_PKEY_get_base_id(pkey) };
    if base_id == crate::evp::pkey_ctx::EVP_PKEY_EC {
        // SAFETY: `pkey` is live; a non-EC key answers `NID_undef`.
        let curve = unsafe { crate::ssl::statem::statem_srvr::ssl_get_ec_curve_nid(pkey) };
        let expected = crate::ssl::statem::statem_srvr::ec_sigalg_for_curve(curve);
        if expected.map(|(scheme, _)| scheme) != Some(sigalg) {
            // SAFETY: `s` is live.
            unsafe { ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_WRONG_CURVE) };
            return 0;
        }
    } else if sigalg != 0x0804 && sigalg != 0x0401 {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_WRONG_SIGNATURE_TYPE) };
        return 0;
    }

    // TBS = 64 spaces || context string || 0x00 || transcript hash (`get_cert_verify_tbs_data`).
    // SAFETY: `s` is live.
    let hash_len = unsafe { (*s).hs_md_len };
    let ctx_str: &[u8] = if is_server {
        b"TLS 1.3, client CertificateVerify"
    } else {
        b"TLS 1.3, server CertificateVerify"
    };
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

    // SAFETY: `EVP_MD_CTX_new` is the matching constructor: it answered the whole, aligned `EVP_MD_CTX`
    // block (or NULL, which yields `None`), live and owned solely by this handle, whose `Drop` runs
    // `EVP_MD_CTX_free` -- its single release.
    let Some(mctx_owner) =
        (unsafe { OwnedCtx::<crate::evp::digest::EvpMdCtx>::new(EVP_MD_CTX_new()) })
    else {
        return 0;
    };
    // The owned `EVP_MD_CTX`'s stable address, for the raw calls below; its single release is the
    // handle's `Drop` at the end of the frame.
    let mctx = mctx_owner.as_ptr();
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
    // TLS1.3 client authentication (`ossl_statem_client13_write_transition`'s `CW_CERT` ->
    // `CW_CERT_VRFY`, `statem_clnt.c:504-527`): when the server sent a CertificateRequest the
    // client answers with its Certificate and CertificateVerify before its Finished, both under the
    // still-active client handshake write key.
    // SAFETY: `s` is live.
    if unsafe { (*s).s3_tmp_cert_req } != 0 {
        // The request context is echoed in the Certificate; in-handshake it is empty, under PHA it
        // is the server's `pha_context` (`statem_clnt.c:3857-3868`).
        // SAFETY: `s` is live; its `pha_context` member obeys the member-buffer invariant.
        let (ctx, ctx_len) = unsafe { (*s).pha_context() };
        // SAFETY: `ctx` names `ctx_len` readable bytes when non-NULL, else the slice is empty.
        let context: &[u8] = if ctx.is_null() {
            &[]
        } else {
            // SAFETY: `pha_context` is `pha_context_len` bytes owned by the connection.
            unsafe { core::slice::from_raw_parts(ctx, ctx_len) }
        };
        // SAFETY: `s` is live.
        if unsafe { crate::ssl::statem::statem_srvr::tls13_construct_certificate(s, context) } == 0
        {
            return 0;
        }
        // `s->s3.tmp.cert_req == 2` when no certificate is available (`statem_clnt.c:3822-3834`),
        // in which case no CertificateVerify follows (`statem_clnt.c:509-514`).
        // SAFETY: `s` is live.
        if unsafe { crate::ssl::statem::statem_srvr::cert_active_present(s) } {
            // SAFETY: `s` is live.
            if unsafe { crate::ssl::statem::statem_srvr::tls13_construct_cert_verify(s, false) }
                == 0
            {
                return 0;
            }
        }
    }
    // SAFETY: `s` is live; the client-handshake write key is active and the transcript is current.
    if unsafe { k::tls13_construct_finished(s, (*s).client_hs_traffic.as_ptr()) } == 0 {
        return 0;
    }
    // `tls13_save_handshake_digest_for_pha` at `CW_FINISHED` (`statem_clnt.c:902-906`): after the
    // client Finished the transcript is snapshotted for a later PHA exchange.
    // SAFETY: `s` is live.
    if unsafe { k::tls13_save_handshake_digest_for_pha(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    let r = unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_APPLICATION | k::SSL3_CHANGE_CIPHER_CLIENT_WRITE,
            cid,
        )
    };
    if r == 0 {
        return 0;
    }
    // The `"res master"` arm of `tls13_change_cipher_state` (`tls13_enc.c:675-685`): the client
    // derives it from the transcript through its own Finished. A post-handshake NewSessionTicket
    // expands the ticket nonce under this secret (`statem_clnt.c:2884-2898`).
    // SAFETY: `s` is live.
    if unsafe { k::tls13_derive_resumption_master_secret(s) } == 0 {
        return 0;
    }
    // `ssl_get_new_session` (`ssl_sess.c:181-266`): the authority attaches a session at handshake
    // time; the reduced client creates the connection's session once the handshake completes so
    // `SSL_get1_session` answers non-NULL (CPython's `SSLSocket.session`).
    // SAFETY: `s` is live.
    unsafe { tls13_client_create_session(s) }
}

/// The reduced `ssl_get_new_session` (`ssl_sess.c:181-266`) for a finished TLS1.3 client: allocate a
/// session with a random id and the negotiated version/cipher. The authority builds the handshake
/// session at ClientHello time and fills it from the ServerHello; no session cache or resumption is
/// modelled here, only the observable `SSL_get1_session != NULL` after a handshake.
///
/// # Safety
/// `s` is live.
unsafe fn tls13_client_create_session(s: *mut Ssl) -> c_int {
    use crate::ssl::ssl_sess::{ssl_session_calculate_timeout, SSL_SESSION_new};
    // SAFETY: `s` is live.
    unsafe {
        if !(*s).session.is_null() {
            return 1;
        }
        // The fresh session is owned here: its single release is the handle's `Drop` running
        // `SSL_SESSION_free`, so the RNG refusal releases it and success hands it to the field with
        // `into_raw`, whose own release is then the only one.
        // SAFETY: `SSL_SESSION_new` is the matching constructor: it answered the whole, aligned
        // session block (or NULL, which yields `None`), live and owned solely by this handle, whose
        // `Drop` runs `SSL_SESSION_free` -- its single release.
        let Some(ss_owner) = OwnedCtx::<crate::ssl::ssl_lib::SslSession>::new(SSL_SESSION_new())
        else {
            return 0;
        };
        let ss = ss_owner.as_ptr();
        let mut id = [0u8; crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH];
        if crate::rand::rand_lib::RAND_bytes(id.as_mut_ptr(), id.len() as c_int) <= 0 {
            // The refusal releases the session it built: returning drops `ss_owner`.
            return 0;
        }
        (*ss).session_id_length = id.len();
        (&mut (*ss).session_id)[..id.len()].copy_from_slice(&id);
        (*ss).ssl_version = (*s).version;
        (*ss).cipher = (*s).pending_cipher;
        (*ss).cipher_id = if (*s).pending_cipher.is_null() {
            0
        } else {
            (*(*s).pending_cipher).id as core::ffi::c_ulong
        };
        ssl_session_calculate_timeout(ss);
        // Success hands the session to the field; the borrow ends and the field's release is the
        // session's only one.
        (*s).session = ss_owner.into_raw();
    }
    1
}

/// The client's TLS1.3 post-handshake-authentication response: process the server's post-handshake
/// `CertificateRequest` (read transition `TLS_ST_OK` -> `TLS_ST_CR_CERT_REQ`,
/// `statem_clnt.c:193-213`), restore the saved transcript, then write the client
/// `Certificate`/`CertificateVerify`/`Finished` flight (`statem_clnt.c:455-517`).
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls13_client_process_post_handshake(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::tls13_enc as k;
    if msg.is_empty() {
        return 0;
    }
    // Any other post-handshake message (a TLS1.3 `NewSessionTicket`, for example) is not part of
    // PHA and is dropped by the reduced reader.
    if msg[0] != SSL3_MT_CERTIFICATE_REQUEST as u8 {
        return 1;
    }
    // Only a client that advertised `post_handshake_auth` (`SSL_PHA_EXT_SENT`) accepts the request.
    // SAFETY: `s` is live.
    if unsafe { (*s).post_handshake_auth } != SSL_PHA_EXT_SENT {
        return 0;
    }
    // `tls13_restore_handshake_digest_for_pha` runs before the request is added to the digest
    // (`statem_clnt.c:195-210`).
    // SAFETY: `s` is live.
    if unsafe { k::tls13_restore_handshake_digest_for_pha(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).post_handshake_auth = SSL_PHA_REQUESTED };
    // Parses the request context and appends the message to the transcript (`tls_process_
    // certificate_request`, `statem_clnt.c:2601-2710`).
    // SAFETY: `s` is live.
    if unsafe { tls_process_certificate_request(s, msg) } == 0 {
        return 0;
    }
    // The same hook before the post-handshake client certificate is selected. The reduced
    // synchronous driver cannot resume a half-built PHA flight, so a negative answer is
    // reported as failure rather than an `SSL_X509_LOOKUP` wait.
    // SAFETY: `s` is live.
    if unsafe { crate::ssl::statem::statem_srvr::invoke_cert_cb(s) } <= 0 {
        return 0;
    }
    // `tls_construct_client_certificate` (`statem_clnt.c:3851-3910`): the stored context is echoed.
    // SAFETY: `s` is live; its `pha_context` member obeys the member-buffer invariant.
    let (ctx, ctx_len) = unsafe { (*s).pha_context() };
    // SAFETY: `ctx` names `ctx_len` readable bytes when non-NULL, else the slice is empty.
    let context: &[u8] = if ctx.is_null() {
        &[]
    } else {
        // SAFETY: `pha_context` is `pha_context_len` bytes owned by the connection.
        unsafe { core::slice::from_raw_parts(ctx, ctx_len) }
    };
    // SAFETY: `s` is live.
    if unsafe { crate::ssl::statem::statem_srvr::tls13_construct_certificate(s, context) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    let cert_active = unsafe { crate::ssl::statem::statem_srvr::cert_active_present(s) };
    // SAFETY: `s` is live.
    if cert_active
        // SAFETY: `s` is live.
        && unsafe { crate::ssl::statem::statem_srvr::tls13_construct_cert_verify(s, false) } == 0
    {
        return 0;
    }
    // The PHA Finished is not the first handshake's, so its finished key comes from the client
    // application traffic secret (`tls13_final_finish_mac`, `tls13_enc.c:267-305`).
    // SAFETY: `s` is live.
    if unsafe { k::tls13_construct_finished(s, (*s).client_app_traffic.as_ptr()) } == 0 {
        return 0;
    }
    // `statem_lib.c:1466-1468`: after the flight the client returns to `SSL_PHA_EXT_SENT` so a
    // further request can be answered.
    // SAFETY: `s` is live.
    unsafe { (*s).post_handshake_auth = SSL_PHA_EXT_SENT };
    1
}

// ============================================================================================
// Phase 17 — the reduced TLS1.2 client flight (`ssl/statem/statem_clnt.c`'s TLS1.2 arms).
// ============================================================================================

/// Dispatch a ServerHello to the TLS1.3 or TLS1.2 processor: a `supported_versions` extension
/// (type 43) is present iff TLS1.3 was negotiated (`tls_process_server_hello`,
/// `statem_clnt.c:1467-1836`).
///
/// # Safety
/// `s` is live; `msg` is the full ServerHello message.
unsafe fn process_server_hello_dispatch(s: *mut Ssl, msg: &[u8]) -> c_int {
    match server_hello_selects_tls13(msg) {
        Err(()) => 0,
        // SAFETY: `s`/`msg` are live.
        Ok(true) => unsafe { tls_process_server_hello(s, msg) },
        // SAFETY: `s`/`msg` are live.
        Ok(false) => unsafe { tls12_process_server_hello(s, msg) },
    }
}

/// `MSG_PROCESS_RETURN tls_process_server_hello(...)` for TLS1.2 (`statem_clnt.c:1467-1836`,
/// legacy-version arm): parse the ServerHello, select the cipher, and open the transcript with the
/// suite's PRF hash.
///
/// # Safety
/// `s` is live; `msg` is the full ServerHello message.
unsafe fn tls12_process_server_hello(s: *mut Ssl, msg: &[u8]) -> c_int {
    let Some(sh) = read_server_hello_layout(msg, SSL3_MT_SERVER_HELLO as u8) else {
        return 0;
    };
    if sh.version != TLS1_2_VERSION as u16 {
        return 0;
    }
    // SAFETY: `s` is live; the layout fixed `random` at exactly `SSL3_RANDOM_SIZE` bytes.
    unsafe { (*s).server_random.copy_from_slice(sh.random) };
    // The authority bounds the server's session id before copying it into the
    // `SSL_MAX_SSL_SESSION_ID_LENGTH`-byte `session_id` (`statem_clnt.c:1519-1524`); without
    // this check a hostile ServerHello length (up to 255) overruns the field and the
    // session block it lives in.
    if sh.session_id.len() > crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_SSL3_SESSION_ID_TOO_LONG) };
        return 0;
    }
    if sh.compression != 0 {
        return 0;
    }
    // SAFETY: `sh.cipher` is exactly two readable bytes by construction.
    let chosen = unsafe { crate::ssl::ssl_ciph::ssl3_get_cipher_by_char(sh.cipher.as_ptr()) };
    if chosen.is_null() {
        return 0;
    }
    let sid_len = sh.session_id.len();
    let session_id = sh.session_id;
    // SAFETY: `s` is live; `chosen` is a table row.
    unsafe {
        (*s).pending_cipher = chosen;
        (*s).version = TLS1_2_VERSION;
        (*s).method = crate::ssl::methods::tls12_method(false);
        (*s).tls12_driver = 1;
    }
    // The resumption check (`statem_clnt.c:1653-1699`): a server session-id echo that matches the
    // offered one is a hit; otherwise the client records the server's id on a fresh session.
    // SAFETY: `s` is live; `session_id` is the ServerHello's slice.
    unsafe {
        // `ssl_get_new_session` (`statem_clnt.c:1195-1203`/`:1669-1683`): a fresh client has no
        // session yet; create one now that the version is known.
        // SAFETY: `s` is live.
        if (*s).session.is_null() && crate::ssl::ssl_sess::ssl_get_new_session(s, 0) == 0 {
            return 0;
        }
        let sess = (*s).session;
        if !sess.is_null() {
            let offered = (*sess).session_id_length;
            let is_hit = sid_len != 0
                && sid_len == offered
                && core::slice::from_raw_parts(
                    core::ptr::addr_of!((*sess).session_id).cast::<u8>(),
                    sid_len,
                ) == session_id;
            if is_hit {
                (*s).hit = 1;
                // `tls12_setup_key_block` reads the resumed master secret on the abbreviated
                // flight; the session already carries it.
                core::ptr::copy_nonoverlapping(
                    (*sess).master_key.as_ptr(),
                    (*s).tls12_master_secret.as_mut_ptr(),
                    48,
                );
                (*s).tls12_key_block_len = 0;
            } else {
                if offered > 0 {
                    let sc = (*s).session_ctx;
                    if !sc.is_null() {
                        (*sc)
                            .stats
                            .sess_miss
                            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                    if crate::ssl::ssl_sess::ssl_get_new_session(s, 0) == 0 {
                        return 0;
                    }
                }
                let sess = (*s).session;
                (*sess).session_id_length = sid_len;
                if sid_len > 0 {
                    core::ptr::copy_nonoverlapping(
                        session_id.as_ptr(),
                        (*sess).session_id.as_mut_ptr(),
                        sid_len,
                    );
                }
            }
        }
    }
    // The `session_ticket` extension in the ServerHello announces a following ticket
    // (`tls_parse_stoc_session_ticket`, `extensions_clnt.c`).
    match read_extension_block(sh.rest) {
        Some(ServerHelloExtensionBlock::Present(exts)) => {
            let mut walk = SliceCursor::new(exts);
            while walk.remaining() >= 4 {
                let Some(etype) = walk.take_u16() else {
                    return 0;
                };
                let Some(elen) = walk.take_u16() else {
                    return 0;
                };
                let elen = elen as usize;
                let Some(eb) = walk.take(elen) else {
                    return 0;
                };
                if etype == TLSEXT_TYPE_SESSION_TICKET {
                    // SAFETY: `s` is live.
                    unsafe { (*s).ext_ticket_expected = 1 };
                }
                if etype == TLSEXT_TYPE_STATUS_REQUEST {
                    // `tls_parse_stoc_status_request` (`extensions_clnt.c:1492-1528`): the server's
                    // TLS1.2 `status_request` acknowledgement is empty and means a
                    // `CertificateStatus` follows.
                    // SAFETY: `s` is live.
                    let status_type = unsafe { (*s).ext_status_type };
                    if !eb.is_empty() || status_type != crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_OCSP
                    {
                        // SAFETY: `s` is live.
                        unsafe {
                            ossl_statem_fatal(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION)
                        };
                        return 0;
                    }
                    // SAFETY: `s` is live.
                    unsafe { (*s).ext_status_expected = 1 };
                }
            }
        }
        // A ServerHello without an extension vector, or with a malformed one, was accepted here
        // before the conversion; the TLS1.2 processor leaves the flags unset.
        Some(ServerHelloExtensionBlock::Absent) | None => {}
    }
    // `ssl_cipher_get_evp`: install the AEAD/hash and replay the buffered ClientHello.
    // SAFETY: `s` is live; `chosen` is the table row.
    if unsafe { crate::ssl::t1_enc::tls12_setup_cipher(s, (*chosen).id as u16) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full ServerHello.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `MSG_PROCESS_RETURN tls_process_server_certificate(...)` (`statem_clnt.c:1995-2134`) for the
/// TLS1.2 `Certificate` shape (`certificate_list<0..2^24-1>` of `cert_data<1..2^24-1>`).
///
/// # Safety
/// `s` is live; `msg` is the full Certificate message.
pub(crate) unsafe fn tls12_process_peer_certificate(
    s: *mut Ssl,
    msg: &[u8],
    is_server: bool,
) -> c_int {
    use crate::x509::x_x509::{d2i_X509, X509};
    if msg.len() < 4 || msg[0] != SSL3_MT_CERTIFICATE as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    if body.len() < 3 {
        return 0;
    }
    let mut p = 0usize;
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    p += 3;
    if p + list_len > body.len() {
        return 0;
    }
    if list_len == 0 {
        // SAFETY: `s` is live.
        unsafe {
            if !(*s).peer_cert.is_null() {
                crate::x509::x_x509::X509_free((*s).peer_cert.cast());
                (*s).peer_cert = core::ptr::null_mut();
            }
            if !(*s).peer_chain.is_null() {
                crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
                (*s).peer_chain = core::ptr::null_mut();
            }
        }
        // SAFETY: `s` is live; `msg` is the full message.
        return unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) };
    }
    let list_end = p + list_len;
    // SAFETY: no preconditions; the new stack owns the references pushed into it.
    let chain = OPENSSL_sk_new_null();
    if chain.is_null() {
        return 0;
    }
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
    }
    // SAFETY: `s` is live; the previous leaf/chain/verified chain are owned here.
    unsafe {
        if !(*s).peer_cert.is_null() {
            crate::x509::x_x509::X509_free((*s).peer_cert.cast());
            (*s).peer_cert = core::ptr::null_mut();
        }
        if !(*s).peer_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
            (*s).peer_chain = core::ptr::null_mut();
        }
        if !(*s).verified_chain.is_null() {
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).verified_chain.cast());
            (*s).verified_chain = core::ptr::null_mut();
        }
        let leaf = OPENSSL_sk_value(chain, 0).cast::<X509>();
        crate::x509::x509_set::X509_up_ref(leaf);
        (*s).peer_cert = leaf.cast();
        (*s).peer_chain = chain;
    }
    // `tls_post_process_server_certificate` (`statem_clnt.c:2092-2131`).
    // SAFETY: `s` is live; `peer_chain` is the chain just stored.
    unsafe {
        ERR_set_mark();
        let chain = (*s).peer_chain;
        let i = crate::ssl::ssl_cert::ssl_verify_cert_chain(s, chain);
        if i <= 0 && (is_server || (*s).verify_mode != t::SSL_VERIFY_NONE as c_int) {
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

/// The `ServerECDHParams` prefix and the signature that follows it.
///
/// `params` is the exact signed extent (`curve_type || named_curve || point`); it stops before
/// the signature algorithm, as `tls_process_ske_ecdhe` does when it hashes only the params.
struct ServerEcdhParams<'a> {
    params: &'a [u8],
    group: u16,
    point: &'a [u8],
    sigalg: u16,
    sig: &'a [u8],
}

/// `ServerECDHParams` framing: `curve_type(1) || named_curve(2) || point_len(1) || point ||
/// sig_alg(2) || sig_len(2) || sig`.
///
/// Only the named-curve form (`curve_type == 3`) is reachable in this client; the explicit-prime
/// `ServerDHParams` form is not implemented here, and the authority's length checks leave it
/// unreachable, so it is refused rather than guessed at. Trailing bytes after the signature are
/// ignored, exactly as the reduce does today.
fn read_server_ecdh_params(body: &[u8]) -> Option<ServerEcdhParams<'_>> {
    let mut cur = SliceCursor::new(body);
    let params_start = cur.pos();
    if cur.take_u8()? != 3 {
        return None;
    }
    let group = cur.take_u16()?;
    let ptlen = cur.take_u8()? as usize;
    let point = cur.take(ptlen)?;
    let params_end = cur.pos();
    let params = body.get(params_start..params_end)?;
    let sigalg = cur.take_u16()?;
    let siglen = cur.take_u16()? as usize;
    let sig = cur.take(siglen)?;
    Some(ServerEcdhParams {
        params,
        group,
        point,
        sigalg,
        sig,
    })
}

/// `MSG_PROCESS_RETURN tls_process_key_exchange(...)` (`statem_clnt.c:1995`/`statem_lib.c:441`) for
/// the ECDHE arm: verify the `ServerECDHParams` signature with the server certificate key and wrap
/// the server's point into an `EVP_PKEY`.
///
/// # Safety
/// `s` is live; `msg` is the full ServerKeyExchange message.
unsafe fn tls12_process_server_key_exchange(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::x509::x509_cmp::X509_get0_pubkey;
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_SERVER_KEY_EXCHANGE as u8) {
        return 0;
    }
    let Some(blen) = take_u24(&mut frame) else {
        return 0;
    };
    let Some(body) = frame.take(blen) else {
        return 0;
    };
    let Some(ServerEcdhParams {
        params,
        group,
        point,
        sigalg,
        sig,
    }) = read_server_ecdh_params(body)
    else {
        return 0;
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
    // The signed data is `client_random || server_random || ServerECDHParams`.
    let mut tbs = [0u8; 32 + 32 + 192];
    if params.len() > 192 {
        return 0;
    }
    // SAFETY: `s` is live; both randoms are 32-byte arrays.
    unsafe {
        core::ptr::copy_nonoverlapping((*s).client_random.as_ptr(), tbs.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping((*s).server_random.as_ptr(), tbs.as_mut_ptr().add(32), 32);
    }
    tbs[64..64 + params.len()].copy_from_slice(params);
    // SAFETY: `pkey` is live; `tbs`/`sig` are readable.
    if !unsafe {
        crate::ssl::statem::statem_srvr::tls12_verify(
            pkey.cast(),
            &tbs[..64 + params.len()],
            sigalg,
            sig,
        )
    } {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECRYPT_ERROR, SSL_R_BAD_SIGNATURE) };
        return 0;
    }
    // `tls_process_ske_ecdhe` (`statem_clnt.c:2402-2405`): the server must have picked one of
    // the groups this side offered and this crate can complete.
    if crate::ssl::t1_lib::tls1_group_id2kex(group).is_none()
        // SAFETY: `s` is live.
        || !unsafe { crate::ssl::t1_lib::tls1_get_supported_groups(s) }.contains(&group)
    {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_KEY_SHARE) };
        return 0;
    }
    // SAFETY: `s` is live; `point` is `ptlen` readable bytes and is an encoded point for `group`.
    let peer =
        unsafe { crate::ssl::statem::statem_srvr::tls12_peer_key_from_point(s, group, point) };
    if peer.is_null() {
        return 0;
    }
    // SAFETY: `s` is live; `peer` is this frame's fresh key and the slot's previous owner is
    // released first.
    unsafe {
        crate::evp::pkey::EVP_PKEY_free((*s).peer_tmp.cast());
        (*s).peer_tmp = peer.cast();
        (*s).group_id = group;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `MSG_PROCESS_RETURN tls_process_certificate_request(...)` (`statem_clnt.c:2210-2290`) for
/// TLS1.2: record that a client certificate is requested, save the vector the signer must choose
/// from (`tls1_save_sigalgs`, `statem_clnt.c:2686`) and append the message.
///
/// # Safety
/// `s` is live; `msg` is the full CertificateRequest message.
unsafe fn tls12_process_certificate_request(s: *mut Ssl, msg: &[u8]) -> c_int {
    // `SSL_AD_DECODE_ERROR` — `ssl3.h` (50); `SSL_AD_INTERNAL_ERROR` — `ssl3.h` (80);
    // `SSL_R_LENGTH_MISMATCH` — `sslerr.h:163`; `SSL_R_SIGNATURE_ALGORITHMS_ERROR` — `sslerr.h:360`.
    const SSL_AD_DECODE_ERROR: c_int = 50;
    const SSL_AD_INTERNAL_ERROR: c_int = 80;
    const SSL_R_LENGTH_MISMATCH: c_int = 159;
    const SSL_R_SIGNATURE_ALGORITHMS_ERROR: c_int = 360;
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_CERTIFICATE_REQUEST as u8) {
        return 0;
    }
    let Some(blen) = take_u24(&mut frame) else {
        return 0;
    };
    let Some(body) = frame.take(blen) else {
        return 0;
    };
    // `CertificateRequest { certificate_types<1>; supported_signature_algorithms<2>;
    // certificate_authorities<2>; }` (`statem_clnt.c:2661-2698`). The reduced client does not use
    // the certificate types or the CA names, but the scheme vector must be saved: the certificate
    // constructors refuse a scheme the server did not offer, and without the saved list a client
    // certificate could never be signed.
    let mut cur = SliceCursor::new(body);
    let Some(ctypes_len) = cur.take_u8() else {
        return 0;
    };
    if cur.take(ctypes_len as usize).is_none() {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    }
    let Some(list_len) = cur.take_u16() else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    };
    let Some(schemes) = cur.take(list_len as usize) else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    };
    // An empty vector is legal (`PACKET_memdup` answers NULL for zero bytes) and leaves the
    // client on its advertised defaults, exactly as an empty list does for the authority.
    // SAFETY: `s` is live; `schemes` is the vector's bytes and the default list is `'static`.
    let saved = if schemes.is_empty() {
        // SAFETY: `s` is live; the default list is a `'static` array.
        unsafe {
            crate::ssl::t1_lib::tls1_save_peer_sigalgs_default(
                s,
                &crate::ssl::statem::extensions_clnt::CLIENT_SIGALGS,
            )
        }
    } else {
        // SAFETY: `s` is live; `schemes` is the vector's bytes.
        unsafe { crate::ssl::t1_lib::tls1_save_peer_sigalgs_raw(s, schemes) }
    };
    if saved == 0 {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, SSL_R_SIGNATURE_ALGORITHMS_ERROR) };
        return 0;
    }
    // `certificate_authorities<2>`: validated for extent but not retained.
    let Some(ca_len) = cur.take_u16() else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    };
    if cur.take(ca_len as usize).is_none() {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).s3_tmp_cert_req = 1 };
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// The TLS1.2 `CertificateVerify` body: `sig_alg(2) || sig_len(2) || sig`.
struct CertVerifyLayout<'a> {
    sigalg: u16,
    sig: &'a [u8],
}

/// Parse the `CertificateVerify` signature algorithm, the u16 signature length and the exact
/// signature extent. Trailing bytes after the signature are ignored, matching the reduce.
fn read_cert_verify_layout(body: &[u8]) -> Option<CertVerifyLayout<'_>> {
    let mut cur = SliceCursor::new(body);
    let sigalg = cur.take_u16()?;
    let siglen = cur.take_u16()? as usize;
    let sig = cur.take(siglen)?;
    Some(CertVerifyLayout { sigalg, sig })
}

/// `MSG_PROCESS_RETURN tls_process_cert_verify(...)` (`statem_lib.c:441-560`) for TLS1.2: the
/// signature is over the handshake transcript hash, verified with the peer's certificate key.
///
/// # Safety
/// `s` is live; `msg` is the full CertificateVerify message.
pub(crate) unsafe fn tls12_process_cert_verify(s: *mut Ssl, msg: &[u8], _is_server: bool) -> c_int {
    use crate::x509::x509_cmp::X509_get0_pubkey;
    let mut frame = SliceCursor::new(msg);
    if frame.take_u8() != Some(SSL3_MT_CERTIFICATE_VERIFY as u8) {
        return 0;
    }
    let Some(blen) = take_u24(&mut frame) else {
        return 0;
    };
    let Some(body) = frame.take(blen) else {
        return 0;
    };
    let Some(CertVerifyLayout { sigalg, sig }) = read_cert_verify_layout(body) else {
        return 0;
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
    let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `s` is live; `hash` is writable.
    if unsafe {
        crate::ssl::tls13_enc::transcript_hash(s, hash.as_mut_ptr(), core::ptr::null_mut())
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live.
    let hl = unsafe { (*s).hs_md_len };
    // SAFETY: `pkey` is live; `hash`/`sig` are readable.
    if !unsafe {
        crate::ssl::statem::statem_srvr::tls12_verify(pkey.cast(), &hash[..hl], sigalg, sig)
    } {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECRYPT_ERROR, SSL_R_BAD_SIGNATURE) };
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `CON_FUNC_RETURN tls_construct_client_key_exchange(...)` (`statem_clnt.c:3387-3540`) for the
/// ECDHE arm: generate the client ephemeral, send `ClientECDHParams`, and derive the master secret
/// and key block.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_client_key_exchange(s: *mut Ssl) -> c_int {
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key, EVP_PKEY_get_size};
    use crate::runtime::mem::CleansedScratch;
    use crate::ssl::ssl_ciph_table as ct;
    use crate::ssl::statem::statem_srvr::TLS12_MAX_RSA_BYTES;
    use crate::ssl::tls13_enc::write_handshake_message;

    // SAFETY: `s` is live.
    let mkey = unsafe { (*(*s).pending_cipher).algorithm_mkey as u64 };
    // The premaster is a secret stack copy; the guard wipes it on every return path, not only on
    // success. 80 bytes covers an X25519/X448 secret and a P-521 x-coordinate (66).
    let mut pms = CleansedScratch::<80>::new();
    let pmslen;
    // The authority's `OPENSSL_RSA_MAX_MODULUS_BITS` is 16384 (`rsa.h:39`), so the largest
    // ciphertext this writer can carry is 2048 bytes. The buffer is sized to that maximum and the
    // actual modulus size is checked against it; the former fixed 512-byte buffer rejected every
    // RSA key above 4088 bits.
    let mut body = [0u8; 2 + TLS12_MAX_RSA_BYTES];
    let bodylen;
    if (mkey & ct::SSL_kRSA) != 0 && (mkey & ct::SSL_kECDHE) == 0 {
        // `tls_construct_cke_rsa` (`statem_clnt.c:3153-3225`): 48-byte pre-master
        // (`client_version || 46 random bytes`) encrypted under the server certificate's RSA key
        // with PKCS#1 v1.5 padding, preceded by a two-byte length in TLS1.2.
        // SAFETY: `s` is live.
        let peer_cert = unsafe { (*s).peer_cert };
        if peer_cert.is_null() {
            return 0;
        }
        // SAFETY: `peer_cert` is a live certificate.
        let server_key = unsafe { crate::x509::x509_cmp::X509_get0_pubkey(peer_cert.cast()) };
        if server_key.is_null() {
            return 0;
        }
        // SAFETY: `server_key` is live.
        let modulus_bytes = unsafe { EVP_PKEY_get_size(server_key) };
        if modulus_bytes <= 0 || modulus_bytes as usize > TLS12_MAX_RSA_BYTES {
            return 0;
        }
        // SAFETY: `s` is live; this is the TLS1.2 client's advertised version.
        let client_version = unsafe { (*s).client_version };
        // SAFETY: `pms` is 80 writable bytes; the two version bytes are this frame's.
        unsafe {
            *pms.as_mut_ptr() = (client_version >> 8) as u8;
            *pms.as_mut_ptr().add(1) = client_version as u8;
        }
        // SAFETY: `pms` is 80 writable bytes; the initialised prefix is two bytes.
        if unsafe { crate::rand::rand_lib::RAND_bytes(pms.as_mut_ptr().add(2), 46) } <= 0 {
            return 0;
        }
        // SAFETY: `s` is live.
        let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq()) };
        // SAFETY: `server_key` is live; `libctx`/`propq` are the context's.
        let ctx =
            unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_from_pkey(libctx, server_key, propq) };
        if ctx.is_null() {
            return 0;
        }
        let mut enclen = 0usize;
        // SAFETY: `ctx` is live; a NULL output is the authority's size query; `pms` is readable.
        let ok = unsafe {
            crate::evp::asymcipher::EVP_PKEY_encrypt_init(ctx) > 0
                && crate::evp::asymcipher::EVP_PKEY_encrypt(
                    ctx,
                    core::ptr::null_mut(),
                    &mut enclen,
                    pms.as_ptr(),
                    crate::ssl::ssl_lib::SSL_MAX_MASTER_KEY_LENGTH,
                ) > 0
        };
        if !ok || enclen == 0 || 2 + enclen > body.len() {
            // SAFETY: `ctx` is this frame's own context.
            unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(ctx) };
            return 0;
        }
        body[0] = (enclen >> 8) as u8;
        body[1] = enclen as u8;
        // SAFETY: `ctx` is live; `body[2..]` is writable for `enclen`; `pms` is readable.
        let ok = unsafe {
            crate::evp::asymcipher::EVP_PKEY_encrypt(
                ctx,
                body.as_mut_ptr().add(2),
                &mut enclen,
                pms.as_ptr(),
                crate::ssl::ssl_lib::SSL_MAX_MASTER_KEY_LENGTH,
            )
        } > 0;
        // SAFETY: `ctx` is this frame's own context.
        unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(ctx) };
        if !ok {
            return 0;
        }
        bodylen = 2 + enclen;
        pmslen = crate::ssl::ssl_lib::SSL_MAX_MASTER_KEY_LENGTH;
    } else if (mkey & ct::SSL_kECDHE) != 0 {
        // `tls_construct_cke_ecdhe` (`statem_clnt.c:3257-3285`): generate the ephemeral for the
        // group the server selected in its ServerKeyExchange and send its encoded point.
        // SAFETY: `s` is live.
        let group = unsafe { (*s).group_id };
        // SAFETY: `s` is live; the constructor's handle owns the whole generated key.
        let Some(pkey) =
            (unsafe { crate::ssl::statem::statem_srvr::tls12_generate_ecdh_key(s, group) })
        else {
            return 0;
        };
        let mut pub_ = core::ptr::null_mut::<u8>();
        // SAFETY: `pkey` is live; `pub_` is this frame's writable slot.
        let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey.as_ptr(), &mut pub_) };
        if publen == 0 || publen > 255 {
            // The refusal releases the key it built: returning drops `pkey`.
            return 0;
        }
        // SAFETY: `pub_` is the block `get1` allocated above and has not been released.
        let Some(pub_) = (unsafe { OwnedBuf::adopt_plain(pub_.cast::<u8>(), SeamFile::NULL, 0) })
        else {
            return 0;
        };
        // SAFETY: `s` is live; the old `pkey` slot is NULL or owned by the field.
        unsafe {
            if !(*s).pkey.is_null() {
                EVP_PKEY_free((*s).pkey.cast());
            }
            (*s).pkey = pkey.into_raw().cast();
        }
        let mut got = 0usize;
        // SAFETY: `s` is live; the ephemerals are set; `pms` is writable for 80 bytes.
        if unsafe {
            crate::ssl::tls13_enc::tls13_derive_shared(
                s,
                (*s).pkey,
                (*s).peer_tmp,
                pms.as_mut_ptr(),
                80,
                &mut got,
            )
        } == 0
        {
            return 0;
        }
        pmslen = got;
        body[0] = publen as u8;
        // SAFETY: `pub_` is `publen` readable bytes; `body` has room.
        unsafe { core::ptr::copy_nonoverlapping(pub_.as_ptr(), body.as_mut_ptr().add(1), publen) };
        // The `get1` block's single release is this drop.
        drop(pub_);
        bodylen = 1 + publen;
    } else {
        return 0;
    }
    // Derive the pre-master secret and the key schedule (`ssl_derive`, `s3_lib.c:5474`).
    // SAFETY: `s` is live; `pms[..pmslen]` is the pre-master secret.
    if unsafe { crate::ssl::t1_enc::tls12_derive_master_secret(s, pms.as_ptr(), pmslen) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { crate::ssl::t1_enc::tls12_derive_key_block(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `body` is `bodylen` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_CLIENT_KEY_EXCHANGE as u8, body.as_ptr(), bodylen) }
}

/// `CON_FUNC_RETURN tls_construct_cert_verify(...)` (`statem_lib.c:313-439`) for TLS1.2: sign the
/// transcript hash with the client certificate key.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_cert_verify(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `s` is live; `hash` is writable.
    if unsafe {
        crate::ssl::tls13_enc::transcript_hash(s, hash.as_mut_ptr(), core::ptr::null_mut())
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live.
    let hl = unsafe { (*s).hs_md_len };
    // Heap-allocated for the same reason as the server's `tls12_construct_server_key_exchange`:
    // this flight must fit a small connect thread's stack.
    let mut sig = vec![0u8; 1024];
    // SAFETY: `s` is live; `hash` is readable; `sig` is writable.
    let Some((sigalg, siglen)) =
        (unsafe { crate::ssl::statem::statem_srvr::tls12_sign(s, &hash[..hl], &mut sig) })
    else {
        return 0;
    };
    let mut body = vec![0u8; 1030];
    body[0] = (sigalg >> 8) as u8;
    body[1] = sigalg as u8;
    body[2] = (siglen >> 8) as u8;
    body[3] = siglen as u8;
    body[4..4 + siglen].copy_from_slice(&sig[..siglen]);
    // SAFETY: `s` is live; `body` is `4 + siglen` initialised bytes.
    unsafe {
        write_handshake_message(
            s,
            SSL3_MT_CERTIFICATE_VERIFY as u8,
            body.as_ptr(),
            4 + siglen,
        )
    }
}

/// `int tls_process_initial_server_flight(SSL_CONNECTION *s)`'s OCSP-callback tail —
/// `statem_clnt.c:3003-3040`. Invoked once the server's initial flight has been processed, so a
/// client that requested status receives the callback whether or not a response was sent.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn status_callback_initial_flight(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    let (status_type, ctx) = unsafe { ((*s).ext_status_type, (*s).ctx) };
    if status_type != crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_NOTHING && !ctx.is_null() {
        // SAFETY: `ctx` is the live context just read.
        if let Some(cb) = unsafe { (*ctx).status_cb } {
            // SAFETY: the callback is the application's `int (*)(SSL *, void *)`; `s` and the
            // stored argument are the ones it was installed to receive.
            let ret = unsafe { cb(s, (*ctx).status_arg) };
            if ret == 0 {
                // SAFETY: `s` is live.
                unsafe {
                    ossl_statem_fatal(
                        s,
                        SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
                        crate::runtime::err::err_reasons::SSL_R_INVALID_STATUS_RESPONSE,
                    )
                };
                return 0;
            }
            if ret < 0 {
                // SAFETY: `s` is live.
                unsafe {
                    ossl_statem_fatal(
                        s,
                        SSL_AD_INTERNAL_ERROR,
                        crate::runtime::err::err_reasons::SSL_R_OCSP_CALLBACK_FAILURE,
                    )
                };
                return 0;
            }
        }
    }
    1
}

/// The TLS1.2 client read/write driver (`statem.c`'s read/write sub-state machines, reduced).
/// Returns `1` when the handshake finishes and `-1` while waiting for the peer.
///
/// # Safety
/// `s` is live.
/// Why a TLS1.2 `CertificateStatus` body was refused. The framing failure is a decode error;
/// a status type or response-length disagreement is a bad-status-response alert, matching the
/// authority's split (`tls_process_cert_status`, `statem_clnt.c`).
#[derive(Debug)]
enum CertStatusReject {
    Decode,
    BadResponse,
}

/// Parse `CertificateStatus`: `status_type(1) || response_len(3) || response`.
///
/// Returns exactly the declared response extent, which must consume the whole body. A
/// zero-length response is valid.
fn read_cert_status_response(
    body: &[u8],
    expected_status_type: c_int,
) -> Result<&[u8], CertStatusReject> {
    let mut cur = SliceCursor::new(body);
    let Some(status_type) = cur.take_u8() else {
        return Err(CertStatusReject::Decode);
    };
    let Some(rlen) = take_u24(&mut cur) else {
        return Err(CertStatusReject::Decode);
    };
    if status_type as c_int != expected_status_type {
        return Err(CertStatusReject::BadResponse);
    }
    let Some(response) = cur.take(rlen) else {
        return Err(CertStatusReject::BadResponse);
    };
    if cur.remaining() != 0 {
        return Err(CertStatusReject::BadResponse);
    }
    Ok(response)
}

unsafe fn tls12_client_drive(s: *mut Ssl) -> c_int {
    use crate::ssl::statem::statem_srvr::{
        tls12_construct_certificate, tls12_construct_finished, tls12_read_handshake,
        tls12_write_change_cipher_spec,
    };
    // SAFETY: `s` is live.
    unsafe {
        loop {
            match (*s).hand_state {
                TLS_ST_CR_CERT => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_client_wait(s);
                    };
                    if buf[0] != SSL3_MT_CERTIFICATE as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if tls12_process_peer_certificate(s, &buf[..n], false) == 0 {
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    // A `ServerKeyExchange` follows the Certificate only for the suites whose
                    // key exchange needs it (`send_server_key_exchange`, `statem_srvr.c:353`).
                    // A static-RSA server goes straight to CertificateRequest/ServerHelloDone.
                    (*s).hand_state = if (*s).ext_status_expected != 0 {
                        TLS_ST_CR_CERT_STATUS
                    } else if crate::ssl::statem::statem_srvr::send_server_key_exchange(s) {
                        TLS_ST_CR_KEY_EXCH
                    } else {
                        TLS_ST_CR_CERT_REQ
                    };
                }
                TLS_ST_CR_CERT_STATUS => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_client_wait(s);
                    };
                    if buf[0] != SSL3_MT_CERTIFICATE_STATUS as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    // `tls_process_cert_status` (`statem_clnt.c`):
                    // `status_type(1) || response<3>`.
                    let mut frame = SliceCursor::new(&buf[..n]);
                    if frame.take_u8() != Some(SSL3_MT_CERTIFICATE_STATUS as u8) {
                        ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                        return -1;
                    }
                    let Some(blen) = take_u24(&mut frame) else {
                        ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                        return -1;
                    };
                    let Some(body) = frame.take(blen) else {
                        ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                        return -1;
                    };
                    let response = match read_cert_status_response(body, (*s).ext_status_type) {
                        Ok(response) => response,
                        Err(CertStatusReject::Decode) => {
                            ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                            return -1;
                        }
                        Err(CertStatusReject::BadResponse) => {
                            ossl_statem_fatal(
                                s,
                                SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE,
                                SSL_R_BAD_EXTENSION,
                            );
                            return -1;
                        }
                    };
                    // SAFETY: `s` is live; `response` names `response.len()` readable bytes. The
                    // ctrl copies them, so the transcript buffer may be reused afterwards.
                    if crate::ssl::ssl_lib::SSL_ctrl(
                        s,
                        crate::ssl::ssl_lib::SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,
                        response.len() as core::ffi::c_long,
                        response.as_ptr().cast_mut().cast(),
                    ) != 1
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if crate::ssl::tls13_enc::transcript_update(s, buf.as_ptr(), n) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state =
                        if crate::ssl::statem::statem_srvr::send_server_key_exchange(s) {
                            TLS_ST_CR_KEY_EXCH
                        } else {
                            TLS_ST_CR_CERT_REQ
                        };
                }
                TLS_ST_CR_KEY_EXCH => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_client_wait(s);
                    };
                    if buf[0] != SSL3_MT_SERVER_KEY_EXCHANGE as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if tls12_process_server_key_exchange(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_CERT_REQ;
                }
                TLS_ST_CR_CERT_REQ => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_client_wait(s);
                    };
                    if buf[0] == SSL3_MT_CERTIFICATE_REQUEST as u8 {
                        if tls12_process_certificate_request(s, &buf[..n]) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return -1;
                        }
                        // `tls_prepare_client_certificate` (`statem_clnt.c:3772-3785`): the hook
                        // runs before `TLS_ST_CW_CERT` decides whether a certificate is sent.
                        // SAFETY: `s` is live.
                        if crate::ssl::statem::statem_srvr::invoke_cert_cb(s) <= 0 {
                            return -1;
                        }
                        // A CertificateRequest is followed by ServerHelloDone.
                        continue;
                    }
                    if buf[0] != SSL3_MT_SERVER_DONE as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    // `tls_process_server_hello_done` appends the message to the transcript
                    // (`statem_clnt.c`); the Finished MAC covers it.
                    if crate::ssl::tls13_enc::transcript_update(s, buf.as_ptr(), n) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // `tls_process_server_done` (`statem_clnt.c:3050-3070`) ends with
                    // `tls_process_initial_server_flight`, whose OCSP callback runs here.
                    if status_callback_initial_flight(s) == 0 {
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CW_CERT;
                }
                TLS_ST_CW_CERT => {
                    // A client certificate is sent only when requested and one is loaded
                    // (`tls_construct_client_certificate`, `statem_clnt.c:3851`).
                    if (*s).s3_tmp_cert_req != 0
                        && crate::ssl::statem::statem_srvr::cert_active_present(s)
                    {
                        if tls12_construct_certificate(s) <= 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return -1;
                        }
                        (*s).statem_no_cert_verify = 0;
                    } else {
                        (*s).statem_no_cert_verify = 1;
                    }
                    (*s).hand_state = TLS_ST_CW_KEY_EXCH;
                }
                TLS_ST_CW_KEY_EXCH => {
                    if tls12_construct_client_key_exchange(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = if (*s).statem_no_cert_verify == 0 {
                        TLS_ST_CW_CERT_VRFY
                    } else {
                        TLS_ST_CW_CHANGE
                    };
                }
                TLS_ST_CW_CERT_VRFY => {
                    if tls12_construct_cert_verify(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CW_CHANGE;
                }
                TLS_ST_CW_CHANGE => {
                    if tls12_write_change_cipher_spec(s, true) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if crate::ssl::t1_enc::tls12_install_write(s, true) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CW_FINISHED;
                }
                TLS_ST_CW_FINISHED => {
                    if tls12_construct_finished(s, true) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if (*s).hit != 0 {
                        // The abbreviated flight ends here: the client spoke last.
                        tls12_client_finish(s);
                        return 1;
                    }
                    (*s).hand_state = TLS_ST_CR_CHANGE;
                }
                TLS_ST_CR_CHANGE => {
                    let r = tls12_client_read_ccs(s);
                    if r < 0 {
                        return -1;
                    }
                    if r == 0 {
                        return tls12_client_wait(s);
                    }
                    // The abbreviated flight derives the key block here (the full flight derived it
                    // in `tls12_construct_client_key_exchange`).
                    if (*s).tls12_key_block_len == 0
                        && crate::ssl::t1_enc::tls12_derive_key_block(s) == 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if crate::ssl::t1_enc::tls12_install_read(s, true) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_FINISHED;
                }
                TLS_ST_CR_FINISHED => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_client_wait(s);
                    };
                    if buf[0] != SSL3_MT_FINISHED as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if tls12_process_server_finished(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if (*s).hit != 0 {
                        // Abbreviated: the client now sends its own CCS+Finished.
                        (*s).hand_state = TLS_ST_CW_CHANGE;
                        continue;
                    }
                    tls12_client_finish(s);
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

/// `SSL3_RT_CHANGE_CIPHER_SPEC` — `ssl3.h` (20).
const SSL3_RT_CHANGE_CIPHER_SPEC: u8 = 20;

/// Finish the client's TLS1.2 handshake (`tls_finish_handshake`, `statem_lib.c:1431-1518`, client
/// arm): update the client cache and counters, and move to `TLS_ST_OK`.
///
/// # Safety
/// `s` is live and its handshake is complete.
unsafe fn tls12_client_finish(s: *mut Ssl) {
    // SAFETY: `s` is live per the contract.
    unsafe {
        crate::ssl::ssl_sess::ssl_update_cache(s, crate::ssl::ssl_sess::SSL_SESS_CACHE_CLIENT);
        let sc = (*s).session_ctx;
        if !sc.is_null() {
            if (*s).hit != 0 {
                (*sc)
                    .stats
                    .sess_hit
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            (*sc)
                .stats
                .sess_connect_good
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        (*s).hand_state = TLS_ST_OK;
        (*s).in_init = 0;
        (*s).rwstate = 1; // SSL_NOTHING
        (*s).statem_state = MSG_FLOW_READING_13;
    }
}

/// Read the server's ChangeCipherSpec on the TLS1.2 client, consuming any `NewSessionTicket`
/// that precedes it (`statem_clnt.c`'s `TLS_ST_CR_CHANGE`/`TLS_ST_CR_SESSION_TICKET` states).
/// Returns 1 on CCS, 0 when the peer BIO is empty, -1 on error.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_client_read_ccs(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the contract.
    unsafe {
        loop {
            // Heap-allocated: the TLS1.2 client's change-cipher-spec read may consume a full
            // record, and a record-sized stack array would overflow a small connect thread.
            let mut buf = vec![0u8; 16384];
            let mut rt = 0u8;
            let n = crate::ssl::record::rec_layer_s3::ssl3_read_bytes(
                s,
                &mut rt,
                buf.as_mut_ptr(),
                buf.len(),
            );
            if n <= 0 {
                if ossl_statem_in_error(s) != 0 {
                    return -1;
                }
                return 0;
            }
            if rt == SSL3_RT_CHANGE_CIPHER_SPEC {
                if let Some(cb) = (*s).msg_callback {
                    cb(
                        0,
                        (*s).version,
                        SSL3_RT_CHANGE_CIPHER_SPEC as c_int,
                        buf.as_ptr().cast(),
                        n as usize,
                        s,
                        (*s).msg_callback_arg,
                    );
                }
                return 1;
            }
            if rt == SSL3_RT_HANDSHAKE && buf[0] == SSL3_MT_NEWSESSION_TICKET as u8 {
                // The generic read path feeds every TLS1.2 handshake message into the transcript
                // (`tls_get_message_body`, `statem_lib.c:1759`), including the NewSessionTicket;
                // the server's Finished covers it.
                if crate::ssl::tls13_enc::transcript_update(s, buf.as_ptr(), n as usize) == 0 {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
                if tls12_process_new_session_ticket(s, &buf[..n as usize]) == 0 {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
                continue;
            }
            ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
            return -1;
        }
    }
}

/// `MSG_PROCESS_RETURN tls_process_new_session_ticket(...)` (`statem_clnt.c:2730-2940`) for the
/// TLS1.2 shape: store the ticket and lifetime hint on the session and set the client's resume id
/// to `SHA256(ticket)` (`statem_clnt.c:2851-2872`).
///
/// # Safety
/// `s` is live; `msg` is the full NewSessionTicket message.
unsafe fn tls12_process_new_session_ticket(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::runtime::mem::CRYPTO_malloc;
    if msg.len() < 4 || msg[0] != SSL3_MT_NEWSESSION_TICKET as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    if body.len() < 6 {
        return 0;
    }
    // SAFETY: `body` has at least 6 bytes; the 4-byte prefix is the lifetime hint.
    let lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ticklen = ((body[4] as usize) << 8) | body[5] as usize;
    if 6 + ticklen > body.len() {
        return 0;
    }
    if ticklen == 0 {
        // `statem_clnt.c:2757`: the server changed its mind; nothing to store.
        return 1;
    }
    let ticket = &body[6..6 + ticklen];
    // SAFETY: `s` is live.
    unsafe {
        let mut sess = (*s).session;
        if sess.is_null() {
            return 0;
        }
        // A session that was already resumable is replaced by a duplicate, so the cached copy is
        // immutable (`statem_clnt.c:2768-2792`).
        if (*sess).session_id_length > 0 {
            let dup = crate::ssl::ssl_sess::ssl_session_dup(sess, 0);
            if dup.is_null() {
                return 0;
            }
            crate::ssl::ssl_sess::SSL_SESSION_free(sess);
            (*s).session = dup;
            sess = dup;
        }
        (*sess).time = crate::ssl::ssl_sess::time_now_secs();
        crate::ssl::ssl_sess::ssl_session_calculate_timeout(sess);
        // Release any incumbent at the authority's own site; a duplicated session's member is
        // unset, so this is `CRYPTO_free`'s no-op (see `MemberBufSlot`).
        (*sess).ext_tick_slot().clear(core::ptr::null(), 0);
        let tp = CRYPTO_malloc(ticklen, core::ptr::null(), 0).cast::<u8>();
        if tp.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(ticket.as_ptr(), tp, ticklen);
        // `tp` is this call's fresh block of `ticklen` bytes; the member is empty after `clear`.
        (*sess).ext_tick_slot().store(tp, ticklen);
        (*sess).ext_tick_lifetime_hint = lifetime as core::ffi::c_ulong;
        (*sess).ext_tick_age_add = 0;
        let mut digest = [0u8; 32];
        crate::digest::sha2::SHA256(ticket.as_ptr(), ticklen, digest.as_mut_ptr());
        (*sess).session_id_length = 32;
        core::ptr::copy_nonoverlapping(digest.as_ptr(), (*sess).session_id.as_mut_ptr(), 32);
        (*sess).not_resumable = 0;
    }
    1
}

/// `MSG_PROCESS_RETURN tls_process_new_session_ticket(...)` (`statem_clnt.c:2730-2940`) for the
/// TLS1.3 shape: the wire body is `ticket_lifetime_hint(4) || ticket_age_add(4) ||
/// ticket_nonce<0..255> || ticket<1..2^16-1> || extensions<0..2^16-2>`; the session is always
/// replaced by a duplicate (a ticket arrives post-handshake, after the session entered the cache —
/// `statem_clnt.c:2767-2795`), its id is set to `SHA256(ticket)`, and its PSK to
/// `HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, Hash.length)`
/// (`statem_clnt.c:2884-2898`).
///
/// # Safety
/// `s` is live and the TLS1.3 handshake has completed; `msg` is the full NewSessionTicket message.
pub(crate) unsafe fn tls13_process_new_session_ticket(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::runtime::mem::CRYPTO_malloc;
    if msg.len() < 4 || msg[0] != SSL3_MT_NEWSESSION_TICKET as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    // lifetime(4) + age_add(4) + nonce-length(1) + ticket-length(2) + extensions-length(2).
    if body.len() < 13 {
        return 0;
    }
    let lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let age_add = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let nonce_len = body[8] as usize;
    let mut p = 9usize;
    if p + nonce_len > body.len() {
        return 0;
    }
    let nonce = &body[p..p + nonce_len];
    p += nonce_len;
    if p + 2 > body.len() {
        return 0;
    }
    let ticklen = ((body[p] as usize) << 8) | body[p + 1] as usize;
    p += 2;
    if ticklen == 0 || p + ticklen > body.len() {
        // `statem_clnt.c:2749-2758`: a zero-length TLS1.3 ticket is a decode error; treat as no-op
        // here rather than aborting the connection.
        return 1;
    }
    let ticket = &body[p..p + ticklen];
    // SAFETY: `s` is live.
    unsafe {
        let sess0 = (*s).session;
        if sess0.is_null() {
            return 0;
        }
        // TLS1.3 always duplicates: the current session may already be in the cache.
        let dup = crate::ssl::ssl_sess::ssl_session_dup(sess0, 0);
        if dup.is_null() {
            return 0;
        }
        crate::ssl::ssl_sess::SSL_SESSION_free(sess0);
        (*s).session = dup;
        let sess = dup;
        (*sess).time = crate::ssl::ssl_sess::time_now_secs();
        crate::ssl::ssl_sess::ssl_session_calculate_timeout(sess);
        // Release any incumbent at the authority's own site; the TLS1.3 session is a fresh duplicate
        // whose member is unset, so this is `CRYPTO_free`'s no-op (see `MemberBufSlot`).
        (*sess).ext_tick_slot().clear(core::ptr::null(), 0);
        let tp = CRYPTO_malloc(ticklen, core::ptr::null(), 0).cast::<u8>();
        if tp.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(ticket.as_ptr(), tp, ticklen);
        // `tp` is this call's fresh block of `ticklen` bytes; the member is empty after `clear`.
        (*sess).ext_tick_slot().store(tp, ticklen);
        // RFC 8446 §4.6.1: never cache for longer than 7 days (`statem_clnt.c:2837-2842`).
        let mut lh = lifetime;
        if lh > 604800 {
            lh = 604800;
        }
        (*sess).ext_tick_lifetime_hint = lh as core::ffi::c_ulong;
        (*sess).ext_tick_age_add = age_add;
        // `tls13_hkdf_expand(... resumption_master_secret, "resumption", nonce,`
        // `                  s->session->master_key, hashlen, 1)` (`statem_clnt.c:2891-2898`).
        if crate::ssl::tls13_enc::tls13_ticket_psk(s, nonce, (*sess).master_key.as_mut_ptr()) == 0 {
            return 0;
        }
        (*sess).master_key_length = (*s).hs_md_len;
        // The client's resume id is `SHA256(ticket)` (`statem_clnt.c:2851-2872`).
        let mut digest = [0u8; 32];
        crate::digest::sha2::SHA256(ticket.as_ptr(), ticklen, digest.as_mut_ptr());
        (*sess).session_id_length = 32;
        core::ptr::copy_nonoverlapping(digest.as_ptr(), (*sess).session_id.as_mut_ptr(), 32);
        (*sess).not_resumable = 0;
        // `ssl_update_cache(s, SSL_SESS_CACHE_CLIENT)` (`statem_clnt.c:2902`).
        crate::ssl::ssl_sess::ssl_update_cache(s, crate::ssl::ssl_sess::SSL_SESS_CACHE_CLIENT);
    }
    1
}

/// `tls_process_finished`'s client half (`statem_lib.c:843-960`) for TLS1.2.
///
/// # Safety
/// `s` is live; `msg` is the full Finished message.
unsafe fn tls12_process_server_finished(s: *mut Ssl, msg: &[u8]) -> c_int {
    if msg.len() < 4 || msg[0] != SSL3_MT_FINISHED as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    let mut expected = [0u8; 12];
    // SAFETY: `s` is live; `expected` is writable.
    let n = unsafe {
        crate::ssl::t1_enc::tls12_finished_mac(s, b"server finished", expected.as_mut_ptr())
    };
    if n != 12 || body.len() != 12 {
        return 0;
    }
    let mut diff = 0u8;
    for i in 0..12 {
        diff |= expected[i] ^ body[i];
    }
    if diff != 0 {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// Mark the client as waiting for the peer's next TLS1.2 record.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_client_wait(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if ossl_statem_in_error(s) != 0 || (*s).shutdown & SSL_RECEIVED_SHUTDOWN != 0 {
            return -1;
        }
        (*s).statem_state = MSG_FLOW_READING_13;
        (*s).rwstate = 3; // SSL_READING
    }
    -1
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
        // A TLS1.2 handshake that returned a wait must resume in its own driver on re-entry.
        if (*s).tls12_driver != 0 {
            return tls12_client_drive(s);
        }
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
                    if process_server_hello_dispatch(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // A ServerHello without a TLS1.3 `supported_versions` extension selects the
                    // TLS1.2 flight (`tls_process_server_hello` installs the version).
                    if (*s).version == TLS1_2_VERSION {
                        // A resumed TLS1.2 session has an abbreviated flight (`statem_clnt.c`'s
                        // read transition from `TLS_ST_CR_SRVR_HELLO`): the server's CCS+Finished
                        // follow the ServerHello directly.
                        (*s).hand_state = if (*s).hit != 0 {
                            TLS_ST_CR_CHANGE
                        } else {
                            TLS_ST_CR_CERT
                        };
                        return tls12_client_drive(s);
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
                    if buf[0] == SSL3_MT_CERTIFICATE_REQUEST as u8 {
                        // The TLS1.3 server sends CertificateRequest before Certificate
                        // (`statem_clnt.c:171-187`).
                        if tls_process_certificate_request(s, &buf[..n]) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return -1;
                        }
                        // `tls_post_process_certificate_request` → `tls_prepare_client_certificate`
                        // (`statem_clnt.c:1172`, `:3772-3785`): the certificate hook runs after
                        // the request and before the client certificate is selected, so a
                        // certificate it installs is the one the client sends.
                        // SAFETY: `s` is live.
                        if crate::ssl::statem::statem_srvr::invoke_cert_cb(s) <= 0 {
                            return -1;
                        }
                        (*s).hand_state = TLS_ST_CR_CERT_REQ;
                        continue;
                    }
                    if tls13_process_peer_certificate(s, &buf[..n], false) == 0 {
                        // `tls13_process_peer_certificate` already raises the verification alert
                        // and enters `MSG_FLOW_ERROR`; only the parse-failure arm needs the generic
                        // alert (`ossl_statem_send_fatal` is idempotent, but the reason is not).
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_CR_CERT_VRFY;
                }
                TLS_ST_CR_CERT_REQ => {
                    let Some((buf, n)) = client_read(s) else {
                        return client_wait(s);
                    };
                    if tls13_process_peer_certificate(s, &buf[..n], false) == 0 {
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
                    if tls_process_cert_verify(s, &buf[..n], false) == 0 {
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
                    // `tls_process_finished` (`statem_lib.c:961`) runs
                    // `tls_process_initial_server_flight` once the server's flight is complete.
                    if status_callback_initial_flight(s) == 0 {
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
unsafe fn client_read(s: *mut Ssl) -> Option<(Vec<u8>, usize)> {
    // Heap-allocated for the same reason as `tls12_read_handshake`.
    let mut buf = vec![0u8; 16384];
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
        // A terminal read already set the connection's error or shutdown state
        // (`ssl3_read_bytes`' alert/EOF arms, `rec_layer_s3.c:864-944`/`:501-524`); it must not be
        // turned back into a wait, or `SSL_get_error` would answer `SSL_ERROR_WANT_READ` and the
        // caller would block on a peer that has gone away.
        if ossl_statem_in_error(s) != 0 || (*s).shutdown & SSL_RECEIVED_SHUTDOWN != 0 {
            return -1;
        }
        (*s).statem_state = MSG_FLOW_READING_13;
        (*s).rwstate = 3; // SSL_READING
    }
    let _ = MSG_FLOW_ERROR_13;
    -1
}

// -------------------------------------------------------------------------------------------
// Adversarial allocator-refusal tests (`stage/p25/adv-tests`, §16 / §18)
// -------------------------------------------------------------------------------------------
//
// Drive the TLS1.2 and TLS1.3 client ticket writers with their replacement allocation refused and
// assert the recorded safety improvement: the member is left `(NULL, 0)` rather than holding the
// just-freed pointer, so the later session destructor cannot release a dangling block.
//
// Run alone in its own process, under the gate, with the ignore-aware filter:
//   OPENSSL_RS_ADV_PROBE=1 cargo test --lib \
//     ssl::statem::statem_clnt::adv_probe -- --ignored --exact --test-threads=1 --nocapture
// or, for every probe one process at a time, `scripts/adv-probe.sh`.
#[cfg(test)]
mod adv_probe {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
    use crate::ssl::adv_alloc::{self, Ev};
    use crate::ssl::ssl_sess::{SSL_SESSION_free, SSL_SESSION_new};

    /// The TLS1.2 body `lifetime(4) || ticket_len(2) || ticket`.
    fn tls12_ticket_msg(ticket: &[u8]) -> Vec<u8> {
        let body_len = 4 + 2 + ticket.len();
        let mut msg = vec![
            SSL3_MT_NEWSESSION_TICKET as u8,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        msg.extend_from_slice(&3600u32.to_be_bytes());
        msg.push((ticket.len() >> 8) as u8);
        msg.push(ticket.len() as u8);
        msg.extend_from_slice(ticket);
        msg
    }

    /// The TLS1.3 body `lifetime(4) || age_add(4) || nonce_len(1)=0 || ticket_len(2) || ticket ||
    /// ext_len(2)=0`.
    fn tls13_ticket_msg(ticket: &[u8]) -> Vec<u8> {
        let body_len = 4 + 4 + 1 + 2 + ticket.len() + 2;
        let mut msg = vec![
            SSL3_MT_NEWSESSION_TICKET as u8,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        msg.extend_from_slice(&3600u32.to_be_bytes());
        msg.extend_from_slice(&0u32.to_be_bytes());
        msg.push(0); // nonce_len
        msg.push((ticket.len() >> 8) as u8);
        msg.push(ticket.len() as u8);
        msg.extend_from_slice(ticket);
        msg.extend_from_slice(&[0, 0]); // extensions
        msg
    }

    /// Shared assertions: exactly one request refused, at the writer's own `(NULL, 0)` site and of
    /// the ticket length; the incumbent released before it; no double release observed.
    fn assert_refusal_transcript(incumbent: usize, ticklen: usize) {
        let ev = adv_alloc::events();
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(e, Ev::Malloc { refused: true, .. }))
                .count(),
            1,
            "exactly one request is refused"
        );
        let at = match ev
            .iter()
            .position(|e| matches!(e, Ev::Malloc { refused: true, .. }))
        {
            Some(i) => i,
            None => panic!("the ticket allocation must be refused: {ev:?}"),
        };
        assert!(
            matches!(&ev[at], Ev::Malloc { n, site: true, refused: true } if *n == ticklen),
            "the refused request is the writer's own (NULL,0) request of `ticklen`"
        );
        assert!(
            ev[..at]
                .iter()
                .any(|e| matches!(e, Ev::Free { p } if *p == incumbent)),
            "the incumbent is released before the refused replacement"
        );
        assert!(!adv_alloc::double_free(), "no release is performed twice");
    }

    /// `tls12_process_new_session_ticket` refusal path. The session has a zero id, so the writer
    /// uses it directly (no duplicate); an incumbent ticket is present and is released before the
    /// refused replacement.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn tls12_process_refused_ticket_alloc_leaves_ext_tick_empty() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        let ticklen = 16usize;
        let msg = tls12_ticket_msg(&[0xAB; 16]);

        // SAFETY: the session and `Ssl` block are this frame's own allocations.
        let (sess, s, incumbent) = unsafe {
            let sess = SSL_SESSION_new();
            assert!(!sess.is_null());
            // session_id_length stays 0, so the writer uses `sess` directly.
            let incumbent = CRYPTO_malloc(20, core::ptr::null(), 0).cast::<u8>();
            assert!(!incumbent.is_null());
            (*sess).ext_tick_slot().store(incumbent, 20);
            let s = adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).session = sess;
            (sess, s, incumbent)
        };

        adv_alloc::reset();
        adv_alloc::arm(ticklen);
        // SAFETY: `s` is the live connection this frame built, with its session set.
        let r = unsafe { tls12_process_new_session_ticket(s, &msg) };
        adv_alloc::disarm();

        assert_eq!(
            r, 0,
            "a refused ticket allocation returns the authority's error"
        );
        // SAFETY: `sess` is live.
        let (p, n) = unsafe { (*sess).ext_tick() };
        assert!(
            p.is_null() && n == 0,
            "the refused path leaves the member (NULL, 0)"
        );
        assert_refusal_transcript(incumbent as usize, ticklen);

        // SAFETY: `sess` is live and owned here; `s` is the block `zeroed_ssl` allocated.
        unsafe {
            SSL_SESSION_free(sess);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        assert!(!adv_alloc::double_free());
    }

    /// `tls13_process_new_session_ticket` refusal path. TLS1.3 always replaces the session with a
    /// duplicate, so the writer's member is the duplicate's; the refusal must still leave it empty.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn tls13_process_refused_ticket_alloc_leaves_ext_tick_empty() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        let ticklen = 16usize;
        let msg = tls13_ticket_msg(&[0xCD; 16]);

        // SAFETY: the session and `Ssl` block are this frame's own allocations.
        let (sess0, s) = unsafe {
            let sess0 = SSL_SESSION_new();
            assert!(!sess0.is_null());
            let s = adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).session = sess0;
            (sess0, s)
        };

        adv_alloc::reset();
        adv_alloc::arm(ticklen);
        // SAFETY: `s` is the live connection this frame built, with its session set.
        let r = unsafe { tls13_process_new_session_ticket(s, &msg) };
        adv_alloc::disarm();

        assert_eq!(
            r, 0,
            "a refused ticket allocation returns the authority's error"
        );
        // SAFETY: `s` is live; the writer replaced its session with a fresh duplicate (sess0 was
        // released inside the writer).
        let dup = unsafe { (*s).session };
        assert!(
            !dup.is_null() && dup != sess0,
            "TLS1.3 replaces the session with a duplicate"
        );
        // SAFETY: `dup` is live.
        let (p, n) = unsafe { (*dup).ext_tick() };
        assert!(
            p.is_null() && n == 0,
            "the refused path leaves the member (NULL, 0)"
        );
        // The duplicate's member is empty, so no incumbent free precedes the refusal.
        let ev = adv_alloc::events();
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(e, Ev::Malloc { refused: true, .. }))
                .count(),
            1,
            "exactly one request is refused"
        );
        let at = match ev
            .iter()
            .position(|e| matches!(e, Ev::Malloc { refused: true, .. }))
        {
            Some(i) => i,
            None => panic!("the ticket allocation must be refused: {ev:?}"),
        };
        assert!(
            matches!(&ev[at], Ev::Malloc { n, site: true, refused: true } if *n == ticklen),
            "the refused request is the writer's own (NULL,0) request of `ticklen`"
        );

        // SAFETY: `dup` is the session the writer owns; `s` is the block `zeroed_ssl` allocated.
        unsafe {
            SSL_SESSION_free(dup);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        assert!(!adv_alloc::double_free());
    }

    /// Negative control (§16): prove the *refusal* instrument fires. Arming a size must make the
    /// next matching `(NULL, 0)` request answer NULL and be recorded, so a probe that asserts a
    /// refusal cannot pass with a dead detector.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn canary_refusal_instrument_fires() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();

        adv_alloc::reset();
        adv_alloc::arm(37);
        let p = unsafe {
            // SAFETY: `file` is NULL or a NUL-terminated coordinate valid for the call (a static literal/default, or a precondition established by the calling boundary), so `malloc_request`/the installed hook may read it.
            CRYPTO_malloc(37, core::ptr::null(), 0)
        };
        adv_alloc::disarm();

        assert!(p.is_null(), "the armed refusal must answer NULL");
        let ev = adv_alloc::events();
        assert_eq!(
            ev.iter()
                .filter(|e| matches!(
                    e,
                    Ev::Malloc {
                        n: 37,
                        site: true,
                        refused: true
                    }
                ))
                .count(),
            1,
            "the refusal must be recorded exactly once: {ev:?}"
        );
    }
}

// -------------------------------------------------------------------------------------------
// ServerHello session-id bounds (§16 negative control for the B4-D1 write)
// -------------------------------------------------------------------------------------------
//
// RFC 8446/RFC 5246 bound `legacy_session_id_echo`/`session_id` at 32 bytes. The authority rejects
// a longer value before any use (`statem_clnt.c:1519-1524`, `SSL_R_SSL3_SESSION_ID_TOO_LONG`), so
// a hostile ServerHello cannot reach the fixed `SslSession::session_id` array. These tests assert
// the refusal happens before the session is created or mutated.
#[cfg(test)]
mod server_hello_bounds {
    #![allow(clippy::panic)]

    use super::*;
    use crate::runtime::mem::CRYPTO_free;

    /// `type || body_len || version(2) || random(32) || sid_len(1) || sid || cipher(2) || 0`.
    fn server_hello(sid: &[u8]) -> Vec<u8> {
        let body_len = 2 + SSL3_RANDOM_SIZE + 1 + sid.len() + 2 + 1;
        let mut msg = vec![
            SSL3_MT_SERVER_HELLO as u8,
            (body_len >> 16) as u8,
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        msg.extend_from_slice(&[0x03, 0x03]);
        msg.extend_from_slice(&[0u8; SSL3_RANDOM_SIZE]);
        msg.push(sid.len() as u8);
        msg.extend_from_slice(sid);
        // `TLS_RSA_WITH_AES_128_CBC_SHA256` (0x003C): a table row, so the size check is the
        // only refusal this input reaches.
        msg.extend_from_slice(&[0x00, 0x3c]);
        msg.push(0);
        msg
    }

    #[test]
    fn tls12_oversized_server_session_id_is_refused_without_partial_state() {
        let _g = crate::test_support::lock_global_state();
        let msg = server_hello(&[0xA5; 64]);
        // SAFETY: the connection is this test's own zeroed allocation; the server id is rejected
        // before a session is created, so nothing else owns state here.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            let r = tls12_process_server_hello(s, &msg);
            assert_eq!(r, 0, "a 64-byte session id must be refused");
            assert!(
                (*s).session.is_null(),
                "the refusal must not publish a partially built session"
            );
            assert_eq!(
                (*s).statem_state,
                MSG_FLOW_ERROR_13,
                "the refusal poisons the connection"
            );
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn tls13_oversized_server_session_id_is_refused() {
        let _g = crate::test_support::lock_global_state();
        let msg = server_hello(&[0x5A; 64]);
        // SAFETY: as above.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            let r = tls_process_server_hello(s, &msg);
            assert_eq!(r, 0, "a 64-byte echoed session id must be refused");
            assert!((*s).session.is_null(), "no session is created on refusal");
            assert_eq!((*s).statem_state, MSG_FLOW_ERROR_13);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }
}

// -------------------------------------------------------------------------------------------
// ServerHello parse cluster: version selection, extension readers, and malformed input.
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod server_hello_parse {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new, SslCtx};

    /// The echoed TLS1.3 `legacy_session_id` used by the valid cases.
    const SID: &[u8] = &[0xA1, 0xB2, 0xC3, 0xD4];
    const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    const ECDHE_RSA_AES_128_GCM_SHA256: u16 = 0xC02F;
    const X25519: u16 = 0x001D;

    fn extension(etype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&etype.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn extension_block(exts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for ext in exts {
            body.extend_from_slice(ext);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn frame(mut body: Vec<u8>) -> Vec<u8> {
        let mut msg = vec![SSL3_MT_SERVER_HELLO as u8];
        msg.push((body.len() >> 16) as u8);
        msg.push((body.len() >> 8) as u8);
        msg.push(body.len() as u8);
        msg.append(&mut body);
        msg
    }

    /// `legacy_version || random || session_id || cipher_suite || compression`.
    fn hello_prefix(sid: &[u8], cipher: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; SSL3_RANDOM_SIZE]);
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0);
        body
    }

    fn server_hello(sid: &[u8], cipher: u16, exts: Option<&[Vec<u8>]>) -> Vec<u8> {
        let mut body = hello_prefix(sid, cipher);
        if let Some(exts) = exts {
            body.extend_from_slice(&extension_block(exts));
        }
        frame(body)
    }

    fn supported_versions_ext(version: u16) -> Vec<u8> {
        extension(TLSEXT_TYPE_SUPPORTED_VERSIONS, &version.to_be_bytes())
    }

    fn key_share_ext(group: u16, share: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&group.to_be_bytes());
        body.extend_from_slice(&(share.len() as u16).to_be_bytes());
        body.extend_from_slice(share);
        extension(TLSEXT_TYPE_KEY_SHARE, &body)
    }

    /// Generate one X25519 key and open a live connection with it installed as the client's
    /// ephemeral. The server's encoded public share is returned for the ServerHello.
    ///
    /// # Safety
    /// The returned connection is owned by the caller and released with `SSL_free`; the context
    /// is owned by the caller and released with `SSL_CTX_free`.
    unsafe fn tls13_connection() -> (*mut SslCtx, *mut Ssl, [u8; 32]) {
        use crate::evp::pkey::{evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
        // SAFETY: every constructor below answers a fresh object owned by this frame.
        unsafe {
            let ctx = SSL_CTX_new(crate::ssl::methods::TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            (&mut (*s).tmp_session_id)[..SID.len()].copy_from_slice(SID);
            (*s).tmp_session_id_len = SID.len();

            let params = [crate::params::END; 1];
            let client = evp_pkey_keygen(
                core::ptr::null_mut(),
                c"X25519".as_ptr(),
                core::ptr::null(),
                params.as_ptr(),
            );
            assert!(!client.is_null(), "a client X25519 key must be generated");
            (*s).pkey = client.cast();

            let server = evp_pkey_keygen(
                core::ptr::null_mut(),
                c"X25519".as_ptr(),
                core::ptr::null(),
                params.as_ptr(),
            );
            assert!(!server.is_null(), "a server X25519 key must be generated");
            let mut pubp: *mut u8 = core::ptr::null_mut();
            let n = EVP_PKEY_get1_encoded_public_key(server, &mut pubp);
            assert_eq!(n, 32, "X25519 public keys are 32 bytes");
            let mut share = [0u8; 32];
            core::ptr::copy_nonoverlapping(pubp, share.as_mut_ptr(), 32);
            CRYPTO_free(pubp.cast(), core::ptr::null(), 0);
            EVP_PKEY_free(server);
            (ctx, s, share)
        }
    }

    #[test]
    fn valid_tls13_server_hello_is_accepted() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the connection and context are this test's own objects.
        unsafe {
            let (ctx, s, share) = tls13_connection();
            let msg = server_hello(
                SID,
                TLS_AES_128_GCM_SHA256,
                Some(&[
                    key_share_ext(X25519, &share),
                    supported_versions_ext(0x0304),
                ]),
            );
            assert_eq!(
                tls_process_server_hello(s, &msg),
                1,
                "a well-formed TLS1.3 ServerHello must be accepted"
            );
            assert_eq!((*s).version, TLS1_3_VERSION);
            assert_eq!((*s).group_id, X25519);
            assert_eq!((*(*s).pending_cipher).id as u16, TLS_AES_128_GCM_SHA256);
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn valid_tls12_server_hello_selects_the_tls12_processor() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the connection and context are this test's own objects.
        unsafe {
            let ctx = SSL_CTX_new(crate::ssl::methods::TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            let msg = server_hello(&[], ECDHE_RSA_AES_128_GCM_SHA256, None);
            assert_eq!(
                process_server_hello_dispatch(s, &msg),
                1,
                "a TLS1.2 ServerHello must be accepted by the legacy arm"
            );
            assert_eq!((*s).version, TLS1_2_VERSION);
            assert_eq!((*s).tls12_driver, 1);
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn missing_supported_versions_selects_the_legacy_processor() {
        let msg = server_hello(&[], ECDHE_RSA_AES_128_GCM_SHA256, None);
        assert_eq!(
            server_hello_selects_tls13(&msg),
            Ok(false),
            "absence of supported_versions must select the TLS1.2 arm"
        );
    }

    #[test]
    fn unknown_cipher_is_refused() {
        let _g = crate::test_support::lock_global_state();
        let msg = server_hello(&[], 0xFFFF, None);
        // SAFETY: the refusal happens before any connection state is read.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls12_process_server_hello(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn session_id_echo_mismatch_is_refused() {
        let _g = crate::test_support::lock_global_state();
        let msg = server_hello(
            SID,
            TLS_AES_128_GCM_SHA256,
            Some(&[supported_versions_ext(0x0304)]),
        );
        // SAFETY: the mismatch is detected before the cipher or context is used.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls_process_server_hello(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn duplicate_extension_keeps_the_last_value() {
        let first = key_share_ext(X25519, &[0x11; 32]);
        let second = key_share_ext(0x0100, &[0x22; 16]);
        let mut exts = Vec::new();
        exts.extend_from_slice(&first);
        exts.extend_from_slice(&second);
        let parsed =
            read_tls13_server_hello_extensions(&exts).expect("both entries are well formed");
        assert_eq!(parsed.group, 0x0100, "the later key_share wins");
        assert_eq!(parsed.share, &[0x22; 16]);
    }

    #[test]
    fn key_share_group_not_offered_is_refused() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the connection and context are this test's own objects.
        unsafe {
            let (ctx, s, _) = tls13_connection();
            let msg = server_hello(
                SID,
                TLS_AES_128_GCM_SHA256,
                Some(&[
                    key_share_ext(0x0100, &[0x33; 16]),
                    supported_versions_ext(0x0304),
                ]),
            );
            assert_eq!(
                tls_process_server_hello(s, &msg),
                0,
                "a group this client did not offer cannot complete the exchange"
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn truncated_extension_block_is_refused() {
        let _g = crate::test_support::lock_global_state();
        let mut body = hello_prefix(SID, TLS_AES_128_GCM_SHA256);
        // `extensions<2>` declares 255 bytes but the body ends here.
        body.extend_from_slice(&[0x00, 0xFF]);
        let msg = frame(body);
        let sh = read_server_hello_layout(&msg, SSL3_MT_SERVER_HELLO as u8)
            .expect("the fixed prefix is well formed");
        assert!(
            read_extension_block(sh.rest).is_none(),
            "a declared extension extent past the body must be rejected"
        );
        // SAFETY: the mismatch is detected before the cipher or context is used.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (&mut (*s).tmp_session_id)[..SID.len()].copy_from_slice(SID);
            (*s).tmp_session_id_len = SID.len();
            assert_eq!(tls_process_server_hello(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    /// Deterministic (seeded, bounded) mutation of a well-formed ServerHello. Every parse helper
    /// must answer `None`/`Err` rather than panic; the production entry points are not called here
    /// because a zeroed connection has no context and a valid frame would reach it.
    #[test]
    fn malformed_server_hello_loop_does_not_panic() {
        let good = server_hello(
            SID,
            TLS_AES_128_GCM_SHA256,
            Some(&[
                key_share_ext(X25519, &[0x44; 32]),
                supported_versions_ext(0x0304),
            ]),
        );
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut msg = good.clone();
            let edits = 1 + (state as usize % 4);
            for i in 0..edits {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state as usize) % msg.len();
                msg[at] ^= (state >> 32) as u8 | (i as u8 + 1);
            }
            if let Some(sh) = read_server_hello_layout(&msg, SSL3_MT_SERVER_HELLO as u8) {
                if let Some(ServerHelloExtensionBlock::Present(exts)) =
                    read_extension_block(sh.rest)
                {
                    let _ = read_tls13_server_hello_extensions(exts);
                }
            }
            let _ = server_hello_selects_tls13(&msg);
        }
    }
}

// -------------------------------------------------------------------------------------------
// EncryptedExtensions / CertificateRequest / Certificate framing on the client path.
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod post_server_hello_parse {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::ssl_lib::{
        SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_get0_alpn_selected, SSL_new,
    };
    use core::ffi::c_uint;

    fn extension(etype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = etype.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn extension_block(exts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for ext in exts {
            body.extend_from_slice(ext);
        }
        let mut out = (body.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// `type || declared_length (ignored by the reduced reader) || extensions<2> || body`.
    fn encrypted_extensions(block: &[u8]) -> Vec<u8> {
        let mut msg = vec![SSL3_MT_EE_BODY, 0, 0, block.len() as u8];
        msg.extend_from_slice(block);
        msg
    }

    /// `type || u24(body_len) || body`.
    fn framed(mt: c_int, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![mt as u8];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(body);
        msg
    }

    fn alpn_ext(proto: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&((proto.len() + 1) as u16).to_be_bytes());
        body.push(proto.len() as u8);
        body.extend_from_slice(proto);
        extension(TLSEXT_TYPE_ALPN, &body)
    }

    #[test]
    fn encrypted_extensions_with_alpn_h2_selects_it() {
        let _g = crate::test_support::lock_global_state();
        let msg = encrypted_extensions(&extension_block(&[alpn_ext(b"h2")]));
        // SAFETY: the context and connection are this test's own objects.
        unsafe {
            let ctx = SSL_CTX_new(crate::ssl::methods::TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            assert_eq!(
                tls_process_encrypted_extensions(s, &msg),
                1,
                "a well-formed ALPN extension must be accepted"
            );
            let mut data: *const u8 = core::ptr::null();
            let mut len: c_uint = 0;
            SSL_get0_alpn_selected(s, &mut data, &mut len);
            assert_eq!(len, 2, "the selected protocol is recorded");
            assert_eq!(
                core::slice::from_raw_parts(data, len as usize),
                b"h2",
                "the selected protocol is the one the server named"
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn encrypted_extensions_unknown_extension_is_ignored() {
        let _g = crate::test_support::lock_global_state();
        let msg = encrypted_extensions(&extension_block(&[extension(0x1234, &[0xAA, 0xBB])]));
        // SAFETY: `s` is this frame's zeroed block; the accepted path only appends to the
        // transcript buffer and records no extension.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(
                tls_process_encrypted_extensions(s, &msg),
                1,
                "an unrecognised extension must be ignored, not rejected"
            );
            let mut data: *const u8 = core::ptr::null();
            let mut len: c_uint = 0;
            SSL_get0_alpn_selected(s, &mut data, &mut len);
            assert!(data.is_null() && len == 0, "no ALPN was selected");
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn truncated_encrypted_extensions_is_refused() {
        // The extension block declares 255 bytes but the message ends after two.
        let msg = encrypted_extensions(&[0x00, 0xFF]);
        // SAFETY: the refusal happens before any connection state is read.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls_process_encrypted_extensions(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        // An extension declares four body bytes but carries two.
        let msg = encrypted_extensions(&[0x00, 0x06, 0x12, 0x34, 0x00, 0x04, 0x00, 0x00]);
        // SAFETY: as above.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls_process_encrypted_extensions(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn tls12_certificate_request_frame_is_accepted_and_bounded() {
        let _g = crate::test_support::lock_global_state();
        // `certificate_types<1>(rsa_sign) || supported_signature_algorithms<2>(empty) ||
        // certificate_authorities<2>(empty)`: an empty scheme vector is legal and selects the
        // client's defaults. The trailing CA field is mandatory for the authority's reader.
        let body = [0x01, 0x01, 0x00, 0x00, 0x00, 0x00];
        let msg = framed(SSL3_MT_CERTIFICATE_REQUEST, &body);
        // SAFETY: `s` is this frame's zeroed block; the accepted path appends to the transcript.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls12_process_certificate_request(s, &msg), 1);
            assert_eq!((*s).s3_tmp_cert_req, 1, "the request is recorded");
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        // The declared body length overruns the message.
        let msg = vec![
            SSL3_MT_CERTIFICATE_REQUEST as u8,
            0x00,
            0x00,
            0x08,
            0x01,
            0x01,
        ];
        // SAFETY: as above; the refusal reads no connection state.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls12_process_certificate_request(s, &msg), 0);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn tls13_certificate_request_frame_is_accepted() {
        let _g = crate::test_support::lock_global_state();
        // `context<1>(empty) || extensions<2>(empty)`.
        let msg = framed(SSL3_MT_CERTIFICATE_REQUEST, &[0x00, 0x00, 0x00]);
        // SAFETY: `s` is this frame's zeroed block; the accepted path appends to the transcript.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls_process_certificate_request(s, &msg), 1);
            assert_eq!((*s).s3_tmp_cert_req, 1, "the request is recorded");
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        // The extension block length does not end the body.
        let msg = framed(SSL3_MT_CERTIFICATE_REQUEST, &[0x00, 0x00, 0x02, 0xAA]);
        // SAFETY: as above; the length mismatch sends the authority's fatal alert.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls_process_certificate_request(s, &msg), 0);
            assert_eq!((*s).statem_state, MSG_FLOW_ERROR_13);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn zero_length_certificate_list_is_refused_for_a_server_but_legal_for_a_peer() {
        let _g = crate::test_support::lock_global_state();
        // `context<1>(empty) || certificate_list<3>(empty)`.
        let msg = framed(SSL3_MT_CERTIFICATE, &[0x00, 0x00, 0x00, 0x00]);
        // SAFETY: `s` is this frame's zeroed block; no certificate is decoded.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(
                tls13_process_peer_certificate(s, &msg, false),
                0,
                "a server may not send an empty certificate list"
            );
            CRYPTO_free(s.cast(), core::ptr::null(), 0);

            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(
                tls13_process_peer_certificate(s, &msg, true),
                1,
                "an empty client certificate list is legal without a verification demand"
            );
            assert!((*s).peer_cert.is_null() && (*s).peer_chain.is_null());
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn certificate_list_length_that_overruns_is_refused() {
        let _g = crate::test_support::lock_global_state();
        // `context<1>(empty) || certificate_list<3>(5)` followed by only two bytes.
        let msg = framed(SSL3_MT_CERTIFICATE, &[0x00, 0x00, 0x00, 0x05, 0x30, 0x01]);
        // SAFETY: the refusal happens before any certificate is decoded.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            assert_eq!(tls13_process_peer_certificate(s, &msg, true), 0);
            assert!((*s).peer_chain.is_null());
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }

    #[test]
    fn tls13_entry_with_a_truncated_extension_block_is_refused() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        // One `CertificateEntry`: `cert_data<3>(5) || extensions<2>(3)` followed by only one
        // extension byte.
        let mut entry = vec![0x00, 0x00, 0x05];
        entry.extend_from_slice(&der);
        entry.extend_from_slice(&[0x00, 0x03, 0xAA]);

        // `context<1>(empty) || certificate_list<3> || entry`.
        let mut body = vec![0x00];
        body.extend_from_slice(&(entry.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&entry);

        let cert_list = &body[4..];
        let mut cur = SliceCursor::new(cert_list);
        assert!(
            read_tls13_certificate_entry(&mut cur).is_none(),
            "an entry whose extension block overruns the list must be refused"
        );

        // The same entry is accepted when the extension block fits, and the frame's trailing
        // one- or two-byte remainder is ignored exactly as before.
        let mut good = Vec::new();
        good.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        good.extend_from_slice(&der);
        good.extend_from_slice(&[0x00, 0x00]);
        good.extend_from_slice(&[0x00, 0x00]);
        let mut cur = SliceCursor::new(&good);
        let Some((entry, exts)) = read_tls13_certificate_entry(&mut cur) else {
            panic!("a complete entry must parse");
        };
        assert_eq!(entry, der);
        assert!(exts.is_empty());
        assert_eq!(cur.remaining(), 2, "a short remainder ends the walk");
    }

    #[test]
    fn zero_length_certificate_entry_is_refused() {
        let list = [0x00, 0x00, 0x00, 0x00, 0x00];
        let mut cur = SliceCursor::new(&list);
        assert!(
            read_tls13_certificate_entry(&mut cur).is_none(),
            "cert_data<1..2^24-1> may not be empty"
        );
    }

    /// Deterministic (seeded, bounded) mutation of an EncryptedExtensions message and a
    /// certificate list. The production EncryptedExtensions parser and the entry framer must
    /// answer a code rather than panic.
    #[test]
    fn malformed_post_server_hello_loop_does_not_panic() {
        let _g = crate::test_support::lock_global_state();
        let good_ee = encrypted_extensions(&extension_block(&[
            alpn_ext(b"h2"),
            extension(0x1234, &[0x01]),
        ]));
        let mut good_cert_list = Vec::new();
        good_cert_list.extend_from_slice(&[0x00, 0x00, 0x05]);
        good_cert_list.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        good_cert_list.extend_from_slice(&[0x00, 0x00]);

        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut ee = good_ee.clone();
            let edits = 1 + (state as usize % 4);
            for i in 0..edits {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state as usize) % ee.len();
                ee[at] ^= (state >> 32) as u8 | (i as u8 + 1);
            }
            // SAFETY: `s` is this iteration's own zeroed block; any recorded ALPN buffer is
            // released here before the enclosing block.
            unsafe {
                let s = crate::ssl::adv_alloc::zeroed_ssl();
                assert!(!s.is_null());
                let _ = tls_process_encrypted_extensions(s, &ee);
                let mut data: *const u8 = core::ptr::null();
                let mut len: c_uint = 0;
                SSL_get0_alpn_selected(s, &mut data, &mut len);
                if !data.is_null() {
                    CRYPTO_free(data.cast_mut().cast(), core::ptr::null(), 0);
                }
                CRYPTO_free(s.cast(), core::ptr::null(), 0);
            }

            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut list = good_cert_list.clone();
            let at = (state as usize) % list.len();
            list[at] ^= ((state >> 32) as u8) | 0x01;
            let mut cur = SliceCursor::new(&list);
            while cur.remaining() >= 3 {
                let Some((_der, _exts)) = read_tls13_certificate_entry(&mut cur) else {
                    break;
                };
            }
        }
    }
}

// -------------------------------------------------------------------------------------------
// TLS1.2 server flight: ServerKeyExchange, CertificateVerify, CertificateStatus framing
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod tls12_server_flight_parse {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::{
        read_cert_status_response, read_cert_verify_layout, read_server_ecdh_params,
        CertStatusReject,
    };

    const CURVE_TYPE_NAMED: u8 = 3;
    const GROUP_P256: u16 = 23;
    const GROUP_X25519: u16 = 29;
    const SIGALG_ECDSA_SHA256: u16 = 0x0403;

    /// `ServerECDHParams || sig_alg || sig_len || sig`, with separately supplied declared
    /// lengths so the malformed cases can disagree with the actual bytes.
    fn ske_body(
        curve_type: u8,
        group: u16,
        point: &[u8],
        declared_ptlen: Option<u8>,
        sigalg: u16,
        sig: &[u8],
        declared_siglen: Option<u16>,
    ) -> Vec<u8> {
        let mut body = vec![curve_type];
        body.extend_from_slice(&group.to_be_bytes());
        body.push(declared_ptlen.unwrap_or(point.len() as u8));
        body.extend_from_slice(point);
        body.extend_from_slice(&sigalg.to_be_bytes());
        body.extend_from_slice(&declared_siglen.unwrap_or(sig.len() as u16).to_be_bytes());
        body.extend_from_slice(sig);
        body
    }

    fn p256_point() -> Vec<u8> {
        let mut point = vec![0x04];
        point.extend((0..64u8).map(|i| i.wrapping_mul(3)));
        point
    }

    fn x25519_point() -> Vec<u8> {
        (0..32u8).map(|i| 0x80 ^ i).collect()
    }

    #[test]
    fn valid_p256_ske_reports_the_signed_params_extent() {
        let point = p256_point();
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let body = ske_body(
            CURVE_TYPE_NAMED,
            GROUP_P256,
            &point,
            None,
            SIGALG_ECDSA_SHA256,
            &sig,
            None,
        );
        let parsed = read_server_ecdh_params(&body).expect("a well-formed P-256 SKE parses");
        assert_eq!(parsed.group, GROUP_P256);
        assert_eq!(parsed.point, &point[..]);
        assert_eq!(parsed.sigalg, SIGALG_ECDSA_SHA256);
        assert_eq!(parsed.sig, &sig[..]);
        // The signed extent is exactly `curve_type || named_curve || point_len || point`.
        assert_eq!(parsed.params.len(), 4 + point.len());
        assert_eq!(parsed.params, &body[..4 + point.len()]);
    }

    #[test]
    fn valid_x25519_ske_parses() {
        let point = x25519_point();
        let sig = [0xaa; 64];
        let body = ske_body(
            CURVE_TYPE_NAMED,
            GROUP_X25519,
            &point,
            None,
            SIGALG_ECDSA_SHA256,
            &sig,
            None,
        );
        let parsed = read_server_ecdh_params(&body).expect("a well-formed X25519 SKE parses");
        assert_eq!(parsed.group, GROUP_X25519);
        assert_eq!(parsed.point, &point[..]);
        assert_eq!(parsed.params.len(), 4 + point.len());
    }

    #[test]
    fn point_length_overrunning_the_body_is_refused() {
        // Declares 200 point bytes but supplies four bytes followed by the signature fields.
        let body = ske_body(
            CURVE_TYPE_NAMED,
            GROUP_P256,
            &[0x04, 0x01, 0x02, 0x03],
            Some(200),
            SIGALG_ECDSA_SHA256,
            &[0u8; 8],
            None,
        );
        assert!(
            read_server_ecdh_params(&body).is_none(),
            "a point length that overruns the params must be refused"
        );
    }

    #[test]
    fn non_named_curve_type_is_refused() {
        let body = ske_body(1, GROUP_P256, &p256_point(), None, 0x0401, &[0u8; 8], None);
        assert!(read_server_ecdh_params(&body).is_none());
    }

    #[test]
    fn signature_length_overrunning_the_body_is_refused() {
        let point = p256_point();
        let body = ske_body(
            CURVE_TYPE_NAMED,
            GROUP_P256,
            &point,
            None,
            SIGALG_ECDSA_SHA256,
            &[0x30, 0x02],
            Some(0xffff),
        );
        assert!(read_server_ecdh_params(&body).is_none());
    }

    #[test]
    fn valid_cert_verify_extent_is_exact() {
        let sig = [0x30, 0x04, 0x02, 0x02, 0x11, 0x22];
        let mut body = SIGALG_ECDSA_SHA256.to_be_bytes().to_vec();
        body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        body.extend_from_slice(&sig);
        let parsed = read_cert_verify_layout(&body).expect("a complete CertificateVerify parses");
        assert_eq!(parsed.sigalg, SIGALG_ECDSA_SHA256);
        assert_eq!(parsed.sig, &sig[..]);
    }

    #[test]
    fn truncated_cert_verify_signature_is_refused() {
        let mut body = SIGALG_ECDSA_SHA256.to_be_bytes().to_vec();
        body.extend_from_slice(&64u16.to_be_bytes());
        body.extend_from_slice(&[0x30, 0x04]); // only two of the declared 64 bytes
        assert!(read_cert_verify_layout(&body).is_none());

        // A body shorter than the four-byte prefix is also refused, not split.
        assert!(read_cert_verify_layout(&[0x04, 0x03, 0x00]).is_none());
    }

    #[test]
    fn zero_length_cert_status_response_is_accepted() {
        let body = [1u8, 0, 0, 0];
        let response =
            read_cert_status_response(&body, 1).expect("a zero length response is valid");
        assert!(response.is_empty());
    }

    #[test]
    fn cert_status_u24_overrun_is_a_bad_response() {
        let body = [1u8, 0, 0, 10, 0xaa];
        assert!(matches!(
            read_cert_status_response(&body, 1),
            Err(CertStatusReject::BadResponse)
        ));
    }

    #[test]
    fn cert_status_trailing_bytes_disagreeing_with_the_length_are_refused() {
        let body = [1u8, 0, 0, 1, 0xaa, 0xbb];
        assert!(matches!(
            read_cert_status_response(&body, 1),
            Err(CertStatusReject::BadResponse)
        ));
    }

    #[test]
    fn unsupported_status_type_is_a_bad_response() {
        let body = [2u8, 0, 0, 0];
        assert!(matches!(
            read_cert_status_response(&body, 1),
            Err(CertStatusReject::BadResponse)
        ));
    }

    #[test]
    fn cert_status_shorter_than_its_prefix_is_a_decode_error() {
        assert!(matches!(
            read_cert_status_response(&[1u8, 0, 0], 1),
            Err(CertStatusReject::Decode)
        ));
        assert!(matches!(
            read_cert_status_response(&[], 1),
            Err(CertStatusReject::Decode)
        ));
    }

    /// Deterministic seeded mutation of the three TLS1.2 server-flight parsers: every entry
    /// point must answer `None`/`Err` rather than panic or read outside the frame.
    #[test]
    fn malformed_tls12_server_flight_loop_does_not_panic() {
        let point = p256_point();
        let good_ske = ske_body(
            CURVE_TYPE_NAMED,
            GROUP_P256,
            &point,
            None,
            SIGALG_ECDSA_SHA256,
            &[0x30; 16],
            None,
        );
        let mut good_cv = SIGALG_ECDSA_SHA256.to_be_bytes().to_vec();
        good_cv.extend_from_slice(&16u16.to_be_bytes());
        good_cv.extend_from_slice(&[0x30; 16]);
        let good_status = [1u8, 0, 0, 4, 0x01, 0x02, 0x03, 0x04];

        let mut state = 0xA5A5_5A5A_1234_5678u64;
        for _ in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut ske = good_ske.clone();
            let edits = 1 + (state as usize % 3);
            for i in 0..edits {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let at = (state as usize) % ske.len();
                ske[at] ^= (state >> 32) as u8 | (i as u8 + 1);
            }
            let _ = read_server_ecdh_params(&ske);

            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut cv = good_cv.clone();
            let at = (state as usize) % cv.len();
            cv[at] ^= ((state >> 32) as u8) | 1;
            let _ = read_cert_verify_layout(&cv);

            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut status = good_status.to_vec();
            let at = (state as usize) % status.len();
            status[at] ^= ((state >> 32) as u8) | 1;
            let _ = read_cert_status_response(&status, 1);
        }
    }
}

#[cfg(test)]
mod certificate_request_sigalgs {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::evp::pkey::{openssl_rs_evp_pkey_q_keygen, EVP_PKEY_free, EvpPkey};
    use crate::runtime::bio::{bss_mem::BIO_s_mem, BIO_new};
    use crate::runtime::err::{ERR_clear_error, ERR_get_error};
    use crate::runtime::obj as o;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new};
    use crate::ssl::ssl_rsa::{SSL_use_PrivateKey, SSL_use_certificate};
    use crate::x509::x_x509::{X509_free, X509_new, X509};
    use core::ffi::c_int;

    const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

    fn extension(etype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = etype.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// `type || u24(body_len) || body`.
    fn framed(mt: c_int, body: &[u8]) -> Vec<u8> {
        let mut msg = vec![mt as u8];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(body);
        msg
    }

    /// TLS1.3 `CertificateRequest`: `context<1> || extensions<2>`.
    fn cr_tls13(exts: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);
        framed(SSL3_MT_CERTIFICATE_REQUEST, &body)
    }

    /// TLS1.2 `CertificateRequest`: `ctypes<1> || sigalgs<2> || CA names<2>`.
    fn cr_tls12(sigalgs: &[u8]) -> Vec<u8> {
        let mut body = vec![1u8, 64u8];
        body.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
        body.extend_from_slice(sigalgs);
        body.extend_from_slice(&0u16.to_be_bytes());
        framed(SSL3_MT_CERTIFICATE_REQUEST, &body)
    }

    /// A provider EC identity on `nid`'s curve, self-signed under SHA-256.
    ///
    /// # Safety
    /// The caller owns both objects and releases them with `EVP_PKEY_free`/`X509_free`.
    unsafe fn ec_identity(nid: c_int) -> (*mut EvpPkey, *mut X509) {
        use crate::asn1::layout::MBSTRING_UTF8;
        use crate::asn1::prim::ASN1_INTEGER_set;
        use crate::evp::legacy_sha::EVP_sha256;
        use crate::x509::x509_set::{
            X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name, X509_set_version,
        };
        use crate::x509::x509_vfy::X509_gmtime_adj;
        use crate::x509::x509name::X509_NAME_add_entry_by_txt;
        use crate::x509::x_all::X509_sign;
        use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};
        let group = match nid {
            o::NID_secp384r1 => c"P-384",
            o::NID_secp521r1 => c"P-521",
            _ => c"P-256",
        };
        // SAFETY: constructors below answer fresh objects owned by this frame.
        unsafe {
            let pkey = openssl_rs_evp_pkey_q_keygen(
                core::ptr::null_mut(),
                core::ptr::null(),
                c"EC".as_ptr(),
                2,
                0,
                group.as_ptr(),
            );
            assert!(!pkey.is_null(), "curve {nid} must create a key");
            let x = X509_new();
            let name = X509_NAME_new();
            assert!(!x.is_null() && !name.is_null());
            assert_eq!(
                X509_NAME_add_entry_by_txt(
                    name,
                    c"CN".as_ptr(),
                    MBSTRING_UTF8,
                    c"client.test".as_ptr().cast::<u8>(),
                    11,
                    -1,
                    0,
                ),
                1
            );
            assert_eq!(X509_set_version(x, 2), 1);
            assert_eq!(ASN1_INTEGER_set(&mut (*x).cert_info.serialNumber, 1), 1);
            assert_eq!(X509_set_subject_name(x, name), 1);
            assert_eq!(X509_set_issuer_name(x, name), 1);
            (*x).cert_info.validity.notBefore = X509_gmtime_adj(core::ptr::null_mut(), 0);
            (*x).cert_info.validity.notAfter = X509_gmtime_adj(core::ptr::null_mut(), 86_400);
            assert!(!(*x).cert_info.validity.notBefore.is_null());
            assert!(!(*x).cert_info.validity.notAfter.is_null());
            assert_eq!(X509_set_pubkey(x, pkey), 1);
            assert!(X509_sign(x, pkey, EVP_sha256()) > 0);
            X509_NAME_free(name);
            (pkey, x)
        }
    }

    fn drain_reasons() -> Vec<c_int> {
        let mut v = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            v.push((e & 0x7f_ffff) as c_int);
        }
        v
    }

    /// # Safety
    /// The connection must be live and own a certificate installed by this test.
    unsafe fn saved(s: *mut Ssl) -> Vec<u16> {
        // SAFETY: `s` is live; a saved list is `peer_sigalgslen` live `u16`s.
        let (p, n) = unsafe { ((*s).peer_sigalgs, (*s).peer_sigalgslen) };
        if p.is_null() || n == 0 {
            Vec::new()
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts(p, n) }.to_vec()
        }
    }

    /// The TLS1.3 request's `signature_algorithms` is saved, so the certificate constructor can
    /// check that its scheme was offered.
    #[test]
    fn tls13_request_saves_sigalgs() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            ERR_clear_error();
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            let msg = cr_tls13(&extension(13, &[0x00, 0x02, 0x05, 0x03]));
            assert_eq!(tls_process_certificate_request(s, &msg), 1);
            assert_eq!(saved(s), vec![0x0503]);
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// A request with no `signature_algorithms` falls back to the list this client advertises —
    /// the authority's defaults arm (`tls_choose_sigalg`, `t1_lib.c:4685-4713`).
    #[test]
    fn tls13_request_without_sigalgs_uses_the_defaults() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            ERR_clear_error();
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            assert_eq!(tls_process_certificate_request(s, &cr_tls13(&[])), 1);
            assert_eq!(
                saved(s),
                crate::ssl::statem::extensions_clnt::CLIENT_SIGALGS.to_vec()
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// A malformed vector is refused and the incumbent list is untouched (`tls1_save_u16` parses
    /// before it stores).
    #[test]
    fn tls13_malformed_sigalgs_is_refused_and_keeps_the_incumbent() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            ERR_clear_error();
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            let good = cr_tls13(&extension(13, &[0x00, 0x02, 0x05, 0x03]));
            assert_eq!(tls_process_certificate_request(s, &good), 1);
            // Odd list length.
            let bad = cr_tls13(&extension(13, &[0x00, 0x03, 0x05, 0x03, 0x00]));
            ERR_clear_error();
            assert_eq!(tls_process_certificate_request(s, &bad), 0);
            assert_eq!(saved(s), vec![0x0503], "the incumbent list survives");
            assert!(drain_reasons().contains(&110), "SSL_R_BAD_EXTENSION");
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// A P-256 client key with a request offering only P-384 cannot be signed: the authority's
    /// `SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM` (118). Offering the key's scheme succeeds.
    #[test]
    fn tls13_p256_client_key_requires_its_scheme_to_be_offered() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            let (pkey, x) = ec_identity(o::NID_X9_62_prime256v1);
            // Case 1: only P-384 offered.
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            assert_eq!(SSL_use_certificate(s, x), 1);
            assert_eq!(SSL_use_PrivateKey(s, pkey), 1);
            (*s).wbio = BIO_new(BIO_s_mem());
            assert!(!(*s).wbio.is_null());
            assert_eq!(
                crate::ssl::tls13_enc::tls13_setup_cipher(s, TLS_AES_128_GCM_SHA256),
                1
            );
            let only384 = cr_tls13(&extension(13, &[0x00, 0x02, 0x05, 0x03]));
            assert_eq!(tls_process_certificate_request(s, &only384), 1);
            ERR_clear_error();
            assert_eq!(
                crate::ssl::statem::statem_srvr::tls13_construct_cert_verify(s, false),
                0
            );
            assert!(
                drain_reasons().contains(&118),
                "SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM"
            );
            SSL_free(s);
            SSL_CTX_free(ctx);

            // Case 2: the key's own scheme is offered.
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            assert_eq!(SSL_use_certificate(s, x), 1);
            assert_eq!(SSL_use_PrivateKey(s, pkey), 1);
            (*s).wbio = BIO_new(BIO_s_mem());
            assert!(!(*s).wbio.is_null());
            assert_eq!(
                crate::ssl::tls13_enc::tls13_setup_cipher(s, TLS_AES_128_GCM_SHA256),
                1
            );
            let both = cr_tls13(&extension(13, &[0x00, 0x04, 0x05, 0x03, 0x04, 0x03]));
            assert_eq!(tls_process_certificate_request(s, &both), 1);
            ERR_clear_error();
            assert_eq!(
                crate::ssl::statem::statem_srvr::tls13_construct_cert_verify(s, false),
                1
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            X509_free(x);
        }
    }

    /// TLS1.2: the request's vector is saved and the client signer refuses a scheme that was not
    /// offered (`tls12_sign`'s `peer_sigalgs` membership test).
    #[test]
    fn tls12_client_signer_uses_the_requested_scheme() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            let (pkey, x) = ec_identity(o::NID_X9_62_prime256v1);
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            assert_eq!(SSL_use_certificate(s, x), 1);
            assert_eq!(SSL_use_PrivateKey(s, pkey), 1);
            let mut sig = [0u8; 512];

            let only384 = cr_tls12(&[0x05, 0x03]);
            ERR_clear_error();
            assert_eq!(tls12_process_certificate_request(s, &only384), 1);
            assert_eq!(saved(s), vec![0x0503]);
            assert!(crate::ssl::statem::statem_srvr::tls12_sign(s, b"tbs", &mut sig).is_none());

            let offered = cr_tls12(&[0x04, 0x03]);
            assert_eq!(tls12_process_certificate_request(s, &offered), 1);
            assert_eq!(saved(s), vec![0x0403]);
            assert_eq!(
                crate::ssl::statem::statem_srvr::tls12_sign(s, b"tbs", &mut sig).map(|(a, _)| a),
                Some(0x0403)
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            X509_free(x);
        }
    }

    /// The TLS1.2 reader refuses a truncated signature-algorithm vector.
    #[test]
    fn tls12_truncated_sigalgs_is_refused() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is this test's own.
        unsafe {
            ERR_clear_error();
            let ctx = SSL_CTX_new(TLS_method());
            let s = SSL_new(ctx);
            assert!(!ctx.is_null() && !s.is_null());
            // Declared 4 bytes, only 2 present, and the message ends there (a following field
            // would supply the two missing bytes, exactly as the authority's packet reader would
            // consume them).
            let mut body = vec![1u8, 64u8];
            body.extend_from_slice(&4u16.to_be_bytes());
            body.extend_from_slice(&[0x04, 0x03]);
            let msg = framed(SSL3_MT_CERTIFICATE_REQUEST, &body);
            assert_eq!(tls12_process_certificate_request(s, &msg), 0);
            assert_eq!(saved(s), Vec::<u16>::new());
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }
}
