//! Phase 16.5 — `ssl/statem/statem_srvr.c`: the server half of the TLS message
//! layer, reduced at the message-construction boundary.
//!
//! Phase 14.5b landed the state machine's control surface and driver
//! ([`crate::ssl::statem::statem`]) but not the server message construction and
//! parsing, so no flight was built or parsed on the server side. 16.5 lands the
//! **transition surface** this file owns: `ossl_statem_server_read_transition`
//! (the parser's decision that a given message type can follow the current hand
//! state) and `ossl_statem_server_write_transition` (the constructor's decision
//! what message to build next), for both TLS1.2 and TLS1.3, plus
//! `ossl_statem_server_max_message_size`, `send_certificate_request`,
//! `send_server_key_exchange` and the `received_client_cert` predicate.
//!
//! ## What is landed, and where the unit stops
//!
//! Every read/write transition arm that reads only the connection's own state is
//! transcribed, and so are the two selection predicates the TLS1.2 write
//! transition reads. **17.2b** lands the server's first-flight message bodies: the
//! reduced `tls_process_client_hello` (the version/cipher/group selection over a
//! reduced plaintext record read) and `tls_construct_server_hello` (the
//! `supported_versions` + `X25519` key share block), plus `write_server_hello`.
//! The **remaining message bodies** -- `tls_construct_encrypted_extensions`,
//! `tls_construct_certificate`, the key schedule and their siblings -- are still
//! not landed: they build bytes through the key schedule (`ssl/t1_enc.c`/
//! `tls13_enc.c`) and the certificate flight, neither of which is landed. See
//! `docs/PHASE-17-SUBPHASES.md`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The message bodies past the ServerHello are the boundary.**
//!   `tls_process_client_hello` is reduced to the fresh-connection fields the
//!   ServerHello reads (the session cache, resumption, the `CLIENTHELLO_MSG`
//!   extension framework and the `SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION` check
//!   are not modelled), and `tls_construct_server_hello` stops before `ssl_derive`
//!   (the key schedule).
//! * **The DTLS arms are unreachable.** Every object this crate builds is a TLS
//!   method, so `SSL_CONNECTION_IS_DTLS` is false at every reachable entry and the
//!   `d1->cookie_verified` / `DTLS_ST_SW_HELLO_VERIFY_REQUEST` arm is not taken.
//! * **The timestamp writes are omitted.** `s->ts_msg_read = ossl_time_now()` and
//!   its write sibling are skipped; `ossl_time_now` is `crypto/time.c`'s unit and
//!   the word is not observable through any court.
//! * **`tls_setup_handshake` is the boundary.** The TLS1.2 write transition's
//!   renegotiation entry calls it (`statem_lib.c`); the call is the boundary and
//!   the transition reports the authority's error return.
//! * **`received_client_cert` is reduced at the session boundary.** A fresh
//!   connection has no session, so both peer pointers are NULL and the answer is
//!   false — the value the TLS1.3 read transition's arms read.
//! * **The plain-PSK identity-hint arm of `send_server_key_exchange` is reduced.**
//!   It reads `s->cert->psk_identity_hint`, a certificate-context field this
//!   stratum does not own; the DHE/ECDHE/PSK-ephemeral/SRP arms are transcribed.
//!
//! SPDX-License-Identifier: Apache-2.0

// The transition functions mirror the authority's `switch`/nested-`if` shape arm for arm;
// collapsing an arm into a match guard would obscure the correspondence.
#![allow(clippy::collapsible_match)]

use core::ffi::{c_int, c_uint};

use crate::packet::Wpacket;
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::statem::statem::{ossl_statem_fatal, ossl_statem_in_error};

// --- hand states (`include/openssl/ssl.h`) -----------------------------------
const TLS_ST_BEFORE: c_int = 0;
const TLS_ST_OK: c_int = 1;
const TLS_ST_SR_CLNT_HELLO: c_int = 22;
const TLS_ST_SW_SRVR_HELLO: c_int = 24;
const TLS_ST_SW_CERT: c_int = 25;
const TLS_ST_SW_COMP_CERT: c_int = 26;
const TLS_ST_SW_KEY_EXCH: c_int = 27;
const TLS_ST_SW_CERT_REQ: c_int = 28;
const TLS_ST_SW_SRVR_DONE: c_int = 29;
const TLS_ST_SR_CERT: c_int = 30;
const TLS_ST_SR_COMP_CERT: c_int = 31;
const TLS_ST_SR_KEY_EXCH: c_int = 32;
const TLS_ST_SR_CERT_VRFY: c_int = 33;
const TLS_ST_SR_NEXT_PROTO: c_int = 34;
const TLS_ST_SR_CHANGE: c_int = 35;
const TLS_ST_SR_FINISHED: c_int = 36;
const TLS_ST_SW_SESSION_TICKET: c_int = 37;
const TLS_ST_SW_CERT_STATUS: c_int = 38;
const TLS_ST_SW_CHANGE: c_int = 39;
const TLS_ST_SW_FINISHED: c_int = 40;
const TLS_ST_SW_ENCRYPTED_EXTENSIONS: c_int = 41;
const TLS_ST_SW_HELLO_REQ: c_int = 21;
const TLS_ST_EARLY_DATA: c_int = 50;
const TLS_ST_SR_END_OF_EARLY_DATA: c_int = 53;
const TLS_ST_SR_KEY_UPDATE: c_int = 48;
const TLS_ST_SW_KEY_UPDATE: c_int = 46;
const TLS_ST_SW_CERT_VRFY: c_int = 44;

// --- message types (`include/openssl/ssl3.h`) --------------------------------
const SSL3_MT_CLIENT_HELLO: c_int = 1;
const SSL3_MT_CERTIFICATE: c_int = 11;
const SSL3_MT_CLIENT_KEY_EXCHANGE: c_int = 16;
const SSL3_MT_CERTIFICATE_VERIFY: c_int = 15;
const SSL3_MT_END_OF_EARLY_DATA: c_int = 5;
const SSL3_MT_FINISHED: c_int = 20;
const SSL3_MT_KEY_UPDATE: c_int = 24;
const SSL3_MT_COMPRESSED_CERTIFICATE: c_int = 25;
const SSL3_MT_NEXT_PROTO: c_int = 67;
const SSL3_MT_CHANGE_CIPHER_SPEC: c_int = 0x0101;

// --- alerts / reasons --------------------------------------------------------
const SSL_AD_INTERNAL_ERROR: c_int = 80;
const SSL_AD_UNEXPECTED_MESSAGE: c_int = 10;
const SSL_AD_HANDSHAKE_FAILURE: c_int = 40;
/// `TLS1_AD_UNRECOGNIZED_NAME` — `tls1.h:76` (the alert `final_server_name` arms with).
const SSL_AD_UNRECOGNIZED_NAME: c_int = 112;
/// `TLS1_AD_DECODE_ERROR` — `tls1.h:61`.
const SSL_AD_DECODE_ERROR: c_int = 50;
/// `SSL_R_BAD_EXTENSION` — `sslerr.h:38`.
const SSL_R_BAD_EXTENSION: c_int = 110;
/// `SSL_R_CALLBACK_FAILED` — `sslerr.h:66`.
const SSL_R_CALLBACK_FAILED: c_int = 234;
/// `SSL_RECEIVED_SHUTDOWN` — `ssl.h:217` (set by a received `close_notify`, `rec_layer_s3.c:913`).
const SSL_RECEIVED_SHUTDOWN: c_int = 2;
const ERR_R_INTERNAL_ERROR: c_int = 259 | (2 << 18) | (1 << 18);
const SSL_R_UNEXPECTED_MESSAGE: c_int = 245;
const SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE: c_int = 205;
/// `SSL_CLIENT_HELLO_SUCCESS` — `ssl.h:1914`.
const SSL_CLIENT_HELLO_SUCCESS: c_int = 1;
/// `SSL_CLIENT_HELLO_RETRY` — `ssl.h:1916`.
const SSL_CLIENT_HELLO_RETRY: c_int = -1;
/// `SSL_CLIENT_HELLO_CB` — `ssl.h:915` (the `SSL_CLIENT_HELLO_CB` want value).
const SSL_CLIENT_HELLO_CB: c_int = 7;

// --- connection flags --------------------------------------------------------
const SSL3_VERSION: c_int = 0x0300;
const TLS1_3_VERSION: c_int = 0x0304;
const DTLS1_VERSION_MAJOR: c_int = 0xFE;
const SSL_PHA_REQUESTED: c_int = 4;
const SSL_PHA_REQUEST_PENDING: c_int = 3;
const SSL_KEY_UPDATE_NONE: c_int = -1;
const SSL_HRR_PENDING: c_int = 1;
const SSL_HRR_COMPLETE: c_int = 2;
const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 1 << 20;
const SSL_VERIFY_PEER: c_int = 1;
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 2;
const SSL_VERIFY_CLIENT_ONCE: c_int = 4;
const SSL_VERIFY_POST_HANDSHAKE: c_int = 8;

// --- transition return codes (`include/internal/statem.h`) --------------------
const WRITE_TRAN_ERROR: c_int = 0;
const WRITE_TRAN_CONTINUE: c_int = 1;
const WRITE_TRAN_FINISHED: c_int = 2;

// --- server-name extension (`tls1.h`) ----------------------------------------
/// `TLSEXT_TYPE_server_name` — `tls1.h:140`.
const TLSEXT_TYPE_SERVERNAME: u16 = 0;
/// `TLSEXT_NAMETYPE_host_name` — `tls1.h:171`.
const TLSEXT_NAMETYPE_HOST_NAME: u8 = 0;
/// `TLSEXT_MAXLEN_host_name` — `tls1.h:172`.
const TLSEXT_MAXLEN_HOST_NAME: usize = 255;
/// `SSL_TLSEXT_ERR_ALERT_WARNING` — `tls1.h:338`.
const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
/// `SSL_TLSEXT_ERR_ALERT_FATAL` — `tls1.h:339`.
const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
/// `SSL_TLSEXT_ERR_NOACK` — `tls1.h:340`.
const SSL_TLSEXT_ERR_NOACK: c_int = 3;

// --- message length caps (`ssl/statem/statem_local.h`, `statem_srvr.c`) -------
const CLIENT_HELLO_MAX_LENGTH: usize = 131396;
const CLIENT_KEY_EXCH_MAX_LENGTH: usize = 2048;
const CERTIFICATE_VERIFY_MAX_LENGTH: usize = 65539;
const NEXT_PROTO_MAX_LENGTH: usize = 514;
const CCS_MAX_LENGTH: usize = 1;
const FINISHED_MAX_LENGTH: usize = 64;
const KEY_UPDATE_MAX_LENGTH: usize = 1;
const END_OF_EARLY_DATA_MAX_LENGTH: usize = 0;

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

#[inline]
fn is_first_handshake(s: *const Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe { (*s).s3_tmp_finish_md_len == 0 }
}

/// `static ossl_inline int received_client_cert(const SSL_CONNECTION *sc)` —
/// `statem_srvr.c:56-59`, reduced at the session boundary (module header).
fn received_client_cert(_s: *const Ssl) -> bool {
    false
}

/// `static CON_FUNC_RETURN tls_construct_encrypted_extensions(...)` is unlanded;
/// the TLS1.3 write transition reports the boundary through this constant.
fn do_compressed_cert(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe { (*s).ext_client_cert_type == 1 && (*s).ext_compress_certificate_from_peer_0 != 0 }
}

/// `int send_certificate_request(SSL_CONNECTION *s)` — `statem_srvr.c:416-456`.
fn send_certificate_request(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        let c = (*s).pending_cipher;
        let auth = if c.is_null() {
            0
        } else {
            (*c).algorithm_auth as u64
        };
        if ((*s).verify_mode & SSL_VERIFY_PEER) != 0
            && (!is_tls13(s)
                || ((*s).verify_mode & SSL_VERIFY_POST_HANDSHAKE) == 0
                || (*s).post_handshake_auth == SSL_PHA_REQUEST_PENDING)
            && ((*s).certreqs_sent < 1 || ((*s).verify_mode & SSL_VERIFY_CLIENT_ONCE) == 0)
            && ((auth & t::SSL_aNULL) == 0
                || ((*s).verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0)
            && (auth & t::SSL_aSRP) == 0
            && (auth & t::SSL_aPSK) == 0
        {
            return true;
        }
    }
    false
}

/// `static int send_server_key_exchange(SSL_CONNECTION *s)` — `statem_srvr.c:353-386`,
/// the plain-PSK identity-hint arm reduced (module header).
fn send_server_key_exchange(s: *mut Ssl) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        let c = (*s).pending_cipher;
        if c.is_null() {
            return false;
        }
        let k = (*c).algorithm_mkey as u64;
        (k & (t::SSL_kDHE | t::SSL_kECDHE)) != 0
            || (k & (t::SSL_kDHEPSK | t::SSL_kECDHEPSK)) != 0
            || (k & t::SSL_kSRP) != 0
    }
}

/// `static int ossl_statem_server13_read_transition(SSL_CONNECTION *s, int mt)` —
/// `statem_srvr.c:70-175`.
fn server13_read_transition(s: *mut Ssl, mt: c_int) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        match (*s).hand_state {
            TLS_ST_EARLY_DATA => {
                if (*s).hello_retry_request == SSL_HRR_PENDING {
                    if mt == SSL3_MT_CLIENT_HELLO {
                        (*s).hand_state = TLS_ST_SR_CLNT_HELLO;
                        return true;
                    }
                } else if (*s).ext_early_data == 2 {
                    if mt == SSL3_MT_END_OF_EARLY_DATA {
                        (*s).hand_state = TLS_ST_SR_END_OF_EARLY_DATA;
                        return true;
                    }
                } else {
                    return server13_cert_or_finished(s, mt);
                }
            }
            TLS_ST_SR_END_OF_EARLY_DATA | TLS_ST_SW_FINISHED => {
                return server13_cert_or_finished(s, mt);
            }
            TLS_ST_SR_COMP_CERT | TLS_ST_SR_CERT => {
                if !received_client_cert(s) {
                    if mt == SSL3_MT_FINISHED {
                        (*s).hand_state = TLS_ST_SR_FINISHED;
                        return true;
                    }
                } else if mt == SSL3_MT_CERTIFICATE_VERIFY {
                    (*s).hand_state = TLS_ST_SR_CERT_VRFY;
                    return true;
                }
            }
            TLS_ST_SR_CERT_VRFY => {
                if mt == SSL3_MT_FINISHED {
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                    return true;
                }
            }
            TLS_ST_OK => {
                if (*s).early_data_state == 11 {
                    // SSL_EARLY_DATA_READING
                    return false;
                }
                if (*s).post_handshake_auth == SSL_PHA_REQUESTED {
                    if mt == SSL3_MT_CERTIFICATE {
                        (*s).hand_state = TLS_ST_SR_CERT;
                        return true;
                    }
                    if mt == SSL3_MT_COMPRESSED_CERTIFICATE
                        && (*s).ext_compress_certificate_sent != 0
                    {
                        (*s).hand_state = TLS_ST_SR_COMP_CERT;
                        return true;
                    }
                }
                if mt == SSL3_MT_KEY_UPDATE {
                    (*s).hand_state = TLS_ST_SR_KEY_UPDATE;
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// The `cert_request ? (compressed ? COMP_CERT : CERT) : FINISHED` step shared by
/// the TLS1.3 server read transition (`statem_srvr.c:100-120`).
fn server13_cert_or_finished(s: *mut Ssl, mt: c_int) -> bool {
    // SAFETY: the caller passes a live connection.
    unsafe {
        if (*s).s3_tmp_cert_request != 0 {
            if mt == SSL3_MT_CERTIFICATE {
                (*s).hand_state = TLS_ST_SR_CERT;
                return true;
            }
            if mt == SSL3_MT_COMPRESSED_CERTIFICATE && (*s).ext_compress_certificate_sent != 0 {
                (*s).hand_state = TLS_ST_SR_COMP_CERT;
                return true;
            }
        } else if mt == SSL3_MT_FINISHED {
            (*s).hand_state = TLS_ST_SR_FINISHED;
            return true;
        }
    }
    false
}

/// `int ossl_statem_server_read_transition(SSL_CONNECTION *s, int mt)` —
/// `statem_srvr.c:186-344`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_server_read_transition(s: *mut Ssl, mt: c_int) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if is_tls13(s) {
            if !server13_read_transition(s, mt) {
                ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                return 0;
            }
            return 1;
        }

        match (*s).hand_state {
            TLS_ST_BEFORE | TLS_ST_OK => {
                if mt == SSL3_MT_CLIENT_HELLO {
                    (*s).hand_state = TLS_ST_SR_CLNT_HELLO;
                    return 1;
                }
            }
            TLS_ST_SW_SRVR_DONE => {
                if mt == SSL3_MT_CLIENT_KEY_EXCHANGE {
                    if (*s).s3_tmp_cert_request != 0 {
                        if (*s).version == SSL3_VERSION
                            && ((*s).verify_mode & SSL_VERIFY_PEER) != 0
                            && ((*s).verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) != 0
                        {
                            ossl_statem_fatal(
                                s,
                                SSL_AD_HANDSHAKE_FAILURE,
                                SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE,
                            );
                            return 0;
                        }
                        if (*s).version == SSL3_VERSION {
                            (*s).hand_state = TLS_ST_SR_KEY_EXCH;
                            return 1;
                        }
                    } else {
                        (*s).hand_state = TLS_ST_SR_KEY_EXCH;
                        return 1;
                    }
                } else if (*s).s3_tmp_cert_request != 0 && mt == SSL3_MT_CERTIFICATE {
                    (*s).hand_state = TLS_ST_SR_CERT;
                    return 1;
                }
            }
            TLS_ST_SR_CERT => {
                if mt == SSL3_MT_CLIENT_KEY_EXCHANGE {
                    (*s).hand_state = TLS_ST_SR_KEY_EXCH;
                    return 1;
                }
            }
            TLS_ST_SR_KEY_EXCH => {
                if !received_client_cert(s) || (*s).statem_no_cert_verify != 0 {
                    if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                        (*s).hand_state = TLS_ST_SR_CHANGE;
                        return 1;
                    }
                } else if mt == SSL3_MT_CERTIFICATE_VERIFY {
                    (*s).hand_state = TLS_ST_SR_CERT_VRFY;
                    return 1;
                }
            }
            TLS_ST_SR_CERT_VRFY => {
                if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                    (*s).hand_state = TLS_ST_SR_CHANGE;
                    return 1;
                }
            }
            TLS_ST_SR_CHANGE => {
                if (*s).s3_npn_seen != 0 {
                    if mt == SSL3_MT_NEXT_PROTO {
                        (*s).hand_state = TLS_ST_SR_NEXT_PROTO;
                        return 1;
                    }
                } else if mt == SSL3_MT_FINISHED {
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                    return 1;
                }
            }
            TLS_ST_SR_NEXT_PROTO => {
                if mt == SSL3_MT_FINISHED {
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                    return 1;
                }
            }
            TLS_ST_SW_FINISHED => {
                if mt == SSL3_MT_CHANGE_CIPHER_SPEC {
                    (*s).hand_state = TLS_ST_SR_CHANGE;
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

/// `static WRITE_TRAN ossl_statem_server13_write_transition(SSL_CONNECTION *s)` —
/// `statem_srvr.c:612-745`.
fn server13_write_transition(s: *mut Ssl) -> c_int {
    // SAFETY: the caller passes a live connection.
    unsafe {
        match (*s).hand_state {
            TLS_ST_OK => {
                if (*s).key_update != SSL_KEY_UPDATE_NONE {
                    (*s).hand_state = TLS_ST_SW_KEY_UPDATE;
                    return WRITE_TRAN_CONTINUE;
                }
                if (*s).post_handshake_auth == SSL_PHA_REQUEST_PENDING {
                    (*s).hand_state = TLS_ST_SW_CERT_REQ;
                    return WRITE_TRAN_CONTINUE;
                }
                if (*s).extra_tickets_expected > 0 {
                    (*s).hand_state = TLS_ST_SW_SESSION_TICKET;
                    return WRITE_TRAN_CONTINUE;
                }
                WRITE_TRAN_FINISHED
            }
            TLS_ST_SR_CLNT_HELLO => {
                (*s).hand_state = TLS_ST_SW_SRVR_HELLO;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_SRVR_HELLO => {
                if ((*s).options & SSL_OP_ENABLE_MIDDLEBOX_COMPAT) != 0
                    && (*s).hello_retry_request != SSL_HRR_COMPLETE
                {
                    (*s).hand_state = TLS_ST_SW_CHANGE;
                } else if (*s).hello_retry_request == SSL_HRR_PENDING {
                    (*s).hand_state = TLS_ST_EARLY_DATA;
                } else {
                    (*s).hand_state = TLS_ST_SW_ENCRYPTED_EXTENSIONS;
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CHANGE => {
                (*s).hand_state = if (*s).hello_retry_request == SSL_HRR_PENDING {
                    TLS_ST_EARLY_DATA
                } else {
                    TLS_ST_SW_ENCRYPTED_EXTENSIONS
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_ENCRYPTED_EXTENSIONS => {
                if (*s).hit != 0 {
                    (*s).hand_state = TLS_ST_SW_FINISHED;
                } else if send_certificate_request(s) {
                    (*s).hand_state = TLS_ST_SW_CERT_REQ;
                } else if do_compressed_cert(s) {
                    (*s).hand_state = TLS_ST_SW_COMP_CERT;
                } else {
                    (*s).hand_state = TLS_ST_SW_CERT;
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CERT_REQ => {
                if (*s).post_handshake_auth == SSL_PHA_REQUEST_PENDING {
                    (*s).post_handshake_auth = SSL_PHA_REQUESTED;
                    (*s).hand_state = TLS_ST_OK;
                } else if do_compressed_cert(s) {
                    (*s).hand_state = TLS_ST_SW_COMP_CERT;
                } else {
                    (*s).hand_state = TLS_ST_SW_CERT;
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_COMP_CERT | TLS_ST_SW_CERT => {
                (*s).hand_state = TLS_ST_SW_CERT_VRFY;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CERT_VRFY => {
                (*s).hand_state = TLS_ST_SW_FINISHED;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_FINISHED => {
                (*s).hand_state = TLS_ST_EARLY_DATA;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_EARLY_DATA => WRITE_TRAN_FINISHED,
            TLS_ST_SR_FINISHED => {
                if (*s).post_handshake_auth == SSL_PHA_REQUESTED {
                    (*s).post_handshake_auth = 2; // SSL_PHA_EXT_RECEIVED
                } else if (*s).ext_ticket_expected == 0 {
                    (*s).hand_state = TLS_ST_OK;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = if (*s).num_tickets > (*s).sent_tickets {
                    TLS_ST_SW_SESSION_TICKET
                } else {
                    TLS_ST_OK
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SR_KEY_UPDATE | TLS_ST_SW_KEY_UPDATE => {
                (*s).hand_state = TLS_ST_OK;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_SESSION_TICKET => {
                if !is_first_handshake(s) && (*s).extra_tickets_expected > 0 {
                    return WRITE_TRAN_CONTINUE;
                }
                if (*s).hit != 0 || (*s).num_tickets <= (*s).sent_tickets {
                    (*s).hand_state = TLS_ST_OK;
                }
                WRITE_TRAN_CONTINUE
            }
            _ => {
                ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                WRITE_TRAN_ERROR
            }
        }
    }
}

/// `WRITE_TRAN ossl_statem_server_write_transition(SSL_CONNECTION *s)` —
/// `statem_srvr.c:751-884`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_server_write_transition(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if is_tls13(s) {
            return server13_write_transition(s);
        }
        match (*s).hand_state {
            TLS_ST_OK => {
                if (*s).statem_request_state == TLS_ST_SW_HELLO_REQ {
                    (*s).hand_state = TLS_ST_SW_HELLO_REQ;
                    (*s).statem_request_state = TLS_ST_BEFORE;
                    return WRITE_TRAN_CONTINUE;
                }
                // `tls_setup_handshake` (`statem_lib.c`) is the boundary (module header).
                ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                WRITE_TRAN_ERROR
            }
            TLS_ST_BEFORE => WRITE_TRAN_FINISHED,
            TLS_ST_SW_HELLO_REQ => {
                (*s).hand_state = TLS_ST_OK;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SR_CLNT_HELLO => {
                // The DTLS cookie arm is unreachable (module header).
                if (*s).renegotiate == 0 && !is_first_handshake(s) {
                    (*s).hand_state = TLS_ST_OK;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = TLS_ST_SW_SRVR_HELLO;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_SRVR_HELLO => {
                if (*s).hit != 0 {
                    (*s).hand_state = if (*s).ext_ticket_expected != 0 {
                        TLS_ST_SW_SESSION_TICKET
                    } else {
                        TLS_ST_SW_CHANGE
                    };
                } else {
                    let c = (*s).pending_cipher;
                    let auth = if c.is_null() {
                        0
                    } else {
                        (*c).algorithm_auth as u64
                    };
                    if (auth & (t::SSL_aNULL | t::SSL_aSRP | t::SSL_aPSK)) == 0 {
                        (*s).hand_state = TLS_ST_SW_CERT;
                    } else if send_server_key_exchange(s) {
                        (*s).hand_state = TLS_ST_SW_KEY_EXCH;
                    } else if send_certificate_request(s) {
                        (*s).hand_state = TLS_ST_SW_CERT_REQ;
                    } else {
                        (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                    }
                }
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CERT => {
                if (*s).ext_status_expected != 0 {
                    (*s).hand_state = TLS_ST_SW_CERT_STATUS;
                    return WRITE_TRAN_CONTINUE;
                }
                if send_server_key_exchange(s) {
                    (*s).hand_state = TLS_ST_SW_KEY_EXCH;
                    return WRITE_TRAN_CONTINUE;
                }
                if send_certificate_request(s) {
                    (*s).hand_state = TLS_ST_SW_CERT_REQ;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CERT_STATUS => {
                if send_server_key_exchange(s) {
                    (*s).hand_state = TLS_ST_SW_KEY_EXCH;
                    return WRITE_TRAN_CONTINUE;
                }
                if send_certificate_request(s) {
                    (*s).hand_state = TLS_ST_SW_CERT_REQ;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_KEY_EXCH => {
                if send_certificate_request(s) {
                    (*s).hand_state = TLS_ST_SW_CERT_REQ;
                    return WRITE_TRAN_CONTINUE;
                }
                (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CERT_REQ => {
                (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_SRVR_DONE => WRITE_TRAN_FINISHED,
            TLS_ST_SR_FINISHED => {
                (*s).hand_state = if (*s).hit != 0 {
                    TLS_ST_OK
                } else if (*s).ext_ticket_expected != 0 {
                    TLS_ST_SW_SESSION_TICKET
                } else {
                    TLS_ST_SW_CHANGE
                };
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_SESSION_TICKET => {
                (*s).hand_state = TLS_ST_SW_CHANGE;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_CHANGE => {
                (*s).hand_state = TLS_ST_SW_FINISHED;
                WRITE_TRAN_CONTINUE
            }
            TLS_ST_SW_FINISHED => {
                if (*s).hit != 0 {
                    return WRITE_TRAN_FINISHED;
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

/// `size_t ossl_statem_server_max_message_size(SSL_CONNECTION *s)` —
/// `statem_srvr.c:1379-1418`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe fn ossl_statem_server_max_message_size(s: *mut Ssl) -> usize {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        match (*s).hand_state {
            TLS_ST_SR_CLNT_HELLO => CLIENT_HELLO_MAX_LENGTH,
            TLS_ST_SR_END_OF_EARLY_DATA => END_OF_EARLY_DATA_MAX_LENGTH,
            TLS_ST_SR_COMP_CERT | TLS_ST_SR_CERT => (*s).max_cert_list,
            TLS_ST_SR_KEY_EXCH => CLIENT_KEY_EXCH_MAX_LENGTH,
            TLS_ST_SR_CERT_VRFY => CERTIFICATE_VERIFY_MAX_LENGTH,
            TLS_ST_SR_NEXT_PROTO => NEXT_PROTO_MAX_LENGTH,
            TLS_ST_SR_CHANGE => CCS_MAX_LENGTH,
            TLS_ST_SR_FINISHED => FINISHED_MAX_LENGTH,
            TLS_ST_SR_KEY_UPDATE => KEY_UPDATE_MAX_LENGTH,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 17.2b — the server's first flight: `tls_process_client_hello` and
// `tls_construct_server_hello` (`statem_srvr.c:1648-1859`/`2590-2699`), reduced at the key schedule.
// ---------------------------------------------------------------------------------------------

/// `int final_server_name(SSL_CONNECTION *s, unsigned int context, int sent)` —
/// `ssl/statem/extensions.c:938-1040`, reduced to the callback dispatch and the fatal arm.
///
/// The authority runs this as the `server_name` extension's finalisation at the end of
/// `tls_parse_all_extensions` (`extensions.c:765-772`), after every ClientHello extension has been
/// parsed and before the cipher is chosen. It invokes the context's `ext.servername_cb` (falling
/// back to the session context's), then maps the return code to an alert or a plain success. The
/// session-hostname copy and the ticket-disable arms need a handshake session this slice does not
/// allocate, so they are recorded as the boundary rather than fabricated.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn final_server_name(s: *mut Ssl, sent: bool) -> c_int {
    let _ = sent;
    // SAFETY: `s` is live per the caller's contract; `ctx` is its context.
    let ctx = unsafe { (*s).ctx };
    let mut altmp = SSL_AD_UNRECOGNIZED_NAME;
    // SAFETY: `ctx` is the live context read above.
    let ret = match unsafe { (*ctx).servername_cb } {
        Some(cb) => {
            // SAFETY: the callback is the application's `int (*)(SSL *, int *, void *)`; `s`,
            // `altmp` and the stored argument are the ones it was installed to receive.
            unsafe { cb(s, &mut altmp, (*ctx).servername_arg) }
        }
        None => SSL_TLSEXT_ERR_NOACK,
    };
    match ret {
        SSL_TLSEXT_ERR_ALERT_FATAL => {
            // `extensions.c:1019-1021`.
            // SAFETY: `s` is live.
            unsafe { ossl_statem_fatal(s, altmp, SSL_R_CALLBACK_FAILED) };
            0
        }
        SSL_TLSEXT_ERR_ALERT_WARNING | SSL_TLSEXT_ERR_NOACK => 1,
        _ => 1,
    }
}

/// `SSL3_MT_SERVER_HELLO` — `ssl3.h`.
const SSL3_MT_SERVER_HELLO: u8 = 2;
/// `SSL3_MT_CLIENT_HELLO` — `ssl3.h`.
const SSL3_MT_CLIENT_HELLO_BODY: u8 = 1;
/// `TLS1_2_VERSION` — `ssl3.h` (the legacy ServerHello version, `statem_srvr.c:2599`).
const TLS1_2_VERSION: c_int = 0x0303;
/// `SSL3_RT_HANDSHAKE` — `ssl3.h` (22).
const SSL3_RT_HANDSHAKE: u8 = 22;
/// `TLSEXT_TYPE_supported_versions` — `tls1.h`.
const TLSEXT_TYPE_SUPPORTED_VERSIONS: u16 = 43;
/// `TLSEXT_TYPE_key_share` — `tls1.h`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;

/// `static MSG_PROCESS_RETURN tls_process_client_hello(...)` — `statem_srvr.c:1648-1859`, reduced to
/// the fields the ServerHello reads: the client random and session id, the offered cipher list
/// (`ssl3_choose_cipher`), and the `supported_versions`/`key_share` extensions.
///
/// The extension framework's `tls_collect_extensions`/`tls_parse_all_extensions` walk, the session
/// cache, the resumption path and the `OPENSSL_zalloc`'d `CLIENTHELLO_MSG` are not modelled; the
/// reachable fresh-connection fields are read directly from the handshake message. A ClientHello
/// that omits `supported_groups` would be a fatal error in the authority
/// (`SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION`, `extensions_srvr.c:867`); the reduced form does not
/// check that here, and the module header names it.
///
/// The application's `SSL_CTX_set_client_hello_cb` callback is invoked after the extension walk and
/// before `final_server_name`/the cipher choice, with a reduced `CLIENTHELLO_MSG` published on
/// `s->clienthello` for its duration (`statem_srvr.c:1881-1893`). This is the path HAProxy uses to
/// switch the connection to the certificate's `SSL_CTX` (`SSL_set_SSL_CTX`); a `SSL_CLIENT_HELLO_RETRY`
/// return is a recorded boundary (the reduced synchronous driver cannot resume a half-processed
/// hello).
///
/// # Safety
/// `s` must be a live connection; `hs` must be the handshake message (`type || len || body`).
pub(crate) unsafe fn tls_process_client_hello(s: *mut Ssl, hs: &[u8]) -> c_int {
    if hs.len() < 4 || hs[0] != SSL3_MT_CLIENT_HELLO_BODY {
        return 0;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    if 4 + hs_len > hs.len() {
        return 0;
    }
    let body = &hs[4..4 + hs_len];

    let mut p = 0usize;
    // legacy_version (2) + random (32).
    if body.len() < 2 + 32 {
        return 0;
    }
    p += 2;
    // SAFETY: the slice is 32 bytes; `client_random` is a 32-byte array.
    unsafe { (*s).client_random.copy_from_slice(&body[p..p + 32]) };
    p += 32;
    // session_id (1 + n): the TLSv1.3 ServerHello echoes it (`statem_srvr.c:2064-2068`).
    if p >= body.len() {
        return 0;
    }
    let sid_len = body[p] as usize;
    p += 1;
    if p + sid_len > body.len() {
        return 0;
    }
    let session_id = &body[p..p + sid_len];
    // SAFETY: `s` is live; the length is bounded by `SSL_MAX_SSL_SESSION_ID_LENGTH` by the client.
    unsafe {
        let n = sid_len.min(crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH);
        core::ptr::copy_nonoverlapping(body.as_ptr().add(p), (*s).tmp_session_id.as_mut_ptr(), n);
        (*s).tmp_session_id_len = n;
    }
    p += sid_len;
    // cipher_suites (2 + n).
    if p + 2 > body.len() {
        return 0;
    }
    let cip_len = ((body[p] as usize) << 8) | body[p + 1] as usize;
    p += 2;
    if p + cip_len > body.len() {
        return 0;
    }
    let clnt_ciphers = &body[p..p + cip_len];
    p += cip_len;
    // compression_methods (1 + n).
    if p >= body.len() {
        return 0;
    }
    let comp_len = body[p] as usize;
    p += 1;
    let compressions: &[u8] = if p + comp_len <= body.len() {
        &body[p..p + comp_len]
    } else {
        &[]
    };
    p += comp_len;
    // extensions (2 + n), if present.
    let exts: &[u8] = if p + 2 <= body.len() {
        let ext_len = ((body[p] as usize) << 8) | body[p + 1] as usize;
        p += 2;
        if p + ext_len > body.len() {
            return 0;
        }
        &body[p..p + ext_len]
    } else {
        &[]
    };

    // Choose the server version and the key-exchange group from the extensions.
    let mut saw_keyshare_group: u16 = 0;
    let mut client_share: &[u8] = &[];
    let mut off = 0usize;
    let mut sni_sent = false;
    while off + 4 <= exts.len() {
        let etype = ((exts[off] as u16) << 8) | exts[off + 1] as u16;
        let elen = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
        off += 4;
        if off + elen > exts.len() {
            return 0;
        }
        let eb = &exts[off..off + elen];
        if etype == TLSEXT_TYPE_SERVERNAME {
            // `tls_parse_ctos_server_name` (`extensions_srvr.c:100-175`): a
            // `ServerNameList` (2-byte length) holding one `host_name` entry
            // (`type(1) || len(2) || name`). Other name types and a NUL byte are refused; the
            // accepted name is stored as the connection's temporary SNI, exactly as the authority
            // stores it before `final_server_name` runs.
            if eb.len() < 2 {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            if list_len == 0 || 2 + list_len > eb.len() || eb.len() < 5 {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            let name_type = eb[2];
            let nlen = ((eb[3] as usize) << 8) | eb[4] as usize;
            if name_type != TLSEXT_NAMETYPE_HOST_NAME || 5 + nlen > eb.len() {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            if nlen > TLSEXT_MAXLEN_HOST_NAME || eb[5..5 + nlen].contains(&0) {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_UNRECOGNIZED_NAME, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            // SAFETY: `s` is live; `eb[5..]` holds `nlen` readable bytes with no interior NUL, so
            // `CRYPTO_strndup` copies exactly `nlen` bytes and appends the terminator.
            unsafe {
                use crate::runtime::mem::{CRYPTO_free, CRYPTO_strndup};
                CRYPTO_free((*s).ext_hostname.cast(), core::ptr::null(), 0);
                (*s).ext_hostname =
                    CRYPTO_strndup(eb.as_ptr().add(5).cast(), nlen, core::ptr::null(), 0);
                if (*s).ext_hostname.is_null() {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
            sni_sent = true;
        }
        if etype == TLSEXT_TYPE_SUPPORTED_VERSIONS && eb.len() >= 3 {
            // The body is `list_len || (version_hi || version_lo)...`.
            let list_len = eb[0] as usize;
            let mut q = 1usize;
            while q + 2 <= 1 + list_len.min(eb.len() - 1) {
                let v = ((eb[q] as c_int) << 8) | eb[q + 1] as c_int;
                if v == TLS1_3_VERSION {
                    // SAFETY: `s` is live.
                    unsafe { (*s).version = TLS1_3_VERSION };
                }
                q += 2;
            }
        }
        if etype == TLSEXT_TYPE_KEY_SHARE && eb.len() >= 2 {
            // `KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1>; }` — the body begins
            // with a two-byte list length (`extensions_srvr.c:857`, RFC 8446 §4.2.8). The reduced
            // server can only complete an `X25519` exchange, so it selects the `X25519` entry
            // wherever it appears in the list (the authority sends X25519MLKEM768 first, then
            // X25519).
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            let end = (2 + list_len).min(eb.len());
            let mut q = 2usize;
            while q + 4 <= end {
                let g = ((eb[q] as u16) << 8) | eb[q + 1] as u16;
                let klen = ((eb[q + 2] as usize) << 8) | eb[q + 3] as usize;
                if q + 4 + klen > eb.len() {
                    break;
                }
                if g == crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519 && klen == 32 {
                    saw_keyshare_group = g;
                    client_share = &eb[q + 4..q + 4 + klen];
                    break;
                }
                q += 4 + klen;
            }
        }
        off += elen;
    }

    // `tls_early_post_process_client_hello`'s ClientHello callback (`statem_srvr.c:1881-1893`):
    // give the application's `SSL_CTX_set_client_hello_cb` a chance to inspect the message and
    // switch the connection's context before the version/cipher choice. The authority publishes
    // `s->clienthello` (with the parsed extension array) for the duration; the reduced readers walk
    // the raw block in place.
    {
        // SAFETY: `s` is live; `body` holds the parsed ClientHello for the duration of this call.
        let ctx = unsafe { (*s).ctx };
        let cb = if ctx.is_null() {
            None
        } else {
            // SAFETY: `ctx` is the live context read above.
            unsafe { (*ctx).client_hello_cb }
        };
        if let Some(cb) = cb {
            let mut chmsg = crate::ssl::ssl_lib::ClientHelloMsg {
                isv2: 0,
                legacy_version: ((body[0] as c_uint) << 8) | body[1] as c_uint,
                random: [0u8; 32],
                session_id_len: session_id.len(),
                session_id: [0u8; crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH],
                ciphersuites: clnt_ciphers.as_ptr(),
                ciphersuites_len: clnt_ciphers.len(),
                compressions_len: compressions.len(),
                compressions: compressions.as_ptr(),
                extensions: exts.as_ptr(),
                extensions_len: exts.len(),
            };
            // SAFETY: `body` holds at least 34 bytes (checked above).
            chmsg.random.copy_from_slice(&body[2..34]);
            let n = session_id.len().min(chmsg.session_id.len());
            chmsg.session_id[..n].copy_from_slice(&session_id[..n]);
            // SAFETY: `ctx` is live; the argument is the one the setter stored.
            let cb_arg = unsafe { (*ctx).client_hello_cb_arg };
            // SAFETY: `s` is live; `chmsg` outlives the callback call below.
            unsafe {
                (*s).clienthello = (&mut chmsg as *mut crate::ssl::ssl_lib::ClientHelloMsg).cast();
            }
            let mut altmp = SSL_AD_INTERNAL_ERROR;
            // SAFETY: the callback is the application's `int (*)(SSL *, int *, void *)`.
            let r = unsafe { cb(s, &mut altmp, cb_arg) };
            // SAFETY: `s` is live.
            unsafe { (*s).clienthello = core::ptr::null_mut() };
            match r {
                SSL_CLIENT_HELLO_SUCCESS => {}
                SSL_CLIENT_HELLO_RETRY => {
                    // The authority returns control to the state machine with
                    // `s->rwstate = SSL_CLIENT_HELLO_CB`; the reduced synchronous driver cannot
                    // resume a half-processed ClientHello, so it reports the wait. Recorded
                    // boundary.
                    // SAFETY: `s` is live.
                    unsafe { (*s).rwstate = SSL_CLIENT_HELLO_CB };
                    return -1;
                }
                _ => {
                    // SAFETY: `s` is live.
                    unsafe { ossl_statem_fatal(s, altmp, SSL_R_CALLBACK_FAILED) };
                    return 0;
                }
            }
        }
    }

    // `tls_parse_all_extensions(..., fin=1)` runs the `server_name` finalisation before the cipher
    // is chosen (`statem_srvr.c:2124`, `extensions.c:938-1040`); nginx's `ngx_http_ssl_servername`
    // is reached from here.
    // SAFETY: `s` is live.
    if unsafe { final_server_name(s, sni_sent) } == 0 {
        return 0;
    }

    // `ssl3_choose_cipher` (`ssl3_lib.c`): the first TLSv1.3 cipher in the server's list that the
    // client also offered. The server-preference/list walk is reduced to that first match.
    // SAFETY: `s` is live; `SSL_get_ciphers` returns the connection's own stack.
    let ciphers = unsafe { crate::ssl::ssl_lib::SSL_get_ciphers(s) };
    if ciphers.is_null() {
        return 0;
    }
    let mut chosen: *const t::SslCipher = core::ptr::null();
    // SAFETY: `ciphers` is a live stack of `const SSL_CIPHER *`.
    let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(ciphers) };
    for i in 0..n {
        // SAFETY: `i` is in range.
        let c =
            unsafe { crate::runtime::stack::OPENSSL_sk_value(ciphers, i) as *const t::SslCipher };
        if c.is_null() {
            continue;
        }
        // SAFETY: `c` is a live table row.
        let (min_tls, id) = unsafe { ((*c).min_tls, (*c).id) };
        if min_tls < TLS1_3_VERSION {
            continue;
        }
        let mut q = 0usize;
        while q + 2 <= clnt_ciphers.len() {
            // The wire id is big-endian.
            let w = ((clnt_ciphers[q] as u16) << 8) | clnt_ciphers[q + 1] as u16;
            if w == id as u16 {
                chosen = c;
                break;
            }
            q += 2;
        }
        if !chosen.is_null() {
            break;
        }
    }
    if chosen.is_null() {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_UNEXPECTED_MESSAGE) };
        return 0;
    }
    // SAFETY: `s` is live and `chosen` a table row.
    unsafe {
        (*s).pending_cipher = chosen;
        (*s).group_id = saw_keyshare_group;
    }

    // Phase 17.2c: buffer the ClientHello for the transcript, choose the AEAD/hash from the
    // negotiated suite (`ssl_cipher_get_evp`), and wrap the client's key share as an `EVP_PKEY`
    // (`tls_parse_ctos_key_share`) so `ssl_derive` can run once the server share is built.
    // SAFETY: `s` is live; `hs` is the full ClientHello message.
    if unsafe { crate::ssl::tls13_enc::transcript_update(s, hs.as_ptr(), hs.len()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `chosen` is the table row selected above.
    if unsafe { crate::ssl::tls13_enc::tls13_setup_cipher(s, (*chosen).id as u16) } == 0 {
        return 0;
    }
    if saw_keyshare_group == crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519
        && client_share.len() == 32
    {
        // SAFETY: `s` is live; `client_share` is 32 readable bytes.
        let peer = unsafe {
            crate::ssl::tls13_enc::tls13_pkey_from_share(
                s,
                client_share.as_ptr(),
                client_share.len(),
            )
        };
        if peer.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).peer_tmp = peer };
    }

    // `ssl_fill_hello_random` (`statem_lib.c`): the fresh-connection arm is RAND.
    // SAFETY: `s` is live; `server_random` is a 32-byte array.
    if unsafe { crate::rand::rand_lib::RAND_bytes((*s).server_random.as_mut_ptr(), 32) } <= 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).hand_state = TLS_ST_SR_CLNT_HELLO };
    1
}

/// `CON_FUNC_RETURN tls_construct_server_hello(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `statem_srvr.c:2590-2699`, reduced at the key schedule.
///
/// # Safety
/// `s` must be a live connection; `pkt` a live packet.
unsafe fn tls_construct_server_hello(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    use crate::packet::{WPACKET_memcpy, WPACKET_put_bytes_u16, WPACKET_put_bytes_u8};

    // SAFETY: `s`/`pkt` are live.
    unsafe {
        let cipher = (*s).pending_cipher;
        if cipher.is_null() {
            return 0;
        }
        if WPACKET_put_bytes_u16(pkt, TLS1_2_VERSION as u16) == 0
            || WPACKET_memcpy(pkt, (*s).server_random.as_ptr().cast(), 32) == 0
            || crate::packet::WPACKET_start_sub_packet_len__(pkt, 1) == 0
            || ((*s).tmp_session_id_len != 0
                && WPACKET_memcpy(
                    pkt,
                    (*s).tmp_session_id.as_ptr().cast(),
                    (*s).tmp_session_id_len,
                ) == 0)
            || crate::packet::WPACKET_close(pkt) == 0
            || WPACKET_put_bytes_u16(pkt, (*cipher).id as u16) == 0
            || WPACKET_put_bytes_u8(pkt, 0) == 0
            || crate::ssl::statem::extensions_srvr::tls_construct_extensions(s, pkt) == 0
        {
            return 0;
        }
    }
    1
}

/// Write the server's first flight: build the ServerHello into `buf`, frame it as one plaintext
/// handshake record and write it to the connection's write BIO. The reduced transcription of
/// `statem.c`'s construct-and-send arm for `TLS_ST_SW_SRVR_HELLO` (mirrors
/// `write_client_hello`, `statem_clnt.rs`).
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write.
pub(crate) unsafe fn write_server_hello(s: *mut Ssl) -> c_int {
    use crate::ssl::statem::statem_clnt::{ssl3_set_handshake_header, tls_close_construct_packet};

    let mut buf = [0u8; 4096];
    // SAFETY: a zeroed `WPACKET` is a valid starting state for `WPACKET_init_static_len`.
    let mut pkt: Wpacket = unsafe { core::mem::zeroed() };
    let mut msglen: usize = 0;
    // SAFETY: `pkt`/`buf` are live locals; the buffer outlives the packet.
    unsafe {
        if crate::packet::WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0) == 0 {
            return 0;
        }
        if ssl3_set_handshake_header(&mut pkt, SSL3_MT_SERVER_HELLO) == 0
            || tls_construct_server_hello(s, &mut pkt) == 0
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
        // The transcript's second message (`tls_construct_server_hello`); the transcript was
        // initialised with the ClientHello by `tls_process_client_hello`.
        if r > 0 {
            crate::ssl::tls13_enc::transcript_update(s, buf.as_ptr(), msglen);
        }
        r
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 17.2c — the server's encrypted flight: `tls_construct_encrypted_extensions`,
// `tls_construct_server_certificate`, `tls_construct_cert_verify`, `tls_construct_finished`
// (`statem_srvr.c:4591/4019`/`statem_lib.c:313/618`), and the flight driver.
// ---------------------------------------------------------------------------------------------

/// `SSL3_MT_ENCRYPTED_EXTENSIONS` — `ssl3.h` (8).
const SSL3_MT_EE: u8 = 8;
/// `SSL3_MT_CERTIFICATE` — `ssl3.h` (11).
const SSL3_MT_CERT: u8 = 11;
/// `SSL3_MT_CERTIFICATE_VERIFY` — `ssl3.h` (15).
const SSL3_MT_CERT_VRFY: u8 = 15;
/// `SSL3_MT_FINISHED` — `ssl3.h` (20).
const SSL3_MT_FIN: u8 = 20;
/// `MSG_FLOW_READING` — `ssl/statem/statem.h`.
const MSG_FLOW_READING_13: c_int = 2;

/// `CON_FUNC_RETURN tls_construct_encrypted_extensions(...)` — `statem_srvr.c:4591-4601`, reduced to
/// an empty extension block (no ALPN/SNI/supported_groups is negotiated in the reduced flight).
///
/// # Safety
/// `s` is live.
unsafe fn tls13_construct_encrypted_extensions(s: *mut Ssl) -> c_int {
    // The `EncryptedExtensions` body is an `Extension extensions<0..2^16-1>` vector even when empty,
    // so the reduced flight writes the two-byte zero-length prefix (`tls_construct_encrypted_
    // extensions`, `statem_srvr.c:4591`; RFC 8446 §4.3.1).
    let body = [0u8, 0u8];
    // SAFETY: `s` is live; `body` is two initialised bytes.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_EE, body.as_ptr(), body.len())
    }
}

/// `CON_FUNC_RETURN tls_construct_server_certificate(...)` — `statem_srvr.c:4019-4055` over
/// `ssl3_output_cert_chain`: the TLS1.3 `context<0> || certificate_list<3>`, with the loaded leaf's
/// DER (`i2d_X509`). The extra chain is empty in the fixture.
///
/// # Safety
/// `s` is live.
unsafe fn tls13_construct_certificate(s: *mut Ssl) -> c_int {
    use crate::x509::x_x509::i2d_X509;
    // SAFETY: `s` is live; `cert` is the connection's active certificate container.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    if cpk.is_null() {
        return 0;
    }
    // SAFETY: `cpk` is a live slot; `x509` is the loaded leaf.
    if unsafe { (*cpk).x509 }.is_null() {
        return 0;
    }
    let mut der = [0u8; 8192];
    let mut p = der.as_mut_ptr();
    // SAFETY: `cpk.x509` is live; `p` points at `der`'s storage.
    let derlen = unsafe { i2d_X509((*cpk).x509, &mut p) };
    if derlen <= 0 {
        return 0;
    }
    let derlen = derlen as usize;
    if derlen > der.len() {
        return 0;
    }
    // `CertificateEntry` is `cert_data<1..2^24-1> || extensions<0..2^16-1>` (`ssl3.h`,
    // RFC 8446 §4.4.2): the six-byte entry prefix plus the empty two-byte extension block.
    let entry_len = 3 + derlen + 2;
    let clen = entry_len;
    let body_len = 4 + clen;
    let mut body = [0u8; 8200];
    if body_len > body.len() {
        return 0;
    }
    body[0] = 0; // opaque certificate_request_context<0..2^8-1>
    body[1] = (clen >> 16) as u8;
    body[2] = (clen >> 8) as u8;
    body[3] = clen as u8;
    body[4] = (derlen >> 16) as u8;
    body[5] = (derlen >> 8) as u8;
    body[6] = derlen as u8;
    // SAFETY: `body[7..]` has room for `derlen` bytes.
    unsafe { core::ptr::copy_nonoverlapping(der.as_ptr(), body.as_mut_ptr().add(7), derlen) };
    // The per-certificate extension block is empty: `extensions<0..2^16-1>` = `00 00`.
    body[7 + derlen] = 0;
    body[8 + derlen] = 0;
    // SAFETY: `s` is live; `body` is `body_len` initialised bytes.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_CERT, body.as_ptr(), body_len)
    }
}

/// `CON_FUNC_RETURN tls_construct_cert_verify(...)` — `statem_lib.c:313-439`, reduced to a real RSA
/// signature produced with the crate's `EVP_DigestSign` over the TLS1.3 TBS preamble
/// (`get_cert_verify_tbs_data`) and the `rsa_pss_rsae_sha256` algorithm id. The reduced client does
/// not verify it (recorded in `statem_clnt.rs`).
///
/// # Safety
/// `s` is live.
unsafe fn tls13_construct_cert_verify(s: *mut Ssl) -> c_int {
    use crate::evp::digest::{EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_free, EVP_MD_CTX_new};
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey::EvpPkey;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx};
    use crate::rsa::ctrl::{
        EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding,
        EVP_PKEY_CTX_set_rsa_pss_saltlen,
    };
    // `RSA_PKCS1_PSS_PADDING` — `include/openssl/rsa.h:321`.
    const RSA_PKCS1_PSS_PADDING: c_int = 6;
    // `RSA_PSS_SALTLEN_DIGEST` — `include/openssl/rsa.h`: salt length equals the digest length,
    // which RFC 8446 §4.2.3 requires for `rsa_pss_rsae_sha256`.
    const RSA_PSS_SALTLEN_DIGEST: c_int = -1;
    // SAFETY: `s` is live.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    if cpk.is_null() {
        return 0;
    }
    // SAFETY: `cpk` is a live slot; `privatekey` is the loaded key.
    if unsafe { (*cpk).privatekey }.is_null() {
        return 0;
    }
    let ctx_str = b"TLS 1.3, server CertificateVerify";
    // SAFETY: `s` is live; `hs_md_len` is the negotiated hash length.
    let hl = unsafe { (*s).hs_md_len };
    let mut tbs = [0u8; 64 + 33 + 1 + 64];
    for b in tbs[..64].iter_mut() {
        *b = 0x20;
    }
    let mut pos = 64;
    tbs[pos..pos + ctx_str.len()].copy_from_slice(ctx_str);
    pos += ctx_str.len();
    tbs[pos] = 0;
    pos += 1;
    // SAFETY: `s` is live; `tbs[pos..]` has room for the hash.
    if unsafe {
        crate::ssl::tls13_enc::transcript_hash(s, tbs.as_mut_ptr().add(pos), core::ptr::null_mut())
    } == 0
    {
        return 0;
    }
    pos += hl;
    // SAFETY: no preconditions.
    let mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        return 0;
    }
    // SAFETY: `cpk` is a live slot; `privatekey` is the loaded signing key.
    let pkey = unsafe { (*cpk).privatekey }.cast::<EvpPkey>();
    let mut ok = false;
    // SAFETY: `mctx`/`pkey` are live; `tbs` is `pos` initialised bytes.
    unsafe {
        let mut siglen = 0usize;
        let mut pctx: *mut EvpPkeyCtx = core::ptr::null_mut();
        let md = EVP_sha256();
        if EVP_DigestSignInit(mctx, &mut pctx, md, core::ptr::null_mut(), pkey) > 0
            && !pctx.is_null()
            && EVP_PKEY_CTX_set_signature_md(pctx, md) > 0
            && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
            && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0
            && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0
            && EVP_DigestSign(mctx, core::ptr::null_mut(), &mut siglen, tbs.as_ptr(), pos) > 0
            && siglen <= 1024
        {
            let mut sig = [0u8; 1024];
            if EVP_DigestSign(mctx, sig.as_mut_ptr(), &mut siglen, tbs.as_ptr(), pos) > 0 {
                let mut body = [0u8; 1030];
                // `rsa_pss_rsae_sha256` — `tls13.h`/`t1_lib.c` sigalg table (0x0804). TLS 1.3
                // requires an RSASSA-PSS scheme for an RSA key (`tls12_check_peer_sigalg`,
                // `tls1_lib.c:2700-2739`; RFC 8446 §4.2.3).
                body[0] = 0x08;
                body[1] = 0x04;
                body[2] = (siglen >> 8) as u8;
                body[3] = siglen as u8;
                core::ptr::copy_nonoverlapping(sig.as_ptr(), body.as_mut_ptr().add(4), siglen);
                ok = crate::ssl::tls13_enc::write_handshake_message(
                    s,
                    SSL3_MT_CERT_VRFY,
                    body.as_ptr(),
                    4 + siglen,
                ) > 0;
            }
        }
        EVP_MD_CTX_free(mctx);
    }
    c_int::from(ok)
}

/// `tls_construct_finished` (`statem_lib.c:618`) for the server, then the application-secret
/// derivation and the write-key switch (`statem_srvr.c:1188`).
///
/// # Safety
/// `s` is live.
unsafe fn tls13_server_finish_flight(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc as k;
    // SAFETY: `s` is live; the server handshake traffic secret is the connection's.
    if unsafe { k::tls13_construct_finished(s, (*s).server_hs_traffic.as_ptr()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; the transcript now includes the server Finished.
    if unsafe { k::tls13_derive_application_traffic(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `pending_cipher` was set by `tls_process_client_hello`.
    let cid = unsafe { (*(*s).pending_cipher).id as u16 };
    // SAFETY: `s` is live.
    unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_APPLICATION | k::SSL3_CHANGE_CIPHER_SERVER_WRITE,
            cid,
        )
    }
}

/// The `ssl_derive` + `tls13_change_cipher_state` + server-flight block of the server's
/// `SW_SRVR_HELLO` post-work (`statem_srvr.c:1120-1134`).
///
/// # Safety
/// `s` is live.
unsafe fn tls13_server_post_server_hello(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc as k;
    let mut pms = [0u8; 64];
    let mut pmslen = 0usize;
    // SAFETY: `s` is live; the server ephemeral (`pkey`) and client share (`peer_tmp`) are set.
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
    // SAFETY: `s` is live; `pms` is `pmslen` initialised bytes.
    if unsafe { k::tls13_generate_handshake_secret(s, &pms[..pmslen]) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; the transcript is `ClientHello || ServerHello`.
    if unsafe { k::tls13_derive_handshake_traffic(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `pending_cipher` was set by `tls_process_client_hello`.
    let cid = unsafe { (*(*s).pending_cipher).id as u16 };
    // SAFETY: `s` is live; the server-write handshake key is installed (`statem_srvr.c:1123`).
    if unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_HANDSHAKE | k::SSL3_CHANGE_CIPHER_SERVER_WRITE,
            cid,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live; the server-read handshake key is installed (`statem_srvr.c:1131`).
    if unsafe {
        k::tls13_change_cipher_state(
            s,
            k::SSL3_CC_HANDSHAKE | k::SSL3_CHANGE_CIPHER_SERVER_READ,
            cid,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_construct_encrypted_extensions(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_construct_certificate(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_construct_cert_verify(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_server_finish_flight(s) } == 0 {
        return 0;
    }
    1
}

/// The server read/write driver: reads the ClientHello, writes the whole server flight, then reads
/// the client Finished (`statem.c`'s read/write sub-state machines, reduced). Returns `1` when the
/// handshake finishes and `-1` while waiting for the peer.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_server_drive(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc as k;
    // SAFETY: `s` is live.
    unsafe {
        loop {
            match (*s).hand_state {
                TLS_ST_BEFORE => {
                    let mut buf = [0u8; 16384];
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    if n <= 0 || buf[0] != SSL3_MT_CLIENT_HELLO_BODY {
                        return server_wait(s);
                    }
                    let pr = tls_process_client_hello(s, &buf[..n as usize]);
                    if pr == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if pr < 0 {
                        // The ClientHello callback asked to be re-entered
                        // (`s->rwstate == SSL_CLIENT_HELLO_CB`); report the wait.
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_SRVR_HELLO;
                }
                TLS_ST_SW_SRVR_HELLO => {
                    if write_server_hello(s) <= 0 || tls13_server_post_server_hello(s) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                }
                TLS_ST_SR_FINISHED => {
                    let mut buf = [0u8; 16384];
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    if n <= 0 || buf[0] != SSL3_MT_FIN {
                        return server_wait(s);
                    }
                    let secret = (*s).client_hs_traffic.as_ptr();
                    if k::tls13_process_finished(s, &buf[..n as usize], secret) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    let cid = (*(*s).pending_cipher).id as u16;
                    if k::tls13_change_cipher_state(
                        s,
                        k::SSL3_CC_APPLICATION | k::SSL3_CHANGE_CIPHER_SERVER_READ,
                        cid,
                    ) == 0
                    {
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
                    // Recorded boundary: the authority's post-handshake write transition may emit
                    // `NewSessionTicket`s here (`tls_construct_new_session_ticket`,
                    // `statem_srvr.c:4370`). That path needs a handshake session
                    // (`ssl_get_new_session`), the resumption-master-secret key schedule, and the
                    // `construct_stateless_ticket` encryption/HMAC round trip, none of which this
                    // slice owns; `SSL_CTX_set_tlsext_ticket_key_cb` is stored and returns 1, but no
                    // ticket is constructed. The boundary is recorded rather than faked.
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

/// Mark the server as waiting for the peer's next record.
///
/// # Safety
/// `s` is live.
unsafe fn server_wait(s: *mut Ssl) -> c_int {
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
    -1
}
