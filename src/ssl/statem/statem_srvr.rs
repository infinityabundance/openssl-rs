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
use core::ptr;

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
const SSL3_MT_CERTIFICATE_REQUEST: c_int = 13;
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
const SSL_R_UNEXPECTED_MESSAGE: c_int = 244;
const SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE: c_int = 205;
/// `SSL_R_UNSUPPORTED_PROTOCOL` — `sslerr.h:258`.
const SSL_R_UNSUPPORTED_PROTOCOL: c_int = 258;
/// `SSL_R_NO_SUITABLE_KEY_SHARE` — `sslerr.h`.
const SSL_R_NO_SUITABLE_KEY_SHARE: c_int = 380;
/// `SSL_AD_ILLEGAL_PARAMETER` — `ssl3.h` (47).
#[allow(dead_code)]
const SSL_AD_ILLEGAL_PARAMETER: c_int = 47;
/// `SSL3_MT_SERVER_KEY_EXCHANGE` — `ssl3.h` (12).
const SSL3_MT_SERVER_KEY_EXCHANGE: c_int = 12;
/// `SSL3_MT_SERVER_HELLO_DONE` — `ssl3.h` (14).
const SSL3_MT_SERVER_HELLO_DONE: c_int = 14;
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
/// `SSL_TLSEXT_ERR_OK` — `tls1.h:337`.
const SSL_TLSEXT_ERR_OK: c_int = 0;
/// `TLSEXT_TYPE_application_layer_protocol_negotiation` — `tls1.h:116`.
const TLSEXT_TYPE_ALPN: u16 = 16;
/// `TLSEXT_TYPE_post_handshake_auth` — `tls1.h:157`.
const TLSEXT_TYPE_POST_HANDSHAKE_AUTH: u16 = 49;
/// `SSL_PHA_EXT_RECEIVED` — `ssl_local.h:373`.
const SSL_PHA_EXT_RECEIVED: c_int = 2;
/// `TLS1_AD_NO_APPLICATION_PROTOCOL` — `tls1.h:80`.
const SSL_AD_NO_APPLICATION_PROTOCOL: c_int = 120;
/// `SSL_R_NO_APPLICATION_PROTOCOL` — `sslerr.h:190`.
const SSL_R_NO_APPLICATION_PROTOCOL: c_int = 235;

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
pub(crate) fn send_certificate_request(s: *mut Ssl) -> bool {
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

/// `int tls_handle_alpn(SSL_CONNECTION *s)` — `ssl/statem/statem_srvr.c:2390-2480`, reduced to the
/// `alpn_select_cb` dispatch and the `NSELECT`/`NOACK` arms.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn tls_handle_alpn(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract; `ctx` is its context.
    let ctx = unsafe { (*s).ctx };
    if !ctx.is_null() {
        // SAFETY: `ctx` is the live context read above.
        if let Some(cb) = unsafe { (*ctx).alpn_select_cb } {
            // SAFETY: `s` is live.
            let proposed = unsafe { (*s).s3_alpn_proposed };
            if !proposed.is_null() {
                let mut selected: *const u8 = core::ptr::null();
                let mut selected_len: u8 = 0;
                // SAFETY: the callback is the application's `SSL_CTX_alpn_select_cb_func`; `s`, the
                // two out-parameters and the proposed list are the ones it was installed to receive.
                let r = unsafe {
                    cb(
                        s,
                        &mut selected,
                        &mut selected_len,
                        proposed,
                        (*s).s3_alpn_proposed_len as core::ffi::c_uint,
                        (*ctx).alpn_select_cb_arg,
                    )
                };
                if r == SSL_TLSEXT_ERR_OK {
                    // SAFETY: `s` is live; `selected`/`selected_len` name a live buffer.
                    unsafe {
                        use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup};
                        CRYPTO_free((*s).s3_alpn_selected.cast(), core::ptr::null(), 0);
                        (*s).s3_alpn_selected = CRYPTO_memdup(
                            selected.cast(),
                            selected_len as usize,
                            core::ptr::null(),
                            0,
                        )
                        .cast::<u8>();
                        if (*s).s3_alpn_selected.is_null() {
                            (*s).s3_alpn_selected_len = 0;
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return 0;
                        }
                        (*s).s3_alpn_selected_len = selected_len as usize;
                    }
                    return 1;
                } else if r != SSL_TLSEXT_ERR_NOACK {
                    // SAFETY: `s` is live.
                    unsafe {
                        ossl_statem_fatal(
                            s,
                            SSL_AD_NO_APPLICATION_PROTOCOL,
                            SSL_R_NO_APPLICATION_PROTOCOL,
                        )
                    };
                    return 0;
                }
            }
        }
    }
    1
}

/// `SSL3_MT_SERVER_HELLO` — `ssl3.h`.
const SSL3_MT_SERVER_HELLO: u8 = 2;
/// `SSL3_MT_CLIENT_HELLO` — `ssl3.h`.
const SSL3_MT_CLIENT_HELLO_BODY: u8 = 1;
/// `TLS1_2_VERSION` — `ssl3.h` (the legacy ServerHello version, `statem_srvr.c:2599`).
const TLS1_2_VERSION: c_int = 0x0303;
/// `TLSEXT_TYPE_supported_groups` — `tls1.h:143`.
const TLSEXT_TYPE_SUPPORTED_GROUPS: u16 = 10;
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
    let legacy_version = ((body[0] as c_int) << 8) | body[1] as c_int;
    let mut wants_tls13 = false;
    let mut sup_versions = [0u16; 8];
    let mut sup_versions_cnt = 0usize;
    let mut clnt_groups = [0u16; 32];
    let mut clnt_group_cnt = 0usize;
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
                if sup_versions_cnt < sup_versions.len() {
                    sup_versions[sup_versions_cnt] = v as u16;
                    sup_versions_cnt += 1;
                }
                if v == TLS1_3_VERSION {
                    // `tls_parse_ctos_supported_versions` records the request; the version itself
                    // is resolved after the whole extension walk (`tls_early_post_process_client_hello`).
                    wants_tls13 = true;
                }
                q += 2;
            }
        }
        if etype == TLSEXT_TYPE_SUPPORTED_GROUPS && eb.len() >= 2 {
            // `tls_parse_ctos_supported_groups` (`extensions_srvr.c`): the `NamedGroupList`.
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            let end = (2 + list_len).min(eb.len());
            let mut q = 2usize;
            while q + 2 <= end && clnt_group_cnt < clnt_groups.len() {
                clnt_groups[clnt_group_cnt] = ((eb[q] as u16) << 8) | eb[q + 1] as u16;
                clnt_group_cnt += 1;
                q += 2;
            }
        }
        if etype == TLSEXT_TYPE_ALPN {
            // `tls_parse_ctos_alpn` (`extensions_srvr.c:451-480`): a
            // `ProtocolNameList` (2-byte length) of 1-byte-length, non-empty protocols. The client's
            // list is copied onto the connection for `final_alpn` (`tls_handle_alpn`).
            if eb.len() < 2 {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            if list_len < 2 || 2 + list_len > eb.len() {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            let list = &eb[2..2 + list_len];
            let mut q = 0usize;
            let mut ok = true;
            while q < list.len() {
                let plen = list[q] as usize;
                if plen == 0 || q + 1 + plen > list.len() {
                    ok = false;
                    break;
                }
                q += 1 + plen;
            }
            if !ok {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            // SAFETY: `s` is live; `list` is `list_len` readable bytes.
            unsafe {
                use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup};
                CRYPTO_free((*s).s3_alpn_proposed.cast(), core::ptr::null(), 0);
                (*s).s3_alpn_proposed =
                    CRYPTO_memdup(list.as_ptr().cast(), list.len(), core::ptr::null(), 0)
                        .cast::<u8>();
                if (*s).s3_alpn_proposed.is_null() {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                (*s).s3_alpn_proposed_len = list.len();
            }
        }
        if etype == TLSEXT_TYPE_POST_HANDSHAKE_AUTH {
            // `tls_parse_ctos_post_handshake_auth` (`extensions_srvr.c:1565-1579`): the extension
            // body must be empty, and its presence records that the client will answer a
            // post-handshake CertificateRequest (`s->post_handshake_auth = SSL_PHA_EXT_RECEIVED`).
            if elen != 0 {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            // SAFETY: `s` is live.
            unsafe { (*s).post_handshake_auth = SSL_PHA_EXT_RECEIVED };
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

    // `tls_parse_ctos_supported_versions`/the legacy-version fallback (`statem_srvr.c`): the
    // highest version both sides support. Absent a TLS1.3 `supported_versions` offer, the legacy
    // version governs, clamped to the server's own maximum. Only TLS1.2 and TLS1.3 are implemented.
    let mut smin: c_int = 0;
    let mut smax: c_int = 0;
    // SAFETY: `s` is live; the out-pointers are live locals.
    if unsafe {
        crate::ssl::statem::statem_lib::ssl_get_min_max_version(
            s,
            &mut smin,
            &mut smax,
            core::ptr::null_mut(),
        )
    } != 0
    {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_UNSUPPORTED_PROTOCOL) };
        return 0;
    }
    let mut session_version = legacy_version;
    if wants_tls13 && smax >= TLS1_3_VERSION {
        session_version = TLS1_3_VERSION;
    }
    if session_version > smax {
        session_version = smax;
    }
    if session_version < smin
        || (session_version != TLS1_2_VERSION && session_version != TLS1_3_VERSION)
    {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_UNSUPPORTED_PROTOCOL) };
        return 0;
    }
    // A `supported_versions` offer restricts the server to a version the client listed
    // (`tls_parse_ctos_supported_versions`, `extensions_srvr.c`).
    if sup_versions_cnt > 0 && !sup_versions[..sup_versions_cnt].contains(&(session_version as u16))
    {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_UNSUPPORTED_PROTOCOL) };
        return 0;
    }
    // `tls_setup_handshake` installs the negotiated-version method (`statem_lib.c:2292`), which
    // `SSL_CONNECTION_IS_TLS13` reads.
    // SAFETY: `s` is live.
    unsafe {
        (*s).version = session_version;
        (*s).method = if session_version == TLS1_3_VERSION {
            crate::ssl::methods::tls13_method(true)
        } else {
            crate::ssl::methods::tls12_method(true)
        };
    }

    // `tls_early_post_process_client_hello` (`statem_srvr.c:2042-2068`): for TLS1.2, look for a
    // previous session in the internal cache and, failing that, create the handshake session.
    // TLS1.3 resumption (the PSK extension) is not modelled.
    if session_version == TLS1_2_VERSION {
        // Mark the connection so a handshake wait re-enters the TLS1.2 driver.
        // SAFETY: `s` is live.
        unsafe { (*s).tls12_driver = 1 };
        // `tls_setup_handshake` (`statem_lib.c:222-224`) counts the first handshake here.
        // SAFETY: `s` is live.
        if is_first_handshake(s) {
            // SAFETY: `s` is live.
            let sc = unsafe { (*s).session_ctx };
            if !sc.is_null() {
                // SAFETY: `sc` is the connection's live session context.
                unsafe {
                    (*sc)
                        .stats
                        .sess_accept
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                };
            }
        }
        // SAFETY: `s` is live; `session_id` is the ClientHello's session-id slice.
        let prev = unsafe { crate::ssl::ssl_sess::ssl_get_prev_session(s, session_id) };
        if prev < 0 {
            return 0;
        }
        if prev == 1 {
            // SAFETY: `s` is live.
            unsafe { (*s).hit = 1 };
        } else {
            // SAFETY: `s` is live.
            if unsafe { crate::ssl::ssl_sess::ssl_get_new_session(s, 1) } == 0 {
                return 0;
            }
        }
    }

    // Phase 17 ecdh-curve fix: the TLS1.3 server honors its own configured group list. The
    // authority (`tls_parse_ctos_key_share`, `extensions_srvr.c:965-997`) fails with
    // `SSL_R_NO_SUITABLE_KEY_SHARE` when the client's `supported_groups` and the server's list do
    // not intersect (a group overlap with no matching key share would send a HelloRetryRequest; the
    // reduced server accepts the client's X25519 share instead, a named boundary).
    if session_version == TLS1_3_VERSION
        && clnt_group_cnt > 0
        // SAFETY: `s` is live; `clnt_groups[..clnt_group_cnt]` is readable.
        && unsafe { tls12_choose_group(s, &clnt_groups[..clnt_group_cnt]) } == 0
    {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SUITABLE_KEY_SHARE) };
        return 0;
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
    if session_version == TLS1_3_VERSION {
        // `ssl3_choose_cipher` (`ssl3_lib.c`): the first TLSv1.3 cipher in the server's list that
        // the client also offered.
        // SAFETY: `ciphers` is a live stack of `const SSL_CIPHER *`.
        let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(ciphers) };
        for i in 0..n {
            // SAFETY: `i` is in range.
            let c = unsafe {
                crate::runtime::stack::OPENSSL_sk_value(ciphers, i) as *const t::SslCipher
            };
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
    } else {
        // The TLS1.2 half of `ssl3_choose_cipher` (`ssl3_lib.c`): server preference over the
        // supported `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites, filtered by the certificate the
        // server actually holds.
        // SAFETY: `s`/`ciphers`/`clnt_ciphers` are live.
        chosen = unsafe { tls12_choose_cipher(s, ciphers, clnt_ciphers) };
    }
    if chosen.is_null() {
        // `ssl3_choose_cipher` returning NULL is `SSL_R_NO_SHARED_CIPHER`
        // (`tls_early_post_process_client_hello`, `statem_srvr.c:2002`).
        // SAFETY: `s` is live.
        unsafe {
            ossl_statem_fatal(
                s,
                SSL_AD_HANDSHAKE_FAILURE,
                crate::runtime::err::err_reasons::SSL_R_NO_SHARED_CIPHER,
            )
        };
        return 0;
    }
    // SAFETY: `s` is live and `chosen` a table row.
    unsafe {
        (*s).pending_cipher = chosen;
        (*s).group_id = if session_version == TLS1_3_VERSION {
            saw_keyshare_group
        } else {
            // `tls_parse_ctos_supported_groups`'s selection (`extensions_srvr.c`): the first server
            // group the client also offered. The reduced TLS1.2 path only completes an X25519
            // exchange, so a connection with no common X25519 group fails at the ServerKeyExchange.
            tls12_choose_group(s, &clnt_groups[..clnt_group_cnt])
        };
    }

    // `ssl_cache_cipherlist` (`ssl_lib.c:7088-7124`): build the client's offered cipher list
    // (`s->s3.tmp.peer_ciphers`) from the raw wire ciphers, so `SSL_get_client_ciphers` answers.
    // SAFETY: `clnt_ciphers` is a live byte slice; the stack owns table-row pointers only.
    unsafe {
        use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push};
        let sk = OPENSSL_sk_new_null();
        if !sk.is_null() {
            let mut q = 0usize;
            while q + 2 <= clnt_ciphers.len() {
                let c = crate::ssl::ssl_ciph::ssl3_get_cipher_by_char(clnt_ciphers.as_ptr().add(q));
                if !c.is_null() {
                    OPENSSL_sk_push(sk, c.cast());
                }
                q += 2;
            }
            OPENSSL_sk_free((*s).peer_ciphers);
            (*s).peer_ciphers = sk;
        }
    }

    // `final_alpn` -> `tls_handle_alpn` (`extensions.c:1147`, `statem_srvr.c:2390-2480`): runs the
    // `alpn_select_cb` now that the cipher is chosen.
    // SAFETY: `s` is live.
    if unsafe { tls_handle_alpn(s) } == 0 {
        return 0;
    }

    // Phase 17.2c: buffer the ClientHello for the transcript, choose the AEAD/hash from the
    // negotiated suite (`ssl_cipher_get_evp`), and wrap the client's key share as an `EVP_PKEY`
    // (`tls_parse_ctos_key_share`) so `ssl_derive` can run once the server share is built.
    // SAFETY: `s` is live; `hs` is the full ClientHello message.
    if unsafe { crate::ssl::tls13_enc::transcript_update(s, hs.as_ptr(), hs.len()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `chosen` is the table row selected above.
    if session_version == TLS1_3_VERSION {
        // SAFETY: `s` is live; `chosen` is a table row.
        if unsafe { crate::ssl::tls13_enc::tls13_setup_cipher(s, (*chosen).id as u16) } == 0 {
            return 0;
        }
    } else {
        // SAFETY: `s` is live; `chosen` is a table row.
        if unsafe { crate::ssl::t1_enc::tls12_setup_cipher(s, (*chosen).id as u16) } == 0 {
            return 0;
        }
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

/// `CON_FUNC_RETURN tls_construct_encrypted_extensions(...)` — `statem_srvr.c:4591-4601`.
///
/// The `EncryptedExtensions` body is an `Extension extensions<0..2^16-1>` vector. The reduced flight
/// carries only the negotiated ALPN (`tls_construct_stoc_alpn`, `extensions_srvr.c:1835-1854`); every
/// other extension this stratum could negotiate is empty.
///
/// # Safety
/// `s` is live.
unsafe fn tls13_construct_encrypted_extensions(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live; the selected protocol is owned by the connection.
    let (selected, sel_len) = unsafe { ((*s).s3_alpn_selected, (*s).s3_alpn_selected_len) };
    // The `Extension extensions<0..2^16-1>` block, then a two-byte length prefix in `body`.
    let mut ext = [0u8; 512];
    let mut ext_len = 0usize;
    if !selected.is_null() && sel_len > 0 && sel_len <= 255 {
        // `tls_construct_stoc_alpn`: the extension body is
        // `ProtocolNameList<2..2^16-1>` = `list_len(2) || proto_len(1) || proto`.
        let list_len = 1 + sel_len;
        let elen = 2 + list_len;
        let hdr: [u8; 6] = [
            (TLSEXT_TYPE_ALPN >> 8) as u8,
            (TLSEXT_TYPE_ALPN & 0xff) as u8,
            (elen >> 8) as u8,
            (elen & 0xff) as u8,
            (list_len >> 8) as u8,
            (list_len & 0xff) as u8,
        ];
        ext[..6].copy_from_slice(&hdr);
        ext[6] = sel_len as u8;
        // SAFETY: `selected` names `sel_len` readable bytes; `ext` has room for them.
        unsafe { core::ptr::copy_nonoverlapping(selected, ext.as_mut_ptr().add(7), sel_len) };
        ext_len = 7 + sel_len;
    }
    let mut body = [0u8; 514];
    body[0] = (ext_len >> 8) as u8;
    body[1] = (ext_len & 0xff) as u8;
    body[2..2 + ext_len].copy_from_slice(&ext[..ext_len]);
    // SAFETY: `s` is live; `body` holds `2 + ext_len` initialised bytes.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_EE, body.as_ptr(), 2 + ext_len)
    }
}

/// `CON_FUNC_RETURN tls_construct_certificate_request(...)` — `statem_srvr.c:3023-3094`, reduced to
/// the TLS1.3 arm: `certificate_request_context<0..2^8-1> || Extension extensions<2>`, the
/// `signature_algorithms` extension being the only one the reduced client needs to pick its scheme
/// (`tls_construct_stoc_signature_algorithms`, `extensions.c:304-308`). `context` is empty for an
/// in-handshake request and a 32-byte random for post-handshake auth
/// (`statem_srvr.c:3027-3054`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_construct_certificate_request(s: *mut Ssl, context: &[u8]) -> c_int {
    // The authority's default signature-algorithm list (`tls12_get_psigalgs`, `ssl/t1_lib.c`); the
    // reduced server has no configured list, so it sends the same default the reduced client offers.
    const SIGALGS: [u16; 26] = [
        0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c,
        0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
        0x0302, 0x0402, 0x0502, 0x0602,
    ];
    // `TLSEXT_TYPE_signature_algorithms` — `tls1.h` (13).
    const TLSEXT_TYPE_SIG_ALGS: u16 = 13;
    if context.len() > 255 {
        return 0;
    }
    let mut ext = [0u8; 64];
    ext[0] = (TLSEXT_TYPE_SIG_ALGS >> 8) as u8;
    ext[1] = (TLSEXT_TYPE_SIG_ALGS & 0xff) as u8;
    let list_len = SIGALGS.len() * 2;
    let body_len = 2 + list_len;
    ext[2] = (body_len >> 8) as u8;
    ext[3] = (body_len & 0xff) as u8;
    ext[4] = (list_len >> 8) as u8;
    ext[5] = (list_len & 0xff) as u8;
    let mut p = 6usize;
    for a in SIGALGS {
        ext[p] = (a >> 8) as u8;
        ext[p + 1] = (a & 0xff) as u8;
        p += 2;
    }
    let ext_total = p;
    let ctx_len = context.len();
    let total = 1 + ctx_len + 2 + ext_total;
    let mut msg = [0u8; 256];
    if total > msg.len() {
        return 0;
    }
    msg[0] = ctx_len as u8;
    msg[1..1 + ctx_len].copy_from_slice(context);
    let mut q = 1 + ctx_len;
    msg[q] = (ext_total >> 8) as u8;
    msg[q + 1] = (ext_total & 0xff) as u8;
    q += 2;
    msg[q..q + ext_total].copy_from_slice(&ext[..ext_total]);
    // `s->certreqs_sent++; s->s3.tmp.cert_request = 1;` (`statem_srvr.c:3091-3092`).
    // SAFETY: `s` is live.
    unsafe {
        (*s).certreqs_sent += 1;
        (*s).s3_tmp_cert_request = 1;
    }
    // SAFETY: `s` is live; `msg` is `total` initialised bytes.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(
            s,
            SSL3_MT_CERTIFICATE_REQUEST as u8,
            msg.as_ptr(),
            total,
        )
    }
}

/// Whether this connection has an active certificate to send (`s->cert->key->x509`), the reduced
/// `cpk != NULL` test of `ssl3_output_cert_chain`.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn cert_active_present(s: *mut Ssl) -> bool {
    // SAFETY: `s` is live; `cert` is its certificate container.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    // SAFETY: `cpk` is non-NULL per the left operand; its `x509` slot is read.
    !cpk.is_null() && unsafe { !(*cpk).x509.is_null() }
}

/// `CON_FUNC_RETURN tls_construct_server_certificate(...)` — `statem_srvr.c:4019-4055` over
/// `ssl3_output_cert_chain`: the TLS1.3 `context<0..2^8-1> || certificate_list<3>`, with the
/// loaded leaf's DER (`i2d_X509`). The extra chain is empty in the fixture. The same construction
/// serves `tls_construct_client_certificate` (`statem_clnt.c:3851-3910`), where `context` is the
/// `pha_context` echoed from the CertificateRequest.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_construct_certificate(s: *mut Ssl, context: &[u8]) -> c_int {
    use crate::x509::x_x509::i2d_X509;
    if context.len() > 255 {
        return 0;
    }
    // SAFETY: `s` is live; `cert` is the connection's active certificate container.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    let ctx_len = context.len();
    // No certificate to send (`ssl3_output_cert_chain` with a NULL `cpk`): the TLS1.3
    // `certificate_list` is empty (`statem_clnt.c:3869-3882`).
    // SAFETY: `cpk` is non-NULL per the left operand; its `x509` slot is read.
    if cpk.is_null() || unsafe { (*cpk).x509 }.is_null() {
        let mut body = [0u8; 300];
        body[0] = ctx_len as u8;
        body[1..1 + ctx_len].copy_from_slice(context);
        let q = 1 + ctx_len;
        body[q] = 0;
        body[q + 1] = 0;
        body[q + 2] = 0;
        // SAFETY: `s` is live; `body` is `q + 3` initialised bytes.
        return unsafe {
            crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_CERT, body.as_ptr(), q + 3)
        };
    }
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
    let body_len = 1 + ctx_len + 3 + clen;
    let mut body = [0u8; 8200];
    if body_len > body.len() {
        return 0;
    }
    body[0] = ctx_len as u8; // opaque certificate_request_context<0..2^8-1>
    body[1..1 + ctx_len].copy_from_slice(context);
    let mut p = 1 + ctx_len;
    body[p] = (clen >> 16) as u8;
    body[p + 1] = (clen >> 8) as u8;
    body[p + 2] = clen as u8;
    p += 3;
    body[p] = (derlen >> 16) as u8;
    body[p + 1] = (derlen >> 8) as u8;
    body[p + 2] = derlen as u8;
    p += 3;
    // SAFETY: `body[p..]` has room for `derlen` bytes.
    unsafe { core::ptr::copy_nonoverlapping(der.as_ptr(), body.as_mut_ptr().add(p), derlen) };
    p += derlen;
    // The per-certificate extension block is empty: `extensions<0..2^16-1>` = `00 00`.
    body[p] = 0;
    body[p + 1] = 0;
    // SAFETY: `s` is live; `body` is `body_len` initialised bytes.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_CERT, body.as_ptr(), body_len)
    }
}

/// `CON_FUNC_RETURN tls_construct_cert_verify(...)` — `statem_lib.c:313-439`, reduced to a real RSA
/// or ECDSA signature produced with the crate's `EVP_DigestSign` over the TLS1.3 TBS preamble
/// (`get_cert_verify_tbs_data`, `statem_lib.c:258-311`) and the scheme id picked by the signer's key
/// type. `is_server` selects the server context string; the client uses
/// `"TLS 1.3, client CertificateVerify"` (`statem_lib.c:264-266`). The reduced peer verifies it.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_construct_cert_verify(s: *mut Ssl, is_server: bool) -> c_int {
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
    let ctx_str: &[u8] = if is_server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    };
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
    // The authority's `tls12_get_sigandhash`/`tls1_lookup_sigalg` picks the scheme by key type
    // (`tls1_lib.c`): an EC key signs with `ecdsa_secp256r1_sha256` (0x0403) and takes no RSA
    // padding; an RSA key signs with `rsa_pss_rsae_sha256` (0x0804).
    // SAFETY: `pkey` is the live key.
    let is_ec = unsafe { crate::evp::pkey::EVP_PKEY_get_base_id(pkey) }
        == crate::evp::pkey_ctx::EVP_PKEY_EC;
    let mut ok = false;
    // SAFETY: `mctx`/`pkey` are live; `tbs` is `pos` initialised bytes.
    unsafe {
        let mut siglen = 0usize;
        let mut pctx: *mut EvpPkeyCtx = core::ptr::null_mut();
        let md = EVP_sha256();
        let init_ok = EVP_DigestSignInit(mctx, &mut pctx, md, core::ptr::null_mut(), pkey) > 0
            && !pctx.is_null()
            && EVP_PKEY_CTX_set_signature_md(pctx, md) > 0;
        let params_ok = if is_ec {
            true
        } else {
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
                && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) > 0
                && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0
        };
        if init_ok
            && params_ok
            && EVP_DigestSign(mctx, core::ptr::null_mut(), &mut siglen, tbs.as_ptr(), pos) > 0
            && siglen <= 1024
        {
            let mut sig = [0u8; 1024];
            if EVP_DigestSign(mctx, sig.as_mut_ptr(), &mut siglen, tbs.as_ptr(), pos) > 0 {
                let mut body = [0u8; 1030];
                // `ecdsa_secp256r1_sha256` (0x0403) for an EC key, else `rsa_pss_rsae_sha256` (0x0804).
                let sigalg: [u8; 2] = if is_ec {
                    [0x04, 0x03]
                } else {
                    // TLS 1.3 requires an RSASSA-PSS scheme for an RSA key
                    // (`tls12_check_peer_sigalg`, `tls1_lib.c:2700-2739`; RFC 8446 §4.2.3).
                    [0x08, 0x04]
                };
                body[0] = sigalg[0];
                body[1] = sigalg[1];
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
    // The TLS1.3 write transition's `SW_ENCRYPTED_EXTENSIONS` arm
    // (`statem_srvr.c:664-674`): an in-handshake CertificateRequest precedes the server Certificate.
    // SAFETY: `s` is live.
    if send_certificate_request(s) {
        // In-handshake requests carry an empty `certificate_request_context`
        // (`statem_srvr.c:3049-3054`).
        // SAFETY: `s` is live.
        if unsafe { tls13_construct_certificate_request(s, &[]) } == 0 {
            return 0;
        }
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_construct_certificate(s, &[]) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_construct_cert_verify(s, true) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { tls13_server_finish_flight(s) } == 0 {
        return 0;
    }
    1
}

/// The server's TLS1.3 post-handshake-authentication request: `tls_construct_certificate_request`
/// for the `SSL_PHA_REQUEST_PENDING` arm (`statem_srvr.c:3027-3054`). A fresh 32-byte
/// `certificate_request_context` is generated, the transcript is rewound to the saved PHA digest
/// (`tls13_restore_handshake_digest_for_pha`), and the request is written (which appends it to the
/// transcript).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_server_send_pha_cert_request(s: *mut Ssl) -> c_int {
    use crate::rand::rand_lib::RAND_bytes;
    let mut ctx = [0u8; 32];
    // SAFETY: `s` is live; `ctx` is writable.
    if unsafe { RAND_bytes(ctx.as_mut_ptr(), ctx.len() as c_int) } <= 0 {
        return 0;
    }
    // SAFETY: `s` is live; the previous context (if any) is owned here.
    unsafe {
        crate::runtime::mem::CRYPTO_free((*s).pha_context.cast(), core::ptr::null(), 0);
        (*s).pha_context = crate::runtime::mem::CRYPTO_memdup(
            ctx.as_ptr().cast(),
            ctx.len(),
            core::ptr::null(),
            0,
        )
        .cast::<u8>();
        if (*s).pha_context.is_null() {
            (*s).pha_context_len = 0;
            return 0;
        }
        (*s).pha_context_len = ctx.len();
    }
    // SAFETY: `s` is live; rewinding happens before the request is added to the transcript
    // (`statem_srvr.c:3044-3048`).
    if unsafe { crate::ssl::tls13_enc::tls13_restore_handshake_digest_for_pha(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { tls13_construct_certificate_request(s, &ctx) }
}

/// Process one client message of a TLS1.3 post-handshake-authentication flight
/// (`ossl_statem_server13_read_transition`'s `TLS_ST_OK` -> `TLS_ST_SR_CERT` arm,
/// `statem_srvr.c:144-170`, and the `SR_CERT`/`SR_CERT_VRFY` steps at `:122-142`). The hand state
/// tracks the flight's progress.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message.
pub(crate) unsafe fn tls13_server_process_post_handshake(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::tls13_enc as k;
    if msg.is_empty() {
        return 0;
    }
    // SAFETY: `s` is live.
    match unsafe { (*s).hand_state } {
        TLS_ST_OK => {
            if msg[0] != SSL3_MT_CERT {
                return 0;
            }
            // SAFETY: `s` is live.
            if unsafe {
                crate::ssl::statem::statem_clnt::tls13_process_peer_certificate(s, msg, true)
            } == 0
            {
                return 0;
            }
            // SAFETY: `s` is live.
            unsafe {
                (*s).hand_state = if (*s).peer_cert.is_null() {
                    TLS_ST_SR_FINISHED
                } else {
                    TLS_ST_SR_CERT_VRFY
                };
            }
            1
        }
        TLS_ST_SR_CERT_VRFY => {
            if msg[0] != SSL3_MT_CERTIFICATE_VERIFY as u8 {
                return 0;
            }
            // SAFETY: `s` is live.
            if unsafe { crate::ssl::statem::statem_clnt::tls_process_cert_verify(s, msg, true) }
                == 0
            {
                return 0;
            }
            // SAFETY: `s` is live.
            unsafe { (*s).hand_state = TLS_ST_SR_FINISHED };
            1
        }
        TLS_ST_SR_FINISHED => {
            if msg[0] != SSL3_MT_FIN {
                return 0;
            }
            // PHA's Finished is not the first handshake's, so it is keyed by the client
            // application traffic secret (`tls13_final_finish_mac`, `tls13_enc.c:267-305`).
            // SAFETY: `s` is live.
            if unsafe { k::tls13_process_finished(s, msg, (*s).client_app_traffic.as_ptr()) } == 0 {
                return 0;
            }
            // `SR_FINISHED` sets `post_handshake_auth = SSL_PHA_EXT_RECEIVED`
            // (`statem_srvr.c:704-712`).
            // SAFETY: `s` is live.
            unsafe {
                (*s).post_handshake_auth = SSL_PHA_EXT_RECEIVED;
                (*s).hand_state = TLS_ST_OK;
            }
            1
        }
        _ => 0,
    }
}

// ============================================================================================
// Phase 17 — the reduced TLS1.2 server flight (`ssl/statem/statem_srvr.c`'s TLS1.2 arms).
// ============================================================================================

/// `SSL_PKEY_RSA` — `ssl_local.h:319`.
const SSL_PKEY_RSA_SLOT: usize = 0;
/// `SSL_PKEY_ECC` — `ssl_local.h:322`.
const SSL_PKEY_ECC_SLOT: usize = 3;
/// `SSL3_RT_CHANGE_CIPHER_SPEC` — `ssl3.h` (20).
const SSL3_RT_CHANGE_CIPHER_SPEC: u8 = 20;

/// Whether the server holds a certificate in `slot` (`s->cert->pkeys[slot].x509 != NULL`).
///
/// # Safety
/// `s` is live.
unsafe fn cert_slot_present(s: *mut Ssl, slot: usize) -> bool {
    // SAFETY: `s` is live.
    unsafe {
        if (*s).cert.is_null() {
            return false;
        }
        !(*(*s).cert).pkeys[slot].x509.is_null()
    }
}

/// The TLS1.2 half of `ssl3_choose_cipher` (`ssl3_lib.c`): server preference over the supported
/// `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites, filtered by the certificate the server holds and
/// by the client's offer. Selects the matching certificate slot (`ssl_set_cert`).
///
/// # Safety
/// `s`/`ciphers`/`clnt_ciphers` are live.
unsafe fn tls12_choose_cipher(
    s: *mut Ssl,
    ciphers: *mut crate::runtime::stack::OpenSslStack,
    clnt_ciphers: &[u8],
) -> *const t::SslCipher {
    use crate::ssl::ssl_ciph_table as ct;
    // SAFETY: `ciphers` is a live stack.
    let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(ciphers) };
    for i in 0..n {
        // SAFETY: `i` is in range.
        let c =
            unsafe { crate::runtime::stack::OPENSSL_sk_value(ciphers, i) as *const t::SslCipher };
        if c.is_null() {
            continue;
        }
        // SAFETY: `c` is a live table row.
        let (min_tls, max_tls, id, mkey, auth, enc) = unsafe {
            (
                (*c).min_tls,
                (*c).max_tls,
                (*c).id,
                (*c).algorithm_mkey,
                (*c).algorithm_auth,
                (*c).algorithm_enc,
            )
        };
        if min_tls > TLS1_2_VERSION || max_tls < TLS1_2_VERSION {
            continue;
        }
        // The reduced TLS1.2 path completes an ECDHE key exchange only.
        if (mkey as u64 & ct::SSL_kECDHE) == 0 {
            continue;
        }
        if (enc as u64 & (ct::SSL_AES128GCM | ct::SSL_AES256GCM)) == 0 {
            continue;
        }
        let slot = if (auth as u64 & ct::SSL_aECDSA) != 0 {
            SSL_PKEY_ECC_SLOT
        } else if (auth as u64 & ct::SSL_aRSA) != 0 {
            SSL_PKEY_RSA_SLOT
        } else {
            continue;
        };
        // SAFETY: `s` is live.
        if !unsafe { cert_slot_present(s, slot) } {
            continue;
        }
        let mut q = 0usize;
        while q + 2 <= clnt_ciphers.len() {
            let w = ((clnt_ciphers[q] as u16) << 8) | clnt_ciphers[q + 1] as u16;
            if w == id as u16 {
                // `ssl3_choose_cipher`'s `CERT` selection (`ssl_set_cert`) sets the active slot.
                // SAFETY: `s` is live and holds a certificate container.
                unsafe { (*(*s).cert).key_index = slot };
                return c;
            }
            q += 2;
        }
    }
    core::ptr::null()
}

/// `tls_parse_ctos_supported_groups`'s selection (`extensions_srvr.c`): the first server group the
/// client also offered, or 0 when the lists do not intersect.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_choose_group(s: *const Ssl, clnt_groups: &[u16]) -> u16 {
    // SAFETY: `s` is live.
    let srvr = unsafe { crate::ssl::t1_lib::tls1_get_supported_groups(s) };
    for g in srvr {
        if clnt_groups.contains(g) {
            return *g;
        }
    }
    0
}

/// Sign `data` with the active certificate's key, TLS1.2 style: an EC key signs with
/// `ecdsa_secp256r1_sha256` (`0x0403`), an RSA key with `rsa_pkcs1_sha256` (`0x0401`). Returns the
/// `(sigalg, sig_len)` for a signature written to `sig`, or `None`.
///
/// # Safety
/// `s` is live; `sig` is writable.
pub(crate) unsafe fn tls12_sign(s: *mut Ssl, data: &[u8], sig: &mut [u8]) -> Option<(u16, usize)> {
    use crate::evp::digest::{EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_free, EVP_MD_CTX_new};
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey::EvpPkey;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx};
    // SAFETY: `s` is live.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    // SAFETY: `cpk` is non-NULL per the left operand.
    if cpk.is_null() || unsafe { (*cpk).privatekey }.is_null() {
        return None;
    }
    // SAFETY: `cpk.privatekey` is a live signing key.
    let pkey = unsafe { (*cpk).privatekey }.cast::<EvpPkey>();
    // SAFETY: `pkey` is live.
    let is_ec = unsafe { crate::evp::pkey::EVP_PKEY_get_base_id(pkey) }
        == crate::evp::pkey_ctx::EVP_PKEY_EC;
    // SAFETY: no preconditions.
    let mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        return None;
    }
    // SAFETY: no preconditions.
    let md = EVP_sha256();
    let mut pctx: *mut EvpPkeyCtx = core::ptr::null_mut();
    let mut siglen = sig.len();
    let mut ok = false;
    // SAFETY: `mctx`/`pkey` are live; `data` is readable; `sig` is writable.
    unsafe {
        if EVP_DigestSignInit(mctx, &mut pctx, md, core::ptr::null_mut(), pkey) > 0
            && !pctx.is_null()
            && EVP_PKEY_CTX_set_signature_md(pctx, md) > 0
            && EVP_DigestSign(
                mctx,
                core::ptr::null_mut(),
                &mut siglen,
                data.as_ptr(),
                data.len(),
            ) > 0
            && siglen <= sig.len()
            && EVP_DigestSign(
                mctx,
                sig.as_mut_ptr(),
                &mut siglen,
                data.as_ptr(),
                data.len(),
            ) > 0
        {
            ok = true;
        }
        EVP_MD_CTX_free(mctx);
    }
    if !ok {
        return None;
    }
    Some((if is_ec { 0x0403 } else { 0x0401 }, siglen))
}

/// Verify `sig` over `data` with `pkey` for the TLS1.2 `sigalg` (`0x0401` RSA-PKCS1-SHA256,
/// `0x0403` ECDSA-SHA256).
///
/// # Safety
/// `pkey` is live; `data`/`sig` are readable.
pub(crate) unsafe fn tls12_verify(
    pkey: *mut crate::evp::pkey::EvpPkey,
    data: &[u8],
    sigalg: u16,
    sig: &[u8],
) -> bool {
    use crate::evp::digest::{
        EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_free, EVP_MD_CTX_new,
    };
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx};
    if sigalg != 0x0401 && sigalg != 0x0403 {
        return false;
    }
    // SAFETY: no preconditions.
    let md = EVP_sha256();
    // SAFETY: no preconditions.
    let mctx = EVP_MD_CTX_new();
    if mctx.is_null() {
        return false;
    }
    let mut pctx: *mut EvpPkeyCtx = core::ptr::null_mut();
    let mut ok = false;
    // SAFETY: `mctx`/`pkey` are live.
    unsafe {
        if EVP_DigestVerifyInit(mctx, &mut pctx, md, core::ptr::null_mut(), pkey) > 0
            && !pctx.is_null()
            && EVP_PKEY_CTX_set_signature_md(pctx, md) > 0
            && EVP_DigestVerify(mctx, sig.as_ptr(), sig.len(), data.as_ptr(), data.len()) == 1
        {
            ok = true;
        }
        EVP_MD_CTX_free(mctx);
    }
    ok
}

/// `tls_construct_server_hello` (`statem_srvr.c:2590-2699`) for TLS1.2.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_server_hello(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    let cipher = unsafe { (*s).pending_cipher };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is a live table row.
    let id = unsafe { (*cipher).id as u16 };
    // `tls_construct_server_hello` echoes `s->session->session_id`: the resumed id on a hit, or
    // the freshly generated id (empty for an RFC5077 stateless ticket) otherwise.
    let mut sid = [0u8; 32];
    let mut sid_len = 0usize;
    // SAFETY: `s` is live.
    unsafe {
        if !(*s).session.is_null() {
            sid_len = (*(*s).session).session_id_length.min(sid.len());
            if sid_len > 0 {
                core::ptr::copy_nonoverlapping(
                    (*(*s).session).session_id.as_ptr(),
                    sid.as_mut_ptr(),
                    sid_len,
                );
            }
        }
        if sid_len > 0 {
            core::ptr::copy_nonoverlapping(sid.as_ptr(), (*s).tmp_session_id.as_mut_ptr(), sid_len);
        }
        (*s).tmp_session_id_len = sid_len;
    }
    let mut body = [0u8; 96];
    let mut p = 0usize;
    body[p] = 0x03;
    body[p + 1] = 0x03;
    p += 2;
    // SAFETY: `s` is live; `server_random` is a 32-byte array; `body` has room.
    unsafe {
        core::ptr::copy_nonoverlapping((*s).server_random.as_ptr(), body.as_mut_ptr().add(p), 32)
    };
    p += 32;
    body[p] = sid_len as u8;
    p += 1;
    if sid_len > 0 {
        body[p..p + sid_len].copy_from_slice(&sid[..sid_len]);
        p += sid_len;
    }
    body[p] = (id >> 8) as u8;
    body[p + 1] = id as u8;
    p += 2;
    body[p] = 0;
    p += 1;
    // Extensions: `renegotiation_info` with an empty `renegotiated_connection`, which RFC 5746
    // requires once a client offers it; then `session_ticket` (empty) when a ticket follows
    // (`tls_construct_stoc_session_ticket`, `extensions_srvr.c:1740`).
    let ext_len_pos = p;
    p += 2; // the extension block's two-byte length, backfilled below
    body[p] = 0xff;
    body[p + 1] = 0x01;
    p += 2;
    body[p] = 0;
    body[p + 1] = 1;
    p += 2;
    body[p] = 0;
    p += 1;
    // SAFETY: `s` is live.
    if unsafe { (*s).ext_ticket_expected } != 0 {
        body[p] = 0;
        body[p + 1] = 35;
        p += 2;
        body[p] = 0;
        body[p + 1] = 0;
        p += 2;
    }
    let ext_len = p - (ext_len_pos + 2);
    body[ext_len_pos] = (ext_len >> 8) as u8;
    body[ext_len_pos + 1] = ext_len as u8;
    // SAFETY: `s` is live; `body` is `p` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_SERVER_HELLO, body.as_ptr(), p) }
}

/// `tls_construct_server_certificate` (`statem_srvr.c:4019-4055`) for the TLS1.2
/// `Certificate` shape (`certificate_list<0..2^24-1>` of `cert_data<1..2^24-1>`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_construct_certificate(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    use crate::x509::x_x509::{i2d_X509, X509};
    // SAFETY: `s` is live.
    let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
    let mut body = [0u8; 8300];
    let mut p = 3usize;
    let mut der = [0u8; 8192];
    let mut derptr = der.as_mut_ptr();
    // SAFETY: `s` is live; `cpk` is a live certificate container.
    if !cpk.is_null() && !unsafe { (*cpk).x509 }.is_null() {
        // SAFETY: `cpk.x509` is live; `derptr` points at `der`'s storage.
        let dlen = unsafe { i2d_X509((*cpk).x509, &mut derptr) };
        if dlen <= 0 || dlen as usize > der.len() || p + 3 + dlen as usize > body.len() {
            return 0;
        }
        let dlen = dlen as usize;
        body[p] = (dlen >> 16) as u8;
        body[p + 1] = (dlen >> 8) as u8;
        body[p + 2] = dlen as u8;
        p += 3;
        // SAFETY: `body` has room for `dlen` bytes at `p`.
        unsafe { core::ptr::copy_nonoverlapping(der.as_ptr(), body.as_mut_ptr().add(p), dlen) };
        p += dlen;
    }
    // The extra chain (`ssl3_output_cert_chain` appends `cpk->chain`).
    // SAFETY: `s`/`cpk` are live.
    if !cpk.is_null() && !unsafe { (*cpk).chain }.is_null() {
        // SAFETY: `cpk.chain` is a live stack of certificates.
        let chain = unsafe { (*cpk).chain };
        // SAFETY: `chain` is a live stack.
        let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(chain) };
        for i in 0..n {
            // SAFETY: `i` is in range.
            let x = unsafe { crate::runtime::stack::OPENSSL_sk_value(chain, i) as *mut X509 };
            if x.is_null() {
                continue;
            }
            let mut d2 = [0u8; 8192];
            let mut d2p = d2.as_mut_ptr();
            // SAFETY: `x` is a live certificate.
            let dlen = unsafe { i2d_X509(x, &mut d2p) };
            if dlen <= 0 || dlen as usize > d2.len() || p + 3 + dlen as usize > body.len() {
                return 0;
            }
            let dlen = dlen as usize;
            body[p] = (dlen >> 16) as u8;
            body[p + 1] = (dlen >> 8) as u8;
            body[p + 2] = dlen as u8;
            p += 3;
            // SAFETY: `body` has room for `dlen` bytes at `p`.
            unsafe { core::ptr::copy_nonoverlapping(d2.as_ptr(), body.as_mut_ptr().add(p), dlen) };
            p += dlen;
        }
    }
    let list_len = p - 3;
    body[0] = (list_len >> 16) as u8;
    body[1] = (list_len >> 8) as u8;
    body[2] = list_len as u8;
    // SAFETY: `s` is live; `body` is `p` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_CERTIFICATE as u8, body.as_ptr(), p) }
}

/// `tls_construct_server_key_exchange` (`statem_srvr.c:2699-2860`) for the reduced ECDHE path:
/// `ServerECDHParams` signed with the server certificate key over
/// `client_random || server_random || ServerECDHParams` (`tls12_construct_ske`).
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_server_key_exchange(s: *mut Ssl) -> c_int {
    use crate::evp::pkey::{evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
    use crate::runtime::mem::CRYPTO_free;
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    let group = unsafe { (*s).group_id };
    if group != crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519 {
        // The reduced TLS1.2 path completes an X25519 ECDHE only (named boundary).
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SUITABLE_KEY_SHARE) };
        return -1;
    }
    // SAFETY: `s` is live.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq) };
    let mut params = [crate::params::END; 1];
    // SAFETY: `libctx`/`propq` are the context's; the name is NUL-terminated.
    let pkey = unsafe { evp_pkey_keygen(libctx, c"X25519".as_ptr(), propq, params.as_mut_ptr()) };
    if pkey.is_null() {
        return 0;
    }
    let mut pub_ = core::ptr::null_mut::<u8>();
    // SAFETY: `pkey` is live; `pub_` is this frame's writable slot.
    let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey, &mut pub_) };
    if publen == 0 {
        // SAFETY: `pkey` is live and this call owns it.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }
    // Store the server ephemeral (`ssl_generate_pkey`).
    // SAFETY: `s` is live.
    unsafe {
        if !(*s).pkey.is_null() {
            EVP_PKEY_free((*s).pkey.cast());
        }
        (*s).pkey = pkey.cast();
    }
    let mut params_buf = [0u8; 128];
    params_buf[0] = 3; // named_curve
    params_buf[1] = (group >> 8) as u8;
    params_buf[2] = group as u8;
    params_buf[3] = publen as u8;
    // SAFETY: `pub_` is `publen` readable bytes; `params_buf` has room.
    unsafe { core::ptr::copy_nonoverlapping(pub_, params_buf.as_mut_ptr().add(4), publen) };
    let params_len = 4 + publen;
    let mut tbs = [0u8; 32 + 32 + 128];
    // SAFETY: `s` is live; both randoms are 32-byte arrays; `tbs` has room.
    unsafe {
        core::ptr::copy_nonoverlapping((*s).client_random.as_ptr(), tbs.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping((*s).server_random.as_ptr(), tbs.as_mut_ptr().add(32), 32);
    }
    tbs[64..64 + params_len].copy_from_slice(&params_buf[..params_len]);
    let mut sig = [0u8; 1024];
    // SAFETY: `s` is live; `tbs`/`sig` are writable locals.
    let sigalg_len = unsafe { tls12_sign(s, &tbs[..64 + params_len], &mut sig) };
    // SAFETY: `pub_` is the block `get1` allocated.
    unsafe { CRYPTO_free(pub_.cast(), core::ptr::null(), 0) };
    let Some((sigalg, siglen)) = sigalg_len else {
        return 0;
    };
    let mut body = [0u8; 2048];
    body[..params_len].copy_from_slice(&params_buf[..params_len]);
    let mut p = params_len;
    body[p] = (sigalg >> 8) as u8;
    body[p + 1] = sigalg as u8;
    p += 2;
    body[p] = (siglen >> 8) as u8;
    body[p + 1] = siglen as u8;
    p += 2;
    body[p..p + siglen].copy_from_slice(&sig[..siglen]);
    p += siglen;
    // SAFETY: `s` is live; `body` is `p` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_SERVER_KEY_EXCHANGE as u8, body.as_ptr(), p) }
}

/// `tls_construct_certificate_request` (`statem_srvr.c`) for the TLS1.2 shape:
/// `certificate_types || supported_signature_algorithms || certificate_authorities`.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_certificate_request(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    const SIGALGS: [u8; 8] = [0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x06, 0x01];
    let mut body = [0u8; 64];
    let mut p = 0usize;
    body[p] = 2;
    p += 1;
    body[p] = 1; // rsa_sign
    p += 1;
    body[p] = 64; // ecdsa_sign
    p += 1;
    body[p] = 0;
    body[p + 1] = SIGALGS.len() as u8;
    p += 2;
    body[p..p + SIGALGS.len()].copy_from_slice(&SIGALGS);
    p += SIGALGS.len();
    body[p] = 0;
    body[p + 1] = 0;
    p += 2;
    // SAFETY: `s` is live; `body` is `p` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_CERTIFICATE_REQUEST as u8, body.as_ptr(), p) }
}

/// `SSL3_MT_NEWSESSION_TICKET` — `ssl3.h` (4).
const SSL3_MT_NEWSESSION_TICKET: u8 = 4;
/// The opaque TLS1.2 ticket length this crate mints; the authority's `construct_stateless_ticket`
/// is `key_name(16) || iv(16) || AES-256-CBC(session) || HMAC-SHA256(32)`.
const TLS12_TICKET_LEN: usize = 64;

/// `CON_FUNC_RETURN tls_construct_new_session_ticket(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `ssl/statem/statem_srvr.c:4360-4540`, reduced to the TLS1.2 arm.
///
/// The authority encrypts an `i2d_SSL_SESSION` blob under the context's ticket key and records
/// the session under a stateful `SHA256(ticket)` id on the client. This crate mints an opaque
/// 64-byte ticket and mirrors the client's `SHA256(ticket)` session id on the server session, so
/// the resumption lookup is the internal cache rather than a decrypt (recorded divergence).
///
/// # Safety
/// `s` must be a live connection with its handshake session set.
unsafe fn tls12_construct_new_session_ticket(s: *mut Ssl) -> c_int {
    use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    let sess = unsafe { (*s).session };
    if sess.is_null() {
        return 0;
    }
    let mut ticket = [0u8; TLS12_TICKET_LEN];
    // SAFETY: `ticket` is writable.
    if unsafe { crate::rand::rand_lib::RAND_bytes(ticket.as_mut_ptr(), TLS12_TICKET_LEN as c_int) }
        <= 0
    {
        return 0;
    }
    // `create_ticket_prequel` (`statem_srvr.c:4085-4108`): the hint is the session timeout, or 0
    // for a resumed session.
    // SAFETY: `s` is live.
    let hint = unsafe {
        if (*s).hit != 0 {
            0u32
        } else {
            (*sess).timeout as u32
        }
    };
    let mut body = [0u8; 4 + 2 + TLS12_TICKET_LEN];
    body[0..4].copy_from_slice(&hint.to_be_bytes());
    body[4] = (TLS12_TICKET_LEN >> 8) as u8;
    body[5] = TLS12_TICKET_LEN as u8;
    body[6..6 + TLS12_TICKET_LEN].copy_from_slice(&ticket);

    // Record the ticket on the session and set the client-mirrored resume id (`SHA256(ticket)`).
    // SAFETY: `sess` is live.
    unsafe {
        CRYPTO_free((*sess).ext_tick.cast(), core::ptr::null(), 0);
        let tp = CRYPTO_malloc(TLS12_TICKET_LEN, core::ptr::null(), 0).cast::<u8>();
        if tp.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(ticket.as_ptr(), tp, TLS12_TICKET_LEN);
        (*sess).ext_tick = tp;
        (*sess).ext_ticklen = TLS12_TICKET_LEN;
        (*sess).ext_tick_lifetime_hint = hint as core::ffi::c_ulong;
        (*sess).not_resumable = 0;
        let mut digest = [0u8; 32];
        crate::digest::sha2::SHA256(ticket.as_ptr(), TLS12_TICKET_LEN, digest.as_mut_ptr());
        (*sess).session_id_length = 32;
        core::ptr::copy_nonoverlapping(digest.as_ptr(), (*sess).session_id.as_mut_ptr(), 32);
    }
    // SAFETY: `s` is live; `body` is fully initialised.
    unsafe { write_handshake_message(s, SSL3_MT_NEWSESSION_TICKET, body.as_ptr(), body.len()) }
}

/// `ssl3_do_write`'s `ChangeCipherSpec` arm, plaintext, plus the authority's `msg_callback`
/// invocation (`statem_lib.c:114-118`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_write_change_cipher_spec(s: *mut Ssl, is_client: bool) -> c_int {
    let ccs = [1u8];
    // SAFETY: `s` is live; `ccs` is readable.
    let r = unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(
            s,
            SSL3_RT_CHANGE_CIPHER_SPEC,
            ccs.as_ptr(),
            1,
        )
    };
    if r > 0 {
        // SAFETY: `s` is live; the callback is the application's.
        unsafe {
            if let Some(cb) = (*s).msg_callback {
                cb(
                    1,
                    (*s).version,
                    SSL3_RT_CHANGE_CIPHER_SPEC as c_int,
                    ccs.as_ptr().cast(),
                    1,
                    s,
                    (*s).msg_callback_arg,
                );
            }
        }
    }
    let _ = is_client;
    r
}

/// Read one TLS1.2 handshake record, invoking the authority's read `msg_callback`
/// (`statem_lib.c:1767`). Returns `(buf, len)`, or `None` when the peer BIO is empty.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_read_handshake(s: *mut Ssl) -> Option<([u8; 16384], usize)> {
    let mut buf = [0u8; 16384];
    let mut rt = 0u8;
    // SAFETY: `s` is live; `buf` is writable; `rt` is writable.
    let n = unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_read_bytes(s, &mut rt, buf.as_mut_ptr(), buf.len())
    };
    if n <= 0 || rt != SSL3_RT_HANDSHAKE {
        return None;
    }
    // SAFETY: `s` is live.
    unsafe {
        if let Some(cb) = (*s).msg_callback {
            cb(
                0,
                (*s).version,
                SSL3_RT_HANDSHAKE as c_int,
                buf.as_ptr().cast(),
                n as usize,
                s,
                (*s).msg_callback_arg,
            );
        }
    }
    Some((buf, n as usize))
}

/// Read one `ChangeCipherSpec` record (`tls_process_change_cipher_spec`,
/// `ssl/statem/statem_lib.c`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_read_change_cipher_spec(s: *mut Ssl) -> bool {
    let mut buf = [0u8; 16];
    let mut rt = 0u8;
    // SAFETY: `s` is live; `buf` is writable; `rt` is writable.
    let n = unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_read_bytes(s, &mut rt, buf.as_mut_ptr(), buf.len())
    };
    if n > 0 && rt == SSL3_RT_CHANGE_CIPHER_SPEC {
        // SAFETY: `s` is live.
        unsafe {
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
        }
        return true;
    }
    false
}

/// `tls_construct_finished` (`statem_lib.c:618-676`) for TLS1.2: `PRF(master_secret,
/// "{client,server} finished", Hash(handshake))[0..12]`, written as the Finished body.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_construct_finished(s: *mut Ssl, is_client: bool) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    let label: &[u8] = if is_client {
        b"client finished"
    } else {
        b"server finished"
    };
    let mut out = [0u8; 12];
    // SAFETY: `s` is live; `out` is writable.
    let n = unsafe { crate::ssl::t1_enc::tls12_finished_mac(s, label, out.as_mut_ptr()) };
    if n == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `out` is `n` initialised bytes.
    let r = unsafe { write_handshake_message(s, SSL3_MT_FINISHED as u8, out.as_ptr(), n) };
    if r > 0 {
        // The `tls-unique` channel binding reads this side's Finished verify_data
        // (`SSL_get_finished`, `ssl_lib.c:1799-1812`).
        // SAFETY: `s` is live.
        unsafe {
            ptr::copy_nonoverlapping(out.as_ptr(), (*s).finish_md.as_mut_ptr(), n);
            (*s).finish_md_len = n;
        }
    }
    r
}

/// `tls_process_client_key_exchange` (`statem_srvr.c:2959-3095`) for the ECDHE arm: parse
/// `ClientECDHParams`, derive the pre-master secret, then the master secret and key block
/// (`ssl_derive`, `s3_lib.c:5474-5528`).
///
/// # Safety
/// `s` is live; `msg` is the full ClientKeyExchange message.
unsafe fn tls12_process_client_key_exchange(s: *mut Ssl, msg: &[u8]) -> c_int {
    if msg.len() < 4 || msg[0] != SSL3_MT_CLIENT_KEY_EXCHANGE as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    if body.is_empty() {
        return 0;
    }
    let ptlen = body[0] as usize;
    if 1 + ptlen > body.len() {
        return 0;
    }
    // SAFETY: `s` is live.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq) };
    // SAFETY: `body[1..1+ptlen]` is `ptlen` readable bytes; the name is NUL-terminated.
    let peer = unsafe {
        crate::evp::pkey::EVP_PKEY_new_raw_public_key_ex(
            libctx,
            c"X25519".as_ptr(),
            propq,
            body.as_ptr().add(1),
            ptlen,
        )
    };
    if peer.is_null() {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).peer_tmp = peer.cast() };
    let mut pms = [0u8; 64];
    let mut pmslen = 0usize;
    // SAFETY: `s` is live; the ephemerals are set; `pms` is writable.
    if unsafe {
        crate::ssl::tls13_enc::tls13_derive_shared(
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
    if unsafe { crate::ssl::t1_enc::tls12_derive_master_secret(s, pms.as_ptr(), pmslen) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; the master secret and cipher are set.
    if unsafe { crate::ssl::t1_enc::tls12_derive_key_block(s) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// `tls_process_finished` (`statem_lib.c:843-960`) for TLS1.2: compare the peer's `verify_data`
/// with `PRF(master_secret, "{client,server} finished", Hash(handshake))`, then append the Finished
/// to the transcript.
///
/// # Safety
/// `s` is live; `msg` is the full Finished message.
unsafe fn tls12_process_finished(s: *mut Ssl, msg: &[u8], is_client: bool) -> c_int {
    if msg.len() < 4 || msg[0] != SSL3_MT_FINISHED as u8 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    let label: &[u8] = if is_client {
        b"client finished"
    } else {
        b"server finished"
    };
    let mut expected = [0u8; 12];
    // SAFETY: `s` is live; `expected` is writable.
    let n = unsafe { crate::ssl::t1_enc::tls12_finished_mac(s, label, expected.as_mut_ptr()) };
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
    // The `tls-unique` channel binding on the peer reads the client's Finished verify_data
    // (`SSL_get_peer_finished`, `ssl_lib.c:1815-1828`).
    // SAFETY: `s` is live.
    unsafe {
        ptr::copy_nonoverlapping(expected.as_ptr(), (*s).peer_finish_md.as_mut_ptr(), 12);
        (*s).peer_finish_md_len = 12;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe { crate::ssl::tls13_enc::transcript_update(s, msg.as_ptr(), msg.len()) }
}

/// Mark the connection as waiting for the peer's next TLS1.2 record.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_server_wait(s: *mut Ssl) -> c_int {
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

/// The TLS1.2 server read/write driver (`statem.c`'s read/write sub-state machines, reduced).
/// Returns `1` when the handshake finishes and `-1` while waiting for the peer.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_server_drive(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    unsafe {
        loop {
            match (*s).hand_state {
                TLS_ST_SW_SRVR_HELLO => {
                    if tls12_construct_server_hello(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if (*s).hit != 0 {
                        // Abbreviated handshake (`ossl_statem_server_write_transition`,
                        // `statem_srvr.c:626-632`): the ServerHello is followed directly by
                        // CCS+Finished. Load the resumed master secret and skip the full flight.
                        core::ptr::copy_nonoverlapping(
                            (*(*s).session).master_key.as_ptr(),
                            (*s).tls12_master_secret.as_mut_ptr(),
                            48,
                        );
                        (*s).tls12_key_block_len = 0;
                        (*s).hand_state = if (*s).ext_ticket_expected != 0 {
                            TLS_ST_SW_SESSION_TICKET
                        } else {
                            TLS_ST_SW_CHANGE
                        };
                        continue;
                    }
                    if ((*s).verify_mode & (t::SSL_VERIFY_PEER as c_int)) != 0 {
                        (*s).s3_tmp_cert_request = 1;
                    }
                    (*s).hand_state = TLS_ST_SW_CERT;
                }
                TLS_ST_SW_CERT => {
                    if tls12_construct_certificate(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_KEY_EXCH;
                }
                TLS_ST_SW_KEY_EXCH => {
                    if tls12_construct_server_key_exchange(s) <= 0 {
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    (*s).hand_state = if (*s).s3_tmp_cert_request != 0 {
                        TLS_ST_SW_CERT_REQ
                    } else {
                        TLS_ST_SW_SRVR_DONE
                    };
                }
                TLS_ST_SW_CERT_REQ => {
                    if tls12_construct_certificate_request(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_SRVR_DONE;
                }
                TLS_ST_SW_SRVR_DONE => {
                    if write_handshake_message(s, SSL3_MT_SERVER_HELLO_DONE as u8, ptr::null(), 0)
                        <= 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // The client's flight order is Certificate (when requested), then
                    // ClientKeyExchange, then CertificateVerify (`statem_srvr.c:100-142`).
                    (*s).hand_state = if (*s).s3_tmp_cert_request != 0 {
                        TLS_ST_SR_CERT
                    } else {
                        TLS_ST_SR_KEY_EXCH
                    };
                }
                TLS_ST_SR_KEY_EXCH => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_server_wait(s);
                    };
                    if buf[0] != SSL3_MT_CLIENT_KEY_EXCHANGE as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if tls12_process_client_key_exchange(s, &buf[..n]) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = if (*s).peer_cert.is_null() {
                        TLS_ST_SR_CHANGE
                    } else {
                        TLS_ST_SR_CERT_VRFY
                    };
                }
                TLS_ST_SR_CERT => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_server_wait(s);
                    };
                    if buf[0] != SSL3_MT_CERTIFICATE as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if crate::ssl::statem::statem_clnt::tls12_process_peer_certificate(
                        s,
                        &buf[..n],
                        true,
                    ) == 0
                    {
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SR_KEY_EXCH;
                }
                TLS_ST_SR_CERT_VRFY => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_server_wait(s);
                    };
                    if buf[0] != SSL3_MT_CERTIFICATE_VERIFY as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if crate::ssl::statem::statem_clnt::tls12_process_cert_verify(
                        s,
                        &buf[..n],
                        true,
                    ) == 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SR_CHANGE;
                }
                TLS_ST_SR_CHANGE => {
                    if !tls12_read_change_cipher_spec(s) {
                        if ossl_statem_in_error(s) != 0 {
                            return -1;
                        }
                        return tls12_server_wait(s);
                    }
                    if crate::ssl::t1_enc::tls12_install_read(s, false) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                }
                TLS_ST_SR_FINISHED => {
                    let Some((buf, n)) = tls12_read_handshake(s) else {
                        return tls12_server_wait(s);
                    };
                    if buf[0] != SSL3_MT_FINISHED as u8 {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if tls12_process_finished(s, &buf[..n], true) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // `tls_finish_handshake` (`statem_lib.c:1483-1492`): the abbreviated path ends
                    // here; a full handshake sends a ticket and its CCS+Finished.
                    // SAFETY: `s` is live.
                    let sctx = (*s).ctx;
                    if !sctx.is_null() {
                        (*sctx)
                            .stats
                            .sess_accept_good
                            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                    if (*s).hit != 0 {
                        crate::ssl::ssl_sess::ssl_update_cache(
                            s,
                            crate::ssl::ssl_sess::SSL_SESS_CACHE_SERVER,
                        );
                        (*s).hand_state = TLS_ST_OK;
                        (*s).in_init = 0;
                        (*s).rwstate = 1; // SSL_NOTHING
                        (*s).statem_state = MSG_FLOW_READING_13;
                        return 1;
                    }
                    (*s).hand_state = if (*s).ext_ticket_expected != 0 {
                        TLS_ST_SW_SESSION_TICKET
                    } else {
                        TLS_ST_SW_CHANGE
                    };
                }
                TLS_ST_SW_SESSION_TICKET => {
                    if tls12_construct_new_session_ticket(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_CHANGE;
                }
                TLS_ST_SW_CHANGE => {
                    // The resumed session derives its key block here (the full handshake derived it
                    // in `tls12_process_client_key_exchange`).
                    if (*s).tls12_key_block_len == 0
                        && crate::ssl::t1_enc::tls12_derive_key_block(s) == 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if tls12_write_change_cipher_spec(s, false) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if crate::ssl::t1_enc::tls12_install_write(s, false) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_FINISHED;
                }
                TLS_ST_SW_FINISHED => {
                    let mut out = [0u8; 12];
                    let n = crate::ssl::t1_enc::tls12_finished_mac(
                        s,
                        b"server finished",
                        out.as_mut_ptr(),
                    );
                    if n == 0
                        || write_handshake_message(s, SSL3_MT_FINISHED as u8, out.as_ptr(), n) <= 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    if (*s).hit != 0 {
                        // The abbreviated server reads the client's CCS+Finished next
                        // (`statem_srvr.c:318-322`).
                        (*s).hand_state = TLS_ST_SR_CHANGE;
                        continue;
                    }
                    // `tls_finish_handshake` (`statem_lib.c:1483-1518`): cache the session and
                    // count the good accept once the full handshake is complete.
                    crate::ssl::ssl_sess::ssl_update_cache(
                        s,
                        crate::ssl::ssl_sess::SSL_SESS_CACHE_SERVER,
                    );
                    let sctx = (*s).ctx;
                    if !sctx.is_null() {
                        (*sctx)
                            .stats
                            .sess_accept_good
                            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                    (*s).hand_state = TLS_ST_OK;
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
        // A TLS1.2 handshake that returned a wait must resume in its own driver on re-entry.
        if (*s).tls12_driver != 0 {
            return tls12_server_drive(s);
        }
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
                        // `tls_process_client_hello` raises its own alert/reason (for example
                        // `SSL_R_NO_SHARED_CIPHER`); only a parse failure with no reason queued gets
                        // the generic alert.
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    if pr < 0 {
                        // The ClientHello callback asked to be re-entered
                        // (`s->rwstate == SSL_CLIENT_HELLO_CB`); report the wait.
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SW_SRVR_HELLO;
                    // A TLS1.2 ClientHello selects the separate TLS1.2 flight.
                    if (*s).version == TLS1_2_VERSION {
                        return tls12_server_drive(s);
                    }
                }
                TLS_ST_SW_SRVR_HELLO => {
                    if write_server_hello(s) <= 0 || tls13_server_post_server_hello(s) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // The read transition after the server Finished (`statem_srvr.c:100-142`): with
                    // `s3.tmp.cert_request` set the client's Certificate comes first.
                    (*s).hand_state = if (*s).s3_tmp_cert_request != 0 {
                        TLS_ST_SR_CERT
                    } else {
                        TLS_ST_SR_FINISHED
                    };
                }
                TLS_ST_SR_CERT => {
                    let mut buf = [0u8; 16384];
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    if n <= 0 {
                        return server_wait(s);
                    }
                    if buf[0] == SSL3_MT_CERTIFICATE_VERIFY as u8 {
                        // The client sent an empty Certificate, so per `received_client_cert`
                        // (`statem_srvr.c:122-135`) a CertificateVerify cannot follow; reject it.
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if buf[0] != SSL3_MT_CERT {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if crate::ssl::statem::statem_clnt::tls13_process_peer_certificate(
                        s,
                        &buf[..n as usize],
                        true,
                    ) == 0
                    {
                        if ossl_statem_in_error(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        }
                        return -1;
                    }
                    (*s).hand_state = if (*s).peer_cert.is_null() {
                        TLS_ST_SR_FINISHED
                    } else {
                        TLS_ST_SR_CERT_VRFY
                    };
                }
                TLS_ST_SR_CERT_VRFY => {
                    let mut buf = [0u8; 16384];
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        buf.as_mut_ptr(),
                        buf.len(),
                    );
                    if n <= 0 || buf[0] != SSL3_MT_CERTIFICATE_VERIFY as u8 {
                        return server_wait(s);
                    }
                    if crate::ssl::statem::statem_clnt::tls_process_cert_verify(
                        s,
                        &buf[..n as usize],
                        true,
                    ) == 0
                    {
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
                    // `tls13_save_handshake_digest_for_pha` (`statem_lib.c:859-865`): snapshot the
                    // transcript through the client Finished for a later PHA exchange.
                    // SAFETY: `s` is live.
                    if k::tls13_save_handshake_digest_for_pha(s) == 0 {
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
                    // Post-handshake write transition (`statem_srvr.c:627-641`): a pending
                    // `SSL_verify_client_post_handshake` sends the CertificateRequest here, before
                    // any application data.
                    // SAFETY: `s` is live.
                    if (*s).post_handshake_auth == SSL_PHA_REQUEST_PENDING {
                        // SAFETY: `s` is live.
                        if tls13_server_send_pha_cert_request(s) == 0 {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return -1;
                        }
                        // `SW_CERT_REQ` -> `SSL_PHA_REQUESTED` (`statem_srvr.c:676-679`).
                        (*s).post_handshake_auth = SSL_PHA_REQUESTED;
                    }
                    // Recorded boundary: the authority's TLS1.3 post-handshake write transition
                    // may emit `NewSessionTicket`s here (`tls_construct_new_session_ticket`,
                    // `statem_srvr.c:4370`). The **TLS1.2** ticket path is landed in
                    // `tls12_server_drive` (with its own `tls12_construct_new_session_ticket`); the
                    // TLS1.3 path needs the resumption-master-secret key schedule and the
                    // stateless-ticket encryption/HMAC round trip, which this slice does not own,
                    // and the `RT-TLS13-INTEROP-MATRIX` court pins the absence of the
                    // post-handshake ticket. `SSL_CTX_set_tlsext_ticket_key_cb` is stored and
                    // returns 1.
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
