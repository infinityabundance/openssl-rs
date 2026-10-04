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

use core::ffi::c_int;

use crate::packet::Wpacket;
use crate::ssl::ssl_ciph_table as t;
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::statem::statem::ossl_statem_fatal;

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
const ERR_R_INTERNAL_ERROR: c_int = 1 | (2 << 18) | (1 << 18);
const SSL_R_UNEXPECTED_MESSAGE: c_int = 245;
const SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE: c_int = 205;

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
    p += 1 + comp_len;
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
    let mut off = 0usize;
    while off + 4 <= exts.len() {
        let etype = ((exts[off] as u16) << 8) | exts[off + 1] as u16;
        let elen = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
        off += 4;
        if off + elen > exts.len() {
            return 0;
        }
        let eb = &exts[off..off + elen];
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
        if etype == TLSEXT_TYPE_KEY_SHARE && eb.len() >= 4 {
            // The first ClientHello key share's group.
            saw_keyshare_group = ((eb[0] as u16) << 8) | eb[1] as u16;
        }
        off += elen;
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
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(
            s,
            SSL3_RT_HANDSHAKE,
            buf.as_ptr(),
            msglen,
        )
    }
}
