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
use crate::runtime::foreign::OwnedCtx;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::owned_str::OwnedCStr;
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
const SSL3_MT_CERTIFICATE_STATUS: c_int = 22;
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

/// The largest RSA modulus the TLS1.2 ClientKeyExchange writer accepts: 16384 bits, the
/// authority's `OPENSSL_RSA_MAX_MODULUS_BITS` (`rsa.h:39`). The handshake writer's own body bound
/// is larger, so this is the limit that keeps the CKE scratch bounded while accepting every key
/// the provider can generate.
pub(crate) const TLS12_MAX_RSA_BYTES: usize = 2048;

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
/// `SSL_R_NO_SUITABLE_KEY_SHARE` — `sslerr.h:215` (101). The value 380 is
/// `SSL_R_ILLEGAL_SUITEB_DIGEST`, which made a TLS1.3 group mismatch report the wrong reason.
const SSL_R_NO_SUITABLE_KEY_SHARE: c_int = 101;
/// `SSL_AD_ILLEGAL_PARAMETER` — `ssl3.h` (47).
#[allow(dead_code)]
const SSL_AD_ILLEGAL_PARAMETER: c_int = 47;
/// `SSL_R_LENGTH_MISMATCH` — `sslerr.h:163` (159).
const SSL_R_LENGTH_MISMATCH: c_int = 159;
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
/// `TLSEXT_TYPE_status_request` — `tls1.h:88`.
const TLSEXT_TYPE_STATUS_REQUEST: u16 = 5;
/// `TLSEXT_TYPE_post_handshake_auth` — `tls1.h:157`.
const TLSEXT_TYPE_POST_HANDSHAKE_AUTH: u16 = 49;
/// `TLSEXT_TYPE_session_ticket` — `tls1.h:148`.
const TLSEXT_TYPE_SESSION_TICKET: u16 = 35;
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
/// the plain-PSK identity-hint arm reduced (module header). `pub(crate)` so the client driver can
/// use the same predicate to know whether a `ServerKeyExchange` follows the Certificate.
pub(crate) fn send_server_key_exchange(s: *mut Ssl) -> bool {
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

/// `int tls_handle_status_request(SSL_CONNECTION *s)` — `statem_srvr.c:2336-2384`.
///
/// Invokes the context's OCSP status callback after the certificate has been chosen, maps the
/// return code to the `status_expected` flag (and the fatal alert), and records whether a response
/// was supplied through `SSL_set_tlsext_status_ocsp_resp` (`SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP`).
///
/// # Safety
/// `s` must be a live connection.
unsafe fn tls_handle_status_request(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe { (*s).ext_status_expected = 0 };
    // SAFETY: `s` is live; `ctx` is its context.
    let (status_type, ctx) = unsafe { ((*s).ext_status_type, (*s).ctx) };
    if status_type != crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_NOTHING && !ctx.is_null() {
        // SAFETY: `ctx` is the live context just read.
        if let Some(cb) = unsafe { (*ctx).status_cb } {
            // The authority only calls the callback when a certificate was selected
            // (`s->s3.tmp.cert != NULL`); the reduced connection's active certificate answers that.
            // SAFETY: `s` is live.
            if unsafe { cert_active_present(s) } {
                // SAFETY: the callback is the application's `int (*)(SSL *, void *)`; `s` and the
                // stored argument are the ones it was installed to receive.
                let ret = unsafe { cb(s, (*ctx).status_arg) };
                match ret {
                    SSL_TLSEXT_ERR_NOACK => {
                        // SAFETY: `s` is live.
                        unsafe { (*s).ext_status_expected = 0 };
                    }
                    SSL_TLSEXT_ERR_OK => {
                        // SAFETY: `s` is live.
                        if unsafe { !(*s).ext_ocsp_resp.is_null() && (*s).ext_ocsp_resp_len > 0 } {
                            // SAFETY: `s` is live.
                            unsafe { (*s).ext_status_expected = 1 };
                        }
                    }
                    _ => {
                        // `SSL_TLSEXT_ERR_ALERT_FATAL` and the default arm.
                        // SAFETY: `s` is live.
                        unsafe {
                            ossl_statem_fatal(
                                s,
                                SSL_AD_INTERNAL_ERROR,
                                crate::runtime::err::err_reasons::SSL_R_CLIENTHELLO_TLSEXT,
                            )
                        };
                        return 0;
                    }
                }
            }
        }
    }
    1
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
            // SAFETY: `s` is live; its `s3_alpn_proposed` member obeys the member-buffer invariant.
            let (proposed, proposed_len) = unsafe { (*s).s3_alpn_proposed() };
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
                        proposed_len as core::ffi::c_uint,
                        (*ctx).alpn_select_cb_arg,
                    )
                };
                if r == SSL_TLSEXT_ERR_OK {
                    // SAFETY: `s` is live; `selected`/`selected_len` name a live buffer and the
                    // `s3_alpn_selected` member obeys the member-buffer invariant.
                    unsafe {
                        use crate::runtime::mem::CRYPTO_memdup;
                        let mut slot = (*s).s3_alpn_selected_slot();
                        slot.clear(core::ptr::null(), 0);
                        let dup = CRYPTO_memdup(
                            selected.cast(),
                            selected_len as usize,
                            core::ptr::null(),
                            0,
                        )
                        .cast::<u8>();
                        if dup.is_null() {
                            ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                            return 0;
                        }
                        slot.store(dup, selected_len as usize);
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

/// A bounds-checked forward cursor over an attacker-supplied byte slice.
///
/// Every accessor answers `None` rather than reading outside `bytes`, so a malformed
/// ClientHello can only end the walk with the authority's error. The cursor is the only
/// The cursor is the only
/// place the extension readers advance an offset; callers never add a length to an index
/// themselves.
///
/// Shared with `statem_clnt.rs` (the ServerHello readers) so the client does not grow a
/// second, subtly different bounds-checked cursor.
pub(crate) struct SliceCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SliceCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes not yet consumed. `pos` is never advanced past `bytes.len()`.
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// Offset of the next unconsumed byte, always within `0..=bytes.len()`.
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Consume exactly `n` bytes, or nothing when they are not all present.
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Consume `n` bytes when present, otherwise consume the remainder and answer `None`.
    /// This mirrors the authority's `PACKET_remaining` readers, which leave an over-long
    /// field as an empty value rather than rejecting the message.
    pub(crate) fn take_or_rest(&mut self, n: usize) -> Option<&'a [u8]> {
        match self.take(n) {
            Some(s) => Some(s),
            None => {
                self.pos = self.bytes.len();
                None
            }
        }
    }

    pub(crate) fn take_u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub(crate) fn take_u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

/// A bounds-checked forward-only writer over a caller-supplied byte block.
///
/// Every method is transactional: it answers `false` when the value does not fit, and on
/// failure the cursor and the underlying buffer are unchanged. Composite operations compute
/// their full extent (prefix plus payload) with checked arithmetic and verify it against the
/// remaining capacity before writing any byte, so they can never leave a length prefix behind
/// whose payload was refused. No method can write outside `out`, so the body writers built on it
/// are safe functions: no argument can make them panic or write out of bounds. A too-small block
/// is a clean `None` at the body-writer seam, which the callers turn into the existing failure
/// return.
struct BytesWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> BytesWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    /// Bytes written so far; `pos` never exceeds `out.len()`.
    fn written(&self) -> usize {
        self.pos
    }

    /// Whether `additional` more bytes could be written, using checked arithmetic so an
    /// overflowing extent is reported as "does not fit" rather than panicking.
    fn has_room(&self, additional: usize) -> bool {
        match self.pos.checked_add(additional) {
            Some(end) => end <= self.out.len(),
            None => false,
        }
    }

    fn put_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.pos.checked_add(bytes.len()) else {
            return false;
        };
        let Some(dst) = self.out.get_mut(self.pos..end) else {
            return false;
        };
        dst.copy_from_slice(bytes);
        self.pos = end;
        true
    }

    fn put_u8(&mut self, value: u8) -> bool {
        self.put_bytes(&[value])
    }

    fn put_u16(&mut self, value: u16) -> bool {
        self.put_bytes(&value.to_be_bytes())
    }

    /// `length(1) || bytes`, with the length derived from the slice and refused when it
    /// cannot be expressed in one byte. Transactional: a refused length or extent writes nothing.
    fn put_u8_len_prefixed(&mut self, bytes: &[u8]) -> bool {
        let Ok(len) = u8::try_from(bytes.len()) else {
            return false;
        };
        let Some(extent) = bytes.len().checked_add(1) else {
            return false;
        };
        if !self.has_room(extent) {
            return false;
        }
        self.put_u8(len) && self.put_bytes(bytes)
    }

    /// `length(2) || bytes`, with the length derived from the slice. Transactional: a refused
    /// length or extent writes nothing.
    fn put_u16_len_prefixed(&mut self, bytes: &[u8]) -> bool {
        let Ok(len) = u16::try_from(bytes.len()) else {
            return false;
        };
        let Some(extent) = bytes.len().checked_add(2) else {
            return false;
        };
        if !self.has_room(extent) {
            return false;
        }
        self.put_u16(len) && self.put_bytes(bytes)
    }

    /// `u24` big-endian, refused when the value cannot be expressed in three bytes.
    /// Transactional: if all three bytes do not fit, none is written.
    fn put_u24(&mut self, value: usize) -> bool {
        if value > 0xFF_FFFF {
            return false;
        }
        if !self.has_room(3) {
            return false;
        }
        self.put_u8((value >> 16) as u8)
            && self.put_u8((value >> 8) as u8)
            && self.put_u8(value as u8)
    }
}

/// The TLS1.3 `CertificateRequest` body: `context<0..2^8-1> || Extension extensions<0..2^16-1>`
/// (`tls_construct_certificate_request`, `statem_srvr.c:3060-3094`). The only extension the
/// reduced server emits is `signature_algorithms` (`TLSEXT_TYPE_signature_algorithms`); an
/// empty `sigalgs` writes the empty extension vector, matching the authority's zero-length
/// vector branch.
fn write_certificate_request_body(
    out: &mut [u8],
    context: &[u8],
    sigalgs: &[u16],
) -> Option<usize> {
    // `TLSEXT_TYPE_signature_algorithms` — `tls1.h` (13).
    const TLSEXT_TYPE_SIG_ALGS: u16 = 13;
    let mut w = BytesWriter::new(out);
    if !w.put_u8_len_prefixed(context) {
        return None;
    }
    if sigalgs.is_empty() {
        if !w.put_u16(0) {
            return None;
        }
        return Some(w.written());
    }
    let list_len = sigalgs.len().checked_mul(2)?;
    // `extensions_len(2) || type(2) || ext_len(2) || list_len(2) || schemes`, where
    // `ext_len` counts the inner two-byte list length as well.
    let ext_len = list_len.checked_add(2)?;
    let extensions_len = ext_len.checked_add(4)?;
    if !(w.put_u16(u16::try_from(extensions_len).ok()?)
        && w.put_u16(TLSEXT_TYPE_SIG_ALGS)
        && w.put_u16(u16::try_from(ext_len).ok()?)
        && w.put_u16(u16::try_from(list_len).ok()?))
    {
        return None;
    }
    for scheme in sigalgs {
        if !w.put_u16(*scheme) {
            return None;
        }
    }
    Some(w.written())
}

/// The TLS1.3 `Certificate` body: `context<0..2^8-1> || certificate_list<0..2^24-1>`, with
/// each `CertificateEntry` = `cert_data<1..2^24-1> || extensions<0..2^16-1>` (RFC 8446
/// §4.4.2). The reduced server sends no per-entry extensions, so the extension block is the
/// two-byte empty vector. Every length is derived from the supplied slices.
fn write_tls13_certificate_body(out: &mut [u8], context: &[u8], ders: &[&[u8]]) -> Option<usize> {
    let mut list_len = 0usize;
    for der in ders {
        if der.is_empty() || der.len() > 0xFF_FFFF {
            return None;
        }
        list_len = list_len
            .checked_add(3)?
            .checked_add(der.len())?
            .checked_add(2)?;
    }
    if list_len > 0xFF_FFFF {
        return None;
    }
    let mut w = BytesWriter::new(out);
    if !(w.put_u8_len_prefixed(context) && w.put_u24(list_len)) {
        return None;
    }
    for der in ders {
        if !(w.put_u24(der.len()) && w.put_bytes(der) && w.put_u16(0)) {
            return None;
        }
    }
    Some(w.written())
}

/// The TLS1.2 `Certificate` body: `certificate_list<0..2^24-1>` of
/// `cert_data<1..2^24-1>` (`ssl3_output_cert_chain`, `ssl_lib.c`). An empty `ders` is the
/// authority's empty chain: `00 00 00`.
fn write_tls12_certificate_body(out: &mut [u8], ders: &[&[u8]]) -> Option<usize> {
    let mut list_len = 0usize;
    for der in ders {
        if der.is_empty() || der.len() > 0xFF_FFFF {
            return None;
        }
        list_len = list_len.checked_add(3)?.checked_add(der.len())?;
    }
    if list_len > 0xFF_FFFF {
        return None;
    }
    let mut w = BytesWriter::new(out);
    if !w.put_u24(list_len) {
        return None;
    }
    for der in ders {
        if !(w.put_u24(der.len()) && w.put_bytes(der)) {
            return None;
        }
    }
    Some(w.written())
}

/// The TLS1.3 `CertificateVerify` body: `scheme(2) || signature<0..2^16-1>`
/// (`tls_construct_cert_verify`, `statem_lib.c:313-439`).
fn write_cert_verify_body(out: &mut [u8], scheme: [u8; 2], signature: &[u8]) -> Option<usize> {
    let mut w = BytesWriter::new(out);
    if !(w.put_bytes(&scheme) && w.put_u16_len_prefixed(signature)) {
        return None;
    }
    Some(w.written())
}

/// The TLS1.2 `CertificateRequest` body (`tls_construct_certificate_request`,
/// `statem_srvr.c:3023-3094`): `certificate_types<1..2^8-1> ||`
/// `supported_signature_algorithms<0..2^16-1> || certificate_authorities<0..2^16-1>`.
///
/// The signature-algorithm vector is present only when `sigalgs` is `Some`, so a caller
/// that does not advertise schemes writes the authority's shorter shape. Both lengths are
/// derived from the supplied slices and the whole extent is checked before the first byte,
/// so a refused call leaves `out` untouched.
fn write_tls12_certificate_request_body(
    out: &mut [u8],
    certificate_types: &[u8],
    sigalgs: Option<&[u8]>,
) -> Option<usize> {
    let types_len = u8::try_from(certificate_types.len()).ok()?;
    let mut extent = 1usize.checked_add(certificate_types.len())?;
    if let Some(sigalgs) = sigalgs {
        u16::try_from(sigalgs.len()).ok()?;
        extent = extent.checked_add(2)?.checked_add(sigalgs.len())?;
    }
    // `certificate_authorities<0..2^16-1>` is always the empty vector in this reduction.
    extent = extent.checked_add(2)?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_u8(types_len) && w.put_bytes(certificate_types)) {
        return None;
    }
    if let Some(sigalgs) = sigalgs {
        // Lengths above 65535 were refused above, so this conversion cannot fail.
        let Ok(len) = u16::try_from(sigalgs.len()) else {
            return None;
        };
        if !(w.put_u16(len) && w.put_bytes(sigalgs)) {
            return None;
        }
    }
    if !w.put_u16(0) {
        return None;
    }
    Some(w.written())
}

/// The `ServerECDHParams` of a TLS1.2 `ServerKeyExchange` (`tls12_construct_ske`):
/// `curve_type(1) = named_curve || namedcurve(2) || public<1..2^8-1>`.
///
/// The point length is the slice length, refused when it cannot be expressed in one byte
/// rather than truncated. The full extent is checked before writing, so a short buffer or
/// an unrepresentable point leaves `out` untouched.
fn write_tls12_ecdh_params(out: &mut [u8], group: u16, point: &[u8]) -> Option<usize> {
    // `named_curve` — `tls1.h` (`curve_type`).
    const NAMED_CURVE: u8 = 3;
    let point_len = u8::try_from(point.len()).ok()?;
    let extent = point.len().checked_add(4)?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_u8(NAMED_CURVE) && w.put_u16(group) && w.put_u8(point_len) && w.put_bytes(point)) {
        return None;
    }
    Some(w.written())
}

/// The signed data of a TLS1.2 `ServerKeyExchange` over ECDHE:
/// `client_random(32) || server_random(32) || ServerECDHParams`
/// (`tls12_construct_ske`, `statem_srvr.c:2828-2860`). The fixed-size randoms make the
/// prefix extent type-checked; the whole sum still uses checked arithmetic.
fn write_tls12_ske_signature_input(
    out: &mut [u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    params: &[u8],
) -> Option<usize> {
    let extent = client_random
        .len()
        .checked_add(server_random.len())?
        .checked_add(params.len())?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_bytes(client_random) && w.put_bytes(server_random) && w.put_bytes(params)) {
        return None;
    }
    Some(w.written())
}

/// The framed TLS1.2 `ServerKeyExchange` body:
/// `ServerECDHParams || SignatureAndHashAlgorithm(2) || signature<0..2^16-1>`.
fn write_tls12_ske_body(
    out: &mut [u8],
    params: &[u8],
    sigalg: u16,
    signature: &[u8],
) -> Option<usize> {
    let extent = params.len().checked_add(4)?.checked_add(signature.len())?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_bytes(params) && w.put_u16(sigalg) && w.put_u16_len_prefixed(signature)) {
        return None;
    }
    Some(w.written())
}

/// The TLS1.2 `NewSessionTicket` body (`create_ticket_prequel`,
/// `statem_srvr.c:4085-4108`): `ticket_lifetime_hint(4) || ticket<0..2^16-1>`.
fn write_tls12_new_session_ticket_body(
    out: &mut [u8],
    lifetime_hint: u32,
    ticket: &[u8],
) -> Option<usize> {
    let ticket_len = u16::try_from(ticket.len()).ok()?;
    let extent = 4usize.checked_add(2)?.checked_add(ticket.len())?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_bytes(&lifetime_hint.to_be_bytes()) && w.put_u16(ticket_len) && w.put_bytes(ticket))
    {
        return None;
    }
    Some(w.written())
}

/// The TLS1.3 `NewSessionTicket` body (RFC 8446 §4.6.1, `create_ticket_prequel`,
/// `statem_srvr.c:4085-4111`): `ticket_lifetime(4) || ticket_age_add(4) ||
/// ticket_nonce<0..255> || ticket<0..2^16-1> || extensions<0..2^16-1>`.
fn write_tls13_new_session_ticket_body(
    out: &mut [u8],
    nonce: &[u8],
    lifetime: u32,
    age_add: u32,
    ticket: &[u8],
    extensions: &[u8],
) -> Option<usize> {
    // Every length prefix is validated before the first byte is written, so a refused value
    // leaves `out` untouched.
    u8::try_from(nonce.len()).ok()?;
    u16::try_from(ticket.len()).ok()?;
    u16::try_from(extensions.len()).ok()?;
    let extent = 4usize
        .checked_add(4)?
        .checked_add(1)?
        .checked_add(nonce.len())?
        .checked_add(2)?
        .checked_add(ticket.len())?
        .checked_add(2)?
        .checked_add(extensions.len())?;
    let mut w = BytesWriter::new(out);
    if !w.has_room(extent) {
        return None;
    }
    if !(w.put_bytes(&lifetime.to_be_bytes())
        && w.put_bytes(&age_add.to_be_bytes())
        && w.put_u8_len_prefixed(nonce)
        && w.put_u16_len_prefixed(ticket)
        && w.put_u16_len_prefixed(extensions))
    {
        return None;
    }
    Some(w.written())
}

/// The TLS1.2 `ServerHelloDone` body: empty (`tls_construct_server_hello_done`).
const TLS12_SERVER_HELLO_DONE_BODY: &[u8] = &[];

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
/// `TLSEXT_TYPE_pre_shared_key` — `tls1.h:163`.
const TLSEXT_TYPE_PSK: u16 = 41;
/// `TLSEXT_TYPE_psk_key_exchange_modes` — `tls1.h:165`.
const TLSEXT_TYPE_PSK_KEX_MODES: u16 = 45;
/// `TLSEXT_KEX_MODE_FLAG_KE_DHE` — `tls1.h` (`psk_dhe_ke`).
const TLSEXT_KEX_MODE_FLAG_KE_DHE: u8 = 1;

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

    let mut cur = SliceCursor::new(body);
    // legacy_version (2) + random (32).
    let Some(legacy) = cur.take(2) else {
        return 0;
    };
    let legacy_version = ((legacy[0] as c_int) << 8) | legacy[1] as c_int;
    let Some(random) = cur.take(32) else {
        return 0;
    };
    // SAFETY: `random` is a 32-byte slice; `client_random` is a 32-byte array.
    unsafe { (*s).client_random.copy_from_slice(random) };
    // session_id (1 + n): the TLSv1.3 ServerHello echoes it (`statem_srvr.c:2064-2068`).
    let Some(sid_len) = cur.take_u8() else {
        return 0;
    };
    let Some(session_id) = cur.take(sid_len as usize) else {
        return 0;
    };
    // The authority rejects an id longer than `SSL_MAX_SSL_SESSION_ID_LENGTH` rather than
    // truncating it. A regular TLS ClientHello (our path) is not an SSLv2-compatible record
    // (`clienthello->isv2 = RECORD_LAYER_is_sslv2_record(...)`, `statem_srvr.c:1682`), so it
    // takes the `else` arm at `statem_srvr.c:1776-1781`: `PACKET_copy_all` into the 32-byte
    // buffer fails and the authority raises `SSL_AD_DECODE_ERROR` / `SSL_R_LENGTH_MISMATCH`.
    // The reduced reader previously clamped to 32; it now matches that arm.
    if session_id.len() > crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH) };
        return 0;
    }
    // SAFETY: `s` is live; `session_id` has exactly `tmp_session_id`'s (32-byte) capacity or less.
    unsafe {
        (&mut (*s).tmp_session_id)[..session_id.len()].copy_from_slice(session_id);
        (*s).tmp_session_id_len = session_id.len();
    }
    // cipher_suites (2 + n).
    let Some(cip_len) = cur.take_u16() else {
        return 0;
    };
    let Some(clnt_ciphers) = cur.take(cip_len as usize) else {
        return 0;
    };
    // compression_methods (1 + n). A body that ends inside the vector leaves the list empty,
    // exactly as the previous `p + comp_len <= body.len()` reader did, and the extension
    // reader then sees the truncated remainder (so no extensions are parsed).
    let Some(comp_len) = cur.take_u8() else {
        return 0;
    };
    let compressions: &[u8] = cur.take_or_rest(comp_len as usize).unwrap_or(&[]);
    // extensions (2 + n), if present. `exts_at` records the sub-slice's offset within `body`, so
    // the binder transcript offset below needs no pointer-to-integer subtraction.
    let mut exts_at = 0usize;
    let exts: &[u8] = match cur.take_u16() {
        Some(ext_len) => {
            let at = cur.pos();
            let Some(exts) = cur.take(ext_len as usize) else {
                return 0;
            };
            exts_at = at;
            exts
        }
        None => &[],
    };

    // Choose the server version and the key-exchange group from the extensions.
    let mut wants_tls13 = false;
    let mut sup_versions = [0u16; 8];
    let mut sup_versions_cnt = 0usize;
    let mut clnt_groups = [0u16; 32];
    let mut clnt_group_cnt = 0usize;
    let mut saw_keyshare_group: u16 = 0;
    let mut client_share: &[u8] = &[];
    // The `pre_shared_key` extension (`tls_parse_ctos_psk`, `extensions_srvr.c:1310`): the first
    // identity's ticket bytes and binder, and the byte offset of the `binders` vector within the
    // ClientHello message (the binder transcript ends there).
    let mut psk_identity: &[u8] = &[];
    let mut psk_binder: &[u8] = &[];
    let mut psk_binderoffset: usize = 0;
    let mut saw_psk = false;
    let mut psk_kex_dhe = false;
    let mut sni_sent = false;
    // `tls_get_ticket_from_client` (`t1_lib.c:2996-3010`): `ticket_expected` is only armed when
    // the ClientHello actually carries the `session_ticket` extension. The previous unconditional
    // arm made the server announce and issue a ticket to a client that had disabled them
    // (`s_client -no_ticket`), which is the unsolicited-extension defect.
    let mut ticket_ext_present = false;
    let mut walk = SliceCursor::new(exts);
    while walk.remaining() >= 4 {
        // `remaining() >= 4` makes the type and length reads infallible; the body read is the
        // one bounds check that decides acceptance, and it answers `None` rather than reading
        // past the extension block.
        let (Some(etype_bytes), Some(elen_bytes)) = (walk.take(2), walk.take(2)) else {
            return 0;
        };
        let etype = u16::from_be_bytes([etype_bytes[0], etype_bytes[1]]);
        let elen = u16::from_be_bytes([elen_bytes[0], elen_bytes[1]]) as usize;
        let ext_body_off = walk.pos();
        let Some(eb) = walk.take(elen) else {
            return 0;
        };
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
            // SAFETY: `s` is live; `eb[5..5 + nlen]` holds `nlen` readable bytes with no
            // interior NUL, so `CRYPTO_strndup` copies exactly `nlen` bytes and appends the
            // terminator, and the `ext_hostname` member obeys the member-buffer invariant.
            unsafe {
                let mut slot = (*s).ext_hostname_slot();
                let empty = slot.clear(SeamFile::NULL, 0);
                let Some(dup) =
                    OwnedCStr::strndup(eb[5..5 + nlen].as_ptr().cast(), nlen, SeamFile::NULL, 0)
                else {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                };
                empty.store(dup);
            }
            sni_sent = true;
        }
        if etype == TLSEXT_TYPE_STATUS_REQUEST {
            // `tls_parse_ctos_status_request` (`extensions_srvr.c:329-424`):
            // `status_type(1) || responder_id_list<2> || request_extensions<2>`. The responder-id
            // and extension bodies are validated for length but not retained: the reduced server
            // only needs the status type for `tls_handle_status_request`.
            if eb.is_empty() {
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            }
            let status_type = eb[0] as c_int;
            if status_type != crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_OCSP {
                // Unknown type: the authority resets it to nothing and ignores the extension.
                // SAFETY: `s` is live.
                unsafe { (*s).ext_status_type = crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_NOTHING };
            } else {
                if eb.len() < 5 {
                    // SAFETY: `s` is live.
                    unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                    return 0;
                }
                let ids_len = ((eb[1] as usize) << 8) | eb[2] as usize;
                let exts_at = 3 + ids_len;
                if exts_at + 2 > eb.len() {
                    // SAFETY: `s` is live.
                    unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                    return 0;
                }
                let req_len = ((eb[exts_at] as usize) << 8) | eb[exts_at + 1] as usize;
                if exts_at + 2 + req_len != eb.len() {
                    // SAFETY: `s` is live.
                    unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                    return 0;
                }
                // SAFETY: `s` is live.
                unsafe { (*s).ext_status_type = crate::ssl::ssl_lib::TLSEXT_STATUSTYPE_OCSP };
            }
        }
        if etype == TLSEXT_TYPE_SUPPORTED_VERSIONS && eb.len() >= 3 {
            // The body is `list_len || (version_hi || version_lo)...`. The declared list may
            // overrun the extension; the walk stops at the shorter of the two, as the
            // authority's `PACKET_remaining` loop does.
            let list_len = eb[0] as usize;
            let end = 1 + list_len.min(eb.len() - 1);
            let mut versions = SliceCursor::new(&eb[1..end]);
            while let Some(v) = versions.take_u16() {
                if sup_versions_cnt < sup_versions.len() {
                    sup_versions[sup_versions_cnt] = v;
                    sup_versions_cnt += 1;
                }
                if v == TLS1_3_VERSION as u16 {
                    // `tls_parse_ctos_supported_versions` records the request; the version itself
                    // is resolved after the whole extension walk (`tls_early_post_process_client_hello`).
                    wants_tls13 = true;
                }
            }
        }
        if etype == TLSEXT_TYPE_SUPPORTED_GROUPS && eb.len() >= 2 {
            // `tls_parse_ctos_supported_groups` (`extensions_srvr.c`): the `NamedGroupList`.
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            let end = (2 + list_len).min(eb.len());
            let mut groups = SliceCursor::new(&eb[2..end]);
            while clnt_group_cnt < clnt_groups.len() {
                let Some(g) = groups.take_u16() else {
                    break;
                };
                clnt_groups[clnt_group_cnt] = g;
                clnt_group_cnt += 1;
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
            // SAFETY: `s` is live; `list` is `list_len` readable bytes and the `s3_alpn_proposed`
            // member obeys the member-buffer invariant.
            unsafe {
                use crate::runtime::mem::CRYPTO_memdup;
                let mut slot = (*s).s3_alpn_proposed_slot();
                slot.clear(core::ptr::null(), 0);
                let dup = CRYPTO_memdup(list.as_ptr().cast(), list.len(), core::ptr::null(), 0)
                    .cast::<u8>();
                if dup.is_null() {
                    ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                slot.store(dup, list.len());
            }
        }
        if etype == TLSEXT_TYPE_SESSION_TICKET {
            // `tls_parse_ctos_session_ticket` (`extensions_srvr.c`): presence alone arms the
            // issue-on-miss path; the stateful ticket reduction keys resumption by session id.
            ticket_ext_present = true;
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
            // X25519). The declared list length bounds where an entry may *start*; an entry's
            // key may still run to the end of the extension, as the authority's reader allows.
            let list_len = ((eb[0] as usize) << 8) | eb[1] as usize;
            let list_end = (2 + list_len).min(eb.len());
            let mut shares = SliceCursor::new(eb);
            let _ = shares.take(2); // the list length word, already read
            while shares.pos() + 4 <= list_end {
                let (Some(g_bytes), Some(klen_bytes)) = (shares.take(2), shares.take(2)) else {
                    break;
                };
                let g = u16::from_be_bytes([g_bytes[0], g_bytes[1]]);
                let klen = u16::from_be_bytes([klen_bytes[0], klen_bytes[1]]) as usize;
                let Some(key) = shares.take(klen) else {
                    break;
                };
                if g == crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519 && klen == 32 {
                    saw_keyshare_group = g;
                    client_share = key;
                    break;
                }
            }
        }
        if etype == TLSEXT_TYPE_PSK_KEX_MODES && !eb.is_empty() {
            // `tls_parse_ctos_psk_kex_modes` (`extensions_srvr.c:568`): `PskKeyExchangeModes` is
            // `ke_modes<1..255>`; only `psk_dhe_ke` is honoured (a `psk_ke`-only offer is a
            // recorded boundary).
            let list_len = eb[0] as usize;
            for &mode in eb[1..].iter().take(list_len) {
                if mode == TLSEXT_KEX_MODE_FLAG_KE_DHE {
                    psk_kex_dhe = true;
                }
            }
        }
        if etype == TLSEXT_TYPE_PSK && eb.len() >= 2 {
            // `tls_parse_ctos_psk` (`extensions_srvr.c:1310`): the body is
            // `identities<2>(identity<2> || obfuscated_ticket_age(4)) || binders<2>(binder<1>)`.
            let mut psk = SliceCursor::new(eb);
            let ids_len = psk.take_u16().unwrap_or(0) as usize;
            let ids = psk.take(ids_len);
            let binders_len = psk.take_u16();
            let (Some(ids), Some(blen)) = (ids, binders_len) else {
                // The identities vector runs past the extension, or no binders vector follows
                // it: the authority refuses the whole extension here.
                // SAFETY: `s` is live.
                unsafe { ossl_statem_fatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION) };
                return 0;
            };
            let blen = blen as usize;
            if let Some(bvec) = psk.take(blen) {
                if ids.len() >= 2 && blen >= 1 {
                    let idlen = ((ids[0] as usize) << 8) | ids[1] as usize;
                    if idlen != 0 && 2 + idlen + 4 <= ids.len() {
                        let binder_len = bvec[0] as usize;
                        if binder_len != 0 && binder_len < bvec.len() {
                            psk_identity = &ids[2..2 + idlen];
                            psk_binder = &bvec[1..1 + binder_len];
                            // Absolute offset of the `binders` vector within the ClientHello
                            // message (the binder transcript ends at the vector's own length
                            // prefix): the 4-byte handshake header, then the extension block,
                            // then this extension, then the vector. The operands are offsets
                            // into the same `hs` slice, so the sum is checked rather than
                            // assumed.
                            let Some(abs) = 4usize
                                .checked_add(exts_at)
                                .and_then(|v| v.checked_add(ext_body_off))
                                .and_then(|v| v.checked_add(ids_len + 2))
                            else {
                                return 0;
                            };
                            psk_binderoffset = abs;
                            saw_psk = true;
                        }
                    }
                }
            }
        }
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
        // `tls_early_post_process_client_hello` records the ClientHello's legacy version as
        // `s->client_version` (`statem_srvr.c:1913`); the static-RSA padding check and the
        // `EncryptedPreMasterSecret` version bytes both read it.
        (*s).client_version = legacy_version;
        (*s).method = if session_version == TLS1_3_VERSION {
            crate::ssl::methods::tls13_method(true)
        } else {
            crate::ssl::methods::tls12_method(true)
        };
    }

    // `tls_early_post_process_client_hello` (`statem_srvr.c:2042-2068`): for TLS1.2, look for a
    // previous session in the internal cache and, failing that, create the handshake session.
    // For TLS1.3 `ssl_get_prev_session` first sets `ext.ticket_expected` to 1 by default
    // (`ssl_sess.c:593-601`); the PSK arm of the lookup is the resumption slice's, so a fresh
    // session is created here, exactly as `statem_srvr.c:2055-2059` does on a miss.
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
        // SAFETY: `s` is live; `session_id` is the ClientHello's session-id slice and
        // `ticket_ext_present` records the extension walk above.
        let prev = unsafe {
            crate::ssl::ssl_sess::ssl_get_prev_session(s, session_id, ticket_ext_present)
        };
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
    } else {
        // `ssl_get_prev_session` (`ssl_sess.c:595-601`): for TLS1.3 a new ticket is sent by
        // default; the PSK lookup is the resumption slice's. `ssl_setup_handshake`'s first-handshake
        // counter (`statem_lib.c:222-224`) is incremented here too.
        // SAFETY: `s` is live.
        unsafe {
            (*s).ext_ticket_expected = 1;
            if (*s).options & crate::ssl::ssl_ciph_table::SSL_OP_NO_TICKET != 0 {
                (*s).ext_ticket_expected = 0;
            }
            if is_first_handshake(s) {
                let sc = (*s).session_ctx;
                if !sc.is_null() {
                    (*sc)
                        .stats
                        .sess_accept
                        .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            }
            if crate::ssl::ssl_sess::ssl_get_new_session(s, 1) == 0 {
                return 0;
            }
        }
    }

    // `tls_parse_ctos_psk` + `ssl_get_prev_session`'s TLS1.3 arm: a `pre_shared_key` offer whose
    // stateless ticket decrypts and whose binder verifies selects the resumed session. The ticket
    // is the authority's encrypted `i2d_SSL_SESSION` (`tls_decrypt_ticket`, `t1_lib.c:3041`). A
    // `psk_ke`-only offer is a recorded boundary and falls back to a full handshake.
    if session_version == TLS1_3_VERSION && saw_psk && psk_kex_dhe && !psk_identity.is_empty() {
        // SAFETY: `s` is live; `psk_identity` is the ticket bytes.
        let looked = unsafe { tls13_decrypt_ticket(s, psk_identity) };
        if !looked.is_null() {
            // SAFETY: `looked` is a live, reference-owning session.
            unsafe {
                let kind = crate::ssl::tls13_enc::tls13_cipher_md_kind((*looked).cipher_id as u16);
                // A ticket cannot produce a length past the session's own key buffer, but the
                // slice is bounded explicitly so a corrupt session cannot request an
                // out-of-range read. Clamping can only act on an already-invalid session.
                let psk_len = (*looked).master_key_length.min((*looked).master_key.len());
                let mut ok = kind >= 0 && psk_len > 0 && (*looked).ssl_version == TLS1_3_VERSION;
                if ok {
                    let md = crate::ssl::tls13_enc::tls13_md_for_kind(kind);
                    let mut calc = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
                    let psk = &(&(*looked).master_key)[..psk_len];
                    // `tls_psk_do_binder(..., sign=0, ...)` (`extensions_srvr.c:1523`).
                    if crate::ssl::tls13_enc::tls13_psk_do_binder(
                        md,
                        hs.as_ptr(),
                        psk_binderoffset,
                        psk,
                        calc.as_mut_ptr(),
                        false,
                        psk_binder.as_ptr(),
                    ) == 0
                    {
                        ok = false;
                    }
                }
                if ok {
                    let n = psk_len.min((*s).psk_secret.len());
                    (&mut (*s).psk_secret)[..n].copy_from_slice(&(&(*looked).master_key)[..n]);
                    (*s).psk_secret_len = n;
                    (*s).hit = 1;
                    crate::ssl::ssl_sess::SSL_SESSION_free((*s).session);
                    (*s).session = looked;
                    // `ssl_get_prev_session` counts the hit (`ssl_sess.c:740-742`).
                    let sc = (*s).session_ctx;
                    if !sc.is_null() {
                        (*sc)
                            .stats
                            .sess_hit
                            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    crate::ssl::ssl_sess::SSL_SESSION_free(looked);
                }
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
    if session_version == TLS1_3_VERSION
        && unsafe {
            // SAFETY: `s` is live.
            (*s).hit
        } != 0
    {
        // A resumed session forces the session's own ciphersuite (`statem_srvr.c:2160-2180`,
        // `ssl3_choose_cipher`'s resumption arm); it must also be one the client offered, or the
        // PSK hash cannot match and the handshake is abandoned.
        // SAFETY: `s` is live.
        let sess = unsafe { (*s).session };
        if !sess.is_null() {
            // SAFETY: `sess` is live.
            let sc = unsafe { (*sess).cipher };
            if !sc.is_null() {
                // SAFETY: `sc` is a live cipher-table row.
                let sid = unsafe { (*sc).id };
                let mut q = 0usize;
                while q + 2 <= clnt_ciphers.len() {
                    let w = ((clnt_ciphers[q] as u16) << 8) | clnt_ciphers[q + 1] as u16;
                    if w == sid as u16 {
                        chosen = sc;
                        break;
                    }
                    q += 2;
                }
            }
        }
        if chosen.is_null() {
            // The session's suite is unavailable: fall back to a full handshake.
            // SAFETY: `s` is live.
            unsafe {
                (*s).hit = 0;
                (*s).psk_secret_len = 0;
                if crate::ssl::ssl_sess::ssl_get_new_session(s, 1) == 0 {
                    return 0;
                }
            }
        }
    }
    if session_version != TLS1_3_VERSION {
        // The TLS1.2 half of `ssl3_choose_cipher` (`ssl3_lib.c`): server preference over the
        // supported `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites, filtered by the certificate the
        // server actually holds.
        // SAFETY: `s`/`ciphers`/`clnt_ciphers` are live.
        chosen = unsafe { tls12_choose_cipher(s, ciphers, clnt_ciphers) };
    } else if chosen.is_null() {
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
            // `as_chunks::<2>()` walks whole wire suites only (its remainder is ignored, as the
            // previous `q + 2 <= len` pointer walk did). The id is assembled with the same
            // `SSL3_CK_CIPHERSUITE_FLAG | (hi << 8) | lo` rule as `ssl3_get_cipher_by_char`,
            // whose only precondition is the two readable bytes the chunk guarantees.
            for pair in clnt_ciphers.as_chunks::<2>().0 {
                let wire = u16::from_be_bytes(*pair);
                // SAFETY: `ssl3_get_cipher_by_id` has no precondition on the lookup itself.
                let c = crate::ssl::ssl_ciph::ssl3_get_cipher_by_id(
                    t::SSL3_CK_CIPHERSUITE_FLAG as u32 | wire as u32,
                );
                if !c.is_null() {
                    OPENSSL_sk_push(sk, c.cast());
                }
            }
            OPENSSL_sk_free((*s).peer_ciphers);
            (*s).peer_ciphers = sk;
        }
    }

    // `tls_handle_status_request` (`statem_srvr.c:2551-2554`): runs after the certificate is
    // selected and before ALPN, so the application's OCSP callback sees the chosen certificate.
    // SAFETY: `s` is live.
    if unsafe { tls_handle_status_request(s) } == 0 {
        return 0;
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

/// Write a Rust slice into a live packet. The slice carries its own length, so the remaining
/// obligation is only that `pkt` is live.
///
/// # Safety
/// `pkt` must be live.
unsafe fn wpacket_put_slice(pkt: *mut Wpacket, bytes: &[u8]) -> c_int {
    // SAFETY: `pkt` is live per the contract; `bytes` is readable for `bytes.len()`.
    unsafe { crate::packet::WPACKET_memcpy(pkt, bytes.as_ptr().cast(), bytes.len()) }
}

/// Upper bound of the fixed ServerHello prelude: `legacy_version(2) || random(32) ||
/// legacy_session_id_echo(1 + 255) || cipher_suite(2) || legacy_compression_method(1)`.
const SERVER_HELLO_PREFIX_MAX: usize = 2 + 32 + 1 + u8::MAX as usize + 2 + 1;

/// The fixed prelude of a ServerHello, before the extension block:
/// `legacy_version || random || legacy_session_id_echo || cipher_suite ||
/// legacy_compression_method` (RFC 8446 §4.1.3; `tls_construct_server_hello`,
/// `statem_srvr.c:2599-2660`).
///
/// `session_id` is echoed as a whole slice: the length byte is derived from the slice, so a
/// longer id produces a longer echo rather than an out-of-bounds read. The connection's own
/// buffer bounds the production argument.
fn write_server_hello_prefix(
    out: &mut [u8],
    version: u16,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_id: u16,
) -> Option<usize> {
    let mut w = BytesWriter::new(out);
    if !(w.put_u16(version)
        && w.put_bytes(random)
        && w.put_u8_len_prefixed(session_id)
        && w.put_u16(cipher_id)
        && w.put_u8(0))
    {
        return None;
    }
    Some(w.written())
}

/// `CON_FUNC_RETURN tls_construct_server_hello(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `statem_srvr.c:2590-2699`, reduced at the key schedule. This is the TLS1.3 ServerHello
/// writer ([`write_server_hello`]); the fixed prelude is built by the safe
/// [`write_server_hello_prefix`] and the extension block by the extension framework, in the
/// authority's order.
///
/// # Safety
/// `s` must be a live connection; `pkt` a live packet.
unsafe fn tls_construct_server_hello(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live; `pending_cipher` is NULL or a live table row, `tmp_session_id` is a
    // 32-byte member paired with its length, and `server_random` is a 32-byte member. A length
    // outside the array is an internal invariant violation, refused rather than read past it.
    let (cipher, session_id, random) = unsafe {
        (
            (*s).pending_cipher,
            (*s).tmp_session_id.get(..(*s).tmp_session_id_len),
            &(*s).server_random,
        )
    };
    let Some(session_id) = session_id else {
        return 0;
    };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is a live table row.
    let cipher_id = unsafe { (*cipher).id as u16 };
    let mut prefix = [0u8; SERVER_HELLO_PREFIX_MAX];
    let Some(prefix_len) = write_server_hello_prefix(
        &mut prefix,
        TLS1_2_VERSION as u16,
        random,
        session_id,
        cipher_id,
    ) else {
        return 0;
    };
    // SAFETY: `pkt` is live; `prefix[..prefix_len]` is initialised by the writer.
    if unsafe { wpacket_put_slice(pkt, &prefix[..prefix_len]) } == 0 {
        return 0;
    }
    // SAFETY: `s`/`pkt` are live.
    unsafe { crate::ssl::statem::extensions_srvr::tls_construct_extensions(s, pkt) }
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

    // The packet buffer is heap-allocated through the crate's allocator seam for the same reason
    // as the client's: a 4 KiB frame here sits directly above the record encoder on the accept
    // path.
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
        if ssl3_set_handshake_header(&mut pkt, SSL3_MT_SERVER_HELLO) == 0
            || tls_construct_server_hello(s, &mut pkt) == 0
            || tls_close_construct_packet(&mut pkt, &mut msglen) == 0
            || crate::packet::WPACKET_finish(&mut pkt) == 0
        {
            crate::packet::WPACKET_cleanup(&mut pkt);
            return 0;
        }
        let r =
            crate::ssl::record::rec_layer_s3::ssl3_write_bytes(s, SSL3_RT_HANDSHAKE, buf, msglen);
        // The transcript's second message (`tls_construct_server_hello`); the transcript was
        // initialised with the ClientHello by `tls_process_client_hello`.
        if r > 0 {
            crate::ssl::tls13_enc::transcript_update(s, buf, msglen);
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

/// The `EncryptedExtensions` body: an `Extension extensions<0..2^16-1>` vector carrying only the
/// negotiated ALPN (`tls_construct_stoc_alpn`, `extensions_srvr.c:1835-1854`), whose body is
/// `ProtocolNameList<2..2^16-1>` = `list_len(2) || proto_len(1) || proto`.
///
/// An absent, empty or over-long protocol emits no extension, matching the previous
/// `sel_len > 0 && sel_len <= 255` guard.
fn write_encrypted_extensions_body(out: &mut [u8], alpn: Option<&[u8]>) -> Option<usize> {
    let alpn = alpn.filter(|proto| !proto.is_empty() && proto.len() <= u8::MAX as usize);
    let ext_len = match alpn {
        // `type(2) || ext_len(2) || list_len(2) || proto_len(1) || proto`
        Some(proto) => 7 + proto.len(),
        None => 0,
    };
    let mut w = BytesWriter::new(out);
    if !w.put_u16(u16::try_from(ext_len).ok()?) {
        return None;
    }
    if let Some(proto) = alpn {
        let list_len = 1 + proto.len();
        if !(w.put_u16(TLSEXT_TYPE_ALPN)
            && w.put_u16(u16::try_from(2 + list_len).ok()?)
            && w.put_u16(u16::try_from(list_len).ok()?)
            && w.put_u8_len_prefixed(proto))
        {
            return None;
        }
    }
    Some(w.written())
}

/// `CON_FUNC_RETURN tls_construct_encrypted_extensions(...)` — `statem_srvr.c:4591-4601`.
///
/// The `EncryptedExtensions` body is an `Extension extensions<0..2^16-1>` vector. The reduced flight
/// carries only the negotiated ALPN (`tls_construct_stoc_alpn`, `extensions_srvr.c:1835-1854`); every
/// other extension this stratum could negotiate is empty.
///
/// # Safety
/// `s` is live.
unsafe fn tls13_construct_encrypted_extensions(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live; its member buffer pairs `selected` with `sel_len`, so a non-NULL
    // pointer names `sel_len` readable bytes for this frame's borrow. The writer below is safe
    // and derives every wire length itself.
    let alpn: Option<&[u8]> = unsafe {
        let (selected, sel_len) = (*s).s3_alpn_selected();
        if selected.is_null() || sel_len == 0 {
            None
        } else {
            Some(core::slice::from_raw_parts(selected, sel_len))
        }
    };
    let mut body = [0u8; 2 + 7 + u8::MAX as usize];
    let Some(body_len) = write_encrypted_extensions_body(&mut body, alpn) else {
        return 0;
    };
    // SAFETY: `s` is live; `body[..body_len]` is initialised by the writer.
    unsafe {
        crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_EE, body.as_ptr(), body_len)
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
    // `context<1> || extensions_len(2) || type(2) || ext_len(2) || list_len(2) || schemes`.
    const BODY_MAX: usize = 1 + u8::MAX as usize + 2 + 4 + 2 + 2 * SIGALGS.len();
    let mut msg = [0u8; BODY_MAX];
    let Some(total) = write_certificate_request_body(&mut msg, context, &SIGALGS) else {
        return 0;
    };
    // `s->certreqs_sent++; s->s3.tmp.cert_request = 1;` (`statem_srvr.c:3091-3092`).
    // SAFETY: `s` is live.
    unsafe {
        (*s).certreqs_sent += 1;
        (*s).s3_tmp_cert_request = 1;
    }
    // SAFETY: `s` is live; `msg[..total]` is initialised bytes produced by the writer.
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

/// `CON_FUNC_RETURN tls_construct_cert_status(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `statem_srvr.c:4538-4553` over `tls_construct_cert_status_body` (`:4514-4536`): the TLS1.2
/// `CertificateStatus` body is `status_type(1) || response<3>`.
///
/// # Safety
/// `s` must be a live connection.
/// `tls_construct_cert_status_body` (`statem_srvr.c:4514-4536`):
/// `status_type(1) || response<0..2^24-1>`, written with bounds-checked indexing.
///
/// A safe interior: every length is checked here, so no caller-supplied length can
/// make this function write out of bounds or panic. `out` is the exact body block
/// the caller sized; a mismatch is refused rather than truncated.
fn write_cert_status_body(out: &mut [u8], status_type: u8, resp: &[u8]) -> bool {
    if resp.len() > 0xff_ffff {
        return false;
    }
    let Some(total) = resp.len().checked_add(4) else {
        return false;
    };
    if out.len() != total {
        return false;
    }
    let Some((header, payload)) = out.split_at_mut_checked(4) else {
        return false;
    };
    header[0] = status_type;
    let len = resp.len();
    header[1] = (len >> 16) as u8;
    header[2] = (len >> 8) as u8;
    header[3] = len as u8;
    payload.copy_from_slice(resp);
    true
}

unsafe fn tls12_construct_cert_status(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live per this function's contract; `ext_ocsp_resp` /
    // `ext_ocsp_resp_len` are the allocation `SSL_set_tlsext_status_ocsp_resp`
    // installed (a `CRYPTO_memdup` of exactly that length, or NULL/0).
    let (resp_ptr, len, status_type) = unsafe {
        (
            (*s).ext_ocsp_resp,
            (*s).ext_ocsp_resp_len,
            (*s).ext_status_type,
        )
    };
    if resp_ptr.is_null() || len == 0 || len > 0xff_ffff {
        // `ossl_get_ocsp_response` answered NULL: the message is not sent.
        return 1;
    }
    let Some(body_len) = len.checked_add(4) else {
        return 0;
    };
    // The same `malloc_request` seam call as `CRYPTO_malloc`, but zero-initialised so a
    // `&mut [u8]` may be derived from it without reading uninitialised memory.
    let Some(body) = OwnedBuf::new_zeroed(body_len, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `body` owns `body_len` zero-initialised bytes from the allocator seam and
    // this frame holds the only reference for the borrow; `resp` names `len` readable
    // bytes from the paired allocation checked non-NULL above.
    let (out, resp) = unsafe {
        (
            core::slice::from_raw_parts_mut(body.as_ptr(), body_len),
            core::slice::from_raw_parts(resp_ptr, len),
        )
    };
    if !write_cert_status_body(out, status_type as u8, resp) {
        return 0;
    }
    // SAFETY: `s` is live; `out` is `body_len` initialised bytes owned by `body`.
    unsafe { write_handshake_message(s, SSL3_MT_CERTIFICATE_STATUS as u8, out.as_ptr(), body_len) }
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
    // SAFETY: `cpk` is NULL or a live certificate slot; its `x509` field is read.
    let leaf = if cpk.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the `else` arm runs only when `cpk` is non-NULL and live.
        unsafe { (*cpk).x509 }
    };
    if leaf.is_null() {
        // No certificate to send (`ssl3_output_cert_chain` with a NULL `cpk`): the TLS1.3
        // `certificate_list` is empty (`statem_clnt.c:3869-3882`).
        let mut body = [0u8; 1 + u8::MAX as usize + 3];
        let Some(n) = write_tls13_certificate_body(&mut body, context, &[]) else {
            return 0;
        };
        // SAFETY: `s` is live; `body[..n]` is initialised by the writer.
        return unsafe {
            crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_CERT, body.as_ptr(), n)
        };
    }
    // Size the DER first (the authority's `i2d_X509(x, NULL)` before
    // `WPACKET_sub_allocate_bytes_u24`).
    // SAFETY: `leaf` is live; a NULL out-pointer asks only for the length.
    let derlen = unsafe { i2d_X509(leaf, ptr::null_mut()) };
    if derlen <= 0 {
        return 0;
    }
    let derlen = derlen as usize;
    // `context<1> || certificate_list_len(3) || cert_len(3) || DER || extensions(2)`.
    let Some(body_len) = 1usize
        .checked_add(context.len())
        .and_then(|n| n.checked_add(3))
        .and_then(|n| n.checked_add(3))
        .and_then(|n| n.checked_add(derlen))
        .and_then(|n| n.checked_add(2))
    else {
        return 0;
    };
    // `write_handshake_message` frames `4 + body_len` bytes in a 17000-byte block; keep
    // the allocation bounded by the same reduced boundary before staging anything.
    if body_len > 17000 - 4 {
        return 0;
    }
    // Encode the DER into an exact-size staging block; its single release is the handle's
    // `Drop` on every refusal below. Zeroed so the `&mut [u8]` below is a valid slice.
    let Some(der_block) = OwnedBuf::new_zeroed(derlen, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `der_block` owns `derlen` initialised bytes and this frame holds the only
    // reference for the borrow.
    let der = unsafe { core::slice::from_raw_parts_mut(der_block.as_ptr(), derlen) };
    // `der` has exactly `derlen` writable bytes (the length the preceding
    // `i2d_X509(leaf, NULL)` reported for this same object).
    let mut der_cursor = der.as_mut_ptr();
    // SAFETY: `leaf` is live and `der_cursor` points at `derlen` writable bytes.
    if unsafe { i2d_X509(leaf, &mut der_cursor) } != derlen as c_int {
        return 0;
    }
    let Some(body) = OwnedBuf::new_zeroed(body_len, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `body` owns `body_len` initialised bytes; this frame holds the only reference.
    let out = unsafe { core::slice::from_raw_parts_mut(body.as_ptr(), body_len) };
    let Some(n) = write_tls13_certificate_body(out, context, &[&*der]) else {
        return 0;
    };
    debug_assert_eq!(n, body_len);
    // SAFETY: `s` is live; `out[..n]` is the framed body written above.
    unsafe { crate::ssl::tls13_enc::write_handshake_message(s, SSL3_MT_CERT, out.as_ptr(), n) }
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
    use crate::evp::digest::{EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_new};
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
            // The signature and its framed body are heap-allocated through the crate's allocator
            // seam; the two ~1 KiB arrays otherwise stack above the record encoder on every
            // post-ClientHello flight and help push a 32 KiB accept thread over its guard page.
            if let Some(sig_block) = OwnedBuf::new_zeroed(1024, SeamFile::NULL, 0) {
                // SAFETY (enclosing block): `sig_block` owns 1024 initialised bytes; this
                // frame holds the only reference for the borrow.
                let sig = core::slice::from_raw_parts_mut(sig_block.as_ptr(), 1024);
                // SAFETY: `mctx` is live; the query above reported `siglen <= 1024`, so the
                // slot's extent holds the signature the encoder is about to write.
                if EVP_DigestSign(mctx, sig.as_mut_ptr(), &mut siglen, tbs.as_ptr(), pos) > 0
                    && siglen <= 1024
                {
                    if let Some(body_block) = OwnedBuf::new_zeroed(1030, SeamFile::NULL, 0) {
                        // SAFETY (enclosing block): `body_block` owns 1030 initialised
                        // bytes; this frame holds the only reference for the borrow.
                        let body = core::slice::from_raw_parts_mut(body_block.as_ptr(), 1030);
                        // `ecdsa_secp256r1_sha256` (0x0403) for an EC key, else
                        // `rsa_pss_rsae_sha256` (0x0804).
                        let sigalg: [u8; 2] = if is_ec {
                            [0x04, 0x03]
                        } else {
                            // TLS 1.3 requires an RSASSA-PSS scheme for an RSA key
                            // (`tls12_check_peer_sigalg`, `tls1_lib.c:2700-2739`; RFC 8446
                            // §4.2.3).
                            [0x08, 0x04]
                        };
                        if let Some(n) = write_cert_verify_body(body, sigalg, &sig[..siglen]) {
                            // SAFETY: `s` is live; `body[..n]` is the framed body written above.
                            ok = crate::ssl::tls13_enc::write_handshake_message(
                                s,
                                SSL3_MT_CERT_VRFY,
                                body.as_ptr(),
                                n,
                            ) > 0;
                        }
                    }
                }
            }
        }
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
    let mut pms = crate::runtime::mem::CleansedScratch::<64>::new();
    let mut pmslen = 0usize;
    // SAFETY: `s` is live; the server ephemeral (`pkey`) and client share (`peer_tmp`) are set.
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
    // SAFETY: `s` is live; `pms` is `pmslen` initialised bytes.
    if unsafe { k::tls13_generate_handshake_secret(s, &pms.as_slice()[..pmslen]) } == 0 {
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
    // A resumed connection (the `SW_ENCRYPTED_EXTENSIONS` `s->hit` arm, `statem_srvr.c:518-520`)
    // sends no CertificateRequest/Certificate/CertificateVerify and goes straight to the Finished.
    // SAFETY: `s` is live.
    if unsafe { (*s).hit } == 0 {
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
        // SAFETY: `s` is live; its `pha_context` member obeys the member-buffer invariant.
        let mut slot = (*s).pha_context_slot();
        slot.clear(core::ptr::null(), 0);
        let dup = crate::runtime::mem::CRYPTO_memdup(
            ctx.as_ptr().cast(),
            ctx.len(),
            core::ptr::null(),
            0,
        )
        .cast::<u8>();
        if dup.is_null() {
            return 0;
        }
        slot.store(dup, ctx.len());
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

/// The one-byte `ChangeCipherSpec` body (`SSL3_MT_CHANGE_CIPHER_SPEC`, `ssl3.h`).
const TLS12_CHANGE_CIPHER_SPEC_BODY: [u8; 1] = [1];

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
        // The TLS1.2 half of `ssl3_choose_cipher` (`ssl3_lib.c`): server preference over the
        // supported ECDHE and RSA key-transport suites, filtered by the certificate the server
        // holds and by the client's offer. The reduced message layer completes ECDHE and static
        // RSA key exchange; DHE/PSK/SRP suites are still outside it.
        if (mkey as u64 & (ct::SSL_kECDHE | ct::SSL_kRSA)) == 0 {
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
/// client also offered that the TLS1.2 ECDHE implementation can complete, or 0 when the lists do
/// not intersect.
///
/// The authority's `tls1_shared_group(s, -2)` (`t1_lib.c:1008`) walks its full `TLS_GROUP_INFO`
/// list; this reduction intersects only the groups [`crate::ssl::t1_lib::tls1_group_id2kex`]
/// implements (the FFDHE entries in the default list are TLS1.3/DHE groups and cannot be used by
/// the ECDHE-only `ServerKeyExchange` path).
///
/// # Safety
/// `s` is live.
unsafe fn tls12_choose_group(s: *const Ssl, clnt_groups: &[u16]) -> u16 {
    // SAFETY: `s` is live.
    let srvr = unsafe { crate::ssl::t1_lib::tls1_get_supported_groups(s) };
    for g in srvr {
        if crate::ssl::t1_lib::tls1_group_id2kex(*g).is_some() && clnt_groups.contains(g) {
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
    use crate::evp::digest::{EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_new};
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
    // SAFETY: `EVP_MD_CTX_new` is the matching constructor: it answered the whole, aligned
    // `EVP_MD_CTX` block (or NULL, which yields `None`), live and owned solely by this handle, whose
    // `Drop` runs `EVP_MD_CTX_free` -- its single release.
    let mctx_owner = unsafe { OwnedCtx::<crate::evp::digest::EvpMdCtx>::new(EVP_MD_CTX_new()) }?;
    // The owned `EVP_MD_CTX`'s stable address, for the raw calls below; its single release is the
    // handle's `Drop` at the end of the frame.
    let mctx = mctx_owner.as_ptr();
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
    use crate::evp::digest::{EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_new};
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx};
    if sigalg != 0x0401 && sigalg != 0x0403 {
        return false;
    }
    // SAFETY: no preconditions.
    let md = EVP_sha256();
    // SAFETY: `EVP_MD_CTX_new` is the matching constructor: it answered the whole, aligned
    // `EVP_MD_CTX` block (or NULL, which yields `None`), live and owned solely by this handle, whose
    // `Drop` runs `EVP_MD_CTX_free` -- its single release.
    let Some(mctx_owner) =
        (unsafe { OwnedCtx::<crate::evp::digest::EvpMdCtx>::new(EVP_MD_CTX_new()) })
    else {
        return false;
    };
    // The owned `EVP_MD_CTX`'s stable address, for the raw calls below; its single release is the
    // handle's `Drop` at the end of the frame.
    let mctx = mctx_owner.as_ptr();
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
    }
    ok
}

/// The TLS1.2 `ServerHello` body: `version || random || session_id(1 + n) || cipher_suite ||
/// compression_method || extensions<2>`. The extension block is `renegotiation_info` (RFC 5746,
/// always, once the client offered it), then `session_ticket` (empty) when a ticket follows
/// (`tls_construct_stoc_session_ticket`, `extensions_srvr.c:1740`), then the TLS1.2
/// `status_request` acknowledgement (`tls_construct_stoc_status_request`,
/// `extensions_srvr.c:1759-1798`).
fn write_tls12_server_hello_body(
    out: &mut [u8],
    version: u16,
    random: &[u8; 32],
    session_id: &[u8],
    cipher_id: u16,
    send_ticket: bool,
    send_status: bool,
) -> Option<usize> {
    let mut ext_buf = [0u8; 32];
    let mut ew = BytesWriter::new(&mut ext_buf);
    // `renegotiation_info` with an empty `renegotiated_connection`.
    let mut ok = ew.put_bytes(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    if ok && send_ticket {
        ok = ew.put_bytes(&[0x00, 0x23, 0x00, 0x00]);
    }
    if ok && send_status {
        ok = ew.put_bytes(&[0x00, 0x05, 0x00, 0x00]);
    }
    if !ok {
        return None;
    }
    let ext_len = ew.written();
    let ext = ext_buf.get(..ext_len)?;
    let mut w = BytesWriter::new(out);
    if !(w.put_u16(version)
        && w.put_bytes(random)
        && w.put_u8_len_prefixed(session_id)
        && w.put_u16(cipher_id)
        && w.put_u8(0)
        && w.put_u16_len_prefixed(ext))
    {
        return None;
    }
    Some(w.written())
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
    // SAFETY: `s` is live; `server_random` is a 32-byte member, `ext_status_expected` is a flag,
    // and `tls_use_ticket` accepts a live connection.
    let (random, send_status, send_ticket) = unsafe {
        (
            &(*s).server_random,
            (*s).ext_status_expected != 0,
            (*s).ext_ticket_expected != 0 && crate::ssl::t1_lib::tls_use_ticket(s),
        )
    };
    // `tls_construct_server_hello` echoes `s->session->session_id`: the resumed id on a hit, or
    // the freshly generated id (empty for an RFC5077 stateless ticket) otherwise.
    let mut sid = [0u8; crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH];
    let sid_len;
    // SAFETY: `s` is live; a non-NULL `session` is a live session whose `session_id` member is
    // the same 32-byte array size as `tmp_session_id`, both bounded below by construction.
    unsafe {
        // Borrow the session id as a slice, bounded by the member's own storage so a corrupt
        // recorded length can only shorten the echo, never index outside the array.
        let session_id: &[u8] = if (*s).session.is_null() {
            &[]
        } else {
            let sess = &*(*s).session;
            let n = sess.session_id_length.min(sess.session_id.len());
            &sess.session_id[..n]
        };
        sid_len = session_id.len().min(sid.len());
        sid[..sid_len].copy_from_slice(&session_id[..sid_len]);
        (&mut (*s).tmp_session_id)[..sid_len].copy_from_slice(&sid[..sid_len]);
        (*s).tmp_session_id_len = sid_len;
    }
    let mut body = [0u8; 96];
    let Some(body_len) = write_tls12_server_hello_body(
        &mut body,
        TLS1_2_VERSION as u16,
        random,
        &sid[..sid_len],
        id,
        send_ticket,
        send_status,
    ) else {
        return 0;
    };
    // SAFETY: `s` is live; `body[..body_len]` is initialised by the writer.
    unsafe { write_handshake_message(s, SSL3_MT_SERVER_HELLO, body.as_ptr(), body_len) }
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
    let leaf = if cpk.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `cpk` is a live slot.
        unsafe { (*cpk).x509 }
    };
    // SAFETY: `cpk` is NULL or a live certificate container.
    let chain = if cpk.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the `else` arm runs only when `cpk` is non-NULL and live.
        unsafe { (*cpk).chain }
    };
    let n = if chain.is_null() {
        0
    } else {
        // SAFETY: `chain` is a live stack.
        unsafe { crate::runtime::stack::OPENSSL_sk_num(chain) }
    };

    // First pass: collect the live certificates and size every DER blob exactly (the
    // authority's `i2d_X509(x, NULL)` before `WPACKET_sub_allocate_bytes_u24`).
    let mut entries: Vec<(*mut X509, usize)> = Vec::new();
    if !leaf.is_null() {
        // SAFETY: `leaf` is a live certificate; a NULL out-pointer asks only for the length.
        let dlen = unsafe { i2d_X509(leaf, ptr::null_mut()) };
        if dlen <= 0 {
            return 0;
        }
        entries.push((leaf, dlen as usize));
    }
    for i in 0..n {
        // SAFETY: `i` is in range.
        let x = unsafe { crate::runtime::stack::OPENSSL_sk_value(chain, i) as *mut X509 };
        if x.is_null() {
            continue;
        }
        // SAFETY: `x` is a live certificate; a NULL out-pointer asks for the length.
        let dlen = unsafe { i2d_X509(x, ptr::null_mut()) };
        if dlen <= 0 {
            return 0;
        }
        entries.push((x, dlen as usize));
    }
    let mut list_len = 0usize;
    for &(_, dlen) in &entries {
        let Some(next) = list_len.checked_add(3).and_then(|v| v.checked_add(dlen)) else {
            return 0;
        };
        list_len = next;
    }
    // `certificate_list<0..2^24-1>`, and the handshake writer's 17000-byte framing bound.
    if list_len > 0xFF_FFFF {
        return 0;
    }
    let Some(body_len) = 3usize.checked_add(list_len) else {
        return 0;
    };
    if body_len > 17000 - 4 {
        return 0;
    }
    // Encode each DER into its exact-size staging block, then frame the list with the safe
    // body writer. Each block's single release is its handle's `Drop`, including on the
    // early returns below.
    let mut staged: Vec<OwnedBuf> = Vec::with_capacity(entries.len());
    for &(x, dlen) in &entries {
        let Some(block) = OwnedBuf::new_zeroed(dlen, SeamFile::NULL, 0) else {
            return 0;
        };
        // SAFETY: `block` owns `dlen` initialised bytes and this frame holds the only
        // reference for the borrow.
        let slot = unsafe { core::slice::from_raw_parts_mut(block.as_ptr(), dlen) };
        // `slot` has exactly `dlen` writable bytes (the length the preceding
        // `i2d_X509(x, NULL)` reported for this same object).
        let mut cursor = slot.as_mut_ptr();
        // SAFETY: `x` is live and `cursor` points at `dlen` writable bytes.
        if unsafe { i2d_X509(x, &mut cursor) } != dlen as c_int {
            return 0;
        }
        staged.push(block);
    }
    // SAFETY: every staged block is live for this frame and `dlen` bytes of it were written
    // by `i2d_X509`; both vectors share the same order.
    let ders: Vec<&[u8]> = staged
        .iter()
        .zip(entries.iter())
        .map(|(block, &(_, dlen))| unsafe { core::slice::from_raw_parts(block.as_ptr(), dlen) })
        .collect();
    // The body block, allocated through the crate's allocator seam; its single release is
    // the handle's `Drop` on every refusal below.
    let Some(body) = OwnedBuf::new_zeroed(body_len, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `body` owns `body_len` initialised bytes and this frame holds the only
    // reference for the borrow.
    let out = unsafe { core::slice::from_raw_parts_mut(body.as_ptr(), body_len) };
    let Some(written) = write_tls12_certificate_body(out, &ders) else {
        return 0;
    };
    debug_assert_eq!(written, body_len);
    // SAFETY: `s` is live; `out[..written]` is the framed body produced above.
    unsafe { write_handshake_message(s, SSL3_MT_CERTIFICATE as u8, out.as_ptr(), written) }
}

/// Generate the ephemeral key for one TLS1.2 ECDHE group.
///
/// `ssl_generate_pkey_group` (`s3_lib.c:5375-5411`) resolves the group to a key-management
/// algorithm and a provider-internal curve name, then calls `EVP_PKEY_CTX_set_group_name`. This
/// reduction builds the same `group` parameter and hands it to the crate's `evp_pkey_keygen`; the
/// X25519/X448 methods take no group parameter.
///
/// The returned handle owns the key and releases it with `EVP_PKEY_free` on `Drop`; the caller
/// either keeps it in the connection's `pkey` slot or derives with it.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_generate_ecdh_key(
    s: *mut Ssl,
    group: u16,
) -> Option<OwnedCtx<crate::evp::pkey::EvpPkey>> {
    use crate::evp::pkey::evp_pkey_keygen;
    use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_utf8_string};

    // SAFETY: `s` is live per the contract.
    let (alg, group_name) = crate::ssl::t1_lib::tls1_group_id2kex(group)?;
    // SAFETY: `s` is live.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq()) };
    let mut params = [OSSL_PARAM_construct_end(); 2];
    if alg == c"EC" {
        // SAFETY: `group_name` is a `'static` NUL-terminated string; `params` has room.
        params[0] = unsafe {
            OSSL_PARAM_construct_utf8_string(c"group".as_ptr(), group_name.as_ptr().cast_mut(), 0)
        };
    }
    // SAFETY: `libctx`/`propq` are the context's; `alg` is NUL-terminated; `params` is a terminated
    // array; `evp_pkey_keygen` is the matching constructor. The non-NULL answer is the whole,
    // aligned key block, live and solely owned by the returned handle.
    unsafe {
        OwnedCtx::new(evp_pkey_keygen(
            libctx,
            alg.as_ptr(),
            propq,
            params.as_mut_ptr(),
        ))
    }
}

/// Wrap a peer's encoded public point as an `EVP_PKEY` for the negotiated group.
///
/// The authority does this with `EVP_PKEY_new` + `EVP_PKEY_copy_parameters`/paramgen +
/// `EVP_PKEY_set1_encoded_public_key` (`statem_srvr.c:3329-3355`, `statem_clnt.c:2408-2425`).
/// For the X25519 family the provider's raw-public-key constructor is exactly that path; for the
/// NIST curves this reduction imports the point with `EVP_PKEY_fromdata`, using the same
/// `group`/`pub` parameters the provider's `ec_import` reads.
///
/// The returned key is owned by the caller and released with `EVP_PKEY_free`.
///
/// # Safety
/// `s` is live; `point` is readable for its length and is an encoded point for `group`.
pub(crate) unsafe fn tls12_peer_key_from_point(
    s: *mut Ssl,
    group: u16,
    point: &[u8],
) -> *mut crate::evp::pkey::EvpPkey {
    use crate::evp::pkey::{
        EVP_PKEY_free, EVP_PKEY_new_raw_public_key_ex, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
        OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
    };
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name};
    use crate::evp::pmeth_gn::{EVP_PKEY_fromdata, EVP_PKEY_fromdata_init};
    use crate::params::{
        OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string,
        OSSL_PARAM_construct_utf8_string,
    };

    // SAFETY: `s` is live per the contract.
    let Some((alg, group_name)) = crate::ssl::t1_lib::tls1_group_id2kex(group) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `s` is live.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq()) };
    if alg != c"EC" {
        // SAFETY: `alg` is NUL-terminated and `point` is readable for `point.len()`; the constructor
        // answers a fresh key owned by the caller.
        return unsafe {
            EVP_PKEY_new_raw_public_key_ex(libctx, alg.as_ptr(), propq, point.as_ptr(), point.len())
        };
    }
    // SAFETY: `alg` is NUL-terminated and `propq` is the context's.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(libctx, alg.as_ptr(), propq) };
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    let mut params = [OSSL_PARAM_construct_end(); 3];
    // SAFETY: `group_name` is NUL-terminated and `point` is readable for its length; `params` has
    // room for both entries.
    unsafe {
        params[0] =
            OSSL_PARAM_construct_utf8_string(c"group".as_ptr(), group_name.as_ptr().cast_mut(), 0);
        params[1] = OSSL_PARAM_construct_octet_string(
            c"pub".as_ptr(),
            point.as_ptr().cast_mut().cast(),
            point.len(),
        );
    }
    let mut pkey: *mut crate::evp::pkey::EvpPkey = core::ptr::null_mut();
    // SAFETY: `ctx` is live; `pkey` is this frame's writable slot; `params` is terminated.
    let ok = unsafe {
        EVP_PKEY_fromdata_init(ctx) > 0
            && EVP_PKEY_fromdata(
                ctx,
                &mut pkey,
                OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                    | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                params.as_mut_ptr(),
            ) > 0
    };
    // SAFETY: `ctx` is this frame's own context.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    if !ok {
        // SAFETY: a non-NULL `pkey` is the failure path's partially built key, owned here.
        unsafe { EVP_PKEY_free(pkey) };
        return core::ptr::null_mut();
    }
    pkey
}

/// `tls_construct_server_key_exchange` (`statem_srvr.c:2699-2860`) for the ECDHE path:
/// `ServerECDHParams` signed with the server certificate key over
/// `client_random || server_random || ServerECDHParams` (`tls12_construct_ske`).
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_server_key_exchange(s: *mut Ssl) -> c_int {
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    let group = unsafe { (*s).group_id };
    // `tls1_shared_group(s, -2)` returns 0 when no group intersects. The authority reports
    // `SSL_R_UNSUPPORTED_ELLIPTIC_CURVE` (315) there (`statem_srvr.c:2809-2814`); this
    // reduction reports `SSL_R_NO_SUITABLE_KEY_SHARE` (101), the reason its TLS1.3 key-share
    // path uses and the one the campaign's no-common-group acceptance test requires. Recorded
    // divergence: a TLS1.2 client sees 101 where the authority sends 315.
    if crate::ssl::t1_lib::tls1_group_id2kex(group).is_none() {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_NO_SUITABLE_KEY_SHARE) };
        return -1;
    }
    // SAFETY: `s` is live; the constructor's handle owns the whole generated key.
    let Some(pkey) = (unsafe { tls12_generate_ecdh_key(s, group) }) else {
        return 0;
    };
    let mut pub_ = core::ptr::null_mut::<u8>();
    // SAFETY: `pkey` is live; `pub_` is this frame's writable slot.
    let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey.as_ptr(), &mut pub_) };
    if publen == 0 {
        // The refusal releases the key it built: returning drops `pkey`. `pub_` stays as the
        // authority leaves it (the failed `get1` does not hand one back).
        return 0;
    }
    // The `get1` out-pointer is this frame's now: its single release is the handle's `Drop`, so the
    // frame no longer writes a `CRYPTO_free` by hand.
    // SAFETY: `pub_` is the block `get1` allocated above and has not been released.
    let Some(pub_) = (unsafe { OwnedBuf::adopt_plain(pub_.cast::<u8>(), SeamFile::NULL, 0) })
    else {
        return 0;
    };
    // Store the server ephemeral (`ssl_generate_pkey`).
    // SAFETY: `s` is live; the old `pkey` slot is NULL or owned by the field.
    unsafe {
        if !(*s).pkey.is_null() {
            EVP_PKEY_free((*s).pkey.cast());
        }
        (*s).pkey = pkey.into_raw().cast();
    }
    // SAFETY: `pub_` is the `get1` block, readable for `publen` bytes until this frame's drop.
    let point = unsafe { core::slice::from_raw_parts(pub_.as_ptr(), publen) };
    // `named_curve(1) || group(2) || point<1..2^8-1>`.
    let mut params_buf = [0u8; 4 + 255];
    let Some(params_len) = write_tls12_ecdh_params(&mut params_buf, group, point) else {
        return 0;
    };
    // The signature covers `client_random || server_random || ServerECDHParams`.
    let mut tbs = [0u8; 32 + 32 + 4 + 255];
    // SAFETY: `s` is live.
    let (client_random, server_random) = unsafe { (&(*s).client_random, &(*s).server_random) };
    let Some(tbs_len) = write_tls12_ske_signature_input(
        &mut tbs,
        client_random,
        server_random,
        &params_buf[..params_len],
    ) else {
        return 0;
    };
    // The signature and framed body are heap-allocated so this pre-Finished flight does not place
    // ~3 KiB of arrays on the accept thread's stack.
    let mut sig = vec![0u8; 1024];
    // SAFETY: `s` is live; `tbs`/`sig` are writable locals.
    let sigalg_len = unsafe { tls12_sign(s, &tbs[..tbs_len], &mut sig) };
    // The `get1` block's single release is this drop, at the authority's own release point.
    drop(pub_);
    let Some((sigalg, siglen)) = sigalg_len else {
        return 0;
    };
    let Some(body_len) = params_len
        .checked_add(4)
        .and_then(|n| n.checked_add(siglen))
    else {
        return 0;
    };
    let mut body = vec![0u8; body_len];
    let Some(written) =
        write_tls12_ske_body(&mut body, &params_buf[..params_len], sigalg, &sig[..siglen])
    else {
        return 0;
    };
    // SAFETY: `s` is live; `body` is `written` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_SERVER_KEY_EXCHANGE as u8, body.as_ptr(), written) }
}

/// `tls_construct_certificate_request` (`statem_srvr.c`) for the TLS1.2 shape:
/// `certificate_types || supported_signature_algorithms || certificate_authorities`.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_certificate_request(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    const SIGALGS: [u8; 8] = [0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x06, 0x01];
    // `certificate_types`: `rsa_sign(1) || ecdsa_sign(64)`.
    const CERT_TYPES: [u8; 2] = [1, 64];
    let mut body = [0u8; 64];
    let Some(written) =
        write_tls12_certificate_request_body(&mut body, &CERT_TYPES, Some(&SIGALGS))
    else {
        return 0;
    };
    // SAFETY: `s` is live; `body` is `written` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_CERTIFICATE_REQUEST as u8, body.as_ptr(), written) }
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
    use crate::runtime::mem::CRYPTO_malloc;
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
    let Some(written) = write_tls12_new_session_ticket_body(&mut body, hint, &ticket) else {
        return 0;
    };

    // Record the ticket on the session and set the client-mirrored resume id (`SHA256(ticket)`).
    // SAFETY: `sess` is live.
    unsafe {
        // Release any incumbent at the authority's own site (see `MemberBufSlot`).
        (*sess).ext_tick_slot().clear(core::ptr::null(), 0);
        let tp = CRYPTO_malloc(TLS12_TICKET_LEN, core::ptr::null(), 0).cast::<u8>();
        if tp.is_null() {
            return 0;
        }
        // SAFETY: `tp` is a fresh, non-NULL block of `TLS12_TICKET_LEN` bytes; the copy is
        // exactly its extent.
        core::slice::from_raw_parts_mut(tp, TLS12_TICKET_LEN).copy_from_slice(&ticket);
        // `tp` is this call's fresh block of `TLS12_TICKET_LEN` bytes; the member is empty.
        (*sess).ext_tick_slot().store(tp, TLS12_TICKET_LEN);
        (*sess).ext_tick_lifetime_hint = hint as core::ffi::c_ulong;
        (*sess).not_resumable = 0;
        let mut digest = [0u8; 32];
        crate::digest::sha2::SHA256(ticket.as_ptr(), TLS12_TICKET_LEN, digest.as_mut_ptr());
        (*sess).session_id_length = 32;
        (*sess).session_id.copy_from_slice(&digest);
    }
    // SAFETY: `s` is live; `body` is `written` initialised bytes.
    unsafe { write_handshake_message(s, SSL3_MT_NEWSESSION_TICKET, body.as_ptr(), written) }
}

/// `tls_construct_server_hello_done` (`statem_srvr.c:3096-3108`): an empty handshake body.
///
/// # Safety
/// `s` is live.
unsafe fn tls12_construct_server_hello_done(s: *mut Ssl) -> c_int {
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live; `TLS12_SERVER_HELLO_DONE_BODY` is a `'static` empty slice, so the
    // zero length is the only byte count read.
    unsafe {
        write_handshake_message(
            s,
            SSL3_MT_SERVER_HELLO_DONE as u8,
            TLS12_SERVER_HELLO_DONE_BODY.as_ptr(),
            TLS12_SERVER_HELLO_DONE_BODY.len(),
        )
    }
}

/// `TLSEXT_KEYNAME_LENGTH` — `ssl_local.h:699`.
const TLSEXT_KEYNAME_LENGTH: usize = 16;
/// `ONE_WEEK_SEC` — `statem_srvr.c:4103`.
const ONE_WEEK_SEC: u64 = 7 * 24 * 60 * 60;
/// `EVP_MAX_IV_LENGTH` — `evp.h:171`.
const EVP_MAX_IV_LENGTH: usize = 16;

/// `static CON_FUNC_RETURN construct_stateless_ticket(SSL_CONNECTION *s, WPACKET *pkt,`
/// `uint32_t age_add, unsigned char *tick_nonce)` — `ssl/statem/statem_srvr.c:4127-4349`.
///
/// The ticket is `key_name(16) || iv(iv_len) || AES-256-CBC(i2d_SSL_SESSION) || HMAC-SHA256(32)`
/// (`statem_srvr.c:4290-4333`). The key/IV and the cipher/HMAC contexts are the application's
/// `ticket_key_cb`'s (`statem_srvr.c:4212-4260`); the default per-context-key arm needs
/// `tctx->ext.secure`, which this crate does not carry, so a context without the callback cannot
/// mint a ticket (a recorded boundary — nginx always installs the callback). Returns the ticket
/// bytes, or `None` on failure or when construction is suppressed.
///
/// # Safety
/// `s` is live with a set handshake session.
unsafe fn construct_stateless_ticket(s: *mut Ssl) -> Option<Vec<u8>> {
    use crate::evp::cipher_ctx::{
        EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_new, EVP_EncryptFinal_ex, EVP_EncryptUpdate,
    };
    use crate::mac::hmac::{HMAC_CTX_new, HMAC_Final, HMAC_Update};
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::ssl::ssl_asn1::i2d_SSL_SESSION;
    // SAFETY: `s` is live.
    unsafe {
        let sess = (*s).session;
        if sess.is_null() {
            return None;
        }
        // `i2d_SSL_SESSION(s->session, NULL)` then the serialisation (`statem_srvr.c:4158-4190`).
        let slen = i2d_SSL_SESSION(sess, core::ptr::null_mut());
        if slen <= 0 || slen > 0xFF00 {
            return None;
        }
        let slen = slen as usize;
        // The serialisation buffer, allocated through the crate's allocator seam at the authority's
        // own size and site; its single release is the handle's `Drop`, so every refusal below
        // releases it rather than freeing by hand.
        // SAFETY: `CRYPTO_malloc` is this crate's own allocator and answers a block or NULL.
        let senc = OwnedBuf::adopt_plain(
            CRYPTO_malloc(slen, core::ptr::null(), 0).cast(),
            SeamFile::NULL,
            0,
        )?;
        let mut p = senc.as_ptr();
        if i2d_SSL_SESSION(sess, &mut p) <= 0 {
            return None;
        }
        let tctx = (*s).session_ctx;
        if tctx.is_null() {
            return None;
        }
        // The cipher and HMAC contexts, owned here: their single release is `Drop` running the
        // authority's own `EVP_CIPHER_CTX_free`/`HMAC_CTX_free`, on every refusal and on success.
        // SAFETY: `EVP_CIPHER_CTX_new` is the matching constructor: it answered the whole, aligned
        // `EVP_CIPHER_CTX` block (or NULL, which yields `None`), live and owned solely by this
        // handle, whose `Drop` runs `EVP_CIPHER_CTX_free` -- its single release.
        let ctx = OwnedCtx::<crate::evp::cipher_ctx::EvpCipherCtx>::new(EVP_CIPHER_CTX_new())?;
        // SAFETY: `HMAC_CTX_new` is the matching constructor: it answered the whole, aligned
        // `HMAC_CTX` block (or NULL, which yields `None`), live and owned solely by this handle,
        // whose `Drop` runs `HMAC_CTX_free` -- its single release.
        let hctx = OwnedCtx::<crate::mac::hmac::HmacCtx>::new(HMAC_CTX_new())?;
        let mut key_name = [0u8; TLSEXT_KEYNAME_LENGTH];
        let mut iv = [0u8; EVP_MAX_IV_LENGTH];
        let cb = match (*tctx).ticket_key_cb {
            Some(cb) => cb,
            None => {
                // No default-key arm (the module boundary above); suppress the ticket.
                return None;
            }
        };
        // SAFETY: the callback is the application's; `ctx`/`hctx` are live candidate contexts.
        let ret = cb(
            s,
            key_name.as_mut_ptr(),
            iv.as_mut_ptr(),
            ctx.as_ptr().cast(),
            hctx.as_ptr().cast(),
            1,
        );
        if ret <= 0 {
            // `ret == 0`/`< 0` (`statem_srvr.c:4250-4275`): a TLS1.3 zero-length ticket is not
            // allowed, so construction is suppressed.
            return None;
        }
        let iv_len = EVP_CIPHER_CTX_get_iv_length(ctx.as_ptr());
        if iv_len < 0 {
            return None;
        }
        let iv_len = iv_len as usize;
        // The callback's `iv` is `EVP_MAX_IV_LENGTH` bytes (the authority's buffer); a
        // cipher reporting a longer IV would make the copy below read past it.
        if iv_len > EVP_MAX_IV_LENGTH {
            return None;
        }
        // Encrypt (`EVP_EncryptUpdate`/`EVP_EncryptFinal`, `statem_srvr.c:4294-4306`). The
        // ciphertext block is heap-allocated through the crate's allocator seam: `0xFF00 + 32`
        // bytes on the stack would overflow a 32 KiB accept thread on its own.
        let enc_block = OwnedBuf::new(0xFF00 + 32, SeamFile::NULL, 0)?;
        let enc = enc_block.as_ptr();
        let mut enc1: c_int = 0;
        let mut enc2: c_int = 0;
        if EVP_EncryptUpdate(ctx.as_ptr(), enc, &mut enc1, senc.as_ptr(), slen as c_int) <= 0
            || EVP_EncryptFinal_ex(ctx.as_ptr(), enc.add(enc1 as usize), &mut enc2) <= 0
        {
            return None;
        }
        let enclen = (enc1 as usize).checked_add(enc2 as usize)?;
        // ticket = key_name || iv || ciphertext, then HMAC over that prefix. The MAC tail
        // is reserved as `EVP_MAX_MD_SIZE`: the application's `ticket_key_cb` chooses the
        // HMAC digest, so the write length is not known here, and the authority reserves
        // `EVP_MAX_MD_SIZE` for exactly this `HMAC_Final` (`statem_srvr.c:4314-4317`). A
        // 32-byte reservation would be overflowed by SHA-384/512.
        let ticket_cap = TLSEXT_KEYNAME_LENGTH
            .checked_add(iv_len)
            .and_then(|n| n.checked_add(enclen))
            .and_then(|n| n.checked_add(crate::ssl::ssl_lib::EVP_MAX_MD_SIZE))?;
        let mut ticket = vec![0u8; ticket_cap];
        ticket[..TLSEXT_KEYNAME_LENGTH].copy_from_slice(&key_name);
        ticket[TLSEXT_KEYNAME_LENGTH..TLSEXT_KEYNAME_LENGTH + iv_len]
            .copy_from_slice(&iv[..iv_len]);
        ticket[TLSEXT_KEYNAME_LENGTH + iv_len..TLSEXT_KEYNAME_LENGTH + iv_len + enclen]
            // SAFETY: `EVP_EncryptUpdate`/`Final` wrote `enclen` bytes into the `enc` block.
            .copy_from_slice(core::slice::from_raw_parts(enc, enclen));
        let mac_at = TLSEXT_KEYNAME_LENGTH + iv_len + enclen;
        let mut hlen: c_uint = 0;
        if HMAC_Update(hctx.as_ptr(), ticket.as_ptr(), mac_at) <= 0
            || HMAC_Final(hctx.as_ptr(), ticket.as_mut_ptr().add(mac_at), &mut hlen) <= 0
        {
            return None;
        }
        let hlen = hlen as usize;
        if hlen > crate::ssl::ssl_lib::EVP_MAX_MD_SIZE {
            return None;
        }
        ticket.truncate(mac_at + hlen);
        Some(ticket)
    }
}

/// `SSL_TICKET_STATUS tls_decrypt_ticket(SSL_CONNECTION *s, const unsigned char *etick,`
/// `size_t eticklen, ...)` — `ssl/t1_lib.c:3041-3300`, reduced to the ticket-key-callback arm.
///
/// Verifies the HMAC, decrypts the `i2d_SSL_SESSION` blob and reconstructs it. Returns the session
/// (one reference owned by the caller) on success, or NULL.
///
/// # Safety
/// `s` is live; `etick` readable for `eticklen`.
unsafe fn tls13_decrypt_ticket(s: *mut Ssl, etick: &[u8]) -> *mut crate::ssl::ssl_lib::SslSession {
    use crate::evp::cipher_ctx::{
        EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex, EVP_DecryptUpdate,
    };
    use crate::mac::hmac::{HMAC_CTX_new, HMAC_Final, HMAC_Update};
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::ssl::ssl_asn1::d2i_SSL_SESSION;
    // SAFETY: `s` is live.
    unsafe {
        if etick.len() < TLSEXT_KEYNAME_LENGTH + EVP_MAX_IV_LENGTH {
            return core::ptr::null_mut();
        }
        let tctx = (*s).session_ctx;
        if tctx.is_null() {
            return core::ptr::null_mut();
        }
        // The cipher and HMAC contexts, owned here: their single release is `Drop` running the
        // authority's own `EVP_CIPHER_CTX_free`/`HMAC_CTX_free`, on every refusal and on success.
        // SAFETY: `EVP_CIPHER_CTX_new` is the matching constructor: it answered the whole, aligned
        // `EVP_CIPHER_CTX` block (or NULL, which yields `None`), live and owned solely by this
        // handle, whose `Drop` runs `EVP_CIPHER_CTX_free` -- its single release.
        let Some(ctx) = OwnedCtx::<crate::evp::cipher_ctx::EvpCipherCtx>::new(EVP_CIPHER_CTX_new())
        else {
            return core::ptr::null_mut();
        };
        // SAFETY: `HMAC_CTX_new` is the matching constructor: it answered the whole, aligned
        // `HMAC_CTX` block (or NULL, which yields `None`), live and owned solely by this handle,
        // whose `Drop` runs `HMAC_CTX_free` -- its single release.
        let Some(hctx) = OwnedCtx::<crate::mac::hmac::HmacCtx>::new(HMAC_CTX_new()) else {
            return core::ptr::null_mut();
        };
        let cb = match (*tctx).ticket_key_cb {
            Some(cb) => cb,
            None => {
                return core::ptr::null_mut();
            }
        };
        // `ticket_key_cb(ssl, etick, etick+16, ctx, hctx, 0)` (`t1_lib.c:3100-3120`).
        let rv = cb(
            s,
            etick.as_ptr() as *mut u8,
            etick.as_ptr().add(TLSEXT_KEYNAME_LENGTH) as *mut u8,
            ctx.as_ptr().cast(),
            hctx.as_ptr().cast(),
            0,
        );
        if rv <= 0 {
            return core::ptr::null_mut();
        }
        let ivlen = EVP_CIPHER_CTX_get_iv_length(ctx.as_ptr());
        if ivlen < 0 {
            return core::ptr::null_mut();
        }
        let ivlen = ivlen as usize;
        let mlen = crate::mac::hmac::HMAC_size(hctx.as_ptr());
        if mlen == 0
            || mlen > crate::ssl::ssl_lib::EVP_MAX_MD_SIZE
            || etick.len() <= TLSEXT_KEYNAME_LENGTH + ivlen + mlen
        {
            return core::ptr::null_mut();
        }
        let enc_end = etick.len() - mlen;
        let mut tick_hmac = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        let mut hlen: c_uint = 0;
        if HMAC_Update(hctx.as_ptr(), etick.as_ptr(), enc_end) <= 0
            || HMAC_Final(hctx.as_ptr(), tick_hmac.as_mut_ptr(), &mut hlen) <= 0
        {
            return core::ptr::null_mut();
        }
        let mut diff = 0u8;
        for i in 0..mlen {
            diff |= tick_hmac[i] ^ etick[enc_end + i];
        }
        if diff != 0 {
            return core::ptr::null_mut();
        }
        // Decrypt the blob after the IV. The plaintext buffer, allocated through the crate's
        // allocator seam at the authority's own size and site, is released by its handle's `Drop`.
        let ct_at = TLSEXT_KEYNAME_LENGTH + ivlen;
        let ct_len = enc_end - ct_at;
        // SAFETY: `CRYPTO_malloc` is this crate's own allocator and answers a block or NULL.
        let Some(sdec) = OwnedBuf::adopt_plain(
            CRYPTO_malloc(ct_len + 16, core::ptr::null(), 0).cast(),
            SeamFile::NULL,
            0,
        ) else {
            return core::ptr::null_mut();
        };
        let mut dec1: c_int = 0;
        let mut dec2: c_int = 0;
        if EVP_DecryptUpdate(
            ctx.as_ptr(),
            sdec.as_ptr(),
            &mut dec1,
            etick.as_ptr().add(ct_at),
            ct_len as c_int,
        ) <= 0
            || EVP_DecryptFinal_ex(ctx.as_ptr(), sdec.as_ptr().add(dec1 as usize), &mut dec2) <= 0
        {
            return core::ptr::null_mut();
        }
        let slen = dec1 as usize + dec2 as usize;
        let mut pp: *const u8 = sdec.as_ptr();
        d2i_SSL_SESSION(core::ptr::null_mut(), &mut pp, slen as core::ffi::c_long)
    }
}

/// `CON_FUNC_RETURN tls_construct_new_session_ticket(SSL_CONNECTION *s, WPACKET *pkt)` —
/// `ssl/statem/statem_srvr.c:4370-4507`, for the TLS1.3 arm.
///
/// The ticket body is `ticket_lifetime_hint(4) || ticket_age_add(4) || ticket_nonce<0..255> ||
/// ticket<1..2^16-1> || extensions<0..2^16-2>` (`create_ticket_prequel`, `statem_srvr.c:4085-4111`,
/// plus the NewSessionTicket wire layout, RFC 8446 §4.6.1). The PSK stored in the session is
/// `HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, Hash.length)`
/// (`statem_srvr.c:4433-4441`), and the ticket itself is the authority's stateless encrypted
/// `i2d_SSL_SESSION` ([`construct_stateless_ticket`]).
///
/// # Safety
/// `s` must be a live server connection whose handshake session is set.
unsafe fn tls13_construct_new_session_ticket(s: *mut Ssl) -> c_int {
    use crate::runtime::mem::CRYPTO_malloc;
    use crate::ssl::tls13_enc::write_handshake_message;
    // SAFETY: `s` is live.
    unsafe {
        // `statem_srvr.c:4410-4420`: after the first ticket (or on resumption) the handshake
        // session may already be in a cache, so it must be copied before it is modified.
        if (*s).sent_tickets != 0 || (*s).hit != 0 {
            let dup = crate::ssl::ssl_sess::ssl_session_dup((*s).session, 0);
            if dup.is_null() {
                return 0;
            }
            crate::ssl::ssl_sess::SSL_SESSION_free((*s).session);
            (*s).session = dup;
        }
        let sess = (*s).session;
        if sess.is_null() {
            return 0;
        }
        // `RAND_bytes_ex(... age_add_u.age_add_c ...)` (`statem_srvr.c:4427`).
        let mut age_add = [0u8; 4];
        if crate::rand::rand_lib::RAND_bytes(age_add.as_mut_ptr(), 4) <= 0 {
            return 0;
        }
        (*sess).ext_tick_age_add = u32::from_be_bytes(age_add);
        // The nonce is `s->next_ticket_nonce`, big-endian (`statem_srvr.c:4428-4432`).
        let nonce = (*s).next_ticket_nonce.to_be_bytes();
        // `tls13_hkdf_expand(... resumption_master_secret, "resumption", tick_nonce,`
        // `                  s->session->master_key, hashlen, 1)` (`statem_srvr.c:4433-4441`).
        if crate::ssl::tls13_enc::tls13_ticket_psk(s, &nonce, (*sess).master_key.as_mut_ptr()) == 0
        {
            return 0;
        }
        (*sess).master_key_length = (*s).hs_md_len;
        // `s->session->time = ossl_time_now(); ssl_session_calculate_timeout(s->session)`.
        (*sess).time = crate::ssl::ssl_sess::time_now_secs();
        crate::ssl::ssl_sess::ssl_session_calculate_timeout(sess);
        (*sess).ext_max_early_data = (*s).max_early_data;
        if !(*s).pending_cipher.is_null() {
            (*sess).cipher = (*s).pending_cipher;
            (*sess).cipher_id = (*(*s).pending_cipher).id as core::ffi::c_ulong;
        }
        // `create_ticket_prequel` (`statem_srvr.c:4093-4108`): the hint is the session timeout,
        // capped at one week per RFC 8446.
        let mut hint = (*sess).timeout;
        if hint > ONE_WEEK_SEC {
            hint = ONE_WEEK_SEC;
        }
        // The ticket is minted by the application's `ticket_key_cb`.
        let Some(ticket) = construct_stateless_ticket(s) else {
            // `CON_FUNC_DONT_SEND` (`statem_srvr.c:4480-4490`): count the ticket and move on.
            (*s).sent_tickets += 1;
            (*s).next_ticket_nonce += 1;
            return 1;
        };
        // The wire body. Its extent is checked before allocation and the builder refuses any
        // length that does not fit its prefix, so no partially framed ticket is ever sent.
        let extent = 4usize
            .checked_add(4)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(nonce.len()))
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_add(ticket.len()))
            .and_then(|n| n.checked_add(2));
        let Some(extent) = extent else {
            return 0;
        };
        let mut body = vec![0u8; extent];
        // The empty extensions vector is the authority's write for this reduction.
        let Some(written) = write_tls13_new_session_ticket_body(
            &mut body,
            &nonce,
            hint as u32,
            u32::from_be_bytes(age_add),
            &ticket,
            &[],
        ) else {
            return 0;
        };
        if written != body.len() {
            return 0;
        }

        // Record the ticket on the session; the client uses `SHA256(ticket)` as its resume id
        // (`statem_clnt.c:2851`). The server session's id stays empty (the stateless ticket is
        // self-describing), matching the authority.
        // Release any incumbent at the authority's own site (see `MemberBufSlot`).
        (*sess).ext_tick_slot().clear(core::ptr::null(), 0);
        let tp = CRYPTO_malloc(ticket.len(), core::ptr::null(), 0).cast::<u8>();
        if tp.is_null() {
            return 0;
        }
        core::ptr::copy_nonoverlapping(ticket.as_ptr(), tp, ticket.len());
        // `tp` is this call's fresh block of `ticket.len()` bytes; the member is empty.
        (*sess).ext_tick_slot().store(tp, ticket.len());
        (*sess).ext_tick_lifetime_hint = hint as core::ffi::c_ulong;
        (*sess).not_resumable = 0;

        // `tls_update_ticket_counts` (`statem_srvr.c:4355-4368`).
        (*s).sent_tickets += 1;
        (*s).next_ticket_nonce += 1;
        // `ssl_update_cache(s, SSL_SESS_CACHE_SERVER)` (`statem_srvr.c:4505`): with `session_id`
        // empty this is a no-op for the internal cache, exactly as in the authority; the
        // `new_session_cb` still fires.
        crate::ssl::ssl_sess::ssl_update_cache(s, crate::ssl::ssl_sess::SSL_SESS_CACHE_SERVER);

        // SAFETY: `s` is live; `body[..written]` is fully initialised by the builder.
        write_handshake_message(s, SSL3_MT_NEWSESSION_TICKET, body.as_ptr(), written)
    }
}

/// `ssl3_do_write`'s `ChangeCipherSpec` arm, plaintext, plus the authority's `msg_callback`
/// invocation (`statem_lib.c:114-118`).
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_write_change_cipher_spec(s: *mut Ssl, is_client: bool) -> c_int {
    let ccs = TLS12_CHANGE_CIPHER_SPEC_BODY;
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
pub(crate) unsafe fn tls12_read_handshake(s: *mut Ssl) -> Option<(Vec<u8>, usize)> {
    // Heap-allocated: a record-sized stack array here (on the TLS1.2 accept/connect path) would
    // overflow a small accept thread.
    let mut buf = vec![0u8; 16384];
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

/// Bounds a Finished verify-data handoff to the bytes `tls12_finished_mac`/
/// `tls13_finished_mac` reports as initialised. `None` means the callee produced no bytes or
/// claimed more than its fixed output buffer holds.
fn finished_verify_data(out: &[u8], produced: usize) -> Option<&[u8]> {
    out.get(..produced)
        .filter(|verify_data| !verify_data.is_empty())
}

/// Copies Finished verify_data into a connection's fixed `EVP_MAX_MD_SIZE` binding array.
/// `None` means the value cannot fit; the destination is then unchanged.
fn store_finished_verify_data(
    dst: &mut [u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE],
    verify_data: &[u8],
) -> Option<usize> {
    let len = verify_data.len();
    let slot = dst.get_mut(..len)?;
    slot.copy_from_slice(verify_data);
    Some(len)
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
    // SAFETY: `s` is live; `out` is writable for `out.len()` bytes; the callee reports how many
    // it initialised.
    let n = unsafe { crate::ssl::t1_enc::tls12_finished_mac(s, label, out.as_mut_ptr()) };
    let Some(verify_data) = finished_verify_data(&out, n) else {
        return 0;
    };
    // The `tls-unique` channel binding reads this side's Finished verify_data
    // (`SSL_get_finished`, `ssl_lib.c:1799-1812`). Refuse before writing if it cannot be stored.
    if crate::ssl::ssl_lib::EVP_MAX_MD_SIZE < verify_data.len() {
        return 0;
    }
    // SAFETY: `s` is live; `verify_data` is initialised and bounded by `out`.
    let r = unsafe {
        write_handshake_message(
            s,
            SSL3_MT_FINISHED as u8,
            verify_data.as_ptr(),
            verify_data.len(),
        )
    };
    if r > 0 {
        // SAFETY: `s` is live; the check above established that `finish_md` holds this value.
        unsafe {
            let Some(stored) = store_finished_verify_data(&mut (*s).finish_md, verify_data) else {
                return 0;
            };
            (*s).finish_md_len = stored;
        }
    }
    r
}

/// `tls_process_client_key_exchange` (`statem_srvr.c:2959-3095`) for the ECDHE and static-RSA
/// arms: parse the client's key-exchange value, derive the pre-master secret, then the master
/// secret and key block (`ssl_derive`, `s3_lib.c:5474-5528`).
///
/// # Safety
/// `s` is live; `msg` is the full ClientKeyExchange message.
unsafe fn tls12_process_client_key_exchange(s: *mut Ssl, msg: &[u8]) -> c_int {
    use crate::ssl::ssl_ciph_table as ct;
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
    // SAFETY: `s` is live.
    let mkey = unsafe { (*(*s).pending_cipher).algorithm_mkey as u64 };
    // The premaster is a secret stack copy; the guard wipes it on every return path, not only on
    // success. 80 bytes covers an X25519/X448 secret and a P-521 x-coordinate (66).
    let mut pms = crate::runtime::mem::CleansedScratch::<80>::new();
    let pmslen = if (mkey & ct::SSL_kRSA) != 0 && (mkey & ct::SSL_kECDHE) == 0 {
        // `tls_process_cke_rsa` (`statem_srvr.c:3157-3250`). TLS1.2 prefixes the encrypted
        // pre-master with its two-byte length; the reduced state machine never negotiates SSLv3.
        if body.len() < 2 {
            return 0;
        }
        let enclen = ((body[0] as usize) << 8) | body[1] as usize;
        if 2 + enclen != body.len() {
            return 0;
        }
        // SAFETY: `s` is live and holds the active certificate slot.
        let cpk = unsafe { crate::ssl::ssl_lib::cert_active_key((*s).cert) };
        // SAFETY: `cpk` is the active slot and its key field is a live key or NULL.
        if cpk.is_null() || unsafe { (*cpk).privatekey }.is_null() {
            return 0;
        }
        // SAFETY: `cpk.privatekey` is a live RSA key for this static-RSA suite.
        let rsa = unsafe { (*cpk).privatekey }.cast::<crate::evp::pkey::EvpPkey>();
        // SAFETY: `s` is live.
        let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq()) };
        // SAFETY: `libctx`/`propq` are the context's and `rsa` is live.
        let ctx = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_from_pkey(libctx, rsa, propq) };
        if ctx.is_null() {
            return 0;
        }
        // The TLS padding mode makes a padding or version failure look like a successful
        // decryption with a random result (RFC 5246 §7.4.7.1); it is the authority's choice and
        // must not be replaced with a plain PKCS#1 decrypt followed by a version compare.
        // SAFETY: `ctx` is live.
        let mut client_version = unsafe { (*s).client_version as core::ffi::c_uint };
        let mut params = [crate::params::OSSL_PARAM_construct_end(); 2];
        // SAFETY: the name is NUL-terminated; `client_version` is this frame's live slot.
        params[0] = unsafe {
            crate::params::OSSL_PARAM_construct_uint(
                c"tls-client-version".as_ptr(),
                &mut client_version,
            )
        };
        // SAFETY: `ctx` is live and `params` is terminated.
        let ok = unsafe {
            crate::evp::asymcipher::EVP_PKEY_decrypt_init(ctx) > 0
                && crate::rsa::ctrl::EVP_PKEY_CTX_set_rsa_padding(
                    ctx,
                    crate::evp::pkey_ctx::RSA_PKCS1_WITH_TLS_PADDING,
                ) > 0
                && crate::evp::pkey_ctx::EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) > 0
        };
        let mut outlen = crate::ssl::ssl_lib::SSL_MAX_MASTER_KEY_LENGTH;
        // SAFETY: `ctx` is live; `pms` is writable for `outlen` bytes; `body[2..]` is readable.
        let ok = ok
            && unsafe {
                crate::evp::asymcipher::EVP_PKEY_decrypt(
                    ctx,
                    pms.as_mut_ptr(),
                    &mut outlen,
                    body.as_ptr().add(2),
                    enclen,
                )
            } > 0;
        // SAFETY: `ctx` is this frame's own context.
        unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_free(ctx) };
        if !ok || outlen != crate::ssl::ssl_lib::SSL_MAX_MASTER_KEY_LENGTH {
            return 0;
        }
        outlen
    } else if (mkey & ct::SSL_kECDHE) != 0 {
        // `tls_process_cke_ecdhe` (`statem_srvr.c:3288-3366`): `ClientECDHParams` is a
        // one-byte-length-prefixed encoded point for the group selected in the ServerKeyExchange.
        let ptlen = body[0] as usize;
        if ptlen == 0 || 1 + ptlen != body.len() {
            return 0;
        }
        // SAFETY: `s` is live; `body[1..]` is the encoded point for `(*s).group_id`.
        let peer = unsafe { tls12_peer_key_from_point(s, (*s).group_id, &body[1..]) };
        if peer.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; `peer` is this frame's fresh key and the slot's previous owner is
        // released first (the authority's `EVP_PKEY_free(s->s3.peer_tmp)` assignment).
        unsafe {
            crate::evp::pkey::EVP_PKEY_free((*s).peer_tmp.cast());
            (*s).peer_tmp = peer.cast();
        }
        let mut got = 0usize;
        // SAFETY: `s` is live; the ephemerals are set; `pms` is writable (80 bytes covers a P-521
        // shared secret's 66 bytes); `got` is this frame's writable slot.
        let derived = unsafe {
            crate::ssl::tls13_enc::tls13_derive_shared(
                s,
                (*s).pkey,
                (*s).peer_tmp,
                pms.as_mut_ptr(),
                80,
                &mut got,
            )
        };
        if derived == 0 {
            return 0;
        }
        // `got` is the shared secret's length (the group's field size).
        got
    } else {
        return 0;
    };
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
    // SAFETY: `s` is live; `expected` is writable for `expected.len()` bytes; the callee reports
    // how many it initialised.
    let n = unsafe { crate::ssl::t1_enc::tls12_finished_mac(s, label, expected.as_mut_ptr()) };
    let Some(verify_data) = finished_verify_data(&expected, n) else {
        return 0;
    };
    if verify_data.len() != 12 || body.len() != 12 {
        return 0;
    }
    let mut diff = 0u8;
    for (a, b) in verify_data.iter().zip(body) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return 0;
    }
    // The `tls-unique` channel binding on the peer reads the client's Finished verify_data
    // (`SSL_get_peer_finished`, `ssl_lib.c:1815-1828`). The binding array is fixed-size.
    if crate::ssl::ssl_lib::EVP_MAX_MD_SIZE < verify_data.len() {
        return 0;
    }
    // SAFETY: `s` is live; the check above established that `peer_finish_md` holds this value.
    unsafe {
        let Some(stored) = store_finished_verify_data(&mut (*s).peer_finish_md, verify_data) else {
            return 0;
        };
        (*s).peer_finish_md_len = stored;
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
                    // `ossl_statem_server_write_transition`'s `TLS_ST_SW_CERT ->
                    // TLS_ST_SW_CERT_STATUS` arm (`statem_srvr.c:658-670`) when the OCSP callback
                    // armed `status_expected`; the reduced driver emits the message here rather
                    // than through a separate state.
                    // SAFETY: `s` is live.
                    if (*s).ext_status_expected != 0 && tls12_construct_cert_status(s) <= 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // Only suites whose key exchange needs ephemeral parameters send a
                    // `ServerKeyExchange` (`send_server_key_exchange`, `statem_srvr.c:353-386`).
                    // A static-RSA suite goes straight to CertificateRequest/ServerHelloDone;
                    // entering `TLS_ST_SW_KEY_EXCH` unconditionally made it build an ECDHE flight
                    // and fail with a key-share error.
                    (*s).hand_state = if send_server_key_exchange(s) {
                        TLS_ST_SW_KEY_EXCH
                    } else if (*s).s3_tmp_cert_request != 0 {
                        TLS_ST_SW_CERT_REQ
                    } else {
                        TLS_ST_SW_SRVR_DONE
                    };
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
                    if tls12_construct_server_hello_done(s) <= 0 {
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
        // A TLS1.2 handshake that returned a wait must resume in its own driver on re-entry, and
        // it needs no handshake read buffer here.
        if (*s).tls12_driver != 0 {
            return tls12_server_drive(s);
        }
    }
    // The handshake-message read buffer is heap-allocated for the whole drive: a 16 KiB stack
    // array here (plus the record encoder's frame) overflows a 32 KiB accept thread. Its single
    // release is the handle's `Drop` on every return below.
    let Some(msg_buf) = OwnedBuf::new(crate::ssl::ssl_lib::TLS13_HS_BUF_LEN, SeamFile::NULL, 0)
    else {
        // SAFETY: `s` is live.
        unsafe { ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR) };
        return -1;
    };
    // SAFETY: `s` is live.
    unsafe {
        loop {
            match (*s).hand_state {
                TLS_ST_BEFORE => {
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        msg_buf.as_ptr(),
                        crate::ssl::ssl_lib::TLS13_HS_BUF_LEN,
                    );
                    if n <= 0 || *msg_buf.as_ptr() != SSL3_MT_CLIENT_HELLO_BODY {
                        return server_wait(s);
                    }
                    let pr = tls_process_client_hello(
                        s,
                        core::slice::from_raw_parts(msg_buf.as_ptr(), n as usize),
                    );
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
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        msg_buf.as_ptr(),
                        crate::ssl::ssl_lib::TLS13_HS_BUF_LEN,
                    );
                    if n <= 0 {
                        return server_wait(s);
                    }
                    if *msg_buf.as_ptr() == SSL3_MT_CERTIFICATE_VERIFY as u8 {
                        // The client sent an empty Certificate, so per `received_client_cert`
                        // (`statem_srvr.c:122-135`) a CertificateVerify cannot follow; reject it.
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if *msg_buf.as_ptr() != SSL3_MT_CERT {
                        ossl_statem_fatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_R_UNEXPECTED_MESSAGE);
                        return -1;
                    }
                    if crate::ssl::statem::statem_clnt::tls13_process_peer_certificate(
                        s,
                        core::slice::from_raw_parts(msg_buf.as_ptr(), n as usize),
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
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        msg_buf.as_ptr(),
                        crate::ssl::ssl_lib::TLS13_HS_BUF_LEN,
                    );
                    if n <= 0 || *msg_buf.as_ptr() != SSL3_MT_CERTIFICATE_VERIFY as u8 {
                        return server_wait(s);
                    }
                    if crate::ssl::statem::statem_clnt::tls_process_cert_verify(
                        s,
                        core::slice::from_raw_parts(msg_buf.as_ptr(), n as usize),
                        true,
                    ) == 0
                    {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    (*s).hand_state = TLS_ST_SR_FINISHED;
                }
                TLS_ST_SR_FINISHED => {
                    let n = crate::ssl::record::rec_layer_s3::tls13_next_handshake_message(
                        s,
                        msg_buf.as_ptr(),
                        crate::ssl::ssl_lib::TLS13_HS_BUF_LEN,
                    );
                    if n <= 0 || *msg_buf.as_ptr() != SSL3_MT_FIN {
                        return server_wait(s);
                    }
                    let secret = (*s).client_hs_traffic.as_ptr();
                    if k::tls13_process_finished(
                        s,
                        core::slice::from_raw_parts(msg_buf.as_ptr(), n as usize),
                        secret,
                    ) == 0
                    {
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
                    // The `"res master"` arm of `tls13_change_cipher_state` (`tls13_enc.c:675-685`)
                    // runs on the server while reading the client Finished; the transcript now
                    // includes it.
                    if k::tls13_derive_resumption_master_secret(s) == 0 {
                        ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    // `server13_write_transition`'s `TLS_ST_SR_FINISHED`/`TLS_ST_SW_SESSION_TICKET`
                    // arms (`statem_srvr.c:707-742`): with `ext.ticket_expected` set a fresh
                    // handshake writes `num_tickets` tickets, a resumption at most one. This runs
                    // as part of `SSL_accept` because the authority keeps `in_init` set while the
                    // post-Finished tickets go out.
                    if (*s).ext_ticket_expected != 0 && (*s).num_tickets > (*s).sent_tickets {
                        let want = if (*s).hit != 0 { 1 } else { (*s).num_tickets };
                        let mut budget = want;
                        while budget > 0 {
                            if tls13_construct_new_session_ticket(s) <= 0 {
                                ossl_statem_fatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                                return -1;
                            }
                            budget -= 1;
                        }
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

// -------------------------------------------------------------------------------------------
// `CertificateStatus` body construction (tls_construct_cert_status_body)
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod cert_status_body_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::write_cert_status_body;

    #[test]
    fn body_is_type_then_u24_length_then_response() {
        let resp = [0xaa, 0xbb, 0xcc];
        let mut out = [0u8; 7];
        assert!(write_cert_status_body(&mut out, 1, &resp));
        assert_eq!(out, [1, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn empty_response_encodes_a_zero_length() {
        let mut out = [0xffu8; 4];
        assert!(write_cert_status_body(&mut out, 1, &[]));
        assert_eq!(out, [1, 0, 0, 0]);
    }

    /// Negative control: a body block one byte short or one byte long is refused and
    /// left untouched, rather than letting the u24 length disagree with the buffer.
    #[test]
    fn malformed_out_length_is_refused_without_writing() {
        let resp = [0xaa, 0xbb, 0xcc];

        let mut short = [0u8; 6];
        assert!(!write_cert_status_body(&mut short, 1, &resp));
        assert_eq!(short, [0u8; 6]);

        let mut long = [0u8; 8];
        assert!(!write_cert_status_body(&mut long, 1, &resp));
        assert_eq!(long, [0u8; 8]);

        let mut empty = [0u8; 0];
        assert!(!write_cert_status_body(&mut empty, 1, &resp));
    }

    /// Negative control: a response that cannot be expressed in the wire's u24 length
    /// is refused before any length arithmetic or write.
    #[test]
    fn oversized_response_is_refused() {
        let resp = vec![0u8; 0x0100_0000];
        let mut out = [0u8; 0];
        assert!(!write_cert_status_body(&mut out, 1, &resp));
    }
}

// -------------------------------------------------------------------------------------------
// ServerHello prelude / EncryptedExtensions body construction
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod server_hello_body_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::{
        write_encrypted_extensions_body, write_server_hello_prefix, write_tls12_server_hello_body,
    };

    fn fixed_random() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    /// Byte-exact TLS1.3 ServerHello prelude for a fixed transcript, including a legacy
    /// session id longer than 32 bytes: the echo length and payload are taken from the slice,
    /// so the writer neither truncates nor reads past it.
    #[test]
    fn tls13_server_hello_prefix_is_byte_exact() {
        let random = fixed_random();
        let sid: Vec<u8> = (0..40u8).map(|i| 0xc0 + i).collect();
        let mut out = [0u8; 96];
        let n = write_server_hello_prefix(&mut out, 0x0303, &random, &sid, 0x1301).unwrap();

        let mut expected = vec![0x03, 0x03];
        expected.extend_from_slice(&random);
        expected.push(40);
        expected.extend_from_slice(&sid);
        expected.extend_from_slice(&[0x13, 0x01, 0x00]);

        assert_eq!(n, 78);
        assert_eq!(&out[..n], &expected[..]);
    }

    #[test]
    fn tls13_server_hello_prefix_encodes_an_empty_session_id() {
        let random = [0x5au8; 32];
        let mut out = [0u8; 64];
        let n = write_server_hello_prefix(&mut out, 0x0303, &random, &[], 0x1302).unwrap();

        let mut expected = vec![0x03, 0x03];
        expected.extend_from_slice(&random);
        expected.extend_from_slice(&[0x00, 0x13, 0x02, 0x00]);

        assert_eq!(n, 38);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// Byte-exact TLS1.2 ServerHello body with the full extension block.
    #[test]
    fn tls12_server_hello_body_is_byte_exact() {
        let random = fixed_random();
        let sid = [0xde, 0xad, 0xbe, 0xef];
        let mut out = [0u8; 96];
        let n = write_tls12_server_hello_body(&mut out, 0x0303, &random, &sid, 0xc02f, true, true)
            .unwrap();

        let mut expected = vec![0x03, 0x03];
        expected.extend_from_slice(&random);
        expected.extend_from_slice(&[0x04]);
        expected.extend_from_slice(&sid);
        expected.extend_from_slice(&[0xc0, 0x2f, 0x00]);
        expected.extend_from_slice(&[0x00, 0x0d]);
        expected.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        expected.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
        expected.extend_from_slice(&[0x00, 0x05, 0x00, 0x00]);

        assert_eq!(n, 57);
        assert_eq!(&out[..n], &expected[..]);
    }

    #[test]
    fn tls12_server_hello_body_minimal_extension_block_is_byte_exact() {
        let random = [0u8; 32];
        let mut out = [0u8; 96];
        let n = write_tls12_server_hello_body(&mut out, 0x0303, &random, &[], 0x009c, false, false)
            .unwrap();

        let mut expected = vec![0x03, 0x03];
        expected.extend_from_slice(&random);
        expected.extend_from_slice(&[0x00, 0x00, 0x9c, 0x00]);
        expected.extend_from_slice(&[0x00, 0x05]);
        expected.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        assert_eq!(n, 45);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// Byte-exact EncryptedExtensions with the negotiated ALPN protocol `h2`.
    #[test]
    fn encrypted_extensions_is_byte_exact() {
        let mut out = [0u8; 32];
        let n = write_encrypted_extensions_body(&mut out, Some(b"h2")).unwrap();
        assert_eq!(n, 11);
        assert_eq!(
            &out[..n],
            &[0x00, 0x09, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'2']
        );
    }

    #[test]
    fn encrypted_extensions_with_an_empty_extension_set_is_two_zero_bytes() {
        let mut out = [0xffu8; 4];
        let n = write_encrypted_extensions_body(&mut out, None).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&out[..n], &[0x00, 0x00]);

        // An empty and an over-long protocol are both omitted, as before.
        let n = write_encrypted_extensions_body(&mut out, Some(&[])).unwrap();
        assert_eq!(&out[..n], &[0x00, 0x00]);
        let over_long = vec![0x61u8; 256];
        let n = write_encrypted_extensions_body(&mut out, Some(&over_long)).unwrap();
        assert_eq!(&out[..n], &[0x00, 0x00]);
    }

    /// Negative control: a deliberately too-small block is refused by every body writer instead
    /// of panicking or writing past it.
    #[test]
    fn too_small_writer_buffers_fail_cleanly() {
        let random = fixed_random();
        let sid: Vec<u8> = (0..40u8).map(|i| 0xc0 + i).collect();

        let mut short_prefix = [0u8; 77];
        assert!(
            write_server_hello_prefix(&mut short_prefix, 0x0303, &random, &sid, 0x1301).is_none()
        );
        let mut exact_prefix = [0u8; 78];
        assert!(
            write_server_hello_prefix(&mut exact_prefix, 0x0303, &random, &sid, 0x1301).is_some()
        );

        let mut short_tls12 = [0u8; 54];
        assert!(write_tls12_server_hello_body(
            &mut short_tls12,
            0x0303,
            &random,
            &[0xde, 0xad],
            0xc02f,
            true,
            true,
        )
        .is_none());

        let mut short_ee = [0u8; 10];
        assert!(write_encrypted_extensions_body(&mut short_ee, Some(b"h2")).is_none());
        let mut empty_ee = [0u8; 0];
        assert!(write_encrypted_extensions_body(&mut empty_ee, None).is_none());
    }

    /// Negative control: a one-byte length cannot express a 256-byte session id, so the writer
    /// refuses rather than truncating the length.
    #[test]
    fn over_long_session_id_is_refused_by_the_one_byte_length() {
        let random = fixed_random();
        let sid = vec![0u8; 256];
        let mut out = [0u8; 400];
        assert!(write_server_hello_prefix(&mut out, 0x0303, &random, &sid, 0x1301).is_none());
    }

    /// The production ServerHello writer refuses a recorded session-id length outside the
    /// member array before deriving any slice from it.
    #[test]
    fn server_hello_refuses_an_out_of_range_session_id_length() {
        use super::tls_construct_server_hello;

        let _g = crate::test_support::lock_global_state();
        // SAFETY: the connection block is this frame's allocation, its fields are set before the
        // writer reads them, and both the packet and the block are released here.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).pending_cipher = crate::ssl::ssl_ciph::ssl3_get_cipher_by_id(
                crate::ssl::ssl_ciph_table::SSL3_CK_CIPHERSUITE_FLAG as u32 | 0x1301,
            );
            assert!(!(*s).pending_cipher.is_null());
            (*s).tmp_session_id_len = crate::ssl::ssl_lib::SSL_MAX_SSL_SESSION_ID_LENGTH + 1;

            let mut buf = [0u8; 128];
            let mut pkt: crate::packet::Wpacket = core::mem::zeroed();
            assert_eq!(
                crate::packet::WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0),
                1
            );
            assert_eq!(tls_construct_server_hello(s, &mut pkt), 0);
            crate::packet::WPACKET_cleanup(&mut pkt);
            crate::runtime::mem::CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }
}

// -------------------------------------------------------------------------------------------
// TLS1.3 NewSessionTicket framing and Finished verify-data handoff
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod tls13_ticket_finished_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::{
        finished_verify_data, server13_write_transition, store_finished_verify_data,
        write_tls13_new_session_ticket_body, TLS12_CHANGE_CIPHER_SPEC_BODY, TLS_ST_OK,
        TLS_ST_SW_KEY_UPDATE, WRITE_TRAN_CONTINUE, WRITE_TRAN_FINISHED,
    };

    const SENTINEL: u8 = 0xa5;
    const TICKET: [u8; 6] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];

    /// A zero-length nonce and zero lifetime: `lifetime(4) || age(4) || nonce<0> ||
    /// ticket<len(2)> || extensions<0>`.
    #[test]
    fn ticket_with_zero_length_nonce_and_zero_lifetime_is_byte_exact() {
        let mut out = [SENTINEL; 19];
        let n = write_tls13_new_session_ticket_body(&mut out, &[], 0, 0, &TICKET, &[]).unwrap();
        assert_eq!(n, 19);
        let mut expected = vec![0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x06];
        expected.extend_from_slice(&TICKET);
        expected.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// A non-empty nonce and non-zero lifetime/age-add encode in wire order.
    #[test]
    fn ticket_with_nonce_and_nonzero_lifetime_is_byte_exact() {
        let nonce = [0xaa, 0xbb, 0xcc];
        let mut out = [SENTINEL; 22];
        let n = write_tls13_new_session_ticket_body(
            &mut out,
            &nonce,
            0x0000_0abc,
            0x0102_0304,
            &TICKET,
            &[],
        )
        .unwrap();
        assert_eq!(n, 22);
        let mut expected = vec![
            0x00, 0x00, 0x0a, 0xbc, // ticket_lifetime
            0x01, 0x02, 0x03, 0x04, // ticket_age_add
            0x03, 0xaa, 0xbb, 0xcc, // ticket_nonce<3>
            0x00, 0x06,
        ];
        expected.extend_from_slice(&TICKET);
        expected.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// Extensions are a u16 length-prefixed vector and follow the ticket exactly.
    #[test]
    fn ticket_with_extensions_is_byte_exact() {
        let nonce = [0x01];
        let extensions = [0x00, 0x2b, 0x00, 0x02];
        let mut out = [SENTINEL; 24];
        let n = write_tls13_new_session_ticket_body(&mut out, &nonce, 7, 9, &TICKET, &extensions)
            .unwrap();
        assert_eq!(n, 24);
        let mut expected = vec![
            0x00, 0x00, 0x00, 0x07, // ticket_lifetime
            0x00, 0x00, 0x00, 0x09, // ticket_age_add
            0x01, 0x01, // ticket_nonce<1>
            0x00, 0x06,
        ];
        expected.extend_from_slice(&TICKET);
        expected.extend_from_slice(&[0x00, 0x04]);
        expected.extend_from_slice(&extensions);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// The u32 fields are full width: their maximum values are emitted, not truncated.
    #[test]
    fn ticket_encodes_full_width_u32_fields() {
        let mut out = [SENTINEL; 19];
        let n =
            write_tls13_new_session_ticket_body(&mut out, &[], u32::MAX, u32::MAX, &TICKET, &[])
                .unwrap();
        assert_eq!(&out[..8], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(n, 19);
    }

    /// Every length that cannot be expressed in its prefix is refused before any byte is
    /// written, including a u16-overflowing ticket or extension vector.
    #[test]
    fn ticket_length_overflows_are_refused_transactionally() {
        let mut out = [SENTINEL; 64];
        let before = out;
        assert!(
            write_tls13_new_session_ticket_body(&mut out, &[0; 256], 0, 0, &TICKET, &[]).is_none()
        );
        assert_eq!(out, before);

        let long_ticket = vec![0x5au8; u16::MAX as usize + 1];
        let mut out = [SENTINEL; 16];
        let before = out;
        assert!(
            write_tls13_new_session_ticket_body(&mut out, &[], 0, 0, &long_ticket, &[]).is_none()
        );
        assert_eq!(out, before);

        let long_exts = vec![0u8; u16::MAX as usize + 1];
        let mut out = [SENTINEL; 16];
        let before = out;
        assert!(
            write_tls13_new_session_ticket_body(&mut out, &[], 0, 0, &TICKET, &long_exts).is_none()
        );
        assert_eq!(out, before);
    }

    /// One byte short of the exact extent is refused with the buffer unchanged.
    #[test]
    fn ticket_refuses_a_short_buffer_transactionally() {
        let nonce = [0xaa, 0xbb, 0xcc];
        let mut out = [SENTINEL; 21];
        let before = out;
        assert!(write_tls13_new_session_ticket_body(
            &mut out,
            &nonce,
            0x0abc,
            0x0102_0304,
            &TICKET,
            &[]
        )
        .is_none());
        assert_eq!(out, before);
    }

    /// The TLS1.2 verify-data handoff (12 bytes) is bounded by the produced length and stored
    /// byte-for-byte in the fixed binding array.
    #[test]
    fn tls12_finished_handoff_is_byte_exact() {
        let produced = [0x5au8; 12];
        let verify_data = finished_verify_data(&produced, 12).unwrap();
        assert_eq!(verify_data, &produced[..]);

        let mut binding = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        let n = store_finished_verify_data(&mut binding, verify_data).unwrap();
        assert_eq!(n, 12);
        assert_eq!(&binding[..12], &produced[..]);
        assert!(binding[12..].iter().all(|&b| b == 0));
    }

    /// The TLS1.3 verify-data handoff (a full hash, 32 bytes here) is likewise bounded and exact.
    #[test]
    fn tls13_finished_handoff_is_byte_exact() {
        let mut produced = [0u8; 32];
        for (i, b) in produced.iter_mut().enumerate() {
            *b = i as u8;
        }
        let verify_data = finished_verify_data(&produced, 32).unwrap();
        assert_eq!(verify_data, &produced[..]);

        let mut binding = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        let n = store_finished_verify_data(&mut binding, verify_data).unwrap();
        assert_eq!(n, 32);
        assert_eq!(&binding[..32], &produced[..]);
    }

    /// A produced length of zero, or one past the output buffer, is refused rather than sliced.
    #[test]
    fn finished_handoff_refuses_an_invalid_produced_length() {
        let produced = [0u8; 12];
        assert!(finished_verify_data(&produced, 0).is_none());
        assert!(finished_verify_data(&produced, 13).is_none());

        let mut binding = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        let before = binding;
        let too_long = vec![0xa5u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE + 1];
        assert!(store_finished_verify_data(&mut binding, &too_long).is_none());
        assert_eq!(binding, before);
    }

    /// `ChangeCipherSpec` is the single byte `0x01`.
    #[test]
    fn change_cipher_spec_body_is_the_byte_one() {
        assert_eq!(TLS12_CHANGE_CIPHER_SPEC_BODY, [0x01]);
    }

    /// Both defined `SSL_key_update` request values (0 = not requested, 1 = requested) arm the
    /// server key-update state; `SSL_KEY_UPDATE_NONE` (-1) does not.
    #[test]
    fn key_update_request_values_arm_the_server_key_update_state() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the connection block is this frame's allocation, released at the end.
        unsafe {
            for request in [0, 1] {
                let s = crate::ssl::adv_alloc::zeroed_ssl();
                assert!(!s.is_null());
                (*s).hand_state = TLS_ST_OK;
                (*s).key_update = request;
                assert_eq!(server13_write_transition(s), WRITE_TRAN_CONTINUE);
                assert_eq!((*s).hand_state, TLS_ST_SW_KEY_UPDATE);
                crate::runtime::mem::CRYPTO_free(s.cast(), core::ptr::null(), 0);
            }

            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).hand_state = TLS_ST_OK;
            (*s).key_update = -1;
            assert_eq!(server13_write_transition(s), WRITE_TRAN_FINISHED);
            assert_eq!((*s).hand_state, TLS_ST_OK);
            crate::runtime::mem::CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
    }
}

// -------------------------------------------------------------------------------------------
// BytesWriter transactional invariants
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod bytes_writer_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::BytesWriter;

    const SENTINEL: u8 = 0xa5;

    /// A too-small buffer is refused with the cursor and every byte of the buffer unchanged:
    /// no length prefix is left behind for a payload that did not fit.
    #[test]
    fn composite_operations_are_transactional_when_one_byte_short() {
        let payload = [0x11u8, 0x22, 0x33, 0x44];

        let mut out = [SENTINEL; 4]; // needs 1 + 4 = 5
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u8_len_prefixed(&payload));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);

        let mut out = [SENTINEL; 5]; // needs 2 + 4 = 6
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u16_len_prefixed(&payload));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);

        let mut out = [SENTINEL; 2]; // needs 3
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u24(0x01_02_03));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);
    }

    /// Exactly the required extent succeeds and produces the exact wire bytes.
    #[test]
    fn composite_operations_succeed_with_exact_bytes_at_exact_size() {
        let payload = [0x11u8, 0x22, 0x33, 0x44];

        let mut out = [SENTINEL; 5];
        let mut w = BytesWriter::new(&mut out);
        assert!(w.put_u8_len_prefixed(&payload));
        assert_eq!(w.written(), 5);
        assert_eq!(out, [4, 0x11, 0x22, 0x33, 0x44]);

        let mut out = [SENTINEL; 6];
        let mut w = BytesWriter::new(&mut out);
        assert!(w.put_u16_len_prefixed(&payload));
        assert_eq!(w.written(), 6);
        assert_eq!(out, [0x00, 0x04, 0x11, 0x22, 0x33, 0x44]);

        let mut out = [SENTINEL; 3];
        let mut w = BytesWriter::new(&mut out);
        assert!(w.put_u24(0x01_02_03));
        assert_eq!(w.written(), 3);
        assert_eq!(out, [0x01, 0x02, 0x03]);
    }

    /// A payload longer than a one-byte length can express is refused before any write, even
    /// though the destination buffer would be large enough.
    #[test]
    fn u8_length_prefix_refuses_a_payload_over_255_bytes() {
        let payload = vec![0x5au8; 256];
        let mut out = [SENTINEL; 300];
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u8_len_prefixed(&payload));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);
    }

    /// A u24 value above `0xFF_FFFF` is refused with nothing written and no cursor advance.
    #[test]
    fn u24_refuses_a_value_over_ffffff() {
        let mut out = [SENTINEL; 3];
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u24(0x1_00_00_00));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);
    }

    /// An empty payload still writes its length prefix and advances by exactly the prefix size.
    #[test]
    fn zero_length_payloads_write_only_the_prefix() {
        let mut out = [SENTINEL; 1];
        let mut w = BytesWriter::new(&mut out);
        assert!(w.put_u8_len_prefixed(&[]));
        assert_eq!(w.written(), 1);
        assert_eq!(out, [0x00]);

        let mut out = [SENTINEL; 2];
        let mut w = BytesWriter::new(&mut out);
        assert!(w.put_u16_len_prefixed(&[]));
        assert_eq!(w.written(), 2);
        assert_eq!(out, [0x00, 0x00]);
    }

    /// The primitive operations are all-or-nothing as well.
    #[test]
    fn primitive_operations_are_transactional() {
        let mut out = [SENTINEL; 1];
        let before = out;
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u16(0x0102));
        assert_eq!(w.written(), 0);
        assert_eq!(out, before);

        let mut out = [SENTINEL; 0];
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u8(1));
        assert!(!w.put_bytes(&[1]));
        assert_eq!(w.written(), 0);
        assert_eq!(out, []);
    }
}

// -------------------------------------------------------------------------------------------
// CertificateRequest / Certificate / CertificateVerify body construction
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod certificate_body_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::{
        write_cert_verify_body, write_certificate_request_body, write_tls12_certificate_body,
        write_tls13_certificate_body, BytesWriter,
    };

    /// One TLS1.3 `CertificateEntry`: `u24(der_len) || DER || u16(0)`.
    #[test]
    fn tls13_certificate_with_one_cert_is_byte_exact() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let mut out = [0u8; 32];
        let n = write_tls13_certificate_body(&mut out, &[], &[&der]).unwrap();

        assert_eq!(n, 14);
        assert_eq!(
            &out[..n],
            &[
                0x00, // certificate_request_context<0>
                0x00, 0x00, 0x0a, // certificate_list length = 3 + 5 + 2
                0x00, 0x00, 0x05, // cert_data length
                0x30, 0x03, 0x02, 0x01, 0x05, // DER
                0x00, 0x00, // empty per-entry extensions
            ]
        );
    }

    /// Two entries and a non-empty request context: the list length sums both framed entries.
    #[test]
    fn tls13_certificate_with_two_certs_is_byte_exact() {
        let first = [0x30, 0x01];
        let second = [0x31, 0x02, 0x03];
        let context = [0xaa, 0xbb];
        let mut out = [0u8; 40];
        let n = write_tls13_certificate_body(&mut out, &context, &[&first, &second]).unwrap();

        assert_eq!(n, 21);
        assert_eq!(
            &out[..n],
            &[
                0x02, 0xaa, 0xbb, // certificate_request_context<2>
                0x00, 0x00, 0x0f, // certificate_list length = 7 + 8
                0x00, 0x00, 0x02, 0x30, 0x01, 0x00, 0x00, // first entry
                0x00, 0x00, 0x03, 0x31, 0x02, 0x03, 0x00, 0x00, // second entry
            ]
        );
    }

    /// `context || extensions_len || signature_algorithms(type 13, list 0x0804, 0x0403)`.
    #[test]
    fn certificate_request_with_extensions_is_byte_exact() {
        let mut out = [0u8; 32];
        let n = write_certificate_request_body(&mut out, &[0x01, 0x02], &[0x0804, 0x0403]).unwrap();

        assert_eq!(n, 15);
        assert_eq!(
            &out[..n],
            &[
                0x02, 0x01, 0x02, // certificate_request_context<2>
                0x00, 0x0a, // extensions length
                0x00, 0x0d, // signature_algorithms
                0x00, 0x06, // extension body length
                0x00, 0x04, // supported_signature_algorithms length
                0x08, 0x04, 0x04, 0x03, // rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
            ]
        );
    }

    /// An empty scheme list writes the empty extension vector (`tls_construct_certificate_request`
    /// with nothing to advertise).
    #[test]
    fn certificate_request_without_extensions_is_byte_exact() {
        let mut out = [0xffu8; 4];
        let n = write_certificate_request_body(&mut out, &[], &[]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&out[..n], &[0x00, 0x00, 0x00]);
    }

    /// `scheme(2) || signature<0..2^16-1>` over a fixed signature.
    #[test]
    fn certificate_verify_is_byte_exact() {
        let signature = [0xde, 0xad, 0xbe, 0xef];
        let mut out = [0u8; 16];
        let n = write_cert_verify_body(&mut out, [0x04, 0x03], &signature).unwrap();

        assert_eq!(n, 8);
        assert_eq!(&out[..n], &[0x04, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
    }

    /// A TLS1.2 empty chain is the three-byte zero `certificate_list`.
    #[test]
    fn tls12_certificate_with_a_zero_length_chain_is_byte_exact() {
        let mut out = [0xffu8; 3];
        let n = write_tls12_certificate_body(&mut out, &[]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, [0x00, 0x00, 0x00]);
    }

    /// Negative control: every body writer refuses a block one byte short of its exact
    /// message instead of panicking or writing past it; the exact block is accepted.
    #[test]
    fn too_small_certificate_buffers_fail_cleanly() {
        let der = [0x30, 0x03, 0x02, 0x01, 0x05];
        let mut short_cert = [0u8; 13];
        assert!(write_tls13_certificate_body(&mut short_cert, &[], &[&der]).is_none());
        let mut exact_cert = [0u8; 14];
        assert!(write_tls13_certificate_body(&mut exact_cert, &[], &[&der]).is_some());

        let first = [0x30, 0x01];
        let second = [0x31, 0x02, 0x03];
        let mut short_two = [0u8; 20];
        assert!(
            write_tls13_certificate_body(&mut short_two, &[0xaa, 0xbb], &[&first, &second])
                .is_none()
        );

        let mut short_request = [0u8; 14];
        assert!(write_certificate_request_body(
            &mut short_request,
            &[0x01, 0x02],
            &[0x0804, 0x0403]
        )
        .is_none());

        let mut short_verify = [0u8; 7];
        assert!(
            write_cert_verify_body(&mut short_verify, [0x04, 0x03], &[0xde, 0xad, 0xbe, 0xef])
                .is_none()
        );

        let mut short_tls12 = [0u8; 2];
        assert!(write_tls12_certificate_body(&mut short_tls12, &[]).is_none());

        let mut short_entries = [0u8; 7];
        assert!(write_tls12_certificate_body(&mut short_entries, &[&der]).is_none());
    }

    /// A context that does not fit the one-byte wire length is refused instead of truncated.
    #[test]
    fn over_long_certificate_request_context_is_refused() {
        let context = [0u8; 256];
        let mut out = [0u8; 400];
        assert!(write_certificate_request_body(&mut out, &context, &[]).is_none());
    }

    /// The `u24` primitive refuses a value it cannot express, rather than truncating it.
    #[test]
    fn u24_length_refuses_an_over_long_value() {
        let mut out = [0u8; 8];
        let mut w = BytesWriter::new(&mut out);
        assert!(!w.put_u24(0x0100_0000));
        assert_eq!(w.written(), 0);
        assert!(w.put_u24(0x00ff_ffff));
        assert_eq!(&out[..3], &[0xff, 0xff, 0xff]);
    }
}

// -------------------------------------------------------------------------------------------
// TLS1.2 server-flight framing: CertificateRequest / ServerKeyExchange / ServerHelloDone /
// NewSessionTicket body construction
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod tls12_flight_body_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::{
        tls12_construct_server_hello_done, write_tls12_certificate_request_body,
        write_tls12_ecdh_params, write_tls12_new_session_ticket_body, write_tls12_ske_body,
        write_tls12_ske_signature_input, TLS12_SERVER_HELLO_DONE_BODY,
    };

    const SIGALGS: [u8; 8] = [0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x06, 0x01];

    /// `certificate_types || supported_signature_algorithms || certificate_authorities<0>`.
    #[test]
    fn certificate_request_with_signature_algorithms_is_byte_exact() {
        let mut out = [0u8; 32];
        let n = write_tls12_certificate_request_body(&mut out, &[1, 64], Some(&SIGALGS)).unwrap();
        assert_eq!(n, 15);
        assert_eq!(
            &out[..n],
            &[
                0x02, 0x01, 0x40, // certificate_types<2>: rsa_sign, ecdsa_sign
                0x00, 0x08, // supported_signature_algorithms length
                0x04, 0x01, 0x04, 0x03, 0x05, 0x01, 0x06,
                0x01, // rsa_pss, ecdsa, ed25519, ...
                0x00, 0x00, // certificate_authorities<0>
            ]
        );
    }

    /// Without a scheme list the extension is omitted, leaving the shorter authority shape.
    #[test]
    fn certificate_request_without_signature_algorithms_is_byte_exact() {
        let mut out = [0u8; 8];
        let n = write_tls12_certificate_request_body(&mut out, &[1, 64], None).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out[..n], &[0x02, 0x01, 0x40, 0x00, 0x00]);
    }

    /// A certificate-type list longer than the one-byte wire length is malformed input and is
    /// refused rather than truncated; the buffer is untouched.
    #[test]
    fn over_long_certificate_type_list_is_refused() {
        let types = [1u8; 256];
        let mut out = [0xa5u8; 400];
        let before = out;
        assert!(write_tls12_certificate_request_body(&mut out, &types, None).is_none());
        assert_eq!(out, before);
    }

    /// `named_curve || group || point<len>` for the two mandatory ECDHE groups.
    #[test]
    fn ecdh_params_for_x25519_and_p256_are_byte_exact() {
        let x25519_point = [0x09u8; 32];
        let mut out = [0u8; 64];
        let n = write_tls12_ecdh_params(&mut out, 0x001d, &x25519_point).unwrap();
        assert_eq!(n, 36);
        let mut expected = vec![0x03, 0x00, 0x1d, 0x20];
        expected.extend_from_slice(&x25519_point);
        assert_eq!(&out[..n], &expected[..]);

        let mut p256_point = [0u8; 65];
        p256_point[0] = 0x04;
        for (i, b) in p256_point[1..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [0u8; 96];
        let n = write_tls12_ecdh_params(&mut out, 0x0017, &p256_point).unwrap();
        assert_eq!(n, 69);
        let mut expected = vec![0x03, 0x00, 0x17, 0x41];
        expected.extend_from_slice(&p256_point);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// The signed input is exactly `client_random || server_random || ServerECDHParams`.
    #[test]
    fn ske_signature_input_is_byte_exact() {
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let params = [0x03u8, 0x00, 0x1d, 0x02, 0xaa, 0xbb];
        let mut out = [0u8; 128];
        let n = write_tls12_ske_signature_input(&mut out, &client_random, &server_random, &params)
            .unwrap();
        assert_eq!(n, 70);
        let mut expected = Vec::new();
        expected.extend_from_slice(&client_random);
        expected.extend_from_slice(&server_random);
        expected.extend_from_slice(&params);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// `ServerECDHParams || sigalg(2) || signature<len(2)>`.
    #[test]
    fn ske_body_is_byte_exact() {
        let params = [0x03u8, 0x00, 0x1d, 0x20];
        let signature = [0xde, 0xad, 0xbe, 0xef];
        let mut out = [0u8; 64];
        let n = write_tls12_ske_body(&mut out, &params, 0x0401, &signature).unwrap();
        assert_eq!(n, 12);
        assert_eq!(
            &out[..n],
            &[
                0x03, 0x00, 0x1d, 0x20, // ServerECDHParams
                0x04, 0x01, // rsa_pkcs1_sha256
                0x00, 0x04, // signature length
                0xde, 0xad, 0xbe, 0xef,
            ]
        );
    }

    /// `ticket_lifetime_hint(4) || ticket<len(2)>`, with and without a hint.
    #[test]
    fn new_session_ticket_body_with_and_without_hint_is_byte_exact() {
        let ticket = [0x5au8; 8];
        let mut out = [0u8; 32];
        let n = write_tls12_new_session_ticket_body(&mut out, 0, &ticket).unwrap();
        assert_eq!(n, 14);
        let mut expected = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x08];
        expected.extend_from_slice(&ticket);
        assert_eq!(&out[..n], &expected[..]);

        let mut out = [0u8; 32];
        let n = write_tls12_new_session_ticket_body(&mut out, 0x0000_0abc, &ticket).unwrap();
        assert_eq!(n, 14);
        let mut expected = vec![0x00, 0x00, 0x0a, 0xbc, 0x00, 0x08];
        expected.extend_from_slice(&ticket);
        assert_eq!(&out[..n], &expected[..]);
    }

    /// Every builder refuses a block one byte short of its exact message, leaving the buffer
    /// byte-for-byte unchanged; the exact size succeeds. `ServerHelloDone` has a zero-length body,
    /// so its empty slice is accepted by any block, including an empty one.
    #[test]
    fn each_builder_refuses_a_short_buffer_transactionally() {
        const SENTINEL: u8 = 0xa5;

        let mut out = [SENTINEL; 14];
        let before = out;
        assert!(write_tls12_certificate_request_body(&mut out, &[1, 64], Some(&SIGALGS)).is_none());
        assert_eq!(out, before);

        let point = [0x09u8; 32];
        let mut out = [SENTINEL; 35];
        let before = out;
        assert!(write_tls12_ecdh_params(&mut out, 0x001d, &point).is_none());
        assert_eq!(out, before);

        let mut out = [SENTINEL; 69];
        let before = out;
        assert!(write_tls12_ske_signature_input(&mut out, &[1; 32], &[2; 32], &point).is_none());
        assert_eq!(out, before);

        let mut out = [SENTINEL; 11];
        let before = out;
        assert!(write_tls12_ske_body(&mut out, &point[..4], 0x0401, &[0xde; 4]).is_none());
        assert_eq!(out, before);

        let mut out = [SENTINEL; 13];
        let before = out;
        assert!(write_tls12_new_session_ticket_body(&mut out, 0, &[0x5a; 8]).is_none());
        assert_eq!(out, before);

        assert!(TLS12_SERVER_HELLO_DONE_BODY.is_empty());
        let mut empty: [u8; 0] = [];
        assert!(write_tls12_ske_body(&mut empty, &[], 0, &[]).is_none());
    }

    /// A point longer than the one-byte wire length is refused rather than truncated.
    #[test]
    fn over_long_ecdh_point_is_refused() {
        let point = [0x04u8; 256];
        let mut out = [0xa5u8; 400];
        let before = out;
        assert!(write_tls12_ecdh_params(&mut out, 0x001d, &point).is_none());
        assert_eq!(out, before);
    }

    /// `ServerHelloDone` is `type(14) || length(0)` with an empty body; the record writer frames
    /// it as one four-byte handshake message.
    #[test]
    fn server_hello_done_writes_an_empty_body() {
        use crate::runtime::bio::bss_mem::BIO_s_mem;
        use crate::runtime::bio::{BIO_ctrl_pending, BIO_new, BIO_read};
        use crate::ssl::methods::TLS_method;
        use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new};

        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created, used and released by this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            let bio = BIO_new(BIO_s_mem());
            assert!(!bio.is_null());
            (*s).wbio = bio; // ownership transferred; `SSL_free` releases it
            assert_eq!(tls12_construct_server_hello_done(s), 1);

            let n = BIO_ctrl_pending(bio);
            let mut out = vec![0u8; n];
            let r = BIO_read(bio, out.as_mut_ptr().cast(), n as core::ffi::c_int);
            assert_eq!(r, n as core::ffi::c_int);
            assert_eq!(
                out.len(),
                9,
                "one empty handshake message: 5-byte record + 4"
            );
            assert_eq!(out[0], 22, "SSL3_RT_HANDSHAKE");
            assert_eq!(u16::from_be_bytes([out[3], out[4]]), 4, "record payload");
            assert_eq!(&out[5..9], &[14, 0, 0, 0]);

            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }
}

// -------------------------------------------------------------------------------------------
// Adversarial allocator-refusal test (`stage/p25/adv-tests`, §16 / §18)
// -------------------------------------------------------------------------------------------
//
// Drives the TLS1.2 server ticket writer with its replacement allocation refused and asserts the
// recorded safety improvement: the member is left `(NULL, 0)` rather than holding the just-freed
// pointer, so the later session destructor cannot release a dangling block.
//
// Run alone in its own process, under the gate, with the ignore-aware filter:
//   OPENSSL_RS_ADV_PROBE=1 cargo test --lib \
//     ssl::statem::statem_srvr::adv_probe -- --ignored --exact --test-threads=1 --nocapture
// or, for every probe one process at a time, `scripts/adv-probe.sh`.
#[cfg(test)]
mod adv_probe {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
    use crate::ssl::adv_alloc::{self, Ev};
    use crate::ssl::ssl_sess::{SSL_SESSION_free, SSL_SESSION_new};

    /// The refusal path of `tls12_construct_new_session_ticket`: the incumbent ticket is released,
    /// the replacement allocation is refused, and the writer answers its authority error with the
    /// member left empty. The allocator transcript is the authority's (one free, then the one
    /// refused request); the destruction performs no second release of the freed block.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn tls12_construct_refused_ticket_alloc_leaves_ext_tick_empty() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();

        // Let RAND initialise its DRBG before the measured window, so its one-off allocation is
        // not mistaken for the writer's own replacement request.
        let mut warm = [0u8; 8];
        // SAFETY: `warm` is writable for 8 bytes.
        unsafe { crate::rand::rand_lib::RAND_bytes(warm.as_mut_ptr(), 8) };

        // SAFETY: the session and the `Ssl` block are this frame's own allocations.
        let (sess, s, incumbent) = unsafe {
            let sess = SSL_SESSION_new();
            assert!(!sess.is_null(), "SSL_SESSION_new must answer a session");
            let incumbent = CRYPTO_malloc(20, core::ptr::null(), 0).cast::<u8>();
            assert!(!incumbent.is_null());
            (*sess).ext_tick_slot().store(incumbent, 20);
            let s = adv_alloc::zeroed_ssl();
            assert!(!s.is_null(), "a zeroed Ssl block must be allocatable");
            (*s).session = sess;
            (*s).hit = 0;
            (sess, s, incumbent)
        };

        adv_alloc::reset();
        adv_alloc::arm(TLS12_TICKET_LEN);
        // SAFETY: `s` is the live connection this frame built, with its session set.
        let r = unsafe { tls12_construct_new_session_ticket(s) };
        adv_alloc::disarm();

        assert_eq!(
            r, 0,
            "a refused ticket allocation must return the authority's error"
        );
        // SAFETY: `sess` is live.
        let (p, n) = unsafe { (*sess).ext_tick() };
        assert!(
            p.is_null() && n == 0,
            "the refused path must leave the member (NULL, 0)"
        );

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
            matches!(&ev[at], Ev::Malloc { n, site: true, refused: true } if *n == TLS12_TICKET_LEN),
            "the refused request is the writer's own (NULL,0) request of TLS12_TICKET_LEN"
        );
        assert!(
            ev[..at]
                .iter()
                .any(|e| matches!(e, Ev::Free { p } if *p == incumbent as usize)),
            "the incumbent is released before the refused replacement"
        );

        // The destruction must not release the freed incumbent a second time.
        // SAFETY: `sess` is live and owned here; `s` is the block `zeroed_ssl` allocated.
        unsafe {
            SSL_SESSION_free(sess);
            CRYPTO_free(s.cast(), core::ptr::null(), 0);
        }
        assert!(
            !adv_alloc::double_free(),
            "the session destructor must not release the freed incumbent"
        );
    }

    /// Negative control (§16): prove the double-release instrument fires, so the assertion above
    /// is meaningful. A block is released twice; the hook must flag it (and must not forward the
    /// second release, so the run continues to the assertion).
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn canary_double_release_is_detected() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        adv_alloc::reset();
        // SAFETY: `b` is a fresh block; the second release is the deliberate test-only defect.
        unsafe {
            let b = CRYPTO_malloc(16, core::ptr::null(), 0).cast::<u8>();
            assert!(!b.is_null());
            CRYPTO_free(b.cast(), core::ptr::null(), 0);
            CRYPTO_free(b.cast(), core::ptr::null(), 0);
        }
        assert!(
            adv_alloc::double_free(),
            "the instrument must flag a double release (negative control)"
        );
    }

    /// Build a certificate whose DER exceeds the old fixed 8192-byte stack buffer.
    ///
    /// `i2d_X509` writes the whole encoding into a non-NULL out-pointer without a
    /// capacity argument, so this is the input that made the pre-fix flight writers
    /// overflow their stack buffers.
    unsafe fn oversized_certificate() -> *mut crate::x509::x_x509::X509 {
        use crate::asn1::layout::MBSTRING_UTF8;
        use crate::asn1::prim::ASN1_INTEGER_set;
        use crate::evp::legacy_sha::EVP_sha256;
        use crate::evp::pkey::{openssl_rs_evp_pkey_q_keygen, EVP_PKEY_free};
        use crate::x509::x509_set::{
            X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name, X509_set_version,
        };
        use crate::x509::x509_vfy::X509_gmtime_adj;
        use crate::x509::x509name::X509_NAME_add_entry_by_txt;
        use crate::x509::x_all::X509_sign;
        use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};
        use crate::x509::x_x509::{i2d_X509, X509_new};
        // SAFETY: every pointer below is this frame's own fresh object.
        unsafe {
            // A complete self-signed certificate is needed: the ASN.1 encoder refuses a
            // certificate whose mandatory issuer/key/validity fields are unset, and an
            // incomplete synthetic object would not exercise `i2d_X509` at all.
            let pkey = openssl_rs_evp_pkey_q_keygen(
                ptr::null_mut(),
                ptr::null(),
                c"EC".as_ptr(),
                2,
                0,
                c"prime256v1".as_ptr(),
            );
            assert!(!pkey.is_null(), "an EC key must be generatable");
            let x = X509_new();
            assert!(!x.is_null(), "X509_new must answer a certificate");
            let name = X509_NAME_new();
            assert!(!name.is_null(), "X509_NAME_new must answer a name");
            let big = [b'A'; 60];
            // `CN` has the authority's 64-byte string-table bound, so build the oversized
            // DER from many valid entries rather than one invalid one. Seventy entries keep
            // the control above the old 8192-byte buffer but below this reduction's
            // 17000-byte handshake-message writer bound.
            for _ in 0..70 {
                assert_eq!(
                    X509_NAME_add_entry_by_txt(
                        name,
                        c"CN".as_ptr(),
                        MBSTRING_UTF8,
                        big.as_ptr(),
                        big.len() as c_int,
                        -1,
                        0,
                    ),
                    1,
                    "the large name must be accepted"
                );
            }
            assert_eq!(X509_set_version(x, 2), 1);
            assert_eq!(
                ASN1_INTEGER_set(ptr::addr_of_mut!((*x).cert_info.serialNumber), 1),
                1
            );
            assert_eq!(X509_set_subject_name(x, name), 1);
            assert_eq!(X509_set_issuer_name(x, name), 1);
            (*x).cert_info.validity.notBefore = X509_gmtime_adj(ptr::null_mut(), 0);
            (*x).cert_info.validity.notAfter = X509_gmtime_adj(ptr::null_mut(), 86_400);
            assert!(!(*x).cert_info.validity.notBefore.is_null());
            assert!(!(*x).cert_info.validity.notAfter.is_null());
            assert_eq!(X509_set_pubkey(x, pkey), 1);
            assert!(X509_sign(x, pkey, EVP_sha256()) > 0, "signing must succeed");
            X509_NAME_free(name);
            EVP_PKEY_free(pkey);
            let derlen = i2d_X509(x, ptr::null_mut());
            assert!(
                derlen > 8192,
                "the control certificate must exceed the old 8192-byte buffer, got {derlen}"
            );
            x
        }
    }

    unsafe fn construct_tls13(s: *mut Ssl) -> c_int {
        // SAFETY: `s` is the live connection the helper built.
        unsafe { tls13_construct_certificate(s, &[]) }
    }

    unsafe fn construct_tls12(s: *mut Ssl) -> c_int {
        // SAFETY: `s` is the live connection the helper built.
        unsafe { tls12_construct_certificate(s) }
    }

    /// Drive one flight writer over the oversized certificate with a memory BIO, so a
    /// successful return proves the whole body was encoded and written. The certificate
    /// is installed as a borrow and cleared before `SSL_free` releases the container.
    fn oversized_cert_flight(construct: unsafe fn(*mut Ssl) -> c_int) {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: all objects are created and released by this frame.
        unsafe {
            let ctx = crate::ssl::ssl_lib::SSL_CTX_new(crate::ssl::methods::TLS_method());
            assert!(!ctx.is_null(), "a TLS context must be allocatable");
            let s = crate::ssl::ssl_lib::SSL_new(ctx);
            assert!(!s.is_null(), "a TLS connection must be allocatable");
            let x = oversized_certificate();
            let cpk = crate::ssl::ssl_lib::cert_active_key((*s).cert);
            assert!(
                !cpk.is_null(),
                "the connection must carry a certificate slot"
            );
            (*cpk).x509 = x;
            let bio = crate::runtime::bio::BIO_new(crate::runtime::bio::bss_mem::BIO_s_mem());
            assert!(!bio.is_null(), "a memory BIO must be allocatable");
            (*s).wbio = bio; // ownership transferred; `SSL_free` releases it
            assert_eq!(
                construct(s),
                1,
                "the oversized certificate must be framed, not refused or overflowed"
            );
            (*cpk).x509 = ptr::null_mut();
            crate::x509::x_x509::X509_free(x);
            crate::ssl::ssl_lib::SSL_free(s);
            crate::ssl::ssl_lib::SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn oversized_certificate_does_not_overflow_the_tls13_flight_buffer() {
        oversized_cert_flight(construct_tls13);
    }

    #[test]
    fn oversized_certificate_does_not_overflow_the_tls12_flight_buffer() {
        oversized_cert_flight(construct_tls12);
    }
}

// -------------------------------------------------------------------------------------------
// TLS1.2 ECDHE group matrix, static RSA and no-common-group reason tests
// -------------------------------------------------------------------------------------------
#[cfg(test)]
mod tls12_group_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use core::ffi::{c_int, c_long, c_uint, c_void, CStr};

    use crate::evp::asymcipher::{EVP_PKEY_encrypt, EVP_PKEY_encrypt_init};
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey::{
        openssl_rs_evp_pkey_q_keygen, EVP_PKEY_free, EVP_PKEY_get_size, EvpPkey,
    };
    use crate::evp::pkey_ctx::{
        EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, RSA_NO_PADDING, RSA_PKCS1_PADDING,
    };
    use crate::rsa::ctrl::EVP_PKEY_CTX_set_rsa_padding;
    use crate::runtime::bio::Bio;
    use crate::runtime::bio::{
        bss_mem::BIO_s_mem, BIO_ctrl_pending, BIO_free, BIO_new, BIO_new_bio_pair, BIO_read,
        BIO_write,
    };
    use crate::runtime::err::{ERR_clear_error, ERR_get_error, ERR_peek_error};
    use crate::runtime::obj as o;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_ciph::{ssl3_get_cipher_by_id, SSL_CIPHER_get_name};
    use crate::ssl::ssl_lib::{
        SSL_CTX_callback_ctrl, SSL_CTX_ctrl, SSL_CTX_free, SSL_CTX_get_ciphers, SSL_CTX_new,
        SSL_CTX_set_cipher_list, SSL_CTX_set_verify, SSL_ctrl, SSL_do_handshake, SSL_free,
        SSL_get_ciphers, SSL_get_current_cipher, SSL_get_error, SSL_new, SSL_peek, SSL_pending,
        SSL_read, SSL_set_accept_state, SSL_set_bio, SSL_set_cipher_list, SSL_set_connect_state,
        SSL_set_options, SSL_write, Ssl, SslCtx,
    };
    use crate::ssl::ssl_rsa::{SSL_CTX_use_PrivateKey, SSL_CTX_use_certificate};
    use crate::ssl::ssl_sess::{SSL_SESSION_get_compress_id, SSL_get_session};
    use crate::ssl::t1_enc::tls12_setup_cipher;
    use crate::x509::x509_set::{
        X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name, X509_set_version,
    };
    use crate::x509::x509_vfy::X509_gmtime_adj;
    use crate::x509::x509name::X509_NAME_add_entry_by_txt;
    use crate::x509::x_all::X509_sign;
    use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};
    use crate::x509::x_x509::{X509_free, X509_new, X509};

    const SSL_CTRL_SET_GROUPS: c_int = 91;
    const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
    const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
    const TLS1_2_VERSION: c_int = 0x0303;
    const TLS1_3_VERSION: c_int = 0x0304;

    /// A self-signed RSA identity for the server, valid for both ECDHE-RSA and static-RSA suites.
    ///
    /// # Safety
    /// Every object is created and released by this function's caller.
    unsafe fn rsa_identity(bits: usize) -> (*mut EvpPkey, *mut X509) {
        use crate::asn1::layout::MBSTRING_UTF8;
        use crate::asn1::prim::ASN1_INTEGER_set;
        // SAFETY: constructors below answer fresh objects owned by this frame.
        unsafe {
            let pkey = openssl_rs_evp_pkey_q_keygen(
                core::ptr::null_mut(),
                core::ptr::null(),
                c"RSA".as_ptr(),
                1,
                bits,
                core::ptr::null(),
            );
            assert!(!pkey.is_null(), "an RSA key must be generatable");
            let x = X509_new();
            assert!(!x.is_null(), "X509_new must answer a certificate");
            let name = X509_NAME_new();
            assert!(!name.is_null(), "X509_NAME_new must answer a name");
            assert_eq!(
                X509_NAME_add_entry_by_txt(
                    name,
                    c"CN".as_ptr(),
                    MBSTRING_UTF8,
                    c"tls12.test".as_ptr().cast::<u8>(),
                    10,
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
            assert!(X509_sign(x, pkey, EVP_sha256()) > 0, "signing must succeed");
            X509_NAME_free(name);
            (pkey, x)
        }
    }

    /// Move every pending byte from one memory BIO to the other. The peer never blocks: an empty
    /// source is the handshake's "want read".
    ///
    /// # Safety
    /// `from`/`to` are live memory BIOs owned by the two connections.
    unsafe fn drain(from: *mut Bio, to: *mut Bio) {
        // 4 KiB is enough to move a full record in a few iterations and keeps this helper's frame
        // small enough for the 32 KiB-stack regression thread.
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: `buf` is writable; `from` is live.
            let n = unsafe { BIO_read(from, buf.as_mut_ptr().cast(), buf.len() as c_int) };
            if n <= 0 {
                break;
            }
            // SAFETY: `buf[..n]` is readable; `to` is live.
            let w = unsafe { BIO_write(to, buf.as_ptr().cast(), n) };
            if w != n {
                break;
            }
        }
    }

    struct Pair {
        cctx: *mut SslCtx,
        sctx: *mut SslCtx,
        c: *mut Ssl,
        s: *mut Ssl,
        c_r: *mut Bio,
        c_w: *mut Bio,
        s_r: *mut Bio,
        s_w: *mut Bio,
    }

    /// Build a client/server pair with the requested version, cipher and per-side group pins.
    ///
    /// # Safety
    /// The caller owns the returned objects and releases them with [`free_pair`].
    unsafe fn make_pair(
        cipher: &CStr,
        version: c_int,
        client_group: Option<c_int>,
        server_group: Option<c_int>,
    ) -> Pair {
        // SAFETY: the caller's contract; the default identity is 2048-bit RSA.
        unsafe { make_pair_bits(cipher, version, client_group, server_group, 2048) }
    }

    /// As [`make_pair`], with an explicit RSA modulus size for the server identity.
    ///
    /// # Safety
    /// The caller owns the returned objects and releases them with [`free_pair`].
    unsafe fn make_pair_bits(
        cipher: &CStr,
        version: c_int,
        client_group: Option<c_int>,
        server_group: Option<c_int>,
        rsa_bits: usize,
    ) -> Pair {
        // SAFETY: every constructor below answers a fresh object owned by this frame.
        unsafe {
            let cctx = SSL_CTX_new(TLS_method());
            let sctx = SSL_CTX_new(TLS_method());
            assert!(!cctx.is_null() && !sctx.is_null());
            // `SSL_CTX_set_cipher_list` selects the TLS1.2 stack; a TLS1.3-only suite name is set
            // by the default ciphersuite configuration instead.
            if !cipher.to_bytes().starts_with(b"TLS_") {
                assert_eq!(SSL_CTX_set_cipher_list(cctx, cipher.as_ptr()), 1);
                assert_eq!(SSL_CTX_set_cipher_list(sctx, cipher.as_ptr()), 1);
            }
            SSL_CTX_set_verify(cctx, 0, None);
            for (ctx, group) in [(cctx, client_group), (sctx, server_group)] {
                assert_eq!(
                    SSL_CTX_ctrl(
                        ctx,
                        SSL_CTRL_SET_MIN_PROTO_VERSION,
                        version as c_long,
                        core::ptr::null_mut(),
                    ),
                    1
                );
                assert_eq!(
                    SSL_CTX_ctrl(
                        ctx,
                        SSL_CTRL_SET_MAX_PROTO_VERSION,
                        version as c_long,
                        core::ptr::null_mut(),
                    ),
                    1
                );
                if let Some(nid) = group {
                    let mut nid = nid;
                    assert_eq!(
                        SSL_CTX_ctrl(
                            ctx,
                            SSL_CTRL_SET_GROUPS,
                            1,
                            (&mut nid as *mut c_int).cast::<c_void>(),
                        ),
                        1,
                        "group pin"
                    );
                }
            }

            let (pkey, x) = rsa_identity(rsa_bits);
            assert_eq!(SSL_CTX_use_certificate(sctx, x), 1);
            assert_eq!(SSL_CTX_use_PrivateKey(sctx, pkey), 1);
            EVP_PKEY_free(pkey);
            X509_free(x);

            let c = SSL_new(cctx);
            let s = SSL_new(sctx);
            assert!(!c.is_null() && !s.is_null());
            SSL_set_connect_state(c);
            SSL_set_accept_state(s);
            let c_r = BIO_new(BIO_s_mem());
            let c_w = BIO_new(BIO_s_mem());
            let s_r = BIO_new(BIO_s_mem());
            let s_w = BIO_new(BIO_s_mem());
            assert!(!c_r.is_null() && !c_w.is_null() && !s_r.is_null() && !s_w.is_null());
            // Each connection owns its own read/write pair; the pump moves the bytes between them.
            SSL_set_bio(c, c_r, c_w);
            SSL_set_bio(s, s_r, s_w);
            Pair {
                cctx,
                sctx,
                c,
                s,
                c_r,
                c_w,
                s_r,
                s_w,
            }
        }
    }

    /// # Safety
    /// `p` is a live pair from [`make_pair`] that has not been freed.
    unsafe fn free_pair(p: Pair) {
        // SAFETY: `c`/`s` own the four BIOs and the contexts are this frame's.
        unsafe {
            SSL_free(p.c);
            SSL_free(p.s);
            SSL_CTX_free(p.cctx);
            SSL_CTX_free(p.sctx);
        }
    }

    /// Pump both directions until both handshakes finish or one side enters the error state.
    ///
    /// # Safety
    /// `p` is a live pair from [`make_pair`].
    unsafe fn drive(p: &Pair) -> (bool, bool) {
        let mut client_ok = false;
        let mut server_ok = false;
        for _ in 0..128 {
            // SAFETY: both connections are live for the duration of the pair.
            let client_ret = unsafe { SSL_do_handshake(p.c) };
            // SAFETY: both connections are live for the duration of the pair.
            let server_ret = unsafe { SSL_do_handshake(p.s) };
            if !client_ok && client_ret == 1 {
                client_ok = true;
            }
            if !server_ok && server_ret == 1 {
                server_ok = true;
            }
            // SAFETY: the four BIOs are live until `free_pair`.
            unsafe {
                drain(p.c_w, p.s_r);
                drain(p.s_w, p.c_r);
            }
            if client_ok && server_ok {
                break;
            }
            // SAFETY: `p.s` is live.
            if unsafe { crate::ssl::statem::statem::ossl_statem_in_error(p.s) } != 0 {
                break;
            }
        }
        (client_ok, server_ok)
    }

    /// Drain this thread's error queue and return the reason codes.
    fn error_reasons() -> Vec<c_int> {
        let mut reasons = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            // `ERR_GET_REASON` is `ERR_REASON_MASK` (0x7FFFFF) on this non-system queue.
            reasons.push((e & 0x7f_ffff) as c_int);
        }
        reasons
    }

    /// Drain this thread's error queue and return `(ERR_GET_LIB, ERR_GET_REASON)` pairs.
    fn error_lib_reasons() -> Vec<(c_int, c_int)> {
        let mut out = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            // `ERR_GET_LIB` is bits 23..30 and `ERR_GET_REASON` is the low 23 bits on this
            // non-system queue (`err.h`).
            out.push((((e >> 23) & 0xff) as c_int, (e & 0x7f_ffff) as c_int));
        }
        out
    }

    fn current_cipher(s: *mut Ssl) -> String {
        // SAFETY: `s` is live until `free_pair`.
        let c = unsafe { SSL_get_current_cipher(s) };
        if c.is_null() {
            return String::new();
        }
        // SAFETY: `c` is a live table row and its name is NUL-terminated.
        let p = unsafe { SSL_CIPHER_get_name(c) };
        if p.is_null() {
            String::new()
        } else {
            // SAFETY: `p` is NUL-terminated.
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    }

    /// Encrypt `input` under the server's public key with an explicit padding mode, for the
    /// canary's textbook (`RSA_NO_PADDING`) malformed blocks and the valid positive control.
    ///
    /// # Safety
    /// `pkey` is a live key; `input` is readable for its length.
    unsafe fn rsa_encrypt_with_key(pkey: *mut EvpPkey, input: &[u8], padding: c_int) -> Vec<u8> {
        // SAFETY: the pointers below are live locals or the caller's live key.
        unsafe {
            let ctx = EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null());
            assert!(
                !ctx.is_null(),
                "an RSA encryption context must be buildable"
            );
            assert!(EVP_PKEY_encrypt_init(ctx) > 0);
            assert!(
                EVP_PKEY_CTX_set_rsa_padding(ctx, padding) > 0,
                "the padding mode must be accepted"
            );
            let mut outlen = 0usize;
            assert!(
                EVP_PKEY_encrypt(
                    ctx,
                    core::ptr::null_mut(),
                    &mut outlen,
                    input.as_ptr(),
                    input.len(),
                ) > 0
            );
            let mut out = vec![0u8; outlen];
            assert!(
                EVP_PKEY_encrypt(
                    ctx,
                    out.as_mut_ptr(),
                    &mut outlen,
                    input.as_ptr(),
                    input.len(),
                ) > 0
            );
            out.truncate(outlen);
            EVP_PKEY_CTX_free(ctx);
            out
        }
    }

    /// A server connection that has processed its ServerHello/cipher setup and can accept a
    /// ClientKeyExchange directly. The caller frees `ctx`, `s` and `pkey`.
    ///
    /// # Safety
    /// Every returned pointer is this frame's own object.
    unsafe fn static_rsa_server(bits: usize) -> (*mut SslCtx, *mut Ssl, *mut EvpPkey) {
        // SAFETY: constructors and installers below use live objects owned by this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let (pkey, x) = rsa_identity(bits);
            assert_eq!(SSL_CTX_use_certificate(ctx, x), 1);
            assert_eq!(SSL_CTX_use_PrivateKey(ctx, pkey), 1);
            X509_free(x);
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            SSL_set_accept_state(s);
            (*s).version = TLS1_2_VERSION;
            (*s).client_version = TLS1_2_VERSION;
            (*s).pending_cipher = ssl3_get_cipher_by_id(0x0300_009c);
            assert!(!(*s).pending_cipher.is_null());
            assert_eq!(tls12_setup_cipher(s, 0x009c), 1);
            (ctx, s, pkey)
        }
    }

    /// Frame a ciphertext as a TLS1.2 `ClientKeyExchange` handshake message.
    fn cke_message(ciphertext: &[u8]) -> Vec<u8> {
        let bodylen = 2 + ciphertext.len();
        let mut msg = Vec::with_capacity(4 + bodylen);
        msg.push(SSL3_MT_CLIENT_KEY_EXCHANGE as u8);
        msg.extend_from_slice(&[(bodylen >> 16) as u8, (bodylen >> 8) as u8, bodylen as u8]);
        msg.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        msg.extend_from_slice(ciphertext);
        msg
    }

    /// Drive one ClientKeyExchange through the real server function and return the master secret
    /// it derived. The caller has cleared the error queue.
    ///
    /// # Safety
    /// `s` is a live server connection from [`static_rsa_server`].
    unsafe fn direct_master_secret(s: *mut Ssl, ciphertext: &[u8]) -> [u8; 48] {
        // SAFETY: `s` is live; the message is this frame's own buffer.
        unsafe {
            (*s).tls12_master_secret = [0x5A; 48];
            let msg = cke_message(ciphertext);
            let r = tls12_process_client_key_exchange(s, &msg);
            assert_eq!(r, 1, "a malformed ciphertext must be implicitly rejected");
            assert_eq!(
                ERR_peek_error(),
                0,
                "implicit rejection must not leave a distinguishable error"
            );
            (*s).tls12_master_secret
        }
    }

    /// Drive one ClientKeyExchange through the real server function and return its answer plus
    /// the queued `(library, reason)` pairs. Used for the public `c >= n` rejection.
    ///
    /// # Safety
    /// `s` is a live server connection from [`static_rsa_server`].
    unsafe fn direct_failure(s: *mut Ssl, ciphertext: &[u8]) -> (c_int, Vec<(c_int, c_int)>) {
        // SAFETY: `s` is live; the message is this frame's own buffer.
        unsafe {
            (*s).tls12_master_secret = [0x5A; 48];
            ERR_clear_error();
            let msg = cke_message(ciphertext);
            let r = tls12_process_client_key_exchange(s, &msg);
            (r, error_lib_reasons())
        }
    }

    /// Read every pending byte out of a memory BIO. The caller writes the (possibly rewritten)
    /// bytes back before the peer reads them.
    ///
    /// # Safety
    /// `b` is a live memory BIO.
    unsafe fn bio_take_all(b: *mut Bio) -> Vec<u8> {
        // SAFETY: `b` is live.
        let n = unsafe { BIO_ctrl_pending(b) };
        if n == 0 {
            return Vec::new();
        }
        let mut v = vec![0u8; n];
        // SAFETY: `v` is writable for `n` bytes; `b` is live.
        let r = unsafe { BIO_read(b, v.as_mut_ptr().cast(), n as c_int) };
        v.truncate(r.max(0) as usize);
        v
    }

    /// Replace the ClientKeyExchange ciphertext in a captured client-to-server stream. Each
    /// record's framing is rebuilt around the replacement, so a differently-sized ciphertext
    /// (the truncated case) is delivered intact.
    fn rewrite_cke(stream: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(stream.len());
        let mut p = 0usize;
        let mut found = false;
        while p + 5 <= stream.len() {
            let rtype = stream[p];
            let version = [stream[p + 1], stream[p + 2]];
            let rlen = u16::from_be_bytes([stream[p + 3], stream[p + 4]]) as usize;
            if p + 5 + rlen > stream.len() {
                return None;
            }
            let payload = &stream[p + 5..p + 5 + rlen];
            if !found && rtype == 22 && payload.len() >= 4 && payload[0] == 16 {
                let hlen = ((payload[1] as usize) << 16)
                    | ((payload[2] as usize) << 8)
                    | payload[3] as usize;
                if 4 + hlen != payload.len() {
                    return None;
                }
                let bodylen = 2 + ciphertext.len();
                let mut replacement = Vec::with_capacity(4 + bodylen);
                replacement.push(16);
                replacement.extend_from_slice(&[
                    (bodylen >> 16) as u8,
                    (bodylen >> 8) as u8,
                    bodylen as u8,
                ]);
                replacement.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                replacement.extend_from_slice(ciphertext);
                out.push(rtype);
                out.extend_from_slice(&version);
                out.extend_from_slice(&(replacement.len() as u16).to_be_bytes());
                out.extend_from_slice(&replacement);
                found = true;
            } else {
                out.extend_from_slice(&stream[p..p + 5 + rlen]);
            }
            p += 5 + rlen;
        }
        (found && p == stream.len()).then_some(out)
    }

    /// Run a full TLS1.2 handshake, replacing the client's ClientKeyExchange ciphertext with one
    /// derived from `block`, and return the server's failing hand state and error reasons.
    ///
    /// `raw` delivers `block` unchanged (the all-zero and `>= n` cases); otherwise it is encrypted
    /// under the pair's own server key with `padding`. `truncate` shortens the ciphertext for the
    /// short-ciphertext case.
    ///
    /// # Safety
    /// The pair is created and released here.
    unsafe fn intercepted_handshake(
        block: &[u8],
        raw: bool,
        padding: c_int,
        truncate: Option<usize>,
    ) -> (c_int, Vec<(c_int, c_int)>) {
        // SAFETY: the pair and its BIOs are live for the whole loop.
        unsafe {
            ERR_clear_error();
            let p = make_pair(c"AES128-GCM-SHA256", TLS1_2_VERSION, None, None);
            let cpk = crate::ssl::ssl_lib::cert_active_key((*p.s).cert);
            assert!(!cpk.is_null() && !(*cpk).x509.is_null());
            let server_key = crate::x509::x509_cmp::X509_get0_pubkey((*cpk).x509);
            assert!(!server_key.is_null());
            let mut ciphertext = if raw {
                block.to_vec()
            } else {
                rsa_encrypt_with_key(server_key, block, padding)
            };
            if let Some(n) = truncate {
                ciphertext.truncate(n);
            }
            let mut injected = false;
            let mut server_ok = false;
            for _ in 0..32 {
                let _ = SSL_do_handshake(p.c);
                let pending = bio_take_all(p.c_w);
                if !pending.is_empty() {
                    let payload = if !injected {
                        if let Some(rewritten) = rewrite_cke(&pending, &ciphertext) {
                            injected = true;
                            rewritten
                        } else {
                            pending
                        }
                    } else {
                        pending
                    };
                    let written = BIO_write(p.c_w, payload.as_ptr().cast(), payload.len() as c_int);
                    assert_eq!(written, payload.len() as c_int);
                }
                drain(p.c_w, p.s_r);
                if SSL_do_handshake(p.s) == 1 {
                    server_ok = true;
                }
                drain(p.s_w, p.c_r);
                if server_ok || crate::ssl::statem::statem::ossl_statem_in_error(p.s) != 0 {
                    break;
                }
            }
            assert!(injected, "the client never emitted a ClientKeyExchange");
            assert!(!server_ok, "a modified ClientKeyExchange must not complete");
            let state = (*p.s).hand_state;
            let reasons = error_lib_reasons();
            free_pair(p);
            (state, reasons)
        }
    }

    fn assert_group_handshake(nid: c_int) {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(
                c"ECDHE-RSA-AES128-GCM-SHA256",
                TLS1_2_VERSION,
                Some(nid),
                Some(nid),
            );
            let (client_ok, server_ok) = drive(&p);
            let cipher = current_cipher(p.c);
            let reasons = if server_ok {
                Vec::new()
            } else {
                error_reasons()
            };
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "TLS1.2 ECDHE handshake for nid {nid} failed \
                 (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert_eq!(cipher, "ECDHE-RSA-AES128-GCM-SHA256");
        }
    }

    #[test]
    fn tls12_handshake_x25519() {
        assert_group_handshake(o::NID_X25519);
    }

    #[test]
    fn tls12_handshake_secp256r1() {
        assert_group_handshake(o::NID_X9_62_prime256v1);
    }

    #[test]
    fn tls12_handshake_secp384r1() {
        assert_group_handshake(o::NID_secp384r1);
    }

    #[test]
    fn tls12_handshake_secp521r1() {
        assert_group_handshake(o::NID_secp521r1);
    }

    #[test]
    fn tls12_handshake_x448() {
        assert_group_handshake(o::NID_X448);
    }

    #[test]
    fn tls12_static_rsa_handshake_sends_no_server_key_exchange() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(c"AES128-GCM-SHA256", TLS1_2_VERSION, None, None);
            let (client_ok, server_ok) = drive(&p);
            let cipher = current_cipher(p.c);
            let reasons = if server_ok {
                Vec::new()
            } else {
                error_reasons()
            };
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "static-RSA TLS1.2 handshake failed \
                 (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert_eq!(cipher, "AES128-GCM-SHA256");
        }
    }

    #[test]
    fn tls12_static_rsa_handshake_4096_bit_modulus() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair_bits(c"AES128-GCM-SHA256", TLS1_2_VERSION, None, None, 4096);
            let (client_ok, server_ok) = drive(&p);
            let cipher = current_cipher(p.c);
            let reasons = if server_ok {
                Vec::new()
            } else {
                error_reasons()
            };
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "4096-bit static-RSA TLS1.2 handshake failed \
                 (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert_eq!(cipher, "AES128-GCM-SHA256");
        }
    }

    #[test]
    fn tls12_static_rsa_malformed_ciphertexts_are_indistinguishable() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame; the crafted ciphertexts are
        // public data encrypted under this test's own server key.
        unsafe {
            let (ctx, s, pkey) = static_rsa_server(2048);
            let size = EVP_PKEY_get_size(pkey) as usize;
            let mut pms = [0u8; 48];
            pms[0] = 0x03;
            pms[1] = 0x03;
            for (i, b) in pms.iter_mut().enumerate().skip(2) {
                *b = (i as u8).wrapping_mul(7);
            }
            ERR_clear_error();
            let master_valid =
                direct_master_secret(s, &rsa_encrypt_with_key(pkey, &pms, RSA_PKCS1_PADDING));
            // The wrong-version block is structurally padding-valid; its embedded premaster is
            // `03 01 || 46 * 0xAA`. If the version check were skipped, the server would derive
            // this master secret instead of a random one.
            let mut embedded_pms = [0xAAu8; 48];
            embedded_pms[0] = 0x03;
            embedded_pms[1] = 0x01;
            let master_embedded = direct_master_secret(
                s,
                &rsa_encrypt_with_key(pkey, &embedded_pms, RSA_PKCS1_PADDING),
            );
            assert_ne!(master_embedded, master_valid);

            // Textbook blocks whose encoded message starts with the three PKCS#1 block types.
            let mut bt00 = [0xAAu8; 2048];
            bt00[0] = 0x00;
            bt00[1] = 0x00;
            let mut bt01 = [0xAAu8; 2048];
            bt01[0] = 0x00;
            bt01[1] = 0x01;
            let mut bt02 = [0xAAu8; 2048];
            bt02[0] = 0x00;
            bt02[1] = 0x02;
            // Block type 2 with a well-formed separator but the wrong client version: the
            // padding check must still reject it and randomise the premaster.
            let mut bad_version = [0xAAu8; 2048];
            bad_version[0] = 0x00;
            bad_version[1] = 0x02;
            bad_version[2..10].fill(0x11);
            bad_version[10] = 0x00;
            bad_version[11] = 0x03;
            bad_version[12] = 0x01;

            let zero = vec![0u8; size];
            let ge_n = vec![0xFFu8; size];
            let valid_ct = rsa_encrypt_with_key(pkey, &pms, RSA_PKCS1_PADDING);
            let truncated = &valid_ct[..size / 4];

            // (c) In-range malformed values: each is implicitly rejected, raises nothing, and
            // yields a master secret different from the padding-valid control.
            for (name, block) in [
                ("block-type-0", &bt00),
                ("block-type-1", &bt01),
                ("block-type-2-no-separator", &bt02),
                ("block-type-2-bad-version", &bad_version),
            ] {
                let ct = rsa_encrypt_with_key(pkey, &block[..size], RSA_NO_PADDING);
                let master = direct_master_secret(s, &ct);
                if name == "block-type-2-bad-version" {
                    assert_ne!(
                        master, master_embedded,
                        "{name} accepted the embedded wrong-version premaster"
                    );
                } else {
                    assert_ne!(
                        master, master_valid,
                        "{name} was accepted as a padding-valid premaster"
                    );
                }
            }
            for (name, ct) in [("all-zero", zero.as_slice()), ("truncated", truncated)] {
                let master = direct_master_secret(s, ct);
                assert_ne!(
                    master, master_valid,
                    "{name} was accepted as a padding-valid premaster"
                );
            }
            // A ciphertext >= n is refused before blinding (`rsa_ossl.c:606`) with
            // RSA_R_DATA_TOO_LARGE_FOR_MODULUS. The comparison depends only on the received
            // ciphertext and the public modulus, so it cannot leak private data or act as a
            // Bleichenbacher oracle; this is the authority's behaviour and must not be softened.
            {
                let (r, errors) = direct_failure(s, &ge_n);
                assert_eq!(r, 0, "c >= n must be refused");
                assert!(
                    errors.contains(&(4, 132)),
                    "expected ERR_LIB_RSA/RSA_R_DATA_TOO_LARGE_FOR_MODULUS, got {errors:?}"
                );
            }

            // (a) and (b) end to end. In-range malformed values all fail in the Finished state
            // with the same reason vector; an early distinguishable decryption error would
            // change both and fail these assertions.
            let mut baseline: Option<(c_int, Vec<(c_int, c_int)>)> = None;
            #[allow(clippy::type_complexity)]
            let cases: [(&str, &[u8], bool, c_int, Option<usize>); 6] = [
                ("block-type-0", &bt00[..size], false, RSA_NO_PADDING, None),
                ("block-type-1", &bt01[..size], false, RSA_NO_PADDING, None),
                (
                    "block-type-2-no-separator",
                    &bt02[..size],
                    false,
                    RSA_NO_PADDING,
                    None,
                ),
                (
                    "block-type-2-bad-version",
                    &bad_version[..size],
                    false,
                    RSA_NO_PADDING,
                    None,
                ),
                ("all-zero", zero.as_slice(), true, RSA_PKCS1_PADDING, None),
                ("truncated", &pms, false, RSA_PKCS1_PADDING, Some(size / 4)),
            ];
            for (name, block, raw, padding, truncate) in cases {
                let (state, reasons) = intercepted_handshake(block, raw, padding, truncate);
                assert_eq!(
                    state, TLS_ST_SR_FINISHED,
                    "{name} failed before the Finished state (state {state})"
                );
                assert!(
                    !reasons.iter().any(|(_, reason)| *reason == 147),
                    "{name} produced a distinguishable decryption failure: {reasons:?}"
                );
                match &baseline {
                    None => baseline = Some((state, reasons)),
                    Some((base_state, base_reasons)) => {
                        assert_eq!(state, *base_state, "{name} failed in a different state");
                        assert_eq!(
                            &reasons, base_reasons,
                            "{name} produced a distinct error/reason"
                        );
                    }
                }
            }

            // The public `c >= n` case is rejected at the key exchange, not at Finished.
            {
                let ct = ge_n.as_slice();
                let (state, errors) = intercepted_handshake(ct, true, RSA_PKCS1_PADDING, None);
                assert_eq!(
                    state, TLS_ST_SR_KEY_EXCH,
                    "c >= n must be rejected while processing the ClientKeyExchange"
                );
                assert!(
                    errors.contains(&(4, 132)),
                    "expected ERR_LIB_RSA/RSA_R_DATA_TOO_LARGE_FOR_MODULUS, got {errors:?}"
                );
            }

            SSL_free(s);
            SSL_CTX_free(ctx);
            EVP_PKEY_free(pkey);
        }
    }

    #[test]
    fn tls12_no_ticket_client_does_not_arm_a_ticket() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(
                c"ECDHE-RSA-AES128-GCM-SHA256",
                TLS1_2_VERSION,
                Some(o::NID_X25519),
                Some(o::NID_X25519),
            );
            // The client's `session_ticket` builder is suppressed by `SSL_OP_NO_TICKET`
            // (`tls_construct_ctos_session_ticket`), so the ClientHello carries no extension and
            // the server must not announce or issue one (`tls_construct_stoc_session_ticket`).
            SSL_set_options(p.c, crate::ssl::ssl_ciph_table::SSL_OP_NO_TICKET);
            let (client_ok, server_ok) = drive(&p);
            let armed = (*p.s).ext_ticket_expected;
            free_pair(p);
            assert!(client_ok && server_ok);
            assert_eq!(
                armed, 0,
                "a client with no ticket extension must not get one"
            );
        }
    }

    #[test]
    fn tls12_no_common_group_reports_no_suitable_key_share() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            // The client offers only P-256 while the server accepts only X25519. The server's
            // `tls12_choose_group` answers 0 and the ECDHE flight reports reason 101.
            let p = make_pair(
                c"ECDHE-RSA-AES128-GCM-SHA256",
                TLS1_2_VERSION,
                Some(o::NID_X9_62_prime256v1),
                Some(o::NID_X25519),
            );
            let (_client_ok, server_ok) = drive(&p);
            let reasons = error_reasons();
            free_pair(p);
            assert!(!server_ok, "a no-common-group handshake must not complete");
            assert!(
                reasons.contains(&101),
                "expected SSL_R_NO_SUITABLE_KEY_SHARE (101), got {reasons:?}"
            );
        }
    }

    #[test]
    fn tls13_no_common_group_reports_no_suitable_key_share() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            // No intersection between the client's supported groups and the server's list.
            let p = make_pair(
                c"TLS_AES_128_GCM_SHA256",
                TLS1_3_VERSION,
                Some(o::NID_X25519),
                Some(o::NID_X9_62_prime256v1),
            );
            let (_client_ok, server_ok) = drive(&p);
            let reasons = error_reasons();
            free_pair(p);
            assert!(!server_ok, "a no-common-group handshake must not complete");
            assert!(
                reasons.contains(&101),
                "expected SSL_R_NO_SUITABLE_KEY_SHARE (101), got {reasons:?}"
            );
        }
    }

    /// `sslscan` 2.1.5 reads `SSL_SESSION_get_compress_id(SSL_get_session(ssl))` after
    /// `SSL_connect` answers 1. The client's handshake session must therefore exist at that
    /// point, for both TLS1.3 and TLS1.2.
    fn assert_session_after_handshake(cipher: &CStr, version: c_int) {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(cipher, version, Some(o::NID_X25519), Some(o::NID_X25519));
            let (client_ok, server_ok) = drive(&p);
            let client_session = SSL_get_session(p.c);
            let server_session = SSL_get_session(p.s);
            let compress = if client_session.is_null() {
                c_uint::MAX
            } else {
                SSL_SESSION_get_compress_id(client_session)
            };
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "the {cipher:?} handshake must complete (client={client_ok}, server={server_ok})"
            );
            assert!(
                !client_session.is_null(),
                "SSL_get_session must answer the negotiated session after a completed handshake"
            );
            assert!(
                !server_session.is_null(),
                "the server's completed handshake must retain its session"
            );
            // `sslscan` reaches this accessor through the returned pointer; it must read the
            // negotiated session rather than fault.
            assert_eq!(compress, 0, "no compression is negotiated");
        }
    }

    #[test]
    fn ssl_get_session_after_tls13_handshake_is_non_null() {
        assert_session_after_handshake(c"TLS_AES_128_GCM_SHA256", TLS1_3_VERSION);
    }

    #[test]
    fn ssl_get_session_after_tls12_handshake_is_non_null() {
        assert_session_after_handshake(c"ECDHE-RSA-AES128-GCM-SHA256", TLS1_2_VERSION);
    }

    /// The `SSL_CIPHER *` names in `sk`, in list order.
    ///
    /// # Safety
    /// `sk` is NULL or a live cipher stack.
    unsafe fn cipher_names(sk: *mut crate::runtime::stack::OpenSslStack) -> Vec<String> {
        if sk.is_null() {
            return Vec::new();
        }
        // SAFETY: `sk` is live per the caller's contract.
        let n = unsafe { crate::runtime::stack::OPENSSL_sk_num(sk) };
        let mut out = Vec::new();
        for i in 0..n {
            // SAFETY: `i` is in range for the stack.
            let c = unsafe { crate::runtime::stack::OPENSSL_sk_value(sk, i) }
                as *const crate::ssl::ssl_ciph_table::SslCipher;
            if c.is_null() {
                continue;
            }
            // SAFETY: `c` is a process-lifetime table row; its name is NUL-terminated.
            let p = unsafe { SSL_CIPHER_get_name(c) };
            if !p.is_null() {
                // SAFETY: `p` is NUL-terminated.
                out.push(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned());
            }
        }
        out
    }

    #[test]
    fn cipher_list_all_selects_tls12_and_tls13_suites_and_handshakes() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            ERR_clear_error();
            // The context entry point: `"ALL"` must select the TLS1.2 ciphers and the context's
            // TLS1.3 suites, exactly as the authority's `ssl_create_cipher_list` does.
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(SSL_CTX_set_cipher_list(ctx, c"ALL".as_ptr()), 1);
            let names = cipher_names(SSL_CTX_get_ciphers(ctx));
            assert!(
                names.iter().any(|n| n == "ECDHE-RSA-AES128-GCM-SHA256"),
                "ALL must select the TLS1.2 suites: {names:?}"
            );
            assert!(
                names.iter().any(|n| n == "TLS_AES_128_GCM_SHA256"),
                "ALL must include the TLS1.3 suites: {names:?}"
            );
            SSL_CTX_free(ctx);

            // The connection entry point: jimtcl calls `SSL_set_cipher_list(ssl, "ALL")` on a
            // fresh `SSL_new` connection before the handshake. A NULL connection
            // `tls13_ciphersuites` used to drop every TLS1.3 suite here, so the server answered
            // `no shared cipher` for a TLS1.3 ClientHello.
            let p = make_pair(c"ALL", TLS1_3_VERSION, None, None);
            assert_eq!(SSL_set_cipher_list(p.c, c"ALL".as_ptr()), 1);
            assert_eq!(SSL_set_cipher_list(p.s, c"ALL".as_ptr()), 1);
            let names = cipher_names(SSL_get_ciphers(p.s));
            assert!(
                names.iter().any(|n| n == "TLS_AES_128_GCM_SHA256"),
                "the connection list must keep the TLS1.3 suites: {names:?}"
            );
            let (client_ok, server_ok) = drive(&p);
            let cipher = current_cipher(p.s);
            let reasons = if server_ok {
                Vec::new()
            } else {
                error_reasons()
            };
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "TLS1.3 handshake after SSL_set_cipher_list(\"ALL\") failed \
                 (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert!(
                cipher.starts_with("TLS_"),
                "a TLS1.3 suite must be negotiated, got {cipher}"
            );
        }
    }

    #[test]
    fn cipher_list_default_and_explicit_suite_select_expected_suites() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the context is created and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(SSL_CTX_set_cipher_list(ctx, c"DEFAULT".as_ptr()), 1);
            let names = cipher_names(SSL_CTX_get_ciphers(ctx));
            assert!(
                names.iter().any(|n| n == "ECDHE-RSA-AES128-GCM-SHA256"),
                "DEFAULT must include the default TLS1.2 suites: {names:?}"
            );
            assert!(
                names.iter().any(|n| n == "TLS_AES_128_GCM_SHA256"),
                "DEFAULT must keep the TLS1.3 suites: {names:?}"
            );

            assert_eq!(
                SSL_CTX_set_cipher_list(ctx, c"ECDHE-RSA-AES128-GCM-SHA256".as_ptr()),
                1
            );
            let sk = SSL_CTX_get_ciphers(ctx);
            let names = cipher_names(sk);
            assert!(
                names.iter().any(|n| n == "ECDHE-RSA-AES128-GCM-SHA256"),
                "the named suite must be selected: {names:?}"
            );
            assert!(
                names.iter().any(|n| n == "TLS_AES_128_GCM_SHA256"),
                "the TLS1.3 suites stay appended: {names:?}"
            );
            assert_eq!(
                crate::ssl::ssl_ciph::cipher_list_tls12_num(sk),
                1,
                "exactly the named TLS1.2 suite: {names:?}"
            );
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn cipher_list_selecting_no_tls12_suite_returns_zero() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            // `!aNULL` kills every anonymous suite and activates nothing; an unknown name matches
            // nothing. The authority raises `SSL_R_NO_CIPHER_MATCH` and returns 0 in both cases.
            assert_eq!(SSL_CTX_set_cipher_list(ctx, c"!aNULL".as_ptr()), 0);
            assert_eq!(SSL_CTX_set_cipher_list(ctx, c"NOT-A-CIPHER".as_ptr()), 0);
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            assert_eq!(SSL_set_cipher_list(s, c"!aNULL".as_ptr()), 0);
            assert_eq!(SSL_set_cipher_list(s, c"NOT-A-CIPHER".as_ptr()), 0);
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn set_tmp_ecdh_is_a_no_op_and_keeps_the_default_group_list() {
        use crate::ec::key::{EC_KEY_free, EC_KEY_new_by_curve_name};
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the context and key are this frame's own objects.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let key = EC_KEY_new_by_curve_name(o::NID_X9_62_prime256v1);
            assert!(!key.is_null());
            assert_eq!((*ctx).supportedgroups_len, 0);
            assert_eq!(
                SSL_CTX_ctrl(
                    ctx,
                    /* SSL_CTRL_SET_TMP_ECDH */ 4,
                    0,
                    key.cast::<c_void>(),
                ),
                1,
                "the documented success value"
            );
            // `tls1_get_supported_groups` still answers the default list.
            assert_eq!((*ctx).supportedgroups_len, 0);
            EC_KEY_free(key);
            SSL_CTX_free(ctx);
        }
    }

    // --- OCSP status callback (`SSL_CTX_set_tlsext_status_cb`) -----------------------------

    use core::sync::atomic::{AtomicUsize, Ordering};

    static STATUS_CB_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STATUS_CB_ARG: AtomicUsize = AtomicUsize::new(0);
    static STATUS_CB_RESP: [u8; 4] = [0x30, 0x02, 0x0a, 0x00];

    /// `int (*)(SSL *, void *)` — records the argument and answers `SSL_TLSEXT_ERR_NOACK`.
    unsafe extern "C" fn status_noack_cb(_ssl: *mut Ssl, arg: *mut c_void) -> c_int {
        STATUS_CB_CALLS.fetch_add(1, Ordering::SeqCst);
        STATUS_CB_ARG.store(arg as usize, Ordering::SeqCst);
        3 // SSL_TLSEXT_ERR_NOACK
    }

    /// Supplies a (minimal, non-empty) response through the connection ctrl.
    unsafe extern "C" fn status_respond_cb(ssl: *mut Ssl, arg: *mut c_void) -> c_int {
        STATUS_CB_CALLS.fetch_add(1, Ordering::SeqCst);
        STATUS_CB_ARG.store(arg as usize, Ordering::SeqCst);
        // SAFETY: `ssl` is the live connection the callback received; `STATUS_CB_RESP` is
        // readable for its length.
        unsafe {
            assert_eq!(
                SSL_ctrl(
                    ssl,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP */ 71,
                    STATUS_CB_RESP.len() as c_long,
                    STATUS_CB_RESP.as_ptr() as *mut c_void,
                ),
                1
            );
        }
        0 // SSL_TLSEXT_ERR_OK
    }

    fn void_cb(
        cb: unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int,
    ) -> Option<unsafe extern "C" fn()> {
        // SAFETY: a `void (*)(void)` and this callback are both pointer-sized; only the pointer
        // bits are stored and compared.
        Some(unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int,
                unsafe extern "C" fn(),
            >(cb)
        })
    }

    #[test]
    fn ssl_ctx_set_tlsext_status_cb_returns_one() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the context is this frame's own object.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                SSL_CTX_callback_ctrl(
                    ctx,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB */ 63,
                    void_cb(status_noack_cb),
                ),
                1,
                "SSL_CTX_set_tlsext_status_cb's macro must observe 1"
            );
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn tlsext_status_cb_and_arg_round_trip() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the context is this frame's own object; the out-slots are live locals.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                SSL_CTX_callback_ctrl(
                    ctx,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB */ 63,
                    void_cb(status_noack_cb),
                ),
                1
            );
            let arg = 0x5a5a_usize as *mut c_void;
            assert_eq!(
                SSL_CTX_ctrl(ctx, /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG */ 64, 0, arg),
                1
            );
            let mut got_cb: Option<unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int> = None;
            assert_eq!(
                SSL_CTX_ctrl(
                    ctx,
                    /* SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB */ 128,
                    0,
                    (&mut got_cb
                        as *mut Option<unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int>)
                        .cast(),
                ),
                1
            );
            assert_eq!(
                got_cb.map(|f| f as usize),
                Some(status_noack_cb as *const () as usize)
            );
            let mut got_arg: *mut c_void = core::ptr::null_mut();
            assert_eq!(
                SSL_CTX_ctrl(
                    ctx,
                    /* SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG */ 129,
                    0,
                    (&mut got_arg as *mut *mut c_void).cast(),
                ),
                1
            );
            assert_eq!(got_arg, arg);
            SSL_CTX_free(ctx);
        }
    }

    fn assert_status_cb_invoked(cipher: &CStr, version: c_int) {
        let _g = crate::test_support::lock_global_state();
        STATUS_CB_CALLS.store(0, Ordering::SeqCst);
        STATUS_CB_ARG.store(0, Ordering::SeqCst);
        let arg = 0x1234_usize as *mut c_void;
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(cipher, version, None, None);
            assert_eq!(
                SSL_CTX_callback_ctrl(
                    p.sctx,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB */ 63,
                    void_cb(status_noack_cb),
                ),
                1
            );
            assert_eq!(
                SSL_CTX_ctrl(p.sctx, /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG */ 64, 0, arg),
                1
            );
            // The client asks for OCSP status (`SSL_set_tlsext_status_type`).
            assert_eq!(
                SSL_ctrl(
                    p.c,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE */ 65,
                    1,
                    core::ptr::null_mut()
                ),
                1
            );
            let (client_ok, server_ok) = drive(&p);
            let reasons = error_reasons();
            free_pair(p);
            assert!(
                client_ok && server_ok,
                "handshake failed (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert_eq!(
                STATUS_CB_CALLS.load(Ordering::SeqCst),
                1,
                "the server's status callback must be invoked exactly once"
            );
            assert_eq!(STATUS_CB_ARG.load(Ordering::SeqCst), arg as usize);
        }
    }

    #[test]
    fn tlsext_status_cb_invoked_tls12() {
        assert_status_cb_invoked(c"ECDHE-RSA-AES128-GCM-SHA256", TLS1_2_VERSION);
    }

    #[test]
    fn tlsext_status_cb_invoked_tls13() {
        assert_status_cb_invoked(c"TLS_AES_128_GCM_SHA256", TLS1_3_VERSION);
    }

    #[test]
    fn tlsext_status_response_included_tls12() {
        let _g = crate::test_support::lock_global_state();
        STATUS_CB_CALLS.store(0, Ordering::SeqCst);
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(c"ECDHE-RSA-AES128-GCM-SHA256", TLS1_2_VERSION, None, None);
            assert_eq!(
                SSL_CTX_callback_ctrl(
                    p.sctx,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB */ 63,
                    void_cb(status_respond_cb),
                ),
                1
            );
            assert_eq!(
                SSL_ctrl(
                    p.c,
                    /* SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE */ 65,
                    1,
                    core::ptr::null_mut()
                ),
                1
            );
            let (client_ok, server_ok) = drive(&p);
            let reasons = error_reasons();
            assert!(
                client_ok && server_ok,
                "handshake failed (client={client_ok} server={server_ok}, reasons={reasons:?})"
            );
            assert_eq!(STATUS_CB_CALLS.load(Ordering::SeqCst), 1);
            let mut got: *mut u8 = core::ptr::null_mut();
            let len = SSL_ctrl(
                p.c,
                /* SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP */ 70,
                0,
                (&mut got as *mut *mut u8).cast(),
            );
            assert_eq!(len, STATUS_CB_RESP.len() as c_long);
            assert!(!got.is_null());
            assert_eq!(
                core::slice::from_raw_parts(got, len as usize),
                &STATUS_CB_RESP
            );
            free_pair(p);
        }
    }

    // --- `SSL_peek` ------------------------------------------------------------------------

    /// `SSL_ERROR_WANT_READ` (`ssl.h`), the class `SSL_get_error` answers for a retryable read.
    const SSL_ERROR_WANT_READ: c_int = 2;

    /// Complete a handshake, send `payload` from the client and assert that a peek returns it
    /// without consuming it, that repeated peeks are identical, that a zero-length peek answers 0
    /// and that the following read returns exactly the peeked bytes.
    fn assert_peek_matches_read(cipher: &CStr, version: c_int) {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(cipher, version, None, None);
            let (client_ok, server_ok) = drive(&p);
            assert!(
                client_ok && server_ok,
                "the {cipher:?} handshake must complete (client={client_ok}, server={server_ok})"
            );

            let payload = b"peek-returns-this";
            let w = SSL_write(p.c, payload.as_ptr().cast(), payload.len() as c_int);
            assert_eq!(w, payload.len() as c_int, "the client write must complete");
            drain(p.c_w, p.s_r);

            let mut buf = [0u8; 64];
            // A peek shorter than the record returns that prefix and consumes nothing.
            let n = SSL_peek(p.s, buf.as_mut_ptr().cast(), 4);
            assert_eq!(n, 4, "a short peek returns the requested prefix");
            assert_eq!(&buf[..4], &payload[..4]);

            // A second, larger peek starts at the record's first byte again.
            let n = SSL_peek(p.s, buf.as_mut_ptr().cast(), buf.len() as c_int);
            assert_eq!(n, payload.len() as c_int, "peek returns the whole record");
            assert_eq!(&buf[..payload.len()], payload);
            assert_eq!(
                SSL_pending(p.s),
                payload.len() as c_int,
                "a peek leaves the plaintext pending"
            );

            // A zero-length peek answers 0 and still consumes nothing.
            assert_eq!(
                SSL_peek(p.s, buf.as_mut_ptr().cast(), 0),
                0,
                "a zero-length peek answers 0"
            );

            // The following read returns exactly the bytes the peek reported.
            let r = SSL_read(p.s, buf.as_mut_ptr().cast(), buf.len() as c_int);
            assert_eq!(
                r,
                payload.len() as c_int,
                "the read after a peek sees the data"
            );
            assert_eq!(&buf[..payload.len()], payload);
            assert_eq!(SSL_pending(p.s), 0, "the read consumes the record");

            free_pair(p);
        }
    }

    #[test]
    fn peek_matches_read_tls12() {
        assert_peek_matches_read(c"ECDHE-RSA-AES128-GCM-SHA256", TLS1_2_VERSION);
    }

    #[test]
    fn peek_matches_read_tls13() {
        assert_peek_matches_read(c"TLS_AES_128_GCM_SHA256", TLS1_3_VERSION);
    }

    /// A peek before the handshake finishes must drive the handshake and report the blocked
    /// transport as `WANT_READ`, not `SYSCALL` (`ssl3_read_bytes`, `rec_layer_s3.c:673-680`).
    #[test]
    fn peek_unfinished_handshake_reports_want_read() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released by this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            SSL_set_connect_state(ssl);

            let mut b1: *mut Bio = ptr::null_mut();
            let mut b2: *mut Bio = ptr::null_mut();
            assert_eq!(BIO_new_bio_pair(&mut b1, 0, &mut b2, 0), 1);
            assert!(!b1.is_null() && !b2.is_null());
            SSL_set_bio(ssl, b1, b1);

            let mut buf = [0u8; 16];
            let ret = SSL_peek(ssl, buf.as_mut_ptr().cast(), buf.len() as c_int);
            assert!(ret <= 0, "an unfinished handshake must not yield data");
            assert_eq!(
                SSL_get_error(ssl, ret),
                SSL_ERROR_WANT_READ,
                "SSL_peek must drive the handshake exactly as SSL_read does"
            );

            SSL_free(ssl);
            BIO_free(b2);
            SSL_CTX_free(ctx);
        }
    }

    /// A peek on an empty, non-blocking transport after the handshake reports `WANT_READ`.
    #[test]
    fn peek_with_no_data_reports_want_read() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created and released in this frame.
        unsafe {
            ERR_clear_error();
            let p = make_pair(c"TLS_AES_128_GCM_SHA256", TLS1_3_VERSION, None, None);
            let (client_ok, server_ok) = drive(&p);
            assert!(client_ok && server_ok, "the TLS1.3 handshake must complete");

            // Replace the server's drained memory BIO with an empty non-blocking pair. The old
            // BIOs are released by `SSL_set_bio`; `free_pair` only releases the connections and
            // contexts, so the stored pointers are not touched again.
            let mut b1: *mut Bio = ptr::null_mut();
            let mut b2: *mut Bio = ptr::null_mut();
            assert_eq!(BIO_new_bio_pair(&mut b1, 0, &mut b2, 0), 1);
            assert!(!b1.is_null() && !b2.is_null());
            SSL_set_bio(p.s, b1, b1);

            let mut buf = [0u8; 16];
            let ret = SSL_peek(p.s, buf.as_mut_ptr().cast(), buf.len() as c_int);
            assert!(ret <= 0, "an empty transport must not yield data");
            assert_eq!(
                SSL_get_error(p.s, ret),
                SSL_ERROR_WANT_READ,
                "an empty non-blocking transport must report WANT_READ"
            );

            free_pair(p);
            BIO_free(b2);
        }
    }

    /// The server handshake plus one application write must fit radsecproxy's 32 KiB thread stack
    /// (`THREAD_STACK_SIZE 32768`). Before the record scratch and handshake framing buffers were
    /// moved to the allocator seam, `ssl3_write_one_record` alone took a ~17 KiB frame, so an
    /// `SSL_accept` inside such a thread crossed the guard page and SIGSEGVed.
    ///
    /// Only the server side runs on the small stack: that is radsecproxy's shape (one
    /// `SSL_accept`/`SSL_write` thread). The client is driven by the test thread, which hands the
    /// server a token per step so the two never touch the memory BIOs concurrently. A regression
    /// faults the test process instead of reporting a clean failure.
    #[test]
    fn tls13_handshake_and_write_fit_a_32_kib_thread_stack() {
        use std::sync::mpsc::channel;

        const THREAD_STACK_SIZE: usize = 32 * 1024;
        enum Cmd {
            Handshake,
            Write,
            Stop,
        }
        let _g = crate::test_support::lock_global_state();
        // SAFETY: the pair is created here; the worker is handed the server's addresses, and the
        // two sides rendezvous on the channels so neither touches a shared BIO concurrently. The
        // pair is released on this frame after the worker has stopped.
        unsafe {
            ERR_clear_error();
            let p = make_pair(c"TLS_AES_128_GCM_SHA256", TLS1_3_VERSION, None, None);
            let (s, s_w) = (p.s as usize, p.s_w as usize);
            let c_r = p.c_r as usize;
            let (cmd_tx, cmd_rx) = channel::<Cmd>();
            let (res_tx, res_rx) = channel::<isize>();
            let worker = std::thread::Builder::new()
                .stack_size(THREAD_STACK_SIZE)
                .spawn(move || {
                    // SAFETY: the addresses name the live server side of the pair this frame
                    // created; this thread is its only user while it runs.
                    let s = s as *mut Ssl;
                    let s_w = s_w as *mut Bio;
                    let c_r = c_r as *mut Bio;
                    while let Ok(cmd) = cmd_rx.recv() {
                        let r = match cmd {
                            Cmd::Handshake => SSL_do_handshake(s),
                            Cmd::Write => {
                                let data = b"radsecproxy-sized application record";
                                SSL_write(s, data.as_ptr().cast(), data.len() as c_int)
                            }
                            Cmd::Stop => break,
                        };
                        drain(s_w, c_r);
                        if res_tx.send(r as isize).is_err() {
                            break;
                        }
                    }
                })
                .expect("the 32 KiB worker thread must spawn");

            let mut client_ok = false;
            let mut server_ok = false;
            for _ in 0..128 {
                let cr = SSL_do_handshake(p.c);
                if cr == 1 {
                    client_ok = true;
                }
                drain(p.c_w, p.s_r);
                cmd_tx.send(Cmd::Handshake).expect("server step channel");
                if res_rx.recv().expect("server step reply") == 1 {
                    server_ok = true;
                }
                if client_ok && server_ok {
                    break;
                }
            }
            assert!(client_ok && server_ok, "the TLS1.3 handshake must complete");

            let data = b"radsecproxy-sized application record";
            cmd_tx.send(Cmd::Write).expect("write channel");
            let written = res_rx.recv().expect("write reply");
            assert_eq!(
                written,
                data.len() as isize,
                "one application record must be written"
            );
            let mut got = [0u8; 64];
            let read = SSL_read(p.c, got.as_mut_ptr().cast(), got.len() as c_int);
            assert_eq!(read, data.len() as c_int, "the client must read the record");
            assert_eq!(&got[..read as usize], data);

            cmd_tx.send(Cmd::Stop).expect("stop channel");
            worker.join().expect("the 32 KiB worker must not fault");
            free_pair(p);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ClientHello parsing cluster: the attacker-supplied session id and cipher-suite vector
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod client_hello_parse_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use core::ffi::c_long;

    use crate::runtime::bio::{bss_mem::BIO_s_mem, BIO_ctrl_pending, BIO_new, BIO_read};
    use crate::runtime::err::ERR_clear_error;
    use crate::runtime::err::ERR_get_error;
    use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_ciph_table::SslCipher;
    use crate::ssl::ssl_lib::{
        SSL_CTX_ctrl, SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new, SSL_set_accept_state, SslCtx,
    };

    const TLS1_3_VERSION: c_int = 0x0304;
    const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
    const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
    const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    const X25519_GROUP: u16 = 0x001d;

    struct Server {
        ctx: *mut SslCtx,
        s: *mut Ssl,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // SAFETY: both objects are this frame's; `SSL_free` releases the connection's
            // references and `SSL_CTX_free` the context's remaining one.
            unsafe {
                SSL_free(self.s);
                SSL_CTX_free(self.ctx);
            }
        }
    }

    /// A TLS1.3-only accept connection. No certificate is needed: TLS1.3 suite selection never
    /// consults one.
    fn tls13_server() -> Server {
        server_with_version_range(TLS1_3_VERSION, TLS1_3_VERSION)
    }

    /// An accept connection restricted to an explicit protocol range.
    fn server_with_version_range(min: c_int, max: c_int) -> Server {
        // SAFETY: every constructor answers a fresh object owned by the returned `Server`.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null(), "a TLS context must be allocatable");
            assert_eq!(
                SSL_CTX_ctrl(
                    ctx,
                    SSL_CTRL_SET_MIN_PROTO_VERSION,
                    min as c_long,
                    core::ptr::null_mut()
                ),
                1
            );
            assert_eq!(
                SSL_CTX_ctrl(
                    ctx,
                    SSL_CTRL_SET_MAX_PROTO_VERSION,
                    max as c_long,
                    core::ptr::null_mut()
                ),
                1
            );
            let s = SSL_new(ctx);
            assert!(!s.is_null(), "a TLS connection must be allocatable");
            SSL_set_accept_state(s);
            Server { ctx, s }
        }
    }

    /// A reduced-server `ClientHello`: TLS1.3 via `supported_versions`, one `x25519`
    /// `supported_groups` entry, one null compression method, and the supplied wire vectors.
    fn client_hello(session_id: &[u8], suites: &[u8]) -> Vec<u8> {
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 43, 0x00, 0x03, 0x02, 0x03, 0x04]); // supported_versions
        let mut groups = X25519_GROUP.to_be_bytes().to_vec();
        let mut group_ext = Vec::new();
        group_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
        group_ext.append(&mut groups);
        exts.extend_from_slice(&[0x00, 10]);
        exts.extend_from_slice(&(group_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&group_ext);
        client_hello_with_exts(session_id, suites, &exts)
    }

    /// The same body with a caller-supplied extension block, so a test can emit exact bytes.
    fn client_hello_with_exts(session_id: &[u8], suites: &[u8], exts: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x5a; 32]); // random
        body.push(session_id.len() as u8); // legacy_session_id<0..255>
        body.extend_from_slice(session_id);
        body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
        body.extend_from_slice(suites);
        body.extend_from_slice(&[1, 0]); // compression_methods: null only
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(exts);
        frame_client_hello(&body)
    }

    /// `ExtensionType(2) || ExtensionData<2> || body`.
    fn ext(etype: u16, body: &[u8]) -> Vec<u8> {
        let mut out = etype.to_be_bytes().to_vec();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// `server_version<1> || versions<2>...`.
    fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
        let mut body = vec![(versions.len() * 2) as u8];
        for v in versions {
            body.extend_from_slice(&v.to_be_bytes());
        }
        ext(TLSEXT_TYPE_SUPPORTED_VERSIONS, &body)
    }

    /// `NamedGroupList<2> || groups<2>...`.
    fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
        let mut body = ((groups.len() * 2) as u16).to_be_bytes().to_vec();
        for g in groups {
            body.extend_from_slice(&g.to_be_bytes());
        }
        ext(TLSEXT_TYPE_SUPPORTED_GROUPS, &body)
    }

    /// `KeyShareClientHello<2> || (group<2> || key<2> || key)...`.
    fn key_share_ext(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (group, key) in entries {
            list.extend_from_slice(&group.to_be_bytes());
            list.extend_from_slice(&(key.len() as u16).to_be_bytes());
            list.extend_from_slice(key);
        }
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        ext(TLSEXT_TYPE_KEY_SHARE, &body)
    }

    /// Attach a fresh memory BIO as the write side so a fatal alert's wire bytes are observable.
    fn attach_wbio(s: *mut Ssl) {
        // SAFETY: `s` is live; ownership of the BIO transfers to the connection, released by
        // `SSL_free`.
        unsafe {
            let bio = BIO_new(BIO_s_mem());
            assert!(!bio.is_null(), "a memory BIO must be allocatable");
            (*s).wbio = bio;
        }
    }

    /// Drain the write side's pending bytes.
    fn wbio_bytes(s: *mut Ssl) -> Vec<u8> {
        // SAFETY: `s` is live and `wbio` is the memory BIO `attach_wbio` installed.
        unsafe {
            let wbio = (*s).wbio;
            assert!(!wbio.is_null());
            let n = BIO_ctrl_pending(wbio);
            let mut out = vec![0u8; n];
            if n > 0 {
                let got = BIO_read(wbio, out.as_mut_ptr().cast(), n as c_int);
                assert!(got >= 0);
                out.truncate(got as usize);
            }
            out
        }
    }

    /// Drain this thread's error queue and return the reason codes.
    fn error_reasons() -> Vec<c_int> {
        let mut reasons = Vec::new();
        loop {
            let e = ERR_get_error();
            if e == 0 {
                break;
            }
            reasons.push((e & 0x7f_ffff) as c_int);
        }
        reasons
    }

    fn frame_client_hello(body: &[u8]) -> Vec<u8> {
        let mut hs = Vec::with_capacity(4 + body.len());
        hs.push(SSL3_MT_CLIENT_HELLO_BODY);
        hs.push((body.len() >> 16) as u8);
        hs.push((body.len() >> 8) as u8);
        hs.push(body.len() as u8);
        hs.extend_from_slice(body);
        hs
    }

    fn pending_id(s: *mut Ssl) -> u16 {
        // SAFETY: `s` is live; the pointer is checked before it is dereferenced.
        unsafe {
            let c = (*s).pending_cipher;
            assert!(!c.is_null(), "a suite must have been selected");
            (*c).id as u16
        }
    }

    fn peer_cipher_ids(s: *mut Ssl) -> Vec<u16> {
        // SAFETY: `s` is live and `peer_ciphers` is NULL or a live stack.
        unsafe {
            let sk = (*s).peer_ciphers;
            assert!(!sk.is_null(), "the peer cipher stack must be built");
            (0..OPENSSL_sk_num(sk))
                .map(|i| (*(OPENSSL_sk_value(sk, i) as *const SslCipher)).id as u16)
                .collect()
        }
    }

    #[test]
    fn valid_suite_list_selects_and_records_the_expected_suite() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let hs = client_hello(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes());
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 1, "a well-formed TLS1.3 ClientHello must be accepted");
        assert_eq!(pending_id(srv.s), TLS_AES_128_GCM_SHA256);
        assert_eq!(peer_cipher_ids(srv.s), vec![TLS_AES_128_GCM_SHA256]);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).tmp_session_id_len }, 32);
    }

    #[test]
    fn odd_length_suite_list_ignores_the_trailing_byte() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut suites = TLS_AES_128_GCM_SHA256.to_be_bytes().to_vec();
        suites.push(0x13); // half a suite: ignored, as the `q + 2 <= len` walk did
        let hs = client_hello(&[], &suites);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 1, "the trailing half-suite must not reject the hello");
        assert_eq!(pending_id(srv.s), TLS_AES_128_GCM_SHA256);
        assert_eq!(peer_cipher_ids(srv.s), vec![TLS_AES_128_GCM_SHA256]);
    }

    #[test]
    fn zero_and_duplicate_suites_keep_the_authority_walk_semantics() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut suites = vec![0x00, 0x00];
        suites.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        suites.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        suites.extend_from_slice(&[0xff, 0xff]); // unknown suite
        let hs = client_hello(&[], &suites);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 1, "the unknown entries must not reject the hello");
        assert_eq!(pending_id(srv.s), TLS_AES_128_GCM_SHA256);
        // The zero and unknown ids resolve to no table row and are skipped; both copies of the
        // known suite are pushed, in wire order, exactly as before.
        assert_eq!(
            peer_cipher_ids(srv.s),
            vec![TLS_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256]
        );
    }

    /// Compatibility correction: the authority's regular-ClientHello arm rejects
    /// `session_id_len` above `SSL_MAX_SSL_SESSION_ID_LENGTH` with `SSL_AD_DECODE_ERROR` /
    /// `SSL_R_LENGTH_MISMATCH` (`statem_srvr.c:1776-1781`) instead of truncating it. The
    /// reduced reader used to clamp to 32; it now raises that alert and reason.
    #[test]
    fn over_long_session_id_is_rejected_with_the_authority_alert() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        attach_wbio(srv.s);
        ERR_clear_error();
        let hs = client_hello(&[0xab; 40], &TLS_AES_128_GCM_SHA256.to_be_bytes());
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 0, "an over-long session id must be rejected");
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!(
                (*srv.s).tmp_session_id_len,
                0,
                "the rejected id must not be recorded"
            );
        }
        assert_eq!(
            error_reasons(),
            vec![SSL_R_LENGTH_MISMATCH],
            "the reason must be the authority's SSL_R_LENGTH_MISMATCH"
        );
        let wire = wbio_bytes(srv.s);
        assert!(
            wire.len() >= 2,
            "the fatal alert must reach the write side: {wire:?}"
        );
        assert_eq!(
            &wire[wire.len() - 2..],
            &[2, SSL_AD_DECODE_ERROR as u8],
            "level fatal (2) and SSL_AD_DECODE_ERROR (50)"
        );
    }

    #[test]
    fn largest_legal_session_id_is_accepted_and_echoed() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let id = [0xcd; 32];
        let hs = client_hello(&id, &TLS_AES_128_GCM_SHA256.to_be_bytes());
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!((*srv.s).tmp_session_id_len, 32);
            assert_eq!((*srv.s).tmp_session_id, id);
        }
    }

    // --- extension walk ------------------------------------------------------------------

    #[test]
    fn supported_versions_present_selects_tls13() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut exts = supported_versions_ext(&[0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, TLS1_3_VERSION);
    }

    #[test]
    fn supported_versions_absent_falls_back_to_the_legacy_version() {
        let _g = crate::test_support::lock_global_state();
        let srv = server_with_version_range(0x0303, TLS1_3_VERSION);
        let exts = supported_groups_ext(&[X25519_GROUP]);
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // Without `supported_versions` the legacy 0x0303 governs; this context has no TLS1.2
        // certificate, so the parse stops at cipher selection, after recording the version.
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 0);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, 0x0303);
    }

    #[test]
    fn supported_versions_prefers_tls13_regardless_of_list_order() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut exts = supported_versions_ext(&[0x0303, 0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, TLS1_3_VERSION);
    }

    #[test]
    fn supported_versions_without_the_selected_version_is_refused() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut exts = supported_versions_ext(&[0x0303]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        ERR_clear_error();
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 0);
        assert_eq!(error_reasons(), vec![SSL_R_UNSUPPORTED_PROTOCOL]);
    }

    #[test]
    fn duplicate_supported_versions_is_accepted() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut exts = supported_versions_ext(&[0x0303]);
        exts.extend_from_slice(&supported_versions_ext(&[0x0304]));
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        assert_eq!(
            // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
            unsafe { tls_process_client_hello(srv.s, &hs) },
            1,
            "both occurrences are walked; the TLS1.3 offer wins"
        );
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, TLS1_3_VERSION);
    }

    #[test]
    fn extension_order_does_not_change_the_selection() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let share = [0x42u8; 32];
        let mut exts = key_share_ext(&[(X25519_GROUP, &share)]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        exts.extend_from_slice(&supported_versions_ext(&[0x0304]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!((*srv.s).version, TLS1_3_VERSION);
            assert_eq!((*srv.s).group_id, X25519_GROUP);
        }
    }

    #[test]
    fn extension_body_overrunning_the_block_is_rejected() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        // A complete, acceptable TLS1.3 preamble, then a trailing `key_share` that claims eight
        // body bytes where only four remain. The overrun alone must reject the hello.
        let mut exts = supported_versions_ext(&[0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        exts.extend_from_slice(&[0x00, 51, 0x00, 0x08, 0xaa, 0xbb, 0xcc, 0xdd]);
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        assert_eq!(
            // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
            unsafe { tls_process_client_hello(srv.s, &hs) },
            0,
            "an extension body that overruns the block must be refused"
        );
    }

    #[test]
    fn truncated_extension_header_is_accepted_as_no_extensions() {
        let _g = crate::test_support::lock_global_state();
        let srv = server_with_version_range(0x0303, TLS1_3_VERSION);
        // One stray byte cannot hold a four-byte extension header; the walk stops cleanly and
        // the legacy version governs.
        let exts = [0x00];
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 0);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, 0x0303);
    }

    #[test]
    fn oversized_supported_versions_list_is_clamped_not_read_past() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        // The declared list is 200 bytes but only one version follows; the walk stops at the
        // extension body's end, exactly as the previous `min` bound did.
        let body = [200u8, 0x03, 0x04];
        let mut exts = ext(TLSEXT_TYPE_SUPPORTED_VERSIONS, &body);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).version }, TLS1_3_VERSION);
    }

    #[test]
    fn key_share_entry_overrunning_the_body_stops_the_walk() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        // One entry declaring a 32-byte key but supplying none: the entry is dropped, and the
        // `supported_groups` selection alone remains (no key share, so no group is recorded).
        let mut body = 6u16.to_be_bytes().to_vec();
        body.extend_from_slice(&X25519_GROUP.to_be_bytes());
        body.extend_from_slice(&32u16.to_be_bytes());
        let mut exts = supported_versions_ext(&[0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        exts.extend_from_slice(&ext(TLSEXT_TYPE_KEY_SHARE, &body));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!((*srv.s).group_id, 0);
            assert!((*srv.s).peer_tmp.is_null());
        }
    }

    #[test]
    fn key_share_with_an_unknown_group_is_ignored() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let share = [0x42u8; 32];
        let mut exts = supported_versions_ext(&[0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        exts.extend_from_slice(&key_share_ext(&[(0x0100, &share)]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!(
                (*srv.s).group_id,
                0,
                "an unknown group must not be selected"
            );
            assert!((*srv.s).peer_tmp.is_null(), "no peer share must be built");
        }
    }

    #[test]
    fn key_share_with_an_empty_share_list_is_ignored() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut exts = supported_versions_ext(&[0x0304]);
        exts.extend_from_slice(&supported_groups_ext(&[X25519_GROUP]));
        exts.extend_from_slice(&key_share_ext(&[]));
        let hs = client_hello_with_exts(&[0x11; 32], &TLS_AES_128_GCM_SHA256.to_be_bytes(), &exts);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        assert_eq!(unsafe { tls_process_client_hello(srv.s, &hs) }, 1);
        // SAFETY: `srv.s` is live.
        unsafe {
            assert_eq!((*srv.s).group_id, 0);
            assert!((*srv.s).peer_tmp.is_null());
        }
    }

    /// Deterministic, bounded malformed-extension loop: every generated block is walked by a
    /// fresh connection, and the only acceptable outcomes are the authority's accept (1) and
    /// reject (0). A panic would fail the test; nothing here depends on process state.
    #[test]
    fn seeded_malformed_extension_walk_never_panics() {
        let _g = crate::test_support::lock_global_state();
        let mut state = 0x0ddc_0ffe_e15e_beefu64;
        let next = |state: &mut u64| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        };
        let suite = TLS_AES_128_GCM_SHA256.to_be_bytes();
        // SAFETY: the context is this frame's and every connection is released below.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            for i in 0..256usize {
                let s = SSL_new(ctx);
                assert!(!s.is_null());
                SSL_set_accept_state(s);
                let mut exts = Vec::new();
                if i % 4 == 0 {
                    // Structured-but-wrong: a valid header with a random length, then noise.
                    let etype = (next(&mut state) % 3) as u16 * 20 + 10;
                    let len = (next(&mut state) % 40) as u16;
                    exts.extend_from_slice(&etype.to_be_bytes());
                    exts.extend_from_slice(&len.to_be_bytes());
                    let n = (next(&mut state) % 48) as usize;
                    exts.extend((0..n).map(|_| next(&mut state) as u8));
                } else {
                    let n = (next(&mut state) % 64) as usize;
                    exts.extend((0..n).map(|_| next(&mut state) as u8));
                }
                let hs = client_hello_with_exts(&[0x33; 16], &suite, &exts);
                let r = tls_process_client_hello(s, &hs);
                assert!(r == 0 || r == 1, "unexpected parse answer {r}");
                ERR_clear_error();
                SSL_free(s);
            }
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn zero_length_session_id_records_zero() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let hs = client_hello(&[], &TLS_AES_128_GCM_SHA256.to_be_bytes());
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 1, "a zero-length session id is legal");
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).tmp_session_id_len }, 0);
    }

    #[test]
    fn truncated_session_id_is_rejected() {
        let _g = crate::test_support::lock_global_state();
        let srv = tls13_server();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x5a; 32]);
        body.push(8); // claims eight bytes ...
        body.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // ... supplies four
        let hs = frame_client_hello(&body);
        // SAFETY: `srv.s` is live and `hs` is a complete handshake message.
        let r = unsafe { tls_process_client_hello(srv.s, &hs) };
        assert_eq!(r, 0, "a session id that overruns the body must be rejected");
        // SAFETY: `srv.s` is live.
        assert_eq!(unsafe { (*srv.s).tmp_session_id_len }, 0);
    }

    #[test]
    fn random_short_buffers_never_panic() {
        let _g = crate::test_support::lock_global_state();
        let baseline = client_hello(&[0x22; 16], &TLS_AES_128_GCM_SHA256.to_be_bytes());
        let mut state = 0x9e37_79b9_7f4a_7c15u64; // xorshift64, deterministic seed
        let next = |state: &mut u64| {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        };
        // A fresh connection per case: a failed parse must never be retried on the same state.
        // SAFETY: the context is this frame's and every connection is released below.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            for i in 0..128usize {
                let s = SSL_new(ctx);
                assert!(!s.is_null());
                SSL_set_accept_state(s);
                let bytes = if i % 2 == 0 {
                    // Mutate a well-formed hello so the deeper paths are reached too.
                    let mut m = baseline.clone();
                    let bit = (next(&mut state) as usize) % (m.len() * 8);
                    m[bit / 8] ^= 1 << (bit % 8);
                    m
                } else {
                    let len = (next(&mut state) as usize) % 96;
                    (0..len).map(|_| next(&mut state) as u8).collect()
                };
                let _ = tls_process_client_hello(s, &bytes);
                ERR_clear_error();
                SSL_free(s);
            }
            SSL_CTX_free(ctx);
        }
    }
}
