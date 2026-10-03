//! Phase 14.9 — `ssl/ssl_stat.c`: the alert and state string readers.
//!
//! The six rows the plan gives this unit: `SSL_state_string`/`_long`, which map the connection's
//! handshake state to the authority's four- and long-character spellings, and the four alert
//! readers, `SSL_alert_type_string`/`_long` and `SSL_alert_desc_string`/`_long`, which decode the
//! packed `(level << 8) | description` value. The state tables are transcribed in full, including
//! the arms a fresh connection cannot reach, so a connection whose `hand_state` a later subphase
//! sets reports the authority's string.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The error test is `statem.state == MSG_FLOW_ERROR`.** The authority calls
//!   `ossl_statem_in_error` (`statem.c:195-201`) and then `SSL_get_state`; this crate reads the two
//!   words `SSL_new` installs (`statem_state`, `hand_state`) directly. A fresh connection reports
//!   `PINIT`/`before SSL initialization`, the authority's own answer for `TLS_ST_BEFORE` with no
//!   error. A NULL `s` reports `SSLERR`/`error`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::ssl::ssl_lib::Ssl;

/// `MSG_FLOW_ERROR` — `internal/statem.h:54`.
const MSG_FLOW_ERROR: c_int = 1;

/// `TLS_ST_BEFORE` — `ssl.h:1066`.
const TLS_ST_BEFORE: c_int = 0;
/// `TLS_ST_OK` — `ssl.h:1067`.
const TLS_ST_OK: c_int = 1;
/// `DTLS_ST_CR_HELLO_VERIFY_REQUEST` — `ssl.h:1068`.
const DTLS_ST_CR_HELLO_VERIFY_REQUEST: c_int = 2;
/// `TLS_ST_CR_SRVR_HELLO` — `ssl.h:1069`.
const TLS_ST_CR_SRVR_HELLO: c_int = 3;
/// `TLS_ST_CR_CERT` — `ssl.h:1070`.
const TLS_ST_CR_CERT: c_int = 4;
/// `TLS_ST_CR_COMP_CERT` — `ssl.h:1071`.
const TLS_ST_CR_COMP_CERT: c_int = 5;
/// `TLS_ST_CR_CERT_STATUS` — `ssl.h:1072`.
const TLS_ST_CR_CERT_STATUS: c_int = 6;
/// `TLS_ST_CR_KEY_EXCH` — `ssl.h:1073`.
const TLS_ST_CR_KEY_EXCH: c_int = 7;
/// `TLS_ST_CR_CERT_REQ` — `ssl.h:1074`.
const TLS_ST_CR_CERT_REQ: c_int = 8;
/// `TLS_ST_CR_SRVR_DONE` — `ssl.h:1075`.
const TLS_ST_CR_SRVR_DONE: c_int = 9;
/// `TLS_ST_CR_SESSION_TICKET` — `ssl.h:1076`.
const TLS_ST_CR_SESSION_TICKET: c_int = 10;
/// `TLS_ST_CR_CHANGE` — `ssl.h:1077`.
const TLS_ST_CR_CHANGE: c_int = 11;
/// `TLS_ST_CR_FINISHED` — `ssl.h:1078`.
const TLS_ST_CR_FINISHED: c_int = 12;
/// `TLS_ST_CW_CLNT_HELLO` — `ssl.h:1079`.
const TLS_ST_CW_CLNT_HELLO: c_int = 13;
/// `TLS_ST_CW_CERT` — `ssl.h:1080`.
const TLS_ST_CW_CERT: c_int = 14;
/// `TLS_ST_CW_COMP_CERT` — `ssl.h:1081`.
const TLS_ST_CW_COMP_CERT: c_int = 15;
/// `TLS_ST_CW_KEY_EXCH` — `ssl.h:1082`.
const TLS_ST_CW_KEY_EXCH: c_int = 16;
/// `TLS_ST_CW_CERT_VRFY` — `ssl.h:1083`.
const TLS_ST_CW_CERT_VRFY: c_int = 17;
/// `TLS_ST_CW_CHANGE` — `ssl.h:1084`.
const TLS_ST_CW_CHANGE: c_int = 18;
/// `TLS_ST_CW_NEXT_PROTO` — `ssl.h:1085`.
const TLS_ST_CW_NEXT_PROTO: c_int = 19;
/// `TLS_ST_CW_FINISHED` — `ssl.h:1086`.
const TLS_ST_CW_FINISHED: c_int = 20;
/// `TLS_ST_SW_HELLO_REQ` — `ssl.h:1087`.
const TLS_ST_SW_HELLO_REQ: c_int = 21;
/// `TLS_ST_SR_CLNT_HELLO` — `ssl.h:1088`.
const TLS_ST_SR_CLNT_HELLO: c_int = 22;
/// `DTLS_ST_SW_HELLO_VERIFY_REQUEST` — `ssl.h:1089`.
const DTLS_ST_SW_HELLO_VERIFY_REQUEST: c_int = 23;
/// `TLS_ST_SW_SRVR_HELLO` — `ssl.h:1090`.
const TLS_ST_SW_SRVR_HELLO: c_int = 24;
/// `TLS_ST_SW_CERT` — `ssl.h:1091`.
const TLS_ST_SW_CERT: c_int = 25;
/// `TLS_ST_SW_COMP_CERT` — `ssl.h:1092`.
const TLS_ST_SW_COMP_CERT: c_int = 26;
/// `TLS_ST_SW_KEY_EXCH` — `ssl.h:1093`.
const TLS_ST_SW_KEY_EXCH: c_int = 27;
/// `TLS_ST_SW_CERT_REQ` — `ssl.h:1094`.
const TLS_ST_SW_CERT_REQ: c_int = 28;
/// `TLS_ST_SW_SRVR_DONE` — `ssl.h:1095`.
const TLS_ST_SW_SRVR_DONE: c_int = 29;
/// `TLS_ST_SR_CERT` — `ssl.h:1096`.
const TLS_ST_SR_CERT: c_int = 30;
/// `TLS_ST_SR_COMP_CERT` — `ssl.h:1097`.
const TLS_ST_SR_COMP_CERT: c_int = 31;
/// `TLS_ST_SR_KEY_EXCH` — `ssl.h:1098`.
const TLS_ST_SR_KEY_EXCH: c_int = 32;
/// `TLS_ST_SR_CERT_VRFY` — `ssl.h:1099`.
const TLS_ST_SR_CERT_VRFY: c_int = 33;
/// `TLS_ST_SR_NEXT_PROTO` — `ssl.h:1100`.
const TLS_ST_SR_NEXT_PROTO: c_int = 34;
/// `TLS_ST_SR_CHANGE` — `ssl.h:1101`.
const TLS_ST_SR_CHANGE: c_int = 35;
/// `TLS_ST_SR_FINISHED` — `ssl.h:1102`.
const TLS_ST_SR_FINISHED: c_int = 36;
/// `TLS_ST_SW_SESSION_TICKET` — `ssl.h:1103`.
const TLS_ST_SW_SESSION_TICKET: c_int = 37;
/// `TLS_ST_SW_CERT_STATUS` — `ssl.h:1104`.
const TLS_ST_SW_CERT_STATUS: c_int = 38;
/// `TLS_ST_SW_CHANGE` — `ssl.h:1105`.
const TLS_ST_SW_CHANGE: c_int = 39;
/// `TLS_ST_SW_FINISHED` — `ssl.h:1106`.
const TLS_ST_SW_FINISHED: c_int = 40;
/// `TLS_ST_SW_ENCRYPTED_EXTENSIONS` — `ssl.h:1107`.
const TLS_ST_SW_ENCRYPTED_EXTENSIONS: c_int = 41;
/// `TLS_ST_CR_ENCRYPTED_EXTENSIONS` — `ssl.h:1108`.
const TLS_ST_CR_ENCRYPTED_EXTENSIONS: c_int = 42;
/// `TLS_ST_CR_CERT_VRFY` — `ssl.h:1109`.
const TLS_ST_CR_CERT_VRFY: c_int = 43;
/// `TLS_ST_SW_CERT_VRFY` — `ssl.h:1110`.
const TLS_ST_SW_CERT_VRFY: c_int = 44;
/// `TLS_ST_CR_HELLO_REQ` — `ssl.h:1111`.
const TLS_ST_CR_HELLO_REQ: c_int = 45;
/// `TLS_ST_SW_KEY_UPDATE` — `ssl.h:1112`.
const TLS_ST_SW_KEY_UPDATE: c_int = 46;
/// `TLS_ST_CW_KEY_UPDATE` — `ssl.h:1113`.
const TLS_ST_CW_KEY_UPDATE: c_int = 47;
/// `TLS_ST_SR_KEY_UPDATE` — `ssl.h:1114`.
const TLS_ST_SR_KEY_UPDATE: c_int = 48;
/// `TLS_ST_CR_KEY_UPDATE` — `ssl.h:1115`.
const TLS_ST_CR_KEY_UPDATE: c_int = 49;
/// `TLS_ST_EARLY_DATA` — `ssl.h:1116`.
const TLS_ST_EARLY_DATA: c_int = 50;
/// `TLS_ST_PENDING_EARLY_DATA_END` — `ssl.h:1117`.
const TLS_ST_PENDING_EARLY_DATA_END: c_int = 51;
/// `TLS_ST_CW_END_OF_EARLY_DATA` — `ssl.h:1118`.
const TLS_ST_CW_END_OF_EARLY_DATA: c_int = 52;
/// `TLS_ST_SR_END_OF_EARLY_DATA` — `ssl.h:1119`.
const TLS_ST_SR_END_OF_EARLY_DATA: c_int = 53;

/// `SSL3_AL_WARNING` — `ssl3.h:227`.
const SSL3_AL_WARNING: c_int = 1;
/// `SSL3_AL_FATAL` — `ssl3.h:228`.
const SSL3_AL_FATAL: c_int = 2;

/// `SSL3_AD_CLOSE_NOTIFY` — `ssl3.h:238`.
const SSL3_AD_CLOSE_NOTIFY: c_int = 0;
/// `SSL3_AD_UNEXPECTED_MESSAGE` — `ssl3.h:239`.
const SSL3_AD_UNEXPECTED_MESSAGE: c_int = 10;
/// `SSL3_AD_BAD_RECORD_MAC` — `ssl3.h:240`.
const SSL3_AD_BAD_RECORD_MAC: c_int = 20;
/// `SSL3_AD_DECOMPRESSION_FAILURE` — `ssl3.h:241`.
const SSL3_AD_DECOMPRESSION_FAILURE: c_int = 30;
/// `SSL3_AD_HANDSHAKE_FAILURE` — `ssl3.h:247`.
const SSL3_AD_HANDSHAKE_FAILURE: c_int = 40;
/// `SSL3_AD_NO_CERTIFICATE` — `ssl3.h:249`.
const SSL3_AD_NO_CERTIFICATE: c_int = 41;
/// `SSL3_AD_BAD_CERTIFICATE` — `ssl3.h:250`.
const SSL3_AD_BAD_CERTIFICATE: c_int = 42;
/// `SSL3_AD_UNSUPPORTED_CERTIFICATE` — `ssl3.h:251`.
const SSL3_AD_UNSUPPORTED_CERTIFICATE: c_int = 43;
/// `SSL3_AD_CERTIFICATE_REVOKED` — `ssl3.h:252`.
const SSL3_AD_CERTIFICATE_REVOKED: c_int = 44;
/// `SSL3_AD_CERTIFICATE_EXPIRED` — `ssl3.h:253`.
const SSL3_AD_CERTIFICATE_EXPIRED: c_int = 45;
/// `SSL3_AD_CERTIFICATE_UNKNOWN` — `ssl3.h:254`.
const SSL3_AD_CERTIFICATE_UNKNOWN: c_int = 46;
/// `SSL3_AD_ILLEGAL_PARAMETER` — `ssl3.h:255`.
const SSL3_AD_ILLEGAL_PARAMETER: c_int = 47;
/// `TLS1_AD_DECRYPTION_FAILED` — `ssl3.h:260`.
const TLS1_AD_DECRYPTION_FAILED: c_int = 21;
/// `TLS1_AD_RECORD_OVERFLOW` — `ssl3.h:261`.
const TLS1_AD_RECORD_OVERFLOW: c_int = 22;
/// `TLS1_AD_UNKNOWN_CA` — `ssl3.h:263`.
const TLS1_AD_UNKNOWN_CA: c_int = 48;
/// `TLS1_AD_ACCESS_DENIED` — `ssl3.h:264`.
const TLS1_AD_ACCESS_DENIED: c_int = 49;
/// `TLS1_AD_DECODE_ERROR` — `ssl3.h:265`.
const TLS1_AD_DECODE_ERROR: c_int = 50;
/// `TLS1_AD_DECRYPT_ERROR` — `ssl3.h:266`.
const TLS1_AD_DECRYPT_ERROR: c_int = 51;
/// `TLS1_AD_EXPORT_RESTRICTION` — `ssl3.h:267`.
const TLS1_AD_EXPORT_RESTRICTION: c_int = 60;
/// `TLS1_AD_PROTOCOL_VERSION` — `ssl3.h:268`.
const TLS1_AD_PROTOCOL_VERSION: c_int = 70;
/// `TLS1_AD_INSUFFICIENT_SECURITY` — `ssl3.h:269`.
const TLS1_AD_INSUFFICIENT_SECURITY: c_int = 71;
/// `TLS1_AD_INTERNAL_ERROR` — `ssl3.h:270`.
const TLS1_AD_INTERNAL_ERROR: c_int = 80;
/// `TLS1_AD_USER_CANCELLED` — `ssl3.h:272`.
const TLS1_AD_USER_CANCELLED: c_int = 90;
/// `TLS1_AD_NO_RENEGOTIATION` — `ssl3.h:273`.
const TLS1_AD_NO_RENEGOTIATION: c_int = 100;
/// `TLS1_AD_UNSUPPORTED_EXTENSION` — `ssl3.h:275`.
const TLS1_AD_UNSUPPORTED_EXTENSION: c_int = 110;
/// `TLS1_AD_CERTIFICATE_UNOBTAINABLE` — `ssl3.h:276`.
const TLS1_AD_CERTIFICATE_UNOBTAINABLE: c_int = 111;
/// `TLS1_AD_UNRECOGNIZED_NAME` — `ssl3.h:277`.
const TLS1_AD_UNRECOGNIZED_NAME: c_int = 112;
/// `TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE` — `ssl3.h:278`.
const TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE: c_int = 113;
/// `TLS1_AD_BAD_CERTIFICATE_HASH_VALUE` — `ssl3.h:279`.
const TLS1_AD_BAD_CERTIFICATE_HASH_VALUE: c_int = 114;
/// `TLS1_AD_UNKNOWN_PSK_IDENTITY` — `ssl3.h:280`.
const TLS1_AD_UNKNOWN_PSK_IDENTITY: c_int = 115;
/// `TLS1_AD_NO_APPLICATION_PROTOCOL` — `ssl3.h:282`.
const TLS1_AD_NO_APPLICATION_PROTOCOL: c_int = 120;

/// `const char *SSL_state_string_long(const SSL *s)` — `ssl/ssl_stat.c:15-130`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_state_string_long(s: *const Ssl) -> *const c_char {
    if s.is_null() {
        return c"error".as_ptr();
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (hand_state, statem_state) = unsafe { ((*s).hand_state, (*s).statem_state) };
    if statem_state == MSG_FLOW_ERROR {
        return c"error".as_ptr();
    }
    match hand_state {
        TLS_ST_CR_CERT_STATUS => c"SSLv3/TLS read certificate status".as_ptr(),
        TLS_ST_CW_NEXT_PROTO => c"SSLv3/TLS write next proto".as_ptr(),
        TLS_ST_SR_NEXT_PROTO => c"SSLv3/TLS read next proto".as_ptr(),
        TLS_ST_SW_CERT_STATUS => c"SSLv3/TLS write certificate status".as_ptr(),
        TLS_ST_BEFORE => c"before SSL initialization".as_ptr(),
        TLS_ST_OK => c"SSL negotiation finished successfully".as_ptr(),
        TLS_ST_CW_CLNT_HELLO => c"SSLv3/TLS write client hello".as_ptr(),
        TLS_ST_CR_SRVR_HELLO => c"SSLv3/TLS read server hello".as_ptr(),
        TLS_ST_CR_CERT => c"SSLv3/TLS read server certificate".as_ptr(),
        TLS_ST_CR_COMP_CERT => c"TLSv1.3 read server compressed certificate".as_ptr(),
        TLS_ST_CR_KEY_EXCH => c"SSLv3/TLS read server key exchange".as_ptr(),
        TLS_ST_CR_CERT_REQ => c"SSLv3/TLS read server certificate request".as_ptr(),
        TLS_ST_CR_SESSION_TICKET => c"SSLv3/TLS read server session ticket".as_ptr(),
        TLS_ST_CR_SRVR_DONE => c"SSLv3/TLS read server done".as_ptr(),
        TLS_ST_CW_CERT => c"SSLv3/TLS write client certificate".as_ptr(),
        TLS_ST_CW_COMP_CERT => c"TLSv1.3 write client compressed certificate".as_ptr(),
        TLS_ST_CW_KEY_EXCH => c"SSLv3/TLS write client key exchange".as_ptr(),
        TLS_ST_CW_CERT_VRFY => c"SSLv3/TLS write certificate verify".as_ptr(),
        TLS_ST_CW_CHANGE | TLS_ST_SW_CHANGE => c"SSLv3/TLS write change cipher spec".as_ptr(),
        TLS_ST_CW_FINISHED | TLS_ST_SW_FINISHED => c"SSLv3/TLS write finished".as_ptr(),
        TLS_ST_CR_CHANGE | TLS_ST_SR_CHANGE => c"SSLv3/TLS read change cipher spec".as_ptr(),
        TLS_ST_CR_FINISHED | TLS_ST_SR_FINISHED => c"SSLv3/TLS read finished".as_ptr(),
        TLS_ST_SR_CLNT_HELLO => c"SSLv3/TLS read client hello".as_ptr(),
        TLS_ST_SW_HELLO_REQ => c"SSLv3/TLS write hello request".as_ptr(),
        TLS_ST_SW_SRVR_HELLO => c"SSLv3/TLS write server hello".as_ptr(),
        TLS_ST_SW_CERT => c"SSLv3/TLS write certificate".as_ptr(),
        TLS_ST_SW_COMP_CERT => c"TLSv1.3 write server compressed certificate".as_ptr(),
        TLS_ST_SW_KEY_EXCH => c"SSLv3/TLS write key exchange".as_ptr(),
        TLS_ST_SW_CERT_REQ => c"SSLv3/TLS write certificate request".as_ptr(),
        TLS_ST_SW_SESSION_TICKET => c"SSLv3/TLS write session ticket".as_ptr(),
        TLS_ST_SW_SRVR_DONE => c"SSLv3/TLS write server done".as_ptr(),
        TLS_ST_SR_CERT => c"SSLv3/TLS read client certificate".as_ptr(),
        TLS_ST_SR_COMP_CERT => c"TLSv1.3 read client compressed certificate".as_ptr(),
        TLS_ST_SR_KEY_EXCH => c"SSLv3/TLS read client key exchange".as_ptr(),
        TLS_ST_SR_CERT_VRFY => c"SSLv3/TLS read certificate verify".as_ptr(),
        DTLS_ST_CR_HELLO_VERIFY_REQUEST => c"DTLS1 read hello verify request".as_ptr(),
        DTLS_ST_SW_HELLO_VERIFY_REQUEST => c"DTLS1 write hello verify request".as_ptr(),
        TLS_ST_SW_ENCRYPTED_EXTENSIONS => c"TLSv1.3 write encrypted extensions".as_ptr(),
        TLS_ST_CR_ENCRYPTED_EXTENSIONS => c"TLSv1.3 read encrypted extensions".as_ptr(),
        TLS_ST_CR_CERT_VRFY => c"TLSv1.3 read server certificate verify".as_ptr(),
        TLS_ST_SW_CERT_VRFY => c"TLSv1.3 write server certificate verify".as_ptr(),
        TLS_ST_CR_HELLO_REQ => c"SSLv3/TLS read hello request".as_ptr(),
        TLS_ST_SW_KEY_UPDATE => c"TLSv1.3 write server key update".as_ptr(),
        TLS_ST_CW_KEY_UPDATE => c"TLSv1.3 write client key update".as_ptr(),
        TLS_ST_SR_KEY_UPDATE => c"TLSv1.3 read client key update".as_ptr(),
        TLS_ST_CR_KEY_UPDATE => c"TLSv1.3 read server key update".as_ptr(),
        TLS_ST_EARLY_DATA => c"TLSv1.3 early data".as_ptr(),
        TLS_ST_PENDING_EARLY_DATA_END => c"TLSv1.3 pending early data end".as_ptr(),
        TLS_ST_CW_END_OF_EARLY_DATA => c"TLSv1.3 write end of early data".as_ptr(),
        TLS_ST_SR_END_OF_EARLY_DATA => c"TLSv1.3 read end of early data".as_ptr(),
        _ => c"unknown state".as_ptr(),
    }
}

/// `const char *SSL_state_string(const SSL *s)` — `ssl/ssl_stat.c:132-247`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_state_string(s: *const Ssl) -> *const c_char {
    if s.is_null() {
        return c"SSLERR".as_ptr();
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (hand_state, statem_state) = unsafe { ((*s).hand_state, (*s).statem_state) };
    if statem_state == MSG_FLOW_ERROR {
        return c"SSLERR".as_ptr();
    }
    match hand_state {
        TLS_ST_SR_NEXT_PROTO => c"TRNP".as_ptr(),
        TLS_ST_SW_SESSION_TICKET => c"TWST".as_ptr(),
        TLS_ST_SW_CERT_STATUS => c"TWCS".as_ptr(),
        TLS_ST_CR_CERT_STATUS => c"TRCS".as_ptr(),
        TLS_ST_CR_SESSION_TICKET => c"TRST".as_ptr(),
        TLS_ST_CW_NEXT_PROTO => c"TWNP".as_ptr(),
        TLS_ST_BEFORE => c"PINIT".as_ptr(),
        TLS_ST_OK => c"SSLOK".as_ptr(),
        TLS_ST_CW_CLNT_HELLO => c"TWCH".as_ptr(),
        TLS_ST_CR_SRVR_HELLO => c"TRSH".as_ptr(),
        TLS_ST_CR_CERT => c"TRSC".as_ptr(),
        TLS_ST_CR_COMP_CERT => c"TRSCC".as_ptr(),
        TLS_ST_CR_KEY_EXCH => c"TRSKE".as_ptr(),
        TLS_ST_CR_CERT_REQ => c"TRCR".as_ptr(),
        TLS_ST_CR_SRVR_DONE => c"TRSD".as_ptr(),
        TLS_ST_CW_CERT => c"TWCC".as_ptr(),
        TLS_ST_CW_COMP_CERT => c"TWCCC".as_ptr(),
        TLS_ST_CW_KEY_EXCH => c"TWCKE".as_ptr(),
        TLS_ST_CW_CERT_VRFY => c"TWCV".as_ptr(),
        TLS_ST_SW_CHANGE | TLS_ST_CW_CHANGE => c"TWCCS".as_ptr(),
        TLS_ST_SW_FINISHED | TLS_ST_CW_FINISHED => c"TWFIN".as_ptr(),
        TLS_ST_SR_CHANGE | TLS_ST_CR_CHANGE => c"TRCCS".as_ptr(),
        TLS_ST_SR_FINISHED | TLS_ST_CR_FINISHED => c"TRFIN".as_ptr(),
        TLS_ST_SW_HELLO_REQ => c"TWHR".as_ptr(),
        TLS_ST_SR_CLNT_HELLO => c"TRCH".as_ptr(),
        TLS_ST_SW_SRVR_HELLO => c"TWSH".as_ptr(),
        TLS_ST_SW_CERT => c"TWSC".as_ptr(),
        TLS_ST_SW_COMP_CERT => c"TWSCC".as_ptr(),
        TLS_ST_SW_KEY_EXCH => c"TWSKE".as_ptr(),
        TLS_ST_SW_CERT_REQ => c"TWCR".as_ptr(),
        TLS_ST_SW_SRVR_DONE => c"TWSD".as_ptr(),
        TLS_ST_SR_CERT => c"TRCC".as_ptr(),
        TLS_ST_SR_COMP_CERT => c"TRCCC".as_ptr(),
        TLS_ST_SR_KEY_EXCH => c"TRCKE".as_ptr(),
        TLS_ST_SR_CERT_VRFY => c"TRCV".as_ptr(),
        DTLS_ST_CR_HELLO_VERIFY_REQUEST => c"DRCHV".as_ptr(),
        DTLS_ST_SW_HELLO_VERIFY_REQUEST => c"DWCHV".as_ptr(),
        TLS_ST_SW_ENCRYPTED_EXTENSIONS => c"TWEE".as_ptr(),
        TLS_ST_CR_ENCRYPTED_EXTENSIONS => c"TREE".as_ptr(),
        TLS_ST_CR_CERT_VRFY => c"TRSCV".as_ptr(),
        TLS_ST_SW_CERT_VRFY => c"TWSCV".as_ptr(),
        TLS_ST_CR_HELLO_REQ => c"TRHR".as_ptr(),
        TLS_ST_SW_KEY_UPDATE => c"TWSKU".as_ptr(),
        TLS_ST_CW_KEY_UPDATE => c"TWCKU".as_ptr(),
        TLS_ST_SR_KEY_UPDATE => c"TRCKU".as_ptr(),
        TLS_ST_CR_KEY_UPDATE => c"TRSKU".as_ptr(),
        TLS_ST_EARLY_DATA => c"TED".as_ptr(),
        TLS_ST_PENDING_EARLY_DATA_END => c"TPEDE".as_ptr(),
        TLS_ST_CW_END_OF_EARLY_DATA => c"TWEOED".as_ptr(),
        TLS_ST_SR_END_OF_EARLY_DATA => c"TWEOED".as_ptr(),
        _ => c"UNKWN".as_ptr(),
    }
}

/// `const char *SSL_alert_type_string_long(int value)` — `ssl/ssl_stat.c:249-259`.
#[no_mangle]
pub extern "C" fn SSL_alert_type_string_long(value: c_int) -> *const c_char {
    match value >> 8 {
        SSL3_AL_WARNING => c"warning".as_ptr(),
        SSL3_AL_FATAL => c"fatal".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}

/// `const char *SSL_alert_type_string(int value)` — `ssl/ssl_stat.c:261-271`.
#[no_mangle]
pub extern "C" fn SSL_alert_type_string(value: c_int) -> *const c_char {
    match value >> 8 {
        SSL3_AL_WARNING => c"W".as_ptr(),
        SSL3_AL_FATAL => c"F".as_ptr(),
        _ => c"U".as_ptr(),
    }
}

/// `const char *SSL_alert_desc_string(int value)` — `ssl/ssl_stat.c:273-339`.
#[no_mangle]
pub extern "C" fn SSL_alert_desc_string(value: c_int) -> *const c_char {
    match value & 0xff {
        SSL3_AD_CLOSE_NOTIFY => c"CN".as_ptr(),
        SSL3_AD_UNEXPECTED_MESSAGE => c"UM".as_ptr(),
        SSL3_AD_BAD_RECORD_MAC => c"BM".as_ptr(),
        SSL3_AD_DECOMPRESSION_FAILURE => c"DF".as_ptr(),
        SSL3_AD_HANDSHAKE_FAILURE => c"HF".as_ptr(),
        SSL3_AD_NO_CERTIFICATE => c"NC".as_ptr(),
        SSL3_AD_BAD_CERTIFICATE => c"BC".as_ptr(),
        SSL3_AD_UNSUPPORTED_CERTIFICATE => c"UC".as_ptr(),
        SSL3_AD_CERTIFICATE_REVOKED => c"CR".as_ptr(),
        SSL3_AD_CERTIFICATE_EXPIRED => c"CE".as_ptr(),
        SSL3_AD_CERTIFICATE_UNKNOWN => c"CU".as_ptr(),
        SSL3_AD_ILLEGAL_PARAMETER => c"IP".as_ptr(),
        TLS1_AD_DECRYPTION_FAILED => c"DC".as_ptr(),
        TLS1_AD_RECORD_OVERFLOW => c"RO".as_ptr(),
        TLS1_AD_UNKNOWN_CA => c"CA".as_ptr(),
        TLS1_AD_ACCESS_DENIED => c"AD".as_ptr(),
        TLS1_AD_DECODE_ERROR => c"DE".as_ptr(),
        TLS1_AD_DECRYPT_ERROR => c"CY".as_ptr(),
        TLS1_AD_EXPORT_RESTRICTION => c"ER".as_ptr(),
        TLS1_AD_PROTOCOL_VERSION => c"PV".as_ptr(),
        TLS1_AD_INSUFFICIENT_SECURITY => c"IS".as_ptr(),
        TLS1_AD_INTERNAL_ERROR => c"IE".as_ptr(),
        TLS1_AD_USER_CANCELLED => c"US".as_ptr(),
        TLS1_AD_NO_RENEGOTIATION => c"NR".as_ptr(),
        TLS1_AD_UNSUPPORTED_EXTENSION => c"UE".as_ptr(),
        TLS1_AD_CERTIFICATE_UNOBTAINABLE => c"CO".as_ptr(),
        TLS1_AD_UNRECOGNIZED_NAME => c"UN".as_ptr(),
        TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE => c"BR".as_ptr(),
        TLS1_AD_BAD_CERTIFICATE_HASH_VALUE => c"BH".as_ptr(),
        TLS1_AD_UNKNOWN_PSK_IDENTITY => c"UP".as_ptr(),
        _ => c"UK".as_ptr(),
    }
}

/// `const char *SSL_alert_desc_string_long(int value)` — `ssl/ssl_stat.c:341-409`.
#[no_mangle]
pub extern "C" fn SSL_alert_desc_string_long(value: c_int) -> *const c_char {
    match value & 0xff {
        SSL3_AD_CLOSE_NOTIFY => c"close notify".as_ptr(),
        SSL3_AD_UNEXPECTED_MESSAGE => c"unexpected message".as_ptr(),
        SSL3_AD_BAD_RECORD_MAC => c"bad record mac".as_ptr(),
        SSL3_AD_DECOMPRESSION_FAILURE => c"decompression failure".as_ptr(),
        SSL3_AD_HANDSHAKE_FAILURE => c"handshake failure".as_ptr(),
        SSL3_AD_NO_CERTIFICATE => c"no certificate".as_ptr(),
        SSL3_AD_BAD_CERTIFICATE => c"bad certificate".as_ptr(),
        SSL3_AD_UNSUPPORTED_CERTIFICATE => c"unsupported certificate".as_ptr(),
        SSL3_AD_CERTIFICATE_REVOKED => c"certificate revoked".as_ptr(),
        SSL3_AD_CERTIFICATE_EXPIRED => c"certificate expired".as_ptr(),
        SSL3_AD_CERTIFICATE_UNKNOWN => c"certificate unknown".as_ptr(),
        SSL3_AD_ILLEGAL_PARAMETER => c"illegal parameter".as_ptr(),
        TLS1_AD_DECRYPTION_FAILED => c"decryption failed".as_ptr(),
        TLS1_AD_RECORD_OVERFLOW => c"record overflow".as_ptr(),
        TLS1_AD_UNKNOWN_CA => c"unknown CA".as_ptr(),
        TLS1_AD_ACCESS_DENIED => c"access denied".as_ptr(),
        TLS1_AD_DECODE_ERROR => c"decode error".as_ptr(),
        TLS1_AD_DECRYPT_ERROR => c"decrypt error".as_ptr(),
        TLS1_AD_EXPORT_RESTRICTION => c"export restriction".as_ptr(),
        TLS1_AD_PROTOCOL_VERSION => c"protocol version".as_ptr(),
        TLS1_AD_INSUFFICIENT_SECURITY => c"insufficient security".as_ptr(),
        TLS1_AD_INTERNAL_ERROR => c"internal error".as_ptr(),
        TLS1_AD_USER_CANCELLED => c"user canceled".as_ptr(),
        TLS1_AD_NO_RENEGOTIATION => c"no renegotiation".as_ptr(),
        TLS1_AD_UNSUPPORTED_EXTENSION => c"unsupported extension".as_ptr(),
        TLS1_AD_CERTIFICATE_UNOBTAINABLE => c"certificate unobtainable".as_ptr(),
        TLS1_AD_UNRECOGNIZED_NAME => c"unrecognized name".as_ptr(),
        TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE => c"bad certificate status response".as_ptr(),
        TLS1_AD_BAD_CERTIFICATE_HASH_VALUE => c"bad certificate hash value".as_ptr(),
        TLS1_AD_UNKNOWN_PSK_IDENTITY => c"unknown PSK identity".as_ptr(),
        TLS1_AD_NO_APPLICATION_PROTOCOL => c"no application protocol".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}
