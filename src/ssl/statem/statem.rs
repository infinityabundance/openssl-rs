//! Phase 14.5 — `ssl/statem/statem.c`: the handshake-state readers.
//!
//! The authority's full state machine (`state_machine`, the read/write sub-state machines and the
//! transition table) is not part of this subphase's measured surface: the plan's section 3.5 names
//! the four readers as the observable, and no handshake is driven, so only the fresh-connection
//! state is reachable. The three state words the readers consult live on [`Ssl`] and are installed
//! by `SSL_new` to the authority's post-`SSL_new` values (`ossl_statem_clear` via
//! `ossl_ssl_connection_reset`, `ssl_lib.c:605`/`statem.c:130-136`): `hand_state = TLS_ST_BEFORE`,
//! `state = MSG_FLOW_UNINITED`, `in_init = 1`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **Only the fresh state is reachable.** `SSL_set_accept_state`/`SSL_set_connect_state` and the
//!   handshake entry points that would move `hand_state` are not landed in this subphase, so every
//!   connection reports `TLS_ST_BEFORE`/`in_init = 1`/`in_before = 1`/`is_init_finished = 0` — which
//!   is the authority's own answer for a connection on which no handshake has been started.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::ssl::ssl_lib::Ssl;

/// `TLS_ST_BEFORE` — `ssl.h:1066`, the first `OSSL_HANDSHAKE_STATE`; "no handshake has been
/// initiated yet".
pub const TLS_ST_BEFORE: c_int = 0;
/// `TLS_ST_OK` — `ssl.h:1067`, "a handshake has been successfully completed".
pub const TLS_ST_OK: c_int = 1;
/// `MSG_FLOW_UNINITED` — `internal/statem.h:52`, the first `MSG_FLOW_STATE`; "no handshake in
/// progress".
const MSG_FLOW_UNINITED: c_int = 0;

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
