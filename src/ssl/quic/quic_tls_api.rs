//! Phase 14.10 — `ssl/quic/quic_tls_api.c`: the QUIC TLS accessors.
//!
//! The three rows the plan gives this unit: `SSL_set_quic_tls_cbs`,
//! `SSL_set_quic_tls_transport_params` and `SSL_set_quic_tls_early_data_enabled`. The dispatch walk
//! (`tls_callbacks_from_dispatch`, `quic_tls_api.c:82-125`) and the callback table are transcribed;
//! the object the callbacks would drive (`ossl_quic_tls_new`/`_configure`/`_set_*` in
//! `ssl/quic/quic_tls.c`) is **Phase 15's** (`quic.h`'s exports), so the arm that would build it is
//! reduced.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The complete-dispatch arm is reduced to a refusal.** With a full six-function table the
//!   authority frees the old `qtls` and builds a new one via `ossl_quic_tls_new`/`_configure`
//!   (`quic_tls_api.c:143-167`). Those are Phase 15's, so this crate stores the callbacks and the
//!   argument and leaves `qtls` NULL, answering 0. **`RT-SSL-INIT` drives only the incomplete-table
//!   refusal**, where the authority's own answer is 0.
//! * **`SSL_set_quic_tls_transport_params`/`_early_data_enabled`'s success arms are likewise
//!   reduced.** They need a non-NULL `qtls`, which this crate never builds; the reachable arms are
//!   the NULL/QUIC connection and the NULL-`qtls` refusals, and those are what the court drives.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_void};

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ffi::guard_ffi;
use crate::runtime::err::raise_with;
use crate::ssl::ssl_lib::{SSL_is_quic, SSL_is_tls, Ssl};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/quic/quic_tls_api.c".as_ptr();

/// `ERR_LIB_SSL` — `err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_MISSING_QUIC_TLS_FUNCTIONS` — `sslerr.h:175`.
const SSL_R_MISSING_QUIC_TLS_FUNCTIONS: c_int = 423;
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` — `err.h.in:355` (`257 | ERR_R_FATAL`).
const ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED: c_int = 257 | (3 << 18);

/// `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND` — `core_dispatch.h:258`.
const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND: c_int = 2001;
/// `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD` — `core_dispatch.h:262`.
const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD: c_int = 2002;
/// `OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD` — `core_dispatch.h:266`.
const OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD: c_int = 2003;
/// `OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET` — `core_dispatch.h:269`.
const OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET: c_int = 2004;
/// `OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS` — `core_dispatch.h:273`.
const OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS: c_int = 2005;
/// `OSSL_FUNC_SSL_QUIC_TLS_ALERT` — `core_dispatch.h:277`.
const OSSL_FUNC_SSL_QUIC_TLS_ALERT: c_int = 2006;

/// `OSSL_QUIC_TLS_CALLBACKS` — `quic_tls_api.c`, the per-connection callback table
/// `SSL_set_quic_tls_cbs` fills. The authority stores typed function pointers; this crate stores the
/// generic `void (*)(void)` the dispatch entry carries (as [`OsslDispatch`] does), because the
/// object that would call them is Phase 15's. An all-zero value is the table with every slot NULL,
/// which is what `SSL_new`'s zeroed `Ssl` carries.
#[repr(C)]
pub struct QuicTlsCallbacks {
    /// `crypto_send_cb`.
    pub crypto_send_cb: *mut c_void,
    /// `crypto_recv_rcd_cb`.
    pub crypto_recv_rcd_cb: *mut c_void,
    /// `crypto_release_rcd_cb`.
    pub crypto_release_rcd_cb: *mut c_void,
    /// `yield_secret_cb`.
    pub yield_secret_cb: *mut c_void,
    /// `got_transport_params_cb`.
    pub got_transport_params_cb: *mut c_void,
    /// `alert_cb`.
    pub alert_cb: *mut c_void,
}

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/quic/quic_tls_api.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` one of this file's constants.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `tls_callbacks_from_dispatch` — `quic_tls_api.c:82-125`.
///
/// # Safety
/// `qtcb` must be a live callback table; `qtdis` must point at a NUL-`function_id`-terminated
/// `OSSL_DISPATCH` array.
unsafe fn tls_callbacks_from_dispatch(
    qtcb: *mut QuicTlsCallbacks,
    qtdis: *const OsslDispatch,
) -> bool {
    let mut i: isize = 0;
    loop {
        // SAFETY: the caller guarantees the array is terminated and every entry before the
        // terminator is readable.
        let entry = unsafe { &*qtdis.offset(i) };
        if entry.function_id == OSSL_DISPATCH_END {
            break;
        }
        // SAFETY: `qtcb` is live and `entry` is a readable dispatch entry.
        unsafe {
            match entry.function_id {
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND if (*qtcb).crypto_send_cb.is_null() => {
                    (*qtcb).crypto_send_cb = entry.function;
                }
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD if (*qtcb).crypto_recv_rcd_cb.is_null() => {
                    (*qtcb).crypto_recv_rcd_cb = entry.function;
                }
                OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD
                    if (*qtcb).crypto_release_rcd_cb.is_null() =>
                {
                    (*qtcb).crypto_release_rcd_cb = entry.function;
                }
                OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET if (*qtcb).yield_secret_cb.is_null() => {
                    (*qtcb).yield_secret_cb = entry.function;
                }
                OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS
                    if (*qtcb).got_transport_params_cb.is_null() =>
                {
                    (*qtcb).got_transport_params_cb = entry.function;
                }
                OSSL_FUNC_SSL_QUIC_TLS_ALERT if (*qtcb).alert_cb.is_null() => {
                    (*qtcb).alert_cb = entry.function;
                }
                _ => {}
            }
        }
        i += 1;
    }
    // SAFETY: `qtcb` is live.
    let complete = unsafe {
        !(*qtcb).crypto_send_cb.is_null()
            && !(*qtcb).crypto_recv_rcd_cb.is_null()
            && !(*qtcb).crypto_release_rcd_cb.is_null()
            && !(*qtcb).yield_secret_cb.is_null()
            && !(*qtcb).got_transport_params_cb.is_null()
            && !(*qtcb).alert_cb.is_null()
    };
    if !complete {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_MISSING_QUIC_TLS_FUNCTIONS, 120) };
        return false;
    }
    true
}

/// `int SSL_set_quic_tls_cbs(SSL *s, const OSSL_DISPATCH *qtdis, void *arg)` —
/// `ssl/quic/quic_tls_api.c:127-169`, reduced at its success arm (see the module header).
///
/// # Safety
/// `s` must be NULL or a live connection; `qtdis` a terminated dispatch array; `arg` the callbacks'
/// argument.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_quic_tls_cbs(
    s: *mut Ssl,
    qtdis: *const OsslDispatch,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `SSL_is_tls` accepts NULL.
        if unsafe { SSL_is_tls(s) } == 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 133) };
            return 0;
        }
        // SAFETY: `s` is a live TLS connection and `qtdis` is terminated per the contract.
        if !unsafe { tls_callbacks_from_dispatch(&mut (*s).qtcb, qtdis) } {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).qtarg = arg };
        // The authority frees `sc->qtls` and builds a new one with `ossl_quic_tls_new`/`_configure`
        // (Phase 15's); this crate leaves `qtls` NULL. Recorded in the module header.
        0
    })
}

/// `int SSL_set_quic_tls_transport_params(SSL *s, const unsigned char *params, size_t params_len)` —
/// `ssl/quic/quic_tls_api.c:171-186`, reduced at its success arm.
///
/// # Safety
/// `s` must be NULL or a live connection; `params` holds `params_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_quic_tls_transport_params(
    s: *mut Ssl,
    params: *const u8,
    params_len: usize,
) -> c_int {
    let _ = (params, params_len);
    guard_ffi(0, || {
        // `SSL_CONNECTION_FROM_SSL(s)` is NULL for a QUIC or NULL `s`.
        // SAFETY: `SSL_is_quic` accepts NULL.
        if s.is_null() || unsafe { SSL_is_quic(s) } != 0 {
            return 0;
        }
        // SAFETY: `s` is a live non-QUIC connection.
        if unsafe { (*s).qtls }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 181) };
            return 0;
        }
        // `ossl_quic_tls_set_transport_params` is Phase 15's; `qtls` is never non-NULL here.
        0
    })
}

/// `int SSL_set_quic_tls_early_data_enabled(SSL *s, int enabled)` —
/// `ssl/quic/quic_tls_api.c:188-203`, reduced at its success arm.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_quic_tls_early_data_enabled(s: *mut Ssl, enabled: c_int) -> c_int {
    let _ = enabled;
    guard_ffi(0, || {
        // SAFETY: `SSL_is_tls` accepts NULL.
        if unsafe { SSL_is_tls(s) } == 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 193) };
            return 0;
        }
        // SAFETY: `s` is a live TLS connection.
        if unsafe { (*s).qtls }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 198) };
            return 0;
        }
        // `ossl_quic_tls_set_early_data_enabled` is Phase 15's; `qtls` is never non-NULL here.
        0
    })
}
