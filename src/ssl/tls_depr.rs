//! Phase 14.9 — `ssl/tls_depr.c`: the deprecated engine and temporary-DH callback setters.
//!
//! The three rows the plan gives this unit: `SSL_CTX_set_client_cert_engine` (the ENGINE-backed
//! client-certificate method) and the two deprecated temporary-DH callback setters,
//! `SSL_CTX_set_tmp_dh_callback` and `SSL_set_tmp_dh_callback`, which store into
//! `cert->dh_tmp_cb` through `SSL_CTX_callback_ctrl`/`SSL_callback_ctrl` with
//! `SSL_CTRL_SET_TMP_DH_CB`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`SSL_CTX_set_client_cert_engine` stores a borrowed engine.** As the authority does, the
//!   function does not up-ref `e`: it calls `ENGINE_init` (which takes its own structural
//!   reference) and keeps the pointer for the client-certificate handshake path. This crate never
//!   runs that path, so the stored pointer is never dereferenced here.
//! * **The temporary-DH callbacks are stored but not invoked.** The authority's `dh_tmp_cb` is
//!   read only by the temporary-key generation inside a handshake (`ssl_rsa.c`/`t1_lib.c`); no arm
//!   of this stratum's tests drives a handshake, so only the setter's return and the stored pointer
//!   identity are observable.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::dh::Dh;
use crate::engine::eng_init::{ENGINE_finish, ENGINE_init};
use crate::engine::eng_lib::Engine;
use crate::engine::eng_pkey::ENGINE_get_ssl_client_cert_function;
use crate::ffi::guard_ffi;
use crate::runtime::err::raise_with;
use crate::ssl::ssl_lib::{Ssl, SslCtx, SSL_CTRL_SET_TMP_DH_CB};

/// `ERR_LIB_SSL` — `err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_R_ENGINE_LIB` — `err.h:338` (`ERR_LIB_ENGINE /* 38 */ | ERR_RFLAG_COMMON`).
const ERR_R_ENGINE_LIB: c_int = 38 | (2 << 18);
/// `SSL_R_NO_CLIENT_CERT_METHOD` — `sslerr.h:198`.
const SSL_R_NO_CLIENT_CERT_METHOD: c_int = 331;

/// The deprecated `DH *(*)(SSL *, int, int)` temporary-key callback.
pub type TmpDhCb = unsafe extern "C" fn(*mut Ssl, c_int, c_int) -> *mut Dh;

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/tls_depr.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` one of this file's constants.
    unsafe { raise_with(ERR_LIB_SSL, reason, c"ssl/tls_depr.c".as_ptr(), line) };
}

/// `int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e)` — `ssl/tls_depr.c:81-94`.
///
/// # Safety
/// `ctx` must be a live context; `e` a live engine.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_client_cert_engine(ctx: *mut SslCtx, e: *mut Engine) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `e` is a live engine per the caller's contract.
        if unsafe { ENGINE_init(e) } == 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_ENGINE_LIB, 84) };
            return 0;
        }
        // SAFETY: `e` is live and was just initialised.
        if unsafe { ENGINE_get_ssl_client_cert_function(e) }.is_none() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_CLIENT_CERT_METHOD, 88) };
            // SAFETY: `e` is live; undo the `ENGINE_init` above.
            unsafe { ENGINE_finish(e) };
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).client_cert_engine = e };
        1
    })
}

/// `void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, DH *(*dh)(SSL *ssl, int is_export,
/// int keylength))` — `ssl/tls_depr.c:204-209`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_tmp_dh_callback(ctx: *mut SslCtx, dh: Option<TmpDhCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is NULL or live per the caller's contract; the callback pointer is stored
        // verbatim through the control, exactly as the authority casts it.
        unsafe {
            crate::ssl::ssl_lib::SSL_CTX_callback_ctrl(
                ctx,
                SSL_CTRL_SET_TMP_DH_CB,
                dh.map(|f| core::mem::transmute::<_, unsafe extern "C" fn()>(f)),
            );
        }
    })
}

/// `void SSL_set_tmp_dh_callback(SSL *ssl, DH *(*dh)(SSL *ssl, int is_export, int keylength))` —
/// `ssl/tls_depr.c:211-214`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_tmp_dh_callback(ssl: *mut Ssl, dh: Option<TmpDhCb>) {
    guard_ffi((), || {
        // SAFETY: `ssl` is NULL or live per the caller's contract; the pointer is stored verbatim.
        unsafe {
            crate::ssl::ssl_lib::SSL_callback_ctrl(
                ssl,
                SSL_CTRL_SET_TMP_DH_CB,
                dh.map(|f| core::mem::transmute::<_, unsafe extern "C" fn()>(f)),
            );
        }
    })
}
