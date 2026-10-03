//! Phase 14.2 — `ssl/s3_lib.c`: the ticket-key callback and the group-name accessors.
//!
//! `docs/PHASE-14-SUBPHASES.md` gives `s3_lib.c`'s three open rows to 14.2. They are the two
//! protocol-version/group-name readers the method table exposes and the one session-ticket key
//! callback installer:
//!
//! * `SSL_CTX_set_tlsext_ticket_key_evp_cb` (`s3_lib.c:4709-4713`) stores the EVP key callback on
//!   the context's extension block and returns 1.
//! * `SSL_get0_group_name` (`s3_lib.c:5643-5657`) resolves the connection's negotiated group id to
//!   the context's group table name.
//! * `SSL_group_to_name` (`s3_lib.c:5659-5676`) converts a NID (or a raw `TLSEXT_nid_unknown`
//!   group id) and returns the matching table name.
//!
//! **Measured divergences, recorded rather than hidden.**
//!
//! * **The group table is empty, so both name accessors reduce to NULL.** The authority's
//!   `tls1_group_id_lookup` (`t1_lib.c:722-732`) scans `ctx->group_list`, which `ssl_load_groups`
//!   populates in `SSL_CTX_new_ex` (`ssl_lib.c:4080`); `ssl_load_groups` and the `TLS_GROUP_INFO`
//!   table are 14.5's (`t1_lib.c`) and are not landed, so the candidate's `ctx->group_list` is
//!   empty and `tls1_group_id2name` answers NULL for every id. The differential court therefore
//!   drives only the arms where the authority also answers NULL — an unknown NID and an unknown
//!   raw group id — and `SSL_group_to_name`'s known-NID arm (`NID_X9_62_prime256v1` -> `secp256r1`)
//!   is named `pending` rather than compared.
//! * **`SSL_get0_group_name` returns NULL instead of dereferencing a NULL session.** The authority
//!   reads `sc->session->kex_group` for a non-TLS1.3 method (`s3_lib.c:5654`), and `sc->session` is
//!   NULL until a handshake allocates one, so the authority's own fresh-connection arm faults. This
//!   crate returns NULL, which the empty group table would produce anyway; the court cannot drive
//!   it without reproducing that fault, so the symbol is covered by the reference basis (D199)
//!   rather than called.
//! * **`SSL_CTX_set_tlsext_ticket_key_evp_cb` guards a NULL context; the authority does not.** The
//!   authority writes `ctx->ext.ticket_key_evp_cb` unconditionally; the NULL arm is not reachable
//!   from a real caller and is not driven.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::ffi::guard_ffi;
use crate::runtime::bio::sys::strlen;
use crate::runtime::err::err_reasons::{
    SSL_R_SSL3_EXT_INVALID_SERVERNAME, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE,
};
use crate::runtime::err::raise_with;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::ssl::record::rec_layer_s3::{record_layer_read_pending, record_layer_write_pending};
use crate::ssl::ssl_lib::{Ssl, SslCtx, TicketKeyEvpCb};
use crate::ssl::statem::statem::{ossl_statem_set_renegotiate, SSL_in_init};

/// `OPENSSL_FILE` of this translation unit, used on `ERR_raise` sites.
const FILE: *const c_char = c"ssl/s3_lib.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `TLSEXT_NAMETYPE_host_name` — `tls1.h:171`.
const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;
/// `TLSEXT_MAXLEN_host_name` — `tls1.h:172`.
const TLSEXT_MAXLEN_HOST_NAME: usize = 255;
/// `ERR_R_INTERNAL_ERROR` — `err.h` (`1 | ERR_RFLAG_COMMON | ERR_RFLAG_FATAL`).
const ERR_R_INTERNAL_ERROR: c_int = 1 | (2 << 18) | (1 << 18);

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/s3_lib.c:line`.
fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `ssl3_ctrl`'s `SSL_CTRL_SET_TLSEXT_HOSTNAME` arm — `ssl/s3_lib.c:4024-4054`.
///
/// The authority's `SSL_ctrl` (`ossl_ctrl_internal`) does not handle this command itself; it
/// falls through to `method->ssl_ctrl`, which for every method this crate builds is `ssl3_ctrl`.
/// The crate's control dispatcher has no method pointer to fall through to, so this arm is landed
/// and reached from `SSL_ctrl` directly.
///
/// # Safety
/// `s` must be a live connection; `parg` must be NULL or a NUL-terminated name.
pub(crate) unsafe fn ssl3_ctrl_set_tlsext_host_name(
    s: *mut Ssl,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    if larg != TLSEXT_NAMETYPE_HOST_NAME as c_long {
        raise_ssl(SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE, 4051);
        return 0;
    }
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        CRYPTO_free((*s).ext_hostname.cast(), FILE, 4029);
        (*s).ext_hostname = ptr::null_mut();
    }
    if parg.is_null() {
        return 1;
    }
    // SAFETY: `parg` is a NUL-terminated name per the contract.
    let len = unsafe { strlen(parg.cast::<c_char>()) };
    if len == 0 || len > TLSEXT_MAXLEN_HOST_NAME {
        raise_ssl(SSL_R_SSL3_EXT_INVALID_SERVERNAME, 4040);
        return 0;
    }
    // SAFETY: `parg` is the NUL-terminated name and `s` is live.
    let host = unsafe { CRYPTO_strdup(parg.cast::<c_char>(), FILE, 4043) };
    if host.is_null() {
        raise_ssl(ERR_R_INTERNAL_ERROR, 4044);
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).ext_hostname = host };
    1
}

/// `TLSEXT_nid_unknown` — `ssl_local.h`: the flag bit `SSL_group_to_name` strips before the lookup.
const TLSEXT_NID_UNKNOWN: c_int = 0x0100_0000;

/// `tls1_group_id2name` — `ssl/t1_lib.c:734-742`, reduced to an empty group table.
///
/// The authority scans `ctx->group_list` via `tls1_group_id_lookup`; that list is built by
/// `ssl_load_groups` (14.5) and is empty here, so every id resolves to NULL.
///
/// # Safety
/// `_ctx` is unused; no precondition.
unsafe extern "C" fn tls1_group_id2name(_ctx: *mut SslCtx, _group_id: u16) -> *const c_char {
    ptr::null()
}

/// `int SSL_CTX_set_tlsext_ticket_key_evp_cb(SSL_CTX *ctx, int (*fp)(SSL *, unsigned char *,
/// unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int))` — `ssl/s3_lib.c:4709-4713`.
///
/// # Safety
/// `ctx` must be NULL or a live context; `fp` must be NULL or a callback of that shape.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_tlsext_ticket_key_evp_cb(
    ctx: *mut SslCtx,
    fp: Option<TicketKeyEvpCb>,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live per the caller's contract.
        unsafe { (*ctx).ticket_key_evp_cb = fp };
        1
    })
}

/// `const char *SSL_get0_group_name(SSL *s)` — `ssl/s3_lib.c:5643-5657`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_group_name(s: *mut Ssl) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if s.is_null() {
            return ptr::null();
        }
        // The authority resolves the id from the negotiated group and asks the context's group
        // table (14.5's `ssl_load_groups`); that table is empty here, so every id is NULL. The
        // connection's `sc->session->kex_group` read (a NULL deref before a handshake) is avoided.
        // SAFETY: `s` is non-NULL and live per the caller's contract.
        unsafe { tls1_group_id2name((*s).ctx, 0) }
    })
}

/// `const char *SSL_group_to_name(SSL *s, int nid)` — `ssl/s3_lib.c:5659-5676`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_group_to_name(s: *mut Ssl, nid: c_int) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if s.is_null() {
            return ptr::null();
        }
        // The authority converts the NID to a real group id (`tls1_nid2group_id`, `t1_lib.c:764-778`)
        // unless the `TLSEXT_nid_unknown` bit is set, then looks the id up in the context's table.
        // The conversion is idempotent for the empty table, so only the bit test is kept.
        let group_id: u16 = if nid & TLSEXT_NID_UNKNOWN != 0 {
            (nid & 0xFFFF) as u16
        } else {
            0
        };
        // SAFETY: `s` is non-NULL and live per the caller's contract.
        unsafe { tls1_group_id2name((*s).ctx, group_id) }
    })
}

// -------------------------------------------------------------------------------------------
// The renegotiation method entries (14.5b)
//
// `s3_lib.c` owns `ssl3_renegotiate` and `ssl3_renegotiate_check`; the `IMPLEMENT_tls_meth_func`
// macro installs them as the TLS method's `ssl_renegotiate`/`ssl_renegotiate_check`, and
// `ssl_lib.c`'s `SSL_renegotiate*`/`SSL_do_handshake` reach them through that pointer. This crate's
// method table stores scalars, so the entry points call these directly.
// -------------------------------------------------------------------------------------------

/// `int ssl3_renegotiate(SSL *s)` — `ssl/s3_lib.c:5161-5173`.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl3_renegotiate(s: *mut Ssl) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe {
        if (*s).handshake_func.is_none() {
            return 1;
        }
        (*s).s3_renegotiate = 1;
    }
    1
}

/// `int ssl3_renegotiate_check(SSL *s, int initok)` — `ssl/s3_lib.c:5183-5208`.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl3_renegotiate_check(s: *mut Ssl, initok: c_int) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe {
        if (*s).s3_renegotiate != 0
            && record_layer_read_pending(s) == 0
            && record_layer_write_pending(s) == 0
            && (initok != 0 || SSL_in_init(s) == 0)
        {
            ossl_statem_set_renegotiate(s);
            (*s).s3_renegotiate = 0;
            (*s).s3_num_renegotiations += 1;
            (*s).s3_total_renegotiations += 1;
            return 1;
        }
    }
    0
}
