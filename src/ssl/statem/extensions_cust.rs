//! Phase 14.5 — `ssl/statem/extensions_cust.c`: the custom-extension registration surface.
//!
//! The authority's custom-extension table is a heap array of `custom_ext_method` hanging off
//! `SSL_CTX->cert->custext` (and, per connection, `SSL->cert->custext`). This crate stores the same
//! records in a `Vec<CustomExtMethod>` inside `Cert`; see `src/ssl/ssl_lib.rs` for why.
//!
//! ## What landed
//!
//! * `SSL_extension_supported` — the pure switch over the internally supported extension types.
//! * `SSL_CTX_has_client_custom_ext` — the lookup, with `ENDPOINT_CLIENT` as the role.
//! * `SSL_CTX_add_custom_ext` (modern API, `ENDPOINT_BOTH`) and the two old-style spellings
//!   `SSL_CTX_add_client_custom_ext`/`SSL_CTX_add_server_custom_ext`, through the same
//!   `ossl_tls_add_custom_ext_intern` refusal ladder.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The old-style callback wrappers are not allocated.** The authority's `add_old_custom_ext`
//!   allocates a `custom_ext_add_cb_wrap`/`custom_ext_parse_cb_wrap` pair and registers the
//!   `*_old_cb_wrap` thunks (`extensions_cust.c:32-72`) so a new-style caller can invoke an
//!   old-style callback. No handshake runs in this slice, so the callbacks are never invoked; the
//!   old-style pointers are stored verbatim and nothing is allocated. A caller that fetched the
//!   registered method back would see a different `add_cb`, but the authority exposes no getter for
//!   one, and `SSL_CTX_has_client_custom_ext` — the only reader here — inspects type and role only.
//! * **A NULL `ctx` answers 0 rather than dereferencing it.** `ossl_tls_add_custom_ext_intern`'s
//!   `exts = &ctx->cert->custext` (`extensions_cust.c:416-417`) is an unrestated NULL dereference
//!   for a NULL context; the UB is not reproduced (docs/CUSTODIAN_CONTRACT.md §5's pattern). The
//!   court does not drive the NULL-context arm.
//! * **`ext_flags` is always 0.** `ossl_tls_add_custom_ext_intern` writes `SSL_EXT_FLAG_CONN` only
//!   when `ctx == NULL` (`extensions_cust.c:460`), which this slice refuses before reaching the
//!   store, so the connection arm is unreachable and the flag is not modelled.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)] // the constants are the authority's own C macro spellings

use core::ffi::{c_int, c_uint, c_void};
use core::ptr;

use crate::ssl::ssl_lib::{SSL_CTX_ct_is_enabled, Ssl, SslCtx};
use crate::x509::x_x509::X509;

// -------------------------------------------------------------------------------------------
// The `ENDPOINT` role and `SSL_EXT_*` flags / `TLSEXT_TYPE_*` numbers the unit reads.
// -------------------------------------------------------------------------------------------

/// `ENDPOINT_CLIENT` — `ssl_local.h:2035`.
pub const ENDPOINT_CLIENT: c_int = 0;
/// `ENDPOINT_SERVER` — `ssl_local.h:2036`.
pub const ENDPOINT_SERVER: c_int = 1;
/// `ENDPOINT_BOTH` — `ssl_local.h:2037`.
pub const ENDPOINT_BOTH: c_int = 2;

/// `SSL_EXT_TLS1_2_AND_BELOW_ONLY` — `ssl.h:294`.
const SSL_EXT_TLS1_2_AND_BELOW_ONLY: c_uint = 0x00010;
/// `SSL_EXT_IGNORE_ON_RESUMPTION` — `ssl.h:298`.
const SSL_EXT_IGNORE_ON_RESUMPTION: c_uint = 0x00040;
/// `SSL_EXT_CLIENT_HELLO` — `ssl.h:299`.
const SSL_EXT_CLIENT_HELLO: c_uint = 0x00080;
/// `SSL_EXT_TLS1_2_SERVER_HELLO` — `ssl.h:301`.
const SSL_EXT_TLS1_2_SERVER_HELLO: c_uint = 0x00100;

/// `TLSEXT_TYPE_server_name` — `tls1.h:83`.
const TLSEXT_TYPE_server_name: c_uint = 0;
/// `TLSEXT_TYPE_max_fragment_length` — `tls1.h:84`.
const TLSEXT_TYPE_max_fragment_length: c_uint = 1;
/// `TLSEXT_TYPE_status_request` — `tls1.h:88`.
const TLSEXT_TYPE_status_request: c_uint = 5;
/// `TLSEXT_TYPE_supported_groups` — `tls1.h:102`.
const TLSEXT_TYPE_supported_groups: c_uint = 10;
/// `TLSEXT_TYPE_ec_point_formats` — `tls1.h:104`.
const TLSEXT_TYPE_ec_point_formats: c_uint = 11;
/// `TLSEXT_TYPE_srp` — `tls1.h:107`.
const TLSEXT_TYPE_srp: c_uint = 12;
/// `TLSEXT_TYPE_signature_algorithms` — `tls1.h:110`.
const TLSEXT_TYPE_signature_algorithms: c_uint = 13;
/// `TLSEXT_TYPE_use_srtp` — `tls1.h:113`.
const TLSEXT_TYPE_use_srtp: c_uint = 14;
/// `TLSEXT_TYPE_application_layer_protocol_negotiation` — `tls1.h:116`.
const TLSEXT_TYPE_application_layer_protocol_negotiation: c_uint = 16;
/// `TLSEXT_TYPE_signed_certificate_timestamp` — `tls1.h:122`.
const TLSEXT_TYPE_signed_certificate_timestamp: c_uint = 18;
/// `TLSEXT_TYPE_client_cert_type` — `tls1.h:129`.
const TLSEXT_TYPE_client_cert_type: c_uint = 19;
/// `TLSEXT_TYPE_server_cert_type` — `tls1.h:130`.
const TLSEXT_TYPE_server_cert_type: c_uint = 20;
/// `TLSEXT_TYPE_padding` — `tls1.h:136`.
const TLSEXT_TYPE_padding: c_uint = 21;
/// `TLSEXT_TYPE_encrypt_then_mac` — `tls1.h:139`.
const TLSEXT_TYPE_encrypt_then_mac: c_uint = 22;
/// `TLSEXT_TYPE_extended_master_secret` — `tls1.h:142`.
const TLSEXT_TYPE_extended_master_secret: c_uint = 23;
/// `TLSEXT_TYPE_compress_certificate` — `tls1.h:145`.
const TLSEXT_TYPE_compress_certificate: c_uint = 27;
/// `TLSEXT_TYPE_session_ticket` — `tls1.h:148`.
const TLSEXT_TYPE_session_ticket: c_uint = 35;
/// `TLSEXT_TYPE_psk` — `tls1.h:151`.
const TLSEXT_TYPE_psk: c_uint = 41;
/// `TLSEXT_TYPE_early_data` — `tls1.h:152`.
const TLSEXT_TYPE_early_data: c_uint = 42;
/// `TLSEXT_TYPE_supported_versions` — `tls1.h:153`.
const TLSEXT_TYPE_supported_versions: c_uint = 43;
/// `TLSEXT_TYPE_cookie` — `tls1.h:154`.
const TLSEXT_TYPE_cookie: c_uint = 44;
/// `TLSEXT_TYPE_psk_kex_modes` — `tls1.h:155`.
const TLSEXT_TYPE_psk_kex_modes: c_uint = 45;
/// `TLSEXT_TYPE_certificate_authorities` — `tls1.h:156`.
const TLSEXT_TYPE_certificate_authorities: c_uint = 47;
/// `TLSEXT_TYPE_post_handshake_auth` — `tls1.h:157`.
const TLSEXT_TYPE_post_handshake_auth: c_uint = 49;
/// `TLSEXT_TYPE_key_share` — `tls1.h:159`.
const TLSEXT_TYPE_key_share: c_uint = 51;
/// `TLSEXT_TYPE_next_proto_neg` — `tls1.h:167`.
const TLSEXT_TYPE_next_proto_neg: c_uint = 13172;
/// `TLSEXT_TYPE_renegotiate` — `tls1.h:163`.
const TLSEXT_TYPE_renegotiate: c_uint = 0xff01;

// -------------------------------------------------------------------------------------------
// The callback types (ssl.h:314-342), both spellings.
// -------------------------------------------------------------------------------------------

/// `custom_ext_add_cb` — `ssl.h:314`.
pub type CustomExtAddCb = unsafe extern "C" fn(
    *mut Ssl,
    c_uint,
    *mut *const u8,
    *mut usize,
    *mut c_int,
    *mut c_void,
) -> c_int;
/// `custom_ext_free_cb` — `ssl.h:318`.
pub type CustomExtFreeCb = unsafe extern "C" fn(*mut Ssl, c_uint, *const u8, *mut c_void);
/// `custom_ext_parse_cb` — `ssl.h:321`.
pub type CustomExtParseCb =
    unsafe extern "C" fn(*mut Ssl, c_uint, *const u8, usize, *mut c_int, *mut c_void) -> c_int;
/// `SSL_custom_ext_add_cb_ex` — `ssl.h:325`.
#[allow(clippy::type_complexity)]
pub type SslCustomExtAddCbEx = unsafe extern "C" fn(
    *mut Ssl,
    c_uint,
    c_uint,
    *mut *const u8,
    *mut usize,
    *mut X509,
    usize,
    *mut c_int,
    *mut c_void,
) -> c_int;
/// `SSL_custom_ext_free_cb_ex` — `ssl.h:332`.
pub type SslCustomExtFreeCbEx =
    unsafe extern "C" fn(*mut Ssl, c_uint, c_uint, *const u8, *mut c_void);
/// `SSL_custom_ext_parse_cb_ex` — `ssl.h:337`.
#[allow(clippy::type_complexity)]
pub type SslCustomExtParseCbEx = unsafe extern "C" fn(
    *mut Ssl,
    c_uint,
    c_uint,
    *const u8,
    usize,
    *mut X509,
    usize,
    *mut c_int,
    *mut c_void,
) -> c_int;

// -------------------------------------------------------------------------------------------
// `custom_ext_method` — `ssl_local.h:2046-2058`, the record the table stores.
// -------------------------------------------------------------------------------------------

/// `custom_ext_method` — `ssl_local.h:2046-2058`.
///
/// The callback pointers are kept erased (`*const c_void`) because the old- and new-style APIs
/// register different signatures and this slice never invokes either; erasure keeps one record type
/// for both while preserving the authority's fields, including the NULL tests the refusal ladder
/// performs.
pub struct CustomExtMethod {
    /// `unsigned short ext_type`.
    pub ext_type: c_uint,
    /// `ENDPOINT role`.
    pub role: c_int,
    /// `unsigned int context`.
    pub context: c_uint,
    /// `uint32_t ext_flags`.
    pub ext_flags: c_uint,
    /// `SSL_custom_ext_add_cb_ex add_cb` — erased.
    pub add_cb: *const c_void,
    /// `SSL_custom_ext_free_cb_ex free_cb` — erased.
    pub free_cb: *const c_void,
    /// `void *add_arg`.
    pub add_arg: *mut c_void,
    /// `SSL_custom_ext_parse_cb_ex parse_cb` — erased.
    pub parse_cb: *const c_void,
    /// `void *parse_arg`.
    pub parse_arg: *mut c_void,
}

/// `custom_ext_find` — `ssl/statem/extensions_cust.c:81-98`.
///
/// Returns the index of the first record whose type matches and whose role is compatible with
/// `role` (`role == ENDPOINT_BOTH`, or either side is `ENDPOINT_BOTH`).
fn custom_ext_find(exts: &[CustomExtMethod], role: c_int, ext_type: c_uint) -> Option<usize> {
    exts.iter().position(|m| {
        m.ext_type == ext_type
            && (role == ENDPOINT_BOTH || role == m.role || m.role == ENDPOINT_BOTH)
    })
}

/// `int SSL_extension_supported(unsigned int ext_type)` — `ssl/statem/extensions_cust.c:550-595`.
///
/// The uncompiled `OPENSSL_NO_*` arms are present because the admitted authority build leaves each
/// of `NEXTPROTONEG`, `SRP`, `OCSP`, `CT` and `SRTP` enabled.
#[no_mangle]
pub extern "C" fn SSL_extension_supported(ext_type: c_uint) -> c_int {
    match ext_type {
        TLSEXT_TYPE_application_layer_protocol_negotiation
        | TLSEXT_TYPE_ec_point_formats
        | TLSEXT_TYPE_supported_groups
        | TLSEXT_TYPE_key_share
        | TLSEXT_TYPE_next_proto_neg
        | TLSEXT_TYPE_padding
        | TLSEXT_TYPE_renegotiate
        | TLSEXT_TYPE_max_fragment_length
        | TLSEXT_TYPE_server_name
        | TLSEXT_TYPE_session_ticket
        | TLSEXT_TYPE_signature_algorithms
        | TLSEXT_TYPE_srp
        | TLSEXT_TYPE_status_request
        | TLSEXT_TYPE_signed_certificate_timestamp
        | TLSEXT_TYPE_use_srtp
        | TLSEXT_TYPE_encrypt_then_mac
        | TLSEXT_TYPE_supported_versions
        | TLSEXT_TYPE_extended_master_secret
        | TLSEXT_TYPE_psk_kex_modes
        | TLSEXT_TYPE_cookie
        | TLSEXT_TYPE_early_data
        | TLSEXT_TYPE_certificate_authorities
        | TLSEXT_TYPE_psk
        | TLSEXT_TYPE_post_handshake_auth
        | TLSEXT_TYPE_compress_certificate
        | TLSEXT_TYPE_client_cert_type
        | TLSEXT_TYPE_server_cert_type => 1,
        _ => 0,
    }
}

/// `int SSL_CTX_has_client_custom_ext(const SSL_CTX *ctx, unsigned int ext_type)` —
/// `ssl/statem/extensions_cust.c:391-396`.
///
/// # Safety
/// `ctx` must be NULL or point to a live `SSL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_has_client_custom_ext(
    ctx: *const SslCtx,
    ext_type: c_uint,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL and live; `cert` is non-NULL for a context this crate built.
    let exts = unsafe { &(*(*ctx).cert).custext };
    c_int::from(custom_ext_find(exts, ENDPOINT_CLIENT, ext_type).is_some())
}

/// `ossl_tls_add_custom_ext_intern` — `ssl/statem/extensions_cust.c:398-465`.
///
/// The refusal ladder, in the authority's order: a `free_cb` with no `add_cb`; the SCT/CT
/// conflict; an internally supported type (SCT excepted); a type wider than 16 bits; a duplicate;
/// then the append.
///
/// # Safety
/// `ctx` must be NULL or a live `SSL_CTX`; the callback pointers are stored, never called.
#[allow(clippy::too_many_arguments)] // the authority's own `ossl_tls_add_custom_ext_intern` arity
unsafe fn add_custom_ext_intern(
    ctx: *mut SslCtx,
    role: c_int,
    ext_type: c_uint,
    context: c_uint,
    add_cb: *const c_void,
    free_cb: *const c_void,
    add_arg: *mut c_void,
    parse_cb: *const c_void,
    parse_arg: *mut c_void,
) -> c_int {
    if add_cb.is_null() && !free_cb.is_null() {
        return 0;
    }
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL and live from here on; `SSL_CTX_ct_is_enabled` reads its flag.
    let ct_enabled = unsafe { SSL_CTX_ct_is_enabled(ctx) } != 0;
    if ext_type == TLSEXT_TYPE_signed_certificate_timestamp
        && (context & SSL_EXT_CLIENT_HELLO) != 0
        && ct_enabled
    {
        return 0;
    }
    if SSL_extension_supported(ext_type) != 0
        && ext_type != TLSEXT_TYPE_signed_certificate_timestamp
    {
        return 0;
    }
    if ext_type > 0xffff {
        return 0;
    }
    // SAFETY: `ctx` is live; `cert` is non-NULL for a context this crate built.
    let exts = unsafe { &mut (*(*ctx).cert).custext };
    if custom_ext_find(exts, role, ext_type).is_some() {
        return 0;
    }
    exts.push(CustomExtMethod {
        ext_type,
        role,
        context,
        ext_flags: 0,
        add_cb,
        free_cb,
        add_arg,
        parse_cb,
        parse_arg,
    });
    1
}

/// `int SSL_CTX_add_custom_ext(...)` — `ssl/statem/extensions_cust.c:538-548`.
///
/// # Safety
/// `ctx` must be NULL or a live `SSL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_custom_ext(
    ctx: *mut SslCtx,
    ext_type: c_uint,
    context: c_uint,
    add_cb: Option<SslCustomExtAddCbEx>,
    free_cb: Option<SslCustomExtFreeCbEx>,
    add_arg: *mut c_void,
    parse_cb: Option<SslCustomExtParseCbEx>,
    parse_arg: *mut c_void,
) -> c_int {
    // SAFETY: the pointers are forwarded under this function's contract.
    unsafe {
        add_custom_ext_intern(
            ctx,
            ENDPOINT_BOTH,
            ext_type,
            context,
            add_cb.map_or(ptr::null(), |f| f as *const c_void),
            free_cb.map_or(ptr::null(), |f| f as *const c_void),
            add_arg,
            parse_cb.map_or(ptr::null(), |f| f as *const c_void),
            parse_arg,
        )
    }
}

/// `int SSL_CTX_add_client_custom_ext(...)` — `ssl/statem/extensions_cust.c:510-522`.
///
/// The old-style spelling, with the authority's fixed context mask
/// (`SSL_EXT_TLS1_2_AND_BELOW_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_2_SERVER_HELLO |
/// SSL_EXT_IGNORE_ON_RESUMPTION`).
///
/// # Safety
/// `ctx` must be NULL or a live `SSL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_client_custom_ext(
    ctx: *mut SslCtx,
    ext_type: c_uint,
    add_cb: Option<CustomExtAddCb>,
    free_cb: Option<CustomExtFreeCb>,
    add_arg: *mut c_void,
    parse_cb: Option<CustomExtParseCb>,
    parse_arg: *mut c_void,
) -> c_int {
    // SAFETY: the pointers are forwarded under this function's contract.
    unsafe {
        add_custom_ext_intern(
            ctx,
            ENDPOINT_CLIENT,
            ext_type,
            SSL_EXT_TLS1_2_AND_BELOW_ONLY
                | SSL_EXT_CLIENT_HELLO
                | SSL_EXT_TLS1_2_SERVER_HELLO
                | SSL_EXT_IGNORE_ON_RESUMPTION,
            add_cb.map_or(ptr::null(), |f| f as *const c_void),
            free_cb.map_or(ptr::null(), |f| f as *const c_void),
            add_arg,
            parse_cb.map_or(ptr::null(), |f| f as *const c_void),
            parse_arg,
        )
    }
}

/// `int SSL_CTX_add_server_custom_ext(...)` — `ssl/statem/extensions_cust.c:524-536`.
///
/// As [`SSL_CTX_add_client_custom_ext`], with `ENDPOINT_SERVER`.
///
/// # Safety
/// `ctx` must be NULL or a live `SSL_CTX`.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_server_custom_ext(
    ctx: *mut SslCtx,
    ext_type: c_uint,
    add_cb: Option<CustomExtAddCb>,
    free_cb: Option<CustomExtFreeCb>,
    add_arg: *mut c_void,
    parse_cb: Option<CustomExtParseCb>,
    parse_arg: *mut c_void,
) -> c_int {
    // SAFETY: the pointers are forwarded under this function's contract.
    unsafe {
        add_custom_ext_intern(
            ctx,
            ENDPOINT_SERVER,
            ext_type,
            SSL_EXT_TLS1_2_AND_BELOW_ONLY
                | SSL_EXT_CLIENT_HELLO
                | SSL_EXT_TLS1_2_SERVER_HELLO
                | SSL_EXT_IGNORE_ON_RESUMPTION,
            add_cb.map_or(ptr::null(), |f| f as *const c_void),
            free_cb.map_or(ptr::null(), |f| f as *const c_void),
            add_arg,
            parse_cb.map_or(ptr::null(), |f| f as *const c_void),
            parse_arg,
        )
    }
}
