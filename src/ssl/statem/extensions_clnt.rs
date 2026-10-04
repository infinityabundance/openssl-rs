//! Phase 17.2a — `ssl/statem/extensions_clnt.c` and `extensions.c`'s client-hello half: the
//! extension block `tls_construct_client_hello` writes, reduced to the initial flight.
//!
//! The authority's extension framework is table-driven: `tls_construct_extensions`
//! (`ssl/statem/extensions.c:803-878`) walks the static `ext_defs[]` (`extensions.c:143-...`), asks
//! `should_add_extension` whether a row belongs in the current context, and calls the row's
//! `construct_ctos` client callback. This module lands the framework for the `SSL_EXT_CLIENT_HELLO`
//! context and the five client constructors whose bodies depend only on the connection's own
//! options, so the initial flight carries a real extension block instead of an empty one.
//!
//! ## What is landed, and the boundary each remaining name is named at
//!
//! Landed: `tls_construct_extensions`'s `WPACKET_start_sub_packet_u16`/`WPACKET_close` shell with
//! the `WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH` flag the authority sets for a ClientHello, and the
//! constructors for `supported_versions`, `psk_kex_modes`, `encrypt_then_mac`,
//! `extended_master_secret` and `session_ticket`, each transcribed from its `extensions_clnt.c`
//! body. **17.2b** adds `supported_groups` and `key_share` (the `X25519` share, generated through
//! the crate's EVP) over the reduced built-in default group list (`ssl/t1_lib.rs`).
//!
//! Named boundaries (not fabricated):
//!
//! * **`renegotiation_info` and `ec_point_formats` are not constructed.** Their constructors need
//!   the effective security level's version arm (`ssl_security(s, SSL_SECOP_VERSION, ...)`, whose
//!   candidate callback `ssl_lib.rs` reduces to `1`) and the supported-group list's policy walk, so
//!   a faithful body cannot be produced yet. They are named here rather than guessed.
//! * **`signature_algorithms` is not constructed.** It needs the client sigalg list
//!   (`tls12_get_psigalgs`), which is unlanded; the flight cannot reach `Finished` without it.
//! * **The `key_share` body is reduced.** The authority's default group list marks `X25519MLKEM768`
//!   and `X25519` for a key share; the hybrid KEM is the key-schedule boundary, so only the `X25519`
//!   share is built. The `ssl_derive`/key-schedule step the authority's constructor ends with is
//!   not called.
//! * **`session_ticket` is reduced.** `tls_use_ticket` (`ssl/statem/statem_lib.c`) is unlanded; the
//!   constructor keeps the authority's `SSL_OP_NO_TICKET` guard and the empty-ticket body a fresh
//!   connection without a resumption ticket produces.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;
use core::ptr;

use crate::packet::{
    WPACKET_close, WPACKET_memcpy, WPACKET_put_bytes_u16, WPACKET_put_bytes_u8, WPACKET_set_flags,
    WPACKET_start_sub_packet_len__, Wpacket, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH,
    WPACKET_FLAGS_NON_ZERO_LENGTH,
};
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::statem::statem_lib::ssl_get_min_max_version;
use crate::ssl::t1_lib::{tls1_get_supported_groups, OSSL_TLS_GROUP_ID_x25519};

/// `TLSEXT_TYPE_renegotiate` — `tls1.h:110`.
#[allow(dead_code)]
const TLSEXT_TYPE_RENEGOTIATE: u16 = 0xff01;
/// `TLSEXT_TYPE_ec_point_formats` — `tls1.h:104`.
#[allow(dead_code)]
const TLSEXT_TYPE_EC_POINT_FORMATS: u16 = 11;
/// `TLSEXT_TYPE_session_ticket` — `tls1.h` (35).
const TLSEXT_TYPE_SESSION_TICKET: u16 = 35;
/// `TLSEXT_TYPE_encrypt_then_mac` — `tls1.h:106`.
const TLSEXT_TYPE_ENCRYPT_THEN_MAC: u16 = 22;
/// `TLSEXT_TYPE_extended_master_secret` — `tls1.h:107`.
const TLSEXT_TYPE_EXTENDED_MASTER_SECRET: u16 = 23;
/// `TLSEXT_TYPE_supported_versions` — `tls1.h:161`.
const TLSEXT_TYPE_SUPPORTED_VERSIONS: u16 = 43;
/// `TLSEXT_TYPE_psk_kex_modes` — `tls1.h:165`.
const TLSEXT_TYPE_PSK_KEX_MODES: u16 = 45;
/// `TLSEXT_TYPE_supported_groups` — `tls1.h:143`.
const TLSEXT_TYPE_SUPPORTED_GROUPS: u16 = 10;
/// `TLSEXT_TYPE_key_share` — `tls1.h:165`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;

/// `TLS1_3_VERSION` — `ssl3.h`.
const TLS1_3_VERSION: c_int = 0x0304;
/// `TLS1_VERSION` — `ssl3.h`.
#[allow(dead_code)]
const TLS1_VERSION: c_int = 0x0301;
/// `SSL_SECOP_VERSION` — `ssl.h:2718`.
#[allow(dead_code)]
const SSL_SECOP_VERSION: c_int = 1;

/// `TLSEXT_KEX_MODE_KE_DHE` — `tls1.h` (the `psk_dhe_ke` mode).
const TLSEXT_KEX_MODE_KE_DHE: u8 = 1;

/// `SSL_OP_NO_ENCRYPT_THEN_MAC` — `ssl.h`.
const SSL_OP_NO_ENCRYPT_THEN_MAC: u64 = 524_288;
/// `SSL_OP_NO_EXTENDED_MASTER_SECRET` — `ssl.h`.
const SSL_OP_NO_EXTENDED_MASTER_SECRET: u64 = 1;
/// `SSL_OP_NO_TICKET` — `ssl.h`.
const SSL_OP_NO_TICKET: u64 = 16_384;

/// `EXT_RETURN_NOT_SENT`.
const EXT_RETURN_NOT_SENT: c_int = 0;
/// `EXT_RETURN_SENT`.
const EXT_RETURN_SENT: c_int = 1;
/// `EXT_RETURN_FAIL`.
const EXT_RETURN_FAIL: c_int = -1;

/// `EXT_RETURN tls_construct_ctos_supported_versions(...)` — `extensions_clnt.c:570-608`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_supported_versions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    let mut min_version: c_int = 0;
    let mut max_version: c_int = 0;

    // SAFETY: `s` is live; the out-pointers are live locals.
    if unsafe { ssl_get_min_max_version(s, &mut min_version, &mut max_version, ptr::null_mut()) }
        != 0
    {
        return EXT_RETURN_FAIL;
    }

    if max_version < TLS1_3_VERSION {
        return EXT_RETURN_NOT_SENT;
    }

    // SAFETY: `pkt` is live. `WPACKET_put_bytes_u16` + two `start_sub_packet`s of 2 and 1 bytes are
    // `WPACKET_put_bytes_u16`/`WPACKET_start_sub_packet_u16`/`WPACKET_start_sub_packet_u8`.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_SUPPORTED_VERSIONS) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_start_sub_packet_len__(pkt, 1) == 0
        {
            return EXT_RETURN_FAIL;
        }
        let mut currv = max_version;
        while currv >= min_version {
            if WPACKET_put_bytes_u16(pkt, currv as u16) == 0 {
                return EXT_RETURN_FAIL;
            }
            currv -= 1;
        }
        if WPACKET_close(pkt) == 0 || WPACKET_close(pkt) == 0 {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_ctos_psk_kex_modes(...)` — `extensions_clnt.c:613-639`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_psk_kex_modes(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live.
    let nodhe = unsafe { (*s).options } & crate::ssl::ssl_ciph_table::SSL_OP_ALLOW_NO_DHE_KEX != 0;

    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_PSK_KEX_MODES) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_start_sub_packet_len__(pkt, 1) == 0
            || WPACKET_put_bytes_u8(pkt, TLSEXT_KEX_MODE_KE_DHE) == 0
            || (nodhe && WPACKET_put_bytes_u8(pkt, 0) == 0)
            || WPACKET_close(pkt) == 0
            || WPACKET_close(pkt) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_ctos_supported_groups(...)` — `extensions_clnt.c:214-281`.
///
/// The `use_ecc` gate is reduced to "the default group list is non-empty" (this stratum has no
/// `tls_valid_group`/`SSL_get1_supported_ciphers` walk).
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_supported_groups(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live.
    let groups = unsafe { tls1_get_supported_groups(s) };
    if groups.is_empty() {
        return EXT_RETURN_NOT_SENT;
    }

    // SAFETY: `pkt` is live. `start_sub_packet_u16` is `start_sub_packet_len__(pkt, 2)`.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_SUPPORTED_GROUPS) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_set_flags(pkt, WPACKET_FLAGS_NON_ZERO_LENGTH) == 0
        {
            return EXT_RETURN_FAIL;
        }
        for g in groups {
            if WPACKET_put_bytes_u16(pkt, *g) == 0 {
                return EXT_RETURN_FAIL;
            }
        }
        if WPACKET_close(pkt) == 0 || WPACKET_close(pkt) == 0 {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_ctos_key_share(...)` — `extensions_clnt.c:701-...`, reduced to the
/// single `X25519` share the reduced default group list requests.
///
/// The authority sends a share for every group marked `*` in the group list (`X25519MLKEM768` and
/// `X25519`); the hybrid share is the key-schedule boundary named in the module header, so only the
/// `X25519` share is built. The key is generated through the crate's EVP (`evp_pkey_keygen`), which
/// is what `ssl_generate_pkey` (`ssl/ssl_rsa.c`/`t1_lib.c`) does.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_key_share(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    use crate::evp::pkey::{evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
    use crate::runtime::mem::CRYPTO_free;

    let group = OSSL_TLS_GROUP_ID_x25519;
    // SAFETY: `s` is live; `ctx` is the connection's context.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq) };
    let mut params = [crate::params::END; 1];
    // SAFETY: `libctx`/`propq` are the context's; the name is NUL-terminated; `params` is a
    // terminated array.
    let pkey = unsafe { evp_pkey_keygen(libctx, c"X25519".as_ptr(), propq, params.as_mut_ptr()) };
    if pkey.is_null() {
        return EXT_RETURN_FAIL;
    }
    let mut pub_ = core::ptr::null_mut::<u8>();
    // SAFETY: `pkey` is live; `pub_` is this frame's writable slot.
    let publen = unsafe { EVP_PKEY_get1_encoded_public_key(pkey, &mut pub_) };
    if publen == 0 {
        // SAFETY: `pkey` is live and this call owns it.
        unsafe { EVP_PKEY_free(pkey) };
        return EXT_RETURN_FAIL;
    }

    // SAFETY: `pkt` is live and `pub_` is `publen` readable bytes.
    let ret = unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_KEY_SHARE) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_put_bytes_u16(pkt, group) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_memcpy(pkt, pub_.cast(), publen) == 0
            || WPACKET_close(pkt) == 0
            || WPACKET_close(pkt) == 0
        {
            EXT_RETURN_FAIL
        } else {
            EXT_RETURN_SENT
        }
    };
    // SAFETY: `pub_` is the block `get1` allocated; the reduced client keeps `pkey` as its
    // ephemeral key share (`s3.tmp.pkey`) so `tls_process_server_hello` can derive the shared
    // secret from it (`ssl_derive`, `s3_lib.c:5474`).
    unsafe {
        CRYPTO_free(pub_.cast(), core::ptr::null(), 0);
        if ret == EXT_RETURN_SENT {
            (*s).pkey = pkey.cast();
        } else {
            EVP_PKEY_free(pkey);
        }
    }
    ret
}

/// `EXT_RETURN tls_construct_ctos_etm(...)` — `extensions_clnt.c:516-532`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_etm(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live.
    if unsafe { (*s).options } & SSL_OP_NO_ENCRYPT_THEN_MAC != 0 {
        return EXT_RETURN_NOT_SENT;
    }
    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ENCRYPT_THEN_MAC) == 0
            || WPACKET_put_bytes_u16(pkt, 0) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_ctos_ems(...)` — `extensions_clnt.c:554-568`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_ems(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live.
    if unsafe { (*s).options } & SSL_OP_NO_EXTENDED_MASTER_SECRET != 0 {
        return EXT_RETURN_NOT_SENT;
    }
    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_EXTENDED_MASTER_SECRET) == 0
            || WPACKET_put_bytes_u16(pkt, 0) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_ctos_session_ticket(...)` — `extensions_clnt.c:283-326`, reduced at
/// `tls_use_ticket`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_ctos_session_ticket(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // `tls_use_ticket(s)` is unlanded; the reachable fresh-connection arm (no resumption ticket,
    // no renegotiation) sends an empty extension unless `SSL_OP_NO_TICKET` is set.
    // SAFETY: `s` is live.
    if unsafe { (*s).options } & SSL_OP_NO_TICKET != 0 {
        return EXT_RETURN_NOT_SENT;
    }
    // SAFETY: `pkt` is live. An empty ticket is the extension's 2-byte zero length.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_SESSION_TICKET) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_close(pkt) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `int tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, SSL_EXT_CLIENT_HELLO, X509 *x,
/// size_t chainidx)` — `ssl/statem/extensions.c:803-878`, for the ClientHello context only.
///
/// The framework shell and the flag are the authority's; the row order is `ext_defs[]`'s. Custom
/// extensions (`custom_ext_add`) and the rows named in the module header as boundaries are not
/// walked.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
pub(crate) unsafe fn tls_construct_extensions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `pkt` is live. `WPACKET_start_sub_packet_u16` is `start_sub_packet_len__(pkt, 2)`.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_set_flags(pkt, WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) == 0
        {
            return 0;
        }
    }

    // `tls_construct_ctos_renegotiate`, `tls_construct_ctos_ec_pt_formats` and
    // `tls_construct_ctos_sig_algs` are named boundaries (module header). The remaining rows, in
    // `ext_defs[]` order.
    let mut ret;
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_supported_groups(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_session_ticket(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_etm(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_ems(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_supported_versions(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_psk_kex_modes(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    ret = unsafe { tls_construct_ctos_key_share(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }

    // SAFETY: `pkt` is live.
    unsafe { WPACKET_close(pkt) }
}
