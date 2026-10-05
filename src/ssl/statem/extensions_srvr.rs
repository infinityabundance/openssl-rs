//! Phase 17.2b — `ssl/statem/extensions_srvr.c`: the server's extension block for the first flight,
//! the ServerHello half.
//!
//! The server walks the same table-driven framework as the client (`extensions.c:803-878`), but
//! `s->server` selects each row's `construct_stoc` callback. This module lands the shell for the
//! `SSL_EXT_TLS1_3_SERVER_HELLO` context and the two constructors a fresh (non-resuming,
//! non-HelloRetryRequest) TLSv1.3 ServerHello carries: `supported_versions` and `key_share`.
//!
//! ## What is landed, and the boundary the remaining names sit on
//!
//! Landed: `tls_construct_extensions`'s `WPACKET_start_sub_packet_u16`/`WPACKET_close` shell with
//! the context flags the authority applies (the `ABANDON_ON_ZERO_LENGTH` flag is only for a
//! ClientHello or TLS1.2 ServerHello, never the TLS1.3 one), `tls_construct_stoc_supported_versions`
//! (`extensions_srvr.c:1924-1942`) and the `HelloRetryRequest == SSL_HRR_NONE`, non-resuming arm of
//! `tls_construct_stoc_key_share` (`extensions_srvr.c:1989-2035`) for an `X25519` group.
//!
//! Named boundaries (not fabricated):
//!
//! * **The HelloRetryRequest arm and the KEM arm of `tls_construct_stoc_key_share` are not built.**
//!   The HRR arm (`:1954-1968`) needs `s->hello_retry_request`, which the reduced state machine
//!   never raises; the KEM arm (`:2036-2073`) needs `ssl_encapsulate`/`ssl_gensecret`, the same
//!   key-schedule boundary the [`crate::ssl::statem::extensions_clnt`] module names. Only the
//!   regular-KEX arm for the `X25519` group runs; a non-`X25519` selection fails rather than
//!   producing a share for a group this stratum cannot generate.
//! * **`ssl_derive` is not called.** The authority's constructor ends by updating the crypto state
//!   (`ssl_derive`, `:2032`); that is `ssl/t1_enc.c`/`tls13_enc.c` and is 17.2's key-schedule
//!   boundary. The share is written and its public key discarded, as the client's constructor does.
//! * **The custom-extension pass (`custom_ext_add`, `:840`) is not walked.** No connection in the
//!   probe installs a custom extension.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::packet::{
    WPACKET_close, WPACKET_memcpy, WPACKET_put_bytes_u16, WPACKET_start_sub_packet_len__, Wpacket,
};
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::t1_lib::OSSL_TLS_GROUP_ID_x25519;

/// `TLSEXT_TYPE_supported_versions` — `tls1.h:151`.
const TLSEXT_TYPE_SUPPORTED_VERSIONS: u16 = 43;
/// `TLSEXT_TYPE_key_share` — `tls1.h:165`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;
/// `TLSEXT_TYPE_pre_shared_key` — `tls1.h:163`.
const TLSEXT_TYPE_PSK: u16 = 41;

/// `SSL_EXT_TLS1_3_SERVER_HELLO` — `ssl.h` (`SSL_EXT_TLS1_3_SERVER_HELLO = 0x80`); the context
/// [`tls_construct_extensions`] builds.
#[allow(dead_code)]
pub(crate) const SSL_EXT_TLS1_3_SERVER_HELLO: c_int = 0x80;

/// `EXT_RETURN_NOT_SENT`.
const EXT_RETURN_NOT_SENT: c_int = 0;
/// `EXT_RETURN_SENT`.
const EXT_RETURN_SENT: c_int = 1;
/// `EXT_RETURN_FAIL`.
const EXT_RETURN_FAIL: c_int = -1;

/// `EXT_RETURN tls_construct_stoc_supported_versions(SSL_CONNECTION *s, WPACKET *pkt,` — `extensions_srvr.c:1924-1942`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_stoc_supported_versions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live.
    let version = unsafe { (*s).version };
    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_SUPPORTED_VERSIONS) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_put_bytes_u16(pkt, version as u16) == 0
            || WPACKET_close(pkt) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `EXT_RETURN tls_construct_stoc_key_share(...)` — `extensions_srvr.c:1989-2035`, the regular-KEX
/// arm for `X25519`.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_stoc_key_share(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    use crate::evp::pkey::{evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
    use crate::runtime::mem::CRYPTO_free;

    // SAFETY: `s` is live.
    let group = unsafe { (*s).group_id };
    if group != OSSL_TLS_GROUP_ID_x25519 {
        // The reduced path only generates an X25519 share (module header).
        return EXT_RETURN_FAIL;
    }
    // SAFETY: `s` is live; `ctx` is the connection's context.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq) };
    let mut params = [crate::params::END; 1];
    // SAFETY: the arguments are the context's; the name is NUL-terminated; `params` is terminated.
    let skey = unsafe { evp_pkey_keygen(libctx, c"X25519".as_ptr(), propq, params.as_mut_ptr()) };
    if skey.is_null() {
        return EXT_RETURN_FAIL;
    }
    let mut pub_ = core::ptr::null_mut::<u8>();
    // SAFETY: `skey` is live; `pub_` is this frame's writable slot.
    let publen = unsafe { EVP_PKEY_get1_encoded_public_key(skey, &mut pub_) };
    if publen == 0 {
        // SAFETY: `skey` is this frame's.
        unsafe { EVP_PKEY_free(skey) };
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
    // SAFETY: `pub_` is the block `get1` allocated; `skey` is the server's ephemeral key share,
    // kept as `s3.tmp.pkey` so the caller's `ssl_derive` can compute the shared secret
    // (`ssl_derive`, `s3_lib.c:5474`; `extensions_srvr.c:2031`).
    unsafe {
        CRYPTO_free(pub_.cast(), core::ptr::null(), 0);
        if ret == EXT_RETURN_SENT {
            (*s).pkey = skey.cast();
        } else {
            EVP_PKEY_free(skey);
        }
    }
    ret
}

/// `EXT_RETURN tls_construct_stoc_psk(...)` — `extensions_srvr.c:1795-1833`, reduced to the single
/// selected identity: the ServerHello `pre_shared_key` extension is
/// `selected_identity(2)` (`extensions_srvr.c:1815-1820`).
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
unsafe fn tls_construct_stoc_psk(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `s` is live. Only a resumed connection selects a PSK identity.
    if unsafe { (*s).hit } == 0 {
        return EXT_RETURN_NOT_SENT;
    }
    // SAFETY: `pkt` is live.
    unsafe {
        if WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_PSK) == 0
            || WPACKET_start_sub_packet_len__(pkt, 2) == 0
            || WPACKET_put_bytes_u16(pkt, 0) == 0
            || WPACKET_close(pkt) == 0
        {
            return EXT_RETURN_FAIL;
        }
    }
    EXT_RETURN_SENT
}

/// `int tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, unsigned int context,` —
/// `ssl/statem/extensions.c:803-878`, for the `SSL_EXT_TLS1_3_SERVER_HELLO` context.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
pub(crate) unsafe fn tls_construct_extensions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    // SAFETY: `pkt` is live. `WPACKET_start_sub_packet_u16` is `start_sub_packet_len__(pkt, 2)`.
    unsafe {
        if WPACKET_start_sub_packet_len__(pkt, 2) == 0 {
            return 0;
        }
    }

    // The rows, in `ext_defs[]` order, that a fresh TLSv1.3 ServerHello carries.
    // SAFETY: live per the contract.
    let ret = unsafe { tls_construct_stoc_supported_versions(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // SAFETY: live per the contract.
    let ret = unsafe { tls_construct_stoc_key_share(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    // `pre_shared_key` (`extensions.c:335`), sent only on a resumed connection.
    // SAFETY: live per the contract.
    let ret = unsafe { tls_construct_stoc_psk(s, pkt) };
    if ret == EXT_RETURN_FAIL {
        return 0;
    }
    let _ = EXT_RETURN_NOT_SENT;

    // SAFETY: `pkt` is live.
    unsafe { WPACKET_close(pkt) }
}
