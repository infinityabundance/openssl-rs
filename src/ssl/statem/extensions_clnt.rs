//! Phase 17.2a — `ssl/statem/extensions_clnt.c` and `extensions.c`'s client-hello half: the
//! extension block `tls_construct_client_hello` writes, reduced to the initial flight.
//!
//! The authority's extension framework is table-driven: `tls_construct_extensions`
//! (`ssl/statem/extensions.c:803-878`) walks the static `ext_defs[]` (`extensions.c:143-...`), asks
//! `should_add_extension` whether a row belongs in the current context, and calls the row's
//! `construct_ctos` client callback. This module lands the framework for the `SSL_EXT_CLIENT_HELLO`
//! context and the client constructors whose bodies depend only on the connection's own options.
//!
//! ## Construction, not parsing
//!
//! This file is the **construction** half only. The authority's client-side parsers
//! (`tls_parse_stoc_*`) and the server's ClientHello readers live in `statem_clnt.rs` /
//! `statem_srvr.rs`; there is no attacker-supplied input here. Every body is written with the
//! shared, bounds-checked [`BytesWriter`] into a scratch block, then copied once into the caller's
//! `WPACKET`, so no extension body performs a raw byte store or an unchecked length write.
//!
//! Named boundaries (not fabricated):
//!
//! * **`supported_groups` is reduced.** The authority's default group list marks `X25519MLKEM768`
//!   and `X25519` for a key share; the hybrid KEM is a later stratum, so the reduced list carries
//!   `X25519` (plus the other named curves) and only the `X25519` share is built.
//! * **`renegotiation_info`/`ec_point_formats` are the authority's non-renegotiating arms.**
//! * **`signature_algorithms` uses the fixed [`CLIENT_SIGALGS`] list** transcribed from the
//!   authority's own ClientHello; `tls12_get_psigalgs`'s policy walk is the boundary.
//! * **`session_ticket` is reduced.** A TLS1.2 resumption offers the session's stored ticket; a
//!   TLS1.3 ticket travels in `pre_shared_key` (a recorded boundary), so the legacy extension is
//!   sent empty.
//! * **`pre_shared_key`, `cookie` and `early_data` are not constructed.** The reduced client has no
//!   PSK/resumption or HRR cookie state, so those `ext_defs[]` rows are named here rather than
//!   emitted.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, CStr};
use core::ptr;

use crate::packet::{WPACKET_memcpy, Wpacket};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::ssl::ssl_lib::{Ssl, TLS1_3_VERSION, TLSEXT_STATUSTYPE_OCSP};
use crate::ssl::statem::statem_lib::ssl_get_min_max_version;
use crate::ssl::statem::statem_srvr::BytesWriter;
use crate::ssl::t1_lib::{tls1_get_supported_groups, OSSL_TLS_GROUP_ID_x25519};

/// `TLSEXT_TYPE_renegotiate` — `tls1.h:110`.
const TLSEXT_TYPE_RENEGOTIATE: u16 = 0xff01;
/// `TLSEXT_TYPE_ec_point_formats` — `tls1.h:104`.
const TLSEXT_TYPE_EC_POINT_FORMATS: u16 = 11;
/// `TLSEXT_TYPE_signature_algorithms` — `tls1.h:96`.
const TLSEXT_TYPE_SIGNATURE_ALGORITHMS: u16 = 13;
/// `TLSEXT_TYPE_session_ticket` — `tls1.h` (35).
const TLSEXT_TYPE_SESSION_TICKET: u16 = 35;
/// `TLSEXT_TYPE_encrypt_then_mac` — `tls1.h:106`.
const TLSEXT_TYPE_ENCRYPT_THEN_MAC: u16 = 22;
/// `TLSEXT_TYPE_extended_master_secret` — `tls1.h:107`.
const TLSEXT_TYPE_EXTENDED_MASTER_SECRET: u16 = 23;
/// `TLSEXT_TYPE_supported_versions` — `tls1.h:161`.
const TLSEXT_TYPE_SUPPORTED_VERSIONS: u16 = 43;
/// `TLSEXT_TYPE_post_handshake_auth` — `tls1.h:157`.
const TLSEXT_TYPE_POST_HANDSHAKE_AUTH: u16 = 49;
/// `TLSEXT_TYPE_psk_kex_modes` — `tls1.h:165`.
const TLSEXT_TYPE_PSK_KEX_MODES: u16 = 45;
/// `TLSEXT_TYPE_supported_groups` — `tls1.h:143`.
const TLSEXT_TYPE_SUPPORTED_GROUPS: u16 = 10;
/// `TLSEXT_TYPE_key_share` — `tls1.h:165`.
const TLSEXT_TYPE_KEY_SHARE: u16 = 51;
/// `TLSEXT_TYPE_server_name` — `tls1.h:140`.
const TLSEXT_TYPE_SERVERNAME: u16 = 0;
/// `TLSEXT_NAMETYPE_host_name` — `tls1.h:171`.
const TLSEXT_NAMETYPE_HOST_NAME: u8 = 0;
/// `TLSEXT_TYPE_status_request` — `tls1.h:88`.
const TLSEXT_TYPE_STATUS_REQUEST: u16 = 5;
/// `TLSEXT_TYPE_application_layer_protocol_negotiation` — `tls1.h:116`.
const TLSEXT_TYPE_ALPN: u16 = 16;

/// The authority's default client signature-algorithm list (`tls12_get_psigalgs`,
/// `ssl/t1_lib.c`), in the authority's wire order.
pub(crate) const CLIENT_SIGALGS: [u16; 26] = [
    0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x081a, 0x081b, 0x081c, 0x0809,
    0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402,
    0x0502, 0x0602,
];

/// `TLSEXT_KEX_MODE_KE_DHE` — `tls1.h` (the `psk_dhe_ke` mode).
const TLSEXT_KEX_MODE_KE_DHE: u8 = 1;

/// `SSL_OP_NO_ENCRYPT_THEN_MAC` — `ssl.h`.
const SSL_OP_NO_ENCRYPT_THEN_MAC: u64 = 524_288;
/// `SSL_OP_NO_EXTENDED_MASTER_SECRET` — `ssl.h`.
const SSL_OP_NO_EXTENDED_MASTER_SECRET: u64 = 1;
/// `SSL_OP_NO_TICKET` — `ssl.h`.
const SSL_OP_NO_TICKET: u64 = 16_384;

/// Scratch extent for the built extension block. The reduced client's extension set is far
/// smaller than a ClientHello record, and the caller's own packet is 4 KiB.
const EXT_SCRATCH: usize = 4096;
/// The reduced group table bound the fixed body buffer can encode.
const MAX_GROUPS: usize = 255;
/// The reduced X25519 public key bound the fixed key-share body can encode.
const MAX_KEY_SHARE: usize = 128;

/// `type || length(2) || body`, the authority's `WPACKET_put_bytes_u16` +
/// `WPACKET_start_sub_packet_u16` + payload + `WPACKET_close` shape.
fn put_extension(w: &mut BytesWriter<'_>, ext_type: u16, body: &[u8]) -> bool {
    w.put_u16(ext_type) && w.put_u16_len_prefixed(body)
}

/// `status_request` body: `status_type=ocsp || responder_id_list<0..2^16-1> ||
/// request_extensions<0..2^16-1>`, both lists empty.
fn write_status_request(w: &mut BytesWriter<'_>) -> bool {
    let body = [TLSEXT_STATUSTYPE_OCSP as u8, 0, 0, 0, 0];
    put_extension(w, TLSEXT_TYPE_STATUS_REQUEST, &body)
}

/// `server_name` body: `server_name_list<1..2^16-1>` holding one `host_name`.
fn write_server_name(w: &mut BytesWriter<'_>, host: &[u8]) -> bool {
    if host.is_empty() || host.len() > u8::MAX as usize {
        return false;
    }
    let mut body = [0u8; 2 + 1 + 2 + u8::MAX as usize];
    let inner_len = {
        let mut b = BytesWriter::new(&mut body[2..]);
        if !(b.put_u8(TLSEXT_NAMETYPE_HOST_NAME) && b.put_u16_len_prefixed(host)) {
            return false;
        }
        b.written()
    };
    let Ok(inner_len16) = u16::try_from(inner_len) else {
        return false;
    };
    body[..2].copy_from_slice(&inner_len16.to_be_bytes());
    put_extension(w, TLSEXT_TYPE_SERVERNAME, &body[..2 + inner_len])
}

/// `alpn` body: `ProtocolNameList<2..2^16-1>`; `alpn` is the already length-prefixed list.
fn write_alpn(w: &mut BytesWriter<'_>, alpn: &[u8]) -> bool {
    let Ok(list_len) = u16::try_from(alpn.len()) else {
        return false;
    };
    let Ok(ext_len) = u16::try_from(alpn.len() + 2) else {
        return false;
    };
    w.put_u16(TLSEXT_TYPE_ALPN) && w.put_u16(ext_len) && w.put_u16(list_len) && w.put_bytes(alpn)
}

/// `supported_versions` body: a one-byte vector of versions, highest first.
fn write_supported_versions(w: &mut BytesWriter<'_>, min: c_int, max: c_int) -> bool {
    if max < TLS1_3_VERSION || min > max {
        return false;
    }
    let count = match (max - min).checked_add(1) {
        Some(n) if n > 0 && n <= 127 => n as usize,
        _ => return false,
    };
    let mut body = [0u8; 1 + u8::MAX as usize * 2];
    body[0] = (count * 2) as u8;
    let mut p = 1usize;
    let mut v = max;
    loop {
        let Ok(v16) = u16::try_from(v) else {
            return false;
        };
        body[p..p + 2].copy_from_slice(&v16.to_be_bytes());
        p += 2;
        if v == min {
            break;
        }
        v -= 1;
    }
    put_extension(w, TLSEXT_TYPE_SUPPORTED_VERSIONS, &body[..p])
}

/// `psk_key_exchange_modes` body: `ke_modes<1..255>`, always `psk_dhe_ke` and optionally `psk_ke`.
fn write_psk_kex_modes(w: &mut BytesWriter<'_>, nodhe: bool) -> bool {
    let body = if nodhe {
        [2, TLSEXT_KEX_MODE_KE_DHE, 0]
    } else {
        [1, TLSEXT_KEX_MODE_KE_DHE, 0]
    };
    put_extension(w, TLSEXT_TYPE_PSK_KEX_MODES, &body[..1 + body[0] as usize])
}

/// `renegotiation_info` body: an empty `renegotiated_connection<0..255>`.
fn write_renegotiate(w: &mut BytesWriter<'_>) -> bool {
    put_extension(w, TLSEXT_TYPE_RENEGOTIATE, &[0])
}

/// `ec_point_formats` body: the single uncompressed point format.
fn write_ec_pt_formats(w: &mut BytesWriter<'_>) -> bool {
    put_extension(w, TLSEXT_TYPE_EC_POINT_FORMATS, &[1, 0])
}

/// `signature_algorithms` body: `supported_signature_algorithms<2..2^16-2>`.
fn write_sig_algs(w: &mut BytesWriter<'_>, algs: &[u16]) -> bool {
    let Some(bytes) = algs.len().checked_mul(2) else {
        return false;
    };
    if algs.is_empty() || algs.len() > 26 || bytes > u16::MAX as usize {
        return false;
    }
    let mut body = [0u8; 2 + 2 * 26];
    let mut data = BytesWriter::new(&mut body[2..]);
    for a in algs {
        if !data.put_u16(*a) {
            return false;
        }
    }
    let written = data.written();
    body[..2].copy_from_slice(&(written as u16).to_be_bytes());
    put_extension(w, TLSEXT_TYPE_SIGNATURE_ALGORITHMS, &body[..2 + written])
}

/// `supported_groups` body: `named_group_list<2..2^16-1>`, in the connection's order.
fn write_supported_groups(w: &mut BytesWriter<'_>, groups: &[u16]) -> bool {
    if groups.is_empty() || groups.len() > MAX_GROUPS {
        return false;
    }
    let mut body = [0u8; 2 + MAX_GROUPS * 2];
    let mut data = BytesWriter::new(&mut body[2..]);
    for g in groups {
        if !data.put_u16(*g) {
            return false;
        }
    }
    let written = data.written();
    body[..2].copy_from_slice(&(written as u16).to_be_bytes());
    put_extension(w, TLSEXT_TYPE_SUPPORTED_GROUPS, &body[..2 + written])
}

/// `key_share` body: `KeyShareClientHello` holding one `KeyShareEntry`.
fn write_key_share(w: &mut BytesWriter<'_>, group: u16, key: &[u8]) -> bool {
    if key.is_empty() || key.len() > MAX_KEY_SHARE {
        return false;
    }
    let mut body = [0u8; 2 + 2 + 2 + MAX_KEY_SHARE];
    let inner_len = {
        let mut b = BytesWriter::new(&mut body[2..]);
        if !(b.put_u16(group) && b.put_u16_len_prefixed(key)) {
            return false;
        }
        b.written()
    };
    body[..2].copy_from_slice(&(inner_len as u16).to_be_bytes());
    put_extension(w, TLSEXT_TYPE_KEY_SHARE, &body[..2 + inner_len])
}

/// `post_handshake_auth` body: empty.
fn write_post_handshake_auth(w: &mut BytesWriter<'_>) -> bool {
    w.put_u16(TLSEXT_TYPE_POST_HANDSHAKE_AUTH) && w.put_u16(0)
}

/// `encrypt_then_mac` body: empty.
fn write_etm(w: &mut BytesWriter<'_>) -> bool {
    w.put_u16(TLSEXT_TYPE_ENCRYPT_THEN_MAC) && w.put_u16(0)
}

/// `extended_master_secret` body: empty.
fn write_ems(w: &mut BytesWriter<'_>) -> bool {
    w.put_u16(TLSEXT_TYPE_EXTENDED_MASTER_SECRET) && w.put_u16(0)
}

/// `session_ticket` body: the stored ticket, or an empty body for a fresh session.
fn write_session_ticket(w: &mut BytesWriter<'_>, ticket: &[u8]) -> bool {
    put_extension(w, TLSEXT_TYPE_SESSION_TICKET, ticket)
}

/// `int tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, SSL_EXT_CLIENT_HELLO, X509 *x,
/// size_t chainidx)` — `ssl/statem/extensions.c:803-878`, for the ClientHello context only.
///
/// The row order is `ext_defs[]`'s. The bodies are written with the shared [`BytesWriter`] into a
/// heap scratch block carrying the outer two-byte extension-block length; the completed block is
/// copied into `pkt` in one operation. Custom extensions (`custom_ext_add`) and the rows named in
/// the module header as boundaries are not walked.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
pub(crate) unsafe fn tls_construct_extensions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    let Some(block) = OwnedBuf::new(EXT_SCRATCH, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `s`/`pkt` are live per the contract; the scratch block is `EXT_SCRATCH` writable
    // bytes; every member access below is under the member-buffer invariants.
    unsafe {
        let buf = core::slice::from_raw_parts_mut(block.as_ptr(), EXT_SCRATCH);
        let mut w = BytesWriter::new(&mut buf[2..]);

        // `server_name` is the first `ext_defs[]` row (`extensions.c:155`).
        let host = (*s).ext_hostname();
        if !host.is_null() {
            let host = CStr::from_ptr(host).to_bytes();
            if !write_server_name(&mut w, host) {
                return 0;
            }
        }
        // `status_request` (`extensions.c:215`).
        if (*s).ext_status_type == TLSEXT_STATUSTYPE_OCSP && !write_status_request(&mut w) {
            return 0;
        }
        if !write_renegotiate(&mut w) || !write_ec_pt_formats(&mut w) {
            return 0;
        }
        let groups = tls1_get_supported_groups(s);
        if !groups.is_empty() && !write_supported_groups(&mut w, groups) {
            return 0;
        }
        if !write_sig_algs(&mut w, &CLIENT_SIGALGS) {
            return 0;
        }
        // `application_layer_protocol_negotiation` (`extensions.c:240`).
        let (alpn, alpn_len) = (*s).ext_alpn();
        if !alpn.is_null() {
            let alpn = core::slice::from_raw_parts(alpn, alpn_len as usize);
            if !write_alpn(&mut w, alpn) {
                return 0;
            }
        }
        // `session_ticket` (`extensions.c:283`), reduced at `tls_use_ticket`.
        if (*s).options & SSL_OP_NO_TICKET == 0 {
            let (tick, ticklen) = {
                let sess = (*s).session;
                if (*s).new_session == 0
                    && !sess.is_null()
                    && !(*sess).ext_tick().0.is_null()
                    && (*sess).ext_tick().1 > 0
                    && (*sess).ssl_version != crate::ssl::ssl_lib::TLS1_3_VERSION
                {
                    (*sess).ext_tick()
                } else {
                    (ptr::null::<u8>(), 0usize)
                }
            };
            let ticket: &[u8] = if ticklen == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(tick, ticklen)
            };
            if !write_session_ticket(&mut w, ticket) {
                return 0;
            }
        }
        if (*s).options & SSL_OP_NO_ENCRYPT_THEN_MAC == 0 && !write_etm(&mut w) {
            return 0;
        }
        if (*s).options & SSL_OP_NO_EXTENDED_MASTER_SECRET == 0 && !write_ems(&mut w) {
            return 0;
        }

        let mut min_version: c_int = 0;
        let mut max_version: c_int = 0;
        if ssl_get_min_max_version(s, &mut min_version, &mut max_version, ptr::null_mut()) != 0 {
            return 0;
        }
        if max_version >= TLS1_3_VERSION {
            if !write_supported_versions(&mut w, min_version, max_version) {
                return 0;
            }
            let nodhe = (*s).options & crate::ssl::ssl_ciph_table::SSL_OP_ALLOW_NO_DHE_KEX != 0;
            if !write_psk_kex_modes(&mut w, nodhe) {
                return 0;
            }

            use crate::evp::pkey::{
                evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key,
            };
            use crate::runtime::mem::CRYPTO_free;

            let (libctx, propq) = ((*(*s).ctx).libctx, (*(*s).ctx).propq());
            let mut params = [crate::params::END; 1];
            let pkey = evp_pkey_keygen(libctx, c"X25519".as_ptr(), propq, params.as_mut_ptr());
            if pkey.is_null() {
                return 0;
            }
            let mut pub_ = ptr::null_mut::<u8>();
            let publen = EVP_PKEY_get1_encoded_public_key(pkey, &mut pub_);
            if publen == 0 {
                EVP_PKEY_free(pkey);
                return 0;
            }
            let key = core::slice::from_raw_parts(pub_, publen);
            let written = write_key_share(&mut w, OSSL_TLS_GROUP_ID_x25519, key);
            CRYPTO_free(pub_.cast(), ptr::null(), 0);
            if !written {
                EVP_PKEY_free(pkey);
                return 0;
            }
            // The slot owns the previous ephemeral, if any.
            if !(*s).pkey.is_null() {
                EVP_PKEY_free((*s).pkey.cast());
            }
            (*s).pkey = pkey.cast();
        }

        // `post_handshake_auth` (`extensions.c:280`).
        if (*s).pha_enabled != 0 {
            if !write_post_handshake_auth(&mut w) {
                return 0;
            }
            // `SSL_PHA_EXT_SENT` (`ssl_local.h:372`).
            (*s).post_handshake_auth = 1;
        }

        let body_len = w.written();
        let Some(total) = body_len.checked_add(2) else {
            return 0;
        };
        if total > u16::MAX as usize {
            return 0;
        }
        buf[..2].copy_from_slice(&(body_len as u16).to_be_bytes());
        if WPACKET_memcpy(pkt, buf.as_ptr().cast(), total) == 0 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new, SslCtx};
    use crate::ssl::statem::statem_srvr::SliceCursor;

    fn write_one(f: impl FnOnce(&mut BytesWriter<'_>) -> bool) -> Option<Vec<u8>> {
        let mut buf = [0u8; EXT_SCRATCH];
        let mut w = BytesWriter::new(&mut buf);
        if !f(&mut w) {
            return None;
        }
        let n = w.written();
        Some(buf[..n].to_vec())
    }

    fn write_body(f: impl FnOnce(&mut BytesWriter<'_>) -> bool) -> Option<Vec<u8>> {
        let ext = write_one(f)?;
        parse_extension_block(&ext)?.first().map(|(_, b)| b.clone())
    }

    fn parse_extension_block(block: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
        let mut c = SliceCursor::new(block);
        let mut out = Vec::new();
        while c.remaining() > 0 {
            let ty = c.take_u16()?;
            let len = c.take_u16()? as usize;
            let body = c.take(len)?;
            out.push((ty, body.to_vec()));
        }
        Some(out)
    }

    fn new_client(max_version: c_int) -> (*mut SslCtx, *mut Ssl) {
        // SAFETY: the context and connection are allocated here and released by `free_client`.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            (*s).min_proto_version = max_version;
            (*s).max_proto_version = max_version;
            (ctx, s)
        }
    }

    fn free_client(ctx: *mut SslCtx, s: *mut Ssl) {
        // SAFETY: both pointers are the allocations from `new_client`.
        unsafe {
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    fn build_block(s: *mut Ssl) -> Vec<u8> {
        let mut storage = [0u8; EXT_SCRATCH];
        // SAFETY: the zeroed packet and static buffer are this frame's; `s` is live.
        unsafe {
            let mut pkt: Wpacket = core::mem::zeroed();
            assert!(
                crate::packet::WPACKET_init_static_len(
                    &mut pkt,
                    storage.as_mut_ptr(),
                    storage.len(),
                    0
                ) != 0
            );
            assert!(tls_construct_extensions(s, &mut pkt) != 0);
            let mut written = 0usize;
            assert!(crate::packet::WPACKET_get_total_written(&mut pkt, &mut written) != 0);
            let out = storage[..written].to_vec();
            crate::packet::WPACKET_cleanup(&mut pkt);
            out
        }
    }

    /// A fixed TLS1.2 configuration emits the deterministic extension set in `ext_defs[]`
    /// order. The expected bytes are the RFC 5246/8446 encodings of those bodies.
    #[test]
    fn client_hello_extension_block_is_byte_exact_tls12() {
        let (ctx, s) = new_client(0x0303);
        let block = build_block(s);
        free_client(ctx, s);
        let expected = hex(concat!(
            "0065",
            "ff01000100",
            "000b00020100",
            "000a0010000e001d0017001e0018001901000101",
            "000d0036003409050906090404030503060308070808081a081b081c0809080a080b080408050806",
            "040105010601030303010302040205020602",
            "00230000",
            "00160000",
            "00170000"
        ));
        assert_eq!(block, expected);
    }

    /// Each constructor's body parses back to the value it was given through the shared
    /// `SliceCursor`, and every field is consumed (no trailing bytes).
    #[test]
    fn every_extension_round_trips_through_slice_cursor() {
        // server_name
        let body = write_body(|w| write_server_name(w, b"example.com")).unwrap();
        let mut c = SliceCursor::new(&body);
        let list_len = c.take_u16().unwrap() as usize;
        assert_eq!(list_len, body.len() - 2);
        assert_eq!(c.take_u8(), Some(0));
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(c.take(n), Some(&b"example.com"[..]));
        assert_eq!(c.remaining(), 0);

        // supported_groups
        let groups = [29u16, 23, 30, 24, 25, 256, 257];
        let body = write_body(|w| write_supported_groups(w, &groups)).unwrap();
        let mut c = SliceCursor::new(&body);
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(n, groups.len() * 2);
        let mut got = Vec::new();
        while c.remaining() > 0 {
            got.push(c.take_u16().unwrap());
        }
        assert_eq!(got, groups);

        // signature_algorithms
        let body = write_body(|w| write_sig_algs(w, &CLIENT_SIGALGS)).unwrap();
        let mut c = SliceCursor::new(&body);
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(n, CLIENT_SIGALGS.len() * 2);
        let mut got = Vec::new();
        while c.remaining() > 0 {
            got.push(c.take_u16().unwrap());
        }
        assert_eq!(got, CLIENT_SIGALGS);

        // supported_versions
        let body = write_body(|w| write_supported_versions(w, 0x0301, 0x0304)).unwrap();
        let mut c = SliceCursor::new(&body);
        assert_eq!(c.take_u8(), Some(8));
        assert_eq!(c.take_u16(), Some(0x0304));
        assert_eq!(c.take_u16(), Some(0x0303));
        assert_eq!(c.take_u16(), Some(0x0302));
        assert_eq!(c.take_u16(), Some(0x0301));

        // psk_key_exchange_modes
        let body = write_body(|w| write_psk_kex_modes(w, true)).unwrap();
        let mut c = SliceCursor::new(&body);
        assert_eq!(c.take_u8(), Some(2));
        assert_eq!(c.take_u8(), Some(1));
        assert_eq!(c.take_u8(), Some(0));

        // key_share
        let key = [7u8; 32];
        let body = write_body(|w| write_key_share(w, 29, &key)).unwrap();
        let mut c = SliceCursor::new(&body);
        let list = c.take_u16().unwrap() as usize;
        assert_eq!(list, 2 + 2 + key.len());
        assert_eq!(c.take_u16(), Some(29));
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(c.take(n), Some(&key[..]));

        // status_request
        let body = write_body(write_status_request).unwrap();
        assert_eq!(body, [1, 0, 0, 0, 0]);

        // alpn
        let alpn = [
            2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ];
        let body = write_body(|w| write_alpn(w, &alpn)).unwrap();
        let mut c = SliceCursor::new(&body);
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(n, alpn.len());
        assert_eq!(c.take(n), Some(&alpn[..]));
    }

    /// Every truncation of every emitted body is refused by the cursor.
    #[test]
    fn truncated_bodies_are_refused() {
        let bodies = [
            write_one(write_status_request).unwrap(),
            write_one(|w| write_server_name(w, b"example.com")).unwrap(),
            write_one(|w| write_alpn(w, &[2, b'h', b'2'])).unwrap(),
            write_one(|w| write_supported_versions(w, 0x0301, 0x0304)).unwrap(),
            write_one(|w| write_psk_kex_modes(w, false)).unwrap(),
            write_one(write_renegotiate).unwrap(),
            write_one(write_ec_pt_formats).unwrap(),
            write_one(|w| write_sig_algs(w, &CLIENT_SIGALGS)).unwrap(),
            write_one(|w| write_supported_groups(w, &[29, 23])).unwrap(),
            write_one(|w| write_key_share(w, 29, &[9u8; 32])).unwrap(),
            write_one(write_post_handshake_auth).unwrap(),
            write_one(write_etm).unwrap(),
            write_one(write_ems).unwrap(),
            write_one(|w| write_session_ticket(w, &[])).unwrap(),
        ];
        for ext in bodies {
            for cut in 1..ext.len() {
                assert!(
                    parse_extension_block(&ext[..cut]).is_none(),
                    "truncation at {cut} of {ext:02x?} must be refused"
                );
            }
            assert!(parse_extension_block(&ext).is_some());
        }
    }

    /// The emitted block carries no duplicate extension type.
    #[test]
    fn emitted_block_has_no_duplicate_extension() {
        let (ctx, s) = new_client(0x0303);
        let block = build_block(s);
        free_client(ctx, s);
        let exts = parse_extension_block(&block[2..]).unwrap();
        assert_eq!(
            u16::from_be_bytes([block[0], block[1]]) as usize,
            block.len() - 2
        );
        let mut seen: Vec<u16> = Vec::new();
        for (ty, _) in exts {
            assert!(!seen.contains(&ty), "duplicate extension {ty}");
            seen.push(ty);
        }
    }

    /// The fixed group body accepts the maximum reduced list and refuses one more.
    #[test]
    fn max_size_group_list_round_trips() {
        let groups: Vec<u16> = (0..MAX_GROUPS).map(|i| (0x100 + i) as u16).collect();
        let body = write_body(|w| write_supported_groups(w, &groups)).unwrap();
        let mut c = SliceCursor::new(&body);
        let n = c.take_u16().unwrap() as usize;
        assert_eq!(n, MAX_GROUPS * 2);
        let mut got = Vec::new();
        while c.remaining() > 0 {
            got.push(c.take_u16().unwrap());
        }
        assert_eq!(got, groups);

        let too_many: Vec<u16> = (0..MAX_GROUPS + 1).map(|i| i as u16).collect();
        assert!(write_one(|w| write_supported_groups(w, &too_many)).is_none());
    }

    /// Deterministic malformed-input sweep: mutate a valid block with an LCG and walk it with
    /// the bounded cursor; the walk must terminate and never read past the slice.
    #[test]
    fn seeded_malformed_loop_does_not_overrun() {
        let (ctx, s) = new_client(0x0303);
        let valid = build_block(s);
        free_client(ctx, s);
        let mut state = 0x1234_5678u64;
        for _ in 0..1000 {
            let mut buf = valid.clone();
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let pos = (state as usize) % buf.len();
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            buf[pos] ^= (state as u8) | 1;
            let mut c = SliceCursor::new(&buf);
            while c.remaining() > 0 {
                let Some(_ty) = c.take_u16() else { break };
                let Some(len) = c.take_u16() else { break };
                if c.take(len as usize).is_none() {
                    break;
                }
            }
            assert!(c.remaining() <= buf.len());
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| {
                let parsed = u8::from_str_radix(&s[i..i + 2], 16);
                assert!(parsed.is_ok());
                parsed.unwrap_or(0)
            })
            .collect()
    }
}
