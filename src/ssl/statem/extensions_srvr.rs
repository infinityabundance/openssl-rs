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
//! Landed: `tls_construct_extensions` builds the block in a frame-owned scratch buffer with the
//! shared, bounds-checked [`BytesWriter`] and commits it with one `WPACKET_memcpy`; the rows are
//! `supported_versions` (`extensions_srvr.c:1924-1942`), the `HelloRetryRequest == SSL_HRR_NONE`,
//! non-resuming arm of `key_share` (`extensions_srvr.c:1989-2035`) for an `X25519` group, and the
//! selected PSK identity on a resumed connection. The commit is the only write to the packet, so a
//! refused construction is transactional.
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
use core::ptr;

use crate::packet::{WPACKET_memcpy, Wpacket};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::ssl::ssl_lib::Ssl;
use crate::ssl::statem::statem_srvr::BytesWriter;
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

/// The extension block scratch bound. A ServerHello block is three rows
/// (`supported_versions` 6 bytes, `key_share` at most 4 + 128, `pre_shared_key` 6), so 4 KiB is
/// the same generous bound the client's constructor uses.
const EXT_SCRATCH: usize = 4096;
/// `MAX_KEY_SHARE` (the client's bound, `extensions_clnt.rs`): an X25519 share is 32 bytes.
const MAX_KEY_SHARE: usize = 128;

/// `supported_versions` (`extensions_srvr.c:1924-1942`):
/// `type(2) || length(2) || selected_version(2)`.
///
/// Transactional at the call site: the caller builds the whole block in a scratch buffer and
/// copies it into the packet only once every row succeeded.
fn write_supported_versions(w: &mut BytesWriter<'_>, version: c_int) -> bool {
    let Ok(version) = u16::try_from(version) else {
        return false;
    };
    w.put_u16(TLSEXT_TYPE_SUPPORTED_VERSIONS) && w.put_u16(2) && w.put_u16(version)
}

/// `key_share` (`extensions_srvr.c:1989-2035`, the regular-KEX arm): one `KeyShareEntry`,
/// `type(2) || length(2) || group(2) || key_length(2) || key`.
///
/// An empty key or one beyond [`MAX_KEY_SHARE`] is refused before anything is written.
fn write_key_share(w: &mut BytesWriter<'_>, group: u16, key: &[u8]) -> bool {
    if key.is_empty() || key.len() > MAX_KEY_SHARE {
        return false;
    }
    let Some(ext_len) = key.len().checked_add(4) else {
        return false;
    };
    let Ok(ext_len) = u16::try_from(ext_len) else {
        return false;
    };
    w.put_u16(TLSEXT_TYPE_KEY_SHARE)
        && w.put_u16(ext_len)
        && w.put_u16(group)
        && w.put_u16_len_prefixed(key)
}

/// `pre_shared_key`, server form (`extensions_srvr.c:1815-1820`): `type(2) || length(2) ||
/// selected_identity(2)`. The reduced resumption path selects identity 0.
fn write_psk_selected_identity(w: &mut BytesWriter<'_>) -> bool {
    w.put_u16(TLSEXT_TYPE_PSK) && w.put_u16(2) && w.put_u16(0)
}

/// `int tls_construct_extensions(SSL_CONNECTION *s, WPACKET *pkt, unsigned int context,` —
/// `ssl/statem/extensions.c:803-878`, for the `SSL_EXT_TLS1_3_SERVER_HELLO` context.
///
/// The rows run in `ext_defs[]` order (`extensions.c:333-335`): `supported_versions`, `key_share`,
/// then `pre_shared_key` on a resumed connection. The block is built in a frame-owned scratch
/// buffer with [`BytesWriter`] and committed with one `WPACKET_memcpy`, so a refused construction
/// leaves `pkt` untouched. The ephemeral key is published as `s->pkey` only after that commit;
/// every refusal releases it exactly once and does not disturb an incumbent key.
///
/// # Safety
/// `s` must be a live connection and `pkt` a live packet.
pub(crate) unsafe fn tls_construct_extensions(s: *mut Ssl, pkt: *mut Wpacket) -> c_int {
    use crate::evp::pkey::{evp_pkey_keygen, EVP_PKEY_free, EVP_PKEY_get1_encoded_public_key};
    use crate::runtime::mem::CRYPTO_free;

    let Some(block) = OwnedBuf::new(EXT_SCRATCH, SeamFile::NULL, 0) else {
        return 0;
    };
    // SAFETY: `s` and `pkt` are live per the contract; `block` is `EXT_SCRATCH` writable bytes
    // owned by this frame and outlives `buf`; every `(*s)` read is within its object; `pkt` is
    // written only by the single commit below, so an earlier return leaves it untouched.
    unsafe {
        let buf = core::slice::from_raw_parts_mut(block.as_ptr(), EXT_SCRATCH);
        let Some(body_storage) = buf.get_mut(2..) else {
            return 0;
        };
        let mut w = BytesWriter::new(body_storage);

        // `supported_versions` (`extensions.c:333`).
        if !write_supported_versions(&mut w, (*s).version) {
            return 0;
        }

        // `key_share` (`extensions.c:334`). The reduced path generates only an X25519 share.
        let group = (*s).group_id;
        if group != OSSL_TLS_GROUP_ID_x25519 {
            return 0;
        }
        let (libctx, propq) = ((*(*s).ctx).libctx, (*(*s).ctx).propq());
        let mut params = [crate::params::END; 1];
        let skey = evp_pkey_keygen(libctx, c"X25519".as_ptr(), propq, params.as_mut_ptr());
        if skey.is_null() {
            return 0;
        }
        let mut pub_ = ptr::null_mut::<u8>();
        let publen = EVP_PKEY_get1_encoded_public_key(skey, &mut pub_);
        if publen == 0 {
            EVP_PKEY_free(skey);
            return 0;
        }
        let key = core::slice::from_raw_parts(pub_, publen);
        let wrote_share = write_key_share(&mut w, group, key);
        CRYPTO_free(pub_.cast(), ptr::null(), 0);
        if !wrote_share {
            EVP_PKEY_free(skey);
            return 0;
        }

        // `pre_shared_key` (`extensions.c:335`), sent only on a resumed connection.
        if (*s).hit != 0 && !write_psk_selected_identity(&mut w) {
            EVP_PKEY_free(skey);
            return 0;
        }

        let body_len = w.written();
        let Some(total) = body_len.checked_add(2) else {
            EVP_PKEY_free(skey);
            return 0;
        };
        let Ok(body_len16) = u16::try_from(body_len) else {
            EVP_PKEY_free(skey);
            return 0;
        };
        buf[..2].copy_from_slice(&body_len16.to_be_bytes());
        if WPACKET_memcpy(pkt, buf.as_ptr().cast(), total) == 0 {
            EVP_PKEY_free(skey);
            return 0;
        }

        // Commit boundary: the packet carries the share and the connection now owns the key.
        // A previous ephemeral is released exactly once, as the client's constructor does.
        if !(*s).pkey.is_null() {
            EVP_PKEY_free((*s).pkey.cast());
        }
        (*s).pkey = skey.cast();
    }
    1
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::packet::{WPACKET_cleanup, WPACKET_get_total_written, WPACKET_init_static_len};
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new, TLS1_3_VERSION};

    /// Run one writer over a fresh 256-byte buffer and return the bytes it produced.
    fn body(f: impl FnOnce(&mut BytesWriter<'_>) -> bool) -> Option<Vec<u8>> {
        let mut buf = [0u8; 256];
        let mut w = BytesWriter::new(&mut buf);
        if !f(&mut w) {
            return None;
        }
        let n = w.written();
        Some(buf[..n].to_vec())
    }

    fn server(group: u16, hit: c_int) -> (*mut crate::ssl::ssl_lib::SslCtx, *mut Ssl) {
        // SAFETY: the caller releases both objects; a fresh context/connection are live.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            (*s).version = TLS1_3_VERSION;
            (*s).group_id = group;
            (*s).hit = hit;
            (ctx, s)
        }
    }

    #[test]
    fn supported_versions_is_byte_exact() {
        // `type = 43`, `length = 2`, TLS1.3 = 0x0304.
        assert_eq!(
            body(|w| write_supported_versions(w, TLS1_3_VERSION)),
            Some(vec![0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])
        );
        assert_eq!(
            body(|w| write_supported_versions(w, 0)),
            Some(vec![0x00, 0x2b, 0x00, 0x02, 0x00, 0x00])
        );
        assert_eq!(
            body(|w| write_supported_versions(w, 0xffff)),
            Some(vec![0x00, 0x2b, 0x00, 0x02, 0xff, 0xff])
        );
        // A version that does not fit the wire field is refused before anything is written.
        let mut buf = [0u8; 16];
        let mut w = BytesWriter::new(&mut buf);
        assert!(!write_supported_versions(&mut w, 0x1_0000));
        assert_eq!(w.written(), 0);
    }

    #[test]
    fn key_share_is_byte_exact_and_bounded() {
        let key: Vec<u8> = (0..32).collect();
        let mut expected = vec![0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
        expected.extend_from_slice(&key);
        assert_eq!(
            body(|w| write_key_share(w, OSSL_TLS_GROUP_ID_x25519, &key)),
            Some(expected)
        );
        // Zero-size and over-long shares are refused.
        assert_eq!(
            body(|w| write_key_share(w, OSSL_TLS_GROUP_ID_x25519, &[])),
            None
        );
        let too_long = vec![0xABu8; MAX_KEY_SHARE + 1];
        assert_eq!(
            body(|w| write_key_share(w, OSSL_TLS_GROUP_ID_x25519, &too_long)),
            None
        );
        let maximum = vec![0xABu8; MAX_KEY_SHARE];
        assert!(body(|w| write_key_share(w, OSSL_TLS_GROUP_ID_x25519, &maximum)).is_some());
    }

    #[test]
    fn psk_selected_identity_is_byte_exact() {
        assert_eq!(
            body(write_psk_selected_identity),
            Some(vec![0x00, 0x29, 0x00, 0x02, 0x00, 0x00])
        );
    }

    #[test]
    fn a_short_packet_refusal_is_transactional() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = server(OSSL_TLS_GROUP_ID_x25519, 0);
        let mut buf = [0u8; 16];
        // SAFETY: `pkt` is a zeroed packet initialised over `buf`, which outlives it; all objects
        // are released below.
        unsafe {
            let mut pkt: Wpacket = core::mem::zeroed();
            assert_eq!(
                WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0),
                1
            );
            assert_eq!(tls_construct_extensions(s, &mut pkt), 0);
            assert_eq!(buf, [0u8; 16], "a refused commit writes nothing");
            assert!((*s).pkey.is_null(), "no key is published on refusal");
            WPACKET_cleanup(&mut pkt);
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn the_block_is_committed_and_owns_the_key() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = server(OSSL_TLS_GROUP_ID_x25519, 0);
        let mut buf = [0u8; EXT_SCRATCH];
        // SAFETY: as above; the key is freed explicitly before the connection.
        unsafe {
            let mut pkt: Wpacket = core::mem::zeroed();
            assert_eq!(
                WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0),
                1
            );
            assert_eq!(tls_construct_extensions(s, &mut pkt), 1);
            let mut total = 0usize;
            assert_eq!(WPACKET_get_total_written(&mut pkt, &mut total), 1);
            assert_eq!(total, 2 + 6 + 40, "length prefix + two extensions");
            let block = &buf[..total];
            assert_eq!(u16::from_be_bytes([block[0], block[1]]) as usize, total - 2);
            assert_eq!(&block[2..8], &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
            assert_eq!(
                &block[8..16],
                &[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]
            );
            let key = (*s).pkey;
            assert!(!key.is_null(), "the key is published only after the commit");

            // A second, refused construction must neither free nor replace the published key.
            let mut tiny = [0u8; 8];
            let mut pkt2: Wpacket = core::mem::zeroed();
            assert_eq!(
                WPACKET_init_static_len(&mut pkt2, tiny.as_mut_ptr(), tiny.len(), 0),
                1
            );
            assert_eq!(tls_construct_extensions(s, &mut pkt2), 0);
            assert_eq!((*s).pkey, key, "the incumbent key is untouched on refusal");
            assert_eq!(tiny, [0u8; 8]);
            WPACKET_cleanup(&mut pkt2);
            WPACKET_cleanup(&mut pkt);
            crate::evp::pkey::EVP_PKEY_free(key.cast());
            (*s).pkey = ptr::null_mut();
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    #[test]
    fn a_resumed_connection_appends_the_psk_identity() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = server(OSSL_TLS_GROUP_ID_x25519, 1);
        let mut buf = [0u8; EXT_SCRATCH];
        // SAFETY: as above.
        unsafe {
            let mut pkt: Wpacket = core::mem::zeroed();
            assert_eq!(
                WPACKET_init_static_len(&mut pkt, buf.as_mut_ptr(), buf.len(), 0),
                1
            );
            assert_eq!(tls_construct_extensions(s, &mut pkt), 1);
            let mut total = 0usize;
            assert_eq!(WPACKET_get_total_written(&mut pkt, &mut total), 1);
            assert_eq!(total, 2 + 6 + 40 + 6);
            assert_eq!(
                &buf[total - 6..total],
                &[0x00, 0x29, 0x00, 0x02, 0x00, 0x00],
                "pre_shared_key is last, as in ext_defs[]"
            );
            WPACKET_cleanup(&mut pkt);
            let key = (*s).pkey;
            crate::evp::pkey::EVP_PKEY_free(key.cast());
            (*s).pkey = ptr::null_mut();
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }
}
