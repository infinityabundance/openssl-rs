//! Phase 17 — the reduced TLS 1.2 key schedule and record protection (`ssl/t1_enc.c` and the
//! TLS1.2 half of `ssl/record/methods/tls_enc.c`).
//!
//! The crate's TLS1.3 schedule is `tls13_enc.rs`; this module lands the TLS1.2 counterpart the
//! CPython downstream tests need, reduced to the one fresh, non-resuming flight they drive:
//!
//! * **The PRF.** [`tls12_prf`] is `tls1_prf` (`ssl/t1_enc.c:50-135`): the TLS1.2 `P_hash`
//!   (`A(i) = HMAC(secret, A(i-1))`, `output += HMAC(secret, A(i) || label || seed)`), over the
//!   suite's PRF hash (SHA-256 for `..._SHA256` suites, SHA-384 for `..._SHA384`).
//! * **The master secret and key block.** [`tls12_derive_master_secret`] is
//!   `tls1_generate_master_secret` (`t1_enc.c:267-275`); [`tls12_derive_key_block`] is
//!   `tls1_setup_key_block` (`t1_enc.c:315-370`), which lays out
//!   `client_write_key || server_write_key || client_write_IV || server_write_IV` for an AEAD suite.
//! * **The Finished MAC.** [`tls12_finished_mac`] is `tls1_final_finish_mac` (`t1_enc.c:186-224`):
//!   `verify_data = PRF(master_secret, "client finished"/"server finished", Hash(handshake))[0..12]`.
//! * **The AEAD record.** [`tls12_encrypt_record`]/[`tls12_decrypt_record`] are the TLS1.2 GCM half
//!   of `tls1_enc` (`ssl/t1_enc.c:400-...`): `nonce = fixed_IV(4) || explicit_nonce(8)`,
//!   `AAD = seq_num(8) || type || version || length`, and the explicit nonce is the sequence number
//!   (RFC 5288 §3).
//!
//! ## Named boundaries (recorded, not fabricated)
//!
//! * **Only the four `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites are built.** The CBC/CCM/ChaCha
//!   suites and the legacy `MAC-then-encrypt` path (`SSL_AEAD` unset) are named here rather than
//!   built; every test this module drives negotiates a GCM suite.
//! * **Extended master secret, encrypt-then-MAC, session tickets and resumption are not derived.**
//!   The reduced ClientHello still advertises EMS/EtM, but the reduced ServerHello does not echo
//!   them, so both sides use the standard (`client_random`/`server_random`) master-secret seed.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uint};
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_key_length};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate,
};
use crate::evp::digest::EVP_MD_get_size;
use crate::evp::legacy_sha::{EVP_sha256, EVP_sha384};
use crate::mac::hmac::HMAC;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
use crate::ssl::ssl_lib::{Ssl, SSL_MAX_MASTER_KEY_LENGTH};
use crate::ssl::tls13_enc::{tls13_init_transcript, transcript_hash};

/// `TLS1_2_VERSION` — `tls1.h:201`, the record version of every TLS1.2 record.
const TLS1_2_VERSION: c_int = 0x0303;
/// `EVP_CTRL_AEAD_SET_IVLEN` — `evp.h:388`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CTRL_AEAD_GET_TAG` — `evp.h:389`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `EVP_CTRL_AEAD_SET_TAG` — `evp.h:390`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `EVP_GCM_TLS_FIXED_IV_LEN` — `ssl/t1_enc.c` (`4`).
const TLS12_FIXED_IV_LEN: usize = 4;
/// `EVP_GCM_TLS_EXPLICIT_IV_LEN` — `ssl/t1_enc.c` (`8`).
const TLS12_EXPLICIT_IV_LEN: usize = 8;
/// `SSL3_RT_MAX_MD_SIZE`-bounded scratch (`EVP_MAX_MD_SIZE` = 64).
const HASH_MAX: usize = 64;
/// The largest `P_hash` HMAC input: `A(i) | seed`.
const P_HASH_INPUT_MAX: usize = HASH_MAX + 255;

/// A fixed scratch block whose contents are cleansed on every exit, including the
/// early returns an HMAC failure takes. The PRF state and its HMAC inputs are
/// secret-derived, so they are wiped with the same volatile primitive the rest of
/// the crate uses.
struct CleansedBlock<const N: usize>([u8; N]);

impl<const N: usize> CleansedBlock<N> {
    fn new() -> Self {
        Self([0u8; N])
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> Drop for CleansedBlock<N> {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live array of exactly `N` writable bytes.
        unsafe { crate::runtime::mem::cleanse(self.0.as_mut_ptr(), N) }
    }
}

/// The reduced TLS1.2 record cipher: `(name, key_len, tag_len, md_kind)` for the four
/// `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites (`ssl_cipher_get_evp`, `t1_enc.c`).
fn cipher_for_id(id: u16) -> Option<(&'static [u8], usize, usize, c_int)> {
    match id {
        0xc02b | 0xc02f => Some((b"AES-128-GCM\0", 16, 16, 0)),
        0xc02c | 0xc030 => Some((b"AES-256-GCM\0", 32, 16, 1)),
        // Static-RSA key transport with the same AEADs: `TLS_RSA_WITH_AES_128_GCM_SHA256`
        // (`0x009c`) and `TLS_RSA_WITH_AES_256_GCM_SHA384` (`0x009d`).
        0x009c => Some((b"AES-128-GCM\0", 16, 16, 0)),
        0x009d => Some((b"AES-256-GCM\0", 32, 16, 1)),
        // Ephemeral DH with the same AEADs: `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` (`0x009e`),
        // `..._256_GCM_SHA384` (`0x009f`), and the DHE-DSS twins (`0x00a2`, `0x00a3`).
        0x009e | 0x00a2 => Some((b"AES-128-GCM\0", 16, 16, 0)),
        0x009f | 0x00a3 => Some((b"AES-256-GCM\0", 32, 16, 1)),
        _ => None,
    }
}

/// The connection's TLS1.2 PRF hash (`ssl_handshake_md`, `t1_enc.c`): SHA-256 for `md_kind` 0,
/// SHA-384 for 1.
fn prf_md(md_kind: c_int) -> *const crate::evp::digest::EvpMd {
    if md_kind == 1 {
        EVP_sha384()
    } else {
        EVP_sha256()
    }
}

/// `ssl_cipher_get_evp(...)` (`t1_enc.c`) for the reduced TLS1.2 GCM suites: cache the AEAD cipher,
/// key/tag lengths and PRF hash, and initialise the transcript with the suite's hash. The final
/// `tls1_setup_key_block` step of computing the key block is [`tls12_derive_key_block`].
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls12_setup_cipher(s: *mut Ssl, cipher_id: u16) -> c_int {
    let Some((name, key_len, tag_len, md_kind)) = cipher_for_id(cipher_id) else {
        return 0;
    };
    // SAFETY: `s` is live.
    unsafe {
        if (*s).tls13_cipher.is_null() {
            let libctx = (*(*s).ctx).libctx;
            let propq = (*(*s).ctx).propq();
            let c = EVP_CIPHER_fetch(libctx, name.as_ptr().cast(), propq);
            if c.is_null() {
                return 0;
            }
            let klen = EVP_CIPHER_get_key_length(c);
            if klen <= 0 || klen as usize != key_len {
                EVP_CIPHER_free(c);
                return 0;
            }
            (*s).tls13_cipher = c.cast();
            (*s).cipher_key_len = key_len;
            (*s).cipher_tag_len = tag_len;
            // TLS1.2 GCM's fixed IV is four bytes; the explicit nonce supplies the other eight.
            (*s).cipher_iv_len = TLS12_FIXED_IV_LEN;
            (*s).tls12_md_kind = md_kind;
        }
        tls13_init_transcript(s, md_kind)
    }
}

/// `P_hash(secret, seed)` — the TLS1.2 PRF's HMAC construction (`tls1_prf`, `ssl/t1_enc.c:50-135`).
///
/// The interior works over slices; the `A(i) | seed` assembly and the output copy are
/// bounds-checked, and every secret-derived block is cleansed on exit.
///
/// # Safety
/// `md` is live.
unsafe fn p_hash(
    md: *const crate::evp::digest::EvpMd,
    secret: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> c_int {
    if secret.len() > c_int::MAX as usize || seed.len() > 255 {
        return 0;
    }
    // SAFETY: `md` is live.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hash_len = sz as usize;
    if hash_len > HASH_MAX {
        return 0;
    }
    // `A(1) = HMAC_hash(secret, seed)`.
    let mut a = CleansedBlock::<HASH_MAX>::new();
    let mut alen: c_uint = 0;
    // SAFETY: `md` is live and `secret`/`seed` are slices; `a` is writable for the digest.
    let r = unsafe {
        HMAC(
            md,
            secret.as_ptr().cast(),
            secret.len() as c_int,
            seed.as_ptr(),
            seed.len(),
            a.as_mut_slice().as_mut_ptr(),
            &mut alen,
        )
    };
    if r.is_null() {
        return 0;
    }
    let mut off = 0usize;
    while off < out.len() {
        let mut blen = alen as usize;
        if blen > HASH_MAX {
            return 0;
        }
        let mut buf = CleansedBlock::<P_HASH_INPUT_MAX>::new();
        buf.as_mut_slice()[..blen].copy_from_slice(&a.as_slice()[..blen]);
        buf.as_mut_slice()[blen..blen + seed.len()].copy_from_slice(seed);
        blen += seed.len();
        let mut h = CleansedBlock::<HASH_MAX>::new();
        let mut hlen: c_uint = 0;
        // SAFETY: `md` is live; `secret`/`buf` are readable for their lengths; `h` is writable.
        let r = unsafe {
            HMAC(
                md,
                secret.as_ptr().cast(),
                secret.len() as c_int,
                buf.as_slice().as_ptr(),
                blen,
                h.as_mut_slice().as_mut_ptr(),
                &mut hlen,
            )
        };
        if r.is_null() || hlen as usize > HASH_MAX {
            return 0;
        }
        let take = (out.len() - off).min(hlen as usize);
        out[off..off + take].copy_from_slice(&h.as_slice()[..take]);
        off += take;
        // `A(i+1) = HMAC_hash(secret, A(i))`.
        let mut alen2: c_uint = 0;
        // SAFETY: `md` is live; `secret`/`a` are readable for their lengths; `a` is writable.
        let r = unsafe {
            HMAC(
                md,
                secret.as_ptr().cast(),
                secret.len() as c_int,
                a.as_slice().as_ptr(),
                hash_len,
                a.as_mut_slice().as_mut_ptr(),
                &mut alen2,
            )
        };
        if r.is_null() {
            return 0;
        }
        alen = alen2;
    }
    1
}

/// `tls1_prf(secret, seed, label, out, out_len)` over the connection's PRF hash: `P_hash` seeded
/// with `label || seed`.
///
/// # Safety
/// `md_kind` selects a live static digest.
unsafe fn tls12_prf(
    md_kind: c_int,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out: &mut [u8],
) -> c_int {
    let Some(total) = label.len().checked_add(seed.len()) else {
        return 0;
    };
    let mut ls = [0u8; 255];
    let Some(dst) = ls.get_mut(..total) else {
        return 0;
    };
    dst[..label.len()].copy_from_slice(label);
    dst[label.len()..].copy_from_slice(seed);
    // SAFETY: `prf_md` is a live static digest; the buffers are slices.
    unsafe { p_hash(prf_md(md_kind), secret, dst, out) }
}

/// `tls1_generate_master_secret(SSL_CONNECTION *s, unsigned char *out, unsigned char *pms,
/// size_t pmslen, ...)` — `ssl/t1_enc.c:365-412`.
///
/// The `SSL_SESS_FLAG_EXTMS` arm is RFC 7627's extended master secret:
/// `master = PRF(pms, "extended master secret", session_hash, 48)`, where `session_hash` is the
/// handshake hash through the ClientKeyExchange. The legacy arm is
/// `PRF(pms, "master secret", client_random || server_random, 48)`. The caller writes the
/// ClientKeyExchange before deriving, so the transcript is at the authority's freeze point.
///
/// # Safety
/// `s` is live; `pms` readable for `pmslen`.
pub(crate) unsafe fn tls12_derive_master_secret(
    s: *mut Ssl,
    pms: *const u8,
    pmslen: usize,
) -> c_int {
    // SAFETY: `s` is live.
    let md_kind = unsafe { (*s).tls12_md_kind };
    // The RFC 7627 arm is selected by the session flag the ServerHello's
    // `extended_master_secret` extension sets (`tls_parse_stoc_ems`, `extensions_clnt.c:1818`).
    // SAFETY: `s` is live; a non-NULL `session` is the connection's own.
    let extms = unsafe {
        !(*s).session.is_null()
            && ((*(*s).session).flags & crate::ssl::ssl_lib::SSL_SESS_FLAG_EXTMS) != 0
    };
    let mut seed = [0u8; 64];
    // SAFETY: `s` is live; the randoms are 32-byte arrays; `pms` is readable for `pmslen`.
    let r = unsafe {
        let pms: &[u8] = if pmslen == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(pms, pmslen)
        };
        let master = &mut (*s).tls12_master_secret;
        if extms {
            let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
            if crate::ssl::tls13_enc::transcript_hash(s, hash.as_mut_ptr(), core::ptr::null_mut())
                == 0
            {
                return 0;
            }
            let hashlen = (*s).hs_md_len;
            tls12_prf(
                md_kind,
                pms,
                b"extended master secret",
                &hash[..hashlen],
                &mut master[..SSL_MAX_MASTER_KEY_LENGTH],
            )
        } else {
            seed[..32].copy_from_slice(&(*s).client_random);
            seed[32..].copy_from_slice(&(*s).server_random);
            tls12_prf(
                md_kind,
                pms,
                b"master secret",
                &seed,
                &mut master[..SSL_MAX_MASTER_KEY_LENGTH],
            )
        }
    };
    // `ssl_generate_master_secret` (`s3_lib.c:5327`) writes into `s->session->master_key`; the
    // handshake session carries the secret so a TLS1.2 ticket can resume from it.
    if r != 0 {
        // SAFETY: `s` is live; `session` is the handshake session created for this connection.
        unsafe {
            if !(*s).session.is_null() {
                let dst = &mut (*(*s).session).master_key;
                dst[..SSL_MAX_MASTER_KEY_LENGTH]
                    .copy_from_slice(&(&(*s).tls12_master_secret)[..SSL_MAX_MASTER_KEY_LENGTH]);
                (*(*s).session).master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
            }
        }
    }
    r
}

/// `tls1_setup_key_block(SSL_CONNECTION *s)` — `ssl/t1_enc.c:315-370`, the AEAD half:
/// `key_block = PRF(master_secret, "key expansion", server_random || client_random, 2*key+2*IV)`.
/// The MAC-key and CBC arms are not built (the reduced suites are AEAD).
///
/// # Safety
/// `s` is live and the TLS1.2 cipher is set up.
pub(crate) unsafe fn tls12_derive_key_block(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    let md_kind = unsafe { (*s).tls12_md_kind };
    // SAFETY: `s` is live.
    let key_len = unsafe { (*s).cipher_key_len };
    let Some(total) = key_len
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * TLS12_FIXED_IV_LEN))
    else {
        return 0;
    };
    let mut seed = [0u8; 64];
    // SAFETY: `s` is live; `tls12_key_block` is 128 bytes and `total <= 2*32+8`.
    let r = unsafe {
        seed[..32].copy_from_slice(&(*s).server_random);
        seed[32..].copy_from_slice(&(*s).client_random);
        let Some(out) = (*s).tls12_key_block.get_mut(..total) else {
            return 0;
        };
        let master = &(&(*s).tls12_master_secret)[..SSL_MAX_MASTER_KEY_LENGTH];
        tls12_prf(md_kind, master, b"key expansion", &seed, out)
    };
    if r == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    unsafe { (*s).tls12_key_block_len = total };
    1
}

/// Install the write direction's key/IV from the key block (`tls12_change_cipher_state` ->
/// `tls1_change_cipher_state`, `t1_enc.c:372-...`). `is_client` selects `client_write_*`; the
/// server uses `server_write_*`.
///
/// # Safety
/// `s` is live and the key block derived.
pub(crate) unsafe fn tls12_install_write(s: *mut Ssl, is_client: bool) -> c_int {
    // SAFETY: `s` is live.
    let key_len = unsafe { (*s).cipher_key_len };
    // The destination is the fixed 32-byte write-key array; refusing a longer key here
    // keeps the copy below bounded even if `cipher_key_len` is set by another schedule.
    // SAFETY: `s` is live.
    if key_len == 0 || key_len > unsafe { (*s).enc_key.len() } {
        return 0;
    }
    // SAFETY: `s` is live.
    let kb_len = unsafe { (*s).tls12_key_block_len };
    let Some(needed) = key_len
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * TLS12_FIXED_IV_LEN))
    else {
        return 0;
    };
    if kb_len < needed {
        return 0;
    }
    let (koff, ioff) = if is_client {
        (0usize, 2 * key_len)
    } else {
        (key_len, 2 * key_len + TLS12_FIXED_IV_LEN)
    };
    // SAFETY: `s` is live; the block offsets are checked slices and the destination
    // arrays are bounded below the fixed 32-byte key / 16-byte IV lengths.
    unsafe {
        let Some(block) = (*s).tls12_key_block.get(..needed) else {
            return 0;
        };
        let Some(key) = block.get(koff..koff + key_len) else {
            return 0;
        };
        let Some(iv) = block.get(ioff..ioff + TLS12_FIXED_IV_LEN) else {
            return 0;
        };
        (&mut (*s).enc_key)[..key_len].copy_from_slice(key);
        (&mut (*s).enc_iv)[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
        (*s).enc_seq = 0;
        (*s).enc_active = 1;
    }
    1
}

/// Install the read direction's key/IV from the key block, the mirror of
/// [`tls12_install_write`].
///
/// # Safety
/// `s` is live and the key block derived.
pub(crate) unsafe fn tls12_install_read(s: *mut Ssl, is_client: bool) -> c_int {
    // SAFETY: `s` is live.
    let key_len = unsafe { (*s).cipher_key_len };
    // As in `tls12_install_write`, the destination is the fixed 32-byte read-key array.
    // SAFETY: `s` is live.
    if key_len == 0 || key_len > unsafe { (*s).dec_key.len() } {
        return 0;
    }
    // SAFETY: `s` is live.
    let kb_len = unsafe { (*s).tls12_key_block_len };
    let Some(needed) = key_len
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * TLS12_FIXED_IV_LEN))
    else {
        return 0;
    };
    if kb_len < needed {
        return 0;
    }
    // The peer's write direction is this side's read direction.
    let (koff, ioff) = if is_client {
        (key_len, 2 * key_len + TLS12_FIXED_IV_LEN)
    } else {
        (0usize, 2 * key_len)
    };
    // SAFETY: `s` is live; the block offsets are checked slices and the destination
    // arrays are bounded below the fixed 32-byte key / 16-byte IV lengths.
    unsafe {
        let Some(block) = (*s).tls12_key_block.get(..needed) else {
            return 0;
        };
        let Some(key) = block.get(koff..koff + key_len) else {
            return 0;
        };
        let Some(iv) = block.get(ioff..ioff + TLS12_FIXED_IV_LEN) else {
            return 0;
        };
        (&mut (*s).dec_key)[..key_len].copy_from_slice(key);
        (&mut (*s).dec_iv)[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
        (*s).dec_seq = 0;
        (*s).dec_active = 1;
    }
    1
}

/// `tls1_final_finish_mac(SSL_CONNECTION *s, const char *str, size_t len, unsigned char *out)` —
/// `ssl/t1_enc.c:186-224`: `verify_data = PRF(master_secret, label, Hash(handshake))[0..12]`.
///
/// # Safety
/// `s` is live; `out` writable for at least 12 bytes.
pub(crate) unsafe fn tls12_finished_mac(s: *mut Ssl, label: &[u8], out: *mut u8) -> usize {
    // SAFETY: `s` is live.
    let md_kind = unsafe { (*s).tls12_md_kind };
    let mut hash = [0u8; HASH_MAX];
    // SAFETY: `s` is live; `hash` is writable.
    if unsafe { transcript_hash(s, hash.as_mut_ptr(), ptr::null_mut()) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live.
    let hash_len = unsafe { (*s).hs_md_len };
    let Some(hash) = hash.get(..hash_len) else {
        return 0;
    };
    // SAFETY: `s` is live; the master secret is 48 readable bytes; `out` is writable for 12.
    unsafe {
        let out = core::slice::from_raw_parts_mut(out, 12);
        let master = &(&(*s).tls12_master_secret)[..SSL_MAX_MASTER_KEY_LENGTH];
        if tls12_prf(md_kind, master, label, hash, out) == 0 {
            return 0;
        }
    }
    12
}

/// The TLS1.2 AEAD `additional_data` (`tls1_enc`, `ssl/t1_enc.c`):
/// `seq_num(8) || type(1) || version(2) || length(2)`.
///
/// Returns `false` when the plaintext length cannot be expressed in the two-byte
/// field, rather than truncating it.
fn tls12_aad(seq: u64, content_type: u8, plain_len: usize, aad: &mut [u8; 13]) -> bool {
    let Ok(len) = u16::try_from(plain_len) else {
        return false;
    };
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8..9].copy_from_slice(&[content_type]);
    aad[9..11].copy_from_slice(&(TLS1_2_VERSION as u16).to_be_bytes());
    aad[11..13].copy_from_slice(&len.to_be_bytes());
    true
}

/// The TLS1.2 GCM nonce (`tls1_enc`): `fixed_IV(4) || explicit_nonce(8)`, where the explicit nonce
/// is the record sequence number (RFC 5288 §3).
fn tls12_nonce(fixed_iv: &[u8; 16], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..TLS12_FIXED_IV_LEN].copy_from_slice(&fixed_iv[..TLS12_FIXED_IV_LEN]);
    nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// `tls1_enc`'s encrypt half for the reduced TLS1.2 GCM suites: seal `plain` under the write key
/// and write `type || version || length || explicit_nonce || ciphertext || tag` into `out`. The
/// return is the total record length, or -1.
///
/// # Safety
/// `s` is live; `plain` readable for `len`; `out` writable for `5 + 8 + len + tag`.
pub(crate) unsafe fn tls12_encrypt_record(
    s: *mut Ssl,
    content_type: u8,
    plain: *const u8,
    len: usize,
    out: *mut u8,
) -> isize {
    // SAFETY: `s` is live; `plain` is readable for `len`; `out` is writable for
    // `5 + rec_len`, checked before any slice is formed.
    unsafe {
        let key_len = (*s).cipher_key_len;
        let tag_len = (*s).cipher_tag_len;
        if key_len == 0 || tag_len == 0 || len > c_int::MAX as usize {
            return -1;
        }
        let seq = (*s).enc_seq;
        let nonce = tls12_nonce(&(*s).enc_iv, seq);
        let mut aad = [0u8; 13];
        if !tls12_aad(seq, content_type, len, &mut aad) {
            return -1;
        }
        let Some(rec_len) = TLS12_EXPLICIT_IV_LEN
            .checked_add(len)
            .and_then(|n| n.checked_add(tag_len))
        else {
            return -1;
        };
        if rec_len > 0xffff {
            return -1;
        }
        let Some(out_len) = 5usize.checked_add(rec_len) else {
            return -1;
        };
        let out = core::slice::from_raw_parts_mut(out, out_len);
        let plain: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(plain, len)
        };
        // Header + explicit nonce (the sequence number, RFC 5288 §3).
        let hdr = [
            content_type,
            (TLS1_2_VERSION >> 8) as u8,
            TLS1_2_VERSION as u8,
            (rec_len >> 8) as u8,
            rec_len as u8,
        ];
        out[..5].copy_from_slice(&hdr);
        out[5..5 + TLS12_EXPLICIT_IV_LEN].copy_from_slice(&seq.to_be_bytes());

        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return -1;
        }
        let mut ok = false;
        if EVP_EncryptInit_ex(
            ctx,
            (*s).tls13_cipher.cast(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        ) == 1
            && EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                nonce.len() as c_int,
                ptr::null_mut(),
            ) == 1
            && EVP_EncryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                (*s).enc_key.as_ptr(),
                nonce.as_ptr(),
            ) == 1
        {
            let body = 5 + TLS12_EXPLICIT_IV_LEN;
            let mut l: c_int = 0;
            let aad_ok = EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut l, aad.as_ptr(), 13);
            let enc_ok = if aad_ok == 1 {
                EVP_EncryptUpdate(
                    ctx,
                    out[body..body + len].as_mut_ptr(),
                    &mut l,
                    plain.as_ptr(),
                    len as c_int,
                )
            } else {
                0
            };
            let mut ctlen = match usize::try_from(l) {
                Ok(n) if n <= len => n,
                _ => usize::MAX,
            };
            let mut fl: c_int = 0;
            let fin_ok = if enc_ok == 1 && ctlen <= len {
                EVP_EncryptFinal_ex(ctx, out[body + ctlen..].as_mut_ptr(), &mut fl)
            } else {
                0
            };
            if fin_ok == 1 && fl > 0 {
                ctlen = ctlen.saturating_add(fl as usize);
            }
            let tag_ok = if enc_ok == 1 && fin_ok == 1 && ctlen <= len {
                match out.get_mut(body + ctlen..body + ctlen + tag_len) {
                    Some(slot) => EVP_CIPHER_CTX_ctrl(
                        ctx,
                        EVP_CTRL_AEAD_GET_TAG,
                        tag_len as c_int,
                        slot.as_mut_ptr().cast(),
                    ),
                    None => 0,
                }
            } else {
                0
            };
            if enc_ok == 1 && fin_ok == 1 && tag_ok == 1 {
                (*s).enc_seq += 1;
                ok = true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        if ok {
            out_len as isize
        } else {
            -1
        }
    }
}

/// `tls1_enc`'s decrypt half for the reduced TLS1.2 GCM suites: open `hdr || ct` under the read
/// key, writing the inner content to `out` and the record's real content type to `*content_type`.
/// The return is the content length, or -1.
///
/// # Safety
/// `s` is live; `ct` readable for `ct_len`; `out` writable for `out_cap`; `content_type` writable.
pub(crate) unsafe fn tls12_decrypt_record(
    s: *mut Ssl,
    hdr: &[u8; 5],
    ct: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_cap: usize,
    content_type: *mut u8,
) -> isize {
    // SAFETY: `s` is live; `ct` is readable for `ct_len`; `out` is writable for `out_cap`;
    // `content_type` is writable.
    unsafe {
        let tag_len = (*s).cipher_tag_len;
        if ct_len < TLS12_EXPLICIT_IV_LEN + tag_len {
            return -1;
        }
        let body_len = ct_len - TLS12_EXPLICIT_IV_LEN - tag_len;
        if body_len > out_cap || body_len > u16::MAX as usize {
            return -1;
        }
        let ct: &[u8] = if ct_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(ct, ct_len)
        };
        let (explicit, rest) = ct.split_at(TLS12_EXPLICIT_IV_LEN);
        let (body, tag) = rest.split_at(body_len);
        let mut nonce = [0u8; 12];
        nonce[..TLS12_FIXED_IV_LEN].copy_from_slice(&(&(*s).dec_iv)[..TLS12_FIXED_IV_LEN]);
        nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(explicit);
        let mut aad = [0u8; 13];
        if !tls12_aad((*s).dec_seq, hdr[0], body_len, &mut aad) {
            return -1;
        }

        // Authenticated plaintext is staged in a cleansed block: a tag failure therefore
        // never leaves unauthenticated bytes in the caller's buffer, and the scratch is
        // wiped on every return.
        let plain_cap = body_len.max(1);
        let Some(plain_block) = OwnedBuf::new_cleansed(plain_cap, SeamFile::NULL, 0) else {
            return -1;
        };
        // SAFETY: the block is allocated for `plain_cap >= body_len` writable bytes.
        let plain = core::slice::from_raw_parts_mut(plain_block.as_ptr(), plain_cap);
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return -1;
        }
        let mut ok = false;
        let mut outl: c_int = 0;
        if EVP_DecryptInit_ex(
            ctx,
            (*s).tls13_cipher.cast(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        ) == 1
            && EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_IVLEN,
                nonce.len() as c_int,
                ptr::null_mut(),
            ) == 1
            && EVP_DecryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                (*s).dec_key.as_ptr(),
                nonce.as_ptr(),
            ) == 1
        {
            let mut l: c_int = 0;
            let aad_ok = EVP_DecryptUpdate(ctx, ptr::null_mut(), &mut l, aad.as_ptr(), 13);
            let dec_ok = if aad_ok == 1 {
                EVP_DecryptUpdate(
                    ctx,
                    plain.as_mut_ptr(),
                    &mut outl,
                    body.as_ptr(),
                    body_len as c_int,
                )
            } else {
                0
            };
            let produced = match usize::try_from(outl) {
                Ok(n) if n <= body_len => n,
                _ => usize::MAX,
            };
            let tag_ok = if dec_ok == 1 && produced <= body_len {
                EVP_CIPHER_CTX_ctrl(
                    ctx,
                    EVP_CTRL_AEAD_SET_TAG,
                    tag_len as c_int,
                    tag.as_ptr().cast_mut().cast(),
                )
            } else {
                0
            };
            let mut fl: c_int = 0;
            let fin_ok = if dec_ok == 1 && tag_ok == 1 && produced <= body_len {
                EVP_DecryptFinal_ex(ctx, plain[produced..].as_mut_ptr(), &mut fl)
            } else {
                0
            };
            let total = if fl > 0 {
                produced.saturating_add(fl as usize)
            } else {
                produced
            };
            if dec_ok == 1 && fin_ok == 1 && total == body_len {
                outl = body_len as c_int;
                ok = true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return -1;
        }
        // SAFETY: `body_len <= out_cap` was checked above, so `out` is writable for the whole copy;
        // it need not be initialised and is only written, never read. `plain` is a distinct
        // cleansed allocation.
        if body_len != 0 {
            core::ptr::copy_nonoverlapping(plain.as_ptr(), out, body_len);
        }
        *content_type = hdr[0];
        (*s).dec_seq += 1;
        outl as isize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free;

    fn hex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string has an even number of digits"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| {
                let parsed = u8::from_str_radix(&s[i..i + 2], 16);
                assert!(parsed.is_ok(), "hex digit");
                parsed.unwrap_or(0)
            })
            .collect()
    }

    /// NIST TLS1.2 PRF key-expansion vector, as shipped in OpenSSL's
    /// `test/recipes/30-test_evp_data/evpkdf_tls12_prf.txt` ("from NIST test vectors").
    const PRF_SECRET: &str =
        "202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf";
    const PRF_SERVER_RANDOM: &str =
        "ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868";
    const PRF_CLIENT_RANDOM: &str =
        "62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616";
    const PRF_OUTPUT: &str = concat!(
        "d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531",
        "016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f",
        "6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f",
        "1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928"
    );

    fn prf_key_expansion() -> Vec<u8> {
        let secret = hex(PRF_SECRET);
        let mut seed = hex(PRF_SERVER_RANDOM);
        seed.extend_from_slice(&hex(PRF_CLIENT_RANDOM));
        let mut out = vec![0u8; 128];
        // SAFETY: `tls12_prf` uses a static digest and every buffer is this frame's slice.
        let r = unsafe { tls12_prf(0, &secret, b"key expansion", &seed, &mut out) };
        assert_eq!(r, 1);
        out
    }

    /// The full 128-byte key-expansion PRF output (four HMAC blocks) against the NIST vector.
    #[test]
    fn tls12_prf_matches_nist_key_expansion_vector() {
        assert_eq!(prf_key_expansion(), hex(PRF_OUTPUT));
    }

    /// `key_block` derivation and the client/server key/IV offset split against the same
    /// vector: `client_write_key || server_write_key || client_write_IV || server_write_IV`.
    #[test]
    fn key_block_and_install_match_nist_vector() {
        let expected = hex(PRF_OUTPUT);
        let key_len = 32;
        // SAFETY: `s` is a live zeroed block owned here; its master secret and randoms are set
        // before use and the block is released once at the end.
        let (block, block_len) = unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).tls12_md_kind = 0;
            (*s).cipher_key_len = key_len;
            (*s).cipher_tag_len = 16;
            let master: &mut [u8; SSL_MAX_MASTER_KEY_LENGTH] = &mut (*s).tls12_master_secret;
            master.copy_from_slice(&hex(PRF_SECRET));
            let server_random: &mut [u8; 32] = &mut (*s).server_random;
            server_random.copy_from_slice(&hex(PRF_SERVER_RANDOM));
            let client_random: &mut [u8; 32] = &mut (*s).client_random;
            client_random.copy_from_slice(&hex(PRF_CLIENT_RANDOM));
            assert_eq!(tls12_derive_key_block(s), 1);
            assert_eq!(
                (*s).tls12_key_block_len,
                2 * key_len + 2 * TLS12_FIXED_IV_LEN
            );
            assert_eq!(tls12_install_write(s, true), 1);
            assert_eq!(&(&(*s).enc_key)[..key_len], &expected[..key_len]);
            assert_eq!(
                &(&(*s).enc_iv)[..TLS12_FIXED_IV_LEN],
                &expected[2 * key_len..2 * key_len + TLS12_FIXED_IV_LEN]
            );
            assert_eq!(tls12_install_read(s, true), 1);
            assert_eq!(&(&(*s).dec_key)[..key_len], &expected[key_len..2 * key_len]);
            assert_eq!(
                &(&(*s).dec_iv)[..TLS12_FIXED_IV_LEN],
                &expected[2 * key_len + TLS12_FIXED_IV_LEN..2 * key_len + 2 * TLS12_FIXED_IV_LEN]
            );
            let block = (*s).tls12_key_block;
            let block_len = (*s).tls12_key_block_len;
            CRYPTO_free(s.cast(), ptr::null(), 0);
            (block, block_len)
        };
        assert_eq!(&block[..block_len], &expected[..block_len]);
    }

    fn aead_ssl(key: &[u8], iv: &[u8], seq: u64) -> *mut Ssl {
        // SAFETY: the caller runs this inside its own unsafe block and releases the block.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).tls13_cipher = crate::evp::e_aes::EVP_aes_128_gcm().cast_mut().cast();
            (*s).cipher_key_len = key.len();
            (*s).cipher_tag_len = 16;
            (*s).cipher_iv_len = TLS12_FIXED_IV_LEN;
            (&mut (*s).enc_key)[..key.len()].copy_from_slice(key);
            (&mut (*s).dec_key)[..key.len()].copy_from_slice(key);
            (&mut (*s).enc_iv)[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
            (&mut (*s).dec_iv)[..TLS12_FIXED_IV_LEN].copy_from_slice(iv);
            (*s).enc_seq = seq;
            (*s).dec_seq = seq;
            s
        }
    }

    const AEAD_KEY: &str = "000102030405060708090a0b0c0d0e0f";
    const AEAD_IV: &str = "a1a2a3a4";
    const AEAD_SEQ: u64 = 7;

    fn seal_record(plain: &[u8], content_type: u8) -> Vec<u8> {
        let key = hex(AEAD_KEY);
        let iv = hex(AEAD_IV);
        let mut rec = vec![0u8; 5 + 8 + plain.len() + 16];
        // SAFETY: `s` is a live fixture; the plaintext and record buffers are this frame's.
        unsafe {
            let s = aead_ssl(&key, &iv, AEAD_SEQ);
            let n = tls12_encrypt_record(
                s,
                content_type,
                plain.as_ptr(),
                plain.len(),
                rec.as_mut_ptr(),
            );
            assert_eq!((*s).enc_seq, AEAD_SEQ + 1);
            CRYPTO_free(s.cast(), ptr::null(), 0);
            assert!(n > 0);
            rec.truncate(n as usize);
        }
        rec
    }

    struct Opened {
        rc: isize,
        out: Vec<u8>,
        content_type: u8,
        seq: u64,
    }

    fn open_record(body: &[u8], content_type: u8, out_cap: usize) -> Opened {
        let key = hex(AEAD_KEY);
        let iv = hex(AEAD_IV);
        let mut hdr = [0u8; 5];
        hdr[0] = content_type;
        hdr[1] = 3;
        hdr[2] = 3;
        hdr[3] = (body.len() >> 8) as u8;
        hdr[4] = body.len() as u8;
        let mut out = vec![0u8; out_cap + 1];
        out[out_cap] = 0xAA;
        let mut got_type = 0u8;
        // SAFETY: `s` is a live fixture; `body`/`hdr` are slices; `out` carries a canary.
        let (rc, seq_after) = unsafe {
            let s = aead_ssl(&key, &iv, AEAD_SEQ);
            let rc = tls12_decrypt_record(
                s,
                &hdr,
                body.as_ptr(),
                body.len(),
                out.as_mut_ptr(),
                out_cap,
                &mut got_type,
            );
            let seq_after = (*s).dec_seq;
            CRYPTO_free(s.cast(), ptr::null(), 0);
            (rc, seq_after)
        };
        assert_eq!(out[out_cap], 0xAA, "no write past out_cap");
        out.truncate(out_cap);
        Opened {
            rc,
            out,
            content_type: got_type,
            seq: seq_after,
        }
    }

    /// Exact seal/open round trip for fixed key, IV and sequence: header, explicit nonce `= seq`,
    /// lengths and tag placement are byte-exact, and opening returns the original plaintext.
    #[test]
    fn seal_open_round_trip_is_exact() {
        let plain = b"TLS 1.2 record";
        let rec = seal_record(plain, 23);
        assert_eq!(rec.len(), 5 + 8 + plain.len() + 16);
        assert_eq!(&rec[..3], &[23, 3, 3]);
        assert_eq!(&rec[3..5], &((8 + plain.len() + 16) as u16).to_be_bytes());
        assert_eq!(&rec[5..13], &AEAD_SEQ.to_be_bytes());
        let opened = open_record(&rec[5..], 23, 16384);
        assert_eq!(opened.rc, plain.len() as isize);
        assert_eq!(&opened.out[..plain.len()], plain);
        assert_eq!(opened.content_type, 23);
        assert_eq!(opened.seq, AEAD_SEQ + 1);
    }

    /// A tampered tag is the single record failure code `-1`, with no sequence advance and no
    /// plaintext in the caller's buffer (the caller maps `-1` to `bad_record_mac`).
    #[test]
    fn open_rejects_tampered_tag_without_sequence_advance() {
        let plain = b"authenticated";
        let mut rec = seal_record(plain, 23);
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        let opened = open_record(&rec[5..], 23, 16384);
        assert_eq!(opened.rc, -1);
        assert_eq!(opened.seq, AEAD_SEQ);
        assert!(
            opened.out.iter().all(|b| *b == 0),
            "no unauthenticated plaintext"
        );
    }

    /// The reduced path is AES-GCM only, which has no TLS padding field: content bytes are
    /// returned verbatim, including an all-zero (padding-looking) payload.
    #[test]
    fn open_preserves_zero_content_no_tls12_padding() {
        let plain = [0u8; 32];
        let rec = seal_record(&plain, 23);
        let opened = open_record(&rec[5..], 23, 16384);
        assert_eq!(opened.rc, plain.len() as isize);
        assert_eq!(&opened.out[..plain.len()], &plain[..]);
    }

    /// The 16 KiB maximum fragment seals and opens unchanged.
    #[test]
    fn max_size_record_round_trips() {
        let plain: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
        let rec = seal_record(&plain, 23);
        assert_eq!(rec.len(), 5 + 8 + 16384 + 16);
        let opened = open_record(&rec[5..], 23, 16384);
        assert_eq!(opened.rc, 16384);
        assert_eq!(opened.out, plain);
        assert_eq!(opened.seq, AEAD_SEQ + 1);
    }

    /// Zero-length application data seals the eight-byte explicit nonce and tag only.
    #[test]
    fn zero_length_plaintext_round_trips() {
        let rec = seal_record(&[], 23);
        assert_eq!(rec.len(), 5 + 8 + 16);
        let opened = open_record(&rec[5..], 23, 0);
        assert_eq!(opened.rc, 0);
        assert!(opened.out.is_empty());
        assert_eq!(opened.seq, AEAD_SEQ + 1);
    }

    /// A caller buffer shorter than the plaintext is refused before decryption, with no write
    /// and no sequence advance.
    #[test]
    fn open_rejects_too_small_output() {
        let plain = b"too small";
        let rec = seal_record(plain, 23);
        let opened = open_record(&rec[5..], 23, plain.len() - 1);
        assert_eq!(opened.rc, -1);
        assert_eq!(opened.seq, AEAD_SEQ);
        assert!(opened.out.iter().all(|b| *b == 0));
    }
}
