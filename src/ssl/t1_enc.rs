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

/// The reduced TLS1.2 record cipher: `(name, key_len, tag_len, md_kind)` for the four
/// `ECDHE-{RSA,ECDSA}-AES{128,256}-GCM` suites (`ssl_cipher_get_evp`, `t1_enc.c`).
fn cipher_for_id(id: u16) -> Option<(&'static [u8], usize, usize, c_int)> {
    match id {
        0xc02b | 0xc02f => Some((b"AES-128-GCM\0", 16, 16, 0)),
        0xc02c | 0xc030 => Some((b"AES-256-GCM\0", 32, 16, 1)),
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
            let propq = (*(*s).ctx).propq;
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
/// # Safety
/// `secret` readable for `secret_len`; `seed` readable; `out` writable for `out_len`.
unsafe fn p_hash(
    md: *const crate::evp::digest::EvpMd,
    secret: *const u8,
    secret_len: usize,
    seed: &[u8],
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if secret_len > c_int::MAX as usize || seed.len() > 255 {
        return 0;
    }
    // SAFETY: `md` is live.
    let hash_len = unsafe { EVP_MD_get_size(md) } as usize;
    if hash_len == 0 || hash_len > HASH_MAX {
        return 0;
    }
    // `A(1) = HMAC_hash(secret, seed)`.
    let mut a = [0u8; HASH_MAX];
    let mut alen: c_uint = 0;
    // SAFETY: `secret`/`seed` readable; `a` writable.
    if unsafe {
        HMAC(
            md,
            secret.cast(),
            secret_len as c_int,
            seed.as_ptr(),
            seed.len(),
            a.as_mut_ptr(),
            &mut alen,
        )
    }
    .is_null()
    {
        return 0;
    }
    let mut buf = [0u8; HASH_MAX + 255];
    let mut off = 0usize;
    while off < out_len {
        let mut blen = alen as usize;
        buf[..blen].copy_from_slice(&a[..blen]);
        buf[blen..blen + seed.len()].copy_from_slice(seed);
        blen += seed.len();
        let mut h = [0u8; HASH_MAX];
        let mut hlen: c_uint = 0;
        // SAFETY: `secret`/`buf` readable; `h` writable.
        if unsafe {
            HMAC(
                md,
                secret.cast(),
                secret_len as c_int,
                buf.as_ptr(),
                blen,
                h.as_mut_ptr(),
                &mut hlen,
            )
        }
        .is_null()
        {
            return 0;
        }
        let take = (out_len - off).min(hlen as usize);
        // SAFETY: `out` has `out_len` writable bytes; `off + take <= out_len`.
        unsafe { ptr::copy_nonoverlapping(h.as_ptr(), out.add(off), take) };
        off += take;
        // `A(i+1) = HMAC_hash(secret, A(i))`.
        let mut alen2: c_uint = 0;
        // SAFETY: `secret`/`a` readable; `a` writable.
        if unsafe {
            HMAC(
                md,
                secret.cast(),
                secret_len as c_int,
                a.as_ptr(),
                hash_len,
                a.as_mut_ptr(),
                &mut alen2,
            )
        }
        .is_null()
        {
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
/// `secret` readable for `secret_len`; `seed` readable; `out` writable for `out_len`.
unsafe fn tls12_prf(
    md_kind: c_int,
    secret: *const u8,
    secret_len: usize,
    label: &[u8],
    seed: &[u8],
    out: *mut u8,
    out_len: usize,
) -> c_int {
    if label.len() + seed.len() > 255 {
        return 0;
    }
    let mut ls = [0u8; 255];
    ls[..label.len()].copy_from_slice(label);
    ls[label.len()..label.len() + seed.len()].copy_from_slice(seed);
    // SAFETY: `secret`/`ls` readable; `out` writable.
    unsafe {
        p_hash(
            prf_md(md_kind),
            secret,
            secret_len,
            &ls[..label.len() + seed.len()],
            out,
            out_len,
        )
    }
}

/// `tls1_generate_master_secret(SSL_CONNECTION *s, unsigned char *out, unsigned char *pms,
/// size_t pmslen, ...)` — `ssl/t1_enc.c:267-275`: `master = PRF(pms, "master secret",
/// client_random || server_random, 48)`. The extended-master-secret arm is not taken (the reduced
/// ServerHello does not echo `extended_master_secret`).
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
    let mut seed = [0u8; 64];
    // SAFETY: `s` is live; both randoms are 32-byte arrays.
    unsafe {
        seed[..32].copy_from_slice(&(*s).client_random);
        seed[32..].copy_from_slice(&(*s).server_random);
    }
    // SAFETY: `s` is live; `pms`/`seed` readable; the master buffer is 48 writable bytes.
    unsafe {
        tls12_prf(
            md_kind,
            pms,
            pmslen,
            b"master secret",
            &seed,
            (*s).tls12_master_secret.as_mut_ptr(),
            SSL_MAX_MASTER_KEY_LENGTH,
        )
    }
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
    let total = 2 * key_len + 2 * TLS12_FIXED_IV_LEN;
    // SAFETY: `s` is live; `tls12_key_block` is 128 bytes and `total <= 2*32+8`.
    if total > unsafe { (*s).tls12_key_block.len() } {
        return 0;
    }
    let mut seed = [0u8; 64];
    // SAFETY: `s` is live.
    unsafe {
        seed[..32].copy_from_slice(&(*s).server_random);
        seed[32..].copy_from_slice(&(*s).client_random);
    }
    // SAFETY: `s` is live; the master secret is 48 readable bytes; the key block is writable.
    let r = unsafe {
        tls12_prf(
            md_kind,
            (*s).tls12_master_secret.as_ptr(),
            SSL_MAX_MASTER_KEY_LENGTH,
            b"key expansion",
            &seed,
            (*s).tls12_key_block.as_mut_ptr(),
            total,
        )
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
    // SAFETY: `s` is live.
    let kb_len = unsafe { (*s).tls12_key_block_len };
    if key_len == 0 || kb_len < 2 * key_len + 2 * TLS12_FIXED_IV_LEN {
        return 0;
    }
    let (koff, ioff) = if is_client {
        (0usize, 2 * key_len)
    } else {
        (key_len, 2 * key_len + TLS12_FIXED_IV_LEN)
    };
    // SAFETY: `s` is live; the offsets are within the block and the destination arrays.
    unsafe {
        ptr::copy_nonoverlapping(
            (*s).tls12_key_block.as_ptr().add(koff),
            (*s).enc_key.as_mut_ptr(),
            key_len,
        );
        ptr::copy_nonoverlapping(
            (*s).tls12_key_block.as_ptr().add(ioff),
            (*s).enc_iv.as_mut_ptr(),
            TLS12_FIXED_IV_LEN,
        );
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
    // SAFETY: `s` is live.
    let kb_len = unsafe { (*s).tls12_key_block_len };
    if key_len == 0 || kb_len < 2 * key_len + 2 * TLS12_FIXED_IV_LEN {
        return 0;
    }
    // The peer's write direction is this side's read direction.
    let (koff, ioff) = if is_client {
        (key_len, 2 * key_len + TLS12_FIXED_IV_LEN)
    } else {
        (0usize, 2 * key_len)
    };
    // SAFETY: `s` is live; the offsets are within the block and the destination arrays.
    unsafe {
        ptr::copy_nonoverlapping(
            (*s).tls12_key_block.as_ptr().add(koff),
            (*s).dec_key.as_mut_ptr(),
            key_len,
        );
        ptr::copy_nonoverlapping(
            (*s).tls12_key_block.as_ptr().add(ioff),
            (*s).dec_iv.as_mut_ptr(),
            TLS12_FIXED_IV_LEN,
        );
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
    // SAFETY: `s` is live; the master secret is 48 readable bytes; `out` is writable for 12.
    if unsafe {
        tls12_prf(
            md_kind,
            (*s).tls12_master_secret.as_ptr(),
            SSL_MAX_MASTER_KEY_LENGTH,
            label,
            &hash[..hash_len],
            out,
            12,
        )
    } == 0
    {
        return 0;
    }
    12
}

/// The TLS1.2 AEAD `additional_data` (`tls1_enc`, `ssl/t1_enc.c`):
/// `seq_num(8) || type(1) || version(2) || length(2)`.
fn tls12_aad(seq: u64, content_type: u8, plain_len: usize, aad: &mut [u8; 13]) {
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = content_type;
    aad[9] = (TLS1_2_VERSION >> 8) as u8;
    aad[10] = TLS1_2_VERSION as u8;
    aad[11] = (plain_len >> 8) as u8;
    aad[12] = plain_len as u8;
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
    // SAFETY: `s` is live.
    unsafe {
        let key_len = (*s).cipher_key_len;
        let tag_len = (*s).cipher_tag_len;
        if key_len == 0 || tag_len == 0 {
            return -1;
        }
        let seq = (*s).enc_seq;
        let seqb = seq.to_be_bytes();
        let nonce = tls12_nonce(&(*s).enc_iv, seq);
        let mut aad = [0u8; 13];
        tls12_aad(seq, content_type, len, &mut aad);
        let rec_len = TLS12_EXPLICIT_IV_LEN + len + tag_len;
        if rec_len > 0xffff {
            return -1;
        }
        // Header + explicit nonce.
        out.write(content_type);
        out.add(1).write((TLS1_2_VERSION >> 8) as u8);
        out.add(2).write(TLS1_2_VERSION as u8);
        out.add(3).write((rec_len >> 8) as u8);
        out.add(4).write(rec_len as u8);
        ptr::copy_nonoverlapping(seqb.as_ptr(), out.add(5), TLS12_EXPLICIT_IV_LEN);

        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return -1;
        }
        let mut ok = false;
        let mut ctlen: c_int = 0;
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
            let body = out.add(5 + TLS12_EXPLICIT_IV_LEN);
            let mut l: c_int = 0;
            let aad_ok = EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut l, aad.as_ptr(), 13);
            let enc_ok = if aad_ok == 1 {
                EVP_EncryptUpdate(ctx, body, &mut ctlen, plain, len as c_int)
            } else {
                0
            };
            let mut fl: c_int = 0;
            let fin_ok = if enc_ok == 1 {
                EVP_EncryptFinal_ex(ctx, body.add(ctlen as usize), &mut fl)
            } else {
                0
            };
            ctlen += fl;
            let tag_ok = EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_GET_TAG,
                tag_len as c_int,
                body.add(ctlen as usize).cast(),
            );
            if enc_ok == 1 && fin_ok == 1 && tag_ok == 1 {
                (*s).enc_seq += 1;
                ok = true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        if ok {
            (5 + rec_len) as isize
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
    // SAFETY: `s` is live.
    unsafe {
        let tag_len = (*s).cipher_tag_len;
        if ct_len < TLS12_EXPLICIT_IV_LEN + tag_len {
            return -1;
        }
        let body_len = ct_len - TLS12_EXPLICIT_IV_LEN - tag_len;
        if body_len > out_cap {
            return -1;
        }
        let mut explicit = [0u8; TLS12_EXPLICIT_IV_LEN];
        ptr::copy_nonoverlapping(ct, explicit.as_mut_ptr(), TLS12_EXPLICIT_IV_LEN);
        let mut nonce = [0u8; 12];
        ptr::copy_nonoverlapping((*s).dec_iv.as_ptr(), nonce.as_mut_ptr(), TLS12_FIXED_IV_LEN);
        nonce[TLS12_FIXED_IV_LEN..].copy_from_slice(&explicit);
        let mut aad = [0u8; 13];
        tls12_aad((*s).dec_seq, hdr[0], body_len, &mut aad);
        let body = ct.add(TLS12_EXPLICIT_IV_LEN);

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
                EVP_DecryptUpdate(ctx, out, &mut outl, body, body_len as c_int)
            } else {
                0
            };
            let tag_ok = EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_TAG,
                tag_len as c_int,
                body.add(body_len).cast_mut().cast(),
            );
            let mut fl: c_int = 0;
            let fin_ok = if dec_ok == 1 && tag_ok == 1 {
                EVP_DecryptFinal_ex(ctx, out.add(outl as usize), &mut fl)
            } else {
                0
            };
            outl += fl;
            if dec_ok == 1 && fin_ok == 1 {
                (*s).dec_seq += 1;
                ok = true;
            }
        }
        EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return -1;
        }
        *content_type = hdr[0];
        outl as isize
    }
}
