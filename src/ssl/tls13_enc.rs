//! Phase 17.2c — `ssl/tls13_enc.c` and the record-protection half of `ssl/t1_enc.c`: the
//! reduced TLS 1.3 key schedule.
//!
//! 17.2a landed the client's `ClientHello` and 17.2b the server's `ServerHello`, both over a
//! plaintext record write/read. Neither side could produce a handshake traffic key, so the server
//! stopped at `TLS_ST_SW_ENCRYPTED_EXTENSIONS` and the client at `TLS_ST_CR_SRVR_HELLO`. This
//! module lands the key schedule the authority's `ssl/tls13_enc.c` owns, reduced to the one path a
//! fresh, non-resuming, non-HelloRetryRequest `TLS_method` flight takes:
//!
//! * **HKDF.** [`hkdf_extract`] is `HKDF-Extract` (`hkdf.c:1044`); [`hkdf_expand`] is
//!   `HKDF-Expand` (`hkdf.c:1104`); [`hkdf_expand_label`] builds the authority's `HkdfLabel`
//!   (`prov_tls13_hkdf_expand`, `hkdf.c:1212`) and runs the expand. The provider's
//!   `EVP_KDF`-based `tls13_hkdf_expand_ex` (`tls13_enc.c:33`) is the same operation; the reduced
//!   form calls HMAC directly through the crate's `HMAC` (`crypto/hmac/hmac.c`).
//! * **Secrets.** [`tls13_generate_secret`] is `tls13_generate_secret` (`tls13_enc.c:164`) —
//!   `Derive-Secret(prevsecret, "derived", Hash(""))` then `HKDF-Extract` — and the early/
//!   handshake/master wrappers are `tls13_generate_secret`'s three callers (`ssl_gensecret`,
//!   `s3_lib.c:5448`; `tls13_generate_handshake_secret`, `tls13_enc.c:231`;
//!   `tls13_generate_master_secret`, `tls13_enc.c:246`).
//! * **Traffic secrets and keys.** [`tls13_derive_handshake_traffic`] and
//!   [`tls13_derive_application_traffic`] are the `"c hs traffic"`/`"s hs traffic"` and
//!   `"c ap traffic"`/`"s ap traffic"` arms of `tls13_change_cipher_state` (`tls13_enc.c:608-661`),
//!   and [`tls13_change_cipher_state`] installs the derived key/IV (`derive_secret_key_and_iv`,
//!   `tls13_enc.c:348`; `tls13_derive_key`/`tls13_derive_iv`, `tls13_enc.c:122/137`).
//! * **Finished.** [`tls13_finished_mac`] is `tls13_final_finish_mac` (`tls13_enc.c:267`): the
//!   `"finished"` key over the transcript hash, `HMAC`ed.
//! * **Records.** [`tls13_encrypt_record`]/[`tls13_decrypt_record`] are the AEAD half of
//!   `tls13_enc`/`tls13_dec` (`ssl/record/methods/tls13_meth.c`): `type || version || length`
//!   here is the authority's AEAD AAD, and the inner content type is the trailing non-zero byte of
//!   the plaintext.
//!
//! ## Named boundaries (recorded, not fabricated)
//!
//! * **The cipher is the reduced three-suite TLS1.3 table.** [`cipher_for_id`] names the
//!   `AES-128-GCM`/`AES-256-GCM`/`ChaCha20-Poly1305` rows and the SHA256/SHA384 hash each selects
//!   (`ssl_cipher_get_evp`, `t1_enc.c`); the CCM suites, the NULL cipher and the legacy MAC path
//!   are not built.
//! * **The transcript is buffered, then replayed.** The authority holds unhashed records in
//!   `s3.handshake_buffer` and calls `ssl3_digest_cached_records` (`s3_enc.c`) once the cipher is
//!   known; the reduced schedule buffers on the connection ([`transcript_update`]) and replays on
//!   [`tls13_init_transcript`], which is the same observable over the one small flight.
//! * **PSK, early data, HelloRetryRequest, key update and the exporter/resumption masters are not
//!   derived.** No connection in the probe resumes or sends early data; `ssl_update_key`,
//!   `tls13_update_key` (`tls13_enc.c:771`) and the `res master`/`exp master` arms are named here
//!   rather than built.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_get_size, EvpMd,
};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::legacy_sha::{EVP_sha256, EVP_sha384};
use crate::evp::pkey::{EVP_PKEY_new_raw_public_key_ex, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey};
use crate::mac::hmac::HMAC;
use crate::ssl::ssl_lib::{Ssl, TLS13_HS_BUF_LEN};

// --- `ssl3.h` change-cipher-state selectors ------------------------------------------------
/// `SSL3_CC_READ` — `ssl3.h:342`.
pub(crate) const SSL3_CC_READ: c_int = 0x001;
/// `SSL3_CC_WRITE` — `ssl3.h:343`.
pub(crate) const SSL3_CC_WRITE: c_int = 0x002;
/// `SSL3_CC_CLIENT` — `ssl3.h:344`.
pub(crate) const SSL3_CC_CLIENT: c_int = 0x010;
/// `SSL3_CC_SERVER` — `ssl3.h:345`.
pub(crate) const SSL3_CC_SERVER: c_int = 0x020;
/// `SSL3_CC_HANDSHAKE` — `ssl3.h:347`.
pub(crate) const SSL3_CC_HANDSHAKE: c_int = 0x080;
/// `SSL3_CC_APPLICATION` — `ssl3.h:348`.
pub(crate) const SSL3_CC_APPLICATION: c_int = 0x100;
/// `SSL3_CHANGE_CIPHER_CLIENT_WRITE` — `ssl3.h:349`.
pub(crate) const SSL3_CHANGE_CIPHER_CLIENT_WRITE: c_int = SSL3_CC_CLIENT | SSL3_CC_WRITE;
/// `SSL3_CHANGE_CIPHER_SERVER_READ` — `ssl3.h:350`.
pub(crate) const SSL3_CHANGE_CIPHER_SERVER_READ: c_int = SSL3_CC_SERVER | SSL3_CC_READ;
/// `SSL3_CHANGE_CIPHER_CLIENT_READ` — `ssl3.h:351`.
pub(crate) const SSL3_CHANGE_CIPHER_CLIENT_READ: c_int = SSL3_CC_CLIENT | SSL3_CC_READ;
/// `SSL3_CHANGE_CIPHER_SERVER_WRITE` — `ssl3.h:352`.
pub(crate) const SSL3_CHANGE_CIPHER_SERVER_WRITE: c_int = SSL3_CC_SERVER | SSL3_CC_WRITE;

/// `TLS1_2_VERSION` — `ssl3.h`. TLS 1.3 protected records carry `0x0303` as `legacy_record_version`
/// (`rec_layer_s3.c`: *"The record version for TLS1.3 is always TLS1.2"*; RFC 8446 §5.1).
const TLS1_2_VERSION: c_int = 0x0303;
/// `SSL3_RT_APPLICATION_DATA` — `ssl3.h` (23): the outer type of every TLS1.3 protected record.
const SSL3_RT_APPLICATION_DATA: u8 = 23;
/// `EVP_CTRL_AEAD_SET_IVLEN` — `evp.h:388`.
const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
/// `EVP_CTRL_AEAD_GET_TAG` — `evp.h:389`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `EVP_CTRL_AEAD_SET_TAG` — `evp.h:390`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// The three-suite reduced cipher record: `(name, key_len, iv_len, tag_len, md_kind)`.
///
/// `md_kind` is 0 for SHA256 and 1 for SHA384, the mapping `ssl_cipher_get_evp` (`t1_enc.c`) makes
/// from `SSL_CIPHER.algorithm2`.
fn cipher_for_id(id: u16) -> Option<(&'static [u8], usize, usize, usize, c_int)> {
    match id {
        0x1301 => Some((b"AES-128-GCM\0", 16, 12, 16, 0)),
        0x1302 => Some((b"AES-256-GCM\0", 32, 12, 16, 1)),
        0x1303 => Some((b"ChaCha20-Poly1305\0", 32, 12, 16, 0)),
        _ => None,
    }
}

/// `const EVP_MD *ssl_handshake_md(SSL_CONNECTION *s)` — the reduced md selector.
fn handshake_md(s: *const Ssl) -> *const EvpMd {
    // SAFETY: the caller passes a live connection.
    if unsafe { (*s).hs_md_kind } == 1 {
        EVP_sha384()
    } else {
        EVP_sha256()
    }
}

/// `int HKDF_Extract(...)` — `hkdf.c:1044-1057`: `PRK = HMAC-Hash(salt, IKM)`.
///
/// # Safety
/// `md` is live; `salt`/`ikm` are readable for their lengths; `out` is writable for the md size.
unsafe fn hkdf_extract(
    md: *const EvpMd,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    out: *mut u8,
) -> c_int {
    let mut l: c_uint = 0;
    // SAFETY: the arguments are the caller's under this function's contract.
    let r = unsafe {
        HMAC(
            md,
            salt.cast(),
            salt_len as c_int,
            ikm.cast(),
            ikm_len,
            out.cast(),
            &mut l,
        )
    };
    c_int::from(!r.is_null())
}

/// `int HKDF_Expand(...)` — `hkdf.c:1104-1167`: `T(i) = HMAC-Hash(PRK, T(i-1) | info | i)`.
///
/// # Safety
/// `md` is live; `prk`/`info` readable; `out` writable for `out_len`.
unsafe fn hkdf_expand(
    md: *const EvpMd,
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: `md` is live.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hash_len = sz as usize;
    let n = out_len.div_ceil(hash_len);
    if n > 255 {
        return 0;
    }
    let mut t = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    let mut done: usize = 0;
    let mut i: u8 = 1;
    while done < out_len {
        // `T(i-1) | info | i`, the authority's three `HMAC_Update`s.
        let mut buf = [0u8; 512];
        let mut p = 0usize;
        if i > 1 {
            // SAFETY: `t` is `hash_len` initialised bytes from the previous iteration.
            unsafe { ptr::copy_nonoverlapping(t.as_ptr(), buf.as_mut_ptr(), hash_len) };
            p += hash_len;
        }
        if info_len != 0 {
            // SAFETY: `info` is readable for `info_len`; `buf` has room.
            unsafe { ptr::copy_nonoverlapping(info, buf.as_mut_ptr().add(p), info_len) };
            p += info_len;
        }
        buf[p] = i;
        p += 1;

        let mut l: c_uint = 0;
        // SAFETY: `prk` is the caller's; `buf` is initialised for `p`; `t` is writable.
        let r = unsafe {
            HMAC(
                md,
                prk.cast(),
                prk_len as c_int,
                buf.as_ptr(),
                p,
                t.as_mut_ptr(),
                &mut l,
            )
        };
        if r.is_null() {
            return 0;
        }
        let take = core::cmp::min(hash_len, out_len - done);
        // SAFETY: `out` is writable for `out_len`; `take <= hash_len`.
        unsafe { ptr::copy_nonoverlapping(t.as_ptr(), out.add(done), take) };
        done += take;
        i += 1;
    }
    1
}

/// `static int prov_tls13_hkdf_expand(...)` — `hkdf.c:1212-1246`, the `HkdfLabel` it packs.
///
/// # Safety
/// `md` is live; `secret` readable for `secret_len`; `context` readable for `context_len` when
/// non-NULL; `out` writable for `out_len`.
#[allow(clippy::too_many_arguments)] // mirrors `prov_tls13_hkdf_expand`'s signature exactly
unsafe fn hkdf_expand_label(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    label: &[u8],
    context: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // ASCII "tls13 ", the authority's `label_prefix` (`tls13_enc.c:23`).
    const PREFIX: &[u8] = b"tls13 ";
    let mut info = [0u8; 512];
    let mut p = 0usize;
    info[p] = (out_len >> 8) as u8;
    info[p + 1] = out_len as u8;
    p += 2;
    let full = PREFIX.len() + label.len();
    info[p] = full as u8;
    p += 1;
    info[p..p + PREFIX.len()].copy_from_slice(PREFIX);
    p += PREFIX.len();
    info[p..p + label.len()].copy_from_slice(label);
    p += label.len();
    info[p] = context_len as u8;
    p += 1;
    if context_len != 0 {
        // SAFETY: `context` is readable for `context_len` per the contract; `info` has room.
        unsafe { ptr::copy_nonoverlapping(context, info.as_mut_ptr().add(p), context_len) };
        p += context_len;
    }
    // SAFETY: the arguments are the caller's.
    unsafe { hkdf_expand(md, secret, secret_len, info.as_ptr(), p, out, out_len) }
}

/// `int tls13_derive_secret` — the `"derived"`/traffic-secret expand (`tls13_enc.c:348-375`).
///
/// # Safety
/// `secret` readable for `secret_len`; `hash` readable for the md size; `out` writable.
unsafe fn derive_secret(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    label: &[u8],
    hash: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: `md` is live.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    // SAFETY: the arguments are the caller's.
    unsafe {
        hkdf_expand_label(
            md,
            secret,
            secret_len,
            label,
            hash,
            sz as usize,
            out,
            sz as usize,
        )
    }
}

/// `static int tls13_derive_key(...)` — `tls13_enc.c:122-131`: the `"key"` label.
///
/// # Safety
/// The arguments are the caller's.
unsafe fn tls13_derive_key(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    key: *mut u8,
    key_len: usize,
) -> c_int {
    // SAFETY: the arguments are the caller's.
    unsafe { hkdf_expand_label(md, secret, secret_len, b"key", ptr::null(), 0, key, key_len) }
}

/// `static int tls13_derive_iv(...)` — `tls13_enc.c:137-146`: the `"iv"` label.
///
/// # Safety
/// The arguments are the caller's.
unsafe fn tls13_derive_iv(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    iv: *mut u8,
    iv_len: usize,
) -> c_int {
    // SAFETY: the arguments are the caller's.
    unsafe { hkdf_expand_label(md, secret, secret_len, b"iv", ptr::null(), 0, iv, iv_len) }
}

/// `static int tls13_derive_finishedkey(...)` — `tls13_enc.c:148-157`.
///
/// # Safety
/// The arguments are the caller's.
unsafe fn tls13_derive_finishedkey(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    fin: *mut u8,
    fin_len: usize,
) -> c_int {
    // SAFETY: the arguments are the caller's.
    unsafe {
        hkdf_expand_label(
            md,
            secret,
            secret_len,
            b"finished",
            ptr::null(),
            0,
            fin,
            fin_len,
        )
    }
}

/// `Hash("")` — the empty transcript hash `tls13_generate_secret` uses as the `"derived"` context.
///
/// # Safety
/// `md` is live; `out` writable for the md size; `out_len` writable.
unsafe fn hash_empty(md: *const EvpMd, out: *mut u8, out_len: *mut usize) -> c_int {
    // SAFETY: no preconditions.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let r = unsafe {
        let mut l: c_uint = 0;
        let r = EVP_DigestInit_ex(ctx, md, ptr::null_mut());
        let r = if r > 0 {
            EVP_DigestFinal_ex(ctx, out.cast(), &mut l)
        } else {
            r
        };
        if r > 0 && !out_len.is_null() {
            *out_len = l as usize;
        }
        r
    };
    // SAFETY: `ctx` is this frame's.
    unsafe { EVP_MD_CTX_free(ctx) };
    c_int::from(r > 0)
}

/// `int tls13_generate_secret(...)` — `tls13_enc.c:164-224`.
///
/// `prevsecret == NULL` uses a zero salt (the authority's `default_zeros`); `insecret == NULL` uses
/// a zero IKM of the hash length. The pre-extract `"derived"` step runs only when `prevsecret` is
/// given.
///
/// # Safety
/// `s` is live; the optional slices are readable; `out` writable for the md size.
pub(crate) unsafe fn tls13_generate_secret(
    s: *mut Ssl,
    prevsecret: Option<&[u8]>,
    insecret: Option<&[u8]>,
    out: *mut u8,
) -> c_int {
    // SAFETY: `s` is live.
    let md = handshake_md(s);
    // SAFETY: `md` is the live digest selector.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hash_len = sz as usize;
    let zeros = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    let mut salt = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    let salt_ptr: *const u8;
    if let Some(prev) = prevsecret {
        let mut empty_hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        // SAFETY: `md` is live; the buffers are this frame's.
        if unsafe { hash_empty(md, empty_hash.as_mut_ptr(), ptr::null_mut()) } == 0 {
            return 0;
        }
        // SAFETY: `prev` is readable; `salt` is writable.
        if unsafe {
            derive_secret(
                md,
                prev.as_ptr(),
                prev.len(),
                b"derived",
                empty_hash.as_ptr(),
                salt.as_mut_ptr(),
            )
        } == 0
        {
            return 0;
        }
        salt_ptr = salt.as_ptr();
    } else {
        salt_ptr = zeros.as_ptr();
    }
    let (ikm_ptr, ikm_len) = match insecret {
        Some(ins) => (ins.as_ptr(), ins.len()),
        None => (zeros.as_ptr(), hash_len),
    };
    // SAFETY: all pointers are live per the branches above.
    unsafe { hkdf_extract(md, salt_ptr, hash_len, ikm_ptr, ikm_len, out) }
}

/// `int ssl_gensecret(...)` — `s3_lib.c:5448-5471` for a fresh connection: the early secret from
/// the zero IKM, then the handshake secret from the shared secret.
///
/// # Safety
/// `s` is live; `pms` readable for `pms_len`.
pub(crate) unsafe fn tls13_generate_handshake_secret(s: *mut Ssl, pms: &[u8]) -> c_int {
    // SAFETY: `s` is live; the early-secret field is writable.
    let early = unsafe { (*s).early_secret.as_mut_ptr() };
    // SAFETY: `s` is live; the buffers are the connection's.
    if unsafe { tls13_generate_secret(s, None, None, early) } == 0 {
        return 0;
    }
    // SAFETY: `s` is live; the handshake-secret field is writable.
    let handshake = unsafe { (*s).handshake_secret.as_mut_ptr() };
    // SAFETY: `s` is live; `hs_md_len` is the negotiated hash length.
    let early_len = unsafe { (*s).hs_md_len };
    // SAFETY: `early` is `early_len` initialised bytes (the freshly generated early secret).
    let early_slice = unsafe { core::slice::from_raw_parts(early, early_len) };
    // SAFETY: `s` is live; `pms` is the caller's.
    unsafe { tls13_generate_secret(s, Some(early_slice), Some(pms), handshake) }
}

/// `int tls13_generate_master_secret(...)` — `tls13_enc.c:246-261`.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_generate_master_secret(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live; `hs_md_len` is the negotiated hash length.
    let hs_len = unsafe { (*s).hs_md_len };
    // SAFETY: `handshake_secret` is `hs_len` initialised bytes.
    let hs = unsafe { core::slice::from_raw_parts((*s).handshake_secret.as_ptr(), hs_len) };
    // SAFETY: `s` is live; the master-secret field is writable.
    let master = unsafe { (*s).master_secret.as_mut_ptr() };
    // SAFETY: `s` is live; `hs` is the connection's; `master` writable.
    unsafe { tls13_generate_secret(s, Some(hs), None, master) }
}

/// `ssl_handshake_md(s)->md_size` — the negotiated transcript hash length. (Retained for the
/// join to `tls13_enc.c`'s `ssl_handshake_md`.)
///
/// # Safety
/// `s` is live.
#[allow(dead_code)]
pub(crate) unsafe fn tls13_hash_len(s: *const Ssl) -> usize {
    // SAFETY: `s` is live.
    unsafe { (*s).hs_md_len }
}

// --- transcript ----------------------------------------------------------------------------

/// Buffer a handshake message, or hash it once the transcript is initialised — the authority's
/// `s3.handshake_buffer` plus `ssl_handshake_hash` (`ssl/ssl_lib.c:6094`).
///
/// # Safety
/// `s` is live; `data` readable for `len`.
pub(crate) unsafe fn transcript_update(s: *mut Ssl, data: *const u8, len: usize) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if (*s).hs_md_ctx.is_null() {
            if (*s).hs_buf_len + len > TLS13_HS_BUF_LEN {
                return 0;
            }
            ptr::copy_nonoverlapping(data, (*s).hs_buf.as_mut_ptr().add((*s).hs_buf_len), len);
            (*s).hs_buf_len += len;
            return 1;
        }
        EVP_DigestUpdate((*s).hs_md_ctx.cast(), data.cast(), len)
    }
}

/// `ssl3_digest_cached_records` (`ssl/s3_enc.c`) once the cipher (and so the hash) is known: init
/// the transcript with `md_kind` and replay the buffered bytes.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_init_transcript(s: *mut Ssl, md_kind: c_int) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if !(*s).hs_md_ctx.is_null() {
            return 1;
        }
        let md = if md_kind == 1 {
            EVP_sha384()
        } else {
            EVP_sha256()
        };
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            return 0;
        }
        if EVP_DigestInit_ex(ctx.cast(), md, ptr::null_mut()) <= 0 {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        if (*s).hs_buf_len != 0
            && EVP_DigestUpdate(ctx.cast(), (*s).hs_buf.as_ptr().cast(), (*s).hs_buf_len) <= 0
        {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        (*s).hs_md_ctx = ctx.cast();
        (*s).hs_buf_len = 0;
        (*s).hs_md_kind = md_kind;
        (*s).hs_md_len = EVP_MD_get_size(md) as usize;
    }
    1
}

/// `int tls13_save_handshake_digest_for_pha(SSL_CONNECTION *s)` — `statem_lib.c:2846-2867`:
/// snapshot the running handshake digest (which is then through the client Finished) so the PHA
/// exchange can restart the transcript from it.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_save_handshake_digest_for_pha(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if !(*s).pha_dgst.is_null() {
            return 1;
        }
        if (*s).hs_md_ctx.is_null() {
            return 0;
        }
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            return 0;
        }
        if EVP_MD_CTX_copy_ex(ctx, (*s).hs_md_ctx.cast()) <= 0 {
            EVP_MD_CTX_free(ctx);
            return 0;
        }
        (*s).pha_dgst = ctx.cast();
    }
    1
}

/// `int tls13_restore_handshake_digest_for_pha(SSL_CONNECTION *s)` — `statem_lib.c:2873-2885`:
/// restore the saved PHA digest into the running transcript.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_restore_handshake_digest_for_pha(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if (*s).pha_dgst.is_null() || (*s).hs_md_ctx.is_null() {
            return 0;
        }
        EVP_MD_CTX_copy_ex((*s).hs_md_ctx.cast(), (*s).pha_dgst.cast())
    }
}

/// `int ssl_handshake_hash(SSL_CONNECTION *s, ...)` — `ssl/ssl_lib.c:6094`: the current transcript
/// hash, without disturbing the running context (`EVP_MD_CTX_copy_ex`).
///
/// # Safety
/// `s` is live; `out` writable for the md size; `out_len` NULL or writable.
pub(crate) unsafe fn transcript_hash(s: *mut Ssl, out: *mut u8, out_len: *mut usize) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        if (*s).hs_md_ctx.is_null() {
            return 0;
        }
        let tmp = EVP_MD_CTX_new();
        if tmp.is_null() {
            return 0;
        }
        if EVP_MD_CTX_copy_ex(tmp.cast(), (*s).hs_md_ctx.cast()) <= 0 {
            EVP_MD_CTX_free(tmp);
            return 0;
        }
        let mut l: c_uint = 0;
        let r = EVP_DigestFinal_ex(tmp.cast(), out.cast(), &mut l);
        EVP_MD_CTX_free(tmp);
        if r <= 0 {
            return 0;
        }
        if !out_len.is_null() {
            *out_len = l as usize;
        }
    }
    1
}

// --- traffic secrets -----------------------------------------------------------------------

/// The `"c hs traffic"`/`"s hs traffic"` arms of `tls13_change_cipher_state` (`tls13_enc.c:608`):
/// save the `CH || SH` transcript hash, then derive both handshake traffic secrets.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_derive_handshake_traffic(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        let md = handshake_md(s);
        let hash_len = (*s).hs_md_len;
        let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        if transcript_hash(s, hash.as_mut_ptr(), ptr::null_mut()) == 0 {
            return 0;
        }
        ptr::copy_nonoverlapping(
            hash.as_ptr(),
            (*s).handshake_traffic_hash.as_mut_ptr(),
            hash_len,
        );
        let hs = core::slice::from_raw_parts((*s).handshake_secret.as_ptr(), hash_len);
        if derive_secret(
            md,
            hs.as_ptr(),
            hash_len,
            b"c hs traffic",
            hash.as_ptr(),
            (*s).client_hs_traffic.as_mut_ptr(),
        ) == 0
        {
            return 0;
        }
        derive_secret(
            md,
            hs.as_ptr(),
            hash_len,
            b"s hs traffic",
            hash.as_ptr(),
            (*s).server_hs_traffic.as_mut_ptr(),
        );
        // `ssl_log_secret` for the two handshake traffic secrets (`tls13_enc.c:718-722`).
        {
            let c = core::slice::from_raw_parts((*s).client_hs_traffic.as_ptr(), hash_len);
            let sv = core::slice::from_raw_parts((*s).server_hs_traffic.as_ptr(), hash_len);
            ssl_log_secret(s, b"CLIENT_HANDSHAKE_TRAFFIC_SECRET", c);
            ssl_log_secret(s, b"SERVER_HANDSHAKE_TRAFFIC_SECRET", sv);
        }
        1
    }
}

/// The `"c ap traffic"`/`"s ap traffic"` arms of `tls13_change_cipher_state` (`tls13_enc.c:629`/
/// `:655`): save the post-server-Finished transcript hash and derive both application traffic
/// secrets from the master secret.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_derive_application_traffic(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        let md = handshake_md(s);
        let hash_len = (*s).hs_md_len;
        let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        if transcript_hash(s, hash.as_mut_ptr(), ptr::null_mut()) == 0 {
            return 0;
        }
        ptr::copy_nonoverlapping(
            hash.as_ptr(),
            (*s).server_finished_hash.as_mut_ptr(),
            hash_len,
        );
        if tls13_generate_master_secret(s) == 0 {
            return 0;
        }
        let ms = core::slice::from_raw_parts((*s).master_secret.as_ptr(), hash_len);
        if derive_secret(
            md,
            ms.as_ptr(),
            hash_len,
            b"c ap traffic",
            hash.as_ptr(),
            (*s).client_app_traffic.as_mut_ptr(),
        ) == 0
        {
            return 0;
        }
        derive_secret(
            md,
            ms.as_ptr(),
            hash_len,
            b"s ap traffic",
            hash.as_ptr(),
            (*s).server_app_traffic.as_mut_ptr(),
        );
        // `ssl_log_secret` for the two application traffic secrets and the exporter secret
        // (`tls13_enc.c:712-724`).
        {
            let c = core::slice::from_raw_parts((*s).client_app_traffic.as_ptr(), hash_len);
            let sv = core::slice::from_raw_parts((*s).server_app_traffic.as_ptr(), hash_len);
            ssl_log_secret(s, b"CLIENT_TRAFFIC_SECRET_0", c);
            ssl_log_secret(s, b"SERVER_TRAFFIC_SECRET_0", sv);
            let mut exporter = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
            if derive_secret(
                md,
                ms.as_ptr(),
                hash_len,
                b"exp master",
                hash.as_ptr(),
                exporter.as_mut_ptr(),
            ) != 0
            {
                ssl_log_secret(s, b"EXPORTER_SECRET", &exporter[..hash_len]);
            }
        }
        1
    }
}

/// `int ssl_log_secret(SSL_CONNECTION *s, const char *label, const uint8_t *secret,`
/// `size_t secret_len)` — `ssl/ssl_lib.c:7077-7086` -> `nss_keylog_int` (`:7030-7076`).
///
/// Formats `LABEL <client_random hex> <secret hex>` and hands it to the context's
/// `SSL_CTX_set_keylog_callback`. The optional write-to-file path is not modelled; a NULL callback
/// is a no-op.
///
/// # Safety
/// `s` is live; `secret` is readable for `secret.len()`.
unsafe fn ssl_log_secret(s: *mut Ssl, label: &[u8], secret: &[u8]) {
    // SAFETY: `s` is live.
    let ctx = unsafe { (*s).ctx };
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is the live context read above.
    let Some(cb) = (unsafe { (*ctx).keylog_callback }) else {
        return;
    };
    let mut out = [0u8; 256];
    let mut n = 0usize;
    let hex = b"0123456789abcdef";
    for &b in label {
        if n < out.len() - 1 {
            out[n] = b;
            n += 1;
        }
    }
    if n < out.len() - 1 {
        out[n] = b' ';
        n += 1;
    }
    // SAFETY: `s` is live; `client_random` is the 32-byte field.
    for &b in unsafe { &(*s).client_random } {
        for hi in [b >> 4, b & 0xf] {
            if n < out.len() - 1 {
                out[n] = hex[hi as usize];
                n += 1;
            }
        }
    }
    if n < out.len() - 1 {
        out[n] = b' ';
        n += 1;
    }
    for &b in secret {
        for hi in [b >> 4, b & 0xf] {
            if n < out.len() - 1 {
                out[n] = hex[hi as usize];
                n += 1;
            }
        }
    }
    out[n] = 0;
    // SAFETY: the callback is the application's `SSL_CTX_keylog_cb_func`; `s` and the
    // NUL-terminated buffer are the ones it was installed to receive.
    unsafe { cb(s, out.as_ptr().cast::<core::ffi::c_char>()) };
}

/// `size_t tls13_final_finish_mac(...)` — `tls13_enc.c:267-317`: the `"finished"` key over the
/// current transcript hash. Returns the verify-data length (0 on error).
///
/// # Safety
/// `s` is live; `secret` readable for the hash length; `out` writable for the md size.
pub(crate) unsafe fn tls13_finished_mac(s: *mut Ssl, secret: *const u8, out: *mut u8) -> usize {
    // SAFETY: `s` is live.
    unsafe {
        let md = handshake_md(s);
        let hash_len = (*s).hs_md_len;
        let mut finsecret = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        if tls13_derive_finishedkey(md, secret, hash_len, finsecret.as_mut_ptr(), hash_len) == 0 {
            return 0;
        }
        let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        if transcript_hash(s, hash.as_mut_ptr(), ptr::null_mut()) == 0 {
            return 0;
        }
        let mut l: c_uint = 0;
        let r = HMAC(
            md,
            finsecret.as_ptr().cast(),
            hash_len as c_int,
            hash.as_ptr(),
            hash_len,
            out.cast(),
            &mut l,
        );
        if r.is_null() {
            return 0;
        }
        l as usize
    }
}

// --- installing keys -----------------------------------------------------------------------

/// The `(secret, key, iv)` a `tls13_change_cipher_state` selector names.
///
/// # Safety
/// `s` is live.
unsafe fn select_secret(s: *mut Ssl, which: c_int) -> (*const u8, bool) {
    // SAFETY: `s` is live.
    unsafe {
        let hs = (which & SSL3_CC_HANDSHAKE) != 0;
        // `(CLIENT && WRITE) || (SERVER && READ)` uses the client's secret direction, exactly as
        // `tls13_change_cipher_state` chooses (`tls13_enc.c:514-516`, `:642`).
        let client = (((which & SSL3_CC_CLIENT) != 0) && ((which & SSL3_CC_WRITE) != 0))
            || (((which & SSL3_CC_SERVER) != 0) && ((which & SSL3_CC_READ) != 0));
        let base = if hs {
            if client {
                (*s).client_hs_traffic.as_ptr()
            } else {
                (*s).server_hs_traffic.as_ptr()
            }
        } else if client {
            (*s).client_app_traffic.as_ptr()
        } else {
            (*s).server_app_traffic.as_ptr()
        };
        (base, (which & SSL3_CC_READ) != 0)
    }
}

/// `int tls13_change_cipher_state(SSL_CONNECTION *s, int which)` — `tls13_enc.c:474-769`, the
/// install half: derive the traffic key/IV (`derive_secret_key_and_iv`, `:348`) and arm the read
/// or write direction. The fetched cipher (`ssl_cipher_get_evp_cipher`) is cached on the
/// connection.
///
/// # Safety
/// `s` is live; `cipher_id` is the negotiated wire ciphersuite id.
pub(crate) unsafe fn tls13_change_cipher_state(s: *mut Ssl, which: c_int, cipher_id: u16) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        let (secret, is_read) = select_secret(s, which);
        let md = handshake_md(s);
        let hash_len = (*s).hs_md_len;
        let key_len = (*s).cipher_key_len;
        let iv_len = (*s).cipher_iv_len;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        if key_len == 0 || iv_len == 0 || key_len > key.len() || iv_len > iv.len() {
            return 0;
        }
        if tls13_derive_key(md, secret, hash_len, key.as_mut_ptr(), key_len) == 0
            || tls13_derive_iv(md, secret, hash_len, iv.as_mut_ptr(), iv_len) == 0
        {
            return 0;
        }
        let _ = cipher_id;
        if is_read {
            ptr::copy_nonoverlapping(
                key.as_ptr(),
                core::ptr::addr_of_mut!((*s).dec_key).cast::<u8>(),
                key_len,
            );
            ptr::copy_nonoverlapping(
                iv.as_ptr(),
                core::ptr::addr_of_mut!((*s).dec_iv).cast::<u8>(),
                iv_len,
            );
            (*s).dec_seq = 0;
            (*s).dec_active = 1;
        } else {
            ptr::copy_nonoverlapping(
                key.as_ptr(),
                core::ptr::addr_of_mut!((*s).enc_key).cast::<u8>(),
                key_len,
            );
            ptr::copy_nonoverlapping(
                iv.as_ptr(),
                core::ptr::addr_of_mut!((*s).enc_iv).cast::<u8>(),
                iv_len,
            );
            (*s).enc_seq = 0;
            (*s).enc_active = 1;
        }
    }
    1
}

/// `ssl_cipher_get_evp` (`t1_enc.c`) — cache the AEAD cipher and its key length for the negotiated
/// suite. `md_kind` selects the transcript hash used from here on.
///
/// # Safety
/// `s` is live.
pub(crate) unsafe fn tls13_setup_cipher(s: *mut Ssl, cipher_id: u16) -> c_int {
    let Some((name, key_len, iv_len, tag_len, md_kind)) = cipher_for_id(cipher_id) else {
        return 0;
    };
    // SAFETY: `s` is live.
    unsafe {
        if (*s).tls13_cipher.is_null() {
            let libctx = (*(*s).ctx).libctx;
            let propq = (*(*s).ctx).propq;
            let c = EVP_CIPHER_fetch(libctx, name.as_ptr().cast::<c_char>(), propq);
            if c.is_null() {
                return 0;
            }
            // The lengths are read from the fetched cipher (`EVP_CIPHER_get_key_length`), as the
            // authority's `derive_secret_key_and_iv` does.
            let klen = EVP_CIPHER_get_key_length(c);
            let ivlen = EVP_CIPHER_get_iv_length(c);
            if klen <= 0 || ivlen < 0 {
                EVP_CIPHER_free(c);
                return 0;
            }
            (*s).tls13_cipher = c.cast();
            (*s).cipher_key_len = klen as usize;
            (*s).cipher_iv_len = ivlen as usize;
            (*s).cipher_tag_len = tag_len;
        }
        let _ = key_len;
        let _ = iv_len;
        tls13_init_transcript(s, md_kind)
    }
}

/// `EVP_PKEY_new_raw_public_key_ex` for an X25519 key share (`tls1_set_peer_legacy_sigalg`/
/// `tls_parse_stoc_key_share`): wrap the peer's 32 encoded bytes in an `EVP_PKEY`.
///
/// # Safety
/// `s` is live; `bytes` readable for `len`.
pub(crate) unsafe fn tls13_pkey_from_share(
    s: *mut Ssl,
    bytes: *const u8,
    len: usize,
) -> *mut c_void {
    // SAFETY: `s` is live.
    unsafe {
        let libctx = (*(*s).ctx).libctx;
        let propq = (*(*s).ctx).propq;
        EVP_PKEY_new_raw_public_key_ex(libctx, c"X25519".as_ptr(), propq, bytes, len).cast()
    }
}

/// `int ssl_derive(...)` — `s3_lib.c:5474-5528`, the ECDH half: `shared = derive(privkey,
/// pubkey)`.
///
/// # Safety
/// `s` is live; `privkey`/`pubkey` are live keys; `out` writable for `out_cap`; `out_len`
/// writable.
pub(crate) unsafe fn tls13_derive_shared(
    s: *mut Ssl,
    privkey: *mut c_void,
    pubkey: *mut c_void,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> c_int {
    if privkey.is_null() || pubkey.is_null() {
        return 0;
    }
    // SAFETY: `s` is live.
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq) };
    // SAFETY: `privkey` is live.
    let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, privkey.cast::<EvpPkey>(), propq) };
    if pctx.is_null() {
        return 0;
    }
    let mut rv = 0;
    // SAFETY: `pctx` is live; `pubkey` is live.
    unsafe {
        if EVP_PKEY_derive_init(pctx) > 0
            && EVP_PKEY_derive_set_peer(pctx, pubkey.cast::<EvpPkey>()) > 0
        {
            let mut l = out_cap;
            if EVP_PKEY_derive(pctx, out, &mut l) > 0 {
                if !out_len.is_null() {
                    *out_len = l;
                }
                rv = 1;
            }
        }
        EVP_PKEY_CTX_free(pctx);
    }
    rv
}

// --- record protection ---------------------------------------------------------------------

/// `EVP_CTRL_AEAD_SET_IVLEN`/nonce derivation: `nonce = iv XOR seq` over the trailing 8 bytes
/// (`tls13_meth.c`, `tls13_enc`).
fn make_nonce(iv: &[u8; 16], iv_len: usize, seq: u64) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce[..iv_len].copy_from_slice(&iv[..iv_len]);
    let s = seq.to_be_bytes();
    for (i, b) in s.iter().enumerate() {
        nonce[iv_len - 8 + i] ^= *b;
    }
    nonce
}

/// `tls13_enc` (`ssl/record/methods/tls13_meth.c`): seal `plain || content_type` under the write
/// key. `out` receives the full record (`type || version || length || ciphertext || tag`); the
/// return is its total length, or -1.
///
/// # Safety
/// `s` is live; `plain` readable for `len`; `out` writable for `len + 1 + tag + 5`.
pub(crate) unsafe fn tls13_encrypt_record(
    s: *mut Ssl,
    content_type: u8,
    plain: *const u8,
    len: usize,
    out: *mut u8,
) -> isize {
    // SAFETY: `s` is live.
    unsafe {
        let tag_len = (*s).cipher_tag_len;
        let iv_len = (*s).cipher_iv_len;
        let key_len = (*s).cipher_key_len;
        let nonce = make_nonce(&(*s).enc_iv, iv_len, (*s).enc_seq);
        let inner_len = len + 1;
        let rec_len = inner_len + tag_len;
        // Header: `type || version || length`, the AEAD AAD (`tls13_enc`). The outer record version
        // is TLS 1.2 (`0x0303`), never TLS 1.3 (`rec_layer_s3.c:395-405`, RFC 8446 §5.1).
        let mut hdr = [0u8; 5];
        hdr[0] = SSL3_RT_APPLICATION_DATA;
        hdr[1] = (TLS1_2_VERSION >> 8) as u8;
        hdr[2] = TLS1_2_VERSION as u8;
        hdr[3] = (rec_len >> 8) as u8;
        hdr[4] = rec_len as u8;
        ptr::copy_nonoverlapping(hdr.as_ptr(), out, 5);
        // Inner plaintext: content then the real content type.
        let mut inner = [0u8; TLS13_HS_BUF_LEN + 1];
        ptr::copy_nonoverlapping(plain, inner.as_mut_ptr(), len);
        inner[len] = content_type;

        // SAFETY: no preconditions.
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return -1;
        }
        let mut ok = false;
        // SAFETY: `ctx` is live; the cipher/key/nonce are the connection's.
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
                iv_len as c_int,
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
            let mut l: c_int = 0;
            let aad = EVP_EncryptUpdate(ctx, ptr::null_mut(), &mut l, hdr.as_ptr(), 5);
            let body = if aad == 1 {
                EVP_EncryptUpdate(ctx, out.add(5), &mut l, inner.as_ptr(), inner_len as c_int)
            } else {
                0
            };
            let mut outl = l as usize;
            let mut fl: c_int = 0;
            let fin = if body == 1 {
                EVP_EncryptFinal_ex(ctx, out.add(5 + outl), &mut fl)
            } else {
                0
            };
            outl += fl as usize;
            let tag = EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_GET_TAG,
                tag_len as c_int,
                out.add(5 + outl).cast(),
            );
            if body == 1 && fin == 1 && tag == 1 {
                (*s).enc_seq += 1;
                ok = true;
            }
            let _ = key_len;
        }
        // SAFETY: `ctx` is this frame's.
        EVP_CIPHER_CTX_free(ctx);
        if ok {
            (5 + rec_len) as isize
        } else {
            -1
        }
    }
}

/// `tls13_dec` (`ssl/record/methods/tls13_meth.c`): open the record `hdr || ct` under the read
/// key. `out` receives the inner content; `*content_type` the inner type; the return is the inner
/// content length, or -1.
///
/// # Safety
/// `s` is live; `ct` readable for `ct_len`; `out` writable for `out_cap`; `content_type` writable.
pub(crate) unsafe fn tls13_decrypt_record(
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
        let iv_len = (*s).cipher_iv_len;
        if ct_len < tag_len {
            return -1;
        }
        let nonce = make_nonce(&(*s).dec_iv, iv_len, (*s).dec_seq);
        let ct_body_len = ct_len - tag_len;
        let mut plain = [0u8; TLS13_HS_BUF_LEN + 1];
        if ct_body_len > plain.len() {
            return -1;
        }
        // SAFETY: no preconditions.
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return -1;
        }
        let mut ok = false;
        let mut outl: usize = 0;
        // SAFETY: `ctx` is live; the cipher/key/nonce are the connection's.
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
                iv_len as c_int,
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
            let aad = EVP_DecryptUpdate(ctx, ptr::null_mut(), &mut l, hdr.as_ptr(), 5);
            let body = if aad == 1 {
                EVP_DecryptUpdate(ctx, plain.as_mut_ptr(), &mut l, ct, ct_body_len as c_int)
            } else {
                0
            };
            outl = l as usize;
            let tagset = EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_AEAD_SET_TAG,
                tag_len as c_int,
                ct.add(ct_body_len).cast_mut().cast(),
            );
            let mut fl: c_int = 0;
            let fin = if body == 1 && tagset == 1 {
                EVP_DecryptFinal_ex(ctx, plain.as_mut_ptr().add(outl), &mut fl)
            } else {
                0
            };
            outl += fl as usize;
            if body == 1 && fin == 1 {
                ok = true;
            }
        }
        // SAFETY: `ctx` is this frame's.
        EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return -1;
        }
        // Strip the record padding and read the inner content type: the last non-zero byte.
        let mut pos = outl;
        while pos > 0 && plain[pos - 1] == 0 {
            pos -= 1;
        }
        if pos == 0 {
            return -1;
        }
        let inner_type = plain[pos - 1];
        let content_len = pos - 1;
        if content_len > out_cap {
            return -1;
        }
        ptr::copy_nonoverlapping(plain.as_ptr(), out, content_len);
        *content_type = inner_type;
        (*s).dec_seq += 1;
        content_len as isize
    }
}

/// Build `mtype || length || body`, write it as one handshake record and append it to the
/// transcript (`ssl3_do_write`/`ssl3_finish_mac`, `statem.c`).
///
/// # Safety
/// `s` is live; `body` readable for `body_len`.
pub(crate) unsafe fn write_handshake_message(
    s: *mut Ssl,
    mtype: u8,
    body: *const u8,
    body_len: usize,
) -> c_int {
    // `SSL3_RT_HANDSHAKE` — `ssl3.h` (22).
    const SSL3_RT_HANDSHAKE: u8 = 22;
    let total = 4 + body_len;
    let mut msg = [0u8; 17000];
    if total > msg.len() {
        return 0;
    }
    msg[0] = mtype;
    msg[1] = (body_len >> 16) as u8;
    msg[2] = (body_len >> 8) as u8;
    msg[3] = body_len as u8;
    if body_len != 0 {
        // SAFETY: `body` is readable for `body_len` per the contract.
        unsafe { ptr::copy_nonoverlapping(body, msg.as_mut_ptr().add(4), body_len) };
    }
    // SAFETY: `s` is live; `msg` is `total` initialised bytes.
    let r = unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(
            s,
            SSL3_RT_HANDSHAKE,
            msg.as_ptr(),
            total,
        )
    };
    if r > 0 {
        // SAFETY: `s` is live; `msg` is `total` initialised bytes.
        unsafe { transcript_update(s, msg.as_ptr(), total) };
    }
    r
}

/// `size_t tls13_final_finish_mac(...)` for this side's secret, written as the Finished body
/// (`ssl3_take_mac`, `statem_lib.c:762`; `tls_construct_finished`, `statem_lib.c:618`). The
/// transcript excludes the Finished being sent, which is why the MAC is taken before
/// [`write_handshake_message`] appends it.
///
/// # Safety
/// `s` is live; `secret` readable for the hash length.
pub(crate) unsafe fn tls13_construct_finished(s: *mut Ssl, secret: *const u8) -> c_int {
    // `SSL3_MT_FINISHED` — `ssl3.h` (20).
    const SSL3_MT_FINISHED: u8 = 20;
    let mut out = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `s` is live; `out` is writable.
    let n = unsafe { tls13_finished_mac(s, secret, out.as_mut_ptr()) };
    if n == 0 {
        return 0;
    }
    // SAFETY: `s` is live; `out` is `n` initialised bytes.
    let r = unsafe { write_handshake_message(s, SSL3_MT_FINISHED, out.as_ptr(), n) };
    if r > 0 {
        // SAFETY: `s` is live.
        unsafe {
            (*s).finish_md_len = n;
            ptr::copy_nonoverlapping(out.as_ptr(), (*s).finish_md.as_mut_ptr(), n);
        }
    }
    r
}

/// `tls_process_finished`'s verify half (`statem_lib.c:843`): compare the peer's verify_data with
/// the expected `HMAC(finished_key, transcript)` taken *before* the Finished is appended.
///
/// # Safety
/// `s` is live; `msg` is the full handshake message (`type || length || body`); `secret` readable
/// for the hash length.
pub(crate) unsafe fn tls13_process_finished(s: *mut Ssl, msg: &[u8], secret: *const u8) -> c_int {
    if msg.len() < 4 {
        return 0;
    }
    let blen = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    if 4 + blen > msg.len() {
        return 0;
    }
    let body = &msg[4..4 + blen];
    let mut expected = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `s` is live; `expected` is writable.
    let n = unsafe { tls13_finished_mac(s, secret, expected.as_mut_ptr()) };
    if n == 0 || n != body.len() {
        return 0;
    }
    let mut diff = 0u8;
    for i in 0..n {
        diff |= expected[i] ^ body[i];
    }
    if diff != 0 {
        return 0;
    }
    // SAFETY: `s` is live; `msg` is the full message.
    unsafe {
        (*s).peer_finish_md_len = n;
        ptr::copy_nonoverlapping(expected.as_ptr(), (*s).peer_finish_md.as_mut_ptr(), n);
        transcript_update(s, msg.as_ptr(), msg.len())
    }
}
