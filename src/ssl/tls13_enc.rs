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
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_buf::OwnedBuf;
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

/// The largest digest the reduced schedule accepts (`EVP_MAX_MD_SIZE`).
const HASH_MAX: usize = crate::ssl::ssl_lib::EVP_MAX_MD_SIZE;
/// The largest `HkdfLabel` RFC 8446 §7.1 can encode: a two-byte output length, a
/// one-byte `"tls13 " || label` length (at most 255), and a one-byte context length
/// (at most 255) followed by that context.
const HKDF_LABEL_MAX: usize = 2 + 1 + u8::MAX as usize + 1 + u8::MAX as usize;
/// The largest `HKDF-Expand` HMAC input: `T(i-1) | info | i`.
const HKDF_EXPAND_INPUT_MAX: usize = HASH_MAX + HKDF_LABEL_MAX + 1;

/// A fixed scratch block whose contents are cleansed when it leaves scope.
///
/// [`hkdf_expand`] has several early returns (a failed HMAC, an over-long input);
/// wrapping the `T(i-1)` state and the HMAC input here wipes them on every path,
/// matching the authority's `OPENSSL_cleanse(prev, sizeof(prev))` and extending it
/// to the input buffer the authority does not hold. The crate's cleaned-free
/// instrument (`ssl::adv_alloc`) observes heap releases, so it cannot see this
/// stack block; the wipe is structural (volatile stores plus a compiler fence).
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

/// Bounds-checked writer for the `HkdfLabel` fields; the analogue of the
/// authority's `WPACKET` calls, without an unsafe byte store or a raw pointer.
struct LabelWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> LabelWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn written(&self) -> usize {
        self.pos
    }

    fn put_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.pos.checked_add(bytes.len()) else {
            return false;
        };
        let Some(dst) = self.buf.get_mut(self.pos..end) else {
            return false;
        };
        dst.copy_from_slice(bytes);
        self.pos = end;
        true
    }

    fn put_u8(&mut self, value: u8) -> bool {
        self.put_bytes(&[value])
    }

    fn put_u16(&mut self, value: u16) -> bool {
        self.put_bytes(&value.to_be_bytes())
    }
}

/// Encodes RFC 8446 §7.1's `HkdfLabel` into `info` and returns its length.
///
/// Every length is range-checked before a write and every write is a
/// bounds-checked slice copy, so a label or context that cannot be expressed in
/// its field is refused instead of truncating or overrunning the buffer. The
/// limits match `tls13_hkdf_expand_ex`'s `TLS13_MAX_LABEL_LEN` and the
/// provider's `WPACKET_*_u8`/`u16` framing.
fn encode_hkdf_label(
    out_len: usize,
    label: &[u8],
    context: &[u8],
    info: &mut [u8; HKDF_LABEL_MAX],
) -> Option<usize> {
    // ASCII "tls13 ", the authority's `label_prefix` (`tls13_enc.c:23`).
    const PREFIX: &[u8] = b"tls13 ";
    let full = PREFIX.len().checked_add(label.len())?;
    let out_len = u16::try_from(out_len).ok()?;
    let full = u8::try_from(full).ok()?;
    let context_len = u8::try_from(context.len()).ok()?;
    let mut w = LabelWriter::new(info);
    let ok = w.put_u16(out_len)
        && w.put_u8(full)
        && w.put_bytes(PREFIX)
        && w.put_bytes(label)
        && w.put_u8(context_len)
        && w.put_bytes(context);
    ok.then(|| w.written())
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
/// The interior works over slices: the `T(i-1) | info | i` assembly and the output
/// copy are bounds-checked, and both scratch blocks are cleansed on every exit.
///
/// # Safety
/// `md` is live. Every buffer is a Rust slice, so length and initialization are
/// carried by the type; `info` longer than an `HkdfLabel` is refused with 0.
unsafe fn hkdf_expand(md: *const EvpMd, prk: &[u8], info: &[u8], out: &mut [u8]) -> c_int {
    // SAFETY: `md` is live per this function's contract.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hash_len = sz as usize;
    if hash_len > HASH_MAX {
        return 0;
    }
    let n = out.len().div_ceil(hash_len);
    if n > 255 {
        return 0;
    }
    // The scratch block holds `T(i-1) | info | i`; refuse an `info` that could not
    // have come from [`encode_hkdf_label`] rather than letting an extent decide.
    if info.len() > HKDF_LABEL_MAX {
        return 0;
    }
    // `HMAC` takes the key length as `int`.
    if prk.len() > c_int::MAX as usize {
        return 0;
    }
    let mut t = CleansedBlock::<HASH_MAX>::new();
    let mut done: usize = 0;
    // Wider than `u8`: the final increment after the 255th iteration must not
    // overflow (the counter itself is always at most 255 because `n <= 255`).
    let mut i: u16 = 1;
    while done < out.len() {
        let ctr = i as u8;
        let mut buf = CleansedBlock::<HKDF_EXPAND_INPUT_MAX>::new();
        let mut p = 0usize;
        if i > 1 {
            buf.as_mut_slice()[..hash_len].copy_from_slice(&t.as_slice()[..hash_len]);
            p += hash_len;
        }
        buf.as_mut_slice()[p..p + info.len()].copy_from_slice(info);
        p += info.len();
        buf.as_mut_slice()[p..p + 1].copy_from_slice(&[ctr]);
        p += 1;

        let mut l: c_uint = 0;
        // SAFETY: `md` is live and `prk` is the caller's slice; `buf` is
        // initialised for `p` bytes; `t` is writable for the digest length.
        let r = unsafe {
            HMAC(
                md,
                prk.as_ptr().cast(),
                prk.len() as c_int,
                buf.as_slice().as_ptr(),
                p,
                t.as_mut_slice().as_mut_ptr(),
                &mut l,
            )
        };
        if r.is_null() {
            return 0;
        }
        let take = core::cmp::min(hash_len, out.len() - done);
        out[done..done + take].copy_from_slice(&t.as_slice()[..take]);
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
pub(crate) unsafe fn hkdf_expand_label(
    md: *const EvpMd,
    secret: *const u8,
    secret_len: usize,
    label: &[u8],
    context: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    // SAFETY: every pointer is the caller's under this function's contract; a NULL
    // context is only read when `context_len == 0`, which selects the empty slice.
    unsafe {
        let secret = core::slice::from_raw_parts(secret, secret_len);
        let context: &[u8] = if context_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(context, context_len)
        };
        let out = core::slice::from_raw_parts_mut(out, out_len);
        hkdf_expand_label_bytes(md, secret, label, context, out)
    }
}

/// The label construction and expand over slices; the only FFI precondition is
/// that `md` is live.
///
/// # Safety
/// `md` is live.
unsafe fn hkdf_expand_label_bytes(
    md: *const EvpMd,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> c_int {
    let mut info = [0u8; HKDF_LABEL_MAX];
    let Some(info_len) = encode_hkdf_label(out.len(), label, context, &mut info) else {
        return 0;
    };
    // SAFETY: `md` is live per this function's contract; `info` holds exactly
    // `info_len` encoded bytes.
    unsafe { hkdf_expand(md, secret, &info[..info_len], out) }
}

/// `int tls13_derive_secret` — the `"derived"`/traffic-secret expand (`tls13_enc.c:348-375`).
///
/// # Safety
/// `md` is live; `hash` and `out` must be the digest length.
unsafe fn derive_secret(
    md: *const EvpMd,
    secret: &[u8],
    label: &[u8],
    hash: &[u8],
    out: &mut [u8],
) -> c_int {
    // SAFETY: `md` is live.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hash_len = sz as usize;
    // Derive-Secret always produces and consumes `Hash.length` bytes.
    if hash.len() != hash_len || out.len() != hash_len {
        return 0;
    }
    // SAFETY: `md` is live; the lengths were just checked.
    unsafe { hkdf_expand_label_bytes(md, secret, label, hash, out) }
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
    // SAFETY: `s` is live; `md` is the connection's digest selector.
    unsafe { tls13_generate_secret_md(md, prevsecret, insecret, out) }
}

/// [`tls13_generate_secret`] with an explicit digest — used by the PSK binder, whose digest comes
/// from the session's ciphersuite before the handshake digest is known (`tls_psk_do_binder`,
/// `extensions.c:1519`).
///
/// # Safety
/// `md` is live; the optional slices are readable; `out` writable for the md size.
pub(crate) unsafe fn tls13_generate_secret_md(
    md: *const EvpMd,
    prevsecret: Option<&[u8]>,
    insecret: Option<&[u8]>,
    out: *mut u8,
) -> c_int {
    // SAFETY: `md` is live.
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
                prev,
                b"derived",
                &empty_hash[..hash_len],
                &mut salt[..hash_len],
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
    // A selected resumption PSK replaces the zero early-secret IKM (`extensions.c:1519`); an empty
    // `psk_secret_len` keeps the fresh-handshake behaviour.
    // SAFETY: `s` is live.
    let psk_len = unsafe { (*s).psk_secret_len };
    let psk_slice: Option<&[u8]> = if psk_len > 0 {
        // SAFETY: `psk_secret` is `psk_secret_len` initialised bytes when the length is non-zero.
        Some(unsafe { core::slice::from_raw_parts((*s).psk_secret.as_ptr(), psk_len) })
    } else {
        None
    };
    // SAFETY: `s` is live; the buffers are the connection's.
    if unsafe { tls13_generate_secret(s, None, psk_slice, early) } == 0 {
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
    // SAFETY: `s` is live; `data` is readable for `len` (a NULL pointer is only permitted when
    // `len == 0`, which selects the empty slice).
    unsafe {
        let data: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(data, len)
        };
        if (*s).hs_md_ctx.is_null() {
            let Some(end) = (*s).hs_buf_len.checked_add(data.len()) else {
                return 0;
            };
            let Some(dst) = (*s).hs_buf.get_mut((*s).hs_buf_len..end) else {
                return 0;
            };
            dst.copy_from_slice(data);
            (*s).hs_buf_len = end;
            return 1;
        }
        EVP_DigestUpdate((*s).hs_md_ctx.cast(), data.as_ptr().cast(), data.len())
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
        if (*s).hs_buf_len != 0 {
            // The buffered prefix is a checked slice of the fixed transcript buffer.
            let Some(buffered) = (*s).hs_buf.get(..(*s).hs_buf_len) else {
                EVP_MD_CTX_free(ctx);
                return 0;
            };
            if EVP_DigestUpdate(ctx.cast(), buffered.as_ptr().cast(), buffered.len()) <= 0 {
                EVP_MD_CTX_free(ctx);
                return 0;
            }
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
    // SAFETY: `s` is live; `out` is writable for the digest size carried by the connection.
    unsafe {
        if (*s).hs_md_ctx.is_null() {
            return 0;
        }
        let hash_len = (*s).hs_md_len;
        if hash_len == 0 || hash_len > HASH_MAX || out.is_null() {
            return 0;
        }
        let out = core::slice::from_raw_parts_mut(out, hash_len);
        let tmp = EVP_MD_CTX_new();
        if tmp.is_null() {
            return 0;
        }
        if EVP_MD_CTX_copy_ex(tmp.cast(), (*s).hs_md_ctx.cast()) <= 0 {
            EVP_MD_CTX_free(tmp);
            return 0;
        }
        let mut l: c_uint = 0;
        let r = EVP_DigestFinal_ex(tmp.cast(), out.as_mut_ptr(), &mut l);
        EVP_MD_CTX_free(tmp);
        if r <= 0 || l as usize != out.len() {
            return 0;
        }
        if !out_len.is_null() {
            *out_len = out.len();
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
        let Some(hash) = hash.get(..hash_len) else {
            return 0;
        };
        ptr::copy_nonoverlapping(
            hash.as_ptr(),
            (*s).handshake_traffic_hash.as_mut_ptr(),
            hash_len,
        );
        let hs = core::slice::from_raw_parts((*s).handshake_secret.as_ptr(), hash_len);
        let Some(out) = (*s).client_hs_traffic.get_mut(..hash_len) else {
            return 0;
        };
        if derive_secret(md, hs, b"c hs traffic", hash, out) == 0 {
            return 0;
        }
        let Some(out) = (*s).server_hs_traffic.get_mut(..hash_len) else {
            return 0;
        };
        derive_secret(md, hs, b"s hs traffic", hash, out);
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
        let Some(hash) = hash.get(..hash_len) else {
            return 0;
        };
        ptr::copy_nonoverlapping(
            hash.as_ptr(),
            (*s).server_finished_hash.as_mut_ptr(),
            hash_len,
        );
        if tls13_generate_master_secret(s) == 0 {
            return 0;
        }
        let ms = core::slice::from_raw_parts((*s).master_secret.as_ptr(), hash_len);
        let Some(out) = (*s).client_app_traffic.get_mut(..hash_len) else {
            return 0;
        };
        if derive_secret(md, ms, b"c ap traffic", hash, out) == 0 {
            return 0;
        }
        let Some(out) = (*s).server_app_traffic.get_mut(..hash_len) else {
            return 0;
        };
        derive_secret(md, ms, b"s ap traffic", hash, out);
        // `ssl_log_secret` for the two application traffic secrets and the exporter secret
        // (`tls13_enc.c:712-724`).
        {
            let c = core::slice::from_raw_parts((*s).client_app_traffic.as_ptr(), hash_len);
            let sv = core::slice::from_raw_parts((*s).server_app_traffic.as_ptr(), hash_len);
            ssl_log_secret(s, b"CLIENT_TRAFFIC_SECRET_0", c);
            ssl_log_secret(s, b"SERVER_TRAFFIC_SECRET_0", sv);
            let mut exporter = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
            let Some(out) = exporter.get_mut(..hash_len) else {
                return 0;
            };
            if derive_secret(md, ms, b"exp master", hash, out) != 0 {
                ssl_log_secret(s, b"EXPORTER_SECRET", &exporter[..hash_len]);
            }
        }
        1
    }
}

/// The `"res master"` derivation of `tls13_change_cipher_state` (`tls13_enc.c:675-685`): when the
/// client-application secret is derived, the authority also stores
/// `Derive-Secret(master_secret, "res master", ClientHello...client Finished)`. On the server that
/// happens while reading the client Finished (`SSL3_CHANGE_CIPHER_SERVER_READ`); on the client while
/// writing its own Finished (`SSL3_CHANGE_CIPHER_CLIENT_WRITE`). The caller must invoke this after
/// the client Finished has entered the transcript.
///
/// # Safety
/// `s` is live with a current transcript and a derived master secret.
pub(crate) unsafe fn tls13_derive_resumption_master_secret(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live.
    unsafe {
        let md = handshake_md(s);
        let hash_len = (*s).hs_md_len;
        let mut hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
        if transcript_hash(s, hash.as_mut_ptr(), ptr::null_mut()) == 0 {
            return 0;
        }
        let Some(hash) = hash.get(..hash_len) else {
            return 0;
        };
        let ms = core::slice::from_raw_parts((*s).master_secret.as_ptr(), hash_len);
        let Some(out) = (*s).resumption_master_secret.get_mut(..hash_len) else {
            return 0;
        };
        derive_secret(md, ms, b"res master", hash, out)
    }
}

/// The digest selector for a TLS1.3 ciphersuite id: 0 is SHA256, 1 is SHA384, `-1` unknown
/// (`ssl_cipher_get_evp`'s `md_kind` mapping, `t1_enc.c`).
pub(crate) fn tls13_cipher_md_kind(id: u16) -> c_int {
    match id {
        0x1301 | 0x1303 => 0,
        0x1302 => 1,
        _ => -1,
    }
}

/// The `EVP_MD *` for a [`tls13_cipher_md_kind`] selector.
pub(crate) fn tls13_md_for_kind(kind: c_int) -> *const EvpMd {
    if kind == 1 {
        EVP_sha384()
    } else {
        EVP_sha256()
    }
}

/// The digest size for a [`tls13_cipher_md_kind`] selector, or 0 when the selector is unknown.
/// This is the length of a TLS1.3 binder for that suite (`hashsize` in `tls_psk_do_binder`), so a
/// received binder of any other length must be refused before the constant-time compare reads it.
pub(crate) fn tls13_md_size(kind: c_int) -> usize {
    if kind < 0 {
        return 0;
    }
    // SAFETY: `tls13_md_for_kind` answers one of the crate's live static digests.
    let n = unsafe { EVP_MD_get_size(tls13_md_for_kind(kind)) };
    if n > 0 {
        n as usize
    } else {
        0
    }
}

/// `int tls_psk_do_binder(...)` — `ssl/statem/extensions.c:1463-1638`, the internal (resumption)
/// arm: derive the early secret from the session's PSK, the `"res binder"` binder key, and its
/// finished key, then HMAC `Hash(ClientHello up to the binders)` (`extensions.c:1519-1627`).
///
/// When `sign` is false (`binderout == NULL` on the caller's side) the received binder is compared
/// in constant time; here the caller supplies the receive slice to compare, and its length must
/// equal the digest size (a received binder of any other length is refused rather than read past).
/// `msgstart` is the ClientHello message start and `binderoffset` the byte offset of the `binders`
/// vector.
///
/// # Safety
/// `md` is live; `msgstart` readable for `binderoffset`; `psk` readable; `binder` readable and
/// writable for the md size.
pub(crate) unsafe fn tls13_psk_do_binder(
    md: *const EvpMd,
    msgstart: *const u8,
    binderoffset: usize,
    psk: &[u8],
    binder: *mut u8,
    sign: bool,
    received: &[u8],
) -> c_int {
    // SAFETY: `md` is live.
    let sz = unsafe { EVP_MD_get_size(md) };
    if sz <= 0 {
        return 0;
    }
    let hashsize = sz as usize;
    // `tls13_generate_secret(s, md, NULL, sess->master_key, sess->master_key_length, early)`.
    let mut early = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: buffers are this frame's; `psk` is the caller's.
    if unsafe { tls13_generate_secret_md(md, None, Some(psk), early.as_mut_ptr()) } == 0 {
        return 0;
    }
    // `hash = Hash("")` (`extensions.c:1526-1533`).
    let mut empty_hash = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `md` is live; the buffers are this frame's.
    if unsafe { hash_empty(md, empty_hash.as_mut_ptr(), ptr::null_mut()) } == 0 {
        return 0;
    }
    // `binderkey = HKDF-Expand-Label(early_secret, "res binder", hash, hashsize)`.
    let mut binderkey = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: the arguments are this frame's.
    if unsafe {
        hkdf_expand_label(
            md,
            early.as_ptr(),
            hashsize,
            b"res binder",
            empty_hash.as_ptr(),
            hashsize,
            binderkey.as_mut_ptr(),
            hashsize,
        )
    } == 0
    {
        return 0;
    }
    // `finishedkey = HKDF-Expand-Label(binderkey, "finished", "", hashsize)`.
    let mut finishedkey = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: the arguments are this frame's.
    if unsafe {
        tls13_derive_finishedkey(
            md,
            binderkey.as_ptr(),
            hashsize,
            finishedkey.as_mut_ptr(),
            hashsize,
        )
    } == 0
    {
        return 0;
    }
    // `hash = Hash(msgstart[..binderoffset])` (`extensions.c:1574-1591`).
    // SAFETY: no preconditions.
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return 0;
    }
    let mut th = [0u8; crate::ssl::ssl_lib::EVP_MAX_MD_SIZE];
    // SAFETY: `ctx` is this frame's; `msgstart`/`binderoffset` are the caller's.
    let ok = unsafe {
        let mut r = EVP_DigestInit_ex(ctx, md, ptr::null_mut()) > 0;
        if r && binderoffset != 0 {
            r = EVP_DigestUpdate(ctx, msgstart.cast(), binderoffset) > 0;
        }
        if r {
            let mut l: c_uint = 0;
            r = EVP_DigestFinal_ex(ctx, th.as_mut_ptr().cast(), &mut l) > 0;
        }
        r
    };
    // SAFETY: `ctx` is this frame's.
    unsafe { EVP_MD_CTX_free(ctx) };
    if !ok {
        return 0;
    }
    // `binder = HMAC(finishedkey, hash)` (`extensions.c:1610-1627`).
    // SAFETY: `md`/`finishedkey`/`th` are live for the hash length; `binder` is writable.
    let ret = unsafe {
        HMAC(
            md,
            finishedkey.as_ptr().cast(),
            hashsize as c_int,
            th.as_ptr(),
            hashsize,
            binder,
            ptr::null_mut(),
        )
    };
    if ret.is_null() {
        return 0;
    }
    if !sign {
        // `tls_parse_ctos_psk` has already required `PACKET_remaining(&binder) == hashsize`
        // (`extensions_srvr.c:1441-1448`); this makes the precondition explicit, so a short binder
        // can never be read past its slice.
        if received.len() != hashsize {
            return 0;
        }
        // Constant-time compare against the received binder (`extensions.c:1628-1636`).
        let mut diff = 0u8;
        for (i, &received_byte) in received.iter().enumerate() {
            // SAFETY: `received.len() == hashsize` (checked above) and `binder` is the caller's
            // `hashsize`-byte writable buffer, so `i < hashsize`.
            diff |= unsafe { *binder.add(i) } ^ received_byte;
        }
        if diff != 0 {
            return 0;
        }
    }
    1
}

/// The ticket nonce expansion of `tls_construct_new_session_ticket` (`statem_srvr.c:4433-4441`):
/// `HKDF-Expand-Label(resumption_master_secret, "resumption", tick_nonce, Hash.length)`. The
/// nonce is the 8-byte big-endian ticket nonce, not a transcript hash, so this cannot use
/// [`derive_secret`].
///
/// # Safety
/// `s` is live with a derived resumption master secret; `out` writable for the hash length.
pub(crate) unsafe fn tls13_ticket_psk(s: *mut Ssl, nonce: &[u8], out: *mut u8) -> c_int {
    // SAFETY: `s` is live.
    let md = handshake_md(s);
    // SAFETY: `s` is live.
    let hash_len = unsafe { (*s).hs_md_len };
    // SAFETY: the resumption secret is `hash_len` bytes; `out` is `hash_len` writable.
    unsafe {
        hkdf_expand_label(
            md,
            (*s).resumption_master_secret.as_ptr(),
            hash_len,
            b"resumption",
            nonce.as_ptr(),
            nonce.len(),
            out,
            hash_len,
        )
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
            let propq = (*(*s).ctx).propq();
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
        let propq = (*(*s).ctx).propq();
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
    let (libctx, propq) = unsafe { ((*(*s).ctx).libctx, (*(*s).ctx).propq()) };
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
/// (`tls13_meth.c`, `tls13_enc`). Returns `None` for an IV length outside 8..=16 rather than
/// indexing with an unchecked offset.
fn make_nonce(iv: &[u8; 16], iv_len: usize, seq: u64) -> Option<[u8; 16]> {
    if !(8..=16).contains(&iv_len) {
        return None;
    }
    let mut nonce = [0u8; 16];
    nonce[..iv_len].copy_from_slice(&iv[..iv_len]);
    let tail = nonce.get_mut(iv_len - 8..iv_len)?;
    for (n, s) in tail.iter_mut().zip(seq.to_be_bytes()) {
        *n ^= s;
    }
    Some(nonce)
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
    // SAFETY: `s` is live; `plain` is readable for `len`; `out` is writable for
    // `5 + rec_len`, which is checked before any slice is formed.
    unsafe {
        let tag_len = (*s).cipher_tag_len;
        let iv_len = (*s).cipher_iv_len;
        let key_len = (*s).cipher_key_len;
        let Some(nonce) = make_nonce(&(*s).enc_iv, iv_len, (*s).enc_seq) else {
            return -1;
        };
        // The inner plaintext is `plain || content_type` in a fixed scratch block, and the
        // record length is a two-byte field; both are refusals rather than overflows.
        let inner_len = match len.checked_add(1) {
            Some(n) if n <= TLS13_HS_BUF_LEN + 1 => n,
            _ => return -1,
        };
        let rec_len = match inner_len.checked_add(tag_len) {
            Some(n) if n <= u16::MAX as usize => n,
            _ => return -1,
        };
        let Some(out_len) = 5usize.checked_add(rec_len) else {
            return -1;
        };
        let out = core::slice::from_raw_parts_mut(out, out_len);
        let plain: &[u8] = if len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(plain, len)
        };
        // Header: `type || version || length`, the AEAD AAD (`tls13_enc`). The outer record version
        // is TLS 1.2 (`0x0303`), never TLS 1.3 (`rec_layer_s3.c:395-405`, RFC 8446 §5.1).
        let hdr = [
            SSL3_RT_APPLICATION_DATA,
            (TLS1_2_VERSION >> 8) as u8,
            TLS1_2_VERSION as u8,
            (rec_len >> 8) as u8,
            rec_len as u8,
        ];
        out[..hdr.len()].copy_from_slice(&hdr);
        // Inner plaintext: content then the real content type. The block is heap-allocated through
        // the crate's allocator seam: a record-sized stack array would put a frame larger than
        // radsecproxy's whole 32 KiB accept thread on every handshake/application write. It is a
        // cleansed block, so the plaintext is released through `OPENSSL_clear_free` on every path.
        let Some(inner_block) = OwnedBuf::new_cleansed(inner_len, SeamFile::NULL, 0) else {
            return -1;
        };
        // SAFETY: the block is allocated for `inner_len` bytes and fully initialised below.
        let inner = core::slice::from_raw_parts_mut(inner_block.as_ptr(), inner_len);
        inner[..len].copy_from_slice(plain);
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
            let aad = EVP_EncryptUpdate(
                ctx,
                ptr::null_mut(),
                &mut l,
                hdr.as_ptr(),
                hdr.len() as c_int,
            );
            let body = if aad == 1 {
                EVP_EncryptUpdate(
                    ctx,
                    out[5..5 + inner_len].as_mut_ptr(),
                    &mut l,
                    inner.as_ptr(),
                    inner_len as c_int,
                )
            } else {
                0
            };
            // `EVP_EncryptUpdate` reports a non-negative byte count; a count past the
            // buffer is refused instead of being used as an offset.
            let mut outl = match usize::try_from(l) {
                Ok(n) if n <= inner_len => n,
                _ => usize::MAX,
            };
            let mut fl: c_int = 0;
            let fin = if body == 1 && outl <= inner_len {
                EVP_EncryptFinal_ex(ctx, out[5 + outl..].as_mut_ptr(), &mut fl)
            } else {
                0
            };
            if fin == 1 && fl > 0 {
                outl = outl.saturating_add(fl as usize);
            }
            let tag = if body == 1 && fin == 1 && outl <= inner_len {
                match out.get_mut(5 + outl..5 + outl + tag_len) {
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
            if body == 1 && fin == 1 && tag == 1 {
                (*s).enc_seq += 1;
                ok = true;
            }
            let _ = key_len;
        }
        // SAFETY: `ctx` is this frame's.
        EVP_CIPHER_CTX_free(ctx);
        if ok {
            out_len as isize
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
    // SAFETY: `s` is live; `ct` is readable for `ct_len`; `out` is writable for `out_cap`;
    // `content_type` is writable.
    unsafe {
        let tag_len = (*s).cipher_tag_len;
        let iv_len = (*s).cipher_iv_len;
        if ct_len < tag_len {
            return -1;
        }
        let Some(nonce) = make_nonce(&(*s).dec_iv, iv_len, (*s).dec_seq) else {
            return -1;
        };
        let ct_body_len = ct_len - tag_len;
        if ct_body_len > TLS13_HS_BUF_LEN + 1 {
            return -1;
        }
        let ct: &[u8] = if ct_len == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(ct, ct_len)
        };
        let (body_ct, tag) = ct.split_at(ct_body_len);
        // The plaintext block is heap-allocated through the crate's allocator seam; a record-sized
        // stack array would overflow a small accept thread. It is a cleansed block, so the
        // decrypted plaintext (and any partial output on tag failure) is wiped before release.
        let plain_cap = ct_body_len.max(1);
        let Some(plain_block) = OwnedBuf::new_cleansed(plain_cap, SeamFile::NULL, 0) else {
            return -1;
        };
        // SAFETY: the block is allocated for `plain_cap >= ct_body_len` writable bytes.
        let plain = core::slice::from_raw_parts_mut(plain_block.as_ptr(), plain_cap);
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
            let aad = EVP_DecryptUpdate(
                ctx,
                ptr::null_mut(),
                &mut l,
                hdr.as_ptr(),
                hdr.len() as c_int,
            );
            let body = if aad == 1 {
                EVP_DecryptUpdate(
                    ctx,
                    plain.as_mut_ptr(),
                    &mut l,
                    body_ct.as_ptr(),
                    ct_body_len as c_int,
                )
            } else {
                0
            };
            // A reported length past the plaintext block is refused rather than used as an
            // offset into it or into `out`.
            outl = match usize::try_from(l) {
                Ok(n) if n <= plain.len() => n,
                _ => usize::MAX,
            };
            let tagset = if body == 1 && outl <= plain.len() {
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
            let fin = if body == 1 && tagset == 1 && outl <= plain.len() {
                EVP_DecryptFinal_ex(ctx, plain[outl..].as_mut_ptr(), &mut fl)
            } else {
                0
            };
            if fin == 1 && fl > 0 {
                outl = outl.saturating_add(fl as usize);
            }
            if body == 1 && fin == 1 && outl <= plain.len() {
                ok = true;
            }
        }
        // SAFETY: `ctx` is this frame's.
        EVP_CIPHER_CTX_free(ctx);
        if !ok {
            return -1;
        }
        // Strip the record padding and read the inner content type: the last non-zero byte.
        // `pos` only ever moves within the `outl` initialised plaintext prefix.
        let mut pos = outl.min(plain.len());
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
        // SAFETY: `content_len <= out_cap` was checked above, so `out` is writable for the whole
        // copy; it need not be initialised and is only written, never read. `plain` is a distinct
        // cleansed allocation.
        if content_len != 0 {
            core::ptr::copy_nonoverlapping(plain.as_ptr(), out, content_len);
        }
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
    let Some(total) = body_len.checked_add(4) else {
        return 0;
    };
    if total > 17000 {
        return 0;
    }
    // The framed message is heap-allocated through the crate's allocator seam, so a handshake
    // write no longer places a 17000-byte frame on the caller's stack. Its single release is the
    // handle's `Drop` on every return below.
    let Some(msg_block) = OwnedBuf::new(17000, SeamFile::NULL, 0) else {
        return 0;
    };
    let msg = msg_block.as_ptr();
    // SAFETY: `msg` is writable for 17000 bytes (`total` was checked against that bound above)
    // and every byte below is written before it is read.
    unsafe {
        *msg = mtype;
        *msg.add(1) = (body_len >> 16) as u8;
        *msg.add(2) = (body_len >> 8) as u8;
        *msg.add(3) = body_len as u8;
    }
    if body_len != 0 {
        // SAFETY: `body` is readable for `body_len` per the contract; `msg + 4` is writable.
        unsafe { ptr::copy_nonoverlapping(body, msg.add(4), body_len) };
    }
    // SAFETY: `s` is live; `msg` is `total` initialised bytes.
    let r = unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(s, SSL3_RT_HANDSHAKE, msg, total)
    };
    if r > 0 {
        // SAFETY: `s` is live; `msg` is `total` initialised bytes.
        unsafe { transcript_update(s, msg, total) };
        // `ssl3_do_write`'s `msg_callback` (`statem_lib.c:114-118`): the authority reports every
        // handshake message written, with `s->version` and `SSL3_RT_HANDSHAKE`.
        // SAFETY: `s` is live; `msg` is `total` initialised bytes.
        unsafe {
            if let Some(cb) = (*s).msg_callback {
                cb(
                    1,
                    (*s).version,
                    SSL3_RT_HANDSHAKE as c_int,
                    msg.cast(),
                    total,
                    s,
                    (*s).msg_callback_arg,
                );
            }
        }
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
    // SAFETY: `s` is live; `out` is writable for `out.len()` bytes; the callee reports how many
    // it initialised.
    let n = unsafe { tls13_finished_mac(s, secret, out.as_mut_ptr()) };
    let Some(verify_data) = out.get(..n).filter(|data| !data.is_empty()) else {
        return 0;
    };
    // Refuse before writing if the verify_data cannot be recorded for `SSL_get_finished`.
    // The binding array is fixed at `EVP_MAX_MD_SIZE`.
    if crate::ssl::ssl_lib::EVP_MAX_MD_SIZE < verify_data.len() {
        return 0;
    }
    // SAFETY: `s` is live; `verify_data` is initialised and bounded by `out`.
    let r = unsafe {
        write_handshake_message(s, SSL3_MT_FINISHED, verify_data.as_ptr(), verify_data.len())
    };
    if r > 0 {
        // SAFETY: `s` is live; the check above established that `finish_md` holds this value.
        unsafe {
            let Some(slot) = (*s).finish_md.get_mut(..verify_data.len()) else {
                return 0;
            };
            slot.copy_from_slice(verify_data);
            (*s).finish_md_len = verify_data.len();
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
    // SAFETY: `s` is live; `expected` is writable for `expected.len()` bytes; the callee reports
    // how many it initialised.
    let n = unsafe { tls13_finished_mac(s, secret, expected.as_mut_ptr()) };
    let Some(verify_data) = expected.get(..n).filter(|data| !data.is_empty()) else {
        return 0;
    };
    if verify_data.len() != body.len() {
        return 0;
    }
    let mut diff = 0u8;
    for (a, b) in verify_data.iter().zip(body) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return 0;
    }
    // The binding array is fixed at `EVP_MAX_MD_SIZE`.
    if crate::ssl::ssl_lib::EVP_MAX_MD_SIZE < verify_data.len() {
        return 0;
    }
    // SAFETY: `s` is live; the check above established that `peer_finish_md` holds this value;
    // `msg` is the full message.
    unsafe {
        let Some(slot) = (*s).peer_finish_md.get_mut(..verify_data.len()) else {
            return 0;
        };
        slot.copy_from_slice(verify_data);
        (*s).peer_finish_md_len = verify_data.len();
        transcript_update(s, msg.as_ptr(), msg.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mem::CRYPTO_free;

    fn hdr_of(rec: &[u8]) -> [u8; 5] {
        let mut hdr = [0u8; 5];
        hdr.copy_from_slice(&rec[..5]);
        hdr
    }

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

    /// Test-only safe wrapper: `EVP_sha256()` is a live static method table and every
    /// buffer is a Rust slice.
    fn expand_label(secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) -> c_int {
        // SAFETY: `EVP_sha256()` returns a live static method table; the buffers are
        // the caller's slices for their full lengths.
        unsafe {
            hkdf_expand_label(
                EVP_sha256(),
                secret.as_ptr(),
                secret.len(),
                label,
                context.as_ptr(),
                context.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        }
    }

    /// Test-only safe wrapper for Derive-Secret under SHA-256.
    fn derive_secret_sha256(secret: &[u8], label: &[u8], hash: &[u8], out: &mut [u8]) -> c_int {
        // SAFETY: `EVP_sha256()` returns a live static method table; the buffers are
        // the caller's slices for their full lengths.
        unsafe { derive_secret(EVP_sha256(), secret, label, hash, out) }
    }

    /// RFC 8446 §7.1 `Derive-Secret(early_secret, "derived", "")` for SHA-256.
    ///
    /// Vector: `draft-ietf-tls-tls13-vectors-06` §3 "Simple 1-RTT Handshake",
    /// step "server derive secret for handshake `tls13 derived`" (the draft RFC
    /// 8446 Appendix C cites as `[TLS13-TRACES]`). PRK and output are the draft's
    /// `secret`/`output`; the context is SHA-256 of the empty transcript.
    #[test]
    fn derive_secret_matches_tls13_test_vector() {
        let secret = hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let empty_hash = hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let expected = hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        let mut out = [0u8; 32];
        let r = derive_secret_sha256(&secret, b"derived", &empty_hash, &mut out);
        assert_eq!(r, 1);
        assert_eq!(&out[..], &expected[..]);
    }

    /// RFC 8446 §7.1 `HKDF-Expand-Label(server_hs_secret, "key", "", 16)`.
    ///
    /// Vector: `draft-ietf-tls-tls13-vectors-06` §3, step "server derive write
    /// traffic keys for handshake data"; its `key info` bytes are checked against
    /// `encode_hkdf_label` as well, so the framing (not just the output) is pinned.
    #[test]
    fn hkdf_expand_label_matches_tls13_test_vector() {
        let secret = hex("3b7a839c239ef2bf0b7305a0e0c4e5a8c6c69330a753b308f5e3a83aa2ef6979");
        let expected = hex("c66cb1aec519df44c91e10995511ac8b");
        let mut out = [0u8; 16];
        let r = expand_label(&secret, b"key", &[], &mut out);
        assert_eq!(r, 1);
        assert_eq!(&out[..], &expected[..]);

        let mut info = [0u8; HKDF_LABEL_MAX];
        let encoded = encode_hkdf_label(out.len(), b"key", &[], &mut info);
        assert!(encoded.is_some(), "the fixed key label is encodable");
        let n = encoded.unwrap_or(0);
        assert_eq!(&info[..n], &hex("001009746c733133206b657900")[..]);
    }

    /// The largest fields RFC 8446 §7.1 permits: `"tls13 "` plus a 249-byte label is
    /// exactly 255 bytes (`TLS13_MAX_LABEL_LEN`, `tls13_enc.c:21`), and a 255-byte
    /// context fills the other one-byte length. Together they need 514 bytes of
    /// `HkdfLabel`, which is why the fixed information block is `HKDF_LABEL_MAX` and
    /// not the old 512-byte buffer.
    #[test]
    fn hkdf_expand_label_accepts_maximum_label_and_context() {
        let label = [b'a'; 249];
        let context = [0x5au8; 255];
        let secret = [7u8; 32];
        let mut out = [0u8; 32];
        let r = expand_label(&secret, &label, &context, &mut out);
        assert_eq!(r, 1);
        assert_ne!(out, [0u8; 32]);

        let mut info = [0u8; HKDF_LABEL_MAX];
        let encoded = encode_hkdf_label(32, &label, &context, &mut info);
        assert!(
            encoded.is_some(),
            "the maximum label and context are encodable"
        );
        let n = encoded.unwrap_or(0);
        assert_eq!(n, 2 + 1 + 255 + 1 + 255);
        assert_eq!(&info[..2], &32u16.to_be_bytes());
        assert_eq!(info[2], 255, "label length is prefix + label");
        assert_eq!(&info[3..9], b"tls13 ");
        assert_eq!(info[258], 255, "context length");
        assert_eq!(&info[259..n], &context[..]);
    }

    /// `"tls13 " + label` must fit one byte: 250 label bytes make 256 and are refused
    /// by the encoder before any output is produced.
    #[test]
    fn hkdf_expand_label_refuses_an_over_long_label() {
        let label = [b'a'; 250];
        let secret = [7u8; 32];
        let mut out = [0u8; 32];
        let mut info = [0u8; HKDF_LABEL_MAX];
        assert!(encode_hkdf_label(32, &label, &[], &mut info).is_none());
        let r = expand_label(&secret, &label, &[], &mut out);
        assert_eq!(r, 0);
    }

    /// A short output buffer is a legal HKDF output length; the expansion writes exactly
    /// that many bytes and does not touch any byte after it.
    #[test]
    fn hkdf_expand_label_fills_a_short_output() {
        let secret = hex("3b7a839c239ef2bf0b7305a0e0c4e5a8c6c69330a753b308f5e3a83aa2ef6979");
        let mut buf = [0x5au8; 2];
        let r = expand_label(&secret, b"key", &[], &mut buf[..1]);
        assert_eq!(r, 1);
        assert_eq!(buf[1], 0x5a, "the byte after the short output is untouched");

        let mut empty = [0u8; 0];
        let r = expand_label(&secret, b"key", &[], &mut empty);
        assert_eq!(r, 1, "an empty expansion is legal HKDF");
    }

    /// The `uint16 length` field is two bytes; an output length that does not fit is
    /// refused by the encoder rather than truncated to 16 bits.
    #[test]
    fn hkdf_expand_label_refuses_an_output_length_that_does_not_fit_u16() {
        let secret = [7u8; 32];
        let mut out = vec![0u8; u16::MAX as usize + 1];
        let mut info = [0u8; HKDF_LABEL_MAX];
        assert!(encode_hkdf_label(out.len(), b"key", &[], &mut info).is_none());
        let r = expand_label(&secret, b"key", &[], &mut out);
        assert_eq!(r, 0);
    }

    /// The `HkdfLabel` encoder writes a one-byte context length; a context that does not fit is
    /// refused before either the length truncation or the copy, while the SHA-256 transcript
    /// length the schedule actually uses still expands.
    #[test]
    fn hkdf_expand_label_refuses_a_context_that_does_not_fit_its_length_byte() {
        let secret = [7u8; 32];
        let context = [0u8; 256];
        let mut out = [0u8; 32];
        assert_eq!(
            expand_label(&secret, b"key", &context, &mut out),
            0,
            "a 256-byte context cannot be encoded in the label"
        );
        assert_eq!(
            expand_label(&secret, b"key", &context[..32], &mut out),
            1,
            "the SHA-256 transcript length is accepted"
        );
        assert_ne!(out, [0u8; 32], "the accepted expansion produced output");
    }

    /// One unsafe block owns the zeroed `Ssl`, its digest context and its single release; the
    /// tests below see only slices and byte vectors.
    fn transcript_sha256(before_init: &[u8], after_init: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut points = Vec::new();
        // SAFETY: `s` is a live zeroed `Ssl` owned here; `hs_md_ctx` is created by
        // `tls13_init_transcript` and released before the block; every data pointer is a slice.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null(), "a zeroed Ssl block must be allocatable");
            if !before_init.is_empty() {
                assert_eq!(
                    transcript_update(s, before_init.as_ptr(), before_init.len()),
                    1,
                    "the pre-cipher transcript buffers"
                );
            }
            assert_eq!(tls13_init_transcript(s, 0), 1, "SHA-256 transcript");
            for chunk in after_init {
                if !chunk.is_empty() {
                    assert_eq!(transcript_update(s, chunk.as_ptr(), chunk.len()), 1);
                }
                let mut digest = [0u8; HASH_MAX];
                let mut n = 0usize;
                assert_eq!(
                    transcript_hash(s, digest.as_mut_ptr(), &mut n),
                    1,
                    "the transcript hash is observable at each point"
                );
                assert_eq!(n, 32);
                points.push(digest[..n].to_vec());
            }
            EVP_MD_CTX_free((*s).hs_md_ctx.cast());
            CRYPTO_free(s.cast(), ptr::null(), 0);
        }
        points
    }

    /// SHA-256 at two fixed points: the `"abc"` digest, then the digest of the standard
    /// two-block message after appending its tail. The first point is produced from the
    /// pre-cipher buffer replayed by `tls13_init_transcript`; the second takes the running
    /// `EVP_DigestUpdate` path. Vectors: FIPS 180-4 / RFC 6234 §8.5 SHA-256 test vectors.
    #[test]
    fn transcript_sha256_matches_fips_vectors_at_two_points() {
        let tail = b"dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let points = transcript_sha256(b"abc", &[&[], tail]);
        assert_eq!(
            points[0],
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            points[1],
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    /// Client application key/IV and the first application-data record of
    /// `draft-ietf-tls-tls13-vectors-06` §3 (record sequence 0).
    const APP_KEY: &str = "88b96ad686c84be55ace18a59cce5c87";
    const APP_IV: &str = "b99dc58cd5ff5ab082fdad19";
    const APP_RECORD: &str = concat!(
        "17030300438c3497da00ae023e53c01b4324b665404c1b49e78fe2bf4d17f6348ae8340551e363a0cd05f2",
        "179c4fef5ad689b5cae0bae94adc63632e571fb79aa91544c6394d28a1"
    );

    fn app_plaintext() -> Vec<u8> {
        (0u8..=0x31).collect()
    }

    fn new_ssl_cipher(key: &[u8], iv: &[u8], seq: u64) -> *mut Ssl {
        // SAFETY: the caller runs this inside its own unsafe block and releases the block.
        unsafe {
            let s = crate::ssl::adv_alloc::zeroed_ssl();
            assert!(!s.is_null());
            (*s).tls13_cipher = crate::evp::e_aes::EVP_aes_128_gcm().cast_mut().cast();
            (*s).cipher_key_len = key.len();
            (*s).cipher_iv_len = iv.len();
            (*s).cipher_tag_len = 16;
            (&mut (*s).enc_key)[..key.len()].copy_from_slice(key);
            (&mut (*s).enc_iv)[..iv.len()].copy_from_slice(iv);
            (&mut (*s).dec_key)[..key.len()].copy_from_slice(key);
            (&mut (*s).dec_iv)[..iv.len()].copy_from_slice(iv);
            (*s).enc_seq = seq;
            (*s).dec_seq = seq;
            s
        }
    }

    fn seal_record(key: &[u8], iv: &[u8], seq: u64, plain: &[u8], content_type: u8) -> Vec<u8> {
        let mut rec = vec![0u8; 5 + plain.len() + 1 + 16];
        // SAFETY: `s` is a live fixture; the plaintext and record buffers are this frame's and
        // the record capacity is exactly the sealed extent.
        unsafe {
            let s = new_ssl_cipher(key, iv, seq);
            let n = tls13_encrypt_record(
                s,
                content_type,
                plain.as_ptr(),
                plain.len(),
                rec.as_mut_ptr(),
            );
            assert_eq!(
                (*s).enc_seq,
                seq + 1,
                "a sealed record advances the sequence"
            );
            CRYPTO_free(s.cast(), ptr::null(), 0);
            assert!(n > 0, "seal succeeds");
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

    fn open_record(
        key: &[u8],
        iv: &[u8],
        seq: u64,
        hdr: &[u8; 5],
        body: &[u8],
        out_cap: usize,
    ) -> Opened {
        let mut out = vec![0u8; out_cap + 1];
        out[out_cap] = 0xAA;
        let mut content_type = 0u8;
        // SAFETY: `s` is a live fixture; `body` and `hdr` are slices; `out` is `out_cap + 1`
        // bytes with the final byte as an overrun canary.
        let (rc, seq_after) = unsafe {
            let s = new_ssl_cipher(key, iv, seq);
            let rc = tls13_decrypt_record(
                s,
                hdr,
                body.as_ptr(),
                body.len(),
                out.as_mut_ptr(),
                out_cap,
                &mut content_type,
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
            content_type,
            seq: seq_after,
        }
    }

    /// Exact seal vector: the draft's first client application-data record under the client
    /// application key at sequence 0.
    #[test]
    fn seal_matches_tls13_test_vector_exactly() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let expected = hex(APP_RECORD);
        let rec = seal_record(&key, &iv, 0, &app_plaintext(), SSL3_RT_APPLICATION_DATA);
        assert_eq!(rec, expected);
        assert_eq!(&rec[..3], &[0x17, 0x03, 0x03]);
        assert_eq!(&rec[3..5], &(rec.len() as u16 - 5).to_be_bytes());
    }

    /// Exact open vector: the same record returns the draft's 50-byte payload and type 23.
    #[test]
    fn open_matches_tls13_test_vector() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let rec = hex(APP_RECORD);
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..], 16384);
        assert_eq!(opened.rc, 50);
        assert_eq!(&opened.out[..50], &app_plaintext()[..]);
        assert_eq!(opened.content_type, SSL3_RT_APPLICATION_DATA);
        assert_eq!(opened.seq, 1);
    }

    /// A flipped tag is the single record failure code `-1`; the sequence does not advance and
    /// the caller's output buffer is untouched (the caller maps `-1` to `bad_record_mac`).
    #[test]
    fn open_rejects_a_flipped_tag_without_advancing_the_sequence() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let mut rec = hex(APP_RECORD);
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..], 16384);
        assert_eq!(opened.rc, -1);
        assert_eq!(opened.seq, 0);
        assert!(
            opened.out.iter().all(|b| *b == 0),
            "no plaintext on failure"
        );
    }

    /// Fewer bytes than the tag cannot name a tag; refused before any decryption.
    #[test]
    fn open_rejects_a_truncated_record() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let rec = hex(APP_RECORD);
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..5 + 15], 16384);
        assert_eq!(opened.rc, -1);
        assert_eq!(opened.seq, 0);
    }

    /// The largest permitted inner plaintext round-trips at the 16 KiB buffer bound.
    #[test]
    fn seal_open_max_size_record_round_trips() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let plain: Vec<u8> = (0..TLS13_HS_BUF_LEN).map(|i| (i % 251) as u8).collect();
        let rec = seal_record(&key, &iv, 0, &plain, SSL3_RT_APPLICATION_DATA);
        assert_eq!(rec.len(), 5 + TLS13_HS_BUF_LEN + 1 + 16);
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..], TLS13_HS_BUF_LEN);
        assert_eq!(opened.rc, TLS13_HS_BUF_LEN as isize);
        assert_eq!(opened.out, plain);
        assert_eq!(opened.content_type, SSL3_RT_APPLICATION_DATA);
        assert_eq!(opened.seq, 1);
    }

    /// Zero-length application data still seals `content_type` and opens to length 0.
    #[test]
    fn seal_open_zero_length_plaintext_round_trips() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let rec = seal_record(&key, &iv, 0, &[], SSL3_RT_APPLICATION_DATA);
        assert_eq!(rec.len(), 5 + 1 + 16);
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..], 0);
        assert_eq!(opened.rc, 0);
        assert!(opened.out.is_empty());
        assert_eq!(opened.content_type, SSL3_RT_APPLICATION_DATA);
        assert_eq!(opened.seq, 1);
    }

    /// A caller buffer shorter than the decrypted content is refused without writing or
    /// advancing the sequence.
    #[test]
    fn open_rejects_a_too_small_output_buffer() {
        let key = hex(APP_KEY);
        let iv = hex(APP_IV);
        let rec = hex(APP_RECORD);
        let hdr = hdr_of(&rec);
        let opened = open_record(&key, &iv, 0, &hdr, &rec[5..], 1);
        assert_eq!(opened.rc, -1);
        assert_eq!(opened.seq, 0);
        assert_eq!(
            opened.out,
            vec![0u8; 1],
            "nothing copied into a short buffer"
        );
    }

    /// The received binder must be exactly the digest size. The pre-fix signature took a bare
    /// `*const u8` and read `hashsize` bytes unconditionally, so a short binder from a client with
    /// a valid ticket was an out-of-bounds read. The slice parameter and its length check are the
    /// repair; this test is the regression control.
    #[test]
    fn binder_length_must_match_the_digest_size() {
        let md = EVP_sha256();
        let psk = [0x11u8; 32];
        let msg = [0u8; 4];
        let mut calc = [0u8; 32];
        let short = [0u8; 31];
        // SAFETY: `md` is the live SHA-256 method table; `msg` is readable for `binderoffset` (0);
        // `calc` is writable for the digest size; `short` is a live slice.
        let r = unsafe {
            tls13_psk_do_binder(md, msg.as_ptr(), 0, &psk, calc.as_mut_ptr(), false, &short)
        };
        assert_eq!(r, 0, "a 31-byte binder must be refused, not read as 32");
        let long = [0u8; 33];
        // SAFETY: as above.
        let r = unsafe {
            tls13_psk_do_binder(md, msg.as_ptr(), 0, &psk, calc.as_mut_ptr(), false, &long)
        };
        assert_eq!(r, 0, "a 33-byte binder must be refused");
    }
}
