//! `crypto/cms/cms_kari.c` — the key-agreement recipient engine: ephemeral-key setup, the KEK
//! derivation and the recipient-encrypted-key surface. Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
// The authority's C initialisers are dead on the paths that reach its `err:` label; the
// assignments are kept so the transcription reads as the source does.
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_new, ASN1_STRING_set0};
use crate::asn1::x_algor::X509Algor;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_reset, EVP_CipherInit_ex, EVP_CipherUpdate,
};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EvpPkeyCtx};
use crate::evp::pmeth_gn::{EVP_PKEY_keygen, EVP_PKEY_keygen_init};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x_x509::X509;

use super::cms_asn1::*;
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, ossl_cms_ias_cert_cmp,
    ossl_cms_keyid_cert_cmp, ossl_cms_set1_ias, ossl_cms_set1_keyid, raise_cms,
};

/// `CMS_USE_KEYID` — `cms.h.in:100`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_USE_ORIGINATOR_KEYID` — `cms.h.in:103`.
const CMS_USE_ORIGINATOR_KEYID: c_uint = 0x200000;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;

// ---------------------------------------------------------------------------------------------
// Ownership of a scratch buffer
// ---------------------------------------------------------------------------------------------

/// An owned scratch buffer allocated through the crate's allocator seam.
///
/// The block stays a `CRYPTO_malloc` at the authority's exact size/`file`/`line` -- a Rust
/// `Box`/`Vec` would hide both the allocation and its release from a caller-installed
/// `CRYPTO_set_mem_functions` hook -- and only its *ownership* is this type: `new`/`new_cleansed`
/// allocate it, `Drop` is its single release, and [`Self::into_raw`] hands it to a consumer that
/// takes it over (`ec->key`, or a `*pout` slot). [`Self::adopt`] takes in a block the crate
/// allocated inside a helper (`cms_kek_cipher`) so the failure paths that follow release what they
/// built. A NULL pointer is a valid, empty buffer whose release is the authority's own no-op
/// `free(NULL)`.
struct OwnedBuf {
    ptr: *mut c_uchar,
    release: BufRelease,
}

/// How the authority releases a scratch buffer.
enum BufRelease {
    /// The authority's plain `CRYPTO_free(ptr, file, line)` (`cek`).
    Plain { file: *const c_char, line: c_int },
    /// The authority's cleansing `OPENSSL_clear_free(ptr, num)`, which zeroes `num` bytes first
    /// (`out`).
    Cleansed { num: usize },
}

impl OwnedBuf {
    /// `CRYPTO_malloc(len, file, line)`, or `None` when the allocator answers NULL.
    fn new(len: usize, file: *const c_char, line: c_int) -> Option<OwnedBuf> {
        let raw = CRYPTO_malloc(len, file, line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::Plain { file, line },
        })
    }

    /// `CRYPTO_malloc(len, file, line)` for a block whose release is the cleansing
    /// `OPENSSL_clear_free(ptr, len)`, or `None` when the allocator answers NULL.
    fn new_cleansed(len: usize, file: *const c_char, line: c_int) -> Option<OwnedBuf> {
        let raw = CRYPTO_malloc(len, file, line).cast::<c_uchar>();
        if raw.is_null() {
            return None;
        }
        Some(OwnedBuf {
            ptr: raw,
            release: BufRelease::Cleansed { num: len },
        })
    }

    /// Adopt a plain block this crate allocated inside a helper, for release by `Drop` at the
    /// authority's own site.
    ///
    /// # Safety
    /// `ptr` is NULL or a live plain block the crate allocated that no one else owns, and `file`
    /// is NULL or a NUL-terminated C string.
    unsafe fn adopt(ptr: *mut c_uchar, file: *const c_char, line: c_int) -> OwnedBuf {
        OwnedBuf {
            ptr,
            release: BufRelease::Plain { file, line },
        }
    }

    /// The writable start of the buffer.
    fn as_ptr(&self) -> *mut c_uchar {
        self.ptr
    }

    /// Give up ownership of the block to a consumer that takes it over.
    fn into_raw(self) -> *mut c_uchar {
        let p = self.ptr;
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedBuf {
    /// The buffer's single release, through the same seam the authority uses.
    fn drop(&mut self) {
        match self.release {
            BufRelease::Plain { file, line } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released; the
                // authority's own `CRYPTO_free` accepts NULL.
                unsafe { CRYPTO_free(self.ptr.cast::<c_void>(), file, line) };
            }
            BufRelease::Cleansed { num } => {
                // SAFETY: `self.ptr` is the block this handle owns and has not released, readable
                // for `num` bytes; `OPENSSL_clear_free` zeroes then releases it and accepts NULL.
                unsafe { super::cms_asn1::OPENSSL_clear_free(self.ptr, num) };
            }
        }
    }
}

/// `int CMS_RecipientInfo_kari_get0_alg(CMS_RecipientInfo *ri, X509_ALGOR **palg,`
/// `ASN1_OCTET_STRING **pukm)` — `cms_kari.c:22-35`.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_get0_alg(
    ri: *mut CmsRecipientInfo,
    palg: *mut *mut X509Algor,
    pukm: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_AGREE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                27,
                c"CMS_RecipientInfo_kari_get0_alg",
                ERR_CMS_R_NOT_KEY_AGREEMENT,
            )
        };
        return 0;
    }
    if !palg.is_null() {
        // SAFETY: `palg` is writable; `ri` is live.
        unsafe { *palg = (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).key_encryption_algorithm };
    }
    if !pukm.is_null() {
        // SAFETY: `pukm` is writable; `ri` is live.
        unsafe { *pukm = (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).ukm };
    }
    1
}

/// `STACK_OF(CMS_RecipientEncryptedKey) *CMS_RecipientInfo_kari_get0_reks(CMS_RecipientInfo *ri)` —
/// `cms_kari.c:39-47`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_get0_reks(
    ri: *mut CmsRecipientInfo,
) -> *mut OpenSslStack {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_AGREE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                43,
                c"CMS_RecipientInfo_kari_get0_reks",
                ERR_CMS_R_NOT_KEY_AGREEMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `ri` is live.
    unsafe { (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).recipient_encrypted_keys }
}

/// `int CMS_RecipientInfo_kari_get0_orig_id(CMS_RecipientInfo *ri, X509_ALGOR **pubalg,`
/// `ASN1_BIT_STRING **pubkey, ASN1_OCTET_STRING **keyid, X509_NAME **issuer,`
/// `ASN1_INTEGER **sno)` — `cms_kari.c:49-89`.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_get0_orig_id(
    ri: *mut CmsRecipientInfo,
    pubalg: *mut *mut X509Algor,
    pubkey: *mut *mut Asn1String,
    keyid: *mut *mut Asn1String,
    issuer: *mut *mut crate::x509::x_name::X509Name,
    sno: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_AGREE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                59,
                c"CMS_RecipientInfo_kari_get0_orig_id",
                ERR_CMS_R_NOT_KEY_AGREEMENT,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let oik = unsafe { (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).originator };
    if !issuer.is_null() {
        // SAFETY: `issuer` is writable.
        unsafe { *issuer = ptr::null_mut() };
    }
    if !sno.is_null() {
        // SAFETY: `sno` is writable.
        unsafe { *sno = ptr::null_mut() };
    }
    if !keyid.is_null() {
        // SAFETY: `keyid` is writable.
        unsafe { *keyid = ptr::null_mut() };
    }
    if !pubalg.is_null() {
        // SAFETY: `pubalg` is writable.
        unsafe { *pubalg = ptr::null_mut() };
    }
    if !pubkey.is_null() {
        // SAFETY: `pubkey` is writable.
        unsafe { *pubkey = ptr::null_mut() };
    }
    // SAFETY: `oik` is live.
    let oik_type = unsafe { (*oik).type_ };
    if oik_type == CMS_OIK_ISSUER_SERIAL {
        // SAFETY: `oik` holds an issuer-and-serial in this arm.
        let ias = unsafe { (*oik).d.cast::<CmsIssuerAndSerialNumber>() };
        if !issuer.is_null() {
            // SAFETY: `ias` is live.
            unsafe { *issuer = (*ias).issuer };
        }
        if !sno.is_null() {
            // SAFETY: `ias` is live.
            unsafe { *sno = (*ias).serial_number };
        }
    } else if oik_type == CMS_OIK_KEYIDENTIFIER {
        if !keyid.is_null() {
            // SAFETY: `oik` holds a key identifier in this arm.
            unsafe { *keyid = (*oik).d.cast::<Asn1String>() };
        }
    } else if oik_type == CMS_OIK_PUBKEY {
        // SAFETY: `oik` holds an originator key in this arm.
        let ok = unsafe { (*oik).d.cast::<CmsOriginatorPublicKey>() };
        if !pubalg.is_null() {
            // SAFETY: `ok` is live.
            unsafe { *pubalg = (*ok).algorithm };
        }
        if !pubkey.is_null() {
            // SAFETY: `ok` is live.
            unsafe { *pubkey = (*ok).public_key };
        }
    } else {
        return 0;
    }
    1
}

/// `int CMS_RecipientInfo_kari_orig_id_cmp(CMS_RecipientInfo *ri, X509 *cert)` —
/// `cms_kari.c:91-105`.
///
/// # Safety
/// `ri`/`cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_orig_id_cmp(
    ri: *mut CmsRecipientInfo,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_AGREE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                96,
                c"CMS_RecipientInfo_kari_orig_id_cmp",
                ERR_CMS_R_NOT_KEY_AGREEMENT,
            )
        };
        return -2;
    }
    // SAFETY: `ri` is live.
    let oik = unsafe { (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).originator };
    // SAFETY: `oik` is live.
    let oik_type = unsafe { (*oik).type_ };
    if oik_type == CMS_OIK_ISSUER_SERIAL {
        // SAFETY: `oik`/`cert` are live.
        return unsafe { ossl_cms_ias_cert_cmp((*oik).d.cast::<CmsIssuerAndSerialNumber>(), cert) };
    } else if oik_type == CMS_OIK_KEYIDENTIFIER {
        // SAFETY: `oik`/`cert` are live.
        return unsafe { ossl_cms_keyid_cert_cmp((*oik).d.cast::<Asn1String>(), cert) };
    }
    -1
}

/// `int CMS_RecipientEncryptedKey_get0_id(CMS_RecipientEncryptedKey *rek,`
/// `ASN1_OCTET_STRING **keyid, ASN1_GENERALIZEDTIME **tm, CMS_OtherKeyAttribute **other,`
/// `X509_NAME **issuer, ASN1_INTEGER **sno)` — `cms_kari.c:107-140`.
///
/// # Safety
/// `rek` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientEncryptedKey_get0_id(
    rek: *mut CmsRecipientEncryptedKey,
    keyid: *mut *mut Asn1String,
    tm: *mut *mut Asn1String,
    other: *mut *mut CmsOtherKeyAttribute,
    issuer: *mut *mut crate::x509::x_name::X509Name,
    sno: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `rek` is live.
    let rid = unsafe { (*rek).rid };
    // SAFETY: `rid` is live.
    let rid_type = unsafe { (*rid).type_ };
    if rid_type == CMS_REK_ISSUER_SERIAL {
        // SAFETY: `rid` holds an issuer-and-serial in this arm.
        let ias = unsafe { (*rid).d.cast::<CmsIssuerAndSerialNumber>() };
        if !issuer.is_null() {
            // SAFETY: `ias` is live.
            unsafe { *issuer = (*ias).issuer };
        }
        if !sno.is_null() {
            // SAFETY: `ias` is live.
            unsafe { *sno = (*ias).serial_number };
        }
        if !keyid.is_null() {
            // SAFETY: the pointer is live per the checks above.
            unsafe { *keyid = ptr::null_mut() };
        }
        if !tm.is_null() {
            // SAFETY: the pointer is live per the checks above.
            unsafe { *tm = ptr::null_mut() };
        }
        if !other.is_null() {
            // SAFETY: the arguments meet the callee's contract.
            unsafe { *other = ptr::null_mut() };
        }
    } else if rid_type == CMS_REK_KEYIDENTIFIER {
        // SAFETY: `rid` holds a recipient key identifier in this arm.
        let rkid = unsafe { (*rid).d.cast::<CmsRecipientKeyIdentifier>() };
        if !keyid.is_null() {
            // SAFETY: `rkid` is live.
            unsafe { *keyid = (*rkid).subject_key_identifier };
        }
        if !tm.is_null() {
            // SAFETY: `rkid` is live.
            unsafe { *tm = (*rkid).date };
        }
        if !other.is_null() {
            // SAFETY: `rkid` is live.
            unsafe { *other = (*rkid).other };
        }
        if !issuer.is_null() {
            // SAFETY: the pointer is live per the checks above.
            unsafe { *issuer = ptr::null_mut() };
        }
        if !sno.is_null() {
            // SAFETY: the arguments meet the callee's contract.
            unsafe { *sno = ptr::null_mut() };
        }
    } else {
        return 0;
    }
    1
}

/// `int CMS_RecipientEncryptedKey_cert_cmp(CMS_RecipientEncryptedKey *rek, X509 *cert)` —
/// `cms_kari.c:142-154`.
///
/// # Safety
/// `rek`/`cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientEncryptedKey_cert_cmp(
    rek: *mut CmsRecipientEncryptedKey,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `rek` is live.
    let rid = unsafe { (*rek).rid };
    // SAFETY: `rid` is live.
    let rid_type = unsafe { (*rid).type_ };
    if rid_type == CMS_REK_ISSUER_SERIAL {
        // SAFETY: `rid`/`cert` are live.
        return unsafe { ossl_cms_ias_cert_cmp((*rid).d.cast::<CmsIssuerAndSerialNumber>(), cert) };
    } else if rid_type == CMS_REK_KEYIDENTIFIER {
        // SAFETY: `rid` holds a recipient key identifier in this arm.
        let rkid = unsafe { (*rid).d.cast::<CmsRecipientKeyIdentifier>() };
        // SAFETY: `rkid`/`cert` are live.
        return unsafe { ossl_cms_keyid_cert_cmp((*rkid).subject_key_identifier, cert) };
    }
    -1
}

/// `int CMS_RecipientInfo_kari_set0_pkey_and_peer(CMS_RecipientInfo *ri, EVP_PKEY *pk,`
/// `X509 *peer)` — `cms_kari.c:156-185`.
///
/// # Safety
/// `ri` is live; `pk`/`peer` are NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_set0_pkey_and_peer(
    ri: *mut CmsRecipientInfo,
    pk: *mut EvpPkey,
    peer: *mut X509,
) -> c_int {
    // SAFETY: `ri` is live.
    let kari = unsafe { (*ri).d.cast::<CmsKeyAgreeRecipientInfo>() };
    // SAFETY: `kari` is live.
    unsafe { EVP_PKEY_CTX_free((*kari).pctx.cast()) };
    // SAFETY: `kari` is live.
    unsafe { (*kari).pctx = ptr::null_mut() };
    if pk.is_null() {
        return 1;
    }

    // SAFETY: `kari` is live; `pk` is live.
    let pctx = unsafe {
        EVP_PKEY_CTX_new_from_pkey(
            ossl_cms_ctx_get0_libctx((*kari).cms_ctx),
            pk,
            ossl_cms_ctx_get0_propq((*kari).cms_ctx),
        )
    };
    // SAFETY: `pctx` is live.
    if pctx.is_null() || unsafe { EVP_PKEY_derive_init(pctx) } <= 0 {
        // SAFETY: `pctx` is NULL or owned.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        return 0;
    }

    if !peer.is_null() {
        // SAFETY: `peer` is live.
        let pub_pkey = unsafe { X509_get0_pubkey(peer) };

        // SAFETY: `pctx`/`pub_pkey` are live.
        if unsafe { EVP_PKEY_derive_set_peer(pctx, pub_pkey) } <= 0 {
            // SAFETY: `pctx` is owned here.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            return 0;
        }
    }

    // SAFETY: `kari` is live.
    unsafe { (*kari).pctx = pctx.cast() };
    1
}

/// `int CMS_RecipientInfo_kari_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk)` —
/// `cms_kari.c:187-190`.
///
/// # Safety
/// `ri` is live; `pk` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_set0_pkey(
    ri: *mut CmsRecipientInfo,
    pk: *mut EvpPkey,
) -> c_int {
    // SAFETY: `ri`/`pk` are live.
    unsafe { CMS_RecipientInfo_kari_set0_pkey_and_peer(ri, pk, ptr::null_mut()) }
}

/// `EVP_CIPHER_CTX *CMS_RecipientInfo_kari_get0_ctx(CMS_RecipientInfo *ri)` —
/// `cms_kari.c:192-197`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_get0_ctx(
    ri: *mut CmsRecipientInfo,
) -> *mut crate::evp::cipher_ctx::EvpCipherCtx {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } == CMS_RECIPINFO_AGREE {
        // SAFETY: `ri` is live.
        return unsafe {
            (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>())
                .ctx
                .cast::<crate::evp::cipher_ctx::EvpCipherCtx>()
        };
    }
    ptr::null_mut()
}

/// `int cms_kek_cipher(unsigned char **pout, size_t *poutlen, const unsigned char *in,`
/// `size_t inlen, CMS_KeyAgreeRecipientInfo *kari, int enc)` — `cms_kari.c:204-254`.
///
/// # Safety
/// `pout`/`poutlen` are writable; `in` is readable for `inlen`; `kari` is live.
unsafe fn cms_kek_cipher(
    pout: *mut *mut c_uchar,
    poutlen: *mut usize,
    input: *const c_uchar,
    inlen: usize,
    kari: *mut CmsKeyAgreeRecipientInfo,
    enc: c_int,
) -> c_int {
    let mut kek = [0u8; EVP_MAX_KEY_LENGTH];
    let mut keklen;
    let mut rv = 0;
    let mut outlen: c_int = 0;
    let mut outsize = 0usize;

    // SAFETY: `kari` is live.
    keklen = unsafe { EVP_CIPHER_CTX_get_key_length((*kari).ctx.cast()) } as usize;
    if keklen > EVP_MAX_KEY_LENGTH || inlen > c_int::MAX as usize {
        return 0;
    }
    // Derive KEK.
    // SAFETY: `kari` is live; `kek` is writable for `keklen`.
    if unsafe { EVP_PKEY_derive((*kari).pctx.cast(), kek.as_mut_ptr(), &mut keklen) } <= 0 {
        // SAFETY: `kari` is live; nothing allocated.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
            EVP_CIPHER_CTX_reset((*kari).ctx.cast());
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            (*kari).pctx = ptr::null_mut();
        }
        return 0;
    }
    // Set KEK in context.
    // SAFETY: `kari` is live; `kek` is readable for `keklen`.
    if unsafe {
        EVP_CipherInit_ex(
            (*kari).ctx.cast(),
            ptr::null(),
            ptr::null_mut(),
            kek.as_ptr(),
            ptr::null(),
            enc,
        )
    } == 0
    {
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
            EVP_CIPHER_CTX_reset((*kari).ctx.cast());
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            (*kari).pctx = ptr::null_mut();
        }
        return 0;
    }
    // Obtain output length of ciphered key.
    // SAFETY: `kari` is live.
    if unsafe {
        EVP_CipherUpdate(
            (*kari).ctx.cast(),
            ptr::null_mut(),
            &mut outlen,
            input,
            inlen as c_int,
        )
    } == 0
    {
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
            EVP_CIPHER_CTX_reset((*kari).ctx.cast());
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            (*kari).pctx = ptr::null_mut();
        }
        return 0;
    }
    // Size the buffer for the worst case the primitive cleanses on failure.
    outsize = if (outlen as usize) < inlen {
        inlen
    } else {
        outlen as usize
    };
    // The ciphered key is this frame's scratch, allocated through the crate's allocator seam at
    // `outsize`; its release is the authority's cleansing `OPENSSL_clear_free`, run by `Drop`.
    // SAFETY: `outsize > 0`.
    let Some(out) = OwnedBuf::new_cleansed(outsize, c"cms_kari.c".as_ptr(), 235) else {
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
            EVP_CIPHER_CTX_reset((*kari).ctx.cast());
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            (*kari).pctx = ptr::null_mut();
        }
        return 0;
    };
    // SAFETY: `kari` is live; `out` is writable.
    if unsafe {
        EVP_CipherUpdate(
            (*kari).ctx.cast(),
            out.as_ptr(),
            &mut outlen,
            input,
            inlen as c_int,
        )
    } == 0
    {
        // `out` clears and releases its own block, at the authority's own site.
        drop(out);
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
            EVP_CIPHER_CTX_reset((*kari).ctx.cast());
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            (*kari).pctx = ptr::null_mut();
        }
        return 0;
    }
    // SAFETY: `pout`/`poutlen` are writable; ownership of the block transfers to the caller.
    unsafe {
        *pout = out.into_raw();
        *poutlen = outlen as usize;
    }
    rv = 1;

    // SAFETY: `kek` is a live buffer; the contexts are live.
    unsafe {
        OPENSSL_cleanse(kek.as_mut_ptr().cast(), keklen);
        EVP_CIPHER_CTX_reset((*kari).ctx.cast());
        EVP_PKEY_CTX_free((*kari).pctx.cast());
        (*kari).pctx = ptr::null_mut();
    }
    let _ = rv;
    rv
}

/// `int CMS_RecipientInfo_kari_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,`
/// `CMS_RecipientEncryptedKey *rek)` — `cms_kari.c:256-283`.
///
/// # Safety
/// `cms`/`ri`/`rek` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kari_decrypt(
    cms: *mut CmsContentInfo,
    ri: *mut CmsRecipientInfo,
    rek: *mut CmsRecipientEncryptedKey,
) -> c_int {
    let mut rv = 0;
    let mut cek: *mut c_uchar = ptr::null_mut();
    let mut ceklen = 0usize;

    // SAFETY: `rek` is live.
    let enckeylen = unsafe { (*(*rek).encrypted_key).length } as usize;
    // SAFETY: `rek` is live.
    let enckey = unsafe { (*(*rek).encrypted_key).data };
    // Setup all parameters to derive KEK.
    // SAFETY: `ri` is live.
    if unsafe { super::cms_env::ossl_cms_env_asn1_ctrl(ri, 1) } == 0 {
        return rv;
    }
    // Attempt to decrypt CEK.
    // SAFETY: `ri` is live.
    if unsafe {
        cms_kek_cipher(
            &mut cek,
            &mut ceklen,
            enckey,
            enckeylen,
            (*ri).d.cast::<CmsKeyAgreeRecipientInfo>(),
            0,
        )
    } == 0
    {
        // The helper leaves no block in the slot on failure; the authority's `err:` release is a
        // plain `CRYPTO_free`, run here by `Drop`.
        // SAFETY: `cek` is NULL or a live block the helper allocated and no one else owns.
        let cek_owned = unsafe { OwnedBuf::adopt(cek, c"cms_kari.c".as_ptr(), 281) };
        drop(cek_owned);
        return rv;
    }
    // The decrypted CEK is the helper's block; its release is the authority's plain `CRYPTO_free`.
    // SAFETY: `cek` is a live block the helper allocated and no one else owns.
    let cek_owned = unsafe { OwnedBuf::adopt(cek, c"cms_kari.c".as_ptr(), 281) };
    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    // SAFETY: `ec` is live.
    unsafe { super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen) };
    // SAFETY: `ec` is live; ownership of the block moves into `ec->key`.
    unsafe {
        (*ec).key = cek_owned.into_raw();
        (*ec).keylen = ceklen;
    }
    rv = 1;
    rv
}

/// `int cms_kari_create_ephemeral_key(CMS_KeyAgreeRecipientInfo *kari, EVP_PKEY *pk)` —
/// `cms_kari.c:286-316`.
///
/// # Safety
/// `kari`/`pk` are live.
unsafe fn cms_kari_create_ephemeral_key(
    kari: *mut CmsKeyAgreeRecipientInfo,
    pk: *mut EvpPkey,
) -> c_int {
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut ekey: *mut EvpPkey = ptr::null_mut();
    let mut rv = 0;
    // SAFETY: `kari` is live.
    let ctx = unsafe { (*kari).cms_ctx };
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_cms_ctx_get0_libctx(ctx) };
    // SAFETY: `ctx` is live.
    let propq = unsafe { ossl_cms_ctx_get0_propq(ctx) };

    // SAFETY: `pk` is live.
    pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq) };
    // SAFETY: `pctx` is live.
    if pctx.is_null() || unsafe { EVP_PKEY_keygen_init(pctx) } <= 0 {
        if !pctx.is_null() {
            // SAFETY: the context and key are live.
            unsafe { EVP_PKEY_CTX_free(pctx) };
        }
        // SAFETY: the context and key are live.
        unsafe { EVP_PKEY_free(ekey) };
        return rv;
    }
    // SAFETY: `pctx` is live; `ekey` is this frame's slot.
    if unsafe { EVP_PKEY_keygen(pctx, &mut ekey) } <= 0 {
        // SAFETY: the context and key are live.
        unsafe {
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(ekey);
        }
        return rv;
    }
    // SAFETY: `pctx` is owned here.
    unsafe { EVP_PKEY_CTX_free(pctx) };
    pctx = ptr::null_mut();
    // SAFETY: `ekey` is live.
    pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, ekey, propq) };
    // SAFETY: `pctx` is live.
    if pctx.is_null() || unsafe { EVP_PKEY_derive_init(pctx) } <= 0 {
        if !pctx.is_null() {
            // SAFETY: the context and key are live.
            unsafe { EVP_PKEY_CTX_free(pctx) };
        }
        // SAFETY: the context and key are live.
        unsafe { EVP_PKEY_free(ekey) };
        return rv;
    }
    // SAFETY: `kari` is live.
    unsafe { (*kari).pctx = pctx.cast() };
    rv = 1;
    // SAFETY: `ekey` is owned here.
    unsafe { EVP_PKEY_free(ekey) };
    rv
}

/// `int cms_kari_set_originator_private_key(CMS_KeyAgreeRecipientInfo *kari,`
/// `EVP_PKEY *originatorPrivKey)` — `cms_kari.c:319-340`.
///
/// # Safety
/// `kari`/`originatorPrivKey` are live.
unsafe fn cms_kari_set_originator_private_key(
    kari: *mut CmsKeyAgreeRecipientInfo,
    originator_priv_key: *mut EvpPkey,
) -> c_int {
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut rv = 0;
    // SAFETY: `kari` is live.
    let ctx = unsafe { (*kari).cms_ctx };

    // SAFETY: `originator_priv_key` is live.
    pctx = unsafe {
        EVP_PKEY_CTX_new_from_pkey(
            ossl_cms_ctx_get0_libctx(ctx),
            originator_priv_key,
            ossl_cms_ctx_get0_propq(ctx),
        )
    };
    // SAFETY: `pctx` is live.
    if pctx.is_null() || unsafe { EVP_PKEY_derive_init(pctx) } <= 0 {
        if rv == 0 && !pctx.is_null() {
            // SAFETY: the context and key are live.
            unsafe { EVP_PKEY_CTX_free(pctx) };
        }
        return rv;
    }

    // SAFETY: `kari` is live.
    unsafe { (*kari).pctx = pctx.cast() };
    rv = 1;
    rv
}

/// `int ossl_cms_RecipientInfo_kari_init(CMS_RecipientInfo *ri, X509 *recip,`
/// `EVP_PKEY *recipPubKey, X509 *originator, EVP_PKEY *originatorPrivKey,`
/// `unsigned int flags, const CMS_CTX *ctx)` — `cms_kari.c:344-416`.
///
/// # Safety
/// `ri`/`recip`/`recipPubKey` are live; `originator`/`originatorPrivKey` are NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kari_init(
    ri: *mut CmsRecipientInfo,
    recip: *mut X509,
    recip_pub_key: *mut EvpPkey,
    originator: *mut X509,
    originator_priv_key: *mut EvpPkey,
    flags: c_uint,
    ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: the item answers a fresh key-agree recipient.
    let kari = unsafe { super::cms_asn1::m_asn1_new(cms_keyagreerecipientinfo_it()) }
        .cast::<CmsKeyAgreeRecipientInfo>();
    // SAFETY: `ri` is live.
    unsafe { (*ri).d = kari.cast() };
    if kari.is_null() {
        return 0;
    }
    // SAFETY: `ri` is live.
    unsafe {
        (*ri).encoded_type = CMS_RECIPINFO_AGREE;
        (*ri).type_ = CMS_RECIPINFO_AGREE;
    }

    // SAFETY: `kari` is live.
    unsafe {
        (*kari).version = 3;
        (*kari).cms_ctx = ctx;
    }

    // SAFETY: the item answers a fresh recipient encrypted key.
    let rek =
        unsafe { super::cms_asn1::m_asn1_new(super::cms_asn1::cms_recipientencryptedkey_it()) }
            .cast::<CmsRecipientEncryptedKey>();
    if rek.is_null() {
        return 0;
    }

    // SAFETY: `kari`/`rek` are live.
    if unsafe { OPENSSL_sk_push((*kari).recipient_encrypted_keys, rek.cast()) } == 0 {
        // SAFETY: `rek` is owned here.
        unsafe {
            super::cms_asn1::m_asn1_free(
                rek.cast(),
                super::cms_asn1::cms_recipientencryptedkey_it(),
            )
        };
        return 0;
    }

    if flags & CMS_USE_KEYID != 0 {
        // SAFETY: `rek` is live.
        unsafe { (*(*rek).rid).type_ = CMS_REK_KEYIDENTIFIER };
        // SAFETY: the item answers a fresh identifier.
        let rkid = unsafe {
            super::cms_asn1::m_asn1_new(super::cms_asn1::cms_recipientkeyidentifier_it())
                .cast::<CmsRecipientKeyIdentifier>()
        };
        // SAFETY: `rek` is live.
        unsafe { (*(*rek).rid).d = rkid.cast() };
        if rkid.is_null() {
            return 0;
        }
        // SAFETY: `rkid`/`recip` are live.
        if unsafe { ossl_cms_set1_keyid(&mut (*rkid).subject_key_identifier, recip) } == 0 {
            return 0;
        }
    } else {
        // SAFETY: `rek` is live.
        unsafe { (*(*rek).rid).type_ = CMS_REK_ISSUER_SERIAL };
        // SAFETY: `rek`/`recip` are live; the union slot is the issuer-and-serial member.
        if unsafe {
            ossl_cms_set1_ias(
                &mut (*(*rek).rid).d as *mut *mut c_void as *mut *mut CmsIssuerAndSerialNumber,
                recip,
            )
        } == 0
        {
            return 0;
        }
    }

    if originator_priv_key.is_null() && originator.is_null() {
        // Create ephemeral key.
        // SAFETY: `kari`/`recip_pub_key` are live.
        if unsafe { cms_kari_create_ephemeral_key(kari, recip_pub_key) } == 0 {
            return 0;
        }
    } else {
        // Use originator key.
        // SAFETY: `kari` is live.
        let oik = unsafe { (*kari).originator };

        if originator_priv_key.is_null() || originator.is_null() {
            return 0;
        }

        if flags & CMS_USE_ORIGINATOR_KEYID != 0 {
            // SAFETY: `oik` is live.
            unsafe { (*oik).type_ = CMS_OIK_KEYIDENTIFIER };
            // SAFETY: the allocator answers a fresh octet string.
            let skid = ASN1_OCTET_STRING_new();
            // SAFETY: `oik` is live.
            unsafe { (*oik).d = skid.cast() };
            if skid.is_null() {
                return 0;
            }
            // SAFETY: `skid`/`originator` are live; the union slot is the key-identifier
            // member.
            if unsafe {
                ossl_cms_set1_keyid(
                    &mut (*oik).d as *mut *mut c_void as *mut *mut Asn1String,
                    originator,
                )
            } == 0
            {
                return 0;
            }
        } else {
            // SAFETY: `oik` is live.
            unsafe { (*oik).type_ = CMS_REK_ISSUER_SERIAL };
            // SAFETY: `oik`/`originator` are live; the union slot is the issuer-and-serial
            // member.
            if unsafe {
                ossl_cms_set1_ias(
                    &mut (*oik).d as *mut *mut c_void as *mut *mut CmsIssuerAndSerialNumber,
                    originator,
                )
            } == 0
            {
                return 0;
            }
        }

        // SAFETY: `kari`/`originator_priv_key` are live.
        if unsafe { cms_kari_set_originator_private_key(kari, originator_priv_key) } == 0 {
            return 0;
        }
    }

    // SAFETY: `recip_pub_key` is live.
    if unsafe { EVP_PKEY_up_ref(recip_pub_key) } == 0 {
        return 0;
    }

    // SAFETY: `rek` is live.
    unsafe { (*rek).pkey = recip_pub_key };
    1
}

/// `int ossl_cms_RecipientInfo_kari_encrypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_kari.c:420-473`.
///
/// # Safety
/// `cms`/`ri` are live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kari_encrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_AGREE {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                430,
                c"ossl_cms_RecipientInfo_kari_encrypt",
                ERR_CMS_R_NOT_KEY_AGREEMENT,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let kari = unsafe { (*ri).d.cast::<CmsKeyAgreeRecipientInfo>() };
    // SAFETY: `kari` is live.
    let reks = unsafe { (*kari).recipient_encrypted_keys };
    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    // Initialise wrap algorithm parameters.
    // SAFETY: `ri`/`ec` are live.
    if unsafe { super::cms_env::ossl_cms_RecipientInfo_wrap_init(ri, (*ec).cipher.cast()) } == 0 {
        return 0;
    }
    // SAFETY: `kari` is live.
    if unsafe { (*(*kari).originator).type_ } == -1 {
        // SAFETY: `kari` is live.
        let oik = unsafe { (*kari).originator };
        // SAFETY: `oik` is live.
        unsafe { (*oik).type_ = CMS_OIK_PUBKEY };
        // SAFETY: the item answers a fresh originator public key.
        let ok = unsafe {
            super::cms_asn1::m_asn1_new(super::cms_asn1::cms_originatorpublickey_it())
                .cast::<CmsOriginatorPublicKey>()
        };
        // SAFETY: `oik` is live.
        unsafe { (*oik).d = ok.cast() };
        if ok.is_null() {
            return 0;
        }
    } else {
        // Currently it is not possible to get public key as it is not stored during kari
        // initialization.
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                454,
                c"ossl_cms_RecipientInfo_kari_encrypt",
                crate::runtime::err::err_reasons::CMS_R_ERROR_UNSUPPORTED_STATIC_KEY_AGREEMENT,
            )
        };
        return 0;
    }
    // Initialise KDF algorithm.
    // SAFETY: `ri` is live.
    if unsafe { super::cms_env::ossl_cms_env_asn1_ctrl(ri, 0) } == 0 {
        return 0;
    }
    // For each rek, derive KEK, encrypt CEK.
    // SAFETY: `reks` is live.
    let n = unsafe { OPENSSL_sk_num(reks) };
    for i in 0..n {
        // SAFETY: `i` is in range.
        let rek = unsafe { OPENSSL_sk_value(reks, i) }.cast::<CmsRecipientEncryptedKey>();
        // SAFETY: `kari`/`rek` are live.
        if unsafe { EVP_PKEY_derive_set_peer((*kari).pctx.cast(), (*rek).pkey) } <= 0 {
            return 0;
        }
        let mut enckey: *mut c_uchar = ptr::null_mut();
        let mut enckeylen = 0usize;
        // SAFETY: `ec`/`kari` are live.
        if unsafe {
            cms_kek_cipher(
                &mut enckey,
                &mut enckeylen,
                (*ec).key,
                (*ec).keylen,
                kari,
                1,
            )
        } == 0
        {
            return 0;
        }
        // SAFETY: `rek`/`enckey` are live; ownership transfers.
        unsafe { ASN1_STRING_set0((*rek).encrypted_key, enckey.cast(), enckeylen as c_int) };
    }

    1
}

/// The error reason the key-agreement arms raise; the name lives in `cms_err.c`.
const ERR_CMS_R_NOT_KEY_AGREEMENT: c_int =
    crate::runtime::err::err_reasons::CMS_R_NOT_KEY_AGREEMENT;
