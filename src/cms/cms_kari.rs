//! `crypto/cms/cms_kari.c` — the key-agreement recipient engine: ephemeral-key setup, the KEK
//! derivation and the recipient-encrypted-key surface. Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
// The authority's C initialisers are dead on the paths that reach its `err:` label; the
// assignments are kept so the transcription reads as the source does.
#![allow(unused_assignments)]

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_new, ASN1_STRING_set0};
use crate::asn1::x_algor::X509Algor;
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_reset,
    EVP_CipherInit_ex, EVP_CipherUpdate, EvpCipherCtx,
};
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_up_ref, EvpPkey};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EvpPkeyCtx};
use crate::evp::pmeth_gn::{EVP_PKEY_keygen, EVP_PKEY_keygen_init};
use crate::runtime::mem::OPENSSL_cleanse;
use crate::runtime::owned_buf::OwnedBuf;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x_x509::X509;

use super::cms_asn1::*;
use super::cms_env::{declared_update_extent, reported_extent, SecretScratch};
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, ossl_cms_ias_cert_cmp,
    ossl_cms_keyid_cert_cmp, ossl_cms_set1_ias, ossl_cms_set1_keyid, raise_cms,
};
use crate::runtime::mem_coords::SeamFile;

/// `CMS_USE_KEYID` — `cms.h.in:100`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_USE_ORIGINATOR_KEYID` — `cms.h.in:103`.
const CMS_USE_ORIGINATOR_KEYID: c_uint = 0x200000;
/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;

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
    // Release whatever the slot held. The authority frees the incumbent first, even when `pk` is
    // NULL; the slot also clears the field.
    // The recipient is live for this call.
    drop(KariAgreeCtx(kari));
    if pk.is_null() {
        return 1;
    }

    // SAFETY: `kari` is live; `pk` is live.
    let Some(pctx) = (unsafe {
        OwnedPkeyCtx::adopt(EVP_PKEY_CTX_new_from_pkey(
            ossl_cms_ctx_get0_libctx((*kari).cms_ctx),
            pk,
            ossl_cms_ctx_get0_propq((*kari).cms_ctx),
        ))
    }) else {
        return 0;
    };
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_derive_init(pctx.as_ptr()) } <= 0 {
        return 0;
    }

    if !peer.is_null() {
        // SAFETY: `peer` is live.
        let pub_pkey = unsafe { X509_get0_pubkey(peer) };

        // SAFETY: `pctx`/`pub_pkey` are live.
        if unsafe { EVP_PKEY_derive_set_peer(pctx.as_ptr(), pub_pkey) } <= 0 {
            return 0;
        }
    }

    // SAFETY: `kari` is live; the context transfers into the recipient's slot.
    unsafe { (*kari).pctx = pctx.into_raw().cast() };
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

/// An `EVP_PKEY_CTX` this frame owns.
struct OwnedPkeyCtx(core::ptr::NonNull<EvpPkeyCtx>);

impl OwnedPkeyCtx {
    /// # Safety
    /// `p` is NULL or a live context whose ownership the caller transfers.
    unsafe fn adopt(p: *mut EvpPkeyCtx) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    fn as_ptr(&self) -> *mut EvpPkeyCtx {
        self.0.as_ptr()
    }

    /// Transfer the context to the recipient's slot.
    fn into_raw(self) -> *mut EvpPkeyCtx {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for OwnedPkeyCtx {
    fn drop(&mut self) {
        // SAFETY: this frame holds the only reference.
        unsafe { EVP_PKEY_CTX_free(self.0.as_ptr()) };
    }
}

/// An `EVP_PKEY` this frame owns.
struct OwnedPkey(core::ptr::NonNull<EvpPkey>);

impl OwnedPkey {
    /// # Safety
    /// `p` is NULL or a live key whose reference the caller transfers.
    unsafe fn adopt(p: *mut EvpPkey) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    fn as_ptr(&self) -> *mut EvpPkey {
        self.0.as_ptr()
    }
}

impl Drop for OwnedPkey {
    fn drop(&mut self) {
        // SAFETY: this frame holds the only reference.
        unsafe { EVP_PKEY_free(self.0.as_ptr()) };
    }
}

/// The `kari->pctx` slot.
///
/// The agreement context lives **in the field** while an operation runs (the ASN.1 callbacks reach
/// it through `CMS_RecipientInfo_kari_get0_ctx` and the KDF arm), so the slot releases it on every
/// exit and clears the field. Clearing stops the recipient's destructor from releasing it again;
/// releasing here stops any failure arm from leaking it.
struct KariAgreeCtx(*mut CmsKeyAgreeRecipientInfo);

impl Drop for KariAgreeCtx {
    fn drop(&mut self) {
        // SAFETY: the recipient is live for this owner's lifetime.
        unsafe {
            let p = (*self.0).pctx;
            (*self.0).pctx = ptr::null_mut();
            EVP_PKEY_CTX_free(p.cast());
        }
    }
}

/// Resets the recipient's cipher context on every exit. `EVP_CIPHER_CTX_reset` keeps the
/// allocation and zeroes its state, which is the authority's own `kari->ctx` cleanup.
struct KariCipherCtxReset(*mut CmsKeyAgreeRecipientInfo);

impl Drop for KariCipherCtxReset {
    fn drop(&mut self) {
        // SAFETY: the recipient is live for this owner's lifetime.
        unsafe { EVP_CIPHER_CTX_reset((*self.0).ctx.cast()) };
    }
}

/// The derived KEK, cleansed on every exit at the length the derivation produced.
struct DerivedKek {
    bytes: [u8; EVP_MAX_KEY_LENGTH],
    len: usize,
}

impl Drop for DerivedKek {
    fn drop(&mut self) {
        // The buffer extent, not a provider report, bounds the cleansing write: a derivation
        // that reports more than the `EVP_MAX_KEY_LENGTH` buffer it was given must not enlarge
        // the cleanse past this frame's allocation.
        let len = self.len.min(self.bytes.len());
        // SAFETY: `bytes` is a live `EVP_MAX_KEY_LENGTH` buffer and `len` is bounded by it.
        unsafe { OPENSSL_cleanse(self.bytes.as_mut_ptr().cast(), len) };
    }
}

/// The block produced by one KEK cipher operation.
///
/// This is the whole output contract in one value: the authority's allocation
/// (`cms_kari.c:235`, its extent recorded in `capacity`), the provider's reported and
/// validated initialised prefix (`produced`, never larger than `capacity`), and the single
/// owner of the seam block. Nothing is published until [`Self::publish_into`] consumes it;
/// every earlier failure drops it through the authority's cleansing release.
struct CipherOutput {
    block: OwnedBuf,
    /// The authority's allocation extent, `max(queried, in_len)`.
    capacity: usize,
    /// The validated initialised prefix, never larger than `capacity`.
    produced: usize,
}

impl CipherOutput {
    fn new(block: OwnedBuf, capacity: usize, produced: usize) -> Option<Self> {
        (produced <= capacity).then_some(Self {
            block,
            capacity,
            produced,
        })
    }

    /// The validated output length. This, never a bare provider report, is what becomes the
    /// published key length.
    fn produced(&self) -> usize {
        self.produced
    }

    /// Give the block to a raw consumer (`ASN1_STRING_set0`) together with its length.
    fn into_raw_parts(self) -> (*mut c_uchar, usize) {
        (self.block.into_raw(), self.produced)
    }

    /// Publish this block as the container's content key.
    ///
    /// This is the single publication point for the recipient handoff: the incumbent is
    /// released and the new block and its validated length are installed in one non-fallible
    /// step, so exactly one owner exists before and after.
    ///
    /// # Safety
    /// `ec` is live; this handle owns the whole seam block and `produced <= capacity`.
    unsafe fn publish_into(self, ec: *mut CmsEncryptedContentInfo) {
        let (ptr_, len) = self.into_raw_parts();
        // SAFETY: `ec` is live; ownership of this frame's block moves into `ec->key` exactly
        // once, and `len` is the validated prefix no larger than the block.
        unsafe {
            super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
            (*ec).key = ptr_;
            (*ec).keylen = len;
        }
    }
}

/// Run the two-pass cipher over `input` and return the single-owned, validated output.
///
/// The first call only queries the length. The block the provider is actually told it may
/// fill (`in_len + block_size`, exactly `in_len` for a one-byte block) is allocated
/// **before** the second call, and the authority's own allocation is sized from the query as
/// before. The second call's report is accepted only if it fits both extents; it is never
/// used as an offset or a published length merely because the call returned success. That
/// includes the primitive's integrity-failure path, where a provider may write and cleanse up
/// to `in_len + block_size` bytes before reporting failure: the writes land in the staging
/// block, not in the smaller authority allocation.
///
/// # Safety
/// `ctx` is live and initialised for `enc`; `input` is readable for `in_len`, which fits
/// `c_int`.
unsafe fn cipher_output(
    ctx: *mut EvpCipherCtx,
    input: *const c_uchar,
    in_len: usize,
) -> Option<CipherOutput> {
    if in_len == 0 || in_len > c_int::MAX as usize || input.is_null() {
        return None;
    }
    // SAFETY: `ctx` is live per this function's contract.
    let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
    let stage_capacity = declared_update_extent(in_len, block_size)?;
    let mut stage = SecretScratch::new(stage_capacity)?;

    let in_len = in_len as c_int;
    let mut reported: c_int = 0;
    // SAFETY: `ctx` is live; a NULL output is the authority's length query.
    if unsafe { EVP_CipherUpdate(ctx, ptr::null_mut(), &mut reported, input, in_len) } == 0 {
        return None;
    }
    let queried = reported_extent(reported, usize::MAX)?;
    // The authority's allocation extent (`cms_kari.c:234`): `max(outlen, in_len)`. A refused
    // allocation is a refused operation, exactly as it was before the staging block.
    let capacity = queried.max(in_len as usize);
    // SAFETY: `capacity > 0` because `in_len > 0`.
    let block = OwnedBuf::new_cleansed_released(
        capacity,
        SeamFile::new(c"cms_kari.c"),
        235,
        SeamFile::NULL,
        0,
    )?;

    // SAFETY: `ctx` is live, and `stage` holds exactly the extent the provider is told it may
    // fill, so a conforming provider cannot write past what it was told.
    if unsafe { EVP_CipherUpdate(ctx, stage.as_mut_ptr(), &mut reported, input, in_len) } == 0 {
        // `stage` and `block` cleanse and release themselves on drop.
        return None;
    }
    let produced = reported_extent(reported, stage_capacity)?;
    if produced > capacity {
        // A report past the authority's allocation would make the published length exceed the
        // block its destructor cleanses; refuse it rather than use it as `keylen`.
        return None;
    }
    // Only the validated prefix is the key. `stage` cleanses the whole staged extent on its
    // way out; the authority's block keeps its exact extent and the validated length.
    // SAFETY: `produced` fits both `stage` and `block`, and the two are distinct allocations.
    unsafe { ptr::copy_nonoverlapping(stage.as_ptr(), block.as_ptr(), produced) };
    CipherOutput::new(block, capacity, produced)
}

/// `int cms_kek_cipher(unsigned char **pout, size_t *poutlen, const unsigned char *in,``
/// `size_t inlen, CMS_KeyAgreeRecipientInfo *kari, int enc)` — `cms_kari.c:204-254`.
///
/// The authority's out-parameters become one [`CipherOutput`]: capacity, validated length,
/// owner and transfer state cannot be separated from each other by a caller.
///
/// # Safety
/// `input` is readable for `inlen`; `kari` is live.
unsafe fn cms_kek_cipher(
    input: *const c_uchar,
    inlen: usize,
    kari: *mut CmsKeyAgreeRecipientInfo,
    enc: c_int,
) -> Option<CipherOutput> {
    // SAFETY: `kari` is live.
    let keklen = unsafe { EVP_CIPHER_CTX_get_key_length((*kari).ctx.cast()) } as usize;
    if keklen > EVP_MAX_KEY_LENGTH || inlen == 0 || inlen > c_int::MAX as usize || input.is_null() {
        return None;
    }
    // Every exit below cleanses the KEK, resets the cipher context and releases the agreement
    // context in the authority's order -- reverse declaration order does it: KEK, cipher, pkey.
    // The recipient is live for this call.
    let _agree = KariAgreeCtx(kari);
    // The recipient is live for this call.
    let _ctx = KariCipherCtxReset(kari);
    let mut kek = DerivedKek {
        bytes: [0u8; EVP_MAX_KEY_LENGTH],
        len: keklen,
    };
    // Derive KEK.
    // SAFETY: `kari` is live; `kek` is writable for `kek.len`.
    if unsafe { EVP_PKEY_derive((*kari).pctx.cast(), kek.bytes.as_mut_ptr(), &mut kek.len) } <= 0 {
        return None;
    }
    // Set KEK in context.
    // SAFETY: `kari` is live; `kek` is readable for `kek.len`.
    if unsafe {
        EVP_CipherInit_ex(
            (*kari).ctx.cast(),
            ptr::null(),
            ptr::null_mut(),
            kek.bytes.as_ptr(),
            ptr::null(),
            enc,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: the context is initialised by the two calls above, and the length and input were
    // validated above.
    unsafe { cipher_output((*kari).ctx.cast(), input, inlen) }
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
    // SAFETY: `rek` is live.
    let enckeylen = unsafe { (*(*rek).encrypted_key).length } as usize;
    // SAFETY: `rek` is live.
    let enckey = unsafe { (*(*rek).encrypted_key).data };
    // Setup all parameters to derive KEK.
    // SAFETY: `ri` is live.
    if unsafe { super::cms_env::ossl_cms_env_asn1_ctrl(ri, 1) } == 0 {
        return 0;
    }
    // The helper hands back the single owner of the CEK block. It remains the only owner until
    // the publication point below; derivation, cipher-initialisation and candidate-processing
    // failures all drop it through the authority's cleansing release, and no raw pointer is
    // ever published into the slot on those paths.
    // SAFETY: `ri` is live; `enckey` is readable for `enckeylen` (both come from the
    // decrypted-key field).
    let Some(key) = (unsafe {
        cms_kek_cipher(
            enckey,
            enckeylen,
            (*ri).d.cast::<CmsKeyAgreeRecipientInfo>(),
            0,
        )
    }) else {
        return 0;
    };
    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    if ec.is_null() {
        // The authority dereferences this unconditionally; refusing is the safe deviation. The
        // candidate owner releases the CEK exactly once on this path.
        return 0;
    }
    // SAFETY: `ec` is live; `key` is the only owner of the block and is consumed by the
    // single publication point.
    unsafe { key.publish_into(ec) };
    1
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
    // SAFETY: `kari` is live.
    let ctx = unsafe { (*kari).cms_ctx };
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_cms_ctx_get0_libctx(ctx) };
    // SAFETY: `ctx` is live.
    let propq = unsafe { ossl_cms_ctx_get0_propq(ctx) };

    // SAFETY: `pk` is live.
    let Some(keygen_ctx) =
        (unsafe { OwnedPkeyCtx::adopt(EVP_PKEY_CTX_new_from_pkey(libctx, pk, propq)) })
    else {
        return 0;
    };
    // SAFETY: `keygen_ctx` is live.
    if unsafe { EVP_PKEY_keygen_init(keygen_ctx.as_ptr()) } <= 0 {
        return 0;
    }
    let mut ekey: *mut EvpPkey = ptr::null_mut();
    // SAFETY: `keygen_ctx` is live; `ekey` is this frame's slot.
    if unsafe { EVP_PKEY_keygen(keygen_ctx.as_ptr(), &mut ekey) } <= 0 {
        return 0;
    }
    // The key generator is done with; release it before the agreement context is created.
    drop(keygen_ctx);
    // SAFETY: a successful `EVP_PKEY_keygen` wrote a fresh key into `ekey`.
    let Some(ekey) = (unsafe { OwnedPkey::adopt(ekey) }) else {
        return 0;
    };
    // SAFETY: `ekey` is live.
    let Some(pctx) =
        (unsafe { OwnedPkeyCtx::adopt(EVP_PKEY_CTX_new_from_pkey(libctx, ekey.as_ptr(), propq)) })
    else {
        return 0;
    };
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_derive_init(pctx.as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `kari` is live; the context transfers into the recipient's slot. The context holds
    // its own reference to `ekey`, which drops at the end of this frame.
    unsafe { (*kari).pctx = pctx.into_raw().cast() };
    1
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
    // SAFETY: `kari` is live.
    let ctx = unsafe { (*kari).cms_ctx };

    // SAFETY: `originator_priv_key` is live.
    let Some(pctx) = (unsafe {
        OwnedPkeyCtx::adopt(EVP_PKEY_CTX_new_from_pkey(
            ossl_cms_ctx_get0_libctx(ctx),
            originator_priv_key,
            ossl_cms_ctx_get0_propq(ctx),
        ))
    }) else {
        return 0;
    };
    // SAFETY: `pctx` is live.
    if unsafe { EVP_PKEY_derive_init(pctx.as_ptr()) } <= 0 {
        return 0;
    }

    // SAFETY: `kari` is live; the context transfers into the recipient's slot.
    unsafe { (*kari).pctx = pctx.into_raw().cast() };
    1
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
        // SAFETY: `ec`/`kari` are live.
        let Some(enckey) = (unsafe { cms_kek_cipher((*ec).key, (*ec).keylen, kari, 1) }) else {
            return 0;
        };
        let (ptr_, len) = enckey.into_raw_parts();
        // SAFETY: `rek`/`ptr_` are live; ownership transfers. `len` is the validated produced
        // length and is at most the authority's allocation, itself at most `c_int::MAX`.
        unsafe { ASN1_STRING_set0((*rek).encrypted_key, ptr_.cast(), len as c_int) };
    }

    1
}

/// The error reason the key-agreement arms raise; the name lives in `cms_err.c`.
const ERR_CMS_R_NOT_KEY_AGREEMENT: c_int =
    crate::runtime::err::err_reasons::CMS_R_NOT_KEY_AGREEMENT;

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::evp::cipher::{EVP_CIPHER_meth_free, EVP_CIPHER_meth_new, EvpCipher};
    use crate::evp::pkey::EVP_PKEY_new;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_set_group_name};

    /// A live `CMS_RecipientInfo` in the AGREE arm with no agreement context installed.
    ///
    /// # Safety
    /// The caller owns the recipient and must free it with `cms_recipientinfo_it`.
    unsafe fn agree_recipient() -> (*mut CmsRecipientInfo, *mut CmsKeyAgreeRecipientInfo) {
        // SAFETY: the item answers a fresh recipient and a fresh AGREE arm.
        unsafe {
            let ri = m_asn1_new(cms_recipientinfo_it()).cast::<CmsRecipientInfo>();
            assert!(!ri.is_null());
            let kari =
                m_asn1_new(cms_keyagreerecipientinfo_it()).cast::<CmsKeyAgreeRecipientInfo>();
            assert!(!kari.is_null());
            (*ri).d = kari.cast();
            (*ri).encoded_type = CMS_RECIPINFO_AGREE;
            (*ri).type_ = CMS_RECIPINFO_AGREE;
            (*kari).cms_ctx = ptr::null();
            (ri, kari)
        }
    }

    /// The slot owns `kari->pctx` for an operation and clears the field when it releases it, so
    /// the recipient's destructor cannot release the same context a second time.
    #[test]
    fn kari_agree_slot_clears_the_field_before_releasing() {
        // SAFETY: the recipient is live; the context is a fresh keymgmt context transferred to
        // the slot.
        unsafe {
            let (ri, kari) = agree_recipient();
            let pctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"EC".as_ptr(), ptr::null());
            assert!(!pctx.is_null(), "a keymgmt context must be available");
            (*kari).pctx = pctx.cast();
            drop(KariAgreeCtx(kari));
            assert!(
                (*kari).pctx.is_null(),
                "the slot must clear the field it released"
            );
            // The recipient's destructor now has nothing to release.
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
        }
    }

    // -------------------------------------------------------------------------------------
    // KEK cipher output: capacity established before dispatch, one owner, one publication
    // -------------------------------------------------------------------------------------

    /// What one fake provider call does: the length it reports for the NULL-output query and,
    /// for the real call, how much it writes (bounded by the declared extent) and reports.
    #[derive(Clone, Copy)]
    struct UpdateScript {
        query_report: usize,
        write: usize,
        report: usize,
    }

    // SAFETY: `out` is writable for `outsize` bytes per the dispatch contract; `state` is this
    // test's own plain-old-data record.
    unsafe extern "C" fn scripted_update(
        state: *mut c_void,
        out: *mut c_uchar,
        outl: *mut usize,
        outsize: usize,
        _input: *const c_uchar,
        _inl: usize,
    ) -> c_int {
        // SAFETY: the dispatch contract gives `out` `outsize` writable bytes.
        unsafe {
            let s = *state.cast::<UpdateScript>();
            if out.is_null() {
                *outl = s.query_report;
            } else {
                let write = s.write.min(outsize);
                if write > 0 {
                    ptr::write_bytes(out, 0x5A, write);
                }
                *outl = s.report;
            }
        }
        1
    }

    /// A hand-built provider method and context for [`cipher_output`].
    ///
    /// # Safety
    /// The returned method must be released with `EVP_CIPHER_meth_free` after its `prov`
    /// marker is cleared, and the context is a plain-old-data value whose callback reads only
    /// `state`.
    unsafe fn scripted_ctx(state: *mut UpdateScript) -> (*mut EvpCipher, EvpCipherCtx) {
        // SAFETY: the constructor answers a fresh `EVP_ORIG_METH` method or NULL.
        let cipher = unsafe { EVP_CIPHER_meth_new(0, 8, 16) };
        assert!(!cipher.is_null());
        // SAFETY: `cipher` is this test's live method; every field write is to it.
        unsafe {
            // A non-NULL marker selects the provider arm; the method is released with it
            // cleared below so nothing dereferences the marker.
            (*cipher).prov = state.cast();
            (*cipher).cupdate = Some(scripted_update);
        }
        // SAFETY: an all-zero `EvpCipherCtx` is its constructed empty state.
        let mut ctx: EvpCipherCtx = unsafe { core::mem::zeroed() };
        ctx.cipher = cipher;
        ctx.encrypt = 0;
        ctx.algctx = state.cast();
        (cipher, ctx)
    }

    /// A provider whose report exceeds the extent it was told it could fill is refused, and the
    /// staging block is not enlarged to accommodate the lie.
    #[test]
    fn cms_kari_provider_reports_more_output_than_capacity() {
        let in_len = 24usize;
        assert_eq!(declared_update_extent(in_len, 8), Some(32));
        let data = [0x33u8; 24];
        // SAFETY: every pointer is this frame's; the fixture meets `cipher_output`'s contract.
        unsafe {
            // The report itself is one past the 32-byte extent the provider was told it may
            // fill (the write is clamped there by the fixture, as a conforming provider would).
            let mut state = UpdateScript {
                query_report: 32,
                write: 32,
                report: 33,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), in_len).is_none(),
                "a report past the declared output extent is refused"
            );
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);

            // A large report without a write is refused just the same.
            let mut state = UpdateScript {
                query_report: 32,
                write: 0,
                report: 4096,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), in_len).is_none(),
                "the report is validated, not trusted because the call succeeded"
            );
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);
        }
    }

    /// The query and the successful update disagree: the second report fits the staging extent
    /// but not the authority's allocation, which would make the published key length exceed the
    /// block its destructor cleanses. An honest pair is accepted with the validated length.
    #[test]
    fn cms_kari_provider_output_length_disagreement_on_success() {
        let in_len = 24usize;
        let data = [0x44u8; 24];
        // SAFETY: every pointer is this frame's; the fixture meets `cipher_output`'s contract.
        unsafe {
            // Query says 16, so the authority allocates `max(16, 24) = 24`; the successful
            // update reports 32, which fits the staging extent but not the allocation.
            let mut state = UpdateScript {
                query_report: 16,
                write: 32,
                report: 32,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), in_len).is_none(),
                "a produced length past the authority's block is refused"
            );
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);

            // Honest pair: the validated length is the reported one and fits the allocation.
            let mut state = UpdateScript {
                query_report: 32,
                write: 32,
                report: 32,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            let out = cipher_output(&mut ctx, data.as_ptr(), in_len)
                .unwrap_or_else(|| panic!("an honest two-pass output is accepted"));
            assert_eq!(out.produced(), 32);
            assert_eq!(out.capacity, 32);
            drop(out);
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);
        }
    }

    /// Malformed encrypted-key lengths are refused before any provider dispatch: zero length, a
    /// NULL data pointer with a positive length, a length the C ABI cannot represent, and an
    /// extent whose arithmetic overflows.
    #[test]
    fn cms_kari_malformed_encrypted_key_lengths_are_refused() {
        let data = [0x55u8; 32];
        // SAFETY: every pointer is this frame's; no scripted call is reached for the refused
        // lengths, and the honest fixture meets `cipher_output`'s contract.
        unsafe {
            let mut state = UpdateScript {
                query_report: 32,
                write: 32,
                report: 32,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), 0).is_none(),
                "a zero-length encrypted key is refused"
            );
            assert!(
                cipher_output(&mut ctx, ptr::null(), 24).is_none(),
                "a NULL encrypted key with a positive length is refused"
            );
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), c_int::MAX as usize + 1).is_none(),
                "a length the C ABI cannot represent is refused"
            );
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);
        }
        assert!(
            declared_update_extent(usize::MAX, 8).is_none(),
            "overflowing extent arithmetic is refused"
        );
    }

    /// §16 negative control (test-only): the pre-fix pairing -- a provider told it may write
    /// `in_len + block_size` bytes into the authority's `max(queried, in_len)` block, which for
    /// a decrypt-like query is `in_len` -- is exactly what the capacity detector refuses. The
    /// canary fires on the old shape, not on the new one.
    #[test]
    fn cms_kari_negative_control_pre_fix_undersized_output_is_detected() {
        let in_len = 24usize;
        let block = 8;
        let declared = declared_update_extent(in_len, block).unwrap();
        let queried = in_len - 8;
        let pre_fix_capacity = queried.max(in_len);
        assert!(
            declared > pre_fix_capacity,
            "the pre-fix block is smaller than the extent the provider is told it may fill"
        );
        assert!(
            reported_extent(declared as c_int, pre_fix_capacity).is_none(),
            "the capacity detector must fire on the pre-fix report/buffer pairing"
        );
    }

    /// Count the seam releases of one address in the current probe window.
    #[cfg(test)]
    fn frees(p: *const c_void) -> usize {
        crate::ssl::adv_alloc::events()
            .into_iter()
            .filter(|e| matches!(e, crate::ssl::adv_alloc::Ev::Free { p: q } if *q == p as usize))
            .count()
    }

    /// A refused output allocation is a refused operation and leaves no partially built output;
    /// a retry succeeds.
    #[test]
    #[ignore = "process-global allocator probe; run via scripts/adv-probe.sh"]
    fn cms_kari_output_allocation_refusal_is_a_refused_operation() {
        let _g = crate::test_support::lock_global_state();
        assert!(crate::ssl::adv_alloc::install());
        crate::ssl::adv_alloc::assert_instrument_live();
        let data = [0x66u8; 24];
        // SAFETY: the fixture meets `cipher_output`'s contract and the armed refusal is this
        // test's own.
        unsafe {
            let mut state = UpdateScript {
                query_report: 32,
                write: 32,
                report: 32,
            };
            let (cipher, mut ctx) = scripted_ctx(&mut state);
            // The authority's block is `max(32, 24) = 32` bytes.
            crate::ssl::adv_alloc::arm_any(32);
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), 24).is_none(),
                "a refused output allocation fails the operation"
            );
            crate::ssl::adv_alloc::disarm_any();
            crate::ssl::adv_alloc::assert_no_double_free();
            assert!(
                cipher_output(&mut ctx, data.as_ptr(), 24).is_some(),
                "a retry after the refusal succeeds"
            );
            crate::ssl::adv_alloc::assert_no_double_free();
            crate::ssl::adv_alloc::reset();
            (*cipher).prov = ptr::null_mut();
            EVP_CIPHER_meth_free(cipher);
        }
    }

    /// A key-agreement recipient and a live enveloped container with a known content key.
    ///
    /// # Safety
    /// The caller owns `ri`/`rek`/`cms` and releases them with the matching ASN.1/CMS free.
    unsafe fn agree_cms_fixture() -> (
        *mut CmsContentInfo,
        *mut CmsEncryptedContentInfo,
        *mut CmsRecipientInfo,
        *mut CmsKeyAgreeRecipientInfo,
        *mut CmsRecipientEncryptedKey,
    ) {
        // SAFETY: every block below is owned and transferred to the caller.
        unsafe {
            let cms =
                crate::cms::cms_env::CMS_EnvelopedData_create(crate::evp::e_aes::EVP_aes_128_cbc());
            assert!(!cms.is_null());
            let ec = crate::cms::cms_env::ossl_cms_get0_env_enc_content(cms);
            assert!(!ec.is_null());
            let (ri, kari) = agree_recipient();
            let rek = m_asn1_new(cms_recipientencryptedkey_it()).cast::<CmsRecipientEncryptedKey>();
            assert!(!rek.is_null());
            if (*rek).encrypted_key.is_null() {
                (*rek).encrypted_key = ASN1_OCTET_STRING_new();
            }
            assert!(!(*rek).encrypted_key.is_null());
            let blob = OwnedBuf::new(24, SeamFile::NULL, 0)
                .unwrap_or_else(|| panic!("the fixture allocation must succeed"))
                .into_raw();
            ASN1_STRING_set0((*rek).encrypted_key, blob.cast(), 24);
            (cms, ec, ri, kari, rek)
        }
    }

    /// Derivation fails (an agreement context with no key). The agreement context is released
    /// exactly once by address and the slot is cleared; nothing else is touched.
    #[test]
    #[ignore = "process-global allocator probe; run via scripts/adv-probe.sh"]
    fn cms_kari_derivation_failure_releases_the_agreement_context_once_by_address() {
        let _g = crate::test_support::lock_global_state();
        assert!(crate::ssl::adv_alloc::install());
        crate::ssl::adv_alloc::assert_instrument_live();
        let data = [0x77u8; 24];
        // SAFETY: the fixture is live; the probe observes only the installed seam.
        unsafe {
            let (cms, _ec, ri, kari, rek) = agree_cms_fixture();
            let pctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"EC".as_ptr(), ptr::null());
            assert!(!pctx.is_null());
            let pctx_addr = pctx.cast::<c_void>();
            (*kari).pctx = pctx_addr;
            crate::ssl::adv_alloc::reset();
            assert!(
                cms_kek_cipher(data.as_ptr(), data.len(), kari, 0).is_none(),
                "an agreement context with no key cannot derive"
            );
            assert!(
                (*kari).pctx.is_null(),
                "the slot cleared the field it released"
            );
            assert_eq!(
                frees(pctx_addr),
                1,
                "the agreement context is released once"
            );
            crate::ssl::adv_alloc::assert_no_double_free();
            crate::ssl::adv_alloc::reset();
            m_asn1_free(rek.cast(), cms_recipientencryptedkey_it());
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
            crate::cms::cms_lib::CMS_ContentInfo_free(cms);
        }
    }

    /// A refusing legacy cipher init makes cipher initialisation the failing step after a real
    /// key agreement. The agreement context is released exactly once and the cipher context is
    /// reset in place, not released.
    #[test]
    #[ignore = "process-global allocator probe; run via scripts/adv-probe.sh"]
    fn cms_kari_cipher_init_failure_releases_the_agreement_context_once_by_address() {
        let _g = crate::test_support::lock_global_state();
        assert!(crate::ssl::adv_alloc::install());
        crate::ssl::adv_alloc::assert_instrument_live();
        let data = [0x88u8; 24];
        // SAFETY: the fixture is live; the probe observes only the installed seam.
        unsafe {
            let (cms, _ec, ri, kari, rek) = agree_cms_fixture();
            let (key_a, key_b) = ec_keypair();
            let pctx = deriving_pctx(key_a, key_b);
            let pctx_addr = pctx.cast::<c_void>();
            (*kari).pctx = pctx_addr;

            // A cipher with a positive key length and an init that refuses: derivation succeeds
            // and `EVP_CipherInit_ex` is the failing step.
            // SAFETY: the constructor answers a fresh method or NULL; every write is to it.
            let cipher = EVP_CIPHER_meth_new(0, 8, 16);
            assert!(!cipher.is_null());
            (*cipher).init = Some(refusing_init);
            let ctx = (*kari).ctx.cast::<EvpCipherCtx>();
            (*ctx).cipher = cipher;
            (*ctx).key_len = 16;
            (*ctx).encrypt = 0;
            let ctx_addr = (*kari).ctx;

            crate::ssl::adv_alloc::reset();
            assert!(
                cms_kek_cipher(data.as_ptr(), data.len(), kari, 0).is_none(),
                "a refused cipher initialisation fails the operation"
            );
            assert!(
                (*kari).pctx.is_null(),
                "the slot cleared the field it released"
            );
            assert_eq!(
                frees(pctx_addr),
                1,
                "the agreement context is released once"
            );
            assert_eq!(
                (*kari).ctx,
                ctx_addr,
                "the cipher context is reset in place, not reallocated"
            );
            assert_eq!(frees(ctx_addr), 0, "the failed operation keeps the context");
            crate::ssl::adv_alloc::assert_no_double_free();

            crate::ssl::adv_alloc::reset();
            EVP_PKEY_free(key_a);
            EVP_PKEY_free(key_b);
            EVP_CIPHER_meth_free(cipher);
            m_asn1_free(rek.cast(), cms_recipientencryptedkey_it());
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
            crate::cms::cms_lib::CMS_ContentInfo_free(cms);
        }
    }

    // SAFETY: the legacy `EVP_CIPHER::init` contract; this test method always refuses.
    unsafe extern "C" fn refusing_init(
        _ctx: *mut c_void,
        _key: *const u8,
        _iv: *const u8,
        _enc: c_int,
    ) -> c_int {
        0
    }

    /// One real EC key pair generated through the keymgmt path.
    ///
    /// # Safety
    /// The caller owns both keys and releases them with `EVP_PKEY_free`.
    unsafe fn ec_keypair() -> (*mut EvpPkey, *mut EvpPkey) {
        // SAFETY: each context is this frame's and is released below on every path taken.
        unsafe {
            let mut keys = [ptr::null_mut(), ptr::null_mut()];
            for slot in keys.iter_mut() {
                let kctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"EC".as_ptr(), ptr::null());
                assert!(!kctx.is_null());
                assert!(EVP_PKEY_keygen_init(kctx) > 0);
                assert!(EVP_PKEY_CTX_set_group_name(kctx, c"P-256".as_ptr()) > 0);
                assert!(EVP_PKEY_keygen(kctx, slot) > 0);
                EVP_PKEY_CTX_free(kctx);
            }
            (keys[0], keys[1])
        }
    }

    /// An agreement context over `key` with `peer` installed.
    ///
    /// # Safety
    /// `key`/`peer` are live and outlive the returned context.
    unsafe fn deriving_pctx(key: *mut EvpPkey, peer: *mut EvpPkey) -> *mut EvpPkeyCtx {
        // SAFETY: the constructor answers a fresh context; each call is given live operands.
        unsafe {
            let pctx = EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), key, ptr::null());
            assert!(!pctx.is_null());
            assert!(EVP_PKEY_derive_init(pctx) > 0);
            assert!(EVP_PKEY_derive_set_peer(pctx, peer) > 0);
            pctx
        }
    }

    /// Recipient processing (`ossl_cms_env_asn1_ctrl`) fails before any agreement work. The
    /// incumbent content key is not released by the failed call, is untouched by address, and
    /// the container later releases it exactly once.
    #[test]
    #[ignore = "process-global allocator probe; run via scripts/adv-probe.sh"]
    fn cms_kari_recipient_processing_failure_releases_the_incumbent_once_by_address() {
        let _g = crate::test_support::lock_global_state();
        assert!(crate::ssl::adv_alloc::install());
        crate::ssl::adv_alloc::assert_instrument_live();
        // SAFETY: the fixture is live; the probe observes only the installed seam.
        unsafe {
            let (cms, ec, ri, kari, rek) = agree_cms_fixture();
            assert!((*kari).pctx.is_null());
            let incumbent = OwnedBuf::new(16, SeamFile::NULL, 0)
                .unwrap_or_else(|| panic!("the fixture allocation must succeed"))
                .into_raw();
            (*ec).key = incumbent;
            (*ec).keylen = 16;
            crate::ssl::adv_alloc::reset();
            assert_eq!(
                CMS_RecipientInfo_kari_decrypt(cms, ri, rek),
                0,
                "a recipient with no agreement context is refused"
            );
            assert_eq!(frees(incumbent.cast()), 0, "the incumbent is kept");
            assert_eq!((*ec).key, incumbent, "the slot is untouched");
            crate::ssl::adv_alloc::assert_no_double_free();
            crate::ssl::adv_alloc::reset();
            m_asn1_free(rek.cast(), cms_recipientencryptedkey_it());
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
            crate::cms::cms_lib::CMS_ContentInfo_free(cms);
            assert_eq!(
                frees(incumbent.cast()),
                1,
                "the container releases the incumbent exactly once"
            );
            crate::ssl::adv_alloc::assert_no_double_free();
        }
    }

    /// A key that yields no agreement context is refused, and the refused call adopts nothing:
    /// the slot stays empty and the caller still owns the key. Clearing the slot with NULL
    /// succeeds and releases nothing.
    #[test]
    fn kari_set0_refuses_a_key_that_cannot_agree() {
        // SAFETY: the recipient is live and the blank key is this frame's.
        unsafe {
            let (ri, kari) = agree_recipient();
            let pk = EVP_PKEY_new();
            assert!(!pk.is_null());
            assert_eq!(
                CMS_RecipientInfo_kari_set0_pkey(ri, pk),
                0,
                "a blank key cannot produce an agreement context"
            );
            assert!((*kari).pctx.is_null(), "nothing was installed");
            EVP_PKEY_free(pk);
            assert_eq!(CMS_RecipientInfo_kari_set0_pkey(ri, ptr::null_mut()), 1);
            assert!((*kari).pctx.is_null());
            m_asn1_free(ri.cast(), cms_recipientinfo_it());
        }
    }
}
