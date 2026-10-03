//! `crypto/cms/cms_kemri.c` — the KEM recipient engine: encapsulate/decapsulate, the KDF
//! derivation and the `CMS_RecipientInfo_kemri_*` surface. Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::{V_ASN1_NULL, V_ASN1_UNDEF};
use crate::asn1::string::{
    ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set, ASN1_STRING_get0_data,
    ASN1_STRING_length, ASN1_STRING_set0,
};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_copy, X509_ALGOR_get0};
use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_reset, EVP_CipherInit_ex, EVP_CipherUpdate};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EvpKdf,
    EvpKdfCtx, OSSL_KDF_PARAM_KEY,
};
use crate::evp::kem::{
    EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate,
    EVP_PKEY_encapsulate_init,
};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, OSSL_KDF_PARAM_INFO};
use crate::params::{OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OsslParam};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, OPENSSL_cleanse};
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{NID_id_smime_ori_kem, OBJ_obj2txt};
use crate::x509::x509_set::X509_get_X509_PUBKEY;
use crate::x509::x_pubkey::X509_PUBKEY_get0_param;
use crate::x509::x_x509::X509;

use super::cms_asn1::*;
use super::cms_lib::{ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq};
use super::cms_sd::{ossl_cms_SignerIdentifier_cert_cmp, ossl_cms_set1_SignerIdentifier};

/// `EVP_MAX_KEY_LENGTH` — `include/openssl/evp.h:35`.
const EVP_MAX_KEY_LENGTH: usize = 64;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// `int ossl_cms_RecipientInfo_kemri_get0_alg(CMS_RecipientInfo *ri, uint32_t **pkekLength,`
/// `X509_ALGOR **pwrap)` — `cms_kemri.c:23-36`. Internal.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kemri_get0_alg(
    ri: *mut CmsRecipientInfo,
    pkek_length: *mut *mut u32,
    pwrap: *mut *mut X509Algor,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                28,
                c"ossl_cms_RecipientInfo_kemri_get0_alg",
                ERR_CMS_R_NOT_KEM,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let kemri = unsafe { (*ri).d.cast::<CmsOtherRecipientInfo>() };
    if !pkek_length.is_null() {
        // SAFETY: `kemri` is live.
        let inner = unsafe { (*kemri).d.cast::<CmsKemRecipientInfo>() };
        // SAFETY: `pkek_length` is writable; `inner` is live.
        unsafe { *pkek_length = &mut (*inner).kek_length };
    }
    if !pwrap.is_null() {
        // SAFETY: `kemri` is live.
        let inner = unsafe { (*kemri).d.cast::<CmsKemRecipientInfo>() };
        // SAFETY: `pwrap` is writable; `inner` is live.
        unsafe { *pwrap = (*inner).wrap };
    }
    1
}

/// `int CMS_RecipientInfo_kemri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert)` —
/// `cms_kemri.c:38-45`.
///
/// # Safety
/// `ri`/`cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kemri_cert_cmp(
    ri: *mut CmsRecipientInfo,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(40, c"CMS_RecipientInfo_kemri_cert_cmp", ERR_CMS_R_NOT_KEM)
        };
        return -2;
    }
    // SAFETY: `ri` is live.
    let inner = unsafe {
        (*(*ri).d.cast::<CmsOtherRecipientInfo>())
            .d
            .cast::<CmsKemRecipientInfo>()
    };
    // SAFETY: `inner`/`cert` are live.
    unsafe { ossl_cms_SignerIdentifier_cert_cmp((*inner).rid, cert) }
}

/// `int CMS_RecipientInfo_kemri_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pk)` —
/// `cms_kemri.c:47-75`.
///
/// # Safety
/// `ri` is live; `pk` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kemri_set0_pkey(
    ri: *mut CmsRecipientInfo,
    pk: *mut crate::evp::pkey::EvpPkey,
) -> c_int {
    let mut pctx: *mut crate::evp::pkey_ctx::EvpPkeyCtx = ptr::null_mut();

    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(54, c"CMS_RecipientInfo_kemri_set0_pkey", ERR_CMS_R_NOT_KEM)
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let kemri = unsafe {
        (*(*ri).d.cast::<CmsOtherRecipientInfo>())
            .d
            .cast::<CmsKemRecipientInfo>()
    };

    // SAFETY: `kemri` is live.
    unsafe { EVP_PKEY_CTX_free((*kemri).pctx.cast()) };
    // SAFETY: `kemri` is live.
    unsafe { (*kemri).pctx = ptr::null_mut() };

    if !pk.is_null() {
        // SAFETY: `kemri` is live; `pk` is live.
        pctx = unsafe {
            EVP_PKEY_CTX_new_from_pkey(
                ossl_cms_ctx_get0_libctx((*kemri).cms_ctx),
                pk,
                ossl_cms_ctx_get0_propq((*kemri).cms_ctx),
            )
        };
        // SAFETY: `pctx` is live; `NULL` params.
        if pctx.is_null() || unsafe { EVP_PKEY_decapsulate_init(pctx, ptr::null()) } <= 0 {
            // SAFETY: `pctx` is NULL or owned.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            return 0;
        }

        // SAFETY: `kemri` is live.
        unsafe { (*kemri).pctx = pctx.cast() };
    }

    1
}

/// `int ossl_cms_RecipientInfo_kemri_init(CMS_RecipientInfo *ri, X509 *recip,`
/// `EVP_PKEY *recipPubKey, unsigned int flags, const CMS_CTX *ctx)` — `cms_kemri.c:79-133`.
///
/// # Safety
/// `ri`/`recip`/`recipPubKey` are live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kemri_init(
    ri: *mut CmsRecipientInfo,
    recip: *mut X509,
    recip_pub_key: *mut crate::evp::pkey::EvpPkey,
    flags: c_uint,
    ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: the item answers a fresh other-recipient.
    let ori = unsafe { m_asn1_new(cms_otherrecipientinfo_it()) }.cast::<CmsOtherRecipientInfo>();
    // SAFETY: `ri` is live.
    unsafe { (*ri).d = ori.cast() };
    if ori.is_null() {
        return 0;
    }
    // SAFETY: `ri` is live.
    unsafe {
        (*ri).encoded_type = CMS_RECIPINFO_OTHER;
        (*ri).type_ = CMS_RECIPINFO_KEM;
    }

    // SAFETY: `ori` is live.
    unsafe { (*ori).ori_type = crate::runtime::obj::OBJ_nid2obj(NID_id_smime_ori_kem) };
    // SAFETY: `ori` is live.
    if unsafe { (*ori).ori_type }.is_null() {
        return 0;
    }
    // SAFETY: the item answers a fresh KEM recipient.
    let kemri = unsafe { m_asn1_new(cms_kemrecipientinfo_it()) }.cast::<CmsKemRecipientInfo>();
    // SAFETY: `ori` is live.
    unsafe { (*ori).d = kemri.cast() };
    if kemri.is_null() {
        return 0;
    }

    // SAFETY: `kemri` is live.
    unsafe {
        (*kemri).version = 0;
        (*kemri).cms_ctx = ctx;
    }

    // Not a typo: RecipientIdentifier and SignerIdentifier are the same structure.
    let idtype = if flags & CMS_USE_KEYID != 0 {
        CMS_RECIPINFO_KEYIDENTIFIER
    } else {
        CMS_RECIPINFO_ISSUER_SERIAL
    };
    // SAFETY: `kemri`/`recip` are live.
    if unsafe { ossl_cms_set1_SignerIdentifier((*kemri).rid, recip, idtype, ctx) } == 0 {
        return 0;
    }

    // SAFETY: `recip` is live.
    let x_pubkey = unsafe { X509_get_X509_PUBKEY(recip) };
    if x_pubkey.is_null() {
        return 0;
    }
    let mut x_alg: *mut X509Algor = ptr::null_mut();
    // SAFETY: `x_pubkey` is live; the slots are this frame's.
    if unsafe {
        X509_PUBKEY_get0_param(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut x_alg,
            x_pubkey,
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: `kemri`/`x_alg` are live.
    if unsafe { X509_ALGOR_copy((*kemri).kem, x_alg) } == 0 {
        return 0;
    }

    // SAFETY: `ctx` is live; `recip_pub_key` is live.
    unsafe {
        (*kemri).pctx = EVP_PKEY_CTX_new_from_pkey(
            ossl_cms_ctx_get0_libctx(ctx),
            recip_pub_key,
            ossl_cms_ctx_get0_propq(ctx),
        )
        .cast()
    };
    // SAFETY: `kemri` is live.
    if unsafe { (*kemri).pctx }.is_null() {
        return 0;
    }
    // SAFETY: `kemri` is live.
    if unsafe { EVP_PKEY_encapsulate_init((*kemri).pctx.cast(), ptr::null()) } <= 0 {
        return 0;
    }

    1
}

/// `EVP_CIPHER_CTX *CMS_RecipientInfo_kemri_get0_ctx(CMS_RecipientInfo *ri)` —
/// `cms_kemri.c:135-140`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kemri_get0_ctx(
    ri: *mut CmsRecipientInfo,
) -> *mut crate::evp::cipher_ctx::EvpCipherCtx {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } == CMS_RECIPINFO_KEM {
        // SAFETY: `ri` is live.
        let inner = unsafe {
            (*(*ri).d.cast::<CmsOtherRecipientInfo>())
                .d
                .cast::<CmsKemRecipientInfo>()
        };
        // SAFETY: `inner` is live.
        return unsafe { (*inner).ctx.cast::<crate::evp::cipher_ctx::EvpCipherCtx>() };
    }
    ptr::null_mut()
}

/// `X509_ALGOR *CMS_RecipientInfo_kemri_get0_kdf_alg(CMS_RecipientInfo *ri)` —
/// `cms_kemri.c:142-147`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kemri_get0_kdf_alg(
    ri: *mut CmsRecipientInfo,
) -> *mut X509Algor {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } == CMS_RECIPINFO_KEM {
        // SAFETY: `ri` is live.
        let inner = unsafe {
            (*(*ri).d.cast::<CmsOtherRecipientInfo>())
                .d
                .cast::<CmsKemRecipientInfo>()
        };
        // SAFETY: `inner` is live.
        return unsafe { (*inner).kdf };
    }
    ptr::null_mut()
}

/// `int CMS_RecipientInfo_kemri_set_ukm(CMS_RecipientInfo *ri, const unsigned char *ukm,`
/// `int ukmLength)` — `cms_kemri.c:149-178`.
///
/// # Safety
/// `ri` is live; `ukm` is readable for `ukmLength` or NULL when `ukmLength` is 0.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kemri_set_ukm(
    ri: *mut CmsRecipientInfo,
    ukm: *const c_uchar,
    ukm_length: c_int,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(157, c"CMS_RecipientInfo_kemri_set_ukm", ERR_CMS_R_NOT_KEM)
        };
        return 0;
    }

    if ukm.is_null() && ukm_length != 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                162,
                c"CMS_RecipientInfo_kemri_set_ukm",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let kemri = unsafe {
        (*(*ri).d.cast::<CmsOtherRecipientInfo>())
            .d
            .cast::<CmsKemRecipientInfo>()
    };

    // SAFETY: the allocator answers a fresh octet string.
    let ukm_str = ASN1_OCTET_STRING_new();
    if ukm_str.is_null() {
        return 0;
    }
    // SAFETY: `ukm_str` is live; `ukm` is readable for `ukm_length`.
    if unsafe { ASN1_OCTET_STRING_set(ukm_str, ukm, ukm_length) } == 0 {
        // SAFETY: `ukm_str` is owned here.
        unsafe { ASN1_OCTET_STRING_free(ukm_str) };
        return 0;
    }
    // SAFETY: `kemri` is live.
    unsafe { ASN1_OCTET_STRING_free((*kemri).ukm) };
    // SAFETY: `kemri` is live.
    unsafe { (*kemri).ukm = ukm_str };
    1
}

/// `EVP_KDF_CTX *create_kdf_ctx(CMS_KEMRecipientInfo *kemri)` — `cms_kemri.c:180-211`.
///
/// # Safety
/// `kemri` is live.
unsafe fn create_kdf_ctx(kemri: *mut CmsKemRecipientInfo) -> *mut EvpKdfCtx {
    let mut kdf_oid: *const Asn1Object = ptr::null();
    let mut ptype = 0;
    let mut kdf_alg = [0 as c_char; OSSL_MAX_NAME_SIZE];
    let mut kdf: *mut EvpKdf = ptr::null_mut();

    // SAFETY: `kemri` is live; the slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut kdf_oid, &mut ptype, ptr::null_mut(), (*kemri).kdf) };
    if ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                196,
                c"create_kdf_ctx",
                crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_KDF_ALGORITHM,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `kdf_alg` is writable; `kdf_oid` is live.
    if unsafe {
        OBJ_obj2txt(
            kdf_alg.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            kdf_oid,
            1,
        )
    } < 0
    {
        return ptr::null_mut();
    }

    // SAFETY: `kemri` is live; `kdf_alg` is a C string.
    kdf = unsafe {
        EVP_KDF_fetch(
            ossl_cms_ctx_get0_libctx((*kemri).cms_ctx),
            kdf_alg.as_ptr(),
            ossl_cms_ctx_get0_propq((*kemri).cms_ctx),
        )
    };
    if kdf.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `kdf` is live.
    let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: `kdf` is owned here.
    unsafe { EVP_KDF_free(kdf) };
    kctx
}

/// `int kdf_derive(unsigned char *kek, size_t keklen, const unsigned char *ss, size_t sslen,`
/// `CMS_KEMRecipientInfo *kemri)` — `cms_kemri.c:213-247`.
///
/// # Safety
/// `kek` is writable for `keklen`; `ss` is readable for `sslen`; `kemri` is live.
unsafe fn kdf_derive(
    kek: *mut c_uchar,
    keklen: usize,
    ss: *const c_uchar,
    sslen: usize,
    kemri: *mut CmsKemRecipientInfo,
) -> c_int {
    let mut kctx: *mut EvpKdfCtx = ptr::null_mut();
    let mut infoder: *mut c_uchar = ptr::null_mut();
    let mut infolen: c_int = 0;
    let mut rv = 0;

    // SAFETY: `infoder` is this frame's slot; `kemri` is live.
    infolen = unsafe {
        super::cms_asn1::CMS_CMSORIforKEMOtherInfo_encode(
            &mut infoder,
            (*kemri).wrap,
            (*kemri).ukm,
            (*kemri).kek_length as c_int,
        )
    };
    if infolen <= 0 {
        return rv;
    }

    // SAFETY: `kemri` is live.
    kctx = unsafe { create_kdf_ctx(kemri) };
    if kctx.is_null() {
        // SAFETY: `infoder` is owned here.
        unsafe { CRYPTO_free(infoder.cast(), c"cms_kemri.c".as_ptr(), 243) };
        return rv;
    }

    let mut params: [OsslParam; 3] = [
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
        OSSL_PARAM_construct_end(),
    ];
    // SAFETY: the constructor writes a descriptor into the caller's slot.
    params[0] =
        unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ss as *mut c_void, sslen) };
    // SAFETY: the constructor writes a descriptor into the caller's slot.
    params[1] = unsafe {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, infoder.cast(), infolen as usize)
    };

    // SAFETY: `kctx` is live; `kek` is writable for `keklen`.
    if unsafe { EVP_KDF_derive(kctx, kek, keklen, params.as_ptr()) } <= 0 {
        rv = 0;
    } else {
        rv = 1;
    }
    // SAFETY: `infoder`/`kctx` are owned here.
    unsafe {
        CRYPTO_free(infoder.cast(), c"cms_kemri.c".as_ptr(), 243);
        EVP_KDF_CTX_free(kctx);
    }

    rv
}

/// `int cms_kek_cipher(unsigned char **pout, size_t *poutlen, const unsigned char *ss,`
/// `size_t sslen, const unsigned char *in, size_t inlen, CMS_KEMRecipientInfo *kemri,`
/// `int enc)` — `cms_kemri.c:254-307`.
///
/// # Safety
/// The out-slots are writable; the inputs are readable; `kemri` is live.
#[allow(clippy::too_many_arguments)]
unsafe fn cms_kek_cipher(
    pout: *mut *mut c_uchar,
    poutlen: *mut usize,
    ss: *const c_uchar,
    sslen: usize,
    input: *const c_uchar,
    inlen: usize,
    kemri: *mut CmsKemRecipientInfo,
    enc: c_int,
) -> c_int {
    let mut kek = [0u8; EVP_MAX_KEY_LENGTH];
    // SAFETY: `kemri` is live.
    let keklen = unsafe { (*kemri).kek_length } as usize;
    let mut out: *mut c_uchar = ptr::null_mut();
    let mut outlen: c_int = 0;
    let mut rv = 0;
    let mut outsize = 0usize;

    if keklen > EVP_MAX_KEY_LENGTH {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                268,
                c"cms_kek_cipher",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        return 0;
    }

    if inlen > c_int::MAX as usize {
        return 0;
    }

    // SAFETY: `kek` is writable for `keklen`; `ss` readable for `sslen`; `kemri` is live.
    if unsafe { kdf_derive(kek.as_mut_ptr(), keklen, ss, sslen, kemri) } == 0 {
        return rv;
    }

    // Set KEK in context.
    // SAFETY: `kemri` is live.
    if unsafe {
        EVP_CipherInit_ex(
            (*kemri).ctx.cast(),
            ptr::null(),
            ptr::null_mut(),
            kek.as_ptr(),
            ptr::null(),
            enc,
        )
    } == 0
    {
        // SAFETY: `kek` is a live buffer; `kemri` is live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), kek.len());
            EVP_CIPHER_CTX_reset((*kemri).ctx.cast());
            EVP_PKEY_CTX_free((*kemri).pctx.cast());
            (*kemri).pctx = ptr::null_mut();
        }
        return rv;
    }
    // Obtain output length of ciphered key.
    // SAFETY: `kemri` is live.
    if unsafe {
        EVP_CipherUpdate(
            (*kemri).ctx.cast(),
            ptr::null_mut(),
            &mut outlen,
            input,
            inlen as c_int,
        )
    } == 0
    {
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), kek.len());
            EVP_CIPHER_CTX_reset((*kemri).ctx.cast());
            EVP_PKEY_CTX_free((*kemri).pctx.cast());
            (*kemri).pctx = ptr::null_mut();
        }
        return rv;
    }
    outsize = if (outlen as usize) < inlen {
        inlen
    } else {
        outlen as usize
    };
    // SAFETY: `outsize > 0`.
    out = CRYPTO_malloc(outsize, c"cms_kemri.c".as_ptr(), 290).cast::<c_uchar>();
    if out.is_null() {
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), kek.len());
            EVP_CIPHER_CTX_reset((*kemri).ctx.cast());
            EVP_PKEY_CTX_free((*kemri).pctx.cast());
            (*kemri).pctx = ptr::null_mut();
        }
        return rv;
    }
    // SAFETY: `kemri` is live; `out` is writable.
    if unsafe { EVP_CipherUpdate((*kemri).ctx.cast(), out, &mut outlen, input, inlen as c_int) }
        == 0
    {
        // SAFETY: `out` is owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(out, outsize) };
        // SAFETY: the context and key are live.
        unsafe {
            OPENSSL_cleanse(kek.as_mut_ptr().cast(), kek.len());
            EVP_CIPHER_CTX_reset((*kemri).ctx.cast());
            EVP_PKEY_CTX_free((*kemri).pctx.cast());
            (*kemri).pctx = ptr::null_mut();
        }
        return rv;
    }
    // SAFETY: the out-slots are writable.
    unsafe {
        *pout = out;
        *poutlen = outlen as usize;
    }
    out = ptr::null_mut();

    rv = 1;
    // SAFETY: each is NULL or owned; the contexts are live.
    unsafe {
        CRYPTO_free(out.cast(), c"cms_kemri.c".as_ptr(), 301);
        OPENSSL_cleanse(kek.as_mut_ptr().cast(), kek.len());
        EVP_CIPHER_CTX_reset((*kemri).ctx.cast());
        EVP_PKEY_CTX_free((*kemri).pctx.cast());
        (*kemri).pctx = ptr::null_mut();
    }
    rv
}

/// `int ossl_cms_RecipientInfo_kemri_encrypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_kemri.c:311-363`.
///
/// # Safety
/// `cms`/`ri` are live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kemri_encrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    let mut kem_ct: *mut c_uchar = ptr::null_mut();
    let mut kem_ct_len: usize = 0;
    let mut kem_secret: *mut c_uchar = ptr::null_mut();
    let mut kem_secret_len: usize = 0;
    let mut rv = 0;

    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                325,
                c"ossl_cms_RecipientInfo_kemri_encrypt",
                ERR_CMS_R_NOT_KEM,
            )
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let kemri = unsafe {
        (*(*ri).d.cast::<CmsOtherRecipientInfo>())
            .d
            .cast::<CmsKemRecipientInfo>()
    };

    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    // Initialise wrap algorithm parameters.
    // SAFETY: `ri`/`ec` are live.
    if unsafe { super::cms_env::ossl_cms_RecipientInfo_wrap_init(ri, (*ec).cipher.cast()) } == 0 {
        return 0;
    }

    // Initialise KDF algorithm.
    // SAFETY: `ri` is live.
    if unsafe { super::cms_env::ossl_cms_env_asn1_ctrl(ri, 0) } == 0 {
        return 0;
    }

    // SAFETY: `kemri` is live; the slots are this frame's.
    if unsafe {
        EVP_PKEY_encapsulate(
            (*kemri).pctx.cast(),
            ptr::null_mut(),
            &mut kem_ct_len,
            ptr::null_mut(),
            &mut kem_secret_len,
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: both lengths are positive.
    kem_ct = CRYPTO_malloc(kem_ct_len, c"cms_kemri.c".as_ptr(), 342).cast::<c_uchar>();
    kem_secret =
         // SAFETY: the length is non-zero.
         CRYPTO_malloc(kem_secret_len, c"cms_kemri.c".as_ptr(), 343).cast::<c_uchar>();
    if kem_ct.is_null() || kem_secret.is_null() {
        // SAFETY: each is NULL or owned.
        unsafe {
            CRYPTO_free(kem_ct.cast(), c"cms_kemri.c".as_ptr(), 360);
            super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len);
        }
        return rv;
    }

    // SAFETY: `kemri` is live; the buffers are sized by the previous call.
    if unsafe {
        EVP_PKEY_encapsulate(
            (*kemri).pctx.cast(),
            kem_ct,
            &mut kem_ct_len,
            kem_secret,
            &mut kem_secret_len,
        )
    } <= 0
    {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            CRYPTO_free(kem_ct.cast(), c"cms_kemri.c".as_ptr(), 360);
            super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len);
        }
        return rv;
    }

    // SAFETY: `kemri`/`kem_ct` are live; ownership transfers.
    unsafe { ASN1_STRING_set0((*kemri).kemct, kem_ct.cast(), kem_ct_len as c_int) };
    kem_ct = ptr::null_mut();

    let mut enckey: *mut c_uchar = ptr::null_mut();
    let mut enckeylen: usize = 0;
    // SAFETY: `kemri`/`ec` are live.
    if unsafe {
        cms_kek_cipher(
            &mut enckey,
            &mut enckeylen,
            kem_secret,
            kem_secret_len,
            (*ec).key,
            (*ec).keylen,
            kemri,
            1,
        )
    } == 0
    {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            CRYPTO_free(kem_ct.cast(), c"cms_kemri.c".as_ptr(), 360);
            super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len);
        }
        return rv;
    }
    // SAFETY: `kemri`/`enckey` are live; ownership transfers.
    unsafe { ASN1_STRING_set0((*kemri).encrypted_key, enckey.cast(), enckeylen as c_int) };

    rv = 1;
    // SAFETY: each is NULL or owned.
    unsafe {
        CRYPTO_free(kem_ct.cast(), c"cms_kemri.c".as_ptr(), 360);
        super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len);
    }
    rv
}

/// `int ossl_cms_RecipientInfo_kemri_decrypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_kemri.c:365-424`.
///
/// # Safety
/// `cms`/`ri` are live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_kemri_decrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    let mut kem_secret: *mut c_uchar = ptr::null_mut();
    let mut kem_secret_len: usize = 0;
    let mut ret = 0;

    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEM {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                381,
                c"ossl_cms_RecipientInfo_kemri_decrypt",
                ERR_CMS_R_NOT_KEM,
            )
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let kemri = unsafe {
        (*(*ri).d.cast::<CmsOtherRecipientInfo>())
            .d
            .cast::<CmsKemRecipientInfo>()
    };

    // SAFETY: `kemri` is live.
    if unsafe { (*kemri).pctx }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                390,
                c"ossl_cms_RecipientInfo_kemri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_NO_PRIVATE_KEY,
            )
        };
        return 0;
    }

    // Setup all parameters to derive KEK.
    // SAFETY: `ri` is live.
    if unsafe { super::cms_env::ossl_cms_env_asn1_ctrl(ri, 1) } == 0 {
        return ret;
    }

    // SAFETY: `kemri` is live.
    let kem_ct = unsafe { ASN1_STRING_get0_data((*kemri).kemct) };
    // SAFETY: `kemri` is live.
    let kem_ct_len = unsafe { ASN1_STRING_length((*kemri).kemct) } as usize;

    // SAFETY: `kemri` is live; the slot is this frame's.
    if unsafe {
        EVP_PKEY_decapsulate(
            (*kemri).pctx.cast(),
            ptr::null_mut(),
            &mut kem_secret_len,
            kem_ct,
            kem_ct_len,
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `kem_secret_len > 0`.
    kem_secret = CRYPTO_malloc(kem_secret_len, c"cms_kemri.c".as_ptr(), 404).cast::<c_uchar>();
    if kem_secret.is_null() {
        return ret;
    }

    // SAFETY: `kemri` is live; `kem_secret` is writable.
    if unsafe {
        EVP_PKEY_decapsulate(
            (*kemri).pctx.cast(),
            kem_secret,
            &mut kem_secret_len,
            kem_ct,
            kem_ct_len,
        )
    } <= 0
    {
        // SAFETY: `kem_secret` is owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len) };
        return ret;
    }

    // Attempt to decrypt CEK.
    // SAFETY: `kemri` is live.
    let enckeylen = unsafe { (*(*kemri).encrypted_key).length } as usize;
    // SAFETY: `kemri` is live.
    let enckey = unsafe { (*(*kemri).encrypted_key).data };
    let mut cek: *mut c_uchar = ptr::null_mut();
    let mut ceklen = 0usize;
    // SAFETY: `kemri` is live.
    if unsafe {
        cms_kek_cipher(
            &mut cek,
            &mut ceklen,
            kem_secret,
            kem_secret_len,
            enckey,
            enckeylen,
            kemri,
            0,
        )
    } == 0
    {
        // SAFETY: `kem_secret` is owned here.
        unsafe { super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len) };
        return ret;
    }
    // SAFETY: `cms` is live.
    let ec = unsafe { super::cms_env::ossl_cms_get0_env_enc_content(cms) };
    let _ = ec;
    // SAFETY: `ec` is live.
    unsafe { super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen) };
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).key = cek;
        (*ec).keylen = ceklen;
    }

    ret = 1;
    // SAFETY: `kem_secret` is owned here.
    unsafe { super::cms_asn1::OPENSSL_clear_free(kem_secret, kem_secret_len) };
    ret
}

/// `CMS_USE_KEYID` — `cms.h.in:100`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_R_NOT_KEM` — `include/openssl/cmserr.h`.
const ERR_CMS_R_NOT_KEM: c_int = crate::runtime::err::err_reasons::CMS_R_NOT_KEM;
