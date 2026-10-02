//! `crypto/cms/cms_env.c` — the `EnvelopedData`/`AuthEnvelopedData` recipient-info engine: the
//! KTRI/KEK/KARI/KEMRI/PWRI dispatch, the content-key wrap and the BIO init/final arms.
//! Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::layout::{Asn1String, Asn1Type, V_ASN1_UNDEF};
use crate::asn1::string::{
    ASN1_OCTET_STRING_cmp, ASN1_STRING_get0_data, ASN1_STRING_length, ASN1_STRING_set0,
};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_set0};
use crate::evp::asymcipher::{
    evp_pkey_decrypt_alloc, EVP_PKEY_decrypt_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_flags,
    EVP_CIPHER_get_mode, EvpCipher,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_tag_length,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_flags,
    EVP_DecryptFinal_ex, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex,
    EVP_EncryptInit_ex, EVP_EncryptUpdate, EvpCipherCtx,
};
use crate::evp::exchange::EVP_PKEY_derive_init;
use crate::evp::kem::EVP_PKEY_encapsulate_init;
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::evp::pkey::{
    evp_pkey_is_provided, EVP_PKEY_free, EVP_PKEY_get_int_param, EVP_PKEY_is_a, EVP_PKEY_up_ref,
    EvpPkey,
};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_pkey};
use crate::runtime::bio::{
    BIO_ctrl, BIO_find_type, BIO_free, Bio, BIO_C_GET_CIPHER_CTX, BIO_TYPE_CIPHER,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{
    NID_id_aes128_wrap, NID_id_aes192_wrap, NID_id_aes256_wrap, NID_pkcs7_data,
    NID_pkcs7_enveloped, NID_undef, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_x509::{ossl_x509_set0_libctx, X509};

use super::cms_asn1::*;
use super::cms_enc::{ossl_cms_EncryptedContent_init, ossl_cms_EncryptedContent_init_bio};
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, ossl_cms_get0_cmsctx, raise_cms,
    CMS_ContentInfo_free, CMS_ContentInfo_new_ex, ERR_R_ASN1_LIB, ERR_R_CMS_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_EVP_LIB, ERR_R_PASSED_NULL_PARAMETER,
};
use super::cms_sd::{
    ossl_cms_SignerIdentifier_cert_cmp, ossl_cms_SignerIdentifier_get0_signer_id,
    ossl_cms_set1_SignerIdentifier,
};

/// `CMS_ENVELOPED_STANDARD` — `cms_env.c:33`.
const CMS_ENVELOPED_STANDARD: c_int = 1;
/// `CMS_ENVELOPED_AUTH` — `cms_env.c:34`.
const CMS_ENVELOPED_AUTH: c_int = 2;
/// `CMS_USE_KEYID` — `cms.h.in:100`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_KEY_PARAM` — `cms.h.in:102`.
const CMS_KEY_PARAM: c_uint = 0x40000;
/// `CMS_DEBUG_DECRYPT` — `cms.h.in:101`.
const CMS_DEBUG_DECRYPT: c_uint = 0x20000;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:529`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `EVP_CIPH_FLAG_CIPHER_WITH_MAC` — `include/openssl/evp.h:364`.
const EVP_CIPH_FLAG_CIPHER_WITH_MAC: c_ulong = 0x200_0000;
/// `EVP_CTRL_PROCESS_UNPROTECTED` — `include/openssl/evp.h:447`.
const EVP_CTRL_PROCESS_UNPROTECTED: c_int = 0x28;
/// `EVP_CIPH_FLAG_GET_WRAP_CIPHER` — `include/openssl/evp.h:366`.
const EVP_CIPH_FLAG_GET_WRAP_CIPHER: c_ulong = 0x400_0000;
/// `EVP_CTRL_GET_WRAP_CIPHER` — `include/openssl/evp.h:449`.
const EVP_CTRL_GET_WRAP_CIPHER: c_int = 0x29;
/// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` — `crypto/evp/evp_local.h`.
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x1;
/// `EVP_CTRL_AEAD_GET_TAG` — `include/openssl/evp.h:443`.
const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
/// `INT_MAX` — `limits.h`.
const INT_MAX: c_int = c_int::MAX;
/// `OSSL_PKEY_PARAM_CMS_RI_TYPE` — `core_names.h:369`.
const OSSL_PKEY_PARAM_CMS_RI_TYPE: *const c_char = c"ri-type".as_ptr();

/// `BIO_get_cipher_ctx(BIO *, EVP_CIPHER_CTX **)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx)`.
///
/// # Safety
/// `b` is a live cipher BIO; `pctx` is writable.
unsafe fn bio_get_cipher_ctx(b: *mut Bio, pctx: *mut *mut EvpCipherCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx.cast()) as c_int }
}

/// `static int cms_get_enveloped_type_simple(const CMS_ContentInfo *cms)` — `cms_env.c:36-50`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get_enveloped_type_simple(cms: *const CmsContentInfo) -> c_int {
    // SAFETY: `cms` is live.
    let nid = unsafe { OBJ_obj2nid((*cms).content_type) };
    match nid {
        // SAFETY: NID comparison, not a binding pattern.
        _ if nid == crate::runtime::obj::NID_pkcs7_enveloped => CMS_ENVELOPED_STANDARD,
        _ if nid == crate::runtime::obj::NID_id_smime_ct_authEnvelopedData => CMS_ENVELOPED_AUTH,
        _ => 0,
    }
}

/// `static int cms_get_enveloped_type(const CMS_ContentInfo *cms)` — `cms_env.c:52-59`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get_enveloped_type(cms: *const CmsContentInfo) -> c_int {
    // SAFETY: `cms` is live.
    let ret = unsafe { cms_get_enveloped_type_simple(cms) };
    if ret == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                57,
                c"cms_get_enveloped_type",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
            )
        };
    }
    ret
}

/// `CMS_EnvelopedData *ossl_cms_get0_enveloped(CMS_ContentInfo *cms)` — `cms_env.c:61-68`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_get0_enveloped(
    cms: *mut CmsContentInfo,
) -> *mut CmsEnvelopedData {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid((*cms).content_type) } != crate::runtime::obj::NID_pkcs7_enveloped {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                64,
                c"ossl_cms_get0_enveloped",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    unsafe { (*cms).d.cast::<CmsEnvelopedData>() }
}

/// `CMS_AuthEnvelopedData *ossl_cms_get0_auth_enveloped(CMS_ContentInfo *cms)` — `cms_env.c:70-77`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_get0_auth_enveloped(
    cms: *mut CmsContentInfo,
) -> *mut CmsAuthEnvelopedData {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid((*cms).content_type) }
        != crate::runtime::obj::NID_id_smime_ct_authEnvelopedData
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                73,
                c"ossl_cms_get0_auth_enveloped",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_TYPE_NOT_ENVELOPED_DATA,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    unsafe { (*cms).d.cast::<CmsAuthEnvelopedData>() }
}

/// `static CMS_EnvelopedData *cms_enveloped_data_init(CMS_ContentInfo *cms)` — `cms_env.c:79-94`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_enveloped_data_init(cms: *mut CmsContentInfo) -> *mut CmsEnvelopedData {
    // SAFETY: `cms` is live.
    if unsafe { (*cms).d }.is_null() {
        // SAFETY: the item answers a fresh enveloped data.
        let env = unsafe { m_asn1_new(CMS_EnvelopedData_it()) }.cast::<CmsEnvelopedData>();
        // SAFETY: `cms` is live.
        unsafe { (*cms).d = env.cast() };
        if env.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(84, c"cms_enveloped_data_init", ERR_R_ASN1_LIB) };
            return ptr::null_mut();
        }
        // SAFETY: `env` is live.
        unsafe {
            (*env).version = 0;
            (*(*env).encrypted_content_info).content_type = OBJ_nid2obj(NID_pkcs7_data);
        }
        // SAFETY: `cms` is live.
        unsafe { crate::asn1::prim::ASN1_OBJECT_free((*cms).content_type) };
        // SAFETY: `cms` is live.
        unsafe { (*cms).content_type = OBJ_nid2obj(NID_pkcs7_enveloped) };
        return env;
    }
    // SAFETY: `cms` is live.
    unsafe { ossl_cms_get0_enveloped(cms) }
}

/// `static CMS_AuthEnvelopedData *cms_auth_enveloped_data_init(CMS_ContentInfo *cms)` —
/// `cms_env.c:96-113`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_auth_enveloped_data_init(cms: *mut CmsContentInfo) -> *mut CmsAuthEnvelopedData {
    // SAFETY: `cms` is live.
    if unsafe { (*cms).d }.is_null() {
        // SAFETY: the item answers a fresh auth-enveloped data.
        let aenv = unsafe { m_asn1_new(cms_authenvelopeddata_it()) }.cast::<CmsAuthEnvelopedData>();
        // SAFETY: `cms` is live.
        unsafe { (*cms).d = aenv.cast() };
        if aenv.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(102, c"cms_auth_enveloped_data_init", ERR_R_ASN1_LIB) };
            return ptr::null_mut();
        }
        // SAFETY: `aenv` is live.
        unsafe {
            (*aenv).version = 0;
            (*(*aenv).auth_encrypted_content_info).content_type = OBJ_nid2obj(NID_pkcs7_data);
        }
        // SAFETY: `cms` is live.
        unsafe { crate::asn1::prim::ASN1_OBJECT_free((*cms).content_type) };
        // SAFETY: `cms` is live.
        unsafe {
            (*cms).content_type =
                OBJ_nid2obj(crate::runtime::obj::NID_id_smime_ct_authEnvelopedData)
        };
        return aenv;
    }
    // SAFETY: `cms` is live.
    unsafe { ossl_cms_get0_auth_enveloped(cms) }
}

/// `int ossl_cms_env_asn1_ctrl(CMS_RecipientInfo *ri, int cmd)` — `cms_env.c:115-160`.
///
/// # Safety
/// `ri` is live.
pub(crate) unsafe extern "C" fn ossl_cms_env_asn1_ctrl(
    ri: *mut CmsRecipientInfo,
    cmd: c_int,
) -> c_int {
    // SAFETY: `ri` is live.
    let ri_type = unsafe { (*ri).type_ };
    let pkey: *mut EvpPkey;
    match ri_type {
        _ if ri_type == CMS_RECIPINFO_TRANS => {
            // SAFETY: `ri` is live.
            pkey = unsafe { (*(*ri).d.cast::<CmsKeyTransRecipientInfo>()).pkey };
        }
        _ if ri_type == CMS_RECIPINFO_AGREE => {
            // SAFETY: `ri` is live.
            let pctx = unsafe {
                (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>())
                    .pctx
                    .cast::<crate::evp::pkey_ctx::EvpPkeyCtx>()
            };
            if pctx.is_null() {
                return 0;
            }
            // SAFETY: `pctx` is live.
            pkey = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey(pctx) };
            if pkey.is_null() {
                return 0;
            }
        }
        _ if ri_type == CMS_RECIPINFO_KEM => {
            // SAFETY: `ri` is live.
            return unsafe { super::cms_kem::ossl_cms_kem_envelope(ri, cmd) };
        }
        _ => return 0,
    }

    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_is_a(pkey, c"DHX".as_ptr()) } != 0
        // SAFETY: `pkey` is live.
        || unsafe { EVP_PKEY_is_a(pkey, c"DH".as_ptr()) } != 0
    {
        // SAFETY: `ri` is live.
        return unsafe { super::cms_dh::ossl_cms_dh_envelope(ri, cmd) };
    // SAFETY: the context and key are live.
    } else if unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } != 0 {
        // SAFETY: `ri` is live.
        return unsafe { super::cms_ec::ossl_cms_ecdh_envelope(ri, cmd) };
    // SAFETY: the context and key are live.
    } else if unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } != 0 {
        // SAFETY: `ri` is live.
        return unsafe { super::cms_rsa::ossl_cms_rsa_envelope(ri, cmd) };
    }

    // Something else? We'll give engines etc a chance to handle this.
    // SAFETY: `pkey` is live.
    if unsafe { (*pkey).ameth.is_null() } {
        return 1;
    }
    1
}

/// `CMS_EncryptedContentInfo *ossl_cms_get0_env_enc_content(const CMS_ContentInfo *cms)` —
/// `cms_env.c:162-176`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_get0_env_enc_content(
    cms: *const CmsContentInfo,
) -> *mut CmsEncryptedContentInfo {
    // SAFETY: `cms` is live.
    match unsafe { cms_get_enveloped_type(cms) } {
        CMS_ENVELOPED_STANDARD => {
            // SAFETY: `cms` is live.
            let env = unsafe { (*cms).d.cast::<CmsEnvelopedData>() };
            if env.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `env` is live.
                unsafe { (*env).encrypted_content_info }
            }
        }
        CMS_ENVELOPED_AUTH => {
            // SAFETY: `cms` is live.
            let aenv = unsafe { (*cms).d.cast::<CmsAuthEnvelopedData>() };
            if aenv.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: `aenv` is live.
                unsafe { (*aenv).auth_encrypted_content_info }
            }
        }
        _ => ptr::null_mut(),
    }
}

/// `STACK_OF(CMS_RecipientInfo) *CMS_get0_RecipientInfos(CMS_ContentInfo *cms)` —
/// `cms_env.c:178-190`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_RecipientInfos(
    cms: *mut CmsContentInfo,
) -> *mut OpenSslStack {
    // SAFETY: `cms` is live.
    match unsafe { cms_get_enveloped_type(cms) } {
        CMS_ENVELOPED_STANDARD => {
            // SAFETY: `cms` is live.
            unsafe { (*(*cms).d.cast::<CmsEnvelopedData>()).recipient_infos }
        }
        CMS_ENVELOPED_AUTH => {
            // SAFETY: `cms` is live.
            unsafe { (*(*cms).d.cast::<CmsAuthEnvelopedData>()).recipient_infos }
        }
        _ => ptr::null_mut(),
    }
}

/// `void ossl_cms_RecipientInfos_set_cmsctx(CMS_ContentInfo *cms)` — `cms_env.c:192-226`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfos_set_cmsctx(cms: *mut CmsContentInfo) {
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    // SAFETY: `cms` is live.
    let rinfos = unsafe { CMS_get0_RecipientInfos(cms) };
    // SAFETY: `rinfos` is live.
    for i in 0..unsafe { OPENSSL_sk_num(rinfos) } {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(rinfos, i) }.cast::<CmsRecipientInfo>();
        if !ri.is_null() {
            // SAFETY: `ri` is live.
            let ri_type = unsafe { (*ri).type_ };
            if ri_type == CMS_RECIPINFO_AGREE {
                // SAFETY: `ri` is live.
                unsafe { (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>()).cms_ctx = ctx };
            } else if ri_type == CMS_RECIPINFO_TRANS {
                // SAFETY: `ri` is live.
                let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };
                // SAFETY: `ktri` is live.
                unsafe { (*ktri).cms_ctx = ctx };
                // SAFETY: `ktri`/`ctx` are live.
                unsafe {
                    ossl_x509_set0_libctx(
                        (*ktri).recip,
                        ossl_cms_ctx_get0_libctx(ctx),
                        ossl_cms_ctx_get0_propq(ctx),
                    )
                };
            } else if ri_type == CMS_RECIPINFO_KEK {
                // SAFETY: `ri` is live.
                unsafe { (*(*ri).d.cast::<CmsKekRecipientInfo>()).cms_ctx = ctx };
            } else if ri_type == CMS_RECIPINFO_PASS {
                // SAFETY: `ri` is live.
                unsafe { (*(*ri).d.cast::<CmsPasswordRecipientInfo>()).cms_ctx = ctx };
            } else if ri_type == CMS_RECIPINFO_KEM {
                // SAFETY: `ri` is live.
                let inner = unsafe {
                    (*(*ri).d.cast::<CmsOtherRecipientInfo>())
                        .d
                        .cast::<CmsKemRecipientInfo>()
                };
                // SAFETY: `inner` is live.
                unsafe { (*inner).cms_ctx = ctx };
            }
        }
    }
}

/// `int CMS_RecipientInfo_type(CMS_RecipientInfo *ri)` — `cms_env.c:228-231`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_type(ri: *mut CmsRecipientInfo) -> c_int {
    // SAFETY: `ri` is live.
    unsafe { (*ri).type_ }
}

/// `EVP_PKEY_CTX *CMS_RecipientInfo_get0_pkey_ctx(CMS_RecipientInfo *ri)` — `cms_env.c:233-242`.
///
/// # Safety
/// `ri` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_get0_pkey_ctx(
    ri: *mut CmsRecipientInfo,
) -> *mut crate::evp::pkey_ctx::EvpPkeyCtx {
    // SAFETY: `ri` is live.
    let ri_type = unsafe { (*ri).type_ };
    if ri_type == CMS_RECIPINFO_TRANS {
        // SAFETY: `ri` is live.
        return unsafe {
            (*(*ri).d.cast::<CmsKeyTransRecipientInfo>())
                .pctx
                .cast::<crate::evp::pkey_ctx::EvpPkeyCtx>()
        };
    } else if ri_type == CMS_RECIPINFO_AGREE {
        // SAFETY: `ri` is live.
        return unsafe {
            (*(*ri).d.cast::<CmsKeyAgreeRecipientInfo>())
                .pctx
                .cast::<crate::evp::pkey_ctx::EvpPkeyCtx>()
        };
    } else if ri_type == CMS_RECIPINFO_KEM {
        // SAFETY: `ri` is live.
        let inner = unsafe {
            (*(*ri).d.cast::<CmsOtherRecipientInfo>())
                .d
                .cast::<CmsKemRecipientInfo>()
        };
        // SAFETY: `inner` is live.
        return unsafe { (*inner).pctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>() };
    }
    ptr::null_mut()
}

/// `CMS_ContentInfo *CMS_EnvelopedData_create_ex(const EVP_CIPHER *cipher, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_env.c:244-266`.
///
/// # Safety
/// `cipher` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EnvelopedData_create_ex(
    cipher: *const EvpCipher,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the constructor answers a fresh container.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if cms.is_null() {
        // SAFETY: `cms` is NULL; free tolerates it.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(264, c"CMS_EnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    let env = unsafe { cms_enveloped_data_init(cms) };
    if env.is_null() {
        // SAFETY: `cms` is live and owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(264, c"CMS_EnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }

    // SAFETY: `env`/`cms` are live.
    if unsafe {
        ossl_cms_EncryptedContent_init(
            (*env).encrypted_content_info,
            cipher,
            ptr::null(),
            0,
            ossl_cms_get0_cmsctx(cms),
        )
    } == 0
    {
        // SAFETY: `cms` is live and owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(264, c"CMS_EnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    cms
}

/// `CMS_ContentInfo *CMS_EnvelopedData_create(const EVP_CIPHER *cipher)` — `cms_env.c:268-271`.
///
/// # Safety
/// `cipher` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EnvelopedData_create(
    cipher: *const EvpCipher,
) -> *mut CmsContentInfo {
    // SAFETY: `cipher` is NULL or live.
    unsafe { CMS_EnvelopedData_create_ex(cipher, ptr::null_mut(), ptr::null()) }
}

/// `BIO *CMS_EnvelopedData_decrypt(CMS_EnvelopedData *env, BIO *detached_data, EVP_PKEY *pkey,`
/// `X509 *cert, ASN1_OCTET_STRING *secret, unsigned int flags, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_env.c:273-311`.
///
/// # Safety
/// `env` is live; the rest are NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EnvelopedData_decrypt(
    env: *mut CmsEnvelopedData,
    detached_data: *mut Bio,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    secret: *mut Asn1String,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Bio {
    let mut bio: *mut Bio = ptr::null_mut();
    let mut res = 0;

    if env.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                283,
                c"CMS_EnvelopedData_decrypt",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return ptr::null_mut();
    }

    // SAFETY: the constructor answers a fresh container.
    let ci = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if ci.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the allocator answers a fresh memory BIO.
    bio = unsafe { crate::runtime::bio::BIO_new(crate::runtime::bio::bss_mem::BIO_s_mem()) };
    if bio.is_null() {
        // SAFETY: `ci` is live and owned here.
        unsafe { CMS_ContentInfo_free(ci) };
        return ptr::null_mut();
    }
    // SAFETY: `ci` is live.
    unsafe {
        (*ci).content_type = OBJ_nid2obj(NID_pkcs7_enveloped);
        (*ci).d = env.cast();
    }
    if !secret.is_null() {
        // SAFETY: `secret` is live.
        let data = unsafe { ASN1_STRING_get0_data(secret) };
        // SAFETY: `secret` is live.
        let slen = unsafe { ASN1_STRING_length(secret) };
        // SAFETY: `ci` is live; `data` is readable for `slen`.
        if unsafe {
            super::cms_smime::CMS_decrypt_set1_password(ci, data.cast_mut(), slen as isize)
        } != 1
        {
            // SAFETY: `ci` is live and owned here.
            unsafe {
                (*ci).d = ptr::null_mut();
                (*ci).content_type = ptr::null_mut();
                CMS_ContentInfo_free(ci);
                BIO_free(bio);
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `ci` is live.
    res = unsafe {
        super::cms_smime::CMS_decrypt(
            ci,
            if secret.is_null() {
                pkey
            } else {
                ptr::null_mut()
            },
            if secret.is_null() {
                cert
            } else {
                ptr::null_mut()
            },
            detached_data,
            bio,
            flags,
        )
    };
    // SAFETY: `ci` is live and owned here.
    unsafe {
        (*ci).d = ptr::null_mut(); /* do not indirectly free |env| */
        (*ci).content_type = ptr::null_mut();
        CMS_ContentInfo_free(ci);
    }
    if res == 0 {
        // SAFETY: `bio` is live and owned here.
        unsafe { BIO_free(bio) };
        return ptr::null_mut();
    }
    bio
}

/// `CMS_ContentInfo *CMS_AuthEnvelopedData_create_ex(const EVP_CIPHER *cipher,`
/// `OSSL_LIB_CTX *libctx, const char *propq)` — `cms_env.c:313-335`.
///
/// # Safety
/// `cipher` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_AuthEnvelopedData_create_ex(
    cipher: *const EvpCipher,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the constructor answers a fresh container.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if cms.is_null() {
        // SAFETY: `cms` is NULL; free tolerates it.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(333, c"CMS_AuthEnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    let aenv = unsafe { cms_auth_enveloped_data_init(cms) };
    if aenv.is_null() {
        // SAFETY: `cms` is live and owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(333, c"CMS_AuthEnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `aenv`/`cms` are live.
    if unsafe {
        ossl_cms_EncryptedContent_init(
            (*aenv).auth_encrypted_content_info,
            cipher,
            ptr::null(),
            0,
            ossl_cms_get0_cmsctx(cms),
        )
    } == 0
    {
        // SAFETY: `cms` is live and owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(333, c"CMS_AuthEnvelopedData_create_ex", ERR_R_CMS_LIB) };
        return ptr::null_mut();
    }
    cms
}

/// `CMS_ContentInfo *CMS_AuthEnvelopedData_create(const EVP_CIPHER *cipher)` — `cms_env.c:337-340`.
///
/// # Safety
/// `cipher` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_AuthEnvelopedData_create(
    cipher: *const EvpCipher,
) -> *mut CmsContentInfo {
    // SAFETY: `cipher` is NULL or live.
    unsafe { CMS_AuthEnvelopedData_create_ex(cipher, ptr::null_mut(), ptr::null()) }
}

/// `static int cms_RecipientInfo_ktri_init(CMS_RecipientInfo *ri, X509 *recip, EVP_PKEY *pk,`
/// `unsigned int flags, const CMS_CTX *ctx)` — `cms_env.c:346-398`.
///
/// # Safety
/// `ri`/`recip`/`pk` are live.
unsafe fn cms_RecipientInfo_ktri_init(
    ri: *mut CmsRecipientInfo,
    recip: *mut X509,
    pk: *mut EvpPkey,
    flags: c_uint,
    ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: the item answers a fresh key-transport recipient.
    let ktri =
        unsafe { m_asn1_new(cms_keytransrecipientinfo_it()) }.cast::<CmsKeyTransRecipientInfo>();
    // SAFETY: `ri` is live.
    unsafe { (*ri).d = ktri.cast() };
    if ktri.is_null() {
        return 0;
    }
    // SAFETY: `ri` is live.
    unsafe {
        (*ri).encoded_type = CMS_RECIPINFO_TRANS;
        (*ri).type_ = CMS_RECIPINFO_TRANS;
    }

    // SAFETY: `ktri` is live.
    unsafe { (*ktri).cms_ctx = ctx };

    let idtype = if flags & CMS_USE_KEYID != 0 {
        // SAFETY: `ktri` is live.
        unsafe { (*ktri).version = 2 };
        CMS_RECIPINFO_KEYIDENTIFIER
    } else {
        // SAFETY: `ktri` is live.
        unsafe { (*ktri).version = 0 };
        CMS_RECIPINFO_ISSUER_SERIAL
    };

    // Not a typo: RecipientIdentifier and SignerIdentifier are the same structure.
    // SAFETY: `ktri`/`recip` are live.
    if unsafe { ossl_cms_set1_SignerIdentifier((*ktri).rid, recip, idtype, ctx) } == 0 {
        return 0;
    }

    // SAFETY: `recip` is live.
    if unsafe { X509_up_ref(recip) } == 0 {
        return 0;
    }
    // SAFETY: `pk` is live.
    if unsafe { EVP_PKEY_up_ref(pk) } == 0 {
        // SAFETY: `recip` is live.
        unsafe { crate::x509::x_x509::X509_free(recip) };
        return 0;
    }

    // SAFETY: `ktri` is live.
    unsafe {
        (*ktri).pkey = pk;
        (*ktri).recip = recip;
    }

    if flags & CMS_KEY_PARAM != 0 {
        // SAFETY: `ctx`/`ktri` are live.
        unsafe {
            (*ktri).pctx = EVP_PKEY_CTX_new_from_pkey(
                ossl_cms_ctx_get0_libctx(ctx),
                (*ktri).pkey,
                ossl_cms_ctx_get0_propq(ctx),
            )
            .cast()
        };
        // SAFETY: `ktri` is live.
        if unsafe { (*ktri).pctx }.is_null() {
            return 0;
        }
        // SAFETY: `ktri` is live.
        if unsafe { EVP_PKEY_encrypt_init((*ktri).pctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>()) }
            <= 0
        {
            return 0;
        }
    // SAFETY: the arguments meet the callee's contract.
    } else if unsafe { ossl_cms_env_asn1_ctrl(ri, 0) } == 0 {
        return 0;
    }
    1
}

/// `CMS_RecipientInfo *CMS_add1_recipient(CMS_ContentInfo *cms, X509 *recip,`
/// `EVP_PKEY *originatorPrivKey, X509 *originator, unsigned int flags)` — `cms_env.c:404-463`.
///
/// # Safety
/// `cms`/`recip` are live; `originatorPrivKey`/`originator` are NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_recipient(
    cms: *mut CmsContentInfo,
    recip: *mut X509,
    originator_priv_key: *mut EvpPkey,
    originator: *mut X509,
    flags: c_uint,
) -> *mut CmsRecipientInfo {
    let mut ri: *mut CmsRecipientInfo = ptr::null_mut();
    let mut pk: *mut EvpPkey = ptr::null_mut();
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };

    // SAFETY: `cms` is live.
    let ris = unsafe { CMS_get0_RecipientInfos(cms) };
    if ris.is_null() {
        return ptr::null_mut();
    }

    // Initialize recipient info.
    // SAFETY: the item answers a fresh recipient.
    ri = unsafe { m_asn1_new(cms_recipientinfo_it()) }.cast::<CmsRecipientInfo>();
    if ri.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(420, c"CMS_add1_recipient", ERR_R_ASN1_LIB) };
        return ptr::null_mut();
    }

    // SAFETY: `recip` is live.
    pk = unsafe { X509_get0_pubkey(recip) };
    if pk.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                426,
                c"CMS_add1_recipient",
                crate::runtime::err::err_reasons::CMS_R_ERROR_GETTING_PUBLIC_KEY,
            )
        };
        // SAFETY: `ri` is NULL or owned.
        unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
        return ptr::null_mut();
    }

    // SAFETY: `pk` is live.
    let ri_kind = unsafe { ossl_cms_pkey_get_ri_type(pk) };
    let ok = if ri_kind == CMS_RECIPINFO_TRANS {
        // SAFETY: `ri`/`recip`/`pk` are live.
        (unsafe { cms_RecipientInfo_ktri_init(ri, recip, pk, flags, ctx) }) != 0
    } else if ri_kind == CMS_RECIPINFO_AGREE {
        // SAFETY: `ri`/`recip`/`pk` are live.
        (unsafe {
            super::cms_kari::ossl_cms_RecipientInfo_kari_init(
                ri,
                recip,
                pk,
                originator,
                originator_priv_key,
                flags,
                ctx,
            )
        }) != 0
    } else if ri_kind == CMS_RECIPINFO_KEM {
        // SAFETY: `ri`/`recip`/`pk` are live.
        (unsafe { super::cms_kemri::ossl_cms_RecipientInfo_kemri_init(ri, recip, pk, flags, ctx) })
            != 0
    } else {
        false
    };
    if !ok {
        // SAFETY: `ri` is NULL or owned.
        unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                449,
                c"CMS_add1_recipient",
                crate::runtime::err::err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
            )
        };
        return ptr::null_mut();
    }

    // SAFETY: `ris`/`ri` are live.
    if unsafe { OPENSSL_sk_push(ris, ri.cast()) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(454, c"CMS_add1_recipient", ERR_R_CRYPTO_LIB) };
        // SAFETY: `ri` is owned here.
        unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
        return ptr::null_mut();
    }

    ri
}

/// `CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms, X509 *recip,`
/// `unsigned int flags)` — `cms_env.c:465-469`.
///
/// # Safety
/// `cms`/`recip` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_recipient_cert(
    cms: *mut CmsContentInfo,
    recip: *mut X509,
    flags: c_uint,
) -> *mut CmsRecipientInfo {
    // SAFETY: `cms`/`recip` are live.
    unsafe { CMS_add1_recipient(cms, recip, ptr::null_mut(), ptr::null_mut(), flags) }
}

/// `int CMS_RecipientInfo_ktri_get0_algs(CMS_RecipientInfo *ri, EVP_PKEY **pk, X509 **recip,`
/// `X509_ALGOR **palg)` — `cms_env.c:471-490`.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_ktri_get0_algs(
    ri: *mut CmsRecipientInfo,
    pk: *mut *mut EvpPkey,
    recip: *mut *mut X509,
    palg: *mut *mut X509Algor,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_TRANS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                477,
                c"CMS_RecipientInfo_ktri_get0_algs",
                ERR_CMS_R_NOT_KEY_TRANSPORT,
            )
        };
        return 0;
    }

    // SAFETY: `ri` is live.
    let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };

    if !pk.is_null() {
        // SAFETY: `pk` is writable; `ktri` is live.
        unsafe { *pk = (*ktri).pkey };
    }
    if !recip.is_null() {
        // SAFETY: `recip` is writable; `ktri` is live.
        unsafe { *recip = (*ktri).recip };
    }
    if !palg.is_null() {
        // SAFETY: `palg` is writable; `ktri` is live.
        unsafe { *palg = (*ktri).key_encryption_algorithm };
    }
    1
}

/// `int CMS_RecipientInfo_ktri_get0_signer_id(CMS_RecipientInfo *ri,`
/// `ASN1_OCTET_STRING **keyid, X509_NAME **issuer, ASN1_INTEGER **sno)` —
/// `cms_env.c:492-506`.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_ktri_get0_signer_id(
    ri: *mut CmsRecipientInfo,
    keyid: *mut *mut Asn1String,
    issuer: *mut *mut crate::x509::x_name::X509Name,
    sno: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_TRANS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                499,
                c"CMS_RecipientInfo_ktri_get0_signer_id",
                ERR_CMS_R_NOT_KEY_TRANSPORT,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };

    // SAFETY: `ktri` is live.
    unsafe { ossl_cms_SignerIdentifier_get0_signer_id((*ktri).rid, keyid, issuer, sno) }
}

/// `int CMS_RecipientInfo_ktri_cert_cmp(CMS_RecipientInfo *ri, X509 *cert)` —
/// `cms_env.c:508-515`.
///
/// # Safety
/// `ri`/`cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_ktri_cert_cmp(
    ri: *mut CmsRecipientInfo,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_TRANS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                511,
                c"CMS_RecipientInfo_ktri_cert_cmp",
                ERR_CMS_R_NOT_KEY_TRANSPORT,
            )
        };
        return -2;
    }
    // SAFETY: `ri`/`cert` are live.
    unsafe {
        ossl_cms_SignerIdentifier_cert_cmp((*(*ri).d.cast::<CmsKeyTransRecipientInfo>()).rid, cert)
    }
}

/// `int CMS_RecipientInfo_set0_pkey(CMS_RecipientInfo *ri, EVP_PKEY *pkey)` —
/// `cms_env.c:517-526`.
///
/// # Safety
/// `ri` is live; `pkey` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_set0_pkey(
    ri: *mut CmsRecipientInfo,
    pkey: *mut EvpPkey,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_TRANS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                520,
                c"CMS_RecipientInfo_set0_pkey",
                ERR_CMS_R_NOT_KEY_TRANSPORT,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };
    // SAFETY: `ktri` is live.
    unsafe { EVP_PKEY_free((*ktri).pkey) };
    // SAFETY: `ktri` is live.
    unsafe { (*ktri).pkey = pkey };
    1
}

/// `static int cms_RecipientInfo_ktri_encrypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_env.c:530-585`.
///
/// # Safety
/// `cms`/`ri` are live.
unsafe fn cms_RecipientInfo_ktri_encrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    let mut pctx;
    let mut ek: *mut c_uchar = ptr::null_mut();
    let mut eklen: usize = 0;
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    let mut ret = 0;

    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_TRANS {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                543,
                c"cms_RecipientInfo_ktri_encrypt",
                ERR_CMS_R_NOT_KEY_TRANSPORT,
            )
        };
        return 0;
    }
    // SAFETY: `ri` is live.
    let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };
    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };

    // SAFETY: `ktri` is live.
    pctx = unsafe { (*ktri).pctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>() };

    if !pctx.is_null() {
        // SAFETY: `ri` is live.
        if unsafe { ossl_cms_env_asn1_ctrl(ri, 0) } == 0 {
            // SAFETY: `pctx` is live.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            // SAFETY: `ktri` is live.
            unsafe { (*ktri).pctx = ptr::null_mut() };
            // SAFETY: each is NULL or owned.
            unsafe { CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583) };
            return ret;
        }
    } else {
        // SAFETY: `ctx`/`ktri` are live.
        pctx = unsafe {
            EVP_PKEY_CTX_new_from_pkey(
                ossl_cms_ctx_get0_libctx(ctx),
                (*ktri).pkey,
                ossl_cms_ctx_get0_propq(ctx),
            )
        };
        if pctx.is_null() {
            return 0;
        }
        // SAFETY: `pctx` is live.
        if unsafe { EVP_PKEY_encrypt_init(pctx) } <= 0 {
            // SAFETY: `pctx` is live.
            unsafe { EVP_PKEY_CTX_free(pctx) };
            // SAFETY: each is NULL or owned.
            unsafe { CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583) };
            return ret;
        }
    }

    // SAFETY: `pctx`/`ec` are live.
    if unsafe { EVP_PKEY_encrypt(pctx, ptr::null_mut(), &mut eklen, (*ec).key, (*ec).keylen) } <= 0
    {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            EVP_PKEY_CTX_free(pctx);
            CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583);
        }
        return ret;
    }

    // SAFETY: `eklen > 0`.
    ek = CRYPTO_malloc(eklen, c"cms_env.c".as_ptr(), 568).cast::<c_uchar>();
    if ek.is_null() {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            EVP_PKEY_CTX_free(pctx);
            CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583);
        }
        return ret;
    }

    // SAFETY: `pctx`/`ec` are live; `ek` is writable.
    if unsafe { EVP_PKEY_encrypt(pctx, ek, &mut eklen, (*ec).key, (*ec).keylen) } <= 0 {
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            EVP_PKEY_CTX_free(pctx);
            CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583);
        }
        return ret;
    }

    // SAFETY: `ktri`/`ek` are live; ownership transfers.
    unsafe { ASN1_STRING_set0((*ktri).encrypted_key, ek.cast(), eklen as c_int) };
    ek = ptr::null_mut();

    ret = 1;

    // SAFETY: `pctx` is live; each pointer is NULL or owned.
    unsafe {
        EVP_PKEY_CTX_free(pctx);
        (*ktri).pctx = ptr::null_mut();
        CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 583);
    }
    ret
}

/// `static int cms_RecipientInfo_ktri_decrypt(CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_env.c:589-666`.
///
/// # Safety
/// `cms`/`ri` are live.
unsafe fn cms_RecipientInfo_ktri_decrypt(
    cms: *mut CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    // SAFETY: `ri` is live.
    let ktri = unsafe { (*ri).d.cast::<CmsKeyTransRecipientInfo>() };
    // SAFETY: `ktri` is live.
    let pkey = unsafe { (*ktri).pkey };
    let mut ek: *mut c_uchar = ptr::null_mut();
    let mut eklen: usize = 0;
    let mut ret = 0;
    let mut fixlen: usize = 0;
    let mut cipher: *const EvpCipher = ptr::null();
    let mut fetched_cipher: *mut EvpCipher = ptr::null_mut();
    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    // SAFETY: `ctx` is live.
    let libctx = unsafe { ossl_cms_ctx_get0_libctx(ctx) };
    // SAFETY: `ctx` is live.
    let propq = unsafe { ossl_cms_ctx_get0_propq(ctx) };

    // SAFETY: `ktri` is live.
    if unsafe { (*ktri).pkey }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                608,
                c"cms_RecipientInfo_ktri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_NO_PRIVATE_KEY,
            )
        };
        return 0;
    }

    // SAFETY: `cms` is live.
    let env = unsafe { (*cms).d.cast::<CmsEnvelopedData>() };
    // SAFETY: `env` is live.
    let eci = unsafe { (*env).encrypted_content_info };
    // SAFETY: `eci` is live.
    if unsafe { (*eci).havenocert } != 0
        // SAFETY: `eci` is live.
        && unsafe { (*eci).debug } == 0
    {
        // SAFETY: `ec` is live.
        let calg = unsafe { (*ec).content_encryption_algorithm };
        let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];

        // SAFETY: `name` is writable; `calg` is live.
        unsafe {
            OBJ_obj2txt(
                name.as_mut_ptr(),
                OSSL_MAX_NAME_SIZE as c_int,
                (*calg).algorithm,
                0,
            )
        };

        // SAFETY: the queue is this thread's.
        crate::runtime::err::ERR_set_mark();
        // SAFETY: `name` is a C string.
        fetched_cipher = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };

        if !fetched_cipher.is_null() {
            cipher = fetched_cipher;
        } else {
            // SAFETY: `calg` is live; the lookup is the macro expansion.
            cipher = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid((*calg).algorithm))) };
        }
        if cipher.is_null() {
            // SAFETY: the queue is this thread's.
            crate::runtime::err::ERR_clear_last_mark();
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    628,
                    c"cms_RecipientInfo_ktri_decrypt",
                    crate::runtime::err::err_reasons::CMS_R_UNKNOWN_CIPHER,
                )
            };
            return 0;
        }
        // SAFETY: the queue is this thread's.
        crate::runtime::err::ERR_pop_to_mark();

        // SAFETY: `cipher` is live.
        fixlen = unsafe { crate::evp::cipher::EVP_CIPHER_get_key_length(cipher) } as usize;
        // SAFETY: `fetched_cipher` is NULL or owned.
        unsafe { EVP_CIPHER_free(fetched_cipher) };
    }

    // SAFETY: `libctx`/`pkey` are live.
    unsafe {
        (*ktri).pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq).cast();
    }
    // SAFETY: `ktri` is live.
    if unsafe { (*ktri).pctx }.is_null() {
        return ret;
    }

    // SAFETY: `ktri` is live.
    if unsafe { EVP_PKEY_decrypt_init((*ktri).pctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>()) }
        <= 0
    {
        // SAFETY: `ktri` is live.
        unsafe { EVP_PKEY_CTX_free((*ktri).pctx.cast()) };
        // SAFETY: `ktri` is live.
        unsafe { (*ktri).pctx = ptr::null_mut() };
        return ret;
    }

    // SAFETY: `ri` is live.
    if unsafe { ossl_cms_env_asn1_ctrl(ri, 1) } == 0 {
        // SAFETY: `ktri` is live.
        unsafe { EVP_PKEY_CTX_free((*ktri).pctx.cast()) };
        // SAFETY: `ktri` is live.
        unsafe { (*ktri).pctx = ptr::null_mut() };
        return ret;
    }

    // SAFETY: `ktri` is live; the encrypted key is readable.
    let (ekdata, eklen_in) = unsafe {
        (
            (*(*ktri).encrypted_key).data,
            (*(*ktri).encrypted_key).length as usize,
        )
    };
    // SAFETY: `ktri` is live; `ek` is this frame's slot.
    if unsafe {
        evp_pkey_decrypt_alloc(
            (*ktri).pctx.cast::<crate::evp::pkey_ctx::EvpPkeyCtx>(),
            &mut ek,
            &mut eklen,
            fixlen,
            ekdata,
            eklen_in,
        )
    } <= 0
    {
        // SAFETY: `ktri` is live; `ek` is NULL or owned.
        unsafe {
            EVP_PKEY_CTX_free((*ktri).pctx.cast());
            (*ktri).pctx = ptr::null_mut();
            CRYPTO_free(ek.cast(), c"cms_env.c".as_ptr(), 663);
        }
        return ret;
    }

    ret = 1;

    // SAFETY: `ec`/`ktri` are live.
    unsafe {
        super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
        (*ec).key = ek;
        (*ec).keylen = eklen;
    }

    // SAFETY: `ktri` is live.
    unsafe {
        EVP_PKEY_CTX_free((*ktri).pctx.cast());
        (*ktri).pctx = ptr::null_mut();
    }
    ret
}

/// `int CMS_RecipientInfo_kekri_id_cmp(CMS_RecipientInfo *ri, const unsigned char *id,`
/// `size_t idlen)` — `cms_env.c:670-685`.
///
/// # Safety
/// `ri` is live; `id` is readable for `idlen`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kekri_id_cmp(
    ri: *mut CmsRecipientInfo,
    id: *const c_uchar,
    idlen: usize,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEK {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(676, c"CMS_RecipientInfo_kekri_id_cmp", ERR_CMS_R_NOT_KEK) };
        return -2;
    }
    // SAFETY: `ri` is live.
    let kekri = unsafe { (*ri).d.cast::<CmsKekRecipientInfo>() };
    let tmp_os = Asn1String {
        length: idlen as c_int,
        type_: crate::asn1::layout::V_ASN1_OCTET_STRING,
        data: id.cast_mut(),
        flags: 0,
    };
    // SAFETY: `kekri` is live; `tmp_os` is live.
    unsafe { ASN1_OCTET_STRING_cmp(&tmp_os, (*(*kekri).kekid).key_identifier) }
}

/// `static size_t aes_wrap_keylen(int nid)` — `cms_env.c:689-704`.
fn aes_wrap_keylen(nid: c_int) -> usize {
    match nid {
        #[allow(non_upper_case_globals)]
        _ if nid == NID_id_aes128_wrap => 16,
        #[allow(non_upper_case_globals)]
        _ if nid == NID_id_aes192_wrap => 24,
        #[allow(non_upper_case_globals)]
        _ if nid == NID_id_aes256_wrap => 32,
        _ => 0,
    }
}

/// `CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,`
/// `unsigned char *key, size_t keylen, unsigned char *id, size_t idlen,`
/// `ASN1_GENERALIZEDTIME *date, ASN1_OBJECT *otherTypeId, ASN1_TYPE *otherType)` —
/// `cms_env.c:706-807`.
///
/// # Safety
/// `cms` is live; the buffers are the caller's and adopted.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add0_recipient_key(
    cms: *mut CmsContentInfo,
    mut nid: c_int,
    key: *mut c_uchar,
    keylen: usize,
    id: *mut c_uchar,
    idlen: usize,
    date: *mut Asn1String,
    other_type_id: *mut Asn1Object,
    other_type: *mut Asn1Type,
) -> *mut CmsRecipientInfo {
    let mut ri: *mut CmsRecipientInfo = ptr::null_mut();
    // SAFETY: `cms` is live.
    let ris = unsafe { CMS_get0_RecipientInfos(cms) };

    if ris.is_null() || idlen > INT_MAX as usize {
        return ptr::null_mut();
    }

    if nid == NID_undef {
        nid = match keylen {
            16 => NID_id_aes128_wrap,
            24 => NID_id_aes192_wrap,
            32 => NID_id_aes256_wrap,
            _ => {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        735,
                        c"CMS_add0_recipient_key",
                        crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
                    )
                };
                return ptr::null_mut();
            }
        };
    } else {
        let exp_keylen = aes_wrap_keylen(nid);

        if exp_keylen == 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    744,
                    c"CMS_add0_recipient_key",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_KEK_ALGORITHM,
                )
            };
            return ptr::null_mut();
        }

        if keylen != exp_keylen {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    749,
                    c"CMS_add0_recipient_key",
                    crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
                )
            };
            return ptr::null_mut();
        }
    }

    // Initialize recipient info.
    // SAFETY: the item answers a fresh recipient.
    ri = unsafe { m_asn1_new(cms_recipientinfo_it()) }.cast::<CmsRecipientInfo>();
    if ri.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(757, c"CMS_add0_recipient_key", ERR_R_ASN1_LIB) };
        return ptr::null_mut();
    }

    // SAFETY: the item answers a fresh KEK recipient.
    let kekri = unsafe { m_asn1_new(cms_kekrecipientinfo_it()) }.cast::<CmsKekRecipientInfo>();
    // SAFETY: `ri` is live.
    unsafe { (*ri).d = kekri.cast() };
    if kekri.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(763, c"CMS_add0_recipient_key", ERR_R_ASN1_LIB) };
        // SAFETY: `ri` is owned here.
        unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
        return ptr::null_mut();
    }
    // SAFETY: `ri` is live.
    unsafe {
        (*ri).encoded_type = CMS_RECIPINFO_KEK;
        (*ri).type_ = CMS_RECIPINFO_KEK;
    }

    if !other_type_id.is_null() {
        // SAFETY: `kekri` is live.
        let other =
            unsafe { m_asn1_new(cms_otherkeyattribute_it()).cast::<CmsOtherKeyAttribute>() };
        // SAFETY: `kekri` is live.
        unsafe { (*(*kekri).kekid).other = other };
        if other.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(773, c"CMS_add0_recipient_key", ERR_R_ASN1_LIB) };
            // SAFETY: `ri` is owned here.
            unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
            return ptr::null_mut();
        }
    }

    // SAFETY: `ris`/`ri` are live.
    if unsafe { OPENSSL_sk_push(ris, ri.cast()) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(779, c"CMS_add0_recipient_key", ERR_R_CRYPTO_LIB) };
        // SAFETY: `ri` is owned here.
        unsafe { m_asn1_free(ri.cast(), cms_recipientinfo_it()) };
        return ptr::null_mut();
    }

    // After this point no calls can fail.

    // SAFETY: `kekri` is live; the buffers are the caller's and adopted.
    unsafe {
        (*kekri).version = 4;
        (*kekri).key = key;
        (*kekri).keylen = keylen;
        ASN1_STRING_set0((*(*kekri).kekid).key_identifier, id.cast(), idlen as c_int);
        (*(*kekri).kekid).date = date;
    }

    // SAFETY: `kekri` is live.
    if !unsafe { (*(*kekri).kekid).other }.is_null() {
        // SAFETY: `kekri` is live.
        unsafe {
            (*(*(*kekri).kekid).other).key_attr_id = other_type_id;
            (*(*(*kekri).kekid).other).key_attr = other_type;
        }
    }

    // SAFETY: `kekri` is live.
    unsafe {
        X509_ALGOR_set0(
            (*kekri).key_encryption_algorithm,
            OBJ_nid2obj(nid),
            V_ASN1_UNDEF,
            ptr::null_mut(),
        )
    };

    ri
}

/// `int CMS_RecipientInfo_kekri_get0_id(CMS_RecipientInfo *ri, X509_ALGOR **palg,`
/// `ASN1_OCTET_STRING **pid, ASN1_GENERALIZEDTIME **pdate, ASN1_OBJECT **potherid,`
/// `ASN1_TYPE **pothertype)` — `cms_env.c:809-841`.
///
/// # Safety
/// `ri` is live; the out-slots are writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_kekri_get0_id(
    ri: *mut CmsRecipientInfo,
    palg: *mut *mut X509Algor,
    pid: *mut *mut Asn1String,
    pdate: *mut *mut Asn1String,
    potherid: *mut *mut Asn1Object,
    pothertype: *mut *mut Asn1Type,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEK {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(818, c"CMS_RecipientInfo_kekri_get0_id", ERR_CMS_R_NOT_KEK) };
        return 0;
    }
    // SAFETY: `ri` is live.
    let kekri = unsafe { (*ri).d.cast::<CmsKekRecipientInfo>() };
    // SAFETY: `kekri` is live.
    let rkid = unsafe { (*kekri).kekid };
    if !palg.is_null() {
        // SAFETY: `palg` is writable; `kekri` is live.
        unsafe { *palg = (*kekri).key_encryption_algorithm };
    }
    if !pid.is_null() {
        // SAFETY: `pid` is writable; `rkid` is live.
        unsafe { *pid = (*rkid).key_identifier };
    }
    if !pdate.is_null() {
        // SAFETY: `pdate` is writable; `rkid` is live.
        unsafe { *pdate = (*rkid).date };
    }
    if !potherid.is_null() {
        // SAFETY: `rkid` is live.
        if !unsafe { (*rkid).other }.is_null() {
            // SAFETY: `rkid` is live.
            unsafe { *potherid = (*(*rkid).other).key_attr_id };
        } else {
            // SAFETY: `potherid` is writable.
            unsafe { *potherid = ptr::null_mut() };
        }
    }
    if !pothertype.is_null() {
        // SAFETY: `rkid` is live.
        if !unsafe { (*rkid).other }.is_null() {
            // SAFETY: `rkid` is live.
            unsafe { *pothertype = (*(*rkid).other).key_attr };
        } else {
            // SAFETY: `pothertype` is writable.
            unsafe { *pothertype = ptr::null_mut() };
        }
    }
    1
}

/// `int CMS_RecipientInfo_set0_key(CMS_RecipientInfo *ri, unsigned char *key,`
/// `size_t keylen)` — `cms_env.c:843-856`.
///
/// # Safety
/// `ri` is live; `key` is NULL or readable for `keylen`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_set0_key(
    ri: *mut CmsRecipientInfo,
    key: *mut c_uchar,
    keylen: usize,
) -> c_int {
    // SAFETY: `ri` is live.
    if unsafe { (*ri).type_ } != CMS_RECIPINFO_KEK {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(848, c"CMS_RecipientInfo_set0_key", ERR_CMS_R_NOT_KEK) };
        return 0;
    }

    // SAFETY: `ri` is live.
    let kekri = unsafe { (*ri).d.cast::<CmsKekRecipientInfo>() };
    // SAFETY: `kekri` is live.
    unsafe {
        (*kekri).key = key;
        (*kekri).keylen = keylen;
    }
    1
}

/// `static EVP_CIPHER *cms_get_key_wrap_cipher(size_t keylen, const CMS_CTX *ctx)` —
/// `cms_env.c:858-877`.
///
/// # Safety
/// `ctx` is live.
unsafe fn cms_get_key_wrap_cipher(keylen: usize, ctx: *const CmsCtx) -> *mut EvpCipher {
    let alg: &core::ffi::CStr = match keylen {
        16 => c"AES-128-WRAP",
        24 => c"AES-192-WRAP",
        32 => c"AES-256-WRAP",
        _ => return ptr::null_mut(),
    };
    // SAFETY: `ctx` is live.
    unsafe {
        EVP_CIPHER_fetch(
            ossl_cms_ctx_get0_libctx(ctx),
            alg.as_ptr(),
            ossl_cms_ctx_get0_propq(ctx),
        )
    }
}

/// `static int cms_RecipientInfo_kekri_encrypt(const CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_env.c:881-946`.
///
/// # Safety
/// `cms`/`ri` are live.
unsafe fn cms_RecipientInfo_kekri_encrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    let mut wkey: *mut c_uchar = ptr::null_mut();
    let mut wkeylen: c_int = 0;
    let mut r = 0;
    let mut cipher: *mut EvpCipher = ptr::null_mut();
    let mut outlen: c_int = 0;
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    // SAFETY: `cms` is live.
    let cms_ctx = unsafe { ossl_cms_get0_cmsctx(cms) };

    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };
    if ec.is_null() {
        return 0;
    }

    // SAFETY: `ri` is live.
    let kekri = unsafe { (*ri).d.cast::<CmsKekRecipientInfo>() };

    // SAFETY: `kekri` is live.
    if unsafe { (*kekri).key }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                901,
                c"cms_RecipientInfo_kekri_encrypt",
                crate::runtime::err::err_reasons::CMS_R_NO_KEY,
            )
        };
        return 0;
    }

    // SAFETY: `kekri` is live.
    cipher = unsafe { cms_get_key_wrap_cipher((*kekri).keylen, cms_ctx) };
    if cipher.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                907,
                c"cms_RecipientInfo_kekri_encrypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        return r;
    }

    // 8 byte prefix for AES wrap ciphers.
    // SAFETY: `ec` is live.
    let alloc = unsafe { (*ec).keylen } + 8;
    // SAFETY: `alloc > 0`.
    wkey = CRYPTO_malloc(alloc, c"cms_env.c".as_ptr(), 912).cast::<c_uchar>();
    if wkey.is_null() {
        // SAFETY: `cipher`/`ctx` are NULL or owned.
        unsafe {
            EVP_CIPHER_free(cipher);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }

    // SAFETY: the allocator answers a fresh context.
    ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(918, c"cms_RecipientInfo_kekri_encrypt", ERR_R_EVP_LIB) };
        // SAFETY: each is NULL or owned.
        unsafe {
            EVP_CIPHER_free(cipher);
            CRYPTO_free(wkey.cast(), c"cms_env.c".as_ptr(), 942);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }

    // SAFETY: `ctx` is live.
    unsafe { EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) };
    // SAFETY: `ctx`/`cipher`/`ec` are live.
    let ok = unsafe {
        EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), (*kekri).key, ptr::null())
    } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_EncryptUpdate(ctx, wkey, &mut wkeylen, (*ec).key, (*ec).keylen as c_int)
        } != 0
        // SAFETY: as above.
        && unsafe { EVP_EncryptFinal_ex(ctx, wkey.add(wkeylen as usize), &mut outlen) } != 0;
    if !ok {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                926,
                c"cms_RecipientInfo_kekri_encrypt",
                crate::runtime::err::err_reasons::CMS_R_WRAP_ERROR,
            )
        };
        // SAFETY: each is NULL or owned.
        unsafe {
            EVP_CIPHER_free(cipher);
            CRYPTO_free(wkey.cast(), c"cms_env.c".as_ptr(), 942);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }
    wkeylen += outlen;
    // SAFETY: `ec` is live.
    if (wkeylen as usize) != unsafe { (*ec).keylen } + 8 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                931,
                c"cms_RecipientInfo_kekri_encrypt",
                crate::runtime::err::err_reasons::CMS_R_WRAP_ERROR,
            )
        };
        // SAFETY: each pointer is NULL or owned here.
        unsafe {
            EVP_CIPHER_free(cipher);
            CRYPTO_free(wkey.cast(), c"cms_env.c".as_ptr(), 942);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }

    // SAFETY: `kekri`/`wkey` are live; ownership transfers.
    unsafe { ASN1_STRING_set0((*kekri).encrypted_key, wkey.cast(), wkeylen) };
    wkey = ptr::null_mut();

    r = 1;

    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_free(cipher);
        if r == 0 {
            CRYPTO_free(wkey.cast(), c"cms_env.c".as_ptr(), 942);
        }
        crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
    }

    r
}

/// `static int cms_RecipientInfo_kekri_decrypt(CMS_ContentInfo *cms,`
/// `CMS_RecipientInfo *ri)` — `cms_env.c:950-1028`.
///
/// # Safety
/// `cms`/`ri` are live.
unsafe fn cms_RecipientInfo_kekri_decrypt(
    cms: *mut CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    let mut ukey: *mut c_uchar = ptr::null_mut();
    let mut ukey_alloc_len: usize = 0;
    let mut ukeylen: c_int = 0;
    let mut r = 0;
    let mut wrap_nid = 0;
    let mut cipher: *mut EvpCipher = ptr::null_mut();
    let mut outlen: c_int = 0;
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    // SAFETY: `cms` is live.
    let cms_ctx = unsafe { ossl_cms_get0_cmsctx(cms) };

    // SAFETY: `cms` is live.
    let ec = unsafe { ossl_cms_get0_env_enc_content(cms) };
    if ec.is_null() {
        return 0;
    }

    // SAFETY: `ri` is live.
    let kekri = unsafe { (*ri).d.cast::<CmsKekRecipientInfo>() };

    // SAFETY: `kekri` is live.
    if unsafe { (*kekri).key }.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                971,
                c"cms_RecipientInfo_kekri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_NO_KEY,
            )
        };
        return 0;
    }

    // SAFETY: `kekri` is live.
    wrap_nid = unsafe { OBJ_obj2nid((*(*kekri).key_encryption_algorithm).algorithm) };
    // SAFETY: `kekri` is live.
    if aes_wrap_keylen(wrap_nid) != unsafe { (*kekri).keylen } {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                977,
                c"cms_RecipientInfo_kekri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        return 0;
    }

    // If encrypted key length is invalid don't bother.
    // SAFETY: `kekri` is live.
    if unsafe { (*(*kekri).encrypted_key).length } < 16 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                984,
                c"cms_RecipientInfo_kekri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_ENCRYPTED_KEY_LENGTH,
            )
        };
        return r;
    }

    // SAFETY: `kekri` is live.
    cipher = unsafe { cms_get_key_wrap_cipher((*kekri).keylen, cms_ctx) };
    if cipher.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                990,
                c"cms_RecipientInfo_kekri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        return r;
    }

    // SAFETY: `kekri` is live.
    ukey_alloc_len = unsafe { (*(*kekri).encrypted_key).length } as usize - 8;
    // SAFETY: `ukey_alloc_len >= 8`.
    ukey = CRYPTO_malloc(ukey_alloc_len, c"cms_env.c".as_ptr(), 995).cast::<c_uchar>();
    if ukey.is_null() {
        // SAFETY: `cipher` is owned here.
        unsafe { EVP_CIPHER_free(cipher) };
        return r;
    }

    // SAFETY: the allocator answers a fresh context.
    ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(1001, c"cms_RecipientInfo_kekri_decrypt", ERR_R_EVP_LIB) };
        // SAFETY: each is NULL or owned.
        unsafe {
            EVP_CIPHER_free(cipher);
            super::cms_asn1::OPENSSL_clear_free(ukey, ukey_alloc_len);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }

    // SAFETY: `ctx`/`cipher`/`kekri` are live.
    let ok = unsafe {
        EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), (*kekri).key.cast(), ptr::null())
    } != 0
        // SAFETY: as above.
        && unsafe {
            EVP_DecryptUpdate(
                ctx,
                ukey,
                &mut ukeylen,
                (*(*kekri).encrypted_key).data,
                (*(*kekri).encrypted_key).length,
            )
        } != 0
        // SAFETY: as above.
        && unsafe { EVP_DecryptFinal_ex(ctx, ukey.add(ukeylen as usize), &mut outlen) } != 0;
    if !ok {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1010,
                c"cms_RecipientInfo_kekri_decrypt",
                crate::runtime::err::err_reasons::CMS_R_UNWRAP_ERROR,
            )
        };
        // SAFETY: each is NULL or owned.
        unsafe {
            EVP_CIPHER_free(cipher);
            super::cms_asn1::OPENSSL_clear_free(ukey, ukey_alloc_len);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
        }
        return r;
    }
    ukeylen += outlen;

    // SAFETY: `ec` is live.
    unsafe {
        super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
        (*ec).key = ukey;
        (*ec).keylen = ukeylen as usize;
    }
    ukey = ptr::null_mut();

    r = 1;

    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_free(cipher);
        if r == 0 {
            super::cms_asn1::OPENSSL_clear_free(ukey, ukey_alloc_len);
        }
        crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx);
    }

    r
}

/// `int CMS_RecipientInfo_decrypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri)` —
/// `cms_env.c:1030-1049`.
///
/// # Safety
/// `cms`/`ri` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_decrypt(
    cms: *mut CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    // SAFETY: `ri` is live.
    let ri_type = unsafe { (*ri).type_ };
    if ri_type == CMS_RECIPINFO_TRANS {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { cms_RecipientInfo_ktri_decrypt(cms, ri) };
    } else if ri_type == CMS_RECIPINFO_KEK {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { cms_RecipientInfo_kekri_decrypt(cms, ri) };
    } else if ri_type == CMS_RECIPINFO_PASS {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { super::cms_pwri::ossl_cms_RecipientInfo_pwri_crypt(cms, ri, 0) };
    } else if ri_type == CMS_RECIPINFO_KEM {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { super::cms_kemri::ossl_cms_RecipientInfo_kemri_decrypt(cms, ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            1046,
            c"CMS_RecipientInfo_decrypt",
            crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE,
        )
    };
    0
}

/// `int CMS_RecipientInfo_encrypt(const CMS_ContentInfo *cms, CMS_RecipientInfo *ri)` —
/// `cms_env.c:1051-1073`.
///
/// # Safety
/// `cms`/`ri` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_RecipientInfo_encrypt(
    cms: *const CmsContentInfo,
    ri: *mut CmsRecipientInfo,
) -> c_int {
    // SAFETY: `ri` is live.
    let ri_type = unsafe { (*ri).type_ };
    if ri_type == CMS_RECIPINFO_TRANS {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { cms_RecipientInfo_ktri_encrypt(cms, ri) };
    } else if ri_type == CMS_RECIPINFO_AGREE {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { super::cms_kari::ossl_cms_RecipientInfo_kari_encrypt(cms, ri) };
    } else if ri_type == CMS_RECIPINFO_KEK {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { cms_RecipientInfo_kekri_encrypt(cms, ri) };
    } else if ri_type == CMS_RECIPINFO_PASS {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { super::cms_pwri::ossl_cms_RecipientInfo_pwri_crypt(cms, ri, 1) };
    } else if ri_type == CMS_RECIPINFO_KEM {
        // SAFETY: `cms`/`ri` are live.
        return unsafe { super::cms_kemri::ossl_cms_RecipientInfo_kemri_encrypt(cms, ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            1070,
            c"CMS_RecipientInfo_encrypt",
            crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_RECIPIENT_TYPE,
        )
    };
    0
}

/// `static void cms_env_set_originfo_version(CMS_EnvelopedData *env)` — `cms_env.c:1077-1103`.
///
/// # Safety
/// `env` is live.
unsafe fn cms_env_set_originfo_version(env: *mut CmsEnvelopedData) {
    // SAFETY: `env` is live.
    let org = unsafe { (*env).originator_info };
    if org.is_null() {
        return;
    }
    // SAFETY: `org` is live.
    for i in 0..unsafe { OPENSSL_sk_num((*org).certificates) } {
        // SAFETY: `i` is in range.
        let cch =
            unsafe { OPENSSL_sk_value((*org).certificates, i) }.cast::<CmsCertificateChoices>();
        // SAFETY: `cch` is live.
        if unsafe { (*cch).type_ } == CMS_CERTCHOICE_OTHER {
            // SAFETY: `env` is live.
            unsafe { (*env).version = 4 };
            return;
        // SAFETY: the arguments meet the callee's contract.
        } else if unsafe { (*cch).type_ } == CMS_CERTCHOICE_V2ACERT {
            // SAFETY: `env` is live.
            if unsafe { (*env).version } < 3 {
                // SAFETY: `env` is live.
                unsafe { (*env).version = 3 };
            }
        }
    }

    // SAFETY: `org` is live.
    for i in 0..unsafe { OPENSSL_sk_num((*org).crls) } {
        // SAFETY: `i` is in range.
        let rch = unsafe { OPENSSL_sk_value((*org).crls, i) }.cast::<CmsRevocationInfoChoice>();
        // SAFETY: `rch` is live.
        if unsafe { (*rch).type_ } == CMS_REVCHOICE_OTHER {
            // SAFETY: `env` is live.
            unsafe { (*env).version = 4 };
            return;
        }
    }
}

/// `static void cms_env_set_version(CMS_EnvelopedData *env)` — `cms_env.c:1105-1137`.
///
/// # Safety
/// `env` is live.
unsafe fn cms_env_set_version(env: *mut CmsEnvelopedData) {
    // SAFETY: `env` is live.
    if unsafe { (*env).version } >= 4 {
        return;
    }

    // SAFETY: `env` is live.
    unsafe { cms_env_set_originfo_version(env) };

    // SAFETY: `env` is live.
    if unsafe { (*env).version } >= 3 {
        return;
    }

    // SAFETY: `env` is live.
    for i in 0..unsafe { OPENSSL_sk_num((*env).recipient_infos) } {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value((*env).recipient_infos, i) }.cast::<CmsRecipientInfo>();
        // SAFETY: `ri` is live.
        let ri_type = unsafe { (*ri).type_ };
        if ri_type == CMS_RECIPINFO_PASS
            || ri_type == CMS_RECIPINFO_OTHER
            || ri_type == CMS_RECIPINFO_KEM
        {
            // SAFETY: `env` is live.
            unsafe { (*env).version = 3 };
            return;
        } else if ri_type != CMS_RECIPINFO_TRANS
            // SAFETY: `ri` is live.
            || unsafe { (*(*ri).d.cast::<CmsKeyTransRecipientInfo>()).version } != 0
        {
            // SAFETY: `env` is live.
            unsafe { (*env).version = 2 };
        }
    }
    // SAFETY: `env` is live.
    if !unsafe { (*env).originator_info }.is_null()
        // SAFETY: `env` is live.
        || !unsafe { (*env).unprotected_attrs }.is_null()
    {
        // SAFETY: `env` is live.
        unsafe { (*env).version = 2 };
    }
    // SAFETY: `env` is live.
    if unsafe { (*env).version } == 2 {
        return;
    }
    // SAFETY: `env` is live.
    unsafe { (*env).version = 0 };
}

/// `static int cms_env_encrypt_content_key(const CMS_ContentInfo *cms,`
/// `STACK_OF(CMS_RecipientInfo) *ris)` — `cms_env.c:1139-1151`.
///
/// # Safety
/// `cms`/`ris` are live.
unsafe fn cms_env_encrypt_content_key(cms: *const CmsContentInfo, ris: *mut OpenSslStack) -> c_int {
    // SAFETY: `ris` is live.
    for i in 0..unsafe { OPENSSL_sk_num(ris) } {
        // SAFETY: `i` is in range.
        let ri = unsafe { OPENSSL_sk_value(ris, i) }.cast::<CmsRecipientInfo>();
        // SAFETY: `cms`/`ri` are live.
        if unsafe { CMS_RecipientInfo_encrypt(cms, ri) } <= 0 {
            return -1;
        }
    }
    1
}

/// `static void cms_env_clear_ec(CMS_EncryptedContentInfo *ec)` — `cms_env.c:1153-1159`.
///
/// # Safety
/// `ec` is live.
unsafe fn cms_env_clear_ec(ec: *mut CmsEncryptedContentInfo) {
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).cipher = ptr::null();
        super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
        (*ec).key = ptr::null_mut();
        (*ec).keylen = 0;
    }
}

/// `static BIO *cms_EnvelopedData_Decryption_init_bio(CMS_ContentInfo *cms)` —
/// `cms_env.c:1161-1191`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_EnvelopedData_Decryption_init_bio(cms: *mut CmsContentInfo) -> *mut Bio {
    // SAFETY: `cms` is live.
    let ec = unsafe { (*(*cms).d.cast::<CmsEnvelopedData>()).encrypted_content_info };
    // SAFETY: `ec`/`cms` are live.
    let content_bio =
        unsafe { ossl_cms_EncryptedContent_init_bio(ec, ossl_cms_get0_cmsctx(cms), 0) };
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();

    if content_bio.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `content_bio` is live; `ctx` is this frame's slot.
    unsafe { bio_get_cipher_ctx(content_bio, &mut ctx) };
    if ctx.is_null() {
        // SAFETY: `content_bio` is owned here.
        unsafe { BIO_free(content_bio) };
        return ptr::null_mut();
    }
    // If the selected cipher supports unprotected attributes, deal with it using the ctrl.
    // SAFETY: `ctx` is live.
    let flags = unsafe { EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) };
    if flags & EVP_CIPH_FLAG_CIPHER_WITH_MAC != 0
        // SAFETY: `ctx` is live; the attrs are borrowed.
        && unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_PROCESS_UNPROTECTED,
                0,
                (*(*cms).d.cast::<CmsEnvelopedData>()).unprotected_attrs.cast(),
            )
        } <= 0
    {
        // SAFETY: `content_bio` is owned here.
        unsafe { BIO_free(content_bio) };
        return ptr::null_mut();
    }
    content_bio
}

/// `static BIO *cms_EnvelopedData_Encryption_init_bio(CMS_ContentInfo *cms)` —
/// `cms_env.c:1193-1228`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_EnvelopedData_Encryption_init_bio(cms: *mut CmsContentInfo) -> *mut Bio {
    // SAFETY: `cms` is live.
    let env = unsafe { (*cms).d.cast::<CmsEnvelopedData>() };
    // SAFETY: `env` is live.
    let ec = unsafe { (*env).encrypted_content_info };
    // SAFETY: `ec`/`cms` are live.
    let ret = unsafe { ossl_cms_EncryptedContent_init_bio(ec, ossl_cms_get0_cmsctx(cms), 0) };

    if ret.is_null() {
        return ret;
    }

    // Now encrypt the content key according to each RecipientInfo type.
    // SAFETY: `env` is live.
    let rinfos = unsafe { (*env).recipient_infos };
    // SAFETY: `cms`/`rinfos` are live.
    let ok = if unsafe { cms_env_encrypt_content_key(cms, rinfos) } < 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1213,
                c"cms_EnvelopedData_Encryption_init_bio",
                crate::runtime::err::err_reasons::CMS_R_ERROR_SETTING_RECIPIENTINFO,
            )
        };
        false
    } else {
        // And finally set the version.
        // SAFETY: `env` is live.
        unsafe { cms_env_set_version(env) };
        true
    };

    // SAFETY: `ec` is live.
    unsafe { cms_env_clear_ec(ec) };
    if ok {
        return ret;
    }
    // SAFETY: `ret` is owned here.
    unsafe { BIO_free(ret) };
    ptr::null_mut()
}

/// `BIO *ossl_cms_EnvelopedData_init_bio(CMS_ContentInfo *cms)` — `cms_env.c:1230-1239`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EnvelopedData_init_bio(
    cms: *mut CmsContentInfo,
) -> *mut Bio {
    // SAFETY: `cms` is live.
    let env = unsafe { (*cms).d.cast::<CmsEnvelopedData>() };
    // SAFETY: `env` is live.
    if !unsafe { (*(*env).encrypted_content_info).cipher }.is_null() {
        // If cipher is set it's encryption.
        // SAFETY: `cms` is live.
        return unsafe { cms_EnvelopedData_Encryption_init_bio(cms) };
    }

    // If cipher is not set it's decryption.
    // SAFETY: `cms` is live.
    unsafe { cms_EnvelopedData_Decryption_init_bio(cms) }
}

/// `static int cms_AuthEnvelopedData_set_aad(BIO *b,`
/// `STACK_OF(X509_ATTRIBUTE) *authAttrs)` — `cms_env.c:1242-1268`.
///
/// # Safety
/// `b`/`auth_attrs` are live.
unsafe fn cms_AuthEnvelopedData_set_aad(b: *mut Bio, auth_attrs: *mut OpenSslStack) -> c_int {
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut aad: *mut c_uchar = ptr::null_mut();
    let mut aadlen = 0;
    let mut outl: c_int = 0;
    let mut ok = 0;

    // SAFETY: `b`/`ctx` are live.
    if unsafe { bio_get_cipher_ctx(b, &mut ctx) } == 0 {
        return 0;
    }
    // SAFETY: `ctx` is live.
    let item = if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0 {
        cms_attributes_sign_it()
    } else {
        cms_attributes_verify_it()
    };
    // SAFETY: `auth_attrs` is live; `aad` is this frame's slot.
    aadlen = unsafe { crate::asn1::i2d::ASN1_item_i2d(auth_attrs.cast(), &mut aad, item) };
    if aadlen <= 0 || aad.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(1257, c"cms_AuthEnvelopedData_set_aad", ERR_R_ASN1_LIB) };
        // SAFETY: `aad` is NULL or owned.
        unsafe { CRYPTO_free(aad.cast(), c"cms_env.c".as_ptr(), 1266) };
        return ok;
    }
    // SAFETY: `ctx` is live; `aad` is readable for `aadlen`.
    if unsafe {
        crate::evp::cipher_ctx::EVP_CipherUpdate(ctx, ptr::null_mut(), &mut outl, aad, aadlen)
    } <= 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(1261, c"cms_AuthEnvelopedData_set_aad", ERR_R_CMS_LIB) };
        // SAFETY: `aad` is owned here.
        unsafe { CRYPTO_free(aad.cast(), c"cms_env.c".as_ptr(), 1266) };
        return ok;
    }
    ok = 1;
    // SAFETY: `aad` is owned here.
    unsafe { CRYPTO_free(aad.cast(), c"cms_env.c".as_ptr(), 1266) };
    ok
}

/// `BIO *ossl_cms_AuthEnvelopedData_init_bio(CMS_ContentInfo *cms)` — `cms_env.c:1270-1316`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_AuthEnvelopedData_init_bio(
    cms: *mut CmsContentInfo,
) -> *mut Bio {
    let mut ok = 0;
    // SAFETY: `cms` is live.
    let aenv = unsafe { (*cms).d.cast::<CmsAuthEnvelopedData>() };

    // Get BIO first to set up key.
    // SAFETY: `aenv` is live.
    let ec = unsafe { (*aenv).auth_encrypted_content_info };
    // Set tag for decryption.
    // SAFETY: `ec`/`aenv` are live.
    if unsafe { (*ec).cipher }.is_null() {
        // SAFETY: `aenv` is live.
        unsafe {
            (*ec).tag = (*(*aenv).mac).data;
            (*ec).taglen = (*(*aenv).mac).length as usize;
        }
    }
    // SAFETY: `ec`/`cms` are live.
    let ret = unsafe { ossl_cms_EncryptedContent_init_bio(ec, ossl_cms_get0_cmsctx(cms), 1) };
    if ret.is_null() {
        return ptr::null_mut();
    }

    // authAttrs, if present, are the AEAD associated data.
    // SAFETY: `aenv` is live.
    if !unsafe { (*aenv).auth_attrs }.is_null()
        // SAFETY: `ret`/`aenv` are live.
        && unsafe { cms_AuthEnvelopedData_set_aad(ret, (*aenv).auth_attrs) } == 0
    {
        // SAFETY: `ret` is owned here.
        unsafe { BIO_free(ret) };
        return ptr::null_mut();
    }

    'body: {
        // If no cipher end of processing.
        // SAFETY: `ec` is live.
        if unsafe { (*ec).cipher }.is_null() {
            return ret;
        }

        // Now encrypt the content key according to each RecipientInfo type.
        // SAFETY: `aenv` is live.
        let rinfos = unsafe { (*aenv).recipient_infos };
        // SAFETY: `cms`/`rinfos` are live.
        if unsafe { cms_env_encrypt_content_key(cms, rinfos) } < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    1301,
                    c"ossl_cms_AuthEnvelopedData_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_ERROR_SETTING_RECIPIENTINFO,
                )
            };
            break 'body;
        }

        // And finally set the version.
        // SAFETY: `aenv` is live.
        unsafe { (*aenv).version = 0 };

        ok = 1;
    }
    // SAFETY: `ec` is live.
    unsafe { cms_env_clear_ec(ec) };
    if ok != 0 {
        return ret;
    }
    // SAFETY: `ret` is owned here.
    unsafe { BIO_free(ret) };
    ptr::null_mut()
}

/// `int ossl_cms_EnvelopedData_final(CMS_ContentInfo *cms, BIO *chain)` — `cms_env.c:1318-1360`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_EnvelopedData_final(
    cms: *mut CmsContentInfo,
    chain: *mut Bio,
) -> c_int {
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    // SAFETY: `chain` is live.
    let mbio = unsafe { BIO_find_type(chain, BIO_TYPE_CIPHER) };

    // SAFETY: `cms` is live.
    let env = unsafe { ossl_cms_get0_enveloped(cms) };
    if env.is_null() {
        return 0;
    }

    if mbio.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1329,
                c"ossl_cms_EnvelopedData_final",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_NOT_FOUND,
            )
        };
        return 0;
    }

    // SAFETY: `mbio` is live; `ctx` is this frame's slot.
    unsafe { bio_get_cipher_ctx(mbio, &mut ctx) };

    // If the selected cipher supports unprotected attributes, deal with it using the ctrl.
    // SAFETY: `ctx` is live.
    let flags = unsafe { EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) };
    if flags & EVP_CIPH_FLAG_CIPHER_WITH_MAC != 0 {
        // SAFETY: `env` is live.
        if unsafe { (*env).unprotected_attrs }.is_null() {
            // SAFETY: the stack allocator answers a fresh stack.
            unsafe { (*env).unprotected_attrs = OPENSSL_sk_new_null() };
        }

        // SAFETY: `env` is live.
        if unsafe { (*env).unprotected_attrs }.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(1346, c"ossl_cms_EnvelopedData_final", ERR_R_CRYPTO_LIB) };
            return 0;
        }

        // SAFETY: `ctx` is live; the attrs are borrowed.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx,
                EVP_CTRL_PROCESS_UNPROTECTED,
                1,
                (*env).unprotected_attrs.cast(),
            )
        } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(1353, c"ossl_cms_EnvelopedData_final", ERR_R_CMS_LIB) };
            return 0;
        }
    }

    // SAFETY: `cms` is live.
    unsafe { cms_env_set_version((*cms).d.cast::<CmsEnvelopedData>()) };
    1
}

/// `int ossl_cms_AuthEnvelopedData_final(CMS_ContentInfo *cms, BIO *cmsbio)` —
/// `cms_env.c:1362-1394`.
///
/// # Safety
/// `cms`/`cmsbio` are live.
pub(crate) unsafe extern "C" fn ossl_cms_AuthEnvelopedData_final(
    cms: *mut CmsContentInfo,
    cmsbio: *mut Bio,
) -> c_int {
    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    let mut tag: *mut c_uchar = ptr::null_mut();
    let mut taglen = 0;
    let mut ok = 0;

    // SAFETY: `cmsbio` is live; `ctx` is this frame's slot.
    unsafe { bio_get_cipher_ctx(cmsbio, &mut ctx) };

    // The tag is set only for encryption. There is nothing to do for decryption.
    // SAFETY: `ctx` is live.
    if unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } == 0 {
        return 1;
    }

    // SAFETY: `ctx` is live.
    taglen = unsafe { EVP_CIPHER_CTX_get_tag_length(ctx) };
    // SAFETY: `taglen > 0`.
    tag = CRYPTO_malloc(taglen as usize, c"cms_env.c".as_ptr(), 1379).cast::<c_uchar>();
    // SAFETY: `ctx` is live; `tag` is writable.
    if taglen <= 0
        || tag.is_null()
        // SAFETY: the context and cipher are live.
        || unsafe {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag.cast())
        } <= 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1383,
                c"ossl_cms_AuthEnvelopedData_final",
                crate::runtime::err::err_reasons::CMS_R_CIPHER_GET_TAG,
            )
        };
        // SAFETY: `tag` is NULL or owned.
        unsafe { CRYPTO_free(tag.cast(), c"cms_env.c".as_ptr(), 1392) };
        return ok;
    }

    // SAFETY: `cms` is live; `tag` is readable for `taglen`.
    if unsafe {
        crate::asn1::string::ASN1_OCTET_STRING_set(
            (*(*cms).d.cast::<CmsAuthEnvelopedData>()).mac,
            tag,
            taglen,
        )
    } == 0
    {
        // SAFETY: `tag` is owned here.
        unsafe { CRYPTO_free(tag.cast(), c"cms_env.c".as_ptr(), 1392) };
        return ok;
    }

    ok = 1;
    // SAFETY: `tag` is owned here.
    unsafe { CRYPTO_free(tag.cast(), c"cms_env.c".as_ptr(), 1392) };
    ok
}

/// `int ossl_cms_pkey_get_ri_type(EVP_PKEY *pk)` — `cms_env.c:1401-1456`.
///
/// # Safety
/// `pk` is live.
pub(crate) unsafe extern "C" fn ossl_cms_pkey_get_ri_type(pk: *mut EvpPkey) -> c_int {
    let mut ri_type = 0;
    let mut ctx: *mut crate::evp::pkey_ctx::EvpPkeyCtx = ptr::null_mut();

    // SAFETY: `pk` is live; `ri_type` is this frame's slot.
    if unsafe { evp_pkey_is_provided(pk) } != 0
        // SAFETY: `pk` is live.
        && unsafe { EVP_PKEY_get_int_param(pk, OSSL_PKEY_PARAM_CMS_RI_TYPE, &mut ri_type) } != 0
    {
        return ri_type;
    }

    // SAFETY: `pk` is live.
    if unsafe { EVP_PKEY_is_a(pk, c"DH".as_ptr()) } != 0
        // SAFETY: `pk` is live.
        || unsafe { EVP_PKEY_is_a(pk, c"DHX".as_ptr()) } != 0
    {
        return CMS_RECIPINFO_AGREE;
    // SAFETY: the context and key are live.
    } else if unsafe { EVP_PKEY_is_a(pk, c"DSA".as_ptr()) } != 0 {
        return CMS_RECIPINFO_NONE;
    // SAFETY: the context and key are live.
    } else if unsafe { EVP_PKEY_is_a(pk, c"EC".as_ptr()) } != 0 {
        return CMS_RECIPINFO_AGREE;
    // SAFETY: the context and key are live.
    } else if unsafe { EVP_PKEY_is_a(pk, c"RSA".as_ptr()) } != 0 {
        return CMS_RECIPINFO_TRANS;
    }

    ri_type = CMS_RECIPINFO_TRANS;
    // SAFETY: `pk` is live.
    ctx = unsafe { EVP_PKEY_CTX_new(pk, ptr::null_mut()) };
    if !ctx.is_null() {
        // SAFETY: the queue is this thread's.
        crate::runtime::err::ERR_set_mark();
        // SAFETY: `ctx` is live.
        if unsafe { EVP_PKEY_encrypt_init(ctx) } > 0 {
            ri_type = CMS_RECIPINFO_TRANS;
        // SAFETY: the context and key are live.
        } else if unsafe { EVP_PKEY_derive_init(ctx) } > 0 {
            ri_type = CMS_RECIPINFO_AGREE;
        // SAFETY: the context and key are live.
        } else if unsafe { EVP_PKEY_encapsulate_init(ctx, ptr::null()) } > 0 {
            ri_type = CMS_RECIPINFO_KEM;
        }
        // SAFETY: the queue is this thread's.
        crate::runtime::err::ERR_pop_to_mark();
    }
    // SAFETY: `ctx` is live.
    unsafe { EVP_PKEY_CTX_free(ctx) };

    ri_type
}

/// `int ossl_cms_pkey_is_ri_type_supported(EVP_PKEY *pk, int ri_type)` — `cms_env.c:1458-1476`.
///
/// # Safety
/// `pk` is live.
pub(crate) unsafe extern "C" fn ossl_cms_pkey_is_ri_type_supported(
    pk: *mut EvpPkey,
    ri_type: c_int,
) -> c_int {
    // SAFETY: `pk` is live.
    let supported = unsafe { ossl_cms_pkey_get_ri_type(pk) };
    if supported < 0 {
        return 0;
    }

    c_int::from(supported == ri_type)
}

/// `int ossl_cms_RecipientInfo_wrap_init(CMS_RecipientInfo *ri, const EVP_CIPHER *cipher)` —
/// `cms_env.c:1478-1552`.
///
/// # Safety
/// `ri` is live; `cipher` is NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfo_wrap_init(
    ri: *mut CmsRecipientInfo,
    cipher: *const EvpCipher,
) -> c_int {
    let cms_ctx: *const CmsCtx;
    let ctx: *mut EvpCipherCtx;
    let mut kekcipher: *const EvpCipher = ptr::null();
    let fetched_kekcipher: *mut EvpCipher;
    let kekcipher_name: *const c_char;
    let mut keylen = 0;
    let mut ret;

    // SAFETY: `ri` is live.
    let ri_type = unsafe { (*ri).type_ };
    if ri_type == CMS_RECIPINFO_AGREE {
        // SAFETY: `ri` is live.
        let kari = unsafe { (*ri).d.cast::<CmsKeyAgreeRecipientInfo>() };
        // SAFETY: `kari` is live.
        cms_ctx = unsafe { (*kari).cms_ctx };
        // SAFETY: `kari` is live.
        ctx = unsafe { (*kari).ctx.cast() };
    } else if ri_type == CMS_RECIPINFO_KEM {
        // SAFETY: `ri` is live.
        let kemri = unsafe {
            (*(*ri).d.cast::<CmsOtherRecipientInfo>())
                .d
                .cast::<CmsKemRecipientInfo>()
        };
        // SAFETY: `kemri` is live.
        cms_ctx = unsafe { (*kemri).cms_ctx };
        // SAFETY: `kemri` is live.
        ctx = unsafe { (*kemri).ctx.cast() };
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1496,
                c"ossl_cms_RecipientInfo_wrap_init",
                crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_RECIPIENTINFO_TYPE,
            )
        };
        return 0;
    }

    // If a suitable wrap algorithm is already set nothing to do.
    // SAFETY: `ctx` is live.
    kekcipher = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    if !kekcipher.is_null() {
        // SAFETY: `ctx` is live.
        if unsafe { EVP_CIPHER_get_mode(kekcipher) } != EVP_CIPH_WRAP_MODE {
            return 0;
        }
        return 1;
    }
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: `cipher` is live.
    keylen = unsafe { crate::evp::cipher::EVP_CIPHER_get_key_length(cipher) };
    if keylen <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1511,
                c"ossl_cms_RecipientInfo_wrap_init",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        return 0;
    }
    // SAFETY: `cipher` is live.
    if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_GET_WRAP_CIPHER != 0 {
        // SAFETY: `cipher` is live.
        if let Some(f) = unsafe { crate::evp::cipher::EVP_CIPHER_meth_get_ctrl(cipher) } {
            let mut kk: *const EvpCipher = ptr::null();
            // SAFETY: the legacy control is the implementation's own callback.
            ret = unsafe {
                f(
                    ptr::null_mut(),
                    EVP_CTRL_GET_WRAP_CIPHER,
                    0,
                    ptr::addr_of_mut!(kk).cast(),
                )
            };
            if ret <= 0 {
                return 0;
            }
            if !kk.is_null() {
                // SAFETY: `kk` is live.
                if unsafe { EVP_CIPHER_get_mode(kk) } != EVP_CIPH_WRAP_MODE {
                    return 0;
                }
                // SAFETY: `kk` is live.
                kekcipher_name = unsafe { EVP_CIPHER_get0_name(kk) };
                // SAFETY: the fetched cipher is the caller's.
                fetched_kekcipher = unsafe {
                    EVP_CIPHER_fetch(
                        ossl_cms_ctx_get0_libctx(cms_ctx),
                        kekcipher_name,
                        ossl_cms_ctx_get0_propq(cms_ctx),
                    )
                };
                if fetched_kekcipher.is_null() {
                    return 0;
                }
                // SAFETY: `ctx`/`fetched_kekcipher` are live.
                ret = unsafe {
                    EVP_EncryptInit_ex(
                        ctx,
                        fetched_kekcipher,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                    )
                };
                // SAFETY: `fetched_kekcipher` is owned here.
                unsafe { EVP_CIPHER_free(fetched_kekcipher) };
                return ret;
            }
        } else {
            return 0;
        }
    }

    // Pick a cipher based on content encryption cipher.
    let sn: &core::ffi::CStr = if keylen <= 16 {
        c"id-aes128-wrap"
    } else if keylen <= 24 {
        c"id-aes192-wrap"
    } else {
        c"id-aes256-wrap"
    };
    kekcipher_name = sn.as_ptr();

    // SAFETY: `cms_ctx` is live; `kekcipher_name` is a C string.
    fetched_kekcipher = unsafe {
        EVP_CIPHER_fetch(
            ossl_cms_ctx_get0_libctx(cms_ctx),
            kekcipher_name,
            ossl_cms_ctx_get0_propq(cms_ctx),
        )
    };
    if fetched_kekcipher.is_null() {
        return 0;
    }
    // SAFETY: `ctx`/`fetched_kekcipher` are live.
    ret = unsafe {
        EVP_EncryptInit_ex(
            ctx,
            fetched_kekcipher,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    };
    // SAFETY: `fetched_kekcipher` is owned here.
    unsafe { EVP_CIPHER_free(fetched_kekcipher) };
    ret
}

/// `CMS_R_NOT_KEY_TRANSPORT` — `include/openssl/cmserr.h`.
const ERR_CMS_R_NOT_KEY_TRANSPORT: c_int =
    crate::runtime::err::err_reasons::CMS_R_NOT_KEY_TRANSPORT;
/// `CMS_R_NOT_KEK` — `include/openssl/cmserr.h`.
const ERR_CMS_R_NOT_KEK: c_int = crate::runtime::err::err_reasons::CMS_R_NOT_KEK;
