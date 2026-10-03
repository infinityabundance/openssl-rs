//! `crypto/cms/cms_kem.c` — the KEM envelope arm. Phase 12.3b.
//!
//! Defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_env.c`'s `ossl_cms_env_asn1_ctrl` reaches it and it is cms-local.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_get, ASN1_TYPE_new};
use crate::asn1::layout::V_ASN1_UNDEF;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::x_algor::{
    d2i_X509_ALGOR, X509Algor, X509_ALGOR_copy, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_set0,
};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode, EVP_CIPHER_get_type,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_asn1_to_param,
    EVP_CIPHER_param_to_asn1, EVP_EncryptInit_ex,
};
use crate::evp::pkey::{EVP_PKEY_get_params, EVP_PKEY_get_security_bits};
use crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_modified, OsslParam,
};
use crate::runtime::obj::Asn1Object;
use crate::runtime::obj::{NID_undef, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt, NID_HKDF_SHA256};

use super::cms_asn1::CmsRecipientInfo;

/// `EVP_CIPH_WRAP_MODE` — `include/openssl/evp.h:529`.
const EVP_CIPH_WRAP_MODE: c_int = 0x10002;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `OSSL_MAX_ALGORITHM_ID_SIZE` — `internal/sizes.h:20`.
const OSSL_MAX_ALGORITHM_ID_SIZE: usize = 256;
/// `OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM` — `core_names.h:368`.
const OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM: *const c_char = c"kemri-kdf-alg".as_ptr();

/// `int kem_cms_decrypt(CMS_RecipientInfo *ri)` — `cms_kem.c:21-62`.
///
/// # Safety
/// `ri` is live.
unsafe fn kem_cms_decrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut kek_length: *mut u32 = ptr::null_mut();
    let mut wrap: *mut X509Algor = ptr::null_mut();
    let mut kekcipher: *mut crate::evp::cipher::EvpCipher = ptr::null_mut();
    let mut rv = 0;
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];

    // SAFETY: `ri` is live.
    if unsafe {
        super::cms_kemri::ossl_cms_RecipientInfo_kemri_get0_alg(ri, &mut kek_length, &mut wrap)
    } == 0
    {
        return rv;
    }

    // SAFETY: `ri` is live.
    let pctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    if pctx.is_null() {
        return rv;
    }

    // SAFETY: `ri` is live.
    let kekctx = unsafe { super::cms_kemri::CMS_RecipientInfo_kemri_get0_ctx(ri) };
    if kekctx.is_null() {
        return rv;
    }

    // SAFETY: `name` is writable; `wrap` is live.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*wrap).algorithm,
            0,
        )
    };
    // SAFETY: `pctx` is live; `name` is a C string.
    kekcipher = unsafe {
        EVP_CIPHER_fetch(
            crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_libctx(pctx),
            name.as_ptr(),
            crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_propq(pctx),
        )
    };
    // SAFETY: the pointer is live per the checks above.
    if kekcipher.is_null() || unsafe { EVP_CIPHER_get_mode(kekcipher) } != EVP_CIPH_WRAP_MODE {
        // SAFETY: the context and cipher are live.
        unsafe { EVP_CIPHER_free(kekcipher) };
        return rv;
    }
    // SAFETY: `kekctx`/`kekcipher` are live.
    if unsafe { EVP_EncryptInit_ex(kekctx, kekcipher, ptr::null_mut(), ptr::null(), ptr::null()) }
        == 0
    {
        // SAFETY: the context and cipher are live.
        unsafe { EVP_CIPHER_free(kekcipher) };
        return rv;
    }
    // SAFETY: `kekctx`/`wrap` are live.
    if unsafe { EVP_CIPHER_asn1_to_param(kekctx, (*wrap).parameter) } <= 0 {
        // SAFETY: the context and cipher are live.
        unsafe { EVP_CIPHER_free(kekcipher) };
        return rv;
    }

    // SAFETY: `kekctx` is live.
    let cipher_length = unsafe { EVP_CIPHER_CTX_get_key_length(kekctx) } as u32;
    // SAFETY: `kek_length` is live per the item arm.
    if cipher_length != unsafe { *kek_length } {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            super::cms_lib::raise_cms(
                54,
                c"kem_cms_decrypt",
                crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
            )
        };
        // SAFETY: the context and cipher are live.
        unsafe { EVP_CIPHER_free(kekcipher) };
        return rv;
    }

    rv = 1;
    // SAFETY: `kekcipher` is NULL or owned.
    unsafe { EVP_CIPHER_free(kekcipher) };
    rv
}

/// `int kem_cms_encrypt(CMS_RecipientInfo *ri)` — `cms_kem.c:64-152`.
///
/// # Safety
/// `ri` is live.
unsafe fn kem_cms_encrypt(ri: *mut CmsRecipientInfo) -> c_int {
    let mut kek_length: *mut u32 = ptr::null_mut();
    let mut wrap: *mut X509Algor = ptr::null_mut();
    let mut x509_algor: *mut X509Algor = ptr::null_mut();
    let mut kdf_obj: *const Asn1Object = ptr::null();
    let mut kemri_x509_algor = [0u8; OSSL_MAX_ALGORITHM_ID_SIZE];
    let mut rv = 0;

    // SAFETY: `ri` is live.
    if unsafe {
        super::cms_kemri::ossl_cms_RecipientInfo_kemri_get0_alg(ri, &mut kek_length, &mut wrap)
    } == 0
    {
        return rv;
    }

    // SAFETY: `ri` is live.
    let kdf = unsafe { super::cms_kemri::CMS_RecipientInfo_kemri_get0_kdf_alg(ri) };
    if kdf.is_null() {
        return rv;
    }

    // SAFETY: `ri` is live.
    let pctx = unsafe { super::cms_env::CMS_RecipientInfo_get0_pkey_ctx(ri) };
    if pctx.is_null() {
        return rv;
    }

    // SAFETY: `pctx` is live.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(pctx) };
    if pkey.is_null() {
        return rv;
    }

    // SAFETY: `pkey` is live.
    let security_bits = unsafe { EVP_PKEY_get_security_bits(pkey) };
    if security_bits == 0 {
        return rv;
    }

    // SAFETY: `kdf` is live; the slots are this frame's.
    unsafe { X509_ALGOR_get0(&mut kdf_obj, ptr::null_mut(), ptr::null_mut(), kdf) };
    // SAFETY: `kdf_obj` is live.
    if kdf_obj.is_null() || unsafe { OBJ_obj2nid(kdf_obj) } == NID_undef {
        // If the KDF OID hasn't already been set, query the provider for a default.
        let mut params: [OsslParam; 2] = [OSSL_PARAM_construct_end(), OSSL_PARAM_construct_end()];
        // SAFETY: the constructor writes a descriptor into the caller's slot.
        params[0] = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM,
                kemri_x509_algor.as_mut_ptr().cast(),
                kemri_x509_algor.len(),
            )
        };
        // SAFETY: `pkey` is live; `params` is terminated.
        if unsafe { EVP_PKEY_get_params(pkey, params.as_mut_ptr()) } == 0 {
            return rv;
        }
        // SAFETY: `params[0]` is live.
        if unsafe { OSSL_PARAM_modified(&params[0]) } != 0 {
            let p = kemri_x509_algor.as_ptr();
            let mut pp = p;
            // SAFETY: `pp` is readable for `return_size`; the item answers a fresh identifier.
            x509_algor = unsafe {
                d2i_X509_ALGOR(ptr::null_mut(), &mut pp, params[0].return_size as c_long)
            };
            if x509_algor.is_null() {
                return rv;
            }
            // SAFETY: `kdf`/`x509_algor` are live.
            if unsafe { X509_ALGOR_copy(kdf, x509_algor) } == 0 {
                // SAFETY: `x509_algor` is owned here.
                unsafe { X509_ALGOR_free(x509_algor) };
                return rv;
            }
        } else {
            // SAFETY: `kdf` is live.
            if unsafe {
                X509_ALGOR_set0(
                    kdf,
                    OBJ_nid2obj(NID_HKDF_SHA256),
                    V_ASN1_UNDEF,
                    ptr::null_mut(),
                )
            } == 0
            {
                // SAFETY: `x509_algor` is NULL or owned.
                unsafe { X509_ALGOR_free(x509_algor) };
                return 0;
            }
        }
    }

    // Get wrap NID.
    // SAFETY: `ri` is live.
    let kekctx = unsafe { super::cms_kemri::CMS_RecipientInfo_kemri_get0_ctx(ri) };
    if kekctx.is_null() {
        // SAFETY: `x509_algor` is NULL or owned.
        unsafe { X509_ALGOR_free(x509_algor) };
        return rv;
    }
    // SAFETY: `kekctx` is live.
    let keylen = unsafe { EVP_CIPHER_CTX_get_key_length(kekctx) };
    // SAFETY: `kek_length` is live per the item arm.
    unsafe { *kek_length = keylen as u32 };
    // SAFETY: `kekctx` is live.
    let wrap_nid = unsafe { EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(kekctx)) };

    // Package wrap algorithm in an AlgorithmIdentifier.
    // SAFETY: `wrap` is live.
    unsafe { ASN1_OBJECT_free((*wrap).algorithm) };
    // SAFETY: `wrap` is live.
    unsafe { ASN1_TYPE_free((*wrap).parameter) };
    // SAFETY: `wrap` is live.
    unsafe { (*wrap).algorithm = OBJ_nid2obj(wrap_nid) };
    // SAFETY: the allocator answers a fresh type.
    unsafe { (*wrap).parameter = ASN1_TYPE_new() };
    // SAFETY: `wrap` is live.
    if unsafe { (*wrap).parameter }.is_null() {
        // SAFETY: `x509_algor` is NULL or owned.
        unsafe { X509_ALGOR_free(x509_algor) };
        return rv;
    }
    // SAFETY: `kekctx`/`wrap` are live.
    if unsafe { EVP_CIPHER_param_to_asn1(kekctx, (*wrap).parameter) } <= 0 {
        // SAFETY: the parameter is owned here.
        unsafe { ASN1_TYPE_free((*wrap).parameter) };
        // SAFETY: `wrap` is live.
        unsafe { (*wrap).parameter = ptr::null_mut() };
        // SAFETY: `x509_algor` is NULL or owned.
        unsafe { X509_ALGOR_free(x509_algor) };
        return rv;
    }
    // SAFETY: `wrap` is live.
    if unsafe { ASN1_TYPE_get((*wrap).parameter) } == NID_undef {
        // SAFETY: the parameter is owned here.
        unsafe { ASN1_TYPE_free((*wrap).parameter) };
        // SAFETY: `wrap` is live.
        unsafe { (*wrap).parameter = ptr::null_mut() };
    }

    rv = 1;
    // SAFETY: `x509_algor` is NULL or owned.
    unsafe { X509_ALGOR_free(x509_algor) };
    rv
}

/// `int ossl_cms_kem_envelope(CMS_RecipientInfo *ri, int decrypt)` — `cms_kem.c:154-166`.
///
/// # Safety
/// `ri` is live.
pub(crate) unsafe extern "C" fn ossl_cms_kem_envelope(
    ri: *mut CmsRecipientInfo,
    decrypt: c_int,
) -> c_int {
    if decrypt == 1 {
        // SAFETY: `ri` is live.
        return unsafe { kem_cms_decrypt(ri) };
    }
    if decrypt == 0 {
        // SAFETY: `ri` is live.
        return unsafe { kem_cms_encrypt(ri) };
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        super::cms_lib::raise_cms(
            164,
            c"ossl_cms_kem_envelope",
            crate::runtime::err::err_reasons::CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE,
        )
    };
    0
}
