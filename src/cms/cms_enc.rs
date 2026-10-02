//! `crypto/cms/cms_enc.c` — the `CMS EncryptedData` content and its session-key setup.
//! Phase 12.3.
//!
//! [`CMS_EncryptedData_set1_key`] and its two helpers land here. The BIO arm
//! (`ossl_cms_EncryptedContent_init_bio`) is withheld with the key-transport and content-cipher
//! machinery of this subphase's PASS-2, so `CMS_dataInit` on an `EncryptedData` container
//! refuses rather than lying; the ledger names the export that is open.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]

use core::ffi::c_int;
use core::ptr;

use crate::evp::cipher::{EVP_CIPHER_get_flags, EvpCipher};
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{NID_pkcs7_data, NID_pkcs7_encrypted, OBJ_nid2obj, OBJ_obj2nid};

use super::cms_asn1::*;
use super::cms_lib::{ossl_cms_get0_cmsctx, raise_cms, ERR_R_ASN1_LIB};

/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h`.
const EVP_CIPH_FLAG_AEAD_CIPHER: u64 = 0x20_0000;

/// `int ossl_cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec, const EVP_CIPHER *cipher,`
/// `const unsigned char *key, size_t keylen, const CMS_CTX *cms_ctx)` — `cms_enc.c:211-226`.
///
/// # Safety
/// `ec` is live; `cipher` NULL or live; `key` NULL or readable for `keylen`.
pub(crate) unsafe fn ossl_cms_EncryptedContent_init(
    ec: *mut CmsEncryptedContentInfo,
    cipher: *const EvpCipher,
    key: *const u8,
    keylen: usize,
    _cms_ctx: *const CmsCtx,
) -> c_int {
    // SAFETY: `ec` is live.
    unsafe {
        (*ec).cipher = cipher.cast();
        if !key.is_null() {
            let k = CRYPTO_malloc(keylen, c"cms_enc.c".as_ptr(), 218);
            if k.is_null() {
                return 0;
            }
            ptr::copy_nonoverlapping(key, k.cast::<u8>(), keylen);
            (*ec).key = k.cast();
        }
        (*ec).keylen = keylen;
        if !cipher.is_null() {
            (*ec).content_type = OBJ_nid2obj(NID_pkcs7_data);
        }
    }
    1
}

/// `int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,`
/// `const unsigned char *key, size_t keylen)` — `cms_enc.c:228-260`.
///
/// # Safety
/// `cms` is live; `ciph` NULL or live; `key` readable for `keylen`.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EncryptedData_set1_key(
    cms: *mut CmsContentInfo,
    ciph: *const EvpCipher,
    key: *const u8,
    keylen: usize,
) -> c_int {
    if key.is_null() || keylen == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                234,
                c"CMS_EncryptedData_set1_key",
                crate::runtime::err::err_reasons::CMS_R_NO_KEY,
            )
        };
        return 0;
    }
    // SAFETY: `cms` is live; `ciph` is NULL or live.
    unsafe {
        if !ciph.is_null() {
            if EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
                raise_cms(
                    239,
                    c"CMS_EncryptedData_set1_key",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                );
                return 0;
            }
            let ed = (*cms).d.cast::<CmsEncryptedData>();
            if !ed.is_null() {
                m_asn1_free(ed.cast(), cms_encrypteddata_it());
                (*cms).d = ptr::null_mut();
            }
            let ed = m_asn1_new(cms_encrypteddata_it()).cast::<CmsEncryptedData>();
            if ed.is_null() {
                raise_cms(248, c"CMS_EncryptedData_set1_key", ERR_R_ASN1_LIB);
                return 0;
            }
            (*cms).d = ed.cast();
            (*cms).content_type = OBJ_nid2obj(NID_pkcs7_encrypted);
            (*ed).version = 0;
        } else if OBJ_obj2nid((*cms).content_type) != NID_pkcs7_encrypted {
            raise_cms(
                254,
                c"CMS_EncryptedData_set1_key",
                crate::runtime::err::err_reasons::CMS_R_NOT_ENCRYPTED_DATA,
            );
            return 0;
        }
        let ed = (*cms).d.cast::<CmsEncryptedData>();
        let ec = (*ed).encrypted_content_info;
        ossl_cms_EncryptedContent_init(ec, ciph, key, keylen, ossl_cms_get0_cmsctx(cms))
    }
}

/// `BIO *ossl_cms_EncryptedData_init_bio(const CMS_ContentInfo *cms)` — `cms_enc.c:262-269`.
///
/// The BIO arm is withheld with the content-cipher machinery of this subphase's PASS-2.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EncryptedData_init_bio(
    cms: *const CmsContentInfo,
) -> *mut Bio {
    let _ = cms;
    ptr::null_mut()
}
