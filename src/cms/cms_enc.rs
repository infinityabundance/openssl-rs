//! `crypto/cms/cms_enc.c` — the `CMS EncryptedData` content and its session-key setup.
//! Phase 12.3b.
//!
//! [`CMS_EncryptedData_set1_key`], [`ossl_cms_EncryptedContent_init`] and the BIO arm
//! [`ossl_cms_EncryptedContent_init_bio`] land here; the last is what `cms_env.rs` and
//! `cms_lib.rs`'s `CMS_dataInit` reach for the content cipher.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_int, c_uchar, c_ulong};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_free, ASN1_TYPE_new};
use crate::asn1::layout::V_ASN1_UNDEF;
use crate::evp::bio_enc::BIO_f_cipher;
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get0_name, EVP_CIPHER_get_flags,
    EVP_CIPHER_get_type, EvpCipher,
};
use crate::evp::cipher_ctx::{
    evp_cipher_asn1_to_param_ex, evp_cipher_param_to_asn1_ex, EVP_CIPHER_CTX_ctrl,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_tag_length, EVP_CIPHER_CTX_rand_key, EVP_CIPHER_CTX_set_key_length,
    EVP_CipherInit_ex, EvpCipherAeadAsn1Params, EvpCipherCtx,
};
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::rand::rand_lib::RAND_bytes_ex;
use crate::runtime::bio::{BIO_ctrl, BIO_free, BIO_new, Bio, BIO_C_GET_CIPHER_CTX};
use crate::runtime::err::{ERR_clear_error, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{
    NID_pkcs7_data, NID_pkcs7_encrypted, NID_undef, OBJ_nid2obj, OBJ_nid2sn, OBJ_obj2nid,
};

use super::cms_asn1::*;
use super::cms_lib::{
    ossl_cms_ctx_get0_libctx, ossl_cms_ctx_get0_propq, ossl_cms_get0_cmsctx, raise_cms,
    ERR_R_ASN1_LIB, ERR_R_EVP_LIB,
};

/// `EVP_CIPH_FLAG_AEAD_CIPHER` — `include/openssl/evp.h:531`.
const EVP_CIPH_FLAG_AEAD_CIPHER: c_ulong = 0x20_0000;
/// `EVP_MAX_IV_LENGTH` — `include/openssl/evp.h:36`.
const EVP_MAX_IV_LENGTH: usize = 16;
/// `EVP_CTRL_AEAD_SET_TAG` — `include/openssl/evp.h`.
const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;
/// `ERR_R_BIO_LIB` — `include/openssl/err.h`.
const ERR_R_BIO_LIB: c_int = 524290;

/// `BIO_get_cipher_ctx(BIO *, EVP_CIPHER_CTX **)` — `BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx)`.
///
/// # Safety
/// `b` is a live cipher BIO; `pctx` is writable.
unsafe fn bio_get_cipher_ctx(b: *mut Bio, pctx: *mut *mut EvpCipherCtx) -> c_int {
    // SAFETY: per this function's contract.
    unsafe { BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, pctx.cast()) as c_int }
}

/// `BIO *ossl_cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec,`
/// `const CMS_CTX *cms_ctx, int auth)` — `cms_enc.c:25-209`.
///
/// # Safety
/// `ec` is live; `cms_ctx` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EncryptedContent_init_bio(
    ec: *mut CmsEncryptedContentInfo,
    cms_ctx: *const CmsCtx,
    auth: c_int,
) -> *mut Bio {
    let mut fetched_ciph: *mut EvpCipher = ptr::null_mut();
    let mut cipher: *const EvpCipher = ptr::null();
    let mut aparams = EvpCipherAeadAsn1Params {
        tag_len: 0,
        iv: [0u8; EVP_MAX_IV_LENGTH],
        iv_len: 0,
    };
    let mut iv = [0u8; EVP_MAX_IV_LENGTH];
    let mut piv: *mut c_uchar = ptr::null_mut();
    let mut tkey: *mut c_uchar = ptr::null_mut();
    let mut len = 0;
    let mut ivlen: c_int = 0;
    let mut tkeylen = 0usize;
    let mut ok = 0;
    let mut keep_key = 0;

    // SAFETY: `ec` is live.
    let calg = unsafe { (*ec).content_encryption_algorithm };
    // SAFETY: `cms_ctx` is live.
    let libctx = unsafe { ossl_cms_ctx_get0_libctx(cms_ctx) };
    // SAFETY: `cms_ctx` is live.
    let propq = unsafe { ossl_cms_ctx_get0_propq(cms_ctx) };

    // SAFETY: `ec` is live.
    let enc = c_int::from(!unsafe { (*ec).cipher }.is_null());

    // SAFETY: the allocator answers a fresh cipher BIO.
    let b = unsafe { BIO_new(BIO_f_cipher()) };
    if b.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(48, c"ossl_cms_EncryptedContent_init_bio", ERR_R_BIO_LIB) };
        return ptr::null_mut();
    }

    let mut ctx: *mut EvpCipherCtx = ptr::null_mut();
    // SAFETY: `b` is live; `ctx` is this frame's slot.
    unsafe { bio_get_cipher_ctx(b, &mut ctx) };

    // SAFETY: the site is a compile-time constant.
    ERR_set_mark();
    if enc != 0 {
        // SAFETY: `ec` is live.
        cipher = unsafe { (*ec).cipher.cast() };
        // If not keeping key set cipher to NULL so subsequent calls decrypt.
        // SAFETY: `ec` is live.
        if !unsafe { (*ec).key }.is_null() {
            // SAFETY: `ec` is live.
            unsafe { (*ec).cipher = ptr::null() };
        }
    } else {
        // SAFETY: `calg` is live.
        let aoid = unsafe { (*calg).algorithm };
        // SAFETY: `aoid` is live; the lookup is the macro expansion.
        cipher = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(aoid))) };
    }
    if !cipher.is_null() {
        // SAFETY: `cipher` is live.
        fetched_ciph = unsafe { EVP_CIPHER_fetch(libctx, EVP_CIPHER_get0_name(cipher), propq) };
        if !fetched_ciph.is_null() {
            cipher = fetched_ciph;
        }
    }
    if cipher.is_null() {
        // SAFETY: as above.
        ERR_clear_last_mark();
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                73,
                c"ossl_cms_EncryptedContent_init_bio",
                crate::runtime::err::err_reasons::CMS_R_UNKNOWN_CIPHER,
            )
        };
        // SAFETY: `fetched_ciph` is NULL or owned.
        unsafe {
            EVP_CIPHER_free(fetched_ciph);
            BIO_free(b);
        }
        return ptr::null_mut();
    }
    // SAFETY: the queue was marked above.
    ERR_pop_to_mark();

    // SAFETY: `ctx`/`cipher` are live.
    if unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), enc) }
        <= 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                79,
                c"ossl_cms_EncryptedContent_init_bio",
                crate::runtime::err::err_reasons::CMS_R_CIPHER_INITIALISATION_ERROR,
            )
        };
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(fetched_ciph);
            BIO_free(b);
        }
        return ptr::null_mut();
    }

    if enc != 0 {
        // SAFETY: `ctx` is live.
        let et = unsafe { EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(ctx)) };
        // SAFETY: `calg` is live.
        unsafe { (*calg).algorithm = OBJ_nid2obj(et) };
        // SAFETY: `calg` is live.
        if unsafe { (*calg).algorithm }.is_null()
            // SAFETY: `calg` is live.
            || unsafe { (*(*calg).algorithm).nid } == NID_undef
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    86,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                )
            };
            // SAFETY: the context and cipher are live.
            unsafe {
                EVP_CIPHER_free(fetched_ciph);
                BIO_free(b);
            }
            return ptr::null_mut();
        }
        // Generate a random IV if we need one.
        // SAFETY: `ctx` is live.
        ivlen = unsafe { EVP_CIPHER_CTX_get_iv_length(ctx) };
        if ivlen < 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(92, c"ossl_cms_EncryptedContent_init_bio", ERR_R_EVP_LIB) };
            // SAFETY: the context and cipher are live.
            unsafe {
                EVP_CIPHER_free(fetched_ciph);
                BIO_free(b);
            }
            return ptr::null_mut();
        }

        if ivlen > 0 {
            // SAFETY: `iv` is writable.
            if unsafe { RAND_bytes_ex(libctx, iv.as_mut_ptr(), ivlen as usize, 0) } <= 0 {
                // SAFETY: the context and cipher are live.
                unsafe {
                    EVP_CIPHER_free(fetched_ciph);
                    BIO_free(b);
                }
                return ptr::null_mut();
            }
            piv = iv.as_mut_ptr();
        }
    } else {
        // SAFETY: `ctx`/`calg` are live.
        if unsafe { evp_cipher_asn1_to_param_ex(ctx, (*calg).parameter, &mut aparams) } <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    103,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                )
            };
            // SAFETY: the context and cipher are live.
            unsafe {
                EVP_CIPHER_free(fetched_ciph);
                BIO_free(b);
            }
            return ptr::null_mut();
        }
        // SAFETY: `cipher` is live.
        if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
            if auth == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        108,
                        c"ossl_cms_EncryptedContent_init_bio",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_IN_ENVELOPED_DATA,
                    )
                };
                // SAFETY: the context and cipher are live.
                unsafe {
                    EVP_CIPHER_free(fetched_ciph);
                    BIO_free(b);
                }
                return ptr::null_mut();
            }
            piv = aparams.iv.as_mut_ptr();

            // SAFETY: `ec` is live.
            let taglen = unsafe { (*ec).taglen };
            // SAFETY: `ec` is live.
            let tag = unsafe { (*ec).tag };
            if !(4usize..=16).contains(&taglen)
                // SAFETY: `ctx` is live; `tag` is readable for `taglen`.
                || unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen as c_int, tag.cast()) } <= 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        115,
                        c"ossl_cms_EncryptedContent_init_bio",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_AEAD_SET_TAG_ERROR,
                    )
                };
                // SAFETY: the context and cipher are live.
                unsafe {
                    EVP_CIPHER_free(fetched_ciph);
                    BIO_free(b);
                }
                return ptr::null_mut();
            }
        } else if auth != 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    119,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
                )
            };
            // SAFETY: the context and cipher are live.
            unsafe {
                EVP_CIPHER_free(fetched_ciph);
                BIO_free(b);
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `ctx` is live.
    len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if len <= 0 {
        // SAFETY: the context and cipher are live.
        unsafe {
            EVP_CIPHER_free(fetched_ciph);
            BIO_free(b);
        }
        return ptr::null_mut();
    }
    tkeylen = len as usize;

    'body: {
        // Generate random session key.
        // SAFETY: `ec` is live.
        if enc == 0 || unsafe { (*ec).key }.is_null() {
            // SAFETY: `tkeylen > 0`.
            tkey = CRYPTO_malloc(tkeylen, c"cms_enc.c".as_ptr(), 130).cast::<c_uchar>();
            if tkey.is_null() {
                break 'body;
            }
            // SAFETY: `ctx` is live; `tkey` is writable.
            if unsafe { EVP_CIPHER_CTX_rand_key(ctx, tkey) } <= 0 {
                break 'body;
            }
        }

        // SAFETY: `ec` is live.
        if unsafe { (*ec).key }.is_null() {
            // SAFETY: `ec` is live.
            unsafe {
                (*ec).key = tkey;
                (*ec).keylen = tkeylen;
            }
            tkey = ptr::null_mut();
            if enc != 0 {
                keep_key = 1;
            } else {
                // SAFETY: the queue is this thread's.
                ERR_clear_error();
            }
        }

        // SAFETY: `ec` is live.
        if unsafe { (*ec).keylen } != tkeylen {
            // If necessary set key length.
            // SAFETY: `ctx` is live.
            let klen = unsafe { (*ec).keylen };
            // SAFETY: the context and cipher are live.
            if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, klen as c_int) } <= 0 {
                // SAFETY: `ec` is live.
                if enc != 0 || unsafe { (*ec).debug } != 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe {
                        raise_cms(
                            155,
                            c"ossl_cms_EncryptedContent_init_bio",
                            crate::runtime::err::err_reasons::CMS_R_INVALID_KEY_LENGTH,
                        )
                    };
                    break 'body;
                } else {
                    // Use random key.
                    // SAFETY: `ec` is live.
                    unsafe {
                        super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
                        (*ec).key = tkey;
                        (*ec).keylen = tkeylen;
                    }
                    tkey = ptr::null_mut();
                    // SAFETY: the queue is this thread's.
                    ERR_clear_error();
                }
            }
        }

        // SAFETY: `ctx` is live; `piv` is NULL or readable.
        if unsafe { EVP_CipherInit_ex(ctx, ptr::null(), ptr::null_mut(), (*ec).key, piv, enc) } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    169,
                    c"ossl_cms_EncryptedContent_init_bio",
                    crate::runtime::err::err_reasons::CMS_R_CIPHER_INITIALISATION_ERROR,
                )
            };
            break 'body;
        }
        if enc != 0 {
            // SAFETY: `calg` is live.
            unsafe { (*calg).parameter = ASN1_TYPE_new() };
            // SAFETY: `calg` is live.
            if unsafe { (*calg).parameter }.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(175, c"ossl_cms_EncryptedContent_init_bio", ERR_R_ASN1_LIB) };
                break 'body;
            }
            // SAFETY: `cipher` is live.
            if unsafe { EVP_CIPHER_get_flags(cipher) } & EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
                // SAFETY: `piv` is readable for `ivlen`.
                unsafe { ptr::copy_nonoverlapping(piv, aparams.iv.as_mut_ptr(), ivlen as usize) };
                aparams.iv_len = ivlen as u32;
                // SAFETY: `ctx` is live.
                aparams.tag_len = unsafe { EVP_CIPHER_CTX_get_tag_length(ctx) } as u32;
                if aparams.tag_len == 0 {
                    break 'body;
                }
            }

            // SAFETY: `ctx`/`calg` are live.
            if unsafe { evp_cipher_param_to_asn1_ex(ctx, (*calg).parameter, &mut aparams) } <= 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        187,
                        c"ossl_cms_EncryptedContent_init_bio",
                        crate::runtime::err::err_reasons::CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR,
                    )
                };
                break 'body;
            }
            // If parameter type not set omit parameter.
            // SAFETY: `calg` is live.
            if unsafe { (*(*calg).parameter).type_ } == V_ASN1_UNDEF {
                // SAFETY: the parameter is owned here.
                unsafe { ASN1_TYPE_free((*calg).parameter) };
                // SAFETY: `calg` is live.
                unsafe { (*calg).parameter = ptr::null_mut() };
            }
        }
        ok = 1;
    }

    // SAFETY: each is NULL or owned.
    unsafe {
        EVP_CIPHER_free(fetched_ciph);
        if keep_key == 0 || ok == 0 {
            super::cms_asn1::OPENSSL_clear_free((*ec).key, (*ec).keylen);
            (*ec).key = ptr::null_mut();
        }
        super::cms_asn1::OPENSSL_clear_free(tkey, tkeylen);
        if ok != 0 {
            return b;
        }
        BIO_free(b);
    }
    ptr::null_mut()
}

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
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EncryptedData_init_bio(
    cms: *const CmsContentInfo,
) -> *mut Bio {
    // SAFETY: `cms` is live.
    let enc = unsafe { (*cms).d.cast::<CmsEncryptedData>() };
    // SAFETY: `enc` is live.
    if !unsafe { (*(*enc).encrypted_content_info).cipher }.is_null()
        // SAFETY: `enc` is live.
        && !unsafe { (*enc).unprotected_attrs }.is_null()
    {
        // SAFETY: `enc` is live.
        unsafe { (*enc).version = 2 };
    }
    // SAFETY: `cms` is live.
    unsafe {
        ossl_cms_EncryptedContent_init_bio(
            (*enc).encrypted_content_info,
            ossl_cms_get0_cmsctx(cms),
            0,
        )
    }
}
