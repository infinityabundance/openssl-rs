//! `crypto/cms/cms_dd.c` — the `DigestedData` content builder. Phase 12.3c.
//!
//! The unit defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_lib.c`'s `CMS_dataInit`/`ossl_cms_DataFinal` reach its two helpers and `cms_smime.c`'s
//! `CMS_digest_create_ex` reaches [`ossl_cms_DigestedData_create`]. All three land here.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::asn1::string::ASN1_STRING_set;
use crate::asn1::x_algor::X509_ALGOR_set_md;
use crate::evp::digest::{EVP_DigestFinal_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, EvpMd};
use crate::runtime::bio::Bio;
use crate::runtime::obj::{NID_pkcs7_data, NID_pkcs7_digest, OBJ_nid2obj};

use super::cms_asn1::{cms_digesteddata_it, m_asn1_new, CmsContentInfo, CmsDigestedData};
use super::cms_lib::{
    ossl_cms_DigestAlgorithm_find_ctx, ossl_cms_DigestAlgorithm_init_bio, ossl_cms_get0_cmsctx,
    raise_cms, CMS_ContentInfo_free, CMS_ContentInfo_new_ex, ERR_R_EVP_LIB,
};

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:43`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `CMS_ContentInfo *ossl_cms_DigestedData_create(const EVP_MD *md, OSSL_LIB_CTX *libctx,`
/// `const char *propq)` — `cms_dd.c:20-49`.
///
/// # Safety
/// `md` is live; `propq` is NULL or a NUL-terminated string.
pub(crate) unsafe extern "C" fn ossl_cms_DigestedData_create(
    md: *const EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut CmsContentInfo {
    // SAFETY: the caller's contract.
    let cms = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if cms.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the item is static.
    let dd = unsafe { m_asn1_new(cms_digesteddata_it()) }.cast::<CmsDigestedData>();

    if dd.is_null() {
        // SAFETY: `cms` is owned here.
        unsafe { CMS_ContentInfo_free(cms) };
        return ptr::null_mut();
    }

    // SAFETY: `cms`/`dd` are live; the objects are statics.
    unsafe {
        (*cms).content_type = OBJ_nid2obj(NID_pkcs7_digest);
        (*cms).d = dd.cast();

        (*dd).version = 0;
        (*(*dd).encap_content_info).e_content_type = OBJ_nid2obj(NID_pkcs7_data);

        X509_ALGOR_set_md((*dd).digest_algorithm, md);
    }

    cms
}

/// `BIO *ossl_cms_DigestedData_init_bio(const CMS_ContentInfo *cms)` — `cms_dd.c:51-57`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_DigestedData_init_bio(
    cms: *const CmsContentInfo,
) -> *mut Bio {
    // SAFETY: `cms` is live.
    let dd = unsafe { (*cms).d.cast::<CmsDigestedData>() };

    // SAFETY: `cms`/`dd` are live.
    unsafe { ossl_cms_DigestAlgorithm_init_bio((*dd).digest_algorithm, ossl_cms_get0_cmsctx(cms)) }
}

/// `int ossl_cms_DigestedData_do_final(const CMS_ContentInfo *cms, BIO *chain, int verify)` —
/// `cms_dd.c:59-101`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_DigestedData_do_final(
    cms: *const CmsContentInfo,
    chain: *mut Bio,
    verify: c_int,
) -> c_int {
    // SAFETY: the digest context is a fresh allocation.
    let mctx = EVP_MD_CTX_new();
    let mut md = [0u8; EVP_MAX_MD_SIZE];
    let mut mdlen: c_uint = 0;
    let mut r = 0;

    if mctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(69, c"ossl_cms_DigestedData_do_final", ERR_R_EVP_LIB) };
        return r;
    }

    // SAFETY: `cms` is live.
    let dd = unsafe { (*cms).d.cast::<CmsDigestedData>() };

    'err: {
        // SAFETY: `mctx`/`chain`/`dd` are live.
        if unsafe { ossl_cms_DigestAlgorithm_find_ctx(mctx, chain, (*dd).digest_algorithm) } == 0 {
            break 'err;
        }

        // SAFETY: `mctx` is live; `md`/`mdlen` are this frame's.
        if unsafe { EVP_DigestFinal_ex(mctx, md.as_mut_ptr(), &mut mdlen) } <= 0 {
            break 'err;
        }

        if verify != 0 {
            // SAFETY: `dd` is live.
            if mdlen != unsafe { (*(*dd).digest).length } as c_uint {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        83,
                        c"ossl_cms_DigestedData_do_final",
                        crate::runtime::err::err_reasons::CMS_R_MESSAGEDIGEST_WRONG_LENGTH,
                    )
                };
                break 'err;
            }

            // SAFETY: `dd` is live; `md` is readable for `mdlen`, as is the digest's `data`.
            let equal = unsafe {
                core::slice::from_raw_parts(md.as_ptr(), mdlen as usize)
                    == core::slice::from_raw_parts((*(*dd).digest).data, mdlen as usize)
            };
            if equal {
                r = 1;
            } else {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        88,
                        c"ossl_cms_DigestedData_do_final",
                        crate::runtime::err::err_reasons::CMS_R_VERIFICATION_FAILURE,
                    )
                };
            }
        } else {
            // SAFETY: `dd` is live; `md` is readable for `mdlen`.
            if unsafe { ASN1_STRING_set((*dd).digest, md.as_ptr().cast(), mdlen as c_int) } == 0 {
                break 'err;
            }
            r = 1;
        }
    }

    // SAFETY: `mctx` is NULL or owned.
    unsafe { EVP_MD_CTX_free(mctx) };

    r
}
