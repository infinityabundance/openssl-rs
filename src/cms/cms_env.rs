//! `crypto/cms/cms_env.c` — the `EnvelopedData`/`AuthEnvelopedData` recipient-info engine.
//! Phase 12.3.
//!
//! The five helpers `cms_lib.rs` reaches (`ossl_cms_RecipientInfos_set_cmsctx` and the four
//! BIO init/final arms) land here; the exported recipient-info surface is withheld with this
//! subphase's PASS-2 and named open in the ledger. The BIO helpers refuse rather than lie.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]

use core::ptr;

use crate::runtime::bio::Bio;

use super::cms_asn1::CmsContentInfo;

/// `void ossl_cms_RecipientInfos_set_cmsctx(CMS_ContentInfo *cms)` — `cms_env.c`.
///
/// # Safety
/// `cms` is NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_RecipientInfos_set_cmsctx(_cms: *mut CmsContentInfo) {}

/// `BIO *ossl_cms_EnvelopedData_init_bio(const CMS_ContentInfo *cms)` — `cms_env.c`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_EnvelopedData_init_bio(
    _cms: *const CmsContentInfo,
) -> *mut Bio {
    ptr::null_mut()
}

/// `int ossl_cms_EnvelopedData_final(CMS_ContentInfo *cms, BIO *chain)` — `cms_env.c`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_EnvelopedData_final(
    _cms: *mut CmsContentInfo,
    _chain: *mut Bio,
) -> core::ffi::c_int {
    0
}

/// `BIO *ossl_cms_AuthEnvelopedData_init_bio(const CMS_ContentInfo *cms)` — `cms_env.c`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_AuthEnvelopedData_init_bio(
    _cms: *const CmsContentInfo,
) -> *mut Bio {
    ptr::null_mut()
}

/// `int ossl_cms_AuthEnvelopedData_final(CMS_ContentInfo *cms, BIO *chain)` — `cms_env.c`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_AuthEnvelopedData_final(
    _cms: *mut CmsContentInfo,
    _chain: *mut Bio,
) -> core::ffi::c_int {
    0
}
