//! `crypto/cms/cms_sd.c` — the `SignedData` signer-info engine. Phase 12.3.
//!
//! The three helpers `cms_lib.rs` reaches (`ossl_cms_SignerInfos_set_cmsctx`,
//! `ossl_cms_SignedData_init_bio`, `ossl_cms_SignedData_final`) land here; the exported
//! signer-infrastructure surface is withheld with this subphase's PASS-2 and named open in the
//! ledger. The two BIO helpers refuse rather than lie.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::runtime::bio::Bio;

use super::cms_asn1::CmsContentInfo;

/// `void ossl_cms_SignerInfos_set_cmsctx(CMS_ContentInfo *cms)` — `cms_sd.c`.
///
/// # Safety
/// `cms` is NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_SignerInfos_set_cmsctx(_cms: *mut CmsContentInfo) {}

/// `BIO *ossl_cms_SignedData_init_bio(const CMS_ContentInfo *cms)` — `cms_sd.c`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_SignedData_init_bio(
    _cms: *const CmsContentInfo,
) -> *mut Bio {
    ptr::null_mut()
}

/// `int ossl_cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain, const unsigned char *precomp_md,`
/// `unsigned int precomp_mdlen)` — `cms_sd.c`.
///
/// # Safety
/// `cms`/`chain` are live.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe extern "C" fn ossl_cms_SignedData_final(
    _cms: *mut CmsContentInfo,
    _chain: *mut Bio,
    _precomp_md: *const c_uchar,
    _precomp_mdlen: u32,
) -> c_int {
    0
}
