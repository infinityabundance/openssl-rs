//! `crypto/cms/cms_dd.c` — the `DigestedData` content builder. Phase 12.3.
//!
//! The unit defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_lib.c`'s `CMS_dataInit`/`ossl_cms_DataFinal` reach its two helpers. Both are withheld
//! with the digest-content machinery of this subphase's PASS-2 and refuse rather than lie.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]

use core::ffi::c_int;
use core::ptr;

use crate::runtime::bio::Bio;

use super::cms_asn1::CmsContentInfo;

/// `BIO *ossl_cms_DigestedData_init_bio(const CMS_ContentInfo *cms)` — `cms_dd.c`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_DigestedData_init_bio(
    _cms: *const CmsContentInfo,
) -> *mut Bio {
    ptr::null_mut()
}

/// `int ossl_cms_DigestedData_do_final(CMS_ContentInfo *cms, BIO *chain, int verify)` — `cms_dd.c`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_DigestedData_do_final(
    _cms: *mut CmsContentInfo,
    _chain: *mut Bio,
    _verify: c_int,
) -> c_int {
    0
}
