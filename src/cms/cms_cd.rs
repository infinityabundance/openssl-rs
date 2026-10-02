//! `crypto/cms/cms_cd.c` — the `CompressedData` content builder. Phase 12.3.
//!
//! The unit defines no export the atlas attributes to this stratum; it is pulled forward because
//! `cms_lib.c`'s `CMS_dataInit` reaches its helper. It is withheld with the compression
//! machinery of this subphase's PASS-2 and refuses rather than lie.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(unused_assignments)]

use core::ptr;

use crate::runtime::bio::Bio;

use super::cms_asn1::CmsContentInfo;

/// `BIO *ossl_cms_CompressedData_init_bio(const CMS_ContentInfo *cms)` — `cms_cd.c`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_CompressedData_init_bio(
    _cms: *const CmsContentInfo,
) -> *mut Bio {
    ptr::null_mut()
}
