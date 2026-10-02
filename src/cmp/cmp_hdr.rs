//! `crypto/cmp/cmp_hdr.c` — the CMP `PKIHeader` accessors. Phase 12.4 (the three `OSSL_CMP_HDR_*`
//! getters; the header builders are reached by the message engine and land with it).
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::c_int;
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::cmp::cmp_asn::CmpPkiHeader;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::OpenSslStack;

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_hdr.c";

/// `ERR_LIB_CMP`.
const ERR_LIB_CMP: c_int = 58;

const fn cmp_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: FILE,
        line,
        func,
        lib: ERR_LIB_CMP,
        reason,
        dynamic_reason: false,
    }
}

/// `ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_transactionID(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:43-50`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_transactionID(
    hdr: *const CmpPkiHeader,
) -> *mut Asn1String {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(46, c"OSSL_CMP_HDR_get0_transactionID", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).transaction_id }
}

/// `ASN1_OCTET_STRING *OSSL_CMP_HDR_get0_recipNonce(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:59-66`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_recipNonce(hdr: *const CmpPkiHeader) -> *mut Asn1String {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(62, c"OSSL_CMP_HDR_get0_recipNonce", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).recip_nonce }
}

/// `STACK_OF(OSSL_CMP_ITAV) *OSSL_CMP_HDR_get0_geninfo_ITAVs(const OSSL_CMP_PKIHEADER *hdr)` —
/// `cmp_hdr.c:68-76`.
///
/// # Safety
/// `hdr` is NULL or a live `OSSL_CMP_PKIHEADER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_HDR_get0_geninfo_ITAVs(
    hdr: *const CmpPkiHeader,
) -> *mut OpenSslStack {
    if hdr.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&cmp_site(72, c"OSSL_CMP_HDR_get0_geninfo_ITAVs", 103)) };
        return ptr::null_mut();
    }
    // SAFETY: `hdr` is live.
    unsafe { (*hdr).general_info }
}
