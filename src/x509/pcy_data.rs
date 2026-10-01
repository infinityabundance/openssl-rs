//! `crypto/x509/pcy_data.c` — the policy-data constructor and destructor. Phase 11.2.
//!
//! `crypto/x509/pcy_data.c` is 81 lines and publishes two internal functions, both of which
//! [`X509_policy_check`](crate::x509::pcy_tree::X509_policy_check)'s closure needs:
//!
//! * `ossl_policy_data_free` (`:18-28`) — releases the policy OID, the qualifier set unless it is
//!   shared, and the expected-policy set, then the data. It was landed *privately* inside
//!   `pcy_tree.rs` when only `X509_policy_tree_free` reached it; now that the whole graph lands it
//!   is transcribed in its own unit and the private copy is gone.
//! * `ossl_policy_data_new` (`:38-80`) — builds data from either a `POLICYINFO` (`policy`) or a
//!   replacement OID (`cid`); the `id == NULL` arm takes ownership of `policy->policyid` and
//!   `policy->qualifiers`.
//!
//! Both are `ossl_*` internal symbols the authority's version script hides from `libcrypto.so`,
//! so no court can name either; they are reached only through [`X509_policy_check`], which the
//! Phase 11.2 court drives.
//!
//! ## The raise site
//!
//! `crypto/x509/pcy_data.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its one
//! `ERR_raise` coordinate (`:61`, the failed `sk_ASN1_OBJECT_new_null` expected-policy set) is
//! **declared locally** in the `err_sites::ErrSite` shape, as `v3_cpols.rs` does. The reason,
//! `ERR_R_CRYPTO_LIB`, is read from `include/openssl/err.h.in`.
//!
//! [`X509_policy_check`]: crate::x509::pcy_tree::X509_policy_check
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_void, CStr};

use crate::asn1::prim::ASN1_OBJECT_free;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_zalloc};
use crate::runtime::obj::{Asn1Object, OBJ_dup};
use crate::runtime::stack::{OPENSSL_sk_new_null, OPENSSL_sk_pop_free};
use crate::x509::pcy_lib::X509PolicyData;
use crate::x509::v3_cpols::{POLICYQUALINFO_free, PolicyInfo, PolicyQualInfo};

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/pcy_data.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in`.
const ERR_LIB_X509V3: c_int = 34;

/// `POLICY_DATA_FLAG_CRITICAL` — `crypto/x509/pcy_local.h:61`.
const POLICY_DATA_FLAG_CRITICAL: c_int = 0x10;
/// `POLICY_DATA_FLAG_SHARED_QUALIFIERS` — `crypto/x509/pcy_local.h:53`, `0x4`.
const POLICY_DATA_FLAG_SHARED_QUALIFIERS: c_int = 0x4;

/// One `pcy_data.c` raise coordinate, declared locally (see the module doc).
const fn pcy_data_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/pcy_data.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `ossl_policy_data_new`'s failed `sk_ASN1_OBJECT_new_null` at `pcy_data.c:61`.
const PCY_DATA_61: ErrSite = pcy_data_site(61, c"ossl_policy_data_new", ERR_R_CRYPTO_LIB);

/// The `POLICYQUALINFO_free` element thunk for `sk_POLICYQUALINFO_pop_free`.
///
/// # Safety
///
/// `q` must be NULL or a live `POLICYQUALINFO`.
unsafe extern "C" fn policy_qualinfo_free_void(q: *mut c_void) {
    // SAFETY: `q` is NULL or live per the contract.
    unsafe { POLICYQUALINFO_free(q.cast::<PolicyQualInfo>()) };
}

/// The `ASN1_OBJECT_free` element thunk for `sk_ASN1_OBJECT_pop_free`.
///
/// # Safety
///
/// `a` must be NULL or a live `ASN1_OBJECT`.
unsafe extern "C" fn asn1_object_free_void(a: *mut c_void) {
    // SAFETY: `a` is NULL or live per the contract.
    unsafe { ASN1_OBJECT_free(a.cast()) };
}

/// `void ossl_policy_data_free(X509_POLICY_DATA *data)` — `crypto/x509/pcy_data.c:18-28`.
///
/// Releases the policy OID, the qualifier set (unless it is shared) and the expected-policy set,
/// then the data. A NULL data is a no-op, matching the authority's first guard.
///
/// # Safety
///
/// `data` must be NULL or policy data this crate owns and has not already freed.
pub(crate) unsafe fn ossl_policy_data_free(data: *mut X509PolicyData) {
    if data.is_null() {
        return;
    }
    // SAFETY: `data` is live per the contract; each member is NULL or owned by it.
    unsafe {
        ASN1_OBJECT_free((*data).valid_policy);
        // Don't free qualifiers if shared (`:24`).
        if ((*data).flags & POLICY_DATA_FLAG_SHARED_QUALIFIERS as u32) == 0 {
            OPENSSL_sk_pop_free((*data).qualifier_set, Some(policy_qualinfo_free_void));
        }
        OPENSSL_sk_pop_free((*data).expected_policy_set, Some(asn1_object_free_void));
        CRYPTO_free(data.cast(), FILE.as_ptr(), 0);
    }
}

/// The `ossl_policy_data_free` element thunk for `sk_X509_POLICY_DATA_pop_free`.
///
/// # Safety
///
/// `d` must be NULL or policy data this crate owns and has not already freed.
pub(crate) unsafe extern "C" fn policy_data_free_void(d: *mut c_void) {
    // SAFETY: `d` is NULL or owned per the contract.
    unsafe { ossl_policy_data_free(d.cast()) };
}

/// `X509_POLICY_DATA *ossl_policy_data_new(POLICYINFO *policy, const ASN1_OBJECT *cid, int crit)`
/// — `crypto/x509/pcy_data.c:38-80`.
///
/// With `cid` non-NULL the OID is duplicated and `policy`'s own OID is left alone; with `cid`
/// NULL the OID and qualifier set are moved out of `policy`. `crit` sets
/// `POLICY_DATA_FLAG_CRITICAL`.
///
/// # Safety
///
/// `policy` is NULL or a live `POLICYINFO` this call may empty; `cid` is NULL or a live
/// `ASN1_OBJECT`. The returned data is owned by the caller.
pub(crate) unsafe fn ossl_policy_data_new(
    policy: *mut PolicyInfo,
    cid: *const Asn1Object,
    crit: c_int,
) -> *mut X509PolicyData {
    if policy.is_null() && cid.is_null() {
        return core::ptr::null_mut();
    }
    // `cid` is NULL or a live `ASN1_OBJECT` per the contract.
    let id = if !cid.is_null() {
        // SAFETY: `cid` is a live `ASN1_OBJECT` under this branch.
        let d = unsafe { OBJ_dup(cid) };
        if d.is_null() {
            return core::ptr::null_mut();
        }
        d
    } else {
        core::ptr::null_mut()
    };
    // A fresh block of the data's own size, written below before it is read.
    let ret = CRYPTO_zalloc(core::mem::size_of::<X509PolicyData>(), FILE.as_ptr(), 0)
        .cast::<X509PolicyData>();
    if ret.is_null() {
        // SAFETY: `id` is owned here.
        unsafe { ASN1_OBJECT_free(id) };
        return core::ptr::null_mut();
    }
    // SAFETY: `ret` is live and writable.
    unsafe { (*ret).expected_policy_set = OPENSSL_sk_new_null() };
    // SAFETY: `ret` is live.
    if unsafe { (*ret).expected_policy_set }.is_null() {
        // SAFETY: `ret` is owned here; `id` is owned here.
        unsafe {
            CRYPTO_free(ret.cast(), FILE.as_ptr(), 0);
            ASN1_OBJECT_free(id);
            raise_site(&PCY_DATA_61);
        }
        return core::ptr::null_mut();
    }

    if crit != 0 {
        // SAFETY: `ret` is live and writable.
        unsafe { (*ret).flags = POLICY_DATA_FLAG_CRITICAL as u32 };
    }

    if !id.is_null() {
        // SAFETY: `ret` is live and writable.
        unsafe { (*ret).valid_policy = id };
    } else {
        // SAFETY: `ret` and `policy` are live; the OID moves out of `policy` (`:71-73`).
        unsafe {
            (*ret).valid_policy = (*policy).policyid;
            (*policy).policyid = core::ptr::null_mut();
        }
    }

    if !policy.is_null() {
        // SAFETY: `ret` and `policy` are live; the qualifier set moves out of `policy` (`:75-78`).
        unsafe {
            (*ret).qualifier_set = (*policy).qualifiers;
            (*policy).qualifiers = core::ptr::null_mut();
        }
    }

    ret
}
