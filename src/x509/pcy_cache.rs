//! `crypto/x509/pcy_cache.c` — the per-certificate policy cache. Phase 11.2.
//!
//! `crypto/x509/pcy_cache.c` is 226 lines. It builds and owns the `X509_POLICY_CACHE` that
//! hangs off `X509::policy_cache`, and [`X509_policy_check`]'s closure reaches it on every
//! non-trust-anchor certificate (`tree_init` and `tree_evaluate` both call `ossl_policy_cache_set`
//! and read the cache's `data`/`anyPolicy`/skip counters). It is transcribed whole:
//!
//! * `policy_cache_create` (`:26-81`) — decodes `CertificatePolicies` into
//!   `cache->data`/`cache->anyPolicy`, rejecting duplicate OIDs and anyPolicy repeats.
//! * `policy_cache_new` (`:83-178`) — the three `policy_constraints`, `certificate_policies`,
//!   `policy_mappings` and `inhibit_any_policy` decodes and the skip counters.
//! * `ossl_policy_cache_free` (`:180-187`) — the destructor.
//! * `ossl_policy_cache_set` (`:189-200`) — the lazy, lock-guarded builder.
//! * `ossl_policy_cache_find_data` (`:202-210`) — the sorted lookup by OID.
//! * `policy_data_cmp` (`:212-216`) and `policy_cache_set_int` (`:218-226`) — the file-local
//!   helpers.
//!
//! `ossl_policy_cache_free` is the one function in this unit with **no caller in this crate**:
//! the authority calls it only from `x509_cb` (`x_x509.c:49`, `:90`), whose release arms are
//! withheld in `x_x509.rs` and which this task may not edit. It is still transcribed — the unit
//! is the unit — and marked `#[allow(dead_code)]` with this sentence as its record; a later slice
//! that lands `x509_cb`'s `policy_cache` release will call it.
//!
//! ## `pcy_map.c`'s one function
//!
//! `policy_cache_new` needs `ossl_policy_cache_set_mapping`, the sole export of
//! `crypto/x509/pcy_map.c` (`:22-77`), which this stratum may not place in its own file. It is
//! transcribed here, at the head of the cache it mutates, with this paragraph as the record of
//! the file-boundary deviation: it is `pcy_map.c:22-77`, not `pcy_cache.c`.
//!
//! ## The raise sites
//!
//! `crypto/x509/pcy_cache.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its four
//! `ERR_raise` coordinates (`:38`, `:45`, `:61`, and `:74` via `ossl_policy_data_free`) are
//! **declared locally** in the `err_sites::ErrSite` shape, as `v3_cpols.rs` does. `pcy_map.c`
//! raises nothing. The reasons are read from `include/openssl/err.h.in`:
//! `ERR_R_CRYPTO_LIB` and `ERR_R_X509_LIB`.
//!
//! [`X509_policy_check`]: crate::x509::pcy_tree::X509_policy_check
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_void, CStr};

use crate::asn1::layout::{Asn1String, V_ASN1_NEG_INTEGER};
use crate::asn1::prim::ASN1_INTEGER_get;
use crate::asn1::string::ASN1_INTEGER_free;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    Asn1Object, NID_any_policy, NID_certificate_policies, NID_inhibit_any_policy,
    NID_policy_constraints, NID_policy_mappings, OBJ_cmp, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::x509::pcy_data::{ossl_policy_data_free, ossl_policy_data_new, policy_data_free_void};
use crate::x509::pcy_lib::{X509PolicyCache, X509PolicyData};
use crate::x509::v3_cpols::{POLICYINFO_free, PolicyInfo};
use crate::x509::v3_pcons::{POLICY_CONSTRAINTS_free, PolicyConstraints};
use crate::x509::v3_pmaps::{POLICY_MAPPING_free, PolicyMapping};
use crate::x509::x509_ext::X509_get_ext_d2i;
use crate::x509::x_x509::X509;

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/pcy_cache.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_X509_LIB` — `err.h`, `(ERR_LIB_X509 | ERR_RFLAG_COMMON)`.
const ERR_R_X509_LIB: c_int = 11 | (0x2 << 18);

/// `EXFLAG_INVALID_POLICY` — `include/openssl/x509v3.h:442`, `0x800`.
const EXFLAG_INVALID_POLICY: u32 = 0x800;

/// `POLICY_DATA_FLAG_MAPPED` — `crypto/x509/pcy_local.h:38`.
const POLICY_DATA_FLAG_MAPPED: u32 = 0x1;
/// `POLICY_DATA_FLAG_MAPPED_ANY` — `crypto/x509/pcy_local.h:45`.
const POLICY_DATA_FLAG_MAPPED_ANY: u32 = 0x2;
/// `POLICY_DATA_FLAG_SHARED_QUALIFIERS` — `crypto/x509/pcy_local.h:53`, `0x4`.
const POLICY_DATA_FLAG_SHARED_QUALIFIERS: u32 = 0x4;
/// `POLICY_DATA_FLAG_CRITICAL` — `crypto/x509/pcy_local.h:61`.
const POLICY_DATA_FLAG_CRITICAL: u32 = 0x10;

/// One `pcy_cache.c` raise coordinate, declared locally (see the module doc).
const fn pcy_cache_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/pcy_cache.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `policy_cache_create`'s failed `sk_X509_POLICY_DATA_new` at `pcy_cache.c:38`.
const PCY_CACHE_38: ErrSite = pcy_cache_site(38, c"policy_cache_create", ERR_R_CRYPTO_LIB);
/// `policy_cache_create`'s failed `ossl_policy_data_new` at `pcy_cache.c:45`.
const PCY_CACHE_45: ErrSite = pcy_cache_site(45, c"policy_cache_create", ERR_R_X509_LIB);
/// `policy_cache_create`'s failed `sk_X509_POLICY_DATA_push` at `pcy_cache.c:61`.
const PCY_CACHE_61: ErrSite = pcy_cache_site(61, c"policy_cache_create", ERR_R_CRYPTO_LIB);

/// The `POLICYINFO_free` element thunk for `sk_POLICYINFO_pop_free`.
///
/// # Safety
///
/// `p` must be NULL or a live `POLICYINFO`.
unsafe extern "C" fn policyinfo_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or live per the contract.
    unsafe { POLICYINFO_free(p.cast::<PolicyInfo>()) };
}

/// The `POLICY_MAPPING_free` element thunk for `sk_POLICY_MAPPING_pop_free`.
///
/// # Safety
///
/// `m` must be NULL or a live `POLICY_MAPPING`.
unsafe extern "C" fn policy_mapping_free_void(m: *mut c_void) {
    // SAFETY: `m` is NULL or live per the contract.
    unsafe { POLICY_MAPPING_free(m.cast::<PolicyMapping>()) };
}

/// `static int policy_data_cmp(const X509_POLICY_DATA *const *a, const X509_POLICY_DATA *const *b)`
/// — `crypto/x509/pcy_cache.c:212-216`.
///
/// # Safety
///
/// The stack comparator contract: `a` and `b` point at element slots holding live
/// `X509_POLICY_DATA *`.
unsafe extern "C" fn policy_data_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the comparator contract above; both elements are live data pointers.
    unsafe {
        let da = *(a.cast::<*const X509PolicyData>());
        let db = *(b.cast::<*const X509PolicyData>());
        OBJ_cmp((*da).valid_policy, (*db).valid_policy)
    }
}

/// `static int policy_cache_set_int(long *out, ASN1_INTEGER *value)` —
/// `crypto/x509/pcy_cache.c:218-226`.
///
/// A missing value leaves `*out` and answers 1; a negative value answers 0.
///
/// # Safety
///
/// `out` must be a writable `long`; `value` must be NULL or a live `ASN1_INTEGER`.
unsafe fn policy_cache_set_int(out: *mut c_long, value: *mut Asn1String) -> c_int {
    if value.is_null() {
        return 1;
    }
    // SAFETY: `value` is live per the contract.
    if unsafe { (*value).type_ } == V_ASN1_NEG_INTEGER {
        return 0;
    }
    // SAFETY: `value` is live; `ASN1_INTEGER_get` reads it. `out` is writable.
    unsafe { *out = ASN1_INTEGER_get(value) };
    1
}

/// `static int policy_cache_create(X509 *x, CERTIFICATEPOLICIES *policies, int crit)` —
/// `crypto/x509/pcy_cache.c:26-81`.
///
/// Consumes `policies` (the authority frees it here) and fills `x`'s cache. `-1` flags an
/// invalid policy on the certificate.
///
/// # Safety
///
/// `x` is live and its cache already allocated; `policies` is NULL or a live
/// `STACK_OF(POLICYINFO)` this call takes over.
unsafe fn policy_cache_create(x: *mut X509, policies: *mut OpenSslStack, crit: c_int) -> c_int {
    // SAFETY: `x` is live per the contract; its cache was set by the caller.
    let cache = unsafe { (*x).policy_cache }.cast::<X509PolicyCache>();
    let mut data: *mut X509PolicyData = core::ptr::null_mut();

    let ret: c_int = 'flow: {
        // SAFETY: `policies` is NULL or live per the contract.
        let num = unsafe { OPENSSL_sk_num(policies) };
        if num <= 0 {
            // `goto bad_policy`: no policies is an invalid CertificatePolicies extension.
            break 'flow 0;
        }
        // SAFETY: `cache` is live and writable.
        unsafe { (*cache).data = OPENSSL_sk_new(Some(policy_data_cmp)) };
        // SAFETY: `cache` is live.
        if unsafe { (*cache).data }.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&PCY_CACHE_38) };
            break 'flow 0;
        }
        for i in 0..num {
            // SAFETY: `i` is in range; the element is a live `POLICYINFO`.
            let policy = unsafe { OPENSSL_sk_value(policies, i) }.cast::<PolicyInfo>();
            // SAFETY: `policy` is live; `ossl_policy_data_new` moves its OID/qualifiers out.
            data = unsafe { ossl_policy_data_new(policy, core::ptr::null(), crit) };
            if data.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PCY_CACHE_45) };
                break 'flow 0;
            }
            // SAFETY: `data` is live.
            if unsafe { OBJ_obj2nid((*data).valid_policy) } == NID_any_policy {
                // SAFETY: `cache` is live.
                if !unsafe { (*cache).anyPolicy }.is_null() {
                    // Duplicate anyPolicy OID: illegal (`:49-56`).
                    break 'flow -1;
                }
                // SAFETY: `cache` is live and writable.
                unsafe { (*cache).anyPolicy = data };
            // SAFETY: `cache` and `data` are live.
            } else if unsafe { OPENSSL_sk_find((*cache).data, data.cast::<c_void>()) } >= 0 {
                // Duplicate policy OID: illegal (`:57-59`).
                break 'flow -1;
            // SAFETY: `cache` and `data` are live.
            } else if unsafe { OPENSSL_sk_push((*cache).data, data.cast::<c_void>()) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PCY_CACHE_61) };
                // `ret` is still 0 here, so the label's flag-set does not fire (`:60-63`).
                break 'flow 0;
            }
            data = core::ptr::null_mut();
        }
        // SAFETY: `cache` is live.
        unsafe { OPENSSL_sk_sort((*cache).data) };
        1
    };

    // The authority's `bad_policy:` and `just_cleanup:` labels reach the same code, because the
    // flag-set is guarded by `ret == -1` and the data free is NULL-safe.
    if ret == -1 {
        // SAFETY: `x` is live and writable.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID_POLICY };
    }
    // SAFETY: `data` is NULL or owned here.
    unsafe { ossl_policy_data_free(data) };
    // SAFETY: `policies` is NULL or owned here.
    unsafe { OPENSSL_sk_pop_free(policies, Some(policyinfo_free_void)) };
    if ret <= 0 {
        // SAFETY: `cache` is live; its data stack is NULL or owned here.
        unsafe {
            OPENSSL_sk_pop_free((*cache).data, Some(policy_data_free_void));
            (*cache).data = core::ptr::null_mut();
        }
    }
    ret
}

/// `static int policy_cache_new(X509 *x)` — `crypto/x509/pcy_cache.c:83-178`.
///
/// Builds `x`'s policy cache from its four policy extensions. Always answers 1 once the cache
/// block exists; an invalid extension sets `EXFLAG_INVALID_POLICY` rather than failing.
///
/// # Safety
///
/// `x` is live and its `policy_cache` is NULL.
unsafe fn policy_cache_new(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract.
    if !unsafe { (*x).policy_cache }.is_null() {
        return 1;
    }
    // A fresh block of the cache's own size, written below before it is read.
    let cache = CRYPTO_malloc(core::mem::size_of::<X509PolicyCache>(), FILE.as_ptr(), 0)
        .cast::<X509PolicyCache>();
    if cache.is_null() {
        return 0;
    }
    // SAFETY: `cache` is live and writable.
    unsafe {
        (*cache).anyPolicy = core::ptr::null_mut();
        (*cache).data = core::ptr::null_mut();
        (*cache).any_skip = -1;
        (*cache).explicit_skip = -1;
        (*cache).map_skip = -1;
        (*x).policy_cache = cache.cast::<c_void>();
    }

    let mut i: c_int = 0;
    // SAFETY: `x` is live; the `crit`/`idx` out-parameters are this frame's own.
    let ext_pcons =
        unsafe { X509_get_ext_d2i(x, NID_policy_constraints, &raw mut i, core::ptr::null_mut()) }
            .cast::<PolicyConstraints>();

    let mut bad = false;
    let mut ext_any: *mut c_void = core::ptr::null_mut();

    'flow: {
        if ext_pcons.is_null() {
            if i != -1 {
                bad = true;
                break 'flow;
            }
        } else {
            // SAFETY: `ext_pcons` is live.
            if unsafe {
                (*ext_pcons).requireExplicitPolicy.is_null()
                    && (*ext_pcons).inhibitPolicyMapping.is_null()
            } {
                bad = true;
                break 'flow;
            }
            // SAFETY: `cache` and `ext_pcons` are live.
            if unsafe {
                policy_cache_set_int(
                    &raw mut (*cache).explicit_skip,
                    (*ext_pcons).requireExplicitPolicy,
                )
            } == 0
            {
                bad = true;
                break 'flow;
            }
            // SAFETY: `cache` and `ext_pcons` are live.
            if unsafe {
                policy_cache_set_int(
                    &raw mut (*cache).map_skip,
                    (*ext_pcons).inhibitPolicyMapping,
                )
            } == 0
            {
                bad = true;
                break 'flow;
            }
        }

        // SAFETY: `x` is live; the out-parameter is this frame's own.
        let ext_cpols = unsafe {
            X509_get_ext_d2i(
                x,
                NID_certificate_policies,
                &raw mut i,
                core::ptr::null_mut(),
            )
        }
        .cast::<OpenSslStack>();
        if ext_cpols.is_null() {
            if i != -1 {
                bad = true;
                break 'flow;
            }
            // SAFETY: `ext_pcons` is NULL or owned here.
            unsafe { POLICY_CONSTRAINTS_free(ext_pcons) };
            return 1;
        }
        // SAFETY: `x` is live; `ext_cpols` is a live `STACK_OF(POLICYINFO)` handed over.
        i = unsafe { policy_cache_create(x, ext_cpols, i) };
        if i <= 0 {
            // SAFETY: `ext_pcons` is NULL or owned here.
            unsafe { POLICY_CONSTRAINTS_free(ext_pcons) };
            return i;
        }

        // SAFETY: `x` is live; the out-parameter is this frame's own.
        let ext_pmaps =
            unsafe { X509_get_ext_d2i(x, NID_policy_mappings, &raw mut i, core::ptr::null_mut()) }
                .cast::<OpenSslStack>();
        if ext_pmaps.is_null() {
            if i != -1 {
                bad = true;
                break 'flow;
            }
        } else {
            // SAFETY: `x` is live; `ext_pmaps` is a live `STACK_OF(POLICY_MAPPING)` handed over.
            i = unsafe { ossl_policy_cache_set_mapping(x, ext_pmaps) };
            if i <= 0 {
                bad = true;
                break 'flow;
            }
        }

        // SAFETY: `x` is live; the out-parameter is this frame's own.
        ext_any = unsafe {
            X509_get_ext_d2i(x, NID_inhibit_any_policy, &raw mut i, core::ptr::null_mut())
        };
        if ext_any.is_null() {
            if i != -1 {
                bad = true;
                break 'flow;
            }
        // SAFETY: `cache` is live; `ext_any` is a live `ASN1_INTEGER`.
        } else if unsafe {
            policy_cache_set_int(&raw mut (*cache).any_skip, ext_any.cast::<Asn1String>())
        } == 0
        {
            bad = true;
            break 'flow;
        }
    }

    if bad {
        // SAFETY: `x` is live and writable.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID_POLICY };
    }
    // SAFETY: `ext_pcons` is NULL or owned here; `ext_any` is NULL or owned here.
    unsafe {
        POLICY_CONSTRAINTS_free(ext_pcons);
        ASN1_INTEGER_free(ext_any.cast::<Asn1String>());
    }
    1
}

/// `void ossl_policy_cache_free(X509_POLICY_CACHE *cache)` — `crypto/x509/pcy_cache.c:180-187`.
///
/// Releases the anyPolicy data, the data stack and the cache block.
///
/// The authority's only callers are `x509_cb`'s `ASN1_OP_D2I_PRE`/`ASN1_OP_FREE_POST` arms
/// (`x_x509.c:49`, `:90`), which `x_x509.rs` withholds and which this slice may not edit, so in
/// this crate the function currently has no caller; see the module doc.
///
/// # Safety
///
/// `cache` must be NULL or a cache this crate owns and has not already freed.
#[allow(dead_code)]
pub(crate) unsafe fn ossl_policy_cache_free(cache: *mut X509PolicyCache) {
    if cache.is_null() {
        return;
    }
    // SAFETY: `cache` is live per the contract; each member is NULL or owned by it.
    unsafe {
        ossl_policy_data_free((*cache).anyPolicy);
        OPENSSL_sk_pop_free((*cache).data, Some(policy_data_free_void));
        CRYPTO_free(cache.cast(), FILE.as_ptr(), 0);
    }
}

/// `const X509_POLICY_CACHE *ossl_policy_cache_set(X509 *x)` — `crypto/x509/pcy_cache.c:189-200`.
///
/// Builds the cache lazily under the certificate's lock and answers it, or NULL if the lock could
/// not be taken.
///
/// # Safety
///
/// `x` must be NULL or a live `X509`.
pub(crate) unsafe fn ossl_policy_cache_set(x: *mut X509) -> *const X509PolicyCache {
    // SAFETY: `x` is NULL or live per the contract.
    unsafe {
        if (*x).policy_cache.is_null() {
            if CRYPTO_THREAD_write_lock((*x).lock) == 0 {
                return core::ptr::null();
            }
            policy_cache_new(x);
            CRYPTO_THREAD_unlock((*x).lock);
        }
        (*x).policy_cache.cast::<X509PolicyCache>()
    }
}

/// `X509_POLICY_DATA *ossl_policy_cache_find_data(const X509_POLICY_CACHE *cache, const ASN1_OBJECT *id)`
/// — `crypto/x509/pcy_cache.c:202-210`.
///
/// The comparator-backed lookup in the sorted data stack; a miss answers NULL.
///
/// # Safety
///
/// `cache` is live; `id` is NULL or a live `ASN1_OBJECT`.
pub(crate) unsafe fn ossl_policy_cache_find_data(
    cache: *const X509PolicyCache,
    id: *const Asn1Object,
) -> *mut X509PolicyData {
    let tmp = X509PolicyData {
        flags: 0,
        valid_policy: id as *mut Asn1Object,
        qualifier_set: core::ptr::null_mut(),
        expected_policy_set: core::ptr::null_mut(),
    };
    // SAFETY: `cache` is live; `&tmp` is the comparator's key element.
    let idx = unsafe { OPENSSL_sk_find((*cache).data, (&raw const tmp).cast::<c_void>()) };
    // SAFETY: `cache` is live; a miss (`idx < 0`) answers NULL.
    unsafe { OPENSSL_sk_value((*cache).data, idx) }.cast::<X509PolicyData>()
}

/// `int ossl_policy_cache_set_mapping(X509 *x, POLICY_MAPPINGS *maps)` —
/// `crypto/x509/pcy_map.c:22-77`.
///
/// Transcribed here rather than in a file this stratum may not add; see the module doc. Qualifies
/// each `POLICY_MAPPING` into `x`'s cache, taking over and freeing `maps`. A `-1` flags an
/// invalid mapping.
///
/// # Safety
///
/// `x` is live with its cache already built; `maps` is NULL or a live
/// `STACK_OF(POLICY_MAPPING)` this call takes over.
pub(crate) unsafe fn ossl_policy_cache_set_mapping(x: *mut X509, maps: *mut OpenSslStack) -> c_int {
    // SAFETY: `x` is live per the contract; its cache was set by `policy_cache_new`.
    let cache = unsafe { (*x).policy_cache }.cast::<X509PolicyCache>();

    let ret: c_int = 'flow: {
        // SAFETY: `maps` is NULL or live per the contract.
        let num = unsafe { OPENSSL_sk_num(maps) };
        if num == 0 {
            break 'flow -1;
        }
        for i in 0..num {
            // SAFETY: `i` is in range; the element is a live `POLICY_MAPPING`.
            let map = unsafe { OPENSSL_sk_value(maps, i) }.cast::<PolicyMapping>();
            // SAFETY: `map` is live.
            if unsafe {
                OBJ_obj2nid((*map).subjectDomainPolicy) == NID_any_policy
                    || OBJ_obj2nid((*map).issuerDomainPolicy) == NID_any_policy
            } {
                break 'flow -1;
            }

            // SAFETY: `cache` and `map` are live.
            let mut data = unsafe { ossl_policy_cache_find_data(cache, (*map).issuerDomainPolicy) };
            // SAFETY: `cache` is live.
            if data.is_null() && unsafe { (*cache).anyPolicy }.is_null() {
                continue;
            }
            if data.is_null() {
                // SAFETY: `cache` is live; its anyPolicy is non-null here.
                let any_flags = unsafe { (*(*cache).anyPolicy).flags };
                // SAFETY: `cache` and `map` are live.
                data = unsafe {
                    ossl_policy_data_new(
                        core::ptr::null_mut(),
                        (*map).issuerDomainPolicy,
                        (any_flags & POLICY_DATA_FLAG_CRITICAL) as c_int,
                    )
                };
                if data.is_null() {
                    // `ret` is still 0 here (`pcy_map.c:53-54`).
                    break 'flow 0;
                }
                // SAFETY: `cache` and `data` are live.
                unsafe {
                    (*data).qualifier_set = (*(*cache).anyPolicy).qualifier_set;
                    (*data).flags |= POLICY_DATA_FLAG_MAPPED_ANY;
                    (*data).flags |= POLICY_DATA_FLAG_SHARED_QUALIFIERS;
                }
                // SAFETY: `cache` and `data` are live.
                if unsafe { OPENSSL_sk_push((*cache).data, data.cast::<c_void>()) } == 0 {
                    // SAFETY: `data` is owned here.
                    unsafe { ossl_policy_data_free(data) };
                    // `ret` is still 0 here (`pcy_map.c:61-63`).
                    break 'flow 0;
                }
            } else {
                // SAFETY: `data` is live and writable.
                unsafe { (*data).flags |= POLICY_DATA_FLAG_MAPPED };
            }
            // SAFETY: `data` and `map` are live; ownership of the mapping OID moves into the set.
            if unsafe {
                OPENSSL_sk_push(
                    (*data).expected_policy_set,
                    (*map).subjectDomainPolicy.cast::<c_void>(),
                )
            } == 0
            {
                // `ret` is still 0 here (`pcy_map.c:67-69`).
                break 'flow 0;
            }
            // SAFETY: `map` is live and writable.
            unsafe { (*map).subjectDomainPolicy = core::ptr::null_mut() };
        }
        1
    };

    // SAFETY: `maps` is NULL or owned here.
    unsafe { OPENSSL_sk_pop_free(maps, Some(policy_mapping_free_void)) };
    ret
}
