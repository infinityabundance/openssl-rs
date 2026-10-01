//! `crypto/x509/x509_vfy.c` — the certificate-path verify engine. Phase 11's unit. This slice
//! lands the `X509_STORE_CTX` object and its lifecycle, every field/error/callback accessor, the
//! issuer lookup, the time-comparison surface and the free-standing parameters helper; the three
//! engine entry points are withheld by name with their blocker (below).
//!
//! `crypto/x509/x509_vfy.c` is 3,984 lines. **This module lands sixty-four of its seventy open
//! exports** — everything whose closure is already landed — and withholds six by name:
//! [`X509_verify_cert`], [`X509_STORE_CTX_verify`], [`X509_build_chain`], [`X509_STORE_CTX_init`],
//! [`X509_STORE_CTX_init_rpk`] and [`X509_CRL_diff`]. The landed surface:
//!
//! * **The context lifecycle** (`:2693-2908`): [`X509_STORE_CTX_new_ex`]/[`X509_STORE_CTX_new`],
//!   [`X509_STORE_CTX_free`], the idempotent [`X509_STORE_CTX_cleanup`] and the `set_default` /
//!   `purpose_inherit` drivers.
//! * **Every field, error and callback accessor** (`:2524-3085`), including the `get0`/`get1`/
//!   `set0` arms, the twelve `set`/`get` verify-callback pairs and the `ex_data` doors.
//! * **The issuer lookup** (`:388-540`, `:454-489`): [`X509_STORE_CTX_get1_issuer`], its
//!   `get0_best_issuer_sk`/`sk_X509_contains` helpers, the `other_sk` alternative and the
//!   [`X509_STORE_CTX_set0_trusted_stack`] door.
//! * **The free-standing time surface** (`:2233-2361`): [`X509_cmp_time`],
//!   [`X509_cmp_current_time`], [`X509_cmp_timeframe`], [`X509_time_adj`], [`X509_time_adj_ex`] and
//!   [`X509_gmtime_adj`], plus the internal `ossl_x509_check_cert_time` (`:2084-2108`) the issuer
//!   lookup calls.
//! * **The parameters helper** [`X509_get_pubkey_parameters`] (`:2364-2397`).
//!
//! ## Withheld by name, with the blocker
//!
//! The three engine entry points and the two that build the context they run on are one closure,
//! and its blocker is measured, not assumed:
//!
//! * [`X509_verify_cert`] (`:305`), [`X509_STORE_CTX_verify`] (`:292`) and [`X509_build_chain`]
//!   (`:3855`) run `x509_verify_x509` (`:346`) -> `verify_chain` (`:253`) -> `build_chain`
//!   (`:3512`), whose checks are `check_extensions`, `check_id`, `check_trust`, `check_revocation`,
//!   `check_policy`, `internal_verify` and the CRL cluster. Their closure is **not landed**:
//!   `check_revocation` (`:1062`) is one half `check_cert_ocsp_resp` (`:1174`) over the
//!   `ocsp.h` objects (Phase 12, none landed) and the other half `check_cert_crl`/`check_crl`/
//!   `cert_crl` (`:1281-1993`) over `X509_CRL_get0_by_cert`/`X509_CRL_verify` (landed in
//!   `x_crl.rs` by 11.4 pulled forward); `x509_verify_x509`/`build_chain`/`check_trust` interleave the
//!   `SSL_DANE` matrix (`dane_match_cert`, `check_dane_issuer`, `check_dane_pkeys`,
//!   `dane_verify*`, `:3087-3490`), whose `SSL_DANE` is the SSL layer's; and `verify_chain`
//!   (`:278-284`) calls `X509v3_asid_validate_path`/`X509v3_addr_validate_path`, both landed in
//!   `v3_asid.rs`/`v3_addr.rs` by 11.5 pulled forward. A transcription with any of those arms omitted would not
//!   be the authority's function, so the names are named, not declared.
//! * [`X509_STORE_CTX_init`] (`:2737`) and [`X509_STORE_CTX_init_rpk`] (`:2729`) install the
//!   engine's default callbacks (`check_revocation`, `check_crl`, `cert_crl`, `check_policy` ->
//!   `internal_verify`) into `ctx`, so they are blocked by the same closure.
//! * [`X509_CRL_diff`] (`:2403`) is blocked by `X509_CRL_set_nextUpdate`, which this crate does not
//!   model yet; the `X509_CRL_add0_revoked`/`X509_CRL_get0_by_serial`/`X509_CRL_verify` it also
//!   reads are now landed in `x_crl.rs`.
//!
//! [`X509_policy_tree_free`](crate::x509::pcy_tree::X509_policy_tree_free) landed with this slice,
//! so [`X509_STORE_CTX_cleanup`] can call it; that is why the lifecycle above lands even though
//! `X509_STORE_CTX_init` does not.
//!
//! ## The context layout
//!
//! `struct x509_store_ctx_st` is defined in `x509_lu.rs` (11.1a) as [`X509StoreCtx`] because the
//! store's read path dereferences three of its members; this module reads and writes the rest.
//!
//! ## The raise site
//!
//! `crypto/x509/x509_vfy.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so the
//! coordinates on its landed paths are **declared locally** in the `err_sites::ErrSite` shape (as
//! `x509_lu.rs` does). The reasons are read from `include/openssl/x509err.h` and
//! `include/openssl/err.h.in`: `X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY` = 108,
//! `X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN` = 107, `X509_R_UNKNOWN_PURPOSE_ID` = 121 and
//! `X509_R_UNKNOWN_TRUST_ID` = 120, against `ERR_LIB_X509` = 11.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::layout::{
    Asn1String, ASN1_STRING_FLAG_MSTRING, V_ASN1_GENERALIZEDTIME, V_ASN1_UTCTIME,
};
use crate::asn1::string::ASN1_TIME_free;
use crate::asn1::time::{
    ASN1_GENERALIZEDTIME_adj, ASN1_TIME_adj, ASN1_TIME_diff, ASN1_UTCTIME_adj,
};
use crate::evp::pkey::{EVP_PKEY_copy_parameters, EVP_PKEY_missing_parameters, EvpPkey};
use crate::runtime::bio::sys::time;
use crate::runtime::ctype::ossl_isdigit;
use crate::runtime::err::err_reasons::{
    X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN, X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY,
    X509_R_UNKNOWN_PURPOSE_ID, X509_R_UNKNOWN_TRUST_ID,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_set_ex_data, CRYPTO_EX_INDEX_X509_STORE_CTX,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::time::TimeT;
use crate::x509::pcy_lib::X509PolicyTree;
use crate::x509::pcy_tree::X509_policy_tree_free;
use crate::x509::v3_purp::{
    ossl_x509_likely_issued, ossl_x509_signing_allowed, ossl_x509v3_cache_extensions,
    X509_PURPOSE_get0, X509_PURPOSE_get_by_id,
};
use crate::x509::x509_cmp::{
    X509_NAME_cmp, X509_add_cert, X509_chain_up_ref, X509_cmp, X509_get0_pubkey,
    X509_get_issuer_name, X509_get_subject_name,
};
use crate::x509::x509_lu::{
    ossl_x509_store_ctx_get_by_subject, X509StoreCtx, X509_OBJECT_free, X509_OBJECT_new,
    X509_STORE_CTX_cert_crl_fn, X509_STORE_CTX_check_crl_fn, X509_STORE_CTX_check_issued_fn,
    X509_STORE_CTX_check_policy_fn, X509_STORE_CTX_check_revocation_fn, X509_STORE_CTX_cleanup_fn,
    X509_STORE_CTX_get1_certs, X509_STORE_CTX_get_crl_fn, X509_STORE_CTX_get_issuer_fn,
    X509_STORE_CTX_lookup_certs_fn, X509_STORE_CTX_lookup_crls_fn, X509_STORE_CTX_verify_cb,
    X509_STORE_CTX_verify_fn, X509_LU_NONE, X509_LU_X509,
};
use crate::x509::x509_set::{X509_get0_notAfter, X509_get0_notBefore, X509_up_ref};
use crate::x509::x509_trust::X509_TRUST_get_by_id;
use crate::x509::x509_vpm::{
    X509VerifyParam, X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_get_flags,
    X509_VERIFY_PARAM_get_time, X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_lookup,
    X509_VERIFY_PARAM_set_depth, X509_VERIFY_PARAM_set_flags, X509_VERIFY_PARAM_set_time,
};
use crate::x509::x_all::X509_verify;
use crate::x509::x_crl::X509Crl;
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::{X509_free, X509};

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;

/// `X509_V_OK` — `include/openssl/x509_vfy.h.in:215`.
const X509_V_OK: c_int = 0;
/// `X509_V_FLAG_USE_CHECK_TIME` — `include/openssl/x509_vfy.h.in:341`, `0x2`.
const X509_V_FLAG_USE_CHECK_TIME: c_ulong = 0x2;
/// `X509_V_FLAG_NO_CHECK_TIME` — `include/openssl/x509_vfy.h.in:385`, `0x200000`.
const X509_V_FLAG_NO_CHECK_TIME: c_ulong = 0x200000;

/// `EXFLAG_SI` — `include/openssl/x509v3.h:434`, self-issued.
const EXFLAG_SI: c_uint = 0x20;
/// `EXFLAG_SS` — `include/openssl/x509v3.h:444`, the word `X509_self_signed` tests once the cache
/// has matched issuer/subject and the authority/subject key identifiers.
const EXFLAG_SS: c_uint = 0x2000;
/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/x509_vfy.c";

/// One `x509_vfy.c` raise coordinate, declared locally (see the module doc).
const fn x509_vfy_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_vfy.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_self_signed`'s failed [`X509_get0_pubkey`] at `x509_vfy.c:105`.
const X509_VFY_105: ErrSite = x509_vfy_site(
    105,
    c"X509_self_signed",
    X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY,
);
/// `X509_get_pubkey_parameters`' failed pubkey at `x509_vfy.c:2375`.
const X509_VFY_2375: ErrSite = x509_vfy_site(
    2375,
    c"X509_get_pubkey_parameters",
    X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY,
);
/// `X509_get_pubkey_parameters`' no-parameters-in-chain at `x509_vfy.c:2383`.
const X509_VFY_2383: ErrSite = x509_vfy_site(
    2383,
    c"X509_get_pubkey_parameters",
    X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN,
);
/// `X509_STORE_CTX_purpose_inherit`'s unknown purpose at `x509_vfy.c:2662`.
const X509_VFY_2662: ErrSite = x509_vfy_site(
    2662,
    c"X509_STORE_CTX_purpose_inherit",
    X509_R_UNKNOWN_PURPOSE_ID,
);
/// `X509_STORE_CTX_purpose_inherit`'s unknown default purpose at `x509_vfy.c:2669`.
const X509_VFY_2669: ErrSite = x509_vfy_site(
    2669,
    c"X509_STORE_CTX_purpose_inherit",
    X509_R_UNKNOWN_PURPOSE_ID,
);
/// `X509_STORE_CTX_purpose_inherit`'s unknown trust at `x509_vfy.c:2681`.
const X509_VFY_2681: ErrSite = x509_vfy_site(
    2681,
    c"X509_STORE_CTX_purpose_inherit",
    X509_R_UNKNOWN_TRUST_ID,
);
/// `X509_STORE_CTX_set_default`'s unknown name at `x509_vfy.c:3065`.
const X509_VFY_3065: ErrSite = x509_vfy_site(
    3065,
    c"X509_STORE_CTX_set_default",
    X509_R_UNKNOWN_PURPOSE_ID,
);

/// The `X509_free` element thunk for `sk_X509_pop_free`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509`.
unsafe extern "C" fn x509_free_void(x: *mut c_void) {
    // SAFETY: `x` is NULL or live per the contract.
    unsafe { X509_free(x.cast()) };
}

// ---------------------------------------------------------------------------------------------
// `X509_self_signed` — `crypto/x509/x509_vfy.c:100-115`.
// ---------------------------------------------------------------------------------------------

/// `int X509_self_signed(X509 *cert, int verify_signature)` — `crypto/x509/x509_vfy.c:100-115`.
///
/// Returns `1` if the certificate is self-signed, `0` if not, and `-1` on error. It caches the
/// extensions first (matching issuer against subject and any authority key identifier against the
/// subject key identifier), tests `EXFLAG_SS`, and — only when `verify_signature` is non-zero —
/// verifies the certificate against its own public key. A NULL `cert` (whose `X509_get0_pubkey`
/// answers NULL) raises and returns `-1`.
///
/// # Safety
///
/// `cert` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_self_signed(cert: *mut X509, verify_signature: c_int) -> c_int {
    // SAFETY: `cert` is NULL or live per the contract; `X509_get0_pubkey` handles NULL.
    let pkey = unsafe { X509_get0_pubkey(cert) };
    if pkey.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VFY_105) };
        return -1;
    }
    // SAFETY: `cert` is live here (its public key resolved).
    if unsafe { ossl_x509v3_cache_extensions(cert) } == 0 {
        return -1;
    }
    // SAFETY: `cert` is live; the cache has released its write lock, matching the authority's own
    // unlocked read of `ex_flags`.
    if (unsafe { (*cert).ex_flags } & EXFLAG_SS) == 0 {
        return 0;
    }
    if verify_signature == 0 {
        return 1;
    }
    // SAFETY: `cert` is live and `pkey` is its own live public key.
    unsafe { X509_verify(cert, pkey) }
}

// ---------------------------------------------------------------------------------------------
// The issuer/chain lookup surface — `x509_vfy.c:388-540`, `:454-489`.
// ---------------------------------------------------------------------------------------------

/// `static int sk_X509_contains(STACK_OF(X509) *sk, X509 *cert)` — `x509_vfy.c:388-396`.
///
/// # Safety
///
/// `sk` must be a live stack of `X509`; `cert` must be live.
unsafe fn sk_x509_contains(sk: *mut OpenSslStack, cert: *mut X509) -> c_int {
    // SAFETY: `sk` is live per the contract.
    let n = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..n {
        // SAFETY: `sk` is live and `i` is in range.
        let e = unsafe { OPENSSL_sk_value(sk, i) }.cast::<X509>();
        // SAFETY: `e` and `cert` are live.
        if unsafe { X509_cmp(e, cert) } == 0 {
            return 1;
        }
    }
    0
}

/// `static X509 *get0_best_issuer_sk(X509_STORE_CTX *ctx, int check_signing_allowed, int no_dup,
/// STACK_OF(X509) *sk, X509 *x)` — `x509_vfy.c:412-443`.
///
/// # Safety
///
/// `ctx` and `x` must be live; `sk` must be a live stack of `X509`.
unsafe fn get0_best_issuer_sk(
    ctx: *mut X509StoreCtx,
    check_signing_allowed: c_int,
    no_dup: c_int,
    sk: *mut OpenSslStack,
    x: *mut X509,
) -> *mut X509 {
    let mut issuer: *mut X509 = ptr::null_mut();
    // SAFETY: `sk` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..num {
        // SAFETY: `sk` is live and `i` is in range.
        let candidate = unsafe { OPENSSL_sk_value(sk, i) }.cast::<X509>();
        // SAFETY: `candidate`, `x` and `ctx` are live; `ctx->chain` is live or NULL.
        unsafe {
            if no_dup != 0
                && !(((*x).ex_flags & EXFLAG_SI) != 0 && OPENSSL_sk_num((*ctx).chain) == 1)
                && sk_x509_contains((*ctx).chain, candidate) != 0
            {
                continue;
            }
            // The callback is installed by `X509_STORE_CTX_init`, matching the authority's call.
            let issued = match (*ctx).check_issued {
                Some(cb) => cb(ctx.cast(), x, candidate),
                None => 0,
            };
            if issued != 0 {
                if check_signing_allowed != 0
                    && ossl_x509_signing_allowed(candidate, x) != X509_V_OK
                {
                    continue;
                }
                if ossl_x509_check_cert_time(ctx, candidate, -1) != 0 {
                    return candidate;
                }
                // Leave in *issuer the first match that has the latest expiration date (`:431-439`).
                if issuer.is_null()
                    || asn1_time_compare(X509_get0_notAfter(candidate), X509_get0_notAfter(issuer))
                        > 0
                {
                    issuer = candidate;
                }
            }
        }
    }
    issuer
}

/// `int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)` —
/// `crypto/x509/x509_vfy.c:454-489`.
///
/// Try to get the issuer certificate from `ctx->store` accepted by `ctx->check_issued`, preferring
/// the first match with suitable validity period or latest expiration. Returns 1 on a successful
/// lookup, 0 when the certificate is not found and -1 on another error. The returned certificate
/// carries an owned reference.
///
/// # Safety
///
/// `issuer` must be writable; `ctx` and `x` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get1_issuer(
    issuer: *mut *mut X509,
    ctx: *mut X509StoreCtx,
    x: *mut X509,
) -> c_int {
    // SAFETY: `issuer` is writable per the contract.
    unsafe { *issuer = ptr::null_mut() };
    // SAFETY: `x` is live per the contract.
    let xn = unsafe { X509_get_issuer_name(x) };
    // SAFETY: `X509_OBJECT_new` allocates an empty object; the caller owns it.
    let obj = unsafe { X509_OBJECT_new() };
    if obj.is_null() {
        return -1;
    }
    let mut ret = -1;
    // SAFETY: `ctx`, `xn` and `obj` are live per the contract.
    let found = unsafe { ossl_x509_store_ctx_get_by_subject(ctx, X509_LU_X509, xn, obj) };
    if found == 1 {
        // SAFETY: `ctx`, `x`, `obj` and the object's cert are live.
        unsafe {
            let cand = (*obj).data.x509;
            let issued = match (*ctx).check_issued {
                Some(cb) => cb(ctx.cast(), x, cand),
                None => 0,
            };
            if issued != 0 && ossl_x509_check_cert_time(ctx, cand, -1) != 0 {
                *issuer = cand;
                // |*issuer| has taken over the cert reference from |obj| (`:472`).
                (*obj).type_ = X509_LU_NONE;
                X509_OBJECT_free(obj);
                return 1;
            }
        }
    } else {
        // SAFETY: `obj` is live.
        unsafe { X509_OBJECT_free(obj) };
        return found;
    }

    // SAFETY: `ctx` and `xn` are live per the contract.
    let certs = unsafe { X509_STORE_CTX_get1_certs(ctx, xn) };
    if !certs.is_null() {
        // SAFETY: `ctx`, `certs` and `x` are live; no_dup is 0 (allow duplicates, `:481`).
        let best = unsafe { get0_best_issuer_sk(ctx, 0, 0, certs, x) };
        ret = 0;
        if !best.is_null() {
            // SAFETY: `best` is live.
            ret = if unsafe { X509_up_ref(best) } != 0 {
                1
            } else {
                -1
            };
            // SAFETY: `issuer` is writable per the contract.
            unsafe { *issuer = best };
        }
        // SAFETY: `certs` is the stack this call owns.
        unsafe { OPENSSL_sk_pop_free(certs, Some(x509_free_void)) };
    }
    // SAFETY: `obj` is live.
    unsafe { X509_OBJECT_free(obj) };
    ret
}

/// `static int check_issued(X509_STORE_CTX *ctx, X509 *x, X509 *issuer)` — `x509_vfy.c:492-503`.
///
/// The default `ctx->check_issued`; its `ctx` argument is unused (`ossl_unused`). It is dead until
/// [`X509_STORE_CTX_init`] (withheld) installs it as the default, which is why it carries the
/// `allow`: the authority's text is transcribed and the caller is named, not stubbed.
///
/// # Safety
///
/// `x` and `issuer` must be live.
#[allow(dead_code)] // referenced only by the withheld `X509_STORE_CTX_init` default roll.
unsafe extern "C" fn check_issued(_ctx: *mut c_void, x: *mut X509, issuer: *mut X509) -> c_int {
    // SAFETY: `issuer` and `x` are live per the contract.
    let err = unsafe { ossl_x509_likely_issued(issuer, x) };
    c_int::from(err == X509_V_OK)
}

/// `static int get1_best_issuer_other_sk(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)` —
/// `x509_vfy.c:509-515`.
///
/// # Safety
///
/// As [`get0_best_issuer_sk`], with `ctx->other_ctx` a live stack of `X509`.
unsafe extern "C" fn get1_best_issuer_other_sk(
    issuer: *mut *mut X509,
    ctx: *mut c_void,
    x: *mut X509,
) -> c_int {
    let ctx = ctx.cast::<X509StoreCtx>();
    // SAFETY: `ctx`, its `other_ctx` stack and `x` are live per the contract.
    let best = unsafe { get0_best_issuer_sk(ctx, 0, 1, (*ctx).other_ctx.cast(), x) };
    // SAFETY: `issuer` is writable per the contract.
    unsafe { *issuer = best };
    if best.is_null() {
        return 0;
    }
    // SAFETY: `best` is live.
    if unsafe { X509_up_ref(best) } != 0 {
        1
    } else {
        -1
    }
}

/// `static STACK_OF(X509) *lookup_certs_sk(X509_STORE_CTX *ctx, const X509_NAME *nm)` —
/// `x509_vfy.c:521-540`.
///
/// # Safety
///
/// `ctx`'s `other_ctx` must be a live stack of `X509`; `nm` must be live.
unsafe extern "C" fn lookup_certs_sk(ctx: *mut c_void, nm: *const X509Name) -> *mut OpenSslStack {
    let ctx = ctx.cast::<X509StoreCtx>();
    let sk = OPENSSL_sk_new_null();
    if sk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` and its `other_ctx` are live per the contract.
    let num = unsafe { OPENSSL_sk_num((*ctx).other_ctx.cast()) };
    for i in 0..num {
        // SAFETY: `other_ctx` is live and `i` is in range.
        let x = unsafe { OPENSSL_sk_value((*ctx).other_ctx.cast(), i) }.cast::<X509>();
        // SAFETY: `x` is live; `nm` is live per the contract.
        if unsafe { X509_NAME_cmp(nm, X509_get_subject_name(x)) } == 0 {
            // SAFETY: `sk` and `x` are live.
            if unsafe { X509_add_cert(sk, x, X509_ADD_FLAG_UP_REF) } == 0 {
                // SAFETY: `sk` is the stack this call owns.
                unsafe {
                    OPENSSL_sk_pop_free(sk, Some(x509_free_void));
                    (*ctx).error = 12 /* X509_V_ERR_OUT_OF_MEM */;
                }
                return ptr::null_mut();
            }
        }
    }
    sk
}

/// `void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)` —
/// `crypto/x509/x509_vfy.c:2877-2882`.
///
/// # Safety
///
/// `ctx` must be live; `sk` must be a live stack of `X509` whose ownership is retained by the
/// caller (the authority stores a borrowed pointer).
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_trusted_stack(
    ctx: *mut X509StoreCtx,
    sk: *mut OpenSslStack,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).other_ctx = sk.cast();
        (*ctx).get_issuer = Some(get1_best_issuer_other_sk);
        (*ctx).lookup_certs = Some(lookup_certs_sk);
    }
}

// ---------------------------------------------------------------------------------------------
// The free-standing time surface — `x509_vfy.c:2233-2361`.
// ---------------------------------------------------------------------------------------------

/// `int X509_cmp_current_time(const ASN1_TIME *ctm)` — `crypto/x509/x509_vfy.c:2233-2236`.
///
/// # Safety
///
/// `ctm` must be NULL or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_current_time(ctm: *const Asn1String) -> c_int {
    // SAFETY: the call forwards `NULL`, the authority's own choice of reference time (`:2235`).
    unsafe { X509_cmp_time(ctm, ptr::null_mut()) }
}

/// `int X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)` —
/// `crypto/x509/x509_vfy.c:2239-2307`.
///
/// Returns 0 on error, otherwise 1 if `ctm > cmp_time`, else -1. `cmp_time` NULL means "now".
///
/// # Safety
///
/// `ctm` must be NULL or a live `ASN1_TIME`; `cmp_time` must be NULL or point at a `time_t`.
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_time(ctm: *const Asn1String, cmp_time: *mut TimeT) -> c_int {
    const UTCTIME_LENGTH: c_int = 13; // sizeof("YYMMDDHHMMSSZ") - 1
    const GENERALIZEDTIME_LENGTH: c_int = 15; // sizeof("YYYYMMDDHHMMSSZ") - 1
    const UPPER_Z: c_char = b'Z' as c_char;

    // SAFETY: `ctm` is NULL or live per the contract.
    if ctm.is_null() {
        return 0;
    }
    // SAFETY: `ctm` is live per the contract.
    let (type_, length, data) = unsafe { ((*ctm).type_, (*ctm).length, (*ctm).data) };
    match type_ {
        V_ASN1_UTCTIME => {
            if length != UTCTIME_LENGTH {
                return 0;
            }
        }
        V_ASN1_GENERALIZEDTIME => {
            if length != GENERALIZEDTIME_LENGTH {
                return 0;
            }
        }
        _ => return 0,
    }

    // Every octet before the final `Z` must be a digit (`:2280-2285`).
    for i in 0..(length - 1) {
        // SAFETY: `data` holds `length` octets; `i < length - 1`.
        if !unsafe { ossl_isdigit(*data.add(i as usize) as c_int) } {
            return 0;
        }
    }
    // SAFETY: the same contract.
    if unsafe { *data.add((length - 1) as usize) } != UPPER_Z as c_uchar {
        return 0;
    }

    // SAFETY: `X509_time_adj(NULL, 0, cmp_time)` allocates the reference (`:2292`).
    let asn1_cmp_time = unsafe { X509_time_adj(ptr::null_mut(), 0, cmp_time) };
    if asn1_cmp_time.is_null() {
        return 0;
    }
    let mut day: c_int = 0;
    let mut sec: c_int = 0;
    // SAFETY: `ctm` and `asn1_cmp_time` are live; `day`/`sec` are writable.
    let ok = unsafe { ASN1_TIME_diff(&mut day, &mut sec, ctm, asn1_cmp_time) };
    let ret = if ok == 0 {
        0
    } else if day >= 0 && sec >= 0 {
        -1
    } else {
        1
    };
    // SAFETY: `asn1_cmp_time` is the block this call owns.
    unsafe { ASN1_TIME_free(asn1_cmp_time) };
    ret
}

/// `int X509_cmp_timeframe(const X509_VERIFY_PARAM *vpm, const ASN1_TIME *start,
/// const ASN1_TIME *end)` — `crypto/x509/x509_vfy.c:2313-2332`.
///
/// Returns 0 if the time should not be checked or the reference time is in range, 1 if it is past
/// `end`, or -1 if it is before `start`.
///
/// # Safety
///
/// `vpm` must be NULL or live; `start`/`end` must be NULL or live `ASN1_TIME`s.
#[no_mangle]
pub unsafe extern "C" fn X509_cmp_timeframe(
    vpm: *const X509VerifyParam,
    start: *const Asn1String,
    end: *const Asn1String,
) -> c_int {
    // SAFETY: `vpm` is NULL or live per the contract.
    let flags = if vpm.is_null() {
        0
    } else {
        // SAFETY: `vpm` is non-NULL here and live per the contract.
        unsafe { X509_VERIFY_PARAM_get_flags(vpm) }
    };

    // The authority reads `check_time` only when `USE_CHECK_TIME` is set; reading it here is
    // unobservable (the value is ignored on the other paths) and avoids a late initialisation.
    // SAFETY: `vpm` is NULL or live per the contract; a NULL read is guarded.
    let mut ref_time: TimeT = if vpm.is_null() {
        0
    } else {
        // SAFETY: `vpm` is non-NULL and live per the contract.
        unsafe { X509_VERIFY_PARAM_get_time(vpm) }
    };
    let time_ptr: *mut TimeT = if (flags & X509_V_FLAG_USE_CHECK_TIME) != 0 {
        &raw mut ref_time
    } else if (flags & X509_V_FLAG_NO_CHECK_TIME) != 0 {
        return 0; // this means ok (`:2324`).
    } else {
        ptr::null_mut()
    };

    if !end.is_null() {
        // SAFETY: `end` is live; `time_ptr` is NULL or points at `ref_time`.
        if unsafe { X509_cmp_time(end, time_ptr) } < 0 {
            return 1;
        }
    }
    if !start.is_null() {
        // SAFETY: `start` is live; `time_ptr` is NULL or points at `ref_time`.
        if unsafe { X509_cmp_time(start, time_ptr) } > 0 {
            return -1;
        }
    }
    0
}

/// `ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj)` — `crypto/x509/x509_vfy.c:2334-2337`.
///
/// # Safety
///
/// `s` must be NULL or a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_gmtime_adj(s: *mut Asn1String, adj: c_long) -> *mut Asn1String {
    // SAFETY: the call forwards `NULL`, the authority's own choice of reference time (`:2336`).
    unsafe { X509_time_adj(s, adj, ptr::null_mut()) }
}

/// `ASN1_TIME *X509_time_adj(ASN1_TIME *s, long offset_sec, time_t *in_tm)` —
/// `crypto/x509/x509_vfy.c:2339-2342`.
///
/// # Safety
///
/// `s` must be NULL or live; `in_tm` must be NULL or point at a `time_t`.
#[no_mangle]
pub unsafe extern "C" fn X509_time_adj(
    s: *mut Asn1String,
    offset_sec: c_long,
    in_tm: *mut TimeT,
) -> *mut Asn1String {
    // SAFETY: the call forwards its arguments unchanged (`:2341`).
    unsafe { X509_time_adj_ex(s, 0, offset_sec, in_tm) }
}

/// `ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s, int offset_day, long offset_sec, time_t *in_tm)` —
/// `crypto/x509/x509_vfy.c:2344-2361`.
///
/// # Safety
///
/// `s` must be NULL or live; `in_tm` must be NULL or point at a `time_t`.
#[no_mangle]
pub unsafe extern "C" fn X509_time_adj_ex(
    s: *mut Asn1String,
    offset_day: c_int,
    offset_sec: c_long,
    in_tm: *mut TimeT,
) -> *mut Asn1String {
    let mut t: TimeT = 0;
    if in_tm.is_null() {
        // SAFETY: `t` is writable; `time` is the libc the authority calls (`:2352`).
        unsafe { time(&mut t) };
    } else {
        // SAFETY: `in_tm` is non-NULL and readable per the contract.
        t = unsafe { *in_tm };
    }

    if !s.is_null() {
        // SAFETY: `s` is live per the contract.
        let (flags, type_) = unsafe { ((*s).flags, (*s).type_) };
        if (flags & ASN1_STRING_FLAG_MSTRING) == 0 {
            if type_ == V_ASN1_UTCTIME {
                // SAFETY: `s` is live; `t` is the reference time.
                return unsafe { ASN1_UTCTIME_adj(s, t, offset_day, offset_sec) };
            }
            if type_ == V_ASN1_GENERALIZEDTIME {
                // SAFETY: `s` is live; `t` is the reference time.
                return unsafe { ASN1_GENERALIZEDTIME_adj(s, t, offset_day, offset_sec) };
            }
        }
    }
    // SAFETY: `s` is NULL or live; `t` is the reference time.
    unsafe { ASN1_TIME_adj(s, t, offset_day, offset_sec) }
}

/// The `ASN1_TIME_compare` the best-issuer scan calls — `crypto/x509/a_time.c`.
///
/// # Safety
///
/// `a`/`b` must be live `ASN1_TIME`s.
unsafe fn asn1_time_compare(a: *const Asn1String, b: *const Asn1String) -> c_int {
    // SAFETY: the contract forwards to `ASN1_TIME_compare`.
    unsafe { crate::asn1::time::ASN1_TIME_compare(a, b) }
}

// ---------------------------------------------------------------------------------------------
// `X509_get_pubkey_parameters` — `x509_vfy.c:2364-2397`.
// ---------------------------------------------------------------------------------------------

/// `int X509_get_pubkey_parameters(EVP_PKEY *pkey, STACK_OF(X509) *chain)` —
/// `crypto/x509/x509_vfy.c:2364-2397`.
///
/// Copies any missing public-key parameters up the chain towards `pkey`. Returns 1 on success, 0
/// when a certificate's public key cannot be decoded or no parameters are found in the chain.
///
/// # Safety
///
/// `pkey` must be NULL or live; `chain` must be a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_pubkey_parameters(
    pkey: *mut EvpPkey,
    chain: *mut OpenSslStack,
) -> c_int {
    if !pkey.is_null() {
        // SAFETY: `pkey` is live per the contract.
        if unsafe { EVP_PKEY_missing_parameters(pkey) } == 0 {
            return 1;
        }
    }

    let mut ktmp: *mut EvpPkey = ptr::null_mut();
    let mut i: c_int = 0;
    // SAFETY: `chain` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(chain) };
    while i < num {
        // SAFETY: `chain` is live and `i` is in range.
        let cert = unsafe { OPENSSL_sk_value(chain, i) }.cast::<X509>();
        // SAFETY: `cert` is live.
        ktmp = unsafe { X509_get0_pubkey(cert) };
        if ktmp.is_null() {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&X509_VFY_2375) };
            return 0;
        }
        // SAFETY: `ktmp` is live.
        if unsafe { EVP_PKEY_missing_parameters(ktmp) } == 0 {
            break;
        }
        ktmp = ptr::null_mut();
        i += 1;
    }
    if ktmp.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VFY_2383) };
        return 0;
    }

    // first, populate the other certs (`:2387-2392`).
    let mut j = i - 1;
    while j >= 0 {
        // SAFETY: `chain` is live and `j` is in range.
        let ktmp2 = unsafe { X509_get0_pubkey(OPENSSL_sk_value(chain, j).cast::<X509>()) };
        // SAFETY: `ktmp2` and `ktmp` are live public keys.
        if unsafe { EVP_PKEY_copy_parameters(ktmp2, ktmp) } == 0 {
            return 0;
        }
        j -= 1;
    }

    if !pkey.is_null() {
        // SAFETY: `pkey` and `ktmp` are live.
        return unsafe { EVP_PKEY_copy_parameters(pkey, ktmp) };
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The store-context lifecycle — `x509_vfy.c:2693-2908`.
// ---------------------------------------------------------------------------------------------

/// `X509_STORE_CTX *X509_STORE_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x509_vfy.c:2693-2710`.
///
/// # Safety
///
/// `libctx` is an opaque pointer; `propq` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut X509StoreCtx {
    // SAFETY: the block is zeroed on allocation.
    let ctx = CRYPTO_zalloc(core::mem::size_of::<X509StoreCtx>(), FILE.as_ptr(), 2695)
        .cast::<X509StoreCtx>();
    if ctx.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is a fresh zeroed block.
    unsafe {
        (*ctx).libctx = libctx;
        if !propq.is_null() {
            (*ctx).propq = CRYPTO_strdup(propq, FILE.as_ptr(), 2702);
            if (*ctx).propq.is_null() {
                CRYPTO_free(ctx.cast(), FILE.as_ptr(), 2704);
                return ptr::null_mut();
            }
        }
    }
    ctx
}

/// `X509_STORE_CTX *X509_STORE_CTX_new(void)` — `crypto/x509/x509_vfy.c:2712-2715`.
#[no_mangle]
pub extern "C" fn X509_STORE_CTX_new() -> *mut X509StoreCtx {
    // SAFETY: the call forwards NULLs, the authority's own arguments (`:2714`).
    unsafe { X509_STORE_CTX_new_ex(ptr::null_mut(), ptr::null()) }
}

/// `void X509_STORE_CTX_free(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:2717-2727`.
///
/// Runs [`X509_STORE_CTX_cleanup`] then releases `propq` (which cleanup preserves) and the context.
///
/// # Safety
///
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_free(ctx: *mut X509StoreCtx) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        X509_STORE_CTX_cleanup(ctx);
        CRYPTO_free((*ctx).propq.cast(), FILE.as_ptr(), 2725);
        CRYPTO_free(ctx.cast(), FILE.as_ptr(), 2726);
    }
}

/// `void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:2884-2908`.
///
/// Idempotent: it runs `ctx->cleanup` once, releases the parameter block and the policy tree, frees
/// the chain and drops the `ex_data` block. The authority's own comment records why the pointers
/// are zeroed (`:2886-2891`), which is what lets `free` call it after `init` already did.
///
/// # Safety
///
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_cleanup(ctx: *mut X509StoreCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if let Some(cleanup) = (*ctx).cleanup {
            cleanup(ctx.cast());
            (*ctx).cleanup = None;
        }
        if !(*ctx).param.is_null() {
            if (*ctx).parent.is_null() {
                X509_VERIFY_PARAM_free((*ctx).param.cast());
            }
            (*ctx).param = ptr::null_mut();
        }
        X509_policy_tree_free((*ctx).tree.cast());
        (*ctx).tree = ptr::null_mut();
        OPENSSL_sk_pop_free((*ctx).chain, Some(x509_free_void));
        (*ctx).chain = ptr::null_mut();
        CRYPTO_free_ex_data(
            CRYPTO_EX_INDEX_X509_STORE_CTX,
            ctx.cast(),
            &raw mut (*ctx).ex_data,
        );
        ptr::write_bytes(&raw mut (*ctx).ex_data, 0, 1);
    }
}

/// `int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name)` —
/// `crypto/x509/x509_vfy.c:3059-3069`.
///
/// # Safety
///
/// `ctx` must be live; `name` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_default(
    ctx: *mut X509StoreCtx,
    name: *const c_char,
) -> c_int {
    // SAFETY: `name` is NUL-terminated per the contract.
    let param = unsafe { X509_VERIFY_PARAM_lookup(name) };
    if param.is_null() {
        // The authority uses `ERR_raise_data(..., "name=%s", name)`. Build that message.
        let mut msg: Vec<u8> = b"name=".to_vec();
        // SAFETY: `name` is NUL-terminated per the contract.
        msg.extend_from_slice(unsafe { CStr::from_ptr(name) }.to_bytes());
        msg.push(0);
        // SAFETY: `msg` is NUL-terminated and lives for the call.
        unsafe { raise_site_data(&X509_VFY_3065, msg.as_ptr().cast()) };
        return 0;
    }
    // SAFETY: `ctx` is live; its `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_inherit((*ctx).param.cast(), param) }
}

/// `int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose, int purpose,
/// int trust)` — `crypto/x509/x509_vfy.c:2642-2691`.
///
/// # Safety
///
/// `ctx` must be live and its `param` live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_purpose_inherit(
    ctx: *mut X509StoreCtx,
    mut def_purpose: c_int,
    mut purpose: c_int,
    mut trust: c_int,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let param = unsafe { (*ctx).param.cast::<X509VerifyParam>() };

    // If purpose not set use default (`:2647-2655`).
    if purpose == 0 {
        purpose = def_purpose;
    } else if def_purpose == 0 {
        def_purpose = purpose;
    }
    // If we have a purpose then check it is valid (`:2656-2677`).
    if purpose != 0 {
        // SAFETY: `purpose` is a plain int; `X509_PURPOSE_get_by_id` reads the purpose table.
        let mut idx = unsafe { X509_PURPOSE_get_by_id(purpose) };
        if idx == -1 {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&X509_VFY_2662) };
            return 0;
        }
        // SAFETY: `idx` names a row of the purpose table.
        let mut ptmp = unsafe { X509_PURPOSE_get0(idx) };
        // SAFETY: `ptmp` is live.
        if unsafe { (*ptmp).trust } == 0 {
            // SAFETY: `def_purpose` is a plain int; the lookup reads the purpose table.
            idx = unsafe { X509_PURPOSE_get_by_id(def_purpose) };
            if idx == -1 {
                // SAFETY: the site's pointers are static.
                unsafe { raise_site(&X509_VFY_2669) };
                return 0;
            }
            // SAFETY: `idx` names a row of the purpose table.
            ptmp = unsafe { X509_PURPOSE_get0(idx) };
        }
        if trust == 0 {
            // SAFETY: `ptmp` is live.
            trust = unsafe { (*ptmp).trust };
        }
    }
    // SAFETY: `trust` is a plain int; `X509_TRUST_get_by_id` reads the trust table.
    if trust != 0 && unsafe { X509_TRUST_get_by_id(trust) } == -1 {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&X509_VFY_2681) };
        return 0;
    }

    // SAFETY: `param` is live per the contract.
    unsafe {
        if (*param).purpose == 0 && purpose != 0 {
            (*param).purpose = purpose;
        }
        if (*param).trust == 0 && trust != 0 {
            (*param).trust = trust;
        }
    }
    1
}

/// `int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose)` —
/// `crypto/x509/x509_vfy.c:2613-2621`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_purpose(
    ctx: *mut X509StoreCtx,
    purpose: c_int,
) -> c_int {
    // SAFETY: the call forwards the authority's own default arguments (`:2620`).
    unsafe { X509_STORE_CTX_purpose_inherit(ctx, 0, purpose, 0) }
}

/// `int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust)` —
/// `crypto/x509/x509_vfy.c:2623-2630`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_trust(ctx: *mut X509StoreCtx, trust: c_int) -> c_int {
    // SAFETY: the call forwards the authority's own default arguments (`:2629`).
    unsafe { X509_STORE_CTX_purpose_inherit(ctx, 0, 0, trust) }
}

// ---------------------------------------------------------------------------------------------
// The field, error and callback accessors — `x509_vfy.c:2524-3085`.
// ---------------------------------------------------------------------------------------------

/// `int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data)` —
/// `crypto/x509/x509_vfy.c:2524-2527`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_ex_data(
    ctx: *mut X509StoreCtx,
    idx: c_int,
    data: *mut c_void,
) -> c_int {
    // SAFETY: `ctx` is live; its `ex_data` is live.
    unsafe { CRYPTO_set_ex_data(&raw mut (*ctx).ex_data, idx, data) }
}

/// `void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx)` —
/// `crypto/x509/x509_vfy.c:2529-2532`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_ex_data(
    ctx: *const X509StoreCtx,
    idx: c_int,
) -> *mut c_void {
    // SAFETY: `ctx` is live; its `ex_data` is live.
    unsafe { CRYPTO_get_ex_data(&raw const (*ctx).ex_data, idx) }
}

/// `int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2534-2537`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_error(ctx: *const X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).error }
}

/// `void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int err)` — `x509_vfy.c:2539-2542`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_error(ctx: *mut X509StoreCtx, err: c_int) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).error = err };
}

/// `int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2544-2547`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_error_depth(ctx: *const X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).error_depth }
}

/// `void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth)` — `x509_vfy.c:2549-2552`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_error_depth(ctx: *mut X509StoreCtx, depth: c_int) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).error_depth = depth };
}

/// `X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2554-2557`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_current_cert(ctx: *const X509StoreCtx) -> *mut X509 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).current_cert }
}

/// `void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x)` — `x509_vfy.c:2559-2562`.
///
/// # Safety
///
/// `ctx` must be live; `x` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_current_cert(ctx: *mut X509StoreCtx, x: *mut X509) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).current_cert = x };
}

/// `STACK_OF(X509) *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2564-2567`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_chain(ctx: *const X509StoreCtx) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).chain }
}

/// `STACK_OF(X509) *X509_STORE_CTX_get1_chain(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2569-2574`.
///
/// # Safety
///
/// `ctx` must be live. The returned stack is the caller's to release.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get1_chain(ctx: *const X509StoreCtx) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    let chain = unsafe { (*ctx).chain };
    if chain.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `chain` is live.
    unsafe { X509_chain_up_ref(chain) }
}

/// `X509 *X509_STORE_CTX_get0_current_issuer(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2576-2579`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_current_issuer(ctx: *const X509StoreCtx) -> *mut X509 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).current_issuer }
}

/// `X509_CRL *X509_STORE_CTX_get0_current_crl(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2581-2584`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_current_crl(ctx: *const X509StoreCtx) -> *mut X509Crl {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).current_crl }
}

/// `X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2586-2589`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_parent_ctx(
    ctx: *const X509StoreCtx,
) -> *mut X509StoreCtx {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).parent }
}

/// `void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *x)` — `x509_vfy.c:2591-2594`.
///
/// # Safety
///
/// `ctx` must be live; `x` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_cert(ctx: *mut X509StoreCtx, x: *mut X509) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cert = x };
}

/// `void X509_STORE_CTX_set0_rpk(X509_STORE_CTX *ctx, EVP_PKEY *rpk)` — `x509_vfy.c:2596-2599`.
///
/// # Safety
///
/// `ctx` must be live; `rpk` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_rpk(ctx: *mut X509StoreCtx, rpk: *mut EvpPkey) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).rpk = rpk };
}

/// `void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk)` —
/// `x509_vfy.c:2601-2604`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_crls(ctx: *mut X509StoreCtx, sk: *mut OpenSslStack) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).crls = sk };
}

/// `void X509_STORE_CTX_set_ocsp_resp(X509_STORE_CTX *ctx, STACK_OF(OCSP_RESPONSE) *sk)` —
/// `crypto/x509/x509_vfy.c:2606-2611`. `OCSP_RESPONSE` is Phase 12's, so the stack is opaque.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_ocsp_resp(
    ctx: *mut X509StoreCtx,
    sk: *mut OpenSslStack,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).ocsp_resp = sk };
}

/// `X509 *X509_STORE_CTX_get0_cert(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2932-2935`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_cert(ctx: *const X509StoreCtx) -> *mut X509 {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cert }
}

/// `EVP_PKEY *X509_STORE_CTX_get0_rpk(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2937-2940`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_rpk(ctx: *const X509StoreCtx) -> *mut EvpPkey {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).rpk }
}

/// `STACK_OF(X509) *X509_STORE_CTX_get0_untrusted(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2942-2945`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_untrusted(
    ctx: *const X509StoreCtx,
) -> *mut OpenSslStack {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).untrusted }
}

/// `void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)` —
/// `x509_vfy.c:2947-2950`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_untrusted(
    ctx: *mut X509StoreCtx,
    sk: *mut OpenSslStack,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).untrusted = sk };
}

/// `void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)` —
/// `x509_vfy.c:2952-2956`.
///
/// # Safety
///
/// `ctx` must be live; `sk` must be a live stack of `X509` whose ownership transfers.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_verified_chain(
    ctx: *mut X509StoreCtx,
    sk: *mut OpenSslStack,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        OPENSSL_sk_pop_free((*ctx).chain, Some(x509_free_void));
        (*ctx).chain = sk;
    }
}

/// `void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx, X509_STORE_CTX_verify_cb verify_cb)` —
/// `x509_vfy.c:2958-2962`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_verify_cb(
    ctx: *mut X509StoreCtx,
    verify_cb: X509_STORE_CTX_verify_cb,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).verify_cb = verify_cb };
}

/// `X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2964-2967`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_verify_cb(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_verify_cb {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).verify_cb }
}

/// `void X509_STORE_CTX_set_verify(X509_STORE_CTX *ctx, X509_STORE_CTX_verify_fn verify)` —
/// `x509_vfy.c:2969-2973`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_verify(
    ctx: *mut X509StoreCtx,
    verify: X509_STORE_CTX_verify_fn,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).verify = verify };
}

/// `X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2975-2978`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_verify(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_verify_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).verify }
}

/// `X509_STORE_CTX_get_issuer_fn X509_STORE_CTX_get_get_issuer(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2980-2984`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_get_issuer(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_get_issuer_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).get_issuer }
}

/// `X509_STORE_CTX_check_issued_fn X509_STORE_CTX_get_check_issued(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2986-2990`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_check_issued(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_check_issued_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).check_issued }
}

/// `X509_STORE_CTX_check_revocation_fn
/// X509_STORE_CTX_get_check_revocation(const X509_STORE_CTX *ctx)` — `x509_vfy.c:2992-2996`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_check_revocation(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_check_revocation_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).check_revocation }
}

/// `X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:2998-3001`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_get_crl(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_get_crl_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).get_crl }
}

/// `void X509_STORE_CTX_set_get_crl(X509_STORE_CTX *ctx, X509_STORE_CTX_get_crl_fn get_crl)` —
/// `x509_vfy.c:3003-3007`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_get_crl(
    ctx: *mut X509StoreCtx,
    get_crl: X509_STORE_CTX_get_crl_fn,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).get_crl = get_crl };
}

/// `X509_STORE_CTX_check_crl_fn X509_STORE_CTX_get_check_crl(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3009-3013`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_check_crl(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_check_crl_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).check_crl }
}

/// `X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3015-3019`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_cert_crl(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_cert_crl_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cert_crl }
}

/// `X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3021-3025`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_check_policy(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_check_policy_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).check_policy }
}

/// `X509_STORE_CTX_lookup_certs_fn X509_STORE_CTX_get_lookup_certs(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3027-3031`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_lookup_certs(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_lookup_certs_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).lookup_certs }
}

/// `X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3033-3037`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_lookup_crls(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_lookup_crls_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).lookup_crls }
}

/// `X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3039-3042`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_cleanup(
    ctx: *const X509StoreCtx,
) -> X509_STORE_CTX_cleanup_fn {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).cleanup }
}

/// `X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3044-3047`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_policy_tree(
    ctx: *const X509StoreCtx,
) -> *mut X509PolicyTree {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).tree.cast() }
}

/// `int X509_STORE_CTX_get_explicit_policy(const X509_STORE_CTX *ctx)` — `x509_vfy.c:3049-3052`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_explicit_policy(ctx: *const X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).explicit_policy }
}

/// `int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx)` — `x509_vfy.c:3054-3057`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get_num_untrusted(ctx: *const X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).num_untrusted }
}

/// `X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *ctx)` —
/// `x509_vfy.c:3071-3074`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_get0_param(
    ctx: *const X509StoreCtx,
) -> *mut X509VerifyParam {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).param.cast() }
}

/// `void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param)` —
/// `x509_vfy.c:3076-3080`.
///
/// # Safety
///
/// `ctx` must be live; `param` must be NULL or a live parameter whose ownership transfers.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_param(
    ctx: *mut X509StoreCtx,
    param: *mut X509VerifyParam,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        X509_VERIFY_PARAM_free((*ctx).param.cast());
        (*ctx).param = param.cast();
    }
}

/// `void X509_STORE_CTX_set0_dane(X509_STORE_CTX *ctx, SSL_DANE *dane)` — `x509_vfy.c:3082-3085`.
///
/// `SSL_DANE` is the SSL layer's type, so the pointer is opaque.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set0_dane(ctx: *mut X509StoreCtx, dane: *mut c_void) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).dane = dane };
}

/// `void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth)` — `x509_vfy.c:2910-2913`.
///
/// # Safety
///
/// `ctx` must be live and its `param` live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_depth(ctx: *mut X509StoreCtx, depth: c_int) {
    // SAFETY: `ctx` is live; its `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_depth((*ctx).param.cast(), depth) };
}

/// `void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags)` —
/// `x509_vfy.c:2915-2918`.
///
/// # Safety
///
/// `ctx` must be live and its `param` live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_flags(ctx: *mut X509StoreCtx, flags: c_ulong) {
    // SAFETY: `ctx` is live; its `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_flags((*ctx).param.cast(), flags) };
}

/// `void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t)` —
/// `x509_vfy.c:2920-2924`.
///
/// # Safety
///
/// `ctx` must be live and its `param` live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_time(
    ctx: *mut X509StoreCtx,
    _flags: c_ulong,
    t: TimeT,
) {
    // SAFETY: `ctx` is live; its `param` is live per the contract.
    unsafe { X509_VERIFY_PARAM_set_time((*ctx).param.cast(), t) };
}

/// `void X509_STORE_CTX_set_current_reasons(X509_STORE_CTX *ctx, unsigned int
/// current_reasons)` — `x509_vfy.c:2926-2930`.
///
/// # Safety
///
/// `ctx` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_set_current_reasons(
    ctx: *mut X509StoreCtx,
    current_reasons: c_uint,
) {
    // SAFETY: `ctx` is live per the contract.
    unsafe { (*ctx).current_reasons = current_reasons };
}

// ---------------------------------------------------------------------------------------------
// The internal helpers the issuer lookup and the withheld engine share — `x509_vfy.c:162-172`,
// `:2084-2108`.
// ---------------------------------------------------------------------------------------------

/// `static int verify_cb_cert(X509_STORE_CTX *ctx, X509 *x, int depth, int err)` —
/// `x509_vfy.c:162-172`.
///
/// # Safety
///
/// `ctx` must be live; `x` must be NULL or live; `ctx->chain` must be live when `x` is NULL.
unsafe fn verify_cb_cert(ctx: *mut X509StoreCtx, x: *mut X509, depth: c_int, err: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let depth = if depth < 0 {
            (*ctx).error_depth
        } else {
            (*ctx).error_depth = depth;
            depth
        };
        (*ctx).current_cert = if !x.is_null() {
            x
        } else {
            OPENSSL_sk_value((*ctx).chain, depth).cast::<X509>()
        };
        if err != X509_V_OK {
            (*ctx).error = err;
        }
        match (*ctx).verify_cb {
            Some(cb) => cb(0, ctx.cast()),
            // The authority calls a NULL pointer here; that is unreachable in the landed surface
            // because only `X509_STORE_CTX_init` (withheld) installs the callback.
            None => 0,
        }
    }
}

/// `int ossl_x509_check_cert_time(X509_STORE_CTX *ctx, X509 *x, int depth)` —
/// `crypto/x509/x509_vfy.c:2084-2108`.
///
/// An internal symbol the authority's version script hides (`nm -D` shows no
/// `ossl_x509_check_cert_time`), so it is not an export and no court names it; it is what the
/// issuer lookup calls.
///
/// # Safety
///
/// `ctx` and `x` must be live; `ctx->param` must be live.
pub(crate) unsafe fn ossl_x509_check_cert_time(
    ctx: *mut X509StoreCtx,
    x: *mut X509,
    depth: c_int,
) -> c_int {
    // SAFETY: `ctx` is live; its `param` is live per the contract.
    let param = unsafe { (*ctx).param.cast::<X509VerifyParam>() };
    // SAFETY: `param` is live.
    let flags = unsafe { X509_VERIFY_PARAM_get_flags(param) };
    // The authority reads `check_time` only when `USE_CHECK_TIME` is set; reading it here is
    // unobservable and lets the pointer be taken without a late initialisation.
    // SAFETY: `param` is live.
    let mut time_buf: TimeT = unsafe { X509_VERIFY_PARAM_get_time(param) };
    let ptime: *mut TimeT = if (flags & X509_V_FLAG_USE_CHECK_TIME) != 0 {
        &raw mut time_buf
    } else if (flags & X509_V_FLAG_NO_CHECK_TIME) != 0 {
        return 1;
    } else {
        ptr::null_mut()
    };

    // SAFETY: `x` is live; `ptime` is NULL or points at `time_buf`.
    let i = unsafe { X509_cmp_time(X509_get0_notBefore(x), ptime) };
    if i >= 0 && depth < 0 {
        return 0;
    }
    // CB_FAIL_IF(i == 0, ...); CB_FAIL_IF(i > 0, ...) (`:2099-2100`).
    // SAFETY: `ctx` and `x` are live.
    unsafe {
        if i == 0
            && verify_cb_cert(
                ctx, x, depth, 13, /* X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD */
            ) == 0
        {
            return 0;
        }
        if i > 0 && verify_cb_cert(ctx, x, depth, 9 /* X509_V_ERR_CERT_NOT_YET_VALID */) == 0 {
            return 0;
        }
    }

    // SAFETY: `x` is live; `ptime` is NULL or points at `time_buf`.
    let i = unsafe { X509_cmp_time(X509_get0_notAfter(x), ptime) };
    if i <= 0 && depth < 0 {
        return 0;
    }
    // SAFETY: `ctx` and `x` are live.
    unsafe {
        if i == 0
            && verify_cb_cert(
                ctx, x, depth, 14, /* X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD */
            ) == 0
        {
            return 0;
        }
        if i < 0 && verify_cb_cert(ctx, x, depth, 10 /* X509_V_ERR_CERT_HAS_EXPIRED */) == 0 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly allocated context is zeroed and its callbacks are unset.
    #[test]
    fn a_new_context_is_zeroed() {
        let ctx = X509_STORE_CTX_new();
        assert!(!ctx.is_null());
        // SAFETY: `ctx` is the live context `X509_STORE_CTX_new` just returned.
        unsafe {
            assert_eq!(X509_STORE_CTX_get_error(ctx), 0);
            assert_eq!(X509_STORE_CTX_get_error_depth(ctx), 0);
            assert_eq!(X509_STORE_CTX_get_num_untrusted(ctx), 0);
            assert_eq!(X509_STORE_CTX_get_explicit_policy(ctx), 0);
            assert!(X509_STORE_CTX_get0_param(ctx).is_null());
            assert!(X509_STORE_CTX_get_verify_cb(ctx).is_none());
            assert!(X509_STORE_CTX_get_verify(ctx).is_none());
            assert!(X509_STORE_CTX_get0_cert(ctx).is_null());
            assert!(X509_STORE_CTX_get0_chain(ctx).is_null());
            assert!(X509_STORE_CTX_get1_chain(ctx).is_null());
            X509_STORE_CTX_cleanup(ctx);
            // Idempotent, as the authority's own comment requires (`x509_vfy.c:2886-2891`).
            X509_STORE_CTX_cleanup(ctx);
            X509_STORE_CTX_free(ctx);
        }
    }

    /// The `set0_param` transfer and the `get0_param` read are one field.
    #[test]
    fn set0_param_adopts_the_block() {
        let ctx = X509_STORE_CTX_new();
        let p = crate::x509::x509_vpm::X509_VERIFY_PARAM_new();
        // SAFETY: `ctx` and `p` are live; the ownership transfer is the authority's `set0`.
        unsafe {
            X509_STORE_CTX_set0_param(ctx, p);
            assert_eq!(X509_STORE_CTX_get0_param(ctx), p);
            // `free` releases the adopted block through `cleanup`.
            X509_STORE_CTX_free(ctx);
        }
    }
}
