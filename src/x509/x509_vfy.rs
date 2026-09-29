//! `crypto/x509/x509_vfy.c` — the certificate-path verify engine. Phase 11's unit, of which this
//! slice lands exactly one name: [`X509_self_signed`].
//!
//! `crypto/x509/x509_vfy.c` is 3,984 lines. **This module lands one function**:
//! [`X509_self_signed`] (`:100-115`), the self-issued/self-signed test that `X509_add_cert`'s
//! `X509_ADD_FLAG_NO_SS` arm (`x509_cmp.rs`) waits on. Its closure is landed whole —
//! [`ossl_x509v3_cache_extensions`](crate::x509::v3_purp::ossl_x509v3_cache_extensions)
//! (`v3_purp.rs`, 10.14), [`X509_get0_pubkey`](crate::x509::x509_cmp::X509_get0_pubkey)
//! (`x509_cmp.rs`) and [`X509_verify`](crate::x509::x_all::X509_verify) (`x_all.rs`) — so the
//! function is transcribed rather than withheld.
//!
//! **Withheld by name — the rest of the unit**, whose one blocker is the unlanded
//! `struct x509_store_ctx_st` (`X509_STORE_CTX`): this crate models no store context (no `chain`,
//! `error`, `error_depth`, `current_cert`, `param` or `verify_cb` surface), so the engine cannot be
//! transcribed without inventing a type outside this unit. The names are named, not declared; the
//! engine lands in Phase 11 alongside the store context itself:
//!
//! * The chain builders and verifiers: `X509_verify_cert` (`:305`), `X509_STORE_CTX_verify`
//!   (`:292`), `x509_verify_x509` (`:346`), `x509_verify_rpk` (`:318`), `verify_chain` (`:253`),
//!   `verify_rpk` (`:240`), `build_chain` (`:2650-3620`), `internal_verify` (`:2114`),
//!   `dane_verify`, `dane_verify_rpk` and the `static` callback `null_callback` (`:88`).
//! * The deciders: `check_extensions` (`:598`), `check_name_constraints` (`:797`), `check_id`
//!   (`:941`), `check_hosts` (`:923`), `check_id_error` (`:918`), `has_san_id` (`:772`),
//!   `check_trust` (`:963`), `check_revocation` (`:1062`), `check_cert_ocsp_resp` (`:1174`),
//!   `check_cert_crl` (`:1281`), `check_policy` (`:1996`), `check_auth_level` (`:209`),
//!   `check_cert_key_level`/`check_key_level`/`check_sig_level`/`check_curve`, `check_issued`
//!   (`:492`), `check_purpose` (`:547`), `check_dane_issuer`, and the CRL cluster
//!   (`get_crl_score` `:1575`, `get_crl_delta` `:1859`, `get_delta_sk` `:1539`, `crl_akid_check`
//!   `:1637`, `crl_crldp_check` `:1825`, `check_crl_path` `:1695`, `check_crl_chain` `:1733`,
//!   `check_crl` `:1901`, `cert_crl` `:1968`, plus `crl_extension_match`, `check_delta_base`,
//!   `get_crl_sk`, `check_crl_time`, `idp_check_dp`, `crldp_check_crlissuer`).
//! * The issuer/cert lookup surface: `X509_STORE_CTX_get1_issuer` (`:454`), `lookup_cert_match`
//!   (`:121`), `get0_best_issuer_sk` (`:412`), `get1_best_issuer_other_sk` (`:509`),
//!   `lookup_certs_sk` (`:521`), `sk_X509_contains` (`:388`).
//! * The whole `X509_STORE_CTX_*` lifecycle and accessor surface (`:2524-3082`): both
//!   `new`/`free` pairs, `_init`/`_init_rpk`/`_cleanup`, the field `set_*`/`get_*` accessors, the
//!   verified-chain and untrusted-stack accessors, the verify-callback and method-function
//!   accessors, `_purpose_inherit`, `_set_default` and the error/error-depth accessors.
//! * The free-standing helpers `ossl_x509_check_cert_time` (`:2084`), `X509_cmp_current_time`
//!   (`:2233`), `X509_cmp_time` (`:2239`), `X509_cmp_timeframe` (`:2313`),
//!   `X509_get_pubkey_parameters` (`:2364`) and `X509_CRL_diff` (`:2403`).
//!
//! ## The raise site
//!
//! `crypto/x509/x509_vfy.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so
//! [`X509_self_signed`]'s one coordinate is **declared locally** in the `err_sites::ErrSite` shape
//! (as `v3_asid.rs`/`v3_purp.rs` do), its reason read from `include/openssl/x509err.h:58`
//! (`X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY` = 108) and its library from
//! `include/openssl/err.h.in:85` (`ERR_LIB_X509` = 11).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_uint};

use crate::runtime::err::err_reasons::X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::x509::v3_purp::ossl_x509v3_cache_extensions;
use crate::x509::x509_cmp::X509_get0_pubkey;
use crate::x509::x_all::X509_verify;
use crate::x509::x_x509::X509;

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;

/// `EXFLAG_SS` — `include/openssl/x509v3.h:684`, the word `X509_self_signed` tests once the cache
/// has matched issuer/subject and the authority/subject key identifiers.
const EXFLAG_SS: c_uint = 0x2000;

/// `X509_self_signed`'s failed [`X509_get0_pubkey`] at `x509_vfy.c:105`, declared locally (see the
/// module doc).
const X509_VFY_105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/x509_vfy.c",
    line: 105,
    func: c"X509_self_signed",
    lib: ERR_LIB_X509,
    reason: X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY,
    dynamic_reason: false,
};

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
