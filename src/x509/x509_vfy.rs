//! `crypto/x509/x509_vfy.c` — the certificate-path verify engine. Phase 11's unit, completed by
//! subphase 11.2c. This module lands the `X509_STORE_CTX` object and its lifecycle, every
//! field/error/callback accessor, the issuer lookup, the time-comparison surface and the
//! free-standing parameters helper; 11.2c lands the whole engine on top of them.
//!
//! `crypto/x509/x509_vfy.c` is 3,984 lines. **This module lands all seventy of its open exports**:
//! [`X509_verify_cert`], [`X509_STORE_CTX_verify`], [`X509_build_chain`], [`X509_STORE_CTX_init`]
//! and [`X509_STORE_CTX_init_rpk`] are the five 11.2c added to the surface below. The landed
//! surface:
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
//! * **The delta-CRL builder** [`X509_CRL_diff`] (`:2403-2522`), whose former blocker
//!   (`X509_CRL_set_nextUpdate`, absent) is discharged: the crate now names
//!   `X509_CRL_set1_lastUpdate`/`X509_CRL_set1_nextUpdate` (`x509cset.rs`), and every other callee was
//!   already landed in `x_crl.rs`/`x509_ext.rs`/`x509cset.rs`. Its file-local helper
//!   `crl_extension_match` (`:1479-1505`) lands with it.
//! * **The verify engine** (`:88-386`, `:547-2074`, `:2114-2231`, `:3512-3984`): the entry points
//!   [`X509_verify_cert`]/[`X509_STORE_CTX_verify`] over `x509_verify_x509`/`x509_verify_rpk`, the
//!   checks `check_extensions`/`check_purpose`/`check_name_constraints`/`check_id`/`check_trust`,
//!   `check_revocation` over `check_cert_ocsp_resp`/`check_cert_crl`, the CRL cluster, `check_policy`,
//!   `internal_verify` and `build_chain`, and the [`X509_STORE_CTX_init`]/
//!   [`X509_STORE_CTX_init_rpk`]/[`X509_build_chain`] drivers.
//! * **The DANE entry points** (`:3392-3490`): `check_leaf_suiteb`, `dane_verify_rpk` and
//!   `dane_verify`, over the `SSL_DANE` matrix [`crate::x509::dane`] holds.
//!
//! The OCSP half of `check_revocation` reaches the `src/ocsp/` pull-forward (11.2b) — its
//! `OCSP_basic_verify`/`ocsp_verify_signer` land with this slice — and the CRL half the landed
//! `X509_CRL_*` surface; both are transcribed whole, `OPENSSL_NO_OCSP` not being defined in this
//! admitted build.
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
use crate::asn1::prim::ASN1_INTEGER_cmp;
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_TIME_free};
use crate::asn1::time::{
    ASN1_GENERALIZEDTIME_adj, ASN1_TIME_adj, ASN1_TIME_diff, ASN1_UTCTIME_adj,
};
use crate::asn1::x_algor::X509_ALGOR_cmp;
use crate::evp::digest::EvpMd;
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_get_id, EVP_PKEY_get_int_param, EVP_PKEY_get_security_bits,
    EVP_PKEY_missing_parameters, EvpPkey,
};
use crate::evp::pkey_ctx::{EVP_PKEY_EC, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS};
use crate::ocsp::ocsp_asn::{OCSP_BASICRESP_free, OCSP_CERTID_free, OcspCertId, OcspResponse};
use crate::ocsp::ocsp_cl::{
    OCSP_SINGLERESP_get0_id, OCSP_check_validity, OCSP_resp_count, OCSP_resp_find_status,
    OCSP_resp_get0, OCSP_response_get1_basic, OCSP_response_status,
};
use crate::ocsp::ocsp_lib::{OCSP_cert_to_id, OCSP_id_cmp};
use crate::ocsp::ocsp_srv::OCSP_id_get0_info;
use crate::ocsp::ocsp_vfy::OCSP_basic_verify;
use crate::runtime::bio::sys::time;
use crate::runtime::ctype::ossl_isdigit;
use crate::runtime::err::err_reasons::{
    X509_R_AKID_MISMATCH, X509_R_CRL_ALREADY_DELTA, X509_R_CRL_VERIFY_FAILURE, X509_R_IDP_MISMATCH,
    X509_R_ISSUER_MISMATCH, X509_R_NEWER_CRL_NOT_NEWER, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY,
    X509_R_NO_CRL_NUMBER, X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN,
    X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY, X509_R_UNKNOWN_PURPOSE_ID, X509_R_UNKNOWN_TRUST_ID,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, raise_site_data, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
    CRYPTO_EX_INDEX_X509_STORE_CTX,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::obj::{
    Asn1Object, NID_authority_key_identifier, NID_commonName, NID_delta_crl,
    NID_issuing_distribution_point, NID_subject_alt_name, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::time::TimeT;
use crate::x509::dane::{
    check_dane_issuer, check_dane_pkeys, dane_match_cert, dane_match_rpk, dane_reset,
    danetls_enabled, danetls_has_dane, danetls_has_dane_ta, danetls_has_pkix, danetls_has_ta,
    get1_trusted_issuer, SslDane,
};
use crate::x509::pcy_lib::X509PolicyTree;
use crate::x509::pcy_tree::{X509_policy_check, X509_policy_tree_free};
use crate::x509::v3_addr::X509v3_addr_validate_path;
use crate::x509::v3_akeya::AuthorityKeyid;
use crate::x509::v3_asid::X509v3_asid_validate_path;
use crate::x509::v3_crld::{DistPoint, DistPointName, IssuingDistPoint};
use crate::x509::v3_genn::{GENERAL_NAMES_free, GENERAL_NAME_cmp, GeneralName};
use crate::x509::v3_ncons::{NAME_CONSTRAINTS_check, NAME_CONSTRAINTS_check_CN, NameConstraints};
use crate::x509::v3_purp::{
    ossl_x509_likely_issued, ossl_x509_signing_allowed, ossl_x509v3_cache_extensions,
    X509_PURPOSE_get0, X509_PURPOSE_get_by_id, X509_PURPOSE_get_trust, X509_check_akid,
    X509_check_ca, X509_check_purpose,
};
use crate::x509::v3_utl::{X509_check_email, X509_check_host, X509_check_ip};
use crate::x509::x509_cmp::{
    ossl_x509_add_cert_new, ossl_x509_add_certs_new, X509_CRL_check_suiteb, X509_NAME_cmp,
    X509_add_cert, X509_add_certs, X509_chain_check_suiteb, X509_chain_up_ref, X509_cmp,
    X509_get0_pubkey, X509_get_issuer_name, X509_get_subject_name,
};
use crate::x509::x509_ext::{
    X509_CRL_add1_ext_i2d, X509_CRL_add_ext, X509_CRL_get_ext, X509_CRL_get_ext_by_NID,
    X509_CRL_get_ext_count, X509_get_ext_d2i,
};
use crate::x509::x509_lu::{
    ossl_x509_store_ctx_get_by_subject, X509Store, X509StoreCtx, X509_OBJECT_free, X509_OBJECT_new,
    X509_STORE_CTX_cert_crl_fn, X509_STORE_CTX_check_crl_fn, X509_STORE_CTX_check_issued_fn,
    X509_STORE_CTX_check_policy_fn, X509_STORE_CTX_check_revocation_fn, X509_STORE_CTX_cleanup_fn,
    X509_STORE_CTX_get1_certs, X509_STORE_CTX_get1_crls, X509_STORE_CTX_get_crl_fn,
    X509_STORE_CTX_get_issuer_fn, X509_STORE_CTX_lookup_certs_fn, X509_STORE_CTX_lookup_crls_fn,
    X509_STORE_CTX_verify_cb, X509_STORE_CTX_verify_fn, X509_LU_NONE, X509_LU_X509,
};
use crate::x509::x509_set::{
    X509_get0_extensions, X509_get0_notAfter, X509_get0_notBefore, X509_get_signature_info,
    X509_get_version, X509_up_ref,
};
use crate::x509::x509_trust::{X509_TRUST_get_by_id, X509_check_trust};
use crate::x509::x509_v3::X509_EXTENSION_get_data;
use crate::x509::x509_vpm::{
    X509VerifyParam, X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_get_flags,
    X509_VERIFY_PARAM_get_time, X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_lookup,
    X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set_depth, X509_VERIFY_PARAM_set_flags,
    X509_VERIFY_PARAM_set_time,
};
use crate::x509::x509cset::{
    X509_CRL_get0_lastUpdate, X509_CRL_get0_nextUpdate, X509_CRL_get_REVOKED, X509_CRL_get_issuer,
    X509_CRL_set1_lastUpdate, X509_CRL_set1_nextUpdate, X509_CRL_set_issuer_name,
    X509_CRL_set_version,
};
use crate::x509::x509name::{
    X509_NAME_ENTRY_get_object, X509_NAME_ENTRY_set, X509_NAME_delete_entry, X509_NAME_entry_count,
    X509_NAME_get_entry,
};
use crate::x509::x_all::{X509_CRL_sign, X509_verify};
use crate::x509::x_crl::{
    X509Crl, X509Revoked, X509_CRL_add0_revoked, X509_CRL_free, X509_CRL_get0_by_cert,
    X509_CRL_get0_by_serial, X509_CRL_new_ex, X509_CRL_up_ref, X509_CRL_verify, X509_REVOKED_dup,
    X509_REVOKED_free,
};
use crate::x509::x_name::{X509Name, X509_NAME_ENTRY_free, X509_NAME_dup, X509_NAME_free};
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

/// `ERR_R_X509_LIB` — `err.h`, `(ERR_LIB_X509 | ERR_RFLAG_COMMON)`.
const ERR_R_X509_LIB: c_int = ERR_LIB_X509 | (0x2 << 18);
/// `ERR_R_ASN1_LIB` — `err.h`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 13 | (0x2 << 18);
/// `X509_CRL_VERSION_2` — `include/openssl/x509.h.in:736`, `1`.
const X509_CRL_VERSION_2: c_long = 1;

/// `X509_CRL_diff`'s already-delta input at `x509_vfy.c:2412`.
const X509_VFY_2412: ErrSite = x509_vfy_site(2412, c"X509_CRL_diff", X509_R_CRL_ALREADY_DELTA);
/// `X509_CRL_diff`'s missing CRL number at `x509_vfy.c:2417`.
const X509_VFY_2417: ErrSite = x509_vfy_site(2417, c"X509_CRL_diff", X509_R_NO_CRL_NUMBER);
/// `X509_CRL_diff`'s issuer mismatch at `x509_vfy.c:2424`.
const X509_VFY_2424: ErrSite = x509_vfy_site(2424, c"X509_CRL_diff", X509_R_ISSUER_MISMATCH);
/// `X509_CRL_diff`'s AKID mismatch at `x509_vfy.c:2429`.
const X509_VFY_2429: ErrSite = x509_vfy_site(2429, c"X509_CRL_diff", X509_R_AKID_MISMATCH);
/// `X509_CRL_diff`'s IDP mismatch at `x509_vfy.c:2434`.
const X509_VFY_2434: ErrSite = x509_vfy_site(2434, c"X509_CRL_diff", X509_R_IDP_MISMATCH);
/// `X509_CRL_diff`'s not-newer input at `x509_vfy.c:2438`.
const X509_VFY_2438: ErrSite = x509_vfy_site(2438, c"X509_CRL_diff", X509_R_NEWER_CRL_NOT_NEWER);
/// `X509_CRL_diff`'s verify failure at `x509_vfy.c:2443`.
const X509_VFY_2443: ErrSite = x509_vfy_site(2443, c"X509_CRL_diff", X509_R_CRL_VERIFY_FAILURE);
/// `X509_CRL_diff`'s failed new/version at `x509_vfy.c:2449`.
const X509_VFY_2449: ErrSite = x509_vfy_site(2449, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed issuer set at `x509_vfy.c:2454`.
const X509_VFY_2454: ErrSite = x509_vfy_site(2454, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed lastUpdate set at `x509_vfy.c:2459`.
const X509_VFY_2459: ErrSite = x509_vfy_site(2459, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed nextUpdate set at `x509_vfy.c:2463`.
const X509_VFY_2463: ErrSite = x509_vfy_site(2463, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed delta-CRL extension at `x509_vfy.c:2469`.
const X509_VFY_2469: ErrSite = x509_vfy_site(2469, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed extension copy at `x509_vfy.c:2481`.
const X509_VFY_2481: ErrSite = x509_vfy_site(2481, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed revoked dup at `x509_vfy.c:2501`.
const X509_VFY_2501: ErrSite = x509_vfy_site(2501, c"X509_CRL_diff", ERR_R_ASN1_LIB);
/// `X509_CRL_diff`'s failed add0_revoked at `x509_vfy.c:2506`.
const X509_VFY_2506: ErrSite = x509_vfy_site(2506, c"X509_CRL_diff", ERR_R_X509_LIB);
/// `X509_CRL_diff`'s failed sign at `x509_vfy.c:2513`.
const X509_VFY_2513: ErrSite = x509_vfy_site(2513, c"X509_CRL_diff", ERR_R_X509_LIB);

/// `x509_verify_x509`'s NULL-cert arm at `x509_vfy.c:351`.
const X509_VFY_351: ErrSite = x509_vfy_site(
    351,
    c"x509_verify_x509",
    X509_R_NO_CERT_SET_FOR_US_TO_VERIFY,
);
/// `x509_verify_x509`'s reused-context arm at `x509_vfy.c:361`.
const X509_VFY_361: ErrSite =
    x509_vfy_site(361, c"x509_verify_x509", ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
/// `X509_STORE_CTX_verify`'s NULL-context arm at `x509_vfy.c:295`.
const X509_VFY_295: ErrSite =
    x509_vfy_site(295, c"X509_STORE_CTX_verify", ERR_R_PASSED_NULL_PARAMETER);
/// `X509_verify_cert`'s NULL-context arm at `x509_vfy.c:308`.
const X509_VFY_308: ErrSite = x509_vfy_site(308, c"X509_verify_cert", ERR_R_PASSED_NULL_PARAMETER);
/// `X509_STORE_CTX_init`'s NULL-context arm at `x509_vfy.c:2741`.
const X509_VFY_2741: ErrSite =
    x509_vfy_site(2741, c"X509_STORE_CTX_init", ERR_R_PASSED_NULL_PARAMETER);
/// `X509_STORE_CTX_init`'s failed parameter allocation at `x509_vfy.c:2834`.
const X509_VFY_2834: ErrSite = x509_vfy_site(2834, c"X509_STORE_CTX_init", ERR_R_ASN1_LIB);
/// `X509_STORE_CTX_init`'s failed ex-data creation at `x509_vfy.c:2862`.
const X509_VFY_2862: ErrSite = x509_vfy_site(2862, c"X509_STORE_CTX_init", ERR_R_CRYPTO_LIB);
/// `X509_build_chain`'s NULL-target arm at `x509_vfy.c:3865`.
const X509_VFY_3865: ErrSite =
    x509_vfy_site(3865, c"X509_build_chain", ERR_R_PASSED_NULL_PARAMETER);
/// `check_name_constraints`'s failed name dup at `x509_vfy.c:857`.
const X509_VFY_857: ErrSite = x509_vfy_site(857, c"check_name_constraints", ERR_R_ASN1_LIB);
/// `check_policy`'s failed bare-TA push at `x509_vfy.c:2014`.
const X509_VFY_2014: ErrSite = x509_vfy_site(2014, c"check_policy", ERR_R_CRYPTO_LIB);
/// `check_policy`'s internal-policy error at `x509_vfy.c:2023`.
const X509_VFY_2023: ErrSite = x509_vfy_site(2023, c"check_policy", ERR_R_X509_LIB);
/// `check_policy`'s unreachable-callback arm at `x509_vfy.c:2041`.
const X509_VFY_2041: ErrSite = x509_vfy_site(2041, c"check_policy", ERR_R_INTERNAL_ERROR);
/// `check_policy`'s unknown-result arm at `x509_vfy.c:2053`.
const X509_VFY_2053: ErrSite = x509_vfy_site(2053, c"check_policy", ERR_R_INTERNAL_ERROR);
/// `build_chain`'s failed untrusted-stack allocation at `x509_vfy.c:3552`.
const X509_VFY_3552: ErrSite = x509_vfy_site(3552, c"build_chain", ERR_R_CRYPTO_LIB);
/// `build_chain`'s failed DANE-cert add at `x509_vfy.c:3562`.
const X509_VFY_3562: ErrSite = x509_vfy_site(3562, c"build_chain", ERR_R_X509_LIB);
/// `build_chain`'s failed untrusted add at `x509_vfy.c:3572`.
const X509_VFY_3572: ErrSite = x509_vfy_site(3572, c"build_chain", ERR_R_X509_LIB);
/// `build_chain`'s failed issuer push at `x509_vfy.c:3684`.
const X509_VFY_3684: ErrSite = x509_vfy_site(3684, c"build_chain", ERR_R_CRYPTO_LIB);
/// `build_chain`'s internal-error label at `x509_vfy.c:3844`.
const X509_VFY_3844: ErrSite = x509_vfy_site(3844, c"build_chain", ERR_R_INTERNAL_ERROR);

// ---------------------------------------------------------------------------------------------
// The engine's reason and flag words — `include/openssl/x509_vfy.h.in` and
// `include/openssl/x509v3.h.in`. Each is named with its header coordinate.
// ---------------------------------------------------------------------------------------------

/// `X509_V_ERR_UNSPECIFIED` — `include/openssl/x509_vfy.h.in:216`.
const X509_V_ERR_UNSPECIFIED: c_int = 1;
/// `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT` — `include/openssl/x509_vfy.h.in:217`.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
/// `X509_V_ERR_UNABLE_TO_GET_CRL` — `include/openssl/x509_vfy.h.in:218`.
const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
/// `X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY` — `include/openssl/x509_vfy.h.in:221`.
const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
/// `X509_V_ERR_CERT_SIGNATURE_FAILURE` — `include/openssl/x509_vfy.h.in:222`.
const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
/// `X509_V_ERR_CRL_SIGNATURE_FAILURE` — `include/openssl/x509_vfy.h.in:223`.
const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
/// `X509_V_ERR_CERT_NOT_YET_VALID` — `include/openssl/x509_vfy.h.in:224`.
const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
/// `X509_V_ERR_CERT_HAS_EXPIRED` — `include/openssl/x509_vfy.h.in:225`.
const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
/// `X509_V_ERR_CRL_NOT_YET_VALID` — `include/openssl/x509_vfy.h.in:226`.
const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
/// `X509_V_ERR_CRL_HAS_EXPIRED` — `include/openssl/x509_vfy.h.in:227`.
const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
/// `X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD` — `include/openssl/x509_vfy.h.in:228`.
const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
/// `X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD` — `include/openssl/x509_vfy.h.in:229`.
const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
/// `X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD` — `include/openssl/x509_vfy.h.in:230`.
const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
/// `X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD` — `include/openssl/x509_vfy.h.in:231`.
const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
/// `X509_V_ERR_OUT_OF_MEM` — `include/openssl/x509_vfy.h.in:232`.
const X509_V_ERR_OUT_OF_MEM: c_int = 17;
/// `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` — `include/openssl/x509_vfy.h.in:233`.
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
/// `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN` — `include/openssl/x509_vfy.h.in:234`.
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
/// `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY` — `include/openssl/x509_vfy.h.in:235`.
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
/// `X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE` — `include/openssl/x509_vfy.h.in:236`.
const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
/// `X509_V_ERR_CERT_CHAIN_TOO_LONG` — `include/openssl/x509_vfy.h.in:237`.
const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
/// `X509_V_ERR_CERT_REVOKED` — `include/openssl/x509_vfy.h.in:238`.
const X509_V_ERR_CERT_REVOKED: c_int = 23;
/// `X509_V_ERR_PATH_LENGTH_EXCEEDED` — `include/openssl/x509_vfy.h.in:240`.
const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
/// `X509_V_ERR_INVALID_PURPOSE` — `include/openssl/x509_vfy.h.in:241`.
const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
/// `X509_V_ERR_CERT_REJECTED` — `include/openssl/x509_vfy.h.in:243`.
const X509_V_ERR_CERT_REJECTED: c_int = 28;
/// `X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER` — `include/openssl/x509_vfy.h.in:250`.
const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
/// `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION` — `include/openssl/x509_vfy.h.in:251`.
const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
/// `X509_V_ERR_KEYUSAGE_NO_CRL_SIGN` — `include/openssl/x509_vfy.h.in:252`.
const X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
/// `X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION` — `include/openssl/x509_vfy.h.in:253`.
const X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
/// `X509_V_ERR_INVALID_NON_CA` — `include/openssl/x509_vfy.h.in:254`.
const X509_V_ERR_INVALID_NON_CA: c_int = 37;
/// `X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED` — `include/openssl/x509_vfy.h.in:255`.
const X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
/// `X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED` — `include/openssl/x509_vfy.h.in:257`.
const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
/// `X509_V_ERR_INVALID_EXTENSION` — `include/openssl/x509_vfy.h.in:258`.
const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
/// `X509_V_ERR_INVALID_POLICY_EXTENSION` — `include/openssl/x509_vfy.h.in:259`.
const X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
/// `X509_V_ERR_NO_EXPLICIT_POLICY` — `include/openssl/x509_vfy.h.in:260`.
const X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
/// `X509_V_ERR_DIFFERENT_CRL_SCOPE` — `include/openssl/x509_vfy.h.in:261`.
const X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
/// `X509_V_ERR_CRL_PATH_VALIDATION_ERROR` — `include/openssl/x509_vfy.h.in:272`.
const X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
/// `X509_V_ERR_HOSTNAME_MISMATCH` — `include/openssl/x509_vfy.h.in:283`.
const X509_V_ERR_HOSTNAME_MISMATCH: c_int = 62;
/// `X509_V_ERR_EMAIL_MISMATCH` — `include/openssl/x509_vfy.h.in:284`.
const X509_V_ERR_EMAIL_MISMATCH: c_int = 63;
/// `X509_V_ERR_IP_ADDRESS_MISMATCH` — `include/openssl/x509_vfy.h.in:285`.
const X509_V_ERR_IP_ADDRESS_MISMATCH: c_int = 64;
/// `X509_V_ERR_DANE_NO_MATCH` — `include/openssl/x509_vfy.h.in:287`.
const X509_V_ERR_DANE_NO_MATCH: c_int = 65;
/// `X509_V_ERR_EE_KEY_TOO_SMALL` — `include/openssl/x509_vfy.h.in:289`.
const X509_V_ERR_EE_KEY_TOO_SMALL: c_int = 66;
/// `X509_V_ERR_CA_KEY_TOO_SMALL` — `include/openssl/x509_vfy.h.in:290`.
const X509_V_ERR_CA_KEY_TOO_SMALL: c_int = 67;
/// `X509_V_ERR_CA_MD_TOO_WEAK` — `include/openssl/x509_vfy.h.in:291`.
const X509_V_ERR_CA_MD_TOO_WEAK: c_int = 68;
/// `X509_V_ERR_INVALID_CALL` — `include/openssl/x509_vfy.h.in:293`.
const X509_V_ERR_INVALID_CALL: c_int = 69;
/// `X509_V_ERR_STORE_LOOKUP` — `include/openssl/x509_vfy.h.in:295`.
const X509_V_ERR_STORE_LOOKUP: c_int = 70;
/// `X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION` — `include/openssl/x509_vfy.h.in:299`.
const X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION: c_int = 72;
/// `X509_V_ERR_OCSP_VERIFY_FAILED` — `include/openssl/x509_vfy.h.in:302`.
const X509_V_ERR_OCSP_VERIFY_FAILED: c_int = 74;
/// `X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY` — `include/openssl/x509_vfy.h.in:309`.
const X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY: c_int = 78;
/// `X509_V_ERR_INVALID_CA` — `include/openssl/x509_vfy.h.in:310`.
const X509_V_ERR_INVALID_CA: c_int = 79;
/// `X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA` — `include/openssl/x509_vfy.h.in:311`.
const X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA: c_int = 80;
/// `X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN` — `include/openssl/x509_vfy.h.in:312`.
const X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN: c_int = 81;
/// `X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA` — `include/openssl/x509_vfy.h.in:313`.
const X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA: c_int = 82;
/// `X509_V_ERR_ISSUER_NAME_EMPTY` — `include/openssl/x509_vfy.h.in:314`.
const X509_V_ERR_ISSUER_NAME_EMPTY: c_int = 83;
/// `X509_V_ERR_SUBJECT_NAME_EMPTY` — `include/openssl/x509_vfy.h.in:315`.
const X509_V_ERR_SUBJECT_NAME_EMPTY: c_int = 84;
/// `X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER` — `include/openssl/x509_vfy.h.in:316`.
const X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER: c_int = 85;
/// `X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER` — `include/openssl/x509_vfy.h.in:317`.
const X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER: c_int = 86;
/// `X509_V_ERR_EMPTY_SUBJECT_ALT_NAME` — `include/openssl/x509_vfy.h.in:318`.
const X509_V_ERR_EMPTY_SUBJECT_ALT_NAME: c_int = 87;
/// `X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL` — `include/openssl/x509_vfy.h.in:319`.
const X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL: c_int = 88;
/// `X509_V_ERR_CA_BCONS_NOT_CRITICAL` — `include/openssl/x509_vfy.h.in:320`.
const X509_V_ERR_CA_BCONS_NOT_CRITICAL: c_int = 89;
/// `X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL` — `include/openssl/x509_vfy.h.in:321`.
const X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL: c_int = 90;
/// `X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL` — `include/openssl/x509_vfy.h.in:322`.
const X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL: c_int = 91;
/// `X509_V_ERR_CA_CERT_MISSING_KEY_USAGE` — `include/openssl/x509_vfy.h.in:323`.
const X509_V_ERR_CA_CERT_MISSING_KEY_USAGE: c_int = 92;
/// `X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3` — `include/openssl/x509_vfy.h.in:324`.
const X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3: c_int = 93;
/// `X509_V_ERR_EC_KEY_EXPLICIT_PARAMS` — `include/openssl/x509_vfy.h.in:325`.
const X509_V_ERR_EC_KEY_EXPLICIT_PARAMS: c_int = 94;
/// `X509_V_ERR_RPK_UNTRUSTED` — `include/openssl/x509_vfy.h.in:326`.
const X509_V_ERR_RPK_UNTRUSTED: c_int = 95;
/// `X509_V_ERR_OCSP_RESP_INVALID` — `include/openssl/x509_vfy.h.in:329`.
const X509_V_ERR_OCSP_RESP_INVALID: c_int = 96;
/// `X509_V_ERR_OCSP_SIGNATURE_FAILURE` — `include/openssl/x509_vfy.h.in:330`.
const X509_V_ERR_OCSP_SIGNATURE_FAILURE: c_int = 97;
/// `X509_V_ERR_OCSP_HAS_EXPIRED` — `include/openssl/x509_vfy.h.in:332`.
const X509_V_ERR_OCSP_HAS_EXPIRED: c_int = 99;
/// `X509_V_ERR_OCSP_NO_RESPONSE` — `include/openssl/x509_vfy.h.in:333`.
const X509_V_ERR_OCSP_NO_RESPONSE: c_int = 100;

/// `X509_V_FLAG_CRL_CHECK` — `include/openssl/x509_vfy.h.in:343`, `0x4`.
const X509_V_FLAG_CRL_CHECK: c_ulong = 0x4;
/// `X509_V_FLAG_CRL_CHECK_ALL` — `include/openssl/x509_vfy.h.in:345`, `0x8`.
const X509_V_FLAG_CRL_CHECK_ALL: c_ulong = 0x8;
/// `X509_V_FLAG_IGNORE_CRITICAL` — `include/openssl/x509_vfy.h.in:347`, `0x10`.
const X509_V_FLAG_IGNORE_CRITICAL: c_ulong = 0x10;
/// `X509_V_FLAG_X509_STRICT` — `include/openssl/x509_vfy.h.in:349`, `0x20`.
const X509_V_FLAG_X509_STRICT: c_ulong = 0x20;
/// `X509_V_FLAG_ALLOW_PROXY_CERTS` — `include/openssl/x509_vfy.h.in:351`, `0x40`.
const X509_V_FLAG_ALLOW_PROXY_CERTS: c_ulong = 0x40;
/// `X509_V_FLAG_POLICY_CHECK` — `include/openssl/x509_vfy.h.in:353`, `0x80`.
const X509_V_FLAG_POLICY_CHECK: c_ulong = 0x80;
/// `X509_V_FLAG_NOTIFY_POLICY` — `include/openssl/x509_vfy.h.in:361`, `0x800`.
const X509_V_FLAG_NOTIFY_POLICY: c_ulong = 0x800;
/// `X509_V_FLAG_EXTENDED_CRL_SUPPORT` — `include/openssl/x509_vfy.h.in:363`, `0x1000`.
const X509_V_FLAG_EXTENDED_CRL_SUPPORT: c_ulong = 0x1000;
/// `X509_V_FLAG_USE_DELTAS` — `include/openssl/x509_vfy.h.in:365`, `0x2000`.
const X509_V_FLAG_USE_DELTAS: c_ulong = 0x2000;
/// `X509_V_FLAG_CHECK_SS_SIGNATURE` — `include/openssl/x509_vfy.h.in:367`, `0x4000`.
const X509_V_FLAG_CHECK_SS_SIGNATURE: c_ulong = 0x4000;
/// `X509_V_FLAG_TRUSTED_FIRST` — `include/openssl/x509_vfy.h.in:369`, `0x8000`.
const X509_V_FLAG_TRUSTED_FIRST: c_ulong = 0x8000;
/// `X509_V_FLAG_PARTIAL_CHAIN` — `include/openssl/x509_vfy.h.in:377`, `0x80000`.
const X509_V_FLAG_PARTIAL_CHAIN: c_ulong = 0x80000;
/// `X509_V_FLAG_NO_ALT_CHAINS` — `include/openssl/x509_vfy.h.in:383`, `0x100000`.
const X509_V_FLAG_NO_ALT_CHAINS: c_ulong = 0x100000;
/// `X509_V_FLAG_OCSP_RESP_CHECK` — `include/openssl/x509_vfy.h.in:388`, `0x400000`.
const X509_V_FLAG_OCSP_RESP_CHECK: c_ulong = 0x400000;
/// `X509_V_FLAG_OCSP_RESP_CHECK_ALL` — `include/openssl/x509_vfy.h.in:390`, `0x800000`.
const X509_V_FLAG_OCSP_RESP_CHECK_ALL: c_ulong = 0x800000;

/// `X509_VP_FLAG_DEFAULT` — `include/openssl/x509_vfy.h.in:392`, `0x1`.
const X509_VP_FLAG_DEFAULT: c_uint = 0x1;
/// `X509_VP_FLAG_ONCE` — `include/openssl/x509_vfy.h.in:396`, `0x10`.
const X509_VP_FLAG_ONCE: c_uint = 0x10;

/// `X509_TRUST_DEFAULT` — `include/openssl/x509_vfy.h.in:98`, `0`.
const X509_TRUST_DEFAULT: c_int = 0;
/// `X509_TRUST_TRUSTED` — `include/openssl/x509_vfy.h.in:122`, `1`.
const X509_TRUST_TRUSTED: c_int = 1;
/// `X509_TRUST_REJECTED` — `include/openssl/x509_vfy.h.in:123`, `2`.
const X509_TRUST_REJECTED: c_int = 2;
/// `X509_TRUST_UNTRUSTED` — `include/openssl/x509_vfy.h.in:124`, `3`.
const X509_TRUST_UNTRUSTED: c_int = 3;
/// `X509_TRUST_NO_SS_COMPAT` — `include/openssl/x509_vfy.h.in:115`, `(1U << 2)`.
const X509_TRUST_NO_SS_COMPAT: c_int = 1 << 2;

/// `X509_PURPOSE_CRL_SIGN` — `include/openssl/x509v3.h.in:507`, `6`.
const X509_PURPOSE_CRL_SIGN: c_int = 6;
/// `X509_PURPOSE_MIN` — `include/openssl/x509v3.h.in:513`, `1`.
const X509_PURPOSE_MIN: c_int = 1;

/// `EXFLAG_BCONS` — `include/openssl/x509v3.h.in:428`, `0x1`.
const EXFLAG_BCONS: c_uint = 0x1;
/// `EXFLAG_KUSAGE` — `include/openssl/x509v3.h.in:429`, `0x2`.
const EXFLAG_KUSAGE: c_uint = 0x2;
/// `EXFLAG_CA` — `include/openssl/x509v3.h.in:433`, `0x10`.
const EXFLAG_CA: c_uint = 0x10;
/// `EXFLAG_CRITICAL` — `include/openssl/x509v3.h.in:439`, `0x200`.
const EXFLAG_CRITICAL: c_uint = 0x200;
/// `EXFLAG_PROXY` — `include/openssl/x509v3.h.in:440`, `0x400`.
const EXFLAG_PROXY: c_uint = 0x400;
/// `EXFLAG_INVALID_POLICY` — `include/openssl/x509v3.h.in:442`, `0x800`.
const EXFLAG_INVALID_POLICY: c_uint = 0x800;
/// `EXFLAG_FRESHEST` — `include/openssl/x509v3.h.in:443`, `0x1000`.
const EXFLAG_FRESHEST: c_uint = 0x1000;
/// `EXFLAG_BCONS_CRITICAL` — `include/openssl/x509v3.h.in:446`, `0x10000`.
const EXFLAG_BCONS_CRITICAL: c_uint = 0x10000;
/// `EXFLAG_AKID_CRITICAL` — `include/openssl/x509v3.h.in:447`, `0x20000`.
const EXFLAG_AKID_CRITICAL: c_uint = 0x20000;
/// `EXFLAG_SKID_CRITICAL` — `include/openssl/x509v3.h.in:448`, `0x40000`.
const EXFLAG_SKID_CRITICAL: c_uint = 0x40000;
/// `EXFLAG_SAN_CRITICAL` — `include/openssl/x509v3.h.in:449`, `0x80000`.
const EXFLAG_SAN_CRITICAL: c_uint = 0x80000;

/// `KU_KEY_CERT_SIGN` — `X509v3_KU_KEY_CERT_SIGN` (`include/openssl/x509.h.in:85`), `0x0004`.
const KU_KEY_CERT_SIGN: c_uint = 0x0004;
/// `KU_CRL_SIGN` — `X509v3_KU_CRL_SIGN` (`include/openssl/x509.h.in:86`), `0x0002`.
const KU_CRL_SIGN: c_uint = 0x0002;

/// `IDP_INVALID` — `include/openssl/x509v3.h.in:380`, `0x2`.
const IDP_INVALID: c_int = 0x2;
/// `IDP_ONLYUSER` — `include/openssl/x509v3.h.in:382`, `0x4`.
const IDP_ONLYUSER: c_int = 0x4;
/// `IDP_ONLYCA` — `include/openssl/x509v3.h.in:384`, `0x8`.
const IDP_ONLYCA: c_int = 0x8;
/// `IDP_ONLYATTR` — `include/openssl/x509v3.h.in:386`, `0x10`.
const IDP_ONLYATTR: c_int = 0x10;
/// `IDP_INDIRECT` — `include/openssl/x509v3.h.in:388`, `0x20`.
const IDP_INDIRECT: c_int = 0x20;
/// `IDP_REASONS` — `include/openssl/x509v3.h.in:390`, `0x40`.
const IDP_REASONS: c_int = 0x40;

/// `CRL_SCORE_NOCRITICAL` — `crypto/x509/x509_vfy.c:34`, `0x100`.
const CRL_SCORE_NOCRITICAL: c_int = 0x100;
/// `CRL_SCORE_SCOPE` — `crypto/x509/x509_vfy.c:35`, `0x080`.
const CRL_SCORE_SCOPE: c_int = 0x080;
/// `CRL_SCORE_TIME` — `crypto/x509/x509_vfy.c:36`, `0x040`.
const CRL_SCORE_TIME: c_int = 0x040;
/// `CRL_SCORE_ISSUER_NAME` — `crypto/x509/x509_vfy.c:37`, `0x020`.
const CRL_SCORE_ISSUER_NAME: c_int = 0x020;
/// `CRL_SCORE_VALID` — `crypto/x509/x509_vfy.c:38-39`.
const CRL_SCORE_VALID: c_int = CRL_SCORE_NOCRITICAL | CRL_SCORE_TIME | CRL_SCORE_SCOPE;
/// `CRL_SCORE_ISSUER_CERT` — `crypto/x509/x509_vfy.c:40`, `0x018`.
const CRL_SCORE_ISSUER_CERT: c_int = 0x018;
/// `CRL_SCORE_SAME_PATH` — `crypto/x509/x509_vfy.c:41`, `0x008`.
const CRL_SCORE_SAME_PATH: c_int = 0x008;
/// `CRL_SCORE_AKID` — `crypto/x509/x509_vfy.c:42`, `0x004`.
const CRL_SCORE_AKID: c_int = 0x004;
/// `CRL_SCORE_TIME_DELTA` — `crypto/x509/x509_vfy.c:43`, `0x002`.
const CRL_SCORE_TIME_DELTA: c_int = 0x002;

/// `CRLDP_ALL_REASONS` — `include/openssl/x509v3.h.in:220`, `0x807f`.
const CRLDP_ALL_REASONS: c_uint = 0x807f;
/// `CRL_REASON_REMOVE_FROM_CRL` — `include/openssl/x509v3.h.in:230`, `8`.
const CRL_REASON_REMOVE_FROM_CRL: c_int = 8;

/// `GEN_DNS` — `include/openssl/x509v3.h.in:155`, `2`.
const GEN_DNS: c_int = 2;
/// `GEN_DIRNAME` — `include/openssl/x509v3.h.in:157`, `4`.
const GEN_DIRNAME: c_int = 4;

/// `X509_CHECK_FLAG_NEVER_CHECK_SUBJECT` — `include/openssl/x509v3.h.in:800`, `0x20`.
const X509_CHECK_FLAG_NEVER_CHECK_SUBJECT: c_uint = 0x20;
/// `X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT` — `include/openssl/x509v3.h.in:790`, `0x1`.
const X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT: c_uint = 0x1;

/// `X509_PCY_TREE_FAILURE` — `include/openssl/x509_vfy.h.in:783`, `-2`.
const X509_PCY_TREE_FAILURE: c_int = -2;
/// `X509_PCY_TREE_INVALID` — `include/openssl/x509_vfy.h.in:784`, `-1`.
const X509_PCY_TREE_INVALID: c_int = -1;
/// `X509_PCY_TREE_INTERNAL` — `include/openssl/x509_vfy.h.in:785`, `0`.
const X509_PCY_TREE_INTERNAL: c_int = 0;
/// `X509_PCY_TREE_VALID` — `include/openssl/x509_vfy.h.in:791`, `1`.
const X509_PCY_TREE_VALID: c_int = 1;

/// `X509_VERSION_3` — `include/openssl/x509.h.in:653`, `2`.
const X509_VERSION_3: c_long = 2;

/// `V_OCSP_CERTSTATUS_GOOD` — `include/openssl/ocsp.h.in:124`, `0`.
const V_OCSP_CERTSTATUS_GOOD: c_int = 0;
/// `V_OCSP_CERTSTATUS_REVOKED` — `include/openssl/ocsp.h.in:125`, `1`.
const V_OCSP_CERTSTATUS_REVOKED: c_int = 1;
/// `OCSP_RESPONSE_STATUS_SUCCESSFUL` — `include/openssl/ocsp.h.in:104`, `0`.
const OCSP_RESPONSE_STATUS_SUCCESSFUL: c_int = 0;

/// `DANE_FLAG_NO_DANE_EE_NAMECHECKS` — `include/openssl/x509_vfy.h.in:721`, `(1L << 0)`.
const DANE_FLAG_NO_DANE_EE_NAMECHECKS: c_ulong = 1;

/// `ERR_R_FATAL` — `include/openssl/err.h.in:354`, `ERR_RFLAG_FATAL | ERR_RFLAG_COMMON`.
const ERR_R_FATAL: c_int = (0x1 << 18) | (0x2 << 18);
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` — `include/openssl/err.h.in:356`.
const ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED: c_int = 257 | ERR_R_FATAL;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:357`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | ERR_R_FATAL;
/// `ERR_R_INTERNAL_ERROR` — `include/openssl/err.h.in:358`.
const ERR_R_INTERNAL_ERROR: c_int = 259 | ERR_R_FATAL;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`.
const ERR_R_CRYPTO_LIB: c_int = 15 | (0x2 << 18);

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
/// The default `ctx->check_issued`; its `ctx` argument is unused (`ossl_unused`).
/// [`X509_STORE_CTX_init`] installs it as the default when the store supplies none.
///
/// # Safety
///
/// `x` and `issuer` must be live.
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
// `crl_extension_match` and `X509_CRL_diff` — `x509_vfy.c:1479-1505`, `:2403-2522`.
// ---------------------------------------------------------------------------------------------

/// `static int crl_extension_match(X509_CRL *a, X509_CRL *b, int nid)` —
/// `crypto/x509/x509_vfy.c:1479-1505`.
///
/// The file-local helper `X509_CRL_diff` uses to require that two CRLs' AKID and IDP extensions
/// agree byte for byte. It refuses a repeated extension.
///
/// # Safety
///
/// `a` and `b` must be live `X509_CRL`.
unsafe fn crl_extension_match(a: *mut X509Crl, b: *mut X509Crl, nid: c_int) -> c_int {
    let mut exta: *mut Asn1String = ptr::null_mut();
    let mut extb: *mut Asn1String = ptr::null_mut();

    // SAFETY: `a` is live per the contract.
    let mut i = unsafe { X509_CRL_get_ext_by_NID(a, nid, -1) };
    if i >= 0 {
        // Can't have multiple occurrences.
        // SAFETY: `a` is live.
        if unsafe { X509_CRL_get_ext_by_NID(a, nid, i) } != -1 {
            return 0;
        }
        // SAFETY: `a` is live; `i` is a valid extension index.
        exta = unsafe { X509_EXTENSION_get_data(X509_CRL_get_ext(a, i)) };
    }

    // SAFETY: `b` is live per the contract.
    i = unsafe { X509_CRL_get_ext_by_NID(b, nid, -1) };
    if i >= 0 {
        // SAFETY: `b` is live.
        if unsafe { X509_CRL_get_ext_by_NID(b, nid, i) } != -1 {
            return 0;
        }
        // SAFETY: `b` is live; `i` is a valid extension index.
        extb = unsafe { X509_EXTENSION_get_data(X509_CRL_get_ext(b, i)) };
    }

    if exta.is_null() && extb.is_null() {
        return 1;
    }
    if exta.is_null() || extb.is_null() {
        return 0;
    }
    // SAFETY: both are live `ASN1_OCTET_STRING`.
    c_int::from(unsafe { ASN1_OCTET_STRING_cmp(exta, extb) } == 0)
}

/// `X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer, EVP_PKEY *skey, const EVP_MD *md, unsigned int flags)`
/// — `crypto/x509/x509_vfy.c:2403-2522`.
///
/// Builds the delta CRL that turns `base` into `newer`: it validates the two are comparable (not
/// already deltas, both numbered, same issuer, matching AKID/IDP, `newer` strictly newer, and, when
/// `skey` is given, both verify), then copies `newer`'s extensions and the revoked entries absent
/// from `base`, and signs with `skey`/`md` when both are supplied. Any failure raises and answers
/// NULL; the `flags` argument is unused by the authority.
///
/// # Safety
///
/// `base` and `newer` must be live `X509_CRL`; `skey`/`md` are NULL or live. The returned CRL is
/// owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_diff(
    base: *mut X509Crl,
    newer: *mut X509Crl,
    skey: *mut EvpPkey,
    md: *const EvpMd,
    _flags: c_uint,
) -> *mut X509Crl {
    // CRLs can't be delta already.
    // SAFETY: `base` and `newer` are live per the contract.
    if unsafe { !(*base).base_crl_number.is_null() || !(*newer).base_crl_number.is_null() } {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2412) };
        return ptr::null_mut();
    }
    // Base and new CRL must have a CRL number.
    // SAFETY: `base` and `newer` are live.
    if unsafe { (*base).crl_number }.is_null() || unsafe { (*newer).crl_number }.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2417) };
        return ptr::null_mut();
    }
    // Issuer names must match.
    // SAFETY: `base` and `newer` are live.
    if unsafe { X509_NAME_cmp(X509_CRL_get_issuer(base), X509_CRL_get_issuer(newer)) } != 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2424) };
        return ptr::null_mut();
    }
    // AKID and IDP must match.
    // SAFETY: `base` and `newer` are live.
    if unsafe { crl_extension_match(base, newer, NID_authority_key_identifier) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2429) };
        return ptr::null_mut();
    }
    // SAFETY: `base` and `newer` are live.
    if unsafe { crl_extension_match(base, newer, NID_issuing_distribution_point) } == 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2434) };
        return ptr::null_mut();
    }
    // Newer CRL number must exceed full CRL number.
    // SAFETY: both numbers are non-null here.
    if unsafe { ASN1_INTEGER_cmp((*newer).crl_number, (*base).crl_number) } <= 0 {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&X509_VFY_2438) };
        return ptr::null_mut();
    }
    // CRLs must verify.
    if !skey.is_null() {
        // SAFETY: `base`, `newer` and `skey` are live.
        if unsafe { X509_CRL_verify(base, skey) <= 0 || X509_CRL_verify(newer, skey) <= 0 } {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&X509_VFY_2443) };
            return ptr::null_mut();
        }
    }

    // Create new CRL.
    // SAFETY: `base` is live.
    let crl = unsafe { X509_CRL_new_ex((*base).libctx, (*base).propq) };
    let mut failed = false;
    'body: {
        // SAFETY: `crl` is NULL or a fresh object; `newer` is live.
        unsafe {
            if crl.is_null() || X509_CRL_set_version(crl, X509_CRL_VERSION_2) == 0 {
                raise_site(&X509_VFY_2449);
                failed = true;
                break 'body;
            }
            // Set issuer name.
            if X509_CRL_set_issuer_name(crl, X509_CRL_get_issuer(newer)) == 0 {
                raise_site(&X509_VFY_2454);
                failed = true;
                break 'body;
            }
            if X509_CRL_set1_lastUpdate(crl, X509_CRL_get0_lastUpdate(newer)) == 0 {
                raise_site(&X509_VFY_2459);
                failed = true;
                break 'body;
            }
            if X509_CRL_set1_nextUpdate(crl, X509_CRL_get0_nextUpdate(newer)) == 0 {
                raise_site(&X509_VFY_2463);
                failed = true;
                break 'body;
            }
            // Set base CRL number: must be critical.
            if X509_CRL_add1_ext_i2d(
                crl,
                NID_delta_crl,
                (*base).crl_number.cast::<c_void>(),
                1,
                0,
            ) <= 0
            {
                raise_site(&X509_VFY_2469);
                failed = true;
                break 'body;
            }

            // Copy extensions across from newest CRL to delta.
            let nunm = X509_CRL_get_ext_count(newer);
            for i in 0..nunm {
                let ext = X509_CRL_get_ext(newer, i);
                if X509_CRL_add_ext(crl, ext, -1) == 0 {
                    raise_site(&X509_VFY_2481);
                    failed = true;
                    break 'body;
                }
            }

            // Go through revoked entries, copying as needed.
            let revs = X509_CRL_get_REVOKED(newer);
            let nrev = OPENSSL_sk_num(revs);
            for i in 0..nrev {
                let rvn = OPENSSL_sk_value(revs, i).cast::<X509Revoked>();
                let mut rvtmp: *mut X509Revoked = ptr::null_mut();
                if X509_CRL_get0_by_serial(base, &raw mut rvtmp, &raw const (*rvn).serialNumber)
                    == 0
                {
                    let dup = X509_REVOKED_dup(rvn);
                    if dup.is_null() {
                        raise_site(&X509_VFY_2501);
                        failed = true;
                        break 'body;
                    }
                    if X509_CRL_add0_revoked(crl, dup) == 0 {
                        X509_REVOKED_free(dup);
                        raise_site(&X509_VFY_2506);
                        failed = true;
                        break 'body;
                    }
                }
            }

            if !skey.is_null() && !md.is_null() && X509_CRL_sign(crl, skey, md) == 0 {
                raise_site(&X509_VFY_2513);
                failed = true;
                break 'body;
            }
        }
    }

    if failed {
        // SAFETY: `crl` is NULL or owned here.
        unsafe { X509_CRL_free(crl) };
        return ptr::null_mut();
    }
    crl
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
// The internal helpers the issuer lookup and the engine share — `x509_vfy.c:162-172`,
// `:2084-2108`.
// ---------------------------------------------------------------------------------------------

/// `static int verify_cb_cert(X509_STORE_CTX *ctx, X509 *x, int depth, int err)` —
/// `x509_vfy.c:162-172`.
///
/// # Safety
///
/// `ctx` must be live; `x` must be NULL or live; `ctx->chain` must be live when `x` is NULL.
pub(crate) unsafe fn verify_cb_cert(
    ctx: *mut X509StoreCtx,
    x: *mut X509,
    depth: c_int,
    err: c_int,
) -> c_int {
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
            // because `X509_STORE_CTX_init` always installs a callback (`null_callback` by default).
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

// =============================================================================================
// The verify engine — `crypto/x509/x509_vfy.c:88-386`, `:547-2074`.
// =============================================================================================

/// `S_DOUNTRUSTED` — `crypto/x509/x509_vfy.c:3530`, `(1 << 0)`.
const S_DOUNTRUSTED: c_uint = 1 << 0;
/// `S_DOTRUSTED` — `crypto/x509/x509_vfy.c:3531`, `(1 << 1)`.
const S_DOTRUSTED: c_uint = 1 << 1;
/// `S_DOALTERNATE` — `crypto/x509/x509_vfy.c:3532`, `(1 << 2)`.
const S_DOALTERNATE: c_uint = 1 << 2;

/// `minbits_table` — `crypto/x509/x509_vfy.c:3901`.
const MINBITS_TABLE: [c_int; 5] = [80, 112, 128, 192, 256];
/// `NUM_AUTH_LEVELS` — `crypto/x509/x509_vfy.c:3902`, `OSSL_NELEM(minbits_table)`.
const NUM_AUTH_LEVELS: c_int = 5;

/// `X509_ADD_FLAG_DEFAULT` — `include/openssl/x509.h:996`, `0`.
const X509_ADD_FLAG_DEFAULT: c_int = 0;
/// `X509_ADD_FLAG_NO_SS` — `include/openssl/x509.h:997`, `0x8`.
const X509_ADD_FLAG_NO_SS: c_int = 0x8;

/// The `X509_CRL_free` element thunk for `sk_X509_CRL_pop_free`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_CRL`.
unsafe extern "C" fn x509_crl_free_void(x: *mut c_void) {
    // SAFETY: `x` is NULL or live per the contract.
    unsafe { X509_CRL_free(x.cast()) };
}

/// The `X509_STORE_CTX_get_issuer_fn` adapter for [`X509_STORE_CTX_get1_issuer`].
///
/// The authority installs the one function pointer (`ctx->get_issuer = X509_STORE_CTX_get1_issuer`,
/// `x509_vfy.c:2785`). The crate models the callback slot's context as `*mut c_void`
/// (`x509_lu.rs`), while the exported lookup takes the concrete `*mut X509StoreCtx`; both pointers
/// are the same width, so this thunk is the one reinterpretation the slot needs.
///
/// # Safety
///
/// The callback contract of [`X509_STORE_CTX_get1_issuer`].
unsafe extern "C" fn get1_issuer_cb(
    issuer: *mut *mut X509,
    ctx: *mut c_void,
    x: *mut X509,
) -> c_int {
    // SAFETY: `ctx` is the `X509StoreCtx` the callback contract promises.
    unsafe { X509_STORE_CTX_get1_issuer(issuer, ctx.cast(), x) }
}

/// The `X509_STORE_CTX_lookup_certs_fn` adapter for [`X509_STORE_CTX_get1_certs`].
///
/// The authority installs the one function pointer (`ctx->lookup_certs = X509_STORE_CTX_get1_certs`,
/// `x509_vfy.c:2825`); the crate's callback slot uses `*mut c_void` while the export takes the
/// concrete `*mut X509StoreCtx`, so this thunk is the one reinterpretation the slot needs.
///
/// # Safety
///
/// The callback contract of [`X509_STORE_CTX_get1_certs`].
unsafe extern "C" fn lookup_certs_cb(ctx: *mut c_void, nm: *const X509Name) -> *mut OpenSslStack {
    // SAFETY: `ctx` is the `X509StoreCtx` the callback contract promises.
    unsafe { X509_STORE_CTX_get1_certs(ctx.cast(), nm) }
}

/// The `X509_STORE_CTX_lookup_crls_fn` adapter for [`X509_STORE_CTX_get1_crls`].
///
/// The authority installs the one function pointer (`ctx->lookup_crls = X509_STORE_CTX_get1_crls`,
/// `x509_vfy.c:2830`); the crate's callback slot uses `*const c_void` while the export takes the
/// concrete `*const X509StoreCtx`, so this thunk is the one reinterpretation the slot needs.
///
/// # Safety
///
/// The callback contract of [`X509_STORE_CTX_get1_crls`].
unsafe extern "C" fn lookup_crls_cb(ctx: *const c_void, nm: *const X509Name) -> *mut OpenSslStack {
    // SAFETY: `ctx` is the `X509StoreCtx` the callback contract promises.
    unsafe { X509_STORE_CTX_get1_crls(ctx.cast(), nm) }
}

/// `static int null_callback(int ok, X509_STORE_CTX *e)` — `crypto/x509/x509_vfy.c:88-91`.
///
/// The default `ctx->verify_cb` [`X509_STORE_CTX_init`] installs. The context parameter is unused
/// (`e` is `ossl_unused` in the authority's spelling); `ok` is forwarded verbatim.
///
/// # Safety
///
/// The authority calls this through `ctx->verify_cb`; `_e` must be the live context the callback
/// contract promises, though it is not read.
unsafe extern "C" fn null_callback(ok: c_int, _e: *mut c_void) -> c_int {
    ok
}

/// `static int lookup_cert_match(X509 **result, X509_STORE_CTX *ctx, X509 *x)` —
/// `crypto/x509/x509_vfy.c:121-151`.
///
/// Looks up every certificate with `x`'s subject name through `ctx->lookup_certs`, then returns the
/// first exact [`X509_cmp`] match with an owned reference. Answers 1 on success, 0 when no exact
/// match exists, and -1 on internal error (a NULL lookup or a failed up-ref).
///
/// # Safety
///
/// `result` must be writable; `ctx` and `x` must be live, and `ctx->lookup_certs` must be the
/// engine-installed callback.
unsafe fn lookup_cert_match(result: *mut *mut X509, ctx: *mut X509StoreCtx, x: *mut X509) -> c_int {
    // SAFETY: `result` is writable per the contract; `ctx` is live, so its callback slot is
    // readable, and `x` is live, so its subject name is readable.
    unsafe {
        *result = ptr::null_mut();
        let subj = X509_get_subject_name(x);
        // `ERR_set_mark`/`ERR_pop_to_mark` bracket the lookup (`:129-131`).
        ERR_set_mark();
        let certs = match (*ctx).lookup_certs {
            Some(cb) => cb(ctx.cast(), subj),
            // The authority calls a NULL pointer here; that is unreachable because only
            // `X509_STORE_CTX_init` installs the callback.
            None => ptr::null_mut(),
        };
        ERR_pop_to_mark();
        if certs.is_null() {
            return -1;
        }

        let mut xtmp: *mut X509 = ptr::null_mut();
        let n = OPENSSL_sk_num(certs);
        let mut i = 0;
        while i < n {
            let cand = OPENSSL_sk_value(certs, i).cast::<X509>();
            if X509_cmp(cand, x) == 0 {
                xtmp = cand;
                break;
            }
            xtmp = ptr::null_mut();
            i += 1;
        }
        let mut ret = c_int::from(!xtmp.is_null());
        if ret != 0 {
            if X509_up_ref(xtmp) == 0 {
                ret = -1;
            } else {
                *result = xtmp;
            }
        }
        OPENSSL_sk_pop_free(certs, Some(x509_free_void));
        ret
    }
}

/// `static int verify_cb_crl(X509_STORE_CTX *ctx, int err)` — `crypto/x509/x509_vfy.c:185-189`.
///
/// # Safety
///
/// `ctx` must be live with a live `verify_cb` slot.
unsafe fn verify_cb_crl(ctx: *mut X509StoreCtx, err: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).error = err;
        match (*ctx).verify_cb {
            Some(cb) => cb(0, ctx.cast()),
            None => 0,
        }
    }
}

/// `static int verify_cb_ocsp(X509_STORE_CTX *ctx, int err)` — `crypto/x509/x509_vfy.c:201-205`.
///
/// # Safety
///
/// `ctx` must be live with a live `verify_cb` slot.
unsafe fn verify_cb_ocsp(ctx: *mut X509StoreCtx, err: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        (*ctx).error = err;
        match (*ctx).verify_cb {
            Some(cb) => cb(0, ctx.cast()),
            None => 0,
        }
    }
}

/// `static int check_auth_level(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:209-234`.
///
/// Returns 0 also on internal error in `ctx->verify_cb`.
///
/// # Safety
///
/// `ctx` must be live with a live `param` and `chain`.
unsafe fn check_auth_level(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract, so its param and chain are live.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        if (*param).auth_level <= 0 {
            return 1;
        }
        let num = OPENSSL_sk_num((*ctx).chain);
        let mut i = 0;
        while i < num {
            let cert = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
            if i > 0
                && check_cert_key_level(ctx, cert) == 0
                && verify_cb_cert(ctx, cert, i, X509_V_ERR_CA_KEY_TOO_SMALL) == 0
            {
                return 0;
            }
            if i < num - 1
                && check_sig_level(ctx, cert) == 0
                && verify_cb_cert(ctx, cert, i, X509_V_ERR_CA_MD_TOO_WEAK) == 0
            {
                return 0;
            }
            i += 1;
        }
        1
    }
}

/// `static int verify_rpk(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:240-247`.
///
/// # Safety
///
/// `ctx` must be live with a live `verify_cb` (and, when non-NULL, `verify`) slot.
unsafe fn verify_rpk(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        if let Some(cb) = (*ctx).verify {
            return cb(ctx.cast());
        }
        match (*ctx).verify_cb {
            Some(cb) => c_int::from(cb(c_int::from((*ctx).error == X509_V_OK), ctx.cast()) != 0),
            None => 0,
        }
    }
}

/// `static int verify_chain(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:253-290`.
///
/// Returns -1 on internal error; returns 0 also on internal error in `ctx->verify_cb`.
///
/// # Safety
///
/// `ctx` must be live and initialised, with a live `param` and `chain`.
unsafe fn verify_chain(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live and initialised per the contract, so every field and callback slot is
    // live; the callees obey their own contracts.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut ok = build_chain(ctx);
        if ok <= 0 {
            return ok;
        }
        ok = check_extensions(ctx);
        if ok <= 0 {
            return ok;
        }
        ok = check_auth_level(ctx);
        if ok <= 0 {
            return ok;
        }
        ok = check_id(ctx);
        if ok <= 0 {
            return ok;
        }
        ok = if X509_get_pubkey_parameters(ptr::null_mut(), (*ctx).chain) != 0 {
            1
        } else {
            -1
        };
        if ok <= 0 {
            return ok;
        }
        ok = match (*ctx).check_revocation {
            Some(cb) => cb(ctx.cast()),
            None => 0,
        };
        if ok <= 0 {
            return ok;
        }

        let err = X509_chain_check_suiteb(
            &raw mut (*ctx).error_depth,
            ptr::null_mut(),
            (*ctx).chain,
            (*param).flags,
        );
        if err != X509_V_OK && verify_cb_cert(ctx, ptr::null_mut(), (*ctx).error_depth, err) == 0 {
            return 0;
        }

        ok = match (*ctx).verify {
            Some(cb) => cb(ctx.cast()),
            None => internal_verify(ctx.cast()),
        };
        if ok <= 0 {
            return ok;
        }

        ok = check_name_constraints(ctx);
        if ok <= 0 {
            return ok;
        }

        ok = X509v3_asid_validate_path(ctx);
        if ok <= 0 {
            return ok;
        }
        ok = X509v3_addr_validate_path(ctx);
        if ok <= 0 {
            return ok;
        }

        if ((*param).flags & X509_V_FLAG_POLICY_CHECK) != 0 {
            ok = match (*ctx).check_policy {
                Some(cb) => cb(ctx.cast()),
                None => 0,
            };
        }
        ok
    }
}

/// `static int x509_verify_rpk(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:318-340`.
///
/// # Safety
///
/// `ctx` must be live, with a live `rpk`, `dane` and `param`.
unsafe fn x509_verify_rpk(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; its `rpk` and `dane` are as installed.
    unsafe {
        if check_key_level(ctx, (*ctx).rpk) == 0
            && verify_cb_cert(ctx, ptr::null_mut(), 0, X509_V_ERR_EE_KEY_TOO_SMALL) == 0
        {
            return 0;
        }
        (*ctx).error = X509_V_ERR_RPK_UNTRUSTED;
        let ret = if danetls_enabled((*ctx).dane.cast::<SslDane>()) {
            dane_verify_rpk(ctx)
        } else {
            verify_rpk(ctx)
        };
        if ret <= 0 && (*ctx).error == X509_V_OK {
            (*ctx).error = X509_V_ERR_UNSPECIFIED;
        }
        ret
    }
}

/// `static int x509_verify_x509(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:346-386`.
///
/// # Safety
///
/// `ctx` must be live, with a live `dane` and `param`.
unsafe fn x509_verify_x509(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the add builds its own chain and the callees obey
    // their own contracts.
    unsafe {
        if (*ctx).cert.is_null() {
            raise_site(&X509_VFY_351);
            (*ctx).error = X509_V_ERR_INVALID_CALL;
            return -1;
        }
        if !(*ctx).chain.is_null() {
            raise_site(&X509_VFY_361);
            (*ctx).error = X509_V_ERR_INVALID_CALL;
            return -1;
        }
        if ossl_x509_add_cert_new(&raw mut (*ctx).chain, (*ctx).cert, X509_ADD_FLAG_UP_REF) == 0 {
            (*ctx).error = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }
        (*ctx).num_untrusted = 1;

        if check_cert_key_level(ctx, (*ctx).cert) == 0
            && verify_cb_cert(ctx, (*ctx).cert, 0, X509_V_ERR_EE_KEY_TOO_SMALL) == 0
        {
            return 0;
        }

        let ret = if danetls_enabled((*ctx).dane.cast::<SslDane>()) {
            dane_verify(ctx)
        } else {
            verify_chain(ctx)
        };
        if ret <= 0 && (*ctx).error == X509_V_OK {
            (*ctx).error = X509_V_ERR_UNSPECIFIED;
        }
        ret
    }
}

// ---------------------------------------------------------------------------------------------
// The purpose, extension, name, trust, revocation and policy checks — `x509_vfy.c:547-1277`,
// `:1996-2074`.
// ---------------------------------------------------------------------------------------------

/// `static int check_purpose(X509_STORE_CTX *ctx, X509 *x, int purpose, int depth, int
/// must_be_ca)` — `crypto/x509/x509_vfy.c:547-592`.
///
/// # Safety
///
/// `ctx` and `x` must be live, with a live `param`.
unsafe fn check_purpose(
    ctx: *mut X509StoreCtx,
    x: *mut X509,
    purpose: c_int,
    depth: c_int,
    must_be_ca: c_int,
) -> c_int {
    // SAFETY: `ctx` and `x` are live per the contract; the callees obey their own contracts.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut tr_ok = X509_TRUST_UNTRUSTED;

        if depth >= (*ctx).num_untrusted && purpose == (*param).purpose {
            tr_ok = X509_check_trust(x, (*param).trust, X509_TRUST_NO_SS_COMPAT);
        }

        match tr_ok {
            X509_TRUST_TRUSTED => return 1,
            X509_TRUST_REJECTED => {}
            _ => match X509_check_purpose(x, purpose, c_int::from(must_be_ca > 0)) {
                1 => return 1,
                0 => {}
                _ => {
                    if ((*param).flags & X509_V_FLAG_X509_STRICT) == 0 {
                        return 1;
                    }
                }
            },
        }

        verify_cb_cert(ctx, x, depth, X509_V_ERR_INVALID_PURPOSE)
    }
}

/// `static int check_extensions(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:598-770`.
///
/// # Safety
///
/// `ctx` must be live with a live `param` and `chain`; each chain element must be a live `X509`.
unsafe fn check_extensions(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract, so its param and chain are live; every chain element
    // and every callee is live per its own contract.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut must_be_ca = -1;
        let mut plen = 0;
        let mut proxy_path_length = 0;
        let num = OPENSSL_sk_num((*ctx).chain);

        let (allow_proxy_certs, purpose);
        if !(*ctx).parent.is_null() {
            allow_proxy_certs = 0;
            purpose = X509_PURPOSE_CRL_SIGN;
        } else {
            allow_proxy_certs = c_int::from(((*param).flags & X509_V_FLAG_ALLOW_PROXY_CERTS) != 0);
            purpose = (*param).purpose;
        }

        let mut i = 0;
        while i < num {
            let x = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
            if ((*param).flags & X509_V_FLAG_IGNORE_CRITICAL) == 0
                && ((*x).ex_flags & EXFLAG_CRITICAL) != 0
                && verify_cb_cert(ctx, x, i, X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) == 0
            {
                return 0;
            }
            if allow_proxy_certs == 0
                && ((*x).ex_flags & EXFLAG_PROXY) != 0
                && verify_cb_cert(ctx, x, i, X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED) == 0
            {
                return 0;
            }
            let mut ret = X509_check_ca(x);
            match must_be_ca {
                -1 => {
                    if ((*param).flags & X509_V_FLAG_X509_STRICT) != 0
                        && ret != 1
                        && ret != 0
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_INVALID_CA) == 0
                    {
                        return 0;
                    }
                }
                0 => {
                    if ret != 0 && verify_cb_cert(ctx, x, i, X509_V_ERR_INVALID_NON_CA) == 0 {
                        return 0;
                    }
                }
                _ => {
                    if (ret == 0
                        || ((i + 1 < num || ((*param).flags & X509_V_FLAG_X509_STRICT) != 0)
                            && ret != 1))
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_INVALID_CA) == 0
                    {
                        return 0;
                    }
                }
            }
            if num > 1 {
                ret = check_curve(x);
                if ret < 0 && verify_cb_cert(ctx, x, i, X509_V_ERR_UNSPECIFIED) == 0 {
                    return 0;
                }
                if ret == 0 && verify_cb_cert(ctx, x, i, X509_V_ERR_EC_KEY_EXPLICIT_PARAMS) == 0 {
                    return 0;
                }
            }
            if ((*param).flags & X509_V_FLAG_X509_STRICT) != 0 && num > 1 {
                if (*x).ex_pathlen != -1 {
                    if ((*x).ex_flags & EXFLAG_CA) == 0
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA) == 0
                    {
                        return 0;
                    }
                    if ((*x).ex_kusage & KU_KEY_CERT_SIGN) == 0
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN)
                            == 0
                    {
                        return 0;
                    }
                }
                if ((*x).ex_flags & EXFLAG_CA) != 0
                    && ((*x).ex_flags & EXFLAG_BCONS) != 0
                    && ((*x).ex_flags & EXFLAG_BCONS_CRITICAL) == 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_CA_BCONS_NOT_CRITICAL) == 0
                {
                    return 0;
                }
                if ((*x).ex_flags & EXFLAG_CA) != 0 {
                    if ((*x).ex_flags & EXFLAG_KUSAGE) == 0
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_CA_CERT_MISSING_KEY_USAGE) == 0
                    {
                        return 0;
                    }
                } else if ((*x).ex_kusage & KU_KEY_CERT_SIGN) != 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA)
                        == 0
                {
                    return 0;
                }
                if X509_NAME_entry_count(X509_get_issuer_name(x)) == 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_ISSUER_NAME_EMPTY) == 0
                {
                    return 0;
                }
                if (((*x).ex_flags & EXFLAG_CA) != 0
                    || ((*x).ex_kusage & KU_CRL_SIGN) != 0
                    || (*x).altname.is_null())
                    && X509_NAME_entry_count(X509_get_subject_name(x)) == 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_SUBJECT_NAME_EMPTY) == 0
                {
                    return 0;
                }
                if X509_NAME_entry_count(X509_get_subject_name(x)) == 0
                    && !(*x).altname.is_null()
                    && ((*x).ex_flags & EXFLAG_SAN_CRITICAL) == 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL) == 0
                {
                    return 0;
                }
                if !(*x).altname.is_null()
                    && OPENSSL_sk_num((*x).altname.cast::<OpenSslStack>()) <= 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_EMPTY_SUBJECT_ALT_NAME) == 0
                {
                    return 0;
                }
                if X509_ALGOR_cmp(&raw const (*x).sig_alg, &raw const (*x).cert_info.signature) != 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY) == 0
                {
                    return 0;
                }
                if !(*x).akid.is_null()
                    && ((*x).ex_flags & EXFLAG_AKID_CRITICAL) != 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL) == 0
                {
                    return 0;
                }
                if !(*x).skid.is_null()
                    && ((*x).ex_flags & EXFLAG_SKID_CRITICAL) != 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL) == 0
                {
                    return 0;
                }
                if X509_get_version(x) >= X509_VERSION_3 {
                    let akid = (*x).akid.cast::<AuthorityKeyid>();
                    if i + 1 < num
                        && (akid.is_null() || (*akid).keyid.is_null())
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER)
                            == 0
                    {
                        return 0;
                    }
                    if ((*x).ex_flags & EXFLAG_CA) != 0
                        && (*x).skid.is_null()
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER) == 0
                    {
                        return 0;
                    }
                } else if OPENSSL_sk_num(X509_get0_extensions(x).cast::<OpenSslStack>()) > 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3) == 0
                {
                    return 0;
                }
            }

            if purpose >= X509_PURPOSE_MIN && check_purpose(ctx, x, purpose, i, must_be_ca) == 0 {
                return 0;
            }
            if i > 1
                && (*x).ex_pathlen != -1
                && c_long::from(plen) > (*x).ex_pathlen + c_long::from(proxy_path_length)
                && verify_cb_cert(ctx, x, i, X509_V_ERR_PATH_LENGTH_EXCEEDED) == 0
            {
                return 0;
            }
            if i > 0 && ((*x).ex_flags & EXFLAG_SI) == 0 {
                plen += 1;
            }
            if ((*x).ex_flags & EXFLAG_PROXY) != 0 {
                if (*x).ex_pcpathlen != -1 {
                    if c_long::from(proxy_path_length) > (*x).ex_pcpathlen
                        && verify_cb_cert(ctx, x, i, X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED) == 0
                    {
                        return 0;
                    }
                    proxy_path_length = (*x).ex_pcpathlen as c_int;
                }
                proxy_path_length += 1;
                must_be_ca = 0;
            } else {
                must_be_ca = 1;
            }
            i += 1;
        }
        1
    }
}

/// `static int has_san_id(X509 *x, int gtype)` — `crypto/x509/x509_vfy.c:772-791`.
///
/// # Safety
///
/// `x` must be live.
unsafe fn has_san_id(x: *mut X509, gtype: c_int) -> c_int {
    // SAFETY: `x` is live per the contract; the extension lookup answers an owned stack or NULL.
    unsafe {
        let mut ret = 0;
        let gs = X509_get_ext_d2i(x, NID_subject_alt_name, ptr::null_mut(), ptr::null_mut())
            .cast::<OpenSslStack>();
        if gs.is_null() {
            return 0;
        }
        let n = OPENSSL_sk_num(gs);
        let mut i = 0;
        while i < n {
            let g = OPENSSL_sk_value(gs, i).cast::<GeneralName>();
            if (*g).type_ == gtype {
                ret = 1;
                break;
            }
            i += 1;
        }
        GENERAL_NAMES_free(gs);
        ret
    }
}

/// `static int check_name_constraints(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:797-916`.
///
/// # Safety
///
/// `ctx` must be live with a live `chain` and `param`.
unsafe fn check_name_constraints(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract, so its chain and param are live; every chain element
    // and callee is live per its own contract.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut i = OPENSSL_sk_num((*ctx).chain) - 1;
        while i >= 0 {
            let x = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();

            if i != 0 && ((*x).ex_flags & EXFLAG_SI) != 0 {
                i -= 1;
                continue;
            }

            if ((*x).ex_flags & EXFLAG_PROXY) != 0 {
                let tmpsubject = X509_get_subject_name(x);
                let tmpissuer = X509_get_issuer_name(x);
                let mut err = X509_V_OK;
                let last_loc = X509_NAME_entry_count(tmpsubject) - 1;

                if last_loc < 1
                    || X509_NAME_entry_count(tmpsubject) != X509_NAME_entry_count(tmpissuer) + 1
                    || X509_NAME_ENTRY_set(X509_NAME_get_entry(tmpsubject, last_loc))
                        == X509_NAME_ENTRY_set(X509_NAME_get_entry(tmpsubject, last_loc - 1))
                {
                    err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                } else {
                    let dup = X509_NAME_dup(tmpsubject);
                    if dup.is_null() {
                        raise_site(&X509_VFY_857);
                        (*ctx).error = X509_V_ERR_OUT_OF_MEM;
                        return -1;
                    }
                    let tmpentry = X509_NAME_delete_entry(dup, last_loc);
                    let last_nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(tmpentry));
                    if last_nid != NID_commonName || X509_NAME_cmp(dup, tmpissuer) != 0 {
                        err = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION;
                    }
                    X509_NAME_ENTRY_free(tmpentry);
                    X509_NAME_free(dup);
                }

                if err != X509_V_OK && verify_cb_cert(ctx, x, i, err) == 0 {
                    return 0;
                }
            }

            let mut j = OPENSSL_sk_num((*ctx).chain) - 1;
            while j > i {
                let nc = OPENSSL_sk_value((*ctx).chain, j).cast::<X509>();
                let nc = (*nc).nc.cast::<NameConstraints>();
                if !nc.is_null() {
                    let mut rv = NAME_CONSTRAINTS_check(x, nc);
                    let mut ret = 1;
                    if rv == X509_V_OK
                        && i == 0
                        && ((*param).hostflags & X509_CHECK_FLAG_NEVER_CHECK_SUBJECT) == 0
                        && (((*param).hostflags & X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT) != 0 || {
                            ret = has_san_id(x, GEN_DNS);
                            ret == 0
                        })
                    {
                        rv = NAME_CONSTRAINTS_check_CN(x, nc);
                    }
                    if ret < 0 {
                        return ret;
                    }
                    match rv {
                        X509_V_OK => {}
                        X509_V_ERR_OUT_OF_MEM => return -1,
                        _ => {
                            if verify_cb_cert(ctx, x, i, rv) == 0 {
                                return 0;
                            }
                        }
                    }
                }
                j -= 1;
            }
            i -= 1;
        }
        1
    }
}

/// `static int check_id_error(X509_STORE_CTX *ctx, int errcode)` — `crypto/x509/x509_vfy.c:918-921`.
///
/// # Safety
///
/// `ctx` must be live with a live `cert`.
unsafe fn check_id_error(ctx: *mut X509StoreCtx, errcode: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract, so its `cert` is as installed.
    unsafe { verify_cb_cert(ctx, (*ctx).cert, 0, errcode) }
}

/// `static int check_hosts(X509 *x, X509_VERIFY_PARAM *vpm)` — `crypto/x509/x509_vfy.c:923-939`.
///
/// # Safety
///
/// `x` must be live; `vpm` must be live with a NULL or live `hosts` stack and writable `peername`.
unsafe fn check_hosts(x: *mut X509, vpm: *mut X509VerifyParam) -> c_int {
    // SAFETY: `vpm` is live per the contract; `x` is live; the host checker obeys its contract.
    unsafe {
        let n = OPENSSL_sk_num((*vpm).hosts);
        if !(*vpm).peername.is_null() {
            CRYPTO_free((*vpm).peername.cast(), FILE.as_ptr(), 930);
            (*vpm).peername = ptr::null_mut();
        }
        let mut i = 0;
        while i < n {
            let name = OPENSSL_sk_value((*vpm).hosts, i).cast::<c_char>();
            if X509_check_host(x, name, 0, (*vpm).hostflags, &raw mut (*vpm).peername) > 0 {
                return 1;
            }
            i += 1;
        }
        c_int::from(n == 0)
    }
}

/// `static int check_id(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:941-960`.
///
/// # Safety
///
/// `ctx` must be live with a live `param` and `cert`.
unsafe fn check_id(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract, so its param and cert are live; the callees obey
    // their own contracts.
    unsafe {
        let vpm = (*ctx).param.cast::<X509VerifyParam>();
        let x = (*ctx).cert;

        if !(*vpm).hosts.is_null()
            && check_hosts(x, vpm) <= 0
            && check_id_error(ctx, X509_V_ERR_HOSTNAME_MISMATCH) == 0
        {
            return 0;
        }
        if !(*vpm).email.is_null()
            && X509_check_email(x, (*vpm).email, (*vpm).emaillen, 0) <= 0
            && check_id_error(ctx, X509_V_ERR_EMAIL_MISMATCH) == 0
        {
            return 0;
        }
        if !(*vpm).ip.is_null()
            && X509_check_ip(x, (*vpm).ip, (*vpm).iplen, 0) <= 0
            && check_id_error(ctx, X509_V_ERR_IP_ADDRESS_MISMATCH) == 0
        {
            return 0;
        }
        1
    }
}

/// `static int check_trust(X509_STORE_CTX *ctx, int num_untrusted)` — `crypto/x509/x509_vfy.c:963-1059`.
///
/// The `trusted:` and `rejected:` labels are folded into a labelled block; the body is otherwise the
/// authority's line for line.
///
/// # Safety
///
/// `ctx` must be live with a live `chain`, `param` and `dane` (NULL or live).
unsafe fn check_trust(ctx: *mut X509StoreCtx, num_untrusted: c_int) -> c_int {
    // SAFETY: `ctx` is live per the contract; the callees obey their own contracts.
    unsafe {
        let dane = (*ctx).dane.cast::<SslDane>();
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let num = OPENSSL_sk_num((*ctx).chain);
        let mut x: *mut X509 = ptr::null_mut();
        let mut i: c_int = num_untrusted;
        let mut trusted = false;
        let mut rejected = false;

        'decide: {
            if danetls_has_ta(dane) && num_untrusted > 0 && num_untrusted < num {
                let trust = check_dane_issuer(ctx, num_untrusted);
                if trust != X509_TRUST_UNTRUSTED {
                    return trust;
                }
            }

            while i < num {
                x = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
                let trust = X509_check_trust(x, (*param).trust, 0);
                if trust == X509_TRUST_TRUSTED {
                    trusted = true;
                    break 'decide;
                }
                if trust == X509_TRUST_REJECTED {
                    rejected = true;
                    break 'decide;
                }
                i += 1;
            }

            if num_untrusted < num {
                if ((*param).flags & X509_V_FLAG_PARTIAL_CHAIN) != 0 {
                    trusted = true;
                    break 'decide;
                }
                return X509_TRUST_UNTRUSTED;
            }

            if num_untrusted == num && ((*param).flags & X509_V_FLAG_PARTIAL_CHAIN) != 0 {
                i = 0;
                x = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
                let mut mx: *mut X509 = ptr::null_mut();
                let res = lookup_cert_match(&raw mut mx, ctx, x);
                if res < 0 {
                    return res;
                }
                if res == 0 {
                    return X509_TRUST_UNTRUSTED;
                }
                let trust = X509_check_trust(mx, (*param).trust, 0);
                if trust == X509_TRUST_REJECTED {
                    X509_free(mx);
                    rejected = true;
                    break 'decide;
                }
                OPENSSL_sk_set((*ctx).chain, 0, mx.cast());
                X509_free(x);
                (*ctx).num_untrusted = 0;
                trusted = true;
            }
        }

        if rejected {
            return if verify_cb_cert(ctx, x, i, X509_V_ERR_CERT_REJECTED) == 0 {
                X509_TRUST_REJECTED
            } else {
                X509_TRUST_UNTRUSTED
            };
        }
        if trusted {
            if !danetls_enabled(dane) {
                return X509_TRUST_TRUSTED;
            }
            if (*dane).pdpth < 0 {
                (*dane).pdpth = num_untrusted;
            }
            if (*dane).mdpth >= 0 {
                return X509_TRUST_TRUSTED;
            }
            return X509_TRUST_UNTRUSTED;
        }
        X509_TRUST_UNTRUSTED
    }
}

/// `static int check_revocation(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:1062-1171`.
///
/// # Safety
///
/// `ctx` must be live; the authority installs it as `ctx->check_revocation`.
unsafe extern "C" fn check_revocation(ctx: *mut c_void) -> c_int {
    // SAFETY: `ctx` is the live context the callback contract promises.
    unsafe {
        let ctx = ctx.cast::<X509StoreCtx>();
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut i = 0;
        let mut last = 0;
        let mut ok;
        let crl_check_enabled = ((*param).flags & X509_V_FLAG_CRL_CHECK) != 0;
        let crl_check_all_enabled =
            crl_check_enabled && ((*param).flags & X509_V_FLAG_CRL_CHECK_ALL) != 0;
        let ocsp_check_enabled = ((*param).flags & X509_V_FLAG_OCSP_RESP_CHECK) != 0;
        let ocsp_check_all_enabled =
            ocsp_check_enabled && ((*param).flags & X509_V_FLAG_OCSP_RESP_CHECK_ALL) != 0;

        if !crl_check_enabled && !ocsp_check_enabled {
            return 1;
        }

        if ocsp_check_enabled {
            if ocsp_check_all_enabled {
                last = OPENSSL_sk_num((*ctx).chain) - 1;
            } else if !crl_check_all_enabled && !(*ctx).parent.is_null() {
                return 1;
            }

            while i <= last {
                (*ctx).error_depth = i;
                (*ctx).current_cert = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
                if ((*(*ctx).current_cert).ex_flags & EXFLAG_SS) != 0 {
                    i += 1;
                    continue;
                }
                (*ctx).current_issuer = OPENSSL_sk_value((*ctx).chain, i + 1).cast::<X509>();
                if (*ctx).current_issuer.is_null() {
                    if ((*param).flags & X509_V_FLAG_PARTIAL_CHAIN) != 0 {
                        i += 1;
                        continue;
                    }
                    return verify_cb_ocsp(ctx, X509_V_ERR_OCSP_VERIFY_FAILED);
                }

                ok = check_cert_ocsp_resp(ctx);
                if ok == V_OCSP_CERTSTATUS_REVOKED {
                    return verify_cb_ocsp(
                        ctx,
                        if (*ctx).error != 0 {
                            (*ctx).error
                        } else {
                            X509_V_ERR_OCSP_VERIFY_FAILED
                        },
                    );
                }
                if ok == V_OCSP_CERTSTATUS_GOOD {
                    i += 1;
                    continue;
                }
                if crl_check_all_enabled || (crl_check_enabled && i == 0) {
                    ok = check_cert_crl(ctx);
                    if ok == 0 {
                        return ok;
                    }
                } else {
                    ok = verify_cb_ocsp(ctx, X509_V_ERR_OCSP_VERIFY_FAILED);
                    if ok == 0 {
                        return ok;
                    }
                }
                i += 1;
            }
        }

        if crl_check_enabled && !ocsp_check_all_enabled {
            if crl_check_all_enabled {
                last = OPENSSL_sk_num((*ctx).chain) - 1;
            } else {
                if !(*ctx).parent.is_null() {
                    return 1;
                }
                last = 0;
            }
            if ocsp_check_enabled && crl_check_all_enabled {
                i = 1;
            } else {
                i = 0;
            }
            while i <= last {
                (*ctx).error_depth = i;
                ok = check_cert_crl(ctx);
                if ok == 0 {
                    return ok;
                }
                i += 1;
            }
        }
        1
    }
}

/// `static int check_cert_ocsp_resp(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:1174-1277`.
///
/// The authority's `end:` label is folded into a labelled block whose cleanup runs once.
///
/// # Safety
///
/// `ctx` must be live with a live `ocsp_resp` stack, `chain`, `store` and `param`.
unsafe fn check_cert_ocsp_resp(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the OCSP callees obey their own contracts.
    unsafe {
        let mut cert_id: *mut OcspCertId = ptr::null_mut();
        let ret: c_int;

        let mut num = OPENSSL_sk_num((*ctx).ocsp_resp);
        if num < 0 || num <= (*ctx).error_depth {
            return X509_V_ERR_OCSP_NO_RESPONSE;
        }

        let resp = OPENSSL_sk_value((*ctx).ocsp_resp, (*ctx).error_depth).cast::<OcspResponse>();
        if resp.is_null() {
            return X509_V_ERR_OCSP_NO_RESPONSE;
        }
        let mut bs = OCSP_response_get1_basic(resp);
        if bs.is_null() {
            return X509_V_ERR_OCSP_NO_RESPONSE;
        }

        'end: {
            num = OCSP_resp_count(bs);
            if num < 1 {
                ret = X509_V_ERR_OCSP_NO_RESPONSE;
                break 'end;
            }

            if OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL {
                OCSP_BASICRESP_free(bs);
                bs = ptr::null_mut();
                ret = X509_V_ERR_OCSP_RESP_INVALID;
                break 'end;
            }

            if OCSP_basic_verify(bs, (*ctx).chain, (*ctx).store, 0) <= 0 {
                ret = X509_V_ERR_OCSP_SIGNATURE_FAILURE;
                break 'end;
            }

            let mut i = 0;
            while i < num {
                let sr = OCSP_resp_get0(bs, i);
                let sr_cert_id = OCSP_SINGLERESP_get0_id(sr) as *mut OcspCertId;
                let mut cert_id_md_oid: *mut Asn1Object = ptr::null_mut();
                OCSP_id_get0_info(
                    ptr::null_mut(),
                    &raw mut cert_id_md_oid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    sr_cert_id,
                );
                // `EVP_get_digestbyobj(a)` is `EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(a)))`
                // (`include/openssl/evp.h:548`), transcribed explicitly.
                let cert_id_md = if !cert_id_md_oid.is_null() {
                    EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(cert_id_md_oid)))
                } else {
                    ptr::null()
                };

                cert_id = OCSP_cert_to_id(cert_id_md, (*ctx).current_cert, (*ctx).current_issuer);
                if cert_id.is_null() {
                    ret = X509_V_ERR_OCSP_RESP_INVALID;
                    break 'end;
                }

                if OCSP_id_cmp(cert_id, sr_cert_id) == 0 {
                    break;
                }

                OCSP_CERTID_free(cert_id);
                cert_id = ptr::null_mut();
                i += 1;
            }

            if cert_id.is_null() {
                ret = X509_V_ERR_OCSP_NO_RESPONSE;
                break 'end;
            }

            let mut cert_status: c_int = 0;
            let mut crl_reason: c_int = 0;
            let mut rev: *mut Asn1String = ptr::null_mut();
            let mut thisupd: *mut Asn1String = ptr::null_mut();
            let mut nextupd: *mut Asn1String = ptr::null_mut();
            if OCSP_resp_find_status(
                bs,
                cert_id,
                &raw mut cert_status,
                &raw mut crl_reason,
                &raw mut rev,
                &raw mut thisupd,
                &raw mut nextupd,
            ) <= 0
            {
                ret = X509_V_ERR_OCSP_RESP_INVALID;
                break 'end;
            }

            if cert_status == V_OCSP_CERTSTATUS_GOOD {
                if OCSP_check_validity(thisupd, nextupd, 300, -1) == 0 {
                    ret = X509_V_ERR_OCSP_HAS_EXPIRED;
                } else {
                    ret = V_OCSP_CERTSTATUS_GOOD;
                }
            } else {
                ret = cert_status;
            }
        }

        OCSP_CERTID_free(cert_id);
        OCSP_BASICRESP_free(bs);
        ret
    }
}

/// `static int check_policy(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:1996-2074`.
///
/// # Safety
///
/// `ctx` must be live; the authority installs it as `ctx->check_policy`.
unsafe extern "C" fn check_policy(ctx: *mut c_void) -> c_int {
    // SAFETY: `ctx` is the live context the callback contract promises.
    unsafe {
        let ctx = ctx.cast::<X509StoreCtx>();
        if !(*ctx).parent.is_null() {
            return 1;
        }
        let param = (*ctx).param.cast::<X509VerifyParam>();

        if (*ctx).bare_ta_signed != 0 && OPENSSL_sk_push((*ctx).chain, ptr::null()) == 0 {
            raise_site(&X509_VFY_2014);
            (*ctx).error = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }
        let ret = X509_policy_check(
            (&raw mut (*ctx).tree).cast::<*mut X509PolicyTree>(),
            &raw mut (*ctx).explicit_policy,
            (*ctx).chain,
            (*param).policies,
            (*param).flags as c_uint,
        );
        if (*ctx).bare_ta_signed != 0 {
            OPENSSL_sk_pop((*ctx).chain);
        }

        if ret == X509_PCY_TREE_INTERNAL {
            raise_site(&X509_VFY_2023);
            (*ctx).error = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }
        if ret == X509_PCY_TREE_INVALID {
            let mut cbcalled = 0;
            let n = OPENSSL_sk_num((*ctx).chain);
            let mut i = 0;
            while i < n {
                let x = OPENSSL_sk_value((*ctx).chain, i).cast::<X509>();
                if ((*x).ex_flags & EXFLAG_INVALID_POLICY) != 0 {
                    cbcalled = 1;
                }
                if ((*x).ex_flags & EXFLAG_INVALID_POLICY) != 0
                    && verify_cb_cert(ctx, x, i, X509_V_ERR_INVALID_POLICY_EXTENSION) == 0
                {
                    return 0;
                }
                i += 1;
            }
            if cbcalled == 0 {
                raise_site(&X509_VFY_2041);
                return 0;
            }
            return 1;
        }
        if ret == X509_PCY_TREE_FAILURE {
            (*ctx).current_cert = ptr::null_mut();
            (*ctx).error = X509_V_ERR_NO_EXPLICIT_POLICY;
            return match (*ctx).verify_cb {
                Some(cb) => cb(0, ctx.cast()),
                None => 0,
            };
        }
        if ret != X509_PCY_TREE_VALID {
            raise_site(&X509_VFY_2053);
            return 0;
        }

        if ((*param).flags & X509_V_FLAG_NOTIFY_POLICY) != 0 {
            (*ctx).current_cert = ptr::null_mut();
            let ok = match (*ctx).verify_cb {
                Some(cb) => cb(2, ctx.cast()),
                None => 0,
            };
            if ok == 0 {
                return 0;
            }
        }
        1
    }
}

// ---------------------------------------------------------------------------------------------
// The CRL cluster — `crypto/x509/x509_vfy.c:1281-1993`.
// ---------------------------------------------------------------------------------------------

/// `static int check_cert_crl(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:1281-1365`.
///
/// The authority's `done:` label is folded into a labelled block whose cleanup runs once.
///
/// # Safety
///
/// `ctx` must be live with a live `chain`, `param` and CRL callback slots.
unsafe fn check_cert_crl(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the CRL callees obey their own contracts.
    unsafe {
        let mut crl: *mut X509Crl = ptr::null_mut();
        let mut dcrl: *mut X509Crl = ptr::null_mut();
        let mut ok: c_int = 0;
        let cnum = (*ctx).error_depth;
        let x = OPENSSL_sk_value((*ctx).chain, cnum).cast::<X509>();

        (*ctx).current_cert = x;
        (*ctx).current_issuer = ptr::null_mut();
        (*ctx).current_crl_score = 0;
        (*ctx).current_reasons = 0;

        if ((*(*ctx).current_cert).ex_flags & EXFLAG_SS) != 0 {
            return 1;
        }
        if ((*x).ex_flags & EXFLAG_PROXY) != 0 {
            return 1;
        }

        'done: {
            while (*ctx).current_reasons != CRLDP_ALL_REASONS {
                let last_reasons = (*ctx).current_reasons;

                if let Some(get_crl) = (*ctx).get_crl {
                    let mut crl_issuer: *mut X509 = ptr::null_mut();
                    let mut reasons: c_uint = 0;
                    ok = get_crl(ctx.cast(), &raw mut crl, x);
                    if !crl.is_null() {
                        (*ctx).current_crl_score =
                            get_crl_score(ctx, &raw mut crl_issuer, &raw mut reasons, crl, x);
                        (*ctx).current_issuer = crl_issuer;
                        (*ctx).current_reasons = reasons;
                    }
                } else {
                    ok = get_crl_delta(ctx, &raw mut crl, &raw mut dcrl, x);
                }
                if ok == 0 {
                    ok = verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
                    break 'done;
                }
                (*ctx).current_crl = crl;
                ok = match (*ctx).check_crl {
                    Some(cb) => cb(ctx.cast(), crl),
                    None => 0,
                };
                if ok == 0 {
                    break 'done;
                }

                if !dcrl.is_null() {
                    ok = match (*ctx).check_crl {
                        Some(cb) => cb(ctx.cast(), dcrl),
                        None => 0,
                    };
                    if ok == 0 {
                        break 'done;
                    }
                    ok = match (*ctx).cert_crl {
                        Some(cb) => cb(ctx.cast(), dcrl, x),
                        None => 0,
                    };
                    if ok == 0 {
                        break 'done;
                    }
                } else {
                    ok = 1;
                }

                if ok != 2 {
                    ok = match (*ctx).cert_crl {
                        Some(cb) => cb(ctx.cast(), crl, x),
                        None => 0,
                    };
                    if ok == 0 {
                        break 'done;
                    }
                }

                (*ctx).current_crl = ptr::null_mut();
                X509_CRL_free(crl);
                X509_CRL_free(dcrl);
                crl = ptr::null_mut();
                dcrl = ptr::null_mut();
                if last_reasons == (*ctx).current_reasons {
                    ok = verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL);
                    break 'done;
                }
            }
        }
        X509_CRL_free(crl);
        X509_CRL_free(dcrl);
        (*ctx).current_crl = ptr::null_mut();
        ok
    }
}

/// `static int check_crl_time(X509_STORE_CTX *ctx, X509_CRL *crl, int notify)` —
/// `crypto/x509/x509_vfy.c:1368-1417`.
///
/// # Safety
///
/// `ctx` must be live with a live `param`; `crl` must be live.
unsafe fn check_crl_time(ctx: *mut X509StoreCtx, crl: *mut X509Crl, notify: c_int) -> c_int {
    // SAFETY: `ctx` and `crl` are live per the contract; the time helpers read their operands.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let ptime: *mut TimeT = if ((*param).flags & X509_V_FLAG_USE_CHECK_TIME) != 0 {
            &raw mut (*param).check_time
        } else if ((*param).flags & X509_V_FLAG_NO_CHECK_TIME) != 0 {
            return 1;
        } else {
            ptr::null_mut()
        };
        if notify != 0 {
            (*ctx).current_crl = crl;
        }

        let mut i = X509_cmp_time(X509_CRL_get0_lastUpdate(crl), ptime);
        if i == 0 {
            if notify == 0 {
                return 0;
            }
            if verify_cb_crl(ctx, X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD) == 0 {
                return 0;
            }
        }

        if i > 0 {
            if notify == 0 {
                return 0;
            }
            if verify_cb_crl(ctx, X509_V_ERR_CRL_NOT_YET_VALID) == 0 {
                return 0;
            }
        }

        if !X509_CRL_get0_nextUpdate(crl).is_null() {
            i = X509_cmp_time(X509_CRL_get0_nextUpdate(crl), ptime);
            if i == 0 {
                if notify == 0 {
                    return 0;
                }
                if verify_cb_crl(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD) == 0 {
                    return 0;
                }
            }
            if i < 0
                && ((*ctx).current_crl_score & CRL_SCORE_TIME_DELTA) == 0
                && (notify == 0 || verify_cb_crl(ctx, X509_V_ERR_CRL_HAS_EXPIRED) == 0)
            {
                return 0;
            }
        }

        if notify != 0 {
            (*ctx).current_crl = ptr::null_mut();
        }
        1
    }
}

/// `static int get_crl_sk(X509_STORE_CTX *ctx, X509_CRL **pcrl, X509_CRL **pdcrl, X509 **pissuer,
/// int *pscore, unsigned int *preasons, STACK_OF(X509_CRL) *crls)` —
/// `crypto/x509/x509_vfy.c:1419-1473`.
///
/// # Safety
///
/// `ctx` must be live; the out-pointers must be writable; `crls` must be a live stack of `X509_CRL`.
unsafe fn get_crl_sk(
    ctx: *mut X509StoreCtx,
    pcrl: *mut *mut X509Crl,
    pdcrl: *mut *mut X509Crl,
    pissuer: *mut *mut X509,
    pscore: *mut c_int,
    preasons: *mut c_uint,
    crls: *mut OpenSslStack,
) -> c_int {
    // SAFETY: every pointer is live per the contract; the callees obey their own contracts.
    unsafe {
        let mut best_score = *pscore;
        let mut best_reasons: c_uint = 0;
        let x = (*ctx).current_cert;
        let mut best_crl: *mut X509Crl = ptr::null_mut();
        let mut best_crl_issuer: *mut X509 = ptr::null_mut();

        let n = OPENSSL_sk_num(crls);
        let mut i = 0;
        while i < n {
            let crl = OPENSSL_sk_value(crls, i).cast::<X509Crl>();
            let mut reasons = *preasons;
            let mut crl_issuer: *mut X509 = ptr::null_mut();
            let crl_score = get_crl_score(ctx, &raw mut crl_issuer, &raw mut reasons, crl, x);
            if crl_score < best_score || crl_score == 0 {
                i += 1;
                continue;
            }
            if crl_score == best_score && !best_crl.is_null() {
                let mut day: c_int = 0;
                let mut sec: c_int = 0;
                if ASN1_TIME_diff(
                    &raw mut day,
                    &raw mut sec,
                    X509_CRL_get0_lastUpdate(best_crl),
                    X509_CRL_get0_lastUpdate(crl),
                ) == 0
                {
                    i += 1;
                    continue;
                }
                if day <= 0 && sec <= 0 {
                    i += 1;
                    continue;
                }
            }
            best_crl = crl;
            best_crl_issuer = crl_issuer;
            best_score = crl_score;
            best_reasons = reasons;
            i += 1;
        }

        if !best_crl.is_null() {
            if X509_CRL_up_ref(best_crl) == 0 {
                return 0;
            }
            X509_CRL_free(*pcrl);
            *pcrl = best_crl;
            *pissuer = best_crl_issuer;
            *pscore = best_score;
            *preasons = best_reasons;
            X509_CRL_free(*pdcrl);
            *pdcrl = ptr::null_mut();
            get_delta_sk(ctx, pdcrl, pscore, best_crl, crls);
        }

        if best_score >= CRL_SCORE_VALID {
            return 1;
        }
        0
    }
}

/// `static int check_delta_base(X509_CRL *delta, X509_CRL *base)` —
/// `crypto/x509/x509_vfy.c:1508-1533`.
///
/// # Safety
///
/// `delta` and `base` must be live.
unsafe fn check_delta_base(delta: *mut X509Crl, base: *mut X509Crl) -> c_int {
    // SAFETY: `delta` and `base` are live per the contract.
    unsafe {
        if (*delta).base_crl_number.is_null() {
            return 0;
        }
        if (*base).crl_number.is_null() {
            return 0;
        }
        if X509_NAME_cmp(X509_CRL_get_issuer(base), X509_CRL_get_issuer(delta)) != 0 {
            return 0;
        }
        if crl_extension_match(delta, base, NID_authority_key_identifier) == 0 {
            return 0;
        }
        if crl_extension_match(delta, base, NID_issuing_distribution_point) == 0 {
            return 0;
        }
        if ASN1_INTEGER_cmp((*delta).base_crl_number, (*base).crl_number) > 0 {
            return 0;
        }
        if (*delta).crl_number.is_null() {
            return 0;
        }
        c_int::from(ASN1_INTEGER_cmp((*delta).crl_number, (*base).crl_number) > 0)
    }
}

/// `static void get_delta_sk(X509_STORE_CTX *ctx, X509_CRL **dcrl, int *pscore, X509_CRL *base,
/// STACK_OF(X509_CRL) *crls)` — `crypto/x509/x509_vfy.c:1539-1566`.
///
/// # Safety
///
/// `ctx` must be live; `dcrl`/`pscore` must be writable; `base` must be live; `crls` must be a live
/// stack of `X509_CRL`.
unsafe fn get_delta_sk(
    ctx: *mut X509StoreCtx,
    dcrl: *mut *mut X509Crl,
    pscore: *mut c_int,
    base: *mut X509Crl,
    crls: *mut OpenSslStack,
) {
    // SAFETY: every pointer is live per the contract; the callees obey their own contracts.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        if ((*param).flags & X509_V_FLAG_USE_DELTAS) == 0 {
            return;
        }
        if (((*(*ctx).current_cert).ex_flags | (*base).flags as c_uint) & EXFLAG_FRESHEST) == 0 {
            return;
        }
        let n = OPENSSL_sk_num(crls);
        let mut i = 0;
        while i < n {
            let delta = OPENSSL_sk_value(crls, i).cast::<X509Crl>();
            if check_delta_base(delta, base) != 0 {
                if X509_CRL_up_ref(delta) == 0 {
                    *dcrl = ptr::null_mut();
                    return;
                }
                *dcrl = delta;
                if check_crl_time(ctx, delta, 0) != 0 {
                    *pscore |= CRL_SCORE_TIME_DELTA;
                }
                return;
            }
            i += 1;
        }
        *dcrl = ptr::null_mut();
    }
}

/// `static int get_crl_score(X509_STORE_CTX *ctx, X509 **pissuer, unsigned int *preasons,
/// X509_CRL *crl, X509 *x)` — `crypto/x509/x509_vfy.c:1575-1635`.
///
/// # Safety
///
/// `ctx` must be live; `pissuer`/`preasons` must be writable; `crl` and `x` must be live.
unsafe fn get_crl_score(
    ctx: *mut X509StoreCtx,
    pissuer: *mut *mut X509,
    preasons: *mut c_uint,
    crl: *mut X509Crl,
    x: *mut X509,
) -> c_int {
    // SAFETY: every pointer is live per the contract; the callees obey their own contracts.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut crl_score: c_int = 0;
        let mut tmp_reasons = *preasons;

        if ((*crl).idp_flags & IDP_INVALID) != 0 {
            return 0;
        }
        if !(*crl).base_crl_number.is_null() {
            return 0;
        }
        if ((*param).flags & X509_V_FLAG_EXTENDED_CRL_SUPPORT) == 0 {
            if ((*crl).idp_flags & (IDP_INDIRECT | IDP_REASONS)) != 0 {
                return 0;
            }
        } else if ((*crl).idp_flags & IDP_REASONS) != 0
            && ((*crl).idp_reasons as c_uint & !tmp_reasons) == 0
        {
            return 0;
        }
        if X509_NAME_cmp(X509_get_issuer_name(x), X509_CRL_get_issuer(crl)) != 0 {
            if ((*crl).idp_flags & IDP_INDIRECT) == 0 {
                return 0;
            }
        } else {
            crl_score |= CRL_SCORE_ISSUER_NAME;
        }

        if ((*crl).flags as c_uint & EXFLAG_CRITICAL) == 0 {
            crl_score |= CRL_SCORE_NOCRITICAL;
        }

        if check_crl_time(ctx, crl, 0) != 0 {
            crl_score |= CRL_SCORE_TIME;
        }

        crl_akid_check(ctx, crl, pissuer, &raw mut crl_score);

        if (crl_score & CRL_SCORE_AKID) == 0 {
            return 0;
        }

        let mut crl_reasons: c_uint = 0;
        if crl_crldp_check(x, crl, crl_score, &raw mut crl_reasons) != 0 {
            if (crl_reasons & !tmp_reasons) == 0 {
                return 0;
            }
            tmp_reasons |= crl_reasons;
            crl_score |= CRL_SCORE_SCOPE;
        }

        *preasons = tmp_reasons;
        crl_score
    }
}

/// `static void crl_akid_check(X509_STORE_CTX *ctx, X509_CRL *crl, X509 **pissuer, int *pcrl_score)`
/// — `crypto/x509/x509_vfy.c:1637-1687`.
///
/// # Safety
///
/// `ctx` must be live; `crl` must be live; `pissuer`/`pcrl_score` must be writable.
unsafe fn crl_akid_check(
    ctx: *mut X509StoreCtx,
    crl: *mut X509Crl,
    pissuer: *mut *mut X509,
    pcrl_score: *mut c_int,
) {
    // SAFETY: every pointer is live per the contract; the callees obey their own contracts.
    unsafe {
        let cnm = X509_CRL_get_issuer(crl);
        let akid = (*crl).akid.cast::<AuthorityKeyid>();
        let mut cidx = (*ctx).error_depth;

        if cidx != OPENSSL_sk_num((*ctx).chain) - 1 {
            cidx += 1;
        }

        let mut crl_issuer = OPENSSL_sk_value((*ctx).chain, cidx).cast::<X509>();

        if X509_check_akid(crl_issuer, akid) == X509_V_OK
            && (*pcrl_score & CRL_SCORE_ISSUER_NAME) != 0
        {
            *pcrl_score |= CRL_SCORE_AKID | CRL_SCORE_ISSUER_CERT;
            *pissuer = crl_issuer;
            return;
        }

        cidx += 1;
        let n = OPENSSL_sk_num((*ctx).chain);
        while cidx < n {
            crl_issuer = OPENSSL_sk_value((*ctx).chain, cidx).cast::<X509>();
            if X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm) != 0 {
                cidx += 1;
                continue;
            }
            if X509_check_akid(crl_issuer, akid) == X509_V_OK {
                *pcrl_score |= CRL_SCORE_AKID | CRL_SCORE_SAME_PATH;
                *pissuer = crl_issuer;
                return;
            }
            cidx += 1;
        }

        let param = (*ctx).param.cast::<X509VerifyParam>();
        if ((*param).flags & X509_V_FLAG_EXTENDED_CRL_SUPPORT) == 0 {
            return;
        }

        let nu = OPENSSL_sk_num((*ctx).untrusted);
        let mut i = 0;
        while i < nu {
            crl_issuer = OPENSSL_sk_value((*ctx).untrusted, i).cast::<X509>();
            if X509_NAME_cmp(X509_get_subject_name(crl_issuer), cnm) != 0 {
                i += 1;
                continue;
            }
            if X509_check_akid(crl_issuer, akid) == X509_V_OK {
                *pissuer = crl_issuer;
                *pcrl_score |= CRL_SCORE_AKID;
                return;
            }
            i += 1;
        }
    }
}

/// `static int check_crl_path(X509_STORE_CTX *ctx, X509 *x)` — `crypto/x509/x509_vfy.c:1695-1723`.
///
/// # Safety
///
/// `ctx` must be live and not already a CRL-path context; `x` must be live.
unsafe fn check_crl_path(ctx: *mut X509StoreCtx, x: *mut X509) -> c_int {
    // SAFETY: `ctx` and `x` are live per the contract; the fresh context is initialised before use.
    unsafe {
        if !(*ctx).parent.is_null() {
            return 0;
        }
        let mut crl_ctx = core::mem::zeroed::<X509StoreCtx>();
        if X509_STORE_CTX_init(&raw mut crl_ctx, (*ctx).store, x, (*ctx).untrusted) == 0 {
            return -1;
        }

        crl_ctx.crls = (*ctx).crls;
        X509_STORE_CTX_set0_param(&raw mut crl_ctx, (*ctx).param.cast());

        crl_ctx.parent = ctx;
        crl_ctx.verify_cb = (*ctx).verify_cb;

        let mut ret = X509_verify_cert(&raw mut crl_ctx);
        if ret > 0 {
            ret = check_crl_chain(ctx, (*ctx).chain, crl_ctx.chain);
        }
        X509_STORE_CTX_cleanup(&raw mut crl_ctx);
        ret
    }
}

/// `static int check_crl_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *cert_path, STACK_OF(X509)
/// *crl_path)` — `crypto/x509/x509_vfy.c:1733-1741`.
///
/// # Safety
///
/// `cert_path` and `crl_path` must be live non-empty stacks of `X509`.
unsafe fn check_crl_chain(
    _ctx: *mut X509StoreCtx,
    cert_path: *mut OpenSslStack,
    crl_path: *mut OpenSslStack,
) -> c_int {
    // SAFETY: the stacks are live and non-empty per the contract.
    unsafe {
        let cert_ta = OPENSSL_sk_value(cert_path, OPENSSL_sk_num(cert_path) - 1).cast::<X509>();
        let crl_ta = OPENSSL_sk_value(crl_path, OPENSSL_sk_num(crl_path) - 1).cast::<X509>();
        c_int::from(X509_cmp(cert_ta, crl_ta) == 0)
    }
}

/// `static int idp_check_dp(DIST_POINT_NAME *a, DIST_POINT_NAME *b)` —
/// `crypto/x509/x509_vfy.c:1750-1803`.
///
/// # Safety
///
/// `a` and `b` must be NULL or live `DIST_POINT_NAME`s whose `fullname` stacks are live where read.
unsafe fn idp_check_dp(a: *mut DistPointName, b: *mut DistPointName) -> c_int {
    // SAFETY: `a` and `b` are NULL or live per the contract; the union arms read are the live ones.
    unsafe {
        if a.is_null() || b.is_null() {
            return 1;
        }
        let mut nm: *mut X509Name = ptr::null_mut();
        let mut gens: *mut OpenSslStack = ptr::null_mut();

        if (*a).type_ == 1 {
            if (*a).dpname.is_null() {
                return 0;
            }
            if (*b).type_ == 1 {
                if (*b).dpname.is_null() {
                    return 0;
                }
                return c_int::from(X509_NAME_cmp((*a).dpname, (*b).dpname) == 0);
            }
            nm = (*a).dpname;
            gens = (*b).name.fullname;
        } else if (*b).type_ == 1 {
            if (*b).dpname.is_null() {
                return 0;
            }
            gens = (*a).name.fullname;
            nm = (*b).dpname;
        }

        if !nm.is_null() {
            let n = OPENSSL_sk_num(gens);
            let mut i = 0;
            while i < n {
                let gena = OPENSSL_sk_value(gens, i).cast::<GeneralName>();
                if (*gena).type_ != GEN_DIRNAME {
                    i += 1;
                    continue;
                }
                if X509_NAME_cmp(nm, (*gena).d.directoryName) == 0 {
                    return 1;
                }
                i += 1;
            }
            return 0;
        }

        let na = OPENSSL_sk_num((*a).name.fullname);
        let nb = OPENSSL_sk_num((*b).name.fullname);
        let mut i = 0;
        while i < na {
            let gena = OPENSSL_sk_value((*a).name.fullname, i).cast::<GeneralName>();
            let mut j = 0;
            while j < nb {
                let genb = OPENSSL_sk_value((*b).name.fullname, j).cast::<GeneralName>();
                if GENERAL_NAME_cmp(gena, genb) == 0 {
                    return 1;
                }
                j += 1;
            }
            i += 1;
        }
        0
    }
}

/// `static int crldp_check_crlissuer(DIST_POINT *dp, X509_CRL *crl, int crl_score)` —
/// `crypto/x509/x509_vfy.c:1805-1822`.
///
/// # Safety
///
/// `dp` and `crl` must be live; `dp->CRLissuer` must be NULL or a live stack of `GENERAL_NAME`.
unsafe fn crldp_check_crlissuer(dp: *mut DistPoint, crl: *mut X509Crl, crl_score: c_int) -> c_int {
    // SAFETY: `dp` and `crl` are live per the contract.
    unsafe {
        let nm = X509_CRL_get_issuer(crl);
        if (*dp).CRLissuer.is_null() {
            return c_int::from((crl_score & CRL_SCORE_ISSUER_NAME) != 0);
        }
        let n = OPENSSL_sk_num((*dp).CRLissuer);
        let mut i = 0;
        while i < n {
            let gen = OPENSSL_sk_value((*dp).CRLissuer, i).cast::<GeneralName>();
            if (*gen).type_ != GEN_DIRNAME {
                i += 1;
                continue;
            }
            if X509_NAME_cmp((*gen).d.directoryName, nm) == 0 {
                return 1;
            }
            i += 1;
        }
        0
    }
}

/// `static int crl_crldp_check(X509 *x, X509_CRL *crl, int crl_score, unsigned int *preasons)` —
/// `crypto/x509/x509_vfy.c:1825-1853`.
///
/// # Safety
///
/// `x` and `crl` must be live; `preasons` must be writable.
unsafe fn crl_crldp_check(
    x: *mut X509,
    crl: *mut X509Crl,
    crl_score: c_int,
    preasons: *mut c_uint,
) -> c_int {
    // SAFETY: `x` and `crl` are live per the contract; the distribution-point stacks are live.
    unsafe {
        if ((*crl).idp_flags & IDP_ONLYATTR) != 0 {
            return 0;
        }
        if ((*x).ex_flags & EXFLAG_CA) != 0 {
            if ((*crl).idp_flags & IDP_ONLYUSER) != 0 {
                return 0;
            }
        } else if ((*crl).idp_flags & IDP_ONLYCA) != 0 {
            return 0;
        }
        *preasons = (*crl).idp_reasons as c_uint;
        let crldp = (*x).crldp.cast::<OpenSslStack>();
        let n = OPENSSL_sk_num(crldp);
        let mut i = 0;
        while i < n {
            let dp = OPENSSL_sk_value(crldp, i).cast::<DistPoint>();
            if crldp_check_crlissuer(dp, crl, crl_score) != 0 {
                let idp = (*crl).idp.cast::<IssuingDistPoint>();
                if idp.is_null() || idp_check_dp((*dp).distpoint, (*idp).distpoint) != 0 {
                    *preasons &= (*dp).dp_reasons as c_uint;
                    return 1;
                }
            }
            i += 1;
        }
        let idp = (*crl).idp.cast::<IssuingDistPoint>();
        c_int::from(
            (idp.is_null() || (*idp).distpoint.is_null())
                && (crl_score & CRL_SCORE_ISSUER_NAME) != 0,
        )
    }
}

/// `static int get_crl_delta(X509_STORE_CTX *ctx, X509_CRL **pcrl, X509_CRL **pdcrl, X509 *x)` —
/// `crypto/x509/x509_vfy.c:1859-1898`.
///
/// # Safety
///
/// `ctx` must be live with a live `crls` stack and `lookup_crls` callback; `pcrl`/`pdcrl` must be
/// writable; `x` must be live.
unsafe fn get_crl_delta(
    ctx: *mut X509StoreCtx,
    pcrl: *mut *mut X509Crl,
    pdcrl: *mut *mut X509Crl,
    x: *mut X509,
) -> c_int {
    // SAFETY: every pointer is live per the contract; the callees obey their own contracts.
    unsafe {
        let mut issuer: *mut X509 = ptr::null_mut();
        let mut crl_score: c_int = 0;
        let mut crl: *mut X509Crl = ptr::null_mut();
        let mut dcrl: *mut X509Crl = ptr::null_mut();
        let nm = X509_get_issuer_name(x);
        let mut reasons = (*ctx).current_reasons;

        let ok = get_crl_sk(
            ctx,
            &raw mut crl,
            &raw mut dcrl,
            &raw mut issuer,
            &raw mut crl_score,
            &raw mut reasons,
            (*ctx).crls,
        );
        if ok == 0 {
            let skcrl = match (*ctx).lookup_crls {
                Some(cb) => cb(ctx.cast(), nm),
                None => ptr::null_mut(),
            };
            if !skcrl.is_null() || crl.is_null() {
                get_crl_sk(
                    ctx,
                    &raw mut crl,
                    &raw mut dcrl,
                    &raw mut issuer,
                    &raw mut crl_score,
                    &raw mut reasons,
                    skcrl,
                );
            }
            OPENSSL_sk_pop_free(skcrl, Some(x509_crl_free_void));
        }

        if !crl.is_null() {
            (*ctx).current_issuer = issuer;
            (*ctx).current_crl_score = crl_score;
            (*ctx).current_reasons = reasons;
            *pcrl = crl;
            *pdcrl = dcrl;
            return 1;
        }
        0
    }
}

/// `static int check_crl(X509_STORE_CTX *ctx, X509_CRL *crl)` — `crypto/x509/x509_vfy.c:1901-1965`.
///
/// # Safety
///
/// `ctx` must be the live context the callback contract promises; `crl` must be live.
unsafe extern "C" fn check_crl(ctx: *mut c_void, crl: *mut X509Crl) -> c_int {
    // SAFETY: `ctx` and `crl` are live per the contract; the callees obey their own contracts.
    unsafe {
        let ctx = ctx.cast::<X509StoreCtx>();
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let cnum = (*ctx).error_depth;
        let chnum = OPENSSL_sk_num((*ctx).chain) - 1;
        let issuer: *mut X509;

        if !(*ctx).current_issuer.is_null() {
            issuer = (*ctx).current_issuer;
        } else if cnum < chnum {
            issuer = OPENSSL_sk_value((*ctx).chain, cnum + 1).cast::<X509>();
        } else {
            issuer = OPENSSL_sk_value((*ctx).chain, chnum).cast::<X509>();
            // `ossl_assert(issuer != NULL)`.
            if issuer.is_null() {
                return 0;
            }
            let issued = match (*ctx).check_issued {
                Some(cb) => cb(ctx.cast(), issuer, issuer),
                None => 0,
            };
            if issued == 0 && verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER) == 0 {
                return 0;
            }
        }

        if issuer.is_null() {
            return 1;
        }

        if (*crl).base_crl_number.is_null() {
            if ((*issuer).ex_flags & EXFLAG_KUSAGE) != 0
                && ((*issuer).ex_kusage & KU_CRL_SIGN) == 0
                && verify_cb_crl(ctx, X509_V_ERR_KEYUSAGE_NO_CRL_SIGN) == 0
            {
                return 0;
            }
            if ((*ctx).current_crl_score & CRL_SCORE_SCOPE) == 0
                && verify_cb_crl(ctx, X509_V_ERR_DIFFERENT_CRL_SCOPE) == 0
            {
                return 0;
            }
            if ((*ctx).current_crl_score & CRL_SCORE_SAME_PATH) == 0
                && check_crl_path(ctx, (*ctx).current_issuer) <= 0
                && verify_cb_crl(ctx, X509_V_ERR_CRL_PATH_VALIDATION_ERROR) == 0
            {
                return 0;
            }
            if ((*crl).idp_flags & IDP_INVALID) != 0
                && verify_cb_crl(ctx, X509_V_ERR_INVALID_EXTENSION) == 0
            {
                return 0;
            }
        }

        if ((*ctx).current_crl_score & CRL_SCORE_TIME) == 0 && check_crl_time(ctx, crl, 1) == 0 {
            return 0;
        }

        let ikey = X509_get0_pubkey(issuer);
        if ikey.is_null() && verify_cb_crl(ctx, X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY) == 0
        {
            return 0;
        }

        if !ikey.is_null() {
            let rv = X509_CRL_check_suiteb(crl, ikey, (*param).flags);
            if rv != X509_V_OK && verify_cb_crl(ctx, rv) == 0 {
                return 0;
            }
            if X509_CRL_verify(crl, ikey) <= 0
                && verify_cb_crl(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE) == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `static int cert_crl(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x)` —
/// `crypto/x509/x509_vfy.c:1968-1993`.
///
/// # Safety
///
/// `ctx` must be the live context the callback contract promises; `crl` and `x` must be live.
unsafe extern "C" fn cert_crl(ctx: *mut c_void, crl: *mut X509Crl, x: *mut X509) -> c_int {
    // SAFETY: `ctx`, `crl` and `x` are live per the contract; the callees obey their contracts.
    unsafe {
        let ctx = ctx.cast::<X509StoreCtx>();
        let param = (*ctx).param.cast::<X509VerifyParam>();

        if ((*param).flags & X509_V_FLAG_IGNORE_CRITICAL) == 0
            && ((*crl).flags as c_uint & EXFLAG_CRITICAL) != 0
            && verify_cb_crl(ctx, X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION) == 0
        {
            return 0;
        }

        let mut rev: *mut X509Revoked = ptr::null_mut();
        if X509_CRL_get0_by_cert(crl, &raw mut rev, x) != 0 {
            if (*rev).reason == CRL_REASON_REMOVE_FROM_CRL {
                return 2;
            }
            if verify_cb_crl(ctx, X509_V_ERR_CERT_REVOKED) == 0 {
                return 0;
            }
        }
        1
    }
}

// ---------------------------------------------------------------------------------------------
// Internal verification, chain building and the level checks — `x509_vfy.c:2114-2231`,
// `:3512-3984`.
// ---------------------------------------------------------------------------------------------

/// `static int internal_verify(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:2114-2231`.
///
/// # Safety
///
/// `ctx` must be the live context the callback contract promises.
unsafe extern "C" fn internal_verify(ctx: *mut c_void) -> c_int {
    // SAFETY: `ctx` is the live context the callback contract promises; the callees obey their
    // own contracts.
    unsafe {
        let ctx = ctx.cast::<X509StoreCtx>();
        let param = (*ctx).param.cast::<X509VerifyParam>();

        if !(*ctx).rpk.is_null() {
            let ok = match (*ctx).verify_cb {
                Some(cb) => cb(c_int::from((*ctx).error == X509_V_OK), ctx.cast()),
                None => 0,
            };
            if ok == 0 {
                return 0;
            }
            return 1;
        }

        let mut n = OPENSSL_sk_num((*ctx).chain) - 1;
        let mut xi = OPENSSL_sk_value((*ctx).chain, n).cast::<X509>();
        let mut xs = xi;

        (*ctx).error_depth = n;
        if (*ctx).bare_ta_signed != 0 {
            xi = ptr::null_mut();
        } else if ossl_x509_likely_issued(xi, xi) != X509_V_OK
            && ((*param).flags & X509_V_FLAG_PARTIAL_CHAIN) == 0
        {
            if n > 0 {
                n -= 1;
                (*ctx).error_depth = n;
                xs = OPENSSL_sk_value((*ctx).chain, n).cast::<X509>();
            } else if verify_cb_cert(ctx, xi, 0, X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) == 0 {
                return 0;
            }
        }

        while n >= 0 {
            if !xi.is_null()
                && (xs != xi
                    || (((*param).flags & X509_V_FLAG_CHECK_SS_SIGNATURE) != 0
                        && ((*xi).ex_flags & EXFLAG_SS) != 0))
            {
                let issuer_depth = n + if xs == xi { 0 } else { 1 };
                let ret = if xs == xi && ((*xi).ex_flags & EXFLAG_CA) == 0 {
                    X509_V_OK
                } else {
                    ossl_x509_signing_allowed(xi, xs)
                };

                if ret != X509_V_OK && verify_cb_cert(ctx, xi, issuer_depth, ret) == 0 {
                    return 0;
                }
                let pkey = X509_get0_pubkey(xi);
                if pkey.is_null() {
                    if verify_cb_cert(
                        ctx,
                        xi,
                        issuer_depth,
                        X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
                    ) == 0
                    {
                        return 0;
                    }
                } else if X509_verify(xs, pkey) <= 0
                    && verify_cb_cert(ctx, xs, n, X509_V_ERR_CERT_SIGNATURE_FAILURE) == 0
                {
                    return 0;
                }
            }

            if ossl_x509_check_cert_time(ctx, xs, n) == 0 {
                return 0;
            }

            (*ctx).current_issuer = xi;
            (*ctx).current_cert = xs;
            (*ctx).error_depth = n;
            let ok = match (*ctx).verify_cb {
                Some(cb) => cb(1, ctx.cast()),
                None => 0,
            };
            if ok == 0 {
                return 0;
            }

            n -= 1;
            if n >= 0 {
                xi = xs;
                xs = OPENSSL_sk_value((*ctx).chain, n).cast::<X509>();
            }
        }
        1
    }
}

/// `static int build_chain(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:3512-3853`.
///
/// The authority's `int_err:` and `memerr:` labels share one `sk_X509_free`; the labelled block
/// below folds both into a single cleanup while preserving each exit's value.
///
/// # Safety
///
/// `ctx` must be live with a live `chain`, `param` and `dane` (NULL or live).
unsafe fn build_chain(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the callees obey their own contracts.
    unsafe {
        let dane = (*ctx).dane.cast::<SslDane>();
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut num = OPENSSL_sk_num((*ctx).chain);
        let mut sk_untrusted: *mut OpenSslStack = ptr::null_mut();
        let mut may_trusted = 0;
        let mut may_alternate = 0;
        let mut trust = X509_TRUST_UNTRUSTED;
        let mut alt_untrusted = 0;

        let result = 'build: {
            // `ossl_assert(num == 1 && ctx->num_untrusted == num)`.
            if !(num == 1 && (*ctx).num_untrusted == num) {
                raise_site(&X509_VFY_3844);
                (*ctx).error = X509_V_ERR_UNSPECIFIED;
                break 'build -1;
            }

            let mut search: c_uint = if !(*ctx).untrusted.is_null() {
                S_DOUNTRUSTED
            } else {
                0
            };
            if danetls_has_pkix(dane) || !danetls_has_dane(dane) {
                if search == 0 || ((*param).flags & X509_V_FLAG_TRUSTED_FIRST) != 0 {
                    search |= S_DOTRUSTED;
                } else if ((*param).flags & X509_V_FLAG_NO_ALT_CHAINS) == 0 {
                    may_alternate = 1;
                }
                may_trusted = 1;
            }

            sk_untrusted = OPENSSL_sk_new_null();
            if sk_untrusted.is_null() {
                raise_site(&X509_VFY_3552);
                (*ctx).error = X509_V_ERR_OUT_OF_MEM;
                break 'build -1;
            }

            if danetls_enabled(dane)
                && !(*dane).certs.is_null()
                && X509_add_certs(sk_untrusted, (*dane).certs, X509_ADD_FLAG_DEFAULT) == 0
            {
                raise_site(&X509_VFY_3562);
                (*ctx).error = X509_V_ERR_OUT_OF_MEM;
                break 'build -1;
            }

            if X509_add_certs(sk_untrusted, (*ctx).untrusted, X509_ADD_FLAG_DEFAULT) == 0 {
                raise_site(&X509_VFY_3572);
                (*ctx).error = X509_V_ERR_OUT_OF_MEM;
                break 'build -1;
            }

            if (*param).depth > c_int::MAX / 2 {
                (*param).depth = c_int::MAX / 2;
            }
            let max_depth = (*param).depth + 1;

            while search != 0 {
                let mut curr: *mut X509;
                let mut issuer: *mut X509 = ptr::null_mut();

                num = OPENSSL_sk_num((*ctx).chain);
                (*ctx).error_depth = num - 1;

                if (search & S_DOTRUSTED) != 0 {
                    let mut idx = num;
                    if (search & S_DOALTERNATE) != 0 {
                        idx = alt_untrusted;
                    }
                    curr = OPENSSL_sk_value((*ctx).chain, idx - 1).cast::<X509>();

                    let mut ok = if num > max_depth {
                        0
                    } else {
                        get1_trusted_issuer(&raw mut issuer, ctx, curr)
                    };

                    if ok < 0 {
                        trust = -1;
                        (*ctx).error = X509_V_ERR_STORE_LOOKUP;
                        break;
                    }

                    if ok > 0 {
                        let mut self_signed = X509_self_signed(curr, 0);
                        if self_signed < 0 {
                            X509_free(issuer);
                            raise_site(&X509_VFY_3844);
                            (*ctx).error = X509_V_ERR_UNSPECIFIED;
                            break 'build -1;
                        }

                        if (search & S_DOALTERNATE) != 0 {
                            // `ossl_assert(num > i && i > 0 && !self_signed)`.
                            if !(num > idx && idx > 0 && self_signed == 0) {
                                X509_free(issuer);
                                raise_site(&X509_VFY_3844);
                                (*ctx).error = X509_V_ERR_UNSPECIFIED;
                                break 'build -1;
                            }
                            search &= !S_DOALTERNATE;
                            while num > idx {
                                X509_free(OPENSSL_sk_pop((*ctx).chain).cast::<X509>());
                                num -= 1;
                            }
                            (*ctx).num_untrusted = num;

                            if danetls_enabled(dane) && (*dane).mdpth >= (*ctx).num_untrusted {
                                (*dane).mdpth = -1;
                                X509_free((*dane).mcert);
                                (*dane).mcert = ptr::null_mut();
                            }
                            if danetls_enabled(dane) && (*dane).pdpth >= (*ctx).num_untrusted {
                                (*dane).pdpth = -1;
                            }
                        }

                        if self_signed == 0 {
                            if OPENSSL_sk_push((*ctx).chain, issuer.cast()) == 0 {
                                X509_free(issuer);
                                raise_site(&X509_VFY_3684);
                                (*ctx).error = X509_V_ERR_OUT_OF_MEM;
                                break 'build -1;
                            }
                            self_signed = X509_self_signed(issuer, 0);
                            if self_signed < 0 {
                                raise_site(&X509_VFY_3844);
                                (*ctx).error = X509_V_ERR_UNSPECIFIED;
                                break 'build -1;
                            }
                        } else if X509_cmp(curr, issuer) != 0 {
                            X509_free(issuer);
                            ok = 0;
                        } else {
                            X509_free(curr);
                            num -= 1;
                            (*ctx).num_untrusted = num;
                            OPENSSL_sk_set((*ctx).chain, num, issuer.cast());
                        }

                        if ok != 0 {
                            // `ossl_assert(ctx->num_untrusted <= num)`.
                            if !((*ctx).num_untrusted <= num) {
                                raise_site(&X509_VFY_3844);
                                (*ctx).error = X509_V_ERR_UNSPECIFIED;
                                break 'build -1;
                            }
                            search &= !S_DOUNTRUSTED;
                            trust = check_trust(ctx, num);
                            if trust != X509_TRUST_UNTRUSTED {
                                break;
                            }
                            if self_signed == 0 {
                                continue;
                            }
                        }
                    }

                    if (search & S_DOUNTRUSTED) == 0 {
                        if (search & S_DOALTERNATE) != 0 {
                            alt_untrusted -= 1;
                            if alt_untrusted > 0 {
                                continue;
                            }
                        }
                        if may_alternate == 0
                            || (search & S_DOALTERNATE) != 0
                            || (*ctx).num_untrusted < 2
                        {
                            break;
                        }
                        search |= S_DOALTERNATE;
                        alt_untrusted = (*ctx).num_untrusted - 1;
                    }
                }

                if (search & S_DOUNTRUSTED) != 0 {
                    num = OPENSSL_sk_num((*ctx).chain);
                    // `ossl_assert(num == ctx->num_untrusted)`.
                    if num != (*ctx).num_untrusted {
                        raise_site(&X509_VFY_3844);
                        (*ctx).error = X509_V_ERR_UNSPECIFIED;
                        break 'build -1;
                    }
                    curr = OPENSSL_sk_value((*ctx).chain, num - 1).cast::<X509>();
                    issuer = if X509_self_signed(curr, 0) > 0 || num > max_depth {
                        ptr::null_mut()
                    } else {
                        get0_best_issuer_sk(ctx, 0, 1, sk_untrusted, curr)
                    };
                    if issuer.is_null() {
                        search &= !S_DOUNTRUSTED;
                        if may_trusted != 0 {
                            search |= S_DOTRUSTED;
                        }
                        continue;
                    }

                    OPENSSL_sk_delete_ptr(sk_untrusted, issuer.cast());

                    if X509_add_cert((*ctx).chain, issuer, X509_ADD_FLAG_UP_REF) == 0 {
                        raise_site(&X509_VFY_3844);
                        (*ctx).error = X509_V_ERR_UNSPECIFIED;
                        break 'build -1;
                    }

                    (*ctx).num_untrusted += 1;

                    trust = check_dane_issuer(ctx, (*ctx).num_untrusted - 1);
                    if trust == X509_TRUST_TRUSTED || trust == X509_TRUST_REJECTED {
                        break;
                    }
                }
            }

            if trust < 0 {
                break 'build trust;
            }

            num = OPENSSL_sk_num((*ctx).chain);
            if num <= max_depth {
                if trust == X509_TRUST_UNTRUSTED && danetls_has_dane_ta(dane) {
                    trust = check_dane_pkeys(ctx);
                }
                if trust == X509_TRUST_UNTRUSTED && num == (*ctx).num_untrusted {
                    trust = check_trust(ctx, num);
                }
            }

            match trust {
                X509_TRUST_TRUSTED => 1,
                X509_TRUST_REJECTED => 0,
                _ => match (*ctx).error {
                    X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
                    | X509_V_ERR_CERT_NOT_YET_VALID
                    | X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
                    | X509_V_ERR_CERT_HAS_EXPIRED => 0,
                    X509_V_OK => {
                        if num > max_depth
                            && verify_cb_cert(
                                ctx,
                                ptr::null_mut(),
                                num - 1,
                                X509_V_ERR_CERT_CHAIN_TOO_LONG,
                            ) == 0
                        {
                            break 'build 0;
                        }
                        if danetls_enabled(dane)
                            && (!danetls_has_pkix(dane) || (*dane).pdpth >= 0)
                            && verify_cb_cert(
                                ctx,
                                ptr::null_mut(),
                                num - 1,
                                X509_V_ERR_DANE_NO_MATCH,
                            ) == 0
                        {
                            break 'build 0;
                        }
                        if X509_self_signed(
                            OPENSSL_sk_value((*ctx).chain, num - 1).cast::<X509>(),
                            0,
                        ) > 0
                        {
                            break 'build verify_cb_cert(
                                ctx,
                                ptr::null_mut(),
                                num - 1,
                                if num == 1 {
                                    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                                } else {
                                    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
                                },
                            );
                        }
                        verify_cb_cert(
                            ctx,
                            ptr::null_mut(),
                            num - 1,
                            if (*ctx).num_untrusted < num {
                                X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
                            } else {
                                X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                            },
                        )
                    }
                    _ => verify_cb_cert(ctx, ptr::null_mut(), num - 1, (*ctx).error),
                },
            }
        };

        OPENSSL_sk_free(sk_untrusted);
        result
    }
}

/// `static int check_key_level(X509_STORE_CTX *ctx, EVP_PKEY *pkey)` —
/// `crypto/x509/x509_vfy.c:3908-3929`.
///
/// # Safety
///
/// `ctx` must be live with a live `param`; `pkey` must be NULL or live.
unsafe fn check_key_level(ctx: *mut X509StoreCtx, pkey: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live per the contract; the key-strength helper reads `pkey`.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut level = (*param).auth_level;

        if level <= 0 {
            return 1;
        }
        if pkey.is_null() {
            return 0;
        }
        if level > NUM_AUTH_LEVELS {
            level = NUM_AUTH_LEVELS;
        }
        c_int::from(EVP_PKEY_get_security_bits(pkey) >= MINBITS_TABLE[(level - 1) as usize])
    }
}

/// `static int check_cert_key_level(X509_STORE_CTX *ctx, X509 *cert)` —
/// `crypto/x509/x509_vfy.c:3935-3938`.
///
/// # Safety
///
/// `ctx` must be live with a live `param`; `cert` must be live.
unsafe fn check_cert_key_level(ctx: *mut X509StoreCtx, cert: *mut X509) -> c_int {
    // SAFETY: `ctx` and `cert` are live per the contract; `cert`'s public key is its own field.
    unsafe { check_key_level(ctx, X509_get0_pubkey(cert)) }
}

/// `static int check_curve(X509 *cert)` — `crypto/x509/x509_vfy.c:3946-3961`.
///
/// # Safety
///
/// `cert` must be live.
unsafe fn check_curve(cert: *mut X509) -> c_int {
    // SAFETY: `cert` is live per the contract; the key getters read its public key's parameters.
    unsafe {
        let pkey = X509_get0_pubkey(cert);
        if pkey.is_null() {
            return -1;
        }
        if EVP_PKEY_get_id(pkey) != EVP_PKEY_EC {
            return 1;
        }

        let mut val: c_int = 0;
        let ret = EVP_PKEY_get_int_param(
            pkey,
            OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
            &raw mut val,
        );
        if ret == 1 {
            c_int::from(val == 0)
        } else {
            -1
        }
    }
}

/// `static int check_sig_level(X509_STORE_CTX *ctx, X509 *cert)` —
/// `crypto/x509/x509_vfy.c:3970-3984`.
///
/// # Safety
///
/// `ctx` must be live with a live `param`; `cert` must be live.
unsafe fn check_sig_level(ctx: *mut X509StoreCtx, cert: *mut X509) -> c_int {
    // SAFETY: `ctx` and `cert` are live per the contract; the signature helper reads `cert`.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let mut level = (*param).auth_level;

        if level <= 0 {
            return 1;
        }
        if level > NUM_AUTH_LEVELS {
            level = NUM_AUTH_LEVELS;
        }

        let mut secbits: c_int = -1;
        if X509_get_signature_info(
            cert,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut secbits,
            ptr::null_mut(),
        ) == 0
        {
            return 0;
        }
        c_int::from(secbits >= MINBITS_TABLE[(level - 1) as usize])
    }
}

// ---------------------------------------------------------------------------------------------
// The five engine exports — `crypto/x509/x509_vfy.c:292-312`, `:2729-2871`, `:3855-3895`.
// ---------------------------------------------------------------------------------------------

/// `int X509_STORE_CTX_init_rpk(X509_STORE_CTX *ctx, X509_STORE *store, EVP_PKEY *rpk)` —
/// `crypto/x509/x509_vfy.c:2729-2735`.
///
/// # Safety
///
/// `ctx` must be live or NULL; `store` must be NULL or live; `rpk` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_init_rpk(
    ctx: *mut X509StoreCtx,
    store: *mut X509Store,
    rpk: *mut EvpPkey,
) -> c_int {
    // SAFETY: `ctx` and `store` are live or NULL per the contract; the callees obey their own
    // contracts.
    unsafe {
        if X509_STORE_CTX_init(ctx, store, ptr::null_mut(), ptr::null_mut()) == 0 {
            return 0;
        }
        (*ctx).rpk = rpk;
        1
    }
}

/// `int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509)
/// *chain)` — `crypto/x509/x509_vfy.c:2737-2871`.
///
/// Installs the engine's default callbacks into `ctx`, inheriting each from `store` when the store
/// supplies one and falling back to the authority's own default otherwise, then installs a fresh
/// `X509_VERIFY_PARAM`, applies the `default` parameter profile and sets up the `ex_data` block.
///
/// # Safety
///
/// `ctx` must be live or NULL; `store` must be NULL or live; `x509` must be NULL or live; `chain`
/// must be NULL or a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_init(
    ctx: *mut X509StoreCtx,
    store: *mut X509Store,
    x509: *mut X509,
    chain: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract; every store field read is a live pointer or
    // callback slot when `store` is non-NULL, and the callees obey their own contracts.
    unsafe {
        if ctx.is_null() {
            raise_site(&X509_VFY_2741);
            return 0;
        }
        X509_STORE_CTX_cleanup(ctx);

        (*ctx).store = store;
        (*ctx).cert = x509;
        (*ctx).untrusted = chain;
        (*ctx).crls = ptr::null_mut();
        (*ctx).num_untrusted = 0;
        (*ctx).other_ctx = ptr::null_mut();
        (*ctx).valid = 0;
        (*ctx).chain = ptr::null_mut();
        (*ctx).error = X509_V_OK;
        (*ctx).explicit_policy = 0;
        (*ctx).error_depth = 0;
        (*ctx).current_cert = ptr::null_mut();
        (*ctx).current_issuer = ptr::null_mut();
        (*ctx).current_crl = ptr::null_mut();
        (*ctx).current_crl_score = 0;
        (*ctx).current_reasons = 0;
        (*ctx).tree = ptr::null_mut();
        (*ctx).parent = ptr::null_mut();
        (*ctx).dane = ptr::null_mut();
        (*ctx).bare_ta_signed = 0;
        (*ctx).rpk = ptr::null_mut();
        // Zero `ex_data` to make sure we're cleanup-safe (`:2767-2768`).
        ptr::write_bytes(&raw mut (*ctx).ex_data, 0, 1);
        (*ctx).ocsp_resp = ptr::null_mut();

        if !store.is_null() {
            (*ctx).cleanup = (*store).cleanup;
        } else {
            (*ctx).cleanup = None;
        }

        if !store.is_null() && (*store).check_issued.is_some() {
            (*ctx).check_issued = (*store).check_issued;
        } else {
            (*ctx).check_issued = Some(check_issued);
        }

        if !store.is_null() && (*store).get_issuer.is_some() {
            (*ctx).get_issuer = (*store).get_issuer;
        } else {
            (*ctx).get_issuer = Some(get1_issuer_cb);
        }

        if !store.is_null() && (*store).verify_cb.is_some() {
            (*ctx).verify_cb = (*store).verify_cb;
        } else {
            (*ctx).verify_cb = Some(null_callback);
        }

        if !store.is_null() && (*store).verify.is_some() {
            (*ctx).verify = (*store).verify;
        } else {
            (*ctx).verify = Some(internal_verify);
        }

        if !store.is_null() && (*store).check_revocation.is_some() {
            (*ctx).check_revocation = (*store).check_revocation;
        } else {
            (*ctx).check_revocation = Some(check_revocation);
        }

        if !store.is_null() && (*store).get_crl.is_some() {
            (*ctx).get_crl = (*store).get_crl;
        } else {
            (*ctx).get_crl = None;
        }

        if !store.is_null() && (*store).check_crl.is_some() {
            (*ctx).check_crl = (*store).check_crl;
        } else {
            (*ctx).check_crl = Some(check_crl);
        }

        if !store.is_null() && (*store).cert_crl.is_some() {
            (*ctx).cert_crl = (*store).cert_crl;
        } else {
            (*ctx).cert_crl = Some(cert_crl);
        }

        if !store.is_null() && (*store).check_policy.is_some() {
            (*ctx).check_policy = (*store).check_policy;
        } else {
            (*ctx).check_policy = Some(check_policy);
        }

        if !store.is_null() && (*store).lookup_certs.is_some() {
            (*ctx).lookup_certs = (*store).lookup_certs;
        } else {
            (*ctx).lookup_certs = Some(lookup_certs_cb);
        }

        if !store.is_null() && (*store).lookup_crls.is_some() {
            (*ctx).lookup_crls = (*store).lookup_crls;
        } else {
            (*ctx).lookup_crls = Some(lookup_crls_cb);
        }

        (*ctx).param = X509_VERIFY_PARAM_new().cast();
        if (*ctx).param.is_null() {
            raise_site(&X509_VFY_2834);
            X509_STORE_CTX_cleanup(ctx);
            return 0;
        }

        if store.is_null() {
            let param = (*ctx).param.cast::<X509VerifyParam>();
            (*param).inh_flags |= X509_VP_FLAG_DEFAULT | X509_VP_FLAG_ONCE;
        } else if X509_VERIFY_PARAM_inherit((*ctx).param.cast(), (*store).param) == 0 {
            X509_STORE_CTX_cleanup(ctx);
            return 0;
        }

        if X509_STORE_CTX_set_default(ctx, c"default".as_ptr()) == 0 {
            X509_STORE_CTX_cleanup(ctx);
            return 0;
        }

        let param = (*ctx).param.cast::<X509VerifyParam>();
        if (*param).trust == X509_TRUST_DEFAULT {
            let idx = X509_PURPOSE_get_by_id((*param).purpose);
            let xp = X509_PURPOSE_get0(idx);
            if !xp.is_null() {
                (*param).trust = X509_PURPOSE_get_trust(xp);
            }
        }

        if CRYPTO_new_ex_data(
            CRYPTO_EX_INDEX_X509_STORE_CTX,
            ctx.cast(),
            &raw mut (*ctx).ex_data,
        ) != 0
        {
            return 1;
        }
        raise_site(&X509_VFY_2862);
        X509_STORE_CTX_cleanup(ctx);
        0
    }
}

/// `int X509_STORE_CTX_verify(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:292-303`.
///
/// # Safety
///
/// `ctx` must be live or NULL, and initialised when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn X509_STORE_CTX_verify(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract; the callees obey their own contracts.
    unsafe {
        if ctx.is_null() {
            raise_site(&X509_VFY_295);
            return -1;
        }
        if !(*ctx).rpk.is_null() {
            return x509_verify_rpk(ctx);
        }
        if (*ctx).cert.is_null() && OPENSSL_sk_num((*ctx).untrusted) >= 1 {
            (*ctx).cert = OPENSSL_sk_value((*ctx).untrusted, 0).cast::<X509>();
        }
        x509_verify_x509(ctx)
    }
}

/// `int X509_verify_cert(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:305-312`.
///
/// # Safety
///
/// `ctx` must be live or NULL, and initialised when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn X509_verify_cert(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is NULL or live per the contract; the callees obey their own contracts.
    unsafe {
        if ctx.is_null() {
            raise_site(&X509_VFY_308);
            return -1;
        }
        if !(*ctx).rpk.is_null() {
            x509_verify_rpk(ctx)
        } else {
            x509_verify_x509(ctx)
        }
    }
}

/// `STACK_OF(X509) *X509_build_chain(X509 *target, STACK_OF(X509) *certs, X509_STORE *store, int
/// with_self_signed, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/x509/x509_vfy.c:3855-3895`.
///
/// # Safety
///
/// `target` must be live; `certs` must be NULL or a live stack of `X509`; `store` must be NULL or
/// live; `libctx` is opaque; `propq` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn X509_build_chain(
    target: *mut X509,
    certs: *mut OpenSslStack,
    store: *mut X509Store,
    with_self_signed: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut OpenSslStack {
    // SAFETY: `target` is live per the contract; the fresh context is initialised before use and
    // freed on every exit; the callees obey their own contracts.
    unsafe {
        let finish_chain = c_int::from(!store.is_null());
        let mut result: *mut OpenSslStack = ptr::null_mut();

        if target.is_null() {
            raise_site(&X509_VFY_3865);
            return ptr::null_mut();
        }

        let ctx = X509_STORE_CTX_new_ex(libctx, propq);
        if ctx.is_null() {
            return ptr::null_mut();
        }
        if X509_STORE_CTX_init(
            ctx,
            store,
            target,
            if finish_chain != 0 {
                certs
            } else {
                ptr::null_mut()
            },
        ) == 0
        {
            X509_STORE_CTX_free(ctx);
            return result;
        }
        if finish_chain == 0 {
            X509_STORE_CTX_set0_trusted_stack(ctx, certs);
        }
        if ossl_x509_add_cert_new(&raw mut (*ctx).chain, target, X509_ADD_FLAG_UP_REF) == 0 {
            (*ctx).error = X509_V_ERR_OUT_OF_MEM;
            X509_STORE_CTX_free(ctx);
            return result;
        }
        (*ctx).num_untrusted = 1;

        if build_chain(ctx) == 0 && finish_chain != 0 {
            X509_STORE_CTX_free(ctx);
            return result;
        }

        let mut flags = X509_ADD_FLAG_UP_REF;
        if OPENSSL_sk_num((*ctx).chain) > 1 && with_self_signed == 0 {
            flags |= X509_ADD_FLAG_NO_SS;
        }
        if ossl_x509_add_certs_new(&raw mut result, (*ctx).chain, flags) == 0 {
            OPENSSL_sk_free(result);
            result = ptr::null_mut();
        }

        X509_STORE_CTX_free(ctx);
        result
    }
}

// ---------------------------------------------------------------------------------------------
// The DANE entry points this unit owns — `crypto/x509/x509_vfy.c:3392-3490`.
// ---------------------------------------------------------------------------------------------

/// `static int check_leaf_suiteb(X509_STORE_CTX *ctx, X509 *cert)` —
/// `crypto/x509/x509_vfy.c:3392-3398`.
///
/// # Safety
///
/// `ctx` must be live with a live `param`; `cert` must be live.
unsafe fn check_leaf_suiteb(ctx: *mut X509StoreCtx, cert: *mut X509) -> c_int {
    // SAFETY: `ctx` and `cert` are live per the contract; the suite-B check reads both.
    unsafe {
        let param = (*ctx).param.cast::<X509VerifyParam>();
        let err = X509_chain_check_suiteb(ptr::null_mut(), cert, ptr::null_mut(), (*param).flags);
        if err != X509_V_OK && verify_cb_cert(ctx, cert, 0, err) == 0 {
            return 0;
        }
        1
    }
}

/// `static int dane_verify_rpk(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:3401-3428`.
///
/// # Safety
///
/// `ctx` must be live with a live `dane` and `rpk`.
unsafe fn dane_verify_rpk(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the DANE callees obey their own contracts.
    unsafe {
        let dane = (*ctx).dane.cast::<SslDane>();
        dane_reset(dane);

        let matched = dane_match_rpk(ctx, (*ctx).rpk);
        (*ctx).error_depth = 0;

        if matched < 0 {
            (*ctx).error = X509_V_ERR_UNSPECIFIED;
            return -1;
        }

        if matched > 0 {
            (*ctx).error = X509_V_OK;
        } else {
            (*ctx).error = X509_V_ERR_DANE_NO_MATCH;
        }

        verify_rpk(ctx)
    }
}

/// `static int dane_verify(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:3431-3490`.
///
/// # Safety
///
/// `ctx` must be live with a live `dane`, `cert` and `chain`.
unsafe fn dane_verify(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract; the DANE and engine callees obey their contracts.
    unsafe {
        let cert = (*ctx).cert;
        let dane = (*ctx).dane.cast::<SslDane>();

        dane_reset(dane);

        let matched = dane_match_cert(ctx, (*ctx).cert, 0);
        let done = matched != 0 || (!danetls_has_ta(dane) && (*dane).mdpth < 0);

        if done && X509_get_pubkey_parameters(ptr::null_mut(), (*ctx).chain) == 0 {
            return -1;
        }

        if matched > 0 {
            if check_leaf_suiteb(ctx, cert) == 0 {
                return 0;
            }
            if ((*dane).flags & DANE_FLAG_NO_DANE_EE_NAMECHECKS) == 0 && check_id(ctx) == 0 {
                return 0;
            }
            (*ctx).error_depth = 0;
            (*ctx).current_cert = cert;
            return match (*ctx).verify_cb {
                Some(cb) => cb(1, ctx.cast()),
                None => 0,
            };
        }

        if matched < 0 {
            (*ctx).error_depth = 0;
            (*ctx).current_cert = cert;
            (*ctx).error = X509_V_ERR_OUT_OF_MEM;
            return -1;
        }

        if done {
            if check_leaf_suiteb(ctx, cert) == 0 {
                return 0;
            }
            return verify_cb_cert(ctx, cert, 0, X509_V_ERR_DANE_NO_MATCH);
        }

        verify_chain(ctx)
    }
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
