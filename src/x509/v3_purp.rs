//! `crypto/x509/v3_purp.c` — the certificate purpose table and the X.509 extension cache. Phase
//! 10.14, landed whole.
//!
//! `crypto/x509/v3_purp.c` is 1,147 lines. **This module transcribes all thirty-one
//! externally-linked functions and their nineteen translation-unit-local helpers, with nothing
//! withheld.** The unit's centre of gravity is [`ossl_x509v3_cache_extensions`] (`:440-679`), the
//! function `X509_self_signed` (`x509_vfy.c`, 10.14.12) and the [`X509_cmp`](crate::x509::x509_cmp)
//! family wait on: every one of its callees is landed, so it lands rather than being withheld.
//!
//! * The purpose table lands: [`XSTANDARD`] (`xstandard[]`, `:46-70`) with its ten rows, the
//!   dynamic [`XPTABLE`] (`:75`), [`xp_cmp`] (`:77-80`), [`X509_check_purpose`] (`:88-103`),
//!   [`X509_PURPOSE_set`] (`:106-114`), the six `X509_PURPOSE_get*` accessors (`:116-170`,
//!   `:281-299`), [`X509_PURPOSE_add`] (`:176-260`), [`xptable_free`] (`:262-273`) and
//!   [`X509_PURPOSE_cleanup`] (`:275-279`).
//! * The extension-support search lands: [`X509_supported_extension`] (`:309-346`) over the
//!   sorted `supported_nids[]` (`:318-336`), with the generated `OBJ_bsearch_nid` collapsed into
//!   [`obj_bsearch_nid`] over [`nid_cmp`].
//! * The cache lands entire: [`setup_dp`] (`:349-388`), [`setup_crldp`] (`:391-406`),
//!   [`check_sig_alg_match`] (`:409-423`) and [`ossl_x509v3_cache_extensions`] (`:440-679`).
//! * The purpose checks land: [`check_ca`] (`:693-717`), the two proxy setters (`:719-730`),
//!   [`X509_check_ca`] (`:732-739`) and the eleven `check_purpose_*`/`purpose_smime`
//!   callbacks (`:742-975`).
//! * The issuer surface lands: [`X509_check_issued`] (`:990-997`), [`ossl_x509_likely_issued`]
//!   (`:1000-1020`), [`ossl_x509_signing_allowed`] (`:1029-1038`) and [`X509_check_akid`]
//!   (`:1040-1074`).
//! * The cache accessors land: [`X509_get_extension_flags`] (`:1076-1081`), the two usage
//!   getters (`:1083-1097`), the four `X509_get0_*` identifiers (`:1099-1129`) and the two
//!   path-length getters (`:1131-1147`).
//!
//! ## Why nothing is withheld
//!
//! The 10.14.5 landing of `crypto/x509/x509_ext.c` removed four of the six names
//! `ossl_x509v3_cache_extensions` was measured to need (`X509_get_ext`/`_by_NID`/`_count`/
//! `_get_ext_d2i`); the other two are [`ossl_x509_init_sig_info`](crate::x509::x509_set) and
//! [`DIST_POINT_set_dpname`](crate::x509::v3_crld), both already landed. The type layer the cache
//! touches is landed too — [`BasicConstraints`] (`v3_bcons.rs`), [`ProxyCertInfoExtension`]
//! (`v3_pcia.rs`), [`DistPoint`] (`v3_crld.rs`), [`GeneralName`] (`v3_genn.rs`) and
//! [`AuthorityKeyid`] (`v3_akeya.rs`) — and the `X509` struct already models `skid`, `akid`,
//! `crldp`, `altname`, `nc`, `rfc3779_addr` and `rfc3779_asid`. The `X509_STORE_CTX`-shaped names
//! this file never had (`X509_verify_cert` lives in `x509_vfy.c`) are not in the unit.
//!
//! ## Local raise sites
//!
//! `crypto/x509/v3_purp.c` is **not** in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its eleven
//! coordinates are **declared locally** in the `err_sites::ErrSite` shape (as `v3_asid.rs` does),
//! with the reason values read from the authority's `err.h.in`/`x509err.h`/`x509v3err.h` rather
//! than typed from memory: `X509_PURPOSE_set`'s invalid-purpose (`:109`), six in
//! `X509_PURPOSE_add` (`:185`/`:189`/`:202`/`:212`/`:241`/`:245`), `setup_dp`'s invalid
//! distribution point (`:355`) and the three cache refusals (`:484`/`:525`/`:677`). The two
//! composite reasons come from `err.h.in`: `ERR_R_PASSED_INVALID_ARGUMENT` = `262 | ERR_RFLAG_COMMON`
//! (`:360`) and `ERR_R_CRYPTO_LIB` = `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON` (`:330`), with
//! `ERR_RFLAG_COMMON` = `0x2 << 18` (`:241`) and `ERR_LIB_CRYPTO` = 15 (`:89`).
//!
//! ## The two composite-value conventions
//!
//! `x->ex_kusage`/`ex_nscert` pack a DER bit string's first two octets little-endian
//! (`:517-519`, `:578-581`), and `dp->dp_reasons` masks the result down to `CRLDP_ALL_REASONS`
//! (`:363`). `X509_PURPOSE_get_by_id` answers the standard table index directly for the ten
//! reserved ids and otherwise binary-searches the dynamic table (`:161-170`), so a dynamic row's
//! index is offset by `X509_PURPOSE_COUNT`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::asn1::layout::V_ASN1_NEG_INTEGER;
use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_get, ASN1_OBJECT_free};
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_OCTET_STRING_cmp};
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::pkey::{EVP_PKEY_is_a, EvpPkey};
use crate::runtime::bio::sys::strcmp;
use crate::runtime::err::err_reasons::{
    X509V3_R_EMPTY_KEY_USAGE, X509V3_R_INVALID_CERTIFICATE, X509V3_R_INVALID_PURPOSE,
    X509V3_R_NEGATIVE_PATHLEN, X509V3_R_PURPOSE_NOT_UNIQUE, X509_R_INVALID_DISTPOINT,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::obj::{
    Asn1Object, NID_OCSP_sign, NID_anyExtendedKeyUsage, NID_authority_key_identifier,
    NID_basic_constraints, NID_certificate_policies, NID_client_auth, NID_code_sign,
    NID_crl_distribution_points, NID_dvcs, NID_email_protect, NID_ext_key_usage, NID_freshest_crl,
    NID_id_pkix_OCSP_noCheck, NID_inhibit_any_policy, NID_issuer_alt_name, NID_key_usage,
    NID_ms_sgc, NID_name_constraints, NID_netscape_cert_type, NID_ns_sgc, NID_policy_constraints,
    NID_policy_mappings, NID_proxyCertInfo, NID_rsassaPss, NID_sbgp_autonomousSysNum,
    NID_sbgp_ipAddrBlock, NID_server_auth, NID_subject_alt_name, NID_subject_key_identifier,
    NID_time_stamp, NID_undef, OBJ_bsearch_, OBJ_find_sigid_algs, OBJ_nid2sn, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_set, OPENSSL_sk_value, OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock};
use crate::x509::v3_akeya::AuthorityKeyid;
use crate::x509::v3_bcons::{BASIC_CONSTRAINTS_free, BasicConstraints};
use crate::x509::v3_crld::{DIST_POINT_set_dpname, DistPoint};
use crate::x509::v3_genn::{GeneralName, GEN_DIRNAME};
use crate::x509::v3_pcia::{PROXY_CERT_INFO_EXTENSION_free, ProxyCertInfoExtension};
use crate::x509::x509_cmp::{
    X509_NAME_cmp, X509_get0_pubkey, X509_get0_serialNumber, X509_get_issuer_name,
    X509_get_subject_name,
};
use crate::x509::x509_ext::{
    X509_get_ext, X509_get_ext_by_NID, X509_get_ext_count, X509_get_ext_d2i,
};
use crate::x509::x509_set::{ossl_x509_init_sig_info, X509_get_version};
use crate::x509::x509_v3::{X509_EXTENSION_get_critical, X509_EXTENSION_get_object};
use crate::x509::x_all::X509_digest;
use crate::x509::x_exten::X509Extension;
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::X509;

// ---------------------------------------------------------------------------------------------
// Local raise coordinates — see the module doc.
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`
/// (`15 | 0x80000`).
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// One `v3_purp.c` raise coordinate, declared locally (see the module doc).
const fn v3_purp_site(line: c_int, func: &'static CStr, lib: c_int, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_purp.c",
        line,
        func,
        lib,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_PURPOSE_set`'s invalid purpose at `v3_purp.c:109`.
const V3_PURP_109: ErrSite = v3_purp_site(
    109,
    c"X509_PURPOSE_set",
    ERR_LIB_X509V3,
    X509V3_R_INVALID_PURPOSE,
);
/// `X509_PURPOSE_add`'s `id < X509_PURPOSE_MIN` at `v3_purp.c:185`.
const V3_PURP_185: ErrSite = v3_purp_site(
    185,
    c"X509_PURPOSE_add",
    ERR_LIB_X509V3,
    X509V3_R_INVALID_PURPOSE,
);
/// `X509_PURPOSE_add`'s NULL/malformed argument at `v3_purp.c:189`.
const V3_PURP_189: ErrSite = v3_purp_site(
    189,
    c"X509_PURPOSE_add",
    ERR_LIB_X509,
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `X509_PURPOSE_add`'s already-taken id for a new entry at `v3_purp.c:202`.
const V3_PURP_202: ErrSite = v3_purp_site(
    202,
    c"X509_PURPOSE_add",
    ERR_LIB_X509V3,
    X509V3_R_PURPOSE_NOT_UNIQUE,
);
/// `X509_PURPOSE_add`'s already-taken id on an id change at `v3_purp.c:212`.
const V3_PURP_212: ErrSite = v3_purp_site(
    212,
    c"X509_PURPOSE_add",
    ERR_LIB_X509V3,
    X509V3_R_PURPOSE_NOT_UNIQUE,
);
/// `X509_PURPOSE_add`'s failed `sk_X509_PURPOSE_new` at `v3_purp.c:241`.
const V3_PURP_241: ErrSite =
    v3_purp_site(241, c"X509_PURPOSE_add", ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
/// `X509_PURPOSE_add`'s failed `sk_X509_PURPOSE_push` at `v3_purp.c:245`.
const V3_PURP_245: ErrSite =
    v3_purp_site(245, c"X509_PURPOSE_add", ERR_LIB_X509V3, ERR_R_CRYPTO_LIB);
/// `setup_dp`'s distribution point with neither a name nor an issuer at `v3_purp.c:355`.
const V3_PURP_355: ErrSite = v3_purp_site(355, c"setup_dp", ERR_LIB_X509, X509_R_INVALID_DISTPOINT);
/// `ossl_x509v3_cache_extensions`' negative basic-constraints path length at `v3_purp.c:484`.
const V3_PURP_484: ErrSite = v3_purp_site(
    484,
    c"ossl_x509v3_cache_extensions",
    ERR_LIB_X509V3,
    X509V3_R_NEGATIVE_PATHLEN,
);
/// `ossl_x509v3_cache_extensions`' empty key usage at `v3_purp.c:525`.
const V3_PURP_525: ErrSite = v3_purp_site(
    525,
    c"ossl_x509v3_cache_extensions",
    ERR_LIB_X509V3,
    X509V3_R_EMPTY_KEY_USAGE,
);
/// `ossl_x509v3_cache_extensions`' invalid certificate at `v3_purp.c:677`.
const V3_PURP_677: ErrSite = v3_purp_site(
    677,
    c"ossl_x509v3_cache_extensions",
    ERR_LIB_X509V3,
    X509V3_R_INVALID_CERTIFICATE,
);

// ---------------------------------------------------------------------------------------------
// Constants — `include/openssl/x509v3.h`, `include/openssl/x509.h`, `include/openssl/x509_vfy.h`.
// ---------------------------------------------------------------------------------------------

/// `X509_VERSION_1` — `include/openssl/x509.h:845`.
const X509_VERSION_1: c_long = 0;

/// `CRLDP_ALL_REASONS` — `include/openssl/x509v3.h:316`.
const CRLDP_ALL_REASONS: c_int = 0x807f;

/// `EXFLAG_BCONS` — `include/openssl/x509v3.h:668`.
const EXFLAG_BCONS: c_uint = 0x1;
/// `EXFLAG_KUSAGE` — `include/openssl/x509v3.h:669`.
const EXFLAG_KUSAGE: c_uint = 0x2;
/// `EXFLAG_XKUSAGE` — `include/openssl/x509v3.h:670`.
const EXFLAG_XKUSAGE: c_uint = 0x4;
/// `EXFLAG_NSCERT` — `include/openssl/x509v3.h:671`.
const EXFLAG_NSCERT: c_uint = 0x8;
/// `EXFLAG_CA` — `include/openssl/x509v3.h:673`.
const EXFLAG_CA: c_uint = 0x10;
/// `EXFLAG_SI` — `include/openssl/x509v3.h:674`.
const EXFLAG_SI: c_uint = 0x20;
/// `EXFLAG_V1` — `include/openssl/x509v3.h:675`.
const EXFLAG_V1: c_uint = 0x40;
/// `EXFLAG_INVALID` — `include/openssl/x509v3.h:676`.
const EXFLAG_INVALID: c_uint = 0x80;
/// `EXFLAG_SET` — `include/openssl/x509v3.h:678`.
const EXFLAG_SET: c_uint = 0x100;
/// `EXFLAG_CRITICAL` — `include/openssl/x509v3.h:679`.
const EXFLAG_CRITICAL: c_uint = 0x200;
/// `EXFLAG_PROXY` — `include/openssl/x509v3.h:680`.
const EXFLAG_PROXY: c_uint = 0x400;
/// `EXFLAG_FRESHEST` — `include/openssl/x509v3.h:683`.
const EXFLAG_FRESHEST: c_uint = 0x1000;
/// `EXFLAG_SS` — `include/openssl/x509v3.h:684`.
const EXFLAG_SS: c_uint = 0x2000;
/// `EXFLAG_BCONS_CRITICAL` — `include/openssl/x509v3.h:686`.
const EXFLAG_BCONS_CRITICAL: c_uint = 0x10000;
/// `EXFLAG_AKID_CRITICAL` — `include/openssl/x509v3.h:687`.
const EXFLAG_AKID_CRITICAL: c_uint = 0x20000;
/// `EXFLAG_SKID_CRITICAL` — `include/openssl/x509v3.h:688`.
const EXFLAG_SKID_CRITICAL: c_uint = 0x40000;
/// `EXFLAG_SAN_CRITICAL` — `include/openssl/x509v3.h:689`.
const EXFLAG_SAN_CRITICAL: c_uint = 0x80000;
/// `EXFLAG_NO_FINGERPRINT` — `include/openssl/x509v3.h:690`.
const EXFLAG_NO_FINGERPRINT: c_uint = 0x100000;

/// `KU_DIGITAL_SIGNATURE` — `include/openssl/x509.h:178`, `X509v3_KU_DIGITAL_SIGNATURE`.
const KU_DIGITAL_SIGNATURE: c_uint = 0x0080;
/// `KU_NON_REPUDIATION` — `include/openssl/x509.h:179`.
const KU_NON_REPUDIATION: c_uint = 0x0040;
/// `KU_KEY_ENCIPHERMENT` — `include/openssl/x509.h:180`.
const KU_KEY_ENCIPHERMENT: c_uint = 0x0020;
/// `KU_KEY_AGREEMENT` — `include/openssl/x509.h:182`.
const KU_KEY_AGREEMENT: c_uint = 0x0008;
/// `KU_KEY_CERT_SIGN` — `include/openssl/x509.h:183`.
const KU_KEY_CERT_SIGN: c_uint = 0x0004;
/// `KU_CRL_SIGN` — `include/openssl/x509.h:184`.
const KU_CRL_SIGN: c_uint = 0x0002;

/// `NS_SSL_CLIENT` — `include/openssl/x509v3.h:703`.
const NS_SSL_CLIENT: c_uint = 0x80;
/// `NS_SSL_SERVER` — `include/openssl/x509v3.h:704`.
const NS_SSL_SERVER: c_uint = 0x40;
/// `NS_SMIME` — `include/openssl/x509v3.h:705`.
const NS_SMIME: c_uint = 0x20;
/// `NS_SSL_CA` — `include/openssl/x509v3.h:707`.
const NS_SSL_CA: c_uint = 0x04;
/// `NS_SMIME_CA` — `include/openssl/x509v3.h:708`.
const NS_SMIME_CA: c_uint = 0x02;
/// `NS_OBJSIGN_CA` — `include/openssl/x509v3.h:709`.
const NS_OBJSIGN_CA: c_uint = 0x01;
/// `NS_ANY_CA` — `include/openssl/x509v3.h:710`, `NS_SSL_CA | NS_SMIME_CA | NS_OBJSIGN_CA`.
const NS_ANY_CA: c_uint = NS_SSL_CA | NS_SMIME_CA | NS_OBJSIGN_CA;

/// `XKU_SSL_SERVER` — `include/openssl/x509v3.h:712`.
const XKU_SSL_SERVER: c_uint = 0x1;
/// `XKU_SSL_CLIENT` — `include/openssl/x509v3.h:713`.
const XKU_SSL_CLIENT: c_uint = 0x2;
/// `XKU_SMIME` — `include/openssl/x509v3.h:714`.
const XKU_SMIME: c_uint = 0x4;
/// `XKU_CODE_SIGN` — `include/openssl/x509v3.h:715`.
const XKU_CODE_SIGN: c_uint = 0x8;
/// `XKU_SGC` — `include/openssl/x509v3.h:716`.
const XKU_SGC: c_uint = 0x10;
/// `XKU_OCSP_SIGN` — `include/openssl/x509v3.h:717`.
const XKU_OCSP_SIGN: c_uint = 0x20;
/// `XKU_TIMESTAMP` — `include/openssl/x509v3.h:718`.
const XKU_TIMESTAMP: c_uint = 0x40;
/// `XKU_DVCS` — `include/openssl/x509v3.h:719`.
const XKU_DVCS: c_uint = 0x80;
/// `XKU_ANYEKU` — `include/openssl/x509v3.h:720`.
const XKU_ANYEKU: c_uint = 0x100;

/// `X509_PURPOSE_DEFAULT_ANY` — `include/openssl/x509v3.h:765`.
const X509_PURPOSE_DEFAULT_ANY: c_int = 0;
/// `X509_PURPOSE_SSL_CLIENT` — `include/openssl/x509v3.h:766`.
const X509_PURPOSE_SSL_CLIENT: c_int = 1;
/// `X509_PURPOSE_SSL_SERVER` — `include/openssl/x509v3.h:767`.
const X509_PURPOSE_SSL_SERVER: c_int = 2;
/// `X509_PURPOSE_NS_SSL_SERVER` — `include/openssl/x509v3.h:768`.
const X509_PURPOSE_NS_SSL_SERVER: c_int = 3;
/// `X509_PURPOSE_SMIME_SIGN` — `include/openssl/x509v3.h:769`.
const X509_PURPOSE_SMIME_SIGN: c_int = 4;
/// `X509_PURPOSE_SMIME_ENCRYPT` — `include/openssl/x509v3.h:770`.
const X509_PURPOSE_SMIME_ENCRYPT: c_int = 5;
/// `X509_PURPOSE_CRL_SIGN` — `include/openssl/x509v3.h:771`.
const X509_PURPOSE_CRL_SIGN: c_int = 6;
/// `X509_PURPOSE_ANY` — `include/openssl/x509v3.h:772`.
const X509_PURPOSE_ANY: c_int = 7;
/// `X509_PURPOSE_OCSP_HELPER` — `include/openssl/x509v3.h:773`.
const X509_PURPOSE_OCSP_HELPER: c_int = 8;
/// `X509_PURPOSE_TIMESTAMP_SIGN` — `include/openssl/x509v3.h:774`.
const X509_PURPOSE_TIMESTAMP_SIGN: c_int = 9;
/// `X509_PURPOSE_CODE_SIGN` — `include/openssl/x509v3.h:775`.
const X509_PURPOSE_CODE_SIGN: c_int = 10;
/// `X509_PURPOSE_MIN` — `include/openssl/x509v3.h:777`.
const X509_PURPOSE_MIN: c_int = 1;
/// `X509_PURPOSE_MAX` — `include/openssl/x509v3.h:778`.
const X509_PURPOSE_MAX: c_int = 10;
/// `X509_PURPOSE_DYNAMIC` — `include/openssl/x509v3.h:722`.
const X509_PURPOSE_DYNAMIC: c_int = 0x1;
/// `X509_PURPOSE_DYNAMIC_NAME` — `include/openssl/x509v3.h:723`.
const X509_PURPOSE_DYNAMIC_NAME: c_int = 0x2;
/// `X509_PURPOSE_COUNT` — `OSSL_NELEM(xstandard)` (`v3_purp.c:72`).
const X509_PURPOSE_COUNT: c_int = 10;

/// `X509_TRUST_DEFAULT` — `include/openssl/x509_vfy.h:195`.
const X509_TRUST_DEFAULT: c_int = 0;
/// `X509_TRUST_COMPAT` — `include/openssl/x509_vfy.h:196`.
const X509_TRUST_COMPAT: c_int = 1;
/// `X509_TRUST_SSL_CLIENT` — `include/openssl/x509_vfy.h:197`.
const X509_TRUST_SSL_CLIENT: c_int = 2;
/// `X509_TRUST_SSL_SERVER` — `include/openssl/x509_vfy.h:198`.
const X509_TRUST_SSL_SERVER: c_int = 3;
/// `X509_TRUST_EMAIL` — `include/openssl/x509_vfy.h:199`.
const X509_TRUST_EMAIL: c_int = 4;
/// `X509_TRUST_OBJECT_SIGN` — `include/openssl/x509_vfy.h:200`.
const X509_TRUST_OBJECT_SIGN: c_int = 5;
/// `X509_TRUST_TSA` — `include/openssl/x509_vfy.h:203`.
const X509_TRUST_TSA: c_int = 8;

/// `X509_V_OK` — `include/openssl/x509_vfy.h`.
const X509_V_OK: c_int = 0;
/// `X509_V_ERR_UNSPECIFIED` — `include/openssl/x509_vfy.h:213`.
const X509_V_ERR_UNSPECIFIED: c_int = 1;
/// `X509_V_ERR_NO_ISSUER_PUBLIC_KEY` — `include/openssl/x509_vfy.h:236`.
const X509_V_ERR_NO_ISSUER_PUBLIC_KEY: c_int = 24;
/// `X509_V_ERR_SUBJECT_ISSUER_MISMATCH` — `include/openssl/x509_vfy.h:241`.
const X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
/// `X509_V_ERR_AKID_SKID_MISMATCH` — `include/openssl/x509_vfy.h:242`.
const X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
/// `X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH` — `include/openssl/x509_vfy.h:243`.
const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
/// `X509_V_ERR_KEYUSAGE_NO_CERTSIGN` — `include/openssl/x509_vfy.h:244`.
const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
/// `X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE` — `include/openssl/x509_vfy.h:251`.
const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
/// `X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM` — `include/openssl/x509_vfy.h:288`.
const X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM: c_int = 76;
/// `X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH` — `include/openssl/x509_vfy.h:289`.
const X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH: c_int = 77;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc`/`OPENSSL_strdup`/`OPENSSL_free` expansions —
/// `crypto/x509/v3_purp.c`.
const FILE: &CStr = c"crypto/x509/v3_purp.c";

/// `X509_PURPOSE_add`'s `OPENSSL_malloc(sizeof(*ptmp))` (`v3_purp.c:205`).
const LINE_ADD_MALLOC: c_int = 205;
/// The same function's `OPENSSL_free(ptmp->name)` of an existing dynamic name (`:219`).
const LINE_ADD_FREE_NAME: c_int = 219;
/// The same function's `OPENSSL_free(ptmp->sname)` (`:220`).
const LINE_ADD_FREE_SNAME: c_int = 220;
/// The same function's `OPENSSL_strdup(name)` (`:223`).
const LINE_ADD_STRDUP_NAME: c_int = 223;
/// The same function's `OPENSSL_strdup(sname)` (`:224`).
const LINE_ADD_STRDUP_SNAME: c_int = 224;
/// The same function's error-path `OPENSSL_free(ptmp->name)` (`:255`).
const LINE_ADD_ERR_NAME: c_int = 255;
/// The same function's error-path `OPENSSL_free(ptmp->sname)` (`:256`).
const LINE_ADD_ERR_SNAME: c_int = 256;
/// The same function's error-path `OPENSSL_free(ptmp)` (`:257`).
const LINE_ADD_ERR_PTMP: c_int = 257;
/// `xptable_free`'s `OPENSSL_free(p->name)` (`:268`).
const LINE_XPFREE_NAME: c_int = 268;
/// The same function's `OPENSSL_free(p->sname)` (`:269`).
const LINE_XPFREE_SNAME: c_int = 269;
/// The same function's `OPENSSL_free(p)` (`:271`).
const LINE_XPFREE_P: c_int = 271;

// ---------------------------------------------------------------------------------------------
// The purpose type and the two tables — `v3_purp.c:46-80`
// ---------------------------------------------------------------------------------------------

/// `struct x509_purpose_st` — `X509_PURPOSE`, from `include/openssl/x509v3.h:725-733`.
///
/// One row of a purpose table: the reserved id, the default trust id, the `X509_PURPOSE_*` flags,
/// the purpose check callback, the long/short names and the application's opaque argument.
#[repr(C)]
pub struct X509Purpose {
    /// `int purpose` — the id, unique among all rows.
    pub(crate) purpose: c_int,
    /// `int trust` — the default trust id the purpose maps to.
    pub(crate) trust: c_int,
    /// `int flags` — `X509_PURPOSE_DYNAMIC`/`X509_PURPOSE_DYNAMIC_NAME`.
    pub(crate) flags: c_int,
    /// `int (*check_purpose)(const X509_PURPOSE *, const X509 *, int)` — the checker.
    pub(crate) check_purpose: Option<CheckPurpose>,
    /// `char *name` — the long name, owned when `X509_PURPOSE_DYNAMIC_NAME` is set.
    pub(crate) name: *mut c_char,
    /// `char *sname` — the short name, likewise owned.
    pub(crate) sname: *mut c_char,
    /// `void *usr_data` — the application's argument.
    pub(crate) usr_data: *mut c_void,
}

/// The `check_purpose` callback the `X509_PURPOSE` struct carries.
type CheckPurpose = unsafe extern "C" fn(*const X509Purpose, *const X509, c_int) -> c_int;

const _: () = {
    assert!(size_of::<X509Purpose>() == 48);
    assert!(core::mem::offset_of!(X509Purpose, purpose) == 0);
    assert!(core::mem::offset_of!(X509Purpose, trust) == 4);
    assert!(core::mem::offset_of!(X509Purpose, flags) == 8);
    assert!(core::mem::offset_of!(X509Purpose, check_purpose) == 16);
    assert!(core::mem::offset_of!(X509Purpose, name) == 24);
    assert!(core::mem::offset_of!(X509Purpose, sname) == 32);
    assert!(core::mem::offset_of!(X509Purpose, usr_data) == 40);
};

// SAFETY: a purpose row is a plain data record reached only through the module's own
// single-threaded table discipline. The standard table is wrapped in an `UnsafeCell` (see
// [`XstandardTable`]) because `X509_PURPOSE_add` may modify a standard row in place, and this
// wrapper is what carries the `Sync` claim for that writable storage.
#[repr(transparent)]
struct XstandardTable(UnsafeCell<[X509Purpose; 10]>);

// SAFETY: the table is read and written only through this module's unlocked, single-threaded
// purpose-table discipline, exactly as the authority's plain `xstandard[]` is.
unsafe impl Sync for XstandardTable {}

/// `static X509_PURPOSE xstandard[]` — `v3_purp.c:46-70`.
///
/// The ten reserved purposes, in `purpose` order so index `id - 1` is the row for reserved id `id`.
static XSTANDARD: XstandardTable = XstandardTable(UnsafeCell::new([
    X509Purpose {
        purpose: X509_PURPOSE_SSL_CLIENT,
        trust: X509_TRUST_SSL_CLIENT,
        flags: 0,
        check_purpose: Some(check_purpose_ssl_client),
        name: c"SSL client".as_ptr().cast_mut(),
        sname: c"sslclient".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_SSL_SERVER,
        trust: X509_TRUST_SSL_SERVER,
        flags: 0,
        check_purpose: Some(check_purpose_ssl_server),
        name: c"SSL server".as_ptr().cast_mut(),
        sname: c"sslserver".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_NS_SSL_SERVER,
        trust: X509_TRUST_SSL_SERVER,
        flags: 0,
        check_purpose: Some(check_purpose_ns_ssl_server),
        name: c"Netscape SSL server".as_ptr().cast_mut(),
        sname: c"nssslserver".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_SMIME_SIGN,
        trust: X509_TRUST_EMAIL,
        flags: 0,
        check_purpose: Some(check_purpose_smime_sign),
        name: c"S/MIME signing".as_ptr().cast_mut(),
        sname: c"smimesign".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_SMIME_ENCRYPT,
        trust: X509_TRUST_EMAIL,
        flags: 0,
        check_purpose: Some(check_purpose_smime_encrypt),
        name: c"S/MIME encryption".as_ptr().cast_mut(),
        sname: c"smimeencrypt".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_CRL_SIGN,
        trust: X509_TRUST_COMPAT,
        flags: 0,
        check_purpose: Some(check_purpose_crl_sign),
        name: c"CRL signing".as_ptr().cast_mut(),
        sname: c"crlsign".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_ANY,
        trust: X509_TRUST_DEFAULT,
        flags: 0,
        check_purpose: Some(no_check_purpose),
        name: c"Any Purpose".as_ptr().cast_mut(),
        sname: c"any".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_OCSP_HELPER,
        trust: X509_TRUST_COMPAT,
        flags: 0,
        check_purpose: Some(check_purpose_ocsp_helper),
        name: c"OCSP helper".as_ptr().cast_mut(),
        sname: c"ocsphelper".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_TIMESTAMP_SIGN,
        trust: X509_TRUST_TSA,
        flags: 0,
        check_purpose: Some(check_purpose_timestamp_sign),
        name: c"Time Stamp signing".as_ptr().cast_mut(),
        sname: c"timestampsign".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
    X509Purpose {
        purpose: X509_PURPOSE_CODE_SIGN,
        trust: X509_TRUST_OBJECT_SIGN,
        flags: 0,
        check_purpose: Some(check_purpose_code_sign),
        name: c"Code signing".as_ptr().cast_mut(),
        sname: c"codesign".as_ptr().cast_mut(),
        usr_data: ptr::null_mut(),
    },
]));

/// `static STACK_OF(X509_PURPOSE) *xptable` — `v3_purp.c:75`.
///
/// The dynamic rows an application adds through [`X509_PURPOSE_add`]. The authority stores a bare
/// pointer and never locks it; this models the same single-threaded slot as an `AtomicPtr` so the
/// static is sound, without adding synchronisation the authority does not have.
static XPTABLE: AtomicPtr<OpenSslStack> = AtomicPtr::new(ptr::null_mut());

/// `static int xp_cmp(const X509_PURPOSE *const *a, const X509_PURPOSE *const *b)` —
/// `v3_purp.c:77-80`.
///
/// The `STACK` comparator receives pointers to the element pointers, so both arguments are cast to
/// `*const *const X509Purpose` before the id is read.
///
/// # Safety
///
/// `a` and `b` must each point at a live `X509_PURPOSE *` slot.
unsafe extern "C" fn xp_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: both arguments are pointer-to-element-pointer slots per the stack's contract.
    unsafe {
        (**a.cast::<*const X509Purpose>()).purpose - (**b.cast::<*const X509Purpose>()).purpose
    }
}

/// `static void xptable_free(X509_PURPOSE *p)` — `v3_purp.c:262-273`.
///
/// Frees a dynamic row's owned names and then the row; a standard row (no `X509_PURPOSE_DYNAMIC`)
/// and NULL are left alone.
///
/// # Safety
///
/// `p` must be NULL or a row this module allocated through [`X509_PURPOSE_add`].
unsafe fn xptable_free(p: *mut X509Purpose) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is non-NULL and live per the contract.
    if (unsafe { (*p).flags } & X509_PURPOSE_DYNAMIC) == 0 {
        return;
    }
    // SAFETY: `p` is a dynamic row and its fields are live.
    if (unsafe { (*p).flags } & X509_PURPOSE_DYNAMIC_NAME) != 0 {
        // SAFETY: `name`/`sname` are the dynamic row's own owned strings.
        unsafe {
            CRYPTO_free((*p).name.cast::<c_void>(), FILE.as_ptr(), LINE_XPFREE_NAME);
            CRYPTO_free(
                (*p).sname.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_XPFREE_SNAME,
            );
        }
    }
    // SAFETY: `p` is the row this function frees.
    unsafe { CRYPTO_free(p.cast::<c_void>(), FILE.as_ptr(), LINE_XPFREE_P) };
}

/// The `X509_PURPOSE` destructor [`X509_PURPOSE_cleanup`] passes to `OPENSSL_sk_pop_free`.
///
/// # Safety
///
/// `elem` must be NULL or an `X509_PURPOSE` this module allocated.
unsafe extern "C" fn xptable_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a row per the contract; `xptable_free` accepts NULL.
    unsafe { xptable_free(elem.cast::<X509Purpose>()) };
}

/// The `ASN1_OBJECT` destructor the extended-key-usage `pop_free` passes.
///
/// # Safety
///
/// `elem` must be NULL or an `ASN1_OBJECT` the stack owns.
unsafe extern "C" fn asn1_object_free_thunk(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or a live object per the contract; `ASN1_OBJECT_free` accepts NULL.
    unsafe { ASN1_OBJECT_free(elem.cast::<Asn1Object>()) };
}

// ---------------------------------------------------------------------------------------------
// The purpose table accessors — `v3_purp.c:88-299`
// ---------------------------------------------------------------------------------------------

/// `int X509_check_purpose(X509 *x, int id, int non_leaf)` — `v3_purp.c:88-103`.
///
/// Caches the certificate's extensions first, then dispatches to the row's `check_purpose`
/// callback. With `id == -1` it only runs the cache and answers 1; an unknown `id` answers -1.
///
/// # Safety
///
/// `x` must be a live, unlocked `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_purpose(x: *mut X509, id: c_int, non_leaf: c_int) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { ossl_x509v3_cache_extensions(x) } == 0 {
        return -1;
    }
    if id == -1 {
        return 1;
    }
    // SAFETY: `x` is live; the id is an arbitrary caller value.
    let idx = unsafe { X509_PURPOSE_get_by_id(id) };
    if idx == -1 {
        return -1;
    }
    // SAFETY: `idx` is a valid index per `X509_PURPOSE_get_by_id`.
    let pt = unsafe { X509_PURPOSE_get0(idx) };
    // SAFETY: `pt` is a live row; `x` is live. A row without a checker cannot be dispatched, which
    // the authority cannot construct either.
    match unsafe { (*pt).check_purpose } {
        // SAFETY: `check` is the row's own checker and both are live.
        Some(check) => unsafe { check(pt, x, non_leaf) },
        None => -1,
    }
}

/// `int X509_PURPOSE_set(int *p, int purpose)` — `v3_purp.c:106-114`.
///
/// Validates `purpose` against the table (allowing the reserved "any" zero) and stores it.
///
/// # Safety
///
/// `p` must be writable.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_set(p: *mut c_int, purpose: c_int) -> c_int {
    // SAFETY: the table is a module-owned static.
    if purpose != X509_PURPOSE_DEFAULT_ANY && unsafe { X509_PURPOSE_get_by_id(purpose) } == -1 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PURP_109) };
        return 0;
    }
    // SAFETY: `p` is writable per the contract.
    unsafe { *p = purpose };
    1
}

/// `int X509_PURPOSE_get_count(void)` — `v3_purp.c:116-121`.
///
/// The standard row count plus the dynamic table's length.
///
/// # Safety
///
/// No pointer arguments; the dynamic table is read under the module's single-threaded contract.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_count() -> c_int {
    let table = XPTABLE.load(Ordering::Acquire);
    if table.is_null() {
        return X509_PURPOSE_COUNT;
    }
    // SAFETY: `table` is the module's own list.
    let count = unsafe { OPENSSL_sk_num(table) };
    count + X509_PURPOSE_COUNT
}

/// `int X509_PURPOSE_get_unused_id(OSSL_LIB_CTX *libctx)` — `v3_purp.c:124-131`.
///
/// The smallest id above `X509_PURPOSE_MAX` not already taken.
///
/// # Safety
///
/// No pointer arguments are read; the dynamic table is read under the module's contract.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_unused_id(_libctx: *mut c_void) -> c_int {
    let mut id = X509_PURPOSE_MAX + 1;
    // SAFETY: the table is a module-owned static.
    while unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
        id += 1;
    }
    id
}

/// `X509_PURPOSE *X509_PURPOSE_get0(int idx)` — `v3_purp.c:133-140`.
///
/// A standard row for `idx < X509_PURPOSE_COUNT`, otherwise the dynamic table's
/// `idx - X509_PURPOSE_COUNT` entry. A negative index answers NULL, as does an out-of-range
/// dynamic index (through `OPENSSL_sk_value`).
///
/// # Safety
///
/// The dynamic table, if present, is the module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0(idx: c_int) -> *mut X509Purpose {
    if idx < 0 {
        return ptr::null_mut();
    }
    if idx < X509_PURPOSE_COUNT {
        // SAFETY: `idx` is within the standard table, whose storage is this module's own.
        return unsafe { XSTANDARD.0.get().cast::<X509Purpose>().add(idx as usize) };
    }
    let table = XPTABLE.load(Ordering::Acquire);
    // SAFETY: `table` is the module's own list; `OPENSSL_sk_value` accepts NULL and any index.
    unsafe { OPENSSL_sk_value(table, idx - X509_PURPOSE_COUNT) }.cast::<X509Purpose>()
}

/// `int X509_PURPOSE_get_by_sname(const char *sname)` — `v3_purp.c:142-153`.
///
/// The index of the row whose short name equals `sname`, or -1.
///
/// # Safety
///
/// `sname` must be a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_by_sname(sname: *const c_char) -> c_int {
    // SAFETY: the table is a module-owned static.
    for i in 0..unsafe { X509_PURPOSE_get_count() } {
        // SAFETY: `i` is a valid index per the count.
        let xptmp = unsafe { X509_PURPOSE_get0(i) };
        // SAFETY: `xptmp` is a live row and `sname` is NUL-terminated per the contract.
        if unsafe { strcmp((*xptmp).sname, sname) } == 0 {
            return i;
        }
    }
    -1
}

/// `int X509_PURPOSE_get_by_id(int purpose)` — `v3_purp.c:156-170`.
///
/// The reserved range answers its index directly; otherwise the dynamic table is binary-searched by
/// id, and a hit is offset by `X509_PURPOSE_COUNT`. A miss answers -1.
///
/// # Safety
///
/// The dynamic table, if present, is the module's own list.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_by_id(purpose: c_int) -> c_int {
    if (X509_PURPOSE_MIN..=X509_PURPOSE_MAX).contains(&purpose) {
        return purpose - X509_PURPOSE_MIN;
    }
    let table = XPTABLE.load(Ordering::Acquire);
    if table.is_null() {
        return -1;
    }
    // Only `purpose` is read from the key, so the zeroed remainder is never observed.
    let tmp = X509Purpose {
        purpose,
        trust: 0,
        flags: 0,
        check_purpose: None,
        name: ptr::null_mut(),
        sname: ptr::null_mut(),
        usr_data: ptr::null_mut(),
    };
    // SAFETY: `table` is the module's own list and `&tmp` is a live key its comparator reads.
    let idx = unsafe { OPENSSL_sk_find(table, (&raw const tmp).cast::<c_void>()) };
    if idx < 0 {
        return -1;
    }
    idx + X509_PURPOSE_COUNT
}

/// `int X509_PURPOSE_add(int id, int trust, int flags, int (*ck)(...), const char *name,
/// const char *sname, void *arg)` — `v3_purp.c:176-260`.
///
/// Adds a dynamic row, or modifies an existing row (including changing its id). The row's names are
/// copied; the flags field's `X509_PURPOSE_DYNAMIC` bit is application-controlled off and the
/// `X509_PURPOSE_DYNAMIC_NAME` bit is forced on.
///
/// # Safety
///
/// `name` and `sname` must be NUL-terminated C strings; `ck` must be a valid checker; the dynamic
/// table must not be raced.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_add(
    id: c_int,
    trust: c_int,
    flags: c_int,
    ck: Option<CheckPurpose>,
    name: *const c_char,
    sname: *const c_char,
    arg: *mut c_void,
) -> c_int {
    let mut old_id = 0;
    let ptmp: *mut X509Purpose;

    if id < X509_PURPOSE_MIN {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PURP_185) };
        return 0;
    }
    if trust < X509_TRUST_DEFAULT || name.is_null() || sname.is_null() || ck.is_none() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PURP_189) };
        return 0;
    }

    // This is set according to what we change: application can't set it.
    // This will always be set for application modified trust entries.
    let flags = (flags & !X509_PURPOSE_DYNAMIC) | X509_PURPOSE_DYNAMIC_NAME;

    // SAFETY: `sname` is NUL-terminated per the contract.
    let idx = unsafe { X509_PURPOSE_get_by_sname(sname) };
    if idx == -1 {
        // SAFETY: the table is a module-owned static.
        if unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PURP_202) };
            return 0;
        }
        // `CRYPTO_malloc` is the authority's safe `OPENSSL_malloc`.
        ptmp = CRYPTO_malloc(size_of::<X509Purpose>(), FILE.as_ptr(), LINE_ADD_MALLOC)
            .cast::<X509Purpose>();
        if ptmp.is_null() {
            return 0;
        }
        // SAFETY: `ptmp` is a fresh allocation.
        unsafe { (*ptmp).flags = X509_PURPOSE_DYNAMIC };
    } else {
        // SAFETY: `idx` is a valid index returned by the lookup above.
        ptmp = unsafe { X509_PURPOSE_get0(idx) };
        // SAFETY: `ptmp` is a live row.
        old_id = unsafe { (*ptmp).purpose };
        // SAFETY: the table is a module-owned static.
        if id != old_id && unsafe { X509_PURPOSE_get_by_id(id) } != -1 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PURP_212) };
            return 0;
        }
    }

    // OPENSSL_free existing name if dynamic
    // SAFETY: `ptmp` is live; its name fields are its own.
    if (unsafe { (*ptmp).flags } & X509_PURPOSE_DYNAMIC_NAME) != 0 {
        // SAFETY: `ptmp`'s owned strings are being replaced.
        unsafe {
            CRYPTO_free(
                (*ptmp).name.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_ADD_FREE_NAME,
            );
            CRYPTO_free(
                (*ptmp).sname.cast::<c_void>(),
                FILE.as_ptr(),
                LINE_ADD_FREE_SNAME,
            );
        }
    }
    // Dup supplied name
    // SAFETY: `name`/`sname` are NUL-terminated and `ptmp` is live.
    unsafe {
        (*ptmp).name = CRYPTO_strdup(name, FILE.as_ptr(), LINE_ADD_STRDUP_NAME);
        (*ptmp).sname = CRYPTO_strdup(sname, FILE.as_ptr(), LINE_ADD_STRDUP_SNAME);
    }

    let mut result = 1;
    // SAFETY: `ptmp` is live and its just-assigned string fields are readable.
    if unsafe { (*ptmp).name.is_null() || (*ptmp).sname.is_null() } {
        // goto err
        result = 0;
    } else {
        // SAFETY: `ptmp` is a live row whose fields are writable.
        unsafe {
            // Keep the dynamic flag of the existing entry, then set all other flags.
            (*ptmp).flags &= X509_PURPOSE_DYNAMIC;
            (*ptmp).flags |= flags;
            (*ptmp).purpose = id;
            (*ptmp).trust = trust;
            (*ptmp).check_purpose = ck;
            (*ptmp).usr_data = arg;
        }

        if idx == -1 {
            let mut table = XPTABLE.load(Ordering::Acquire);
            if table.is_null() {
                // SAFETY: `xp_cmp` is the module's own comparator.
                table = OPENSSL_sk_new(Some(xp_cmp));
                if table.is_null() {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_PURP_241) };
                    result = 0;
                } else {
                    XPTABLE.store(table, Ordering::Release);
                }
            }
            // SAFETY: `table` is the module's own list and `ptmp` is a fresh dynamic row.
            if result == 1 && unsafe { OPENSSL_sk_push(table, ptmp.cast::<c_void>()) } == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PURP_245) };
                result = 0;
            }
        } else if id != old_id {
            // on changing existing entry id, make sure to reset 'sorted'
            let table = XPTABLE.load(Ordering::Acquire);
            // SAFETY: `table` is the module's own list (NULL matches the authority's direct pass)
            // and `idx` is the index the row was found at.
            unsafe { OPENSSL_sk_set(table, idx, ptmp.cast::<c_void>()) };
        }
    }

    if result == 0 {
        if idx == -1 {
            // SAFETY: `ptmp` is the fresh row this failure path owns.
            unsafe {
                CRYPTO_free(
                    (*ptmp).name.cast::<c_void>(),
                    FILE.as_ptr(),
                    LINE_ADD_ERR_NAME,
                );
                CRYPTO_free(
                    (*ptmp).sname.cast::<c_void>(),
                    FILE.as_ptr(),
                    LINE_ADD_ERR_SNAME,
                );
                CRYPTO_free(ptmp.cast::<c_void>(), FILE.as_ptr(), LINE_ADD_ERR_PTMP);
            }
        }
        return 0;
    }
    1
}

/// `void X509_PURPOSE_cleanup(void)` — `v3_purp.c:275-279`.
///
/// Drops the dynamic table, freeing each dynamic row.
///
/// # Safety
///
/// Must not race another `X509_PURPOSE_add`; the authority's table is unlocked, so this is the same
/// single-threaded contract the authority documents.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_cleanup() {
    let table = XPTABLE.swap(ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: `table` is NULL or the list this module built; `xptable_free_thunk` handles NULL.
    unsafe { OPENSSL_sk_pop_free(table, Some(xptable_free_thunk)) };
}

/// `int X509_PURPOSE_get_id(const X509_PURPOSE *xp)` — `v3_purp.c:281-284`.
///
/// # Safety
///
/// `xp` must be a live purpose row.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_id(xp: *const X509Purpose) -> c_int {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).purpose }
}

/// `char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp)` — `v3_purp.c:286-289`.
///
/// # Safety
///
/// `xp` must be a live purpose row; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0_name(xp: *const X509Purpose) -> *mut c_char {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).name }
}

/// `char *X509_PURPOSE_get0_sname(const X509_PURPOSE *xp)` — `v3_purp.c:291-294`.
///
/// # Safety
///
/// `xp` must be a live purpose row; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get0_sname(xp: *const X509Purpose) -> *mut c_char {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).sname }
}

/// `int X509_PURPOSE_get_trust(const X509_PURPOSE *xp)` — `v3_purp.c:296-299`.
///
/// # Safety
///
/// `xp` must be a live purpose row.
#[no_mangle]
pub unsafe extern "C" fn X509_PURPOSE_get_trust(xp: *const X509Purpose) -> c_int {
    // SAFETY: `xp` is live per the contract.
    unsafe { (*xp).trust }
}

// ---------------------------------------------------------------------------------------------
// The supported-extension search — `v3_purp.c:301-346`
// ---------------------------------------------------------------------------------------------

/// `static int nid_cmp(const int *a, const int *b)` — `v3_purp.c:301-304`.
///
/// # Safety
///
/// `a` and `b` must point at live `int`s.
unsafe fn nid_cmp(a: *const c_int, b: *const c_int) -> c_int {
    // SAFETY: both arguments are live `int`s per the contract.
    unsafe { *a - *b }
}

/// The adapter `IMPLEMENT_OBJ_BSEARCH_CMP_FN(int, int, nid)` emits around [`nid_cmp`]
/// (`objects.h:120-132`): a `const void *` comparator over `int` array slots.
///
/// # Safety
///
/// `a_` and `b_` must each point at a live `int`.
unsafe extern "C" fn nid_cmp_bsearch(a_: *const c_void, b_: *const c_void) -> c_int {
    // SAFETY: both arguments point at `int` slots per the contract.
    unsafe { nid_cmp(a_.cast::<c_int>(), b_.cast::<c_int>()) }
}

/// The `OBJ_bsearch_nid` the authority generates (`objects.h:127-131`) over the same comparator.
///
/// # Safety
///
/// `key` must point at a live `int`; `base` must point at `num` live `int`s in ascending order.
unsafe fn obj_bsearch_nid(key: *const c_int, base: *const c_int, num: c_int) -> *const c_int {
    // SAFETY: the table and comparator match per the contract.
    unsafe {
        OBJ_bsearch_(
            key.cast::<c_void>(),
            base.cast::<c_void>(),
            num,
            size_of::<c_int>() as c_int,
            Some(nid_cmp_bsearch),
        )
    }
    .cast::<c_int>()
}

/// `int X509_supported_extension(X509_EXTENSION *ex)` — `v3_purp.c:309-346`.
///
/// Answers 1 when the extension's NID is one the verify process understands, else 0. The table
/// (`v3_purp.c:318-336`) is ascending, so a binary search decides it.
///
/// # Safety
///
/// `ex` must be a live `X509_EXTENSION`.
#[no_mangle]
pub unsafe extern "C" fn X509_supported_extension(ex: *mut X509Extension) -> c_int {
    // The authority's `supported_nids[]` (`v3_purp.c:318-336`), ascending.
    const SUPPORTED_NIDS: [c_int; 15] = [
        NID_netscape_cert_type,      // 71
        NID_key_usage,               // 83
        NID_subject_alt_name,        // 85
        NID_basic_constraints,       // 87
        NID_certificate_policies,    // 89
        NID_crl_distribution_points, // 103
        NID_ext_key_usage,           // 126
        NID_sbgp_ipAddrBlock,        // 290
        NID_sbgp_autonomousSysNum,   // 291
        NID_id_pkix_OCSP_noCheck,    // 369
        NID_policy_constraints,      // 401
        NID_proxyCertInfo,           // 663
        NID_name_constraints,        // 666
        NID_policy_mappings,         // 747
        NID_inhibit_any_policy,      // 748
    ];

    // SAFETY: `ex` is live per the contract.
    let ex_nid = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(ex)) };
    if ex_nid == NID_undef {
        return 0;
    }
    // SAFETY: `ex_nid` and the static table are live `int`s.
    if !unsafe { obj_bsearch_nid(&raw const ex_nid, SUPPORTED_NIDS.as_ptr(), 15) }.is_null() {
        return 1;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Building the extension cache — `v3_purp.c:349-679`
// ---------------------------------------------------------------------------------------------

/// `static int setup_dp(const X509 *x, DIST_POINT *dp)` — `v3_purp.c:349-388`.
///
/// Validates one distribution point, unpacks its reason flags and, for a `relativename`, resolves
/// the name fragment against the CRL issuer. Answers 1 on success, 0 for an invalid point and -1
/// for an internal error.
///
/// # Safety
///
/// `x` must be a live `X509`; `dp` must be a live `DIST_POINT` whose `distpoint`, `reasons` and
/// `CRLissuer` members are its own.
unsafe fn setup_dp(x: *const X509, dp: *mut DistPoint) -> c_int {
    // SAFETY: `dp` is live per the contract.
    if unsafe { (*dp).distpoint.is_null() && OPENSSL_sk_num((*dp).CRLissuer) <= 0 } {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PURP_355) };
        return 0;
    }
    // SAFETY: `dp` is live; its reason bit string is NULL or live.
    if !unsafe { (*dp).reasons.is_null() } {
        // SAFETY: `reasons` is non-NULL and live.
        let reasons = unsafe { (*dp).reasons };
        // SAFETY: `reasons` is a live ASN1_BIT_STRING.
        let length = unsafe { (*reasons).length };
        if length > 0 {
            // SAFETY: the bit string has at least one octet.
            unsafe { (*dp).dp_reasons = *(*reasons).data as c_int };
        }
        if length > 1 {
            // SAFETY: the bit string has at least two octets.
            unsafe { (*dp).dp_reasons |= (*(*reasons).data.add(1) as c_int) << 8 };
        }
        // SAFETY: `dp` is live and writable.
        unsafe { (*dp).dp_reasons &= CRLDP_ALL_REASONS };
    } else {
        // SAFETY: `dp` is live and writable.
        unsafe { (*dp).dp_reasons = CRLDP_ALL_REASONS };
    }
    // SAFETY: `dp` is live.
    if unsafe { (*dp).distpoint.is_null() || (*(*dp).distpoint).type_ != 1 } {
        return 1;
    }

    let mut iname: *const X509Name = ptr::null();
    // SAFETY: `dp` is live; `CRLissuer` is a live stack.
    let n = unsafe { OPENSSL_sk_num((*dp).CRLissuer) };
    for i in 0..n {
        // SAFETY: `i` is a valid index and `CRLissuer` is the live stack.
        let gen = unsafe { OPENSSL_sk_value((*dp).CRLissuer, i) }.cast::<GeneralName>();
        // SAFETY: `gen` is a live general name.
        if unsafe { (*gen).type_ } == GEN_DIRNAME {
            // SAFETY: a `GEN_DIRNAME` name carries its directory name in the union.
            iname = unsafe { (*gen).d.directoryName };
            break;
        }
    }
    if iname.is_null() {
        // SAFETY: `x` is live per the contract.
        iname = unsafe { X509_get_issuer_name(x) };
    }
    // SAFETY: `dp->distpoint` is a live `relativename` and `iname` is a live name.
    if unsafe { DIST_POINT_set_dpname((*dp).distpoint, iname) } != 0 {
        1
    } else {
        -1
    }
}

/// `static int setup_crldp(X509 *x)` — `v3_purp.c:391-406`.
///
/// Decodes and validates the certificate's CRL distribution points, caching the stack in
/// `x->crldp`. Answers 1 on success, 0 for an invalid extension and -1 for an internal error.
///
/// # Safety
///
/// `x` must be a live `X509`.
unsafe fn setup_crldp(x: *mut X509) -> c_int {
    let mut i: c_int = 0;
    // SAFETY: `x` is live; `crldp` is its own cache slot and `&i` is a writable crit out-param.
    unsafe {
        (*x).crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).crldp.is_null() } && i != -1 {
        return 0;
    }
    // SAFETY: `x` is live; `crldp` is a live stack of distribution points.
    let crldp = unsafe { (*x).crldp }.cast::<OpenSslStack>();
    // SAFETY: `crldp` is a live stack.
    let n = unsafe { OPENSSL_sk_num(crldp) };
    for i in 0..n {
        // SAFETY: `i` is a valid index and `crldp` is the live stack.
        let dp = unsafe { OPENSSL_sk_value(crldp, i) }.cast::<DistPoint>();
        // SAFETY: `x` is live and `dp` is a live distribution point.
        let res = unsafe { setup_dp(x, dp) };
        if res < 1 {
            return res;
        }
    }
    1
}

/// `static int check_sig_alg_match(const EVP_PKEY *issuer_key, const X509 *subject)` —
/// `v3_purp.c:409-423`.
///
/// Matches the subject's signature algorithm against the issuer's public-key algorithm, answering
/// the `X509_V_*` reason for a mismatch.
///
/// # Safety
///
/// `issuer_key` must be NULL or a live `EVP_PKEY`; `subject` must be a live `X509`.
unsafe fn check_sig_alg_match(issuer_key: *const EvpPkey, subject: *const X509) -> c_int {
    if issuer_key.is_null() {
        return X509_V_ERR_NO_ISSUER_PUBLIC_KEY;
    }
    // SAFETY: `subject` is live per the contract.
    let signid = unsafe { OBJ_obj2nid((*subject).cert_info.signature.algorithm) };
    let mut subj_sig_nid: c_int = 0;
    // SAFETY: `&subj_sig_nid` is writable; the pkey out-param is unused.
    if unsafe { OBJ_find_sigid_algs(signid, ptr::null_mut(), &raw mut subj_sig_nid) } == 0 {
        return X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM;
    }
    // SAFETY: `issuer_key` is non-NULL and live; the short name is a static string.
    if unsafe { EVP_PKEY_is_a(issuer_key, OBJ_nid2sn(subj_sig_nid)) } != 0 {
        return X509_V_OK;
    }
    // SAFETY: as above; the `RSA` spelling is a static string.
    if unsafe { EVP_PKEY_is_a(issuer_key, c"RSA".as_ptr()) } != 0 && subj_sig_nid == NID_rsassaPss {
        return X509_V_OK;
    }
    X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH
}

/// `int ossl_x509v3_cache_extensions(X509 *x)` — `v3_purp.c:440-679`.
///
/// Caches the certificate's SHA-1 fingerprint, extension flags, key-usage words, key identifiers,
/// alternative names, name constraints, CRL distribution points and RFC 3779 blocks, and derives
/// the self-issued/self-signed flags. Answers 1 on success and 0 when the certificate is invalid.
///
/// # Safety
///
/// `x` must be a live, unlocked `X509` with a live `lock` (or a NULL lock, which the authority's
/// `CRYPTO_THREAD_write_lock` refuses by answering 0).
#[no_mangle]
pub unsafe extern "C" fn ossl_x509v3_cache_extensions(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract; its lock field is NULL or live.
    if unsafe { CRYPTO_THREAD_write_lock((*x).lock) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live and now write-locked.
    if (unsafe { (*x).ex_flags } & EXFLAG_SET) != 0 {
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock((*x).lock) };
        // SAFETY: `x` is live.
        return c_int::from(unsafe { ((*x).ex_flags & EXFLAG_INVALID) == 0 });
    }

    // ERR_set_mark is a safe entry point with no pointer arguments.
    ERR_set_mark();

    // Cache the SHA1 digest of the cert
    // SAFETY: `x` is live; `sha1_hash` is its own twenty-byte buffer.
    if unsafe { X509_digest(x, EVP_sha1(), (*x).sha1_hash.as_mut_ptr(), ptr::null_mut()) } == 0 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_NO_FINGERPRINT };
    }

    // V1 should mean no extensions ...
    // SAFETY: `x` is live.
    if unsafe { X509_get_version(x) } == X509_VERSION_1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_V1 };
    }

    // Handle basic constraints
    // SAFETY: `x` is live.
    unsafe { (*x).ex_pathlen = -1 };
    let mut i: c_int = 0;
    // SAFETY: `x` is live; `bs` is the decoded extension or NULL and `&i` is writable.
    let bs = unsafe { X509_get_ext_d2i(x, NID_basic_constraints, &raw mut i, ptr::null_mut()) }
        .cast::<BasicConstraints>();
    if !bs.is_null() {
        // SAFETY: `bs` is a live BASIC_CONSTRAINTS.
        if unsafe { (*bs).ca } != 0 {
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_CA };
        }
        // SAFETY: `bs` is live.
        if !unsafe { (*bs).pathlen.is_null() } {
            // SAFETY: `pathlen` is a live ASN1_INTEGER.
            if unsafe { (*(*bs).pathlen).type_ } == V_ASN1_NEG_INTEGER {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_PURP_484) };
                // SAFETY: `x` is live and write-locked.
                unsafe { (*x).ex_flags |= EXFLAG_INVALID };
            } else {
                // SAFETY: `pathlen` is a live integer and `x` is writable.
                unsafe { (*x).ex_pathlen = ASN1_INTEGER_get((*bs).pathlen) };
            }
        }
        // SAFETY: `bs` is the value decoded above.
        unsafe { BASIC_CONSTRAINTS_free(bs) };
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_BCONS };
    } else if i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle proxy certificates
    // SAFETY: `x` is live; the decoded value is NULL or a live proxy extension and `&i` is writable.
    let pci = unsafe { X509_get_ext_d2i(x, NID_proxyCertInfo, &raw mut i, ptr::null_mut()) }
        .cast::<ProxyCertInfoExtension>();
    if !pci.is_null() {
        // SAFETY: `x` is live.
        let has_ca_flag = (unsafe { (*x).ex_flags } & EXFLAG_CA) != 0;
        // SAFETY: `x` is live.
        let has_san = unsafe { X509_get_ext_by_NID(x, NID_subject_alt_name, -1) } >= 0;
        // SAFETY: `x` is live.
        let has_ian = unsafe { X509_get_ext_by_NID(x, NID_issuer_alt_name, -1) } >= 0;
        if has_ca_flag || has_san || has_ian {
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_INVALID };
        }
        // SAFETY: `pci` is live.
        if !unsafe { (*pci).pcPathLengthConstraint.is_null() } {
            // SAFETY: the constraint is a live integer and `x` is writable.
            unsafe {
                (*x).ex_pcpathlen = ASN1_INTEGER_get((*pci).pcPathLengthConstraint);
            }
        } else {
            // SAFETY: `x` is live and writable.
            unsafe { (*x).ex_pcpathlen = -1 };
        }
        // SAFETY: `pci` is the value decoded above.
        unsafe { PROXY_CERT_INFO_EXTENSION_free(pci) };
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_PROXY };
    } else if i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle (basic) key usage
    // SAFETY: `x` is live; the decoded value is NULL or a live bit string and `&i` is writable.
    let usage = unsafe { X509_get_ext_d2i(x, NID_key_usage, &raw mut i, ptr::null_mut()) }
        .cast::<crate::asn1::layout::Asn1String>();
    if !usage.is_null() {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_kusage = 0 };
        // SAFETY: `usage` is a live ASN1_BIT_STRING.
        let length = unsafe { (*usage).length };
        if length > 0 {
            // SAFETY: the bit string has at least one octet.
            unsafe { (*x).ex_kusage = *(*usage).data as c_uint };
            if length > 1 {
                // SAFETY: the bit string has at least two octets.
                unsafe { (*x).ex_kusage |= (*(*usage).data.add(1) as c_uint) << 8 };
            }
        }
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_KUSAGE };
        // SAFETY: `usage` is the value decoded above.
        unsafe { ASN1_BIT_STRING_free(usage) };
        // Check for empty key usage according to RFC 5280 section 4.2.1.3
        // SAFETY: `x` is live.
        if unsafe { (*x).ex_kusage } == 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PURP_525) };
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_INVALID };
        }
    } else if i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle extended key usage
    // SAFETY: `x` is live and write-locked.
    unsafe { (*x).ex_xkusage = 0 };
    // SAFETY: `x` is live; the decoded value is NULL or a live stack and `&i` is writable.
    let extusage = unsafe { X509_get_ext_d2i(x, NID_ext_key_usage, &raw mut i, ptr::null_mut()) }
        .cast::<OpenSslStack>();
    if !extusage.is_null() {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_XKUSAGE };
        // SAFETY: `extusage` is a live stack.
        let n = unsafe { OPENSSL_sk_num(extusage) };
        for j in 0..n {
            // SAFETY: `j` is a valid index and `extusage` is the live stack.
            let nid = unsafe { OBJ_obj2nid(OPENSSL_sk_value(extusage, j).cast::<Asn1Object>()) };
            // SAFETY: `x` is live and write-locked.
            unsafe {
                match nid {
                    NID_server_auth => (*x).ex_xkusage |= XKU_SSL_SERVER,
                    NID_client_auth => (*x).ex_xkusage |= XKU_SSL_CLIENT,
                    NID_email_protect => (*x).ex_xkusage |= XKU_SMIME,
                    NID_code_sign => (*x).ex_xkusage |= XKU_CODE_SIGN,
                    NID_ms_sgc | NID_ns_sgc => (*x).ex_xkusage |= XKU_SGC,
                    NID_OCSP_sign => (*x).ex_xkusage |= XKU_OCSP_SIGN,
                    NID_time_stamp => (*x).ex_xkusage |= XKU_TIMESTAMP,
                    NID_dvcs => (*x).ex_xkusage |= XKU_DVCS,
                    NID_anyExtendedKeyUsage => (*x).ex_xkusage |= XKU_ANYEKU,
                    // Ignore unknown extended key usage.
                    _ => {}
                }
            }
        }
        // SAFETY: `extusage` is the value decoded above; the thunk frees its objects.
        unsafe { OPENSSL_sk_pop_free(extusage, Some(asn1_object_free_thunk)) };
    } else if i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle legacy Netscape extension
    // SAFETY: `x` is live; the decoded value is NULL or a live bit string and `&i` is writable.
    let ns = unsafe { X509_get_ext_d2i(x, NID_netscape_cert_type, &raw mut i, ptr::null_mut()) }
        .cast::<crate::asn1::layout::Asn1String>();
    if !ns.is_null() {
        // SAFETY: `ns` is a live ASN1_BIT_STRING.
        if unsafe { (*ns).length } > 0 {
            // SAFETY: the bit string has at least one octet and `x` is writable.
            unsafe { (*x).ex_nscert = *(*ns).data as c_uint };
        } else {
            // SAFETY: `x` is live and writable.
            unsafe { (*x).ex_nscert = 0 };
        }
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_NSCERT };
        // SAFETY: `ns` is the value decoded above.
        unsafe { ASN1_BIT_STRING_free(ns) };
    } else if i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle subject key identifier and issuer/authority key identifier
    // SAFETY: `x` is live; `skid` is its own cache slot and `&i` is writable.
    unsafe {
        (*x).skid = X509_get_ext_d2i(x, NID_subject_key_identifier, &raw mut i, ptr::null_mut())
            .cast::<crate::asn1::layout::Asn1String>();
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).skid.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // SAFETY: `x` is live; `akid` is its own cache slot and `&i` is writable.
    unsafe {
        (*x).akid = X509_get_ext_d2i(x, NID_authority_key_identifier, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).akid.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Check if subject name matches issuer
    // SAFETY: `x` is live.
    if unsafe { X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) } == 0 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_SI }; // Cert is self-issued
                                               // SAFETY: `x` is live; its akid cache slot holds the decoded value or NULL.
        let akid_ok =
            unsafe { X509_check_akid(x, (*x).akid.cast::<AuthorityKeyid>()) } == X509_V_OK;
        // SAFETY: `x` is live and its public key is its own.
        let sig_ok = unsafe { check_sig_alg_match(X509_get0_pubkey(x), x) } == X509_V_OK;
        // .. and the signature alg matches the PUBKEY alg.
        if akid_ok && sig_ok {
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_SS }; // indicate self-signed
        }
    }

    // Handle subject alternative names and various other extensions
    // SAFETY: `x` is live; `altname` is its own cache slot and `&i` is writable.
    unsafe {
        (*x).altname = X509_get_ext_d2i(x, NID_subject_alt_name, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).altname.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }
    // SAFETY: `x` is live; `nc` is its own cache slot and `&i` is writable.
    unsafe {
        (*x).nc = X509_get_ext_d2i(x, NID_name_constraints, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).nc.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // Handle CRL distribution point entries
    // SAFETY: `x` is live.
    let res = unsafe { setup_crldp(x) };
    if res == 0 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // SAFETY: `x` is live; each RFC 3779 cache slot is its own and `&i` is writable.
    unsafe {
        (*x).rfc3779_addr = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).rfc3779_addr.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }
    // SAFETY: `x` is live; the RFC 3779 AS cache slot is its own and `&i` is writable.
    unsafe {
        (*x).rfc3779_asid =
            X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, &raw mut i, ptr::null_mut());
    }
    // SAFETY: `x` is live.
    if unsafe { (*x).rfc3779_asid.is_null() } && i != -1 {
        // SAFETY: `x` is live and write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_INVALID };
    }

    // SAFETY: `x` is live.
    let ext_count = unsafe { X509_get_ext_count(x) };
    for i in 0..ext_count {
        // SAFETY: `i` is a valid index.
        let ex = unsafe { X509_get_ext(x, i) };
        // SAFETY: `ex` is a live extension.
        let nid = unsafe { OBJ_obj2nid(X509_EXTENSION_get_object(ex)) };

        if nid == NID_freshest_crl {
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_FRESHEST };
        }
        // SAFETY: `ex` is live.
        if unsafe { X509_EXTENSION_get_critical(ex) } == 0 {
            continue;
        }
        // SAFETY: `ex` is live.
        if unsafe { X509_supported_extension(ex) } == 0 {
            // SAFETY: `x` is live and write-locked.
            unsafe { (*x).ex_flags |= EXFLAG_CRITICAL };
            break;
        }
        // SAFETY: `x` is live and write-locked.
        unsafe {
            match nid {
                NID_basic_constraints => (*x).ex_flags |= EXFLAG_BCONS_CRITICAL,
                NID_authority_key_identifier => (*x).ex_flags |= EXFLAG_AKID_CRITICAL,
                NID_subject_key_identifier => (*x).ex_flags |= EXFLAG_SKID_CRITICAL,
                NID_subject_alt_name => (*x).ex_flags |= EXFLAG_SAN_CRITICAL,
                _ => {}
            }
        }
    }

    // Set x->siginf, ignoring errors due to unsupported algos
    // SAFETY: `x` is live.
    let _ = unsafe { ossl_x509_init_sig_info(x) };

    // SAFETY: `x` is live and write-locked.
    unsafe { (*x).ex_flags |= EXFLAG_SET }; // Indicate that cert has been processed
                                            // ERR_pop_to_mark is a safe entry point with no pointer arguments.
    ERR_pop_to_mark();

    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_INVALID) == 0 {
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock((*x).lock) };
        return 1;
    }
    // SAFETY: the lock is held.
    unsafe { CRYPTO_THREAD_unlock((*x).lock) };
    // SAFETY: the site is a compiled-in constant.
    unsafe { raise_site(&V3_PURP_677) };
    0
}

// ---------------------------------------------------------------------------------------------
// CA and purpose checks — `v3_purp.c:693-975`
// ---------------------------------------------------------------------------------------------

/// The `ku_reject` macro (`v3_purp.c:426-427`): true when a key-usage extension is present and the
/// requested bits are absent.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn ku_reject(x: *const X509, usage: c_uint) -> bool {
    // SAFETY: `x` is live per the contract.
    unsafe { ((*x).ex_flags & EXFLAG_KUSAGE) != 0 && ((*x).ex_kusage & usage) == 0 }
}

/// The `xku_reject` macro (`v3_purp.c:428-429`).
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn xku_reject(x: *const X509, usage: c_uint) -> bool {
    // SAFETY: `x` is live per the contract.
    unsafe { ((*x).ex_flags & EXFLAG_XKUSAGE) != 0 && ((*x).ex_xkusage & usage) == 0 }
}

/// The `ns_reject` macro (`v3_purp.c:430-431`).
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn ns_reject(x: *const X509, usage: c_uint) -> bool {
    // SAFETY: `x` is live per the contract.
    unsafe { ((*x).ex_flags & EXFLAG_NSCERT) != 0 && ((*x).ex_nscert & usage) == 0 }
}

/// `static int check_ca(const X509 *x)` — `v3_purp.c:693-717`.
///
/// The CA check common to every purpose: 0 for not-a-CA, 1 for a CA, 3 for an absent
/// `basicConstraints` on a self-signed V1, 4 when key usage carries `keyCertSign`, and 5 for the
/// Netscape CA type.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn check_ca(x: *const X509) -> c_int {
    // keyUsage if present should allow cert signing
    // SAFETY: `x` is live per the contract.
    if unsafe { ku_reject(x, KU_KEY_CERT_SIGN) } {
        return 0;
    }
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_BCONS) != 0 {
        // If basicConstraints says not a CA then say so
        // SAFETY: `x` is live.
        return c_int::from(unsafe { ((*x).ex_flags & EXFLAG_CA) != 0 });
    }
    // We support V1 roots for...  uh, I don't really know why.
    /// `V1_ROOT` — `EXFLAG_V1 | EXFLAG_SS` (`v3_purp.c:425`).
    const V1_ROOT: c_uint = EXFLAG_V1 | EXFLAG_SS;
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & V1_ROOT) == V1_ROOT {
        return 3;
    }
    // If key usage present it must have certSign so tolerate it
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_KUSAGE) != 0 {
        return 4;
    }
    // Older certificates could have Netscape-specific CA types
    // SAFETY: `x` is live.
    let is_nscert = (unsafe { (*x).ex_flags } & EXFLAG_NSCERT) != 0;
    // SAFETY: `x` is live.
    let is_ns_ca = (unsafe { (*x).ex_nscert } & NS_ANY_CA) != 0;
    if is_nscert && is_ns_ca {
        return 5;
    }
    // Can this still be regarded a CA certificate?  I doubt it.
    0
}

/// `void X509_set_proxy_flag(X509 *x)` — `v3_purp.c:719-725`.
///
/// # Safety
///
/// `x` must be a live `X509` with a live `lock`.
#[no_mangle]
pub unsafe extern "C" fn X509_set_proxy_flag(x: *mut X509) {
    // SAFETY: `x` is live; its lock is live per the contract.
    if unsafe { CRYPTO_THREAD_write_lock((*x).lock) } != 0 {
        // SAFETY: `x` is live and now write-locked.
        unsafe { (*x).ex_flags |= EXFLAG_PROXY };
        // SAFETY: the lock is held.
        unsafe { CRYPTO_THREAD_unlock((*x).lock) };
    }
}

/// `void X509_set_proxy_pathlen(X509 *x, long l)` — `v3_purp.c:727-730`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_set_proxy_pathlen(x: *mut X509, l: c_long) {
    // SAFETY: `x` is live and its field is writable.
    unsafe { (*x).ex_pcpathlen = l };
}

/// `int X509_check_ca(X509 *x)` — `v3_purp.c:732-739`.
///
/// Builds the cache and runs [`check_ca`]; 0 means either "not a CA" or an internal error, as the
/// authority documents.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_ca(x: *mut X509) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { ossl_x509v3_cache_extensions(x) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live and cached.
    unsafe { check_ca(x) }
}

/// `static int check_ssl_ca(const X509 *x)` — `v3_purp.c:742-750`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn check_ssl_ca(x: *const X509) -> c_int {
    // SAFETY: `x` is live per the contract.
    let ca_ret = unsafe { check_ca(x) };
    if ca_ret == 0 {
        return 0;
    }
    // Check nsCertType if present
    // SAFETY: `x` is live.
    c_int::from(ca_ret != 5 || (unsafe { (*x).ex_nscert } & NS_SSL_CA) != 0)
}

/// `static int check_purpose_ssl_client(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:752-766`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_ssl_client(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { xku_reject(x, XKU_SSL_CLIENT) } {
        return 0;
    }
    if non_leaf != 0 {
        // SAFETY: `x` is live.
        return unsafe { check_ssl_ca(x) };
    }
    // We need to do digital signatures or key agreement
    // SAFETY: `x` is live.
    if unsafe { ku_reject(x, KU_DIGITAL_SIGNATURE | KU_KEY_AGREEMENT) } {
        return 0;
    }
    // nsCertType if present should allow SSL client use
    // SAFETY: `x` is live.
    if unsafe { ns_reject(x, NS_SSL_CLIENT) } {
        return 0;
    }
    1
}

/// `KU_TLS` — `KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT` (`v3_purp.c:773-774`).
const KU_TLS: c_uint = KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT;

/// `static int check_purpose_ssl_server(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:776-790`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_ssl_server(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { xku_reject(x, XKU_SSL_SERVER | XKU_SGC) } {
        return 0;
    }
    if non_leaf != 0 {
        // SAFETY: `x` is live.
        return unsafe { check_ssl_ca(x) };
    }
    // SAFETY: `x` is live.
    if unsafe { ns_reject(x, NS_SSL_SERVER) } {
        return 0;
    }
    // SAFETY: `x` is live.
    if unsafe { ku_reject(x, KU_TLS) } {
        return 0;
    }
    1
}

/// `static int check_purpose_ns_ssl_server(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:792-801`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_ns_ssl_server(
    xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    let ret = unsafe { check_purpose_ssl_server(xp, x, non_leaf) };
    if ret == 0 || non_leaf != 0 {
        return ret;
    }
    // We need to encipher or Netscape complains
    // SAFETY: `x` is live.
    if unsafe { ku_reject(x, KU_KEY_ENCIPHERMENT) } {
        0
    } else {
        ret
    }
}

/// `static int purpose_smime(const X509 *x, int non_leaf)` — `v3_purp.c:804-826`.
///
/// The common S/MIME check: an extended key usage must allow S/MIME, and a leaf may also derive 2
/// from the Netscape SSL-client workaround.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe fn purpose_smime(x: *const X509, non_leaf: c_int) -> c_int {
    // SAFETY: `x` is live per the contract.
    if unsafe { xku_reject(x, XKU_SMIME) } {
        return 0;
    }
    if non_leaf != 0 {
        // SAFETY: `x` is live.
        let ca_ret = unsafe { check_ca(x) };
        if ca_ret == 0 {
            return 0;
        }
        // Check nsCertType if present
        // SAFETY: `x` is live.
        if ca_ret != 5 || (unsafe { (*x).ex_nscert } & NS_SMIME_CA) != 0 {
            return ca_ret;
        }
        return 0;
    }
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_NSCERT) != 0 {
        // SAFETY: `x` is live.
        if (unsafe { (*x).ex_nscert } & NS_SMIME) != 0 {
            return 1;
        }
        // Workaround for some buggy certificates
        // SAFETY: `x` is live.
        return if (unsafe { (*x).ex_nscert } & NS_SSL_CLIENT) != 0 {
            2
        } else {
            0
        };
    }
    1
}

/// `static int check_purpose_smime_sign(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:828-836`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_smime_sign(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    let ret = unsafe { purpose_smime(x, non_leaf) };
    if ret == 0 || non_leaf != 0 {
        return ret;
    }
    // SAFETY: `x` is live.
    if unsafe { ku_reject(x, KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION) } {
        0
    } else {
        ret
    }
}

/// `static int check_purpose_smime_encrypt(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:838-846`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_smime_encrypt(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    let ret = unsafe { purpose_smime(x, non_leaf) };
    if ret == 0 || non_leaf != 0 {
        return ret;
    }
    // SAFETY: `x` is live.
    if unsafe { ku_reject(x, KU_KEY_ENCIPHERMENT) } {
        0
    } else {
        ret
    }
}

/// `static int check_purpose_crl_sign(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:848-857`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_crl_sign(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    if non_leaf != 0 {
        // SAFETY: `x` is live per the contract.
        let ca_ret = unsafe { check_ca(x) };
        return if ca_ret == 2 { 0 } else { ca_ret };
    }
    // SAFETY: `x` is live.
    c_int::from(!unsafe { ku_reject(x, KU_CRL_SIGN) })
}

/// `static int check_purpose_ocsp_helper(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:863-874`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_ocsp_helper(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    if non_leaf != 0 {
        // SAFETY: `x` is live per the contract.
        return unsafe { check_ca(x) };
    }
    // Leaf certificate is checked in OCSP_verify()
    1
}

/// `static int check_purpose_timestamp_sign(const X509_PURPOSE *xp, const X509 *x, int non_leaf)`
/// — `v3_purp.c:876-916`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_timestamp_sign(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    if non_leaf != 0 {
        // SAFETY: `x` is live per the contract.
        return unsafe { check_ca(x) };
    }
    // SAFETY: `x` is live per the contract.
    let (flags, kusage, xkusage) = unsafe { ((*x).ex_flags, (*x).ex_kusage, (*x).ex_xkusage) };
    let sig_bits = KU_NON_REPUDIATION | KU_DIGITAL_SIGNATURE;
    if (flags & EXFLAG_KUSAGE) != 0 && ((kusage & !sig_bits) != 0 || (kusage & sig_bits) == 0) {
        return 0;
    }
    // Only timestamp key usage is permitted and it's required.
    if (flags & EXFLAG_XKUSAGE) == 0 || xkusage != XKU_TIMESTAMP {
        return 0;
    }
    // Extended Key Usage MUST be critical
    // SAFETY: `x` is live.
    let i_ext = unsafe { X509_get_ext_by_NID(x, NID_ext_key_usage, -1) };
    if i_ext >= 0
        // SAFETY: `i_ext` is a valid index and `x` is live.
        && unsafe { X509_EXTENSION_get_critical(X509_get_ext(x, i_ext)) } == 0
    {
        return 0;
    }
    1
}

/// `static int check_purpose_code_sign(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:918-969`.
///
/// # Safety
///
/// `x` must be a live `X509` whose cache has been built.
unsafe extern "C" fn check_purpose_code_sign(
    _xp: *const X509Purpose,
    x: *const X509,
    non_leaf: c_int,
) -> c_int {
    if non_leaf != 0 {
        // SAFETY: `x` is live per the contract.
        return unsafe { check_ca(x) };
    }
    // SAFETY: `x` is live per the contract.
    let (flags, kusage, xkusage) = unsafe { ((*x).ex_flags, (*x).ex_kusage, (*x).ex_xkusage) };
    // Key Usage
    if (flags & EXFLAG_KUSAGE) == 0 {
        return 0;
    }
    if (kusage & KU_DIGITAL_SIGNATURE) == 0 {
        return 0;
    }
    if (kusage & (KU_KEY_CERT_SIGN | KU_CRL_SIGN)) != 0 {
        return 0;
    }
    // Key Usage MUST be critical
    // SAFETY: `x` is live.
    let i_ext = unsafe { X509_get_ext_by_NID(x, NID_key_usage, -1) };
    if i_ext < 0 {
        return 0;
    }
    if i_ext >= 0 {
        // SAFETY: `i_ext` is a valid index and `x` is live.
        let ext = unsafe { X509_get_ext(x, i_ext) };
        // SAFETY: `ext` is a live extension.
        if unsafe { X509_EXTENSION_get_critical(ext) } == 0 {
            return 0;
        }
    }
    // Extended Key Usage
    if (flags & EXFLAG_XKUSAGE) == 0 {
        return 0;
    }
    if (xkusage & XKU_CODE_SIGN) == 0 {
        return 0;
    }
    if (xkusage & (XKU_ANYEKU | XKU_SSL_SERVER)) != 0 {
        return 0;
    }
    1
}

/// `static int no_check_purpose(const X509_PURPOSE *xp, const X509 *x, int non_leaf)` —
/// `v3_purp.c:971-975`.
///
/// # Safety
///
/// The arguments are ignored; no contract is required.
unsafe extern "C" fn no_check_purpose(
    _xp: *const X509Purpose,
    _x: *const X509,
    _non_leaf: c_int,
) -> c_int {
    1
}

// ---------------------------------------------------------------------------------------------
// The issuer checks — `v3_purp.c:990-1074`
// ---------------------------------------------------------------------------------------------

/// `int X509_check_issued(X509 *issuer, X509 *subject)` — `v3_purp.c:990-997`.
///
/// The name/AKID/signature-algorithm match followed by the issuer's key-usage signing allowance.
/// Answers 0 when `issuer` may have issued `subject`, else an `X509_V_*` reason.
///
/// # Safety
///
/// `issuer` and `subject` must each be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> c_int {
    // SAFETY: both are live per the contract.
    let ret = unsafe { ossl_x509_likely_issued(issuer, subject) };
    if ret != X509_V_OK {
        return ret;
    }
    // SAFETY: both are live per the contract.
    unsafe { ossl_x509_signing_allowed(issuer, subject) }
}

/// `int ossl_x509_likely_issued(X509 *issuer, X509 *subject)` — `v3_purp.c:1000-1020`.
///
/// Checks 1. (issuer name matches subject's issuer name), 2. (AKID matches) and 3. (signature
/// algorithm matches the issuer's public key), building both caches first.
///
/// # Safety
///
/// `issuer` and `subject` must each be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_likely_issued(issuer: *mut X509, subject: *mut X509) -> c_int {
    // SAFETY: both are live per the contract.
    if unsafe { X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(subject)) } != 0 {
        return X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
    }
    // set issuer->skid and subject->akid
    // SAFETY: `issuer` is live per the contract.
    if unsafe { ossl_x509v3_cache_extensions(issuer) } == 0 {
        return X509_V_ERR_UNSPECIFIED;
    }
    // SAFETY: `subject` is live per the contract.
    if unsafe { ossl_x509v3_cache_extensions(subject) } == 0 {
        return X509_V_ERR_UNSPECIFIED;
    }
    // SAFETY: both are live and now cached.
    let ret = unsafe { X509_check_akid(issuer, (*subject).akid.cast::<AuthorityKeyid>()) };
    if ret != X509_V_OK {
        return ret;
    }
    // Check if the subject signature alg matches the issuer's PUBKEY alg
    // SAFETY: both are live and cached.
    unsafe { check_sig_alg_match(X509_get0_pubkey(issuer), subject) }
}

/// `int ossl_x509_signing_allowed(const X509 *issuer, const X509 *subject)` — `v3_purp.c:1029-1038`.
///
/// Applies the issuer's key usage to the subject kind: a proxy subject needs `digitalSignature`,
/// anything else needs `keyCertSign`.
///
/// # Safety
///
/// `issuer` and `subject` must each be a live `X509` whose caches have been built.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_signing_allowed(
    issuer: *const X509,
    subject: *const X509,
) -> c_int {
    // SAFETY: both are live per the contract.
    if (unsafe { (*subject).ex_flags } & EXFLAG_PROXY) != 0 {
        // SAFETY: `issuer` is live.
        if unsafe { ku_reject(issuer, KU_DIGITAL_SIGNATURE) } {
            return X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
        }
    } else {
        // SAFETY: `issuer` is live.
        if unsafe { ku_reject(issuer, KU_KEY_CERT_SIGN) } {
            return X509_V_ERR_KEYUSAGE_NO_CERTSIGN;
        }
    }
    X509_V_OK
}

/// `int X509_check_akid(const X509 *issuer, const AUTHORITY_KEYID *akid)` — `v3_purp.c:1040-1074`.
///
/// Matches an authority key identifier against the issuer: the key ids, then the serial, then the
/// first directory name in the issuer sequence. A NULL `akid` is an unconditional OK.
///
/// # Safety
///
/// `issuer` must be a live `X509`; `akid` must be NULL or a live `AUTHORITY_KEYID`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_akid(
    issuer: *const X509,
    akid: *const AuthorityKeyid,
) -> c_int {
    if akid.is_null() {
        return X509_V_OK;
    }

    // Check key ids (if present)
    // SAFETY: `akid` is live and `issuer` is live.
    if !unsafe { (*akid).keyid.is_null() } && !unsafe { (*issuer).skid.is_null() } {
        // SAFETY: both key ids are live octet strings.
        if unsafe { ASN1_OCTET_STRING_cmp((*akid).keyid, (*issuer).skid) } != 0 {
            return X509_V_ERR_AKID_SKID_MISMATCH;
        }
    }
    // Check serial number
    // SAFETY: `akid` is live.
    if !unsafe { (*akid).serial.is_null() } {
        // SAFETY: `issuer` and `akid->serial` are live integers.
        if unsafe { ASN1_INTEGER_cmp(X509_get0_serialNumber(issuer), (*akid).serial) } != 0 {
            return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
        }
    }
    // Check issuer name
    // SAFETY: `akid` is live.
    if !unsafe { (*akid).issuer.is_null() } {
        // SAFETY: `akid->issuer` is a live stack of general names.
        let gens = unsafe { (*akid).issuer };
        let mut nm: *mut X509Name = ptr::null_mut();
        // SAFETY: `gens` is the live stack.
        let n = unsafe { OPENSSL_sk_num(gens) };
        for i in 0..n {
            // SAFETY: `i` is a valid index and `gens` is the live stack.
            let gen = unsafe { OPENSSL_sk_value(gens, i) }.cast::<GeneralName>();
            // SAFETY: `gen` is a live general name.
            if unsafe { (*gen).type_ } == GEN_DIRNAME {
                // SAFETY: a `GEN_DIRNAME` name carries its directory name in the union.
                nm = unsafe { (*gen).d.directoryName };
                break;
            }
        }
        // SAFETY: `nm` is NULL or live and `issuer` is live.
        if !nm.is_null() && unsafe { X509_NAME_cmp(nm, X509_get_issuer_name(issuer)) } != 0 {
            return X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
        }
    }
    X509_V_OK
}

// ---------------------------------------------------------------------------------------------
// The cache accessors — `v3_purp.c:1076-1147`
// ---------------------------------------------------------------------------------------------

/// `uint32_t X509_get_extension_flags(X509 *x)` — `v3_purp.c:1076-1081`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_extension_flags(x: *mut X509) -> c_uint {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    unsafe { X509_check_purpose(x, -1, 0) };
    // SAFETY: `x` is live.
    unsafe { (*x).ex_flags }
}

/// `uint32_t X509_get_key_usage(X509 *x)` — `v3_purp.c:1083-1089`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_key_usage(x: *mut X509) -> c_uint {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return 0;
    }
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_KUSAGE) != 0 {
        // SAFETY: `x` is live and its key-usage word is set.
        unsafe { (*x).ex_kusage }
    } else {
        c_uint::MAX
    }
}

/// `uint32_t X509_get_extended_key_usage(X509 *x)` — `v3_purp.c:1091-1097`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_extended_key_usage(x: *mut X509) -> c_uint {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return 0;
    }
    // SAFETY: `x` is live.
    if (unsafe { (*x).ex_flags } & EXFLAG_XKUSAGE) != 0 {
        // SAFETY: `x` is live and its extended-key-usage word is set.
        unsafe { (*x).ex_xkusage }
    } else {
        c_uint::MAX
    }
}

/// `const ASN1_OCTET_STRING *X509_get0_subject_key_id(X509 *x)` — `v3_purp.c:1099-1105`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_subject_key_id(
    x: *mut X509,
) -> *const crate::asn1::layout::Asn1String {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return ptr::null();
    }
    // SAFETY: `x` is live.
    unsafe { (*x).skid }
}

/// `const ASN1_OCTET_STRING *X509_get0_authority_key_id(X509 *x)` — `v3_purp.c:1107-1113`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_key_id(
    x: *mut X509,
) -> *const crate::asn1::layout::Asn1String {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return ptr::null();
    }
    // SAFETY: `x` is live; its akid cache slot is NULL or a live AUTHORITY_KEYID.
    if !unsafe { (*x).akid.is_null() } {
        // SAFETY: the akid is non-NULL and live.
        unsafe { (*(*x).akid.cast::<AuthorityKeyid>()).keyid }
    } else {
        ptr::null()
    }
}

/// `const GENERAL_NAMES *X509_get0_authority_issuer(X509 *x)` — `v3_purp.c:1115-1121`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_issuer(x: *mut X509) -> *const OpenSslStack {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return ptr::null();
    }
    // SAFETY: `x` is live; its akid cache slot is NULL or a live AUTHORITY_KEYID.
    if !unsafe { (*x).akid.is_null() } {
        // SAFETY: the akid is non-NULL and live.
        unsafe { (*(*x).akid.cast::<AuthorityKeyid>()).issuer }
    } else {
        ptr::null()
    }
}

/// `const ASN1_INTEGER *X509_get0_authority_serial(X509 *x)` — `v3_purp.c:1123-1129`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_authority_serial(
    x: *mut X509,
) -> *const crate::asn1::layout::Asn1String {
    // Call for side-effect of computing hash and caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return ptr::null();
    }
    // SAFETY: `x` is live; its akid cache slot is NULL or a live AUTHORITY_KEYID.
    if !unsafe { (*x).akid.is_null() } {
        // SAFETY: the akid is non-NULL and live.
        unsafe { (*(*x).akid.cast::<AuthorityKeyid>()).serial }
    } else {
        ptr::null()
    }
}

/// `long X509_get_pathlen(X509 *x)` — `v3_purp.c:1131-1138`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_pathlen(x: *mut X509) -> c_long {
    // Called for side effect of caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return -1;
    }
    // SAFETY: `x` is live and cached.
    if (unsafe { (*x).ex_flags } & EXFLAG_BCONS) == 0 {
        return -1;
    }
    // SAFETY: `x` is live and cached.
    unsafe { (*x).ex_pathlen }
}

/// `long X509_get_proxy_pathlen(X509 *x)` — `v3_purp.c:1140-1147`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_proxy_pathlen(x: *mut X509) -> c_long {
    // Called for side effect of caching extensions
    // SAFETY: `x` is live per the contract.
    if unsafe { X509_check_purpose(x, -1, 0) } != 1 {
        return -1;
    }
    // SAFETY: `x` is live and cached.
    if (unsafe { (*x).ex_flags } & EXFLAG_PROXY) == 0 {
        return -1;
    }
    // SAFETY: `x` is live and cached.
    unsafe { (*x).ex_pcpathlen }
}
