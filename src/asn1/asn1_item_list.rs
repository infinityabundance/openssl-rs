//! `crypto/asn1/asn1_item_list.c` — the two lookup entry points over the generated
//! item list. Phase 12.9, the last row handed from Phase 5 (D80).
//!
//! The authority's unit is 46 lines: two loops over a `static` array that is not in
//! the `.c` file at all but in the **generated** `crypto/asn1/asn1_item_list.h`. That
//! header is a 147-entry `ASN1_ITEM_ref(NAME)` table, and since every guard in it
//! (`OPENSSL_NO_RFC3779`, `OPENSSL_NO_CMS`, `OPENSSL_NO_DH`, `OPENSSL_NO_EC`,
//! `OPENSSL_NO_OCSP`, `OPENSSL_NO_SCRYPT`, `OPENSSL_NO_DEPRECATED_3_0`) is *unset* in
//! the admitted authority's `configuration.h`, all 147 entries are present in the
//! production build. The header's order is the contract: `ASN1_ITEM_get(i)` is
//! index-addressed, so the table below reproduces that order exactly rather than
//! sorting by name.
//!
//! `ASN1_ITEM_ref(NAME)` is `NAME_it` — the accessor *function* — and `ASN1_ITEM_ptr(x)`
//! is `(x)()` (`include/openssl/asn1.h:428,431`), so the authority's array is an array
//! of function pointers that it calls on every access. This crate lands each item as a
//! `pub extern "C" fn NAME_it() -> *const Asn1Item` accessor; [`asn1_item_list`]
//! resolves them to the item pointers in the header's order, which is what both
//! functions below then scan.
//!
//! This is where D80 lands: a lookup over only the 40 items that existed before Phase 12
//! would answer `NULL` for the other 107 and be a silently wrong function. The table is
//! therefore exactly as wide as the authority's.
//!
//! SPDX-License-Identifier: Apache-2.0

// The two entry points carry the authority's own names, so a reader can line them up
// with `include/openssl/asn1.h:1107-1108` without a translation table.
#![allow(non_snake_case)]
// The module is `pub(crate)` (the two symbols reach C through `#[no_mangle]`, not
// through Rust paths), so the `pub` below is the ABI-visibility statement the task and
// the crate's other `no_mangle` modules use; this is the same allow they carry.
#![allow(unreachable_pub)]

use core::ffi::c_char;

use crate::asn1::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_BMPSTRING_it, ASN1_BOOLEAN_it, ASN1_ENUMERATED_it,
    ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it, ASN1_GENERALSTRING_it, ASN1_IA5STRING_it,
    ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it,
    ASN1_PRINTABLESTRING_it, ASN1_PRINTABLE_it, ASN1_SEQUENCE_ANY_it, ASN1_SEQUENCE_it,
    ASN1_SET_ANY_it, ASN1_T61STRING_it, ASN1_TBOOLEAN_it, ASN1_TIME_it, ASN1_UNIVERSALSTRING_it,
    ASN1_UTCTIME_it, ASN1_UTF8STRING_it, ASN1_VISIBLESTRING_it, DIRECTORYSTRING_it, DISPLAYTEXT_it,
};
use crate::asn1::layout::Asn1Item;
use crate::asn1::nsseq::NETSCAPE_CERT_SEQUENCE_it;
use crate::asn1::p5_pbe::PBEPARAM_it;
use crate::asn1::p5_pbev2::{PBE2PARAM_it, PBKDF2PARAM_it};
use crate::asn1::p5_scrypt::SCRYPT_PARAMS_it;
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_it;
use crate::asn1::x_algor::{X509_ALGORS_it, X509_ALGOR_it};
use crate::asn1::x_bignum::{BIGNUM_it, CBIGNUM_it};
use crate::asn1::x_int64::{
    INT32_it, INT64_it, UINT32_it, UINT64_it, ZINT32_it, ZINT64_it, ZUINT32_it, ZUINT64_it,
};
use crate::asn1::x_long::{LONG_it, ZLONG_it};
use crate::asn1::x_sig::X509_SIG_it;
use crate::asn1::x_spki::{NETSCAPE_SPKAC_it, NETSCAPE_SPKI_it};
use crate::asn1::x_val::X509_VAL_it;
use crate::cms::cms_asn1::{CMS_ContentInfo_it, CMS_EnvelopedData_it, CMS_ReceiptRequest_it};
use crate::dh::asn1::DHparams_it;
use crate::ec::asn1::{ECPARAMETERS_it, ECPKPARAMETERS_it};
use crate::ocsp::ocsp_asn::{
    OCSP_BASICRESP_it, OCSP_CERTID_it, OCSP_CERTSTATUS_it, OCSP_CRLID_it, OCSP_ONEREQ_it,
    OCSP_REQINFO_it, OCSP_REQUEST_it, OCSP_RESPBYTES_it, OCSP_RESPDATA_it, OCSP_RESPID_it,
    OCSP_RESPONSE_it, OCSP_REVOKEDINFO_it, OCSP_SERVICELOC_it, OCSP_SIGNATURE_it,
    OCSP_SINGLERESP_it,
};
use crate::pkcs12::p12_asn::{
    PKCS12_AUTHSAFES_it, PKCS12_BAGS_it, PKCS12_MAC_DATA_it, PKCS12_SAFEBAGS_it, PKCS12_SAFEBAG_it,
    PKCS12_it,
};
use crate::pkcs7::pk7_asn1::{
    PKCS7_ATTR_SIGN_it, PKCS7_ATTR_VERIFY_it, PKCS7_DIGEST_it, PKCS7_ENCRYPT_it,
    PKCS7_ENC_CONTENT_it, PKCS7_ENVELOPE_it, PKCS7_ISSUER_AND_SERIAL_it, PKCS7_RECIP_INFO_it,
    PKCS7_SIGNED_it, PKCS7_SIGNER_INFO_it, PKCS7_SIGN_ENVELOPE_it, PKCS7_it,
};
use crate::rsa::asn1::{RSAPrivateKey_it, RSAPublicKey_it, RSA_OAEP_PARAMS_it, RSA_PSS_PARAMS_it};
use crate::runtime::bio::sys::strcmp;
use crate::x509::v3_addr::{
    IPAddressChoice_it, IPAddressFamily_it, IPAddressOrRange_it, IPAddressRange_it,
};
use crate::x509::v3_akeya::AUTHORITY_KEYID_it;
use crate::x509::v3_asid::{ASIdOrRange_it, ASIdentifierChoice_it, ASIdentifiers_it, ASRange_it};
use crate::x509::v3_bcons::BASIC_CONSTRAINTS_it;
use crate::x509::v3_cpols::{
    CERTIFICATEPOLICIES_it, NOTICEREF_it, POLICYINFO_it, POLICYQUALINFO_it, USERNOTICE_it,
};
use crate::x509::v3_crld::{
    CRL_DIST_POINTS_it, DIST_POINT_NAME_it, DIST_POINT_it, ISSUING_DIST_POINT_it,
};
use crate::x509::v3_extku::EXTENDED_KEY_USAGE_it;
use crate::x509::v3_genn::{EDIPARTYNAME_it, GENERAL_NAMES_it, GENERAL_NAME_it, OTHERNAME_it};
use crate::x509::v3_info::{ACCESS_DESCRIPTION_it, AUTHORITY_INFO_ACCESS_it};
use crate::x509::v3_ist::ISSUER_SIGN_TOOL_it;
use crate::x509::v3_ncons::{GENERAL_SUBTREE_it, NAME_CONSTRAINTS_it};
use crate::x509::v3_pcia::{PROXY_CERT_INFO_EXTENSION_it, PROXY_POLICY_it};
use crate::x509::v3_pcons::POLICY_CONSTRAINTS_it;
use crate::x509::v3_pku::PKEY_USAGE_PERIOD_it;
use crate::x509::v3_pmaps::{POLICY_MAPPINGS_it, POLICY_MAPPING_it};
use crate::x509::v3_sxnet::{SXNETID_it, SXNET_it};
use crate::x509::x509_acert::X509_ACERT_it;
use crate::x509::x_attrib::X509_ATTRIBUTE_it;
use crate::x509::x_crl::{X509_CRL_INFO_it, X509_CRL_it, X509_REVOKED_it};
use crate::x509::x_exten::{X509_EXTENSIONS_it, X509_EXTENSION_it};
use crate::x509::x_name::{X509_NAME_ENTRY_it, X509_NAME_it};
use crate::x509::x_pubkey::X509_PUBKEY_it;
use crate::x509::x_req::{X509_REQ_INFO_it, X509_REQ_it};
use crate::x509::x_x509::{X509_CINF_it, X509_it};
use crate::x509::x_x509a::X509_CERT_AUX_it;

/// The number of entries in the authority's generated `asn1_item_list[]`
/// (`OSSL_NELEM(asn1_item_list)`), i.e. the value `ASN1_ITEM_get` bounds-checks against.
pub(crate) const ASN1_ITEM_LIST_LEN: usize = 147;

/// The authority's `static ASN1_ITEM_EXP *asn1_item_list[]` with `ASN1_ITEM_ptr`
/// applied: the resolved item pointers, in `crypto/asn1/asn1_item_list.h`'s order.
///
/// In C the array holds the accessor functions and each read calls one; here every
/// element already is the result of `NAME_it()`, which is the same pointer. The order
/// is the contract `ASN1_ITEM_get` is addressed by, so it is transcribed, not sorted.
fn asn1_item_list() -> [*const Asn1Item; ASN1_ITEM_LIST_LEN] {
    [
        ACCESS_DESCRIPTION_it(),
        ASIdOrRange_it(),
        ASIdentifierChoice_it(),
        ASIdentifiers_it(),
        ASN1_ANY_it(),
        ASN1_BIT_STRING_it(),
        ASN1_BMPSTRING_it(),
        ASN1_BOOLEAN_it(),
        ASN1_ENUMERATED_it(),
        ASN1_FBOOLEAN_it(),
        ASN1_GENERALIZEDTIME_it(),
        ASN1_GENERALSTRING_it(),
        ASN1_IA5STRING_it(),
        ASN1_INTEGER_it(),
        ASN1_NULL_it(),
        ASN1_OBJECT_it(),
        ASN1_OCTET_STRING_NDEF_it(),
        ASN1_OCTET_STRING_it(),
        ASN1_PRINTABLESTRING_it(),
        ASN1_PRINTABLE_it(),
        ASN1_SEQUENCE_ANY_it(),
        ASN1_SEQUENCE_it(),
        ASN1_SET_ANY_it(),
        ASN1_T61STRING_it(),
        ASN1_TBOOLEAN_it(),
        ASN1_TIME_it(),
        ASN1_UNIVERSALSTRING_it(),
        ASN1_UTCTIME_it(),
        ASN1_UTF8STRING_it(),
        ASN1_VISIBLESTRING_it(),
        ASRange_it(),
        AUTHORITY_INFO_ACCESS_it(),
        AUTHORITY_KEYID_it(),
        BASIC_CONSTRAINTS_it(),
        BIGNUM_it(),
        CBIGNUM_it(),
        CERTIFICATEPOLICIES_it(),
        CMS_ContentInfo_it(),
        CMS_EnvelopedData_it(),
        CMS_ReceiptRequest_it(),
        CRL_DIST_POINTS_it(),
        DHparams_it(),
        DIRECTORYSTRING_it(),
        DISPLAYTEXT_it(),
        DIST_POINT_NAME_it(),
        DIST_POINT_it(),
        ECPARAMETERS_it(),
        ECPKPARAMETERS_it(),
        EDIPARTYNAME_it(),
        EXTENDED_KEY_USAGE_it(),
        GENERAL_NAMES_it(),
        GENERAL_NAME_it(),
        GENERAL_SUBTREE_it(),
        IPAddressChoice_it(),
        IPAddressFamily_it(),
        IPAddressOrRange_it(),
        IPAddressRange_it(),
        ISSUING_DIST_POINT_it(),
        LONG_it(),
        NAME_CONSTRAINTS_it(),
        NETSCAPE_CERT_SEQUENCE_it(),
        NETSCAPE_SPKAC_it(),
        NETSCAPE_SPKI_it(),
        NOTICEREF_it(),
        OCSP_BASICRESP_it(),
        OCSP_CERTID_it(),
        OCSP_CERTSTATUS_it(),
        OCSP_CRLID_it(),
        OCSP_ONEREQ_it(),
        OCSP_REQINFO_it(),
        OCSP_REQUEST_it(),
        OCSP_RESPBYTES_it(),
        OCSP_RESPDATA_it(),
        OCSP_RESPID_it(),
        OCSP_RESPONSE_it(),
        OCSP_REVOKEDINFO_it(),
        OCSP_SERVICELOC_it(),
        OCSP_SIGNATURE_it(),
        OCSP_SINGLERESP_it(),
        OTHERNAME_it(),
        PBE2PARAM_it(),
        PBEPARAM_it(),
        PBKDF2PARAM_it(),
        PKCS12_AUTHSAFES_it(),
        PKCS12_BAGS_it(),
        PKCS12_MAC_DATA_it(),
        PKCS12_SAFEBAGS_it(),
        PKCS12_SAFEBAG_it(),
        PKCS12_it(),
        PKCS7_ATTR_SIGN_it(),
        PKCS7_ATTR_VERIFY_it(),
        PKCS7_DIGEST_it(),
        PKCS7_ENCRYPT_it(),
        PKCS7_ENC_CONTENT_it(),
        PKCS7_ENVELOPE_it(),
        PKCS7_ISSUER_AND_SERIAL_it(),
        PKCS7_RECIP_INFO_it(),
        PKCS7_SIGNED_it(),
        PKCS7_SIGNER_INFO_it(),
        PKCS7_SIGN_ENVELOPE_it(),
        PKCS7_it(),
        PKCS8_PRIV_KEY_INFO_it(),
        PKEY_USAGE_PERIOD_it(),
        POLICYINFO_it(),
        POLICYQUALINFO_it(),
        POLICY_CONSTRAINTS_it(),
        POLICY_MAPPINGS_it(),
        POLICY_MAPPING_it(),
        PROXY_CERT_INFO_EXTENSION_it(),
        PROXY_POLICY_it(),
        RSAPrivateKey_it(),
        RSAPublicKey_it(),
        RSA_OAEP_PARAMS_it(),
        RSA_PSS_PARAMS_it(),
        SCRYPT_PARAMS_it(),
        SXNETID_it(),
        SXNET_it(),
        ISSUER_SIGN_TOOL_it(),
        USERNOTICE_it(),
        X509_ACERT_it(),
        X509_ALGORS_it(),
        X509_ALGOR_it(),
        X509_ATTRIBUTE_it(),
        X509_CERT_AUX_it(),
        X509_CINF_it(),
        X509_CRL_INFO_it(),
        X509_CRL_it(),
        X509_EXTENSIONS_it(),
        X509_EXTENSION_it(),
        X509_NAME_ENTRY_it(),
        X509_NAME_it(),
        X509_PUBKEY_it(),
        X509_REQ_INFO_it(),
        X509_REQ_it(),
        X509_REVOKED_it(),
        X509_SIG_it(),
        X509_VAL_it(),
        X509_it(),
        ZLONG_it(),
        INT32_it(),
        UINT32_it(),
        ZINT32_it(),
        ZUINT32_it(),
        INT64_it(),
        UINT64_it(),
        ZINT64_it(),
        ZUINT64_it(),
    ]
}

/// `const ASN1_ITEM *ASN1_ITEM_lookup(const char *name)` — `crypto/asn1/asn1_item_list.c:28`.
///
/// Scans the generated list in order and answers the first item whose `sname` compares
/// equal to `name`, or null when no item matches.
///
/// # Safety
///
/// `name` must point to a NUL-terminated C string, as it does at every authority call
/// site. The authority guards nothing before handing it to `strcmp`, so neither does
/// this transcription: a null `name` is undefined behaviour here exactly as it is in
/// the authority, and is deliberately not turned into a null return.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ITEM_lookup(name: *const c_char) -> *const Asn1Item {
    for item in asn1_item_list() {
        // SAFETY: every element of `asn1_item_list()` is a pointer answered by an
        // `_it()` accessor, which returns the address of a `'static` item the crate
        // owns, so it is valid to read `sname` through it. `name` is the caller's
        // contract stated above.
        if unsafe { strcmp((*item).sname, name) } == 0 {
            return item;
        }
    }
    core::ptr::null()
}

/// `const ASN1_ITEM *ASN1_ITEM_get(size_t i)` — `crypto/asn1/asn1_item_list.c:41`.
///
/// Answers the `i`-th item of the generated list, or null when `i` is at or past its
/// end (`i >= OSSL_NELEM(asn1_item_list)`).
///
/// # Safety
///
/// `i` is bounds-checked, so the call has no precondition of its own and never reads
/// out of range. It is an `extern "C"` entry point that hands back a raw pointer into a
/// `'static` item; the pointer is valid for the lifetime of the program and must not be
/// freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn ASN1_ITEM_get(i: usize) -> *const Asn1Item {
    let list = asn1_item_list();
    if i >= list.len() {
        return core::ptr::null();
    }
    list[i]
}
