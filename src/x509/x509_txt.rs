//! `crypto/x509/x509_txt.c` — the certificate-verification error strings. Phase 10.12.
//!
//! `crypto/x509/x509_txt.c` is 236 lines and **lands whole**: `X509_verify_cert_error_string`, a
//! switch over every `X509_V_ERR_*` value the authority names in `x509_vfy.h`, each arm answering
//! the exact literal the authority's own `:232-234` default answers for anything else. Nothing in
//! the unit is withheld — it reaches no other symbol — so the transcription is the switch and the
//! `X509_V_*` values it is keyed on, taken from the admitted `x509_vfy.h` rather than typed.
//!
//! **No raise, and the court.** The unit raises nothing, so it is deliberately not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`. Its evidence is `RT-STORE`'s 10.12 arms: the string
//! for a valid code, for each of the arms section 6 calls out (the certificate/CRL validity pair,
//! the key-usage pair, the two RPK/EC reasons) and for an out-of-range code whose answer must be
//! the default.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long};

// The `X509_V_ERR_*` values, from `include/openssl/x509_vfy.h`. Each names the authority's macro;
// the numbers are the header's own.
const X509_V_OK: c_int = 0;
const X509_V_ERR_UNSPECIFIED: c_int = 1;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
const X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
const X509_V_ERR_OUT_OF_MEM: c_int = 17;
const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
const X509_V_ERR_CERT_REVOKED: c_int = 23;
const X509_V_ERR_NO_ISSUER_PUBLIC_KEY: c_int = 24;
const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
const X509_V_ERR_CERT_REJECTED: c_int = 28;
const X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
const X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
const X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
const X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
const X509_V_ERR_INVALID_NON_CA: c_int = 37;
const X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
const X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
const X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
const X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
const X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
const X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
const X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
const X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
const X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
const X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
const X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
const X509_V_ERR_PATH_LOOP: c_int = 55;
const X509_V_ERR_SUITE_B_INVALID_VERSION: c_int = 56;
const X509_V_ERR_SUITE_B_INVALID_ALGORITHM: c_int = 57;
const X509_V_ERR_SUITE_B_INVALID_CURVE: c_int = 58;
const X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM: c_int = 59;
const X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED: c_int = 60;
const X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256: c_int = 61;
const X509_V_ERR_HOSTNAME_MISMATCH: c_int = 62;
const X509_V_ERR_EMAIL_MISMATCH: c_int = 63;
const X509_V_ERR_IP_ADDRESS_MISMATCH: c_int = 64;
const X509_V_ERR_DANE_NO_MATCH: c_int = 65;
const X509_V_ERR_EE_KEY_TOO_SMALL: c_int = 66;
const X509_V_ERR_CA_KEY_TOO_SMALL: c_int = 67;
const X509_V_ERR_CA_MD_TOO_WEAK: c_int = 68;
const X509_V_ERR_INVALID_CALL: c_int = 69;
const X509_V_ERR_STORE_LOOKUP: c_int = 70;
const X509_V_ERR_NO_VALID_SCTS: c_int = 71;
const X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION: c_int = 72;
const X509_V_ERR_OCSP_VERIFY_NEEDED: c_int = 73;
const X509_V_ERR_OCSP_VERIFY_FAILED: c_int = 74;
const X509_V_ERR_OCSP_CERT_UNKNOWN: c_int = 75;
const X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM: c_int = 76;
const X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH: c_int = 77;
const X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY: c_int = 78;
const X509_V_ERR_INVALID_CA: c_int = 79;
const X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA: c_int = 80;
const X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN: c_int = 81;
const X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA: c_int = 82;
const X509_V_ERR_ISSUER_NAME_EMPTY: c_int = 83;
const X509_V_ERR_SUBJECT_NAME_EMPTY: c_int = 84;
const X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER: c_int = 85;
const X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER: c_int = 86;
const X509_V_ERR_EMPTY_SUBJECT_ALT_NAME: c_int = 87;
const X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL: c_int = 88;
const X509_V_ERR_CA_BCONS_NOT_CRITICAL: c_int = 89;
const X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL: c_int = 90;
const X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL: c_int = 91;
const X509_V_ERR_CA_CERT_MISSING_KEY_USAGE: c_int = 92;
const X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3: c_int = 93;
const X509_V_ERR_EC_KEY_EXPLICIT_PARAMS: c_int = 94;
const X509_V_ERR_RPK_UNTRUSTED: c_int = 95;
const X509_V_ERR_OCSP_RESP_INVALID: c_int = 96;
const X509_V_ERR_OCSP_SIGNATURE_FAILURE: c_int = 97;
const X509_V_ERR_OCSP_NOT_YET_VALID: c_int = 98;
const X509_V_ERR_OCSP_HAS_EXPIRED: c_int = 99;
const X509_V_ERR_OCSP_NO_RESPONSE: c_int = 100;

/// `const char *X509_verify_cert_error_string(long n)` — `crypto/x509/x509_txt.c:21-236`.
///
/// The argument is narrowed to `int` exactly as the authority's `switch ((int)n)` does. Every
/// value `x509_vfy.h` names has an arm; anything else answers the authority's own default at
/// `:232-234`, whose comment records why it is a pointer to a literal rather than a formatted
/// static buffer.
#[no_mangle]
pub extern "C" fn X509_verify_cert_error_string(n: c_long) -> *const c_char {
    match n as c_int {
        X509_V_OK => c"ok".as_ptr(),
        X509_V_ERR_UNSPECIFIED => c"unspecified certificate verification error".as_ptr(),
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT => c"unable to get issuer certificate".as_ptr(),
        X509_V_ERR_UNABLE_TO_GET_CRL => c"unable to get certificate CRL".as_ptr(),
        X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE => {
            c"unable to decrypt certificate's signature".as_ptr()
        }
        X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE => c"unable to decrypt CRL's signature".as_ptr(),
        X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY => {
            c"unable to decode issuer public key".as_ptr()
        }
        X509_V_ERR_CERT_SIGNATURE_FAILURE => c"certificate signature failure".as_ptr(),
        X509_V_ERR_CRL_SIGNATURE_FAILURE => c"CRL signature failure".as_ptr(),
        X509_V_ERR_CERT_NOT_YET_VALID => {
            c"certificate is not yet valid or the system clock is incorrect".as_ptr()
        }
        X509_V_ERR_CERT_HAS_EXPIRED => c"certificate has expired".as_ptr(),
        X509_V_ERR_CRL_NOT_YET_VALID => c"CRL is not yet valid".as_ptr(),
        X509_V_ERR_CRL_HAS_EXPIRED => c"CRL has expired".as_ptr(),
        X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD => {
            c"format error in certificate's notBefore field".as_ptr()
        }
        X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD => {
            c"format error in certificate's notAfter field".as_ptr()
        }
        X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD => {
            c"format error in CRL's lastUpdate field".as_ptr()
        }
        X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD => {
            c"format error in CRL's nextUpdate field".as_ptr()
        }
        X509_V_ERR_OUT_OF_MEM => c"out of memory".as_ptr(),
        X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT => c"self-signed certificate".as_ptr(),
        X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN => {
            c"self-signed certificate in certificate chain".as_ptr()
        }
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY => {
            c"unable to get local issuer certificate".as_ptr()
        }
        X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE => {
            c"unable to verify the first certificate".as_ptr()
        }
        X509_V_ERR_CERT_CHAIN_TOO_LONG => c"certificate chain too long".as_ptr(),
        X509_V_ERR_CERT_REVOKED => c"certificate revoked".as_ptr(),
        X509_V_ERR_NO_ISSUER_PUBLIC_KEY => c"issuer certificate doesn't have a public key".as_ptr(),
        X509_V_ERR_PATH_LENGTH_EXCEEDED => c"path length constraint exceeded".as_ptr(),
        X509_V_ERR_INVALID_PURPOSE => c"unsuitable certificate purpose".as_ptr(),
        X509_V_ERR_CERT_UNTRUSTED => c"certificate not trusted".as_ptr(),
        X509_V_ERR_CERT_REJECTED => c"certificate rejected".as_ptr(),
        X509_V_ERR_SUBJECT_ISSUER_MISMATCH => c"subject issuer mismatch".as_ptr(),
        X509_V_ERR_AKID_SKID_MISMATCH => c"authority and subject key identifier mismatch".as_ptr(),
        X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH => {
            c"authority and issuer serial number mismatch".as_ptr()
        }
        X509_V_ERR_KEYUSAGE_NO_CERTSIGN => {
            c"key usage does not include certificate signing".as_ptr()
        }
        X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER => c"unable to get CRL issuer certificate".as_ptr(),
        X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION => c"unhandled critical extension".as_ptr(),
        X509_V_ERR_KEYUSAGE_NO_CRL_SIGN => c"key usage does not include CRL signing".as_ptr(),
        X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION => c"unhandled critical CRL extension".as_ptr(),
        X509_V_ERR_INVALID_NON_CA => c"invalid non-CA certificate (has CA markings)".as_ptr(),
        X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED => c"proxy path length constraint exceeded".as_ptr(),
        X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE => {
            c"key usage does not include digital signature".as_ptr()
        }
        X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED => {
            c"proxy certificates not allowed, please set the appropriate flag".as_ptr()
        }
        X509_V_ERR_INVALID_EXTENSION => c"invalid or inconsistent certificate extension".as_ptr(),
        X509_V_ERR_INVALID_POLICY_EXTENSION => {
            c"invalid or inconsistent certificate policy extension".as_ptr()
        }
        X509_V_ERR_NO_EXPLICIT_POLICY => c"no explicit policy".as_ptr(),
        X509_V_ERR_DIFFERENT_CRL_SCOPE => c"different CRL scope".as_ptr(),
        X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE => c"unsupported extension feature".as_ptr(),
        X509_V_ERR_UNNESTED_RESOURCE => {
            c"RFC 3779 resource not subset of parent's resources".as_ptr()
        }
        X509_V_ERR_PERMITTED_VIOLATION => c"permitted subtree violation".as_ptr(),
        X509_V_ERR_EXCLUDED_VIOLATION => c"excluded subtree violation".as_ptr(),
        X509_V_ERR_SUBTREE_MINMAX => c"name constraints minimum and maximum not supported".as_ptr(),
        X509_V_ERR_APPLICATION_VERIFICATION => c"application verification failure".as_ptr(),
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE => c"unsupported name constraint type".as_ptr(),
        X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX => {
            c"unsupported or invalid name constraint syntax".as_ptr()
        }
        X509_V_ERR_UNSUPPORTED_NAME_SYNTAX => c"unsupported or invalid name syntax".as_ptr(),
        X509_V_ERR_CRL_PATH_VALIDATION_ERROR => c"CRL path validation error".as_ptr(),
        X509_V_ERR_PATH_LOOP => c"path loop".as_ptr(),
        X509_V_ERR_SUITE_B_INVALID_VERSION => c"Suite B: certificate version invalid".as_ptr(),
        X509_V_ERR_SUITE_B_INVALID_ALGORITHM => c"Suite B: invalid public key algorithm".as_ptr(),
        X509_V_ERR_SUITE_B_INVALID_CURVE => c"Suite B: invalid ECC curve".as_ptr(),
        X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM => {
            c"Suite B: invalid signature algorithm".as_ptr()
        }
        X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED => c"Suite B: curve not allowed for this LOS".as_ptr(),
        X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 => {
            c"Suite B: cannot sign P-384 with P-256".as_ptr()
        }
        X509_V_ERR_HOSTNAME_MISMATCH => c"hostname mismatch".as_ptr(),
        X509_V_ERR_EMAIL_MISMATCH => c"email address mismatch".as_ptr(),
        X509_V_ERR_IP_ADDRESS_MISMATCH => c"IP address mismatch".as_ptr(),
        X509_V_ERR_DANE_NO_MATCH => c"no matching DANE TLSA records".as_ptr(),
        X509_V_ERR_EE_KEY_TOO_SMALL => c"EE certificate key too weak".as_ptr(),
        X509_V_ERR_CA_KEY_TOO_SMALL => c"CA certificate key too weak".as_ptr(),
        X509_V_ERR_CA_MD_TOO_WEAK => c"CA signature digest algorithm too weak".as_ptr(),
        X509_V_ERR_INVALID_CALL => c"invalid certificate verification context".as_ptr(),
        X509_V_ERR_STORE_LOOKUP => c"issuer certificate lookup error".as_ptr(),
        X509_V_ERR_NO_VALID_SCTS => {
            c"Certificate Transparency required, but no valid SCTs found".as_ptr()
        }
        X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION => c"proxy subject name violation".as_ptr(),
        X509_V_ERR_OCSP_VERIFY_NEEDED => c"OCSP verification needed".as_ptr(),
        X509_V_ERR_OCSP_VERIFY_FAILED => c"OCSP verification failed".as_ptr(),
        X509_V_ERR_OCSP_CERT_UNKNOWN => c"OCSP unknown cert".as_ptr(),
        X509_V_ERR_OCSP_RESP_INVALID => c"OCSP response(s) invalid".as_ptr(),
        X509_V_ERR_OCSP_SIGNATURE_FAILURE => {
            c"OCSP response signature verification failure".as_ptr()
        }
        X509_V_ERR_OCSP_NOT_YET_VALID => {
            c"OCSP response not yet valid (contains a date in the future)".as_ptr()
        }
        X509_V_ERR_OCSP_HAS_EXPIRED => c"OCSP response has expired".as_ptr(),
        X509_V_ERR_OCSP_NO_RESPONSE => c"no OCSP response available for certificate".as_ptr(),
        X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM => {
            c"Cannot find certificate signature algorithm".as_ptr()
        }
        X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH => {
            c"subject signature algorithm and issuer public key algorithm mismatch".as_ptr()
        }
        X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY => {
            c"cert info signature and signature algorithm mismatch".as_ptr()
        }
        X509_V_ERR_INVALID_CA => c"invalid CA certificate".as_ptr(),
        X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA => c"Path length invalid for non-CA cert".as_ptr(),
        X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN => {
            c"Path length given without key usage keyCertSign".as_ptr()
        }
        X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA => {
            c"Key usage keyCertSign invalid for non-CA cert".as_ptr()
        }
        X509_V_ERR_ISSUER_NAME_EMPTY => c"Issuer name empty".as_ptr(),
        X509_V_ERR_SUBJECT_NAME_EMPTY => c"Subject name empty".as_ptr(),
        X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER => c"Missing Authority Key Identifier".as_ptr(),
        X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER => c"Missing Subject Key Identifier".as_ptr(),
        X509_V_ERR_EMPTY_SUBJECT_ALT_NAME => c"Empty Subject Alternative Name extension".as_ptr(),
        X509_V_ERR_CA_BCONS_NOT_CRITICAL => {
            c"Basic Constraints of CA cert not marked critical".as_ptr()
        }
        X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL => {
            c"Subject empty and Subject Alt Name extension not critical".as_ptr()
        }
        X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL => {
            c"Authority Key Identifier marked critical".as_ptr()
        }
        X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL => {
            c"Subject Key Identifier marked critical".as_ptr()
        }
        X509_V_ERR_CA_CERT_MISSING_KEY_USAGE => {
            c"CA cert does not include key usage extension".as_ptr()
        }
        X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3 => {
            c"Using cert extension requires at least X509v3".as_ptr()
        }
        X509_V_ERR_EC_KEY_EXPLICIT_PARAMS => {
            c"Certificate public key has explicit ECC parameters".as_ptr()
        }
        X509_V_ERR_RPK_UNTRUSTED => {
            c"Raw public key untrusted, no trusted keys configured".as_ptr()
        }
        // Entries must be kept consistent with `x509_vfy.h` and
        // `doc/man3/X509_STORE_CTX_get_error.pod`. Printing an error number into a static buffer
        // is not thread-safe, so the default is a literal.
        _ => c"unknown certificate verification error".as_ptr(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn s(n: c_long) -> &'static core::ffi::CStr {
        // SAFETY: the function returns a pointer to a NUL-terminated literal for every input.
        unsafe { core::ffi::CStr::from_ptr(X509_verify_cert_error_string(n)) }
    }

    /// The known codes answer the authority's literals and anything else answers the default.
    #[test]
    fn the_error_strings_match_the_authoritys_switch() {
        // SAFETY: `s` reads a literal the callee owns for the process lifetime.
        unsafe {
            assert_eq!(s(0), c"ok");
            assert_eq!(s(10), c"certificate has expired");
            assert_eq!(
                s(95),
                c"Raw public key untrusted, no trusted keys configured"
            );
            assert_eq!(s(101), c"unknown certificate verification error");
            assert_eq!(s(-1), c"unknown certificate verification error");
        }
    }
}
