//! Phase 8 — the default provider's `OSSL_OP_SIGNATURE` table, and the operation's `deflt_query`
//! arm.
//!
//! `providers/defltprov.c:415-521` declares `deflt_signature[]`, a fifty-nine-row table of the
//! default provider's signature algorithms. This module carries the run of it the crate has landed,
//! in the authority's own order, so the provider census (`forensics/tools/gen_provider_algorithms.py`)
//! can join each row to the authority's by its full alias sequence.
//!
//! ## Why the table is here and the units are elsewhere
//!
//! The authority's signature rows are defined by six `providers/implementations/signature/` units
//! plus the two PQC key units this crate does not have. Each row's *dispatch table* is that unit's
//! (`ossl_rsa_signature_functions` and its neighbours), so each is transcribed in the module named
//! for its unit — `src/provider/mac_legacy_sig.rs` is the first. `deflt_signature[]` is the one
//! thing that belongs to no single unit, because the authority's `defltprov.c` is the unit that
//! declares it, and this module is the crate's transcription of that declaration.
//!
//! ## The order is the constraint, not a preference
//!
//! The census requires the crate's landed rows for one operation to be a **subsequence** of the
//! authority's rows in the authority's order (D386). `deflt_signature[]`'s order interleaves the
//! units — the ten `DSA` rows, then the fourteen `RSA` ones, then the five `EdDSA` ones, the ten
//! `ECDSA` ones, `SM2`, the three `ML-DSA` ones, the four legacy-MAC ones and the twelve
//! `SLH-DSA` ones — so a row added out of that order would be a census failure rather than a
//! cosmetic one. The table below is therefore appended to in the authority's order as the units
//! land, and a unit that lands later inserts *between* the rows already here.
//!
//! ## What is not here
//!
//! The `SLH-DSA` and `ML-DSA` rows are not stubbed: their units are built on `crypto/slh_dsa/` and
//! `crypto/ml_dsa/`, which this crate does not have, so their transcription cannot close. The
//! `RSA`, `DSA`, `ECDSA`, `EdDSA` and `SM2` units are absent for a reason that is a *measured*
//! prerequisite rather than a size judgement, and each is named with its remaining callee:
//!
//!   * `rsa_sig.c.in` waits on `providers/common/der/der_rsa_sig.c`'s two
//!     `ossl_DER_w_algorithmIdentifier_*` writers and `providers/common/securitycheck.c`'s
//!     `ossl_rsa_key_op_get_protect`;
//!   * `dsa_sig.c.in` waits on `der_dsa_sig.c`'s writer and `securitycheck.c`'s `ossl_dsa_check_key`;
//!   * `ecdsa_sig.c.in` waits on `der_ec_sig.c`'s writer and `securitycheck.c`'s
//!     `ossl_digest_get_approved_nid`;
//!   * `eddsa_sig.c.in` waits only on `der_ecx_key.c`'s two writers;
//!   * `sm2_sig.c.in` waits on `der_sm2_sig.c`'s writer and `crypto/sm2/sm2_sign.c`.
//!
//! The legacy-MAC unit waits on none of them, which is why it is the one the table opens with.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

use crate::provider::activate::OsslAlgorithm;
use crate::provider::dsa_sig::{
    DSA_SHA1_SIGNATURE_FUNCTIONS, DSA_SHA224_SIGNATURE_FUNCTIONS, DSA_SHA256_SIGNATURE_FUNCTIONS,
    DSA_SHA384_SIGNATURE_FUNCTIONS, DSA_SHA3_224_SIGNATURE_FUNCTIONS,
    DSA_SHA3_256_SIGNATURE_FUNCTIONS, DSA_SHA3_384_SIGNATURE_FUNCTIONS,
    DSA_SHA3_512_SIGNATURE_FUNCTIONS, DSA_SHA512_SIGNATURE_FUNCTIONS, DSA_SIGNATURE_FUNCTIONS,
};
use crate::provider::mac_legacy_sig::{
    MAC_LEGACY_CMAC_SIGNATURE_FUNCTIONS, MAC_LEGACY_HMAC_SIGNATURE_FUNCTIONS,
    MAC_LEGACY_POLY1305_SIGNATURE_FUNCTIONS, MAC_LEGACY_SIPHASH_SIGNATURE_FUNCTIONS,
};

/// `static const OSSL_ALGORITHM deflt_signature[]` — `providers/defltprov.c:415-521`, **the rows
/// this module has landed**, in the authority's order.
///
/// Two units have landed. `dsa_sig.c.in` is the authority's first ten rows (`:417-426`), the
/// `DSA` row first and its nine `DSA-<MD>` sigalgs after it; the ten dispatch tables are
/// `src/provider/dsa_sig.rs`'s. The four legacy-MAC rows are the second landing: `HMAC` (`:476`),
/// `SIPHASH` (`:478-479`), `POLY1305` (`:481-482`) and `CMAC` (`:484`), whose tables are
/// `src/provider/mac_legacy_sig.rs`'s.
///
/// **The property definition is `"provider=default"` on every row** (`defltprov.c`'s three-field
/// initializer, D247). The rows between the two runs — the fourteen `RSA` ones, the five `EdDSA`
/// ones, the ten `ECDSA` ones, `SM2`, the three `ML-DSA` ones — are absent rather than reordered
/// until their units land: the census requires this table's rows to be a **subsequence** of
/// `deflt_signature[]` in the authority's order (D386).
///
/// **`#[rustfmt::skip]` is load-bearing, not cosmetic.** `gen_provider_algorithms.py`'s row
/// reader anchors a row on `algorithm_names: c"…"` and `implementation: …as_ptr()` in one another's
/// neighbourhood; the longer `DSA-<MD>` alias sequences exceed the formatter's width, and a
/// rustfmt pass that moved the `c"…"` onto its own line would make the census read a table with
/// fewer rows than it has.
#[rustfmt::skip]
pub(crate) static DEFLT_SIGNATURES: [OsslAlgorithm; 15] = [
    OsslAlgorithm {
        // `PROV_NAMES_DSA` — the OID alias is part of the row.
        algorithm_names: c"DSA:dsaEncryption:1.2.840.10040.4.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA1`.
        algorithm_names: c"DSA-SHA1:DSA-SHA-1:dsaWithSHA1:1.2.840.10040.4.3".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA1_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA224`.
        algorithm_names: c"DSA-SHA2-224:DSA-SHA224:dsa_with_SHA224:2.16.840.1.101.3.4.3.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA256`.
        algorithm_names: c"DSA-SHA2-256:DSA-SHA256:dsa_with_SHA256:2.16.840.1.101.3.4.3.2".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA384`.
        algorithm_names: c"DSA-SHA2-384:DSA-SHA384:dsa_with_SHA384:id-dsa-with-sha384:1.2.840.1.101.3.4.3.3".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA512`.
        algorithm_names: c"DSA-SHA2-512:DSA-SHA512:dsa_with_SHA512:id-dsa-with-sha512:1.2.840.1.101.3.4.3.4".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA3_224`.
        algorithm_names: c"DSA-SHA3-224:dsa_with_SHA3-224:id-dsa-with-sha3-224:2.16.840.1.101.3.4.3.5".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA3_224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA3_256`.
        algorithm_names: c"DSA-SHA3-256:dsa_with_SHA3-256:id-dsa-with-sha3-256:2.16.840.1.101.3.4.3.6".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA3_256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA3_384`.
        algorithm_names: c"DSA-SHA3-384:dsa_with_SHA3-384:id-dsa-with-sha3-384:2.16.840.1.101.3.4.3.7".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA3_384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_DSA_SHA3_512`.
        algorithm_names: c"DSA-SHA3-512:dsa_with_SHA3-512:id-dsa-with-sha3-512:2.16.840.1.101.3.4.3.8".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: DSA_SHA3_512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_HMAC`.
        algorithm_names: c"HMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_HMAC_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SIPHASH`.
        algorithm_names: c"SIPHASH".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_SIPHASH_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_POLY1305`.
        algorithm_names: c"POLY1305".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_POLY1305_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_CMAC`.
        algorithm_names: c"CMAC".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MAC_LEGACY_CMAC_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The table's shape: fifteen entries, the last the NULL terminator, and the two landed runs
    /// in the authority's order -- `DSA` first (`defltprov.c:417`) and `CMAC` last (`:484`).
    #[test]
    fn the_signature_table_is_the_authoritys_two_landed_runs_in_order() {
        assert_eq!(DEFLT_SIGNATURES.len(), 15);
        // SAFETY: the first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[0].algorithm_names) };
        assert_eq!(first.to_bytes(), b"DSA:dsaEncryption:1.2.840.10040.4.1");
        // SAFETY: the tenth row is initialised.
        let tenth = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[9].algorithm_names) };
        assert_eq!(
            tenth.to_bytes(),
            b"DSA-SHA3-512:dsa_with_SHA3-512:id-dsa-with-sha3-512:2.16.840.1.101.3.4.3.8"
        );
        // SAFETY: the eleventh row is initialised.
        let eleventh = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[10].algorithm_names) };
        assert_eq!(eleventh.to_bytes(), b"HMAC");
        // SAFETY: the fourteenth row is initialised.
        let last = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[13].algorithm_names) };
        assert_eq!(last.to_bytes(), b"CMAC");
        assert!(DEFLT_SIGNATURES[14].algorithm_names.is_null());
        assert!(DEFLT_SIGNATURES[14].property_definition.is_null());
        assert!(DEFLT_SIGNATURES[14].implementation.is_null());
    }
}
