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
//! `crypto/ml_dsa/`, which this crate does not have, so their transcription cannot close. The `SM2`
//! unit is absent for a reason that is a *measured* prerequisite rather than a size judgement, and
//! is named with its remaining callees:
//!
//!   * `sm2_sig.c.in` waits on `providers/common/der/der_sm2_sig.c`'s writer and
//!     `crypto/sm2/sm2_sign.c`'s three functions.
//!
//! The `DSA` unit opened the table (its two callees landed with it); the `RSA` unit is the second
//! (whose three callees — `der_rsa_sig.c`, `der_rsa_key.c`'s PSS writer and `securitycheck*.c` —
//! landed with it, D395); the `EdDSA` unit is the third (whose one callee is `der_ecx_key.c`'s
//! pair); the `ECDSA` unit is the fourth (whose one callee is `der_ec_sig.c`'s writer); the
//! legacy-MAC unit waits on none of them.
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
use crate::provider::ecdsa_sig::{
    ECDSA_SHA1_SIGNATURE_FUNCTIONS, ECDSA_SHA224_SIGNATURE_FUNCTIONS,
    ECDSA_SHA256_SIGNATURE_FUNCTIONS, ECDSA_SHA384_SIGNATURE_FUNCTIONS,
    ECDSA_SHA3_224_SIGNATURE_FUNCTIONS, ECDSA_SHA3_256_SIGNATURE_FUNCTIONS,
    ECDSA_SHA3_384_SIGNATURE_FUNCTIONS, ECDSA_SHA3_512_SIGNATURE_FUNCTIONS,
    ECDSA_SHA512_SIGNATURE_FUNCTIONS, ECDSA_SIGNATURE_FUNCTIONS,
};
use crate::provider::eddsa_sig::{
    ED25519CTX_SIGNATURE_FUNCTIONS, ED25519PH_SIGNATURE_FUNCTIONS, ED25519_SIGNATURE_FUNCTIONS,
    ED448PH_SIGNATURE_FUNCTIONS, ED448_SIGNATURE_FUNCTIONS,
};
use crate::provider::mac_legacy_sig::{
    MAC_LEGACY_CMAC_SIGNATURE_FUNCTIONS, MAC_LEGACY_HMAC_SIGNATURE_FUNCTIONS,
    MAC_LEGACY_POLY1305_SIGNATURE_FUNCTIONS, MAC_LEGACY_SIPHASH_SIGNATURE_FUNCTIONS,
};
use crate::provider::ml_dsa_sig::{
    ML_DSA_44_SIGNATURE_FUNCTIONS, ML_DSA_65_SIGNATURE_FUNCTIONS, ML_DSA_87_SIGNATURE_FUNCTIONS,
};
use crate::provider::rsa_sig::{
    RSA_RIPEMD160_SIGNATURE_FUNCTIONS, RSA_SHA1_SIGNATURE_FUNCTIONS,
    RSA_SHA224_SIGNATURE_FUNCTIONS, RSA_SHA256_SIGNATURE_FUNCTIONS, RSA_SHA384_SIGNATURE_FUNCTIONS,
    RSA_SHA3_224_SIGNATURE_FUNCTIONS, RSA_SHA3_256_SIGNATURE_FUNCTIONS,
    RSA_SHA3_384_SIGNATURE_FUNCTIONS, RSA_SHA3_512_SIGNATURE_FUNCTIONS,
    RSA_SHA512_224_SIGNATURE_FUNCTIONS, RSA_SHA512_256_SIGNATURE_FUNCTIONS,
    RSA_SHA512_SIGNATURE_FUNCTIONS, RSA_SIGNATURE_FUNCTIONS, RSA_SM3_SIGNATURE_FUNCTIONS,
};
use crate::provider::slh_dsa_sig::{
    SLH_DSA_SHA2_128F_SIGNATURE_FUNCTIONS, SLH_DSA_SHA2_128S_SIGNATURE_FUNCTIONS,
    SLH_DSA_SHA2_192F_SIGNATURE_FUNCTIONS, SLH_DSA_SHA2_192S_SIGNATURE_FUNCTIONS,
    SLH_DSA_SHA2_256F_SIGNATURE_FUNCTIONS, SLH_DSA_SHA2_256S_SIGNATURE_FUNCTIONS,
    SLH_DSA_SHAKE_128F_SIGNATURE_FUNCTIONS, SLH_DSA_SHAKE_128S_SIGNATURE_FUNCTIONS,
    SLH_DSA_SHAKE_192F_SIGNATURE_FUNCTIONS, SLH_DSA_SHAKE_192S_SIGNATURE_FUNCTIONS,
    SLH_DSA_SHAKE_256F_SIGNATURE_FUNCTIONS, SLH_DSA_SHAKE_256S_SIGNATURE_FUNCTIONS,
};
use crate::provider::sm2_sig::SM2_SIGNATURE_FUNCTIONS;

/// `static const OSSL_ALGORITHM deflt_signature[]` — `providers/defltprov.c:415-521`, **the rows
/// this module has landed**, in the authority's order.
///
/// Three units have landed. `dsa_sig.c.in` is the authority's first ten rows (`:417-426`), the
/// `DSA` row first and its nine `DSA-<MD>` sigalgs after it; the ten dispatch tables are
/// `src/provider/dsa_sig.rs`'s. The five `EdDSA` rows are the second landing (`:444-448`), whose
/// tables are `src/provider/eddsa_sig.rs`'s. The ten `ECDSA` rows are the third (`:455-464`), whose
/// tables are `src/provider/ecdsa_sig.rs`'s. The four legacy-MAC rows are the fourth: `HMAC`
/// (`:476`), `SIPHASH` (`:478-479`), `POLY1305` (`:481-482`) and `CMAC` (`:484`), whose tables are
/// `src/provider/mac_legacy_sig.rs`'s.
///
/// **The property definition is `"provider=default"` on every row** (`defltprov.c`'s three-field
/// initializer, D247). The rows between the runs — the fourteen `RSA` ones — are absent rather than
/// reordered until their unit lands: the census requires this table's rows to be a **subsequence**
/// of `deflt_signature[]` in the authority's order (D386). The three `ML-DSA` rows are the fifth
/// landing (D409), between `SM2` and the legacy MACs, which is `defltprov.c:469-472`'s position.
///
/// **`#[rustfmt::skip]` is load-bearing, not cosmetic.** `gen_provider_algorithms.py`'s row
/// reader anchors a row on `algorithm_names: c"…"` and `implementation: …as_ptr()` in one another's
/// neighbourhood; the longer `DSA-<MD>` alias sequences exceed the formatter's width, and a
/// rustfmt pass that moved the `c"…"` onto its own line would make the census read a table with
/// fewer rows than it has.
#[rustfmt::skip]
pub(crate) static DEFLT_SIGNATURES: [OsslAlgorithm; 60] = [
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
        // `PROV_NAMES_RSA` (`defltprov.c:428`).
        algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_RIPEMD160` (`defltprov.c:429`).
        algorithm_names: c"RSA-RIPEMD160:ripemd160WithRSA:1.3.36.3.3.1.2".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_RIPEMD160_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA1` (`defltprov.c:430`).
        algorithm_names: c"RSA-SHA1:RSA-SHA-1:sha1WithRSAEncryption:1.2.840.113549.1.1.5".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA1_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA224` (`defltprov.c:431`).
        algorithm_names: c"RSA-SHA2-224:RSA-SHA224:sha224WithRSAEncryption:1.2.840.113549.1.1.14".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA256` (`defltprov.c:432`).
        algorithm_names: c"RSA-SHA2-256:RSA-SHA256:sha256WithRSAEncryption:1.2.840.113549.1.1.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA384` (`defltprov.c:433`).
        algorithm_names: c"RSA-SHA2-384:RSA-SHA384:sha384WithRSAEncryption:1.2.840.113549.1.1.12".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA512` (`defltprov.c:434`).
        algorithm_names: c"RSA-SHA2-512:RSA-SHA512:sha512WithRSAEncryption:1.2.840.113549.1.1.13".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA512_224` (`defltprov.c:435`).
        algorithm_names: c"RSA-SHA2-512/224:RSA-SHA512-224:sha512-224WithRSAEncryption:1.2.840.113549.1.1.15".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA512_224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA512_256` (`defltprov.c:436`).
        algorithm_names: c"RSA-SHA2-512/256:RSA-SHA512-256:sha512-256WithRSAEncryption:1.2.840.113549.1.1.16".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA512_256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA3_224` (`defltprov.c:437`).
        algorithm_names: c"RSA-SHA3-224:id-rsassa-pkcs1-v1_5-with-sha3-224:2.16.840.1.101.3.4.3.13".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA3_224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA3_256` (`defltprov.c:438`).
        algorithm_names: c"RSA-SHA3-256:id-rsassa-pkcs1-v1_5-with-sha3-256:2.16.840.1.101.3.4.3.14".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA3_256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA3_384` (`defltprov.c:439`).
        algorithm_names: c"RSA-SHA3-384:id-rsassa-pkcs1-v1_5-with-sha3-384:2.16.840.1.101.3.4.3.15".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA3_384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SHA3_512` (`defltprov.c:440`).
        algorithm_names: c"RSA-SHA3-512:id-rsassa-pkcs1-v1_5-with-sha3-512:2.16.840.1.101.3.4.3.16".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SHA3_512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_RSA_SM3` (`defltprov.c:441`).
        algorithm_names: c"RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_SM3_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED25519`.
        algorithm_names: c"ED25519:1.3.101.112".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED25519_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED25519ph`.
        algorithm_names: c"ED25519ph".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED25519PH_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED25519ctx`.
        algorithm_names: c"ED25519ctx".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED25519CTX_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED448`.
        algorithm_names: c"ED448:1.3.101.113".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED448_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ED448ph`.
        algorithm_names: c"ED448ph".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ED448PH_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA`.
        algorithm_names: c"ECDSA".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA1`.
        algorithm_names: c"ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:1.2.840.10045.4.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA1_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA224`.
        algorithm_names: c"ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:1.2.840.10045.4.3.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA256`.
        algorithm_names: c"ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:1.2.840.10045.4.3.2".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA384`.
        algorithm_names: c"ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:1.2.840.10045.4.3.3".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA512`.
        algorithm_names: c"ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:1.2.840.10045.4.3.4".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA3_224`.
        algorithm_names: c"ECDSA-SHA3-224:ecdsa_with_SHA3-224:id-ecdsa-with-sha3-224:2.16.840.1.101.3.4.3.9".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA3_224_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA3_256`.
        algorithm_names: c"ECDSA-SHA3-256:ecdsa_with_SHA3-256:id-ecdsa-with-sha3-256:2.16.840.1.101.3.4.3.10".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA3_256_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA3_384`.
        algorithm_names: c"ECDSA-SHA3-384:ecdsa_with_SHA3-384:id-ecdsa-with-sha3-384:2.16.840.1.101.3.4.3.11".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA3_384_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ECDSA_SHA3_512`.
        algorithm_names: c"ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1.101.3.4.3.12".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECDSA_SHA3_512_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SM2` (`defltprov.c:460`), the authority's row after the ECDSA group.
        algorithm_names: c"SM2:1.2.156.10197.1.301".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SM2_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_DSA_44` (`defltprov.c:470`, `names.h:409`), the authority's row after
        // `SM2` and before the legacy MACs.
        algorithm_names: c"ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_DSA_44_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_DSA_65` (`defltprov.c:471`, `names.h:411`).
        algorithm_names: c"ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_DSA_65_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_DSA_87` (`defltprov.c:472`, `names.h:413`).
        algorithm_names: c"ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_DSA_87_SIGNATURE_FUNCTIONS.as_ptr().cast(),
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
        // `PROV_NAMES_SLH_DSA_SHA2_128S` — all three aliases are part of the row.
        algorithm_names: c"SLH-DSA-SHA2-128s:id-slh-dsa-sha2-128s:2.16.840.1.101.3.4.3.20".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_128S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHA2_128F`.
        algorithm_names: c"SLH-DSA-SHA2-128f:id-slh-dsa-sha2-128f:2.16.840.1.101.3.4.3.21".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_128F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHA2_192S`.
        algorithm_names: c"SLH-DSA-SHA2-192s:id-slh-dsa-sha2-192s:2.16.840.1.101.3.4.3.22".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_192S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHA2_192F`.
        algorithm_names: c"SLH-DSA-SHA2-192f:id-slh-dsa-sha2-192f:2.16.840.1.101.3.4.3.23".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_192F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHA2_256S`.
        algorithm_names: c"SLH-DSA-SHA2-256s:id-slh-dsa-sha2-256s:2.16.840.1.101.3.4.3.24".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_256S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHA2_256F`.
        algorithm_names: c"SLH-DSA-SHA2-256f:id-slh-dsa-sha2-256f:2.16.840.1.101.3.4.3.25".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHA2_256F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_128S`.
        algorithm_names: c"SLH-DSA-SHAKE-128s:id-slh-dsa-shake-128s:2.16.840.1.101.3.4.3.26".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_128S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_128F`.
        algorithm_names: c"SLH-DSA-SHAKE-128f:id-slh-dsa-shake-128f:2.16.840.1.101.3.4.3.27".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_128F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_192S`.
        algorithm_names: c"SLH-DSA-SHAKE-192s:id-slh-dsa-shake-192s:2.16.840.1.101.3.4.3.28".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_192S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_192F`.
        algorithm_names: c"SLH-DSA-SHAKE-192f:id-slh-dsa-shake-192f:2.16.840.1.101.3.4.3.29".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_192F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_256S`.
        algorithm_names: c"SLH-DSA-SHAKE-256s:id-slh-dsa-shake-256s:2.16.840.1.101.3.4.3.30".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_256S_SIGNATURE_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SLH_DSA_SHAKE_256F`.
        algorithm_names: c"SLH-DSA-SHAKE-256f:id-slh-dsa-shake-256f:2.16.840.1.101.3.4.3.31".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SLH_DSA_SHAKE_256F_SIGNATURE_FUNCTIONS.as_ptr().cast(),
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

    /// The table's shape: sixty entries, the last the NULL terminator, and the eight landed runs in
    /// the authority's order -- `DSA` first (`defltprov.c:417`), then the fourteen `RSA` rows
    /// (`:428-441`, D395), `EdDSA` (`:444`), `ECDSA` (`:455`), the one `SM2` row (`:460`, D406), the
    /// three `ML-DSA` rows (`:470-472`, D409), the legacy-MAC four (`:476-484`, D389) and the twelve
    /// `SLH-DSA` rows last (`:497-521`, D399).
    #[test]
    fn the_signature_table_is_the_authoritys_landed_runs_in_order() {
        assert_eq!(DEFLT_SIGNATURES.len(), 60);
        // SAFETY: the first row is initialised.
        let first = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[0].algorithm_names) };
        assert_eq!(first.to_bytes(), b"DSA:dsaEncryption:1.2.840.10040.4.1");
        // SAFETY: the tenth row is initialised -- the `DSA` run's last.
        let tenth = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[9].algorithm_names) };
        assert_eq!(
            tenth.to_bytes(),
            b"DSA-SHA3-512:dsa_with_SHA3-512:id-dsa-with-sha3-512:2.16.840.1.101.3.4.3.8"
        );
        // SAFETY: the eleventh row is initialised -- the `RSA` run's first.
        let eleventh = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[10].algorithm_names) };
        assert_eq!(
            eleventh.to_bytes(),
            b"RSA:rsaEncryption:1.2.840.113549.1.1.1"
        );
        // SAFETY: the twenty-fourth row is initialised -- the `RSA` run's last.
        let twenty_fourth =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[23].algorithm_names) };
        assert_eq!(
            twenty_fourth.to_bytes(),
            b"RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504"
        );
        // SAFETY: the twenty-fifth row is initialised -- the `EdDSA` run's first.
        let twenty_fifth =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[24].algorithm_names) };
        assert_eq!(twenty_fifth.to_bytes(), b"ED25519:1.3.101.112");
        // SAFETY: the twenty-ninth row is initialised -- the `EdDSA` run's last.
        let twenty_ninth =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[28].algorithm_names) };
        assert_eq!(twenty_ninth.to_bytes(), b"ED448ph");
        // SAFETY: the thirtieth row is initialised -- the `ECDSA` run's first.
        let thirtieth = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[29].algorithm_names) };
        assert_eq!(thirtieth.to_bytes(), b"ECDSA");
        // SAFETY: the thirty-ninth row is initialised -- the `ECDSA` run's last.
        let thirty_ninth =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[38].algorithm_names) };
        assert_eq!(
            thirty_ninth.to_bytes(),
            b"ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1.101.3.4.3.12"
        );
        // SAFETY: the fortieth row is initialised -- the `SM2` row (`defltprov.c:460`, D406).
        let sm2_row = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[39].algorithm_names) };
        assert_eq!(sm2_row.to_bytes(), b"SM2:1.2.156.10197.1.301");
        // SAFETY: the forty-first row is initialised -- the `ML-DSA` run's first (`:470`, D409).
        let mldsa_first =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[40].algorithm_names) };
        assert_eq!(
            mldsa_first.to_bytes(),
            b"ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44"
        );
        // SAFETY: the forty-second row is initialised -- the `ML-DSA` run's second.
        let mldsa_second =
            unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[41].algorithm_names) };
        assert_eq!(
            mldsa_second.to_bytes(),
            b"ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65"
        );
        // SAFETY: the forty-third row is initialised -- the `ML-DSA` run's last.
        let mldsa_last = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[42].algorithm_names) };
        assert_eq!(
            mldsa_last.to_bytes(),
            b"ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87"
        );
        // SAFETY: the forty-fourth row is initialised -- the legacy-MAC run's first.
        let hmac = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[43].algorithm_names) };
        assert_eq!(hmac.to_bytes(), b"HMAC");
        // SAFETY: the forty-seventh row is initialised -- the legacy-MAC run's last.
        let cmac = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[46].algorithm_names) };
        assert_eq!(cmac.to_bytes(), b"CMAC");
        // SAFETY: the forty-eighth row is initialised -- the `SLH-DSA` run's first.
        let slh_first = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[47].algorithm_names) };
        assert_eq!(
            slh_first.to_bytes(),
            b"SLH-DSA-SHA2-128s:id-slh-dsa-sha2-128s:2.16.840.1.101.3.4.3.20"
        );
        // SAFETY: the fifty-ninth row is initialised -- the `SLH-DSA` run's last.
        let slh_last = unsafe { core::ffi::CStr::from_ptr(DEFLT_SIGNATURES[58].algorithm_names) };
        assert_eq!(
            slh_last.to_bytes(),
            b"SLH-DSA-SHAKE-256f:id-slh-dsa-shake-256f:2.16.840.1.101.3.4.3.31"
        );
        assert!(DEFLT_SIGNATURES[59].algorithm_names.is_null());
        assert!(DEFLT_SIGNATURES[59].property_definition.is_null());
        assert!(DEFLT_SIGNATURES[59].implementation.is_null());
    }
}
