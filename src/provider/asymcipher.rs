//! Phase 8.4 — the default provider's `OSSL_OP_ASYM_CIPHER` row.
//!
//! The authority publishes two `deflt_asym_cipher[]` rows on this profile (`defltprov.c:518-524`):
//! `RSA` first, `SM2` second. This module is where the crate answers the first, and the operation's
//! `deflt_query` arm joins `OSSL_OP_SIGNATURE` and `OSSL_OP_KEM` in `src/provider/digest.rs`. The
//! table exists as its own module rather than beside the unit because `deflt_query` reads it, and the
//! census resolves an arm's table path to the module that declares it (D246).
//!
//! The `SM2` row is the authority's second (`defltprov.c:523`), and it lands with
//! `asymciphers/sm2_enc.c.in`'s unit (D406): the crate's rows are a **subsequence** of
//! `deflt_asym_cipher[]` in the authority's order (D386).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

use crate::provider::activate::OsslAlgorithm;
use crate::provider::rsa_enc::RSA_ASYM_CIPHER_FUNCTIONS;
use crate::provider::sm2_enc::SM2_ASYM_CIPHER_FUNCTIONS;

/// `static const OSSL_ALGORITHM deflt_asym_cipher[]` — `providers/defltprov.c:518-524`, **every
/// row this profile publishes**, in the authority's order: `RSA` then `SM2`.
///
/// **`#[rustfmt::skip]` is load-bearing, not cosmetic** (D392): `gen_provider_algorithms.py`'s row
/// reader anchors a row on `algorithm_names: c"…"` and `implementation: …as_ptr()` in one another's
/// neighbourhood, and the `RSA` alias sequence is long enough that a rustfmt pass could move the
/// `c"…"` onto its own line.
#[rustfmt::skip]
pub(crate) static DEFLT_ASYM_CIPHER: [OsslAlgorithm; 3] = [
    OsslAlgorithm {
        // `PROV_NAMES_RSA` (`defltprov.c:519`).
        algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_ASYM_CIPHER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_SM2` (`defltprov.c:523`), the authority's second row.
        algorithm_names: c"SM2:1.2.156.10197.1.301".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: SM2_ASYM_CIPHER_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
