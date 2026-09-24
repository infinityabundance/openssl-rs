//! Phase 8.10 — the default provider's `OSSL_OP_KEM` rows.
//!
//! The authority publishes ten `deflt_asym_kem[]` rows on this profile; this module is where the
//! crate answers the two the ECX chain lands, and the operation's `deflt_query` arm joins
//! `OSSL_OP_KEYMGMT` and `OSSL_OP_KEYEXCH` here. The table exists as its own module rather than
//! beside the units because `deflt_query` reads it, and the census resolves an arm's table path to
//! the module that declares it (D246).
//!
//! The `X25519` and `X448` rows share `ossl_ecx_asym_kem_functions` — one dispatch table, two rows —
//! exactly as the authority's `defltprov.c:529-531` publishes them. The order is the authority's,
//! because the census requires the crate's rows to be a **subsequence** of `deflt_asym_kem[]`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ptr;

use crate::provider::activate::OsslAlgorithm;
use crate::provider::ecx_kem::ECX_ASYM_KEM_FUNCTIONS;
use crate::provider::ml_kem_kem::ML_KEM_ASYM_KEM_FUNCTIONS;
use crate::provider::mlx_kem::MLX_ASYM_KEM_FUNCTIONS;
use crate::provider::rsa_kem::RSA_ASYM_KEM_FUNCTIONS;

/// `static const OSSL_ALGORITHM deflt_asym_kem[]` — `providers/defltprov.c:526-549`, **the rows
/// this module has landed**, in the authority's order. The `RSA` row is the authority's first; the
/// `EC` row sits between the two ECX rows and the three ML-KEM rows and is unlanded; the four
/// `mlx` hybrid rows that follow the ML-KEM ones are the authority's last. The two ECX rows are
/// the authority's second group, the three ML-KEM rows its fourth, and the four hybrids its fifth.
///
/// **`#[rustfmt::skip]` is load-bearing, not cosmetic** (D392): `gen_provider_algorithms.py`'s row
/// reader anchors a row on `algorithm_names: c"…"` and `implementation: …as_ptr()` in one another's
/// neighbourhood, and the `RSA` alias sequence is long enough that a rustfmt pass could move the
/// `c"…"` onto its own line.
#[rustfmt::skip]
pub(crate) static DEFLT_ASYM_KEM: [OsslAlgorithm; 11] = [
    OsslAlgorithm {
        // `PROV_NAMES_RSA` (`defltprov.c:527`).
        algorithm_names: c"RSA:rsaEncryption:1.2.840.113549.1.1.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: RSA_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X25519`.
        algorithm_names: c"X25519:1.3.101.110".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_X448`.
        algorithm_names: c"X448:1.3.101.111".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ECX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_KEM_512` (`names.h:415`).
        algorithm_names: c"ML-KEM-512:MLKEM512:id-alg-ml-kem-512:2.16.840.1.101.3.4.4.1".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_KEM_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_KEM_768` (`names.h:417`).
        algorithm_names: c"ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_KEM_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        // `PROV_NAMES_ML_KEM_1024` (`names.h:419`).
        algorithm_names: c"ML-KEM-1024:MLKEM1024:id-alg-ml-kem-1024:2.16.840.1.101.3.4.4.3".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: ML_KEM_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    // The four `mlx` hybrid rows (`defltprov.c:539-546`), in the authority's order.
    OsslAlgorithm {
        algorithm_names: c"X25519MLKEM768".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MLX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"X448MLKEM1024".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MLX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SecP256r1MLKEM768".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MLX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: c"SecP384r1MLKEM1024".as_ptr(),
        property_definition: c"provider=default".as_ptr(),
        implementation: MLX_ASYM_KEM_FUNCTIONS.as_ptr().cast(),
        algorithm_description: ptr::null(),
    },
    OsslAlgorithm {
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
