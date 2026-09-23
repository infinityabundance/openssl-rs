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

/// `static const OSSL_ALGORITHM deflt_asym_kem[]` — `providers/defltprov.c:526-547`, **the rows
/// this module has landed**, in the authority's order. The `RSA` row is the authority's first, the
/// four `ML-KEM`/`mlx` groups are its last, and `EC` sits between — all unlanded. The two ECX rows
/// are the authority's second group.
pub(crate) static DEFLT_ASYM_KEM: [OsslAlgorithm; 3] = [
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
        algorithm_names: ptr::null(),
        property_definition: ptr::null(),
        implementation: ptr::null(),
        algorithm_description: ptr::null(),
    },
];
