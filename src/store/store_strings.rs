//! `crypto/store/store_strings.c` — the one `OSSL_STORE_INFO` type-name table. Phase 10 (10.5).
//!
//! The unit is 31 lines and one export, [`OSSL_STORE_INFO_type_string`], over a
//! six-element `static char *type_strings[]` indexed by the public `OSSL_STORE_INFO_*`
//! type number minus one. There is no closure to measure: the only callee is the array
//! itself, and the authority raises nothing here.
//!
//! The bounds test is `type < 1 || type > types`, so the number `0` and every negative
//! number answer NULL, and **the answer is a borrowed pointer into a static**, never an
//! allocation: a caller must not free it. That is what `RT-STORE`'s
//! `info.type_string.<n>` observations print for all six types and for the two refusal
//! arms (`0` and `7`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int, CStr};

/// `static char *type_strings[]` — `store_strings.c:14-21`.
///
/// Six entries, in the authority's order, which is the `OSSL_STORE_INFO_*` numbering
/// (`store.h:157-162`): NAME, PARAMS, PUBKEY, PKEY, CERT, CRL.
static TYPE_STRINGS: [&CStr; 6] = [
    c"Name",        // OSSL_STORE_INFO_NAME
    c"Parameters",  // OSSL_STORE_INFO_PARAMS
    c"Public key",  // OSSL_STORE_INFO_PUBKEY
    c"Pkey",        // OSSL_STORE_INFO_PKEY
    c"Certificate", // OSSL_STORE_INFO_CERT
    c"CRL",         // OSSL_STORE_INFO_CRL
];

/// `const char *OSSL_STORE_INFO_type_string(int type)` — `store_strings.c:23-31`.
///
/// Answers the borrowed name of `type_`, or NULL when `type_` is outside `1..=6`. The
/// authority reads `OSSL_NELEM(type_strings)`, which is the array's own length.
#[no_mangle]
pub extern "C" fn OSSL_STORE_INFO_type_string(type_: c_int) -> *const c_char {
    let types = TYPE_STRINGS.len() as c_int;

    if type_ < 1 || type_ > types {
        return core::ptr::null();
    }

    TYPE_STRINGS[(type_ - 1) as usize].as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::lock_global_state;

    /// Every public type number answers its own name, and the two refusal arms answer NULL.
    ///
    /// `lock_global_state` because the assertions read the process-global error queue's
    /// neighbours only incidentally — the function raises nothing — but the module is part
    /// of the store subsystem whose other tests do, and the policy in
    /// `docs/CONCURRENCY_MODEL.md` section 7 is that a test touching store state runs alone.
    #[test]
    fn type_string_answers_the_six_names_and_refuses_outside() {
        let _guard = lock_global_state();
        let names = [
            "Name",
            "Parameters",
            "Public key",
            "Pkey",
            "Certificate",
            "CRL",
        ];
        for (i, want) in names.iter().enumerate() {
            let got = OSSL_STORE_INFO_type_string(i as c_int + 1);
            assert!(!got.is_null());
            // SAFETY: the returned pointer is a NUL-terminated static string literal.
            let got = unsafe { core::ffi::CStr::from_ptr(got) };
            assert_eq!(got.to_bytes(), want.as_bytes());
        }
        assert!(OSSL_STORE_INFO_type_string(0).is_null());
        assert!(OSSL_STORE_INFO_type_string(7).is_null());
        assert!(OSSL_STORE_INFO_type_string(-1).is_null());
    }
}
