//! Phase 8.10 — `providers/implementations/kem/kem_util.c`: the KEM mode-name table.
//!
//! Thirty-three lines, one published function. It is transcribed because the **ECX KEM** unit
//! (`kem/ecx_kem.c`, landed in this pass) calls it from `ecxkem_set_ctx_params` (`:329`), and the
//! `EC` KEM unit (`kem/ec_kem.c`, still withheld) calls it from its twin (`:326`). The two units
//! share this one table, which is exactly why the authority gave the table a translation unit of
//! its own.
//!
//! The function is an authority **internal** — `prov/eckem.h` declares it and is not installed — so
//! it is a `pub(crate)` Rust function rather than a `#[no_mangle]` export, the same treatment
//! `ossl_eckem_modename2id`'s neighbour `ossl_hpke_labeled_extract` has.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

/// `KEM_MODE_UNDEFINED` — `providers/implementations/include/prov/eckem.h:10`.
pub(crate) const KEM_MODE_UNDEFINED: c_int = 0;
/// `KEM_MODE_DHKEM` — `prov/eckem.h:11`.
pub(crate) const KEM_MODE_DHKEM: c_int = 1;

/// `OSSL_KEM_PARAM_OPERATION_DHKEM` — `core_names.h:118`. Restated here rather than re-exported
/// from `crate::hpke`, which carries it privately, because this unit's table is the authority's.
const OSSL_KEM_PARAM_OPERATION_DHKEM: *const c_char = c"DHKEM".as_ptr();

/// `static const KEM_MODE eckem_modename_id_map[]` — `kem_util.c:19-22`. One entry plus the
/// sentinel, and the sentinel is the loop's own stop condition rather than a stored member.
const ECKEM_MODENAME_ID_MAP: [(c_int, *const c_char); 1] =
    [(KEM_MODE_DHKEM, OSSL_KEM_PARAM_OPERATION_DHKEM)];

/// `int ossl_eckem_modename2id(const char *name)` — `kem_util.c:25-39`.
///
/// A NULL `name` is `KEM_MODE_UNDEFINED` before the table is touched, which is why the guard is not
/// folded into the comparison. The comparison is `OPENSSL_strcasecmp`, the platform's
/// `strcasecmp` on this profile, exactly as `crate::hpke`'s synonym tables compare.
///
/// # Safety
/// `name` is NULL or NUL-terminated.
pub(crate) unsafe fn ossl_eckem_modename2id(name: *const c_char) -> c_int {
    if name.is_null() {
        return KEM_MODE_UNDEFINED;
    }

    for (id, mode) in ECKEM_MODENAME_ID_MAP.iter() {
        // SAFETY: `name` is NUL-terminated per the contract and `mode` is a `'static` literal.
        if unsafe { crate::runtime::str::OPENSSL_strcasecmp(name, *mode) } == 0 {
            return *id;
        }
    }
    KEM_MODE_UNDEFINED
}
