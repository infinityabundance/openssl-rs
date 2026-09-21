//! `crypto/rsa/rsa_mp_names.c` — the three fixed name tables the RSA multi-prime parameter
//! helpers walk, Phase 8.4.
//!
//! Seventy-six lines and **three data objects**, no function at all. The unit exists because
//! "it is easier to point to one of these fixed strings than have to dynamically add and
//! generate the names on the fly" — the file's own comment — and the tables are what
//! [`crate::rsa::backend::ossl_rsa_fromdata`] hands to `collect_numbers` when it reads a
//! multiprime key back out of an `OSSL_PARAM[]`, and what `ossl_rsa_todata` hands to
//! `ossl_param_build_set_multi_key_bn` when it writes one in.
//!
//! ## The three lengths, and why they are not all ten
//!
//! `ossl_rsa_mp_factor_names` and `ossl_rsa_mp_exp_names` carry ten entries each and
//! `ossl_rsa_mp_coeff_names` carries nine, because the first CRT coefficient is `iqmp` and the
//! remaining ones are numbered from **two** (`core_names.h:444-452` against `:459-479`). Each
//! table is terminated by a NULL — the `#ifndef FIPS_MODULE` guard around entries three upward
//! is *absent* from this profile's `configuration.h`, so all three tables are the wide form —
//! and the terminator is load-bearing rather than decorative: every reader of these names
//! iterates `for (i = 0; names[i] != NULL; i++)`.
//!
//! ## Why the tables are a wrapper type and not a bare array
//!
//! A Rust `static` of `[*const c_char; N]` does not compile: raw pointers are not `Sync`, and
//! the compiler is right to refuse — a `static` is process-wide shared state. The authority's
//! objects are `const char *[]` with **external** linkage and are never written, which is the
//! same fact stated in C's vocabulary. [`NameTable`] is `#[repr(transparent)]` over exactly
//! that array, so a table's address is the first string pointer's address and its size is
//! `N * sizeof(char *)`; the `Sync` assertion below is the "read-only after initialisation"
//! half of the authority's `const`.
//!
//! The three objects are **not** `#[no_mangle]`: nothing outside this crate can read them (the
//! version script's `local: *;` hides every non-export from the DSO), so making them global
//! archive symbols would only grow the collision surface
//! `forensics/atlas/implemented-surface.json` measures. D349's `ossl_x509_PUBKEY_get0_libctx`
//! is the precedent.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_char;

use crate::evp::pkey_ctx::{
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1, OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT3, OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT5, OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT7, OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT9, OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT10, OSSL_PKEY_PARAM_RSA_EXPONENT2, OSSL_PKEY_PARAM_RSA_EXPONENT3,
    OSSL_PKEY_PARAM_RSA_EXPONENT4, OSSL_PKEY_PARAM_RSA_EXPONENT5, OSSL_PKEY_PARAM_RSA_EXPONENT6,
    OSSL_PKEY_PARAM_RSA_EXPONENT7, OSSL_PKEY_PARAM_RSA_EXPONENT8, OSSL_PKEY_PARAM_RSA_EXPONENT9,
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR10, OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_FACTOR3, OSSL_PKEY_PARAM_RSA_FACTOR4, OSSL_PKEY_PARAM_RSA_FACTOR5,
    OSSL_PKEY_PARAM_RSA_FACTOR6, OSSL_PKEY_PARAM_RSA_FACTOR7, OSSL_PKEY_PARAM_RSA_FACTOR8,
    OSSL_PKEY_PARAM_RSA_FACTOR9,
};

/// A NULL-terminated array of parameter-name strings, laid out exactly as the authority's
/// `const char *names[]`.
///
/// `#[repr(transparent)]` so the array's own address is the wrapper's, which is what lets the
/// three tables below be passed as `*const *const c_char` without a second pointer.
#[repr(transparent)]
pub(crate) struct NameTable<const N: usize>(
    /// The name pointers, the last of which is NULL.
    pub [*const c_char; N],
);

// SAFETY: a `NameTable` is written once, as the initialiser of the `static` that holds it, and
// never mutated afterwards; every element is a pointer to a `'static` string literal and the
// final element is NULL. Sharing one therefore shares only immutable data. The authority's own
// objects are `const char *[]` and mutable in principle only because C has no way to say
// otherwise about an array of pointers.
unsafe impl<const N: usize> Sync for NameTable<N> {}

/// `const char *ossl_rsa_mp_factor_names[]` — `crypto/rsa/rsa_mp_names.c:23-37`.
///
/// "A fixed table of names for the RSA prime factors starting with P,Q and up to 8 additional
/// primes" — the file's comment, and the arithmetic is exact: `P` and `Q` plus eight gives ten
/// names, and the eight after the first two are inside `#ifndef FIPS_MODULE`, which this
/// profile compiles.
#[allow(non_upper_case_globals)] // the authority's own name, kept verbatim
pub(crate) static ossl_rsa_mp_factor_names: NameTable<11> = NameTable([
    OSSL_PKEY_PARAM_RSA_FACTOR1,
    OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_FACTOR3,
    OSSL_PKEY_PARAM_RSA_FACTOR4,
    OSSL_PKEY_PARAM_RSA_FACTOR5,
    OSSL_PKEY_PARAM_RSA_FACTOR6,
    OSSL_PKEY_PARAM_RSA_FACTOR7,
    OSSL_PKEY_PARAM_RSA_FACTOR8,
    OSSL_PKEY_PARAM_RSA_FACTOR9,
    OSSL_PKEY_PARAM_RSA_FACTOR10,
    core::ptr::null(),
]);

/// `const char *ossl_rsa_mp_exp_names[]` — `crypto/rsa/rsa_mp_names.c:43-57`.
///
/// "A fixed table of names for the RSA exponents starting with DP,DQ and up to 8 additional
/// exponents": `dmp1` and `dmq1` are `EXPONENT1` and `EXPONENT2`, and the eight after them are
/// the extra primes' exponents.
#[allow(non_upper_case_globals)] // the authority's own name, kept verbatim
pub(crate) static ossl_rsa_mp_exp_names: NameTable<11> = NameTable([
    OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,
    OSSL_PKEY_PARAM_RSA_EXPONENT3,
    OSSL_PKEY_PARAM_RSA_EXPONENT4,
    OSSL_PKEY_PARAM_RSA_EXPONENT5,
    OSSL_PKEY_PARAM_RSA_EXPONENT6,
    OSSL_PKEY_PARAM_RSA_EXPONENT7,
    OSSL_PKEY_PARAM_RSA_EXPONENT8,
    OSSL_PKEY_PARAM_RSA_EXPONENT9,
    OSSL_PKEY_PARAM_RSA_EXPONENT10,
    core::ptr::null(),
]);

/// `const char *ossl_rsa_mp_coeff_names[]` — `crypto/rsa/rsa_mp_names.c:63-76`.
///
/// Nine and not ten, and the file's own comment carries the miscount that makes the point:
/// "a fixed table of names for the RSA coefficients starting with QINV and up to 8 additional
/// exponents". `QINV` is `COEFFICIENT1` and the eight that follow it are numbered two through
/// nine, because the remaining coefficients are `t_i` for `i` from 2 and the first is not a
/// `t` at all.
#[allow(non_upper_case_globals)] // the authority's own name, kept verbatim
pub(crate) static ossl_rsa_mp_coeff_names: NameTable<10> = NameTable([
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT9,
    core::ptr::null(),
]);

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::CStr;

    /// The authority's own loop shape over one table: name it, and check it is the string the
    /// table's row claims to be.
    ///
    /// # Safety
    /// `table` is one of the three statics above: every element is a pointer to a `'static`
    /// NUL-terminated literal and the last is NULL.
    unsafe fn names<const N: usize>(table: &NameTable<N>) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < N {
            // SAFETY: `i` is within the array and each element points at a `'static` literal.
            let p = table.0[i];
            if p.is_null() {
                break;
            }
            // SAFETY: `p` is a `'static` NUL-terminated literal, per the caller's contract.
            out.push(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned());
            i += 1;
        }
        out
    }

    /// The three tables are the authority's names, in the authority's order, NULL-terminated —
    /// which is the only property a reader of them depends on. The `N` of each static is the
    /// `OSSL_NELEM` the authority's own array initialiser gives, and the last row is the NULL
    /// the loop above stops at.
    #[test]
    fn the_three_name_tables_are_the_authoritys() {
        // SAFETY: each table is one of this module's statics, so every element is a pointer to a
        // `'static` literal and the last is NULL -- `names`'s contract.
        let factors = unsafe { names(&ossl_rsa_mp_factor_names) };
        // SAFETY: as above, for the exponents table.
        let exps = unsafe { names(&ossl_rsa_mp_exp_names) };
        // SAFETY: as above, for the coefficients table.
        let coeffs = unsafe { names(&ossl_rsa_mp_coeff_names) };

        assert_eq!(
            factors,
            vec![
                "rsa-factor1",
                "rsa-factor2",
                "rsa-factor3",
                "rsa-factor4",
                "rsa-factor5",
                "rsa-factor6",
                "rsa-factor7",
                "rsa-factor8",
                "rsa-factor9",
                "rsa-factor10",
            ]
        );
        assert_eq!(
            exps,
            vec![
                "rsa-exponent1",
                "rsa-exponent2",
                "rsa-exponent3",
                "rsa-exponent4",
                "rsa-exponent5",
                "rsa-exponent6",
                "rsa-exponent7",
                "rsa-exponent8",
                "rsa-exponent9",
                "rsa-exponent10",
            ]
        );
        assert_eq!(
            coeffs,
            vec![
                "rsa-coefficient1",
                "rsa-coefficient2",
                "rsa-coefficient3",
                "rsa-coefficient4",
                "rsa-coefficient5",
                "rsa-coefficient6",
                "rsa-coefficient7",
                "rsa-coefficient8",
                "rsa-coefficient9",
            ]
        );
    }

    /// The terminator is the eleventh row of the first two tables and the tenth of the third,
    /// and that is the difference between a caller that stops and one that walks off the end.
    #[test]
    fn each_table_ends_with_the_null_terminator() {
        assert_eq!(ossl_rsa_mp_factor_names.0.len(), 11);
        assert_eq!(ossl_rsa_mp_exp_names.0.len(), 11);
        assert_eq!(ossl_rsa_mp_coeff_names.0.len(), 10);
        assert!(ossl_rsa_mp_factor_names.0[10].is_null());
        assert!(ossl_rsa_mp_exp_names.0[10].is_null());
        assert!(ossl_rsa_mp_coeff_names.0[9].is_null());
    }
}
