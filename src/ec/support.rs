//! `crypto/evp/ec_support.c` — the EC curve-name tables, Phase 8.7.
//!
//! The file is one hundred and ninety lines and defines exactly four functions and two
//! tables: `OSSL_EC_curve_nid2name` and `ossl_ec_curve_name2nid` over a
//! `(name, nid)` list of the eighty-two built-in curves, and
//! `ossl_ec_curve_nid2nist_int` and `ossl_ec_curve_nist2nid_int` over the fifteen
//! NIST short names. `crypto/ec/ec_curve.c`'s `EC_curve_nid2nist` and `EC_curve_nist2nid`
//! are three-line wrappers around the last two, which is why the unit is transcribed here
//! rather than beside them: it is `crypto/evp/`'s, and D327's rule makes a unit whole.
//!
//! ## The two lookups are not the same comparison
//!
//! `ossl_ec_curve_name2nid` folds case through `OPENSSL_strcasecmp` — the ASCII-only,
//! sign-extending one, so `"SM2"` and `"sm2"` are one curve — and falls back to the
//! `nist_curves[]` table **first**, before its own list. `ossl_ec_curve_nist2nid_int` uses
//! plain `strcmp`, so `EC_curve_nist2nid("p-256")` is `NID_undef` while
//! `EC_curve_nist2nid("P-256")` is `NID_X9_62_prime256v1`. `RT-EC` observes both.
//!
//! ## The names are kept verbatim, including the one that is not lower case
//!
//! Seventy-eight of the eighty-two names are the lower-case short name of their NID, and
//! the last four are not: `Oakley-EC2N-3`, `Oakley-EC2N-4` and the three `brainpool*`
//! spellings with a capital `P`, and `SM2`. They are the authority's own strings and are
//! what `OSSL_EC_curve_nid2name` answers, so they are transcribed as written rather than
//! normalised to the NID's spelling.
//!
//! ## What a NULL argument does
//!
//! `ossl_ec_curve_nist2nid_int` passes `name` straight to `strcmp` and
//! `ossl_ec_curve_name2nid` guards with `name != NULL`, so a NULL is a fault in the first
//! and `NID_undef` in the second. That is the authority's behaviour and it is transcribed
//! rather than repaired; `RT-EC` calls neither with NULL, because a probe cannot compare a
//! crash.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};

use crate::runtime::obj;
use crate::runtime::str::OPENSSL_strcasecmp;

extern "C" {
    /// `int strcmp(const char *, const char *)`.
    fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
}

/// `static const EC_NAME2NID curve_list[]` — `crypto/evp/ec_support.c:22-115`.
///
/// The eighty-two built-in curves' names, in the authority's own order, which is the order
/// `ossl_ec_curve_name2nid`'s linear search walks and therefore the order that decides
/// which of two curves sharing a name would answer. `forensics/tools/gen_ec_curves.py`
/// checks every row and its position against the authority, in both of its tiers.
pub(crate) const CURVE_NAME_ROWS: [(&CStr, c_int); 82] = [
    (c"secp112r1", obj::NID_secp112r1),
    (c"secp112r2", obj::NID_secp112r2),
    (c"secp128r1", obj::NID_secp128r1),
    (c"secp128r2", obj::NID_secp128r2),
    (c"secp160k1", obj::NID_secp160k1),
    (c"secp160r1", obj::NID_secp160r1),
    (c"secp160r2", obj::NID_secp160r2),
    (c"secp192k1", obj::NID_secp192k1),
    (c"secp224k1", obj::NID_secp224k1),
    (c"secp224r1", obj::NID_secp224r1),
    (c"secp256k1", obj::NID_secp256k1),
    (c"secp384r1", obj::NID_secp384r1),
    (c"secp521r1", obj::NID_secp521r1),
    (c"prime192v1", obj::NID_X9_62_prime192v1),
    (c"prime192v2", obj::NID_X9_62_prime192v2),
    (c"prime192v3", obj::NID_X9_62_prime192v3),
    (c"prime239v1", obj::NID_X9_62_prime239v1),
    (c"prime239v2", obj::NID_X9_62_prime239v2),
    (c"prime239v3", obj::NID_X9_62_prime239v3),
    (c"prime256v1", obj::NID_X9_62_prime256v1),
    (c"sect113r1", obj::NID_sect113r1),
    (c"sect113r2", obj::NID_sect113r2),
    (c"sect131r1", obj::NID_sect131r1),
    (c"sect131r2", obj::NID_sect131r2),
    (c"sect163k1", obj::NID_sect163k1),
    (c"sect163r1", obj::NID_sect163r1),
    (c"sect163r2", obj::NID_sect163r2),
    (c"sect193r1", obj::NID_sect193r1),
    (c"sect193r2", obj::NID_sect193r2),
    (c"sect233k1", obj::NID_sect233k1),
    (c"sect233r1", obj::NID_sect233r1),
    (c"sect239k1", obj::NID_sect239k1),
    (c"sect283k1", obj::NID_sect283k1),
    (c"sect283r1", obj::NID_sect283r1),
    (c"sect409k1", obj::NID_sect409k1),
    (c"sect409r1", obj::NID_sect409r1),
    (c"sect571k1", obj::NID_sect571k1),
    (c"sect571r1", obj::NID_sect571r1),
    (c"c2pnb163v1", obj::NID_X9_62_c2pnb163v1),
    (c"c2pnb163v2", obj::NID_X9_62_c2pnb163v2),
    (c"c2pnb163v3", obj::NID_X9_62_c2pnb163v3),
    (c"c2pnb176v1", obj::NID_X9_62_c2pnb176v1),
    (c"c2tnb191v1", obj::NID_X9_62_c2tnb191v1),
    (c"c2tnb191v2", obj::NID_X9_62_c2tnb191v2),
    (c"c2tnb191v3", obj::NID_X9_62_c2tnb191v3),
    (c"c2pnb208w1", obj::NID_X9_62_c2pnb208w1),
    (c"c2tnb239v1", obj::NID_X9_62_c2tnb239v1),
    (c"c2tnb239v2", obj::NID_X9_62_c2tnb239v2),
    (c"c2tnb239v3", obj::NID_X9_62_c2tnb239v3),
    (c"c2pnb272w1", obj::NID_X9_62_c2pnb272w1),
    (c"c2pnb304w1", obj::NID_X9_62_c2pnb304w1),
    (c"c2tnb359v1", obj::NID_X9_62_c2tnb359v1),
    (c"c2pnb368w1", obj::NID_X9_62_c2pnb368w1),
    (c"c2tnb431r1", obj::NID_X9_62_c2tnb431r1),
    (c"wap-wsg-idm-ecid-wtls1", obj::NID_wap_wsg_idm_ecid_wtls1),
    (c"wap-wsg-idm-ecid-wtls3", obj::NID_wap_wsg_idm_ecid_wtls3),
    (c"wap-wsg-idm-ecid-wtls4", obj::NID_wap_wsg_idm_ecid_wtls4),
    (c"wap-wsg-idm-ecid-wtls5", obj::NID_wap_wsg_idm_ecid_wtls5),
    (c"wap-wsg-idm-ecid-wtls6", obj::NID_wap_wsg_idm_ecid_wtls6),
    (c"wap-wsg-idm-ecid-wtls7", obj::NID_wap_wsg_idm_ecid_wtls7),
    (c"wap-wsg-idm-ecid-wtls8", obj::NID_wap_wsg_idm_ecid_wtls8),
    (c"wap-wsg-idm-ecid-wtls9", obj::NID_wap_wsg_idm_ecid_wtls9),
    (c"wap-wsg-idm-ecid-wtls10", obj::NID_wap_wsg_idm_ecid_wtls10),
    (c"wap-wsg-idm-ecid-wtls11", obj::NID_wap_wsg_idm_ecid_wtls11),
    (c"wap-wsg-idm-ecid-wtls12", obj::NID_wap_wsg_idm_ecid_wtls12),
    (c"Oakley-EC2N-3", obj::NID_ipsec3),
    (c"Oakley-EC2N-4", obj::NID_ipsec4),
    (c"brainpoolP160r1", obj::NID_brainpoolP160r1),
    (c"brainpoolP160t1", obj::NID_brainpoolP160t1),
    (c"brainpoolP192r1", obj::NID_brainpoolP192r1),
    (c"brainpoolP192t1", obj::NID_brainpoolP192t1),
    (c"brainpoolP224r1", obj::NID_brainpoolP224r1),
    (c"brainpoolP224t1", obj::NID_brainpoolP224t1),
    (c"brainpoolP256r1", obj::NID_brainpoolP256r1),
    (c"brainpoolP256t1", obj::NID_brainpoolP256t1),
    (c"brainpoolP320r1", obj::NID_brainpoolP320r1),
    (c"brainpoolP320t1", obj::NID_brainpoolP320t1),
    (c"brainpoolP384r1", obj::NID_brainpoolP384r1),
    (c"brainpoolP384t1", obj::NID_brainpoolP384t1),
    (c"brainpoolP512r1", obj::NID_brainpoolP512r1),
    (c"brainpoolP512t1", obj::NID_brainpoolP512t1),
    (c"SM2", obj::NID_sm2),
];

/// `static const EC_NAME2NID nist_curves[]` — `crypto/evp/ec_support.c:152-168`.
///
/// Fifteen rows: the ten B/K binary curves and the five P- prime curves, each under the
/// NIST short name rather than its SECG one. The order is `B-`, then `K-`, then `P-`,
/// which is the order `ossl_ec_curve_nist2nid_int` searches and therefore the order that
/// decides which of two rows would answer a duplicate.
pub(crate) const NIST_CURVE_ROWS: [(&CStr, c_int); 15] = [
    (c"B-163", obj::NID_sect163r2),
    (c"B-233", obj::NID_sect233r1),
    (c"B-283", obj::NID_sect283r1),
    (c"B-409", obj::NID_sect409r1),
    (c"B-571", obj::NID_sect571r1),
    (c"K-163", obj::NID_sect163k1),
    (c"K-233", obj::NID_sect233k1),
    (c"K-283", obj::NID_sect283k1),
    (c"K-409", obj::NID_sect409k1),
    (c"K-571", obj::NID_sect571k1),
    (c"P-192", obj::NID_X9_62_prime192v1),
    (c"P-224", obj::NID_secp224r1),
    (c"P-256", obj::NID_X9_62_prime256v1),
    (c"P-384", obj::NID_secp384r1),
    (c"P-521", obj::NID_secp521r1),
];

/// `const char *OSSL_EC_curve_nid2name(int nid)` — `crypto/evp/ec_support.c:118-130`.
///
/// The lower-case (mostly — see the module documentation) short name of a built-in curve,
/// or NULL. A non-positive `nid` answers NULL without the walk, and a positive NID that is
/// not a curve answers NULL after it: this is a linear search over `curve_list[]`, so it
/// never consults the object table.
#[no_mangle]
pub extern "C" fn OSSL_EC_curve_nid2name(nid: c_int) -> *const c_char {
    if nid <= 0 {
        return core::ptr::null();
    }
    for (name, row) in CURVE_NAME_ROWS {
        if row == nid {
            return name.as_ptr();
        }
    }
    core::ptr::null()
}

/// `int ossl_ec_curve_name2nid(const char *name)` — `crypto/evp/ec_support.c:132-148`.
///
/// `nist_curves[]` **first**, then the case-insensitive walk of `curve_list[]`. The order
/// is load-bearing: `"P-256"` is in neither list under that spelling and `"p-256"` is in
/// the second, but `"B-163"` is in the first, so a version that walked the big list first
/// would answer `NID_undef` for it and a version that folded case in the first table would
/// answer for `"b-163"`, which the authority does not.
///
/// `#[allow(dead_code)]`'s reason: **its callers are the ASN.1 method objects and the
/// provider's parameter translation.** `crypto/evp/ctrl_params_translate.c` (slice E) and
/// `crypto/ec/ec_backend.c` are the only two, and neither unit is on this slice's path;
/// the two exports above reach [`ossl_ec_curve_nid2nist_int`] and
/// [`ossl_ec_curve_nist2nid_int`] instead.
///
/// # Safety
///
/// `name` is NULL or a NUL-terminated string. A NULL answers [`obj::NID_undef`] rather
/// than faulting, which is the authority's own `if (name != NULL)` guard.
#[allow(dead_code)] // read by `ec_backend.c` and the EVP parameter translation, neither in this crate yet
pub(crate) unsafe fn ossl_ec_curve_name2nid(name: *const c_char) -> c_int {
    if name.is_null() {
        return obj::NID_undef;
    }
    // SAFETY: `name` is a NUL-terminated string per this function's contract, and every
    // row's name is a `&'static CStr`, so both sides of every comparison are terminated.
    let nid = unsafe { ossl_ec_curve_nist2nid_int(name) };
    if nid != obj::NID_undef {
        return nid;
    }
    for (row, row_nid) in CURVE_NAME_ROWS {
        // SAFETY: as above.
        if unsafe { OPENSSL_strcasecmp(row.as_ptr(), name) } == 0 {
            return row_nid;
        }
    }
    obj::NID_undef
}

/// `const char *ossl_ec_curve_nid2nist_int(int nid)` — `crypto/evp/ec_support.c:170-178`.
///
/// The NIST short name for a NID, or NULL. Note the asymmetry with the read direction:
/// this walk has no `nid <= 0` guard, so it is a pure table lookup whose only answer for a
/// non-NIST NID is NULL.
pub(crate) fn ossl_ec_curve_nid2nist_int(nid: c_int) -> *const c_char {
    for (name, row) in NIST_CURVE_ROWS {
        if row == nid {
            return name.as_ptr();
        }
    }
    core::ptr::null()
}

/// `int ossl_ec_curve_nist2nid_int(const char *name)` — `crypto/evp/ec_support.c:180-188`.
///
/// A case-**sensitive** `strcmp`, which is the whole difference between this and
/// [`ossl_ec_curve_name2nid`]. `NID_undef` for any string not in the fifteen rows.
///
/// # Safety
///
/// `name` is a NUL-terminated string; a NULL faults inside `strcmp`, exactly as the
/// authority's does.
pub(crate) unsafe fn ossl_ec_curve_nist2nid_int(name: *const c_char) -> c_int {
    for (row, row_nid) in NIST_CURVE_ROWS {
        // SAFETY: `name` is NUL-terminated per this function's contract and the row's name
        // is a `&'static CStr`, so `strcmp` reads two terminated strings.
        if unsafe { strcmp(row.as_ptr(), name) } == 0 {
            return row_nid;
        }
    }
    obj::NID_undef
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_tables_are_the_authoritys_rows_in_order() {
        // The counts and the ends of each table, which is what a dropped or reordered row
        // moves. The generator checks every row against `ec_support.c`; these two are the
        // part a reader can check without the authority.
        assert_eq!(CURVE_NAME_ROWS.len(), 82);
        assert_eq!(NIST_CURVE_ROWS.len(), 15);
        assert_eq!(CURVE_NAME_ROWS[0], (c"secp112r1", obj::NID_secp112r1));
        assert_eq!(CURVE_NAME_ROWS[81], (c"SM2", obj::NID_sm2));
        assert_eq!(NIST_CURVE_ROWS[0], (c"B-163", obj::NID_sect163r2));
        assert_eq!(NIST_CURVE_ROWS[14], (c"P-521", obj::NID_secp521r1));
        // The last row is the one whose spelling is not its NID's: `SM2`, not `sm2`.
        let sm2 = OSSL_EC_curve_nid2name(obj::NID_sm2);
        assert!(!sm2.is_null());
        // SAFETY: non-null and NUL-terminated is what this function answers.
        assert_eq!(unsafe { CStr::from_ptr(sm2) }, c"SM2");
    }

    #[test]
    fn the_name_lookup_folds_case_and_the_nist_lookup_does_not() {
        // `ossl_ec_curve_name2nid` folds, through the NIST table first and then the big
        // one. Every argument below is a `&'static CStr`, so all of them are
        // NUL-terminated and live for the call.
        let fold = |name: &'static CStr| {
            // SAFETY: `name` is a `&'static CStr`, hence NUL-terminated.
            unsafe { ossl_ec_curve_name2nid(name.as_ptr()) }
        };
        let exact = |name: &'static CStr| {
            // SAFETY: `name` is a `&'static CStr`, hence NUL-terminated.
            unsafe { ossl_ec_curve_nist2nid_int(name.as_ptr()) }
        };
        assert_eq!(fold(c"P-256"), obj::NID_X9_62_prime256v1);
        assert_eq!(fold(c"B-163"), obj::NID_sect163r2);
        assert_eq!(fold(c"sm2"), obj::NID_sm2);
        assert_eq!(fold(c"SM2"), obj::NID_sm2);
        assert_eq!(fold(c"nonesuch"), obj::NID_undef);
        // SAFETY: a NULL is the one input this function's own guard accepts, and it is
        // documented to answer `NID_undef` for it rather than faulting.
        let null_name = unsafe { ossl_ec_curve_name2nid(core::ptr::null()) };
        assert_eq!(null_name, obj::NID_undef);
        // `ossl_ec_curve_nist2nid_int` is a plain `strcmp`, so only the exact spelling
        // answers.
        assert_eq!(exact(c"P-256"), obj::NID_X9_62_prime256v1);
        assert_eq!(exact(c"p-256"), obj::NID_undef);
        assert_eq!(exact(c"b-163"), obj::NID_undef);
        assert_eq!(exact(c""), obj::NID_undef);
        assert_eq!(exact(c"secp256k1"), obj::NID_undef);
    }

    #[test]
    fn the_nist_short_names_are_the_ten_binary_and_the_five_prime_curves() {
        for (name, nid) in NIST_CURVE_ROWS {
            let back = ossl_ec_curve_nid2nist_int(nid);
            assert!(!back.is_null(), "{name:?}");
            // SAFETY: the answer is one of this module's own `&'static CStr`s, and the
            // assert above rules the null out.
            assert_eq!(unsafe { CStr::from_ptr(back) }, name);
            // SAFETY: `back` points at a `&'static CStr`'s buffer, so it is
            // NUL-terminated.
            assert_eq!(unsafe { ossl_ec_curve_nist2nid_int(back) }, nid);
        }
        // Sixteen rows are not fifteen, and a sixteenth is not silently ignored.
        assert!(ossl_ec_curve_nid2nist_int(obj::NID_sm2).is_null());
        assert!(ossl_ec_curve_nid2nist_int(obj::NID_brainpoolP256r1).is_null());
        assert!(ossl_ec_curve_nid2nist_int(obj::NID_undef).is_null());
        assert!(ossl_ec_curve_nid2nist_int(-1).is_null());
    }
}
