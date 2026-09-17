//! Phase 7.4 — the `EVP_PKEY` object.
//!
//! `crypto/evp/p_lib.c`'s **provider half**: the object, its lifetime, and the two name/type
//! translations every other unit of this stratum reaches for. What is *not* here is the legacy
//! half, and it is not here for a reason that has to be stated rather than discovered — see the
//! section at the end.
//!
//! ## The object
//!
//! `struct evp_pkey_st` is three objects in one struct, and the authority says so: a **legacy
//! attribute** block (`ameth`, `engine`, `pmeth_engine`, and two unions holding a low-level key), a
//! **common** block (`references`, `lock`, attributes, `ex_data`), and a **provider** block
//! (`keymgmt`, `keydata`, the dirty counter, an operation cache, and a cache of four computed key
//! properties). An `EVP_PKEY` is exactly one of the first and third at a time; the comment the
//! authority writes on the provider pair — *"This is never used at the same time as the legacy key
//! data above"* — is the invariant every function in this unit is written against, and every one of
//! them branches on `keymgmt == NULL` rather than on a state flag.
//!
//! ## The two translations, and one deliberate gap
//!
//! `evp_pkey_name2type` answers the legacy NID for a key-type name, and `evp_pkey_type2name` the
//! other way round. Both begin with a **hard-coded table of twelve names** — the authority's own
//! comment calls it "pure hackery to get around the fact that names in
//! `crypto/objects/objects.txt` are a mess", because there is no `"EC"` object and `"RSA"` resolves
//! to a NID that has fallen out of favour. Only a name *outside* those twelve falls through to
//! `EVP_PKEY_type(OBJ_sn2nid(name))`.
//!
//! **That fallback is Phase 8's, and its absence is named here rather than hidden.** `EVP_PKEY_type`
//! is `crypto/evp/evp_pkey_type.c`'s and calls `EVP_PKEY_asn1_find`, which searches
//! `crypto/asn1/ameth_lib.c`'s `standard_methods[]` — a compile-time table of the twelve
//! `ossl_<alg>_asn1_meth` objects that `crypto/rsa/rsa_ameth.c` and its siblings define. Those
//! objects *are* Phase 8's, so the fallback cannot be written before that stratum lands, and neither
//! can `EVP_PKEY_type` itself. `docs/DECISIONS.md` D163 records the dependency and
//! `docs/PHASE-7-SUBPHASES.md` splits 7.4 accordingly.
//!
//! What that means concretely, and it is the strongest statement this file can make: **no exported
//! function in this crate can observe the gap yet.** `evp_pkey_name2type`'s callers are
//! `EVP_PKEY_is_a`'s legacy arm, `EVP_PKEY_type_names_do_all`'s legacy arm and `keymgmt_meth.c`'s
//! `legacy_alg` fill — and all three read it through a `pkey->ameth` path or through
//! `evp_keymgmt_get_legacy_alg`, which the legacy half owns. The moment Phase 8 lands the fallback
//! is the first thing that has to be filled. A **deferral row in `forensics/prerequisites.json` is
//! not the right record for it**, and that is worth writing down: the gate refuses a deferral whose
//! name the crate already defines (`stale_deferral`), and this name is defined here — partially and
//! by design. So the record is the decision entry, this section, and the site comment.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};

use crate::runtime::obj::{
    NID_X9_62_id_ecPublicKey, NID_dhKeyAgreement, NID_dhpublicnumber, NID_dsa, NID_rsaEncryption,
    NID_rsassaPss, NID_sm2, NID_undef, OBJ_ln2nid, OBJ_nid2sn, OBJ_sn2nid, NID_ED25519, NID_ED448,
    NID_X25519, NID_X448,
};

/// `EVP_PKEY_NONE` — `include/openssl/evp.h`, which spells it `NID_undef`.
#[allow(dead_code)] // read by `pkey_set_type` and `EVP_PKEY_get_id`, both of which 7.4a's next slice lands
pub(crate) const EVP_PKEY_NONE: c_int = NID_undef;
/// `EVP_PKEY_KEYMGMT` — **`-1`**, and the one pseudo-NID in the family that is not `-2`.
///
/// A provider-only key reports this from `EVP_PKEY_get_id` and its `keymgmt` from
/// `EVP_PKEY_get_base_id`, which is why the two are separate entry points rather than one.
#[allow(dead_code)] // read by `EVP_PKEY_get_id`'s provider arm, which 7.4a's next slice lands
pub(crate) const EVP_PKEY_KEYMGMT: c_int = -1;

/// `static const OSSL_ITEM standard_name2type[]`.
///
/// Twelve entries, and `EVP_PKEY_DHX` appears **twice** — under `"X9.42 DH"` and under `"DHX"`,
/// which is how the authority spells the second name. A transcription that deduplicated them would
/// answer `NID_undef` for one of the two spellings, and `evp_pkey_type2name` would answer the wrong
/// one of them: it returns the **first** entry whose id matches, so `EVPP_PKEY_DHX` answers
/// `"X9.42 DH"` and never `"DHX"`.
///
/// The strings are `&CStr` rather than `&str` because `evp_pkey_type2name` hands one of them to a
/// caller as a `const char *`, and the authority hands out its table's own storage.
#[allow(dead_code)] // the table itself is private to this file's two readers; the enum below is the public shape
pub(crate) const STANDARD_NAME2TYPE: [(c_int, &CStr); 12] = [
    (NID_rsaEncryption, c"RSA"),
    (NID_rsassaPss, c"RSA-PSS"),
    (NID_X9_62_id_ecPublicKey, c"EC"),
    (NID_ED25519, c"ED25519"),
    (NID_ED448, c"ED448"),
    (NID_X25519, c"X25519"),
    (NID_X448, c"X448"),
    (NID_sm2, c"SM2"),
    (NID_dhKeyAgreement, c"DH"),
    (NID_dhpublicnumber, c"X9.42 DH"),
    (NID_dhpublicnumber, c"DHX"),
    (NID_dsa, c"DSA"),
];

/// `int evp_pkey_name2type(const char *name)`.
///
/// The twelve-name table first, compared with **`OPENSSL_strcasecmp`** — so `"rsa"`, `"Rsa"` and
/// `"RSA"` are one name — and then the `EVP_PKEY_type` fallback, which is Phase 8's and is the one
/// line of this function that is not here. See the module documentation: nothing exported can
/// observe the gap, and the record for it is D163.
///
/// `name` is **not** guarded against NULL and the authority does not guard it either: the first
/// thing the body does is hand it to a comparison, so a NULL is the caller's fault on both sides.
///
/// # Safety
/// `name` must be a NUL-terminated C string.
#[allow(dead_code)] // no caller until `keymgmt_meth.c`'s `legacy_alg` fill lands, in this subphase
pub(crate) unsafe fn evp_pkey_name2type(name: *const c_char) -> c_int {
    // SAFETY: `name` is NUL-terminated per the contract.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    for (id, spelling) in STANDARD_NAME2TYPE {
        if bytes.eq_ignore_ascii_case(spelling.to_bytes()) {
            return id;
        }
    }
    /* Phase 8: `EVP_PKEY_type(OBJ_sn2nid(name))` and then `EVP_PKEY_type(OBJ_ln2nid(name))`. Both
     * are absent because `EVP_PKEY_type` seaches a table of method objects that stratum defines.
     * The two object lookups themselves are available, and they are named here so that the gap is
     * exactly three lines wide rather than a paragraph: a name that is neither one of the twelve
     * above nor a provider-published key type answers `NID_undef` today, and will answer a NID once
     * Phase 8 lands. */
    let _ = (OBJ_sn2nid, OBJ_ln2nid);
    NID_undef
}

/// `const char *evp_pkey_type2name(int type)`.
///
/// The inverse, and the same shape: the twelve names, then **`OBJ_nid2sn`**. Its fallback *is*
/// writable, because `OBJ_nid2sn` is the object table's and not the method table's — so this
/// function is complete, and the asymmetry between it and `evp_pkey_name2type` is a real property of
/// the two directions rather than an oversight.
#[allow(dead_code)] // no caller until `EVP_PKEY_get0_type_name` and `EVP_PKEY_get_base_id` land
pub(crate) fn evp_pkey_type2name(type_: c_int) -> *const c_char {
    for (id, spelling) in STANDARD_NAME2TYPE {
        if type_ == id {
            return spelling.as_ptr();
        }
    }
    OBJ_nid2sn(type_)
}

// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    /// The twelve names resolve, case-insensitively, and each answers its own NID.
    #[test]
    fn the_twelve_standard_names_resolve_case_insensitively() {
        // SAFETY: every argument is a NUL-terminated constant.
        unsafe {
            assert_eq!(evp_pkey_name2type(c"RSA".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"rsa".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"Rsa".as_ptr()), NID_rsaEncryption);
            assert_eq!(evp_pkey_name2type(c"RSA-PSS".as_ptr()), NID_rsassaPss);
            assert_eq!(evp_pkey_name2type(c"EC".as_ptr()), NID_X9_62_id_ecPublicKey);
            assert_eq!(evp_pkey_name2type(c"ED25519".as_ptr()), NID_ED25519);
            assert_eq!(evp_pkey_name2type(c"ED448".as_ptr()), NID_ED448);
            assert_eq!(evp_pkey_name2type(c"X25519".as_ptr()), NID_X25519);
            assert_eq!(evp_pkey_name2type(c"X448".as_ptr()), NID_X448);
            assert_eq!(evp_pkey_name2type(c"SM2".as_ptr()), NID_sm2);
            assert_eq!(evp_pkey_name2type(c"DH".as_ptr()), NID_dhKeyAgreement);
            assert_eq!(evp_pkey_name2type(c"DSA".as_ptr()), NID_dsa);
        }
    }

    /// `DHX` has **two** spellings and both answer the same NID — and `type2name` answers the
    /// *first* of them, which is the observation that makes the duplicate row load-bearing rather
    /// than untidy.
    #[test]
    fn the_dhx_nid_has_two_spellings_and_one_inverse() {
        // SAFETY: both arguments are NUL-terminated constants.
        unsafe {
            assert_eq!(evp_pkey_name2type(c"DHX".as_ptr()), NID_dhpublicnumber);
            assert_eq!(evp_pkey_name2type(c"X9.42 DH".as_ptr()), NID_dhpublicnumber);
        }
        assert_eq!(
            // SAFETY: the answer is a NUL-terminated constant of this crate.
            unsafe { CStr::from_ptr(evp_pkey_type2name(NID_dhpublicnumber)) },
            c"X9.42 DH",
            "the first matching row wins, so DHX answers the long spelling"
        );
    }

    /// The inverse answers the table's own spelling for a table NID and the object table's short
    /// name for anything else — the half of the pair that does not need Phase 8.
    #[test]
    fn the_inverse_answers_a_name_for_every_nid() {
        // SAFETY: the answers are NUL-terminated strings owned by this crate or the object table.
        unsafe {
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_ED25519)), c"ED25519");
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_X448)), c"X448");
            assert_eq!(
                CStr::from_ptr(evp_pkey_type2name(NID_rsassaPss)),
                c"RSA-PSS"
            );
            assert_eq!(CStr::from_ptr(evp_pkey_type2name(NID_undef)), c"UNDEF");
        }
    }

    /// The documented gap, asserted so that its size is a test rather than a claim: a name outside
    /// the twelve answers `NID_undef` today and will answer a NID once Phase 8 lands.
    #[test]
    fn a_name_outside_the_table_is_the_phase_8_gap() {
        // SAFETY: the argument is a NUL-terminated constant.
        let unknown = unsafe { evp_pkey_name2type(c"openssl-rs-not-a-key-type".as_ptr()) };
        assert_eq!(unknown, NID_undef);
    }
}
