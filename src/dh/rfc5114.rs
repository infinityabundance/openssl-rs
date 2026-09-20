//! Phase 8 — `crypto/dh/dh_rfc5114.c`: the three deprecated RFC 5114 constructors.
//!
//! `DH_get_1024_160`, `DH_get_2048_224` and `DH_get_2048_256` are one macro expanded
//! three times (`make_dh`), and the macro's own comment gives the reason it does not
//! simply share the constants the way `ossl_ffc_named_group_set` does:
//!
//! > although just copying the BIGNUM static pointers would be more efficient, we can't
//! > do that because they get wiped using `BN_clear_free()` when `DH_free()` is called.
//!
//! That comment is why the three **duplicate** and `DH_new_by_nid`'s three do not: this
//! unit's objects own their numbers, and the named-group table's share the constants.
//! Both behaviours are the authority's, they are visible through `DH_get0_pqg`'s pointer
//! identity, and `RT-DH` compares the two.
//!
//! ## Two asymmetries a tidy rewrite would remove
//!
//! * **The assignment order is `p`, `g`, `q`** — not the declaration's `p`, `q`, `g`.
//!   Nothing observes it (the object is fresh and nothing between the three lines can
//!   fail in this crate), and it is transcribed rather than reordered because the order
//!   is the file's.
//! * **The three fields are assigned directly, not through
//!   `ossl_ffc_params_set0_pqg`.** So `dirty_cnt` is *not* bumped and `params.nid` is
//!   left at the `NID_undef` `ossl_ffc_params_init` set — which means
//!   `DH_get_nid(DH_get_1024_160())` answers `NID_undef` even though
//!   `DH_get_nid(DH_new_by_nid(1))` answers 1 for the same group. The unit test pins
//!   that asymmetry: it is the authority's, and a transcription that routed these three
//!   through the FFC setter would erase it.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::bn::bignum::{BN_dup, BigNum};
use crate::bn::dh::{
    ossl_bignum_dh1024_160_g, ossl_bignum_dh1024_160_p, ossl_bignum_dh1024_160_q,
    ossl_bignum_dh2048_224_g, ossl_bignum_dh2048_224_p, ossl_bignum_dh2048_224_q,
    ossl_bignum_dh2048_256_g, ossl_bignum_dh2048_256_p, ossl_bignum_dh2048_256_q,
};

use super::object::{DH_free, DH_new};
use super::Dh;

/// `static DH *make_dh(x)`'s body — `crypto/dh/dh_rfc5114.c:28-45`, the `make_dh` macro.
///
/// A fresh object holding **duplicates** of the three constants, in the authority's
/// `p`, `g`, `q` order. A null `DH_new` is answered as it is, without a reason raised;
/// a null duplicate releases the object and answers NULL.
///
/// # Safety
///
/// Takes no pointer.
unsafe fn make_dh(
    p_of: unsafe fn() -> *const BigNum,
    q_of: unsafe fn() -> *const BigNum,
    g_of: unsafe fn() -> *const BigNum,
) -> *mut Dh {
    // SAFETY: `DH_new` takes no pointer.
    let dh = unsafe { DH_new() };
    if dh.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `dh` is this call's own object; each accessor takes no pointer; each
    // `BN_dup` reads a shared constant and answers an owned copy, or NULL.
    unsafe {
        (*dh).params.p = BN_dup(p_of());
        (*dh).params.g = BN_dup(g_of());
        (*dh).params.q = BN_dup(q_of());
        if (*dh).params.p.is_null() || (*dh).params.q.is_null() || (*dh).params.g.is_null() {
            DH_free(dh);
            return core::ptr::null_mut();
        }
    }
    dh
}

/// `DH *DH_get_1024_160(void)` — `crypto/dh/dh_rfc5114.c:47`, `make_dh(1024_160)`.
///
/// RFC 5114 §2.1's 1024-bit group with its 160-bit subgroup order, and the one the
/// authority's own documentation marks deprecated: 1024 bits is below every bound this
/// crate enforces for key generation and for agreement, so the object is constructible
/// and unusable — exactly as the authority's is.
///
/// # Safety
///
/// Takes no pointer. The result is owned by the caller and released with `DH_free`.
#[no_mangle]
pub unsafe extern "C" fn DH_get_1024_160() -> *mut Dh {
    // SAFETY: every accessor takes no pointer.
    unsafe {
        make_dh(
            ossl_bignum_dh1024_160_p,
            ossl_bignum_dh1024_160_q,
            ossl_bignum_dh1024_160_g,
        )
    }
}

/// `DH *DH_get_2048_224(void)` — `crypto/dh/dh_rfc5114.c:48`, `make_dh(2048_224)`.
///
/// RFC 5114 §2.2. Its modulus is shared with `DH_get_2048_256`'s — the two groups differ
/// in the generator and in the subgroup order — and each call duplicates its own copy.
///
/// # Safety
///
/// As [`DH_get_1024_160`].
#[no_mangle]
pub unsafe extern "C" fn DH_get_2048_224() -> *mut Dh {
    // SAFETY: every accessor takes no pointer.
    unsafe {
        make_dh(
            ossl_bignum_dh2048_224_p,
            ossl_bignum_dh2048_224_q,
            ossl_bignum_dh2048_224_g,
        )
    }
}

/// `DH *DH_get_2048_256(void)` — `crypto/dh/dh_rfc5114.c:49`, `make_dh(2048_256)`.
///
/// RFC 5114 §2.3.
///
/// # Safety
///
/// As [`DH_get_1024_160`].
#[no_mangle]
pub unsafe extern "C" fn DH_get_2048_256() -> *mut Dh {
    // SAFETY: every accessor takes no pointer.
    unsafe {
        make_dh(
            ossl_bignum_dh2048_256_p,
            ossl_bignum_dh2048_256_q,
            ossl_bignum_dh2048_256_g,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ptr;

    use crate::bn::bignum::BN_num_bits;
    use crate::dh::group_params::{ossl_dh_cache_named_group, DH_get_nid, DH_new_by_nid};
    use crate::dh::object::{DH_get0_pqg, DH_set0_pqg};

    /// The width triple each constructor must answer, and the uid that names the same
    /// group in `dh_named_groups[]`.
    #[test]
    fn the_three_constructors_answer_their_groups_numbers() {
        for (make, uid, nbits_p, nbits_q) in [
            (
                DH_get_1024_160 as unsafe extern "C" fn() -> *mut Dh,
                1,
                1024,
                160,
            ),
            (
                DH_get_2048_224 as unsafe extern "C" fn() -> *mut Dh,
                2,
                2048,
                224,
            ),
            (
                DH_get_2048_256 as unsafe extern "C" fn() -> *mut Dh,
                3,
                2048,
                256,
            ),
        ] {
            // SAFETY: each constructor takes no pointer.
            let dh = unsafe { make() };
            assert!(!dh.is_null());
            // SAFETY: `dh` is this test's own object.
            let (p, q, g) = unsafe {
                let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
                DH_get0_pqg(dh, &raw mut p, &raw mut q, &raw mut g);
                (p, q, g)
            };
            // SAFETY: the three are live, borrowed from `dh`.
            unsafe {
                assert_eq!(BN_num_bits(p), nbits_p);
                assert_eq!(BN_num_bits(q), nbits_q);
                assert_ne!(BN_num_bits(g), 2, "an RFC 5114 group has its own generator");
            }
            // SAFETY: `dh` is this test's own; the lookup takes no pointer.
            let named = unsafe { DH_new_by_nid(uid) };
            assert!(!named.is_null());
            // SAFETY: `named` is this test's own object, and the row's three pointers are
            // the shared constants.
            unsafe {
                let group = crate::ffc::dh::ossl_ffc_uid_to_dh_named_group(uid);
                assert!(!group.is_null());
                let (np, nq, ng) = {
                    let (mut np, mut nq, mut ng) = (ptr::null(), ptr::null(), ptr::null());
                    DH_get0_pqg(named, &raw mut np, &raw mut nq, &raw mut ng);
                    (np, nq, ng)
                };
                /* The same group, but these three own their numbers and the table's
                 * three share the constants -- which is `make_dh`'s own comment. */
                assert_eq!(np, (*group).p, "`DH_new_by_nid` holds the shared constants");
                assert_eq!(nq, (*group).q);
                assert_eq!(ng, (*group).g);
                assert_ne!(np, p, "`make_dh` duplicates and the table shares");
                assert_ne!(nq, q);
                assert_ne!(ng, g);
                DH_free(named);
            }
            // SAFETY: `dh` is this test's own object.
            unsafe { DH_free(dh) };
        }
    }

    /// **The asymmetry between the two ways of building the same group.**
    ///
    /// `DH_new_by_nid(uid)` caches the uid through `dh_param_init`;
    /// `DH_get_*` assigns the three fields directly and never touches `params.nid`, so
    /// it answers `NID_undef`. This test is what stops a later reader from routing
    /// `make_dh` through `ossl_ffc_params_set0_pqg` "for consistency".
    #[test]
    fn the_deprecated_constructors_do_not_cache_a_nid() {
        // SAFETY: the constructors take no pointer.
        let (by_uid, by_get) = unsafe { (DH_new_by_nid(1), DH_get_1024_160()) };
        assert!(!by_uid.is_null() && !by_get.is_null());
        // SAFETY: both are this test's own objects.
        unsafe {
            assert_eq!(DH_get_nid(by_uid), 1);
            assert_eq!(DH_get_nid(by_get), crate::runtime::obj::NID_undef);
            /* And the cache will not invent one either: it fills `nid` only on a
             * `p`/`g` match, and the two share neither pointer nor a `q` that would
             * refine the search — but the *numbers* do match, so the cache does find the
             * row. That is the authority's behaviour: the deprecated path is
             * cache-less until something asks. */
            ossl_dh_cache_named_group(by_get);
            assert_eq!(DH_get_nid(by_get), 1, "the cache fills it on a match");
            DH_free(by_uid);
            DH_free(by_get);
        }
    }

    /// A second `DH_set0_pqg` over a deprecated constructor's object replaces the
    /// numbers and the outgoing duplicates are released, so the object is an ordinary
    /// one afterwards — which is what makes `DH_get_*`'s ownership claim real rather
    /// than a leak test's business.
    #[test]
    fn the_objects_hold_duplicates_that_a_later_set0_pqg_releases() {
        // SAFETY: the constructor takes no pointer.
        let dh = unsafe { DH_get_2048_256() };
        assert!(!dh.is_null());
        // SAFETY: `dh` is this test's own object.
        let (p, q, g) = unsafe {
            let (mut p, mut q, mut g) = (ptr::null(), ptr::null(), ptr::null());
            DH_get0_pqg(dh, &raw mut p, &raw mut q, &raw mut g);
            (p, q, g)
        };
        // SAFETY: `dh` is this test's own object and the three duplicates are replaced
        // by fresh ones, which releases the originals.
        unsafe {
            assert_eq!(DH_set0_pqg(dh, BN_dup(p), BN_dup(q), BN_dup(g)), 1);
            let (p2, _, _) = {
                let (mut p2, mut q2, mut g2) = (ptr::null(), ptr::null(), ptr::null());
                DH_get0_pqg(dh, &raw mut p2, &raw mut q2, &raw mut g2);
                (p2, q2, g2)
            };
            assert_ne!(p2, p, "the replacement is a new allocation");
            assert_eq!(BN_num_bits(p2), 2048);
            DH_free(dh);
        }
    }
}
