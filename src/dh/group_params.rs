//! Phase 8 — `crypto/dh/dh_group_params.c`: the named-group unit.
//!
//! Six definitions: the static `dh_param_init`, the three internals
//! (`ossl_dh_new_by_nid_ex`, `ossl_dh_cache_named_group`, `ossl_dh_is_named_safe_prime_group`)
//! and the two exports (`DH_new_by_nid`, `DH_get_nid`). The unit is what turns a `uid`
//! into a `DH`, and a `DH` back into a `uid` — it is the *only* writer of
//! `params.nid`, and therefore the thing that makes `DH_get_nid` answer anything but
//! `NID_undef`.
//!
//! ## This is the unit D329, D330 and D331 each named as the follow-up
//!
//! D329 recorded the tables as "a separable large data transcription"; D330 took up the
//! same phrase for `crypto/bn/bn_dh.c`; D331 transcribed the three callers of
//! `DH_get_nid` as the `params.nid` field read they reduce to and said the day the
//! tables land the four sites "replace the reductions with no other change". This is
//! that day:
//!
//! * [`crate::dh::object`]'s `DH_set0_pqg` calls [`ossl_dh_cache_named_group`];
//! * [`crate::dh::key`]'s `generate_key` calls [`DH_get_nid`];
//! * [`crate::dh::check`]'s `DH_check` calls it;
//! * [`crate::dh::check`]'s `ossl_dh_check_priv_key` calls it.
//!
//! Each of those was a real read of `params.nid`, so each reduction was exact; what was
//! missing was a writer, and [`ossl_dh_cache_named_group`] is it.
//!
//! ## `params.nid` has two writers and they are both in this file's reach
//!
//! `dh_param_init` sets it from a group it was *given*; `ossl_dh_cache_named_group`
//! sets it from the numbers the object holds. `ossl_ffc_named_group_set` — the setter
//! `dh_param_init` calls — deliberately **clears** it, which is why the two statements
//! in `dh_param_init` are a sequence rather than a redundancy, and why the cache's own
//! first line is a flush of the field it is about to fill.
//!
//! ## `ossl_dh_is_named_safe_prime_group` is `id > 3`, and the 3 is a uid
//!
//! The RFC 5114 groups' uids are 1, 2 and 3 — the only rows in
//! `crypto/ffc/ffc_dh.c`'s table whose `uid` is not an NID — and their `q` is a proper
//! subgroup order rather than `(p - 1) / 2`. So the predicate is not "is it a named
//! group" but "is it a *safe-prime* named group", and the test is an inequality against
//! those three uids. `#[allow(dead_code)]`'s reason: **its one caller is the EVP
//! control translator** (`crypto/evp/ctrl_params_translate.c`), which is 8.5's slice E.
//!
//! ## The refusal is the authority's own reason
//!
//! `ossl_dh_new_by_nid_ex` raises `DH_R_INVALID_PARAMETER_NID` when the uid names no
//! row. This is the unit's one raise site and it is the *only* raise in the whole of
//! `dh_group_params.c`; D331 recorded that the coordinate stayed uncovered "with its
//! unit", and `gen_err_raise_sites.py`'s `COVERED_FILES` now names the file, so
//! `DH_GROUP_PARAMS_47` is in `err_sites::ALL` like every other landed coordinate.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::c_int;

use crate::ffc::dh::{
    ossl_ffc_named_group_get_keylength, ossl_ffc_named_group_get_q, ossl_ffc_named_group_get_uid,
    ossl_ffc_named_group_set, ossl_ffc_numbers_to_dh_named_group, ossl_ffc_uid_to_dh_named_group,
    DhNamedGroup,
};
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_undef;

use super::object::ossl_dh_new_ex;
use super::Dh;

/// `static DH *dh_param_init(OSSL_LIB_CTX *libctx, const DH_NAMED_GROUP *group)` —
/// `crypto/dh/dh_group_params.c:27-38`.
///
/// A fresh object with the group's numbers installed and `dirty_cnt` bumped. **The two
/// statements are ordered**: `ossl_ffc_named_group_set` flushes `params.nid` to
/// `NID_undef` on its way through, so the assignment that follows is what actually
/// caches the uid, and a reader who folded the two together would leave every named
/// group `DH_new_by_nid` builds answering `NID_undef` from `DH_get_nid`.
///
/// `ossl_dh_new_ex` answers NULL on an allocation failure, and the authority returns
/// that NULL without a reason raised — there is no `goto err` and no `ERR_raise` here.
///
/// # Safety
///
/// `libctx` is NULL or a live library context that outlives the object; `group` is a
/// pointer this crate's named-group table answered.
unsafe fn dh_param_init(libctx: *mut core::ffi::c_void, group: *const DhNamedGroup) -> *mut Dh {
    // SAFETY: `libctx` is NULL or live per this function's contract.
    let dh = unsafe { ossl_dh_new_ex(libctx) };
    if dh.is_null() {
        return core::ptr::null_mut();
    }

    // SAFETY: `dh` is this call's own object; `group` is a table row. The setter stores
    // the constants by pointer and flushes `params.nid`.
    unsafe {
        ossl_ffc_named_group_set(core::ptr::addr_of_mut!((*dh).params), group);
        (*dh).params.nid = ossl_ffc_named_group_get_uid(group);
        (*dh).dirty_cnt += 1;
    }
    dh
}

/// `DH *ossl_dh_new_by_nid_ex(OSSL_LIB_CTX *libctx, int nid)` —
/// `crypto/dh/dh_group_params.c:40-49`. Internal.
///
/// The lookup is [`ossl_ffc_uid_to_dh_named_group`]'s, so the argument is compared
/// against each row's `uid`: an NID for the eleven FFDHE and MODP groups, and the
/// integers 1, 2 and 3 for the three RFC 5114 ones. A miss raises
/// `DH_R_INVALID_PARAMETER_NID` and answers NULL, and the reason is the unit's only one.
///
/// # Safety
///
/// `libctx` is NULL or a live library context that outlives the object.
pub(crate) unsafe fn ossl_dh_new_by_nid_ex(libctx: *mut core::ffi::c_void, nid: c_int) -> *mut Dh {
    // SAFETY: the lookup takes no pointer.
    let group = unsafe { ossl_ffc_uid_to_dh_named_group(nid) };
    if !group.is_null() {
        // SAFETY: `libctx` and `group` are the caller's, and are this function's too.
        return unsafe { dh_param_init(libctx, group) };
    }

    // SAFETY: a compile-time-constant site.
    unsafe { raise_site(&err_sites::DH_GROUP_PARAMS_47) };
    core::ptr::null_mut()
}

/// `DH *DH_new_by_nid(int nid)` — `crypto/dh/dh_group_params.c:51-54`.
///
/// The library-context-less spelling, which is the whole of the export: the authority's
/// comment on the pair is that the `_ex` form exists for callers that have a context.
///
/// # Safety
///
/// Takes no pointer.
#[no_mangle]
pub unsafe extern "C" fn DH_new_by_nid(nid: c_int) -> *mut Dh {
    // SAFETY: a NULL library context is explicitly allowed.
    unsafe { ossl_dh_new_by_nid_ex(core::ptr::null_mut(), nid) }
}

/// `void ossl_dh_cache_named_group(DH *dh)` — `crypto/dh/dh_group_params.c:56-81`.
/// Internal.
///
/// The **writer** the four reductions were waiting for. Its body is three steps:
///
/// 1. flush `params.nid`, which happens even for an object it then refuses to touch, so
///    a `DH` whose numbers *stopped* matching a group stops claiming to be one;
/// 2. return without doing anything else if `p` or `g` is NULL — the two `BN_cmp`s
///    below need both, and `q` is deliberately not required;
/// 3. on a match, install the group's `q` **only if the object has none**, cache the
///    uid and the RFC 7919 key length, and bump `dirty_cnt`.
///
/// Step 3's condition is what makes this function a cache rather than an overwrite: a
/// caller who set their own `q` keeps it even when the `p` and `g` happen to name a
/// group, and `ossl_ffc_numbers_to_dh_named_group` was given that `q` so the match was
/// already refined by it.
///
/// # Safety
///
/// `dh` is NULL or a live object.
pub(crate) unsafe fn ossl_dh_cache_named_group(dh: *mut Dh) {
    if dh.is_null() {
        return;
    }

    // SAFETY: `dh` is live per the NULL test above.
    let (p, q, g) = unsafe {
        (*dh).params.nid = NID_undef; /* flush cached value */
        ((*dh).params.p, (*dh).params.q, (*dh).params.g)
    };

    /* Exit if p or g is not set */
    if p.is_null() || g.is_null() {
        return;
    }

    // SAFETY: `p` and `g` are non-NULL as established above and `q` is NULL or live,
    // which is the lookup's contract.
    let group = unsafe { ossl_ffc_numbers_to_dh_named_group(p, q, g) };
    if group.is_null() {
        return;
    }

    // SAFETY: `dh` is live; `group` is a table row. The `q` assignment is a store into
    // the object's own field, and the group's `q` carries `BN_FLG_STATIC_DATA`, so the
    // field may not be released — which is why `ossl_ffc_params_cleanup` checks the flag
    // before it frees anything.
    unsafe {
        if (*dh).params.q.is_null() {
            (*dh).params.q = ossl_ffc_named_group_get_q(group).cast_mut();
        }
        /* cache the nid and default key length */
        (*dh).params.nid = ossl_ffc_named_group_get_uid(group);
        (*dh).params.keylength = ossl_ffc_named_group_get_keylength(group);
        (*dh).dirty_cnt += 1;
    }
}

/// `int ossl_dh_is_named_safe_prime_group(const DH *dh)` —
/// `crypto/dh/dh_group_params.c:83-92`. Internal.
///
/// "Exclude RFC5114 groups (id = 1..3) since they do not have `q = (p - 1) / 2`" — the
/// authority's own comment, and the reason the test is `> 3` rather than "is a named
/// group". A group the object does not name answers `NID_undef` (0), which is also
/// `<= 3`, so an unnamed object takes the same arm as an RFC 5114 one. That is the
/// authority's behaviour.
///
/// `#[allow(dead_code)]`'s reason: **its one caller is the EVP control translator**
/// (`crypto/evp/ctrl_params_translate.c`), which is 8.5's slice E — `EVP_PKEY_CTX`'s
/// `DH_PARAMGEN_TYPE`/key-length translation, not the DH object layer.
///
/// # Safety
///
/// `dh` is a live object.
#[allow(dead_code)] // read by `ctrl_params_translate.c`, which is slice E
pub(crate) unsafe fn ossl_dh_is_named_safe_prime_group(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per this function's contract.
    let id = unsafe { DH_get_nid(dh) };

    /*
     * Exclude RFC5114 groups (id = 1..3) since they do not have
     * q = (p - 1) / 2
     */
    c_int::from(id > 3)
}

/// `int DH_get_nid(const DH *dh)` — `crypto/dh/dh_group_params.c:94-100`.
///
/// `dh->params.nid` behind a NULL test, and **`NID_undef` for a NULL object** rather
/// than a fault. That NULL answer is the same value an object that names no group
/// answers, which is what makes the two callers in [`crate::dh::check`] and the one in
/// [`crate::dh::key`] writable as a single comparison.
///
/// # Safety
///
/// `dh` is NULL or a live object.
#[no_mangle]
pub unsafe extern "C" fn DH_get_nid(dh: *const Dh) -> c_int {
    // SAFETY: NULL-or-live per this function's contract.
    match unsafe { dh.as_ref() } {
        None => NID_undef,
        Some(dh) => dh.params.nid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ffi::CStr;
    use core::ptr;

    use crate::bn::bignum::{BN_dup, BN_num_bits, BigNum};
    use crate::dh::object::{DH_free, DH_get0_pqg, DH_new, DH_set0_pqg};
    use crate::dh::OPENSSL_DH_MAX_MODULUS_BITS;
    use crate::runtime::err::err_sites::DH_GROUP_PARAMS_47;
    use crate::runtime::err::{ERR_clear_error, ERR_peek_error_all};
    use crate::runtime::obj::{NID_ffdhe2048, NID_ffdhe8192, NID_modp_8192};

    /// The three numbers an object's parameter block holds, as borrowed pointers.
    ///
    /// # Safety
    ///
    /// `dh` is a live object.
    unsafe fn pqg(dh: *const Dh) -> (*const BigNum, *const BigNum, *const BigNum) {
        let mut p: *const BigNum = ptr::null();
        let mut q: *const BigNum = ptr::null();
        let mut g: *const BigNum = ptr::null();
        // SAFETY: `dh` is live at every call site and each out-parameter is a local.
        unsafe { DH_get0_pqg(dh, &raw mut p, &raw mut q, &raw mut g) };
        (p, q, g)
    }

    /// A group's identity is visible through three surfaces at once: the nid
    /// `DH_get_nid` reads, the parameters `DH_get0_pqg` borrows, and the RFC 7919 key
    /// length the object caches for the key layer.
    #[test]
    fn new_by_nid_answers_the_group_and_get_nid_reads_it_back() {
        // SAFETY: the constructor takes no pointer.
        let dh = unsafe { DH_new_by_nid(NID_ffdhe2048) };
        assert!(!dh.is_null());
        // SAFETY: `dh` is this test's own object.
        unsafe {
            assert_eq!(DH_get_nid(dh), NID_ffdhe2048);
            assert_eq!((*dh).params.keylength, 225);
            /* `dh_init` bumps the counter once, and `dh_param_init` once more. */
            assert_eq!((*dh).dirty_cnt, 2, "the method's init and the cache");
            let (p, q, g) = pqg(dh);
            assert_eq!(BN_num_bits(p), 2048);
            assert_eq!(BN_num_bits(q), 2047);
            assert_eq!(BN_num_bits(g), 2, "the shared generator is the constant 2");
            DH_free(dh);
        }
    }

    /// **The pointer identity the shared constants buy.** Two objects built from one
    /// group hold one modulus, and releasing either leaves the other's intact — which
    /// is only true because the constants carry `BN_FLG_STATIC_DATA` and `BN_free`
    /// honours it. A crate that had modelled them as ordinary heap objects would
    /// double-free here rather than fail an assertion.
    #[test]
    fn two_objects_from_one_group_share_one_modulus() {
        // SAFETY: the constructors take no pointer.
        let (first, second) =
            unsafe { (DH_new_by_nid(NID_modp_8192), DH_new_by_nid(NID_modp_8192)) };
        assert!(!first.is_null() && !second.is_null());
        // SAFETY: both are this test's own objects.
        unsafe {
            let (p1, _, _) = pqg(first);
            let (p2, _, _) = pqg(second);
            assert_eq!(p1, p2, "one group is one set of constants");
            DH_free(first);
            assert_eq!(BN_num_bits(p2), 8192, "the constant outlived one `DH_free`");
            DH_free(second);
        }
    }

    /// The refusal is the authority's own reason at the authority's own coordinate, and
    /// a NULL object is not a refusal at all: `DH_get_nid(NULL)` answers `NID_undef`.
    #[test]
    fn an_unknown_uid_refuses_at_the_units_one_raise_site() {
        ERR_clear_error();
        // SAFETY: uid 4 names no row — the RFC 5114 uids are 1..3, and the FFDHE and
        // MODP uids are NIDs — and the constructor takes no pointer.
        let dh = unsafe { DH_new_by_nid(4) };
        assert!(dh.is_null());

        let mut file: *const core::ffi::c_char = ptr::null();
        let mut line: c_int = 0;
        let mut func: *const core::ffi::c_char = ptr::null();
        // SAFETY: each out-parameter is NULL or a live local, and `data`/`flags` are
        // explicitly NULL, which the reader accepts.
        let err = unsafe {
            ERR_peek_error_all(
                &raw mut file,
                &raw mut line,
                &raw mut func,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_ne!(err, 0, "the refusal left a record");
        assert_eq!(line, DH_GROUP_PARAMS_47.line, "the record's line");
        // SAFETY: both pointers are NUL-terminated and live.
        unsafe {
            assert_eq!(CStr::from_ptr(func), DH_GROUP_PARAMS_47.func);
            assert_eq!(CStr::from_ptr(file), DH_GROUP_PARAMS_47.file);
        }
        // SAFETY: the queue is this test's own state; the NULL object takes no pointer.
        unsafe {
            ERR_clear_error();
            assert_eq!(DH_get_nid(ptr::null()), NID_undef);
        }
    }

    /// The cache is a **cache**: it flushes first, fills on a match, installs the
    /// group's `q` only where the object has none, and leaves a caller's own `q` alone.
    ///
    /// The `q`-less arm is the one `DH_set0_pqg(dh, p, NULL, g)` reaches — the shape
    /// `RT-DH` builds its second party with — and it is the only path by which an
    /// object acquires a `q` it was not given.
    #[test]
    fn the_cache_flushes_finds_and_leaves_a_callers_q_alone() {
        // SAFETY: the constructor takes no pointer.
        let source = unsafe { DH_new_by_nid(NID_modp_8192) };
        assert!(!source.is_null());
        // SAFETY: `source` is this test's own object.
        let (p, q, g) = unsafe { pqg(source) };

        // SAFETY: `DH_new` takes no pointer; the three `BN_dup`s read live objects; the
        // `DH_set0_pqg` calls take ownership of the duplicates.
        let (with_q, without_q, mismatched) = unsafe {
            let copy = DH_new();
            let noq = DH_new();
            let bad = DH_new();
            assert!(!copy.is_null() && !noq.is_null() && !bad.is_null());
            assert_eq!(DH_set0_pqg(copy, BN_dup(p), BN_dup(q), BN_dup(g)), 1);
            assert_eq!(DH_set0_pqg(noq, BN_dup(p), ptr::null_mut(), BN_dup(g)), 1);
            /* The right `p` with the wrong `g`: no row, because the pair identifies. */
            assert_eq!(DH_set0_pqg(bad, BN_dup(p), BN_dup(q), BN_dup(p)), 1);
            (copy, noq, bad)
        };

        // SAFETY: all three are this test's own objects.
        unsafe {
            assert_eq!(
                DH_get_nid(with_q),
                NID_modp_8192,
                "p, q and g name the group"
            );
            assert_ne!(pqg(with_q).1, q, "the caller's own q is not replaced");

            assert_eq!(
                DH_get_nid(without_q),
                NID_modp_8192,
                "p and g name it alone"
            );
            assert_eq!(pqg(without_q).1, q, "and the group's q is installed");

            assert_eq!(DH_get_nid(mismatched), NID_undef, "the pair identifies");

            DH_free(with_q);
            DH_free(without_q);
            DH_free(mismatched);
            DH_free(source);
        }
    }

    /// A `DH` whose numbers stop naming a group stops claiming to: the cache's first
    /// act is to flush `params.nid`, and `DH_set0_pqg` is its only caller, so every
    /// parameter assignment runs the flush.
    #[test]
    fn the_cache_flushes_before_it_looks() {
        // SAFETY: the constructor takes no pointer.
        let dh = unsafe { DH_new_by_nid(NID_ffdhe2048) };
        assert!(!dh.is_null());
        // SAFETY: `dh` is this test's own object.
        unsafe {
            assert_eq!(DH_get_nid(dh), NID_ffdhe2048);
            /* Replace `g` with a value no row carries, keeping `p`. */
            let (p, _, _) = pqg(dh);
            assert_eq!(
                DH_set0_pqg(dh, ptr::null_mut(), ptr::null_mut(), BN_dup(p)),
                1
            );
            assert_eq!(DH_get_nid(dh), NID_undef, "the old claim was flushed");
            DH_free(dh);
        }
    }

    /// `ossl_dh_is_named_safe_prime_group` is `id > 3`, so an FFDHE group is one, an
    /// RFC 5114 group is not, and an object that names nothing is not either — because
    /// `NID_undef` is 0 and 0 is not greater than 3.
    #[test]
    fn the_safe_prime_predicate_excludes_the_three_rfc5114_uids() {
        // SAFETY: the constructors take no pointer.
        let (ffdhe, rfc, none) =
            unsafe { (DH_new_by_nid(NID_ffdhe2048), DH_new_by_nid(1), DH_new()) };
        assert!(!ffdhe.is_null() && !rfc.is_null() && !none.is_null());
        // SAFETY: all three are this test's own objects.
        unsafe {
            assert_eq!(DH_get_nid(rfc), 1, "uid 1 is the first RFC 5114 group");
            assert_ne!(ossl_dh_is_named_safe_prime_group(ffdhe), 0);
            assert_eq!(ossl_dh_is_named_safe_prime_group(rfc), 0);
            assert_eq!(ossl_dh_is_named_safe_prime_group(none), 0);
            DH_free(ffdhe);
            DH_free(rfc);
            DH_free(none);
        }
    }

    /// **The three RFC 5114 uids are 1, 2 and 3**, so `DH_new_by_nid(1)` — an integer no
    /// NID has — answers a group. That is the authority's own consequence of "the uid
    /// can be any unique identifier", and the reason a caller must not use a uid as an
    /// NID; `RT-DH` observes it rather than the crate inventing a guard.
    #[test]
    fn the_rfc5114_groups_are_reachable_by_their_small_uids() {
        for (uid, nbits_p, nbits_q) in [(1, 1024, 160), (2, 2048, 224), (3, 2048, 256)] {
            // SAFETY: the constructor takes no pointer.
            let dh = unsafe { DH_new_by_nid(uid) };
            assert!(!dh.is_null(), "uid {uid} names no group");
            // SAFETY: `dh` is this test's own object.
            unsafe {
                assert_eq!(DH_get_nid(dh), uid);
                let (p, q, g) = pqg(dh);
                assert_eq!(BN_num_bits(p), nbits_p);
                assert_eq!(BN_num_bits(q), nbits_q, "the subgroup order's width");
                assert_ne!(BN_num_bits(g), 2, "an RFC 5114 group has its own generator");
                assert_eq!((*dh).params.keylength, 0, "and no RFC 7919 key length");
                DH_free(dh);
            }
        }
    }

    /// Every row's modulus is within the key layer's own bound, which is what lets
    /// `DH_generate_key` run on a `DH_new_by_nid` object at all. A group above the bound
    /// would be constructible and unusable, and the table has no such row.
    #[test]
    fn every_rows_modulus_is_within_the_key_layers_bound() {
        for uid in [NID_ffdhe2048, NID_ffdhe8192, NID_modp_8192, 1, 2, 3] {
            // SAFETY: the constructor takes no pointer.
            let dh = unsafe { DH_new_by_nid(uid) };
            assert!(!dh.is_null(), "uid {uid} names no group");
            // SAFETY: `dh` is this test's own object.
            unsafe {
                assert!(BN_num_bits(pqg(dh).0) <= OPENSSL_DH_MAX_MODULUS_BITS);
                DH_free(dh);
            }
        }
    }

    /// A group never comes back with a flushed `nid`, which is the ordering
    /// `ossl_ffc_named_group_set`'s own flush makes load-bearing: the setter clears the
    /// field and `dh_param_init`'s next line is what restores it.
    #[test]
    fn a_group_never_comes_back_with_a_flushed_nid() {
        for uid in [NID_ffdhe2048, NID_modp_8192, 1] {
            // SAFETY: the constructor takes no pointer.
            let dh = unsafe { DH_new_by_nid(uid) };
            assert!(!dh.is_null());
            // SAFETY: `dh` is this test's own object.
            unsafe {
                assert_eq!((*dh).params.nid, uid, "the setter's flush was not undone");
                DH_free(dh);
            }
        }
    }
}
