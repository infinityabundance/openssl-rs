//! `crypto/x509/v3_crld.c` — the CRL distribution point surface. Phase 10.14.6, landed at
//! function granularity.
//!
//! `crypto/x509/v3_crld.c` is 724 lines. **One function and the type it needs land**; everything
//! else is withheld by name:
//!
//! * the [`DistPointName`] layout (`include/openssl/x509v3.h`'s `DIST_POINT_NAME_st`: an `int`
//!   discriminant, a two-pointer `union { GENERAL_NAMES *fullname; STACK_OF(X509_NAME_ENTRY)
//!   *relativename; }` and an `X509_NAME *dpname`), with the reported-size and offset asserts;
//! * `DIST_POINT_set_dpname` (`:526-552`), **an export** (`x509v3.h`, present in the admitted
//!   DSO), and one of the six names `ossl_x509v3_cache_extensions` (`v3_purp.c`) was measured to
//!   need: its `setup_dp` calls it to fold a `nameRelativeToCRLIssuer` fragment onto the issuer's
//!   name. Its closure is satisfied by landed names alone — `X509_NAME_dup`/`_free`/`_add_entry`
//!   and `i2d_X509_NAME` (`x_name.rs`, `x509name.rs`) and the `OPENSSL_sk_*` primitives.
//!
//! ## What is withheld, by name
//!
//! Every other container the unit's object defines is withheld, each with its blocker:
//!
//! * **the five extension tables** — `ossl_v3_crld` (`:26-35`), `ossl_v3_freshest_crl` (`:36-45`),
//!   `ossl_v3_idp` (`:360-370`), `ossl_v3_crl_invdate` (`:487-495`) and `ossl_v3_crl_hold`
//!   (`:496-504`) — plus `ossl_v3_aa_issuing_dist_point` (`:715-724`). Each is an unexported
//!   `ossl_v3_*` symbol the admitted DSO does not admit (`nm -D` shows none), and each names a
//!   callback that is itself withheld below. They are entries of `standard_exts[]` and are
//!   withheld behind [`crate::x509::v3_lib`]'s `X509V3_EXT_get_nid`, exactly as D456 records.
//! * the `DIST_POINT_NAME`/`DIST_POINT`/`CRL_DIST_POINTS`/`ISSUING_DIST_POINT`/
//!   `OSSL_AA_DIST_POINT` item groups and their generated `_new`/`_free`/`d2i_`/`i2d_` functions
//!   (`:323-353`, `:554-563`) — the `_new`/`_free` set is exported, but the item's own encoding
//!   path is reached only through the withheld tables and `DIST_POINT_set_dpname` does not need
//!   it, so it lands only when the dispatch does;
//! * the section/configuration callbacks — `gnames_from_sectname` (`:46-66`),
//!   `set_dist_point_name` (`:67-137`), `set_reasons` (`:151-185`), `print_reasons` (`:186-207`),
//!   `crldp_from_section` (`:208-241`), `v2i_crld` (`:242-305`), `v2i_idp` (`:371-419`),
//!   `i2r_idp` (`:436-459`), `i2r_crldp` (`:460-481`), `i2r_crl_invdate` (`:505-513`),
//!   `i2r_object` (`:515-523`), `print_distpoint` (`:420-435`), `aaidp_from_section` (`:570-610`),
//!   `v2i_aaidp` (`:611-663`), `i2r_aaidp` (`:664-714`) and `print_boolean` (`:565-569`) — reached
//!   only through the withheld tables, and several blocked on `X509V3_get_section`/
//!   `X509V3_section_free` (`v3_conf.c`), `v2i_GENERAL_NAME`/`GENERAL_NAME_print` (`v3_san.c`)
//!   and `OSSL_GENERAL_NAMES_print` (`v3_utl.c`, withheld by 10.14.3).
//!
//! Nothing is stubbed: the withheld containers are named rather than declared.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.14.6 arm builds a `DIST_POINT_NAME` with `type` 0 and 1 and calls
//! `DIST_POINT_set_dpname` over a fixed issuer `X509_NAME`, observing the 1/1 answers and the
//! `dpname` NULL/non-NULL distinction — the two branches its closure reaches. It pops the error
//! queue first (D455's lesson).
//!
//! ## No raise
//!
//! The unit's only reaches in this landing raise nothing, so `crypto/x509/v3_crld.c` is not
//! added to `gen_err_raise_sites.py`'s covered set (its one `ERR_raise` is in the withheld
//! `v2i_crld`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::c_int;
use core::ptr;

use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509name::X509_NAME_add_entry;
use crate::x509::x_name::{i2d_X509_NAME, X509Name, X509NameEntry, X509_NAME_dup, X509_NAME_free};

/// `struct DIST_POINT_NAME_st` — `DIST_POINT_NAME`, from `include/openssl/x509v3.h`.
///
/// The authority's `int type` and its two-arm union of pointers, flattened to one pointer (both
/// arms are the same size), then `X509_NAME *dpname`. `name` is read as
/// `relativename`/`fullname` according to `type`.
#[repr(C)]
pub struct DistPointName {
    /// `int type` — 0 for `fullname`, 1 for `relativename`.
    pub(crate) type_: c_int,
    /// The `union { GENERAL_NAMES *fullname; STACK_OF(X509_NAME_ENTRY) *relativename; }`.
    pub(crate) name: *mut OpenSslStack,
    /// `X509_NAME *dpname` — the cached full name when `type == 1`.
    pub(crate) dpname: *mut X509Name,
}

const _: () = {
    assert!(core::mem::size_of::<DistPointName>() == 24);
    assert!(core::mem::offset_of!(DistPointName, type_) == 0);
    assert!(core::mem::offset_of!(DistPointName, name) == 8);
    assert!(core::mem::offset_of!(DistPointName, dpname) == 16);
};

/// `int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname)` —
/// `crypto/x509/v3_crld.c:526-552`.
///
/// A NULL `dpn` or a `type != 1` (no `nameRelativeToCRLIssuer`) answers 1 and changes nothing.
/// Otherwise the cached `dpname` is replaced by a duplicate of `iname`, each `relativename`
/// entry is added to it (the first with `set = 1`, the rest with `set = 0`), and the name's
/// encoding is generated — a failure anywhere frees the partial `dpname`, NULLs it and answers 0.
///
/// # Safety
///
/// `dpn` must be NULL or a live `DIST_POINT_NAME`; when `type == 1` its `name.relativename` must
/// be NULL or a live stack of `X509_NAME_ENTRY`; `iname` must be a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn DIST_POINT_set_dpname(
    dpn: *mut DistPointName,
    iname: *const X509Name,
) -> c_int {
    // SAFETY: `dpn` is NULL or live per the contract.
    if dpn.is_null() || unsafe { (*dpn).type_ } != 1 {
        return 1;
    }
    // SAFETY: `dpn` is non-NULL and live; `type == 1` so `name` is a `relativename` stack.
    let frag = unsafe { (*dpn).name };
    // SAFETY: `dpname` is NULL or a live `X509_NAME` this item owns.
    unsafe { X509_NAME_free((*dpn).dpname) };
    // SAFETY: `iname` is live per the contract.
    let dup = unsafe { X509_NAME_dup(iname) };
    // SAFETY: `dpn` is writable per the contract.
    unsafe { (*dpn).dpname = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `frag` is NULL or a live stack; `OPENSSL_sk_num` accepts NULL.
    let n = unsafe { OPENSSL_sk_num(frag) };
    let mut i: c_int = 0;
    while i < n {
        // SAFETY: `0 <= i < n`, so `frag` is live and the slot holds an `X509_NAME_ENTRY`.
        let ne = unsafe { OPENSSL_sk_value(frag, i) }.cast::<X509NameEntry>();
        // SAFETY: `dpname` is live (just built) and `ne` is a live entry; the authority's
        // `i ? 0 : 1` is the `set` argument.
        if unsafe { X509_NAME_add_entry((*dpn).dpname, ne, -1, c_int::from(i == 0)) } == 0 {
            // SAFETY: `dpname` is a live name this call owns.
            unsafe {
                X509_NAME_free((*dpn).dpname);
                (*dpn).dpname = ptr::null_mut();
            }
            return 0;
        }
        i += 1;
    }
    // SAFETY: `dpname` is live; a NULL cursor asks for the encoded length.
    if unsafe { i2d_X509_NAME((*dpn).dpname, ptr::null_mut()) } >= 0 {
        return 1;
    }
    // SAFETY: `dpname` is a live name this call owns.
    unsafe {
        X509_NAME_free((*dpn).dpname);
        (*dpn).dpname = ptr::null_mut();
    }
    0
}
