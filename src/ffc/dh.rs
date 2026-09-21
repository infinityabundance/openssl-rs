//! Phase 8 — `crypto/ffc/ffc_dh.c`: the named-group table and its eight entry points.
//!
//! `dh_named_groups[]` — fourteen rows, each a name, a uid, a modulus size, an RFC 7919
//! key length and three `const BIGNUM`s — and the eight functions that read it: the
//! three lookups (by name, by uid, by the numbers themselves), the four accessors the DH
//! layer uses to learn what a group *is*, and the one setter that installs a group into
//! an `FFC_PARAMS`. D329 and D330 both named this file as the separable follow-up the
//! constants blocked; D331 named the four call sites that had been written as the
//! `params.nid` field read they reduce to, and this is where they become real calls.
//!
//! ## The table's rows are hand-transcribed; its constants are generated
//!
//! The fourteen rows' `name`, `uid`, `nbits` and `keylength` are read out of `ffc_dh.c`
//! and, unlike the constants, they are small enough for a reader to check against the
//! sources the file itself cites: 225, 275, 325, 375 and 400 are RFC 7919's own
//! private-key lengths for the five FFDHE groups, and its comment is why `MODP(8192,
//! 400)` shares FFDHE's 400. `forensics/atlas/bn-dh.json`'s `named_groups` records the
//! authority's own table — parsed from `ffc_dh.c` with its three macros expanded — beside
//! the generated constants, so a reader can compare the two without the authority. The
//! five *other* columns are not transcribed at all: the three `BIGNUM` pointers are
//! [`crate::bn::dh`]'s accessors, whose values `gen_bn_dh.py` read back from the
//! authority, and the unit test `the_table_is_the_authoritys_fourteen_rows_in_order`
//! asserts each row's `nbits` against the width of its own `p`.
//!
//! ## Why the table is built lazily where the authority's is `static const`
//!
//! `dh_named_groups[]` is `static const DH_NAMED_GROUP`, so in C its `&ossl_bignum_*`
//! members are link-time constants. This crate's `BIGNUM` owns a heap `Vec` and cannot
//! be placed in static storage at all, so those three pointers only exist once the
//! accessors have been called and the table is built **once**, on first use, and never
//! mutated afterwards. That is the contract a C `static const` array has by
//! construction, and [`Table`] asserts it so the compiler can accept the shared
//! reference.
//!
//! ## The four things a reader should not tidy away
//!
//! * **`ossl_ffc_numbers_to_dh_named_group` requires `p` and `g` and treats `q` as
//!   optional.** Its comment — "Keep searching until a matching p and g is found" — is
//!   the contract: the `q` term applies only when the caller has one, which is what lets
//!   `DH_set0_pqg(dh, p, NULL, g)` find its `nid` at all.
//! * **The three NULL answers differ.** `get_uid` answers `NID_undef`, `get_name` and
//!   `get_q` answer NULL, `get_keylength` answers 0 — and 0 is also the real key length
//!   of every RFC 5114 group, so a caller must not read it as "no group".
//! * **`ossl_ffc_named_group_set` flushes `ffc->nid`** with a comment handing the caching
//!   to the DH layer. The flush is what makes `ossl_dh_cache_named_group`'s own flush
//!   meaningful rather than redundant.
//! * **The rows carry `BN_FLG_STATIC_DATA`** and `set0_pqg` therefore stores them by
//!   pointer: two `DH` objects built from one group share one modulus, and releasing
//!   either does not release it. `RT-DH` observes both.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, CStr};
use std::sync::OnceLock;

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::BigNum;
use crate::bn::dh::{
    ossl_bignum_const_2, ossl_bignum_dh1024_160_g, ossl_bignum_dh1024_160_p,
    ossl_bignum_dh1024_160_q, ossl_bignum_dh2048_224_g, ossl_bignum_dh2048_224_p,
    ossl_bignum_dh2048_224_q, ossl_bignum_dh2048_256_g, ossl_bignum_dh2048_256_p,
    ossl_bignum_dh2048_256_q, ossl_bignum_ffdhe2048_p, ossl_bignum_ffdhe2048_q,
    ossl_bignum_ffdhe3072_p, ossl_bignum_ffdhe3072_q, ossl_bignum_ffdhe4096_p,
    ossl_bignum_ffdhe4096_q, ossl_bignum_ffdhe6144_p, ossl_bignum_ffdhe6144_q,
    ossl_bignum_ffdhe8192_p, ossl_bignum_ffdhe8192_q, ossl_bignum_modp_1536_p,
    ossl_bignum_modp_1536_q, ossl_bignum_modp_2048_p, ossl_bignum_modp_2048_q,
    ossl_bignum_modp_3072_p, ossl_bignum_modp_3072_q, ossl_bignum_modp_4096_p,
    ossl_bignum_modp_4096_q, ossl_bignum_modp_6144_p, ossl_bignum_modp_6144_q,
    ossl_bignum_modp_8192_p, ossl_bignum_modp_8192_q,
};
use crate::ffc::params::ossl_ffc_params_set0_pqg;
use crate::ffc::FfcParams;
use crate::runtime::obj;
use crate::runtime::str::OPENSSL_strcasecmp;

/// `SN_ffdhe2048` — `include/openssl/obj_mac.h:5822`.
///
/// The authority writes `dh_named_groups[]`'s `name` column with the `SN_*` macros, each
/// of which is `#define SN_ffdhe2048 "ffdhe2048"` — a *string literal*, so the macro is
/// modelled as the constant it expands to. The names are kept in the header's spelling
/// because they are what `ossl_ffc_name_to_dh_named_group` compares against and what a
/// caller reads back through the provider's name-keyed parameters.
#[allow(non_upper_case_globals)] // the authority's macro name, kept verbatim
const SN_ffdhe2048: &CStr = c"ffdhe2048";
/// `SN_ffdhe3072` — `include/openssl/obj_mac.h:5825`.
#[allow(non_upper_case_globals)]
const SN_ffdhe3072: &CStr = c"ffdhe3072";
/// `SN_ffdhe4096` — `include/openssl/obj_mac.h:5828`.
#[allow(non_upper_case_globals)]
const SN_ffdhe4096: &CStr = c"ffdhe4096";
/// `SN_ffdhe6144` — `include/openssl/obj_mac.h:5831`.
#[allow(non_upper_case_globals)]
const SN_ffdhe6144: &CStr = c"ffdhe6144";
/// `SN_ffdhe8192` — `include/openssl/obj_mac.h:5834`.
#[allow(non_upper_case_globals)]
const SN_ffdhe8192: &CStr = c"ffdhe8192";
/// `SN_modp_1536` — `include/openssl/obj_mac.h:5837`.
#[allow(non_upper_case_globals)]
const SN_modp_1536: &CStr = c"modp_1536";
/// `SN_modp_2048` — `include/openssl/obj_mac.h:5840`.
#[allow(non_upper_case_globals)]
const SN_modp_2048: &CStr = c"modp_2048";
/// `SN_modp_3072` — `include/openssl/obj_mac.h:5843`.
#[allow(non_upper_case_globals)]
const SN_modp_3072: &CStr = c"modp_3072";
/// `SN_modp_4096` — `include/openssl/obj_mac.h:5846`.
#[allow(non_upper_case_globals)]
const SN_modp_4096: &CStr = c"modp_4096";
/// `SN_modp_6144` — `include/openssl/obj_mac.h:5849`.
#[allow(non_upper_case_globals)]
const SN_modp_6144: &CStr = c"modp_6144";
/// `SN_modp_8192` — `include/openssl/obj_mac.h:5852`.
#[allow(non_upper_case_globals)]
const SN_modp_8192: &CStr = c"modp_8192";

/// The number of rows in `dh_named_groups[]`, which is `OSSL_NELEM`'s answer for the
/// authority's initialiser: five FFDHE, six MODP — including the `#ifndef FIPS_MODULE`
/// 1536 row, which this profile compiles — and three RFC 5114.
const NAMED_GROUP_COUNT: usize = 14;

/// `struct dh_named_group_st` — `crypto/ffc/ffc_dh.c:50-60`.
///
/// The authority's own shape, with its fields in its order: `name` and `uid` sit outside
/// the `#ifndef OPENSSL_NO_DH` guard and the five members after them are inside it and
/// are compiled on this profile. Nothing outside the unit reads a field by name —
/// `include/internal/ffc.h` declares `DH_NAMED_GROUP` opaque and every other unit reaches
/// it through the eight functions below — so this transcribes the file's own local
/// struct rather than a layout other code depends on.
#[repr(C)]
pub(crate) struct DhNamedGroup {
    /// `name` — the `SN_*` string, which is what the name lookup compares against.
    pub name: *const c_char,
    /// `uid` — an NID for the FFDHE and MODP families, and a small integer (1..3) for
    /// the RFC 5114 groups, which have no NID of their own.
    pub uid: c_int,
    /// `nbits` — the modulus size, an `int32_t`.
    pub nbits: i32,
    /// `keylength` — the RFC 7919 private-key length, or 0 for the RFC 5114 groups.
    pub keylength: c_int,
    /// `p` — the modulus, borrowed from [`crate::bn::dh`]'s shared constants.
    pub p: *const BigNum,
    /// `q` — `(p - 1) / 2` for the safe-prime families, the subgroup order otherwise.
    pub q: *const BigNum,
    /// `g` — the generator; `ossl_bignum_const_2` for the eleven safe-prime groups.
    pub g: *const BigNum,
}

/// The table, once built, behind the `Send`/`Sync` assertion a shared reference needs.
///
/// `OnceLock` requires `T: Send + Sync`, and [`DhNamedGroup`] holds raw pointers into
/// another module's constants. The invariant that makes the assertion true is the
/// table's own: it is written **once**, by `OnceLock`'s initialiser, before any reader
/// can observe it, and never mutated afterwards.
struct Table([DhNamedGroup; NAMED_GROUP_COUNT]);

// SAFETY: nothing in a `DhNamedGroup` is ever written after `OnceLock` publishes it; the
// three pointers are the addresses of process-lifetime constants and the three integers
// are plain values, so sending or sharing the table shares only immutable data.
unsafe impl Send for Table {}
// SAFETY: as the `Send` implementation above.
unsafe impl Sync for Table {}

/// `static const DH_NAMED_GROUP dh_named_groups[]` — `crypto/ffc/ffc_dh.c:67-90`.
///
/// Built once on first use, in the authority's own row order. The order is load-bearing
/// for [`ossl_ffc_numbers_to_dh_named_group`], which answers the **first** row whose `p`
/// and `g` match: the three RFC 5114 rows come last even though two of them share a
/// modulus with no FFDHE or MODP row, and `dh_2048_224`/`dh_2048_256` are separated by
/// the `g` the search compares.
fn named_groups() -> &'static [DhNamedGroup; NAMED_GROUP_COUNT] {
    static TABLE: OnceLock<Table> = OnceLock::new();
    &TABLE
        .get_or_init(|| {
            // SAFETY: every accessor takes no pointers and answers the shared constant
            // behind its own authority symbol.
            let entries = unsafe {
                [
                    DhNamedGroup {
                        name: SN_ffdhe2048.as_ptr(),
                        uid: obj::NID_ffdhe2048,
                        nbits: 2048,
                        keylength: 225,
                        p: ossl_bignum_ffdhe2048_p(),
                        q: ossl_bignum_ffdhe2048_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_ffdhe3072.as_ptr(),
                        uid: obj::NID_ffdhe3072,
                        nbits: 3072,
                        keylength: 275,
                        p: ossl_bignum_ffdhe3072_p(),
                        q: ossl_bignum_ffdhe3072_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_ffdhe4096.as_ptr(),
                        uid: obj::NID_ffdhe4096,
                        nbits: 4096,
                        keylength: 325,
                        p: ossl_bignum_ffdhe4096_p(),
                        q: ossl_bignum_ffdhe4096_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_ffdhe6144.as_ptr(),
                        uid: obj::NID_ffdhe6144,
                        nbits: 6144,
                        keylength: 375,
                        p: ossl_bignum_ffdhe6144_p(),
                        q: ossl_bignum_ffdhe6144_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_ffdhe8192.as_ptr(),
                        uid: obj::NID_ffdhe8192,
                        nbits: 8192,
                        keylength: 400,
                        p: ossl_bignum_ffdhe8192_p(),
                        q: ossl_bignum_ffdhe8192_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_1536.as_ptr(),
                        uid: obj::NID_modp_1536,
                        nbits: 1536,
                        keylength: 200,
                        p: ossl_bignum_modp_1536_p(),
                        q: ossl_bignum_modp_1536_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_2048.as_ptr(),
                        uid: obj::NID_modp_2048,
                        nbits: 2048,
                        keylength: 225,
                        p: ossl_bignum_modp_2048_p(),
                        q: ossl_bignum_modp_2048_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_3072.as_ptr(),
                        uid: obj::NID_modp_3072,
                        nbits: 3072,
                        keylength: 275,
                        p: ossl_bignum_modp_3072_p(),
                        q: ossl_bignum_modp_3072_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_4096.as_ptr(),
                        uid: obj::NID_modp_4096,
                        nbits: 4096,
                        keylength: 325,
                        p: ossl_bignum_modp_4096_p(),
                        q: ossl_bignum_modp_4096_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_6144.as_ptr(),
                        uid: obj::NID_modp_6144,
                        nbits: 6144,
                        keylength: 375,
                        p: ossl_bignum_modp_6144_p(),
                        q: ossl_bignum_modp_6144_q(),
                        g: ossl_bignum_const_2(),
                    },
                    DhNamedGroup {
                        name: SN_modp_8192.as_ptr(),
                        uid: obj::NID_modp_8192,
                        nbits: 8192,
                        keylength: 400,
                        p: ossl_bignum_modp_8192_p(),
                        q: ossl_bignum_modp_8192_q(),
                        g: ossl_bignum_const_2(),
                    },
                    /* Additional dh named groups from RFC 5114 that have a different g.
                     * The uid can be any unique identifier. */
                    DhNamedGroup {
                        name: c"dh_1024_160".as_ptr(),
                        uid: 1,
                        nbits: 1024,
                        keylength: 0,
                        p: ossl_bignum_dh1024_160_p(),
                        q: ossl_bignum_dh1024_160_q(),
                        g: ossl_bignum_dh1024_160_g(),
                    },
                    DhNamedGroup {
                        name: c"dh_2048_224".as_ptr(),
                        uid: 2,
                        nbits: 2048,
                        keylength: 0,
                        p: ossl_bignum_dh2048_224_p(),
                        q: ossl_bignum_dh2048_224_q(),
                        g: ossl_bignum_dh2048_224_g(),
                    },
                    DhNamedGroup {
                        name: c"dh_2048_256".as_ptr(),
                        uid: 3,
                        nbits: 2048,
                        keylength: 0,
                        p: ossl_bignum_dh2048_256_p(),
                        q: ossl_bignum_dh2048_256_q(),
                        g: ossl_bignum_dh2048_256_g(),
                    },
                ]
            };
            Table(entries)
        })
        .0
}

/// `const DH_NAMED_GROUP *ossl_ffc_name_to_dh_named_group(const char *name)` —
/// `crypto/ffc/ffc_dh.c:92-101`.
///
/// A case-insensitive linear search, so `"FFDHE2048"` and `"ffdhe2048"` are one group —
/// `OPENSSL_strcasecmp`'s contract, and the reason the lookup is not `OPENSSL_strcmp`.
///
/// `#[allow(dead_code)]`'s reason: **its two callers are the provider half of this
/// layer.** `crypto/ffc/ffc_backend.c:38` (the `FFC_PARAMS` importer) and
/// `providers/implementations/keymgmt/dh_kmgmt.c:556` (the `group` parameter of a
/// keymgmt import) are the only places an authority *name* becomes a group, and neither
/// unit is on `dh_lib.c`/`dh_key.c`/`dh_check.c`'s path. Nothing else in the authority
/// calls it: `DH_new_by_nid` goes through the uid.
///
/// # Safety
///
/// `name` is NULL or a NUL-terminated string; a NULL faults, exactly as the authority's
/// `OPENSSL_strcasecmp` would.
#[allow(dead_code)] // read by `ffc_backend.c` and the DH keymgmt, neither in this crate yet
pub(crate) unsafe fn ossl_ffc_name_to_dh_named_group(name: *const c_char) -> *const DhNamedGroup {
    for group in named_groups() {
        // SAFETY: `group.name` is one of the table's own `SN_*` literals, and `name` is
        // a NUL-terminated string per this function's contract; the comparison reads
        // both until a NUL.
        if unsafe { OPENSSL_strcasecmp(group.name, name) } == 0 {
            return group;
        }
    }
    core::ptr::null()
}

/// `const DH_NAMED_GROUP *ossl_ffc_uid_to_dh_named_group(int uid)` —
/// `crypto/ffc/ffc_dh.c:103-112`.
///
/// This is the whole of `DH_new_by_nid`'s lookup: the integer a caller passes reaches
/// `group->uid` here, which is why `DH_new_by_nid(1)`, `(2)` and `(3)` answer the three
/// RFC 5114 groups — their uids are 1, 2 and 3, because the file's own comment says a
/// uid "can be any unique identifier". That is the authority's behaviour and not a
/// defect introduced here; `RT-DH` observes it rather than asserting it away.
///
/// # Safety
///
/// Takes no pointer.
pub(crate) unsafe fn ossl_ffc_uid_to_dh_named_group(uid: c_int) -> *const DhNamedGroup {
    for group in named_groups() {
        if group.uid == uid {
            return group;
        }
    }
    core::ptr::null()
}

/// `const DH_NAMED_GROUP *ossl_ffc_numbers_to_dh_named_group(const BIGNUM *p,`
/// `const BIGNUM *q, const BIGNUM *g)` — `crypto/ffc/ffc_dh.c:115-130`.
///
/// The pair that identifies a group is **`p` and `g`**, not `p` alone: RFC 5114's
/// `dh_2048_224` and `dh_2048_256` share a modulus and differ in the generator, and all
/// eleven safe-prime groups use `g = 2` with different moduli. `q` is a *refinement*
/// applied only when the caller has one, which is what lets a `DH` built with
/// `DH_set0_pqg(dh, p, NULL, g)` find its `nid`.
///
/// # Safety
///
/// `p` and `g` are live `BIGNUM`s; `q` is NULL or live.
pub(crate) unsafe fn ossl_ffc_numbers_to_dh_named_group(
    p: *const BigNum,
    q: *const BigNum,
    g: *const BigNum,
) -> *const DhNamedGroup {
    for group in named_groups() {
        /* Keep searching until a matching p and g is found */
        // SAFETY: `p` is live per this function's contract, and the table's `p` is a
        // shared constant.
        let p_matches = unsafe { BN_cmp(p, group.p) } == 0;
        // SAFETY: `g` is live per this function's contract, and the table's `g` is a
        // shared constant.
        let g_matches = unsafe { BN_cmp(g, group.g) } == 0;
        if !p_matches || !g_matches {
            continue;
        }
        /* Verify q is correct if it exists */
        if q.is_null() {
            return group;
        }
        // SAFETY: `q` is non-NULL and live per this function's contract, and the table's
        // `q` is a shared constant.
        if unsafe { BN_cmp(q, group.q) } == 0 {
            return group;
        }
    }
    core::ptr::null()
}

/// `int ossl_ffc_named_group_get_uid(const DH_NAMED_GROUP *group)` —
/// `crypto/ffc/ffc_dh.c:133-138`.
///
/// A NULL group answers `NID_undef` rather than 0 by accident: no real group has uid 0,
/// which is what makes the answer usable as a "no group" sentinel — the class the RFC
/// 5114 rows' uids 1..3 deliberately stay out of.
///
/// # Safety
///
/// `group` is NULL or a pointer this unit answered.
pub(crate) unsafe fn ossl_ffc_named_group_get_uid(group: *const DhNamedGroup) -> c_int {
    // SAFETY: NULL-or-live per this function's contract.
    match unsafe { group.as_ref() } {
        None => obj::NID_undef,
        Some(group) => group.uid,
    }
}

/// `const char *ossl_ffc_named_group_get_name(const DH_NAMED_GROUP *group)` —
/// `crypto/ffc/ffc_dh.c:140-145`.
///
/// Its reader is now **the EVP ctrl translator**: `crypto/evp/ctrl_params_translate.c`'s
/// `fix_dh_nid` and `fix_dh_nid5114` are what D343 wires to it (`src/evp/pkey_ctx.rs`), which is the
/// reader the `#[allow(dead_code)]` that stood here before D343 named. The other callers remain
/// later strata: `crypto/ffc/ffc_params.c:252` is inside `ossl_ffc_params_todata`, which this crate
/// withholds (`src/ffc/params.rs` records why), and `crypto/encode_decode/encoder_lib.c:818` is
/// Phase 10's.
///
/// # Safety
///
/// As [`ossl_ffc_named_group_get_uid`].
pub(crate) unsafe fn ossl_ffc_named_group_get_name(group: *const DhNamedGroup) -> *const c_char {
    // SAFETY: NULL-or-live per this function's contract.
    match unsafe { group.as_ref() } {
        None => core::ptr::null(),
        Some(group) => group.name,
    }
}

/// `int ossl_ffc_named_group_get_keylength(const DH_NAMED_GROUP *group)` —
/// `crypto/ffc/ffc_dh.c:148-153`.
///
/// The RFC 7919 private-key length — and **0 for the three RFC 5114 groups as well as
/// for a NULL group**, the same value for two different reasons, which is why a caller
/// must not read 0 as "the group is absent".
///
/// # Safety
///
/// As [`ossl_ffc_named_group_get_uid`].
pub(crate) unsafe fn ossl_ffc_named_group_get_keylength(group: *const DhNamedGroup) -> c_int {
    // SAFETY: NULL-or-live per this function's contract.
    match unsafe { group.as_ref() } {
        None => 0,
        Some(group) => group.keylength,
    }
}

/// `const BIGNUM *ossl_ffc_named_group_get_q(const DH_NAMED_GROUP *group)` —
/// `crypto/ffc/ffc_dh.c:155-160`.
///
/// # Safety
///
/// As [`ossl_ffc_named_group_get_uid`]. The result is borrowed from the table and must
/// not be freed: it is one of `crypto/bn/bn_dh.c`'s shared constants.
pub(crate) unsafe fn ossl_ffc_named_group_get_q(group: *const DhNamedGroup) -> *const BigNum {
    // SAFETY: NULL-or-live per this function's contract.
    match unsafe { group.as_ref() } {
        None => core::ptr::null(),
        Some(group) => group.q,
    }
}

/// `int ossl_ffc_named_group_set(FFC_PARAMS *ffc, const DH_NAMED_GROUP *group)` —
/// `crypto/ffc/ffc_dh.c:162-174`.
///
/// Installs a group's three numbers **by pointer**: `ossl_ffc_params_set0_pqg` takes
/// ownership, but the constants carry `BN_FLG_STATIC_DATA`, so their release is a no-op
/// and two `DH` objects built from one group share one modulus. That is the authority's
/// own object graph, and it is why `crate::bn::dh`'s accessors carry the flag at all.
///
/// The last line **flushes the cached nid** and hands the caching to the DH layer;
/// `crate::dh::group_params`'s `ossl_dh_cache_named_group` then fills it back in, so the
/// flush is a step in a sequence rather than a no-op.
///
/// # Safety
///
/// `ffc` is live and writable; `group` is NULL or a pointer this unit answered.
pub(crate) unsafe fn ossl_ffc_named_group_set(
    ffc: *mut FfcParams,
    group: *const DhNamedGroup,
) -> c_int {
    // SAFETY: `ffc` is live per this function's contract.
    if ffc.is_null() {
        return 0;
    }
    // SAFETY: NULL-or-live per this function's contract.
    let Some(group) = (unsafe { group.as_ref() }) else {
        return 0;
    };

    // SAFETY: `ffc` is live, and the three pointers are the table's shared constants,
    // which `set0_pqg` may store directly because their release is a no-op.
    unsafe {
        ossl_ffc_params_set0_pqg(
            ffc,
            group.p.cast_mut(),
            group.q.cast_mut(),
            group.g.cast_mut(),
        );
        (*ffc).keylength = group.keylength;

        /* flush the cached nid, The DH layer is responsible for caching */
        (*ffc).nid = obj::NID_undef;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::ptr;

    use crate::bn::bignum::BN_num_bits;
    use crate::ffc::params::{ossl_ffc_params_cleanup, ossl_ffc_params_init};
    use crate::ffc::FFC_UNVERIFIABLE_GINDEX;

    /// A live `FFC_PARAMS` for the setter's arms; the caller cleans it up.
    fn fresh_params() -> FfcParams {
        let mut params = FfcParams {
            p: ptr::null_mut(),
            q: ptr::null_mut(),
            g: ptr::null_mut(),
            j: ptr::null_mut(),
            seed: ptr::null_mut(),
            seedlen: 0,
            pcounter: -1,
            nid: obj::NID_undef,
            gindex: FFC_UNVERIFIABLE_GINDEX,
            h: 0,
            flags: 0,
            mdname: ptr::null(),
            mdprops: ptr::null(),
            keylength: 0,
        };
        // SAFETY: `params` is a live, writable local and `init` memsets it.
        unsafe { ossl_ffc_params_init(&raw mut params) };
        params
    }

    /// The table is the authority's fourteen rows in the authority's order, each row's
    /// `nbits` is the width of its own `p`, and each row's uid is what its lookup
    /// answers.
    ///
    /// The `nbits` assertion is the one that turns "these numbers were transcribed" into
    /// "these numbers are the ones the constants give": a row whose size disagreed with
    /// its own modulus would be a table that describes a different group from the one it
    /// points at.
    #[test]
    fn the_table_is_the_authoritys_fourteen_rows_in_order() {
        let expected: [(&str, c_int, i32, c_int); NAMED_GROUP_COUNT] = [
            ("ffdhe2048", obj::NID_ffdhe2048, 2048, 225),
            ("ffdhe3072", obj::NID_ffdhe3072, 3072, 275),
            ("ffdhe4096", obj::NID_ffdhe4096, 4096, 325),
            ("ffdhe6144", obj::NID_ffdhe6144, 6144, 375),
            ("ffdhe8192", obj::NID_ffdhe8192, 8192, 400),
            ("modp_1536", obj::NID_modp_1536, 1536, 200),
            ("modp_2048", obj::NID_modp_2048, 2048, 225),
            ("modp_3072", obj::NID_modp_3072, 3072, 275),
            ("modp_4096", obj::NID_modp_4096, 4096, 325),
            ("modp_6144", obj::NID_modp_6144, 6144, 375),
            ("modp_8192", obj::NID_modp_8192, 8192, 400),
            ("dh_1024_160", 1, 1024, 0),
            ("dh_2048_224", 2, 2048, 0),
            ("dh_2048_256", 3, 2048, 0),
        ];
        let table = named_groups();
        assert_eq!(table.len(), NAMED_GROUP_COUNT);
        for (row, (name, uid, nbits, keylength)) in table.iter().zip(expected) {
            assert_eq!(row.uid, uid, "{name} has the wrong uid");
            assert_eq!(row.nbits, nbits, "{name} has the wrong nbits");
            assert_eq!(row.keylength, keylength, "{name} has the wrong keylength");
            // SAFETY: `row.name` is one of the table's own literals.
            let got = unsafe { CStr::from_ptr(row.name) };
            assert_eq!(
                got.to_bytes(),
                name.as_bytes(),
                "{name} is at the wrong row"
            );
            // SAFETY: `row.p` is a shared constant, live for the process.
            assert_eq!(unsafe { BN_num_bits(row.p) }, nbits, "{name}: p's width");
        }
    }

    /// RFC 7919's private-key lengths, and the three RFC 5114 zeros beside them.
    ///
    /// These are the table's one hand-transcribed number per row that no width confirms,
    /// so they are asserted from the document the authority's own comment cites.
    #[test]
    fn the_keylengths_are_rfc7919s() {
        for (nid, keylength) in [
            (obj::NID_ffdhe2048, 225),
            (obj::NID_ffdhe3072, 275),
            (obj::NID_ffdhe4096, 325),
            (obj::NID_ffdhe6144, 375),
            (obj::NID_ffdhe8192, 400),
        ] {
            // SAFETY: the lookup takes no pointer.
            let group = unsafe { ossl_ffc_uid_to_dh_named_group(nid) };
            assert!(!group.is_null());
            // SAFETY: `group` is a table row.
            let length = unsafe { ossl_ffc_named_group_get_keylength(group) };
            assert_eq!(length, keylength);
        }
        for uid in 1..=3 {
            // SAFETY: the lookup takes no pointer.
            let group = unsafe { ossl_ffc_uid_to_dh_named_group(uid) };
            assert!(!group.is_null());
            /* The RFC 5114 groups carry no RFC 7919 key length, and 0 is also the
             * NULL answer: the same value for two different reasons. */
            // SAFETY: `group` is a table row.
            assert_eq!(unsafe { ossl_ffc_named_group_get_keylength(group) }, 0);
        }
    }

    /// The name lookup is case-insensitive and answers NULL for a name no row has; the
    /// uid lookup answers NULL for a uid no row uses — which is every NID, because the
    /// eleven safe-prime rows' uids are 1126..1130 and 1212..1217.
    #[test]
    fn the_two_lookups_answer_their_rows_and_null_otherwise() {
        // SAFETY: every argument is a NUL-terminated literal.
        unsafe {
            let lower = ossl_ffc_name_to_dh_named_group(c"ffdhe2048".as_ptr());
            let upper = ossl_ffc_name_to_dh_named_group(c"FFDHE2048".as_ptr());
            let mixed = ossl_ffc_name_to_dh_named_group(c"FfDhE2048".as_ptr());
            assert!(!lower.is_null());
            assert_eq!(lower, upper);
            assert_eq!(lower, mixed);
            assert!(ossl_ffc_name_to_dh_named_group(c"ffdhe1024".as_ptr()).is_null());
            assert!(ossl_ffc_name_to_dh_named_group(c"".as_ptr()).is_null());
            assert_eq!(ossl_ffc_uid_to_dh_named_group(obj::NID_ffdhe2048), lower);
            assert!(ossl_ffc_uid_to_dh_named_group(obj::NID_undef).is_null());
            assert!(ossl_ffc_uid_to_dh_named_group(4).is_null());
        }
    }

    /// `ossl_ffc_numbers_to_dh_named_group` matches on `p` **and** `g`, refines on `q`
    /// only when the caller has one, and answers NULL for numbers no row names.
    ///
    /// The `q`-less arm is the one that matters: `DH_set0_pqg` reaches the cache with
    /// whatever `q` its caller supplied, and a `DH_new_by_nid` group arrives with none.
    /// The `g` arm is asserted against a row whose `g` is **not** the shared 2, because
    /// that is the case where comparing `p` alone would answer a group the caller's
    /// generator does not belong to.
    #[test]
    fn the_numbers_lookup_needs_p_and_g_and_refines_on_q() {
        // SAFETY: `group` is a table row and its three pointers are shared constants.
        unsafe {
            let group = ossl_ffc_uid_to_dh_named_group(2);
            assert!(!group.is_null());
            let (p, q, g) = ((*group).p, (*group).q, (*group).g);
            let shared_g = ossl_bignum_const_2();

            /* p and g, no q: a match, and the arm `DH_set0_pqg` reaches. */
            assert_eq!(ossl_ffc_numbers_to_dh_named_group(p, ptr::null(), g), group);
            /* p, q and g together: still a match. */
            assert_eq!(ossl_ffc_numbers_to_dh_named_group(p, q, g), group);

            /* The row's `p` with the shared generator instead of its own: no row,
             * because the pair identifies -- and if the search compared `p` alone it
             * would answer `group`, whose generator this is not. */
            assert!(ossl_ffc_numbers_to_dh_named_group(p, ptr::null(), shared_g).is_null());
            /* Numbers no row names at all: no row either. */
            assert!(ossl_ffc_numbers_to_dh_named_group(q, ptr::null(), g).is_null());
            /* A `q` the row does not carry: the refinement refuses. */
            assert!(ossl_ffc_numbers_to_dh_named_group(p, shared_g, g).is_null());

            /* ... and the positive half of the same statement, on a safe-prime row
             * where `g` *is* the shared constant. */
            let ffdhe = ossl_ffc_uid_to_dh_named_group(obj::NID_ffdhe2048);
            assert_eq!((*ffdhe).g, shared_g);
            assert_eq!(
                ossl_ffc_numbers_to_dh_named_group((*ffdhe).p, ptr::null(), shared_g),
                ffdhe
            );
        }
    }

    /// The three RFC 5114 rows have a modulus, a subgroup order and a generator each.
    ///
    /// Unlike the FFDHE and MODP families they share nothing: there is no
    /// `q = (p - 1) / 2` among them, which is what
    /// [`crate::dh::group_params`]'s `ossl_dh_is_named_safe_prime_group` means by
    /// excluding uids 1..3.
    #[test]
    fn the_three_rfc5114_rows_have_their_own_numbers() {
        // SAFETY: the lookups take no pointer.
        let rows: [*const DhNamedGroup; 3] = unsafe {
            [
                ossl_ffc_uid_to_dh_named_group(1),
                ossl_ffc_uid_to_dh_named_group(2),
                ossl_ffc_uid_to_dh_named_group(3),
            ]
        };
        for row in rows {
            assert!(!row.is_null());
        }
        // SAFETY: all three are table rows.
        unsafe {
            let (a, b, c) = (rows[0], rows[1], rows[2]);
            assert_ne!((*a).p, (*b).p);
            assert_ne!((*a).p, (*c).p);
            assert_ne!((*b).p, (*c).p);
            assert_ne!((*a).g, (*b).g);
            assert_ne!((*a).g, (*c).g);
            assert_ne!((*b).g, (*c).g);
            /* None of them is a safe prime: `p` is not `2q + 1`, and `2q + 1` is not
             * even the width of `p`. */
            assert_ne!(BN_num_bits((*a).q) + 1, 1024);
            assert_ne!(BN_num_bits((*b).q) + 1, 2048);
            assert_ne!(BN_num_bits((*c).q) + 1, 2048);
            /* Each is found by its own numbers and not by its neighbour's. */
            for row in rows {
                assert_eq!(
                    ossl_ffc_numbers_to_dh_named_group((*row).p, (*row).q, (*row).g),
                    row
                );
            }
        }
    }

    /// The setter installs the row's three numbers **by pointer**, copies `keylength`,
    /// flushes `nid`, and refuses a NULL argument on either side.
    ///
    /// The flush is observed by writing a value into `nid` first: a setter that only
    /// stored the numbers would leave the 7 standing.
    #[test]
    fn the_setter_installs_by_pointer_and_flushes_the_nid() {
        let mut params = fresh_params();
        // SAFETY: the lookup takes no pointer.
        let group = unsafe { ossl_ffc_uid_to_dh_named_group(obj::NID_ffdhe8192) };
        assert!(!group.is_null());
        // SAFETY: `params` is a live local and `group` is a table row.
        unsafe {
            params.nid = 7;
            assert_eq!(ossl_ffc_named_group_set(&raw mut params, group), 1);
            assert_eq!(params.p, (*group).p.cast_mut());
            assert_eq!(params.q, (*group).q.cast_mut());
            assert_eq!(params.g, (*group).g.cast_mut());
            assert_eq!(params.keylength, 400);
            assert_eq!(params.nid, obj::NID_undef);
            /* A NULL on either side is refused, and the refusal stores nothing. */
            assert_eq!(ossl_ffc_named_group_set(&raw mut params, ptr::null()), 0);
            assert_eq!(params.keylength, 400);
            assert_eq!(ossl_ffc_named_group_set(ptr::null_mut(), group), 0);
            /* The cleanup releases the three slots, which is a no-op: they hold the
             * shared constants, which carry `BN_FLG_STATIC_DATA`. The modulus is still
             * 8192 bits wide afterwards, which is what makes `DH_free` of a
             * `DH_new_by_nid` object safe. */
            ossl_ffc_params_cleanup(&raw mut params);
            assert_eq!(BN_num_bits((*group).p), 8192);
        }
    }

    /// Each accessor's NULL answer is its own: `NID_undef` for the uid, NULL for the
    /// name and the `q`, 0 for the keylength.
    #[test]
    fn the_accessors_answers_for_null_are_the_authoritys_three() {
        // SAFETY: every argument is NULL, which each accessor accepts.
        unsafe {
            assert_eq!(ossl_ffc_named_group_get_uid(ptr::null()), obj::NID_undef);
            assert!(ossl_ffc_named_group_get_name(ptr::null()).is_null());
            assert_eq!(ossl_ffc_named_group_get_keylength(ptr::null()), 0);
            assert!(ossl_ffc_named_group_get_q(ptr::null()).is_null());
        }
    }
}
