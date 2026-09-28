//! `crypto/x509/x509_ext.c` — the `X509`/`X509_CRL`/`X509_REVOKED` extension accessors. Phase
//! 10.14.5, landed at function granularity.
//!
//! `crypto/x509/x509_ext.c` is 170 lines and publishes 26 functions: the same nine-function
//! extension surface (`_get_ext_count`, `_get_ext_by_NID`/`_by_OBJ`/`_by_critical`, `_get_ext`,
//! `_delete_ext`, `_add_ext`, `_get_ext_d2i`, `_add1_ext_i2d`) over three carriers — `X509_CRL`
//! (`:19-76`), `X509` (`:78-123`) and `X509_REVOKED` (`:125-169`).
//! Every function is a one-line delegation to [`crate::x509::x509_v3`]'s list primitives
//! (`X509v3_get_ext_count`/`_by_NID`/`_by_OBJ`/`_by_critical`/`_get_ext`/`_delete_ext`/
//! `_add_ext`) or to the two withheld lookups in [`crate::x509::v3_lib`].
//!
//! ## What lands, and what is withheld
//!
//! **21 of the 27 containers land**: the count/by-NID/by-OBJ/by-critical/get accessors and the
//! add/delete mutators for all three carriers. Their closure is satisfied by 10.11's `x509_v3.rs`
//! alone, and the three carriers (`X509.cert_info.extensions`, `X509Crl.crl.extensions`,
//! `X509Revoked.extensions`) are 10.8's landed structs, so every one is writable today. The
//! `X509_EXTENSION` destructor `delete_ext`'s empty-list case passes to `OPENSSL_sk_pop_free` is
//! 10.8's `x_exten.rs`.
//!
//! **Six are withheld by name**, each with the same blocker: the two value-level lookups
//! `X509V3_get_d2i` and `X509V3_add1_i2d` in [`crate::x509::v3_lib`], which are themselves
//! withheld behind `standard_exts[]` — the table of **63 `ossl_v3_*` tables** this subphase
//! cannot complete. They are:
//!
//! | withheld | authority lines | blocker |
//! |---|---|---|
//! | `X509_CRL_get_ext_d2i` | `:62-65` | `X509V3_get_d2i` (`v3_lib.c`) |
//! | `X509_CRL_add1_ext_i2d` | `:67-72` | `X509V3_add1_i2d` (`v3_lib.c`) |
//! | `X509_get_ext_d2i` | `:113-116` | `X509V3_get_d2i` (`v3_lib.c`) |
//! | `X509_add1_ext_i2d` | `:118-123` | `X509V3_add1_i2d` (`v3_lib.c`) |
//! | `X509_REVOKED_get_ext_d2i` | `:161-164` | `X509V3_get_d2i` (`v3_lib.c`) |
//! | `X509_REVOKED_add1_ext_i2d` | `:166-169` | `X509V3_add1_i2d` (`v3_lib.c`) |
//!
//! Nothing is stubbed: the six are named rather than declared, so the crate's surface is only
//! what the 21 land.
//!
//! ## Why this unit sits in 10.14.5
//!
//! `x509_ext.c` was never named in section 7's table; D459 assigned it here because its only
//! callees are `v3_lib.c`'s two halves. `X509_get_ext`/`_by_NID`/`_count` are three of the six
//! names `ossl_x509v3_cache_extensions` (`v3_purp.c`) was measured to need — the other three are
//! `X509_get_ext_d2i` (withheld here), `ossl_x509_init_sig_info` (`x509_set.c`) and
//! `DIST_POINT_set_dpname` (`v3_crld.c`) — so this landing removes three of that function's six
//! blockers and leaves the one that is the whole `standard_exts[]` wall.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.14.5 arms drive the six accessors over the fixed certificate/CRL DER the probe
//! already carries, and the add/delete mutators over a probe-built `X509_EXTENSION`, each popping
//! the error queue first (D455's lesson). The withheld six are not driven.
//!
//! ## No raise
//!
//! The unit raises nothing — every error path is a delegated return value — so
//! `crypto/x509/x509_ext.c` is deliberately not added to `gen_err_raise_sites.py`'s covered set.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OpenSslStack};
use crate::x509::x509_v3::{
    X509v3_add_ext, X509v3_delete_ext, X509v3_get_ext, X509v3_get_ext_by_NID,
    X509v3_get_ext_by_OBJ, X509v3_get_ext_by_critical, X509v3_get_ext_count,
};
use crate::x509::x_crl::{X509Crl, X509Revoked};
use crate::x509::x_exten::{X509Extension, X509_EXTENSION_free};
use crate::x509::x_x509::X509;

/// The element destructor `sk_X509_EXTENSION_pop_free` passes to `OPENSSL_sk_pop_free` — the
/// authority spells it `X509_EXTENSION_free` (`crypto/x509/x509_ext.c:51`).
///
/// # Safety
///
/// `elem` must be NULL or an `X509_EXTENSION` this crate allocated.
unsafe extern "C" fn free_x509_extension(elem: *mut c_void) {
    // SAFETY: `elem` is NULL or an `X509_EXTENSION`; `X509_EXTENSION_free` accepts NULL.
    unsafe { X509_EXTENSION_free(elem.cast::<X509Extension>()) };
}

// ---------------------------------------------------------------------------------------------
// X509_CRL — `crypto/x509/x509_ext.c:19-76`
// ---------------------------------------------------------------------------------------------

/// `int X509_CRL_get_ext_count(const X509_CRL *x)` — `crypto/x509/x509_ext.c:19-22`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_count(x: *const X509Crl) -> c_int {
    // SAFETY: `x` is live per the contract; `X509v3_get_ext_count` accepts NULL or a live stack.
    unsafe { X509v3_get_ext_count((*x).crl.extensions) }
}

/// `int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos)` —
/// `crypto/x509/x509_ext.c:24-28`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_NID(
    x: *const X509Crl,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).crl.extensions, nid, lastpos) }
}

/// `int X509_CRL_get_ext_by_OBJ(const X509_CRL *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/x509/x509_ext.c:29-34`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`; `obj` must be a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_OBJ(
    x: *const X509Crl,
    obj: *const crate::runtime::obj::Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract; `obj` is a live object.
    unsafe { X509v3_get_ext_by_OBJ((*x).crl.extensions, obj, lastpos) }
}

/// `int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos)` —
/// `crypto/x509/x509_ext.c:35-39`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext_by_critical(
    x: *const X509Crl,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).crl.extensions, crit, lastpos) }
}

/// `X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc)` —
/// `crypto/x509/x509_ext.c:40-43`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_ext(x: *const X509Crl, loc: c_int) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).crl.extensions, loc) }
}

/// `static X509_EXTENSION *delete_ext(STACK_OF(X509_EXTENSION) **sk, int loc)` —
/// `crypto/x509/x509_ext.c:45-55`.
///
/// Deletes through [`X509v3_delete_ext`], then — when the list is now empty — drops the list
/// itself, because the authority omits empty extension lists from the encoding. `*sk` is written
/// NULL in that case; the removed element is the caller's.
///
/// # Safety
///
/// `sk` must point at a writable stack slot holding NULL or a live extension stack.
unsafe fn delete_ext(sk: *mut *mut OpenSslStack, loc: c_int) -> *mut X509Extension {
    // SAFETY: `sk` points at a writable slot per the contract.
    let ret = unsafe { X509v3_delete_ext(*sk, loc) };
    // SAFETY: `sk` is writable and `*sk` is NULL or a live stack per the contract.
    unsafe {
        if !(*sk).is_null() && OPENSSL_sk_num(*sk) == 0 {
            OPENSSL_sk_pop_free(*sk, Some(free_x509_extension));
            *sk = ptr::null_mut();
        }
    }
    ret
}

/// `X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc)` — `crypto/x509/x509_ext.c:57-60`.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_delete_ext(x: *mut X509Crl, loc: c_int) -> *mut X509Extension {
    // SAFETY: `x` is live, so its `crl.extensions` field is a writable slot.
    unsafe { delete_ext(&raw mut (*x).crl.extensions, loc) }
}

/// `int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/x509/x509_ext.c:73-76`.
///
/// The authority's `!= NULL` test, as a 0/1 answer.
///
/// # Safety
///
/// `x` must be a live `X509_CRL`; `ex` must be a live extension.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_add_ext(
    x: *mut X509Crl,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` is live; `X509v3_add_ext` takes the field's address and a live extension.
    c_int::from(!unsafe { X509v3_add_ext(&raw mut (*x).crl.extensions, ex, loc) }.is_null())
}

// `X509_CRL_get_ext_d2i` (`:62-65`) and `X509_CRL_add1_ext_i2d` (`:67-72`) are withheld by name;
// their blocker is `X509V3_get_d2i`/`X509V3_add1_i2d` in `crate::x509::v3_lib`.

// ---------------------------------------------------------------------------------------------
// X509 — `crypto/x509/x509_ext.c:78-123`
// ---------------------------------------------------------------------------------------------

/// `int X509_get_ext_count(const X509 *x)` — `crypto/x509/x509_ext.c:78-81`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_count(x: *const X509) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_count((*x).cert_info.extensions) }
}

/// `int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos)` —
/// `crypto/x509/x509_ext.c:83-86`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_NID(x: *const X509, nid: c_int, lastpos: c_int) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).cert_info.extensions, nid, lastpos) }
}

/// `int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/x509/x509_ext.c:88-92`.
///
/// # Safety
///
/// `x` must be a live `X509`; `obj` must be a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_OBJ(
    x: *const X509,
    obj: *const crate::runtime::obj::Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live and `obj` is a live object per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).cert_info.extensions, obj, lastpos) }
}

/// `int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos)` —
/// `crypto/x509/x509_ext.c:93-97`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext_by_critical(
    x: *const X509,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).cert_info.extensions, crit, lastpos) }
}

/// `X509_EXTENSION *X509_get_ext(const X509 *x, int loc)` — `crypto/x509/x509_ext.c:98-101`.
///
/// One of the six names `ossl_x509v3_cache_extensions` (`v3_purp.c`) needs.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_ext(x: *const X509, loc: c_int) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).cert_info.extensions, loc) }
}

/// `X509_EXTENSION *X509_delete_ext(X509 *x, int loc)` — `crypto/x509/x509_ext.c:103-106`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_delete_ext(x: *mut X509, loc: c_int) -> *mut X509Extension {
    // SAFETY: `x` is live, so its `cert_info.extensions` field is a writable slot.
    unsafe { delete_ext(&raw mut (*x).cert_info.extensions, loc) }
}

/// `int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc)` — `crypto/x509/x509_ext.c:108-111`.
///
/// # Safety
///
/// `x` must be a live `X509`; `ex` must be a live extension.
#[no_mangle]
pub unsafe extern "C" fn X509_add_ext(x: *mut X509, ex: *mut X509Extension, loc: c_int) -> c_int {
    // SAFETY: `x` is live; `X509v3_add_ext` takes the field's address and a live extension.
    c_int::from(!unsafe { X509v3_add_ext(&raw mut (*x).cert_info.extensions, ex, loc) }.is_null())
}

// `X509_get_ext_d2i` (`:113-116`) and `X509_add1_ext_i2d` (`:118-123`) are withheld by name;
// their blocker is `X509V3_get_d2i`/`X509V3_add1_i2d` in `crate::x509::v3_lib`.

// ---------------------------------------------------------------------------------------------
// X509_REVOKED — `crypto/x509/x509_ext.c:125-169`
// ---------------------------------------------------------------------------------------------

/// `int X509_REVOKED_get_ext_count(const X509_REVOKED *x)` — `crypto/x509/x509_ext.c:125-128`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_count(x: *const X509Revoked) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_count((*x).extensions) }
}

/// `int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos)` —
/// `crypto/x509/x509_ext.c:130-133`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_NID(
    x: *const X509Revoked,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_NID((*x).extensions, nid, lastpos) }
}

/// `int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED *x, const ASN1_OBJECT *obj, int lastpos)` —
/// `crypto/x509/x509_ext.c:135-139`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`; `obj` must be a live object.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_OBJ(
    x: *const X509Revoked,
    obj: *const crate::runtime::obj::Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live and `obj` is a live object per the contract.
    unsafe { X509v3_get_ext_by_OBJ((*x).extensions, obj, lastpos) }
}

/// `int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *x, int crit, int lastpos)` —
/// `crypto/x509/x509_ext.c:141-144`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext_by_critical(
    x: *const X509Revoked,
    crit: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext_by_critical((*x).extensions, crit, lastpos) }
}

/// `X509_EXTENSION *X509_REVOKED_get_ext(const X509_REVOKED *x, int loc)` —
/// `crypto/x509/x509_ext.c:146-149`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get_ext(
    x: *const X509Revoked,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live per the contract.
    unsafe { X509v3_get_ext((*x).extensions, loc) }
}

/// `X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc)` —
/// `crypto/x509/x509_ext.c:151-154`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_delete_ext(
    x: *mut X509Revoked,
    loc: c_int,
) -> *mut X509Extension {
    // SAFETY: `x` is live, so its `extensions` field is a writable slot.
    unsafe { delete_ext(&raw mut (*x).extensions, loc) }
}

/// `int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc)` —
/// `crypto/x509/x509_ext.c:156-159`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`; `ex` must be a live extension.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_add_ext(
    x: *mut X509Revoked,
    ex: *mut X509Extension,
    loc: c_int,
) -> c_int {
    // SAFETY: `x` is live; `X509v3_add_ext` takes the field's address and a live extension.
    c_int::from(!unsafe { X509v3_add_ext(&raw mut (*x).extensions, ex, loc) }.is_null())
}

// `X509_REVOKED_get_ext_d2i` (`:161-164`) and `X509_REVOKED_add1_ext_i2d` (`:166-169`) are
// withheld by name; their blocker is `X509V3_get_d2i`/`X509V3_add1_i2d` in `crate::x509::v3_lib`.
