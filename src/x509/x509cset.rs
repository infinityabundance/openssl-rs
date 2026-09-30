//! Phase 10.14.1 — `crypto/x509/x509cset.c`: the `X509_CRL` and `X509_REVOKED` mutator and
//! accessor layer, whole but for one function already landed elsewhere.
//!
//! `crypto/x509/x509cset.c` is 185 lines and publishes twenty-two functions. **Twenty-one land
//! here**; the twenty-second, `X509_CRL_up_ref` (`:74-84`), already landed in
//! [`crate::x509::x_crl`] as part of 10.8's object core (D451), and is deliberately not
//! re-declared — a second `#[no_mangle]` definition would be a duplicate symbol.
//!
//! Ten of the twenty-one are the `X509_CRL` getters (`_get_version`, the `lastUpdate`/`nextUpdate`
//! pair and its deprecated spellings, `_get_issuer`, `_get0_extensions`, `_get_REVOKED`,
//! `_get0_tbs_sigalg`, `_get0_signature`, `_get_signature_nid`); four are its setters
//! (`_set_version`, `_set_issuer_name`, `_set1_lastUpdate`, `_set1_nextUpdate`) plus
//! `X509_CRL_sort` and `i2d_re_X509_CRL_tbs`; six are the `X509_REVOKED` accessors. The unit is
//! dependency-complete for this slice: its only unlanded callee is `ossl_x509_set1_time`, which
//! 10.14.1 un-withholds from [`crate::x509::x509_set`].
//!
//! ## `ossl_x509_set1_time` is the unit's one shared helper, and is not this file's
//!
//! Four functions here (`_set1_lastUpdate`, `_set1_nextUpdate`, `X509_REVOKED_set_revocationDate`
//! and, through `x509_set.c`'s own setters, the certificate validity pair) call the same
//! `ossl_x509_set1_time`. It is defined in `crypto/x509/x509_set.c:78-92`, not here, so it lands
//! with `x509_set.rs`; the `X509_REVOKED` caller passes a NULL `modified` pointer because an
//! `X509_REVOKED` carries no cached-encoding flag.
//!
//! ## No raise
//!
//! Every function in the unit signals failure by a 0 or NULL return and none calls `ERR_raise*`,
//! so `crypto/x509/x509cset.c` is deliberately **not** an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES` — the rule `x_crl.c` and `x509_set.c` already follow.
//!
//! ## The one deliberate modelling difference
//!
//! `X509_CRL_get_REVOKED`'s authority return type is `STACK_OF(X509_REVOKED) *`, and the crate
//! models stacks as the type-erased [`OpenSslStack`]. Every caller re-interprets it, and the
//! item layer already stores the same pointer, so this is the same object under a different
//! static type rather than a conversion.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar};

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_new, ASN1_STRING_copy};
use crate::asn1::x_algor::X509Algor;
use crate::runtime::obj::OBJ_obj2nid;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_set::ossl_x509_set1_time;
use crate::x509::x_crl::{i2d_X509_CRL_INFO, X509Crl, X509Revoked};
use crate::x509::x_name::{X509Name, X509_NAME_set};

/// `int X509_CRL_set_version(X509_CRL *x, long version)` — `crypto/x509/x509cset.c:19-31`.
///
/// Allocates the version integer on first use, sets it and marks the cached encoding stale.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_version(x: *mut X509Crl, version: c_long) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract.
    unsafe {
        if (*x).crl.version.is_null() {
            (*x).crl.version = ASN1_INTEGER_new();
            if (*x).crl.version.is_null() {
                return 0;
            }
        }
        if ASN1_INTEGER_set((*x).crl.version, version) == 0 {
            return 0;
        }
        (*x).crl.enc.modified = 1;
    }
    1
}

/// `int X509_CRL_set_issuer_name(X509_CRL *x, const X509_NAME *name)` —
/// `crypto/x509/x509cset.c:33-41`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509_CRL`; `name` must be a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set_issuer_name(x: *mut X509Crl, name: *const X509Name) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live; `&mut (*x).crl.issuer` is the live slot `X509_NAME_set` replaces.
    if unsafe { X509_NAME_set(&raw mut (*x).crl.issuer, name) } == 0 {
        return 0;
    }
    // SAFETY: `x` is live.
    unsafe { (*x).crl.enc.modified = 1 };
    1
}

/// `int X509_CRL_set1_lastUpdate(X509_CRL *x, const ASN1_TIME *tm)` —
/// `crypto/x509/x509cset.c:43-48`.
///
/// # Safety
///
/// `x` must be NULL or live; `tm` must be a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_lastUpdate(x: *mut X509Crl, tm: *const Asn1String) -> c_int {
    if x.is_null() || tm.is_null() {
        return 0;
    }
    // SAFETY: `x` is live; the modified flag and the time slot are its own.
    unsafe {
        ossl_x509_set1_time(
            &raw mut (*x).crl.enc.modified,
            &raw mut (*x).crl.lastUpdate,
            tm,
        )
    }
}

/// `int X509_CRL_set1_nextUpdate(X509_CRL *x, const ASN1_TIME *tm)` —
/// `crypto/x509/x509cset.c:50-55`.
///
/// # Safety
///
/// `x` must be NULL or live; `tm` must be a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_set1_nextUpdate(x: *mut X509Crl, tm: *const Asn1String) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live; the modified flag and the time slot are its own.
    unsafe {
        ossl_x509_set1_time(
            &raw mut (*x).crl.enc.modified,
            &raw mut (*x).crl.nextUpdate,
            tm,
        )
    }
}

/// `int X509_CRL_sort(X509_CRL *c)` — `crypto/x509/x509cset.c:57-72`.
///
/// Sorts the revoked stack by its `X509_REVOKED_cmp` comparator and renumbers `sequence`. Answers
/// 1 unconditionally; an empty or NULL stack sorts to no elements and still answers 1.
///
/// # Safety
///
/// `c` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_sort(c: *mut X509Crl) -> c_int {
    // SAFETY: `c` is live per the contract.
    unsafe {
        let revoked = (*c).crl.revoked;
        OPENSSL_sk_sort(revoked);
        let n = OPENSSL_sk_num(revoked);
        for i in 0..n {
            let r = OPENSSL_sk_value(revoked, i).cast::<X509Revoked>();
            (*r).sequence = i;
        }
        (*c).crl.enc.modified = 1;
    }
    1
}

/// `long X509_CRL_get_version(const X509_CRL *crl)` — `crypto/x509/x509cset.c:86-89`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_version(crl: *const X509Crl) -> c_long {
    // SAFETY: `crl` is live per the contract.
    unsafe { ASN1_INTEGER_get((*crl).crl.version) }
}

/// `const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:91-94`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_lastUpdate(crl: *const X509Crl) -> *const Asn1String {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.lastUpdate }
}

/// `const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:96-99`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_nextUpdate(crl: *const X509Crl) -> *const Asn1String {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.nextUpdate }
}

/// `ASN1_TIME *X509_CRL_get_lastUpdate(X509_CRL *crl)` — `crypto/x509/x509cset.c:102-105`.
///
/// The pre-1.1.0 non-`const` spelling; `OPENSSL_NO_DEPRECATED_1_1_0` is unset in this profile.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_lastUpdate(crl: *mut X509Crl) -> *mut Asn1String {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.lastUpdate }
}

/// `ASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *crl)` — `crypto/x509/x509cset.c:107-110`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_nextUpdate(crl: *mut X509Crl) -> *mut Asn1String {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.nextUpdate }
}

/// `X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl)` — `crypto/x509/x509cset.c:113-116`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_issuer(crl: *const X509Crl) -> *mut X509Name {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.issuer }
}

/// `const STACK_OF(X509_EXTENSION) *X509_CRL_get0_extensions(const X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:118-121`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_extensions(crl: *const X509Crl) -> *const OpenSslStack {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.extensions }
}

/// `STACK_OF(X509_REVOKED) *X509_CRL_get_REVOKED(X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:123-126`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_REVOKED(crl: *mut X509Crl) -> *mut OpenSslStack {
    // SAFETY: `crl` is live per the contract.
    unsafe { (*crl).crl.revoked }
}

/// `const X509_ALGOR *X509_CRL_get0_tbs_sigalg(const X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:128-131`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_tbs_sigalg(crl: *const X509Crl) -> *const X509Algor {
    // SAFETY: `crl` is live per the contract.
    unsafe { &raw const (*crl).crl.sig_alg }
}

/// `void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig,
/// const X509_ALGOR **palg)` — `crypto/x509/x509cset.c:133-140`.
///
/// Either out-pointer may be NULL, in which case that half is not written. Both point into the
/// caller's CRL and must not be freed.
///
/// # Safety
///
/// `crl` must be live; each out-pointer must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get0_signature(
    crl: *const X509Crl,
    psig: *mut *const Asn1String,
    palg: *mut *const X509Algor,
) {
    // SAFETY: `crl` is live per the contract.
    unsafe {
        if !psig.is_null() {
            *psig = &raw const (*crl).signature;
        }
        if !palg.is_null() {
            *palg = &raw const (*crl).sig_alg;
        }
    }
}

/// `int X509_CRL_get_signature_nid(const X509_CRL *crl)` —
/// `crypto/x509/x509cset.c:142-145`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_get_signature_nid(crl: *const X509Crl) -> c_int {
    // SAFETY: `crl` is live per the contract.
    unsafe { OBJ_obj2nid((*crl).sig_alg.algorithm) }
}

/// `const ASN1_TIME *X509_REVOKED_get0_revocationDate(const X509_REVOKED *x)` —
/// `crypto/x509/x509cset.c:147-150`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_revocationDate(
    x: *const X509Revoked,
) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { (*x).revocationDate }
}

/// `int X509_REVOKED_set_revocationDate(X509_REVOKED *x, ASN1_TIME *tm)` —
/// `crypto/x509/x509cset.c:152-157`.
///
/// The NULL `modified` argument is the authority's: an `X509_REVOKED` carries no cached-encoding
/// flag, so only the duplicated time is swapped in.
///
/// # Safety
///
/// `x` must be NULL or live; `tm` must be a live `ASN1_TIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_set_revocationDate(
    x: *mut X509Revoked,
    tm: *mut Asn1String,
) -> c_int {
    if x.is_null() || tm.is_null() {
        return 0;
    }
    // SAFETY: `x` is live; the time slot is its own.
    unsafe { ossl_x509_set1_time(core::ptr::null_mut(), &raw mut (*x).revocationDate, tm) }
}

/// `const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x)` —
/// `crypto/x509/x509cset.c:159-162`.
///
/// # Safety
///
/// `x` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_serialNumber(
    x: *const X509Revoked,
) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { &raw const (*x).serialNumber }
}

/// `int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial)` —
/// `crypto/x509/x509cset.c:164-174`.
///
/// Copies the value; a self-assignment is a no-op that answers 1.
///
/// # Safety
///
/// `x` must be NULL or live; `serial` must be a live `ASN1_INTEGER`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_set_serialNumber(
    x: *mut X509Revoked,
    serial: *mut Asn1String,
) -> c_int {
    if x.is_null() {
        return 0;
    }
    // SAFETY: `x` is live per the contract.
    unsafe {
        let in_ = &raw mut (*x).serialNumber;
        if in_ != serial {
            return ASN1_STRING_copy(in_, serial);
        }
    }
    1
}

/// `const STACK_OF(X509_EXTENSION) *X509_REVOKED_get0_extensions(const X509_REVOKED *r)` —
/// `crypto/x509/x509cset.c:176-179`.
///
/// # Safety
///
/// `r` must be a live `X509_REVOKED`.
#[no_mangle]
pub unsafe extern "C" fn X509_REVOKED_get0_extensions(
    r: *const X509Revoked,
) -> *const OpenSslStack {
    // SAFETY: `r` is live per the contract.
    unsafe { (*r).extensions }
}

/// `int i2d_re_X509_CRL_tbs(X509_CRL *crl, unsigned char **pp)` —
/// `crypto/x509/x509cset.c:181-185`.
///
/// Marks the CRL body modified before re-encoding, so a stale cached encoding is never reused.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`; `pp` must be NULL or a writable out-pointer.
#[no_mangle]
pub unsafe extern "C" fn i2d_re_X509_CRL_tbs(crl: *mut X509Crl, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: `crl` is live per the contract.
    unsafe {
        (*crl).crl.enc.modified = 1;
        i2d_X509_CRL_INFO(&raw const (*crl).crl, pp)
    }
}
