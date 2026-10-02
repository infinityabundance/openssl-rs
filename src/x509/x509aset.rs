//! `crypto/x509/x509aset.c` -- the `X509_ACERT`/`OSSL_ISSUER_SERIAL`/`OSSL_OBJECT_DIGEST_INFO`
//! setters. Phase 11.3.
//!
//! `crypto/x509/x509aset.c` is 177 lines and publishes twelve setters: two static replacement
//! helpers ([`replace_gentime`] `:15-35`, [`replace_dirName`] `:37-75`), the `OSSL_*` setters
//! (`:77-117`), `X509_ACERT_set_version` (`:119-122`), the three `set0_holder_*` transfers
//! (`:124-142`) and the four `set1_*` copies (`:144-177`). **The whole unit lands here**;
//! nothing is withheld and nothing is stubbed.
//!
//! The two helpers are the ones with a shape worth naming: [`replace_gentime`] duplicates a
//! `GENERALIZEDTIME`, refusing a value of any other string type, and replaces the destination
//! in place; [`replace_dirName`] builds a fresh one-entry `GEN_DIRNAME` `GENERAL_NAMES` and
//! releases the old one, refusing the whole operation on any allocation failure. Both are
//! `static` in the authority and file-private here.
//!
//! ## The raise sites
//!
//! `crypto/x509/x509aset.c` is not an entry in `gen_err_raise_sites.py` (the generator's
//! covered set is the closed-stratum file list), so its seven coordinates are **declared
//! locally** with the `err_sites::ErrSite` shape, as `v3_ac_tgt.rs` does. Their reason values
//! are read from the authority's `err.h`, not typed from memory: six carry `ERR_R_ASN1_LIB`
//! (`:27`, `:44`, `:49`, `:54`, `:113`, `:154`) and the failed stack push carries
//! `ERR_R_CRYPTO_LIB` (`:59`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_void};

use crate::asn1::prim::{ASN1_ENUMERATED_set, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_STRING_copy, ASN1_STRING_dup, ASN1_STRING_free};
use crate::asn1::x_algor::X509_ALGOR_copy;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, OpenSslStack};
use crate::x509::v3_ac_tgt::{OsslIssuerSerial, OsslObjectDigestInfo};
use crate::x509::v3_genn::{
    GENERAL_NAMES_free, GENERAL_NAME_free, GENERAL_NAME_new, GENERAL_NAME_set0_value, GEN_DIRNAME,
};
use crate::x509::x509_acert::{
    OSSL_ISSUER_SERIAL_free, OSSL_OBJECT_DIGEST_INFO_free, X509Acert, X509_ACERT_ISSUER_V2FORM_new,
    X509_ACERT_ISSUER_V2,
};
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_ASN1_LIB` -- `include/openssl/err.h.in:328`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`.
const ERR_R_ASN1_LIB: c_int = 13 | (0x2 << 18);
/// `ERR_R_CRYPTO_LIB` -- `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 15 | (0x2 << 18);

/// One `x509aset.c` raise coordinate, declared locally (see the module doc).
const fn x509aset_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509aset.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `replace_gentime`'s failed `ASN1_STRING_dup` at `x509aset.c:27`.
const X509ASET_27: ErrSite = x509aset_site(27, c"replace_gentime", ERR_R_ASN1_LIB);
/// `replace_dirName`'s failed `X509_NAME_dup` at `x509aset.c:44`.
const X509ASET_44: ErrSite = x509aset_site(44, c"replace_dirName", ERR_R_ASN1_LIB);
/// `replace_dirName`'s failed `sk_GENERAL_NAME_new_null` at `x509aset.c:49`.
const X509ASET_49: ErrSite = x509aset_site(49, c"replace_dirName", ERR_R_ASN1_LIB);
/// `replace_dirName`'s failed `GENERAL_NAME_new` at `x509aset.c:54`.
const X509ASET_54: ErrSite = x509aset_site(54, c"replace_dirName", ERR_R_ASN1_LIB);
/// `replace_dirName`'s failed `sk_GENERAL_NAME_push` at `x509aset.c:59`.
const X509ASET_59: ErrSite = x509aset_site(59, c"replace_dirName", ERR_R_CRYPTO_LIB);
/// `OSSL_ISSUER_SERIAL_set1_issuerUID`'s failed duplicate at `x509aset.c:113`.
const X509ASET_113: ErrSite =
    x509aset_site(113, c"OSSL_ISSUER_SERIAL_set1_issuerUID", ERR_R_ASN1_LIB);
/// `X509_ACERT_set1_issuerName`'s failed `X509_ACERT_ISSUER_V2FORM_new` at `x509aset.c:154`.
const X509ASET_154: ErrSite = x509aset_site(154, c"X509_ACERT_set1_issuerName", ERR_R_ASN1_LIB);

/// `static int replace_gentime(ASN1_STRING **dest, const ASN1_GENERALIZEDTIME *src)` --
/// `x509aset.c:15-35`.
///
/// A source of any type but `V_ASN1_GENERALIZEDTIME` answers 0; a source identical to the
/// destination is a no-op answering 1; otherwise the source is duplicated, the old destination
/// released and the new one installed.
///
/// # Safety
///
/// `dest` is a writable `ASN1_STRING *` slot; `src` is a live `ASN1_STRING`.
unsafe fn replace_gentime(
    dest: *mut *mut crate::asn1::layout::Asn1String,
    src: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `src` is live per the contract.
    if unsafe { (*src).type_ } != crate::asn1::layout::V_ASN1_GENERALIZEDTIME {
        return 0;
    }
    // SAFETY: `dest` is a readable slot per the contract.
    if unsafe { *dest } == src.cast_mut() {
        return 1;
    }
    // SAFETY: `src` is live and has a type.
    let s = unsafe { ASN1_STRING_dup(src) };
    if s.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_27) };
        return 0;
    }
    // SAFETY: `dest` is a readable/writable slot; its old value is owned by the caller.
    unsafe {
        ASN1_STRING_free(*dest);
        *dest = s;
    }
    1
}

/// `static int replace_dirName(GENERAL_NAMES **names, const X509_NAME *dirName)` --
/// `x509aset.c:37-75`.
///
/// Builds a fresh one-entry `GEN_DIRNAME` `GENERAL_NAMES` and installs it, releasing the old
/// stack. Every allocation failure releases whatever this call already built and answers 0.
///
/// # Safety
///
/// `names` is a writable `GENERAL_NAMES *` slot; `dirName` is a live `X509_NAME`.
unsafe fn replace_dirName(names: *mut *mut OpenSslStack, dirName: *const X509Name) -> c_int {
    // SAFETY: `dirName` is live per the contract.
    let name_copy = unsafe { X509_NAME_dup(dirName) };
    if name_copy.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_44) };
        return 0;
    }
    // SAFETY: no preconditions.
    let new_names = OPENSSL_sk_new_null();
    if new_names.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_49) };
        // SAFETY: `name_copy` is this call's own and is not owned elsewhere.
        unsafe { X509_NAME_free(name_copy) };
        return 0;
    }
    // SAFETY: `GENERAL_NAME_new()` answers a fresh name or NULL.
    let gen_name = GENERAL_NAME_new();
    if gen_name.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_54) };
        // SAFETY: both are this call's own.
        unsafe {
            OPENSSL_sk_free(new_names);
            X509_NAME_free(name_copy);
        }
        return 0;
    }
    // SAFETY: `new_names` is live and `gen_name` is this call's own.
    if unsafe { OPENSSL_sk_push(new_names, gen_name.cast::<c_void>()) } <= 0 {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_59) };
        // SAFETY: all three are this call's own; `gen_name` was not stored.
        unsafe {
            GENERAL_NAME_free(gen_name);
            OPENSSL_sk_free(new_names);
            X509_NAME_free(name_copy);
        }
        return 0;
    }
    // SAFETY: `gen_name` is live; `name_copy` is handed to it.
    unsafe { GENERAL_NAME_set0_value(gen_name, GEN_DIRNAME, name_copy.cast::<c_void>()) };
    // SAFETY: `names` is a readable/writable slot; the old stack is owned by the caller.
    unsafe {
        GENERAL_NAMES_free(*names);
        *names = new_names;
    }
    1
}

/// `int OSSL_OBJECT_DIGEST_INFO_set1_digest(OSSL_OBJECT_DIGEST_INFO *o, int digestedObjectType,
/// X509_ALGOR *digestAlgorithm, ASN1_BIT_STRING *digest)` -- `x509aset.c:77-93`.
///
/// # Safety
///
/// `o` is a live `OSSL_OBJECT_DIGEST_INFO`; `digestAlgorithm`/`digest` are live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_set1_digest(
    o: *mut OsslObjectDigestInfo,
    digestedObjectType: c_int,
    digestAlgorithm: *mut crate::asn1::x_algor::X509Algor,
    digest: *mut crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `o` is live and its embedded ENUMERATED is writable.
    if unsafe {
        ASN1_ENUMERATED_set(
            &raw mut (*o).digestedObjectType,
            digestedObjectType as c_long,
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `o` is live and `digestAlgorithm` is the caller's live source.
    if unsafe { X509_ALGOR_copy(&raw mut (*o).digestAlgorithm, digestAlgorithm) } <= 0 {
        return 0;
    }
    // SAFETY: `o` is live and `digest` is the caller's live source.
    if unsafe { ASN1_STRING_copy(&raw mut (*o).objectDigest, digest) } <= 0 {
        return 0;
    }
    1
}

/// `int OSSL_ISSUER_SERIAL_set1_issuer(OSSL_ISSUER_SERIAL *isss, const X509_NAME *issuer)` --
/// `x509aset.c:95-99`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`; `issuer` is a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_issuer(
    isss: *mut OsslIssuerSerial,
    issuer: *const X509Name,
) -> c_int {
    // SAFETY: `isss` is live and its `issuer` slot is writable; `issuer` is the caller's.
    unsafe { replace_dirName(&raw mut (*isss).issuer, issuer) }
}

/// `int OSSL_ISSUER_SERIAL_set1_serial(OSSL_ISSUER_SERIAL *isss, const ASN1_INTEGER *serial)` --
/// `x509aset.c:101-105`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`; `serial` is a live `ASN1_INTEGER`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_serial(
    isss: *mut OsslIssuerSerial,
    serial: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `isss` is live and `serial` is the caller's live source.
    unsafe { ASN1_STRING_copy(&raw mut (*isss).serial, serial) }
}

/// `int OSSL_ISSUER_SERIAL_set1_issuerUID(OSSL_ISSUER_SERIAL *isss, const ASN1_BIT_STRING *uid)`
/// -- `x509aset.c:107-117`.
///
/// Releases the old UID and installs a duplicate of `uid`; a failed duplicate answers 0 with
/// `ERR_R_ASN1_LIB`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`; `uid` is a live `ASN1_BIT_STRING`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_set1_issuerUID(
    isss: *mut OsslIssuerSerial,
    uid: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `isss` is live and its old UID is its own.
    unsafe { ASN1_STRING_free((*isss).issuerUID) };
    // SAFETY: `uid` is live per the contract.
    let dup = unsafe { ASN1_STRING_dup(uid) };
    // SAFETY: `isss` is live and its `issuerUID` slot is writable.
    unsafe { (*isss).issuerUID = dup };
    if dup.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X509ASET_113) };
        return 0;
    }
    1
}

/// `int X509_ACERT_set_version(X509_ACERT *x, long version)` -- `x509aset.c:119-122`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set_version(x: *mut X509Acert, version: c_long) -> c_int {
    // SAFETY: `x` is live and its `acinfo->version` slot is writable.
    unsafe { ASN1_INTEGER_set(&raw mut (*(*x).acinfo).version, version) }
}

/// `void X509_ACERT_set0_holder_entityName(X509_ACERT *x, GENERAL_NAMES *names)` --
/// `x509aset.c:124-128`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `names` is NULL or a stack this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set0_holder_entityName(
    x: *mut X509Acert,
    names: *mut OpenSslStack,
) {
    // SAFETY: `x` is live and its holder's old stack is its own.
    unsafe { GENERAL_NAMES_free((*(*x).acinfo).holder.entityName) };
    // SAFETY: `x` is live and the holder slot is writable.
    unsafe { (*(*x).acinfo).holder.entityName = names };
}

/// `void X509_ACERT_set0_holder_baseCertId(X509_ACERT *x, OSSL_ISSUER_SERIAL *isss)` --
/// `x509aset.c:130-135`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `isss` is NULL or a value this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set0_holder_baseCertId(
    x: *mut X509Acert,
    isss: *mut OsslIssuerSerial,
) {
    // SAFETY: `x` is live and its holder's old issuer-serial is its own.
    unsafe { OSSL_ISSUER_SERIAL_free((*(*x).acinfo).holder.baseCertificateID) };
    // SAFETY: `x` is live and the holder slot is writable.
    unsafe { (*(*x).acinfo).holder.baseCertificateID = isss };
}

/// `void X509_ACERT_set0_holder_digest(X509_ACERT *x, OSSL_OBJECT_DIGEST_INFO *dinfo)` --
/// `x509aset.c:137-142`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `dinfo` is NULL or a value this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set0_holder_digest(
    x: *mut X509Acert,
    dinfo: *mut OsslObjectDigestInfo,
) {
    // SAFETY: `x` is live and its holder's old digest info is its own.
    unsafe { OSSL_OBJECT_DIGEST_INFO_free((*(*x).acinfo).holder.objectDigestInfo) };
    // SAFETY: `x` is live and the holder slot is writable.
    unsafe { (*(*x).acinfo).holder.objectDigestInfo = dinfo };
}

/// `int X509_ACERT_set1_issuerName(X509_ACERT *x, const X509_NAME *name)` -- `x509aset.c:144-162`.
///
/// Only the `v2Form` issuer is supported; the arm is created on the first call and the selector
/// set to `X509_ACERT_ISSUER_V2`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `name` is a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set1_issuerName(
    x: *mut X509Acert,
    name: *const X509Name,
) -> c_int {
    // SAFETY: `x` is live; its issuer union arm is readable.
    let mut v2 = unsafe { (*(*x).acinfo).issuer.u.v2Form };
    if v2.is_null() {
        // SAFETY: `X509_ACERT_ISSUER_V2FORM_new()` answers a fresh value or NULL.
        v2 = X509_ACERT_ISSUER_V2FORM_new();
        if v2.is_null() {
            // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
            unsafe { raise_site(&X509ASET_154) };
            return 0;
        }
        // SAFETY: `x` is live and its issuer union/selector slots are writable.
        unsafe {
            (*(*x).acinfo).issuer.u.v2Form = v2;
            (*(*x).acinfo).issuer.type_ = X509_ACERT_ISSUER_V2;
        }
    }
    // SAFETY: `v2` is the live arm and `name` is the caller's.
    unsafe { replace_dirName(&raw mut (*v2).issuerName, name) }
}

/// `int X509_ACERT_set1_serialNumber(X509_ACERT *x, const ASN1_INTEGER *serial)` --
/// `x509aset.c:164-167`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `serial` is a live `ASN1_INTEGER`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set1_serialNumber(
    x: *mut X509Acert,
    serial: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `x` is live and `serial` is the caller's live source.
    unsafe { ASN1_STRING_copy(&raw mut (*(*x).acinfo).serialNumber, serial) }
}

/// `int X509_ACERT_set1_notBefore(X509_ACERT *x, const ASN1_GENERALIZEDTIME *time)` --
/// `x509aset.c:169-172`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `time` is a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set1_notBefore(
    x: *mut X509Acert,
    time: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `x` is live and its `validityPeriod.notBefore` slot is writable; `time` is the
    // caller's.
    unsafe { replace_gentime(&raw mut (*(*x).acinfo).validityPeriod.notBefore, time) }
}

/// `int X509_ACERT_set1_notAfter(X509_ACERT *x, const ASN1_GENERALIZEDTIME *time)` --
/// `x509aset.c:174-177`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `time` is a live `ASN1_GENERALIZEDTIME`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_set1_notAfter(
    x: *mut X509Acert,
    time: *const crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `x` is live and its `validityPeriod.notAfter` slot is writable; `time` is the
    // caller's.
    unsafe { replace_gentime(&raw mut (*(*x).acinfo).validityPeriod.notAfter, time) }
}
