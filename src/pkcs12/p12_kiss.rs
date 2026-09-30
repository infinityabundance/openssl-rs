//! `crypto/pkcs12/p12_kiss.c` — the simplified read path behind `PKCS12_parse`. Phase 10.
//!
//! The authority unit is 274 lines and one export: `PKCS12_parse` (`include/openssl/pkcs12.h`,
//! `PKCS12_parse`), together with its three `static` workers `parse_pk12` (`:137-177`),
//! `parse_bags` (`:180-192`) and `parse_bag` (`:195-273`). It is the reader that mirrors the
//! write path 10.3/10.15 landed: it unpacks the `authsafes` `PKCS7` container, walks the
//! `SafeBag` stacks, and splits the recovered certificates across the caller's `*cert` and `*ca`
//! slots.
//!
//! ## The whole unit lands here
//!
//! Every name the unit needs is landed. The two MAC probes ([`PKCS12_mac_present`],
//! [`PKCS12_verify_mac`], 10.3/10.4), the four container readers ([`PKCS12_unpack_authsafes`],
//! [`PKCS12_unpack_p7data`], [`PKCS12_unpack_p7encdata`], [`PKCS12_decrypt_skey_ex`], 10.3), the
//! `SafeBag` accessors [`PKCS12_SAFEBAG_get0_attr`], [`PKCS12_SAFEBAG_get_nid`],
//! [`PKCS12_SAFEBAG_get0_p8inf`], [`PKCS12_SAFEBAG_get0_safes`], [`PKCS12_SAFEBAG_get_bag_nid`]
//! and [`PKCS12_SAFEBAG_get1_cert_ex`] (10.2/10.15), [`X509_check_private_key`] (10.14.1),
//! `ossl_evp_pkcs82pkey_ex` (the authority's `EVP_PKCS82PKEY_ex`, 10.11) and the `X509`
//! aux-setter pair [`X509_keyid_set1`]/[`X509_alias_set1`] (10.x) all exist. `PKCS12_parse`'s last
//! remaining blocker — `ossl_x509_add_cert_new` in `crypto/x509/x509_cmp.c` — is the one the
//! parallel Phase 11 slice supplies; this module names it and nothing else.
//!
//! ## The raise sites are declared locally
//!
//! `crypto/pkcs12/p12_kiss.c` is **not** an entry in `forensics/tools/gen_err_raise_sites.py`'s
//! `COVERED_FILES`, so its five `ERR_raise*` coordinates (`:49`, `:67`, `:71`, `:81`, `:90`) are
//! declared here, exactly as `crypto/ct/ct_b64.c`'s are in [`crate::ct::ct_b64`]. Every reason
//! value is read from the installed headers: `PKCS12_R_*` from `include/openssl/pkcs12err.h`,
//! `ERR_LIB_PKCS12` from `include/openssl/err.h.in:100`, and the one generic reason
//! `ERR_R_CRYPTO_LIB` (the `authsafes`-stack allocation failure) from `err.h.in:330`.
//!
//! ## `EVP_PKCS82PKEY_ex` is reached through the crate's internal spelling
//!
//! The authority's `parse_bag` calls `EVP_PKCS82PKEY_ex` at `:215` and `:228`. The crate already
//! transcribes that body once, as `ossl_evp_pkcs82pkey_ex` in `crate::evp::evp_pkey` (published
//! for `pem_pk8.c`): the export row `EVP_PKCS82PKEY_ex` belongs to Phase 11's `x509.h` surface,
//! but the *behaviour* is that landed function, so this module calls it rather than re-deriving
//! it. That is the same posture `crypto/pem/pem_pk8.c` takes.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_uchar, c_ulong, c_void, CStr};
use core::ptr;

use crate::asn1::a_strex::ASN1_STRING_to_UTF8;
use crate::asn1::layout::{Asn1String, V_ASN1_BMPSTRING, V_ASN1_OCTET_STRING};
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_free;
use crate::evp::evp_pkey::ossl_evp_pkcs82pkey_ex;
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::pkcs12::p12_add::{
    PKCS12_decrypt_skey_ex, PKCS12_unpack_authsafes, PKCS12_unpack_p7data, PKCS12_unpack_p7encdata,
};
use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, Pkcs12, Pkcs12Safebag};
use crate::pkcs12::p12_mutl::{PKCS12_mac_present, PKCS12_verify_mac};
use crate::pkcs12::p12_sbag::{
    PKCS12_SAFEBAG_get0_attr, PKCS12_SAFEBAG_get0_p8inf, PKCS12_SAFEBAG_get0_safes,
    PKCS12_SAFEBAG_get1_cert_ex, PKCS12_SAFEBAG_get_bag_nid, PKCS12_SAFEBAG_get_nid,
};
use crate::pkcs7::{PKCS7_free, Pkcs7};
use crate::runtime::err::err_reasons::{
    EVP_R_UNSUPPORTED_ALGORITHM, PKCS12_R_INVALID_NULL_PKCS12_POINTER, PKCS12_R_MAC_VERIFY_FAILURE,
    PKCS12_R_PARSE_ERROR,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{
    peek_last_lib, peek_last_reason, raise_site, ERR_pop_to_mark, ERR_set_mark,
};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    NID_certBag, NID_friendlyName, NID_keyBag, NID_localKeyID, NID_pkcs7_data, NID_pkcs7_encrypted,
    NID_pkcs8ShroudedKeyBag, NID_safeContentsBag, NID_x509Certificate, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_shift, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_cmp::{ossl_x509_add_cert_new, X509_check_private_key};
use crate::x509::x_x509::{X509_free, X509};
use crate::x509::x_x509a::{X509_alias_set1, X509_keyid_set1};

/// `crypto/pkcs12/p12_kiss.c` — the authority's `__FILE__` string for the allocator's
/// bookkeeping.
const FILE: &CStr = c"crypto/pkcs12/p12_kiss.c";
/// `parse_bag`'s `OPENSSL_free(data)` (`:251`), the buffer `ASN1_STRING_to_UTF8` allocates.
const LINE_FREE: c_int = 251;

/// `ERR_LIB_PKCS12` — `include/openssl/err.h.in:100`.
const ERR_LIB_PKCS12: c_int = 35;
/// `ERR_LIB_EVP` — `include/openssl/err.h.in:80`.
const ERR_LIB_EVP: c_int = 6;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `(ERR_LIB_CRYPTO /* 15 */ |
/// ERR_RFLAG_COMMON)`, `ERR_RFLAG_COMMON = 0x2 << ERR_RFLAGS_OFFSET` with `ERR_RFLAGS_OFFSET`
/// `18` (`err.h.in:232`).
const ERR_R_CRYPTO_LIB: c_int = 15 | (0x2 << 18);
/// `X509_ADD_FLAG_DEFAULT` — `include/openssl/x509.h.in:800`.
const X509_ADD_FLAG_DEFAULT: c_int = 0;

/// One `p12_kiss.c` raise coordinate, declared locally (see the module doc). `func` is the
/// authority's `__func__` and `file` its prefixed `__FILE__`, matching the generated table's
/// spelling.
const fn p12_kiss_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/pkcs12/p12_kiss.c",
        line,
        func,
        lib: ERR_LIB_PKCS12,
        reason,
        dynamic_reason: false,
    }
}

/// `PKCS12_parse` at `crypto/pkcs12/p12_kiss.c:49` (`PKCS12_R_INVALID_NULL_PKCS12_POINTER`).
const PKCS12_KISS_49: ErrSite =
    p12_kiss_site(49, c"PKCS12_parse", PKCS12_R_INVALID_NULL_PKCS12_POINTER);
/// `PKCS12_parse` at `crypto/pkcs12/p12_kiss.c:67` (`PKCS12_R_MAC_VERIFY_FAILURE`).
const PKCS12_KISS_67: ErrSite = p12_kiss_site(67, c"PKCS12_parse", PKCS12_R_MAC_VERIFY_FAILURE);
/// `PKCS12_parse` at `crypto/pkcs12/p12_kiss.c:71` (`PKCS12_R_MAC_VERIFY_FAILURE`).
const PKCS12_KISS_71: ErrSite = p12_kiss_site(71, c"PKCS12_parse", PKCS12_R_MAC_VERIFY_FAILURE);
/// `PKCS12_parse` at `crypto/pkcs12/p12_kiss.c:81` (`ERR_R_CRYPTO_LIB`).
const PKCS12_KISS_81: ErrSite = p12_kiss_site(81, c"PKCS12_parse", ERR_R_CRYPTO_LIB);
/// `PKCS12_parse` at `crypto/pkcs12/p12_kiss.c:90` (`PKCS12_R_PARSE_ERROR`).
const PKCS12_KISS_90: ErrSite = p12_kiss_site(90, c"PKCS12_parse", PKCS12_R_PARSE_ERROR);

/// The `X509_free` destructor shape `OPENSSL_sk_pop_free` takes, for the `ocerts` stack the
/// authority releases through `OSSL_STACK_OF_X509_free`.
///
/// # Safety
/// `p` is null or an `X509` this item layer owns.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast::<X509>()) };
}

/// The `PKCS12_SAFEBAG_free` destructor shape for `sk_PKCS12_SAFEBAG_pop_free`.
///
/// # Safety
/// `p` is null or a `PKCS12_SAFEBAG` this item layer owns.
unsafe extern "C" fn safebag_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { PKCS12_SAFEBAG_free(p.cast::<Pkcs12Safebag>()) };
}

/// The `PKCS7_free` destructor shape for `sk_PKCS7_pop_free`.
///
/// # Safety
/// `p` is null or a `PKCS7` this item layer owns.
unsafe extern "C" fn pkcs7_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { PKCS7_free(p.cast::<Pkcs7>()) };
}

/// `static int parse_pk12(PKCS12 *p12, const char *pass, int passlen, EVP_PKEY **pkey,
/// STACK_OF(X509) *ocerts)` — `crypto/pkcs12/p12_kiss.c:137-177`.
///
/// Unpacks the `authsafes` container and walks each decoded `PKCS7`: a `data` contentInfo is read
/// through `PKCS12_unpack_p7data`, an `encrypted` one through `PKCS12_unpack_p7encdata`, and any
/// other content type is skipped with `continue`. Each bag stack is released after it has been
/// walked, and every failure releases the bag stack (when one was produced) and the container
/// stack before answering 0.
///
/// # Safety
/// `p12` is live; `pass` is NULL or a string of `passlen` bytes; `pkey`/`ocerts` are each NULL or
/// the caller's live out-parameter.
unsafe fn parse_pk12(
    p12: *mut Pkcs12,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EvpPkey,
    ocerts: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `p12` is live per the caller's contract.
    let asafes = unsafe { PKCS12_unpack_authsafes(p12) };
    if asafes.is_null() {
        return 0;
    }
    // SAFETY: `asafes` is a live stack of `PKCS7`.
    let n = unsafe { OPENSSL_sk_num(asafes) };
    for i in 0..n {
        // SAFETY: `i` is within `asafes`.
        let p7 = unsafe { OPENSSL_sk_value(asafes, i) }.cast::<Pkcs7>();
        // SAFETY: `p7` is a live element of `asafes` and its `type_` is its own object.
        let bagnid = unsafe { OBJ_obj2nid((*p7).type_) };
        let bags = if bagnid == NID_pkcs7_data {
            // SAFETY: the selector says `p7` is a `data` contentInfo.
            unsafe { PKCS12_unpack_p7data(p7) }
        } else if bagnid == NID_pkcs7_encrypted {
            // SAFETY: the selector says `p7` is an `encrypted` contentInfo; `pass`/`passlen` are
            // the caller's.
            unsafe { PKCS12_unpack_p7encdata(p7, pass, passlen) }
        } else {
            continue;
        };
        if bags.is_null() {
            // SAFETY: `asafes` is this frame's stack of `PKCS7`.
            unsafe { OPENSSL_sk_pop_free(asafes, Some(pkcs7_free_void)) };
            return 0;
        }
        // SAFETY: `bags` is a live stack of `PKCS12_SAFEBAG`; `p7` is live and its context
        // columns are the decode context.
        let ok = unsafe {
            parse_bags(
                bags,
                pass,
                passlen,
                pkey,
                ocerts,
                (*p7).ctx.libctx,
                (*p7).ctx.propq,
            )
        };
        if ok == 0 {
            // SAFETY: both stacks are this frame's; the bag stack's elements are released with it.
            unsafe {
                OPENSSL_sk_pop_free(bags, Some(safebag_free_void));
                OPENSSL_sk_pop_free(asafes, Some(pkcs7_free_void));
            }
            return 0;
        }
        // SAFETY: `bags` is this frame's stack of `PKCS12_SAFEBAG`.
        unsafe { OPENSSL_sk_pop_free(bags, Some(safebag_free_void)) };
    }
    // SAFETY: `asafes` is this frame's stack of `PKCS7`.
    unsafe { OPENSSL_sk_pop_free(asafes, Some(pkcs7_free_void)) };
    1
}

/// `static int parse_bags(const STACK_OF(PKCS12_SAFEBAG) *bags, const char *pass, int passlen,
/// EVP_PKEY **pkey, STACK_OF(X509) *ocerts, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/pkcs12/p12_kiss.c:180-192`.
///
/// Walks a bag stack in place, refusing as soon as one bag refuses.
///
/// # Safety
/// `bags` is NULL or a live stack of `PKCS12_SAFEBAG`; the remaining arguments are the caller's
/// for [`parse_bag`].
unsafe fn parse_bags(
    bags: *const OpenSslStack,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EvpPkey,
    ocerts: *mut OpenSslStack,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `bags` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(bags) };
    for i in 0..n {
        // SAFETY: `i` is within `bags`.
        let bag = unsafe { OPENSSL_sk_value(bags, i) }.cast::<Pkcs12Safebag>();
        // SAFETY: `bag` is a live element of `bags`; the context arguments are the caller's.
        if unsafe { parse_bag(bag, pass, passlen, pkey, ocerts, libctx, propq) } == 0 {
            return 0;
        }
    }
    1
}

/// `static int parse_bag(PKCS12_SAFEBAG *bag, const char *pass, int passlen, EVP_PKEY **pkey,
/// STACK_OF(X509) *ocerts, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crypto/pkcs12/p12_kiss.c:195-273`.
///
/// Reads the bag's `friendlyName` and `localKeyID` attributes first — a wrong attribute *type*
/// refuses the whole parse, not just the bag — then dispatches on the bag's own `BAG-TYPE` NID.
/// A `keyBag`/`pkcs8ShroudedKeyBag` supplies `*pkey` once; a `certBag`/`x509Certificate` is
/// stamped with the key id and alias and pushed onto `ocerts`; a `safeContentsBag` recurses; any
/// other bag is ignored.
///
/// # Safety
/// `bag` is live; `pass` is NULL or a string of `passlen` bytes; `pkey`/`ocerts` are each NULL or
/// the caller's live out-parameter; `libctx`/`propq` are the decode context.
unsafe fn parse_bag(
    bag: *mut Pkcs12Safebag,
    pass: *const c_char,
    passlen: c_int,
    pkey: *mut *mut EvpPkey,
    ocerts: *mut OpenSslStack,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: `bag` is live.
    let attrib = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName) };
    let mut fname: *const Asn1String = ptr::null();
    if !attrib.is_null() {
        // SAFETY: `attrib` is a live `ASN1_TYPE`.
        if unsafe { (*attrib).type_ } != V_ASN1_BMPSTRING {
            return 0;
        }
        // SAFETY: the selector is `V_ASN1_BMPSTRING`, so the union holds the string.
        fname = unsafe { (*attrib).value.ptr.cast::<Asn1String>() };
    }

    // SAFETY: `bag` is live.
    let attrib = unsafe { PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID) };
    let mut lkid: *const Asn1String = ptr::null();
    if !attrib.is_null() {
        // SAFETY: `attrib` is a live `ASN1_TYPE`.
        if unsafe { (*attrib).type_ } != V_ASN1_OCTET_STRING {
            return 0;
        }
        // SAFETY: the selector is `V_ASN1_OCTET_STRING`, so the union holds the string.
        lkid = unsafe { (*attrib).value.ptr.cast::<Asn1String>() };
    }

    // SAFETY: `bag` is live and its `type_` is its own object.
    match unsafe { PKCS12_SAFEBAG_get_nid(bag) } {
        NID_keyBag => {
            // SAFETY: `pkey` is the caller's out-parameter.
            if pkey.is_null() || unsafe { !(*pkey).is_null() } {
                return 1;
            }
            // SAFETY: `bag` is a `keyBag`, so `get0_p8inf` borrows its live private key; the
            // context arguments are the caller's.
            let key =
                unsafe { ossl_evp_pkcs82pkey_ex(PKCS12_SAFEBAG_get0_p8inf(bag), libctx, propq) };
            // SAFETY: `pkey` is the caller's out-slot.
            unsafe { *pkey = key };
            if key.is_null() {
                return 0;
            }
        }
        NID_pkcs8ShroudedKeyBag => {
            // SAFETY: `pkey` is the caller's out-parameter.
            if pkey.is_null() || unsafe { !(*pkey).is_null() } {
                return 1;
            }
            // SAFETY: `bag` is live; `pass`/`passlen`/`libctx`/`propq` are the caller's.
            let p8 = unsafe { PKCS12_decrypt_skey_ex(bag, pass, passlen, libctx, propq) };
            if p8.is_null() {
                return 0;
            }
            // SAFETY: `p8` is live and the context arguments are the caller's.
            let key = unsafe { ossl_evp_pkcs82pkey_ex(p8, libctx, propq) };
            // SAFETY: `pkey` is the caller's out-slot.
            unsafe { *pkey = key };
            // SAFETY: `p8` is this frame's and has been consumed by the conversion.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            if key.is_null() {
                return 0;
            }
        }
        NID_certBag => {
            // SAFETY: `bag` is live and its inner `BAG-TYPE` is its own object.
            if ocerts.is_null() || unsafe { PKCS12_SAFEBAG_get_bag_nid(bag) } != NID_x509Certificate
            {
                return 1;
            }
            // SAFETY: `bag` is a `certBag` holding an `x509Certificate`; the context arguments
            // are the caller's.
            let x509 = unsafe { PKCS12_SAFEBAG_get1_cert_ex(bag, libctx, propq) };
            if x509.is_null() {
                return 0;
            }
            if !lkid.is_null() {
                // SAFETY: `lkid` is a live `OCTET STRING` and `x509` is live.
                if unsafe { X509_keyid_set1(x509, (*lkid).data, (*lkid).length) } == 0 {
                    // SAFETY: `x509` is this frame's on this failure path.
                    unsafe { X509_free(x509) };
                    return 0;
                }
            }
            if !fname.is_null() {
                let mut data: *mut c_uchar = ptr::null_mut();
                // SAFETY: `fname` is a live BMP string; `data` is this frame's out-slot.
                let len = unsafe { ASN1_STRING_to_UTF8(&raw mut data, fname) };
                if len >= 0 {
                    // SAFETY: `x509` is live and `data` holds `len` bytes.
                    let r = unsafe { X509_alias_set1(x509, data, len) };
                    // SAFETY: `data` is the buffer `ASN1_STRING_to_UTF8` allocated.
                    unsafe { CRYPTO_free(data.cast::<c_void>(), FILE.as_ptr(), LINE_FREE) };
                    if r == 0 {
                        // SAFETY: `x509` is this frame's on this failure path.
                        unsafe { X509_free(x509) };
                        return 0;
                    }
                }
            }
            // SAFETY: `ocerts` is a live stack and `x509` is this frame's.
            if unsafe { OPENSSL_sk_push(ocerts, x509.cast::<c_void>()) } == 0 {
                // SAFETY: the stack refused `x509`, so this frame still owns it.
                unsafe { X509_free(x509) };
                return 0;
            }
        }
        NID_safeContentsBag => {
            // SAFETY: `bag` is a `safeContentsBag`, so `get0_safes` borrows its live inner stack;
            // the remaining arguments are the caller's.
            return unsafe {
                parse_bags(
                    PKCS12_SAFEBAG_get0_safes(bag),
                    pass,
                    passlen,
                    pkey,
                    ocerts,
                    libctx,
                    propq,
                )
            };
        }
        _ => return 1,
    }
    1
}

/// `int PKCS12_parse(PKCS12 *p12, const char *pass, EVP_PKEY **pkey, X509 **cert,
/// STACK_OF(X509) **ca)` — `crypto/pkcs12/p12_kiss.c:35-131`.
///
/// Parses and decrypts a PKCS#12 structure, returning the user key, the user certificate matching
/// it, and the other (CA) certificates the caller asked for. Either `ca` is NULL, `*ca` is NULL,
/// or it points to a valid stack; `pkey` and/or `cert` may be NULL.
///
/// The MAC is checked first when one is present: a NULL or empty password is tried both ways
/// (NULL and the empty string are distinct under PKCS#12 PBE), and any other password is verified
/// whole. The recovered certificates are then split: the first one that matches `*pkey` becomes
/// `*cert` (the `ERR_set_mark`/`ERR_pop_to_mark` pair hides `X509_check_private_key`'s internal
/// error), and the rest are appended to `*ca` through `ossl_x509_add_cert_new` or released when
/// `ca` is NULL. Every failure path releases what it had built and answers 0.
///
/// # Safety
/// `p12` is a live `PKCS12` whose `authsafes` column is set, or NULL; `pass` is NULL or a
/// NUL-terminated password; `pkey`, `cert` and `ca` are each NULL or a live out-parameter of
/// their type. The key, certificate and stack handed back are owned by the caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_parse(
    p12: *mut Pkcs12,
    pass: *const c_char,
    pkey: *mut *mut EvpPkey,
    cert: *mut *mut X509,
    ca: *mut *mut OpenSslStack,
) -> c_int {
    let mut ocerts: *mut OpenSslStack = ptr::null_mut();
    let mut x: *mut X509 = ptr::null_mut();

    if !pkey.is_null() {
        // SAFETY: `pkey` is the caller's out-slot.
        unsafe { *pkey = ptr::null_mut() };
    }
    if !cert.is_null() {
        // SAFETY: `cert` is the caller's out-slot.
        unsafe { *cert = ptr::null_mut() };
    }

    if p12.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&PKCS12_KISS_49) };
        return 0;
    }

    let mut pass = pass;
    // SAFETY: the short-circuit leaves `pass` non-NULL before the dereference.
    let pass_empty = pass.is_null() || unsafe { *pass == b'\0' as c_char };
    'err: {
        // SAFETY: `p12` is live per the caller's contract.
        if unsafe { PKCS12_mac_present(p12) } != 0 {
            if pass_empty {
                // SAFETY: `p12` is live; a NULL password of length 0 is one of the two spellings.
                if unsafe { PKCS12_verify_mac(p12, ptr::null(), 0) } != 0 {
                    pass = ptr::null();
                // SAFETY: `p12` is live; the empty string is the other spelling.
                } else if unsafe { PKCS12_verify_mac(p12, c"".as_ptr(), 0) } != 0 {
                    pass = c"".as_ptr();
                } else {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&PKCS12_KISS_67) };
                    break 'err;
                }
            // SAFETY: `p12` is live and `pass` is a NUL-terminated password.
            } else if unsafe { PKCS12_verify_mac(p12, pass, -1) } == 0 {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PKCS12_KISS_71) };
                break 'err;
            }
        } else if pass_empty {
            pass = ptr::null();
        }

        /* If needed, allocate stack for other certificates */
        if !cert.is_null() || !ca.is_null() {
            // The stack for the certificates the caller did not ask to be split out.
            ocerts = OPENSSL_sk_new_null();
            if ocerts.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PKCS12_KISS_81) };
                break 'err;
            }
        }

        // SAFETY: `p12` is live; the out-slots and `ocerts` are the caller's/this frame's.
        if unsafe { parse_pk12(p12, pass, -1, pkey, ocerts) } == 0 {
            // SAFETY: `peek_last_lib`/`peek_last_reason` read this thread's own queue.
            let lib = peek_last_lib();
            let reason = peek_last_reason();

            if lib != ERR_LIB_EVP as c_ulong && reason != EVP_R_UNSUPPORTED_ALGORITHM as c_ulong {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&PKCS12_KISS_90) };
            }
            break 'err;
        }

        /* Split the certs in ocerts over *cert and *ca as far as requested */
        loop {
            // SAFETY: `ocerts` is a live stack (the loop left the stack non-empty).
            x = unsafe { OPENSSL_sk_shift(ocerts) }.cast::<X509>();
            if x.is_null() {
                break;
            }
            if !pkey.is_null()
                // SAFETY: `pkey` is non-NULL, so its slot is readable.
                && unsafe { !(*pkey).is_null() }
                && !cert.is_null()
                // SAFETY: `cert` is non-NULL, so its slot is readable.
                && unsafe { (*cert).is_null() }
            {
                // SAFETY: the mark functions touch this thread's own error queue.
                ERR_set_mark();
                // SAFETY: `x` is a live certificate and `*pkey` its candidate private key.
                let matched = unsafe { X509_check_private_key(x, *pkey) };
                // SAFETY: as above.
                ERR_pop_to_mark();
                if matched != 0 {
                    // SAFETY: `cert` is the caller's out-slot.
                    unsafe { *cert = x };
                    continue;
                }
            }

            if !ca.is_null() {
                // SAFETY: `ca` is the caller's out-stack-pointer slot; `x` is live and owned here.
                if unsafe { ossl_x509_add_cert_new(ca, x, X509_ADD_FLAG_DEFAULT) } == 0 {
                    break 'err;
                }
                continue;
            }
            // SAFETY: nobody claimed `x`, so this frame releases it.
            unsafe { X509_free(x) };
        }
        // SAFETY: the stack itself is this frame's; its elements have been shifted out.
        unsafe { OPENSSL_sk_free(ocerts) };

        return 1;
    }

    // err:
    if !pkey.is_null() {
        // SAFETY: `pkey` is the caller's out-slot.
        unsafe {
            EVP_PKEY_free(*pkey);
            *pkey = ptr::null_mut();
        }
    }
    if !cert.is_null() {
        // SAFETY: `cert` is the caller's out-slot.
        unsafe {
            X509_free(*cert);
            *cert = ptr::null_mut();
        }
    }
    // SAFETY: `x` is NULL or a live certificate this frame owns on the failure path.
    unsafe { X509_free(x) };
    // SAFETY: `ocerts` is NULL or this frame's stack of `X509`.
    unsafe { OPENSSL_sk_pop_free(ocerts, Some(x509_free_void)) };
    0
}
