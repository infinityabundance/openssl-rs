//! Phase 10.14.1 — `crypto/x509/x509_cmp.c`: the certificate comparison and accessor surface.
//!
//! `crypto/x509/x509_cmp.c` is 594 lines and publishes thirty-two functions. **This module lands
//! all thirty-two**: the issuer-and-serial / issuer / subject comparators, the two `X509`
//! name hashes and their `X509_NAME` lower halves, the two `X509_find_by_*` searches, the
//! `X509_get0_pubkey`/`X509_get_pubkey` pair and `X509_check_private_key` with its `ossl_`
//! helper, the Suite-B checks, `X509_chain_up_ref`, and — landed once their closure closed —
//! `X509_cmp` (`:152-179`) together with the four-name add family: `ossl_x509_add_cert_new`
//! (`:181-188`), `X509_add_cert` (`:190-226`), `X509_add_certs` (`:228-236`) and
//! `ossl_x509_add_certs_new` (`:238-253`). Nothing is withheld.
//!
//! The add family was the last to land because it is a single strongly-connected closure:
//! `X509_add_cert` calls `X509_cmp` and `X509_self_signed`, and `X509_cmp` calls
//! `X509_check_purpose`. With `X509_check_purpose` (`v3_purp.c`, 10.14) and `X509_self_signed`
//! (`x509_vfy.rs`, 10.14.12) now landed, the closure is complete, so the five names are
//! transcribed rather than withheld.
//!
//! ## The comparison result is not the `memcmp` value
//!
//! Every comparator normalises: `X509_CRL_match` and `X509_cmp` answer `-1`/`0`/`1` rather than
//! the raw `memcmp` value, and the name comparators are the difference `a->canon_enclen -
//! b->canon_enclen` negated to a sign. That normalisation is the contract — a `STACK` comparator
//! and a caller's `== 0` test both depend on it, not on the magnitude — so the transcription
//! normalises at the same points the authority does.
//!
//! `X509_issuer_and_serial_cmp` and `X509_NAME_cmp` both treat a NULL `b` as "greater than a
//! non-NULL `a`" and a NULL `a` as "less than"; that asymmetry matches `OPENSSL_sk`'s expectation
//! that a NULL element sorts last.
//!
//! ## The `X509_find_by_*` stack-local certificate
//!
//! `X509_find_by_issuer_and_serial` builds a **stack-local `X509` with only two members
//! initialised** and passes it as the second comparator argument; only `serialNumber` and
//! `issuer` are ever read from it. The transcription writes exactly those two fields into
//! `MaybeUninit<X509>` rather than zero-filling the other sixty-odd members, because the
//! authority does not and a zero-filled `issuer`/`key` would be a different object (a NULL
//! `issuer` is what `X509_issuer_and_serial_cmp` reads).
//!
//! ## The raise sites
//!
//! Nine `ERR_raise*` sites in the unit, all now reachable: the four
//! `ossl_x509_check_private_key` refusals (`:406`, `:413`, `:416`, `:419`),
//! `X509_check_private_key`'s "no public key" (`:397`), and the four in the add family —
//! `ossl_x509_add_cert_new`'s failed stack (`:184`), `X509_add_cert`'s NULL stack (`:193`) and
//! failed insert (`:222`), and `X509_add_certs`'s NULL stack (`:232`). All nine are the generated
//! `X509_CMP_*` constants in [`crate::runtime::err::err_sites`]; `crypto/x509/x509_cmp.c` joins
//! `gen_err_raise_sites.py`'s covered set.
//!
//! ## The two Suite-B constants
//!
//! `check_suite_b` reads the `X509_V_FLAG_SUITEB_*` words and writes back `X509_V_ERR_SUITE_B_*`
//! reasons; both families are declared in `include/openssl/x509_vfy.h` and are **not** modelled
//! elsewhere in the crate, so they are transcribed here with their header lines cited rather than
//! pulled from an unlanded `x509_vpm` unit.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_cmp;
use crate::digest::md5_sha1::SHA_DIGEST_LENGTH;
use crate::evp::digest::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EvpMd, EvpMdCtx,
};
use crate::evp::pkey::{EVP_PKEY_eq, EVP_PKEY_get_group_name, EVP_PKEY_is_a, EvpPkey};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_X9_62_prime256v1, NID_ecdsa_with_SHA256, NID_ecdsa_with_SHA384, NID_secp384r1, OBJ_obj2nid,
    OBJ_txt2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_dup, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x509_obj::X509_NAME_oneline;
use crate::x509::x509_set::{X509_get_version, X509_up_ref};
use crate::x509::x509_vfy::X509_self_signed;
use crate::x509::x_crl::X509Crl;
use crate::x509::x_name::{i2d_X509_NAME, X509Name};
use crate::x509::x_pubkey::{X509_PUBKEY_get, X509_PUBKEY_get0};
use crate::x509::x_x509::{X509_free, X509_get_signature_nid, X509};

/// `EXFLAG_NO_FINGERPRINT` — `include/openssl/x509v3.h:450`, the word `X509_CRL_match` and
/// `X509_cmp` test before trusting the cached `sha1_hash`.
const EXFLAG_NO_FINGERPRINT: c_uint = 0x100000;

/// `X509_ADD_FLAG_UP_REF` — `include/openssl/x509.h:995`, the word `X509_add_cert` up-refs each
/// certificate it accepts.
const X509_ADD_FLAG_UP_REF: c_int = 0x1;
/// `X509_ADD_FLAG_PREPEND` — `include/openssl/x509.h:996`, the word selecting the stack end.
const X509_ADD_FLAG_PREPEND: c_int = 0x2;
/// `X509_ADD_FLAG_NO_DUP` — `include/openssl/x509.h:997`, the word that suppresses duplicates.
const X509_ADD_FLAG_NO_DUP: c_int = 0x4;
/// `X509_ADD_FLAG_NO_SS` — `include/openssl/x509.h:998`, the word that rejects self-signed
/// certificates.
const X509_ADD_FLAG_NO_SS: c_int = 0x8;

/// `X509_VERSION_3` — `include/openssl/x509.h:651`'s `2`, the version `X509_chain_check_suiteb`
/// requires of every certificate in a Suite-B chain.
const X509_VERSION_3: c_long = 2;

/// `X509_V_FLAG_SUITEB_128_LOS_ONLY` — `include/openssl/x509_vfy.h:371`.
const X509_V_FLAG_SUITEB_128_LOS_ONLY: c_ulong = 0x10000;
/// `X509_V_FLAG_SUITEB_192_LOS` — `include/openssl/x509_vfy.h:373`.
const X509_V_FLAG_SUITEB_192_LOS: c_ulong = 0x20000;
/// `X509_V_FLAG_SUITEB_128_LOS` — `include/openssl/x509_vfy.h:375`, the union of the two above.
const X509_V_FLAG_SUITEB_128_LOS: c_ulong = 0x30000;

/// `X509_V_OK` — `include/openssl/x509_vfy.h`.
const X509_V_OK: c_int = 0;
/// `X509_V_ERR_SUITE_B_INVALID_VERSION` — `include/openssl/x509_vfy.h:276`.
const X509_V_ERR_SUITE_B_INVALID_VERSION: c_int = 56;
/// `X509_V_ERR_SUITE_B_INVALID_ALGORITHM` — `include/openssl/x509_vfy.h:277`.
const X509_V_ERR_SUITE_B_INVALID_ALGORITHM: c_int = 57;
/// `X509_V_ERR_SUITE_B_INVALID_CURVE` — `include/openssl/x509_vfy.h:278`.
const X509_V_ERR_SUITE_B_INVALID_CURVE: c_int = 58;
/// `X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM` — `include/openssl/x509_vfy.h:279`.
const X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM: c_int = 59;
/// `X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED` — `include/openssl/x509_vfy.h:280`.
const X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED: c_int = 60;
/// `X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256` — `include/openssl/x509_vfy.h:281`.
const X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256: c_int = 61;

/// `SN_md5` — the short name `X509_issuer_and_serial_hash` fetches its MD5 by.
const SN_MD5: &core::ffi::CStr = c"MD5";
/// `OSSL_DIGEST_NAME_MD5` — the registered name `X509_NAME_hash_old` fetches.
const OSSL_DIGEST_NAME_MD5: &core::ffi::CStr = c"MD5";
/// The property query `X509_NAME_hash_old` restricts its MD5 fetch with.
const OSSL_PROPERTY_FIPS: &core::ffi::CStr = c"-fips";

/// `int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b)` — `crypto/x509/x509_cmp.c:19-34`.
///
/// The serial is compared as an `ASN1_INTEGER` first, then the issuer name; the result is
/// normalised to `-1`/`0`/`1`. A NULL `b` is "greater" (the `b == NULL` test answers
/// `a != NULL`), and a NULL `a` is "less".
///
/// # Safety
///
/// `a` and `b` must each be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_and_serial_cmp(a: *const X509, b: *const X509) -> c_int {
    if b.is_null() {
        return c_int::from(!a.is_null());
    }
    if a.is_null() {
        return -1;
    }
    // SAFETY: both pointers are live per the contract.
    let i = unsafe {
        ASN1_INTEGER_cmp(
            &raw const (*a).cert_info.serialNumber,
            &raw const (*b).cert_info.serialNumber,
        )
    };
    if i != 0 {
        return if i < 0 { -1 } else { 1 };
    }
    // SAFETY: the issuer pointers are the live names of live certificates.
    unsafe { X509_NAME_cmp((*a).cert_info.issuer, (*b).cert_info.issuer) }
}

/// `unsigned long X509_issuer_and_serial_hash(X509 *a)` — `crypto/x509/x509_cmp.c:37-69`.
///
/// The MD5 of the `X509_NAME_oneline` rendering followed by the raw serial bytes, folded into the
/// authority's little-endian `unsigned long` from the first four digest bytes. Every failure path
/// falls to the common `err:` tail and answers 0; the fetched `EVP_MD` and context are always
/// released. Compiled only when `OPENSSL_NO_MD5` is unset, which is this profile.
///
/// # Safety
///
/// `a` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_and_serial_hash(a: *mut X509) -> c_ulong {
    let ret: c_ulong = 0;
    let mut md = [0u8; 16];
    let ctx = EVP_MD_CTX_new();
    if ctx.is_null() {
        return ret;
    }
    // SAFETY: `a` is live and `issuer` is its live name.
    let f = unsafe { X509_NAME_oneline((*a).cert_info.issuer, ptr::null_mut(), 0) };
    if f.is_null() {
        return X509_issuer_and_serial_hash_err(ctx, f, ptr::null_mut(), ret);
    }
    // SAFETY: `a` is live; `libctx`/`propq` are its own.
    let digest = unsafe { EVP_MD_fetch((*a).libctx, SN_MD5.as_ptr(), (*a).propq) };
    if digest.is_null() {
        return X509_issuer_and_serial_hash_err(ctx, f, digest, ret);
    }
    // SAFETY: `ctx` and `digest` are live; the update pointers and lengths are valid.
    unsafe {
        if EVP_DigestInit_ex(ctx, digest, ptr::null_mut()) == 0 {
            return X509_issuer_and_serial_hash_err(ctx, f, digest, ret);
        }
        let flen = core::ffi::CStr::from_ptr(f).to_bytes().len();
        if EVP_DigestUpdate(ctx, f.cast::<c_void>(), flen) == 0 {
            return X509_issuer_and_serial_hash_err(ctx, f, digest, ret);
        }
        let slen = (*a).cert_info.serialNumber.length as usize;
        if EVP_DigestUpdate(ctx, (*a).cert_info.serialNumber.data.cast::<c_void>(), slen) == 0 {
            return X509_issuer_and_serial_hash_err(ctx, f, digest, ret);
        }
        if EVP_DigestFinal_ex(ctx, md.as_mut_ptr(), ptr::null_mut()) == 0 {
            return X509_issuer_and_serial_hash_err(ctx, f, digest, ret);
        }
    }
    let ret = ((md[0] as c_ulong)
        | ((md[1] as c_ulong) << 8)
        | ((md[2] as c_ulong) << 16)
        | ((md[3] as c_ulong) << 24))
        & 0xffff_ffff;
    X509_issuer_and_serial_hash_err(ctx, f, digest, ret)
}

/// The shared `err:` tail of [`X509_issuer_and_serial_hash`] — `crypto/x509/x509_cmp.c:64-68`.
///
/// `ctx`/`f`/`digest` are the live locals of the caller or already-released values; the one
/// unsafe call frees each and is safe on a NULL pointer.
fn X509_issuer_and_serial_hash_err(
    ctx: *mut EvpMdCtx,
    f: *mut c_char,
    digest: *mut EvpMd,
    ret: c_ulong,
) -> c_ulong {
    // SAFETY: each pointer is NULL or was returned by the matching allocation.
    unsafe {
        crate::runtime::mem::CRYPTO_free(
            f.cast::<c_void>(),
            c"crypto/x509/x509_cmp.c".as_ptr(),
            65,
        );
        EVP_MD_free(digest);
        EVP_MD_CTX_free(ctx);
    }
    ret
}

/// `int X509_issuer_name_cmp(const X509 *a, const X509 *b)` — `crypto/x509/x509_cmp.c:72-75`.
///
/// # Safety
///
/// `a` and `b` must be live `X509` values.
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_cmp(a: *const X509, b: *const X509) -> c_int {
    // SAFETY: both are live per the contract.
    unsafe { X509_NAME_cmp((*a).cert_info.issuer, (*b).cert_info.issuer) }
}

/// `int X509_subject_name_cmp(const X509 *a, const X509 *b)` — `crypto/x509/x509_cmp.c:77-80`.
///
/// # Safety
///
/// `a` and `b` must be live `X509` values.
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_cmp(a: *const X509, b: *const X509) -> c_int {
    // SAFETY: both are live per the contract.
    unsafe { X509_NAME_cmp((*a).cert_info.subject, (*b).cert_info.subject) }
}

/// `int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b)` —
/// `crypto/x509/x509_cmp.c:82-85`.
///
/// # Safety
///
/// `a` and `b` must be live `X509_CRL` values.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_cmp(a: *const X509Crl, b: *const X509Crl) -> c_int {
    // SAFETY: both are live per the contract.
    unsafe { X509_NAME_cmp((*a).crl.issuer, (*b).crl.issuer) }
}

/// `int X509_CRL_match(const X509_CRL *a, const X509_CRL *b)` —
/// `crypto/x509/x509_cmp.c:87-98`.
///
/// Compares the cached SHA-1 fingerprints when both CRLs carry one. When either has
/// `EXFLAG_NO_FINGERPRINT` set it answers **`-2`** rather than a comparison — a third value the
/// authority defines and a caller distinguishes.
///
/// # Safety
///
/// `a` and `b` must be live `X509_CRL` values.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_match(a: *const X509Crl, b: *const X509Crl) -> c_int {
    // SAFETY: both are live per the contract.
    let (fa, fb) = unsafe { ((*a).flags, (*b).flags) };
    if (fa as c_ulong & EXFLAG_NO_FINGERPRINT as c_ulong) == 0
        && (fb as c_ulong & EXFLAG_NO_FINGERPRINT as c_ulong) == 0
    {
        // SAFETY: the two `sha1_hash` arrays are live and 20 bytes each.
        let ra = unsafe { core::slice::from_raw_parts((*a).sha1_hash.as_ptr(), SHA_DIGEST_LENGTH) };
        // SAFETY: as above.
        let rb = unsafe { core::slice::from_raw_parts((*b).sha1_hash.as_ptr(), SHA_DIGEST_LENGTH) };
        return match ra.cmp(rb) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    -2
}

/// `X509_NAME *X509_get_issuer_name(const X509 *a)` — `crypto/x509/x509_cmp.c:100-103`.
///
/// # Safety
///
/// `a` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_issuer_name(a: *const X509) -> *mut X509Name {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).cert_info.issuer }
}

/// `unsigned long X509_issuer_name_hash(X509 *x)` — `crypto/x509/x509_cmp.c:105-108`.
///
/// The `libctx`/`propq`-less spelling: it passes NULL for all three optional arguments of
/// `X509_NAME_hash_ex`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_hash(x: *mut X509) -> c_ulong {
    // SAFETY: `x` is live and its issuer is the live name.
    unsafe {
        X509_NAME_hash_ex(
            (*x).cert_info.issuer,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
        )
    }
}

/// `unsigned long X509_issuer_name_hash_old(X509 *x)` — `crypto/x509/x509_cmp.c:111-115`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_issuer_name_hash_old(x: *mut X509) -> c_ulong {
    // SAFETY: `x` is live and its issuer is the live name.
    unsafe { X509_NAME_hash_old((*x).cert_info.issuer) }
}

/// `X509_NAME *X509_get_subject_name(const X509 *a)` — `crypto/x509/x509_cmp.c:117-120`.
///
/// # Safety
///
/// `a` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_subject_name(a: *const X509) -> *mut X509Name {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).cert_info.subject }
}

/// `ASN1_INTEGER *X509_get_serialNumber(X509 *a)` — `crypto/x509/x509_cmp.c:122-125`.
///
/// # Safety
///
/// `a` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_serialNumber(a: *mut X509) -> *mut Asn1String {
    // SAFETY: `a` is live per the contract.
    unsafe { &raw mut (*a).cert_info.serialNumber }
}

/// `const ASN1_INTEGER *X509_get0_serialNumber(const X509 *a)` —
/// `crypto/x509/x509_cmp.c:127-130`.
///
/// # Safety
///
/// `a` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_serialNumber(a: *const X509) -> *const Asn1String {
    // SAFETY: `a` is live per the contract.
    unsafe { &raw const (*a).cert_info.serialNumber }
}

/// `unsigned long X509_subject_name_hash(X509 *x)` — `crypto/x509/x509_cmp.c:132-135`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_hash(x: *mut X509) -> c_ulong {
    // SAFETY: `x` is live and its subject is the live name.
    unsafe {
        X509_NAME_hash_ex(
            (*x).cert_info.subject,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
        )
    }
}

/// `unsigned long X509_subject_name_hash_old(X509 *x)` — `crypto/x509/x509_cmp.c:138-142`.
///
/// # Safety
///
/// `x` must be a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_subject_name_hash_old(x: *mut X509) -> c_ulong {
    // SAFETY: `x` is live and its subject is the live name.
    unsafe { X509_NAME_hash_old((*x).cert_info.subject) }
}

/// `int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)` —
/// `crypto/x509/x509_cmp.c:255-283`.
///
/// Ensures each name's canonical encoding is current (`i2d_X509_NAME(x, NULL)`) and then compares
/// the two cached `canon_enc` buffers. A NULL `b` answers `a != NULL` and a NULL `a` answers
/// `-1`. A failure to build the canonical encoding answers **`-2`**, distinct from inequality.
///
/// # Safety
///
/// `a` and `b` must each be NULL or a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_cmp(a: *const X509Name, b: *const X509Name) -> c_int {
    if b.is_null() {
        return c_int::from(!a.is_null());
    }
    if a.is_null() {
        return -1;
    }
    // SAFETY: `a` is live per the contract.
    if unsafe { (*a).canon_enc.is_null() || (*a).modified != 0 } {
        // SAFETY: `i2d_X509_NAME` with a NULL out-pointer only measures/refreshes.
        if unsafe { i2d_X509_NAME(a, ptr::null_mut()) } < 0 {
            return -2;
        }
    }
    // SAFETY: `b` is live per the contract.
    if unsafe { (*b).canon_enc.is_null() || (*b).modified != 0 } {
        // SAFETY: as above.
        if unsafe { i2d_X509_NAME(b, ptr::null_mut()) } < 0 {
            return -2;
        }
    }
    // SAFETY: both names are live; the canonical encodings are current.
    let (la, lb, pa, pb) = unsafe {
        (
            (*a).canon_enclen,
            (*b).canon_enclen,
            (*a).canon_enc,
            (*b).canon_enc,
        )
    };
    let mut ret = la - lb;
    if ret == 0 && la == 0 {
        return 0;
    }
    if ret == 0 {
        if pa.is_null() || pb.is_null() {
            return -2;
        }
        // SAFETY: both buffers are at least `la` bytes.
        let sa = unsafe { core::slice::from_raw_parts(pa, la as usize) };
        // SAFETY: as above.
        let sb = unsafe { core::slice::from_raw_parts(pb, lb as usize) };
        ret = match sa.cmp(sb) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    if ret < 0 {
        -1
    } else {
        c_int::from(ret > 0)
    }
}

/// `unsigned long X509_NAME_hash_ex(const X509_NAME *x, OSSL_LIB_CTX *libctx, const char *propq,
/// int *ok)` — `crypto/x509/x509_cmp.c:290-302`.
///
/// The SHA-1 of the canonical encoding's first four bytes folded into an `unsigned long`. `ok`,
/// when non-NULL, is written 0 at entry and 1 only on the full success path; a NULL `sha1` or a
/// failed `i2d` leaves it 0 and answers 0.
///
/// # Safety
///
/// `x` must be a live `X509_NAME`; `libctx`/`propq` are forwarded to the fetch; `ok` is NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_hash_ex(
    x: *const X509Name,
    libctx: *mut c_void,
    propq: *const c_char,
    ok: *mut c_int,
) -> c_ulong {
    let mut ret: c_ulong = 0;
    let mut md = [0u8; SHA_DIGEST_LENGTH];
    // SAFETY: `libctx`/`propq` are forwarded under the caller's contract.
    let sha1 = unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
    // SAFETY: `x` is live.
    let i2d_ret = unsafe { i2d_X509_NAME(x, ptr::null_mut()) };
    if !ok.is_null() {
        // SAFETY: `ok` is writable.
        unsafe { *ok = 0 };
    }
    if i2d_ret >= 0 && !sha1.is_null() {
        // SAFETY: `x` is live and the canonical encoding is current; `sha1` is live.
        let ok_digest = unsafe {
            EVP_Digest(
                (*x).canon_enc.cast::<c_void>(),
                (*x).canon_enclen as usize,
                md.as_mut_ptr(),
                ptr::null_mut(),
                sha1,
                ptr::null_mut(),
            )
        };
        if ok_digest != 0 {
            ret = ((md[0] as c_ulong)
                | ((md[1] as c_ulong) << 8)
                | ((md[2] as c_ulong) << 16)
                | ((md[3] as c_ulong) << 24))
                & 0xffff_ffff;
            if !ok.is_null() {
                // SAFETY: `ok` is writable.
                unsafe { *ok = 1 };
            }
        }
    }
    // SAFETY: `sha1` is NULL or a fetched method.
    unsafe { EVP_MD_free(sha1) };
    ret
}

/// `unsigned long X509_NAME_hash_old(const X509_NAME *x)` —
/// `crypto/x509/x509_cmp.c:317-328`.
///
/// The MD5 of the name's *cached bytes* (not its canonical encoding) under the `-fips` property,
/// because the authority wants the legacy hash regardless of the default provider's properties.
/// Every failure path reaches `end:` and answers 0.
///
/// # Safety
///
/// `x` must be a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn X509_NAME_hash_old(x: *const X509Name) -> c_ulong {
    // SAFETY: NULL `libctx`, a static property string.
    let md5 = unsafe {
        EVP_MD_fetch(
            ptr::null_mut(),
            OSSL_DIGEST_NAME_MD5.as_ptr(),
            OSSL_PROPERTY_FIPS.as_ptr(),
        )
    };
    let md_ctx = EVP_MD_CTX_new();
    let mut ret: c_ulong = 0;
    let mut md = [0u8; 16];
    if md5.is_null() || md_ctx.is_null() {
        // SAFETY: each pointer is NULL or owned.
        unsafe {
            EVP_MD_CTX_free(md_ctx);
            EVP_MD_free(md5);
        }
        return ret;
    }
    // SAFETY: `x` is live.
    if unsafe { i2d_X509_NAME(x, ptr::null_mut()) } < 0 {
        // SAFETY: each pointer is live.
        unsafe {
            EVP_MD_CTX_free(md_ctx);
            EVP_MD_free(md5);
        }
        return ret;
    }
    // SAFETY: `md_ctx`/`md5` are live; `x->bytes` is the live cached buffer.
    unsafe {
        let bytes = (*x).bytes;
        let updated = !bytes.is_null()
            && EVP_DigestInit_ex(md_ctx, md5, ptr::null_mut()) != 0
            && EVP_DigestUpdate(md_ctx, (*bytes).data.cast::<c_void>(), (*bytes).length) != 0
            && EVP_DigestFinal_ex(md_ctx, md.as_mut_ptr(), ptr::null_mut()) != 0;
        if updated {
            ret = ((md[0] as c_ulong)
                | ((md[1] as c_ulong) << 8)
                | ((md[2] as c_ulong) << 16)
                | ((md[3] as c_ulong) << 24))
                & 0xffff_ffff;
        }
        EVP_MD_CTX_free(md_ctx);
        EVP_MD_free(md5);
    }
    ret
}

/// `X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) *sk, const X509_NAME *name,
/// const ASN1_INTEGER *serial)` — `crypto/x509/x509_cmp.c:345-362`.
///
/// Builds the two-member stack-local certificate described in the module doc and returns the
/// first element that compares equal, or NULL.
///
/// # Safety
///
/// `sk` must be NULL or a live stack of `X509`; `name` and `serial` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_find_by_issuer_and_serial(
    sk: *mut OpenSslStack,
    name: *const X509Name,
    serial: *const Asn1String,
) -> *mut X509 {
    if sk.is_null() {
        return ptr::null_mut();
    }
    // The authority's stack-local `X509 x` with only `serialNumber` and `issuer` written.
    let mut x = core::mem::MaybeUninit::<X509>::uninit();
    let p = x.as_mut_ptr();
    // SAFETY: `serial` is live; only the `serialNumber` field is written.
    unsafe {
        ptr::addr_of_mut!((*p).cert_info.serialNumber).write(ptr::read(serial));
        ptr::addr_of_mut!((*p).cert_info.issuer).write(name.cast_mut());
        let n = OPENSSL_sk_num(sk);
        for i in 0..n {
            let x509 = OPENSSL_sk_value(sk, i).cast::<X509>();
            if X509_issuer_and_serial_cmp(x509, p) == 0 {
                return x509;
            }
        }
    }
    ptr::null_mut()
}

/// `X509 *X509_find_by_subject(STACK_OF(X509) *sk, const X509_NAME *name)` —
/// `crypto/x509/x509_cmp.c:365-376`.
///
/// # Safety
///
/// `sk` must be NULL or a live stack of `X509`; `name` must be live.
#[no_mangle]
pub unsafe extern "C" fn X509_find_by_subject(
    sk: *mut OpenSslStack,
    name: *const X509Name,
) -> *mut X509 {
    // SAFETY: `sk` is NULL or a live stack per the contract.
    unsafe {
        let n = OPENSSL_sk_num(sk);
        for i in 0..n {
            let x509 = OPENSSL_sk_value(sk, i).cast::<X509>();
            if X509_NAME_cmp(X509_get_subject_name(x509), name) == 0 {
                return x509;
            }
        }
    }
    ptr::null_mut()
}

/// `EVP_PKEY *X509_get0_pubkey(const X509 *x)` — `crypto/x509/x509_cmp.c:378-383`.
///
/// A borrowed reference: no up-ref, the caller must not free it.
///
/// # Safety
///
/// `x` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get0_pubkey(x: *const X509) -> *mut EvpPkey {
    if x.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live and `cert_info.key` is its live `X509_PUBKEY`.
    unsafe { X509_PUBKEY_get0((*x).cert_info.key) }
}

/// `EVP_PKEY *X509_get_pubkey(X509 *x)` — `crypto/x509/x509_cmp.c:385-390`.
///
/// An owned reference: the caller frees it with `EVP_PKEY_free`.
///
/// # Safety
///
/// `x` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_get_pubkey(x: *mut X509) -> *mut EvpPkey {
    if x.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `x` is live and `cert_info.key` is its live `X509_PUBKEY`.
    unsafe { X509_PUBKEY_get((*x).cert_info.key) }
}

/// `int X509_check_private_key(const X509 *cert, const EVP_PKEY *pkey)` —
/// `crypto/x509/x509_cmp.c:392-401`.
///
/// Reads the certificate's public key and delegates to [`ossl_x509_check_private_key`], which
/// owns the four reason codes. A certificate whose `X509_PUBKEY` has no decoded key raises
/// `X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY` at `:397`.
///
/// # Safety
///
/// `cert` must be a live `X509`; `pkey` must be a live `EVP_PKEY`.
#[no_mangle]
pub unsafe extern "C" fn X509_check_private_key(cert: *const X509, pkey: *const EvpPkey) -> c_int {
    // SAFETY: `cert` is live per the contract.
    let xk = unsafe { X509_get0_pubkey(cert) };
    if xk.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&err_sites::X509_CMP_397) };
        return 0;
    }
    // SAFETY: `xk` is the certificate's live public key.
    unsafe { ossl_x509_check_private_key(xk, pkey) }
}

/// `int ossl_x509_check_private_key(const EVP_PKEY *x, const EVP_PKEY *pkey)` —
/// `crypto/x509/x509_cmp.c:403-424`.
///
/// The shared body of the public check. `EVP_PKEY_eq`'s four answers map to the authority's
/// four arms, the `-2` arm falling through to the default so both `-2` and any other value
/// answer 0 after the `UNKNOWN_KEY_TYPE` raise.
///
/// # Safety
///
/// `x` and `pkey` must be live `EVP_PKEY` values.
#[no_mangle]
pub unsafe extern "C" fn ossl_x509_check_private_key(
    x: *const EvpPkey,
    pkey: *const EvpPkey,
) -> c_int {
    if x.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&err_sites::X509_CMP_406) };
        return 0;
    }
    // SAFETY: `x` and `pkey` are live per the contract.
    match unsafe { EVP_PKEY_eq(x, pkey) } {
        1 => 1,
        0 => {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&err_sites::X509_CMP_413) };
            0
        }
        -1 => {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&err_sites::X509_CMP_416) };
            0
        }
        -2 => {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&err_sites::X509_CMP_419) };
            0
        }
        _ => 0,
    }
}

/// `static int check_suite_b(EVP_PKEY *pkey, int sign_nid, unsigned long *pflags)` —
/// `crypto/x509/x509_cmp.c:434-469`.
///
/// The two-curve Suite-B rule: a P-384 key clears `SUITEB_128_LOS_ONLY` from `*pflags`, a P-256
/// key requires it, and the signature NID (when `sign_nid != -1`) must match the curve's.
///
/// # Safety
///
/// `pkey` must be NULL or a live `EVP_PKEY`; `pflags` must be writable.
unsafe fn check_suite_b(pkey: *mut EvpPkey, sign_nid: c_int, pflags: *mut c_ulong) -> c_int {
    if pkey.is_null() {
        return X509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    }
    // SAFETY: `pkey` is live.
    if unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } == 0 {
        return X509_V_ERR_SUITE_B_INVALID_ALGORITHM;
    }
    let mut curve_name = [0 as c_char; 80];
    let mut curve_name_len: usize = 0;
    // SAFETY: `pkey` is live and the buffer is 80 writable bytes.
    if unsafe {
        EVP_PKEY_get_group_name(
            pkey,
            curve_name.as_mut_ptr(),
            curve_name.len(),
            &raw mut curve_name_len,
        )
    } == 0
    {
        return X509_V_ERR_SUITE_B_INVALID_CURVE;
    }
    // SAFETY: the buffer was NUL-terminated by the getter.
    let curve_nid = unsafe { OBJ_txt2nid(curve_name.as_ptr()) };
    // SAFETY: `pflags` is writable per the contract; read once and written back once so the
    // caller's `tflags` sees exactly the P-384 clearing the authority performs.
    let mut pf = unsafe { *pflags };
    if curve_nid == NID_secp384r1 {
        if sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA384 {
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        }
        if pf & X509_V_FLAG_SUITEB_192_LOS == 0 {
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        }
        pf &= !X509_V_FLAG_SUITEB_128_LOS_ONLY;
    } else if curve_nid == NID_X9_62_prime256v1 {
        if sign_nid != -1 && sign_nid != NID_ecdsa_with_SHA256 {
            return X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM;
        }
        if pf & X509_V_FLAG_SUITEB_128_LOS_ONLY == 0 {
            return X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED;
        }
    } else {
        return X509_V_ERR_SUITE_B_INVALID_CURVE;
    }
    // SAFETY: `pflags` is writable per the contract.
    unsafe { *pflags = pf };
    X509_V_OK
}

/// `int X509_chain_check_suiteb(int *perror_depth, X509 *x, STACK_OF(X509) *chain,
/// unsigned long flags)` — `crypto/x509/x509_cmp.c:470-544`.
///
/// Walks the chain checking each certificate's key against its issuer's signature NID. A NULL
/// `x` starts at the chain's first element; a NULL `chain` asks only about the leaf key. The
/// authority's two `goto end` paths are folded into one exit that applies the "error belongs to
/// the previous certificate" correction and the P-384-with-P-256 relabel.
///
/// # Safety
///
/// `perror_depth` must be NULL or writable; `x` must be NULL or live; `chain` must be NULL or a
/// live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_chain_check_suiteb(
    perror_depth: *mut c_int,
    x: *mut X509,
    chain: *mut OpenSslStack,
    flags: c_ulong,
) -> c_int {
    if flags & X509_V_FLAG_SUITEB_128_LOS == 0 {
        return X509_V_OK;
    }
    let mut x = x;
    let mut i;
    if x.is_null() {
        // SAFETY: `chain` is a live stack here (the caller passed a NULL cert with a chain).
        x = unsafe { OPENSSL_sk_value(chain, 0).cast::<X509>() };
        i = 1;
    } else {
        i = 0;
    }
    let mut tflags = flags;
    // SAFETY: `x` is live.
    let mut pk = unsafe { X509_get0_pubkey(x) };
    if chain.is_null() {
        // SAFETY: `pk` is live or NULL; `check_suite_b` handles NULL; `tflags` is writable.
        return unsafe { check_suite_b(pk, -1, &raw mut tflags) };
    }
    let mut rv;
    // SAFETY: `x` is live.
    if unsafe { X509_get_version(x) } != X509_VERSION_3 {
        rv = X509_V_ERR_SUITE_B_INVALID_VERSION;
        i = 0;
        return suite_b_end(perror_depth, rv, i, flags, tflags);
    }
    // SAFETY: `pk` is live or NULL; `tflags` is writable.
    rv = unsafe { check_suite_b(pk, -1, &raw mut tflags) };
    if rv != X509_V_OK {
        i = 0;
        return suite_b_end(perror_depth, rv, i, flags, tflags);
    }
    // SAFETY: `chain` is live per the contract.
    let n = unsafe { OPENSSL_sk_num(chain) };
    while i < n {
        // SAFETY: `x` is live.
        let sign_nid = unsafe { X509_get_signature_nid(x) };
        // SAFETY: `i` is within `0..n`.
        x = unsafe { OPENSSL_sk_value(chain, i).cast::<X509>() };
        // SAFETY: `x` is live.
        if unsafe { X509_get_version(x) } != X509_VERSION_3 {
            rv = X509_V_ERR_SUITE_B_INVALID_VERSION;
            return suite_b_end(perror_depth, rv, i, flags, tflags);
        }
        // SAFETY: `x` is live.
        pk = unsafe { X509_get0_pubkey(x) };
        // SAFETY: `pk` is live or NULL; `tflags` is writable.
        rv = unsafe { check_suite_b(pk, sign_nid, &raw mut tflags) };
        if rv != X509_V_OK {
            return suite_b_end(perror_depth, rv, i, flags, tflags);
        }
        i += 1;
    }
    // SAFETY: `x` is live.
    let sign_nid = unsafe { X509_get_signature_nid(x) };
    // SAFETY: `pk` is live or NULL; `tflags` is writable.
    rv = unsafe { check_suite_b(pk, sign_nid, &raw mut tflags) };
    suite_b_end(perror_depth, rv, i, flags, tflags)
}

/// The authority's `end:` label of [`X509_chain_check_suiteb`] —
/// `crypto/x509/x509_cmp.c:530-540`.
///
/// `perror_depth` must be NULL or writable; the one unsafe write is guarded by a null test.
fn suite_b_end(
    perror_depth: *mut c_int,
    mut rv: c_int,
    mut i: c_int,
    flags: c_ulong,
    tflags: c_ulong,
) -> c_int {
    if rv != X509_V_OK {
        if (rv == X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM
            || rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED)
            && i != 0
        {
            i -= 1;
        }
        if rv == X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED && flags != tflags {
            rv = X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256;
        }
        if !perror_depth.is_null() {
            // SAFETY: `perror_depth` is writable per the contract.
            unsafe { *perror_depth = i };
        }
    }
    rv
}

/// `int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags)` —
/// `crypto/x509/x509_cmp.c:546-553`.
///
/// # Safety
///
/// `crl` must be a live `X509_CRL`; `pk` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn X509_CRL_check_suiteb(
    crl: *mut X509Crl,
    pk: *mut EvpPkey,
    flags: c_ulong,
) -> c_int {
    if flags & X509_V_FLAG_SUITEB_128_LOS == 0 {
        return X509_V_OK;
    }
    // SAFETY: `crl` is live per the contract.
    let sign_nid = unsafe { OBJ_obj2nid((*crl).crl.sig_alg.algorithm) };
    let mut f = flags;
    // SAFETY: `pk` is live or NULL; `f` is a writable local.
    unsafe { check_suite_b(pk, sign_nid, &raw mut f) }
}

/// `STACK_OF(X509) *X509_chain_up_ref(STACK_OF(X509) *chain)` —
/// `crypto/x509/x509_cmp.c:574-590`.
///
/// Duplicates the stack and up-refs every element. On a failed up-ref it frees the elements it
/// had already up-ref'd and the duplicate stack, then answers NULL; the caller's stack is
/// untouched.
///
/// # Safety
///
/// `chain` must be a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_chain_up_ref(chain: *mut OpenSslStack) -> *mut OpenSslStack {
    // SAFETY: `chain` is live per the contract.
    let ret = unsafe { OPENSSL_sk_dup(chain) };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is the live duplicate.
    let n = unsafe { OPENSSL_sk_num(ret) };
    let mut i = 0;
    while i < n {
        // SAFETY: `i` is within `0..n`.
        let x = unsafe { OPENSSL_sk_value(ret, i).cast::<X509>() };
        // SAFETY: `x` is a live certificate.
        if unsafe { X509_up_ref(x) } == 0 {
            // Unwind: free the elements up-ref'd so far, then the stack itself.
            // SAFETY: `i` is the count already up-ref'd; each is live.
            unsafe {
                while i > 0 {
                    i -= 1;
                    X509_free(OPENSSL_sk_value(ret, i).cast::<X509>());
                }
                OPENSSL_sk_free(ret);
            }
            return ptr::null_mut();
        }
        i += 1;
    }
    ret
}

/// `int X509_cmp(const X509 *a, const X509 *b)` — `crypto/x509/x509_cmp.c:152-179`.
///
/// Identical certificates compare equal. The two `const` certificates are cast to mutable: the
/// pointer-identity fast path comes first, then `X509_check_purpose` (which caches the extension
/// flags `X509_ADD_FLAG_NO_SS` and the fingerprint below read), then the cached SHA-1
/// fingerprints, then the stored DER encodings. The result is normalised to `-1`/`0`/`1`; a
/// certificate with `EXFLAG_NO_FINGERPRINT` skips the fingerprint step.
///
/// # Safety
///
/// `a` and `b` must be live `X509` values (the authority's documented "evil cast" is the reason
/// the contract is `live`, not `const`).
#[no_mangle]
pub unsafe extern "C" fn X509_cmp(a: *const X509, b: *const X509) -> c_int {
    if a == b {
        return 0;
    }
    // The authority casts the two `const` certificates to non-const to refresh their caches.
    // SAFETY: `a` and `b` are live per the contract.
    unsafe {
        let _ = X509_check_purpose(a.cast_mut(), -1, 0);
        let _ = X509_check_purpose(b.cast_mut(), -1, 0);
    }
    let mut rv = 0;
    // SAFETY: both are live per the contract.
    let (fa, fb) = unsafe { ((*a).ex_flags, (*b).ex_flags) };
    if (fa & EXFLAG_NO_FINGERPRINT) == 0 && (fb & EXFLAG_NO_FINGERPRINT) == 0 {
        // SAFETY: both certificates are live and each `sha1_hash` is `SHA_DIGEST_LENGTH` bytes.
        let ra = unsafe { core::slice::from_raw_parts((*a).sha1_hash.as_ptr(), SHA_DIGEST_LENGTH) };
        // SAFETY: as above.
        let rb = unsafe { core::slice::from_raw_parts((*b).sha1_hash.as_ptr(), SHA_DIGEST_LENGTH) };
        rv = match ra.cmp(rb) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    if rv != 0 {
        return if rv < 0 { -1 } else { 1 };
    }
    // Check for a match against the stored encoding too.
    // SAFETY: both are live per the contract.
    let (ma, mb) = unsafe { ((*a).cert_info.enc.modified, (*b).cert_info.enc.modified) };
    if ma == 0 && mb == 0 {
        // SAFETY: both are live per the contract.
        let (la, lb) = unsafe { ((*a).cert_info.enc.len, (*b).cert_info.enc.len) };
        if la < lb {
            return -1;
        }
        if la > lb {
            return 1;
        }
        // SAFETY: both encodings are current and each buffer holds at least `la` bytes.
        let sa = unsafe { core::slice::from_raw_parts((*a).cert_info.enc.enc, la as usize) };
        // SAFETY: as above.
        let sb = unsafe { core::slice::from_raw_parts((*b).cert_info.enc.enc, lb as usize) };
        rv = match sa.cmp(sb) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    if rv < 0 {
        -1
    } else {
        c_int::from(rv > 0)
    }
}

/// `int ossl_x509_add_cert_new(STACK_OF(X509) **p_sk, X509 *cert, int flags)` —
/// `crypto/x509/x509_cmp.c:181-188`.
///
/// Creates the stack when `*p_sk` is NULL, then delegates to [`X509_add_cert`]. A failed stack
/// allocation raises `ERR_R_CRYPTO_LIB` at `:184`.
///
/// # Safety
///
/// `p_sk` must point to a writable `*mut OpenSslStack` slot; `cert` must be a live `X509`.
/// Internal to the crate (not exported by the authority's DSO), so no `#[no_mangle]`.
pub unsafe extern "C" fn ossl_x509_add_cert_new(
    p_sk: *mut *mut OpenSslStack,
    cert: *mut X509,
    flags: c_int,
) -> c_int {
    // SAFETY: `p_sk` is a live out-pointer per the contract.
    if unsafe { (*p_sk).is_null() } {
        let sk = OPENSSL_sk_new_null();
        // SAFETY: `p_sk` is writable per the contract.
        unsafe { *p_sk = sk };
        if sk.is_null() {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&err_sites::X509_CMP_184) };
            return 0;
        }
    }
    // SAFETY: `*p_sk` is now non-NULL and `cert` is live per the contract.
    unsafe { X509_add_cert(*p_sk, cert, flags) }
}

/// `int X509_add_cert(STACK_OF(X509) *sk, X509 *cert, int flags)` —
/// `crypto/x509/x509_cmp.c:190-226`.
///
/// Adds `cert` to `sk` under `flags`. `NO_DUP` scans with [`X509_cmp`] and answers 1 on a duplicate
/// without reordering the stack; `NO_SS` refuses a self-signed certificate via
/// [`X509_self_signed`]; `UP_REF` moves an owned reference in (and is undone if the insert fails);
/// `PREPEND` inserts at index 0 rather than appending. A NULL stack raises
/// `ERR_R_PASSED_NULL_PARAMETER` (`:193`) and a failed insert raises `ERR_R_CRYPTO_LIB` (`:222`).
///
/// # Safety
///
/// `sk` must be NULL or a live stack of `X509`; `cert` must be NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_add_cert(
    sk: *mut OpenSslStack,
    cert: *mut X509,
    flags: c_int,
) -> c_int {
    if sk.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&err_sites::X509_CMP_193) };
        return 0;
    }
    if cert.is_null() {
        return 0;
    }
    if (flags & X509_ADD_FLAG_NO_DUP) != 0 {
        // The authority deliberately avoids the stack's own comparator and `find`, because that
        // would reorder the stack.
        // SAFETY: `sk` is live per the contract.
        let n = unsafe { OPENSSL_sk_num(sk) };
        for i in 0..n {
            // SAFETY: `i` is within `0..n`.
            let xi = unsafe { OPENSSL_sk_value(sk, i).cast::<X509>() };
            // SAFETY: `xi` and `cert` are live certificates.
            if unsafe { X509_cmp(xi, cert) } == 0 {
                return 1;
            }
        }
    }
    if (flags & X509_ADD_FLAG_NO_SS) != 0 {
        // SAFETY: `cert` is live per the contract.
        let ret = unsafe { X509_self_signed(cert, 0) };
        if ret != 0 {
            return c_int::from(ret > 0);
        }
    }
    if (flags & X509_ADD_FLAG_UP_REF) != 0 {
        // SAFETY: `cert` is live per the contract.
        if unsafe { X509_up_ref(cert) } == 0 {
            return 0;
        }
    }
    // SAFETY: `sk` is live and `cert` is live per the contract.
    if unsafe {
        OPENSSL_sk_insert(
            sk,
            cert.cast::<c_void>(),
            if (flags & X509_ADD_FLAG_PREPEND) != 0 {
                0
            } else {
                -1
            },
        )
    } == 0
    {
        if (flags & X509_ADD_FLAG_UP_REF) != 0 {
            // SAFETY: the up-ref above succeeded, so this releases the reference we took.
            unsafe { X509_free(cert) };
        }
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&err_sites::X509_CMP_222) };
        return 0;
    }
    1
}

/// `int X509_add_certs(STACK_OF(X509) *sk, STACK_OF(X509) *certs, int flags)` —
/// `crypto/x509/x509_cmp.c:228-236`.
///
/// Adds every certificate of `certs` to `sk`. A NULL `sk` raises `ERR_R_PASSED_NULL_PARAMETER`
/// (`:232`) and answers 0; otherwise the work is the `ossl_` helper's. A NULL `certs` is treated
/// as an empty stack (the helper's `num` returns `-1`).
///
/// # Safety
///
/// `sk` must be NULL or a live stack of `X509`; `certs` must be NULL or a live stack of `X509`.
#[no_mangle]
pub unsafe extern "C" fn X509_add_certs(
    sk: *mut OpenSslStack,
    certs: *mut OpenSslStack,
    flags: c_int,
) -> c_int {
    if sk.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&err_sites::X509_CMP_232) };
        return 0;
    }
    let mut p_sk = sk;
    // SAFETY: `p_sk` is the non-NULL stack's address; `certs` is NULL or live per the contract.
    unsafe { ossl_x509_add_certs_new(&raw mut p_sk, certs, flags) }
}

/// `int ossl_x509_add_certs_new(STACK_OF(X509) **p_sk, STACK_OF(X509) *certs, int flags)` —
/// `crypto/x509/x509_cmp.c:238-253`.
///
/// Walks `certs` (NULL counts as empty) in forward order, or reverse order when `PREPEND` is set so
/// the original order is preserved on a prepend stack, delegating each element to
/// [`ossl_x509_add_cert_new`]. Answers 0 as soon as one add fails, else 1.
///
/// # Safety
///
/// `p_sk` must point to a writable `*mut OpenSslStack` slot; `certs` must be NULL or a live stack
/// of `X509`. Internal to the crate (not exported by the authority's DSO), so no `#[no_mangle]`.
pub unsafe extern "C" fn ossl_x509_add_certs_new(
    p_sk: *mut *mut OpenSslStack,
    certs: *mut OpenSslStack,
    flags: c_int,
) -> c_int {
    // SAFETY: `certs` is NULL or live per the contract; `OPENSSL_sk_num` handles NULL (answering
    // -1, which makes the loop below run zero times).
    let n = unsafe { OPENSSL_sk_num(certs) };
    let mut i = 0;
    while i < n {
        let j = if (flags & X509_ADD_FLAG_PREPEND) == 0 {
            i
        } else {
            n - 1 - i
        };
        // SAFETY: `certs` is live and `j` is within `0..n`.
        let cert = unsafe { OPENSSL_sk_value(certs, j).cast::<X509>() };
        // SAFETY: `p_sk` is a live out-pointer and `cert` is live.
        if unsafe { ossl_x509_add_cert_new(p_sk, cert, flags) } == 0 {
            return 0;
        }
        i += 1;
    }
    1
}
