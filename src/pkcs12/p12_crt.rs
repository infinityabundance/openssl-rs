//! `crypto/pkcs12/p12_crt.c` — the `PKCS12_create` worker and the `add_*` family. Phase 10 (10.3).
//!
//! The unit is 409 lines and eleven exports, and **all eleven now land**: the `add_*` family
//! [`PKCS12_add_secret`], [`PKCS12_add_key`]/[`PKCS12_add_key_ex`],
//! [`PKCS12_add_safe`]/[`PKCS12_add_safe_ex`] and [`PKCS12_add_safes`]/[`PKCS12_add_safes_ex`]
//! landed first; 10.15 adds the container builder's two remaining arms [`PKCS12_create`]/
//! [`PKCS12_create_ex`]/[`PKCS12_create_ex2`] and [`PKCS12_add_cert`], with their three static
//! helpers `copy_bag_attr`, `pkcs12_add_cert_bag` and `pkcs12_remove_bag`.
//!
//! [`PKCS12_add_secret`] was the first to land (its only callees are
//! `PKCS12_SAFEBAG_create_secret` from `p12_sbag.rs` and the internal `pkcs12_add_bag`, which uses
//! the `OPENSSL_sk_*` stack functions). **The `PKCS7` subset was then pulled forward** (D441; see
//! [`crate::pkcs7`]) and [`PKCS12_add_safes_ex`]/[`PKCS12_add_safes`] landed on the object it
//! supplies. **D444's Phase 11 subset pull-forward landed `EVP_PKEY2PKCS8`**, which was
//! `PKCS12_add_key(_ex)`'s named blocker, and D443's PBE pull-forward plus 10.3's own
//! `PKCS12_pack_p7encdata_ex` supply `PKCS12_add_safe(_ex)`'s encrypted arm; so both pairs land
//! here.
//!
//! **The container builder was measured, not assumed, and this slice is what the frontier now
//! allows.** `nm --undefined-only` over the authority's `libcrypto-lib-p12_crt.o` had shown the
//! closure of `PKCS12_create(_ex/_ex2)`/`_add_cert` reaching `X509_check_private_key`,
//! `X509_digest`, `X509_alias_get0`, `X509_keyid_get0`, `PKCS12_SAFEBAG_create_cert` and
//! `X509at_add1_attr`; the first five have since landed (10.14.1's `x509_cmp.rs`, 10.14.2's
//! `x_all.rs`, 10.12's `x_x509a.rs`, 10.15's `p12_sbag.rs`) and `X509at_add1_attr` has been
//! landed since 10.11 (`x509_att.rs`), so the builder is transcribed rather than withheld again.
//! Its only remaining unlanded callee, `EVP_PKEY_get_attr`/`_by_NID`, is landed too (Phase 7's
//! `evp_pkey.rs`). The two `pkcs12.h` exports still `open` in the whole stratum belong to
//! `p12_kiss.c`'s `PKCS12_parse` and `store_lib.c`'s `OSSL_STORE_load`.
//!
//! `copy_bag_attr` and the two bag-management helpers raise nothing; the builder's four raise
//! sites (`PKCS12_R_INVALID_NULL_ARGUMENT` once, `PKCS12_R_CALLBACK_FAILED` three times) are now
//! reachable, so `crypto/pkcs12/p12_crt.c` is an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES` and its coordinates are `err_sites::PKCS12_CRT_*`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::layout::V_ASN1_OCTET_STRING;
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_free;
use crate::evp::evp_pkey::{EVP_PKEY_get_attr, EVP_PKEY_get_attr_by_NID, EVP_PKEY2PKCS8};
use crate::evp::legacy_sha::EVP_sha1;
use crate::evp::pkey::EvpPkey;
use crate::pkcs12::p12_add::{PKCS12_pack_authsafes, PKCS12_pack_p7data, PKCS12_pack_p7encdata_ex};
use crate::pkcs12::p12_asn::PKCS12_free;
use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, Pkcs12, Pkcs12Safebag};
use crate::pkcs12::p12_attr::{
    PKCS12_add_friendlyname_utf8, PKCS12_add_localkeyid, PKCS8_add_keyusage,
};
use crate::pkcs12::p12_init::PKCS12_init_ex;
use crate::pkcs12::p12_mutl::PKCS12_set_mac;
use crate::pkcs12::p12_sbag::{
    PKCS12_SAFEBAG_create0_p8inf, PKCS12_SAFEBAG_create_pkcs8_encrypt_ex,
};
use crate::pkcs12::p12_sbag::{PKCS12_SAFEBAG_create_cert, PKCS12_SAFEBAG_create_secret};
use crate::pkcs7::pk7_asn1::Pkcs7;
use crate::pkcs7::PKCS7_free;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    NID_LocalKeySet, NID_aes_256_cbc, NID_ms_csp_name, NID_pbe_WithSHA1And40BitRC2_CBC,
    NID_pkcs7_data, NID_undef,
};
use crate::runtime::stack::{
    OPENSSL_sk_delete_ptr, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::x509_att::X509at_add1_attr;
use crate::x509::x509_cmp::X509_check_private_key;
use crate::x509::x_all::X509_digest;
use crate::x509::x_x509::X509;
use crate::x509::x_x509a::{X509_alias_get0, X509_keyid_get0};

/// `static int pkcs12_add_bag(STACK_OF(PKCS12_SAFEBAG) **pbags, PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_crt.c:362-385`.
///
/// A NULL `pbags` means "do not collect", and answers success without taking the bag. Otherwise a
/// NULL `*pbags` is filled with a fresh stack; a push failure releases a stack this call built and
/// leaves a pre-existing one alone.
///
/// # Safety
/// `pbags` is NULL or a writable stack slot; `bag` is live and ownership passes to the stack on
/// success.
unsafe fn pkcs12_add_bag(pbags: *mut *mut OpenSslStack, bag: *mut Pkcs12Safebag) -> c_int {
    if pbags.is_null() {
        return 1;
    }
    // SAFETY: `pbags` is the caller's writable slot.
    let existing = unsafe { *pbags };
    let mut built_here = false;
    let sk = if existing.is_null() {
        // SAFETY: no preconditions.
        let fresh = OPENSSL_sk_new_null();
        if fresh.is_null() {
            return 0;
        }
        built_here = true;
        fresh
    } else {
        existing
    };

    // SAFETY: `sk` is live and `bag` is a live value the push adopts.
    if unsafe { OPENSSL_sk_push(sk, bag.cast()) } == 0 {
        if built_here {
            // SAFETY: `sk` was built by this call.
            unsafe { OPENSSL_sk_free(sk) };
        }
        return 0;
    }
    if built_here {
        // SAFETY: `pbags` is the caller's writable slot.
        unsafe { *pbags = sk };
    }
    1
}

/// `PKCS12_SAFEBAG *PKCS12_add_secret(STACK_OF(PKCS12_SAFEBAG) **pbags, int nid_type,
/// const unsigned char *value, int len)` — `crypto/pkcs12/p12_crt.c:281-297`.
///
/// Builds a `secretBag` wrapping the octets and appends it to `*pbags`. On a failure the bag is
/// released and NULL answered; the caller owns the answer, and the stack holds the same pointer
/// on success.
///
/// # Safety
/// `pbags` is NULL or a writable stack slot; `value` is readable for `len` bytes. The answer is
/// owned by the caller (and borrowed by `*pbags` on success).
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_secret(
    pbags: *mut *mut OpenSslStack,
    nid_type: c_int,
    value: *const c_uchar,
    len: c_int,
) -> *mut Pkcs12Safebag {
    // SAFETY: `value`/`len` are the caller's; ownership of the answer passes to this frame.
    let bag = unsafe { PKCS12_SAFEBAG_create_secret(nid_type, V_ASN1_OCTET_STRING, value, len) };
    if bag.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `bag` is live; `pbags` is the caller's slot and adopts `bag` on success.
    if unsafe { pkcs12_add_bag(pbags, bag) } == 0 {
        // SAFETY: `bag` is live and this failure path still owns it.
        unsafe { PKCS12_SAFEBAG_free(bag) };
        return ptr::null_mut();
    }
    bag
}

/// `PKCS12 *PKCS12_add_safes_ex(STACK_OF(PKCS7) *safes, int nid_p7, OSSL_LIB_CTX *ctx,
/// const char *propq)` — `crypto/pkcs12/p12_crt.c:387-404`.
///
/// A non-positive `nid_p7` means `NID_pkcs7_data`. The container is initialised through
/// [`PKCS12_init_ex`] and packed with [`PKCS12_pack_authsafes`]; a pack failure releases the
/// half-built container rather than returning it.
///
/// # Safety
/// `safes` is null or a live stack of `PKCS7`; `ctx` is null or a live library context and
/// `propq` null or NUL-terminated. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_safes_ex(
    safes: *mut OpenSslStack,
    nid_p7: c_int,
    ctx: *mut core::ffi::c_void,
    propq: *const core::ffi::c_char,
) -> *mut Pkcs12 {
    let nid_p7 = if nid_p7 <= 0 { NID_pkcs7_data } else { nid_p7 };
    // SAFETY: `ctx`/`propq` are the caller's.
    let p12 = unsafe { PKCS12_init_ex(nid_p7, ctx, propq) };
    if p12.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `p12` is live and owns its `authsafes` column; `safes` is the caller's.
    if unsafe { PKCS12_pack_authsafes(p12, safes) } == 0 {
        // SAFETY: `p12` is live and this failure path still owns it.
        unsafe { PKCS12_free(p12) };
        return ptr::null_mut();
    }
    p12
}

/// `PKCS12 *PKCS12_add_safes(STACK_OF(PKCS7) *safes, int nid_p7)` —
/// `crypto/pkcs12/p12_crt.c:406-409`.
///
/// # Safety
/// `safes` is null or a live stack of `PKCS7`. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_safes(safes: *mut OpenSslStack, nid_p7: c_int) -> *mut Pkcs12 {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe { PKCS12_add_safes_ex(safes, nid_p7, ptr::null_mut(), ptr::null()) }
}

/// `PKCS12_SAFEBAG *PKCS12_add_key_ex(STACK_OF(PKCS12_SAFEBAG) **pbags, EVP_PKEY *key,
/// int key_usage, int iter, int nid_key, const char *pass, OSSL_LIB_CTX *ctx,
/// const char *propq)` — `crypto/pkcs12/p12_crt.c:234-271`.
///
/// Serialises `key` to a `PKCS8_PRIV_KEY_INFO`, optionally adds the key-usage attribute, and wraps
/// it as either a shrouded key bag (`nid_key != -1`, through
/// [`PKCS12_SAFEBAG_create_pkcs8_encrypt_ex`]) or a plain key bag (`nid_key == -1`, through
/// [`PKCS12_SAFEBAG_create0_p8inf`]); the bag is then appended to `*pbags`. The unit raises
/// nothing of its own.
///
/// # Safety
/// `pbags` is NULL or a writable stack slot; `key` is a live `EVP_PKEY`; `pass` is NULL or a
/// string of `passlen` bytes; `ctx`/`propq` are the shroud's. The answer is owned by the caller
/// (and borrowed by `*pbags` on success).
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_key_ex(
    pbags: *mut *mut OpenSslStack,
    key: *mut EvpPkey,
    key_usage: c_int,
    iter: c_int,
    nid_key: c_int,
    pass: *const c_char,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs12Safebag {
    // SAFETY: `key` is live per the caller's contract.
    let mut p8 = unsafe { EVP_PKEY2PKCS8(key) };
    if p8.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `p8` is live; every pointer is checked before use.
    unsafe {
        if key_usage != 0 && PKCS8_add_keyusage(p8, key_usage) == 0 {
            PKCS8_PRIV_KEY_INFO_free(p8);
            return ptr::null_mut();
        }
        let bag = if nid_key != -1 {
            // This call does not take ownership of `p8`.
            PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(
                nid_key,
                pass,
                -1,
                ptr::null_mut(),
                0,
                iter,
                p8,
                ctx,
                propq,
            )
        } else {
            let bag = PKCS12_SAFEBAG_create0_p8inf(p8);
            if !bag.is_null() {
                // The bag takes ownership of `p8`.
                p8 = ptr::null_mut();
            }
            bag
        };
        if !p8.is_null() {
            PKCS8_PRIV_KEY_INFO_free(p8);
        }
        if bag.is_null() || pkcs12_add_bag(pbags, bag) == 0 {
            PKCS12_SAFEBAG_free(bag);
            return ptr::null_mut();
        }
        bag
    }
}

/// `PKCS12_SAFEBAG *PKCS12_add_key(STACK_OF(PKCS12_SAFEBAG) **pbags, EVP_PKEY *key, int key_usage,
/// int iter, int nid_key, const char *pass)` — `crypto/pkcs12/p12_crt.c:273-279`.
///
/// # Safety
/// As [`PKCS12_add_key_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_key(
    pbags: *mut *mut OpenSslStack,
    key: *mut EvpPkey,
    key_usage: c_int,
    iter: c_int,
    nid_key: c_int,
    pass: *const c_char,
) -> *mut Pkcs12Safebag {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_add_key_ex(
            pbags,
            key,
            key_usage,
            iter,
            nid_key,
            pass,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `int PKCS12_add_safe_ex(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags, int nid_safe,
/// int iter, const char *pass, OSSL_LIB_CTX *ctx, const char *propq)` —
/// `crypto/pkcs12/p12_crt.c:299-339`.
///
/// A NULL `*psafes` is filled with a fresh `STACK_OF(PKCS7)`. A zero `nid_safe` selects the
/// default `NID_pbe_WithSHA1And40BitRC2_CBC`, `-1` packs a plain `NID_pkcs7_data` contentInfo and
/// anything else a shrouded one; the resulting `PKCS7` is pushed. On failure a stack this call
/// built is released, and the half-built `PKCS7` always is.
///
/// # Safety
/// `psafes` is a live writable stack slot; `bags` is null or a live stack of `PKCS12_SAFEBAG`;
/// `pass` is NULL or NUL-terminated; `ctx`/`propq` are the shroud's.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_safe_ex(
    psafes: *mut *mut OpenSslStack,
    bags: *mut OpenSslStack,
    nid_safe: c_int,
    iter: c_int,
    pass: *const c_char,
    ctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    let mut free_safes = false;
    // SAFETY: `psafes` is the caller's writable slot.
    unsafe {
        if (*psafes).is_null() {
            let fresh = OPENSSL_sk_new_null();
            if fresh.is_null() {
                return 0;
            }
            *psafes = fresh;
            free_safes = true;
        }
    }

    let nid_safe = if nid_safe == 0 {
        NID_pbe_WithSHA1And40BitRC2_CBC
    } else {
        nid_safe
    };

    // SAFETY: `bags` is live (or NULL) and `ctx`/`propq` are the caller's.
    let p7 = unsafe {
        if nid_safe == -1 {
            PKCS12_pack_p7data(bags)
        } else {
            PKCS12_pack_p7encdata_ex(
                nid_safe,
                pass,
                -1,
                ptr::null_mut(),
                0,
                iter,
                bags,
                ctx,
                propq,
            )
        }
    };
    let pushed = if p7.is_null() {
        false
    } else {
        // SAFETY: `p7` is live and `*psafes` is the live stack checked above.
        unsafe { OPENSSL_sk_push(*psafes, p7.cast()) != 0 }
    };
    if !pushed {
        // SAFETY: `psafes` is the caller's slot; `free_safes` says whether this call built the
        // stack it holds.
        unsafe {
            if free_safes {
                OPENSSL_sk_free(*psafes);
                *psafes = ptr::null_mut();
            }
            PKCS7_free(p7);
        }
        return 0;
    }
    1
}

/// `int PKCS12_add_safe(STACK_OF(PKCS7) **psafes, STACK_OF(PKCS12_SAFEBAG) *bags, int nid_safe,
/// int iter, const char *pass)` — `crypto/pkcs12/p12_crt.c:341-345`.
///
/// # Safety
/// As [`PKCS12_add_safe_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_add_safe(
    psafes: *mut *mut OpenSslStack,
    bags: *mut OpenSslStack,
    nid_safe: c_int,
    iter: c_int,
    pass: *const c_char,
) -> c_int {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_add_safe_ex(
            psafes,
            bags,
            nid_safe,
            iter,
            pass,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

/// `typedef int PKCS12_create_cb(PKCS12_SAFEBAG *bag, void *cbarg)` — `include/openssl/pkcs12.h:305`.
///
/// The consumer callback `PKCS12_create_ex2` invokes once per bag: `-1` aborts the build, `0`
/// drops that bag, anything else keeps it.
#[allow(non_camel_case_types)]
pub type PKCS12_create_cb =
    Option<unsafe extern "C" fn(bag: *mut Pkcs12Safebag, cbarg: *mut c_void) -> c_int>;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:175`: 64, the widest digest the `keyid` buffer must
/// hold.
const EVP_MAX_MD_SIZE: usize = 64;

/// `PKCS12_DEFAULT_ITER` — `crypto/pkcs12/p12_local.h:60`: 2048, the iteration count both the
/// certificate and the MAC default to.
const PKCS12_DEFAULT_ITER: c_int = 2048;

/// `void (*)(void *)` adapter for `sk_PKCS7_pop_free(safes, PKCS7_free)`.
///
/// # Safety
/// `p` is NULL or a live `PKCS7` this frame owns.
unsafe extern "C" fn pkcs7_free_void(p: *mut c_void) {
    // SAFETY: the stack held `PKCS7` values per the caller's contract.
    unsafe { PKCS7_free(p.cast::<Pkcs7>()) }
}

/// `void (*)(void *)` adapter for `sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free)`.
///
/// # Safety
/// `p` is NULL or a live `PKCS12_SAFEBAG` this frame owns.
unsafe extern "C" fn safebag_free_void(p: *mut c_void) {
    // SAFETY: the stack held `PKCS12_SAFEBAG` values per the caller's contract.
    unsafe { PKCS12_SAFEBAG_free(p.cast::<Pkcs12Safebag>()) }
}

/// `static int copy_bag_attr(PKCS12_SAFEBAG *bag, EVP_PKEY *pkey, int nid)` —
/// `crypto/pkcs12/p12_crt.c:26-33`.
///
/// Copies the `pkey` attribute selected by `nid` onto the bag's attribute stack, or does nothing
/// and answers 1 when the key does not carry it. A duplicate OID is refused through
/// `X509at_add1_attr`'s guard, which is what the authority's return-value test observes.
///
/// # Safety
/// `bag` is live; `pkey` is live.
unsafe fn copy_bag_attr(bag: *mut Pkcs12Safebag, pkey: *mut EvpPkey, nid: c_int) -> c_int {
    // SAFETY: `pkey` is live per the caller's contract.
    let idx = unsafe { EVP_PKEY_get_attr_by_NID(pkey, nid, -1) };
    if idx < 0 {
        return 1;
    }
    // SAFETY: `idx` is a live index into `pkey`'s own attribute stack; the attribute is borrowed.
    let attr = unsafe { EVP_PKEY_get_attr(pkey, idx) };
    // SAFETY: `bag` is live, so its `attrib` slot is writable; `attr` is live.
    c_int::from(!unsafe { X509at_add1_attr(&raw mut (*bag).attrib, attr) }.is_null())
}

/// `static int pkcs12_remove_bag(STACK_OF(PKCS12_SAFEBAG) **pbags, PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_crt.c:347-360`.
///
/// Removes and frees `bag` from `*pbags`. A NULL `pbags` or `bag` answers 1 (nothing to do); a
/// bag not on the stack answers 0 and is **not** freed, exactly as the authority leaves it.
///
/// # Safety
/// `pbags` is NULL or a live stack slot; `bag` is NULL or a live bag owned by the caller.
unsafe fn pkcs12_remove_bag(pbags: *mut *mut OpenSslStack, bag: *mut Pkcs12Safebag) -> c_int {
    if pbags.is_null() || bag.is_null() {
        return 1;
    }
    // SAFETY: `pbags` is the caller's slot and `*pbags` is a live stack; `bag` is live.
    let tmp = unsafe { OPENSSL_sk_delete_ptr(*pbags, bag.cast()) };
    if tmp.is_null() {
        return 0;
    }
    // SAFETY: `tmp` is the removed element, live and transferred to this call.
    unsafe { PKCS12_SAFEBAG_free(tmp.cast::<Pkcs12Safebag>()) };
    1
}

/// `static PKCS12_SAFEBAG *pkcs12_add_cert_bag(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert,
/// const char *name, int namelen, unsigned char *keyid, int keyidlen)` —
/// `crypto/pkcs12/p12_crt.c:189-216`.
///
/// Builds the `certBag`, stamps the optional friendly name and local key id, and appends it to
/// `*pbags`. On any failure the half-built bag is released and NULL answered.
///
/// # Safety
/// `pbags` is NULL or a writable stack slot; `cert` is live; `name` is NULL or readable for
/// `namelen` bytes; `keyid` is NULL or readable for `keyidlen` bytes. The answer is owned by the
/// caller (and borrowed by `*pbags` on success).
unsafe fn pkcs12_add_cert_bag(
    pbags: *mut *mut OpenSslStack,
    cert: *mut X509,
    name: *const c_char,
    namelen: c_int,
    keyid: *mut c_uchar,
    keyidlen: c_int,
) -> *mut Pkcs12Safebag {
    // SAFETY: `cert` is live per the caller's contract.
    let bag = unsafe { PKCS12_SAFEBAG_create_cert(cert) };
    if bag.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: every pointer is checked before use; `bag` is live.
    unsafe {
        if !name.is_null() && PKCS12_add_friendlyname_utf8(bag, name, namelen) == 0 {
            PKCS12_SAFEBAG_free(bag);
            return ptr::null_mut();
        }
        if !keyid.is_null() && PKCS12_add_localkeyid(bag, keyid, keyidlen) == 0 {
            PKCS12_SAFEBAG_free(bag);
            return ptr::null_mut();
        }
        if pkcs12_add_bag(pbags, bag) == 0 {
            PKCS12_SAFEBAG_free(bag);
            return ptr::null_mut();
        }
    }
    bag
}

/// `PKCS12_SAFEBAG *PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert)` —
/// `crypto/pkcs12/p12_crt.c:218-232`.
///
/// Carries the certificate's own friendly name and local key id (if present) onto the bag.
///
/// # Safety
/// `pbags` is NULL or a writable stack slot; `cert` is live. The answer is owned by the caller
/// (and borrowed by `*pbags` on success).
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_add_cert(
    pbags: *mut *mut OpenSslStack,
    cert: *mut X509,
) -> *mut Pkcs12Safebag {
    let mut namelen: c_int = -1;
    let mut keyidlen: c_int = -1;
    // SAFETY: `cert` is live per the caller's contract; both length slots are this frame's.
    let name = unsafe { X509_alias_get0(cert, &raw mut namelen) }.cast::<c_char>();
    // SAFETY: as above.
    let keyid = unsafe { X509_keyid_get0(cert, &raw mut keyidlen) };
    // SAFETY: the arguments are the caller's and `cert` is live.
    unsafe { pkcs12_add_cert_bag(pbags, cert, name, namelen, keyid, keyidlen) }
}

/// `PKCS12 *PKCS12_create_ex2(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert,
/// STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
/// OSSL_LIB_CTX *ctx, const char *propq, PKCS12_create_cb *cb, void *cbarg)` —
/// `crypto/pkcs12/p12_crt.c:35-169`.
///
/// The full container builder. The C `goto err` is written as a function-local `'err` block that
/// jumps to the shared cleanup below, so the release order (`p12`, then `safes`, then `bags`) is
/// the same on every failure path. A `nid_cert`/`nid_key` of `NID_undef` defaults to AES-256-CBC,
/// and a zero `iter`/`mac_iter` to `PKCS12_DEFAULT_ITER`; a `mac_iter` of `-1` skips the MAC.
///
/// # Safety
/// `pass` is NULL or a string of the length the callers pass; `pkey`/`cert`/`ca` are NULL or live;
/// `ctx` is NULL or a live context and `propq` NULL or NUL-terminated; `cb`/`cbarg` are the
/// caller's. The answer is owned by the caller.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_create_ex2(
    pass: *const c_char,
    mut name: *const c_char,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    ca: *mut OpenSslStack,
    nid_key: c_int,
    nid_cert: c_int,
    iter: c_int,
    mac_iter: c_int,
    keytype: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
    cb: PKCS12_create_cb,
    cbarg: *mut c_void,
) -> *mut Pkcs12 {
    let mut p12: *mut Pkcs12 = ptr::null_mut();
    let mut safes: *mut OpenSslStack = ptr::null_mut();
    let mut bags: *mut OpenSslStack = ptr::null_mut();
    let mut keyid = [0 as c_uchar; EVP_MAX_MD_SIZE];
    let mut keyidlen: c_uint = 0;
    let mut namelen: c_int = -1;
    let mut pkeyidlen: c_int = -1;

    let nid_cert = if nid_cert == NID_undef {
        NID_aes_256_cbc
    } else {
        nid_cert
    };
    let nid_key = if nid_key == NID_undef {
        NID_aes_256_cbc
    } else {
        nid_key
    };
    let iter = if iter == 0 { PKCS12_DEFAULT_ITER } else { iter };
    let mac_iter = if mac_iter == 0 {
        PKCS12_DEFAULT_ITER
    } else {
        mac_iter
    };

    // The C `goto err` target. Every failure `break 'err`; success falls off the end with a live
    // `p12` and both stacks released below.
    'err: {
        if pkey.is_null() && cert.is_null() && ca.is_null() {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_CRT_63) };
            break 'err;
        }

        if !pkey.is_null() && !cert.is_null() {
            // SAFETY: both are live per the contract.
            if unsafe { X509_check_private_key(cert, pkey) } == 0 {
                break 'err;
            }
            // SAFETY: `cert` is live; `keyid`/`keyidlen` are this frame's.
            if unsafe { X509_digest(cert, EVP_sha1(), keyid.as_mut_ptr(), &raw mut keyidlen) } == 0
            {
                break 'err;
            }
        }

        if !cert.is_null() {
            if name.is_null() {
                // SAFETY: `cert` is live; `namelen` is this frame's.
                name = unsafe { X509_alias_get0(cert, &raw mut namelen) }.cast::<c_char>();
            }
            let pkeyid: *mut c_uchar;
            if keyidlen > 0 {
                pkeyid = keyid.as_mut_ptr();
                pkeyidlen = keyidlen as c_int;
            } else {
                // SAFETY: `cert` is live; `pkeyidlen` is this frame's.
                pkeyid = unsafe { X509_keyid_get0(cert, &raw mut pkeyidlen) };
            }

            // SAFETY: `cert` is live; the rest is the caller's or this frame's.
            let bag = unsafe {
                pkcs12_add_cert_bag(&raw mut bags, cert, name, namelen, pkeyid, pkeyidlen)
            };
            if let Some(cb_fn) = cb {
                // SAFETY: `cb_fn` is the caller's callback; `bag` may be NULL exactly as the
                // authority passes it.
                let cbret = unsafe { cb_fn(bag, cbarg) };
                if cbret == -1 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PKCS12_CRT_88) };
                    break 'err;
                } else if cbret == 0 {
                    // SAFETY: `bags`/`bag` are the caller's and this frame's.
                    unsafe { pkcs12_remove_bag(&raw mut bags, bag) };
                }
            }
        }

        // Add all other certificates.
        // SAFETY: `ca` is NULL or a live stack; a NULL stack yields a non-positive count.
        let ca_num = unsafe { OPENSSL_sk_num(ca) };
        for i in 0..ca_num {
            // SAFETY: `ca` is live for the count above; `i` is in range.
            let elem = unsafe { OPENSSL_sk_value(ca, i) }.cast::<X509>();
            // SAFETY: `elem` is a live certificate; the stack slot is this frame's.
            let bag = unsafe { PKCS12_add_cert(&raw mut bags, elem) };
            if bag.is_null() {
                break 'err;
            }
            if let Some(cb_fn) = cb {
                // SAFETY: `cb_fn` is the caller's callback; `bag` is live.
                let cbret = unsafe { cb_fn(bag, cbarg) };
                if cbret == -1 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PKCS12_CRT_103) };
                    break 'err;
                } else if cbret == 0 {
                    // SAFETY: `bags`/`bag` are this frame's.
                    unsafe { pkcs12_remove_bag(&raw mut bags, bag) };
                }
            }
        }

        let safe_failed = !bags.is_null() && {
            // SAFETY: `bags` is NULL or a live stack; the context arguments are the caller's.
            unsafe { PKCS12_add_safe_ex(&raw mut safes, bags, nid_cert, iter, pass, ctx, propq) }
        } == 0;
        if safe_failed {
            break 'err;
        }

        // SAFETY: `bags` is NULL or a live stack this frame owns.
        unsafe { OPENSSL_sk_pop_free(bags, Some(safebag_free_void)) };
        bags = ptr::null_mut();

        if !pkey.is_null() {
            // SAFETY: `pkey` is live; the rest is the caller's or this frame's.
            let bag = unsafe {
                PKCS12_add_key_ex(
                    &raw mut bags,
                    pkey,
                    keytype,
                    iter,
                    nid_key,
                    pass,
                    ctx,
                    propq,
                )
            };
            if bag.is_null() {
                break 'err;
            }

            // SAFETY: `bag`/`pkey` are live.
            if unsafe { copy_bag_attr(bag, pkey, NID_ms_csp_name) } == 0 {
                break 'err;
            }
            // SAFETY: as above.
            if unsafe { copy_bag_attr(bag, pkey, NID_LocalKeySet) } == 0 {
                break 'err;
            }

            // SAFETY: `bag` is live; `name` is NULL or readable.
            if !name.is_null() && unsafe { PKCS12_add_friendlyname_utf8(bag, name, -1) } == 0 {
                break 'err;
            }
            let keyid_failed = keyidlen != 0 && {
                // SAFETY: `bag` is live; `keyid` is this frame's buffer of `keyidlen` bytes.
                unsafe { PKCS12_add_localkeyid(bag, keyid.as_mut_ptr(), keyidlen as c_int) }
            } == 0;
            if keyid_failed {
                break 'err;
            }
            if let Some(cb_fn) = cb {
                // SAFETY: `cb_fn` is the caller's callback; `bag` is live.
                let cbret = unsafe { cb_fn(bag, cbarg) };
                if cbret == -1 {
                    // SAFETY: a compile-time-constant site.
                    unsafe { raise_site(&err_sites::PKCS12_CRT_136) };
                    break 'err;
                } else if cbret == 0 {
                    // SAFETY: `bags`/`bag` are this frame's.
                    unsafe { pkcs12_remove_bag(&raw mut bags, bag) };
                }
            }
        }

        let safe_failed = !bags.is_null() && {
            // SAFETY: `bags` is NULL or a live stack; the call takes ownership of `safes` on
            // success.
            unsafe { PKCS12_add_safe(&raw mut safes, bags, -1, 0, ptr::null()) }
        } == 0;
        if safe_failed {
            break 'err;
        }

        // SAFETY: `bags` is NULL or a live stack this frame owns.
        unsafe { OPENSSL_sk_pop_free(bags, Some(safebag_free_void)) };
        bags = ptr::null_mut();

        // SAFETY: `safes` is NULL or a live stack; the context arguments are the caller's.
        p12 = unsafe { PKCS12_add_safes_ex(safes, 0, ctx, propq) };
        if p12.is_null() {
            break 'err;
        }

        // SAFETY: `safes` is NULL or a live stack this frame owns.
        unsafe { OPENSSL_sk_pop_free(safes, Some(pkcs7_free_void)) };
        safes = ptr::null_mut();

        let mac_failed = mac_iter != -1 && {
            // SAFETY: `p12` is live; `pass`/`salt`/`md` are the caller's (or NULL).
            unsafe { PKCS12_set_mac(p12, pass, -1, ptr::null_mut(), 0, mac_iter, ptr::null()) }
        } == 0;
        if mac_failed {
            // SAFETY: `p12` is live and this failure path still owns it.
            unsafe { PKCS12_free(p12) };
            p12 = ptr::null_mut();
            break 'err;
        }
    }

    if p12.is_null() {
        // SAFETY: `safes`/`bags` are NULL or live stacks this frame owns.
        unsafe {
            OPENSSL_sk_pop_free(safes, Some(pkcs7_free_void));
            OPENSSL_sk_pop_free(bags, Some(safebag_free_void));
        }
    }
    p12
}

/// `PKCS12 *PKCS12_create_ex(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert,
/// STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
/// OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/pkcs12/p12_crt.c:171-179`.
///
/// # Safety
/// As [`PKCS12_create_ex2`], without the callback.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_create_ex(
    pass: *const c_char,
    name: *const c_char,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    ca: *mut OpenSslStack,
    nid_key: c_int,
    nid_cert: c_int,
    iter: c_int,
    mac_iter: c_int,
    keytype: c_int,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs12 {
    // SAFETY: the arguments are forwarded under this function's contract, with no callback.
    unsafe {
        PKCS12_create_ex2(
            pass,
            name,
            pkey,
            cert,
            ca,
            nid_key,
            nid_cert,
            iter,
            mac_iter,
            keytype,
            ctx,
            propq,
            None,
            ptr::null_mut(),
        )
    }
}

/// `PKCS12 *PKCS12_create(const char *pass, const char *name, EVP_PKEY *pkey, X509 *cert,
/// STACK_OF(X509) *ca, int nid_key, int nid_cert, int iter, int mac_iter, int keytype)` —
/// `crypto/pkcs12/p12_crt.c:181-187`.
///
/// # Safety
/// As [`PKCS12_create_ex`], without the context arguments.
#[allow(clippy::too_many_arguments)] // mirrors the authority's signature exactly
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_create(
    pass: *const c_char,
    name: *const c_char,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    ca: *mut OpenSslStack,
    nid_key: c_int,
    nid_cert: c_int,
    iter: c_int,
    mac_iter: c_int,
    keytype: c_int,
) -> *mut Pkcs12 {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_create_ex(
            pass,
            name,
            pkey,
            cert,
            ca,
            nid_key,
            nid_cert,
            iter,
            mac_iter,
            keytype,
            ptr::null_mut(),
            ptr::null(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs12::p12_sbag::{PKCS12_SAFEBAG_get_bag_nid, PKCS12_SAFEBAG_get_nid};
    use crate::runtime::obj::{NID_pkcs7_data, NID_secretBag};
    use crate::runtime::stack::OPENSSL_sk_num;

    /// `PKCS12_add_secret` builds a fresh stack when handed a NULL one, appends exactly one bag
    /// whose two NIDs are the ones the call named, and hands the same bag back. The stack and the
    /// object table are process-global state. The octets are a literal the test chose.
    #[test]
    fn add_secret_creates_the_collection_and_returns_the_bag() {
        let _guard = crate::test_support::lock_global_state();
        let value: [u8; 3] = [0x01, 0x02, 0x03];
        let mut bags: *mut OpenSslStack = ptr::null_mut();
        // SAFETY: `bags` is this frame's own slot and `value`/`3` describe a live literal.
        let bag = unsafe { PKCS12_add_secret(&raw mut bags, NID_pkcs7_data, value.as_ptr(), 3) };
        assert!(!bag.is_null());
        assert!(!bags.is_null());
        // SAFETY: `bags` is live and holds one bag; `bag` is that live bag.
        unsafe {
            assert_eq!(OPENSSL_sk_num(bags), 1);
            assert_eq!(PKCS12_SAFEBAG_get_nid(bag), NID_secretBag);
            assert_eq!(PKCS12_SAFEBAG_get_bag_nid(bag), NID_pkcs7_data);
            // The stack's element is the returned bag, by pointer identity: the call adopts
            // rather than copies.
            assert_eq!(crate::runtime::stack::OPENSSL_sk_value(bags, 0), bag.cast());
            OPENSSL_sk_free(bags);
            PKCS12_SAFEBAG_free(bag);
        }
    }

    /// An all-NULL build request is refused before any allocation, through the covered
    /// `PKCS12_R_INVALID_NULL_ARGUMENT` site, and answers NULL.
    #[test]
    fn create_refuses_an_all_null_request() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every pointer is a NULL the authority tests for first, and every count is zero.
        let p12 = unsafe {
            PKCS12_create(
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                0,
                0,
                0,
            )
        };
        assert!(p12.is_null());
    }
}
