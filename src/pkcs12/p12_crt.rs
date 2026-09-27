//! `crypto/pkcs12/p12_crt.c` — the `PKCS12_create` worker and the `add_*` family. Phase 10 (10.3).
//!
//! The unit is 409 lines and eleven exports, and **seven of them land here**: the `add_*` family
//! [`PKCS12_add_secret`], [`PKCS12_add_key`]/[`PKCS12_add_key_ex`],
//! [`PKCS12_add_safe`]/[`PKCS12_add_safe_ex`] and [`PKCS12_add_safes`]/[`PKCS12_add_safes_ex`].
//! The container builder's two remaining arms, `PKCS12_create(_ex/_ex2)` and `PKCS12_add_cert`,
//! stay `open` on Phase 11's certificate object graph and the court prints each as `pending`,
//! never as a pass (docs/PHASE-10-SUBPHASES.md §3.5).
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
//! **The two that remain open were measured, not assumed.** `nm --undefined-only` over the
//! authority's `libcrypto-lib-p12_crt.o` shows the closure of `PKCS12_create(_ex/_ex2)`/`_add_cert`
//! reaching `X509_check_private_key`, `X509_digest`, `X509_alias_get0`, `X509_keyid_get0`,
//! `PKCS12_SAFEBAG_create_cert` (all Phase 11's `X509` object graph) and `X509at_add1_attr`;
//! `EVP_PKEY_get_attr`/`_by_NID` are only on the `copy_bag_attr` path those two share. None of
//! the `X509_*` names is landed, so nothing of theirs is stubbed.
//!
//! The unit raises nothing of its own on the landed path, and `pkcs12_add_bag` raises nothing at
//! all, so `crypto/pkcs12/p12_crt.c` is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`: an entry would read as coverage this slice does
//! not have. The file's other raise sites belong to the `create`/`add_key` arms that remain open
//! and land with them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::V_ASN1_OCTET_STRING;
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_free;
use crate::evp::evp_pkey::EVP_PKEY2PKCS8;
use crate::evp::pkey::EvpPkey;
use crate::pkcs12::p12_add::{PKCS12_pack_authsafes, PKCS12_pack_p7data, PKCS12_pack_p7encdata_ex};
use crate::pkcs12::p12_asn::PKCS12_free;
use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, Pkcs12, Pkcs12Safebag};
use crate::pkcs12::p12_attr::PKCS8_add_keyusage;
use crate::pkcs12::p12_init::PKCS12_init_ex;
use crate::pkcs12::p12_sbag::PKCS12_SAFEBAG_create_secret;
use crate::pkcs12::p12_sbag::{
    PKCS12_SAFEBAG_create0_p8inf, PKCS12_SAFEBAG_create_pkcs8_encrypt_ex,
};
use crate::pkcs7::PKCS7_free;
use crate::runtime::obj::{NID_pbe_WithSHA1And40BitRC2_CBC, NID_pkcs7_data};
use crate::runtime::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, OpenSslStack};

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
}
