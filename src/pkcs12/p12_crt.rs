//! `crypto/pkcs12/p12_crt.c` — the `PKCS12_create` worker and the `add_*` family. Phase 10 (10.3).
//!
//! The authority file is 409 lines and eleven exports. Almost all of it is the container builder:
//! `PKCS12_create(_ex/_ex2)` and the `PKCS12_add_cert`/`add_key`/`add_safe`/`add_safes` family,
//! every arm of which reaches the `PKCS7` object (`PKCS12_pack_p7data`/`PKCS12_pack_p7encdata_ex`,
//! `PKCS12_init_ex`, `PKCS12_pack_authsafes`) that `crypto/pkcs7/pk7_asn1.c` defines and Phase 12
//! owns, and Phase 11's `X509_it`/`X509_alias_get0`/`X509_digest` and `EVP_PKEY2PKCS8`. Those
//! ten stay `open` with their measured blockers; the court prints each as `pending`, never as a
//! pass (docs/PHASE-10-SUBPHASES.md §3.5).
//!
//! **Exactly one export here has a landed closure**: [`PKCS12_add_secret`], whose only callees are
//! `PKCS12_SAFEBAG_create_secret` (this crate's `p12_sbag.rs`, 10.2) and the internal
//! `pkcs12_add_bag`, which uses the `OPENSSL_sk_*` stack functions. It is the `add_*` surface the
//! subphase's slice can actually drive, and the court builds a one-element
//! `STACK_OF(PKCS12_SAFEBAG)` through it and prints the bag's DER.
//!
//! **The `PKCS7` subset was then pulled forward** (D441's stratum-ordering defect; see
//! [`crate::pkcs7`]), and [`PKCS12_add_safes_ex`]/[`PKCS12_add_safes`] are the pair that becomes
//! reachable: they need only `PKCS12_init_ex` and `PKCS12_pack_authsafes`, both of which land on
//! the pulled-forward object. `PKCS12_add_safe(_ex)` is **not** in that set: its encrypted arm
//! reaches `PKCS12_pack_p7encdata_ex` (`:323`), which stays open on Phase 11's
//! `PKCS5_pbe_set_ex`/`PKCS5_pbe2_set_iv_ex`, so the `add_*` pair that calls it stays open with
//! it. `PKCS12_create(_ex/_ex2)`, `PKCS12_add_cert` and `PKCS12_add_key(_ex)` stay open on Phase
//! 11's `X509_it`/`EVP_PKEY2PKCS8` as well.
//!
//! The unit raises nothing of its own on the landed path, and `pkcs12_add_bag` raises nothing at
//! all, so `crypto/pkcs12/p12_crt.c` is deliberately **not** an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`: an entry would read as coverage this slice does
//! not have. The file's other raise sites belong to the `create`/`add_key` arms that remain open
//! and land with them.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::asn1::layout::V_ASN1_OCTET_STRING;
use crate::pkcs12::p12_add::PKCS12_pack_authsafes;
use crate::pkcs12::p12_asn::PKCS12_free;
use crate::pkcs12::p12_asn::{PKCS12_SAFEBAG_free, Pkcs12, Pkcs12Safebag};
use crate::pkcs12::p12_init::PKCS12_init_ex;
use crate::pkcs12::p12_sbag::PKCS12_SAFEBAG_create_secret;
use crate::runtime::obj::NID_pkcs7_data;
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
