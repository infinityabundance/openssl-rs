//! `crypto/pkcs12/p12_sbag.c` — the `SafeBag` accessors and constructors. Phase 10 (10.2).
//!
//! The unit is 292 lines and twenty-two exports: the five `get0_*` readers over the `SafeBag`
//! union, the four `nid`/`type` readers, the two attribute readers, six constructors and the two
//! `get1_*` certificate readers. What lands here is everything whose dependency closure is landed.
//!
//! ## What is held open, and each with its own measured blocker
//!
//! * `PKCS12_SAFEBAG_get1_cert`/`_crl`/`_ex` (four names) call `ASN1_item_unpack[_ex]` with
//!   `ASN1_ITEM_rptr(X509)`/`X509_CRL`, and the `_ex` arm also calls `ossl_x509_set0_libctx`/
//!   `ossl_x509_crl_set0_libctx`. The `X509` and `X509_CRL` items are `crypto/x509/x_x509.c`'s and
//!   `crypto/x509/x_crl.c`'s, both Phase 11's, so the four cannot be built here.
//! * `PKCS12_SAFEBAG_create_cert`/`create_crl` call `PKCS12_item_pack_safebag`
//!   (`crypto/pkcs12/p12_add.c`, 10.3), which is open.
//! * `PKCS12_SAFEBAG_create_pkcs8_encrypt`/`_ex` call `PKCS8_encrypt[_ex]`
//!   (`crypto/pkcs12/p12_p8e.c`, 10.4) and `EVP_CIPHER_fetch`, so they are 10.4's.
//!
//! Each is left `open` in the ledger rather than stubbed, and the court prints each as `pending`
//! with the blocker rather than driving a fabricated arm.
//!
//! ## The `get0_*` guards are the identity §3.2 measures
//!
//! Three of the readers first check the selector: `get0_p8inf` insists on `NID_keyBag`,
//! `get0_pkcs8` on `NID_pkcs8ShroudedKeyBag`, `get0_safes` on `NID_safeContentsBag`, and a
//! non-matching bag answers NULL rather than a reinterpreted union. `get0_bag_obj` is the inverse
//! — it answers NULL precisely for the three `PKCS12_BAGS` types whose value is *not* an
//! `ASN1_TYPE` and returns the `other` arm otherwise.
//!
//! ## The two constructors adopt their argument
//!
//! `create0_p8inf` and `create0_pkcs8` store the caller's pointer directly, so ownership of the
//! `PKCS8_PRIV_KEY_INFO`/`X509_SIG` passes to the bag and is released by `PKCS12_SAFEBAG_free`.
//! That is observable through `get0_p8inf`/`get0_pkcs8` and is driven by the court.
//!
//! The unit raises from `create_secret` and the two `create0_*` allocators, so it is an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`; its coordinates are `err_sites::PKCS12_*`.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_uchar};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::layout::{Asn1Type, V_ASN1_OCTET_STRING};
use crate::asn1::p8_pkey::{PKCS8_pkey_get0_attrs, Pkcs8PrivKeyInfo};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::x_sig::X509Sig;
use crate::pkcs12::p12_asn::{
    PKCS12_BAGS_free, PKCS12_BAGS_new, PKCS12_SAFEBAG_new, Pkcs12Bags, Pkcs12Safebag,
};
use crate::pkcs12::p12_attr::PKCS12_get_attr_gen;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{
    Asn1Object, NID_certBag, NID_crlBag, NID_keyBag, NID_pkcs8ShroudedKeyBag, NID_safeContentsBag,
    NID_sdsiCertificate, NID_secretBag, NID_x509Certificate, NID_x509Crl, OBJ_nid2obj, OBJ_obj2nid,
};
use crate::runtime::stack::OpenSslStack;

/// `ASN1_TYPE *PKCS12_get_attr(const PKCS12_SAFEBAG *bag, int attr_nid)` —
/// `crypto/pkcs12/p12_sbag.c:17-20`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_get_attr(
    bag: *const Pkcs12Safebag,
    attr_nid: c_int,
) -> *mut Asn1Type {
    // SAFETY: `bag` is live and its `attrib` is a live stack or NULL.
    unsafe { PKCS12_get_attr_gen((*bag).attrib, attr_nid) }
}

/// `const ASN1_TYPE *PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag, int attr_nid)` —
/// `crypto/pkcs12/p12_sbag.c:23-27`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_attr(
    bag: *const Pkcs12Safebag,
    attr_nid: c_int,
) -> *const Asn1Type {
    // SAFETY: `bag` is live and its `attrib` is a live stack or NULL.
    unsafe { PKCS12_get_attr_gen((*bag).attrib, attr_nid) }
}

/// `ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid)` —
/// `crypto/pkcs12/p12_sbag.c:29-32`.
///
/// # Safety
/// `p8` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS8_get_attr(
    p8: *mut Pkcs8PrivKeyInfo,
    attr_nid: c_int,
) -> *mut Asn1Type {
    // SAFETY: `p8` is live and its attribute stack is borrowed from it.
    unsafe { PKCS12_get_attr_gen(PKCS8_pkey_get0_attrs(p8), attr_nid) }
}

/// `const PKCS8_PRIV_KEY_INFO *PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:34-39`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_p8inf(
    bag: *const Pkcs12Safebag,
) -> *const Pkcs8PrivKeyInfo {
    // SAFETY: `bag` is live.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_keyBag {
        return ptr::null();
    }
    // SAFETY: the selector is `NID_keyBag`, so the union holds a `keybag`.
    unsafe { (*bag).value.cast::<Pkcs8PrivKeyInfo>() }
}

/// `const X509_SIG *PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:41-46`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_pkcs8(bag: *const Pkcs12Safebag) -> *const X509Sig {
    // SAFETY: `bag` is live and its `type` is its own object.
    if unsafe { OBJ_obj2nid((*bag).type_) } != NID_pkcs8ShroudedKeyBag {
        return ptr::null();
    }
    // SAFETY: the selector is `NID_pkcs8ShroudedKeyBag`, so the union holds a `shkeybag`.
    unsafe { (*bag).value.cast::<X509Sig>() }
}

/// `const STACK_OF(PKCS12_SAFEBAG) *PKCS12_SAFEBAG_get0_safes(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:48-54`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_safes(
    bag: *const Pkcs12Safebag,
) -> *const OpenSslStack {
    // SAFETY: `bag` is live and its `type` is its own object.
    if unsafe { OBJ_obj2nid((*bag).type_) } != NID_safeContentsBag {
        return ptr::null();
    }
    // SAFETY: the selector is `NID_safeContentsBag`, so the union holds a `safes` stack.
    unsafe { (*bag).value.cast::<OpenSslStack>() }
}

/// `const ASN1_OBJECT *PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:56-59`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_type(bag: *const Pkcs12Safebag) -> *const Asn1Object {
    // SAFETY: `bag` is live per the contract.
    unsafe { (*bag).type_ }
}

/// `int PKCS12_SAFEBAG_get_nid(const PKCS12_SAFEBAG *bag)` — `crypto/pkcs12/p12_sbag.c:61-64`.
///
/// # Safety
/// `bag` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get_nid(bag: *const Pkcs12Safebag) -> c_int {
    // SAFETY: `bag` is live and its `type` is its own object.
    unsafe { OBJ_obj2nid((*bag).type_) }
}

/// `int PKCS12_SAFEBAG_get_bag_nid(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:66-73`.
///
/// `-1` for a bag that is not a `certBag`/`crlBag`/`secretBag`, because only those three carry a
/// `PKCS12_BAGS`; otherwise the inner `BAG-TYPE`'s NID.
///
/// # Safety
/// `bag` is live.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get_bag_nid(bag: *const Pkcs12Safebag) -> c_int {
    // SAFETY: `bag` is live.
    let btype = unsafe { PKCS12_SAFEBAG_get_nid(bag) };
    if btype != NID_certBag && btype != NID_crlBag && btype != NID_secretBag {
        return -1;
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    unsafe { OBJ_obj2nid((*inner).type_) }
}

/// `const ASN1_OBJECT *PKCS12_SAFEBAG_get0_bag_type(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:75-82`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_bag_type(
    bag: *const Pkcs12Safebag,
) -> *const Asn1Object {
    // SAFETY: `bag` is live.
    let btype = unsafe { PKCS12_SAFEBAG_get_nid(bag) };
    if btype != NID_certBag && btype != NID_crlBag && btype != NID_secretBag {
        return ptr::null();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    unsafe { (*inner).type_ }
}

/// `const ASN1_TYPE *PKCS12_SAFEBAG_get0_bag_obj(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:84-92`.
///
/// # Safety
/// `bag` is live; the answer is borrowed from it.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get0_bag_obj(bag: *const Pkcs12Safebag) -> *const Asn1Type {
    // SAFETY: `bag` is live.
    let vtype = unsafe { PKCS12_SAFEBAG_get_bag_nid(bag) };
    if vtype == -1
        || vtype == NID_x509Certificate
        || vtype == NID_x509Crl
        || vtype == NID_sdsiCertificate
    {
        return ptr::null();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live; its `value` is the `other` arm here.
    unsafe { (*inner).value.cast::<Asn1Type>() }
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_secret(int type, int vtype,
/// const unsigned char *value, int len)` — `crypto/pkcs12/p12_sbag.c:162-212`.
///
/// Only `V_ASN1_OCTET_STRING` is accepted; any other `vtype` raises `PKCS12_R_INVALID_TYPE` and
/// answers NULL. The answer is a `secretBag` whose `PKCS12_BAGS` value is an `ASN1_TYPE` holding
/// the octets.
///
/// # Safety
/// `value` is readable for `len` bytes; `type` is an OID NID. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create_secret(
    type_: c_int,
    vtype: c_int,
    value: *const c_uchar,
    len: c_int,
) -> *mut Pkcs12Safebag {
    // SAFETY: no preconditions.
    let bag = PKCS12_BAGS_new();
    if bag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_168) };
        return ptr::null_mut();
    }
    // SAFETY: `bag` is live and its `type_` slot is writable.
    unsafe { (*bag).type_ = OBJ_nid2obj(type_) };

    match vtype {
        V_ASN1_OCTET_STRING => {
            // SAFETY: no preconditions.
            let strtmp = ASN1_OCTET_STRING_new();
            if strtmp.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_178) };
                // SAFETY: `bag` is live and this call owns it.
                unsafe { PKCS12_BAGS_free(bag) };
                return ptr::null_mut();
            }
            // Pack data into an octet string.
            // SAFETY: `strtmp` is fresh and `value`/`len` are the caller's.
            if unsafe { ASN1_OCTET_STRING_set(strtmp, value, len) } == 0 {
                // SAFETY: `strtmp` is live and this call owns it.
                unsafe { ASN1_OCTET_STRING_free(strtmp) };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_184) };
                // SAFETY: `bag` is live and this call owns it.
                unsafe { PKCS12_BAGS_free(bag) };
                return ptr::null_mut();
            }
            // SAFETY: no preconditions.
            let any = ASN1_TYPE_new();
            if any.is_null() {
                // SAFETY: `strtmp` is live and this call owns it.
                unsafe { ASN1_OCTET_STRING_free(strtmp) };
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&err_sites::PKCS12_190) };
                // SAFETY: `bag` is live and this call owns it.
                unsafe { PKCS12_BAGS_free(bag) };
                return ptr::null_mut();
            }
            // SAFETY: `any` is fresh; ownership of `strtmp` passes to it.
            unsafe {
                ASN1_TYPE_set(any, vtype, strtmp.cast());
                (*bag).value = any.cast();
            }
        }
        _ => {
            // SAFETY: a compile-time-constant site.
            unsafe { raise_site(&err_sites::PKCS12_197) };
            // SAFETY: `bag` is live and this call owns it.
            unsafe { PKCS12_BAGS_free(bag) };
            return ptr::null_mut();
        }
    }

    // SAFETY: no preconditions.
    let safebag = PKCS12_SAFEBAG_new();
    if safebag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_202) };
        // SAFETY: `bag` is live and this call owns it.
        unsafe { PKCS12_BAGS_free(bag) };
        return ptr::null_mut();
    }
    // SAFETY: `safebag` is live; ownership of `bag` passes to it.
    unsafe {
        (*safebag).value = bag.cast();
        (*safebag).type_ = OBJ_nid2obj(NID_secretBag);
    }
    safebag
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8)` —
/// `crypto/pkcs12/p12_sbag.c:216-227`.
///
/// The `keyBag` arm: ownership of `p8` passes to the answer.
///
/// # Safety
/// `p8` is live and transferred to the answer on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create0_p8inf(
    p8: *mut Pkcs8PrivKeyInfo,
) -> *mut Pkcs12Safebag {
    // SAFETY: no preconditions.
    let bag = PKCS12_SAFEBAG_new();
    if bag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_221) };
        return ptr::null_mut();
    }
    // SAFETY: `bag` is live; ownership of `p8` passes to it.
    unsafe {
        (*bag).type_ = OBJ_nid2obj(NID_keyBag);
        (*bag).value = p8.cast();
    }
    bag
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8)` —
/// `crypto/pkcs12/p12_sbag.c:231-243`.
///
/// The `pkcs8ShroudedKeyBag` arm: ownership of `p8` passes to the answer.
///
/// # Safety
/// `p8` is live and transferred to the answer on success.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create0_pkcs8(p8: *mut X509Sig) -> *mut Pkcs12Safebag {
    // SAFETY: no preconditions.
    let bag = PKCS12_SAFEBAG_new();
    if bag.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::PKCS12_237) };
        return ptr::null_mut();
    }
    // SAFETY: `bag` is live; ownership of `p8` passes to it.
    unsafe {
        (*bag).type_ = OBJ_nid2obj(NID_pkcs8ShroudedKeyBag);
        (*bag).value = p8.cast();
    }
    bag
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_new;
    use crate::pkcs12::p12_asn::{
        PKCS12_BAGS_it, PKCS12_SAFEBAGS_it, PKCS12_SAFEBAG_free, PKCS12_SAFEBAG_it,
    };

    /// The secret-bag constructor produces a `secretBag` whose inner bag carries the octets, and
    /// every accessor agrees. The octets are a literal the test chose.
    #[test]
    fn create_secret_accessors_agree() {
        // The item layer and the object table are process-global state.
        let _guard = crate::test_support::lock_global_state();
        let value: [c_uchar; 3] = [0x01, 0x02, 0x03];
        // A `secretBag`'s outer type is `NID_secretBag`; the inner `type` is the caller's.
        // SAFETY: `value` is three readable bytes and the NIDs are known.
        let bag = unsafe {
            PKCS12_SAFEBAG_create_secret(
                NID_x509Certificate,
                V_ASN1_OCTET_STRING,
                value.as_ptr(),
                3,
            )
        };
        assert!(!bag.is_null());
        // SAFETY: `bag` is live.
        unsafe {
            assert_eq!(PKCS12_SAFEBAG_get_nid(bag), NID_secretBag);
            assert_eq!(PKCS12_SAFEBAG_get_bag_nid(bag), NID_x509Certificate);
            assert!(!PKCS12_SAFEBAG_get0_bag_type(bag).is_null());
            assert!(PKCS12_SAFEBAG_get0_bag_obj(bag).is_null());
            assert!(PKCS12_SAFEBAG_get0_p8inf(bag).is_null());
            assert!(PKCS12_SAFEBAG_get0_pkcs8(bag).is_null());
            assert!(PKCS12_SAFEBAG_get0_safes(bag).is_null());
            assert!(!PKCS12_SAFEBAG_get0_type(bag).is_null());
            PKCS12_SAFEBAG_free(bag);
        }
    }

    /// `create0_p8inf` adopts its argument, so `get0_p8inf` answers the same pointer and freeing
    /// the bag releases it. The `_it` accessors are the same static each call.
    #[test]
    fn create0_adopts_and_items_are_stable() {
        // The item layer and the object table are process-global state.
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let p8 = PKCS8_PRIV_KEY_INFO_new();
        assert!(!p8.is_null());
        // SAFETY: `p8` is live and transferred to the bag.
        let bag = unsafe { PKCS12_SAFEBAG_create0_p8inf(p8) };
        assert!(!bag.is_null());
        // SAFETY: `bag` is live.
        unsafe {
            assert_eq!(PKCS12_SAFEBAG_get_nid(bag), NID_keyBag);
            assert_eq!(PKCS12_SAFEBAG_get0_p8inf(bag), p8);
            assert!(PKCS12_SAFEBAG_get0_pkcs8(bag).is_null());
            PKCS12_SAFEBAG_free(bag);
        }
        assert_eq!(PKCS12_SAFEBAG_it(), PKCS12_SAFEBAG_it());
        assert_eq!(PKCS12_BAGS_it(), PKCS12_BAGS_it());
        assert_eq!(PKCS12_SAFEBAGS_it(), PKCS12_SAFEBAGS_it());
    }
}
