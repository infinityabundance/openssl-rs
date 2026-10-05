//! `crypto/pkcs12/p12_sbag.c` — the `SafeBag` accessors and constructors. Phase 10 (10.2).
//!
//! The unit is 292 lines and twenty-two exports: the five `get0_*` readers over the `SafeBag`
//! union, the four `nid`/`type` readers, the two attribute readers, six constructors and the two
//! `get1_*` certificate readers. What lands here is everything whose dependency closure is landed.
//!
//! ## The six cert/CRL rows, un-withheld by this slice (10.15)
//!
//! `PKCS12_SAFEBAG_get1_cert`/`_crl`/`_ex` (four names) call `ASN1_item_unpack[_ex]` with
//! `ASN1_ITEM_rptr(X509)`/`X509_CRL`, and the `_ex` arm also calls `ossl_x509_set0_libctx`/
//! `ossl_x509_crl_set0_libctx`; `PKCS12_SAFEBAG_create_cert`/`create_crl` call
//! `PKCS12_item_pack_safebag`. Every one of those was withheld when this module was written
//! because the two items and the two `set0_libctx` helpers were **not landed**. 10.8 (`X509_it`,
//! `ossl_x509_set0_libctx`) and 10.8's CRL object (`X509_CRL_it`, `ossl_x509_crl_set0_libctx`)
//! then landed them, and 10.3 landed `PKCS12_item_pack_safebag`: the frontier moved and the six
//! are transcribed here rather than withheld a second time (D451's rule). The one name that kept
//! `p12_kiss.c`'s `PKCS12_parse` `open` — `ossl_x509_add_cert_new` (`x509_cmp.c`, 10.14.1) — has
//! since landed with the Phase 11 slice, and that unit is transcribed in [`crate::pkcs12::p12_kiss`].
//!
//! `PKCS12_SAFEBAG_create_pkcs8_encrypt`/`_ex` call `PKCS8_encrypt[_ex]`
//! (`crypto/pkcs12/p12_p8e.c`, 10.4) and `EVP_CIPHER_fetch`; with the PBE pull-forward (D443)
//! those landed, so this pair landed before this slice.
//!
//! **No raise of its own.** The six new functions raise nothing directly — `get1_*` lets
//! `ASN1_item_unpack[_ex]` raise on a decode failure and `create_cert`/`create_crl` delegate to
//! `PKCS12_item_pack_safebag`, which raises — so the unit's `gen_err_raise_sites.py` entry is
//! unchanged and its existing coordinates are `err_sites::PKCS12_*`.
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

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_set};
use crate::asn1::asn_pack::{ASN1_item_unpack, ASN1_item_unpack_ex};
use crate::asn1::layout::{Asn1String, Asn1Type, V_ASN1_OCTET_STRING};
use crate::asn1::p8_pkey::{PKCS8_pkey_get0_attrs, Pkcs8PrivKeyInfo};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::x_sig::{X509Sig, X509_SIG_free};
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EvpCipher};
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::pkcs12::p12_add::PKCS12_item_pack_safebag;
use crate::pkcs12::p12_asn::{
    PKCS12_BAGS_free, PKCS12_BAGS_new, PKCS12_SAFEBAG_new, Pkcs12Bags, Pkcs12Safebag,
};
use crate::pkcs12::p12_attr::PKCS12_get_attr_gen;
use crate::pkcs12::p12_p8e::PKCS8_encrypt_ex;
use crate::runtime::err::{err_sites, raise_site, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::obj::{
    Asn1Object, NID_certBag, NID_crlBag, NID_keyBag, NID_pkcs8ShroudedKeyBag, NID_safeContentsBag,
    NID_sdsiCertificate, NID_secretBag, NID_x509Certificate, NID_x509Crl, OBJ_nid2obj, OBJ_nid2sn,
    OBJ_obj2nid,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x_crl::{ossl_x509_crl_set0_libctx, X509Crl, X509_CRL_free, X509_CRL_it};
use crate::x509::x_x509::{ossl_x509_set0_libctx, X509_free, X509_it, X509};

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

/// `X509 *PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:94-102`.
///
/// Only a `certBag` whose inner `BAG-TYPE` is `x509Certificate` decodes; anything else answers
/// NULL without raising. The bytes are unpacked through the static `X509_it`.
///
/// # Safety
/// `bag` is live; the answer is owned by the caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_cert(bag: *const Pkcs12Safebag) -> *mut X509 {
    // SAFETY: `bag` is live.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_certBag {
        return ptr::null_mut();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    if unsafe { OBJ_obj2nid((*inner).type_) } != NID_x509Certificate {
        return ptr::null_mut();
    }
    // SAFETY: the inner selector says the octet arm holds the `ASN1_OCTET_STRING`; `X509_it` is
    // the static item the crate owns.
    unsafe { ASN1_item_unpack((*inner).value.cast::<Asn1String>(), X509_it()).cast::<X509>() }
}

/// `X509_CRL *PKCS12_SAFEBAG_get1_crl(const PKCS12_SAFEBAG *bag)` —
/// `crypto/pkcs12/p12_sbag.c:104-112`.
///
/// The `crlBag`/`x509Crl` twin of [`PKCS12_SAFEBAG_get1_cert`], through `X509_CRL_it`.
///
/// # Safety
/// `bag` is live; the answer is owned by the caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_crl(bag: *const Pkcs12Safebag) -> *mut X509Crl {
    // SAFETY: `bag` is live.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_crlBag {
        return ptr::null_mut();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    if unsafe { OBJ_obj2nid((*inner).type_) } != NID_x509Crl {
        return ptr::null_mut();
    }
    // SAFETY: the inner selector says the octet arm holds the `ASN1_OCTET_STRING`; `X509_CRL_it`
    // is the static item the crate owns.
    unsafe {
        ASN1_item_unpack((*inner).value.cast::<Asn1String>(), X509_CRL_it()).cast::<X509Crl>()
    }
}

/// `X509 *PKCS12_SAFEBAG_get1_cert_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/pkcs12/p12_sbag.c:114-130`.
///
/// As [`PKCS12_SAFEBAG_get1_cert`], but the decode carries `libctx`/`propq` and the answer is
/// stamped with them through `ossl_x509_set0_libctx`; a stamping failure releases the decoded
/// certificate and answers NULL.
///
/// # Safety
/// `bag` is live; `libctx` is NULL or a live context and `propq` NULL or NUL-terminated. The
/// answer is owned by the caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_cert_ex(
    bag: *const Pkcs12Safebag,
    libctx: *mut core::ffi::c_void,
    propq: *const c_char,
) -> *mut X509 {
    // SAFETY: `bag` is live.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_certBag {
        return ptr::null_mut();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    if unsafe { OBJ_obj2nid((*inner).type_) } != NID_x509Certificate {
        return ptr::null_mut();
    }
    // SAFETY: the inner selector says the octet arm holds the `ASN1_OCTET_STRING`; the context
    // arguments are the caller's.
    let ret = unsafe {
        ASN1_item_unpack_ex(
            (*inner).value.cast::<Asn1String>(),
            X509_it(),
            libctx,
            propq,
        )
        .cast::<X509>()
    };
    // SAFETY: `ret` is NULL or a live certificate this frame owns.
    if unsafe { ossl_x509_set0_libctx(ret, libctx, propq) } == 0 {
        // SAFETY: `ret` is live and this failure path owns it.
        unsafe { X509_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `X509_CRL *PKCS12_SAFEBAG_get1_crl_ex(const PKCS12_SAFEBAG *bag, OSSL_LIB_CTX *libctx,
/// const char *propq)` — `crypto/pkcs12/p12_sbag.c:132-148`.
///
/// The `crlBag`/`x509Crl` twin of [`PKCS12_SAFEBAG_get1_cert_ex`], stamping through
/// `ossl_x509_crl_set0_libctx`.
///
/// # Safety
/// As [`PKCS12_SAFEBAG_get1_cert_ex`], for a CRL. The answer is owned by the caller.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_get1_crl_ex(
    bag: *const Pkcs12Safebag,
    libctx: *mut core::ffi::c_void,
    propq: *const c_char,
) -> *mut X509Crl {
    // SAFETY: `bag` is live.
    if unsafe { PKCS12_SAFEBAG_get_nid(bag) } != NID_crlBag {
        return ptr::null_mut();
    }
    // SAFETY: the selector says the union holds a `bag`.
    let inner = unsafe { (*bag).value.cast::<Pkcs12Bags>() };
    // SAFETY: `inner` is live and its `type_` is its own object.
    if unsafe { OBJ_obj2nid((*inner).type_) } != NID_x509Crl {
        return ptr::null_mut();
    }
    // SAFETY: the inner selector says the octet arm holds the `ASN1_OCTET_STRING`; the context
    // arguments are the caller's.
    let ret = unsafe {
        ASN1_item_unpack_ex(
            (*inner).value.cast::<Asn1String>(),
            X509_CRL_it(),
            libctx,
            propq,
        )
        .cast::<X509Crl>()
    };
    // SAFETY: `ret` is NULL or a live CRL this frame owns.
    if unsafe { ossl_x509_crl_set0_libctx(ret, libctx, propq) } == 0 {
        // SAFETY: `ret` is live and this failure path owns it.
        unsafe { X509_CRL_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_cert(X509 *x509)` —
/// `crypto/pkcs12/p12_sbag.c:150-154`.
///
/// Packs the certificate through `X509_it` as an `x509Certificate` inside a `certBag`.
///
/// # Safety
/// `x509` is NULL or a live certificate; the answer is owned by the caller and does not adopt
/// `x509`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create_cert(x509: *mut X509) -> *mut Pkcs12Safebag {
    // SAFETY: `x509`/`X509_it()` are the caller's; the NIDs are the authority's literals.
    unsafe { PKCS12_item_pack_safebag(x509.cast(), X509_it(), NID_x509Certificate, NID_certBag) }
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_crl(X509_CRL *crl)` —
/// `crypto/pkcs12/p12_sbag.c:156-160`.
///
/// The `x509Crl`/`crlBag` twin of [`PKCS12_SAFEBAG_create_cert`], through `X509_CRL_it`.
///
/// # Safety
/// `crl` is NULL or a live CRL; the answer is owned by the caller and does not adopt `crl`.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create_crl(crl: *mut X509Crl) -> *mut Pkcs12Safebag {
    // SAFETY: `crl`/`X509_CRL_it()` are the caller's; the NIDs are the authority's literals.
    unsafe { PKCS12_item_pack_safebag(crl.cast(), X509_CRL_it(), NID_x509Crl, NID_crlBag) }
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

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(int pbe_nid, const char *pass,
/// int passlen, unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf,
/// OSSL_LIB_CTX *ctx, const char *propq)` — `crypto/pkcs12/p12_sbag.c:245-280`.
///
/// The cipher is first *fetched* by the NID's short name; a fetch failure falls back to the
/// legacy table, and a cipher found either way forces `pbe_nid = -1` so the PBES2 builder runs.
/// The failed fetch's error is discarded by the `ERR_set_mark`/`ERR_pop_to_mark` pair.
///
/// # Safety
/// `pass` is NULL or a string of `passlen` bytes (or NUL-terminated when `passlen == -1`);
/// `salt` is NULL or `saltlen` readable bytes; `p8inf` is a live `PKCS8_PRIV_KEY_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(
    pbe_nid: c_int,
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    iter: c_int,
    p8inf: *mut Pkcs8PrivKeyInfo,
    ctx: *mut c_void,
    propq: *const c_char,
) -> *mut Pkcs12Safebag {
    let mut pbe_nid = pbe_nid;

    let _ = ERR_set_mark();
    // SAFETY: `ctx`/`propq` are the fetch's; a NULL context is the default library context.
    let pbe_ciph_fetch = unsafe { EVP_CIPHER_fetch(ctx, OBJ_nid2sn(pbe_nid), propq) };
    let mut pbe_ciph: *const EvpCipher = pbe_ciph_fetch;
    if pbe_ciph.is_null() {
        // SAFETY: the NID resolves through the legacy name table.
        pbe_ciph = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(pbe_nid)) };
    }
    let _ = ERR_pop_to_mark();

    if !pbe_ciph.is_null() {
        pbe_nid = -1;
    }

    // SAFETY: `pbe_ciph` is NULL or a live cipher; the rest is forwarded.
    let p8 = unsafe {
        PKCS8_encrypt_ex(
            pbe_nid, pbe_ciph, pass, passlen, salt, saltlen, iter, p8inf, ctx, propq,
        )
    };
    if p8.is_null() {
        // SAFETY: `pbe_ciph_fetch` is NULL or a reference this frame holds.
        unsafe { EVP_CIPHER_free(pbe_ciph_fetch) };
        return ptr::null_mut();
    }

    // SAFETY: `p8` is live; ownership passes to the bag on success.
    let bag = unsafe { PKCS12_SAFEBAG_create0_pkcs8(p8) };
    if bag.is_null() {
        // SAFETY: `p8` is live and was not adopted.
        unsafe { X509_SIG_free(p8) };
    }

    // SAFETY: `pbe_ciph_fetch` is NULL or a reference this frame holds.
    unsafe { EVP_CIPHER_free(pbe_ciph_fetch) };
    bag
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid, const char *pass,
/// int passlen, unsigned char *salt, int saltlen, int iter,
/// PKCS8_PRIV_KEY_INFO *p8inf)` — `crypto/pkcs12/p12_sbag.c:282-292`.
///
/// # Safety
/// As [`PKCS12_SAFEBAG_create_pkcs8_encrypt_ex`], without the context arguments.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_create_pkcs8_encrypt(
    pbe_nid: c_int,
    pass: *const c_char,
    passlen: c_int,
    salt: *mut c_uchar,
    saltlen: c_int,
    iter: c_int,
    p8inf: *mut Pkcs8PrivKeyInfo,
) -> *mut Pkcs12Safebag {
    // SAFETY: the arguments are forwarded under this function's contract, with no context.
    unsafe {
        PKCS12_SAFEBAG_create_pkcs8_encrypt_ex(
            pbe_nid,
            pass,
            passlen,
            salt,
            saltlen,
            iter,
            p8inf,
            ptr::null_mut(),
            ptr::null(),
        )
    }
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
        // A `secretBag`'s outer type is `NID_secretBag`; the inner `type` is the caller's. It must
        // not be one of the three OIDs in `PKCS12_BAGS_adbtbl` (`p12_asn.c:51-55`) unless the value
        // really is that arm's type: those arms select an `ASN1_OCTET_STRING`/`ASN1_IA5STRING`, while
        // `create_secret` stores an `ASN1_ANY`, so freeing such a bag type-confuses the union. The
        // authority's own callers (`test/helpers/pkcs12.c`) pass a custom NID, which the ADB's
        // `bag_default` arm (an `ASN1_ANY`) matches.
        // SAFETY: `value` is three readable bytes and the NIDs are known.
        let bag = unsafe {
            PKCS12_SAFEBAG_create_secret(NID_secretBag, V_ASN1_OCTET_STRING, value.as_ptr(), 3)
        };
        assert!(!bag.is_null());
        // SAFETY: `bag` is live.
        unsafe {
            assert_eq!(PKCS12_SAFEBAG_get_nid(bag), NID_secretBag);
            assert_eq!(PKCS12_SAFEBAG_get_bag_nid(bag), NID_secretBag);
            assert!(!PKCS12_SAFEBAG_get0_bag_type(bag).is_null());
            // The inner `type` is not one of the three ADB OIDs, so `get0_bag_obj` takes the
            // default arm and answers the stored `ASN1_ANY`; the NULL answer belongs to the
            // certificate/CRL/ sdsi arms, which a secret bag never selects.
            assert!(!PKCS12_SAFEBAG_get0_bag_obj(bag).is_null());
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

    /// The cert/CRL readers refuse a bag whose outer type is not a `certBag`/`crlBag` without
    /// raising, on both the plain and the context spellings. The positive path needs a certificate
    /// that encodes, which the RT-PKCS12 court drives from the shared fixed DER.
    #[test]
    fn cert_readers_reject_a_secret_bag() {
        // The item layer and the object table are process-global state.
        let _guard = crate::test_support::lock_global_state();
        let value: [c_uchar; 2] = [0xaa, 0xbb];
        // The inner `type` is deliberately not one of the `PKCS12_BAGS_adbtbl` OIDs, so the ADB's
        // `bag_default` arm matches the `ASN1_ANY` `create_secret` stores and the free is
        // well-typed; the readers reject on the bag's outer `secretBag` type regardless.
        // SAFETY: `value` is two readable bytes and the NIDs are known.
        let secret = unsafe {
            PKCS12_SAFEBAG_create_secret(NID_secretBag, V_ASN1_OCTET_STRING, value.as_ptr(), 2)
        };
        assert!(!secret.is_null());
        // SAFETY: `secret` is live; the readers inspect its outer type and answer NULL.
        unsafe {
            assert!(PKCS12_SAFEBAG_get1_cert(secret).is_null());
            assert!(PKCS12_SAFEBAG_get1_crl(secret).is_null());
            assert!(PKCS12_SAFEBAG_get1_cert_ex(secret, ptr::null_mut(), ptr::null()).is_null());
            assert!(PKCS12_SAFEBAG_get1_crl_ex(secret, ptr::null_mut(), ptr::null()).is_null());
            PKCS12_SAFEBAG_free(secret);
        }
    }
}
