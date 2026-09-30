//! `crypto/x509/v3_skid.c` — the subject-key-identifier helpers and their row. Phase 10.12's
//! helpers, 10.14's table layer.
//!
//! `crypto/x509/v3_skid.c` is 108 lines and it now transcribes **whole** -- the unit's own five
//! names all land (D468 landed the row and the two helpers; D472 landed the two the row's `s2i` slot
//! and its `hash` arm needed):
//!
//! * `i2s_ASN1_OCTET_STRING` (`:27-31`) and `s2i_ASN1_OCTET_STRING` (`:33-52`) -- the octet-string
//!   pair every extension method that carries an `OCTET STRING` shares; `s2i_ASN1_OCTET_STRING`
//!   raises `ERR_R_ASN1_LIB` (`:40`, the generated `V3_SKID_40`).
//! * `ossl_x509_pubkey_hash` (`:54-88`) -- the SHA-1 digest of the public key's subjectPublicKey
//!   bits, the `keyid` the authority synthesises for a self-signed issuer carrying no
//!   subject-key-identifier extension. It raises `X509V3_R_NO_PUBLIC_KEY` (`:66`, the generated
//!   `V3_SKID_66`). **It belongs to this unit** (`crypto/x509/v3_skid.c`), and it was first landed
//!   inside `v3_akid.rs`'s module in D472 to avoid publishing a 72-entry partial array; D472's
//!   follow-up moved it here, where its authority unit and its `prerequisites.json` `owner_module`
//!   both say it lives.
//! * `s2i_skey_id` (`:90-108`) -- the row's `s2i` callback, landed now that the crate models
//!   `X509_REQ`/`X509_REQ_INFO` (`src/x509/x509_req.rs`, D472's pulled-forward subset), which was
//!   the one blocker: its `hash` arm reads `ctx->subject_req->req_info.pubkey`. It raises
//!   `X509V3_R_NO_SUBJECT_DETAILS` (`:103`, the generated `V3_SKID_103`).
//! * The row [`ossl_v3_skey_id`] (`:18-25`) lands with **every slot faithful to the authority**:
//!   `it` is `ASN1_ITEM_ref(ASN1_OCTET_STRING)`, `i2s` is `i2s_ASN1_OCTET_STRING`, `s2i` is now
//!   `s2i_skey_id` rather than the `None` D468 had to publish, and `ext_nid` is
//!   `NID_subject_key_identifier`.
//!
//! Nothing is withheld from this unit.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456). This unit
//! contributes one of the 63. The row is internal data the admitted DSO does not export (`nm -D`
//! shows no `ossl_v3_*`); the two helpers are the drivable surface, driven by `RT-STORE`.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.12 arms drive `s2i_ASN1_OCTET_STRING` on a hex string and on a malformed one,
//! then `i2s_ASN1_OCTET_STRING` over the round trip — byte-exact through the authority's own
//! `OPENSSL_buf2hexstr`/`OPENSSL_hexstr2buf`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::ASN1_OCTET_STRING_set;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::evp::digest::{EVP_Digest, EVP_MD_fetch, EVP_MD_free};
use crate::runtime::bio::sys::strcmp;
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::NID_subject_key_identifier;
use crate::runtime::str::{OPENSSL_buf2hexstr, OPENSSL_hexstr2buf};
use crate::x509::v3_conf::{X509V3Ctx, X509V3_CTX_TEST};
use crate::x509::v3_lib::{X509V3ExtI2s, X509V3ExtMethod};
use crate::x509::x509_req::X509Req;
use crate::x509::x_pubkey::{ossl_x509_PUBKEY_get0_libctx, X509Pubkey, X509_PUBKEY_get0_param};

/// `char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, const ASN1_OCTET_STRING *oct)` —
/// `crypto/x509/v3_skid.c:27-31`.
///
/// The authority does not null-check `oct`; it hands `oct->data` and `oct->length` straight to
/// `OPENSSL_buf2hexstr`.
///
/// # Safety
///
/// `oct` is a live `ASN1_OCTET_STRING` whose `data` holds `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_OCTET_STRING(
    method: *mut c_void,
    oct: *const Asn1String,
) -> *mut c_char {
    let _ = method;
    // SAFETY: `oct` is live per the contract.
    unsafe { OPENSSL_buf2hexstr((*oct).data, (*oct).length as c_long) }
}

/// `ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// const char *str)` — `crypto/x509/v3_skid.c:33-52`.
///
/// # Safety
///
/// `str` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn s2i_ASN1_OCTET_STRING(
    method: *mut c_void,
    ctx: *mut c_void,
    str_: *const c_char,
) -> *mut Asn1String {
    let _ = (method, ctx);
    let oct = ASN1_OCTET_STRING_new();
    if oct.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_SKID_40) };
        return ptr::null_mut();
    }
    let mut length: c_long = 0;
    // SAFETY: `str_` is NULL or NUL-terminated per the contract; `length` is writable.
    let data = unsafe { OPENSSL_hexstr2buf(str_, &raw mut length) };
    if data.is_null() {
        // SAFETY: `oct` is a live string this call owns.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        return ptr::null_mut();
    }
    // SAFETY: `oct` is live and owns `data` from here on.
    unsafe {
        (*oct).data = data;
        (*oct).length = length as c_int;
    }
    oct
}

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`, the digest buffer's maximum.
const EVP_MAX_MD_SIZE: usize = 64;
/// `SN_sha1` — `include/openssl/obj_mac.h`, the short name the fetch asks for.
const SN_SHA1: *const c_char = c"SHA1".as_ptr();

/// `ASN1_OCTET_STRING *ossl_x509_pubkey_hash(X509_PUBKEY *pubkey)` —
/// `crypto/x509/v3_skid.c:54-88`.
///
/// The SHA-1 digest of the public key's `subjectPublicKey` bits, the `keyid` the authority
/// synthesises for a self-signed issuer carrying no subject-key-identifier extension.
///
/// # Safety
///
/// `pubkey` is NULL or a live `X509_PUBKEY`.
pub(crate) unsafe fn ossl_x509_pubkey_hash(pubkey: *mut X509Pubkey) -> *mut Asn1String {
    if pubkey.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_SKID_66) };
        return ptr::null_mut();
    }
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    // SAFETY: `pubkey` is live; both out-pointers are writable locals.
    if unsafe { ossl_x509_PUBKEY_get0_libctx(&mut libctx, &mut propq, pubkey) } == 0 {
        return ptr::null_mut();
    }
    // SAFETY: `libctx`/`propq` come from the getter; the fetch answers NULL or a live `EVP_MD`.
    let md = unsafe { EVP_MD_fetch(libctx, SN_SHA1, propq) };
    if md.is_null() {
        return ptr::null_mut();
    }
    let oct = ASN1_OCTET_STRING_new();
    if oct.is_null() {
        // SAFETY: `md` is this call's own fetched method.
        unsafe { EVP_MD_free(md) };
        return ptr::null_mut();
    }

    let mut pk: *const c_uchar = ptr::null();
    let mut pklen: c_int = 0;
    // SAFETY: `pubkey` is live; the two out-pointers are writable locals and the rest are NULL.
    unsafe {
        X509_PUBKEY_get0_param(
            ptr::null_mut(),
            &mut pk,
            &mut pklen,
            ptr::null_mut(),
            pubkey,
        )
    };

    let mut pkey_dig = [0 as c_uchar; EVP_MAX_MD_SIZE];
    let mut diglen: c_uint = 0;
    // SAFETY: `pk` is borrowed for `pklen` bytes, `pkey_dig` is `EVP_MAX_MD_SIZE` writable bytes,
    // `diglen` is writable, and `md` is the fetched method.
    let ok = unsafe {
        EVP_Digest(
            pk.cast(),
            pklen as usize,
            pkey_dig.as_mut_ptr(),
            &mut diglen,
            md,
            ptr::null_mut(),
        )
    } != 0
        // SAFETY: `oct` is live; `pkey_dig` holds `diglen` bytes.
        && unsafe { ASN1_OCTET_STRING_set(oct, pkey_dig.as_ptr(), diglen as c_int) } != 0;
    // SAFETY: `md` is this call's own fetched method.
    unsafe { EVP_MD_free(md) };
    if ok {
        return oct;
    }
    // SAFETY: `oct` is this call's own string.
    unsafe { ASN1_OCTET_STRING_free(oct) };
    ptr::null_mut()
}

/// `static ASN1_OCTET_STRING *s2i_skey_id(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *str)` —
/// `crypto/x509/v3_skid.c:90-108`.
///
/// `"none"` answers a fresh empty string, any other non-`"hash"` text is handed to
/// [`s2i_ASN1_OCTET_STRING`], and `"hash"` answers the SHA-1 public-key digest of the context's
/// subject certificate or request — or, with neither, raises and answers NULL.
///
/// # Safety
///
/// `str` is NULL or NUL-terminated; `ctx` is NULL or a live `X509V3_CTX`.
unsafe extern "C" fn s2i_skey_id(
    method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    str_: *const c_char,
) -> *mut c_void {
    // SAFETY: `str_` is NULL or NUL-terminated per the contract; both literals are static.
    if unsafe { strcmp(str_, c"none".as_ptr()) } == 0 {
        return ASN1_OCTET_STRING_new().cast::<c_void>(); /* dummy */
    }
    // SAFETY: as above.
    if unsafe { strcmp(str_, c"hash".as_ptr()) } != 0 {
        // SAFETY: `method`/`ctx`/`str_` are the caller's, per this function's contract.
        return unsafe { s2i_ASN1_OCTET_STRING(method.cast_mut().cast(), ctx, str_) }
            .cast::<c_void>();
    }
    let ctx_v3 = ctx.cast::<X509V3Ctx>();
    // SAFETY: `ctx` is NULL or a live `X509V3_CTX` per the contract.
    if !ctx.is_null() && unsafe { (*ctx_v3).flags } & X509V3_CTX_TEST != 0 {
        return ASN1_OCTET_STRING_new().cast::<c_void>();
    }
    if ctx.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_SKID_103) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live per the contract; both fields are its own pointers.
    let (subject_cert, subject_req) = unsafe { ((*ctx_v3).subject_cert, (*ctx_v3).subject_req) };
    if subject_cert.is_null() && subject_req.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_SKID_103) };
        return ptr::null_mut();
    }
    let pubkey = if !subject_cert.is_null() {
        // SAFETY: `subject_cert` is a live `X509`; its embedded `cert_info.key` is the public key.
        unsafe { (*subject_cert).cert_info.key }
    } else {
        // SAFETY: `subject_req` is a live `X509_REQ` (the authority's `else` arm says so).
        unsafe { (*subject_req.cast::<X509Req>()).req_info.pubkey }
    };
    // SAFETY: `pubkey` is the live key the branch above read, or NULL; the callee accepts NULL.
    unsafe { ossl_x509_pubkey_hash(pubkey) }.cast::<c_void>()
}
const fn as_i2s(
    f: unsafe extern "C" fn(*mut c_void, *const Asn1String) -> *mut c_char,
) -> X509V3ExtI2s {
    // SAFETY: both function types take two pointer arguments and answer a pointer; the authority
    // writes exactly this cast in the row.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*mut c_void, *const Asn1String) -> *mut c_char,
            unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void) -> *mut c_char,
        >(f)
    })
}

/// `const X509V3_EXT_METHOD ossl_v3_skey_id` — `crypto/x509/v3_skid.c:18-25`.
///
/// The `s2i` slot is `None`, not the authority's `s2i_skey_id`, because that callback is withheld
/// (see the module doc); every other slot is the authority's.
pub static ossl_v3_skey_id: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_subject_key_identifier,
    ext_flags: 0,
    it: Some(ASN1_OCTET_STRING_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: as_i2s(i2s_ASN1_OCTET_STRING),
    s2i: Some(s2i_skey_id),
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
