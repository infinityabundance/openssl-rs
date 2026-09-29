//! `crypto/x509/v3_skid.c` — the subject-key-identifier helpers and their row. Phase 10.12's
//! helpers, 10.14's table layer.
//!
//! `crypto/x509/v3_skid.c` is 108 lines. **Three names land and two are withheld**:
//!
//! * `i2s_ASN1_OCTET_STRING` (`:27-31`) and `s2i_ASN1_OCTET_STRING` (`:33-52`) land. Both are
//!   public exports (`x509v3.h`) and are the octet-string pair every extension method that carries
//!   an `OCTET STRING` shares; `s2i_ASN1_OCTET_STRING` raises `ERR_R_ASN1_LIB` (`:40`), whose
//!   coordinate is the generated `V3_SKID_40`.
//! * The row [`ossl_v3_skey_id`] (`:18-25`) lands. Its `it` is `ASN1_ITEM_ref(ASN1_OCTET_STRING)`,
//!   its `i2s` is `i2s_ASN1_OCTET_STRING`, and its `ext_nid` is `NID_subject_key_identifier`. The
//!   row's **`s2i` slot is `None`**: the authority's `s2i` is `s2i_skey_id`, which is withheld (see
//!   below), so this one slot is not byte-faithful to the authority.
//!
//! **Withheld by name, with its blocker**:
//!
//! * `s2i_skey_id` (`:90-108`) — the authority's `s2i` callback and the reason for the row's NULL
//!   `s2i` slot above. Its `hash` arm reads `ctx->subject_req->req_info.pubkey`, and the crate has
//!   **no `X509_REQ`/`X509_REQ_INFO` type to name** (`crypto/x509/x509_req.c` is 10.14.11, and
//!   `X509V3Ctx.subject_req` is an opaque `*mut c_void` slot). Landing it piecewise would be a
//!   partial body, so it is withheld whole (rule 1: never stub). It raises
//!   `X509V3_R_NO_SUBJECT_DETAILS` (`:103`, the generated `V3_SKID_103`).
//! * `ossl_x509_pubkey_hash` (`:54-88`) — D453's second reason: its closure is complete (every
//!   callee is landed: `EVP_MD_fetch`/`EVP_Digest`/`EVP_MD_free`, `X509_PUBKEY_get0_param`,
//!   `ossl_x509_PUBKEY_get0_libctx`, `ASN1_OCTET_STRING_new`/`_set`/`_free`) but it has **no
//!   reachable caller**: its only in-unit caller `s2i_skey_id` is itself withheld, and its other
//!   authority callers are unlanded. It raises `X509V3_R_NO_PUBLIC_KEY` (`:66`, the generated
//!   `V3_SKID_66`). One coordinate per withheld raise site is already generated.
//!
//! Nothing is stubbed: the two withheld names are named rather than declared.
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

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::items::ASN1_OCTET_STRING_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::NID_subject_key_identifier;
use crate::runtime::str::{OPENSSL_buf2hexstr, OPENSSL_hexstr2buf};
use crate::x509::v3_lib::{X509V3ExtI2s, X509V3ExtMethod};

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

/// `(X509V3_EXT_I2S)i2s_ASN1_OCTET_STRING` — the cast the row's initialiser writes.
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
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
