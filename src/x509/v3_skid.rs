//! `crypto/x509/v3_skid.c` — the subject-key-identifier helpers. Phase 10.12.
//!
//! `crypto/x509/v3_skid.c` is 108 lines. **Two helpers land and three names are withheld**:
//!
//! * `i2s_ASN1_OCTET_STRING` (`:27-31`) and `s2i_ASN1_OCTET_STRING` (`:33-52`) land. Both are
//!   public exports (`x509v3.h`) and are the octet-string pair every extension method that carries
//!   an `OCTET STRING` shares; `s2i_ASN1_OCTET_STRING` raises `ERR_R_ASN1_LIB` (`:40`), whose
//!   coordinate is the generated `V3_SKID_40`.
//! * `ossl_v3_skey_id` (`:18-25`) is **withheld by name**: it is the `NID_subject_key_identifier`
//!   table, internal and not exported by the admitted DSO (`nm -D` shows no `ossl_v3_*`), and its
//!   only authority caller is `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`),
//!   which is 10.14's.
//! * `ossl_x509_pubkey_hash` (`:54-88`) is **withheld by name**: an internal `ossl_`-prefixed
//!   export absent from the DSO, whose only authority callers are `s2i_skey_id` here and
//!   `X509_PUBKEY_get0_...` consumers that are not landed. It raises `X509V3_R_NO_PUBLIC_KEY`
//!   (`:66`), an unused coordinate once the generator carries the file.
//! * `s2i_skey_id` (`:90-108`) is **withheld by name**: a `static` reached only through the
//!   withheld `ossl_v3_skey_id`, so landing it would be dead code. It raises
//!   `X509V3_R_NO_SUBJECT_DETAILS` (`:103`), also unused until it lands.
//!
//! Nothing is stubbed: the three withheld names are named rather than declared, so the crate's
//! surface is only what the two helpers define.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.12 arms drive `s2i_ASN1_OCTET_STRING` on a hex string and on a malformed one,
//! then `i2s_ASN1_OCTET_STRING` over the round trip — byte-exact through the authority's own
//! `OPENSSL_buf2hexstr`/`OPENSSL_hexstr2buf`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::str::{OPENSSL_buf2hexstr, OPENSSL_hexstr2buf};

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
