//! `crypto/x509/v3_ia5.c` — the Netscape IA5 helpers and their table. Phase 10.12, table landed
//! under 10.14's table layer.
//!
//! `crypto/x509/v3_ia5.c` is 61 lines and now transcribes whole:
//!
//! * `i2s_ASN1_IA5STRING` (`:28-39`) and `s2i_ASN1_IA5STRING` (`:41-61`) land. Both are public
//!   exports (`x509v3.h`), and both are reached by the extension machinery every table in this
//!   stratum shares; `s2i_ASN1_IA5STRING` raises `X509V3_R_INVALID_NULL_ARGUMENT` (`:46`) and
//!   `ERR_R_ASN1_LIB` (`:50`), whose coordinates are the generated `V3_IA5_*` constants.
//! * `ossl_v3_ns_ia5_list` (`:17-26`) lands as an eight-row `[X509V3ExtMethod; 8]` — the seven
//!   `EXT_IA5STRING` rows plus the `EXT_END` sentinel (`x509v3.h:408-423`). It was withheld through
//!   10.12/10.13 as "dead data with no court"; D463 named it one of the 63 tables the published
//!   array needs and this slice lands it rather than withholding it again.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456), so the array is withheld until all 63 tables exist. The table is internal data the
//! admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); its drivable surface is the two
//! helpers, driven by `RT-STORE`.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.12 arms drive `s2i_ASN1_IA5STRING` on a valid string and on NULL (the refusal
//! and its coordinate), then `i2s_ASN1_IA5STRING` over the round trip and over an empty string
//! (the NULL answer). Both sides are compiled against the same public declarations.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::items::ASN1_IA5STRING_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_IA5STRING_free, ASN1_IA5STRING_new, ASN1_STRING_set};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::{
    NID_netscape_base_url, NID_netscape_ca_policy_url, NID_netscape_ca_revocation_url,
    NID_netscape_comment, NID_netscape_renewal_url, NID_netscape_revocation_url,
    NID_netscape_ssl_server_name,
};
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc` expansion — `crypto/x509/v3_ia5.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_ia5.c";
/// `i2s_ASN1_IA5STRING`'s `OPENSSL_malloc(ia5->length + 1)` (`:34`).
const LINE_MALLOC: c_int = 34;

/// `strlen` without a libc dependency, matching `src/asn1/a_dup.rs`'s local helper.
///
/// # Safety
/// `s` is NUL-terminated.
unsafe fn c_strlen(s: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: `s` is NUL-terminated per the contract.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5)` —
/// `crypto/x509/v3_ia5.c:28-39`.
///
/// A NULL or zero-length string answers NULL; otherwise a fresh NUL-terminated copy.
///
/// # Safety
///
/// `ia5` is NULL or a live `ASN1_IA5STRING` whose `data` holds `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_IA5STRING(
    method: *mut c_void,
    ia5: *mut Asn1String,
) -> *mut c_char {
    let _ = method;
    // SAFETY: `ia5` is NULL or live per the contract.
    unsafe {
        if ia5.is_null() || (*ia5).length <= 0 {
            return ptr::null_mut();
        }
        let len = (*ia5).length as usize;
        let tmp = CRYPTO_malloc(len + 1, FILE.as_ptr(), LINE_MALLOC).cast::<c_char>();
        if tmp.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping((*ia5).data, tmp.cast(), len);
        *tmp.add(len) = 0;
        tmp
    }
}

/// `ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)`
/// — `crypto/x509/v3_ia5.c:41-61`.
///
/// # Safety
///
/// `str` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn s2i_ASN1_IA5STRING(
    method: *mut c_void,
    ctx: *mut c_void,
    str_: *const c_char,
) -> *mut Asn1String {
    let _ = (method, ctx);
    if str_.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_IA5_46) };
        return ptr::null_mut();
    }
    let ia5 = ASN1_IA5STRING_new();
    if ia5.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_IA5_50) };
        return ptr::null_mut();
    }
    // SAFETY: `ia5` is live and `str_` is NUL-terminated per the contract.
    if unsafe { ASN1_STRING_set(ia5, str_.cast::<c_void>(), c_strlen(str_) as c_int) } == 0 {
        // SAFETY: `ia5` is a live string this call owns.
        unsafe { ASN1_IA5STRING_free(ia5) };
        return ptr::null_mut();
    }
    ia5
}

/// `EXT_IA5STRING(nid)` — `include/openssl/x509v3.h:408-413`. One table row: the
/// `ASN1_IA5STRING` item and this unit's `i2s_`/`s2i_` helpers, every other slot zero.
const fn ext_ia5string(nid: c_int) -> X509V3ExtMethod {
    X509V3ExtMethod {
        ext_nid: nid,
        ext_flags: 0,
        it: Some(ASN1_IA5STRING_it),
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        // SAFETY: both function types take two pointer arguments and answer a pointer; the
        // authority writes exactly this cast in the macro.
        i2s: Some(unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut c_void, *mut Asn1String) -> *mut c_char,
                unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void) -> *mut c_char,
            >(i2s_ASN1_IA5STRING)
        }),
        // SAFETY: both function types take three pointer arguments and answer a pointer.
        s2i: Some(unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut Asn1String,
                unsafe extern "C" fn(
                    *const X509V3ExtMethod,
                    *mut c_void,
                    *const c_char,
                ) -> *mut c_void,
            >(s2i_ASN1_IA5STRING)
        }),
        i2v: None,
        v2i: None,
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// `EXT_END` — `include/openssl/x509v3.h:423`, the `-1` terminator row `X509V3_EXT_add_list`
/// stops on.
const EXT_END: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: -1,
    ext_flags: 0,
    it: None,
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_ns_ia5_list[8]` — `crypto/x509/v3_ia5.c:17-26`.
///
/// The seven Netscape IA5 extensions a `NID` names, plus the `EXT_END` sentinel the array's
/// length-8 declaration includes.
pub static ossl_v3_ns_ia5_list: [X509V3ExtMethod; 8] = [
    ext_ia5string(NID_netscape_base_url),
    ext_ia5string(NID_netscape_revocation_url),
    ext_ia5string(NID_netscape_ca_revocation_url),
    ext_ia5string(NID_netscape_renewal_url),
    ext_ia5string(NID_netscape_ca_policy_url),
    ext_ia5string(NID_netscape_ssl_server_name),
    ext_ia5string(NID_netscape_comment),
    EXT_END,
];
