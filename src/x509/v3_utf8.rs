//! `crypto/x509/v3_utf8.c` — the Subject Sign Tool UTF-8 pair and its table. Phase 10.13, table
//! landed under 10.14's table layer.
//!
//! `crypto/x509/v3_utf8.c` is 65 lines and now transcribes whole:
//!
//! * `i2s_ASN1_UTF8STRING` (`:28-42`) and `s2i_ASN1_UTF8STRING` (`:44-64`) land. Both are public
//!   exports (`x509v3.h`) and are the UTF-8 pair the extension machinery shares.
//!   `i2s_ASN1_UTF8STRING` raises `ERR_R_PASSED_NULL_PARAMETER` (`:34`) for a NULL or empty
//!   string; `s2i_ASN1_UTF8STRING` raises `X509V3_R_INVALID_NULL_ARGUMENT` (`:49`) for a NULL
//!   argument and `ERR_R_ASN1_LIB` (`:53`, `:57`) for the allocation and `ASN1_STRING_set`
//!   failures, whose coordinates are the generated `V3_UTF8_*` constants.
//! * `ossl_v3_utf8_list` (`:24-26`) lands as a one-row `[X509V3ExtMethod; 1]`, the
//!   `EXT_UTF8STRING` row for `NID_subjectSignTool` (`x509v3.h:415-420`; the array is length-1, so
//!   it carries no `EXT_END`). It was withheld through 10.13; D463 named it one of the 63 tables.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). The table is unnameable from the admitted DSO; the two helpers are the drivable
//! surface.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms drive `s2i_ASN1_UTF8STRING` on a valid string and on NULL (the refusal
//! and its coordinate), then `i2s_ASN1_UTF8STRING` over the round trip and over an empty string
//! (the `PASSED_NULL_PARAMETER` refusal and its coordinate). Every arm pops its own error first.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::items::ASN1_UTF8STRING_it;
use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_STRING_set, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;
use crate::runtime::obj::NID_subjectSignTool;
use crate::x509::v3_lib::X509V3ExtMethod;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc` expansion — `crypto/x509/v3_utf8.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_utf8.c";
/// `i2s_ASN1_UTF8STRING`'s `OPENSSL_malloc(utf8->length + 1)` (`:37`).
const LINE_MALLOC: c_int = 37;

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

/// `char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8)` —
/// `crypto/x509/v3_utf8.c:28-42`.
///
/// A NULL or zero-length string raises `ERR_R_PASSED_NULL_PARAMETER` and answers NULL
/// (`:33-36`); otherwise a fresh NUL-terminated copy, or NULL if the allocation fails.
///
/// # Safety
///
/// `utf8` is NULL or a live `ASN1_UTF8STRING` whose `data` holds `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn i2s_ASN1_UTF8STRING(
    method: *mut c_void,
    utf8: *mut Asn1String,
) -> *mut c_char {
    let _ = method;
    // SAFETY: `utf8` is NULL or live per the contract.
    unsafe {
        if utf8.is_null() || (*utf8).length == 0 {
            // SAFETY: the site is a compiled-in constant.
            raise_site(&err_sites::V3_UTF8_34);
            return ptr::null_mut();
        }
        let len = (*utf8).length as usize;
        let tmp = CRYPTO_malloc(len + 1, FILE.as_ptr(), LINE_MALLOC).cast::<c_char>();
        if tmp.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping((*utf8).data, tmp.cast(), len);
        *tmp.add(len) = 0;
        tmp
    }
}

/// `ASN1_UTF8STRING *s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// const char *str)` — `crypto/x509/v3_utf8.c:44-64`.
///
/// # Safety
///
/// `str_` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn s2i_ASN1_UTF8STRING(
    method: *mut c_void,
    ctx: *mut c_void,
    str_: *const c_char,
) -> *mut Asn1String {
    let _ = (method, ctx);
    if str_.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_UTF8_49) };
        return ptr::null_mut();
    }
    let utf8 = ASN1_UTF8STRING_new();
    if utf8.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_UTF8_53) };
        return ptr::null_mut();
    }
    // SAFETY: `utf8` is live and `str_` is NUL-terminated per the contract.
    if unsafe { ASN1_STRING_set(utf8, str_.cast::<c_void>(), c_strlen(str_) as c_int) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&err_sites::V3_UTF8_57) };
        // SAFETY: `utf8` is a live string this call owns.
        unsafe { ASN1_UTF8STRING_free(utf8) };
        return ptr::null_mut();
    }
    utf8
}

/// `EXT_UTF8STRING(nid)` — `include/openssl/x509v3.h:415-420`. One table row: the
/// `ASN1_UTF8STRING` item and this unit's `i2s_`/`s2i_` helpers, every other slot zero.
const fn ext_utf8string(nid: c_int) -> X509V3ExtMethod {
    X509V3ExtMethod {
        ext_nid: nid,
        ext_flags: 0,
        it: Some(ASN1_UTF8STRING_it),
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
            >(i2s_ASN1_UTF8STRING)
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
            >(s2i_ASN1_UTF8STRING)
        }),
        i2v: None,
        v2i: None,
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// `const X509V3_EXT_METHOD ossl_v3_utf8_list[1]` — `crypto/x509/v3_utf8.c:24-26`.
///
/// The Subject Sign Tool extension (1.2.643.100.111), a single `EXT_UTF8STRING` row with no
/// `EXT_END` sentinel (the array is length-1).
pub static ossl_v3_utf8_list: [X509V3ExtMethod; 1] = [ext_utf8string(NID_subjectSignTool)];
