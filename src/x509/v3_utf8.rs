//! `crypto/x509/v3_utf8.c` — the Subject Sign Tool UTF-8 pair. Phase 10.13.
//!
//! `crypto/x509/v3_utf8.c` is 65 lines. **Two helpers land and the extension table is withheld**:
//!
//! * `i2s_ASN1_UTF8STRING` (`:28-42`) and `s2i_ASN1_UTF8STRING` (`:44-64`) land. Both are public
//!   exports (`x509v3.h`) and are the UTF-8 pair the extension machinery shares.
//!   `i2s_ASN1_UTF8STRING` raises `ERR_R_PASSED_NULL_PARAMETER` (`:34`) for a NULL or empty
//!   string; `s2i_ASN1_UTF8STRING` raises `X509V3_R_INVALID_NULL_ARGUMENT` (`:49`) for a NULL
//!   argument and `ERR_R_ASN1_LIB` (`:53`, `:57`) for the allocation and `ASN1_STRING_set`
//!   failures, whose coordinates are the generated `V3_UTF8_*` constants.
//! * `ossl_v3_utf8_list` (`:24-26`) is **withheld by name**. It is the one-row `EXT_UTF8STRING`
//!   table (`ASN1_UTF8STRING_it`, the two helpers landed here), and its blocker is the one every
//!   `ossl_v3_*` table shares in this subphase: the admitted DSO exports no `ossl_v3_*` symbol
//!   (`nm -D`), and its only authority caller is `X509V3_add_standard_extensions`
//!   (`crypto/x509/v3_lib.c:127`). That caller lands in [`crate::x509::v3_lib`], but the *dispatch*
//!   that would make the row observable -- `X509V3_EXT_get_nid` -- is withheld there because it
//!   searches `standard_exts[]` (`standard_exts.h:15-95`), which names ~63 `ossl_v3_*` tables from
//!   units this subphase does not own. See [`crate::x509::v3_lib`] for the whole blocker.
//!
//! Nothing is stubbed: the withheld table is named rather than declared.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.13 arms drive `s2i_ASN1_UTF8STRING` on a valid string and on NULL (the refusal
//! and its coordinate), then `i2s_ASN1_UTF8STRING` over the round trip and over an empty string
//! (the `PASSED_NULL_PARAMETER` refusal and its coordinate). Every arm pops its own error first.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_STRING_set, ASN1_UTF8STRING_free, ASN1_UTF8STRING_new};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;

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
