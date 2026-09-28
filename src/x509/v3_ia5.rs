//! `crypto/x509/v3_ia5.c` — the Netscape IA5 helpers. Phase 10.12.
//!
//! `crypto/x509/v3_ia5.c` is 61 lines. **Two functions land and the extension table is withheld**:
//!
//! * `i2s_ASN1_IA5STRING` (`:28-39`) and `s2i_ASN1_IA5STRING` (`:41-61`) land. Both are public
//!   exports (`x509v3.h`), and both are reached by the extension machinery every table in this
//!   stratum shares; `s2i_ASN1_IA5STRING` raises `X509V3_R_INVALID_NULL_ARGUMENT` (`:46`) and
//!   `ERR_R_ASN1_LIB` (`:50`), whose coordinates are the generated `V3_IA5_*` constants.
//! * `ossl_v3_ns_ia5_list` (`:17-26`) is **withheld by name**. It is the eight-row `EXT_IA5STRING`
//!   table, and its blocker is the same for every v3 table in this subphase: it is an internal
//!   symbol the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`), so the differential
//!   plane cannot name it; and its only authority caller is `X509V3_add_standard_extensions`
//!   (`crypto/x509/v3_lib.c:127`), which is 10.14's. It would be dead data with no court.
//!
//! Nothing is stubbed: the withheld table is named rather than declared, so the crate's surface is
//! only what the two helpers define.
//!
//! ## The court
//!
//! `RT-STORE`'s 10.12 arms drive `s2i_ASN1_IA5STRING` on a valid string and on NULL (the refusal
//! and its coordinate), then `i2s_ASN1_IA5STRING` over the round trip and over an empty string
//! (the NULL answer). Both sides are compiled against the same public declarations.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::string::{ASN1_IA5STRING_free, ASN1_IA5STRING_new, ASN1_STRING_set};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_malloc;

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
