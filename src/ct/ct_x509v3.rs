//! `crypto/ct/ct_x509v3.c` — the Certificate Transparency X509v3/OCSP extension handlers. Phase
//! 10.14.15's CT layer. This unit defines the table `ossl_v3_ct_scts`, the CT row `crypto/x509`'s
//! `standard_exts[]` joins.
//!
//! `crypto/ct/ct_x509v3.c` is 104 lines and transcribes whole: the two poison hooks
//! `i2s_poison`/`s2i_poison` (`:16-24`), the reader `i2r_SCT_LIST` (`:26-31`), the source setter
//! `set_sct_list_source` (`:33-47`), the two d2i wrappers `x509_ext_d2i_SCT_LIST` (`:49-61`) and
//! `ocsp_ext_d2i_SCT_LIST` (`:63-75`), and the three-row table `ossl_v3_ct_scts[3]` (`:78-104`).
//!
//! The table's three rows, in source order:
//!
//! | row | `ext_nid` | `ext_flags` | `it` | `ext_free` | `d2i` | `i2d` | `i2r` |
//! |---|---|---|---|---|---|---|---|
//! | 0 | `NID_ct_precert_scts` (`951`) | `0` | `NULL` | `SCT_LIST_free` | `x509_ext_d2i_SCT_LIST` | `i2d_SCT_LIST` | `i2r_SCT_LIST` |
//! | 1 | `NID_ct_precert_poison` (`952`) | `0` | `ASN1_ITEM_ref(ASN1_NULL)` | `NULL` | `NULL` | `NULL` | `NULL` (also `i2s_poison`/`s2i_poison`) |
//! | 2 | `NID_ct_cert_scts` (`954`) | `0` | `NULL` | `SCT_LIST_free` | `ocsp_ext_d2i_SCT_LIST` | `i2d_SCT_LIST` | `i2r_SCT_LIST` |
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the lookup names in
//! `src/x509/v3_lib.rs` it feeds, exactly as every other `v3_*.rs` table unit withholds them (D456).
//! This unit contributes one of the 63 rows. The row itself is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`), so it carries `pub static` but **not** `#[no_mangle]`.
//!
//! The unit raises nothing, so it declares no coordinates.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::items::ASN1_NULL_it;
use crate::asn1::typ::ASN1_NULL_new;
use crate::ct::ct_oct::{d2i_SCT_LIST, i2d_SCT_LIST};
use crate::ct::ct_prn::SCT_LIST_print;
use crate::ct::ct_sct::{
    SCT_LIST_free, SCT_set_source, Sct, SCT_SOURCE_OCSP_STAPLED_RESPONSE,
    SCT_SOURCE_X509V3_EXTENSION,
};
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_strdup;
use crate::runtime::obj::{NID_ct_cert_scts, NID_ct_precert_poison, NID_ct_precert_scts};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{
    X509V3ExtD2i, X509V3ExtFree, X509V3ExtI2d, X509V3ExtI2r, X509V3ExtMethod,
};

/// `static char *i2s_poison(const X509V3_EXT_METHOD *method, void *val)` —
/// `crypto/ct/ct_x509v3.c:16-19`.
///
/// # Safety
///
/// The caller's contract is the row's: neither argument is read.
unsafe extern "C" fn i2s_poison(_method: *const X509V3ExtMethod, _val: *mut c_void) -> *mut c_char {
    // SAFETY: `"NULL"` is a static NUL-terminated string.
    unsafe { CRYPTO_strdup(c"NULL".as_ptr(), ptr::null(), 0) }
}

/// `static void *s2i_poison(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str)` —
/// `crypto/ct/ct_x509v3.c:21-24`.
///
/// # Safety
///
/// The caller's contract is the row's: no argument is read.
unsafe extern "C" fn s2i_poison(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list, BIO *out, int
/// indent)` — `crypto/ct/ct_x509v3.c:26-31`.
///
/// # Safety
///
/// `sct_list` is a live `STACK_OF(SCT)`; `out` is a live `BIO`.
unsafe extern "C" fn i2r_SCT_LIST(
    _method: *mut X509V3ExtMethod,
    sct_list: *mut OpenSslStack,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `sct_list` and `out` are live per the contract; the separator is static and no log
    // store is supplied.
    unsafe { SCT_LIST_print(sct_list, out, indent, c"\n".as_ptr(), ptr::null()) };
    1
}

/// `static int set_sct_list_source(STACK_OF(SCT) *s, sct_source_t source)` —
/// `crypto/ct/ct_x509v3.c:33-47`.
///
/// # Safety
///
/// `s` is NULL or a live `STACK_OF(SCT)` of live `SCT`s.
unsafe fn set_sct_list_source(s: *mut OpenSslStack, source: c_int) -> c_int {
    if !s.is_null() {
        // SAFETY: `s` is live per the contract.
        let num = unsafe { OPENSSL_sk_num(s) };
        let mut i = 0;
        while i < num {
            // SAFETY: `s` is live and `i` is in bounds.
            let value = unsafe { OPENSSL_sk_value(s, i) }.cast::<Sct>();
            // SAFETY: `value` is a live element.
            let res = unsafe { SCT_set_source(value, source) };
            if res != 1 {
                return 0;
            }
            i += 1;
        }
    }
    1
}

/// `static STACK_OF(SCT) *x509_ext_d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp, long
/// len)` — `crypto/ct/ct_x509v3.c:49-61`.
///
/// # Safety
///
/// `a` is NULL or a writable stack slot; `pp` addresses a readable cursor for at least `len` bytes.
unsafe extern "C" fn x509_ext_d2i_SCT_LIST(
    a: *mut *mut OpenSslStack,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: `a` and `pp` satisfy the decoder's contract per this function's own.
    let s = unsafe { d2i_SCT_LIST(a, pp, len) };

    // SAFETY: `s` is NULL or the stack the decoder produced.
    if unsafe { set_sct_list_source(s, SCT_SOURCE_X509V3_EXTENSION) } != 1 {
        // SAFETY: `s` is NULL or the stack this call owns.
        unsafe { SCT_LIST_free(s) };
        if !a.is_null() {
            // SAFETY: `a` is non-NULL, hence a writable slot, per the contract.
            unsafe { *a = ptr::null_mut() };
        }
        return ptr::null_mut();
    }
    s
}

/// `static STACK_OF(SCT) *ocsp_ext_d2i_SCT_LIST(STACK_OF(SCT) **a, const unsigned char **pp, long
/// len)` — `crypto/ct/ct_x509v3.c:63-75`.
///
/// # Safety
///
/// `a` is NULL or a writable stack slot; `pp` addresses a readable cursor for at least `len` bytes.
unsafe extern "C" fn ocsp_ext_d2i_SCT_LIST(
    a: *mut *mut OpenSslStack,
    pp: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: `a` and `pp` satisfy the decoder's contract per this function's own.
    let s = unsafe { d2i_SCT_LIST(a, pp, len) };

    // SAFETY: `s` is NULL or the stack the decoder produced.
    if unsafe { set_sct_list_source(s, SCT_SOURCE_OCSP_STAPLED_RESPONSE) } != 1 {
        // SAFETY: `s` is NULL or the stack this call owns.
        unsafe { SCT_LIST_free(s) };
        if !a.is_null() {
            // SAFETY: `a` is non-NULL, hence a writable slot, per the contract.
            unsafe { *a = ptr::null_mut() };
        }
        return ptr::null_mut();
    }
    s
}

/// `(X509V3_EXT_FREE)SCT_LIST_free` — the cast the table's `ext_free` slot writes.
const fn as_free(f: unsafe extern "C" fn(*mut OpenSslStack)) -> X509V3ExtFree {
    // SAFETY: both function types take one pointer argument and answer nothing.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*mut OpenSslStack),
            unsafe extern "C" fn(*mut c_void),
        >(f)
    })
}

/// `(X509V3_EXT_D2I)x509_ext_d2i_SCT_LIST` — the cast the table's `d2i` slot writes.
const fn as_d2i(
    f: unsafe extern "C" fn(
        *mut *mut OpenSslStack,
        *mut *const c_uchar,
        c_long,
    ) -> *mut OpenSslStack,
) -> X509V3ExtD2i {
    // SAFETY: both function types take a `void **`, a cursor and a length, and answer a pointer.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                *mut *mut OpenSslStack,
                *mut *const c_uchar,
                c_long,
            ) -> *mut OpenSslStack,
            unsafe extern "C" fn(*mut c_void, *mut *const c_uchar, c_long) -> *mut c_void,
        >(f)
    })
}

/// `(X509V3_EXT_I2D)i2d_SCT_LIST` — the cast the table's `i2d` slot writes.
const fn as_i2d(
    f: unsafe extern "C" fn(*const OpenSslStack, *mut *mut c_uchar) -> c_int,
) -> X509V3ExtI2d {
    // SAFETY: both function types take a `const void *` and a cursor, and answer an `int`.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*const OpenSslStack, *mut *mut c_uchar) -> c_int,
            unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int,
        >(f)
    })
}

/// `(X509V3_EXT_I2R)i2r_SCT_LIST` — the cast the table's `i2r` slot writes.
const fn as_i2r(
    f: unsafe extern "C" fn(*mut X509V3ExtMethod, *mut OpenSslStack, *mut Bio, c_int) -> c_int,
) -> X509V3ExtI2r {
    // SAFETY: both function types take a method, a value, a `BIO` and an indent, and answer an
    // `int`.
    Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(*mut X509V3ExtMethod, *mut OpenSslStack, *mut Bio, c_int) -> c_int,
            unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void, *mut Bio, c_int) -> c_int,
        >(f)
    })
}

/// `const X509V3_EXT_METHOD ossl_v3_ct_scts[3]` — `crypto/ct/ct_x509v3.c:78-104`.
///
/// Row 0 is the certificate SCT extension, row 1 the poison marker (the only row with an item and
/// the string pair), and row 2 the OCSP SCT extension.
pub static ossl_v3_ct_scts: [X509V3ExtMethod; 3] = [
    // X509v3 extension in certificates that contains SCTs.
    X509V3ExtMethod {
        ext_nid: NID_ct_precert_scts,
        ext_flags: 0,
        it: None,
        ext_new: None,
        ext_free: as_free(SCT_LIST_free),
        d2i: as_d2i(x509_ext_d2i_SCT_LIST),
        i2d: as_i2d(i2d_SCT_LIST),
        i2s: None,
        s2i: None,
        i2v: None,
        v2i: None,
        i2r: as_i2r(i2r_SCT_LIST),
        r2i: None,
        usr_data: ptr::null_mut(),
    },
    // X509v3 extension to mark a certificate as a pre-certificate.
    X509V3ExtMethod {
        ext_nid: NID_ct_precert_poison,
        ext_flags: 0,
        it: Some(ASN1_NULL_it),
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: Some(i2s_poison),
        s2i: Some(s2i_poison),
        i2v: None,
        v2i: None,
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    },
    // OCSP extension that contains SCTs.
    X509V3ExtMethod {
        ext_nid: NID_ct_cert_scts,
        ext_flags: 0,
        it: None,
        ext_new: None,
        ext_free: as_free(SCT_LIST_free),
        d2i: as_d2i(ocsp_ext_d2i_SCT_LIST),
        i2d: as_i2d(i2d_SCT_LIST),
        i2s: None,
        s2i: None,
        i2v: None,
        v2i: None,
        i2r: as_i2r(i2r_SCT_LIST),
        r2i: None,
        usr_data: ptr::null_mut(),
    },
];
