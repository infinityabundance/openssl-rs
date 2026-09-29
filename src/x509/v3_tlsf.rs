//! `crypto/x509/v3_tlsf.c` — the `TLS_FEATURE` item and its row. Phase 10.14.8's table layer,
//! landed whole.
//!
//! `crypto/x509/v3_tlsf.c` is 137 lines and transcribes whole:
//!
//! * `TLS_FEATURE ::= SEQUENCE OF ASN1_INTEGER` (`:26-29`) lands. The authority ends it with
//!   `static_ASN1_ITEM_TEMPLATE_END`, so the item is **file-local** and no `TLS_FEATURE_it` is
//!   exported; only `TLS_FEATURE_new`/`TLS_FEATURE_free` are, from
//!   `DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)` (`x509v3.h:609`) and
//!   `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)` (`:29`). The row references the item through a
//!   crate-local function, not an exported symbol.
//! * `i2v_TLS_FEATURE` (`:58-78`) and `v2i_TLS_FEATURE` (`:85-137`) land, over the two-row
//!   `tls_feature_tbl` (`:47-50`).
//! * The row [`ossl_v3_tls_feature`] (`:31-40`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the allocator pair and the two callbacks are the
//! drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_tlsf.c` is not an entry in `gen_err_raise_sites.py`, so its three coordinates
//! are **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{ASN1_INTEGER_get, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new};
use crate::runtime::bio::sys::strtol;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_INVALID_SYNTAX;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_tlsfeature;
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::str::OPENSSL_strcasecmp;
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{conf_add_error_name_value, X509V3_add_value, X509V3_add_value_int};

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_tlsf.c` raise coordinate, declared locally (see the module doc).
const fn v3_tlsf_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_tlsf.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_TLS_FEATURE`'s stack allocation failure at `v3_tlsf.c:97`.
const V3_TLSF_97: crate::runtime::err::err_sites::ErrSite =
    v3_tlsf_site(97, c"v2i_TLS_FEATURE", ERR_R_CRYPTO_LIB);
/// `v2i_TLS_FEATURE`'s ill-formed id at `v3_tlsf.c:116`.
const V3_TLSF_116: crate::runtime::err::err_sites::ErrSite =
    v3_tlsf_site(116, c"v2i_TLS_FEATURE", X509V3_R_INVALID_SYNTAX);
/// `v2i_TLS_FEATURE`'s integer build failure at `v3_tlsf.c:125`.
const V3_TLSF_125: crate::runtime::err::err_sites::ErrSite =
    v3_tlsf_site(125, c"v2i_TLS_FEATURE", ERR_R_ASN1_LIB);

/// `static TLS_FEATURE_NAME tls_feature_tbl[]` — `crypto/x509/v3_tlsf.c:47-50`.
///
/// A `{ long num; const char *name; }` row.
struct TlsFeatureName {
    /// `long num` — the TLS extension id.
    num: c_long,
    /// `const char *name`.
    name: *const c_char,
}

// SAFETY: every row is fully initialised at compile time and never written; its name borrows a
// `'static` literal. The same claim `BitStringBitname` makes.
unsafe impl Sync for TlsFeatureName {}

/// `static TLS_FEATURE_NAME tls_feature_tbl[]` — `crypto/x509/v3_tlsf.c:47-50`.
static TLS_FEATURE_TBL: [TlsFeatureName; 2] = [
    TlsFeatureName {
        num: 5,
        name: c"status_request".as_ptr(),
    },
    TlsFeatureName {
        num: 17,
        name: c"status_request_v2".as_ptr(),
    },
];

/// `void (*)(void *)` thunk for `sk_ASN1_INTEGER_pop_free(..., ASN1_INTEGER_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `ASN1_INTEGER` (the stack contract).
unsafe extern "C" fn asn1_integer_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_INTEGER` pointers per the contract.
    unsafe { ASN1_INTEGER_free(p.cast::<Asn1String>()) };
}

/// `TLS_FEATURE_tmpl_tt` — `ASN1_ITEM_TEMPLATE(TLS_FEATURE)`'s single template
/// (`crypto/x509/v3_tlsf.c:26`): `ASN1_TFLG_SEQUENCE_OF` over `ASN1_INTEGER`.
static TLS_FEATURE_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"TLS_FEATURE".as_ptr(),
    item: ASN1_INTEGER_it as *mut c_void,
};

/// `TLS_FEATURE_it`'s descriptor — `static_ASN1_ITEM_TEMPLATE_END(TLS_FEATURE)` at
/// `crypto/x509/v3_tlsf.c:27`.
static TLS_FEATURE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &TLS_FEATURE_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"TLS_FEATURE".as_ptr(),
};

/// The authority's `static ... TLS_FEATURE_it` — **not** an exported symbol, so this module answers
/// it privately for the row and does not mark it `#[no_mangle]`.
unsafe extern "C" fn tls_feature_it() -> *const Asn1Item {
    &TLS_FEATURE_ITEM
}

/// `TLS_FEATURE *TLS_FEATURE_new(void)` — `crypto/x509/v3_tlsf.c:29`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)`.
#[no_mangle]
pub extern "C" fn TLS_FEATURE_new() -> *mut OpenSslStack {
    // SAFETY: the item is a static the crate owns.
    unsafe { ASN1_item_new(tls_feature_it()).cast::<OpenSslStack>() }
}

/// `void TLS_FEATURE_free(TLS_FEATURE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn TLS_FEATURE_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), tls_feature_it()) }
}

/// `static STACK_OF(CONF_VALUE) *i2v_TLS_FEATURE(const X509V3_EXT_METHOD *method, TLS_FEATURE
/// *tls_feature, STACK_OF(CONF_VALUE) *ext_list)` — `crypto/x509/v3_tlsf.c:58-78`.
///
/// A known id prints as its name; anything else prints through `X509V3_add_value_int`.
unsafe extern "C" fn i2v_TLS_FEATURE(
    _method: *const X509V3ExtMethod,
    tls_feature: *mut c_void,
    ext_list: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut ext_list = ext_list;
    let tls_feature = tls_feature.cast::<OpenSslStack>();
    // SAFETY: `tls_feature` is a live `STACK_OF(ASN1_INTEGER)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(tls_feature) };
    let mut i = 0;
    while i < num {
        // SAFETY: `tls_feature` is live and `i` is in bounds.
        let ai = unsafe { OPENSSL_sk_value(tls_feature, i) }.cast::<Asn1String>();
        // SAFETY: `ai` is a live `ASN1_INTEGER`.
        let tlsextid = unsafe { ASN1_INTEGER_get(ai) };
        let mut matched: Option<&TlsFeatureName> = None;
        for row in TLS_FEATURE_TBL.iter() {
            if tlsextid == row.num {
                matched = Some(row);
                break;
            }
        }
        match matched {
            // SAFETY: the name is a static literal; `ext_list` is this call's sink.
            Some(row) => unsafe { X509V3_add_value(ptr::null(), row.name, &mut ext_list) },
            // SAFETY: `ai` is live; `ext_list` is this call's sink.
            None => unsafe { X509V3_add_value_int(ptr::null(), ai, &mut ext_list) },
        };
        i += 1;
    }
    ext_list
}

/// `static TLS_FEATURE *v2i_TLS_FEATURE(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_tlsf.c:85-137`.
unsafe extern "C" fn v2i_TLS_FEATURE(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let tlsf = OPENSSL_sk_new_null();
    if tlsf.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_TLSF_97) };
        return ptr::null_mut();
    }
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract.
        let extval = unsafe {
            if (*val).value.is_null() {
                (*val).name
            } else {
                (*val).value
            }
        };
        let mut tlsextid: c_long = 0;
        let mut matched = false;
        for row in TLS_FEATURE_TBL.iter() {
            // SAFETY: both strings are NUL-terminated; the row's name is static.
            if unsafe { OPENSSL_strcasecmp(extval, row.name) } == 0 {
                tlsextid = row.num;
                matched = true;
                break;
            }
        }
        if !matched {
            let mut endptr: *mut c_char = ptr::null_mut();
            // SAFETY: `extval` is NUL-terminated; `endptr` is writable.
            tlsextid = unsafe { strtol(extval, &raw mut endptr, 10) };
            // SAFETY: `endptr` points into `extval`'s buffer.
            if unsafe { *endptr != 0 } || extval == endptr || !(0..=65535).contains(&tlsextid) {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_TLSF_116) };
                // SAFETY: `val` is live per the contract.
                unsafe { conf_add_error_name_value(val) };
                // SAFETY: `tlsf` is the list this call built, holding only integers.
                unsafe { OPENSSL_sk_pop_free(tlsf, Some(asn1_integer_free_thunk)) };
                return ptr::null_mut();
            }
        }
        let ai = ASN1_INTEGER_new();
        let pushed = if ai.is_null() {
            0
        } else {
            // SAFETY: `ai` is live; `tlsextid` is a value.
            if unsafe { ASN1_INTEGER_set(ai, tlsextid) } == 0 {
                0
            } else {
                // SAFETY: `tlsf` is a live list; `ai` is a live integer this call owns.
                unsafe { OPENSSL_sk_push(tlsf, ai.cast::<c_void>()) }
            }
        };
        if pushed <= 0 {
            // SAFETY: `ai` is NULL or a live integer this call owns.
            unsafe { ASN1_INTEGER_free(ai) };
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_TLSF_125) };
            // SAFETY: `tlsf` is the list this call built.
            unsafe { OPENSSL_sk_pop_free(tlsf, Some(asn1_integer_free_thunk)) };
            return ptr::null_mut();
        }
        i += 1;
    }
    tlsf.cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_tls_feature` — `crypto/x509/v3_tlsf.c:31-40`.
pub static ossl_v3_tls_feature: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_tlsfeature,
    ext_flags: 0,
    it: Some(tls_feature_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: Some(i2v_TLS_FEATURE),
    v2i: Some(v2i_TLS_FEATURE),
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
