//! `crypto/x509/v3_extku.c` — the `EXTENDED_KEY_USAGE` item and its four rows. Phase 10.14.6's
//! table layer, landed whole.
//!
//! `crypto/x509/v3_extku.c` is 125 lines and transcribes whole:
//!
//! * `EXTENDED_KEY_USAGE ::= SEQUENCE OF ASN1_OBJECT` (`:71-72`) lands, with `EXTENDED_KEY_USAGE_it`
//!   and the `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:74`). All five
//!   are public exports (`x509v3.h:606`), so the differential plane can build one, encode it and
//!   decode the bytes back.
//! * `i2v_EXTENDED_KEY_USAGE` (`:76-90`) and `v2i_EXTENDED_KEY_USAGE` (`:92-125`) land.
//! * The **four rows** land: [`ossl_v3_ext_ku`] (`:24-33`, `NID_ext_key_usage`),
//!   [`ossl_v3_ocsp_accresp`] (`:36-45`, `NID_id_pkix_OCSP_acceptableResponses`),
//!   [`ossl_v3_acc_cert_policies`] (`:48-57`) and [`ossl_v3_acc_priv_policies`] (`:60-69`) -- the
//!   last three reusing the same `SEQUENCE OF OBJECT` item and callbacks, which is why they share
//!   this unit rather than the OCSP one.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456), so the array is withheld until all 63 tables exist. This unit contributes four of the
//! 63. The rows are internal data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`);
//! the item group and the two callbacks are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_extku.c` is not an entry in `gen_err_raise_sites.py` (the generator's covered set
//! is the closed-stratum file list), so its two coordinates are **declared locally** with the
//! `err_sites::ErrSite` shape, as `v3_bitst.rs` does. Their reason values are read from the
//! authority's own headers (`err.h`, `x509v3err.h`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OBJECT_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::text::i2t_ASN1_OBJECT;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_INVALID_OBJECT_IDENTIFIER;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::obj::{
    Asn1Object, NID_acceptable_cert_policies, NID_acceptable_privilege_policies, NID_ext_key_usage,
    NID_id_pkix_OCSP_acceptableResponses, OBJ_txt2obj,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3ExtV2i};
use crate::x509::v3_utl::X509V3_add_value;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;

/// One `v3_extku.c` raise coordinate, declared locally (see the module doc).
const fn v3_extku_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_extku.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_EXTENDED_KEY_USAGE`'s allocation failure at `v3_extku.c:105`.
const V3_EXTKU_105: crate::runtime::err::err_sites::ErrSite =
    v3_extku_site(105, c"v2i_EXTENDED_KEY_USAGE", ERR_R_CRYPTO_LIB);
/// `v2i_EXTENDED_KEY_USAGE`'s failed `OBJ_txt2obj` at `v3_extku.c:118`.
const V3_EXTKU_118: crate::runtime::err::err_sites::ErrSite = v3_extku_site(
    118,
    c"v2i_EXTENDED_KEY_USAGE",
    X509V3_R_INVALID_OBJECT_IDENTIFIER,
);

/// `void (*)(void *)` thunk for `sk_ASN1_OBJECT_pop_free(..., ASN1_OBJECT_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `ASN1_OBJECT` (the stack contract).
unsafe extern "C" fn asn1_object_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_OBJECT` pointers per the contract.
    unsafe { ASN1_OBJECT_free(p.cast::<Asn1Object>()) };
}

/// `EXTENDED_KEY_USAGE_tmpl_tt` — `ASN1_ITEM_TEMPLATE(EXTENDED_KEY_USAGE)`'s single template
/// (`crypto/x509/v3_extku.c:71`): `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, EXTENDED_KEY_USAGE,
/// ASN1_OBJECT)`. The value is a `STACK_OF(ASN1_OBJECT)`.
static EXTENDED_KEY_USAGE_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"EXTENDED_KEY_USAGE".as_ptr(),
    item: ASN1_OBJECT_it as *mut c_void,
};

/// `EXTENDED_KEY_USAGE_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(EXTENDED_KEY_USAGE)` at
/// `crypto/x509/v3_extku.c:72`.
static EXTENDED_KEY_USAGE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &EXTENDED_KEY_USAGE_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"EXTENDED_KEY_USAGE".as_ptr(),
};

/// `const ASN1_ITEM *EXTENDED_KEY_USAGE_it(void)` — `include/openssl/x509v3.h:606`, from
/// `DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)`.
#[no_mangle]
pub extern "C" fn EXTENDED_KEY_USAGE_it() -> *const Asn1Item {
    &EXTENDED_KEY_USAGE_ITEM
}

/// `EXTENDED_KEY_USAGE *EXTENDED_KEY_USAGE_new(void)` — `crypto/x509/v3_extku.c:74`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)`.
#[no_mangle]
pub extern "C" fn EXTENDED_KEY_USAGE_new() -> *mut OpenSslStack {
    // SAFETY: `EXTENDED_KEY_USAGE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(EXTENDED_KEY_USAGE_it()).cast::<OpenSslStack>() }
}

/// `void EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn EXTENDED_KEY_USAGE_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), EXTENDED_KEY_USAGE_it()) }
}

/// `EXTENDED_KEY_USAGE *d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_EXTENDED_KEY_USAGE(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, EXTENDED_KEY_USAGE_it()).cast::<OpenSslStack>() }
}

/// `int i2d_EXTENDED_KEY_USAGE(const EXTENDED_KEY_USAGE *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_EXTENDED_KEY_USAGE(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, EXTENDED_KEY_USAGE_it()) }
}

/// `static STACK_OF(CONF_VALUE) *i2v_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method, void *a,
/// STACK_OF(CONF_VALUE) *ext_list)` — `crypto/x509/v3_extku.c:76-90`.
///
/// One `CONF_VALUE` per object, name NULL, value the object's textual form.
unsafe extern "C" fn i2v_EXTENDED_KEY_USAGE(
    _method: *const X509V3ExtMethod,
    a: *mut c_void,
    ext_list: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut ext_list = ext_list;
    let eku = a.cast::<OpenSslStack>();
    // SAFETY: `eku` is a live `STACK_OF(ASN1_OBJECT)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(eku) };
    let mut i = 0;
    while i < num {
        // SAFETY: `eku` is live and `i` is in bounds.
        let obj = unsafe { OPENSSL_sk_value(eku, i) }.cast::<Asn1Object>();
        let mut obj_tmp = [0 as c_char; 80];
        // SAFETY: `obj_tmp` is 80 writable bytes; `obj` is a live object.
        unsafe { i2t_ASN1_OBJECT(obj_tmp.as_mut_ptr(), 80, obj) };
        // SAFETY: `obj_tmp` is NUL-terminated; `ext_list` is this call's sink.
        unsafe { X509V3_add_value(ptr::null(), obj_tmp.as_ptr(), &mut ext_list) };
        i += 1;
    }
    ext_list
}

/// `static void *v2i_EXTENDED_KEY_USAGE(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_extku.c:92-125`.
///
/// Reserves a `STACK_OF(ASN1_OBJECT)`, then one `OBJ_txt2obj` per entry; a bad OID is
/// `X509V3_R_INVALID_OBJECT_IDENTIFIER` with the offending text as data.
unsafe extern "C" fn v2i_EXTENDED_KEY_USAGE(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let extku = OPENSSL_sk_new_reserve(None, num);
    if extku.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_EXTKU_105) };
        // SAFETY: `extku` is NULL, which the authority's `sk_free` accepts.
        unsafe { OPENSSL_sk_free(extku) };
        return ptr::null_mut();
    }
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
        // SAFETY: `extval` is NUL-terminated; `no_name` is 0.
        let objtmp = unsafe { OBJ_txt2obj(extval, 0) };
        if objtmp.is_null() {
            // SAFETY: `extku` is the list this call built; `asn1_object_free_thunk` its destructor.
            unsafe { OPENSSL_sk_pop_free(extku, Some(asn1_object_free_thunk)) };
            // SAFETY: `extval` is NUL-terminated; the site is a compiled-in constant.
            unsafe { raise_site_data(&V3_EXTKU_118, extval) };
            return ptr::null_mut();
        }
        // SAFETY: `extku` was reserved for `num`, so the push cannot fail.
        unsafe { OPENSSL_sk_push(extku, objtmp.cast::<c_void>()) };
        i += 1;
    }
    extku.cast::<c_void>()
}

/// The `v2i` slot's cast of a callback taking the non-`const` method the authority declares.
const fn as_v2i(
    f: unsafe extern "C" fn(*const X509V3ExtMethod, *mut c_void, *mut OpenSslStack) -> *mut c_void,
) -> X509V3ExtV2i {
    Some(f)
}

/// One `EXTENDED_KEY_USAGE`-backed row: the item, `i2v_EXTENDED_KEY_USAGE` and
/// `v2i_EXTENDED_KEY_USAGE`, every other slot zero.
const fn ext_key_usage_row(nid: c_int) -> X509V3ExtMethod {
    X509V3ExtMethod {
        ext_nid: nid,
        ext_flags: 0,
        it: Some(EXTENDED_KEY_USAGE_it),
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: None,
        s2i: None,
        i2v: Some(i2v_EXTENDED_KEY_USAGE),
        v2i: as_v2i(v2i_EXTENDED_KEY_USAGE),
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// `const X509V3_EXT_METHOD ossl_v3_ext_ku` — `crypto/x509/v3_extku.c:24-33`.
pub static ossl_v3_ext_ku: X509V3ExtMethod = ext_key_usage_row(NID_ext_key_usage);

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_accresp` — `crypto/x509/v3_extku.c:36-45`.
///
/// The OCSP acceptable-responses extension, which is also a `SEQUENCE OF OBJECT`; it is defined
/// here by the authority, not in `v3_ocsp.c`.
pub static ossl_v3_ocsp_accresp: X509V3ExtMethod =
    ext_key_usage_row(NID_id_pkix_OCSP_acceptableResponses);

/// `const X509V3_EXT_METHOD ossl_v3_acc_cert_policies` — `crypto/x509/v3_extku.c:48-57`.
pub static ossl_v3_acc_cert_policies: X509V3ExtMethod =
    ext_key_usage_row(NID_acceptable_cert_policies);

/// `const X509V3_EXT_METHOD ossl_v3_acc_priv_policies` — `crypto/x509/v3_extku.c:60-69`.
pub static ossl_v3_acc_priv_policies: X509V3ExtMethod =
    ext_key_usage_row(NID_acceptable_privilege_policies);
