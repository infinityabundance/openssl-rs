//! `crypto/x509/v3_battcons.c` — the `OSSL_BASIC_ATTR_CONSTRAINTS` item and its row. Phase
//! 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_battcons.c` is 86 lines and transcribes whole:
//!
//! * `OSSL_BASIC_ATTR_CONSTRAINTS ::= SEQUENCE { authority BOOLEAN DEFAULT FALSE, pathlen INTEGER
//!   OPTIONAL }` (`:38-41`) lands, with `OSSL_BASIC_ATTR_CONSTRAINTS_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:43`; all five are
//!   declared at `x509v3.h:540`).
//! * `i2v_OSSL_BASIC_ATTR_CONSTRAINTS` (`:45-53`) and `v2i_OSSL_BASIC_ATTR_CONSTRAINTS` (`:55-86`)
//!   land.
//! * The row [`ossl_v3_battcons`] (`:27-36`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item group and the two callbacks are the drivable
//! surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_battcons.c` is not an entry in `gen_err_raise_sites.py`, so its two coordinates
//! are **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BOOLEAN_it, ASN1_INTEGER_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_INVALID_NAME;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_basic_att_constraints;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{
    conf_add_error_name_value, X509V3_add_value_bool, X509V3_add_value_int, X509V3_get_value_bool,
    X509V3_get_value_int,
};

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_battcons.c` raise coordinate, declared locally (see the module doc).
const fn v3_battcons_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_battcons.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_OSSL_BASIC_ATTR_CONSTRAINTS`'s allocation failure at `v3_battcons.c:65`.
const V3_BATTCONS_65: crate::runtime::err::err_sites::ErrSite =
    v3_battcons_site(65, c"v2i_OSSL_BASIC_ATTR_CONSTRAINTS", ERR_R_ASN1_LIB);
/// `v2i_OSSL_BASIC_ATTR_CONSTRAINTS`'s unknown name at `v3_battcons.c:77`.
const V3_BATTCONS_77: crate::runtime::err::err_sites::ErrSite = v3_battcons_site(
    77,
    c"v2i_OSSL_BASIC_ATTR_CONSTRAINTS",
    X509V3_R_INVALID_NAME,
);

/// `struct OSSL_BASIC_ATTR_CONSTRAINTS_st` — `include/openssl/x509v3.h`.
#[repr(C)]
pub struct OsslBasicAttrConstraints {
    /// `int authority` — the `ASN1_BOOLEAN`, `FALSE` by default so the encoder may omit it.
    pub authority: c_int,
    /// `ASN1_INTEGER *pathlen` — optional.
    pub pathlen: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OsslBasicAttrConstraints>() == 16);
    assert!(core::mem::offset_of!(OsslBasicAttrConstraints, authority) == 0);
    assert!(core::mem::offset_of!(OsslBasicAttrConstraints, pathlen) == 8);
};

/// `OSSL_BASIC_ATTR_CONSTRAINTS_seq_tt` — `ASN1_SEQUENCE(OSSL_BASIC_ATTR_CONSTRAINTS)`
/// (`crypto/x509/v3_battcons.c:38-41`): `authority` over `ASN1_FBOOLEAN`, `pathlen` over
/// `ASN1_INTEGER`, both `ASN1_OPT`.
static OSSL_BASIC_ATTR_CONSTRAINTS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"authority".as_ptr(),
        item: ASN1_BOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"pathlen".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `OSSL_BASIC_ATTR_CONSTRAINTS_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_BASIC_ATTR_CONSTRAINTS)`
/// at `crypto/x509/v3_battcons.c:41`.
static OSSL_BASIC_ATTR_CONSTRAINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_BASIC_ATTR_CONSTRAINTS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslBasicAttrConstraints>() as c_long,
    sname: c"OSSL_BASIC_ATTR_CONSTRAINTS".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_BASIC_ATTR_CONSTRAINTS_it(void)` — `include/openssl/x509v3.h:540`.
#[no_mangle]
pub extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_it() -> *const Asn1Item {
    &OSSL_BASIC_ATTR_CONSTRAINTS_ITEM
}

/// `OSSL_BASIC_ATTR_CONSTRAINTS *OSSL_BASIC_ATTR_CONSTRAINTS_new(void)` — `crypto/x509/v3_battcons.c:43`.
#[no_mangle]
pub extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_new() -> *mut OsslBasicAttrConstraints {
    // SAFETY: `OSSL_BASIC_ATTR_CONSTRAINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_BASIC_ATTR_CONSTRAINTS_it()).cast::<OsslBasicAttrConstraints>() }
}

/// `void OSSL_BASIC_ATTR_CONSTRAINTS_free(OSSL_BASIC_ATTR_CONSTRAINTS *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_BASIC_ATTR_CONSTRAINTS_free(a: *mut OsslBasicAttrConstraints) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_BASIC_ATTR_CONSTRAINTS_it()) }
}

/// `OSSL_BASIC_ATTR_CONSTRAINTS *d2i_OSSL_BASIC_ATTR_CONSTRAINTS(OSSL_BASIC_ATTR_CONSTRAINTS **a,
/// const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_BASIC_ATTR_CONSTRAINTS(
    a: *mut *mut OsslBasicAttrConstraints,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslBasicAttrConstraints {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_BASIC_ATTR_CONSTRAINTS_it())
            .cast::<OsslBasicAttrConstraints>()
    }
}

/// `int i2d_OSSL_BASIC_ATTR_CONSTRAINTS(const OSSL_BASIC_ATTR_CONSTRAINTS *a, unsigned char **out)`
/// — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_BASIC_ATTR_CONSTRAINTS(
    a: *const OsslBasicAttrConstraints,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_BASIC_ATTR_CONSTRAINTS_it()) }
}

/// `static STACK_OF(CONF_VALUE) *i2v_OSSL_BASIC_ATTR_CONSTRAINTS(X509V3_EXT_METHOD *method,
/// OSSL_BASIC_ATTR_CONSTRAINTS *battcons, STACK_OF(CONF_VALUE) *extlist)` —
/// `crypto/x509/v3_battcons.c:45-53`.
unsafe extern "C" fn i2v_OSSL_BASIC_ATTR_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    battcons: *mut c_void,
    extlist: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut extlist = extlist;
    let battcons = battcons.cast::<OsslBasicAttrConstraints>();
    // SAFETY: `battcons` is a live value per the caller's contract.
    unsafe {
        X509V3_add_value_bool(c"authority".as_ptr(), (*battcons).authority, &mut extlist);
        X509V3_add_value_int(c"pathlen".as_ptr(), (*battcons).pathlen, &mut extlist);
    }
    extlist
}

/// `static OSSL_BASIC_ATTR_CONSTRAINTS *v2i_OSSL_BASIC_ATTR_CONSTRAINTS(X509V3_EXT_METHOD *method,
/// X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_battcons.c:55-86`.
unsafe extern "C" fn v2i_OSSL_BASIC_ATTR_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    values: *mut OpenSslStack,
) -> *mut c_void {
    let battcons = OSSL_BASIC_ATTR_CONSTRAINTS_new();
    if battcons.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_BATTCONS_65) };
        return ptr::null_mut();
    }
    // SAFETY: `values` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(values) };
    let mut i = 0;
    while i < num {
        // SAFETY: `values` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract; each literal is static.
        let name = unsafe { (*val).name };
        // SAFETY: `name` is NUL-terminated; the literal is static.
        if unsafe { strcmp(name, c"authority".as_ptr()) } == 0 {
            // SAFETY: `battcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_bool(val, &raw mut (*battcons).authority) } == 0 {
                // SAFETY: `battcons` is a live value this call owns.
                unsafe { OSSL_BASIC_ATTR_CONSTRAINTS_free(battcons) };
                return ptr::null_mut();
            }
        // SAFETY: `name` is NUL-terminated; the literal is static.
        } else if unsafe { strcmp(name, c"pathlen".as_ptr()) } == 0 {
            // SAFETY: `battcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_int(val, &raw mut (*battcons).pathlen) } == 0 {
                // SAFETY: `battcons` is a live value this call owns.
                unsafe { OSSL_BASIC_ATTR_CONSTRAINTS_free(battcons) };
                return ptr::null_mut();
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_BATTCONS_77) };
            // SAFETY: `val` is live per the contract.
            unsafe { conf_add_error_name_value(val) };
            // SAFETY: `battcons` is a live value this call owns.
            unsafe { OSSL_BASIC_ATTR_CONSTRAINTS_free(battcons) };
            return ptr::null_mut();
        }
        i += 1;
    }
    battcons.cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_battcons` — `crypto/x509/v3_battcons.c:27-36`.
pub static ossl_v3_battcons: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_basic_att_constraints,
    ext_flags: 0,
    it: Some(OSSL_BASIC_ATTR_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: Some(i2v_OSSL_BASIC_ATTR_CONSTRAINTS),
    v2i: Some(v2i_OSSL_BASIC_ATTR_CONSTRAINTS),
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
