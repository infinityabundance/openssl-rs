//! `crypto/x509/v3_bcons.c` — the `BASIC_CONSTRAINTS` item. Phase 10.14.6, landed at function
//! granularity.
//!
//! `crypto/x509/v3_bcons.c` is 85 lines and now transcribes **whole**. The item group lands first
//! (it is what `ossl_x509v3_cache_extensions` needs), then this slice adds the two `static`
//! callbacks and the row:
//!
//! * `BASIC_CONSTRAINTS ::= SEQUENCE { ca BOOLEAN DEFAULT FALSE, pathlen INTEGER OPTIONAL }`
//!   (`:38-41`) lands, with `BASIC_CONSTRAINTS_it` and the `_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:43`). All five are public exports (`x509v3.h`).
//!   **`BASIC_CONSTRAINTS_free` is the seventh name `ossl_x509v3_cache_extensions` (`v3_purp.c`)
//!   was measured to need.**
//! * `i2v_BASIC_CONSTRAINTS` (`:45-54`) and `v2i_BASIC_CONSTRAINTS` (`:55-85`) land.
//! * `ossl_v3_bcons` (`:27-36`) lands as the row both callbacks feed.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456), so the array is the last thing to land, not the first. The row is internal data the
//! admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the item group and the two
//! callbacks are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_bcons.c` is not an entry in `gen_err_raise_sites.py`, so its two coordinates are
//! **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`.
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
use crate::runtime::obj::NID_basic_constraints;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{
    conf_add_error_name_value, X509V3_add_value_bool, X509V3_add_value_int, X509V3_get_value_bool,
    X509V3_get_value_int,
};

/// `struct BASIC_CONSTRAINTS_st` — `BASIC_CONSTRAINTS`, from `include/openssl/x509v3.h:127-130`.
///
/// The authority's `int ca` and `ASN1_INTEGER *pathlen`. The internal `X509` struct already
/// models a `BASIC_CONSTRAINTS` as an opaque pointer, so this is the one definition of the name.
#[repr(C)]
pub struct BasicConstraints {
    /// `int ca` — the `ASN1_BOOLEAN`, `FALSE` by default so the encoder may omit it.
    pub ca: c_int,
    /// `ASN1_INTEGER *pathlen` — optional.
    pub pathlen: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<BasicConstraints>() == 16);
    assert!(core::mem::offset_of!(BasicConstraints, ca) == 0);
    assert!(core::mem::offset_of!(BasicConstraints, pathlen) == 8);
};

/// `BASIC_CONSTRAINTS_seq_tt` — `ASN1_SEQUENCE(BASIC_CONSTRAINTS)`
/// (`crypto/x509/v3_bcons.c:38-41`): two `ASN1_OPT` rows, `ca` over `ASN1_FBOOLEAN` and `pathlen`
/// over `ASN1_INTEGER`.
static BASIC_CONSTRAINTS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"ca".as_ptr(),
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

/// `BASIC_CONSTRAINTS_it`'s descriptor — `ASN1_SEQUENCE_END(BASIC_CONSTRAINTS)` at
/// `crypto/x509/v3_bcons.c:41`.
static BASIC_CONSTRAINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: BASIC_CONSTRAINTS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<BasicConstraints>() as c_long,
    sname: c"BASIC_CONSTRAINTS".as_ptr(),
};

/// `const ASN1_ITEM *BASIC_CONSTRAINTS_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn BASIC_CONSTRAINTS_it() -> *const Asn1Item {
    &BASIC_CONSTRAINTS_ITEM
}

/// `BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void)` — `crypto/x509/v3_bcons.c:43`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn BASIC_CONSTRAINTS_new() -> *mut BasicConstraints {
    // SAFETY: `BASIC_CONSTRAINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(BASIC_CONSTRAINTS_it()).cast::<BasicConstraints>() }
}

/// `void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a)` — the same macro's free half.
///
/// The seventh name `ossl_x509v3_cache_extensions` needs.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn BASIC_CONSTRAINTS_free(a: *mut BasicConstraints) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), BASIC_CONSTRAINTS_it()) }
}

/// `BASIC_CONSTRAINTS *d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_BASIC_CONSTRAINTS(
    a: *mut *mut BasicConstraints,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut BasicConstraints {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, BASIC_CONSTRAINTS_it()).cast::<BasicConstraints>() }
}

/// `int i2d_BASIC_CONSTRAINTS(const BASIC_CONSTRAINTS *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_BASIC_CONSTRAINTS(
    a: *const BasicConstraints,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, BASIC_CONSTRAINTS_it()) }
}

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_bcons.c` raise coordinate, declared locally (see the module doc).
const fn v3_bcons_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_bcons.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_BASIC_CONSTRAINTS`'s allocation failure at `v3_bcons.c:64`.
const V3_BCONS_64: crate::runtime::err::err_sites::ErrSite =
    v3_bcons_site(64, c"v2i_BASIC_CONSTRAINTS", ERR_R_ASN1_LIB);
/// `v2i_BASIC_CONSTRAINTS`'s unknown name at `v3_bcons.c:76`.
const V3_BCONS_76: crate::runtime::err::err_sites::ErrSite =
    v3_bcons_site(76, c"v2i_BASIC_CONSTRAINTS", X509V3_R_INVALID_NAME);

/// `static STACK_OF(CONF_VALUE) *i2v_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method,
/// BASIC_CONSTRAINTS *bcons, STACK_OF(CONF_VALUE) *extlist)` — `crypto/x509/v3_bcons.c:45-54`.
unsafe extern "C" fn i2v_BASIC_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    bcons: *mut c_void,
    extlist: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut extlist = extlist;
    let bcons = bcons.cast::<BasicConstraints>();
    // SAFETY: `bcons` is a live `BASIC_CONSTRAINTS` per the caller's contract.
    unsafe {
        X509V3_add_value_bool(c"CA".as_ptr(), (*bcons).ca, &mut extlist);
        X509V3_add_value_int(c"pathlen".as_ptr(), (*bcons).pathlen, &mut extlist);
    }
    extlist
}

/// `static BASIC_CONSTRAINTS *v2i_BASIC_CONSTRAINTS(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_bcons.c:55-85`.
unsafe extern "C" fn v2i_BASIC_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    values: *mut OpenSslStack,
) -> *mut c_void {
    let bcons = BASIC_CONSTRAINTS_new();
    if bcons.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_BCONS_64) };
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
        if unsafe { strcmp(name, c"CA".as_ptr()) } == 0 {
            // SAFETY: `bcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_bool(val, &raw mut (*bcons).ca) } == 0 {
                // SAFETY: `bcons` is a live value this call owns.
                unsafe { BASIC_CONSTRAINTS_free(bcons) };
                return ptr::null_mut();
            }
        // SAFETY: `name` is NUL-terminated; the literal is static.
        } else if unsafe { strcmp(name, c"pathlen".as_ptr()) } == 0 {
            // SAFETY: `bcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_int(val, &raw mut (*bcons).pathlen) } == 0 {
                // SAFETY: `bcons` is a live value this call owns.
                unsafe { BASIC_CONSTRAINTS_free(bcons) };
                return ptr::null_mut();
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_BCONS_76) };
            // SAFETY: `val` is live per the contract.
            unsafe { conf_add_error_name_value(val) };
            // SAFETY: `bcons` is a live value this call owns.
            unsafe { BASIC_CONSTRAINTS_free(bcons) };
            return ptr::null_mut();
        }
        i += 1;
    }
    bcons.cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_bcons` — `crypto/x509/v3_bcons.c:27-36`.
pub static ossl_v3_bcons: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_basic_constraints,
    ext_flags: 0,
    it: Some(BASIC_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: Some(i2v_BASIC_CONSTRAINTS),
    v2i: Some(v2i_BASIC_CONSTRAINTS),
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
