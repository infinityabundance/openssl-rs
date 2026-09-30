//! `crypto/x509/v3_sda.c` — the `OSSL_ATTRIBUTES_SYNTAX` item and its two rows. Phase 10.14.8's
//! table layer, landed whole.
//!
//! `crypto/x509/v3_sda.c` is 88 lines and transcribes whole:
//!
//! * `OSSL_ATTRIBUTES_SYNTAX ::= SEQUENCE OF X509_ATTRIBUTE` (`:15-18`) lands, with
//!   `OSSL_ATTRIBUTES_SYNTAX_it` and the `_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:18`; all five are declared at `x509v3.h:1064-1065`, the
//!   value type being `STACK_OF(X509_ATTRIBUTE)`). The element item is `X509_ATTRIBUTE_it`, landed
//!   in `x_attrib.rs`.
//! * `i2r_ATTRIBUTES_SYNTAX` (`:20-68`) lands, over `X509_ATTRIBUTE_get0_object`/`_count`/
//!   `_get0_type` (`x509_att.rs`) and `ossl_print_attribute_value` (`x_attrib.rs`, the D465 hub).
//! * The **two rows** land: [`ossl_v3_subj_dir_attrs`] (`:70-78`) and
//!   [`ossl_v3_associated_info`] (`:80-88`), both `X509V3_EXT_MULTILINE`, sharing the same item and
//!   printer.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes two of the 63. The rows are internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item group and the printer are the drivable
//! surface.
//!
//! ## No raise
//!
//! The unit raises nothing, so `crypto/x509/v3_sda.c` is deliberately not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{
    NID_associated_information, NID_subject_directory_attributes, NID_undef, OBJ_nid2ln,
    OBJ_obj2nid,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::x509_att::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type,
};
use crate::x509::x_attrib::{ossl_print_attribute_value, X509_ATTRIBUTE_it};

/// `OSSL_ATTRIBUTES_SYNTAX_tmpl_tt` — `ASN1_ITEM_TEMPLATE(OSSL_ATTRIBUTES_SYNTAX)`'s single
/// template (`crypto/x509/v3_sda.c:15`): `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
/// Attributes, X509_ATTRIBUTE)`.
static OSSL_ATTRIBUTES_SYNTAX_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"Attributes".as_ptr(),
    item: X509_ATTRIBUTE_it as *mut c_void,
};

/// `OSSL_ATTRIBUTES_SYNTAX_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(OSSL_ATTRIBUTES_SYNTAX)` at
/// `crypto/x509/v3_sda.c:16`.
static OSSL_ATTRIBUTES_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_ATTRIBUTES_SYNTAX_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_ATTRIBUTES_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTES_SYNTAX_it(void)` — `include/openssl/x509v3.h:1065`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTES_SYNTAX_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTES_SYNTAX_ITEM
}

/// `OSSL_ATTRIBUTES_SYNTAX *OSSL_ATTRIBUTES_SYNTAX_new(void)` — `crypto/x509/v3_sda.c:18`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTES_SYNTAX_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_ATTRIBUTES_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTES_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_ATTRIBUTES_SYNTAX_free(OSSL_ATTRIBUTES_SYNTAX *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTES_SYNTAX_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTES_SYNTAX_it()) }
}

/// `OSSL_ATTRIBUTES_SYNTAX *d2i_OSSL_ATTRIBUTES_SYNTAX(OSSL_ATTRIBUTES_SYNTAX **a,
/// const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTES_SYNTAX(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTES_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `int i2d_OSSL_ATTRIBUTES_SYNTAX(const OSSL_ATTRIBUTES_SYNTAX *a, unsigned char **out)` — the
/// same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTES_SYNTAX(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTES_SYNTAX_it()) }
}

/// `static int i2r_ATTRIBUTES_SYNTAX(X509V3_EXT_METHOD *method, OSSL_ATTRIBUTES_SYNTAX *attrlst,
/// BIO *out, int indent)` — `crypto/x509/v3_sda.c:20-68`.
///
/// A NULL list prints `<No Attributes>`, an empty one `<Empty Attributes>`; otherwise one block per
/// attribute, its name from `OBJ_nid2ln` when the object resolves and from `i2a_ASN1_OBJECT` when it
/// does not, then one `ossl_print_attribute_value` line per value (or `<No Values>`).
unsafe extern "C" fn i2r_ATTRIBUTES_SYNTAX(
    _method: *const X509V3ExtMethod,
    attrlst: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    if attrlst.is_null() {
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe { BIO_printf(out, c"<No Attributes>\n".as_ptr()) } <= 0 {
            return 0;
        }
        return 1;
    }
    let attrlst = attrlst.cast::<OpenSslStack>();
    // SAFETY: `attrlst` is a live `STACK_OF(X509_ATTRIBUTE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(attrlst) };
    if num == 0 {
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe { BIO_printf(out, c"<Empty Attributes>\n".as_ptr()) } <= 0 {
            return 0;
        }
        return 1;
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `attrlst` is live and `i` is in bounds.
        let attr =
            unsafe { OPENSSL_sk_value(attrlst, i) }.cast::<crate::x509::x_attrib::X509Attribute>();
        // SAFETY: `attr` is a live attribute.
        let attr_obj = unsafe { X509_ATTRIBUTE_get0_object(attr) };
        // SAFETY: `attr_obj` is NULL or a live object.
        let attr_nid = unsafe { OBJ_obj2nid(attr_obj) };
        if indent != 0 {
            // SAFETY: `out` is a live BIO; the format and its arguments are constants.
            if unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
                return 0;
            }
        }
        if attr_nid == NID_undef {
            // SAFETY: `out` is live; `attr_obj` is NULL or live.
            if unsafe { i2a_ASN1_OBJECT(out, attr_obj) } <= 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            if unsafe { BIO_puts(out, c":\n".as_ptr()) } <= 0 {
                return 0;
            }
        } else {
            // SAFETY: `out` is live; `OBJ_nid2ln` answers a static string for a known nid.
            if unsafe { BIO_printf(out, c"%s:\n".as_ptr(), OBJ_nid2ln(attr_nid)) } <= 0 {
                return 0;
            }
        }
        // SAFETY: `attr` is live.
        let count = unsafe { X509_ATTRIBUTE_count(attr) };
        if count != 0 {
            let mut j = 0;
            while j < count {
                // SAFETY: `attr` is live and `j` is in bounds.
                let av = unsafe { X509_ATTRIBUTE_get0_type(attr, j) };
                // SAFETY: `out` is live; `av` is a live value borrowed from `attr`.
                if unsafe { ossl_print_attribute_value(out, attr_nid, av, indent + 4) } <= 0 {
                    return 0;
                }
                // SAFETY: `out` is live; the literal is static.
                if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                    return 0;
                }
                j += 1;
            }
        } else {
            // SAFETY: `out` is a live BIO; the format and its arguments are constants.
            if unsafe { BIO_printf(out, c"%*s<No Values>\n".as_ptr(), indent + 4, c"".as_ptr()) }
                <= 0
            {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// One `OSSL_ATTRIBUTES_SYNTAX`-backed row: the item, `i2r_ATTRIBUTES_SYNTAX`, the
/// `X509V3_EXT_MULTILINE` flag, every other slot zero.
const fn attributes_syntax_row(nid: c_int) -> X509V3ExtMethod {
    X509V3ExtMethod {
        ext_nid: nid,
        ext_flags: X509V3_EXT_MULTILINE,
        it: Some(OSSL_ATTRIBUTES_SYNTAX_it),
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: None,
        s2i: None,
        i2v: None,
        v2i: None,
        i2r: Some(i2r_ATTRIBUTES_SYNTAX),
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// `const X509V3_EXT_METHOD ossl_v3_subj_dir_attrs` — `crypto/x509/v3_sda.c:70-78`.
pub static ossl_v3_subj_dir_attrs: X509V3ExtMethod =
    attributes_syntax_row(NID_subject_directory_attributes);

/// `const X509V3_EXT_METHOD ossl_v3_associated_info` — `crypto/x509/v3_sda.c:80-88`.
pub static ossl_v3_associated_info: X509V3ExtMethod =
    attributes_syntax_row(NID_associated_information);
