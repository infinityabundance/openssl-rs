//! `crypto/x509/v3_aaa.c` — the `OSSL_ALLOWED_ATTRIBUTES_SYNTAX` item and its row. Phase 10.14's
//! table layer, landed whole.
//!
//! `crypto/x509/v3_aaa.c` is 128 lines and transcribes whole:
//!
//! * `OSSL_ALLOWED_ATTRIBUTES_CHOICE ::= CHOICE { attributeType [0] ASN1_OBJECT, attributeTypeandValues
//!   [1] X509_ATTRIBUTE }` (`:16-21`) lands, with the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:34`; all five are declared at `x509v3.h:1934`).
//! * `OSSL_ALLOWED_ATTRIBUTES_ITEM ::= SEQUENCE { attributes [0] SET OF OSSL_ALLOWED_ATTRIBUTES_CHOICE,
//!   holderDomain [1] EXPLICIT GENERAL_NAME }` (`:23-28`) lands, with its own five-name group
//!   (`:35`, declared at `x509v3.h:1935`). The `holderDomain` row is explicit because it contains a
//!   choice, as the authority's comment says (`:26`).
//! * `OSSL_ALLOWED_ATTRIBUTES_SYNTAX ::= SET OF OSSL_ALLOWED_ATTRIBUTES_ITEM` (`:30-32`) lands, with
//!   its five-name group (`:36`, declared at `x509v3.h:1936`); the value type is
//!   `STACK_OF(OSSL_ALLOWED_ATTRIBUTES_ITEM)` (`x509v3.h:1932`).
//! * The three `static` printers land: `i2r_ALLOWED_ATTRIBUTES_CHOICE` (`:38-76`),
//!   `i2r_ALLOWED_ATTRIBUTES_ITEM` (`:78-99`) and `i2r_ALLOWED_ATTRIBUTES_SYNTAX` (`:101-116`), the
//!   last over `GENERAL_NAME_print` (`v3_san.rs`) and `ossl_print_attribute_value` (`x_attrib.rs`,
//!   the D465 hub).
//! * The row [`ossl_v3_allowed_attribute_assignments`] (`:118-128`) lands, `NID_allowed_attribute_assignments`
//!   (`obj_mac.h:2880`), `ext_flags` 0, `i2r` set.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the three item groups and the printer are the drivable
//! surface.
//!
//! ## No raise
//!
//! The unit raises nothing, so `crypto/x509/v3_aaa.c` is deliberately not an entry in
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
use crate::asn1::items::ASN1_OBJECT_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_allowed_attribute_assignments, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::x509_att::{
    X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type,
};
use crate::x509::x_attrib::{ossl_print_attribute_value, X509Attribute, X509_ATTRIBUTE_it};

/// `#define OSSL_AAA_ATTRIBUTE_TYPE 0` — `include/openssl/x509v3.h:1916`.
const OSSL_AAA_ATTRIBUTE_TYPE: c_int = 0;
/// `#define OSSL_AAA_ATTRIBUTE_VALUES 1` — `include/openssl/x509v3.h:1917`.
const OSSL_AAA_ATTRIBUTE_VALUES: c_int = 1;

/// `struct ALLOWED_ATTRIBUTES_CHOICE_st` — `OSSL_ALLOWED_ATTRIBUTES_CHOICE`, from
/// `include/openssl/x509v3.h:1919-1925`. The `choice` union is modelled as one pointer because
/// both arms (`attributeType`/`attributeTypeandValues`) are the same width; the arm is chosen by the
/// CHOICE selector `type`.
#[repr(C)]
pub struct OsslAllowedAttributesChoice {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ASN1_OBJECT *attributeType; X509_ATTRIBUTE *attributeTypeandValues; } choice`.
    pub choice: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAllowedAttributesChoice>() == 16);
    assert!(core::mem::offset_of!(OsslAllowedAttributesChoice, type_) == 0);
    assert!(core::mem::offset_of!(OsslAllowedAttributesChoice, choice) == 8);
};

/// `struct ALLOWED_ATTRIBUTES_ITEM_st` — `OSSL_ALLOWED_ATTRIBUTES_ITEM`, from
/// `include/openssl/x509v3.h:1927-1930`.
#[repr(C)]
pub struct OsslAllowedAttributesItem {
    /// `STACK_OF(OSSL_ALLOWED_ATTRIBUTES_CHOICE) *attributes` — `[0]` implicit, a `SET OF`.
    pub attributes: *mut OpenSslStack,
    /// `GENERAL_NAME *holderDomain` — `[1]` explicit, because it contains a choice.
    pub holderDomain: *mut GeneralName,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAllowedAttributesItem>() == 16);
    assert!(core::mem::offset_of!(OsslAllowedAttributesItem, attributes) == 0);
    assert!(core::mem::offset_of!(OsslAllowedAttributesItem, holderDomain) == 8);
};

// ---------------------------------------------------------------------------------------------
// The three item groups — `ASN1_CHOICE`/`ASN1_SEQUENCE`/`ASN1_ITEM_TEMPLATE` at `v3_aaa.c:16-32`.
// ---------------------------------------------------------------------------------------------

/// `OSSL_ALLOWED_ATTRIBUTES_CHOICE_ch_tt` — `ASN1_CHOICE(OSSL_ALLOWED_ATTRIBUTES_CHOICE)`
/// (`crypto/x509/v3_aaa.c:16-21`): two `ASN1_IMP` rows at union offset 8.
static OSSL_ALLOWED_ATTRIBUTES_CHOICE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: OSSL_AAA_ATTRIBUTE_TYPE as c_long,
        offset: 8,
        field_name: c"choice.attributeType".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: OSSL_AAA_ATTRIBUTE_VALUES as c_long,
        offset: 8,
        field_name: c"choice.attributeTypeandValues".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
];

/// `OSSL_ALLOWED_ATTRIBUTES_CHOICE_it`'s descriptor — `ASN1_CHOICE_END(OSSL_ALLOWED_ATTRIBUTES_CHOICE)`
/// at `crypto/x509/v3_aaa.c:21`. `utype` is the selector offset (0).
static OSSL_ALLOWED_ATTRIBUTES_CHOICE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: OSSL_ALLOWED_ATTRIBUTES_CHOICE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAllowedAttributesChoice>() as c_long,
    sname: c"OSSL_ALLOWED_ATTRIBUTES_CHOICE".as_ptr(),
};

/// `OSSL_ALLOWED_ATTRIBUTES_ITEM_seq_tt` — `ASN1_SEQUENCE(OSSL_ALLOWED_ATTRIBUTES_ITEM)`
/// (`crypto/x509/v3_aaa.c:23-28`): an `ASN1_IMP_SET_OF` attributes row and an `ASN1_EXP`
/// `holderDomain` row.
static OSSL_ALLOWED_ATTRIBUTES_ITEM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 0,
        field_name: c"attributes".as_ptr(),
        item: OSSL_ALLOWED_ATTRIBUTES_CHOICE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"holderDomain".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
];

/// `OSSL_ALLOWED_ATTRIBUTES_ITEM_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ALLOWED_ATTRIBUTES_ITEM)`
/// at `crypto/x509/v3_aaa.c:28`.
static OSSL_ALLOWED_ATTRIBUTES_ITEM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ALLOWED_ATTRIBUTES_ITEM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAllowedAttributesItem>() as c_long,
    sname: c"OSSL_ALLOWED_ATTRIBUTES_ITEM".as_ptr(),
};

/// `OSSL_ALLOWED_ATTRIBUTES_SYNTAX_item_tt` — `ASN1_ITEM_TEMPLATE(OSSL_ALLOWED_ATTRIBUTES_SYNTAX)`'s
/// single template (`crypto/x509/v3_aaa.c:30`): `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0,
/// OSSL_ALLOWED_ATTRIBUTES_SYNTAX, OSSL_ALLOWED_ATTRIBUTES_ITEM)`.
static OSSL_ALLOWED_ATTRIBUTES_SYNTAX_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SET_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_ALLOWED_ATTRIBUTES_SYNTAX".as_ptr(),
    item: OSSL_ALLOWED_ATTRIBUTES_ITEM_it as *mut c_void,
};

/// `OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it`'s descriptor —
/// `ASN1_ITEM_TEMPLATE_END(OSSL_ALLOWED_ATTRIBUTES_SYNTAX)` at `crypto/x509/v3_aaa.c:32`.
static OSSL_ALLOWED_ATTRIBUTES_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_ALLOWED_ATTRIBUTES_SYNTAX_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_ALLOWED_ATTRIBUTES_SYNTAX".as_ptr(),
};

// NOTE: the three groups below are written out one by one rather than produced by a `macro_rules!`
// group, because a macro that fills the *type* position (`X_new`/`d2i_X`/`i2d_X`) is refused by
// `prototype_court.py` as an unreadable declaration (D456).

/// `const ASN1_ITEM *OSSL_ALLOWED_ATTRIBUTES_CHOICE_it(void)` — `include/openssl/x509v3.h:1934`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_ALLOWED_ATTRIBUTES_CHOICE)`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_it() -> *const Asn1Item {
    &OSSL_ALLOWED_ATTRIBUTES_CHOICE_ITEM
}

/// `OSSL_ALLOWED_ATTRIBUTES_CHOICE *OSSL_ALLOWED_ATTRIBUTES_CHOICE_new(void)` —
/// `crypto/x509/v3_aaa.c:34`, from `IMPLEMENT_ASN1_FUNCTIONS`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_new() -> *mut OsslAllowedAttributesChoice {
    // SAFETY: `OSSL_ALLOWED_ATTRIBUTES_CHOICE_it()` answers a static item the crate owns.
    unsafe {
        ASN1_item_new(OSSL_ALLOWED_ATTRIBUTES_CHOICE_it()).cast::<OsslAllowedAttributesChoice>()
    }
}

/// `void OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(OSSL_ALLOWED_ATTRIBUTES_CHOICE *a)` — the same macro's
/// free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_CHOICE_free(a: *mut OsslAllowedAttributesChoice) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ALLOWED_ATTRIBUTES_CHOICE_it()) }
}

/// `OSSL_ALLOWED_ATTRIBUTES_CHOICE *d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(OSSL_ALLOWED_ATTRIBUTES_CHOICE
/// **a, const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_CHOICE(
    a: *mut *mut OsslAllowedAttributesChoice,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAllowedAttributesChoice {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ALLOWED_ATTRIBUTES_CHOICE_it())
            .cast::<OsslAllowedAttributesChoice>()
    }
}

/// `int i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(const OSSL_ALLOWED_ATTRIBUTES_CHOICE *a, unsigned char
/// **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_CHOICE(
    a: *const OsslAllowedAttributesChoice,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ALLOWED_ATTRIBUTES_CHOICE_it()) }
}

/// `const ASN1_ITEM *OSSL_ALLOWED_ATTRIBUTES_ITEM_it(void)` — `include/openssl/x509v3.h:1935`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_it() -> *const Asn1Item {
    &OSSL_ALLOWED_ATTRIBUTES_ITEM_ITEM
}

/// `OSSL_ALLOWED_ATTRIBUTES_ITEM *OSSL_ALLOWED_ATTRIBUTES_ITEM_new(void)` — `crypto/x509/v3_aaa.c:35`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_new() -> *mut OsslAllowedAttributesItem {
    // SAFETY: `OSSL_ALLOWED_ATTRIBUTES_ITEM_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ALLOWED_ATTRIBUTES_ITEM_it()).cast::<OsslAllowedAttributesItem>() }
}

/// `void OSSL_ALLOWED_ATTRIBUTES_ITEM_free(OSSL_ALLOWED_ATTRIBUTES_ITEM *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_ITEM_free(a: *mut OsslAllowedAttributesItem) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ALLOWED_ATTRIBUTES_ITEM_it()) }
}

/// `OSSL_ALLOWED_ATTRIBUTES_ITEM *d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(OSSL_ALLOWED_ATTRIBUTES_ITEM **a,
/// const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_ITEM(
    a: *mut *mut OsslAllowedAttributesItem,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAllowedAttributesItem {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ALLOWED_ATTRIBUTES_ITEM_it())
            .cast::<OsslAllowedAttributesItem>()
    }
}

/// `int i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(const OSSL_ALLOWED_ATTRIBUTES_ITEM *a, unsigned char **out)`
/// — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_ITEM(
    a: *const OsslAllowedAttributesItem,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ALLOWED_ATTRIBUTES_ITEM_it()) }
}

/// `const ASN1_ITEM *OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it(void)` — `include/openssl/x509v3.h:1936`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it() -> *const Asn1Item {
    &OSSL_ALLOWED_ATTRIBUTES_SYNTAX_ITEM
}

/// `OSSL_ALLOWED_ATTRIBUTES_SYNTAX *OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new(void)` — `crypto/x509/v3_aaa.c:36`.
#[no_mangle]
pub extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(OSSL_ALLOWED_ATTRIBUTES_SYNTAX *a)` — the same macro's
/// free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ALLOWED_ATTRIBUTES_SYNTAX_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it()) }
}

/// `OSSL_ALLOWED_ATTRIBUTES_SYNTAX *d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(OSSL_ALLOWED_ATTRIBUTES_SYNTAX
/// **a, const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it())
            .cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(const OSSL_ALLOWED_ATTRIBUTES_SYNTAX *a, unsigned char
/// **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ALLOWED_ATTRIBUTES_SYNTAX(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it()) }
}

/// `static int i2r_ALLOWED_ATTRIBUTES_CHOICE(X509V3_EXT_METHOD *method,
/// OSSL_ALLOWED_ATTRIBUTES_CHOICE *a, BIO *out, int indent)` — `crypto/x509/v3_aaa.c:38-76`.
///
/// The `OSSL_AAA_ATTRIBUTE_TYPE` arm prints the bare object; the `OSSL_AAA_ATTRIBUTE_VALUES` arm
/// prints the object and one `ossl_print_attribute_value` line per value; any other selector is
/// refused `0`.
unsafe extern "C" fn i2r_ALLOWED_ATTRIBUTES_CHOICE(
    _method: *const X509V3ExtMethod,
    a: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let a = a.cast::<OsslAllowedAttributesChoice>();
    // SAFETY: `a` is a live `OSSL_ALLOWED_ATTRIBUTES_CHOICE` per the caller's contract.
    let sel = unsafe { (*a).type_ };
    // SAFETY: `a` is live; the union is one pointer, selected by `sel`.
    let choice = unsafe { (*a).choice };
    match sel {
        OSSL_AAA_ATTRIBUTE_TYPE => {
            // SAFETY: `out` is a live BIO; the format and its argument are constants.
            if unsafe { BIO_printf(out, c"%*sAttribute Type: ".as_ptr(), indent, c"".as_ptr()) }
                <= 0
            {
                return 0;
            }
            // SAFETY: `out` is live; `choice` is the arm's live object.
            if unsafe { i2a_ASN1_OBJECT(out, choice.cast::<Asn1Object>()) } <= 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            return (unsafe { BIO_puts(out, c"\n".as_ptr()) } > 0) as c_int;
        }
        OSSL_AAA_ATTRIBUTE_VALUES => {
            let attr = choice.cast::<X509Attribute>();
            // SAFETY: `attr` is the arm's live attribute.
            let attr_obj = unsafe { X509_ATTRIBUTE_get0_object(attr) };
            // SAFETY: `attr_obj` is NULL or a live object.
            let attr_nid = unsafe { OBJ_obj2nid(attr_obj) };
            // SAFETY: `out` is live; the format and its argument are constants.
            if unsafe { BIO_printf(out, c"%*sAttribute Values: ".as_ptr(), indent, c"".as_ptr()) }
                <= 0
            {
                return 0;
            }
            // SAFETY: `out` is live; `attr_obj` is NULL or live.
            if unsafe { i2a_ASN1_OBJECT(out, attr_obj) } <= 0 {
                return 0;
            }
            // SAFETY: `out` is live; the literal is static.
            if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: `attr` is live.
            let count = unsafe { X509_ATTRIBUTE_count(attr) };
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
        }
        _ => return 0,
    }
    1
}

/// `static int i2r_ALLOWED_ATTRIBUTES_ITEM(X509V3_EXT_METHOD *method, OSSL_ALLOWED_ATTRIBUTES_ITEM
/// *aai, BIO *out, int indent)` — `crypto/x509/v3_aaa.c:78-99`.
unsafe extern "C" fn i2r_ALLOWED_ATTRIBUTES_ITEM(
    method: *const X509V3ExtMethod,
    aai: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let aai = aai.cast::<OsslAllowedAttributesItem>();
    // SAFETY: `aai` is a live `OSSL_ALLOWED_ATTRIBUTES_ITEM` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num((*aai).attributes) };
    let mut i = 0;
    while i < num {
        // SAFETY: `out` is live; the format and its argument are constants.
        if unsafe {
            BIO_printf(
                out,
                c"%*sAllowed Attribute Type or Values:\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `aai->attributes` is live and `i` is in bounds.
        let a = unsafe { OPENSSL_sk_value((*aai).attributes, i) };
        // SAFETY: `a` is a live choice per the stack contract.
        if unsafe { i2r_ALLOWED_ATTRIBUTES_CHOICE(method, a, out, indent + 4) } <= 0 {
            return 0;
        }
        i += 1;
    }
    // SAFETY: `out` is live; the format and its argument are constants.
    if unsafe { BIO_printf(out, c"%*sHolder Domain: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; `aai->holderDomain` is its live name.
    if unsafe { GENERAL_NAME_print(out, (*aai).holderDomain) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    1
}

/// `static int i2r_ALLOWED_ATTRIBUTES_SYNTAX(X509V3_EXT_METHOD *method,
/// OSSL_ALLOWED_ATTRIBUTES_SYNTAX *aaa, BIO *out, int indent)` — `crypto/x509/v3_aaa.c:101-116`.
unsafe extern "C" fn i2r_ALLOWED_ATTRIBUTES_SYNTAX(
    method: *const X509V3ExtMethod,
    aaa: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let aaa = aaa.cast::<OpenSslStack>();
    // SAFETY: `aaa` is a live `STACK_OF(OSSL_ALLOWED_ATTRIBUTES_ITEM)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(aaa) };
    let mut i = 0;
    while i < num {
        // SAFETY: `out` is live; the format and its argument are constants.
        if unsafe {
            BIO_printf(
                out,
                c"%*sAllowed Attributes:\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `aaa` is live and `i` is in bounds.
        let aai = unsafe { OPENSSL_sk_value(aaa, i) };
        // SAFETY: `aai` is a live item per the stack contract.
        if unsafe { i2r_ALLOWED_ATTRIBUTES_ITEM(method, aai, out, indent + 4) } <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_allowed_attribute_assignments` — `crypto/x509/v3_aaa.c:118-128`.
pub static ossl_v3_allowed_attribute_assignments: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_allowed_attribute_assignments,
    ext_flags: 0,
    it: Some(OSSL_ALLOWED_ATTRIBUTES_SYNTAX_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ALLOWED_ATTRIBUTES_SYNTAX),
    r2i: None,
    usr_data: ptr::null_mut(),
};
