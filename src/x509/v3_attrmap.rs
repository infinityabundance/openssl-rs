//! `crypto/x509/v3_attrmap.c` — the attribute-mappings item group and its row. Phase 10.14.6's table
//! layer, landed whole.
//!
//! `crypto/x509/v3_attrmap.c` is 116 lines and transcribes whole:
//!
//! * `OSSL_ATAV ::= SEQUENCE { type ASN1_OBJECT, value ASN1_ANY }` (`:15-18`),
//!   `OSSL_ATTRIBUTE_TYPE_MAPPING ::= SEQUENCE { local [0] IMPLICIT ASN1_OBJECT, remote [1] IMPLICIT
//!   ASN1_OBJECT }` (`:20-23`), `OSSL_ATTRIBUTE_VALUE_MAPPING ::= SEQUENCE { local [0] IMPLICIT
//!   OSSL_ATAV, remote [1] IMPLICIT OSSL_ATAV }` (`:25-28`), `OSSL_ATTRIBUTE_MAPPING ::= CHOICE {
//!   typeMappings [0] IMPLICIT OSSL_ATTRIBUTE_TYPE_MAPPING, typeValueMappings [1] IMPLICIT
//!   OSSL_ATTRIBUTE_VALUE_MAPPING }` (`:30-35`) and `OSSL_ATTRIBUTE_MAPPINGS ::= SET OF
//!   OSSL_ATTRIBUTE_MAPPING` (`:37-38`). All five end in a non-`static` macro, so each yields the
//!   `_it`/`_new`/`_free`/`d2i_`/`i2d_` group of `IMPLEMENT_ASN1_FUNCTIONS` (`:40-44`).
//! * the two printers [`i2r_ATTRIBUTE_MAPPING`] (`:46-85`) and [`i2r_ATTRIBUTE_MAPPINGS`] (`:87-104`).
//! * the row [`ossl_v3_attribute_mappings`] (`:106-116`, `NID_attribute_mappings`).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the array
//! is withheld until all 63 tables exist. This unit contributes one of the 63. The row is internal
//! data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the item group and the two
//! printers are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_attrmap.c` contains no `ERR_raise*`, so no raise coordinate is declared here.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_ANY_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_attribute_mappings, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::x_attrib::ossl_print_attribute_value;

/// `OSSL_ATTR_MAP_TYPE` — `include/openssl/x509v3.h:1868`.
const OSSL_ATTR_MAP_TYPE: c_int = 0;
/// `OSSL_ATTR_MAP_VALUE` — `include/openssl/x509v3.h:1869`.
const OSSL_ATTR_MAP_VALUE: c_int = 1;

/// `struct atav_st` — `OSSL_ATAV`, from `include/openssl/x509v3.h:1853-1856`.
#[repr(C)]
pub struct OsslAtav {
    /// `ASN1_OBJECT *type`.
    pub type_: *mut Asn1Object,
    /// `ASN1_TYPE *value`.
    pub value: *mut Asn1Type,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAtav>() == 16);
    assert!(core::mem::offset_of!(OsslAtav, type_) == 0);
    assert!(core::mem::offset_of!(OsslAtav, value) == 8);
};

/// `struct ATTRIBUTE_TYPE_MAPPING_st` — `OSSL_ATTRIBUTE_TYPE_MAPPING`, from
/// `include/openssl/x509v3.h:1858-1861`.
#[repr(C)]
pub struct OsslAttributeTypeMapping {
    /// `ASN1_OBJECT *local` — `[0]` implicit.
    pub local: *mut Asn1Object,
    /// `ASN1_OBJECT *remote` — `[1]` implicit.
    pub remote: *mut Asn1Object,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAttributeTypeMapping>() == 16);
    assert!(core::mem::offset_of!(OsslAttributeTypeMapping, local) == 0);
    assert!(core::mem::offset_of!(OsslAttributeTypeMapping, remote) == 8);
};

/// `struct ATTRIBUTE_VALUE_MAPPING_st` — `OSSL_ATTRIBUTE_VALUE_MAPPING`, from
/// `include/openssl/x509v3.h:1863-1866`.
#[repr(C)]
pub struct OsslAttributeValueMapping {
    /// `OSSL_ATAV *local` — `[0]` implicit.
    pub local: *mut OsslAtav,
    /// `OSSL_ATAV *remote` — `[1]` implicit.
    pub remote: *mut OsslAtav,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAttributeValueMapping>() == 16);
    assert!(core::mem::offset_of!(OsslAttributeValueMapping, local) == 0);
    assert!(core::mem::offset_of!(OsslAttributeValueMapping, remote) == 8);
};

/// The `type`-selected union of `struct ATTRIBUTE_MAPPING_st` — `include/openssl/x509v3.h:1872-1876`.
#[repr(C)]
pub union OsslAttributeMappingChoice {
    /// `OSSL_ATTRIBUTE_TYPE_MAPPING *typeMappings` — the `[0]` arm.
    pub typeMappings: *mut OsslAttributeTypeMapping,
    /// `OSSL_ATTRIBUTE_VALUE_MAPPING *typeValueMappings` — the `[1]` arm.
    pub typeValueMappings: *mut OsslAttributeValueMapping,
}

/// `struct ATTRIBUTE_MAPPING_st` — `OSSL_ATTRIBUTE_MAPPING`, from
/// `include/openssl/x509v3.h:1871-1877`.
#[repr(C)]
pub struct OsslAttributeMapping {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ... } choice`.
    pub choice: OsslAttributeMappingChoice,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAttributeMapping>() == 16);
    assert!(core::mem::offset_of!(OsslAttributeMapping, type_) == 0);
    assert!(core::mem::offset_of!(OsslAttributeMapping, choice) == 8);
};

/// `OSSL_ATAV_seq_tt` — `ASN1_SEQUENCE(OSSL_ATAV)` (`crypto/x509/v3_attrmap.c:15-17`):
/// `ASN1_SIMPLE(OSSL_ATAV, type, ASN1_OBJECT)` and `ASN1_SIMPLE(OSSL_ATAV, value, ASN1_ANY)`.
static OSSL_ATAV_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
];

/// `OSSL_ATAV_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ATAV)` at `crypto/x509/v3_attrmap.c:18`.
static OSSL_ATAV_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ATAV_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAtav>() as c_long,
    sname: c"OSSL_ATAV".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATAV_it(void)` — `include/openssl/x509v3.h:1881`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_ATAV)`.
#[no_mangle]
pub extern "C" fn OSSL_ATAV_it() -> *const Asn1Item {
    &OSSL_ATAV_ITEM
}

/// `OSSL_ATAV *OSSL_ATAV_new(void)` — `crypto/x509/v3_attrmap.c:40`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATAV)`.
#[no_mangle]
pub extern "C" fn OSSL_ATAV_new() -> *mut OsslAtav {
    // SAFETY: `OSSL_ATAV_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATAV_it()).cast::<OsslAtav>() }
}

/// `void OSSL_ATAV_free(OSSL_ATAV *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATAV_free(a: *mut OsslAtav) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATAV_it()) }
}

/// `OSSL_ATAV *d2i_OSSL_ATAV(OSSL_ATAV **a, const unsigned char **in, long len)` — the same macro's
/// decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATAV(
    a: *mut *mut OsslAtav,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAtav {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_ATAV_it()).cast::<OsslAtav>() }
}

/// `int i2d_OSSL_ATAV(const OSSL_ATAV *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATAV(a: *const OsslAtav, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATAV_it()) }
}

/// `OSSL_ATTRIBUTE_TYPE_MAPPING_seq_tt` — `ASN1_SEQUENCE(OSSL_ATTRIBUTE_TYPE_MAPPING)`
/// (`crypto/x509/v3_attrmap.c:20-23`): `ASN1_IMP(..., local, ASN1_OBJECT, 0)` and
/// `ASN1_IMP(..., remote, ASN1_OBJECT, 1)`.
static OSSL_ATTRIBUTE_TYPE_MAPPING_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 0,
        field_name: c"local".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"remote".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
];

/// `OSSL_ATTRIBUTE_TYPE_MAPPING_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ATTRIBUTE_TYPE_MAPPING)`
/// at `crypto/x509/v3_attrmap.c:23`.
static OSSL_ATTRIBUTE_TYPE_MAPPING_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ATTRIBUTE_TYPE_MAPPING_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAttributeTypeMapping>() as c_long,
    sname: c"OSSL_ATTRIBUTE_TYPE_MAPPING".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTE_TYPE_MAPPING_it(void)` — `include/openssl/x509v3.h:1882`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTE_TYPE_MAPPING_ITEM
}

/// `OSSL_ATTRIBUTE_TYPE_MAPPING *OSSL_ATTRIBUTE_TYPE_MAPPING_new(void)` —
/// `crypto/x509/v3_attrmap.c:41`, from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATTRIBUTE_TYPE_MAPPING)`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_new() -> *mut OsslAttributeTypeMapping {
    // SAFETY: `OSSL_ATTRIBUTE_TYPE_MAPPING_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTE_TYPE_MAPPING_it()).cast::<OsslAttributeTypeMapping>() }
}

/// `void OSSL_ATTRIBUTE_TYPE_MAPPING_free(OSSL_ATTRIBUTE_TYPE_MAPPING *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTE_TYPE_MAPPING_free(a: *mut OsslAttributeTypeMapping) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTE_TYPE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_TYPE_MAPPING *d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(OSSL_ATTRIBUTE_TYPE_MAPPING **a,
/// const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_TYPE_MAPPING(
    a: *mut *mut OsslAttributeTypeMapping,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAttributeTypeMapping {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTE_TYPE_MAPPING_it())
            .cast::<OsslAttributeTypeMapping>()
    }
}

/// `int i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(const OSSL_ATTRIBUTE_TYPE_MAPPING *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_TYPE_MAPPING(
    a: *const OsslAttributeTypeMapping,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTE_TYPE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_VALUE_MAPPING_seq_tt` — `ASN1_SEQUENCE(OSSL_ATTRIBUTE_VALUE_MAPPING)`
/// (`crypto/x509/v3_attrmap.c:25-28`): `ASN1_IMP(..., local, OSSL_ATAV, 0)` and
/// `ASN1_IMP(..., remote, OSSL_ATAV, 1)`.
static OSSL_ATTRIBUTE_VALUE_MAPPING_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 0,
        field_name: c"local".as_ptr(),
        item: OSSL_ATAV_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"remote".as_ptr(),
        item: OSSL_ATAV_it as *mut c_void,
    },
];

/// `OSSL_ATTRIBUTE_VALUE_MAPPING_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ATTRIBUTE_VALUE_MAPPING)`
/// at `crypto/x509/v3_attrmap.c:28`.
static OSSL_ATTRIBUTE_VALUE_MAPPING_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ATTRIBUTE_VALUE_MAPPING_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAttributeValueMapping>() as c_long,
    sname: c"OSSL_ATTRIBUTE_VALUE_MAPPING".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTE_VALUE_MAPPING_it(void)` — `include/openssl/x509v3.h:1883`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTE_VALUE_MAPPING_ITEM
}

/// `OSSL_ATTRIBUTE_VALUE_MAPPING *OSSL_ATTRIBUTE_VALUE_MAPPING_new(void)` —
/// `crypto/x509/v3_attrmap.c:42`, from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATTRIBUTE_VALUE_MAPPING)`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_new() -> *mut OsslAttributeValueMapping {
    // SAFETY: `OSSL_ATTRIBUTE_VALUE_MAPPING_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTE_VALUE_MAPPING_it()).cast::<OsslAttributeValueMapping>() }
}

/// `void OSSL_ATTRIBUTE_VALUE_MAPPING_free(OSSL_ATTRIBUTE_VALUE_MAPPING *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTE_VALUE_MAPPING_free(a: *mut OsslAttributeValueMapping) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTE_VALUE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_VALUE_MAPPING *d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(OSSL_ATTRIBUTE_VALUE_MAPPING **a,
/// const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_VALUE_MAPPING(
    a: *mut *mut OsslAttributeValueMapping,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAttributeValueMapping {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTE_VALUE_MAPPING_it())
            .cast::<OsslAttributeValueMapping>()
    }
}

/// `int i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(const OSSL_ATTRIBUTE_VALUE_MAPPING *a, unsigned char
/// **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_VALUE_MAPPING(
    a: *const OsslAttributeValueMapping,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTE_VALUE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_MAPPING_ch_tt` — `ASN1_CHOICE(OSSL_ATTRIBUTE_MAPPING)`
/// (`crypto/x509/v3_attrmap.c:30-35`): `ASN1_IMP(..., choice.typeMappings, OSSL_ATTRIBUTE_TYPE_MAPPING,
/// OSSL_ATTR_MAP_TYPE)` and `ASN1_IMP(..., choice.typeValueMappings, OSSL_ATTRIBUTE_VALUE_MAPPING,
/// OSSL_ATTR_MAP_VALUE)`. Both arms live at the union's offset, 8.
static OSSL_ATTRIBUTE_MAPPING_CH_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"choice.typeMappings".as_ptr(),
        item: OSSL_ATTRIBUTE_TYPE_MAPPING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"choice.typeValueMappings".as_ptr(),
        item: OSSL_ATTRIBUTE_VALUE_MAPPING_it as *mut c_void,
    },
];

/// `OSSL_ATTRIBUTE_MAPPING_it`'s descriptor — `ASN1_CHOICE_END(OSSL_ATTRIBUTE_MAPPING)` at
/// `crypto/x509/v3_attrmap.c:35`. The `utype` of a `CHOICE` is the selector's offset.
static OSSL_ATTRIBUTE_MAPPING_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OsslAttributeMapping, type_) as c_long,
    templates: OSSL_ATTRIBUTE_MAPPING_CH_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAttributeMapping>() as c_long,
    sname: c"OSSL_ATTRIBUTE_MAPPING".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTE_MAPPING_it(void)` — `include/openssl/x509v3.h:1884`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_MAPPING_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTE_MAPPING_ITEM
}

/// `OSSL_ATTRIBUTE_MAPPING *OSSL_ATTRIBUTE_MAPPING_new(void)` — `crypto/x509/v3_attrmap.c:43`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATTRIBUTE_MAPPING)`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_MAPPING_new() -> *mut OsslAttributeMapping {
    // SAFETY: `OSSL_ATTRIBUTE_MAPPING_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTE_MAPPING_it()).cast::<OsslAttributeMapping>() }
}

/// `void OSSL_ATTRIBUTE_MAPPING_free(OSSL_ATTRIBUTE_MAPPING *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPING_free(a: *mut OsslAttributeMapping) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_MAPPING *d2i_OSSL_ATTRIBUTE_MAPPING(OSSL_ATTRIBUTE_MAPPING **a, const unsigned
/// char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_MAPPING(
    a: *mut *mut OsslAttributeMapping,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAttributeMapping {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTE_MAPPING_it())
            .cast::<OsslAttributeMapping>()
    }
}

/// `int i2d_OSSL_ATTRIBUTE_MAPPING(const OSSL_ATTRIBUTE_MAPPING *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_MAPPING(
    a: *const OsslAttributeMapping,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTE_MAPPING_it()) }
}

/// `OSSL_ATTRIBUTE_MAPPINGS_item_tt` —
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, OSSL_ATTRIBUTE_MAPPINGS, OSSL_ATTRIBUTE_MAPPING)` at
/// `crypto/x509/v3_attrmap.c:37`. The value is a `STACK_OF(OSSL_ATTRIBUTE_MAPPING)`.
static OSSL_ATTRIBUTE_MAPPINGS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SET_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_ATTRIBUTE_MAPPINGS".as_ptr(),
    item: OSSL_ATTRIBUTE_MAPPING_it as *mut c_void,
};

/// `OSSL_ATTRIBUTE_MAPPINGS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(OSSL_ATTRIBUTE_MAPPINGS)` at
/// `crypto/x509/v3_attrmap.c:38`: a `PRIMITIVE` item over one `SET OF` template, `utype` `-1`,
/// `tcount` 0.
static OSSL_ATTRIBUTE_MAPPINGS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_ATTRIBUTE_MAPPINGS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_ATTRIBUTE_MAPPINGS".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTE_MAPPINGS_it(void)` — `include/openssl/x509v3.h:1884`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTE_MAPPINGS_ITEM
}

/// `OSSL_ATTRIBUTE_MAPPINGS *OSSL_ATTRIBUTE_MAPPINGS_new(void)` — `crypto/x509/v3_attrmap.c:44`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATTRIBUTE_MAPPINGS)`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_ATTRIBUTE_MAPPINGS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTE_MAPPINGS_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_ATTRIBUTE_MAPPINGS_free(OSSL_ATTRIBUTE_MAPPINGS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTE_MAPPINGS_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTE_MAPPINGS_it()) }
}

/// `OSSL_ATTRIBUTE_MAPPINGS *d2i_OSSL_ATTRIBUTE_MAPPINGS(OSSL_ATTRIBUTE_MAPPINGS **a, const unsigned
/// char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_MAPPINGS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTE_MAPPINGS_it()).cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_ATTRIBUTE_MAPPINGS(const OSSL_ATTRIBUTE_MAPPINGS *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_MAPPINGS(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTE_MAPPINGS_it()) }
}

// ---------------------------------------------------------------------------------------------
// The two printers (`:46-104`)
// ---------------------------------------------------------------------------------------------

/// `static int i2r_ATTRIBUTE_MAPPING(X509V3_EXT_METHOD *method, OSSL_ATTRIBUTE_MAPPING *am, BIO *out,
/// int indent)` — `crypto/x509/v3_attrmap.c:46-85`.
///
/// # Safety
///
/// `out` is a live BIO; `am` is a live `OSSL_ATTRIBUTE_MAPPING`.
unsafe extern "C" fn i2r_ATTRIBUTE_MAPPING(
    _method: *const X509V3ExtMethod,
    am: *mut c_void,
    out: *mut Bio,
    _indent: c_int,
) -> c_int {
    let am = am.cast::<OsslAttributeMapping>();
    // SAFETY: `am` is live.
    let type_ = unsafe { (*am).type_ };
    if type_ == OSSL_ATTR_MAP_TYPE {
        // SAFETY: `am`'s selector selects the live `typeMappings` arm.
        let mapping = unsafe { (*am).choice.typeMappings };
        // SAFETY: `out` is live and `mapping`'s `local` is a live object.
        if unsafe { i2a_ASN1_OBJECT(out, (*mapping).local) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c" == ".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `mapping`'s `remote` is a live object.
        return unsafe { i2a_ASN1_OBJECT(out, (*mapping).remote) };
    }
    if type_ == OSSL_ATTR_MAP_VALUE {
        // SAFETY: `am`'s selector selects the live `typeValueMappings` arm.
        let vm = unsafe { (*am).choice.typeValueMappings };
        // SAFETY: both `vm` pointers are live `OSSL_ATAV` values.
        let (local_type, remote_type, local_val, remote_val) = unsafe {
            let local = (*vm).local;
            let remote = (*vm).remote;
            (
                (*local).type_,
                (*remote).type_,
                (*local).value,
                (*remote).value,
            )
        };
        // SAFETY: the two object pointers are live.
        let local_attr_nid = unsafe { OBJ_obj2nid(local_type) };
        // SAFETY: as above.
        let remote_attr_nid = unsafe { OBJ_obj2nid(remote_type) };
        // SAFETY: `out` is live and `local_type` is a live object.
        if unsafe { i2a_ASN1_OBJECT(out, local_type) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c":".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `local_val` is a live `ASN1_TYPE`.
        if unsafe { ossl_print_attribute_value(out, local_attr_nid, local_val, 0) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c" == ".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `remote_type` is a live object.
        if unsafe { i2a_ASN1_OBJECT(out, remote_type) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c":".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `remote_val` is a live `ASN1_TYPE`.
        return unsafe { ossl_print_attribute_value(out, remote_attr_nid, remote_val, 0) };
    }
    0
}

/// `static int i2r_ATTRIBUTE_MAPPINGS(X509V3_EXT_METHOD *method, OSSL_ATTRIBUTE_MAPPINGS *ams,
/// BIO *out, int indent)` — `crypto/x509/v3_attrmap.c:87-104`.
///
/// # Safety
///
/// `out` is a live BIO; `ams` is a live `STACK_OF(OSSL_ATTRIBUTE_MAPPING)`.
unsafe extern "C" fn i2r_ATTRIBUTE_MAPPINGS(
    method: *const X509V3ExtMethod,
    ams: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let ams = ams.cast::<OpenSslStack>();
    // SAFETY: `ams` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(ams) };
    let mut i = 0;
    while i < num {
        // SAFETY: `ams` is live and `i` is in bounds.
        let am = unsafe { OPENSSL_sk_value(ams, i) };
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `am` is a live `OSSL_ATTRIBUTE_MAPPING`.
        if unsafe { i2r_ATTRIBUTE_MAPPING(method, am, out, indent + 4) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_attribute_mappings` — `crypto/x509/v3_attrmap.c:106-116`.
///
/// `NID_attribute_mappings`, `X509V3_EXT_MULTILINE`, item [`OSSL_ATTRIBUTE_MAPPINGS_it`] and the
/// [`i2r_ATTRIBUTE_MAPPINGS`] printer.
pub static ossl_v3_attribute_mappings: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_attribute_mappings,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(OSSL_ATTRIBUTE_MAPPINGS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ATTRIBUTE_MAPPINGS),
    r2i: None,
    usr_data: ptr::null_mut(),
};
