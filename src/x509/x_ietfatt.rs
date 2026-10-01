//! `crypto/x509/x_ietfatt.c` -- the `IetfAttrSyntax` item group of RFC 5755 4.4 and its
//! accessors. Phase 11.3.
//!
//! `crypto/x509/x_ietfatt.c` is 239 lines and publishes fourteen functions: the
//! `OSSL_IETF_ATTR_SYNTAX_VALUE` CHOICE item and its `_it`/`_new`/`_free` group (`:45-49`,
//! `:57`), the `OSSL_IETF_ATTR_SYNTAX` SEQUENCE item and its `_it`/`_new`/`_free`/`d2i_`/`i2d_`
//! group (`:51-54`, `:56`), the hand-written `d2i_`/`i2d_` pair that validates the "all values
//! share one choice" rule (`:59-95`), and the four accessors plus the value adder and the
//! printer (`:97-239`). **The whole unit lands here**; nothing is withheld and nothing is
//! stubbed.
//!
//! ```text
//! IetfAttrSyntax ::= SEQUENCE {
//!   policyAuthority [0] GeneralNames    OPTIONAL,
//!   values          SEQUENCE OF CHOICE {
//!                     octets    OCTET STRING,
//!                     oid       OBJECT IDENTIFIER,
//!                     string    UTF8String
//!                   }
//! }
//! ```
//!
//! Section 4.4.2 states that every value in the sequence MUST use the same choice, so the
//! `d2i_` wrapper decodes with the item layer and then walks the `values` stack refusing a
//! mixed sequence with `X509V3_R`'s `ERR_R_PASSED_INVALID_ARGUMENT`. That is the one rule the
//! template cannot express, and it is why the unit overrides the generated decoder.
//!
//! ## The two layouts
//!
//! `struct OSSL_IETF_ATTR_SYNTAX_VALUE_st` is `{ int type; union { ASN1_OCTET_STRING *octets;
//! ASN1_OBJECT *oid; ASN1_UTF8STRING *string; } u; }` (`include/openssl/x509_acert.h:140`);
//! `struct OSSL_IETF_ATTR_SYNTAX_st` is `{ GENERAL_NAMES *policyAuthority; int type;
//! STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *values; }` (`:141`). Both are unsigned-byte
//! offsets asserted below (16 and 24), read from the authority's own declarations.
//!
//! ## The raise sites
//!
//! `crypto/x509/x_ietfatt.c` is not an entry in `gen_err_raise_sites.py` (the generator's
//! covered set is the closed-stratum file list), so its four coordinates are **declared
//! locally** with the `err_sites::ErrSite` shape, as `v3_ac_tgt.rs` does. Their reason values
//! are read from the authority's `err.h`, not typed from memory: the mixed-type refusals carry
//! `ERR_R_PASSED_INVALID_ARGUMENT` (`:87`, `:157`, `:177`) and the stack-allocation failure
//! carries `ERR_R_CRYPTO_LIB` (`:189`).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{Asn1Object, OBJ_obj2txt};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_genn::{GENERAL_NAMES_free, GENERAL_NAME_it};
use crate::x509::v3_san::GENERAL_NAME_print;

/// `OSSL_IETFAS_OCTETS` -- `include/openssl/x509_acert.h:136`.
const OSSL_IETFAS_OCTETS: c_int = 0;
/// `OSSL_IETFAS_OID` -- `include/openssl/x509_acert.h:137`.
const OSSL_IETFAS_OID: c_int = 1;
/// `OSSL_IETFAS_STRING` -- `include/openssl/x509_acert.h:138`.
const OSSL_IETFAS_STRING: c_int = 2;

/// `ERR_LIB_X509V3` -- `include/openssl/err.h.in:99`, `34`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_PASSED_INVALID_ARGUMENT` -- `include/openssl/err.h.in:360`, `262 | ERR_RFLAG_COMMON`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 262 | (0x2 << 18);
/// `ERR_R_CRYPTO_LIB` -- `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`.
const ERR_R_CRYPTO_LIB: c_int = 15 | (0x2 << 18);

/// One `x_ietfatt.c` raise coordinate, declared locally (see the module doc).
const fn x_ietfatt_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x_ietfatt.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `d2i_OSSL_IETF_ATTR_SYNTAX`'s mixed-choice refusal at `x_ietfatt.c:87`.
const X_IETFATT_87: ErrSite = x_ietfatt_site(
    87,
    c"d2i_OSSL_IETF_ATTR_SYNTAX",
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `OSSL_IETF_ATTR_SYNTAX_add1_value`'s mismatched-type refusal at `x_ietfatt.c:157`.
const X_IETFATT_157: ErrSite = x_ietfatt_site(
    157,
    c"OSSL_IETF_ATTR_SYNTAX_add1_value",
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `OSSL_IETF_ATTR_SYNTAX_add1_value`'s unknown-type refusal at `x_ietfatt.c:177`.
const X_IETFATT_177: ErrSite = x_ietfatt_site(
    177,
    c"OSSL_IETF_ATTR_SYNTAX_add1_value",
    ERR_R_PASSED_INVALID_ARGUMENT,
);
/// `OSSL_IETF_ATTR_SYNTAX_add1_value`'s stack-allocation failure at `x_ietfatt.c:189`.
const X_IETFATT_189: ErrSite =
    x_ietfatt_site(189, c"OSSL_IETF_ATTR_SYNTAX_add1_value", ERR_R_CRYPTO_LIB);

// ---------------------------------------------------------------------------------------------
// The `OSSL_IETF_ATTR_SYNTAX_VALUE` CHOICE item -- `ASN1_CHOICE(...)` (`:45-49`)
// ---------------------------------------------------------------------------------------------

/// The `type`-selected union of `struct OSSL_IETF_ATTR_SYNTAX_VALUE_st` --
/// `include/openssl/x509_acert.h:30-37`. All three arms are pointer-sized, so the union begins
/// at the structure's `u` offset, 8.
#[repr(C)]
pub union OsslIetfAttrSyntaxValueUnion {
    /// `ASN1_OCTET_STRING *octets` -- the `:30` arm.
    pub(crate) octets: *mut Asn1String,
    /// `ASN1_OBJECT *oid` -- the `:31` arm.
    pub(crate) oid: *mut Asn1Object,
    /// `ASN1_UTF8STRING *string` -- the `:32` arm.
    pub(crate) string: *mut Asn1String,
}

/// `struct OSSL_IETF_ATTR_SYNTAX_VALUE_st` -- from `crypto/x509/x_ietfatt.c:30-37`.
#[repr(C)]
pub struct OsslIetfAttrSyntaxValue {
    /// `int type` -- the CHOICE selector.
    pub type_: c_int,
    /// `union { ... } u`.
    pub u: OsslIetfAttrSyntaxValueUnion,
}

const _: () = {
    assert!(core::mem::size_of::<OsslIetfAttrSyntaxValue>() == 16);
    assert!(core::mem::offset_of!(OsslIetfAttrSyntaxValue, type_) == 0);
    assert!(core::mem::offset_of!(OsslIetfAttrSyntaxValue, u) == 8);
};

/// `OSSL_IETF_ATTR_SYNTAX_VALUE_ch_tt` -- `ASN1_CHOICE(OSSL_IETF_ATTR_SYNTAX_VALUE)`
/// (`crypto/x509/x_ietfatt.c:45-49`): `ASN1_SIMPLE(..., u.octets, ASN1_OCTET_STRING)`,
/// `ASN1_SIMPLE(..., u.oid, ASN1_OBJECT)` and `ASN1_SIMPLE(..., u.string, ASN1_UTF8STRING)`.
/// Every arm lives at the union's offset, 8.
static OSSL_IETF_ATTR_SYNTAX_VALUE_CH_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.octets".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.oid".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.string".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
];

/// `OSSL_IETF_ATTR_SYNTAX_VALUE_it`'s descriptor -- `ASN1_CHOICE_END(...)` at
/// `crypto/x509/x_ietfatt.c:49`. The `utype` of a `CHOICE` is the selector's offset (0 here).
static OSSL_IETF_ATTR_SYNTAX_VALUE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OsslIetfAttrSyntaxValue, type_) as c_long,
    templates: OSSL_IETF_ATTR_SYNTAX_VALUE_CH_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslIetfAttrSyntaxValue>() as c_long,
    sname: c"OSSL_IETF_ATTR_SYNTAX_VALUE".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_IETF_ATTR_SYNTAX_VALUE_it(void)` -- `include/crypto/x509_acert.h:148`,
/// from `DECLARE_ASN1_ITEM(OSSL_IETF_ATTR_SYNTAX_VALUE)`.
#[no_mangle]
pub extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_it() -> *const Asn1Item {
    &OSSL_IETF_ATTR_SYNTAX_VALUE_ITEM
}

/// `OSSL_IETF_ATTR_SYNTAX_VALUE *OSSL_IETF_ATTR_SYNTAX_VALUE_new(void)` --
/// `crypto/x509/x_ietfatt.c:57`, from `IMPLEMENT_ASN1_ALLOC_FUNCTIONS`.
#[no_mangle]
pub extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_new() -> *mut OsslIetfAttrSyntaxValue {
    // SAFETY: `OSSL_IETF_ATTR_SYNTAX_VALUE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_IETF_ATTR_SYNTAX_VALUE_it()).cast::<OsslIetfAttrSyntaxValue>() }
}

/// `void OSSL_IETF_ATTR_SYNTAX_VALUE_free(OSSL_IETF_ATTR_SYNTAX_VALUE *a)` -- the same macro's
/// free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_VALUE_free(a: *mut OsslIetfAttrSyntaxValue) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_IETF_ATTR_SYNTAX_VALUE_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_IETF_ATTR_SYNTAX` SEQUENCE item -- `ASN1_SEQUENCE(...)` (`:51-54`)
// ---------------------------------------------------------------------------------------------

/// `struct OSSL_IETF_ATTR_SYNTAX_st` -- from `crypto/x509/x_ietfatt.c:39-43`.
#[repr(C)]
pub struct OsslIetfAttrSyntax {
    /// `GENERAL_NAMES *policyAuthority` -- optional, an implicit `[0]` `GENERAL_NAME` sequence.
    pub policyAuthority: *mut OpenSslStack,
    /// `int type` -- the choice all `values` share.
    pub type_: c_int,
    /// `STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *values`.
    pub values: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OsslIetfAttrSyntax>() == 24);
    assert!(core::mem::offset_of!(OsslIetfAttrSyntax, policyAuthority) == 0);
    assert!(core::mem::offset_of!(OsslIetfAttrSyntax, type_) == 8);
    assert!(core::mem::offset_of!(OsslIetfAttrSyntax, values) == 16);
};

/// `OSSL_IETF_ATTR_SYNTAX_seq_tt` -- `ASN1_SEQUENCE(OSSL_IETF_ATTR_SYNTAX)`
/// (`crypto/x509/x_ietfatt.c:51-54`):
/// `ASN1_IMP_SEQUENCE_OF_OPT(..., policyAuthority, GENERAL_NAME, 0)` and
/// `ASN1_SEQUENCE_OF(..., values, OSSL_IETF_ATTR_SYNTAX_VALUE)`.
static OSSL_IETF_ATTR_SYNTAX_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"policyAuthority".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 16,
        field_name: c"values".as_ptr(),
        item: OSSL_IETF_ATTR_SYNTAX_VALUE_it as *mut c_void,
    },
];

/// `OSSL_IETF_ATTR_SYNTAX_it`'s descriptor -- `ASN1_SEQUENCE_END(OSSL_IETF_ATTR_SYNTAX)` at
/// `crypto/x509/x_ietfatt.c:54`.
static OSSL_IETF_ATTR_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_IETF_ATTR_SYNTAX_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslIetfAttrSyntax>() as c_long,
    sname: c"OSSL_IETF_ATTR_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_IETF_ATTR_SYNTAX_it(void)` -- `include/crypto/x509_acert.h:150`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_IETF_ATTR_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_IETF_ATTR_SYNTAX_it() -> *const Asn1Item {
    &OSSL_IETF_ATTR_SYNTAX_ITEM
}

/// `OSSL_IETF_ATTR_SYNTAX *OSSL_IETF_ATTR_SYNTAX_new(void)` -- `crypto/x509/x_ietfatt.c:56`,
/// from `IMPLEMENT_ASN1_FUNCTIONS`.
#[no_mangle]
pub extern "C" fn OSSL_IETF_ATTR_SYNTAX_new() -> *mut OsslIetfAttrSyntax {
    // SAFETY: `OSSL_IETF_ATTR_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_IETF_ATTR_SYNTAX_it()).cast::<OsslIetfAttrSyntax>() }
}

/// `void OSSL_IETF_ATTR_SYNTAX_free(OSSL_IETF_ATTR_SYNTAX *a)` -- the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_free(a: *mut OsslIetfAttrSyntax) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_IETF_ATTR_SYNTAX_it()) }
}

/// `OSSL_IETF_ATTR_SYNTAX *d2i_OSSL_IETF_ATTR_SYNTAX(OSSL_IETF_ATTR_SYNTAX **a,
/// const unsigned char **in, long len)` -- `crypto/x509/x_ietfatt.c:59-89`.
///
/// Decodes with the item layer, then enforces RFC 5755 4.4.2: every value in the sequence must
/// share the first value's choice, or the whole object is released and
/// `ERR_R_PASSED_INVALID_ARGUMENT` raised.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_IETF_ATTR_SYNTAX(
    a: *mut *mut OsslIetfAttrSyntax,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslIetfAttrSyntax {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    let ias = unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_IETF_ATTR_SYNTAX_it()) }
        .cast::<OsslIetfAttrSyntax>();
    if ias.is_null() {
        return ias;
    }
    // SAFETY: `ias` is this call's own live value; its `values` is a stack or NULL.
    let num = unsafe { OPENSSL_sk_num((*ias).values) };
    for i in 0..num {
        // SAFETY: `ias` is live and `i` is within the stack; the element is a value.
        let val = unsafe { OPENSSL_sk_value((*ias).values, i) }.cast::<OsslIetfAttrSyntaxValue>();
        // SAFETY: `val` is the live element just read; `ias` is live.
        let vt = unsafe { (*val).type_ };
        // SAFETY: `ias` is this call's own live value.
        let cur = unsafe { (*ias).type_ };
        if i == 0 {
            // SAFETY: `ias` is this call's own live value and its selector slot is writable.
            unsafe { (*ias).type_ = vt };
        } else if vt != cur {
            // SAFETY: `ias` is this call's own and is not owned elsewhere.
            unsafe { OSSL_IETF_ATTR_SYNTAX_free(ias) };
            if !a.is_null() {
                // SAFETY: `a` is writable per the contract.
                unsafe { *a = ptr::null_mut() };
            }
            // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
            unsafe { raise_site(&X_IETFATT_87) };
            return ptr::null_mut();
        }
    }
    ias
}

/// `int i2d_OSSL_IETF_ATTR_SYNTAX(const OSSL_IETF_ATTR_SYNTAX *a, unsigned char **out)` --
/// `crypto/x509/x_ietfatt.c:91-95`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_IETF_ATTR_SYNTAX(
    a: *const OsslIetfAttrSyntax,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_IETF_ATTR_SYNTAX_it()) }
}

/// `int OSSL_IETF_ATTR_SYNTAX_get_value_num(const OSSL_IETF_ATTR_SYNTAX *a)` --
/// `crypto/x509/x_ietfatt.c:97-103`.
///
/// An absent `values` stack answers 0 rather than `OPENSSL_sk_num`'s `-1`.
///
/// # Safety
///
/// `a` must be a live `OSSL_IETF_ATTR_SYNTAX`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get_value_num(
    a: *const OsslIetfAttrSyntax,
) -> c_int {
    // SAFETY: `a` is live per the contract.
    if unsafe { (*a).values }.is_null() {
        return 0;
    }
    // SAFETY: `a` is live and its `values` is a live stack per the check above.
    unsafe { OPENSSL_sk_num((*a).values) }
}

/// `const GENERAL_NAMES *OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(const
/// OSSL_IETF_ATTR_SYNTAX *a)` -- `crypto/x509/x_ietfatt.c:105-109`.
///
/// # Safety
///
/// `a` must be a live `OSSL_IETF_ATTR_SYNTAX`; the answer borrows its `policyAuthority`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(
    a: *const OsslIetfAttrSyntax,
) -> *const OpenSslStack {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).policyAuthority }
}

/// `void OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(OSSL_IETF_ATTR_SYNTAX *a,
/// GENERAL_NAMES *names)` -- `crypto/x509/x_ietfatt.c:111-116`.
///
/// # Safety
///
/// `a` must be a live `OSSL_IETF_ATTR_SYNTAX`; `names` is NULL or a stack this call takes
/// ownership of.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(
    a: *mut OsslIetfAttrSyntax,
    names: *mut OpenSslStack,
) {
    // SAFETY: `a` is live per the contract; its `policyAuthority` is its own.
    unsafe { GENERAL_NAMES_free((*a).policyAuthority) };
    // SAFETY: `a` is live and its `policyAuthority` slot is writable.
    unsafe { (*a).policyAuthority = names };
}

/// `void *OSSL_IETF_ATTR_SYNTAX_get0_value(const OSSL_IETF_ATTR_SYNTAX *a, int ind,
/// int *type)` -- `crypto/x509/x_ietfatt.c:118-140`.
///
/// Answers the selected value's union member (borrowed) and, when `type` is non-NULL, its
/// choice. An out-of-range index or an unknown selector answers NULL.
///
/// # Safety
///
/// `a` must be a live `OSSL_IETF_ATTR_SYNTAX`; `type` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_get0_value(
    a: *const OsslIetfAttrSyntax,
    ind: c_int,
    type_: *mut c_int,
) -> *mut c_void {
    // SAFETY: `a` is live per the contract; `OPENSSL_sk_value` accepts a NULL stack.
    let val = unsafe { OPENSSL_sk_value((*a).values, ind) }.cast::<OsslIetfAttrSyntaxValue>();
    if val.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `val` is the live element just read.
    let vt = unsafe { (*val).type_ };
    if !type_.is_null() {
        // SAFETY: `type_` is writable per the contract.
        unsafe { *type_ = vt };
    }
    // SAFETY: `val` is live and its union holds a pointer for every selector.
    unsafe {
        match vt {
            OSSL_IETFAS_OCTETS => (*val).u.octets.cast::<c_void>(),
            OSSL_IETFAS_OID => (*val).u.oid.cast::<c_void>(),
            OSSL_IETFAS_STRING => (*val).u.string.cast::<c_void>(),
            _ => ptr::null_mut(),
        }
    }
}

/// `int OSSL_IETF_ATTR_SYNTAX_add1_value(OSSL_IETF_ATTR_SYNTAX *a, int type, void *data)` --
/// `crypto/x509/x_ietfatt.c:142-191`.
///
/// Takes ownership of `data` on success. A NULL `data`, a type differing from the sequence's
/// already-selected one, or an unknown selector is refused (the last two with
/// `ERR_R_PASSED_INVALID_ARGUMENT`); a stack or value allocation failure carries
/// `ERR_R_CRYPTO_LIB`.
///
/// # Safety
///
/// `a` must be a live `OSSL_IETF_ATTR_SYNTAX`; `data` is NULL or a live value this call takes
/// ownership of.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_add1_value(
    a: *mut OsslIetfAttrSyntax,
    type_: c_int,
    data: *mut c_void,
) -> c_int {
    if data.is_null() {
        return 0;
    }
    // SAFETY: `a` is live per the contract; its `values` slot is writable.
    if unsafe { (*a).values }.is_null() {
        // SAFETY: no preconditions.
        let sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
            unsafe { raise_site(&X_IETFATT_189) };
            return 0;
        }
        // SAFETY: `a` is live and its `values`/`type_` slots are writable.
        unsafe {
            (*a).values = sk;
            (*a).type_ = type_;
        }
    }
    // SAFETY: `a` is live.
    if type_ != unsafe { (*a).type_ } {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X_IETFATT_157) };
        return 0;
    }
    // SAFETY: `OSSL_IETF_ATTR_SYNTAX_VALUE_new()` answers a fresh value or NULL.
    let val = OSSL_IETF_ATTR_SYNTAX_VALUE_new();
    if val.is_null() {
        // SAFETY: a compile-time-constant site, exactly as `ERR_raise` is.
        unsafe { raise_site(&X_IETFATT_189) };
        return 0;
    }
    // SAFETY: `val` is this call's own fresh value and its slots are writable.
    unsafe {
        (*val).type_ = type_;
        match type_ {
            OSSL_IETFAS_OCTETS => (*val).u.octets = data.cast::<Asn1String>(),
            OSSL_IETFAS_OID => (*val).u.oid = data.cast::<Asn1Object>(),
            OSSL_IETFAS_STRING => (*val).u.string = data.cast::<Asn1String>(),
            _ => {
                OSSL_IETF_ATTR_SYNTAX_VALUE_free(val);
                raise_site(&X_IETFATT_177);
                return 0;
            }
        }
    }
    // SAFETY: `a` is live and its `values` is a live stack; `val` is this call's own.
    if unsafe { OPENSSL_sk_push((*a).values, val.cast::<c_void>()) } <= 0 {
        // SAFETY: `val` is this call's own and was not stored.
        unsafe { OSSL_IETF_ATTR_SYNTAX_VALUE_free(val) };
        return 0;
    }
    1
}

/// `int OSSL_IETF_ATTR_SYNTAX_print(BIO *bp, OSSL_IETF_ATTR_SYNTAX *a, int indent)` --
/// `crypto/x509/x_ietfatt.c:193-239`.
///
/// Each `policyAuthority` name is printed on its own `indent`-spaced line; each value follows,
/// indented, with an OID rendered through `OBJ_obj2txt` and an octet/UTF-8 string through
/// `ASN1_STRING_print`, and a single trailing newline closes the block. A failed write answers 0.
///
/// # Safety
///
/// `bp` must be a live BIO; `a` must be a live `OSSL_IETF_ATTR_SYNTAX`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_IETF_ATTR_SYNTAX_print(
    bp: *mut Bio,
    a: *mut OsslIetfAttrSyntax,
    indent: c_int,
) -> c_int {
    // SAFETY: `a` is live per the contract.
    let pa = unsafe { (*a).policyAuthority };
    if !pa.is_null() {
        // SAFETY: `pa` is live per the check above.
        let num = unsafe { OPENSSL_sk_num(pa) };
        for i in 0..num {
            // SAFETY: `bp` is live; the format and its arguments are constants.
            if unsafe { BIO_printf(bp, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
                return 0;
            }
            // SAFETY: `pa` is live and `i` is in bounds; the element is a `GENERAL_NAME`.
            let gen =
                unsafe { OPENSSL_sk_value(pa, i) }.cast::<crate::x509::v3_genn::GeneralName>();
            // SAFETY: `bp` and `gen` are live.
            if unsafe { GENERAL_NAME_print(bp, gen) } <= 0 {
                return 0;
            }
            // SAFETY: `bp` is live; the format is a constant.
            if unsafe { BIO_printf(bp, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
    }

    // SAFETY: `a` is live per the contract.
    let num = unsafe { OSSL_IETF_ATTR_SYNTAX_get_value_num(a) };
    for i in 0..num {
        let mut oidstr = [0 as core::ffi::c_char; 80];
        let mut ietf_type: c_int = 0;
        // SAFETY: `a` is live and `ietf_type` is a writable slot.
        let attr_value = unsafe { OSSL_IETF_ATTR_SYNTAX_get0_value(a, i, &raw mut ietf_type) };
        if attr_value.is_null() {
            return 0;
        }
        // SAFETY: `bp` is live; the format and its arguments are constants.
        if unsafe { BIO_printf(bp, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        match ietf_type {
            OSSL_IETFAS_OID => {
                // SAFETY: `oidstr` is an 80-byte writable buffer and `attr_value` is the live OID.
                unsafe {
                    OBJ_obj2txt(
                        oidstr.as_mut_ptr(),
                        oidstr.len() as c_int,
                        attr_value.cast::<Asn1Object>(),
                        0,
                    );
                }
                // SAFETY: `bp` is live; the format and its arguments are constants. The precision
                // is the buffer's size, as the authority's `(int)sizeof(oidstr)` spells it.
                if unsafe {
                    BIO_printf(bp, c"%.*s".as_ptr(), oidstr.len() as c_int, oidstr.as_ptr())
                } <= 0
                {
                    return 0;
                }
            }
            OSSL_IETFAS_OCTETS | OSSL_IETFAS_STRING => {
                // SAFETY: `bp` is live and the value is an `ASN1_STRING`.
                let r = unsafe { ASN1_STRING_print(bp, attr_value.cast::<Asn1String>()) };
                if r <= 0 {
                    return 0;
                }
            }
            _ => {}
        }
    }
    // SAFETY: `bp` is live; the format is a constant.
    if unsafe { BIO_printf(bp, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    1
}
