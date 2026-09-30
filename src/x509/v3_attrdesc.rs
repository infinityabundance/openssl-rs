//! `crypto/x509/v3_attrdesc.c` — the attribute-descriptor item group and its row. Phase 10.14.6's
//! table layer, landed whole.
//!
//! `crypto/x509/v3_attrdesc.c` is 178 lines and transcribes whole:
//!
//! * `OSSL_HASH ::= SEQUENCE { algorithmIdentifier X509_ALGOR, hashValue ASN1_BIT_STRING OPTIONAL }`
//!   (`:15-18`), `OSSL_INFO_SYNTAX_POINTER ::= SEQUENCE { name GENERAL_NAMES, hash OSSL_HASH
//!   OPTIONAL }` (`:20-23`), `OSSL_INFO_SYNTAX ::= CHOICE { content DIRECTORYSTRING, pointer
//!   OSSL_INFO_SYNTAX_POINTER }` (`:25-28`), `OSSL_PRIVILEGE_POLICY_ID ::= SEQUENCE { privilegePolicy
//!   ASN1_OBJECT, privPolSyntax OSSL_INFO_SYNTAX }` (`:30-33`) and `OSSL_ATTRIBUTE_DESCRIPTOR ::=
//!   SEQUENCE { identifier ASN1_OBJECT, attributeSyntax ASN1_OCTET_STRING, name [0] IMPLICIT
//!   ASN1_UTF8STRING OPTIONAL, description [1] IMPLICIT ASN1_UTF8STRING OPTIONAL, dominationRule
//!   OSSL_PRIVILEGE_POLICY_ID }` (`:35-41`). All five end in a non-`static` macro, so each yields
//!   the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group of `IMPLEMENT_ASN1_FUNCTIONS` (`:43-47`).
//! * the five printers [`i2r_HASH`] (`:49-74`), [`i2r_INFO_SYNTAX_POINTER`] (`:76-93`),
//!   [`i2r_OSSL_INFO_SYNTAX`] (`:95-116`), [`i2r_OSSL_PRIVILEGE_POLICY_ID`] (`:118-132`) and
//!   [`i2r_OSSL_ATTRIBUTE_DESCRIPTOR`] (`:134-166`).
//! * the row [`ossl_v3_attribute_descriptor`] (`:168-178`, `NID_attribute_descriptor`).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the array
//! is withheld until all 63 tables exist. This unit contributes one of the 63. The row is internal
//! data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the item group and the
//! printers are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_attrdesc.c` contains no `ERR_raise*`, so no raise coordinate is declared here.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_BIT_STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it,
    DIRECTORYSTRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_attribute_descriptor, OBJ_obj2txt};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::GENERAL_NAMES_it;
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_utl::{ossl_bio_print_hex, OSSL_GENERAL_NAMES_print};
use crate::x509::x_attrib::ossl_print_attribute_value;

/// `OSSL_INFO_SYNTAX_TYPE_CONTENT` — `include/openssl/x509v3.h:1585`.
const OSSL_INFO_SYNTAX_TYPE_CONTENT: c_int = 0;
/// `OSSL_INFO_SYNTAX_TYPE_POINTER` — `include/openssl/x509v3.h:1586`.
const OSSL_INFO_SYNTAX_TYPE_POINTER: c_int = 1;

/// `struct OSSL_HASH_st` — `OSSL_HASH`, from `include/openssl/x509v3.h:1575-1578`.
#[repr(C)]
pub struct OsslHash {
    /// `X509_ALGOR *algorithmIdentifier`.
    pub algorithmIdentifier: *mut X509Algor,
    /// `ASN1_BIT_STRING *hashValue` — optional.
    pub hashValue: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OsslHash>() == 16);
    assert!(core::mem::offset_of!(OsslHash, algorithmIdentifier) == 0);
    assert!(core::mem::offset_of!(OsslHash, hashValue) == 8);
};

/// `struct OSSL_INFO_SYNTAX_POINTER_st` — `OSSL_INFO_SYNTAX_POINTER`, from
/// `include/openssl/x509v3.h:1580-1583`.
#[repr(C)]
pub struct OsslInfoSyntaxPointer {
    /// `GENERAL_NAMES *name`.
    pub name: *mut OpenSslStack,
    /// `OSSL_HASH *hash` — optional.
    pub hash: *mut OsslHash,
}

const _: () = {
    assert!(core::mem::size_of::<OsslInfoSyntaxPointer>() == 16);
    assert!(core::mem::offset_of!(OsslInfoSyntaxPointer, name) == 0);
    assert!(core::mem::offset_of!(OsslInfoSyntaxPointer, hash) == 8);
};

/// The `type`-selected union of `struct OSSL_INFO_SYNTAX_st` — `include/openssl/x509v3.h:1590-1593`.
#[repr(C)]
pub union OsslInfoSyntaxChoice {
    /// `ASN1_STRING *content` — the `DIRECTORYSTRING` arm.
    pub content: *mut Asn1String,
    /// `OSSL_INFO_SYNTAX_POINTER *pointer` — the `OSSL_INFO_SYNTAX_POINTER` arm.
    pub pointer: *mut OsslInfoSyntaxPointer,
}

/// `struct OSSL_INFO_SYNTAX_st` — `OSSL_INFO_SYNTAX`, from `include/openssl/x509v3.h:1588-1594`.
#[repr(C)]
pub struct OsslInfoSyntax {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ... } choice`.
    pub choice: OsslInfoSyntaxChoice,
}

const _: () = {
    assert!(core::mem::size_of::<OsslInfoSyntax>() == 16);
    assert!(core::mem::offset_of!(OsslInfoSyntax, type_) == 0);
    assert!(core::mem::offset_of!(OsslInfoSyntax, choice) == 8);
};

/// `struct OSSL_PRIVILEGE_POLICY_ID_st` — `OSSL_PRIVILEGE_POLICY_ID`, from
/// `include/openssl/x509v3.h:1596-1599`.
#[repr(C)]
pub struct OsslPrivilegePolicyId {
    /// `ASN1_OBJECT *privilegePolicy`.
    pub privilegePolicy: *mut Asn1Object,
    /// `OSSL_INFO_SYNTAX *privPolSyntax`.
    pub privPolSyntax: *mut OsslInfoSyntax,
}

const _: () = {
    assert!(core::mem::size_of::<OsslPrivilegePolicyId>() == 16);
    assert!(core::mem::offset_of!(OsslPrivilegePolicyId, privilegePolicy) == 0);
    assert!(core::mem::offset_of!(OsslPrivilegePolicyId, privPolSyntax) == 8);
};

/// `struct OSSL_ATTRIBUTE_DESCRIPTOR_st` — `OSSL_ATTRIBUTE_DESCRIPTOR`, from
/// `include/openssl/x509v3.h:1601-1607`.
#[repr(C)]
pub struct OsslAttributeDescriptor {
    /// `ASN1_OBJECT *identifier`.
    pub identifier: *mut Asn1Object,
    /// `ASN1_STRING *attributeSyntax`.
    pub attributeSyntax: *mut Asn1String,
    /// `ASN1_UTF8STRING *name` — `[0]` implicit, optional.
    pub name: *mut Asn1String,
    /// `ASN1_UTF8STRING *description` — `[1]` implicit, optional.
    pub description: *mut Asn1String,
    /// `OSSL_PRIVILEGE_POLICY_ID *dominationRule`.
    pub dominationRule: *mut OsslPrivilegePolicyId,
}

const _: () = {
    assert!(core::mem::size_of::<OsslAttributeDescriptor>() == 40);
    assert!(core::mem::offset_of!(OsslAttributeDescriptor, identifier) == 0);
    assert!(core::mem::offset_of!(OsslAttributeDescriptor, attributeSyntax) == 8);
    assert!(core::mem::offset_of!(OsslAttributeDescriptor, name) == 16);
    assert!(core::mem::offset_of!(OsslAttributeDescriptor, description) == 24);
    assert!(core::mem::offset_of!(OsslAttributeDescriptor, dominationRule) == 32);
};

/// `OSSL_HASH_seq_tt` — `ASN1_SEQUENCE(OSSL_HASH)` (`crypto/x509/v3_attrdesc.c:15-17`):
/// `ASN1_SIMPLE(OSSL_HASH, algorithmIdentifier, X509_ALGOR)` and
/// `ASN1_OPT(OSSL_HASH, hashValue, ASN1_BIT_STRING)`.
static OSSL_HASH_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algorithmIdentifier".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"hashValue".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `OSSL_HASH_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_HASH)` at `crypto/x509/v3_attrdesc.c:18`.
static OSSL_HASH_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_HASH_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslHash>() as c_long,
    sname: c"OSSL_HASH".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_HASH_it(void)` — `include/openssl/x509v3.h:1609`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_HASH)`.
#[no_mangle]
pub extern "C" fn OSSL_HASH_it() -> *const Asn1Item {
    &OSSL_HASH_ITEM
}

/// `OSSL_HASH *OSSL_HASH_new(void)` — `crypto/x509/v3_attrdesc.c:43`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_HASH)`.
#[no_mangle]
pub extern "C" fn OSSL_HASH_new() -> *mut OsslHash {
    // SAFETY: `OSSL_HASH_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_HASH_it()).cast::<OsslHash>() }
}

/// `void OSSL_HASH_free(OSSL_HASH *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_HASH_free(a: *mut OsslHash) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_HASH_it()) }
}

/// `OSSL_HASH *d2i_OSSL_HASH(OSSL_HASH **a, const unsigned char **in, long len)` — the same macro's
/// decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_HASH(
    a: *mut *mut OsslHash,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslHash {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_HASH_it()).cast::<OsslHash>() }
}

/// `int i2d_OSSL_HASH(const OSSL_HASH *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_HASH(a: *const OsslHash, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_HASH_it()) }
}

/// `OSSL_INFO_SYNTAX_POINTER_seq_tt` — `ASN1_SEQUENCE(OSSL_INFO_SYNTAX_POINTER)`
/// (`crypto/x509/v3_attrdesc.c:20-22`): `ASN1_SIMPLE(..., name, GENERAL_NAMES)` and
/// `ASN1_OPT(..., hash, OSSL_HASH)`.
static OSSL_INFO_SYNTAX_POINTER_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"name".as_ptr(),
        item: GENERAL_NAMES_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"hash".as_ptr(),
        item: OSSL_HASH_it as *mut c_void,
    },
];

/// `OSSL_INFO_SYNTAX_POINTER_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_INFO_SYNTAX_POINTER)` at
/// `crypto/x509/v3_attrdesc.c:23`.
static OSSL_INFO_SYNTAX_POINTER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_INFO_SYNTAX_POINTER_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslInfoSyntaxPointer>() as c_long,
    sname: c"OSSL_INFO_SYNTAX_POINTER".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_INFO_SYNTAX_POINTER_it(void)` — `include/openssl/x509v3.h:1611`.
#[no_mangle]
pub extern "C" fn OSSL_INFO_SYNTAX_POINTER_it() -> *const Asn1Item {
    &OSSL_INFO_SYNTAX_POINTER_ITEM
}

/// `OSSL_INFO_SYNTAX_POINTER *OSSL_INFO_SYNTAX_POINTER_new(void)` —
/// `crypto/x509/v3_attrdesc.c:45`, from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_INFO_SYNTAX_POINTER)`.
#[no_mangle]
pub extern "C" fn OSSL_INFO_SYNTAX_POINTER_new() -> *mut OsslInfoSyntaxPointer {
    // SAFETY: `OSSL_INFO_SYNTAX_POINTER_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_INFO_SYNTAX_POINTER_it()).cast::<OsslInfoSyntaxPointer>() }
}

/// `void OSSL_INFO_SYNTAX_POINTER_free(OSSL_INFO_SYNTAX_POINTER *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_INFO_SYNTAX_POINTER_free(a: *mut OsslInfoSyntaxPointer) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_INFO_SYNTAX_POINTER_it()) }
}

/// `OSSL_INFO_SYNTAX_POINTER *d2i_OSSL_INFO_SYNTAX_POINTER(OSSL_INFO_SYNTAX_POINTER **a, const
/// unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_INFO_SYNTAX_POINTER(
    a: *mut *mut OsslInfoSyntaxPointer,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslInfoSyntaxPointer {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_INFO_SYNTAX_POINTER_it())
            .cast::<OsslInfoSyntaxPointer>()
    }
}

/// `int i2d_OSSL_INFO_SYNTAX_POINTER(const OSSL_INFO_SYNTAX_POINTER *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_INFO_SYNTAX_POINTER(
    a: *const OsslInfoSyntaxPointer,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_INFO_SYNTAX_POINTER_it()) }
}

/// `OSSL_INFO_SYNTAX_ch_tt` — `ASN1_CHOICE(OSSL_INFO_SYNTAX)` (`crypto/x509/v3_attrdesc.c:25-28`):
/// `ASN1_SIMPLE(..., choice.content, DIRECTORYSTRING)` and
/// `ASN1_SIMPLE(..., choice.pointer, OSSL_INFO_SYNTAX_POINTER)`. Both arms live at the union's
/// offset, 8.
static OSSL_INFO_SYNTAX_CH_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.content".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"choice.pointer".as_ptr(),
        item: OSSL_INFO_SYNTAX_POINTER_it as *mut c_void,
    },
];

/// `OSSL_INFO_SYNTAX_it`'s descriptor — `ASN1_CHOICE_END(OSSL_INFO_SYNTAX)` at
/// `crypto/x509/v3_attrdesc.c:28`. The `utype` of a `CHOICE` is the selector's offset.
static OSSL_INFO_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OsslInfoSyntax, type_) as c_long,
    templates: OSSL_INFO_SYNTAX_CH_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslInfoSyntax>() as c_long,
    sname: c"OSSL_INFO_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_INFO_SYNTAX_it(void)` — `include/openssl/x509v3.h:1610`.
#[no_mangle]
pub extern "C" fn OSSL_INFO_SYNTAX_it() -> *const Asn1Item {
    &OSSL_INFO_SYNTAX_ITEM
}

/// `OSSL_INFO_SYNTAX *OSSL_INFO_SYNTAX_new(void)` — `crypto/x509/v3_attrdesc.c:44`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_INFO_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_INFO_SYNTAX_new() -> *mut OsslInfoSyntax {
    // SAFETY: `OSSL_INFO_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_INFO_SYNTAX_it()).cast::<OsslInfoSyntax>() }
}

/// `void OSSL_INFO_SYNTAX_free(OSSL_INFO_SYNTAX *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_INFO_SYNTAX_free(a: *mut OsslInfoSyntax) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_INFO_SYNTAX_it()) }
}

/// `OSSL_INFO_SYNTAX *d2i_OSSL_INFO_SYNTAX(OSSL_INFO_SYNTAX **a, const unsigned char **in, long
/// len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_INFO_SYNTAX(
    a: *mut *mut OsslInfoSyntax,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslInfoSyntax {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_INFO_SYNTAX_it()).cast::<OsslInfoSyntax>() }
}

/// `int i2d_OSSL_INFO_SYNTAX(const OSSL_INFO_SYNTAX *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_INFO_SYNTAX(
    a: *const OsslInfoSyntax,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_INFO_SYNTAX_it()) }
}

/// `OSSL_PRIVILEGE_POLICY_ID_seq_tt` — `ASN1_SEQUENCE(OSSL_PRIVILEGE_POLICY_ID)`
/// (`crypto/x509/v3_attrdesc.c:30-33`): `ASN1_SIMPLE(..., privilegePolicy, ASN1_OBJECT)` and
/// `ASN1_SIMPLE(..., privPolSyntax, OSSL_INFO_SYNTAX)`.
static OSSL_PRIVILEGE_POLICY_ID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"privilegePolicy".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"privPolSyntax".as_ptr(),
        item: OSSL_INFO_SYNTAX_it as *mut c_void,
    },
];

/// `OSSL_PRIVILEGE_POLICY_ID_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_PRIVILEGE_POLICY_ID)` at
/// `crypto/x509/v3_attrdesc.c:33`.
static OSSL_PRIVILEGE_POLICY_ID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_PRIVILEGE_POLICY_ID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslPrivilegePolicyId>() as c_long,
    sname: c"OSSL_PRIVILEGE_POLICY_ID".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_PRIVILEGE_POLICY_ID_it(void)` — `include/openssl/x509v3.h:1612`.
#[no_mangle]
pub extern "C" fn OSSL_PRIVILEGE_POLICY_ID_it() -> *const Asn1Item {
    &OSSL_PRIVILEGE_POLICY_ID_ITEM
}

/// `OSSL_PRIVILEGE_POLICY_ID *OSSL_PRIVILEGE_POLICY_ID_new(void)` — `crypto/x509/v3_attrdesc.c:46`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_PRIVILEGE_POLICY_ID)`.
#[no_mangle]
pub extern "C" fn OSSL_PRIVILEGE_POLICY_ID_new() -> *mut OsslPrivilegePolicyId {
    // SAFETY: `OSSL_PRIVILEGE_POLICY_ID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_PRIVILEGE_POLICY_ID_it()).cast::<OsslPrivilegePolicyId>() }
}

/// `void OSSL_PRIVILEGE_POLICY_ID_free(OSSL_PRIVILEGE_POLICY_ID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_PRIVILEGE_POLICY_ID_free(a: *mut OsslPrivilegePolicyId) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_PRIVILEGE_POLICY_ID_it()) }
}

/// `OSSL_PRIVILEGE_POLICY_ID *d2i_OSSL_PRIVILEGE_POLICY_ID(OSSL_PRIVILEGE_POLICY_ID **a, const
/// unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_PRIVILEGE_POLICY_ID(
    a: *mut *mut OsslPrivilegePolicyId,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslPrivilegePolicyId {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_PRIVILEGE_POLICY_ID_it())
            .cast::<OsslPrivilegePolicyId>()
    }
}

/// `int i2d_OSSL_PRIVILEGE_POLICY_ID(const OSSL_PRIVILEGE_POLICY_ID *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_PRIVILEGE_POLICY_ID(
    a: *const OsslPrivilegePolicyId,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_PRIVILEGE_POLICY_ID_it()) }
}

/// `OSSL_ATTRIBUTE_DESCRIPTOR_seq_tt` — `ASN1_SEQUENCE(OSSL_ATTRIBUTE_DESCRIPTOR)`
/// (`crypto/x509/v3_attrdesc.c:35-41`): `ASN1_SIMPLE(..., identifier, ASN1_OBJECT)`,
/// `ASN1_SIMPLE(..., attributeSyntax, ASN1_OCTET_STRING)`,
/// `ASN1_IMP_OPT(..., name, ASN1_UTF8STRING, 0)`,
/// `ASN1_IMP_OPT(..., description, ASN1_UTF8STRING, 1)` and
/// `ASN1_SIMPLE(..., dominationRule, OSSL_PRIVILEGE_POLICY_ID)`.
static OSSL_ATTRIBUTE_DESCRIPTOR_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"identifier".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"attributeSyntax".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"name".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 24,
        field_name: c"description".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"dominationRule".as_ptr(),
        item: OSSL_PRIVILEGE_POLICY_ID_it as *mut c_void,
    },
];

/// `OSSL_ATTRIBUTE_DESCRIPTOR_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ATTRIBUTE_DESCRIPTOR)` at
/// `crypto/x509/v3_attrdesc.c:41`.
static OSSL_ATTRIBUTE_DESCRIPTOR_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ATTRIBUTE_DESCRIPTOR_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslAttributeDescriptor>() as c_long,
    sname: c"OSSL_ATTRIBUTE_DESCRIPTOR".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ATTRIBUTE_DESCRIPTOR_it(void)` — `include/openssl/x509v3.h:1613`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_it() -> *const Asn1Item {
    &OSSL_ATTRIBUTE_DESCRIPTOR_ITEM
}

/// `OSSL_ATTRIBUTE_DESCRIPTOR *OSSL_ATTRIBUTE_DESCRIPTOR_new(void)` — `crypto/x509/v3_attrdesc.c:47`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ATTRIBUTE_DESCRIPTOR)`.
#[no_mangle]
pub extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_new() -> *mut OsslAttributeDescriptor {
    // SAFETY: `OSSL_ATTRIBUTE_DESCRIPTOR_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ATTRIBUTE_DESCRIPTOR_it()).cast::<OsslAttributeDescriptor>() }
}

/// `void OSSL_ATTRIBUTE_DESCRIPTOR_free(OSSL_ATTRIBUTE_DESCRIPTOR *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ATTRIBUTE_DESCRIPTOR_free(a: *mut OsslAttributeDescriptor) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ATTRIBUTE_DESCRIPTOR_it()) }
}

/// `OSSL_ATTRIBUTE_DESCRIPTOR *d2i_OSSL_ATTRIBUTE_DESCRIPTOR(OSSL_ATTRIBUTE_DESCRIPTOR **a, const
/// unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ATTRIBUTE_DESCRIPTOR(
    a: *mut *mut OsslAttributeDescriptor,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslAttributeDescriptor {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ATTRIBUTE_DESCRIPTOR_it())
            .cast::<OsslAttributeDescriptor>()
    }
}

/// `int i2d_OSSL_ATTRIBUTE_DESCRIPTOR(const OSSL_ATTRIBUTE_DESCRIPTOR *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ATTRIBUTE_DESCRIPTOR(
    a: *const OsslAttributeDescriptor,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ATTRIBUTE_DESCRIPTOR_it()) }
}

// ---------------------------------------------------------------------------------------------
// The five printers (`:49-166`)
// ---------------------------------------------------------------------------------------------

/// `static int i2r_HASH(X509V3_EXT_METHOD *method, OSSL_HASH *hash, BIO *out, int indent)` —
/// `crypto/x509/v3_attrdesc.c:49-74`.
///
/// # Safety
///
/// `out` is a live BIO; `hash` is a live `OSSL_HASH`.
unsafe extern "C" fn i2r_HASH(
    _method: *const X509V3ExtMethod,
    hash: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let hash = hash.cast::<OsslHash>();
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_printf(out, c"%*sAlgorithm: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live and `hash`'s algorithm is live.
    if unsafe { i2a_ASN1_OBJECT(out, (*(*hash).algorithmIdentifier).algorithm) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `hash` is live.
    if !unsafe { (*(*hash).algorithmIdentifier).parameter }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_printf(out, c"%*sParameter: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `hash`'s parameter is a live `ASN1_TYPE`.
        if unsafe {
            ossl_print_attribute_value(out, 0, (*(*hash).algorithmIdentifier).parameter, indent + 4)
        } <= 0
        {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_printf(out, c"%*sHash Value: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `hash` is live.
    if unsafe { (*hash).hashValue }.is_null() {
        return 0;
    }
    // SAFETY: `out` is live; `hash`'s `hashValue` is a live bit string whose `data` is readable
    // for `length` bytes.
    unsafe {
        ossl_bio_print_hex(
            out,
            (*((*hash).hashValue)).data,
            (*((*hash).hashValue)).length,
        )
    }
}

/// `static int i2r_INFO_SYNTAX_POINTER(X509V3_EXT_METHOD *method, OSSL_INFO_SYNTAX_POINTER *pointer,
/// BIO *out, int indent)` — `crypto/x509/v3_attrdesc.c:76-93`.
///
/// # Safety
///
/// `out` is a live BIO; `pointer` is a live `OSSL_INFO_SYNTAX_POINTER`.
unsafe extern "C" fn i2r_INFO_SYNTAX_POINTER(
    method: *const X509V3ExtMethod,
    pointer: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let pointer = pointer.cast::<OsslInfoSyntaxPointer>();
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_printf(out, c"%*sNames:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live and `pointer`'s `name` is a live `GENERAL_NAMES`.
    if unsafe { OSSL_GENERAL_NAMES_print(out, (*pointer).name, indent) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `pointer` is live.
    if !unsafe { (*pointer).hash }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_printf(out, c"%*sHash:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live and `pointer`'s `hash` is live.
        if unsafe { i2r_HASH(method, (*pointer).hash.cast::<c_void>(), out, indent + 4) } <= 0 {
            return 0;
        }
    }
    1
}

/// `static int i2r_OSSL_INFO_SYNTAX(X509V3_EXT_METHOD *method, OSSL_INFO_SYNTAX *info, BIO *out,
/// int indent)` — `crypto/x509/v3_attrdesc.c:95-116`.
///
/// # Safety
///
/// `out` is a live BIO; `info` is a live `OSSL_INFO_SYNTAX`.
unsafe extern "C" fn i2r_OSSL_INFO_SYNTAX(
    method: *const X509V3ExtMethod,
    info: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let info = info.cast::<OsslInfoSyntax>();
    // SAFETY: `info` is live.
    let type_ = unsafe { (*info).type_ };
    if type_ == OSSL_INFO_SYNTAX_TYPE_CONTENT {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_printf(out, c"%*sContent: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `info`'s selector selects the live `content` string; `out` is live.
        if unsafe {
            BIO_printf(
                out,
                c"%.*s".as_ptr(),
                (*(*info).choice.content).length,
                (*(*info).choice.content).data.cast::<c_char>(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        return 1;
    }
    if type_ == OSSL_INFO_SYNTAX_TYPE_POINTER {
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_printf(out, c"%*sPointer:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `info`'s selector selects the live `pointer` arm; `out` is live.
        return unsafe {
            i2r_INFO_SYNTAX_POINTER(
                method,
                (*info).choice.pointer.cast::<c_void>(),
                out,
                indent + 4,
            )
        };
    }
    0
}

/// `static int i2r_OSSL_PRIVILEGE_POLICY_ID(X509V3_EXT_METHOD *method, OSSL_PRIVILEGE_POLICY_ID
/// *ppid, BIO *out, int indent)` — `crypto/x509/v3_attrdesc.c:118-132`.
///
/// # Safety
///
/// `out` is a live BIO; `ppid` is a live `OSSL_PRIVILEGE_POLICY_ID`.
unsafe extern "C" fn i2r_OSSL_PRIVILEGE_POLICY_ID(
    method: *const X509V3ExtMethod,
    ppid: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let mut buf = [0 as c_char; 80];
    let ppid = ppid.cast::<OsslPrivilegePolicyId>();

    // Intentionally display the numeric OID, rather than the textual name.
    // SAFETY: `buf` is 80 writable bytes; `ppid`'s object is live.
    if unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 80, (*ppid).privilegePolicy, 1) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; `buf` is NUL-terminated and the literals are static.
    if unsafe {
        BIO_printf(
            out,
            c"%*sPrivilege Policy Identifier: %s\n".as_ptr(),
            indent,
            c"".as_ptr(),
            buf.as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe {
        BIO_printf(
            out,
            c"%*sPrivilege Policy Syntax:\n".as_ptr(),
            indent,
            c"".as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `out` is live and `ppid`'s `privPolSyntax` is live.
    unsafe {
        i2r_OSSL_INFO_SYNTAX(
            method,
            (*ppid).privPolSyntax.cast::<c_void>(),
            out,
            indent + 4,
        )
    }
}

/// `static int i2r_OSSL_ATTRIBUTE_DESCRIPTOR(X509V3_EXT_METHOD *method, OSSL_ATTRIBUTE_DESCRIPTOR
/// *ad, BIO *out, int indent)` — `crypto/x509/v3_attrdesc.c:134-166`.
///
/// # Safety
///
/// `out` is a live BIO; `ad` is a live `OSSL_ATTRIBUTE_DESCRIPTOR`.
unsafe extern "C" fn i2r_OSSL_ATTRIBUTE_DESCRIPTOR(
    method: *const X509V3ExtMethod,
    ad: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let mut buf = [0 as c_char; 80];
    let ad = ad.cast::<OsslAttributeDescriptor>();

    // Intentionally display the numeric OID, rather than the textual name.
    // SAFETY: `buf` is 80 writable bytes; `ad`'s object is live.
    if unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 80, (*ad).identifier, 1) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; `buf` is NUL-terminated and the literals are static.
    if unsafe {
        BIO_printf(
            out,
            c"%*sIdentifier: %s\n".as_ptr(),
            indent,
            c"".as_ptr(),
            buf.as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_printf(out, c"%*sSyntax:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live and `ad`'s `attributeSyntax` is a live string.
    if unsafe {
        BIO_printf(
            out,
            c"%*s%.*s".as_ptr(),
            indent + 4,
            c"".as_ptr(),
            (*(*ad).attributeSyntax).length,
            (*(*ad).attributeSyntax).data.cast::<c_char>(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_puts(out, c"\n\n".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `ad` is live.
    if !unsafe { (*ad).name }.is_null() {
        // SAFETY: `out` is live; `ad`'s `name` is a live string and the literal is static.
        if unsafe {
            BIO_printf(
                out,
                c"%*sName: %.*s\n".as_ptr(),
                indent,
                c"".as_ptr(),
                (*(*ad).name).length,
                (*(*ad).name).data.cast::<c_char>(),
            )
        } <= 0
        {
            return 0;
        }
    }
    // SAFETY: `ad` is live.
    if !unsafe { (*ad).description }.is_null() {
        // SAFETY: `out` is live; `ad`'s `description` is a live string and the literal is static.
        if unsafe {
            BIO_printf(
                out,
                c"%*sDescription: %.*s\n".as_ptr(),
                indent,
                c"".as_ptr(),
                (*(*ad).description).length,
                (*(*ad).description).data.cast::<c_char>(),
            )
        } <= 0
        {
            return 0;
        }
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_printf(out, c"%*sDomination Rule:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live and `ad`'s `dominationRule` is live.
    unsafe {
        i2r_OSSL_PRIVILEGE_POLICY_ID(
            method,
            (*ad).dominationRule.cast::<c_void>(),
            out,
            indent + 4,
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_attribute_descriptor` — `crypto/x509/v3_attrdesc.c:168-178`.
///
/// `NID_attribute_descriptor`, `X509V3_EXT_MULTILINE`, item [`OSSL_ATTRIBUTE_DESCRIPTOR_it`] and the
/// [`i2r_OSSL_ATTRIBUTE_DESCRIPTOR`] printer.
pub static ossl_v3_attribute_descriptor: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_attribute_descriptor,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(OSSL_ATTRIBUTE_DESCRIPTOR_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_OSSL_ATTRIBUTE_DESCRIPTOR),
    r2i: None,
    usr_data: ptr::null_mut(),
};
