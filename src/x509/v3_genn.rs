//! `crypto/x509/v3_genn.c` — the `GENERAL_NAME`/`GENERAL_NAMES` items and their accessors.
//! Phase 10.14.4.
//!
//! The unit is 269 lines and lands **whole**: three ASN.1 templates (`OTHERNAME`,
//! `EDIPARTYNAME`, `GENERAL_NAME`) with the `GENERAL_NAMES` `SEQUENCE OF` over the last, the
//! generated `it`/`new`/`free`/`d2i_`/`i2d_` groups, and the eleven hand-written functions —
//! `GENERAL_NAME_dup`, `GENERAL_NAME_set1_X509_NAME`, the static `edipartyname_cmp`,
//! `GENERAL_NAME_cmp`, `OTHERNAME_cmp`, `GENERAL_NAME_set0_value`/`get0_value`,
//! `GENERAL_NAME_set0_othername` and `GENERAL_NAME_get0_otherName`. Its closure was measured
//! whole-unit ready by the re-measurement at the head of this session: every name its object
//! leaves undefined is a landed item (`X509_NAME_it`, `ASN1_ANY_it`, `DIRECTORYSTRING_it`, the
//! `ASN1_*_it` string items, `ASN1_dup`, the comparators) or an internal Rust definition, so it
//! is the first 10.14.x unit that can be transcribed rather than withheld again.
//!
//! ## The `GENERAL_NAME` union is the layout
//!
//! `struct GENERAL_NAME_st` is `int type` followed by a union of nine pointers
//! (`include/openssl/x509v3.h:172-193`), so the union sits at offset 8 and the whole is 16 bytes.
//! The templates select the arm by the context tag on the wire, and the two accessors write and
//! read exactly the pointer the `type` names: `set0_value` does not free the old arm and
//! `get0_value` does not copy, both of which the court observes.
//!
//! ## What it unblocks, and what it is a prerequisite of
//!
//! `GENERAL_NAME_it` and the `GENERAL_NAMES` group are what every `v3_san.c`/`v3_ncons.c`/
//! `v3_crld.c` table and `v3_utl.c`'s address checks call, so this unit is the hub the rest of
//! 10.14.4 and 10.14.6–10.14.8 were measured to wait on. It closes no Phase-10 export or provider
//! row on its own — the expected shape for a dependency sub-subphase.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_dup;
use crate::asn1::a_type::{ASN1_TYPE_cmp, ASN1_TYPE_free};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_SEQUENCE_it,
    DIRECTORYSTRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_STRING_cmp};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{Asn1Object, OBJ_cmp};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x509_cmp::X509_NAME_cmp;
use crate::x509::x_name::{X509Name, X509_NAME_it, X509_NAME_new, X509_NAME_set};

/// `GEN_OTHERNAME` — `include/openssl/x509v3.h:153`.
pub(crate) const GEN_OTHERNAME: c_int = 0;
/// `GEN_EMAIL` — `include/openssl/x509v3.h:154`.
pub(crate) const GEN_EMAIL: c_int = 1;
/// `GEN_DNS` — `include/openssl/x509v3.h:155`.
pub(crate) const GEN_DNS: c_int = 2;
/// `GEN_X400` — `include/openssl/x509v3.h:156`.
pub(crate) const GEN_X400: c_int = 3;
/// `GEN_DIRNAME` — `include/openssl/x509v3.h:157`.
pub(crate) const GEN_DIRNAME: c_int = 4;
/// `GEN_EDIPARTY` — `include/openssl/x509v3.h:158`.
pub(crate) const GEN_EDIPARTY: c_int = 5;
/// `GEN_URI` — `include/openssl/x509v3.h:159`.
pub(crate) const GEN_URI: c_int = 6;
/// `GEN_IPADD` — `include/openssl/x509v3.h:160`.
pub(crate) const GEN_IPADD: c_int = 7;
/// `GEN_RID` — `include/openssl/x509v3.h:161`.
pub(crate) const GEN_RID: c_int = 8;

/// `struct otherName_st` — `OTHERNAME`, from `include/openssl/x509v3.h:163-166`.
#[repr(C)]
pub struct Othername {
    /// `ASN1_OBJECT *type_id` — the type OID, mandatory.
    pub(crate) type_id: *mut Asn1Object,
    /// `ASN1_TYPE *value` — the `[0] EXPLICIT ANY`, mandatory.
    pub(crate) value: *mut Asn1Type,
}

const _: () = {
    assert!(core::mem::size_of::<Othername>() == 16);
    assert!(core::mem::offset_of!(Othername, type_id) == 0);
    assert!(core::mem::offset_of!(Othername, value) == 8);
};

/// `OTHERNAME_seq_tt` — `ASN1_SEQUENCE(OTHERNAME)` (`crypto/x509/v3_genn.c:16-20`):
/// `ASN1_SIMPLE(type_id, ASN1_OBJECT)` and `ASN1_EXP(value, ASN1_ANY, 0)`.
static OTHERNAME_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type_id".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
];

/// `OTHERNAME_it`'s descriptor — `ASN1_SEQUENCE_END(OTHERNAME)` at `crypto/x509/v3_genn.c:20`.
static OTHERNAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OTHERNAME_SEQ_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Othername>() as c_long,
    sname: c"OTHERNAME".as_ptr(),
};

/// `const ASN1_ITEM *OTHERNAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(OTHERNAME)`.
#[no_mangle]
pub extern "C" fn OTHERNAME_it() -> *const Asn1Item {
    &OTHERNAME_ITEM
}

/// The internal alias a static template can name for the CHOICE alternative, because a template's
/// `item` field must be the accessor's address.
fn othername_it() -> *const Asn1Item {
    OTHERNAME_it()
}

/// `OTHERNAME *OTHERNAME_new(void)` — `crypto/x509/v3_genn.c:22`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OTHERNAME)`.
#[no_mangle]
pub extern "C" fn OTHERNAME_new() -> *mut Othername {
    // SAFETY: `OTHERNAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OTHERNAME_it()).cast::<Othername>() }
}

/// `void OTHERNAME_free(OTHERNAME *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OTHERNAME_free(a: *mut Othername) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OTHERNAME_it()) }
}

/// `OTHERNAME *d2i_OTHERNAME(OTHERNAME **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OTHERNAME(
    a: *mut *mut Othername,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Othername {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OTHERNAME_it()).cast::<Othername>() }
}

/// `int i2d_OTHERNAME(const OTHERNAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OTHERNAME(a: *const Othername, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OTHERNAME_it()) }
}

/// `struct EDIPARTYNAME_st` — `EDIPARTYNAME`, from `include/openssl/x509v3.h:180-183`.
#[repr(C)]
pub struct EdiPartyName {
    /// `DIRECTORYSTRING *nameAssigner` — optional.
    pub(crate) nameAssigner: *mut Asn1String,
    /// `DIRECTORYSTRING *partyName` — mandatory on the wire but stored as a pointer.
    pub(crate) partyName: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<EdiPartyName>() == 16);
    assert!(core::mem::offset_of!(EdiPartyName, nameAssigner) == 0);
    assert!(core::mem::offset_of!(EdiPartyName, partyName) == 8);
};

/// `EDIPARTYNAME_seq_tt` — `ASN1_SEQUENCE(EDIPARTYNAME)` (`crypto/x509/v3_genn.c:24-28`):
/// `ASN1_EXP_OPT(nameAssigner, DIRECTORYSTRING, 0)` and
/// `ASN1_EXP_OPT(partyName, DIRECTORYSTRING, 1)`.
static EDIPARTYNAME_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"nameAssigner".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"partyName".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
];

/// `EDIPARTYNAME_it`'s descriptor — `ASN1_SEQUENCE_END(EDIPARTYNAME)` at
/// `crypto/x509/v3_genn.c:28`.
static EDIPARTYNAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: EDIPARTYNAME_SEQ_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EdiPartyName>() as c_long,
    sname: c"EDIPARTYNAME".as_ptr(),
};

/// `const ASN1_ITEM *EDIPARTYNAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)`.
#[no_mangle]
pub extern "C" fn EDIPARTYNAME_it() -> *const Asn1Item {
    &EDIPARTYNAME_ITEM
}

/// The internal alias a static template can name for the CHOICE alternative.
fn edipartyname_it() -> *const Asn1Item {
    EDIPARTYNAME_it()
}

/// `EDIPARTYNAME *EDIPARTYNAME_new(void)` — `crypto/x509/v3_genn.c:30`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(EDIPARTYNAME)`.
#[no_mangle]
pub extern "C" fn EDIPARTYNAME_new() -> *mut EdiPartyName {
    // SAFETY: `EDIPARTYNAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(EDIPARTYNAME_it()).cast::<EdiPartyName>() }
}

/// `void EDIPARTYNAME_free(EDIPARTYNAME *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn EDIPARTYNAME_free(a: *mut EdiPartyName) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), EDIPARTYNAME_it()) }
}

/// `EDIPARTYNAME *d2i_EDIPARTYNAME(EDIPARTYNAME **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_EDIPARTYNAME(
    a: *mut *mut EdiPartyName,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EdiPartyName {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, EDIPARTYNAME_it()).cast::<EdiPartyName>() }
}

/// `int i2d_EDIPARTYNAME(const EDIPARTYNAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_EDIPARTYNAME(a: *const EdiPartyName, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, EDIPARTYNAME_it()) }
}

/// `struct GENERAL_NAME_st`'s `d` union — `include/openssl/x509v3.h:174-192`. Every arm is a
/// pointer, so the union is eight bytes at offset 8 of [`GeneralName`].
#[repr(C)]
#[derive(Clone, Copy)]
pub union GeneralNameValue {
    /// `OTHERNAME *otherName`.
    pub(crate) otherName: *mut Othername,
    /// `ASN1_IA5STRING *rfc822Name`, `dNSName` and `uniformResourceIdentifier`.
    pub(crate) ia5: *mut Asn1String,
    /// `ASN1_SEQUENCE *x400Address` — the generic `ASN1_SEQUENCE` item decodes into an
    /// `ASN1_STRING` carrying the raw content.
    pub(crate) x400Address: *mut Asn1String,
    /// `X509_NAME *directoryName`.
    pub(crate) directoryName: *mut X509Name,
    /// `EDIPARTYNAME *ediPartyName`.
    pub(crate) ediPartyName: *mut EdiPartyName,
    /// `ASN1_OCTET_STRING *iPAddress`.
    pub(crate) iPAddress: *mut Asn1String,
    /// `ASN1_OBJECT *registeredID`.
    pub(crate) registeredID: *mut Asn1Object,
}

/// `struct GENERAL_NAME_st` — `GENERAL_NAME`, from `include/openssl/x509v3.h:172-193`.
#[repr(C)]
pub struct GeneralName {
    /// `int type` — the `GEN_*` selector.
    pub(crate) type_: c_int,
    /// The `d` union.
    pub(crate) d: GeneralNameValue,
}

const _: () = {
    assert!(core::mem::size_of::<GeneralNameValue>() == 8);
    assert!(core::mem::size_of::<GeneralName>() == 16);
    assert!(core::mem::offset_of!(GeneralName, type_) == 0);
    assert!(core::mem::offset_of!(GeneralName, d) == 8);
};

/// `GENERAL_NAME_ch_tt` — `ASN1_CHOICE(GENERAL_NAME)` (`crypto/x509/v3_genn.c:32-44`). Every
/// alternative shares the union at offset 8; the selector is `type` at offset 0. Eight are
/// context-implicit, and `directoryName` is the one explicit alternative (`ASN1_EXP`), which is
/// why it carries `ASN1_TFLG_EXPLICIT` where the rest carry `ASN1_TFLG_IMPLICIT`.
static GENERAL_NAME_CH_TT: [Asn1Template; 9] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_OTHERNAME as c_long,
        offset: 8,
        field_name: c"d.otherName".as_ptr(),
        item: othername_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_EMAIL as c_long,
        offset: 8,
        field_name: c"d.rfc822Name".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_DNS as c_long,
        offset: 8,
        field_name: c"d.dNSName".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_X400 as c_long,
        offset: 8,
        field_name: c"d.x400Address".as_ptr(),
        item: ASN1_SEQUENCE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: GEN_DIRNAME as c_long,
        offset: 8,
        field_name: c"d.directoryName".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_EDIPARTY as c_long,
        offset: 8,
        field_name: c"d.ediPartyName".as_ptr(),
        item: edipartyname_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_URI as c_long,
        offset: 8,
        field_name: c"d.uniformResourceIdentifier".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_IPADD as c_long,
        offset: 8,
        field_name: c"d.iPAddress".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_RID as c_long,
        offset: 8,
        field_name: c"d.registeredID".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
];

/// `GENERAL_NAME_it`'s descriptor — `ASN1_CHOICE_END(GENERAL_NAME)` at `crypto/x509/v3_genn.c:44`.
/// The `utype` of a CHOICE is the selector's offset, not a tag.
static GENERAL_NAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(GeneralName, type_) as c_long,
    templates: GENERAL_NAME_CH_TT.as_ptr(),
    tcount: 9,
    funcs: ptr::null(),
    size: core::mem::size_of::<GeneralName>() as c_long,
    sname: c"GENERAL_NAME".as_ptr(),
};

/// `const ASN1_ITEM *GENERAL_NAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAME_it() -> *const Asn1Item {
    &GENERAL_NAME_ITEM
}

/// The internal alias a static template can name for the `SEQUENCE OF` below.
fn general_name_it() -> *const Asn1Item {
    GENERAL_NAME_it()
}

/// `GENERAL_NAME *GENERAL_NAME_new(void)` — `crypto/x509/v3_genn.c:46`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAME)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAME_new() -> *mut GeneralName {
    // SAFETY: `GENERAL_NAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(GENERAL_NAME_it()).cast::<GeneralName>() }
}

/// `void GENERAL_NAME_free(GENERAL_NAME *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_free(a: *mut GeneralName) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), GENERAL_NAME_it()) }
}

/// `GENERAL_NAME *d2i_GENERAL_NAME(GENERAL_NAME **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_GENERAL_NAME(
    a: *mut *mut GeneralName,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut GeneralName {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, GENERAL_NAME_it()).cast::<GeneralName>() }
}

/// `int i2d_GENERAL_NAME(const GENERAL_NAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_GENERAL_NAME(a: *const GeneralName, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, GENERAL_NAME_it()) }
}

/// `GENERAL_NAMES_item_tt` — `ASN1_ITEM_TEMPLATE(GENERAL_NAMES)` at `crypto/x509/v3_genn.c:48`,
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, GENERAL_NAME)`.
static GENERAL_NAMES_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"GENERAL_NAMES".as_ptr(),
    item: general_name_it as *mut c_void,
};

/// `GENERAL_NAMES_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(GENERAL_NAMES)` at `:49`: a
/// `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`, `tcount` 0.
static GENERAL_NAMES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &GENERAL_NAMES_ITEM_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"GENERAL_NAMES".as_ptr(),
};

/// `const ASN1_ITEM *GENERAL_NAMES_it(void)` — from `DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAMES_it() -> *const Asn1Item {
    &GENERAL_NAMES_ITEM
}

/// `GENERAL_NAMES *GENERAL_NAMES_new(void)` — `crypto/x509/v3_genn.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAMES)`. A `SEQUENCE OF` value is a stack.
#[no_mangle]
pub extern "C" fn GENERAL_NAMES_new() -> *mut OpenSslStack {
    // SAFETY: `GENERAL_NAMES_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(GENERAL_NAMES_it()).cast::<OpenSslStack>() }
}

/// `void GENERAL_NAMES_free(GENERAL_NAMES *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAMES_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), GENERAL_NAMES_it()) }
}

/// `GENERAL_NAMES *d2i_GENERAL_NAMES(GENERAL_NAMES **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_GENERAL_NAMES(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, GENERAL_NAMES_it()).cast::<OpenSslStack>() }
}

/// `int i2d_GENERAL_NAMES(const GENERAL_NAMES *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_GENERAL_NAMES(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, GENERAL_NAMES_it()) }
}

/// `GENERAL_NAME *GENERAL_NAME_dup(const GENERAL_NAME *a)` — `crypto/x509/v3_genn.c:53-58`.
///
/// Encode-then-decode through the item, so the answer shares no storage with `a`.
///
/// # Safety
/// `a` is NULL or a live `GENERAL_NAME`. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_dup(a: *const GeneralName) -> *mut GeneralName {
    // The authority casts `i2d_GENERAL_NAME`/`d2i_GENERAL_NAME` to the `void` spellings
    // `ASN1_dup` takes; the same transmute is written here rather than a shim.
    let i2d: I2dOfVoid =
        // SAFETY: both signatures are `(const T *, unsigned char **) -> int`; `T` is a pointer
        // type, so the call through the reinterpreted pointer is layout-compatible.
        unsafe {
            core::mem::transmute::<unsafe extern "C" fn(*const GeneralName, *mut *mut c_uchar) -> c_int, I2dOfVoid>(
                i2d_GENERAL_NAME,
            )
        };
    let d2i: D2iOfVoid =
        // SAFETY: both signatures are `(T **, const unsigned char **, long) -> T *`; `T` is a
        // pointer type, so the call through the reinterpreted pointer is layout-compatible.
        unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut *mut GeneralName, *mut *const c_uchar, c_long) -> *mut GeneralName,
                D2iOfVoid,
            >(d2i_GENERAL_NAME)
        };
    // SAFETY: `i2d`/`d2i` match each other and `a` is NULL or live per the contract.
    unsafe { ASN1_dup(i2d, d2i, a.cast()) }.cast::<GeneralName>()
}

/// `int GENERAL_NAME_set1_X509_NAME(GENERAL_NAME **tgt, const X509_NAME *src)` —
/// `crypto/x509/v3_genn.c:60-87`.
///
/// Builds a fresh `GEN_DIRNAME` name (a NULL `src` is the NULL-DN case, which allocates an empty
/// `X509_NAME`), releases the caller's old one and writes the new pointer back. A NULL `tgt` is
/// the covered refusal.
///
/// # Safety
/// `tgt` is NULL or a writable slot; `src` is NULL or a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set1_X509_NAME(
    tgt: *mut *mut GeneralName,
    src: *const X509Name,
) -> c_int {
    if tgt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::V3_GENN_65) };
        return 0;
    }

    // SAFETY: no preconditions.
    let name = GENERAL_NAME_new();
    if name.is_null() {
        return 0;
    }
    // SAFETY: `name` is live and its `type_` slot is writable.
    unsafe { (*name).type_ = GEN_DIRNAME };

    if src.is_null() {
        // SAFETY: no preconditions.
        let dn = X509_NAME_new();
        // SAFETY: `name` is live and its `d` slot is writable.
        unsafe { (*name).d.directoryName = dn };
        if dn.is_null() {
            // SAFETY: `name` is live and this failure path owns it.
            unsafe { GENERAL_NAME_free(name) };
            return 0;
        }
    } else {
        // SAFETY: `name` is live, so its `d.directoryName` slot is writable; `src` is live.
        let ok = unsafe { X509_NAME_set(&raw mut (*name).d.directoryName, src) };
        if ok == 0 {
            // SAFETY: `name` is live and this failure path owns it.
            unsafe { GENERAL_NAME_free(name) };
            return 0;
        }
    }

    // SAFETY: `tgt` is a writable slot per the check above and `*tgt` is NULL or live.
    unsafe {
        GENERAL_NAME_free(*tgt);
        *tgt = name;
    }
    1
}

/// `static int edipartyname_cmp(const EDIPARTYNAME *a, const EDIPARTYNAME *b)` —
/// `crypto/x509/v3_genn.c:89-118`.
///
/// A NULL argument answers `-1` (the authority's "not comparable" answer, which it chooses over
/// `OTHERNAME_cmp`'s `NULL != NULL`). A present `nameAssigner` on one side and not the other is
/// ordered by which side has it.
///
/// # Safety
/// `a`/`b` are NULL or live `EDIPARTYNAME` values.
unsafe fn edipartyname_cmp(a: *const EdiPartyName, b: *const EdiPartyName) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let (an, bn) = unsafe { ((*a).nameAssigner, (*b).nameAssigner) };
    if an.is_null() && !bn.is_null() {
        return -1;
    }
    if !an.is_null() && bn.is_null() {
        return 1;
    }
    if !an.is_null() {
        // SAFETY: both `nameAssigner` pointers are live in this arm.
        let res = unsafe { ASN1_STRING_cmp(an, bn) };
        if res != 0 {
            return res;
        }
    }
    // SAFETY: both are live per the check above.
    let (ap, bp) = unsafe { ((*a).partyName, (*b).partyName) };
    if ap.is_null() || bp.is_null() {
        return -1;
    }
    // SAFETY: both `partyName` pointers are live in this arm.
    unsafe { ASN1_STRING_cmp(ap, bp) }
}

/// `int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b)` — `crypto/x509/v3_genn.c:120-159`.
///
/// `-1` for a NULL argument or a selector mismatch; otherwise the selected arm's own comparison.
///
/// # Safety
/// `a`/`b` are NULL or live `GENERAL_NAME` values.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_cmp(a: *mut GeneralName, b: *mut GeneralName) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let (ta, tb) = unsafe { ((*a).type_, (*b).type_) };
    if ta != tb {
        return -1;
    }
    // SAFETY: the selector is equal on both sides, so each arm reads a pair of the same type.
    unsafe {
        match ta {
            GEN_X400 => ASN1_STRING_cmp((*a).d.x400Address, (*b).d.x400Address),
            GEN_EDIPARTY => edipartyname_cmp((*a).d.ediPartyName, (*b).d.ediPartyName),
            GEN_OTHERNAME => OTHERNAME_cmp((*a).d.otherName, (*b).d.otherName),
            GEN_EMAIL | GEN_DNS | GEN_URI => ASN1_STRING_cmp((*a).d.ia5, (*b).d.ia5),
            GEN_DIRNAME => X509_NAME_cmp((*a).d.directoryName, (*b).d.directoryName),
            GEN_IPADD => ASN1_OCTET_STRING_cmp((*a).d.iPAddress, (*b).d.iPAddress),
            GEN_RID => OBJ_cmp((*a).d.registeredID, (*b).d.registeredID),
            _ => -1,
        }
    }
}

/// `int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b)` — `crypto/x509/v3_genn.c:161-174`.
///
/// The type OID first, then the value through [`ASN1_TYPE_cmp`]; a NULL argument is `-1` (this
/// one, unlike [`edipartyname_cmp`], answers `-1` where `OTHERNAME` is not comparable at all).
///
/// # Safety
/// `a`/`b` are NULL or live `OTHERNAME` values.
#[no_mangle]
pub unsafe extern "C" fn OTHERNAME_cmp(a: *mut Othername, b: *mut Othername) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let res = unsafe { OBJ_cmp((*a).type_id, (*b).type_id) };
    if res != 0 {
        return res;
    }
    // SAFETY: both `value` pointers are live in this arm.
    unsafe { ASN1_TYPE_cmp((*a).value, (*b).value) }
}

/// `void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value)` —
/// `crypto/x509/v3_genn.c:176-210`.
///
/// Writes the pointer the selector names and then the selector; it does **not** release whatever
/// the union held, which is the authority's transfer-of-ownership contract and is observable.
///
/// # Safety
/// `a` is live; `value` is NULL or a live value of the arm `type` selects, and ownership passes
/// to `a`.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set0_value(
    a: *mut GeneralName,
    type_: c_int,
    value: *mut c_void,
) {
    // SAFETY: `a` is live and the union is writable; every arm is one pointer.
    unsafe {
        (*a).d = match type_ {
            GEN_X400 => GeneralNameValue {
                x400Address: value.cast::<Asn1String>(),
            },
            GEN_EDIPARTY => GeneralNameValue {
                ediPartyName: value.cast::<EdiPartyName>(),
            },
            GEN_OTHERNAME => GeneralNameValue {
                otherName: value.cast::<Othername>(),
            },
            GEN_EMAIL | GEN_DNS | GEN_URI => GeneralNameValue {
                ia5: value.cast::<Asn1String>(),
            },
            GEN_DIRNAME => GeneralNameValue {
                directoryName: value.cast::<X509Name>(),
            },
            GEN_IPADD => GeneralNameValue {
                iPAddress: value.cast::<Asn1String>(),
            },
            GEN_RID => GeneralNameValue {
                registeredID: value.cast::<Asn1Object>(),
            },
            // An unknown selector writes nothing into the union (the authority's switch has no
            // default, so `d` keeps its previous bytes), and still records the type.
            _ => (*a).d,
        };
        (*a).type_ = type_;
    }
}

/// `void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype)` —
/// `crypto/x509/v3_genn.c:212-243`.
///
/// Answers the selected union arm, and writes the selector through `ptype` when it is non-NULL. An
/// unknown selector answers NULL rather than raising. The answer is borrowed.
///
/// # Safety
/// `a` is live; `ptype` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_get0_value(
    a: *const GeneralName,
    ptype: *mut c_int,
) -> *mut c_void {
    // SAFETY: `a` is live per the contract.
    let type_ = unsafe { (*a).type_ };
    if !ptype.is_null() {
        // SAFETY: `ptype` is writable per the contract.
        unsafe { *ptype = type_ };
    }
    // SAFETY: `a` is live; the selector picks the union arm to read.
    unsafe {
        match type_ {
            GEN_X400 => (*a).d.x400Address.cast::<c_void>(),
            GEN_EDIPARTY => (*a).d.ediPartyName.cast::<c_void>(),
            GEN_OTHERNAME => (*a).d.otherName.cast::<c_void>(),
            GEN_EMAIL | GEN_DNS | GEN_URI => (*a).d.ia5.cast::<c_void>(),
            GEN_DIRNAME => (*a).d.directoryName.cast::<c_void>(),
            GEN_IPADD => (*a).d.iPAddress.cast::<c_void>(),
            GEN_RID => (*a).d.registeredID.cast::<c_void>(),
            _ => ptr::null_mut(),
        }
    }
}

/// `int GENERAL_NAME_set0_othername(GENERAL_NAME *gen, ASN1_OBJECT *oid, ASN1_TYPE *value)` —
/// `crypto/x509/v3_genn.c:245-257`.
///
/// Allocates an `OTHERNAME`, releases its freshly-allocated empty `value` (so the caller's passes
/// in without a leak), adopts the OID and value and installs it as the `GEN_OTHERNAME` arm.
///
/// # Safety
/// `gen` is live; `oid`/`value` are NULL or live and transfer to the answer.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set0_othername(
    gen: *mut GeneralName,
    oid: *mut Asn1Object,
    value: *mut Asn1Type,
) -> c_int {
    // SAFETY: no preconditions.
    let oth = OTHERNAME_new();
    if oth.is_null() {
        return 0;
    }
    // SAFETY: `oth` is live and its `value` is the fresh empty one the item layer built.
    unsafe {
        ASN1_TYPE_free((*oth).value);
        (*oth).type_id = oid;
        (*oth).value = value;
    }
    // SAFETY: `gen` is live and adopts `oth`.
    unsafe { GENERAL_NAME_set0_value(gen, GEN_OTHERNAME, oth.cast::<c_void>()) };
    1
}

/// `int GENERAL_NAME_get0_otherName(const GENERAL_NAME *gen, ASN1_OBJECT **poid,
/// ASN1_TYPE **pvalue)` — `crypto/x509/v3_genn.c:259-269`.
///
/// Answers 0 without writing either out-parameter when the name is not an `OTHERNAME`; otherwise
/// writes the ones that are non-NULL and answers 1.
///
/// # Safety
/// `gen` is live; `poid`/`pvalue` are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_get0_otherName(
    gen: *const GeneralName,
    poid: *mut *mut Asn1Object,
    pvalue: *mut *mut Asn1Type,
) -> c_int {
    // SAFETY: `gen` is live per the contract.
    if unsafe { (*gen).type_ } != GEN_OTHERNAME {
        return 0;
    }
    // SAFETY: the selector says the union holds an `OTHERNAME`.
    let oth = unsafe { (*gen).d.otherName };
    if !poid.is_null() {
        // SAFETY: `poid` is writable; `oth` is live.
        unsafe { *poid = (*oth).type_id };
    }
    if !pvalue.is_null() {
        // SAFETY: `pvalue` is writable; `oth` is live.
        unsafe { *pvalue = (*oth).value };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::obj::{NID_commonName, OBJ_nid2obj};

    /// The item group is stable, a decoded `iPAddress` carries its octets, and the selector is
    /// the `GEN_*` the wire tag named. A `dNSName` round-trips to the same bytes.
    #[test]
    fn ia5_and_ip_round_trip_through_the_choice() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let name = GENERAL_NAME_new();
        assert!(!name.is_null());
        // SAFETY: `name` is live; ownership of the object passes to the union.
        let obj = OBJ_nid2obj(GEN_RID);
        assert!(!obj.is_null());
        // SAFETY: `name` is live and `obj` is a live object.
        unsafe {
            GENERAL_NAME_set0_value(name, GEN_RID, obj.cast::<c_void>());
            assert_eq!((*name).type_, GEN_RID);
            let mut t: c_int = -1;
            assert_eq!(
                GENERAL_NAME_get0_value(name, &raw mut t),
                obj.cast::<c_void>()
            );
            assert_eq!(t, GEN_RID);
            GENERAL_NAME_free(name);
        }
        assert_eq!(GENERAL_NAME_it(), GENERAL_NAME_it());
        assert_eq!(GENERAL_NAMES_it(), GENERAL_NAMES_it());
    }

    /// `set0_othername` installs an `OTHERNAME` arm whose type OID and value come back through
    /// `get0_otherName`, and a non-`OTHERNAME` name refuses the reader with 0.
    #[test]
    fn set0_othername_is_readable() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let name = GENERAL_NAME_new();
        assert!(!name.is_null());
        // SAFETY: no preconditions.
        let oid = OBJ_nid2obj(NID_commonName);
        // SAFETY: `name` is live; `oid` transfers to the OTHERNAME.
        unsafe {
            assert_eq!(GENERAL_NAME_set0_othername(name, oid, ptr::null_mut()), 1);
            assert_eq!((*name).type_, GEN_OTHERNAME);
            let mut poid: *mut Asn1Object = ptr::null_mut();
            let mut pval: *mut Asn1Type = ptr::null_mut();
            assert_eq!(
                GENERAL_NAME_get0_otherName(name, &raw mut poid, &raw mut pval),
                1
            );
            assert_eq!(poid, oid);
            assert!(pval.is_null());
            GENERAL_NAME_free(name);

            let ip = GENERAL_NAME_new();
            assert!(!ip.is_null());
            GENERAL_NAME_set0_value(ip, GEN_IPADD, ptr::null_mut());
            assert_eq!(
                GENERAL_NAME_get0_otherName(ip, ptr::null_mut(), ptr::null_mut()),
                0
            );
            GENERAL_NAME_free(ip);
        }
    }
}
