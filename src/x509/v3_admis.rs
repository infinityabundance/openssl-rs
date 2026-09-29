//! `crypto/x509/v3_admis.c` — the RFC 5755 admission-syntax item groups, their printer and their
//! row. Phase 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_admis.c` is 355 lines and transcribes whole:
//!
//! * `NAMING_AUTHORITY ::= SEQUENCE { namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
//!   namingAuthorityUrl IA5String OPTIONAL, namingAuthorityText DirectoryString OPTIONAL }`
//!   (`:23-27`), `PROFESSION_INFO ::= SEQUENCE { namingAuthority [0] EXPLICIT NAMING_AUTHORITY
//!   OPTIONAL, professionItems SEQUENCE OF DirectoryString, professionOIDs SEQUENCE OF OBJECT
//!   OPTIONAL, registrationNumber PrintableString OPTIONAL, addProfessionInfo OCTET STRING
//!   OPTIONAL }` (`:29-35`), `ADMISSIONS ::= SEQUENCE { admissionAuthority [0] EXPLICIT
//!   GeneralName OPTIONAL, namingAuthority [1] EXPLICIT NAMING_AUTHORITY OPTIONAL, professionInfos
//!   SEQUENCE OF PROFESSION_INFO }` (`:37-41`) and `ADMISSION_SYNTAX ::= SEQUENCE {
//!   admissionAuthority GeneralName OPTIONAL, contentsOfAdmissions SEQUENCE OF ADMISSIONS }`
//!   (`:43-46`) all land, with the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group each
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:48-51`). All twenty are public exports
//!   (`x509v3.h:1002-1005`).
//! * The two `static` printers land: `i2r_NAMING_AUTHORITY` (`:70-116`) and `i2r_ADMISSION_SYNTAX`
//!   (`:118-205`).
//! * The exported field accessors land: the two `NAMING_AUTHORITY` getter/`set0` pairs, the two
//!   `ADMISSION_SYNTAX` pairs, the three `ADMISSIONS` pairs and the five `PROFESSION_INFO` pairs
//!   (`:207-355`), all declared in `x509v3.h:1014-1061`.
//! * The row [`ossl_v3_ext_admission`] (`:56-68`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the array
//! is withheld until all 63 tables exist. This unit contributes one of the 63. The row is internal
//! data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the item groups, the field
//! accessors and the two printers are the drivable surface.
//!
//! ## No raise
//!
//! `crypto/x509/v3_admis.c` raises nothing (`ERR_raise` appears nowhere), so it is deliberately not
//! an entry in `gen_err_raise_sites.py`'s `COVERED_FILES` and this module declares no site.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_IA5STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_PRINTABLESTRING_it,
    DIRECTORYSTRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{
    ASN1_IA5STRING_free, ASN1_OCTET_STRING_free, ASN1_PRINTABLESTRING_free, ASN1_STRING_free,
};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::{Asn1Object, NID_x509ExtAdmission, OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_genn::{GENERAL_NAME_free, GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::GENERAL_NAME_print;

// ---------------------------------------------------------------------------------------------
// The structures
// ---------------------------------------------------------------------------------------------

/// `struct NamingAuthority_st` — `NAMING_AUTHORITY`, from `crypto/x509/v3_admis.h:13-17`.
#[repr(C)]
pub struct NamingAuthority {
    /// `ASN1_OBJECT *namingAuthorityId` — the naming-authority OID, optional.
    pub(crate) namingAuthorityId: *mut Asn1Object,
    /// `ASN1_IA5STRING *namingAuthorityUrl` — the naming-authority URL, optional.
    pub(crate) namingAuthorityUrl: *mut Asn1String,
    /// `ASN1_STRING *namingAuthorityText` — the `DIRECTORYSTRING` text, optional.
    pub(crate) namingAuthorityText: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<NamingAuthority>() == 24);
    assert!(core::mem::offset_of!(NamingAuthority, namingAuthorityId) == 0);
    assert!(core::mem::offset_of!(NamingAuthority, namingAuthorityUrl) == 8);
    assert!(core::mem::offset_of!(NamingAuthority, namingAuthorityText) == 16);
};

/// `struct ProfessionInfo_st` — `PROFESSION_INFO`, from `crypto/x509/v3_admis.h:19-25`.
#[repr(C)]
pub struct ProfessionInfo {
    /// `NAMING_AUTHORITY *namingAuthority` — the `[0]` explicit naming authority, optional.
    pub(crate) namingAuthority: *mut NamingAuthority,
    /// `STACK_OF(ASN1_STRING) *professionItems` — the `SEQUENCE OF DIRECTORYSTRING`, mandatory.
    pub(crate) professionItems: *mut OpenSslStack,
    /// `STACK_OF(ASN1_OBJECT) *professionOIDs` — the `SEQUENCE OF OBJECT`, optional.
    pub(crate) professionOIDs: *mut OpenSslStack,
    /// `ASN1_PRINTABLESTRING *registrationNumber` — optional.
    pub(crate) registrationNumber: *mut Asn1String,
    /// `ASN1_OCTET_STRING *addProfessionInfo` — optional.
    pub(crate) addProfessionInfo: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<ProfessionInfo>() == 40);
    assert!(core::mem::offset_of!(ProfessionInfo, namingAuthority) == 0);
    assert!(core::mem::offset_of!(ProfessionInfo, professionItems) == 8);
    assert!(core::mem::offset_of!(ProfessionInfo, professionOIDs) == 16);
    assert!(core::mem::offset_of!(ProfessionInfo, registrationNumber) == 24);
    assert!(core::mem::offset_of!(ProfessionInfo, addProfessionInfo) == 32);
};

/// `struct Admissions_st` — `ADMISSIONS`, from `crypto/x509/v3_admis.h:27-31`.
#[repr(C)]
pub struct Admissions {
    /// `GENERAL_NAME *admissionAuthority` — the `[0]` explicit authority, optional.
    pub(crate) admissionAuthority: *mut GeneralName,
    /// `NAMING_AUTHORITY *namingAuthority` — the `[1]` explicit naming authority, optional.
    pub(crate) namingAuthority: *mut NamingAuthority,
    /// `STACK_OF(PROFESSION_INFO) *professionInfos` — the `SEQUENCE OF`, mandatory.
    pub(crate) professionInfos: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<Admissions>() == 24);
    assert!(core::mem::offset_of!(Admissions, admissionAuthority) == 0);
    assert!(core::mem::offset_of!(Admissions, namingAuthority) == 8);
    assert!(core::mem::offset_of!(Admissions, professionInfos) == 16);
};

/// `struct AdmissionSyntax_st` — `ADMISSION_SYNTAX`, from `crypto/x509/v3_admis.h:33-36`.
#[repr(C)]
pub struct AdmissionSyntax {
    /// `GENERAL_NAME *admissionAuthority` — optional.
    pub(crate) admissionAuthority: *mut GeneralName,
    /// `STACK_OF(ADMISSIONS) *contentsOfAdmissions` — the `SEQUENCE OF`, mandatory.
    pub(crate) contentsOfAdmissions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<AdmissionSyntax>() == 16);
    assert!(core::mem::offset_of!(AdmissionSyntax, admissionAuthority) == 0);
    assert!(core::mem::offset_of!(AdmissionSyntax, contentsOfAdmissions) == 8);
};

// ---------------------------------------------------------------------------------------------
// NAMING_AUTHORITY — `ASN1_SEQUENCE(NAMING_AUTHORITY)` (`:23-27`)
// ---------------------------------------------------------------------------------------------

/// `NAMING_AUTHORITY_seq_tt` — `ASN1_SEQUENCE(NAMING_AUTHORITY)` (`crypto/x509/v3_admis.c:23-26`):
/// three `ASN1_OPT` rows.
static NAMING_AUTHORITY_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"namingAuthorityId".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"namingAuthorityUrl".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"namingAuthorityText".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
];

/// `NAMING_AUTHORITY_it`'s descriptor — `ASN1_SEQUENCE_END(NAMING_AUTHORITY)` at
/// `crypto/x509/v3_admis.c:27`.
static NAMING_AUTHORITY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NAMING_AUTHORITY_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<NamingAuthority>() as c_long,
    sname: c"NAMING_AUTHORITY".as_ptr(),
};

/// `const ASN1_ITEM *NAMING_AUTHORITY_it(void)` — `include/openssl/x509v3.h:1002`, from
/// `DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)`.
#[no_mangle]
pub extern "C" fn NAMING_AUTHORITY_it() -> *const Asn1Item {
    &NAMING_AUTHORITY_ITEM
}

/// `NAMING_AUTHORITY *NAMING_AUTHORITY_new(void)` — `crypto/x509/v3_admis.c:48`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(NAMING_AUTHORITY)`.
#[no_mangle]
pub extern "C" fn NAMING_AUTHORITY_new() -> *mut NamingAuthority {
    // SAFETY: `NAMING_AUTHORITY_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NAMING_AUTHORITY_it()).cast::<NamingAuthority>() }
}

/// `void NAMING_AUTHORITY_free(NAMING_AUTHORITY *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_free(a: *mut NamingAuthority) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NAMING_AUTHORITY_it()) }
}

/// `NAMING_AUTHORITY *d2i_NAMING_AUTHORITY(NAMING_AUTHORITY **a, const unsigned char **in, long
/// len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_NAMING_AUTHORITY(
    a: *mut *mut NamingAuthority,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut NamingAuthority {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, NAMING_AUTHORITY_it()).cast::<NamingAuthority>() }
}

/// `int i2d_NAMING_AUTHORITY(const NAMING_AUTHORITY *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_NAMING_AUTHORITY(
    a: *const NamingAuthority,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, NAMING_AUTHORITY_it()) }
}

// ---------------------------------------------------------------------------------------------
// PROFESSION_INFO — `ASN1_SEQUENCE(PROFESSION_INFO)` (`:29-35`)
// ---------------------------------------------------------------------------------------------

/// `PROFESSION_INFO_seq_tt` — `ASN1_SEQUENCE(PROFESSION_INFO)` (`crypto/x509/v3_admis.c:29-34`):
/// `ASN1_EXP_OPT`, `ASN1_SEQUENCE_OF`, `ASN1_SEQUENCE_OF_OPT` and two `ASN1_OPT`.
static PROFESSION_INFO_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"namingAuthority".as_ptr(),
        item: NAMING_AUTHORITY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"professionItems".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"professionOIDs".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"registrationNumber".as_ptr(),
        item: ASN1_PRINTABLESTRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"addProfessionInfo".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `PROFESSION_INFO_it`'s descriptor — `ASN1_SEQUENCE_END(PROFESSION_INFO)` at
/// `crypto/x509/v3_admis.c:35`.
static PROFESSION_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PROFESSION_INFO_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<ProfessionInfo>() as c_long,
    sname: c"PROFESSION_INFO".as_ptr(),
};

/// `const ASN1_ITEM *PROFESSION_INFO_it(void)` — `include/openssl/x509v3.h:1003`, from
/// `DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)`.
#[no_mangle]
pub extern "C" fn PROFESSION_INFO_it() -> *const Asn1Item {
    &PROFESSION_INFO_ITEM
}

/// `PROFESSION_INFO *PROFESSION_INFO_new(void)` — `crypto/x509/v3_admis.c:49`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PROFESSION_INFO)`.
#[no_mangle]
pub extern "C" fn PROFESSION_INFO_new() -> *mut ProfessionInfo {
    // SAFETY: `PROFESSION_INFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PROFESSION_INFO_it()).cast::<ProfessionInfo>() }
}

/// `void PROFESSION_INFO_free(PROFESSION_INFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_free(a: *mut ProfessionInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PROFESSION_INFO_it()) }
}

/// `PROFESSION_INFO *d2i_PROFESSION_INFO(PROFESSION_INFO **a, const unsigned char **in, long len)`
/// — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PROFESSION_INFO(
    a: *mut *mut ProfessionInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut ProfessionInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PROFESSION_INFO_it()).cast::<ProfessionInfo>() }
}

/// `int i2d_PROFESSION_INFO(const PROFESSION_INFO *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PROFESSION_INFO(
    a: *const ProfessionInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PROFESSION_INFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// ADMISSIONS — `ASN1_SEQUENCE(ADMISSIONS)` (`:37-41`)
// ---------------------------------------------------------------------------------------------

/// `ADMISSIONS_seq_tt` — `ASN1_SEQUENCE(ADMISSIONS)` (`crypto/x509/v3_admis.c:37-40`):
/// two `ASN1_EXP_OPT` rows (`GENERAL_NAME` and `NAMING_AUTHORITY`) and one `ASN1_SEQUENCE_OF`.
static ADMISSIONS_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"admissionAuthority".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"namingAuthority".as_ptr(),
        item: NAMING_AUTHORITY_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 16,
        field_name: c"professionInfos".as_ptr(),
        item: PROFESSION_INFO_it as *mut c_void,
    },
];

/// `ADMISSIONS_it`'s descriptor — `ASN1_SEQUENCE_END(ADMISSIONS)` at `crypto/x509/v3_admis.c:41`.
static ADMISSIONS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ADMISSIONS_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<Admissions>() as c_long,
    sname: c"ADMISSIONS".as_ptr(),
};

/// `const ASN1_ITEM *ADMISSIONS_it(void)` — `include/openssl/x509v3.h:1004`, from
/// `DECLARE_ASN1_FUNCTIONS(ADMISSIONS)`.
#[no_mangle]
pub extern "C" fn ADMISSIONS_it() -> *const Asn1Item {
    &ADMISSIONS_ITEM
}

/// `ADMISSIONS *ADMISSIONS_new(void)` — `crypto/x509/v3_admis.c:50`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(ADMISSIONS)`.
#[no_mangle]
pub extern "C" fn ADMISSIONS_new() -> *mut Admissions {
    // SAFETY: `ADMISSIONS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ADMISSIONS_it()).cast::<Admissions>() }
}

/// `void ADMISSIONS_free(ADMISSIONS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_free(a: *mut Admissions) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ADMISSIONS_it()) }
}

/// `ADMISSIONS *d2i_ADMISSIONS(ADMISSIONS **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ADMISSIONS(
    a: *mut *mut Admissions,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Admissions {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ADMISSIONS_it()).cast::<Admissions>() }
}

/// `int i2d_ADMISSIONS(const ADMISSIONS *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ADMISSIONS(a: *const Admissions, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ADMISSIONS_it()) }
}

// ---------------------------------------------------------------------------------------------
// ADMISSION_SYNTAX — `ASN1_SEQUENCE(ADMISSION_SYNTAX)` (`:43-46`)
// ---------------------------------------------------------------------------------------------

/// `ADMISSION_SYNTAX_seq_tt` — `ASN1_SEQUENCE(ADMISSION_SYNTAX)` (`crypto/x509/v3_admis.c:43-45`):
/// one `ASN1_OPT` (`GENERAL_NAME`) and one `ASN1_SEQUENCE_OF` (`ADMISSIONS`).
static ADMISSION_SYNTAX_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"admissionAuthority".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"contentsOfAdmissions".as_ptr(),
        item: ADMISSIONS_it as *mut c_void,
    },
];

/// `ADMISSION_SYNTAX_it`'s descriptor — `ASN1_SEQUENCE_END(ADMISSION_SYNTAX)` at
/// `crypto/x509/v3_admis.c:46`.
static ADMISSION_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ADMISSION_SYNTAX_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AdmissionSyntax>() as c_long,
    sname: c"ADMISSION_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *ADMISSION_SYNTAX_it(void)` — `include/openssl/x509v3.h:1005`, from
/// `DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)`.
#[no_mangle]
pub extern "C" fn ADMISSION_SYNTAX_it() -> *const Asn1Item {
    &ADMISSION_SYNTAX_ITEM
}

/// `ADMISSION_SYNTAX *ADMISSION_SYNTAX_new(void)` — `crypto/x509/v3_admis.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(ADMISSION_SYNTAX)`.
#[no_mangle]
pub extern "C" fn ADMISSION_SYNTAX_new() -> *mut AdmissionSyntax {
    // SAFETY: `ADMISSION_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ADMISSION_SYNTAX_it()).cast::<AdmissionSyntax>() }
}

/// `void ADMISSION_SYNTAX_free(ADMISSION_SYNTAX *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ADMISSION_SYNTAX_free(a: *mut AdmissionSyntax) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ADMISSION_SYNTAX_it()) }
}

/// `ADMISSION_SYNTAX *d2i_ADMISSION_SYNTAX(ADMISSION_SYNTAX **a, const unsigned char **in, long
/// len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ADMISSION_SYNTAX(
    a: *mut *mut AdmissionSyntax,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AdmissionSyntax {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ADMISSION_SYNTAX_it()).cast::<AdmissionSyntax>() }
}

/// `int i2d_ADMISSION_SYNTAX(const ADMISSION_SYNTAX *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ADMISSION_SYNTAX(
    a: *const AdmissionSyntax,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ADMISSION_SYNTAX_it()) }
}

// ---------------------------------------------------------------------------------------------
// The two printers
// ---------------------------------------------------------------------------------------------

/// `static int i2r_NAMING_AUTHORITY(const struct v3_ext_method *method, void *in, BIO *bp, int
/// ind)` — `crypto/x509/v3_admis.c:70-116`.
///
/// Answers 0 for a null authority, for one whose three fields are all absent, and on a failed
/// write; otherwise 1.
///
/// # Safety
///
/// `bp` is a live BIO; `in_` is NULL or a live `NAMING_AUTHORITY`.
unsafe extern "C" fn i2r_NAMING_AUTHORITY(
    _method: *const X509V3ExtMethod,
    in_: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    let na = in_.cast::<NamingAuthority>();
    if na.is_null() {
        return 0;
    }
    // SAFETY: `na` is live per the contract.
    let (id, url, text) = unsafe {
        (
            (*na).namingAuthorityId,
            (*na).namingAuthorityUrl,
            (*na).namingAuthorityText,
        )
    };
    if id.is_null() && text.is_null() && url.is_null() {
        return 0;
    }
    // SAFETY: `bp` is live; the literal is static.
    if unsafe { BIO_printf(bp, c"%*snamingAuthority:\n".as_ptr(), ind, c"".as_ptr()) } <= 0 {
        return 0;
    }
    if !id.is_null() {
        let mut objbuf = [0 as c_char; 128];
        // SAFETY: `id` is a live object.
        let ln = OBJ_nid2ln(unsafe { OBJ_obj2nid(id) });
        // SAFETY: `bp` is live; the literal is static.
        if unsafe { BIO_printf(bp, c"%*s  namingAuthorityId: ".as_ptr(), ind, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `objbuf` is 128 writable bytes; `id` is a live object.
        unsafe { OBJ_obj2txt(objbuf.as_mut_ptr(), 128, id, 1) };
        let (l, o, c2) = if ln.is_null() {
            (c"".as_ptr(), c"".as_ptr(), c"".as_ptr())
        } else {
            (ln, c" (".as_ptr(), c")".as_ptr())
        };
        // SAFETY: `bp` is live; every literal is static; `objbuf` is NUL-terminated.
        if unsafe { BIO_printf(bp, c"%s%s%s%s\n".as_ptr(), l, o, objbuf.as_ptr(), c2) } <= 0 {
            return 0;
        }
    }
    if !text.is_null() {
        // SAFETY: `bp` and `text` are live; each literal is static.
        let bad = unsafe {
            BIO_printf(
                bp,
                c"%*s  namingAuthorityText: ".as_ptr(),
                ind,
                c"".as_ptr(),
            ) <= 0
                || ASN1_STRING_print(bp, text) <= 0
                || BIO_printf(bp, c"\n".as_ptr()) <= 0
        };
        if bad {
            return 0;
        }
    }
    if !url.is_null() {
        // SAFETY: `bp` and `url` are live; each literal is static.
        let bad = unsafe {
            BIO_printf(bp, c"%*s  namingAuthorityUrl: ".as_ptr(), ind, c"".as_ptr()) <= 0
                || ASN1_STRING_print(bp, url) <= 0
                || BIO_printf(bp, c"\n".as_ptr()) <= 0
        };
        if bad {
            return 0;
        }
    }
    1
}

/// `static int i2r_ADMISSION_SYNTAX(const struct v3_ext_method *method, void *in, BIO *bp, int
/// ind)` — `crypto/x509/v3_admis.c:118-205`.
///
/// Prints the authority and every admissions entry, delegating to [`i2r_NAMING_AUTHORITY`].
///
/// # Safety
///
/// `method` is a live row; `bp` is a live BIO; `in_` is a live `ADMISSION_SYNTAX`.
unsafe extern "C" fn i2r_ADMISSION_SYNTAX(
    method: *const X509V3ExtMethod,
    in_: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    let admission = in_.cast::<AdmissionSyntax>();
    // SAFETY: `admission` is live per the contract.
    let adm_authority = unsafe { (*admission).admissionAuthority };
    if !adm_authority.is_null() {
        // SAFETY: `bp` is live and each literal is static.
        let bad = unsafe {
            BIO_printf(bp, c"%*sadmissionAuthority:\n".as_ptr(), ind, c"".as_ptr()) <= 0
                || BIO_printf(bp, c"%*s  ".as_ptr(), ind, c"".as_ptr()) <= 0
                || GENERAL_NAME_print(bp, adm_authority) <= 0
                || BIO_printf(bp, c"\n".as_ptr()) <= 0
        };
        if bad {
            return 0;
        }
    }
    // SAFETY: `admission` is live.
    let num = unsafe { OPENSSL_sk_num((*admission).contentsOfAdmissions) };
    let mut i = 0;
    while i < num {
        // SAFETY: the stack is live and `i` is in bounds.
        let entry =
            unsafe { OPENSSL_sk_value((*admission).contentsOfAdmissions, i) }.cast::<Admissions>();
        // SAFETY: `bp` is live; the literals are static.
        if unsafe { BIO_printf(bp, c"%*sEntry %0d:\n".as_ptr(), ind, c"".as_ptr(), 1 + i) } <= 0 {
            return 0;
        }
        // SAFETY: `entry` is live.
        let entry_authority = unsafe { (*entry).admissionAuthority };
        if !entry_authority.is_null() {
            // SAFETY: `bp` is live and each literal is static.
            let bad = unsafe {
                BIO_printf(
                    bp,
                    c"%*s  admissionAuthority:\n".as_ptr(),
                    ind,
                    c"".as_ptr(),
                ) <= 0
                    || BIO_printf(bp, c"%*s    ".as_ptr(), ind, c"".as_ptr()) <= 0
                    || GENERAL_NAME_print(bp, entry_authority) <= 0
                    || BIO_printf(bp, c"\n".as_ptr()) <= 0
            };
            if bad {
                return 0;
            }
        }
        // SAFETY: `entry` is live.
        let entry_na = unsafe { (*entry).namingAuthority };
        if !entry_na.is_null() {
            // SAFETY: `method` is per the contract.
            if unsafe { i2r_NAMING_AUTHORITY(method, entry_na.cast::<c_void>(), bp, ind + 2) } <= 0
            {
                return 0;
            }
        }
        // SAFETY: `entry` is live.
        let pnum = unsafe { OPENSSL_sk_num((*entry).professionInfos) };
        let mut j = 0;
        while j < pnum {
            // SAFETY: the stack is live and `j` is in bounds.
            let pinfo =
                unsafe { OPENSSL_sk_value((*entry).professionInfos, j) }.cast::<ProfessionInfo>();
            // SAFETY: `bp` is live; the literals are static.
            if unsafe {
                BIO_printf(
                    bp,
                    c"%*s  Profession Info Entry %0d:\n".as_ptr(),
                    ind,
                    c"".as_ptr(),
                    1 + j,
                )
            } <= 0
            {
                return 0;
            }
            // SAFETY: `pinfo` is live.
            let reg = unsafe { (*pinfo).registrationNumber };
            if !reg.is_null() {
                // SAFETY: `bp` is live and each literal is static.
                let bad = unsafe {
                    BIO_printf(
                        bp,
                        c"%*s    registrationNumber: ".as_ptr(),
                        ind,
                        c"".as_ptr(),
                    ) <= 0
                        || ASN1_STRING_print(bp, reg) <= 0
                        || BIO_printf(bp, c"\n".as_ptr()) <= 0
                };
                if bad {
                    return 0;
                }
            }
            // SAFETY: `pinfo` is live.
            let pinfo_na = unsafe { (*pinfo).namingAuthority };
            if !pinfo_na.is_null() {
                // SAFETY: `method` is per the contract.
                if unsafe { i2r_NAMING_AUTHORITY(method, pinfo_na.cast::<c_void>(), bp, ind + 4) }
                    <= 0
                {
                    return 0;
                }
            }
            // SAFETY: `pinfo` is live.
            let items = unsafe { (*pinfo).professionItems };
            if !items.is_null() {
                // SAFETY: `bp` is live; the literal is static.
                if unsafe { BIO_printf(bp, c"%*s    Info Entries:\n".as_ptr(), ind, c"".as_ptr()) }
                    <= 0
                {
                    return 0;
                }
                // SAFETY: `items` is a live stack.
                let innum = unsafe { OPENSSL_sk_num(items) };
                let mut k = 0;
                while k < innum {
                    // SAFETY: the stack is live and `k` is in bounds.
                    let val = unsafe { OPENSSL_sk_value(items, k) }.cast::<Asn1String>();
                    // SAFETY: `bp` and `val` are live; each literal is static.
                    let bad = unsafe {
                        BIO_printf(bp, c"%*s      ".as_ptr(), ind, c"".as_ptr()) <= 0
                            || ASN1_STRING_print(bp, val) <= 0
                            || BIO_printf(bp, c"\n".as_ptr()) <= 0
                    };
                    if bad {
                        return 0;
                    }
                    k += 1;
                }
            }
            // SAFETY: `pinfo` is live.
            let oids = unsafe { (*pinfo).professionOIDs };
            if !oids.is_null() {
                // SAFETY: `bp` is live; the literal is static.
                if unsafe {
                    BIO_printf(bp, c"%*s    Profession OIDs:\n".as_ptr(), ind, c"".as_ptr())
                } <= 0
                {
                    return 0;
                }
                // SAFETY: `oids` is a live stack.
                let oidnum = unsafe { OPENSSL_sk_num(oids) };
                let mut k = 0;
                while k < oidnum {
                    // SAFETY: the stack is live and `k` is in bounds.
                    let obj = unsafe { OPENSSL_sk_value(oids, k) }.cast::<Asn1Object>();
                    // SAFETY: `obj` is a live object.
                    let ln = OBJ_nid2ln(unsafe { OBJ_obj2nid(obj) });
                    let mut objbuf = [0 as c_char; 128];
                    // SAFETY: `objbuf` is 128 writable bytes; `obj` is a live object.
                    unsafe { OBJ_obj2txt(objbuf.as_mut_ptr(), 128, obj, 1) };
                    let (l, o, c2) = if ln.is_null() {
                        (c"".as_ptr(), c"".as_ptr(), c"".as_ptr())
                    } else {
                        (ln, c" (".as_ptr(), c")".as_ptr())
                    };
                    // SAFETY: `bp` is live; every literal is static; `objbuf` is NUL-terminated.
                    if unsafe {
                        BIO_printf(
                            bp,
                            c"%*s      %s%s%s%s\n".as_ptr(),
                            ind,
                            c"".as_ptr(),
                            l,
                            o,
                            objbuf.as_ptr(),
                            c2,
                        )
                    } <= 0
                    {
                        return 0;
                    }
                    k += 1;
                }
            }
            j += 1;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The field accessors (`:207-355`)
// ---------------------------------------------------------------------------------------------

/// `const ASN1_OBJECT *NAMING_AUTHORITY_get0_authorityId(const NAMING_AUTHORITY *n)` —
/// `crypto/x509/v3_admis.c:207-210`.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityId(
    n: *const NamingAuthority,
) -> *const Asn1Object {
    // SAFETY: `n` is live per the contract.
    unsafe { (*n).namingAuthorityId }
}

/// `void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY *n, ASN1_OBJECT *id)` —
/// `crypto/x509/v3_admis.c:212-216`.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`; `id` is NULL or an object this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityId(
    n: *mut NamingAuthority,
    id: *mut Asn1Object,
) {
    // SAFETY: `n` is live; its `namingAuthorityId` is NULL or owned.
    unsafe { ASN1_OBJECT_free((*n).namingAuthorityId) };
    // SAFETY: `n` is live; the field slot is writable.
    unsafe { (*n).namingAuthorityId = id };
}

/// `const ASN1_IA5STRING *NAMING_AUTHORITY_get0_authorityURL(const NAMING_AUTHORITY *n)` —
/// `crypto/x509/v3_admis.c:218-221`.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityURL(
    n: *const NamingAuthority,
) -> *const Asn1String {
    // SAFETY: `n` is live per the contract.
    unsafe { (*n).namingAuthorityUrl }
}

/// `void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY *n, ASN1_IA5STRING *u)` —
/// `crypto/x509/v3_admis.c:223-227`.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`; `u` is NULL or a string this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityURL(
    n: *mut NamingAuthority,
    u: *mut Asn1String,
) {
    // SAFETY: `n` is live; its `namingAuthorityUrl` is NULL or owned.
    unsafe { ASN1_IA5STRING_free((*n).namingAuthorityUrl) };
    // SAFETY: `n` is live; the field slot is writable.
    unsafe { (*n).namingAuthorityUrl = u };
}

/// `const ASN1_STRING *NAMING_AUTHORITY_get0_authorityText(const NAMING_AUTHORITY *n)` —
/// `crypto/x509/v3_admis.c:229-232`.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_get0_authorityText(
    n: *const NamingAuthority,
) -> *const Asn1String {
    // SAFETY: `n` is live per the contract.
    unsafe { (*n).namingAuthorityText }
}

/// `void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *n, ASN1_STRING *t)` —
/// `crypto/x509/v3_admis.c:234-238`.
///
/// The authority frees the old text through `ASN1_IA5STRING_free`, not `ASN1_STRING_free`; that
/// asymmetry is transcribed literally.
///
/// # Safety
///
/// `n` is a live `NAMING_AUTHORITY`; `t` is NULL or a string this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn NAMING_AUTHORITY_set0_authorityText(
    n: *mut NamingAuthority,
    t: *mut Asn1String,
) {
    // SAFETY: `n` is live; its `namingAuthorityText` is NULL or owned.
    unsafe { ASN1_IA5STRING_free((*n).namingAuthorityText) };
    // SAFETY: `n` is live; the field slot is writable.
    unsafe { (*n).namingAuthorityText = t };
}

/// `const GENERAL_NAME *ADMISSION_SYNTAX_get0_admissionAuthority(const ADMISSION_SYNTAX *as)` —
/// `crypto/x509/v3_admis.c:240-243`.
///
/// # Safety
///
/// `as_` is a live `ADMISSION_SYNTAX`.
#[no_mangle]
pub unsafe extern "C" fn ADMISSION_SYNTAX_get0_admissionAuthority(
    as_: *const AdmissionSyntax,
) -> *const GeneralName {
    // SAFETY: `as_` is live per the contract.
    unsafe { (*as_).admissionAuthority }
}

/// `void ADMISSION_SYNTAX_set0_admissionAuthority(ADMISSION_SYNTAX *as, GENERAL_NAME *aa)` —
/// `crypto/x509/v3_admis.c:245-250`.
///
/// # Safety
///
/// `as_` is a live `ADMISSION_SYNTAX`; `aa` is NULL or a name this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn ADMISSION_SYNTAX_set0_admissionAuthority(
    as_: *mut AdmissionSyntax,
    aa: *mut GeneralName,
) {
    // SAFETY: `as_` is live; its `admissionAuthority` is NULL or owned.
    unsafe { GENERAL_NAME_free((*as_).admissionAuthority) };
    // SAFETY: `as_` is live; the field slot is writable.
    unsafe { (*as_).admissionAuthority = aa };
}

/// `const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(const ADMISSION_SYNTAX
/// *as)` — `crypto/x509/v3_admis.c:252-255`.
///
/// # Safety
///
/// `as_` is a live `ADMISSION_SYNTAX`.
#[no_mangle]
pub unsafe extern "C" fn ADMISSION_SYNTAX_get0_contentsOfAdmissions(
    as_: *const AdmissionSyntax,
) -> *const OpenSslStack {
    // SAFETY: `as_` is live per the contract.
    unsafe { (*as_).contentsOfAdmissions }
}

/// `void ADMISSION_SYNTAX_set0_contentsOfAdmissions(ADMISSION_SYNTAX *as, STACK_OF(ADMISSIONS)
/// *a)` — `crypto/x509/v3_admis.c:257-262`.
///
/// # Safety
///
/// `as_` is a live `ADMISSION_SYNTAX`; `a` is NULL or an `ADMISSIONS` stack this call owns.
#[no_mangle]
pub unsafe extern "C" fn ADMISSION_SYNTAX_set0_contentsOfAdmissions(
    as_: *mut AdmissionSyntax,
    a: *mut OpenSslStack,
) {
    // SAFETY: `as_` is live; its stack holds owned `ADMISSIONS`; the thunk is their destructor.
    unsafe { OPENSSL_sk_pop_free((*as_).contentsOfAdmissions, Some(admissions_free_thunk)) };
    // SAFETY: `as_` is live; the field slot is writable.
    unsafe { (*as_).contentsOfAdmissions = a };
}

/// `const GENERAL_NAME *ADMISSIONS_get0_admissionAuthority(const ADMISSIONS *a)` —
/// `crypto/x509/v3_admis.c:264-267`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_get0_admissionAuthority(
    a: *const Admissions,
) -> *const GeneralName {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).admissionAuthority }
}

/// `void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa)` —
/// `crypto/x509/v3_admis.c:269-273`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`; `aa` is NULL or a name this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_set0_admissionAuthority(
    a: *mut Admissions,
    aa: *mut GeneralName,
) {
    // SAFETY: `a` is live; its `admissionAuthority` is NULL or owned.
    unsafe { GENERAL_NAME_free((*a).admissionAuthority) };
    // SAFETY: `a` is live; the field slot is writable.
    unsafe { (*a).admissionAuthority = aa };
}

/// `const NAMING_AUTHORITY *ADMISSIONS_get0_namingAuthority(const ADMISSIONS *a)` —
/// `crypto/x509/v3_admis.c:275-278`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_get0_namingAuthority(
    a: *const Admissions,
) -> *const NamingAuthority {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).namingAuthority }
}

/// `void ADMISSIONS_set0_namingAuthority(ADMISSIONS *a, NAMING_AUTHORITY *na)` —
/// `crypto/x509/v3_admis.c:280-284`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`; `na` is NULL or a value this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_set0_namingAuthority(
    a: *mut Admissions,
    na: *mut NamingAuthority,
) {
    // SAFETY: `a` is live; its `namingAuthority` is NULL or owned.
    unsafe { NAMING_AUTHORITY_free((*a).namingAuthority) };
    // SAFETY: `a` is live; the field slot is writable.
    unsafe { (*a).namingAuthority = na };
}

/// `const PROFESSION_INFOS *ADMISSIONS_get0_professionInfos(const ADMISSIONS *a)` —
/// `crypto/x509/v3_admis.c:286-289`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_get0_professionInfos(
    a: *const Admissions,
) -> *const OpenSslStack {
    // SAFETY: `a` is live per the contract.
    unsafe { (*a).professionInfos }
}

/// `void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi)` —
/// `crypto/x509/v3_admis.c:291-295`.
///
/// # Safety
///
/// `a` is a live `ADMISSIONS`; `pi` is NULL or a `PROFESSION_INFO` stack this call owns.
#[no_mangle]
pub unsafe extern "C" fn ADMISSIONS_set0_professionInfos(
    a: *mut Admissions,
    pi: *mut OpenSslStack,
) {
    // SAFETY: `a` is live; its stack holds owned `PROFESSION_INFO`; the thunk is their destructor.
    unsafe { OPENSSL_sk_pop_free((*a).professionInfos, Some(profession_info_free_thunk)) };
    // SAFETY: `a` is live; the field slot is writable.
    unsafe { (*a).professionInfos = pi };
}

/// `const ASN1_OCTET_STRING *PROFESSION_INFO_get0_addProfessionInfo(const PROFESSION_INFO *pi)` —
/// `crypto/x509/v3_admis.c:297-300`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_get0_addProfessionInfo(
    pi: *const ProfessionInfo,
) -> *const Asn1String {
    // SAFETY: `pi` is live per the contract.
    unsafe { (*pi).addProfessionInfo }
}

/// `void PROFESSION_INFO_set0_addProfessionInfo(PROFESSION_INFO *pi, ASN1_OCTET_STRING *aos)` —
/// `crypto/x509/v3_admis.c:302-307`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`; `aos` is NULL or a string this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_set0_addProfessionInfo(
    pi: *mut ProfessionInfo,
    aos: *mut Asn1String,
) {
    // SAFETY: `pi` is live; its `addProfessionInfo` is NULL or owned.
    unsafe { ASN1_OCTET_STRING_free((*pi).addProfessionInfo) };
    // SAFETY: `pi` is live; the field slot is writable.
    unsafe { (*pi).addProfessionInfo = aos };
}

/// `const NAMING_AUTHORITY *PROFESSION_INFO_get0_namingAuthority(const PROFESSION_INFO *pi)` —
/// `crypto/x509/v3_admis.c:309-312`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_get0_namingAuthority(
    pi: *const ProfessionInfo,
) -> *const NamingAuthority {
    // SAFETY: `pi` is live per the contract.
    unsafe { (*pi).namingAuthority }
}

/// `void PROFESSION_INFO_set0_namingAuthority(PROFESSION_INFO *pi, NAMING_AUTHORITY *na)` —
/// `crypto/x509/v3_admis.c:314-319`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`; `na` is NULL or a value this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_set0_namingAuthority(
    pi: *mut ProfessionInfo,
    na: *mut NamingAuthority,
) {
    // SAFETY: `pi` is live; its `namingAuthority` is NULL or owned.
    unsafe { NAMING_AUTHORITY_free((*pi).namingAuthority) };
    // SAFETY: `pi` is live; the field slot is writable.
    unsafe { (*pi).namingAuthority = na };
}

/// `const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(const PROFESSION_INFO *pi)` —
/// `crypto/x509/v3_admis.c:321-324`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_get0_professionItems(
    pi: *const ProfessionInfo,
) -> *const OpenSslStack {
    // SAFETY: `pi` is live per the contract.
    unsafe { (*pi).professionItems }
}

/// `void PROFESSION_INFO_set0_professionItems(PROFESSION_INFO *pi, STACK_OF(ASN1_STRING) *as)` —
/// `crypto/x509/v3_admis.c:326-331`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`; `s` is NULL or an `ASN1_STRING` stack this call owns.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_set0_professionItems(
    pi: *mut ProfessionInfo,
    s: *mut OpenSslStack,
) {
    // SAFETY: `pi` is live; its stack holds owned `ASN1_STRING`; the thunk is their destructor.
    unsafe { OPENSSL_sk_pop_free((*pi).professionItems, Some(asn1_string_free_thunk)) };
    // SAFETY: `pi` is live; the field slot is writable.
    unsafe { (*pi).professionItems = s };
}

/// `const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(const PROFESSION_INFO *pi)` —
/// `crypto/x509/v3_admis.c:333-336`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_get0_professionOIDs(
    pi: *const ProfessionInfo,
) -> *const OpenSslStack {
    // SAFETY: `pi` is live per the contract.
    unsafe { (*pi).professionOIDs }
}

/// `void PROFESSION_INFO_set0_professionOIDs(PROFESSION_INFO *pi, STACK_OF(ASN1_OBJECT) *po)` —
/// `crypto/x509/v3_admis.c:338-343`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`; `po` is NULL or an `ASN1_OBJECT` stack this call owns.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_set0_professionOIDs(
    pi: *mut ProfessionInfo,
    po: *mut OpenSslStack,
) {
    // SAFETY: `pi` is live; its stack holds owned `ASN1_OBJECT`; the thunk is their destructor.
    unsafe { OPENSSL_sk_pop_free((*pi).professionOIDs, Some(asn1_object_free_thunk)) };
    // SAFETY: `pi` is live; the field slot is writable.
    unsafe { (*pi).professionOIDs = po };
}

/// `const ASN1_PRINTABLESTRING *PROFESSION_INFO_get0_registrationNumber(const PROFESSION_INFO
/// *pi)` — `crypto/x509/v3_admis.c:345-348`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_get0_registrationNumber(
    pi: *const ProfessionInfo,
) -> *const Asn1String {
    // SAFETY: `pi` is live per the contract.
    unsafe { (*pi).registrationNumber }
}

/// `void PROFESSION_INFO_set0_registrationNumber(PROFESSION_INFO *pi, ASN1_PRINTABLESTRING *rn)` —
/// `crypto/x509/v3_admis.c:350-355`.
///
/// # Safety
///
/// `pi` is a live `PROFESSION_INFO`; `rn` is NULL or a string this call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn PROFESSION_INFO_set0_registrationNumber(
    pi: *mut ProfessionInfo,
    rn: *mut Asn1String,
) {
    // SAFETY: `pi` is live; its `registrationNumber` is NULL or owned.
    unsafe { ASN1_PRINTABLESTRING_free((*pi).registrationNumber) };
    // SAFETY: `pi` is live; the field slot is writable.
    unsafe { (*pi).registrationNumber = rn };
}

// ---------------------------------------------------------------------------------------------
// The stack destructors
// ---------------------------------------------------------------------------------------------

/// `sk_ADMISSIONS_pop_free(..., ADMISSIONS_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `ADMISSIONS` (the stack contract).
unsafe extern "C" fn admissions_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ADMISSIONS` pointers per the contract.
    unsafe { ADMISSIONS_free(p.cast::<Admissions>()) };
}

/// `sk_PROFESSION_INFO_pop_free(..., PROFESSION_INFO_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `PROFESSION_INFO` (the stack contract).
unsafe extern "C" fn profession_info_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `PROFESSION_INFO` pointers per the contract.
    unsafe { PROFESSION_INFO_free(p.cast::<ProfessionInfo>()) };
}

/// `sk_ASN1_STRING_pop_free(..., ASN1_STRING_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `ASN1_STRING` (the stack contract).
unsafe extern "C" fn asn1_string_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_STRING` pointers per the contract.
    unsafe { ASN1_STRING_free(p.cast::<Asn1String>()) };
}

/// `sk_ASN1_OBJECT_pop_free(..., ASN1_OBJECT_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `ASN1_OBJECT` (the stack contract).
unsafe extern "C" fn asn1_object_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ASN1_OBJECT` pointers per the contract.
    unsafe { ASN1_OBJECT_free(p.cast::<Asn1Object>()) };
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_ext_admission` — `crypto/x509/v3_admis.c:56-68`.
///
/// `NID_x509ExtAdmission`, item [`ADMISSION_SYNTAX_it`] and the [`i2r_ADMISSION_SYNTAX`] printer;
/// every other slot is zero.
pub static ossl_v3_ext_admission: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_x509ExtAdmission,
    ext_flags: 0,
    it: Some(ADMISSION_SYNTAX_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ADMISSION_SYNTAX),
    r2i: None,
    usr_data: ptr::null_mut(),
};
