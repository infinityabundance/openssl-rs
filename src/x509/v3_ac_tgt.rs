//! `crypto/x509/v3_ac_tgt.c` — the attribute-certificate targeting-information item group and its
//! row. Phase 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_ac_tgt.c` is 253 lines and transcribes whole:
//!
//! * `OSSL_ISSUER_SERIAL ::= SEQUENCE { issuer SEQUENCE OF GENERAL_NAME, serial ASN1_INTEGER,
//!   issuerUID ASN1_BIT_STRING OPTIONAL }` (`:43-47`), `OSSL_OBJECT_DIGEST_INFO ::= SEQUENCE {
//!   digestedObjectType ASN1_ENUMERATED, otherObjectTypeID ASN1_OBJECT OPTIONAL, digestAlgorithm
//!   X509_ALGOR, objectDigest ASN1_BIT_STRING }` (`:49-55`) and `OSSL_TARGET_CERT ::= SEQUENCE {
//!   targetCertificate OSSL_ISSUER_SERIAL, targetName GENERAL_NAME OPTIONAL, certDigestInfo
//!   OSSL_OBJECT_DIGEST_INFO OPTIONAL }` (`:57-62`). All three close with a **`static_`** end macro,
//!   so their `_it` accessors are file-local; the head declares only `DECLARE_ASN1_ALLOC_FUNCTIONS`
//!   for the first two (`x509_acert.h:39-40`), so no allocator/`d2i`/`i2d` group is emitted here.
//!   This module defines the three file-local `_it` accessors the item templates name.
//! * `OSSL_TARGET ::= CHOICE { targetName [0] EXPLICIT GeneralName, targetGroup [1] EXPLICIT
//!   GeneralName, targetCert [2] IMPLICIT OSSL_TARGET_CERT }` (`:64-69`) and the two `SEQUENCE OF`
//!   item templates `OSSL_TARGETS` (`:71-72`) and `OSSL_TARGETING_INFORMATION` (`:74-75`), giving
//!   the `_it`/`_new`/`_free`/`d2i_`/`i2d_` groups of `IMPLEMENT_ASN1_FUNCTIONS` (`:77-79`).
//! * the five printers [`i2r_ISSUER_SERIAL`] (`:81-105`), [`i2r_OBJECT_DIGEST_INFO`] (`:107-167`),
//!   [`i2r_TARGET_CERT`] (`:169-189`), [`i2r_TARGET`] (`:191-212`) and [`i2r_TARGETS`]
//!   (`:214-227`), plus the row's [`i2r_TARGETING_INFORMATION`] (`:229-242`).
//! * the row [`ossl_v3_targeting_information`] (`:244-253`, `NID_target_information`).
//!
//! The one `#ifndef OPENSSL_NO_DEPRECATED_3_6` block inside [`i2r_OBJECT_DIGEST_INFO`] (`:112-115`,
//! `:149-161`) lands unconditionally: the admitted build does not define the macro, so the block is
//! compiled by the authority and reproducing it is the transcription.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the
//! array is withheld until all 63 tables exist. This unit contributes one of the 63. The row is
//! internal data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the item group and
//! the printers are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_ac_tgt.c` is not an entry in `gen_err_raise_sites.py` (the generator's covered
//! set is the closed-stratum file list), so its one coordinate is **declared locally** with the
//! `err_sites::ErrSite` shape, as `v3_bitst.rs` does. Its reason value is read from the authority's
//! `err.h`, not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_INTEGER_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_ENUMERATED_get_int64;
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT, i2a_ASN1_STRING};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::evp::pkey_asn1::EVP_PKEY_asn1_find;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{
    Asn1Object, NID_target_information, NID_undef, OBJ_find_sigid_algs, OBJ_obj2nid,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::t_x509::X509_signature_dump;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::v3_utl::OSSL_GENERAL_NAMES_print;

/// `ERR_LIB_ASN1` — `include/openssl/err.h.in:87`.
const ERR_LIB_ASN1: c_int = 13;
/// `ERR_R_PASSED_NULL_PARAMETER` — `include/openssl/err.h.in:356`, `258 | ERR_R_FATAL`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;

/// One `v3_ac_tgt.c` raise coordinate, declared locally (see the module doc).
const fn v3_ac_tgt_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_ac_tgt.c",
        line,
        func,
        lib: ERR_LIB_ASN1,
        reason,
        dynamic_reason: false,
    }
}

/// `i2r_OBJECT_DIGEST_INFO`'s NULL `odi` at `v3_ac_tgt.c:119`.
const V3_AC_TGT_119: ErrSite =
    v3_ac_tgt_site(119, c"i2r_OBJECT_DIGEST_INFO", ERR_R_PASSED_NULL_PARAMETER);

/// `OSSL_ODI_TYPE_PUBLIC_KEY` — `crypto/x509_acert.h:16`.
const OSSL_ODI_TYPE_PUBLIC_KEY: i64 = 0;
/// `OSSL_ODI_TYPE_PUBLIC_KEY_CERT` — `crypto/x509_acert.h:17`.
const OSSL_ODI_TYPE_PUBLIC_KEY_CERT: i64 = 1;
/// `OSSL_ODI_TYPE_OTHER` — `crypto/x509_acert.h:18`.
const OSSL_ODI_TYPE_OTHER: i64 = 2;

/// `OSSL_TGT_TARGET_NAME` — `include/openssl/x509_acert.h:195`.
const OSSL_TGT_TARGET_NAME: c_int = 0;
/// `OSSL_TGT_TARGET_GROUP` — `include/openssl/x509_acert.h:196`.
const OSSL_TGT_TARGET_GROUP: c_int = 1;
/// `OSSL_TGT_TARGET_CERT` — `include/openssl/x509_acert.h:197`.
const OSSL_TGT_TARGET_CERT: c_int = 2;

// ---------------------------------------------------------------------------------------------
// The `OSSL_ISSUER_SERIAL` SEQUENCE item — `ASN1_SEQUENCE(OSSL_ISSUER_SERIAL)` (`:43-47`)
// ---------------------------------------------------------------------------------------------

/// `struct ossl_issuer_serial_st` — `OSSL_ISSUER_SERIAL`, from `crypto/x509_acert.h:27-31`.
#[repr(C)]
pub struct OsslIssuerSerial {
    /// `STACK_OF(GENERAL_NAME) *issuer` — the `GENERAL_NAMES`, a `SEQUENCE OF`.
    pub issuer: *mut OpenSslStack,
    /// `ASN1_INTEGER serial` — embedded.
    pub serial: Asn1String,
    /// `ASN1_BIT_STRING *issuerUID` — optional.
    pub issuerUID: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OsslIssuerSerial>() == 40);
    assert!(core::mem::offset_of!(OsslIssuerSerial, issuer) == 0);
    assert!(core::mem::offset_of!(OsslIssuerSerial, serial) == 8);
    assert!(core::mem::offset_of!(OsslIssuerSerial, issuerUID) == 32);
};

/// `OSSL_ISSUER_SERIAL_seq_tt` — `ASN1_SEQUENCE(OSSL_ISSUER_SERIAL)` (`crypto/x509/v3_ac_tgt.c:43-46`):
/// `ASN1_SEQUENCE_OF(OSSL_ISSUER_SERIAL, issuer, GENERAL_NAME)`,
/// `ASN1_EMBED(OSSL_ISSUER_SERIAL, serial, ASN1_INTEGER)` and
/// `ASN1_OPT(OSSL_ISSUER_SERIAL, issuerUID, ASN1_BIT_STRING)`.
static OSSL_ISSUER_SERIAL_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"serial".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 32,
        field_name: c"issuerUID".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `OSSL_ISSUER_SERIAL_it`'s descriptor — `static_ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)` at
/// `crypto/x509/v3_ac_tgt.c:47`. The `static_` end macro keeps the accessor file-local.
static OSSL_ISSUER_SERIAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ISSUER_SERIAL_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslIssuerSerial>() as c_long,
    sname: c"OSSL_ISSUER_SERIAL".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *OSSL_ISSUER_SERIAL_it(void)` — `static_ASN1_ITEM_start` at
/// `crypto/x509/v3_ac_tgt.c:47`. No `#[no_mangle]`: the C accessor is `static`.
fn ossl_issuer_serial_it() -> *const Asn1Item {
    &OSSL_ISSUER_SERIAL_ITEM
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_OBJECT_DIGEST_INFO` SEQUENCE item — `ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO)` (`:49-55`)
// ---------------------------------------------------------------------------------------------

/// `struct ossl_object_digest_info_st` — `OSSL_OBJECT_DIGEST_INFO`, from `crypto/x509_acert.h:20-25`.
#[repr(C)]
pub struct OsslObjectDigestInfo {
    /// `ASN1_ENUMERATED digestedObjectType` — embedded.
    pub digestedObjectType: Asn1String,
    /// `ASN1_OBJECT *otherObjectTypeID` — optional.
    pub otherObjectTypeID: *mut Asn1Object,
    /// `X509_ALGOR digestAlgorithm` — embedded.
    pub digestAlgorithm: X509Algor,
    /// `ASN1_BIT_STRING objectDigest` — embedded.
    pub objectDigest: Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<OsslObjectDigestInfo>() == 72);
    assert!(core::mem::offset_of!(OsslObjectDigestInfo, digestedObjectType) == 0);
    assert!(core::mem::offset_of!(OsslObjectDigestInfo, otherObjectTypeID) == 24);
    assert!(core::mem::offset_of!(OsslObjectDigestInfo, digestAlgorithm) == 32);
    assert!(core::mem::offset_of!(OsslObjectDigestInfo, objectDigest) == 48);
};

/// `OSSL_OBJECT_DIGEST_INFO_seq_tt` — `ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO)`
/// (`crypto/x509/v3_ac_tgt.c:49-54`): `ASN1_EMBED(..., digestedObjectType, ASN1_ENUMERATED)`,
/// `ASN1_OPT(..., otherObjectTypeID, ASN1_OBJECT)`, `ASN1_EMBED(..., digestAlgorithm, X509_ALGOR)`
/// and `ASN1_EMBED(..., objectDigest, ASN1_BIT_STRING)`.
static OSSL_OBJECT_DIGEST_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"digestedObjectType".as_ptr(),
        item: ASN1_ENUMERATED_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"otherObjectTypeID".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 32,
        field_name: c"digestAlgorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 48,
        field_name: c"objectDigest".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `OSSL_OBJECT_DIGEST_INFO_it`'s descriptor — `static_ASN1_SEQUENCE_END(OSSL_OBJECT_DIGEST_INFO)` at
/// `crypto/x509/v3_ac_tgt.c:55`.
static OSSL_OBJECT_DIGEST_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_OBJECT_DIGEST_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslObjectDigestInfo>() as c_long,
    sname: c"OSSL_OBJECT_DIGEST_INFO".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *OSSL_OBJECT_DIGEST_INFO_it(void)` —
/// `static_ASN1_ITEM_start` at `crypto/x509/v3_ac_tgt.c:55`.
fn ossl_object_digest_info_it() -> *const Asn1Item {
    &OSSL_OBJECT_DIGEST_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_TARGET_CERT` SEQUENCE item — `ASN1_SEQUENCE(OSSL_TARGET_CERT)` (`:57-62`)
// ---------------------------------------------------------------------------------------------

/// `struct TARGET_CERT_st` — `OSSL_TARGET_CERT`, from `include/openssl/x509_acert.h:187-193`.
#[repr(C)]
pub struct OsslTargetCert {
    /// `OSSL_ISSUER_SERIAL *targetCertificate`.
    pub targetCertificate: *mut OsslIssuerSerial,
    /// `GENERAL_NAME *targetName` — optional.
    pub targetName: *mut GeneralName,
    /// `OSSL_OBJECT_DIGEST_INFO *certDigestInfo` — optional.
    pub certDigestInfo: *mut OsslObjectDigestInfo,
}

const _: () = {
    assert!(core::mem::size_of::<OsslTargetCert>() == 24);
    assert!(core::mem::offset_of!(OsslTargetCert, targetCertificate) == 0);
    assert!(core::mem::offset_of!(OsslTargetCert, targetName) == 8);
    assert!(core::mem::offset_of!(OsslTargetCert, certDigestInfo) == 16);
};

/// `OSSL_TARGET_CERT_seq_tt` — `ASN1_SEQUENCE(OSSL_TARGET_CERT)` (`crypto/x509/v3_ac_tgt.c:57-61`):
/// `ASN1_SIMPLE(..., targetCertificate, OSSL_ISSUER_SERIAL)`,
/// `ASN1_OPT(..., targetName, GENERAL_NAME)` and `ASN1_OPT(..., certDigestInfo,
/// OSSL_OBJECT_DIGEST_INFO)`.
static OSSL_TARGET_CERT_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"targetCertificate".as_ptr(),
        item: ossl_issuer_serial_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"targetName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"certDigestInfo".as_ptr(),
        item: ossl_object_digest_info_it as *mut c_void,
    },
];

/// `OSSL_TARGET_CERT_it`'s descriptor — `static_ASN1_SEQUENCE_END(OSSL_TARGET_CERT)` at
/// `crypto/x509/v3_ac_tgt.c:62`.
static OSSL_TARGET_CERT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_TARGET_CERT_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTargetCert>() as c_long,
    sname: c"OSSL_TARGET_CERT".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *OSSL_TARGET_CERT_it(void)` — `static_ASN1_ITEM_start` at
/// `crypto/x509/v3_ac_tgt.c:62`.
fn ossl_target_cert_it() -> *const Asn1Item {
    &OSSL_TARGET_CERT_ITEM
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_TARGET` CHOICE item — `ASN1_CHOICE(OSSL_TARGET)` (`:64-69`)
// ---------------------------------------------------------------------------------------------

/// The `type`-selected union of `struct TARGET_st` — `include/openssl/x509_acert.h:201-205`. All
/// three arms are pointer-sized, so the union begins at the structure's `choice` offset.
#[repr(C)]
pub union OsslTargetChoice {
    /// `GENERAL_NAME *targetName` — the `[0]` arm.
    pub targetName: *mut GeneralName,
    /// `GENERAL_NAME *targetGroup` — the `[1]` arm.
    pub targetGroup: *mut GeneralName,
    /// `OSSL_TARGET_CERT *targetCert` — the `[2]` arm.
    pub targetCert: *mut OsslTargetCert,
}

/// `struct TARGET_st` — `OSSL_TARGET`, from `include/openssl/x509_acert.h:199-206`.
#[repr(C)]
pub struct OsslTarget {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ... } choice`.
    pub choice: OsslTargetChoice,
}

const _: () = {
    assert!(core::mem::size_of::<OsslTarget>() == 16);
    assert!(core::mem::offset_of!(OsslTarget, type_) == 0);
    assert!(core::mem::offset_of!(OsslTarget, choice) == 8);
};

/// `OSSL_TARGET_ch_tt` — `ASN1_CHOICE(OSSL_TARGET)` (`crypto/x509/v3_ac_tgt.c:64-69`):
/// `ASN1_EXP(..., choice.targetName, GENERAL_NAME, 0)`,
/// `ASN1_EXP(..., choice.targetGroup, GENERAL_NAME, 1)` and
/// `ASN1_IMP(..., choice.targetCert, OSSL_TARGET_CERT, 2)`. The two `EXPLICIT` arms carry the
/// implicit `ASN1_TFLG_EXPLICIT` and the third the `ASN1_TFLG_IMPLICIT`; every arm lives at the
/// union's offset, 8.
static OSSL_TARGET_CH_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"choice.targetName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"choice.targetGroup".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"choice.targetCert".as_ptr(),
        item: ossl_target_cert_it as *mut c_void,
    },
];

/// `OSSL_TARGET_it`'s descriptor — `ASN1_CHOICE_END(OSSL_TARGET)` at `crypto/x509/v3_ac_tgt.c:69`.
/// The `utype` of a `CHOICE` is the selector's offset; `funcs` is NULL (the item carries no
/// `ASN1_AUX`).
static OSSL_TARGET_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(OsslTarget, type_) as c_long,
    templates: OSSL_TARGET_CH_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslTarget>() as c_long,
    sname: c"OSSL_TARGET".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_TARGET_it(void)` — `include/openssl/x509_acert.h:271`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_TARGET)`.
#[no_mangle]
pub extern "C" fn OSSL_TARGET_it() -> *const Asn1Item {
    &OSSL_TARGET_ITEM
}

/// `OSSL_TARGET *OSSL_TARGET_new(void)` — `crypto/x509/v3_ac_tgt.c:77`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_TARGET)`.
#[no_mangle]
pub extern "C" fn OSSL_TARGET_new() -> *mut OsslTarget {
    // SAFETY: `OSSL_TARGET_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_TARGET_it()).cast::<OsslTarget>() }
}

/// `void OSSL_TARGET_free(OSSL_TARGET *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TARGET_free(a: *mut OsslTarget) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_TARGET_it()) }
}

/// `OSSL_TARGET *d2i_OSSL_TARGET(OSSL_TARGET **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TARGET(
    a: *mut *mut OsslTarget,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslTarget {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_TARGET_it()).cast::<OsslTarget>() }
}

/// `int i2d_OSSL_TARGET(const OSSL_TARGET *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TARGET(a: *const OsslTarget, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TARGET_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_TARGETS` and `OSSL_TARGETING_INFORMATION` SEQUENCE OF templates (`:71-75`)
// ---------------------------------------------------------------------------------------------

/// `OSSL_TARGETS_item_tt` — `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Targets, OSSL_TARGET)`
/// at `crypto/x509/v3_ac_tgt.c:71`. The value is a `STACK_OF(OSSL_TARGET)`.
static OSSL_TARGETS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"Targets".as_ptr(),
    item: OSSL_TARGET_it as *mut c_void,
};

/// `OSSL_TARGETS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(OSSL_TARGETS)` at
/// `crypto/x509/v3_ac_tgt.c:72`: a `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`,
/// `tcount` 0.
static OSSL_TARGETS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_TARGETS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_TARGETS".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_TARGETS_it(void)` — `include/openssl/x509_acert.h:272`.
#[no_mangle]
pub extern "C" fn OSSL_TARGETS_it() -> *const Asn1Item {
    &OSSL_TARGETS_ITEM
}

/// `OSSL_TARGETS *OSSL_TARGETS_new(void)` — `crypto/x509/v3_ac_tgt.c:78`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_TARGETS)`.
#[no_mangle]
pub extern "C" fn OSSL_TARGETS_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_TARGETS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_TARGETS_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_TARGETS_free(OSSL_TARGETS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TARGETS_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_TARGETS_it()) }
}

/// `OSSL_TARGETS *d2i_OSSL_TARGETS(OSSL_TARGETS **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TARGETS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_TARGETS_it()).cast::<OpenSslStack>() }
}

/// `int i2d_OSSL_TARGETS(const OSSL_TARGETS *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TARGETS(a: *const OpenSslStack, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TARGETS_it()) }
}

/// `OSSL_TARGETING_INFORMATION_item_tt` —
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, TargetingInformation, OSSL_TARGETS)` at
/// `crypto/x509/v3_ac_tgt.c:74`. The value is a `STACK_OF(OSSL_TARGETS)`.
static OSSL_TARGETING_INFORMATION_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"TargetingInformation".as_ptr(),
    item: OSSL_TARGETS_it as *mut c_void,
};

/// `OSSL_TARGETING_INFORMATION_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(OSSL_TARGETING_INFORMATION)`
/// at `crypto/x509/v3_ac_tgt.c:75`.
static OSSL_TARGETING_INFORMATION_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_TARGETING_INFORMATION_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_TARGETING_INFORMATION".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_TARGETING_INFORMATION_it(void)` — `include/openssl/x509_acert.h:273`.
#[no_mangle]
pub extern "C" fn OSSL_TARGETING_INFORMATION_it() -> *const Asn1Item {
    &OSSL_TARGETING_INFORMATION_ITEM
}

/// `OSSL_TARGETING_INFORMATION *OSSL_TARGETING_INFORMATION_new(void)` —
/// `crypto/x509/v3_ac_tgt.c:79`, from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_TARGETING_INFORMATION)`.
#[no_mangle]
pub extern "C" fn OSSL_TARGETING_INFORMATION_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_TARGETING_INFORMATION_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_TARGETING_INFORMATION_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_TARGETING_INFORMATION_free(OSSL_TARGETING_INFORMATION *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_TARGETING_INFORMATION_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_TARGETING_INFORMATION_it()) }
}

/// `OSSL_TARGETING_INFORMATION *d2i_OSSL_TARGETING_INFORMATION(OSSL_TARGETING_INFORMATION **a,
/// const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_TARGETING_INFORMATION(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_TARGETING_INFORMATION_it()).cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_TARGETING_INFORMATION(const OSSL_TARGETING_INFORMATION *a, unsigned char **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_TARGETING_INFORMATION(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_TARGETING_INFORMATION_it()) }
}

// ---------------------------------------------------------------------------------------------
// The five printers (`:81-242`)
// ---------------------------------------------------------------------------------------------

/// `static int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method, OSSL_ISSUER_SERIAL *iss, BIO *out,
/// int indent)` — `crypto/x509/v3_ac_tgt.c:81-105`.
///
/// # Safety
///
/// `out` is a live BIO; `iss` is a live `OSSL_ISSUER_SERIAL`.
unsafe extern "C" fn i2r_ISSUER_SERIAL(
    _method: *const X509V3ExtMethod,
    iss: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let iss = iss.cast::<OsslIssuerSerial>();
    // SAFETY: `iss` is live per the contract.
    if !unsafe { (*iss).issuer }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sIssuer Names:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live and `iss`'s `issuer` is a live `GENERAL_NAMES`.
        unsafe { OSSL_GENERAL_NAMES_print(out, (*iss).issuer, indent) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sIssuer Names: <none>\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_printf(out, c"%*sIssuer Serial: ".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `out` and `iss` are live; the embedded integer is at `serial`.
    if unsafe { i2a_ASN1_INTEGER(out, &raw const (*iss).serial) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    // SAFETY: `iss` is live.
    if !unsafe { (*iss).issuerUID }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sIssuer UID: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` and `iss` are live; `issuerUID` is a live bit string.
        if unsafe { i2a_ASN1_STRING(out, (*iss).issuerUID, V_ASN1_BIT_STRING) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sIssuer UID: <none>\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    }
    1
}

/// `static int i2r_OBJECT_DIGEST_INFO(X509V3_EXT_METHOD *method, OSSL_OBJECT_DIGEST_INFO *odi,
/// BIO *out, int indent)` — `crypto/x509/v3_ac_tgt.c:107-167`.
///
/// # Safety
///
/// `out` is a live BIO; `odi` is a live `OSSL_OBJECT_DIGEST_INFO`.
unsafe extern "C" fn i2r_OBJECT_DIGEST_INFO(
    _method: *const X509V3ExtMethod,
    odi: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let mut dot: i64 = 0;
    let odi = odi.cast::<OsslObjectDigestInfo>();

    if odi.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_AC_TGT_119) };
        return 0;
    }
    // SAFETY: `odi` is non-NULL and live per the contract.
    let sig: *mut Asn1String = unsafe { &raw mut (*odi).objectDigest };
    // SAFETY: `odi` is live; the embedded enumerated is read into `dot`.
    if unsafe { ASN1_ENUMERATED_get_int64(&mut dot, &raw const (*odi).digestedObjectType) } == 0 {
        return 0;
    }
    if dot == OSSL_ODI_TYPE_PUBLIC_KEY {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sDigest Type: Public Key\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    } else if dot == OSSL_ODI_TYPE_PUBLIC_KEY_CERT {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sDigest Type: Public Key Certificate\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    } else if dot == OSSL_ODI_TYPE_OTHER {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sDigest Type: Other\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    }
    // SAFETY: `odi` is live.
    if !unsafe { (*odi).otherObjectTypeID }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sDigest Type Identifier: ".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
        // SAFETY: `out` is live and `odi`'s `otherObjectTypeID` is a live object.
        unsafe { i2a_ASN1_OBJECT(out, (*odi).otherObjectTypeID) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe {
        BIO_printf(
            out,
            c"%*sSignature Algorithm: ".as_ptr(),
            indent,
            c"".as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `out` is live and `odi`'s algorithm OID is live.
    if unsafe { i2a_ASN1_OBJECT(out, (*odi).digestAlgorithm.algorithm) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    // SAFETY: `out` is live; the literal is static.
    if unsafe {
        BIO_printf(
            out,
            c"\n%*sSignature Value: ".as_ptr(),
            indent,
            c"".as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // The authority's `#ifndef OPENSSL_NO_DEPRECATED_3_6` block (`:149-161`), compiled in the
    // admitted build: a known signature NID with an ameth `sig_print` prints through it.
    // SAFETY: `odi` is live; the embedded algorithm's OID slot is readable.
    let sig_nid = unsafe { OBJ_obj2nid((*odi).digestAlgorithm.algorithm) };
    if sig_nid != NID_undef {
        let mut dig_nid: c_int = 0;
        let mut pkey_nid: c_int = 0;
        // SAFETY: both output slots are this frame's own.
        if unsafe { OBJ_find_sigid_algs(sig_nid, &mut dig_nid, &mut pkey_nid) } != 0 {
            // SAFETY: no preconditions; the lookup searches this crate's own tables.
            let ameth = unsafe { EVP_PKEY_asn1_find(ptr::null_mut(), pkey_nid) };
            if !ameth.is_null() {
                // SAFETY: `ameth` is a live method row.
                if let Some(sig_print) = unsafe { (*ameth).sig_print } {
                    // SAFETY: `odi` is live; the embedded algorithm's address is valid.
                    let digalg = unsafe { &raw const (*odi).digestAlgorithm };
                    // SAFETY: `out` and `sig` are live; `digalg` is `odi`'s live algorithm; the last
                    // argument is the authority's NULL `ASN1_PCTX`.
                    return unsafe { sig_print(out, digalg, sig, indent + 4, ptr::null_mut()) };
                }
            }
        }
    }
    // SAFETY: `out` is live; the literal is static.
    if unsafe { BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1) } != 1 {
        return 0;
    }
    if !sig.is_null() {
        // SAFETY: `out` is live and `sig` is `odi`'s live object digest.
        return unsafe { X509_signature_dump(out, sig, indent + 4) };
    }
    1
}

/// `static int i2r_TARGET_CERT(X509V3_EXT_METHOD *method, OSSL_TARGET_CERT *tc, BIO *out,
/// int indent)` — `crypto/x509/v3_ac_tgt.c:169-189`.
///
/// # Safety
///
/// `out` is a live BIO; `tc` is a live `OSSL_TARGET_CERT`.
unsafe extern "C" fn i2r_TARGET_CERT(
    method: *const X509V3ExtMethod,
    tc: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let tc = tc.cast::<OsslTargetCert>();
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `tc` is live.
    if !unsafe { (*tc).targetCertificate }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"Target Certificate:\n".as_ptr()) };
        // SAFETY: `out` is live and `tc`'s `targetCertificate` is live.
        unsafe {
            i2r_ISSUER_SERIAL(
                method,
                (*tc).targetCertificate.cast::<c_void>(),
                out,
                indent + 2,
            )
        };
    }
    // SAFETY: `tc` is live.
    if !unsafe { (*tc).targetName }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTarget Name: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live and `tc`'s `targetName` is a live general name.
        unsafe { GENERAL_NAME_print(out, (*tc).targetName) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
    // SAFETY: `tc` is live.
    if !unsafe { (*tc).certDigestInfo }.is_null() {
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sCertificate Digest Info:\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
        // SAFETY: `out` is live and `tc`'s `certDigestInfo` is live.
        unsafe {
            i2r_OBJECT_DIGEST_INFO(
                method,
                (*tc).certDigestInfo.cast::<c_void>(),
                out,
                indent + 2,
            )
        };
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    1
}

/// `static int i2r_TARGET(X509V3_EXT_METHOD *method, OSSL_TARGET *target, BIO *out, int indent)` —
/// `crypto/x509/v3_ac_tgt.c:191-212`.
///
/// # Safety
///
/// `out` is a live BIO; `target` is a live `OSSL_TARGET`.
unsafe extern "C" fn i2r_TARGET(
    method: *const X509V3ExtMethod,
    target: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let target = target.cast::<OsslTarget>();
    // SAFETY: `target` is live.
    let type_ = unsafe { (*target).type_ };
    if type_ == OSSL_TGT_TARGET_NAME {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTarget Name: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `target`'s selector selects the live `targetName` union member.
        unsafe { GENERAL_NAME_print(out, (*target).choice.targetName) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else if type_ == OSSL_TGT_TARGET_GROUP {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTarget Group: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `target`'s selector selects the live `targetGroup` union member.
        unsafe { GENERAL_NAME_print(out, (*target).choice.targetGroup) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else if type_ == OSSL_TGT_TARGET_CERT {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTarget Cert:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `target`'s selector selects the live `targetCert` union member.
        unsafe {
            i2r_TARGET_CERT(
                method,
                (*target).choice.targetCert.cast::<c_void>(),
                out,
                indent + 2,
            )
        };
    }
    1
}

/// `static int i2r_TARGETS(X509V3_EXT_METHOD *method, OSSL_TARGETS *targets, BIO *out, int indent)`
/// — `crypto/x509/v3_ac_tgt.c:214-227`.
///
/// # Safety
///
/// `out` is a live BIO; `targets` is a live `STACK_OF(OSSL_TARGET)`.
unsafe extern "C" fn i2r_TARGETS(
    method: *const X509V3ExtMethod,
    targets: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let targets = targets.cast::<OpenSslStack>();
    // SAFETY: `targets` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(targets) };
    let mut i = 0;
    while i < num {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTarget:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `targets` is live and `i` is in bounds.
        let target = unsafe { OPENSSL_sk_value(targets, i) };
        // SAFETY: `out` is live and `target` is a live `OSSL_TARGET`.
        unsafe { i2r_TARGET(method, target, out, indent + 2) };
        i += 1;
    }
    1
}

/// `static int i2r_TARGETING_INFORMATION(X509V3_EXT_METHOD *method, OSSL_TARGETING_INFORMATION
/// *tinfo, BIO *out, int indent)` — `crypto/x509/v3_ac_tgt.c:229-242`.
///
/// # Safety
///
/// `out` is a live BIO; `tinfo` is a live `STACK_OF(OSSL_TARGETS)`.
unsafe extern "C" fn i2r_TARGETING_INFORMATION(
    method: *const X509V3ExtMethod,
    tinfo: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let tinfo = tinfo.cast::<OpenSslStack>();
    // SAFETY: `tinfo` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(tinfo) };
    let mut i = 0;
    while i < num {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sTargets:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `tinfo` is live and `i` is in bounds.
        let targets = unsafe { OPENSSL_sk_value(tinfo, i) };
        // SAFETY: `out` is live and `targets` is a live `OSSL_TARGETS`.
        unsafe { i2r_TARGETS(method, targets, out, indent + 2) };
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_targeting_information` — `crypto/x509/v3_ac_tgt.c:244-253`.
///
/// `NID_target_information`, item [`OSSL_TARGETING_INFORMATION_it`] and the
/// [`i2r_TARGETING_INFORMATION`] printer; every other slot is zero.
pub static ossl_v3_targeting_information: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_target_information,
    ext_flags: 0,
    it: Some(OSSL_TARGETING_INFORMATION_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_TARGETING_INFORMATION),
    r2i: None,
    usr_data: ptr::null_mut(),
};
