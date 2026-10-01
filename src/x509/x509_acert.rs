//! `crypto/x509/x509_acert.c` -- the `X509_ACERT` attribute-certificate item group, its
//! accessors, its attribute/extension surface and its PEM spellings. Phase 11.3.
//!
//! `crypto/x509/x509_acert.c` is 326 lines and lands whole here: the seven item templates, the
//! six `IMPLEMENT_ASN1_*` groups, the PEM spellings and the accessor/attribute/extension surface.
//! **Nothing in this unit is withheld and nothing is stubbed.** The attribute certificate's two
//! printers are a *different* unit, `crypto/x509/t_acert.c`, and are addressed (and withheld) in
//! `src/x509/t_acert.rs`.
//!
//! ```text
//! X509_ACERT ::= SEQUENCE {
//!   acinfo     X509_ACERT_INFO,
//!   sig_alg    X509_ALGOR,
//!   signature  ASN1_BIT_STRING
//! }
//! X509_ACERT_INFO ::= SEQUENCE {
//!   version         ASN1_INTEGER,        -- default v2
//!   holder          X509_HOLDER,
//!   issuer          X509_ACERT_ISSUER,   -- CHOICE
//!   signature       X509_ALGOR,
//!   serialNumber    ASN1_INTEGER,
//!   validityPeriod  X509_VAL,
//!   attributes      SEQUENCE OF X509_ATTRIBUTE,
//!   issuerUID       ASN1_BIT_STRING OPTIONAL,
//!   extensions      SEQUENCE OF X509_EXTENSION OPTIONAL
//! }
//! ```
//!
//! * The seven item templates of `:22-68` and the six `IMPLEMENT_ASN1_*` groups of `:70-75`:
//!   `X509_ACERT`'s `_it`/`_new`/`_free`/`d2i_`/`i2d_`/`_dup_` group, `X509_ACERT_INFO`'s
//!   `_it`/`_new`/`_free`, and `_new`/`_free` for `OSSL_ISSUER_SERIAL`,
//!   `OSSL_OBJECT_DIGEST_INFO` and `X509_ACERT_ISSUER_V2FORM`. The five internal `_it`
//!   accessors the templates name are file-local (the authority's `x509_acert.h:17-21` declares
//!   them `DECLARE_ASN1_ITEM`, and the admitted DSO's version script hides them).
//! * `IMPLEMENT_PEM_rw(X509_ACERT, X509_ACERT, PEM_STRING_ACERT, X509_ACERT)` (`:77`, the
//!   header is `"ATTRIBUTE CERTIFICATE"`, `include/openssl/pem.h:62`), giving the four
//!   `PEM_read[_bio]_X509_ACERT`/`PEM_write[_bio]_X509_ACERT` names.
//! * the thirteen `get0`/`get_` accessors (`:79-188`, `:314-327`), the eight attribute
//!   containers (`:190-247`), `check_asn1_attribute`/`X509_ACERT_add_attr_nconf` (`:249-312`)
//!   and the three extension containers (`:314-327`).
//!
//! ## The `holder`/`issuer` layouts
//!
//! The embedded `X509_HOLDER` (`:47-51`), the `X509_ACERT_ISSUER` CHOICE (`:39-45`) and its
//! `X509_ACERT_ISSUER_V2FORM` arm (`:33-37`) are the authority's own; their offsets and the
//! enclosing `X509_acert_info_st`/`X509_acert_st` (`:53-69`) are asserted below. The two leaf
//! structures `OSSL_ISSUER_SERIAL`/`OSSL_OBJECT_DIGEST_INFO` are `crate::x509::v3_ac_tgt`'s
//! already (that unit defines the same two templates at `v3_ac_tgt.c:43-55`), so this module
//! reuses those layouts and declares its own copies of the two items, exactly as the authority
//! has two translation units each defining the template.
//!
//! ## The raise sites
//!
//! `crypto/x509/x509_acert.c` is not an entry in `gen_err_raise_sites.py` (the generator's
//! covered set is the closed-stratum file list), so its one hand-raised coordinate is
//! **declared locally**: `X509_ACERT_add_attr_nconf`'s NULL-value refusal at `:278`
//! (`ERR_raise_data(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES, "name=%s,section=%s", ...)`).
//! Its reason value is read from the authority's `x509err.h`, not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_type::{i2d_ASN1_TYPE, ASN1_TYPE_free};
use crate::asn1::asn1_gen::ASN1_generate_nconf;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_INTEGER_it, ASN1_OBJECT_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{ASN1_ENUMERATED_get, ASN1_INTEGER_get};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::asn1::x_val::{X509Val, X509_VAL_it};
use crate::evp::pem_bridge::PemPasswordCb;
use crate::pem::pem_lib::{PEM_ASN1_read, PEM_ASN1_write, PEM_ASN1_write_bio};
use crate::pem::pem_oth::PEM_ASN1_read_bio;
use crate::runtime::bio::Bio;
use crate::runtime::conf::lib::NCONF_get_section;
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::ctype::ossl_isspace;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{Asn1Object, OBJ_obj2nid};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_ac_tgt::{OsslIssuerSerial, OsslObjectDigestInfo};
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName, GEN_DIRNAME};
use crate::x509::v3_lib::{X509V3_add1_i2d, X509V3_get_d2i};
use crate::x509::x509_att::{
    X509at_add1_attr, X509at_add1_attr_by_NID, X509at_add1_attr_by_OBJ, X509at_add1_attr_by_txt,
    X509at_delete_attr, X509at_get_attr, X509at_get_attr_by_NID, X509at_get_attr_by_OBJ,
    X509at_get_attr_count,
};
use crate::x509::x_attrib::{X509Attribute, X509_ATTRIBUTE_it};
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::X509Name;

/// `X509_ACERT_ISSUER_V2` -- `crypto/x509/x509_acert.h:15`, `1`. The selector
/// `X509_ACERT_ISSUER` takes when its union holds a `v2Form`.
pub(crate) const X509_ACERT_ISSUER_V2: c_int = 1;

/// `PEM_STRING_ACERT` -- `include/openssl/pem.h:62`, the header
/// `IMPLEMENT_PEM_rw(X509_ACERT, ...)` writes and its reader looks for.
const PEM_STRING_ACERT: *const c_char = c"ATTRIBUTE CERTIFICATE".as_ptr();

/// `ERR_LIB_X509` -- `include/openssl/err.h.in:85`, `11`.
const ERR_LIB_X509: c_int = 11;
/// `X509_R_INVALID_ATTRIBUTES` -- `include/openssl/x509err.h:36`, `138`.
const X509_R_INVALID_ATTRIBUTES: c_int = 138;

/// The translation unit `X509_ACERT_add_attr_nconf`'s `OPENSSL_free` names.
const FILE: &core::ffi::CStr = c"crypto/x509/x509_acert.c";
/// `X509_ACERT_add_attr_nconf`'s `OPENSSL_free(att_data)` at `x509_acert.c:295`.
const LINE_FREE_ATTDATA: c_int = 295;

/// One `x509_acert.c` raise coordinate, declared locally (see the module doc).
const fn x509_acert_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_acert.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `X509_ACERT_add_attr_nconf`'s NULL-value refusal at `x509_acert.c:278`.
const X509_ACERT_278: ErrSite =
    x509_acert_site(278, c"X509_ACERT_add_attr_nconf", X509_R_INVALID_ATTRIBUTES);

// ---------------------------------------------------------------------------------------------
// The layouts -- `crypto/x509/x509_acert.h:20-69`
// ---------------------------------------------------------------------------------------------

/// `struct X509_acert_issuer_v2form_st` -- `X509_ACERT_ISSUER_V2FORM`, from
/// `include/crypto/x509_acert.h:33-37`.
#[repr(C)]
pub struct X509AcertIssuerV2form {
    /// `STACK_OF(GENERAL_NAME) *issuerName` -- an optional `SEQUENCE OF`.
    pub issuerName: *mut OpenSslStack,
    /// `OSSL_ISSUER_SERIAL *baseCertificateId` -- an implicit `[0]`, optional.
    pub baseCertificateId: *mut OsslIssuerSerial,
    /// `OSSL_OBJECT_DIGEST_INFO *objectDigestInfo` -- an implicit `[1]`, optional.
    pub objectDigestInfo: *mut OsslObjectDigestInfo,
}

const _: () = {
    assert!(core::mem::size_of::<X509AcertIssuerV2form>() == 24);
    assert!(core::mem::offset_of!(X509AcertIssuerV2form, issuerName) == 0);
    assert!(core::mem::offset_of!(X509AcertIssuerV2form, baseCertificateId) == 8);
    assert!(core::mem::offset_of!(X509AcertIssuerV2form, objectDigestInfo) == 16);
};

/// The `type`-selected union of `struct X509_acert_issuer_st` -- `include/crypto/x509_acert.h:41-44`.
#[repr(C)]
pub union X509AcertIssuerChoice {
    /// `STACK_OF(GENERAL_NAME) *v1Form` -- the `[0]` `SEQUENCE OF` arm.
    pub v1Form: *mut OpenSslStack,
    /// `X509_ACERT_ISSUER_V2FORM *v2Form` -- the implicit `[0]`-tagged arm.
    pub v2Form: *mut X509AcertIssuerV2form,
}

/// `struct X509_acert_issuer_st` -- `X509_ACERT_ISSUER`, from `include/crypto/x509_acert.h:39-45`.
#[repr(C)]
pub struct X509AcertIssuer {
    /// `int type` -- the CHOICE selector.
    pub type_: c_int,
    /// `union { ... } u`.
    pub u: X509AcertIssuerChoice,
}

const _: () = {
    assert!(core::mem::size_of::<X509AcertIssuer>() == 16);
    assert!(core::mem::offset_of!(X509AcertIssuer, type_) == 0);
    assert!(core::mem::offset_of!(X509AcertIssuer, u) == 8);
};

/// `struct X509_holder_st` -- `X509_HOLDER`, from `include/crypto/x509_acert.h:47-51`.
#[repr(C)]
pub struct X509Holder {
    /// `OSSL_ISSUER_SERIAL *baseCertificateID` -- an implicit `[0]`, optional.
    pub baseCertificateID: *mut OsslIssuerSerial,
    /// `STACK_OF(GENERAL_NAME) *entityName` -- an implicit `[1]` `SEQUENCE OF`, optional.
    pub entityName: *mut OpenSslStack,
    /// `OSSL_OBJECT_DIGEST_INFO *objectDigestInfo` -- an implicit `[2]`, optional.
    pub objectDigestInfo: *mut OsslObjectDigestInfo,
}

const _: () = {
    assert!(core::mem::size_of::<X509Holder>() == 24);
    assert!(core::mem::offset_of!(X509Holder, baseCertificateID) == 0);
    assert!(core::mem::offset_of!(X509Holder, entityName) == 8);
    assert!(core::mem::offset_of!(X509Holder, objectDigestInfo) == 16);
};

/// `struct X509_acert_info_st` -- `X509_ACERT_INFO`, from `include/crypto/x509_acert.h:53-63`.
#[repr(C)]
pub struct X509AcertInfo {
    /// `ASN1_INTEGER version` -- embedded, defaulting to v2.
    pub version: Asn1String,
    /// `X509_HOLDER holder` -- embedded.
    pub holder: X509Holder,
    /// `X509_ACERT_ISSUER issuer` -- embedded.
    pub issuer: X509AcertIssuer,
    /// `X509_ALGOR signature` -- embedded.
    pub signature: X509Algor,
    /// `ASN1_INTEGER serialNumber` -- embedded.
    pub serialNumber: Asn1String,
    /// `X509_VAL validityPeriod` -- embedded.
    pub validityPeriod: X509Val,
    /// `STACK_OF(X509_ATTRIBUTE) *attributes`.
    pub attributes: *mut OpenSslStack,
    /// `ASN1_BIT_STRING *issuerUID` -- optional.
    pub issuerUID: *mut Asn1String,
    /// `X509_EXTENSIONS *extensions` -- optional.
    pub extensions: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<X509AcertInfo>() == 144);
    assert!(core::mem::offset_of!(X509AcertInfo, version) == 0);
    assert!(core::mem::offset_of!(X509AcertInfo, holder) == 24);
    assert!(core::mem::offset_of!(X509AcertInfo, issuer) == 48);
    assert!(core::mem::offset_of!(X509AcertInfo, signature) == 64);
    assert!(core::mem::offset_of!(X509AcertInfo, serialNumber) == 80);
    assert!(core::mem::offset_of!(X509AcertInfo, validityPeriod) == 104);
    assert!(core::mem::offset_of!(X509AcertInfo, attributes) == 120);
    assert!(core::mem::offset_of!(X509AcertInfo, issuerUID) == 128);
    assert!(core::mem::offset_of!(X509AcertInfo, extensions) == 136);
};

/// `struct X509_acert_st` -- `X509_ACERT`, from `include/crypto/x509_acert.h:65-69`.
#[repr(C)]
pub struct X509Acert {
    /// `X509_ACERT_INFO *acinfo` -- pointed at, not embedded.
    pub acinfo: *mut X509AcertInfo,
    /// `X509_ALGOR sig_alg` -- embedded.
    pub sig_alg: X509Algor,
    /// `ASN1_BIT_STRING signature` -- embedded.
    pub signature: Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<X509Acert>() == 48);
    assert!(core::mem::offset_of!(X509Acert, acinfo) == 0);
    assert!(core::mem::offset_of!(X509Acert, sig_alg) == 8);
    assert!(core::mem::offset_of!(X509Acert, signature) == 24);
};

// ---------------------------------------------------------------------------------------------
// The item templates -- `ASN1_SEQUENCE(...)` blocks at `x509_acert.c:22-68`
// ---------------------------------------------------------------------------------------------

/// `OSSL_OBJECT_DIGEST_INFO_seq_tt` -- `ASN1_SEQUENCE(OSSL_OBJECT_DIGEST_INFO)`
/// (`crypto/x509/x509_acert.c:22-27`). Identical in shape to `v3_ac_tgt.c`'s, but a separate
/// item, as the authority has.
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

/// `OSSL_OBJECT_DIGEST_INFO_it`'s descriptor -- `ASN1_SEQUENCE_END(OSSL_OBJECT_DIGEST_INFO)` at
/// `crypto/x509/x509_acert.c:27`.
static OSSL_OBJECT_DIGEST_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_OBJECT_DIGEST_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslObjectDigestInfo>() as c_long,
    sname: c"OSSL_OBJECT_DIGEST_INFO".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *OSSL_OBJECT_DIGEST_INFO_it(void)` --
/// `x509_acert.h:17`'s `DECLARE_ASN1_ITEM`, hidden by the version script.
fn ossl_object_digest_info_it() -> *const Asn1Item {
    &OSSL_OBJECT_DIGEST_INFO_ITEM
}

/// `OSSL_ISSUER_SERIAL_seq_tt` -- `ASN1_SEQUENCE(OSSL_ISSUER_SERIAL)`
/// (`crypto/x509/x509_acert.c:29-33`).
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

/// `OSSL_ISSUER_SERIAL_it`'s descriptor -- `ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)` at
/// `crypto/x509/x509_acert.c:33`.
static OSSL_ISSUER_SERIAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ISSUER_SERIAL_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslIssuerSerial>() as c_long,
    sname: c"OSSL_ISSUER_SERIAL".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *OSSL_ISSUER_SERIAL_it(void)` --
/// `x509_acert.h:18`'s `DECLARE_ASN1_ITEM`, hidden by the version script.
fn ossl_issuer_serial_it() -> *const Asn1Item {
    &OSSL_ISSUER_SERIAL_ITEM
}

/// `X509_ACERT_ISSUER_V2FORM_seq_tt` -- `ASN1_SEQUENCE(X509_ACERT_ISSUER_V2FORM)`
/// (`crypto/x509/x509_acert.c:35-39`): `ASN1_SEQUENCE_OF_OPT(..., issuerName, GENERAL_NAME)`,
/// `ASN1_IMP_OPT(..., baseCertificateId, OSSL_ISSUER_SERIAL, 0)` and
/// `ASN1_IMP_OPT(..., objectDigestInfo, OSSL_OBJECT_DIGEST_INFO, 1)`.
static X509_ACERT_ISSUER_V2FORM_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"issuerName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"baseCertificateId".as_ptr(),
        item: ossl_issuer_serial_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 16,
        field_name: c"objectDigestInfo".as_ptr(),
        item: ossl_object_digest_info_it as *mut c_void,
    },
];

/// `X509_ACERT_ISSUER_V2FORM_it`'s descriptor -- `ASN1_SEQUENCE_END(X509_ACERT_ISSUER_V2FORM)`
/// at `crypto/x509/x509_acert.c:39`.
static X509_ACERT_ISSUER_V2FORM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ACERT_ISSUER_V2FORM_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509AcertIssuerV2form>() as c_long,
    sname: c"X509_ACERT_ISSUER_V2FORM".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *X509_ACERT_ISSUER_V2FORM_it(void)` --
/// `x509_acert.h:19`'s `DECLARE_ASN1_ITEM`.
fn x509_acert_issuer_v2form_it() -> *const Asn1Item {
    &X509_ACERT_ISSUER_V2FORM_ITEM
}

/// `X509_ACERT_ISSUER_ch_tt` -- `ASN1_CHOICE(X509_ACERT_ISSUER)`
/// (`crypto/x509/x509_acert.c:41-44`): `ASN1_SEQUENCE_OF(..., u.v1Form, GENERAL_NAME)` and
/// `ASN1_IMP(..., u.v2Form, X509_ACERT_ISSUER_V2FORM, 0)`.
static X509_ACERT_ISSUER_CH_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"u.v1Form".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"u.v2Form".as_ptr(),
        item: x509_acert_issuer_v2form_it as *mut c_void,
    },
];

/// `X509_ACERT_ISSUER_it`'s descriptor -- `ASN1_CHOICE_END(X509_ACERT_ISSUER)` at
/// `crypto/x509/x509_acert.c:44`. The `utype` of a CHOICE is the selector's offset (0 here).
static X509_ACERT_ISSUER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(X509AcertIssuer, type_) as c_long,
    templates: X509_ACERT_ISSUER_CH_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509AcertIssuer>() as c_long,
    sname: c"X509_ACERT_ISSUER".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *X509_ACERT_ISSUER_it(void)` --
/// `x509_acert.h:20`'s `DECLARE_ASN1_ITEM`.
fn x509_acert_issuer_it() -> *const Asn1Item {
    &X509_ACERT_ISSUER_ITEM
}

/// `X509_HOLDER_seq_tt` -- `ASN1_SEQUENCE(X509_HOLDER)` (`crypto/x509/x509_acert.c:46-50`):
/// `ASN1_IMP_OPT(..., baseCertificateID, OSSL_ISSUER_SERIAL, 0)`,
/// `ASN1_IMP_SEQUENCE_OF_OPT(..., entityName, GENERAL_NAME, 1)` and
/// `ASN1_IMP_OPT(..., objectDigestInfo, OSSL_OBJECT_DIGEST_INFO, 2)`.
static X509_HOLDER_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"baseCertificateID".as_ptr(),
        item: ossl_issuer_serial_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"entityName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"objectDigestInfo".as_ptr(),
        item: ossl_object_digest_info_it as *mut c_void,
    },
];

/// `X509_HOLDER_it`'s descriptor -- `ASN1_SEQUENCE_END(X509_HOLDER)` at
/// `crypto/x509/x509_acert.c:50`.
static X509_HOLDER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_HOLDER_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Holder>() as c_long,
    sname: c"X509_HOLDER".as_ptr(),
};

/// The file-local `static const ASN1_ITEM *X509_HOLDER_it(void)` -- `x509_acert.h:21`'s
/// `DECLARE_ASN1_ITEM`.
fn x509_holder_it() -> *const Asn1Item {
    &X509_HOLDER_ITEM
}

/// `X509_ACERT_INFO_seq_tt` -- `ASN1_SEQUENCE(X509_ACERT_INFO)`
/// (`crypto/x509/x509_acert.c:52-62`).
static X509_ACERT_INFO_TT: [Asn1Template; 9] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 24,
        field_name: c"holder".as_ptr(),
        item: x509_holder_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 48,
        field_name: c"issuer".as_ptr(),
        item: x509_acert_issuer_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 64,
        field_name: c"signature".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 80,
        field_name: c"serialNumber".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 104,
        field_name: c"validityPeriod".as_ptr(),
        item: X509_VAL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 120,
        field_name: c"attributes".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 128,
        field_name: c"issuerUID".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 136,
        field_name: c"extensions".as_ptr(),
        item: X509_EXTENSION_it as *mut c_void,
    },
];

/// `X509_ACERT_INFO_it`'s descriptor -- `ASN1_SEQUENCE_END(X509_ACERT_INFO)` at
/// `crypto/x509/x509_acert.c:62`.
static X509_ACERT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ACERT_INFO_TT.as_ptr(),
    tcount: 9,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509AcertInfo>() as c_long,
    sname: c"X509_ACERT_INFO".as_ptr(),
};

/// `const ASN1_ITEM *X509_ACERT_INFO_it(void)` -- `include/openssl/x509_acert.h:38`, from
/// `DECLARE_ASN1_ITEM(X509_ACERT_INFO)`.
#[no_mangle]
pub extern "C" fn X509_ACERT_INFO_it() -> *const Asn1Item {
    &X509_ACERT_INFO_ITEM
}

/// `X509_ACERT_seq_tt` -- `ASN1_SEQUENCE(X509_ACERT)` (`crypto/x509/x509_acert.c:64-68`):
/// `ASN1_SIMPLE(..., acinfo, X509_ACERT_INFO)`, `ASN1_EMBED(..., sig_alg, X509_ALGOR)` and
/// `ASN1_EMBED(..., signature, ASN1_BIT_STRING)`.
static X509_ACERT_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"acinfo".as_ptr(),
        item: X509_ACERT_INFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"sig_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 24,
        field_name: c"signature".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `X509_ACERT_it`'s descriptor -- `ASN1_SEQUENCE_END(X509_ACERT)` at
/// `crypto/x509/x509_acert.c:68`.
static X509_ACERT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: X509_ACERT_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<X509Acert>() as c_long,
    sname: c"X509_ACERT".as_ptr(),
};

/// `const ASN1_ITEM *X509_ACERT_it(void)` -- `include/openssl/x509_acert.h:36`, from
/// `DECLARE_ASN1_FUNCTIONS(X509_ACERT)`.
#[no_mangle]
pub extern "C" fn X509_ACERT_it() -> *const Asn1Item {
    &X509_ACERT_ITEM
}

// ---------------------------------------------------------------------------------------------
// The `IMPLEMENT_ASN1_*` groups -- `x509_acert.c:70-75`
// ---------------------------------------------------------------------------------------------

/// `X509_ACERT *X509_ACERT_new(void)` -- `crypto/x509/x509_acert.c:70`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(X509_ACERT)`.
#[no_mangle]
pub extern "C" fn X509_ACERT_new() -> *mut X509Acert {
    // SAFETY: `X509_ACERT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_ACERT_it()).cast::<X509Acert>() }
}

/// `void X509_ACERT_free(X509_ACERT *a)` -- the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_free(a: *mut X509Acert) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_ACERT_it()) }
}

/// `X509_ACERT *X509_ACERT_dup(const X509_ACERT *a)` -- `crypto/x509/x509_acert.c:71`, from
/// `IMPLEMENT_ASN1_DUP_FUNCTION(X509_ACERT)`.
///
/// # Safety
///
/// `a` is NULL or a live value.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_dup(a: *const X509Acert) -> *mut X509Acert {
    // SAFETY: `a` is NULL or live per the contract; `X509_ACERT_it()` is a static item.
    unsafe { ASN1_item_dup(X509_ACERT_it(), a.cast()).cast::<X509Acert>() }
}

/// `X509_ACERT *d2i_X509_ACERT(X509_ACERT **a, const unsigned char **in, long len)` --
/// `crypto/x509/x509_acert.c:70`'s generated decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_X509_ACERT(
    a: *mut *mut X509Acert,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut X509Acert {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, X509_ACERT_it()).cast::<X509Acert>() }
}

/// `int i2d_X509_ACERT(const X509_ACERT *a, unsigned char **out)` -- the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_X509_ACERT(a: *const X509Acert, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, X509_ACERT_it()) }
}

/// `X509_ACERT_INFO *X509_ACERT_INFO_new(void)` -- `crypto/x509/x509_acert.c:72`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X509_ACERT_INFO)`.
#[no_mangle]
pub extern "C" fn X509_ACERT_INFO_new() -> *mut X509AcertInfo {
    // SAFETY: `X509_ACERT_INFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(X509_ACERT_INFO_it()).cast::<X509AcertInfo>() }
}

/// `void X509_ACERT_INFO_free(X509_ACERT_INFO *a)` -- the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_INFO_free(a: *mut X509AcertInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), X509_ACERT_INFO_it()) }
}

/// `OSSL_ISSUER_SERIAL *OSSL_ISSUER_SERIAL_new(void)` -- `crypto/x509/x509_acert.c:73`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(OSSL_ISSUER_SERIAL)`.
#[no_mangle]
pub extern "C" fn OSSL_ISSUER_SERIAL_new() -> *mut OsslIssuerSerial {
    // SAFETY: `ossl_issuer_serial_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ossl_issuer_serial_it()).cast::<OsslIssuerSerial>() }
}

/// `void OSSL_ISSUER_SERIAL_free(OSSL_ISSUER_SERIAL *a)` -- the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_free(a: *mut OsslIssuerSerial) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ossl_issuer_serial_it()) }
}

/// `OSSL_OBJECT_DIGEST_INFO *OSSL_OBJECT_DIGEST_INFO_new(void)` --
/// `crypto/x509/x509_acert.c:74`, from `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(OSSL_OBJECT_DIGEST_INFO)`.
#[no_mangle]
pub extern "C" fn OSSL_OBJECT_DIGEST_INFO_new() -> *mut OsslObjectDigestInfo {
    // SAFETY: `ossl_object_digest_info_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ossl_object_digest_info_it()).cast::<OsslObjectDigestInfo>() }
}

/// `void OSSL_OBJECT_DIGEST_INFO_free(OSSL_OBJECT_DIGEST_INFO *a)` -- the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_free(a: *mut OsslObjectDigestInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ossl_object_digest_info_it()) }
}

/// `X509_ACERT_ISSUER_V2FORM *X509_ACERT_ISSUER_V2FORM_new(void)` --
/// `crypto/x509/x509_acert.c:75`, from `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(X509_ACERT_ISSUER_V2FORM)`.
#[no_mangle]
pub extern "C" fn X509_ACERT_ISSUER_V2FORM_new() -> *mut X509AcertIssuerV2form {
    // SAFETY: `x509_acert_issuer_v2form_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(x509_acert_issuer_v2form_it()).cast::<X509AcertIssuerV2form>() }
}

/// `void X509_ACERT_ISSUER_V2FORM_free(X509_ACERT_ISSUER_V2FORM *a)` -- the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_ISSUER_V2FORM_free(a: *mut X509AcertIssuerV2form) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), x509_acert_issuer_v2form_it()) }
}

// ---------------------------------------------------------------------------------------------
// `IMPLEMENT_PEM_rw(X509_ACERT, X509_ACERT, PEM_STRING_ACERT, X509_ACERT)` -- `x509_acert.c:77`
// ---------------------------------------------------------------------------------------------

/// The `(d2i_of_void *)` cast for the `X509_ACERT` decoder.
///
/// # Safety
///
/// The `void *` arguments must be [`d2i_X509_ACERT`]'s own.
unsafe extern "C" fn d2i_void_x509_acert(
    a: *mut *mut c_void,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut c_void {
    // SAFETY: the caller's contract, restated in the typed decoder's terms.
    unsafe { d2i_X509_ACERT(a.cast::<*mut X509Acert>(), in_, len).cast::<c_void>() }
}

/// The `(i2d_of_void *)` cast for the `X509_ACERT` encoder.
///
/// # Safety
///
/// `x` must be live and `out` the encoder's own cursor.
unsafe extern "C" fn i2d_void_x509_acert(x: *const c_void, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract, restated in the typed encoder's terms.
    unsafe { i2d_X509_ACERT(x.cast::<X509Acert>(), out) }
}

/// `X509_ACERT *PEM_read_X509_ACERT(FILE *fp, X509_ACERT **x, pem_password_cb *cb, void *u)` --
/// `crypto/x509/x509_acert.c:77`, from `IMPLEMENT_PEM_rw`.
///
/// # Safety
///
/// `fp` is a live `FILE *`; `x` NULL or writable; `cb` NULL or a callback; `u` the callback's
/// own argument.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_X509_ACERT(
    fp: *mut c_void,
    x: *mut *mut X509Acert,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Acert {
    // SAFETY: `d2i_void_x509_acert` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read(d2i_void_x509_acert, PEM_STRING_ACERT, fp, x.cast(), cb, u) }
        .cast::<X509Acert>()
}

/// `X509_ACERT *PEM_read_bio_X509_ACERT(BIO *bp, X509_ACERT **x, pem_password_cb *cb,
/// void *u)` -- the same macro's BIO reader.
///
/// # Safety
///
/// `bp` is a live BIO; `x` NULL or writable; `cb` NULL or a callback; `u` the callback's own
/// argument.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_X509_ACERT(
    bp: *mut Bio,
    x: *mut *mut X509Acert,
    cb: Option<PemPasswordCb>,
    u: *mut c_void,
) -> *mut X509Acert {
    // SAFETY: `d2i_void_x509_acert` is the decoder and the arguments are the caller's.
    unsafe { PEM_ASN1_read_bio(d2i_void_x509_acert, PEM_STRING_ACERT, bp, x.cast(), cb, u) }
        .cast::<X509Acert>()
}

/// `int PEM_write_X509_ACERT(FILE *fp, const X509_ACERT *x)` -- the same macro's `FILE *`
/// writer.
///
/// # Safety
///
/// `out` is a live `FILE *`; `x` is a live value.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_X509_ACERT(out: *mut c_void, x: *const X509Acert) -> c_int {
    // SAFETY: the caller's contract; the NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write(
            Some(i2d_void_x509_acert),
            PEM_STRING_ACERT,
            out,
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `int PEM_write_bio_X509_ACERT(BIO *bp, const X509_ACERT *x)` -- the same macro's BIO writer.
///
/// # Safety
///
/// `out` is a live BIO; `x` is a live value.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_X509_ACERT(out: *mut Bio, x: *const X509Acert) -> c_int {
    // SAFETY: the caller's contract; the NULLs are the macro's no-cipher arms.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d_void_x509_acert),
            PEM_STRING_ACERT,
            out,
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// The accessors -- `x509_acert.c:79-188`, `:314-327`
// ---------------------------------------------------------------------------------------------

/// `static X509_NAME *get_dirName(const GENERAL_NAMES *names)` -- `x509_acert.c:79-91`.
///
/// Answers the `X509_NAME` of a one-entry `GENERAL_NAMES` whose sole name is a `directoryName`,
/// and NULL for every other shape.
///
/// # Safety
///
/// `names` is NULL or a live `GENERAL_NAMES` stack.
unsafe fn get_dirName(names: *const OpenSslStack) -> *mut X509Name {
    // SAFETY: `names` is NULL or live per the contract; `OPENSSL_sk_num` accepts NULL.
    if unsafe { OPENSSL_sk_num(names) } != 1 {
        return ptr::null_mut();
    }
    // SAFETY: `names` holds exactly one live `GENERAL_NAME`.
    let dirName = unsafe { OPENSSL_sk_value(names, 0) }.cast::<GeneralName>();
    // SAFETY: `dirName` is the live element just read.
    if unsafe { (*dirName).type_ } != GEN_DIRNAME {
        return ptr::null_mut();
    }
    // SAFETY: `dirName` is a `directoryName` per the check above.
    unsafe { (*dirName).d.directoryName }
}

/// `void OSSL_OBJECT_DIGEST_INFO_get0_digest(const OSSL_OBJECT_DIGEST_INFO *o,
/// int *digestedObjectType, const X509_ALGOR **digestAlgorithm, const ASN1_BIT_STRING **digest)`
/// -- `x509_acert.c:93-104`.
///
/// # Safety
///
/// `o` is a live `OSSL_OBJECT_DIGEST_INFO`; each out-parameter is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_OBJECT_DIGEST_INFO_get0_digest(
    o: *const OsslObjectDigestInfo,
    digestedObjectType: *mut c_int,
    digestAlgorithm: *mut *const X509Algor,
    digest: *mut *const Asn1String,
) {
    if !digestedObjectType.is_null() {
        // SAFETY: `o` is live and its embedded ENUMERATED is readable.
        let v = unsafe { ASN1_ENUMERATED_get(&raw const (*o).digestedObjectType) } as c_int;
        // SAFETY: `digestedObjectType` is writable per the contract.
        unsafe { *digestedObjectType = v };
    }
    if !digestAlgorithm.is_null() {
        // SAFETY: `o` is live; the answer borrows its embedded algorithm.
        unsafe { *digestAlgorithm = &raw const (*o).digestAlgorithm };
    }
    if !digest.is_null() {
        // SAFETY: `o` is live; the answer borrows its embedded bit string.
        unsafe { *digest = &raw const (*o).objectDigest };
    }
}

/// `const X509_NAME *OSSL_ISSUER_SERIAL_get0_issuer(const OSSL_ISSUER_SERIAL *isss)` --
/// `x509_acert.c:106-109`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`; the answer borrows its `issuer` stack.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_issuer(
    isss: *const OsslIssuerSerial,
) -> *const X509Name {
    // SAFETY: `isss` is live per the contract.
    unsafe { get_dirName((*isss).issuer) }
}

/// `const ASN1_INTEGER *OSSL_ISSUER_SERIAL_get0_serial(const OSSL_ISSUER_SERIAL *isss)` --
/// `x509_acert.c:111-114`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`; the answer borrows its embedded `serial`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_serial(
    isss: *const OsslIssuerSerial,
) -> *const Asn1String {
    // SAFETY: `isss` is live per the contract.
    unsafe { &raw const (*isss).serial }
}

/// `const ASN1_BIT_STRING *OSSL_ISSUER_SERIAL_get0_issuerUID(const OSSL_ISSUER_SERIAL *isss)` --
/// `x509_acert.c:116-119`.
///
/// # Safety
///
/// `isss` is a live `OSSL_ISSUER_SERIAL`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ISSUER_SERIAL_get0_issuerUID(
    isss: *const OsslIssuerSerial,
) -> *const Asn1String {
    // SAFETY: `isss` is live per the contract.
    unsafe { (*isss).issuerUID }
}

/// `long X509_ACERT_get_version(const X509_ACERT *x)` -- `x509_acert.c:121-124`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_version(x: *const X509Acert) -> c_long {
    // SAFETY: `x` is live per the contract.
    unsafe { ASN1_INTEGER_get(&raw const (*(*x).acinfo).version) }
}

/// `void X509_ACERT_get0_signature(const X509_ACERT *x, const ASN1_BIT_STRING **psig,
/// const X509_ALGOR **palg)` -- `x509_acert.c:126-134`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; each out-parameter is NULL or writable and the answers borrow
/// `x`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_signature(
    x: *const X509Acert,
    psig: *mut *const Asn1String,
    palg: *mut *const X509Algor,
) {
    if !psig.is_null() {
        // SAFETY: `x` is live and `psig` is writable per the contract.
        unsafe { *psig = &raw const (*x).signature };
    }
    if !palg.is_null() {
        // SAFETY: `x` is live and `palg` is writable per the contract.
        unsafe { *palg = &raw const (*x).sig_alg };
    }
}

/// `int X509_ACERT_get_signature_nid(const X509_ACERT *x)` -- `x509_acert.c:136-139`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_signature_nid(x: *const X509Acert) -> c_int {
    // SAFETY: `x` is live per the contract; its `sig_alg` holds a readable OID slot.
    unsafe { OBJ_obj2nid((*x).sig_alg.algorithm) }
}

/// `const GENERAL_NAMES *X509_ACERT_get0_holder_entityName(const X509_ACERT *x)` --
/// `x509_acert.c:141-144`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its holder.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_holder_entityName(
    x: *const X509Acert,
) -> *const OpenSslStack {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).holder.entityName }
}

/// `const OSSL_ISSUER_SERIAL *X509_ACERT_get0_holder_baseCertId(const X509_ACERT *x)` --
/// `x509_acert.c:146-149`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its holder.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_holder_baseCertId(
    x: *const X509Acert,
) -> *const OsslIssuerSerial {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).holder.baseCertificateID }
}

/// `const OSSL_OBJECT_DIGEST_INFO *X509_ACERT_get0_holder_digest(const X509_ACERT *x)` --
/// `x509_acert.c:151-154`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its holder.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_holder_digest(
    x: *const X509Acert,
) -> *const OsslObjectDigestInfo {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).holder.objectDigestInfo }
}

/// `const X509_NAME *X509_ACERT_get0_issuerName(const X509_ACERT *x)` -- `x509_acert.c:156-163`.
///
/// Only the `v2Form` issuer is supported; a `v1Form` (or an absent one) answers NULL.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its issuer.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_issuerName(x: *const X509Acert) -> *const X509Name {
    // SAFETY: `x` is live per the contract.
    let issuer = unsafe { &raw const (*(*x).acinfo).issuer };
    // SAFETY: `issuer` is live and readable.
    if unsafe { (*issuer).type_ } != X509_ACERT_ISSUER_V2 {
        return ptr::null();
    }
    // SAFETY: `issuer` is live; its union arm is a `v2Form` per the selector above.
    let v2 = unsafe { (*issuer).u.v2Form };
    if v2.is_null() {
        return ptr::null();
    }
    // SAFETY: `v2` is the live `v2Form`.
    unsafe { get_dirName((*v2).issuerName) }
}

/// `const ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(const X509_ACERT *x)` --
/// `x509_acert.c:165-168`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_issuerUID(x: *const X509Acert) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).issuerUID }
}

/// `const X509_ALGOR *X509_ACERT_get0_info_sigalg(const X509_ACERT *x)` --
/// `x509_acert.c:170-173`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its `acinfo`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_info_sigalg(x: *const X509Acert) -> *const X509Algor {
    // SAFETY: `x` is live per the contract.
    unsafe { &raw const (*(*x).acinfo).signature }
}

/// `const ASN1_INTEGER *X509_ACERT_get0_serialNumber(const X509_ACERT *x)` --
/// `x509_acert.c:175-178`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its `acinfo`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_serialNumber(x: *const X509Acert) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { &raw const (*(*x).acinfo).serialNumber }
}

/// `const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notBefore(const X509_ACERT *x)` --
/// `x509_acert.c:180-183`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_notBefore(x: *const X509Acert) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).validityPeriod.notBefore }
}

/// `const ASN1_GENERALIZEDTIME *X509_ACERT_get0_notAfter(const X509_ACERT *x)` --
/// `x509_acert.c:185-188`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_notAfter(x: *const X509Acert) -> *const Asn1String {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).validityPeriod.notAfter }
}

/// `const STACK_OF(X509_EXTENSION) *X509_ACERT_get0_extensions(const X509_ACERT *x)` --
/// `x509_acert.c:325-327`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its `acinfo`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get0_extensions(x: *const X509Acert) -> *const OpenSslStack {
    // SAFETY: `x` is live per the contract.
    unsafe { (*(*x).acinfo).extensions }
}

// ---------------------------------------------------------------------------------------------
// The attribute containers -- `x509_acert.c:190-247`
// ---------------------------------------------------------------------------------------------

/// `int X509_ACERT_get_attr_count(const X509_ACERT *x)` -- `x509_acert.c:192-195`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_attr_count(x: *const X509Acert) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509at_get_attr_count((*(*x).acinfo).attributes) }
}

/// `int X509_ACERT_get_attr_by_NID(const X509_ACERT *x, int nid, int lastpos)` --
/// `x509_acert.c:197-200`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_attr_by_NID(
    x: *const X509Acert,
    nid: c_int,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509at_get_attr_by_NID((*(*x).acinfo).attributes, nid, lastpos) }
}

/// `int X509_ACERT_get_attr_by_OBJ(const X509_ACERT *x, const ASN1_OBJECT *obj, int lastpos)` --
/// `x509_acert.c:202-206`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `obj` is a live OID.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_attr_by_OBJ(
    x: *const X509Acert,
    obj: *const Asn1Object,
    lastpos: c_int,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    unsafe { X509at_get_attr_by_OBJ((*(*x).acinfo).attributes, obj, lastpos) }
}

/// `X509_ATTRIBUTE *X509_ACERT_get_attr(const X509_ACERT *x, int loc)` --
/// `x509_acert.c:208-211`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer borrows its attribute stack.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_attr(
    x: *const X509Acert,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `x` is live per the contract.
    unsafe { X509at_get_attr((*(*x).acinfo).attributes, loc) }
}

/// `X509_ATTRIBUTE *X509_ACERT_delete_attr(X509_ACERT *x, int loc)` -- `x509_acert.c:213-216`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; the answer is the removed attribute, now the caller's.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_delete_attr(
    x: *mut X509Acert,
    loc: c_int,
) -> *mut X509Attribute {
    // SAFETY: `x` is live per the contract.
    unsafe { X509at_delete_attr((*(*x).acinfo).attributes, loc) }
}

/// `int X509_ACERT_add1_attr(X509_ACERT *x, X509_ATTRIBUTE *attr)` -- `x509_acert.c:218-223`.
///
/// The condition is `X509at_add1_attr(...) != NULL`: a success answers 1 and a refusal 0.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `attr` is a live attribute the stack takes a copy of.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add1_attr(
    x: *mut X509Acert,
    attr: *mut X509Attribute,
) -> c_int {
    // SAFETY: `x` is live and its `attributes` slot is writable.
    let slot = unsafe { &raw mut (*(*x).acinfo).attributes };
    // SAFETY: `slot` is a writable stack slot and `attr` is live.
    let r = unsafe { X509at_add1_attr(slot, attr) };
    c_int::from(!r.is_null())
}

/// `int X509_ACERT_add1_attr_by_OBJ(X509_ACERT *x, const ASN1_OBJECT *obj, int type,
/// const void *bytes, int len)` -- `x509_acert.c:225-231`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `obj` a live OID; `bytes` readable for `len`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add1_attr_by_OBJ(
    x: *mut X509Acert,
    obj: *const Asn1Object,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `x` is live and its `attributes` slot is writable.
    let slot = unsafe { &raw mut (*(*x).acinfo).attributes };
    // SAFETY: the arguments are the caller's.
    let r = unsafe { X509at_add1_attr_by_OBJ(slot, obj, type_, bytes.cast::<c_uchar>(), len) };
    c_int::from(!r.is_null())
}

/// `int X509_ACERT_add1_attr_by_NID(X509_ACERT *x, int nid, int type, const void *bytes,
/// int len)` -- `x509_acert.c:233-239`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `bytes` readable for `len`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add1_attr_by_NID(
    x: *mut X509Acert,
    nid: c_int,
    type_: c_int,
    bytes: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `x` is live and its `attributes` slot is writable.
    let slot = unsafe { &raw mut (*(*x).acinfo).attributes };
    // SAFETY: the arguments are the caller's.
    let r = unsafe { X509at_add1_attr_by_NID(slot, nid, type_, bytes.cast::<c_uchar>(), len) };
    c_int::from(!r.is_null())
}

/// `int X509_ACERT_add1_attr_by_txt(X509_ACERT *x, const char *attrname, int type,
/// const unsigned char *bytes, int len)` -- `x509_acert.c:241-247`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `attrname` NUL-terminated; `bytes` readable for `len`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add1_attr_by_txt(
    x: *mut X509Acert,
    attrname: *const c_char,
    type_: c_int,
    bytes: *const c_uchar,
    len: c_int,
) -> c_int {
    // SAFETY: `x` is live and its `attributes` slot is writable.
    let slot = unsafe { &raw mut (*(*x).acinfo).attributes };
    // SAFETY: the arguments are the caller's.
    let r = unsafe { X509at_add1_attr_by_txt(slot, attrname, type_, bytes, len) };
    c_int::from(!r.is_null())
}

/// `static int check_asn1_attribute(const char **value)` -- `x509_acert.c:249-262`.
///
/// On a leading `"ASN1:"` (then any run of spaces) the pointer is advanced past it and 1 is
/// answered; otherwise 0, with `*value` untouched.
///
/// # Safety
///
/// `*value` points at a NUL-terminated string.
unsafe fn check_asn1_attribute(value: *mut *const c_char) -> c_int {
    // SAFETY: `value` is a readable slot per the contract.
    let mut p = unsafe { *value };
    // `strncmp(p, "ASN1:", 5)`.
    for (i, b) in b"ASN1:".iter().enumerate() {
        // SAFETY: `p` is NUL-terminated, so the first six bytes are readable.
        if unsafe { *p.add(i) } as u8 != *b {
            return 0;
        }
    }
    // SAFETY: the five bytes just compared are readable.
    p = unsafe { p.add(5) };
    // SAFETY: `p` walks a NUL-terminated string.
    while ossl_isspace(unsafe { *p } as c_int) {
        // SAFETY: `p` still walks the same NUL-terminated string.
        p = unsafe { p.add(1) };
    }
    // SAFETY: `value` is a writable slot per the contract.
    unsafe { *value = p };
    1
}

/// `int X509_ACERT_add_attr_nconf(CONF *conf, const char *section, X509_ACERT *acert)` --
/// `x509_acert.c:264-312`.
///
/// Each entry of the named section becomes one attribute: a value prefixed `"ASN1:"` is built
/// through `ASN1_generate_nconf` and added as a `V_ASN1_SEQUENCE`; any other value is added
/// verbatim as a `V_ASN1_OCTET_STRING`. A missing section or a NULL value refuses.
///
/// # Safety
///
/// `conf` is a live `CONF`; `section` NUL-terminated; `acert` a live `X509_ACERT`.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add_attr_nconf(
    conf: *mut Conf,
    section: *const c_char,
    acert: *mut X509Acert,
) -> c_int {
    // SAFETY: `conf` and `section` are the caller's; a missing section answers NULL.
    let attr_sk = unsafe { NCONF_get_section(conf, section) };
    if attr_sk.is_null() {
        return 0;
    }
    // SAFETY: `attr_sk` is the live section stack.
    let num = unsafe { OPENSSL_sk_num(attr_sk) };
    for i in 0..num {
        // SAFETY: `attr_sk` is live and `i` is in bounds; the element is a `CONF_VALUE`.
        let v = unsafe { OPENSSL_sk_value(attr_sk, i) }.cast::<ConfValue>();
        // SAFETY: `v` is the live entry just read.
        let value = unsafe { (*v).value };
        if value.is_null() {
            // `ERR_raise_data(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES, "name=%s,section=%s", ...)`.
            let mut msg = b"name=".to_vec();
            // SAFETY: `v` is live and its `name` is a NUL-terminated key.
            unsafe { push_cstr(&mut msg, (*v).name) };
            msg.extend_from_slice(b",section=");
            // SAFETY: `section` is NUL-terminated per the contract.
            unsafe { push_cstr(&mut msg, section) };
            msg.push(0);
            // SAFETY: `msg` is NUL-terminated and outlives the call.
            unsafe { raise_site_data(&X509_ACERT_278, msg.as_ptr().cast()) };
            return 0;
        }
        // SAFETY: `value` is a live NUL-terminated string per the check above.
        let mut value: *const c_char = value;
        // SAFETY: `value` is a live NUL-terminated string and `value` is a writable slot.
        if unsafe { check_asn1_attribute(&raw mut value) } == 1 {
            // SAFETY: `value` now points at the generated form and `conf` is live.
            let asn1 = unsafe { ASN1_generate_nconf(value, conf) };
            if asn1.is_null() {
                return 0;
            }
            let mut att_data: *mut c_uchar = ptr::null_mut();
            // SAFETY: `asn1` is live and `att_data` is a null slot.
            let att_len = unsafe { i2d_ASN1_TYPE(asn1, &raw mut att_data) };
            // SAFETY: `acert` is live; `att_data`/`att_len` are the encoding just made.
            let ret = unsafe {
                X509_ACERT_add1_attr_by_txt(
                    acert,
                    (*v).name,
                    V_ASN1_SEQUENCE as c_int,
                    att_data,
                    att_len,
                )
            };
            // SAFETY: `att_data` came from this allocator and is not owned elsewhere.
            unsafe { CRYPTO_free(att_data.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_ATTDATA) };
            // SAFETY: `asn1` is this call's own.
            unsafe { ASN1_TYPE_free(asn1) };
            if ret == 0 {
                return 0;
            }
        } else {
            // `strlen(value)`, the octet-string arm's length.
            // SAFETY: `value` is a live NUL-terminated string.
            let vlen = unsafe { c_strlen(value) };
            // SAFETY: `acert` is live; `v->name` and `value` are the caller's strings.
            let ret = unsafe {
                X509_ACERT_add1_attr_by_txt(
                    acert,
                    (*v).name,
                    V_ASN1_OCTET_STRING as c_int,
                    value.cast::<c_uchar>(),
                    vlen,
                )
            };
            if ret == 0 {
                return 0;
            }
        }
    }
    1
}

/// Append a NUL-terminated C string's bytes (without its terminator) to a byte vector, for the
/// data message `X509_ACERT_add_attr_nconf` builds.
///
/// # Safety
///
/// `s` is NULL or points at a NUL-terminated string.
unsafe fn push_cstr(out: &mut Vec<u8>, s: *const c_char) {
    if s.is_null() {
        out.extend_from_slice(b"<NULL>");
        return;
    }
    let mut i = 0isize;
    loop {
        // SAFETY: `s` is NUL-terminated per the contract.
        let c = unsafe { *s.offset(i) };
        if c == 0 {
            break;
        }
        out.push(c as u8);
        i += 1;
    }
}

/// `strlen` over a NUL-terminated C string.
///
/// # Safety
///
/// `s` points at a NUL-terminated string.
unsafe fn c_strlen(s: *const c_char) -> c_int {
    let mut i = 0isize;
    loop {
        // SAFETY: `s` is NUL-terminated per the contract.
        if unsafe { *s.offset(i) } == 0 {
            return i as c_int;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------------------------
// The extension containers -- `x509_acert.c:314-327`
// ---------------------------------------------------------------------------------------------

/// `void *X509_ACERT_get_ext_d2i(const X509_ACERT *x, int nid, int *crit, int *idx)` --
/// `x509_acert.c:314-317`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `crit`/`idx` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_get_ext_d2i(
    x: *const X509Acert,
    nid: c_int,
    crit: *mut c_int,
    idx: *mut c_int,
) -> *mut c_void {
    // SAFETY: `x` is live per the contract; the rest are the caller's.
    unsafe { X509V3_get_d2i((*(*x).acinfo).extensions, nid, crit, idx) }
}

/// `int X509_ACERT_add1_ext_i2d(X509_ACERT *x, int nid, void *value, int crit,
/// unsigned long flags)` -- `x509_acert.c:319-323`.
///
/// # Safety
///
/// `x` is a live `X509_ACERT`; `value` the extension item's own value.
#[no_mangle]
pub unsafe extern "C" fn X509_ACERT_add1_ext_i2d(
    x: *mut X509Acert,
    nid: c_int,
    value: *mut c_void,
    crit: c_int,
    flags: core::ffi::c_ulong,
) -> c_int {
    // SAFETY: `x` is live and its `extensions` slot is writable.
    let slot = unsafe { &raw mut (*(*x).acinfo).extensions };
    // SAFETY: the remaining arguments are the caller's.
    unsafe { X509V3_add1_i2d(slot, nid, value, crit, flags) }
}
