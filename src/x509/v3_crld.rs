//! `crypto/x509/v3_crld.c` — the CRL distribution point and issuing distribution point items and
//! their six rows. Phase 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_crld.c` is 724 lines and transcribes whole:
//!
//! * `DIST_POINT_NAME ::= CHOICE { fullname [0] IMPLICIT GeneralNames, relativename [1] IMPLICIT
//!   RelativeDistinguishedName }` (`:323-326`) lands, with its `ASN1_CHOICE_cb` [`dpn_cb`] aux
//!   (`:306-321`), the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group (`:328`) and the
//!   `DIST_POINT_NAME_dup` of `IMPLEMENT_ASN1_DUP_FUNCTION` (`:329`).
//! * `DIST_POINT ::= SEQUENCE { distributionPoint [0] EXPLICIT OPTIONAL, reasons [1] IMPLICIT
//!   OPTIONAL, cRLIssuer [2] IMPLICIT OPTIONAL }` (`:331-337`).
//! * `CRL_DIST_POINTS ::= SEQUENCE OF DIST_POINT` (`:339-342`).
//! * `ISSUING_DIST_POINT ::= SEQUENCE { distributionPoint [0] EXPLICIT OPTIONAL,
//!   onlyContainsUserCerts [1] IMPLICIT OPTIONAL, onlyContainsCACerts [2] IMPLICIT OPTIONAL,
//!   onlySomeReasons [3] IMPLICIT OPTIONAL, indirectCRL [4] IMPLICIT OPTIONAL,
//!   onlyContainsAttributeCerts [5] IMPLICIT OPTIONAL }` (`:344-353`).
//! * `OSSL_AA_DIST_POINT ::= SEQUENCE { distributionPoint [0] EXPLICIT OPTIONAL, reasons [1]
//!   IMPLICIT OPTIONAL, indirectCRL [2] IMPLICIT OPTIONAL, containsUserAttributeCerts [3] IMPLICIT
//!   OPTIONAL, containsAACerts [4] IMPLICIT OPTIONAL, containsSOAPublicKeyCerts [5] IMPLICIT
//!   OPTIONAL }` (`:554-563`).
//! * the static helpers [`gnames_from_sectname`] (`:46-65`), [`set_dist_point_name`] (`:67-136`),
//!   `reason_flags` (`:138-149`), [`set_reasons`] (`:151-184`), [`print_reasons`] (`:186-206`),
//!   [`crldp_from_section`] (`:208-240`), [`v2i_crld`] (`:242-304`), [`dpn_cb`] (`:306-321`),
//!   [`v2i_idp`] (`:371-418`), [`print_distpoint`] (`:420-434`), [`i2r_idp`] (`:436-458`),
//!   [`i2r_crldp`] (`:460-480`), [`i2r_crl_invdate`] (`:505-513`), [`i2r_object`] (`:515-523`),
//!   [`print_boolean`] (`:565-568`), [`aaidp_from_section`] (`:570-609`), [`v2i_aaidp`] (`:611-662`)
//!   and [`i2r_aaidp`] (`:664-713`).
//! * the exported `DIST_POINT_set_dpname` (`:526-552`, `x509v3.h:622`).
//! * the **six rows**: [`ossl_v3_crld`] (`:26-34`), [`ossl_v3_freshest_crl`] (`:36-44`),
//!   [`ossl_v3_idp`] (`:360-369`), [`ossl_v3_crl_invdate`] (`:487-494`), [`ossl_v3_crl_hold`]
//!   (`:496-503`) and [`ossl_v3_aa_issuing_dist_point`] (`:715-724`).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the array
//! is withheld until all 63 tables exist. This unit contributes six of the 63. The rows are internal
//! data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the five item groups,
//! `DIST_POINT_set_dpname` and the callbacks are the drivable surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_crld.c` is not an entry in `gen_err_raise_sites.py` (the generator's covered set
//! is the closed-stratum file list), so its sixteen coordinates are **declared locally** with the
//! `err_sites::ErrSite` shape, as `v3_pcons.rs` does. Their reason values are read from the
//! authority's own headers (`err.h`, `x509v3err.h`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::asn1::bitstr::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_BIT_STRING_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it, ASN1_OBJECT_it, ASN1_TBOOLEAN_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::ASN1_BIT_STRING_new;
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{strcmp, strncmp};
use crate::runtime::bio::{Bio, ERR_R_CRYPTO_LIB};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_DISTPOINT_ALREADY_SET, X509V3_R_INVALID_MULTIPLE_RDNS, X509V3_R_INVALID_NAME,
    X509V3_R_MISSING_VALUE, X509V3_R_SECTION_NOT_FOUND,
};
use crate::runtime::err::raise_site;
use crate::runtime::obj::{
    Asn1Object, NID_crl_distribution_points, NID_freshest_crl, NID_hold_instruction_code,
    NID_id_aa_issuing_distribution_point, NID_invalidity_date, NID_issuing_distribution_point,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::x509::v3_bitst::BitStringBitname;
use crate::x509::v3_conf::{X509V3Ctx, X509V3_get_section, X509V3_section_free};
use crate::x509::v3_genn::{
    GENERAL_NAMES_free, GENERAL_NAMES_new, GENERAL_NAME_free, GENERAL_NAME_it, GeneralName,
};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_san::{v2i_GENERAL_NAME, v2i_GENERAL_NAMES};
use crate::x509::v3_utl::{
    conf_add_error_name_value, OSSL_GENERAL_NAMES_print, X509V3_NAME_from_section,
    X509V3_conf_free, X509V3_get_value_bool, X509V3_parse_list,
};
use crate::x509::x509name::X509_NAME_add_entry;
use crate::x509::x_name::{
    i2d_X509_NAME, X509Name, X509NameEntry, X509_NAME_ENTRY_free, X509_NAME_ENTRY_it,
    X509_NAME_dup, X509_NAME_free, X509_NAME_new,
};

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)` with `ERR_LIB_ASN1` = 13.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_crld.c` raise coordinate, declared locally (see the module doc).
const fn v3_crld_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_crld.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `gnames_from_sectname`'s missing-section raise at `v3_crld.c:56` —
/// `X509V3_R_SECTION_NOT_FOUND` (`x509v3err.h:83`, 150).
const V3_CRLD_56: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(56, c"gnames_from_sectname", X509V3_R_SECTION_NOT_FOUND);
/// `set_dist_point_name`'s missing-value raise at `v3_crld.c:74` —
/// `X509V3_R_MISSING_VALUE` (`x509v3err.h:66`, 124).
const V3_CRLD_74: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(74, c"set_dist_point_name", X509V3_R_MISSING_VALUE);
/// `set_dist_point_name`'s missing-section raise at `v3_crld.c:92` —
/// `X509V3_R_SECTION_NOT_FOUND` (`x509v3err.h:83`, 150).
const V3_CRLD_92: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(92, c"set_dist_point_name", X509V3_R_SECTION_NOT_FOUND);
/// `set_dist_point_name`'s multiple-RDN raise at `v3_crld.c:108` —
/// `X509V3_R_INVALID_MULTIPLE_RDNS` (`x509v3err.h:51`, 161).
const V3_CRLD_108: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(108, c"set_dist_point_name", X509V3_R_INVALID_MULTIPLE_RDNS);
/// `set_dist_point_name`'s already-set raise at `v3_crld.c:115` —
/// `X509V3_R_DISTPOINT_ALREADY_SET` (`x509v3err.h:29`, 160).
const V3_CRLD_115: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(115, c"set_dist_point_name", X509V3_R_DISTPOINT_ALREADY_SET);
/// `v2i_crld`'s stack-allocation raise at `v3_crld.c:254` — `ERR_R_CRYPTO_LIB`
/// (`err.h:330`, 524303).
const V3_CRLD_254: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(254, c"v2i_crld", ERR_R_CRYPTO_LIB);
/// `v2i_crld`'s `GENERAL_NAMES_new` raise at `v3_crld.c:275` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_275: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(275, c"v2i_crld", ERR_R_ASN1_LIB);
/// `v2i_crld`'s `sk_GENERAL_NAME_push` raise at `v3_crld.c:279` — `ERR_R_CRYPTO_LIB`
/// (`err.h:330`, 524303).
const V3_CRLD_279: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(279, c"v2i_crld", ERR_R_CRYPTO_LIB);
/// `v2i_crld`'s `DIST_POINT_new` raise at `v3_crld.c:284` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_284: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(284, c"v2i_crld", ERR_R_ASN1_LIB);
/// `v2i_crld`'s `DIST_POINT_NAME_new` raise at `v3_crld.c:289` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_289: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(289, c"v2i_crld", ERR_R_ASN1_LIB);
/// `v2i_idp`'s `ISSUING_DIST_POINT_new` raise at `v3_crld.c:380` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_380: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(380, c"v2i_idp", ERR_R_ASN1_LIB);
/// `v2i_idp`'s invalid-name raise at `v3_crld.c:408` — `X509V3_R_INVALID_NAME`
/// (`x509v3err.h:52`, 106).
const V3_CRLD_408: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(408, c"v2i_idp", X509V3_R_INVALID_NAME);
/// `v2i_aaidp`'s `GENERAL_NAMES_new` raise at `v3_crld.c:635` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_635: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(635, c"v2i_aaidp", ERR_R_ASN1_LIB);
/// `v2i_aaidp`'s `sk_GENERAL_NAME_push` raise at `v3_crld.c:639` — `ERR_R_CRYPTO_LIB`
/// (`err.h:330`, 524303).
const V3_CRLD_639: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(639, c"v2i_aaidp", ERR_R_CRYPTO_LIB);
/// `v2i_aaidp`'s `OSSL_AA_DIST_POINT_new` raise at `v3_crld.c:644` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_644: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(644, c"v2i_aaidp", ERR_R_ASN1_LIB);
/// `v2i_aaidp`'s `DIST_POINT_NAME_new` raise at `v3_crld.c:648` — `ERR_R_ASN1_LIB`
/// (`err.h:328`, 524301).
const V3_CRLD_648: crate::runtime::err::err_sites::ErrSite =
    v3_crld_site(648, c"v2i_aaidp", ERR_R_ASN1_LIB);

// ---------------------------------------------------------------------------------------------
// The structures
// ---------------------------------------------------------------------------------------------

/// The `name` union of `DIST_POINT_NAME`: a `fullname` `GENERAL_NAMES` or a `relativename`
/// `STACK_OF(X509_NAME_ENTRY)`. Both arms are a pointer at offset 0.
#[repr(C)]
pub union DistPointNameName {
    /// `GENERAL_NAMES *fullname` — the `[0]` alternative.
    pub(crate) fullname: *mut OpenSslStack,
    /// `STACK_OF(X509_NAME_ENTRY) *relativename` — the `[1]` alternative.
    pub(crate) relativename: *mut OpenSslStack,
}

/// `struct DIST_POINT_NAME_st` — `DIST_POINT_NAME`, from `include/openssl/x509v3.h:209-217`.
#[repr(C)]
pub struct DistPointName {
    /// `int type` — the `CHOICE` selector: 0 for `fullname`, 1 for `relativename`.
    pub(crate) type_: c_int,
    /// The `name` union.
    pub(crate) name: DistPointNameName,
    /// `X509_NAME *dpname` — the cached full distribution point name, when `relativename`.
    pub(crate) dpname: *mut X509Name,
}

const _: () = {
    assert!(core::mem::size_of::<DistPointNameName>() == 8);
    assert!(core::mem::size_of::<DistPointName>() == 24);
    assert!(core::mem::offset_of!(DistPointName, type_) == 0);
    assert!(core::mem::offset_of!(DistPointName, name) == 8);
    assert!(core::mem::offset_of!(DistPointName, dpname) == 16);
};

/// `struct DIST_POINT_st` — `DIST_POINT`, from `include/openssl/x509v3.h:234-240`.
#[repr(C)]
pub struct DistPoint {
    /// `DIST_POINT_NAME *distpoint` — the `[0] EXPLICIT DIST_POINT_NAME`, optional.
    pub(crate) distpoint: *mut DistPointName,
    /// `ASN1_BIT_STRING *reasons` — the `[1] IMPLICIT` reason flags, optional.
    pub(crate) reasons: *mut Asn1String,
    /// `GENERAL_NAMES *CRLissuer` — the `[2] IMPLICIT SEQUENCE OF GENERAL_NAME`, optional.
    pub(crate) CRLissuer: *mut OpenSslStack,
    /// `int dp_reasons` — a derived flag the authority does not set here.
    pub(crate) dp_reasons: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<DistPoint>() == 32);
    assert!(core::mem::offset_of!(DistPoint, distpoint) == 0);
    assert!(core::mem::offset_of!(DistPoint, reasons) == 8);
    assert!(core::mem::offset_of!(DistPoint, CRLissuer) == 16);
    assert!(core::mem::offset_of!(DistPoint, dp_reasons) == 24);
};

/// `struct ISSUING_DIST_POINT_st` — `ISSUING_DIST_POINT`, from `include/openssl/x509v3.h:367-374`.
#[repr(C)]
pub struct IssuingDistPoint {
    /// `DIST_POINT_NAME *distpoint` — the `[0] EXPLICIT DIST_POINT_NAME`, optional.
    pub(crate) distpoint: *mut DistPointName,
    /// `int onlyuser` — the `[1] IMPLICIT ASN1_FBOOLEAN`, optional.
    pub(crate) onlyuser: c_int,
    /// `int onlyCA` — the `[2] IMPLICIT ASN1_FBOOLEAN`, optional.
    pub(crate) onlyCA: c_int,
    /// `ASN1_BIT_STRING *onlysomereasons` — the `[3] IMPLICIT` reason flags, optional.
    pub(crate) onlysomereasons: *mut Asn1String,
    /// `int indirectCRL` — the `[4] IMPLICIT ASN1_FBOOLEAN`, optional.
    pub(crate) indirectCRL: c_int,
    /// `int onlyattr` — the `[5] IMPLICIT ASN1_FBOOLEAN`, optional.
    pub(crate) onlyattr: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<IssuingDistPoint>() == 32);
    assert!(core::mem::offset_of!(IssuingDistPoint, distpoint) == 0);
    assert!(core::mem::offset_of!(IssuingDistPoint, onlyuser) == 8);
    assert!(core::mem::offset_of!(IssuingDistPoint, onlyCA) == 12);
    assert!(core::mem::offset_of!(IssuingDistPoint, onlysomereasons) == 16);
    assert!(core::mem::offset_of!(IssuingDistPoint, indirectCRL) == 24);
    assert!(core::mem::offset_of!(IssuingDistPoint, onlyattr) == 28);
};

/// `struct AA_DIST_POINT_st` — `OSSL_AA_DIST_POINT`, from `include/openssl/x509v3.h:1397-1405`.
#[repr(C)]
pub struct AaDistPoint {
    /// `DIST_POINT_NAME *distpoint` — the `[0] EXPLICIT DIST_POINT_NAME`, optional.
    pub(crate) distpoint: *mut DistPointName,
    /// `ASN1_BIT_STRING *reasons` — the `[1] IMPLICIT` reason flags, optional.
    pub(crate) reasons: *mut Asn1String,
    /// `int dp_reasons` — a derived flag the authority does not set here.
    pub(crate) dp_reasons: c_int,
    /// `ASN1_BOOLEAN indirectCRL` — the `[2] IMPLICIT ASN1_FBOOLEAN`, optional.
    pub(crate) indirectCRL: c_int,
    /// `ASN1_BOOLEAN containsUserAttributeCerts` — the `[3] IMPLICIT ASN1_TBOOLEAN`, optional.
    pub(crate) containsUserAttributeCerts: c_int,
    /// `ASN1_BOOLEAN containsAACerts` — the `[4] IMPLICIT ASN1_TBOOLEAN`, optional.
    pub(crate) containsAACerts: c_int,
    /// `ASN1_BOOLEAN containsSOAPublicKeyCerts` — the `[5] IMPLICIT ASN1_TBOOLEAN`, optional.
    pub(crate) containsSOAPublicKeyCerts: c_int,
}

const _: () = {
    assert!(core::mem::size_of::<AaDistPoint>() == 40);
    assert!(core::mem::offset_of!(AaDistPoint, distpoint) == 0);
    assert!(core::mem::offset_of!(AaDistPoint, reasons) == 8);
    assert!(core::mem::offset_of!(AaDistPoint, dp_reasons) == 16);
    assert!(core::mem::offset_of!(AaDistPoint, indirectCRL) == 20);
    assert!(core::mem::offset_of!(AaDistPoint, containsUserAttributeCerts) == 24);
    assert!(core::mem::offset_of!(AaDistPoint, containsAACerts) == 28);
    assert!(core::mem::offset_of!(AaDistPoint, containsSOAPublicKeyCerts) == 32);
};

// ---------------------------------------------------------------------------------------------
// The `DIST_POINT_NAME` CHOICE item — `ASN1_CHOICE_cb(DIST_POINT_NAME, dpn_cb)` (`:323-326`)
// ---------------------------------------------------------------------------------------------

/// `DIST_POINT_NAME`'s `ASN1_AUX` callback — `dpn_cb` (`crypto/x509/v3_crld.c:306-321`).
///
/// On `ASN1_OP_NEW_POST` it clears the cached `dpname`; on `ASN1_OP_FREE_POST` it releases it.
///
/// # Safety
///
/// The item layer's own callback contract: `pval` points at a live `DIST_POINT_NAME` slot for this
/// operation.
unsafe extern "C" fn dpn_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    // SAFETY: `pval` points at a live `DIST_POINT_NAME` for this operation.
    let dpn = unsafe { (*pval).cast::<DistPointName>() };
    match operation {
        // SAFETY: `dpn` is live for this operation.
        ASN1_OP_NEW_POST => unsafe { (*dpn).dpname = ptr::null_mut() },
        // SAFETY: `dpn` is live for this operation.
        ASN1_OP_FREE_POST => unsafe { X509_NAME_free((*dpn).dpname) },
        _ => {}
    }
    1
}

/// The `DIST_POINT_NAME` item's `ASN1_AUX`. Wrapped for the same reason `crate::asn1::p8_pkey` wraps
/// its own: [`Asn1Aux`] holds raw pointers and so is not `Sync` by itself.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants (a null `app_data`, integer offsets, a `None` const-callback and one
// function pointer), written once by the loader, and with no interior mutability reachable through a
// shared reference. The machinery reads only `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX DIST_POINT_NAME_aux = { NULL, 0, 0, 0, dpn_cb, 0, NULL }` —
/// `ASN1_CHOICE_cb(DIST_POINT_NAME, dpn_cb)` (`crypto/x509/v3_crld.c:323`).
static DIST_POINT_NAME_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(dpn_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `DIST_POINT_NAME_ch_tt` — `ASN1_CHOICE_cb(DIST_POINT_NAME, dpn_cb)` (`crypto/x509/v3_crld.c:323-326`):
/// `ASN1_IMP_SEQUENCE_OF(name.fullname, GENERAL_NAME, 0)` and
/// `ASN1_IMP_SET_OF(name.relativename, X509_NAME_ENTRY, 1)`. Both arms live at the union's offset 8.
static DIST_POINT_NAME_CH_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"name.fullname".as_ptr(),
        item: general_name_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF,
        tag: 1,
        offset: 8,
        field_name: c"name.relativename".as_ptr(),
        item: X509_NAME_ENTRY_it as *mut c_void,
    },
];

/// `DIST_POINT_NAME_it`'s descriptor — `ASN1_CHOICE_END_cb(DIST_POINT_NAME, DIST_POINT_NAME, type)`
/// at `crypto/x509/v3_crld.c:326`. The `utype` of a `CHOICE` is the selector's offset, and `funcs`
/// is the `DIST_POINT_NAME_aux` block `ASN1_CHOICE_cb` installs.
static DIST_POINT_NAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(DistPointName, type_) as c_long,
    templates: DIST_POINT_NAME_CH_TT.as_ptr(),
    tcount: 2,
    funcs: (&DIST_POINT_NAME_AUX.0) as *const Asn1Aux as *const c_void,
    size: core::mem::size_of::<DistPointName>() as c_long,
    sname: c"DIST_POINT_NAME".as_ptr(),
};

/// The internal alias a static template can name for the name of an item defined later.
fn general_name_it() -> *const Asn1Item {
    GENERAL_NAME_it()
}

/// `const ASN1_ITEM *DIST_POINT_NAME_it(void)` — `include/openssl/x509v3.h:619`, from
/// `DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)`.
#[no_mangle]
pub extern "C" fn DIST_POINT_NAME_it() -> *const Asn1Item {
    &DIST_POINT_NAME_ITEM
}

/// `DIST_POINT_NAME *DIST_POINT_NAME_new(void)` — `crypto/x509/v3_crld.c:328`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(DIST_POINT_NAME)`.
#[no_mangle]
pub extern "C" fn DIST_POINT_NAME_new() -> *mut DistPointName {
    // SAFETY: `DIST_POINT_NAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(DIST_POINT_NAME_it()).cast::<DistPointName>() }
}

/// `void DIST_POINT_NAME_free(DIST_POINT_NAME *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn DIST_POINT_NAME_free(a: *mut DistPointName) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), DIST_POINT_NAME_it()) }
}

/// `DIST_POINT_NAME *d2i_DIST_POINT_NAME(DIST_POINT_NAME **a, const unsigned char **in, long len)`
/// — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_DIST_POINT_NAME(
    a: *mut *mut DistPointName,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut DistPointName {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, DIST_POINT_NAME_it()).cast::<DistPointName>() }
}

/// `int i2d_DIST_POINT_NAME(const DIST_POINT_NAME *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DIST_POINT_NAME(
    a: *const DistPointName,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, DIST_POINT_NAME_it()) }
}

/// `DIST_POINT_NAME *DIST_POINT_NAME_dup(const DIST_POINT_NAME *a)` — `crypto/x509/v3_crld.c:329`,
/// from `IMPLEMENT_ASN1_DUP_FUNCTION(DIST_POINT_NAME)`.
///
/// # Safety
///
/// `a` is NULL or a live `DIST_POINT_NAME`. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn DIST_POINT_NAME_dup(a: *const DistPointName) -> *mut DistPointName {
    // SAFETY: `a` is NULL or live per the contract; `DIST_POINT_NAME_it()` is a static item.
    unsafe { ASN1_item_dup(DIST_POINT_NAME_it(), a.cast()).cast::<DistPointName>() }
}

// ---------------------------------------------------------------------------------------------
// The `DIST_POINT` SEQUENCE item — `ASN1_SEQUENCE(DIST_POINT)` (`:331-337`)
// ---------------------------------------------------------------------------------------------

/// `DIST_POINT_seq_tt` — `ASN1_SEQUENCE(DIST_POINT)` (`crypto/x509/v3_crld.c:331-335`):
/// `ASN1_EXP_OPT(distpoint, DIST_POINT_NAME, 0)`, `ASN1_IMP_OPT(reasons, ASN1_BIT_STRING, 1)` and
/// `ASN1_IMP_SEQUENCE_OF_OPT(CRLissuer, GENERAL_NAME, 2)`.
static DIST_POINT_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"distpoint".as_ptr(),
        item: dist_point_name_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"reasons".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"CRLissuer".as_ptr(),
        item: general_name_it as *mut c_void,
    },
];

/// `DIST_POINT_it`'s descriptor — `ASN1_SEQUENCE_END(DIST_POINT)` at `crypto/x509/v3_crld.c:335`.
static DIST_POINT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: DIST_POINT_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<DistPoint>() as c_long,
    sname: c"DIST_POINT".as_ptr(),
};

/// The internal alias a static template can name for `DIST_POINT_NAME_it`.
fn dist_point_name_it() -> *const Asn1Item {
    DIST_POINT_NAME_it()
}

/// `const ASN1_ITEM *DIST_POINT_it(void)` — `include/openssl/x509v3.h:618`, from
/// `DECLARE_ASN1_FUNCTIONS(DIST_POINT)`.
#[no_mangle]
pub extern "C" fn DIST_POINT_it() -> *const Asn1Item {
    &DIST_POINT_ITEM
}

/// `DIST_POINT *DIST_POINT_new(void)` — `crypto/x509/v3_crld.c:337`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(DIST_POINT)`.
#[no_mangle]
pub extern "C" fn DIST_POINT_new() -> *mut DistPoint {
    // SAFETY: `DIST_POINT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(DIST_POINT_it()).cast::<DistPoint>() }
}

/// `void DIST_POINT_free(DIST_POINT *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn DIST_POINT_free(a: *mut DistPoint) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), DIST_POINT_it()) }
}

/// `DIST_POINT *d2i_DIST_POINT(DIST_POINT **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_DIST_POINT(
    a: *mut *mut DistPoint,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut DistPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, DIST_POINT_it()).cast::<DistPoint>() }
}

/// `int i2d_DIST_POINT(const DIST_POINT *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_DIST_POINT(a: *const DistPoint, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, DIST_POINT_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `CRL_DIST_POINTS` SEQUENCE OF item — `ASN1_ITEM_TEMPLATE(CRL_DIST_POINTS)` (`:339-342`)
// ---------------------------------------------------------------------------------------------

/// `CRL_DIST_POINTS_item_tt` — `ASN1_ITEM_TEMPLATE(CRL_DIST_POINTS)` at `crypto/x509/v3_crld.c:339`,
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, CRLDistributionPoints, DIST_POINT)`.
static CRL_DIST_POINTS_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"CRLDistributionPoints".as_ptr(),
    item: dist_point_it as *mut c_void,
};

/// `CRL_DIST_POINTS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(CRL_DIST_POINTS)` at
/// `crypto/x509/v3_crld.c:340`: a `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`,
/// `tcount` 0.
static CRL_DIST_POINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &CRL_DIST_POINTS_ITEM_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"CRL_DIST_POINTS".as_ptr(),
};

/// The internal alias a static template can name for `DIST_POINT_it`.
fn dist_point_it() -> *const Asn1Item {
    DIST_POINT_it()
}

/// `const ASN1_ITEM *CRL_DIST_POINTS_it(void)` — `include/openssl/x509v3.h:617`, from
/// `DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)`.
#[no_mangle]
pub extern "C" fn CRL_DIST_POINTS_it() -> *const Asn1Item {
    &CRL_DIST_POINTS_ITEM
}

/// `CRL_DIST_POINTS *CRL_DIST_POINTS_new(void)` — `crypto/x509/v3_crld.c:342`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(CRL_DIST_POINTS)`. A `SEQUENCE OF` value is a stack.
#[no_mangle]
pub extern "C" fn CRL_DIST_POINTS_new() -> *mut OpenSslStack {
    // SAFETY: `CRL_DIST_POINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(CRL_DIST_POINTS_it()).cast::<OpenSslStack>() }
}

/// `void CRL_DIST_POINTS_free(CRL_DIST_POINTS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn CRL_DIST_POINTS_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), CRL_DIST_POINTS_it()) }
}

/// `CRL_DIST_POINTS *d2i_CRL_DIST_POINTS(CRL_DIST_POINTS **a, const unsigned char **in, long len)`
/// — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_CRL_DIST_POINTS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, CRL_DIST_POINTS_it()).cast::<OpenSslStack>() }
}

/// `int i2d_CRL_DIST_POINTS(const CRL_DIST_POINTS *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_CRL_DIST_POINTS(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, CRL_DIST_POINTS_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `ISSUING_DIST_POINT` SEQUENCE item — `ASN1_SEQUENCE(ISSUING_DIST_POINT)` (`:344-353`)
// ---------------------------------------------------------------------------------------------

/// `ISSUING_DIST_POINT_seq_tt` — `ASN1_SEQUENCE(ISSUING_DIST_POINT)` (`crypto/x509/v3_crld.c:344-351`):
/// `distpoint` explicit `[0]`, then `onlyuser`/`onlyCA`/`onlysomereasons`/`indirectCRL`/`onlyattr` as
/// implicit `[1]`–`[5]`.
static ISSUING_DIST_POINT_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"distpoint".as_ptr(),
        item: dist_point_name_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"onlyuser".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 12,
        field_name: c"onlyCA".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 16,
        field_name: c"onlysomereasons".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 24,
        field_name: c"indirectCRL".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 5,
        offset: 28,
        field_name: c"onlyattr".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
];

/// `ISSUING_DIST_POINT_it`'s descriptor — `ASN1_SEQUENCE_END(ISSUING_DIST_POINT)` at
/// `crypto/x509/v3_crld.c:351`.
static ISSUING_DIST_POINT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ISSUING_DIST_POINT_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<IssuingDistPoint>() as c_long,
    sname: c"ISSUING_DIST_POINT".as_ptr(),
};

/// `const ASN1_ITEM *ISSUING_DIST_POINT_it(void)` — `include/openssl/x509v3.h:620`, from
/// `DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)`.
#[no_mangle]
pub extern "C" fn ISSUING_DIST_POINT_it() -> *const Asn1Item {
    &ISSUING_DIST_POINT_ITEM
}

/// `ISSUING_DIST_POINT *ISSUING_DIST_POINT_new(void)` — `crypto/x509/v3_crld.c:353`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(ISSUING_DIST_POINT)`.
#[no_mangle]
pub extern "C" fn ISSUING_DIST_POINT_new() -> *mut IssuingDistPoint {
    // SAFETY: `ISSUING_DIST_POINT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ISSUING_DIST_POINT_it()).cast::<IssuingDistPoint>() }
}

/// `void ISSUING_DIST_POINT_free(ISSUING_DIST_POINT *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ISSUING_DIST_POINT_free(a: *mut IssuingDistPoint) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ISSUING_DIST_POINT_it()) }
}

/// `ISSUING_DIST_POINT *d2i_ISSUING_DIST_POINT(ISSUING_DIST_POINT **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ISSUING_DIST_POINT(
    a: *mut *mut IssuingDistPoint,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IssuingDistPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ISSUING_DIST_POINT_it()).cast::<IssuingDistPoint>() }
}

/// `int i2d_ISSUING_DIST_POINT(const ISSUING_DIST_POINT *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ISSUING_DIST_POINT(
    a: *const IssuingDistPoint,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ISSUING_DIST_POINT_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_AA_DIST_POINT` SEQUENCE item — `ASN1_SEQUENCE(OSSL_AA_DIST_POINT)` (`:554-563`)
// ---------------------------------------------------------------------------------------------

/// `OSSL_AA_DIST_POINT_seq_tt` — `ASN1_SEQUENCE(OSSL_AA_DIST_POINT)`
/// (`crypto/x509/v3_crld.c:554-560`): `distpoint` explicit `[0]`, `reasons` implicit `[1]`,
/// `indirectCRL` `[2]` and the three `ASN1_TBOOLEAN`s `[3]`–`[5]`.
static OSSL_AA_DIST_POINT_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"distpoint".as_ptr(),
        item: dist_point_name_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"reasons".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"indirectCRL".as_ptr(),
        item: ASN1_FBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 20,
        field_name: c"containsUserAttributeCerts".as_ptr(),
        item: ASN1_TBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 24,
        field_name: c"containsAACerts".as_ptr(),
        item: ASN1_TBOOLEAN_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 5,
        offset: 28,
        field_name: c"containsSOAPublicKeyCerts".as_ptr(),
        item: ASN1_TBOOLEAN_it as *mut c_void,
    },
];

/// `OSSL_AA_DIST_POINT_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_AA_DIST_POINT)` at
/// `crypto/x509/v3_crld.c:561`.
static OSSL_AA_DIST_POINT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_AA_DIST_POINT_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<AaDistPoint>() as c_long,
    sname: c"OSSL_AA_DIST_POINT".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_AA_DIST_POINT_it(void)` — `include/openssl/x509v3.h:1407`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_AA_DIST_POINT)`.
#[no_mangle]
pub extern "C" fn OSSL_AA_DIST_POINT_it() -> *const Asn1Item {
    &OSSL_AA_DIST_POINT_ITEM
}

/// `OSSL_AA_DIST_POINT *OSSL_AA_DIST_POINT_new(void)` — `crypto/x509/v3_crld.c:563`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OSSL_AA_DIST_POINT)`.
#[no_mangle]
pub extern "C" fn OSSL_AA_DIST_POINT_new() -> *mut AaDistPoint {
    // SAFETY: `OSSL_AA_DIST_POINT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_AA_DIST_POINT_it()).cast::<AaDistPoint>() }
}

/// `void OSSL_AA_DIST_POINT_free(OSSL_AA_DIST_POINT *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_AA_DIST_POINT_free(a: *mut AaDistPoint) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_AA_DIST_POINT_it()) }
}

/// `OSSL_AA_DIST_POINT *d2i_OSSL_AA_DIST_POINT(OSSL_AA_DIST_POINT **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_AA_DIST_POINT(
    a: *mut *mut AaDistPoint,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AaDistPoint {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OSSL_AA_DIST_POINT_it()).cast::<AaDistPoint>() }
}

/// `int i2d_OSSL_AA_DIST_POINT(const OSSL_AA_DIST_POINT *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_AA_DIST_POINT(
    a: *const AaDistPoint,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_AA_DIST_POINT_it()) }
}

// ---------------------------------------------------------------------------------------------
// `void (*)(void *)` thunks for the typed `sk_*_pop_free` destructors
// ---------------------------------------------------------------------------------------------

/// `sk_GENERAL_NAME_pop_free(..., GENERAL_NAME_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `GENERAL_NAME` (the stack contract).
unsafe extern "C" fn general_name_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `GENERAL_NAME` pointers per the contract.
    unsafe { GENERAL_NAME_free(p.cast::<GeneralName>()) };
}

/// `sk_X509_NAME_ENTRY_pop_free(..., X509_NAME_ENTRY_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `X509_NAME_ENTRY` (the stack contract).
unsafe extern "C" fn x509_name_entry_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `X509_NAME_ENTRY` pointers per the contract.
    unsafe { X509_NAME_ENTRY_free(p.cast::<X509NameEntry>()) };
}

/// `sk_CONF_VALUE_pop_free(..., X509V3_conf_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `sk_DIST_POINT_pop_free(..., DIST_POINT_free)`'s adapter.
///
/// # Safety
///
/// `p` is NULL or a live `DIST_POINT` (the stack contract).
unsafe extern "C" fn dist_point_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `DIST_POINT` pointers per the contract.
    unsafe { DIST_POINT_free(p.cast::<DistPoint>()) };
}

// ---------------------------------------------------------------------------------------------
// The static helpers
// ---------------------------------------------------------------------------------------------

/// `static STACK_OF(GENERAL_NAME) *gnames_from_sectname(X509V3_CTX *ctx, char *sect)` —
/// `crypto/x509/v3_crld.c:46-65`.
///
/// A leading `@` names a config section; otherwise `sect` is a comma-separated list. Either way the
/// result is handed to `v2i_GENERAL_NAMES`. A missing source is `X509V3_R_SECTION_NOT_FOUND`.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `sect` is NUL-terminated (and, when it leads with `@`, its tail
/// names a section).
unsafe fn gnames_from_sectname(ctx: *mut X509V3Ctx, sect: *mut c_char) -> *mut OpenSslStack {
    // SAFETY: `sect` is NUL-terminated per the contract.
    let is_section = c_int::from(unsafe { *sect } == b'@' as c_char) != 0;
    let gnsect = if is_section {
        // SAFETY: `sect` is NUL-terminated; `sect + 1` names a section.
        unsafe { X509V3_get_section(ctx, sect.add(1)) }
    } else {
        // SAFETY: `sect` is NUL-terminated per the contract.
        unsafe { X509V3_parse_list(sect) }
    };
    if gnsect.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CRLD_56) };
        return ptr::null_mut();
    }
    // SAFETY: `ctx` is live and `gnsect` is a live `CONF_VALUE` stack; the NULL method is the
    // authority's own argument.
    let gens = unsafe { v2i_GENERAL_NAMES(ptr::null(), ctx, gnsect) };
    if is_section {
        // SAFETY: `ctx` is live and `gnsect` is a section this call owns.
        unsafe { X509V3_section_free(ctx, gnsect) };
    } else {
        // SAFETY: `gnsect` is a list this call owns; `conf_value_free_thunk` its destructor.
        unsafe { OPENSSL_sk_pop_free(gnsect, Some(conf_value_free_thunk)) };
    }
    gens
}

/// `static int set_dist_point_name(DIST_POINT_NAME **pdp, X509V3_CTX *ctx, CONF_VALUE *cnf)` —
/// `crypto/x509/v3_crld.c:67-136`.
///
/// Builds the `DIST_POINT_NAME` a `fullname`/`relativename` entry names, storing it through `pdp`.
/// `> 0` means handled, `0` means "not a name entry" and `< 0` a failure.
///
/// # Safety
///
/// `pdp` is a writable slot; `ctx` is a live `X509V3_CTX`; `cnf` is a live `CONF_VALUE`.
unsafe fn set_dist_point_name(
    pdp: *mut *mut DistPointName,
    ctx: *mut X509V3Ctx,
    cnf: *mut ConfValue,
) -> c_int {
    let mut fnm: *mut OpenSslStack = ptr::null_mut();
    let mut rnm: *mut OpenSslStack = ptr::null_mut();
    'body: {
        // SAFETY: `cnf` is live per the contract.
        if unsafe { (*cnf).value }.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CRLD_74) };
            break 'body;
        }
        // `HAS_PREFIX(cnf->name, "fullname")` == `strncmp(name, "fullname", 8) == 0`.
        // SAFETY: `name` is NUL-terminated and the literal is static.
        if unsafe { strncmp((*cnf).name, c"fullname".as_ptr(), 8) } == 0 {
            // SAFETY: `ctx` is live and `value` is NUL-terminated per the contract.
            fnm = unsafe { gnames_from_sectname(ctx, (*cnf).value) };
            if fnm.is_null() {
                break 'body;
            }
        // SAFETY: `name` is NUL-terminated and the literal is static.
        } else if unsafe { strcmp((*cnf).name, c"relativename".as_ptr()) } == 0 {
            let nm = X509_NAME_new();
            if nm.is_null() {
                return -1;
            }
            // SAFETY: `ctx` is live and `value` is NUL-terminated per the contract.
            let dnsect = unsafe { X509V3_get_section(ctx, (*cnf).value) };
            if dnsect.is_null() {
                // SAFETY: `nm` is a live value this call owns.
                unsafe { X509_NAME_free(nm) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_92) };
                return -1;
            }
            // SAFETY: `nm` and `dnsect` are live per the contract; `MBSTRING_ASC` is the
            // authority's `chtype`.
            let ret = unsafe { X509V3_NAME_from_section(nm, dnsect, MBSTRING_ASC as c_ulong) };
            // SAFETY: `ctx` is live and `dnsect` is a section this call owns.
            unsafe { X509V3_section_free(ctx, dnsect) };
            // SAFETY: `nm` is live; its `entries` is the fragment this call takes over.
            unsafe {
                rnm = (*nm).entries;
                (*nm).entries = ptr::null_mut();
            }
            // SAFETY: `nm` is a live value this call owns.
            unsafe { X509_NAME_free(nm) };
            // SAFETY: `rnm` is a live stack.
            let num = unsafe { OPENSSL_sk_num(rnm) };
            if ret == 0 || num <= 0 {
                break 'body;
            }
            // SAFETY: `rnm` is live and `num - 1` is in bounds.
            let ne = unsafe { OPENSSL_sk_value(rnm, num - 1) }.cast::<X509NameEntry>();
            // SAFETY: `ne` is a live entry.
            if unsafe { (*ne).set } != 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_108) };
                break 'body;
            }
        } else {
            return 0;
        }

        // SAFETY: `pdp` is a writable slot per the contract.
        if !unsafe { *pdp }.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CRLD_115) };
            break 'body;
        }

        let created = DIST_POINT_NAME_new();
        // SAFETY: `pdp` is a writable slot per the contract.
        unsafe { *pdp = created };
        if created.is_null() {
            break 'body;
        }
        if !fnm.is_null() {
            // SAFETY: `created` is the value just stored through `pdp`; its union member is
            // writable.
            unsafe {
                (*created).type_ = 0;
                (*created).name.fullname = fnm;
            }
        } else {
            // SAFETY: as above.
            unsafe {
                (*created).type_ = 1;
                (*created).name.relativename = rnm;
            }
        }
        return 1;
    }
    // SAFETY: `fnm` is NULL or a stack this call built; `general_name_free_thunk` its destructor.
    unsafe { OPENSSL_sk_pop_free(fnm, Some(general_name_free_thunk)) };
    // SAFETY: `rnm` is NULL or a stack this call built; `x509_name_entry_free_thunk` its destructor.
    unsafe { OPENSSL_sk_pop_free(rnm, Some(x509_name_entry_free_thunk)) };
    -1
}

/// `static const BIT_STRING_BITNAME reason_flags[]` — `crypto/x509/v3_crld.c:138-149`.
///
/// The `-1`/NULL-terminated reason-flag table both the `reasons` and `onlysomereasons` entries read.
static REASON_FLAGS: [BitStringBitname; 10] = [
    BitStringBitname {
        bitnum: 0,
        lname: c"Unused".as_ptr(),
        sname: c"unused".as_ptr(),
    },
    BitStringBitname {
        bitnum: 1,
        lname: c"Key Compromise".as_ptr(),
        sname: c"keyCompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: 2,
        lname: c"CA Compromise".as_ptr(),
        sname: c"CACompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: 3,
        lname: c"Affiliation Changed".as_ptr(),
        sname: c"affiliationChanged".as_ptr(),
    },
    BitStringBitname {
        bitnum: 4,
        lname: c"Superseded".as_ptr(),
        sname: c"superseded".as_ptr(),
    },
    BitStringBitname {
        bitnum: 5,
        lname: c"Cessation Of Operation".as_ptr(),
        sname: c"cessationOfOperation".as_ptr(),
    },
    BitStringBitname {
        bitnum: 6,
        lname: c"Certificate Hold".as_ptr(),
        sname: c"certificateHold".as_ptr(),
    },
    BitStringBitname {
        bitnum: 7,
        lname: c"Privilege Withdrawn".as_ptr(),
        sname: c"privilegeWithdrawn".as_ptr(),
    },
    BitStringBitname {
        bitnum: 8,
        lname: c"AA Compromise".as_ptr(),
        sname: c"AACompromise".as_ptr(),
    },
    BitStringBitname {
        bitnum: -1,
        lname: ptr::null(),
        sname: ptr::null(),
    },
];

/// `static int set_reasons(ASN1_BIT_STRING **preas, char *value)` — `crypto/x509/v3_crld.c:151-184`.
///
/// Parses a comma-separated list of short reason names into a bit string, allocating one on first
/// use. An already-set `*preas` or an unknown name is a failure.
///
/// # Safety
///
/// `preas` is a writable slot; `value` is NUL-terminated.
unsafe fn set_reasons(preas: *mut *mut Asn1String, value: *mut c_char) -> c_int {
    let mut ret = 0;
    // SAFETY: `value` is NUL-terminated per the contract.
    let rsk = unsafe { X509V3_parse_list(value) };
    if rsk.is_null() {
        return 0;
    }
    'body: {
        // SAFETY: `preas` is a writable slot per the contract.
        if !unsafe { *preas }.is_null() {
            break 'body;
        }
        // SAFETY: `rsk` is a live stack.
        let num = unsafe { OPENSSL_sk_num(rsk) };
        let mut i = 0;
        while i < num {
            // SAFETY: `rsk` is live and `i` is in bounds.
            let bnam = unsafe { (*OPENSSL_sk_value(rsk, i).cast::<ConfValue>()).name };
            // SAFETY: `preas` is a writable slot per the contract.
            if unsafe { *preas }.is_null() {
                let bs = ASN1_BIT_STRING_new();
                if bs.is_null() {
                    break 'body;
                }
                // SAFETY: `preas` is a writable slot per the contract.
                unsafe { *preas = bs };
            }
            let mut pbn = REASON_FLAGS.as_ptr();
            let mut matched = false;
            // SAFETY: the table is NULL-`lname`-terminated.
            while !unsafe { (*pbn).lname }.is_null() {
                // SAFETY: `pbn` is a live row and `bnam` is NUL-terminated.
                if unsafe { strcmp((*pbn).sname, bnam) } == 0 {
                    matched = true;
                    // SAFETY: `*preas` is live and `pbn` a live row.
                    if unsafe { ASN1_BIT_STRING_set_bit(*preas, (*pbn).bitnum, 1) } == 0 {
                        break 'body;
                    }
                    break;
                }
                // SAFETY: advancing within the static table.
                pbn = unsafe { pbn.add(1) };
            }
            if !matched {
                break 'body;
            }
            i += 1;
        }
        ret = 1;
    }
    // SAFETY: `rsk` is a live stack this call owns; `conf_value_free_thunk` its destructor.
    unsafe { OPENSSL_sk_pop_free(rsk, Some(conf_value_free_thunk)) };
    ret
}

/// `static int print_reasons(BIO *out, const char *rname, ASN1_BIT_STRING *rflags, int indent)` —
/// `crypto/x509/v3_crld.c:186-206`.
///
/// Prints the set bits of `rflags` by long name, comma-separated, or `<EMPTY>` when none are set.
///
/// # Safety
///
/// `out` is a live BIO; `rname` is NUL-terminated; `rflags` is a live `ASN1_BIT_STRING`.
unsafe fn print_reasons(
    out: *mut Bio,
    rname: *const c_char,
    rflags: *mut Asn1String,
    indent: c_int,
) -> c_int {
    let mut first = true;
    // SAFETY: `out` is live, `rname` is NUL-terminated and the literals are static.
    unsafe {
        BIO_printf(
            out,
            c"%*s%s:\n%*s".as_ptr(),
            indent,
            c"".as_ptr(),
            rname,
            indent + 2,
            c"".as_ptr(),
        )
    };
    let mut pbn = REASON_FLAGS.as_ptr();
    // SAFETY: the table is NULL-`lname`-terminated.
    while !unsafe { (*pbn).lname }.is_null() {
        // SAFETY: `rflags` is live and `pbn` a live row.
        if unsafe { ASN1_BIT_STRING_get_bit(rflags, (*pbn).bitnum) } != 0 {
            if first {
                first = false;
            } else {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c", ".as_ptr()) };
            }
            // SAFETY: `out` is live and `lname` is a static string.
            unsafe { BIO_puts(out, (*pbn).lname) };
        }
        // SAFETY: advancing within the static table.
        pbn = unsafe { pbn.add(1) };
    }
    if first {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"<EMPTY>\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
    1
}

/// `static DIST_POINT *crldp_from_section(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)` —
/// `crypto/x509/v3_crld.c:208-240`.
///
/// Builds a `DIST_POINT` from a config section: the name entries via [`set_dist_point_name`], then
/// `reasons` and `CRLissuer`.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `nval` is a live `CONF_VALUE` stack.
unsafe fn crldp_from_section(ctx: *mut X509V3Ctx, nval: *mut OpenSslStack) -> *mut DistPoint {
    let point = DIST_POINT_new();
    if point.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `nval` is a live stack.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    'body: {
        while i < num {
            // SAFETY: `nval` is live and `i` is in bounds.
            let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
            // SAFETY: `point` is live and `ctx`/`cnf` are per the contract.
            let ret = unsafe { set_dist_point_name(&raw mut (*point).distpoint, ctx, cnf) };
            if ret > 0 {
                i += 1;
                continue;
            }
            if ret < 0 {
                break 'body;
            }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            if unsafe { strcmp((*cnf).name, c"reasons".as_ptr()) } == 0 {
                // SAFETY: `point` is live; `cnf->value` is NUL-terminated.
                if unsafe { set_reasons(&raw mut (*point).reasons, (*cnf).value) } == 0 {
                    break 'body;
                }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            } else if unsafe { strcmp((*cnf).name, c"CRLissuer".as_ptr()) } == 0 {
                // SAFETY: `ctx` is live and `cnf->value` is NUL-terminated.
                let iss = unsafe { gnames_from_sectname(ctx, (*cnf).value) };
                // SAFETY: `point` is live; the field slot is writable.
                unsafe { (*point).CRLissuer = iss };
                if iss.is_null() {
                    break 'body;
                }
            }
            i += 1;
        }
        return point;
    }
    // SAFETY: `point` is a live value this call owns.
    unsafe { DIST_POINT_free(point) };
    ptr::null_mut()
}

/// `static void *v2i_crld(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_crld.c:242-304`.
///
/// Builds a `CRL_DIST_POINTS` stack. An entry with no value names a section (via
/// [`crldp_from_section`]); one with a value is a bare `GENERAL_NAME` wrapped in a `DIST_POINT`.
///
/// # Safety
///
/// `method` is a live row; `ctx` is a live `X509V3_CTX`; `nval` is a live `CONF_VALUE` stack.
unsafe extern "C" fn v2i_crld(
    method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let ctx = ctx.cast::<X509V3Ctx>();
    // SAFETY: `nval` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut gens: *mut OpenSslStack = ptr::null_mut();
    let mut gen: *mut GeneralName = ptr::null_mut();
    let crld = OPENSSL_sk_new_reserve(None, num);
    if crld.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CRLD_254) };
    } else {
        'body: {
            let mut i = 0;
            while i < num {
                // SAFETY: `nval` is live and `i` is in bounds.
                let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
                // SAFETY: `cnf` is live per the contract.
                if unsafe { (*cnf).value }.is_null() {
                    // SAFETY: `ctx` is live and `cnf->name` is NUL-terminated.
                    let dpsect = unsafe { X509V3_get_section(ctx, (*cnf).name) };
                    if dpsect.is_null() {
                        break 'body;
                    }
                    // SAFETY: `ctx` is live and `dpsect` is a live section.
                    let point = unsafe { crldp_from_section(ctx, dpsect) };
                    // SAFETY: `ctx` is live and `dpsect` is a section this call owns.
                    unsafe { X509V3_section_free(ctx, dpsect) };
                    if point.is_null() {
                        break 'body;
                    }
                    // SAFETY: `crld` was reserved for `num`, so the push cannot fail.
                    unsafe { OPENSSL_sk_push(crld, point.cast::<c_void>()) };
                } else {
                    // SAFETY: `method`, `ctx` and `cnf` are per the contract.
                    gen = unsafe { v2i_GENERAL_NAME(method, ctx, cnf) };
                    if gen.is_null() {
                        break 'body;
                    }
                    gens = GENERAL_NAMES_new();
                    if gens.is_null() {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_CRLD_275) };
                        break 'body;
                    }
                    // SAFETY: `gens` is live and `gen` is a value this call built.
                    if unsafe { OPENSSL_sk_push(gens, gen.cast::<c_void>()) } == 0 {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_CRLD_279) };
                        break 'body;
                    }
                    gen = ptr::null_mut();
                    let point = DIST_POINT_new();
                    if point.is_null() {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_CRLD_284) };
                        break 'body;
                    }
                    // SAFETY: `crld` was reserved for `num`, so the push cannot fail.
                    unsafe { OPENSSL_sk_push(crld, point.cast::<c_void>()) };
                    // SAFETY: `point` is live; the field slot is writable.
                    let dpn = DIST_POINT_NAME_new();
                    // SAFETY: `point` is live; the field slot is writable.
                    unsafe { (*point).distpoint = dpn };
                    if dpn.is_null() {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_CRLD_289) };
                        break 'body;
                    }
                    // SAFETY: `point` and its `distpoint` are live; the union member and selector
                    // are writable.
                    unsafe {
                        (*(*point).distpoint).name.fullname = gens;
                        (*(*point).distpoint).type_ = 0;
                    }
                    gens = ptr::null_mut();
                }
                i += 1;
            }
            return crld.cast::<c_void>();
        }
    }
    // SAFETY: `gen` is NULL or a value this call built.
    unsafe { GENERAL_NAME_free(gen) };
    // SAFETY: `gens` is NULL or a stack this call built.
    unsafe { GENERAL_NAMES_free(gens) };
    // SAFETY: `crld` is NULL or a stack this call built; `dist_point_free_thunk` its destructor.
    unsafe { OPENSSL_sk_pop_free(crld, Some(dist_point_free_thunk)) };
    ptr::null_mut()
}

/// `static int print_distpoint(BIO *out, DIST_POINT_NAME *dpn, int indent)` —
/// `crypto/x509/v3_crld.c:420-434`.
///
/// Prints a full name through `OSSL_GENERAL_NAMES_print`, or a relative name by wrapping the
/// fragment in a scratch `X509_NAME` and printing it one-line.
///
/// # Safety
///
/// `out` is a live BIO; `dpn` is a live `DIST_POINT_NAME`.
unsafe fn print_distpoint(out: *mut Bio, dpn: *mut DistPointName, indent: c_int) -> c_int {
    // SAFETY: `dpn` is live per the contract.
    if unsafe { (*dpn).type_ } == 0 {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*sFull Name:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live and `dpn`'s `fullname` is a live `GENERAL_NAMES`.
        unsafe { OSSL_GENERAL_NAMES_print(out, (*dpn).name.fullname, indent) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // The authority builds a scratch `X509_NAME` on the stack and sets only `entries`; every
        // other field is zero here.
        // SAFETY: `X509Name` is a plain-old-data struct for which all-zeroes is valid.
        let mut ntmp: X509Name = unsafe { core::mem::zeroed() };
        // SAFETY: `dpn` is live; `dpn`'s `relativename` is the fragment.
        ntmp.entries = unsafe { (*dpn).name.relativename };
        // SAFETY: `out` is live; the literal is static.
        unsafe {
            BIO_printf(
                out,
                c"%*sRelative Name:\n%*s".as_ptr(),
                indent,
                c"".as_ptr(),
                indent + 2,
                c"".as_ptr(),
            )
        };
        // SAFETY: `out` is live and `ntmp` is a live `X509_NAME`.
        unsafe { X509_NAME_print_ex(out, &raw const ntmp, 0, XN_FLAG_ONELINE) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    }
    1
}

/// `static int i2r_idp(const X509V3_EXT_METHOD *method, void *pidp, BIO *out, int indent)` —
/// `crypto/x509/v3_crld.c:436-458`.
///
/// Human-readable form of an `ISSUING_DIST_POINT`, or `<EMPTY>` when every field is absent.
///
/// # Safety
///
/// `out` is a live BIO; `pidp` is a live `ISSUING_DIST_POINT`.
unsafe extern "C" fn i2r_idp(
    _method: *const X509V3ExtMethod,
    pidp: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let idp = pidp.cast::<IssuingDistPoint>();
    // SAFETY: `idp` is live per the contract.
    if !unsafe { (*idp).distpoint }.is_null() {
        // SAFETY: `out` is live and `idp`'s `distpoint` is a live `DIST_POINT_NAME`.
        unsafe { print_distpoint(out, (*idp).distpoint, indent) };
    }
    // SAFETY: `out` is live; `idp` is live.
    unsafe {
        if (*idp).onlyuser > 0 {
            BIO_printf(
                out,
                c"%*sOnly User Certificates\n".as_ptr(),
                indent,
                c"".as_ptr(),
            );
        }
        if (*idp).onlyCA > 0 {
            BIO_printf(
                out,
                c"%*sOnly CA Certificates\n".as_ptr(),
                indent,
                c"".as_ptr(),
            );
        }
        if (*idp).indirectCRL > 0 {
            BIO_printf(out, c"%*sIndirect CRL\n".as_ptr(), indent, c"".as_ptr());
        }
    }
    // SAFETY: `idp` is live.
    if !unsafe { (*idp).onlysomereasons }.is_null() {
        // SAFETY: `out` is live; `idp`'s `onlysomereasons` is a live bit string.
        unsafe {
            print_reasons(
                out,
                c"Only Some Reasons".as_ptr(),
                (*idp).onlysomereasons,
                indent,
            )
        };
    }
    // SAFETY: `out` is live; `idp` is live.
    unsafe {
        if (*idp).onlyattr > 0 {
            BIO_printf(
                out,
                c"%*sOnly Attribute Certificates\n".as_ptr(),
                indent,
                c"".as_ptr(),
            );
        }
    }
    // SAFETY: `idp` is live.
    let empty = unsafe {
        (*idp).distpoint.is_null()
            && (*idp).onlyuser <= 0
            && (*idp).onlyCA <= 0
            && (*idp).indirectCRL <= 0
            && (*idp).onlysomereasons.is_null()
            && (*idp).onlyattr <= 0
    };
    if empty {
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_printf(out, c"%*s<EMPTY>\n".as_ptr(), indent, c"".as_ptr()) };
    }
    1
}

/// `static void *v2i_idp(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_crld.c:371-418`.
///
/// Builds an `ISSUING_DIST_POINT`: name entries via [`set_dist_point_name`], then the five booleans
/// and `onlysomereasons`. An unknown name is `X509V3_R_INVALID_NAME` with `name=`/`value=` error
/// data.
///
/// # Safety
///
/// `method` is a live row; `ctx` is a live `X509V3_CTX`; `nval` is a live `CONF_VALUE` stack.
unsafe extern "C" fn v2i_idp(
    _method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let ctx = ctx.cast::<X509V3Ctx>();
    let idp = ISSUING_DIST_POINT_new();
    if idp.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CRLD_380) };
        return ptr::null_mut();
    }
    // SAFETY: `nval` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    'body: {
        while i < num {
            // SAFETY: `nval` is live and `i` is in bounds.
            let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
            // SAFETY: `cnf` is live.
            let (name, val) = unsafe { ((*cnf).name, (*cnf).value) };
            // SAFETY: `idp` is live and `ctx`/`cnf` are per the contract.
            let ret = unsafe { set_dist_point_name(&raw mut (*idp).distpoint, ctx, cnf) };
            if ret > 0 {
                i += 1;
                continue;
            }
            if ret < 0 {
                break 'body;
            }
            // SAFETY: `cnf` is live and its field slots are writable.
            if unsafe { strcmp(name, c"onlyuser".as_ptr()) } == 0 {
                // SAFETY: `idp` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*idp).onlyuser) } == 0 {
                    break 'body;
                }
            // SAFETY: `name` is NUL-terminated and the literal is static.
            } else if unsafe { strcmp(name, c"onlyCA".as_ptr()) } == 0 {
                // SAFETY: `idp` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*idp).onlyCA) } == 0 {
                    break 'body;
                }
            // SAFETY: `name` is NUL-terminated and the literal is static.
            } else if unsafe { strcmp(name, c"onlyAA".as_ptr()) } == 0 {
                // SAFETY: `idp` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*idp).onlyattr) } == 0 {
                    break 'body;
                }
            // SAFETY: `name` is NUL-terminated and the literal is static.
            } else if unsafe { strcmp(name, c"indirectCRL".as_ptr()) } == 0 {
                // SAFETY: `idp` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*idp).indirectCRL) } == 0 {
                    break 'body;
                }
            // SAFETY: `name` is NUL-terminated and the literal is static.
            } else if unsafe { strcmp(name, c"onlysomereasons".as_ptr()) } == 0 {
                // SAFETY: `idp` is live; `val` is NUL-terminated.
                if unsafe { set_reasons(&raw mut (*idp).onlysomereasons, val) } == 0 {
                    break 'body;
                }
            } else {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_408) };
                // SAFETY: `cnf` is live per the contract.
                unsafe { conf_add_error_name_value(cnf) };
                break 'body;
            }
            i += 1;
        }
        return idp.cast::<c_void>();
    }
    // SAFETY: `idp` is a live value this call owns.
    unsafe { ISSUING_DIST_POINT_free(idp) };
    ptr::null_mut()
}

/// `static int i2r_crldp(const X509V3_EXT_METHOD *method, void *pcrldp, BIO *out, int indent)` —
/// `crypto/x509/v3_crld.c:460-480`.
///
/// Human-readable form of a `CRL_DIST_POINTS` stack, one blank line between points.
///
/// # Safety
///
/// `out` is a live BIO; `pcrldp` is a live `DIST_POINT` stack.
unsafe extern "C" fn i2r_crldp(
    _method: *const X509V3ExtMethod,
    pcrldp: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let crld = pcrldp.cast::<OpenSslStack>();
    // SAFETY: `crld` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(crld) };
    let mut i = 0;
    while i < num {
        if i > 0 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: `crld` is live and `i` is in bounds.
        let point = unsafe { OPENSSL_sk_value(crld, i) }.cast::<DistPoint>();
        // SAFETY: `point` is live.
        if !unsafe { (*point).distpoint }.is_null() {
            // SAFETY: `out` is live and `point`'s `distpoint` is live.
            unsafe { print_distpoint(out, (*point).distpoint, indent) };
        }
        // SAFETY: `point` is live.
        if !unsafe { (*point).reasons }.is_null() {
            // SAFETY: `out` is live and `point`'s `reasons` is a live bit string.
            unsafe { print_reasons(out, c"Reasons".as_ptr(), (*point).reasons, indent) };
        }
        // SAFETY: `point` is live.
        if !unsafe { (*point).CRLissuer }.is_null() {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_printf(out, c"%*sCRL Issuer:\n".as_ptr(), indent, c"".as_ptr()) };
            // SAFETY: `out` is live and `point`'s `CRLissuer` is a live `GENERAL_NAMES`.
            unsafe { OSSL_GENERAL_NAMES_print(out, (*point).CRLissuer, indent) };
        }
        i += 1;
    }
    1
}

/// `static int i2r_crl_invdate(const X509V3_EXT_METHOD *method, void *date, BIO *bp, int ind)` —
/// `crypto/x509/v3_crld.c:505-513`.
///
/// Indents, then prints the `ASN1_GENERALIZEDTIME`.
///
/// # Safety
///
/// `bp` is a live BIO; `date` is a live `ASN1_GENERALIZEDTIME`.
unsafe extern "C" fn i2r_crl_invdate(
    _method: *const X509V3ExtMethod,
    date: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    // SAFETY: `bp` is live; the literals are static.
    if unsafe { BIO_printf(bp, c"%*s".as_ptr(), ind, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `bp` is live and `date` is a live generalized time.
    if unsafe { ASN1_GENERALIZEDTIME_print(bp, date.cast::<Asn1String>()) } == 0 {
        return 0;
    }
    1
}

/// `static int i2r_object(const X509V3_EXT_METHOD *method, void *oid, BIO *bp, int ind)` —
/// `crypto/x509/v3_crld.c:515-523`.
///
/// Indents, then prints the `ASN1_OBJECT`.
///
/// # Safety
///
/// `bp` is a live BIO; `oid` is a live `ASN1_OBJECT`.
unsafe extern "C" fn i2r_object(
    _method: *const X509V3ExtMethod,
    oid: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    // SAFETY: `bp` is live; the literals are static.
    if unsafe { BIO_printf(bp, c"%*s".as_ptr(), ind, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `bp` is live and `oid` is a live object.
    if unsafe { i2a_ASN1_OBJECT(bp, oid.cast::<Asn1Object>()) } <= 0 {
        return 0;
    }
    1
}

/// `int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname)` —
/// `crypto/x509/v3_crld.c:526-552`, `include/openssl/x509v3.h:622`.
///
/// Appends any `nameRelativeToCRLIssuer` fragment to `iname` and caches the result in `dpn->dpname`.
/// A non-`relativename` (or NULL) `dpn` is a no-op success.
///
/// # Safety
///
/// `dpn` is NULL or a live `DIST_POINT_NAME`; `iname` is a live `X509_NAME`. The cache is owned by
/// `dpn`.
#[no_mangle]
pub unsafe extern "C" fn DIST_POINT_set_dpname(
    dpn: *mut DistPointName,
    iname: *const X509Name,
) -> c_int {
    // SAFETY: `dpn` is NULL or live per the contract.
    if dpn.is_null() || unsafe { (*dpn).type_ } != 1 {
        return 1;
    }
    // SAFETY: `dpn` is live and of `relativename` type.
    let frag = unsafe { (*dpn).name.relativename };
    // SAFETY: `dpn` is live; freeing its cached name is the authority's `just in case` release.
    unsafe { X509_NAME_free((*dpn).dpname) };
    // SAFETY: `iname` is live; the answer is owned by `dpn`.
    let dup = unsafe { X509_NAME_dup(iname) };
    // SAFETY: `dpn` is live; the field slot is writable.
    unsafe { (*dpn).dpname = dup };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `frag` is a live stack.
    let num = unsafe { OPENSSL_sk_num(frag) };
    let mut i = 0;
    'body: {
        while i < num {
            // SAFETY: `frag` is live and `i` is in bounds.
            let ne = unsafe { OPENSSL_sk_value(frag, i) }.cast::<X509NameEntry>();
            // SAFETY: `dpn`'s `dpname` and `ne` are live.
            // The authority's `i ? 0 : 1`: the first entry is added with `set = 1`, the rest with
            // `set = 0` (`crypto/x509/v3_crld.c:541`).
            if unsafe { X509_NAME_add_entry((*dpn).dpname, ne, -1, c_int::from(i == 0)) } == 0 {
                break 'body;
            }
            i += 1;
        }
        // Generate the cached encoding of the name.
        // SAFETY: `dpn`'s `dpname` is live and `NULL` asks for the length only.
        if unsafe { i2d_X509_NAME((*dpn).dpname, ptr::null_mut()) } >= 0 {
            return 1;
        }
    }
    // SAFETY: `dpn`'s `dpname` is a live value this call owns.
    unsafe { X509_NAME_free((*dpn).dpname) };
    // SAFETY: `dpn` is live; the field slot is writable.
    unsafe { (*dpn).dpname = ptr::null_mut() };
    0
}

/// `static int print_boolean(BIO *out, ASN1_BOOLEAN b)` — `crypto/x509/v3_crld.c:565-568`.
///
/// # Safety
///
/// `out` is a live BIO.
unsafe fn print_boolean(out: *mut Bio, b: c_int) -> c_int {
    // SAFETY: `out` is live; the literals are static.
    unsafe {
        BIO_puts(
            out,
            if b != 0 {
                c"TRUE".as_ptr()
            } else {
                c"FALSE".as_ptr()
            },
        )
    }
}

/// `static OSSL_AA_DIST_POINT *aaidp_from_section(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)` —
/// `crypto/x509/v3_crld.c:570-609`.
///
/// Builds an `OSSL_AA_DIST_POINT` from a config section: the name entries, then `reasons`,
/// `indirectCRL` and the three `contains*` booleans.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `nval` is a live `CONF_VALUE` stack.
unsafe fn aaidp_from_section(ctx: *mut X509V3Ctx, nval: *mut OpenSslStack) -> *mut AaDistPoint {
    let point = OSSL_AA_DIST_POINT_new();
    if point.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `nval` is a live stack.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    'body: {
        while i < num {
            // SAFETY: `nval` is live and `i` is in bounds.
            let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
            // SAFETY: `point` is live and `ctx`/`cnf` are per the contract.
            let ret = unsafe { set_dist_point_name(&raw mut (*point).distpoint, ctx, cnf) };
            if ret > 0 {
                i += 1;
                continue;
            }
            if ret < 0 {
                break 'body;
            }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            if unsafe { strcmp((*cnf).name, c"reasons".as_ptr()) } == 0 {
                // SAFETY: `point` is live; `cnf->value` is NUL-terminated.
                if unsafe { set_reasons(&raw mut (*point).reasons, (*cnf).value) } == 0 {
                    break 'body;
                }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            } else if unsafe { strcmp((*cnf).name, c"indirectCRL".as_ptr()) } == 0 {
                // SAFETY: `point` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*point).indirectCRL) } == 0 {
                    break 'body;
                }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            } else if unsafe { strcmp((*cnf).name, c"containsUserAttributeCerts".as_ptr()) } == 0 {
                // SAFETY: `point` is live; the field slot is writable.
                if unsafe {
                    X509V3_get_value_bool(cnf, &raw mut (*point).containsUserAttributeCerts)
                } == 0
                {
                    break 'body;
                }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            } else if unsafe { strcmp((*cnf).name, c"containsAACerts".as_ptr()) } == 0 {
                // SAFETY: `point` is live; the field slot is writable.
                if unsafe { X509V3_get_value_bool(cnf, &raw mut (*point).containsAACerts) } == 0 {
                    break 'body;
                }
            // SAFETY: `cnf` is live and its `name` is NUL-terminated.
            } else if unsafe { strcmp((*cnf).name, c"containsSOAPublicKeyCerts".as_ptr()) } == 0 {
                // SAFETY: `point` is live; the field slot is writable.
                if unsafe {
                    X509V3_get_value_bool(cnf, &raw mut (*point).containsSOAPublicKeyCerts)
                } == 0
                {
                    break 'body;
                }
            }
            i += 1;
        }
        return point;
    }
    // SAFETY: `point` is a live value this call owns.
    unsafe { OSSL_AA_DIST_POINT_free(point) };
    ptr::null_mut()
}

/// `static void *v2i_aaidp(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_crld.c:611-662`.
///
/// Builds an `OSSL_AA_DIST_POINT` from a single entry: a bare `GENERAL_NAME` wrapped in a
/// `DIST_POINT_NAME`, or a section via [`aaidp_from_section`].
///
/// # Safety
///
/// `method` is a live row; `ctx` is a live `X509V3_CTX`; `nval` is a live `CONF_VALUE` stack.
// The authority's `gens = NULL` after `point->distpoint->name.fullname = gens` is dead on the
// success path: the function returns `point` before reaching the `err:` cleanup, and Rust models
// that as a `return` inside the block. It is kept because it is what the authority writes and
// what the cleanup would read if a later change moved the return (as `dsa/check.rs` does).
#[allow(unused_assignments)]
unsafe extern "C" fn v2i_aaidp(
    method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let ctx = ctx.cast::<X509V3Ctx>();
    let mut gens: *mut OpenSslStack = ptr::null_mut();
    let mut gen: *mut GeneralName = ptr::null_mut();
    let mut point: *mut AaDistPoint = ptr::null_mut();
    // SAFETY: `nval` is a live stack per the contract.
    let cnf = unsafe { OPENSSL_sk_value(nval, 0) }.cast::<ConfValue>();
    if cnf.is_null() {
        return ptr::null_mut();
    }
    'body: {
        // SAFETY: `cnf` is live per the contract.
        if unsafe { (*cnf).value }.is_null() {
            // SAFETY: `ctx` is live and `cnf->name` is NUL-terminated.
            let dpsect = unsafe { X509V3_get_section(ctx, (*cnf).name) };
            if dpsect.is_null() {
                break 'body;
            }
            // SAFETY: `ctx` is live and `dpsect` is a live section.
            point = unsafe { aaidp_from_section(ctx, dpsect) };
            // SAFETY: `ctx` is live and `dpsect` is a section this call owns.
            unsafe { X509V3_section_free(ctx, dpsect) };
            if point.is_null() {
                break 'body;
            }
        } else {
            // SAFETY: `method`, `ctx` and `cnf` are per the contract.
            gen = unsafe { v2i_GENERAL_NAME(method, ctx, cnf) };
            if gen.is_null() {
                break 'body;
            }
            gens = GENERAL_NAMES_new();
            if gens.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_635) };
                break 'body;
            }
            // SAFETY: `gens` is live and `gen` is a value this call built.
            if unsafe { OPENSSL_sk_push(gens, gen.cast::<c_void>()) } == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_639) };
                break 'body;
            }
            gen = ptr::null_mut();
            point = OSSL_AA_DIST_POINT_new();
            if point.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_644) };
                break 'body;
            }
            // SAFETY: `point` is live; the field slot is writable.
            let dpn = DIST_POINT_NAME_new();
            // SAFETY: `point` is live; the field slot is writable.
            unsafe { (*point).distpoint = dpn };
            if dpn.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CRLD_648) };
                break 'body;
            }
            // SAFETY: `point` and its `distpoint` are live; the union member and selector are
            // writable.
            unsafe {
                (*(*point).distpoint).name.fullname = gens;
                (*(*point).distpoint).type_ = 0;
            }
            gens = ptr::null_mut();
        }
        return point.cast::<c_void>();
    }
    // SAFETY: `point` is NULL or a value this call owns.
    unsafe { OSSL_AA_DIST_POINT_free(point) };
    // SAFETY: `gen` is NULL or a value this call built.
    unsafe { GENERAL_NAME_free(gen) };
    // SAFETY: `gens` is NULL or a stack this call built.
    unsafe { GENERAL_NAMES_free(gens) };
    ptr::null_mut()
}

/// `static int i2r_aaidp(const X509V3_EXT_METHOD *method, void *dp, BIO *out, int indent)` —
/// `crypto/x509/v3_crld.c:664-713`.
///
/// Human-readable form of an `OSSL_AA_DIST_POINT`, each present field on its own line.
///
/// # Safety
///
/// `out` is a live BIO; `dp` is a live `OSSL_AA_DIST_POINT`.
unsafe extern "C" fn i2r_aaidp(
    _method: *const X509V3ExtMethod,
    dp: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let pdp = dp.cast::<AaDistPoint>();
    // SAFETY: `pdp` is live per the contract.
    if !unsafe { (*pdp).distpoint }.is_null() {
        // SAFETY: `out` is live and `pdp`'s `distpoint` is live.
        if unsafe { print_distpoint(out, (*pdp).distpoint, indent) } <= 0 {
            return 0;
        }
    }
    // SAFETY: `pdp` is live.
    if !unsafe { (*pdp).reasons }.is_null() {
        // SAFETY: `out` is live and `pdp`'s `reasons` is a live bit string.
        if unsafe { print_reasons(out, c"Reasons".as_ptr(), (*pdp).reasons, indent) } <= 0 {
            return 0;
        }
    }
    // SAFETY: `out` is live; `pdp` is live.
    unsafe {
        if (*pdp).indirectCRL != 0
            && (BIO_printf(out, c"%*sIndirect CRL: ".as_ptr(), indent, c"".as_ptr()) <= 0
                || print_boolean(out, (*pdp).indirectCRL) <= 0
                || BIO_puts(out, c"\n".as_ptr()) <= 0)
        {
            return 0;
        }
        if (*pdp).containsUserAttributeCerts != 0
            && (BIO_printf(
                out,
                c"%*sContains User Attribute Certificates: ".as_ptr(),
                indent,
                c"".as_ptr(),
            ) <= 0
                || print_boolean(out, (*pdp).containsUserAttributeCerts) <= 0
                || BIO_puts(out, c"\n".as_ptr()) <= 0)
        {
            return 0;
        }
        if (*pdp).containsAACerts != 0
            && (BIO_printf(
                out,
                c"%*sContains Attribute Authority (AA) Certificates: ".as_ptr(),
                indent,
                c"".as_ptr(),
            ) <= 0
                || print_boolean(out, (*pdp).containsAACerts) <= 0
                || BIO_puts(out, c"\n".as_ptr()) <= 0)
        {
            return 0;
        }
        if (*pdp).containsSOAPublicKeyCerts != 0
            && (BIO_printf(
                out,
                c"%*sContains Source Of Authority (SOA) Public Key Certificates: ".as_ptr(),
                indent,
                c"".as_ptr(),
            ) <= 0
                || print_boolean(out, (*pdp).containsSOAPublicKeyCerts) <= 0
                || BIO_puts(out, c"\n".as_ptr()) <= 0)
        {
            return 0;
        }
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The six rows
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_crld` — `crypto/x509/v3_crld.c:26-34`.
///
/// `NID_crl_distribution_points`, item [`CRL_DIST_POINTS_it`], the [`v2i_crld`] builder and the
/// [`i2r_crldp`] printer.
pub static ossl_v3_crld: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_crl_distribution_points,
    ext_flags: 0,
    it: Some(CRL_DIST_POINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_crld),
    i2r: Some(i2r_crldp),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_freshest_crl` — `crypto/x509/v3_crld.c:36-44`.
///
/// `NID_freshest_crl`, the same `CRL_DIST_POINTS` item and the same two callbacks as
/// [`ossl_v3_crld`].
pub static ossl_v3_freshest_crl: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_freshest_crl,
    ext_flags: 0,
    it: Some(CRL_DIST_POINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_crld),
    i2r: Some(i2r_crldp),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_idp` — `crypto/x509/v3_crld.c:360-369`.
///
/// `NID_issuing_distribution_point`, `X509V3_EXT_MULTILINE`, item [`ISSUING_DIST_POINT_it`], the
/// [`v2i_idp`] builder and the [`i2r_idp`] printer.
pub static ossl_v3_idp: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_issuing_distribution_point,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(ISSUING_DIST_POINT_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_idp),
    i2r: Some(i2r_idp),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_crl_invdate` — `crypto/x509/v3_crld.c:487-494`.
///
/// `NID_invalidity_date`, item `ASN1_GENERALIZEDTIME_it`, printer [`i2r_crl_invdate`]. Both the
/// `i2v` and `v2i` slots are zero.
pub static ossl_v3_crl_invdate: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_invalidity_date,
    ext_flags: 0,
    it: Some(ASN1_GENERALIZEDTIME_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_crl_invdate),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_crl_hold` — `crypto/x509/v3_crld.c:496-503`.
///
/// `NID_hold_instruction_code`, item `ASN1_OBJECT_it`, printer [`i2r_object`]. Both the `i2v` and
/// `v2i` slots are zero.
pub static ossl_v3_crl_hold: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_hold_instruction_code,
    ext_flags: 0,
    it: Some(ASN1_OBJECT_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_object),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_aa_issuing_dist_point` — `crypto/x509/v3_crld.c:715-724`.
///
/// `NID_id_aa_issuing_distribution_point`, item [`OSSL_AA_DIST_POINT_it`], the [`v2i_aaidp`]
/// builder and the [`i2r_aaidp`] printer.
pub static ossl_v3_aa_issuing_dist_point: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_aa_issuing_distribution_point,
    ext_flags: 0,
    it: Some(OSSL_AA_DIST_POINT_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_aaidp),
    i2r: Some(i2r_aaidp),
    r2i: None,
    usr_data: ptr::null_mut(),
};
