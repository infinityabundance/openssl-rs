//! `crypto/cmp/cmp_asn.c` — the CMP item groups and their accessors. Phase 12.4.
//!
//! Every struct is `cmp_local.h`'s spelling in its order and every template is its
//! `ASN1_SEQUENCE`/`ASN1_CHOICE`/`ASN1_ADB`/`ASN1_ITEM_TEMPLATE` macro expanded by hand, so a
//! round trip is not the contract — `docs/PHASE-12-SUBPHASES.md` §3.1 makes the DER bytes the
//! contract. The `OSSL_CRMF_*` item groups the CMP definitions name are landed crate-internally by
//! [`super::crmf_asn`]; the plan orders 12.4 before 12.7 for that reason.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_NULL_it,
    ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_TIME_it, ASN1_UTF8STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new};
use crate::asn1::time::ASN1_TIME_dup;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_dup, X509_ALGOR_free, X509_ALGOR_it};
use crate::cmp::crmf_asn::{
    atav_dup, atav_free, atav_new, certtemplate_dup, certtemplate_free, crmf_atav_it,
    crmf_certid_it, crmf_certtemplate_it, crmf_encryptedkey_it, crmf_encryptedvalue_it,
    crmf_msgs_it, crmf_pkipublicationinfo_it, CrmfAttributeTypeAndValue, CrmfCertId,
    CrmfCertTemplate, CrmfPkiPublicationInfo, SyncAdb, SyncAdbTable,
};
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::{
    Asn1Object, NID_authority_key_identifier, NID_crl_distribution_points, NID_id_it_caCerts,
    NID_id_it_caKeyUpdateInfo, NID_id_it_caProtEncCert, NID_id_it_certProfile,
    NID_id_it_certReqTemplate, NID_id_it_confirmWaitTime, NID_id_it_crlStatusList, NID_id_it_crls,
    NID_id_it_currentCRL, NID_id_it_encKeyPairTypes, NID_id_it_implicitConfirm,
    NID_id_it_keyPairParamRep, NID_id_it_keyPairParamReq, NID_id_it_origPKIMessage,
    NID_id_it_preferredSymmAlg, NID_id_it_revPassphrase, NID_id_it_rootCaCert,
    NID_id_it_rootCaKeyUpdate, NID_id_it_signKeyPairTypes, NID_id_it_suppLangTags,
    NID_id_it_unsupportedOIDs, NID_id_regCtrl_algId, NID_id_regCtrl_rsaKeyLen,
    NID_issuing_distribution_point, OBJ_nid2obj, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_deep_copy, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_new_reserve,
    OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_akeya::{AUTHORITY_KEYID_free, AuthorityKeyid};
use crate::x509::v3_crld::{
    DIST_POINT_NAME_dup, DIST_POINT_NAME_it, DIST_POINT_free, DistPoint, DistPointName,
    ISSUING_DIST_POINT_free, IssuingDistPoint,
};
use crate::x509::v3_genn::{
    GENERAL_NAMES_it, GENERAL_NAME_dup, GENERAL_NAME_free, GENERAL_NAME_it,
    GENERAL_NAME_set1_X509_NAME, GeneralName, GEN_DIRNAME,
};
use crate::x509::x509_cmp::X509_get_issuer_name;
use crate::x509::x509_ext::{X509_CRL_get_ext_d2i, X509_get_ext_d2i};
use crate::x509::x509cset::{X509_CRL_get0_lastUpdate, X509_CRL_get_issuer};
use crate::x509::x_crl::{X509Crl, X509_CRL_dup, X509_CRL_free, X509_CRL_it};
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::X509Name;
use crate::x509::x_req::X509_REQ_it;
use crate::x509::x_x509::{X509_dup, X509_free, X509_it, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cmp/cmp_asn.c";

/// `ERR_LIB_CMP` — `include/openssl/err.h.in:123`.
pub(crate) const ERR_LIB_CMP: c_int = 58;
/// `CMP_R_NULL_ARGUMENT` — `include/openssl/cmperr.h:91`.
const CMP_R_NULL_ARGUMENT: c_int = 103;
/// `ERR_R_PASSED_NULL_PARAMETER` — `(258 | ERR_R_FATAL)`.
const ERR_R_PASSED_NULL_PARAMETER: c_int = 786690;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `(262 | ERR_RFLAG_COMMON)`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `ASN1_R_INVALID_NUMBER` — `include/openssl/asn1err.h`.
const ASN1_R_INVALID_NUMBER: c_int = 187;
/// `ASN1_R_TOO_SMALL` — `include/openssl/asn1err.h`.
const ASN1_R_TOO_SMALL: c_int = 224;
/// `ASN1_R_TOO_LARGE` — `include/openssl/asn1err.h`.
const ASN1_R_TOO_LARGE: c_int = 223;

/// The two type-choice selectors of `OSSL_CMP_CRLSOURCE` — `cmp_asn.c:163-164`.
pub(crate) const OSSL_CMP_CRLSOURCE_DPN: c_int = 0;
pub(crate) const OSSL_CMP_CRLSOURCE_ISSUER: c_int = 1;

/// `ASN1_ITEM_ref(type)`.
const fn item_ref(f: extern "C" fn() -> *const Asn1Item) -> *mut c_void {
    f as *mut c_void
}

/// `ASN1_TEMPLATE` initialiser.
macro_rules! tpl {
    ($flags:expr, $tag:expr, $offset:expr, $name:expr, $item:expr) => {
        Asn1Template {
            flags: $flags,
            tag: $tag,
            offset: $offset,
            field_name: $name.as_ptr(),
            item: $item,
        }
    };
}

/// `ADB_ENTRY(val, ASN1_SIMPLE(...))` — the union arm is at offset 8 in both ADB-carriers here.
macro_rules! adb_entry {
    ($flags:expr, $value:expr, $name:expr, $item:expr) => {
        Asn1AdbTable {
            value: $value as c_long,
            tt: tpl!($flags, 0, 8, $name, $item),
        }
    };
}

/// `static` constructor for a SEQUENCE item.
const fn seq(
    templates: *const Asn1Template,
    tcount: c_long,
    size: c_long,
    sname: *const c_char,
) -> Asn1Item {
    Asn1Item {
        itype: ASN1_ITYPE_SEQUENCE,
        utype: V_ASN1_SEQUENCE as c_long,
        templates,
        tcount,
        funcs: ptr::null(),
        size,
        sname,
    }
}

/// `static` constructor for a CHOICE item.
const fn choice(
    templates: *const Asn1Template,
    tcount: c_long,
    size: c_long,
    sname: *const c_char,
) -> Asn1Item {
    Asn1Item {
        itype: ASN1_ITYPE_CHOICE,
        utype: 0,
        templates,
        tcount,
        funcs: ptr::null(),
        size,
        sname,
    }
}

/// `static` constructor for a `SEQUENCE OF` primitive item template.
const fn template_item(tt: *const Asn1Template, sname: *const c_char) -> Asn1Item {
    Asn1Item {
        itype: ASN1_ITYPE_PRIMITIVE,
        utype: V_ASN1_UNDEF as c_long,
        templates: tt,
        tcount: 0,
        funcs: ptr::null(),
        size: 0,
        sname,
    }
}

/// One raise coordinate of this unit, declared locally because `crypto/cmp/` is not in
/// `gen_err_raise_sites.py`'s covered set.
const fn cmp_site(line: c_int, func: &'static core::ffi::CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: FILE,
        line,
        func,
        lib: ERR_LIB_CMP,
        reason,
        dynamic_reason: false,
    }
}

/// `ERR_raise(ERR_LIB_CMP, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_cmp(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe { raise_site(&cmp_site(line, func, reason)) };
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `DIST_POINT_free`.
///
/// # Safety
/// `p` is a `DIST_POINT`.
unsafe extern "C" fn dist_point_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { DIST_POINT_free(p.cast()) };
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `GENERAL_NAME_free`.
///
/// # Safety
/// `p` is a `GENERAL_NAME`.
unsafe extern "C" fn general_name_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { GENERAL_NAME_free(p.cast()) };
}

/// The `void *(*)(const void *)` duplication hook for a `GENERAL_NAME` stack.
///
/// # Safety
/// `p` is a `GENERAL_NAME`.
unsafe extern "C" fn general_name_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { GENERAL_NAME_dup(p.cast()) }.cast()
}

/// The `void (*)(void *)` shape for `X509_free`.
///
/// # Safety
/// `p` is an `X509`.
unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { X509_free(p.cast()) };
}

/// The `void *(*)(const void *)` duplication hook for `X509_dup`.
///
/// # Safety
/// `p` is an `X509`.
unsafe extern "C" fn x509_dup_void(p: *const c_void) -> *mut c_void {
    // SAFETY: per this function's contract.
    unsafe { X509_dup(p.cast()) }.cast()
}

/// The `void (*)(void *)` shape for the `OSSL_CMP_ATAV` item free.
///
/// # Safety
/// `p` is an `OSSL_CMP_ATAV`.
unsafe extern "C" fn atav_free_void(p: *mut c_void) {
    // SAFETY: per this function's contract.
    unsafe { atav_free(p.cast()) };
}

// ---------------------------------------------------------------------------------------------
// The structures — `cmp_local.h`
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_REVANNCONTENT` — `cmp_local.h:148-154`.
#[repr(C)]
pub(crate) struct CmpRevAnnContent {
    status: *mut Asn1String,
    cert_id: *mut CrmfCertId,
    will_be_revoked_at: *mut Asn1String,
    bad_since_date: *mut Asn1String,
    crl_details: *mut OpenSslStack,
}

/// `OSSL_CMP_CHALLENGE` — `cmp_local.h:181-185`.
#[repr(C)]
pub(crate) struct CmpChallenge {
    owf: *mut X509Algor,
    witness: *mut Asn1String,
    challenge: *mut Asn1String,
}

/// `OSSL_CMP_CAKEYUPDANNCONTENT` — `cmp_local.h:195-199`.
#[repr(C)]
pub(crate) struct CmpCaKeyUpdAnnContent {
    old_with_new: *mut X509,
    new_with_old: *mut X509,
    new_with_new: *mut X509,
}

/// `OSSL_CMP_ROOTCAKEYUPDATE` — `cmp_local.h:789-793`.
#[repr(C)]
pub(crate) struct CmpRootCaKeyUpdate {
    new_with_new: *mut X509,
    new_with_old: *mut X509,
    old_with_new: *mut X509,
}

/// `OSSL_CMP_CERTREQTEMPLATE` — `cmp_local.h:802-805`.
#[repr(C)]
pub(crate) struct CmpCertReqTemplate {
    cert_template: *mut CrmfCertTemplate,
    key_spec: *mut OpenSslStack,
}

/// `OSSL_CMP_CRLSOURCE` — `cmp_local.h:214-220`.
#[repr(C)]
pub(crate) struct CmpCrlSource {
    type_: c_int,
    value: CmpCrlSourceValue,
}

/// The `CRLSOURCE` union.
#[repr(C)]
pub(crate) union CmpCrlSourceValue {
    dpn: *mut DistPointName,
    issuer: *mut OpenSslStack,
}

/// `OSSL_CMP_CRLSTATUS` — `cmp_local.h:229-232`.
#[repr(C)]
pub(crate) struct CmpCrlStatus {
    source: *mut CmpCrlSource,
    this_update: *mut Asn1String,
}

/// `OSSL_CMP_ITAV` — `cmp_local.h:248-298`.
#[repr(C)]
pub(crate) struct CmpItav {
    info_type: *mut Asn1Object,
    info_value: CmpItavValue,
}

/// The `ITAV` union — every arm is a pointer.
#[repr(C)]
pub(crate) union CmpItavValue {
    ptr: *mut c_void,
    ca_prot_enc_cert: *mut X509,
    sign_key_pair_types: *mut OpenSslStack,
    enc_key_pair_types: *mut OpenSslStack,
    preferred_symm_alg: *mut X509Algor,
    ca_key_update_info: *mut CmpCaKeyUpdAnnContent,
    current_crl: *mut X509Crl,
    unsupported_oids: *mut OpenSslStack,
    key_pair_param_req: *mut Asn1Object,
    key_pair_param_rep: *mut X509Algor,
    rev_passphrase: *mut c_void,
    implicit_confirm: *mut Asn1String,
    confirm_wait_time: *mut Asn1String,
    orig_pki_message: *mut OpenSslStack,
    supp_lang_tags_value: *mut OpenSslStack,
    cert_profile: *mut OpenSslStack,
    ca_certs: *mut OpenSslStack,
    root_ca_cert: *mut X509,
    root_ca_key_update: *mut CmpRootCaKeyUpdate,
    cert_req_template: *mut CmpCertReqTemplate,
    crl_status_list: *mut OpenSslStack,
    crls: *mut OpenSslStack,
    other: *mut Asn1Type,
}

/// `OSSL_CMP_CERTORENCCERT` — `cmp_local.h:301-307`.
#[repr(C)]
pub(crate) struct CmpCertOrEncCert {
    type_: c_int,
    value: CmpCertOrEncCertValue,
}

/// The `CERTORENCCERT` union.
#[repr(C)]
pub(crate) union CmpCertOrEncCertValue {
    certificate: *mut X509,
    encrypted_cert: *mut c_void,
}

/// `OSSL_CMP_CERTIFIEDKEYPAIR` — `cmp_local.h:318-322`.
#[repr(C)]
pub(crate) struct CmpCertifiedKeyPair {
    cert_or_enc_cert: *mut CmpCertOrEncCert,
    private_key: *mut c_void,
    publication_info: *mut CrmfPkiPublicationInfo,
}

/// `OSSL_CMP_PKISI` — `cmp_local.h:332-336`.
#[repr(C)]
pub(crate) struct CmpPkisi {
    pub(crate) status: *mut Asn1String,
    pub(crate) status_string: *mut OpenSslStack,
    pub(crate) fail_info: *mut Asn1String,
}

/// `OSSL_CMP_REVDETAILS` — `cmp_local.h:346-349`.
#[repr(C)]
pub(crate) struct CmpRevDetails {
    cert_details: *mut CrmfCertTemplate,
    crl_entry_details: *mut OpenSslStack,
}

/// `OSSL_CMP_REVREPCONTENT` — `cmp_local.h:367-371`.
#[repr(C)]
pub(crate) struct CmpRevRepContent {
    status: *mut OpenSslStack,
    rev_certs: *mut OpenSslStack,
    crls: *mut OpenSslStack,
}

/// `OSSL_CMP_KEYRECREPCONTENT` — `cmp_local.h:384-389`.
#[repr(C)]
pub(crate) struct CmpKeyRecRepContent {
    status: *mut CmpPkisi,
    new_sig_cert: *mut X509,
    ca_certs: *mut OpenSslStack,
    key_pair_hist: *mut OpenSslStack,
}

/// `OSSL_CMP_ERRORMSGCONTENT` — `cmp_local.h:401-405`.
#[repr(C)]
pub(crate) struct CmpErrorMsgContent {
    pub(crate) pki_status_info: *mut CmpPkisi,
    error_code: *mut Asn1String,
    error_details: *mut OpenSslStack,
}

/// `OSSL_CMP_CERTSTATUS` — `cmp_local.h:421-426`.
#[repr(C)]
pub(crate) struct CmpCertStatus {
    cert_hash: *mut Asn1String,
    cert_req_id: *mut Asn1String,
    status_info: *mut CmpPkisi,
    hash_alg: *mut X509Algor,
}

/// `OSSL_CMP_CERTRESPONSE` — `cmp_local.h:444-449`.
#[repr(C)]
pub(crate) struct CmpCertResponse {
    cert_req_id: *mut Asn1String,
    status: *mut CmpPkisi,
    certified_key_pair: *mut CmpCertifiedKeyPair,
    rsp_info: *mut Asn1String,
}

/// `OSSL_CMP_CERTREPMESSAGE` — `cmp_local.h:459-462`.
#[repr(C)]
pub(crate) struct CmpCertRepMessage {
    ca_pubs: *mut OpenSslStack,
    response: *mut OpenSslStack,
}

/// `OSSL_CMP_POLLREQ` — `cmp_local.h:470-472`.
#[repr(C)]
pub(crate) struct CmpPollReq {
    cert_req_id: *mut Asn1String,
}

/// `OSSL_CMP_POLLREP` — `cmp_local.h:485-489`.
#[repr(C)]
pub(crate) struct CmpPollRep {
    cert_req_id: *mut Asn1String,
    check_after: *mut Asn1String,
    reason: *mut OpenSslStack,
}

/// `OSSL_CMP_PKIHEADER` — `cmp_local.h:529-542`.
#[repr(C)]
pub(crate) struct CmpPkiHeader {
    pub(crate) pvno: *mut Asn1String,
    pub(crate) sender: *mut c_void,
    pub(crate) recipient: *mut c_void,
    pub(crate) message_time: *mut Asn1String,
    pub(crate) protection_alg: *mut X509Algor,
    pub(crate) sender_kid: *mut Asn1String,
    pub(crate) recip_kid: *mut Asn1String,
    pub(crate) transaction_id: *mut Asn1String,
    pub(crate) sender_nonce: *mut Asn1String,
    pub(crate) recip_nonce: *mut Asn1String,
    pub(crate) free_text: *mut OpenSslStack,
    pub(crate) general_info: *mut OpenSslStack,
}

/// `OSSL_CMP_PKIBODY` — `cmp_local.h:588-698`.
#[repr(C)]
pub(crate) struct CmpPkiBody {
    pub(crate) type_: c_int,
    pub(crate) value: CmpPkiBodyValue,
}

/// The `PKIBODY` union — all 27 arms are pointers.
#[repr(C)]
pub(crate) union CmpPkiBodyValue {
    ir: *mut OpenSslStack,
    ip: *mut CmpCertRepMessage,
    cr: *mut OpenSslStack,
    cp: *mut CmpCertRepMessage,
    p10cr: *mut c_void,
    popdecc: *mut OpenSslStack,
    popdecr: *mut OpenSslStack,
    kur: *mut OpenSslStack,
    kup: *mut CmpCertRepMessage,
    krr: *mut OpenSslStack,
    krp: *mut CmpKeyRecRepContent,
    rr: *mut OpenSslStack,
    rp: *mut CmpRevRepContent,
    ccr: *mut OpenSslStack,
    ccp: *mut CmpCertRepMessage,
    ckuann: *mut CmpCaKeyUpdAnnContent,
    cann: *mut X509,
    rann: *mut CmpRevAnnContent,
    crlann: *mut OpenSslStack,
    pkiconf: *mut Asn1Type,
    nested: *mut OpenSslStack,
    genm: *mut OpenSslStack,
    genp: *mut OpenSslStack,
    pub(crate) error: *mut CmpErrorMsgContent,
    cert_conf: *mut OpenSslStack,
    poll_req: *mut OpenSslStack,
    poll_rep: *mut OpenSslStack,
}

/// `OSSL_CMP_MSG` — `cmp_local.h:714-722`.
#[repr(C)]
pub(crate) struct CmpMsg {
    pub(crate) header: *mut CmpPkiHeader,
    pub(crate) body: *mut CmpPkiBody,
    pub(crate) protection: *mut Asn1String,
    pub(crate) extra_certs: *mut OpenSslStack,
    pub(crate) libctx: *mut c_void,
    pub(crate) propq: *mut c_char,
}

/// `OSSL_CMP_PROTECTEDPART` — `cmp_local.h:732-735`.
#[repr(C)]
pub(crate) struct CmpProtectedPart {
    header: *mut CmpPkiHeader,
    body: *mut CmpPkiBody,
}

// ---------------------------------------------------------------------------------------------
// The templates
// ---------------------------------------------------------------------------------------------

/// The `OSSL_CMP_MSG` auxiliary block — `ASN1_SEQUENCE_cb(OSSL_CMP_MSG, ossl_cmp_msg_cb)`.
struct SyncAux(Asn1Aux);
// SAFETY: the aux block is compiled from constants and never mutated.
unsafe impl Sync for SyncAux {}

static CMP_REVANNCONTENT_TT: [Asn1Template; 5] = [
    tpl!(0, 0, 0, c"status", item_ref(ASN1_INTEGER_it)),
    tpl!(0, 0, 8, c"certId", item_ref(crmf_certid_it)),
    tpl!(
        0,
        0,
        16,
        c"willBeRevokedAt",
        item_ref(ASN1_GENERALIZEDTIME_it)
    ),
    tpl!(0, 0, 24, c"badSinceDate", item_ref(ASN1_GENERALIZEDTIME_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        32,
        c"crlDetails",
        item_ref(X509_EXTENSION_it)
    ),
];
static CMP_REVANNCONTENT_ITEM: Asn1Item = seq(
    CMP_REVANNCONTENT_TT.as_ptr(),
    5,
    core::mem::size_of::<CmpRevAnnContent>() as c_long,
    c"OSSL_CMP_REVANNCONTENT".as_ptr(),
);

static CMP_CHALLENGE_TT: [Asn1Template; 3] = [
    tpl!(ASN1_TFLG_OPTIONAL, 0, 0, c"owf", item_ref(X509_ALGOR_it)),
    tpl!(0, 0, 8, c"witness", item_ref(ASN1_OCTET_STRING_it)),
    tpl!(0, 0, 16, c"challenge", item_ref(ASN1_OCTET_STRING_it)),
];
static CMP_CHALLENGE_ITEM: Asn1Item = seq(
    CMP_CHALLENGE_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpChallenge>() as c_long,
    c"OSSL_CMP_CHALLENGE".as_ptr(),
);

static CMP_CAKEYUPDANNCONTENT_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"oldWithNew", item_ref(X509_it)),
    tpl!(0, 0, 8, c"newWithOld", item_ref(X509_it)),
    tpl!(0, 0, 16, c"newWithNew", item_ref(X509_it)),
];
static CMP_CAKEYUPDANNCONTENT_ITEM: Asn1Item = seq(
    CMP_CAKEYUPDANNCONTENT_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpCaKeyUpdAnnContent>() as c_long,
    c"OSSL_CMP_CAKEYUPDANNCONTENT".as_ptr(),
);

static CMP_ROOTCAKEYUPDATE_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"newWithNew", item_ref(X509_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"newWithOld",
        item_ref(X509_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        16,
        c"oldWithNew",
        item_ref(X509_it)
    ),
];
static CMP_ROOTCAKEYUPDATE_ITEM: Asn1Item = seq(
    CMP_ROOTCAKEYUPDATE_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpRootCaKeyUpdate>() as c_long,
    c"OSSL_CMP_ROOTCAKEYUPDATE".as_ptr(),
);

static CMP_CERTREQTEMPLATE_TT: [Asn1Template; 2] = [
    tpl!(0, 0, 0, c"certTemplate", item_ref(crmf_certtemplate_it)),
    tpl!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"keySpec",
        item_ref(crmf_atav_it)
    ),
];
static CMP_CERTREQTEMPLATE_ITEM: Asn1Item = seq(
    CMP_CERTREQTEMPLATE_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpCertReqTemplate>() as c_long,
    c"OSSL_CMP_CERTREQTEMPLATE".as_ptr(),
);

static CMP_CRLSOURCE_TT: [Asn1Template; 2] = [
    tpl!(
        ASN1_TFLG_EXPLICIT,
        0,
        8,
        c"value.dpn",
        item_ref(DIST_POINT_NAME_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        1,
        8,
        c"value.issuer",
        item_ref(GENERAL_NAMES_it)
    ),
];
static CMP_CRLSOURCE_ITEM: Asn1Item = choice(
    CMP_CRLSOURCE_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpCrlSource>() as c_long,
    c"OSSL_CMP_CRLSOURCE".as_ptr(),
);

static CMP_CRLSTATUS_TT: [Asn1Template; 2] = [
    tpl!(0, 0, 0, c"source", item_ref(cmp_crlsource_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"thisUpdate",
        item_ref(ASN1_TIME_it)
    ),
];
static CMP_CRLSTATUS_ITEM: Asn1Item = seq(
    CMP_CRLSTATUS_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpCrlStatus>() as c_long,
    c"OSSL_CMP_CRLSTATUS".as_ptr(),
);

static CMP_ITAV_DEFAULT_TT: Asn1Template = tpl!(
    ASN1_TFLG_OPTIONAL,
    0,
    8,
    c"infoValue.other",
    item_ref(ASN1_ANY_it)
);

static CMP_ITAV_ADBTBL: SyncAdbTable<21> = SyncAdbTable([
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_caProtEncCert,
        c"infoValue.caProtEncCert",
        item_ref(X509_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_signKeyPairTypes,
        c"infoValue.signKeyPairTypes",
        item_ref(X509_ALGOR_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_encKeyPairTypes,
        c"infoValue.encKeyPairTypes",
        item_ref(X509_ALGOR_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_preferredSymmAlg,
        c"infoValue.preferredSymmAlg",
        item_ref(X509_ALGOR_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_caKeyUpdateInfo,
        c"infoValue.caKeyUpdateInfo",
        item_ref(cmp_cakeyupdanncontent_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_currentCRL,
        c"infoValue.currentCRL",
        item_ref(X509_CRL_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_unsupportedOIDs,
        c"infoValue.unsupportedOIDs",
        item_ref(ASN1_OBJECT_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_keyPairParamReq,
        c"infoValue.keyPairParamReq",
        item_ref(ASN1_OBJECT_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_keyPairParamRep,
        c"infoValue.keyPairParamRep",
        item_ref(X509_ALGOR_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_revPassphrase,
        c"infoValue.revPassphrase",
        item_ref(crmf_encryptedvalue_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_implicitConfirm,
        c"infoValue.implicitConfirm",
        item_ref(ASN1_NULL_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_confirmWaitTime,
        c"infoValue.confirmWaitTime",
        item_ref(ASN1_GENERALIZEDTIME_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_origPKIMessage,
        c"infoValue.origPKIMessage",
        item_ref(crmf_msgs_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_suppLangTags,
        c"infoValue.suppLangTagsValue",
        item_ref(ASN1_UTF8STRING_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_caCerts,
        c"infoValue.caCerts",
        item_ref(X509_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_rootCaCert,
        c"infoValue.rootCaCert",
        item_ref(X509_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_rootCaKeyUpdate,
        c"infoValue.rootCaKeyUpdate",
        item_ref(cmp_rootcakeyupdate_it)
    ),
    adb_entry!(
        ASN1_TFLG_OPTIONAL,
        NID_id_it_certReqTemplate,
        c"infoValue.certReqTemplate",
        item_ref(cmp_certreqtemplate_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_certProfile,
        c"infoValue.certProfile",
        item_ref(ASN1_UTF8STRING_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_crlStatusList,
        c"infoValue.crlStatusList",
        item_ref(cmp_crlstatus_it)
    ),
    adb_entry!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        NID_id_it_crls,
        c"infoValue.crls",
        item_ref(X509_CRL_it)
    ),
]);

static CMP_ITAV_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: CMP_ITAV_ADBTBL.0.as_ptr(),
    tblcount: 21,
    default_tt: &CMP_ITAV_DEFAULT_TT,
    null_tt: ptr::null(),
});

/// The accessor the `OSSL_CMP_ITAV` ADB field's `item` slot names.
pub(crate) extern "C" fn cmp_itav_adb() -> *const Asn1Item {
    &CMP_ITAV_ADB.0 as *const Asn1Adb as *const Asn1Item
}

static CMP_ITAV_TT: [Asn1Template; 2] = [
    tpl!(0, 0, 0, c"infoType", item_ref(ASN1_OBJECT_it)),
    tpl!(
        ASN1_TFLG_ADB_OID,
        -1,
        0,
        c"OSSL_CMP_ITAV",
        cmp_itav_adb as *mut c_void
    ),
];
static CMP_ITAV_ITEM: Asn1Item = seq(
    CMP_ITAV_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpItav>() as c_long,
    c"OSSL_CMP_ITAV".as_ptr(),
);

static CMP_CERTORENCCERT_TT: [Asn1Template; 2] = [
    tpl!(
        ASN1_TFLG_EXPLICIT,
        0,
        8,
        c"value.certificate",
        item_ref(X509_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        1,
        8,
        c"value.encryptedCert",
        item_ref(crmf_encryptedkey_it)
    ),
];
static CMP_CERTORENCCERT_ITEM: Asn1Item = choice(
    CMP_CERTORENCCERT_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpCertOrEncCert>() as c_long,
    c"OSSL_CMP_CERTORENCCERT".as_ptr(),
);

static CMP_CERTIFIEDKEYPAIR_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"certOrEncCert", item_ref(cmp_certorenccert_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"privateKey",
        item_ref(crmf_encryptedkey_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        16,
        c"publicationInfo",
        item_ref(crmf_pkipublicationinfo_it)
    ),
];
static CMP_CERTIFIEDKEYPAIR_ITEM: Asn1Item = seq(
    CMP_CERTIFIEDKEYPAIR_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpCertifiedKeyPair>() as c_long,
    c"OSSL_CMP_CERTIFIEDKEYPAIR".as_ptr(),
);

static CMP_PKISTATUS_TT: Asn1Template = tpl!(
    ASN1_TFLG_UNIVERSAL,
    0,
    0,
    c"status",
    item_ref(ASN1_INTEGER_it)
);
static CMP_PKISTATUS_ITEM: Asn1Item =
    template_item(&CMP_PKISTATUS_TT, c"OSSL_CMP_PKISTATUS".as_ptr());

static CMP_PKISI_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"status", item_ref(cmp_pkistatus_it)),
    tpl!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"statusString",
        item_ref(ASN1_UTF8STRING_it)
    ),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"failInfo",
        item_ref(ASN1_BIT_STRING_it)
    ),
];
static CMP_PKISI_ITEM: Asn1Item = seq(
    CMP_PKISI_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpPkisi>() as c_long,
    c"OSSL_CMP_PKISI".as_ptr(),
);

static CMP_REVDETAILS_TT: [Asn1Template; 2] = [
    tpl!(0, 0, 0, c"certDetails", item_ref(crmf_certtemplate_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"crlEntryDetails",
        item_ref(X509_EXTENSION_it)
    ),
];
static CMP_REVDETAILS_ITEM: Asn1Item = seq(
    CMP_REVDETAILS_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpRevDetails>() as c_long,
    c"OSSL_CMP_REVDETAILS".as_ptr(),
);

static CMP_REVREPCONTENT_TT: [Asn1Template; 3] = [
    tpl!(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        0,
        c"status",
        item_ref(cmp_pkisi_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"revCerts",
        item_ref(crmf_certid_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        16,
        c"crls",
        item_ref(X509_CRL_it)
    ),
];
static CMP_REVREPCONTENT_ITEM: Asn1Item = seq(
    CMP_REVREPCONTENT_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpRevRepContent>() as c_long,
    c"OSSL_CMP_REVREPCONTENT".as_ptr(),
);

static CMP_KEYRECREPCONTENT_TT: [Asn1Template; 4] = [
    tpl!(0, 0, 0, c"status", item_ref(cmp_pkisi_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"newSigCert",
        item_ref(X509_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        16,
        c"caCerts",
        item_ref(X509_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        2,
        24,
        c"keyPairHist",
        item_ref(cmp_certifiedkeypair_it)
    ),
];
static CMP_KEYRECREPCONTENT_ITEM: Asn1Item = seq(
    CMP_KEYRECREPCONTENT_TT.as_ptr(),
    4,
    core::mem::size_of::<CmpKeyRecRepContent>() as c_long,
    c"OSSL_CMP_KEYRECREPCONTENT".as_ptr(),
);

static CMP_ERRORMSGCONTENT_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"pKIStatusInfo", item_ref(cmp_pkisi_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        8,
        c"errorCode",
        item_ref(ASN1_INTEGER_it)
    ),
    tpl!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"errorDetails",
        item_ref(ASN1_UTF8STRING_it)
    ),
];
static CMP_ERRORMSGCONTENT_ITEM: Asn1Item = seq(
    CMP_ERRORMSGCONTENT_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpErrorMsgContent>() as c_long,
    c"OSSL_CMP_ERRORMSGCONTENT".as_ptr(),
);

static CMP_CERTSTATUS_TT: [Asn1Template; 4] = [
    tpl!(0, 0, 0, c"certHash", item_ref(ASN1_OCTET_STRING_it)),
    tpl!(0, 0, 8, c"certReqId", item_ref(ASN1_INTEGER_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"statusInfo",
        item_ref(cmp_pkisi_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        24,
        c"hashAlg",
        item_ref(X509_ALGOR_it)
    ),
];
static CMP_CERTSTATUS_ITEM: Asn1Item = seq(
    CMP_CERTSTATUS_TT.as_ptr(),
    4,
    core::mem::size_of::<CmpCertStatus>() as c_long,
    c"OSSL_CMP_CERTSTATUS".as_ptr(),
);

static CMP_CERTRESPONSE_TT: [Asn1Template; 4] = [
    tpl!(0, 0, 0, c"certReqId", item_ref(ASN1_INTEGER_it)),
    tpl!(0, 0, 8, c"status", item_ref(cmp_pkisi_it)),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"certifiedKeyPair",
        item_ref(cmp_certifiedkeypair_it)
    ),
    tpl!(
        ASN1_TFLG_OPTIONAL,
        0,
        24,
        c"rspInfo",
        item_ref(ASN1_OCTET_STRING_it)
    ),
];
static CMP_CERTRESPONSE_ITEM: Asn1Item = seq(
    CMP_CERTRESPONSE_TT.as_ptr(),
    4,
    core::mem::size_of::<CmpCertResponse>() as c_long,
    c"OSSL_CMP_CERTRESPONSE".as_ptr(),
);

static CMP_POLLREQ_TT: [Asn1Template; 1] = [tpl!(0, 0, 0, c"certReqId", item_ref(ASN1_INTEGER_it))];
static CMP_POLLREQ_ITEM: Asn1Item = seq(
    CMP_POLLREQ_TT.as_ptr(),
    1,
    core::mem::size_of::<CmpPollReq>() as c_long,
    c"OSSL_CMP_POLLREQ".as_ptr(),
);

static CMP_POLLREP_TT: [Asn1Template; 3] = [
    tpl!(0, 0, 0, c"certReqId", item_ref(ASN1_INTEGER_it)),
    tpl!(0, 0, 8, c"checkAfter", item_ref(ASN1_INTEGER_it)),
    tpl!(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"reason",
        item_ref(ASN1_UTF8STRING_it)
    ),
];
static CMP_POLLREP_ITEM: Asn1Item = seq(
    CMP_POLLREP_TT.as_ptr(),
    3,
    core::mem::size_of::<CmpPollRep>() as c_long,
    c"OSSL_CMP_POLLREP".as_ptr(),
);

static CMP_CERTREPMESSAGE_TT: [Asn1Template; 2] = [
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        0,
        c"caPubs",
        item_ref(X509_it)
    ),
    tpl!(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        8,
        c"response",
        item_ref(cmp_certresponse_it)
    ),
];
static CMP_CERTREPMESSAGE_ITEM: Asn1Item = seq(
    CMP_CERTREPMESSAGE_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpCertRepMessage>() as c_long,
    c"OSSL_CMP_CERTREPMESSAGE".as_ptr(),
);

static CMP_PKIHEADER_TT: [Asn1Template; 12] = [
    tpl!(0, 0, 0, c"pvno", item_ref(ASN1_INTEGER_it)),
    tpl!(0, 0, 8, c"sender", item_ref(GENERAL_NAME_it)),
    tpl!(0, 0, 16, c"recipient", item_ref(GENERAL_NAME_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        24,
        c"messageTime",
        item_ref(ASN1_GENERALIZEDTIME_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        32,
        c"protectionAlg",
        item_ref(X509_ALGOR_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        40,
        c"senderKID",
        item_ref(ASN1_OCTET_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        3,
        48,
        c"recipKID",
        item_ref(ASN1_OCTET_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        4,
        56,
        c"transactionID",
        item_ref(ASN1_OCTET_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        5,
        64,
        c"senderNonce",
        item_ref(ASN1_OCTET_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        6,
        72,
        c"recipNonce",
        item_ref(ASN1_OCTET_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        7,
        80,
        c"freeText",
        item_ref(ASN1_UTF8STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        8,
        88,
        c"generalInfo",
        item_ref(cmp_itav_it)
    ),
];
static CMP_PKIHEADER_ITEM: Asn1Item = seq(
    CMP_PKIHEADER_TT.as_ptr(),
    12,
    core::mem::size_of::<CmpPkiHeader>() as c_long,
    c"OSSL_CMP_PKIHEADER".as_ptr(),
);

static CMP_PKIBODY_TT: [Asn1Template; 27] = [
    tpl!(
        ASN1_TFLG_EXPLICIT,
        0,
        8,
        c"value.ir",
        item_ref(crmf_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        1,
        8,
        c"value.ip",
        item_ref(cmp_certrepmessage_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        2,
        8,
        c"value.cr",
        item_ref(crmf_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        3,
        8,
        c"value.cp",
        item_ref(cmp_certrepmessage_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        4,
        8,
        c"value.p10cr",
        item_ref(X509_REQ_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        5,
        8,
        c"value.popdecc",
        item_ref(cmp_popodecc_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        6,
        8,
        c"value.popdecr",
        item_ref(cmp_popodecr_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        7,
        8,
        c"value.kur",
        item_ref(crmf_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        8,
        8,
        c"value.kup",
        item_ref(cmp_certrepmessage_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        9,
        8,
        c"value.krr",
        item_ref(crmf_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        10,
        8,
        c"value.krp",
        item_ref(cmp_keyrecrepcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        11,
        8,
        c"value.rr",
        item_ref(cmp_revreqcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        12,
        8,
        c"value.rp",
        item_ref(cmp_revrepcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        13,
        8,
        c"value.ccr",
        item_ref(crmf_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        14,
        8,
        c"value.ccp",
        item_ref(cmp_certrepmessage_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        15,
        8,
        c"value.ckuann",
        item_ref(cmp_cakeyupdanncontent_it)
    ),
    tpl!(ASN1_TFLG_EXPLICIT, 16, 8, c"value.cann", item_ref(X509_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        17,
        8,
        c"value.rann",
        item_ref(cmp_revanncontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        18,
        8,
        c"value.crlann",
        item_ref(cmp_crlanncontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        19,
        8,
        c"value.pkiconf",
        item_ref(ASN1_ANY_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        20,
        8,
        c"value.nested",
        item_ref(cmp_msgs_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        21,
        8,
        c"value.genm",
        item_ref(cmp_genmsgcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        22,
        8,
        c"value.genp",
        item_ref(cmp_genrepcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        23,
        8,
        c"value.error",
        item_ref(cmp_errormsgcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        24,
        8,
        c"value.certConf",
        item_ref(cmp_certconfirmcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        25,
        8,
        c"value.pollReq",
        item_ref(cmp_pollreqcontent_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT,
        26,
        8,
        c"value.pollRep",
        item_ref(cmp_pollrepcontent_it)
    ),
];
static CMP_PKIBODY_ITEM: Asn1Item = choice(
    CMP_PKIBODY_TT.as_ptr(),
    27,
    core::mem::size_of::<CmpPkiBody>() as c_long,
    c"OSSL_CMP_PKIBODY".as_ptr(),
);

static CMP_PROTECTEDPART_TT: [Asn1Template; 2] = [
    tpl!(0, 0, 0, c"header", item_ref(cmp_pkiheader_it)),
    tpl!(0, 0, 8, c"body", item_ref(cmp_pkibody_it)),
];
static CMP_PROTECTEDPART_ITEM: Asn1Item = seq(
    CMP_PROTECTEDPART_TT.as_ptr(),
    2,
    core::mem::size_of::<CmpProtectedPart>() as c_long,
    c"OSSL_CMP_PROTECTEDPART".as_ptr(),
);

static CMP_MSG_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(ossl_cmp_msg_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMP_MSG_TT: [Asn1Template; 4] = [
    tpl!(0, 0, 0, c"header", item_ref(cmp_pkiheader_it)),
    tpl!(0, 0, 8, c"body", item_ref(cmp_pkibody_it)),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        16,
        c"protection",
        item_ref(ASN1_BIT_STRING_it)
    ),
    tpl!(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        1,
        24,
        c"extraCerts",
        item_ref(X509_it)
    ),
];
static CMP_MSG_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMP_MSG_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::addr_of!(CMP_MSG_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmpMsg>() as c_long,
    sname: c"OSSL_CMP_MSG".as_ptr(),
};

// ---------------------------------------------------------------------------------------------
// The item-template wrappers (SEQUENCE OF / universal)
// ---------------------------------------------------------------------------------------------

static CMP_ATA_VS_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_ATAVS",
    item_ref(crmf_atav_it)
);
static CMP_ATA_VS_ITEM: Asn1Item = template_item(&CMP_ATA_VS_TT, c"OSSL_CMP_ATAVS".as_ptr());

static CMP_POPODECC_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_POPODECKEYCHALLCONTENT",
    item_ref(cmp_challenge_it)
);
static CMP_POPODECC_ITEM: Asn1Item = template_item(
    &CMP_POPODECC_TT,
    c"OSSL_CMP_POPODECKEYCHALLCONTENT".as_ptr(),
);

static CMP_POPODECR_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_POPODECKEYRESPCONTENT",
    item_ref(ASN1_INTEGER_it)
);
static CMP_POPODECR_ITEM: Asn1Item =
    template_item(&CMP_POPODECR_TT, c"OSSL_CMP_POPODECKEYRESPCONTENT".as_ptr());

static CMP_REVREQCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_REVREQCONTENT",
    item_ref(cmp_revdetails_it)
);
static CMP_REVREQCONTENT_ITEM: Asn1Item =
    template_item(&CMP_REVREQCONTENT_TT, c"OSSL_CMP_REVREQCONTENT".as_ptr());

static CMP_CERTCONFIRMCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_CERTCONFIRMCONTENT",
    item_ref(cmp_certstatus_it)
);
static CMP_CERTCONFIRMCONTENT_ITEM: Asn1Item = template_item(
    &CMP_CERTCONFIRMCONTENT_TT,
    c"OSSL_CMP_CERTCONFIRMCONTENT".as_ptr(),
);

static CMP_POLLREQCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_POLLREQCONTENT",
    item_ref(cmp_pollreq_it)
);
static CMP_POLLREQCONTENT_ITEM: Asn1Item =
    template_item(&CMP_POLLREQCONTENT_TT, c"OSSL_CMP_POLLREQCONTENT".as_ptr());

static CMP_POLLREPCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_POLLREPCONTENT",
    item_ref(cmp_pollrep_it)
);
static CMP_POLLREPCONTENT_ITEM: Asn1Item =
    template_item(&CMP_POLLREPCONTENT_TT, c"OSSL_CMP_POLLREPCONTENT".as_ptr());

static CMP_GENMSGCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_GENMSGCONTENT",
    item_ref(cmp_itav_it)
);
static CMP_GENMSGCONTENT_ITEM: Asn1Item =
    template_item(&CMP_GENMSGCONTENT_TT, c"OSSL_CMP_GENMSGCONTENT".as_ptr());

static CMP_GENREPCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_GENREPCONTENT",
    item_ref(cmp_itav_it)
);
static CMP_GENREPCONTENT_ITEM: Asn1Item =
    template_item(&CMP_GENREPCONTENT_TT, c"OSSL_CMP_GENREPCONTENT".as_ptr());

static CMP_CRLANNCONTENT_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_CRLANNCONTENT",
    item_ref(X509_CRL_it)
);
static CMP_CRLANNCONTENT_ITEM: Asn1Item =
    template_item(&CMP_CRLANNCONTENT_TT, c"OSSL_CMP_CRLANNCONTENT".as_ptr());

static CMP_MSGS_TT: Asn1Template = tpl!(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    0,
    c"OSSL_CMP_MSGS",
    item_ref(cmp_msg_it)
);
static CMP_MSGS_ITEM: Asn1Item = template_item(&CMP_MSGS_TT, c"OSSL_CMP_MSGS".as_ptr());

// ---------------------------------------------------------------------------------------------
// The typed item accessors
// ---------------------------------------------------------------------------------------------

macro_rules! accessor {
    ($fname:ident, $item:ident) => {
        pub(crate) extern "C" fn $fname() -> *const Asn1Item {
            &$item
        }
    };
}
accessor!(cmp_revanncontent_it, CMP_REVANNCONTENT_ITEM);
accessor!(cmp_challenge_it, CMP_CHALLENGE_ITEM);
accessor!(cmp_cakeyupdanncontent_it, CMP_CAKEYUPDANNCONTENT_ITEM);
accessor!(cmp_rootcakeyupdate_it, CMP_ROOTCAKEYUPDATE_ITEM);
accessor!(cmp_certreqtemplate_it, CMP_CERTREQTEMPLATE_ITEM);
accessor!(cmp_crlsource_it, CMP_CRLSOURCE_ITEM);
accessor!(cmp_crlstatus_it, CMP_CRLSTATUS_ITEM);
accessor!(cmp_itav_it, CMP_ITAV_ITEM);
accessor!(cmp_certorenccert_it, CMP_CERTORENCCERT_ITEM);
accessor!(cmp_certifiedkeypair_it, CMP_CERTIFIEDKEYPAIR_ITEM);
accessor!(cmp_pkistatus_it, CMP_PKISTATUS_ITEM);
accessor!(cmp_pkisi_it, CMP_PKISI_ITEM);
accessor!(cmp_revdetails_it, CMP_REVDETAILS_ITEM);
accessor!(cmp_revrepcontent_it, CMP_REVREPCONTENT_ITEM);
accessor!(cmp_keyrecrepcontent_it, CMP_KEYRECREPCONTENT_ITEM);
accessor!(cmp_errormsgcontent_it, CMP_ERRORMSGCONTENT_ITEM);
accessor!(cmp_certstatus_it, CMP_CERTSTATUS_ITEM);
accessor!(cmp_certresponse_it, CMP_CERTRESPONSE_ITEM);
accessor!(cmp_pollreq_it, CMP_POLLREQ_ITEM);
accessor!(cmp_pollrep_it, CMP_POLLREP_ITEM);
accessor!(cmp_certrepmessage_it, CMP_CERTREPMESSAGE_ITEM);
accessor!(cmp_pkiheader_it, CMP_PKIHEADER_ITEM);
accessor!(cmp_pkibody_it, CMP_PKIBODY_ITEM);
accessor!(cmp_protectedpart_it, CMP_PROTECTEDPART_ITEM);
accessor!(cmp_msg_it, CMP_MSG_ITEM);
accessor!(cmp_atavs_it, CMP_ATA_VS_ITEM);
accessor!(cmp_popodecc_it, CMP_POPODECC_ITEM);
accessor!(cmp_popodecr_it, CMP_POPODECR_ITEM);
accessor!(cmp_revreqcontent_it, CMP_REVREQCONTENT_ITEM);
accessor!(cmp_certconfirmcontent_it, CMP_CERTCONFIRMCONTENT_ITEM);
accessor!(cmp_pollreqcontent_it, CMP_POLLREQCONTENT_ITEM);
accessor!(cmp_pollrepcontent_it, CMP_POLLREPCONTENT_ITEM);
accessor!(cmp_genmsgcontent_it, CMP_GENMSGCONTENT_ITEM);
accessor!(cmp_genrepcontent_it, CMP_GENREPCONTENT_ITEM);
accessor!(cmp_crlanncontent_it, CMP_CRLANNCONTENT_ITEM);
accessor!(cmp_msgs_it, CMP_MSGS_ITEM);

/// `OSSL_CMP_PKISTATUS_it` — `DECLARE_ASN1_ITEM(OSSL_CMP_PKISTATUS)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_PKISTATUS_it() -> *const Asn1Item {
    &CMP_PKISTATUS_ITEM
}

// ---------------------------------------------------------------------------------------------
// The message callback and its libctx helper
// ---------------------------------------------------------------------------------------------

/// `int ossl_cmp_msg_set0_libctx(OSSL_CMP_MSG *msg, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `cmp_msg.c:41-55`. Defined here because `ossl_cmp_msg_cb` is this unit's, and the callback
/// needs it on the duplicate path.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CMP_MSG`; `propq` is NULL or a NUL-terminated string.
pub(crate) unsafe fn ossl_cmp_msg_set0_libctx(
    msg: *mut CmpMsg,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if !msg.is_null() {
        // SAFETY: `msg` is live per the contract.
        unsafe {
            (*msg).libctx = libctx;
            CRYPTO_free((*msg).propq.cast(), FILE.as_ptr(), 46);
            (*msg).propq = ptr::null_mut();
        }
        if !propq.is_null() {
            // SAFETY: `propq` is a NUL-terminated string per the contract.
            let dup = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 49) };
            // SAFETY: `msg` is live.
            unsafe { (*msg).propq = dup };
            if dup.is_null() {
                return 0;
            }
        }
    }
    1
}

/// `static int ossl_cmp_msg_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)`
/// — `cmp_asn.c:847-878`.
///
/// # Safety
/// The engine calls this with the `ASN1_AUX` contract: `pval` addresses a live `OSSL_CMP_MSG` for
/// the operations used here.
unsafe extern "C" fn ossl_cmp_msg_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    // SAFETY: `pval` addresses the live value per the engine's contract.
    let msg = unsafe { *pval } as *mut CmpMsg;
    match operation {
        ASN1_OP_FREE_POST => {
            // SAFETY: `msg` is live.
            unsafe { CRYPTO_free((*msg).propq.cast(), FILE.as_ptr(), 854) };
        }
        ASN1_OP_DUP_POST => {
            let old = exarg as *const CmpMsg;
            // SAFETY: both values are live per the engine's contract.
            let ok = unsafe { ossl_cmp_msg_set0_libctx(msg, (*old).libctx, (*old).propq) };
            if ok == 0 {
                return 0;
            }
        }
        ASN1_OP_GET0_LIBCTX => {
            // SAFETY: `exarg` is an `OSSL_LIB_CTX **` per the operation.
            unsafe { *(exarg as *mut *mut c_void) = (*msg).libctx };
        }
        ASN1_OP_GET0_PROPQ => {
            // SAFETY: `exarg` is a `const char **` per the operation.
            unsafe { *(exarg as *mut *const c_char) = (*msg).propq };
        }
        _ => {}
    }
    1
}

// ---------------------------------------------------------------------------------------------
// Allocation / free helpers for the internal item types
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_ITAV_new` — the `IMPLEMENT_ASN1_FUNCTIONS(OSSL_CMP_ITAV)` allocator, crate-internal
/// because `cmp.h` does not declare it.
unsafe fn itav_new() -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_itav_it()) }.cast()
}

/// `OSSL_CMP_ITAV_free` — the item free.
unsafe fn itav_free(itav: *mut CmpItav) {
    // SAFETY: `itav` is NULL or a live item value.
    unsafe { ASN1_item_free(itav.cast(), cmp_itav_it()) };
}

/// `OSSL_CMP_ROOTCAKEYUPDATE_new` — internal.
unsafe fn rootcakeyupdate_new() -> *mut CmpRootCaKeyUpdate {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_rootcakeyupdate_it()) }.cast()
}

/// `OSSL_CMP_ROOTCAKEYUPDATE_free` — internal.
unsafe fn rootcakeyupdate_free(p: *mut CmpRootCaKeyUpdate) {
    // SAFETY: `p` is NULL or a live item value.
    unsafe { ASN1_item_free(p.cast(), cmp_rootcakeyupdate_it()) };
}

/// `OSSL_CMP_CERTREQTEMPLATE_new` — internal.
unsafe fn certreqtemplate_new() -> *mut CmpCertReqTemplate {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_certreqtemplate_it()) }.cast()
}

/// `OSSL_CMP_CRLSTATUS_new` — internal.
unsafe fn crlstatus_new() -> *mut CmpCrlStatus {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_crlstatus_it()) }.cast()
}

/// `OSSL_CMP_CRLSTATUS_free` — the item free.
///
/// # Safety
/// `p` is NULL or a value the item layer built.
unsafe fn crlstatus_free(p: *mut CmpCrlStatus) {
    // SAFETY: `p` is NULL or a live item value.
    unsafe { ASN1_item_free(p.cast(), cmp_crlstatus_it()) };
}

// ---------------------------------------------------------------------------------------------
// The exported surface
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_create(ASN1_OBJECT *type, ASN1_TYPE *value)` — `cmp_asn.c:172`.
///
/// # Safety
/// `type_` is NULL or a live `ASN1_OBJECT`; `value` is NULL or a live `ASN1_TYPE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_create(
    type_: *mut Asn1Object,
    value: *mut Asn1Type,
) -> *mut CmpItav {
    if type_.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live; ownership of `type_`/`value` transfers to it.
    unsafe { OSSL_CMP_ITAV_set0(itav, type_, value) };
    itav
}

/// `void OSSL_CMP_ITAV_set0(OSSL_CMP_ITAV *itav, ASN1_OBJECT *type, ASN1_TYPE *value)` —
/// `cmp_asn.c:182-187`.
///
/// # Safety
/// `itav` is a live `OSSL_CMP_ITAV`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_set0(
    itav: *mut CmpItav,
    type_: *mut Asn1Object,
    value: *mut Asn1Type,
) {
    // SAFETY: `itav` is live per the contract.
    unsafe {
        (*itav).info_type = type_;
        (*itav).info_value.other = value;
    }
}

/// `ASN1_OBJECT *OSSL_CMP_ITAV_get0_type(const OSSL_CMP_ITAV *itav)` — `cmp_asn.c:189-194`.
///
/// # Safety
/// `itav` is NULL or a live `OSSL_CMP_ITAV`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_type(itav: *const CmpItav) -> *mut Asn1Object {
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live per the contract.
    unsafe { (*itav).info_type }
}

/// `ASN1_TYPE *OSSL_CMP_ITAV_get0_value(const OSSL_CMP_ITAV *itav)` — `cmp_asn.c:196-201`.
///
/// # Safety
/// `itav` is NULL or a live `OSSL_CMP_ITAV`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_value(itav: *const CmpItav) -> *mut Asn1Type {
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live per the contract.
    unsafe { (*itav).info_value.other }
}

/// `int OSSL_CMP_ITAV_push0_stack_item(STACK_OF(OSSL_CMP_ITAV) **sk_p, OSSL_CMP_ITAV *itav)` —
/// `cmp_asn.c:203-228`.
///
/// # Safety
/// `itav_sk_p` is NULL or a writable slot; `itav` is NULL or a live `OSSL_CMP_ITAV` that
/// ownership transfers to the stack.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_push0_stack_item(
    itav_sk_p: *mut *mut OpenSslStack,
    itav: *mut CmpItav,
) -> c_int {
    if itav_sk_p.is_null() || itav.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(208, c"OSSL_CMP_ITAV_push0_stack_item", 103) };
        return 0;
    }
    let mut created = false;
    // SAFETY: `itav_sk_p` is writable per the contract.
    let sk = unsafe { *itav_sk_p };
    let sk = if sk.is_null() {
        let new = OPENSSL_sk_new_null();
        if new.is_null() {
            return 0;
        }
        // SAFETY: `itav_sk_p` is writable.
        unsafe { *itav_sk_p = new };
        created = true;
        new
    } else {
        sk
    };
    // SAFETY: `sk` is a live stack.
    if unsafe { OPENSSL_sk_push(sk, itav.cast()) } == 0 {
        if created {
            // SAFETY: `sk` was created here.
            unsafe {
                OPENSSL_sk_free(sk);
                *itav_sk_p = ptr::null_mut();
            }
        }
        return 0;
    }
    1
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new0_certProfile(STACK_OF(ASN1_UTF8STRING) *certProfile)` —
/// `cmp_asn.c:230-240`.
///
/// # Safety
/// `cert_profile` is NULL or a live stack whose ownership transfers to the result.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_certProfile(
    cert_profile: *mut OpenSslStack,
) -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live.
    unsafe {
        (*itav).info_type = OBJ_nid2obj(NID_id_it_certProfile);
        (*itav).info_value.cert_profile = cert_profile;
    }
    itav
}

/// `int OSSL_CMP_ITAV_get0_certProfile(const OSSL_CMP_ITAV *itav, STACK_OF(ASN1_UTF8STRING) **out)`
/// — `cmp_asn.c:242-255`.
///
/// # Safety
/// `itav` is NULL or live; `out` is NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_certProfile(
    itav: *const CmpItav,
    out: *mut *mut OpenSslStack,
) -> c_int {
    if itav.is_null() || out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                246,
                c"OSSL_CMP_ITAV_get0_certProfile",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_certProfile {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                250,
                c"OSSL_CMP_ITAV_get0_certProfile",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: both pointers are live/writable.
    unsafe { *out = (*itav).info_value.cert_profile };
    1
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_caCerts(const STACK_OF(X509) *caCerts)` — `cmp_asn.c:257-270`.
///
/// # Safety
/// `ca_certs` is NULL or a live stack; the result owns a copy.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new_caCerts(ca_certs: *const OpenSslStack) -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ca_certs` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(ca_certs) };
    if n > 0 {
        // SAFETY: the stack and its elements are live.
        let copy =
            unsafe { OPENSSL_sk_deep_copy(ca_certs, Some(x509_dup_void), Some(x509_free_void)) };
        if copy.is_null() {
            // SAFETY: `itav` is live.
            unsafe { itav_free(itav) };
            return ptr::null_mut();
        }
        // SAFETY: `itav` is live.
        unsafe { (*itav).info_value.ca_certs = copy };
    }
    // SAFETY: `itav` is live.
    unsafe { (*itav).info_type = OBJ_nid2obj(NID_id_it_caCerts) };
    itav
}

/// `int OSSL_CMP_ITAV_get0_caCerts(const OSSL_CMP_ITAV *itav, STACK_OF(X509) **out)` —
/// `cmp_asn.c:272-286`.
///
/// # Safety
/// `itav` is NULL or live; `out` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_caCerts(
    itav: *const CmpItav,
    out: *mut *mut OpenSslStack,
) -> c_int {
    if itav.is_null() || out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                275,
                c"OSSL_CMP_ITAV_get0_caCerts",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_caCerts {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                279,
                c"OSSL_CMP_ITAV_get0_caCerts",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    let sk = unsafe { (*itav).info_value.ca_certs };
    // SAFETY: `sk` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(sk) };
    // SAFETY: `out` is writable.
    unsafe { *out = if n > 0 { sk } else { ptr::null_mut() } };
    1
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_rootCaCert(const X509 *rootCaCert)` — `cmp_asn.c:288-301`.
///
/// # Safety
/// `root_ca_cert` is NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new_rootCaCert(root_ca_cert: *const X509) -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    if !root_ca_cert.is_null() {
        // SAFETY: `root_ca_cert` is live.
        let dup = unsafe { X509_dup(root_ca_cert) };
        if dup.is_null() {
            // SAFETY: `itav` is live.
            unsafe { itav_free(itav) };
            return ptr::null_mut();
        }
        // SAFETY: `itav` is live.
        unsafe { (*itav).info_value.root_ca_cert = dup };
    }
    // SAFETY: `itav` is live.
    unsafe { (*itav).info_type = OBJ_nid2obj(NID_id_it_rootCaCert) };
    itav
}

/// `int OSSL_CMP_ITAV_get0_rootCaCert(const OSSL_CMP_ITAV *itav, X509 **out)` — `cmp_asn.c:303-315`.
///
/// # Safety
/// `itav` is NULL or live; `out` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_rootCaCert(
    itav: *const CmpItav,
    out: *mut *mut X509,
) -> c_int {
    if itav.is_null() || out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                306,
                c"OSSL_CMP_ITAV_get0_rootCaCert",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_rootCaCert {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                310,
                c"OSSL_CMP_ITAV_get0_rootCaCert",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: both pointers are live/writable.
    unsafe { *out = (*itav).info_value.root_ca_cert };
    1
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_rootCaKeyUpdate(const X509 *newWithNew, ...)` —
/// `cmp_asn.c:316-347`.
///
/// # Safety
/// Each argument is NULL or a live `X509`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new_rootCaKeyUpdate(
    new_with_new: *const X509,
    new_with_old: *const X509,
    old_with_new: *const X509,
) -> *mut CmpItav {
    let mut upd: *mut CmpRootCaKeyUpdate = ptr::null_mut();
    if !new_with_new.is_null() {
        // SAFETY: the accessor answers a static item.
        upd = unsafe { rootcakeyupdate_new() };
        if upd.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `upd` and `new_with_new` are live.
        let d = unsafe { X509_dup(new_with_new) };
        if d.is_null() {
            // SAFETY: `upd` is live.
            unsafe { rootcakeyupdate_free(upd) };
            return ptr::null_mut();
        }
        // SAFETY: `upd` is live.
        unsafe { (*upd).new_with_new = d };
        if !new_with_old.is_null() {
            // SAFETY: `new_with_old` is live.
            let d = unsafe { X509_dup(new_with_old) };
            if d.is_null() {
                // SAFETY: `upd` is live.
                unsafe { rootcakeyupdate_free(upd) };
                return ptr::null_mut();
            }
            // SAFETY: `upd` is live.
            unsafe { (*upd).new_with_old = d };
        }
        if !old_with_new.is_null() {
            // SAFETY: `old_with_new` is live.
            let d = unsafe { X509_dup(old_with_new) };
            if d.is_null() {
                // SAFETY: `upd` is live.
                unsafe { rootcakeyupdate_free(upd) };
                return ptr::null_mut();
            }
            // SAFETY: `upd` is live.
            unsafe { (*upd).old_with_new = d };
        }
    }
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        // SAFETY: `upd` is NULL or live.
        unsafe { rootcakeyupdate_free(upd) };
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live.
    unsafe {
        (*itav).info_type = OBJ_nid2obj(NID_id_it_rootCaKeyUpdate);
        (*itav).info_value.root_ca_key_update = upd;
    }
    itav
}

/// `int OSSL_CMP_ITAV_get0_rootCaKeyUpdate(const OSSL_CMP_ITAV *itav, ...)` — `cmp_asn.c:349-371`.
///
/// # Safety
/// `itav` is NULL or live; the out-parameters are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_rootCaKeyUpdate(
    itav: *const CmpItav,
    new_with_new: *mut *mut X509,
    new_with_old: *mut *mut X509,
    old_with_new: *mut *mut X509,
) -> c_int {
    if itav.is_null() || new_with_new.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                357,
                c"OSSL_CMP_ITAV_get0_rootCaKeyUpdate",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_rootCaKeyUpdate {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                361,
                c"OSSL_CMP_ITAV_get0_rootCaKeyUpdate",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    let upd = unsafe { (*itav).info_value.root_ca_key_update };
    // SAFETY: `new_with_new` is writable.
    unsafe {
        *new_with_new = if upd.is_null() {
            ptr::null_mut()
        } else {
            (*upd).new_with_new
        }
    };
    if !new_with_old.is_null() {
        // SAFETY: `new_with_old` is writable.
        unsafe {
            *new_with_old = if upd.is_null() {
                ptr::null_mut()
            } else {
                (*upd).new_with_old
            }
        };
    }
    if !old_with_new.is_null() {
        // SAFETY: `old_with_new` is writable.
        unsafe {
            *old_with_new = if upd.is_null() {
                ptr::null_mut()
            } else {
                (*upd).old_with_new
            }
        };
    }
    1
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new0_certReqTemplate(OSSL_CRMF_CERTTEMPLATE *certTemplate,
/// OSSL_CMP_ATAVS *keySpec)` — `cmp_asn.c:373-398`.
///
/// # Safety
/// `cert_template` is NULL or a live value that ownership transfers to the result; `key_spec`
/// likewise.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_certReqTemplate(
    cert_template: *mut CrmfCertTemplate,
    key_spec: *mut OpenSslStack,
) -> *mut CmpItav {
    if cert_template.is_null() && !key_spec.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                381,
                c"OSSL_CMP_ITAV_new0_certReqTemplate",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live.
    unsafe { (*itav).info_type = OBJ_nid2obj(NID_id_it_certReqTemplate) };
    if cert_template.is_null() {
        return itav;
    }
    // SAFETY: the accessor answers a static item.
    let tmpl = unsafe { certreqtemplate_new() };
    if tmpl.is_null() {
        // SAFETY: `itav` is live.
        unsafe { itav_free(itav) };
        return ptr::null_mut();
    }
    // SAFETY: all pointers are live.
    unsafe {
        (*itav).info_value.cert_req_template = tmpl;
        (*tmpl).cert_template = cert_template;
        (*tmpl).key_spec = key_spec;
    }
    itav
}

/// `int OSSL_CMP_ITAV_get1_certReqTemplate(const OSSL_CMP_ITAV *itav, ...)` — `cmp_asn.c:400-469`.
///
/// # Safety
/// `itav` is NULL or live; `cert_template` and `key_spec` are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get1_certReqTemplate(
    itav: *const CmpItav,
    cert_template: *mut *mut CrmfCertTemplate,
    key_spec: *mut *mut OpenSslStack,
) -> c_int {
    if itav.is_null() || cert_template.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(407, c"OSSL_CMP_ITAV_get1_certReqTemplate", 103) };
        return 0;
    }
    // SAFETY: `cert_template` is writable.
    unsafe { *cert_template = ptr::null_mut() };
    if !key_spec.is_null() {
        // SAFETY: `key_spec` is writable.
        unsafe { *key_spec = ptr::null_mut() };
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_certReqTemplate {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                416,
                c"OSSL_CMP_ITAV_get1_certReqTemplate",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    let tpl = unsafe { (*itav).info_value.cert_req_template };
    if tpl.is_null() {
        return 1;
    }
    // SAFETY: `tpl` is live.
    let tpl_cert = unsafe { (*tpl).cert_template };
    // SAFETY: `tpl_cert` is live.
    let dup = unsafe { certtemplate_dup(tpl_cert) };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: `cert_template` is writable.
    unsafe { *cert_template = dup };
    // SAFETY: `tpl` is live.
    let tpl_key = unsafe { (*tpl).key_spec };
    if !key_spec.is_null() && !tpl_key.is_null() {
        // SAFETY: `tpl_key` is a live stack.
        let n = unsafe { OPENSSL_sk_num(tpl_key) };
        let out = OPENSSL_sk_new_reserve(None, n);
        // SAFETY: `key_spec` is writable.
        unsafe { *key_spec = out };
        if out.is_null() {
            // SAFETY: `dup` is live.
            unsafe {
                certtemplate_free(dup);
                *cert_template = ptr::null_mut();
            }
            return 0;
        }
        let mut i = 0;
        while i < n {
            // SAFETY: `tpl_key` is a live stack; `i` is in range.
            let atav = unsafe { OPENSSL_sk_value(tpl_key, i) } as *mut CrmfAttributeTypeAndValue;
            // SAFETY: `atav` is NULL or live.
            let type_ = unsafe { OSSL_CMP_ATAV_get0_type(atav) };
            let bad = type_.is_null() || {
                // SAFETY: `type_` is live.
                let nid = unsafe { OBJ_obj2nid(type_) };
                nid != NID_id_regCtrl_algId && nid != NID_id_regCtrl_rsaKeyLen
            };
            if bad {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cmp(438, c"OSSL_CMP_ITAV_get1_certReqTemplate", 202) };
                // SAFETY: `dup`/`out` are live.
                unsafe {
                    certtemplate_free(dup);
                    *cert_template = ptr::null_mut();
                    OPENSSL_sk_pop_free(out, Some(atav_free_void));
                    *key_spec = ptr::null_mut();
                }
                return 0;
            }
            // SAFETY: `key_spec` is writable and `atav` is live.
            unsafe { OSSL_CMP_ATAV_push1(key_spec, atav) };
            i += 1;
        }
    }
    1
}

/// `OSSL_CMP_ATAV *OSSL_CMP_ATAV_create(ASN1_OBJECT *type, ASN1_TYPE *value)` — `cmp_asn.c:471-479`.
///
/// # Safety
/// `type_` is NULL or a live `ASN1_OBJECT`; `value` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_create(
    type_: *mut Asn1Object,
    value: *mut Asn1Type,
) -> *mut CrmfAttributeTypeAndValue {
    // SAFETY: the accessor answers a static item.
    let atav = unsafe { atav_new() };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `atav` is live; ownership transfers.
    unsafe { OSSL_CMP_ATAV_set0(atav, type_, value) };
    atav
}

/// `void OSSL_CMP_ATAV_set0(OSSL_CMP_ATAV *atav, ASN1_OBJECT *type, ASN1_TYPE *value)` —
/// `cmp_asn.c:481-486`.
///
/// # Safety
/// `atav` is a live `OSSL_CMP_ATAV`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_set0(
    atav: *mut CrmfAttributeTypeAndValue,
    type_: *mut Asn1Object,
    value: *mut Asn1Type,
) {
    // SAFETY: `atav` is live per the contract.
    unsafe {
        (*atav).type_ = type_;
        (*atav).value.other = value.cast();
    }
}

/// `ASN1_OBJECT *OSSL_CMP_ATAV_get0_type(const OSSL_CMP_ATAV *atav)` — `cmp_asn.c:488-493`.
///
/// # Safety
/// `atav` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_type(
    atav: *const CrmfAttributeTypeAndValue,
) -> *mut Asn1Object {
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `atav` is live per the contract.
    unsafe { (*atav).type_ }
}

/// `OSSL_CMP_ATAV *OSSL_CMP_ATAV_new_algId(const X509_ALGOR *alg)` — `cmp_asn.c:495-511`.
///
/// # Safety
/// `alg` is NULL or a live `X509_ALGOR`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_new_algId(
    alg: *const X509Algor,
) -> *mut CrmfAttributeTypeAndValue {
    if alg.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(501, c"OSSL_CMP_ATAV_new_algId", 103) };
        return ptr::null_mut();
    }
    // SAFETY: `alg` is live.
    let dup = unsafe { X509_ALGOR_dup(alg) };
    if dup.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the object table answers a static object.
    let res = unsafe { OSSL_CMP_ATAV_create(OBJ_nid2obj(NID_id_regCtrl_algId), dup.cast()) };
    if res.is_null() {
        // SAFETY: `dup` is live.
        unsafe { X509_ALGOR_free(dup) };
    }
    res
}

/// `X509_ALGOR *OSSL_CMP_ATAV_get0_algId(const OSSL_CMP_ATAV *atav)` — `cmp_asn.c:513-518`.
///
/// # Safety
/// `atav` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_algId(
    atav: *const CrmfAttributeTypeAndValue,
) -> *mut X509Algor {
    if atav.is_null()
        // SAFETY: `atav` is live.
        || unsafe { OBJ_obj2nid((*atav).type_) } != NID_id_regCtrl_algId
    {
        return ptr::null_mut();
    }
    // SAFETY: `atav` is live.
    unsafe { (*atav).value.alg_id }
}

/// `OSSL_CMP_ATAV *OSSL_CMP_ATAV_new_rsaKeyLen(int len)` — `cmp_asn.c:520-537`.
///
/// # Safety
/// Nothing beyond the returned value's ownership.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_new_rsaKeyLen(len: c_int) -> *mut CrmfAttributeTypeAndValue {
    if len <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                526,
                c"OSSL_CMP_ATAV_new_rsaKeyLen",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item.
    let aint = ASN1_INTEGER_new();
    if aint.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `aint` is live.
    if unsafe { crate::asn1::prim::ASN1_INTEGER_set(aint, len as c_long) } == 0 {
        // SAFETY: `aint` is live.
        unsafe { ASN1_INTEGER_free(aint) };
        return ptr::null_mut();
    }
    // SAFETY: the object table answers a static object.
    let res = unsafe { OSSL_CMP_ATAV_create(OBJ_nid2obj(NID_id_regCtrl_rsaKeyLen), aint.cast()) };
    if res.is_null() {
        // SAFETY: `aint` is live.
        unsafe { ASN1_INTEGER_free(aint) };
    }
    res
}

/// `int OSSL_CMP_ATAV_get_rsaKeyLen(const OSSL_CMP_ATAV *atav)` — `cmp_asn.c:539-549`.
///
/// # Safety
/// `atav` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_get_rsaKeyLen(
    atav: *const CrmfAttributeTypeAndValue,
) -> c_int {
    if atav.is_null()
        // SAFETY: `atav` is live.
        || unsafe { OBJ_obj2nid((*atav).type_) } != NID_id_regCtrl_rsaKeyLen
    {
        return -1;
    }
    let mut val: i64 = 0;
    // SAFETY: `atav` is live.
    let rsa = unsafe { (*atav).value.rsa_key_len };
    // SAFETY: `rsa` is live.
    if unsafe { crate::asn1::prim::ASN1_INTEGER_get_int64(&mut val, rsa) } == 0 {
        return -1;
    }
    if val <= 0 || val > c_int::MAX as i64 {
        return -2;
    }
    val as c_int
}

/// `ASN1_TYPE *OSSL_CMP_ATAV_get0_value(const OSSL_CMP_ATAV *atav)` — `cmp_asn.c:551-556`.
///
/// # Safety
/// `atav` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_get0_value(
    atav: *const CrmfAttributeTypeAndValue,
) -> *mut Asn1Type {
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `atav` is live per the contract.
    unsafe { (*atav).value.other as *mut Asn1Type }
}

/// `int OSSL_CMP_ATAV_push1(OSSL_CMP_ATAVS **sk_p, const OSSL_CMP_ATAV *atav)` — `cmp_asn.c:558-586`.
///
/// # Safety
/// `sk_p` is NULL or a writable slot; `atav` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAV_push1(
    sk_p: *mut *mut OpenSslStack,
    atav: *const CrmfAttributeTypeAndValue,
) -> c_int {
    if sk_p.is_null() || atav.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(564, c"OSSL_CMP_ATAV_push1", 103) };
        return 0;
    }
    let mut created = false;
    // SAFETY: `sk_p` is writable.
    let mut sk = unsafe { *sk_p };
    if sk.is_null() {
        sk = OPENSSL_sk_new_null();
        if sk.is_null() {
            return 0;
        }
        // SAFETY: `sk_p` is writable.
        unsafe { *sk_p = sk };
        created = true;
    }
    // SAFETY: `atav` is live.
    let dup = unsafe { atav_dup(atav) };
    if dup.is_null() {
        if created {
            // SAFETY: `sk` was created here.
            unsafe {
                OPENSSL_sk_free(sk);
                *sk_p = ptr::null_mut();
            }
        }
        return 0;
    }
    // SAFETY: `sk` is live.
    if unsafe { OPENSSL_sk_push(sk, dup.cast()) } != 0 {
        return 1;
    }
    // SAFETY: `dup` is live.
    unsafe { atav_free(dup) };
    if created {
        // SAFETY: `sk` was created here.
        unsafe {
            OPENSSL_sk_free(sk);
            *sk_p = ptr::null_mut();
        }
    }
    0
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new0_crlStatusList(STACK_OF(OSSL_CMP_CRLSTATUS) *crlStatusList)`
/// — `cmp_asn.c:588-598`.
///
/// # Safety
/// `crl_status_list` is NULL or a live stack whose ownership transfers to the result.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new0_crlStatusList(
    crl_status_list: *mut OpenSslStack,
) -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `itav` is live.
    unsafe {
        (*itav).info_type = OBJ_nid2obj(NID_id_it_crlStatusList);
        (*itav).info_value.crl_status_list = crl_status_list;
    }
    itav
}

/// `int OSSL_CMP_ITAV_get0_crlStatusList(const OSSL_CMP_ITAV *itav, ...)` — `cmp_asn.c:600-613`.
///
/// # Safety
/// `itav` is NULL or live; `out` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_crlStatusList(
    itav: *const CmpItav,
    out: *mut *mut OpenSslStack,
) -> c_int {
    if itav.is_null() || out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                604,
                c"OSSL_CMP_ITAV_get0_crlStatusList",
                ERR_R_PASSED_NULL_PARAMETER,
            )
        };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_crlStatusList {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                608,
                c"OSSL_CMP_ITAV_get0_crlStatusList",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: both pointers are live/writable.
    unsafe { *out = (*itav).info_value.crl_status_list };
    1
}

/// `OSSL_CMP_CRLSTATUS *OSSL_CMP_CRLSTATUS_new1(const DIST_POINT_NAME *dpn,
/// const GENERAL_NAMES *issuer, const ASN1_TIME *thisUpdate)` — `cmp_asn.c:615-655`.
///
/// # Safety
/// `dpn` and `issuer` are mutually exclusive NULL or live values; `this_update` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_new1(
    dpn: *const DistPointName,
    issuer: *const OpenSslStack,
    this_update: *const Asn1String,
) -> *mut CmpCrlStatus {
    if dpn.is_null() && issuer.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(623, c"OSSL_CMP_CRLSTATUS_new1", ERR_R_PASSED_NULL_PARAMETER) };
        return ptr::null_mut();
    }
    if !dpn.is_null() && !issuer.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                627,
                c"OSSL_CMP_CRLSTATUS_new1",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item.
    let status = unsafe { crlstatus_new() };
    if status.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `status` is live.
    let source = unsafe { (*status).source };
    if !dpn.is_null() {
        // SAFETY: `source` is live.
        unsafe { (*source).type_ = OSSL_CMP_CRLSOURCE_DPN };
        // SAFETY: `dpn` is live.
        let dup = unsafe { DIST_POINT_NAME_dup(dpn) };
        if dup.is_null() {
            // SAFETY: `status` is live.
            unsafe { crlstatus_free(status) };
            return ptr::null_mut();
        }
        // SAFETY: `source` is live.
        unsafe { (*source).value.dpn = dup };
    } else {
        // SAFETY: `source` is live.
        unsafe { (*source).type_ = OSSL_CMP_CRLSOURCE_ISSUER };
        // SAFETY: `issuer` is a live stack.
        let dup = unsafe {
            OPENSSL_sk_deep_copy(
                issuer,
                Some(general_name_dup_void),
                Some(general_name_free_void),
            )
        };
        if dup.is_null() {
            // SAFETY: `status` is live.
            unsafe { crlstatus_free(status) };
            return ptr::null_mut();
        }
        // SAFETY: `source` is live.
        unsafe { (*source).value.issuer = dup };
    }
    if !this_update.is_null() {
        // SAFETY: `this_update` is live.
        let dup = unsafe { ASN1_TIME_dup(this_update) };
        if dup.is_null() {
            // SAFETY: `status` is live.
            unsafe { crlstatus_free(status) };
            return ptr::null_mut();
        }
        // SAFETY: `status` is live.
        unsafe { (*status).this_update = dup };
    }
    status
}

/// `int OSSL_CMP_CRLSTATUS_get0(const OSSL_CMP_CRLSTATUS *crlstatus, ...)` — `cmp_asn.c:755-783`.
///
/// # Safety
/// `crlstatus` is NULL or live; the out-parameters are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_get0(
    crlstatus: *const CmpCrlStatus,
    dpn: *mut *mut DistPointName,
    issuer: *mut *mut OpenSslStack,
    this_update: *mut *mut Asn1String,
) -> c_int {
    if crlstatus.is_null() || dpn.is_null() || issuer.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(761, c"OSSL_CMP_CRLSTATUS_get0", 103) };
        return 0;
    }
    // SAFETY: `crlstatus` is live.
    let source = unsafe { (*crlstatus).source };
    if source.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                766,
                c"OSSL_CMP_CRLSTATUS_get0",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `source` is live.
    let type_ = unsafe { (*source).type_ };
    if type_ == OSSL_CMP_CRLSOURCE_DPN {
        // SAFETY: all pointers are live/writable.
        unsafe {
            *dpn = (*source).value.dpn;
            *issuer = ptr::null_mut();
        }
    } else if type_ == OSSL_CMP_CRLSOURCE_ISSUER {
        // SAFETY: all pointers are live/writable.
        unsafe {
            *dpn = ptr::null_mut();
            *issuer = (*source).value.issuer;
        }
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                777,
                c"OSSL_CMP_CRLSTATUS_get0",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    if !this_update.is_null() {
        // SAFETY: `crlstatus` is live.
        unsafe { *this_update = (*crlstatus).this_update };
    }
    1
}

/// `void OSSL_CMP_CRLSTATUS_free(OSSL_CMP_CRLSTATUS *crlstatus)` — the item free.
///
/// # Safety
/// `crlstatus` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_free(crlstatus: *mut CmpCrlStatus) {
    // SAFETY: `crlstatus` is NULL or a live item value.
    unsafe { crlstatus_free(crlstatus) };
}

/// `static GENERAL_NAMES *gennames_new(const X509_NAME *nm)` — `cmp_asn.c:657-670`.
///
/// # Safety
/// `nm` is NULL or a live `X509_NAME`.
unsafe fn gennames_new(nm: *const X509Name) -> *mut OpenSslStack {
    // SAFETY: `None` is the no-comparator arm and `1` reserves one slot.
    let names = OPENSSL_sk_new_reserve(None, 1);
    if names.is_null() {
        return ptr::null_mut();
    }
    let mut name: *mut GeneralName = ptr::null_mut();
    // SAFETY: `&mut name` is a writable slot; `nm` is the caller's.
    if unsafe { GENERAL_NAME_set1_X509_NAME(&mut name, nm) } == 0 {
        // SAFETY: `names` is live.
        unsafe { OPENSSL_sk_free(names) };
        return ptr::null_mut();
    }
    // SAFETY: `names` is live and `name` is a fresh general name.
    unsafe { OPENSSL_sk_push(names, name.cast()) }; /* cannot fail */
    names
}

/// `static int gennames_allowed(GENERAL_NAMES *names, int only_DN)` — `cmp_asn.c:672-680`.
///
/// # Safety
/// `names` is NULL or a live `GENERAL_NAMES` stack.
unsafe fn gennames_allowed(names: *mut OpenSslStack, only_dn: c_int) -> c_int {
    if names.is_null() {
        return 0;
    }
    if only_dn == 0 {
        return 1;
    }
    // SAFETY: `names` is live.
    if unsafe { OPENSSL_sk_num(names) } != 1 {
        return 0;
    }
    // SAFETY: the stack holds one `GENERAL_NAME`.
    let gen = unsafe { OPENSSL_sk_value(names, 0) }.cast::<GeneralName>();
    // SAFETY: `gen` is live.
    c_int::from(unsafe { (*gen).type_ } == GEN_DIRNAME)
}

/// `OSSL_CMP_CRLSTATUS *OSSL_CMP_CRLSTATUS_create(const X509_CRL *crl, const X509 *cert, int only_DN)`
/// — `cmp_asn.c:682-753`.
///
/// # Safety
/// `crl` and `cert` are NULL or live objects.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_CRLSTATUS_create(
    crl: *const X509Crl,
    cert: *const X509,
    only_dn: c_int,
) -> *mut CmpCrlStatus {
    let mut crldps: *mut OpenSslStack = ptr::null_mut();
    let mut idp: *mut IssuingDistPoint = ptr::null_mut();
    let mut dpn: *mut DistPointName = ptr::null_mut();
    let mut akid: *mut AuthorityKeyid = ptr::null_mut();
    let mut issuers: *mut OpenSslStack = ptr::null_mut();
    let mut crl_issuer: *mut OpenSslStack = ptr::null_mut();
    let last = if crl.is_null() {
        ptr::null()
    } else {
        // SAFETY: `crl` is live on this arm.
        unsafe { X509_CRL_get0_lastUpdate(crl) }
    };
    let mut status: *mut CmpCrlStatus = ptr::null_mut();
    let nid_akid = NID_authority_key_identifier;

    /*
     * Note:
     * X509{,_CRL}_get_ext_d2i(..., NID, ..., NULL) return the 1st extension with
     * given NID that is available, if any. If there are more, this is an error.
     */
    if !cert.is_null() {
        // SAFETY: `cert` is live.
        crldps = unsafe {
            X509_get_ext_d2i(
                cert,
                NID_crl_distribution_points,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .cast();
        /* if available, take the first suitable element */
        let mut i = 0;
        // SAFETY: `crldps` is NULL or a live stack; `OPENSSL_sk_num` handles NULL.
        while i < unsafe { OPENSSL_sk_num(crldps) } {
            // SAFETY: `i` is a valid index when `crldps` is live.
            let dp = unsafe { OPENSSL_sk_value(crldps, i) }.cast::<DistPoint>();
            i += 1;
            if dp.is_null() {
                continue;
            }
            // SAFETY: `dp` is live.
            dpn = unsafe { (*dp).distpoint };
            if !dpn.is_null() {
                crl_issuer = ptr::null_mut();
                break;
            }
            // SAFETY: `dp` is live.
            if unsafe { gennames_allowed((*dp).CRLissuer, only_dn) } != 0 && crl_issuer.is_null() {
                /* don't break because any dp->distpoint in list is preferred */
                // SAFETY: `dp` is live.
                crl_issuer = unsafe { (*dp).CRLissuer };
            }
        }
    } else {
        if crl.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cmp(718, c"OSSL_CMP_CRLSTATUS_create", CMP_R_NULL_ARGUMENT) };
            return ptr::null_mut();
        }
        // SAFETY: `crl` is live.
        idp = unsafe {
            X509_CRL_get_ext_d2i(
                crl,
                NID_issuing_distribution_point,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        }
        .cast();
        // SAFETY: `idp` is NULL or live.
        if !idp.is_null() && !unsafe { (*idp).distpoint }.is_null() {
            // SAFETY: `idp` is live.
            dpn = unsafe { (*idp).distpoint };
        }
    }

    if dpn.is_null() && crl_issuer.is_null() {
        if !cert.is_null() {
            // SAFETY: `cert` is live.
            akid = unsafe { X509_get_ext_d2i(cert, nid_akid, ptr::null_mut(), ptr::null_mut()) }
                .cast();
            // SAFETY: `akid` is NULL or live.
            if !akid.is_null() && unsafe { gennames_allowed((*akid).issuer, only_dn) } != 0 {
                // SAFETY: `akid` is live.
                crl_issuer = unsafe { (*akid).issuer };
            } else {
                // SAFETY: `cert` is live.
                crl_issuer = unsafe { gennames_new(X509_get_issuer_name(cert)) };
                issuers = crl_issuer;
            }
        }
        if crl_issuer.is_null() && !crl.is_null() {
            // SAFETY: `crl` is live.
            akid = unsafe { X509_CRL_get_ext_d2i(crl, nid_akid, ptr::null_mut(), ptr::null_mut()) }
                .cast();
            // SAFETY: `akid` is NULL or live.
            if !akid.is_null() && unsafe { gennames_allowed((*akid).issuer, only_dn) } != 0 {
                // SAFETY: `akid` is live.
                crl_issuer = unsafe { (*akid).issuer };
            } else {
                // SAFETY: `crl` is live.
                crl_issuer = unsafe { gennames_new(X509_CRL_get_issuer(crl)) };
                issuers = crl_issuer;
            }
        }
        if crl_issuer.is_null() {
            // goto end
            // SAFETY: the four values are NULL or live, per the contract.
            unsafe {
                OPENSSL_sk_pop_free(crldps, Some(dist_point_free_void));
                ISSUING_DIST_POINT_free(idp);
                AUTHORITY_KEYID_free(akid);
                OPENSSL_sk_pop_free(issuers, Some(general_name_free_void));
            }
            return status;
        }
    }

    // SAFETY: `dpn`/`crl_issuer`/`last` are the caller's per the contract.
    status = unsafe { OSSL_CMP_CRLSTATUS_new1(dpn, crl_issuer, last) };
    // SAFETY: the four values are NULL or live, per the contract.
    unsafe {
        OPENSSL_sk_pop_free(crldps, Some(dist_point_free_void));
        ISSUING_DIST_POINT_free(idp);
        AUTHORITY_KEYID_free(akid);
        OPENSSL_sk_pop_free(issuers, Some(general_name_free_void));
    }
    status
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_new_crls(const X509_CRL *crl)` — `cmp_asn.c:785-811`.
///
/// # Safety
/// `crl` is NULL or a live `X509_CRL`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_new_crls(crl: *const X509Crl) -> *mut CmpItav {
    // SAFETY: the accessor answers a static item.
    let itav = unsafe { itav_new() };
    if itav.is_null() {
        return ptr::null_mut();
    }
    let mut crls: *mut OpenSslStack = ptr::null_mut();
    if !crl.is_null() {
        crls = OPENSSL_sk_new_reserve(None, 1);
        if crls.is_null() {
            // SAFETY: `itav` is live.
            unsafe { itav_free(itav) };
            return ptr::null_mut();
        }
        // SAFETY: `crl` is live.
        let crl_copy = unsafe { X509_CRL_dup(crl) };
        if crl_copy.is_null() {
            // SAFETY: `crls` was created here.
            unsafe { OPENSSL_sk_free(crls) };
            // SAFETY: `itav` is live.
            unsafe { itav_free(itav) };
            return ptr::null_mut();
        }
        // SAFETY: `crls` is live.
        if unsafe { OPENSSL_sk_push(crls, crl_copy.cast()) } == 0 {
            // SAFETY: `crl_copy` is live.
            unsafe { X509_CRL_free(crl_copy) };
            // SAFETY: `crls` was created here.
            unsafe { OPENSSL_sk_free(crls) };
            // SAFETY: `itav` is live.
            unsafe { itav_free(itav) };
            return ptr::null_mut();
        }
    }
    // SAFETY: `itav` is live.
    unsafe {
        (*itav).info_type = OBJ_nid2obj(NID_id_it_crls);
        (*itav).info_value.crls = crls;
    }
    itav
}

/// `int OSSL_CMP_ITAV_get0_crls(const OSSL_CMP_ITAV *itav, STACK_OF(X509_CRL) **out)` —
/// `cmp_asn.c:813-825`.
///
/// # Safety
/// `itav` is NULL or live; `out` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_get0_crls(
    itav: *const CmpItav,
    out: *mut *mut OpenSslStack,
) -> c_int {
    if itav.is_null() || out.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(816, c"OSSL_CMP_ITAV_get0_crls", ERR_R_PASSED_NULL_PARAMETER) };
        return 0;
    }
    // SAFETY: `itav` is live.
    if unsafe { OBJ_obj2nid((*itav).info_type) } != NID_id_it_crls {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cmp(
                820,
                c"OSSL_CMP_ITAV_get0_crls",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: both pointers are live/writable.
    unsafe { *out = (*itav).info_value.crls };
    1
}

/// `int ossl_cmp_asn1_get_int(const ASN1_INTEGER *a)` — `cmp_asn.c:828-845`. Crate-internal.
///
/// # Safety
/// `a` is NULL or a live `ASN1_INTEGER`.
pub(crate) unsafe fn ossl_cmp_asn1_get_int(a: *const Asn1String) -> c_int {
    let mut res: i64 = 0;
    // SAFETY: `a` is NULL or live per this function's contract, and `res` is writable.
    if a.is_null() || unsafe { crate::asn1::prim::ASN1_INTEGER_get_int64(&mut res, a) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(833, c"ossl_cmp_asn1_get_int", ASN1_R_INVALID_NUMBER) };
        return -2;
    }
    if res < c_int::MIN as i64 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(837, c"ossl_cmp_asn1_get_int", ASN1_R_TOO_SMALL) };
        return -2;
    }
    if res > c_int::MAX as i64 {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cmp(841, c"ossl_cmp_asn1_get_int", ASN1_R_TOO_LARGE) };
        return -2;
    }
    res as c_int
}

// ---------------------------------------------------------------------------------------------
// The generated alloc/encode functions the public header declares
// ---------------------------------------------------------------------------------------------

/// `OSSL_CMP_ATAVS *OSSL_CMP_ATAVS_new(void)` — `IMPLEMENT_ASN1_FUNCTIONS(OSSL_CMP_ATAVS)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_ATAVS_new() -> *mut OpenSslStack {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_atavs_it()) }.cast()
}

/// `void OSSL_CMP_ATAVS_free(OSSL_CMP_ATAVS *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ATAVS_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cmp_atavs_it()) };
}

/// `OSSL_CMP_PKIHEADER *OSSL_CMP_PKIHEADER_new(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_PKIHEADER_new() -> *mut CmpPkiHeader {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_pkiheader_it()) }.cast()
}

/// `void OSSL_CMP_PKIHEADER_free(OSSL_CMP_PKIHEADER *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_PKIHEADER_free(a: *mut CmpPkiHeader) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cmp_pkiheader_it()) };
}

/// `OSSL_CMP_PKISI *OSSL_CMP_PKISI_new(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_PKISI_new() -> *mut CmpPkisi {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cmp_pkisi_it()) }.cast()
}

/// `void OSSL_CMP_PKISI_free(OSSL_CMP_PKISI *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_PKISI_free(a: *mut CmpPkisi) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cmp_pkisi_it()) };
}

/// `OSSL_CMP_PKISI *OSSL_CMP_PKISI_dup(const OSSL_CMP_PKISI *a)`.
///
/// # Safety
/// `a` is NULL or a live `OSSL_CMP_PKISI`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_PKISI_dup(a: *const CmpPkisi) -> *mut CmpPkisi {
    // SAFETY: `a` is NULL or a live value; the item layer duplicates it.
    unsafe { ASN1_item_dup(cmp_pkisi_it(), a.cast()) }.cast()
}

/// `OSSL_CMP_ITAV *OSSL_CMP_ITAV_dup(const OSSL_CMP_ITAV *a)`.
///
/// # Safety
/// `a` is NULL or a live `OSSL_CMP_ITAV`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_dup(a: *const CmpItav) -> *mut CmpItav {
    // SAFETY: `a` is NULL or a live value; the item layer duplicates it.
    unsafe { ASN1_item_dup(cmp_itav_it(), a.cast()) }.cast()
}

/// `void OSSL_CMP_ITAV_free(OSSL_CMP_ITAV *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_ITAV_free(a: *mut CmpItav) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cmp_itav_it()) };
}

/// `OSSL_CMP_MSG *OSSL_CMP_MSG_dup(const OSSL_CMP_MSG *a)`.
///
/// # Safety
/// `a` is NULL or a live `OSSL_CMP_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CMP_MSG_dup(a: *const CmpMsg) -> *mut CmpMsg {
    // SAFETY: `a` is NULL or a live value; the item layer duplicates it.
    unsafe { ASN1_item_dup(cmp_msg_it(), a.cast()) }.cast()
}

/// `const ASN1_ITEM *OSSL_CMP_MSG_it(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_MSG_it() -> *const Asn1Item {
    &CMP_MSG_ITEM
}

/// `const ASN1_ITEM *OSSL_CMP_PKIHEADER_it(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_PKIHEADER_it() -> *const Asn1Item {
    &CMP_PKIHEADER_ITEM
}

/// `const ASN1_ITEM *OSSL_CMP_PKISI_it(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_PKISI_it() -> *const Asn1Item {
    &CMP_PKISI_ITEM
}

/// `const ASN1_ITEM *OSSL_CMP_ATAVS_it(void)`.
#[no_mangle]
pub extern "C" fn OSSL_CMP_ATAVS_it() -> *const Asn1Item {
    &CMP_ATA_VS_ITEM
}

/// `OSSL_CMP_ATAVS *d2i_OSSL_CMP_ATAVS(OSSL_CMP_ATAVS **a, const unsigned char **in, long len)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_CMP_ATAVS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, cmp_atavs_it()) }.cast()
}

/// `int i2d_OSSL_CMP_ATAVS(const OSSL_CMP_ATAVS *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_CMP_ATAVS(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, cmp_atavs_it()) }
}

/// `OSSL_CMP_PKIHEADER *d2i_OSSL_CMP_PKIHEADER(OSSL_CMP_PKIHEADER **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_CMP_PKIHEADER(
    a: *mut *mut CmpPkiHeader,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut CmpPkiHeader {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, cmp_pkiheader_it()) }.cast()
}

/// `int i2d_OSSL_CMP_PKIHEADER(const OSSL_CMP_PKIHEADER *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_CMP_PKIHEADER(
    a: *const CmpPkiHeader,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, cmp_pkiheader_it()) }
}

/// `OSSL_CMP_PKISI *d2i_OSSL_CMP_PKISI(OSSL_CMP_PKISI **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_CMP_PKISI(
    a: *mut *mut CmpPkisi,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut CmpPkisi {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, cmp_pkisi_it()) }.cast()
}

/// `int i2d_OSSL_CMP_PKISI(const OSSL_CMP_PKISI *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_CMP_PKISI(a: *const CmpPkisi, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, cmp_pkisi_it()) }
}
