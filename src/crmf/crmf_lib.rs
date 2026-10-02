//! `crypto/crmf/crmf_lib.c` — the CRMF object-graph library. Phase 12.7.
//!
//! This unit transcribes `crmf_lib.c`'s exported surface: the `CertTemplate`/`CertRequest` field
//! accessors, the sixteen `regCtrl`/`regInfo` attribute getters and setters the
//! `IMPLEMENT_CRMF_CTRL_FUNC` macro generates, the `OSSL_CRMF_CERTID_gen`/`CERTTEMPLATE_fill`
//! builders, the `ProofOfPossession` create/verify pair, and the `ENCRYPTEDVALUE`/`ENCRYPTEDKEY`
//! decryption helpers.
//!
//! The struct fields it reaches are `crmf_local.h`'s and live in [`super::crmf_asn`], which 12.4
//! laid out and 12.7 published.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(private_interfaces)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;

use crate::asn1::a_sign::ASN1_item_sign_ex;
use crate::asn1::a_verify::ASN1_item_verify_ex;
use crate::asn1::layout::V_ASN1_UNDEF;
use crate::asn1::prim::{ASN1_INTEGER_dup, ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_STRING_dup};
use crate::asn1::typ::ASN1_NULL_new;
use crate::cms::cms_asn1::{
    cms_signeddata_it, CMS_SignedData_free, CmsEnvelopedData, CmsSignedData,
};
use crate::cms::cms_env::CMS_EnvelopedData_decrypt;
use crate::cms::cms_sd::CMS_SignedData_verify;
use crate::crmf::crmf_asn::{
    atav_free, atav_new, certrequest_dup, optionalvalidity_new, popo_free, popo_new,
    popoprivkey_new, poposigningkey_free, poposigningkey_new, CrmfAttributeTypeAndValue,
    CrmfCertId, CrmfCertRequest, CrmfCertTemplate, CrmfEncryptedKey, CrmfEncryptedValue, CrmfMsg,
    CrmfPkiPublicationInfo, OSSL_CRMF_CERTID_dup, OSSL_CRMF_CERTID_free, OSSL_CRMF_CERTID_new,
};
use crate::evp::cipher::EVP_CIPHER_free;
use crate::evp::legacy_evp::EVP_get_cipherbyname;
use crate::evp::pkey::{EVP_PKEY_get_default_digest_name, EvpPkey};
use crate::runtime::constant_time::{
    constant_time_eq_s, constant_time_is_zero_s, constant_time_is_zero_u32, constant_time_msb_u32,
};
use crate::runtime::err::err_reasons::*;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::{raise_site, ERR_clear_error, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{Asn1Object, OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt};
use crate::runtime::obj::{NID_cmKGA, NID_ext_key_usage};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_genn::{GENERAL_NAME_free, GeneralName, GEN_DIRNAME};
use crate::x509::v3_purp::{
    X509Purpose, X509_PURPOSE_add, X509_PURPOSE_get_by_sname, X509_PURPOSE_get_unused_id,
};
use crate::x509::x509_cmp::ossl_x509_check_private_key;
use crate::x509::x509_lu::{X509Store, X509_STORE_get0_param, X509_STORE_set_purpose};
use crate::x509::x509_vpm::X509_VERIFY_PARAM_get_purpose;
use crate::x509::x_exten::X509_EXTENSION_free;
use crate::x509::x_name::{X509Name, X509_NAME_set};
use crate::x509::x_pubkey::{
    X509Pubkey, X509_PUBKEY_dup, X509_PUBKEY_get0, X509_PUBKEY_get0_param,
};
use crate::x509::x_x509::{d2i_X509, X509_free, X509_new_ex, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/crmf/crmf_lib.c";

/// `ERR_LIB_CRMF` — `include/openssl/err.h.in:121`.
const ERR_LIB_CRMF: c_int = 56;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h.in:360`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;
/// `X509_TRUST_COMPAT` — `include/openssl/x509_vfy.h.in:99`.
const X509_TRUST_COMPAT: c_int = 1;
/// `V_ASN1_UNDEF` is imported above; the alias keeps the `X509_ALGOR_set0` call readable.
const _V_ASN1_UNDEF: c_int = V_ASN1_UNDEF;

/// `SN_cmKGA` — `include/openssl/obj_mac.h:1798`.
const SN_cmKGA: &core::ffi::CStr = c"cmKGA";
/// `LN_cmKGA` — `include/openssl/obj_mac.h:1799`.
const LN_cmKGA: &core::ffi::CStr = c"Certificate Management Key Generation Authority";

/// `crypto/crmf/crmf_local.h`'s `OSSL_CRMF_PUB_METHOD_*` bounds and `OSSL_CRMF_PUB_ACTION_*`.
const OSSL_CRMF_PUB_METHOD_DONTCARE: c_int = 0;
const OSSL_CRMF_PUB_METHOD_LDAP: c_int = 3;
const OSSL_CRMF_PUB_ACTION_DONTPUBLISH: c_int = 0;
const OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH: c_int = 1;

/// `OSSL_CRMF_POPO_*` — `include/openssl/crmf.h.in:178-182`.
const OSSL_CRMF_POPO_NONE: c_int = -1;
const OSSL_CRMF_POPO_RAVERIFIED: c_int = 0;
const OSSL_CRMF_POPO_SIGNATURE: c_int = 1;
const OSSL_CRMF_POPO_KEYENC: c_int = 2;
const OSSL_CRMF_POPO_KEYAGREE: c_int = 3;
/// `OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE` — `include/openssl/crmf.h.in:37`.
const OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE: c_int = 1;
/// `OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT` — `include/openssl/crmf.h.in:42`.
const OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT: c_long = 0;

/// `ossl_unused` is a no-op here: the parameter is genuinely used by the tail.
const _: () = ();

/// `ERR_raise(ERR_LIB_CRMF, reason)` at an authority coordinate of this unit.
///
/// # Safety
/// The site is a compile-time constant.
unsafe fn raise_crmf(line: c_int, func: &'static core::ffi::CStr, reason: c_int) {
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_site(&ErrSite {
            file: FILE,
            line,
            func,
            lib: ERR_LIB_CRMF,
            reason,
            dynamic_reason: false,
        })
    };
}

/// `static int crmf_asn1_get_int(const ASN1_INTEGER *a)` — `crmf_lib.c:279-296`.
///
/// # Safety
/// `a` is NULL or a live `ASN1_INTEGER`.
unsafe fn crmf_asn1_get_int(a: *const crate::asn1::layout::Asn1String) -> c_int {
    let mut res: i64 = 0;
    // SAFETY: `a` is NULL or live per the contract; `res` is a live local.
    if unsafe { ASN1_INTEGER_get_int64(&mut res, a) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(284, c"crmf_asn1_get_int", ASN1_R_INVALID_NUMBER) };
        return -1;
    }
    if res < c_int::MIN as i64 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(288, c"crmf_asn1_get_int", ASN1_R_TOO_SMALL) };
        return -1;
    }
    if res > c_int::MAX as i64 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(292, c"crmf_asn1_get_int", ASN1_R_TOO_LARGE) };
        return -1;
    }
    res as c_int
}

/// `static int OSSL_CRMF_MSG_push0_regCtrl(OSSL_CRMF_MSG *crm, OSSL_CRMF_ATTRIBUTETYPEANDVALUE`
/// `*ctrl)` — `crmf_lib.c:83-109`.
///
/// # Safety
/// `crm` is NULL or a live `OSSL_CRMF_MSG`; `ctrl` is NULL or a value the item layer built.
unsafe fn push0_regCtrl(crm: *mut CrmfMsg, ctrl: *mut CrmfAttributeTypeAndValue) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    if crm.is_null() || unsafe { (*crm).cert_req }.is_null() || ctrl.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(89, c"OSSL_CRMF_MSG_push0_regCtrl", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut new = 0;
    // SAFETY: `crm` and its `cert_req` are live per the check above.
    unsafe {
        if (*(*crm).cert_req).controls.is_null() {
            (*(*crm).cert_req).controls = OPENSSL_sk_new_null();
            if (*(*crm).cert_req).controls.is_null() {
                return 0;
            }
            new = 1;
        }
        if OPENSSL_sk_push((*(*crm).cert_req).controls, ctrl.cast()) == 0 {
            if new != 0 {
                OPENSSL_sk_free((*(*crm).cert_req).controls);
                (*(*crm).cert_req).controls = ptr::null_mut();
            }
            return 0;
        }
    }
    1
}

/// `static int OSSL_CRMF_MSG_push0_regInfo(OSSL_CRMF_MSG *crm, OSSL_CRMF_ATTRIBUTETYPEANDVALUE`
/// `*ri)` — `crmf_lib.c:208-231`.
///
/// # Safety
/// `crm` is NULL or a live `OSSL_CRMF_MSG`; `ri` is NULL or a value the item layer built.
unsafe fn push0_regInfo(crm: *mut CrmfMsg, ri: *mut CrmfAttributeTypeAndValue) -> c_int {
    if crm.is_null() || ri.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(214, c"OSSL_CRMF_MSG_push0_regInfo", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut info: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `crm` is live per the check above.
    unsafe {
        if (*crm).reg_info.is_null() {
            info = OPENSSL_sk_new_null();
            (*crm).reg_info = info;
        }
        if (*crm).reg_info.is_null() {
            return 0;
        }
        if OPENSSL_sk_push((*crm).reg_info, ri.cast()) == 0 {
            if !info.is_null() {
                (*crm).reg_info = ptr::null_mut();
            }
            OPENSSL_sk_free(info);
            return 0;
        }
    }
    1
}

/// `IMPLEMENT_CRMF_CTRL_FUNC`'s shared `get0` scanner — `crmf_lib.c:41-56`. It walks the
/// `controls`/`regInfo` stack for the `ATTRIBUTETYPEANDVALUE` whose `type` NID is `nid`, and
/// answers it, or NULL. Each exported getter below is the macro's one-liner over this helper.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
unsafe fn get0_ctrl_atav(msg: *const CrmfMsg, nid: c_int) -> *mut CrmfAttributeTypeAndValue {
    // SAFETY: `msg` is NULL or live per the contract; the read is guarded by the null check.
    if msg.is_null() || unsafe { (*msg).cert_req }.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `msg` and its `cert_req` are live per the check above.
    let controls = unsafe { (*(*msg).cert_req).controls };
    // SAFETY: `controls` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(controls) };
    for i in 0..n {
        // SAFETY: `i` is a valid index per the count.
        let atav =
            // SAFETY: `controls` is the live stack from above and `i` is in range.
            unsafe { OPENSSL_sk_value(controls, i) }.cast::<CrmfAttributeTypeAndValue>();
        // SAFETY: `atav` is a live stack element; `atav.type_` is live.
        if unsafe { OBJ_obj2nid((*atav).type_) } == nid {
            return atav;
        }
    }
    ptr::null_mut()
}

/// `IMPLEMENT_CRMF_CTRL_FUNC`'s shared `set1` prologue — `crmf_lib.c:58-67`: a fresh
/// `ATTRIBUTETYPEANDVALUE` whose `type` is the attribute's NID, or NULL with the value freed.
///
/// # Safety
/// The returned value is freshly built; release it with [`atav_free`].
unsafe fn new_ctrl(nid: c_int) -> *mut CrmfAttributeTypeAndValue {
    // SAFETY: the accessor answers a fresh item value.
    let atav = unsafe { atav_new() };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `atav` is live; the OID is a borrowed static.
    unsafe {
        (*atav).type_ = OBJ_nid2obj(nid);
        if (*atav).type_.is_null() {
            atav_free(atav);
            return ptr::null_mut();
        }
    }
    atav
}

/// `ASN1_UTF8STRING *OSSL_CRMF_MSG_get0_regCtrl_regToken(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:112`, the macro's `get0` half for `regToken`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_regToken(
    msg: *const CrmfMsg,
) -> *mut crate::asn1::layout::Asn1String {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regCtrl_regToken) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.reg_token }
}

/// `int OSSL_CRMF_MSG_set1_regCtrl_regToken(OSSL_CRMF_MSG *msg, const ASN1_UTF8STRING *tok)` —
/// `crmf_lib.c:112`, the macro's `set1` half.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_regToken(
    msg: *mut CrmfMsg,
    in_: *const crate::asn1::layout::Asn1String,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regCtrl_regToken) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { ASN1_STRING_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.reg_token = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regCtrl(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `ASN1_UTF8STRING *OSSL_CRMF_MSG_get0_regCtrl_authenticator(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:116`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_authenticator(
    msg: *const CrmfMsg,
) -> *mut crate::asn1::layout::Asn1String {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regCtrl_authenticator) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.authenticator }
}

/// `int OSSL_CRMF_MSG_set1_regCtrl_authenticator(OSSL_CRMF_MSG *msg, const ASN1_UTF8STRING
/// *auth)` — `crmf_lib.c:116`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_authenticator(
    msg: *mut CrmfMsg,
    in_: *const crate::asn1::layout::Asn1String,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regCtrl_authenticator) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { ASN1_STRING_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.authenticator = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regCtrl(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `OSSL_CRMF_PKIPUBLICATIONINFO *OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(const
/// OSSL_CRMF_MSG *msg)` — `crmf_lib.c:164`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(
    msg: *const CrmfMsg,
) -> *mut CrmfPkiPublicationInfo {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav =
        unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regCtrl_pkiPublicationInfo) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.pki_publication_info }
}

/// `int OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(OSSL_CRMF_MSG *msg, const
/// OSSL_CRMF_PKIPUBLICATIONINFO *pi)` — `crmf_lib.c:164`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_pkiPublicationInfo(
    msg: *mut CrmfMsg,
    in_: *const CrmfPkiPublicationInfo,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regCtrl_pkiPublicationInfo) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { crate::crmf::crmf_asn::pkipublicationinfo_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.pki_publication_info = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regCtrl(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `OSSL_CRMF_CERTID *OSSL_CRMF_MSG_get0_regCtrl_oldCertID(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:168`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_oldCertID(
    msg: *const CrmfMsg,
) -> *mut CrmfCertId {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regCtrl_oldCertID) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.old_cert_id }
}

/// `int OSSL_CRMF_MSG_set1_regCtrl_oldCertID(OSSL_CRMF_MSG *msg, const OSSL_CRMF_CERTID *cid)` —
/// `crmf_lib.c:168`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_oldCertID(
    msg: *mut CrmfMsg,
    in_: *const CrmfCertId,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regCtrl_oldCertID) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { OSSL_CRMF_CERTID_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.old_cert_id = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regCtrl(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `X509_PUBKEY *OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:201`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regCtrl_protocolEncrKey(
    msg: *const CrmfMsg,
) -> *mut X509Pubkey {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regCtrl_protocolEncrKey) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.protocol_encr_key }.cast::<X509Pubkey>()
}

/// `int OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(OSSL_CRMF_MSG *msg, const X509_PUBKEY
/// *pubkey)` — `crmf_lib.c:201`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regCtrl_protocolEncrKey(
    msg: *mut CrmfMsg,
    in_: *const X509Pubkey,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regCtrl_protocolEncrKey) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { X509_PUBKEY_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.protocol_encr_key = dup.cast() };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regCtrl(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `ASN1_UTF8STRING *OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:234`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regInfo_utf8Pairs(
    msg: *const CrmfMsg,
) -> *mut crate::asn1::layout::Asn1String {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regInfo_utf8Pairs) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.utf8_pairs }
}

/// `int OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(OSSL_CRMF_MSG *msg, const ASN1_UTF8STRING
/// *utf8pairs)` — `crmf_lib.c:234`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regInfo_utf8Pairs(
    msg: *mut CrmfMsg,
    in_: *const crate::asn1::layout::Asn1String,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regInfo_utf8Pairs) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { ASN1_STRING_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.utf8_pairs = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regInfo(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `OSSL_CRMF_CERTREQUEST *OSSL_CRMF_MSG_get0_regInfo_certReq(const OSSL_CRMF_MSG *msg)` —
/// `crmf_lib.c:237`.
///
/// # Safety
/// `msg` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_regInfo_certReq(
    msg: *const CrmfMsg,
) -> *mut CrmfCertRequest {
    // SAFETY: `msg` is NULL or live per the contract.
    let atav = unsafe { get0_ctrl_atav(msg, crate::runtime::obj::NID_id_regInfo_certReq) };
    if atav.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the one the NID selects, per the ADB table.
    unsafe { (*atav).value.cert_req }
}

/// `int OSSL_CRMF_MSG_set1_regInfo_certReq(OSSL_CRMF_MSG *msg, const OSSL_CRMF_CERTREQUEST *cr)`
/// — `crmf_lib.c:237`.
///
/// # Safety
/// `msg` is NULL or live; `in_` NULL or a live value whose duplicate is taken.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set1_regInfo_certReq(
    msg: *mut CrmfMsg,
    in_: *const CrmfCertRequest,
) -> c_int {
    if msg.is_null() || in_.is_null() {
        return 0;
    }
    // SAFETY: the accessor answers a fresh value with its `type` set.
    let atav = unsafe { new_ctrl(crate::runtime::obj::NID_id_regInfo_certReq) };
    if atav.is_null() {
        return 0;
    }
    // SAFETY: `in_` is live per the check above.
    let dup = unsafe { certrequest_dup(in_) };
    if dup.is_null() {
        // SAFETY: `atav` is live.
        unsafe { atav_free(atav) };
        return 0;
    }
    // SAFETY: `atav` is live and the union arm is the one its NID selects.
    unsafe { (*atav).value.cert_req = dup };
    // SAFETY: `msg` and `atav` are live.
    if unsafe { push0_regInfo(msg, atav) } == 0 {
        // SAFETY: `atav` is live and still owned here.
        unsafe { atav_free(atav) };
        return 0;
    }
    1
}

/// `int OSSL_CRMF_MSG_set0_SinglePubInfo(OSSL_CRMF_SINGLEPUBINFO *spi, int method, GENERAL_NAME`
/// `*nm)` — `crmf_lib.c:118-133`.
///
/// # Safety
/// `spi` is NULL or a live `OSSL_CRMF_SINGLEPUBINFO`; `nm` is NULL or a live `GENERAL_NAME` whose
/// ownership passes to `spi`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_SinglePubInfo(
    spi: *mut crate::crmf::crmf_asn::CrmfSinglePubInfo,
    method: c_int,
    nm: *mut GeneralName,
) -> c_int {
    if spi.is_null()
        || !(OSSL_CRMF_PUB_METHOD_DONTCARE..=OSSL_CRMF_PUB_METHOD_LDAP).contains(&method)
    {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                124,
                c"OSSL_CRMF_MSG_set0_SinglePubInfo",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `spi` is live per the check above.
    unsafe {
        if ASN1_INTEGER_set((*spi).pub_method, method as c_long) == 0 {
            return 0;
        }
        GENERAL_NAME_free((*spi).pub_location.cast::<GeneralName>());
        (*spi).pub_location = nm.cast();
    }
    1
}

/// `int OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(OSSL_CRMF_PKIPUBLICATIONINFO *pi,`
/// `OSSL_CRMF_SINGLEPUBINFO *spi)` — `crmf_lib.c:135-148`.
///
/// # Safety
/// `pi` is NULL or a live `OSSL_CRMF_PKIPUBLICATIONINFO`; `spi` NULL or a value whose ownership
/// passes to `pi`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo(
    pi: *mut CrmfPkiPublicationInfo,
    spi: *mut crate::crmf::crmf_asn::CrmfSinglePubInfo,
) -> c_int {
    if pi.is_null() || spi.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                139,
                c"OSSL_CRMF_MSG_PKIPublicationInfo_push0_SinglePubInfo",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `pi` is live per the check above.
    unsafe {
        if (*pi).pub_infos.is_null() {
            (*pi).pub_infos = OPENSSL_sk_new_null();
        }
        if (*pi).pub_infos.is_null() {
            return 0;
        }
        c_int::from(OPENSSL_sk_push((*pi).pub_infos, spi.cast()) != 0)
    }
}

/// `int OSSL_CRMF_MSG_set_PKIPublicationInfo_action(OSSL_CRMF_PKIPUBLICATIONINFO *pi, int action)`
/// — `crmf_lib.c:150-161`.
///
/// # Safety
/// `pi` is NULL or a live `OSSL_CRMF_PKIPUBLICATIONINFO`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set_PKIPublicationInfo_action(
    pi: *mut CrmfPkiPublicationInfo,
    action: c_int,
) -> c_int {
    if pi.is_null()
        || !(OSSL_CRMF_PUB_ACTION_DONTPUBLISH..=OSSL_CRMF_PUB_ACTION_PLEASEPUBLISH)
            .contains(&action)
    {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                156,
                c"OSSL_CRMF_MSG_set_PKIPublicationInfo_action",
                ERR_R_PASSED_INVALID_ARGUMENT,
            )
        };
        return 0;
    }
    // SAFETY: `pi` and its `action` are live per the check above.
    unsafe { ASN1_INTEGER_set((*pi).action, action as c_long) }
}

/// `OSSL_CRMF_CERTID *OSSL_CRMF_CERTID_gen(const X509_NAME *issuer, const ASN1_INTEGER *serial)` —
/// `crmf_lib.c:170-196`.
///
/// # Safety
/// `issuer` and `serial` are NULL or live objects; the returned value is freshly built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTID_gen(
    issuer: *const X509Name,
    serial: *const crate::asn1::layout::Asn1String,
) -> *mut CrmfCertId {
    if issuer.is_null() || serial.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(176, c"OSSL_CRMF_CERTID_gen", CRMF_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: the accessor answers a static item.
    let cid = OSSL_CRMF_CERTID_new();
    if cid.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cid` is live and its `issuer` is a fresh `GENERAL_NAME` from the item layer.
    unsafe {
        let gn = (*cid).issuer.cast::<GeneralName>();
        if X509_NAME_set(&mut (*gn).d.directoryName, issuer) == 0 {
            OSSL_CRMF_CERTID_free(cid);
            return ptr::null_mut();
        }
        (*gn).type_ = GEN_DIRNAME;
        ASN1_INTEGER_free((*cid).serial_number);
        (*cid).serial_number = ASN1_INTEGER_dup(serial);
        if (*cid).serial_number.is_null() {
            OSSL_CRMF_CERTID_free(cid);
            return ptr::null_mut();
        }
    }
    cid
}

/// `OSSL_CRMF_CERTTEMPLATE *OSSL_CRMF_MSG_get0_tmpl(const OSSL_CRMF_MSG *crm)` — `crmf_lib.c:240`.
///
/// # Safety
/// `crm` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get0_tmpl(crm: *const CrmfMsg) -> *mut CrmfCertTemplate {
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    if crm.is_null() || unsafe { (*crm).cert_req }.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(243, c"OSSL_CRMF_MSG_get0_tmpl", CRMF_R_NULL_ARGUMENT) };
        return ptr::null_mut();
    }
    // SAFETY: `crm` and its `cert_req` are live per the check above.
    unsafe { (*(*crm).cert_req).cert_template }
}

/// `int OSSL_CRMF_MSG_set0_validity(OSSL_CRMF_MSG *crm, ASN1_TIME *notBefore, ASN1_TIME` `*notAfter)`
/// — `crmf_lib.c:249-266`.
///
/// # Safety
/// `crm` is NULL or live; `notBefore`/`notAfter` are NULL or live times whose ownership passes in.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_validity(
    crm: *mut CrmfMsg,
    not_before: *mut crate::asn1::layout::Asn1String,
    not_after: *mut crate::asn1::layout::Asn1String,
) -> c_int {
    // SAFETY: `crm` is NULL or live per the contract.
    let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
    if tmpl.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(256, c"OSSL_CRMF_MSG_set0_validity", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: the accessor answers a static item.
    let vld = unsafe { optionalvalidity_new() };
    if vld.is_null() {
        return 0;
    }
    // SAFETY: `vld` is fresh and `tmpl` is live per the check above.
    unsafe {
        (*vld).not_before = not_before;
        (*vld).not_after = not_after;
        (*tmpl).validity = vld;
    }
    1
}

/// `int OSSL_CRMF_MSG_set_certReqId(OSSL_CRMF_MSG *crm, int rid)` — `crmf_lib.c:268-276`.
///
/// # Safety
/// `crm` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set_certReqId(crm: *mut CrmfMsg, rid: c_int) -> c_int {
    // SAFETY: `crm` is NULL or live per the contract.
    let ok = unsafe {
        !crm.is_null() && !(*crm).cert_req.is_null() && !(*(*crm).cert_req).cert_req_id.is_null()
    };
    if !ok {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(271, c"OSSL_CRMF_MSG_set_certReqId", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `crm` and its `cert_req_id` are live per the check above.
    unsafe { ASN1_INTEGER_set((*(*crm).cert_req).cert_req_id, rid as c_long) }
}

/// `int OSSL_CRMF_MSG_get_certReqId(const OSSL_CRMF_MSG *crm)` — `crmf_lib.c:298-305`.
///
/// # Safety
/// `crm` is NULL or a live `OSSL_CRMF_MSG`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_get_certReqId(crm: *const CrmfMsg) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    if crm.is_null() || unsafe { (*crm).cert_req }.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(301, c"OSSL_CRMF_MSG_get_certReqId", CRMF_R_NULL_ARGUMENT) };
        return -1;
    }
    // SAFETY: `crm` and its `cert_req_id` are live per the check above.
    unsafe { crmf_asn1_get_int((*(*crm).cert_req).cert_req_id) }
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for [`X509_EXTENSION_free`].
///
/// # Safety
/// `p` is NULL or a live `X509_EXTENSION`.
unsafe extern "C" fn x509_extension_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or a live extension per the contract.
    unsafe { X509_EXTENSION_free(p.cast()) };
}

/// `int OSSL_CRMF_MSG_set0_extensions(OSSL_CRMF_MSG *crm, X509_EXTENSIONS *exts)` —
/// `crmf_lib.c:307-325`.
///
/// # Safety
/// `crm` is NULL or live; `exts` NULL or a stack whose ownership passes in.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_set0_extensions(
    crm: *mut CrmfMsg,
    exts: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `crm` is NULL or live per the contract.
    let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
    if tmpl.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(313, c"OSSL_CRMF_MSG_set0_extensions", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut exts = exts;
    // SAFETY: `exts` is NULL or a live stack per the contract.
    unsafe {
        if OPENSSL_sk_num(exts) == 0 {
            OPENSSL_sk_free(exts);
            exts = ptr::null_mut();
        }
        OPENSSL_sk_pop_free((*tmpl).extensions, Some(x509_extension_free_void));
        (*tmpl).extensions = exts;
    }
    1
}

/// `int OSSL_CRMF_MSG_push0_extension(OSSL_CRMF_MSG *crm, X509_EXTENSION *ext)` —
/// `crmf_lib.c:327-353`.
///
/// # Safety
/// `crm` is NULL or live; `ext` NULL or a value whose ownership passes in.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_push0_extension(
    crm: *mut CrmfMsg,
    ext: *mut crate::x509::x_exten::X509Extension,
) -> c_int {
    // SAFETY: `crm` is NULL or live per the contract.
    let tmpl = unsafe { OSSL_CRMF_MSG_get0_tmpl(crm) };
    if tmpl.is_null() || ext.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(333, c"OSSL_CRMF_MSG_push0_extension", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    let mut new = 0;
    // SAFETY: `tmpl` is live per the check above.
    unsafe {
        if (*tmpl).extensions.is_null() {
            (*tmpl).extensions = OPENSSL_sk_new_null();
            if (*tmpl).extensions.is_null() {
                return 0;
            }
            new = 1;
        }
        if OPENSSL_sk_push((*tmpl).extensions, ext.cast()) == 0 {
            if new != 0 {
                OPENSSL_sk_free((*tmpl).extensions);
                (*tmpl).extensions = ptr::null_mut();
            }
            return 0;
        }
    }
    1
}

/// `static int create_popo_signature(OSSL_CRMF_POPOSIGNINGKEY *ps, const OSSL_CRMF_CERTREQUEST`
/// `*cr, EVP_PKEY *pkey, const EVP_MD *digest, OSSL_LIB_CTX *libctx, const char *propq)` —
/// `crmf_lib.c:355-385`.
///
/// # Safety
/// Every pointer is NULL or live per the caller's contract; `pkey` is live.
unsafe fn create_popo_signature(
    ps: *mut crate::crmf::crmf_asn::CrmfPopoSigningKey,
    cr: *const CrmfCertRequest,
    pkey: *mut EvpPkey,
    mut digest: *const crate::evp::digest::EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if ps.is_null() || cr.is_null() || pkey.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(364, c"create_popo_signature", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `cr` and its template are live per the contract.
    let pubkey =
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { X509_PUBKEY_get0((*(*cr).cert_template).public_key.cast::<X509Pubkey>()) };
    // SAFETY: `pubkey`/`pkey` are the caller's.
    if unsafe { ossl_x509_check_private_key(pubkey, pkey) } == 0 {
        return 0;
    }
    // SAFETY: `ps` is live per the contract.
    if unsafe { (*ps).poposk_input }.is_null() {
        // fall through: the supported case
    } else {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                373,
                c"create_popo_signature",
                CRMF_R_POPOSKINPUT_NOT_SUPPORTED,
            )
        };
        return 0;
    }
    let mut name = [0i8; 80];
    // SAFETY: `pkey` is live and `name` is writable for 80 bytes.
    if unsafe { EVP_PKEY_get_default_digest_name(pkey, name.as_mut_ptr(), name.len()) } > 0 {
        // SAFETY: `name` holds a NUL-terminated name on success.
        if unsafe { c_char_slice_eq(name.as_ptr(), c"UNDEF") } {
            digest = ptr::null();
        }
    }
    // SAFETY: the item is a static the crate owns; the remaining pointers are the caller's.
    unsafe {
        ASN1_item_sign_ex(
            crate::crmf::crmf_asn::crmf_certrequest_it(),
            (*ps).algorithm_identifier,
            ptr::null_mut(),
            (*ps).signature,
            cr.cast(),
            ptr::null(),
            pkey,
            digest,
            libctx,
            propq,
        )
    }
}

/// `strcmp`-equality against a Rust `CStr`, for the Ed25519/Ed448 "UNDEF" test.
///
/// # Safety
/// `p` is NUL-terminated.
unsafe fn c_char_slice_eq(p: *const c_char, s: &core::ffi::CStr) -> bool {
    let bytes = s.to_bytes_with_nul();
    let mut i = 0;
    loop {
        // SAFETY: `p` is NUL-terminated per the contract.
        let c = unsafe { *p.add(i) } as u8;
        if i >= bytes.len() {
            return false;
        }
        if c != bytes[i] {
            return false;
        }
        if c == 0 {
            return true;
        }
        i += 1;
    }
}

/// `int OSSL_CRMF_MSG_create_popo(int meth, OSSL_CRMF_MSG *crm, EVP_PKEY *pkey, const EVP_MD`
/// `*digest, OSSL_LIB_CTX *libctx, const char *propq)` — `crmf_lib.c:387-448`.
///
/// # Safety
/// `crm` is NULL or live; `pkey`/`digest` NULL or live; `libctx`/`propq` NULL or the caller's.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_create_popo(
    meth: c_int,
    crm: *mut CrmfMsg,
    pkey: *mut EvpPkey,
    digest: *const crate::evp::digest::EvpMd,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if crm.is_null() || (meth == OSSL_CRMF_POPO_SIGNATURE && pkey.is_null()) {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(395, c"OSSL_CRMF_MSG_create_popo", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `crm` is live; `popo_free` accepts NULL.
    if meth == OSSL_CRMF_POPO_NONE {
        // SAFETY: `crm` is live; `popo_free` accepts NULL.
        unsafe {
            popo_free((*crm).popo);
            (*crm).popo = ptr::null_mut();
        }
        return 1;
    }
    // SAFETY: the accessor answers a static item.
    let pp = unsafe { popo_new() };
    if pp.is_null() {
        return 0;
    }
    // SAFETY: `pp` is live per the allocation above.
    unsafe { (*pp).type_ = meth };
    match meth {
        OSSL_CRMF_POPO_RAVERIFIED => {
            // SAFETY: the accessor answers a fresh NULL sentinel.
            let null = ASN1_NULL_new();
            if null.is_null() {
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { popo_free(pp) };
                return 0;
            }
            // SAFETY: `pp` is live.
            unsafe { (*pp).value.ra_verified = null.cast() };
        }
        OSSL_CRMF_POPO_SIGNATURE => {
            // SAFETY: the accessor answers a fresh signing key.
            let ps = unsafe { poposigningkey_new() };
            if ps.is_null() {
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { popo_free(pp) };
                return 0;
            }
            // SAFETY: `crm` and its `cert_req` are live per the checks above.
            let cr = unsafe { (*crm).cert_req };
            // SAFETY: the arguments are the caller's; `ps` is live.
            if unsafe { create_popo_signature(ps, cr, pkey, digest, libctx, propq) } == 0 {
                // SAFETY: `ps` is live.
                unsafe { poposigningkey_free(ps) };
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { popo_free(pp) };
                return 0;
            }
            // SAFETY: `pp` is live.
            unsafe { (*pp).value.signature = ps };
        }
        OSSL_CRMF_POPO_KEYENC => {
            // SAFETY: the accessor answers a fresh private key.
            let pk = unsafe { popoprivkey_new() };
            if pk.is_null() {
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { popo_free(pp) };
                return 0;
            }
            // SAFETY: `pp` is live.
            unsafe { (*pp).value.key_encipherment = pk };
            // SAFETY: the accessor answers a fresh integer.
            let tag = ASN1_INTEGER_new();
            // SAFETY: `pk` is live.
            unsafe {
                (*pk).type_ = OSSL_CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
                (*pk).value.subsequent_message = tag;
            }
            if tag.is_null()
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                || unsafe { ASN1_INTEGER_set(tag, OSSL_CRMF_SUBSEQUENTMESSAGE_ENCRCERT) } == 0
            {
                // SAFETY: `pp` owns `pk`.
                unsafe { popo_free(pp) };
                return 0;
            }
        }
        _ => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_crmf(
                    436,
                    c"OSSL_CRMF_MSG_create_popo",
                    CRMF_R_UNSUPPORTED_METHOD_FOR_CREATING_POPO,
                )
            };
            // SAFETY: `pp` is live.
            unsafe { popo_free(pp) };
            return 0;
        }
    }
    // SAFETY: `crm` is live; its old `popo` is released and replaced.
    unsafe {
        popo_free((*crm).popo);
        (*crm).popo = pp;
    }
    1
}

/// `int OSSL_CRMF_MSGS_verify_popo(const OSSL_CRMF_MSGS *reqs, int rid, int acceptRAVerified,`
/// `OSSL_LIB_CTX *libctx, const char *propq)` — `crmf_lib.c:451-534`.
///
/// # Safety
/// `reqs` is NULL or a live stack of `OSSL_CRMF_MSG`; `libctx`/`propq` NULL or the caller's.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSGS_verify_popo(
    reqs: *const OpenSslStack,
    rid: c_int,
    accept_raverified: c_int,
    libctx: *mut c_void,
    propq: *const c_char,
) -> c_int {
    if reqs.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(462, c"OSSL_CRMF_MSGS_verify_popo", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `reqs` is live and `rid` is the caller's index.
    let req = unsafe { OPENSSL_sk_value(reqs, rid) }.cast::<CrmfMsg>();
    if req.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(462, c"OSSL_CRMF_MSGS_verify_popo", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `req` is a live stack element.
    if unsafe { (*req).popo }.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(467, c"OSSL_CRMF_MSGS_verify_popo", CRMF_R_POPO_MISSING) };
        return 0;
    }
    // SAFETY: `req` and its `popo` are live.
    let popo_type = unsafe { (*(*req).popo).type_ };
    match popo_type {
        OSSL_CRMF_POPO_RAVERIFIED => {
            if accept_raverified == 0 {
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe {
                    raise_crmf(
                        474,
                        c"OSSL_CRMF_MSGS_verify_popo",
                        CRMF_R_POPO_RAVERIFIED_NOT_ACCEPTED,
                    )
                };
                return 0;
            }
        }
        OSSL_CRMF_POPO_SIGNATURE => {
            // SAFETY: `req` is live and its template carries the public key.
            let pubkey =
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe { (*(*(*req).cert_req).cert_template).public_key }.cast::<X509Pubkey>();
            if pubkey.is_null() {
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                unsafe {
                    raise_crmf(
                        481,
                        c"OSSL_CRMF_MSGS_verify_popo",
                        CRMF_R_POPO_MISSING_PUBLIC_KEY,
                    )
                };
                return 0;
            }
            // SAFETY: the popo type is SIGNATURE, so the union arm is the signing key.
            let sig = unsafe { (*(*req).popo).value.signature };
            let it: *const crate::asn1::layout::Asn1Item;
            let asn: *const c_void;
            // SAFETY: `sig` is live per the type check.
            if unsafe { (*sig).poposk_input }.is_null() {
                // SAFETY: `req` is live.
                if unsafe { (*(*(*req).cert_req).cert_template).subject }.is_null() {
                    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                    unsafe {
                        raise_crmf(
                            509,
                            c"OSSL_CRMF_MSGS_verify_popo",
                            CRMF_R_POPO_MISSING_SUBJECT,
                        )
                    };
                    return 0;
                }
                it = crate::crmf::crmf_asn::crmf_certrequest_it();
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                asn = unsafe { (*req).cert_req }.cast();
            } else {
                // SAFETY: `sig` and its `poposk_input` are live.
                let pk = unsafe { (*sig).poposk_input };
                // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                if unsafe { (*pk).public_key }.is_null() {
                    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                    unsafe {
                        raise_crmf(
                            492,
                            c"OSSL_CRMF_MSGS_verify_popo",
                            CRMF_R_POPO_MISSING_PUBLIC_KEY,
                        )
                    };
                    return 0;
                }
                // SAFETY: `pk.public_key` is a live `X509_PUBKEY`.
                if unsafe { crate::x509::x_pubkey::X509_PUBKEY_eq(pubkey, (*pk).public_key.cast()) }
                    != 1
                {
                    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
                    unsafe {
                        raise_crmf(
                            496,
                            c"OSSL_CRMF_MSGS_verify_popo",
                            CRMF_R_POPO_INCONSISTENT_PUBLIC_KEY,
                        )
                    };
                    return 0;
                }
                it = crate::crmf::crmf_asn::crmf_poposigningkeyinput_it();
                asn = pk.cast();
            }
            // SAFETY: the remaining pointers are the caller's; `it`/`asn` are consistent.
            if unsafe {
                ASN1_item_verify_ex(
                    it,
                    (*sig).algorithm_identifier,
                    (*sig).signature,
                    asn,
                    ptr::null(),
                    X509_PUBKEY_get0(pubkey),
                    libctx,
                    propq,
                )
            } < 1
            {
                return 0;
            }
        }
        _ => {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_crmf(
                    530,
                    c"OSSL_CRMF_MSGS_verify_popo",
                    CRMF_R_UNSUPPORTED_POPO_METHOD,
                )
            };
            return 0;
        }
    }
    1
}

/// `int OSSL_CRMF_MSG_centralkeygen_requested(const OSSL_CRMF_MSG *crm, const X509_REQ *p10cr)` —
/// `crmf_lib.c:536-566`.
///
/// # Safety
/// `crm` and `p10cr` are NULL or live; at least one is non-NULL.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_MSG_centralkeygen_requested(
    crm: *const CrmfMsg,
    p10cr: *const crate::x509::x509_req::X509Req,
) -> c_int {
    if crm.is_null() && p10cr.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                543,
                c"OSSL_CRMF_MSG_centralkeygen_requested",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return -1;
    }
    // SAFETY: `crm` is live per the check above.
    let pubkey = if !crm.is_null() {
        // SAFETY: `crm` is live per the check above.
        unsafe { OSSL_CRMF_CERTTEMPLATE_get0_publicKey(OSSL_CRMF_MSG_get0_tmpl(crm)) }
    } else {
        // SAFETY: `p10cr` is live per the check above.
        unsafe { (*p10cr).req_info.pubkey }
    };
    let mut pk: *const u8 = ptr::null();
    let mut pklen: c_int = 0;
    let mut ret = 0;
    // SAFETY: `pubkey` is NULL or live; the out-pointers are live locals.
    if pubkey.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || (unsafe {
            X509_PUBKEY_get0_param(
                ptr::null_mut(),
                &mut pk,
                &mut pklen,
                ptr::null_mut(),
                pubkey,
            )
        } != 0
            && pklen == 0)
    {
        ret = 1;
    }
    if !crm.is_null() {
        // SAFETY: `crm` is live.
        let popo_absent = unsafe { (*crm).popo }.is_null();
        if ret != c_int::from(popo_absent) {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                raise_crmf(
                    562,
                    c"OSSL_CRMF_MSG_centralkeygen_requested",
                    CRMF_R_POPO_INCONSISTENT_CENTRAL_KEYGEN,
                )
            };
            return -2;
        }
    }
    ret
}

/// `X509_PUBKEY *OSSL_CRMF_CERTTEMPLATE_get0_publicKey(const OSSL_CRMF_CERTTEMPLATE *tmpl)` —
/// `crmf_lib.c:568-572`.
///
/// # Safety
/// `tmpl` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_publicKey(
    tmpl: *const CrmfCertTemplate,
) -> *mut X509Pubkey {
    if tmpl.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe { (*tmpl).public_key.cast::<X509Pubkey>() }
}

/// `const ASN1_INTEGER *OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(const OSSL_CRMF_CERTTEMPLATE`
/// `*tmpl)` — `crmf_lib.c:574-577`.
///
/// # Safety
/// `tmpl` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(
    tmpl: *const CrmfCertTemplate,
) -> *const crate::asn1::layout::Asn1String {
    if tmpl.is_null() {
        return ptr::null();
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe { (*tmpl).serial_number }
}

/// `const X509_NAME *OSSL_CRMF_CERTTEMPLATE_get0_subject(const OSSL_CRMF_CERTTEMPLATE *tmpl)` —
/// `crmf_lib.c:579-582`.
///
/// # Safety
/// `tmpl` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_subject(
    tmpl: *const CrmfCertTemplate,
) -> *const X509Name {
    if tmpl.is_null() {
        return ptr::null();
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe { (*tmpl).subject }
}

/// `const X509_NAME *OSSL_CRMF_CERTTEMPLATE_get0_issuer(const OSSL_CRMF_CERTTEMPLATE *tmpl)` —
/// `crmf_lib.c:584-587`.
///
/// # Safety
/// `tmpl` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_issuer(
    tmpl: *const CrmfCertTemplate,
) -> *const X509Name {
    if tmpl.is_null() {
        return ptr::null();
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe { (*tmpl).issuer }
}

/// `X509_EXTENSIONS *OSSL_CRMF_CERTTEMPLATE_get0_extensions(const OSSL_CRMF_CERTTEMPLATE *tmpl)` —
/// `crmf_lib.c:589-593`.
///
/// # Safety
/// `tmpl` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_get0_extensions(
    tmpl: *const CrmfCertTemplate,
) -> *mut OpenSslStack {
    if tmpl.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe { (*tmpl).extensions }
}

/// `const X509_NAME *OSSL_CRMF_CERTID_get0_issuer(const OSSL_CRMF_CERTID *cid)` —
/// `crmf_lib.c:595-598`.
///
/// # Safety
/// `cid` is NULL or a live `OSSL_CRMF_CERTID`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTID_get0_issuer(cid: *const CrmfCertId) -> *const X509Name {
    if cid.is_null() {
        return ptr::null();
    }
    // SAFETY: `cid` is live per the check above; its `issuer` is a live `GENERAL_NAME`.
    unsafe {
        let gn = (*cid).issuer.cast::<GeneralName>();
        if (*gn).type_ == GEN_DIRNAME {
            (*gn).d.directoryName
        } else {
            ptr::null()
        }
    }
}

/// `const ASN1_INTEGER *OSSL_CRMF_CERTID_get0_serialNumber(const OSSL_CRMF_CERTID *cid)` —
/// `crmf_lib.c:600-604`.
///
/// # Safety
/// `cid` is NULL or a live `OSSL_CRMF_CERTID`.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTID_get0_serialNumber(
    cid: *const CrmfCertId,
) -> *const crate::asn1::layout::Asn1String {
    if cid.is_null() {
        return ptr::null();
    }
    // SAFETY: `cid` is live per the check above.
    unsafe { (*cid).serial_number }
}

/// `int OSSL_CRMF_CERTTEMPLATE_fill(OSSL_CRMF_CERTTEMPLATE *tmpl, EVP_PKEY *pubkey, const X509_NAME`
/// `*subject, const X509_NAME *issuer, const ASN1_INTEGER *serial)` — `crmf_lib.c:610-632`.
///
/// # Safety
/// `tmpl` is NULL or live; every other argument is NULL or live; the returned value follows the C
/// ownership rules.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_CERTTEMPLATE_fill(
    tmpl: *mut CrmfCertTemplate,
    pubkey: *mut EvpPkey,
    subject: *const X509Name,
    issuer: *const X509Name,
    serial: *const crate::asn1::layout::Asn1String,
) -> c_int {
    if tmpl.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe { raise_crmf(617, c"OSSL_CRMF_CERTTEMPLATE_fill", CRMF_R_NULL_ARGUMENT) };
        return 0;
    }
    // SAFETY: `tmpl` is live per the check above.
    unsafe {
        if !subject.is_null() && X509_NAME_set(&mut (*tmpl).subject, subject) == 0 {
            return 0;
        }
        if !issuer.is_null() && X509_NAME_set(&mut (*tmpl).issuer, issuer) == 0 {
            return 0;
        }
        if !serial.is_null() {
            ASN1_INTEGER_free((*tmpl).serial_number);
            (*tmpl).serial_number = ASN1_INTEGER_dup(serial);
            if (*tmpl).serial_number.is_null() {
                return 0;
            }
        }
        if !pubkey.is_null() {
            let mut slot: *mut X509Pubkey = (*tmpl).public_key.cast();
            // SAFETY: `slot` receives the new key; `pubkey` is the caller's live key.
            let ok = crate::x509::x_pubkey::X509_PUBKEY_set(&mut slot, pubkey);
            (*tmpl).public_key = slot.cast();
            if ok == 0 {
                return 0;
            }
        }
    }
    1
}

/// `static int check_cmKGA(ossl_unused const X509_PURPOSE *purpose, const X509 *x, int ca)` —
/// `crmf_lib.c:638-655`.
///
/// # Safety
/// `x` is a live `X509`.
unsafe extern "C" fn check_cmKGA(_purpose: *const X509Purpose, x: *const X509, ca: c_int) -> c_int {
    if ca != 0 {
        return 1;
    }
    // SAFETY: `x` is live per the contract; the extension lookup answers a stack or NULL.
    let ekus = unsafe {
        crate::x509::x509_ext::X509_get_ext_d2i(
            x,
            NID_ext_key_usage,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    }
    .cast::<OpenSslStack>();
    // SAFETY: `ekus` is NULL or a live stack.
    let n = unsafe { OPENSSL_sk_num(ekus) };
    let mut ret = 0;
    for i in 0..n {
        // SAFETY: `i` is a valid index per the count.
        let obj = unsafe { OPENSSL_sk_value(ekus, i) }.cast::<Asn1Object>();
        // SAFETY: `obj` is a live stack element.
        if unsafe { OBJ_obj2nid(obj) } == NID_cmKGA {
            ret = 1;
            break;
        }
    }
    // SAFETY: `ekus` is NULL or a live stack of `ASN1_OBJECT`; the destructor frees each element.
    unsafe {
        OPENSSL_sk_pop_free(ekus, Some(asn1_object_free_void));
    }
    ret
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for `ASN1_OBJECT_free`.
///
/// # Safety
/// `p` is NULL or a live `ASN1_OBJECT`.
unsafe extern "C" fn asn1_object_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or a live object per the contract; `OBJ_nid2obj` results are static and
    // never freed here because the stack elements are owned copies.
    // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
    unsafe { crate::asn1::prim::ASN1_OBJECT_free(p.cast()) };
}

/// `EVP_PKEY *OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(const OSSL_CRMF_ENCRYPTEDKEY *encryptedKey,`
/// `X509_STORE *ts, STACK_OF(X509) *extra, EVP_PKEY *pkey, X509 *cert, ASN1_OCTET_STRING *secret,`
/// `OSSL_LIB_CTX *libctx, const char *propq)` — `crmf_lib.c:658-749`.
///
/// # Safety
/// Every pointer is NULL or live per the C contract; the returned key is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_get1_pkey(
    encrypted_key: *const CrmfEncryptedKey,
    ts: *mut X509Store,
    extra: *mut OpenSslStack,
    pkey: *mut EvpPkey,
    cert: *mut X509,
    secret: *mut crate::asn1::layout::Asn1String,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut EvpPkey {
    if encrypted_key.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                673,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `encrypted_key` is live per the check above.
    if unsafe { (*encrypted_key).type_ } != OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA {
        let mut len: c_int = 0;
        // SAFETY: the union arm is the deprecated encValue, and the remaining pointers are the
        // caller's.
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        let p = unsafe {
            OSSL_CRMF_ENCRYPTEDVALUE_decrypt(
                (*encrypted_key).value.encrypted_value,
                libctx,
                propq,
                pkey,
                &mut len,
            )
        };
        let mut ret: *mut EvpPkey = ptr::null_mut();
        if !p.is_null() {
            let mut p_copy = p as *const u8;
            // SAFETY: `p`/`p_copy` are a readable buffer of `len` bytes; `d2i` reads it.
            ret = unsafe {
                crate::asn1::d2i_pr::d2i_AutoPrivateKey_ex(
                    ptr::null_mut(),
                    &mut p_copy,
                    len as c_long,
                    libctx,
                    propq,
                )
            };
        }
        // SAFETY: `p` is a heap buffer this function owns or NULL.
        if !p.is_null() {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe { crate::runtime::mem::CRYPTO_free(p.cast(), FILE.as_ptr(), 685) };
        }
        return ret;
    }

    if ts.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                691,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: the union arm is the enveloped data; the pointers are the caller's.
    let bio = unsafe {
        CMS_EnvelopedData_decrypt(
            (*encrypted_key)
                .value
                .enveloped_data
                .cast::<CmsEnvelopedData>(),
            ptr::null_mut(),
            pkey,
            cert,
            secret,
            0,
            libctx,
            propq,
        )
    };
    if bio.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                699,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_ERROR_DECRYPTING_ENCRYPTEDKEY,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `bio` is live; the item is a static the crate owns.
    let sd = unsafe {
        crate::asn1::a_d2i_fp::ASN1_item_d2i_bio(cms_signeddata_it(), bio, ptr::null_mut())
    }
    .cast::<CmsSignedData>();
    if sd.is_null() {
        // SAFETY: `sd` is NULL; `bio` is live.
        unsafe { crate::runtime::bio::BIO_free(bio) };
        return ptr::null_mut();
    }
    // SAFETY: the purpose table is a module-owned static; the name is NUL-terminated.
    let mut purpose_id = unsafe { X509_PURPOSE_get_by_sname(SN_cmKGA.as_ptr()) };
    if purpose_id < 0 {
        // SAFETY: `libctx` is the caller's.
        purpose_id = unsafe { X509_PURPOSE_get_unused_id(libctx) };
        // SAFETY: the callback and the two names are static; `ret` is a live local.
        if unsafe {
            X509_PURPOSE_add(
                purpose_id,
                X509_TRUST_COMPAT,
                0,
                Some(check_cmKGA),
                LN_cmKGA.as_ptr(),
                SN_cmKGA.as_ptr(),
                ptr::null_mut(),
            )
        } == 0
        {
            // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
            unsafe {
                CMS_SignedData_free(sd);
                crate::runtime::bio::BIO_free(bio);
            }
            return ptr::null_mut();
        }
    }
    // SAFETY: `ts` is live per the check above.
    let vpm = unsafe { X509_STORE_get0_param(ts) };
    if vpm.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            CMS_SignedData_free(sd);
            crate::runtime::bio::BIO_free(bio);
        }
        return ptr::null_mut();
    }
    // SAFETY: `vpm` is live.
    let bak_purpose_id = unsafe { X509_VERIFY_PARAM_get_purpose(vpm) };
    // SAFETY: `ts` is live.
    if unsafe { X509_STORE_set_purpose(ts, purpose_id) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                717,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_ERROR_SETTING_PURPOSE,
            );
            CMS_SignedData_free(sd);
            crate::runtime::bio::BIO_free(bio);
        }
        return ptr::null_mut();
    }
    // SAFETY: every pointer is the caller's or live; the arguments mirror the authority's call.
    let pkey_bio = unsafe {
        CMS_SignedData_verify(
            sd,
            ptr::null_mut(),
            ptr::null_mut(),
            ts,
            extra,
            ptr::null_mut(),
            0,
            libctx,
            propq,
        )
    };
    // SAFETY: `ts` is live.
    if unsafe { X509_STORE_set_purpose(ts, bak_purpose_id) } == 0 {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                725,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_ERROR_SETTING_PURPOSE,
            );
            CMS_SignedData_free(sd);
            crate::runtime::bio::BIO_free(pkey_bio);
            crate::runtime::bio::BIO_free(bio);
        }
        return ptr::null_mut();
    }
    if pkey_bio.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                730,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_ERROR_VERIFYING_ENCRYPTEDKEY,
            );
            CMS_SignedData_free(sd);
            crate::runtime::bio::BIO_free(bio);
        }
        return ptr::null_mut();
    }
    // SAFETY: `pkey_bio` is live; the remaining pointers are the caller's.
    let ret = unsafe {
        crate::x509::x_all::d2i_PrivateKey_ex_bio(pkey_bio, ptr::null_mut(), libctx, propq)
    };
    if ret.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                736,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_pkey",
                CRMF_R_ERROR_DECODING_ENCRYPTEDKEY,
            )
        };
    }
    // SAFETY: every pointer is NULL or a value this function owns.
    unsafe {
        CMS_SignedData_free(sd);
        crate::runtime::bio::BIO_free(bio);
        crate::runtime::bio::BIO_free(pkey_bio);
    }
    ret
}

/// `unsigned char *OSSL_CRMF_ENCRYPTEDVALUE_decrypt(const OSSL_CRMF_ENCRYPTEDVALUE *enc,`
/// `OSSL_LIB_CTX *libctx, const char *propq, EVP_PKEY *pkey, int *outlen)` —
/// `crmf_lib.c:751-852`.
///
/// # Safety
/// `enc` and `pkey` are NULL or live; `outlen` is NULL or a writable `int`; the returned buffer is
/// owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_decrypt(
    enc: *const CrmfEncryptedValue,
    libctx: *mut c_void,
    propq: *const c_char,
    pkey: *mut EvpPkey,
    outlen: *mut c_int,
) -> *mut u8 {
    if outlen.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                768,
                c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `outlen` is writable per the check above.
    unsafe { *outlen = 0 };
    // SAFETY: `enc` is NULL or live per the contract.
    let ok = unsafe {
        !enc.is_null()
            && !(*enc).symm_alg.is_null()
            && !(*enc).enc_symm_key.is_null()
            && !(*enc).enc_value.is_null()
            && !pkey.is_null()
    };
    if !ok {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                774,
                c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                CRMF_R_NULL_ARGUMENT,
            )
        };
        return ptr::null_mut();
    }
    // The C's `EVP_CIPHER *cipher`, `EVP_CIPHER_CTX *evp_ctx`, `EVP_PKEY_CTX *pkctx` are owned
    // pointers; the `end:` tail releases each.
    let evp_ctx: *mut crate::evp::cipher_ctx::EvpCipherCtx;
    let mut ek: *mut u8 = ptr::null_mut();
    let mut eksize: usize = 0;
    let mut cipher: *mut crate::evp::cipher::EvpCipher;
    let mut iv: *mut u8 = ptr::null_mut();
    let out: *mut u8;
    let mut ret = 0;
    let mut name = [0i8; OSSL_MAX_NAME_SIZE];

    // SAFETY: `enc` is live per the checks above; `name` is writable.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            name.len() as c_int,
            (*(*enc).symm_alg).algorithm,
            0,
        );
    }
    // SAFETY: no preconditions.
    ERR_set_mark();
    // SAFETY: `name` is NUL-terminated; `libctx`/`propq` are the caller's.
    cipher = unsafe { crate::evp::cipher::EVP_CIPHER_fetch(libctx, name.as_ptr(), propq) };
    if cipher.is_null() {
        // SAFETY: the legacy table lookup; the OID is live.
        cipher = unsafe {
            EVP_get_cipherbyname(crate::runtime::obj::OBJ_nid2sn(OBJ_obj2nid(
                (*(*enc).symm_alg).algorithm,
            )))
        } as *mut crate::evp::cipher::EvpCipher;
    }
    if cipher.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            crate::runtime::err::ERR_clear_last_mark();
            raise_crmf(
                786,
                c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                CRMF_R_UNSUPPORTED_CIPHER,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    ERR_pop_to_mark();

    // SAFETY: `cipher` is live per the checks above.
    let cikeysize = unsafe { crate::evp::cipher::EVP_CIPHER_get_key_length(cipher) };
    // SAFETY: `libctx`/`pkey`/`propq` are the caller's.
    let pkctx = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
    // SAFETY: `pkctx` is NULL or live.
    if !pkctx.is_null() && unsafe { crate::evp::asymcipher::EVP_PKEY_decrypt_init(pkctx) } > 0 {
        // SAFETY: `enc` is live and its `enc_symm_key` is a live BIT STRING.
        unsafe {
            let enc_key = (*enc).enc_symm_key;
            if crate::evp::asymcipher::EVP_PKEY_decrypt(
                pkctx,
                ptr::null_mut(),
                &mut eksize,
                (*enc_key).data,
                (*enc_key).length as usize,
            ) <= 0
            {
                // fall to the exit path
            } else {
                ek = CRYPTO_malloc(eksize, FILE.as_ptr(), 802).cast::<u8>();
                if !ek.is_null() {
                    let retval = crate::evp::asymcipher::EVP_PKEY_decrypt(
                        pkctx,
                        ek,
                        &mut eksize,
                        (*enc_key).data,
                        (*enc_key).length as usize,
                    );
                    let failure = !constant_time_is_zero_s(
                        (constant_time_msb_u32(retval as u32)
                            | constant_time_is_zero_u32(retval as u32))
                            as usize,
                    );
                    let failure = failure | !constant_time_eq_s(eksize, cikeysize as usize);
                    if failure != 0 {
                        ERR_clear_error();
                        raise_crmf(
                            810,
                            c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                            CRMF_R_ERROR_DECRYPTING_SYMMETRIC_KEY,
                        );
                        // SAFETY: `pkctx`/`cipher` are NULL or owned; `ek` is owned.
                        CRYPTO_free(ek.cast(), FILE.as_ptr(), 846);
                        crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pkctx);
                        crate::evp::cipher::EVP_CIPHER_free(cipher);
                        return ptr::null_mut();
                    }
                }
            }
        }
    }
    // SAFETY: `cipher` is live.
    let iv_len = unsafe { crate::evp::cipher::EVP_CIPHER_get_iv_length(cipher) };
    // SAFETY: `iv_len` is the cipher's own length; allocate that many bytes.
    if iv_len > 0 {
        iv = CRYPTO_malloc(iv_len as usize, FILE.as_ptr(), 817).cast::<u8>();
    }
    if iv.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || unsafe { (*enc).symm_alg }.is_null()
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        || unsafe {
            crate::asn1::evp_asn1::ASN1_TYPE_get_octetstring(
                (*(*enc).symm_alg).parameter,
                iv,
                iv_len,
            )
        } != iv_len
    {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                822,
                c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                CRMF_R_MALFORMED_IV,
            );
            crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pkctx);
            EVP_CIPHER_free(cipher);
            if !iv.is_null() {
                CRYPTO_free(iv.cast(), FILE.as_ptr(), 847);
            }
        };
        return ptr::null_mut();
    }
    // SAFETY: `enc` is live; the cipher's block size and the payload length bound the output.
    unsafe {
        let enc_value = (*enc).enc_value;
        let total = (*enc_value).length as usize
            + crate::evp::cipher::EVP_CIPHER_get_block_size(cipher) as usize;
        out = CRYPTO_malloc(total, FILE.as_ptr(), 826).cast::<u8>();
        evp_ctx = crate::evp::cipher_ctx::EVP_CIPHER_CTX_new();
        if out.is_null() || evp_ctx.is_null() {
            // tail
            crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pkctx);
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(evp_ctx);
            EVP_CIPHER_free(cipher);
            CRYPTO_free(ek.cast(), FILE.as_ptr(), 846);
            CRYPTO_free(iv.cast(), FILE.as_ptr(), 847);
            if !out.is_null() {
                CRYPTO_free(out.cast(), FILE.as_ptr(), 850);
            }
            return ptr::null_mut();
        }
        crate::evp::cipher_ctx::EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
        let mut n: c_int = 0;
        if crate::evp::cipher_ctx::EVP_DecryptInit(evp_ctx, cipher, ek, iv) == 0
            || crate::evp::cipher_ctx::EVP_DecryptUpdate(
                evp_ctx,
                out,
                outlen,
                (*enc_value).data,
                (*enc_value).length as c_int,
            ) == 0
            || crate::evp::cipher_ctx::EVP_DecryptFinal(evp_ctx, out.add(*outlen as usize), &mut n)
                == 0
        {
            raise_crmf(
                836,
                c"OSSL_CRMF_ENCRYPTEDVALUE_decrypt",
                CRMF_R_ERROR_DECRYPTING_ENCRYPTEDVALUE,
            );
        } else {
            *outlen += n;
            ret = 1;
        }
        crate::evp::pkey_ctx::EVP_PKEY_CTX_free(pkctx);
        crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(evp_ctx);
        EVP_CIPHER_free(cipher);
        CRMF_free_clear(ek, eksize);
        CRYPTO_free(iv.cast(), FILE.as_ptr(), 847);
        if ret != 0 {
            return out;
        }
        CRYPTO_free(out.cast(), FILE.as_ptr(), 850);
    }
    ptr::null_mut()
}

/// `OSSL_MAX_NAME_SIZE` — `include/internal/sizes.h:18`.
const OSSL_MAX_NAME_SIZE: usize = 50;

/// `OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA` — `crmf_local.h:54`.
const OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA: c_int = 1;

/// Release and zero a heap buffer, the authority's `OPENSSL_clear_free`.
///
/// # Safety
/// `p` is NULL or a buffer of `len` bytes this function owns.
unsafe fn CRMF_free_clear(p: *mut u8, len: usize) {
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is a live buffer of `len` bytes per the contract; zero it, then free.
    unsafe {
        core::ptr::write_bytes(p, 0, len);
        crate::runtime::mem::CRYPTO_free(p.cast(), FILE.as_ptr(), 846);
    }
}

/// `X509 *OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(const OSSL_CRMF_ENCRYPTEDVALUE *ecert,`
/// `OSSL_LIB_CTX *libctx, const char *propq, EVP_PKEY *pkey)` — `crmf_lib.c:861-883`.
///
/// # Safety
/// `ecert` and `pkey` are NULL or live; the returned certificate is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(
    ecert: *const CrmfEncryptedValue,
    libctx: *mut c_void,
    propq: *const c_char,
    pkey: *mut EvpPkey,
) -> *mut X509 {
    let mut len: c_int = 0;
    // SAFETY: the arguments are the caller's.
    let buf = unsafe { OSSL_CRMF_ENCRYPTEDVALUE_decrypt(ecert, libctx, propq, pkey, &mut len) };
    let mut cert: *mut X509;
    if buf.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `libctx`/`propq` are the caller's.
    cert = unsafe { X509_new_ex(libctx, propq) };
    if cert.is_null() {
        // SAFETY: `buf` is a heap buffer this function owns.
        unsafe { crate::runtime::mem::CRYPTO_free(buf.cast(), FILE.as_ptr(), 881) };
        return ptr::null_mut();
    }
    let mut p: *const u8 = buf;
    // SAFETY: `p` is a readable cursor over `len` bytes; `cert` is a live writable slot.
    if unsafe { d2i_X509(&mut cert, &mut p, len as c_long) }.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                875,
                c"OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert",
                CRMF_R_ERROR_DECODING_CERTIFICATE,
            );
            X509_free(cert);
        }
        cert = ptr::null_mut();
    }
    // SAFETY: `buf` is a heap buffer this function owns.
    unsafe { crate::runtime::mem::CRYPTO_free(buf.cast(), FILE.as_ptr(), 881) };
    cert
}

/// `X509 *OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(const OSSL_CRMF_ENCRYPTEDKEY *ecert,`
/// `OSSL_LIB_CTX *libctx, const char *propq, EVP_PKEY *pkey, unsigned int flags)` —
/// `crmf_lib.c:891-919`.
///
/// # Safety
/// `ecert` and `pkey` are NULL or live; the returned certificate is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_get1_encCert(
    ecert: *const CrmfEncryptedKey,
    libctx: *mut c_void,
    propq: *const c_char,
    pkey: *mut EvpPkey,
    flags: c_uint,
) -> *mut X509 {
    // SAFETY: `ecert` is live per the contract.
    if unsafe { (*ecert).type_ } != OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA {
        // SAFETY: the union arm is the deprecated encrypted value.
        return unsafe {
            OSSL_CRMF_ENCRYPTEDVALUE_get1_encCert(
                (*ecert).value.encrypted_value,
                libctx,
                propq,
                pkey,
            )
        };
    }
    // SAFETY: the union arm is the enveloped data; the pointers are the caller's.
    let bio = unsafe {
        CMS_EnvelopedData_decrypt(
            (*ecert).value.enveloped_data.cast::<CmsEnvelopedData>(),
            ptr::null_mut(),
            pkey,
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
            libctx,
            propq,
        )
    };
    if bio.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `bio` is live.
    let cert = unsafe { crate::x509::x_all::d2i_X509_bio(bio, ptr::null_mut()) };
    if cert.is_null() {
        // SAFETY: the enclosing function's `# Safety` section is the contract for the pointers here.
        unsafe {
            raise_crmf(
                911,
                c"OSSL_CRMF_ENCRYPTEDKEY_get1_encCert",
                CRMF_R_ERROR_DECODING_CERTIFICATE,
            )
        };
    }
    // SAFETY: `bio` is live.
    unsafe { crate::runtime::bio::BIO_free(bio) };
    cert
}

/// `OSSL_CRMF_ENCRYPTEDKEY *OSSL_CRMF_ENCRYPTEDKEY_init_envdata(CMS_EnvelopedData *envdata)` —
/// `crmf_lib.c:922-931`.
///
/// # Safety
/// `envdata` is NULL or a live `CMS_EnvelopedData` whose ownership passes to the result.
#[no_mangle]
pub unsafe extern "C" fn OSSL_CRMF_ENCRYPTEDKEY_init_envdata(
    envdata: *mut CmsEnvelopedData,
) -> *mut CrmfEncryptedKey {
    // SAFETY: the accessor answers a fresh item value.
    let ek = crate::crmf::crmf_asn::OSSL_CRMF_ENCRYPTEDKEY_new();
    if ek.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ek` is live per the allocation above.
    unsafe {
        (*ek).type_ = OSSL_CRMF_ENCRYPTEDKEY_ENVELOPEDDATA;
        (*ek).value.enveloped_data = envdata.cast();
    }
    ek
}
