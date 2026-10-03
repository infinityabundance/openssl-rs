//! `crypto/cms/cms_sd.c` — the `SignedData` signer-info engine: `CMS_add1_signer`, the
//! signer-info accessors, the sign/verify cycle and the S/MIME capability surface. Phase 12.3b.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]
// The authority's C initialisers (`si`, `pctx`, `mctx`, `abuf`, `res`) are dead on the paths that
// reach their `err:`/`end:` label; the assignments are kept so the transcription reads as the
// source does.
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::a_sign::ASN1_item_sign_ctx;
use crate::asn1::a_verify::ASN1_item_verify_ex;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::{
    Asn1String, V_ASN1_INTEGER, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_UNDEF,
};
use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_new, ASN1_STRING_set, ASN1_STRING_set0};
use crate::asn1::x_algor::{
    ossl_X509_ALGOR_from_nid, X509Algor, X509_ALGOR_free, X509_ALGOR_get0, X509_ALGOR_new,
    X509_ALGOR_set0, X509_ALGOR_set_md,
};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestSignFinal, EVP_DigestSignInit_ex, EVP_DigestSignUpdate,
    EVP_DigestVerifyFinal, EVP_DigestVerifyInit_ex, EVP_DigestVerifyUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_get0_md, EVP_MD_CTX_new, EVP_MD_CTX_reset, EVP_MD_CTX_set_flags, EVP_MD_fetch,
    EVP_MD_free, EVP_MD_get0_name, EVP_MD_is_a, EvpMd, EvpMdCtx,
};
use crate::evp::legacy_evp::{EVP_get_cipherbyname, EVP_get_digestbyname};
use crate::evp::p_legacy::EVP_SignFinal_ex;
use crate::evp::pkey::{
    EVP_PKEY_free, EVP_PKEY_get0_type_name, EVP_PKEY_get_default_digest_name,
    EVP_PKEY_get_default_digest_nid, EVP_PKEY_get_id, EVP_PKEY_get_size, EVP_PKEY_is_a,
    EVP_PKEY_up_ref, EvpPkey,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_CTX_set_signature_md, EvpPkeyCtx,
};
use crate::evp::signature::{
    EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify, EVP_PKEY_verify_init,
};
use crate::runtime::bio::bss_mem::BIO_s_mem;
use crate::runtime::bio::{BIO_new, BIO_push, Bio};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
use crate::runtime::obj::{
    Asn1Object, NID_SMIMECapabilities, NID_aes_128_cbc, NID_aes_192_cbc, NID_aes_256_cbc,
    NID_des_cbc, NID_des_ede3_cbc, NID_id_Gost28147_89, NID_id_GostR3411_2012_256,
    NID_id_GostR3411_2012_512, NID_id_GostR3411_94, NID_id_smime_aa_signingCertificate,
    NID_id_smime_aa_signingCertificateV2, NID_pkcs9_contentType, NID_pkcs9_messageDigest,
    NID_pkcs9_signingTime, NID_rc2_cbc, NID_undef, OBJ_cmp, OBJ_find_sigid_by_algs, OBJ_nid2obj,
    OBJ_nid2sn, OBJ_obj2nid, OBJ_obj2txt, OBJ_txt2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_purp::X509_check_purpose;
use crate::x509::x509_cmp::{ossl_x509_add_cert_new, X509_check_private_key, X509_get_pubkey};
use crate::x509::x509_lu::X509Store;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x509_vfy::X509_gmtime_adj;
use crate::x509::x_name::X509Name;
use crate::x509::x_x509::{X509_free, X509};

use super::cms_asn1::*;
use super::cms_att::{
    ossl_cms_si_check_attributes, CMS_signed_add1_attr_by_NID, CMS_signed_get0_data_by_OBJ,
    CMS_signed_get_attr_by_NID, CMS_signed_get_attr_count,
};
use super::cms_lib::{
    ossl_cms_DigestAlgorithm_find_ctx, ossl_cms_DigestAlgorithm_init_bio, ossl_cms_ctx_get0_libctx,
    ossl_cms_ctx_get0_propq, ossl_cms_get0_cmsctx, ossl_cms_ias_cert_cmp, ossl_cms_keyid_cert_cmp,
    ossl_cms_set1_ias, ossl_cms_set1_keyid, raise_cms, CMS_ContentInfo_free,
    CMS_ContentInfo_new_ex, CMS_add1_cert, CMS_add1_crl, ERR_R_ASN1_LIB, ERR_R_CMS_LIB,
    ERR_R_CRYPTO_LIB, ERR_R_EVP_LIB, ERR_R_PASSED_NULL_PARAMETER, ERR_R_X509_LIB,
};
use super::cms_rsa::ossl_cms_rsa_sign;

/// `CMS_USE_KEYID` — `cms.h.in:100`.
const CMS_USE_KEYID: c_uint = 0x10000;
/// `CMS_NOCERTS` — `cms.h.in:82`.
const CMS_NOCERTS: c_uint = 0x2;
/// `CMS_NOATTR` — `cms.h.in:92`.
const CMS_NOATTR: c_uint = 0x100;
/// `CMS_NOSMIMECAP` — `cms.h.in:93`.
const CMS_NOSMIMECAP: c_uint = 0x200;
/// `CMS_PARTIAL` — `cms.h.in:98`.
const CMS_PARTIAL: c_uint = 0x4000;
/// `CMS_REUSE_DIGEST` — `cms.h.in:99`.
const CMS_REUSE_DIGEST: c_uint = 0x8000;
/// `CMS_KEY_PARAM` — `cms.h.in:102`.
const CMS_KEY_PARAM: c_uint = 0x40000;
/// `CMS_CADES` — `cms.h.in:104`.
const CMS_CADES: c_uint = 0x100000;
/// `CMS_NO_SIGNING_TIME` — `cms.h.in:106`.
const CMS_NO_SIGNING_TIME: c_uint = 0x400000;
/// `CMS_NOINTERN` — `cms.h.in:87`.
const CMS_NOINTERN: c_uint = 0x10;
/// `CMS_SIGNERINFO_ISSUER_SERIAL` / `_KEYIDENTIFIER` — `cms_local.h:410-411` (in `cms_asn1`).
/// `EVP_MD_CTX_FLAG_KEEP_PKEY_CTX` — `include/crypto/evp.h:263`.
const EVP_MD_CTX_FLAG_KEEP_PKEY_CTX: c_int = 0x0400;
/// `OSSL_MAX_NAME_SIZE` — `internal/sizes.h:15`.
const OSSL_MAX_NAME_SIZE: usize = 50;
/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:43`.
const EVP_MAX_MD_SIZE: usize = 64;
/// `SN_sha1` — `include/openssl/obj_mac.h`.
const SN_SHA1: &core::ffi::CStr = c"SHA1";
/// `X509_ADD_FLAG_DEFAULT` — `include/openssl/x509.h:996`.
const X509_ADD_FLAG_DEFAULT: c_int = 0;

// The ESS surface `cms_sd.c` reaches for `CMS_CADES`. It is Phase 12.7's (`crypto/ess/`), landed
// by that subphase; the shell scaffolds the exports, so this unit declares them exactly as the
// authority's prototypes spell them and the `CMS_CADES` arm is the only caller.
extern "C" {
    fn i2d_ESS_SIGNING_CERT(sc: *const c_void, out: *mut *mut c_uchar) -> c_int;
    fn i2d_ESS_SIGNING_CERT_V2(sc: *const c_void, out: *mut *mut c_uchar) -> c_int;
    fn ESS_SIGNING_CERT_free(sc: *mut c_void);
    fn ESS_SIGNING_CERT_V2_free(sc: *mut c_void);
    fn OSSL_ESS_signing_cert_new_init(
        signer: *const X509,
        iss: *const OpenSslStack,
        set_issuer_serial: c_int,
    ) -> *mut c_void;
    fn OSSL_ESS_signing_cert_v2_new_init(
        md: *const EvpMd,
        signer: *const X509,
        iss: *const OpenSslStack,
        set_issuer_serial: c_int,
    ) -> *mut c_void;
}

/// `CMS_SignedData *cms_get0_signed(CMS_ContentInfo *cms)` — `cms_sd.c:27-34`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_get0_signed(cms: *mut CmsContentInfo) -> *mut CmsSignedData {
    // SAFETY: `cms` is live.
    if unsafe { OBJ_obj2nid((*cms).content_type) } != crate::runtime::obj::NID_pkcs7_signed {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                30,
                c"cms_get0_signed",
                crate::runtime::err::err_reasons::CMS_R_CONTENT_TYPE_NOT_SIGNED_DATA,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live; the union arm matches the content type.
    unsafe { (*cms).d.cast::<CmsSignedData>() }
}

/// `CMS_SignedData *cms_signed_data_init(CMS_ContentInfo *cms)` — `cms_sd.c:36-52`.
///
/// # Safety
/// `cms` is live.
unsafe fn cms_signed_data_init(cms: *mut CmsContentInfo) -> *mut CmsSignedData {
    // SAFETY: `cms` is live.
    if unsafe { (*cms).d.is_null() } {
        // SAFETY: the item allocator answers a fresh value.
        let sd = unsafe { m_asn1_new(cms_signeddata_it()).cast::<CmsSignedData>() };
        if sd.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(41, c"cms_signed_data_init", ERR_R_ASN1_LIB) };
            return ptr::null_mut();
        }
        // SAFETY: `cms`/`sd` are live.
        unsafe {
            (*cms).d = sd.cast();
            (*sd).version = 1;
            (*(*sd).encap_content_info).e_content_type =
                OBJ_nid2obj(crate::runtime::obj::NID_pkcs7_data);
            (*(*sd).encap_content_info).partial = 1;
            crate::asn1::prim::ASN1_OBJECT_free((*cms).content_type);
            (*cms).content_type = OBJ_nid2obj(crate::runtime::obj::NID_pkcs7_signed);
        }
        return sd;
    }
    // SAFETY: `cms` is live.
    unsafe { cms_get0_signed(cms) }
}

/// `int CMS_SignedData_init(CMS_ContentInfo *cms)` — `cms_sd.c:55-61`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignedData_init(cms: *mut CmsContentInfo) -> c_int {
    // SAFETY: `cms` is live.
    c_int::from(!unsafe { cms_signed_data_init(cms) }.is_null())
}

/// `void cms_sd_set_version(CMS_SignedData *sd)` — `cms_sd.c:64-111`.
///
/// # Safety
/// `sd` is live.
unsafe fn cms_sd_set_version(sd: *mut CmsSignedData) {
    // SAFETY: `sd` is live.
    unsafe {
        let n = OPENSSL_sk_num((*sd).certificates);
        for i in 0..n {
            let cch = OPENSSL_sk_value((*sd).certificates, i).cast::<CmsCertificateChoices>();
            if (*cch).type_ == CMS_CERTCHOICE_OTHER {
                if (*sd).version < 5 {
                    (*sd).version = 5;
                }
            } else if (*cch).type_ == CMS_CERTCHOICE_V2ACERT {
                if (*sd).version < 4 {
                    (*sd).version = 4;
                }
            } else if (*cch).type_ == CMS_CERTCHOICE_V1ACERT && (*sd).version < 3 {
                (*sd).version = 3;
            }
        }
        let n = OPENSSL_sk_num((*sd).crls);
        for i in 0..n {
            let rch = OPENSSL_sk_value((*sd).crls, i).cast::<CmsRevocationInfoChoice>();
            if (*rch).type_ == CMS_REVCHOICE_OTHER && (*sd).version < 5 {
                (*sd).version = 5;
            }
        }
        if OBJ_obj2nid((*(*sd).encap_content_info).e_content_type)
            != crate::runtime::obj::NID_pkcs7_data
            && (*sd).version < 3
        {
            (*sd).version = 3;
        }
        let n = OPENSSL_sk_num((*sd).signer_infos);
        for i in 0..n {
            let si = OPENSSL_sk_value((*sd).signer_infos, i).cast::<CmsSignerInfo>();
            if (*(*si).sid).type_ == CMS_SIGNERINFO_KEYIDENTIFIER {
                if (*si).version < 3 {
                    (*si).version = 3;
                }
                if (*sd).version < 3 {
                    (*sd).version = 3;
                }
            } else if (*si).version < 1 {
                (*si).version = 1;
            }
        }
        if (*sd).version < 1 {
            (*sd).version = 1;
        }
    }
}

/// `int cms_set_si_contentType_attr(CMS_ContentInfo *cms, CMS_SignerInfo *si)` — `cms_sd.c:125-133`.
///
/// # Safety
/// `cms`/`si` are live.
unsafe fn cms_set_si_contentType_attr(cms: *mut CmsContentInfo, si: *mut CmsSignerInfo) -> c_int {
    // SAFETY: `cms` is live.
    let ctype = unsafe { (*(*(*cms).d.cast::<CmsSignedData>()).encap_content_info).e_content_type };
    // SAFETY: `si`/`ctype` are live.
    c_int::from(
        unsafe {
            CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType, V_ASN1_OBJECT, ctype.cast(), -1)
        } > 0,
    )
}

/// `int cms_copy_messageDigest(CMS_ContentInfo *cms, CMS_SignerInfo *si)` — `cms_sd.c:136-171`.
///
/// # Safety
/// `cms`/`si` are live.
unsafe fn cms_copy_messageDigest(cms: *mut CmsContentInfo, si: *mut CmsSignerInfo) -> c_int {
    // SAFETY: `cms` is live.
    let sinfos = unsafe { CMS_get0_SignerInfos(cms) };
    // SAFETY: `sinfos` is a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    for i in 0..n {
        // SAFETY: `i` is within `0..n`.
        let sitmp = unsafe { OPENSSL_sk_value(sinfos, i).cast::<CmsSignerInfo>() };
        if sitmp == si {
            continue;
        }
        // SAFETY: `sitmp` is live.
        if unsafe { CMS_signed_get_attr_count(sitmp) } < 0 {
            continue;
        }
        // SAFETY: `si`/`sitmp` are live.
        if unsafe {
            OBJ_cmp(
                (*(*si).digest_algorithm).algorithm,
                (*(*sitmp).digest_algorithm).algorithm,
            )
        } != 0
        {
            continue;
        }
        // SAFETY: `sitmp` is live.
        let message_digest = unsafe {
            CMS_signed_get0_data_by_OBJ(
                sitmp,
                OBJ_nid2obj(NID_pkcs9_messageDigest),
                -3,
                V_ASN1_OCTET_STRING,
            )
        };
        if message_digest.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    158,
                    c"cms_copy_messageDigest",
                    crate::runtime::err::err_reasons::CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE,
                )
            };
            return 0;
        }
        // SAFETY: `si`/`message_digest` are live.
        return c_int::from(
            unsafe {
                CMS_signed_add1_attr_by_NID(
                    si,
                    NID_pkcs9_messageDigest,
                    V_ASN1_OCTET_STRING,
                    message_digest,
                    -1,
                )
            } != 0,
        );
    }
    // SAFETY: the site is a compile-time constant.
    unsafe {
        raise_cms(
            169,
            c"cms_copy_messageDigest",
            crate::runtime::err::err_reasons::CMS_R_NO_MATCHING_DIGEST,
        )
    };
    0
}

/// `int ossl_cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid, X509 *cert, int type,`
/// `const CMS_CTX *ctx)` — `cms_sd.c:173-195`.
///
/// # Safety
/// `sid`/`cert` are live.
pub(crate) unsafe fn ossl_cms_set1_SignerIdentifier(
    sid: *mut CmsSignerIdentifier,
    cert: *mut X509,
    type_: c_int,
    _ctx: *const CmsCtx,
) -> c_int {
    match type_ {
        CMS_SIGNERINFO_ISSUER_SERIAL => {
            // SAFETY: `sid` is live.
            let pias =
                unsafe { ptr::addr_of_mut!((*sid).d).cast::<*mut CmsIssuerAndSerialNumber>() };
            // SAFETY: `pias`/`cert` are live.
            if unsafe { ossl_cms_set1_ias(pias, cert) } == 0 {
                return 0;
            }
        }
        CMS_SIGNERINFO_KEYIDENTIFIER => {
            // SAFETY: `sid` is live.
            let pkeyid = unsafe { ptr::addr_of_mut!((*sid).d).cast::<*mut Asn1String>() };
            // SAFETY: `pkeyid`/`cert` are live.
            if unsafe { ossl_cms_set1_keyid(pkeyid, cert) } == 0 {
                return 0;
            }
        }
        _ => {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    188,
                    c"ossl_cms_set1_SignerIdentifier",
                    crate::runtime::err::err_reasons::CMS_R_UNKNOWN_ID,
                )
            };
            return 0;
        }
    }
    // SAFETY: `sid` is live.
    unsafe { (*sid).type_ = type_ };
    1
}

/// `int ossl_cms_SignerIdentifier_get0_signer_id(...)` — `cms_sd.c:197-214`.
///
/// # Safety
/// `sid` is live; the out-parameters are writable or NULL.
pub(crate) unsafe fn ossl_cms_SignerIdentifier_get0_signer_id(
    sid: *mut CmsSignerIdentifier,
    keyid: *mut *mut Asn1String,
    issuer: *mut *mut X509Name,
    sno: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `sid` is live.
    let t = unsafe { (*sid).type_ };
    if t == CMS_SIGNERINFO_ISSUER_SERIAL {
        // SAFETY: `sid` is live and the arm matches.
        let ias = unsafe { (*sid).d.cast::<CmsIssuerAndSerialNumber>() };
        // SAFETY: each out-parameter is writable when non-null.
        unsafe {
            if !issuer.is_null() {
                *issuer = (*ias).issuer;
            }
            if !sno.is_null() {
                *sno = (*ias).serial_number;
            }
        }
    } else if t == CMS_SIGNERINFO_KEYIDENTIFIER {
        // SAFETY: `keyid` is writable when non-null.
        if !keyid.is_null() {
            // SAFETY: `sid` is live and the arm matches.
            unsafe { *keyid = (*sid).d.cast() };
        }
    } else {
        return 0;
    }
    1
}

/// `int ossl_cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid, X509 *cert)` —
/// `cms_sd.c:216-224`.
///
/// # Safety
/// `sid`/`cert` are live.
pub(crate) unsafe fn ossl_cms_SignerIdentifier_cert_cmp(
    sid: *mut CmsSignerIdentifier,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `sid` is live.
    let t = unsafe { (*sid).type_ };
    if t == CMS_SIGNERINFO_ISSUER_SERIAL {
        // SAFETY: `sid` is live and the arm matches.
        return unsafe { ossl_cms_ias_cert_cmp((*sid).d.cast(), cert) };
    }
    if t == CMS_SIGNERINFO_KEYIDENTIFIER {
        // SAFETY: `sid` is live and the arm matches.
        return unsafe { ossl_cms_keyid_cert_cmp((*sid).d.cast(), cert) };
    }
    -1
}

/// `int cms_signature_nomd(EVP_PKEY *pkey)` — `cms_sd.c:226-234`.
///
/// # Safety
/// `pkey` is live.
unsafe fn cms_signature_nomd(pkey: *mut EvpPkey) -> c_int {
    let mut def_md = [0 as c_char; 80];
    // SAFETY: `pkey` is live; `def_md` is writable.
    if unsafe { EVP_PKEY_get_default_digest_name(pkey, def_md.as_mut_ptr(), def_md.len()) } != 2 {
        return 0;
    }
    // SAFETY: the callee NUL-terminates `def_md` on success.
    let name = unsafe { core::ffi::CStr::from_ptr(def_md.as_ptr()) };
    c_int::from(name.to_bytes() == b"UNDEF")
}

/// `int cms_generic_sign(CMS_SignerInfo *si, int verify)` — `cms_sd.c:238-267`.
///
/// # Safety
/// `si` is live.
unsafe fn cms_generic_sign(si: *mut CmsSignerInfo, verify: c_int) -> c_int {
    if verify != 0 {
        return 1;
    }
    // SAFETY: `si` is live.
    let pkey = unsafe { (*si).pkey };
    // SAFETY: `pkey` is live.
    let mut pknid = unsafe { EVP_PKEY_get_id(pkey) };
    let mut alg1: *mut X509Algor = ptr::null_mut();
    let mut alg2: *mut X509Algor = ptr::null_mut();
    // SAFETY: `si` is live.
    unsafe { CMS_SignerInfo_get0_algs(si, ptr::null_mut(), ptr::null_mut(), &mut alg1, &mut alg2) };
    if alg1.is_null() {
        return -1;
    }
    // SAFETY: `alg1` is live.
    if unsafe { (*alg1).algorithm.is_null() } {
        return -1;
    }
    // SAFETY: `alg1` is live.
    let hnid = unsafe { OBJ_obj2nid((*alg1).algorithm) };
    if hnid == NID_undef {
        return -1;
    }
    if pknid <= 0 {
        // SAFETY: `pkey` is live.
        let typename = unsafe { EVP_PKEY_get0_type_name(pkey) };
        if !typename.is_null() {
            // SAFETY: `typename` is a NUL-terminated name.
            pknid = unsafe { OBJ_txt2nid(typename) };
        }
    }
    let snid = if pknid > 0
        // SAFETY: `pkey` is live.
        && unsafe { cms_signature_nomd(pkey) } != 0
    {
        pknid
    } else {
        let mut snid = 0;
        // SAFETY: `hnid`/`pknid` are NIDs.
        if unsafe { OBJ_find_sigid_by_algs(&mut snid, hnid, pknid) } == 0 {
            return -1;
        }
        snid
    };
    // SAFETY: `alg2` is live.
    unsafe { X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, ptr::null_mut()) }
}

/// `int cms_sd_asn1_ctrl(CMS_SignerInfo *si, int cmd)` — `cms_sd.c:269-292`.
///
/// The engine/method arm is omitted: the admitted profile has no legacy engines, and the crate's
/// `EvpPkey::ameth` models no `pkey_ctrl` for the provider keys this path reaches, so the
/// authority's fall-through (`cms_generic_sign`) is what every key that is not DSA/EC/RSA takes.
///
/// # Safety
/// `si` is live.
unsafe fn cms_sd_asn1_ctrl(si: *mut CmsSignerInfo, cmd: c_int) -> c_int {
    // SAFETY: `si` is live.
    let pkey = unsafe { (*si).pkey };
    // SAFETY: `pkey` is live.
    let is_dsa = unsafe { EVP_PKEY_is_a(pkey, c"DSA".as_ptr()) } != 0;
    // SAFETY: `pkey` is live.
    let is_ec = unsafe { EVP_PKEY_is_a(pkey, c"EC".as_ptr()) } != 0;
    if is_dsa || is_ec {
        // SAFETY: `si` is live.
        return c_int::from(unsafe { cms_generic_sign(si, cmd) } > 0);
    }
    // SAFETY: `pkey` is live.
    let is_rsa = unsafe { EVP_PKEY_is_a(pkey, c"RSA".as_ptr()) } != 0;
    // SAFETY: `pkey` is live.
    let is_pss = unsafe { EVP_PKEY_is_a(pkey, c"RSA-PSS".as_ptr()) } != 0;
    if is_rsa || is_pss {
        // SAFETY: `si` is live.
        return c_int::from(unsafe { ossl_cms_rsa_sign(si, cmd) } > 0);
    }
    // SAFETY: `si` is live.
    c_int::from(unsafe { cms_generic_sign(si, cmd) } > 0)
}

/// `int ossl_cms_add1_signing_cert(CMS_SignerInfo *si, const ESS_SIGNING_CERT *sc)` —
/// `cms_sd.c:295-317`.
///
/// # Safety
/// `si`/`sc` are live.
unsafe fn ossl_cms_add1_signing_cert(si: *mut CmsSignerInfo, sc: *const c_void) -> c_int {
    // SAFETY: `sc` is live.
    let len = unsafe { i2d_ESS_SIGNING_CERT(sc, ptr::null_mut()) };
    if len <= 0 {
        return 0;
    }
    // SAFETY: `len > 0`.
    let pp = CRYPTO_malloc(len as usize, c"cms_sd.c".as_ptr(), 302).cast::<c_uchar>();
    if pp.is_null() {
        return 0;
    }
    let mut p = pp;
    // SAFETY: `sc` is live; `p` is writable for `len`.
    unsafe { i2d_ESS_SIGNING_CERT(sc, &mut p) };
    // SAFETY: the allocator answers a fresh string.
    let seq = ASN1_STRING_new();
    if seq.is_null()
        // SAFETY: `seq` is live; `pp`/`len` describe the content.
        || unsafe { ASN1_STRING_set(seq, pp.cast(), len) } == 0
    {
        // SAFETY: each is NULL or owned.
        unsafe {
            ASN1_STRING_free(seq);
            CRYPTO_free(pp.cast(), c"cms_sd.c".as_ptr(), 309);
        }
        return 0;
    }
    // SAFETY: `pp` is owned here.
    unsafe { CRYPTO_free(pp.cast(), c"cms_sd.c".as_ptr(), 312) };
    // SAFETY: `si`/`seq` are live.
    let ret = unsafe {
        CMS_signed_add1_attr_by_NID(
            si,
            NID_id_smime_aa_signingCertificate,
            V_ASN1_SEQUENCE,
            seq.cast(),
            -1,
        )
    };
    // SAFETY: `seq` is owned here.
    unsafe { ASN1_STRING_free(seq) };
    ret
}

/// `int ossl_cms_add1_signing_cert_v2(CMS_SignerInfo *si, const ESS_SIGNING_CERT_V2 *sc)` —
/// `cms_sd.c:320-342`.
///
/// # Safety
/// `si`/`sc` are live.
unsafe fn ossl_cms_add1_signing_cert_v2(si: *mut CmsSignerInfo, sc: *const c_void) -> c_int {
    // SAFETY: `sc` is live.
    let len = unsafe { i2d_ESS_SIGNING_CERT_V2(sc, ptr::null_mut()) };
    if len <= 0 {
        return 0;
    }
    // SAFETY: `len > 0`.
    let pp = CRYPTO_malloc(len as usize, c"cms_sd.c".as_ptr(), 327).cast::<c_uchar>();
    if pp.is_null() {
        return 0;
    }
    let mut p = pp;
    // SAFETY: `sc` is live; `p` is writable for `len`.
    unsafe { i2d_ESS_SIGNING_CERT_V2(sc, &mut p) };
    // SAFETY: the allocator answers a fresh string.
    let seq = ASN1_STRING_new();
    if seq.is_null()
        // SAFETY: `seq` is live; `pp`/`len` describe the content.
        || unsafe { ASN1_STRING_set(seq, pp.cast(), len) } == 0
    {
        // SAFETY: each is NULL or owned.
        unsafe {
            ASN1_STRING_free(seq);
            CRYPTO_free(pp.cast(), c"cms_sd.c".as_ptr(), 334);
        }
        return 0;
    }
    // SAFETY: `pp` is owned here.
    unsafe { CRYPTO_free(pp.cast(), c"cms_sd.c".as_ptr(), 337) };
    // SAFETY: `si`/`seq` are live.
    let ret = unsafe {
        CMS_signed_add1_attr_by_NID(
            si,
            NID_id_smime_aa_signingCertificateV2,
            V_ASN1_SEQUENCE,
            seq.cast(),
            -1,
        )
    };
    // SAFETY: `seq` is owned here.
    unsafe { ASN1_STRING_free(seq) };
    ret
}

/// `CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *cms, X509 *signer, EVP_PKEY *pk,`
/// `const EVP_MD *md, unsigned int flags)` — `cms_sd.c:344-559`.
///
/// # Safety
/// `cms`/`signer`/`pk` are live; `md` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add1_signer(
    cms: *mut CmsContentInfo,
    signer: *mut X509,
    pk: *mut EvpPkey,
    md: *const EvpMd,
    flags: c_uint,
) -> *mut CmsSignerInfo {
    let mut si: *mut CmsSignerInfo = ptr::null_mut();
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    // SAFETY: `signer`/`pk` are live.
    if unsafe { X509_check_private_key(signer, pk) } == 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                355,
                c"CMS_add1_signer",
                crate::runtime::err::err_reasons::CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE,
            )
        };
        return ptr::null_mut();
    }
    // SAFETY: `cms` is live.
    let sd = unsafe { cms_signed_data_init(cms) };
    if sd.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the item allocator answers a fresh value.
    si = unsafe { m_asn1_new(cms_signerinfo_it()).cast::<CmsSignerInfo>() };
    if si.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(363, c"CMS_add1_signer", ERR_R_ASN1_LIB) };
        return ptr::null_mut();
    }
    // SAFETY: `signer` is live.
    unsafe { X509_check_purpose(signer, -1, -1) };
    let mut md = md;

    'body: {
        // SAFETY: `signer` is live.
        if unsafe { X509_up_ref(signer) } == 0 {
            break 'body;
        }
        // SAFETY: `pk` is live.
        if unsafe { EVP_PKEY_up_ref(pk) } == 0 {
            // SAFETY: `signer` is live and the reference added above is ours.
            unsafe { X509_free(signer) };
            break 'body;
        }
        // SAFETY: `si` is live.
        unsafe {
            (*si).cms_ctx = ctx;
            (*si).pkey = pk;
            (*si).signer = signer;
            (*si).mctx = EVP_MD_CTX_new().cast();
            (*si).pctx = ptr::null_mut();
            (*si).omit_signing_time = 0;
        }
        // SAFETY: `si` is live.
        if unsafe { (*si).mctx.is_null() } {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(384, c"CMS_add1_signer", ERR_R_EVP_LIB) };
            break 'body;
        }
        let type_;
        if flags & CMS_USE_KEYID != 0 {
            // SAFETY: `si`/`sd` are live.
            unsafe {
                (*si).version = 3;
                if (*sd).version < 3 {
                    (*sd).version = 3;
                }
            }
            type_ = CMS_SIGNERINFO_KEYIDENTIFIER;
        } else {
            type_ = CMS_SIGNERINFO_ISSUER_SERIAL;
            // SAFETY: `si` is live.
            unsafe { (*si).version = 1 };
        }
        // SAFETY: `si`/`signer` are live.
        if unsafe { ossl_cms_set1_SignerIdentifier((*si).sid, signer, type_, ctx) } == 0 {
            break 'body;
        }
        if md.is_null() {
            let mut def_nid = 0;
            // SAFETY: `pk` is live.
            if unsafe { EVP_PKEY_get_default_digest_nid(pk, &mut def_nid) } <= 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        405,
                        c"CMS_add1_signer",
                        crate::runtime::err::err_reasons::CMS_R_NO_DEFAULT_DIGEST,
                    )
                };
                break 'body;
            }
            // SAFETY: `def_nid` is a NID.
            md = unsafe { EVP_get_digestbyname(OBJ_nid2sn(def_nid)) };
            if md.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        411,
                        c"CMS_add1_signer",
                        crate::runtime::err::err_reasons::CMS_R_NO_DEFAULT_DIGEST,
                    )
                };
                break 'body;
            }
        }
        // SAFETY: `si`/`md` are live.
        unsafe { X509_ALGOR_set_md((*si).digest_algorithm, md) };
        // SAFETY: `sd` is live.
        let mut i = 0;
        // SAFETY: `sd` is live.
        let ndig = unsafe { OPENSSL_sk_num((*sd).digest_algorithms) };
        while i < ndig {
            // SAFETY: `i` is within range.
            let alg = unsafe { OPENSSL_sk_value((*sd).digest_algorithms, i).cast::<X509Algor>() };
            let mut aoid: *const Asn1Object = ptr::null();
            // SAFETY: `alg` is live.
            unsafe { X509_ALGOR_get0(&mut aoid, ptr::null_mut(), ptr::null_mut(), alg) };
            let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];
            // SAFETY: `aoid` is live; `name` writable.
            unsafe { OBJ_obj2txt(name.as_mut_ptr(), OSSL_MAX_NAME_SIZE as c_int, aoid, 0) };
            // SAFETY: `md` is live; `name` is a C string.
            if unsafe { EVP_MD_is_a(md, name.as_ptr()) } != 0 {
                break;
            }
            i += 1;
        }
        if i == ndig {
            // SAFETY: the allocator answers a fresh value.
            let alg = X509_ALGOR_new();
            if alg.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(433, c"CMS_add1_signer", ERR_R_ASN1_LIB) };
                break 'body;
            }
            // SAFETY: `alg`/`md` are live.
            unsafe { X509_ALGOR_set_md(alg, md) };
            // SAFETY: `sd` is live.
            if unsafe { OPENSSL_sk_push((*sd).digest_algorithms, alg.cast()) } == 0 {
                // SAFETY: `alg` is owned here.
                unsafe { X509_ALGOR_free(alg) };
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(439, c"CMS_add1_signer", ERR_R_CRYPTO_LIB) };
                break 'body;
            }
        }
        if flags & CMS_KEY_PARAM == 0
            // SAFETY: `si` is live.
            && unsafe { cms_sd_asn1_ctrl(si, 0) } == 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    445,
                    c"CMS_add1_signer",
                    crate::runtime::err::err_reasons::CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM,
                )
            };
            break 'body;
        }
        if flags & CMS_NOATTR == 0 {
            // SAFETY: `si` is live.
            if unsafe { (*si).signed_attrs.is_null() } {
                // SAFETY: the stack allocator answers a fresh stack.
                let sk = OPENSSL_sk_new_null();
                if sk.is_null() {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cms(457, c"CMS_add1_signer", ERR_R_CRYPTO_LIB) };
                    break 'body;
                }
                // SAFETY: `si` is live.
                unsafe { (*si).signed_attrs = sk };
            }
            if flags & CMS_NOSMIMECAP == 0 {
                let mut smcap: *mut OpenSslStack = ptr::null_mut();
                // SAFETY: the caller's contract.
                let mut r = unsafe { CMS_add_standard_smimecap(&mut smcap) };
                if r != 0 {
                    // SAFETY: `si`/`smcap` are live.
                    r = unsafe { CMS_add_smimecap(si, smcap) };
                }
                // SAFETY: `smcap` is NULL or owned.
                unsafe { OPENSSL_sk_pop_free(smcap, Some(x509_algor_free_void)) };
                if r == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_cms(470, c"CMS_add1_signer", ERR_R_CMS_LIB) };
                    break 'body;
                }
            }
            if flags & CMS_NO_SIGNING_TIME != 0 {
                // SAFETY: `si` is live.
                unsafe { (*si).omit_signing_time = 1 };
            }
            if flags & CMS_CADES != 0 {
                let add_sc;
                if md.is_null()
                    // SAFETY: `md` is live; the literal is static.
                    || unsafe { EVP_MD_is_a(md, SN_SHA1.as_ptr()) } != 0
                {
                    // SAFETY: `signer` is live.
                    let sc = unsafe { OSSL_ESS_signing_cert_new_init(signer, ptr::null(), 1) };
                    if sc.is_null() {
                        break 'body;
                    }
                    // SAFETY: `si`/`sc` are live.
                    add_sc = unsafe { ossl_cms_add1_signing_cert(si, sc) };
                    // SAFETY: `sc` is owned here.
                    unsafe { ESS_SIGNING_CERT_free(sc) };
                } else {
                    // SAFETY: `md`/`signer` are live.
                    let sc2 =
                        unsafe { OSSL_ESS_signing_cert_v2_new_init(md, signer, ptr::null(), 1) };
                    if sc2.is_null() {
                        break 'body;
                    }
                    // SAFETY: `si`/`sc2` are live.
                    add_sc = unsafe { ossl_cms_add1_signing_cert_v2(si, sc2) };
                    // SAFETY: `sc2` is owned here.
                    unsafe { ESS_SIGNING_CERT_V2_free(sc2) };
                }
                if add_sc == 0 {
                    break 'body;
                }
            }
            if flags & CMS_REUSE_DIGEST != 0 {
                // SAFETY: `cms`/`si` are live.
                if unsafe { cms_copy_messageDigest(cms, si) } == 0 {
                    break 'body;
                }
                // SAFETY: same.
                if unsafe { cms_set_si_contentType_attr(cms, si) } == 0 {
                    break 'body;
                }
                if flags & (CMS_PARTIAL | CMS_KEY_PARAM) == 0
                    // SAFETY: `si` is live.
                    && unsafe { CMS_SignerInfo_sign(si) } == 0
                {
                    break 'body;
                }
            }
        }
        if flags & CMS_NOCERTS == 0 {
            // SAFETY: `cms`/`signer` are live.
            if unsafe { CMS_add1_cert(cms, signer) } == 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_cms(518, c"CMS_add1_signer", ERR_R_CMS_LIB) };
                break 'body;
            }
        }
        if flags & CMS_KEY_PARAM != 0 {
            if flags & CMS_NOATTR != 0 {
                // SAFETY: `si` is live.
                let pctx = unsafe {
                    EVP_PKEY_CTX_new_from_pkey(
                        ossl_cms_ctx_get0_libctx(ctx),
                        (*si).pkey,
                        ossl_cms_ctx_get0_propq(ctx),
                    )
                };
                // SAFETY: `si` is live.
                unsafe { (*si).pctx = pctx.cast() };
                if pctx.is_null() {
                    break 'body;
                }
                // SAFETY: `pctx` is live.
                if unsafe { EVP_PKEY_sign_init(pctx) } <= 0 {
                    break 'body;
                }
                // SAFETY: `pctx`/`md` are live.
                if unsafe { EVP_PKEY_CTX_set_signature_md(pctx, md) } <= 0 {
                    break 'body;
                }
            } else {
                // SAFETY: `si`/`pk` are live.
                let r = unsafe {
                    EVP_DigestSignInit_ex(
                        (*si).mctx.cast(),
                        ptr::addr_of_mut!((*si).pctx).cast(),
                        EVP_MD_get0_name(md),
                        ossl_cms_ctx_get0_libctx(ctx),
                        ossl_cms_ctx_get0_propq(ctx),
                        pk,
                        ptr::null(),
                    )
                };
                if r <= 0 {
                    // SAFETY: `si` is live.
                    unsafe { (*si).pctx = ptr::null_mut() };
                    break 'body;
                }
                // SAFETY: `si` is live.
                unsafe { EVP_MD_CTX_set_flags((*si).mctx.cast(), EVP_MD_CTX_FLAG_KEEP_PKEY_CTX) };
            }
        }
        // SAFETY: `sd` is live.
        unsafe {
            if (*sd).signer_infos.is_null() {
                (*sd).signer_infos = OPENSSL_sk_new_null();
            }
            if (*sd).signer_infos.is_null() || OPENSSL_sk_push((*sd).signer_infos, si.cast()) == 0 {
                raise_cms(550, c"CMS_add1_signer", ERR_R_CRYPTO_LIB);
                break 'body;
            }
        }
        return si;
    }
    // SAFETY: `si` is NULL or a value the item layer built.
    unsafe { m_asn1_free(si.cast(), cms_signerinfo_it()) };
    ptr::null_mut()
}

/// `void ossl_cms_SignerInfos_set_cmsctx(CMS_ContentInfo *cms)` — `cms_sd.c:561-577`.
///
/// # Safety
/// `cms` is NULL or live.
pub(crate) unsafe extern "C" fn ossl_cms_SignerInfos_set_cmsctx(cms: *mut CmsContentInfo) {
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    // SAFETY: `cms` is live.
    let sinfos = unsafe { CMS_get0_SignerInfos(cms) };
    // SAFETY: `sinfos` is a live stack (possibly NULL).
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    for i in 0..n {
        // SAFETY: `i` is within range.
        let si = unsafe { OPENSSL_sk_value(sinfos, i).cast::<CmsSignerInfo>() };
        if !si.is_null() {
            // SAFETY: `si` is live.
            unsafe { (*si).cms_ctx = ctx };
        }
    }
}

/// `int cms_add1_signingTime(CMS_SignerInfo *si, ASN1_TIME *t)` — `cms_sd.c:579-607`.
///
/// # Safety
/// `si` is live; `t` is NULL or live.
unsafe fn cms_add1_signingTime(si: *mut CmsSignerInfo, t: *mut Asn1String) -> c_int {
    let tt = if !t.is_null() {
        t
    } else {
        // SAFETY: the argument is a NULL `ASN1_TIME`.
        unsafe { X509_gmtime_adj(ptr::null_mut(), 0) }
    };
    if tt.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(590, c"cms_add1_signingTime", ERR_R_X509_LIB) };
        return 0;
    }
    // SAFETY: `si`/`tt` are live.
    let mut r = 0;
    // SAFETY: `si`/`tt` are live.
    if unsafe { CMS_signed_add1_attr_by_NID(si, NID_pkcs9_signingTime, (*tt).type_, tt.cast(), -1) }
        > 0
    {
        r = 1;
    } else {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(597, c"cms_add1_signingTime", ERR_R_CMS_LIB) };
    }
    if t.is_null() {
        // SAFETY: `tt` is owned here.
        unsafe { ASN1_STRING_free(tt) };
    }
    r
}

/// `EVP_PKEY_CTX *CMS_SignerInfo_get0_pkey_ctx(CMS_SignerInfo *si)` — `cms_sd.c:609-612`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_get0_pkey_ctx(
    si: *mut CmsSignerInfo,
) -> *mut EvpPkeyCtx {
    // SAFETY: `si` is live.
    unsafe { (*si).pctx.cast() }
}

/// `EVP_MD_CTX *CMS_SignerInfo_get0_md_ctx(CMS_SignerInfo *si)` — `cms_sd.c:614-617`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_get0_md_ctx(
    si: *mut CmsSignerInfo,
) -> *mut EvpMdCtx {
    // SAFETY: `si` is live.
    unsafe { (*si).mctx.cast() }
}

/// `STACK_OF(CMS_SignerInfo) *CMS_get0_SignerInfos(CMS_ContentInfo *cms)` — `cms_sd.c:619-624`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_SignerInfos(
    cms: *mut CmsContentInfo,
) -> *mut OpenSslStack {
    // SAFETY: `cms` is live.
    let sd = unsafe { cms_get0_signed(cms) };
    if sd.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: `sd` is live.
        unsafe { (*sd).signer_infos }
    }
}

/// `STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms)` — `cms_sd.c:626-645`.
///
/// # Safety
/// `cms` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_get0_signers(cms: *mut CmsContentInfo) -> *mut OpenSslStack {
    let mut signers: *mut OpenSslStack = ptr::null_mut();
    // SAFETY: `cms` is live.
    let sinfos = unsafe { CMS_get0_SignerInfos(cms) };
    // SAFETY: `sinfos` is a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    for i in 0..n {
        // SAFETY: `i` is within range.
        let si = unsafe { OPENSSL_sk_value(sinfos, i).cast::<CmsSignerInfo>() };
        // SAFETY: `si` is live.
        if unsafe { !(*si).signer.is_null() } {
            // SAFETY: `signers`/`(*si).signer` are live.
            if unsafe { ossl_x509_add_cert_new(&mut signers, (*si).signer, X509_ADD_FLAG_DEFAULT) }
                == 0
            {
                // SAFETY: `signers` is NULL or owned.
                unsafe { OPENSSL_sk_free(signers) };
                return ptr::null_mut();
            }
        }
    }
    signers
}

/// `void CMS_SignerInfo_set1_signer_cert(CMS_SignerInfo *si, X509 *signer)` — `cms_sd.c:647-657`.
///
/// # Safety
/// `si` is live; `signer` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_set1_signer_cert(
    si: *mut CmsSignerInfo,
    signer: *mut X509,
) {
    if !signer.is_null() {
        // SAFETY: `signer` is live.
        if unsafe { X509_up_ref(signer) } == 0 {
            return;
        }
        // SAFETY: `si` is live.
        unsafe {
            EVP_PKEY_free((*si).pkey);
            (*si).pkey = X509_get_pubkey(signer);
        }
    }
    // SAFETY: `si` is live.
    unsafe {
        X509_free((*si).signer);
        (*si).signer = signer;
    }
}

/// `int CMS_SignerInfo_get0_signer_id(CMS_SignerInfo *si, ASN1_OCTET_STRING **keyid,`
/// `X509_NAME **issuer, ASN1_INTEGER **sno)` — `cms_sd.c:659-664`.
///
/// # Safety
/// `si` is live; out-parameters writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_get0_signer_id(
    si: *mut CmsSignerInfo,
    keyid: *mut *mut Asn1String,
    issuer: *mut *mut X509Name,
    sno: *mut *mut Asn1String,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { ossl_cms_SignerIdentifier_get0_signer_id((*si).sid, keyid, issuer, sno) }
}

/// `int CMS_SignerInfo_cert_cmp(CMS_SignerInfo *si, X509 *cert)` — `cms_sd.c:666-669`.
///
/// # Safety
/// `si`/`cert` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_cert_cmp(
    si: *mut CmsSignerInfo,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `si` is live.
    unsafe { ossl_cms_SignerIdentifier_cert_cmp((*si).sid, cert) }
}

/// `int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *scerts, unsigned int flags)` —
/// `cms_sd.c:671-716`.
///
/// # Safety
/// `cms` is live; `scerts` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_set1_signers_certs(
    cms: *mut CmsContentInfo,
    scerts: *mut OpenSslStack,
    flags: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    let sd = unsafe { cms_get0_signed(cms) };
    if sd.is_null() {
        return -1;
    }
    // SAFETY: `sd` is live.
    let certs = unsafe { (*sd).certificates };
    let mut ret = 0;
    // SAFETY: `sd` is live.
    let nsi = unsafe { OPENSSL_sk_num((*sd).signer_infos) };
    for i in 0..nsi {
        // SAFETY: `i` is within range.
        let si = unsafe { OPENSSL_sk_value((*sd).signer_infos, i).cast::<CmsSignerInfo>() };
        // SAFETY: `si` is live.
        if unsafe { !(*si).signer.is_null() } {
            continue;
        }
        // SAFETY: `scerts` is NULL or live.
        let ncert = unsafe { OPENSSL_sk_num(scerts) };
        for j in 0..ncert {
            // SAFETY: `j` is within range.
            let x = unsafe { OPENSSL_sk_value(scerts, j).cast::<X509>() };
            // SAFETY: `si`/`x` are live.
            if unsafe { CMS_SignerInfo_cert_cmp(si, x) } == 0 {
                // SAFETY: `si`/`x` are live.
                unsafe { CMS_SignerInfo_set1_signer_cert(si, x) };
                ret += 1;
                break;
            }
        }
        // SAFETY: `si` is live.
        if unsafe { !(*si).signer.is_null() } || flags & CMS_NOINTERN != 0 {
            continue;
        }
        // SAFETY: `certs` is NULL or live.
        let ncch = unsafe { OPENSSL_sk_num(certs) };
        for j in 0..ncch {
            // SAFETY: `j` is within range.
            let cch = unsafe { OPENSSL_sk_value(certs, j).cast::<CmsCertificateChoices>() };
            // SAFETY: `cch` is live.
            if unsafe { (*cch).type_ != CMS_CERTCHOICE_CERT } {
                continue;
            }
            // SAFETY: `cch` is live and the arm matches.
            let x = unsafe { (*cch).d.cast::<X509>() };
            // SAFETY: `si`/`x` are live.
            if unsafe { CMS_SignerInfo_cert_cmp(si, x) } == 0 {
                // SAFETY: `si`/`x` are live.
                unsafe { CMS_SignerInfo_set1_signer_cert(si, x) };
                ret += 1;
                break;
            }
        }
    }
    ret
}

/// `void CMS_SignerInfo_get0_algs(CMS_SignerInfo *si, EVP_PKEY **pk, X509 **signer,`
/// `X509_ALGOR **pdig, X509_ALGOR **psig)` — `cms_sd.c:718-730`.
///
/// # Safety
/// `si` is live; out-parameters writable or NULL.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_get0_algs(
    si: *mut CmsSignerInfo,
    pk: *mut *mut EvpPkey,
    signer: *mut *mut X509,
    pdig: *mut *mut X509Algor,
    psig: *mut *mut X509Algor,
) {
    // SAFETY: `si` is live.
    unsafe {
        if !pk.is_null() {
            *pk = (*si).pkey;
        }
        if !signer.is_null() {
            *signer = (*si).signer;
        }
        if !pdig.is_null() {
            *pdig = (*si).digest_algorithm;
        }
        if !psig.is_null() {
            *psig = (*si).signature_algorithm;
        }
    }
}

/// `ASN1_OCTET_STRING *CMS_SignerInfo_get0_signature(CMS_SignerInfo *si)` — `cms_sd.c:732-735`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_get0_signature(
    si: *mut CmsSignerInfo,
) -> *mut Asn1String {
    // SAFETY: `si` is live.
    unsafe { (*si).signature }
}

/// `int cms_SignerInfo_content_sign(CMS_ContentInfo *cms, CMS_SignerInfo *si, BIO *chain,`
/// `const unsigned char *md, unsigned int mdlen)` — `cms_sd.c:737-830`.
///
/// # Safety
/// `cms`/`si`/`chain` are live; `md` is NULL or readable for `mdlen`.
unsafe fn cms_SignerInfo_content_sign(
    cms: *mut CmsContentInfo,
    si: *mut CmsSignerInfo,
    chain: *mut Bio,
    md: *const c_uchar,
    mdlen: c_uint,
) -> c_int {
    // SAFETY: the allocator answers a fresh context.
    let mctx = EVP_MD_CTX_new();
    // SAFETY: `cms` is live.
    let ctx = unsafe { ossl_cms_get0_cmsctx(cms) };
    if mctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(748, c"cms_SignerInfo_content_sign", ERR_R_CMS_LIB) };
        return 0;
    }
    let mut r = 0;
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    // SAFETY: `si` is live.
    if unsafe { (*si).pkey.is_null() } {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                753,
                c"cms_SignerInfo_content_sign",
                crate::runtime::err::err_reasons::CMS_R_NO_PRIVATE_KEY,
            )
        };
        // SAFETY: `mctx` is owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    // SAFETY: `mctx`/`chain`/`si` are live.
    if unsafe { ossl_cms_DigestAlgorithm_find_ctx(mctx, chain, (*si).digest_algorithm) } == 0 {
        // SAFETY: `mctx` is owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    // SAFETY: `si` is live.
    if unsafe { !(*si).pctx.is_null() && cms_sd_asn1_ctrl(si, 0) == 0 } {
        // SAFETY: `mctx` is owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return 0;
    }
    'body: {
        // SAFETY: `si` is live.
        if unsafe { CMS_signed_get_attr_count(si) } >= 0 {
            let mut computed_md = [0u8; EVP_MAX_MD_SIZE];
            let mut md = md;
            let mut mdlen = mdlen;
            if md.is_null() {
                // SAFETY: `mctx` is live; `computed_md` writable.
                if unsafe { EVP_DigestFinal_ex(mctx, computed_md.as_mut_ptr(), &mut mdlen) } == 0 {
                    break 'body;
                }
                md = computed_md.as_ptr();
            }
            // SAFETY: `si`/`md` are live.
            if unsafe {
                CMS_signed_add1_attr_by_NID(
                    si,
                    NID_pkcs9_messageDigest,
                    V_ASN1_OCTET_STRING,
                    md.cast(),
                    mdlen as c_int,
                )
            } == 0
            {
                break 'body;
            }
            // SAFETY: `cms`/`si` are live.
            if unsafe { cms_set_si_contentType_attr(cms, si) } == 0 {
                break 'body;
            }
            // SAFETY: `si` is live.
            if unsafe { CMS_SignerInfo_sign(si) } == 0 {
                break 'body;
            }
        // SAFETY: `si` is live.
        } else if unsafe { !(*si).pctx.is_null() } {
            let mut computed_md = [0u8; EVP_MAX_MD_SIZE];
            let mut md = md;
            let mut mdlen = mdlen;
            // SAFETY: `si` is live.
            pctx = unsafe { (*si).pctx.cast() };
            // SAFETY: `si` is live.
            unsafe { (*si).pctx = ptr::null_mut() };
            if md.is_null() {
                // SAFETY: `mctx` is live.
                if unsafe { EVP_DigestFinal_ex(mctx, computed_md.as_mut_ptr(), &mut mdlen) } == 0 {
                    break 'body;
                }
                md = computed_md.as_ptr();
            }
            // SAFETY: `si` is live.
            let mut siglen = unsafe { EVP_PKEY_get_size((*si).pkey) } as usize;
            if siglen == 0 {
                break 'body;
            }
            let sig = CRYPTO_malloc(siglen, c"cms_sd.c".as_ptr(), 796).cast::<c_uchar>();
            if sig.is_null() {
                break 'body;
            }
            // SAFETY: `pctx`/`sig`/`md` are live.
            if unsafe { EVP_PKEY_sign(pctx, sig, &mut siglen, md, mdlen as usize) } <= 0 {
                // SAFETY: `sig` is owned here.
                unsafe { CRYPTO_free(sig.cast(), c"cms_sd.c".as_ptr(), 799) };
                break 'body;
            }
            // SAFETY: `si` is live.
            let _ = ctx;
            // SAFETY: `si`/`sig` are live.
            unsafe { ASN1_STRING_set0((*si).signature, sig.cast(), siglen as c_int) };
        } else {
            let mut siglen: c_uint;
            if !md.is_null() {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        808,
                        c"cms_SignerInfo_content_sign",
                        crate::runtime::err::err_reasons::CMS_R_OPERATION_UNSUPPORTED,
                    )
                };
                break 'body;
            }
            // SAFETY: `si` is live.
            siglen = unsafe { EVP_PKEY_get_size((*si).pkey) } as c_uint;
            if siglen == 0 {
                break 'body;
            }
            let sig = CRYPTO_malloc(siglen as usize, c"cms_sd.c".as_ptr(), 812).cast::<c_uchar>();
            if sig.is_null() {
                break 'body;
            }
            // SAFETY: `mctx`/`sig`/`si` are live.
            if unsafe {
                EVP_SignFinal_ex(
                    mctx,
                    sig,
                    &mut siglen,
                    (*si).pkey,
                    ossl_cms_ctx_get0_libctx(ctx),
                    ossl_cms_ctx_get0_propq(ctx),
                )
            } == 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        817,
                        c"cms_SignerInfo_content_sign",
                        crate::runtime::err::err_reasons::CMS_R_SIGNFINAL_ERROR,
                    )
                };
                // SAFETY: `sig` is owned here.
                unsafe { CRYPTO_free(sig.cast(), c"cms_sd.c".as_ptr(), 818) };
                break 'body;
            }
            // SAFETY: `si` is live.
            unsafe { ASN1_STRING_set0((*si).signature, sig.cast(), siglen as c_int) };
        }
        r = 1;
    }
    // SAFETY: `mctx` is owned here; `pctx` NULL or owned.
    unsafe {
        EVP_MD_CTX_free(mctx);
        EVP_PKEY_CTX_free(pctx);
    }
    r
}

/// `int ossl_cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain,`
/// `const unsigned char *precomp_md, unsigned int precomp_mdlen)` — `cms_sd.c:832-849`.
///
/// # Safety
/// `cms`/`chain` are live.
pub(crate) unsafe extern "C" fn ossl_cms_SignedData_final(
    cms: *mut CmsContentInfo,
    chain: *mut Bio,
    precomp_md: *const c_uchar,
    precomp_mdlen: c_uint,
) -> c_int {
    // SAFETY: `cms` is live.
    let sinfos = unsafe { CMS_get0_SignerInfos(cms) };
    // SAFETY: `sinfos` is a live stack.
    let n = unsafe { OPENSSL_sk_num(sinfos) };
    for i in 0..n {
        // SAFETY: `i` is within range.
        let si = unsafe { OPENSSL_sk_value(sinfos, i).cast::<CmsSignerInfo>() };
        // SAFETY: all live.
        if unsafe { cms_SignerInfo_content_sign(cms, si, chain, precomp_md, precomp_mdlen) } == 0 {
            return 0;
        }
    }
    // SAFETY: `cms` is live.
    unsafe { (*(*(*cms).d.cast::<CmsSignedData>()).encap_content_info).partial = 0 };
    1
}

/// `int CMS_SignerInfo_sign(CMS_SignerInfo *si)` — `cms_sd.c:851-923`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_sign(si: *mut CmsSignerInfo) -> c_int {
    // SAFETY: `si` is live.
    let mctx = unsafe { (*si).mctx.cast::<EvpMdCtx>() };
    let mut pctx: *mut EvpPkeyCtx = ptr::null_mut();
    let mut abuf: *mut c_uchar = ptr::null_mut();
    // SAFETY: `si` is live.
    let ctx = unsafe { (*si).cms_ctx };
    let mut md_name_buf = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `si` is live; `md_name_buf` writable.
    if unsafe {
        OBJ_obj2txt(
            md_name_buf.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*(*si).digest_algorithm).algorithm,
            0,
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `si` is live.
    let md_name = if unsafe { cms_signature_nomd((*si).pkey) } != 0 {
        ptr::null()
    } else {
        md_name_buf.as_ptr()
    };
    // SAFETY: `si` is live.
    if unsafe { (*si).omit_signing_time } == 0
        // SAFETY: `si` is live.
        && unsafe { CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) } < 0
        // SAFETY: `si` is live.
        && unsafe { cms_add1_signingTime(si, ptr::null_mut()) } == 0
    {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(870, c"CMS_SignerInfo_sign", ERR_R_CMS_LIB) };
        return 0;
    }
    // SAFETY: `si` is live.
    if unsafe { ossl_cms_si_check_attributes(si) } == 0 {
        return 0;
    }
    // SAFETY: `si` is live.
    if unsafe { !(*si).pctx.is_null() } {
        // SAFETY: `si` is live.
        pctx = unsafe { (*si).pctx.cast() };
    } else {
        // SAFETY: `mctx` is live.
        unsafe { EVP_MD_CTX_reset(mctx) };
        // SAFETY: `mctx`/`si`/`ctx` are live.
        if unsafe {
            EVP_DigestSignInit_ex(
                mctx,
                &mut pctx,
                md_name,
                ossl_cms_ctx_get0_libctx(ctx),
                ossl_cms_ctx_get0_propq(ctx),
                (*si).pkey,
                ptr::null(),
            )
        } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(885, c"CMS_SignerInfo_sign", ERR_R_EVP_LIB) };
            return 0;
        }
        // SAFETY: `mctx` is live.
        unsafe {
            EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX);
            (*si).pctx = pctx.cast();
        }
    }
    if md_name.is_null() {
        // SAFETY: `mctx`/`si` are live.
        if unsafe {
            ASN1_item_sign_ctx(
                cms_attributes_sign_it(),
                ptr::null_mut(),
                ptr::null_mut(),
                (*si).signature,
                (*si).signed_attrs.cast(),
                mctx,
            )
        } <= 0
        {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(894, c"CMS_SignerInfo_sign", ERR_R_CMS_LIB) };
            return 0;
        }
        return 1;
    }
    // SAFETY: `si` is live.
    let alen = unsafe {
        ASN1_item_i2d(
            (*si).signed_attrs.cast(),
            &mut abuf,
            cms_attributes_sign_it(),
        )
    };
    let mut siglen: usize = 0;
    'body: {
        if alen < 0 || abuf.is_null() {
            break 'body;
        }
        // SAFETY: `mctx`/`abuf` are live.
        if unsafe { EVP_DigestSignUpdate(mctx, abuf.cast(), alen as usize) } <= 0 {
            break 'body;
        }
        // SAFETY: `mctx` is live.
        if unsafe { EVP_DigestSignFinal(mctx, ptr::null_mut(), &mut siglen) } <= 0 {
            break 'body;
        }
        // SAFETY: `abuf` is owned here.
        unsafe { CRYPTO_free(abuf.cast(), c"cms_sd.c".as_ptr(), 906) };
        abuf = CRYPTO_malloc(siglen, c"cms_sd.c".as_ptr(), 907).cast::<c_uchar>();
        if abuf.is_null() {
            // SAFETY: `mctx` is live.
            unsafe { EVP_MD_CTX_reset(mctx) };
            return 0;
        }
        // SAFETY: `mctx`/`abuf` are live.
        if unsafe { EVP_DigestSignFinal(mctx, abuf, &mut siglen) } <= 0 {
            break 'body;
        }
        // SAFETY: `mctx` is live.
        unsafe { EVP_MD_CTX_reset(mctx) };
        // SAFETY: `si` is live.
        unsafe { ASN1_STRING_set0((*si).signature, abuf.cast(), siglen as c_int) };
        return 1;
    }
    // SAFETY: `abuf` is NULL or owned.
    unsafe {
        CRYPTO_free(abuf.cast(), c"cms_sd.c".as_ptr(), 920);
        EVP_MD_CTX_reset(mctx);
    }
    0
}

/// `int CMS_SignerInfo_verify(CMS_SignerInfo *si)` — `cms_sd.c:925-1009`.
///
/// # Safety
/// `si` is live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_verify(si: *mut CmsSignerInfo) -> c_int {
    // SAFETY: `si` is live.
    let mut mctx: *mut EvpMdCtx = ptr::null_mut();
    let mut abuf: *mut c_uchar = ptr::null_mut();
    let mut r = -1;
    // SAFETY: `si` is live.
    let ctx = unsafe { (*si).cms_ctx };
    // SAFETY: `si` is live.
    if unsafe { (*si).pkey.is_null() } {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                938,
                c"CMS_SignerInfo_verify",
                crate::runtime::err::err_reasons::CMS_R_NO_PUBLIC_KEY,
            )
        };
        return -1;
    }
    // SAFETY: `si` is live.
    if unsafe { ossl_cms_si_check_attributes(si) } == 0 {
        return -1;
    }
    // SAFETY: `si` is live.
    if unsafe { cms_signature_nomd((*si).pkey) } != 0 {
        // SAFETY: `si` is live.
        let r = unsafe {
            ASN1_item_verify_ex(
                cms_attributes_sign_it(),
                (*si).signature_algorithm,
                (*si).signature,
                (*si).signed_attrs.cast(),
                ptr::null(),
                (*si).pkey,
                ossl_cms_ctx_get0_libctx(ctx),
                ossl_cms_ctx_get0_propq(ctx),
            )
        };
        if r <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    951,
                    c"CMS_SignerInfo_verify",
                    crate::runtime::err::err_reasons::CMS_R_VERIFICATION_FAILURE,
                )
            };
        }
        return r;
    }
    let mut name = [0 as c_char; OSSL_MAX_NAME_SIZE];
    // SAFETY: `si` is live; `name` writable.
    unsafe {
        OBJ_obj2txt(
            name.as_mut_ptr(),
            OSSL_MAX_NAME_SIZE as c_int,
            (*(*si).digest_algorithm).algorithm,
            0,
        )
    };
    // SAFETY: `ctx` is live.
    let fetched = unsafe {
        EVP_MD_fetch(
            ossl_cms_ctx_get0_libctx(ctx),
            name.as_ptr(),
            ossl_cms_ctx_get0_propq(ctx),
        )
    };
    let md = if !fetched.is_null() {
        fetched
    } else {
        // SAFETY: `si` is live.
        unsafe {
            EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid((*(*si).digest_algorithm).algorithm)))
        }
    };
    if md.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                966,
                c"CMS_SignerInfo_verify",
                crate::runtime::err::err_reasons::CMS_R_UNKNOWN_DIGEST_ALGORITHM,
            )
        };
        // SAFETY: `fetched` is NULL.
        unsafe { EVP_MD_free(fetched) };
        return -1;
    }
    // SAFETY: `si` is live.
    if unsafe { (*si).mctx.is_null() } {
        // SAFETY: the allocator answers a fresh context.
        let nm = EVP_MD_CTX_new();
        if nm.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe { raise_cms(973, c"CMS_SignerInfo_verify", ERR_R_EVP_LIB) };
            // SAFETY: `fetched` is owned.
            unsafe { EVP_MD_free(fetched) };
            return -1;
        }
        // SAFETY: `si` is live.
        unsafe { (*si).mctx = nm.cast() };
    }
    // SAFETY: `si` is live.
    mctx = unsafe { (*si).mctx.cast() };
    // SAFETY: `si` is live.
    if unsafe { !(*si).pctx.is_null() } {
        // SAFETY: `si` is live.
        unsafe {
            EVP_PKEY_CTX_free((*si).pctx.cast());
            (*si).pctx = ptr::null_mut();
        }
    }
    'body: {
        // SAFETY: `mctx`/`si`/`ctx` are live.
        if unsafe {
            EVP_DigestVerifyInit_ex(
                mctx,
                ptr::addr_of_mut!((*si).pctx).cast(),
                EVP_MD_get0_name(md),
                ossl_cms_ctx_get0_libctx(ctx),
                ossl_cms_ctx_get0_propq(ctx),
                (*si).pkey,
                ptr::null(),
            )
        } <= 0
        {
            // SAFETY: `si` is live.
            unsafe { (*si).pctx = ptr::null_mut() };
            break 'body;
        }
        // SAFETY: `mctx` is live.
        unsafe { EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX) };
        // SAFETY: `si` is live.
        if unsafe { cms_sd_asn1_ctrl(si, 1) } == 0 {
            break 'body;
        }
        // SAFETY: `si` is live.
        let alen = unsafe {
            ASN1_item_i2d(
                (*si).signed_attrs.cast(),
                &mut abuf,
                cms_attributes_verify_it(),
            )
        };
        if abuf.is_null() || alen < 0 {
            break 'body;
        }
        // SAFETY: `mctx`/`abuf` are live.
        r = unsafe { EVP_DigestVerifyUpdate(mctx, abuf.cast(), alen as usize) };
        // SAFETY: `abuf` is owned here.
        unsafe { CRYPTO_free(abuf.cast(), c"cms_sd.c".as_ptr(), 996) };
        abuf = ptr::null_mut();
        if r <= 0 {
            r = -1;
            break 'body;
        }
        // SAFETY: `mctx`/`si` are live.
        r = unsafe {
            EVP_DigestVerifyFinal(
                mctx,
                (*(*si).signature).data,
                (*(*si).signature).length as usize,
            )
        };
        if r <= 0 {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    1004,
                    c"CMS_SignerInfo_verify",
                    crate::runtime::err::err_reasons::CMS_R_VERIFICATION_FAILURE,
                )
            };
        }
    }
    // SAFETY: `fetched` is NULL or owned; `mctx` is live.
    unsafe {
        EVP_MD_free(fetched);
        EVP_MD_CTX_reset(mctx);
    }
    r
}

/// `BIO *ossl_cms_SignedData_init_bio(CMS_ContentInfo *cms)` — `cms_sd.c:1012-1041`.
///
/// # Safety
/// `cms` is live.
pub(crate) unsafe extern "C" fn ossl_cms_SignedData_init_bio(cms: *mut CmsContentInfo) -> *mut Bio {
    // SAFETY: `cms` is live.
    let sd = unsafe { cms_get0_signed(cms) };
    if sd.is_null() {
        return ptr::null_mut();
    }
    let mut chain: *mut Bio = ptr::null_mut();
    // SAFETY: `cms`/`sd` are live.
    unsafe {
        if (*(*sd).encap_content_info).partial != 0 {
            cms_sd_set_version(sd);
        }
        let n = OPENSSL_sk_num((*sd).digest_algorithms);
        for i in 0..n {
            let digest_algorithm = OPENSSL_sk_value((*sd).digest_algorithms, i).cast::<X509Algor>();
            let mdbio =
                ossl_cms_DigestAlgorithm_init_bio(digest_algorithm, ossl_cms_get0_cmsctx(cms));
            if mdbio.is_null() {
                crate::runtime::bio::BIO_free_all(chain);
                return ptr::null_mut();
            }
            if !chain.is_null() {
                BIO_push(chain, mdbio);
            } else {
                chain = mdbio;
            }
        }
    }
    chain
}

/// `int CMS_SignerInfo_verify_content(CMS_SignerInfo *si, BIO *chain)` — `cms_sd.c:1043-1119`.
///
/// # Safety
/// `si`/`chain` are live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignerInfo_verify_content(
    si: *mut CmsSignerInfo,
    chain: *mut Bio,
) -> c_int {
    // SAFETY: the allocator answers a fresh context.
    let mctx = EVP_MD_CTX_new();
    // SAFETY: `si` is live.
    let ctx = unsafe { (*si).cms_ctx };
    if mctx.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(1053, c"CMS_SignerInfo_verify_content", ERR_R_EVP_LIB) };
        return -1;
    }
    let mut r = -1;
    let mut os: *mut Asn1String = ptr::null_mut();
    let mut pkctx: *mut EvpPkeyCtx = ptr::null_mut();
    // SAFETY: `si` is live.
    if unsafe { CMS_signed_get_attr_count(si) } >= 0 {
        // SAFETY: `si` is live.
        os = unsafe {
            CMS_signed_get0_data_by_OBJ(
                si,
                OBJ_nid2obj(NID_pkcs9_messageDigest),
                -3,
                V_ASN1_OCTET_STRING,
            )
        }
        .cast();
        if os.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                raise_cms(
                    1062,
                    c"CMS_SignerInfo_verify_content",
                    crate::runtime::err::err_reasons::CMS_R_ERROR_READING_MESSAGEDIGEST_ATTRIBUTE,
                )
            };
            // SAFETY: `mctx` is owned.
            unsafe { EVP_MD_CTX_free(mctx) };
            return -1;
        }
    }
    // SAFETY: `mctx`/`chain`/`si` are live.
    if unsafe { ossl_cms_DigestAlgorithm_find_ctx(mctx, chain, (*si).digest_algorithm) } == 0 {
        // SAFETY: `mctx` is owned.
        unsafe { EVP_MD_CTX_free(mctx) };
        return -1;
    }
    let mut mval = [0u8; EVP_MAX_MD_SIZE];
    let mut mlen: c_uint = 0;
    // SAFETY: `mctx`/`mval` are live.
    if unsafe { EVP_DigestFinal_ex(mctx, mval.as_mut_ptr(), &mut mlen) } <= 0 {
        // SAFETY: the site is a compile-time constant.
        unsafe {
            raise_cms(
                1071,
                c"CMS_SignerInfo_verify_content",
                crate::runtime::err::err_reasons::CMS_R_UNABLE_TO_FINALIZE_CONTEXT,
            )
        };
        // SAFETY: `mctx` is owned here.
        unsafe { EVP_MD_CTX_free(mctx) };
        return -1;
    }
    'body: {
        if !os.is_null() {
            // SAFETY: `os` is live.
            if mlen != unsafe { (*os).length } as c_uint {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        1078,
                        c"CMS_SignerInfo_verify_content",
                        crate::runtime::err::err_reasons::CMS_R_MESSAGEDIGEST_ATTRIBUTE_WRONG_LENGTH,
                    )
                };
                break 'body;
            }
            // SAFETY: `os` is live and `mval` holds `mlen` bytes.
            let cmp = unsafe { core::slice::from_raw_parts(mval.as_ptr(), mlen as usize) }
                == unsafe { core::slice::from_raw_parts((*os).data, mlen as usize) };
            if !cmp {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        1083,
                        c"CMS_SignerInfo_verify_content",
                        crate::runtime::err::err_reasons::CMS_R_VERIFICATION_FAILURE,
                    )
                };
                r = 0;
            } else {
                r = 1;
            }
        } else {
            // SAFETY: `mctx` is live.
            let md = unsafe { EVP_MD_CTX_get0_md(mctx) };
            // SAFETY: `si`/`ctx` are live.
            pkctx = unsafe {
                EVP_PKEY_CTX_new_from_pkey(
                    ossl_cms_ctx_get0_libctx(ctx),
                    (*si).pkey,
                    ossl_cms_ctx_get0_propq(ctx),
                )
            };
            if pkctx.is_null() {
                break 'body;
            }
            // SAFETY: `pkctx` is live.
            if unsafe { EVP_PKEY_verify_init(pkctx) } <= 0 {
                break 'body;
            }
            // SAFETY: `pkctx`/`md` are live.
            if unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, md) } <= 0 {
                break 'body;
            }
            // SAFETY: `si` is live.
            unsafe { (*si).pctx = pkctx.cast() };
            // SAFETY: `si` is live.
            if unsafe { cms_sd_asn1_ctrl(si, 1) } == 0 {
                // SAFETY: `si` is live.
                unsafe { (*si).pctx = ptr::null_mut() };
                break 'body;
            }
            // SAFETY: `si` is live.
            unsafe { (*si).pctx = ptr::null_mut() };
            // SAFETY: `pkctx`/`si` are live.
            r = unsafe {
                EVP_PKEY_verify(
                    pkctx,
                    (*(*si).signature).data,
                    (*(*si).signature).length as usize,
                    mval.as_ptr(),
                    mlen as usize,
                )
            };
            if r <= 0 {
                // SAFETY: the site is a compile-time constant.
                unsafe {
                    raise_cms(
                        1110,
                        c"CMS_SignerInfo_verify_content",
                        crate::runtime::err::err_reasons::CMS_R_VERIFICATION_FAILURE,
                    )
                };
                r = 0;
            }
        }
    }
    // SAFETY: `pkctx` NULL or owned; `mctx` owned.
    unsafe {
        EVP_PKEY_CTX_free(pkctx);
        EVP_MD_CTX_free(mctx);
    }
    r
}

/// `BIO *CMS_SignedData_verify(CMS_SignedData *sd, BIO *detached_data, STACK_OF(X509) *scerts,`
/// `X509_STORE *store, STACK_OF(X509) *extra, STACK_OF(X509_CRL) *crls, unsigned int flags,`
/// `OSSL_LIB_CTX *libctx, const char *propq)` — `cms_sd.c:1121-1160`.
///
/// # Safety
/// `sd` is live; the stacks are NULL or live.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignedData_verify(
    sd: *mut CmsSignedData,
    detached_data: *mut Bio,
    scerts: *mut OpenSslStack,
    store: *mut X509Store,
    extra: *mut OpenSslStack,
    crls: *mut OpenSslStack,
    flags: c_uint,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Bio {
    if sd.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_cms(1132, c"CMS_SignedData_verify", ERR_R_PASSED_NULL_PARAMETER) };
        return ptr::null_mut();
    }
    // SAFETY: the caller's contract.
    let ci = unsafe { CMS_ContentInfo_new_ex(libctx, propq) };
    if ci.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ci` is live.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    let mut res = 0;
    if bio.is_null() {
        // SAFETY: `ci` is live.
        unsafe { CMS_ContentInfo_free(ci) };
        return ptr::null_mut();
    }
    // SAFETY: `ci` is live.
    unsafe {
        (*ci).content_type = OBJ_nid2obj(crate::runtime::obj::NID_pkcs7_signed);
        (*ci).d = sd.cast();
        let n = OPENSSL_sk_num(extra);
        for i in 0..n {
            if CMS_add1_cert(ci, OPENSSL_sk_value(extra, i).cast()) == 0 {
                (*ci).d = ptr::null_mut();
                (*ci).content_type = ptr::null_mut();
                CMS_ContentInfo_free(ci);
                crate::runtime::bio::BIO_free(bio);
                return ptr::null_mut();
            }
        }
        let n = OPENSSL_sk_num(crls);
        for i in 0..n {
            if CMS_add1_crl(ci, OPENSSL_sk_value(crls, i).cast()) == 0 {
                (*ci).d = ptr::null_mut();
                (*ci).content_type = ptr::null_mut();
                CMS_ContentInfo_free(ci);
                crate::runtime::bio::BIO_free(bio);
                return ptr::null_mut();
            }
        }
        res = super::cms_smime::CMS_verify(ci, scerts, store, detached_data, bio, flags);
        (*ci).d = ptr::null_mut();
        CMS_ContentInfo_free(ci);
    }
    if res == 0 {
        // SAFETY: `bio` is owned here.
        unsafe { crate::runtime::bio::BIO_free(bio) };
        return ptr::null_mut();
    }
    bio
}

/// `int CMS_add_smimecap(CMS_SignerInfo *si, STACK_OF(X509_ALGOR) *algs)` — `cms_sd.c:1162-1174`.
///
/// # Safety
/// `si` is live; `algs` is NULL or live.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add_smimecap(
    si: *mut CmsSignerInfo,
    algs: *mut OpenSslStack,
) -> c_int {
    // SAFETY: `algs` is NULL or live.
    let mut smder: *mut c_uchar = ptr::null_mut();
    // SAFETY: the caller's contract.
    let smderlen = unsafe { crate::asn1::x_algor::i2d_X509_ALGORS(algs, &mut smder) };
    if smderlen <= 0 {
        return 0;
    }
    // SAFETY: `si`/`smder` are live.
    let r = unsafe {
        CMS_signed_add1_attr_by_NID(
            si,
            NID_SMIMECapabilities,
            V_ASN1_SEQUENCE,
            smder.cast(),
            smderlen,
        )
    };
    // SAFETY: `smder` is owned here.
    unsafe { CRYPTO_free(smder.cast(), c"cms_sd.c".as_ptr(), 1172) };
    r
}

/// `int CMS_add_simple_smimecap(STACK_OF(X509_ALGOR) **algs, int algnid, int keysize)` —
/// `cms_sd.c:1176-1202`.
///
/// # Safety
/// `algs` is writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add_simple_smimecap(
    algs: *mut *mut OpenSslStack,
    algnid: c_int,
    keysize: c_int,
) -> c_int {
    let mut key: *mut Asn1String = ptr::null_mut();
    if keysize > 0 {
        // SAFETY: the allocator answers a fresh value.
        key = crate::asn1::string::ASN1_STRING_type_new(V_ASN1_INTEGER);
        if key.is_null()
            // SAFETY: `key` is live; `keysize` is a scalar.
            || unsafe { crate::asn1::prim::ASN1_INTEGER_set(key, keysize as c_long) } == 0
        {
            // SAFETY: `key` is NULL or owned.
            unsafe { ASN1_STRING_free(key) };
            return 0;
        }
    }
    // SAFETY: `key` is NULL or live.
    let alg = unsafe {
        ossl_X509_ALGOR_from_nid(
            algnid,
            if !key.is_null() {
                crate::asn1::layout::V_ASN1_INTEGER
            } else {
                V_ASN1_UNDEF
            },
            key.cast(),
        )
    };
    if alg.is_null() {
        // SAFETY: `key` is NULL or owned.
        unsafe { ASN1_STRING_free(key) };
        return 0;
    }
    // SAFETY: `algs` is writable.
    unsafe {
        if (*algs).is_null() {
            *algs = OPENSSL_sk_new_null();
        }
        if (*algs).is_null() || OPENSSL_sk_push(*algs, alg.cast()) == 0 {
            X509_ALGOR_free(alg);
            return 0;
        }
    }
    1
}

/// `int cms_add_cipher_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)` — `cms_sd.c:1205-1210`.
///
/// # Safety
/// `sk` is writable.
unsafe fn cms_add_cipher_smcap(sk: *mut *mut OpenSslStack, nid: c_int, arg: c_int) -> c_int {
    // SAFETY: `nid` names the cipher.
    let c = unsafe { EVP_get_cipherbyname(OBJ_nid2sn(nid)) };
    if !c.is_null() {
        // SAFETY: `sk` is writable.
        return unsafe { CMS_add_simple_smimecap(sk, nid, arg) };
    }
    1
}

/// `int cms_add_digest_smcap(STACK_OF(X509_ALGOR) **sk, int nid, int arg)` — `cms_sd.c:1212-1217`.
///
/// # Safety
/// `sk` is writable.
unsafe fn cms_add_digest_smcap(sk: *mut *mut OpenSslStack, nid: c_int, arg: c_int) -> c_int {
    // SAFETY: `nid` names the digest.
    let d = unsafe { EVP_get_digestbyname(OBJ_nid2sn(nid)) };
    if !d.is_null() {
        // SAFETY: `sk` is writable.
        return unsafe { CMS_add_simple_smimecap(sk, nid, arg) };
    }
    1
}

/// `int CMS_add_standard_smimecap(STACK_OF(X509_ALGOR) **smcap)` — `cms_sd.c:1219-1235`.
///
/// # Safety
/// `smcap` is writable.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_add_standard_smimecap(smcap: *mut *mut OpenSslStack) -> c_int {
    // SAFETY: each helper is called with the caller's slot.
    unsafe {
        if cms_add_cipher_smcap(smcap, NID_aes_256_cbc, -1) == 0
            || cms_add_digest_smcap(smcap, NID_id_GostR3411_2012_256, -1) == 0
            || cms_add_digest_smcap(smcap, NID_id_GostR3411_2012_512, -1) == 0
            || cms_add_digest_smcap(smcap, NID_id_GostR3411_94, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_id_Gost28147_89, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_aes_192_cbc, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_aes_128_cbc, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_des_ede3_cbc, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_rc2_cbc, 128) == 0
            || cms_add_cipher_smcap(smcap, NID_rc2_cbc, 64) == 0
            || cms_add_cipher_smcap(smcap, NID_des_cbc, -1) == 0
            || cms_add_cipher_smcap(smcap, NID_rc2_cbc, 40) == 0
        {
            return 0;
        }
    }
    1
}

/// The `void (*)(void *)` shape `OPENSSL_sk_pop_free` takes for [`X509_ALGOR_free`].
unsafe extern "C" fn x509_algor_free_void(p: *mut c_void) {
    // SAFETY: `p` is an `X509_ALGOR` per the stack's element type.
    unsafe { X509_ALGOR_free(p.cast()) };
}
