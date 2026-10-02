//! `crypto/cms/cms_asn1.c` — the `CMS` object model's item groups. Phase 12.3.
//!
//! Every struct is the authority's `cms_local.h` spelling in its order; every template is its
//! `ASN1_SEQUENCE`/`ASN1_CHOICE`/`ASN1_ADB` macro expanded by hand. Three accessors are exports
//! (`CMS_ContentInfo_it`, `CMS_EnvelopedData_it`, `CMS_ReceiptRequest_it`); the rest are
//! crate-internal and named `cms_<type>_it` so the modules that build a value by `ASN1_item_new`
//! reach them by path.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
//! **Why the dead-code lint is off for this module.** Like `asn1/layout.rs`, this file is a
//! projection of the authority's `cms_asn1.c`: the item groups the exported surface does not yet
//! reach are the part of the contract the later subphases read, not dead code.
#![allow(dead_code, non_snake_case)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::evp::cipher_ctx::{EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_flags};
use crate::evp::digest::EVP_MD_CTX_free;
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::evp::pkey_ctx::EVP_PKEY_CTX_free;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    Asn1Object, NID_id_smime_ct_authData, NID_id_smime_ct_authEnvelopedData,
    NID_id_smime_ct_compressedData, NID_id_smime_ori_kem, NID_pkcs7_data, NID_pkcs7_digest,
    NID_pkcs7_encrypted, NID_pkcs7_enveloped, NID_pkcs7_signed,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::GENERAL_NAMES_it;
use crate::x509::x_attrib::X509_ATTRIBUTE_it;
use crate::x509::x_crl::X509_CRL_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_x509::{X509_it, X509};

use super::cms_io::CMS_stream;
use super::cms_lib::{CMS_dataFinal, CMS_dataInit};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/cms/cms_asn1.c";

// The type-choice selectors, from `cms_local.h`.
pub(crate) const CMS_SIGNERINFO_ISSUER_SERIAL: c_int = 0;
pub(crate) const CMS_SIGNERINFO_KEYIDENTIFIER: c_int = 1;
pub(crate) const CMS_RECIPINFO_ISSUER_SERIAL: c_int = 0;
pub(crate) const CMS_RECIPINFO_KEYIDENTIFIER: c_int = 1;
pub(crate) const CMS_REK_ISSUER_SERIAL: c_int = 0;
pub(crate) const CMS_REK_KEYIDENTIFIER: c_int = 1;
pub(crate) const CMS_OIK_ISSUER_SERIAL: c_int = 0;
pub(crate) const CMS_OIK_KEYIDENTIFIER: c_int = 1;
pub(crate) const CMS_OIK_PUBKEY: c_int = 2;

pub(crate) const CMS_CERTCHOICE_CERT: c_int = 0;
pub(crate) const CMS_CERTCHOICE_EXCERT: c_int = 1;
pub(crate) const CMS_CERTCHOICE_V1ACERT: c_int = 2;
pub(crate) const CMS_CERTCHOICE_V2ACERT: c_int = 3;
pub(crate) const CMS_CERTCHOICE_OTHER: c_int = 4;

pub(crate) const CMS_REVCHOICE_CRL: c_int = 0;
pub(crate) const CMS_REVCHOICE_OTHER: c_int = 1;

// `CMS_RecipientInfo` internal types — `include/openssl/cms.h.in`.
pub(crate) const CMS_RECIPINFO_NONE: c_int = -1;
pub(crate) const CMS_RECIPINFO_TRANS: c_int = 0;
pub(crate) const CMS_RECIPINFO_AGREE: c_int = 1;
pub(crate) const CMS_RECIPINFO_KEK: c_int = 2;
pub(crate) const CMS_RECIPINFO_PASS: c_int = 3;
pub(crate) const CMS_RECIPINFO_OTHER: c_int = 4;
pub(crate) const CMS_RECIPINFO_KEM: c_int = 5;

// ---------------------------------------------------------------------------------------------
// The structures
// ---------------------------------------------------------------------------------------------

/// `CMS_CTX` — `cms_local.h:47-50`.
#[repr(C)]
pub(crate) struct CmsCtx {
    pub(crate) libctx: *mut c_void,
    pub(crate) propq: *mut c_char,
}

/// `CMS_ContentInfo` — `cms_local.h:52-68`. The `d` union is at offset 8; every arm is a pointer.
#[repr(C)]
pub(crate) struct CmsContentInfo {
    pub(crate) content_type: *mut Asn1Object,
    pub(crate) d: *mut c_void,
    pub(crate) ctx: CmsCtx,
}

/// `CMS_SignedData` — `cms_local.h:72-79`.
#[repr(C)]
pub(crate) struct CmsSignedData {
    pub(crate) version: i32,
    pub(crate) digest_algorithms: *mut OpenSslStack,
    pub(crate) encap_content_info: *mut CmsEncapsulatedContentInfo,
    pub(crate) certificates: *mut OpenSslStack,
    pub(crate) crls: *mut OpenSslStack,
    pub(crate) signer_infos: *mut OpenSslStack,
}

/// `CMS_EncapsulatedContentInfo` — `cms_local.h:81-86`.
#[repr(C)]
pub(crate) struct CmsEncapsulatedContentInfo {
    pub(crate) e_content_type: *mut Asn1Object,
    pub(crate) e_content: *mut Asn1String,
    pub(crate) partial: c_int,
}

/// `CMS_SignerInfo` — `cms_local.h:88-105`.
#[repr(C)]
pub(crate) struct CmsSignerInfo {
    pub(crate) version: i32,
    pub(crate) sid: *mut CmsSignerIdentifier,
    pub(crate) digest_algorithm: *mut X509Algor,
    pub(crate) signed_attrs: *mut OpenSslStack,
    pub(crate) signature_algorithm: *mut X509Algor,
    pub(crate) signature: *mut Asn1String,
    pub(crate) unsigned_attrs: *mut OpenSslStack,
    pub(crate) signer: *mut X509,
    pub(crate) pkey: *mut EvpPkey,
    pub(crate) mctx: *mut c_void,
    pub(crate) pctx: *mut c_void,
    pub(crate) cms_ctx: *const CmsCtx,
    pub(crate) omit_signing_time: c_int,
}

/// `CMS_SignerIdentifier` — `cms_local.h:107-113`.
#[repr(C)]
pub(crate) struct CmsSignerIdentifier {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_IssuerAndSerialNumber` — `cms_local.h:364-367`.
#[repr(C)]
pub(crate) struct CmsIssuerAndSerialNumber {
    pub(crate) issuer: *mut X509Name,
    pub(crate) serial_number: *mut Asn1String,
}

/// `CMS_EncryptedContentInfo` — `cms_local.h:128-142`.
#[repr(C)]
pub(crate) struct CmsEncryptedContentInfo {
    pub(crate) content_type: *mut Asn1Object,
    pub(crate) content_encryption_algorithm: *mut X509Algor,
    pub(crate) encrypted_content: *mut Asn1String,
    pub(crate) cipher: *const c_void,
    pub(crate) key: *mut c_uchar,
    pub(crate) keylen: usize,
    pub(crate) tag: *mut c_uchar,
    pub(crate) taglen: usize,
    pub(crate) debug: c_int,
    pub(crate) havenocert: c_int,
}

/// `CMS_EnvelopedData` — `cms_local.h:115-121`.
#[repr(C)]
pub(crate) struct CmsEnvelopedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut CmsOriginatorInfo,
    pub(crate) recipient_infos: *mut OpenSslStack,
    pub(crate) encrypted_content_info: *mut CmsEncryptedContentInfo,
    pub(crate) unprotected_attrs: *mut OpenSslStack,
}

/// `CMS_OriginatorInfo` — `cms_local.h:123-126`.
#[repr(C)]
pub(crate) struct CmsOriginatorInfo {
    pub(crate) certificates: *mut OpenSslStack,
    pub(crate) crls: *mut OpenSslStack,
}

/// `CMS_DigestedData` — `cms_local.h:279-284`.
#[repr(C)]
pub(crate) struct CmsDigestedData {
    pub(crate) version: i32,
    pub(crate) digest_algorithm: *mut X509Algor,
    pub(crate) encap_content_info: *mut CmsEncapsulatedContentInfo,
    pub(crate) digest: *mut Asn1String,
}

/// `CMS_EncryptedData` — `cms_local.h:286-290`.
#[repr(C)]
pub(crate) struct CmsEncryptedData {
    pub(crate) version: i32,
    pub(crate) encrypted_content_info: *mut CmsEncryptedContentInfo,
    pub(crate) unprotected_attrs: *mut OpenSslStack,
}

/// `CMS_AuthenticatedData` — `cms_local.h:292-302`.
#[repr(C)]
pub(crate) struct CmsAuthenticatedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut CmsOriginatorInfo,
    pub(crate) recipient_infos: *mut OpenSslStack,
    pub(crate) mac_algorithm: *mut X509Algor,
    pub(crate) digest_algorithm: *mut X509Algor,
    pub(crate) encap_content_info: *mut CmsEncapsulatedContentInfo,
    pub(crate) auth_attrs: *mut OpenSslStack,
    pub(crate) mac: *mut Asn1String,
    pub(crate) unauth_attrs: *mut OpenSslStack,
}

/// `CMS_AuthEnvelopedData` — `cms_local.h:304-312`.
#[repr(C)]
pub(crate) struct CmsAuthEnvelopedData {
    pub(crate) version: i32,
    pub(crate) originator_info: *mut CmsOriginatorInfo,
    pub(crate) recipient_infos: *mut OpenSslStack,
    pub(crate) auth_encrypted_content_info: *mut CmsEncryptedContentInfo,
    pub(crate) auth_attrs: *mut OpenSslStack,
    pub(crate) mac: *mut Asn1String,
    pub(crate) unauth_attrs: *mut OpenSslStack,
}

/// `CMS_CompressedData` — `cms_local.h:314-319`.
#[repr(C)]
pub(crate) struct CmsCompressedData {
    pub(crate) version: i32,
    pub(crate) compression_algorithm: *mut X509Algor,
    pub(crate) recipient_infos: *mut OpenSslStack,
    pub(crate) encap_content_info: *mut CmsEncapsulatedContentInfo,
}

/// `CMS_RecipientInfo` — `cms_local.h:144-159`.
#[repr(C)]
pub(crate) struct CmsRecipientInfo {
    pub(crate) encoded_type: c_int,
    pub(crate) d: *mut c_void,
    pub(crate) type_: c_int,
}

/// `CMS_KeyTransRecipientInfo` — `cms_local.h:163-174`.
#[repr(C)]
pub(crate) struct CmsKeyTransRecipientInfo {
    pub(crate) version: i32,
    pub(crate) rid: *mut CmsSignerIdentifier,
    pub(crate) key_encryption_algorithm: *mut X509Algor,
    pub(crate) encrypted_key: *mut Asn1String,
    pub(crate) recip: *mut X509,
    pub(crate) pkey: *mut EvpPkey,
    pub(crate) pctx: *mut c_void,
    pub(crate) cms_ctx: *const CmsCtx,
}

/// `CMS_KeyAgreeRecipientInfo` — `cms_local.h:176-187`.
#[repr(C)]
pub(crate) struct CmsKeyAgreeRecipientInfo {
    pub(crate) version: i32,
    pub(crate) originator: *mut CmsOriginatorIdentifierOrKey,
    pub(crate) ukm: *mut Asn1String,
    pub(crate) key_encryption_algorithm: *mut X509Algor,
    pub(crate) recipient_encrypted_keys: *mut OpenSslStack,
    pub(crate) pctx: *mut c_void,
    pub(crate) ctx: *mut c_void,
    pub(crate) cms_ctx: *const CmsCtx,
}

/// `CMS_OriginatorIdentifierOrKey` — `cms_local.h:189-196`.
#[repr(C)]
pub(crate) struct CmsOriginatorIdentifierOrKey {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_OriginatorPublicKey` — `cms_local.h:198-201`.
#[repr(C)]
pub(crate) struct CmsOriginatorPublicKey {
    pub(crate) algorithm: *mut X509Algor,
    pub(crate) public_key: *mut Asn1String,
}

/// `CMS_RecipientEncryptedKey` — `cms_local.h:203-208`.
#[repr(C)]
pub(crate) struct CmsRecipientEncryptedKey {
    pub(crate) rid: *mut CmsKeyAgreeRecipientIdentifier,
    pub(crate) encrypted_key: *mut Asn1String,
    pub(crate) pkey: *mut EvpPkey,
}

/// `CMS_KeyAgreeRecipientIdentifier` — `cms_local.h:210-216`.
#[repr(C)]
pub(crate) struct CmsKeyAgreeRecipientIdentifier {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_RecipientKeyIdentifier` — `cms_local.h:218-222`.
#[repr(C)]
pub(crate) struct CmsRecipientKeyIdentifier {
    pub(crate) subject_key_identifier: *mut Asn1String,
    pub(crate) date: *mut Asn1String,
    pub(crate) other: *mut CmsOtherKeyAttribute,
}

/// `CMS_OtherKeyAttribute` — `cms_local.h:369-372`.
#[repr(C)]
pub(crate) struct CmsOtherKeyAttribute {
    pub(crate) key_attr_id: *mut Asn1Object,
    pub(crate) key_attr: *mut Asn1Type,
}

/// `CMS_KEKRecipientInfo` — `cms_local.h:224-233`.
#[repr(C)]
pub(crate) struct CmsKekRecipientInfo {
    pub(crate) version: i32,
    pub(crate) kekid: *mut CmsKekIdentifier,
    pub(crate) key_encryption_algorithm: *mut X509Algor,
    pub(crate) encrypted_key: *mut Asn1String,
    pub(crate) key: *mut c_uchar,
    pub(crate) keylen: usize,
    pub(crate) cms_ctx: *const CmsCtx,
}

/// `CMS_KEKIdentifier` — `cms_local.h:235-239`.
#[repr(C)]
pub(crate) struct CmsKekIdentifier {
    pub(crate) key_identifier: *mut Asn1String,
    pub(crate) date: *mut Asn1String,
    pub(crate) other: *mut CmsOtherKeyAttribute,
}

/// `CMS_PasswordRecipientInfo` — `cms_local.h:241-250`.
#[repr(C)]
pub(crate) struct CmsPasswordRecipientInfo {
    pub(crate) version: i32,
    pub(crate) key_derivation_algorithm: *mut X509Algor,
    pub(crate) key_encryption_algorithm: *mut X509Algor,
    pub(crate) encrypted_key: *mut Asn1String,
    pub(crate) pass: *mut c_uchar,
    pub(crate) passlen: usize,
    pub(crate) cms_ctx: *const CmsCtx,
}

/// `CMS_OtherRecipientInfo` — `cms_local.h:252-260`.
#[repr(C)]
pub(crate) struct CmsOtherRecipientInfo {
    pub(crate) ori_type: *mut Asn1Object,
    pub(crate) d: *mut c_void,
}

/// `CMS_KEMRecipientInfo` — `cms_local.h:262-277`.
#[repr(C)]
pub(crate) struct CmsKemRecipientInfo {
    pub(crate) version: i32,
    pub(crate) rid: *mut CmsSignerIdentifier,
    pub(crate) kem: *mut X509Algor,
    pub(crate) kemct: *mut Asn1String,
    pub(crate) kdf: *mut X509Algor,
    pub(crate) kek_length: u32,
    pub(crate) ukm: *mut Asn1String,
    pub(crate) wrap: *mut X509Algor,
    pub(crate) encrypted_key: *mut Asn1String,
    pub(crate) pctx: *mut c_void,
    pub(crate) ctx: *mut c_void,
    pub(crate) cms_ctx: *const CmsCtx,
}

/// `CMS_RevocationInfoChoice` — `cms_local.h:321-327`.
#[repr(C)]
pub(crate) struct CmsRevocationInfoChoice {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_OtherRevocationInfoFormat` — `cms_local.h:332-335`.
#[repr(C)]
pub(crate) struct CmsOtherRevocationInfoFormat {
    pub(crate) other_rev_info_format: *mut Asn1Object,
    pub(crate) other_rev_info: *mut Asn1Type,
}

/// `CMS_CertificateChoices` — `cms_local.h:337-346`.
#[repr(C)]
pub(crate) struct CmsCertificateChoices {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_OtherCertificateFormat` — `cms_local.h:354-357`.
#[repr(C)]
pub(crate) struct CmsOtherCertificateFormat {
    pub(crate) other_cert_format: *mut Asn1Object,
    pub(crate) other_cert: *mut Asn1Type,
}

/// `CMS_ReceiptRequest` — `cms_local.h:376-380`.
#[repr(C)]
pub(crate) struct CmsReceiptRequest {
    pub(crate) signed_content_identifier: *mut Asn1String,
    pub(crate) receipts_from: *mut CmsReceiptsFrom,
    pub(crate) receipts_to: *mut OpenSslStack,
}

/// `CMS_ReceiptsFrom` — `cms_local.h:382-388`.
#[repr(C)]
pub(crate) struct CmsReceiptsFrom {
    pub(crate) type_: c_int,
    pub(crate) d: *mut c_void,
}

/// `CMS_Receipt` — `cms_local.h:390-395`.
#[repr(C)]
pub(crate) struct CmsReceipt {
    pub(crate) version: i32,
    pub(crate) content_type: *mut Asn1Object,
    pub(crate) signed_content_identifier: *mut Asn1String,
    pub(crate) originator_signature_value: *mut Asn1String,
}

/// `CMS_SharedInfo` — `cms_asn1.c:425-429`.
#[repr(C)]
pub(crate) struct CmsSharedInfo {
    pub(crate) key_info: *mut X509Algor,
    pub(crate) entity_u_info: *mut Asn1String,
    pub(crate) supp_pub_info: *mut Asn1String,
}

/// `CMS_CMSORIforKEMOtherInfo` — `cms_asn1.c:471-475`.
#[repr(C)]
pub(crate) struct CmsOriForKemOtherInfo {
    pub(crate) wrap: *mut X509Algor,
    pub(crate) kek_length: u32,
    pub(crate) ukm: *mut Asn1String,
}

// ---------------------------------------------------------------------------------------------
// The item callbacks
// ---------------------------------------------------------------------------------------------

/// `cms_si_cb` — `cms_asn1.c:38-48`. On `FREE_POST`, release the signer key, cert and contexts.
unsafe extern "C" fn cms_si_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_POST {
        // SAFETY: `pval` is a live value slot per the callback contract.
        let si = unsafe { (*pval).cast::<CmsSignerInfo>() };
        // SAFETY: `si` is the object being freed.
        unsafe {
            EVP_PKEY_free((*si).pkey);
            crate::x509::x_x509::X509_free((*si).signer);
            EVP_MD_CTX_free((*si).mctx.cast());
            EVP_PKEY_CTX_free((*si).pctx.cast());
        }
    }
    1
}

/// `cms_ec_cb` — `cms_asn1.c:83-90`. On `FREE_POST`, clear the session key.
unsafe extern "C" fn cms_ec_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_POST {
        // SAFETY: `pval` is the object being freed.
        let ec = unsafe { (*pval).cast::<CmsEncryptedContentInfo>() };
        // SAFETY: `ec` is live; `key`/`keylen` are its own fields.
        unsafe { OPENSSL_clear_free((*ec).key, (*ec).keylen) };
    }
    1
}

/// `cms_rek_cb` — `cms_asn1.c:121-128`. On `FREE_POST`, release the recipient key.
unsafe extern "C" fn cms_rek_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_POST {
        // SAFETY: `pval` is the object being freed.
        let rek = unsafe { (*pval).cast::<CmsRecipientEncryptedKey>() };
        // SAFETY: `rek` is live.
        unsafe { EVP_PKEY_free((*rek).pkey) };
    }
    1
}

/// `cms_kari_cb` — `cms_asn1.c:146-160`. `NEW_POST` creates the wrapping cipher context;
/// `FREE_POST` releases the contexts.
unsafe extern "C" fn cms_kari_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    // SAFETY: `pval` is a live value slot per the callback contract.
    let kari = unsafe { (*pval).cast::<CmsKeyAgreeRecipientInfo>() };
    if operation == ASN1_OP_NEW_POST {
        // SAFETY: `kari` was just allocated by the item machinery.
        unsafe {
            (*kari).ctx = EVP_CIPHER_CTX_new().cast();
            if (*kari).ctx.is_null() {
                return 0;
            }
            EVP_CIPHER_CTX_set_flags((*kari).ctx.cast(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            (*kari).pctx = ptr::null_mut();
        }
    } else if operation == ASN1_OP_FREE_POST {
        // SAFETY: `kari` is live.
        unsafe {
            EVP_PKEY_CTX_free((*kari).pctx.cast());
            EVP_CIPHER_CTX_free((*kari).ctx.cast());
        }
    }
    1
}

/// `cms_kemri_cb` — `cms_asn1.c:186-203`.
unsafe extern "C" fn cms_kemri_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    // SAFETY: `pval` is a live value slot per the callback contract.
    let kemri = unsafe { (*pval).cast::<CmsKemRecipientInfo>() };
    if operation == ASN1_OP_NEW_POST {
        // SAFETY: `kemri` was just allocated.
        unsafe {
            (*kemri).ctx = EVP_CIPHER_CTX_new().cast();
            if (*kemri).ctx.is_null() {
                return 0;
            }
            EVP_CIPHER_CTX_set_flags((*kemri).ctx.cast(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            (*kemri).pctx = ptr::null_mut();
        }
    } else if operation == ASN1_OP_FREE_POST {
        // SAFETY: `kemri` is live; `ukm` is its own field.
        unsafe {
            EVP_PKEY_CTX_free((*kemri).pctx.cast());
            EVP_CIPHER_CTX_free((*kemri).ctx.cast());
            crate::asn1::string::ASN1_STRING_free((*kemri).ukm);
        }
    }
    1
}

/// `cms_ri_cb` — `cms_asn1.c:233-269`. Frees the per-arm payload on `FREE_PRE` and copies the
/// encoded type into the internal `type` on `D2I_POST`/`NEW_POST`, mapping an ORI whose OID is
/// the KEM ORI to the KEM arm.
unsafe extern "C" fn cms_ri_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    // SAFETY: `pval` is a live value slot per the callback contract.
    let ri = unsafe { (*pval).cast::<CmsRecipientInfo>() };
    if operation == ASN1_OP_FREE_PRE {
        // SAFETY: `ri` is live and `type_` selects the arm.
        unsafe {
            match (*ri).type_ {
                CMS_RECIPINFO_TRANS => {
                    let ktri = (*ri).d.cast::<CmsKeyTransRecipientInfo>();
                    EVP_PKEY_free((*ktri).pkey);
                    crate::x509::x_x509::X509_free((*ktri).recip);
                    EVP_PKEY_CTX_free((*ktri).pctx.cast());
                }
                CMS_RECIPINFO_KEK => {
                    let kekri = (*ri).d.cast::<CmsKekRecipientInfo>();
                    OPENSSL_clear_free((*kekri).key, (*kekri).keylen);
                }
                CMS_RECIPINFO_PASS => {
                    let pwri = (*ri).d.cast::<CmsPasswordRecipientInfo>();
                    OPENSSL_clear_free((*pwri).pass, (*pwri).passlen);
                }
                _ => {}
            }
        }
    } else if operation == ASN1_OP_D2I_POST {
        // SAFETY: `ri` is live; its selector field is readable.
        unsafe {
            (*ri).type_ = (*ri).encoded_type;
            if (*ri).type_ == CMS_RECIPINFO_OTHER {
                let ori = (*ri).d.cast::<CmsOtherRecipientInfo>();
                let nid = crate::runtime::obj::OBJ_obj2nid((*ori).ori_type);
                if nid == NID_id_smime_ori_kem {
                    (*ri).type_ = CMS_RECIPINFO_KEM;
                }
            }
        }
    } else if operation == ASN1_OP_NEW_POST {
        // SAFETY: `ri` was just allocated.
        unsafe { (*ri).type_ = (*ri).encoded_type };
    }
    1
}

/// `cms_cb` — `cms_asn1.c:347-379`. The streaming encoder's four arms call
/// [`CMS_stream`], [`CMS_dataInit`] and [`CMS_dataFinal`]; `FREE_POST` releases the property
/// query.
unsafe extern "C" fn cms_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    if pval.is_null() {
        return 1;
    }
    // SAFETY: `pval` is a live value slot per the callback contract.
    let cms = unsafe { (*pval).cast::<CmsContentInfo>() };
    // SAFETY: `exarg` is the `ASN1_STREAM_ARG` the streaming encoder passes.
    let sarg = exarg.cast::<Asn1StreamArg>();
    match operation {
        ASN1_OP_STREAM_PRE => {
            // SAFETY: `sarg` and `cms` are live.
            if unsafe { CMS_stream(ptr::addr_of_mut!((*sarg).boundary), cms) } <= 0 {
                return 0;
            }
            // SAFETY: `sarg` and `cms` are live.
            unsafe {
                (*sarg).ndef_bio = CMS_dataInit(cms, (*sarg).out);
                if (*sarg).ndef_bio.is_null() {
                    return 0;
                }
            }
        }
        ASN1_OP_DETACHED_PRE => {
            // SAFETY: `sarg` and `cms` are live.
            unsafe {
                (*sarg).ndef_bio = CMS_dataInit(cms, (*sarg).out);
                if (*sarg).ndef_bio.is_null() {
                    return 0;
                }
            }
        }
        ASN1_OP_STREAM_POST | ASN1_OP_DETACHED_POST => {
            // SAFETY: `sarg` and `cms` are live.
            if unsafe { CMS_dataFinal(cms, (*sarg).ndef_bio) } <= 0 {
                return 0;
            }
        }
        ASN1_OP_FREE_POST => {
            // SAFETY: `cms` is live and `ctx.propq` is its own allocation.
            unsafe { CRYPTO_free((*cms).ctx.propq.cast(), FILE.as_ptr(), 375) };
        }
        _ => {}
    }
    1
}

/// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW` — `crypto/evp/evp_local.h:94`.
const EVP_CIPHER_CTX_FLAG_WRAP_ALLOW: c_int = 0x1;

/// `ASN1_STREAM_ARG` — the streaming callback's argument.
#[repr(C)]
pub(crate) struct Asn1StreamArg {
    pub(crate) out: *mut Bio,
    pub(crate) boundary: *mut *mut u8,
    pub(crate) ndef_bio: *mut Bio,
}

/// `OPENSSL_clear_free` — release and zero.
///
/// # Safety
/// `ptr` is NULL or a live allocation of `len` bytes this crate owns.
#[allow(non_snake_case)] // the authority's own macro spelling (`OPENSSL_clear_free`)
pub(crate) unsafe fn OPENSSL_clear_free(ptr_: *mut c_uchar, len: usize) {
    // SAFETY: the caller's contract; `CRYPTO_clear_free` zeroes before releasing.
    unsafe { crate::runtime::mem::CRYPTO_clear_free(ptr_.cast(), len, core::ptr::null(), 0) };
}

/// The `Sync` wrapper for the `ASN1_ADB` statics, as `pk7_asn1.rs` does.
#[repr(transparent)]
struct SyncAdb(Asn1Adb);

// SAFETY: built from constants, written once by the loader, no interior mutability reachable
// through a shared reference.
unsafe impl Sync for SyncAdb {}

/// The `Sync` wrapper for the `ASN1_AUX` statics.
#[repr(transparent)]
struct SyncAux(crate::asn1::layout::Asn1Aux);

// SAFETY: built from constants, written once by the loader, no interior mutability reachable
// through a shared reference.
unsafe impl Sync for SyncAux {}

/// The `Sync` wrapper for `Asn1Template` arrays built at module scope.
#[repr(transparent)]
struct SyncTemplate([Asn1Template; 1]);

// SAFETY: the authority's templates are compile-time constants, as `layout.rs` records for
// `Asn1Template` itself.
unsafe impl Sync for SyncTemplate {}

// ---------------------------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------------------------

/// `ASN1_ITEM_ref(type)` as a template's `item` slot: the item's accessor function cast to the
/// untyped `item` pointer the engine calls. `const` so a template's `static` initialiser may
/// name it.
const fn item_ref(f: extern "C" fn() -> *const Asn1Item) -> *mut c_void {
    f as *mut c_void
}

/// `M_ASN1_new_of(type)` — allocate a value of `it`.
///
/// # Safety
/// `it` is a live item this crate owns.
pub(crate) unsafe fn m_asn1_new(it: *const Asn1Item) -> *mut c_void {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_new(it) }
}

/// `M_ASN1_free_of(value, type)`.
///
/// # Safety
/// `value` is NULL or a value `it` built; `it` is that item.
pub(crate) unsafe fn m_asn1_free(value: *mut c_void, it: *const Asn1Item) {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_free(value, it) };
}

// ---------------------------------------------------------------------------------------------
// CMS_IssuerAndSerialNumber
// ---------------------------------------------------------------------------------------------

static CMS_ISSUERANDSERIAL_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: item_ref(X509_NAME_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"serialNumber".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
];

static CMS_ISSUERANDSERIAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ISSUERANDSERIAL_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsIssuerAndSerialNumber>() as c_long,
    sname: c"CMS_IssuerAndSerialNumber".as_ptr(),
};

pub(crate) extern "C" fn cms_issuerandserial_it() -> *const Asn1Item {
    &CMS_ISSUERANDSERIAL_ITEM
}

/// `CMS_IssuerAndSerialNumber *CMS_IssuerAndSerialNumber_new(void)` — `DECLARE_ASN1_ALLOC_FUNCTIONS`
/// in `cms_local.h:408`.
///
/// # Safety
/// The returned pointer must be released with [`cms_issuerandserial_free`].
pub(crate) unsafe extern "C" fn CMS_IssuerAndSerialNumber_new() -> *mut CmsIssuerAndSerialNumber {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cms_issuerandserial_it()) }.cast()
}

/// `void CMS_IssuerAndSerialNumber_free(CMS_IssuerAndSerialNumber *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
pub(crate) unsafe extern "C" fn CMS_IssuerAndSerialNumber_free(a: *mut CmsIssuerAndSerialNumber) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cms_issuerandserial_it()) };
}

// ---------------------------------------------------------------------------------------------
// CMS_OtherCertificateFormat
// ---------------------------------------------------------------------------------------------

static CMS_OTHER_CERTIFICATE_FORMAT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"otherCertFormat".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"otherCert".as_ptr(),
        item: item_ref(ASN1_ANY_it),
    },
];

static CMS_OTHER_CERTIFICATE_FORMAT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_OTHER_CERTIFICATE_FORMAT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOtherCertificateFormat>() as c_long,
    sname: c"CMS_OtherCertificateFormat".as_ptr(),
};

pub(crate) extern "C" fn cms_othercertificateformat_it() -> *const Asn1Item {
    &CMS_OTHER_CERTIFICATE_FORMAT_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_CertificateChoices
// ---------------------------------------------------------------------------------------------

static CMS_CERTIFICATE_CHOICES_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.certificate".as_ptr(),
        item: item_ref(X509_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"d.extendedCertificate".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_SEQUENCE_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"d.v1AttrCert".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_SEQUENCE_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"d.v2AttrCert".as_ptr(),
        item: item_ref(crate::asn1::items::ASN1_SEQUENCE_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 3,
        offset: 8,
        field_name: c"d.other".as_ptr(),
        item: item_ref(cms_othercertificateformat_it),
    },
];

static CMS_CERTIFICATE_CHOICES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_CERTIFICATE_CHOICES_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsCertificateChoices>() as c_long,
    sname: c"CMS_CertificateChoices".as_ptr(),
};

pub(crate) extern "C" fn cms_certificatechoices_it() -> *const Asn1Item {
    &CMS_CERTIFICATE_CHOICES_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_SignerIdentifier
// ---------------------------------------------------------------------------------------------

static CMS_SIGNER_IDENTIFIER_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.issuerAndSerialNumber".as_ptr(),
        item: item_ref(cms_issuerandserial_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"d.subjectKeyIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_SIGNER_IDENTIFIER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_SIGNER_IDENTIFIER_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsSignerIdentifier>() as c_long,
    sname: c"CMS_SignerIdentifier".as_ptr(),
};

pub(crate) extern "C" fn cms_signeridentifier_it() -> *const Asn1Item {
    &CMS_SIGNER_IDENTIFIER_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_EncapsulatedContentInfo
// ---------------------------------------------------------------------------------------------

static CMS_ENCAPSULATED_CONTENT_INFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"eContentType".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
        tag: 0,
        offset: 8,
        field_name: c"eContent".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_NDEF_it),
    },
];

static CMS_ENCAPSULATED_CONTENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ENCAPSULATED_CONTENT_INFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsEncapsulatedContentInfo>() as c_long,
    sname: c"CMS_EncapsulatedContentInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_encapsulatedcontentinfo_it() -> *const Asn1Item {
    &CMS_ENCAPSULATED_CONTENT_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_SignerInfo
// ---------------------------------------------------------------------------------------------

static CMS_SIGNER_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_si_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_SIGNER_INFO_TT: [Asn1Template; 7] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"sid".as_ptr(),
        item: item_ref(cms_signeridentifier_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"digestAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"signedAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"signatureAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"signature".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 48,
        field_name: c"unsignedAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];

static CMS_SIGNER_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_SIGNER_INFO_TT.as_ptr(),
    tcount: 7,
    funcs: ptr::addr_of!(CMS_SIGNER_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsSignerInfo>() as c_long,
    sname: c"CMS_SignerInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_signerinfo_it() -> *const Asn1Item {
    &CMS_SIGNER_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_OtherRevocationInfoFormat / CMS_RevocationInfoChoice
// ---------------------------------------------------------------------------------------------

static CMS_OTHER_REVOCATION_INFO_FORMAT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"otherRevInfoFormat".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"otherRevInfo".as_ptr(),
        item: item_ref(ASN1_ANY_it),
    },
];

static CMS_OTHER_REVOCATION_INFO_FORMAT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_OTHER_REVOCATION_INFO_FORMAT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOtherRevocationInfoFormat>() as c_long,
    sname: c"CMS_OtherRevocationInfoFormat".as_ptr(),
};

pub(crate) extern "C" fn cms_otherrevocationinfoformat_it() -> *const Asn1Item {
    &CMS_OTHER_REVOCATION_INFO_FORMAT_ITEM
}

static CMS_REVOCATION_INFO_CHOICE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.crl".as_ptr(),
        item: item_ref(X509_CRL_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"d.other".as_ptr(),
        item: item_ref(cms_otherrevocationinfoformat_it),
    },
];

static CMS_REVOCATION_INFO_CHOICE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_REVOCATION_INFO_CHOICE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsRevocationInfoChoice>() as c_long,
    sname: c"CMS_RevocationInfoChoice".as_ptr(),
};

pub(crate) extern "C" fn cms_revocationinfochoice_it() -> *const Asn1Item {
    &CMS_REVOCATION_INFO_CHOICE_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_SignedData / CMS_OriginatorInfo
// ---------------------------------------------------------------------------------------------

static CMS_SIGNED_DATA_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"digestAlgorithms".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"encapContentInfo".as_ptr(),
        item: item_ref(cms_encapsulatedcontentinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"certificates".as_ptr(),
        item: item_ref(cms_certificatechoices_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"crls".as_ptr(),
        item: item_ref(cms_revocationinfochoice_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 40,
        field_name: c"signerInfos".as_ptr(),
        item: item_ref(cms_signerinfo_it),
    },
];

static CMS_SIGNED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_SIGNED_DATA_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsSignedData>() as c_long,
    sname: c"CMS_SignedData".as_ptr(),
};

pub(crate) extern "C" fn cms_signeddata_it() -> *const Asn1Item {
    &CMS_SIGNED_DATA_ITEM
}

/// `CMS_SignedData *CMS_SignedData_new(void)` — `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` at
/// `cms_asn1.c:76`.
#[no_mangle]
pub(crate) extern "C" fn CMS_SignedData_new() -> *mut CmsSignedData {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(cms_signeddata_it()) }.cast()
}

/// `void CMS_SignedData_free(CMS_SignedData *a)`.
///
/// # Safety
/// `a` is NULL or a value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SignedData_free(a: *mut CmsSignedData) {
    // SAFETY: `a` is NULL or a live item value.
    unsafe { ASN1_item_free(a.cast(), cms_signeddata_it()) };
}

static CMS_ORIGINATOR_INFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"certificates".as_ptr(),
        item: item_ref(cms_certificatechoices_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"crls".as_ptr(),
        item: item_ref(cms_revocationinfochoice_it),
    },
];

static CMS_ORIGINATOR_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ORIGINATOR_INFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOriginatorInfo>() as c_long,
    sname: c"CMS_OriginatorInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_originatorinfo_it() -> *const Asn1Item {
    &CMS_ORIGINATOR_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_EncryptedContentInfo
// ---------------------------------------------------------------------------------------------

static CMS_ENCRYPTED_CONTENT_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_ec_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_ENCRYPTED_CONTENT_INFO_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"contentType".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"contentEncryptionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"encryptedContent".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_NDEF_it),
    },
];

static CMS_ENCRYPTED_CONTENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ENCRYPTED_CONTENT_INFO_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::addr_of!(CMS_ENCRYPTED_CONTENT_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsEncryptedContentInfo>() as c_long,
    sname: c"CMS_EncryptedContentInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_encryptedcontentinfo_it() -> *const Asn1Item {
    &CMS_ENCRYPTED_CONTENT_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_KeyTransRecipientInfo / key-agreement helpers
// ---------------------------------------------------------------------------------------------

static CMS_KEY_TRANS_RECIPIENT_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"rid".as_ptr(),
        item: item_ref(cms_signeridentifier_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"keyEncryptionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"encryptedKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_KEY_TRANS_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_KEY_TRANS_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsKeyTransRecipientInfo>() as c_long,
    sname: c"CMS_KeyTransRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_keytransrecipientinfo_it() -> *const Asn1Item {
    &CMS_KEY_TRANS_RECIPIENT_INFO_ITEM
}

static CMS_OTHER_KEY_ATTRIBUTE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyAttrId".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"keyAttr".as_ptr(),
        item: item_ref(ASN1_ANY_it),
    },
];

static CMS_OTHER_KEY_ATTRIBUTE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_OTHER_KEY_ATTRIBUTE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOtherKeyAttribute>() as c_long,
    sname: c"CMS_OtherKeyAttribute".as_ptr(),
};

pub(crate) extern "C" fn cms_otherkeyattribute_it() -> *const Asn1Item {
    &CMS_OTHER_KEY_ATTRIBUTE_ITEM
}

static CMS_RECIPIENT_KEY_IDENTIFIER_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"subjectKeyIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"date".as_ptr(),
        item: item_ref(ASN1_GENERALIZEDTIME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"other".as_ptr(),
        item: item_ref(cms_otherkeyattribute_it),
    },
];

static CMS_RECIPIENT_KEY_IDENTIFIER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_RECIPIENT_KEY_IDENTIFIER_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsRecipientKeyIdentifier>() as c_long,
    sname: c"CMS_RecipientKeyIdentifier".as_ptr(),
};

pub(crate) extern "C" fn cms_recipientkeyidentifier_it() -> *const Asn1Item {
    &CMS_RECIPIENT_KEY_IDENTIFIER_ITEM
}

static CMS_KEY_AGREE_RECIPIENT_IDENTIFIER_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.issuerAndSerialNumber".as_ptr(),
        item: item_ref(cms_issuerandserial_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"d.rKeyId".as_ptr(),
        item: item_ref(cms_recipientkeyidentifier_it),
    },
];

static CMS_KEY_AGREE_RECIPIENT_IDENTIFIER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_KEY_AGREE_RECIPIENT_IDENTIFIER_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsKeyAgreeRecipientIdentifier>() as c_long,
    sname: c"CMS_KeyAgreeRecipientIdentifier".as_ptr(),
};

pub(crate) extern "C" fn cms_keyagreerecipientidentifier_it() -> *const Asn1Item {
    &CMS_KEY_AGREE_RECIPIENT_IDENTIFIER_ITEM
}

static CMS_RECIPIENT_ENCRYPTED_KEY_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_rek_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_RECIPIENT_ENCRYPTED_KEY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"rid".as_ptr(),
        item: item_ref(cms_keyagreerecipientidentifier_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"encryptedKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_RECIPIENT_ENCRYPTED_KEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_RECIPIENT_ENCRYPTED_KEY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::addr_of!(CMS_RECIPIENT_ENCRYPTED_KEY_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsRecipientEncryptedKey>() as c_long,
    sname: c"CMS_RecipientEncryptedKey".as_ptr(),
};

pub(crate) extern "C" fn cms_recipientencryptedkey_it() -> *const Asn1Item {
    &CMS_RECIPIENT_ENCRYPTED_KEY_ITEM
}

static CMS_ORIGINATOR_PUBLIC_KEY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"publicKey".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
];

static CMS_ORIGINATOR_PUBLIC_KEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ORIGINATOR_PUBLIC_KEY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOriginatorPublicKey>() as c_long,
    sname: c"CMS_OriginatorPublicKey".as_ptr(),
};

pub(crate) extern "C" fn cms_originatorpublickey_it() -> *const Asn1Item {
    &CMS_ORIGINATOR_PUBLIC_KEY_ITEM
}

static CMS_ORIGINATOR_IDENTIFIER_OR_KEY_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.issuerAndSerialNumber".as_ptr(),
        item: item_ref(cms_issuerandserial_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"d.subjectKeyIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"d.originatorKey".as_ptr(),
        item: item_ref(cms_originatorpublickey_it),
    },
];

static CMS_ORIGINATOR_IDENTIFIER_OR_KEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_ORIGINATOR_IDENTIFIER_OR_KEY_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOriginatorIdentifierOrKey>() as c_long,
    sname: c"CMS_OriginatorIdentifierOrKey".as_ptr(),
};

pub(crate) extern "C" fn cms_originatoridentifierorkey_it() -> *const Asn1Item {
    &CMS_ORIGINATOR_IDENTIFIER_OR_KEY_ITEM
}

static CMS_KEY_AGREE_RECIPIENT_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_kari_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_KEY_AGREE_RECIPIENT_INFO_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"originator".as_ptr(),
        item: item_ref(cms_originatoridentifierorkey_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 16,
        field_name: c"ukm".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"keyEncryptionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 32,
        field_name: c"recipientEncryptedKeys".as_ptr(),
        item: item_ref(cms_recipientencryptedkey_it),
    },
];

static CMS_KEY_AGREE_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_KEY_AGREE_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::addr_of!(CMS_KEY_AGREE_RECIPIENT_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsKeyAgreeRecipientInfo>() as c_long,
    sname: c"CMS_KeyAgreeRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_keyagreerecipientinfo_it() -> *const Asn1Item {
    &CMS_KEY_AGREE_RECIPIENT_INFO_ITEM
}

static CMS_KEK_IDENTIFIER_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"date".as_ptr(),
        item: item_ref(ASN1_GENERALIZEDTIME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"other".as_ptr(),
        item: item_ref(cms_otherkeyattribute_it),
    },
];

static CMS_KEK_IDENTIFIER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_KEK_IDENTIFIER_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsKekIdentifier>() as c_long,
    sname: c"CMS_KEKIdentifier".as_ptr(),
};

pub(crate) extern "C" fn cms_kekidentifier_it() -> *const Asn1Item {
    &CMS_KEK_IDENTIFIER_ITEM
}

static CMS_KEK_RECIPIENT_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"kekid".as_ptr(),
        item: item_ref(cms_kekidentifier_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"keyEncryptionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"encryptedKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_KEK_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_KEK_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsKekRecipientInfo>() as c_long,
    sname: c"CMS_KEKRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_kekrecipientinfo_it() -> *const Asn1Item {
    &CMS_KEK_RECIPIENT_INFO_ITEM
}

static CMS_PASSWORD_RECIPIENT_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"keyDerivationAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"keyEncryptionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"encryptedKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_PASSWORD_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_PASSWORD_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsPasswordRecipientInfo>() as c_long,
    sname: c"CMS_PasswordRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_passwordrecipientinfo_it() -> *const Asn1Item {
    &CMS_PASSWORD_RECIPIENT_INFO_ITEM
}

static CMS_KEM_RECIPIENT_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_kemri_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_KEM_RECIPIENT_INFO_TT: [Asn1Template; 9] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"rid".as_ptr(),
        item: item_ref(cms_signeridentifier_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"kem".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"kemct".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"kdf".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 40,
        field_name: c"kekLength".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 48,
        field_name: c"ukm".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 56,
        field_name: c"wrap".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 64,
        field_name: c"encryptedKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_KEM_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_KEM_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 9,
    funcs: ptr::addr_of!(CMS_KEM_RECIPIENT_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsKemRecipientInfo>() as c_long,
    sname: c"CMS_KEMRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_kemrecipientinfo_it() -> *const Asn1Item {
    &CMS_KEM_RECIPIENT_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_OtherRecipientInfo (ANY DEFINED BY) and CMS_RecipientInfo
// ---------------------------------------------------------------------------------------------

static CMS_ORI_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: 0,
    tag: 0,
    offset: 8,
    field_name: c"d.other".as_ptr(),
    item: item_ref(ASN1_ANY_it),
};

static CMS_ORI_ADBTBL: [Asn1AdbTable; 1] = [Asn1AdbTable {
    value: NID_id_smime_ori_kem as c_long,
    tt: Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.kemri".as_ptr(),
        item: item_ref(cms_kemrecipientinfo_it),
    },
}];

static CMS_ORI_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: CMS_ORI_ADBTBL.as_ptr(),
    tblcount: 1,
    default_tt: ptr::addr_of!(CMS_ORI_DEFAULT_TT),
    null_tt: ptr::null(),
});

fn cms_ori_adb() -> *const c_void {
    ptr::addr_of!(CMS_ORI_ADB.0).cast::<c_void>()
}

static CMS_ORI_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"oriType".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"CMS_OtherRecipientInfo".as_ptr(),
        item: cms_ori_adb as *mut c_void,
    },
];

static CMS_ORI_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ORI_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOtherRecipientInfo>() as c_long,
    sname: c"CMS_OtherRecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_otherrecipientinfo_it() -> *const Asn1Item {
    &CMS_ORI_ITEM
}

static CMS_RECIPIENT_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_ri_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_RECIPIENT_INFO_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"d.ktri".as_ptr(),
        item: item_ref(cms_keytransrecipientinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"d.kari".as_ptr(),
        item: item_ref(cms_keyagreerecipientinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"d.kekri".as_ptr(),
        item: item_ref(cms_kekrecipientinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 3,
        offset: 8,
        field_name: c"d.pwri".as_ptr(),
        item: item_ref(cms_passwordrecipientinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 4,
        offset: 8,
        field_name: c"d.ori".as_ptr(),
        item: item_ref(cms_otherrecipientinfo_it),
    },
];

static CMS_RECIPIENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_RECIPIENT_INFO_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::addr_of!(CMS_RECIPIENT_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsRecipientInfo>() as c_long,
    sname: c"CMS_RecipientInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_recipientinfo_it() -> *const Asn1Item {
    &CMS_RECIPIENT_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// The remaining content types
// ---------------------------------------------------------------------------------------------

static CMS_ENVELOPED_DATA_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"originatorInfo".as_ptr(),
        item: item_ref(cms_originatorinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 16,
        field_name: c"recipientInfos".as_ptr(),
        item: item_ref(cms_recipientinfo_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"encryptedContentInfo".as_ptr(),
        item: item_ref(cms_encryptedcontentinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"unprotectedAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];

static CMS_ENVELOPED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ENVELOPED_DATA_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsEnvelopedData>() as c_long,
    sname: c"CMS_EnvelopedData".as_ptr(),
};

/// `const ASN1_ITEM *CMS_EnvelopedData_it(void)` — `DECLARE_ASN1_ITEM(CMS_EnvelopedData)`,
/// `cms.h.in:58`.
#[no_mangle]
pub(crate) extern "C" fn CMS_EnvelopedData_it() -> *const Asn1Item {
    &CMS_ENVELOPED_DATA_ITEM
}

/// `CMS_EnvelopedData *CMS_EnvelopedData_dup(const CMS_EnvelopedData *a)` —
/// `IMPLEMENT_ASN1_DUP_FUNCTION` at `cms_asn1.c:286`.
///
/// # Safety
/// `a` is NULL or a live value the item layer built.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_EnvelopedData_dup(
    a: *const CmsEnvelopedData,
) -> *mut CmsEnvelopedData {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_dup(CMS_EnvelopedData_it(), a.cast()) }.cast()
}

static CMS_DIGESTED_DATA_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"digestAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"encapContentInfo".as_ptr(),
        item: item_ref(cms_encapsulatedcontentinfo_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"digest".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_DIGESTED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_DIGESTED_DATA_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsDigestedData>() as c_long,
    sname: c"CMS_DigestedData".as_ptr(),
};

pub(crate) extern "C" fn cms_digesteddata_it() -> *const Asn1Item {
    &CMS_DIGESTED_DATA_ITEM
}

static CMS_ENCRYPTED_DATA_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"encryptedContentInfo".as_ptr(),
        item: item_ref(cms_encryptedcontentinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 16,
        field_name: c"unprotectedAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];

static CMS_ENCRYPTED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ENCRYPTED_DATA_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsEncryptedData>() as c_long,
    sname: c"CMS_EncryptedData".as_ptr(),
};

pub(crate) extern "C" fn cms_encrypteddata_it() -> *const Asn1Item {
    &CMS_ENCRYPTED_DATA_ITEM
}

static CMS_AUTH_ENVELOPED_DATA_TT: [Asn1Template; 7] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"originatorInfo".as_ptr(),
        item: item_ref(cms_originatorinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 16,
        field_name: c"recipientInfos".as_ptr(),
        item: item_ref(cms_recipientinfo_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"authEncryptedContentInfo".as_ptr(),
        item: item_ref(cms_encryptedcontentinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 32,
        field_name: c"authAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"mac".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 48,
        field_name: c"unauthAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];

static CMS_AUTH_ENVELOPED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_AUTH_ENVELOPED_DATA_TT.as_ptr(),
    tcount: 7,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsAuthEnvelopedData>() as c_long,
    sname: c"CMS_AuthEnvelopedData".as_ptr(),
};

pub(crate) extern "C" fn cms_authenvelopeddata_it() -> *const Asn1Item {
    &CMS_AUTH_ENVELOPED_DATA_ITEM
}

static CMS_AUTHENTICATED_DATA_TT: [Asn1Template; 9] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"originatorInfo".as_ptr(),
        item: item_ref(cms_originatorinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 16,
        field_name: c"recipientInfos".as_ptr(),
        item: item_ref(cms_recipientinfo_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"macAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 32,
        field_name: c"digestAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"encapContentInfo".as_ptr(),
        item: item_ref(cms_encapsulatedcontentinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 48,
        field_name: c"authAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 56,
        field_name: c"mac".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 64,
        field_name: c"unauthAttrs".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];

static CMS_AUTHENTICATED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_AUTHENTICATED_DATA_TT.as_ptr(),
    tcount: 9,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsAuthenticatedData>() as c_long,
    sname: c"CMS_AuthenticatedData".as_ptr(),
};

pub(crate) extern "C" fn cms_authenticateddata_it() -> *const Asn1Item {
    &CMS_AUTHENTICATED_DATA_ITEM
}

static CMS_COMPRESSED_DATA_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"compressionAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"encapContentInfo".as_ptr(),
        item: item_ref(cms_encapsulatedcontentinfo_it),
    },
];

static CMS_COMPRESSED_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_COMPRESSED_DATA_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsCompressedData>() as c_long,
    sname: c"CMS_CompressedData".as_ptr(),
};

pub(crate) extern "C" fn cms_compresseddata_it() -> *const Asn1Item {
    &CMS_COMPRESSED_DATA_ITEM
}

// ---------------------------------------------------------------------------------------------
// CMS_ContentInfo and its ANY DEFINED BY table
// ---------------------------------------------------------------------------------------------

static CMS_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_EXPLICIT,
    tag: 0,
    offset: 8,
    field_name: c"d.other".as_ptr(),
    item: item_ref(ASN1_ANY_it),
};

static CMS_ADBTBL: [Asn1AdbTable; 8] = [
    Asn1AdbTable {
        value: NID_pkcs7_data as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.data".as_ptr(),
            item: item_ref(ASN1_OCTET_STRING_NDEF_it),
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_signed as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.signedData".as_ptr(),
            item: item_ref(cms_signeddata_it),
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_enveloped as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.envelopedData".as_ptr(),
            item: item_ref(CMS_EnvelopedData_it),
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_digest as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.digestedData".as_ptr(),
            item: item_ref(cms_digesteddata_it),
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_encrypted as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.encryptedData".as_ptr(),
            item: item_ref(cms_encrypteddata_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_smime_ct_authEnvelopedData as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.authEnvelopedData".as_ptr(),
            item: item_ref(cms_authenvelopeddata_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_smime_ct_authData as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.authenticatedData".as_ptr(),
            item: item_ref(cms_authenticateddata_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_smime_ct_compressedData as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_NDEF,
            tag: 0,
            offset: 8,
            field_name: c"d.compressedData".as_ptr(),
            item: item_ref(cms_compresseddata_it),
        },
    },
];

static CMS_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: CMS_ADBTBL.as_ptr(),
    tblcount: 8,
    default_tt: ptr::addr_of!(CMS_DEFAULT_TT),
    null_tt: ptr::null(),
});

fn cms_adb() -> *const c_void {
    ptr::addr_of!(CMS_ADB.0).cast::<c_void>()
}

static CMS_CONTENT_INFO_AUX: SyncAux = SyncAux(crate::asn1::layout::Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(cms_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

static CMS_CONTENT_INFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"contentType".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"CMS_ContentInfo".as_ptr(),
        item: cms_adb as *mut c_void,
    },
];

static CMS_CONTENT_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_CONTENT_INFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::addr_of!(CMS_CONTENT_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<CmsContentInfo>() as c_long,
    sname: c"CMS_ContentInfo".as_ptr(),
};

/// `const ASN1_ITEM *CMS_ContentInfo_it(void)` — `DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)`,
/// `cms.h.in:60`.
#[no_mangle]
pub(crate) extern "C" fn CMS_ContentInfo_it() -> *const Asn1Item {
    &CMS_CONTENT_INFO_ITEM
}

// ---------------------------------------------------------------------------------------------
// The signed/unsigned attribute templates and the receipt/ESS structures
// ---------------------------------------------------------------------------------------------

static CMS_ATTRIBUTES_SIGN_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SET_OF | ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"CMS_ATTRIBUTES".as_ptr(),
    item: item_ref(X509_ATTRIBUTE_it),
};

static CMS_ATTRIBUTES_SIGN_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &CMS_ATTRIBUTES_SIGN_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"CMS_ATTRIBUTES".as_ptr(),
};

pub(crate) extern "C" fn cms_attributes_sign_it() -> *const Asn1Item {
    &CMS_ATTRIBUTES_SIGN_ITEM
}

static CMS_ATTRIBUTES_VERIFY_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
    tag: V_ASN1_SET as c_long,
    offset: 0,
    field_name: c"CMS_ATTRIBUTES".as_ptr(),
    item: item_ref(X509_ATTRIBUTE_it),
};

static CMS_ATTRIBUTES_VERIFY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &CMS_ATTRIBUTES_VERIFY_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"CMS_ATTRIBUTES".as_ptr(),
};

pub(crate) extern "C" fn cms_attributes_verify_it() -> *const Asn1Item {
    &CMS_ATTRIBUTES_VERIFY_ITEM
}

static CMS_RECEIPTS_FROM_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"d.allOrFirstTier".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF,
        tag: 1,
        offset: 8,
        field_name: c"d.receiptList".as_ptr(),
        item: item_ref(GENERAL_NAMES_it),
    },
];

static CMS_RECEIPTS_FROM_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CMS_RECEIPTS_FROM_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsReceiptsFrom>() as c_long,
    sname: c"CMS_ReceiptsFrom".as_ptr(),
};

pub(crate) extern "C" fn cms_receiptsfrom_it() -> *const Asn1Item {
    &CMS_RECEIPTS_FROM_ITEM
}

static CMS_RECEIPT_REQUEST_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"signedContentIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"receiptsFrom".as_ptr(),
        item: item_ref(cms_receiptsfrom_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 16,
        field_name: c"receiptsTo".as_ptr(),
        item: item_ref(GENERAL_NAMES_it),
    },
];

static CMS_RECEIPT_REQUEST_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_RECEIPT_REQUEST_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsReceiptRequest>() as c_long,
    sname: c"CMS_ReceiptRequest".as_ptr(),
};

/// `const ASN1_ITEM *CMS_ReceiptRequest_it(void)` — `DECLARE_ASN1_FUNCTIONS(CMS_ReceiptRequest)`,
/// `cms.h.in:61`.
#[no_mangle]
pub(crate) extern "C" fn CMS_ReceiptRequest_it() -> *const Asn1Item {
    &CMS_RECEIPT_REQUEST_ITEM
}

static CMS_RECEIPT_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"contentType".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"signedContentIdentifier".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"originatorSignatureValue".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_RECEIPT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_RECEIPT_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsReceipt>() as c_long,
    sname: c"CMS_Receipt".as_ptr(),
};

pub(crate) extern "C" fn cms_receipt_it() -> *const Asn1Item {
    &CMS_RECEIPT_ITEM
}

static CMS_SHARED_INFO_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"keyInfo".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"entityUInfo".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"suppPubInfo".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_SHARED_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_SHARED_INFO_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsSharedInfo>() as c_long,
    sname: c"CMS_SharedInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_sharedinfo_it() -> *const Asn1Item {
    &CMS_SHARED_INFO_ITEM
}

static CMS_ORI_FOR_KEM_OTHER_INFO_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"wrap".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EMBED,
        tag: 0,
        offset: 8,
        field_name: c"kekLength".as_ptr(),
        item: crate::asn1::x_int64::INT32_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"ukm".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
];

static CMS_ORI_FOR_KEM_OTHER_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CMS_ORI_FOR_KEM_OTHER_INFO_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CmsOriForKemOtherInfo>() as c_long,
    sname: c"CMS_CMSORIforKEMOtherInfo".as_ptr(),
};

pub(crate) extern "C" fn cms_ori_for_kem_other_info_it() -> *const Asn1Item {
    &CMS_ORI_FOR_KEM_OTHER_INFO_ITEM
}

/// `int CMS_SharedInfo_encode(unsigned char **pder, X509_ALGOR *kekalg,`
/// `ASN1_OCTET_STRING *ukm, int keylen)` — `cms_asn1.c:437-464`.
///
/// # Safety
/// `pder` is a writable cursor; `kekalg` and `ukm` are borrowed and not retained.
#[no_mangle]
pub(crate) unsafe extern "C" fn CMS_SharedInfo_encode(
    pder: *mut *mut c_uchar,
    kekalg: *mut X509Algor,
    ukm: *mut Asn1String,
    keylen: c_int,
) -> c_int {
    let mut kl = [0u8; 4];
    let keylen = keylen << 3;
    kl[0] = ((keylen >> 24) & 0xff) as u8;
    kl[1] = ((keylen >> 16) & 0xff) as u8;
    kl[2] = ((keylen >> 8) & 0xff) as u8;
    kl[3] = (keylen & 0xff) as u8;
    let mut oklen = Asn1String {
        length: 4,
        type_: V_ASN1_OCTET_STRING,
        data: kl.as_mut_ptr(),
        flags: 0,
    };
    let ecsi = CmsSharedInfo {
        key_info: kekalg,
        entity_u_info: ukm,
        supp_pub_info: &mut oklen,
    };
    // SAFETY: `ecsi` is a fully-populated value the item reads; the item is static.
    unsafe {
        ASN1_item_i2d(
            (&ecsi as *const CmsSharedInfo).cast(),
            pder,
            cms_sharedinfo_it(),
        )
    }
}

/// `int CMS_CMSORIforKEMOtherInfo_encode(unsigned char **pder, X509_ALGOR *wrap,`
/// `ASN1_OCTET_STRING *ukm, int keylen)` — `cms_asn1.c:483-493`.
///
/// # Safety
/// `pder` is a writable cursor; `wrap` and `ukm` are borrowed and not retained.
pub(crate) unsafe extern "C" fn CMS_CMSORIforKEMOtherInfo_encode(
    pder: *mut *mut c_uchar,
    wrap: *mut X509Algor,
    ukm: *mut Asn1String,
    keylen: c_int,
) -> c_int {
    let kem_otherinfo = CmsOriForKemOtherInfo {
        wrap,
        kek_length: keylen as u32,
        ukm,
    };
    // SAFETY: `kem_otherinfo` is fully populated; the item is static.
    unsafe {
        ASN1_item_i2d(
            (&kem_otherinfo as *const CmsOriForKemOtherInfo).cast(),
            pder,
            cms_ori_for_kem_other_info_it(),
        )
    }
}
