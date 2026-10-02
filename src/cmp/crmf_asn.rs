//! `crypto/crmf/crmf_asn.c` — the CRMF item groups, landed **internally** by Phase 12.4.
//!
//! `cmp_asn.c`'s message engine carries `OSSL_CRMF` certificate requests: `OSSL_CMP_PKIBODY`
//! CHOICEs `OSSL_CRMF_MSGS`, `OSSL_CMP_ITAV`'s `ANY DEFINED BY` table names
//! `OSSL_CRMF_ENCRYPTEDVALUE`, and `OSSL_CMP_ATAVS` is a `SEQUENCE OF`
//! `OSSL_CRMF_ATTRIBUTETYPEANDVALUE`. The plan orders 12.4 before 12.7 for exactly this reason
//! (`docs/PHASE-12-SUBPHASES.md` §2.1), so the item groups those CMP definitions name are
//! transcribed here, crate-internal and **without** the `OSSL_CRMF_*` exports: the public CRMF
//! surface is 12.7's, and its 92 open rows stay open. What lands here is the layout and the
//! templates, so that `crmf_asn.c`'s exports can be published by 12.7 without moving a byte.
//!
//! Every struct is `crmf_local.h`'s spelling in its order and every template is its
//! `ASN1_SEQUENCE`/`ASN1_CHOICE`/`ASN1_ADB` macro expanded by hand.
//!
//! SPDX-License-Identifier: Apache-2.0
#![allow(dead_code, non_snake_case)]

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_BIT_STRING_it, ASN1_INTEGER_it, ASN1_NULL_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_it, ASN1_TIME_it, ASN1_UTF8STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::cms::cms_asn1::CMS_EnvelopedData_it;
use crate::runtime::obj::{
    Asn1Object, NID_id_regCtrl_algId, NID_id_regCtrl_authenticator, NID_id_regCtrl_oldCertID,
    NID_id_regCtrl_pkiPublicationInfo, NID_id_regCtrl_protocolEncrKey, NID_id_regCtrl_regToken,
    NID_id_regCtrl_rsaKeyLen, NID_id_regInfo_certReq, NID_id_regInfo_utf8Pairs,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::v3_genn::GENERAL_NAME_it;
use crate::x509::x_attrib::X509_ATTRIBUTE_it;
use crate::x509::x_exten::X509_EXTENSION_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_pubkey::X509_PUBKEY_it;

/// The authority translation unit this module is a projection of.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/crmf/crmf_asn.c";

/// `ASN1_ITEM_ref(type)`: the item accessor, cast to the untyped `item` slot.
const fn item_ref(f: extern "C" fn() -> *const Asn1Item) -> *mut c_void {
    f as *mut c_void
}

/// A `static` [`Asn1Adb`] cannot be a `Sync` static directly; this wrapper carries the impl.
pub(crate) struct SyncAdb(pub(crate) Asn1Adb);
// SAFETY: an `Asn1Adb` the crate builds is compiled from constants and never mutated.
unsafe impl Sync for SyncAdb {}

/// A `static` array of [`Asn1AdbTable`] rows, with the `Sync` impl a `static` needs.
pub(crate) struct SyncAdbTable<const N: usize>(pub(crate) [Asn1AdbTable; N]);
// SAFETY: the table is compiled from constants and never mutated.
unsafe impl<const N: usize> Sync for SyncAdbTable<N> {}

// ---------------------------------------------------------------------------------------------
// The structures — `crmf_local.h`
// ---------------------------------------------------------------------------------------------

/// `OSSL_CRMF_PRIVATEKEYINFO` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPrivateKeyInfo {
    version: *mut Asn1String,
    private_key_algorithm: *mut X509Algor,
    private_key: *mut Asn1String,
    attributes: *mut OpenSslStack,
}

/// `OSSL_CRMF_ENCKEYWITHID_IDENTIFIER` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfEncKeyWithIdIdentifier {
    type_: c_int,
    value: CrmfEncKeyWithIdIdentifierValue,
}

/// The `ENCKEYWITHID_IDENTIFIER` union.
#[repr(C)]
pub(crate) union CrmfEncKeyWithIdIdentifierValue {
    string: *mut Asn1String,
    general_name: *mut c_void,
}

/// `OSSL_CRMF_ENCKEYWITHID` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfEncKeyWithId {
    private_key: *mut CrmfPrivateKeyInfo,
    identifier: *mut CrmfEncKeyWithIdIdentifier,
}

/// `OSSL_CRMF_CERTID` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfCertId {
    issuer: *mut c_void,
    serial_number: *mut Asn1String,
}

/// `OSSL_CRMF_ENCRYPTEDVALUE` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfEncryptedValue {
    intended_alg: *mut X509Algor,
    symm_alg: *mut X509Algor,
    enc_symm_key: *mut Asn1String,
    key_alg: *mut X509Algor,
    value_hint: *mut Asn1String,
    enc_value: *mut Asn1String,
}

/// `OSSL_CRMF_ENCRYPTEDKEY` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfEncryptedKey {
    type_: c_int,
    value: CrmfEncryptedKeyValue,
}

/// The `ENCRYPTEDKEY` union.
#[repr(C)]
pub(crate) union CrmfEncryptedKeyValue {
    encrypted_value: *mut CrmfEncryptedValue,
    enveloped_data: *mut c_void,
}

/// `OSSL_CRMF_SINGLEPUBINFO` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfSinglePubInfo {
    pub_method: *mut Asn1String,
    pub_location: *mut c_void,
}

/// `OSSL_CRMF_PKIPUBLICATIONINFO` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPkiPublicationInfo {
    action: *mut Asn1String,
    pub_infos: *mut OpenSslStack,
}

/// `OSSL_CRMF_PKMACVALUE` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPkmacValue {
    alg_id: *mut X509Algor,
    value: *mut Asn1String,
}

/// `OSSL_CRMF_POPOPRIVKEY` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPopoPrivKey {
    type_: c_int,
    value: CrmfPopoPrivKeyValue,
}

/// The `POPOPRIVKEY` union.
#[repr(C)]
pub(crate) union CrmfPopoPrivKeyValue {
    this_message: *mut Asn1String,
    subsequent_message: *mut Asn1String,
    dh_mac: *mut Asn1String,
    agree_mac: *mut CrmfPkmacValue,
    encrypted_key: *mut Asn1String,
}

/// `OSSL_CRMF_PBMPARAMETER` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPbmParameter {
    salt: *mut Asn1String,
    owf: *mut X509Algor,
    iteration_count: *mut Asn1String,
    mac: *mut X509Algor,
}

/// `OSSL_CRMF_POPOSIGNINGKEYINPUT_AUTHINFO` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPopoSigningKeyInputAuthInfo {
    type_: c_int,
    value: CrmfPopoSigningKeyInputAuthInfoValue,
}

/// The `POPOSIGNINGKEYINPUT_AUTHINFO` union.
#[repr(C)]
pub(crate) union CrmfPopoSigningKeyInputAuthInfoValue {
    sender: *mut c_void,
    public_key_mac: *mut CrmfPkmacValue,
}

/// `OSSL_CRMF_POPOSIGNINGKEYINPUT` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPopoSigningKeyInput {
    auth_info: *mut CrmfPopoSigningKeyInputAuthInfo,
    public_key: *mut c_void,
}

/// `OSSL_CRMF_POPOSIGNINGKEY` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPopoSigningKey {
    poposk_input: *mut CrmfPopoSigningKeyInput,
    algorithm_identifier: *mut X509Algor,
    signature: *mut Asn1String,
}

/// `OSSL_CRMF_POPO` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfPopo {
    type_: c_int,
    value: CrmfPopoValue,
}

/// The `POPO` union.
#[repr(C)]
pub(crate) union CrmfPopoValue {
    ra_verified: *mut Asn1String,
    signature: *mut CrmfPopoSigningKey,
    key_encipherment: *mut CrmfPopoPrivKey,
    key_agreement: *mut CrmfPopoPrivKey,
}

/// `OSSL_CRMF_ATTRIBUTETYPEANDVALUE` — `internal/crmf.h`.
#[repr(C)]
pub(crate) struct CrmfAttributeTypeAndValue {
    pub(crate) type_: *mut Asn1Object,
    pub(crate) value: CrmfAttributeTypeAndValueValue,
}

/// The `ATTRIBUTETYPEANDVALUE` union.
#[repr(C)]
pub(crate) union CrmfAttributeTypeAndValueValue {
    pub(crate) reg_token: *mut Asn1String,
    pub(crate) authenticator: *mut Asn1String,
    pub(crate) pki_publication_info: *mut CrmfPkiPublicationInfo,
    pub(crate) old_cert_id: *mut CrmfCertId,
    pub(crate) protocol_encr_key: *mut c_void,
    pub(crate) alg_id: *mut X509Algor,
    pub(crate) rsa_key_len: *mut Asn1String,
    pub(crate) utf8_pairs: *mut Asn1String,
    pub(crate) cert_req: *mut CrmfCertRequest,
    pub(crate) other: *mut c_void,
}

/// `OSSL_CRMF_OPTIONALVALIDITY` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfOptionalValidity {
    not_before: *mut Asn1String,
    not_after: *mut Asn1String,
}

/// `OSSL_CRMF_CERTTEMPLATE` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfCertTemplate {
    version: *mut Asn1String,
    serial_number: *mut Asn1String,
    signing_alg: *mut X509Algor,
    issuer: *mut X509Name,
    validity: *mut CrmfOptionalValidity,
    subject: *mut X509Name,
    public_key: *mut c_void,
    issuer_uid: *mut Asn1String,
    subject_uid: *mut Asn1String,
    extensions: *mut OpenSslStack,
}

/// `OSSL_CRMF_CERTREQUEST` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfCertRequest {
    cert_req_id: *mut Asn1String,
    cert_template: *mut CrmfCertTemplate,
    controls: *mut OpenSslStack,
}

/// `OSSL_CRMF_MSG` — `crmf_local.h`.
#[repr(C)]
pub(crate) struct CrmfMsg {
    cert_req: *mut CrmfCertRequest,
    popo: *mut CrmfPopo,
    reg_info: *mut OpenSslStack,
}

// ---------------------------------------------------------------------------------------------
// The templates
// ---------------------------------------------------------------------------------------------

static CRMF_PRIVATEKEYINFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"privateKeyAlgorithm".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"privateKey".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"attributes".as_ptr(),
        item: item_ref(X509_ATTRIBUTE_it),
    },
];
static CRMF_PRIVATEKEYINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_PRIVATEKEYINFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPrivateKeyInfo>() as c_long,
    sname: c"OSSL_CRMF_PRIVATEKEYINFO".as_ptr(),
};
pub(crate) extern "C" fn crmf_privatekeyinfo_it() -> *const Asn1Item {
    &CRMF_PRIVATEKEYINFO_ITEM
}

static CRMF_ENCKEYWITHID_IDENTIFIER_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value.string".as_ptr(),
        item: item_ref(ASN1_UTF8STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value.generalName".as_ptr(),
        item: item_ref(GENERAL_NAME_it),
    },
];
static CRMF_ENCKEYWITHID_IDENTIFIER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CRMF_ENCKEYWITHID_IDENTIFIER_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfEncKeyWithIdIdentifier>() as c_long,
    sname: c"OSSL_CRMF_ENCKEYWITHID_IDENTIFIER".as_ptr(),
};
pub(crate) extern "C" fn crmf_enckeywithid_identifier_it() -> *const Asn1Item {
    &CRMF_ENCKEYWITHID_IDENTIFIER_ITEM
}

static CRMF_ENCKEYWITHID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"privateKey".as_ptr(),
        item: item_ref(crmf_privatekeyinfo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"identifier".as_ptr(),
        item: item_ref(crmf_enckeywithid_identifier_it),
    },
];
static CRMF_ENCKEYWITHID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_ENCKEYWITHID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfEncKeyWithId>() as c_long,
    sname: c"OSSL_CRMF_ENCKEYWITHID".as_ptr(),
};
pub(crate) extern "C" fn crmf_enckeywithid_it() -> *const Asn1Item {
    &CRMF_ENCKEYWITHID_ITEM
}

static CRMF_CERTID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: item_ref(GENERAL_NAME_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"serialNumber".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
];
static CRMF_CERTID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_CERTID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfCertId>() as c_long,
    sname: c"OSSL_CRMF_CERTID".as_ptr(),
};
pub(crate) extern "C" fn crmf_certid_it() -> *const Asn1Item {
    &CRMF_CERTID_ITEM
}

static CRMF_ENCRYPTEDVALUE_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"intendedAlg".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"symmAlg".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"encSymmKey".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 24,
        field_name: c"keyAlg".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 32,
        field_name: c"valueHint".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"encValue".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
];
static CRMF_ENCRYPTEDVALUE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_ENCRYPTEDVALUE_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfEncryptedValue>() as c_long,
    sname: c"OSSL_CRMF_ENCRYPTEDVALUE".as_ptr(),
};
pub(crate) extern "C" fn crmf_encryptedvalue_it() -> *const Asn1Item {
    &CRMF_ENCRYPTEDVALUE_ITEM
}

static CRMF_ENCRYPTEDKEY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value.encryptedValue".as_ptr(),
        item: item_ref(crmf_encryptedvalue_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value.envelopedData".as_ptr(),
        item: item_ref(CMS_EnvelopedData_it),
    },
];
static CRMF_ENCRYPTEDKEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CRMF_ENCRYPTEDKEY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfEncryptedKey>() as c_long,
    sname: c"OSSL_CRMF_ENCRYPTEDKEY".as_ptr(),
};
pub(crate) extern "C" fn crmf_encryptedkey_it() -> *const Asn1Item {
    &CRMF_ENCRYPTEDKEY_ITEM
}

static CRMF_SINGLEPUBINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"pubMethod".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"pubLocation".as_ptr(),
        item: item_ref(GENERAL_NAME_it),
    },
];
static CRMF_SINGLEPUBINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_SINGLEPUBINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfSinglePubInfo>() as c_long,
    sname: c"OSSL_CRMF_SINGLEPUBINFO".as_ptr(),
};
pub(crate) extern "C" fn crmf_singlepubinfo_it() -> *const Asn1Item {
    &CRMF_SINGLEPUBINFO_ITEM
}

static CRMF_PKIPUBLICATIONINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"action".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"pubInfos".as_ptr(),
        item: item_ref(crmf_singlepubinfo_it),
    },
];
static CRMF_PKIPUBLICATIONINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_PKIPUBLICATIONINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPkiPublicationInfo>() as c_long,
    sname: c"OSSL_CRMF_PKIPUBLICATIONINFO".as_ptr(),
};
pub(crate) extern "C" fn crmf_pkipublicationinfo_it() -> *const Asn1Item {
    &CRMF_PKIPUBLICATIONINFO_ITEM
}

static CRMF_PKMACVALUE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"algId".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
];
static CRMF_PKMACVALUE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_PKMACVALUE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPkmacValue>() as c_long,
    sname: c"OSSL_CRMF_PKMACVALUE".as_ptr(),
};
pub(crate) extern "C" fn crmf_pkmacvalue_it() -> *const Asn1Item {
    &CRMF_PKMACVALUE_ITEM
}

static CRMF_POPOPRIVKEY_TT: [Asn1Template; 5] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value.thisMessage".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"value.subsequentMessage".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"value.dhMAC".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 3,
        offset: 8,
        field_name: c"value.agreeMAC".as_ptr(),
        item: item_ref(crmf_pkmacvalue_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 4,
        offset: 8,
        field_name: c"value.encryptedKey".as_ptr(),
        item: item_ref(ASN1_NULL_it),
    },
];
static CRMF_POPOPRIVKEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CRMF_POPOPRIVKEY_TT.as_ptr(),
    tcount: 5,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPopoPrivKey>() as c_long,
    sname: c"OSSL_CRMF_POPOPRIVKEY".as_ptr(),
};
pub(crate) extern "C" fn crmf_popoprivkey_it() -> *const Asn1Item {
    &CRMF_POPOPRIVKEY_ITEM
}

static CRMF_PBMPARAMETER_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"salt".as_ptr(),
        item: item_ref(ASN1_OCTET_STRING_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"owf".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"iterationCount".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"mac".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
];
static CRMF_PBMPARAMETER_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_PBMPARAMETER_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPbmParameter>() as c_long,
    sname: c"OSSL_CRMF_PBMPARAMETER".as_ptr(),
};
pub(crate) extern "C" fn crmf_pbmparameter_it() -> *const Asn1Item {
    &CRMF_PBMPARAMETER_ITEM
}

static CRMF_POPOSIGNINGKEYINPUT_AUTHINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value.sender".as_ptr(),
        item: item_ref(GENERAL_NAME_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"value.publicKeyMAC".as_ptr(),
        item: item_ref(crmf_pkmacvalue_it),
    },
];
static CRMF_POPOSIGNINGKEYINPUT_AUTHINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CRMF_POPOSIGNINGKEYINPUT_AUTHINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPopoSigningKeyInputAuthInfo>() as c_long,
    sname: c"OSSL_CRMF_POPOSIGNINGKEYINPUT_AUTHINFO".as_ptr(),
};
pub(crate) extern "C" fn crmf_poposigningkeyinput_authinfo_it() -> *const Asn1Item {
    &CRMF_POPOSIGNINGKEYINPUT_AUTHINFO_ITEM
}

static CRMF_POPOSIGNINGKEYINPUT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"authInfo".as_ptr(),
        item: item_ref(crmf_poposigningkeyinput_authinfo_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"publicKey".as_ptr(),
        item: item_ref(X509_PUBKEY_it),
    },
];
static CRMF_POPOSIGNINGKEYINPUT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_POPOSIGNINGKEYINPUT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPopoSigningKeyInput>() as c_long,
    sname: c"OSSL_CRMF_POPOSIGNINGKEYINPUT".as_ptr(),
};
pub(crate) extern "C" fn crmf_poposigningkeyinput_it() -> *const Asn1Item {
    &CRMF_POPOSIGNINGKEYINPUT_ITEM
}

static CRMF_POPOSIGNINGKEY_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"poposkInput".as_ptr(),
        item: item_ref(crmf_poposigningkeyinput_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"algorithmIdentifier".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"signature".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
];
static CRMF_POPOSIGNINGKEY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_POPOSIGNINGKEY_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPopoSigningKey>() as c_long,
    sname: c"OSSL_CRMF_POPOSIGNINGKEY".as_ptr(),
};
pub(crate) extern "C" fn crmf_poposigningkey_it() -> *const Asn1Item {
    &CRMF_POPOSIGNINGKEY_ITEM
}

static CRMF_POPO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value.raVerified".as_ptr(),
        item: item_ref(ASN1_NULL_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"value.signature".as_ptr(),
        item: item_ref(crmf_poposigningkey_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 2,
        offset: 8,
        field_name: c"value.keyEncipherment".as_ptr(),
        item: item_ref(crmf_popoprivkey_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 3,
        offset: 8,
        field_name: c"value.keyAgreement".as_ptr(),
        item: item_ref(crmf_popoprivkey_it),
    },
];
static CRMF_POPO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: CRMF_POPO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfPopo>() as c_long,
    sname: c"OSSL_CRMF_POPO".as_ptr(),
};
pub(crate) extern "C" fn crmf_popo_it() -> *const Asn1Item {
    &CRMF_POPO_ITEM
}

// --- OSSL_CRMF_ATTRIBUTETYPEANDVALUE, an ADB on `type` ---

static CRMF_ATAV_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_OPTIONAL,
    tag: 0,
    offset: 8,
    field_name: c"value.other".as_ptr(),
    item: item_ref(ASN1_ANY_it),
};

static CRMF_ATAV_ADBTBL: SyncAdbTable<9> = SyncAdbTable([
    Asn1AdbTable {
        value: NID_id_regCtrl_regToken as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.regToken".as_ptr(),
            item: item_ref(ASN1_UTF8STRING_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_authenticator as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.authenticator".as_ptr(),
            item: item_ref(ASN1_UTF8STRING_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_pkiPublicationInfo as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.pkiPublicationInfo".as_ptr(),
            item: item_ref(crmf_pkipublicationinfo_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_oldCertID as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.oldCertID".as_ptr(),
            item: item_ref(crmf_certid_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_protocolEncrKey as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.protocolEncrKey".as_ptr(),
            item: item_ref(X509_PUBKEY_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_algId as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.algId".as_ptr(),
            item: item_ref(X509_ALGOR_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regCtrl_rsaKeyLen as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.rsaKeyLen".as_ptr(),
            item: item_ref(ASN1_INTEGER_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regInfo_utf8Pairs as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.utf8Pairs".as_ptr(),
            item: item_ref(ASN1_UTF8STRING_it),
        },
    },
    Asn1AdbTable {
        value: NID_id_regInfo_certReq as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"value.certReq".as_ptr(),
            item: item_ref(crmf_certrequest_it),
        },
    },
]);

pub(crate) static CRMF_ATAV_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: CRMF_ATAV_ADBTBL.0.as_ptr(),
    tblcount: 9,
    default_tt: &CRMF_ATAV_DEFAULT_TT,
    null_tt: ptr::null(),
});

pub(crate) extern "C" fn crmf_atav_adb() -> *const Asn1Item {
    &CRMF_ATAV_ADB.0 as *const Asn1Adb as *const Asn1Item
}

static CRMF_ATAV_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type".as_ptr(),
        item: item_ref(ASN1_OBJECT_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"OSSL_CRMF_ATTRIBUTETYPEANDVALUE".as_ptr(),
        item: crmf_atav_adb as *mut c_void,
    },
];
static CRMF_ATAV_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_ATAV_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfAttributeTypeAndValue>() as c_long,
    sname: c"OSSL_CRMF_ATTRIBUTETYPEANDVALUE".as_ptr(),
};
pub(crate) extern "C" fn crmf_atav_it() -> *const Asn1Item {
    &CRMF_ATAV_ITEM
}

// --- OSSL_CRMF_OPTIONALVALIDITY, CERTTEMPLATE, CERTREQUEST, MSG, MSGS ---

static CRMF_OPTIONALVALIDITY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"notBefore".as_ptr(),
        item: item_ref(ASN1_TIME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"notAfter".as_ptr(),
        item: item_ref(ASN1_TIME_it),
    },
];
static CRMF_OPTIONALVALIDITY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_OPTIONALVALIDITY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfOptionalValidity>() as c_long,
    sname: c"OSSL_CRMF_OPTIONALVALIDITY".as_ptr(),
};
pub(crate) extern "C" fn crmf_optionalvalidity_it() -> *const Asn1Item {
    &CRMF_OPTIONALVALIDITY_ITEM
}

static CRMF_CERTTEMPLATE_TT: [Asn1Template; 10] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"serialNumber".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"signingAlg".as_ptr(),
        item: item_ref(X509_ALGOR_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 24,
        field_name: c"issuer".as_ptr(),
        item: item_ref(X509_NAME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 4,
        offset: 32,
        field_name: c"validity".as_ptr(),
        item: item_ref(crmf_optionalvalidity_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 5,
        offset: 40,
        field_name: c"subject".as_ptr(),
        item: item_ref(X509_NAME_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 6,
        offset: 48,
        field_name: c"publicKey".as_ptr(),
        item: item_ref(X509_PUBKEY_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 7,
        offset: 56,
        field_name: c"issuerUID".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 8,
        offset: 64,
        field_name: c"subjectUID".as_ptr(),
        item: item_ref(ASN1_BIT_STRING_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 9,
        offset: 72,
        field_name: c"extensions".as_ptr(),
        item: item_ref(X509_EXTENSION_it),
    },
];
static CRMF_CERTTEMPLATE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_CERTTEMPLATE_TT.as_ptr(),
    tcount: 10,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfCertTemplate>() as c_long,
    sname: c"OSSL_CRMF_CERTTEMPLATE".as_ptr(),
};
pub(crate) extern "C" fn crmf_certtemplate_it() -> *const Asn1Item {
    &CRMF_CERTTEMPLATE_ITEM
}

static CRMF_CERTREQUEST_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"certReqId".as_ptr(),
        item: item_ref(ASN1_INTEGER_it),
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"certTemplate".as_ptr(),
        item: item_ref(crmf_certtemplate_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"controls".as_ptr(),
        item: item_ref(crmf_atav_it),
    },
];
static CRMF_CERTREQUEST_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_CERTREQUEST_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfCertRequest>() as c_long,
    sname: c"OSSL_CRMF_CERTREQUEST".as_ptr(),
};
pub(crate) extern "C" fn crmf_certrequest_it() -> *const Asn1Item {
    &CRMF_CERTREQUEST_ITEM
}

static CRMF_MSG_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"certReq".as_ptr(),
        item: item_ref(crmf_certrequest_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"popo".as_ptr(),
        item: item_ref(crmf_popo_it),
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"regInfo".as_ptr(),
        item: item_ref(crmf_atav_it),
    },
];
static CRMF_MSG_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: CRMF_MSG_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<CrmfMsg>() as c_long,
    sname: c"OSSL_CRMF_MSG".as_ptr(),
};
pub(crate) extern "C" fn crmf_msg_it() -> *const Asn1Item {
    &CRMF_MSG_ITEM
}

static CRMF_MSGS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_CRMF_MSGS".as_ptr(),
    item: item_ref(crmf_msg_it),
};
static CRMF_MSGS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &CRMF_MSGS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_CRMF_MSGS".as_ptr(),
};
pub(crate) extern "C" fn crmf_msgs_it() -> *const Asn1Item {
    &CRMF_MSGS_ITEM
}

// ---------------------------------------------------------------------------------------------
// The alloc/dup/free helpers cmp_asn.c reaches
// ---------------------------------------------------------------------------------------------

/// # Safety
/// The returned pointer is a fresh value the item layer built; release it with the matching free.
pub(crate) unsafe fn atav_new() -> *mut CrmfAttributeTypeAndValue {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(crmf_atav_it()) }.cast()
}

/// # Safety
/// `p` is NULL or a value [`atav_new`] or the item layer built.
pub(crate) unsafe fn atav_free(p: *mut CrmfAttributeTypeAndValue) {
    // SAFETY: `p` is NULL or a live item value.
    unsafe { ASN1_item_free(p.cast(), crmf_atav_it()) };
}

/// # Safety
/// `p` is NULL or a live `OSSL_CRMF_ATTRIBUTETYPEANDVALUE`.
pub(crate) unsafe fn atav_dup(
    p: *const CrmfAttributeTypeAndValue,
) -> *mut CrmfAttributeTypeAndValue {
    // SAFETY: `p` is NULL or a live value; the item layer duplicates it.
    unsafe { crate::asn1::a_dup::ASN1_item_dup(crmf_atav_it(), p.cast()) }.cast()
}

/// # Safety
/// The returned pointer is a fresh value; release with [`certtemplate_free`].
pub(crate) unsafe fn certtemplate_new() -> *mut CrmfCertTemplate {
    // SAFETY: the accessor answers a static item.
    unsafe { ASN1_item_new(crmf_certtemplate_it()) }.cast()
}

/// # Safety
/// `p` is NULL or a value the item layer built.
pub(crate) unsafe fn certtemplate_free(p: *mut CrmfCertTemplate) {
    // SAFETY: `p` is NULL or a live item value.
    unsafe { ASN1_item_free(p.cast(), crmf_certtemplate_it()) };
}

/// # Safety
/// `p` is NULL or a live `OSSL_CRMF_CERTTEMPLATE`.
pub(crate) unsafe fn certtemplate_dup(p: *const CrmfCertTemplate) -> *mut CrmfCertTemplate {
    // SAFETY: `p` is NULL or a live value; the item layer duplicates it.
    unsafe { crate::asn1::a_dup::ASN1_item_dup(crmf_certtemplate_it(), p.cast()) }.cast()
}

/// # Safety
/// `p` is NULL or a live `OSSL_CRMF_CERTID`.
pub(crate) unsafe fn certid_dup(p: *const CrmfCertId) -> *mut CrmfCertId {
    // SAFETY: `p` is NULL or a live value; the item layer duplicates it.
    unsafe { crate::asn1::a_dup::ASN1_item_dup(crmf_certid_it(), p.cast()) }.cast()
}
