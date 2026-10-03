//! `crypto/pkcs7/pk7_asn1.c` — the `PKCS7` object's ASN.1 item group. Phase 10 landed the
//! PKCS#12 subset (the `data`, `digest` and `encrypted` arms); Phase 12.2 lands the remainder:
//! the `signed`, `enveloped` and `signedAndEnveloped` arms over Phase 11's `X509_it`,
//! `X509_CRL_it` and `X509_NAME_it`, the streaming callback's four arms, and the
//! `PKCS7_ATTR_SIGN`/`PKCS7_ATTR_VERIFY` attribute templates.
//!
//! ## What lands
//!
//! The `PKCS7` item itself (`PKCS7_it`/`_new`/`_new_ex`/`_free`, `d2i_PKCS7`/`i2d_PKCS7`,
//! `i2d_PKCS7_NDEF`, `PKCS7_dup`, `PKCS7_print_ctx`) and all six `ANY DEFINED BY` arms —
//! `data`, `signed`, `enveloped`, `signedAndEnveloped`, `digest` and `encrypted` — with the
//! item groups `PKCS7_SIGNED`, `PKCS7_SIGNER_INFO`, `PKCS7_ISSUER_AND_SERIAL`,
//! `PKCS7_ENVELOPE`, `PKCS7_RECIP_INFO`, `PKCS7_ENC_CONTENT`, `PKCS7_SIGN_ENVELOPE`,
//! `PKCS7_ENCRYPT` and `PKCS7_DIGEST` whole. The `signed`/`enveloped`/`signedAndEnveloped`
//! arms were withheld by Phase 10 because their templates name Phase 11's `X509_it`,
//! `X509_CRL_it` and `X509_NAME_it`, which are now landed.
//!
//! ## The `pk7_cb` streaming arms
//!
//! `ASN1_NDEF_SEQUENCE_cb(PKCS7, pk7_cb)` gives the item a callback. Its `ASN1_OP_STREAM_*`
//! and `ASN1_OP_DETACHED_*` arms call `PKCS7_stream`, `PKCS7_dataInit` and `PKCS7_dataFinal`
//! (`pk7_asn1.c:33-58`), which Phase 12.2 lands in `pk7_lib.rs`/`pk7_doit.rs`, so all four
//! arms are transcribed. The remaining operations fall through and answer 1.
//!
//! ## The bytes are the contract
//!
//! Each template is the authority's own `ASN1_*` spelling, in its order, with its `ASN1_TFLG_*`
//! set. `docs/PHASE-10-SUBPHASES.md` §3.2 is why a round trip is not enough.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_item_dup;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::{ASN1_item_i2d, ASN1_item_ndef_i2d};
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::tasn_prn::ASN1_item_print;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::evp::pkey::{EVP_PKEY_free, EvpPkey};
use crate::pkcs7::pk7_doit::{PKCS7_dataFinal, PKCS7_dataInit};
use crate::pkcs7::pk7_lib::PKCS7_stream;
use crate::runtime::bio::Bio;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::{
    Asn1Object, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted, NID_pkcs7_enveloped,
    NID_pkcs7_signed, NID_pkcs7_signedAndEnveloped,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x_attrib::X509_ATTRIBUTE_it;
use crate::x509::x_crl::X509_CRL_it;
use crate::x509::x_name::{X509Name, X509_NAME_it};
use crate::x509::x_x509::{X509_free, X509_it, X509};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_asn1.c";

/// `PKCS7_CTX` — `include/openssl/pkcs7.h.in:49-52`. The library context and property query a
/// `PKCS7` resolves its fetches in; embedded in the object and borrowed by each sub-object.
#[repr(C)]
pub struct Pkcs7Ctx {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — owned by the `PKCS7`, freed by [`PKCS7_free`].
    pub(crate) propq: *mut c_char,
}

/// `struct pkcs7_issuer_and_serial_st` — `pkcs7.h.in:54-57`.
#[repr(C)]
pub struct Pkcs7IssuerAndSerial {
    /// `X509_NAME *issuer`.
    pub(crate) issuer: *mut X509Name,
    /// `ASN1_INTEGER *serial`.
    pub(crate) serial: *mut Asn1String,
}

/// `struct pkcs7_signer_info_st` — `pkcs7.h.in:59-70`. The four template columns, the two
/// attribute stacks, the private key the authority keeps for a while, and the borrowed context.
#[repr(C)]
pub struct Pkcs7SignerInfo {
    /// `ASN1_INTEGER *version` — version 1.
    pub(crate) version: *mut Asn1String,
    /// `PKCS7_ISSUER_AND_SERIAL *issuer_and_serial`.
    pub(crate) issuer_and_serial: *mut Pkcs7IssuerAndSerial,
    /// `X509_ALGOR *digest_alg`.
    pub(crate) digest_alg: *mut X509Algor,
    /// `STACK_OF(X509_ATTRIBUTE) *auth_attr` — `[0] IMPLICIT`.
    pub(crate) auth_attr: *mut OpenSslStack,
    /// `X509_ALGOR *digest_enc_alg` — actually used for signing.
    pub(crate) digest_enc_alg: *mut X509Algor,
    /// `ASN1_OCTET_STRING *enc_digest` — actually the signature.
    pub(crate) enc_digest: *mut Asn1String,
    /// `STACK_OF(X509_ATTRIBUTE) *unauth_attr` — `[1] IMPLICIT`.
    pub(crate) unauth_attr: *mut OpenSslStack,
    /// `EVP_PKEY *pkey` — the private key to sign with, released by the item callback.
    pub(crate) pkey: *mut EvpPkey,
    /// `const PKCS7_CTX *ctx`.
    pub(crate) ctx: *const Pkcs7Ctx,
}

/// `struct pkcs7_recip_info_st` — `pkcs7.h.in:77-84`.
#[repr(C)]
pub struct Pkcs7RecipInfo {
    /// `ASN1_INTEGER *version` — version 0.
    pub(crate) version: *mut Asn1String,
    /// `PKCS7_ISSUER_AND_SERIAL *issuer_and_serial`.
    pub(crate) issuer_and_serial: *mut Pkcs7IssuerAndSerial,
    /// `X509_ALGOR *key_enc_algor`.
    pub(crate) key_enc_algor: *mut X509Algor,
    /// `ASN1_OCTET_STRING *enc_key`.
    pub(crate) enc_key: *mut Asn1String,
    /// `X509 *cert` — the public-key source, released by the item callback.
    pub(crate) cert: *mut X509,
    /// `const PKCS7_CTX *ctx`.
    pub(crate) ctx: *const Pkcs7Ctx,
}

/// `struct pkcs7_signed_st` — `pkcs7.h.in:91-98`. The template's field order differs from the
/// struct's; the template offsets below map each column to its member.
#[repr(C)]
pub struct Pkcs7Signed {
    /// `ASN1_INTEGER *version` — version 1.
    pub(crate) version: *mut Asn1String,
    /// `STACK_OF(X509_ALGOR) *md_algs`.
    pub(crate) md_algs: *mut OpenSslStack,
    /// `STACK_OF(X509) *cert` — `[0] IMPLICIT`.
    pub(crate) cert: *mut OpenSslStack,
    /// `STACK_OF(X509_CRL) *crl` — `[1] IMPLICIT`.
    pub(crate) crl: *mut OpenSslStack,
    /// `STACK_OF(PKCS7_SIGNER_INFO) *signer_info`.
    pub(crate) signer_info: *mut OpenSslStack,
    /// `struct pkcs7_st *contents`.
    pub(crate) contents: *mut Pkcs7,
}

/// `struct pkcs7_enc_content_st` — `pkcs7.h.in:104-110`. The four template columns and the
/// context are load-bearing here; `cipher` is the fetched cipher the authority caches.
#[repr(C)]
pub struct Pkcs7EncContent {
    /// `ASN1_OBJECT *content_type`.
    pub(crate) content_type: *mut Asn1Object,
    /// `X509_ALGOR *algorithm`.
    pub(crate) algorithm: *mut X509Algor,
    /// `ASN1_OCTET_STRING *enc_data` — `[0] IMPLICIT OPTIONAL`.
    pub(crate) enc_data: *mut Asn1String,
    /// `const EVP_CIPHER *cipher`.
    pub(crate) cipher: *const c_void,
    /// `const PKCS7_CTX *ctx`.
    pub(crate) ctx: *const Pkcs7Ctx,
}

/// `struct pkcs7_enveloped_st` — `pkcs7.h.in:112-116`.
#[repr(C)]
pub struct Pkcs7Envelope {
    /// `ASN1_INTEGER *version` — version 0.
    pub(crate) version: *mut Asn1String,
    /// `STACK_OF(PKCS7_RECIP_INFO) *recipientinfo`.
    pub(crate) recipientinfo: *mut OpenSslStack,
    /// `PKCS7_ENC_CONTENT *enc_data`.
    pub(crate) enc_data: *mut Pkcs7EncContent,
}

/// `struct pkcs7_signedandenveloped_st` — `pkcs7.h.in:118-126`.
#[repr(C)]
pub struct Pkcs7SignEnvelope {
    /// `ASN1_INTEGER *version` — version 1.
    pub(crate) version: *mut Asn1String,
    /// `STACK_OF(X509_ALGOR) *md_algs`.
    pub(crate) md_algs: *mut OpenSslStack,
    /// `STACK_OF(X509) *cert` — `[0] IMPLICIT`.
    pub(crate) cert: *mut OpenSslStack,
    /// `STACK_OF(X509_CRL) *crl` — `[1] IMPLICIT`.
    pub(crate) crl: *mut OpenSslStack,
    /// `STACK_OF(PKCS7_SIGNER_INFO) *signer_info`.
    pub(crate) signer_info: *mut OpenSslStack,
    /// `PKCS7_ENC_CONTENT *enc_data`.
    pub(crate) enc_data: *mut Pkcs7EncContent,
    /// `STACK_OF(PKCS7_RECIP_INFO) *recipientinfo`.
    pub(crate) recipientinfo: *mut OpenSslStack,
}

/// `struct pkcs7_digest_st` — `pkcs7.h.in:128-133`.
#[repr(C)]
pub struct Pkcs7Digest {
    /// `ASN1_INTEGER *version`.
    pub(crate) version: *mut Asn1String,
    /// `X509_ALGOR *md`.
    pub(crate) md: *mut X509Algor,
    /// `struct pkcs7_st *contents` — the digested contentInfo.
    pub(crate) contents: *mut Pkcs7,
    /// `ASN1_OCTET_STRING *digest`.
    pub(crate) digest: *mut Asn1String,
}

/// `struct pkcs7_encrypted_st` — `pkcs7.h.in:135-138`.
#[repr(C)]
pub struct Pkcs7Encrypt {
    /// `ASN1_INTEGER *version`.
    pub(crate) version: *mut Asn1String,
    /// `PKCS7_ENC_CONTENT *enc_data`.
    pub(crate) enc_data: *mut Pkcs7EncContent,
}

/// `struct pkcs7_st`'s `d` union — `pkcs7.h.in:158-174`. Every arm is a pointer, so the union is
/// one pointer wide and each arm has the union's offset. All six content arms are modelled.
#[repr(C)]
pub union Pkcs7D {
    /// `char *ptr` — the null test `ossl_pkcs7_resolve_libctx` and friends use.
    pub(crate) ptr: *mut c_void,
    /// `ASN1_OCTET_STRING *data` — `NID_pkcs7_data`.
    pub(crate) data: *mut Asn1String,
    /// `PKCS7_SIGNED *sign` — `NID_pkcs7_signed`.
    pub(crate) sign: *mut Pkcs7Signed,
    /// `PKCS7_ENVELOPE *enveloped` — `NID_pkcs7_enveloped`.
    pub(crate) enveloped: *mut Pkcs7Envelope,
    /// `PKCS7_SIGN_ENVELOPE *signed_and_enveloped` — `NID_pkcs7_signedAndEnveloped`.
    pub(crate) signed_and_enveloped: *mut Pkcs7SignEnvelope,
    /// `PKCS7_DIGEST *digest` — `NID_pkcs7_digest`.
    pub(crate) digest: *mut Pkcs7Digest,
    /// `PKCS7_ENCRYPT *encrypted` — `NID_pkcs7_encrypted`.
    pub(crate) encrypted: *mut Pkcs7Encrypt,
    /// `ASN1_TYPE *other` — the `ASN1_ADB` default arm.
    pub(crate) other: *mut Asn1Type,
}

/// `struct pkcs7_st` — `include/openssl/pkcs7.h.in:140-176`: the received encoding cache, the
/// processing state, the type OID and the content union, then the context. The item's `size`.
#[repr(C)]
pub struct Pkcs7 {
    /// `unsigned char *asn1` — the cached received encoding, or null.
    pub(crate) asn1: *mut c_uchar,
    /// `long length` — its length.
    pub(crate) length: c_long,
    /// `int state` — `PKCS7_S_HEADER`/`_BODY`/`_TAIL` during processing.
    pub(crate) state: c_int,
    /// `int detached`.
    pub(crate) detached: c_int,
    /// `ASN1_OBJECT *type` — the contentInfo's `contentType`, and the `ASN1_ADB` selector at
    /// offset 24.
    pub(crate) type_: *mut Asn1Object,
    /// The content union, modelled by [`Pkcs7D`].
    pub(crate) d: Pkcs7D,
    /// `PKCS7_CTX ctx`.
    pub(crate) ctx: Pkcs7Ctx,
}

const _: () = {
    assert!(core::mem::size_of::<Pkcs7>() == 56);
    assert!(core::mem::offset_of!(Pkcs7, asn1) == 0);
    assert!(core::mem::offset_of!(Pkcs7, length) == 8);
    assert!(core::mem::offset_of!(Pkcs7, state) == 16);
    assert!(core::mem::offset_of!(Pkcs7, detached) == 20);
    assert!(core::mem::offset_of!(Pkcs7, type_) == 24);
    assert!(core::mem::offset_of!(Pkcs7, d) == 32);
    assert!(core::mem::offset_of!(Pkcs7, ctx) == 40);
    assert!(core::mem::size_of::<Pkcs7Ctx>() == 16);
    assert!(core::mem::size_of::<Pkcs7IssuerAndSerial>() == 16);
    assert!(core::mem::offset_of!(Pkcs7IssuerAndSerial, issuer) == 0);
    assert!(core::mem::offset_of!(Pkcs7IssuerAndSerial, serial) == 8);
    assert!(core::mem::size_of::<Pkcs7SignerInfo>() == 72);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, issuer_and_serial) == 8);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, digest_alg) == 16);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, auth_attr) == 24);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, digest_enc_alg) == 32);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, enc_digest) == 40);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, unauth_attr) == 48);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, pkey) == 56);
    assert!(core::mem::offset_of!(Pkcs7SignerInfo, ctx) == 64);
    assert!(core::mem::size_of::<Pkcs7RecipInfo>() == 48);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, issuer_and_serial) == 8);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, key_enc_algor) == 16);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, enc_key) == 24);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, cert) == 32);
    assert!(core::mem::offset_of!(Pkcs7RecipInfo, ctx) == 40);
    assert!(core::mem::size_of::<Pkcs7Signed>() == 48);
    assert!(core::mem::offset_of!(Pkcs7Signed, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Signed, md_algs) == 8);
    assert!(core::mem::offset_of!(Pkcs7Signed, cert) == 16);
    assert!(core::mem::offset_of!(Pkcs7Signed, crl) == 24);
    assert!(core::mem::offset_of!(Pkcs7Signed, signer_info) == 32);
    assert!(core::mem::offset_of!(Pkcs7Signed, contents) == 40);
    assert!(core::mem::size_of::<Pkcs7EncContent>() == 40);
    assert!(core::mem::offset_of!(Pkcs7EncContent, content_type) == 0);
    assert!(core::mem::offset_of!(Pkcs7EncContent, algorithm) == 8);
    assert!(core::mem::offset_of!(Pkcs7EncContent, enc_data) == 16);
    assert!(core::mem::offset_of!(Pkcs7EncContent, cipher) == 24);
    assert!(core::mem::offset_of!(Pkcs7EncContent, ctx) == 32);
    assert!(core::mem::size_of::<Pkcs7Envelope>() == 24);
    assert!(core::mem::offset_of!(Pkcs7Envelope, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Envelope, recipientinfo) == 8);
    assert!(core::mem::offset_of!(Pkcs7Envelope, enc_data) == 16);
    assert!(core::mem::size_of::<Pkcs7SignEnvelope>() == 56);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, md_algs) == 8);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, cert) == 16);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, crl) == 24);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, signer_info) == 32);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, enc_data) == 40);
    assert!(core::mem::offset_of!(Pkcs7SignEnvelope, recipientinfo) == 48);
    assert!(core::mem::size_of::<Pkcs7Digest>() == 32);
    assert!(core::mem::offset_of!(Pkcs7Digest, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Digest, md) == 8);
    assert!(core::mem::offset_of!(Pkcs7Digest, contents) == 16);
    assert!(core::mem::offset_of!(Pkcs7Digest, digest) == 24);
    assert!(core::mem::size_of::<Pkcs7Encrypt>() == 16);
    assert!(core::mem::offset_of!(Pkcs7Encrypt, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Encrypt, enc_data) == 8);
};

/// `offsetof(PKCS7, type)` — the ADB selector's offset, and the `type` column's.
const OFFSET_PKCS7_TYPE: c_ulong = 24;
/// `offsetof(PKCS7, d)` — every union arm's offset.
const OFFSET_PKCS7_D: c_ulong = 32;

// ---------------------------------------------------------------------------------------------
// The `ANY DEFINED BY` table — `ASN1_ADB_TEMPLATE`/`ADB_ENTRY`/`ASN1_ADB_END`
// ---------------------------------------------------------------------------------------------

/// The `ASN1_ADB` the ADB-carrying template points at. Wrapped because [`Asn1Adb`] holds raw
/// pointers and is therefore not `Sync`; the wrapper's `unsafe impl` is the same claim
/// [`crate::asn1::layout`] makes for [`Asn1Item`] and [`Asn1Template`].
#[repr(transparent)]
struct SyncAdb(Asn1Adb);

// SAFETY: built from constants — a null callback, a `&'static` table of compiled-in templates and
// two `&'static`/null template pointers — written once by the loader and never again, with no
// interior mutability reachable through a shared reference. The machinery only ever reads it.
unsafe impl Sync for SyncAdb {}

/// `p7default_tt` — `pk7_asn1.c:21`, `ASN1_ADB_TEMPLATE(p7default) = ASN1_EXP_OPT(PKCS7, d.other,
/// ASN1_ANY, 0)`. The template an unmatched content OID uses.
static PKCS7_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
    tag: 0,
    offset: OFFSET_PKCS7_D,
    field_name: c"d.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `PKCS7_adbtbl[]` — `pk7_asn1.c:23-30`, all six arms in the authority's order: `data` (`:24`),
/// `signed` (`:25`), `enveloped` (`:26`), `signedAndEnveloped` (`:27`), `digest` (`:28`) and
/// `encrypted` (`:29`).
static PKCS7_ADBTBL: [Asn1AdbTable; 6] = [
    Asn1AdbTable {
        value: NID_pkcs7_data as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.data".as_ptr(),
            item: ASN1_OCTET_STRING_NDEF_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_signed as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.sign".as_ptr(),
            item: PKCS7_SIGNED_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_enveloped as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.enveloped".as_ptr(),
            item: PKCS7_ENVELOPE_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_signedAndEnveloped as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.signed_and_enveloped".as_ptr(),
            item: PKCS7_SIGN_ENVELOPE_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_digest as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.digest".as_ptr(),
            item: PKCS7_DIGEST_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs7_encrypted as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_NDEF,
            tag: 0,
            offset: OFFSET_PKCS7_D,
            field_name: c"d.encrypted".as_ptr(),
            item: PKCS7_ENCRYPT_it as *mut c_void,
        },
    },
];

/// `PKCS7_adb` — the `ASN1_ADB_END(PKCS7, 0, type, 0, &p7default_tt, NULL)` accessor at `:30`.
/// Selector `type` at offset 24; the default is `p7default_tt` and there is no null arm.
static PKCS7_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: OFFSET_PKCS7_TYPE,
    adb_cb: None,
    tbl: PKCS7_ADBTBL.as_ptr(),
    tblcount: 6,
    default_tt: ptr::addr_of!(PKCS7_DEFAULT_TT),
    null_tt: ptr::null(),
});

/// The `p7default_adb` accessor the `ADB` template stores: it answers the `ASN1_ADB`, which the
/// machinery reads through `call_item_exp` exactly as it reads an item accessor.
fn pkcs7_adb() -> *const c_void {
    ptr::addr_of!(PKCS7_ADB.0).cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// The item callbacks
// ---------------------------------------------------------------------------------------------

/// `pk7_cb` — `pk7_asn1.c:33-58`. The four streaming operations call Phase 12.2's
/// `PKCS7_stream`/`PKCS7_dataInit`/`PKCS7_dataFinal`; every other operation falls through and
/// answers 1.
unsafe extern "C" fn pk7_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    exarg: *mut c_void,
) -> c_int {
    // SAFETY: `exarg` is the `ASN1_STREAM_ARG` the streaming encoder passes; only read on the
    // four streaming arms below.
    let sarg = exarg.cast::<Asn1StreamArg>();
    // SAFETY: `pval` is the item's value slot per the callback contract.
    let pp7 = pval.cast::<*mut Pkcs7>();
    match operation {
        ASN1_OP_STREAM_PRE => {
            // SAFETY: `sarg` is live and `*pp7` is the object being encoded.
            if unsafe { PKCS7_stream(ptr::addr_of_mut!((*sarg).boundary), *pp7) } <= 0 {
                return 0;
            }
            // fall through to DETACHED_PRE, as the authority's `case` does.
            // SAFETY: `sarg` is live and `*pp7` is the object being encoded.
            unsafe {
                (*sarg).ndef_bio = PKCS7_dataInit(*pp7, (*sarg).out);
            };
            // SAFETY: `sarg` is live and its `ndef_bio` is a readable field.
            if unsafe { (*sarg).ndef_bio }.is_null() {
                return 0;
            }
        }
        ASN1_OP_DETACHED_PRE => {
            // SAFETY: `sarg` is live and `*pp7` is the object being encoded.
            unsafe { (*sarg).ndef_bio = PKCS7_dataInit(*pp7, (*sarg).out) };
            // SAFETY: `sarg` is live and its `ndef_bio` is a readable field.
            if unsafe { (*sarg).ndef_bio }.is_null() {
                return 0;
            }
        }
        ASN1_OP_STREAM_POST | ASN1_OP_DETACHED_POST
            // SAFETY: `sarg` is live and `*pp7` is the object being encoded.
            if unsafe { PKCS7_dataFinal(*pp7, (*sarg).ndef_bio) } <= 0 =>
        {
            return 0;
        }
        _ => {}
    }
    1
}

/// The `PKCS7` item's `ASN1_AUX`. Wrapped for the same reason [`crate::asn1::p8_pkey`] wraps its
/// own: [`Asn1Aux`] holds raw pointers and so is not `Sync` by itself.
#[repr(transparent)]
struct SyncAux(Asn1Aux);

// SAFETY: built from constants (a null `app_data`, integer offsets, a `None` const-callback and
// one function pointer), written once by the loader, and with no interior mutability reachable
// through a shared reference. The machinery reads only `asn1_cb` out of it.
unsafe impl Sync for SyncAux {}

/// `static const ASN1_AUX PKCS7_aux = { NULL, 0, 0, 0, pk7_cb, 0, NULL }` —
/// `ASN1_NDEF_SEQUENCE_cb(PKCS7, pk7_cb)` at `pk7_asn1.c:60`.
static PKCS7_AUX: SyncAux = SyncAux(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(pk7_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `ASN1_STREAM_ARG` — `include/openssl/asn1.h`: the boundary, the input/output BIOs and the
/// `ndef_bio` the callback hands back. Modelled where the streaming callback reads it.
#[repr(C)]
struct Asn1StreamArg {
    /// `BIO *out`.
    out: *mut Bio,
    /// `unsigned char ***boundary`.
    boundary: *mut *mut u8,
    /// `BIO *ndef_bio`.
    ndef_bio: *mut Bio,
}

/// A tiny forwarder so `pk7_cb`'s `STREAM_PRE` arm can spell the authority's
/// `PKCS7_dataInit(*pp7, sarg->out)`.
#[allow(dead_code)] // retained to mirror the authority; the landed arm calls `PKCS7_dataInit` directly
fn pkcs7_get_octet_string_address(_p7: *mut Pkcs7) -> *mut Bio {
    ptr::null_mut()
}

/// `si_cb` — `pk7_asn1.c:136-144`. On `ASN1_OP_FREE_POST` the signer's private key, which the
/// item layer does not own, is released.
unsafe extern "C" fn si_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_POST {
        // SAFETY: `pval` is the item's value slot per the callback contract.
        let si = unsafe { *pval }.cast::<Pkcs7SignerInfo>();
        // SAFETY: `si` is a live `PKCS7_SIGNER_INFO` being freed.
        unsafe { EVP_PKEY_free((*si).pkey) };
    }
    1
}

/// `ri_cb` — `pk7_asn1.c:179-187`. On `ASN1_OP_FREE_POST` the recipient's certificate, which the
/// item layer does not own, is released.
unsafe extern "C" fn ri_cb(
    operation: c_int,
    pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    if operation == ASN1_OP_FREE_POST {
        // SAFETY: `pval` is the item's value slot per the callback contract.
        let ri = unsafe { *pval }.cast::<Pkcs7RecipInfo>();
        // SAFETY: `ri` is a live `PKCS7_RECIP_INFO` being freed.
        unsafe { X509_free((*ri).cert) };
    }
    1
}

/// A wrapper holding the `si_cb`/`ri_cb` auxiliaries the same way [`PKCS7_AUX`] holds `pk7_cb`.
#[repr(transparent)]
struct SyncAuxSi(Asn1Aux);
// SAFETY: as [`SyncAux`] — built from constants and only read.
unsafe impl Sync for SyncAuxSi {}
#[repr(transparent)]
struct SyncAuxRi(Asn1Aux);
// SAFETY: as [`SyncAux`] — built from constants and only read.
unsafe impl Sync for SyncAuxRi {}

/// `static const ASN1_AUX PKCS7_SIGNER_INFO_aux = { ..., si_cb, ... }` —
/// `ASN1_SEQUENCE_cb(PKCS7_SIGNER_INFO, si_cb)` at `pk7_asn1.c:146`.
static PKCS7_SIGNER_INFO_AUX: SyncAuxSi = SyncAuxSi(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(si_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

/// `static const ASN1_AUX PKCS7_RECIP_INFO_aux = { ..., ri_cb, ... }` —
/// `ASN1_SEQUENCE_cb(PKCS7_RECIP_INFO, ri_cb)` at `pk7_asn1.c:189`.
static PKCS7_RECIP_INFO_AUX: SyncAuxRi = SyncAuxRi(Asn1Aux {
    app_data: ptr::null_mut(),
    flags: 0,
    ref_offset: 0,
    ref_lock: 0,
    asn1_cb: Some(ri_cb),
    enc_offset: 0,
    asn1_const_cb: None,
});

// ---------------------------------------------------------------------------------------------
// PKCS7_ISSUER_AND_SERIAL
// ---------------------------------------------------------------------------------------------

/// `PKCS7_ISSUER_AND_SERIAL_seq_tt` — `ASN1_SEQUENCE(PKCS7_ISSUER_AND_SERIAL)` at
/// `pk7_asn1.c:163-166`: `issuer` (`X509_NAME`) and `serial` (`ASN1_INTEGER`).
static PKCS7_ISSUER_AND_SERIAL_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"issuer".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"serial".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `PKCS7_ISSUER_AND_SERIAL_it`'s descriptor — `ASN1_SEQUENCE_END` at `:166`.
static PKCS7_ISSUER_AND_SERIAL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_ISSUER_AND_SERIAL_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7IssuerAndSerial>() as c_long,
    sname: c"PKCS7_ISSUER_AND_SERIAL".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ISSUER_AND_SERIAL_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_ISSUER_AND_SERIAL_it() -> *const Asn1Item {
    &PKCS7_ISSUER_AND_SERIAL_ITEM
}

/// `PKCS7_ISSUER_AND_SERIAL *PKCS7_ISSUER_AND_SERIAL_new(void)` — `pk7_asn1.c:168`.
#[no_mangle]
pub extern "C" fn PKCS7_ISSUER_AND_SERIAL_new() -> *mut Pkcs7IssuerAndSerial {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_ISSUER_AND_SERIAL_it()).cast::<Pkcs7IssuerAndSerial>() }
}

/// `void PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ISSUER_AND_SERIAL_free(a: *mut Pkcs7IssuerAndSerial) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_ISSUER_AND_SERIAL_it()) }
}

/// `PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ISSUER_AND_SERIAL(
    a: *mut *mut Pkcs7IssuerAndSerial,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7IssuerAndSerial {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_ISSUER_AND_SERIAL_it()) }
        .cast::<Pkcs7IssuerAndSerial>()
}

/// `int i2d_PKCS7_ISSUER_AND_SERIAL(const PKCS7_ISSUER_AND_SERIAL *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ISSUER_AND_SERIAL(
    a: *const Pkcs7IssuerAndSerial,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_ISSUER_AND_SERIAL_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_SIGNER_INFO
// ---------------------------------------------------------------------------------------------

/// `PKCS7_SIGNER_INFO_seq_tt` — `ASN1_SEQUENCE_cb(PKCS7_SIGNER_INFO, si_cb)` at
/// `pk7_asn1.c:146-159`.
static PKCS7_SIGNER_INFO_TT: [Asn1Template; 7] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"issuer_and_serial".as_ptr(),
        item: PKCS7_ISSUER_AND_SERIAL_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"digest_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 24,
        field_name: c"auth_attr".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 32,
        field_name: c"digest_enc_alg".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"enc_digest".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 48,
        field_name: c"unauth_attr".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
];

/// `PKCS7_SIGNER_INFO_it`'s descriptor — `ASN1_SEQUENCE_END_cb` at `:159`.
static PKCS7_SIGNER_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_SIGNER_INFO_TT.as_ptr(),
    tcount: 7,
    funcs: ptr::addr_of!(PKCS7_SIGNER_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<Pkcs7SignerInfo>() as c_long,
    sname: c"PKCS7_SIGNER_INFO".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_SIGNER_INFO_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGNER_INFO_it() -> *const Asn1Item {
    &PKCS7_SIGNER_INFO_ITEM
}

/// `PKCS7_SIGNER_INFO *PKCS7_SIGNER_INFO_new(void)` — `pk7_asn1.c:161`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGNER_INFO_new() -> *mut Pkcs7SignerInfo {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_SIGNER_INFO_it()).cast::<Pkcs7SignerInfo>() }
}

/// `void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNER_INFO_free(a: *mut Pkcs7SignerInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_SIGNER_INFO_it()) }
}

/// `PKCS7_SIGNER_INFO *d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGNER_INFO(
    a: *mut *mut Pkcs7SignerInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7SignerInfo {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_SIGNER_INFO_it()) }.cast::<Pkcs7SignerInfo>()
}

/// `int i2d_PKCS7_SIGNER_INFO(const PKCS7_SIGNER_INFO *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGNER_INFO(
    a: *const Pkcs7SignerInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_SIGNER_INFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_RECIP_INFO
// ---------------------------------------------------------------------------------------------

/// `PKCS7_RECIP_INFO_seq_tt` — `ASN1_SEQUENCE_cb(PKCS7_RECIP_INFO, ri_cb)` at
/// `pk7_asn1.c:189-194`.
static PKCS7_RECIP_INFO_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"issuer_and_serial".as_ptr(),
        item: PKCS7_ISSUER_AND_SERIAL_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"key_enc_algor".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"enc_key".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `PKCS7_RECIP_INFO_it`'s descriptor — `ASN1_SEQUENCE_END_cb` at `:194`.
static PKCS7_RECIP_INFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_RECIP_INFO_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::addr_of!(PKCS7_RECIP_INFO_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<Pkcs7RecipInfo>() as c_long,
    sname: c"PKCS7_RECIP_INFO".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_RECIP_INFO_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_RECIP_INFO_it() -> *const Asn1Item {
    &PKCS7_RECIP_INFO_ITEM
}

/// `PKCS7_RECIP_INFO *PKCS7_RECIP_INFO_new(void)` — `pk7_asn1.c:196`.
#[no_mangle]
pub extern "C" fn PKCS7_RECIP_INFO_new() -> *mut Pkcs7RecipInfo {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_RECIP_INFO_it()).cast::<Pkcs7RecipInfo>() }
}

/// `void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_RECIP_INFO_free(a: *mut Pkcs7RecipInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_RECIP_INFO_it()) }
}

/// `PKCS7_RECIP_INFO *d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_RECIP_INFO(
    a: *mut *mut Pkcs7RecipInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7RecipInfo {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_RECIP_INFO_it()) }.cast::<Pkcs7RecipInfo>()
}

/// `int i2d_PKCS7_RECIP_INFO(const PKCS7_RECIP_INFO *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_RECIP_INFO(
    a: *const Pkcs7RecipInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_RECIP_INFO_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_SIGNED
// ---------------------------------------------------------------------------------------------

/// `PKCS7_SIGNED_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_SIGNED)` at `pk7_asn1.c:124-131`. The
/// template order differs from the struct's; the offsets map each column to its member.
static PKCS7_SIGNED_TT: [Asn1Template; 6] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"md_algs".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"contents".as_ptr(),
        item: PKCS7_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"cert".as_ptr(),
        item: X509_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 24,
        field_name: c"crl".as_ptr(),
        item: X509_CRL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 32,
        field_name: c"signer_info".as_ptr(),
        item: PKCS7_SIGNER_INFO_it as *mut c_void,
    },
];

/// `PKCS7_SIGNED_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END` at `:131`.
static PKCS7_SIGNED_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_SIGNED_TT.as_ptr(),
    tcount: 6,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7Signed>() as c_long,
    sname: c"PKCS7_SIGNED".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_SIGNED_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGNED_it() -> *const Asn1Item {
    &PKCS7_SIGNED_ITEM
}

/// `PKCS7_SIGNED *PKCS7_SIGNED_new(void)` — `pk7_asn1.c:133`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGNED_new() -> *mut Pkcs7Signed {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_SIGNED_it()).cast::<Pkcs7Signed>() }
}

/// `void PKCS7_SIGNED_free(PKCS7_SIGNED *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGNED_free(a: *mut Pkcs7Signed) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_SIGNED_it()) }
}

/// `PKCS7_SIGNED *d2i_PKCS7_SIGNED(PKCS7_SIGNED **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGNED(
    a: *mut *mut Pkcs7Signed,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7Signed {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_SIGNED_it()) }.cast::<Pkcs7Signed>()
}

/// `int i2d_PKCS7_SIGNED(const PKCS7_SIGNED *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGNED(a: *const Pkcs7Signed, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_SIGNED_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_ENVELOPE
// ---------------------------------------------------------------------------------------------

/// `PKCS7_ENVELOPE_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_ENVELOPE)` at `pk7_asn1.c:170-174`.
static PKCS7_ENVELOPE_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"recipientinfo".as_ptr(),
        item: PKCS7_RECIP_INFO_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"enc_data".as_ptr(),
        item: PKCS7_ENC_CONTENT_it as *mut c_void,
    },
];

/// `PKCS7_ENVELOPE_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END` at `:174`.
static PKCS7_ENVELOPE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_ENVELOPE_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7Envelope>() as c_long,
    sname: c"PKCS7_ENVELOPE".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ENVELOPE_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_ENVELOPE_it() -> *const Asn1Item {
    &PKCS7_ENVELOPE_ITEM
}

/// `PKCS7_ENVELOPE *PKCS7_ENVELOPE_new(void)` — `pk7_asn1.c:176`.
#[no_mangle]
pub extern "C" fn PKCS7_ENVELOPE_new() -> *mut Pkcs7Envelope {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_ENVELOPE_it()).cast::<Pkcs7Envelope>() }
}

/// `void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENVELOPE_free(a: *mut Pkcs7Envelope) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_ENVELOPE_it()) }
}

/// `PKCS7_ENVELOPE *d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENVELOPE(
    a: *mut *mut Pkcs7Envelope,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7Envelope {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_ENVELOPE_it()) }.cast::<Pkcs7Envelope>()
}

/// `int i2d_PKCS7_ENVELOPE(const PKCS7_ENVELOPE *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENVELOPE(
    a: *const Pkcs7Envelope,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_ENVELOPE_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_ENC_CONTENT
// ---------------------------------------------------------------------------------------------

/// `PKCS7_ENC_CONTENT_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_ENC_CONTENT)` at `pk7_asn1.c:198-202`:
/// `content_type`, `algorithm` and the implicit optional `[0]` `enc_data`.
static PKCS7_ENC_CONTENT_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"content_type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"algorithm".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"enc_data".as_ptr(),
        item: ASN1_OCTET_STRING_NDEF_it as *mut c_void,
    },
];

/// `PKCS7_ENC_CONTENT_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END(PKCS7_ENC_CONTENT)` at `:202`.
static PKCS7_ENC_CONTENT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_ENC_CONTENT_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7EncContent>() as c_long,
    sname: c"PKCS7_ENC_CONTENT".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ENC_CONTENT_it(void)` — from `ASN1_NDEF_SEQUENCE_END`.
#[no_mangle]
pub extern "C" fn PKCS7_ENC_CONTENT_it() -> *const Asn1Item {
    &PKCS7_ENC_CONTENT_ITEM
}

/// `PKCS7_ENC_CONTENT *PKCS7_ENC_CONTENT_new(void)` — `pk7_asn1.c:204`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ENC_CONTENT)`.
#[no_mangle]
pub extern "C" fn PKCS7_ENC_CONTENT_new() -> *mut Pkcs7EncContent {
    // SAFETY: `PKCS7_ENC_CONTENT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_ENC_CONTENT_it()).cast::<Pkcs7EncContent>() }
}

/// `void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENC_CONTENT_free(a: *mut Pkcs7EncContent) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_ENC_CONTENT_it()) }
}

/// `PKCS7_ENC_CONTENT *d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENC_CONTENT(
    a: *mut *mut Pkcs7EncContent,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7EncContent {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_ENC_CONTENT_it()) }.cast::<Pkcs7EncContent>()
}

/// `int i2d_PKCS7_ENC_CONTENT(const PKCS7_ENC_CONTENT *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENC_CONTENT(
    a: *const Pkcs7EncContent,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_ENC_CONTENT_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_SIGN_ENVELOPE
// ---------------------------------------------------------------------------------------------

/// `PKCS7_SIGN_ENVELOPE_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_SIGN_ENVELOPE)` at
/// `pk7_asn1.c:206-214`.
static PKCS7_SIGN_ENVELOPE_TT: [Asn1Template; 7] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 48,
        field_name: c"recipientinfo".as_ptr(),
        item: PKCS7_RECIP_INFO_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 8,
        field_name: c"md_algs".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 40,
        field_name: c"enc_data".as_ptr(),
        item: PKCS7_ENC_CONTENT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"cert".as_ptr(),
        item: X509_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 24,
        field_name: c"crl".as_ptr(),
        item: X509_CRL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF,
        tag: 0,
        offset: 32,
        field_name: c"signer_info".as_ptr(),
        item: PKCS7_SIGNER_INFO_it as *mut c_void,
    },
];

/// `PKCS7_SIGN_ENVELOPE_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END` at `:214`.
static PKCS7_SIGN_ENVELOPE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_SIGN_ENVELOPE_TT.as_ptr(),
    tcount: 7,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7SignEnvelope>() as c_long,
    sname: c"PKCS7_SIGN_ENVELOPE".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_SIGN_ENVELOPE_it(void)`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGN_ENVELOPE_it() -> *const Asn1Item {
    &PKCS7_SIGN_ENVELOPE_ITEM
}

/// `PKCS7_SIGN_ENVELOPE *PKCS7_SIGN_ENVELOPE_new(void)` — `pk7_asn1.c:216`.
#[no_mangle]
pub extern "C" fn PKCS7_SIGN_ENVELOPE_new() -> *mut Pkcs7SignEnvelope {
    // SAFETY: the accessor answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_SIGN_ENVELOPE_it()).cast::<Pkcs7SignEnvelope>() }
}

/// `void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_SIGN_ENVELOPE_free(a: *mut Pkcs7SignEnvelope) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_SIGN_ENVELOPE_it()) }
}

/// `PKCS7_SIGN_ENVELOPE *d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_SIGN_ENVELOPE(
    a: *mut *mut Pkcs7SignEnvelope,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7SignEnvelope {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_SIGN_ENVELOPE_it()) }
        .cast::<Pkcs7SignEnvelope>()
}

/// `int i2d_PKCS7_SIGN_ENVELOPE(const PKCS7_SIGN_ENVELOPE *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_SIGN_ENVELOPE(
    a: *const Pkcs7SignEnvelope,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_SIGN_ENVELOPE_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_ENCRYPT
// ---------------------------------------------------------------------------------------------

/// `PKCS7_ENCRYPT_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_ENCRYPT)` at `pk7_asn1.c:218-221`.
static PKCS7_ENCRYPT_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"enc_data".as_ptr(),
        item: PKCS7_ENC_CONTENT_it as *mut c_void,
    },
];

/// `PKCS7_ENCRYPT_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END(PKCS7_ENCRYPT)` at `:221`.
static PKCS7_ENCRYPT_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_ENCRYPT_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7Encrypt>() as c_long,
    sname: c"PKCS7_ENCRYPT".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ENCRYPT_it(void)` — from `ASN1_NDEF_SEQUENCE_END`.
#[no_mangle]
pub extern "C" fn PKCS7_ENCRYPT_it() -> *const Asn1Item {
    &PKCS7_ENCRYPT_ITEM
}

/// `PKCS7_ENCRYPT *PKCS7_ENCRYPT_new(void)` — `pk7_asn1.c:223`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ENCRYPT)`.
#[no_mangle]
pub extern "C" fn PKCS7_ENCRYPT_new() -> *mut Pkcs7Encrypt {
    // SAFETY: `PKCS7_ENCRYPT_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_ENCRYPT_it()).cast::<Pkcs7Encrypt>() }
}

/// `void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_ENCRYPT_free(a: *mut Pkcs7Encrypt) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_ENCRYPT_it()) }
}

/// `PKCS7_ENCRYPT *d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_ENCRYPT(
    a: *mut *mut Pkcs7Encrypt,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7Encrypt {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_ENCRYPT_it()) }.cast::<Pkcs7Encrypt>()
}

/// `int i2d_PKCS7_ENCRYPT(const PKCS7_ENCRYPT *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_ENCRYPT(
    a: *const Pkcs7Encrypt,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_ENCRYPT_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_DIGEST
// ---------------------------------------------------------------------------------------------

/// `PKCS7_DIGEST_seq_tt` — `ASN1_NDEF_SEQUENCE(PKCS7_DIGEST)` at `pk7_asn1.c:225-230`.
static PKCS7_DIGEST_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"md".as_ptr(),
        item: X509_ALGOR_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"contents".as_ptr(),
        item: PKCS7_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"digest".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `PKCS7_DIGEST_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END(PKCS7_DIGEST)` at `:230`.
static PKCS7_DIGEST_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_DIGEST_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs7Digest>() as c_long,
    sname: c"PKCS7_DIGEST".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_DIGEST_it(void)` — from `ASN1_NDEF_SEQUENCE_END`.
#[no_mangle]
pub extern "C" fn PKCS7_DIGEST_it() -> *const Asn1Item {
    &PKCS7_DIGEST_ITEM
}

/// `PKCS7_DIGEST *PKCS7_DIGEST_new(void)` — `pk7_asn1.c:232`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS7_DIGEST)`.
#[no_mangle]
pub extern "C" fn PKCS7_DIGEST_new() -> *mut Pkcs7Digest {
    // SAFETY: `PKCS7_DIGEST_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_DIGEST_it()).cast::<Pkcs7Digest>() }
}

/// `void PKCS7_DIGEST_free(PKCS7_DIGEST *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_DIGEST_free(a: *mut Pkcs7Digest) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS7_DIGEST_it()) }
}

/// `PKCS7_DIGEST *d2i_PKCS7_DIGEST(PKCS7_DIGEST **a, ...)`.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7_DIGEST(
    a: *mut *mut Pkcs7Digest,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7Digest {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS7_DIGEST_it()) }.cast::<Pkcs7Digest>()
}

/// `int i2d_PKCS7_DIGEST(const PKCS7_DIGEST *a, unsigned char **out)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_DIGEST(a: *const Pkcs7Digest, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_DIGEST_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS7_ATTR_SIGN / PKCS7_ATTR_VERIFY
// ---------------------------------------------------------------------------------------------

/// `PKCS7_ATTR_SIGN_item_tt` — `ASN1_ITEM_TEMPLATE(PKCS7_ATTR_SIGN) =
/// ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_ORDER, 0, PKCS7_ATTRIBUTES, X509_ATTRIBUTE)` at
/// `pk7_asn1.c:241`. `ASN1_TFLG_SET_ORDER` is `ASN1_TFLG_SET_OF | ASN1_TFLG_SEQUENCE_OF`, the
/// "sorted set" the signer reorders its attributes to.
static PKCS7_ATTR_SIGN_ITEM_TT: Asn1Template = Asn1Template {
    flags: (ASN1_TFLG_SET_OF | ASN1_TFLG_SEQUENCE_OF),
    tag: 0,
    offset: 0,
    field_name: c"PKCS7_ATTRIBUTES".as_ptr(),
    item: X509_ATTRIBUTE_it as *mut c_void,
};

/// `PKCS7_ATTR_SIGN_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END` at `:242`.
static PKCS7_ATTR_SIGN_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &PKCS7_ATTR_SIGN_ITEM_TT,
    tcount: 0,
    funcs: ptr::null_mut(),
    size: 0,
    sname: c"PKCS7_ATTR_SIGN".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ATTR_SIGN_it(void)` — `include/openssl/pkcs7.h.in:265`.
#[no_mangle]
pub extern "C" fn PKCS7_ATTR_SIGN_it() -> *const Asn1Item {
    &PKCS7_ATTR_SIGN_ITEM
}

/// `PKCS7_ATTR_VERIFY_item_tt` — `ASN1_ITEM_TEMPLATE(PKCS7_ATTR_VERIFY) =
/// ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
/// V_ASN1_SET, PKCS7_ATTRIBUTES, X509_ATTRIBUTE)` at `pk7_asn1.c:249-250`. A `SEQUENCE OF`
/// tagged as a universal `SET`, so the received order is retained.
static PKCS7_ATTR_VERIFY_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_IMPTAG | ASN1_TFLG_UNIVERSAL,
    tag: V_ASN1_SET as c_long,
    offset: 0,
    field_name: c"PKCS7_ATTRIBUTES".as_ptr(),
    item: X509_ATTRIBUTE_it as *mut c_void,
};

/// `PKCS7_ATTR_VERIFY_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END` at `:251`.
static PKCS7_ATTR_VERIFY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &PKCS7_ATTR_VERIFY_ITEM_TT,
    tcount: 0,
    funcs: ptr::null_mut(),
    size: 0,
    sname: c"PKCS7_ATTR_VERIFY".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_ATTR_VERIFY_it(void)` — `include/openssl/pkcs7.h.in:266`.
#[no_mangle]
pub extern "C" fn PKCS7_ATTR_VERIFY_it() -> *const Asn1Item {
    &PKCS7_ATTR_VERIFY_ITEM
}

// ---------------------------------------------------------------------------------------------
// PKCS7
// ---------------------------------------------------------------------------------------------

/// `PKCS7_seq_tt` — `ASN1_NDEF_SEQUENCE_cb(PKCS7, pk7_cb)` at `pk7_asn1.c:60-63`: the `type` OID
/// and the `ASN1_ADB_OBJECT` content.
static PKCS7_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: OFFSET_PKCS7_TYPE,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"PKCS7".as_ptr(),
        item: pkcs7_adb as *mut c_void,
    },
];

/// `PKCS7_it`'s descriptor — `ASN1_NDEF_SEQUENCE_END_cb(PKCS7, PKCS7)` at `:63`.
static PKCS7_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_NDEF_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS7_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::addr_of!(PKCS7_AUX.0).cast::<c_void>(),
    size: core::mem::size_of::<Pkcs7>() as c_long,
    sname: c"PKCS7".as_ptr(),
};

/// `const ASN1_ITEM *PKCS7_it(void)` — from `ASN1_NDEF_SEQUENCE_END_cb(PKCS7, PKCS7)`.
#[no_mangle]
pub extern "C" fn PKCS7_it() -> *const Asn1Item {
    &PKCS7_ITEM
}

/// `PKCS7 *PKCS7_new(void)` — `pk7_asn1.c:88-91`,
/// `(PKCS7 *)ASN1_item_new(ASN1_ITEM_rptr(PKCS7))`.
#[no_mangle]
pub extern "C" fn PKCS7_new() -> *mut Pkcs7 {
    // SAFETY: `PKCS7_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS7_it()).cast::<Pkcs7>() }
}

/// `PKCS7 *PKCS7_new_ex(OSSL_LIB_CTX *libctx, const char *propq)` — `pk7_asn1.c:93-110`.
///
/// The item is allocated with the context and query, then the object's own `ctx` is set: the
/// library context by assignment and a **copy** of the property query. A failed copy releases the
/// object, so a caller never sees a `PKCS7` whose `propq` should have been set and was not.
///
/// # Safety
/// `libctx` is null or a live library context; `propq` is null or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_new_ex(libctx: *mut c_void, propq: *const c_char) -> *mut Pkcs7 {
    // SAFETY: `PKCS7_it()` answers a static item the crate owns; the caller's contract covers
    // `libctx`/`propq`.
    let pkcs7 = unsafe { ASN1_item_new_ex(PKCS7_it(), libctx, propq).cast::<Pkcs7>() };
    if pkcs7.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `pkcs7` is live and its `ctx` slot is writable.
    unsafe {
        (*pkcs7).ctx.libctx = libctx;
        (*pkcs7).ctx.propq = ptr::null_mut();
    }
    if !propq.is_null() {
        // SAFETY: `propq` is NUL-terminated per the caller's contract.
        let copy = unsafe { CRYPTO_strdup(propq, FILE.as_ptr(), 102) };
        if copy.is_null() {
            // SAFETY: `pkcs7` is live and owned here.
            unsafe { PKCS7_free(pkcs7) };
            return ptr::null_mut();
        }
        // SAFETY: `pkcs7` is live and its `ctx.propq` slot is writable.
        unsafe { (*pkcs7).ctx.propq = copy };
    }
    pkcs7
}

/// `void PKCS7_free(PKCS7 *p7)` — `pk7_asn1.c:112-118`. The property query is owned by the object
/// and released first, then the item layer frees the structure.
///
/// # Safety
/// `p7` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_free(p7: *mut Pkcs7) {
    if p7.is_null() {
        return;
    }
    // SAFETY: `p7` is live; its `ctx.propq` is either null or this object's own copy.
    unsafe {
        CRYPTO_free((*p7).ctx.propq.cast(), FILE.as_ptr(), 115);
        ASN1_item_free(p7.cast(), PKCS7_it());
    }
}

/// `PKCS7 *d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len)` — `pk7_asn1.c:65-81`.
///
/// The context is carried from a pre-existing object in `*a` (the authority's `_ex` reads it
/// before decoding) and the decoded object's library context is resolved afterwards.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS7(
    a: *mut *mut Pkcs7,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs7 {
    let mut libctx: *mut c_void = ptr::null_mut();
    let mut propq: *const c_char = ptr::null();
    // SAFETY: `*a` is the caller's live `PKCS7` slot when non-null.
    if !a.is_null() && !unsafe { *a }.is_null() {
        // SAFETY: `*a` is a live `PKCS7` per the caller's contract.
        unsafe {
            libctx = (**a).ctx.libctx;
            propq = (**a).ctx.propq;
        }
    }
    // SAFETY: the caller's contract carries throughout.
    let ret = unsafe {
        crate::asn1::d2i::ASN1_item_d2i_ex(a.cast(), in_, len, PKCS7_it(), libctx, propq)
    }
    .cast::<Pkcs7>();
    if !ret.is_null() {
        // SAFETY: `ret` is a fresh live `PKCS7`.
        unsafe { crate::pkcs7::pk7_lib::ossl_pkcs7_resolve_libctx(ret) };
    }
    ret
}

/// `int i2d_PKCS7(const PKCS7 *a, unsigned char **out)` — `pk7_asn1.c:83-86`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7(a: *const Pkcs7, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS7_it()) }
}

/// `int i2d_PKCS7_NDEF(const PKCS7 *a, unsigned char **out)` — `pk7_asn1.c:120`,
/// `IMPLEMENT_ASN1_NDEF_FUNCTION(PKCS7)`.
///
/// # Safety
/// `a` is NULL or live; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS7_NDEF(a: *const Pkcs7, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_ndef_i2d(a.cast(), out, PKCS7_it()) }
}

/// `PKCS7 *PKCS7_dup(const PKCS7 *x)` — `pk7_asn1.c:122`, `IMPLEMENT_ASN1_DUP_FUNCTION(PKCS7)`.
///
/// # Safety
/// `x` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_dup(x: *const Pkcs7) -> *mut Pkcs7 {
    // SAFETY: the caller's contract; `PKCS7_it()` is a static item.
    unsafe { ASN1_item_dup(PKCS7_it(), x.cast()).cast::<Pkcs7>() }
}

/// `int PKCS7_print_ctx(BIO *out, const PKCS7 *x, int indent, const ASN1_PCTX *pctx)` —
/// `pk7_asn1.c:253`, `IMPLEMENT_ASN1_PRINT_FUNCTION(PKCS7)`.
///
/// # Safety
/// `out` is a live BIO; `x` is NULL or live; `pctx` is NULL or live.
#[no_mangle]
pub unsafe extern "C" fn PKCS7_print_ctx(
    out: *mut Bio,
    x: *const Pkcs7,
    indent: c_int,
    pctx: *const Asn1Pctx,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { ASN1_item_print(out, x.cast(), indent, PKCS7_it(), pctx) }
}
