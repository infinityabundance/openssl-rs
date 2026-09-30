//! `crypto/pkcs7/pk7_asn1.c` — the `PKCS7` object's ASN.1 item group, pulled forward so the
//! `PKCS12` container can be built. Phase 10 (the PKCS#12 landing D441 blocked).
//!
//! ## What lands
//!
//! The `PKCS7` item itself (`PKCS7_it`/`_new`/`_new_ex`/`_free`) and the three of its six
//! `ANY DEFINED BY` arms whose item closure is landed — `data`, `digest` and `encrypted`, with
//! `PKCS7_ENC_CONTENT`, `PKCS7_ENCRYPT` and `PKCS7_DIGEST` whole. The three arms a PKCS#12
//! container never reaches (`signed`, `enveloped`, `signedAndEnveloped`) are withheld: their
//! templates name Phase 11's `X509_it`, `X509_CRL_it` and `X509_NAME_it`, which are not landed,
//! so the descriptors cannot be built. `mod.rs` records that measurement.
//!
//! ## The `pk7_cb` streaming arms
//!
//! `ASN1_NDEF_SEQUENCE_cb(PKCS7, pk7_cb)` gives the item a callback. Four of its arms
//! (`ASN1_OP_STREAM_PRE`/`_POST`, `ASN1_OP_DETACHED_PRE`/`_POST`) call Phase 12's `PKCS7_stream`,
//! `PKCS7_dataInit` and `PKCS7_dataFinal`, which this subset does not carry; the authority's
//! remaining arms all fall through and answer 1. The callback below therefore answers 1 for every
//! operation the crate's ASN.1 machinery can reach, and 0 for the four streaming arms, which no
//! path in this crate invokes (`crypto/asn1/bio_asn1.c`'s streaming BIO is the only caller and is
//! not in the PKCS#12 closure). Transcribing the arms as the authority has them would require the
//! three functions, so they are recorded rather than stubbed.
//!
//! ## The bytes are the contract
//!
//! Each template is the authority's own `ASN1_*` spelling, in its order, with its `ASN1_TFLG_*`
//! set: the `data` arm is `ASN1_NDEF_EXP_OPT` over `ASN1_OCTET_STRING_NDEF`, the `PKCS7` item is
//! an `ASN1_ITYPE_NDEF_SEQUENCE`, and the `type` selector sits at offset 24 with the union at 32.
//! `docs/PHASE-10-SUBPHASES.md` §3.2 is why a round trip is not enough.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_NDEF_it, ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::{ASN1_item_new, ASN1_item_new_ex};
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_it};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::{Asn1Object, NID_pkcs7_data, NID_pkcs7_digest, NID_pkcs7_encrypted};

/// The authority translation unit for this module.
pub(crate) const FILE: &core::ffi::CStr = c"crypto/pkcs7/pk7_asn1.c";

/// `PKCS7_CTX` — `include/openssl/pkcs7.h.in:49-52`. The library context and property query a
/// `PKCS7` resolves its fetches in; embedded in the object at offset 40.
#[repr(C)]
pub struct Pkcs7Ctx {
    /// `OSSL_LIB_CTX *libctx`.
    pub(crate) libctx: *mut c_void,
    /// `char *propq` — owned by the `PKCS7`, freed by [`PKCS7_free`].
    pub(crate) propq: *mut c_char,
}

/// `struct pkcs7_st`'s `d` union — `pkcs7.h.in:158-174`. Every arm is a pointer, so the union is
/// one pointer wide and each arm has the union's offset. The `sign`, `enveloped` and
/// `signed_and_enveloped` arms are modelled untyped because their item groups are withheld.
#[repr(C)]
pub union Pkcs7D {
    /// `char *ptr` — the null test `ossl_pkcs7_resolve_libctx` and friends use.
    pub(crate) ptr: *mut c_void,
    /// `ASN1_OCTET_STRING *data` — `NID_pkcs7_data`.
    pub(crate) data: *mut crate::asn1::layout::Asn1String,
    /// `PKCS7_SIGNED *sign` — `NID_pkcs7_signed`; the item group is withheld.
    pub(crate) sign: *mut c_void,
    /// `PKCS7_ENVELOPE *enveloped` — `NID_pkcs7_enveloped`; the item group is withheld.
    pub(crate) enveloped: *mut c_void,
    /// `PKCS7_SIGN_ENVELOPE *signed_and_enveloped`; the item group is withheld.
    pub(crate) signed_and_enveloped: *mut c_void,
    /// `PKCS7_DIGEST *digest` — `NID_pkcs7_digest`.
    pub(crate) digest: *mut Pkcs7Digest,
    /// `PKCS7_ENCRYPT *encrypted` — `NID_pkcs7_encrypted`.
    pub(crate) encrypted: *mut Pkcs7Encrypt,
    /// `ASN1_TYPE *other` — the `ASN1_ADB` default arm.
    pub(crate) other: *mut crate::asn1::layout::Asn1Type,
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

/// `struct pkcs7_enc_content_st` — `pkcs7.h.in:104-110`. Only the four template columns and the
/// context are load-bearing here; `cipher` is the fetched cipher the authority caches.
#[repr(C)]
pub struct Pkcs7EncContent {
    /// `ASN1_OBJECT *content_type`.
    pub(crate) content_type: *mut Asn1Object,
    /// `X509_ALGOR *algorithm`.
    pub(crate) algorithm: *mut X509Algor,
    /// `ASN1_OCTET_STRING *enc_data` — `[0] IMPLICIT OPTIONAL`.
    pub(crate) enc_data: *mut crate::asn1::layout::Asn1String,
    /// `const EVP_CIPHER *cipher`.
    pub(crate) cipher: *const c_void,
    /// `const PKCS7_CTX *ctx`.
    pub(crate) ctx: *const Pkcs7Ctx,
}

/// `struct pkcs7_encrypted_st` — `pkcs7.h.in:135-138`.
#[repr(C)]
pub struct Pkcs7Encrypt {
    /// `ASN1_INTEGER *version`.
    pub(crate) version: *mut crate::asn1::layout::Asn1String,
    /// `PKCS7_ENC_CONTENT *enc_data`.
    pub(crate) enc_data: *mut Pkcs7EncContent,
}

/// `struct pkcs7_digest_st` — `pkcs7.h.in:128-133`.
#[repr(C)]
pub struct Pkcs7Digest {
    /// `ASN1_INTEGER *version`.
    pub(crate) version: *mut crate::asn1::layout::Asn1String,
    /// `X509_ALGOR *md`.
    pub(crate) md: *mut X509Algor,
    /// `struct pkcs7_st *contents` — the digested contentInfo.
    pub(crate) contents: *mut Pkcs7,
    /// `ASN1_OCTET_STRING *digest`.
    pub(crate) digest: *mut crate::asn1::layout::Asn1String,
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
    assert!(core::mem::size_of::<Pkcs7EncContent>() == 40);
    assert!(core::mem::offset_of!(Pkcs7EncContent, content_type) == 0);
    assert!(core::mem::offset_of!(Pkcs7EncContent, algorithm) == 8);
    assert!(core::mem::offset_of!(Pkcs7EncContent, enc_data) == 16);
    assert!(core::mem::offset_of!(Pkcs7EncContent, cipher) == 24);
    assert!(core::mem::offset_of!(Pkcs7EncContent, ctx) == 32);
    assert!(core::mem::size_of::<Pkcs7Encrypt>() == 16);
    assert!(core::mem::offset_of!(Pkcs7Encrypt, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Encrypt, enc_data) == 8);
    assert!(core::mem::size_of::<Pkcs7Digest>() == 32);
    assert!(core::mem::offset_of!(Pkcs7Digest, version) == 0);
    assert!(core::mem::offset_of!(Pkcs7Digest, md) == 8);
    assert!(core::mem::offset_of!(Pkcs7Digest, contents) == 16);
    assert!(core::mem::offset_of!(Pkcs7Digest, digest) == 24);
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

/// `PKCS7_adbtbl[]` — `pk7_asn1.c:23-30`, the authority's entries for the three arms whose item
/// closure is landed, in the authority's order: `data` (`:24`), `digest` (`:28`) and `encrypted`
/// (`:29`). The `signed` (`:25`), `enveloped` (`:26`) and `signedAndEnveloped` (`:27`) entries are
/// withheld with their Phase 11 item dependencies and are listed in `mod.rs`.
static PKCS7_ADBTBL: [Asn1AdbTable; 3] = [
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
    tblcount: 3,
    default_tt: ptr::addr_of!(PKCS7_DEFAULT_TT),
    null_tt: ptr::null(),
});

/// The `p7default_adb` accessor the `ADB` template stores: it answers the `ASN1_ADB`, which the
/// machinery reads through `call_item_exp` exactly as it reads an item accessor.
fn pkcs7_adb() -> *const c_void {
    ptr::addr_of!(PKCS7_ADB.0).cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// The item callback
// ---------------------------------------------------------------------------------------------

/// `pk7_cb` — `pk7_asn1.c:33-58`. The authority's arms for `STREAM`/`DETACHED` call Phase 12's
/// `PKCS7_stream`/`PKCS7_dataInit`/`PKCS7_dataFinal`, which this subset does not carry; every
/// other operation falls through and answers 1. The four streaming arms are therefore the only
/// ones that answer 0, and no path in this crate invokes them (`mod.rs` records the measurement).
unsafe extern "C" fn pk7_cb(
    operation: c_int,
    _pval: *mut *mut c_void,
    _it: *const Asn1Item,
    _exarg: *mut c_void,
) -> c_int {
    match operation {
        ASN1_OP_STREAM_PRE | ASN1_OP_STREAM_POST | ASN1_OP_DETACHED_PRE | ASN1_OP_DETACHED_POST => {
            0
        }
        _ => 1,
    }
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
