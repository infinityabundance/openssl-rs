//! `crypto/pkcs12/p12_asn.c` — the PKCS#12 ASN.1 item groups. Phase 10 (10.2).
//!
//! The authority file is 89 lines and four item groups: `PKCS12` itself (the `PFX` structure),
//! `PKCS12_MAC_DATA` (the `MacData`), `PKCS12_BAGS` (the `BagValue` union) and `PKCS12_SAFEBAG`
//! (the `SafeBag`), plus the two `SEQUENCE OF` templates `PKCS12_SAFEBAGS`/`PKCS12_AUTHSAFES`.
//!
//! ## What lands, and what is held open with its blocker
//!
//! Three of the four groups land whole — `PKCS12_MAC_DATA`, `PKCS12_BAGS`, `PKCS12_SAFEBAG` and
//! the `PKCS12_SAFEBAGS` template — together with their `_it`/`_new`/`_free`/`d2i_`/`i2d_` names.
//! The `PKCS12` group itself is **held open**: its `authsafes` column is `ASN1_SIMPLE(PKCS12,
//! authsafes, PKCS7)`, and `PKCS7_it` is `crypto/pkcs7/pk7_asn1.c`'s, which the ownership atlas
//! gives to Phase 12. `PKCS12_it`, `PKCS12_new`, `PKCS12_free`, `d2i_PKCS12`, `i2d_PKCS12` and
//! `PKCS12_AUTHSAFES_it` (the `SEQUENCE OF PKCS7` template) therefore cannot be built until
//! Phase 12 lands the `PKCS7` object; they are left `open` in the ledger rather than stubbed.
//!
//! ## The `PFX` order, and why the struct's order is not it
//!
//! `struct PKCS12_st` (`p12_local.h:28-32`) declares `version`, `mac`, `authsafes`, where the
//! ASN.1 sequence on `p12_asn.c:19-23` is `version`, `authsafes`, `mac`. So a `PKCS12` is a
//! **different** byte order from its C layout, and the transcription must follow the *template*
//! order rather than the struct order. That is part of the identity §3.2 measures; it is the
//! reason the item groups are transcribed by their `ASN1_*` spellings and not from the struct.
//!
//! ## The `ANY DEFINED BY` tables
//!
//! `PKCS12_BAGS`'s value and `PKCS12_SAFEBAG`'s value are `ASN1_ADB_OBJECT` fields, so the union
//! arm is selected by the OID in the preceding `type` column. The tables below are
//! `ASN1_ADB_TEMPLATE`/`ADB_ENTRY`/`ASN1_ADB_END`, in the authority's order, exactly as
//! [`crate::ec::asn1`] transcribed its two.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::p8_pkey::PKCS8_PRIV_KEY_INFO_it;
use crate::asn1::x_sig::{X509Sig, X509_SIG_it};
use crate::runtime::obj::{
    Asn1Object, NID_certBag, NID_crlBag, NID_keyBag, NID_pkcs8ShroudedKeyBag, NID_safeContentsBag,
    NID_sdsiCertificate, NID_secretBag, NID_x509Certificate, NID_x509Crl,
};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x_attrib::X509_ATTRIBUTE_it;

/// `struct PKCS12_MAC_DATA_st` — `crypto/pkcs12/p12_local.h:20-24`. The three members are also
/// the item's three columns, in order: the `DigestInfo`-carrying `X509_SIG`, the salt and the
/// optional iteration count.
#[repr(C)]
pub struct Pkcs12MacData {
    /// `X509_SIG *dinfo` — the digest algorithm and its `MacData` digest.
    pub(crate) dinfo: *mut X509Sig,
    /// `ASN1_OCTET_STRING *salt`.
    pub(crate) salt: *mut Asn1String,
    /// `ASN1_INTEGER *iter` — optional; defaults to 1.
    pub(crate) iter: *mut Asn1String,
}

/// `struct pkcs12_bag_st` — `crypto/pkcs12/p12_local.h:44-53`. `value` is a pointer union whose
/// arm is chosen by the `ASN1_ADB` table; it is modelled as one pointer, the way
/// [`crate::ec::asn1`] models `X9_62_CHARACTERISTIC_TWO`'s, because every arm is the same width.
#[repr(C)]
pub struct Pkcs12Bags {
    /// `ASN1_OBJECT *type` — the `BAG-TYPE` OID, and the ADB selector at offset 0.
    pub(crate) type_: *mut Asn1Object,
    /// The `value` union: `x509cert`/`x509crl`/`octet`/`sdsicert`/`other`, all one pointer.
    pub(crate) value: *mut c_void,
}

/// `struct PKCS12_SAFEBAG_st` — `crypto/pkcs12/p12_local.h:33-42`. The `value` union's arms are
/// `bag`, `keybag`, `shkeybag`, `safes` and `other`; modelled as one pointer for the reason
/// [`Pkcs12Bags`]'s is, with the arm chosen by the `type` OID through the ADB table.
#[repr(C)]
pub struct Pkcs12Safebag {
    /// `ASN1_OBJECT *type` — the `BAG-TYPE` OID, and the ADB selector at offset 0.
    pub(crate) type_: *mut Asn1Object,
    /// The `value` union: `bag`/`keybag`/`shkeybag`/`safes`/`other`, all one pointer.
    pub(crate) value: *mut c_void,
    /// `STACK_OF(X509_ATTRIBUTE) *attrib` — the optional attribute set (`ASN1_SET_OF_OPT`).
    pub(crate) attrib: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<Pkcs12MacData>() == 24);
    assert!(core::mem::offset_of!(Pkcs12MacData, dinfo) == 0);
    assert!(core::mem::offset_of!(Pkcs12MacData, salt) == 8);
    assert!(core::mem::offset_of!(Pkcs12MacData, iter) == 16);
    assert!(core::mem::size_of::<Pkcs12Bags>() == 16);
    assert!(core::mem::offset_of!(Pkcs12Bags, type_) == 0);
    assert!(core::mem::offset_of!(Pkcs12Bags, value) == 8);
    assert!(core::mem::size_of::<Pkcs12Safebag>() == 24);
    assert!(core::mem::offset_of!(Pkcs12Safebag, type_) == 0);
    assert!(core::mem::offset_of!(Pkcs12Safebag, value) == 8);
    assert!(core::mem::offset_of!(Pkcs12Safebag, attrib) == 16);
};

// ---------------------------------------------------------------------------------------------
// The `ANY DEFINED BY` tables — `ASN1_ADB_TEMPLATE`/`ADB_ENTRY`/`ASN1_ADB_END`
// ---------------------------------------------------------------------------------------------

/// The `ASN1_ADB` the ADB-carrying templates point at. Wrapped because [`Asn1Adb`] holds raw
/// pointers and is therefore not `Sync`; the wrapper's `unsafe impl` is the same claim
/// [`crate::asn1::layout`] makes for [`Asn1Item`].
#[repr(transparent)]
struct SyncAdb(Asn1Adb);

// SAFETY: built from constants — a null callback, a `&'static` table of compiled-in templates and
// two `&'static`/null template pointers — written once by the loader and never again, and with no
// interior mutability reachable through a shared reference. The machinery only ever reads it.
unsafe impl Sync for SyncAdb {}

/// `bag_default_tt` — `ASN1_ADB_TEMPLATE(bag_default) = ASN1_EXP(PKCS12_BAGS, value.other,
/// ASN1_ANY, 0)` at `crypto/pkcs12/p12_asn.c:49`.
static BAG_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_EXPLICIT,
    tag: 0,
    offset: 8,
    field_name: c"value.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `PKCS12_BAGS_adbtbl[]` — `crypto/pkcs12/p12_asn.c:51-55`, in the authority's order: the three
/// certificate types, each an explicit `[0]` arm of the same `value` union.
static PKCS12_BAGS_ADBTBL: [Asn1AdbTable; 3] = [
    Asn1AdbTable {
        value: NID_x509Certificate as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.x509cert".as_ptr(),
            item: ASN1_OCTET_STRING_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_x509Crl as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.x509crl".as_ptr(),
            item: ASN1_OCTET_STRING_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_sdsiCertificate as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.sdsicert".as_ptr(),
            item: ASN1_IA5STRING_it as *mut c_void,
        },
    },
];

/// `PKCS12_BAGS_adb` — the `ASN1_ADB_END(PKCS12_BAGS, 0, type, 0, &bag_default_tt, NULL)`
/// accessor at `:55`. Selector `type` at offset 0; the default is `bag_default_tt`.
static PKCS12_BAGS_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: PKCS12_BAGS_ADBTBL.as_ptr(),
    tblcount: 3,
    default_tt: ptr::addr_of!(BAG_DEFAULT_TT),
    null_tt: ptr::null(),
});

/// The `bag_default_adb` accessor the `ADB` template stores: it answers the `ASN1_ADB`, which the
/// machinery reads through `call_item_exp` exactly as it reads an item accessor.
fn pkcs12_bags_adb() -> *const c_void {
    ptr::addr_of!(PKCS12_BAGS_ADB.0).cast::<c_void>()
}

/// `safebag_default_tt` — `ASN1_ADB_TEMPLATE(safebag_default) = ASN1_EXP(PKCS12_SAFEBAG,
/// value.other, ASN1_ANY, 0)` at `crypto/pkcs12/p12_asn.c:64`.
static SAFEBAG_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_EXPLICIT,
    tag: 0,
    offset: 8,
    field_name: c"value.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `PKCS12_SAFEBAG_adbtbl[]` — `crypto/pkcs12/p12_asn.c:66-73`, the six bag types in the
/// authority's order. The fourth through sixth share the `value.bag` arm and the `PKCS12_BAGS`
/// item; the third is the `SEQUENCE OF` safe-contents bag.
static PKCS12_SAFEBAG_ADBTBL: [Asn1AdbTable; 6] = [
    Asn1AdbTable {
        value: NID_keyBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.keybag".as_ptr(),
            item: PKCS8_PRIV_KEY_INFO_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_pkcs8ShroudedKeyBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.shkeybag".as_ptr(),
            item: X509_SIG_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_safeContentsBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF,
            tag: 0,
            offset: 8,
            field_name: c"value.safes".as_ptr(),
            item: PKCS12_SAFEBAG_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_certBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.bag".as_ptr(),
            item: PKCS12_BAGS_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_crlBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.bag".as_ptr(),
            item: PKCS12_BAGS_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_secretBag as c_long,
        tt: Asn1Template {
            flags: ASN1_TFLG_EXPLICIT,
            tag: 0,
            offset: 8,
            field_name: c"value.bag".as_ptr(),
            item: PKCS12_BAGS_it as *mut c_void,
        },
    },
];

/// `PKCS12_SAFEBAG_adb` — the `ASN1_ADB_END(PKCS12_SAFEBAG, 0, type, 0, &safebag_default_tt,
/// NULL)` accessor at `:73`.
static PKCS12_SAFEBAG_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: PKCS12_SAFEBAG_ADBTBL.as_ptr(),
    tblcount: 6,
    default_tt: ptr::addr_of!(SAFEBAG_DEFAULT_TT),
    null_tt: ptr::null(),
});

/// The `safebag_default_adb` accessor the `ADB` template stores.
fn pkcs12_safebag_adb() -> *const c_void {
    ptr::addr_of!(PKCS12_SAFEBAG_ADB.0).cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// PKCS12_MAC_DATA
// ---------------------------------------------------------------------------------------------

/// `PKCS12_MAC_DATA_seq_tt` — `ASN1_SEQUENCE(PKCS12_MAC_DATA)` at `crypto/pkcs12/p12_asn.c:41-45`:
/// `dinfo`, `salt` and the optional `iter`.
static PKCS12_MAC_DATA_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"dinfo".as_ptr(),
        item: X509_SIG_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"salt".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"iter".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `PKCS12_MAC_DATA_it`'s descriptor — `ASN1_SEQUENCE_END(PKCS12_MAC_DATA)` at `:45`.
static PKCS12_MAC_DATA_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS12_MAC_DATA_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs12MacData>() as c_long,
    sname: c"PKCS12_MAC_DATA".as_ptr(),
};

/// `const ASN1_ITEM *PKCS12_MAC_DATA_it(void)` — from `ASN1_SEQUENCE_END(PKCS12_MAC_DATA)`.
#[no_mangle]
pub extern "C" fn PKCS12_MAC_DATA_it() -> *const Asn1Item {
    &PKCS12_MAC_DATA_ITEM
}

/// `PKCS12_MAC_DATA *PKCS12_MAC_DATA_new(void)` — `crypto/pkcs12/p12_asn.c:47`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS12_MAC_DATA)`.
#[no_mangle]
pub extern "C" fn PKCS12_MAC_DATA_new() -> *mut Pkcs12MacData {
    // SAFETY: `PKCS12_MAC_DATA_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS12_MAC_DATA_it()).cast::<Pkcs12MacData>() }
}

/// `void PKCS12_MAC_DATA_free(PKCS12_MAC_DATA *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_MAC_DATA_free(a: *mut Pkcs12MacData) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS12_MAC_DATA_it()) }
}

/// `PKCS12_MAC_DATA *d2i_PKCS12_MAC_DATA(PKCS12_MAC_DATA **a, const unsigned char **in,
/// long len)` — `:47`'s generated decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS12_MAC_DATA(
    a: *mut *mut Pkcs12MacData,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs12MacData {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS12_MAC_DATA_it()).cast::<Pkcs12MacData>() }
}

/// `int i2d_PKCS12_MAC_DATA(const PKCS12_MAC_DATA *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS12_MAC_DATA(
    a: *const Pkcs12MacData,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS12_MAC_DATA_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS12_BAGS
// ---------------------------------------------------------------------------------------------

/// `PKCS12_BAGS_seq_tt` — `ASN1_SEQUENCE(PKCS12_BAGS)` at `crypto/pkcs12/p12_asn.c:57-60`: the
/// `type` OID and the `ASN1_ADB_OBJECT` value.
static PKCS12_BAGS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"PKCS12_BAGS".as_ptr(),
        item: pkcs12_bags_adb as *mut c_void,
    },
];

/// `PKCS12_BAGS_it`'s descriptor — `ASN1_SEQUENCE_END(PKCS12_BAGS)` at `:60`.
static PKCS12_BAGS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS12_BAGS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs12Bags>() as c_long,
    sname: c"PKCS12_BAGS".as_ptr(),
};

/// `const ASN1_ITEM *PKCS12_BAGS_it(void)` — from `ASN1_SEQUENCE_END(PKCS12_BAGS)`.
#[no_mangle]
pub extern "C" fn PKCS12_BAGS_it() -> *const Asn1Item {
    &PKCS12_BAGS_ITEM
}

/// `PKCS12_BAGS *PKCS12_BAGS_new(void)` — `crypto/pkcs12/p12_asn.c:62`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS12_BAGS)`.
#[no_mangle]
pub extern "C" fn PKCS12_BAGS_new() -> *mut Pkcs12Bags {
    // SAFETY: `PKCS12_BAGS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS12_BAGS_it()).cast::<Pkcs12Bags>() }
}

/// `void PKCS12_BAGS_free(PKCS12_BAGS *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_BAGS_free(a: *mut Pkcs12Bags) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS12_BAGS_it()) }
}

/// `PKCS12_BAGS *d2i_PKCS12_BAGS(PKCS12_BAGS **a, const unsigned char **in, long len)` — `:62`'s
/// generated decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS12_BAGS(
    a: *mut *mut Pkcs12Bags,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs12Bags {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS12_BAGS_it()).cast::<Pkcs12Bags>() }
}

/// `int i2d_PKCS12_BAGS(const PKCS12_BAGS *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS12_BAGS(a: *const Pkcs12Bags, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS12_BAGS_it()) }
}

// ---------------------------------------------------------------------------------------------
// PKCS12_SAFEBAG and PKCS12_SAFEBAGS
// ---------------------------------------------------------------------------------------------

/// `PKCS12_SAFEBAG_seq_tt` — `ASN1_SEQUENCE(PKCS12_SAFEBAG)` at `crypto/pkcs12/p12_asn.c:75-79`:
/// the `type` OID, the `ASN1_ADB_OBJECT` value and the optional `ASN1_SET_OF_OPT` attribute set.
static PKCS12_SAFEBAG_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"PKCS12_SAFEBAG".as_ptr(),
        item: pkcs12_safebag_adb as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SET_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 16,
        field_name: c"attrib".as_ptr(),
        item: X509_ATTRIBUTE_it as *mut c_void,
    },
];

/// `PKCS12_SAFEBAG_it`'s descriptor — `ASN1_SEQUENCE_END(PKCS12_SAFEBAG)` at `:79`.
static PKCS12_SAFEBAG_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PKCS12_SAFEBAG_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<Pkcs12Safebag>() as c_long,
    sname: c"PKCS12_SAFEBAG".as_ptr(),
};

/// `const ASN1_ITEM *PKCS12_SAFEBAG_it(void)` — from `ASN1_SEQUENCE_END(PKCS12_SAFEBAG)`.
#[no_mangle]
pub extern "C" fn PKCS12_SAFEBAG_it() -> *const Asn1Item {
    &PKCS12_SAFEBAG_ITEM
}

/// `PKCS12_SAFEBAG *PKCS12_SAFEBAG_new(void)` — `crypto/pkcs12/p12_asn.c:81`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PKCS12_SAFEBAG)`.
#[no_mangle]
pub extern "C" fn PKCS12_SAFEBAG_new() -> *mut Pkcs12Safebag {
    // SAFETY: `PKCS12_SAFEBAG_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PKCS12_SAFEBAG_it()).cast::<Pkcs12Safebag>() }
}

/// `void PKCS12_SAFEBAG_free(PKCS12_SAFEBAG *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PKCS12_SAFEBAG_free(a: *mut Pkcs12Safebag) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PKCS12_SAFEBAG_it()) }
}

/// `PKCS12_SAFEBAG *d2i_PKCS12_SAFEBAG(PKCS12_SAFEBAG **a, const unsigned char **in, long len)` —
/// `:81`'s generated decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PKCS12_SAFEBAG(
    a: *mut *mut Pkcs12Safebag,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Pkcs12Safebag {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PKCS12_SAFEBAG_it()).cast::<Pkcs12Safebag>() }
}

/// `int i2d_PKCS12_SAFEBAG(const PKCS12_SAFEBAG *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PKCS12_SAFEBAG(
    a: *const Pkcs12Safebag,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PKCS12_SAFEBAG_it()) }
}

/// `PKCS12_SAFEBAGS_item_tt` — `ASN1_ITEM_TEMPLATE(PKCS12_SAFEBAGS)` at
/// `crypto/pkcs12/p12_asn.c:84-85`, an `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
/// PKCS12_SAFEBAGS, PKCS12_SAFEBAG)`.
static PKCS12_SAFEBAGS_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"PKCS12_SAFEBAGS".as_ptr(),
    item: PKCS12_SAFEBAG_it as *mut c_void,
};

/// `PKCS12_SAFEBAGS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(PKCS12_SAFEBAGS)` at `:85`: a
/// `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`, `tcount` 0.
static PKCS12_SAFEBAGS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &PKCS12_SAFEBAGS_ITEM_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"PKCS12_SAFEBAGS".as_ptr(),
};

/// `const ASN1_ITEM *PKCS12_SAFEBAGS_it(void)` — from `ASN1_ITEM_TEMPLATE_END(PKCS12_SAFEBAGS)`.
#[no_mangle]
pub extern "C" fn PKCS12_SAFEBAGS_it() -> *const Asn1Item {
    &PKCS12_SAFEBAGS_ITEM
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_set};
    use crate::asn1::string::{ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
    use crate::runtime::obj::{NID_secretBag, OBJ_nid2obj, OBJ_obj2nid};

    /// A `PKCS12_SAFEBAG` built by hand — a secret bag whose value is a fixed octet string —
    /// round-trips through its own item. The octets are a literal the test chose, so nothing
    /// random or private is touched.
    #[test]
    fn safebag_item_round_trips() {
        // The item layer and the object table are process-global state.
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions; the secret-bag fields are set below.
        let bag = unsafe {
            let b = PKCS12_SAFEBAG_new();
            assert!(!b.is_null());
            let inner = PKCS12_BAGS_new();
            assert!(!inner.is_null());
            (*inner).type_ = OBJ_nid2obj(NID_secretBag);
            let oct = ASN1_OCTET_STRING_new();
            let value: [u8; 2] = [0xde, 0xad];
            ASN1_OCTET_STRING_set(oct, value.as_ptr(), 2);
            let any = ASN1_TYPE_new();
            ASN1_TYPE_set(any, V_ASN1_OCTET_STRING, oct.cast());
            (*inner).value = any.cast();
            (*b).type_ = OBJ_nid2obj(NID_secretBag);
            (*b).value = inner.cast();
            b
        };
        let mut out: *mut c_uchar = ptr::null_mut();
        // SAFETY: `bag` is live and `out` is this frame's own cursor.
        let len = unsafe { i2d_PKCS12_SAFEBAG(bag, &mut out) };
        assert!(len > 0 && !out.is_null());
        let decoded = {
            let mut p: *const c_uchar = out;
            // SAFETY: the cursor is this frame's own and `out`/`len` describe a fresh encoding.
            unsafe { d2i_PKCS12_SAFEBAG(ptr::null_mut(), &mut p, len as c_long) }
        };
        assert!(!decoded.is_null());
        // SAFETY: `decoded` is live and its `type` is its own object.
        unsafe {
            assert_eq!(OBJ_obj2nid((*decoded).type_), NID_secretBag);
            PKCS12_SAFEBAG_free(decoded);
            PKCS12_SAFEBAG_free(bag);
            crate::runtime::mem::CRYPTO_free(out.cast(), ptr::null(), 0);
        }
    }

    /// The `PKCS12_BAGS` item round-trips a fixed `BAG-TYPE` value; a fresh one has a null value
    /// because an `ANY DEFINED BY` column is not allocated until the selector is known.
    #[test]
    fn bags_new_leaves_the_adb_value_null() {
        // The item layer is process-global state.
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let b = PKCS12_BAGS_new();
        assert!(!b.is_null());
        // SAFETY: `b` is fresh, so its selector and value are its own nulls.
        unsafe {
            assert!((*b).value.is_null());
            assert!((*b).type_.is_null());
            PKCS12_BAGS_free(b);
        }
    }
}
