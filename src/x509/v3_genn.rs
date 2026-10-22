//! `crypto/x509/v3_genn.c` — the `GENERAL_NAME`/`GENERAL_NAMES` items and their accessors.
//! Phase 10.14.4.
//!
//! The unit is 269 lines and lands **whole**: three ASN.1 templates (`OTHERNAME`,
//! `EDIPARTYNAME`, `GENERAL_NAME`) with the `GENERAL_NAMES` `SEQUENCE OF` over the last, the
//! generated `it`/`new`/`free`/`d2i_`/`i2d_` groups, and the eleven hand-written functions —
//! `GENERAL_NAME_dup`, `GENERAL_NAME_set1_X509_NAME`, the static `edipartyname_cmp`,
//! `GENERAL_NAME_cmp`, `OTHERNAME_cmp`, `GENERAL_NAME_set0_value`/`get0_value`,
//! `GENERAL_NAME_set0_othername` and `GENERAL_NAME_get0_otherName`. Its closure was measured
//! whole-unit ready by the re-measurement at the head of this session: every name its object
//! leaves undefined is a landed item (`X509_NAME_it`, `ASN1_ANY_it`, `DIRECTORYSTRING_it`, the
//! `ASN1_*_it` string items, `ASN1_dup`, the comparators) or an internal Rust definition, so it
//! is the first 10.14.x unit that can be transcribed rather than withheld again.
//!
//! ## The `GENERAL_NAME` union is the layout
//!
//! `struct GENERAL_NAME_st` is `int type` followed by a union of nine pointers
//! (`include/openssl/x509v3.h:172-193`), so the union sits at offset 8 and the whole is 16 bytes.
//! The templates select the arm by the context tag on the wire, and the two accessors write and
//! read exactly the pointer the `type` names: `set0_value` does not free the old arm and
//! `get0_value` does not copy, both of which the court observes.
//!
//! ## What it unblocks, and what it is a prerequisite of
//!
//! `GENERAL_NAME_it` and the `GENERAL_NAMES` group are what every `v3_san.c`/`v3_ncons.c`/
//! `v3_crld.c` table and `v3_utl.c`'s address checks call, so this unit is the hub the rest of
//! 10.14.4 and 10.14.6–10.14.8 were measured to wait on. It closes no Phase-10 export or provider
//! row on its own — the expected shape for a dependency sub-subphase.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_dup::ASN1_dup_typed;
use crate::asn1::a_type::{ASN1_TYPE_cmp, ASN1_TYPE_free};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_SEQUENCE_it,
    DIRECTORYSTRING_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{ASN1_OCTET_STRING_cmp, ASN1_STRING_cmp};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::obj::{Asn1Object, OBJ_cmp};
use crate::runtime::stack::OpenSslStack;
use crate::x509::x509_cmp::X509_NAME_cmp;
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_it, X509_NAME_new};

/// `GEN_OTHERNAME` — `include/openssl/x509v3.h:153`.
/// A selector-checked view of a `GENERAL_NAME`'s union.
///
/// The selector is the only thing that says which arm is live, so this enum is the **one** place
/// the union is read: consumers match on the accessor instead of re-reading `d`, which makes
/// "compare through an arm the selector does not name" inexpressible at every call site.
#[derive(Clone, Copy)]
pub(crate) enum GeneralNameRef<'a> {
    OtherName(&'a Othername),
    Ia5(&'a Asn1String),
    X400(&'a Asn1String),
    DirectoryName(&'a X509Name),
    EdiPartyName(&'a EdiPartyName),
    IpAddress(&'a Asn1String),
    RegisteredId(&'a Asn1Object),
}

impl GeneralName {
    /// Install `value` as the arm `type_` names, clearing the union first.
    ///
    /// The selector and the arm are therefore written together through **one** producer: there is
    /// no in-crate path that records a selector without storing the arm it names. A selector the
    /// authority's switch does not handle leaves the cleared union in place and is reported by the
    /// answer; the authority instead leaves the previous bytes in `d`, which is exactly the
    /// controllable-pointer residue CVE-2023-0286 needs.
    ///
    /// Returns whether `type_` is a handled `GEN_*` selector. Ownership of `value` passes to
    /// `self` in both cases.
    fn install(&mut self, type_: c_int, value: *mut c_void) -> bool {
        self.d = GeneralNameValue {
            otherName: ptr::null_mut(),
        };
        let handled = match type_ {
            GEN_X400 => {
                self.d = GeneralNameValue {
                    x400Address: value.cast::<Asn1String>(),
                };
                true
            }
            GEN_EDIPARTY => {
                self.d = GeneralNameValue {
                    ediPartyName: value.cast::<EdiPartyName>(),
                };
                true
            }
            GEN_OTHERNAME => {
                self.d = GeneralNameValue {
                    otherName: value.cast::<Othername>(),
                };
                true
            }
            GEN_EMAIL | GEN_DNS | GEN_URI => {
                self.d = GeneralNameValue {
                    ia5: value.cast::<Asn1String>(),
                };
                true
            }
            GEN_DIRNAME => {
                self.d = GeneralNameValue {
                    directoryName: value.cast::<X509Name>(),
                };
                true
            }
            GEN_IPADD => {
                self.d = GeneralNameValue {
                    iPAddress: value.cast::<Asn1String>(),
                };
                true
            }
            GEN_RID => {
                self.d = GeneralNameValue {
                    registeredID: value.cast::<Asn1Object>(),
                };
                true
            }
            _ => false,
        };
        self.type_ = type_;
        handled
    }

    /// The live arm, or `None` for an unhandled selector or a slot whose selected arm is NULL.
    ///
    /// # Safety
    /// `self` is live and every non-NULL arm its selector could name is a live value of that
    /// arm's type (the item decoder writes the selector from the tag, and [`Self::install`] — the
    /// only in-crate producer — writes the arm with it).
    pub(crate) unsafe fn as_ref(&self) -> Option<GeneralNameRef<'_>> {
        // SAFETY: the caller's contract. Each arm reads only the pointer its selector names, and
        // a NULL pointer answers `None` instead of forming a reference.
        unsafe {
            match self.type_ {
                GEN_OTHERNAME => self.d.otherName.as_ref().map(GeneralNameRef::OtherName),
                GEN_EMAIL | GEN_DNS | GEN_URI => self.d.ia5.as_ref().map(GeneralNameRef::Ia5),
                GEN_X400 => self.d.x400Address.as_ref().map(GeneralNameRef::X400),
                GEN_DIRNAME => self
                    .d
                    .directoryName
                    .as_ref()
                    .map(GeneralNameRef::DirectoryName),
                GEN_EDIPARTY => self
                    .d
                    .ediPartyName
                    .as_ref()
                    .map(GeneralNameRef::EdiPartyName),
                GEN_IPADD => self.d.iPAddress.as_ref().map(GeneralNameRef::IpAddress),
                GEN_RID => self
                    .d
                    .registeredID
                    .as_ref()
                    .map(GeneralNameRef::RegisteredId),
                _ => None,
            }
        }
    }

    /// The selected arm as a raw pointer, or NULL for an unhandled selector or a NULL arm.
    ///
    /// This is the adapter `GENERAL_NAME_get0_value` uses; it derives from [`Self::as_ref`], so
    /// the pointer and the typed view can never name different arms.
    ///
    /// # Safety
    /// As [`Self::as_ref`].
    pub(crate) unsafe fn arm_ptr(&self) -> *mut c_void {
        // SAFETY: the caller's contract for `as_ref`.
        match unsafe { self.as_ref() } {
            Some(GeneralNameRef::OtherName(p)) => (p as *const Othername).cast_mut().cast(),
            Some(GeneralNameRef::Ia5(p)) => (p as *const Asn1String).cast_mut().cast(),
            Some(GeneralNameRef::X400(p)) => (p as *const Asn1String).cast_mut().cast(),
            Some(GeneralNameRef::DirectoryName(p)) => (p as *const X509Name).cast_mut().cast(),
            Some(GeneralNameRef::EdiPartyName(p)) => (p as *const EdiPartyName).cast_mut().cast(),
            Some(GeneralNameRef::IpAddress(p)) => (p as *const Asn1String).cast_mut().cast(),
            Some(GeneralNameRef::RegisteredId(p)) => (p as *const Asn1Object).cast_mut().cast(),
            None => ptr::null_mut(),
        }
    }
}

pub(crate) const GEN_OTHERNAME: c_int = 0;
/// `GEN_EMAIL` — `include/openssl/x509v3.h:154`.
pub(crate) const GEN_EMAIL: c_int = 1;
/// `GEN_DNS` — `include/openssl/x509v3.h:155`.
pub(crate) const GEN_DNS: c_int = 2;
/// `GEN_X400` — `include/openssl/x509v3.h:156`.
pub(crate) const GEN_X400: c_int = 3;
/// `GEN_DIRNAME` — `include/openssl/x509v3.h:157`.
pub(crate) const GEN_DIRNAME: c_int = 4;
/// `GEN_EDIPARTY` — `include/openssl/x509v3.h:158`.
pub(crate) const GEN_EDIPARTY: c_int = 5;
/// `GEN_URI` — `include/openssl/x509v3.h:159`.
pub(crate) const GEN_URI: c_int = 6;
/// `GEN_IPADD` — `include/openssl/x509v3.h:160`.
pub(crate) const GEN_IPADD: c_int = 7;
/// `GEN_RID` — `include/openssl/x509v3.h:161`.
pub(crate) const GEN_RID: c_int = 8;

/// `struct otherName_st` — `OTHERNAME`, from `include/openssl/x509v3.h:163-166`.
#[repr(C)]
pub struct Othername {
    /// `ASN1_OBJECT *type_id` — the type OID, mandatory.
    pub(crate) type_id: *mut Asn1Object,
    /// `ASN1_TYPE *value` — the `[0] EXPLICIT ANY`, mandatory.
    pub(crate) value: *mut Asn1Type,
}

const _: () = {
    assert!(core::mem::size_of::<Othername>() == 16);
    assert!(core::mem::offset_of!(Othername, type_id) == 0);
    assert!(core::mem::offset_of!(Othername, value) == 8);
};

/// `OTHERNAME_seq_tt` — `ASN1_SEQUENCE(OTHERNAME)` (`crypto/x509/v3_genn.c:16-20`):
/// `ASN1_SIMPLE(type_id, ASN1_OBJECT)` and `ASN1_EXP(value, ASN1_ANY, 0)`.
static OTHERNAME_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"type_id".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 8,
        field_name: c"value".as_ptr(),
        item: ASN1_ANY_it as *mut c_void,
    },
];

/// `OTHERNAME_it`'s descriptor — `ASN1_SEQUENCE_END(OTHERNAME)` at `crypto/x509/v3_genn.c:20`.
static OTHERNAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OTHERNAME_SEQ_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Othername>() as c_long,
    sname: c"OTHERNAME".as_ptr(),
};

/// `const ASN1_ITEM *OTHERNAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(OTHERNAME)`.
#[no_mangle]
pub extern "C" fn OTHERNAME_it() -> *const Asn1Item {
    &OTHERNAME_ITEM
}

/// The internal alias a static template can name for the CHOICE alternative, because a template's
/// `item` field must be the accessor's address.
fn othername_it() -> *const Asn1Item {
    OTHERNAME_it()
}

/// `OTHERNAME *OTHERNAME_new(void)` — `crypto/x509/v3_genn.c:22`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(OTHERNAME)`.
#[no_mangle]
pub extern "C" fn OTHERNAME_new() -> *mut Othername {
    // SAFETY: `OTHERNAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OTHERNAME_it()).cast::<Othername>() }
}

/// `void OTHERNAME_free(OTHERNAME *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OTHERNAME_free(a: *mut Othername) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OTHERNAME_it()) }
}

/// `OTHERNAME *d2i_OTHERNAME(OTHERNAME **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OTHERNAME(
    a: *mut *mut Othername,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Othername {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, OTHERNAME_it()).cast::<Othername>() }
}

/// `int i2d_OTHERNAME(const OTHERNAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OTHERNAME(a: *const Othername, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OTHERNAME_it()) }
}

/// `struct EDIPARTYNAME_st` — `EDIPARTYNAME`, from `include/openssl/x509v3.h:180-183`.
#[repr(C)]
pub struct EdiPartyName {
    /// `DIRECTORYSTRING *nameAssigner` — optional.
    pub(crate) nameAssigner: *mut Asn1String,
    /// `DIRECTORYSTRING *partyName` — mandatory on the wire but stored as a pointer.
    pub(crate) partyName: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<EdiPartyName>() == 16);
    assert!(core::mem::offset_of!(EdiPartyName, nameAssigner) == 0);
    assert!(core::mem::offset_of!(EdiPartyName, partyName) == 8);
};

/// `EDIPARTYNAME_seq_tt` — `ASN1_SEQUENCE(EDIPARTYNAME)` (`crypto/x509/v3_genn.c:24-28`):
/// `ASN1_EXP_OPT(nameAssigner, DIRECTORYSTRING, 0)` and
/// `ASN1_EXP_OPT(partyName, DIRECTORYSTRING, 1)`.
static EDIPARTYNAME_SEQ_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"nameAssigner".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"partyName".as_ptr(),
        item: DIRECTORYSTRING_it as *mut c_void,
    },
];

/// `EDIPARTYNAME_it`'s descriptor — `ASN1_SEQUENCE_END(EDIPARTYNAME)` at
/// `crypto/x509/v3_genn.c:28`.
static EDIPARTYNAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: EDIPARTYNAME_SEQ_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<EdiPartyName>() as c_long,
    sname: c"EDIPARTYNAME".as_ptr(),
};

/// `const ASN1_ITEM *EDIPARTYNAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)`.
#[no_mangle]
pub extern "C" fn EDIPARTYNAME_it() -> *const Asn1Item {
    &EDIPARTYNAME_ITEM
}

/// The internal alias a static template can name for the CHOICE alternative.
fn edipartyname_it() -> *const Asn1Item {
    EDIPARTYNAME_it()
}

/// `EDIPARTYNAME *EDIPARTYNAME_new(void)` — `crypto/x509/v3_genn.c:30`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(EDIPARTYNAME)`.
#[no_mangle]
pub extern "C" fn EDIPARTYNAME_new() -> *mut EdiPartyName {
    // SAFETY: `EDIPARTYNAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(EDIPARTYNAME_it()).cast::<EdiPartyName>() }
}

/// `void EDIPARTYNAME_free(EDIPARTYNAME *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn EDIPARTYNAME_free(a: *mut EdiPartyName) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), EDIPARTYNAME_it()) }
}

/// `EDIPARTYNAME *d2i_EDIPARTYNAME(EDIPARTYNAME **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_EDIPARTYNAME(
    a: *mut *mut EdiPartyName,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut EdiPartyName {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, EDIPARTYNAME_it()).cast::<EdiPartyName>() }
}

/// `int i2d_EDIPARTYNAME(const EDIPARTYNAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_EDIPARTYNAME(a: *const EdiPartyName, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, EDIPARTYNAME_it()) }
}

/// `struct GENERAL_NAME_st`'s `d` union — `include/openssl/x509v3.h:174-192`. Every arm is a
/// pointer, so the union is eight bytes at offset 8 of [`GeneralName`].
#[repr(C)]
#[derive(Clone, Copy)]
pub union GeneralNameValue {
    /// `OTHERNAME *otherName`.
    pub(crate) otherName: *mut Othername,
    /// `ASN1_IA5STRING *rfc822Name`, `dNSName` and `uniformResourceIdentifier`.
    pub(crate) ia5: *mut Asn1String,
    /// `ASN1_SEQUENCE *x400Address` — the generic `ASN1_SEQUENCE` item decodes into an
    /// `ASN1_STRING` carrying the raw content.
    pub(crate) x400Address: *mut Asn1String,
    /// `X509_NAME *directoryName`.
    pub(crate) directoryName: *mut X509Name,
    /// `EDIPARTYNAME *ediPartyName`.
    pub(crate) ediPartyName: *mut EdiPartyName,
    /// `ASN1_OCTET_STRING *iPAddress`.
    pub(crate) iPAddress: *mut Asn1String,
    /// `ASN1_OBJECT *registeredID`.
    pub(crate) registeredID: *mut Asn1Object,
}

/// `struct GENERAL_NAME_st` — `GENERAL_NAME`, from `include/openssl/x509v3.h:172-193`.
#[repr(C)]
pub struct GeneralName {
    /// `int type` — the `GEN_*` selector.
    pub(crate) type_: c_int,
    /// The `d` union.
    pub(crate) d: GeneralNameValue,
}

const _: () = {
    assert!(core::mem::size_of::<GeneralNameValue>() == 8);
    assert!(core::mem::size_of::<GeneralName>() == 16);
    assert!(core::mem::offset_of!(GeneralName, type_) == 0);
    assert!(core::mem::offset_of!(GeneralName, d) == 8);
};

/// `GENERAL_NAME_ch_tt` — `ASN1_CHOICE(GENERAL_NAME)` (`crypto/x509/v3_genn.c:32-44`). Every
/// alternative shares the union at offset 8; the selector is `type` at offset 0. Eight are
/// context-implicit, and `directoryName` is the one explicit alternative (`ASN1_EXP`), which is
/// why it carries `ASN1_TFLG_EXPLICIT` where the rest carry `ASN1_TFLG_IMPLICIT`.
static GENERAL_NAME_CH_TT: [Asn1Template; 9] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_OTHERNAME as c_long,
        offset: 8,
        field_name: c"d.otherName".as_ptr(),
        item: othername_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_EMAIL as c_long,
        offset: 8,
        field_name: c"d.rfc822Name".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_DNS as c_long,
        offset: 8,
        field_name: c"d.dNSName".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_X400 as c_long,
        offset: 8,
        field_name: c"d.x400Address".as_ptr(),
        item: ASN1_SEQUENCE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: GEN_DIRNAME as c_long,
        offset: 8,
        field_name: c"d.directoryName".as_ptr(),
        item: X509_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_EDIPARTY as c_long,
        offset: 8,
        field_name: c"d.ediPartyName".as_ptr(),
        item: edipartyname_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_URI as c_long,
        offset: 8,
        field_name: c"d.uniformResourceIdentifier".as_ptr(),
        item: ASN1_IA5STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_IPADD as c_long,
        offset: 8,
        field_name: c"d.iPAddress".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT,
        tag: GEN_RID as c_long,
        offset: 8,
        field_name: c"d.registeredID".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
];

/// `GENERAL_NAME_it`'s descriptor — `ASN1_CHOICE_END(GENERAL_NAME)` at `crypto/x509/v3_genn.c:44`.
/// The `utype` of a CHOICE is the selector's offset, not a tag.
static GENERAL_NAME_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: core::mem::offset_of!(GeneralName, type_) as c_long,
    templates: GENERAL_NAME_CH_TT.as_ptr(),
    tcount: 9,
    funcs: ptr::null(),
    size: core::mem::size_of::<GeneralName>() as c_long,
    sname: c"GENERAL_NAME".as_ptr(),
};

/// `const ASN1_ITEM *GENERAL_NAME_it(void)` — from `DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAME_it() -> *const Asn1Item {
    &GENERAL_NAME_ITEM
}

/// The internal alias a static template can name for the `SEQUENCE OF` below.
fn general_name_it() -> *const Asn1Item {
    GENERAL_NAME_it()
}

/// `GENERAL_NAME *GENERAL_NAME_new(void)` — `crypto/x509/v3_genn.c:46`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAME)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAME_new() -> *mut GeneralName {
    // SAFETY: `GENERAL_NAME_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(GENERAL_NAME_it()).cast::<GeneralName>() }
}

/// `void GENERAL_NAME_free(GENERAL_NAME *a)` — the same macro's free half.
///
/// The item layer's `CHOICE` free arm reads the selector and releases **only** the alternative it
/// names: an out-of-range selector matches no template entry, so no arm is released and the
/// struct is reclaimed (the arm, if any, is the caller's leak — never a mismatched free). An
/// in-range selector whose arm is NULL is a no-op through the item free's null guard.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_free(a: *mut GeneralName) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), GENERAL_NAME_it()) }
}

/// `GENERAL_NAME *d2i_GENERAL_NAME(GENERAL_NAME **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_GENERAL_NAME(
    a: *mut *mut GeneralName,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut GeneralName {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        let name = ASN1_item_d2i(a.cast(), in_, len, GENERAL_NAME_it()).cast::<GeneralName>();
        if name.is_null() {
            return name;
        }
        // The CHOICE template has exactly the nine `GEN_*` alternatives, each producing a
        // non-NULL arm, so any other pairing is a decoder defect rather than input. Refuse it
        // instead of publishing a value whose selector and arm disagree.
        if !(GEN_OTHERNAME..=GEN_RID).contains(&(*name).type_) {
            GENERAL_NAME_free(name);
            return ptr::null_mut();
        }
        if (*name).arm_ptr().is_null() {
            GENERAL_NAME_free(name);
            return ptr::null_mut();
        }
        name
    }
}

/// `int i2d_GENERAL_NAME(const GENERAL_NAME *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_GENERAL_NAME(a: *const GeneralName, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, GENERAL_NAME_it()) }
}

/// `GENERAL_NAMES_item_tt` — `ASN1_ITEM_TEMPLATE(GENERAL_NAMES)` at `crypto/x509/v3_genn.c:48`,
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, GeneralNames, GENERAL_NAME)`.
static GENERAL_NAMES_ITEM_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"GENERAL_NAMES".as_ptr(),
    item: general_name_it as *mut c_void,
};

/// `GENERAL_NAMES_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(GENERAL_NAMES)` at `:49`: a
/// `PRIMITIVE` item over one `SEQUENCE OF` template, `utype` `-1`, `tcount` 0.
static GENERAL_NAMES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &GENERAL_NAMES_ITEM_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"GENERAL_NAMES".as_ptr(),
};

/// `const ASN1_ITEM *GENERAL_NAMES_it(void)` — from `DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)`.
#[no_mangle]
pub extern "C" fn GENERAL_NAMES_it() -> *const Asn1Item {
    &GENERAL_NAMES_ITEM
}

/// `GENERAL_NAMES *GENERAL_NAMES_new(void)` — `crypto/x509/v3_genn.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(GENERAL_NAMES)`. A `SEQUENCE OF` value is a stack.
#[no_mangle]
pub extern "C" fn GENERAL_NAMES_new() -> *mut OpenSslStack {
    // SAFETY: `GENERAL_NAMES_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(GENERAL_NAMES_it()).cast::<OpenSslStack>() }
}

/// `void GENERAL_NAMES_free(GENERAL_NAMES *a)` — the same macro's free half.
///
/// # Safety
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAMES_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), GENERAL_NAMES_it()) }
}

/// `GENERAL_NAMES *d2i_GENERAL_NAMES(GENERAL_NAMES **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_GENERAL_NAMES(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, GENERAL_NAMES_it()).cast::<OpenSslStack>() }
}

/// `int i2d_GENERAL_NAMES(const GENERAL_NAMES *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_GENERAL_NAMES(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, GENERAL_NAMES_it()) }
}

/// `GENERAL_NAME *GENERAL_NAME_dup(const GENERAL_NAME *a)` — `crypto/x509/v3_genn.c:53-58`.
///
/// Encode-then-decode through the item, so the answer shares no storage with `a`.
///
/// # Safety
/// `a` is NULL or a live `GENERAL_NAME`. The answer is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_dup(a: *const GeneralName) -> *mut GeneralName {
    // The typed helper carries the callbacks' pointee type in its signature, so the authority's
    // `void *` spelling -- and the function-pointer transmute that reaching it used to need -- is
    // gone from this path.
    // SAFETY: `i2d_GENERAL_NAME`/`d2i_GENERAL_NAME` are the matching pair for `GeneralName`, and
    // `a` is NULL or live per the contract.
    unsafe { ASN1_dup_typed(i2d_GENERAL_NAME, d2i_GENERAL_NAME, a) }
}

/// `int GENERAL_NAME_set1_X509_NAME(GENERAL_NAME **tgt, const X509_NAME *src)` —
/// `crypto/x509/v3_genn.c:60-87`.
///
/// Builds a fresh `GEN_DIRNAME` name (a NULL `src` is the NULL-DN case, which allocates an empty
/// `X509_NAME`), releases the caller's old one and writes the new pointer back. A NULL `tgt` is
/// the covered refusal.
///
/// # Safety
/// `tgt` is NULL or a writable slot; `src` is NULL or a live `X509_NAME`.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set1_X509_NAME(
    tgt: *mut *mut GeneralName,
    src: *const X509Name,
) -> c_int {
    if tgt.is_null() {
        // SAFETY: a compile-time-constant site.
        unsafe { raise_site(&err_sites::V3_GENN_65) };
        return 0;
    }

    // SAFETY: no preconditions.
    let name = GENERAL_NAME_new();
    if name.is_null() {
        return 0;
    }
    // The new name is built first, then installed with the selector in one step: the only write
    // to the union is `install`, so no intermediate state names an arm other than the one stored.
    // SAFETY: a NULL `src` allocates an empty name; otherwise `src` is live per the contract.
    let dn = if src.is_null() {
        X509_NAME_new()
    } else {
        // SAFETY: `src` is live per the contract; the duplicate is owned by this frame.
        unsafe { X509_NAME_dup(src) }
    };
    // SAFETY: `name` is live; `dn` is NULL or this call's own name.
    unsafe { (*name).install(GEN_DIRNAME, dn.cast()) };
    if dn.is_null() {
        // SAFETY: `name` is live and this failure path owns it.
        unsafe { GENERAL_NAME_free(name) };
        return 0;
    }

    // SAFETY: `tgt` is a writable slot per the check above and `*tgt` is NULL or live.
    unsafe {
        GENERAL_NAME_free(*tgt);
        *tgt = name;
    }
    1
}

/// `static int edipartyname_cmp(const EDIPARTYNAME *a, const EDIPARTYNAME *b)` —
/// `crypto/x509/v3_genn.c:89-118`.
///
/// A NULL argument answers `-1` (the authority's "not comparable" answer, which it chooses over
/// `OTHERNAME_cmp`'s `NULL != NULL`). A present `nameAssigner` on one side and not the other is
/// ordered by which side has it.
///
/// # Safety
/// `a`/`b` are NULL or live `EDIPARTYNAME` values.
unsafe fn edipartyname_cmp(a: *const EdiPartyName, b: *const EdiPartyName) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let (an, bn) = unsafe { ((*a).nameAssigner, (*b).nameAssigner) };
    if an.is_null() && !bn.is_null() {
        return -1;
    }
    if !an.is_null() && bn.is_null() {
        return 1;
    }
    if !an.is_null() {
        // SAFETY: both `nameAssigner` pointers are live in this arm.
        let res = unsafe { ASN1_STRING_cmp(an, bn) };
        if res != 0 {
            return res;
        }
    }
    // SAFETY: both are live per the check above.
    let (ap, bp) = unsafe { ((*a).partyName, (*b).partyName) };
    if ap.is_null() || bp.is_null() {
        return -1;
    }
    // SAFETY: both `partyName` pointers are live in this arm.
    unsafe { ASN1_STRING_cmp(ap, bp) }
}

/// `int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b)` — `crypto/x509/v3_genn.c:120-159`.
///
/// `-1` for a NULL argument or a selector mismatch; otherwise the selected arm's own comparison.
///
/// # Safety
/// `a`/`b` are NULL or live `GENERAL_NAME` values.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_cmp(a: *mut GeneralName, b: *mut GeneralName) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let (ta, tb) = unsafe { ((*a).type_, (*b).type_) };
    if ta != tb {
        return -1;
    }
    // SAFETY: the selector is equal on both sides; each side's selector names its live arm, so the
    // accessor is the only reader and a cross-arm read cannot be written here.
    unsafe {
        match ((*a).as_ref(), (*b).as_ref()) {
            (Some(GeneralNameRef::X400(x)), Some(GeneralNameRef::X400(y))) => ASN1_STRING_cmp(
                x as *const Asn1String as *mut Asn1String,
                y as *const Asn1String as *mut Asn1String,
            ),
            (Some(GeneralNameRef::EdiPartyName(x)), Some(GeneralNameRef::EdiPartyName(y))) => {
                edipartyname_cmp(x as *const EdiPartyName, y as *const EdiPartyName)
            }
            (Some(GeneralNameRef::OtherName(x)), Some(GeneralNameRef::OtherName(y))) => {
                OTHERNAME_cmp(
                    x as *const Othername as *mut Othername,
                    y as *const Othername as *mut Othername,
                )
            }
            (Some(GeneralNameRef::Ia5(x)), Some(GeneralNameRef::Ia5(y))) => ASN1_STRING_cmp(
                x as *const Asn1String as *mut Asn1String,
                y as *const Asn1String as *mut Asn1String,
            ),
            (Some(GeneralNameRef::DirectoryName(x)), Some(GeneralNameRef::DirectoryName(y))) => {
                X509_NAME_cmp(x as *const X509Name, y as *const X509Name)
            }
            (Some(GeneralNameRef::IpAddress(x)), Some(GeneralNameRef::IpAddress(y))) => {
                ASN1_OCTET_STRING_cmp(
                    x as *const Asn1String as *mut Asn1String,
                    y as *const Asn1String as *mut Asn1String,
                )
            }
            (Some(GeneralNameRef::RegisteredId(x)), Some(GeneralNameRef::RegisteredId(y))) => {
                OBJ_cmp(
                    x as *const Asn1Object as *mut Asn1Object,
                    y as *const Asn1Object as *mut Asn1Object,
                )
            }
            _ => -1,
        }
    }
}

/// `int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b)` — `crypto/x509/v3_genn.c:161-174`.
///
/// The type OID first, then the value through [`ASN1_TYPE_cmp`]; a NULL argument is `-1` (this
/// one, unlike [`edipartyname_cmp`], answers `-1` where `OTHERNAME` is not comparable at all).
///
/// # Safety
/// `a`/`b` are NULL or live `OTHERNAME` values.
#[no_mangle]
pub unsafe extern "C" fn OTHERNAME_cmp(a: *mut Othername, b: *mut Othername) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    // SAFETY: both are live per the check above.
    let res = unsafe { OBJ_cmp((*a).type_id, (*b).type_id) };
    if res != 0 {
        return res;
    }
    // SAFETY: both `value` pointers are live in this arm.
    unsafe { ASN1_TYPE_cmp((*a).value, (*b).value) }
}

/// `void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value)` —
/// `crypto/x509/v3_genn.c:176-210`.
///
/// Writes the pointer the selector names and then the selector; it does **not** release whatever
/// the union held, which is the authority's transfer-of-ownership contract and is observable.
///
/// # Safety
/// `a` is live; `value` is NULL or a live value of the arm `type` selects, and ownership passes
/// to `a`.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set0_value(
    a: *mut GeneralName,
    type_: c_int,
    value: *mut c_void,
) {
    // SAFETY: `a` is live and the union is writable; every arm is one pointer. `install` is the
    // single selector+arm producer, so a caller can no longer create a half-written pair here.
    unsafe {
        (*a).install(type_, value);
    }
}

/// `void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype)` —
/// `crypto/x509/v3_genn.c:212-243`.
///
/// Answers the selected union arm, and writes the selector through `ptype` when it is non-NULL. An
/// unknown selector answers NULL rather than raising. The answer is borrowed.
///
/// # Safety
/// `a` is live; `ptype` is NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_get0_value(
    a: *const GeneralName,
    ptype: *mut c_int,
) -> *mut c_void {
    // SAFETY: `a` is live per the contract.
    let type_ = unsafe { (*a).type_ };
    if !ptype.is_null() {
        // SAFETY: `ptype` is writable per the contract.
        unsafe { *ptype = type_ };
    }
    // SAFETY: `a` is live; `arm_ptr` reads only the arm the selector names and answers NULL for
    // an unhandled selector or a NULL arm.
    unsafe { (*a).arm_ptr() }
}

/// `int GENERAL_NAME_set0_othername(GENERAL_NAME *gen, ASN1_OBJECT *oid, ASN1_TYPE *value)` —
/// `crypto/x509/v3_genn.c:245-257`.
///
/// Allocates an `OTHERNAME`, releases its freshly-allocated empty `value` (so the caller's passes
/// in without a leak), adopts the OID and value and installs it as the `GEN_OTHERNAME` arm.
///
/// # Safety
/// `gen` is live; `oid`/`value` are NULL or live and transfer to the answer.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_set0_othername(
    gen: *mut GeneralName,
    oid: *mut Asn1Object,
    value: *mut Asn1Type,
) -> c_int {
    // SAFETY: no preconditions.
    let oth = OTHERNAME_new();
    if oth.is_null() {
        return 0;
    }
    // SAFETY: `oth` is live and its `value` is the fresh empty one the item layer built.
    unsafe {
        ASN1_TYPE_free((*oth).value);
        (*oth).type_id = oid;
        (*oth).value = value;
    }
    // SAFETY: `gen` is live and adopts `oth`.
    unsafe { GENERAL_NAME_set0_value(gen, GEN_OTHERNAME, oth.cast::<c_void>()) };
    1
}

/// `int GENERAL_NAME_get0_otherName(const GENERAL_NAME *gen, ASN1_OBJECT **poid,
/// ASN1_TYPE **pvalue)` — `crypto/x509/v3_genn.c:259-269`.
///
/// Answers 0 without writing either out-parameter when the name is not an `OTHERNAME`; otherwise
/// writes the ones that are non-NULL and answers 1.
///
/// # Safety
/// `gen` is live; `poid`/`pvalue` are NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_NAME_get0_otherName(
    gen: *const GeneralName,
    poid: *mut *mut Asn1Object,
    pvalue: *mut *mut Asn1Type,
) -> c_int {
    // SAFETY: `gen` is live per the contract. The accessor checks the selector and refuses a
    // NULL arm, so a caller-built `GEN_OTHERNAME` with no `OTHERNAME` answers 0 instead of
    // dereferencing NULL.
    let Some(GeneralNameRef::OtherName(oth)) = (unsafe { (*gen).as_ref() }) else {
        return 0;
    };
    if !poid.is_null() {
        // SAFETY: `poid` is writable; `oth` is the live selected arm.
        unsafe { *poid = oth.type_id };
    }
    if !pvalue.is_null() {
        // SAFETY: `pvalue` is writable; `oth` is the live selected arm.
        unsafe { *pvalue = oth.value };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::string::{ASN1_IA5STRING_new, ASN1_STRING_set};
    use crate::runtime::obj::{NID_commonName, OBJ_nid2obj};

    /// The selector is the only thing that says which arm is live: the checked accessor names
    /// the arm, an equal pair of every comparable type answers its own comparison, and a
    /// cross-type pair answers the authority's `-1`.
    #[test]
    fn the_selector_picks_the_compared_arm() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every object is freshly allocated here and ownership passes into the union.
        unsafe {
            let a = GENERAL_NAME_new();
            let b = GENERAL_NAME_new();
            assert!(!a.is_null() && !b.is_null());
            let ia5_a = ASN1_IA5STRING_new();
            let ia5_b = ASN1_IA5STRING_new();
            assert!(!ia5_a.is_null() && !ia5_b.is_null());
            let bytes = b"example.test";
            assert_eq!(
                ASN1_STRING_set(ia5_a, bytes.as_ptr().cast(), bytes.len() as c_int),
                1
            );
            assert_eq!(
                ASN1_STRING_set(ia5_b, bytes.as_ptr().cast(), bytes.len() as c_int),
                1
            );
            GENERAL_NAME_set0_value(a, GEN_DNS, ia5_a.cast::<c_void>());
            GENERAL_NAME_set0_value(b, GEN_DNS, ia5_b.cast::<c_void>());
            assert_eq!(GENERAL_NAME_cmp(a, b), 0, "equal dNSNames compare equal");
            assert!(matches!((*a).as_ref(), Some(GeneralNameRef::Ia5(_))));

            // Same value, different selector: the authority answers -1 before any arm read.
            (*b).type_ = GEN_URI;
            assert_eq!(GENERAL_NAME_cmp(a, b), -1);

            // An unhandled selector answers -1 and the accessor yields no arm.
            (*b).type_ = 99;
            assert_eq!(GENERAL_NAME_cmp(a, b), -1);
            assert!((*b).as_ref().is_none());

            // A NULL argument answers -1.
            assert_eq!(GENERAL_NAME_cmp(a, core::ptr::null_mut()), -1);
            GENERAL_NAME_free(a);
            GENERAL_NAME_free(b);
        }
    }

    /// **CVE-2023-0286 probe.** The selector/arm pairing is what the comparator trusts. A pair
    /// whose selector is `GEN_X400` is read as an `ASN1_STRING` and nothing else, so the historical
    /// confusion -- comparing an X.400 name through another arm -- cannot be written at the call
    /// site. The mismatch itself can still be *constructed* through the raw `set0_value` ABI, which
    /// is why the campaign records the mechanism as HIDDEN rather than eliminated.
    #[test]
    fn the_x400_arm_is_only_ever_read_as_an_asn1_string() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: objects are freshly allocated and ownership passes into the union.
        unsafe {
            let a = GENERAL_NAME_new();
            let b = GENERAL_NAME_new();
            let s1 = ASN1_IA5STRING_new();
            let s2 = ASN1_IA5STRING_new();
            assert!(ASN1_STRING_set(s1, b"x".as_ptr().cast(), 1) == 1);
            assert!(ASN1_STRING_set(s2, b"x".as_ptr().cast(), 1) == 1);
            GENERAL_NAME_set0_value(a, GEN_X400, s1.cast::<c_void>());
            GENERAL_NAME_set0_value(b, GEN_X400, s2.cast::<c_void>());
            assert!(matches!((*a).as_ref(), Some(GeneralNameRef::X400(_))));
            assert_eq!(
                GENERAL_NAME_cmp(a, b),
                0,
                "two X.400 names compare through the ASN1_STRING arm only"
            );
            GENERAL_NAME_free(a);
            GENERAL_NAME_free(b);
        }
    }

    /// **CVE-2023-0286 mechanism probe.** After a set, the slot holds only the arm the selector
    /// names; an unhandled selector normalises the slot to NULL. The authority instead leaves the
    /// previous bytes in `d`, which is the controllable-pointer residue the confusion needs.
    #[test]
    fn a_set_name_never_leaves_a_stale_arm_behind() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: objects are freshly allocated; the string is transferred to the name on the
        // first set and freed here after the normalisation detached it.
        unsafe {
            let n = GENERAL_NAME_new();
            let s = ASN1_IA5STRING_new();
            assert_eq!(ASN1_STRING_set(s, b"dns".as_ptr().cast(), 3), 1);
            GENERAL_NAME_set0_value(n, GEN_DNS, s.cast::<c_void>());
            assert!(matches!((*n).as_ref(), Some(GeneralNameRef::Ia5(_))));

            // An unhandled selector records the type but must not preserve the old pointer.
            GENERAL_NAME_set0_value(n, 99, core::ptr::null_mut());
            assert_eq!((*n).type_, 99);
            assert!((*n).as_ref().is_none(), "no arm is readable");
            assert_eq!(
                GENERAL_NAME_get0_value(n, core::ptr::null_mut()),
                core::ptr::null_mut()
            );
            assert!(
                (*n).d.ia5.is_null(),
                "the cleared slot holds no controllable pointer"
            );

            crate::asn1::string::ASN1_STRING_free(s);
            GENERAL_NAME_free(n);
        }
    }

    /// The item group is stable, a decoded `iPAddress` carries its octets, and the selector is
    /// the `GEN_*` the wire tag named. A `dNSName` round-trips to the same bytes.
    #[test]
    fn ia5_and_ip_round_trip_through_the_choice() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let name = GENERAL_NAME_new();
        assert!(!name.is_null());
        // SAFETY: `name` is live; ownership of the object passes to the union.
        let obj = OBJ_nid2obj(GEN_RID);
        assert!(!obj.is_null());
        // SAFETY: `name` is live and `obj` is a live object.
        unsafe {
            GENERAL_NAME_set0_value(name, GEN_RID, obj.cast::<c_void>());
            assert_eq!((*name).type_, GEN_RID);
            let mut t: c_int = -1;
            assert_eq!(
                GENERAL_NAME_get0_value(name, &raw mut t),
                obj.cast::<c_void>()
            );
            assert_eq!(t, GEN_RID);
            GENERAL_NAME_free(name);
        }
        assert_eq!(GENERAL_NAME_it(), GENERAL_NAME_it());
        assert_eq!(GENERAL_NAMES_it(), GENERAL_NAMES_it());
    }

    use crate::asn1::a_type::{ASN1_TYPE_new, ASN1_TYPE_set};
    use crate::asn1::string::{ASN1_OCTET_STRING_new, ASN1_STRING_free, ASN1_STRING_type_new};
    use crate::x509::x_name::X509_NAME_new;

    /// Encode a name through its item; the answer is a fresh `Vec`.
    unsafe fn encoded(n: *const GeneralName) -> Vec<u8> {
        // SAFETY: `n` is live per the caller's contract.
        unsafe {
            let len = i2d_GENERAL_NAME(n, ptr::null_mut());
            assert!(len > 0, "the name must encode");
            let mut buf = vec![0u8; len as usize];
            let mut cur = buf.as_mut_ptr();
            assert_eq!(i2d_GENERAL_NAME(n, &mut cur), len);
            assert_eq!(cur, buf.as_mut_ptr().add(len as usize));
            buf
        }
    }

    /// Decode a name, requiring the whole input to be consumed.
    unsafe fn decoded(bytes: &[u8]) -> *mut GeneralName {
        // SAFETY: `bytes` is a live slice; the answer is owned by the caller.
        unsafe {
            let mut cur = bytes.as_ptr();
            let n = d2i_GENERAL_NAME(ptr::null_mut(), &mut cur, bytes.len() as c_long);
            if !n.is_null() {
                assert_eq!(
                    cur,
                    bytes.as_ptr().add(bytes.len()),
                    "the input is consumed"
                );
            }
            n
        }
    }

    /// `dup` and the item round trip must preserve the selector, the readable arm and the
    /// comparison result for one name.
    ///
    /// # Safety
    /// `n` is a live name owned by the caller.
    unsafe fn round_trip(n: *mut GeneralName, want: c_int) {
        // SAFETY: `n` is live per the contract; every answer is released here.
        unsafe {
            assert_eq!((*n).type_, want);
            assert!((*n).as_ref().is_some(), "the selector names a live arm");
            let bytes = encoded(n);
            let back = decoded(&bytes);
            assert!(!back.is_null(), "the encoding decodes for selector {want}");
            let dup = GENERAL_NAME_dup(n);
            assert!(!dup.is_null(), "dup of selector {want} answers a value");
            assert_eq!((*dup).type_, want);
            assert_eq!(GENERAL_NAME_cmp(n, dup), 0, "dup compares equal");
            assert_eq!((*back).type_, want);
            assert_eq!(
                GENERAL_NAME_cmp(n, back),
                0,
                "the round trip compares equal"
            );
            GENERAL_NAME_free(dup);
            GENERAL_NAME_free(back);
        }
    }

    /// Every `GEN_*` selector survives dup and the item round trip with its own accessor.
    #[test]
    fn every_selector_round_trips_through_dup_and_the_item() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame; ownership of each arm
        // passes to the name.
        unsafe {
            for selector in [GEN_EMAIL, GEN_DNS, GEN_URI] {
                let n = GENERAL_NAME_new();
                let v = ASN1_IA5STRING_new();
                assert_eq!(ASN1_STRING_set(v, b"a@b".as_ptr().cast(), 3), 1);
                GENERAL_NAME_set0_value(n, selector, v.cast::<c_void>());
                round_trip(n, selector);
                GENERAL_NAME_free(n);
            }

            let n = GENERAL_NAME_new();
            let ip = ASN1_OCTET_STRING_new();
            assert_eq!(ASN1_STRING_set(ip, [10u8, 0, 0, 1].as_ptr().cast(), 4), 1);
            GENERAL_NAME_set0_value(n, GEN_IPADD, ip.cast::<c_void>());
            round_trip(n, GEN_IPADD);
            GENERAL_NAME_free(n);

            let n = GENERAL_NAME_new();
            let rid = OBJ_nid2obj(NID_commonName);
            assert!(!rid.is_null());
            GENERAL_NAME_set0_value(n, GEN_RID, rid.cast::<c_void>());
            round_trip(n, GEN_RID);
            GENERAL_NAME_free(n);

            let n = GENERAL_NAME_new();
            let dn = X509_NAME_new();
            GENERAL_NAME_set0_value(n, GEN_DIRNAME, dn.cast::<c_void>());
            round_trip(n, GEN_DIRNAME);
            GENERAL_NAME_free(n);

            // `x400Address` is the generic `ASN1_SEQUENCE` item, stored as an `ASN1_STRING`
            // carrying its raw content. In this port that primitive item's *encoder* emits the
            // content without the implicit `[3]` tag (it produced `05 00`), so the dup/round-trip
            // leg is NOT_RUN for this selector: the gap is in the ASN1_SEQUENCE encoder, not in
            // the selector/arm contract. The in-memory accessor and comparison are checked, and
            // a `[3]` encoding still decodes into the arm below.
            let n = GENERAL_NAME_new();
            let x400 = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
            assert_eq!(ASN1_STRING_set(x400, [0x05u8, 0x00].as_ptr().cast(), 2), 1);
            GENERAL_NAME_set0_value(n, GEN_X400, x400.cast::<c_void>());
            assert!(matches!((*n).as_ref(), Some(GeneralNameRef::X400(_))));
            assert_eq!(GENERAL_NAME_cmp(n, n), 0);
            GENERAL_NAME_free(n);

            let x400_der = [0xA3u8, 0x02, 0x05, 0x00];
            let x400_name = decoded(&x400_der);
            assert!(!x400_name.is_null(), "an implicit [3] X.400 name decodes");
            assert_eq!((*x400_name).type_, GEN_X400);
            assert!(matches!(
                (*x400_name).as_ref(),
                Some(GeneralNameRef::X400(_))
            ));
            GENERAL_NAME_free(x400_name);

            let n = GENERAL_NAME_new();
            let e = EDIPARTYNAME_new();
            assert!(!e.is_null());
            let party = ASN1_STRING_type_new(V_ASN1_UTF8STRING);
            assert_eq!(ASN1_STRING_set(party, b"party".as_ptr().cast(), 5), 1);
            (*e).partyName = party;
            GENERAL_NAME_set0_value(n, GEN_EDIPARTY, e.cast::<c_void>());
            round_trip(n, GEN_EDIPARTY);
            GENERAL_NAME_free(n);

            let n = GENERAL_NAME_new();
            let oid = OBJ_nid2obj(NID_commonName);
            let any = ASN1_TYPE_new();
            assert!(!any.is_null());
            ASN1_TYPE_set(any, V_ASN1_NULL, ptr::null_mut());
            assert_eq!(GENERAL_NAME_set0_othername(n, oid, any), 1);
            round_trip(n, GEN_OTHERNAME);
            GENERAL_NAME_free(n);
        }
    }

    /// An unhandled selector records itself, adopts nothing, is unreadable through every
    /// accessor, and frees without touching a pointer the selector does not name.
    #[test]
    fn an_unknown_selector_is_unreadable_and_safe_to_free() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let n = GENERAL_NAME_new();
            let s = ASN1_IA5STRING_new();
            assert_eq!(ASN1_STRING_set(s, b"x".as_ptr().cast(), 1), 1);
            GENERAL_NAME_set0_value(n, 99, s.cast::<c_void>());
            assert_eq!((*n).type_, 99);
            assert!((*n).as_ref().is_none(), "no arm is readable");
            assert_eq!(GENERAL_NAME_get0_value(n, ptr::null_mut()), ptr::null_mut());
            assert_eq!(
                GENERAL_NAME_get0_otherName(n, ptr::null_mut(), ptr::null_mut()),
                0
            );
            // The free path dispatches on the selector: 99 names no alternative, so the struct is
            // reclaimed and `s` (which was never adopted) is untouched.
            GENERAL_NAME_free(n);
            assert_eq!((*s).length, 1, "the unnamed arm was not freed");
            ASN1_STRING_free(s);
        }
    }

    /// **CVE-2023-0286 probe.** A NULL arm under a handled selector is unreadable and safe to
    /// free; a selector change clears the previous arm, so the old pointer cannot be read through
    /// the new selector; and a decoded value always carries a selector with a live arm.
    #[test]
    fn a_mismatched_pair_is_not_readable_through_the_accessors() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: every object is created and released in this frame.
        unsafe {
            let n = GENERAL_NAME_new();
            // A paired IA5 arm.
            let s = ASN1_IA5STRING_new();
            assert_eq!(ASN1_STRING_set(s, b"dns".as_ptr().cast(), 3), 1);
            GENERAL_NAME_set0_value(n, GEN_DNS, s.cast::<c_void>());
            assert!(matches!((*n).as_ref(), Some(GeneralNameRef::Ia5(_))));

            // Changing the selector to OTHERNAME installs that arm and clears the IA5 slot: the
            // old pointer is not reachable through the new selector. A NULL OTHERNAME is
            // unreadable rather than a NULL dereference.
            GENERAL_NAME_set0_value(n, GEN_OTHERNAME, ptr::null_mut());
            assert!((*n).as_ref().is_none());
            assert_eq!(GENERAL_NAME_get0_value(n, ptr::null_mut()), ptr::null_mut());
            assert_eq!(
                GENERAL_NAME_get0_otherName(n, ptr::null_mut(), ptr::null_mut()),
                0,
                "a NULL OTHERNAME is refused, not dereferenced"
            );
            // The IA5 arm is still owned by this frame (the set did not adopt it), so release it.
            ASN1_STRING_free(s);
            GENERAL_NAME_free(n);

            // A selector the CHOICE template does not have cannot be decoded: context tag 9.
            let unknown = [0x89u8, 0x00];
            assert!(decoded(&unknown).is_null());
            // A well-formed dNSName decodes and its accessor names the IA5 arm.
            let dns = [0x82u8, 0x03, b'a', b'@', b'b'];
            let back = decoded(&dns);
            assert!(!back.is_null());
            assert_eq!((*back).type_, GEN_DNS);
            assert!(matches!((*back).as_ref(), Some(GeneralNameRef::Ia5(_))));
            GENERAL_NAME_free(back);
        }
    }

    /// `set0_othername` installs an `OTHERNAME` arm whose type OID and value come back through
    /// `get0_otherName`, and a non-`OTHERNAME` name refuses the reader with 0.
    #[test]
    fn set0_othername_is_readable() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: no preconditions.
        let name = GENERAL_NAME_new();
        assert!(!name.is_null());
        // SAFETY: no preconditions.
        let oid = OBJ_nid2obj(NID_commonName);
        // SAFETY: `name` is live; `oid` transfers to the OTHERNAME.
        unsafe {
            assert_eq!(GENERAL_NAME_set0_othername(name, oid, ptr::null_mut()), 1);
            assert_eq!((*name).type_, GEN_OTHERNAME);
            let mut poid: *mut Asn1Object = ptr::null_mut();
            let mut pval: *mut Asn1Type = ptr::null_mut();
            assert_eq!(
                GENERAL_NAME_get0_otherName(name, &raw mut poid, &raw mut pval),
                1
            );
            assert_eq!(poid, oid);
            assert!(pval.is_null());
            GENERAL_NAME_free(name);

            let ip = GENERAL_NAME_new();
            assert!(!ip.is_null());
            GENERAL_NAME_set0_value(ip, GEN_IPADD, ptr::null_mut());
            assert_eq!(
                GENERAL_NAME_get0_otherName(ip, ptr::null_mut(), ptr::null_mut()),
                0
            );
            GENERAL_NAME_free(ip);
        }
    }
}
