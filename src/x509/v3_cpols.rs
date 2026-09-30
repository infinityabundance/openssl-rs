//! `crypto/x509/v3_cpols.c` — the certificate-policies item groups, their printers and their row.
//! Phase 10.14's table layer, landed whole.
//!
//! `crypto/x509/v3_cpols.c` is 515 lines and transcribes whole:
//!
//! * `CERTIFICATEPOLICIES ::= SEQUENCE OF POLICYINFO` (`:48-49`),
//!   `POLICYINFO ::= SEQUENCE { policyid OBJECT IDENTIFIER, qualifiers SEQUENCE OF POLICYQUALINFO
//!   OPTIONAL }` (`:53-56`),
//!   `POLICYQUALINFO ::= SEQUENCE { pqualid OBJECT IDENTIFIER, { CPS IA5String |
//!   userNotice USERNOTICE | other ANY } }` (`:60-70`, the `ASN1_ADB` `ANY DEFINED BY` on
//!   `pqualid`), `USERNOTICE ::= SEQUENCE { noticeref NOTICEREF OPTIONAL, exptext DISPLAYTEXT
//!   OPTIONAL }` (`:74-77`) and `NOTICEREF ::= SEQUENCE { organization DISPLAYTEXT, noticenos
//!   SEQUENCE OF INTEGER }` (`:81-84`) all land, with the `_it`/`_new`/`_free`/`d2i_`/`i2d_` group
//!   each `IMPLEMENT_ASN1_FUNCTIONS` emits (`:51`, `:58`, `:72`, `:79`, `:86`). All twenty are
//!   public exports (`x509v3.h:873-879`).
//! * The ten `static` functions land: `r2i_certpol` (`:88-163`), `policy_section` (`:165-255`),
//!   `displaytext_get_tag_len` (`:257-262`), `displaytext_str2tag` (`:264-288`), `notice_section`
//!   (`:290-390`), `nref_nos` (`:392-412`), `i2r_certpol` (`:414-432`), `print_qualifiers`
//!   (`:434-462`), `print_notice` (`:464-498`) and the exported `X509_POLICY_NODE_print`
//!   (`:500-515`).
//! * The row [`ossl_v3_cpols`] (`:38-46`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item groups and the printers are the drivable
//! surface.
//!
//! ## The two header-macro expansions, defined locally
//!
//! `X509V3_conf_err` (`x509v3.h:632-635`) and `X509V3_conf_add_error_name_value`
//! (`x509_local.h:12`) are macros, not functions. The second is already landed as
//! [`crate::x509::v3_utl::conf_add_error_name_value`]; the first is expanded here as [`conf_err`]
//! through [`crate::runtime::err::openssl_rs_err_add_data`], both with the authority's
//! NULL-becomes-`<NULL>` rule (`crypto/err/err.c:855-856`).
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_cpols.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`
//! (D467 names it a closure-ready table unit, not a generator input), so its thirty-two coordinates
//! are **declared locally** with the `err_sites::ErrSite` shape, as `v3_bitst.rs` does. Their reason
//! values are read from the authority's own headers (`x509v3err.h` for the nine `X509V3_R_*`,
//! `err.h` for the two `ERR_R_*_LIB` and `ERR_R_INTERNAL_ERROR`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void, CStr};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{
    ASN1_ANY_it, ASN1_IA5STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, DISPLAYTEXT_it,
};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::string::{
    ASN1_IA5STRING_new, ASN1_INTEGER_free, ASN1_STRING_set, ASN1_STRING_type_new,
};
use crate::asn1::text::i2a_ASN1_OBJECT;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{strchr, strcmp, strlen, strncmp};
use crate::runtime::bio::{Bio, ERR_R_CRYPTO_LIB, ERR_R_INTERNAL_ERROR};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_EXPECTED_A_SECTION_NAME, X509V3_R_INVALID_NUMBER, X509V3_R_INVALID_NUMBERS,
    X509V3_R_INVALID_OBJECT_IDENTIFIER, X509V3_R_INVALID_OPTION,
    X509V3_R_INVALID_POLICY_IDENTIFIER, X509V3_R_INVALID_SECTION,
    X509V3_R_NEED_ORGANIZATION_AND_NUMBERS, X509V3_R_NO_POLICY_IDENTIFIER,
};
use crate::runtime::err::{openssl_rs_err_add_data, raise_site, raise_site_data};
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::{
    Asn1Object, NID_certificate_policies, NID_id_qt_cps, NID_id_qt_unotice, OBJ_nid2obj,
    OBJ_obj2nid, OBJ_txt2obj,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::pcy_lib::X509PolicyNode;
use crate::x509::v3_conf::{X509V3Ctx, X509V3_get_section, X509V3_section_free};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{
    conf_add_error_name_value, i2s_ASN1_INTEGER, ossl_v3_name_cmp, s2i_ASN1_INTEGER,
    X509V3_conf_free, X509V3_parse_list,
};

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansions — `crypto/x509/v3_cpols.c`.
const FILE: &CStr = c"crypto/x509/v3_cpols.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509V3_LIB` — `err.h`, `(ERR_LIB_X509V3 | ERR_RFLAG_COMMON)`.
const ERR_R_X509V3_LIB: c_int = 34 | (0x2 << 18);
/// `POLICY_DATA_FLAG_CRITICAL` — `crypto/x509/pcy_local.h:61`, the bit `node_data_critical` reads.
const POLICY_DATA_FLAG_CRITICAL: c_uint = 0x10;

/// One `v3_cpols.c` raise coordinate, declared locally (see the module doc).
const fn v3_cpols_site(
    line: c_int,
    func: &'static CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_cpols.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `r2i_certpol`'s failed `X509V3_parse_list` at `v3_cpols.c:101`.
const V3_CPOLS_101: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(101, c"r2i_certpol", ERR_R_X509V3_LIB);
/// `r2i_certpol`'s failed `sk_POLICYINFO_new_reserve` at `v3_cpols.c:107`.
const V3_CPOLS_107: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(107, c"r2i_certpol", ERR_R_CRYPTO_LIB);
/// `r2i_certpol`'s malformed policy identifier at `v3_cpols.c:115`.
const V3_CPOLS_115: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(115, c"r2i_certpol", X509V3_R_INVALID_POLICY_IDENTIFIER);
/// `r2i_certpol`'s missing section at `v3_cpols.c:128`.
const V3_CPOLS_128: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(128, c"r2i_certpol", X509V3_R_INVALID_SECTION);
/// `r2i_certpol`'s failed `OBJ_txt2obj` at `v3_cpols.c:138`.
const V3_CPOLS_138: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(138, c"r2i_certpol", X509V3_R_INVALID_OBJECT_IDENTIFIER);
/// `r2i_certpol`'s failed `POLICYINFO_new` at `v3_cpols.c:146`.
const V3_CPOLS_146: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(146, c"r2i_certpol", ERR_R_ASN1_LIB);
/// `r2i_certpol`'s failed stack push at `v3_cpols.c:153`.
const V3_CPOLS_153: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(153, c"r2i_certpol", ERR_R_CRYPTO_LIB);
/// `policy_section`'s failed `POLICYINFO_new` at `v3_cpols.c:174`.
const V3_CPOLS_174: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(174, c"policy_section", ERR_R_ASN1_LIB);
/// `policy_section`'s failed `OBJ_txt2obj` at `v3_cpols.c:183`.
const V3_CPOLS_183: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(183, c"policy_section", X509V3_R_INVALID_OBJECT_IDENTIFIER);
/// `policy_section`'s failed `POLICYQUALINFO_new` at `v3_cpols.c:193`.
const V3_CPOLS_193: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(193, c"policy_section", ERR_R_ASN1_LIB);
/// `policy_section`'s failed qualifier push at `v3_cpols.c:198`.
const V3_CPOLS_198: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(198, c"policy_section", ERR_R_CRYPTO_LIB);
/// `policy_section`'s failed `OBJ_nid2obj(NID_id_qt_cps)` at `v3_cpols.c:202`.
const V3_CPOLS_202: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(202, c"policy_section", ERR_R_INTERNAL_ERROR);
/// `policy_section`'s failed `ASN1_IA5STRING_new` at `v3_cpols.c:206`.
const V3_CPOLS_206: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(206, c"policy_section", ERR_R_ASN1_LIB);
/// `policy_section`'s failed `ASN1_STRING_set` at `v3_cpols.c:211`.
const V3_CPOLS_211: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(211, c"policy_section", ERR_R_ASN1_LIB);
/// `policy_section`'s `userNotice` without a section name at `v3_cpols.c:217`.
const V3_CPOLS_217: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(217, c"policy_section", X509V3_R_EXPECTED_A_SECTION_NAME);
/// `policy_section`'s missing `userNotice` section at `v3_cpols.c:223`.
const V3_CPOLS_223: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(223, c"policy_section", X509V3_R_INVALID_SECTION);
/// `policy_section`'s failed user-notice qualifier push at `v3_cpols.c:236`.
const V3_CPOLS_236: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(236, c"policy_section", ERR_R_CRYPTO_LIB);
/// `policy_section`'s unknown option at `v3_cpols.c:240`.
const V3_CPOLS_240: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(240, c"policy_section", X509V3_R_INVALID_OPTION);
/// `policy_section`'s missing `policyIdentifier` at `v3_cpols.c:246`.
const V3_CPOLS_246: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(246, c"policy_section", X509V3_R_NO_POLICY_IDENTIFIER);
/// `notice_section`'s failed `POLICYQUALINFO_new` at `v3_cpols.c:301`.
const V3_CPOLS_301: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(301, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed `OBJ_nid2obj(NID_id_qt_unotice)` at `v3_cpols.c:305`.
const V3_CPOLS_305: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(305, c"notice_section", ERR_R_INTERNAL_ERROR);
/// `notice_section`'s failed `USERNOTICE_new` at `v3_cpols.c:309`.
const V3_CPOLS_309: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(309, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed `ASN1_STRING_type_new` at `v3_cpols.c:320`.
const V3_CPOLS_320: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(320, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed `explicitText` set at `v3_cpols.c:327`.
const V3_CPOLS_327: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(327, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed `NOTICEREF_new` for `organization` at `v3_cpols.c:335`.
const V3_CPOLS_335: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(335, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed organization set at `v3_cpols.c:347`.
const V3_CPOLS_347: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(347, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s failed `NOTICEREF_new` for `noticeNumbers` at `v3_cpols.c:356`.
const V3_CPOLS_356: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(356, c"notice_section", ERR_R_ASN1_LIB);
/// `notice_section`'s bad `noticeNumbers` list at `v3_cpols.c:364`.
const V3_CPOLS_364: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(364, c"notice_section", X509V3_R_INVALID_NUMBERS);
/// `notice_section`'s unknown option at `v3_cpols.c:374`.
const V3_CPOLS_374: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(374, c"notice_section", X509V3_R_INVALID_OPTION);
/// `notice_section`'s incomplete notice reference at `v3_cpols.c:381`.
const V3_CPOLS_381: crate::runtime::err::err_sites::ErrSite = v3_cpols_site(
    381,
    c"notice_section",
    X509V3_R_NEED_ORGANIZATION_AND_NUMBERS,
);
/// `nref_nos`'s failed `s2i_ASN1_INTEGER` at `v3_cpols.c:402`.
const V3_CPOLS_402: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(402, c"nref_nos", X509V3_R_INVALID_NUMBER);
/// `nref_nos`'s failed stack push at `v3_cpols.c:407`.
const V3_CPOLS_407: crate::runtime::err::err_sites::ErrSite =
    v3_cpols_site(407, c"nref_nos", ERR_R_CRYPTO_LIB);

/// `struct POLICYINFO_st` — `POLICYINFO`, from `include/openssl/x509v3.h:473-476`.
#[repr(C)]
pub struct PolicyInfo {
    /// `ASN1_OBJECT *policyid` — the policy OID.
    pub policyid: *mut Asn1Object,
    /// `STACK_OF(POLICYQUALINFO) *qualifiers` — the optional qualifier list.
    pub qualifiers: *mut OpenSslStack,
}

/// `struct POLICYQUALINFO_st` — `POLICYQUALINFO`, from `include/openssl/x509v3.h:434-441`.
///
/// `d` is a pointer union (`d.cpsuri`/`d.usernotice`/`d.other`), modelled as one pointer because
/// every arm is the same width; the arm is chosen by the `ASN1_ADB` on `pqualid`.
#[repr(C)]
pub struct PolicyQualInfo {
    /// `ASN1_OBJECT *pqualid` — the qualifier OID, and the ADB selector.
    pub pqualid: *mut Asn1Object,
    /// The `d` union: `cpsuri`/`usernotice`/`other`, all one pointer.
    pub d: *mut c_void,
}

/// `struct USERNOTICE_st` — `USERNOTICE`, from `include/openssl/x509v3.h:429-432`.
#[repr(C)]
pub struct UserNotice {
    /// `NOTICEREF *noticeref` — optional and first on the wire.
    pub noticeref: *mut NoticeRef,
    /// `ASN1_STRING *exptext` — the optional explicit text.
    pub exptext: *mut Asn1String,
}

/// `struct NOTICEREF_st` — `NOTICEREF`, from `include/openssl/x509v3.h:424-427`.
#[repr(C)]
pub struct NoticeRef {
    /// `ASN1_STRING *organization` — a `DISPLAYTEXT`.
    pub organization: *mut Asn1String,
    /// `STACK_OF(ASN1_INTEGER) *noticenos` — the notice numbers.
    pub noticenos: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<PolicyInfo>() == 16);
    assert!(core::mem::offset_of!(PolicyInfo, policyid) == 0);
    assert!(core::mem::offset_of!(PolicyInfo, qualifiers) == 8);
    assert!(core::mem::size_of::<PolicyQualInfo>() == 16);
    assert!(core::mem::offset_of!(PolicyQualInfo, pqualid) == 0);
    assert!(core::mem::offset_of!(PolicyQualInfo, d) == 8);
    assert!(core::mem::size_of::<UserNotice>() == 16);
    assert!(core::mem::offset_of!(UserNotice, noticeref) == 0);
    assert!(core::mem::offset_of!(UserNotice, exptext) == 8);
    assert!(core::mem::size_of::<NoticeRef>() == 16);
    assert!(core::mem::offset_of!(NoticeRef, organization) == 0);
    assert!(core::mem::offset_of!(NoticeRef, noticenos) == 8);
};

/// The `ASN1_ADB` the ADB-carrying template points at. Wrapped because [`Asn1Adb`] holds raw
/// pointers and is therefore not `Sync`; the wrapper's `unsafe impl` is the same claim
/// [`crate::asn1::layout`] makes for [`Asn1Item`].
#[repr(transparent)]
struct SyncAdb(Asn1Adb);

// SAFETY: built from constants — a null callback, a `&'static` table of compiled-in templates and
// two `&'static`/null template pointers — written once by the loader and never again, and with no
// interior mutability reachable through a shared reference. The machinery only ever reads it.
unsafe impl Sync for SyncAdb {}

/// `policydefault_tt` — `ASN1_ADB_TEMPLATE(policydefault) = ASN1_SIMPLE(POLICYQUALINFO, d.other,
/// ASN1_ANY)` at `crypto/x509/v3_cpols.c:60`.
static POLICYQUAL_DEFAULT_TT: Asn1Template = Asn1Template {
    flags: 0,
    tag: 0,
    offset: 8,
    field_name: c"d.other".as_ptr(),
    item: ASN1_ANY_it as *mut c_void,
};

/// `POLICYQUALINFO_adbtbl[]` — `crypto/x509/v3_cpols.c:62-65`, in the authority's order: the CPS
/// URI (an `IA5String`) and the user notice (a `USERNOTICE`).
static POLICYQUALINFO_ADBTBL: [Asn1AdbTable; 2] = [
    Asn1AdbTable {
        value: NID_id_qt_cps as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"d.cpsuri".as_ptr(),
            item: ASN1_IA5STRING_it as *mut c_void,
        },
    },
    Asn1AdbTable {
        value: NID_id_qt_unotice as c_long,
        tt: Asn1Template {
            flags: 0,
            tag: 0,
            offset: 8,
            field_name: c"d.usernotice".as_ptr(),
            item: USERNOTICE_it as *mut c_void,
        },
    },
];

/// `POLICYQUALINFO_adb` — the `ASN1_ADB_END(POLICYQUALINFO, 0, pqualid, 0, &policydefault_tt,
/// NULL)` accessor at `:65`. Selector `pqualid` at offset 0; the default is `policydefault_tt`.
static POLICYQUALINFO_ADB: SyncAdb = SyncAdb(Asn1Adb {
    flags: 0,
    offset: 0,
    adb_cb: None,
    tbl: POLICYQUALINFO_ADBTBL.as_ptr(),
    tblcount: 2,
    default_tt: ptr::addr_of!(POLICYQUAL_DEFAULT_TT),
    null_tt: ptr::null(),
});

/// The `policydefault_adb` accessor the `ADB` template stores: it answers the `ASN1_ADB`, which the
/// machinery reads through `call_item_exp` exactly as it reads an item accessor.
fn policyqualinfo_adb() -> *const c_void {
    ptr::addr_of!(POLICYQUALINFO_ADB.0).cast::<c_void>()
}

/// `NOTICEREF_seq_tt` — `ASN1_SEQUENCE(NOTICEREF)` (`crypto/x509/v3_cpols.c:81-84`): the
/// `DISPLAYTEXT` organization and the `SEQUENCE OF ASN1_INTEGER` notice numbers.
static NOTICEREF_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"organization".as_ptr(),
        item: DISPLAYTEXT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"noticenos".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `NOTICEREF_it`'s descriptor — `ASN1_SEQUENCE_END(NOTICEREF)` at `crypto/x509/v3_cpols.c:84`.
static NOTICEREF_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NOTICEREF_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<NoticeRef>() as c_long,
    sname: c"NOTICEREF".as_ptr(),
};

/// `const ASN1_ITEM *NOTICEREF_it(void)` — `include/openssl/x509v3.h:879`.
#[no_mangle]
pub extern "C" fn NOTICEREF_it() -> *const Asn1Item {
    &NOTICEREF_ITEM
}

/// `NOTICEREF *NOTICEREF_new(void)` — `crypto/x509/v3_cpols.c:86`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(NOTICEREF)`.
#[no_mangle]
pub extern "C" fn NOTICEREF_new() -> *mut NoticeRef {
    // SAFETY: `NOTICEREF_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NOTICEREF_it()).cast::<NoticeRef>() }
}

/// `void NOTICEREF_free(NOTICEREF *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NOTICEREF_free(a: *mut NoticeRef) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NOTICEREF_it()) }
}

/// `NOTICEREF *d2i_NOTICEREF(NOTICEREF **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_NOTICEREF(
    a: *mut *mut NoticeRef,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut NoticeRef {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, NOTICEREF_it()).cast::<NoticeRef>() }
}

/// `int i2d_NOTICEREF(const NOTICEREF *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_NOTICEREF(a: *const NoticeRef, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, NOTICEREF_it()) }
}

/// `USERNOTICE_seq_tt` — `ASN1_SEQUENCE(USERNOTICE)` (`crypto/x509/v3_cpols.c:74-77`): the two
/// optional columns, `ASN1_OPT(noticeref, NOTICEREF)` and `ASN1_OPT(exptext, DISPLAYTEXT)`.
static USERNOTICE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"noticeref".as_ptr(),
        item: NOTICEREF_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"exptext".as_ptr(),
        item: DISPLAYTEXT_it as *mut c_void,
    },
];

/// `USERNOTICE_it`'s descriptor — `ASN1_SEQUENCE_END(USERNOTICE)` at `crypto/x509/v3_cpols.c:77`.
static USERNOTICE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: USERNOTICE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<UserNotice>() as c_long,
    sname: c"USERNOTICE".as_ptr(),
};

/// `const ASN1_ITEM *USERNOTICE_it(void)` — `include/openssl/x509v3.h:878`.
#[no_mangle]
pub extern "C" fn USERNOTICE_it() -> *const Asn1Item {
    &USERNOTICE_ITEM
}

/// `USERNOTICE *USERNOTICE_new(void)` — `crypto/x509/v3_cpols.c:79`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(USERNOTICE)`.
#[no_mangle]
pub extern "C" fn USERNOTICE_new() -> *mut UserNotice {
    // SAFETY: `USERNOTICE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(USERNOTICE_it()).cast::<UserNotice>() }
}

/// `void USERNOTICE_free(USERNOTICE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn USERNOTICE_free(a: *mut UserNotice) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), USERNOTICE_it()) }
}

/// `USERNOTICE *d2i_USERNOTICE(USERNOTICE **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_USERNOTICE(
    a: *mut *mut UserNotice,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut UserNotice {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, USERNOTICE_it()).cast::<UserNotice>() }
}

/// `int i2d_USERNOTICE(const USERNOTICE *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_USERNOTICE(a: *const UserNotice, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, USERNOTICE_it()) }
}

/// `POLICYQUALINFO_seq_tt` — `ASN1_SEQUENCE(POLICYQUALINFO)` (`crypto/x509/v3_cpols.c:67-70`): the
/// `pqualid` OID and the `ASN1_ADB_OBJECT` `d` column.
static POLICYQUALINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"pqualid".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_ADB_OID,
        tag: -1,
        offset: 0,
        field_name: c"POLICYQUALINFO".as_ptr(),
        item: policyqualinfo_adb as *mut c_void,
    },
];

/// `POLICYQUALINFO_it`'s descriptor — `ASN1_SEQUENCE_END(POLICYQUALINFO)` at
/// `crypto/x509/v3_cpols.c:70`.
static POLICYQUALINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: POLICYQUALINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PolicyQualInfo>() as c_long,
    sname: c"POLICYQUALINFO".as_ptr(),
};

/// `const ASN1_ITEM *POLICYQUALINFO_it(void)` — `include/openssl/x509v3.h:877`.
#[no_mangle]
pub extern "C" fn POLICYQUALINFO_it() -> *const Asn1Item {
    &POLICYQUALINFO_ITEM
}

/// `POLICYQUALINFO *POLICYQUALINFO_new(void)` — `crypto/x509/v3_cpols.c:72`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(POLICYQUALINFO)`.
#[no_mangle]
pub extern "C" fn POLICYQUALINFO_new() -> *mut PolicyQualInfo {
    // SAFETY: `POLICYQUALINFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(POLICYQUALINFO_it()).cast::<PolicyQualInfo>() }
}

/// `void POLICYQUALINFO_free(POLICYQUALINFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn POLICYQUALINFO_free(a: *mut PolicyQualInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), POLICYQUALINFO_it()) }
}

/// `POLICYQUALINFO *d2i_POLICYQUALINFO(POLICYQUALINFO **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_POLICYQUALINFO(
    a: *mut *mut PolicyQualInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut PolicyQualInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, POLICYQUALINFO_it()).cast::<PolicyQualInfo>() }
}

/// `int i2d_POLICYQUALINFO(const POLICYQUALINFO *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_POLICYQUALINFO(
    a: *const PolicyQualInfo,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, POLICYQUALINFO_it()) }
}

/// `POLICYINFO_seq_tt` — `ASN1_SEQUENCE(POLICYINFO)` (`crypto/x509/v3_cpols.c:53-56`): the
/// `policyid` OID and the optional `SEQUENCE OF POLICYQUALINFO` qualifiers.
static POLICYINFO_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"policyid".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"qualifiers".as_ptr(),
        item: POLICYQUALINFO_it as *mut c_void,
    },
];

/// `POLICYINFO_it`'s descriptor — `ASN1_SEQUENCE_END(POLICYINFO)` at `crypto/x509/v3_cpols.c:56`.
static POLICYINFO_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: POLICYINFO_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PolicyInfo>() as c_long,
    sname: c"POLICYINFO".as_ptr(),
};

/// `const ASN1_ITEM *POLICYINFO_it(void)` — `include/openssl/x509v3.h:876`.
#[no_mangle]
pub extern "C" fn POLICYINFO_it() -> *const Asn1Item {
    &POLICYINFO_ITEM
}

/// `POLICYINFO *POLICYINFO_new(void)` — `crypto/x509/v3_cpols.c:58`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(POLICYINFO)`.
#[no_mangle]
pub extern "C" fn POLICYINFO_new() -> *mut PolicyInfo {
    // SAFETY: `POLICYINFO_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(POLICYINFO_it()).cast::<PolicyInfo>() }
}

/// `void POLICYINFO_free(POLICYINFO *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn POLICYINFO_free(a: *mut PolicyInfo) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), POLICYINFO_it()) }
}

/// `POLICYINFO *d2i_POLICYINFO(POLICYINFO **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_POLICYINFO(
    a: *mut *mut PolicyInfo,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut PolicyInfo {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, POLICYINFO_it()).cast::<PolicyInfo>() }
}

/// `int i2d_POLICYINFO(const POLICYINFO *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_POLICYINFO(a: *const PolicyInfo, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, POLICYINFO_it()) }
}

/// `CERTIFICATEPOLICIES_item_tt` — `ASN1_ITEM_TEMPLATE(CERTIFICATEPOLICIES)` at
/// `crypto/x509/v3_cpols.c:48`, an `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
/// CERTIFICATEPOLICIES, POLICYINFO)`.
static CERTIFICATEPOLICIES_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"CERTIFICATEPOLICIES".as_ptr(),
    item: POLICYINFO_it as *mut c_void,
};

/// `CERTIFICATEPOLICIES_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(CERTIFICATEPOLICIES)` at
/// `crypto/x509/v3_cpols.c:49`: a `PRIMITIVE` item over one `SEQUENCE OF` template.
static CERTIFICATEPOLICIES_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &CERTIFICATEPOLICIES_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"CERTIFICATEPOLICIES".as_ptr(),
};

/// `const ASN1_ITEM *CERTIFICATEPOLICIES_it(void)` — `include/openssl/x509v3.h:875`.
#[no_mangle]
pub extern "C" fn CERTIFICATEPOLICIES_it() -> *const Asn1Item {
    &CERTIFICATEPOLICIES_ITEM
}

/// `CERTIFICATEPOLICIES *CERTIFICATEPOLICIES_new(void)` — `crypto/x509/v3_cpols.c:51`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)`. The value is a `STACK_OF(POLICYINFO)`.
#[no_mangle]
pub extern "C" fn CERTIFICATEPOLICIES_new() -> *mut OpenSslStack {
    // SAFETY: `CERTIFICATEPOLICIES_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(CERTIFICATEPOLICIES_it()).cast::<OpenSslStack>() }
}

/// `void CERTIFICATEPOLICIES_free(CERTIFICATEPOLICIES *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn CERTIFICATEPOLICIES_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), CERTIFICATEPOLICIES_it()) }
}

/// `CERTIFICATEPOLICIES *d2i_CERTIFICATEPOLICIES(CERTIFICATEPOLICIES **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_CERTIFICATEPOLICIES(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, CERTIFICATEPOLICIES_it()).cast::<OpenSslStack>() }
}

/// `int i2d_CERTIFICATEPOLICIES(const CERTIFICATEPOLICIES *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_CERTIFICATEPOLICIES(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, CERTIFICATEPOLICIES_it()) }
}

/// Appends `p`'s bytes, or the literal `<NULL>` when `p` is NULL — `crypto/err/err.c:855-856`,
/// the convention `ERR_add_error_data` uses.
///
/// # Safety
///
/// `p` must be NULL or NUL-terminated.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { CStr::from_ptr(p) }.to_bytes());
    }
}

/// `X509V3_conf_err(val)` — the `x509v3.h:632-635` macro's expansion,
/// `ERR_add_error_data(6, "section:", (val)->section, ",name:", (val)->name, ",value:",
/// (val)->value)`.
///
/// # Safety
///
/// `val` must be a live `CONF_VALUE`.
unsafe fn conf_err(val: *const ConfValue) {
    let mut buf: Vec<u8> = b"section:".to_vec();
    // SAFETY: `val` is live per the contract.
    unsafe { push_cstr_or_null(&mut buf, (*val).section) };
    buf.extend_from_slice(b",name:");
    // SAFETY: as above.
    unsafe { push_cstr_or_null(&mut buf, (*val).name) };
    buf.extend_from_slice(b",value:");
    // SAFETY: as above.
    unsafe { push_cstr_or_null(&mut buf, (*val).value) };
    buf.push(0);
    // SAFETY: `buf` is NUL-terminated.
    unsafe { openssl_rs_err_add_data(buf.as_ptr().cast::<c_char>()) };
}

/// `void (*)(void *)` thunk for `sk_POLICYINFO_pop_free(..., POLICYINFO_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `POLICYINFO` (the stack contract).
unsafe extern "C" fn policyinfo_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `POLICYINFO` pointers per the contract.
    unsafe { POLICYINFO_free(p.cast::<PolicyInfo>()) };
}

/// `void (*)(void *)` thunk for `sk_CONF_VALUE_pop_free(..., X509V3_conf_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `static int displaytext_get_tag_len(const char *tagstr)` — `crypto/x509/v3_cpols.c:257-262`.
///
/// The index of the first `:`, or `-1` when there is none.
///
/// # Safety
///
/// `tagstr` is NUL-terminated.
unsafe fn displaytext_get_tag_len(tagstr: *const c_char) -> c_int {
    // SAFETY: `tagstr` is NUL-terminated per the contract.
    let colon = unsafe { strchr(tagstr, b':' as c_int) };
    if colon.is_null() {
        -1
    } else {
        // SAFETY: `colon` points inside the string `tagstr` starts.
        unsafe { (colon as *const c_char).offset_from(tagstr) as c_int }
    }
}

/// `static int displaytext_str2tag(const char *tagstr, unsigned int *tag_len)` —
/// `crypto/x509/v3_cpols.c:264-288`.
///
/// Six `name:` prefixes select the string type; anything else (or no colon) is
/// `V_ASN1_VISIBLESTRING` with `*tag_len` zeroed.
///
/// # Safety
///
/// `tagstr` is NUL-terminated; `tag_len` is writable.
unsafe fn displaytext_str2tag(tagstr: *const c_char, tag_len: *mut c_uint) -> c_int {
    // SAFETY: `tag_len` is writable per the contract.
    unsafe { *tag_len = 0 };
    // SAFETY: `tagstr` is NUL-terminated per the contract.
    let len = unsafe { displaytext_get_tag_len(tagstr) };
    if len == -1 {
        return V_ASN1_VISIBLESTRING;
    }
    // SAFETY: `tag_len` is writable per the contract.
    unsafe { *tag_len = len as c_uint };
    let l = len as usize;
    // SAFETY: each literal is static and `tagstr` has at least `l` readable bytes when `l` matched.
    if l == 4 && unsafe { strncmp(tagstr, c"UTF8".as_ptr(), 4) } == 0 {
        return V_ASN1_UTF8STRING;
    }
    // SAFETY: as above.
    if l == 10 && unsafe { strncmp(tagstr, c"UTF8String".as_ptr(), 10) } == 0 {
        return V_ASN1_UTF8STRING;
    }
    // SAFETY: as above.
    if l == 3 && unsafe { strncmp(tagstr, c"BMP".as_ptr(), 3) } == 0 {
        return V_ASN1_BMPSTRING;
    }
    // SAFETY: as above.
    if l == 9 && unsafe { strncmp(tagstr, c"BMPSTRING".as_ptr(), 9) } == 0 {
        return V_ASN1_BMPSTRING;
    }
    // SAFETY: as above.
    if l == 7 && unsafe { strncmp(tagstr, c"VISIBLE".as_ptr(), 7) } == 0 {
        return V_ASN1_VISIBLESTRING;
    }
    // SAFETY: as above.
    if l == 13 && unsafe { strncmp(tagstr, c"VISIBLESTRING".as_ptr(), 13) } == 0 {
        return V_ASN1_VISIBLESTRING;
    }
    // SAFETY: `tag_len` is writable per the contract.
    unsafe { *tag_len = 0 };
    V_ASN1_VISIBLESTRING
}

/// `static int nref_nos(STACK_OF(ASN1_INTEGER) *nnums, STACK_OF(CONF_VALUE) *nos)` —
/// `crypto/x509/v3_cpols.c:392-412`.
///
/// One `s2i_ASN1_INTEGER` per `CONF_VALUE`'s name, pushed onto `nnums`.
///
/// # Safety
///
/// `nnums` is a live `STACK_OF(ASN1_INTEGER)`; `nos` is a live `STACK_OF(CONF_VALUE)`.
unsafe fn nref_nos(nnums: *mut OpenSslStack, nos: *mut OpenSslStack) -> c_int {
    // SAFETY: `nos` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(nos) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nos` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(nos, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live; `name` is NULL or NUL-terminated.
        let aint = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), (*cnf).name) };
        if aint.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CPOLS_402) };
            return 0;
        }
        // SAFETY: `nnums` is live; `aint` is a fresh integer.
        if unsafe { OPENSSL_sk_push(nnums, aint.cast::<c_void>()) } == 0 {
            // SAFETY: `aint` is this call's own.
            unsafe { ASN1_INTEGER_free(aint) };
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CPOLS_407) };
            return 0;
        }
        i += 1;
    }
    1
}

/// `static POLICYINFO *policy_section(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *polstrs, int ia5org)`
/// — `crypto/x509/v3_cpols.c:165-255`.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `polstrs` is a live `STACK_OF(CONF_VALUE)`.
unsafe fn policy_section(
    ctx: *mut X509V3Ctx,
    polstrs: *mut OpenSslStack,
    ia5org: c_int,
) -> *mut PolicyInfo {
    let pol = POLICYINFO_new();
    if pol.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_174) };
        return ptr::null_mut();
    }
    // SAFETY: `polstrs` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(polstrs) };
    let mut failed = false;
    let mut i = 0;
    while i < num {
        // SAFETY: `polstrs` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(polstrs, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        if unsafe { strcmp((*cnf).name, c"policyIdentifier".as_ptr()) } == 0 {
            // SAFETY: `cnf` is live; `value` is NULL or NUL-terminated.
            let pobj = unsafe { OBJ_txt2obj((*cnf).value, 0) };
            if pobj.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_183) };
                // SAFETY: `cnf` is live.
                unsafe { conf_err(cnf) };
                failed = true;
                break;
            }
            // SAFETY: `pol` is live; the field slot is writable.
            unsafe { (*pol).policyid = pobj };
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        } else if unsafe { ossl_v3_name_cmp((*cnf).name, c"CPS".as_ptr()) } == 0 {
            // SAFETY: `pol` is live; the field slot is writable.
            if unsafe { (*pol).qualifiers.is_null() } {
                // SAFETY: `pol` is live; the field slot is writable.
                unsafe { (*pol).qualifiers = OPENSSL_sk_new_null() };
            }
            let qual = POLICYQUALINFO_new();
            if qual.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_193) };
                failed = true;
                break;
            }
            // SAFETY: `pol` is live; `qual` is a fresh qualifier.
            if unsafe { OPENSSL_sk_push((*pol).qualifiers, qual.cast::<c_void>()) } == 0 {
                // SAFETY: `qual` is this call's own.
                unsafe { POLICYQUALINFO_free(qual) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_198) };
                failed = true;
                break;
            }
            // SAFETY: `qual` is live; the field slot is writable.
            unsafe { (*qual).pqualid = OBJ_nid2obj(NID_id_qt_cps) };
            // SAFETY: `qual` is live.
            if unsafe { (*qual).pqualid.is_null() } {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_202) };
                failed = true;
                break;
            }
            let cpsuri = ASN1_IA5STRING_new();
            // SAFETY: `qual` is live; the union slot is writable.
            unsafe { (*qual).d = cpsuri.cast::<c_void>() };
            if cpsuri.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_206) };
                failed = true;
                break;
            }
            // SAFETY: `cpsuri` is live; `cnf->value` is NUL-terminated.
            let len = unsafe { strlen((*cnf).value) } as c_int;
            // SAFETY: `cpsuri` is live and `cnf->value` is NUL-terminated.
            if unsafe { ASN1_STRING_set(cpsuri, (*cnf).value.cast::<c_void>(), len) } == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_211) };
                failed = true;
                break;
            }
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        } else if unsafe { ossl_v3_name_cmp((*cnf).name, c"userNotice".as_ptr()) } == 0 {
            // SAFETY: `cnf->value` is NUL-terminated.
            if unsafe { *(*cnf).value } != b'@' as c_char {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_217) };
                // SAFETY: `cnf` is live.
                unsafe { conf_err(cnf) };
                failed = true;
                break;
            }
            // SAFETY: `cntx` is live; `value + 1` points into its NUL-terminated string.
            let unot = unsafe { X509V3_get_section(ctx, (*cnf).value.add(1)) };
            if unot.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_223) };
                // SAFETY: `cnf` is live.
                unsafe { conf_err(cnf) };
                failed = true;
                break;
            }
            // SAFETY: `ctx` is live; `unot` is a live section.
            let qual = unsafe { notice_section(ctx, unot, ia5org) };
            // SAFETY: `ctx` is live; `unot` is a live section.
            unsafe { X509V3_section_free(ctx, unot) };
            if qual.is_null() {
                failed = true;
                break;
            }
            // SAFETY: `pol` is live; the field slot is writable.
            if unsafe { (*pol).qualifiers.is_null() } {
                // SAFETY: `pol` is live; the field slot is writable.
                unsafe { (*pol).qualifiers = OPENSSL_sk_new_null() };
            }
            // SAFETY: `pol` is live; `qual` is a fresh qualifier.
            if unsafe { OPENSSL_sk_push((*pol).qualifiers, qual.cast::<c_void>()) } == 0 {
                // SAFETY: `qual` is this call's own.
                unsafe { POLICYQUALINFO_free(qual) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_236) };
                failed = true;
                break;
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CPOLS_240) };
            // SAFETY: `cnf` is live.
            unsafe { conf_err(cnf) };
            failed = true;
            break;
        }
        i += 1;
    }
    // SAFETY: `pol` is live.
    if !failed && unsafe { (*pol).policyid.is_null() } {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_246) };
        failed = true;
    }
    if failed {
        // SAFETY: `pol` is a live value this call owns.
        unsafe { POLICYINFO_free(pol) };
        return ptr::null_mut();
    }
    pol
}

/// `static POLICYQUALINFO *notice_section(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *unot,
/// int ia5org)` — `crypto/x509/v3_cpols.c:290-390`.
///
/// # Safety
///
/// `ctx` is a live `X509V3_CTX`; `unot` is a live `STACK_OF(CONF_VALUE)`.
unsafe fn notice_section(
    ctx: *mut X509V3Ctx,
    unot: *mut OpenSslStack,
    ia5org: c_int,
) -> *mut PolicyQualInfo {
    let qual = POLICYQUALINFO_new();
    if qual.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_301) };
        return ptr::null_mut();
    }
    // SAFETY: `qual` is live; the field slot is writable.
    unsafe { (*qual).pqualid = OBJ_nid2obj(NID_id_qt_unotice) };
    // SAFETY: `qual` is live.
    if unsafe { (*qual).pqualid.is_null() } {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_305) };
        // SAFETY: `qual` is a live value this call owns.
        unsafe { POLICYQUALINFO_free(qual) };
        return ptr::null_mut();
    }
    let not = USERNOTICE_new();
    if not.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_309) };
        // SAFETY: `qual` is a live value this call owns.
        unsafe { POLICYQUALINFO_free(qual) };
        return ptr::null_mut();
    }
    // SAFETY: `qual` is live; the union slot is writable.
    unsafe { (*qual).d = not.cast::<c_void>() };
    // SAFETY: `unot` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(unot) };
    let mut failed = false;
    let mut i = 0;
    while i < num {
        // SAFETY: `unot` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(unot, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live; `value` is NULL or NUL-terminated.
        let mut value = unsafe { (*cnf).value };
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        if unsafe { strcmp((*cnf).name, c"explicitText".as_ptr()) } == 0 {
            let mut tag_len: c_uint = 0;
            // SAFETY: `value` is NUL-terminated; `tag_len` is writable.
            let tag = unsafe { displaytext_str2tag(value, &raw mut tag_len) };
            // SAFETY: `not` is live; the field slot is writable.
            unsafe { (*not).exptext = ASN1_STRING_type_new(tag) };
            // SAFETY: `not` is live.
            if unsafe { (*not).exptext.is_null() } {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_320) };
                failed = true;
                break;
            }
            if tag_len != 0 {
                // SAFETY: `value` points into a NUL-terminated string with at least
                // `tag_len + 1` bytes before its terminator.
                value = unsafe { value.add(tag_len as usize + 1) };
            }
            // SAFETY: `not` is live; `value` is NUL-terminated.
            let len = unsafe { strlen(value) } as c_int;
            // SAFETY: `not->exptext` is live and `value` is NUL-terminated.
            if unsafe { ASN1_STRING_set((*not).exptext, value.cast::<c_void>(), len) } == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_327) };
                failed = true;
                break;
            }
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        } else if unsafe { strcmp((*cnf).name, c"organization".as_ptr()) } == 0 {
            // SAFETY: `not` is live; `noticeref` is NULL or its own.
            let mut nref = unsafe { (*not).noticeref };
            if nref.is_null() {
                nref = NOTICEREF_new();
                if nref.is_null() {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_CPOLS_335) };
                    failed = true;
                    break;
                }
                // SAFETY: `not` is live; the field slot is writable.
                unsafe { (*not).noticeref = nref };
            }
            // SAFETY: `nref` is live; `organization` is its live string.
            unsafe {
                if ia5org != 0 {
                    (*(*nref).organization).type_ = V_ASN1_IA5STRING;
                } else {
                    (*(*nref).organization).type_ = V_ASN1_VISIBLESTRING;
                }
            }
            // SAFETY: `nref` is live; `cnf->value` is NUL-terminated.
            let len = unsafe { strlen((*cnf).value) } as c_int;
            // SAFETY: `nref->organization` is live and `cnf->value` is NUL-terminated.
            if unsafe { ASN1_STRING_set((*nref).organization, (*cnf).value.cast::<c_void>(), len) }
                == 0
            {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_347) };
                failed = true;
                break;
            }
        // SAFETY: `cnf` is live; `name` is NUL-terminated.
        } else if unsafe { strcmp((*cnf).name, c"noticeNumbers".as_ptr()) } == 0 {
            // SAFETY: `not` is live; `noticeref` is NULL or its own.
            let mut nref = unsafe { (*not).noticeref };
            if nref.is_null() {
                nref = NOTICEREF_new();
                if nref.is_null() {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_CPOLS_356) };
                    failed = true;
                    break;
                }
                // SAFETY: `not` is live; the field slot is writable.
                unsafe { (*not).noticeref = nref };
            }
            // SAFETY: `cnf->value` is NULL or NUL-terminated.
            let nos = unsafe { X509V3_parse_list((*cnf).value) };
            // SAFETY: `nos` is NULL or live.
            let nos_num = unsafe { OPENSSL_sk_num(nos) };
            if nos.is_null() || nos_num == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_364) };
                // SAFETY: `cnf` is live.
                unsafe { conf_add_error_name_value(cnf) };
                // SAFETY: `nos` is NULL or a live list this call owns.
                unsafe { OPENSSL_sk_pop_free(nos, Some(conf_free_thunk)) };
                failed = true;
                break;
            }
            // SAFETY: `nref` is live; `nos` is a live list.
            let ret = unsafe { nref_nos((*nref).noticenos, nos) };
            // SAFETY: `nos` is a live list this call owns.
            unsafe { OPENSSL_sk_pop_free(nos, Some(conf_free_thunk)) };
            if ret == 0 {
                failed = true;
                break;
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CPOLS_374) };
            // SAFETY: `cnf` is live.
            unsafe { conf_add_error_name_value(cnf) };
            failed = true;
            break;
        }
        i += 1;
    }
    // SAFETY: `not` is live; `noticeref` is NULL or its own.
    let incomplete = unsafe {
        let nref = (*not).noticeref;
        !nref.is_null() && ((*nref).noticenos.is_null() || (*nref).organization.is_null())
    };
    if !failed && incomplete {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_381) };
        failed = true;
    }
    let _ = ctx;
    if failed {
        // SAFETY: `qual` is a live value this call owns.
        unsafe { POLICYQUALINFO_free(qual) };
        return ptr::null_mut();
    }
    qual
}

/// `static STACK_OF(POLICYINFO) *r2i_certpol(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// const char *value)` — `crypto/x509/v3_cpols.c:88-163`.
///
/// # Safety
///
/// `ctx` is NULL or a live `X509V3_CTX`; `value` is NUL-terminated.
unsafe extern "C" fn r2i_certpol(
    _method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    value: *const c_char,
) -> *mut c_void {
    // SAFETY: `value` is NUL-terminated per the caller's contract.
    let vals = unsafe { X509V3_parse_list(value) };
    // SAFETY: `vals` is NULL or live; the authority reads `sk_num` before its NULL test.
    let num = unsafe { OPENSSL_sk_num(vals) };
    if vals.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_101) };
        return ptr::null_mut();
    }
    let pols = OPENSSL_sk_new_reserve(None, num);
    if pols.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_CPOLS_107) };
        // SAFETY: `vals` is a live list this call owns.
        unsafe { OPENSSL_sk_pop_free(vals, Some(conf_free_thunk)) };
        return ptr::null_mut();
    }
    let ctx = ctx.cast::<X509V3Ctx>();
    let mut ia5org = 0;
    let mut failed = false;
    let mut i = 0;
    while i < num {
        // SAFETY: `vals` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(vals, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live; each field is NULL or NUL-terminated.
        if unsafe { !(*cnf).value.is_null() || (*cnf).name.is_null() } {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_CPOLS_115) };
            // SAFETY: `cnf` is live.
            unsafe { conf_add_error_name_value(cnf) };
            failed = true;
            break;
        }
        // SAFETY: `cnf` is live; `name` is non-NULL and NUL-terminated.
        let pstr = unsafe { (*cnf).name };
        // SAFETY: `pstr` is NUL-terminated.
        if unsafe { strcmp(pstr, c"ia5org".as_ptr()) } == 0 {
            ia5org = 1;
            i += 1;
            continue;
        // SAFETY: `pstr` points at a NUL-terminated string.
        } else if unsafe { *pstr } == b'@' as c_char {
            // SAFETY: `ctx` is live; `pstr + 1` points into the NUL-terminated name.
            let polsect = unsafe { X509V3_get_section(ctx, pstr.add(1)) };
            if polsect.is_null() {
                // SAFETY: `cnf->name` is NUL-terminated; the site is a compiled-in constant.
                unsafe { raise_site_data(&V3_CPOLS_128, (*cnf).name) };
                failed = true;
                break;
            }
            // SAFETY: `ctx` is live; `polsect` is a live section.
            let pol = unsafe { policy_section(ctx, polsect, ia5org) };
            // SAFETY: `ctx` is live; `polsect` is a live section.
            unsafe { X509V3_section_free(ctx, polsect) };
            if pol.is_null() {
                failed = true;
                break;
            }
            // SAFETY: `pols` is live; `pol` is a fresh value.
            if unsafe { OPENSSL_sk_push(pols, pol.cast::<c_void>()) } == 0 {
                // SAFETY: `pol` is this call's own.
                unsafe { POLICYINFO_free(pol) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_153) };
                failed = true;
                break;
            }
        } else {
            // SAFETY: `cnf->name` is NULL or NUL-terminated.
            let pobj = unsafe { OBJ_txt2obj((*cnf).name, 0) };
            if pobj.is_null() {
                // SAFETY: `cnf->name` is NUL-terminated; the site is a compiled-in constant.
                unsafe { raise_site_data(&V3_CPOLS_138, (*cnf).name) };
                failed = true;
                break;
            }
            let pol = POLICYINFO_new();
            if pol.is_null() {
                // SAFETY: `pobj` is this call's own.
                unsafe { ASN1_OBJECT_free(pobj) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_146) };
                failed = true;
                break;
            }
            // SAFETY: `pol` is live; the field slot is writable.
            unsafe { (*pol).policyid = pobj };
            // SAFETY: `pols` is live; `pol` is a fresh value.
            if unsafe { OPENSSL_sk_push(pols, pol.cast::<c_void>()) } == 0 {
                // SAFETY: `pol` is this call's own.
                unsafe { POLICYINFO_free(pol) };
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_CPOLS_153) };
                failed = true;
                break;
            }
        }
        i += 1;
    }
    // SAFETY: `vals` is a live list this call owns.
    unsafe { OPENSSL_sk_pop_free(vals, Some(conf_free_thunk)) };
    if failed {
        // SAFETY: `pols` is a live list this call owns.
        unsafe { OPENSSL_sk_pop_free(pols, Some(policyinfo_free_thunk)) };
        return ptr::null_mut();
    }
    pols.cast::<c_void>()
}

/// `static int i2r_certpol(X509V3_EXT_METHOD *method, STACK_OF(POLICYINFO) *pol, BIO *out,
/// int indent)` — `crypto/x509/v3_cpols.c:414-432`.
///
/// One `Policy: <oid>` line per policy, with a blank line between, and — when the policy has
/// qualifiers — the qualifiers printed by [`print_qualifiers`] two columns deeper.
unsafe extern "C" fn i2r_certpol(
    _method: *const X509V3ExtMethod,
    pol: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let pol = pol.cast::<OpenSslStack>();
    // SAFETY: `pol` is a live `STACK_OF(POLICYINFO)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(pol) };
    let mut i = 0;
    while i < num {
        if i > 0 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: `pol` is live and `i` is in bounds.
        let pinfo = unsafe { OPENSSL_sk_value(pol, i) }.cast::<PolicyInfo>();
        // SAFETY: `out` is live; the format and its arguments are constants.
        unsafe { BIO_printf(out, c"%*sPolicy: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live; `pinfo->policyid` is its live object.
        unsafe { i2a_ASN1_OBJECT(out, (*pinfo).policyid) };
        // SAFETY: `pinfo` is live; `qualifiers` is NULL or its own list.
        if !unsafe { (*pinfo).qualifiers }.is_null() {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
            // SAFETY: `out` is live; `qualifiers` is a live list.
            unsafe { print_qualifiers(out, (*pinfo).qualifiers, indent + 2) };
        }
        i += 1;
    }
    1
}

/// `static void print_qualifiers(BIO *out, STACK_OF(POLICYQUALINFO) *quals, int indent)` —
/// `crypto/x509/v3_cpols.c:434-462`.
///
/// # Safety
///
/// `out` is a live BIO; `quals` is a live `STACK_OF(POLICYQUALINFO)`.
unsafe fn print_qualifiers(out: *mut Bio, quals: *mut OpenSslStack, indent: c_int) {
    // SAFETY: `quals` is live per the contract.
    let num = unsafe { OPENSSL_sk_num(quals) };
    let mut i = 0;
    while i < num {
        if i > 0 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
        // SAFETY: `quals` is live and `i` is in bounds.
        let qualinfo = unsafe { OPENSSL_sk_value(quals, i) }.cast::<PolicyQualInfo>();
        // SAFETY: `qualinfo` is live; `pqualid` is its live object.
        match unsafe { OBJ_obj2nid((*qualinfo).pqualid) } {
            n if n == NID_id_qt_cps => {
                // SAFETY: the CPS arm of the union is an `ASN1_IA5STRING`.
                let cpsuri = unsafe { (*qualinfo).d.cast::<Asn1String>() };
                // SAFETY: `out` is live; `cpsuri` is the live arm selected by the OID.
                unsafe {
                    BIO_printf(
                        out,
                        c"%*sCPS: %.*s".as_ptr(),
                        indent,
                        c"".as_ptr(),
                        (*cpsuri).length,
                        (*cpsuri).data.cast::<c_char>(),
                    )
                };
            }
            n if n == NID_id_qt_unotice => {
                // SAFETY: the userNotice arm of the union is a `USERNOTICE`.
                let usernotice = unsafe { (*qualinfo).d.cast::<UserNotice>() };
                // SAFETY: `out` is live; the format and its arguments are constants.
                unsafe { BIO_printf(out, c"%*sUser Notice:\n".as_ptr(), indent, c"".as_ptr()) };
                // SAFETY: `out` is live; `usernotice` is the live arm.
                unsafe { print_notice(out, usernotice, indent + 2) };
            }
            _ => {
                // SAFETY: `out` is live; the format and its arguments are constants.
                unsafe {
                    BIO_printf(
                        out,
                        c"%*sUnknown Qualifier: ".as_ptr(),
                        indent + 2,
                        c"".as_ptr(),
                    )
                };
                // SAFETY: `out` is live; `pqualid` is its live object.
                unsafe { i2a_ASN1_OBJECT(out, (*qualinfo).pqualid) };
            }
        }
        i += 1;
    }
}

/// `static void print_notice(BIO *out, USERNOTICE *notice, int indent)` —
/// `crypto/x509/v3_cpols.c:464-498`.
///
/// # Safety
///
/// `out` is a live BIO; `notice` is a live `USERNOTICE`.
unsafe fn print_notice(out: *mut Bio, notice: *mut UserNotice, indent: c_int) {
    // SAFETY: `notice` is live per the contract.
    if !unsafe { (*notice).noticeref }.is_null() {
        // SAFETY: `notice` is live; `noticeref` is its live reference.
        let reference = unsafe { (*notice).noticeref };
        // SAFETY: `out` is live; `reference->organization` is its live string.
        unsafe {
            BIO_printf(
                out,
                c"%*sOrganization: %.*s\n".as_ptr(),
                indent,
                c"".as_ptr(),
                (*(*reference).organization).length,
                (*(*reference).organization).data.cast::<c_char>(),
            )
        };
        // SAFETY: `reference` is live; `noticenos` is its live list.
        let num = unsafe { OPENSSL_sk_num((*reference).noticenos) };
        let plural = if num > 1 { c"s".as_ptr() } else { c"".as_ptr() };
        // SAFETY: `out` is live; `plural` is static.
        unsafe { BIO_printf(out, c"%*sNumber%s: ".as_ptr(), indent, c"".as_ptr(), plural) };
        let mut i = 0;
        while i < num {
            // SAFETY: `reference->noticenos` is live and `i` is in bounds.
            let num_p = unsafe { OPENSSL_sk_value((*reference).noticenos, i) }.cast::<Asn1String>();
            if i > 0 {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c", ".as_ptr()) };
            }
            if num_p.is_null() {
                // SAFETY: `out` is live; the literal is static.
                unsafe { BIO_puts(out, c"(null)".as_ptr()) };
            } else {
                // SAFETY: `num_p` is a live integer.
                let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), num_p) };
                if tmp.is_null() {
                    return;
                }
                // SAFETY: `out` is live; `tmp` is NUL-terminated.
                unsafe { BIO_puts(out, tmp) };
                // SAFETY: `tmp` is this call's own.
                unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 488) };
            }
            i += 1;
        }
        // SAFETY: `notice` is live; `exptext` is NULL or its own.
        if !unsafe { (*notice).exptext }.is_null() {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_puts(out, c"\n".as_ptr()) };
        }
    }
    // SAFETY: `notice` is live; `exptext` is NULL or its own.
    if !unsafe { (*notice).exptext }.is_null() {
        // SAFETY: `out` is live; `exptext` is its live string.
        unsafe {
            BIO_printf(
                out,
                c"%*sExplicit Text: %.*s".as_ptr(),
                indent,
                c"".as_ptr(),
                (*(*notice).exptext).length,
                (*(*notice).exptext).data.cast::<c_char>(),
            )
        };
    }
}

/// `void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent)` —
/// `crypto/x509/v3_cpols.c:500-515`.
///
/// # Safety
///
/// `out` is a live BIO; `node` is a live `X509_POLICY_NODE`.
#[no_mangle]
pub unsafe extern "C" fn X509_POLICY_NODE_print(
    out: *mut Bio,
    node: *mut X509PolicyNode,
    indent: c_int,
) {
    // SAFETY: `node` is live per the contract; `data` is its live policy data.
    let dat = unsafe { (*node).data };
    // SAFETY: `out` is live; the format and its arguments are constants.
    unsafe { BIO_printf(out, c"%*sPolicy: ".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `out` is live; `dat->valid_policy` is its live object.
    unsafe { i2a_ASN1_OBJECT(out, (*dat).valid_policy) };
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    // SAFETY: `dat` is live.
    let critical = if unsafe { (*dat).flags & POLICY_DATA_FLAG_CRITICAL } != 0 {
        c"Critical".as_ptr()
    } else {
        c"Non Critical".as_ptr()
    };
    // SAFETY: `out` is live; `critical` is static.
    unsafe { BIO_printf(out, c"%*s%s\n".as_ptr(), indent + 2, c"".as_ptr(), critical) };
    // SAFETY: `dat` is live; `qualifier_set` is NULL or its own list.
    if !unsafe { (*dat).qualifier_set }.is_null() {
        // SAFETY: `out` is live; `qualifier_set` is a live list.
        unsafe { print_qualifiers(out, (*dat).qualifier_set, indent + 2) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the format and its arguments are constants.
        unsafe {
            BIO_printf(
                out,
                c"%*sNo Qualifiers\n".as_ptr(),
                indent + 2,
                c"".as_ptr(),
            )
        };
    }
}

/// `const X509V3_EXT_METHOD ossl_v3_cpols` — `crypto/x509/v3_cpols.c:38-46`.
///
/// `it` is `CERTIFICATEPOLICIES_it`; `i2r` is `i2r_certpol`; `r2i` is `r2i_certpol`; every other
/// slot is zero.
pub static ossl_v3_cpols: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_certificate_policies,
    ext_flags: 0,
    it: Some(CERTIFICATEPOLICIES_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_certpol),
    r2i: Some(r2i_certpol),
    usr_data: ptr::null_mut(),
};
