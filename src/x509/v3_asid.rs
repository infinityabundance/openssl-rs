//! `crypto/x509/v3_asid.c` — the RFC 3779 §3.2 `ASIdentifiers` item group and its row. Phase
//! 10.14.7's table layer, landed whole.
//!
//! `crypto/x509/v3_asid.c` is 871 lines (859 of them inside `#ifndef OPENSSL_NO_RFC3779`, which
//! this profile enables) and transcribes as follows:
//!
//! * The four ASN.1 templates (`:34-52`) land: `ASRange ::= SEQUENCE { min, max }`,
//!   `ASIdOrRange ::= CHOICE { id, range }`, `ASIdentifierChoice ::= CHOICE { inherit, asIdsOrRanges }`
//!   and `ASIdentifiers ::= SEQUENCE { asnum [0] EXPLICIT OPTIONAL, rdi [1] EXPLICIT OPTIONAL }`,
//!   with `ASRange_it`/`ASIdOrRange_it`/`ASIdentifierChoice_it`/`ASIdentifiers_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:54-57`). All four groups
//!   are public exports (`x509v3.h:867-870`), so the differential plane can build a value, encode it
//!   and decode the bytes back.
//! * The two printers land: `i2r_ASIdentifierChoice` (`:62-104`) and the row's callback
//!   `i2r_ASIdentifiers` (`:109-117`).
//! * The sort comparator `ASIdOrRange_cmp` (`:122-143`) lands, wired into the `ASIdOrRanges` stack
//!   `X509v3_asid_add_id_or_range` builds.
//! * The construction surface lands: `X509v3_asid_add_inherit` (`:148-174`),
//!   `X509v3_asid_add_id_or_range` (`:179-233`), `extract_min_max` (`:238-255`),
//!   `ASIdentifierChoice_is_canonical` (`:260-338`), `X509v3_asid_is_canonical` (`:343-346`),
//!   `ASIdentifierChoice_canonize` (`:351-482`), `X509v3_asid_canonize` (`:487-490`) and the
//!   config callback `v2i_ASIdentifiers` (`:495-609`).
//! * The containment surface lands: `X509v3_asid_inherits` (`:631-634`), `asid_contains`
//!   (`:639-668`) and `X509v3_asid_subset` (`:673-697`).
//! * The row [`ossl_v3_asid`] (`:614-626`) lands: `ext_nid` is `NID_sbgp_autonomousSysNum`, `it` is
//!   `ASN1_ITEM_ref(ASIdentifiers)`, `v2i` is `v2i_ASIdentifiers` and `i2r` is `i2r_ASIdentifiers`.
//!   It is one row, not two: the authority's table is the autonomous-system half only, the
//!   `ipAddrBlock` row living in `v3_addr.c` (`NID_sbgp_ipAddrBlock`), a unit this subphase does
//!   not own.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456), so the array is the last thing to land, not the first; this unit contributes one of the
//! 63 tables. The row is internal data the admitted DSO does not export (`nm -D` shows no
//! `ossl_v3_*`), so no court can name it; its drivable surface is the four exported item groups and
//! the `X509v3_asid_*` accessors.
//!
//! * The path-validation surface lands: `asid_validate_path_internal` (`:719-837`),
//!   `X509v3_asid_validate_path` (`:844-853`) and `X509v3_asid_validate_resource_set` (`:859-869`).
//!   The `validation_err` macro (`:702-714`) is transcribed as a private function of the same name:
//!   a `macro_rules!` body cannot name its caller's `ctx`/`x`/`i`/`ret`, so the macro's `goto done`
//!   becomes the caller's `if ret == 0 { return ret; }` and the helper returns the callback's value.
//!   The blocker this file used to record is resolved: `X509_STORE_CTX` is 11.1a's `X509StoreCtx`
//!   (`src/x509/x509_lu.rs`), whose `pub(crate)` `chain`, `error`, `error_depth`, `current_cert` and
//!   `verify_cb` members are read here; the walk uses the generic `OPENSSL_sk_num`/`OPENSSL_sk_value`
//!   rather than typed `sk_X509_*` wrappers. No `ERR_raise` coordinate is added -- the block raises
//!   nothing, as it raises nothing in the authority.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_asid.c` is not an entry in `gen_err_raise_sites.py`, so its sixteen coordinates
//! are **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`
//! (not typed from memory), as `v3_bitst.rs` does. `ERR_LIB_X509V3` is `err.h.in:99`; the three
//! `ERR_R_*_LIB` composite reasons are the `err.h.in` rows `:319`/`:328`/`:335`; the five
//! `X509V3_R_*` reasons are the `x509v3err.h` rows read below the helper.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_NULL_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_to_BN, BN_to_ASN1_INTEGER};
use crate::asn1::string::ASN1_INTEGER_free;
use crate::asn1::typ::ASN1_NULL_new;
use crate::bn::arith::BN_add_word;
use crate::bn::bignum::{BN_free, BN_new, BigNum};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_EXTENSION_NAME_ERROR, X509V3_R_EXTENSION_VALUE_ERROR, X509V3_R_INVALID_ASNUMBER,
    X509V3_R_INVALID_ASRANGE, X509V3_R_INVALID_INHERITANCE,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strdup};
use crate::runtime::obj::NID_sbgp_autonomousSysNum;
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_new, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_reserve,
    OPENSSL_sk_sort, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{
    conf_add_error_name_value, i2s_ASN1_INTEGER, ossl_v3_name_cmp, s2i_ASN1_INTEGER,
    X509V3_get_value_int,
};
use crate::x509::x509_lu::X509StoreCtx;
use crate::x509::x_x509::X509;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_BN_LIB` — `include/openssl/err.h.in:319`, `ERR_LIB_BN | ERR_RFLAG_COMMON` (`3 | 0x80000`).
const ERR_R_BN_LIB: c_int = 524291;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in:328`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`
/// (`13 | 0x80000`).
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_X509V3_LIB` — `include/openssl/err.h.in:335`, `ERR_LIB_X509V3 | ERR_RFLAG_COMMON`
/// (`34 | 0x80000`).
const ERR_R_X509V3_LIB: c_int = 524322;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc`/`OPENSSL_free`/`OPENSSL_strdup` expansions —
/// `crypto/x509/v3_asid.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_asid.c";
/// `i2r_ASIdentifierChoice`'s `OPENSSL_free(s)` on the `ASIdOrRange_id` arm (`v3_asid.c:83`).
const LINE_FREE_ID: c_int = 83;
/// The same function's `OPENSSL_free(s)` on the range's lower bound (`v3_asid.c:89`).
const LINE_FREE_RANGE_MIN: c_int = 89;
/// The same function's `OPENSSL_free(s)` on the range's upper bound (`v3_asid.c:93`).
const LINE_FREE_RANGE_MAX: c_int = 93;
/// `ASIdentifierChoice_canonize`'s `OPENSSL_malloc(sizeof(*r))` (`v3_asid.c:431`).
const LINE_CANONIZE_MALLOC: c_int = 431;
/// `v2i_ASIdentifiers`'s `OPENSSL_strdup(val->value)` (`v3_asid.c:574`).
const LINE_V2I_STRDUP: c_int = 574;
/// The same function's `OPENSSL_free(s)` (`v3_asid.c:580`).
const LINE_V2I_FREE: c_int = 580;

/// One `v3_asid.c` raise coordinate, declared locally (see the module doc).
const fn v3_asid_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_asid.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `ASIdentifierChoice_is_canonical`'s failed `BN_new`/`ASN1_INTEGER_to_BN`/`BN_add_word` at
/// `v3_asid.c:301`.
const V3_ASID_301: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(301, c"ASIdentifierChoice_is_canonical", ERR_R_BN_LIB);
/// `ASIdentifierChoice_is_canonical`'s failed `BN_to_ASN1_INTEGER` at `v3_asid.c:307`.
const V3_ASID_307: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(307, c"ASIdentifierChoice_is_canonical", ERR_R_ASN1_LIB);
/// `ASIdentifierChoice_canonize`'s non-list/empty-list rejection at `v3_asid.c:368`.
const V3_ASID_368: crate::runtime::err::err_sites::ErrSite = v3_asid_site(
    368,
    c"ASIdentifierChoice_canonize",
    X509V3_R_EXTENSION_VALUE_ERROR,
);
/// `ASIdentifierChoice_canonize`'s overlap rejection at `v3_asid.c:406`.
const V3_ASID_406: crate::runtime::err::err_sites::ErrSite = v3_asid_site(
    406,
    c"ASIdentifierChoice_canonize",
    X509V3_R_EXTENSION_VALUE_ERROR,
);
/// `ASIdentifierChoice_canonize`'s failed `BN_new`/`ASN1_INTEGER_to_BN`/`BN_add_word` at
/// `v3_asid.c:414`.
const V3_ASID_414: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(414, c"ASIdentifierChoice_canonize", ERR_R_BN_LIB);
/// `ASIdentifierChoice_canonize`'s failed `BN_to_ASN1_INTEGER` at `v3_asid.c:420`.
const V3_ASID_420: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(420, c"ASIdentifierChoice_canonize", ERR_R_ASN1_LIB);
/// `v2i_ASIdentifiers`'s failed `ASIdentifiers_new` at `v3_asid.c:504`.
const V3_ASID_504: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(504, c"v2i_ASIdentifiers", ERR_R_X509V3_LIB);
/// `v2i_ASIdentifiers`'s unknown `AS`/`RDI` name at `v3_asid.c:520`.
const V3_ASID_520: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(520, c"v2i_ASIdentifiers", X509V3_R_EXTENSION_NAME_ERROR);
/// `v2i_ASIdentifiers`'s absent value at `v3_asid.c:526`.
const V3_ASID_526: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(526, c"v2i_ASIdentifiers", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v2i_ASIdentifiers`'s non-inherit use of `inherit` at `v3_asid.c:536`.
const V3_ASID_536: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(536, c"v2i_ASIdentifiers", X509V3_R_INVALID_INHERITANCE);
/// `v2i_ASIdentifiers`'s malformed number at `v3_asid.c:551`.
const V3_ASID_551: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(551, c"v2i_ASIdentifiers", X509V3_R_INVALID_ASNUMBER);
/// `v2i_ASIdentifiers`'s malformed range at `v3_asid.c:559`.
const V3_ASID_559: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(559, c"v2i_ASIdentifiers", X509V3_R_INVALID_ASRANGE);
/// `v2i_ASIdentifiers`'s failed `X509V3_get_value_int` at `v3_asid.c:570`.
const V3_ASID_570: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(570, c"v2i_ASIdentifiers", ERR_R_X509V3_LIB);
/// `v2i_ASIdentifiers`'s failed `s2i_ASN1_INTEGER` at `v3_asid.c:582`.
const V3_ASID_582: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(582, c"v2i_ASIdentifiers", ERR_R_X509V3_LIB);
/// `v2i_ASIdentifiers`'s inverted range at `v3_asid.c:586`.
const V3_ASID_586: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(586, c"v2i_ASIdentifiers", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v2i_ASIdentifiers`'s failed `X509v3_asid_add_id_or_range` at `v3_asid.c:591`.
const V3_ASID_591: crate::runtime::err::err_sites::ErrSite =
    v3_asid_site(591, c"v2i_ASIdentifiers", ERR_R_X509V3_LIB);

/// `#define ASIdOrRange_id 0` — `include/openssl/x509v3.h:833`.
const ASIdOrRange_id: c_int = 0;
/// `#define ASIdOrRange_range 1` — `include/openssl/x509v3.h:834`.
const ASIdOrRange_range: c_int = 1;
/// `#define ASIdentifierChoice_inherit 0` — `include/openssl/x509v3.h:852`.
const ASIdentifierChoice_inherit: c_int = 0;
/// `#define ASIdentifierChoice_asIdsOrRanges 1` — `include/openssl/x509v3.h:853`.
const ASIdentifierChoice_asIdsOrRanges: c_int = 1;
/// `#define V3_ASID_ASNUM 0` — `include/openssl/x509v3.h:927`.
const V3_ASID_ASNUM: c_int = 0;
/// `#define V3_ASID_RDI 1` — `include/openssl/x509v3.h:928`.
const V3_ASID_RDI: c_int = 1;

/// `struct ASRange_st` — `ASRange`, from `include/openssl/x509v3.h:829-831`.
#[repr(C)]
pub struct AsRange {
    /// `ASN1_INTEGER *min`.
    pub min: *mut Asn1String,
    /// `ASN1_INTEGER *max`.
    pub max: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<AsRange>() == 16);
    assert!(core::mem::offset_of!(AsRange, min) == 0);
    assert!(core::mem::offset_of!(AsRange, max) == 8);
};

/// `struct ASIdOrRange_st` — `ASIdOrRange`, from `include/openssl/x509v3.h:836-842`. The union is
/// one pointer at offset 8; `type_` selects `id` or `range`.
#[repr(C)]
pub struct AsIdOrRange {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ASN1_INTEGER *id; ASRange *range; } u`.
    pub u: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<AsIdOrRange>() == 16);
    assert!(core::mem::offset_of!(AsIdOrRange, type_) == 0);
    assert!(core::mem::offset_of!(AsIdOrRange, u) == 8);
};

/// `struct ASIdentifierChoice_st` — `ASIdentifierChoice`, from
/// `include/openssl/x509v3.h:855-861`.
#[repr(C)]
pub struct AsIdentifierChoice {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ASN1_NULL *inherit; ASIdOrRanges *asIdsOrRanges; } u`.
    pub u: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<AsIdentifierChoice>() == 16);
    assert!(core::mem::offset_of!(AsIdentifierChoice, type_) == 0);
    assert!(core::mem::offset_of!(AsIdentifierChoice, u) == 8);
};

/// `struct ASIdentifiers_st` — `ASIdentifiers`, from `include/openssl/x509v3.h:863-865`.
#[repr(C)]
pub struct AsIdentifiers {
    /// `ASIdentifierChoice *asnum`.
    pub asnum: *mut AsIdentifierChoice,
    /// `ASIdentifierChoice *rdi`.
    pub rdi: *mut AsIdentifierChoice,
}

const _: () = {
    assert!(core::mem::size_of::<AsIdentifiers>() == 16);
    assert!(core::mem::offset_of!(AsIdentifiers, asnum) == 0);
    assert!(core::mem::offset_of!(AsIdentifiers, rdi) == 8);
};

// ---------------------------------------------------------------------------------------------
// The four item groups — `ASN1_SEQUENCE`/`ASN1_CHOICE` at `v3_asid.c:34-57`.
// ---------------------------------------------------------------------------------------------

/// `ASRange_seq_tt` — `ASN1_SEQUENCE(ASRange)` (`v3_asid.c:34-37`): two `ASN1_SIMPLE(..., ASN1_INTEGER)`.
static ASRANGE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"min".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"max".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `ASRange_it`'s descriptor — `ASN1_SEQUENCE_END(ASRange)` at `v3_asid.c:37`.
static ASRANGE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ASRANGE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AsRange>() as c_long,
    sname: c"ASRange".as_ptr(),
};

/// `ASIdOrRange_ch_tt` — `ASN1_CHOICE(ASIdOrRange)` (`v3_asid.c:39-42`): `ASN1_SIMPLE(..., u.id,
/// ASN1_INTEGER)` and `ASN1_SIMPLE(..., u.range, ASRange)`, both at offset 8.
static ASIDORRANGE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.id".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.range".as_ptr(),
        item: ASRange_it as *mut c_void,
    },
];

/// `ASIdOrRange_it`'s descriptor — `ASN1_CHOICE_END(ASIdOrRange)` at `v3_asid.c:42`. `utype` is the
/// selector offset (0), as `ASN1_CHOICE_END_selector` passes.
static ASIDORRANGE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: ASIDORRANGE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AsIdOrRange>() as c_long,
    sname: c"ASIdOrRange".as_ptr(),
};

/// `ASIdentifierChoice_ch_tt` — `ASN1_CHOICE(ASIdentifierChoice)` (`v3_asid.c:44-47`):
/// `ASN1_SIMPLE(..., u.inherit, ASN1_NULL)` and `ASN1_SEQUENCE_OF(..., u.asIdsOrRanges, ASIdOrRange)`.
static ASIDENTIFIERCHOICE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.inherit".as_ptr(),
        item: ASN1_NULL_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"u.asIdsOrRanges".as_ptr(),
        item: ASIdOrRange_it as *mut c_void,
    },
];

/// `ASIdentifierChoice_it`'s descriptor — `ASN1_CHOICE_END(ASIdentifierChoice)` at `v3_asid.c:47`.
static ASIDENTIFIERCHOICE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: ASIDENTIFIERCHOICE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AsIdentifierChoice>() as c_long,
    sname: c"ASIdentifierChoice".as_ptr(),
};

/// `ASIdentifiers_seq_tt` — `ASN1_SEQUENCE(ASIdentifiers)` (`v3_asid.c:49-52`): two
/// `ASN1_EXP_OPT(..., ASIdentifierChoice, n)` rows.
static ASIDENTIFIERS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"asnum".as_ptr(),
        item: ASIdentifierChoice_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"rdi".as_ptr(),
        item: ASIdentifierChoice_it as *mut c_void,
    },
];

/// `ASIdentifiers_it`'s descriptor — `ASN1_SEQUENCE_END(ASIdentifiers)` at `v3_asid.c:52`.
static ASIDENTIFIERS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ASIDENTIFIERS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AsIdentifiers>() as c_long,
    sname: c"ASIdentifiers".as_ptr(),
};

// NOTE: the four groups below are written out one by one rather than produced by a `macro_rules!`
// group, because a macro that fills the *type* position (`X_new`/`d2i_X`/`i2d_X`) is refused by
// `prototype_court.py` as an unreadable declaration (D456).

/// `const ASN1_ITEM *ASRange_it(void)` — `include/openssl/x509v3.h:867`, from
/// `DECLARE_ASN1_FUNCTIONS(ASRange)`.
#[no_mangle]
pub extern "C" fn ASRange_it() -> *const Asn1Item {
    &ASRANGE_ITEM
}

/// `ASRange *ASRange_new(void)` — `crypto/x509/v3_asid.c:54`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(ASRange)`.
#[no_mangle]
pub extern "C" fn ASRange_new() -> *mut AsRange {
    // SAFETY: `ASRange_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ASRange_it()).cast::<AsRange>() }
}

/// `void ASRange_free(ASRange *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ASRange_free(a: *mut AsRange) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ASRange_it()) }
}

/// `ASRange *d2i_ASRange(ASRange **a, const unsigned char **in, long len)` — the same macro's
/// decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASRange(
    a: *mut *mut AsRange,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AsRange {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ASRange_it()).cast::<AsRange>() }
}

/// `int i2d_ASRange(const ASRange *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASRange(a: *const AsRange, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ASRange_it()) }
}

/// `const ASN1_ITEM *ASIdOrRange_it(void)` — `include/openssl/x509v3.h:868`.
#[no_mangle]
pub extern "C" fn ASIdOrRange_it() -> *const Asn1Item {
    &ASIDORRANGE_ITEM
}

/// `ASIdOrRange *ASIdOrRange_new(void)` — `crypto/x509/v3_asid.c:55`.
#[no_mangle]
pub extern "C" fn ASIdOrRange_new() -> *mut AsIdOrRange {
    // SAFETY: `ASIdOrRange_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ASIdOrRange_it()).cast::<AsIdOrRange>() }
}

/// `void ASIdOrRange_free(ASIdOrRange *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ASIdOrRange_free(a: *mut AsIdOrRange) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ASIdOrRange_it()) }
}

/// `ASIdOrRange *d2i_ASIdOrRange(ASIdOrRange **a, const unsigned char **in, long len)` — the same
/// macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASIdOrRange(
    a: *mut *mut AsIdOrRange,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AsIdOrRange {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ASIdOrRange_it()).cast::<AsIdOrRange>() }
}

/// `int i2d_ASIdOrRange(const ASIdOrRange *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASIdOrRange(a: *const AsIdOrRange, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ASIdOrRange_it()) }
}

/// `const ASN1_ITEM *ASIdentifierChoice_it(void)` — `include/openssl/x509v3.h:869`.
#[no_mangle]
pub extern "C" fn ASIdentifierChoice_it() -> *const Asn1Item {
    &ASIDENTIFIERCHOICE_ITEM
}

/// `ASIdentifierChoice *ASIdentifierChoice_new(void)` — `crypto/x509/v3_asid.c:56`.
#[no_mangle]
pub extern "C" fn ASIdentifierChoice_new() -> *mut AsIdentifierChoice {
    // SAFETY: `ASIdentifierChoice_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ASIdentifierChoice_it()).cast::<AsIdentifierChoice>() }
}

/// `void ASIdentifierChoice_free(ASIdentifierChoice *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ASIdentifierChoice_free(a: *mut AsIdentifierChoice) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ASIdentifierChoice_it()) }
}

/// `ASIdentifierChoice *d2i_ASIdentifierChoice(ASIdentifierChoice **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASIdentifierChoice(
    a: *mut *mut AsIdentifierChoice,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AsIdentifierChoice {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, ASIdentifierChoice_it()).cast::<AsIdentifierChoice>()
    }
}

/// `int i2d_ASIdentifierChoice(const ASIdentifierChoice *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASIdentifierChoice(
    a: *const AsIdentifierChoice,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ASIdentifierChoice_it()) }
}

/// `const ASN1_ITEM *ASIdentifiers_it(void)` — `include/openssl/x509v3.h:870`.
#[no_mangle]
pub extern "C" fn ASIdentifiers_it() -> *const Asn1Item {
    &ASIDENTIFIERS_ITEM
}

/// `ASIdentifiers *ASIdentifiers_new(void)` — `crypto/x509/v3_asid.c:57`.
#[no_mangle]
pub extern "C" fn ASIdentifiers_new() -> *mut AsIdentifiers {
    // SAFETY: `ASIdentifiers_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ASIdentifiers_it()).cast::<AsIdentifiers>() }
}

/// `void ASIdentifiers_free(ASIdentifiers *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ASIdentifiers_free(a: *mut AsIdentifiers) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ASIdentifiers_it()) }
}

/// `ASIdentifiers *d2i_ASIdentifiers(ASIdentifiers **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ASIdentifiers(
    a: *mut *mut AsIdentifiers,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AsIdentifiers {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ASIdentifiers_it()).cast::<AsIdentifiers>() }
}

/// `int i2d_ASIdentifiers(const ASIdentifiers *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ASIdentifiers(
    a: *const AsIdentifiers,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ASIdentifiers_it()) }
}

// ---------------------------------------------------------------------------------------------
// The printers — `v3_asid.c:62-117`.
// ---------------------------------------------------------------------------------------------

/// `static int i2r_ASIdentifierChoice(BIO *out, ASIdentifierChoice *choice, int indent, const char
/// *msg)` — `crypto/x509/v3_asid.c:62-104`.
///
/// A null choice prints nothing and answers 1. An inherit choice prints `inherit`; a list prints one
/// line per element, rendering each integer through `i2s_ASN1_INTEGER` and releasing it.
unsafe fn i2r_ASIdentifierChoice(
    out: *mut crate::runtime::bio::Bio,
    choice: *mut AsIdentifierChoice,
    indent: c_int,
    msg: *const c_char,
) -> c_int {
    if choice.is_null() {
        return 1;
    }
    // SAFETY: `out` is a live BIO per the caller's contract; each argument is as the format says.
    unsafe { BIO_printf(out, c"%*s%s:\n".as_ptr(), indent, c"".as_ptr(), msg) };
    // SAFETY: `choice` is live per the caller's contract.
    match unsafe { (*choice).type_ } {
        ASIdentifierChoice_inherit => {
            // SAFETY: `out` is live; the format and arguments are as declared.
            unsafe { BIO_printf(out, c"%*sinherit\n".as_ptr(), indent + 2, c"".as_ptr()) };
        }
        ASIdentifierChoice_asIdsOrRanges => {
            // SAFETY: the union's `asIdsOrRanges` arm is live under this selector.
            let list = unsafe { (*choice).u.cast::<OpenSslStack>() };
            // SAFETY: `list` is a live `STACK_OF(ASIdOrRange)`.
            let num = unsafe { OPENSSL_sk_num(list) };
            let mut i = 0;
            while i < num {
                // SAFETY: `list` is live and `i` is in bounds.
                let aor = unsafe { OPENSSL_sk_value(list, i) }.cast::<AsIdOrRange>();
                // SAFETY: `aor` is a live element per the stack contract.
                match unsafe { (*aor).type_ } {
                    ASIdOrRange_id => {
                        // SAFETY: the union's `id` arm is live under this selector.
                        let id = unsafe { (*aor).u.cast::<Asn1String>() };
                        // SAFETY: `id` is a live integer; `i2s_ASN1_INTEGER` accepts a NULL method.
                        let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), id) };
                        if s.is_null() {
                            return 0;
                        }
                        // SAFETY: `out` is live and `s` is NUL-terminated.
                        unsafe {
                            BIO_printf(out, c"%*s%s\n".as_ptr(), indent + 2, c"".as_ptr(), s)
                        };
                        // SAFETY: `s` is this call's own allocation.
                        unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_ID) };
                    }
                    ASIdOrRange_range => {
                        // SAFETY: the union's `range` arm is live under this selector.
                        let range = unsafe { (*aor).u.cast::<AsRange>() };
                        // SAFETY: the range's `min` is a live integer.
                        let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), (*range).min) };
                        if s.is_null() {
                            return 0;
                        }
                        // SAFETY: `out` is live and `s` is NUL-terminated.
                        unsafe { BIO_printf(out, c"%*s%s-".as_ptr(), indent + 2, c"".as_ptr(), s) };
                        // SAFETY: `s` is this call's own allocation.
                        unsafe {
                            CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_RANGE_MIN)
                        };
                        // SAFETY: the range's `max` is a live integer.
                        let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), (*range).max) };
                        if s.is_null() {
                            return 0;
                        }
                        // SAFETY: `out` is live and `s` is NUL-terminated.
                        unsafe { BIO_printf(out, c"%s\n".as_ptr(), s) };
                        // SAFETY: `s` is this call's own allocation.
                        unsafe {
                            CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_RANGE_MAX)
                        };
                    }
                    _ => return 0,
                }
                i += 1;
            }
        }
        _ => return 0,
    }
    1
}

/// `static int i2r_ASIdentifiers(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent)`
/// — `crypto/x509/v3_asid.c:109-117`. The two choices are printed with `&&`, so a refusal on the
/// first short-circuits the second.
unsafe extern "C" fn i2r_ASIdentifiers(
    _method: *const X509V3ExtMethod,
    ext: *mut c_void,
    out: *mut crate::runtime::bio::Bio,
    indent: c_int,
) -> c_int {
    let asid = ext.cast::<AsIdentifiers>();
    // SAFETY: `asid` is a live `ASIdentifiers` per the caller's contract; `out` is live.
    if unsafe {
        i2r_ASIdentifierChoice(
            out,
            (*asid).asnum,
            indent,
            c"Autonomous System Numbers".as_ptr(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: as above, for the RDI half.
    if unsafe {
        i2r_ASIdentifierChoice(
            out,
            (*asid).rdi,
            indent,
            c"Routing Domain Identifiers".as_ptr(),
        )
    } == 0
    {
        return 0;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// Construction — `v3_asid.c:122-233`.
// ---------------------------------------------------------------------------------------------

/// `static int ASIdOrRange_cmp(const ASIdOrRange *const *a_, const ASIdOrRange *const *b_)` —
/// `crypto/x509/v3_asid.c:122-143`.
///
/// The stack layer hands a comparator the addresses of the *slots*, so each argument is
/// dereferenced once to reach the element. The two `assert`s (`:127`, `:129`) are compiled out under
/// `NDEBUG`, as `ossl_assert` is in this build.
unsafe extern "C" fn asid_or_range_cmp(a_: *const c_void, b_: *const c_void) -> c_int {
    // SAFETY: the stack passes element slots for a comparator installed on this list.
    let a = unsafe { *a_.cast::<*const AsIdOrRange>() };
    // SAFETY: as above.
    let b = unsafe { *b_.cast::<*const AsIdOrRange>() };
    // SAFETY: both are live elements the caller pushed.
    let (a_is_id, b_is_id, a_is_range, b_is_range) = unsafe {
        (
            (*a).type_ == ASIdOrRange_id,
            (*b).type_ == ASIdOrRange_id,
            (*a).type_ == ASIdOrRange_range,
            (*b).type_ == ASIdOrRange_range,
        )
    };
    if a_is_id && b_is_id {
        // SAFETY: both `id` arms are live under their selectors.
        return unsafe {
            ASN1_INTEGER_cmp((*a).u.cast::<Asn1String>(), (*b).u.cast::<Asn1String>())
        };
    }
    if a_is_range && b_is_range {
        // SAFETY: both `range` arms are live under their selectors.
        let (ar, br) = unsafe { ((*a).u.cast::<AsRange>(), (*b).u.cast::<AsRange>()) };
        // SAFETY: both ranges' `min` are live integers.
        let r = unsafe { ASN1_INTEGER_cmp((*ar).min, (*br).min) };
        return if r != 0 {
            r
        } else {
            // SAFETY: both ranges' `max` are live integers.
            unsafe { ASN1_INTEGER_cmp((*ar).max, (*br).max) }
        };
    }
    if a_is_id {
        // SAFETY: `a`'s `id` and `b`'s `range` are live under their selectors.
        let br = unsafe { (*b).u.cast::<AsRange>() };
        // SAFETY: `a`'s `id` and `br`'s `min` are live under their selectors.
        unsafe { ASN1_INTEGER_cmp((*a).u.cast::<Asn1String>(), (*br).min) }
    } else {
        // SAFETY: `a`'s `range` and `b`'s `id` are live under their selectors.
        let ar = unsafe { (*a).u.cast::<AsRange>() };
        // SAFETY: `ar`'s `min` and `b`'s `id` are live under their selectors.
        unsafe { ASN1_INTEGER_cmp((*ar).min, (*b).u.cast::<Asn1String>()) }
    }
}

/// `int X509v3_asid_add_inherit(ASIdentifiers *asid, int which)` — `crypto/x509/v3_asid.c:148-174`.
///
/// # Safety
///
/// `asid` is NULL or a live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_add_inherit(asid: *mut AsIdentifiers, which: c_int) -> c_int {
    if asid.is_null() {
        return 0;
    }
    // SAFETY: `asid` is live per the contract; `&raw mut` names the field's slot.
    let choice: *mut *mut AsIdentifierChoice = unsafe {
        match which {
            V3_ASID_ASNUM => &raw mut (*asid).asnum,
            V3_ASID_RDI => &raw mut (*asid).rdi,
            _ => return 0,
        }
    };
    // SAFETY: `choice` points at a field of the live `asid`.
    if unsafe { (*choice).is_null() } {
        // SAFETY: no preconditions; the item is the crate's own static.
        let fresh = ASIdentifierChoice_new();
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `choice` is writable.
        unsafe { *choice = fresh };
        // SAFETY: no preconditions; `ASN1_NULL_new` answers the `(ASN1_VALUE *)1` sentinel.
        let inherit = ASN1_NULL_new();
        if inherit.is_null() {
            // SAFETY: `fresh` is this call's own value.
            unsafe { ASIdentifierChoice_free(fresh) };
            // SAFETY: `choice` is writable.
            unsafe { *choice = ptr::null_mut() };
            return 0;
        }
        // SAFETY: `fresh` is live and its `inherit` arm is the one being selected.
        unsafe {
            (*fresh).u = inherit.cast::<c_void>();
            (*fresh).type_ = ASIdentifierChoice_inherit;
        }
    }
    // SAFETY: `choice` points at a live `ASIdentifierChoice`.
    c_int::from(unsafe { (**choice).type_ } == ASIdentifierChoice_inherit)
}

/// `int X509v3_asid_add_id_or_range(ASIdentifiers *asid, int which, ASN1_INTEGER *min,
/// ASN1_INTEGER *max)` — `crypto/x509/v3_asid.c:179-233`.
///
/// # Safety
///
/// `asid` is NULL or a live `ASIdentifiers`; `min`/`max` are NULL or live integers whose ownership
/// transfers to `asid` on success (and to the caller on failure).
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_add_id_or_range(
    asid: *mut AsIdentifiers,
    which: c_int,
    min: *mut Asn1String,
    max: *mut Asn1String,
) -> c_int {
    if asid.is_null() {
        return 0;
    }
    // SAFETY: `asid` is live per the contract; `&raw mut` names the field's slot.
    let choice: *mut *mut AsIdentifierChoice = unsafe {
        match which {
            V3_ASID_ASNUM => &raw mut (*asid).asnum,
            V3_ASID_RDI => &raw mut (*asid).rdi,
            _ => return 0,
        }
    };
    // SAFETY: `choice` points at a field of the live `asid`.
    let existing = unsafe { *choice };
    // SAFETY: `existing` is non-null and live on this arm.
    if !existing.is_null() && unsafe { (*existing).type_ } != ASIdentifierChoice_asIdsOrRanges {
        return 0;
    }
    if existing.is_null() {
        // SAFETY: no preconditions; the item is the crate's own static.
        let fresh = ASIdentifierChoice_new();
        if fresh.is_null() {
            return 0;
        }
        // SAFETY: `choice` is writable.
        unsafe { *choice = fresh };
        // SAFETY: `OPENSSL_sk_new(ASIdOrRange_cmp)` builds a comparator-ordered empty stack.
        let list = OPENSSL_sk_new(Some(asid_or_range_cmp));
        if list.is_null() {
            // SAFETY: `fresh` is this call's own value.
            unsafe { ASIdentifierChoice_free(fresh) };
            // SAFETY: `choice` is writable.
            unsafe { *choice = ptr::null_mut() };
            return 0;
        }
        // SAFETY: `fresh` is live and its list arm is the one being selected.
        unsafe {
            (*fresh).u = list.cast::<c_void>();
            (*fresh).type_ = ASIdentifierChoice_asIdsOrRanges;
        }
    }
    // SAFETY: `choice` points at a live list-backed `ASIdentifierChoice`.
    let choice_ref = unsafe { *choice };
    // SAFETY: `choice_ref` is live and list-backed under the selector above.
    let list = unsafe { (*choice_ref).u.cast::<OpenSslStack>() };
    // SAFETY: no preconditions; the item is the crate's own static.
    let aor = ASIdOrRange_new();
    if aor.is_null() {
        return 0;
    }
    // SAFETY: `list` is live; one element is being reserved.
    if unsafe { OPENSSL_sk_reserve(list, 1) } == 0 {
        // SAFETY: `aor` is this call's own value; `list` owns nothing of it yet.
        unsafe { ASIdOrRange_free(aor) };
        return 0;
    }
    if max.is_null() {
        // SAFETY: `aor` is live and its `id` arm is the one being selected.
        unsafe {
            (*aor).type_ = ASIdOrRange_id;
            (*aor).u = min.cast::<c_void>();
        }
    } else {
        // SAFETY: `aor` is live and its `range` arm is the one being selected.
        let range = ASRange_new();
        if range.is_null() {
            // SAFETY: `aor` is this call's own value; `list` owns nothing of it yet.
            unsafe { ASIdOrRange_free(aor) };
            return 0;
        }
        // SAFETY: `aor` is live; its `range` arm is being installed.
        unsafe {
            (*aor).type_ = ASIdOrRange_range;
            (*aor).u = range.cast::<c_void>()
        };
        // SAFETY: the range's `min`/`max` are fresh integers this call discards in favour of the
        // caller's.
        unsafe {
            ASN1_INTEGER_free((*range).min);
            (*range).min = min;
            ASN1_INTEGER_free((*range).max);
            (*range).max = max;
        }
    }
    // Cannot fail due to the reservation above. `ossl_assert(push)` under `NDEBUG` is `push != 0`.
    // SAFETY: `list` was reserved for one element, so the push cannot fail.
    if unsafe { OPENSSL_sk_push(list, aor.cast::<c_void>()) } == 0 {
        // SAFETY: `aor` is this call's own value; the failed push left it off the list.
        unsafe { ASIdOrRange_free(aor) };
        return 0;
    }
    1
}

/// `static int extract_min_max(ASIdOrRange *aor, ASN1_INTEGER **min, ASN1_INTEGER **max)` —
/// `crypto/x509/v3_asid.c:238-255`.
///
/// # Safety
///
/// `aor` is NULL or live; `min`/`max` are NULL or writable slots.
unsafe fn extract_min_max(
    aor: *mut AsIdOrRange,
    min: *mut *mut Asn1String,
    max: *mut *mut Asn1String,
) -> c_int {
    // `ossl_assert(aor != NULL)` under `NDEBUG` is `aor != NULL`.
    if aor.is_null() {
        return 0;
    }
    // SAFETY: `aor` is live per the contract.
    match unsafe { (*aor).type_ } {
        ASIdOrRange_id => {
            // SAFETY: the `id` arm is live under this selector; the slots are writable.
            unsafe {
                *min = (*aor).u.cast::<Asn1String>();
                *max = (*aor).u.cast::<Asn1String>();
            }
            1
        }
        ASIdOrRange_range => {
            // SAFETY: the `range` arm is live under this selector.
            let range = unsafe { (*aor).u.cast::<AsRange>() };
            // SAFETY: the slots are writable; the range's bounds are live.
            unsafe {
                *min = (*range).min;
                *max = (*range).max;
            }
            1
        }
        _ => 0,
    }
}

/// `static int ASIdentifierChoice_is_canonical(ASIdentifierChoice *choice)` —
/// `crypto/x509/v3_asid.c:260-338`.
///
/// An absent or inheriting choice is canonical; a non-list or an empty list is not; a list is
/// canonical when it is strictly ascending, non-overlapping, non-adjacent and un-inverted.
unsafe fn as_identifier_choice_is_canonical(choice: *mut AsIdentifierChoice) -> c_int {
    let mut a_max_plus_one: *mut Asn1String = ptr::null_mut();
    let mut bn: *mut BigNum = ptr::null_mut();
    let mut ret: c_int = 0;

    // SAFETY: `choice` is NULL or live per the caller's contract.
    if choice.is_null() || unsafe { (*choice).type_ } == ASIdentifierChoice_inherit {
        return 1;
    }
    // SAFETY: `choice` is live and not inheriting.
    if unsafe { (*choice).type_ } != ASIdentifierChoice_asIdsOrRanges
        // SAFETY: `choice` is live and list-backed on this arm.
        || unsafe { OPENSSL_sk_num((*choice).u.cast::<OpenSslStack>()) } == 0
    {
        return 0;
    }
    // SAFETY: the list arm is live under the selector.
    let list = unsafe { (*choice).u.cast::<OpenSslStack>() };

    'done: {
        let mut i: c_int = 0;
        // SAFETY: `list` is a live non-empty stack.
        while i < unsafe { OPENSSL_sk_num(list) } - 1 {
            // SAFETY: `i` and `i + 1` are in bounds.
            let a = unsafe { OPENSSL_sk_value(list, i) }.cast::<AsIdOrRange>();
            // SAFETY: as above.
            let b = unsafe { OPENSSL_sk_value(list, i + 1) }.cast::<AsIdOrRange>();
            let mut a_min: *mut Asn1String = ptr::null_mut();
            let mut a_max: *mut Asn1String = ptr::null_mut();
            let mut b_min: *mut Asn1String = ptr::null_mut();
            let mut b_max: *mut Asn1String = ptr::null_mut();
            // SAFETY: both elements are live; the slots are writable locals.
            if unsafe {
                extract_min_max(a, &raw mut a_min, &raw mut a_max) == 0
                    || extract_min_max(b, &raw mut b_min, &raw mut b_max) == 0
            } {
                break 'done;
            }
            // SAFETY: all four bounds are live integers.
            if unsafe { ASN1_INTEGER_cmp(a_min, b_min) } >= 0
                // SAFETY: `a_min`/`a_max` are live integers.
                || unsafe { ASN1_INTEGER_cmp(a_min, a_max) } > 0
                // SAFETY: `b_min`/`b_max` are live integers.
                || unsafe { ASN1_INTEGER_cmp(b_min, b_max) } > 0
            {
                break 'done;
            }
            if bn.is_null() {
                // SAFETY: no preconditions.
                bn = unsafe { BN_new() };
            }
            // SAFETY: `bn` is a live bignum when non-null; `a_max` is a live integer.
            if bn.is_null()
                // SAFETY: `bn` is a live bignum and `a_max` a live integer.
                || unsafe { ASN1_INTEGER_to_BN(a_max, bn) }.is_null()
                // SAFETY: `bn` is a live bignum.
                || unsafe { BN_add_word(bn, 1) } == 0
            {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_301) };
                break 'done;
            }
            let orig = a_max_plus_one;
            // SAFETY: `bn` is live; `orig` is NULL or this call's own value.
            let next = unsafe { BN_to_ASN1_INTEGER(bn, orig) };
            if next.is_null() {
                a_max_plus_one = orig;
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_307) };
                break 'done;
            }
            a_max_plus_one = next;
            // SAFETY: `a_max_plus_one` and `b_min` are live integers.
            if unsafe { ASN1_INTEGER_cmp(a_max_plus_one, b_min) } >= 0 {
                break 'done;
            }
            i += 1;
        }

        // SAFETY: `list` is a live non-empty stack.
        let i = unsafe { OPENSSL_sk_num(list) } - 1;
        // SAFETY: `i` is in bounds.
        let a = unsafe { OPENSSL_sk_value(list, i) }.cast::<AsIdOrRange>();
        // SAFETY: `a` is non-null and live on this arm.
        if !a.is_null() && unsafe { (*a).type_ } == ASIdOrRange_range {
            let mut a_min: *mut Asn1String = ptr::null_mut();
            let mut a_max: *mut Asn1String = ptr::null_mut();
            // SAFETY: `a` is live; the slots are writable locals.
            if unsafe { extract_min_max(a, &raw mut a_min, &raw mut a_max) } == 0
                // SAFETY: both bounds are live integers once `extract_min_max` succeeds.
                || unsafe { ASN1_INTEGER_cmp(a_min, a_max) } > 0
            {
                break 'done;
            }
        }
        ret = 1;
    }

    // SAFETY: both are NULL or this call's own allocations.
    unsafe {
        ASN1_INTEGER_free(a_max_plus_one);
        BN_free(bn);
    }
    ret
}

/// `int X509v3_asid_is_canonical(ASIdentifiers *asid)` — `crypto/x509/v3_asid.c:343-346`.
///
/// # Safety
///
/// `asid` is NULL or a live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_is_canonical(asid: *mut AsIdentifiers) -> c_int {
    if asid.is_null() {
        return 1;
    }
    // SAFETY: `asid` is live per the contract; both choices are NULL or live.
    if unsafe { as_identifier_choice_is_canonical((*asid).asnum) } == 0 {
        return 0;
    }
    // SAFETY: as above.
    c_int::from(unsafe { as_identifier_choice_is_canonical((*asid).rdi) } != 0)
}

/// `static int ASIdentifierChoice_canonize(ASIdentifierChoice *choice)` —
/// `crypto/x509/v3_asid.c:351-482`.
///
/// Sorts a list, rejects overlaps and inverted ranges, and merges adjacent ranges.
unsafe fn as_identifier_choice_canonize(choice: *mut AsIdentifierChoice) -> c_int {
    let mut a_max_plus_one: *mut Asn1String = ptr::null_mut();
    let mut bn: *mut BigNum = ptr::null_mut();
    let mut ret: c_int = 0;

    // SAFETY: `choice` is NULL or live per the caller's contract.
    if choice.is_null() || unsafe { (*choice).type_ } == ASIdentifierChoice_inherit {
        return 1;
    }
    // SAFETY: `choice` is live and not inheriting.
    if unsafe { (*choice).type_ } != ASIdentifierChoice_asIdsOrRanges
        // SAFETY: `choice` is a live list-backed choice on this arm.
        || unsafe { OPENSSL_sk_num((*choice).u.cast::<OpenSslStack>()) } == 0
    {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_ASID_368) };
        return 0;
    }
    // SAFETY: the list arm is live under the selector.
    let list = unsafe { (*choice).u.cast::<OpenSslStack>() };
    // SAFETY: `list` is a live stack carrying this comparator.
    unsafe { OPENSSL_sk_sort(list) };

    'done: {
        let mut i: c_int = 0;
        // SAFETY: `list` is a live non-empty stack.
        while i < unsafe { OPENSSL_sk_num(list) } - 1 {
            // SAFETY: `i` and `i + 1` are in bounds.
            let a = unsafe { OPENSSL_sk_value(list, i) }.cast::<AsIdOrRange>();
            // SAFETY: as above.
            let b = unsafe { OPENSSL_sk_value(list, i + 1) }.cast::<AsIdOrRange>();
            let mut a_min: *mut Asn1String = ptr::null_mut();
            let mut a_max: *mut Asn1String = ptr::null_mut();
            let mut b_min: *mut Asn1String = ptr::null_mut();
            let mut b_max: *mut Asn1String = ptr::null_mut();
            // SAFETY: both elements are live; the slots are writable locals.
            if unsafe {
                extract_min_max(a, &raw mut a_min, &raw mut a_max) == 0
                    || extract_min_max(b, &raw mut b_min, &raw mut b_max) == 0
            } {
                break 'done;
            }
            // `ossl_assert(cmp <= 0)` under `NDEBUG` is `cmp <= 0`.
            // SAFETY: both bounds are live integers.
            if unsafe { ASN1_INTEGER_cmp(a_min, b_min) } > 0 {
                break 'done;
            }
            // SAFETY: as above.
            if unsafe { ASN1_INTEGER_cmp(a_min, a_max) } > 0
                // SAFETY: `a_min`/`a_max`/`b_min`/`b_max` are live integers.
                || unsafe { ASN1_INTEGER_cmp(b_min, b_max) } > 0
            {
                break 'done;
            }
            // SAFETY: `a_max` and `b_min` are live integers.
            if unsafe { ASN1_INTEGER_cmp(a_max, b_min) } >= 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_406) };
                break 'done;
            }
            if bn.is_null() {
                // SAFETY: no preconditions.
                bn = unsafe { BN_new() };
            }
            // SAFETY: `bn` is a live bignum when non-null; `a_max` is a live integer.
            if bn.is_null()
                // SAFETY: `bn` is a live bignum and `a_max` a live integer.
                || unsafe { ASN1_INTEGER_to_BN(a_max, bn) }.is_null()
                // SAFETY: `bn` is a live bignum.
                || unsafe { BN_add_word(bn, 1) } == 0
            {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_414) };
                break 'done;
            }
            let orig = a_max_plus_one;
            // SAFETY: `bn` is live; `orig` is NULL or this call's own value.
            let next = unsafe { BN_to_ASN1_INTEGER(bn, orig) };
            if next.is_null() {
                a_max_plus_one = orig;
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_420) };
                break 'done;
            }
            a_max_plus_one = next;
            // SAFETY: `a_max_plus_one` and `b_min` are live integers.
            if unsafe { ASN1_INTEGER_cmp(a_max_plus_one, b_min) } == 0 {
                // The two elements are adjacent; merge them and delete the second.
                // SAFETY: `a` is live.
                match unsafe { (*a).type_ } {
                    ASIdOrRange_id => {
                        // `CRYPTO_malloc` is the authority's safe `OPENSSL_malloc`.
                        let r = CRYPTO_malloc(
                            core::mem::size_of::<AsRange>(),
                            FILE.as_ptr(),
                            LINE_CANONIZE_MALLOC,
                        )
                        .cast::<AsRange>();
                        if r.is_null() {
                            break 'done;
                        }
                        // SAFETY: `r` is a fresh allocation; `a` is live.
                        unsafe {
                            (*r).min = a_min;
                            (*r).max = b_max;
                            (*a).type_ = ASIdOrRange_range;
                            (*a).u = r.cast::<c_void>();
                        }
                    }
                    ASIdOrRange_range => {
                        // SAFETY: the `range` arm is live under the selector.
                        let ar = unsafe { (*a).u.cast::<AsRange>() };
                        // SAFETY: `ar` is live; its `max` is replaced.
                        unsafe {
                            ASN1_INTEGER_free((*ar).max);
                            (*ar).max = b_max;
                        }
                    }
                    _ => {}
                }
                // SAFETY: `b` is live and no longer owns the bounds it lent to `a`.
                match unsafe { (*b).type_ } {
                    // SAFETY: `b` is live and the `id` arm is selected.
                    ASIdOrRange_id => unsafe { (*b).u = ptr::null_mut() },
                    // SAFETY: `b` is live, the `range` arm is selected, and `u` names a live `AsRange`.
                    ASIdOrRange_range => unsafe {
                        (*(*b).u.cast::<AsRange>()).max = ptr::null_mut();
                    },
                    _ => {}
                }
                // SAFETY: `b` is a live element this call owns.
                unsafe { ASIdOrRange_free(b) };
                // SAFETY: `list` is live and `i + 1` is in bounds.
                unsafe { OPENSSL_sk_delete(list, i + 1) };
                i -= 1;
            }
            i += 1;
        }

        // SAFETY: `list` is a live non-empty stack.
        let i = unsafe { OPENSSL_sk_num(list) } - 1;
        // SAFETY: `i` is in bounds.
        let a = unsafe { OPENSSL_sk_value(list, i) }.cast::<AsIdOrRange>();
        // SAFETY: `a` is non-null and live on this arm.
        if !a.is_null() && unsafe { (*a).type_ } == ASIdOrRange_range {
            let mut a_min: *mut Asn1String = ptr::null_mut();
            let mut a_max: *mut Asn1String = ptr::null_mut();
            // SAFETY: `a` is live; the slots are writable locals.
            if unsafe { extract_min_max(a, &raw mut a_min, &raw mut a_max) } == 0
                // SAFETY: both bounds are live integers once `extract_min_max` succeeds.
                || unsafe { ASN1_INTEGER_cmp(a_min, a_max) } > 0
            {
                break 'done;
            }
        }
        // `ossl_assert(ASIdentifierChoice_is_canonical(choice))` under `NDEBUG` is the predicate.
        // SAFETY: `choice` is live and list-backed.
        if unsafe { as_identifier_choice_is_canonical(choice) } == 0 {
            break 'done;
        }
        ret = 1;
    }

    // SAFETY: both are NULL or this call's own allocations.
    unsafe {
        ASN1_INTEGER_free(a_max_plus_one);
        BN_free(bn);
    }
    ret
}

/// `int X509v3_asid_canonize(ASIdentifiers *asid)` — `crypto/x509/v3_asid.c:487-490`.
///
/// # Safety
///
/// `asid` is NULL or a live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_canonize(asid: *mut AsIdentifiers) -> c_int {
    if asid.is_null() {
        return 1;
    }
    // SAFETY: `asid` is live per the contract; both choices are NULL or live.
    if unsafe { as_identifier_choice_canonize((*asid).asnum) } == 0 {
        return 0;
    }
    // SAFETY: as above.
    c_int::from(unsafe { as_identifier_choice_canonize((*asid).rdi) } != 0)
}

/// `strspn(s, accept)` — the C library's, over a NUL-terminated string (the two accept sets here are
/// the digits and the space/tab pair, as `v3_asid.c:544-557` uses).
///
/// # Safety
///
/// `s` must be NUL-terminated.
unsafe fn strspn(s: *const c_char, accept: &[u8]) -> usize {
    let mut n = 0;
    loop {
        // SAFETY: the caller's contract makes `s` NUL-terminated, so the walk stops at the NUL.
        let b = unsafe { *s.add(n) } as u8;
        if b == 0 || !accept.contains(&b) {
            return n;
        }
        n += 1;
    }
}

/// `static void *v2i_ASIdentifiers(const struct v3_ext_method *method, struct v3_ext_ctx *ctx,
/// STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_asid.c:495-609`.
///
/// Reads `name:value` pairs naming `AS` or `RDI`, each value an inherited list, a number or a range,
/// then canonizes the result.
unsafe extern "C" fn v2i_ASIdentifiers(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    values: *mut OpenSslStack,
) -> *mut c_void {
    let mut min: *mut Asn1String = ptr::null_mut();
    let mut max: *mut Asn1String = ptr::null_mut();
    // SAFETY: no preconditions; the item is the crate's own static.
    let asid = ASIdentifiers_new();
    if asid.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_ASID_504) };
        return ptr::null_mut();
    }
    // SAFETY: `values` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(values) };
    let mut i = 0;
    let result: *mut AsIdentifiers = 'each: loop {
        if i >= num {
            break 'each asid;
        }
        // SAFETY: `values` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract.
        let name = unsafe { (*val).name };
        // SAFETY: `name` is NUL-terminated; each literal is static.

        let which = if unsafe { ossl_v3_name_cmp(name, c"AS".as_ptr()) } == 0 {
            V3_ASID_ASNUM
        // SAFETY: as above.
        } else if unsafe { ossl_v3_name_cmp(name, c"RDI".as_ptr()) } == 0 {
            V3_ASID_RDI
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_ASID_520) };
            // SAFETY: `val` is live per the stack contract.
            unsafe { conf_add_error_name_value(val) };
            break 'each ptr::null_mut();
        };
        // SAFETY: `val` is live per the stack contract.
        let value = unsafe { (*val).value };
        if value.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_ASID_526) };
            break 'each ptr::null_mut();
        }
        // SAFETY: `value` is NUL-terminated; the literal is static.
        if unsafe { strcmp(value, c"inherit".as_ptr()) } == 0 {
            // SAFETY: `asid` is live; `val` is live when the add fails.
            if unsafe { X509v3_asid_add_inherit(asid, which) } != 0 {
                i += 1;
                continue 'each;
            }
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_ASID_536) };
            // SAFETY: `val` is live per the stack contract.
            unsafe { conf_add_error_name_value(val) };
            break 'each ptr::null_mut();
        }
        // SAFETY: `value` is NUL-terminated, so `strspn` reads in bounds.
        let i1 = unsafe { strspn(value, b"0123456789") } as c_int;
        let is_range;
        // SAFETY: `i1` is within the NUL-terminated buffer.
        if unsafe { *value.add(i1 as usize) } == 0 {
            is_range = false;
        } else {
            is_range = true;
            // SAFETY: `value + i1` points at a non-terminator; `strspn` reads in bounds.
            let i2a = i1 + unsafe { strspn(value.add(i1 as usize), b" \t") } as c_int;
            // SAFETY: `i2a` is within the buffer.
            if unsafe { *value.add(i2a as usize) } != b'-' as c_char {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_551) };
                // SAFETY: `val` is live per the stack contract.
                unsafe { conf_add_error_name_value(val) };
                break 'each ptr::null_mut();
            }
            let i2 = i2a + 1;
            // SAFETY: `i2` is within the buffer; `strspn` reads in bounds.
            let i2b = i2 + unsafe { strspn(value.add(i2 as usize), b" \t") } as c_int;
            // SAFETY: as above.
            let i3 = i2b + unsafe { strspn(value.add(i2b as usize), b"0123456789") } as c_int;
            // SAFETY: `i3` is within the buffer.
            if unsafe { *value.add(i3 as usize) } != 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_559) };
                // SAFETY: `val` is live per the stack contract.
                unsafe { conf_add_error_name_value(val) };
                break 'each ptr::null_mut();
            }
        }
        if !is_range {
            // SAFETY: `val` is live; `min` is a writable local slot.
            if unsafe { X509V3_get_value_int(val, &raw mut min) } == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_570) };
                break 'each ptr::null_mut();
            }
        } else {
            // SAFETY: `value` is NUL-terminated; the file/line are this unit's.
            let s = unsafe { CRYPTO_strdup(value, FILE.as_ptr(), LINE_V2I_STRDUP) };
            if s.is_null() {
                break 'each ptr::null_mut();
            }
            // Recompute the split offsets the number arm above measured.
            // SAFETY: `s` is a NUL-terminated duplicate owned by this frame.
            let i1 = unsafe { strspn(s, b"0123456789") };
            let i2 = {
                // SAFETY: `s.add(i1)` points inside the same NUL-terminated buffer.
                let after = i1 + unsafe { strspn(s.add(i1), b" \t") } + 1;
                // SAFETY: `s.add(after)` points inside the same NUL-terminated buffer.
                after + unsafe { strspn(s.add(after), b" \t") }
            };
            // SAFETY: `i1` is within the duplicated buffer.
            unsafe { *s.add(i1) = 0 };
            // SAFETY: `s` and `s + i2` are NUL-terminated; the method is NULL.
            min = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), s) };
            // SAFETY: as above.
            max = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), s.add(i2)) };
            // SAFETY: `s` is this call's own allocation.
            unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_V2I_FREE) };
            if min.is_null() || max.is_null() {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_582) };
                break 'each ptr::null_mut();
            }
            // SAFETY: both are live integers.
            if unsafe { ASN1_INTEGER_cmp(min, max) } > 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ASID_586) };
                break 'each ptr::null_mut();
            }
        }
        // SAFETY: `asid` is live; `min`/`max` ownership transfers on success.
        if unsafe { X509v3_asid_add_id_or_range(asid, which, min, max) } == 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_ASID_591) };
            break 'each ptr::null_mut();
        }
        min = ptr::null_mut();
        max = ptr::null_mut();
        i += 1;
    };
    if result.is_null() {
        // SAFETY: `asid` is this call's own value; `min`/`max` are the caller's on failure.
        unsafe {
            ASIdentifiers_free(asid);
            ASN1_INTEGER_free(min);
            ASN1_INTEGER_free(max);
        }
        return ptr::null_mut();
    }
    // SAFETY: `result` is live and list-backed.
    if unsafe { X509v3_asid_canonize(result) } == 0 {
        // SAFETY: `result` is this call's own value.
        unsafe { ASIdentifiers_free(result) };
        return ptr::null_mut();
    }
    result.cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// Inheritance, containment and the row — `v3_asid.c:614-697`.
// ---------------------------------------------------------------------------------------------

/// `int X509v3_asid_inherits(ASIdentifiers *asid)` — `crypto/x509/v3_asid.c:631-634`.
///
/// # Safety
///
/// `asid` is NULL or a live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_inherits(asid: *mut AsIdentifiers) -> c_int {
    if asid.is_null() {
        return 0;
    }
    // SAFETY: `asid` is live per the contract; both choices are NULL or live.
    let (asnum, rdi) = unsafe { ((*asid).asnum, (*asid).rdi) };
    // SAFETY: `asnum` is non-null and live on this arm.
    let as_inherits = !asnum.is_null() && unsafe { (*asnum).type_ } == ASIdentifierChoice_inherit;
    // SAFETY: `rdi` is non-null and live on this arm.
    let rdi_inherits = !rdi.is_null() && unsafe { (*rdi).type_ } == ASIdentifierChoice_inherit;
    c_int::from(as_inherits || rdi_inherits)
}

/// `static int asid_contains(ASIdOrRanges *parent, ASIdOrRanges *child)` — `crypto/x509/v3_asid.c:639-668`.
///
/// # Safety
///
/// `parent` and `child` are NULL or live `ASIdOrRanges` stacks in ascending canonical form.
unsafe fn asid_contains(parent: *mut OpenSslStack, child: *mut OpenSslStack) -> c_int {
    if child.is_null() || parent == child {
        return 1;
    }
    if parent.is_null() {
        return 0;
    }
    let mut p: c_int = 0;
    let mut c: c_int = 0;
    // SAFETY: `child` is a live stack.
    while c < unsafe { OPENSSL_sk_num(child) } {
        // SAFETY: `c` is in bounds.
        let ce = unsafe { OPENSSL_sk_value(child, c) }.cast::<AsIdOrRange>();
        let mut c_min: *mut Asn1String = ptr::null_mut();
        let mut c_max: *mut Asn1String = ptr::null_mut();
        // SAFETY: `ce` is live; the slots are writable locals.
        if unsafe { extract_min_max(ce, &raw mut c_min, &raw mut c_max) } == 0 {
            return 0;
        }
        loop {
            // SAFETY: `parent` is a live stack.
            if p >= unsafe { OPENSSL_sk_num(parent) } {
                return 0;
            }
            // SAFETY: `p` is in bounds.
            let pe = unsafe { OPENSSL_sk_value(parent, p) }.cast::<AsIdOrRange>();
            let mut p_min: *mut Asn1String = ptr::null_mut();
            let mut p_max: *mut Asn1String = ptr::null_mut();
            // SAFETY: `pe` is live; the slots are writable locals.
            if unsafe { extract_min_max(pe, &raw mut p_min, &raw mut p_max) } == 0 {
                return 0;
            }
            // SAFETY: both bounds are live integers.
            if unsafe { ASN1_INTEGER_cmp(p_max, c_max) } < 0 {
                p += 1;
                continue;
            }
            // SAFETY: as above.
            if unsafe { ASN1_INTEGER_cmp(p_min, c_min) } > 0 {
                return 0;
            }
            break;
        }
        c += 1;
    }
    1
}

/// `int X509v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b)` — `crypto/x509/v3_asid.c:673-697`.
///
/// # Safety
///
/// `a` and `b` are NULL or live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_subset(a: *mut AsIdentifiers, b: *mut AsIdentifiers) -> c_int {
    if a.is_null() || a == b {
        return 1;
    }
    if b.is_null() {
        return 0;
    }
    // SAFETY: both are live per the contract.
    if unsafe { X509v3_asid_inherits(a) } != 0 || unsafe { X509v3_asid_inherits(b) } != 0 {
        return 0;
    }
    // SAFETY: both are live; the choices are NULL or live.
    let (a_asnum, b_asnum, a_rdi, b_rdi) = unsafe { ((*a).asnum, (*b).asnum, (*a).rdi, (*b).rdi) };
    let subset = a_asnum.is_null()
        || (!b_asnum.is_null()
            // SAFETY: both lists are live under their selectors.
            && unsafe {
                asid_contains(
                    (*b_asnum).u.cast::<OpenSslStack>(),
                    (*a_asnum).u.cast::<OpenSslStack>(),
                )
            } != 0);
    if !subset {
        return 0;
    }
    c_int::from(
        a_rdi.is_null()
            || (!b_rdi.is_null()
                // SAFETY: both lists are live under their selectors.
                && unsafe {
                    asid_contains(
                        (*b_rdi).u.cast::<OpenSslStack>(),
                        (*a_rdi).u.cast::<OpenSslStack>(),
                    )
                } != 0),
    )
}

/// `const X509V3_EXT_METHOD ossl_v3_asid` — `crypto/x509/v3_asid.c:614-626`.
///
/// One row: `ext_nid` is `NID_sbgp_autonomousSysNum`, `it` is `ASN1_ITEM_ref(ASIdentifiers)`, `v2i`
/// is `v2i_ASIdentifiers`, `i2r` is `i2r_ASIdentifiers`; every other slot is zero.
pub static ossl_v3_asid: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_sbgp_autonomousSysNum,
    ext_flags: 0,
    it: Some(ASIdentifiers_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_ASIdentifiers),
    i2r: Some(i2r_ASIdentifiers),
    r2i: None,
    usr_data: ptr::null_mut(),
};

// ---------------------------------------------------------------------------------------------
// Path validation -- `v3_asid.c:700-869`.
// ---------------------------------------------------------------------------------------------

/// The authority's `ossl_assert` under `-DNDEBUG`, which this profile sets: a plain check that
/// returns its argument, not the `OPENSSL_die` form. `src/x509/x_pubkey.rs` carries the same helper.
fn ossl_assert(expr: bool) -> c_int {
    c_int::from(expr)
}

/// `X509_V_ERR_UNSPECIFIED` -- `include/openssl/x509_vfy.h.in:216`.
const X509_V_ERR_UNSPECIFIED: c_int = 1;
/// `X509_V_ERR_INVALID_EXTENSION` -- `include/openssl/x509_vfy.h.in:258`.
const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
/// `X509_V_ERR_UNNESTED_RESOURCE` -- `include/openssl/x509_vfy.h.in:263`.
const X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;

/// `validation_err(_err_)` -- the `crypto/x509/v3_asid.c:702-714` macro, over this frame's `ctx`,
/// `x` and `i`.
///
/// The authority spells this as a statement macro whose `goto done` returns from
/// `asid_validate_path_internal` with `ret` set to the callback's value; here it is a function
/// returning that value (or 0 when `ctx` is NULL), which the caller stores in `ret` and returns
/// from when it is zero.
///
/// # Safety
///
/// `ctx` is NULL or a live `X509StoreCtx` whose `verify_cb` is non-NULL whenever `ctx` is non-NULL;
/// `x` is NULL or a live `X509`.
unsafe fn validation_err(ctx: *mut X509StoreCtx, x: *mut X509, i: c_int, err: c_int) -> c_int {
    if !ctx.is_null() {
        // SAFETY: `ctx` is live and `verify_cb` is non-NULL per the caller's contract, and `x` is
        // NULL or live; the callback's own contract is the `X509_STORE_CTX_verify_cb` ABI.
        unsafe {
            (*ctx).error = err;
            (*ctx).error_depth = i;
            (*ctx).current_cert = x;
            ((*ctx).verify_cb.unwrap_unchecked())(0, ctx.cast::<c_void>())
        }
    } else {
        0
    }
}

/// `static int asid_validate_path_internal(X509_STORE_CTX *ctx, STACK_OF(X509) *chain, ASIdentifiers *ext)` -- `crypto/x509/v3_asid.c:719-837`.
///
/// # Safety
///
/// `chain` is a live non-empty `STACK_OF(X509)`; `ctx` is NULL or a live `X509StoreCtx`; `ext` is
/// NULL or a live `ASIdentifiers`; and `ctx` is non-NULL whenever `ext` is NULL.
unsafe fn asid_validate_path_internal(
    ctx: *mut X509StoreCtx,
    chain: *mut OpenSslStack,
    mut ext: *mut AsIdentifiers,
) -> c_int {
    let mut child_as: *mut OpenSslStack = ptr::null_mut();
    let mut child_rdi: *mut OpenSslStack = ptr::null_mut();
    let mut i: c_int;
    let mut ret: c_int = 1;
    let mut inherit_as: c_int = 0;
    let mut inherit_rdi: c_int = 0;
    let mut x: *mut X509;

    // SAFETY: `chain` is NULL or live per the contract; the `&&` short-circuits a NULL chain, and
    // `ctx` is non-NULL on the arm that reads `verify_cb`.
    let chain_nonempty = !chain.is_null() && unsafe { OPENSSL_sk_num(chain) } > 0;
    let ctx_or_ext = !ctx.is_null() || !ext.is_null();
    // SAFETY: `ctx` is non-NULL on the arm that reads `verify_cb`.
    let cb_present = ctx.is_null() || unsafe { (*ctx).verify_cb.is_some() };
    if ossl_assert(chain_nonempty) == 0
        || ossl_assert(ctx_or_ext) == 0
        || ossl_assert(cb_present) == 0
    {
        if !ctx.is_null() {
            // SAFETY: `ctx` is live per the contract.
            unsafe { (*ctx).error = X509_V_ERR_UNSPECIFIED };
        }
        return 0;
    }

    // Figure out where to start.  If we don't have an extension to check, we're done.  Otherwise,
    // check canonical form and set up for walking up the chain.
    if !ext.is_null() {
        i = -1;
        x = ptr::null_mut();
    } else {
        i = 0;
        // SAFETY: `chain` is a live non-empty stack (asserted above).
        x = unsafe { OPENSSL_sk_value(chain, i) }.cast::<X509>();
        // SAFETY: `x` is a live certificate.
        ext = unsafe { (*x).rfc3779_asid }.cast::<AsIdentifiers>();
        if ext.is_null() {
            return ret;
        }
    }
    // SAFETY: `ext` is live.
    if unsafe { X509v3_asid_is_canonical(ext) } == 0 {
        // SAFETY: `validation_err`'s contract holds here: `ctx` is NULL or live, `x` is NULL or
        // live, and `verify_cb` is non-NULL whenever `ctx` is.
        ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_INVALID_EXTENSION) };
        if ret == 0 {
            return ret;
        }
    }
    // SAFETY: `ext` is live; its choices are NULL or live.
    let asnum = unsafe { (*ext).asnum };
    if !asnum.is_null() {
        // SAFETY: `asnum` is live under both selector arms.
        match unsafe { (*asnum).type_ } {
            ASIdentifierChoice_inherit => inherit_as = 1,
            ASIdentifierChoice_asIdsOrRanges => {
                // SAFETY: `asnum` is live under this selector.
                child_as = unsafe { (*asnum).u }.cast::<OpenSslStack>();
            }
            _ => {}
        }
    }
    // SAFETY: `ext` is live; its choices are NULL or live.
    let rdi = unsafe { (*ext).rdi };
    if !rdi.is_null() {
        // SAFETY: `rdi` is live under both selector arms.
        match unsafe { (*rdi).type_ } {
            ASIdentifierChoice_inherit => inherit_rdi = 1,
            ASIdentifierChoice_asIdsOrRanges => {
                // SAFETY: `rdi` is live under this selector.
                child_rdi = unsafe { (*rdi).u }.cast::<OpenSslStack>();
            }
            _ => {}
        }
    }

    // Now walk up the chain.  Extensions must be in canonical form, no cert may list resources
    // that its parent doesn't list.
    i += 1;
    // SAFETY: `chain` is a live non-empty stack.
    while i < unsafe { OPENSSL_sk_num(chain) } {
        // SAFETY: `i` is in bounds.
        x = unsafe { OPENSSL_sk_value(chain, i) }.cast::<X509>();
        if ossl_assert(!x.is_null()) == 0 {
            if !ctx.is_null() {
                // SAFETY: `ctx` is live per the contract.
                unsafe { (*ctx).error = X509_V_ERR_UNSPECIFIED };
            }
            return 0;
        }
        // SAFETY: `x` is a live certificate.
        let x_asid = unsafe { (*x).rfc3779_asid }.cast::<AsIdentifiers>();
        if x_asid.is_null() {
            if !child_as.is_null() || !child_rdi.is_null() {
                // SAFETY: `validation_err`'s contract holds here.
                ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
                if ret == 0 {
                    return ret;
                }
            }
            i += 1;
            continue;
        }
        // SAFETY: `x_asid` is live.
        if unsafe { X509v3_asid_is_canonical(x_asid) } == 0 {
            // SAFETY: `validation_err`'s contract holds here.
            ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_INVALID_EXTENSION) };
            if ret == 0 {
                return ret;
            }
        }
        // SAFETY: `x_asid` is live; `asnum` is NULL or live.
        let x_asnum = unsafe { (*x_asid).asnum };
        if x_asnum.is_null() && !child_as.is_null() {
            // SAFETY: `validation_err`'s contract holds here.
            ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
            if ret == 0 {
                return ret;
            }
            child_as = ptr::null_mut();
            inherit_as = 0;
        }
        // SAFETY: `x_asnum` is live under this selector.
        if !x_asnum.is_null() && unsafe { (*x_asnum).type_ } == ASIdentifierChoice_asIdsOrRanges {
            // SAFETY: `x_asnum` is live under its `asIdsOrRanges` selector.
            let list = unsafe { (*x_asnum).u }.cast::<OpenSslStack>();
            // SAFETY: `list` and `child_as` are NULL or live ascending `ASIdOrRanges` stacks.
            if inherit_as != 0 || unsafe { asid_contains(list, child_as) } != 0 {
                child_as = list;
                inherit_as = 0;
            } else {
                // SAFETY: `validation_err`'s contract holds here.
                ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
                if ret == 0 {
                    return ret;
                }
            }
        }
        // SAFETY: `x_asid` is live; `rdi` is NULL or live.
        let x_rdi = unsafe { (*x_asid).rdi };
        if x_rdi.is_null() && !child_rdi.is_null() {
            // SAFETY: `validation_err`'s contract holds here.
            ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
            if ret == 0 {
                return ret;
            }
            child_rdi = ptr::null_mut();
            inherit_rdi = 0;
        }
        // SAFETY: `x_rdi` is live under this selector.
        if !x_rdi.is_null() && unsafe { (*x_rdi).type_ } == ASIdentifierChoice_asIdsOrRanges {
            // SAFETY: `x_rdi` is live under its `asIdsOrRanges` selector.
            let list = unsafe { (*x_rdi).u }.cast::<OpenSslStack>();
            // SAFETY: `list` and `child_rdi` are NULL or live ascending `ASIdOrRanges` stacks.
            if inherit_rdi != 0 || unsafe { asid_contains(list, child_rdi) } != 0 {
                child_rdi = list;
                inherit_rdi = 0;
            } else {
                // SAFETY: `validation_err`'s contract holds here.
                ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
                if ret == 0 {
                    return ret;
                }
            }
        }
        i += 1;
    }

    // Trust anchor can't inherit.
    if ossl_assert(!x.is_null()) == 0 {
        if !ctx.is_null() {
            // SAFETY: `ctx` is live per the contract.
            unsafe { (*ctx).error = X509_V_ERR_UNSPECIFIED };
        }
        return 0;
    }
    // SAFETY: `x` is a live certificate.
    let ta_asid = unsafe { (*x).rfc3779_asid }.cast::<AsIdentifiers>();
    if !ta_asid.is_null() {
        // SAFETY: `ta_asid` is live; `asnum` is NULL or live.
        let asnum = unsafe { (*ta_asid).asnum };
        // SAFETY: `asnum` is live under this selector.
        if !asnum.is_null() && unsafe { (*asnum).type_ } == ASIdentifierChoice_inherit {
            // SAFETY: `validation_err`'s contract holds here.
            ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
            if ret == 0 {
                return ret;
            }
        }
        // SAFETY: `ta_asid` is live; `rdi` is NULL or live.
        let rdi = unsafe { (*ta_asid).rdi };
        // SAFETY: `rdi` is live under this selector.
        if !rdi.is_null() && unsafe { (*rdi).type_ } == ASIdentifierChoice_inherit {
            // SAFETY: `validation_err`'s contract holds here.
            ret = unsafe { validation_err(ctx, x, i, X509_V_ERR_UNNESTED_RESOURCE) };
            if ret == 0 {
                return ret;
            }
        }
    }

    ret
}

/// `int X509v3_asid_validate_path(X509_STORE_CTX *ctx)` -- `crypto/x509/v3_asid.c:844-853`.
///
/// # Safety
///
/// `ctx` is live.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_validate_path(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let chain_is_null = unsafe { (*ctx).chain }.is_null();
    // SAFETY: `ctx` is live and `chain` is non-NULL on the arm that reads it.
    let chain_is_empty = !chain_is_null && unsafe { OPENSSL_sk_num((*ctx).chain) } == 0;
    // SAFETY: `ctx` is live per the contract.
    let no_verify_cb = unsafe { (*ctx).verify_cb.is_none() };
    if chain_is_null || chain_is_empty || no_verify_cb {
        // SAFETY: `ctx` is live per the contract.
        unsafe { (*ctx).error = X509_V_ERR_UNSPECIFIED };
        return 0;
    }
    // SAFETY: `ctx` and its non-empty chain are live per the checks above.
    unsafe { asid_validate_path_internal(ctx, (*ctx).chain, ptr::null_mut()) }
}

/// `int X509v3_asid_validate_resource_set(STACK_OF(X509) *chain, ASIdentifiers *ext, int allow_inheritance)` -- `crypto/x509/v3_asid.c:859-869`.
///
/// # Safety
///
/// `chain` is NULL or a live `STACK_OF(X509)`; `ext` is NULL or a live `ASIdentifiers`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_asid_validate_resource_set(
    chain: *mut OpenSslStack,
    ext: *mut AsIdentifiers,
    allow_inheritance: c_int,
) -> c_int {
    if ext.is_null() {
        return 1;
    }
    // SAFETY: `chain` is NULL or live and the `||` short-circuits.
    if chain.is_null() || unsafe { OPENSSL_sk_num(chain) } == 0 {
        return 0;
    }
    // SAFETY: `ext` is live per the checks above.
    if allow_inheritance == 0 && unsafe { X509v3_asid_inherits(ext) } != 0 {
        return 0;
    }
    // SAFETY: `chain` and `ext` are live per the checks above.
    unsafe { asid_validate_path_internal(ptr::null_mut(), chain, ext) }
}
