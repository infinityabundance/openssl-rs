//! `crypto/x509/v3_addr.c` — the RFC 3779 §2.2 `IPAddrBlocks` item group and the
//! `X509v3_addr_*` construction surface. Phase 10's table layer, landed whole.
//!
//! `crypto/x509/v3_addr.c` is 1,359 lines (1,330 of them inside `#ifndef OPENSSL_NO_RFC3779`,
//! which this profile enables) and transcribes as follows:
//!
//! * The five ASN.1 templates (`:36-58`) land: `IPAddressRange ::= SEQUENCE { min, max }`,
//!   `IPAddressOrRange ::= CHOICE { addressPrefix, addressRange }`,
//!   `IPAddressChoice ::= CHOICE { inherit, addressesOrRanges }`,
//!   `IPAddressFamily ::= SEQUENCE { addressFamily, ipAddressChoice }` and the
//!   `IPAddrBlocks ::= SEQUENCE OF IPAddressFamily` item template.
//! * The four exported item groups land. `IMPLEMENT_ASN1_FUNCTIONS` (`:60-63`) emits
//!   `IPAddressRange_it`/`_new`/`_free`/`d2i_`/`i2d_` and the same five for `IPAddressOrRange`,
//!   `IPAddressChoice` and `IPAddressFamily`; all four groups are public exports
//!   (`x509v3.h:919-922`), so the differential plane can build a value, encode it and decode the
//!   bytes back. `IPAddrBlocks` has **no** `IMPLEMENT_ASN1_FUNCTIONS` and no
//!   `DECLARE_ASN1_FUNCTIONS`; its item is `static_ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)` (`:58`),
//!   a file-local getter the row below references, so it lands here as the private
//!   [`IPAddrBlocks_it`] rather than an export.
//! * The printers land: `i2r_address` (`:131`), `i2r_IPAddressOrRanges` (`:172`) and the row's
//!   callback `i2r_IPAddrBlocks` (`:205`).
//! * The construction surface lands: `length_from_afi` (`:73`), `addr_expand` (`:102`),
//!   `X509v3_addr_get_afi` (`:88`), `IPAddressOrRange_cmp` (`:284`) and its v4/v6 closures
//!   (`:331`/`:341`), `range_should_be_prefix` (`:351`), `make_addressPrefix` (`:407`),
//!   `make_addressRange` (`:439`), `make_IPAddressFamily` (`:501`), `X509v3_addr_add_inherit`
//!   (`:546`), `make_prefix_or_range` (`:564`), `X509v3_addr_add_prefix` (`:595`),
//!   `X509v3_addr_add_range` (`:615`), `extract_min_max` (`:637`), `X509v3_addr_get_range`
//!   (`:654`), `IPAddressFamily_cmp` (`:677`), `IPAddressFamily_check_len` (`:688`),
//!   `X509v3_addr_is_canonical` (`:699`), `IPAddressOrRanges_canonize` (`:812`) and
//!   `X509v3_addr_canonize` (`:889`).
//! * The config callback `v2i_IPAddrBlocks` (`:917`) lands.
//! * The containment surface lands: `X509v3_addr_inherits` (`:1104`), `addr_contains` (`:1122`)
//!   and `X509v3_addr_subset` (`:1159`).
//! * The row [`ossl_v3_addr`] (`:1087-1099`) lands: `ext_nid` is `NID_sbgp_ipAddrBlock`, `it` is
//!   `ASN1_ITEM_ref(IPAddrBlocks)`, `v2i` is `v2i_IPAddrBlocks` and `i2r` is `i2r_IPAddrBlocks`.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456); this unit contributes one of the 63 rows. The row is internal data the admitted DSO
//! does not export (`nm -D` shows no `ossl_v3_*`), so a court cannot name it; its drivable surface
//! is the four exported item groups and the `X509v3_addr_*` API.
//!
//! **Also withheld by name**: the three path-validation names — `addr_validate_path_internal`
//! (`:1212-1325`), `X509v3_addr_validate_path` (`:1332-1341`), `X509v3_addr_validate_resource_set`
//! (`:1347-1357`) — the `validation_err` macro (`:1190-1202`) they share, and that macro's one
//! `ERR_raise` at `:1246`. Their blocker is the unlanded `X509_STORE_CTX`:
//! `grep -rn x509_store_ctx_st src/` finds no `struct x509_store_ctx_st` (no `chain`, `error`,
//! `error_depth`, `current_cert` or `verify_cb` surface), and `sk_X509_num`/`sk_X509_value` are
//! absent too, so the functions cannot be transcribed without inventing a type outside this unit.
//! Withheld whole rather than stubbed: the names are named, not declared.
//!
//! ## Naming divergence
//!
//! The unit's one undefined reference, `ossl_asn1_string_set_bits_left` (`v3_addr.c:424`, `:466`,
//! `:480`), is landed under the name `crate::asn1::bitstr::set_bits_left` (`src/asn1/bitstr.rs:79`,
//! `pub(crate) unsafe fn set_bits_left(a: *mut Asn1String, num: c_int)`). The two are one function;
//! only the Rust name differs. This divergence is recorded in `forensics/prerequisites.json` by the
//! orchestrator.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_addr.c` is not an entry in `gen_err_raise_sites.py`, so the fifteen coordinates
//! in the landed functions are **declared locally**, their reason values read from the authority's
//! `err.h.in`/`x509v3err.h` (not typed from memory), as `v3_bitst.rs` does. `ERR_LIB_X509V3` is
//! `err.h.in:99`; `ERR_R_CRYPTO_LIB` and `ERR_R_X509V3_LIB` are the `err.h.in` rows `:330`/`:335`;
//! the seven `X509V3_R_*` reasons are the `x509v3err.h` rows cited on each constant below.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use crate::asn1::bitstr::{set_bits_left, ASN1_BIT_STRING_set};
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_BIT_STRING_it, ASN1_NULL_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::{ASN1_BIT_STRING_new, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::typ::ASN1_NULL_new;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{memcmp, memcpy, memset, strcmp, strtoul};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_EXTENSION_NAME_ERROR, X509V3_R_EXTENSION_VALUE_ERROR, X509V3_R_INVALID_INHERITANCE,
    X509V3_R_INVALID_IPADDRESS, X509V3_R_INVALID_NULL_ARGUMENT, X509V3_R_INVALID_SAFI,
    X509V3_R_MISSING_VALUE,
};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup};
use crate::runtime::obj::NID_sbgp_ipAddrBlock;
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_new_null, OPENSSL_sk_num,
    OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_set, OPENSSL_sk_set_cmp_func, OPENSSL_sk_sort,
    OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{conf_add_error_name_value, ossl_a2i_ipadd, ossl_v3_name_cmp};

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`
/// (`15 | 0x80000`).
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_X509V3_LIB` — `include/openssl/err.h.in:335`, `ERR_LIB_X509V3 | ERR_RFLAG_COMMON`
/// (`34 | 0x80000`).
const ERR_R_X509V3_LIB: c_int = 524322;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strdup`/`OPENSSL_free` expansions —
/// `crypto/x509/v3_addr.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_addr.c";
/// `v2i_IPAddrBlocks`'s `OPENSSL_strdup(t)` on the SAFI path (`v3_addr.c:983`).
const LINE_V2I_STRDUP_SAFI: c_int = 983;
/// The same function's `OPENSSL_strdup(val->value)` (`v3_addr.c:985`).
const LINE_V2I_STRDUP: c_int = 985;
/// The same function's `OPENSSL_free(s)` on the `inherit` path (`v3_addr.c:1000`).
const LINE_V2I_FREE_INHERIT: c_int = 1000;
/// The same function's `OPENSSL_free(s)` at the end of the loop body (`v3_addr.c:1067`).
const LINE_V2I_FREE: c_int = 1067;
/// The same function's `OPENSSL_free(s)` on the `err` path (`v3_addr.c:1079`).
const LINE_V2I_ERR_FREE: c_int = 1079;

/// One `v3_addr.c` raise coordinate, declared locally (see the module doc).
const fn v3_addr_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_addr.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `X509v3_addr_canonize`'s NULL argument at `v3_addr.c:894` (`X509V3_R_INVALID_NULL_ARGUMENT`,
/// `x509v3err.h:53`).
const V3_ADDR_894: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(894, c"X509v3_addr_canonize", X509V3_R_INVALID_NULL_ARGUMENT);
/// `v2i_IPAddrBlocks`'s failed `sk_IPAddressFamily_new` at `v3_addr.c:928` (`ERR_R_CRYPTO_LIB`).
const V3_ADDR_928: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(928, c"v2i_IPAddrBlocks", ERR_R_CRYPTO_LIB);
/// `v2i_IPAddrBlocks`'s unknown name at `v3_addr.c:950` (`X509V3_R_EXTENSION_NAME_ERROR`,
/// `x509v3err.h:37`; the `%s` argument is `val->name`).
const V3_ADDR_950: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(950, c"v2i_IPAddrBlocks", X509V3_R_EXTENSION_NAME_ERROR);
/// `v2i_IPAddrBlocks`'s absent value at `v3_addr.c:972` (`X509V3_R_MISSING_VALUE`,
/// `x509v3err.h:66`).
const V3_ADDR_972: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(972, c"v2i_IPAddrBlocks", X509V3_R_MISSING_VALUE);
/// `v2i_IPAddrBlocks`'s malformed SAFI at `v3_addr.c:978` (`X509V3_R_INVALID_SAFI`,
/// `x509v3err.h:62`).
const V3_ADDR_978: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(978, c"v2i_IPAddrBlocks", X509V3_R_INVALID_SAFI);
/// `v2i_IPAddrBlocks`'s non-inherit use of `inherit` at `v3_addr.c:996`
/// (`X509V3_R_INVALID_INHERITANCE`, `x509v3err.h:49`).
const V3_ADDR_996: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(996, c"v2i_IPAddrBlocks", X509V3_R_INVALID_INHERITANCE);
/// `v2i_IPAddrBlocks`'s malformed address at `v3_addr.c:1011` (`X509V3_R_INVALID_IPADDRESS`,
/// `x509v3err.h:50`).
const V3_ADDR_1011: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1011, c"v2i_IPAddrBlocks", X509V3_R_INVALID_IPADDRESS);
/// `v2i_IPAddrBlocks`'s malformed prefix length at `v3_addr.c:1023`
/// (`X509V3_R_EXTENSION_VALUE_ERROR`, `x509v3err.h:40`).
const V3_ADDR_1023: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1023, c"v2i_IPAddrBlocks", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v2i_IPAddrBlocks`'s failed `X509v3_addr_add_prefix` at `v3_addr.c:1028` (`ERR_R_X509V3_LIB`).
const V3_ADDR_1028: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1028, c"v2i_IPAddrBlocks", ERR_R_X509V3_LIB);
/// `v2i_IPAddrBlocks`'s malformed range spelling at `v3_addr.c:1036`
/// (`X509V3_R_EXTENSION_VALUE_ERROR`).
const V3_ADDR_1036: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1036, c"v2i_IPAddrBlocks", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v2i_IPAddrBlocks`'s malformed range bound at `v3_addr.c:1041` (`X509V3_R_INVALID_IPADDRESS`).
const V3_ADDR_1041: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1041, c"v2i_IPAddrBlocks", X509V3_R_INVALID_IPADDRESS);
/// `v2i_IPAddrBlocks`'s inverted range at `v3_addr.c:1046` (`X509V3_R_EXTENSION_VALUE_ERROR`).
const V3_ADDR_1046: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1046, c"v2i_IPAddrBlocks", X509V3_R_EXTENSION_VALUE_ERROR);
/// `v2i_IPAddrBlocks`'s failed `X509v3_addr_add_range` at `v3_addr.c:1051` (`ERR_R_X509V3_LIB`).
const V3_ADDR_1051: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1051, c"v2i_IPAddrBlocks", ERR_R_X509V3_LIB);
/// `v2i_IPAddrBlocks`'s failed full-length `X509v3_addr_add_prefix` at `v3_addr.c:1057`
/// (`ERR_R_X509V3_LIB`).
const V3_ADDR_1057: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1057, c"v2i_IPAddrBlocks", ERR_R_X509V3_LIB);
/// `v2i_IPAddrBlocks`'s unknown delimiter at `v3_addr.c:1062` (`X509V3_R_EXTENSION_VALUE_ERROR`).
const V3_ADDR_1062: crate::runtime::err::err_sites::ErrSite =
    v3_addr_site(1062, c"v2i_IPAddrBlocks", X509V3_R_EXTENSION_VALUE_ERROR);

/// `#define IPAddressOrRange_addressPrefix 0` — `include/openssl/x509v3.h:876`.
const IPAddressOrRange_addressPrefix: c_int = 0;
/// `#define IPAddressOrRange_addressRange 1` — `include/openssl/x509v3.h:877`.
const IPAddressOrRange_addressRange: c_int = 1;
/// `#define IPAddressChoice_inherit 0` — `include/openssl/x509v3.h:895`.
const IPAddressChoice_inherit: c_int = 0;
/// `#define IPAddressChoice_addressesOrRanges 1` — `include/openssl/x509v3.h:896`.
const IPAddressChoice_addressesOrRanges: c_int = 1;
/// `#define IANA_AFI_IPV4 1` — `include/openssl/x509v3.h:936`.
const IANA_AFI_IPV4: c_uint = 1;
/// `#define IANA_AFI_IPV6 2` — `include/openssl/x509v3.h:937`.
const IANA_AFI_IPV6: c_uint = 2;
/// `#define ADDR_RAW_BUF_LEN 16` — `crypto/x509/v3_addr.c:68`.
const ADDR_RAW_BUF_LEN: usize = 16;

/// `struct IPAddressRange_st` — `IPAddressRange`, from `include/openssl/x509v3.h:872-874`.
#[repr(C)]
pub struct IpAddressRange {
    /// `ASN1_BIT_STRING *min`.
    pub min: *mut Asn1String,
    /// `ASN1_BIT_STRING *max`.
    pub max: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<IpAddressRange>() == 16);
    assert!(core::mem::offset_of!(IpAddressRange, min) == 0);
    assert!(core::mem::offset_of!(IpAddressRange, max) == 8);
};

/// `struct IPAddressOrRange_st` — `IPAddressOrRange`, from `include/openssl/x509v3.h:879-885`.
/// The union is one pointer at offset 8; `type_` selects `addressPrefix` or `addressRange`.
#[repr(C)]
pub struct IpAddressOrRange {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ASN1_BIT_STRING *addressPrefix; IPAddressRange *addressRange; } u`.
    pub u: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<IpAddressOrRange>() == 16);
    assert!(core::mem::offset_of!(IpAddressOrRange, type_) == 0);
    assert!(core::mem::offset_of!(IpAddressOrRange, u) == 8);
};

/// `struct IPAddressChoice_st` — `IPAddressChoice`, from `include/openssl/x509v3.h:898-904`.
#[repr(C)]
pub struct IpAddressChoice {
    /// `int type` — the CHOICE selector.
    pub type_: c_int,
    /// `union { ASN1_NULL *inherit; IPAddressOrRanges *addressesOrRanges; } u`.
    pub u: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<IpAddressChoice>() == 16);
    assert!(core::mem::offset_of!(IpAddressChoice, type_) == 0);
    assert!(core::mem::offset_of!(IpAddressChoice, u) == 8);
};

/// `struct IPAddressFamily_st` — `IPAddressFamily`, from `include/openssl/x509v3.h:906-909`.
#[repr(C)]
pub struct IpAddressFamily {
    /// `ASN1_OCTET_STRING *addressFamily`.
    pub addressFamily: *mut Asn1String,
    /// `IPAddressChoice *ipAddressChoice`.
    pub ipAddressChoice: *mut IpAddressChoice,
}

const _: () = {
    assert!(core::mem::size_of::<IpAddressFamily>() == 16);
    assert!(core::mem::offset_of!(IpAddressFamily, addressFamily) == 0);
    assert!(core::mem::offset_of!(IpAddressFamily, ipAddressChoice) == 8);
};

// ---------------------------------------------------------------------------------------------
// The five item templates — `ASN1_SEQUENCE`/`ASN1_CHOICE`/`ASN1_ITEM_TEMPLATE` at
// `v3_addr.c:36-58`.
// ---------------------------------------------------------------------------------------------

/// `IPAddressRange_seq_tt` — `ASN1_SEQUENCE(IPAddressRange)` (`v3_addr.c:36-39`): two
/// `ASN1_SIMPLE(..., ASN1_BIT_STRING)` rows.
static IPADDRESSRANGE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"min".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"max".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
];

/// `IPAddressRange_it`'s descriptor — `ASN1_SEQUENCE_END(IPAddressRange)` at `v3_addr.c:39`.
static IPADDRESSRANGE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: IPADDRESSRANGE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<IpAddressRange>() as c_long,
    sname: c"IPAddressRange".as_ptr(),
};

/// `IPAddressOrRange_ch_tt` — `ASN1_CHOICE(IPAddressOrRange)` (`v3_addr.c:41-44`):
/// `ASN1_SIMPLE(..., u.addressPrefix, ASN1_BIT_STRING)` and
/// `ASN1_SIMPLE(..., u.addressRange, IPAddressRange)`, both at offset 8.
static IPADDRESSORRANGE_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.addressPrefix".as_ptr(),
        item: ASN1_BIT_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"u.addressRange".as_ptr(),
        item: IPAddressRange_it as *mut c_void,
    },
];

/// `IPAddressOrRange_it`'s descriptor — `ASN1_CHOICE_END(IPAddressOrRange)` at `v3_addr.c:44`.
/// `utype` is the selector offset (0), as `ASN1_CHOICE_END_selector` passes.
static IPADDRESSORRANGE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: IPADDRESSORRANGE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<IpAddressOrRange>() as c_long,
    sname: c"IPAddressOrRange".as_ptr(),
};

/// `IPAddressChoice_ch_tt` — `ASN1_CHOICE(IPAddressChoice)` (`v3_addr.c:46-49`):
/// `ASN1_SIMPLE(..., u.inherit, ASN1_NULL)` and
/// `ASN1_SEQUENCE_OF(..., u.addressesOrRanges, IPAddressOrRange)`.
static IPADDRESSCHOICE_TT: [Asn1Template; 2] = [
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
        field_name: c"u.addressesOrRanges".as_ptr(),
        item: IPAddressOrRange_it as *mut c_void,
    },
];

/// `IPAddressChoice_it`'s descriptor — `ASN1_CHOICE_END(IPAddressChoice)` at `v3_addr.c:49`.
static IPADDRESSCHOICE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_CHOICE,
    utype: 0,
    templates: IPADDRESSCHOICE_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<IpAddressChoice>() as c_long,
    sname: c"IPAddressChoice".as_ptr(),
};

/// `IPAddressFamily_seq_tt` — `ASN1_SEQUENCE(IPAddressFamily)` (`v3_addr.c:51-54`):
/// `ASN1_SIMPLE(..., addressFamily, ASN1_OCTET_STRING)` and
/// `ASN1_SIMPLE(..., ipAddressChoice, IPAddressChoice)`.
static IPADDRESSFAMILY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"addressFamily".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"ipAddressChoice".as_ptr(),
        item: IPAddressChoice_it as *mut c_void,
    },
];

/// `IPAddressFamily_it`'s descriptor — `ASN1_SEQUENCE_END(IPAddressFamily)` at `v3_addr.c:54`.
static IPADDRESSFAMILY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: IPADDRESSFAMILY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<IpAddressFamily>() as c_long,
    sname: c"IPAddressFamily".as_ptr(),
};

/// `IPAddrBlocks_item_tt` — `ASN1_ITEM_TEMPLATE(IPAddrBlocks)` with
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, IPAddrBlocks, IPAddressFamily)`
/// (`v3_addr.c:56-57`).
static IPADDRBLOCKS_TT: [Asn1Template; 1] = [Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"IPAddrBlocks".as_ptr(),
    item: IPAddressFamily_it as *mut c_void,
}];

/// `IPAddrBlocks_it`'s descriptor — `static_ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)` at
/// `v3_addr.c:58`. A primitive item whose single template is the `SEQUENCE OF`; `tcount` is 0, as
/// the template macro spells it.
static IPADDRBLOCKS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: -1,
    templates: IPADDRBLOCKS_TT.as_ptr(),
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"IPAddrBlocks".as_ptr(),
};

/// `static const ASN1_ITEM *IPAddrBlocks_it(void)` — the file-local getter
/// `static_ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)` defines at `v3_addr.c:58`. It is `static` in the
/// authority (not exported; `nm -D` shows no `IPAddrBlocks_it`) and is referenced only by the row.
extern "C" fn IPAddrBlocks_it() -> *const Asn1Item {
    &IPADDRBLOCKS_ITEM
}

// ---------------------------------------------------------------------------------------------
// The item groups — `IMPLEMENT_ASN1_FUNCTIONS` at `v3_addr.c:60-63`.
// ---------------------------------------------------------------------------------------------

/// `const ASN1_ITEM *IPAddressRange_it(void)` — `include/openssl/x509v3.h:919`, from
/// `DECLARE_ASN1_FUNCTIONS(IPAddressRange)`.
#[no_mangle]
pub extern "C" fn IPAddressRange_it() -> *const Asn1Item {
    &IPADDRESSRANGE_ITEM
}

/// `IPAddressRange *IPAddressRange_new(void)` — `crypto/x509/v3_addr.c:60`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(IPAddressRange)`.
#[no_mangle]
pub extern "C" fn IPAddressRange_new() -> *mut IpAddressRange {
    // SAFETY: `IPAddressRange_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(IPAddressRange_it()).cast::<IpAddressRange>() }
}

/// `void IPAddressRange_free(IPAddressRange *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn IPAddressRange_free(a: *mut IpAddressRange) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), IPAddressRange_it()) }
}

/// `IPAddressRange *d2i_IPAddressRange(IPAddressRange **a, const unsigned char **in, long len)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_IPAddressRange(
    a: *mut *mut IpAddressRange,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IpAddressRange {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, IPAddressRange_it()).cast::<IpAddressRange>() }
}

/// `int i2d_IPAddressRange(const IPAddressRange *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_IPAddressRange(
    a: *const IpAddressRange,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, IPAddressRange_it()) }
}

/// `const ASN1_ITEM *IPAddressOrRange_it(void)` — `include/openssl/x509v3.h:920`.
#[no_mangle]
pub extern "C" fn IPAddressOrRange_it() -> *const Asn1Item {
    &IPADDRESSORRANGE_ITEM
}

/// `IPAddressOrRange *IPAddressOrRange_new(void)` — `crypto/x509/v3_addr.c:61`.
#[no_mangle]
pub extern "C" fn IPAddressOrRange_new() -> *mut IpAddressOrRange {
    // SAFETY: `IPAddressOrRange_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(IPAddressOrRange_it()).cast::<IpAddressOrRange>() }
}

/// `void IPAddressOrRange_free(IPAddressOrRange *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn IPAddressOrRange_free(a: *mut IpAddressOrRange) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), IPAddressOrRange_it()) }
}

/// `IPAddressOrRange *d2i_IPAddressOrRange(IPAddressOrRange **a, const unsigned char **in, long
/// len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_IPAddressOrRange(
    a: *mut *mut IpAddressOrRange,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IpAddressOrRange {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, IPAddressOrRange_it()).cast::<IpAddressOrRange>() }
}

/// `int i2d_IPAddressOrRange(const IPAddressOrRange *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_IPAddressOrRange(
    a: *const IpAddressOrRange,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, IPAddressOrRange_it()) }
}

/// `const ASN1_ITEM *IPAddressChoice_it(void)` — `include/openssl/x509v3.h:921`.
#[no_mangle]
pub extern "C" fn IPAddressChoice_it() -> *const Asn1Item {
    &IPADDRESSCHOICE_ITEM
}

/// `IPAddressChoice *IPAddressChoice_new(void)` — `crypto/x509/v3_addr.c:62`.
#[no_mangle]
pub extern "C" fn IPAddressChoice_new() -> *mut IpAddressChoice {
    // SAFETY: `IPAddressChoice_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(IPAddressChoice_it()).cast::<IpAddressChoice>() }
}

/// `void IPAddressChoice_free(IPAddressChoice *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn IPAddressChoice_free(a: *mut IpAddressChoice) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), IPAddressChoice_it()) }
}

/// `IPAddressChoice *d2i_IPAddressChoice(IPAddressChoice **a, const unsigned char **in, long len)`
/// — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_IPAddressChoice(
    a: *mut *mut IpAddressChoice,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IpAddressChoice {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, IPAddressChoice_it()).cast::<IpAddressChoice>() }
}

/// `int i2d_IPAddressChoice(const IPAddressChoice *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_IPAddressChoice(
    a: *const IpAddressChoice,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, IPAddressChoice_it()) }
}

/// `const ASN1_ITEM *IPAddressFamily_it(void)` — `include/openssl/x509v3.h:922`.
#[no_mangle]
pub extern "C" fn IPAddressFamily_it() -> *const Asn1Item {
    &IPADDRESSFAMILY_ITEM
}

/// `IPAddressFamily *IPAddressFamily_new(void)` — `crypto/x509/v3_addr.c:63`.
#[no_mangle]
pub extern "C" fn IPAddressFamily_new() -> *mut IpAddressFamily {
    // SAFETY: `IPAddressFamily_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(IPAddressFamily_it()).cast::<IpAddressFamily>() }
}

/// `void IPAddressFamily_free(IPAddressFamily *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn IPAddressFamily_free(a: *mut IpAddressFamily) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), IPAddressFamily_it()) }
}

/// `IPAddressFamily *d2i_IPAddressFamily(IPAddressFamily **a, const unsigned char **in, long len)`
/// — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_IPAddressFamily(
    a: *mut *mut IpAddressFamily,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IpAddressFamily {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, IPAddressFamily_it()).cast::<IpAddressFamily>() }
}

/// `int i2d_IPAddressFamily(const IPAddressFamily *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_IPAddressFamily(
    a: *const IpAddressFamily,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, IPAddressFamily_it()) }
}

/// The typed destructor adapter for `sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `IPAddressFamily` the stack owns.
unsafe extern "C" fn ip_address_family_free_void(p: *mut c_void) {
    // SAFETY: the stack holds `IPAddressFamily *` values, per its declaration.
    unsafe { IPAddressFamily_free(p.cast::<IpAddressFamily>()) };
}

// ---------------------------------------------------------------------------------------------
// The printers — `v3_addr.c:88-272`.
// ---------------------------------------------------------------------------------------------

/// `static int length_from_afi(const unsigned afi)` — `crypto/x509/v3_addr.c:73-83`. Four for
/// `IANA_AFI_IPV4`, sixteen for `IANA_AFI_IPV6`, zero otherwise.
fn length_from_afi(afi: c_uint) -> c_int {
    match afi {
        IANA_AFI_IPV4 => 4,
        IANA_AFI_IPV6 => 16,
        _ => 0,
    }
}

/// `unsigned int X509v3_addr_get_afi(const IPAddressFamily *f)` — `crypto/x509/v3_addr.c:88-96`.
///
/// # Safety
///
/// `f` is NULL or a live `IPAddressFamily`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_get_afi(f: *const IpAddressFamily) -> c_uint {
    if f.is_null() {
        return 0;
    }
    // SAFETY: `f` is live per the contract.
    let af = unsafe { (*f).addressFamily };
    if af.is_null() {
        return 0;
    }
    // SAFETY: `af` is a live octet string.
    if unsafe { (*af).data }.is_null() || unsafe { (*af).length } < 2 {
        return 0;
    }
    // SAFETY: `af->data` has at least two readable bytes.
    unsafe { (c_uint::from(*(*af).data) << 8) | c_uint::from(*(*af).data.add(1)) }
}

/// `static int addr_expand(unsigned char *addr, const ASN1_BIT_STRING *bs, const int length, const
/// unsigned char fill)` — `crypto/x509/v3_addr.c:102-121`.
///
/// # Safety
///
/// `addr` is `length` writable bytes; `bs` is a live bit string whose `data` has `length` readable
/// bytes.
unsafe fn addr_expand(
    addr: *mut c_uchar,
    bs: *const Asn1String,
    length: c_int,
    fill: c_uchar,
) -> c_int {
    // SAFETY: `bs` is a live bit string per the caller's contract.
    let bs_len = unsafe { (*bs).length };
    if bs_len < 0 || bs_len > length {
        return 0;
    }
    if bs_len > 0 {
        // SAFETY: `addr` has `length` writable bytes and `bs->data` has `bs_len` readable bytes.
        unsafe {
            memcpy(
                addr.cast::<c_void>(),
                (*bs).data.cast::<c_void>(),
                bs_len as usize,
            )
        };
        // SAFETY: `bs` is live; its `flags` holds the unused-bit count in the low three bits.
        let bits = (unsafe { (*bs).flags } & 7) as c_int;
        if bits != 0 {
            let mask: c_uchar = (0xFF_u32 >> (8 - bits)) as c_uchar;
            let idx = (bs_len - 1) as usize;
            // SAFETY: `idx` is within `addr`'s `length` writable bytes.
            unsafe {
                if fill == 0 {
                    *addr.add(idx) &= !mask;
                } else {
                    *addr.add(idx) |= mask;
                }
            }
        }
    }
    // SAFETY: `addr + bs_len` has `length - bs_len` writable bytes.
    unsafe {
        memset(
            addr.add(bs_len as usize).cast::<c_void>(),
            c_int::from(fill),
            (length - bs_len) as usize,
        )
    };
    1
}

/// The authority's `addr_prefixlen(bs)` macro (`v3_addr.c:126`):
/// `(int)((bs)->length * 8 - ((bs)->flags & 7))`.
///
/// # Safety
///
/// `bs` is a live bit string.
unsafe fn addr_prefixlen(bs: *const Asn1String) -> c_int {
    // SAFETY: `bs` is a live bit string per the contract.
    unsafe { (*bs).length * 8 - ((*bs).flags & 7) as c_int }
}

/// `static int i2r_address(BIO *out, const unsigned afi, const unsigned char fill, const
/// ASN1_BIT_STRING *bs)` — `crypto/x509/v3_addr.c:131-167`.
///
/// # Safety
///
/// `out` is a live BIO; `bs` is a live bit string.
unsafe fn i2r_address(
    out: *mut crate::runtime::bio::Bio,
    afi: c_uint,
    fill: c_uchar,
    bs: *const Asn1String,
) -> c_int {
    let mut addr = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    // SAFETY: `bs` is a live bit string per the contract.
    if unsafe { (*bs).length } < 0 {
        return 0;
    }
    match afi {
        IANA_AFI_IPV4 => {
            // SAFETY: `addr` has 16 writable bytes; `bs` is a live bit string.
            if unsafe { addr_expand(addr.as_mut_ptr(), bs, 4, fill) } == 0 {
                return 0;
            }
            // SAFETY: `out` is live and the four bytes were expanded.
            unsafe {
                BIO_printf(
                    out,
                    c"%d.%d.%d.%d".as_ptr(),
                    c_int::from(addr[0]),
                    c_int::from(addr[1]),
                    c_int::from(addr[2]),
                    c_int::from(addr[3]),
                )
            };
        }
        IANA_AFI_IPV6 => {
            // SAFETY: `addr` has 16 writable bytes; `bs` is a live bit string.
            if unsafe { addr_expand(addr.as_mut_ptr(), bs, 16, fill) } == 0 {
                return 0;
            }
            let mut n: c_int = 16;
            while n > 1 && addr[(n - 1) as usize] == 0x00 && addr[(n - 2) as usize] == 0x00 {
                n -= 2;
            }
            let mut i: c_int = 0;
            while i < n {
                let v = (c_int::from(addr[i as usize]) << 8) | c_int::from(addr[(i + 1) as usize]);
                let sep: *const c_char = if i < 14 { c":".as_ptr() } else { c"".as_ptr() };
                // SAFETY: `out` is live; `v` and `sep` are as the format declares.
                unsafe { BIO_printf(out, c"%x%s".as_ptr(), v, sep) };
                i += 2;
            }
            if i < 16 {
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c":".as_ptr()) };
            }
            if i == 0 {
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c":".as_ptr()) };
            }
        }
        _ => {
            let mut i: c_int = 0;
            // SAFETY: `bs` is a live bit string with `length` readable bytes at `data`.
            while i < unsafe { (*bs).length } {
                let sep: *const c_char = if i > 0 { c":".as_ptr() } else { c"".as_ptr() };
                // SAFETY: `out` is live and `i` indexes `bs->data`.
                unsafe {
                    BIO_printf(
                        out,
                        c"%s%02x".as_ptr(),
                        sep,
                        c_int::from(*(*bs).data.add(i as usize)),
                    )
                };
                i += 1;
            }
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_printf(out, c"[%d]".as_ptr(), ((*bs).flags & 7) as c_int) };
        }
    }
    1
}

/// `static int i2r_IPAddressOrRanges(BIO *out, const int indent, const IPAddressOrRanges *aors,
/// const unsigned afi)` — `crypto/x509/v3_addr.c:172-200`.
///
/// # Safety
///
/// `out` is a live BIO; `aors` is a live `STACK_OF(IPAddressOrRange)`.
unsafe fn i2r_IPAddressOrRanges(
    out: *mut crate::runtime::bio::Bio,
    indent: c_int,
    aors: *const OpenSslStack,
    afi: c_uint,
) -> c_int {
    let mut i: c_int = 0;
    // SAFETY: `aors` is a live stack per the contract.
    while i < unsafe { OPENSSL_sk_num(aors) } {
        // SAFETY: `i` is in bounds.
        let aor = unsafe { OPENSSL_sk_value(aors, i) }.cast::<IpAddressOrRange>();
        // SAFETY: `out` is live; the format and arguments are as declared.
        unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `aor` is a live element per the stack contract.
        match unsafe { (*aor).type_ } {
            IPAddressOrRange_addressPrefix => {
                // SAFETY: the `addressPrefix` arm is live under this selector.
                let bs = unsafe { (*aor).u.cast::<Asn1String>() };
                // SAFETY: `bs` is a live bit string; `out` is live.
                if unsafe { i2r_address(out, afi, 0x00, bs) } == 0 {
                    return 0;
                }
                // SAFETY: `out` is live and `bs` is a live bit string.
                unsafe { BIO_printf(out, c"/%d\n".as_ptr(), addr_prefixlen(bs)) };
            }
            IPAddressOrRange_addressRange => {
                // SAFETY: the `addressRange` arm is live under this selector.
                let range = unsafe { (*aor).u.cast::<IpAddressRange>() };
                // SAFETY: the range's `min` is a live bit string; `out` is live.
                if unsafe { i2r_address(out, afi, 0x00, (*range).min) } == 0 {
                    return 0;
                }
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c"-".as_ptr()) };
                // SAFETY: the range's `max` is a live bit string; `out` is live.
                if unsafe { i2r_address(out, afi, 0xFF, (*range).max) } == 0 {
                    return 0;
                }
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c"\n".as_ptr()) };
            }
            _ => {}
        }
        i += 1;
    }
    1
}

/// `static int i2r_IPAddrBlocks(const X509V3_EXT_METHOD *method, void *ext, BIO *out, int indent)`
/// — `crypto/x509/v3_addr.c:205-272`. The row's `i2r` callback.
///
/// # Safety
///
/// `ext` is a live `STACK_OF(IPAddressFamily)`; `out` is a live BIO.
unsafe extern "C" fn i2r_IPAddrBlocks(
    _method: *const X509V3ExtMethod,
    ext: *mut c_void,
    out: *mut crate::runtime::bio::Bio,
    indent: c_int,
) -> c_int {
    let addr = ext.cast::<OpenSslStack>();
    let mut i: c_int = 0;
    // SAFETY: `addr` is a live stack per the caller's contract.
    while i < unsafe { OPENSSL_sk_num(addr) } {
        // SAFETY: `i` is in bounds.
        let f = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: `f` is a live element per the stack contract.
        let afi = unsafe { X509v3_addr_get_afi(f) };
        match afi {
            IANA_AFI_IPV4 => {
                // SAFETY: `out` is live; the format and arguments are as declared.
                unsafe { BIO_printf(out, c"%*sIPv4".as_ptr(), indent, c"".as_ptr()) };
            }
            IANA_AFI_IPV6 => {
                // SAFETY: as above.
                unsafe { BIO_printf(out, c"%*sIPv6".as_ptr(), indent, c"".as_ptr()) };
            }
            _ => {
                // SAFETY: `out` is live; `afi` is the unsigned the format declares.
                unsafe {
                    BIO_printf(
                        out,
                        c"%*sUnknown AFI %u".as_ptr(),
                        indent,
                        c"".as_ptr(),
                        afi,
                    )
                };
            }
        }
        // SAFETY: `f` is live and its `addressFamily` is a live octet string.
        if unsafe { (*(*f).addressFamily).length } > 2 {
            // SAFETY: the octet string has at least three readable bytes.
            let safi = unsafe { *(*(*f).addressFamily).data.add(2) };
            match safi {
                1 => {
                    // SAFETY: `out` is live and the literal is static.
                    unsafe { BIO_puts(out, c" (Unicast)".as_ptr()) };
                }
                2 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (Multicast)".as_ptr()) };
                }
                3 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (Unicast/Multicast)".as_ptr()) };
                }
                4 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (MPLS)".as_ptr()) };
                }
                64 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (Tunnel)".as_ptr()) };
                }
                65 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (VPLS)".as_ptr()) };
                }
                66 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (BGP MDT)".as_ptr()) };
                }
                128 => {
                    // SAFETY: as above.
                    unsafe { BIO_puts(out, c" (MPLS-labeled VPN)".as_ptr()) };
                }
                _ => {
                    // SAFETY: `out` is live; `safi` is the unsigned the format declares.
                    unsafe { BIO_printf(out, c" (Unknown SAFI %u)".as_ptr(), c_uint::from(safi)) };
                }
            }
        }
        // SAFETY: `f` is live and its `ipAddressChoice` is live.
        let choice = unsafe { (*f).ipAddressChoice };
        // SAFETY: `choice` is live.
        match unsafe { (*choice).type_ } {
            IPAddressChoice_inherit => {
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c": inherit\n".as_ptr()) };
            }
            IPAddressChoice_addressesOrRanges => {
                // SAFETY: `out` is live and the literal is static.
                unsafe { BIO_puts(out, c":\n".as_ptr()) };
                // SAFETY: the list arm is live under the selector; `out` is live.
                if unsafe {
                    i2r_IPAddressOrRanges(out, indent + 2, (*choice).u.cast::<OpenSslStack>(), afi)
                } == 0
                {
                    return 0;
                }
            }
            _ => {}
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// Sort comparators — `v3_addr.c:284-345` and `:677-694`.
// ---------------------------------------------------------------------------------------------

/// `static int IPAddressOrRange_cmp(const IPAddressOrRange *a, const IPAddressOrRange *b, const
/// int length)` — `crypto/x509/v3_addr.c:284-325`.
///
/// # Safety
///
/// `a` and `b` are live `IPAddressOrRange` values; `length` is 4 or 16.
unsafe fn ip_address_or_range_cmp(
    a: *const IpAddressOrRange,
    b: *const IpAddressOrRange,
    length: c_int,
) -> c_int {
    let mut addr_a = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut addr_b = [0 as c_uchar; ADDR_RAW_BUF_LEN];

    // SAFETY: `a` is live per the contract.
    let prefixlen_a: c_int = match unsafe { (*a).type_ } {
        IPAddressOrRange_addressPrefix => {
            // SAFETY: the `addressPrefix` arm is live under this selector.
            let bs = unsafe { (*a).u.cast::<Asn1String>() };
            // SAFETY: `addr_a` has 16 writable bytes; `bs` is a live bit string.
            if unsafe { addr_expand(addr_a.as_mut_ptr(), bs, length, 0x00) } == 0 {
                return -1;
            }
            // SAFETY: `bs` is a live bit string.
            unsafe { addr_prefixlen(bs) }
        }
        IPAddressOrRange_addressRange => {
            // SAFETY: the `addressRange` arm is live under this selector.
            let range = unsafe { (*a).u.cast::<IpAddressRange>() };
            // SAFETY: the range's `min` is a live bit string.
            if unsafe { addr_expand(addr_a.as_mut_ptr(), (*range).min, length, 0x00) } == 0 {
                return -1;
            }
            length * 8
        }
        _ => return -1,
    };

    // SAFETY: `b` is live per the contract.
    let prefixlen_b: c_int = match unsafe { (*b).type_ } {
        IPAddressOrRange_addressPrefix => {
            // SAFETY: the `addressPrefix` arm is live under this selector.
            let bs = unsafe { (*b).u.cast::<Asn1String>() };
            // SAFETY: `addr_b` has 16 writable bytes; `bs` is a live bit string.
            if unsafe { addr_expand(addr_b.as_mut_ptr(), bs, length, 0x00) } == 0 {
                return -1;
            }
            // SAFETY: `bs` is a live bit string.
            unsafe { addr_prefixlen(bs) }
        }
        IPAddressOrRange_addressRange => {
            // SAFETY: the `addressRange` arm is live under this selector.
            let range = unsafe { (*b).u.cast::<IpAddressRange>() };
            // SAFETY: the range's `min` is a live bit string.
            if unsafe { addr_expand(addr_b.as_mut_ptr(), (*range).min, length, 0x00) } == 0 {
                return -1;
            }
            length * 8
        }
        _ => return -1,
    };

    // SAFETY: both arrays have `length` readable bytes.
    let r = unsafe {
        memcmp(
            addr_a.as_ptr().cast::<c_void>(),
            addr_b.as_ptr().cast::<c_void>(),
            length as usize,
        )
    };
    if r != 0 {
        r
    } else {
        prefixlen_a - prefixlen_b
    }
}

/// `static int v4IPAddressOrRange_cmp(const IPAddressOrRange *const *a, const IPAddressOrRange
/// *const *b)` — `crypto/x509/v3_addr.c:331-335`.
///
/// # Safety
///
/// The stack passes element slots for a comparator installed on this list.
unsafe extern "C" fn v4ip_address_or_range_cmp(a_: *const c_void, b_: *const c_void) -> c_int {
    // SAFETY: the stack passes element slots for a comparator installed on this list.
    let a = unsafe { *a_.cast::<*const IpAddressOrRange>() };
    // SAFETY: as above.
    let b = unsafe { *b_.cast::<*const IpAddressOrRange>() };
    // SAFETY: both are live elements the caller pushed.
    unsafe { ip_address_or_range_cmp(a, b, 4) }
}

/// `static int v6IPAddressOrRange_cmp(const IPAddressOrRange *const *a, const IPAddressOrRange
/// *const *b)` — `crypto/x509/v3_addr.c:341-345`.
///
/// # Safety
///
/// The stack passes element slots for a comparator installed on this list.
unsafe extern "C" fn v6ip_address_or_range_cmp(a_: *const c_void, b_: *const c_void) -> c_int {
    // SAFETY: the stack passes element slots for a comparator installed on this list.
    let a = unsafe { *a_.cast::<*const IpAddressOrRange>() };
    // SAFETY: as above.
    let b = unsafe { *b_.cast::<*const IpAddressOrRange>() };
    // SAFETY: both are live elements the caller pushed.
    unsafe { ip_address_or_range_cmp(a, b, 16) }
}

/// `static int IPAddressFamily_cmp(const IPAddressFamily *const *a_, const IPAddressFamily *const
/// *b_)` — `crypto/x509/v3_addr.c:677-686`.
///
/// # Safety
///
/// The stack passes element slots for a comparator installed on this list; each slot names a live
/// address family.
unsafe extern "C" fn ip_address_family_cmp(a_: *const c_void, b_: *const c_void) -> c_int {
    // SAFETY: the stack passes element slots for a comparator installed on this list.
    let a = unsafe { *a_.cast::<*const IpAddressFamily>() };
    // SAFETY: as above.
    let b = unsafe { *b_.cast::<*const IpAddressFamily>() };
    // SAFETY: both are live elements the caller pushed.
    let (ao, bo) = unsafe { ((*a).addressFamily, (*b).addressFamily) };
    // SAFETY: both octet strings are live.
    let (al, bl) = unsafe { ((*ao).length, (*bo).length) };
    let len = if al <= bl { al } else { bl };
    // SAFETY: both `data` arrays have at least `len` readable bytes.
    let cmp = unsafe {
        memcmp(
            (*ao).data.cast::<c_void>(),
            (*bo).data.cast::<c_void>(),
            len as usize,
        )
    };
    if cmp != 0 {
        cmp
    } else {
        al - bl
    }
}

/// `static int IPAddressFamily_check_len(const IPAddressFamily *f)` — `crypto/x509/v3_addr.c:688-694`.
///
/// # Safety
///
/// `f` is a live address family whose `addressFamily` is a live octet string.
unsafe fn ip_address_family_check_len(f: *const IpAddressFamily) -> c_int {
    // SAFETY: `f` is live per the contract.
    let len = unsafe { (*(*f).addressFamily).length };
    c_int::from((2..=3).contains(&len))
}

/// `static int range_should_be_prefix(const unsigned char *min, const unsigned char *max, const int
/// length)` — `crypto/x509/v3_addr.c:351-402`.
///
/// # Safety
///
/// `min` and `max` are `length` readable bytes each.
unsafe fn range_should_be_prefix(min: *const c_uchar, max: *const c_uchar, length: c_int) -> c_int {
    // `assert(memcmp(min, max, length) <= 0)` (`v3_addr.c:362`) is compiled out under `NDEBUG`.
    let mut i: c_int = 0;
    while i < length {
        // SAFETY: both pointers have `length` readable bytes; `i` is in bounds.
        let (lo, hi) = unsafe { (*min.add(i as usize), *max.add(i as usize)) };
        if lo != hi {
            break;
        }
        i += 1;
    }
    let mut j = length - 1;
    while j >= 0 {
        // SAFETY: both pointers have `length` readable bytes; `j` is in bounds.
        let (lo, hi) = unsafe { (*min.add(j as usize), *max.add(j as usize)) };
        if lo != 0x00 || hi != 0xFF {
            break;
        }
        j -= 1;
    }
    if i < j {
        return -1;
    }
    if i > j {
        return i * 8;
    }
    // SAFETY: `i` is in bounds.
    let (lo, hi) = unsafe { (*min.add(i as usize), *max.add(i as usize)) };
    let mask = lo ^ hi;
    let j = match mask {
        0x01 => 7,
        0x03 => 6,
        0x07 => 5,
        0x0F => 4,
        0x1F => 3,
        0x3F => 2,
        0x7F => 1,
        _ => return -1,
    };
    if (lo & mask) != 0 || (hi & mask) != mask {
        return -1;
    }
    i * 8 + j
}

// ---------------------------------------------------------------------------------------------
// Construction — `v3_addr.c:407-665`.
// ---------------------------------------------------------------------------------------------

/// `static int make_addressPrefix(IPAddressOrRange **result, unsigned char *addr, const int
/// prefixlen, const int afilen)` — `crypto/x509/v3_addr.c:407-432`.
///
/// # Safety
///
/// `result` is a writable slot; `addr` is `(prefixlen + 7) / 8` readable bytes when `prefixlen` is
/// in range.
unsafe fn make_addressPrefix(
    result: *mut *mut IpAddressOrRange,
    addr: *mut c_uchar,
    prefixlen: c_int,
    afilen: c_int,
) -> c_int {
    let bytelen = (prefixlen + 7) / 8;
    let bitlen = prefixlen % 8;

    if prefixlen < 0 || prefixlen > afilen * 8 {
        return 0;
    }
    let aor = IPAddressOrRange_new();
    if aor.is_null() {
        return 0;
    }
    // SAFETY: `aor` is a fresh value this call owns.
    unsafe { (*aor).type_ = IPAddressOrRange_addressPrefix };
    // SAFETY: `aor` is live.
    let mut bs = unsafe { (*aor).u.cast::<Asn1String>() };
    if bs.is_null() {
        // SAFETY: no preconditions; the item is the crate's own static.
        bs = ASN1_BIT_STRING_new();
        if bs.is_null() {
            // SAFETY: `aor` is a live value this call owns.
            unsafe { IPAddressOrRange_free(aor) };
            return 0;
        }
        // SAFETY: `aor` is live and its `addressPrefix` arm is the one being selected.
        unsafe { (*aor).u = bs.cast::<c_void>() };
    }
    // SAFETY: `bs` is a live bit string; `addr` has `bytelen` readable bytes.
    if unsafe { ASN1_BIT_STRING_set(bs, addr, bytelen) } == 0 {
        // SAFETY: `aor` is a live value this call owns.
        unsafe { IPAddressOrRange_free(aor) };
        return 0;
    }
    if bitlen > 0 {
        let keep: c_uchar = !((0xFF_u32 >> bitlen) as c_uchar);
        // SAFETY: `bs` is live and `data` has `bytelen` bytes, so `bytelen - 1` is in bounds.
        unsafe { *(*bs).data.add((bytelen - 1) as usize) &= keep };
    }
    // SAFETY: `bs` is a live bit string this call owns.
    unsafe { set_bits_left(bs, 8 - bitlen) };

    // SAFETY: `result` is a writable slot per the contract.
    unsafe { *result = aor };
    1
}

/// `static int make_addressRange(IPAddressOrRange **result, unsigned char *min, unsigned char *max,
/// const int length)` — `crypto/x509/v3_addr.c:439-496`.
///
/// # Safety
///
/// `result` is a writable slot; `min`/`max` are `length` readable bytes each with `min <= max`.
unsafe fn make_addressRange(
    result: *mut *mut IpAddressOrRange,
    min: *mut c_uchar,
    max: *mut c_uchar,
    length: c_int,
) -> c_int {
    // SAFETY: both pointers have `length` readable bytes.
    if unsafe { memcmp(min.cast::<c_void>(), max.cast::<c_void>(), length as usize) } > 0 {
        return 0;
    }

    // SAFETY: both pointers have `length` readable bytes.
    let prefixlen = unsafe { range_should_be_prefix(min, max, length) };
    if prefixlen >= 0 {
        // SAFETY: forwards the caller's contract; `result` is writable.
        return unsafe { make_addressPrefix(result, min, prefixlen, length) };
    }

    let aor = IPAddressOrRange_new();
    if aor.is_null() {
        return 0;
    }
    // SAFETY: `aor` is a fresh value this call owns.
    unsafe { (*aor).type_ = IPAddressOrRange_addressRange };
    let range = IPAddressRange_new();
    if range.is_null() {
        // SAFETY: `aor` is a live value this call owns.
        unsafe { IPAddressOrRange_free(aor) };
        return 0;
    }
    // SAFETY: `aor` is live and its `addressRange` arm is the one being selected.
    unsafe { (*aor).u = range.cast::<c_void>() };

    // SAFETY: `range` is live.
    if unsafe { (*range).min.is_null() } {
        // SAFETY: no preconditions; the item is the crate's own static.
        let p = ASN1_BIT_STRING_new();
        if p.is_null() {
            // SAFETY: `aor` is a live value this call owns.
            unsafe { IPAddressOrRange_free(aor) };
            return 0;
        }
        // SAFETY: `range` is live and its `min` slot is writable.
        unsafe { (*range).min = p };
    }
    // SAFETY: `range` is live.
    if unsafe { (*range).max.is_null() } {
        // SAFETY: no preconditions; the item is the crate's own static.
        let p = ASN1_BIT_STRING_new();
        if p.is_null() {
            // SAFETY: `aor` is a live value this call owns.
            unsafe { IPAddressOrRange_free(aor) };
            return 0;
        }
        // SAFETY: `range` is live and its `max` slot is writable.
        unsafe { (*range).max = p };
    }

    // The lower bound: strip trailing zero bytes.
    let mut i = length;
    // SAFETY: `min` has `length` readable bytes; `i - 1` is in bounds.
    while i > 0 && unsafe { *min.add((i - 1) as usize) } == 0x00 {
        i -= 1;
    }
    // SAFETY: `range->min` is a live bit string; `min` has `i` readable bytes.
    if unsafe { ASN1_BIT_STRING_set((*range).min, min, i) } == 0 {
        // SAFETY: `aor` is a live value this call owns.
        unsafe { IPAddressOrRange_free(aor) };
        return 0;
    }
    // SAFETY: `range->min` is a live bit string this call owns.
    unsafe { set_bits_left((*range).min, 0) };
    if i > 0 {
        // SAFETY: `min` has `i` readable bytes, so `i - 1` is in bounds.
        let b = c_uint::from(unsafe { *min.add((i - 1) as usize) });
        let mut j: c_int = 1;
        while (b & (0xFF_u32 >> j)) != 0 {
            j += 1;
        }
        // SAFETY: `range->min` is a live bit string.
        unsafe { (*(*range).min).flags |= c_long::from(8 - j) };
    }

    // The upper bound: strip trailing 0xFF bytes.
    let mut i = length;
    // SAFETY: `max` has `length` readable bytes; `i - 1` is in bounds.
    while i > 0 && unsafe { *max.add((i - 1) as usize) } == 0xFF {
        i -= 1;
    }
    // SAFETY: `range->max` is a live bit string; `max` has `i` readable bytes.
    if unsafe { ASN1_BIT_STRING_set((*range).max, max, i) } == 0 {
        // SAFETY: `aor` is a live value this call owns.
        unsafe { IPAddressOrRange_free(aor) };
        return 0;
    }
    // SAFETY: `range->max` is a live bit string this call owns.
    unsafe { set_bits_left((*range).max, 0) };
    if i > 0 {
        // SAFETY: `max` has `i` readable bytes, so `i - 1` is in bounds.
        let b = c_uint::from(unsafe { *max.add((i - 1) as usize) });
        let mut j: c_int = 1;
        while (b & (0xFF_u32 >> j)) != (0xFF_u32 >> j) {
            j += 1;
        }
        // SAFETY: `range->max` is a live bit string.
        unsafe { (*(*range).max).flags |= c_long::from(8 - j) };
    }

    // SAFETY: `result` is a writable slot per the contract.
    unsafe { *result = aor };
    1
}

/// `static IPAddressFamily *make_IPAddressFamily(IPAddrBlocks *addr, const unsigned afi, const
/// unsigned *safi)` — `crypto/x509/v3_addr.c:501-541`.
///
/// # Safety
///
/// `addr` is a live `STACK_OF(IPAddressFamily)`; `safi` is NULL or a readable `unsigned`.
unsafe fn make_IPAddressFamily(
    addr: *mut OpenSslStack,
    afi: c_uint,
    safi: *const c_uint,
) -> *mut IpAddressFamily {
    let mut key = [0 as c_uchar; 3];
    key[0] = ((afi >> 8) & 0xFF) as c_uchar;
    key[1] = (afi & 0xFF) as c_uchar;
    let keylen: c_int = if safi.is_null() {
        2
    } else {
        // SAFETY: `safi` is non-null (checked here) and readable per the contract.
        key[2] = (unsafe { *safi } & 0xFF) as c_uchar;
        3
    };

    let mut i: c_int = 0;
    // SAFETY: `addr` is a live stack per the contract.
    while i < unsafe { OPENSSL_sk_num(addr) } {
        // SAFETY: `i` is in bounds.
        let f = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: `f` is live; its octet string is live.
        let matches = unsafe {
            (*(*f).addressFamily).length == keylen
                && memcmp(
                    (*(*f).addressFamily).data.cast::<c_void>(),
                    key.as_ptr().cast::<c_void>(),
                    keylen as usize,
                ) == 0
        };
        if matches {
            return f;
        }
        i += 1;
    }

    let f = IPAddressFamily_new();
    if f.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `f` is live.
    if unsafe { (*f).ipAddressChoice.is_null() } {
        // SAFETY: the item getter answers a static item the crate owns.
        let c = IPAddressChoice_new();
        if c.is_null() {
            // SAFETY: `f` is a live value this call owns.
            unsafe { IPAddressFamily_free(f) };
            return ptr::null_mut();
        }
        // SAFETY: `f` is live and its `ipAddressChoice` slot is writable.
        unsafe { (*f).ipAddressChoice = c };
    }
    // SAFETY: `f` is live.
    if unsafe { (*f).addressFamily.is_null() } {
        // SAFETY: no preconditions; the item is the crate's own static.
        let s = ASN1_OCTET_STRING_new();
        if s.is_null() {
            // SAFETY: `f` is a live value this call owns.
            unsafe { IPAddressFamily_free(f) };
            return ptr::null_mut();
        }
        // SAFETY: `f` is live and its `addressFamily` slot is writable.
        unsafe { (*f).addressFamily = s };
    }
    // SAFETY: `f`'s octet string is live; `key` has `keylen` readable bytes.
    if unsafe { ASN1_OCTET_STRING_set((*f).addressFamily, key.as_ptr(), keylen) } == 0 {
        // SAFETY: `f` is a live value this call owns.
        unsafe { IPAddressFamily_free(f) };
        return ptr::null_mut();
    }
    // SAFETY: `addr` is a live stack; `f` transfers to it on success.
    if unsafe { OPENSSL_sk_push(addr, f.cast::<c_void>()) } == 0 {
        // SAFETY: `f` is a live value this call owns; the failed push left it off the list.
        unsafe { IPAddressFamily_free(f) };
        return ptr::null_mut();
    }
    f
}

/// `int X509v3_addr_add_inherit(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi)` —
/// `crypto/x509/v3_addr.c:546-559`.
///
/// # Safety
///
/// `addr` is a live `STACK_OF(IPAddressFamily)`; `safi` is NULL or a readable `unsigned`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_add_inherit(
    addr: *mut OpenSslStack,
    afi: c_uint,
    safi: *const c_uint,
) -> c_int {
    // SAFETY: `addr` is live per the contract.
    let f = unsafe { make_IPAddressFamily(addr, afi, safi) };
    if f.is_null() {
        return 0;
    }
    // SAFETY: `f` is live.
    let choice = unsafe { (*f).ipAddressChoice };
    if choice.is_null() {
        return 0;
    }
    // SAFETY: `choice` is live.
    let (t, u) = unsafe { ((*choice).type_, (*choice).u) };
    if t == IPAddressChoice_addressesOrRanges && !u.is_null() {
        return 0;
    }
    if t == IPAddressChoice_inherit && !u.is_null() {
        return 1;
    }
    // SAFETY: `choice` is live; its `inherit` arm is the one being selected.
    unsafe {
        if (*choice).u.is_null() {
            // SAFETY: no preconditions; `ASN1_NULL_new` answers the sentinel.
            let inherit = ASN1_NULL_new();
            if inherit.is_null() {
                return 0;
            }
            (*choice).u = inherit.cast::<c_void>();
        }
        (*choice).type_ = IPAddressChoice_inherit;
    }
    1
}

/// `static IPAddressOrRanges *make_prefix_or_range(IPAddrBlocks *addr, const unsigned afi, const
/// unsigned *safi)` — `crypto/x509/v3_addr.c:564-590`.
///
/// # Safety
///
/// `addr` is a live `STACK_OF(IPAddressFamily)`; `safi` is NULL or a readable `unsigned`.
unsafe fn make_prefix_or_range(
    addr: *mut OpenSslStack,
    afi: c_uint,
    safi: *const c_uint,
) -> *mut OpenSslStack {
    // SAFETY: `addr` is live per the contract.
    let f = unsafe { make_IPAddressFamily(addr, afi, safi) };
    if f.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `f` is live.
    let choice = unsafe { (*f).ipAddressChoice };
    if choice.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `choice` is live.
    let (t, u) = unsafe { ((*choice).type_, (*choice).u) };
    if t == IPAddressChoice_inherit && !u.is_null() {
        return ptr::null_mut();
    }
    let mut aors: *mut OpenSslStack = ptr::null_mut();
    if t == IPAddressChoice_addressesOrRanges {
        aors = u.cast::<OpenSslStack>();
    }
    if !aors.is_null() {
        return aors;
    }
    aors = OPENSSL_sk_new_null();
    if aors.is_null() {
        return ptr::null_mut();
    }
    match afi {
        IANA_AFI_IPV4 => {
            // SAFETY: `aors` is a live stack; the comparator is over its element type.
            unsafe { OPENSSL_sk_set_cmp_func(aors, Some(v4ip_address_or_range_cmp)) };
        }
        IANA_AFI_IPV6 => {
            // SAFETY: as above.
            unsafe { OPENSSL_sk_set_cmp_func(aors, Some(v6ip_address_or_range_cmp)) };
        }
        _ => {}
    }
    // SAFETY: `choice` is live and its list arm is the one being selected.
    unsafe {
        (*choice).type_ = IPAddressChoice_addressesOrRanges;
        (*choice).u = aors.cast::<c_void>();
    }
    aors
}

/// `int X509v3_addr_add_prefix(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi,
/// unsigned char *a, const int prefixlen)` — `crypto/x509/v3_addr.c:595-610`.
///
/// # Safety
///
/// `addr` is a live `STACK_OF(IPAddressFamily)`; `safi` is NULL or a readable `unsigned`; `a` is
/// `(prefixlen + 7) / 8` readable bytes when `prefixlen` is in range.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_add_prefix(
    addr: *mut OpenSslStack,
    afi: c_uint,
    safi: *const c_uint,
    a: *mut c_uchar,
    prefixlen: c_int,
) -> c_int {
    // SAFETY: `addr` is live per the contract.
    let aors = unsafe { make_prefix_or_range(addr, afi, safi) };
    if aors.is_null() {
        return 0;
    }
    let mut aor: *mut IpAddressOrRange = ptr::null_mut();
    // SAFETY: `aor` is a writable slot; forwards the caller's contract.
    if unsafe { make_addressPrefix(&raw mut aor, a, prefixlen, length_from_afi(afi)) } == 0 {
        return 0;
    }
    // SAFETY: `aors` is a live stack; `aor` transfers to it on success.
    if unsafe { OPENSSL_sk_push(aors, aor.cast::<c_void>()) } != 0 {
        return 1;
    }
    // SAFETY: `aor` is a live value this call owns; the failed push left it off the list.
    unsafe { IPAddressOrRange_free(aor) };
    0
}

/// `int X509v3_addr_add_range(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi,
/// unsigned char *min, unsigned char *max)` — `crypto/x509/v3_addr.c:615-632`.
///
/// # Safety
///
/// `addr` is a live `STACK_OF(IPAddressFamily)`; `safi` is NULL or a readable `unsigned`;
/// `min`/`max` are `length_from_afi(afi)` readable bytes each.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_add_range(
    addr: *mut OpenSslStack,
    afi: c_uint,
    safi: *const c_uint,
    min: *mut c_uchar,
    max: *mut c_uchar,
) -> c_int {
    // SAFETY: `addr` is live per the contract.
    let aors = unsafe { make_prefix_or_range(addr, afi, safi) };
    let length = length_from_afi(afi);
    if aors.is_null() {
        return 0;
    }
    let mut aor: *mut IpAddressOrRange = ptr::null_mut();
    // SAFETY: `aor` is a writable slot; forwards the caller's contract.
    if unsafe { make_addressRange(&raw mut aor, min, max, length) } == 0 {
        return 0;
    }
    // SAFETY: `aors` is a live stack; `aor` transfers to it on success.
    if unsafe { OPENSSL_sk_push(aors, aor.cast::<c_void>()) } != 0 {
        return 1;
    }
    // SAFETY: `aor` is a live value this call owns; the failed push left it off the list.
    unsafe { IPAddressOrRange_free(aor) };
    0
}

/// `static int extract_min_max(IPAddressOrRange *aor, unsigned char *min, unsigned char *max, int
/// length)` — `crypto/x509/v3_addr.c:637-649`.
///
/// # Safety
///
/// `aor` is NULL or live; `min`/`max` are NULL or `length` writable bytes each.
unsafe fn extract_min_max(
    aor: *mut IpAddressOrRange,
    min: *mut c_uchar,
    max: *mut c_uchar,
    length: c_int,
) -> c_int {
    if aor.is_null() || min.is_null() || max.is_null() {
        return 0;
    }
    // SAFETY: `aor` is live per the contract.
    match unsafe { (*aor).type_ } {
        IPAddressOrRange_addressPrefix => {
            // SAFETY: the `addressPrefix` arm is live; the arrays are `length` writable bytes.
            let bs = unsafe { (*aor).u.cast::<Asn1String>() };
            // SAFETY: both arrays satisfy `addr_expand`'s contract.
            c_int::from(unsafe {
                addr_expand(min, bs, length, 0x00) != 0 && addr_expand(max, bs, length, 0xFF) != 0
            })
        }
        IPAddressOrRange_addressRange => {
            // SAFETY: the `addressRange` arm is live under this selector.
            let range = unsafe { (*aor).u.cast::<IpAddressRange>() };
            // SAFETY: both arrays satisfy `addr_expand`'s contract.
            unsafe {
                c_int::from(
                    addr_expand(min, (*range).min, length, 0x00) != 0
                        && addr_expand(max, (*range).max, length, 0xFF) != 0,
                )
            }
        }
        _ => 0,
    }
}

/// `int X509v3_addr_get_range(IPAddressOrRange *aor, const unsigned afi, unsigned char *min,
/// unsigned char *max, const int length)` — `crypto/x509/v3_addr.c:654-665`.
///
/// # Safety
///
/// `aor` is NULL or live; `min`/`max` are NULL or writable with at least `length_from_afi(afi)`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_get_range(
    aor: *mut IpAddressOrRange,
    afi: c_uint,
    min: *mut c_uchar,
    max: *mut c_uchar,
    length: c_int,
) -> c_int {
    let afi_length = length_from_afi(afi);
    if aor.is_null() || min.is_null() || max.is_null() || afi_length == 0 || length < afi_length {
        return 0;
    }
    // SAFETY: `aor` is live under this selector.
    let t = unsafe { (*aor).type_ };
    if t != IPAddressOrRange_addressPrefix && t != IPAddressOrRange_addressRange {
        return 0;
    }
    // SAFETY: `aor` is live; `min`/`max` are `afi_length` writable bytes.
    if unsafe { extract_min_max(aor, min, max, afi_length) } == 0 {
        return 0;
    }
    afi_length
}

// ---------------------------------------------------------------------------------------------
// Canonicalisation — `v3_addr.c:699-912`.
// ---------------------------------------------------------------------------------------------

/// `int X509v3_addr_is_canonical(IPAddrBlocks *addr)` — `crypto/x509/v3_addr.c:699-807`.
///
/// # Safety
///
/// `addr` is NULL or a live `STACK_OF(IPAddressFamily)`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_is_canonical(addr: *mut OpenSslStack) -> c_int {
    let mut a_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut a_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut b_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut b_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];

    if addr.is_null() {
        return 1;
    }

    // The top-level list must be strictly ascending by address family.
    let mut i: c_int = 0;
    // SAFETY: `addr` is a live stack.
    while i < unsafe { OPENSSL_sk_num(addr) } - 1 {
        // SAFETY: `i` and `i + 1` are in bounds.
        let a = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: as above.
        let b = unsafe { OPENSSL_sk_value(addr, i + 1) }.cast::<IpAddressFamily>();
        // SAFETY: both are live address families.
        if unsafe { ip_address_family_check_len(a) == 0 || ip_address_family_check_len(b) == 0 } {
            return 0;
        }
        // SAFETY: both are live; the comparator reads through the slot pointers.
        if unsafe {
            ip_address_family_cmp(
                (&raw const a).cast::<c_void>(),
                (&raw const b).cast::<c_void>(),
            )
        } >= 0
        {
            return 0;
        }
        i += 1;
    }

    // Each address family's `IPAddressOrRange` list must be canonical.
    i = 0;
    // SAFETY: `addr` is a live stack.
    while i < unsafe { OPENSSL_sk_num(addr) } {
        // SAFETY: `i` is in bounds.
        let f = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: `f` is live (or NULL, which the getter tolerates).
        let length = length_from_afi(unsafe { X509v3_addr_get_afi(f) });
        if f.is_null() {
            return 0;
        }
        // SAFETY: `f` is live.
        let choice = unsafe { (*f).ipAddressChoice };
        if choice.is_null() {
            return 0;
        }
        // SAFETY: `choice` is live.
        match unsafe { (*choice).type_ } {
            IPAddressChoice_inherit => {
                i += 1;
                continue;
            }
            IPAddressChoice_addressesOrRanges => {}
            _ => return 0,
        }
        // SAFETY: `f` is live.
        if unsafe { ip_address_family_check_len(f) } == 0 {
            return 0;
        }
        // SAFETY: the list arm is live under the selector.
        let aors = unsafe { (*choice).u.cast::<OpenSslStack>() };
        // SAFETY: `aors` is a live stack.
        if unsafe { OPENSSL_sk_num(aors) } == 0 {
            return 0;
        }
        let mut j: c_int = 0;
        // SAFETY: `aors` is a live non-empty stack.
        while j < unsafe { OPENSSL_sk_num(aors) } - 1 {
            // SAFETY: `j` and `j + 1` are in bounds.
            let a = unsafe { OPENSSL_sk_value(aors, j) }.cast::<IpAddressOrRange>();
            // SAFETY: as above.
            let b = unsafe { OPENSSL_sk_value(aors, j + 1) }.cast::<IpAddressOrRange>();
            // SAFETY: both elements are live; the arrays are writable locals.
            if unsafe {
                extract_min_max(a, a_min.as_mut_ptr(), a_max.as_mut_ptr(), length) == 0
                    || extract_min_max(b, b_min.as_mut_ptr(), b_max.as_mut_ptr(), length) == 0
            } {
                return 0;
            }
            // SAFETY: the four arrays have `length` readable bytes.
            if unsafe {
                memcmp(
                    a_min.as_ptr().cast::<c_void>(),
                    b_min.as_ptr().cast::<c_void>(),
                    length as usize,
                ) >= 0
                    || memcmp(
                        a_min.as_ptr().cast::<c_void>(),
                        a_max.as_ptr().cast::<c_void>(),
                        length as usize,
                    ) > 0
                    || memcmp(
                        b_min.as_ptr().cast::<c_void>(),
                        b_max.as_ptr().cast::<c_void>(),
                        length as usize,
                    ) > 0
            } {
                return 0;
            }
            // Adjacency is tested by subtracting one from `b_min` first.
            let mut k = length - 1;
            while k >= 0 {
                let idx = k as usize;
                let old = b_min[idx];
                b_min[idx] = old.wrapping_sub(1);
                if old != 0 {
                    break;
                }
                k -= 1;
            }
            // SAFETY: both arrays have `length` readable bytes.
            if unsafe {
                memcmp(
                    a_max.as_ptr().cast::<c_void>(),
                    b_min.as_ptr().cast::<c_void>(),
                    length as usize,
                )
            } >= 0
            {
                return 0;
            }
            // SAFETY: `a` is a live element.
            if unsafe { (*a).type_ } == IPAddressOrRange_addressRange
                // SAFETY: both arrays have `length` readable bytes.
                && unsafe { range_should_be_prefix(a_min.as_ptr(), a_max.as_ptr(), length) } >= 0
            {
                return 0;
            }
            j += 1;
        }

        // The final element must not be inverted or prefix-collapsible.
        // SAFETY: `aors` is a live non-empty stack.
        let j = unsafe { OPENSSL_sk_num(aors) } - 1;
        // SAFETY: `j` is in bounds.
        let a = unsafe { OPENSSL_sk_value(aors, j) }.cast::<IpAddressOrRange>();
        // SAFETY: `a` is non-null and live on this arm.
        if !a.is_null() && unsafe { (*a).type_ } == IPAddressOrRange_addressRange {
            // SAFETY: `a` is live; the arrays are writable locals.
            if unsafe { extract_min_max(a, a_min.as_mut_ptr(), a_max.as_mut_ptr(), length) } == 0 {
                return 0;
            }
            // SAFETY: both arrays have `length` readable bytes.
            if unsafe { memcmp(a_min.as_ptr().cast::<c_void>(), a_max.as_ptr().cast::<c_void>(), length as usize) } > 0
                // SAFETY: both arrays have `length` readable bytes.
                || unsafe { range_should_be_prefix(a_min.as_ptr(), a_max.as_ptr(), length) } >= 0
            {
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// `static int IPAddressOrRanges_canonize(IPAddressOrRanges *aors, const unsigned afi)` —
/// `crypto/x509/v3_addr.c:812-884`.
///
/// # Safety
///
/// `aors` is a live stack carrying the AFI's comparator.
unsafe fn ip_address_or_ranges_canonize(aors: *mut OpenSslStack, afi: c_uint) -> c_int {
    let length = length_from_afi(afi);

    // SAFETY: `aors` is a live stack.
    unsafe { OPENSSL_sk_sort(aors) };

    let mut i: c_int = 0;
    // SAFETY: `aors` is a live stack.
    while i < unsafe { OPENSSL_sk_num(aors) } - 1 {
        // SAFETY: `i` and `i + 1` are in bounds.
        let a = unsafe { OPENSSL_sk_value(aors, i) }.cast::<IpAddressOrRange>();
        // SAFETY: as above.
        let b = unsafe { OPENSSL_sk_value(aors, i + 1) }.cast::<IpAddressOrRange>();
        let mut a_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
        let mut a_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];
        let mut b_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
        let mut b_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];

        // SAFETY: both elements are live; the arrays are writable locals.
        if unsafe {
            extract_min_max(a, a_min.as_mut_ptr(), a_max.as_mut_ptr(), length) == 0
                || extract_min_max(b, b_min.as_mut_ptr(), b_max.as_mut_ptr(), length) == 0
        } {
            return 0;
        }
        // SAFETY: the four arrays have `length` readable bytes.
        if unsafe {
            memcmp(
                a_min.as_ptr().cast::<c_void>(),
                a_max.as_ptr().cast::<c_void>(),
                length as usize,
            ) > 0
                || memcmp(
                    b_min.as_ptr().cast::<c_void>(),
                    b_max.as_ptr().cast::<c_void>(),
                    length as usize,
                ) > 0
        } {
            return 0;
        }
        // SAFETY: both arrays have `length` readable bytes.
        if unsafe {
            memcmp(
                a_max.as_ptr().cast::<c_void>(),
                b_min.as_ptr().cast::<c_void>(),
                length as usize,
            )
        } >= 0
        {
            return 0;
        }
        // Adjacency is tested by subtracting one from `b_min` first.
        let mut j = length - 1;
        while j >= 0 {
            let idx = j as usize;
            let old = b_min[idx];
            b_min[idx] = old.wrapping_sub(1);
            if old != 0 {
                break;
            }
            j -= 1;
        }
        // SAFETY: both arrays have `length` readable bytes.
        if unsafe {
            memcmp(
                a_max.as_ptr().cast::<c_void>(),
                b_min.as_ptr().cast::<c_void>(),
                length as usize,
            )
        } == 0
        {
            let mut merged: *mut IpAddressOrRange = ptr::null_mut();
            // SAFETY: `merged` is a writable slot; the bounds are `length` bytes.
            if unsafe {
                make_addressRange(
                    &raw mut merged,
                    a_min.as_mut_ptr(),
                    b_max.as_mut_ptr(),
                    length,
                )
            } == 0
            {
                return 0;
            }
            // SAFETY: `aors` is live; `merged` replaces element `i`.
            unsafe { OPENSSL_sk_set(aors, i, merged.cast::<c_void>()) };
            // SAFETY: `aors` is live and `i + 1` is in bounds.
            unsafe { OPENSSL_sk_delete(aors, i + 1) };
            // SAFETY: `a` and `b` are live elements this call owns after the delete.
            unsafe {
                IPAddressOrRange_free(a);
                IPAddressOrRange_free(b);
            }
            // `--i; continue;` re-tests the same index after the list shrank.
            continue;
        }
        i += 1;
    }

    // The final element must not be inverted.
    // SAFETY: `aors` is a live stack.
    let j = unsafe { OPENSSL_sk_num(aors) } - 1;
    // SAFETY: `j` is in bounds.
    let a = unsafe { OPENSSL_sk_value(aors, j) }.cast::<IpAddressOrRange>();
    // SAFETY: `a` is non-null and live on this arm.
    if !a.is_null() && unsafe { (*a).type_ } == IPAddressOrRange_addressRange {
        let mut a_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
        let mut a_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];
        // SAFETY: `a` is live; the arrays are writable locals.
        if unsafe { extract_min_max(a, a_min.as_mut_ptr(), a_max.as_mut_ptr(), length) } == 0 {
            return 0;
        }
        // SAFETY: both arrays have `length` readable bytes.
        if unsafe {
            memcmp(
                a_min.as_ptr().cast::<c_void>(),
                a_max.as_ptr().cast::<c_void>(),
                length as usize,
            )
        } > 0
        {
            return 0;
        }
    }
    1
}

/// `int X509v3_addr_canonize(IPAddrBlocks *addr)` — `crypto/x509/v3_addr.c:889-912`.
///
/// # Safety
///
/// `addr` is NULL or a live `STACK_OF(IPAddressFamily)`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_canonize(addr: *mut OpenSslStack) -> c_int {
    if addr.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_ADDR_894) };
        return 0;
    }

    let mut i: c_int = 0;
    // SAFETY: `addr` is a live stack.
    while i < unsafe { OPENSSL_sk_num(addr) } {
        // SAFETY: `i` is in bounds.
        let f = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: `f` is live.
        if unsafe { ip_address_family_check_len(f) } == 0 {
            return 0;
        }
        // SAFETY: `f` is live and its choice is live.
        let choice = unsafe { (*f).ipAddressChoice };
        // SAFETY: `choice` is live.
        if unsafe { (*choice).type_ } == IPAddressChoice_addressesOrRanges
            // SAFETY: the list arm is live under the selector; `f` is live.
            && unsafe {
                ip_address_or_ranges_canonize(
                    (*choice).u.cast::<OpenSslStack>(),
                    X509v3_addr_get_afi(f),
                )
            } == 0
        {
            return 0;
        }
        i += 1;
    }
    // SAFETY: `addr` is a live stack.
    unsafe { OPENSSL_sk_set_cmp_func(addr, Some(ip_address_family_cmp)) };
    // SAFETY: `addr` is a live stack.
    unsafe { OPENSSL_sk_sort(addr) };
    // `ossl_assert(X509v3_addr_is_canonical(addr))` under `NDEBUG` returns its argument.
    // SAFETY: `addr` is a live stack.
    if unsafe { X509v3_addr_is_canonical(addr) } == 0 {
        return 0;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The config callback — `v3_addr.c:917-1082`.
// ---------------------------------------------------------------------------------------------

/// `strspn(s, accept)` — the C library's, over a NUL-terminated string (the accept sets here are
/// the digits, the space/tab pair and the address-character sets the callback builds).
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

/// `static void *v2i_IPAddrBlocks(const struct v3_ext_method *method, struct v3_ext_ctx *ctx,
/// STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_addr.c:917-1082`.
///
/// Reads `name:value` pairs naming `IPv4`/`IPv6`/`IPv4-SAFI`/`IPv6-SAFI`, each value an inherited
/// list, a prefix, a range or a bare address, then canonizes the result.
///
/// # Safety
///
/// `values` is a live `STACK_OF(CONF_VALUE)`.
unsafe extern "C" fn v2i_IPAddrBlocks(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    values: *mut OpenSslStack,
) -> *mut c_void {
    const V4ADDR_CHARS: &[u8] = b"0123456789.";
    const V6ADDR_CHARS: &[u8] = b"0123456789.:abcdefABCDEF";

    let mut s: *mut c_char = ptr::null_mut();
    let mut t: *mut c_char = ptr::null_mut();

    // SAFETY: `ip_address_family_cmp` is the comparator for this element type.
    let addr = OPENSSL_sk_new(Some(ip_address_family_cmp));
    if addr.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_ADDR_928) };
        return ptr::null_mut();
    }

    // SAFETY: `values` is a live stack per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(values) };
    let mut i: c_int = 0;
    let ok = 'each: {
        while i < num {
            // SAFETY: `values` is live and `i` is in bounds.
            let val = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
            let mut min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
            let mut max = [0 as c_uchar; ADDR_RAW_BUF_LEN];
            let mut safi_storage: c_uint = 0;
            let mut safi_mut: *mut c_uint = ptr::null_mut();

            // SAFETY: `val` is live per the stack contract.
            let name = unsafe { (*val).name };
            let afi: c_uint;
            // SAFETY: `name` is NUL-terminated; each literal is static.
            if unsafe { ossl_v3_name_cmp(name, c"IPv4".as_ptr()) } == 0 {
                afi = IANA_AFI_IPV4;
            // SAFETY: as above.
            } else if unsafe { ossl_v3_name_cmp(name, c"IPv6".as_ptr()) } == 0 {
                afi = IANA_AFI_IPV6;
            // SAFETY: as above.
            } else if unsafe { ossl_v3_name_cmp(name, c"IPv4-SAFI".as_ptr()) } == 0 {
                afi = IANA_AFI_IPV4;
                safi_mut = &raw mut safi_storage;
            // SAFETY: as above.
            } else if unsafe { ossl_v3_name_cmp(name, c"IPv6-SAFI".as_ptr()) } == 0 {
                afi = IANA_AFI_IPV6;
                safi_mut = &raw mut safi_storage;
            } else {
                // SAFETY: the site is a compiled-in constant and `name` is NUL-terminated.
                unsafe { raise_site_data(&V3_ADDR_950, name) };
                break 'each false;
            }

            let addr_chars: &[u8] = if afi == IANA_AFI_IPV4 {
                V4ADDR_CHARS
            } else {
                V6ADDR_CHARS
            };
            let length = length_from_afi(afi);

            if !safi_mut.is_null() {
                // SAFETY: `val` is live.
                let value = unsafe { (*val).value };
                if value.is_null() {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_ADDR_972) };
                    break 'each false;
                }
                // SAFETY: `value` is NUL-terminated; `&raw mut t` is a writable slot.
                let parsed = unsafe { strtoul(value, &raw mut t, 0) };
                // SAFETY: `safi_mut` is the address of this frame's `safi_storage`.
                unsafe { *safi_mut = parsed as c_uint };
                // SAFETY: `t` points into `value`.
                t = unsafe { t.add(strspn(t, b" \t")) };
                // SAFETY: `safi_mut` and `t` are as above.
                let bad = unsafe { *safi_mut } > 0xFF || {
                    // SAFETY: `t` points at a readable byte in `value`.
                    let c = unsafe { *t };
                    // SAFETY: `t` may step to the terminator, still in `value`.
                    t = unsafe { t.add(1) };
                    c != b':' as c_char
                };
                if bad {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_ADDR_978) };
                    // SAFETY: `val` is live per the stack contract.
                    unsafe { conf_add_error_name_value(val) };
                    break 'each false;
                }
                // SAFETY: `t` points into `value`.
                t = unsafe { t.add(strspn(t, b" \t")) };
                // SAFETY: `t` is NUL-terminated; the file/line are this unit's.
                s = unsafe { CRYPTO_strdup(t, FILE.as_ptr(), LINE_V2I_STRDUP_SAFI) };
            } else {
                // SAFETY: `val` is live; `val->value` is NUL-terminated.
                let value = unsafe { (*val).value };
                // SAFETY: `value` is NUL-terminated; the file/line are this unit's.
                s = unsafe { CRYPTO_strdup(value, FILE.as_ptr(), LINE_V2I_STRDUP) };
            }
            if s.is_null() {
                break 'each false;
            }

            // SAFETY: `s` is NUL-terminated; the literal is static.
            if unsafe { strcmp(s, c"inherit".as_ptr()) } == 0 {
                // SAFETY: `addr` is live; `safi_mut` is NULL or this frame's storage.
                if unsafe { X509v3_addr_add_inherit(addr, afi, safi_mut) } == 0 {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_ADDR_996) };
                    // SAFETY: `val` is live per the stack contract.
                    unsafe { conf_add_error_name_value(val) };
                    break 'each false;
                }
                // SAFETY: `s` is this call's own allocation.
                unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_V2I_FREE_INHERIT) };
                s = ptr::null_mut();
                i += 1;
                continue;
            }

            // SAFETY: `s` is NUL-terminated; `addr_chars` is a static byte set.
            let mut i1 = unsafe { strspn(s, addr_chars) } as c_int;
            // SAFETY: `s.add(i1)` points into `s`'s buffer.
            let mut i2 = i1 + unsafe { strspn(s.add(i1 as usize), b" \t") } as c_int;
            // SAFETY: `i2` indexes within `s` (bounded by its NUL).
            let delim = unsafe { *s.add(i2 as usize) } as u8;
            i2 += 1;
            // SAFETY: `i1` indexes within `s`.
            unsafe { *s.add(i1 as usize) = 0 };

            // SAFETY: `min` has 16 writable bytes; `s` is NUL-terminated.
            if unsafe { ossl_a2i_ipadd(min.as_mut_ptr(), s) } != length {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_ADDR_1011) };
                // SAFETY: `val` is live per the stack contract.
                unsafe { conf_add_error_name_value(val) };
                break 'each false;
            }

            match delim {
                b'/' => {
                    // SAFETY: `s.add(i2)` is NUL-terminated; `&raw mut t` is writable.
                    let prefixlen = unsafe { strtoul(s.add(i2 as usize), &raw mut t, 10) } as c_int;
                    // SAFETY: `t` and `s.add(i2)` point into `s`.
                    let (at_start, tc) = unsafe { (t == s.add(i2 as usize), *t) };
                    if at_start || tc != 0 || prefixlen > length * 8 || prefixlen < 0 {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1023) };
                        // SAFETY: `val` is live per the stack contract.
                        unsafe { conf_add_error_name_value(val) };
                        break 'each false;
                    }
                    // SAFETY: `addr` is live; `min` has 16 readable bytes; `safi_mut` is NULL or
                    // this frame's storage.
                    if unsafe {
                        X509v3_addr_add_prefix(addr, afi, safi_mut, min.as_mut_ptr(), prefixlen)
                    } == 0
                    {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1028) };
                        break 'each false;
                    }
                }
                b'-' => {
                    // SAFETY: `s.add(i2)` points at a readable byte in `s`.
                    i1 = i2 + unsafe { strspn(s.add(i2 as usize), b" \t") } as c_int;
                    // SAFETY: `s.add(i1)` points at a readable byte in `s`.
                    i2 = i1 + unsafe { strspn(s.add(i1 as usize), addr_chars) } as c_int;
                    // SAFETY: `i2` indexes within `s`.
                    if i1 == i2 || unsafe { *s.add(i2 as usize) } != 0 {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1036) };
                        // SAFETY: `val` is live per the stack contract.
                        unsafe { conf_add_error_name_value(val) };
                        break 'each false;
                    }
                    // SAFETY: `max` has 16 writable bytes; `s.add(i1)` is a NUL-terminated suffix.
                    if unsafe { ossl_a2i_ipadd(max.as_mut_ptr(), s.add(i1 as usize)) } != length {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1041) };
                        // SAFETY: `val` is live per the stack contract.
                        unsafe { conf_add_error_name_value(val) };
                        break 'each false;
                    }
                    // SAFETY: both arrays have 16 readable bytes; `length` is 4 or 16.
                    if unsafe {
                        memcmp(
                            min.as_ptr().cast::<c_void>(),
                            max.as_ptr().cast::<c_void>(),
                            length_from_afi(afi) as usize,
                        )
                    } > 0
                    {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1046) };
                        // SAFETY: `val` is live per the stack contract.
                        unsafe { conf_add_error_name_value(val) };
                        break 'each false;
                    }
                    // SAFETY: `addr` is live; both bounds are 16 readable bytes.
                    if unsafe {
                        X509v3_addr_add_range(
                            addr,
                            afi,
                            safi_mut,
                            min.as_mut_ptr(),
                            max.as_mut_ptr(),
                        )
                    } == 0
                    {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1051) };
                        break 'each false;
                    }
                }
                0 => {
                    // SAFETY: `addr` is live; `min` has 16 readable bytes.
                    if unsafe {
                        X509v3_addr_add_prefix(addr, afi, safi_mut, min.as_mut_ptr(), length * 8)
                    } == 0
                    {
                        // SAFETY: the site is a compiled-in constant.
                        unsafe { raise_site(&V3_ADDR_1057) };
                        break 'each false;
                    }
                }
                _ => {
                    // SAFETY: the site is a compiled-in constant.
                    unsafe { raise_site(&V3_ADDR_1062) };
                    // SAFETY: `val` is live per the stack contract.
                    unsafe { conf_add_error_name_value(val) };
                    break 'each false;
                }
            }

            // SAFETY: `s` is this call's own allocation.
            unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_V2I_FREE) };
            s = ptr::null_mut();
            i += 1;
        }
        // SAFETY: `addr` is a live stack.
        if unsafe { X509v3_addr_canonize(addr) } == 0 {
            break 'each false;
        }
        true
    };

    if !ok {
        // SAFETY: `s` is NULL or this call's own allocation.
        unsafe { CRYPTO_free(s.cast::<c_void>(), FILE.as_ptr(), LINE_V2I_ERR_FREE) };
        // SAFETY: `addr` is live and owns its elements; the thunk frees each.
        unsafe { OPENSSL_sk_pop_free(addr, Some(ip_address_family_free_void)) };
        return ptr::null_mut();
    }
    addr.cast::<c_void>()
}

// ---------------------------------------------------------------------------------------------
// Inheritance, containment and the row — `v3_addr.c:1087-1185`.
// ---------------------------------------------------------------------------------------------

/// `int X509v3_addr_inherits(IPAddrBlocks *addr)` — `crypto/x509/v3_addr.c:1104-1117`.
///
/// # Safety
///
/// `addr` is NULL or a live `STACK_OF(IPAddressFamily)`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_inherits(addr: *mut OpenSslStack) -> c_int {
    if addr.is_null() {
        return 0;
    }
    let mut i: c_int = 0;
    // SAFETY: `addr` is a live stack.
    while i < unsafe { OPENSSL_sk_num(addr) } {
        // SAFETY: `i` is in bounds.
        let f = unsafe { OPENSSL_sk_value(addr, i) }.cast::<IpAddressFamily>();
        // SAFETY: `f` is live and its choice is live.
        if unsafe { (*(*f).ipAddressChoice).type_ } == IPAddressChoice_inherit {
            return 1;
        }
        i += 1;
    }
    0
}

/// `static int addr_contains(IPAddressOrRanges *parent, IPAddressOrRanges *child, int length)` —
/// `crypto/x509/v3_addr.c:1122-1154`.
///
/// # Safety
///
/// `parent` and `child` are NULL or live `IPAddressOrRanges` stacks in ascending canonical form;
/// `length` is 4 or 16.
unsafe fn addr_contains(
    parent: *mut OpenSslStack,
    child: *mut OpenSslStack,
    length: c_int,
) -> c_int {
    let mut p_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut p_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut c_min = [0 as c_uchar; ADDR_RAW_BUF_LEN];
    let mut c_max = [0 as c_uchar; ADDR_RAW_BUF_LEN];

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
        let ce = unsafe { OPENSSL_sk_value(child, c) }.cast::<IpAddressOrRange>();
        // SAFETY: `ce` is live; the arrays are writable locals.
        if unsafe { extract_min_max(ce, c_min.as_mut_ptr(), c_max.as_mut_ptr(), length) } == 0 {
            return 0;
        }
        loop {
            // SAFETY: `parent` is a live stack.
            if p >= unsafe { OPENSSL_sk_num(parent) } {
                return 0;
            }
            // SAFETY: `p` is in bounds.
            let pe = unsafe { OPENSSL_sk_value(parent, p) }.cast::<IpAddressOrRange>();
            // SAFETY: `pe` is live; the arrays are writable locals.
            if unsafe { extract_min_max(pe, p_min.as_mut_ptr(), p_max.as_mut_ptr(), length) } == 0 {
                return 0;
            }
            // SAFETY: both arrays have `length` readable bytes.
            if unsafe {
                memcmp(
                    p_max.as_ptr().cast::<c_void>(),
                    c_max.as_ptr().cast::<c_void>(),
                    length as usize,
                )
            } < 0
            {
                p += 1;
                continue;
            }
            // SAFETY: both arrays have `length` readable bytes.
            if unsafe {
                memcmp(
                    p_min.as_ptr().cast::<c_void>(),
                    c_min.as_ptr().cast::<c_void>(),
                    length as usize,
                )
            } > 0
            {
                return 0;
            }
            break;
        }
        c += 1;
    }
    1
}

/// `int X509v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b)` — `crypto/x509/v3_addr.c:1159-1185`.
///
/// # Safety
///
/// `a` and `b` are NULL or live `STACK_OF(IPAddressFamily)`.
#[no_mangle]
pub unsafe extern "C" fn X509v3_addr_subset(a: *mut OpenSslStack, b: *mut OpenSslStack) -> c_int {
    if a.is_null() || a == b {
        return 1;
    }
    // A NULL `b` is not a subset.
    if b.is_null() {
        return 0;
    }
    // SAFETY: `a` is non-null (checked above) and `b` was just checked.
    if unsafe { X509v3_addr_inherits(a) != 0 || X509v3_addr_inherits(b) != 0 } {
        return 0;
    }
    // SAFETY: `b` is a live stack; the comparator is over its element type.
    unsafe { OPENSSL_sk_set_cmp_func(b, Some(ip_address_family_cmp)) };
    // SAFETY: `b` is a live stack.
    unsafe { OPENSSL_sk_sort(b) };
    let mut i: c_int = 0;
    // SAFETY: `a` is a live stack.
    while i < unsafe { OPENSSL_sk_num(a) } {
        // SAFETY: `i` is in bounds.
        let fa = unsafe { OPENSSL_sk_value(a, i) }.cast::<IpAddressFamily>();
        // SAFETY: `b` is live; `fa` is a live element.
        let j = unsafe { OPENSSL_sk_find(b, fa.cast::<c_void>()) };
        // SAFETY: `j` may be -1 (yielding NULL) or in bounds.
        let fb = unsafe { OPENSSL_sk_value(b, j) }.cast::<IpAddressFamily>();
        if fb.is_null() {
            return 0;
        }
        // SAFETY: both are live address families.
        if unsafe { ip_address_family_check_len(fa) == 0 || ip_address_family_check_len(fb) == 0 } {
            return 0;
        }
        // SAFETY: both choices are live under their selectors.
        if unsafe {
            addr_contains(
                (*(*fb).ipAddressChoice).u.cast::<OpenSslStack>(),
                (*(*fa).ipAddressChoice).u.cast::<OpenSslStack>(),
                length_from_afi(X509v3_addr_get_afi(fb)),
            )
        } == 0
        {
            return 0;
        }
        i += 1;
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_addr` — `crypto/x509/v3_addr.c:1087-1099`.
///
/// One row: `ext_nid` is `NID_sbgp_ipAddrBlock`, `it` is `ASN1_ITEM_ref(IPAddrBlocks)`, `v2i` is
/// `v2i_IPAddrBlocks`, `i2r` is `i2r_IPAddrBlocks`; every other slot is zero.
pub static ossl_v3_addr: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_sbgp_ipAddrBlock,
    ext_flags: 0,
    it: Some(IPAddrBlocks_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_IPAddrBlocks),
    i2r: Some(i2r_IPAddrBlocks),
    r2i: None,
    usr_data: ptr::null_mut(),
};
