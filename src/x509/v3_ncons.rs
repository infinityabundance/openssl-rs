//! `crypto/x509/v3_ncons.c` — the RFC 5280 `NAME_CONSTRAINTS` item group, its two exported check
//! entry points and the three `standard_exts[]` rows. Phase 10.14.4's table layer, landed whole.
//!
//! `crypto/x509/v3_ncons.c` is 862 lines and transcribes as follows:
//!
//! * The two ASN.1 templates (`:77-88`) land: `GENERAL_SUBTREE ::= SEQUENCE { base GENERAL_NAME,
//!   minimum [0] IMPLICIT INTEGER OPTIONAL, maximum [1] IMPLICIT INTEGER OPTIONAL }` and
//!   `NAME_CONSTRAINTS ::= SEQUENCE { permittedSubtrees [0] IMPLICIT SEQUENCE OF GENERAL_SUBTREE
//!   OPTIONAL, excludedSubtrees [1] IMPLICIT SEQUENCE OF GENERAL_SUBTREE OPTIONAL }`, with the
//!   `_it`/`_new`/`_free` group `ASN1_SEQUENCE_END` plus `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` emits
//!   (`:90-91`). Both groups are public exports (`x509v3.h:898-902`); the header declares no
//!   `d2i_`/`i2d_` for either, so the item group here is the allocator half plus `_it`.
//! * The printers land: `i2r_NAME_CONSTRAINTS` (`:202-213`, the rows' `i2r`),
//!   `do_i2r_name_constraints` (`:215-234`) and `print_nc_ipadd` (`:236-250`).
//! * The config callback `v2i_NAME_CONSTRAINTS` (`:148-200`, the rows' `v2i`) lands.
//! * The string helpers land: `ia5memrchr` (`:102-113`) and `ia5ncasecmp` (`:122-146`).
//! * The check surface lands: the two length guards `safe_add_int` (the `OSSL_SAFE_MATH_SIGNED(int,
//!   int)` expansion at `:25`) and `add_lengths` (`:254-266`), `cn2dnsid` (`:341-432`),
//!   `nc_minmax_valid` (`:483-499`), `nc_match` (`:501-561`), `nc_match_single` (`:563-599`),
//!   `nc_dn` (`:607-625`), `nc_dns` (`:627-653`), `nc_email_eai` (`:662-730`), `nc_email`
//!   (`:732-775`), `nc_uri` (`:777-832`) and `nc_ip` (`:834-862`), and the two exported entry
//!   points `NAME_CONSTRAINTS_check` (`:280-339`) and `NAME_CONSTRAINTS_check_CN` (`:437-477`).
//! * The three rows land: [`ossl_v3_name_constraints`] (`:47-55`),
//!   [`ossl_v3_holder_name_constraints`] (`:57-65`) and [`ossl_v3_delegated_name_constraints`]
//!   (`:67-75`). All three carry `it` `ASN1_ITEM_ref(NAME_CONSTRAINTS)`, `v2i`
//!   [`v2i_NAME_CONSTRAINTS`] and `i2r` [`i2r_NAME_CONSTRAINTS`]; every other slot is zero. Their
//!   `ext_nid`s are `NID_name_constraints` / `NID_holder_name_constraints` /
//!   `NID_delegated_name_constraints`.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456), so the array is the last thing to land, not the first; this unit contributes three of
//! the 63 tables (rows `standard_exts.h:59`, `:78`, `:93`). The rows are internal data the admitted
//! DSO does not export (`nm -D` shows no `ossl_v3_*`), so no court can name them; the drivable
//! surface is the two exported item groups and the two `NAME_CONSTRAINTS_check*` entry points.
//!
//! **No other name is withheld.** Unlike `v3_asid.c`/`v3_addr.c`, this unit has no path-validation
//! surface: it references no `X509_STORE_CTX` and no `validation_err` macro, so nothing here waits
//! on the unlanded store context.
//!
//! ## Naming divergence
//!
//! `safe_add_int` is the `OSSL_SAFE_MATH_SIGNED(int, int)` macro expansion at `v3_ncons.c:25`
//! (`internal/safe_math.h:415-430`), which the authority emits *into this translation unit*; it is
//! not a crate-level helper. It is transcribed here as the builtin-overflow variant
//! (`internal/safe_math.h:34-45`), the one the admitted gcc/clang profile selects, using
//! `checked_add`.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_ncons.c` is not an entry in `gen_err_raise_sites.py`, so its six coordinates are
//! **declared locally**, their reason values read from the authority's `err.h.in`/`x509v3err.h`
//! (not typed from memory), as `v3_bitst.rs` does. `ERR_LIB_X509V3` is `err.h.in:99`; the three
//! `ERR_R_*_LIB` composite reasons are the `err.h.in` rows `:328`/`:330`/`:335`;
//! `X509V3_R_INVALID_SYNTAX` is the `x509v3err.h` row `:64`; and `nc_uri`'s one `ERR_raise_data`
//! uses the X.509 verify code `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX` (`x509_vfy.h.in:271`) as its
//! reason.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr};
use core::ptr;

use crate::asn1::a_strex::ASN1_STRING_to_UTF8;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::bn::bignum::{BN_free, BN_is_zero};
use crate::http::http_lib::OSSL_parse_url;
use crate::punycode::ossl_a2ulabel;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{memchr, memcmp, strlen, strncmp};
use crate::runtime::bio::Bio;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_INVALID_SYNTAX;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strndup};
use crate::runtime::obj::{
    NID_commonName, NID_delegated_name_constraints, NID_holder_name_constraints,
    NID_id_on_SmtpUTF8Mailbox, NID_name_constraints, NID_pkcs9_emailAddress, OBJ_cmp, OBJ_obj2nid,
};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_conf::X509V3Ctx;
use crate::x509::v3_genn::{
    GENERAL_NAME_it, GeneralName, GEN_DIRNAME, GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_OTHERNAME,
    GEN_URI,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::{v2i_GENERAL_NAME_ex, GENERAL_NAME_print};
use crate::x509::v3_utl::ossl_ipaddr_to_asc;
use crate::x509::x509_cmp::X509_get_subject_name;
use crate::x509::x509name::{
    X509_NAME_ENTRY_get_data, X509_NAME_entry_count, X509_NAME_get_entry,
    X509_NAME_get_index_by_NID,
};
use crate::x509::x_name::{i2d_X509_NAME, X509Name};
use crate::x509::x_x509::X509;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in:328`, `ERR_LIB_ASN1 | ERR_RFLAG_COMMON`
/// (`13 | 0x80000`).
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_CRYPTO_LIB` — `include/openssl/err.h.in:330`, `ERR_LIB_CRYPTO | ERR_RFLAG_COMMON`
/// (`15 | 0x80000`).
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_X509V3_LIB` — `include/openssl/err.h.in:335`, `ERR_LIB_X509V3 | ERR_RFLAG_COMMON`
/// (`34 | 0x80000`).
const ERR_R_X509V3_LIB: c_int = 524322;

/// `X509_V_OK` — `include/openssl/x509_vfy.h.in:215`.
const X509_V_OK: c_int = 0;
/// `X509_V_ERR_UNSPECIFIED` — `include/openssl/x509_vfy.h.in:216`.
const X509_V_ERR_UNSPECIFIED: c_int = 1;
/// `X509_V_ERR_OUT_OF_MEM` — `include/openssl/x509_vfy.h.in:232`.
const X509_V_ERR_OUT_OF_MEM: c_int = 17;
/// `X509_V_ERR_PERMITTED_VIOLATION` — `include/openssl/x509_vfy.h.in:264`.
const X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
/// `X509_V_ERR_EXCLUDED_VIOLATION` — `include/openssl/x509_vfy.h.in:265`.
const X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
/// `X509_V_ERR_SUBTREE_MINMAX` — `include/openssl/x509_vfy.h.in:266`.
const X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
/// `X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE` — `include/openssl/x509_vfy.h.in:269`.
const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
/// `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX` — `include/openssl/x509_vfy.h.in:271`.
const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;

/// `OPENSSL_FILE` for this unit's `OPENSSL_strndup`/`OPENSSL_free` expansions —
/// `crypto/x509/v3_ncons.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_ncons.c";
/// `print_nc_ipadd`'s `OPENSSL_free(ip1)` (`v3_ncons.c:247`).
const LINE_FREE_IP1: c_int = 247;
/// The same function's `OPENSSL_free(ip2)` (`v3_ncons.c:248`).
const LINE_FREE_IP2: c_int = 248;
/// `cn2dnsid`'s `OPENSSL_free(utf8_value)` on the embedded-NUL rejection (`v3_ncons.c:382`).
const LINE_FREE_UTF8_EMBEDDED: c_int = 382;
/// The same function's `OPENSSL_free(utf8_value)` when the name is not a DNS-ID (`v3_ncons.c:430`).
const LINE_FREE_UTF8_NOTDNS: c_int = 430;
/// `NAME_CONSTRAINTS_check_CN`'s `OPENSSL_free(idval)` (`v3_ncons.c:472`).
const LINE_FREE_IDVAL: c_int = 472;
/// `nc_email_eai`'s `OPENSSL_strndup((char *)base->data, base->length)` (`v3_ncons.c:678`).
const LINE_STRNDUP_BASE: c_int = 678;
/// The same function's `OPENSSL_free(baseptr)` (`v3_ncons.c:728`).
const LINE_FREE_BASEPTR: c_int = 728;
/// `nc_uri`'s `OPENSSL_strndup((const char *)uri->data, uri->length)` (`v3_ncons.c:786`).
const LINE_STRNDUP_URI: c_int = 786;
/// The same function's `OPENSSL_free(uri_copy)` on the `OSSL_parse_url` failure arm
/// (`v3_ncons.c:790`).
const LINE_FREE_URI_COPY_PARSE: c_int = 790;
/// The same function's `OPENSSL_free(scheme)` on the missing-scheme arm (`v3_ncons.c:798`).
const LINE_FREE_SCHEME_MISSING: c_int = 798;
/// The same function's `OPENSSL_free(uri_copy)` on the missing-scheme arm (`v3_ncons.c:799`).
const LINE_FREE_URI_COPY_MISSING: c_int = 799;
/// The same function's `OPENSSL_free(scheme)` on the success path (`v3_ncons.c:805`).
const LINE_FREE_SCHEME: c_int = 805;
/// The same function's `OPENSSL_free(uri_copy)` on the success path (`v3_ncons.c:806`).
const LINE_FREE_URI_COPY: c_int = 806;
/// The same function's `OPENSSL_free(host)` at the `end:` label (`v3_ncons.c:830`).
const LINE_FREE_HOST: c_int = 830;

/// One `v3_ncons.c` raise coordinate, declared locally (see the module doc).
const fn v3_ncons_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_ncons.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_NAME_CONSTRAINTS`'s failed `NAME_CONSTRAINTS_new` at `v3_ncons.c:159`.
const V3_NCONS_159: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(159, c"v2i_NAME_CONSTRAINTS", ERR_R_ASN1_LIB);
/// `v2i_NAME_CONSTRAINTS`'s name that is neither `permitted*` nor `excluded*` at `v3_ncons.c:171`.
const V3_NCONS_171: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(171, c"v2i_NAME_CONSTRAINTS", X509V3_R_INVALID_SYNTAX);
/// `v2i_NAME_CONSTRAINTS`'s failed `GENERAL_SUBTREE_new` at `v3_ncons.c:177`.
const V3_NCONS_177: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(177, c"v2i_NAME_CONSTRAINTS", ERR_R_ASN1_LIB);
/// `v2i_NAME_CONSTRAINTS`'s failed `v2i_GENERAL_NAME_ex` at `v3_ncons.c:181`.
const V3_NCONS_181: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(181, c"v2i_NAME_CONSTRAINTS", ERR_R_X509V3_LIB);
/// `v2i_NAME_CONSTRAINTS`'s failed subtree-stack creation/push at `v3_ncons.c:187`.
const V3_NCONS_187: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(187, c"v2i_NAME_CONSTRAINTS", ERR_R_CRYPTO_LIB);
/// `nc_uri`'s missing scheme at `v3_ncons.c:796`, an `ERR_raise_data` whose reason is the X.509
/// verify code `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX`.
const V3_NCONS_796: crate::runtime::err::err_sites::ErrSite =
    v3_ncons_site(796, c"nc_uri", X509_V_ERR_UNSUPPORTED_NAME_SYNTAX);

/// `#define NAME_CHECK_MAX (1 << 20)` — `crypto/x509/v3_ncons.c:252`.
const NAME_CHECK_MAX: c_int = 1 << 20;

/// `struct GENERAL_SUBTREE_st` — `GENERAL_SUBTREE`, from `include/openssl/x509v3.h:547-551`.
#[repr(C)]
pub struct GeneralSubtree {
    /// `GENERAL_NAME *base`.
    pub base: *mut GeneralName,
    /// `ASN1_INTEGER *minimum` — `[0]` implicit, optional.
    pub minimum: *mut Asn1String,
    /// `ASN1_INTEGER *maximum` — `[1]` implicit, optional.
    pub maximum: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<GeneralSubtree>() == 24);
    assert!(core::mem::offset_of!(GeneralSubtree, base) == 0);
    assert!(core::mem::offset_of!(GeneralSubtree, minimum) == 8);
    assert!(core::mem::offset_of!(GeneralSubtree, maximum) == 16);
};

/// `struct NAME_CONSTRAINTS_st` — `NAME_CONSTRAINTS`, from `include/openssl/x509v3.h:583-586`.
#[repr(C)]
pub struct NameConstraints {
    /// `STACK_OF(GENERAL_SUBTREE) *permittedSubtrees` — `[0]` implicit, optional.
    pub permittedSubtrees: *mut OpenSslStack,
    /// `STACK_OF(GENERAL_SUBTREE) *excludedSubtrees` — `[1]` implicit, optional.
    pub excludedSubtrees: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<NameConstraints>() == 16);
    assert!(core::mem::offset_of!(NameConstraints, permittedSubtrees) == 0);
    assert!(core::mem::offset_of!(NameConstraints, excludedSubtrees) == 8);
};

/// `GENERAL_SUBTREE_seq_tt` — `ASN1_SEQUENCE(GENERAL_SUBTREE)` (`crypto/x509/v3_ncons.c:77-81`):
/// `ASN1_SIMPLE(base, GENERAL_NAME)` and two `ASN1_IMP_OPT(..., ASN1_INTEGER, n)` rows.
static GENERAL_SUBTREE_TT: [Asn1Template; 3] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"base".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"minimum".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 16,
        field_name: c"maximum".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `GENERAL_SUBTREE_it`'s descriptor — `ASN1_SEQUENCE_END(GENERAL_SUBTREE)` at
/// `crypto/x509/v3_ncons.c:81`.
static GENERAL_SUBTREE_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: GENERAL_SUBTREE_TT.as_ptr(),
    tcount: 3,
    funcs: ptr::null(),
    size: core::mem::size_of::<GeneralSubtree>() as c_long,
    sname: c"GENERAL_SUBTREE".as_ptr(),
};

/// `NAME_CONSTRAINTS_seq_tt` — `ASN1_SEQUENCE(NAME_CONSTRAINTS)` (`crypto/x509/v3_ncons.c:83-88`):
/// two `ASN1_IMP_SEQUENCE_OF_OPT(..., GENERAL_SUBTREE, n)` rows.
static NAME_CONSTRAINTS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"permittedSubtrees".as_ptr(),
        item: GENERAL_SUBTREE_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"excludedSubtrees".as_ptr(),
        item: GENERAL_SUBTREE_it as *mut c_void,
    },
];

/// `NAME_CONSTRAINTS_it`'s descriptor — `ASN1_SEQUENCE_END(NAME_CONSTRAINTS)` at
/// `crypto/x509/v3_ncons.c:88`.
static NAME_CONSTRAINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: NAME_CONSTRAINTS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<NameConstraints>() as c_long,
    sname: c"NAME_CONSTRAINTS".as_ptr(),
};

/// `const ASN1_ITEM *GENERAL_SUBTREE_it(void)` — `include/openssl/x509v3.h:898`, from
/// `DECLARE_ASN1_ITEM(GENERAL_SUBTREE)`.
#[no_mangle]
pub extern "C" fn GENERAL_SUBTREE_it() -> *const Asn1Item {
    &GENERAL_SUBTREE_ITEM
}

/// `GENERAL_SUBTREE *GENERAL_SUBTREE_new(void)` — `crypto/x509/v3_ncons.c:90`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)`.
#[no_mangle]
pub extern "C" fn GENERAL_SUBTREE_new() -> *mut GeneralSubtree {
    // SAFETY: `GENERAL_SUBTREE_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(GENERAL_SUBTREE_it()).cast::<GeneralSubtree>() }
}

/// `void GENERAL_SUBTREE_free(GENERAL_SUBTREE *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn GENERAL_SUBTREE_free(a: *mut GeneralSubtree) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), GENERAL_SUBTREE_it()) }
}

/// `const ASN1_ITEM *NAME_CONSTRAINTS_it(void)` — `include/openssl/x509v3.h:901`, from
/// `DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn NAME_CONSTRAINTS_it() -> *const Asn1Item {
    &NAME_CONSTRAINTS_ITEM
}

/// `NAME_CONSTRAINTS *NAME_CONSTRAINTS_new(void)` — `crypto/x509/v3_ncons.c:91`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn NAME_CONSTRAINTS_new() -> *mut NameConstraints {
    // SAFETY: `NAME_CONSTRAINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(NAME_CONSTRAINTS_it()).cast::<NameConstraints>() }
}

/// `void NAME_CONSTRAINTS_free(NAME_CONSTRAINTS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn NAME_CONSTRAINTS_free(a: *mut NameConstraints) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), NAME_CONSTRAINTS_it()) }
}

/// Append the bytes of a NUL-terminated C string to a byte buffer, for the one
/// `ERR_raise_data` message this unit formats. `(null)` stands in for a NULL
/// pointer, as the formatting helpers of `v3_san.rs`/`v3_addr.rs` do.
///
/// # Safety
///
/// `s` must be NULL or NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, s: *const c_char) {
    if s.is_null() {
        buf.extend_from_slice(b"(null)");
        return;
    }
    // SAFETY: `s` is NUL-terminated per the contract.
    buf.extend_from_slice(unsafe { CStr::from_ptr(s) }.to_bytes());
}

/// `static void *v2i_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_ncons.c:148-200`.
///
/// Each `CONF_VALUE` names a `permitted*` or `excluded*` subtree; its suffix is decoded as a
/// `GENERAL_NAME` with `v2i_GENERAL_NAME_ex(..., is_nc = 1)` and pushed onto the matching stack.
///
/// # Safety
///
/// `method`/`ctx` are the caller's; `nval` is a live `STACK_OF(CONF_VALUE)`.
unsafe extern "C" fn v2i_NAME_CONSTRAINTS(
    method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    // SAFETY: no preconditions; the item is the crate's own static.
    let ncons = NAME_CONSTRAINTS_new();
    if ncons.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_NCONS_159) };
        return ptr::null_mut();
    }
    let mut ptree;
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract.
        let name = unsafe { (*val).name };
        // SAFETY: `name` is NUL-terminated; the literal is static.
        let is_permitted = unsafe { strncmp(name, c"permitted".as_ptr(), 9) } == 0;
        // SAFETY: as above.
        let is_excluded = unsafe { strncmp(name, c"excluded".as_ptr(), 8) } == 0;
        let mut tval = ConfValue {
            section: ptr::null_mut(),
            name: ptr::null_mut(),
            value: ptr::null_mut(),
        };
        // SAFETY: `name` matched the 9-byte `permitted` prefix, so index 9 is in bounds.
        if is_permitted && unsafe { *name.add(9) } != 0 {
            // SAFETY: `ncons` is live and this names one of its two fields.
            ptree = unsafe { &raw mut (*ncons).permittedSubtrees };
            // SAFETY: as above; the suffix begins one byte past the prefix.
            tval.name = unsafe { name.add(10) };
        // SAFETY: `name` matched the 8-byte `excluded` prefix, so index 8 is in bounds.
        } else if is_excluded && unsafe { *name.add(8) } != 0 {
            // SAFETY: `ncons` is live and this names one of its two fields.
            ptree = unsafe { &raw mut (*ncons).excludedSubtrees };
            // SAFETY: as above; the suffix begins one byte past the prefix.
            tval.name = unsafe { name.add(9) };
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_NCONS_171) };
            // SAFETY: `ncons` is a live value this call owns.
            unsafe { NAME_CONSTRAINTS_free(ncons) };
            return ptr::null_mut();
        }
        // SAFETY: `val` is live per the stack contract.
        tval.value = unsafe { (*val).value };
        // SAFETY: no preconditions; the item is the crate's own static.
        let sub = GENERAL_SUBTREE_new();
        if sub.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_NCONS_177) };
            // SAFETY: `ncons` is a live value this call owns.
            unsafe { NAME_CONSTRAINTS_free(ncons) };
            return ptr::null_mut();
        }
        // SAFETY: `sub` is live; `sub->base` is its allocated GENERAL_NAME slot; `ctx` is the
        // caller's; `tval` is this call's own.
        if unsafe {
            v2i_GENERAL_NAME_ex(
                (*sub).base,
                method,
                ctx.cast::<X509V3Ctx>(),
                &raw mut tval,
                1,
            )
        }
        .is_null()
        {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_NCONS_181) };
            // SAFETY: `ncons`/`sub` are live values this call owns.
            unsafe {
                NAME_CONSTRAINTS_free(ncons);
                GENERAL_SUBTREE_free(sub);
            }
            return ptr::null_mut();
        }
        // SAFETY: `ptree` names one of `ncons`'s two fields.
        let stack_null = unsafe { *ptree }.is_null();
        if stack_null {
            // SAFETY: no preconditions; the stack is a fresh empty list.
            unsafe { *ptree = OPENSSL_sk_new_null() };
        }
        // SAFETY: `*ptree` is NULL or a live subtree stack; `sub` transfers on success.
        let pushed = unsafe { OPENSSL_sk_push(*ptree, sub.cast::<c_void>()) };
        // SAFETY: `ptree` names one of `ncons`'s two fields.
        if unsafe { *ptree }.is_null() || pushed == 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_NCONS_187) };
            // SAFETY: `ncons`/`sub` are live values this call owns.
            unsafe {
                NAME_CONSTRAINTS_free(ncons);
                GENERAL_SUBTREE_free(sub);
            }
            return ptr::null_mut();
        }
        i += 1;
    }
    ncons.cast::<c_void>()
}

/// `static int do_i2r_name_constraints(const X509V3_EXT_METHOD *method, STACK_OF(GENERAL_SUBTREE)
/// *trees, BIO *bp, int ind, const char *name)` — `crypto/x509/v3_ncons.c:215-234`.
///
/// # Safety
///
/// `trees` is NULL or a live `STACK_OF(GENERAL_SUBTREE)`; `bp` is a live BIO.
unsafe fn do_i2r_name_constraints(
    _method: *const X509V3ExtMethod,
    trees: *const OpenSslStack,
    bp: *mut Bio,
    ind: c_int,
    name: *const c_char,
) -> c_int {
    // SAFETY: `trees` is NULL or live per the contract.
    if unsafe { OPENSSL_sk_num(trees) } > 0 {
        // SAFETY: `bp` is live; the format and arguments are as declared.
        unsafe { BIO_printf(bp, c"%*s%s:\n".as_ptr(), ind, c"".as_ptr(), name) };
    }
    let mut i = 0;
    // SAFETY: `trees` is NULL or live per the contract.
    while i < unsafe { OPENSSL_sk_num(trees) } {
        if i > 0 {
            // SAFETY: `bp` is live and the literal is static.
            unsafe { BIO_puts(bp, c"\n".as_ptr()) };
        }
        // SAFETY: `i` is in bounds.
        let tree = unsafe { OPENSSL_sk_value(trees, i) }.cast::<GeneralSubtree>();
        // SAFETY: `bp` is live; the format and arguments are as declared.
        unsafe { BIO_printf(bp, c"%*s".as_ptr(), ind + 2, c"".as_ptr()) };
        // SAFETY: `tree` is a live element per the stack contract.
        if unsafe { (*(*tree).base).type_ } == GEN_IPADD {
            // SAFETY: the `iPAddress` arm is live under the `GEN_IPADD` selector; `bp` is live.
            unsafe { print_nc_ipadd(bp, (*(*tree).base).d.iPAddress) };
        } else {
            // SAFETY: `bp` is live and `tree->base` is a live `GENERAL_NAME`.
            unsafe { GENERAL_NAME_print(bp, (*tree).base) };
        }
        i += 1;
    }
    1
}

/// `static int print_nc_ipadd(BIO *bp, ASN1_OCTET_STRING *ip)` — `crypto/x509/v3_ncons.c:236-250`.
///
/// # Safety
///
/// `bp` is a live BIO, `ip` a live octet string.
unsafe fn print_nc_ipadd(bp: *mut Bio, ip: *mut Asn1String) -> c_int {
    // The `ip->length` field is split into an address and a mask half; the authority's own
    // comment says it should be 8 or 32 with `len1 == len2 == 4` or `16`.
    // SAFETY: `ip` is live per the contract.
    let length = unsafe { (*ip).length };
    let len1 = if length >= 16 {
        16
    } else if length >= 4 {
        4
    } else {
        length
    };
    let len2 = length - len1;
    // SAFETY: `ip` is live and `data` has `len1` readable bytes.
    let ip1 = unsafe { ossl_ipaddr_to_asc((*ip).data, len1) };
    // SAFETY: `ip` is live and `data + len1` has `len2` readable bytes.
    let ip2 = unsafe { ossl_ipaddr_to_asc((*ip).data.add(len1 as usize), len2) };
    // SAFETY: `bp` is live; `ip1`/`ip2` are NULL or NUL-terminated.
    let ret = c_int::from(
        !ip1.is_null()
            && !ip2.is_null()
            && unsafe { BIO_printf(bp, c"IP:%s/%s".as_ptr(), ip1, ip2) } > 0,
    );
    // SAFETY: `ip1` is NULL or this call's own `ossl_ipaddr_to_asc` allocation.
    unsafe { CRYPTO_free(ip1.cast(), FILE.as_ptr(), LINE_FREE_IP1) };
    // SAFETY: `ip2` is NULL or this call's own `ossl_ipaddr_to_asc` allocation.
    unsafe { CRYPTO_free(ip2.cast(), FILE.as_ptr(), LINE_FREE_IP2) };
    ret
}

/// `static int i2r_NAME_CONSTRAINTS(const X509V3_EXT_METHOD *method, void *a, BIO *bp, int ind)`
/// — `crypto/x509/v3_ncons.c:202-213`. The three rows' `i2r` callback. Always answers 1.
///
/// # Safety
///
/// `a` is a live `NAME_CONSTRAINTS`; `bp` is a live BIO.
unsafe extern "C" fn i2r_NAME_CONSTRAINTS(
    method: *const X509V3ExtMethod,
    a: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    let ncons = a.cast::<NameConstraints>();
    // SAFETY: `ncons` is live; its two stacks are per the item contract.
    unsafe {
        do_i2r_name_constraints(
            method,
            (*ncons).permittedSubtrees,
            bp,
            ind,
            c"Permitted".as_ptr(),
        )
    };
    // SAFETY: `ncons` is live per the contract.
    if unsafe { !(*ncons).permittedSubtrees.is_null() && !(*ncons).excludedSubtrees.is_null() } {
        // SAFETY: `bp` is live and the literal is static.
        unsafe { BIO_puts(bp, c"\n".as_ptr()) };
    }
    // SAFETY: `ncons` is live; its two stacks are per the item contract.
    unsafe {
        do_i2r_name_constraints(
            method,
            (*ncons).excludedSubtrees,
            bp,
            ind,
            c"Excluded".as_ptr(),
        )
    };
    1
}

/// `safe_add_int(a, b, err)` — the `OSSL_SAFE_MATH_SIGNED(int, int)` expansion at
/// `crypto/x509/v3_ncons.c:25`, builtin-overflow variant (`internal/safe_math.h:34-45`). On
/// overflow it sets `*err` and answers `INT_MIN`/`INT_MAX` by the sign of `a`, as the authority's
/// `__builtin_add_overflow` arm does.
///
/// # Safety
///
/// `err` is a live `int` slot.
unsafe fn safe_add_int(a: c_int, b: c_int, err: *mut c_int) -> c_int {
    match a.checked_add(b) {
        Some(r) => r,
        None => {
            // SAFETY: `err` is a live `int` slot per the contract.
            unsafe { *err |= 1 };
            if a < 0 {
                c_int::MIN
            } else {
                c_int::MAX
            }
        }
    }
}

/// `static int add_lengths(int *out, int a, int b)` — `crypto/x509/v3_ncons.c:254-266`. Clamps a
/// negative operand (a NULL stack's `sk_num` is `-1`) to 0, then adds with the overflow guard.
///
/// # Safety
///
/// `out` is a live `int` slot.
unsafe fn add_lengths(out: *mut c_int, a: c_int, b: c_int) -> c_int {
    let mut err: c_int = 0;
    let a = if a < 0 { 0 } else { a };
    let b = if b < 0 { 0 } else { b };
    // SAFETY: `err` is this call's own live slot.
    let sum = unsafe { safe_add_int(a, b, &raw mut err) };
    // SAFETY: `out` is a live `int` slot per the contract.
    unsafe { *out = sum };
    c_int::from(err == 0)
}

/// `static int nc_minmax_valid(GENERAL_SUBTREE *sub)` — `crypto/x509/v3_ncons.c:483-499`. Nonzero
/// only when `maximum` is absent and `minimum` is absent or zero.
///
/// # Safety
///
/// `sub` is a live `GENERAL_SUBTREE`.
unsafe fn nc_minmax_valid(sub: *mut GeneralSubtree) -> c_int {
    let mut ok = 1;
    // SAFETY: `sub` is live per the contract.
    if unsafe { !(*sub).maximum.is_null() } {
        ok = 0;
    }
    // SAFETY: `sub` is live per the contract.
    if unsafe { !(*sub).minimum.is_null() } {
        // SAFETY: the `minimum` field is a live integer; a NULL second argument allocates.
        let bn = unsafe { ASN1_INTEGER_to_BN((*sub).minimum, ptr::null_mut()) };
        // SAFETY: `bn` is NULL or a live BIGNUM.
        if bn.is_null() || unsafe { BN_is_zero(bn) } == 0 {
            ok = 0;
        }
        // SAFETY: `bn` is NULL or a live BIGNUM this call owns.
        unsafe { BN_free(bn) };
    }
    ok
}

/// `static int nc_match(GENERAL_NAME *gen, NAME_CONSTRAINTS *nc)` — `crypto/x509/v3_ncons.c:501-561`.
/// The `otherName` `SmtpUTF8Mailbox` type is treated as `GEN_EMAIL` (RFC 8398 §6) via the
/// "effective type".
///
/// # Safety
///
/// `gen` is a live `GENERAL_NAME`; `nc` a live `NAME_CONSTRAINTS`.
unsafe fn nc_match(gen: *mut GeneralName, nc: *mut NameConstraints) -> c_int {
    let mut matched = 0;
    // SAFETY: `gen` is live per the contract.
    let mut effective_type = unsafe { (*gen).type_ };
    if effective_type == GEN_OTHERNAME
        // SAFETY: the `otherName` arm is live under the `GEN_OTHERNAME` selector.
        && unsafe { OBJ_obj2nid((*(*gen).d.otherName).type_id) } == NID_id_on_SmtpUTF8Mailbox
    {
        effective_type = GEN_EMAIL;
    }

    // Permitted subtrees: if any exist of matching type at least one must match.
    // SAFETY: `nc` is live per the contract.
    let permitted = unsafe { (*nc).permittedSubtrees };
    let mut i = 0;
    // SAFETY: `permitted` is NULL or a live subtree stack.
    while i < unsafe { OPENSSL_sk_num(permitted) } {
        // SAFETY: `i` is in bounds.
        let sub = unsafe { OPENSSL_sk_value(permitted, i) }.cast::<GeneralSubtree>();
        // SAFETY: `sub` is a live element per the stack contract; its `base` is live.
        let skip = unsafe {
            effective_type != (*(*sub).base).type_
                || (effective_type == GEN_OTHERNAME
                    && OBJ_cmp(
                        (*(*gen).d.otherName).type_id,
                        (*(*(*sub).base).d.otherName).type_id,
                    ) != 0)
        };
        if !skip {
            // SAFETY: `sub` is live per the stack contract.
            if unsafe { nc_minmax_valid(sub) } == 0 {
                return X509_V_ERR_SUBTREE_MINMAX;
            }
            // If we already have a match don't bother trying any more.
            if matched != 2 {
                if matched == 0 {
                    matched = 1;
                }
                // SAFETY: `sub->base` is a live `GENERAL_NAME`; `gen` is live.
                let r = unsafe { nc_match_single(effective_type, gen, (*sub).base) };
                if r == X509_V_OK {
                    matched = 2;
                } else if r != X509_V_ERR_PERMITTED_VIOLATION {
                    return r;
                }
            }
        }
        i += 1;
    }
    if matched == 1 {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }

    // Excluded subtrees: must not match any of these.
    // SAFETY: `nc` is live per the contract.
    let excluded = unsafe { (*nc).excludedSubtrees };
    let mut i = 0;
    // SAFETY: `excluded` is NULL or a live subtree stack.
    while i < unsafe { OPENSSL_sk_num(excluded) } {
        // SAFETY: `i` is in bounds.
        let sub = unsafe { OPENSSL_sk_value(excluded, i) }.cast::<GeneralSubtree>();
        // SAFETY: `sub` is a live element per the stack contract; its `base` is live.
        let skip = unsafe {
            effective_type != (*(*sub).base).type_
                || (effective_type == GEN_OTHERNAME
                    && OBJ_cmp(
                        (*(*gen).d.otherName).type_id,
                        (*(*(*sub).base).d.otherName).type_id,
                    ) != 0)
        };
        if !skip {
            // SAFETY: `sub` is live per the stack contract.
            if unsafe { nc_minmax_valid(sub) } == 0 {
                return X509_V_ERR_SUBTREE_MINMAX;
            }
            // SAFETY: `sub->base` is a live `GENERAL_NAME`; `gen` is live.
            let r = unsafe { nc_match_single(effective_type, gen, (*sub).base) };
            if r == X509_V_OK {
                return X509_V_ERR_EXCLUDED_VIOLATION;
            } else if r != X509_V_ERR_PERMITTED_VIOLATION {
                return r;
            }
        }
        i += 1;
    }
    X509_V_OK
}

/// `static int nc_match_single(int effective_type, GENERAL_NAME *gen, GENERAL_NAME *base)` —
/// `crypto/x509/v3_ncons.c:563-599`. Dispatches on `gen->type` to the per-type matcher.
///
/// # Safety
///
/// `gen` and `base` are live `GENERAL_NAME`s of the same `type`.
unsafe fn nc_match_single(
    effective_type: c_int,
    gen: *mut GeneralName,
    base: *mut GeneralName,
) -> c_int {
    // SAFETY: `gen` is live per the contract; the selected arm is live under this selector.
    match unsafe { (*gen).type_ } {
        GEN_OTHERNAME => match effective_type {
            GEN_EMAIL => {
                // SAFETY: the `otherName`/`rfc822Name` arms are live under the selectors.
                unsafe { nc_email_eai((*(*gen).d.otherName).value, (*base).d.ia5) }
            }
            _ => X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
        },
        // SAFETY: the `directoryName` arm is live under the `GEN_DIRNAME` selector.
        GEN_DIRNAME => unsafe { nc_dn((*gen).d.directoryName, (*base).d.directoryName) },
        // SAFETY: the `dNSName` arm is live under the `GEN_DNS` selector.
        GEN_DNS => unsafe { nc_dns((*gen).d.ia5, (*base).d.ia5) },
        // SAFETY: the `rfc822Name` arm is live under the `GEN_EMAIL` selector.
        GEN_EMAIL => unsafe { nc_email((*gen).d.ia5, (*base).d.ia5) },
        // SAFETY: the `uniformResourceIdentifier` arm is live under the `GEN_URI` selector.
        GEN_URI => unsafe { nc_uri((*gen).d.ia5, (*base).d.ia5) },
        // SAFETY: the `iPAddress` arm is live under the `GEN_IPADD` selector.
        GEN_IPADD => unsafe { nc_ip((*gen).d.iPAddress, (*base).d.iPAddress) },
        _ => X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
    }
}

/// `static int nc_dn(const X509_NAME *nm, const X509_NAME *base)` — `crypto/x509/v3_ncons.c:607-625`.
/// The canonical encoding makes a directory-name subtree test a prefix comparison.
///
/// # Safety
///
/// `nm` and `base` are live `X509_NAME`s.
unsafe fn nc_dn(nm: *const X509Name, base: *const X509Name) -> c_int {
    // SAFETY: `nm` is live per the contract; a NULL out-pointer only refreshes `canon_enc`.
    if unsafe { (*nm).modified } != 0 && unsafe { i2d_X509_NAME(nm, ptr::null_mut()) } < 0 {
        return X509_V_ERR_OUT_OF_MEM;
    }
    // SAFETY: `base` is live per the contract.
    if unsafe { (*base).modified } != 0 && unsafe { i2d_X509_NAME(base, ptr::null_mut()) } < 0 {
        return X509_V_ERR_OUT_OF_MEM;
    }
    // SAFETY: both are live per the contract.
    unsafe {
        if (*base).canon_enclen > (*nm).canon_enclen {
            return X509_V_ERR_PERMITTED_VIOLATION;
        }
        // An empty base Name has no canonical encoding and is a prefix of every Name.
        if (*base).canon_enclen == 0 {
            return X509_V_OK;
        }
        if memcmp(
            (*base).canon_enc.cast(),
            (*nm).canon_enc.cast(),
            (*base).canon_enclen as usize,
        ) != 0
        {
            return X509_V_ERR_PERMITTED_VIOLATION;
        }
    }
    X509_V_OK
}

/// `static int nc_dns(ASN1_IA5STRING *dns, ASN1_IA5STRING *base)` — `crypto/x509/v3_ncons.c:627-653`.
///
/// # Safety
///
/// `dns` and `base` are live IA5 strings.
unsafe fn nc_dns(dns: *mut Asn1String, base: *mut Asn1String) -> c_int {
    // SAFETY: `base`/`dns` are live per the contract.
    let (baseptr, mut dnsptr, dnslen, baselen) = unsafe {
        (
            (*base).data.cast::<c_char>(),
            (*dns).data.cast::<c_char>(),
            (*dns).length,
            (*base).length,
        )
    };
    // Empty matches everything.
    if baselen == 0 {
        return X509_V_OK;
    }
    if dnslen < baselen {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    // Otherwise can add zero or more components on the left.
    if dnslen > baselen {
        // SAFETY: `dnsptr` has `dnslen` readable bytes and `dnslen > baselen >= 1`.
        dnsptr = unsafe { dnsptr.add((dnslen - baselen) as usize) };
        // SAFETY: `baseptr` and `dnsptr` are in bounds; `dnsptr` is not the first byte.
        if unsafe { *baseptr != b'.' as c_char && *dnsptr.sub(1) != b'.' as c_char } {
            return X509_V_ERR_PERMITTED_VIOLATION;
        }
    }
    // SAFETY: both pointers have `baselen` readable bytes.
    if unsafe { ia5ncasecmp(baseptr, dnsptr, baselen as usize) } != 0 {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

/// `static int nc_email_eai(ASN1_TYPE *emltype, ASN1_IA5STRING *base)` — `crypto/x509/v3_ncons.c:662-730`.
/// RFC 8398 §6's A-label/U-label comparison of an `SmtpUTF8Mailbox` value against a `base`
/// rfc822Name.
///
/// # Safety
///
/// `emltype` is a live `ASN1_TYPE`; `base` a live IA5 string.
unsafe fn nc_email_eai(emltype: *mut Asn1Type, base: *mut Asn1String) -> c_int {
    // We do not accept embedded NUL characters.
    // SAFETY: `base` is live per the contract.
    let base_len_prefix = unsafe { (*base).length };
    // SAFETY: `base` is live and its data has `base_len_prefix` readable bytes.
    let base_has_nul =
        unsafe { !memchr((*base).data.cast(), 0, base_len_prefix as usize).is_null() };
    if base_len_prefix > 0 && base_has_nul {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    // 'base' may not be NUL terminated. Create a copy that is.
    // SAFETY: `base` is live and has `length` readable bytes; the file/line are this unit's.
    let baseptr = unsafe {
        CRYPTO_strndup(
            (*base).data.cast::<c_char>(),
            (*base).length as usize,
            FILE.as_ptr(),
            LINE_STRNDUP_BASE,
        )
    };
    if baseptr.is_null() {
        return X509_V_ERR_OUT_OF_MEM;
    }
    let mut ulabel = [0 as c_char; 256];
    let size = ulabel.len();
    // `ret` in the authority starts at X509_V_OK and is overwritten on every non-final path; the
    // labelled block below carries exactly those assignments, then the single `end:` free runs.
    let ret = 'end: {
        // SAFETY: `emltype` is live per the contract.
        if unsafe { (*emltype).type_ } != V_ASN1_UTF8STRING {
            break 'end X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
        }
        // SAFETY: the `utf8string` arm is live under this selector.
        let eml = unsafe { (*emltype).value.ptr.cast::<Asn1String>() };
        // SAFETY: `eml` is a live UTF8 string.
        let mut emlptr = unsafe { (*eml).data.cast::<c_char>() };
        // SAFETY: `eml` is live and its content is `eml->length` bytes.
        let emlat = unsafe { ia5memrchr(eml, '@' as c_int) };
        if emlat.is_null() {
            break 'end X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
        }
        // SAFETY: `baseptr` is NUL-terminated per `CRYPTO_strndup`.
        if unsafe { *baseptr } == b'.' as c_char {
            ulabel[0] = b'.' as c_char;
            // SAFETY: `baseptr` is NUL-terminated; `ulabel + 1` has `size - 1` writable bytes.
            if unsafe { ossl_a2ulabel(baseptr, ulabel.as_mut_ptr().add(1), size - 1) } <= 0 {
                break 'end X509_V_ERR_UNSPECIFIED;
            }
            // SAFETY: `ulabel` is NUL-terminated by `ossl_a2ulabel` on success.
            let ulen = unsafe { strlen(ulabel.as_ptr()) };
            // SAFETY: `eml` is live per the contract.
            if unsafe { (*eml).length as usize } > ulen {
                // SAFETY: `emlptr` has `eml->length` bytes; the offset is within them.
                emlptr = unsafe { emlptr.add((*eml).length as usize - ulen) };
                // SAFETY: `emlptr` has `ulen` readable bytes; `ulabel` is NUL-terminated.
                if unsafe { ia5ncasecmp(ulabel.as_ptr(), emlptr, ulen) } == 0 {
                    break 'end X509_V_OK;
                }
            }
            break 'end X509_V_ERR_PERMITTED_VIOLATION;
        }
        // SAFETY: `baseptr` is NUL-terminated; `ulabel` has `size` writable bytes.
        if unsafe { ossl_a2ulabel(baseptr, ulabel.as_mut_ptr(), size) } <= 0 {
            break 'end X509_V_ERR_UNSPECIFIED;
        }
        // Just have hostname left to match: case insensitive.
        // SAFETY: `emlat` points into `eml`'s bytes, so `emlat + 1` is within them.
        let hostptr = unsafe { emlat.add(1) };
        // SAFETY: `eml` is live and `hostptr` points within its bytes.
        let emlhostlen = unsafe { ia5_offset_len(eml, hostptr) };
        // SAFETY: `ulabel` is NUL-terminated by `ossl_a2ulabel` on success.
        let ulen = unsafe { strlen(ulabel.as_ptr()) };
        // SAFETY: both pointers have `emlhostlen`/`ulen` readable bytes.
        if emlhostlen != ulen || unsafe { ia5ncasecmp(ulabel.as_ptr(), hostptr, emlhostlen) } != 0 {
            break 'end X509_V_ERR_PERMITTED_VIOLATION;
        }
        X509_V_OK
    };
    // SAFETY: `baseptr` is NULL or this call's own `CRYPTO_strndup` allocation.
    unsafe { CRYPTO_free(baseptr.cast(), FILE.as_ptr(), LINE_FREE_BASEPTR) };
    ret
}

/// `static int nc_email(ASN1_IA5STRING *eml, ASN1_IA5STRING *base)` — `crypto/x509/v3_ncons.c:732-775`.
///
/// # Safety
///
/// `eml` and `base` are live IA5 strings.
unsafe fn nc_email(eml: *mut Asn1String, base: *mut Asn1String) -> c_int {
    // SAFETY: `eml`/`base` are live per the contract.
    let (mut baseptr, mut emlptr, eml_len, base_len) = unsafe {
        (
            (*base).data.cast::<c_char>().cast_const(),
            (*eml).data.cast::<c_char>().cast_const(),
            (*eml).length,
            (*base).length,
        )
    };
    // SAFETY: both are live IA5 strings; `ia5memrchr` reads within them.
    let baseat = unsafe { ia5memrchr(base, '@' as c_int) };
    // SAFETY: as above.
    let emlat = unsafe { ia5memrchr(eml, '@' as c_int) };

    if emlat.is_null() {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    // Special case: initial '.' is RHS match.
    // SAFETY: `baseptr` has `base_len` readable bytes (or `base_len == 0`).
    if baseat.is_null() && base_len > 0 && unsafe { *baseptr } == b'.' as c_char {
        if eml_len > base_len {
            // SAFETY: `emlptr` has `eml_len` bytes and `eml_len > base_len`.
            emlptr = unsafe { emlptr.add((eml_len - base_len) as usize) };
            // SAFETY: both pointers have `base_len` readable bytes.
            if unsafe { ia5ncasecmp(baseptr, emlptr, base_len as usize) } == 0 {
                return X509_V_OK;
            }
        }
        return X509_V_ERR_PERMITTED_VIOLATION;
    }

    // If we have anything before '@' match local part.
    if !baseat.is_null() {
        if baseat != baseptr {
            // Both pointers are into their live strings, so the differences are the local-part
            // lengths the authority compares.
            let base_local = baseat as usize - baseptr as usize;
            let eml_local = emlat as usize - emlptr as usize;
            if base_local != eml_local {
                return X509_V_ERR_PERMITTED_VIOLATION;
            }
            // SAFETY: both spans are within their live strings.
            if unsafe {
                !memchr(baseptr.cast(), 0, base_local).is_null()
                    || !memchr(emlptr.cast(), 0, eml_local).is_null()
            } {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            // Case sensitive match of local part.
            // SAFETY: both pointers have `eml_local` readable bytes.
            if unsafe { strncmp(baseptr, emlptr, eml_local) } != 0 {
                return X509_V_ERR_PERMITTED_VIOLATION;
            }
        }
        // Position base after '@'.
        // SAFETY: `baseat` points at an '@' within `base`, so `baseat + 1` is within it.
        baseptr = unsafe { baseat.add(1) };
    }
    // SAFETY: `emlat` points at an '@' within `eml`, so `emlat + 1` is within it.
    emlptr = unsafe { emlat.add(1) };
    // SAFETY: `base`/`eml` are live and the two pointers point within them.
    let (basehostlen, emlhostlen) =
        unsafe { (ia5_offset_len(base, baseptr), ia5_offset_len(eml, emlptr)) };
    // Just have hostname left to match: case insensitive.
    // SAFETY: both pointers have `emlhostlen` readable bytes.
    if basehostlen != emlhostlen || unsafe { ia5ncasecmp(baseptr, emlptr, emlhostlen) } != 0 {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    X509_V_OK
}

/// `static int nc_uri(ASN1_IA5STRING *uri, ASN1_IA5STRING *base)` — `crypto/x509/v3_ncons.c:777-832`.
///
/// # Safety
///
/// `uri` and `base` are live IA5 strings.
unsafe fn nc_uri(uri: *mut Asn1String, base: *mut Asn1String) -> c_int {
    // SAFETY: `base` is live per the contract.
    let baseptr = unsafe { (*base).data.cast::<c_char>() };
    // SAFETY: `uri` is live and has `length` readable bytes; the file/line are this unit's.
    let uri_copy = unsafe {
        CRYPTO_strndup(
            (*uri).data.cast::<c_char>(),
            (*uri).length as usize,
            FILE.as_ptr(),
            LINE_STRNDUP_URI,
        )
    };
    if uri_copy.is_null() {
        return X509_V_ERR_UNSPECIFIED;
    }
    let mut scheme: *mut c_char = ptr::null_mut();
    let mut host: *mut c_char = ptr::null_mut();
    // SAFETY: `uri_copy` is NUL-terminated; `scheme`/`host` are this call's own writable slots.
    let parsed = unsafe {
        OSSL_parse_url(
            uri_copy,
            &raw mut scheme,
            ptr::null_mut(),
            &raw mut host,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if parsed == 0 {
        // SAFETY: `uri_copy` is this call's own allocation.
        unsafe { CRYPTO_free(uri_copy.cast(), FILE.as_ptr(), LINE_FREE_URI_COPY_PARSE) };
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    // Make sure the scheme is there.
    // SAFETY: `scheme` is NULL or NUL-terminated by `OSSL_parse_url`.
    if scheme.is_null() || unsafe { *scheme } == 0 {
        // `ERR_raise_data(ERR_LIB_X509V3, X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
        //  "x509: missing scheme in URI: %s\n", uri_copy)`.
        let mut msg = b"x509: missing scheme in URI: ".to_vec();
        // SAFETY: `uri_copy` is NUL-terminated per `CRYPTO_strndup`.
        unsafe { push_cstr(&mut msg, uri_copy) };
        msg.push(b'\n');
        msg.push(0);
        // SAFETY: `msg` is NUL-terminated; the site is a compiled-in constant.
        unsafe { raise_site_data(&V3_NCONS_796, msg.as_ptr().cast()) };
        // SAFETY: `scheme`/`uri_copy`/`host` are this call's own allocations.
        unsafe {
            CRYPTO_free(scheme.cast(), FILE.as_ptr(), LINE_FREE_SCHEME_MISSING);
            CRYPTO_free(uri_copy.cast(), FILE.as_ptr(), LINE_FREE_URI_COPY_MISSING);
            CRYPTO_free(host.cast(), FILE.as_ptr(), LINE_FREE_HOST);
        }
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    // We don't need these anymore.
    // SAFETY: `scheme`/`uri_copy` are this call's own allocations.
    unsafe {
        CRYPTO_free(scheme.cast(), FILE.as_ptr(), LINE_FREE_SCHEME);
        CRYPTO_free(uri_copy.cast(), FILE.as_ptr(), LINE_FREE_URI_COPY);
    }
    // SAFETY: `host` is NUL-terminated by `OSSL_parse_url`.
    let hostlen = unsafe { strlen(host) } as c_int;
    // `ret` is assigned on every path; the single `end:` free below releases `host`.
    let ret = 'end: {
        // SAFETY: `base` is live per the contract.
        let base_len = unsafe { (*base).length };
        // SAFETY: `baseptr` has `base_len` readable bytes (or `base_len == 0`).
        let base_is_dot = base_len > 0 && unsafe { *baseptr } == b'.' as c_char;
        if base_is_dot {
            if hostlen > base_len {
                // SAFETY: `hostlen` is `host`'s length and `base_len < hostlen`, so the suffix
                // pointer is within `host`; `baseptr` has `base_len` readable bytes.
                let suffix_match = unsafe {
                    ia5ncasecmp(
                        host.add((hostlen - base_len) as usize),
                        baseptr,
                        base_len as usize,
                    )
                } == 0;
                if suffix_match {
                    break 'end X509_V_OK;
                }
            }
            break 'end X509_V_ERR_PERMITTED_VIOLATION;
        }
        // SAFETY: `host` has `hostlen` readable bytes; `baseptr` has `base_len` readable bytes.
        let hostname_mismatch =
            base_len != hostlen || unsafe { ia5ncasecmp(host, baseptr, hostlen as usize) } != 0;
        if hostname_mismatch {
            break 'end X509_V_ERR_PERMITTED_VIOLATION;
        }
        X509_V_OK
    };
    // SAFETY: `host` is this call's own allocation.
    unsafe { CRYPTO_free(host.cast(), FILE.as_ptr(), LINE_FREE_HOST) };
    ret
}

/// `static int nc_ip(ASN1_OCTET_STRING *ip, ASN1_OCTET_STRING *base)` — `crypto/x509/v3_ncons.c:834-862`.
/// Masks the host address and the base address with the base's mask half and compares.
///
/// # Safety
///
/// `ip` and `base` are live octet strings.
unsafe fn nc_ip(ip: *mut Asn1String, base: *mut Asn1String) -> c_int {
    // SAFETY: `ip`/`base` are live per the contract.
    let (hostptr, hostlen, baseptr, baselen) =
        unsafe { ((*ip).data, (*ip).length, (*base).data, (*base).length) };
    // Invalid if not IPv4 or IPv6.
    if hostlen != 4 && hostlen != 16 {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    if baselen != 8 && baselen != 32 {
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    // Do not match IPv4 with IPv6.
    if hostlen * 2 != baselen {
        return X509_V_ERR_PERMITTED_VIOLATION;
    }
    // SAFETY: `baseptr` has `baselen >= hostlen * 2` bytes; the mask half begins at `hostlen`.
    let maskptr = unsafe { baseptr.add(hostlen as usize) };
    let mut i = 0;
    while i < hostlen {
        // SAFETY: `hostptr`/`baseptr`/`maskptr` each have at least `hostlen` readable bytes.
        let masked_host = unsafe { *hostptr.add(i as usize) & *maskptr.add(i as usize) };
        // SAFETY: as above.
        let masked_base = unsafe { *baseptr.add(i as usize) & *maskptr.add(i as usize) };
        if masked_host != masked_base {
            return X509_V_ERR_PERMITTED_VIOLATION;
        }
        i += 1;
    }
    X509_V_OK
}

/// `static char *ia5memrchr(ASN1_IA5STRING *str, int c)` — `crypto/x509/v3_ncons.c:102-113`.
/// The last occurrence of `c` in an IA5 string, or NULL.
///
/// # Safety
///
/// `str_` is a live IA5 string.
unsafe fn ia5memrchr(str_: *const Asn1String, c: c_int) -> *const c_char {
    // SAFETY: `str_` is live per the contract.
    let mut i = unsafe { (*str_).length };
    while i > 0 {
        // SAFETY: `i - 1` is a valid index into `data`'s `length` bytes.
        if unsafe { *(*str_).data.add((i - 1) as usize) } as c_int == c {
            break;
        }
        i -= 1;
    }
    if i == 0 {
        return ptr::null();
    }
    // SAFETY: `i - 1` is a valid index into `data`'s `length` bytes.
    unsafe { (*str_).data.add((i - 1) as usize).cast::<c_char>() }
}

/// `static int ia5ncasecmp(const char *s1, const char *s2, size_t n)` — `crypto/x509/v3_ncons.c:122-146`.
/// A locale-independent ASCII case comparison, so embedded NULs and Turkish `I` are handled as the
/// authority documents.
///
/// # Safety
///
/// `s1` and `s2` are readable for `n` bytes.
unsafe fn ia5ncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    let mut s1 = s1;
    let mut s2 = s2;
    let mut n = n;
    while n > 0 {
        // SAFETY: both pointers are readable for `n >= 1` bytes.
        if unsafe { *s1 != *s2 } {
            // SAFETY: as above.
            let mut c1 = unsafe { *s1 } as c_uchar;
            // SAFETY: as above.
            let mut c2 = unsafe { *s2 } as c_uchar;
            if (0x41..=0x5A).contains(&c1) {
                c1 += 0x20;
            }
            if (0x41..=0x5A).contains(&c2) {
                c2 += 0x20;
            }
            if c1 != c2 {
                if c1 < c2 {
                    return -1;
                }
                return 1;
            }
        }
        n -= 1;
        // SAFETY: the pointers are advanced within their readable spans.
        unsafe {
            s1 = s1.add(1);
            s2 = s2.add(1);
        }
    }
    0
}

/// `IA5_OFFSET_LEN(ia5base, offset)` — `crypto/x509/v3_ncons.c:93-94`. The byte count from
/// `offset` to the end of `ia5base`.
///
/// # Safety
///
/// `offset` points within `ia5base`'s `data` span.
unsafe fn ia5_offset_len(ia5base: *const Asn1String, offset: *const c_char) -> usize {
    // SAFETY: `ia5base` is live and `offset` is within its data per the contract.
    unsafe { ((*ia5base).length as isize - (offset as isize - (*ia5base).data as isize)) as usize }
}

/// `static int cn2dnsid(ASN1_STRING *cn, unsigned char **dnsid, size_t *idlen)` —
/// `crypto/x509/v3_ncons.c:341-432`. Converts a commonName to UTF-8 and, when it has plausible
/// DNS-ID syntax with two or more labels, hands the buffer to the caller.
///
/// # Safety
///
/// `cn` is a live string; `dnsid`/`idlen` are writable slots.
unsafe fn cn2dnsid(cn: *mut Asn1String, dnsid: *mut *mut c_uchar, idlen: *mut usize) -> c_int {
    let mut isdnsname = 0;
    // SAFETY: `dnsid`/`idlen` are writable per the contract.
    unsafe {
        *dnsid = ptr::null_mut();
        *idlen = 0;
    }
    let mut utf8_value: *mut c_uchar = ptr::null_mut();
    // SAFETY: `cn` is live; `utf8_value` is this call's own writable slot.
    let mut utf8_length = unsafe { ASN1_STRING_to_UTF8(&raw mut utf8_value, cn) };
    if utf8_length < 0 {
        return X509_V_ERR_OUT_OF_MEM;
    }
    // Remove a trailing NUL run.
    // SAFETY: `utf8_value` has `utf8_length` readable bytes.
    while utf8_length > 0 && unsafe { *utf8_value.add((utf8_length - 1) as usize) } == 0 {
        utf8_length -= 1;
    }
    // Reject embedded NULs.
    // SAFETY: `utf8_value` has `utf8_length` readable bytes.
    if unsafe { !memchr(utf8_value.cast(), 0, utf8_length as usize).is_null() } {
        // SAFETY: `utf8_value` is this call's own allocation.
        unsafe { CRYPTO_free(utf8_value.cast(), FILE.as_ptr(), LINE_FREE_UTF8_EMBEDDED) };
        return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
    }
    let mut i = 0;
    while i < utf8_length {
        // SAFETY: `i` indexes `utf8_value`'s `utf8_length` bytes.
        let c = unsafe { *utf8_value.add(i as usize) };
        let simple = c.is_ascii_alphanumeric() || c == b'_';
        if !simple {
            let mut handled = false;
            if i > 0 && i < utf8_length - 1 {
                if c == b'-' {
                    handled = true;
                } else if c == b'.' {
                    // SAFETY: `i - 1` and `i + 1` are both in bounds by the guard above.
                    let dot_ok = unsafe {
                        *utf8_value.add((i + 1) as usize) != b'.'
                            && *utf8_value.add((i - 1) as usize) != b'-'
                            && *utf8_value.add((i + 1) as usize) != b'-'
                    };
                    if dot_ok {
                        isdnsname = 1;
                        handled = true;
                    }
                }
            }
            if !handled {
                isdnsname = 0;
                break;
            }
        }
        i += 1;
    }
    if isdnsname != 0 {
        // SAFETY: `dnsid`/`idlen` are writable per the contract; `utf8_value` transfers to caller.
        unsafe {
            *dnsid = utf8_value;
            *idlen = utf8_length as usize;
        }
        return X509_V_OK;
    }
    // SAFETY: `utf8_value` is this call's own allocation.
    unsafe { CRYPTO_free(utf8_value.cast(), FILE.as_ptr(), LINE_FREE_UTF8_NOTDNS) };
    X509_V_OK
}

/// `int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc)` — `crypto/x509/v3_ncons.c:280-339`.
/// Checks a certificate's subject name, its `pkcs9_emailAddress` attributes and every subject
/// alternative name against the constraints, guarding against a quadratic blow-up first.
///
/// # Safety
///
/// `x` is a live `X509`; `nc` a live `NAME_CONSTRAINTS`.
#[no_mangle]
pub unsafe extern "C" fn NAME_CONSTRAINTS_check(x: *mut X509, nc: *mut NameConstraints) -> c_int {
    // SAFETY: `x` is live per the contract.
    let nm = unsafe { X509_get_subject_name(x) };
    let mut name_count: c_int = 0;
    let mut constraint_count: c_int = 0;
    // SAFETY: `x` is live; `altname` is NULL or a live `STACK_OF(GENERAL_NAME)`.
    let altname = unsafe { (*x).altname.cast::<OpenSslStack>() };
    // SAFETY: `nm` is live; `nc`'s two stacks are NULL or live.
    let (name_num, permit_num, exclude_num) = unsafe {
        (
            X509_NAME_entry_count(nm),
            OPENSSL_sk_num((*nc).permittedSubtrees),
            OPENSSL_sk_num((*nc).excludedSubtrees),
        )
    };
    // SAFETY: the two out-arguments are this call's own live slots.
    let ok = unsafe { add_lengths(&raw mut name_count, name_num, OPENSSL_sk_num(altname)) };
    // SAFETY: as above.
    let ok2 = unsafe { add_lengths(&raw mut constraint_count, permit_num, exclude_num) };
    if ok == 0 || ok2 == 0 || (name_count > 0 && constraint_count > NAME_CHECK_MAX / name_count) {
        return X509_V_ERR_UNSPECIFIED;
    }

    if name_num > 0 {
        // SAFETY: an all-zero `GENERAL_NAME` is a valid starting value; each arm is written before
        // it is read.
        let mut gntmp: GeneralName = unsafe { core::mem::zeroed() };
        gntmp.type_ = GEN_DIRNAME;
        // SAFETY: the `directoryName` arm is live under this selector.
        gntmp.d.directoryName = nm;
        // SAFETY: `gntmp` is live; `nc` is live.
        let mut r = unsafe { nc_match(&raw mut gntmp, nc) };
        if r != X509_V_OK {
            return r;
        }
        gntmp.type_ = GEN_EMAIL;
        // Process any email address attributes in subject name.
        let mut i: c_int = -1;
        loop {
            // SAFETY: `nm` is live.
            i = unsafe { X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i) };
            if i == -1 {
                break;
            }
            // SAFETY: `i` is a valid entry index returned above.
            let ne = unsafe { X509_NAME_get_entry(nm, i) };
            // SAFETY: `ne` is a live entry.
            gntmp.d.ia5 = unsafe { X509_NAME_ENTRY_get_data(ne) };
            // SAFETY: the `rfc822Name` arm is live under the `GEN_EMAIL` selector.
            if unsafe { (*gntmp.d.ia5).type_ } != V_ASN1_IA5STRING {
                return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
            }
            // SAFETY: `gntmp` is live; `nc` is live.
            r = unsafe { nc_match(&raw mut gntmp, nc) };
            if r != X509_V_OK {
                return r;
            }
        }
    }

    let mut i = 0;
    // SAFETY: `altname` is NULL or a live alt-name stack.
    while i < unsafe { OPENSSL_sk_num(altname) } {
        // SAFETY: `i` is in bounds.
        let gen = unsafe { OPENSSL_sk_value(altname, i) }.cast::<GeneralName>();
        // SAFETY: `gen` is a live element per the stack contract; `nc` is live.
        let r = unsafe { nc_match(gen, nc) };
        if r != X509_V_OK {
            return r;
        }
        i += 1;
    }
    X509_V_OK
}

/// `int NAME_CONSTRAINTS_check_CN(X509 *x, NAME_CONSTRAINTS *nc)` — `crypto/x509/v3_ncons.c:437-477`.
/// Checks every `commonName` that looks like a hostname against the DNS name constraints.
///
/// # Safety
///
/// `x` is a live `X509`; `nc` a live `NAME_CONSTRAINTS`.
#[no_mangle]
pub unsafe extern "C" fn NAME_CONSTRAINTS_check_CN(
    x: *mut X509,
    nc: *mut NameConstraints,
) -> c_int {
    // SAFETY: `x` is live per the contract.
    let nm = unsafe { X509_get_subject_name(x) };
    // SAFETY: an all-zero `ASN1_STRING` is a valid starting value; the fields used are set below.
    let mut stmp: Asn1String = unsafe { core::mem::zeroed() };
    stmp.flags = 0;
    stmp.type_ = V_ASN1_IA5STRING;
    // SAFETY: an all-zero `GENERAL_NAME` is a valid starting value; the arm is set below.
    let mut gntmp: GeneralName = unsafe { core::mem::zeroed() };
    gntmp.type_ = GEN_DNS;
    // SAFETY: the `dNSName` arm is live under this selector; `stmp` outlives `gntmp` here.
    gntmp.d.ia5 = &raw mut stmp;

    // Process any commonName attributes in subject name.
    let mut i: c_int = -1;
    loop {
        // SAFETY: `nm` is live.
        i = unsafe { X509_NAME_get_index_by_NID(nm, NID_commonName, i) };
        if i == -1 {
            break;
        }
        // SAFETY: `i` is a valid entry index returned above.
        let ne = unsafe { X509_NAME_get_entry(nm, i) };
        // SAFETY: `ne` is a live entry.
        let cn = unsafe { X509_NAME_ENTRY_get_data(ne) };
        let mut idval: *mut c_uchar = ptr::null_mut();
        let mut idlen: usize = 0;
        // SAFETY: `cn` is live; `idval`/`idlen` are this call's own writable slots.
        let r = unsafe { cn2dnsid(cn, &raw mut idval, &raw mut idlen) };
        if r != X509_V_OK {
            return r;
        }
        // Only process attributes that look like hostnames; `idval` is NULL when `idlen` is 0.
        if idlen != 0 {
            // SAFETY: `gntmp.d.ia5` names the live `stmp` local, whose fields are writable.
            unsafe {
                (*gntmp.d.ia5).length = idlen as c_int;
                (*gntmp.d.ia5).data = idval;
            }
            // SAFETY: `gntmp` is live and its `dNSName` arm points at `stmp`; `nc` is live.
            let r = unsafe { nc_match(&raw mut gntmp, nc) };
            // SAFETY: `idval` is this call's own `cn2dnsid` allocation.
            unsafe { CRYPTO_free(idval.cast(), FILE.as_ptr(), LINE_FREE_IDVAL) };
            if r != X509_V_OK {
                return r;
            }
        }
    }
    X509_V_OK
}

/// `const X509V3_EXT_METHOD ossl_v3_name_constraints` — `crypto/x509/v3_ncons.c:47-55`.
/// `ext_nid` is `NID_name_constraints`, `it` is `ASN1_ITEM_ref(NAME_CONSTRAINTS)`, `v2i` is
/// [`v2i_NAME_CONSTRAINTS`] and `i2r` is [`i2r_NAME_CONSTRAINTS`]; every other slot is zero.
pub static ossl_v3_name_constraints: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_name_constraints,
    ext_flags: 0,
    it: Some(NAME_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_NAME_CONSTRAINTS),
    i2r: Some(i2r_NAME_CONSTRAINTS),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_holder_name_constraints` — `crypto/x509/v3_ncons.c:57-65`.
/// `ext_nid` is `NID_holder_name_constraints`; the item and callbacks are as
/// [`ossl_v3_name_constraints`]'s.
pub static ossl_v3_holder_name_constraints: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_holder_name_constraints,
    ext_flags: 0,
    it: Some(NAME_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_NAME_CONSTRAINTS),
    i2r: Some(i2r_NAME_CONSTRAINTS),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_delegated_name_constraints` — `crypto/x509/v3_ncons.c:67-75`.
/// `ext_nid` is `NID_delegated_name_constraints`; the item and callbacks are as
/// [`ossl_v3_name_constraints`]'s.
pub static ossl_v3_delegated_name_constraints: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_delegated_name_constraints,
    ext_flags: 0,
    it: Some(NAME_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_NAME_CONSTRAINTS),
    i2r: Some(i2r_NAME_CONSTRAINTS),
    r2i: None,
    usr_data: ptr::null_mut(),
};
