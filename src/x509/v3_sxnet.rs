//! `crypto/x509/v3_sxnet.c` — the Thawte strong-extranet `SXNET` item groups, their utility
//! functions and their row. Phase 10.14's table layer, landed whole.
//!
//! `crypto/x509/v3_sxnet.c` is 259 lines and transcribes whole:
//!
//! * `SXNETID ::= SEQUENCE { zone INTEGER, user OCTET STRING }` (`:43-46`) and
//!   `SXNET ::= SEQUENCE { version INTEGER, ids SEQUENCE OF SXNETID }` (`:50-53`) land, with the
//!   `_it`/`_new`/`_free`/`d2i_`/`i2d_` group each `IMPLEMENT_ASN1_FUNCTIONS` emits (`:48`, `:55`).
//!   All ten are public exports (`x509v3.h:804-805`), so the differential plane can build one,
//!   encode it and decode the bytes back.
//! * The two `static` callbacks `sxnet_i2r` (`:57-88`) and `sxnet_v2i` (`:98-112`) land.
//! * The five public utilities land: `SXNET_add_id_asc` (`:120-133`), `SXNET_add_id_ulong`
//!   (`:137-153`), `SXNET_add_id_INTEGER` (`:160-217`), `SXNET_get_id_asc` (`:219-231`),
//!   `SXNET_get_id_ulong` (`:233-247`) and `SXNET_get_id_INTEGER` (`:249-259`).
//! * The row [`ossl_v3_sxnet`] (`:28-41`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item groups and the utilities are the drivable
//! surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_sxnet.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`
//! (D456's closure list names it a closure-ready table unit, not a generator input), so its twelve
//! coordinates are **declared locally** with the `err_sites::ErrSite` shape, as `v3_bitst.rs` does.
//! Their reason values are read from the authority's own headers (`x509v3err.h` for the six
//! `X509V3_R_*`, `err.h` for the two `ERR_R_*_LIB`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::{ASN1_INTEGER_cmp, ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::{ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_set};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::strlen;
use crate::runtime::bio::{Bio, ERR_R_CRYPTO_LIB};
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{
    X509V3_R_DUPLICATE_ZONE_ID, X509V3_R_ERROR_CONVERTING_ZONE, X509V3_R_INVALID_NULL_ARGUMENT,
    X509V3_R_USER_TOO_LONG,
};
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::NID_sxnet;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_utl::{i2s_ASN1_INTEGER, s2i_ASN1_INTEGER};

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansions — `crypto/x509/v3_sxnet.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_sxnet.c";

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_sxnet.c` raise coordinate, declared locally (see the module doc).
const fn v3_sxnet_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_sxnet.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `SXNET_add_id_asc`'s failed `s2i_ASN1_INTEGER` at `v3_sxnet.c:125`.
const V3_SXNET_125: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(125, c"SXNET_add_id_asc", X509V3_R_ERROR_CONVERTING_ZONE);
/// `SXNET_add_id_ulong`'s allocation/set failure at `v3_sxnet.c:144`.
const V3_SXNET_144: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(144, c"SXNET_add_id_ulong", ERR_R_ASN1_LIB);
/// `SXNET_add_id_INTEGER`'s NULL argument at `v3_sxnet.c:167`.
const V3_SXNET_167: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(167, c"SXNET_add_id_INTEGER", X509V3_R_INVALID_NULL_ARGUMENT);
/// `SXNET_add_id_INTEGER`'s over-long user at `v3_sxnet.c:173`.
const V3_SXNET_173: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(173, c"SXNET_add_id_INTEGER", X509V3_R_USER_TOO_LONG);
/// `SXNET_add_id_INTEGER`'s failed `SXNET_new` at `v3_sxnet.c:178`.
const V3_SXNET_178: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(178, c"SXNET_add_id_INTEGER", ERR_R_ASN1_LIB);
/// `SXNET_add_id_INTEGER`'s failed version set at `v3_sxnet.c:182`.
const V3_SXNET_182: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(182, c"SXNET_add_id_INTEGER", ERR_R_ASN1_LIB);
/// `SXNET_add_id_INTEGER`'s duplicate zone at `v3_sxnet.c:188`.
const V3_SXNET_188: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(188, c"SXNET_add_id_INTEGER", X509V3_R_DUPLICATE_ZONE_ID);
/// `SXNET_add_id_INTEGER`'s failed `SXNETID_new` at `v3_sxnet.c:195`.
const V3_SXNET_195: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(195, c"SXNET_add_id_INTEGER", ERR_R_ASN1_LIB);
/// `SXNET_add_id_INTEGER`'s failed `ASN1_OCTET_STRING_set` at `v3_sxnet.c:200`.
const V3_SXNET_200: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(200, c"SXNET_add_id_INTEGER", ERR_R_ASN1_LIB);
/// `SXNET_add_id_INTEGER`'s failed stack push at `v3_sxnet.c:204`.
const V3_SXNET_204: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(204, c"SXNET_add_id_INTEGER", ERR_R_CRYPTO_LIB);
/// `SXNET_get_id_asc`'s failed `s2i_ASN1_INTEGER` at `v3_sxnet.c:225`.
const V3_SXNET_225: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(225, c"SXNET_get_id_asc", X509V3_R_ERROR_CONVERTING_ZONE);
/// `SXNET_get_id_ulong`'s allocation/set failure at `v3_sxnet.c:240`.
const V3_SXNET_240: crate::runtime::err::err_sites::ErrSite =
    v3_sxnet_site(240, c"SXNET_get_id_ulong", ERR_R_ASN1_LIB);

/// `struct SXNET_ID_st` — `SXNETID`, from `include/openssl/x509v3.h:377-380`.
#[repr(C)]
pub struct Sxnetid {
    /// `ASN1_INTEGER *zone` — the zone number.
    pub zone: *mut Asn1String,
    /// `ASN1_OCTET_STRING *user` — the user's identifier.
    pub user: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<Sxnetid>() == 16);
    assert!(core::mem::offset_of!(Sxnetid, zone) == 0);
    assert!(core::mem::offset_of!(Sxnetid, user) == 8);
};

/// `struct SXNET_st` — `SXNET`, from `include/openssl/x509v3.h:412-415`.
#[repr(C)]
pub struct Sxnet {
    /// `ASN1_INTEGER *version` — the extranet version.
    pub version: *mut Asn1String,
    /// `STACK_OF(SXNETID) *ids` — the identifiers.
    pub ids: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<Sxnet>() == 16);
    assert!(core::mem::offset_of!(Sxnet, version) == 0);
    assert!(core::mem::offset_of!(Sxnet, ids) == 8);
};

/// `SXNETID_seq_tt` — `ASN1_SEQUENCE(SXNETID)` (`crypto/x509/v3_sxnet.c:43-46`): two
/// `ASN1_SIMPLE` rows, `zone` then `user`.
static SXNETID_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"zone".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"user".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `SXNETID_it`'s descriptor — `ASN1_SEQUENCE_END(SXNETID)` at `crypto/x509/v3_sxnet.c:46`.
static SXNETID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: SXNETID_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Sxnetid>() as c_long,
    sname: c"SXNETID".as_ptr(),
};

/// `const ASN1_ITEM *SXNETID_it(void)` — `include/openssl/x509v3.h:805`, from
/// `DECLARE_ASN1_FUNCTIONS(SXNETID)`.
#[no_mangle]
pub extern "C" fn SXNETID_it() -> *const Asn1Item {
    &SXNETID_ITEM
}

/// `SXNETID *SXNETID_new(void)` — `crypto/x509/v3_sxnet.c:48`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(SXNETID)`.
#[no_mangle]
pub extern "C" fn SXNETID_new() -> *mut Sxnetid {
    // SAFETY: `SXNETID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(SXNETID_it()).cast::<Sxnetid>() }
}

/// `void SXNETID_free(SXNETID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn SXNETID_free(a: *mut Sxnetid) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), SXNETID_it()) }
}

/// `SXNETID *d2i_SXNETID(SXNETID **a, const unsigned char **in, long len)` — the same macro's
/// decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_SXNETID(
    a: *mut *mut Sxnetid,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Sxnetid {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, SXNETID_it()).cast::<Sxnetid>() }
}

/// `int i2d_SXNETID(const SXNETID *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_SXNETID(a: *const Sxnetid, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, SXNETID_it()) }
}

/// `SXNET_seq_tt` — `ASN1_SEQUENCE(SXNET)` (`crypto/x509/v3_sxnet.c:50-53`): `version` and the
/// `ASN1_SEQUENCE_OF` `ids` column.
static SXNET_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"version".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_SEQUENCE_OF,
        tag: 0,
        offset: 8,
        field_name: c"ids".as_ptr(),
        item: SXNETID_it as *mut c_void,
    },
];

/// `SXNET_it`'s descriptor — `ASN1_SEQUENCE_END(SXNET)` at `crypto/x509/v3_sxnet.c:53`.
static SXNET_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: SXNET_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<Sxnet>() as c_long,
    sname: c"SXNET".as_ptr(),
};

/// `const ASN1_ITEM *SXNET_it(void)` — `include/openssl/x509v3.h:804`.
#[no_mangle]
pub extern "C" fn SXNET_it() -> *const Asn1Item {
    &SXNET_ITEM
}

/// `SXNET *SXNET_new(void)` — `crypto/x509/v3_sxnet.c:55`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(SXNET)`.
#[no_mangle]
pub extern "C" fn SXNET_new() -> *mut Sxnet {
    // SAFETY: `SXNET_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(SXNET_it()).cast::<Sxnet>() }
}

/// `void SXNET_free(SXNET *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn SXNET_free(a: *mut Sxnet) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), SXNET_it()) }
}

/// `SXNET *d2i_SXNET(SXNET **a, const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_SXNET(
    a: *mut *mut Sxnet,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut Sxnet {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, SXNET_it()).cast::<Sxnet>() }
}

/// `int i2d_SXNET(const SXNET *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_SXNET(a: *const Sxnet, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, SXNET_it()) }
}

/// `static int sxnet_i2r(X509V3_EXT_METHOD *method, SXNET *sx, BIO *out, int indent)` —
/// `crypto/x509/v3_sxnet.c:57-88`.
///
/// Prints the version (as `v + 1` and as `v`, or `<unsupported>` outside `long`), then one
/// `Zone: ..., User: ...` line per identifier. Each `i2s_ASN1_INTEGER` that answers NULL aborts.
unsafe extern "C" fn sxnet_i2r(
    _method: *const X509V3ExtMethod,
    sx: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let sx = sx.cast::<Sxnet>();
    let mut v: i64 = 0;
    // SAFETY: `sx` is a live `SXNET` per the caller's contract; `version` is its live integer.
    let got = unsafe { ASN1_INTEGER_get_int64(&raw mut v, (*sx).version) };
    if got == 0 || !(c_long::MIN..c_long::MAX).contains(&v) {
        // SAFETY: `out` is a live BIO; the format and its arguments are constants.
        unsafe {
            BIO_printf(
                out,
                c"%*sVersion: <unsupported>".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    } else {
        let vl = v as c_long;
        // SAFETY: `out` is a live BIO; the format and its arguments are constants.
        unsafe {
            BIO_printf(
                out,
                c"%*sVersion: %ld (0x%lX)".as_ptr(),
                indent,
                c"".as_ptr(),
                vl + 1,
                vl,
            )
        };
    }
    // SAFETY: `sx` is live; `ids` is a live `STACK_OF(SXNETID)`.
    let num = unsafe { OPENSSL_sk_num((*sx).ids) };
    let mut i = 0;
    while i < num {
        // SAFETY: `sx->ids` is live and `i` is in bounds.
        let id = unsafe { OPENSSL_sk_value((*sx).ids, i) }.cast::<Sxnetid>();
        // SAFETY: `id` is a live identifier; `zone` is its live integer.
        let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), (*id).zone) };
        if tmp.is_null() {
            return 0;
        }
        // SAFETY: `out` is a live BIO; `tmp` is NUL-terminated.
        unsafe {
            BIO_printf(
                out,
                c"\n%*sZone: %s, User: ".as_ptr(),
                indent,
                c"".as_ptr(),
                tmp,
            )
        };
        // SAFETY: `tmp` is this call's own, from `i2s_ASN1_INTEGER`.
        unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), 84) };
        // SAFETY: `out` is live; `id->user` is its live string.
        unsafe { ASN1_STRING_print(out, (*id).user) };
        i += 1;
    }
    1
}

/// `static SXNET *sxnet_v2i(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_sxnet.c:98-112`.
///
/// One `SXNET_add_id_asc` per `CONF_VALUE`, accumulating into a single `SXNET`; the first refusal
/// frees the partial value and answers NULL.
unsafe extern "C" fn sxnet_v2i(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let mut sx: *mut Sxnet = ptr::null_mut();
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `cnf` is live; each field is NULL or NUL-terminated.
        let ok = unsafe { SXNET_add_id_asc(&raw mut sx, (*cnf).name, (*cnf).value, -1) };
        if ok == 0 {
            // SAFETY: `sx` is the partial value this call owns.
            unsafe { SXNET_free(sx) };
            return ptr::null_mut();
        }
        i += 1;
    }
    sx.cast::<c_void>()
}

/// `int SXNET_add_id_asc(SXNET **psx, const char *zone, const char *user, int userlen)` —
/// `crypto/x509/v3_sxnet.c:120-133`.
///
/// # Safety
///
/// `psx` is a writable slot; `zone` and `user` are NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SXNET_add_id_asc(
    psx: *mut *mut Sxnet,
    zone: *const c_char,
    user: *const c_char,
    userlen: c_int,
) -> c_int {
    // SAFETY: `zone` is NULL or NUL-terminated per the contract.
    let izone = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), zone) };
    if izone.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_125) };
        return 0;
    }
    // SAFETY: `psx` is writable, `izone` is a fresh integer, `user` is NUL-terminated.
    if unsafe { SXNET_add_id_INTEGER(psx, izone, user, userlen) } == 0 {
        // SAFETY: `izone` is this call's own.
        unsafe { ASN1_INTEGER_free(izone) };
        return 0;
    }
    1
}

/// `int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, const char *user, int userlen)` —
/// `crypto/x509/v3_sxnet.c:137-153`.
///
/// # Safety
///
/// `psx` is a writable slot; `user` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SXNET_add_id_ulong(
    psx: *mut *mut Sxnet,
    lzone: c_ulong,
    user: *const c_char,
    userlen: c_int,
) -> c_int {
    let izone = ASN1_INTEGER_new();
    // SAFETY: `izone` is NULL or a fresh integer.
    if izone.is_null() || unsafe { ASN1_INTEGER_set(izone, lzone as c_long) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_144) };
        // SAFETY: `izone` is NULL or this call's own.
        unsafe { ASN1_INTEGER_free(izone) };
        return 0;
    }
    // SAFETY: `psx` is writable, `izone` is a fresh integer, `user` is NUL-terminated.
    if unsafe { SXNET_add_id_INTEGER(psx, izone, user, userlen) } == 0 {
        // SAFETY: `izone` is this call's own.
        unsafe { ASN1_INTEGER_free(izone) };
        return 0;
    }
    1
}

/// `int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *zone, const char *user, int userlen)` —
/// `crypto/x509/v3_sxnet.c:160-217`.
///
/// The caller hands ownership of `zone`; on success the identifier takes it and the caller must
/// not free it. `userlen == -1` measures `user`; over 64 it is refused.
///
/// # Safety
///
/// `psx` is a writable slot; `zone` is NULL or a live integer; `user` is NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SXNET_add_id_INTEGER(
    psx: *mut *mut Sxnet,
    zone: *mut Asn1String,
    user: *const c_char,
    userlen: c_int,
) -> c_int {
    if psx.is_null() || zone.is_null() || user.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_167) };
        return 0;
    }
    let mut userlen = userlen;
    if userlen == -1 {
        // SAFETY: `user` is NUL-terminated per the contract.
        userlen = unsafe { strlen(user) } as c_int;
    }
    if userlen > 64 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_173) };
        return 0;
    }
    let sx: *mut Sxnet;
    let mut id: *mut Sxnetid = ptr::null_mut();
    // SAFETY: `psx` is a writable slot per the contract.
    if unsafe { (*psx).is_null() } {
        sx = SXNET_new();
        if sx.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_SXNET_178) };
            // SAFETY: `id` is still NULL; the authority's `err:` frees `sx` only when `*psx` is NULL.
            unsafe {
                SXNETID_free(id);
                if (*psx).is_null() {
                    SXNET_free(sx);
                }
            }
            return 0;
        }
        // SAFETY: `sx` is a fresh value; `version` is its live integer.
        if unsafe { ASN1_INTEGER_set((*sx).version, 0) } == 0 {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_SXNET_182) };
            // SAFETY: `id` is still NULL; the authority's `err:` frees `sx` only when `*psx` is NULL.
            unsafe {
                SXNETID_free(id);
                if (*psx).is_null() {
                    SXNET_free(sx);
                }
            }
            return 0;
        }
    } else {
        // SAFETY: `psx` is a writable slot, and the branch proves `*psx` is non-NULL.
        sx = unsafe { *psx };
    }
    // SAFETY: `sx` is live; `zone` is a live integer.
    if !unsafe { SXNET_get_id_INTEGER(sx, zone) }.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_188) };
        // SAFETY: `(*psx)` is NULL, so this call owns `sx`; the authority frees it here.
        unsafe {
            if (*psx).is_null() {
                SXNET_free(sx);
            }
        }
        return 0;
    }
    id = SXNETID_new();
    if id.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_195) };
        // SAFETY: `id` is NULL; the authority's `err:` frees `sx` only when `*psx` is NULL.
        unsafe {
            SXNETID_free(id);
            if (*psx).is_null() {
                SXNET_free(sx);
            }
        }
        return 0;
    }
    // SAFETY: `id` is a fresh value; `user` is readable for `userlen` bytes.
    if unsafe { ASN1_OCTET_STRING_set((*id).user, user.cast::<c_uchar>(), userlen) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_200) };
        // SAFETY: `id` is this call's own; the authority's `err:` frees `sx` only when `*psx` is NULL.
        unsafe {
            SXNETID_free(id);
            if (*psx).is_null() {
                SXNET_free(sx);
            }
        }
        return 0;
    }
    // SAFETY: `sx` is live; `id` is a fresh identifier not yet owned by the stack.
    if unsafe { OPENSSL_sk_push((*sx).ids, id.cast::<c_void>()) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_204) };
        // SAFETY: the push failed, so `id` is not in the stack; `sx` is freed only when `*psx` is NULL.
        unsafe {
            SXNETID_free(id);
            if (*psx).is_null() {
                SXNET_free(sx);
            }
        }
        return 0;
    }
    // SAFETY: `id` is live and now owned by the stack; `zone` is transferred in.
    unsafe {
        ASN1_INTEGER_free((*id).zone);
        (*id).zone = zone;
        *psx = sx;
    }
    1
}

/// `ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, const char *zone)` —
/// `crypto/x509/v3_sxnet.c:219-231`.
///
/// # Safety
///
/// `sx` is a live `SXNET`; `zone` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SXNET_get_id_asc(sx: *mut Sxnet, zone: *const c_char) -> *mut Asn1String {
    // SAFETY: `zone` is NULL or NUL-terminated per the contract.
    let izone = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), zone) };
    if izone.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_225) };
        return ptr::null_mut();
    }
    // SAFETY: `sx` is live; `izone` is a live integer.
    let oct = unsafe { SXNET_get_id_INTEGER(sx, izone) };
    // SAFETY: `izone` is this call's own.
    unsafe { ASN1_INTEGER_free(izone) };
    oct
}

/// `ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone)` —
/// `crypto/x509/v3_sxnet.c:233-247`.
///
/// # Safety
///
/// `sx` is a live `SXNET`.
#[no_mangle]
pub unsafe extern "C" fn SXNET_get_id_ulong(sx: *mut Sxnet, lzone: c_ulong) -> *mut Asn1String {
    let izone = ASN1_INTEGER_new();
    // SAFETY: `izone` is NULL or a fresh integer.
    if izone.is_null() || unsafe { ASN1_INTEGER_set(izone, lzone as c_long) } == 0 {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_SXNET_240) };
        // SAFETY: `izone` is NULL or this call's own.
        unsafe { ASN1_INTEGER_free(izone) };
        return ptr::null_mut();
    }
    // SAFETY: `sx` is live; `izone` is a live integer.
    let oct = unsafe { SXNET_get_id_INTEGER(sx, izone) };
    // SAFETY: `izone` is this call's own.
    unsafe { ASN1_INTEGER_free(izone) };
    oct
}

/// `ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone)` —
/// `crypto/x509/v3_sxnet.c:249-259`.
///
/// # Safety
///
/// `sx` is a live `SXNET`; `zone` is a live integer.
#[no_mangle]
pub unsafe extern "C" fn SXNET_get_id_INTEGER(
    sx: *mut Sxnet,
    zone: *mut Asn1String,
) -> *mut Asn1String {
    // SAFETY: `sx` is live; `ids` is a live `STACK_OF(SXNETID)`.
    let num = unsafe { OPENSSL_sk_num((*sx).ids) };
    let mut i = 0;
    while i < num {
        // SAFETY: `sx->ids` is live and `i` is in bounds.
        let id = unsafe { OPENSSL_sk_value((*sx).ids, i) }.cast::<Sxnetid>();
        // SAFETY: `id` is live; `zone` is a live integer.
        if unsafe { ASN1_INTEGER_cmp((*id).zone, zone) } == 0 {
            // SAFETY: `id` is live.
            return unsafe { (*id).user };
        }
        i += 1;
    }
    ptr::null_mut()
}

/// `const X509V3_EXT_METHOD ossl_v3_sxnet` — `crypto/x509/v3_sxnet.c:28-41`.
///
/// `ext_flags` is `X509V3_EXT_MULTILINE`; `it`, `v2i` (the `sxnet_v2i` callback) and `i2r` (the
/// `sxnet_i2r` callback) are set; every other slot is zero.
pub static ossl_v3_sxnet: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_sxnet,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(SXNET_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(sxnet_v2i),
    i2r: Some(sxnet_i2r),
    r2i: None,
    usr_data: ptr::null_mut(),
};
