//! `crypto/ocsp/v3_ocsp.c` — the five OCSP extension tables. Phase 10.14.14's second unit, landed
//! whole.
//!
//! `crypto/ocsp/v3_ocsp.c` is 234 lines and transcribes whole:
//!
//! * The **five rows** land, in source order:
//!   [`ossl_v3_ocsp_crlid`] (`:42-49`, `NID_id_pkix_OCSP_CrlID`, item `OCSP_CRLID`, `i2r`
//!   [`i2r_ocsp_crlid`]);
//!   [`ossl_v3_ocsp_acutoff`] (`:51-58`, `NID_id_pkix_OCSP_archiveCutoff`, item
//!   `ASN1_GENERALIZEDTIME`, `i2r` [`i2r_ocsp_acutoff`]);
//!   [`ossl_v3_ocsp_nonce`] (`:60-70`, `NID_id_pkix_OCSP_Nonce`, no item — the nonce is raw octets
//!   with no ASN.1 encoding, so the row carries the `ext_new`/`ext_free`/`d2i`/`i2d` quartet plus `i2r`
//!   [`i2r_ocsp_nonce`]);
//!   [`ossl_v3_ocsp_nocheck`] (`:72-79`, `NID_id_pkix_OCSP_noCheck`, item `ASN1_NULL`, `s2i`
//!   [`s2i_ocsp_nocheck`] and `i2r` [`i2r_ocsp_nocheck`]);
//!   and [`ossl_v3_ocsp_serviceloc`] (`:81-88`, `NID_id_pkix_OCSP_serviceLocator`, item
//!   `OCSP_SERVICELOC`, `i2r` [`i2r_ocsp_serviceloc`]).
//! * The ten `static` callbacks those rows name land: the two forward-declared printers
//!   (`i2r_ocsp_crlid` `:90-121`, `i2r_ocsp_acutoff` `:123-131`), the nonce quartet
//!   (`ocsp_nonce_new` `:138-141`, `i2d_ocsp_nonce` `:143-151`, `d2i_ocsp_nonce` `:153-178`,
//!   `ocsp_nonce_free` `:180-183`) with its printer (`i2r_ocsp_nonce` `:185-193`), the nocheck pair
//!   (`i2r_ocsp_nocheck` `:197-201`, `s2i_ocsp_nocheck` `:203-207`), and `i2r_ocsp_serviceloc`
//!   (`:209-234`).
//! * The item groups `OCSP_CRLID`/`OCSP_SERVICELOC` are **not** defined here: they belong to
//!   `crypto/ocsp/ocsp_asn.c` and are already landed as
//!   [`crate::ocsp::ocsp_asn::OCSP_CRLID_it`]/[`crate::ocsp::ocsp_asn::OCSP_SERVICELOC_it`]. The two
//!   rows reference them, exactly as the authority's `ASN1_ITEM_ref` does — this unit redefines
//!   neither.
//!
//! **Withheld by name**: `standard_exts[]` (`crypto/x509/standard_exts.h:15-95`) and the six lookup
//! names in `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`, `X509V3_EXT_get`, `X509V3_EXT_add_alias`,
//! `X509V3_EXT_d2i`, `X509V3_get_d2i`, `X509V3_add1_i2d`). A partial array would silently change
//! `OBJ_bsearch_ext` for every missing NID (D456), so the array is withheld until all 63 tables
//! exist; this unit contributes five of them, and neither creates nor references the array. The rows
//! themselves are internal data the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); the
//! callbacks are the drivable surface. Nothing else is withheld: every `static` helper and every row
//! in the unit lands.
//!
//! ## The raise site
//!
//! `crypto/ocsp/v3_ocsp.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its one
//! coordinate is **declared locally** with the `err_sites::ErrSite` shape, as `v3_pcons.rs` does. Its
//! library and reason are read from the authority's own `err.h.in` (`ERR_LIB_OCSP` is 39 at `:104`;
//! `ERR_R_ASN1_LIB` is `ERR_LIB_ASN1 | ERR_RFLAG_COMMON` = 524301 at `:328`), not typed from memory.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::a_print::ASN1_STRING_print;
use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::asn1::items::{ASN1_GENERALIZEDTIME_it, ASN1_NULL_it};
use crate::asn1::layout::{Asn1String, V_ASN1_OCTET_STRING};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_OBJECT, i2a_ASN1_STRING};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::asn1::typ::ASN1_NULL_new;
use crate::ocsp::ocsp_asn::{OCSP_CRLID_it, OCSP_SERVICELOC_it, OcspCrlId, OcspServiceLoc};
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::err::raise_site;
use crate::runtime::obj::{
    NID_id_pkix_OCSP_CrlID, NID_id_pkix_OCSP_Nonce, NID_id_pkix_OCSP_archiveCutoff,
    NID_id_pkix_OCSP_noCheck, NID_id_pkix_OCSP_serviceLocator,
};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::v3_info::AccessDescription;
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_san::GENERAL_NAME_print;

/// `ERR_LIB_OCSP` — `include/openssl/err.h.in:104`.
const ERR_LIB_OCSP: c_int = 39;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h.in:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_ocsp.c` raise coordinate, declared locally (see the module doc).
const fn v3_ocsp_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/ocsp/v3_ocsp.c",
        line,
        func,
        lib: ERR_LIB_OCSP,
        reason,
        dynamic_reason: false,
    }
}

/// `d2i_ocsp_nonce`'s allocation/set failure at `v3_ocsp.c:176`. The `err:` label's single
/// `ERR_raise(ERR_LIB_OCSP, ERR_R_ASN1_LIB)`; both the allocation-failure and the
/// `ASN1_OCTET_STRING_set`-failure arms reach it.
const V3_OCSP_176: crate::runtime::err::err_sites::ErrSite =
    v3_ocsp_site(176, c"d2i_ocsp_nonce", ERR_R_ASN1_LIB);

// ---------------------------------------------------------------------------------------------
// The callbacks
// ---------------------------------------------------------------------------------------------

/// `static int i2r_ocsp_crlid(const X509V3_EXT_METHOD *method, void *in, BIO *bp, int ind)` —
/// `crypto/ocsp/v3_ocsp.c:90-121`.
///
/// Prints whichever of `crlUrl`/`crlNum`/`crlTime` are present, each prefixed by an `ind`-space
/// indent and suffixed by a newline. Every write is a refusal arm: a non-positive answer aborts
/// with 0.
unsafe extern "C" fn i2r_ocsp_crlid(
    _method: *const X509V3ExtMethod,
    in_: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    let a = in_.cast::<OcspCrlId>();
    // SAFETY: `a` is a live `OCSP_CRLID` per the caller's contract.
    let (crl_url, crl_num, crl_time) = unsafe { ((*a).crlUrl, (*a).crlNum, (*a).crlTime) };
    if !crl_url.is_null() {
        // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
        if unsafe { BIO_printf(bp, c"%*scrlUrl: ".as_ptr(), ind, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `bp` is live and `crl_url` is a live `ASN1_IA5STRING`.
        if unsafe { ASN1_STRING_print(bp, crl_url) } == 0 {
            return 0;
        }
        // SAFETY: `bp` is live; the literal is static.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
            return 0;
        }
    }
    if !crl_num.is_null() {
        // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
        if unsafe { BIO_printf(bp, c"%*scrlNum: ".as_ptr(), ind, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `bp` is live and `crl_num` is a live `ASN1_INTEGER`.
        if unsafe { i2a_ASN1_INTEGER(bp, crl_num) } <= 0 {
            return 0;
        }
        // SAFETY: `bp` is live; the literal is static.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
            return 0;
        }
    }
    if !crl_time.is_null() {
        // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
        if unsafe { BIO_printf(bp, c"%*scrlTime: ".as_ptr(), ind, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `bp` is live and `crl_time` is a live `ASN1_GENERALIZEDTIME`.
        if unsafe { ASN1_GENERALIZEDTIME_print(bp, crl_time) } == 0 {
            return 0;
        }
        // SAFETY: `bp` is live; the literal is static.
        if unsafe { BIO_write(bp, c"\n".as_ptr().cast(), 1) } <= 0 {
            return 0;
        }
    }
    1
}

/// `static int i2r_ocsp_acutoff(const X509V3_EXT_METHOD *method, void *cutoff, BIO *bp, int ind)` —
/// `crypto/ocsp/v3_ocsp.c:123-131`.
///
/// Indents, then prints the `ASN1_GENERALIZEDTIME` itself (no field label, no trailing newline).
unsafe extern "C" fn i2r_ocsp_acutoff(
    _method: *const X509V3ExtMethod,
    cutoff: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
    if unsafe { BIO_printf(bp, c"%*s".as_ptr(), ind, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `cutoff` is a live `ASN1_GENERALIZEDTIME` and `bp` is live.
    if unsafe { ASN1_GENERALIZEDTIME_print(bp, cutoff.cast::<Asn1String>()) } == 0 {
        return 0;
    }
    1
}

/// `static void *ocsp_nonce_new(void)` — `crypto/ocsp/v3_ocsp.c:138-141`.
///
/// The nonce has no ASN.1 item, so the row supplies its own allocator: a bare
/// `ASN1_OCTET_STRING_new`.
unsafe extern "C" fn ocsp_nonce_new() -> *mut c_void {
    ASN1_OCTET_STRING_new().cast::<c_void>()
}

/// `static int i2d_ocsp_nonce(const void *a, unsigned char **pp)` — `crypto/ocsp/v3_ocsp.c:143-151`.
///
/// Not an ASN.1 encoder: it copies the octet string's raw bytes to `*pp` and advances the cursor,
/// returning the length. A NULL `pp` only measures.
unsafe extern "C" fn i2d_ocsp_nonce(a: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    let os = a.cast::<Asn1String>();
    // SAFETY: `os` is a live `ASN1_OCTET_STRING` per the caller's contract.
    let (data, length) = unsafe { ((*os).data, (*os).length) };
    if !pp.is_null() && length > 0 {
        // SAFETY: `pp` points at a writable cursor and `*pp` has room for `length` bytes per the
        // encoder contract; `data` holds `length` readable bytes.
        unsafe {
            ptr::copy_nonoverlapping(data, *pp, length as usize);
            *pp = (*pp).add(length as usize);
        }
    }
    length
}

/// `static void *d2i_ocsp_nonce(void *a, const unsigned char **pp, long length)` —
/// `crypto/ocsp/v3_ocsp.c:153-178`.
///
/// Decodes the raw octets into an `ASN1_OCTET_STRING`, reusing the slot at `*a` when one is given
/// (and writing the result back), and advancing `*pp` by `length`. Any failure raises
/// [`V3_OCSP_176`] and answers NULL.
unsafe extern "C" fn d2i_ocsp_nonce(
    a: *mut c_void,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut c_void {
    let pos = a.cast::<*mut Asn1String>();
    let os;
    // SAFETY: `pos` is NULL or a writable slot per the caller's contract; the short-circuit reads
    // `*pos` only when `pos` is non-NULL.
    if pos.is_null() || unsafe { (*pos).is_null() } {
        os = ASN1_OCTET_STRING_new();
        if os.is_null() {
            // The authority's `goto err` with `os == NULL` frees nothing.
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_OCSP_176) };
            return ptr::null_mut();
        }
    } else {
        // SAFETY: `pos` is non-NULL and its slot holds a live value per the contract.
        os = unsafe { *pos };
    }
    // SAFETY: `os` is a live `ASN1_OCTET_STRING`; `pp` points at a readable cursor and `length`
    // bytes are readable from `*pp`.
    if unsafe { ASN1_OCTET_STRING_set(os, *pp, length as c_int) } == 0 {
        // SAFETY: `pos` is NULL or a live slot; `os` is live, so the comparison reads no freed
        // memory.
        if pos.is_null() || unsafe { *pos != os } {
            // SAFETY: `os` is a live value this call owns.
            unsafe { ASN1_OCTET_STRING_free(os) };
        }
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_OCSP_176) };
        return ptr::null_mut();
    }
    // SAFETY: `pp` points at a readable cursor holding `length` readable bytes.
    unsafe { *pp = (*pp).add(length as usize) };
    if !pos.is_null() {
        // SAFETY: `pos` is a writable slot per the contract.
        unsafe { *pos = os };
    }
    os.cast::<c_void>()
}

/// `static void ocsp_nonce_free(void *a)` — `crypto/ocsp/v3_ocsp.c:180-183`.
///
/// # Safety
///
/// `a` is NULL or an `ASN1_OCTET_STRING` this unit's [`d2i_ocsp_nonce`]/[`ocsp_nonce_new`] made.
unsafe extern "C" fn ocsp_nonce_free(a: *mut c_void) {
    // SAFETY: `a` is NULL or a live octet string per the contract.
    unsafe { ASN1_OCTET_STRING_free(a.cast::<Asn1String>()) };
}

/// `static int i2r_ocsp_nonce(const X509V3_EXT_METHOD *method, void *nonce, BIO *out, int indent)` —
/// `crypto/ocsp/v3_ocsp.c:185-193`.
///
/// Indents, then spells the bytes through `i2a_ASN1_STRING` as an `OCTET STRING`.
unsafe extern "C" fn i2r_ocsp_nonce(
    _method: *const X509V3ExtMethod,
    nonce: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `out` is a live BIO; the format and its arguments are compile-time constants.
    if unsafe { BIO_printf(out, c"%*s".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `nonce` is a live `ASN1_OCTET_STRING` and `out` is live.
    if unsafe { i2a_ASN1_STRING(out, nonce.cast::<Asn1String>(), V_ASN1_OCTET_STRING) } <= 0 {
        return 0;
    }
    1
}

/// `static int i2r_ocsp_nocheck(const X509V3_EXT_METHOD *method, void *nocheck, BIO *out, int
/// indent)` — `crypto/ocsp/v3_ocsp.c:197-201`.
///
/// Nocheck is a single NULL; the authority prints nothing and always succeeds.
unsafe extern "C" fn i2r_ocsp_nocheck(
    _method: *const X509V3ExtMethod,
    _nocheck: *mut c_void,
    _out: *mut Bio,
    _indent: c_int,
) -> c_int {
    1
}

/// `static void *s2i_ocsp_nocheck(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char
/// *str)` — `crypto/ocsp/v3_ocsp.c:203-207`.
///
/// The text form contributes nothing; the value is always a fresh `ASN1_NULL`.
unsafe extern "C" fn s2i_ocsp_nocheck(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    _str: *const c_char,
) -> *mut c_void {
    ASN1_NULL_new().cast::<c_void>()
}

/// `static int i2r_ocsp_serviceloc(const X509V3_EXT_METHOD *method, void *in, BIO *bp, int ind)` —
/// `crypto/ocsp/v3_ocsp.c:209-234`.
///
/// Prints `Issuer:`, then the issuer name on one line, then one `method - location` line per
/// `ACCESS_DESCRIPTION` in the locator stack, each indented by `2 * ind`. Every write is a refusal
/// arm.
unsafe extern "C" fn i2r_ocsp_serviceloc(
    _method: *const X509V3ExtMethod,
    in_: *mut c_void,
    bp: *mut Bio,
    ind: c_int,
) -> c_int {
    let a = in_.cast::<OcspServiceLoc>();
    // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
    if unsafe { BIO_printf(bp, c"%*sIssuer: ".as_ptr(), ind, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `a` is a live `OCSP_SERVICELOC` per the caller's contract; `bp` is live.
    if unsafe { X509_NAME_print_ex(bp, (*a).issuer, 0, XN_FLAG_ONELINE) } <= 0 {
        return 0;
    }
    // SAFETY: `a` is live; the `locator` stack is NULL or live.
    let num = unsafe { OPENSSL_sk_num((*a).locator) };
    let mut i = 0;
    while i < num {
        // SAFETY: `a` is live and `i` is in bounds.
        let ad = unsafe { OPENSSL_sk_value((*a).locator, i) }.cast::<AccessDescription>();
        // SAFETY: `bp` is a live BIO; the format and its arguments are compile-time constants.
        if unsafe { BIO_printf(bp, c"\n%*s".as_ptr(), 2 * ind, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `ad` is a live `ACCESS_DESCRIPTION` and `bp` is live.
        if unsafe { i2a_ASN1_OBJECT(bp, (*ad).method) } <= 0 {
            return 0;
        }
        // SAFETY: `bp` is live; the literal is static.
        if unsafe { BIO_puts(bp, c" - ".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `ad` is live and `bp` is live.
        if unsafe { GENERAL_NAME_print(bp, (*ad).location) } <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The rows
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_crlid` — `crypto/ocsp/v3_ocsp.c:42-49`.
///
/// `it` is `ASN1_ITEM_ref(OCSP_CRLID)`; `i2r` is [`i2r_ocsp_crlid`]; every other slot is zero.
pub static ossl_v3_ocsp_crlid: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_pkix_OCSP_CrlID,
    ext_flags: 0,
    it: Some(OCSP_CRLID_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ocsp_crlid),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_acutoff` — `crypto/ocsp/v3_ocsp.c:51-58`.
///
/// `it` is `ASN1_ITEM_ref(ASN1_GENERALIZEDTIME)`; `i2r` is [`i2r_ocsp_acutoff`]; every other slot is
/// zero.
pub static ossl_v3_ocsp_acutoff: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_pkix_OCSP_archiveCutoff,
    ext_flags: 0,
    it: Some(ASN1_GENERALIZEDTIME_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ocsp_acutoff),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_nonce` — `crypto/ocsp/v3_ocsp.c:60-70`.
///
/// No item (`it` is NULL): the nonce is raw octets, so the row carries its own
/// [`ocsp_nonce_new`]/[`ocsp_nonce_free`]/[`d2i_ocsp_nonce`]/[`i2d_ocsp_nonce`] quartet and the
/// [`i2r_ocsp_nonce`] printer.
pub static ossl_v3_ocsp_nonce: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_pkix_OCSP_Nonce,
    ext_flags: 0,
    it: None,
    ext_new: Some(ocsp_nonce_new),
    ext_free: Some(ocsp_nonce_free),
    d2i: Some(d2i_ocsp_nonce),
    i2d: Some(i2d_ocsp_nonce),
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ocsp_nonce),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_nocheck` — `crypto/ocsp/v3_ocsp.c:72-79`.
///
/// `it` is `ASN1_ITEM_ref(ASN1_NULL)`; `s2i` is [`s2i_ocsp_nocheck`]; `i2r` is
/// [`i2r_ocsp_nocheck`]; every other slot is zero.
pub static ossl_v3_ocsp_nocheck: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_pkix_OCSP_noCheck,
    ext_flags: 0,
    it: Some(ASN1_NULL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: Some(s2i_ocsp_nocheck),
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ocsp_nocheck),
    r2i: None,
    usr_data: ptr::null_mut(),
};

/// `const X509V3_EXT_METHOD ossl_v3_ocsp_serviceloc` — `crypto/ocsp/v3_ocsp.c:81-88`.
///
/// `it` is `ASN1_ITEM_ref(OCSP_SERVICELOC)`; `i2r` is [`i2r_ocsp_serviceloc`]; every other slot is
/// zero.
pub static ossl_v3_ocsp_serviceloc: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_id_pkix_OCSP_serviceLocator,
    ext_flags: 0,
    it: Some(OCSP_SERVICELOC_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_ocsp_serviceloc),
    r2i: None,
    usr_data: ptr::null_mut(),
};
