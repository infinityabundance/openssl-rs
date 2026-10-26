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
///
/// # Safety
///
/// Installed as `ossl_v3_ocsp_crlid.i2r` and invoked only by `X509V3_EXT_print`
/// (`src/x509/v3_prn.rs`), which establishes the preconditions: `_method` is this row (unread),
/// `in` is the live `OCSP_CRLID` that row's `it` decoder produced (borrowed for the call, never
/// retained) and `bp` is a live BIO owned by the caller. Each field pointer is NULL or the live
/// `ASN1_IA5STRING`/`ASN1_INTEGER`/`ASN1_GENERALIZEDTIME` the decoder installed, borrowed for the
/// call only.
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
///
/// # Safety
///
/// Installed as `ossl_v3_ocsp_nonce.i2d` and invoked only by `do_ext_i2d`
/// (`src/x509/v3_conf.rs`), which establishes the twice-pass encoder contract: the first call
/// passes `pp == NULL` to size the output, and the second passes `*pp` pointing at a writable
/// cursor with room for the `length` bytes this function returns. `a` is the octet string
/// [`d2i_ocsp_nonce`] decoded (or one the caller owns), live for the call and borrowed only.
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
///
/// # Safety
///
/// Invoked by `X509V3_EXT_d2i`/`X509V3_EXT_print` (`src/x509/v3_lib.rs`, `src/x509/v3_prn.rs`) with
/// `a` NULL (allocate) or pointing at a live `ASN1_OCTET_STRING *` slot whose value is NULL or an
/// octet string the caller owns, and with `pp` pointing at a readable cursor holding at least
/// `length` bytes, where `0 <= length <= c_int::MAX` (the authority narrows `long` to `int` in
/// `ASN1_OCTET_STRING_set`; a larger `length` is outside the caller's contract). On success the
/// decoded value is stored through `a` when `a` is non-NULL, and the caller owns it; on failure a
/// caller-supplied value is left untouched and nothing this call allocated is leaked.
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
        #[cfg(test)]
        nonce_probe::created(os.cast::<c_void>());
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
            #[cfg(test)]
            nonce_probe::released(os.cast::<c_void>());
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
    #[cfg(test)]
    nonce_probe::released(a);
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
///
/// It is a safe `extern "C" fn`: no argument is read, so no caller precondition exists and a safe
/// fn coerces to the `unsafe extern "C" fn` slot `X509V3ExtMethod::s2i` stores. The value it
/// answers is the returned pointer's own (a fresh `ASN1_NULL`, released by the caller).
extern "C" fn s2i_ocsp_nocheck(
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
///
/// # Safety
///
/// Installed as `ossl_v3_ocsp_serviceloc.i2r` and invoked only by `X509V3_EXT_print`, which
/// establishes the preconditions: `_method` is this row (unread), `in` is the live
/// `OCSP_SERVICELOC` that row's `it` decoder produced (borrowed for the call, never retained) and
/// `bp` is a live BIO owned by the caller. `issuer` and every `locator` element are the decoder's
/// own borrowed members; this callback retains neither.
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

// ---------------------------------------------------------------------------------------------
// Test-only observation of the nonce object's lifetime
// ---------------------------------------------------------------------------------------------

/// Address-indexed observation of the octet string [`d2i_ocsp_nonce`] creates and releases.
///
/// The campaign cannot install a counting allocator in the ordinary suite (that is a
/// process-global act reserved for the `adv_alloc` probes), so the two release sites record the
/// **address** they release here, and [`nonce_probe::created`] records the address the decode
/// allocated. A test can then assert that the address released is the address created, exactly
/// once, instead of counting every release in a window. Thread-local, so concurrent tests cannot
/// contribute, and compiled out of every non-test build.
#[cfg(test)]
mod nonce_probe {
    use core::cell::RefCell;
    use core::ffi::c_void;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Event {
        Created(usize),
        Released(usize),
    }

    thread_local! {
        static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    /// Forget every observation made on this thread.
    pub(super) fn reset() {
        EVENTS.with(|events| events.borrow_mut().clear());
    }

    /// Record that the decode allocated an octet string at `p` (NULL records nothing).
    pub(super) fn created(p: *mut c_void) {
        if !p.is_null() {
            EVENTS.with(|events| events.borrow_mut().push(Event::Created(p as usize)));
        }
    }

    /// Record that `p` is about to be released (NULL records nothing).
    pub(super) fn released(p: *mut c_void) {
        if !p.is_null() {
            EVENTS.with(|events| events.borrow_mut().push(Event::Released(p as usize)));
        }
    }

    /// Everything observed on this thread since the last [`reset`].
    pub(super) fn events() -> Vec<Event> {
        EVENTS.with(|events| events.borrow().clone())
    }
}

#[cfg(test)]
mod nonce_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::nonce_probe::{self, Event};
    use super::*;

    /// `d2i_ocsp_nonce` decodes the raw octets and advances the cursor by exactly `length`; the
    /// decoded object is released exactly once, at the address the decode returned.
    #[test]
    fn asn1_ocsp_nonce_decode_release_is_exactly_once_at_the_decoded_address() {
        nonce_probe::reset();
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let mut pp: *const c_uchar = data.as_ptr();
        // SAFETY: a NULL `a` asks for a fresh octet string; `pp` is readable for four bytes.
        let a = unsafe { d2i_ocsp_nonce(ptr::null_mut(), &mut pp, 4) };
        assert!(!a.is_null(), "the decode must answer the octet string");
        assert_eq!(
            pp as usize,
            // SAFETY: `data` is a four-byte array and the decode advanced by its length.
            unsafe { data.as_ptr().add(4) } as usize,
            "the cursor advances past the decoded octets"
        );
        // SAFETY: `a` is the fresh object this call produced and this frame owns.
        let (length, first) = unsafe {
            let os = a.cast::<Asn1String>();
            ((*os).length, *(*os).data)
        };
        assert_eq!((length, first), (4, 0x01));
        assert_eq!(
            nonce_probe::events(),
            vec![Event::Created(a as usize)],
            "the decode records exactly the object it created"
        );

        nonce_probe::reset();
        // SAFETY: `a` is live and this frame owns it; `ocsp_nonce_free` is its single release.
        unsafe { ocsp_nonce_free(a) };
        assert_eq!(
            nonce_probe::events(),
            vec![Event::Released(a as usize)],
            "the release names the decoded address, exactly once"
        );

        // A second release of the cleared slot is the NULL no-op: nothing is released again.
        // SAFETY: NULL is the documented no-op input.
        unsafe { ocsp_nonce_free(ptr::null_mut()) };
        assert_eq!(
            nonce_probe::events(),
            vec![Event::Released(a as usize)],
            "a NULL release adds no second release"
        );
    }

    /// A `set` failure after the octet string was allocated releases exactly that object, once,
    /// before answering NULL: the partial initialisation owns no second resource and leaks none.
    #[test]
    fn asn1_ocsp_nonce_set_failure_releases_the_new_string_exactly_once() {
        nonce_probe::reset();
        let data = [0x00u8];
        let mut pp: *const c_uchar = data.as_ptr();
        // `INT_MAX` exceeds `ASN1_STRING_set`'s `INT_MAX - 1` guard, so the set fails after the
        // octet string was allocated -- the allocation-refusal/partial-init arm without a hook.
        // SAFETY: a NULL `a` asks for a fresh octet string; the set fails before reading `pp`.
        let r = unsafe { d2i_ocsp_nonce(ptr::null_mut(), &mut pp, c_int::MAX as c_long) };
        assert!(r.is_null(), "a refused set answers NULL");
        let events = nonce_probe::events();
        assert_eq!(events.len(), 2, "one creation, one release: {events:?}");
        match (events[0], events[1]) {
            (Event::Created(created), Event::Released(released)) => assert_eq!(
                created, released,
                "the release must name the object the decode created"
            ),
            other => panic!("unexpected nonce events: {other:?}"),
        }
        assert_eq!(
            pp as usize,
            data.as_ptr() as usize,
            "a failed set does not advance the cursor"
        );
    }

    /// A `set` failure over a caller-supplied object leaves that object owned by the caller: the
    /// failure path releases nothing, so a later single release is the first.
    #[test]
    fn asn1_ocsp_nonce_set_failure_leaves_a_caller_object_untouched() {
        nonce_probe::reset();
        // SAFETY: a fresh octet string this test owns.
        let mut os = ASN1_OCTET_STRING_new();
        assert!(!os.is_null());
        let addr = os as usize;
        let slot = (&raw mut os).cast::<c_void>();
        let data = [0x00u8];
        let mut pp: *const c_uchar = data.as_ptr();
        // SAFETY: `slot` points at a live `ASN1_OCTET_STRING *`; `pp` is readable for the length.
        let r = unsafe { d2i_ocsp_nonce(slot, &mut pp, c_int::MAX as c_long) };
        assert!(r.is_null());
        assert_eq!(
            os as usize, addr,
            "the caller's slot still names its object"
        );
        assert_eq!(
            nonce_probe::events(),
            Vec::new(),
            "a caller-supplied object is neither released nor adopted"
        );
        // SAFETY: `os` is the live object this test still owns; this is its first release.
        unsafe { ocsp_nonce_free(os.cast::<c_void>()) };
        assert_eq!(nonce_probe::events(), vec![Event::Released(addr)]);
    }
}
