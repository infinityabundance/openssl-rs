//! `crypto/x509/v3_authattid.c` — the authority attribute identifier item group and its row.
//! Phase 10.14's blocked-unit pivots, landed whole.
//!
//! `crypto/x509/v3_authattid.c` is 79 lines and transcribes whole:
//!
//! * `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX ::= SEQUENCE OF OSSL_ISSUER_SERIAL` — the
//!   `ASN1_ITEM_TEMPLATE`/`ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
//!   OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX, OSSL_ISSUER_SERIAL)` (`:19`) with its
//!   `ASN1_ITEM_TEMPLATE_END` (`:20`). The value type is `STACK_OF(OSSL_ISSUER_SERIAL)`
//!   (`include/openssl/x509_acert.h:275`), and `IMPLEMENT_ASN1_FUNCTIONS` (`:22`) emits the
//!   `_it`/`_new`/`_free`/`d2i_`/`i2d_` group (`IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname` plus
//!   `IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname`, `include/openssl/asn1t.h:808-810`; all five are
//!   declared at `x509_acert.h:276`). There is no `_dup`: the macro pair does not emit one.
//! * The two `static` printers land: [`i2r_ISSUER_SERIAL`] (`:24-48`) and [`i2r_auth_attr_id`]
//!   (`:50-67`).
//! * The row [`ossl_v3_authority_attribute_identifier`] (`:69-79`) lands,
//!   `NID_authority_attribute_identifier` (`obj_mac.h:2780`, `1295`), `X509V3_EXT_MULTILINE`, the
//!   item accessor and `i2r` set; every other slot is zero.
//!
//! ## The one reachability edge, and the type it reads
//!
//! The `OSSL_ISSUER_SERIAL` element item is **not** defined by this unit: the authority reaches it
//! through the `DECLARE_ASN1_ITEM(OSSL_ISSUER_SERIAL)` at `:17`, and its descriptor is the
//! `static_ASN1_SEQUENCE_END(OSSL_ISSUER_SERIAL)` of `crypto/x509/v3_ac_tgt.c:47`. The crate lands
//! that item as the file-local `fn ossl_issuer_serial_it` in [`crate::x509::v3_ac_tgt`]; this
//! module is the one caller the authority has, so that accessor is made `pub(crate)` and reached as
//! `ossl_issuer_serial_it()`, and the struct is [`crate::x509::v3_ac_tgt::OsslIssuerSerial`]. No
//! other name in that unit's closure is missing.
//!
//! The `_new`/`_free`/`d2i_`/`i2d_` group for `OSSL_ISSUER_SERIAL` is `crypto/x509/x509_acert.c`'s
//! (this unit only reaches the item, never those functions), so nothing here calls it.
//!
//! **Withheld by name**: `standard_exts[]` (`crypto/x509/standard_exts.h:15-95`) and the six lookup
//! names in `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/
//! `_add1_i2d`). A partial array would silently change `OBJ_bsearch_ext` for every missing NID
//! (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does not
//! export (`nm -D` shows no `ossl_v3_*`); the item group and the two printers are the drivable
//! surface.
//!
//! ## No raise
//!
//! Neither printer raises: `i2r_ISSUER_SERIAL` reports a failed `i2a_ASN1_INTEGER`/`i2a_ASN1_STRING`
//! by returning `0`, and `i2r_auth_attr_id` propagates it. `crypto/x509/v3_authattid.c` therefore
//! has an empty raise set and is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`; no `ErrSite` is declared here.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::{i2a_ASN1_INTEGER, i2a_ASN1_STRING};
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_authority_attribute_identifier;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_ac_tgt::{ossl_issuer_serial_it, OsslIssuerSerial};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_utl::OSSL_GENERAL_NAMES_print;

/// `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_item_tt` — `ASN1_ITEM_TEMPLATE(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)`'s
/// single template (`crypto/x509/v3_authattid.c:19`): `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
/// OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX, OSSL_ISSUER_SERIAL)`. The element item is the file-local
/// accessor [`ossl_issuer_serial_it`], reached through the crate's `pub(crate)` visibility.
static OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX".as_ptr(),
    item: ossl_issuer_serial_it as *mut c_void,
};

/// `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it`'s descriptor —
/// `ASN1_ITEM_TEMPLATE_END(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)` at `crypto/x509/v3_authattid.c:20`:
/// a `PRIMITIVE` item whose single template is a `SEQUENCE OF`, with `utype` `-1` and `tcount` 0.
static OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it(void)` —
/// `include/openssl/x509_acert.h:276`, from `ASN1_ITEM_TEMPLATE_END(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it() -> *const Asn1Item {
    &OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_ITEM
}

/// `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX *OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new(void)` —
/// `crypto/x509/v3_authattid.c:22`, from `IMPLEMENT_ASN1_FUNCTIONS`' allocator half. The value type
/// is `STACK_OF(OSSL_ISSUER_SERIAL)`.
#[no_mangle]
pub extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX *a)` — the same
/// macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it()) }
}

/// `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX *d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(
/// OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX **a, const unsigned char **in, long len)` — the same macro's
/// decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it())
            .cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(const OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX *a,
/// unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it()) }
}

/// `static int i2r_ISSUER_SERIAL(X509V3_EXT_METHOD *method, OSSL_ISSUER_SERIAL *iss, BIO *out,
/// int indent)` — `crypto/x509/v3_authattid.c:24-48`.
///
/// # Safety
///
/// `iss` is a live `OSSL_ISSUER_SERIAL`; `out` is a live BIO.
unsafe extern "C" fn i2r_ISSUER_SERIAL(
    _method: *const X509V3ExtMethod,
    iss: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let iss = iss.cast::<OsslIssuerSerial>();
    // SAFETY: `iss` is live per the contract.
    if !unsafe { (*iss).issuer }.is_null() {
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*sIssuer Names:\n".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live and `iss`'s `issuer` is a live `GENERAL_NAMES`.
        unsafe { OSSL_GENERAL_NAMES_print(out, (*iss).issuer, indent) };
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe {
            BIO_printf(
                out,
                c"%*sIssuer Names: <none>\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    }
    // SAFETY: `out` is live; the format and its argument are constants.
    unsafe { BIO_printf(out, c"%*sIssuer Serial: ".as_ptr(), indent, c"".as_ptr()) };
    // SAFETY: `out` and `iss` are live; the embedded integer is at `serial`.
    if unsafe { i2a_ASN1_INTEGER(out, &raw const (*iss).serial) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is live; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) };
    // SAFETY: `iss` is live.
    if !unsafe { (*iss).issuerUID }.is_null() {
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*sIssuer UID: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` and `iss` are live; `issuerUID` is a live bit string.
        if unsafe { i2a_ASN1_STRING(out, (*iss).issuerUID, V_ASN1_BIT_STRING) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        unsafe { BIO_puts(out, c"\n".as_ptr()) };
    } else {
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe {
            BIO_printf(
                out,
                c"%*sIssuer UID: <none>\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        };
    }
    1
}

/// `static int i2r_auth_attr_id(X509V3_EXT_METHOD *method, OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX *aids,
/// BIO *out, int indent)` — `crypto/x509/v3_authattid.c:50-67`.
///
/// # Safety
///
/// `aids` is a live `OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX` (a `STACK_OF(OSSL_ISSUER_SERIAL)`); `out`
/// is a live BIO.
unsafe extern "C" fn i2r_auth_attr_id(
    method: *const X509V3ExtMethod,
    aids: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let aids = aids.cast::<OpenSslStack>();
    // SAFETY: `aids` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(aids) };
    let mut i = 0;
    while i < num {
        // SAFETY: `out` is live; the format and its argument are constants.
        if unsafe { BIO_printf(out, c"%*sIssuer-Serials:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `aids` is live and `i` is in bounds; the element is an `OSSL_ISSUER_SERIAL`.
        let aid = unsafe { OPENSSL_sk_value(aids, i) };
        // SAFETY: `method` and `out` are the caller's; `aid` is the live element just read.
        if unsafe { i2r_ISSUER_SERIAL(method, aid, out, indent + 4) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_authority_attribute_identifier` —
/// `crypto/x509/v3_authattid.c:69-79`.
///
/// `NID_authority_attribute_identifier`, `X509V3_EXT_MULTILINE`, item
/// [`OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it`] and the [`i2r_auth_attr_id`] printer; every other slot
/// is zero.
pub static ossl_v3_authority_attribute_identifier: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_authority_attribute_identifier,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_auth_attr_id),
    r2i: None,
    usr_data: ptr::null_mut(),
};
