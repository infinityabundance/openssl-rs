//! `crypto/x509/v3_rolespec.c` — the `OSSL_ROLE_SPEC_CERT_ID_SYNTAX` item group and its row.
//! Phase 10.14.8's table layer, landed whole.
//!
//! `crypto/x509/v3_rolespec.c` is 95 lines and transcribes whole:
//!
//! * `OSSL_ROLE_SPEC_CERT_ID ::= SEQUENCE { roleName [0] EXPLICIT GENERAL_NAME,
//!   roleCertIssuer [1] EXPLICIT GENERAL_NAME, roleCertSerialNumber [2] IMPLICIT ASN1_INTEGER
//!   OPTIONAL, roleCertLocator [3] IMPLICIT SEQUENCE OF GENERAL_NAME OPTIONAL }` (`:15-20`),
//!   closing with the non-`static_` `ASN1_SEQUENCE_END`, so `OSSL_ROLE_SPEC_CERT_ID_it` is an
//!   export.
//! * `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ROLE_SPEC_CERT_ID)` (`:22`) — the `_new`/`_free`/`d2i_`/
//!   `i2d_` group. All five names are declared by `DECLARE_ASN1_FUNCTIONS(OSSL_ROLE_SPEC_CERT_ID)`
//!   at `x509v3.h.in:1083` and are exported by the admitted DSO (`nm -D` lists all five).
//! * `OSSL_ROLE_SPEC_CERT_ID_SYNTAX ::= SEQUENCE OF OSSL_ROLE_SPEC_CERT_ID` via
//!   `ASN1_ITEM_TEMPLATE`/`ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
//!   OSSL_ROLE_SPEC_CERT_ID_SYNTAX, OSSL_ROLE_SPEC_CERT_ID)` (`:24-26`), and its
//!   `IMPLEMENT_ASN1_FUNCTIONS` group (`:28`). The value type is `STACK_OF(OSSL_ROLE_SPEC_CERT_ID)`
//!   (`x509v3.h.in:1091`). All five names are declared at `x509v3.h.in:1093` and exported.
//! * `i2r_OSSL_ROLE_SPEC_CERT_ID` (`:30-61`) and `i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX` (`:63-83`),
//!   the two `static` printers. The first reaches `GENERAL_NAME_print` (`v3_san.rs`),
//!   `ossl_serial_number_print` (`t_x509.rs`, the Phase 10.14.8 prerequisite) and
//!   `OSSL_GENERAL_NAMES_print` (`v3_utl.rs`); the second walks the stack with the
//!   `sk_OSSL_ROLE_SPEC_CERT_ID_num`/`_value` macros (`OPENSSL_sk_num`/`OPENSSL_sk_value`).
//! * The row [`ossl_v3_role_spec_cert_identifier`] (`:85-95`, `NID_role_spec_cert_identifier`,
//!   `X509V3_EXT_MULTILINE`).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds (`X509V3_EXT_get_nid`/`_get`/`_add_alias`/`_EXT_d2i`/`_get_d2i`/`_add1_i2d`).
//! A partial array would silently change `OBJ_bsearch_ext` for every missing NID (D456), so the
//! array is withheld until all 63 tables exist. This unit contributes one of the 63. The row is
//! internal data the admitted DSO does not export (`nm -D` shows only the ten item functions, no
//! `ossl_v3_*`); the item groups and the two printers are the drivable surface.
//!
//! ## No raise
//!
//! The unit raises nothing: `crypto/x509/v3_rolespec.c` is deliberately not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`, and there is no `ERR_raise` in the file to declare a
//! coordinate for. Every printer failure arm answers 0.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::obj::NID_role_spec_cert_identifier;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::t_x509::ossl_serial_number_print;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_san::GENERAL_NAME_print;
use crate::x509::v3_utl::OSSL_GENERAL_NAMES_print;

// ---------------------------------------------------------------------------------------------
// The `OSSL_ROLE_SPEC_CERT_ID` SEQUENCE item — `ASN1_SEQUENCE(OSSL_ROLE_SPEC_CERT_ID)` (`:15-20`)
// ---------------------------------------------------------------------------------------------

/// `struct OSSL_ROLE_SPEC_CERT_ID_st` — `OSSL_ROLE_SPEC_CERT_ID`, from
/// `include/openssl/x509v3.h.in:1076-1081`.
#[repr(C)]
pub struct OsslRoleSpecCertId {
    /// `GENERAL_NAME *roleName` — `[0]` EXPLICIT, required.
    pub roleName: *mut GeneralName,
    /// `GENERAL_NAME *roleCertIssuer` — `[1]` EXPLICIT, required.
    pub roleCertIssuer: *mut GeneralName,
    /// `ASN1_INTEGER *roleCertSerialNumber` — `[2]` IMPLICIT, optional.
    pub roleCertSerialNumber: *mut Asn1String,
    /// `GENERAL_NAMES *roleCertLocator` — `[3]` IMPLICIT `SEQUENCE OF GENERAL_NAME`, optional.
    pub roleCertLocator: *mut OpenSslStack,
}

const _: () = {
    assert!(core::mem::size_of::<OsslRoleSpecCertId>() == 32);
    assert!(core::mem::offset_of!(OsslRoleSpecCertId, roleName) == 0);
    assert!(core::mem::offset_of!(OsslRoleSpecCertId, roleCertIssuer) == 8);
    assert!(core::mem::offset_of!(OsslRoleSpecCertId, roleCertSerialNumber) == 16);
    assert!(core::mem::offset_of!(OsslRoleSpecCertId, roleCertLocator) == 24);
};

/// `OSSL_ROLE_SPEC_CERT_ID_seq_tt` — `ASN1_SEQUENCE(OSSL_ROLE_SPEC_CERT_ID)`
/// (`crypto/x509/v3_rolespec.c:15-19`): two `ASN1_EXP(..., GENERAL_NAME, n)` rows and one
/// `ASN1_IMP_OPT(..., ASN1_INTEGER, 2)` row, plus `ASN1_IMP_SEQUENCE_OF_OPT(..., GENERAL_NAME, 3)`.
static OSSL_ROLE_SPEC_CERT_ID_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 0,
        offset: 0,
        field_name: c"roleName".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_EXPLICIT,
        tag: 1,
        offset: 8,
        field_name: c"roleCertIssuer".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 2,
        offset: 16,
        field_name: c"roleCertSerialNumber".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        tag: 3,
        offset: 24,
        field_name: c"roleCertLocator".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
];

/// `OSSL_ROLE_SPEC_CERT_ID_it`'s descriptor — `ASN1_SEQUENCE_END(OSSL_ROLE_SPEC_CERT_ID)` at
/// `crypto/x509/v3_rolespec.c:20`. The non-`static_` end macro makes the accessor an export.
static OSSL_ROLE_SPEC_CERT_ID_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: OSSL_ROLE_SPEC_CERT_ID_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<OsslRoleSpecCertId>() as c_long,
    sname: c"OSSL_ROLE_SPEC_CERT_ID".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ROLE_SPEC_CERT_ID_it(void)` — `include/openssl/x509v3.h.in:1083`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_ROLE_SPEC_CERT_ID)`.
#[no_mangle]
pub extern "C" fn OSSL_ROLE_SPEC_CERT_ID_it() -> *const Asn1Item {
    &OSSL_ROLE_SPEC_CERT_ID_ITEM
}

/// `OSSL_ROLE_SPEC_CERT_ID *OSSL_ROLE_SPEC_CERT_ID_new(void)` — `crypto/x509/v3_rolespec.c:22`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ROLE_SPEC_CERT_ID)`.
#[no_mangle]
pub extern "C" fn OSSL_ROLE_SPEC_CERT_ID_new() -> *mut OsslRoleSpecCertId {
    // SAFETY: `OSSL_ROLE_SPEC_CERT_ID_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ROLE_SPEC_CERT_ID_it()).cast::<OsslRoleSpecCertId>() }
}

/// `void OSSL_ROLE_SPEC_CERT_ID_free(OSSL_ROLE_SPEC_CERT_ID *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_free(a: *mut OsslRoleSpecCertId) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ROLE_SPEC_CERT_ID_it()) }
}

/// `OSSL_ROLE_SPEC_CERT_ID *d2i_OSSL_ROLE_SPEC_CERT_ID(OSSL_ROLE_SPEC_CERT_ID **a, const unsigned
/// char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ROLE_SPEC_CERT_ID(
    a: *mut *mut OsslRoleSpecCertId,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OsslRoleSpecCertId {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ROLE_SPEC_CERT_ID_it()).cast::<OsslRoleSpecCertId>()
    }
}

/// `int i2d_OSSL_ROLE_SPEC_CERT_ID(const OSSL_ROLE_SPEC_CERT_ID *a, unsigned char **out)` — the
/// same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ROLE_SPEC_CERT_ID(
    a: *const OsslRoleSpecCertId,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ROLE_SPEC_CERT_ID_it()) }
}

// ---------------------------------------------------------------------------------------------
// The `OSSL_ROLE_SPEC_CERT_ID_SYNTAX` SEQUENCE OF template — `ASN1_ITEM_TEMPLATE(...)` (`:24-26`)
// ---------------------------------------------------------------------------------------------

/// `OSSL_ROLE_SPEC_CERT_ID_SYNTAX_item_tt` —
/// `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, OSSL_ROLE_SPEC_CERT_ID_SYNTAX,
/// OSSL_ROLE_SPEC_CERT_ID)` at `crypto/x509/v3_rolespec.c:24-25`. The value is a
/// `STACK_OF(OSSL_ROLE_SPEC_CERT_ID)`.
static OSSL_ROLE_SPEC_CERT_ID_SYNTAX_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_ROLE_SPEC_CERT_ID_SYNTAX".as_ptr(),
    item: OSSL_ROLE_SPEC_CERT_ID_it as *mut c_void,
};

/// `OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(...)` at
/// `crypto/x509/v3_rolespec.c:26`: a `PRIMITIVE` item over one `SEQUENCE OF` template, `utype`
/// `-1`, `tcount` 0.
static OSSL_ROLE_SPEC_CERT_ID_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_ROLE_SPEC_CERT_ID_SYNTAX_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_ROLE_SPEC_CERT_ID_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it(void)` — `include/openssl/x509v3.h.in:1093`.
#[no_mangle]
pub extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it() -> *const Asn1Item {
    &OSSL_ROLE_SPEC_CERT_ID_SYNTAX_ITEM
}

/// `OSSL_ROLE_SPEC_CERT_ID_SYNTAX *OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new(void)` —
/// `crypto/x509/v3_rolespec.c:28`, from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_ROLE_SPEC_CERT_ID_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(OSSL_ROLE_SPEC_CERT_ID_SYNTAX *a)` — the same macro's
/// free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_ROLE_SPEC_CERT_ID_SYNTAX_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it()) }
}

/// `OSSL_ROLE_SPEC_CERT_ID_SYNTAX *d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(OSSL_ROLE_SPEC_CERT_ID_SYNTAX
/// **a, const unsigned char **in, long len)`.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it()).cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(const OSSL_ROLE_SPEC_CERT_ID_SYNTAX *a, unsigned char
/// **out)`.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it()) }
}

// ---------------------------------------------------------------------------------------------
// The two printers (`:30-83`)
// ---------------------------------------------------------------------------------------------

/// `static int i2r_OSSL_ROLE_SPEC_CERT_ID(X509V3_EXT_METHOD *method, OSSL_ROLE_SPEC_CERT_ID
/// *rscid, BIO *out, int indent)` — `crypto/x509/v3_rolespec.c:30-61`.
///
/// Writes the role name and issuer through `GENERAL_NAME_print`, then, only when present, the
/// serial through `ossl_serial_number_print` and the locator through `OSSL_GENERAL_NAMES_print`.
///
/// # Safety
///
/// `out` is a live BIO; `rscid` is a live `OSSL_ROLE_SPEC_CERT_ID`.
unsafe extern "C" fn i2r_OSSL_ROLE_SPEC_CERT_ID(
    _method: *const X509V3ExtMethod,
    rscid: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let rscid = rscid.cast::<OsslRoleSpecCertId>();
    // SAFETY: `out` is a live BIO; the literal is static.
    if unsafe { BIO_printf(out, c"%*sRole Name: ".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `rscid` is live; `roleName` is a live `GENERAL_NAME`.
    if unsafe { GENERAL_NAME_print(out, (*rscid).roleName) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is a live BIO; the literal is static.
    if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
        return 0;
    }
    // SAFETY: `out` is a live BIO; the literal is static.
    if unsafe {
        BIO_printf(
            out,
            c"%*sRole Certificate Issuer: ".as_ptr(),
            indent,
            c"".as_ptr(),
        )
    } <= 0
    {
        return 0;
    }
    // SAFETY: `rscid` is live; `roleCertIssuer` is a live `GENERAL_NAME`.
    if unsafe { GENERAL_NAME_print(out, (*rscid).roleCertIssuer) } <= 0 {
        return 0;
    }
    // SAFETY: `rscid` is live.
    if !unsafe { (*rscid).roleCertSerialNumber }.is_null() {
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe {
            BIO_printf(
                out,
                c"%*sRole Certificate Serial Number:".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `out` is live; the serial is a live `ASN1_INTEGER`.
        if unsafe { ossl_serial_number_print(out, (*rscid).roleCertSerialNumber, indent) } != 0 {
            return 0;
        }
    }
    // SAFETY: `rscid` is live.
    if !unsafe { (*rscid).roleCertLocator }.is_null() {
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
            return 0;
        }
        // SAFETY: `out` is a live BIO; the literal is static.
        if unsafe {
            BIO_printf(
                out,
                c"%*sRole Certificate Locator:\n".as_ptr(),
                indent,
                c"".as_ptr(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `out` is live and `roleCertLocator` is a live `GENERAL_NAMES`.
        if unsafe { OSSL_GENERAL_NAMES_print(out, (*rscid).roleCertLocator, indent) } <= 0 {
            return 0;
        }
    }
    // SAFETY: `out` is a live BIO; the literal is static.
    unsafe { BIO_puts(out, c"\n".as_ptr()) }
}

/// `static int i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(X509V3_EXT_METHOD *method,
/// OSSL_ROLE_SPEC_CERT_ID_SYNTAX *rscids, BIO *out, int indent)` —
/// `crypto/x509/v3_rolespec.c:63-83`.
///
/// One `Role Specification Certificate Identifier #n:` block per stack entry, indented four
/// further, with a blank line between entries.
///
/// # Safety
///
/// `out` is a live BIO; `rscids` is a live `STACK_OF(OSSL_ROLE_SPEC_CERT_ID)`.
unsafe extern "C" fn i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX(
    method: *const X509V3ExtMethod,
    rscids: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    let rscids = rscids.cast::<OpenSslStack>();
    // SAFETY: `rscids` is a live stack per the contract.
    let num = unsafe { OPENSSL_sk_num(rscids) };
    let mut i = 0;
    while i < num {
        if i > 0 {
            // SAFETY: `out` is a live BIO; the literal is static.
            if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
        // SAFETY: `out` is a live BIO; the format and its arguments are constants.
        if unsafe {
            BIO_printf(
                out,
                c"%*sRole Specification Certificate Identifier #%d:\n".as_ptr(),
                indent,
                c"".as_ptr(),
                i + 1,
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `rscids` is live and `i` is in bounds.
        let rscid = unsafe { OPENSSL_sk_value(rscids, i) };
        // SAFETY: `out` is live and `rscid` is a live `OSSL_ROLE_SPEC_CERT_ID`.
        if unsafe { i2r_OSSL_ROLE_SPEC_CERT_ID(method, rscid, out, indent + 4) } != 1 {
            return 0;
        }
        i += 1;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// The row
// ---------------------------------------------------------------------------------------------

/// `const X509V3_EXT_METHOD ossl_v3_role_spec_cert_identifier` —
/// `crypto/x509/v3_rolespec.c:85-95`.
///
/// `NID_role_spec_cert_identifier`, the `X509V3_EXT_MULTILINE` flag, the
/// [`OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it`] item and the [`i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX`]
/// printer; every other slot is zero.
pub static ossl_v3_role_spec_cert_identifier: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_role_spec_cert_identifier,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(OSSL_ROLE_SPEC_CERT_ID_SYNTAX_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_OSSL_ROLE_SPEC_CERT_ID_SYNTAX),
    r2i: None,
    usr_data: ptr::null_mut(),
};
