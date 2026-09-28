//! `crypto/x509/v3_ist.c` — the Issuer Sign Tool item. Phase 10.12.
//!
//! `crypto/x509/v3_ist.c` is 144 lines. **The item and its generated lifecycle land; the
//! extension method and its two callbacks are withheld by name**:
//!
//! * `ISSUER_SIGN_TOOL ::= SEQUENCE { signTool UTF8String, cATool UTF8String, signToolCert
//!   UTF8String, cAToolCert UTF8String }` (`:25-30`) lands, with `ISSUER_SIGN_TOOL_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:32`). All five are
//!   public exports (`x509v3.h`), so the differential plane can build one, encode it and decode
//!   the bytes back.
//! * `ossl_v3_issuer_sign_tool` (`:132-144`) is **withheld by name**: internal, not exported by
//!   the admitted DSO, its only authority caller being `X509V3_add_standard_extensions`
//!   (`crypto/x509/v3_lib.c:127`, 10.14). It is the row the OpenSSL 3.6.4 change added for the
//!   RFC 4491-bis `1.2.643.100.112` Russian qualified-certificate extension.
//! * `v2i_issuer_sign_tool` (`:34-88`) and `i2r_issuer_sign_tool` (`:90-130`) are **withheld by
//!   name**: `static` callbacks reached only through the withheld table, so landing them would be
//!   dead code. `v2i_issuer_sign_tool` raises `ERR_LIB_X509V3`'s `ERR_R_ASN1_LIB` and
//!   `ERR_R_PASSED_INVALID_ARGUMENT`, and `i2r_issuer_sign_tool` raises the latter; both land with
//!   the table, and `crypto/x509/v3_ist.c` is deliberately **not** in
//!   `gen_err_raise_sites.py`'s `COVERED_FILES` until then.
//!
//! Nothing is stubbed: the three withheld names are named rather than declared.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_UTF8STRING_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;

/// `struct ISSUER_SIGN_TOOL_st` — `ISSUER_SIGN_TOOL`, from `include/openssl/x509v3.h:417-422`.
///
/// Four mandatory UTF-8 strings, in the order RFC 4491-bis names them.
#[repr(C)]
pub struct IssuerSignTool {
    /// `ASN1_UTF8STRING *signTool` — the tool that signed the subject.
    pub(crate) signTool: *mut Asn1String,
    /// `ASN1_UTF8STRING *cATool` — the CA's tool.
    pub(crate) cATool: *mut Asn1String,
    /// `ASN1_UTF8STRING *signToolCert` — the signing tool's certificate.
    pub(crate) signToolCert: *mut Asn1String,
    /// `ASN1_UTF8STRING *cAToolCert` — the CA tool's certificate.
    pub(crate) cAToolCert: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<IssuerSignTool>() == 32);
    assert!(core::mem::offset_of!(IssuerSignTool, signTool) == 0);
    assert!(core::mem::offset_of!(IssuerSignTool, cATool) == 8);
    assert!(core::mem::offset_of!(IssuerSignTool, signToolCert) == 16);
    assert!(core::mem::offset_of!(IssuerSignTool, cAToolCert) == 24);
};

/// `ISSUER_SIGN_TOOL_seq_tt` — `ASN1_SEQUENCE(ISSUER_SIGN_TOOL)` (`crypto/x509/v3_ist.c:25-30`):
/// four `ASN1_SIMPLE(..., ASN1_UTF8STRING)` rows.
static ISSUER_SIGN_TOOL_TT: [Asn1Template; 4] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"signTool".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"cATool".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 16,
        field_name: c"signToolCert".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 24,
        field_name: c"cAToolCert".as_ptr(),
        item: ASN1_UTF8STRING_it as *mut c_void,
    },
];

/// `ISSUER_SIGN_TOOL_it`'s descriptor — `ASN1_SEQUENCE_END(ISSUER_SIGN_TOOL)` at
/// `crypto/x509/v3_ist.c:30`.
static ISSUER_SIGN_TOOL_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ISSUER_SIGN_TOOL_TT.as_ptr(),
    tcount: 4,
    funcs: ptr::null(),
    size: core::mem::size_of::<IssuerSignTool>() as c_long,
    sname: c"ISSUER_SIGN_TOOL".as_ptr(),
};

/// `const ASN1_ITEM *ISSUER_SIGN_TOOL_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(ISSUER_SIGN_TOOL)`.
#[no_mangle]
pub extern "C" fn ISSUER_SIGN_TOOL_it() -> *const Asn1Item {
    &ISSUER_SIGN_TOOL_ITEM
}

/// `ISSUER_SIGN_TOOL *ISSUER_SIGN_TOOL_new(void)` — `crypto/x509/v3_ist.c:32`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(ISSUER_SIGN_TOOL)`.
#[no_mangle]
pub extern "C" fn ISSUER_SIGN_TOOL_new() -> *mut IssuerSignTool {
    // SAFETY: `ISSUER_SIGN_TOOL_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ISSUER_SIGN_TOOL_it()).cast::<IssuerSignTool>() }
}

/// `void ISSUER_SIGN_TOOL_free(ISSUER_SIGN_TOOL *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ISSUER_SIGN_TOOL_free(a: *mut IssuerSignTool) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ISSUER_SIGN_TOOL_it()) }
}

/// `ISSUER_SIGN_TOOL *d2i_ISSUER_SIGN_TOOL(ISSUER_SIGN_TOOL **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ISSUER_SIGN_TOOL(
    a: *mut *mut IssuerSignTool,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut IssuerSignTool {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, ISSUER_SIGN_TOOL_it()).cast::<IssuerSignTool>() }
}

/// `int i2d_ISSUER_SIGN_TOOL(const ISSUER_SIGN_TOOL *a, unsigned char **out)` — the same macro's
/// encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ISSUER_SIGN_TOOL(
    a: *const IssuerSignTool,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ISSUER_SIGN_TOOL_it()) }
}
