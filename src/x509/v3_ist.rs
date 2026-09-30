//! `crypto/x509/v3_ist.c` — the Issuer Sign Tool item and its row. Phase 10.12's item group plus
//! the 10.14 table layer, landed whole.
//!
//! `crypto/x509/v3_ist.c` is 144 lines and now transcribes whole:
//!
//! * `ISSUER_SIGN_TOOL ::= SEQUENCE { signTool UTF8String, cATool UTF8String, signToolCert
//!   UTF8String, cAToolCert UTF8String }` (`:25-30`) lands, with `ISSUER_SIGN_TOOL_it` and the
//!   `_new`/`_free`/`d2i_`/`i2d_` group `IMPLEMENT_ASN1_FUNCTIONS` emits (`:32`). All five are
//!   public exports (`x509v3.h:809`), so the differential plane can build one, encode it and decode
//!   the bytes back.
//! * `v2i_issuer_sign_tool` (`:34-88`) lands: it builds a fresh item and fills each of the four
//!   UTF-8 members from the matching `CONF_VALUE` name, raising `ERR_R_ASN1_LIB` on an allocation or
//!   `ASN1_STRING_set` failure and `ERR_R_PASSED_INVALID_ARGUMENT` on an unknown name.
//! * `i2r_issuer_sign_tool` (`:90-130`) lands: it prints each non-NULL member on its own line,
//!   raising `ERR_R_PASSED_INVALID_ARGUMENT` for a NULL item.
//! * The row [`ossl_v3_issuer_sign_tool`] (`:132-144`) lands, `NID_issuerSignTool` (`obj_mac.h:5000`),
//!   `X509V3_EXT_MULTILINE`, `v2i`/`i2r` set. It is the row the OpenSSL 3.6.4 change added for the
//!   RFC 4491-bis `1.2.643.100.112` Russian qualified-certificate extension. It is internal data
//!   the admitted DSO does not export (`nm -D` shows no `ossl_v3_*`); its only authority caller is
//!   `X509V3_add_standard_extensions` (`crypto/x509/v3_lib.c:127`).
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_ist.c` is not an entry in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its
//! seven coordinates are **declared locally**, their reason values read from the authority's
//! `err.h` (not typed from memory), as `v3_pcons.rs` does.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_UTF8STRING_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::string::ASN1_STRING_set;
use crate::runtime::bio::iolib::BIO_write;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::sys::{strcmp, strlen};
use crate::runtime::bio::Bio;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::raise_site;
use crate::runtime::obj::NID_issuerSignTool;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};

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

/// `ERR_LIB_X509V3` — `include/openssl/err.h:97`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `include/openssl/err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `include/openssl/err.h:358`, `(262 | ERR_RFLAG_COMMON)`.
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 524550;

/// One `v3_ist.c` raise coordinate, declared locally (see the module doc).
const fn v3_ist_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_ist.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_issuer_sign_tool`'s failed `ISSUER_SIGN_TOOL_new` at `v3_ist.c:41`.
const V3_IST_41: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(41, c"v2i_issuer_sign_tool", ERR_R_ASN1_LIB);
/// `v2i_issuer_sign_tool`'s failed `signTool` fill at `v3_ist.c:54`.
const V3_IST_54: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(54, c"v2i_issuer_sign_tool", ERR_R_ASN1_LIB);
/// `v2i_issuer_sign_tool`'s failed `cATool` fill at `v3_ist.c:61`.
const V3_IST_61: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(61, c"v2i_issuer_sign_tool", ERR_R_ASN1_LIB);
/// `v2i_issuer_sign_tool`'s failed `signToolCert` fill at `v3_ist.c:68`.
const V3_IST_68: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(68, c"v2i_issuer_sign_tool", ERR_R_ASN1_LIB);
/// `v2i_issuer_sign_tool`'s failed `cAToolCert` fill at `v3_ist.c:75`.
const V3_IST_75: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(75, c"v2i_issuer_sign_tool", ERR_R_ASN1_LIB);
/// `v2i_issuer_sign_tool`'s unknown name at `v3_ist.c:79`.
const V3_IST_79: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(79, c"v2i_issuer_sign_tool", ERR_R_PASSED_INVALID_ARGUMENT);
/// `i2r_issuer_sign_tool`'s NULL item at `v3_ist.c:97`.
const V3_IST_97: crate::runtime::err::err_sites::ErrSite =
    v3_ist_site(97, c"i2r_issuer_sign_tool", ERR_R_PASSED_INVALID_ARGUMENT);

/// The `member == NULL || value == NULL || !ASN1_STRING_set(member, value, (int)strlen(value))`
/// guard `v2i_issuer_sign_tool` repeats for each of its four members. Answers nonzero when the fill
/// succeeded.
///
/// # Safety
///
/// `member` is NULL or a live `ASN1_UTF8STRING`; `value` is NULL or a live NUL-terminated C string.
unsafe fn ist_member_guard(member: *mut Asn1String, value: *mut c_char) -> c_int {
    if member.is_null() || value.is_null() {
        return 0;
    }
    // SAFETY: `value` is NUL-terminated per the contract.
    let len = unsafe { strlen(value) };
    // SAFETY: `member` is live; `value` is readable for `len` bytes.
    unsafe { ASN1_STRING_set(member, value.cast::<c_void>(), len as c_int) }
}

/// `static ISSUER_SIGN_TOOL *v2i_issuer_sign_tool(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_ist.c:34-88`.
unsafe extern "C" fn v2i_issuer_sign_tool(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    let ist = ISSUER_SIGN_TOOL_new();
    if ist.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_IST_41) };
        return ptr::null_mut();
    }
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        if cnf.is_null() {
            i += 1;
            continue;
        }
        // SAFETY: `cnf` is live per the stack contract; each literal is static.
        let name = unsafe { (*cnf).name };
        // SAFETY: `name` is NUL-terminated; the literal is static.
        let is_signtool = unsafe { strcmp(name, c"signTool".as_ptr()) } == 0;
        // SAFETY: as above.
        let is_catool = unsafe { strcmp(name, c"cATool".as_ptr()) } == 0;
        // SAFETY: as above.
        let is_signtoolcert = unsafe { strcmp(name, c"signToolCert".as_ptr()) } == 0;
        // SAFETY: as above.
        let is_catoolcert = unsafe { strcmp(name, c"cAToolCert".as_ptr()) } == 0;
        if is_signtool {
            // SAFETY: `ist` and `cnf` are live; the guard short-circuits as the authority's does.
            let ok = unsafe { ist_member_guard((*ist).signTool, (*cnf).value) };
            if ok == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_IST_54) };
                // SAFETY: `ist` is a live value this call owns.
                unsafe { ISSUER_SIGN_TOOL_free(ist) };
                return ptr::null_mut();
            }
        } else if is_catool {
            // SAFETY: `ist` and `cnf` are live; the guard short-circuits as the authority's does.
            let ok = unsafe { ist_member_guard((*ist).cATool, (*cnf).value) };
            if ok == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_IST_61) };
                // SAFETY: `ist` is a live value this call owns.
                unsafe { ISSUER_SIGN_TOOL_free(ist) };
                return ptr::null_mut();
            }
        } else if is_signtoolcert {
            // SAFETY: `ist` and `cnf` are live; the guard short-circuits as the authority's does.
            let ok = unsafe { ist_member_guard((*ist).signToolCert, (*cnf).value) };
            if ok == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_IST_68) };
                // SAFETY: `ist` is a live value this call owns.
                unsafe { ISSUER_SIGN_TOOL_free(ist) };
                return ptr::null_mut();
            }
        } else if is_catoolcert {
            // SAFETY: `ist` and `cnf` are live; the guard short-circuits as the authority's does.
            let ok = unsafe { ist_member_guard((*ist).cAToolCert, (*cnf).value) };
            if ok == 0 {
                // SAFETY: the site is a compiled-in constant.
                unsafe { raise_site(&V3_IST_75) };
                // SAFETY: `ist` is a live value this call owns.
                unsafe { ISSUER_SIGN_TOOL_free(ist) };
                return ptr::null_mut();
            }
        } else {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_IST_79) };
            // SAFETY: `ist` is a live value this call owns.
            unsafe { ISSUER_SIGN_TOOL_free(ist) };
            return ptr::null_mut();
        }
        i += 1;
    }
    ist.cast::<c_void>()
}

/// `static int i2r_issuer_sign_tool(X509V3_EXT_METHOD *method, ISSUER_SIGN_TOOL *ist, BIO *out,
/// int indent)` — `crypto/x509/v3_ist.c:90-130`.
unsafe extern "C" fn i2r_issuer_sign_tool(
    _method: *const X509V3ExtMethod,
    ist: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    if ist.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_IST_97) };
        return 0;
    }
    let ist = ist.cast::<IssuerSignTool>();
    let mut new_line = 0;
    // SAFETY: `ist` is live per the caller's contract.
    if !unsafe { (*ist).signTool }.is_null() {
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*ssignTool    : ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live; `ist->signTool` is its live string.
        unsafe {
            BIO_write(
                out,
                (*(*ist).signTool).data.cast::<c_void>(),
                (*(*ist).signTool).length,
            )
        };
        new_line = 1;
    }
    // SAFETY: `ist` is live per the caller's contract.
    if !unsafe { (*ist).cATool }.is_null() {
        if new_line == 1 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1) };
        }
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*scATool      : ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live; `ist->cATool` is its live string.
        unsafe {
            BIO_write(
                out,
                (*(*ist).cATool).data.cast::<c_void>(),
                (*(*ist).cATool).length,
            )
        };
        new_line = 1;
    }
    // SAFETY: `ist` is live per the caller's contract.
    if !unsafe { (*ist).signToolCert }.is_null() {
        if new_line == 1 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1) };
        }
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*ssignToolCert: ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live; `ist->signToolCert` is its live string.
        unsafe {
            BIO_write(
                out,
                (*(*ist).signToolCert).data.cast::<c_void>(),
                (*(*ist).signToolCert).length,
            )
        };
        new_line = 1;
    }
    // SAFETY: `ist` is live per the caller's contract.
    if !unsafe { (*ist).cAToolCert }.is_null() {
        if new_line == 1 {
            // SAFETY: `out` is live; the literal is static.
            unsafe { BIO_write(out, c"\n".as_ptr().cast::<c_void>(), 1) };
        }
        // SAFETY: `out` is live; the format and its argument are constants.
        unsafe { BIO_printf(out, c"%*scAToolCert  : ".as_ptr(), indent, c"".as_ptr()) };
        // SAFETY: `out` is live; `ist->cAToolCert` is its live string.
        unsafe {
            BIO_write(
                out,
                (*(*ist).cAToolCert).data.cast::<c_void>(),
                (*(*ist).cAToolCert).length,
            )
        };
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_issuer_sign_tool` — `crypto/x509/v3_ist.c:132-144`.
pub static ossl_v3_issuer_sign_tool: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_issuerSignTool,
    ext_flags: X509V3_EXT_MULTILINE,
    it: Some(ISSUER_SIGN_TOOL_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: Some(v2i_issuer_sign_tool),
    i2r: Some(i2r_issuer_sign_tool),
    r2i: None,
    usr_data: ptr::null_mut(),
};
