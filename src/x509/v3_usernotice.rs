//! `crypto/x509/v3_usernotice.c` — the `OSSL_USER_NOTICE_SYNTAX` item and its row. Phase 10.14's
//! table layer, landed whole.
//!
//! `crypto/x509/v3_usernotice.c` is 96 lines and transcribes whole:
//!
//! * `OSSL_USER_NOTICE_SYNTAX ::= SEQUENCE OF USERNOTICE` (`:14-15`) lands, with
//!   `OSSL_USER_NOTICE_SYNTAX_it` and the `_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:17`; all five are declared at `x509v3.h:1501`). The value
//!   type is `STACK_OF(USERNOTICE)` (`x509v3.h:1500`). The element item is `USERNOTICE_it`, landed
//!   in `v3_cpols.rs` alongside `NOTICEREF_it` and its `UserNotice`/`NoticeRef` layouts.
//! * `print_notice` (`:19-64`) lands over `i2s_ASN1_INTEGER` (`v3_utl.rs`); its two `OPENSSL_free`
//!   calls are `CRYPTO_free` with this unit's own `OPENSSL_FILE`/`OPENSSL_LINE` (`:48`, `:51`).
//! * `i2r_USER_NOTICE_SYNTAX` (`:66-84`) lands.
//! * The row [`ossl_v3_user_notice`] (`:86-96`) lands, `NID_user_notice` (`obj_mac.h:2815`),
//!   `ext_flags` 0, `i2r` set.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item group and the printer are the drivable
//! surface.
//!
//! ## No raise
//!
//! The unit raises nothing, so `crypto/x509/v3_usernotice.c` is deliberately not an entry in
//! `gen_err_raise_sites.py`'s `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::bio::iolib::BIO_puts;
use crate::runtime::bio::print::BIO_printf;
use crate::runtime::bio::Bio;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::obj::NID_user_notice;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_cpols::{USERNOTICE_it, UserNotice};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::i2s_ASN1_INTEGER;

/// `OPENSSL_FILE` for this unit's `OPENSSL_free` expansions — `crypto/x509/v3_usernotice.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_usernotice.c";
/// `print_notice`'s failure-path `OPENSSL_free(tmp)` (`v3_usernotice.c:48`).
const LINE_FREE_FAIL: c_int = 48;
/// The same function's success-path `OPENSSL_free(tmp)` (`v3_usernotice.c:51`).
const LINE_FREE_OK: c_int = 51;

/// `OSSL_USER_NOTICE_SYNTAX_item_tt` — `ASN1_ITEM_TEMPLATE(OSSL_USER_NOTICE_SYNTAX)`'s single
/// template (`crypto/x509/v3_usernotice.c:14`): `ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
/// OSSL_USER_NOTICE_SYNTAX, USERNOTICE)`.
static OSSL_USER_NOTICE_SYNTAX_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"OSSL_USER_NOTICE_SYNTAX".as_ptr(),
    item: USERNOTICE_it as *mut c_void,
};

/// `OSSL_USER_NOTICE_SYNTAX_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(OSSL_USER_NOTICE_SYNTAX)` at
/// `crypto/x509/v3_usernotice.c:15`.
static OSSL_USER_NOTICE_SYNTAX_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &OSSL_USER_NOTICE_SYNTAX_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"OSSL_USER_NOTICE_SYNTAX".as_ptr(),
};

/// `const ASN1_ITEM *OSSL_USER_NOTICE_SYNTAX_it(void)` — `include/openssl/x509v3.h:1501`, from
/// `DECLARE_ASN1_FUNCTIONS(OSSL_USER_NOTICE_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_USER_NOTICE_SYNTAX_it() -> *const Asn1Item {
    &OSSL_USER_NOTICE_SYNTAX_ITEM
}

/// `OSSL_USER_NOTICE_SYNTAX *OSSL_USER_NOTICE_SYNTAX_new(void)` — `crypto/x509/v3_usernotice.c:17`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(OSSL_USER_NOTICE_SYNTAX)`.
#[no_mangle]
pub extern "C" fn OSSL_USER_NOTICE_SYNTAX_new() -> *mut OpenSslStack {
    // SAFETY: `OSSL_USER_NOTICE_SYNTAX_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(OSSL_USER_NOTICE_SYNTAX_it()).cast::<OpenSslStack>() }
}

/// `void OSSL_USER_NOTICE_SYNTAX_free(OSSL_USER_NOTICE_SYNTAX *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn OSSL_USER_NOTICE_SYNTAX_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), OSSL_USER_NOTICE_SYNTAX_it()) }
}

/// `OSSL_USER_NOTICE_SYNTAX *d2i_OSSL_USER_NOTICE_SYNTAX(OSSL_USER_NOTICE_SYNTAX **a,
/// const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_OSSL_USER_NOTICE_SYNTAX(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, OSSL_USER_NOTICE_SYNTAX_it()).cast::<OpenSslStack>()
    }
}

/// `int i2d_OSSL_USER_NOTICE_SYNTAX(const OSSL_USER_NOTICE_SYNTAX *a, unsigned char **out)` — the
/// same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_OSSL_USER_NOTICE_SYNTAX(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, OSSL_USER_NOTICE_SYNTAX_it()) }
}

/// `static int print_notice(BIO *out, USERNOTICE *notice, int indent)` —
/// `crypto/x509/v3_usernotice.c:19-64`.
///
/// Prints the notice reference (organization, then the notice-number list, one `i2s_ASN1_INTEGER`
/// rendering per entry or `(null)`) and the explicit text. Every `BIO_printf`/`BIO_puts` failure
/// returns `0`; a NULL `exptext` returns `1` without printing.
///
/// # Safety
///
/// `out` is a live BIO; `notice` is a live `USERNOTICE`.
unsafe fn print_notice(out: *mut Bio, notice: *mut UserNotice, indent: c_int) -> c_int {
    // SAFETY: `notice` is live per the contract.
    let noticeref = unsafe { (*notice).noticeref };
    if !noticeref.is_null() {
        // SAFETY: `out` is live; `noticeref->organization` is its live string.
        if unsafe {
            BIO_printf(
                out,
                c"%*sOrganization: %.*s\n".as_ptr(),
                indent,
                c"".as_ptr(),
                (*(*noticeref).organization).length,
                (*(*noticeref).organization).data.cast::<c_char>(),
            )
        } <= 0
        {
            return 0;
        }
        // SAFETY: `noticeref` is live; `noticenos` is its live list.
        let nnum = unsafe { OPENSSL_sk_num((*noticeref).noticenos) };
        let plural = if nnum > 1 {
            c"s".as_ptr()
        } else {
            c"".as_ptr()
        };
        // SAFETY: `out` is live; `plural` is static.
        if unsafe { BIO_printf(out, c"%*sNumber%s: ".as_ptr(), indent, c"".as_ptr(), plural) } <= 0
        {
            return 0;
        }
        let mut i = 0;
        while i < nnum {
            // SAFETY: `noticeref->noticenos` is live and `i` is in bounds.
            let num = unsafe { OPENSSL_sk_value((*noticeref).noticenos, i) }.cast::<Asn1String>();
            if i != 0 {
                // SAFETY: `out` is live; the literal is static.
                if unsafe { BIO_puts(out, c", ".as_ptr()) } <= 0 {
                    return 0;
                }
            }
            // SAFETY: `out` is live; the literal is static.
            if num.is_null() && unsafe { BIO_puts(out, c"(null)".as_ptr()) } <= 0 {
                return 0;
            } else {
                // SAFETY: `num` is the element at `i`; `i2s_ASN1_INTEGER` answers NULL for NULL.
                let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), num) };
                if tmp.is_null() {
                    return 0;
                }
                // SAFETY: `out` is live; `tmp` is NUL-terminated.
                if unsafe { BIO_puts(out, tmp) } <= 0 {
                    // SAFETY: `tmp` is this call's own allocation.
                    unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_FAIL) };
                    return 0;
                }
                // SAFETY: `tmp` is this call's own allocation.
                unsafe { CRYPTO_free(tmp.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_OK) };
            }
            i += 1;
        }
        // SAFETY: `notice` is live; `exptext` is NULL or its own.
        if !unsafe { (*notice).exptext }.is_null() {
            // SAFETY: `out` is live; the literal is static.
            if unsafe { BIO_puts(out, c"\n".as_ptr()) } <= 0 {
                return 0;
            }
        }
    }
    // SAFETY: `notice` is live; `exptext` is NULL or its own.
    if unsafe { (*notice).exptext }.is_null() {
        return 1;
    }
    // SAFETY: `out` is live; `notice->exptext` is its live string.
    (unsafe {
        BIO_printf(
            out,
            c"%*sExplicit Text: %.*s".as_ptr(),
            indent,
            c"".as_ptr(),
            (*(*notice).exptext).length,
            (*(*notice).exptext).data.cast::<c_char>(),
        )
    } >= 0) as c_int
}

/// `static int i2r_USER_NOTICE_SYNTAX(X509V3_EXT_METHOD *method, OSSL_USER_NOTICE_SYNTAX *uns,
/// BIO *out, int indent)` — `crypto/x509/v3_usernotice.c:66-84`.
unsafe extern "C" fn i2r_USER_NOTICE_SYNTAX(
    _method: *const X509V3ExtMethod,
    uns: *mut c_void,
    out: *mut Bio,
    indent: c_int,
) -> c_int {
    // SAFETY: `out` is live; the format and its argument are constants.
    if unsafe { BIO_printf(out, c"%*sUser Notices:\n".as_ptr(), indent, c"".as_ptr()) } <= 0 {
        return 0;
    }
    let uns = uns.cast::<OpenSslStack>();
    // SAFETY: `uns` is a live `STACK_OF(USERNOTICE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(uns) };
    let mut i = 0;
    while i < num {
        // SAFETY: `uns` is live and `i` is in bounds.
        let unotice = unsafe { OPENSSL_sk_value(uns, i) }.cast::<UserNotice>();
        // SAFETY: `unotice` is a live notice per the stack contract.
        if unsafe { print_notice(out, unotice, indent + 4) } == 0 {
            return 0;
        }
        // SAFETY: `out` is live; the literal is static.
        if unsafe { BIO_puts(out, c"\n\n".as_ptr()) } <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `const X509V3_EXT_METHOD ossl_v3_user_notice` — `crypto/x509/v3_usernotice.c:86-96`.
pub static ossl_v3_user_notice: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_user_notice,
    ext_flags: 0,
    it: Some(OSSL_USER_NOTICE_SYNTAX_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: None,
    v2i: None,
    i2r: Some(i2r_USER_NOTICE_SYNTAX),
    r2i: None,
    usr_data: ptr::null_mut(),
};
