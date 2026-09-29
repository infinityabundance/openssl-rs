//! `crypto/x509/v3_info.c` — the `ACCESS_DESCRIPTION`/`AUTHORITY_INFO_ACCESS` items and the two
//! `infoAccess` rows. Phase 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_info.c` is 155 lines and transcribes whole:
//!
//! * `ACCESS_DESCRIPTION ::= SEQUENCE { method ASN1_OBJECT, location GENERAL_NAME }` (`:48-51`)
//!   lands with `ACCESS_DESCRIPTION_it` and the `_new`/`_free`/`d2i_`/`i2d_` group
//!   `IMPLEMENT_ASN1_FUNCTIONS` emits (`:53`; `x509v3.h:627`).
//! * `AUTHORITY_INFO_ACCESS ::= SEQUENCE OF ACCESS_DESCRIPTION` (`:55-56`) lands with
//!   `AUTHORITY_INFO_ACCESS_it` and its group (`:58`; `x509v3.h:628`).
//! * `i2v_AUTHORITY_INFO_ACCESS` (`:60-99`) and `v2i_AUTHORITY_INFO_ACCESS` (`:101-149`) land.
//! * The exported helper `i2a_ACCESS_DESCRIPTION` (`:151-155`) lands.
//! * The **two rows** land: [`ossl_v3_info`] (`:30-37`, `NID_info_access`) and
//!   [`ossl_v3_sinfo`] (`:39-46`, `NID_sinfo_access`), both `X509V3_EXT_MULTILINE`, sharing the
//!   same item and callbacks.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes two of the 63. The rows are internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item groups and the two callbacks are the drivable
//! surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_info.c` is not an entry in `gen_err_raise_sites.py`, so its five coordinates are
//! **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::ASN1_OBJECT_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::text::{i2a_ASN1_OBJECT, i2t_ASN1_OBJECT};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::bio::sys::{strchr, strlen};
use crate::runtime::bio::Bio;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{X509V3_R_BAD_OBJECT, X509V3_R_INVALID_SYNTAX};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc, CRYPTO_strndup};
use crate::runtime::obj::{Asn1Object, NID_info_access, NID_sinfo_access, OBJ_txt2obj};
use crate::runtime::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value, OpenSslStack,
};
use crate::x509::v3_conf::X509V3Ctx;
use crate::x509::v3_genn::{GENERAL_NAME_it, GeneralName};
use crate::x509::v3_lib::{X509V3ExtMethod, X509V3_EXT_MULTILINE};
use crate::x509::v3_san::{i2v_GENERAL_NAME, v2i_GENERAL_NAME_ex};
use crate::x509::v3_utl::X509V3_conf_free;

/// `OPENSSL_FILE` for this unit's `OPENSSL_malloc`/`OPENSSL_free` expansions —
/// `crypto/x509/v3_info.c`.
const FILE: &core::ffi::CStr = c"crypto/x509/v3_info.c";
/// `i2v_AUTHORITY_INFO_ACCESS`'s `OPENSSL_malloc(nlen)` (`:84`).
const LINE_MALLOC: c_int = 84;
/// `i2v_AUTHORITY_INFO_ACCESS`'s `OPENSSL_free(vtmp->name)` (`:88`).
const LINE_FREE_NAME: c_int = 88;
/// `v2i_AUTHORITY_INFO_ACCESS`'s `OPENSSL_strndup(...)` (`:134`).
const LINE_STRNDUP: c_int = 134;
/// `v2i_AUTHORITY_INFO_ACCESS`'s `OPENSSL_free(objtmp)` (`:140`).
const LINE_FREE_OBJ: c_int = 140;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_CRYPTO_LIB` — `err.h:330`, `(ERR_LIB_CRYPTO | ERR_RFLAG_COMMON)`.
const ERR_R_CRYPTO_LIB: c_int = 524303;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_info.c` raise coordinate, declared locally (see the module doc).
const fn v3_info_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_info.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `i2v_AUTHORITY_INFO_ACCESS`'s `i2v_GENERAL_NAME` failure at `v3_info.c:77`.
const V3_INFO_77: crate::runtime::err::err_sites::ErrSite =
    v3_info_site(77, c"i2v_AUTHORITY_INFO_ACCESS", ERR_R_ASN1_LIB);
/// `v2i_AUTHORITY_INFO_ACCESS`'s reserve failure at `v3_info.c:115`.
const V3_INFO_115: crate::runtime::err::err_sites::ErrSite =
    v3_info_site(115, c"v2i_AUTHORITY_INFO_ACCESS", ERR_R_CRYPTO_LIB);
/// `v2i_AUTHORITY_INFO_ACCESS`'s `ACCESS_DESCRIPTION_new` failure at `v3_info.c:121`.
const V3_INFO_121: crate::runtime::err::err_sites::ErrSite =
    v3_info_site(121, c"v2i_AUTHORITY_INFO_ACCESS", ERR_R_ASN1_LIB);
/// `v2i_AUTHORITY_INFO_ACCESS`'s missing `;` at `v3_info.c:127`.
const V3_INFO_127: crate::runtime::err::err_sites::ErrSite =
    v3_info_site(127, c"v2i_AUTHORITY_INFO_ACCESS", X509V3_R_INVALID_SYNTAX);
/// `v2i_AUTHORITY_INFO_ACCESS`'s bad method object at `v3_info.c:138`.
const V3_INFO_138: crate::runtime::err::err_sites::ErrSite =
    v3_info_site(138, c"v2i_AUTHORITY_INFO_ACCESS", X509V3_R_BAD_OBJECT);

/// `struct ACCESS_DESCRIPTION_st` — `ACCESS_DESCRIPTION`, from `include/openssl/x509v3.h`.
#[repr(C)]
pub struct AccessDescription {
    /// `ASN1_OBJECT *method`.
    pub method: *mut Asn1Object,
    /// `GENERAL_NAME *location`.
    pub location: *mut GeneralName,
}

const _: () = {
    assert!(core::mem::size_of::<AccessDescription>() == 16);
    assert!(core::mem::offset_of!(AccessDescription, method) == 0);
    assert!(core::mem::offset_of!(AccessDescription, location) == 8);
};

/// `void (*)(void *)` thunk for `sk_ACCESS_DESCRIPTION_pop_free(..., ACCESS_DESCRIPTION_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `ACCESS_DESCRIPTION` (the stack contract).
unsafe extern "C" fn access_description_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `ACCESS_DESCRIPTION` pointers per the contract.
    unsafe { ACCESS_DESCRIPTION_free(p.cast::<AccessDescription>()) };
}

/// `void (*)(void *)` thunk for `sk_CONF_VALUE_pop_free(..., X509V3_conf_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `CONF_VALUE` (the stack contract).
unsafe extern "C" fn conf_value_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `CONF_VALUE` pointers per the contract.
    unsafe { X509V3_conf_free(p.cast::<ConfValue>()) };
}

/// `ACCESS_DESCRIPTION_seq_tt` — `ASN1_SEQUENCE(ACCESS_DESCRIPTION)`
/// (`crypto/x509/v3_info.c:48-51`): `method` over `ASN1_OBJECT`, `location` over `GENERAL_NAME`.
static ACCESS_DESCRIPTION_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"method".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"location".as_ptr(),
        item: GENERAL_NAME_it as *mut c_void,
    },
];

/// `ACCESS_DESCRIPTION_it`'s descriptor — `ASN1_SEQUENCE_END(ACCESS_DESCRIPTION)` at
/// `crypto/x509/v3_info.c:51`.
static ACCESS_DESCRIPTION_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: ACCESS_DESCRIPTION_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<AccessDescription>() as c_long,
    sname: c"ACCESS_DESCRIPTION".as_ptr(),
};

/// `const ASN1_ITEM *ACCESS_DESCRIPTION_it(void)` — `include/openssl/x509v3.h:627`.
#[no_mangle]
pub extern "C" fn ACCESS_DESCRIPTION_it() -> *const Asn1Item {
    &ACCESS_DESCRIPTION_ITEM
}

/// `ACCESS_DESCRIPTION *ACCESS_DESCRIPTION_new(void)` — `crypto/x509/v3_info.c:53`.
#[no_mangle]
pub extern "C" fn ACCESS_DESCRIPTION_new() -> *mut AccessDescription {
    // SAFETY: `ACCESS_DESCRIPTION_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(ACCESS_DESCRIPTION_it()).cast::<AccessDescription>() }
}

/// `void ACCESS_DESCRIPTION_free(ACCESS_DESCRIPTION *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn ACCESS_DESCRIPTION_free(a: *mut AccessDescription) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), ACCESS_DESCRIPTION_it()) }
}

/// `ACCESS_DESCRIPTION *d2i_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION **a, const unsigned char **in,
/// long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_ACCESS_DESCRIPTION(
    a: *mut *mut AccessDescription,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut AccessDescription {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, ACCESS_DESCRIPTION_it()).cast::<AccessDescription>()
    }
}

/// `int i2d_ACCESS_DESCRIPTION(const ACCESS_DESCRIPTION *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_ACCESS_DESCRIPTION(
    a: *const AccessDescription,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, ACCESS_DESCRIPTION_it()) }
}

/// `AUTHORITY_INFO_ACCESS_tmpl_tt` — `ASN1_ITEM_TEMPLATE(AUTHORITY_INFO_ACCESS)`'s single template
/// (`crypto/x509/v3_info.c:55`): `ASN1_TFLG_SEQUENCE_OF` over `ACCESS_DESCRIPTION`.
static AUTHORITY_INFO_ACCESS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"GeneralNames".as_ptr(),
    item: ACCESS_DESCRIPTION_it as *mut c_void,
};

/// `AUTHORITY_INFO_ACCESS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(AUTHORITY_INFO_ACCESS)` at
/// `crypto/x509/v3_info.c:56`.
static AUTHORITY_INFO_ACCESS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &AUTHORITY_INFO_ACCESS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"AUTHORITY_INFO_ACCESS".as_ptr(),
};

/// `const ASN1_ITEM *AUTHORITY_INFO_ACCESS_it(void)` — `include/openssl/x509v3.h:628`.
#[no_mangle]
pub extern "C" fn AUTHORITY_INFO_ACCESS_it() -> *const Asn1Item {
    &AUTHORITY_INFO_ACCESS_ITEM
}

/// `AUTHORITY_INFO_ACCESS *AUTHORITY_INFO_ACCESS_new(void)` — `crypto/x509/v3_info.c:58`.
#[no_mangle]
pub extern "C" fn AUTHORITY_INFO_ACCESS_new() -> *mut OpenSslStack {
    // SAFETY: `AUTHORITY_INFO_ACCESS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(AUTHORITY_INFO_ACCESS_it()).cast::<OpenSslStack>() }
}

/// `void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn AUTHORITY_INFO_ACCESS_free(a: *mut OpenSslStack) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), AUTHORITY_INFO_ACCESS_it()) }
}

/// `AUTHORITY_INFO_ACCESS *d2i_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS **a,
/// const unsigned char **in, long len)` — the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_AUTHORITY_INFO_ACCESS(
    a: *mut *mut OpenSslStack,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut OpenSslStack {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, AUTHORITY_INFO_ACCESS_it()).cast::<OpenSslStack>() }
}

/// `int i2d_AUTHORITY_INFO_ACCESS(const AUTHORITY_INFO_ACCESS *a, unsigned char **out)` — the same
/// macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_AUTHORITY_INFO_ACCESS(
    a: *const OpenSslStack,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, AUTHORITY_INFO_ACCESS_it()) }
}

/// `static STACK_OF(CONF_VALUE) *i2v_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
/// AUTHORITY_INFO_ACCESS *ainfo, STACK_OF(CONF_VALUE) *ret)` — `crypto/x509/v3_info.c:60-99`.
///
/// One `CONF_VALUE` per access description, its name rewritten in place to
/// `"<object> - <general-name>"`.
unsafe extern "C" fn i2v_AUTHORITY_INFO_ACCESS(
    method: *const X509V3ExtMethod,
    ainfo: *mut c_void,
    ret: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let ainfo = ainfo.cast::<OpenSslStack>();
    let mut tret = ret;
    // SAFETY: `ainfo` is a live `STACK_OF(ACCESS_DESCRIPTION)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(ainfo) };
    let mut i = 0;
    while i < num {
        // SAFETY: `ainfo` is live and `i` is in bounds.
        let desc = unsafe { OPENSSL_sk_value(ainfo, i) }.cast::<AccessDescription>();
        // SAFETY: `desc` is a live row; `method` is the caller's; `tret` is this call's sink.
        let tmp = unsafe { i2v_GENERAL_NAME(method.cast_mut(), (*desc).location, tret) };
        if tmp.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_INFO_77) };
            return i2v_ainfo_err(ret, tret);
        }
        tret = tmp;
        // SAFETY: `tret` holds at least `i + 1` values from the call above.
        let vtmp = unsafe { OPENSSL_sk_value(tret, i) }.cast::<ConfValue>();
        let mut objtmp = [0 as c_char; 80];
        // SAFETY: `objtmp` is 80 writable bytes; `desc` is live.
        unsafe { i2t_ASN1_OBJECT(objtmp.as_mut_ptr(), 80, (*desc).method) };
        // SAFETY: both strings are NUL-terminated.
        let nlen = unsafe { strlen(objtmp.as_ptr()) + 3 + strlen((*vtmp).name) } + 1;
        // SAFETY: `nlen` is the exact byte count the authority frees.
        let ntmp = CRYPTO_malloc(nlen, FILE.as_ptr(), LINE_MALLOC).cast::<c_char>();
        if ntmp.is_null() {
            return i2v_ainfo_err(ret, tret);
        }
        // SAFETY: `ntmp` has `nlen` bytes; both sources are NUL-terminated.
        unsafe {
            BIO_snprintf(
                ntmp,
                nlen,
                c"%s - %s".as_ptr(),
                objtmp.as_ptr(),
                (*vtmp).name,
            );
            CRYPTO_free((*vtmp).name.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_NAME);
            (*vtmp).name = ntmp;
        }
        i += 1;
    }
    if ret.is_null() && tret.is_null() {
        // SAFETY: no preconditions.
        return OPENSSL_sk_new_null();
    }
    tret
}

/// `i2v_AUTHORITY_INFO_ACCESS`'s `err:` label — `crypto/x509/v3_info.c:95-98`.
///
/// A safe helper: `ret`/`tret` are the caller's own stacks (either may be NULL).
fn i2v_ainfo_err(ret: *mut OpenSslStack, tret: *mut OpenSslStack) -> *mut OpenSslStack {
    if ret.is_null() && !tret.is_null() {
        // SAFETY: `tret` is a live list this call built; `X509V3_conf_free` its destructor.
        unsafe { OPENSSL_sk_pop_free(tret, Some(conf_value_free_thunk)) };
    }
    ptr::null_mut()
}

/// Extract a NUL-terminated C string's bytes, growing `buf`.
///
/// # Safety
///
/// `p` is NULL or NUL-terminated.
unsafe fn push_cstr(buf: &mut Vec<u8>, p: *const c_char) {
    // SAFETY: `p` is NUL-terminated per the contract.
    let s = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
    buf.extend_from_slice(s);
}

/// `static AUTHORITY_INFO_ACCESS *v2i_AUTHORITY_INFO_ACCESS(X509V3_EXT_METHOD *method,
/// X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_info.c:101-149`.
unsafe extern "C" fn v2i_AUTHORITY_INFO_ACCESS(
    method: *const X509V3ExtMethod,
    ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let ainfo = OPENSSL_sk_new_reserve(None, num);
    if ainfo.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_INFO_115) };
        return ptr::null_mut();
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let cnf = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        let acc = ACCESS_DESCRIPTION_new();
        if acc.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_INFO_121) };
            return v2i_ainfo_err(ainfo);
        }
        // SAFETY: `ainfo` was reserved for `num`, so the push cannot fail.
        unsafe { OPENSSL_sk_push(ainfo, acc.cast::<c_void>()) };
        // SAFETY: `cnf` is live and `name` is NUL-terminated.
        let ptmp = unsafe { strchr((*cnf).name, b';' as c_int) };
        if ptmp.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_INFO_127) };
            return v2i_ainfo_err(ainfo);
        }
        // SAFETY: `ptmp` points inside `cnf->name`, so `ptmp + 1` is a suffix of it.
        let cname = unsafe { ptmp.add(1) };
        // SAFETY: `cnf` is a live `CONF_VALUE` per the caller's contract.
        let cvalue = unsafe { (*cnf).value };
        let mut ctmp = ConfValue {
            section: ptr::null_mut(),
            name: cname,
            value: cvalue,
        };
        // SAFETY: `acc->location` is a live `GENERAL_NAME` slot; `method`/`ctx` are the caller's;
        // `ctmp` is this call's own.
        let gn = unsafe {
            v2i_GENERAL_NAME_ex(
                (*acc).location,
                method,
                ctx.cast::<X509V3Ctx>(),
                &raw mut ctmp,
                0,
            )
        };
        if gn.is_null() {
            return v2i_ainfo_err(ainfo);
        }
        // SAFETY: `cnf->name` is NUL-terminated; the length is the `;` prefix.
        let objtmp = unsafe {
            CRYPTO_strndup(
                (*cnf).name,
                (ptmp as usize) - ((*cnf).name as usize),
                FILE.as_ptr(),
                LINE_STRNDUP,
            )
        };
        if objtmp.is_null() {
            return v2i_ainfo_err(ainfo);
        }
        // SAFETY: `objtmp` is NUL-terminated; `no_name` is 0.
        unsafe { (*acc).method = OBJ_txt2obj(objtmp, 0) };
        // SAFETY: `acc` is live.
        if unsafe { (*acc).method }.is_null() {
            let mut msg: Vec<u8> = b"value=".to_vec();
            // SAFETY: `objtmp` is NUL-terminated.
            unsafe { push_cstr(&mut msg, objtmp) };
            msg.push(0);
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site_data(&V3_INFO_138, msg.as_ptr().cast::<c_char>()) };
            // SAFETY: `objtmp` is this call's own.
            unsafe { CRYPTO_free(objtmp.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_OBJ) };
            return v2i_ainfo_err(ainfo);
        }
        // SAFETY: `objtmp` is this call's own.
        unsafe { CRYPTO_free(objtmp.cast::<c_void>(), FILE.as_ptr(), LINE_FREE_OBJ) };
        i += 1;
    }
    ainfo.cast::<c_void>()
}

/// `v2i_AUTHORITY_INFO_ACCESS`'s `err:` label — `crypto/x509/v3_info.c:146-148`.
///
/// A safe helper: `ainfo` is a live list this call built.
fn v2i_ainfo_err(ainfo: *mut OpenSslStack) -> *mut c_void {
    // SAFETY: `ainfo` is a live list this call built; `access_description_free_thunk` its destructor.
    unsafe { OPENSSL_sk_pop_free(ainfo, Some(access_description_free_thunk)) };
    ptr::null_mut()
}

/// `int i2a_ACCESS_DESCRIPTION(BIO *bp, const ACCESS_DESCRIPTION *a)` — `crypto/x509/v3_info.c:151-155`.
///
/// # Safety
///
/// `bp` is a live BIO; `a` is a live `ACCESS_DESCRIPTION`.
#[no_mangle]
pub unsafe extern "C" fn i2a_ACCESS_DESCRIPTION(
    bp: *mut Bio,
    a: *const AccessDescription,
) -> c_int {
    // SAFETY: `a` is live per the contract.
    unsafe { i2a_ASN1_OBJECT(bp, (*a).method) };
    2
}

/// One `AUTHORITY_INFO_ACCESS`-backed row: the item, `i2v`/`v2i` callbacks, the
/// `X509V3_EXT_MULTILINE` flag.
const fn info_access_row(nid: c_int) -> X509V3ExtMethod {
    X509V3ExtMethod {
        ext_nid: nid,
        ext_flags: X509V3_EXT_MULTILINE,
        it: Some(AUTHORITY_INFO_ACCESS_it),
        ext_new: None,
        ext_free: None,
        d2i: None,
        i2d: None,
        i2s: None,
        s2i: None,
        i2v: Some(i2v_AUTHORITY_INFO_ACCESS),
        v2i: Some(v2i_AUTHORITY_INFO_ACCESS),
        i2r: None,
        r2i: None,
        usr_data: ptr::null_mut(),
    }
}

/// `const X509V3_EXT_METHOD ossl_v3_info` — `crypto/x509/v3_info.c:30-37`.
pub static ossl_v3_info: X509V3ExtMethod = info_access_row(NID_info_access);

/// `const X509V3_EXT_METHOD ossl_v3_sinfo` — `crypto/x509/v3_info.c:39-46`.
pub static ossl_v3_sinfo: X509V3ExtMethod = info_access_row(NID_sinfo_access);
