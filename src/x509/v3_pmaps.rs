//! `crypto/x509/v3_pmaps.c` — the `POLICY_MAPPING`/`POLICY_MAPPINGS` items and their row. Phase
//! 10.14.6's table layer, landed whole.
//!
//! `crypto/x509/v3_pmaps.c` is 109 lines and transcribes whole:
//!
//! * `POLICY_MAPPING ::= SEQUENCE { issuerDomainPolicy ASN1_OBJECT, subjectDomainPolicy
//!   ASN1_OBJECT }` (`:34-37`) lands with `POLICY_MAPPING_it` and the `_new`/`_free` pair
//!   `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` emits (`:43`; `x509v3.h:630-631` declares no `d2i_`/`i2d_`).
//! * `POLICY_MAPPINGS ::= SEQUENCE OF POLICY_MAPPING` (`:39-41`) lands with `POLICY_MAPPINGS_it`.
//! * `i2v_POLICY_MAPPINGS` (`:45-62`) and `v2i_POLICY_MAPPINGS` (`:64-109`) land.
//! * The row [`ossl_v3_policy_mappings`] (`:23-32`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item groups and the two callbacks are the drivable
//! surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_pmaps.c` is not an entry in `gen_err_raise_sites.py`, so its four coordinates
//! are **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::ASN1_OBJECT_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::asn1::prim::ASN1_OBJECT_free;
use crate::asn1::text::i2t_ASN1_OBJECT;
use crate::runtime::bio::ERR_R_CRYPTO_LIB;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::X509V3_R_INVALID_OBJECT_IDENTIFIER;
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::obj::{Asn1Object, NID_policy_mappings, OBJ_txt2obj};
use crate::runtime::stack::{
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::X509V3_add_value;

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_pmaps.c` raise coordinate, declared locally (see the module doc).
const fn v3_pmaps_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_pmaps.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_POLICY_MAPPINGS`'s reserve failure at `v3_pmaps.c:75`.
const V3_PMAPS_75: crate::runtime::err::err_sites::ErrSite =
    v3_pmaps_site(75, c"v2i_POLICY_MAPPINGS", ERR_R_CRYPTO_LIB);
/// `v2i_POLICY_MAPPINGS`'s missing name/value at `v3_pmaps.c:82`.
const V3_PMAPS_82: crate::runtime::err::err_sites::ErrSite = v3_pmaps_site(
    82,
    c"v2i_POLICY_MAPPINGS",
    X509V3_R_INVALID_OBJECT_IDENTIFIER,
);
/// `v2i_POLICY_MAPPINGS`'s bad OID at `v3_pmaps.c:89`.
const V3_PMAPS_89: crate::runtime::err::err_sites::ErrSite = v3_pmaps_site(
    89,
    c"v2i_POLICY_MAPPINGS",
    X509V3_R_INVALID_OBJECT_IDENTIFIER,
);
/// `v2i_POLICY_MAPPINGS`'s `POLICY_MAPPING_new` failure at `v3_pmaps.c:95`.
const V3_PMAPS_95: crate::runtime::err::err_sites::ErrSite =
    v3_pmaps_site(95, c"v2i_POLICY_MAPPINGS", ERR_R_ASN1_LIB);

/// `struct POLICY_MAPPING_st` — `POLICY_MAPPING`, from `include/openssl/x509v3.h`.
#[repr(C)]
pub struct PolicyMapping {
    /// `ASN1_OBJECT *issuerDomainPolicy`.
    pub issuerDomainPolicy: *mut Asn1Object,
    /// `ASN1_OBJECT *subjectDomainPolicy`.
    pub subjectDomainPolicy: *mut Asn1Object,
}

const _: () = {
    assert!(core::mem::size_of::<PolicyMapping>() == 16);
    assert!(core::mem::offset_of!(PolicyMapping, issuerDomainPolicy) == 0);
    assert!(core::mem::offset_of!(PolicyMapping, subjectDomainPolicy) == 8);
};

/// `void (*)(void *)` thunk for `sk_POLICY_MAPPING_pop_free(..., POLICY_MAPPING_free)`.
///
/// # Safety
///
/// `p` is NULL or a live `POLICY_MAPPING` (the stack contract).
unsafe extern "C" fn policy_mapping_free_thunk(p: *mut c_void) {
    // SAFETY: the stack holds `POLICY_MAPPING` pointers per the contract.
    unsafe { POLICY_MAPPING_free(p.cast::<PolicyMapping>()) };
}

/// `POLICY_MAPPING_seq_tt` — `ASN1_SEQUENCE(POLICY_MAPPING)` (`crypto/x509/v3_pmaps.c:34-37`): two
/// mandatory `ASN1_OBJECT` fields.
static POLICY_MAPPING_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"issuerDomainPolicy".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"subjectDomainPolicy".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
];

/// `POLICY_MAPPING_it`'s descriptor — `ASN1_SEQUENCE_END(POLICY_MAPPING)` at
/// `crypto/x509/v3_pmaps.c:37`.
static POLICY_MAPPING_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: POLICY_MAPPING_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PolicyMapping>() as c_long,
    sname: c"POLICY_MAPPING".as_ptr(),
};

/// `const ASN1_ITEM *POLICY_MAPPING_it(void)` — `include/openssl/x509v3.h:630`.
#[no_mangle]
pub extern "C" fn POLICY_MAPPING_it() -> *const Asn1Item {
    &POLICY_MAPPING_ITEM
}

/// `POLICY_MAPPING *POLICY_MAPPING_new(void)` — `crypto/x509/v3_pmaps.c:43`.
#[no_mangle]
pub extern "C" fn POLICY_MAPPING_new() -> *mut PolicyMapping {
    // SAFETY: `POLICY_MAPPING_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(POLICY_MAPPING_it()).cast::<PolicyMapping>() }
}

/// `void POLICY_MAPPING_free(POLICY_MAPPING *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn POLICY_MAPPING_free(a: *mut PolicyMapping) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), POLICY_MAPPING_it()) }
}

/// `POLICY_MAPPINGS_tmpl_tt` — `ASN1_ITEM_TEMPLATE(POLICY_MAPPINGS)`'s single template
/// (`crypto/x509/v3_pmaps.c:39-40`): `ASN1_TFLG_SEQUENCE_OF` over `POLICY_MAPPING`.
static POLICY_MAPPINGS_TT: Asn1Template = Asn1Template {
    flags: ASN1_TFLG_SEQUENCE_OF,
    tag: 0,
    offset: 0,
    field_name: c"POLICY_MAPPINGS".as_ptr(),
    item: POLICY_MAPPING_it as *mut c_void,
};

/// `POLICY_MAPPINGS_it`'s descriptor — `ASN1_ITEM_TEMPLATE_END(POLICY_MAPPINGS)` at
/// `crypto/x509/v3_pmaps.c:41`.
static POLICY_MAPPINGS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_PRIMITIVE,
    utype: V_ASN1_UNDEF as c_long,
    templates: &POLICY_MAPPINGS_TT,
    tcount: 0,
    funcs: ptr::null(),
    size: 0,
    sname: c"POLICY_MAPPINGS".as_ptr(),
};

/// `const ASN1_ITEM *POLICY_MAPPINGS_it(void)` — `include/openssl/x509v3.h:632`.
#[no_mangle]
pub extern "C" fn POLICY_MAPPINGS_it() -> *const Asn1Item {
    &POLICY_MAPPINGS_ITEM
}

/// `static STACK_OF(CONF_VALUE) *i2v_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method, void *a,
/// STACK_OF(CONF_VALUE) *ext_list)` — `crypto/x509/v3_pmaps.c:45-62`.
unsafe extern "C" fn i2v_POLICY_MAPPINGS(
    _method: *const X509V3ExtMethod,
    a: *mut c_void,
    ext_list: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut ext_list = ext_list;
    let pmaps = a.cast::<OpenSslStack>();
    // SAFETY: `pmaps` is a live `STACK_OF(POLICY_MAPPING)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(pmaps) };
    let mut i = 0;
    while i < num {
        // SAFETY: `pmaps` is live and `i` is in bounds.
        let pmap = unsafe { OPENSSL_sk_value(pmaps, i) }.cast::<PolicyMapping>();
        let mut obj_tmp1 = [0 as c_char; 80];
        let mut obj_tmp2 = [0 as c_char; 80];
        // SAFETY: both buffers are 80 writable bytes; each object is live.
        unsafe {
            i2t_ASN1_OBJECT(obj_tmp1.as_mut_ptr(), 80, (*pmap).issuerDomainPolicy);
            i2t_ASN1_OBJECT(obj_tmp2.as_mut_ptr(), 80, (*pmap).subjectDomainPolicy);
        }
        // SAFETY: both buffers are NUL-terminated; `ext_list` is this call's sink.
        unsafe { X509V3_add_value(obj_tmp1.as_ptr(), obj_tmp2.as_ptr(), &mut ext_list) };
        i += 1;
    }
    ext_list
}

/// `static void *v2i_POLICY_MAPPINGS(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *nval)` — `crypto/x509/v3_pmaps.c:64-109`.
unsafe extern "C" fn v2i_POLICY_MAPPINGS(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    nval: *mut OpenSslStack,
) -> *mut c_void {
    // SAFETY: `nval` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(nval) };
    let pmaps = OPENSSL_sk_new_reserve(None, num);
    if pmaps.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PMAPS_75) };
        return ptr::null_mut();
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `nval` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(nval, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract.
        let (name, value) = unsafe { ((*val).name, (*val).value) };
        if value.is_null() || name.is_null() {
            // SAFETY: `name` is NUL-terminated; the site is a compiled-in constant.
            unsafe { raise_site_data(&V3_PMAPS_82, name) };
            // SAFETY: the call's own `# Safety` section is the contract.
            return unsafe { v3_pmaps_err(pmaps, ptr::null_mut(), ptr::null_mut()) };
        }
        // SAFETY: both strings are NUL-terminated; `no_name` is 0.
        let obj1 = unsafe { OBJ_txt2obj(name, 0) };
        // SAFETY: as above.
        let obj2 = unsafe { OBJ_txt2obj(value, 0) };
        if obj1.is_null() || obj2.is_null() {
            // SAFETY: `name` is NUL-terminated; the site is a compiled-in constant.
            unsafe { raise_site_data(&V3_PMAPS_89, name) };
            // SAFETY: the call's own `# Safety` section is the contract.
            return unsafe { v3_pmaps_err(pmaps, obj1, obj2) };
        }
        let pmap = POLICY_MAPPING_new();
        if pmap.is_null() {
            // SAFETY: the site is a compiled-in constant.
            unsafe { raise_site(&V3_PMAPS_95) };
            // SAFETY: `obj1`/`obj2` are live objects this call owns.
            unsafe {
                ASN1_OBJECT_free(obj1);
                ASN1_OBJECT_free(obj2);
            }
            // SAFETY: `pmaps` is the list this call built.
            unsafe { OPENSSL_sk_pop_free(pmaps, Some(policy_mapping_free_thunk)) };
            return ptr::null_mut();
        }
        // SAFETY: `pmap` is live and takes ownership of the two objects.
        unsafe {
            (*pmap).issuerDomainPolicy = obj1;
            (*pmap).subjectDomainPolicy = obj2;
        }
        // SAFETY: `pmaps` was reserved for `num`, so the push cannot fail.
        unsafe { OPENSSL_sk_push(pmaps, pmap.cast::<c_void>()) };
        i += 1;
    }
    pmaps.cast::<c_void>()
}

/// The authority's `err:` label — frees the two objects and the list, then answers NULL.
///
/// # Safety
///
/// `pmaps` is a live list this call built; `obj1`/`obj2` are NULL or live objects this call owns.
unsafe fn v3_pmaps_err(
    pmaps: *mut OpenSslStack,
    obj1: *mut Asn1Object,
    obj2: *mut Asn1Object,
) -> *mut c_void {
    // SAFETY: per the contract; `ASN1_OBJECT_free` accepts NULL.
    unsafe {
        ASN1_OBJECT_free(obj1);
        ASN1_OBJECT_free(obj2);
        OPENSSL_sk_pop_free(pmaps, Some(policy_mapping_free_thunk));
    }
    ptr::null_mut()
}

/// `const X509V3_EXT_METHOD ossl_v3_policy_mappings` — `crypto/x509/v3_pmaps.c:23-32`.
pub static ossl_v3_policy_mappings: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_policy_mappings,
    ext_flags: 0,
    it: Some(POLICY_MAPPINGS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: Some(i2v_POLICY_MAPPINGS),
    v2i: Some(v2i_POLICY_MAPPINGS),
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
