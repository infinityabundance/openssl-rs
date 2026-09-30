//! `crypto/x509/v3_pcons.c` — the `POLICY_CONSTRAINTS` item and its row. Phase 10.14.6's table
//! layer, landed whole.
//!
//! `crypto/x509/v3_pcons.c` is 91 lines and transcribes whole:
//!
//! * `POLICY_CONSTRAINTS ::= SEQUENCE { requireExplicitPolicy [0] INTEGER OPTIONAL,
//!   inhibitPolicyMapping [1] INTEGER OPTIONAL }` (`:36-39`) lands, with `POLICY_CONSTRAINTS_it`
//!   and the `_new`/`_free` pair `IMPLEMENT_ASN1_ALLOC_FUNCTIONS` emits (`:41`). The header declares
//!   no `d2i_`/`i2d_` for this type (`x509v3.h:640-641`), so the item group here is only the
//!   allocator half.
//! * `i2v_POLICY_CONSTRAINTS` (`:43-53`) and `v2i_POLICY_CONSTRAINTS` (`:55-91`) land.
//! * The row [`ossl_v3_policy_constraints`] (`:25-34`) lands.
//!
//! **Withheld by name**: `standard_exts[]` (`standard_exts.h:15-95`) and the six lookup names in
//! `v3_lib.rs` it feeds. A partial array would silently change `OBJ_bsearch_ext` for every missing
//! NID (D456). This unit contributes one of the 63. The row is internal data the admitted DSO does
//! not export (`nm -D` shows no `ossl_v3_*`); the item group and the two callbacks are the drivable
//! surface.
//!
//! ## The raise sites
//!
//! `crypto/x509/v3_pcons.c` is not an entry in `gen_err_raise_sites.py`, so its three coordinates
//! are **declared locally**, their reason values read from the authority's `err.h`/`x509v3err.h`
//! (not typed from memory), as `v3_bitst.rs` does.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use crate::asn1::fre::ASN1_item_free;
use crate::asn1::items::ASN1_INTEGER_it;
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::types::ConfValue;
use crate::runtime::err::err_reasons::{X509V3_R_ILLEGAL_EMPTY_EXTENSION, X509V3_R_INVALID_NAME};
use crate::runtime::err::{raise_site, raise_site_data};
use crate::runtime::obj::NID_policy_constraints;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value, OpenSslStack};
use crate::x509::v3_lib::X509V3ExtMethod;
use crate::x509::v3_utl::{X509V3_add_value_int, X509V3_get_value_int};

/// `ERR_LIB_X509V3` — `include/openssl/err.h.in:99`.
const ERR_LIB_X509V3: c_int = 34;
/// `ERR_R_ASN1_LIB` — `err.h:328`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 524301;

/// One `v3_pcons.c` raise coordinate, declared locally (see the module doc).
const fn v3_pcons_site(
    line: c_int,
    func: &'static core::ffi::CStr,
    reason: c_int,
) -> crate::runtime::err::err_sites::ErrSite {
    crate::runtime::err::err_sites::ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/v3_pcons.c",
        line,
        func,
        lib: ERR_LIB_X509V3,
        reason,
        dynamic_reason: false,
    }
}

/// `v2i_POLICY_CONSTRAINTS`'s allocation failure at `v3_pcons.c:64`.
const V3_PCONS_64: crate::runtime::err::err_sites::ErrSite =
    v3_pcons_site(64, c"v2i_POLICY_CONSTRAINTS", ERR_R_ASN1_LIB);
/// `v2i_POLICY_CONSTRAINTS`'s unknown name at `v3_pcons.c:76`.
const V3_PCONS_76: crate::runtime::err::err_sites::ErrSite =
    v3_pcons_site(76, c"v2i_POLICY_CONSTRAINTS", X509V3_R_INVALID_NAME);
/// `v2i_POLICY_CONSTRAINTS`'s empty extension at `v3_pcons.c:83`.
const V3_PCONS_83: crate::runtime::err::err_sites::ErrSite = v3_pcons_site(
    83,
    c"v2i_POLICY_CONSTRAINTS",
    X509V3_R_ILLEGAL_EMPTY_EXTENSION,
);

/// `struct POLICY_CONSTRAINTS_st` — `POLICY_CONSTRAINTS`, from `include/openssl/x509v3.h`.
#[repr(C)]
pub struct PolicyConstraints {
    /// `ASN1_INTEGER *requireExplicitPolicy` — `[0]` implicit, optional.
    pub requireExplicitPolicy: *mut Asn1String,
    /// `ASN1_INTEGER *inhibitPolicyMapping` — `[1]` implicit, optional.
    pub inhibitPolicyMapping: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<PolicyConstraints>() == 16);
    assert!(core::mem::offset_of!(PolicyConstraints, requireExplicitPolicy) == 0);
    assert!(core::mem::offset_of!(PolicyConstraints, inhibitPolicyMapping) == 8);
};

/// `POLICY_CONSTRAINTS_seq_tt` — `ASN1_SEQUENCE(POLICY_CONSTRAINTS)`
/// (`crypto/x509/v3_pcons.c:36-39`): two `ASN1_IMP_OPT(..., ASN1_INTEGER, n)` rows.
static POLICY_CONSTRAINTS_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"requireExplicitPolicy".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        tag: 1,
        offset: 8,
        field_name: c"inhibitPolicyMapping".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
];

/// `POLICY_CONSTRAINTS_it`'s descriptor — `ASN1_SEQUENCE_END(POLICY_CONSTRAINTS)` at
/// `crypto/x509/v3_pcons.c:39`.
static POLICY_CONSTRAINTS_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: POLICY_CONSTRAINTS_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<PolicyConstraints>() as c_long,
    sname: c"POLICY_CONSTRAINTS".as_ptr(),
};

/// `const ASN1_ITEM *POLICY_CONSTRAINTS_it(void)` — `include/openssl/x509v3.h:641`.
#[no_mangle]
pub extern "C" fn POLICY_CONSTRAINTS_it() -> *const Asn1Item {
    &POLICY_CONSTRAINTS_ITEM
}

/// `POLICY_CONSTRAINTS *POLICY_CONSTRAINTS_new(void)` — `crypto/x509/v3_pcons.c:41`, from
/// `IMPLEMENT_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)`.
#[no_mangle]
pub extern "C" fn POLICY_CONSTRAINTS_new() -> *mut PolicyConstraints {
    // SAFETY: `POLICY_CONSTRAINTS_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(POLICY_CONSTRAINTS_it()).cast::<PolicyConstraints>() }
}

/// `void POLICY_CONSTRAINTS_free(POLICY_CONSTRAINTS *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn POLICY_CONSTRAINTS_free(a: *mut PolicyConstraints) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), POLICY_CONSTRAINTS_it()) }
}

/// `static STACK_OF(CONF_VALUE) *i2v_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD *method, void *a,
/// STACK_OF(CONF_VALUE) *extlist)` — `crypto/x509/v3_pcons.c:43-53`.
unsafe extern "C" fn i2v_POLICY_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    a: *mut c_void,
    extlist: *mut OpenSslStack,
) -> *mut OpenSslStack {
    let mut extlist = extlist;
    let pcons = a.cast::<PolicyConstraints>();
    // SAFETY: `pcons` is a live `POLICY_CONSTRAINTS` per the caller's contract.
    unsafe {
        X509V3_add_value_int(
            c"Require Explicit Policy".as_ptr(),
            (*pcons).requireExplicitPolicy,
            &mut extlist,
        );
        X509V3_add_value_int(
            c"Inhibit Policy Mapping".as_ptr(),
            (*pcons).inhibitPolicyMapping,
            &mut extlist,
        );
    }
    extlist
}

/// `static void *v2i_POLICY_CONSTRAINTS(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
/// STACK_OF(CONF_VALUE) *values)` — `crypto/x509/v3_pcons.c:55-91`.
unsafe extern "C" fn v2i_POLICY_CONSTRAINTS(
    _method: *const X509V3ExtMethod,
    _ctx: *mut c_void,
    values: *mut OpenSslStack,
) -> *mut c_void {
    let pcons = POLICY_CONSTRAINTS_new();
    if pcons.is_null() {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PCONS_64) };
        return ptr::null_mut();
    }
    // SAFETY: `values` is a live `STACK_OF(CONF_VALUE)` per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(values) };
    let mut i = 0;
    while i < num {
        // SAFETY: `values` is live and `i` is in bounds.
        let val = unsafe { OPENSSL_sk_value(values, i) }.cast::<ConfValue>();
        // SAFETY: `val` is live per the stack contract; each literal is static.
        let name = unsafe { (*val).name };
        // SAFETY: `name` is NUL-terminated; the literal is static.
        let is_req = unsafe { strcmp(name, c"requireExplicitPolicy".as_ptr()) } == 0;
        // SAFETY: as above.
        let is_inh = unsafe { strcmp(name, c"inhibitPolicyMapping".as_ptr()) } == 0;
        if is_req {
            // SAFETY: `pcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_int(val, &raw mut (*pcons).requireExplicitPolicy) } == 0 {
                // SAFETY: `pcons` is a live value this call owns.
                unsafe { POLICY_CONSTRAINTS_free(pcons) };
                return ptr::null_mut();
            }
        } else if is_inh {
            // SAFETY: `pcons` is live; the field slot is writable.
            if unsafe { X509V3_get_value_int(val, &raw mut (*pcons).inhibitPolicyMapping) } == 0 {
                // SAFETY: `pcons` is a live value this call owns.
                unsafe { POLICY_CONSTRAINTS_free(pcons) };
                return ptr::null_mut();
            }
        } else {
            // SAFETY: `name` is NUL-terminated; the site is a compiled-in constant.
            unsafe { raise_site_data(&V3_PCONS_76, name) };
            // SAFETY: `pcons` is a live value this call owns.
            unsafe { POLICY_CONSTRAINTS_free(pcons) };
            return ptr::null_mut();
        }
        i += 1;
    }
    // SAFETY: `pcons` is live per the contract.
    let both_null = unsafe {
        (*pcons).inhibitPolicyMapping.is_null() && (*pcons).requireExplicitPolicy.is_null()
    };
    if both_null {
        // SAFETY: the site is a compiled-in constant.
        unsafe { raise_site(&V3_PCONS_83) };
        // SAFETY: `pcons` is a live value this call owns.
        unsafe { POLICY_CONSTRAINTS_free(pcons) };
        return ptr::null_mut();
    }
    pcons.cast::<c_void>()
}

/// `const X509V3_EXT_METHOD ossl_v3_policy_constraints` — `crypto/x509/v3_pcons.c:25-34`.
pub static ossl_v3_policy_constraints: X509V3ExtMethod = X509V3ExtMethod {
    ext_nid: NID_policy_constraints,
    ext_flags: 0,
    it: Some(POLICY_CONSTRAINTS_it),
    ext_new: None,
    ext_free: None,
    d2i: None,
    i2d: None,
    i2s: None,
    s2i: None,
    i2v: Some(i2v_POLICY_CONSTRAINTS),
    v2i: Some(v2i_POLICY_CONSTRAINTS),
    i2r: None,
    r2i: None,
    usr_data: ptr::null_mut(),
};
