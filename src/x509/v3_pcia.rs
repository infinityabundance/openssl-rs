//! `crypto/x509/v3_pcia.c` — the RFC 3820 proxy-certificate items. Phase 10.12.
//!
//! `crypto/x509/v3_pcia.c` is 62 lines (after its 44-line dual-licence header) and **lands
//! whole**. It is two `ASN1_SEQUENCE` templates and the `IMPLEMENT_ASN1_FUNCTIONS` groups over
//! them, with no hand-written function at all:
//!
//! * `PROXY_POLICY ::= SEQUENCE { policyLanguage OBJECT IDENTIFIER, policy OCTET STRING OPTIONAL }`
//!   (`:50-53`);
//! * `PROXY_CERT_INFO_EXTENSION ::= SEQUENCE { pcPathLengthConstraint INTEGER OPTIONAL,
//!   proxyPolicy PROXY_POLICY }` (`:57-60`).
//!
//! Nothing is withheld: both templates reference only landed items (`ASN1_OBJECT_it`,
//! `ASN1_OCTET_STRING_it`, `ASN1_INTEGER_it`) and the inner `PROXY_POLICY_it`.
//!
//! ## The court
//!
//! `PROXY_POLICY_it`/`_new`/`_free`/`d2i_`/`i2d_` and the `PROXY_CERT_INFO_EXTENSION` group are
//! public exports (`x509v3.h`), so `RT-STORE`'s 10.12 arms build one of each with the public
//! setters, encode it, and decode the bytes back — a byte-exact observation of the item.
//!
//! ## No raise
//!
//! The unit raises nothing, so it is deliberately not an entry in `gen_err_raise_sites.py`'s
//! `COVERED_FILES`.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::d2i::ASN1_item_d2i;
use crate::asn1::fre::ASN1_item_free;
use crate::asn1::i2d::ASN1_item_i2d;
use crate::asn1::items::{ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it};
use crate::asn1::layout::*;
use crate::asn1::new::ASN1_item_new;
use crate::runtime::obj::Asn1Object;

/// `struct proxy_policy_st` — `PROXY_POLICY`, from `include/openssl/x509v3.h:594-597`.
#[repr(C)]
pub struct ProxyPolicy {
    /// `ASN1_OBJECT *policyLanguage` — the proxy policy OID, mandatory.
    pub(crate) policyLanguage: *mut Asn1Object,
    /// `ASN1_OCTET_STRING *policy` — the policy data, optional.
    pub(crate) policy: *mut Asn1String,
}

const _: () = {
    assert!(core::mem::size_of::<ProxyPolicy>() == 16);
    assert!(core::mem::offset_of!(ProxyPolicy, policyLanguage) == 0);
    assert!(core::mem::offset_of!(ProxyPolicy, policy) == 8);
};

/// `PROXY_POLICY_seq_tt` — `ASN1_SEQUENCE(PROXY_POLICY)` (`crypto/x509/v3_pcia.c:50-53`):
/// `ASN1_SIMPLE(policyLanguage, ASN1_OBJECT)` and `ASN1_OPT(policy, ASN1_OCTET_STRING)`.
static PROXY_POLICY_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 0,
        field_name: c"policyLanguage".as_ptr(),
        item: ASN1_OBJECT_it as *mut c_void,
    },
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 8,
        field_name: c"policy".as_ptr(),
        item: ASN1_OCTET_STRING_it as *mut c_void,
    },
];

/// `PROXY_POLICY_it`'s descriptor — `ASN1_SEQUENCE_END(PROXY_POLICY)` at
/// `crypto/x509/v3_pcia.c:53`.
static PROXY_POLICY_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PROXY_POLICY_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<ProxyPolicy>() as c_long,
    sname: c"PROXY_POLICY".as_ptr(),
};

/// `const ASN1_ITEM *PROXY_POLICY_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(PROXY_POLICY)`.
#[no_mangle]
pub extern "C" fn PROXY_POLICY_it() -> *const Asn1Item {
    &PROXY_POLICY_ITEM
}

/// `PROXY_POLICY *PROXY_POLICY_new(void)` — `crypto/x509/v3_pcia.c:55`, from
/// `IMPLEMENT_ASN1_FUNCTIONS(PROXY_POLICY)`.
#[no_mangle]
pub extern "C" fn PROXY_POLICY_new() -> *mut ProxyPolicy {
    // SAFETY: `PROXY_POLICY_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PROXY_POLICY_it()).cast::<ProxyPolicy>() }
}

/// `void PROXY_POLICY_free(PROXY_POLICY *a)` — the same macro's free half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PROXY_POLICY_free(a: *mut ProxyPolicy) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PROXY_POLICY_it()) }
}

/// `PROXY_POLICY *d2i_PROXY_POLICY(PROXY_POLICY **a, const unsigned char **in, long len)` — the
/// same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PROXY_POLICY(
    a: *mut *mut ProxyPolicy,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut ProxyPolicy {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_d2i(a.cast(), in_, len, PROXY_POLICY_it()).cast::<ProxyPolicy>() }
}

/// `int i2d_PROXY_POLICY(const PROXY_POLICY *a, unsigned char **out)` — the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PROXY_POLICY(a: *const ProxyPolicy, out: *mut *mut c_uchar) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PROXY_POLICY_it()) }
}

/// `struct proxy_cert_info_extension_st` — `PROXY_CERT_INFO_EXTENSION`, from
/// `include/openssl/x509v3.h:599-602`.
#[repr(C)]
pub struct ProxyCertInfoExtension {
    /// `ASN1_INTEGER *pcPathLengthConstraint` — optional path-length constraint.
    pub(crate) pcPathLengthConstraint: *mut Asn1String,
    /// `PROXY_POLICY *proxyPolicy` — the mandatory proxy policy.
    pub(crate) proxyPolicy: *mut ProxyPolicy,
}

const _: () = {
    assert!(core::mem::size_of::<ProxyCertInfoExtension>() == 16);
    assert!(core::mem::offset_of!(ProxyCertInfoExtension, pcPathLengthConstraint) == 0);
    assert!(core::mem::offset_of!(ProxyCertInfoExtension, proxyPolicy) == 8);
};

/// `PROXY_CERT_INFO_EXTENSION_seq_tt` — `ASN1_SEQUENCE(PROXY_CERT_INFO_EXTENSION)`
/// (`crypto/x509/v3_pcia.c:57-60`): `ASN1_OPT(pcPathLengthConstraint, ASN1_INTEGER)` and
/// `ASN1_SIMPLE(proxyPolicy, PROXY_POLICY)`.
static PROXY_CERT_INFO_EXTENSION_TT: [Asn1Template; 2] = [
    Asn1Template {
        flags: ASN1_TFLG_OPTIONAL,
        tag: 0,
        offset: 0,
        field_name: c"pcPathLengthConstraint".as_ptr(),
        item: ASN1_INTEGER_it as *mut c_void,
    },
    Asn1Template {
        flags: 0,
        tag: 0,
        offset: 8,
        field_name: c"proxyPolicy".as_ptr(),
        item: PROXY_POLICY_it as *mut c_void,
    },
];

/// `PROXY_CERT_INFO_EXTENSION_it`'s descriptor — `ASN1_SEQUENCE_END(PROXY_CERT_INFO_EXTENSION)` at
/// `crypto/x509/v3_pcia.c:60`.
static PROXY_CERT_INFO_EXTENSION_ITEM: Asn1Item = Asn1Item {
    itype: ASN1_ITYPE_SEQUENCE,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: PROXY_CERT_INFO_EXTENSION_TT.as_ptr(),
    tcount: 2,
    funcs: ptr::null(),
    size: core::mem::size_of::<ProxyCertInfoExtension>() as c_long,
    sname: c"PROXY_CERT_INFO_EXTENSION".as_ptr(),
};

/// `const ASN1_ITEM *PROXY_CERT_INFO_EXTENSION_it(void)` — `include/openssl/x509v3.h`, from
/// `DECLARE_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)`.
#[no_mangle]
pub extern "C" fn PROXY_CERT_INFO_EXTENSION_it() -> *const Asn1Item {
    &PROXY_CERT_INFO_EXTENSION_ITEM
}

/// `PROXY_CERT_INFO_EXTENSION *PROXY_CERT_INFO_EXTENSION_new(void)` — `crypto/x509/v3_pcia.c:62`,
/// from `IMPLEMENT_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)`.
#[no_mangle]
pub extern "C" fn PROXY_CERT_INFO_EXTENSION_new() -> *mut ProxyCertInfoExtension {
    // SAFETY: `PROXY_CERT_INFO_EXTENSION_it()` answers a static item the crate owns.
    unsafe { ASN1_item_new(PROXY_CERT_INFO_EXTENSION_it()).cast::<ProxyCertInfoExtension>() }
}

/// `void PROXY_CERT_INFO_EXTENSION_free(PROXY_CERT_INFO_EXTENSION *a)` — the same macro's free
/// half.
///
/// # Safety
///
/// `a` is NULL or a value this item layer built.
#[no_mangle]
pub unsafe extern "C" fn PROXY_CERT_INFO_EXTENSION_free(a: *mut ProxyCertInfoExtension) {
    // SAFETY: `a` is NULL or a live item value per the contract.
    unsafe { ASN1_item_free(a.cast(), PROXY_CERT_INFO_EXTENSION_it()) }
}

/// `PROXY_CERT_INFO_EXTENSION *d2i_PROXY_CERT_INFO_EXTENSION(PROXY_CERT_INFO_EXTENSION **a, ...)` —
/// the same macro's decoder.
///
/// # Safety
///
/// `a` is NULL or a writable slot; `in_` points at a readable cursor; `len` describes the input.
#[no_mangle]
pub unsafe extern "C" fn d2i_PROXY_CERT_INFO_EXTENSION(
    a: *mut *mut ProxyCertInfoExtension,
    in_: *mut *const c_uchar,
    len: c_long,
) -> *mut ProxyCertInfoExtension {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe {
        ASN1_item_d2i(a.cast(), in_, len, PROXY_CERT_INFO_EXTENSION_it())
            .cast::<ProxyCertInfoExtension>()
    }
}

/// `int i2d_PROXY_CERT_INFO_EXTENSION(const PROXY_CERT_INFO_EXTENSION *a, unsigned char **out)` —
/// the same macro's encoder.
///
/// # Safety
///
/// `a` is NULL or a live value; `out` is NULL or a writable cursor.
#[no_mangle]
pub unsafe extern "C" fn i2d_PROXY_CERT_INFO_EXTENSION(
    a: *const ProxyCertInfoExtension,
    out: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the enclosing function's `# Safety` section is the contract for every pointer here.
    unsafe { ASN1_item_i2d(a.cast(), out, PROXY_CERT_INFO_EXTENSION_it()) }
}
